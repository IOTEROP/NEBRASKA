/* NEBRASKA sample code
 * This sample code is based on Espressif's CoAP client Example
 *
 *  This example code is in the Public Domain (or CC0 licensed, at your option.)
 *
 * Unless required by applicable law or agreed to in writing, this
 * software is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR
 * CONDITIONS OF ANY KIND, either express or implied.
*/

/*
 * WARNING
 * libcoap is not multi-thread safe, so only this thread must make any coap_*()
 * calls.  Any external (to this thread) data transmitted in/out via libcoap
 * therefore has to be passed in/out by xQueue*() via this thread.
 */


#include <string.h>
#include <sys/socket.h>
#include <netdb.h>
#include <sys/param.h>

#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "freertos/event_groups.h"

#include "esp_log.h"
#include "esp_wifi.h"
#include "esp_event.h"

#include "nvs_flash.h"

#include "protocol_examples_common.h"

#if 1
/* Needed until coap_dtls.h becomes a part of libcoap proper */
#include "libcoap.h"
#include "coap_dtls.h"
#endif
#include "coap.h"

#define COAP_DEFAULT_TIME_SEC 5

char NEBRASKA_URI_PATH[] = "mqtt";

/* State machine */
typedef enum
{
    CLT_STATE_FAILURE,
    CLT_STATE_REGISTRATION_NEEDED, /* Initial state */
    CLT_STATE_REGISTRATION_CONNECTING,
    CLT_STATE_RUNNING
} client_state_t;
client_state_t g_state;

/* saved (after registration) options list */
static coap_optlist_t *pub_optlist = NULL;

/* The examples use simple Pre-Shared-Key configuration that you can set via
   'make menuconfig'.

   If you'd rather not, just change the below entries to strings with
   the config you want - ie #define EXAMPLE_COAP_PSK_KEY "some-agreed-preshared-key"

   Note: PSK will only be used if the URI is prefixed with coaps://
   instead of coap:// and the PSK must be one that the server supports
   (potentially associated with the IDENTITY)
*/
#define EXAMPLE_COAP_PSK_KEY CONFIG_DEMO_NEBRASKA_PSK_KEY
#define EXAMPLE_COAP_PSK_IDENTITY CONFIG_DEMO_NEBRASKA_PSK_IDENTITY

/* The examples use uri Logging Level that
   you can set via 'make menuconfig'.

   If you'd rather not, just change the below entry to a value
   that is between 0 and 7 with
   the config you want - ie #define EXAMPLE_LOG_DEFAULT_LEVEL 7
*/
#define EXAMPLE_LOG_DEFAULT_LEVEL 7

/* The examples use uri "coaps://ingress.nebraska.ioterop.com:18834" that
   you can set via the project configuration (idf.py menuconfig)

   If you'd rather not, just change the below entries to strings with
   the config you want - ie:
        #define COAP_DEFAULT_DEMO_URI "coaps://ingress.nebraska.ioterop.com:18834"
*/
#define COAP_DEFAULT_DEMO_URI CONFIG_NEBRASKA_TARGET_DOMAIN_URI

const static char *TAG = "Nebraska_";

static int resp_wait = 1;
static int wait_ms;
static coap_optlist_t *optlist = NULL;

#ifdef CONFIG_COAP_MBEDTLS_PKI
/* CA cert, taken from coap_ca.pem
   Client cert, taken from fake_client.crt
   Client key, taken from fake_client.key

   The PEM, CRT and KEY file are examples taken from the wpa2 enterprise
   example.

   To embed it in the app binary, the PEM, CRT and KEY file is named
   in the component.mk COMPONENT_EMBED_TXTFILES variable.
 */
extern uint8_t ca_pem_start[] asm("_binary_fake_ca_pem_start");
extern uint8_t ca_pem_end[] asm("_binary_fake_ca_pem_end");
extern uint8_t client_crt_start[] asm("_binary_fake_client_crt_start");
extern uint8_t client_crt_end[] asm("_binary_fake_client_crt_end");
extern uint8_t client_key_start[] asm("_binary_fake_client_key_start");
extern uint8_t client_key_end[] asm("_binary_fake_client_key_end");
#endif /* CONFIG_COAP_MBEDTLS_PKI */

/*--------------------------------------------------------------
 * build_pdu_Registration()
 * Prepare the registration PDU
 * 	- identifier: The device identifier used when provisioning the device.
 *	- topic: The MQTT topic to publish the device data to.
 *
 * e.g.:
 * Type: Confirmable, message ID: 0
 * Code: 0.02 (POST)
 * Token: 1 bytes 0x52
 * Option 11 (URI Path), 4 bytes: 0x6d717474 ("mqtt")
 * Option 15 (URI Query), 20 bytes: 0x743d2f696f7465726f702f6d7174742f74657374 ("t=/ioterop/mqtt/test")
 * Option 15 (URI Query), 18 bytes: 0x65703d4e65627261736b615f636c69656e74 ("ep=Nebraska_client")
 * ...
*/
coap_pdu_t *build_pdu_Registration(coap_session_t *session)
{
    char buf[127];
    coap_pdu_t *pdu = NULL;

    /* construct CoAP message */
    pdu = coap_new_pdu(session);
    if (!pdu)
    {
        ESP_LOGE(TAG, "cannot create PDU\n");
        return NULL;
    }

    /* Initialize PDU */
    pdu->type = COAP_MESSAGE_CON;
    pdu->tid = coap_new_message_id(session);
    pdu->code = COAP_REQUEST_POST;

    /* Uri-Path */
    coap_add_option(pdu, COAP_OPTION_URI_PATH, strlen(NEBRASKA_URI_PATH), (const unsigned char *)NEBRASKA_URI_PATH);

    /* Identifier */
    snprintf(buf, sizeof(buf), "ep=%s", CONFIG_DEMO_NEBRASKA_ENDPOINT);
    coap_add_option(pdu, COAP_OPTION_URI_QUERY, strlen(buf), (const unsigned char *)buf);

    /* Topic */
    snprintf(buf, sizeof(buf), "t=%s", CONFIG_DEMO_NEBRASKA_TOPIC);
    coap_add_option(pdu, COAP_OPTION_URI_QUERY, strlen(buf), (const unsigned char *)buf);

    /* QoS */
    if (CONFIG_DEMO_NEBRASKA_QOS != -1)
    {
        snprintf(buf, sizeof(buf), "qos=%d", CONFIG_DEMO_NEBRASKA_QOS);
        coap_add_option(pdu, COAP_OPTION_URI_QUERY, strlen(buf), (const unsigned char *)buf);
    }

    /* Keep Alive */
    if (CONFIG_DEMO_NEBRASKA_KEEPALIVE != -1)
    {
        snprintf(buf, sizeof(buf), "ka=%d", CONFIG_DEMO_NEBRASKA_KEEPALIVE);
        coap_add_option(pdu, COAP_OPTION_URI_QUERY, strlen(buf), (const unsigned char *)buf);
    }

    /* Retain Flag */
    if (CONFIG_DEMO_NEBRASKA_RFLAGS != -1)
    {
        snprintf(buf, sizeof(buf), "rf=%d", CONFIG_DEMO_NEBRASKA_RFLAGS);
        coap_add_option(pdu, COAP_OPTION_URI_QUERY, strlen(buf), (const unsigned char *)buf);
    }

    ESP_LOGI(TAG, "=== PDU registration ===");
    coap_show_pdu(LOG_DEBUG, pdu);

    return pdu;
}

/*--------------------------------------------------------------
 * build_pdu_Publication() is called each time you need to update the value
 * that will be published to the MQTT broker
 *
 * e.g.:
 * Type: Confirmable, message ID: 50772
 * Code: 0.03 (PUT)
 * Option 11 (URI Path), 4 bytes: 0x6d717474 ("mqtt")
 * Option 11 (URI Path), 4 bytes: 0x685a704b ("hZpK")
 * Option 12 (Content Format), integer value: 0
 * Payload, 9 bytes: 0x44656d6f2044617461
 */
coap_pdu_t *build_pdu_Publication(coap_session_t *sess)
{
    coap_pdu_t *pdu = NULL;
    char buf_data[32];

    /* construct CoAP message */
    pdu = coap_new_pdu(sess);
    if (!pdu)
    {
        ESP_LOGE(TAG, "cannot create PDU\n");
        return NULL;
    }

    /* Fill pdu fields */
    pdu->type = COAP_MESSAGE_CON;
    pdu->tid = coap_new_message_id(sess);
    pdu->code = COAP_REQUEST_PUT;

    /* add previously saved (from registration) options */
    coap_add_optlist_pdu(pdu, &pub_optlist);

    /* add the Publication options */
    coap_add_option(pdu, COAP_OPTION_CONTENT_FORMAT, 0, NULL);

    /* SAMPLE ! add some Demo Data values */
    wifi_ap_record_t wifidata;
    if (esp_wifi_sta_get_ap_info(&wifidata) == 0)
    {
        snprintf(buf_data, sizeof(buf_data), "si=%d - rnd:%d", wifidata.rssi, rand() % 50);
    }
    else
    {
        snprintf(buf_data, sizeof(buf_data), "rssi=?");
    }

    coap_add_data(pdu, strlen(buf_data), (const unsigned char *)buf_data);

    /* trace */
    ESP_LOGI(TAG, "=== PDU Publication ===");
    coap_show_pdu(LOG_DEBUG, pdu);

    return pdu;
}

/*--------------------------------------------------------------
 * save_register_pub_options() saves the Registration returned values.
 * (default URI and handle). Handle is needed for publishing
 */
void save_register_pub_options(coap_pdu_t *pdu)
{
    char buf[64];
    coap_opt_iterator_t opt_iter;
    coap_opt_t *option;
    coap_optlist_t *opt;

    coap_option_iterator_init(pdu, &opt_iter, COAP_OPT_ALL);

    while ((option = coap_option_next(&opt_iter)))
    {
        if (opt_iter.type == COAP_OPTION_LOCATION_PATH)
        {
            memcpy(buf, coap_opt_value(option), coap_opt_length(option));
            buf[coap_opt_length(option)] = 0; /* Stringify */

            /* Change to URI path */
            coap_log(LOG_DEBUG, "* add opt in list: %s %d\n", buf, coap_opt_length(option));
            opt = coap_new_optlist(COAP_OPTION_URI_PATH, coap_opt_length(option), (const uint8_t *)buf);
            if (opt)
            {
                coap_insert_optlist(&pub_optlist, opt);
            }
        }
    }
}

/*--------------------------------------------------------------
 * message_handler() processes incoming CoAP messages, according to
 * the state.
 * TODO: add checks on return code
 */
static void message_handler(coap_context_t *ctx, coap_session_t *session,
                            coap_pdu_t *sent, coap_pdu_t *received,
                            const coap_tid_t id)
{
    ctx = ctx;
    session = session;
    sent = sent;
    (void)id;

    switch (g_state)
    {
    case CLT_STATE_REGISTRATION_CONNECTING:
        ESP_LOGD(TAG, "Handler: CLT_STATE_REGISTRATION_CONNECTING\n");
        coap_show_pdu(LOG_DEBUG, received);

        /* Check returned code */
        if (COAP_RESPONSE_CLASS(received->code) != 2)
        {
            ESP_LOGE(TAG, "Handler: INVALID CODE  - %d.%02d \n", ((received->code & 0xE0) >> 5), (received->code & 0x1F));
            g_state = CLT_STATE_FAILURE;
            resp_wait = 0;
            break;
        }

        /* On registration, we clean the pub option list */
        if (pub_optlist)
        {
            coap_delete_optlist(pub_optlist);
            pub_optlist = NULL;
        }

        /* ... and save the new options */
        save_register_pub_options(received);
        ESP_LOGI(TAG, "Registration OK %d.%02d \n", ((received->code & 0xE0) >> 5), (received->code & 0x1F));

        g_state = CLT_STATE_RUNNING;
        resp_wait = 0;
        break;

    case CLT_STATE_RUNNING:
        ESP_LOGD(TAG, "Handler: CLT_STATE_RUNNING\n");
        coap_show_pdu(LOG_DEBUG, received);

        /* Check returned code */
        if (COAP_RESPONSE_CLASS(received->code) != 2)
        {
            ESP_LOGE(TAG, "Handler: INVALID CODE  - %d.%02d \n", ((received->code & 0xE0) >> 5), (received->code & 0x1F));
            g_state = CLT_STATE_FAILURE;
            resp_wait = 0;
            break;
        }

        ESP_LOGI(TAG, "Publication OK %d.%02d \n", ((received->code & 0xE0) >> 5), (received->code & 0x1F));
        coap_show_pdu(LOG_DEBUG, received);
        resp_wait = 0;
        break;

    default:
        ESP_LOGE(TAG, "Handler: Unknown state: %d\n", g_state);
        break;
    }
}

#ifdef CONFIG_COAP_MBEDTLS_PKI

static int
verify_cn_callback(const char *cn,
                   const uint8_t *asn1_public_cert,
                   size_t asn1_length,
                   coap_session_t *session,
                   unsigned depth,
                   int validated,
                   void *arg)
{
    coap_log(LOG_INFO, "CN '%s' presented by server (%s)\n",
             cn, depth ? "CA" : "Certificate");
    return 1;
}
#endif /* CONFIG_COAP_MBEDTLS_PKI */

/*--------------------------------------------------------------
 * Main task entry
*/
static void Nebraska_example_client(void *p)
{
    struct hostent *hp;
    coap_address_t dst_addr;
    static coap_uri_t uri;
    const char *server_uri = COAP_DEFAULT_DEMO_URI;
    char *phostname = NULL;

    coap_set_log_level(EXAMPLE_LOG_DEFAULT_LEVEL);

    while (1)
    {
        coap_context_t *ctx = NULL;
        coap_session_t *session = NULL;

        optlist = NULL;
        if (coap_split_uri((const uint8_t *)server_uri, strlen(server_uri), &uri) == -1)
        {
            ESP_LOGE(TAG, "CoAP server uri error");
            break;
        }

        if (uri.scheme == COAP_URI_SCHEME_COAPS && !coap_dtls_is_supported())
        {
            ESP_LOGE(TAG, "MbedTLS (D)TLS Client Mode not configured");
            break;
        }
        if (uri.scheme == COAP_URI_SCHEME_COAPS_TCP && !coap_tls_is_supported())
        {
            ESP_LOGE(TAG, "CoAP server uri coaps+tcp:// scheme is not supported");
            break;
        }

        phostname = (char *)calloc(1, uri.host.length + 1);
        if (phostname == NULL)
        {
            ESP_LOGE(TAG, "calloc failed");
            break;
        }

        memcpy(phostname, uri.host.s, uri.host.length);
        hp = gethostbyname(phostname);
        free(phostname);

        if (hp == NULL)
        {
            ESP_LOGE(TAG, "DNS lookup failed");
            vTaskDelay(1000 / portTICK_PERIOD_MS);
            free(phostname);
            continue;
        }
        char tmpbuf[INET6_ADDRSTRLEN];
        coap_address_init(&dst_addr);
        switch (hp->h_addrtype)
        {
        case AF_INET:
            dst_addr.addr.sin.sin_family = AF_INET;
            dst_addr.addr.sin.sin_port = htons(uri.port);
            memcpy(&dst_addr.addr.sin.sin_addr, hp->h_addr, sizeof(dst_addr.addr.sin.sin_addr));
            inet_ntop(AF_INET, &dst_addr.addr.sin.sin_addr, tmpbuf, sizeof(tmpbuf));
            ESP_LOGI(TAG, "DNS lookup succeeded. IP=%s", tmpbuf);
            break;
        case AF_INET6:
            dst_addr.addr.sin6.sin6_family = AF_INET6;
            dst_addr.addr.sin6.sin6_port = htons(uri.port);
            memcpy(&dst_addr.addr.sin6.sin6_addr, hp->h_addr, sizeof(dst_addr.addr.sin6.sin6_addr));
            inet_ntop(AF_INET6, &dst_addr.addr.sin6.sin6_addr, tmpbuf, sizeof(tmpbuf));
            ESP_LOGI(TAG, "DNS lookup succeeded. IP=%s", tmpbuf);
            break;
        default:
            ESP_LOGE(TAG, "DNS lookup response failed");
            goto clean_up;
        }

        ctx = coap_new_context(NULL);
        if (!ctx)
        {
            ESP_LOGE(TAG, "coap_new_context() failed");
            goto clean_up;
        }

        /*
         * Note that if the URI starts with just coap:// (not coaps://) the
         * session will still be plain text.
         *
         * coaps+tcp:// is NOT supported by the libcoap->mbedtls interface
         * so COAP_URI_SCHEME_COAPS_TCP will have failed in a test above,
         * but the code is left in for completeness.
         */
        if (uri.scheme == COAP_URI_SCHEME_COAPS || uri.scheme == COAP_URI_SCHEME_COAPS_TCP)
        {
#ifndef CONFIG_MBEDTLS_TLS_CLIENT
            ESP_LOGE(TAG, "MbedTLS (D)TLS Client Mode not configured");
            goto clean_up;
#endif /* CONFIG_MBEDTLS_TLS_CLIENT */
#ifdef CONFIG_COAP_MBEDTLS_PSK
            session = coap_new_client_session_psk(ctx, NULL, &dst_addr,
                                                  uri.scheme == COAP_URI_SCHEME_COAPS ? COAP_PROTO_DTLS : COAP_PROTO_TLS,
                                                  EXAMPLE_COAP_PSK_IDENTITY,
                                                  (const uint8_t *)EXAMPLE_COAP_PSK_KEY,
                                                  sizeof(EXAMPLE_COAP_PSK_KEY) - 1);
#endif /* CONFIG_COAP_MBEDTLS_PSK */

#ifdef CONFIG_COAP_MBEDTLS_PKI
            unsigned int ca_pem_bytes = ca_pem_end - ca_pem_start;
            unsigned int client_crt_bytes = client_crt_end - client_crt_start;
            unsigned int client_key_bytes = client_key_end - client_key_start;
            coap_dtls_pki_t dtls_pki;
            static char client_sni[256];

            memset(&dtls_pki, 0, sizeof(dtls_pki));
            dtls_pki.version = COAP_DTLS_PKI_SETUP_VERSION;
            if (ca_pem_bytes)
            {
                /*
                 * Add in additional certificate checking.
                 * This list of enabled can be tuned for the specific
                 * requirements - see 'man coap_encryption'.
                 *
                 * Note: A list of root ca file can be setup separately using
                 * coap_context_set_pki_root_cas(), but the below is used to
                 * define what checking actually takes place.
                 */
                dtls_pki.verify_peer_cert = 1;
                dtls_pki.require_peer_cert = 1;
                dtls_pki.allow_self_signed = 1;
                dtls_pki.allow_expired_certs = 1;
                dtls_pki.cert_chain_validation = 1;
                dtls_pki.cert_chain_verify_depth = 2;
                dtls_pki.check_cert_revocation = 1;
                dtls_pki.allow_no_crl = 1;
                dtls_pki.allow_expired_crl = 1;
                dtls_pki.allow_bad_md_hash = 1;
                dtls_pki.allow_short_rsa_length = 1;
                dtls_pki.validate_cn_call_back = verify_cn_callback;
                dtls_pki.cn_call_back_arg = NULL;
                dtls_pki.validate_sni_call_back = NULL;
                dtls_pki.sni_call_back_arg = NULL;
                memset(client_sni, 0, sizeof(client_sni));
                if (uri.host.length)
                {
                    memcpy(client_sni, uri.host.s, MIN(uri.host.length, sizeof(client_sni)));
                }
                else
                {
                    memcpy(client_sni, "localhost", 9);
                }
                dtls_pki.client_sni = client_sni;
            }
            dtls_pki.pki_key.key_type = COAP_PKI_KEY_PEM_BUF;
            dtls_pki.pki_key.key.pem_buf.public_cert = client_crt_start;
            dtls_pki.pki_key.key.pem_buf.public_cert_len = client_crt_bytes;
            dtls_pki.pki_key.key.pem_buf.private_key = client_key_start;
            dtls_pki.pki_key.key.pem_buf.private_key_len = client_key_bytes;
            dtls_pki.pki_key.key.pem_buf.ca_cert = ca_pem_start;
            dtls_pki.pki_key.key.pem_buf.ca_cert_len = ca_pem_bytes;

            session = coap_new_client_session_pki(ctx, NULL, &dst_addr,
                                                  uri.scheme == COAP_URI_SCHEME_COAPS ? COAP_PROTO_DTLS : COAP_PROTO_TLS,
                                                  &dtls_pki);
#endif /* CONFIG_COAP_MBEDTLS_PKI */
        }
        else
        {
            session = coap_new_client_session(ctx, NULL, &dst_addr,
                                              uri.scheme == COAP_URI_SCHEME_COAP_TCP ? COAP_PROTO_TCP : COAP_PROTO_UDP);
        }
        if (!session)
        {
            ESP_LOGE(TAG, "coap_new_client_session() failed");
            goto clean_up;
        }

        coap_register_response_handler(ctx, message_handler);
        g_state = CLT_STATE_REGISTRATION_NEEDED; /* Initial state */

        while (g_state != CLT_STATE_FAILURE)
        {
            switch (g_state)
            {
            case CLT_STATE_REGISTRATION_NEEDED: /* should be the 1st state */
                ESP_LOGD(TAG, "send PDU(): CLT_STATE_REGISTRATION_NEEDED\n");
                g_state = CLT_STATE_REGISTRATION_CONNECTING;
                /* we build registration PDU and send it */
                coap_pdu_t *pdu = build_pdu_Registration(session);
                if (pdu == NULL)
                {
                    g_state = CLT_STATE_FAILURE;
                    ESP_LOGE(TAG, "Registration_start() failed - exiting");
                }

                /* and send the PDU */
                coap_tid_t ret = coap_send(session, pdu);
                if (COAP_INVALID_TID == ret)
                {
                    g_state = CLT_STATE_FAILURE;
                    ESP_LOGE(TAG, "Registration_send() failed - exiting");
                }
                resp_wait = 1;
                break;

            case CLT_STATE_REGISTRATION_CONNECTING:
                resp_wait = 1;
                break;

            case CLT_STATE_RUNNING:
                ESP_LOGD(TAG, "send PDU(): CLT_STATE_RUNNING\n");
                /* Wait 2s before publishing */
                vTaskDelay(2000 / portTICK_PERIOD_MS);

                pdu = build_pdu_Publication(session);
                coap_send(session, pdu);
                resp_wait = 1;
                break;

            case CLT_STATE_FAILURE:
                goto clean_up;
            }

            /* default CoAP loop */
            wait_ms = COAP_DEFAULT_TIME_SEC * 1000;

            while (resp_wait)
            {
                int result = coap_run_once(ctx, wait_ms > 1000 ? 1000 : wait_ms);
                if (result >= 0)
                {
                    if (result >= wait_ms)
                    {
                        coap_log(LOG_DEBUG, "select timeout\n");
                        break;
                    }
                    else
                    {
                        wait_ms -= result;
                    }
                }
            }
        }

    clean_up:
        if (optlist)
        {
            coap_delete_optlist(optlist);
            optlist = NULL;
        }
        if (session)
        {
            coap_session_release(session);
        }
        if (ctx)
        {
            coap_free_context(ctx);
        }
        coap_cleanup();
        /*
         * change the following line to something like sleep(2)
         * if you want the request to continually be sent
         */
        break;
    }

    vTaskDelete(NULL);
}

void app_main(void)
{
    ESP_ERROR_CHECK(nvs_flash_init());
    ESP_ERROR_CHECK(esp_netif_init());
    ESP_ERROR_CHECK(esp_event_loop_create_default());

    /* This helper function configures Wi-Fi or Ethernet, as selected in menuconfig.
     * Read "Establishing Wi-Fi or Ethernet Connection" section in
     * examples/protocols/README.md for more information about this function.
     */
    ESP_ERROR_CHECK(example_connect());

    xTaskCreate(Nebraska_example_client, "coap", 8 * 1024, NULL, 5, NULL);
}
