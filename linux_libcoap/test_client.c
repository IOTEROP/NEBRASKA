/* -----------------------------------------------------------
 * Linux sample code for Nebraska
 *
 *  Copyright (C) 2021 Ioterop - All rigghts reserved
 *
 * This code is given "as-is" without any guarantees
 *
 * Steps:
 *     Send a Registration request to Nebraska Server (POST)
 *     NB returns a handle to the AWS IoT Core
 *     The client loops on publishing (CoAP) on the associated topic
 *         using the handle (PUT)
 *
 * Requirements:
 *  To build this sample:
 *  -   libcoap 4.2.1
 *
 *  To run this sample:
 *  - AWS IoT Core account
 *  - Nebraska account:
 *      (https://aws.amazon.com/marketplace/pp/IoTerop-Nebraska/B08PPS33V5​)
 *
 *-----------------------------------------------------------*/

#include "coap2/coap.h"
#include <stdio.h>
#include <stdbool.h>
#include <time.h>

#include <netdb.h>
#include <arpa/inet.h>

/* State machine */
typedef enum
{
    CLT_STATE_FAILURE,
    CLT_STATE_REGISTRATION_NEEDED, /* Initial state */
    CLT_STATE_REGISTRATION_CONNECTING,
    CLT_STATE_REGISTRATION_ONGOING,

    CLT_STATE_RUNNING
} client_state_t;

client_state_t state;

/* saved (after registration) options list */
static coap_optlist_t *pub_optlist = NULL;

#define COAP_DEFAULT_TIME_SEC 5
static int resp_wait = 1;

/* */
#define NEBRASKA_SERVER_URI "coaps://ingress.nebraska.ioterop.com:18834"
#define DEFAULT_URI_PATH "mqtt"

/* Sample PKS values */
#define EXAMPLE_COAP_PSK_KEY "abcdef" /* ! if coded in base64: "YWJjZGVm" */
#define EXAMPLE_COAP_PSK_IDENTITY "MqttIdentity"

#define EXAMPLE_ENDPOINT_NAME "Nebraska_client_1"
#define EXAMPLE_TOPIC "/demo/test_1"

/*--------------------------------------------------------------
* build_pdu_Registration()
* Prepare the registration PDU
* 	- identifier: The device identifier used when provisioning the device.
*	- topic: The MQTT topic to publish the device data to.
*/
coap_pdu_t *build_pdu_Registration(coap_session_t *sess,
                                   char *identifier,
                                   char *topic,
                                   int QoS,
                                   int KeepAlive,
                                   int RetainFlag)
{
    char buf[127];
    coap_pdu_t *pdu = NULL;

    /* construct CoAP message */
    pdu = coap_new_pdu(sess);
    if (!pdu)
    {
        coap_log(LOG_EMERG, "cannot create PDU\n");
        return NULL;
    }

    /* Fill pdu fields */
    pdu->type = COAP_MESSAGE_CON;
    pdu->tid = coap_new_message_id(sess);
    pdu->code = COAP_REQUEST_POST;

    /* add some Uri-Path options */
    coap_add_option(pdu, COAP_OPTION_URI_PATH, strlen(DEFAULT_URI_PATH), (const unsigned char *)DEFAULT_URI_PATH);

    /* Identifier */
    snprintf(buf, sizeof(buf), "ep=%s", identifier);
    coap_add_option(pdu, COAP_OPTION_URI_QUERY, strlen(buf), (const unsigned char *)buf);

    /* Topic */
    snprintf(buf, sizeof(buf), "t=%s", topic);
    coap_add_option(pdu, COAP_OPTION_URI_QUERY, strlen(buf), (const unsigned char *)buf);

    /* QoS */
    if (QoS != -1)
    {
        snprintf(buf, sizeof(buf), "qos=%d", QoS);
        coap_add_option(pdu, COAP_OPTION_URI_QUERY, strlen(buf), (const unsigned char *)buf);
    }

    /* Keep Alive */
    if (KeepAlive != -1)
    {
        snprintf(buf, sizeof(buf), "ka=%d", KeepAlive);
        coap_add_option(pdu, COAP_OPTION_URI_QUERY, strlen(buf), (const unsigned char *)buf);
    }

    /* Retain Flag */
    if (RetainFlag != -1)
    {
        snprintf(buf, sizeof(buf), "rf=%d", RetainFlag);
        coap_add_option(pdu, COAP_OPTION_URI_QUERY, strlen(buf), (const unsigned char *)buf);
    }

    coap_log(LOG_DEBUG, "=== PDU registration: ===\n");
    coap_show_pdu(LOG_DEBUG, pdu);
    coap_log(LOG_DEBUG, "===\n");

    return pdu;
}

/*--------------------------------------------------------------
* build_pdu_Publication is called each time you need to change the value
* that will be published to the MQTT broker
*/
coap_pdu_t *build_pdu_Publication(coap_session_t *sess)
{
    coap_pdu_t *pdu = NULL;
    char buf_data[32];

    /* construct CoAP message */
    pdu = coap_new_pdu(sess);
    if (!pdu)
    {
        coap_log(LOG_EMERG, "cannot create PDU\n");
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

    /* add the Demo Data Value */
    snprintf(buf_data, sizeof(buf_data), "Value=%d", rand() % 50);
    coap_add_data(pdu, strlen(buf_data), (const unsigned char *)buf_data);

    /* trace */
    coap_log(LOG_INFO, "=== PDU Publication ===\n");
    coap_show_pdu(LOG_INFO, pdu);

    return pdu;
}

/* ---------------------------------------------
* Start registration for device "Nebraska_client_1" (already
* registered on Nebraska, on topic "/demo/test_1"
*/
coap_tid_t Registration_start(coap_session_t *sess)
{
    coap_pdu_t *pdu = NULL;
    coap_tid_t ret;

    if (sess == NULL)
    {
        coap_log(LOG_EMERG, "Registration_start: invalid session");
        return COAP_INVALID_TID;
    }

    /* we build registration PDU and send it */
    pdu = build_pdu_Registration(sess, EXAMPLE_ENDPOINT_NAME, EXAMPLE_TOPIC, 0, 120, 1);

    /* and send the PDU */
    ret = coap_send(sess, pdu);

    return ret;
}

/* =======================================================================
* Will save the returned values (on registration), for subsequent use (pub)
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

/* ---------------------------------------------
* message handler for POST and PUT answers
 */
static void message_handler(coap_context_t *ctx, coap_session_t *session,
                            coap_pdu_t *sent, coap_pdu_t *received,
                            const coap_tid_t id)
{
    ctx = ctx;
    session = session;
    sent = sent;
    (void)id;

    switch (state)
    {
    case CLT_STATE_REGISTRATION_CONNECTING:
        coap_log(LOG_DEBUG, "Handler: CLT_STATE_REGISTRATION_CONNECTING\n");
        coap_show_pdu(LOG_DEBUG, received);

        /* On registration, we clean the pub option list */
        if (pub_optlist)
        {
            coap_delete_optlist(pub_optlist);
            pub_optlist = NULL;
        }

        /* .. and save the new options */
        save_register_pub_options(received);

        state = CLT_STATE_RUNNING;
        resp_wait = 0;
        break;

    case CLT_STATE_RUNNING:
        coap_log(LOG_DEBUG, "Handler: CLT_STATE_RUNNING\n");
        coap_show_pdu(LOG_DEBUG, received);
        /* do what you want */
        /* ... */

        resp_wait = 0;
        break;

    default:
        coap_log(LOG_DEBUG, "Handler: Unknown state: %d\n", state);
        break;
    }
}

/*========================================================================
* Main entry point
*/
int main(void)
{
    coap_context_t *ctx = NULL;
    coap_session_t *session = NULL;

    coap_pdu_t *pdu = NULL;
    static coap_uri_t uri;
    int result = EXIT_FAILURE;
    const char *server_uri = NEBRASKA_SERVER_URI;
    char *phostname = NULL;
    struct hostent *hp;
    bool g_quit = false;
    int wait_ms;
    char tmpbuf[INET6_ADDRSTRLEN];

    coap_address_t dst_addr;

    /* Set log output */
    coap_set_log_level(LOG_INFO);
    //coap_set_log_level(LOG_DEBUG);

    /* rand init for the demo value */
    srand(time(0));

    /* Crack the full URI in uri struct */
    if (coap_split_uri((const uint8_t *)server_uri, strlen(server_uri), &uri) == -1)
    {
        coap_log(LOG_EMERG, "CoAP server uri error");
        goto finish;
    }

    /* check URI scheme */
    if (uri.scheme == COAP_URI_SCHEME_COAPS && !coap_dtls_is_supported())
    {
        coap_log(LOG_EMERG, "MbedTLS (D)TLS Client Mode not configured");
        goto finish;
    }

    /* Additional check on TCP + TLS */
    if (uri.scheme == COAP_URI_SCHEME_COAPS_TCP && !coap_tls_is_supported())
    {
        coap_log(LOG_EMERG, "CoAP server uri coaps+tcp:// scheme is not supported");
        goto finish;
    }

    /* Fill hostent if possible... */
    phostname = (char *)calloc(1, uri.host.length + 1);
    if (phostname == NULL)
    {
        coap_log(LOG_EMERG, "calloc failed");
        goto finish;
    }
    memcpy(phostname, uri.host.s, uri.host.length);
    hp = gethostbyname(phostname);

    coap_log(LOG_DEBUG, "Host name: %s\n", phostname);
    free(phostname);

    if (hp == NULL)
    {
        coap_log(LOG_CRIT, "DNS lookup failed\n");
        goto finish;
    }

    /* Get the IP address ... */
    coap_address_init(&dst_addr);

    switch (hp->h_addrtype)
    {
    case AF_INET:
        dst_addr.addr.sin.sin_family = AF_INET;
        dst_addr.addr.sin.sin_port = htons(uri.port);
        memcpy(&dst_addr.addr.sin.sin_addr, hp->h_addr, sizeof(dst_addr.addr.sin.sin_addr));
        inet_ntop(AF_INET, &dst_addr.addr.sin.sin_addr, tmpbuf, sizeof(tmpbuf));
        coap_log(LOG_DEBUG, "DNS ipv4 lookup succeeded. IP=%s\n", tmpbuf);
        break;

    case AF_INET6:
        dst_addr.addr.sin6.sin6_family = AF_INET6;
        dst_addr.addr.sin6.sin6_port = htons(uri.port);
        memcpy(&dst_addr.addr.sin6.sin6_addr, hp->h_addr, sizeof(dst_addr.addr.sin6.sin6_addr));
        inet_ntop(AF_INET6, &dst_addr.addr.sin6.sin6_addr, tmpbuf, sizeof(tmpbuf));
        coap_log(LOG_DEBUG, "DNS ipv6 lookup succeeded. IP=%s\n", tmpbuf);
        break;
    default:
        coap_log(LOG_CRIT, "DNS lookup response failed\n");
        goto finish;
    }

    /* Stage #2 : coap */
    ctx = coap_new_context(NULL);
    if (!ctx)
    {
        coap_log(LOG_EMERG, "coap_new_context() failed\n");
        goto finish;
    }

    /* Start session with TLS (PSK) or not */
    if (uri.scheme == COAP_URI_SCHEME_COAPS || uri.scheme == COAP_URI_SCHEME_COAPS_TCP)
    {
        session = coap_new_client_session_psk(ctx, NULL, &dst_addr,
                                              uri.scheme == COAP_URI_SCHEME_COAPS ? COAP_PROTO_DTLS : COAP_PROTO_TLS,
                                              EXAMPLE_COAP_PSK_IDENTITY,
                                              (const uint8_t *)EXAMPLE_COAP_PSK_KEY,
                                              sizeof(EXAMPLE_COAP_PSK_KEY) - 1);
    }
    else
    {
        coap_log(LOG_EMERG, "Cannot find psk scheme / coap_new_client_session_psk() failed");
        goto finish;
    }

    /* Are we unable to create a session ? */
    if (!session)
    {
        coap_log(LOG_EMERG, "coap_new_client_session() failed");
        goto finish;
    }
    coap_log(LOG_INFO, "coap_new_client_session() OK\n");

    /* Register the response handler */
    coap_register_response_handler(ctx, message_handler);

    /* Stage #3, the main loop */
    state = CLT_STATE_REGISTRATION_NEEDED; /* Initial state */
    result = 0;
    g_quit = false; /* "loopxit" */

    while (g_quit == false && result >= 0)
    {
        switch (state)
        {
        case CLT_STATE_REGISTRATION_NEEDED: /* should be the 1st state */
            coap_log(LOG_DEBUG, "send PDU(): CLT_STATE_REGISTRATION_NEEDED\n");
            state = CLT_STATE_REGISTRATION_CONNECTING;
            if (COAP_INVALID_TID == Registration_start(session))
            {
                state = CLT_STATE_FAILURE;
                coap_log(LOG_EMERG, "Registration_start() failed - exiting");
            }
            resp_wait = 1;
            break;

        case CLT_STATE_REGISTRATION_CONNECTING:
            resp_wait = 1;
            break;

        case CLT_STATE_REGISTRATION_ONGOING:
            resp_wait = 1;
            /* ! Expected skip break; */

        case CLT_STATE_RUNNING:
            coap_log(LOG_DEBUG, "send PDU(): CLT_STATE_RUNNING\n");

            pdu = build_pdu_Publication(session);
            coap_send(session, pdu);
            resp_wait = 1;
            break;

        case CLT_STATE_FAILURE:
            goto finish;
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

finish:

    coap_session_release(session);
    coap_free_context(ctx);
    coap_cleanup();

    return result;
}
