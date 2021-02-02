/*
 * Copyright (c) 2021 Ioterop
 *
 * NEBRASKA client sample code.
 *
 * This code runs on nRF9160DK board / LTE mode
 * Registration on NEBRASKA homepage is needed !
 *
 * This client will:
 *  - Establish a modem session
 *  - The data session uses a PSK (previously provisionned on NEBRASKA server)
 *  - The client sends a registration request to the NB server
 *  - The NB server sends an ACK to the client
 *  - - The NB server checks with AWS the credentials
 *  - - The NB server gets validation token from AWS
 *  - The NB server post a message which contains a valid path
 *  - The client acknowledges the message (ACK)
 *  - Using the valid path, the client can publish to the MQTT broker (waiting 3s between each publication)
 *
 * NOTES:
 *  - The PSK key should be in "clear": e.g.: "abcdef" (vs base64=>"YWJjZGVm")
 *
 * Copyright (c) 2021 Ioterop
 * (original code from Nordic Semiconductor ASA)
 *
 */

#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include <modem/lte_lc.h>
#include <modem/modem_key_mgmt.h>
#include <net/coap.h>
#include <net/socket.h>
#include <net/tls_credentials.h>
#include <random/rand32.h>
#include <zephyr.h>

/* State machine */
/* ! don't change order. see waiting_for_ACK(): state +/-1 */
typedef enum
{
    CLT_STATE_REGISTRATION_NEEDED = 0, /* Initial state */
    CLT_STATE_REGISTRATION_ACK,
    CLT_STATE_REGISTRATION_RESULT,

    CLT_STATE_PUBLICATION_START,
    CLT_STATE_PUBLICATION_ACK,
    CLT_STATE_PUBLICATION_RESULT,

    CLT_STATE_FAILURE
} client_state_t;

client_state_t state;

#if !defined(CONFIG_COAP_DTLS_SUPPORT)
#error "This sample needs CONFIG_COAP_DTLS_SUPPORT=y to run"
#endif /* CONFIG_COAP_DTLS_SUPPORT */

#define APP_COAP_SEND_INTERVAL_MS 5000
#define APP_COAP_MAX_MSG_LEN 1280
#define APP_COAP_VERSION 1
/* nRF9160DK Secured key tag */
#define BOARD_TLS_TAG 19660228

#define COAP_RESULT_MAJOR(a) ((a & 0xE0) >> 5)
#define COAP_RESULT_MINOR(a) (a & 0x1F)

/* This is the default Nebraska Location-Path */
static char default_Nebraska_Path[] = "mqtt";

/* Harcoded demo values */
static char DEMO_QOS[] = "qos=0";
static char DEMO_KA[] = "ka=120";
static char DEMO_RF[] = "rf=1";

#if defined(CONFIG_COAP_DTLS_SUPPORT)
static char client_identity[] = CONFIG_NEBRASKA_DEMO_PSK_IDENTITY; /*e.g.: "MqttIdentity" */
static char client_psk[] = CONFIG_NEBRASKA_DEMO_PSK_KEY;           /* e.g. "abcdef" - see NOTES */
#endif

static int sock;
static struct pollfd fds;
static struct sockaddr_storage server;
static uint16_t next_token;

static uint8_t coap_buf[APP_COAP_MAX_MSG_LEN];

#define MAX_NEBRASKA_OPTIONS 2
struct coap_option options[MAX_NEBRASKA_OPTIONS];

#if defined(CONFIG_BSD_LIBRARY)

/**@brief Recoverable BSD library error. */
void bsd_recoverable_error_handler(uint32_t err)
{
    printk("bsdlib recoverable error: %u\n", (unsigned int)err);
}

#endif /* defined(CONFIG_BSD_LIBRARY) */

/* Enable or disable function to dump CoAP structure */
//#define DUMP_DEBUG

#ifdef DUMP_DEBUG
static void dump_hexa(const char *str, uint8_t *packet, size_t length)
{

    printk("\n--------------dump beg-------------------\n");

    int n = 0;

    if (!length)
    {
        printk("%s zero-length frame\n", str);
        return;
    }

    while (length--)
    {
        if (n % 16 == 0)
        {
            printk("\n\t%s %08X ", str, n);
        }

        printk("%02X ", *packet++);

        n++;
        if (n % 8 == 0)
        {
            if (n % 16 == 0)
            {
                printk("");
            }
            else
            {
                printk(" ");
            }
        }
    }

    if (n % 16)
    {
        printk("\n");
    }
    printk("\n");
}

static void pdu_hexdump(const char *str, uint8_t *packet, size_t length)
{

    struct coap_packet reply;
    uint8_t type;

    uint8_t opt_num = 32;
    struct coap_option options[32];
    uint8_t token[16];
    size_t length_save = length;
    uint8_t *packet_save = packet;

    dump_hexa(str, packet, length);

    int err = coap_packet_parse(&reply, packet_save, length_save, options,
                                opt_num);
    if (err < 0)
    {
        printk("Malformed response received: %d", err);
        return;
    }

    type = coap_header_get_type(&reply);
    switch (type)
    {
    case COAP_TYPE_CON:
        printk("\tType:COAP_TYPE_CON\n");
        break;
    case COAP_TYPE_NON_CON:
        printk("\tType:COAP_TYPE_NON_CON\n");
        break;
    case COAP_TYPE_ACK:
        printk("\tType:COAP_TYPE_ACK\n");
        break;
    case COAP_TYPE_RESET:
        printk("\tType:COAP_TYPE_RESET\n");
        break;
    default:
        printk("\tTyp ??: %d (0x%02X)", type, type);
        break;
    }

    uint8_t token_len = coap_header_get_token(&reply, token);
    printk("\tToken len: %d - ", token_len);
    for (int i = 0; i < token_len; i++)
        printk("%02X ", token[i]);
    printk("\n");

    uint8_t icode = coap_header_get_code(&reply);
    printk("\tCode: %d.%02d (icode:0x%02x) \n", ((icode & 0xE0) >> 5), (icode & 0x1F), icode);

    printk("\tOptions:\n");
    for (int i = 0; i < 32; i++)
    {
        if (options[i].len != 0)
        {
            printk("\t\t-->opt id# %d \n", i);
            printk("\t\tdelta: 0x%04X\n", options[i].delta);
            printk("\t\tlen: 0x%02X\n", options[i].len);
            printk("\t\tvalue: ");
            for (int j = 0; j < 12; j++)
                printk("%02X ", options[i].value[j]);
            printk("\n");
        }
    }
    printk("\n--------------dump end----------------\n");
}
#endif

/**@brief Resolves the configured hostname. */
static int server_resolve(void)
{
    int err;
    struct addrinfo *result;
    struct addrinfo hints = {
        .ai_family = AF_INET,
        .ai_socktype = SOCK_DGRAM};
    char ipv4_addr[NET_IPV4_ADDR_LEN];

    err = getaddrinfo(CONFIG_NEBRASKA_SERVER_HOSTNAME, NULL, &hints, &result);
    if (err != 0)
    {
        printk("ERROR: getaddrinfo failed %d\n", err);
        return -EIO;
    }

    if (result == NULL)
    {
        printk("ERROR: Address not found\n");
        return -ENOENT;
    }

    /* IPv4 Address. */
    struct sockaddr_in *server4 = ((struct sockaddr_in *)&server);

    server4->sin_addr.s_addr =
        ((struct sockaddr_in *)result->ai_addr)->sin_addr.s_addr;
    server4->sin_family = AF_INET;
    server4->sin_port = htons(CONFIG_NEBRASKA_SERVER_PORT);

    inet_ntop(AF_INET, &server4->sin_addr.s_addr, ipv4_addr,
              sizeof(ipv4_addr));
    printk("IPv4 Address found %s\n", ipv4_addr);

    /* Free the address. */
    freeaddrinfo(result);

    return 0;
}

/**@brief Add socket credentials according to security tag */
static int socket_sectag_set(int fd, int sec_tag)
{
    int err;
    int verify;
    sec_tag_t sec_tag_list[] = {sec_tag};

    enum
    {
        NONE = 0,
        OPTIONAL = 1,
        REQUIRED = 2,
    };

    verify = NONE;

    err = setsockopt(fd, SOL_TLS, TLS_PEER_VERIFY, &verify, sizeof(verify));
    if (err)
    {
        printk("Failed to setup peer verification, errno %d\n", errno);
        return -errno;
    }

    printk("Setting up TLS credentials, tag %d\n", sec_tag);
    err = setsockopt(fd, SOL_TLS, TLS_SEC_TAG_LIST, sec_tag_list,
                     sizeof(sec_tag_t) * ARRAY_SIZE(sec_tag_list));
    if (err)
    {
        printk("Failed to setup socket security tag, errno %d\n", errno);
        return -errno;
    }

    return 0;
}

/**@brief Initialize the CoAP client. */
static int client_init(void)
{
    int err;

    sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_DTLS_1_2);
    if (sock < 0)
    {
        printk("Failed to create CoAP socket: %d.\n", errno);
        return -errno;
    }

    err = socket_sectag_set(sock, BOARD_TLS_TAG);
    if (err)
    {
        printk("Failed on socket_sectag_set: %d.\n", err);
        return err;
    }

    err = connect(sock, (struct sockaddr *)&server,
                  sizeof(struct sockaddr_in));
    if (err < 0)
    {
        printk("Connect failed : %d\n", errno);
        return -errno;
    }

    /* Initialize FDS, for poll. */
    fds.fd = sock;
    fds.events = POLLIN;

    /* Randomize token. */
    next_token = sys_rand32_get();

    return 0;
}

/**@brief Send ACK to incoming CON CoAP message. */
static int send_reply_ack(uint16_t id, uint8_t *token, uint8_t tkl)
{
    struct coap_packet request;
    uint8_t *data;
    int ret;

    data = (uint8_t *)k_malloc(APP_COAP_MAX_MSG_LEN);
    if (!data)
    {
        return -ENOMEM;
    }

    ret = coap_packet_init(&request, data, APP_COAP_MAX_MSG_LEN,
                           1, COAP_TYPE_ACK, tkl, token, 0, id);
    if (ret < 0)
    {
        printk("Failed to init CoAP message");
        goto end;
    }

    ret = send(sock, request.data, request.offset, 0);
end:
    k_free(data);

    return ret;
}

/**@brief Handles responses from the remote CoAP server. */
static int client_handle_get_response(uint8_t *buf, int received)
{
    int err;
    struct coap_packet reply;
    uint8_t token[8];
    uint16_t token_len;
    uint8_t type;

    printk("client_handle_get_response (%d)\n", received);

    err = coap_packet_parse(&reply, buf, received, NULL, 0);
    if (err < 0)
    {
        printk("Malformed response received: %d\n", err);
        return err;
    }

    /* check the type */
    type = coap_header_get_type(&reply);

    /* check if we receive an ACK */
    if (type == COAP_TYPE_ACK)
    {
        return 0;
    }

    /* check the roken */
    token_len = coap_header_get_token(&reply, token);
    if ((token_len != sizeof(next_token)) &&
        (memcmp(&next_token, token, sizeof(next_token)) != 0))
    {
        printk("Invalid token received: 0x%02x%02x\n",
               token[1], token[0]);
        return 0;
    }

    if (type == COAP_TYPE_CON)
    {
        uint16_t id = coap_header_get_id(&reply);
        send_reply_ack(id, token, sizeof(next_token));
    }

    return err;
}

/**@brief Send NEBRASKA registration.
 * - CoAP POST/CON request.
 */
static int client_get_send_REGISTRATION(void)
{
    int err;
    struct coap_packet request;
    char buf[128];
    uint16_t next_id;

    printk("Send REGISTRATION request\n");
    next_token++;

    next_id = coap_next_id();

    err = coap_packet_init(&request, coap_buf, APP_COAP_MAX_MSG_LEN,
                           APP_COAP_VERSION,
                           COAP_TYPE_CON,
                           sizeof(next_token), (uint8_t *)&next_token,
                           COAP_METHOD_POST,
                           next_id);
    if (err < 0)
    {
        printk("Failed to create CoAP request, %d\n", err);
        return err;
    }

    err = coap_packet_append_option(&request, COAP_OPTION_URI_PATH,
                                    (uint8_t *)default_Nebraska_Path,
                                    strlen(default_Nebraska_Path));
    if (err < 0)
    {
        printk("Failed to encode CoAP option Nebraska_Path, %d\n", err);
        return err;
    }

    /* for Registration test only */
    snprintf(buf, sizeof(buf) - 1, "t=%s", CONFIG_NEBRASKA_DEMO_TOPIC);
    err = coap_packet_append_option(&request, COAP_OPTION_URI_QUERY,
                                    (uint8_t *)buf, strlen(buf));
    if (err < 0)
    {
        printk("Failed to encode CoAP option {%s}, %d\n", buf, err);
        return err;
    }

    snprintf(buf, sizeof(buf) - 1, "ep=%s", CONFIG_NEBRASKA_DEMO_CLIENT);
    err = coap_packet_append_option(&request, COAP_OPTION_URI_QUERY,
                                    (uint8_t *)buf, strlen(buf));
    if (err < 0)
    {
        printk("Failed to encode CoAP option {%s}, %d\n", buf, err);
        return err;
    }

    err = coap_packet_append_option(&request, COAP_OPTION_URI_QUERY,
                                    (uint8_t *)DEMO_QOS, strlen(DEMO_QOS));
    if (err < 0)
    {
        printk("Failed to encode CoAP option DEMO_QOS, %d\n", err);
        return err;
    }

    err = coap_packet_append_option(&request, COAP_OPTION_URI_QUERY,
                                    (uint8_t *)DEMO_KA, strlen(DEMO_KA));
    if (err < 0)
    {
        printk("Failed to encode CoAP option DEMO_KA, %d\n", err);
        return err;
    }

    err = coap_packet_append_option(&request, COAP_OPTION_URI_QUERY,
                                    (uint8_t *)DEMO_RF, strlen(DEMO_RF));
    if (err < 0)
    {
        printk("Failed to encode CoAP option DEMO_RF, %d\n", err);
        return err;
    }

    printk("send REG COAP: CON/POST - ID:x%04X Token:0x%04X\n", next_id, next_token);
    err = send(sock, request.data, request.offset, 0);
    if (err < 0)
    {
        printk("Failed to send CoAP request, %d\n", errno);
        return -errno;
    }

    printk("CoAP request sent: token 0x%04x\n", next_token);

    return 0;
}

/**@brief Send NEBRASKA Publication.
 * - CoAP PUT/CON request.
 */
static int client_get_send_PUBLICATION(struct coap_option *options, uint8_t max_options, char *payload)
{
    int err;
    struct coap_packet request;

    printk("Prepare PUBLICATION request\n");
    next_token++;
    err = coap_packet_init(&request, coap_buf, APP_COAP_MAX_MSG_LEN,
                           APP_COAP_VERSION, COAP_TYPE_CON,
                           sizeof(next_token), (uint8_t *)&next_token,
                           COAP_METHOD_PUT, coap_next_id());
    if (err < 0)
    {
        printk("Failed to create CoAP request, %d\n", err);
        return err;
    }

    /* Add mandatory options
    * these values (path & handle) are stored in a global array
    */
    for (int i = 0; i < max_options; i++)
    {
        err = coap_packet_append_option(&request,
                                        COAP_OPTION_URI_PATH,
                                        (uint8_t *)options[i].value, options[i].len);
        if (err < 0)
        {
            printk("Failed to encode CoAP option, %d\n", err);
            return err;
        }
    }

    /* Add payload (string) */
    err = coap_packet_append_payload_marker(&request);
    if (err < 0)
    {
        printk("Failed to add payload marker %d\n", err);
        return err;
    }

    err = coap_packet_append_payload(&request, (uint8_t *)payload,
                                     strlen(payload));
    if (err < 0)
    {
        printk("Failed to add payload %d\n", err);
        return err;
    }

#ifdef DUMP_DEBUG
    dump_hexa("AAA", request.data, request.offset);
#endif

    err = send(sock, request.data, request.offset, 0);
    if (err < 0)
    {
        printk("Failed to send CoAP request, %d\n", errno);
        return -errno;
    }

    printk("CoAP request sent: token 0x%04x\n", next_token);

    return 0;
}

/**@brief Configures modem to provide LTE link. Blocks until link is
 * successfully established.
 */
static int modem_configure(void)
{
#if defined(CONFIG_LTE_LINK_CONTROL)
    if (IS_ENABLED(CONFIG_LTE_AUTO_INIT_AND_CONNECT))
    {
        /* Do nothing, modem is already turned on
		 * and connected.
		 */
        return 0;
    }
    else
    {
        int err;

#if defined(CONFIG_COAP_DTLS_SUPPORT)
        char psk_hex[64];
        uint16_t psk_len;

        /* Convert PSK to a format accepted by the modem storage. */
        psk_len = bin2hex(client_psk, strlen(client_psk), psk_hex,
                          sizeof(psk_hex));
        if (psk_len == 0)
        {
            printk("PSK is too large to convert.");
            return -ENOBUFS;
        }

        /* Store keys in the modem */
        err = modem_key_mgmt_write(BOARD_TLS_TAG,
                                   MODEM_KEY_MGMT_CRED_TYPE_PSK,
                                   psk_hex, psk_len);
        if (err < 0)
        {
            printk("Error setting cred tag %d type %d: Error %d",
                   BOARD_TLS_TAG, MODEM_KEY_MGMT_CRED_TYPE_PSK,
                   err);
            return err;
        }

        err = modem_key_mgmt_write(BOARD_TLS_TAG,
                                   MODEM_KEY_MGMT_CRED_TYPE_IDENTITY,
                                   client_identity,
                                   strlen(client_identity));
        if (err < 0)
        {
            printk("Error setting cred tag %d type %d: Error %d",
                   BOARD_TLS_TAG,
                   MODEM_KEY_MGMT_CRED_TYPE_IDENTITY, err);
            return err;
        }

#endif /* defined(CONFIG_COAP_DTLS_SUPPORT) */
        printk("LTE Link Connecting ...\n");
        err = lte_lc_init_and_connect();
        __ASSERT(err == 0, "LTE link could not be established.");
        printk("LTE Link Connected!\n");
    }
#endif /* defined(CONFIG_LTE_LINK_CONTROL) */

    return 0;
}

/**@brief wait for a network event. */
static int wait(int timeout)
{
    int ret = poll(&fds, 1, timeout);

    if (ret < 0)
    {
        printk("poll error: %d\n", errno);
        return -errno;
    }

    if (ret == 0)
    {
        /* Timeout. */
        return -EAGAIN;
    }

    if ((fds.revents & POLLERR) == POLLERR)
    {
        printk("wait: POLLERR\n");
        return -EIO;
    }

    if ((fds.revents & POLLNVAL) == POLLNVAL)
    {
        printk("wait: POLLNVAL\n");
        return -EBADF;
    }

    if ((fds.revents & POLLIN) != POLLIN)
    {
        return -EAGAIN;
    }

    return 0;
}

/**@brief get network incoming bytes. */
static int get_server_answer(int64_t remaining)
{
    int err, received;

    err = wait(remaining);
    if (err < 0)
    {
        if (err == -EAGAIN)
        {
            return 0;
        }

        printk("Poll error, exit...\n");
        return err; /* state = CLT_STATE_FAILURE; */
    }

    /* Handle incoming datas and process */
    received = recv(sock, coap_buf, sizeof(coap_buf), MSG_DONTWAIT);
    if (received < 0)
    {
        if (errno == EAGAIN || errno == EWOULDBLOCK)
        {
            printk("socket EAGAIN\n");
            return 0; /* EAGAIN */
        }
        else
        {
            printk("Socket error, exit...\n");
            return received;
        }
    }

    if (received == 0)
    {
        printk("Empty datagram\n");
        return 0;
    }

    return received;
}

/**@brief Will change the status of "state" if there's a ACK
 * on the incoming CoAP frame
 */
static client_state_t waiting_for_ACK(client_state_t state, int64_t *next_msg_time, int64_t *remaining)
{
    int err, received;
    client_state_t ret_state = state;

    /* timeout => resend */
    if (k_uptime_get() >= *next_msg_time)
    {
        *next_msg_time = k_uptime_get();
        ret_state = state - 1; /* previous state */
        goto end;
    }

    /* how long should we wait ...*/
    *remaining = *next_msg_time - k_uptime_get();
    if (*remaining < 0)
    {
        *remaining = 0;
    }

    /* Check if there is some incoming data */
    received = get_server_answer(*remaining);
    if (received < 0)
    {
        ret_state = CLT_STATE_FAILURE; /* error / fatal */
        goto end;
    }

    if (received == 0)
    {
        ret_state = state;
        goto end;
    }

    /* process the received bytes */
    err = client_handle_get_response(coap_buf, received);
    if (err < 0)
    {
        printk("Invalid response, exit...\n");
        ret_state = state;
        goto end; /* No change */
    }

    if (err == 0)
    {
        printk("\tACK received\n");
        ret_state = state + 1; /* next state */
        goto end;
    }

end:
    return ret_state;
}

/**@brief get the result code frame */
client_state_t get_result_code(client_state_t state, uint8_t *icode,
                               struct coap_option *opt, uint8_t max_opts,
                               int64_t *next_msg_time, int64_t *remaining)
{
    int err, received;
    client_state_t ret_state = state;
    struct coap_packet reply;

    /* timeout => resend */
    if (k_uptime_get() >= *next_msg_time)
    {
        *next_msg_time = k_uptime_get();
        ret_state = state - 1; /* previous state */
        goto end;
    }

    /* how long should we wait ...*/
    *remaining = *next_msg_time - k_uptime_get();
    if (*remaining < 0)
    {
        *remaining = 0;
    }

    /* Check if there is some incoming data---*/
    received = get_server_answer(*remaining);
    if (received < 0)
    {
        ret_state = CLT_STATE_FAILURE; /* error / fatal */
        goto end;
    }

    if (received == 0)
    {
        ret_state = state;
        goto end;
    }

    /* process the received bytes */
    err = client_handle_get_response(coap_buf, received);
    if (err < 0)
    {
        printk("Invalid response, exit...\n");
        ret_state = state;
        goto end; /* No change */
    }

    err = coap_packet_parse(&reply, coap_buf, received, opt, max_opts);
    if (err < 0)
    {
        printk("Malformed response received: %d\n", err);
        ret_state = CLT_STATE_FAILURE; // TODO decide if we fail or not
        goto end;
    }

    *icode = coap_header_get_code(&reply);

    ret_state = state + 1;
    *next_msg_time = k_uptime_get();

end:
    return ret_state;
}

/* ------------------------------------------------------
 * main()
 * -> : Send Registrations Request (POST/CON)
 * <- : Wait for ACK
 * <- : Wait for Registration Information
 * ...
 * -> : Publish
 * <- : Wait for ACK
 */
void main(void)
{
    int64_t next_msg_time = APP_COAP_SEND_INTERVAL_MS;
    int64_t remaining;
    uint8_t icode;
    uint8_t demo_value = 0;
    char demo_buf[64]; /* custom payload buf */

    printk("************************************\n");
    printk("** Nebraska client sample started **\n");
    printk("************************************\n");

    modem_configure();

    if (server_resolve() != 0)
    {
        printk("Failed to resolve server name\n");
        return;
    }

    if (client_init() != 0)
    {
        printk("Failed to initialize CoAP client\n");
        return;
    }

    next_msg_time = k_uptime_get();
    client_state_t state = CLT_STATE_REGISTRATION_NEEDED;

    while (state != CLT_STATE_FAILURE)
    {

        switch (state)
        {
        /* ** Registration ** */
        case CLT_STATE_REGISTRATION_NEEDED: /* Send the registration request POST/CON */
            printk("\n==> STATE REGISTRATION NEEDED:\n");
            if (client_get_send_REGISTRATION() != 0)
            {
                printk("Failed to send GET request, exit...\n");
                state = CLT_STATE_FAILURE;
                break;
            }
            /* we should get an answer in the next 5s */
            next_msg_time += APP_COAP_SEND_INTERVAL_MS;
            state = CLT_STATE_REGISTRATION_ACK;
            break;

        case CLT_STATE_REGISTRATION_ACK:
            printk("\n==> STATE REGISTRATION ACK:\n");
            state = waiting_for_ACK(state, &next_msg_time, &remaining);
            break;

        case CLT_STATE_REGISTRATION_RESULT:
            printk("\n==> STATE REGISTRATION RESULT:\n");
            state = get_result_code(state, &icode, options, MAX_NEBRASKA_OPTIONS,
                                    &next_msg_time, &remaining);
            if (COAP_RESULT_MAJOR(icode) != 2)
            {
                printk("\tFail: Result: %d.%02d (0x%02x) \n",
                       COAP_RESULT_MAJOR(icode), COAP_RESULT_MINOR(icode), icode);
                state = CLT_STATE_FAILURE; /* Exit */
            }
            break;

        /* ** Publication ** */
        case CLT_STATE_PUBLICATION_START:
            printk("\n==> STATE CLT_STATE_PUBLICATION_START NEEDED:\n");

            /* Custom value to send to the broker */
            sys_rand_get(&demo_value, sizeof(demo_value));
            sprintf(demo_buf, "T:%d", demo_value);
            printk("Send data {%s} to MQTT broker\n", demo_buf);

            if (client_get_send_PUBLICATION(options, MAX_NEBRASKA_OPTIONS, demo_buf) != 0)
            {
                printk("Failed to send GET request, exit...\n");
                state = CLT_STATE_FAILURE;
                break;
            }

            /* we should get an answer in the next 5s */
            next_msg_time += APP_COAP_SEND_INTERVAL_MS;
            state = CLT_STATE_PUBLICATION_ACK;
            break;

        case CLT_STATE_PUBLICATION_ACK:
            printk("\n==> STATE PUBLICATION ACK:\n");
            state = waiting_for_ACK(state, &next_msg_time, &remaining);
            break;

        case CLT_STATE_PUBLICATION_RESULT:
            printk("\n==> STATE PUBLICATION RESULT:\n");
            state = get_result_code(state, &icode, NULL, 0, &next_msg_time, &remaining);
            if (COAP_RESULT_MAJOR(icode) != 2)
            {
                printk("\tFail: Result: %d.%02d (0x%02x) \n", COAP_RESULT_MAJOR(icode), COAP_RESULT_MINOR(icode), icode);
                state = CLT_STATE_FAILURE; /* Exit */
                break;
            }

            printk("suspend for 3s before the next publication...\n");
            k_msleep(3000); /* Next publication starts in 3s */
            next_msg_time = k_uptime_get();
            state = CLT_STATE_PUBLICATION_START;
            break;
        }
    }

    (void)close(sock);
}
