/**
* \file    stream_client.c
* \brief   Persistent HTTPS stream client for a fixed-address server.
*
* This block opens with two stars and carries a \file tag rather than the
* four-star banner printed in GL11-C 2.4, because Doxygen ignores any block
* opening with three or more stars. Everything else follows 2.4 unchanged.
*
* Module name: stream_client.c
*
* Copyright 2026 \@PINETICS as an unpublished work.
* All Rights Reserved.
*
* The information contained herein is confidential property of PINETICS. The
* user is prohibited from copying, transfer or disclosure of such information
* except by express written agreement with PINETICS.
*
* First written on 21-AUG-2026 by
* Ported to a fixed server address on 24-AUG-2026.
*
* Module Description:
* Connection manager, TLS client and stream consumer. Opens an HTTPS
* connection to STREAM_SERVER_HOST, reads a continuous response body, and
* hands every payload byte to the UART bridge. See stream_client.h for the
* layering, the reconnect policy and the wire format.
*
* PROVENANCE. This is a port of imx7_client.c from
* HTTP_Server_H753_RTOS_ES_MBEDTLS_mDNS_V00. It was ported rather than
* rewritten because that module already solves several things that are not
* obvious and were each found on hardware: the 2048-byte
* MBEDTLS_SSL_IN_CONTENT_LEN record ceiling, chunked versus identity framing,
* case-insensitive header matching without POSIX strncasecmp, a bounded
* connect (lwip_connect is otherwise unbounded), and an explicitly seeded
* ctr_drbg. Three things changed, all marked with 24-08-2026 in the text:
*
*   1. THE ADDRESS IS FIXED. STREAM_SERVER_HOST is a dotted quad, parsed once
*      in stream_client_init(). All mDNS discovery and rediscovery is gone.
*   2. THE UART DESTINATION IS FIXED. Every received byte goes to
*      STREAM_UART_SELECTOR. No selector byte is read from the stream - see
*      stream_forward_to_uart(), which is the whole point of the change.
*   3. NO TLS HOSTNAME IS SET, because the target is an address and mbedTLS
*      2.x does not match iPAddress SANs. Chain verification is unaffected;
*      the reasoning is at the mbedtls_ssl_set_hostname() call.
*
* THREE THINGS THIS MODULE OWNS ITS OWN COPY OF, AND WHY
*
* 1. Entropy and DRBG contexts. It would be shorter to borrow the project's
*    global ctr_drbg, and that is exactly the mistake made on the firmware
*    update client in the sibling App1 project: MX_MBEDTLS_Init() calls
*    mbedtls_ctr_drbg_init() but NEVER mbedtls_ctr_drbg_seed(), because the
*    HTTPS server side goes through altcp_tls which seeds a drbg of its own. An
*    unseeded drbg survives until it RESEEDS, which a handshake triggers, and
*    the result was a HardFault with CFSR=0x00020000 and PC=0x00000000 - a NULL
*    f_entropy called from mbedtls_ctr_drbg_reseed(). Owning and seeding them
*    here removes the question entirely.
*
* 2. The socket. Kept in the module state rather than passed around, so
*    stream_disconnect() can be called from any failure path and always closes
*    exactly what was opened.
*
* 3. Its task. The stream read blocks; running it on the network task would
*    stall link monitoring.
*
* WHAT IS DELIBERATELY NOT DONE HERE
*
* No name resolution of any kind. The address is a compile-time literal, so
* there is no DNS query, no mDNS query, and nothing for another task to hand
* in. The reference module needed a resolver and two entry points to service
* it; both were removed on 24-08-2026 and the removal is documented at the
* point in this file where they used to be.
*
* ENDIANNESS (GL11-C 13.4). This module reads a byte stream and an HTTP header
* block, both byte-oriented, and never reinterprets received bytes as a wider
* type. The only multi-byte value it builds is the port number handed to
* lwip_connect(), converted with htons(). No byte-order assumption is made about
* the payload; that is the application's business in stream_process_payload().
*
* APPROVED EXCEPTIONS (GL11-C 1.1)
* 1. Integer types. GL11-C 13.1 mandates uint8 / uint32 style typedefs. This
*    project uses the C99 <stdint.h> names together with lwIP's and mbedTLS's
*    own types, because every interface it calls is declared in those terms.
*    Ruled by the project owner on 12-08-2026.
*
* OPEN NON-COMPLIANCE - DEFERRED (GL11-C 11.4.1)
* 2. printf(). Used for progress and failure reporting, as in every module of
*    this project. Deferred by the project owner on 12-08-2026.
*
****************************************************************/

/* Include section
***************************************************/
#include "stream_client.h"
#include "tls_credentials.h"

/* RFC 6455 framing and handshake. Included unconditionally rather than under
   STREAM_USE_WEBSOCKET so that ws_selftest() can still be run from a build
   with WebSocket disabled - the protocol layer is worth testing whether or
   not this particular connection uses it. */
#include "websocket.h"

/* uart_dispatch_send(), UART_SELECTOR_*, UART_DISPATCH_MAX_PAYLOAD - the
   bridge every received byte is handed to.

   NOTE there is no uart_dispatch_name() to call: uart_dispatch.c has a
   selector-to-name mapping but keeps it static. STREAM_UART_NAME in
   stream_client.h carries the printable name instead, which is why that header
   insists the two are changed together. */
#include "uart_dispatch.h"

/* Streaming JSON field extractor, added 27-08-2026. Only reached when
   STREAM_JSON_EXTRACT_ENABLE is 1; the header is included unconditionally so
   json_parser_selftest() can be run from a raw-forwarding build too. */
#include "json_parser.h"

/* ntp_format_epoch() - the local epoch appended as a third column on every
   emitted field line. See STREAM_JSON_APPEND_EPOCH in stream_client.h. */
#include "ntp_client.h"

/* vcom_tx_write() - the raw frame dump to the VCP, non-blocking. See
   STREAM_DUMP_FRAME_TO_VCP in stream_client.h. */
#include "vcom_tx.h"

/* mdns_service_get_address() and MDNS_TARGET_HOSTNAME - the server address when
   STREAM_SERVER_USE_MDNS is 1. This module only CONSUMES a published address;
   driving the query is mdns_service.c's job, which is why the two-flag
   want_discovery / awaiting_result arrangement noted further down is not needed
   here. */
#include "mdns_service.h"

/* PE9 oscilloscope trigger. This file owns the RISING edge when
   SCOPE_TRIG_FROM_NETWORK is 1 - see stream_process_payload(). The falling edge
   belongs to uart_dispatch.c either way. Compiles to nothing when the trigger
   is disabled. */
#include "scope_trig.h"

#include "cmsis_os2.h"

#include "lwip/sockets.h"
#include "lwip/inet.h"

#include "mbedtls/ssl.h"
#include "mbedtls/entropy.h"
#include "mbedtls/ctr_drbg.h"
#include "mbedtls/x509_crt.h"
#include "mbedtls/error.h"

#include <stdio.h>
#include <string.h>

#if STREAM_CLIENT_ENABLE

/* Defines section
***************************************************/

/* Task stack, in BYTES - osThreadAttr_t.stack_size is bytes under
   CMSIS-RTOS2, not words as in the older FreeRTOS v1 API. A TLS handshake is
   the deepest thing this task does; 6 KB covers it with margin without
   repeating the sibling project's mistake of raising it to 16 KB on a theory
   that turned out to be wrong and costing 8 KB of heap for nothing. */
#define STREAM_TASK_STACK_BYTES           6144U

/* Largest HTTP response head this client will parse before giving up. A stream
   response head is a few hundred bytes; this is a bound, not a target. */
#define STREAM_HTTP_HEAD_MAX              512U

/* Longest chunk-size line accepted in a chunked body. "%X\r\n" plus optional
   chunk extensions; 32 is generous for a length that cannot exceed 8 hex
   digits in any sane server. */
#define STREAM_CHUNK_LINE_MAX             32U

/* How often the console reports a healthy stream. printf() is blocking UART at
   roughly 8.5 ms a line, so a message per record would dominate the very
   timing this project measures elsewhere - and at a high data rate it would
   stall the receive loop enough to lose the connection. Report on a byte
   interval instead. */
#define STREAM_REPORT_EVERY_BYTES         4096U

/* Variables section
***************************************************/

/* One connection at a time, by design. Grouped rather than left as loose
   file-scope variables, per GL11-C 7.14.4. */
static struct Stream_Variables
{
    int                        sock;         /**< lwIP socket, -1 when closed  */
    mbedtls_ssl_context        ssl;
    mbedtls_ssl_config         conf;
    mbedtls_x509_crt           ca;
    mbedtls_entropy_context    entropy;
    mbedtls_ctr_drbg_context   drbg;

#if STREAM_CLIENT_MUTUAL_TLS
    mbedtls_x509_crt           own_cert;     /**< our identity, when mTLS on   */
    mbedtls_pk_context         own_key;
#endif

    /* THE TARGET IS FIXED, not discovered. STREAM_SERVER_HOST is parsed once
       in stream_client_init() and never changes afterwards.

       The reference module this was ported from resolved the address by mDNS
       and therefore carried cached_tries / want_discovery / awaiting_result to
       drive rediscovery. All three are gone: with a literal address there is
       nothing to rediscover, and keeping flags that can only ever hold one
       value invites someone to write code that waits on them.

       WHAT THAT GIVES UP, stated so it is a choice and not an accident: if the
       server moves to another address, this board will retry the old one for
       ever. That is the correct behaviour for a fixed-IP deployment - failing
       visibly against a known address beats silently talking to whichever host
       answered a name query - but it does mean STREAM_SERVER_HOST has to be
       right, and changing it needs a rebuild. */
    ip4_addr_t                 target;       /**< STREAM_SERVER_HOST, parsed   */
    uint8_t                    have_target;  /**< 0 only if the literal is bad */
    uint32_t                   mdns_gen;     /**< generation of target, if mDNS*/
    uint32_t                   fail_run;     /**< consecutive failed attempts  */
    uint8_t                    drbg_seeded;  /**< one-time seed guard          */

    uint32_t                   backoff_ms;
    uint32_t                   rx_bytes;     /**< cumulative payload bytes     */
    uint32_t                   connects;     /**< successful streams           */
    uint32_t                   report_at;    /**< next rx_bytes to report at   */
    uint32_t                   echo_bytes;   /**< bytes echoed for RTT timing  */
    uint32_t                   echo_fails;   /**< echo writes that failed      */
    uint32_t                   uart_bytes;   /**< bytes handed to the bridge   */
    uint32_t                   uart_drops;   /**< records the bridge refused   */

    volatile stream_client_state_t state;

    uint8_t                    rx[STREAM_RX_CHUNK_BYTES];
} Stream;

static osThreadId_t         stream_task_handle;

static const osThreadAttr_t stream_task_attributes = {
    .name       = "StreamClient",
    .stack_size = STREAM_TASK_STACK_BYTES,
    .priority   = (osPriority_t)osPriorityLow
};

/* Function Prototype Section
***************************************************/
static int      stream_bio_send(void *ctx, const unsigned char *buf, size_t len);
static int      stream_bio_recv(void *ctx, unsigned char *buf, size_t len);
static int32_t  stream_tcp_connect(void);
static int32_t  stream_tls_setup(void);
static void     stream_disconnect(void);
/* THE PLAIN-HTTP BODY PATH, compiled only when WebSocket is off.
   Left defined in WebSocket mode they are unreachable, and -Wall says so with
   four "defined but not used" warnings. A build that is expected to emit
   warnings is one where the next real warning goes unnoticed, so the switch
   removes them rather than the reader learning to ignore them.

   stream_read_line() and stream_header_is() are NOT in this group: the
   WebSocket opening handshake is an HTTP exchange up to the blank line and
   uses both. */
#if !STREAM_USE_WEBSOCKET
static int32_t  stream_send_request(void);
static int32_t  stream_parse_response_head(int32_t *chunked, int32_t *has_length,
                                         uint32_t *content_length);
static int32_t  stream_stream_identity(uint32_t limit, int32_t bounded);
static int32_t  stream_stream_chunked(void);
#endif
static int32_t  stream_read_some(uint8_t *dst, uint32_t want, uint32_t *got);
static int32_t  stream_read_line(char *dst, uint32_t max, uint32_t *len);
static int32_t  stream_header_is(const char *line, const char *field);
static void     stream_forward_to_uart(const uint8_t *data, uint32_t len);
static void     stream_process_payload(const uint8_t *data, uint32_t len);
static int32_t  stream_run_cycle(void);
static void     stream_task(void *argument);
static const char *stream_state_name(stream_client_state_t s);

/**
* \copyright 2026 \@PINETICS as an unpublished work.
* Function name: static int stream_bio_send(void *ctx, const unsigned char *buf,
*                                         size_t len)
*    \return Bytes written, or MBEDTLS_ERR_SSL_INTERNAL_ERROR on a socket error.
*    \param  ctx - unused; the socket lives in the module state.
*    \param  buf - bytes to write.
*    \param  len - how many.
* \author
* \date 21-AUG-2026
* \brief Transport send callback handed to mbedTLS.
**************************************************/
static int stream_bio_send(void *ctx, const unsigned char *buf, size_t len)
{
    int sent;

    (void)ctx;

    sent = lwip_send(Stream.sock, buf, len, 0);
    if (sent < 0)
    {
        return MBEDTLS_ERR_SSL_INTERNAL_ERROR;
    }
    else
    {
        /* Socket accepted the write, possibly partially - mbedTLS handles a
           short write by calling again. */
    }

    return sent;
}

/**
* \copyright 2026 \@PINETICS as an unpublished work.
* Function name: static int stream_bio_recv(void *ctx, unsigned char *buf,
*                                         size_t len)
*    \return Bytes read, MBEDTLS_ERR_SSL_WANT_READ on timeout, 0 on an orderly
*            close by the peer, or MBEDTLS_ERR_SSL_INTERNAL_ERROR otherwise.
*    \param  ctx - unused; the socket lives in the module state.
*    \param  buf - destination.
*    \param  len - buffer size.
* \author
* \date 21-AUG-2026
* \brief Transport receive callback handed to mbedTLS.
*
*        A TIMEOUT IS REPORTED AS WANT_READ, NOT AS AN ERROR, and that
*        distinction is what makes a long-lived idle stream survive. SO_RCVTIMEO
*        fires whenever the server simply has nothing to say for
*        STREAM_SOCKET_TIMEOUT_S; treating that as a failure would tear down a
*        perfectly good connection. The stream loop decides separately when
*        silence has gone on long enough to mean the peer is gone.
**************************************************/
static int stream_bio_recv(void *ctx, unsigned char *buf, size_t len)
{
    int got;

    (void)ctx;

    got = lwip_recv(Stream.sock, buf, len, 0);
    if (got > 0)
    {
        /* THE PE9 RISING EDGE, when SCOPE_TRIG_ARM_ON_SOCKET_DATA is 1.
           -----------------------------------------------------------------
           This is the earliest point at which the board knows the bytes in
           hand belong to the STREAM SOCKET rather than to mDNS, ARP, NTP or a
           bare TCP acknowledgement. The Ethernet ISR cannot make that
           distinction - the packet is still encrypted and undescribed there -
           which is why arming from the ISR left the pin permanently HIGH on
           this subnet. See SCOPE_TRIG_ARM_ON_SOCKET_DATA in scope_trig.h.

           The bytes here are still CIPHERTEXT: this is the transport callback
           mbedTLS pulls through, underneath the record layer. Decryption,
           WebSocket unmasking and JSON parsing therefore all happen after this
           line and remain inside the pulse, which is what the measurement
           asked for.

           GATED ON STREAMING so the TLS handshake and the HTTP upgrade cannot
           arm it. Those produce plenty of socket reads and no JSON object, so
           an ungated call would raise the pin at connect and hold it there
           until the first frame - reproducing the original fault at every
           reconnection. */
        if (Stream.state == STREAM_STATE_STREAMING)
        {
            scope_trig_data_rx();
        }
        else
        {
            /* Connecting, handshaking or upgrading - not a measurable frame. */
        }

        return got;
    }
    else if (got == 0)
    {
        /* Peer closed the connection cleanly. */
        return 0;
    }
    else
    {
        /* lwIP does not expose errno reliably through this path, so a negative
           return is taken as "nothing available now". The caller's own
           accounting decides whether that has persisted long enough to matter. */
        return MBEDTLS_ERR_SSL_WANT_READ;
    }
}

/**
* \copyright 2026 \@PINETICS as an unpublished work.
* Function name: static int32_t stream_tcp_connect(void)
*    \return 0 on a connected socket, -1 otherwise.
*    \param  void
* \author
* \date 21-AUG-2026
* \brief Opens a TCP connection to the cached address, bounded in time.
*
*        THE CONNECT IS MADE NON-BLOCKING ON PURPOSE. lwip_connect() is NOT
*        bounded by SO_SNDTIMEO or SO_RCVTIMEO - those cover send and recv only.
*        A blocking connect to an absent host therefore wedges this task for as
*        long as lwIP's own retransmission policy takes, which on the sibling
*        App1 project meant the update task sat silent while everything else
*        kept running. Non-blocking connect plus select() plus an explicit
*        SO_ERROR check is the only way to hold it to STREAM_CONNECT_TIMEOUT_MS.
*
*        The socket is returned to blocking mode afterwards, because the stream
*        loop wants ordinary timed reads.
**************************************************/
static int32_t stream_tcp_connect(void)
{
    struct sockaddr_in  addr;
    struct timeval      tv;
    fd_set              wfds;
    int                 flags;
    int                 rc;
    int                 so_err = 0;
    socklen_t           so_len = (socklen_t)sizeof(so_err);
    int32_t             status = -1;

    Stream.sock = lwip_socket(AF_INET, SOCK_STREAM, 0);
    if (Stream.sock < 0)
    {
        printf("stream: socket() failed\r\n");
        return -1;
    }
    else
    {
        /* Socket open - carry on. */
    }

    memset(&addr, 0, sizeof(addr));
    addr.sin_family      = AF_INET;
    addr.sin_port        = lwip_htons((uint16_t)STREAM_SERVER_PORT);
    addr.sin_addr.s_addr = ip4_addr_get_u32(&Stream.target);

    /* Non-blocking for the connect only. */
    flags = lwip_fcntl(Stream.sock, F_GETFL, 0);
    (void)lwip_fcntl(Stream.sock, F_SETFL, flags | O_NONBLOCK);

    rc = lwip_connect(Stream.sock, (struct sockaddr *)&addr, sizeof(addr));

    /* A non-blocking connect almost always returns -1 with EINPROGRESS. Success
       here would mean it completed instantly, which is legal on a local link. */
    FD_ZERO(&wfds);
    FD_SET(Stream.sock, &wfds);
    tv.tv_sec  = (time_t)(STREAM_CONNECT_TIMEOUT_MS / 1000U);
    tv.tv_usec = (long)((STREAM_CONNECT_TIMEOUT_MS % 1000U) * 1000U);

    if (rc == 0)
    {
        status = 0;
    }
    else if (lwip_select(Stream.sock + 1, NULL, &wfds, NULL, &tv) <= 0)
    {
        printf("stream: connect to %s:%u timed out after %lu ms\r\n",
               ip4addr_ntoa(&Stream.target), (unsigned)STREAM_SERVER_PORT,
               (unsigned long)STREAM_CONNECT_TIMEOUT_MS);
        status = -1;
    }
    else if (lwip_getsockopt(Stream.sock, SOL_SOCKET, SO_ERROR,
                             &so_err, &so_len) != 0)
    {
        printf("stream: getsockopt(SO_ERROR) failed\r\n");
        status = -1;
    }
    else if (so_err != 0)
    {
        /* select() reports writability for a REFUSED connection too, so this
           check is what distinguishes "connected" from "rejected". Without it a
           closed port looks like success until the first read fails. */
        printf("stream: connect refused by %s:%u (SO_ERROR %d)\r\n",
               ip4addr_ntoa(&Stream.target), (unsigned)STREAM_SERVER_PORT, so_err);
        status = -1;
    }
    else
    {
        status = 0;
    }

    /* Back to blocking, with read and write timeouts, for the stream phase. */
    (void)lwip_fcntl(Stream.sock, F_SETFL, flags);

    if (status == 0)
    {
        tv.tv_sec  = (time_t)STREAM_SOCKET_TIMEOUT_S;
        tv.tv_usec = 0;
        (void)lwip_setsockopt(Stream.sock, SOL_SOCKET, SO_RCVTIMEO,
                              &tv, sizeof(tv));
        (void)lwip_setsockopt(Stream.sock, SOL_SOCKET, SO_SNDTIMEO,
                              &tv, sizeof(tv));
    }
    else
    {
        lwip_close(Stream.sock);
        Stream.sock = -1;
    }

    return status;
}

/**
* \copyright 2026 \@PINETICS as an unpublished work.
* Function name: static int32_t stream_tls_setup(void)
*    \return 0 once the handshake has completed, -1 otherwise.
*    \param  void
* \author
* \date 21-AUG-2026
* \brief Seeds the RNG if needed, configures a TLS client and handshakes.
*
*        THE ONE-TIME DRBG SEED IS LOAD BEARING - see the module header. Without
*        it the first reseed inside a handshake dereferences a NULL entropy
*        function and the board HardFaults rather than failing the connection.
*
*        The server's certificate is verified against tls_ca_cert_der with
*        MBEDTLS_SSL_VERIFY_REQUIRED regardless of STREAM_CLIENT_MUTUAL_TLS.
*        That switch governs whether WE present a certificate; it never weakens
*        our checking of THEM. Turning off server verification would make the
*        encryption pointless, since anything on the subnet could impersonate
*        the server.
*
*        NOTE the SERVER-side switch is a different macro, ENABLE_MUTUAL_TLS in
*        main.h, which decides what the board's own HTTPS server demands of PCs
*        connecting to it. The two were one name until 24-08-2026 and could not
*        both be satisfied by one value - see main.h for why they were split.
**************************************************/
static int32_t stream_tls_setup(void)
{
    int      ret;
    int32_t  status = 0;

    mbedtls_ssl_init(&Stream.ssl);
    mbedtls_ssl_config_init(&Stream.conf);
    mbedtls_x509_crt_init(&Stream.ca);

    if (Stream.drbg_seeded == 0U)
    {
        static const char pers[] = "stream_client";

        mbedtls_entropy_init(&Stream.entropy);
        mbedtls_ctr_drbg_init(&Stream.drbg);

        ret = mbedtls_ctr_drbg_seed(&Stream.drbg, mbedtls_entropy_func,
                                    &Stream.entropy,
                                    (const unsigned char *)pers,
                                    sizeof(pers) - 1U);
        if (ret != 0)
        {
            printf("stream: ctr_drbg_seed failed (-0x%04X)\r\n",
                   (unsigned)(-ret));
            status = -1;
        }
        else
        {
            Stream.drbg_seeded = 1U;
        }
    }
    else
    {
        /* Already seeded on an earlier cycle - reseeding every reconnect would
           drain entropy for no benefit. */
    }

    if (status == 0)
    {
        ret = mbedtls_x509_crt_parse_der(&Stream.ca, tls_ca_cert_der,
                                         tls_ca_cert_der_len);
        if (ret != 0)
        {
            printf("stream: CA parse failed (-0x%04X)\r\n", (unsigned)(-ret));
            status = -1;
        }
        else
        {
            /* CA ready. */
        }
    }
    else
    {
        /* Already failed. */
    }

    if (status == 0)
    {
        ret = mbedtls_ssl_config_defaults(&Stream.conf, MBEDTLS_SSL_IS_CLIENT,
                                          MBEDTLS_SSL_TRANSPORT_STREAM,
                                          MBEDTLS_SSL_PRESET_DEFAULT);
        if (ret != 0)
        {
            printf("stream: ssl_config_defaults failed (-0x%04X)\r\n",
                   (unsigned)(-ret));
            status = -1;
        }
        else
        {
            mbedtls_ssl_conf_authmode(&Stream.conf, MBEDTLS_SSL_VERIFY_REQUIRED);
            mbedtls_ssl_conf_ca_chain(&Stream.conf, &Stream.ca, NULL);
            mbedtls_ssl_conf_rng(&Stream.conf, mbedtls_ctr_drbg_random,
                                 &Stream.drbg);
        }
    }
    else
    {
        /* Already failed. */
    }

#if STREAM_CLIENT_MUTUAL_TLS
    if (status == 0)
    {
        /* OUR identity, presented to the i.MX7. Reaching here with the switch
           at 1 requires a client certificate and key to be compiled in - see
           the note at STREAM_CLIENT_MUTUAL_TLS in main.h. The server
           certificate cannot be reused: its extendedKeyUsage is serverAuth
           only, so a server that checks EKU will refuse it. */
        mbedtls_x509_crt_init(&Stream.own_cert);
        mbedtls_pk_init(&Stream.own_key);

        printf("stream: *** STREAM_CLIENT_MUTUAL_TLS=1 but no client identity is "
               "compiled in ***\r\n");
        printf("stream:     embed certs/client.crt and certs/client.key as DER "
               "in tls_credentials.h,\r\n");
        printf("stream:     then load them here with "
               "mbedtls_x509_crt_parse_der / mbedtls_pk_parse_key\r\n");
        status = -1;
    }
    else
    {
        /* Already failed. */
    }
#endif

    if (status == 0)
    {
        ret = mbedtls_ssl_setup(&Stream.ssl, &Stream.conf);
        if (ret != 0)
        {
            printf("stream: ssl_setup failed (-0x%04X)\r\n", (unsigned)(-ret));
            status = -1;
        }
        else
        {
            /* NO HOSTNAME IS SET, AND THAT IS A DECISION.  24-08-2026.
               ------------------------------------------------------------
               The reference module called mbedtls_ssl_set_hostname() with the
               mDNS name, because it HAD a name and the server's certificate
               carried it. This client connects to a literal address, and
               passing "192.168.40.239" here would not do what it looks like it
               does.

               mbedTLS 2.x matches the hostname argument against the
               certificate's CN and its dNSName SANs. It does NOT match
               iPAddress SANs. So a server certificate correctly issued for
               IP:192.168.40.239 - the right way to certify an address - would
               be REJECTED with MBEDTLS_X509_BADCERT_CN_MISMATCH, and the
               console would report a name mismatch for a certificate that
               names exactly the host we are talking to. That failure is
               genuinely hard to read.

               Passing NULL disables only the NAME check. Chain verification is
               untouched: authmode is MBEDTLS_SSL_VERIFY_REQUIRED and the CA
               from tls_credentials.h still has to have signed the server's
               certificate, so an unknown or self-signed server is still
               refused. What is given up is the assurance that the certificate
               was issued for THIS address rather than some other host our CA
               also signed - acceptable on a closed bench with a private CA,
               and worth revisiting if this ever faces a wider network.

               TO RESTORE THE NAME CHECK: give the server a certificate whose
               CN or dNSName SAN is a real hostname, set STREAM_SERVER_HOST to
               that name, and pass it here. That needs DNS or a hosts entry the
               board can resolve, which is why it is not the default. */
            (void)mbedtls_ssl_set_hostname(&Stream.ssl, NULL);
            mbedtls_ssl_set_bio(&Stream.ssl, NULL, stream_bio_send,
                                stream_bio_recv, NULL);
        }
    }
    else
    {
        /* Already failed. */
    }

    if (status == 0)
    {
        Stream.state = STREAM_STATE_HANDSHAKE;

        do
        {
            ret = mbedtls_ssl_handshake(&Stream.ssl);
        } while ((ret == MBEDTLS_ERR_SSL_WANT_READ)
                 || (ret == MBEDTLS_ERR_SSL_WANT_WRITE));

        if (ret != 0)
        {
            uint32_t flags = mbedtls_ssl_get_verify_result(&Stream.ssl);

            printf("stream: TLS handshake failed (-0x%04X)\r\n",
                   (unsigned)(-ret));
            if (flags != 0U)
            {
                /* Naming the verify flags turns "handshake failed" into an
                   actionable message - the usual cause is the i.MX7's
                   certificate not being signed by the CA in
                   tls_credentials.h. */
                printf("stream:     certificate verify flags 0x%08lX\r\n",
                       (unsigned long)flags);
            }
            else
            {
                /* Failed before or independently of certificate verification. */
            }
            status = -1;
        }
        else
        {
            printf("stream: TLS up (%s, %s)\r\n",
                   mbedtls_ssl_get_version(&Stream.ssl),
                   mbedtls_ssl_get_ciphersuite(&Stream.ssl));
        }
    }
    else
    {
        /* Already failed. */
    }

    return status;
}

/**
* \copyright 2026 \@PINETICS as an unpublished work.
* Function name: static void stream_disconnect(void)
*    \return void
*    \param  void
* \author
* \date 21-AUG-2026
* \brief Tears the connection down and releases everything, in the reverse
*        order it was acquired. Safe after a partial or failed setup, which is
*        why every failure path can call it unconditionally.
*
*        The entropy and DRBG contexts are deliberately NOT freed - they are
*        seeded once and reused for the lifetime of the board.
**************************************************/
static void stream_disconnect(void)
{
    if (Stream.sock >= 0)
    {
        (void)mbedtls_ssl_close_notify(&Stream.ssl);
        (void)lwip_close(Stream.sock);
        Stream.sock = -1;
    }
    else
    {
        /* Nothing open. */
    }

#if STREAM_CLIENT_MUTUAL_TLS
    mbedtls_pk_free(&Stream.own_key);
    mbedtls_x509_crt_free(&Stream.own_cert);
#endif

    mbedtls_ssl_free(&Stream.ssl);
    mbedtls_ssl_config_free(&Stream.conf);
    mbedtls_x509_crt_free(&Stream.ca);
}

#if !STREAM_USE_WEBSOCKET   /* plain-HTTP body path */
/**
* \copyright 2026 \@PINETICS as an unpublished work.
* Function name: static int32_t stream_send_request(void)
*    \return 0 if the request went out whole, -1 otherwise.
*    \param  void
* \author
* \date 21-AUG-2026
* \brief Sends the single GET that opens the stream.
*
*        Head and request line go out in ONE mbedtls_ssl_write. Two writes
*        become two TLS records and two TCP segments, and Nagle then holds the
*        second until the first is acknowledged - a delayed-ACK stall this
*        workspace measured at about 164 ms per exchange on the firmware update
*        path. One write cannot produce that pattern.
*
*        "Connection: keep-alive" is stated explicitly even though HTTP/1.1
*        implies it, because lwIP's own httpd requires the literal header before
*        it will hold a connection open, and a server written against that
*        behaviour may do the same.
**************************************************/
static int32_t stream_send_request(void)
{
    char     request[256];
    int      len;
    int32_t  status = 0;

    len = snprintf(request, sizeof(request),
                   "GET %s HTTP/1.1\r\n"
                   "Host: %s:%u\r\n"
                   "Accept: */*\r\n"
                   "Connection: keep-alive\r\n"
                   "\r\n",
                   /* Host goes on the wire - same reasoning as the WebSocket
                      upgrade below: announce the name actually in use, not the
                      literal that mDNS has replaced. */
                   STREAM_PATH, STREAM_SERVER_NAME_FOR_LOG,
                   (unsigned)STREAM_SERVER_PORT);

    if ((len <= 0) || ((size_t)len >= sizeof(request)))
    {
        printf("stream: request does not fit its buffer\r\n");
        status = -1;
    }
    else if (mbedtls_ssl_write(&Stream.ssl, (const unsigned char *)request,
                               (size_t)len) != len)
    {
        printf("stream: request write failed\r\n");
        status = -1;
    }
    else
    {
        /* Request away. */
    }

    return status;
}
#endif /* !STREAM_USE_WEBSOCKET */

/**
* \copyright 2026 \@PINETICS as an unpublished work.
* Function name: static int32_t stream_read_some(uint8_t *dst, uint32_t want,
*                                              uint32_t *got)
*    \return 0 if at least one byte was read, -1 on a closed connection or a
*            hard error.
*    \param  dst - destination buffer.
*    \param  want - buffer capacity.
*    \param  got - receives the number of bytes actually read; 0 only when the
*            call timed out with the connection still healthy.
* \author
* \date 21-AUG-2026
* \brief Reads whatever is available, without insisting on filling the buffer.
*
*        THIS IS THE PARTIAL-RECEIVE HANDLER. TLS delivers whatever one record
*        happens to carry, and TCP may split a server's single write across many
*        records, or coalesce many writes into one. A reader that demanded an
*        exact count would stall on the first short record; every caller here is
*        written to cope with a partial result instead.
*
*        A timeout returns 0 bytes with status 0 - the connection is still up,
*        the server simply had nothing to send. The stream loop counts those.
**************************************************/
static int32_t stream_read_some(uint8_t *dst, uint32_t want, uint32_t *got)
{
    int n;

    *got = 0U;

    n = mbedtls_ssl_read(&Stream.ssl, dst, (size_t)want);

    if (n > 0)
    {
        *got = (uint32_t)n;
        return 0;
    }
    else if ((n == MBEDTLS_ERR_SSL_WANT_READ)
             || (n == MBEDTLS_ERR_SSL_WANT_WRITE))
    {
        /* Idle, not broken. */
        return 0;
    }
    else if (n == MBEDTLS_ERR_SSL_PEER_CLOSE_NOTIFY)
    {
        printf("stream: server closed the stream (close_notify)\r\n");
        return -1;
    }
    else if (n == 0)
    {
        printf("stream: connection closed by peer\r\n");
        return -1;
    }
    else
    {
        printf("stream: read error (-0x%04X)\r\n", (unsigned)(-n));
        return -1;
    }
}

/**
* \copyright 2026 \@PINETICS as an unpublished work.
* Function name: static int32_t stream_read_line(char *dst, uint32_t max,
*                                              uint32_t *len)
*    \return 0 on a complete line, -1 on a closed connection or overflow.
*    \param  dst - destination, NUL terminated on success.
*    \param  max - capacity of dst including the terminator.
*    \param  len - receives the line length excluding CRLF.
* \author
* \date 21-AUG-2026
* \brief Reads one CRLF-terminated line, one byte at a time.
*
*        Byte-at-a-time looks wasteful and is not: mbedtls_ssl_read() serves
*        these from its already-decrypted record buffer, so these are cheap
*        function calls rather than network round trips. Reading in larger
*        blocks would over-read into the body, which then has to be buffered and
*        handed back - complexity this module does not need, since lines only
*        appear in the response head and in chunk-size markers.
**************************************************/
static int32_t stream_read_line(char *dst, uint32_t max, uint32_t *len)
{
    uint32_t n = 0U;
    uint32_t idle = 0U;

    while (n < (max - 1U))
    {
        uint8_t  c;
        uint32_t got = 0U;

        if (stream_read_some(&c, 1U, &got) != 0)
        {
            return -1;
        }
        else if (got == 0U)
        {
            /* Timed out mid-line. A server that stops halfway through a header
               is not merely idle, so this is bounded rather than infinite. */
            idle++;
            if (idle > 2U)
            {
                printf("stream: timed out mid-line\r\n");
                return -1;
            }
            else
            {
                continue;
            }
        }
        else
        {
            idle = 0U;
        }

        if (c == (uint8_t)'\n')
        {
            /* Strip a trailing CR if present - tolerate a bare LF, which some
               servers emit, rather than failing on it. */
            if ((n > 0U) && (dst[n - 1U] == '\r'))
            {
                n--;
            }
            else
            {
                /* Bare LF. */
            }
            dst[n] = '\0';
            *len = n;
            return 0;
        }
        else
        {
            dst[n] = (char)c;
            n++;
        }
    }

    printf("stream: line longer than %lu bytes\r\n", (unsigned long)max);
    return -1;
}

/**
* \copyright 2026 \@PINETICS as an unpublished work.
* Function name: static int32_t stream_header_is(const char *line,
*                                              const char *field)
*    \return 1 if line begins with field, compared without regard to case.
*            0 otherwise.
*    \param  line - a header line, NUL terminated.
*    \param  field - the field name to test for, including its colon.
* \author
* \date 21-AUG-2026
* \brief Case-insensitive header-name match.
*
*        WHY THIS EXISTS RATHER THAN strncasecmp(). That function is POSIX, not
*        ANSI C, so relying on it is a compiler extension of the kind GL11-C
*        13.8 says to avoid - and GL11-C 11 asks for our own substitute under a
*        different name where a library function is unsuitable. The name cannot
*        begin "str" either: GL11-C 3.11 reserves str[a-z]* for the standard
*        library.
*
*        Case-insensitivity is not optional. RFC 9110 makes header field names
*        case-insensitive, and a server emitting "transfer-encoding" in lower
*        case would otherwise be read as an unbounded identity stream - with the
*        chunk-size lines delivered to the application as if they were payload.
*
*        Only ASCII letters are folded, which is all a header name can contain.
**************************************************/
static int32_t stream_header_is(const char *line, const char *field)
{
    uint32_t i = 0U;

    while (field[i] != '\0')
    {
        char a = line[i];
        char b = field[i];

        if ((a >= 'A') && (a <= 'Z'))
        {
            a = (char)(a + ('a' - 'A'));
        }
        else
        {
            /* Not an upper-case letter - compared as it stands. */
        }

        if ((b >= 'A') && (b <= 'Z'))
        {
            b = (char)(b + ('a' - 'A'));
        }
        else
        {
            /* Not an upper-case letter - compared as it stands. */
        }

        if (a != b)
        {
            return 0;
        }
        else
        {
            /* Still matching. */
        }

        i++;
    }

    return 1;
}

#if !STREAM_USE_WEBSOCKET   /* plain-HTTP body path */
/**
* \copyright 2026 \@PINETICS as an unpublished work.
* Function name: static int32_t stream_parse_response_head(int32_t *chunked,
*                     int32_t *has_length, uint32_t *content_length)
*    \return 0 if the head was a 200 and was parsed, -1 otherwise.
*    \param  chunked - set to 1 if Transfer-Encoding is chunked.
*    \param  has_length - set to 1 if a Content-Length was present.
*    \param  content_length - the Content-Length value when has_length is 1.
* \author
* \date 21-AUG-2026
* \brief Reads and interprets the HTTP response head.
*
*        Accepts only 200. A redirect or an error status is reported by name
*        rather than silently retried, because a 404 on the stream path means the
*        server is running but the path is wrong - a configuration mistake that
*        an endless reconnect loop would hide.
*
*        Header names are matched case-insensitively, as RFC 9110 requires.
*        Getting that wrong is a classic interop failure: a server emitting
*        "transfer-encoding" in lower case would otherwise be read as an
*        unbounded identity stream, and the chunk-size lines would be delivered
*        to the application as payload.
**************************************************/
static int32_t stream_parse_response_head(int32_t *chunked, int32_t *has_length,
                                        uint32_t *content_length)
{
    char     line[STREAM_HTTP_HEAD_MAX];
    uint32_t len = 0U;
    int      code = 0;
    int32_t  status = 0;

    *chunked = 0;
    *has_length = 0;
    *content_length = 0U;

    if (stream_read_line(line, sizeof(line), &len) != 0)
    {
        return -1;
    }
    else
    {
        /* Status line in hand. */
    }

    if (sscanf(line, "HTTP/1.%*d %d", &code) != 1)
    {
        printf("stream: unparseable status line '%s'\r\n", line);
        return -1;
    }
    else if (code != 200)
    {
        printf("stream: server answered %d for %s - not streaming\r\n",
               code, STREAM_PATH);
        return -1;
    }
    else
    {
        /* 200 OK. */
    }

    /* Headers until the blank line. */
    for (;;)
    {
        if (stream_read_line(line, sizeof(line), &len) != 0)
        {
            status = -1;
            break;
        }
        else if (len == 0U)
        {
            /* Blank line - end of head. */
            break;
        }
        else
        {
            /* A header to inspect. */
        }

        if (stream_header_is(line, "transfer-encoding:") != 0)
        {
            if (strstr(line, "chunked") != NULL)
            {
                *chunked = 1;
            }
            else
            {
                /* Some other encoding - treated as identity below. */
            }
        }
        else if (stream_header_is(line, "content-length:") != 0)
        {
            *content_length = (uint32_t)strtoul(&line[15], NULL, 10);
            *has_length = 1;
        }
        else
        {
            /* Not a header this module acts on. */
        }
    }

    if (status == 0)
    {
        printf("stream: stream open - %s\r\n",
               (*chunked != 0) ? "chunked"
                               : ((*has_length != 0) ? "content-length"
                                                     : "identity (unbounded)"));
    }
    else
    {
        /* Already failed. */
    }

    return status;
}
#endif /* !STREAM_USE_WEBSOCKET */

/**
* \copyright 2026 \@PINETICS as an unpublished work.
* Function name: static void stream_process_payload(const uint8_t *data,
*                                                 uint32_t len)
*    \return void
*    \param  data - payload bytes, not NUL terminated.
*    \param  len - how many.
* \author
* \date 21-AUG-2026
* \brief THE APPLICATION HOOK. Handles received stream payload.
*
*        This is the one function to change when the i.MX7's data format is
*        known. Everything above it is transport and framing; nothing above it
*        cares what the bytes mean.
*
*        The default implementation accounts for the bytes and reports on a BYTE
*        INTERVAL rather than per record. That is not laziness: printf() here is
*        blocking UART at roughly 8.5 ms a line, so a message per record would
*        both flood the console and slow the receive loop enough to risk losing
*        the connection on a fast stream. The same mistake in this codebase once
*        produced a bogus 23x latency regression.
**************************************************/
#if STREAM_JSON_EXTRACT_ENABLE
/* ===========================================================================
 * FIELD -> UART ROUTING TABLE.  Added 27-08-2026.
 * ===========================================================================
 * The two tables are indexed together: Stream_json_fields[i] is extracted and
 * sent to Stream_json_route[i]. They must stay the same length and the same
 * order, which the compile-time check below enforces - a mismatch would route
 * timestamps to the wrong peripheral silently, and both values are plausible
 * on either UART so nothing downstream could tell.
 *
 * EVERY KEY CARRIES ITS OWN QUOTES. That is not decoration: without the
 * opening quote, "ntp_time" also matches inside
 * "controller_to_base_station_received_ntp_time", and the ntp_time entry would
 * carry the controller timestamp - so BOTH timestamp UARTs would transmit the
 * same value, whichever way round the routing table happens to be. See the
 * decoy note in json_parser.h.
 *
 * Order within the table does NOT have to match the order the server emits the
 * fields in - verified against a reference model on 27-08-2026, including the
 * case where the two timestamp fields are swapped in the JSON.
 * ========================================================================= */
/* CHANGED 10-09-2026 - now the four MOTOR POSITIONS, not two timestamps and
   two joystick axes.

   None of these four keys is a substring of any other key in the message, so
   the quote-prefix rule is not load-bearing here the way it was for
   "ntp_time" inside "controller_to_base_station_received_ntp_time". The quotes
   are kept regardless: they cost nothing, they are what json_parser_label_of()
   strips to produce the label column, and the next field added might well be
   "motor_1_pos_target". */
static const json_parser_field_t Stream_json_fields[] =
{
    { "\"motor_1_pos\"" },            /* -> UART4  */
    { "\"motor_2_pos\"" },            /* -> UART5  */
    { "\"motor_3_pos\"" },            /* -> USART1 */
    { "\"motor_4_insertion_pos\"" }   /* -> USART2 */
};

/* Routing changed 10-09-2026 to the motor positions. The order here is the
   requested mapping and is deliberately NOT the natural 1-2-3-4 across the
   peripherals: motors 1 and 2 go to the two UARTs, motors 3 and 4 to the two
   USARTs.

   WHY THE LABEL COLUMN WAS ADDED AT THE SAME TIME. The previous four fields
   were self-evident on arrival: a timestamp on the joystick port was obviously
   wrong. Four motor positions are the same shape, in the same range, and move
   together, so a line on the wrong port now looks entirely plausible. Each
   line therefore carries its own field name - see JSON_PARSER_EMIT_LABEL. */
static const uint8_t Stream_json_route[] =
{
    UART_SELECTOR_UART4,
    UART_SELECTOR_UART5,
    UART_SELECTOR_USART1,
    UART_SELECTOR_USART2
};

/* Scope-tracker bit for each field's destination, parallel to the two tables
   above. Kept as a third table rather than derived from the selector at run
   time so the mapping is visible in one place; the length check below covers
   all three. */
/* REORDERED 10-09-2026 in step with Stream_json_route above. The length check
   below cannot catch a mis-ORDERED table, only a mis-sized one, so this is the
   entry that has to be read against its neighbour by eye. Getting it wrong
   would leave the tracker waiting on a peripheral that was never sent to, and
   the PE9 pulse would simply never end - which is indistinguishable from the
   two faults already chased on 10-09-2026. */
static const uint8_t Stream_json_scope_idx[] =
{
    (uint8_t)SCOPE_TRIG_U_UART4,     /* motor_1_pos          */
    (uint8_t)SCOPE_TRIG_U_UART5,     /* motor_2_pos          */
    (uint8_t)SCOPE_TRIG_U_USART1,    /* motor_3_pos          */
    (uint8_t)SCOPE_TRIG_U_USART2     /* motor_4_insertion_pos*/
};

/* One entry per field in every table, or the routing is wrong. Fails the BUILD
   rather than the measurement. */
typedef char stream_json_route_len_check
    [(((sizeof(Stream_json_fields) / sizeof(Stream_json_fields[0])) ==
       (sizeof(Stream_json_route)  / sizeof(Stream_json_route[0]))) &&
      ((sizeof(Stream_json_route)  / sizeof(Stream_json_route[0])) ==
       (sizeof(Stream_json_scope_idx) / sizeof(Stream_json_scope_idx[0])))) ? 1 : -1];

/* Sequence id of the object currently being emitted, published by the begin
   hook below and read by stream_emit_json_value(). Single-threaded: both run in
   the stream task, inside one json_parser_feed() call. */
static uint32_t Stream_json_seq;

#if STREAM_JSON_APPEND_EPOCH
/* Local epoch for the object currently being emitted, formatted once by the
   begin hook. Empty when the clock is not yet synchronised. Single-threaded:
   written and read in the stream task inside one json_parser_feed() call. */
static char Stream_json_epoch[32];
#endif

/**
* \copyright 2026 \@PINETICS as an unpublished work.
* Function name: static void stream_json_object_begin(uint32_t seq)
*    \return None
*    \param  seq: sequence_id of the object about to be emitted
* \author
* \date 27-AUG-2026
* \brief Opens a per-object transaction for the PE9 measurement.
*
*        Binds this sequence id to whichever scope pulse the Ethernet interrupt
*        started, so the four transmit-complete events that follow can be
*        matched to it and to nothing else.
**************************************************/
static void stream_json_object_begin(uint32_t seq)
{
    Stream_json_seq = seq;

#if STREAM_JSON_APPEND_EPOCH
    /* SAMPLED ONCE PER OBJECT, not once per field. All four UARTs must report
       the same instant for a given sequence_id, or the columns cannot be
       compared row by row - which is the whole point of carrying the epoch.
       Reading it per field would give four values a few microseconds apart.

       An empty string when the clock has not synchronised; stream_emit_json_
       value() then omits the column rather than printing 0.000000, which would
       look like a reading. */
    if (ntp_format_epoch(Stream_json_epoch,
                         (uint32_t)sizeof(Stream_json_epoch)) <= 0)
    {
        Stream_json_epoch[0] = '\0';
    }
    else
    {
        /* Formatted, e.g. "1787909495.021000". */
    }
#endif

    scope_trig_seq_begin(seq);
}

/**
* \copyright 2026 \@PINETICS as an unpublished work.
* Function name: static void stream_json_object_end(void)
*    \return None
*    \param  void
* \author
* \date 27-AUG-2026
* \brief Closes the transaction - the expected UART set is now final.
*
*        Until this runs the tracker will not drop the pin even if every UART
*        has already reported, because the set it is comparing against is still
*        being built. A one-byte joystick value is out in about 5 us at 2 Mbaud,
*        comfortably faster than the remaining sends can be queued, so this
*        ordering is what stops the pulse ending after the first UART instead of
*        the last.
**************************************************/
static void stream_json_object_end(void)
{
    scope_trig_seq_commit();

    /* HOLD THE PIN LOW LONG ENOUGH TO SEE.  Added 10-09-2026.
       The commit above has already dropped the pin and recorded the span, so
       the measurement is complete and this cannot affect it. Without the hold
       the stream task loops straight back into the next read, lwip_recv()
       returns the following frame from the socket buffer immediately, and the
       pin goes high again microseconds later - a falling edge far too narrow
       to see on any timebase that also shows the pulse.

       Task context, interrupts enabled, and self-disabling if no pulse ended.
       See SCOPE_TRIG_MIN_IDLE_US in scope_trig.h. */
    scope_trig_hold_idle();
}

#define STREAM_JSON_FIELD_COUNT \
    ((uint8_t)(sizeof(Stream_json_fields) / sizeof(Stream_json_fields[0])))

/* PREFIX FIELD - tags every emitted line on every UART.  Added 27-08-2026.
   -------------------------------------------------------------------------
   Each UART carries "<sequence_id>,<value>\r\n" instead of a bare value:

       USART1   18,1787819915.843
       USART2   18,1787819915.830
       UART4    18,0
       UART5    18,0

   WHY IT IS WORTH THE FOUR EXTRA BYTES. Without it the four UARTs are four
   independent streams that merely happen to arrive at similar times. Nothing
   in the data says which lines belong together, so if any one UART ever drops
   or delays a line, everything after it is silently mis-paired - and the values
   stay individually valid, so no receiver can detect the skew. The sequence id
   makes that detectable, and makes the four re-joinable into one sample.

   The parser reads it ONCE per object and reuses it for all four fields, so the
   four cannot disagree about which sample they describe.

   Set to NULL to emit bare values as before. */
#define STREAM_JSON_PREFIX_KEY   "\"sequence_id\""

/**
* \copyright 2026 \@PINETICS as an unpublished work.
* Function name: static void stream_emit_json_value(uint8_t field,
*                                                   const char *text,
*                                                   uint16_t len)
*    \return None
*    \param  field: index into Stream_json_fields / Stream_json_route
*    \param  text: extracted value, CR LF already appended by the parser
*    \param  len: characters in text, excluding the NUL
* \author
* \date 27-AUG-2026
* \brief Sink for json_parser - routes one extracted value to its own UART.
*
*        ONE uart_dispatch_send() PER VALUE, deliberately. The parser appends
*        the CR LF itself precisely so this can be a single call: splitting the
*        value and its terminator into two messages would put two frames on the
*        queue per value, double the per-message RTOS overhead, and split the
*        PE9 scope pulse in two - making the receive-to-transmit measurement
*        read as two events where there was one.
*
*        THIS IS ALREADY NON-BLOCKING. uart_dispatch_send() copies into a heap
*        message and returns as soon as the queue accepts it; the four per-UART
*        FreeRTOS tasks do the transmitting with HAL_UART_Transmit_IT() and wait
*        on a semaphore, so the TLS read loop never waits for a UART. That is
*        the existing architecture and it is exactly what is wanted here - no
*        new task, queue or lock is introduced.
*
*        A value plus CR LF is about 16 bytes against UART_DISPATCH_MAX_PAYLOAD
*        of 128, so the length check inside uart_dispatch_send() cannot fire
*        here unless JSON_PARSER_VALUE_MAX is raised past 126.
**************************************************/
static void stream_emit_json_value(uint8_t field, const char *text, uint16_t len)
{
    if (field < STREAM_JSON_FIELD_COUNT)
    {
        int rc;

#if STREAM_JSON_APPEND_EPOCH
        /* Rebuild the line with the epoch as a third column. The parser hands
           over "<seq>,<value>\r\n"; the CR LF is dropped, ",<epoch>" is
           appended, and the terminator put back, giving
           "<seq>,<value>,<epoch>\r\n".

           Rebuilt HERE rather than asking the parser for a suffix, because the
           epoch is not JSON - it is this application's local clock, and
           json_parser.c has no business knowing about it. */
        /* Sized for the parser's worst-case line plus ",<epoch>". The epoch is
           at most 17 characters until the year 2286, so 40 is ample.

           NOTE the real ceiling is UART_DISPATCH_MAX_PAYLOAD, 128 bytes. A
           realistic line - "13627,1787909496.189722,1787909495.821000" - is
           about 42, and even the parser's theoretical maximum leaves headroom.
           If a line ever did exceed 128, uart_dispatch_send_seq() refuses it
           and it shows up in Stream.uart_drops rather than being truncated. */
        char     line[JSON_PARSER_OUT_MAX + 40U];
        uint16_t body = len;
        int      n;

        while ((body > 0U) &&
               ((text[body - 1U] == '\n') || (text[body - 1U] == '\r')))
        {
            body--;
        }

        if (Stream_json_epoch[0] != '\0')
        {
            n = snprintf(line, sizeof(line), "%.*s,%s\r\n",
                         (int)body, text, Stream_json_epoch);
        }
        else
        {
            /* Clock not synchronised - two columns, not a fake third. */
            n = snprintf(line, sizeof(line), "%.*s\r\n", (int)body, text);
        }

        if ((n <= 0) || ((size_t)n >= sizeof(line)))
        {
            /* Would have truncated. Send the parser's line unchanged rather
               than a half-formed one. */
            rc = uart_dispatch_send_seq(Stream_json_route[field],
                                        (const uint8_t *)text, (size_t)len,
                                        NULL, Stream_json_seq);
        }
        else
        {
            rc = uart_dispatch_send_seq(Stream_json_route[field],
                                        (const uint8_t *)line, (size_t)n,
                                        NULL, Stream_json_seq);
            len = (uint16_t)n;   /* so uart_bytes below counts what was sent */
        }
#else
        /* TAGGED WITH THE SEQUENCE ID so the transmit-complete interrupt can
           say which object it belonged to - see uart_dispatch_send_seq(). */
        rc = uart_dispatch_send_seq(Stream_json_route[field],
                                    (const uint8_t *)text, (size_t)len,
                                    NULL, Stream_json_seq);
#endif

        if (rc == 0)
        {
            Stream.uart_bytes += len;

            /* Only a SUCCESSFUL send joins the expected set. A dropped message
               produces no transmit-complete, so counting it here would leave
               the pin waiting for a report that can never arrive. */
            scope_trig_seq_expect(Stream_json_scope_idx[field]);
        }
        else
        {
            /* Same policy as the raw path: counted, never retried. Blocking to
               wait for queue space would stall the TLS read loop and cost the
               connection - and at ~16 bytes per field against a 2 Mbaud UART
               the queue should never fill, so a non-zero uart_drops with
               extraction on means something is genuinely wrong, not busy. */
            Stream.uart_drops++;
            if (Stream.uart_drops <= 3U)
            {
                printf("stream: json field %u -> uart_dispatch_send returned %d\r\n",
                       (unsigned)field, rc);
            }
            else
            {
                /* Already reported three times. */
            }
        }
    }
    else
    {
        /* Cannot happen - the parser only reports indices from the table it was
           given. Guarded anyway because the alternative is an out-of-bounds
           read of Stream_json_route[]. */
    }
}
#endif /* STREAM_JSON_EXTRACT_ENABLE */

static void stream_forward_to_uart(const uint8_t *data, uint32_t len)
{
#if STREAM_JSON_EXTRACT_ENABLE
    /* ===== EXTRACT ONE FIELD INSTEAD OF FORWARDING EVERYTHING ==============
       Added 27-08-2026. The parser holds its own reassembly buffer across calls,
       so this hands it whatever arrived without caring whether that is half an
       object, one object, or several - see json_parser.h. Values are emitted
       through stream_emit_json_value() above as they complete.

       Nothing else in this function runs in this build; the raw splitter below
       is what STREAM_JSON_EXTRACT_ENABLE == 0 selects instead. */
    (void)json_parser_feed(data, len);
#else
    /* FIXED DESTINATION, AND NO SELECTOR BYTE IS CONSUMED.  24-08-2026.
       ------------------------------------------------------------------
       The reference module read data[0] as a UART selector and started the
       payload at data[1]. This one does not: every byte received on the
       stream is payload, and all of it goes to STREAM_UART_SELECTOR.

       That is the whole point of the change, so it is worth being explicit
       about the consequence. If the server ever DOES prefix records with a
       selector byte, that byte will now be printed as data rather than
       obeyed - it will show up as a stray 0x01..0x04 at the start of each
       record on the UART. Nothing will report it, because from here it is
       indistinguishable from real payload. Should the wire format grow a
       selector later, this function is the one place to change.

       There is no minimum length check any more either. A zero-length
       payload is simply nothing to send, which the loop below handles by
       not iterating - the old "len < 2" guard existed only because one of
       those bytes had to be the selector. */
    const uint8_t selector = (uint8_t)STREAM_UART_SELECTOR;
    uint32_t      offset;

    /* Dispatch the payload in pieces no larger than the bridge accepts.
       uart_dispatch_send() refuses more than UART_DISPATCH_MAX_PAYLOAD with -1,
       so splitting is what lets an arbitrary record size through intact. */
    offset = 0U;
    while (offset < len)
    {
        uint32_t piece = len - offset;
        int      rc;

        if (piece > UART_DISPATCH_MAX_PAYLOAD)
        {
            piece = UART_DISPATCH_MAX_PAYLOAD;
        }
        else
        {
            /* Fits in one message. */
        }

        /* conn is NULL: there is no HTTP connection awaiting a reply on this
           path, unlike POST /uart. uart_dispatch_send() only stores it. */
        rc = uart_dispatch_send(selector, &data[offset], (size_t)piece, NULL);

        if (rc == 0)
        {
            Stream.uart_bytes += piece;
        }
        else
        {
            /* -1 is a rejected selector or length, -2 a full queue. Both mean
               this piece did not make it, and a full queue is the expected one
               under load: the UART is far slower than the network, so a stream
               faster than the baud rate WILL back up here. Counted rather than
               retried - blocking the receive loop to wait for a UART would cost
               the TLS connection. */
            Stream.uart_drops++;
            if (Stream.uart_drops <= 3U)
            {
                printf("stream: uart_dispatch_send(sel=%u, %lu B) returned %d\r\n",
                       (unsigned)selector, (unsigned long)piece, rc);
            }
            else
            {
                /* Already reported three times. */
            }
        }

        offset += piece;
    }
#endif /* STREAM_JSON_EXTRACT_ENABLE - raw splitter above is the 0 branch */
}

static void stream_process_payload(const uint8_t *data, uint32_t len)
{
    /* ===== SCOPE TRIGGER: RISING EDGE - "a frame arrived from the server" ==
       FIRST STATEMENT IN THE FUNCTION, deliberately. Everything after this line
       - the echo, the accounting, the JSON reassembly, the key search, the UART
       queue and the transmit itself - is inside the measured window. Anything
       placed above it would be processing time the pulse silently omits.

       ONLY IN FROM_NETWORK MODE. With SCOPE_TRIG_FROM_ETH the rising edge is
       earlier still - ETH_IRQHandler, before HAL_ETH_IRQHandler() - so this
       call must NOT be compiled: two sources raising one pin against a single
       release would leave it permanently ACTIVE. scope_trig_net_arrival() does
       not even exist in that build, so the mistake shows up as an undefined
       reference at LINK rather than as a wrong measurement. */
#if (SCOPE_TRIG_ENABLE && SCOPE_TRIG_FROM_NETWORK && !SCOPE_TRIG_FROM_ETH)
    scope_trig_net_arrival();
#endif

    Stream.rx_bytes += len;

#if STREAM_DUMP_FRAME_TO_VCP
    /* ===== THE WHOLE RECEIVED FRAME, VERBATIM, TO THE VCP ==================
       The complete decrypted WebSocket payload as it arrived - before any JSON
       parsing, so what appears on the console is exactly what came off the
       wire, not a reconstruction of it.

       vcom_tx_write() rather than printf(): the payload is not NUL-terminated
       and may contain any byte, so "%s" would run off the end of it and "%.*s"
       would still stop at an embedded zero. Writing the bytes with an explicit
       length is the only form that cannot misread the buffer.

       NON-BLOCKING. The bytes are copied into the console ring and this returns
       immediately; the USART3 interrupt drains it. With the BSP's original
       blocking console this same line would have stalled the stream task for
       14.8 ms per frame at 115200 baud, inside the TLS receive path.

       If the ring is full the frame is dropped and counted in vcom_tx_dropped -
       the console never holds up the network. */
    (void)vcom_tx_write(data, len);
    (void)vcom_tx_write((const uint8_t *)"\r\n", 2U);
#endif

#if STREAM_ECHO_ENABLE
    /* ECHO STRAIGHT BACK, so the sender can time the round trip. Done FIRST,
       before the accounting and any printf below, because everything after this
       point adds to the measured latency and none of it is part of what the
       round trip is supposed to represent.

       The record has already been decrypted by mbedtls_ssl_read() before this
       function was called, so what is timed is genuinely receive, decrypt,
       re-encrypt and send - not a TCP-level bounce. */
    {
        size_t   n = (len < STREAM_ECHO_MAX_BYTES) ? len : STREAM_ECHO_MAX_BYTES;
        int      w = mbedtls_ssl_write(&Stream.ssl, data, n);

        if (w < 0)
        {
            /* Reported once per failure and then ignored. A lost timing sample
               is not worth tearing down a working stream for, and the read loop
               will notice soon enough if the connection is genuinely gone. */
            Stream.echo_fails++;
            if (Stream.echo_fails <= 3U)
            {
                printf("stream: echo write failed (-0x%04X)\r\n",
                       (unsigned)(-w));
            }
            else
            {
                /* Already reported three times - staying quiet. */
            }
        }
        else
        {
            Stream.echo_bytes += (uint32_t)w;
        }
    }
#endif

#if STREAM_UART_FORWARD_ENABLE
    /* Forward to the physical UART. Done AFTER the echo above so the round-trip
       measurement is not inflated by queueing work the sender cannot see. */
    stream_forward_to_uart(data, len);
#endif

#if STREAM_REPORT_ENABLE
    if (Stream.rx_bytes >= Stream.report_at)
    {
        /* Show a short printable preview so the log proves real data arrived,
           not merely that a byte counter moved. Non-printable bytes become '.'
           so a binary stream cannot corrupt the terminal. */
        char     preview[33];
        uint32_t n = (len < 32U) ? len : 32U;
        uint32_t i;

        for (i = 0U; i < n; i++)
        {
            char c = (char)data[i];
            preview[i] = ((c >= 0x20) && (c < 0x7F)) ? c : '.';
        }
        preview[n] = '\0';

        printf("stream: %lu B in, %lu echoed, %lu to UART (%lu dropped) | %s\r\n",
               (unsigned long)Stream.rx_bytes, (unsigned long)Stream.echo_bytes,
               (unsigned long)Stream.uart_bytes, (unsigned long)Stream.uart_drops,
               preview);

        Stream.report_at = Stream.rx_bytes + STREAM_REPORT_EVERY_BYTES;
    }
    else
    {
        /* Below the reporting interval - counted, not printed. */
    }
#else
    /* Periodic reporting disabled - see STREAM_REPORT_ENABLE. The counters
       Stream.rx_bytes, uart_bytes and uart_drops are still maintained and are
       readable in the debugger; only the printf is gone. */
#endif
}

#if !STREAM_USE_WEBSOCKET   /* plain-HTTP body path */
/**
* \copyright 2026 \@PINETICS as an unpublished work.
* Function name: static int32_t stream_stream_identity(uint32_t limit,
*                                                    int32_t bounded)
*    \return 0 on an orderly end of a bounded body, -1 when the connection ends.
*    \param  limit - byte count to stop after, when bounded is 1.
*    \param  bounded - 1 for a Content-Length body, 0 for an endless stream.
* \author
* \date 21-AUG-2026
* \brief Consumes an unframed body until the length is met or the peer goes.
*
*        For the unbounded case a return is always -1, because the only way such
*        a stream ends is the connection ending. That is the expected path for
*        this application and is not treated as an error by the caller.
**************************************************/
static int32_t stream_stream_identity(uint32_t limit, int32_t bounded)
{
    uint32_t taken = 0U;
    uint32_t idle_reads = 0U;

    for (;;)
    {
        uint32_t got = 0U;
        uint32_t want = STREAM_RX_CHUNK_BYTES;

        if ((bounded != 0) && ((limit - taken) < want))
        {
            want = limit - taken;
        }
        else
        {
            /* Read a full buffer. */
        }

        if (stream_read_some(Stream.rx, want, &got) != 0)
        {
            return -1;
        }
        else if (got == 0U)
        {
            /* Idle. A continuous stream that has said nothing for several
               consecutive timeouts is treated as gone, which is what detects a
               peer that vanished without closing - a yanked cable or a killed
               process leaves TCP with nothing to report for minutes. */
            idle_reads++;
            if (idle_reads >= 3U)
            {
                printf("stream: no data for %lu s - assuming the peer is gone\r\n",
                       (unsigned long)(3U * (uint32_t)STREAM_SOCKET_TIMEOUT_S));
                return -1;
            }
            else
            {
                continue;
            }
        }
        else
        {
            idle_reads = 0U;
        }

        stream_process_payload(Stream.rx, got);
        taken += got;

        if ((bounded != 0) && (taken >= limit))
        {
            printf("stream: bounded body of %lu bytes complete\r\n",
                   (unsigned long)limit);
            return 0;
        }
        else
        {
            /* Keep going. */
        }
    }
}
#endif /* !STREAM_USE_WEBSOCKET */

#if !STREAM_USE_WEBSOCKET   /* plain-HTTP body path */
/**
* \copyright 2026 \@PINETICS as an unpublished work.
* Function name: static int32_t stream_stream_chunked(void)
*    \return 0 on the terminating zero-length chunk, -1 when the connection
*            ends or the framing is malformed.
*    \param  void
* \author
* \date 21-AUG-2026
* \brief Consumes a chunked body, chunk by chunk, indefinitely.
*
*        This is the recommended framing for the i.MX7 because each record is
*        self-delimiting: the reader always knows how many payload bytes to
*        expect next, so a partial TCP receive can never be mistaken for the end
*        of a record. An identity stream has no such marker and relies on the
*        application to find its own boundaries.
*
*        A zero-length chunk is the server saying the stream is finished. That
*        is an orderly end, so it returns 0 and the caller reconnects after a
*        backoff rather than reporting a fault.
**************************************************/
static int32_t stream_stream_chunked(void)
{
    char     line[STREAM_CHUNK_LINE_MAX];
    uint32_t len = 0U;

    for (;;)
    {
        uint32_t remaining;
        uint32_t discard = 0U;

        if (stream_read_line(line, sizeof(line), &len) != 0)
        {
            return -1;
        }
        else if (len == 0U)
        {
            /* Blank line where a chunk size was expected - this is the CRLF
               that terminated the PREVIOUS chunk's data, so skip it and read
               the size on the next pass. */
            continue;
        }
        else
        {
            /* A chunk-size line. */
        }

        /* strtoul stops at the first non-hex character, which correctly ignores
           any chunk extension after a semicolon. */
        remaining = (uint32_t)strtoul(line, NULL, 16);

        if (remaining == 0U)
        {
            printf("stream: server ended the stream (zero-length chunk)\r\n");
            /* Consume the trailer's blank line if it arrives; failing to is not
               an error, since the connection is finished either way. */
            (void)stream_read_line(line, sizeof(line), &discard);
            return 0;
        }
        else
        {
            /* Payload follows. */
        }

        while (remaining > 0U)
        {
            uint32_t got = 0U;
            uint32_t want = (remaining < STREAM_RX_CHUNK_BYTES)
                            ? remaining : STREAM_RX_CHUNK_BYTES;

            if (stream_read_some(Stream.rx, want, &got) != 0)
            {
                return -1;
            }
            else if (got == 0U)
            {
                /* Timed out PART WAY THROUGH a chunk. Unlike an idle gap
                   between chunks this is a broken promise - the server declared
                   a length and then stopped - so it is not tolerated. */
                printf("stream: stalled with %lu bytes of a chunk outstanding\r\n",
                       (unsigned long)remaining);
                return -1;
            }
            else
            {
                /* Data in hand. */
            }

            stream_process_payload(Stream.rx, got);
            remaining -= got;
        }
    }
}
#endif /* !STREAM_USE_WEBSOCKET */

/**
* \copyright 2026 \@PINETICS as an unpublished work.
* Function name: static int32_t stream_run_cycle(void)
*    \return 0 if a stream was established and later ended in an orderly way,
*            -1 if the cycle failed at any earlier point.
*    \param  void
* \author
* \date 21-AUG-2026
* \brief One complete attempt: connect, handshake, request, stream, tear down.
*
*        Always disconnects before returning, on every path, so the caller never
*        has to reason about whether a socket is still open.
**************************************************/
#if STREAM_USE_WEBSOCKET

/**
* \copyright 2026 \@PINETICS as an unpublished work.
* Function name: static int32_t stream_ws_handshake(void)
*    \return 0 if the connection is now a WebSocket, -1 otherwise.
*    \param  void
* \author
* \date 24-AUG-2026
* \brief Performs the RFC 6455 opening handshake over the established TLS
*        connection.
*
*        THE ACCEPT VALUE IS CHECKED, NOT ASSUMED. A server answering 101 has
*        not proved anything by itself - the Sec-WebSocket-Accept header must
*        be base64(SHA-1(our key + the RFC's GUID)). Skipping that check would
*        mean treating any 101 as success and then parsing whatever followed
*        as frame headers, taking a payload length from arbitrary bytes.
*
*        The status line and headers are read with the SAME line reader the
*        plain-HTTP path uses, because up to the blank line a WebSocket
*        handshake IS an HTTP exchange.
**************************************************/
static int32_t stream_ws_handshake(void)
{
    char     key[WS_KEY_B64_SIZE];
    char     want_accept[WS_ACCEPT_B64_SIZE];
    char     request[320];
    char     line[192];
    uint32_t line_len = 0U;
    int      len;
    int32_t  status = 0;
    int32_t  code = 0;
    int32_t  saw_accept = 0;
    int32_t  saw_upgrade = 0;

    if (ws_make_key(&Stream.drbg, key, sizeof(key)) != WS_OK)
    {
        printf("stream: could not generate a Sec-WebSocket-Key\r\n");
        return -1;
    }
    else if (ws_expected_accept(key, want_accept, sizeof(want_accept)) != WS_OK)
    {
        printf("stream: could not compute the expected accept value\r\n");
        return -1;
    }
    else
    {
        /* Key and its expected answer both ready. */
    }

    /* Sec-WebSocket-Version is 13 and nothing else is legal - RFC 6455 4.1.
       No Sec-WebSocket-Extensions or -Protocol are offered, deliberately: this
       module implements neither, and offering one a server then selects would
       leave us decoding a stream we do not understand. */
    len = snprintf(request, sizeof(request),
                   "GET %s HTTP/1.1\r\n"
                   "Host: %s:%u\r\n"
                   "Upgrade: websocket\r\n"
                   "Connection: Upgrade\r\n"
                   "Sec-WebSocket-Key: %s\r\n"
                   "Sec-WebSocket-Version: 13\r\n"
                   "\r\n",
                   /* THE Host HEADER GOES ON THE WIRE - it is not a log line.
                      It named STREAM_SERVER_HOST unconditionally, so with mDNS
                      selected the board connected to the resolved address but
                      announced itself to the stale literal. This server does
                      not check, which is why it worked; one doing name-based
                      virtual hosting would have refused the upgrade, and the
                      failure would have pointed at the WebSocket layer rather
                      than at a header field. */
                   STREAM_WS_PATH, STREAM_SERVER_NAME_FOR_LOG,
                   (unsigned)STREAM_SERVER_PORT, key);

    if ((len <= 0) || ((size_t)len >= sizeof(request)))
    {
        printf("stream: upgrade request does not fit its buffer\r\n");
        status = -1;
    }
    else if (mbedtls_ssl_write(&Stream.ssl, (const unsigned char *)request,
                               (size_t)len) != len)
    {
        printf("stream: upgrade request write failed\r\n");
        status = -1;
    }
    else
    {
        /* Sent. */
    }

    /* ---- status line: must be 101 -------------------------------------- */
    if (status == 0)
    {
        if (stream_read_line(line, sizeof(line), &line_len) != 0)
        {
            printf("stream: no response to the upgrade request\r\n");
            status = -1;
        }
        else if (sscanf(line, "HTTP/1.%*d %ld", (long *)&code) != 1)
        {
            printf("stream: unparseable status line: %s\r\n", line);
            status = -1;
        }
        else if (code != 101)
        {
            /* 101 IS THE ONLY SUCCESS. A 200 here means the server served the
               path as an ordinary resource and never upgraded - the commonest
               misconfiguration, and one that would otherwise show up as
               garbage frame headers. */
            printf("stream: upgrade refused - server answered %ld, wanted 101\r\n",
                   (long)code);
            if (code == 200)
            {
                printf("stream:     200 means %s is a normal HTTP resource on "
                       "this server, not a WebSocket endpoint.\r\n",
                       STREAM_WS_PATH);
            }
            else
            {
                /* Some other refusal; the code above is the useful part. */
            }
            status = -1;
        }
        else
        {
            /* Switching Protocols. */
        }
    }

    /* ---- headers: Upgrade, and the accept value ------------------------ */
    while (status == 0)
    {
        if (stream_read_line(line, sizeof(line), &line_len) != 0)
        {
            printf("stream: connection closed inside the handshake headers\r\n");
            status = -1;
        }
        else if (line_len == 0U)
        {
            break;                       /* blank line - headers done */
        }
        else if (stream_header_is(line, "Sec-WebSocket-Accept") != 0)
        {
            const char *val = strchr(line, ':');

            if (val == NULL)
            {
                /* Cannot happen - stream_header_is matched the colon - but a
                   NULL dereference here would be a hard fault, so it is
                   handled rather than assumed away. */
                status = -1;
            }
            else
            {
                val++;
                while ((*val == ' ') || (*val == '\t'))
                {
                    val++;
                }

                if (strcmp(val, want_accept) != 0)
                {
                    printf("stream: *** Sec-WebSocket-Accept MISMATCH ***\r\n");
                    printf("stream:     got  %s\r\n", val);
                    printf("stream:     want %s\r\n", want_accept);
                    printf("stream:     the peer answered 101 but cannot prove "
                           "it speaks WebSocket - refusing.\r\n");
                    status = -1;
                }
                else
                {
                    saw_accept = 1;
                }
            }
        }
        else if (stream_header_is(line, "Upgrade") != 0)
        {
            saw_upgrade = 1;
        }
        else
        {
            /* Any other header - Connection, Server, Date. Not needed. */
        }
    }

    if (status == 0)
    {
        if (saw_accept == 0)
        {
            /* No accept header at all. Same conclusion as a wrong one: the
               peer has not proved it is a WebSocket server. */
            printf("stream: 101 with no Sec-WebSocket-Accept header - refusing\r\n");
            status = -1;
        }
        else if (saw_upgrade == 0)
        {
            /* Reported but not fatal: the accept value is the cryptographic
               proof, and a server that computed it correctly while omitting
               the Upgrade echo is sloppy rather than an impostor. */
            printf("stream: note - 101 without an Upgrade header (accepted, "
                   "the accept value matched)\r\n");
        }
        else
        {
            /* Fully formed. */
        }
    }

    if (status == 0)
    {
        printf("stream: WebSocket established on %s\r\n", STREAM_WS_PATH);
    }
    else
    {
        /* Already reported. */
    }

    return status;
}

/**
* \copyright 2026 \@PINETICS as an unpublished work.
* Function name: static int32_t stream_ws_read_loop(void)
*    \return 0 if the peer closed cleanly, -1 on error.
*    \param  void
* \author
* \date 24-AUG-2026
* \brief Reads WebSocket frames until the connection ends, forwarding payload.
*
*        ONLY PAYLOAD REACHES stream_process_payload(). Frame headers, pings,
*        pongs and close frames are consumed here and never forwarded, which is
*        the practical improvement over the plain-HTTP path - there, the HTTP
*        response headers arrive at the UART as data.
*
*        THE HEADER IS READ ONE BYTE AT A TIME, and that is deliberate rather
*        than lazy. A header is 2 to 14 bytes and its length is not known until
*        the second byte has been seen; reading a fixed block would over-read
*        into the payload, and reading into a holding buffer would mean
*        carrying leftovers across frames. ws_parse_header() reports NEED_MORE
*        until it has enough, so the loop simply feeds it. The cost is a few
*        extra mbedtls_ssl_read() calls per frame, all served from a record
*        already decrypted in mbedTLS's buffer.
**************************************************/
static int32_t stream_ws_read_loop(void)
{
    uint8_t  hdr_buf[WS_MAX_HEADER_BYTES];
    uint8_t  ctrl[125];                  /* control payloads cap at 125 */
    int32_t  status = 0;
    int32_t  running = 1;

    while (running != 0)
    {
        ws_frame_hdr_t h;
        uint32_t       hdr_len = 0U;
        int32_t        rc;
        uint64_t       remaining;
        uint32_t       ctrl_len = 0U;

        /* ---- accumulate one frame header ------------------------------- */
        rc = ws_parse_header(hdr_buf, hdr_len, &h);
        while (rc == WS_ERR_NEED_MORE)
        {
            uint32_t got = 0U;

            if (hdr_len >= (uint32_t)sizeof(hdr_buf))
            {
                /* Unreachable while ws_parse_header is correct - it never asks
                   for more than 14 bytes - but a runaway here would read for
                   ever, so it is bounded rather than trusted. */
                printf("stream: frame header exceeded %u bytes\r\n",
                       (unsigned)sizeof(hdr_buf));
                return -1;
            }
            else
            {
                /* Room remains. */
            }

            if (stream_read_some(&hdr_buf[hdr_len], 1U, &got) != 0)
            {
                printf("stream: connection lost inside a frame header\r\n");
                return -1;
            }
            else if (got == 0U)
            {
                continue;                /* timeout, connection still up */
            }
            else
            {
                hdr_len += got;
            }

            rc = ws_parse_header(hdr_buf, hdr_len, &h);
        }

        if (rc < 0)
        {
            printf("stream: bad frame header (%ld) - closing\r\n", (long)rc);
            if (rc == WS_ERR_MASKED)
            {
                printf("stream:     the server masked a frame, which RFC 6455 "
                       "5.1 forbids.\r\n");
            }
            else if (rc == WS_ERR_TOO_LONG)
            {
                printf("stream:     frame larger than this client accepts.\r\n");
            }
            else
            {
                printf("stream:     reserved opcode or RSV bit - an extension "
                       "we never negotiated.\r\n");
            }
            return -1;
        }
        else
        {
            /* Header decoded. */
        }

        /* ---- consume the payload --------------------------------------- */
        remaining = h.payload_len;

        while (remaining > 0U)
        {
            uint32_t want;
            uint32_t got = 0U;

            want = (remaining > (uint64_t)STREAM_RX_CHUNK_BYTES)
                   ? (uint32_t)STREAM_RX_CHUNK_BYTES : (uint32_t)remaining;

            if (stream_read_some(Stream.rx, want, &got) != 0)
            {
                printf("stream: connection lost inside a frame payload\r\n");
                return -1;
            }
            else if (got == 0U)
            {
                continue;                /* timeout, connection still up */
            }
            else
            {
                /* Got some. */
            }

            if ((h.opcode & 0x08U) != 0U)
            {
                /* Control frame - keep it, do not forward it. Bounded by the
                   125-byte cap ws_parse_header() already enforced. */
                uint32_t room = (uint32_t)sizeof(ctrl) - ctrl_len;
                uint32_t take = (got < room) ? got : room;

                (void)memcpy(&ctrl[ctrl_len], Stream.rx, take);
                ctrl_len += take;
            }
            else
            {
                /* Data - TEXT, BINARY or CONTINUATION, all treated as opaque
                   bytes. This client does not care which: the requirement is
                   to forward what arrives, unchanged. */
                Stream.rx_bytes += got;
                stream_process_payload(Stream.rx, got);
            }

            remaining -= (uint64_t)got;
        }

        /* ---- act on control frames -------------------------------------- */
        if (h.opcode == WS_OP_PING)
        {
#if STREAM_WS_PONG_ENABLE
            uint8_t frame[WS_MAX_HEADER_BYTES + sizeof(ctrl)];
            int32_t n = ws_build_frame(WS_OP_PONG, ctrl, ctrl_len,
                                       &Stream.drbg, frame,
                                       (uint32_t)sizeof(frame));

            /* RFC 6455 5.5.3: the pong must carry the ping's payload back
               verbatim. A server using the payload as a nonce will reject an
               empty pong. */
            if (n <= 0)
            {
                printf("stream: could not build a PONG (%ld)\r\n", (long)n);
                status = -1;
                running = 0;
            }
            else if (mbedtls_ssl_write(&Stream.ssl, frame, (size_t)n) != n)
            {
                printf("stream: PONG write failed - closing\r\n");
                status = -1;
                running = 0;
            }
            else
            {
                /* Answered. Not logged: a server pinging every few seconds
                   would fill the console, and printf here is blocking UART. */
            }
#else
            /* Pongs disabled. A server that pings for liveness will drop this
               connection; see STREAM_WS_PONG_ENABLE. */
#endif
        }
        else if (h.opcode == WS_OP_CLOSE)
        {
            /* Echo the close and finish. Returning 0 marks this an orderly
               end, so the task reconnects on the minimum backoff rather than
               treating it as a fault. */
            uint8_t frame[WS_MAX_HEADER_BYTES + 2U];
            int32_t n = ws_build_frame(WS_OP_CLOSE, ctrl,
                                       (ctrl_len > 2U) ? 2U : ctrl_len,
                                       &Stream.drbg, frame,
                                       (uint32_t)sizeof(frame));

            if (n > 0)
            {
                (void)mbedtls_ssl_write(&Stream.ssl, frame, (size_t)n);
            }
            else
            {
                /* Could not build one; closing anyway. */
            }

            printf("stream: server sent CLOSE after %lu B\r\n",
                   (unsigned long)Stream.rx_bytes);
            status = 0;
            running = 0;
        }
        else
        {
            /* PONG, or a data frame already forwarded. Nothing further. */
        }
    }

    return status;
}

#endif /* STREAM_USE_WEBSOCKET */

static int32_t stream_run_cycle(void)
{
    int32_t  status;
#if !STREAM_USE_WEBSOCKET
    /* Outputs of stream_parse_response_head(), which only the plain-HTTP path
       calls. A WebSocket body has no Content-Length and no chunked encoding -
       its framing is in the frames - so in that mode these three would sit
       unused and -Wall would say so three times. */
    int32_t  chunked = 0;
    int32_t  has_length = 0;
    uint32_t content_length = 0U;
#endif

    Stream.state = STREAM_STATE_CONNECTING;
    /* THE NAME PRINTED MUST BE THE ONE ACTUALLY IN USE.  Fixed 10-09-2026.
       This line named STREAM_SERVER_HOST unconditionally, so with mDNS
       selected it read "connecting to 192.168.0.61 (192.168.40.146)" - the
       stale literal beside the resolved address. The connection was correct;
       the log was not, and a log that names an address the firmware is not
       using is worse than one that says nothing. */
    printf("stream: connecting to %s (%s) port %u\r\n",
           STREAM_SERVER_NAME_FOR_LOG, ip4addr_ntoa(&Stream.target),
           (unsigned)STREAM_SERVER_PORT);

    status = stream_tcp_connect();

    if (status == 0)
    {
        status = stream_tls_setup();
    }
    else
    {
        /* Already failed. */
    }

    /* ONE BRANCH, TAKEN TWICE. The connect and TLS handshake above are shared;
       everything after them differs between the two protocols, so the switch
       is applied to the request and to the body reader together. Splitting it
       would allow a WebSocket handshake followed by an HTTP body reader, which
       is a state nothing could recover from. */
    if (status == 0)
    {
        Stream.state = STREAM_STATE_REQUESTING;
#if STREAM_USE_WEBSOCKET
        status = stream_ws_handshake();
#else
        status = stream_send_request();
#endif
    }
    else
    {
        /* Already failed. */
    }

#if !STREAM_USE_WEBSOCKET
    if (status == 0)
    {
        status = stream_parse_response_head(&chunked, &has_length,
                                          &content_length);
    }
    else
    {
        /* Already failed. */
    }
#endif

    if (status == 0)
    {
        /* A stream is up. Recorded BEFORE consuming it, so the counter reflects
           connections established rather than connections that ended tidily. */
        Stream.connects++;
        Stream.backoff_ms = STREAM_BACKOFF_MIN_MS;
        Stream.state = STREAM_STATE_STREAMING;

#if STREAM_JSON_EXTRACT_ENABLE
        /* DISCARD ANY HALF-RECEIVED OBJECT FROM THE PREVIOUS CONNECTION.
           Without this, the tail of an object cut off by a dropped stream would
           be joined to the first bytes of the new one, producing exactly one
           corrupt object per reconnect - the kind of fault that appears only
           after a cable event and is then very hard to attribute.

           This also zeroes the parser counters, so they read per-connection.
           Cumulative byte totals are still in the stream report. */
        json_parser_reset();
#endif

#if STREAM_USE_WEBSOCKET
        status = stream_ws_read_loop();
#else
        if (chunked != 0)
        {
            status = stream_stream_chunked();
        }
        else
        {
            status = stream_stream_identity(content_length, has_length);
        }
#endif
    }
    else
    {
        /* Never got as far as streaming. */
    }

    stream_disconnect();

    return status;
}

/**
* \copyright 2026 \@PINETICS as an unpublished work.
* Function name: static const char *stream_state_name(stream_client_state_t s)
*    \return A short name for the state.
*    \param  s - the state to name.
* \author
* \date 21-AUG-2026
* \brief Turns a state into text so the console says what the link is doing
*        rather than printing a bare number.
**************************************************/
static const char *stream_state_name(stream_client_state_t s)
{
    const char *name;

    /* One statement per line per GL11-C 14.14. The compact
       "case X: name = "Y"; break;" form reads better in a table like this, but
       it puts an assignment and a break on the same line, which 14.14 does not
       allow. Written out rather than argued about. */
    switch (s)
    {
        case STREAM_STATE_IDLE:
            name = "IDLE";
            break;

        case STREAM_STATE_WAIT_ADDR:
            name = "WAIT_ADDR";
            break;

        case STREAM_STATE_CONNECTING:
            name = "CONNECTING";
            break;

        case STREAM_STATE_HANDSHAKE:
            name = "HANDSHAKE";
            break;

        case STREAM_STATE_REQUESTING:
            name = "REQUESTING";
            break;

        case STREAM_STATE_STREAMING:
            name = "STREAMING";
            break;

        case STREAM_STATE_BACKOFF:
            name = "BACKOFF";
            break;

        default:
            name = "UNKNOWN";
            break;
    }

    return name;
}

/**
* \copyright 2026 \@PINETICS as an unpublished work.
* Function name: static void stream_task(void *argument)
*    \return void - never returns.
*    \param  argument - unused.
* \author
* \date 21-AUG-2026
* \brief The connection manager loop. Implements the reconnect policy described
*        in stream_client.h.
*
*        NEVER TERMINATES AND NEVER GIVES UP. There is no attempt limit after
*        which this task stops trying, because "the i.MX7 is switched off" must
*        not require a board reset to recover from. What bounds the cost instead
*        is the backoff: doubling from STREAM_BACKOFF_MIN_MS to
*        STREAM_BACKOFF_MAX_MS, so a long outage settles into one attempt every
*        30 s rather than a busy loop.
**************************************************/
static void stream_task(void *argument)
{
    (void)argument;

#if STREAM_USE_WEBSOCKET
    printf("stream: client ready - wss://%s:%u%s\r\n",
           STREAM_SERVER_NAME_FOR_LOG, (unsigned)STREAM_SERVER_PORT,
           STREAM_WS_PATH);
    printf("stream: WebSocket mode - only frame PAYLOAD reaches %s; HTTP and "
           "frame headers do not\r\n", STREAM_UART_NAME);
#else
    printf("stream: client ready - https://%s:%u%s\r\n",
           STREAM_SERVER_NAME_FOR_LOG, (unsigned)STREAM_SERVER_PORT,
           STREAM_PATH);
    printf("stream: plain HTTPS mode - the response HEADERS are forwarded to "
           "%s as data too\r\n", STREAM_UART_NAME);
#endif
    printf("stream: received data goes to %s (selector %u), whole payload, "
           "no selector byte consumed\r\n",
           STREAM_UART_NAME, (unsigned)STREAM_UART_SELECTOR);

    Stream.backoff_ms = STREAM_BACKOFF_MIN_MS;
    Stream.report_at = STREAM_REPORT_EVERY_BYTES;
    Stream.fail_run  = 0U;
    Stream.mdns_gen  = 0U;

#if STREAM_SERVER_USE_MDNS
    /* WAIT FOR mDNS, DO NOT PARK.  Added 10-09-2026.
       With mDNS selected there is no address at init by design, so the "bad
       literal" reasoning above does not apply: this is not a permanent fault,
       it is an answer that has not arrived yet. The task therefore waits here
       instead of stopping.

       WAITING IS THE WHOLE POINT. Before this, the client connected
       immediately to whatever the literal held and raced the resolver - and
       won, because a TCP connect starts in microseconds while an mDNS query
       takes hundreds of milliseconds. The 10-09-2026 log shows the result:
       "connecting to 192.168.0.61" three lines above "resolved to
       192.168.40.135", followed by a timeout on the address it should never
       have used.

       There is no timeout on this wait, and that is deliberate. mdns_service
       retries for ever on its own schedule, so a server that is merely switched
       on late is picked up without a reset; and there is nothing this task
       could usefully do after giving up, since it has no other address to try.
       The rest of the firmware - HTTPS server, UART bridge, DHCP, scope
       trigger - runs normally throughout. */
    if (Stream.have_target == 0U)
    {
        uint32_t waited_ms = 0U;

        Stream.state = STREAM_STATE_WAIT_ADDR;
        printf("stream: waiting for mDNS to resolve %s\r\n",
               MDNS_TARGET_HOSTNAME);

        while (mdns_service_get_address_gen(&Stream.target,
                                            &Stream.mdns_gen) != 0)
        {
            osDelay(STREAM_MDNS_WAIT_POLL_MS);
            waited_ms += STREAM_MDNS_WAIT_POLL_MS;

            /* Reported periodically rather than per poll, so a genuinely
               absent server leaves a trail without flooding the console. */
            if ((waited_ms % STREAM_MDNS_WAIT_REPORT_MS) == 0U)
            {
                printf("stream: still waiting for %s (%lu s)\r\n",
                       MDNS_TARGET_HOSTNAME, (unsigned long)(waited_ms / 1000U));
            }
            else
            {
                /* Not a reporting boundary - stay quiet. */
            }
        }

        Stream.have_target = 1U;
        printf("stream: adopted %s from mDNS as %s:%u\r\n",
               MDNS_TARGET_HOSTNAME, ip4addr_ntoa(&Stream.target),
               (unsigned)STREAM_SERVER_PORT);
    }
    else
    {
        /* Cannot happen in this mode - init leaves have_target clear. */
    }
#else
    /* A BAD LITERAL IS FATAL TO THIS TASK, AND SAYS SO ONCE.
       stream_client_init() already reported the parse failure. Retrying would
       be pointless - STREAM_SERVER_HOST is a compile-time string and cannot
       become valid at run time - but the task must not spin either, so it
       parks. The rest of the firmware is unaffected: the HTTPS server, the
       UART bridge and DHCP all carry on. */
    if (Stream.have_target == 0U)
    {
        Stream.state = STREAM_STATE_WAIT_ADDR;
        printf("stream: *** no usable target address - this task is stopping "
               "***\r\n");
        for (;;)
        {
            osDelay(60000U);
        }
    }
    else
    {
        /* Address parsed at init; nothing to wait for. */
    }
#endif

    for (;;)
    {
        if (stream_run_cycle() == 0)
        {
            /* The stream ended in an orderly way - the server said it was
               finished. Reconnect after the minimum delay rather than the
               escalating one; this is not a fault. */
            printf("stream: stream ended cleanly, reconnecting\r\n");
            Stream.backoff_ms = STREAM_BACKOFF_MIN_MS;
            Stream.fail_run   = 0U;
        }
        else
        {
            Stream.fail_run++;

            /* A FIXED ADDRESS IS RETRIED FOR EVER, deliberately.
               The reference module counted failures here and, past a
               threshold, discarded the address and re-ran mDNS discovery.
               There is no equivalent for a literal address: re-parsing the
               same string cannot produce a different result. So the only
               response to a failure is to back off and try the same host
               again, which is what the code below does.

               The practical effect is that a server which is switched off,
               unreachable, or has MOVED to another address all look the same
               from here: repeated failures against STREAM_SERVER_HOST, once
               every STREAM_BACKOFF_MAX_MS. The console line printed by
               stream_run_cycle() names the address each time, so the log says
               plainly which host is not answering. */
            printf("stream: attempt %lu on %s failed\r\n",
                   (unsigned long)Stream.fail_run,
                   ip4addr_ntoa(&Stream.target));
        }

#if (STREAM_SERVER_USE_MDNS && (STREAM_MDNS_REFRESH_AFTER_FAILURES > 0U))
        /* ==================================================================
         * RE-RESOLVE AFTER REPEATED FAILURE, AND ADOPT A NEW ANSWER.
         * ==================================================================
         * A server that MOVED and a server that is merely DOWN are
         * indistinguishable from here - both just fail to connect. So after a
         * few failures the resolver is asked again, and if it comes back with
         * a different address the next attempt uses it.
         *
         * THE GENERATION IS WHAT MAKES THIS SAFE, and it is the whole reason
         * mdns_service_get_address_gen() exists. Asking for a refresh and then
         * reading the address would return the OLD one immediately - the
         * refresh has not been serviced yet - and that reads as a successful
         * rediscovery with no query on the wire. That exact fault cost real
         * time on hardware in mDNS_V00 on 21-08-2026; the note at the foot of
         * this file warns about it. Comparing generations is what tells a
         * genuinely new answer from the stale one still published.
         *
         * NOTHING BLOCKS HERE. The refresh is requested and the loop carries on
         * retrying the address it already has. A new generation is picked up
         * whenever it appears, on this pass or a later one. Blocking until the
         * resolver answered would stop retrying an address that may simply be
         * coming back up, which is the more common case of the two.
         * ============================================================== */
        if (Stream.fail_run == (uint32_t)STREAM_MDNS_REFRESH_AFTER_FAILURES)
        {
            printf("stream: %lu failures - asking mDNS to re-resolve %s\r\n",
                   (unsigned long)Stream.fail_run, MDNS_TARGET_HOSTNAME);
            mdns_service_request_refresh();
        }
        else
        {
            /* Not the threshold - one request per run of failures, not one per
               attempt, or a server that is off would put a query on the wire
               every backoff cycle. */
        }

        {
            ip4_addr_t fresh_addr;
            uint32_t   fresh_gen;

            if (mdns_service_get_address_gen(&fresh_addr, &fresh_gen) == 0)
            {
                if (fresh_gen != Stream.mdns_gen)
                {
                    /* A genuinely new answer. Adopt it even when the address is
                       unchanged - the generation moved, so the resolver did ask
                       and this is current information. */
                    /* NOTE THE SENSE OF ip4_addr_cmp(): lwIP defines it as
                       "addr1 == addr2", so it is TRUE when they MATCH. Testing
                       it against 0 therefore means the address CHANGED. */
                    if (ip4_addr_cmp(&fresh_addr, &Stream.target) == 0)
                    {
                        printf("stream: mDNS moved %s from %s",
                               MDNS_TARGET_HOSTNAME,
                               ip4addr_ntoa(&Stream.target));
                        printf(" to %s - adopting\r\n",
                               ip4addr_ntoa(&fresh_addr));
                        Stream.backoff_ms = STREAM_BACKOFF_MIN_MS;
                    }
                    else
                    {
                        /* Re-resolved to the same address; the server is down
                           rather than moved. Keep backing off. */
                    }

                    Stream.target   = fresh_addr;
                    Stream.mdns_gen = fresh_gen;
                    Stream.fail_run = 0U;
                }
                else
                {
                    /* Same generation - the refresh has not been answered yet,
                       or none was asked for. Keep the current address. */
                }
            }
            else
            {
                /* Resolver has nothing at all. Cannot happen once an address
                   has been adopted, since the published one is never cleared. */
            }
        }
#endif

        /* Backoff, then double it for next time. */
        Stream.state = STREAM_STATE_BACKOFF;
        printf("stream: state %s - next attempt in %lu ms\r\n",
               stream_state_name(Stream.state), (unsigned long)Stream.backoff_ms);
        osDelay(Stream.backoff_ms);

        if (Stream.backoff_ms < STREAM_BACKOFF_MAX_MS)
        {
            Stream.backoff_ms *= 2U;
            if (Stream.backoff_ms > STREAM_BACKOFF_MAX_MS)
            {
                Stream.backoff_ms = STREAM_BACKOFF_MAX_MS;
            }
            else
            {
                /* Still below the cap. */
            }
        }
        else
        {
            /* Already at the cap. */
        }
    }
}

/**
* \copyright 2026 \@PINETICS as an unpublished work.
* Function name: void stream_client_init(void)
*    \return void
*    \param  void
* \author
* \date 21-AUG-2026
* \brief Creates the client task. See the header.
**************************************************/
void stream_client_init(void)
{
    Stream.sock = -1;
    Stream.state = STREAM_STATE_IDLE;

#if STREAM_JSON_EXTRACT_ENABLE
    /* Install the field table and sink before anything can arrive.
       json_parser_init() also clears the parser, so this doubles as the
       initial reset. */
    json_parser_init(Stream_json_fields, STREAM_JSON_FIELD_COUNT,
                     STREAM_JSON_PREFIX_KEY, stream_emit_json_value);

    /* Per-object hooks for the PE9 Ethernet-to-UART measurement. Installed
       after json_parser_init() because that call clears the parser; the hooks
       themselves survive json_parser_reset() on reconnect. */
    json_parser_set_object_hooks(stream_json_object_begin,
                                 stream_json_object_end);
#endif

    /* PARSE THE TARGET ONCE, HERE, AND CHECK IT.  24-08-2026.
       ------------------------------------------------------------------
       STREAM_SERVER_HOST is a dotted-quad string literal, so this cannot
       fail at run time for any reason other than the literal being wrong -
       which is exactly why it is checked. ip4addr_aton() returns 0 on a
       malformed address, and without this check a typo such as
       "192.168.40.2 39" would leave Stream.target holding whatever was in
       .bss and the board would connect somewhere unintended, or nowhere,
       with nothing on the console pointing at the cause.

       ip4addr_aton(), not inet_addr(): inet_addr() reports failure as
       INADDR_NONE, which is also the valid broadcast address 255.255.255.255,
       so a caller cannot distinguish the two. lwIP's own parser returns a
       separate success flag and has no such ambiguity.

       Note this is a LITERAL ADDRESS, not a hostname - no DNS lookup happens
       and none is wanted. "192.168.40.239" resolves instantly and offline;
       a name would need a DNS server the bench may not have. */
#if STREAM_SERVER_USE_MDNS
    /* THE LITERAL IS DELIBERATELY NOT PARSED IN THIS MODE.  10-09-2026.
       The address comes from the mDNS resolver, which has almost certainly not
       answered yet - stream_client_init() runs from StartEthIfTask moments
       after mdns_service_init(), and a query takes hundreds of milliseconds at
       best. Parsing the literal here as a "default" would give the task an
       address it could connect to, and it would race the resolver and usually
       win: exactly the behaviour seen on 10-09-2026, where the client
       connected to the stale 192.168.0.61 and timed out while mDNS was
       reporting the correct 192.168.40.135 a few lines later.

       Starting with no address is what forces the wait in stream_task(). */
    Stream.have_target = 0U;
    ip4_addr_set_zero(&Stream.target);
    printf("stream: address will come from mDNS (%s), literal ignored\r\n",
           MDNS_TARGET_HOSTNAME);
#else
    if (ip4addr_aton(STREAM_SERVER_HOST, &Stream.target) != 0)
    {
        Stream.have_target = 1U;
    }
    else
    {
        Stream.have_target = 0U;
        printf("stream: *** STREAM_SERVER_HOST \"%s\" is not a valid IPv4 "
               "address ***\r\n", STREAM_SERVER_HOST);
        printf("stream:     expected a dotted quad such as \"192.168.40.239\"; "
               "fix it in stream_client.h and rebuild.\r\n");
    }
#endif

#if WS_SELFTEST_ENABLE
    /* RUN BEFORE THE FIRST CONNECTION, not after. If the framing is wrong,
       saying so here costs about 2 ms and names the fault; discovering it on
       the wire instead presents as a corrupt stream or an unexplained
       disconnect, with the actual defect several layers from the symptom.

       THE DRBG IS DELIBERATELY NOT PASSED. It is initialised but not yet
       SEEDED at this point - seeding happens in stream_tls_setup() on the
       first connection - and calling mbedtls_ctr_drbg_random() on an unseeded
       context is exactly the fault that HardFaulted this codebase with
       CFSR=0x00020000 and PC=0. ws_selftest() skips only its round-trip case
       without one; every RFC vector still runs. */
    (void)ws_selftest(NULL);
#endif

    stream_task_handle = osThreadNew(stream_task, NULL, &stream_task_attributes);
    if (stream_task_handle == NULL)
    {
        printf("stream: *** task creation FAILED ***\r\n");
    }
    else
    {
        /* Task created - it announces itself when it runs. */
    }
}

/* ==========================================================================
 * stream_client_set_target() and stream_client_service_resolver() were
 * REMOVED here on 24-08-2026, along with 142 lines of mDNS plumbing.
 * ==========================================================================
 * The module this was ported from learned its server address by mDNS, so it
 * needed one entry point for the resolver to hand an address in, and another
 * that the network task called every 250 ms to drive the query state machine.
 *
 * This client has a literal address, parsed once in stream_client_init(), so
 * both are meaningless - there is no query to drive and no result to collect.
 * They are noted rather than silently dropped because the reference module is
 * still in HTTP_Server_H753_RTOS_ES_MBEDTLS_mDNS_V00 and anyone diffing the
 * two will find them missing and want to know whether that was intentional.
 *
 * IF THIS EVER NEEDS mDNS AGAIN, take both functions back from
 * mDNS_V00\Core\Src\imx7_client.c rather than rewriting them. The two-flag
 * want_discovery / awaiting_result split in that file exists because a single
 * flag could not distinguish "please re-query" from "waiting for the query I
 * already asked for", and the resulting bug - a rediscovery satisfied by the
 * resolver's stale RESOLVED result, with no query on the wire - cost real
 * time on hardware on 21-08-2026.
 * ======================================================================= */


/**
* \copyright 2026 \@PINETICS as an unpublished work.
* Function name: stream_client_state_t stream_client_get_state(void)
*    \return The current state.
*    \param  void
* \author
* \date 21-AUG-2026
* \brief Reports the connection manager state.
**************************************************/
stream_client_state_t stream_client_get_state(void)
{
    return Stream.state;
}

/**
* \copyright 2026 \@PINETICS as an unpublished work.
* Function name: uint32_t stream_client_get_rx_bytes(void)
*    \return Cumulative payload bytes received.
*    \param  void
* \author
* \date 21-AUG-2026
* \brief Reports cumulative received payload.
**************************************************/
uint32_t stream_client_get_rx_bytes(void)
{
    return Stream.rx_bytes;
}

/**
* \copyright 2026 \@PINETICS as an unpublished work.
* Function name: uint32_t stream_client_get_connect_count(void)
*    \return Number of streams successfully established.
*    \param  void
* \author
* \date 21-AUG-2026
* \brief Reports how many times a stream has been established.
**************************************************/
uint32_t stream_client_get_connect_count(void)
{
    return Stream.connects;
}

#endif /* STREAM_CLIENT_ENABLE */
