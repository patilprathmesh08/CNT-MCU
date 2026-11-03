/**
* \file    stream_client.h
* \brief   Persistent HTTPS stream client - configuration and public interface.
*
* This block opens with two stars and carries a \file tag rather than the
* four-star banner printed in GL11-C 2.4, because Doxygen ignores any block
* opening with three or more stars. Everything else follows 2.4 unchanged.
*
* Module name: stream_client.h
*
* Copyright 2026 \@PINETICS as an unpublished work.
* All Rights Reserved.
*
* The information contained herein is confidential property of PINETICS. The
* user is prohibited from copying, transfer or disclosure of such information
* except by express written agreement with PINETICS.
*
* First written on 24-AUG-2026 by
*
* Module Description:
* The board opens an HTTPS connection OUT to a server at a fixed address,
* reads a continuous response body from it, and prints every byte of that body
* to one UART. It is a client here, unlike the rest of this project, which is
* an HTTPS server - the two run side by side and share nothing but the TLS
* credentials and the UART bridge.
*
*     board  ---- TLS 1.2 ---->  STREAM_SERVER_HOST : STREAM_SERVER_PORT
*            <--- body ---------  GET STREAM_PATH
*            ---- every byte -->  STREAM_UART_NAME
*
* WHAT THIS IS A PORT OF. imx7_client.c/.h in
* HTTP_Server_H753_RTOS_ES_MBEDTLS_mDNS_V00, which does the same job but finds
* its server by mDNS and reads a selector byte from each record. Both of those
* are gone here; see the provenance note at the top of stream_client.c for the
* full list of differences and why each was made.
*
* THREADING. Everything in this module runs on its own task, created by
* stream_client_init(). Nothing here may be called from tcpip_thread: the
* stream read blocks, and blocking tcpip_thread stops lwIP dead. The public
* accessors below are the exception - they read one word each and are safe to
* call from anywhere.
*
* APPROVED EXCEPTIONS (GL11-C 1.1)
* 1. Integer types. GL11-C 13.1 mandates uint8 / uint32 style typedefs. This
*    project uses the C99 <stdint.h> names together with lwIP's and mbedTLS's
*    own types, because every interface it calls is declared in those terms.
*    Ruled by the project owner on 12-08-2026.
*
****************************************************************/

#ifndef STREAM_CLIENT_H
#define STREAM_CLIENT_H

#ifdef __cplusplus
extern "C" {
#endif

/* Include section
***************************************************/
#include "main.h"            /* STREAM_CLIENT_MUTUAL_TLS */
#include "uart_dispatch.h"   /* UART_SELECTOR_* - STREAM_UART_SELECTOR uses one */
#include "lwip/ip_addr.h"    /* ip4_addr_t */

/* MDNS_TARGET_HOSTNAME - used by STREAM_SERVER_NAME_FOR_LOG below. Included
   directly rather than relying on main.h having pulled it in first; the header
   is dependency-free so this costs nothing and removes an ordering assumption. */
#include "mdns_config.h"

#include <stdint.h>

/* Defines section
***************************************************/

/* ==========================================================================
 * WHAT YOU ARE MOST LIKELY TO WANT TO CHANGE
 * ======================================================================= */

/**
  * @brief  Master switch. 0 compiles the whole module out - the .c file is one
  *         big #if - so the outbound client can be removed without touching
  *         the build configuration or main.c.
  */
#ifndef STREAM_CLIENT_ENABLE
#define STREAM_CLIENT_ENABLE            1
#endif

/**
  * @brief  The server this board connects OUT to.
  *
  * A DOTTED QUAD, NOT A HOSTNAME. It is parsed once with ip4addr_aton() in
  * stream_client_init() and no DNS lookup happens - deliberately, because the
  * bench has no DNS server and the board's own address now comes from DHCP,
  * which makes a name lookup one more thing that can fail at start-up.
  *
  * A malformed literal is caught at init and reported by name on the console;
  * the client task then parks rather than connecting somewhere unintended.
  *
  * IF THE SERVER MOVES, THIS MUST BE CHANGED AND THE FIRMWARE REBUILT. There
  * is no rediscovery - see the target note in stream_client.c for why that is
  * the right trade for a fixed-IP deployment and what it costs.
  */
/* CHANGED 25-08-2026 from 192.168.40.239 to .48 - .239 was not the PC.
   The bench on 25-08-2026 was:
       PC running stream_wss_server   192.168.40.48   (DHCP from 192.168.40.1)
       this macro said                192.168.40.239  <- nothing there
   stream_wss_server.py reads this macro and warned about the mismatch before a
   connection was ever attempted; without that check it would have presented as
   "connect timed out after 5000 ms" backing off 1s, 2s, 4s ... 30s, with the
   server sitting at "waiting for the board" looking perfectly healthy.

   .48 IS A DHCP LEASE, granted 11:11 and expiring 13:11 on 25-08-2026, so it
   CAN MOVE - a reboot or a lease expiry may hand the PC a different address and
   the board will then dial into nothing again. Two durable fixes, either of
   which removes the dependency:
     - a DHCP reservation for the PC's MAC on the 192.168.40.1 router, or
     - a static address on the PC, put here.
   Until then, if the timeouts return, check the PC's address FIRST -
   stream_wss_server.py/.ps1 print it at start-up next to this value. */
#ifndef STREAM_SERVER_HOST
#define STREAM_SERVER_HOST              "192.168.0.61"//"192.168.40.48"
#endif

/**
  * @brief  Port and path of the stream.
  *
  * 443 collides with nothing: the HTTPS server this project also runs listens
  * on 443 INBOUND on the board's own address, while this dials 443 OUTBOUND on
  * a different host. Different sockets, different directions.
  */
/**
  * @brief  1 takes the server address from mDNS, 0 from STREAM_SERVER_HOST.
  *
  * With this at 1 the literal below is IGNORED for the connection - the address
  * comes from mdns_service_get_address(), which resolves MDNS_TARGET_HOSTNAME.
  * The literal is kept only as documentation of the last known address and as
  * the fallback when this is 0.
  *
  * WHY THIS EXISTS. A literal address is wrong every time the bench moves. It
  * happened on 28-08-2026: the network changed from 192.168.40.x to
  * 192.168.0.x, this literal was updated, NTP_SERVER_HOST was not, and the
  * epoch clock silently stopped. Resolving by name removes the whole class of
  * fault - the name is stable across re-addressing.
  *
  * THE TASK WAITS RATHER THAN GUESSING. With mDNS selected, the client has no
  * address at startup and must not invent one. It blocks in
  * STREAM_STATE_WAIT_ADDR until the resolver publishes an answer, which is why
  * the "no target" path in stream_task() waits instead of parking.
  */
#ifndef STREAM_SERVER_USE_MDNS
#define STREAM_SERVER_USE_MDNS          1
#endif

/** What the banners name as the server.
  *
  * The literal is meaningless once mDNS supplies the address, and printing it
  * anyway is what made the 10-09-2026 log so confusing: "client ready -
  * wss://192.168.0.61:8080" sat three lines above "resolved to
  * 192.168.40.135". A banner that can contradict the code is worse than none,
  * so this resolves to whichever the build actually uses. */
#if STREAM_SERVER_USE_MDNS
#define STREAM_SERVER_NAME_FOR_LOG      MDNS_TARGET_HOSTNAME
#else
#define STREAM_SERVER_NAME_FOR_LOG      STREAM_SERVER_HOST
#endif

/**
  * @brief  Consecutive connection failures before mDNS is asked to re-resolve.
  *
  * A server that has MOVED and a server that is merely DOWN look identical from
  * here: connect attempts fail either way. So the response to repeated failure
  * is to ask the resolver again - if the address changed, the next attempt uses
  * the new one; if it did not, nothing is lost but one multicast query.
  *
  * 3 rather than 1 because a single failure is usually a server restarting at
  * the same address, and re-querying on every one would put a query on the wire
  * for each backoff cycle of a server that is simply switched off.
  *
  * 0 disables re-resolution: the address adopted at startup is then used for
  * the life of the run, which is the behaviour before 10-09-2026.
  */
#ifndef STREAM_MDNS_REFRESH_AFTER_FAILURES
#define STREAM_MDNS_REFRESH_AFTER_FAILURES  3U
#endif

/** How often the task checks whether mDNS has published an address, in ms.
  * Only used while waiting for the first resolution. 250 ms adopts the address
  * promptly without polling hard during the seconds the query may take. */
#ifndef STREAM_MDNS_WAIT_POLL_MS
#define STREAM_MDNS_WAIT_POLL_MS        250U
#endif

/** How often to say it is still waiting, in ms. A multiple of
  * STREAM_MDNS_WAIT_POLL_MS, or the modulo test never fires and the console
  * stays silent through an outage. */
#ifndef STREAM_MDNS_WAIT_REPORT_MS
#define STREAM_MDNS_WAIT_REPORT_MS      5000U
#endif

#ifndef STREAM_SERVER_PORT
#define STREAM_SERVER_PORT              8080//443
#endif

#ifndef STREAM_PATH
#define STREAM_PATH                     "/stream"
#endif

/**
  * @brief  Which UART every received byte is printed to, and its printable
  *         name. CHANGE BOTH TOGETHER - nothing checks that they agree.
  *
  * The name is here because uart_dispatch.c keeps its own selector-to-name
  * mapping static, so there is no function to ask.
  *
  * NO SELECTOR BYTE IS READ FROM THE STREAM. The whole response body is
  * payload and all of it goes to this one UART. That is the difference from
  * the reference module, which took byte 0 of each record as a selector; if
  * the server ever starts sending one it will be printed as data rather than
  * obeyed. stream_forward_to_uart() is the one place to change for that.
  *
  * USART2 is selector 0x02 on this board and comes out on PD5 (TX) / PD6 (RX)
  * at 115200 8N1.
  */
#ifndef STREAM_UART_SELECTOR
#define STREAM_UART_SELECTOR            UART_SELECTOR_USART2
#endif

#ifndef STREAM_UART_NAME
#define STREAM_UART_NAME                "USART2"
#endif

/**
  * @brief  1 forwards received payload to the UART, 0 counts it and drops it.
  *
  * Set this to 0 to measure the network path on its own. The UART is far
  * slower than the network - 115200 8N1 is 11.52 kB/s against a link that will
  * happily deliver megabytes - so on a fast stream the bridge queue is the
  * bottleneck, and separating the two is the only way to tell which one is
  * limiting throughput.
  */
#ifndef STREAM_UART_FORWARD_ENABLE
#define STREAM_UART_FORWARD_ENABLE      1
#endif

/**
  * @brief  1 extracts named JSON fields to separate UARTs; 0 forwards raw bytes.
  *
  * WHAT CHANGES ON THE WIRE. With this at 1, no UART carries the received
  * stream. Each carries one line per JSON object, holding only its own field:
  *
  *     USART1   1787819915.843\r\n     ntp_time
  *     USART2   1787819915.830\r\n     controller_..._received_ntp_time
  *     UART4    0\r\n                  joystick_x
  *     UART5    0\r\n                  joystick_y
  *
  * The field list and its UART routing are the two tables at the top of
  * stream_forward_to_uart()'s section in stream_client.c - Stream_json_fields
  * and Stream_json_route. Changing which field goes where is an edit to those,
  * not to the parser.
  *
  * WHY IT IS A SWITCH RATHER THAN A REWRITE. Raw forwarding is still the way to
  * prove the network path works when the extraction produces nothing: set this
  * to 0 and the UART shows exactly what arrived, which separates "the server
  * stopped sending" from "the parser stopped matching". Deleting the raw path
  * would have removed the one measurement that distinguishes those.
  *
  * It also cuts UART load by roughly 90 percent - 16 bytes per object instead
  * of about 170 - so the bridge queue stops being the bottleneck it is under
  * raw forwarding.
  */
#ifndef STREAM_JSON_EXTRACT_ENABLE
#define STREAM_JSON_EXTRACT_ENABLE      1
#endif

/**
  * @brief  1 appends the local NTP epoch to every emitted field line.
  *
  * Each UART line becomes three comma-separated columns:
  *
  *     13627,1787909496.189722,1787909495.821000
  *     |     |                 |
  *     |     |                 +-- local epoch, microseconds, 6 decimals
  *     |     +-------------------- the extracted JSON field value
  *     +-------------------------- sequence_id
  *
  * WHY ON THE SAME LINE RATHER THAN A SEPARATE ONE. A standalone "EPOCH ..."
  * line interleaved with the data lines gives two timestamps in one capture
  * with nothing tying them together - you cannot tell which data line a given
  * epoch line belongs to, which is the entire reason for wanting the epoch.
  * Putting it in a third column pairs it with a specific sequence_id, so the
  * server's timestamp and the board's can be compared row by row.
  *
  * The epoch is read ONCE per object, not once per field, so all four UARTs
  * report the same instant for a given sequence_id. Reading it per field would
  * give four values a few microseconds apart and make the columns
  * incomparable.
  *
  * If the clock has not synchronised yet the column is omitted entirely rather
  * than filled with zeros - a line that is two columns wide is obviously
  * unsynchronised, whereas 0.000000 looks like a reading.
  */
/* SET TO 0 ON 09-10-2026. The UARTs now carry the extracted value and nothing
   else, so the third column goes too - along with the sequence-id and
   field-name columns, switched off by JSON_PARSER_EMIT_PREFIX and
   JSON_PARSER_EMIT_LABEL in json_parser.h.

   Those three switches are the complete set: with all of them at 0 a line is
   the value followed by CR LF, and nothing in the emit path adds anything
   else. Turning any one back on restores just its own column.

   NOTE this is the switch that also stops ntp_format_epoch() being called once
   per object in stream_json_object_begin(). The NTP client itself keeps
   running and the clock stays synchronised - only the column is gone. */
#ifndef STREAM_JSON_APPEND_EPOCH
#define STREAM_JSON_APPEND_EPOCH        0
#endif

/**
  * @brief  1 prints the periodic "stream: N B in, ..." line, 0 keeps quiet.
  *
  * OFF by default since 28-08-2026. It was useful while bringing the stream up
  * and is noise once it works: at 4.4 kB/s it prints roughly once a second for
  * ever, burying the boot banner and every genuine warning underneath it.
  *
  * TURNING IT OFF COSTS NO INFORMATION. Stream.rx_bytes, Stream.uart_bytes and
  * Stream.uart_drops are still maintained exactly as before and are readable in
  * the debugger, as are json_parser_objects and the ntp_* counters. Only the
  * printf is removed.
  *
  * IT ALSO REMOVES A REAL DISTURBANCE. printf goes to USART3 through
  * HAL_UART_Transmit_IT, one interrupt per byte. An 80-character line is 80
  * interrupts fired straight into the middle of the TLS receive path and the
  * PE9 measurement window - the same per-byte interrupt storm that the latency
  * work in http_server.c was written to avoid. Silence is not just tidier here,
  * it is measurably less intrusive.
  */
#ifndef STREAM_REPORT_ENABLE
#define STREAM_REPORT_ENABLE            0
#endif

/**
  * @brief  1 dumps every received frame to the VCP, 0 keeps the console quiet.
  *
  * Prints the whole decrypted WebSocket payload - the complete JSON object as
  * it arrived - to the ST-LINK Virtual COM Port, one frame per line.
  *
  * REQUIRES THE BUFFERED CONSOLE. With the BSP's blocking console this would
  * stall the stream task for 14.8 ms per frame at 115200 baud, inside the TLS
  * receive path. vcom_tx.c makes the write non-blocking, and VCOM_TX_BAUD
  * raises the drain rate so the ring does not simply fill and discard.
  *
  * WHAT IT COSTS EVEN SO. At 2 Mbaud a 170-byte frame takes 0.85 ms to shift
  * out. One frame a second is nothing; a hundred frames a second is 85 ms of
  * every second spent transmitting, and the ring will start dropping. Watch
  * vcom_tx_dropped - if it climbs, the console is the bottleneck and this
  * should go back off.
  *
  * IT INVALIDATES THE PE9 MEASUREMENT WHILE ENABLED. The dump happens inside
  * stream_process_payload(), which is inside the ETH-to-UART pulse, so
  * scope_trig_span_us stops being processing time and becomes processing time
  * plus however long the console queue took. Turn this off before trusting a
  * scope reading.
  */
#ifndef STREAM_DUMP_FRAME_TO_VCP
#define STREAM_DUMP_FRAME_TO_VCP        1
#endif

/* ==========================================================================
 * TIMING AND SIZING - sensible defaults, change only with a reason
 * ======================================================================= */

/**
  * @brief  SO_RCVTIMEO / SO_SNDTIMEO on the stream socket, in SECONDS.
  *
  * This is what stops a silent server from wedging the task for ever. It must
  * be LONGER than the longest gap the server may legitimately leave between
  * records, or a healthy but idle stream is torn down and reconnected in a
  * loop. 15 s suits a server that sends continuously or nearly so; raise it if
  * the source is bursty.
  */
#ifndef STREAM_SOCKET_TIMEOUT_S
#define STREAM_SOCKET_TIMEOUT_S         15
#endif

/**
  * @brief  Bound on the TCP connect, in milliseconds.
  *
  * lwip_connect() on a blocking socket has NO timeout of its own - against a
  * host that is powered off it returns only when the stack gives up, which can
  * be minutes. The socket is put into non-blocking mode for the connect and
  * polled, purely to impose this bound.
  */
#ifndef STREAM_CONNECT_TIMEOUT_MS
#define STREAM_CONNECT_TIMEOUT_MS       5000U
#endif

/**
  * @brief  Reconnect backoff, doubling from MIN to MAX.
  *
  * A server that is switched off must not become a busy loop, and must not
  * need a board reset to recover from either. Doubling settles a long outage
  * into one attempt every 30 s while still reconnecting within a second after
  * a brief blip.
  */
#ifndef STREAM_BACKOFF_MIN_MS
#define STREAM_BACKOFF_MIN_MS           1000U
#endif

#ifndef STREAM_BACKOFF_MAX_MS
#define STREAM_BACKOFF_MAX_MS           30000U
#endif

/**
  * @brief  Receive buffer, in bytes. Lives inside the module's state struct in
  *         .bss, not on the task stack.
  *
  * MUST NOT EXCEED MBEDTLS_SSL_IN_CONTENT_LEN, which is 2048 in this project
  * (Core/Inc/main.h). A TLS record larger than that is rejected with
  * MBEDTLS_ERR_SSL_INVALID_RECORD, -0x7200 - a failure that looks like a
  * network fault and is not. 1024 leaves margin.
  */
#ifndef STREAM_RX_CHUNK_BYTES
#define STREAM_RX_CHUNK_BYTES           1024U
#endif

/* ==========================================================================
 * WEBSOCKET (wss://).  Added 24-08-2026.
 * ======================================================================= */

/**
  * @brief  1 = speak WebSocket over the TLS connection. 0 = plain HTTPS
  *         streaming, exactly as before this switch existed.
  *
  * WHAT CHANGES AT 1. The connect and TLS handshake are identical - WebSocket
  * runs over the same socket. What differs is everything after it:
  *   - the request becomes an HTTP Upgrade rather than a plain GET
  *   - the response must be 101, and Sec-WebSocket-Accept must match
  *   - the body is read as RFC 6455 frames instead of raw or chunked bytes
  *
  * WHAT REACHES USART2 IMPROVES AT 1. In plain mode the HTTP response headers
  * are forwarded as data, because this client does not parse them out of the
  * stream. In WebSocket mode only frame PAYLOAD is forwarded - headers, frame
  * headers, pings and pongs never reach the UART.
  *
  * TLS IS ORTHOGONAL. This switch selects the protocol INSIDE the tunnel;
  * whether there is a tunnel is decided by the TLS setup, which is always on
  * in this project. So 1 here gives wss://, and 1 here with TLS removed would
  * give ws://.
  */
#ifndef STREAM_USE_WEBSOCKET
#define STREAM_USE_WEBSOCKET            1
#endif

/**
  * @brief  Resource path for the Upgrade request. Defaults to STREAM_PATH so
  *         one setting serves both modes, but a server that exposes its
  *         WebSocket endpoint elsewhere can be pointed at it here.
  */
#ifndef STREAM_WS_PATH
#define STREAM_WS_PATH                  STREAM_PATH
#endif

/**
  * @brief  1 = answer a server PING with a PONG carrying the same payload.
  *
  * KEEP THIS AT 1 UNLESS YOU KNOW THE SERVER NEVER PINGS. RFC 6455 5.5.2 says
  * a pong must be sent "as soon as is practical", and a server that pings to
  * check liveness will close a connection that never answers - which presents
  * as an unexplained disconnect every N seconds, with nothing in the log
  * pointing at the missing pong.
  *
  * Answering costs a masked write of at most 131 bytes per ping.
  */
#ifndef STREAM_WS_PONG_ENABLE
#define STREAM_WS_PONG_ENABLE           1
#endif

/**
  * @brief  1 writes each received record back to the server, for round-trip
  *         timing from the far end. 0 receives only.
  *
  * DEFAULTS TO 0 HERE, unlike the reference module. This client exists to
  * print received data to a UART; echoing puts traffic back on the wire that
  * the server did not ask for, and a server not expecting it may treat the
  * write as a protocol error and drop the connection.
  */
#ifndef STREAM_ECHO_ENABLE
#define STREAM_ECHO_ENABLE              0
#endif

#ifndef STREAM_ECHO_MAX_BYTES
#define STREAM_ECHO_MAX_BYTES           256U
#endif

/* Exported types
***************************************************/

/**
  * @brief  What the client is doing. Reported by stream_client_get_state() and
  *         printed by name on every transition.
  */
typedef enum
{
    STREAM_STATE_IDLE = 0,      /**< created, not yet started            */
    STREAM_STATE_WAIT_ADDR,     /**< STREAM_SERVER_HOST would not parse  */
    STREAM_STATE_CONNECTING,    /**< TCP connect in progress             */
    STREAM_STATE_HANDSHAKE,     /**< TLS handshake in progress           */
    STREAM_STATE_REQUESTING,    /**< request sent, reading response head */
    STREAM_STATE_STREAMING,     /**< body arriving                       */
    STREAM_STATE_BACKOFF        /**< waiting before the next attempt     */
} stream_client_state_t;

/* Exported functions prototypes
***************************************************/

/**
  * @brief  Creates the client task. Call once, after the network is up.
  * @retval None
  *
  * CALL IT AFTER THE DHCP LEASE, not before. The task connects out, and a
  * connect attempted from 0.0.0.0 fails immediately - which the backoff would
  * then paper over, turning a start-up ordering mistake into a slow reconnect
  * loop that looks like an unreachable server. StartEthIfTask() in main.c
  * already waits for the lease and calls this afterwards.
  */
void stream_client_init(void);

/**
  * @brief  Current state.
  * @retval One of stream_client_state_t.
  */
stream_client_state_t stream_client_get_state(void);

/**
  * @brief  Cumulative payload bytes received since boot, across all
  *         connections. Excludes HTTP headers and chunk framing.
  * @retval Byte count.
  */
uint32_t stream_client_get_rx_bytes(void);

/**
  * @brief  Number of streams successfully established since boot. Counted when
  *         the response head is accepted, so it measures connections made, not
  *         connections that ended tidily.
  * @retval Connection count.
  */
uint32_t stream_client_get_connect_count(void);

#ifdef __cplusplus
}
#endif

#endif /* STREAM_CLIENT_H */
