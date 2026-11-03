/**
  ******************************************************************************
  * @file    http_server.c
  * @brief   lwIP HTTPD bring-up plus the HTTP echo and UART-bridge endpoints
  * @version 2.0 - 07-08-2026  (FreeRTOS + POST endpoints)
  *          1.0 - 05-08-2026  (bare-metal, static files only)
  *
  * Target: NUCLEO-H753ZI, FreeRTOS + lwIP (NO_SYS=0), no TLS.
  *
  * ---------------------------------------------------------------------------
  * WHAT THIS REPLACES
  * ---------------------------------------------------------------------------
  * TCP_Server_H753_RTOS__ES_V00 exposed the UART bridge over a raw TCP listener
  * on port 4433: the client held one connection open, sent
  * [selector byte][payload], and a late UART reply was pushed back onto that
  * same socket via tcpip_callback().
  *
  * That model does not survive the move to HTTP. httpd closes the connection
  * after every response (LWIP_HTTPD_SUPPORT_11_KEEPALIVE is 0), so there is no
  * open socket to push a late reply onto. The bridge is therefore split into
  * submit and collect, which is the natural HTTP idiom for an asynchronous
  * device:
  *
  *   POST /echo               body is returned verbatim
  *   POST /uart               body is [selector][payload], queued to a UART
  *   POST /uartecho           as /uart, but the PAYLOAD is returned as well, so a
  *                            client can measure bridge RTT in one round trip
  *   GET  /uart/lastN.json     most recent reply captured from UART N (N=1..4)
  *
  * ---------------------------------------------------------------------------
  * THREADING
  * ---------------------------------------------------------------------------
  * Every function here runs on tcpip_thread - httpd is a raw/altcp application
  * and lwIP calls it from its own thread. That has two consequences:
  *   - httpd_init() must NOT be called from any other task. main.c marshals
  *     http_server_start() in via tcpip_callback(); see
  *     http_server_init_callback() there.
  *   - the POST handlers may call uart_dispatch_send(), which only touches a
  *     FreeRTOS queue, and uart_dispatch_get_last(), which takes a short
  *     critical section. Neither blocks, so tcpip_thread is never stalled.
  *
  * ---------------------------------------------------------------------------
  * WHY THE RESPONSES CARRY THEIR OWN HTTP HEADERS
  * ---------------------------------------------------------------------------
  * httpd can only hand back a response URI from httpd_post_finished(); it has no
  * way to return a body directly. So every dynamic reply is stored in a buffer
  * and served by fs_open_custom() (LWIP_HTTPD_CUSTOM_FILES=1).
  *
  * Those buffers include a complete HTTP header and set
  * FS_FILE_FLAGS_HEADER_INCLUDED, rather than relying on
  * LWIP_HTTPD_DYNAMIC_HEADERS to infer a Content-Type from the URI extension.
  * Reason: httpd_structs.h has no ".txt" entry - the extensions it knows are
  * .html/.htm/.json/.js/.css/.xml and a handful of image types - so an
  * extensionless or .txt URI would get a guessed or absent Content-Type. Writing
  * the header ourselves gives exact control and works for binary bodies, and it
  * is the same thing fsdata_custom.c does for the static files.
  ******************************************************************************
  */

#include "http_server.h"
#include "uart_dispatch.h"

/* ENABLE_MUTUAL_TLS, tested in http_server_tls_config(). Added 24-08-2026 with
   that switch. NOTHING pulled main.h in here before - not http_server.h, not
   uart_dispatch.h, not tls_credentials.h - so without this line the #if would
   have evaluated the undefined identifier as 0 and silently DISABLED client
   authentication on a build that asked for it. It would have compiled clean
   and the only evidence would have been the banner. */
#include "main.h"

/* Belt and braces, for the same reason. If this include is ever lost to a
   refactor, fail the BUILD rather than the security policy. */
#ifndef ENABLE_MUTUAL_TLS
#error "ENABLE_MUTUAL_TLS is not defined - Core/Inc/main.h is not included here."
#endif

#include "lwip/opt.h"
#include "lwip/apps/httpd.h"
#include "lwip/apps/fs.h"
#include "lwip/def.h"

/* ---- TLS, added 07-08-2026 ------------------------------------------------
   altcp_tls.h gives the public config API; mbedtls/ssl.h and x509_crt.h are
   needed because mutual TLS has to be finished off with mbedTLS calls that lwIP
   does not wrap - see http_server_tls_config() below. */
#include "lwip/altcp_tls.h"
#include "mbedtls/ssl.h"
#include "mbedtls/x509_crt.h"
#include "tls_credentials.h"

/* xPortGetFreeHeapSize() - reported alongside the TLS banner because every
   mbedTLS allocation comes from ucHeap, so this is the number that decides
   whether a handshake can complete. See mbedtls_platform_glue.c. */
#include "FreeRTOS.h"
#include "task.h"

#if defined(MBEDTLS_DEBUG_C)
/* mbedtls_debug_set_threshold(). Declared only when MBEDTLS_DEBUG_C is defined,
   hence the guard - see MBEDTLS/App/mbedtls_config.h USER CODE 1. */
#include "mbedtls/debug.h"
#endif

/* Serve plain HTTP on port 80 as well as HTTPS on 443.
 *
 * NOW 0 - HTTPS ONLY, which is this project's actual goal. Set 11-08-2026 once the
 * HTTPS path was fully verified: test_https.ps1 reports 54/54 with 0 warnings,
 * including mutual TLS, an anonymous client rejected, and a rogue-CA client
 * rejected. With this at 0, httpd_init() is simply never called and nothing
 * listens on port 80.
 *
 * WHAT THIS COSTS YOU, so it is not a surprise later: test_http.ps1 (49 checks)
 * and measure_http_rtt.ps1 both speak plain HTTP and will now fail at "TCP connect
 * to 192.168.1.10:80" - correctly. They are NOT dead: set this back to 1 and
 * rebuild whenever you need them, which is the fastest way to tell a TLS fault
 * apart from an HTTP-layer regression. That is precisely why it stayed at 1
 * through the whole TLS bring-up.
 *
 * The regression net on 443 is test_https.ps1, which covers the same static files
 * byte-for-byte against fsdata_custom.c plus every dynamic endpoint. Note its
 * timings are not comparable with the port-80 figures: a TLS handshake is ~1.6 s
 * and steady-state RTT is roughly 2x. See docs/https_bringup_diagnosis_v1.3. */
#define HTTP_SERVER_ENABLE_PLAIN_HTTP   0

/* Declares DWT, CoreDebug and SystemCoreClock for the latency instrumentation
   below (via stm32h7xx.h -> core_cm7.h). http_server.h has no includes of its own,
   so without this the DWT block does not compile. Added 12-08-2026.

   NOT main.h, deliberately: main.h lines 64-66 define MBEDTLS_PLATFORM_STD_CALLOC
   and MBEDTLS_PLATFORM_STD_FREE, which mbedtls_config.h also defines, so including
   it here produced two "redefined" warnings in every mbedTLS-aware translation
   unit. This header is the part actually needed and carries no such macros. */
#include "stm32h7xx_hal.h"

#include <stdio.h>
#include <stdarg.h>   /* va_list / va_start / va_end for resp_build_json() */
#include <string.h>

/* ==========================================================================
 * Sizing
 * ======================================================================== */

/* Largest POST body accepted. Deliberately matched to the UART payload limit:
   a /uart body is one selector byte plus a payload, so anything larger could
   not be dispatched anyway and is better refused up front with a clear 400
   than silently truncated. /echo shares the limit for simplicity. */
#define HTTP_POST_MAX_BODY   (UART_DISPATCH_MAX_PAYLOAD + 1U)

/* Response buffer: our own HTTP header plus the largest body we ever emit. 256
   bytes is comfortably more than the fixed headers below. */
#define HTTP_RESP_HDR_MAX    256U

/* Largest RESPONSE body, which is NOT the same thing as the largest request body.
   Corrected 12-08-2026: resp_build() previously clamped to HTTP_POST_MAX_BODY,
   conflating the two. That was harmless while every JSON reply was short, but it
   silently caps any longer response - /lat.json emits about 280 characters - and a
   clamp produces truncated, unparseable JSON with no error anywhere. The clamp is
   still there as a backstop; it now uses the right limit.
   Must be >= HTTP_POST_MAX_BODY because /echo and /uartecho hand a request body
   straight back. */
/* 384 -> 640 on 12-08-2026: adding the "tx" object to /lat.json took the body to
   roughly 430 characters, which would have tripped the overflow guard below and
   returned a 500 instead of the data. Sized with headroom so the next counter
   added does not repeat that. */
#define HTTP_RESP_BODY_MAX   640U
#if HTTP_RESP_BODY_MAX < HTTP_POST_MAX_BODY
#error "HTTP_RESP_BODY_MAX must be at least HTTP_POST_MAX_BODY - /echo returns the request body verbatim"
#endif

#define HTTP_RESP_MAX        (HTTP_RESP_HDR_MAX + HTTP_RESP_BODY_MAX)

/* ==========================================================================
 * Per-POST state
 * ======================================================================== */

/* ONE POST AT A TIME, BY DESIGN.
   httpd identifies a POST by an opaque connection pointer and can in principle
   have several in flight, so the textbook solution is a small table keyed by
   that pointer. A single slot is used here instead because:
     - these are control-plane requests from a test client or script, not
       browser traffic, so concurrency is not the normal case;
     - a second concurrent POST is REFUSED EXPLICITLY (503) rather than
       corrupting the first, which is the failure mode a shared buffer without
       a table would actually produce;
     - MEMP_NUM_TCP_PCB is 8, so an accidental burst is bounded anyway.
   If concurrent POSTs are ever needed, make active_conn/body/body_len an array
   indexed by a lookup on the connection pointer - nothing else here changes. */
static void    *active_conn = NULL;              /* NULL => no POST in progress */
static uint8_t  post_body[HTTP_POST_MAX_BODY];
static uint16_t post_body_len;
static uint16_t post_content_len;                /* as declared by the client   */
/* Which POST endpoint the in-flight request is for.
 *
 * Was a uint8_t post_is_echo (1 = /echo, 0 = /uart) until 11-08-2026, when
 * /uartecho added a third behaviour and a boolean could no longer express it.
 * The two original modes behave EXACTLY as before. */
typedef enum
{
  POST_MODE_ECHO      = 0,   /* /echo      - return the body verbatim, no UART   */
  POST_MODE_UART      = 1,   /* /uart      - queue to a UART, reply 202 + JSON   */
  POST_MODE_UART_ECHO = 2    /* /uartecho  - queue to a UART AND return payload  */
} post_mode_t;

static post_mode_t post_mode;

/* The response fs_open_custom() will serve, built by httpd_post_finished() or
   by the GET handler.

   KNOWN LIMITATION - ONE DYNAMIC RESPONSE IN FLIGHT AT A TIME.
   This is a single shared buffer, so two connections both fetching a DYNAMIC URI
   simultaneously would have the second overwrite the first mid-transmission and
   the client would receive spliced garbage. It is safe for:
     - any number of concurrent STATIC file requests (they never touch resp_buf);
     - sequential requests on one keep-alive connection, which is what the
       measure_http_rtt.ps1 Echo case does - httpd does not pipeline, so one
       response completes before the next request is parsed.
   It is NOT safe for concurrent POSTs from different clients, which is why
   httpd_post_begin() refuses a second overlapping POST with 503 rather than
   letting it corrupt the first. The GET side has no such guard: two clients
   polling /uart/lastN.json at the same instant could interleave.

   Why it has not shown up: test_http.ps1's Concurrent suite opens 8 sockets but
   requests /index.html on all of them, which is static.

   The fix, if concurrency is ever needed, is a small pool of response buffers
   keyed on the connection pointer, sized to MEMP_NUM_TCP_PCB. Deliberately not
   done yet: at 385 bytes each that is real RAM for a control-plane API whose
   clients are scripts, and a wrong guess about the key would be worse than the
   current explicit single-slot behaviour. */
static char     resp_buf[HTTP_RESP_MAX];
static uint16_t resp_len;

/* Response URIs. These are never fetched from the file system - fs_open_custom()
   recognises them and serves resp_buf instead. Kept as distinct names so a
   packet capture shows which path was taken. */
#define URI_RESULT       "/hs/result"      /* whatever the last request produced */

/* ---------------------------------------------------------------------------
 * THE SELECTOR IS IN THE PATH, NOT A QUERY PARAMETER.  Corrected 07-08-2026.
 * ---------------------------------------------------------------------------
 * This was "/uart/last.json" read with "?sel=N", and it never worked: every
 * selector answered "missing or invalid sel". httpd.c line 2277 does
 *     params = strchr(uri, '?');
 *     if (params != NULL) { *params = '\0'; }
 * UNCONDITIONALLY - it truncates the URI at the '?' before any file lookup, and
 * only hands the parameters onward when LWIP_HTTPD_CGI is enabled. So
 * fs_open_custom() receives "/uart/last.json" with the query string already
 * gone, and no amount of parsing inside it can recover the selector.
 *
 * Encoding the selector in the path sidesteps that entirely and needs no extra
 * lwIP option or CubeMX regeneration:
 *     GET /uart/last1.json  .. /uart/last4.json
 * ------------------------------------------------------------------------- */
#define URI_UART_LAST_PREFIX  "/uart/last"     /* followed by one digit + ".json" */

/* Latency counters as JSON, so the DWT figures can be read WITHOUT a debugger:
       GET /lat.json           read the counters
       GET /lat.json?reset=1   read them, then zero the maxima
   Reading over HTTPS costs one request on the same keep-alive session and does
   not disturb a measured POST - fs_open_custom() only closes the measurement
   window for URI_RESULT, so this path leaves lat_active untouched. Added
   12-08-2026 alongside the instrumentation. */
#define URI_LAT          "/lat.json"

/* ==========================================================================
 * Response building
 * ======================================================================== */

/**
  * @brief  Builds a complete HTTP response (header + body) into resp_buf.
  * @param  status: status line text, e.g. "200 OK"
  * @param  content_type: full Content-Type value, e.g. "application/json"
  * @param  body: body bytes (may be NULL when body_len is 0)
  * @param  body_len: number of body bytes
  * @retval None
  *
  * Content-Length is emitted explicitly and "Connection: close" is stated
  * outright, matching what httpd actually does with keep-alive disabled. Being
  * explicit means a client does not have to infer the end of the body from the
  * connection closing, which is what makes binary /echo replies reliable.
  */
static void resp_build(const char *status, const char *content_type,
                       const void *body, uint16_t body_len)
{
  int n;

  if (body_len > HTTP_RESP_BODY_MAX)
  {
    body_len = HTTP_RESP_BODY_MAX;
  }

  /* HTTP/1.1 + "Connection: keep-alive" since 07-08-2026, so a client can issue
     many requests down one socket instead of paying a TCP handshake each time.
     This was HTTP/1.0 + "Connection: close".

     Content-Length is what makes it work: a persistent connection has no other
     way to know where one response ends and the next begins, since the socket
     closing can no longer be the delimiter. It was already emitted explicitly,
     which is why this change is only two words in the header.

     See resp_flags() below for the FS_FILE_FLAGS_HEADER_PERSISTENT half of this,
     which is what actually stops httpd from tearing the connection down. */
  n = snprintf(resp_buf, HTTP_RESP_HDR_MAX,
               "HTTP/1.1 %s\r\n"
               "Server: HTTP_Server_H753_RTOS_ES_V00\r\n"
               "Content-Type: %s\r\n"
               "Content-Length: %u\r\n"
               "Cache-Control: no-store\r\n"
               "Connection: keep-alive\r\n"
               "\r\n",
               status, content_type, (unsigned)body_len);

  /* snprintf returns what it WOULD have written. Treat overflow as a hard
     internal error rather than emitting a truncated header, which would corrupt
     the response framing. */
  if ((n < 0) || ((unsigned)n >= HTTP_RESP_HDR_MAX))
  {
    resp_len = 0;
    return;
  }

  if ((body != NULL) && (body_len > 0U))
  {
    memcpy(&resp_buf[n], body, body_len);
  }
  resp_len = (uint16_t)((unsigned)n + body_len);
}

/* Small JSON status body. Used for every /uart outcome so a script can parse
   one shape regardless of success or failure. */
static void resp_build_json(const char *status, const char *fmt, ...)
{
  /* Was 128 until 12-08-2026, which sufficed for every short error reply but
     silently truncated /lat.json (about 280 characters) into unparseable JSON.
     Sized from HTTP_RESP_BODY_MAX so the two cannot drift apart again. */
  char body[HTTP_RESP_BODY_MAX];
  int  n;
  va_list ap;

  va_start(ap, fmt);
  n = vsnprintf(body, sizeof(body), fmt, ap);
  va_end(ap);

  if (n < 0) { n = 0; }
  if ((unsigned)n >= sizeof(body))
  {
    /* Truncating produces JSON a client cannot parse and cannot distinguish from
       a protocol fault, so report the overflow as valid JSON instead. Fits well
       inside the buffer, so it cannot itself overflow. Added 12-08-2026 - the old
       code clamped to sizeof(body)-1 and shipped the truncated text. */
    n = snprintf(body, sizeof(body),
                 "{\"ok\":false,\"error\":\"json body overflow\",\"needed\":%u,\"have\":%u}",
                 (unsigned)n + 1U, (unsigned)sizeof(body));
    resp_build("500 Internal Server Error", "application/json", body, (uint16_t)n);
    return;
  }

  resp_build(status, "application/json", body, (uint16_t)n);
}

/* ==========================================================================
 * POST handling - the three callbacks httpd requires
 * ======================================================================== */

/* ===========================================================================
 * LATENCY INSTRUMENTATION - added 12-08-2026
 *
 * WHY THIS EXISTS. A tshark capture taken during a 1000-message run split each
 * cycle into board time (request on the wire -> response on the wire) and host
 * time, and proved the latency tail belongs to the BOARD:
 *
 *     wire RTT   p50 0.658   p95 5.257   p99 11.584   max 15.138 ms
 *     PC script  p50 1.093   p95 5.976   p99 12.514   max 15.751 ms
 *
 * The host adds a near-constant 0.4-0.9 ms and none of the tail shape. So the
 * 5-15 ms comes from somewhere between the board receiving the request and the
 * board transmitting the reply. The capture bounds that whole window but cannot
 * subdivide it - only firmware can.
 *
 * WHAT IS MEASURED. Everything this file can see, which is the APPLICATION part
 * of the window:
 *
 *   httpd_post_begin ---> httpd_post_receive_data ---> httpd_post_finished
 *        |                     (body copy)               (dispatch + build)
 *        |                                                      |
 *        +---------------- lat_app_us -------------------> fs_open_custom
 *                                                          (response served)
 *
 * Before post_begin: lwIP input, TLS record decrypt, HTTP header parse.
 * After fs_open_custom returns: TLS encrypt, altcp_write, TCP transmit.
 * Neither is visible here, and that is the point - see HOW TO READ IT.
 *
 * HOW TO READ IT. Watch lat_app_us_max in Live Expressions while running
 * measure_uart_rtt.ps1, then compare against the wire RTT max for the same run:
 *
 *   lat_app_us_max stays small (tens/hundreds of us) while the wire shows 15 ms
 *       -> the delay is OUTSIDE this file: TLS crypto, lwIP, or the application
 *          thread not being scheduled. Preemption by the per-byte UART TX
 *          interrupt (uart_dispatch.c:365, HAL_UART_Transmit_IT) is then the
 *          leading candidate and the DMA change is justified.
 *
 *   lat_app_us_max approaches the wire max
 *       -> the delay IS in this file, and latw_* below says which part.
 *
 * The lat_*_max values can each come from a DIFFERENT request, so a set of
 * maxima cannot be added up. latw_* is a snapshot of every segment taken at the
 * single worst request, which can be read as one coherent breakdown.
 *
 * DELIBERATELY NO PERIODIC printf. Printing from here would run
 * HAL_UART_Transmit_IT on the VCP inside the very window being measured and
 * would corrupt the result - the same per-byte interrupt storm this is trying to
 * detect. Read the variables with the debugger; only lat_init() prints.
 *
 * COST WHEN ENABLED: six DWT->CYCCNT reads and a handful of compares per POST,
 * about 20-30 cycles each, so well under 1 us total against a 658 us median.
 * Set HTTP_LAT_DIAG to 0 to remove every variable and every read.
 * =========================================================================== */
#define HTTP_LAT_DIAG 1

#if HTTP_LAT_DIAG

/* DWT->LAR is absent from some CMSIS core headers, so it is addressed directly.
   Writing this key unlocks the DWT registers; on parts where the lock is active
   CYCCNT stays at zero even with TRCENA set, which would silently report 0 us
   for everything - a failure that looks like "the application is instant". The
   self-test in lat_init() is what catches that. */
#define HTTP_LAT_DWT_LAR   (*(volatile uint32_t *)0xE0001FB0U)

volatile uint8_t  lat_dwt_ok;        /* 0 => counter never ran, ALL figures junk  */
volatile uint32_t lat_cyc_per_us;    /* SystemCoreClock/1e6, 480 expected here    */

volatile uint32_t lat_app_us_max;    /* post_begin -> response served  <-- WATCH  */
volatile uint32_t lat_app_us_last;
volatile uint32_t lat_recv_us_max;   /* body copy, summed over all pbufs          */
volatile uint32_t lat_fin_us_max;    /* httpd_post_finished body                  */
volatile uint32_t lat_disp_us_max;   /* uart_dispatch_send() alone                */
volatile uint32_t lat_serve_us_max;  /* fs_open_custom for URI_RESULT             */
volatile uint32_t lat_count;         /* POSTs measured                            */
volatile uint32_t lat_over_1ms;      /* app windows over 1 ms                     */
volatile uint32_t lat_over_5ms;      /* app windows over 5 ms                     */

/* Breakdown of the SINGLE worst app window - these do add up. */
volatile uint32_t latw_app_us, latw_recv_us, latw_fin_us, latw_disp_us, latw_serve_us;

/* ---- Ethernet transmit-path counters, owned by LWIP/Target/ethernetif.c ------
   Surfaced here because /lat.json is the only way to read board counters without
   a debugger. Added 12-08-2026 to test the leading explanation for the 13-17 ms
   RTT maximum: eth_tx_output() waits up to ETH_TX_BUSY_WAIT_MS (20 ms) on
   TxPktSemaphore when the Tx descriptor ring is full, and that wait runs ON
   tcpip_thread, so it stalls the whole stack. A 20 ms ceiling would put maxima
   exactly where they are observed. eth_tx_wait_us_max is the figure that decides
   it: if it reaches ~13-17 ms, this is the cause; if it stays near zero, it is
   not, whatever eth_tx_busy_wait says about how often the path is entered. */
extern volatile uint32_t eth_tx_busy_wait;
extern volatile uint32_t eth_tx_wait_us_max;
extern volatile uint32_t eth_tx_wait_us_last;
extern volatile uint32_t eth_tx_wait_over1ms;
extern volatile uint32_t eth_tx_wait_over10ms;
extern volatile uint32_t eth_tx_ok;
extern volatile uint32_t eth_tx_clone_fail;
extern volatile uint32_t eth_tx_toolong;
extern volatile uint32_t eth_tx_chain_max;

/* ---- Full board-window decomposition, added 12-08-2026 ----------------------
   See the long comment in LWIP/Target/ethernetif.c. Four segments cover the
   whole board window; segment 3 is the application window already measured above.

     1 lat_rx_sched_us_max   ETH RX ISR -> netif->input()      (ethernetif.c)
     2 lat_rx2app_us_max     netif->input() -> post_begin      (here)
     3 lat_app_us_max        post_begin -> response served     (here, 18 us)
     4 lat_serve2tx_us_max   served -> eth_tx_output()         (ethernetif.c)

   Segment 2 is the interesting one: it contains the tcpip_thread mailbox hop,
   the mbedTLS record DECRYPT, and httpd's header parsing - none of it previously
   visible. */
extern volatile uint32_t eth_rx_input_cyc;
extern volatile uint32_t lat_rx_sched_us_max;
extern volatile uint32_t lat_rx_sched_over1ms;
extern volatile uint32_t lat_rx_sched_over5ms;
extern volatile uint32_t lat_rx_sched_over10ms;
extern volatile uint32_t lat_rx_sched_bogus;
extern volatile uint8_t  eth_rx_isr_fresh;
extern volatile uint32_t lat_serve2tx_us_max;
extern volatile uint32_t lat_serve2tx_over1ms;
extern volatile uint8_t  lat_tx_pending;

/* Receive-side stalls, previously invisible. See ethernetif.c: RBU suspends the
   Rx DMA until descriptors are rebuilt, and it is caused by the zero-copy Rx pbuf
   pool running dry. Both are prime suspects for the 13-17 ms maximum because they
   sit in segment 1, which elimination has already shown must contain it. */
extern volatile uint32_t eth_rbu_events;
extern volatile uint32_t eth_rx_alloc_fail;
extern volatile uint32_t eth_rx_pool_recover;

volatile uint32_t lat_serve_cyc      = 0;   /* read by eth_tx_output() */
volatile uint32_t lat_rx2app_us_max  = 0;   /* segment 2 worst case    */
volatile uint32_t lat_rx2app_over1ms = 0;

static uint32_t lat_t0;              /* post_begin entry                          */
static uint32_t lat_recv_acc;        /* accumulated body-copy us this POST        */
static uint32_t lat_fin_us;          /* post_finished duration this POST          */
static uint32_t lat_disp_us;         /* dispatch duration this POST               */
static uint8_t  lat_active;          /* a measured POST is in progress            */

static void lat_init(void)
{
  uint32_t a, b;

  CoreDebug->DEMCR |= CoreDebug_DEMCR_TRCENA_Msk;
  HTTP_LAT_DWT_LAR  = 0xC5ACCE55U;
  DWT->CYCCNT       = 0U;
  DWT->CTRL        |= DWT_CTRL_CYCCNTENA_Msk;

  /* SystemCoreClock is the CPU clock, which is what CYCCNT counts. If it were
     ever wrong the absolute microseconds would scale wrongly, but the RELATIVE
     split between segments - the thing this is for - would still hold. */
  lat_cyc_per_us = SystemCoreClock / 1000000U;
  if (lat_cyc_per_us == 0U) { lat_cyc_per_us = 1U; }

  /* CYCCNT was just zeroed above, so any eth_rx_isr_fresh left set by an interrupt
     that ran BEFORE the counter started would pair a pre-reset timestamp with a
     post-reset one and yield a nonsense duration. Clear it here. Added 12-08-2026
     alongside the LAT_RX_SCHED_SANE_US bound in ethernetif.c, which catches the
     same class of error arising from a counter wrap. */
  eth_rx_isr_fresh = 0U;

  /* Self-test: the counter must actually advance. */
  a = DWT->CYCCNT;
  __NOP(); __NOP(); __NOP(); __NOP(); __NOP(); __NOP();
  b = DWT->CYCCNT;
  lat_dwt_ok = (b != a) ? 1U : 0U;

  printf("lat: DWT %s, %lu cyc/us (core %lu Hz) - watch lat_app_us_max\r\n",
         (lat_dwt_ok != 0U) ? "running" : "DEAD, figures INVALID",
         (unsigned long)lat_cyc_per_us, (unsigned long)SystemCoreClock);
}

/* Unsigned subtraction wraps correctly, so the ~8.9 s CYCCNT rollover at 480 MHz
   needs no special case - it is far longer than any single request. */
static inline uint32_t lat_us_since(uint32_t t0)
{
  return (DWT->CYCCNT - t0) / lat_cyc_per_us;
}

#define LAT_NOW()   (DWT->CYCCNT)

#endif /* HTTP_LAT_DIAG */

err_t httpd_post_begin(void *connection, const char *uri, const char *http_request,
                       u16_t http_request_len, int content_len, char *response_uri,
                       u16_t response_uri_len, u8_t *post_auto_wnd)
{
  LWIP_UNUSED_ARG(http_request);
  LWIP_UNUSED_ARG(http_request_len);

#if HTTP_LAT_DIAG
  /* Start of the application window. Reset the per-POST accumulators here rather
     than at the end, so an abandoned POST cannot leak its timings into the next. */
  lat_t0       = LAT_NOW();
  lat_recv_acc = 0U;
  lat_fin_us   = 0U;
  lat_disp_us  = 0U;
  lat_active   = 1U;

  /* Segment 2 closes here: the frame that triggered this POST was handed to lwIP
     at eth_rx_input_cyc, so this delta is the tcpip_thread mailbox hop plus the
     mbedTLS record decrypt plus httpd's header parse. */
  if (lat_cyc_per_us != 0U)
  {
    uint32_t us = (lat_t0 - eth_rx_input_cyc) / lat_cyc_per_us;

    if (us > lat_rx2app_us_max) { lat_rx2app_us_max = us; }
    if (us > 1000U)             { lat_rx2app_over1ms++;   }
  }
#endif

  /* Let httpd manage the receive window itself. Manual window control
     (LWIP_HTTPD_POST_MANUAL_WND) is only worth the complexity when the body is
     streamed to slow storage; ours fits in RAM. */
  *post_auto_wnd = 1;

  /* Refuse rather than corrupt - see the single-slot note above. */
  if (active_conn != NULL)
  {
    resp_build_json("503 Service Unavailable",
                    "{\"ok\":false,\"error\":\"another POST in progress\"}");
    snprintf(response_uri, response_uri_len, URI_RESULT);
    return ERR_OK;   /* ERR_OK + a response URI = "answer with this", not "accept body" */
  }

  if (strcmp(uri, "/echo") == 0)
  {
    post_mode = POST_MODE_ECHO;
  }
  else if (strcmp(uri, "/uart") == 0)
  {
    post_mode = POST_MODE_UART;
  }
  else if (strcmp(uri, "/uartecho") == 0)
  {
    /* Added 11-08-2026 for client-side RTT measurement of the UART bridge.
       Deliberately a SEPARATE URI rather than a change to /uart: /uart's 202 +
       JSON contract is asserted by 7 checks in test_https.ps1 and relied on by
       measure_https_rtt.ps1, and altering it to return the payload would break
       both. */
    post_mode = POST_MODE_UART_ECHO;
  }
  else
  {
    /* Unknown POST target. Returning anything other than ERR_OK makes httpd
       send its own 400, which is the correct answer here. */
    return ERR_VAL;
  }

  /* content_len is -1 when the client used chunked transfer encoding, which
     lwIP's httpd does not support for POST. Refuse it explicitly - otherwise
     the length check below would pass a negative value through. */
  if (content_len < 0)
  {
    resp_build_json("400 Bad Request",
                    "{\"ok\":false,\"error\":\"chunked encoding not supported, send Content-Length\"}");
    snprintf(response_uri, response_uri_len, URI_RESULT);
    return ERR_OK;
  }

  if ((unsigned)content_len > HTTP_POST_MAX_BODY)
  {
    resp_build_json("413 Payload Too Large",
                    "{\"ok\":false,\"error\":\"body too large\",\"max\":%u}",
                    (unsigned)HTTP_POST_MAX_BODY);
    snprintf(response_uri, response_uri_len, URI_RESULT);
    return ERR_OK;
  }

  active_conn      = connection;
  post_body_len    = 0U;
  post_content_len = (uint16_t)content_len;
  return ERR_OK;
}

err_t httpd_post_receive_data(void *connection, struct pbuf *p)
{
  /* A body can arrive across several pbufs; this is called once per pbuf and
     owns freeing it, on every path including the error ones. */
  if (connection != active_conn)
  {
    pbuf_free(p);
    return ERR_VAL;
  }

  {
#if HTTP_LAT_DIAG
    uint32_t t_rx = LAT_NOW();
#endif
    u16_t copied = pbuf_copy_partial(p, &post_body[post_body_len],
                                     (u16_t)(HTTP_POST_MAX_BODY - post_body_len), 0);
    post_body_len = (uint16_t)(post_body_len + copied);
#if HTTP_LAT_DIAG
    /* Accumulated, not overwritten: a body can arrive across several pbufs and
       this is called once per pbuf. */
    lat_recv_acc += lat_us_since(t_rx);
#endif
  }

  pbuf_free(p);
  return ERR_OK;
}

void httpd_post_finished(void *connection, char *response_uri, u16_t response_uri_len)
{
#if HTTP_LAT_DIAG
  uint32_t t_fin = LAT_NOW();
#endif

  /* Always answer through URI_RESULT; resp_buf already holds the response for
     the early-rejection paths in httpd_post_begin(). */
  if (connection != active_conn)
  {
    snprintf(response_uri, response_uri_len, URI_RESULT);
    return;
  }

  if (post_body_len != post_content_len)
  {
    /* Short body: the client declared more than it sent, or the connection was
       cut mid-body. Do NOT act on a partial frame - a truncated UART payload
       could be a valid-looking but wrong command to an attached device. */
    resp_build_json("400 Bad Request",
                    "{\"ok\":false,\"error\":\"incomplete body\",\"got\":%u,\"expected\":%u}",
                    (unsigned)post_body_len, (unsigned)post_content_len);
  }
  else if (post_mode == POST_MODE_ECHO)
  {
    /* Echo: hand the bytes straight back. application/octet-stream rather than
       a text type, because the body is whatever the client sent - possibly
       binary - and mislabelling it would corrupt it through some clients. */
    resp_build("200 OK", "application/octet-stream", post_body, post_body_len);
  }
  else if (post_body_len < 1U)
  {
    resp_build_json("400 Bad Request",
                    "{\"ok\":false,\"error\":\"need at least a selector byte\"}");
  }
  else if (post_mode == POST_MODE_UART_ECHO)
  {
    /* ----------------------------------------------------------------------
     * /uartecho - queue to the UART AND return the decrypted payload.
     * ----------------------------------------------------------------------
     * Exists so a client can measure end-to-end RTT of the UART bridge in ONE
     * round trip. /uart cannot serve that purpose: its 202 reply is JSON derived
     * from the request, not the message, so a client measuring against it is not
     * measuring a message coming back. /echo returns the message but never
     * touches a UART. This does both.
     *
     * WHAT IS ECHOED, and why it is the payload rather than the whole body: the
     * selector is addressing, not content. Returning post_body[1..] means the
     * client can compare the reply against exactly the bytes it asked to be
     * transmitted, so a mismatch is unambiguous.
     *
     * The RTT this yields is HTTPS-in to HTTPS-out: TLS decrypt, HTTP parse,
     * uart_dispatch_send() queue put, response build, TLS encrypt. It does NOT
     * include the UART task dequeuing or the bytes reaching the wire - those
     * happen after the response has gone, exactly as for /uart. Measuring to the
     * wire needs a scope on TX; no software timestamp can observe both ends.
     *
     * Dispatch happens BEFORE the response is built so that a queue failure is
     * reported honestly rather than echoed as success.
     * -------------------------------------------------------------------- */
#if HTTP_LAT_DIAG
    uint32_t t_disp = LAT_NOW();
#endif
    int rc = uart_dispatch_send(post_body[0],
                                &post_body[1],
                                (size_t)(post_body_len - 1U),
                                NULL);
#if HTTP_LAT_DIAG
    /* Isolated because it is the one call here that reaches another task's queue.
       osMessageQueuePut() at uart_dispatch.c:191 uses a 0 timeout so it cannot
       block - this measures that rather than trusting it. */
    lat_disp_us = lat_us_since(t_disp);
#endif

    if (rc == 0)
    {
      resp_build("200 OK", "application/octet-stream",
                 &post_body[1], (uint16_t)(post_body_len - 1U));
    }
    else if (rc == -1)
    {
      resp_build_json("400 Bad Request",
                      "{\"ok\":false,\"error\":\"bad selector or oversized payload\",\"sel\":%u}",
                      (unsigned)post_body[0]);
    }
    else
    {
      resp_build_json("503 Service Unavailable",
                      "{\"ok\":false,\"error\":\"queue full or out of memory\",\"sel\":%u}",
                      (unsigned)post_body[0]);
    }
  }
  else
  {
    /* UART dispatch: first byte selects the UART, the rest is the payload.
       Same wire format as the raw-TCP version in TCP_Server_H753_RTOS__ES_V00,
       so existing selector values carry over unchanged.
       conn is passed as NULL: it existed so a late reply could be written back
       onto the originating socket, and under HTTP there is no such socket. The
       reply is collected from the per-UART slot via GET instead. */
    int rc = uart_dispatch_send(post_body[0],
                                &post_body[1],
                                (size_t)(post_body_len - 1U),
                                NULL);

    if (rc == 0)
    {
      resp_build_json("202 Accepted",
                      "{\"ok\":true,\"sel\":%u,\"queued\":%u}",
                      (unsigned)post_body[0], (unsigned)(post_body_len - 1U));
    }
    else if (rc == -1)
    {
      resp_build_json("400 Bad Request",
                      "{\"ok\":false,\"error\":\"bad selector or oversized payload\",\"sel\":%u}",
                      (unsigned)post_body[0]);
    }
    else
    {
      /* -2: pvPortMalloc failed or the queue is full. 503 is the honest answer -
         the request was well formed, the device is momentarily out of capacity. */
      resp_build_json("503 Service Unavailable",
                      "{\"ok\":false,\"error\":\"queue full or out of memory\",\"sel\":%u}",
                      (unsigned)post_body[0]);
    }
  }

  active_conn = NULL;
  snprintf(response_uri, response_uri_len, URI_RESULT);

#if HTTP_LAT_DIAG
  lat_fin_us = lat_us_since(t_fin);
#endif
}

/* ==========================================================================
 * Custom file hooks - how every dynamic response actually reaches the client
 * ======================================================================== */

/* Extracts the selector digit from "/uart/lastN.json". Returns 0 for anything
   malformed - 0 is not a valid selector, so it doubles as the error value. */
static uint8_t parse_sel(const char *name)
{
  char c = name[sizeof(URI_UART_LAST_PREFIX) - 1U];   /* the char right after the prefix */

  if ((c < '1') || (c > '4'))
  {
    return 0U;
  }
  return (uint8_t)(c - '0');
}

int fs_open_custom(struct fs_file *file, const char *name)
{
  /* Called for EVERY file open before the static fsdata is consulted, so it
     must recognise only its own URIs and return 0 for everything else -
     otherwise index.html and the rest would stop being served. */

#if HTTP_LAT_DIAG
  uint32_t t_serve   = LAT_NOW();
  uint8_t  is_result = 0U;
#endif

  if (strncmp(name, URI_RESULT, sizeof(URI_RESULT) - 1U) == 0)
  {
#if HTTP_LAT_DIAG
    is_result = 1U;
#endif
    if (resp_len == 0U)
    {
      /* resp_build() overflowed, which should be impossible. Answer something
         valid rather than a zero-length file that would look like a hang. */
      resp_build_json("500 Internal Server Error",
                      "{\"ok\":false,\"error\":\"response buffer overflow\"}");
    }
  }
#if HTTP_LAT_DIAG
  else if (strncmp(name, URI_LAT, sizeof(URI_LAT) - 1U) == 0)
  {
    /* dwt_ok is reported first and deliberately: if it is false every other
       number here is meaningless, and a reader that ignores it would conclude the
       application is infinitely fast. app_max is the headline - compare it with
       the wire RTT max for the same run. The w_* block is the breakdown of the
       single worst request and is the only set of figures that adds up. */
    resp_build_json("200 OK",
        "{\"dwt_ok\":%u,\"cyc_per_us\":%lu,\"count\":%lu,"
        "\"app_us_max\":%lu,\"app_us_last\":%lu,"
        "\"over_1ms\":%lu,\"over_5ms\":%lu,"
        "\"recv_us_max\":%lu,\"fin_us_max\":%lu,\"disp_us_max\":%lu,\"serve_us_max\":%lu,"
        "\"worst\":{\"app_us\":%lu,\"recv_us\":%lu,\"fin_us\":%lu,\"disp_us\":%lu,\"serve_us\":%lu},"
        "\"tx\":{\"ok\":%lu,\"busy_wait\":%lu,\"wait_us_max\":%lu,\"wait_us_last\":%lu,"
        "\"wait_over1ms\":%lu,\"wait_over10ms\":%lu,\"clone_fail\":%lu,\"toolong\":%lu,\"chain_max\":%lu},"
        "\"seg\":{\"rx_sched_us\":%lu,\"rx_sched_1ms\":%lu,\"rx_sched_5ms\":%lu,"
        "\"rx_sched_10ms\":%lu,\"rx_sched_bogus\":%lu,\"rx2app_us\":%lu,"
        "\"rx2app_1ms\":%lu,\"serve2tx_us\":%lu,\"serve2tx_1ms\":%lu},"
        "\"rx\":{\"rbu\":%lu,\"alloc_fail\":%lu,\"pool_recover\":%lu}}",
        (unsigned)lat_dwt_ok, (unsigned long)lat_cyc_per_us, (unsigned long)lat_count,
        (unsigned long)lat_app_us_max, (unsigned long)lat_app_us_last,
        (unsigned long)lat_over_1ms, (unsigned long)lat_over_5ms,
        (unsigned long)lat_recv_us_max, (unsigned long)lat_fin_us_max,
        (unsigned long)lat_disp_us_max, (unsigned long)lat_serve_us_max,
        (unsigned long)latw_app_us, (unsigned long)latw_recv_us,
        (unsigned long)latw_fin_us, (unsigned long)latw_disp_us,
        (unsigned long)latw_serve_us,
        (unsigned long)eth_tx_ok, (unsigned long)eth_tx_busy_wait,
        (unsigned long)eth_tx_wait_us_max, (unsigned long)eth_tx_wait_us_last,
        (unsigned long)eth_tx_wait_over1ms, (unsigned long)eth_tx_wait_over10ms,
        (unsigned long)eth_tx_clone_fail, (unsigned long)eth_tx_toolong,
        (unsigned long)eth_tx_chain_max,
        (unsigned long)lat_rx_sched_us_max, (unsigned long)lat_rx_sched_over1ms,
        (unsigned long)lat_rx_sched_over5ms, (unsigned long)lat_rx_sched_over10ms,
        (unsigned long)lat_rx_sched_bogus,
        (unsigned long)lat_rx2app_us_max,   (unsigned long)lat_rx2app_over1ms,
        (unsigned long)lat_serve2tx_us_max, (unsigned long)lat_serve2tx_over1ms,
        (unsigned long)eth_rbu_events, (unsigned long)eth_rx_alloc_fail,
        (unsigned long)eth_rx_pool_recover);

    /* Reset AFTER building the response, so the caller still sees the values it
       asked for. strstr on the whole name because httpd hands the query string
       through in it. */
    if (strstr(name, "reset=1") != NULL)
    {
      lat_app_us_max = 0U; lat_recv_us_max = 0U; lat_fin_us_max  = 0U;
      lat_disp_us_max = 0U; lat_serve_us_max = 0U;
      lat_count = 0U; lat_over_1ms = 0U; lat_over_5ms = 0U;
      latw_app_us = 0U; latw_recv_us = 0U; latw_fin_us = 0U;
      latw_disp_us = 0U; latw_serve_us = 0U;
      /* Tx counters too, so a reset gives a clean per-run picture on both sides.
         eth_tx_ok is deliberately NOT reset - it is a lifetime frame count and is
         useful as a sanity check that frames are flowing at all. */
      eth_tx_busy_wait = 0U; eth_tx_wait_us_max = 0U; eth_tx_wait_us_last = 0U;
      eth_tx_wait_over1ms = 0U; eth_tx_wait_over10ms = 0U;
      lat_rx_sched_us_max = 0U; lat_rx_sched_over1ms = 0U;
      lat_rx_sched_over5ms = 0U; lat_rx_sched_over10ms = 0U; lat_rx_sched_bogus = 0U;
      lat_rx2app_us_max   = 0U; lat_rx2app_over1ms   = 0U;
      lat_serve2tx_us_max = 0U; lat_serve2tx_over1ms = 0U;
      eth_rbu_events = 0U; eth_rx_alloc_fail = 0U; eth_rx_pool_recover = 0U;
    }
  }
#endif
  else if (strncmp(name, URI_UART_LAST_PREFIX, sizeof(URI_UART_LAST_PREFIX) - 1U) == 0)
  {
    uint8_t  sel = parse_sel(name);
    uint8_t  reply[UART_DISPATCH_MAX_REPLY];
    uint16_t reply_len = 0U;
    uint32_t seq = 0U;

    if ((sel == 0U) || (uart_dispatch_get_last(sel, reply, sizeof(reply),
                                               &reply_len, &seq) != 0))
    {
      resp_build_json("400 Bad Request",
                      "{\"ok\":false,\"error\":\"bad URI, expected /uart/lastN.json with N=1..4\"}");
    }
    else
    {
      /* Hex-encode the payload. JSON cannot carry arbitrary bytes, and a UART
         reply is not guaranteed to be printable text - hex keeps the endpoint
         honest for binary protocols and is trivial for a script to decode.
         "seq" is what lets a poller distinguish a genuinely new reply from an
         identical repeat; comparing the payload alone cannot. */
      char   body[(UART_DISPATCH_MAX_REPLY * 2U) + 96U];
      int    n;
      uint16_t i;

      n = snprintf(body, sizeof(body),
                   "{\"ok\":true,\"sel\":%u,\"seq\":%lu,\"len\":%u,\"hex\":\"",
                   (unsigned)sel, (unsigned long)seq, (unsigned)reply_len);

      for (i = 0U; (i < reply_len) && ((unsigned)n + 3U < sizeof(body)); i++)
      {
        n += snprintf(&body[n], sizeof(body) - (unsigned)n, "%02X", reply[i]);
      }
      n += snprintf(&body[n], sizeof(body) - (unsigned)n, "\"}");

      resp_build("200 OK", "application/json", body, (uint16_t)n);
    }
  }
  else
  {
    return 0;   /* not ours - fall through to fsdata_custom.c */
  }

  file->data  = resp_buf;
  file->len   = (int)resp_len;
  file->index = (int)resp_len;   /* whole body already in memory */

  /* ---- FLAGS: both bits are required, for different reasons ---------------
     HEADER_INCLUDED  resp_buf carries its own status line and headers, so httpd
                      must not prepend any of its own.

     HEADER_PERSISTENT  ADDED 07-08-2026, and it is what actually enables
                      keep-alive. httpd.c line 2448 reads:
                          if ((flags & (INCLUDED | PERSISTENT)) == INCLUDED)
                              hs->keepalive = 0;
                      so a baked header WITHOUT this bit forces the connection
                      closed no matter what the header itself says. With
                      HEADER_INCLUDED alone, the "Connection: keep-alive" in
                      resp_build() would have been a promise httpd then broke.

     An earlier version of this comment claimed PERSISTENT had to be omitted
     because "httpd must not cache a pointer to resp_buf beyond this response".
     That was wrong - the flag is only ever read to decide keep-alive (line 2448)
     and whether httpd adds its own Content-Length (line 973, which does not
     apply to us because HEADER_INCLUDED skips header generation entirely).
     Nothing caches the pointer. fs_close_custom() still ends the response.
     ---------------------------------------------------------------------- */
  file->flags = FS_FILE_FLAGS_HEADER_INCLUDED | FS_FILE_FLAGS_HEADER_PERSISTENT;

#if HTTP_LAT_DIAG
  /* Close the application window. Only for URI_RESULT and only when a measured
     POST is actually in flight - fs_open_custom() also serves /uart/lastN.json
     and static files, which have no post_begin to measure from and would
     otherwise produce a nonsense app total from a stale lat_t0. */
  if ((is_result != 0U) && (lat_active != 0U))
  {
    uint32_t app = lat_us_since(lat_t0);
    uint32_t srv = lat_us_since(t_serve);

    /* Segment 4 begins: hand the baton to eth_tx_output(), which closes it on the
       next transmitted frame. */
    lat_serve_cyc  = LAT_NOW();
    lat_tx_pending = 1U;

    lat_active       = 0U;
    lat_app_us_last  = app;
    lat_count++;
    if (app > 1000U) { lat_over_1ms++; }
    if (app > 5000U) { lat_over_5ms++; }

    if (lat_recv_acc > lat_recv_us_max)  { lat_recv_us_max  = lat_recv_acc; }
    if (lat_fin_us   > lat_fin_us_max)   { lat_fin_us_max   = lat_fin_us;   }
    if (lat_disp_us  > lat_disp_us_max)  { lat_disp_us_max  = lat_disp_us;  }
    if (srv          > lat_serve_us_max) { lat_serve_us_max = srv;          }

    if (app > lat_app_us_max)
    {
      /* Snapshot every segment together, so the worst request can be read as one
         coherent breakdown. The individual _max values above may each come from a
         different request and must NOT be added up. */
      lat_app_us_max = app;
      latw_app_us    = app;
      latw_recv_us   = lat_recv_acc;
      latw_fin_us    = lat_fin_us;
      latw_disp_us   = lat_disp_us;
      latw_serve_us  = srv;
    }
  }
#endif

  return 1;
}

void fs_close_custom(struct fs_file *file)
{
  /* Nothing to release: resp_buf is static. Present because
     LWIP_HTTPD_CUSTOM_FILES requires the pair. */
  LWIP_UNUSED_ARG(file);
}

/* ==========================================================================
 * Bring-up
 * ======================================================================== */

/* Parsed CA used to verify client certificates. File-scope and never freed: the
   TLS config holds a pointer to it for the life of the listener, so it must
   outlive http_server_start(). A local would be a dangling pointer.

   COMPILED OUT WITH THE SWITCH. Nothing references it when ENABLE_MUTUAL_TLS is
   0, and leaving it defined cost a -Wunused-variable warning on that build. A
   warning that appears only in one configuration is worse than it looks: it
   trains you to expect a non-clean build, and the next real warning hides in
   the noise. It also occupies an mbedtls_x509_crt in .bss for nothing. */
#if ENABLE_MUTUAL_TLS
static mbedtls_x509_crt tls_client_ca;
#endif

/**
  * @brief  Builds the HTTPS server config, including mutual-TLS client
  *         verification.
  * @retval config handle, or NULL on failure (caller must not start HTTPS)
  *
  * ---------------------------------------------------------------------------
  * WHY MUTUAL TLS NEEDS TWO STEPS lwIP DOES NOT PROVIDE
  * ---------------------------------------------------------------------------
  * lwIP's altcp_tls API has altcp_tls_create_config_client_2wayauth() for a
  * CLIENT doing mutual auth, but there is NO server equivalent. Worse,
  * altcp_tls_create_config_server() actively clears the CA chain
  * (altcp_tls_mbedtls.c line 879):
  *     mbedtls_ssl_conf_ca_chain(&conf->conf, NULL, NULL);
  * So a server built through the public API cannot verify client certificates at
  * all, whatever ALTCP_MBEDTLS_AUTHMODE says.
  *
  * Two things therefore have to be done outside the API:
  *   1. ALTCP_MBEDTLS_AUTHMODE = MBEDTLS_SSL_VERIFY_REQUIRED, set in
  *      lwipopts.h USER CODE 1. Its default is VERIFY_OPTIONAL, which ACCEPTS a
  *      client with no certificate - failing open.
  *   2. Install a CA chain on the finished config, below.
  *
  * ---------------------------------------------------------------------------
  * THE CAST, AND WHY IT IS LEGAL RATHER THAN A HACK
  * ---------------------------------------------------------------------------
  * struct altcp_tls_config is defined in altcp_tls_mbedtls.c (line 103), not in
  * any header, so it is opaque to us. But its FIRST member is the
  * mbedtls_ssl_config:
  *     struct altcp_tls_config {
  *       mbedtls_ssl_config conf;      <-- offset 0
  *       mbedtls_x509_crt *cert;
  *       ...
  * and C guarantees a pointer to a struct compares equal to a pointer to its
  * first member. So casting the handle to mbedtls_ssl_config* is well defined.
  *
  * The alternative was patching altcp_tls_mbedtls.c to add a server-2wayauth
  * helper. Rejected: CubeMX copies that file, so the patch would be destroyed by
  * every regeneration - the fsdata_custom.c problem, on a file whose loss would
  * silently disable client verification rather than break the build.
  *
  * THE COUPLING THIS CREATES: if lwIP is ever upgraded, re-check that
  * mbedtls_ssl_config is still the first member of struct altcp_tls_config. If a
  * field were inserted before it, this cast would corrupt the config silently.
  * ------------------------------------------------------------------------- */
static struct altcp_tls_config *http_server_tls_config(void)
{
  struct altcp_tls_config *conf;
#if ENABLE_MUTUAL_TLS
  /* Only the client-CA parse below returns a code worth keeping. Declared
     inside the switch so the mutual-TLS-off build stays warning-clean. */
  int rc;
#endif

  /* Server identity: private key + certificate. No key password - the DER key
     in tls_credentials.h is unencrypted, hence NULL/0 for the middle pair. */
  conf = altcp_tls_create_config_server_privkey_cert(
             tls_server_key_der,  sizeof(tls_server_key_der),
             NULL, 0,
             tls_server_cert_der, sizeof(tls_server_cert_der));
  if (conf == NULL)
  {
    /* Most likely causes, in order: LWIP_ALTCP_TLS_MBEDTLS not defined (the
       whole file compiles away and this always returns NULL), the FreeRTOS heap
       exhausted, or a malformed key/cert DER. */
    printf("tls: *** altcp_tls_create_config_server_privkey_cert failed ***\r\n");
    printf("tls:     check LWIP_ALTCP_TLS_MBEDTLS=1 in lwipopts.h USER CODE 1\r\n");
    return NULL;
  }

  /* ------------------------------------------------------------------------
   * CLIENT AUTHENTICATION - switched by ENABLE_MUTUAL_TLS.  24-08-2026.
   * ------------------------------------------------------------------------
   * This block was unconditional until 24-08-2026: the board ALWAYS demanded a
   * client certificate and there was no way to accept an anonymous client
   * without editing this function. It now follows the switch in main.h.
   *
   * THE AUTHMODE IS SET EXPLICITLY HERE, not left to ALTCP_MBEDTLS_AUTHMODE in
   * lwipopts.h. Two places deciding one policy is how they end up disagreeing:
   * lwipopts.h would still say VERIFY_REQUIRED while this switch said 0, and
   * whichever ran last would win silently. lwipopts.h is deliberately left
   * alone; this call overrides it either way, so main.h is the single source
   * of truth.
   *
   * AT 0 THE BOARD STILL PRESENTS ITS OWN CERTIFICATE and the client still
   * verifies it. Only the CLIENT's identity stops being demanded, which is
   * server-authenticated HTTPS - the ordinary web arrangement.
   *
   * VERIFY_NONE, NOT VERIFY_OPTIONAL, for the off case. OPTIONAL asks for a
   * certificate and then accepts a client that presents none, which reads as
   * "mutual TLS is on" in a packet capture while enforcing nothing. That
   * fail-open behaviour is exactly what test_mtls.py exists to catch, so it
   * must not be what this switch selects.
   * --------------------------------------------------------------------- */
#if ENABLE_MUTUAL_TLS
  /* Now make it MUTUAL. Parse the CA that signed the client certificates and
     install it, undoing the NULL chain the server constructor left behind. */
  mbedtls_x509_crt_init(&tls_client_ca);
  rc = mbedtls_x509_crt_parse_der(&tls_client_ca,
                                  tls_ca_cert_der, sizeof(tls_ca_cert_der));
  if (rc != 0)
  {
    printf("tls: *** CA parse failed, rc=-0x%04X - client auth NOT enabled ***\r\n",
           (unsigned)-rc);
    altcp_tls_free_config(conf);
    return NULL;
  }

  /* See the cast rationale above. Second argument NULL = no CRL. */
  mbedtls_ssl_conf_ca_chain((mbedtls_ssl_config *)conf, &tls_client_ca, NULL);
  mbedtls_ssl_conf_authmode((mbedtls_ssl_config *)conf,
                            MBEDTLS_SSL_VERIFY_REQUIRED);
#else
  /* No client CA is installed and none is asked for. tls_client_ca is left
     untouched - it is a file-scope object, so it stays zeroed rather than
     holding a half-parsed chain. */
  mbedtls_ssl_conf_authmode((mbedtls_ssl_config *)conf,
                            MBEDTLS_SSL_VERIFY_NONE);
#endif

#if defined(MBEDTLS_DEBUG_C)
  /* ------------------------------------------------------------------------
   * HTTPS BRING-UP DIAGNOSTIC.  07-08-2026.  Remove with MBEDTLS_DEBUG_C.
   * ------------------------------------------------------------------------
   * mbedTLS emits NOTHING until a threshold is set here, even with
   * MBEDTLS_DEBUG_C defined and altcp's mbedtls_ssl_conf_dbg() hook installed -
   * its internal debug_threshold starts at 0. Level 1 is errors only, which is
   * what names the failing function, e.g.
   *     ssl_srv.c:NNNN: ssl_write_server_key_exchange() returned -0xXXXX
   *
   * KEEP THIS AT 1. printf is blocking UART at roughly 8.5 ms a line; level 3+
   * emits hundreds of lines and will itself change handshake timing.
   * -------------------------------------------------------------------- */
  mbedtls_debug_set_threshold(1);
  printf("tls: DIAGNOSTIC BUILD - mbedTLS debug level 1 (errors only)\r\n");
#endif

  /* SAY WHICH MODE THIS BUILD IS IN. The banner is the only thing a serial log
     has to tell the two apart, and the PC-side test suites take the expected
     mode as a parameter - test_mtls.py --expect-mtls, test_https.ps1
     -NoMutualTls - so a log that does not say which was built makes a FAIL
     impossible to interpret. */
#if ENABLE_MUTUAL_TLS
  printf("tls: mutual TLS enabled - client certificate REQUIRED\r\n");
#else
  printf("tls: mutual TLS OFF - server-authenticated HTTPS only "
         "(ENABLE_MUTUAL_TLS = 0)\r\n");
#endif
  printf("tls: server cert %u B, key %u B, CA %u B\r\n",
         (unsigned)sizeof(tls_server_cert_der),
         (unsigned)sizeof(tls_server_key_der),
         (unsigned)sizeof(tls_ca_cert_der));

  /* Free-heap figure taken AFTER the TLS config is built, so it is the headroom
     an actual handshake will have to work in. Every mbedTLS allocation comes from
     ucHeap via mbedtls_platform_calloc() (Core/Src/mbedtls_platform_glue.c), and
     a session needs roughly 7 KB of record buffers - MBEDTLS_SSL_IN_CONTENT_LEN
     2048 plus MBEDTLS_SSL_OUT_CONTENT_LEN 4096 plus overhead - and a further
     2-3 KB of handshake state. If this number is below about 12 KB, suspect the
     heap before anything else; vApplicationMallocFailedHook() in freertos.c will
     say so outright now that it is no longer empty. */
  printf("tls: FreeRTOS heap free %u B (session needs ~10-12 KB)\r\n",
         (unsigned)xPortGetFreeHeapSize());
  return conf;
}

void http_server_start(void)
{
  /* MUST already be on tcpip_thread - see the threading note at the top of this
     file and http_server_init_callback() in main.c. Both httpd_init() and
     httpd_inits() create listening PCBs through the raw/altcp API. */

#if HTTP_LAT_DIAG
  /* Before anything can be served, so no POST is ever measured against a
     stopped counter. Prints once; see the no-periodic-printf note in the
     instrumentation block. */
  lat_init();
#endif

#if HTTP_SERVER_ENABLE_PLAIN_HTTP
  httpd_init();
  printf("http: listening on TCP port %d (PLAIN HTTP - see "
         "HTTP_SERVER_ENABLE_PLAIN_HTTP)\r\n", (int)HTTPD_SERVER_PORT);
#else
  printf("http: plain HTTP disabled (HTTP_SERVER_ENABLE_PLAIN_HTTP = 0)\r\n");
#endif

  /* HTTPS. httpd_inits() takes ownership of the config for the listener's
     lifetime, so it must not be freed on the success path. */
  {
    struct altcp_tls_config *tls_conf = http_server_tls_config();

    if (tls_conf != NULL)
    {
      httpd_inits(tls_conf);
      printf("https: listening on TCP port %d\r\n", (int)HTTPD_SERVER_PORT_HTTPS);
      /* Expect roughly a second per handshake on this hardware - the reference
         project measured ~1.05 s with MBEDTLS_ECP_NIST_OPTIM already enabled.
         Keep-alive is what makes that tolerable, by amortising it across every
         request on the connection. */
      printf("https: handshake is ~1 s; keep-alive amortises it per connection\r\n");
    }
    else
    {
      printf("https: *** NOT STARTED - see the tls: errors above ***\r\n");
    }
  }

  printf("http: POST /echo | POST /uart | POST /uartecho [sel][payload] | GET %sN.json (N=1..4)\r\n",
         URI_UART_LAST_PREFIX);
  printf("http: max POST body %u bytes\r\n", (unsigned)HTTP_POST_MAX_BODY);

  /* Prove the static file system is reachable. A missing or mis-excluded
     fsdata_custom.c is otherwise a silent fault: the server accepts connections
     and answers every request with 404, which reads as a content problem rather
     than a build problem. */
  {
    struct fs_file f;

    if (fs_open(&f, "/index.html") == ERR_OK)
    {
      printf("http: fs OK - /index.html is %d bytes\r\n", f.len);
      fs_close(&f);
    }
    else
    {
      printf("http: *** fs FAILED - /index.html not found in fsdata_custom.c ***\r\n");
    }
  }
}
