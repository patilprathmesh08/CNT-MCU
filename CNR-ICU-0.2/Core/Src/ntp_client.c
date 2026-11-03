/**
  ******************************************************************************
  * @file    ntp_client.c
  * @brief   SNTP client and free-running local epoch clock - implementation
  * @version 1.0 - 28-08-2026
  *
  * See ntp_client.h for the design and for why nothing is incremented. This
  * file is the mechanism: one task, one UDP socket per poll, one anchor.
  *
  * SELECT() IS USED FOR THE RECEIVE TIMEOUT, NOT SO_RCVTIMEO, and that is not a
  * style choice. LWIP_SO_RCVTIMEO defaults to 0 in opt.h and this project's
  * lwipopts.h does not override it, so lwip_setsockopt(SO_RCVTIMEO) FAILS here
  * and the socket stays fully blocking. stream_client.c makes that call with
  * its return value cast to (void), which is why the problem has gone unnoticed
  * there. A blocking recvfrom on a dead server would wedge this task for ever.
  * LWIP_SOCKET_SELECT is 1, so select() works and is used instead.
  ******************************************************************************
  */

/* Includes ------------------------------------------------------------------*/
#include "ntp_client.h"
#include "main.h"
#include "cmsis_os2.h"
#include "uart_dispatch.h"

/* mdns_service_get_address() - the server address when NTP_SERVER_USE_MDNS is
   1. The i.MX8 serves both NTP and the WSS stream, so both take the address
   from the same resolution rather than configuring it twice. */
#include "mdns_service.h"

#include "lwip/opt.h"
#include "lwip/sockets.h"
#include "lwip/inet.h"

#include <stdio.h>
#include <string.h>

/* Private defines -----------------------------------------------------------*/

/* An SNTP packet is exactly 48 bytes. Indexed as a byte array rather than
   overlaid with a struct: a struct would depend on the compiler not inserting
   padding and on the fields being naturally aligned, neither of which is worth
   assuming for a wire format. */
#define NTP_PACKET_LEN          48U

#define NTP_OFF_LI_VN_MODE      0U
#define NTP_OFF_STRATUM         1U
#define NTP_OFF_TX_SEC          40U   /* transmit timestamp, seconds  */
#define NTP_OFF_TX_FRAC         44U   /* transmit timestamp, fraction */

/* LI = 0 (no warning), VN = 4, Mode = 3 (client). */
#define NTP_LI_VN_MODE_CLIENT   0x23U

#define NTP_MODE_MASK           0x07U
#define NTP_MODE_SERVER         4U
#define NTP_LI_MASK             0xC0U
#define NTP_LI_UNSYNC           0xC0U  /* server says it is not synchronised */

/* Private variables ---------------------------------------------------------*/

/* THE ANCHOR, in MICROSECONDS. Written only by the NTP task, read by anyone.
   The three fields must be read together or the answer is wrong by however long
   elapsed between the reads, so every access goes through the critical section.

   THE TICK IS KEPT AS A SEPARATE uint32_t rather than folded into a 64-bit
   microsecond count, and that is deliberate. HAL_GetTick() wraps every 49.7
   days; multiplying it by 1000 into a uint64 does NOT make the wrap go away, it
   just moves it somewhere harder to see. Subtracting two uint32 ticks is
   wrap-safe by construction, so the elapsed calculation below stays correct
   across a wrap with no special case. */
static volatile uint64_t Epoch_us_at_sync;
static volatile uint32_t Tick_at_sync;   /* HAL_GetTick() milliseconds  */
static volatile uint32_t Cnt_at_sync;    /* TIM6->CNT, 0..999 within it */
static volatile uint8_t  Synced;

volatile uint32_t ntp_polls;
volatile uint32_t ntp_replies;
volatile uint32_t ntp_timeouts;
volatile uint32_t ntp_bad_packets;
volatile uint32_t ntp_syncs;
volatile uint32_t ntp_last_rtt_ms;
volatile int32_t  ntp_last_offset_us;

static osThreadId_t         ntp_task_handle;

#if NTP_CLIENT_ENABLE
static const osThreadAttr_t ntp_task_attributes = {
    .name       = "NtpClient",
    .stack_size = NTP_TASK_STACK_BYTES,
    .priority   = (osPriority_t)osPriorityLow
};
#endif

/* Private function prototypes -----------------------------------------------*/
static uint32_t ntp_lock(void);
static void     ntp_unlock(uint32_t primask);
static uint32_t ntp_be32(const uint8_t *p);
static void     ntp_read_local(uint32_t *tick, uint32_t *cnt);
static void     ntp_build_request(uint8_t *pkt);
static int32_t  ntp_parse_reply(const uint8_t *pkt, uint32_t len,
                                uint64_t *epoch_us);
#if NTP_CLIENT_ENABLE
static void     ntp_apply_sync(uint64_t server_us, uint32_t tick_at_rx,
                               uint32_t cnt_at_rx, uint32_t rtt_ms);
static int32_t  ntp_poll_once(void);
#endif
/* Both conditions: the only caller is ntp_task(), which itself exists only when
   NTP_CLIENT_ENABLE is 1. Guarding on the print interval alone would leave this
   defined but uncalled in a bisect build. */
#if (NTP_CLIENT_ENABLE && (NTP_PRINT_INTERVAL_MS > 0))
static void     ntp_print_epoch(void);
#endif
#if NTP_CLIENT_ENABLE
static void     ntp_task(void *argument);
#endif

/* Private functions ---------------------------------------------------------*/

/**
  * @brief  Masks interrupts, returning the previous PRIMASK.
  * @return PRIMASK in force before masking.
  * @param  None
  *
  * PRIMASK is saved and restored rather than using a bare
  * __disable_irq()/__enable_irq() pair, so a caller that already holds a
  * critical section does not have it silently released underneath.
  */
static uint32_t ntp_lock(void)
{
    uint32_t primask = __get_PRIMASK();

    __disable_irq();

    return primask;
}

/**
  * @brief  Restores a PRIMASK saved by ntp_lock().
  * @return None
  * @param  primask: value from the matching ntp_lock()
  */
static void ntp_unlock(uint32_t primask)
{
    __set_PRIMASK(primask);
}

/**
  * @brief  Reads a big-endian 32-bit value from a wire buffer.
  * @return The value in host order.
  * @param  p: four bytes, most significant first
  *
  * Written out byte by byte rather than casting to a uint32_t* and calling
  * ntohl(). The cast would assume the buffer is 4-byte aligned, which nothing
  * guarantees for an offset into a received packet, and an unaligned word load
  * is a fault on this core when the compiler does not know to split it.
  */
static uint32_t ntp_be32(const uint8_t *p)
{
    return (((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) |
            ((uint32_t)p[2] << 8)  |  (uint32_t)p[3]);
}

/**
  * @brief  Reads the local time base as milliseconds plus microseconds.
  * @return None
  * @param  tick: receives HAL_GetTick()
  * @param  cnt: receives TIM6->CNT, 0..999 microseconds inside that millisecond
  *
  * WHERE THE MICROSECONDS COME FROM. HAL_InitTick() in
  * stm32h7xx_hal_timebase_tim.c configures TIM6 with a 1 MHz counter clock and
  * Period = 999, so its counter IS a microsecond counter that rolls over
  * exactly when the millisecond tick increments. The sub-millisecond digits are
  * therefore measured, not padded - a timestamp printed with six decimal places
  * has six meaningful ones.
  *
  * THE RETRY LOOP IS NOT OPTIONAL. Reading the tick and the counter takes two
  * separate loads, and the millisecond can roll over between them. Without the
  * loop, a read straddling that boundary pairs the OLD millisecond with the NEW
  * counter and reports a time up to a millisecond in the past - once every
  * thousand reads or so, which is frequent enough to see and rare enough to be
  * dismissed as jitter. Re-reading the tick and repeating while it changed is
  * the standard fix and costs nothing when there is no rollover.
  */
static void ntp_read_local(uint32_t *tick, uint32_t *cnt)
{
    uint32_t t1;
    uint32_t t2;
    uint32_t c;

    do
    {
        t1 = HAL_GetTick();
        c  = TIM6->CNT;
        t2 = HAL_GetTick();
    } while (t1 != t2);

    *tick = t1;
    *cnt  = c;
}

/**
  * @brief  Fills a 48-byte SNTP client request.
  * @return None
  * @param  pkt: at least NTP_PACKET_LEN bytes
  *
  * Everything except the first byte is zero. A client request carries no
  * information the server needs; the reply is what matters.
  */
static void ntp_build_request(uint8_t *pkt)
{
    memset(pkt, 0, (size_t)NTP_PACKET_LEN);
    pkt[NTP_OFF_LI_VN_MODE] = NTP_LI_VN_MODE_CLIENT;
}

/**
  * @brief  Validates a reply and extracts its transmit timestamp.
  * @return 0 on success, -1 if the packet is not a usable server reply.
  * @param  pkt: received bytes
  * @param  len: how many were received
  * @param  epoch_us: receives Unix microseconds
  *
  * THREE THINGS ARE CHECKED, and each of them has been a real bug somewhere:
  *
  *   1. The length. A short read would otherwise index past the buffer.
  *   2. The mode field. Anything that is not a server reply - a stray broadcast,
  *      our own request looped back - would otherwise be read as a timestamp.
  *   3. Stratum 0 and the "unsynchronised" leap indicator. A server that is
  *      itself unsynchronised sends a well-formed packet carrying a meaningless
  *      time. Accepting it looks exactly like a successful sync and would step
  *      the local clock to nonsense.
  */
static int32_t ntp_parse_reply(const uint8_t *pkt, uint32_t len,
                               uint64_t *epoch_us)
{
    int32_t status = -1;

    if (len < NTP_PACKET_LEN)
    {
        /* Truncated - cannot contain a transmit timestamp. */
    }
    else if ((pkt[NTP_OFF_LI_VN_MODE] & NTP_MODE_MASK) != NTP_MODE_SERVER)
    {
        /* Not a server reply. */
    }
    else if ((pkt[NTP_OFF_LI_VN_MODE] & NTP_LI_MASK) == NTP_LI_UNSYNC)
    {
        /* The server is telling us its own clock is not synchronised. */
    }
    else if (pkt[NTP_OFF_STRATUM] == 0U)
    {
        /* Stratum 0 is a "kiss-o'-death" packet, not a time source. */
    }
    else
    {
        uint32_t sec  = ntp_be32(&pkt[NTP_OFF_TX_SEC]);
        uint32_t frac = ntp_be32(&pkt[NTP_OFF_TX_FRAC]);

        if (sec < (uint32_t)NTP_UNIX_EPOCH_DELTA)
        {
            /* Before 1970. Either era 1 after the 2036 NTP rollover, or a
               server with no clock at all. Refused rather than wrapped into a
               plausible-looking date. */
        }
        else
        {
            /* The fraction is a 32-bit binary fraction of a second. Multiplying
               by 1000000 before shifting down 32 keeps the arithmetic in
               integers and cannot overflow: frac is at most 2^32-1, so the
               product is under 4.3e15 and fits in a uint64 with room to spare.
               No floating point is involved, so nothing is rounded away - which
               matters when six decimal places are going to be printed. */
            uint64_t us = (uint64_t)(sec - (uint32_t)NTP_UNIX_EPOCH_DELTA)
                          * 1000000ULL;

            us += ((uint64_t)frac * 1000000ULL) >> 32;

            *epoch_us = us;
            status = 0;
        }
    }

    return status;
}

/**
  * @brief  Moves the anchor to a newly received server time.
  * @return None
  * @param  server_ms: server epoch at its transmit instant
  * @param  tick_at_rx: HAL_GetTick() when the reply arrived
  * @param  rtt_ms: measured round trip
  *
  * HALF THE ROUND TRIP IS ADDED. The server stamped the packet somewhere
  * between our send and our receive; with a symmetric path the best estimate of
  * "server time now" is its timestamp plus half the round trip. On a LAN the
  * round trip is a millisecond or two, so this correction is small - but
  * omitting it biases every sync late by that amount, consistently, which is
  * exactly the kind of error that looks like a working clock.
  */
#if NTP_CLIENT_ENABLE
static void ntp_apply_sync(uint64_t server_us, uint32_t tick_at_rx,
                           uint32_t cnt_at_rx, uint32_t rtt_ms)
{
    uint64_t corrected = server_us + ((uint64_t)rtt_ms * 500ULL); /* rtt/2 in us */
    uint32_t primask;
    uint64_t before    = 0U;
    uint8_t  had_sync;

    primask  = ntp_lock();
    had_sync = Synced;
    if (had_sync != 0U)
    {
        /* What the OLD anchor would have reported at this very instant. That is
           what the new value has to be compared against to measure drift; the
           anchor itself is a different moment in time and comparing to it would
           report the poll interval instead. */
        int64_t elapsed = ((int64_t)(uint32_t)(tick_at_rx - Tick_at_sync)
                           * 1000LL)
                        + ((int64_t)cnt_at_rx - (int64_t)Cnt_at_sync);

        before = Epoch_us_at_sync + (uint64_t)elapsed;
    }
    else
    {
        /* First sync - there is no previous estimate to compare against. */
    }

    Epoch_us_at_sync = corrected;
    Tick_at_sync     = tick_at_rx;
    Cnt_at_sync      = cnt_at_rx;
    Synced           = 1U;
    ntp_unlock(primask);

    ntp_syncs++;
    ntp_last_rtt_ms = rtt_ms;

    if (had_sync != 0U)
    {
        ntp_last_offset_us = (int32_t)((int64_t)corrected - (int64_t)before);
    }
    else
    {
        ntp_last_offset_us = 0;
    }
}

/**
  * @brief  Sends one request and waits for the reply.
  * @return 0 if the clock was synchronised, -1 otherwise.
  * @param  None
  *
  * A socket is opened and closed per poll. At one poll per second the cost is
  * irrelevant, and it means a socket cannot be left half-open across a link
  * bounce or a DHCP address change.
  */
static int32_t ntp_poll_once(void)
{
    int32_t            status = -1;
    int                sock;
    struct sockaddr_in server;
    uint8_t            pkt[NTP_PACKET_LEN];
    ip4_addr_t         addr;

#if NTP_SERVER_USE_MDNS
    /* SAME MACHINE, SAME ADDRESS.  10-09-2026.
       The i.MX8 serves the WSS stream and NTP, so resolving it twice by two
       mechanisms would be two chances to disagree. Taking the address the
       resolver already published means one name governs both, and the failure
       that cost the epoch clock on 28-08-2026 - the stream literal updated, the
       NTP literal left behind - cannot recur.

       A poll before the first resolution is simply skipped and counted as a
       timeout. That is the correct outcome: there is no address yet, so there
       is nothing to send to, and the clock keeps free-running on the TIM6
       anchor exactly as it does when the server is unreachable. */
    if (mdns_service_get_address(&addr) != 0)
    {
        /* Not resolved yet, or resolution has failed. Counted as a timeout and
           skipped - there is no address to send to. The clock keeps
           free-running on the TIM6 anchor, exactly as when the server is
           unreachable. */
        ntp_timeouts++;
        return -1;
    }
    else
    {
        /* Address available. */
    }
#else
    if (ip4addr_aton(NTP_SERVER_HOST, &addr) == 0)
    {
        /* The literal in the header is malformed. Nothing to retry. */
        return -1;
    }
    else
    {
        /* Address parsed. */
    }
#endif

    sock = lwip_socket(AF_INET, SOCK_DGRAM, 0);
    if (sock < 0)
    {
        return -1;
    }
    else
    {
        /* Socket open. */
    }

    memset(&server, 0, sizeof(server));
    server.sin_family      = AF_INET;
    server.sin_port        = lwip_htons((uint16_t)NTP_SERVER_PORT);
    server.sin_addr.s_addr = addr.addr;

    ntp_build_request(pkt);
    ntp_polls++;

    {
        uint32_t t_send = HAL_GetTick();

        if (lwip_sendto(sock, pkt, (size_t)NTP_PACKET_LEN, 0,
                        (struct sockaddr *)&server, sizeof(server)) < 0)
        {
            /* Send failed - no route, or the interface is down. */
        }
        else
        {
            /* WAIT WITH select(), NOT SO_RCVTIMEO - see the file header. */
            fd_set         rd;
            struct timeval tv;
            int            ready;

            FD_ZERO(&rd);
            FD_SET(sock, &rd);
            tv.tv_sec  = (time_t)(NTP_RESPONSE_TIMEOUT_MS / 1000U);
            tv.tv_usec = (long)((NTP_RESPONSE_TIMEOUT_MS % 1000U) * 1000U);

            ready = lwip_select(sock + 1, &rd, NULL, NULL, &tv);

            if (ready <= 0)
            {
                ntp_timeouts++;
            }
            else
            {
                struct sockaddr_in from;
                socklen_t          from_len = sizeof(from);
                int                got;

                got = lwip_recvfrom(sock, pkt, (size_t)NTP_PACKET_LEN, 0,
                                    (struct sockaddr *)&from, &from_len);

                if (got <= 0)
                {
                    ntp_bad_packets++;
                }
                else
                {
                    uint32_t t_recv;
                    uint32_t c_recv;
                    uint64_t server_us;

                    /* Stamped immediately, before parsing, so the parse time is
                       not charged to the transit correction. */
                    ntp_read_local(&t_recv, &c_recv);

                    if (ntp_parse_reply(pkt, (uint32_t)got, &server_us) != 0)
                    {
                        ntp_bad_packets++;
                    }
                    else
                    {
                        ntp_replies++;
                        ntp_apply_sync(server_us, t_recv, c_recv,
                                       t_recv - t_send);
                        status = 0;
                    }
                }
            }
        }
    }

    lwip_close(sock);

    return status;
}

/**
  * @brief  Sends the current epoch to every dispatch UART.
  * @return None
  * @param  None
  *
  * UNTAGGED, via uart_dispatch_send(), so these lines carry
  * UART_DISPATCH_SEQ_NONE and can never satisfy a PE9 scope measurement. That
  * matters: without the sentinel these completions would have been tagged
  * sequence 0, which is a real sequence_id in the JSON stream.
  */
#if (NTP_CLIENT_ENABLE && (NTP_PRINT_INTERVAL_MS > 0))
static void ntp_print_epoch(void)
{
#if NTP_PRINT_TO_UARTS
    static const uint8_t selectors[4] =
    {
        UART_SELECTOR_USART1, UART_SELECTOR_USART2,
        UART_SELECTOR_UART4,  UART_SELECTOR_UART5
    };

    char    stamp[32];
    int32_t sn = ntp_format_epoch(stamp, (uint32_t)sizeof(stamp));

    if (sn <= 0)
    {
        /* Not synchronised yet - nothing truthful to print. */
    }
    else
    {
        char    line[48];
        int     n;
        uint8_t i;

        n = snprintf(line, sizeof(line), NTP_PRINT_PREFIX "%s\r\n", stamp);

        if ((n > 0) && ((size_t)n < sizeof(line)))
        {
            for (i = 0U; i < 4U; i++)
            {
                (void)uart_dispatch_send(selectors[i], (const uint8_t *)line,
                                         (size_t)n, NULL);
            }
        }
        else
        {
            /* Formatting failed or would have truncated - print nothing rather
               than a partial timestamp that looks real. */
        }
    }
#else
    /* Sending to the UARTs is disabled; the formatting above is skipped. */
#endif
}
#endif /* NTP_PRINT_INTERVAL_MS > 0 - otherwise nothing ever calls this */

/**
  * @brief  The NTP task body. Never returns.
  * @return None
  * @param  argument: unused
  *
  * PACED BY ABSOLUTE DEADLINES, not by sleeping for the interval. The loop
  * wakes every 50 ms and acts when a deadline has passed, so the poll period
  * does not drift by however long each poll takes - sleeping for
  * NTP_POLL_INTERVAL_MS after each poll would make the true period the interval
  * PLUS the round trip, every time.
  *
  * Two deadlines rather than osDelayUntil, because the poll and the print
  * intervals are independent and either can be the next one due.
  *
  * The comparison is written (int32_t)(now - deadline) >= 0 rather than
  * now >= deadline, so it stays correct when the tick counter wraps.
  */
static void ntp_task(void *argument)
{
    uint32_t next_poll;
#if (NTP_PRINT_INTERVAL_MS > 0)
    uint32_t next_print;
#endif

    (void)argument;

    next_poll = osKernelGetTickCount();
#if (NTP_PRINT_INTERVAL_MS > 0)
    next_print = next_poll;
#endif

    for (;;)
    {
        uint32_t now = osKernelGetTickCount();

        if ((int32_t)(now - next_poll) >= 0)
        {
            (void)ntp_poll_once();
            next_poll = now + (uint32_t)NTP_POLL_INTERVAL_MS;
        }
        else
        {
            /* Not yet time to poll. */
        }

#if (NTP_PRINT_INTERVAL_MS > 0)
        now = osKernelGetTickCount();
        if ((int32_t)(now - next_print) >= 0)
        {
            ntp_print_epoch();
            next_print = now + (uint32_t)NTP_PRINT_INTERVAL_MS;
        }
        else
        {
            /* Not yet time to print. */
        }
#endif

        /* Wake often enough to serve whichever deadline comes first, without
           spinning. 50 ms is well below both intervals and costs nothing. */
        osDelay(50U);
    }
}
#endif /* NTP_CLIENT_ENABLE - task, poll and sync are all dead without it */

/* Exported functions --------------------------------------------------------*/

void ntp_client_init(void)
{
    uint32_t primask = ntp_lock();

    Epoch_us_at_sync = 0U;
    Tick_at_sync     = 0U;
    Cnt_at_sync      = 0U;
    Synced           = 0U;
    ntp_unlock(primask);

    ntp_polls          = 0U;
    ntp_replies        = 0U;
    ntp_timeouts       = 0U;
    ntp_bad_packets    = 0U;
    ntp_syncs          = 0U;
    ntp_last_rtt_ms    = 0U;
    ntp_last_offset_us = 0;

#if NTP_CLIENT_ENABLE
    ntp_task_handle = osThreadNew(ntp_task, NULL, &ntp_task_attributes);

    if (ntp_task_handle == NULL)
    {
        printf("ntp: *** task creation FAILED - no epoch clock ***\r\n");
    }
    else
    {
        /* NAMES THE ADDRESS SOURCE ACTUALLY IN USE. Printing NTP_SERVER_HOST
           unconditionally would report the literal even when mDNS supplies the
           address - which is precisely the confusion the 10-09-2026 log caused,
           where the banner said 192.168.0.61 while the resolver was reporting
           192.168.40.135. A banner that can disagree with the code is worse
           than no banner. */
#if NTP_SERVER_USE_MDNS
        printf("ntp: polling %s (via mDNS) port %u every %lu ms\r\n",
               MDNS_TARGET_HOSTNAME, (unsigned)NTP_SERVER_PORT,
               (unsigned long)NTP_POLL_INTERVAL_MS);
#else
        printf("ntp: polling %s:%u every %lu ms\r\n",
               NTP_SERVER_HOST, (unsigned)NTP_SERVER_PORT,
               (unsigned long)NTP_POLL_INTERVAL_MS);
#endif
    }
#else
    /* Bisect mode - see NTP_CLIENT_ENABLE. No task, no UDP socket, no sync, so
       the epoch column is absent from the UART lines by design. */
    ntp_task_handle = NULL;
    printf("ntp: DISABLED (NTP_CLIENT_ENABLE = 0) - no epoch column on the "
           "UART lines\r\n");
#endif
}

uint8_t ntp_get_epoch_us(uint64_t *out_us)
{
    uint8_t  ok = 0U;
    uint32_t primask;
    uint32_t now_tick;
    uint32_t now_cnt;

    if (out_us == NULL)
    {
        return 0U;
    }
    else
    {
        /* Normal case. */
    }

    /* Sampled BEFORE taking the lock, so interrupts are masked for the
       arithmetic only and not for the retry loop inside ntp_read_local(). */
    ntp_read_local(&now_tick, &now_cnt);

    primask = ntp_lock();
    if (Synced != 0U)
    {
        /* THE WHOLE CLOCK.

           The millisecond term uses UNSIGNED subtraction, so a 49.7-day
           HAL_GetTick() wrap between the anchor and now still gives the right
           elapsed count. The microsecond term is SIGNED and may be negative -
           when now_cnt is below Cnt_at_sync the millisecond term has already
           counted that millisecond, and subtracting the difference is exactly
           right. Anchor at tick 5 / cnt 900 read at tick 6 / cnt 100 gives
           1000 - 800 = 200 us, which is correct. */
        int64_t elapsed = ((int64_t)(uint32_t)(now_tick - Tick_at_sync) * 1000LL)
                        + ((int64_t)now_cnt - (int64_t)Cnt_at_sync);

        *out_us = Epoch_us_at_sync + (uint64_t)elapsed;
        ok = 1U;
    }
    else
    {
        /* Never synchronised. out_us is left untouched. */
    }
    ntp_unlock(primask);

    return ok;
}

int32_t ntp_format_epoch(char *buf, uint32_t max)
{
    uint64_t now_us;
    int      n;

    if ((buf == NULL) || (max < 2U))
    {
        return -1;
    }
    else
    {
        /* Normal case. */
    }

    if (ntp_get_epoch_us(&now_us) == 0U)
    {
        buf[0] = '\0';
        return -1;
    }
    else
    {
        /* Synchronised - format it. */
    }

    {
        uint32_t sec = (uint32_t)(now_us / 1000000ULL);
        uint32_t us  = (uint32_t)(now_us % 1000000ULL);

        /* SPLIT INTO TWO uint32_t VALUES rather than printing a uint64 with
           "%llu". This build uses nano.specs, whose printf has already turned
           out in this project not to support every specifier that looks
           standard, and a silently mis-formatted timestamp is worse than a
           compile error. Two 32-bit values stay correct until 2106.

           "%06lu" pads the fraction, so 1787909495.021000 keeps its leading
           zero instead of collapsing to .21. */
        n = snprintf(buf, (size_t)max, "%lu.%06lu",
                     (unsigned long)sec, (unsigned long)us);
    }

    if ((n <= 0) || ((uint32_t)n >= max))
    {
        buf[0] = '\0';
        return -1;
    }
    else
    {
        /* Fitted. */
    }

    return (int32_t)n;
}

uint8_t ntp_is_synced(void)
{
    return Synced;
}

int ntp_selftest(void)
{
    int      result = 0;
    uint8_t  pkt[NTP_PACKET_LEN];
    uint64_t us;

    /* Saved and restored, so running the test cannot disturb a clock that is
       already synchronised. */
    uint32_t primask   = ntp_lock();
    uint64_t keep_anch = Epoch_us_at_sync;
    uint32_t keep_tick = Tick_at_sync;
    uint32_t keep_cnt  = Cnt_at_sync;
    uint8_t  keep_sync = Synced;
    ntp_unlock(primask);

    /* ---- 1. a client request is well formed --------------------------- */
    memset(pkt, 0xAA, sizeof(pkt));
    ntp_build_request(pkt);
    if ((pkt[NTP_OFF_LI_VN_MODE] != NTP_LI_VN_MODE_CLIENT) ||
        (pkt[1] != 0U) || (pkt[NTP_PACKET_LEN - 1U] != 0U))
    {
        result = 1;
    }

    /* ---- 2. a known reply decodes to the expected epoch ----------------
       NTP seconds 0x83AA7E80 is 1970-01-01 00:00:00 UTC exactly - the standard
       worked example. With a zero fraction it must decode to 0 ms. If the
       epoch constant or the byte order were wrong this is the check that says
       so, rather than a date that merely looks odd. */
    if (result == 0)
    {
        memset(pkt, 0, sizeof(pkt));
        pkt[NTP_OFF_LI_VN_MODE] = 0x24U;  /* LI 0, VN 4, mode 4 = server */
        pkt[NTP_OFF_STRATUM]    = 2U;
        pkt[NTP_OFF_TX_SEC + 0U] = 0x83U;
        pkt[NTP_OFF_TX_SEC + 1U] = 0xAAU;
        pkt[NTP_OFF_TX_SEC + 2U] = 0x7EU;
        pkt[NTP_OFF_TX_SEC + 3U] = 0x80U;

        if ((ntp_parse_reply(pkt, NTP_PACKET_LEN, &us) != 0) || (us != 0ULL))
        {
            result = 2;
        }
    }

    /* ---- 3. the fraction field becomes MICROseconds --------------------
       0x80000000 is exactly half a second, so 500000 us. Checking the exact
       value rather than a range is what catches a shift or multiplier that is
       out by a factor of 1000 - an error that still produces a well-formed
       timestamp, just one whose fractional digits are nonsense. */
    if (result == 0)
    {
        pkt[NTP_OFF_TX_FRAC + 0U] = 0x80U;

        if ((ntp_parse_reply(pkt, NTP_PACKET_LEN, &us) != 0) ||
            (us != 500000ULL))
        {
            result = 3;
        }
    }

    /* ---- 4. malformed replies are refused ------------------------------
       Four ways a packet can be unusable, each checked separately. Every one of
       them would otherwise decode to a well-formed but meaningless time and
       step the clock to it. */
    if (result == 0)
    {
        uint8_t bad[NTP_PACKET_LEN];

        /* a. truncated */
        memcpy(bad, pkt, sizeof(bad));
        if (ntp_parse_reply(bad, 47U, &us) == 0)
        {
            result = 4;
        }
        else
        {
            /* b. mode 3 - our own request, not a reply */
            memcpy(bad, pkt, sizeof(bad));
            bad[NTP_OFF_LI_VN_MODE] = 0x23U;
            if (ntp_parse_reply(bad, NTP_PACKET_LEN, &us) == 0)
            {
                result = 4;
            }
            else
            {
                /* c. leap indicator 3 - the server's own clock is not set */
                memcpy(bad, pkt, sizeof(bad));
                bad[NTP_OFF_LI_VN_MODE] = 0xE4U;
                if (ntp_parse_reply(bad, NTP_PACKET_LEN, &us) == 0)
                {
                    result = 4;
                }
                else
                {
                    /* d. stratum 0 - kiss-o'-death, not a time source */
                    memcpy(bad, pkt, sizeof(bad));
                    bad[NTP_OFF_STRATUM] = 0U;
                    if (ntp_parse_reply(bad, NTP_PACKET_LEN, &us) == 0)
                    {
                        result = 4;
                    }
                    else
                    {
                        /* All four rejected, as they must be. */
                    }
                }
            }
        }
    }

    /* ---- 5. the anchor advances with the tick --------------------------
       The point of the whole module: with no further NTP traffic the reported
       time must still move. Anchored 10 s in the "past" of the current tick, a
       read must come back about 10 s later than the anchor. */
    if (result == 0)
    {
        uint64_t got;
        uint32_t now_tick;
        uint32_t now_cnt;

        ntp_read_local(&now_tick, &now_cnt);

        primask          = ntp_lock();
        Epoch_us_at_sync = 1000000000000000ULL;  /* 2001-09-09, arbitrary */
        Tick_at_sync     = now_tick - 10000U;    /* anchored 10 s ago     */
        Cnt_at_sync      = now_cnt;              /* same sub-ms phase     */
        Synced           = 1U;
        ntp_unlock(primask);

        /* Anchored exactly 10 s in the past with the same sub-millisecond
           phase, so a read must come back 10 s later give or take the handful
           of microseconds this test itself takes. A window of 10.000 to 10.010
           s catches a clock that does not advance at all, and one that advances
           by the wrong scale, without being so tight that ordinary preemption
           between the two reads fails it. */
        if ((ntp_get_epoch_us(&got) == 0U) ||
            (got < (1000000000000000ULL + 10000000ULL)) ||
            (got > (1000000000000000ULL + 10010000ULL)))
        {
            result = 5;
        }
        else
        {
            /* Advanced by 10 s. */
        }
    }

    primask          = ntp_lock();
    Epoch_us_at_sync = keep_anch;
    Tick_at_sync     = keep_tick;
    Cnt_at_sync      = keep_cnt;
    Synced           = keep_sync;
    ntp_unlock(primask);

    return result;
}
