/**
  ******************************************************************************
  * @file    ntp_client.h
  * @brief   SNTP client and free-running local epoch clock
  * @version 1.0 - 28-08-2026
  *
  * Polls the i.MX8's NTP server over UDP at a configurable interval, and
  * maintains a local epoch clock that keeps running between polls.
  *
  * ===========================================================================
  * THE CENTRAL DESIGN DECISION: NOTHING IS INCREMENTED
  * ===========================================================================
  * The obvious implementation is a 1 Hz timer that does "epoch_seconds++". It
  * is also the wrong one, for three separate reasons:
  *
  *   1. It loses time whenever the tick is late. Under a TLS handshake or a
  *      burst of UART interrupts a software timer can slip by tens of
  *      milliseconds, and an incrementing counter never gets that back - the
  *      error accumulates for as long as the board runs.
  *   2. It cannot express sub-second time without a faster timer and a bigger
  *      error.
  *   3. It stops being correct the moment a tick is missed entirely.
  *
  * So this module stores an ANCHOR instead:
  *
  *     Epoch_us_at_sync   the server's epoch, in MICROseconds, at the last sync
  *     Tick_at_sync       HAL_GetTick() at that same instant
  *     Cnt_at_sync        TIM6->CNT at that same instant, 0..999 us
  *
  * and computes the answer on demand:
  *
  *     now_us = Epoch_us_at_sync
  *            + (HAL_GetTick() - Tick_at_sync) * 1000
  *            + (TIM6->CNT     - Cnt_at_sync)
  *
  * MICROSECOND RESOLUTION COMES FROM TIM6 ITSELF. HAL_InitTick() configures it
  * with a 1 MHz counter clock and Period = 999, so its counter IS a microsecond
  * counter that rolls over exactly as the millisecond tick increments. The six
  * printed decimal places are measured digits, not zero padding.
  *
  * Requirements 4 and 8 - "increment continuously" and "keep advancing with no
  * NTP response" - are then satisfied by construction rather than by a task
  * that has to keep running. There is no counter to fall behind, no drift from
  * missed ticks, and the clock advances correctly even if the network is dead
  * and the NTP task never runs again.
  *
  * ===========================================================================
  * WHY HAL_GetTick() AND NOT A NEW TIMER
  * ===========================================================================
  * NO .ioc CHANGE IS REQUIRED FOR THIS MODULE, and that is deliberate.
  *
  * This project already runs TIM6 at a 1 MHz counter clock producing a 1 ms
  * tick - see stm32h7xx_hal_timebase_tim.c. CubeMX put the HAL timebase there
  * because FreeRTOS took SysTick. That interrupt is already in the system, is
  * already the highest-frequency periodic event, and reading its counter is a
  * single volatile load.
  *
  * Adding a second hardware timer would mean another peripheral, another NVIC
  * entry, another ISR competing with the Ethernet and UART interrupts, and a
  * fresh chance of a peripheral conflict - to produce a number the board is
  * already computing.
  *
  * ACCURACY. The tick derives from the HSE, so roughly +/-50 ppm. Over the
  * default 1000 ms poll interval that is about 50 microseconds of drift, four
  * orders of magnitude below the millisecond resolution of the timestamps being
  * received. The polls are correcting the SERVER's clock relative to ours, not
  * compensating for a bad local oscillator.
  *
  * WRAPAROUND. HAL_GetTick() is a uint32_t of milliseconds and wraps every 49.7
  * days. The subtraction above is unsigned, so a wrap between anchor and read
  * still yields the correct elapsed value. No special case is needed and none
  * is written.
  *
  * ===========================================================================
  * WHY A TASK AND NOT A FreeRTOS SOFTWARE TIMER
  * ===========================================================================
  * The poll does blocking network I/O: sendto, then select() for up to
  * NTP_RESPONSE_TIMEOUT_MS. FreeRTOS software timer callbacks all run in the
  * single timer service task, so blocking inside one stalls EVERY other
  * software timer in the system - here that includes the DHCP fine timer and
  * the link check. A dedicated task with its own stack is the only correct
  * home for a call that can block.
  *
  * The timer-versus-task question therefore has different answers for the two
  * halves: the CLOCK uses the existing hardware tick, the POLL uses a task.
  ******************************************************************************
  */

#ifndef __NTP_CLIENT_H__
#define __NTP_CLIENT_H__

#include <stdint.h>

/* STREAM_SERVER_HOST - NTP_SERVER_HOST defaults to it, because the i.MX8 hosts
   both services and two separate literals drifted apart once already. See the
   note on NTP_SERVER_HOST below. No include cycle: stream_client.h does not
   include this header. */
#include "stream_client.h"

/* ---------------------------------------------------------------------------
 * Configuration
 * ------------------------------------------------------------------------- */

/**
  * @brief  1 creates the NTP task, 0 leaves the module compiled but idle.
  *
  * A BISECT SWITCH, added 28-08-2026. On 28-08-2026 a
  * "pbuf_free: p->ref > 0" assertion appeared in a long run, at roughly 1 MB
  * received. That assertion is lwIP reporting a pbuf freed twice, and this
  * module is the newest thing on the network path - it opens and closes a UDP
  * socket once per second, so it is a fair suspect and must be eliminated or
  * confirmed rather than argued about.
  *
  * HOW TO USE IT. Set to 0, rebuild, and run for at least as long as the run
  * that produced the assertion - past 1 MB received, which at ~4.4 kB/s is
  * about four minutes.
  *
  *   assertion still appears  -> not this module; it predates the NTP client
  *                               and was simply never run long enough to see
  *   assertion gone           -> this module is implicated, and the socket
  *                               open/close cycle is where to look first
  *
  * With this at 0 the epoch column disappears from the UART lines, because the
  * clock never synchronises. That is the expected and correct behaviour, not a
  * second fault.
  */
#ifndef NTP_CLIENT_ENABLE
#define NTP_CLIENT_ENABLE           1
#endif

/* Where the NTP server lives. The i.MX8 hosts both the WSS server and NTP, so
   this is normally the same address as STREAM_SERVER_HOST - kept separate so
   the two can be pointed at different machines without touching the code. */
#ifndef NTP_SERVER_HOST
#define NTP_SERVER_HOST             STREAM_SERVER_HOST
#endif

/**
  * @brief  1 takes the NTP server address from mDNS, 0 from NTP_SERVER_HOST.
  *
  * ANSWERS THE "SHOULD NTP SHARE THE mDNS ADDRESS" QUESTION WITH A SWITCH
  * RATHER THAN A DECISION, because both answers are legitimate:
  *
  *   1  the i.MX8 serves the stream AND NTP, so one name governs both. This is
  *      the default because it is true of this bench and because two
  *      independently configured addresses for one machine is precisely how
  *      the epoch clock was lost on 28-08-2026 - the stream literal was
  *      updated for the new subnet, this one was not, and the failure was
  *      silent.
  *
  *   0  NTP lives somewhere else - a gateway, a dedicated appliance, an
  *      upstream pool. NTP_SERVER_HOST is then used and is independent of
  *      whatever mDNS resolves.
  *
  * Defaults to STREAM_SERVER_USE_MDNS so the two move together unless
  * deliberately separated: using mDNS for the stream while leaving NTP on a
  * literal would reintroduce exactly the drift this is meant to prevent.
  */
#ifndef NTP_SERVER_USE_MDNS
#define NTP_SERVER_USE_MDNS         STREAM_SERVER_USE_MDNS
#endif

#ifndef NTP_SERVER_PORT
#define NTP_SERVER_PORT             123U
#endif

/* HOW OFTEN TO RESYNCHRONISE. The poll cadence is this macro and nothing else;
   no application logic changes when it moves.

   RAISED FROM 1000 TO 16000 ON 28-08-2026, for three reasons.

   1. ACCURACY DOES NOT NEED IT. The local clock is driven by the HSE at roughly
      50 ppm, so it drifts about 50 us per second. Even at a 16 s interval the
      worst-case drift between polls is under a millisecond - far below the
      transit uncertainty of the reply itself. Polling every second was buying
      nothing measurable.

   2. IT IS WHAT NTP ITSELF DOES. RFC 4330 sets a MINIMUM poll interval of 15
      seconds for SNTP clients and explicitly warns against hammering a server
      more often. One second is 15x over that floor, and against a small i.MX8
      that is a real load for no benefit.

   3. IT NARROWS A SUSPECT. Each poll opens and closes a UDP socket. A
      "pbuf_free: p->ref > 0" assertion appeared on 28-08-2026, and fewer socket
      cycles means fewer chances to hit whatever causes it. This is not a fix -
      see NTP_CLIENT_ENABLE for how to actually establish whether this module is
      responsible - but it reduces the exposure while that is settled.

   The clock keeps running between polls regardless of this value; see the
   anchor design at the top of this file. Nothing about the epoch column stops
   updating when this is raised. */
#ifndef NTP_POLL_INTERVAL_MS
#define NTP_POLL_INTERVAL_MS        1000U//16000U
#endif

/* How long to wait for a reply before giving up on one poll. Short, because a
   missed poll costs nothing: the local clock keeps running and the next poll is
   NTP_POLL_INTERVAL_MS away. */
#ifndef NTP_RESPONSE_TIMEOUT_MS
#define NTP_RESPONSE_TIMEOUT_MS     500U
#endif

/* How often the standalone epoch line is printed. Set to 0 to disable it.

   OFF BY DEFAULT, because the epoch is now appended to every JSON data line
   instead - see STREAM_JSON_APPEND_EPOCH in stream_client.h. A separate
   "EPOCH ..." line would interleave with those and give two different
   timestamps in the same capture with no way to pair them up. Turn it back on
   only to watch the clock with no stream running. */
#ifndef NTP_PRINT_INTERVAL_MS
#define NTP_PRINT_INTERVAL_MS       0U
#endif

/* 1 sends the standalone epoch line to all four dispatch UARTs, 0 to none.
   Only has any effect when NTP_PRINT_INTERVAL_MS is non-zero. */
#ifndef NTP_PRINT_TO_UARTS
#define NTP_PRINT_TO_UARTS          0
#endif

/* Marker at the start of every epoch line, so it is separable from the JSON
   field values sharing the same UART. */
#ifndef NTP_PRINT_PREFIX
#define NTP_PRINT_PREFIX            "EPOCH "
#endif

#ifndef NTP_TASK_STACK_BYTES
#define NTP_TASK_STACK_BYTES        2048U
#endif

/* Seconds between the NTP epoch (1900-01-01) and the Unix epoch (1970-01-01).
   Seventy years including seventeen leap days. */
#define NTP_UNIX_EPOCH_DELTA        2208988800UL

/* ---------------------------------------------------------------------------
 * Counters - read in the debugger
 * ------------------------------------------------------------------------- */

extern volatile uint32_t ntp_polls;        /**< requests sent               */
extern volatile uint32_t ntp_replies;      /**< valid replies accepted      */
extern volatile uint32_t ntp_timeouts;     /**< no reply within the timeout */
extern volatile uint32_t ntp_bad_packets;  /**< reply rejected as malformed */
extern volatile uint32_t ntp_syncs;        /**< times the anchor was moved  */

/** Round-trip time of the last accepted reply, milliseconds. Half of it is
    added to the server's timestamp as the transit correction. A figure much
    above a few ms on a LAN means the correction is guesswork. */
extern volatile uint32_t ntp_last_rtt_ms;

/** How far the local clock had drifted from the server at the last sync,
    MICROseconds, signed. Small and roughly constant is healthy. A value that
    grows every poll means the local tick is wrong, not the server. At the
    board's ~50 ppm this should sit in the tens of microseconds over a 1 s
    interval; hundreds of milliseconds means something else is wrong. */
extern volatile int32_t  ntp_last_offset_us;

/* ---------------------------------------------------------------------------
 * API
 * ------------------------------------------------------------------------- */

/**
  * @brief  Creates the NTP task. Does not block and does not poll.
  * @return None
  * @param  None
  *
  * Call from StartEthIfTask AFTER the interface has an address. Calling it
  * before means the first few polls go out from 0.0.0.0 and fail - harmless,
  * since the task retries, but it fills the counters with noise.
  */
void ntp_client_init(void);

/**
  * @brief  Reads the current epoch time in MICROseconds.
  * @return 1 if the value is valid, 0 if no sync has happened yet.
  * @param  out_us: receives microseconds since 1970-01-01, untouched when the
  *         return is 0
  *
  * THE MICROSECONDS ARE MEASURED, NOT PADDED. TIM6 runs at 1 MHz with
  * Period = 999, so its counter is a microsecond counter that rolls over
  * exactly as the millisecond tick increments. Six printed decimal places
  * therefore carry six meaningful digits.
  *
  * SAFE FROM ANY TASK. The anchor is a 64-bit value plus two 32-bit counters,
  * which cannot be read atomically on this core, so they are read inside a
  * critical section. Not safe from an ISR, and it does not need to be, since
  * nothing in an interrupt wants the wall-clock time.
  *
  * Returns 0 rather than a plausible-looking zero epoch before the first sync.
  * A caller that ignored the return would otherwise print 1970-01-01, and that
  * looks exactly like a working clock.
  */
uint8_t ntp_get_epoch_us(uint64_t *out_us);

/**
  * @brief  Formats the current epoch as "<seconds>.<6 digits>".
  * @return Characters written, or -1 if not synchronised or the buffer is too
  *         small. On -1 the buffer is set to an empty string.
  * @param  buf: destination
  * @param  max: capacity of buf; 24 is comfortable
  *
  * Produces exactly the form used on the UART data lines, for example
  * "1787909495.021000". The fraction is zero-padded to six digits, so a
  * timestamp 21 milliseconds into its second reads .021000 and not .21.
  *
  * Provided here rather than left to each caller so there is ONE definition of
  * the timestamp format. Two callers formatting it separately is how a log ends
  * up with two subtly different time formats in it.
  */
int32_t ntp_format_epoch(char *buf, uint32_t max);

/**
  * @brief  Reports whether the clock has ever been synchronised.
  * @return 1 once a valid reply has been accepted, 0 before that.
  * @param  None
  */
uint8_t ntp_is_synced(void);

/**
  * @brief  Verifies the packet building, parsing and anchor arithmetic.
  * @return 0 if every check passed, otherwise the number of the first failing
  *         check (1..5)
  * @param  None
  *
  * WHY IT MATTERS. Every failure mode here produces a plausible number rather
  * than an obvious fault: a byte-order slip gives a wildly wrong but
  * well-formed date, the wrong epoch constant gives a time exactly 70 years
  * out, and a broken anchor gives a clock that simply does not advance. None
  * of those looks like an error on a terminal.
  *
  * Uses a known-good packet built from a fixed timestamp, so it needs no
  * network and can run before the interface is up.
  */
int ntp_selftest(void);

#endif /* __NTP_CLIENT_H__ */
