/**
  ******************************************************************************
  * @file    scope_trig.c
  * @brief   Oscilloscope timing trigger - implementation
  * @version 1.0 - 26-08-2026
  *
  * See scope_trig.h for what the signal means, where the two edges are set, and
  * why the back-to-back case is handled the way it is. This file is only the
  * mechanism.
  *
  * TWO CONCURRENCY FACTS THAT SHAPE EVERYTHING HERE
  *
  * 1. THE PIN WRITE NEEDS NO GUARD. HAL_GPIO_WritePin() compiles to a single
  *    store to GPIOE->BSRR - set in the low half-word, reset in the high one -
  *    so it is not a read-modify-write and cannot tear against another writer
  *    of the same port. Nothing else in this project drives GPIOE anyway (PE1
  *    is the yellow LED, owned by BSP, and BSP writes it the same way), but the
  *    property is worth stating because it is the reason no critical section
  *    wraps the writes themselves.
  *
  * 2. THE COUNTER DOES. scope_trig_inflight is incremented from task context
  *    (tcpip_thread, or the stream task) and decremented from ISR context
  *    (HAL_UART_TxCpltCallback). "++" and "--" are load-modify-store on
  *    Cortex-M7, so an interrupt landing between the load and the store loses
  *    an update. Every access below is therefore inside a PRIMASK-saved
  *    critical section.
  *
  *    PRIMASK is SAVED AND RESTORED rather than using a bare
  *    __disable_irq()/__enable_irq() pair, because scope_trig_tx_complete()
  *    runs in an ISR and a bare enable would drop the mask early if this were
  *    ever reached with interrupts already off - re-enabling interrupts in the
  *    middle of a caller's own critical section, which is a fault that shows up
  *    somewhere else entirely.
  *
  * The critical sections are a handful of cycles: they mask interrupts for the
  * duration of one increment and one compare, which is far below the jitter
  * already present in the measurement.
  ******************************************************************************
  */

/* Includes ------------------------------------------------------------------*/
#include "scope_trig.h"

#if SCOPE_TRIG_ENABLE

/* Private defines -----------------------------------------------------------*/

/* Active and idle levels, resolved once from SCOPE_TRIG_ACTIVE_LOW so no logic
   below has to care which way round the signal is. */
#if SCOPE_TRIG_ACTIVE_LOW
#define SCOPE_TRIG_LEVEL_ACTIVE   GPIO_PIN_RESET
#define SCOPE_TRIG_LEVEL_IDLE     GPIO_PIN_SET
#else
#define SCOPE_TRIG_LEVEL_ACTIVE   GPIO_PIN_SET
#define SCOPE_TRIG_LEVEL_IDLE     GPIO_PIN_RESET
#endif

#define SCOPE_TRIG_PIN_ACTIVE()   HAL_GPIO_WritePin(SCOPE_TRIG_GPIO_Port,      \
                                                    SCOPE_TRIG_Pin,             \
                                                    SCOPE_TRIG_LEVEL_ACTIVE)

#define SCOPE_TRIG_PIN_IDLE()     HAL_GPIO_WritePin(SCOPE_TRIG_GPIO_Port,      \
                                                    SCOPE_TRIG_Pin,             \
                                                    SCOPE_TRIG_LEVEL_IDLE)

/* Reads the pad back through IDR. Used only by the self-test - reading an
   output pin is what catches a pin left in analogue mode or a missing port
   clock, both of which look exactly like "no traffic" on a scope. */
#define SCOPE_TRIG_PIN_READ()     HAL_GPIO_ReadPin(SCOPE_TRIG_GPIO_Port,       \
                                                   SCOPE_TRIG_Pin)

/* Exported variables --------------------------------------------------------*/

/* In BURST mode this is a genuine count of frames in flight. In PER-FRAME mode
   it only ever holds 0 or 1 and acts as a "a pulse is running" flag - the name
   is kept so the debugger expression is the same in both builds. */
volatile uint32_t scope_trig_inflight;
volatile uint32_t scope_trig_inflight_max;
volatile uint32_t scope_trig_pulses;
volatile uint32_t scope_trig_skipped;
volatile uint32_t scope_trig_underflow;

/* The FROM_ETH counters are defined UNCONDITIONALLY, unlike the tracker itself.
   Twelve bytes of .bss buys two things: a debugger expression on any of them
   resolves in every build rather than only in one mode, and no call site can
   ever reference a symbol that was not emitted - which is precisely the mistake
   that produced the link failure on 27-08-2026. They simply stay at zero when
   the mode is off. */
volatile uint32_t scope_trig_eth_extra;
volatile uint32_t scope_trig_unbound;
volatile uint32_t scope_trig_seq_mismatch;

volatile uint32_t scope_trig_lead_us_last;
volatile uint32_t scope_trig_lead_us_max;
volatile uint32_t scope_trig_span_us_last;
volatile uint32_t scope_trig_span_us_max;
volatile uint32_t scope_trig_lead_over_1ms;
volatile uint8_t  scope_trig_dwt_ok;

/* Cycle counter, used only for the lead/span figures. The pin itself does not
   depend on any of this - a dead DWT costs the numbers, never the trace.

   DWT->LAR is absent from some CMSIS core headers, so it is addressed directly.
   Writing this key unlocks the DWT registers; where the lock is active CYCCNT
   stays at zero even with TRCENA set, and every figure would silently read 0 us
   - a failure that looks exactly like "the processing is instant". That is what
   scope_trig_dwt_ok exists to distinguish. */
#define SCOPE_TRIG_DWT_LAR   (*(volatile uint32_t *)0xE0001FB0U)

static uint32_t CycPerUs;   /* SystemCoreClock / 1e6, 450 on this board */
static uint32_t ArmCyc;     /* CYCCNT at the rising edge                */
static uint32_t BindCyc;    /* CYCCNT when the sequence was bound       */

/**
  * @brief  Converts a cycle delta to microseconds.
  * @return Elapsed microseconds, or 0 if the counter is not running.
  * @param  from: earlier CYCCNT sample
  * @param  to: later CYCCNT sample
  *
  * Unsigned subtraction, so a 32-bit wrap is handled without a special case -
  * at 450 MHz CYCCNT wraps every 9.5 s, far longer than any pulse.
  */
static uint32_t scope_trig_elapsed_us(uint32_t from, uint32_t to)
{
    uint32_t us = 0U;

    if ((scope_trig_dwt_ok != 0U) && (CycPerUs != 0U))
    {
        us = (to - from) / CycPerUs;
    }
    else
    {
        /* Counter never started - leave it at 0, which scope_trig_dwt_ok
           marks as "not measured". */
    }

    return us;
}

/* Private function prototypes -----------------------------------------------*/
static uint32_t scope_trig_lock(void);
static void     scope_trig_unlock(uint32_t primask);

/* Private functions ---------------------------------------------------------*/

/**
  * @brief  Masks interrupts, returning the previous PRIMASK for restoration.
  * @return The PRIMASK value in force before masking.
  * @param  None
  */
static uint32_t scope_trig_lock(void)
{
    uint32_t primask = __get_PRIMASK();

    __disable_irq();

    return primask;
}

/**
  * @brief  Restores a PRIMASK saved by scope_trig_lock().
  * @return None
  * @param  primask: value returned by the matching scope_trig_lock() call
  */
static void scope_trig_unlock(uint32_t primask)
{
    __set_PRIMASK(primask);
}

/* Exported functions --------------------------------------------------------*/

void scope_trig_init(void)
{
    uint32_t primask = scope_trig_lock();

    scope_trig_inflight     = 0U;
    scope_trig_inflight_max = 0U;
    scope_trig_pulses       = 0U;
    scope_trig_skipped      = 0U;
    scope_trig_underflow    = 0U;

    scope_trig_unlock(primask);

    /* Explicit even though MX_GPIO_Init() already left the pin low: with
       SCOPE_TRIG_ACTIVE_LOW == 1 the idle level is HIGH, and the .ioc initial
       level would then be wrong. Setting it here means the idle level always
       matches the mode actually compiled in. */
    SCOPE_TRIG_PIN_IDLE();

#if SCOPE_TRIG_FROM_ETH
    /* ---- cycle counter for the lead/span figures -------------------------
       Started here rather than borrowed from http_server.c's lat_init(), which
       runs later and could be disabled independently. Enabling the DWT twice is
       harmless, so the duplication costs nothing and removes an ordering
       dependency that would otherwise be invisible.

       The pin does NOT depend on any of this: a dead DWT costs the numbers,
       never the trace. */
    CycPerUs = SystemCoreClock / 1000000U;

    CoreDebug->DEMCR    |= CoreDebug_DEMCR_TRCENA_Msk;
    SCOPE_TRIG_DWT_LAR   = 0xC5ACCE55U;
    DWT->CYCCNT          = 0U;
    DWT->CTRL           |= DWT_CTRL_CYCCNTENA_Msk;

    /* PROVE IT ACTUALLY COUNTS. On a part where the DWT lock is active, CYCCNT
       reads 0 for ever even with TRCENA set - and every lead and span would
       then report 0 us, which reads as "instant" rather than "not measured".
       Two reads with work between them is the only way to tell those apart. */
    {
        uint32_t a = DWT->CYCCNT;
        uint32_t b;
        volatile uint32_t spin;

        for (spin = 0U; spin < 32U; spin++)
        {
            /* Deliberately empty - just burning cycles the counter must see. */
        }

        b = DWT->CYCCNT;
        scope_trig_dwt_ok = (uint8_t)((b != a) ? 1U : 0U);
    }
#else
    scope_trig_dwt_ok = 0U;
#endif
}

#if SCOPE_TRIG_FROM_ETH

/* ===========================================================================
 * PER-SEQUENCE TRACKER
 * ===========================================================================
 * Six pieces of state, all touched from both task and ISR context and all
 * therefore only read or written inside the PRIMASK critical section.
 *
 * THE ORDERING THAT MATTERS. Completions can arrive BEFORE the remaining sends
 * are queued: at 2 Mbaud a 20-byte message is out in 100 us, while queuing the
 * other three takes a few. So Done bits are accepted from the moment a sequence
 * is bound, but the pin is not dropped until Committed says the expected set is
 * final. Comparing an incomplete Expect against Done would end the pulse at the
 * first UART to finish and report a latency several times too short - and the
 * result would look entirely plausible.
 * ========================================================================= */
static volatile uint8_t  Armed;      /* a pulse is running (pin ACTIVE)       */
static volatile uint8_t  Bound;      /* a sequence id is attached to it       */
static volatile uint8_t  Committed;  /* every send for it has been queued     */
static volatile uint32_t BoundSeq;   /* the id being tracked                  */
static volatile uint8_t  ExpectMask; /* UARTs that accepted a message         */
static volatile uint8_t  DoneMask;   /* UARTs that have reported completion   */

/* CYCCNT at the most recent falling edge, and a flag saying one has happened
   that scope_trig_hold_idle() has not yet honoured. The flag is what stops the
   hold from firing twice for one pulse, or firing at all before the first
   pulse - both of which would stall the stream task for no reason. */
static volatile uint32_t DropCyc;
static volatile uint8_t  DropPending;

/**
  * @brief  Records the width of the pulse that has just ended.
  * @return None
  * @param  None
  *
  * Caller MUST already hold the critical section, and must have written the pin
  * IDLE first so the measurement work is outside the pulse it is measuring.
  *
  * Also stamps the falling edge for SCOPE_TRIG_MIN_IDLE_US. Done here rather
  * than at each of the three drop sites because every one of them already calls
  * this immediately after writing the pin idle - so there is exactly one place
  * that can forget, instead of three.
  */
static void scope_trig_record_span(void)
{
    uint32_t now = DWT->CYCCNT;

    scope_trig_span_us_last = scope_trig_elapsed_us(ArmCyc, now);

    if (scope_trig_span_us_last > scope_trig_span_us_max)
    {
        scope_trig_span_us_max = scope_trig_span_us_last;
    }
    else
    {
        /* Not a new worst case. */
    }

    /* Stamped from the same sample the span was measured against, so the hold
       starts at the falling edge itself and not a few cycles after it. */
    DropCyc     = now;
    DropPending = 1U;
}

/**
  * @brief  Ends the pulse if every expected UART has reported.
  * @return None
  * @param  None
  *
  * Caller MUST already hold the critical section.
  */
static void scope_trig_check_done(void)
{
    if ((Armed != 0U) && (Bound != 0U) && (Committed != 0U))
    {
        if (ExpectMask == 0U)
        {
            /* The object produced no successful sends at all - every field
               missing, or every queue full. There is nothing to wait for, so
               end the pulse rather than leaving the pin stuck ACTIVE until the
               next object happens to succeed. */
            SCOPE_TRIG_PIN_IDLE();
            Armed = 0U;
            Bound = 0U;
            scope_trig_record_span();
        }
        else if ((DoneMask & ExpectMask) == ExpectMask)
        {
            /* THE FALLING EDGE. Every UART that took a message for this
               sequence has finished shifting it out. */
            SCOPE_TRIG_PIN_IDLE();
            Armed = 0U;
            Bound = 0U;
            scope_trig_record_span();
        }
        else
        {
            /* Still waiting on at least one UART - hold the pin. */
        }
    }
    else
    {
        /* Not yet committed, or no pulse running. */
    }
}

/**
  * @brief  Raises the pin and opens a fresh measurement window.
  * @return None
  * @param  None
  *
  * Caller MUST already hold the critical section, and MUST have established
  * that nothing is currently armed. Shared by both arming sources so the two
  * cannot drift apart - the state they leave behind is what every other
  * function in this tracker assumes.
  */
static void scope_trig_arm_locked(void)
{
    Armed      = 1U;
    Bound      = 0U;
    Committed  = 0U;
    ExpectMask = 0U;
    DoneMask   = 0U;

    /* THE RISING EDGE. First statement after the state is consistent, so
       nothing measurable happens between the caller's entry and the edge. */
    SCOPE_TRIG_PIN_ACTIVE();
    scope_trig_pulses++;

    /* Stamped AFTER the pin write, so the timing work never delays the edge
       the scope is looking at. */
    ArmCyc  = DWT->CYCCNT;
    BindCyc = ArmCyc;
}

#if SCOPE_TRIG_ARM_ON_SOCKET_DATA

void scope_trig_data_rx(void)
{
    uint32_t primask = scope_trig_lock();

    if (Armed == 0U)
    {
        scope_trig_arm_locked();
    }
    else
    {
        /* One TLS record is pulled through this callback in several reads, and
           one WebSocket frame can span several records, so a measurement
           already running is the common case rather than an error. Re-arming
           here would restart the window part-way through the frame and report
           only the tail of the processing. */
        scope_trig_eth_extra++;
    }

    scope_trig_unlock(primask);
}

#endif /* SCOPE_TRIG_ARM_ON_SOCKET_DATA */

void scope_trig_hold_idle(void)
{
#if SCOPE_TRIG_MIN_IDLE_US
    uint32_t start;
    uint8_t  pending;
    uint32_t primask = scope_trig_lock();

    /* Take the stamp and clear the flag together, so a second call for the
       same pulse - or a call before any pulse has ended - returns at once
       instead of waiting on a stale timestamp. */
    pending     = DropPending;
    start       = DropCyc;
    DropPending = 0U;

    scope_trig_unlock(primask);

    if ((pending != 0U) && (scope_trig_dwt_ok != 0U) && (CycPerUs != 0U))
    {
        /* SPUN WITH INTERRUPTS ENABLED, AND OUTSIDE THE CRITICAL SECTION -
           the lock above was released before this loop is reached. Ethernet
           receive, the four transmit-complete interrupts and the RTOS tick all
           continue to be serviced for the whole wait. Masking here would trade
           dropped packets for a tidier trace, which is the wrong way round.

           The Armed test is the early exit: in the modes where the Ethernet
           ISR can still arm, a real frame arriving mid-hold has already raised
           the pin, and there is nothing left to keep low. Waiting out the
           remainder would then delay live processing to no purpose. */
        while ((scope_trig_elapsed_us(start, DWT->CYCCNT) < SCOPE_TRIG_MIN_IDLE_US) &&
               (Armed == 0U))
        {
            /* Deliberately empty - the pin is being held at its idle level and
               the only job here is to let time pass where a scope can see it. */
        }
    }
    else
    {
        /* No pulse has ended since the last hold, or the cycle counter never
           started. Either way there is nothing to time against, and spinning
           on a dead counter would never terminate. */
    }
#else
    /* Minimum idle disabled - the falling edge is left as narrow as the
       traffic makes it. */
#endif
}

void scope_trig_eth_rx(void)
{
    uint32_t primask = scope_trig_lock();

#if SCOPE_TRIG_ARM_ON_SOCKET_DATA

    /* ARMING IS DELEGATED TO scope_trig_data_rx() IN THIS MODE, so this hook
       only counts. It is deliberately still called from the ISR: the ratio of
       scope_trig_eth_extra to scope_trig_pulses is the direct measure of how
       much traffic on this subnet is NOT ours, and that ratio is the whole
       justification for not arming here. Removing the call would hide it. */
    scope_trig_eth_extra++;

#else

    if (Armed == 0U)
    {
        /* THE RISING EDGE, as early as this code can be reached - ahead of
           HAL_ETH_IRQHandler(), so even the HAL's own descriptor handling is
           inside the measured window. */
        scope_trig_arm_locked();
    }
#if SCOPE_TRIG_REARM_WHILE_UNBOUND
    else if (Bound == 0U)
    {
        /* ARMED, BUT NOTHING HAS BOUND - so the packet that started this
           window carried no data, and neither did any since. Restart from
           here: the pin drops and rises again, and the clock is re-stamped.

           This is what stops a stray mDNS, NTP or ARP packet holding the pin
           HIGH until the next JSON object happens along. See
           SCOPE_TRIG_REARM_WHILE_UNBOUND in scope_trig.h for why it is an
           approximation rather than a cure.

           The drop is deliberately a real edge, not a silent re-stamp. A
           silent one would leave the scope showing a wide pulse while the
           counters reported a narrow one, and the two would disagree with no
           way to tell which was lying. */
        SCOPE_TRIG_PIN_IDLE();
        SCOPE_TRIG_PIN_ACTIVE();

        ArmCyc  = DWT->CYCCNT;
        BindCyc = ArmCyc;

        scope_trig_eth_extra++;
    }
#endif
    else
    {
        /* A measurement is already running AND a sequence is bound, so the
           data is being processed. One frame takes several receive interrupts,
           so this is the common case, not an error - and the pin must not be
           disturbed now, or the window being measured would be cut short. */
        scope_trig_eth_extra++;
    }

#endif /* SCOPE_TRIG_ARM_ON_SOCKET_DATA */

    scope_trig_unlock(primask);
}

/**
  * @brief  Raises the pin through whichever arming source this build uses.
  * @return None
  * @param  None
  *
  * The self-test must exercise the source that is actually live, or it would
  * pass while proving nothing about the configuration being shipped.
  */
static void scope_trig_test_arm(void)
{
#if SCOPE_TRIG_ARM_ON_SOCKET_DATA
    scope_trig_data_rx();
#else
    scope_trig_eth_rx();
#endif
}

void scope_trig_seq_begin(uint32_t seq)
{
    uint32_t primask = scope_trig_lock();

    if (Armed == 0U)
    {
        /* An object completed with no pulse running - the ETH hook is not
           firing. Counted because the pin would then never move and the trace
           would be a flat line indistinguishable from no traffic. */
        scope_trig_unbound++;
    }
    else if (Bound == 0U)
    {
        Bound      = 1U;
        BoundSeq   = seq;
        ExpectMask = 0U;
        DoneMask   = 0U;
        Committed  = 0U;

        /* LEAD: how long the pin sat HIGH before the data this measurement is
           about actually turned up. Near zero means the packet that started the
           pulse WAS the data and the width is honest. Large means something
           unrelated started it and the pulse is mostly idle waiting. */
        BindCyc = DWT->CYCCNT;
        scope_trig_lead_us_last = scope_trig_elapsed_us(ArmCyc, BindCyc);

        if (scope_trig_lead_us_last > scope_trig_lead_us_max)
        {
            scope_trig_lead_us_max = scope_trig_lead_us_last;
        }
        else
        {
            /* Not a new worst case. */
        }

        if (scope_trig_lead_us_last > 1000U)
        {
            scope_trig_lead_over_1ms++;
        }
        else
        {
            /* Started promptly - almost certainly the data packet itself. */
        }
    }
    else
    {
        /* A second object inside the same pulse - one receive can carry
           several. Only the first is measured; the rest ride along and are not
           tracked, which keeps the pulse a single-sequence measurement. */
    }

    scope_trig_unlock(primask);
}

void scope_trig_seq_expect(uint8_t uart_idx)
{
    uint32_t primask = scope_trig_lock();

    if ((Armed != 0U) && (Bound != 0U) && (Committed == 0U) &&
        (uart_idx < (uint8_t)SCOPE_TRIG_U_COUNT))
    {
        ExpectMask = (uint8_t)(ExpectMask | (uint8_t)(1U << uart_idx));
    }
    else
    {
        /* Not tracking, already committed, or a bad index. */
    }

    scope_trig_unlock(primask);
}

void scope_trig_seq_commit(void)
{
    uint32_t primask = scope_trig_lock();

    if ((Armed != 0U) && (Bound != 0U))
    {
        Committed = 1U;

#if SCOPE_TRIG_END_ON_PARSE
        /* THE FALLING EDGE, in parse-complete mode.
           Everything the frame needed doing to it has been done: decrypted,
           unmasked, parsed, its four values extracted and queued. The bytes
           have not left the board yet and deliberately are not waited for -
           see SCOPE_TRIG_END_ON_PARSE in scope_trig.h.

           The expected/done masks are still maintained above and below, so
           switching modes needs no other change; they simply stop deciding
           when the pin drops. */
        SCOPE_TRIG_PIN_IDLE();
        Armed = 0U;
        Bound = 0U;
        scope_trig_record_span();
#else
        scope_trig_check_done();   /* completions may all have arrived already */
#endif
    }
    else
    {
        /* Nothing being tracked. */
    }

    scope_trig_unlock(primask);
}

void scope_trig_seq_uart_done(uint8_t uart_idx, uint32_t seq)
{
    uint32_t primask = scope_trig_lock();

    if ((Armed != 0U) && (Bound != 0U) &&
        (uart_idx < (uint8_t)SCOPE_TRIG_U_COUNT) &&
        (seq != SCOPE_TRIG_SEQ_NONE))
    {
        /* SCOPE_TRIG_SEQ_NONE is refused before the comparison, not by relying
           on it differing from BoundSeq. Untracked traffic - the NTP epoch
           lines, an HTTPS POST - must never be able to complete a measurement,
           and testing the sentinel explicitly says so rather than leaving it to
           the arithmetic. */
        if (seq == BoundSeq)
        {
            DoneMask = (uint8_t)(DoneMask | (uint8_t)(1U << uart_idx));
            scope_trig_check_done();
        }
        else
        {
            /* THE PER-SEQUENCE GUARD. This UART is still draining a message
               from an earlier sequence, or one that was never tracked. Counting
               it would drop the pin on somebody else's completion and report a
               latency for a sequence that has not finished. Non-zero here is
               normal and healthy. */
            scope_trig_seq_mismatch++;
        }
    }
    else
    {
        /* No pulse, or nothing bound yet - nothing to record against. */
    }

    scope_trig_unlock(primask);
}

/* The other two rising-edge sources are not compiled in this mode: three
   sources raising one pin would leave it permanently ACTIVE. */

#elif SCOPE_TRIG_FROM_NETWORK

void scope_trig_net_arrival(void)
{
    uint32_t primask = scope_trig_lock();

    /* A LATCH, NOT A COUNT - see scope_trig.h. One arrival can produce no
       values at all (the payload was a fragment), one, or several (it held
       many objects), so arrivals and completions do not pair up and a depth
       counter would drift until the pin stuck. The first arrival while idle
       starts the pulse; the next followed-UART completion ends it. */
    if (scope_trig_inflight == 0U)
    {
        scope_trig_inflight     = 1U;
        scope_trig_inflight_max = 1U;

        /* FIRST STATEMENT AFTER THE LOCK, deliberately. Everything between the
           payload arriving and this write is time the measurement misses. */
        SCOPE_TRIG_PIN_ACTIVE();
        scope_trig_pulses++;
    }
    else
    {
        /* A payload arrived while the previous one was still being processed
           and transmitted. Not measured - re-triggering here would truncate the
           pulse already running and report a latency shorter than reality. */
        scope_trig_skipped++;
    }

    scope_trig_unlock(primask);
}

/* scope_trig_frame_received() is the UART-dispatch rising edge. It is NOT
   compiled in this mode: with both edges active the pin would be raised twice
   per value and the latch released once, leaving it stuck ACTIVE. The call site
   in uart_dispatch.c is gated by the same macro. */

#else /* rising edge comes from the UART dispatch */

void scope_trig_frame_received(void)
{
    uint32_t primask = scope_trig_lock();

#if SCOPE_TRIG_MODE_BURST

    /* Count the frame, then raise the pin only on the 0 -> 1 transition. Later
       frames arriving while the pin is already active deliberately do NOT
       produce an edge - there is nothing to show on a scope for "one more frame
       joined the backlog", and emitting a spurious edge would corrupt the width
       being measured. */
    scope_trig_inflight++;

    if (scope_trig_inflight > scope_trig_inflight_max)
    {
        scope_trig_inflight_max = scope_trig_inflight;
    }
    else
    {
        /* Backlog is not a new peak - nothing to record. */
    }

    if (scope_trig_inflight == 1U)
    {
        SCOPE_TRIG_PIN_ACTIVE();
        scope_trig_pulses++;
    }
    else
    {
        /* A pulse is already running; this frame extends it rather than
           starting a new one. */
    }

#else /* PER-FRAME mode */

    /* Time this frame only if nothing is currently being timed. Frames arriving
       mid-pulse are counted, not measured - see the mode note in scope_trig.h.
       This is what keeps every pulse a clean single-frame width. */
    if (scope_trig_inflight == 0U)
    {
        scope_trig_inflight     = 1U;
        scope_trig_inflight_max = 1U;

        SCOPE_TRIG_PIN_ACTIVE();
        scope_trig_pulses++;
    }
    else
    {
        scope_trig_skipped++;
    }

#endif /* SCOPE_TRIG_MODE_BURST */

    scope_trig_unlock(primask);
}

#endif /* SCOPE_TRIG_FROM_NETWORK */

void scope_trig_tx_complete(void)
{
    uint32_t primask = scope_trig_lock();

    if (scope_trig_inflight == 0U)
    {
#if (SCOPE_TRIG_MODE_BURST && !SCOPE_TRIG_FROM_NETWORK)
        /* Should not happen: every counted frame produces exactly one
           completion. Counted rather than ignored because it means the pairing
           is broken - most likely a UART whose uart_dispatch_send() was not
           counted, or a completion delivered twice - and the pulse widths are
           not trustworthy until that is explained.

           NOT decremented, so the counter cannot wrap to 0xFFFFFFFF and hold
           the pin active for the rest of the run. */
        scope_trig_underflow++;
#else
        /* EXPECTED in both of the other two modes, for the same underlying
           reason: something was transmitted that was never latched.

           PER-FRAME - frames arriving mid-pulse were never counted, so their
           completions land here with nothing outstanding.

           FROM_NETWORK - one arrival can yield several values on the followed
           UART. The first completion released the latch; the rest arrive with
           nothing outstanding and must NOT be treated as an error, or the
           counter would climb on every multi-object frame and wrongly suggest
           the widths cannot be trusted.

           scope_trig_skipped already reports how many arrivals went unmeasured. */
#endif
    }
    else
    {
        scope_trig_inflight--;

        if (scope_trig_inflight == 0U)
        {
            /* Last outstanding frame is out. THIS is the falling edge whose
               distance from the rising edge is the measurement. */
            SCOPE_TRIG_PIN_IDLE();
        }
        else
        {
            /* Still frames queued behind this one - hold the pin active. A
               peripheral that never reports completion therefore leaves the pin
               stuck active, which is a visible fault rather than a silent one:
               check scope_trig_inflight against a quiet link. */
        }
    }

    scope_trig_unlock(primask);
}

/**
  * @brief  Raises the pin the same way the live code does, whichever rising
  *         edge this build uses.
  * @return None
  * @param  None
  *
  * Without this the self-test would call scope_trig_frame_received(), which is
  * not compiled when SCOPE_TRIG_FROM_NETWORK is 1 - so the test would fail to
  * build in exactly the configuration it most needs to check.
  */
#if !SCOPE_TRIG_FROM_ETH
static void scope_trig_test_rise(void)
{
#if SCOPE_TRIG_FROM_NETWORK
    scope_trig_net_arrival();
#else
    scope_trig_frame_received();
#endif
}
#endif /* !SCOPE_TRIG_FROM_ETH - that mode drives scope_trig_eth_rx() directly */

int scope_trig_selftest(void)
{
    int      result  = 0;
    uint32_t primask;

    /* ===================================================================
     * THE WHOLE TEST RUNS WITH INTERRUPTS MASKED.  Added 28-08-2026.
     * ===================================================================
     * BECAUSE THE ETHERNET IS ALREADY RUNNING BY THE TIME THIS IS CALLED.
     * The test runs from StartEthIfTask, after MX_LWIP_Init() has brought the
     * interface up and before the DHCP wait - so DISCOVER is going out, ARP
     * replies are coming back, and ETH_IRQHandler is firing. Every one of those
     * interrupts calls scope_trig_eth_rx().
     *
     * That broke the test on 28-08-2026, reported as "check 3 = the ETH hook
     * does not raise the pin". What actually happened: a real interrupt armed
     * the tracker before the test began, so check 3's own scope_trig_eth_rx()
     * found Armed already set, did nothing, and the pin stayed IDLE from
     * check 2. The hook was working perfectly; the test was racing it.
     *
     * Masking for the few microseconds this takes removes the race entirely.
     * The nested scope_trig_lock() calls inside the functions under test save
     * and restore PRIMASK, so they leave interrupts masked as they found them.
     *
     * The tracker state is also cleared first, in case an interrupt armed it
     * between scope_trig_init() and here - which is exactly what happened. */
    primask = scope_trig_lock();

    Armed      = 0U;
    Bound      = 0U;
    Committed  = 0U;
    ExpectMask = 0U;
    DoneMask   = 0U;

    scope_trig_pulses       = 0U;
    scope_trig_skipped      = 0U;
    scope_trig_eth_extra    = 0U;
    scope_trig_unbound      = 0U;
    scope_trig_seq_mismatch = 0U;

    /* ---- 1. the pin can be driven ACTIVE and reads back ------------------
       Reading an output pin returns IDR, which follows the pad, so this
       catches a pin left in analogue mode, a missing GPIOE clock, or a label
       pointing at a port that was never initialised. All three otherwise look
       exactly like "no traffic yet" on a scope. */
    SCOPE_TRIG_PIN_ACTIVE();
    if (HAL_GPIO_ReadPin(SCOPE_TRIG_GPIO_Port, SCOPE_TRIG_Pin) != SCOPE_TRIG_LEVEL_ACTIVE)
    {
        result = 1;
    }
    else
    {
        /* ---- 2. and back to IDLE ---------------------------------------- */
        SCOPE_TRIG_PIN_IDLE();
        if (HAL_GPIO_ReadPin(SCOPE_TRIG_GPIO_Port, SCOPE_TRIG_Pin) != SCOPE_TRIG_LEVEL_IDLE)
        {
            result = 2;
        }
        else
        {
#if SCOPE_TRIG_FROM_ETH
            /* ---- 3. the live arming hook raises the pin ----------------
               scope_trig_data_rx() when SCOPE_TRIG_ARM_ON_SOCKET_DATA is 1,
               scope_trig_eth_rx() otherwise. Testing the wrong one would pass
               on a build whose real trigger never fires. */
            scope_trig_test_arm();

            if ((SCOPE_TRIG_PIN_READ() != SCOPE_TRIG_LEVEL_ACTIVE) ||
                (scope_trig_pulses != 1U))
            {
                result = 3;
            }
            else
            {
                /* ---- 4. THREE of four completions must NOT drop the pin,
                   and the fourth must. This is the requirement itself: the
                   pulse ends when the LAST expected UART finishes, not the
                   first. A tracker that dropped early would still produce a
                   clean, plausible pulse - just far too narrow. */
                uint8_t u;

                scope_trig_seq_begin(4242U);
                for (u = 0U; u < 4U; u++)
                {
                    scope_trig_seq_expect(u);
                }

#if SCOPE_TRIG_END_ON_PARSE
                /* ---- 4. THE PIN MUST SURVIVE THE EXTRACTION AND DROP ONLY
                   AT COMMIT. Binding the sequence and declaring four expected
                   UARTs is the parsing phase; the pin belongs HIGH throughout
                   it. Dropping early here would mean the pulse ended somewhere
                   inside the JSON extraction and measured only part of it. */
                if (SCOPE_TRIG_PIN_READ() != SCOPE_TRIG_LEVEL_ACTIVE)
                {
                    result = 4;      /* dropped during extraction - too early */
                }
                else
                {
                    scope_trig_seq_commit();

                    if (SCOPE_TRIG_PIN_READ() != SCOPE_TRIG_LEVEL_IDLE)
                    {
                        result = 4;  /* did not drop at parse-complete */
                    }
                    else
                    {
                        /* ---- 5. UART COMPLETIONS MUST NOT DISTURB ANYTHING,
                           AND THE TRACKER MUST RE-ARM.

                           In this mode the pulse is already over by the time
                           the UARTs report, so their completions - including a
                           stale one from an older sequence - must be inert.
                           Then a second full cycle has to work, because a
                           tracker that dropped the pin without releasing Armed
                           would run once and never again, which on a scope
                           looks like the traffic stopping. */
                        scope_trig_seq_uart_done(SCOPE_TRIG_U_USART1, 4242U);
                        scope_trig_seq_uart_done(SCOPE_TRIG_U_USART2, 9999U);

                        if (SCOPE_TRIG_PIN_READ() != SCOPE_TRIG_LEVEL_IDLE)
                        {
                            result = 5;      /* a completion moved the pin */
                        }
                        else
                        {
                            scope_trig_test_arm();
                            scope_trig_seq_begin(4243U);
                            scope_trig_seq_expect(SCOPE_TRIG_U_USART1);

                            if (SCOPE_TRIG_PIN_READ() != SCOPE_TRIG_LEVEL_ACTIVE)
                            {
                                result = 5;  /* did not re-arm */
                            }
                            else
                            {
                                scope_trig_seq_commit();

                                if (SCOPE_TRIG_PIN_READ() != SCOPE_TRIG_LEVEL_IDLE)
                                {
                                    result = 5;
                                }
                                else
                                {
                                    /* All five checks passed. */
                                }
                            }
                        }
                    }
                }
#else
                scope_trig_seq_commit();

                scope_trig_seq_uart_done(SCOPE_TRIG_U_USART1, 4242U);
                scope_trig_seq_uart_done(SCOPE_TRIG_U_USART2, 4242U);
                scope_trig_seq_uart_done(SCOPE_TRIG_U_UART4,  4242U);

                if (SCOPE_TRIG_PIN_READ() != SCOPE_TRIG_LEVEL_ACTIVE)
                {
                    result = 4;      /* dropped on 3 of 4 - too early */
                }
                else
                {
                    scope_trig_seq_uart_done(SCOPE_TRIG_U_UART5, 4242U);

                    if (SCOPE_TRIG_PIN_READ() != SCOPE_TRIG_LEVEL_IDLE)
                    {
                        result = 4;  /* did not drop on the fourth */
                    }
                    else
                    {
                        /* ---- 5. A COMPLETION FROM ANOTHER SEQUENCE MUST BE
                           IGNORED. The guard the requirement calls for: a UART
                           still draining sequence N-1 must not end sequence N's
                           pulse. Without it the measurement would silently
                           report the wrong window whenever the UARTs ran even
                           slightly behind. */
                        scope_trig_test_arm();
                        scope_trig_seq_begin(4243U);
                        scope_trig_seq_expect(SCOPE_TRIG_U_USART1);
                        scope_trig_seq_commit();

                        /* stale completion from the PREVIOUS sequence */
                        scope_trig_seq_uart_done(SCOPE_TRIG_U_USART1, 4242U);

                        if ((SCOPE_TRIG_PIN_READ() != SCOPE_TRIG_LEVEL_ACTIVE) ||
                            (scope_trig_seq_mismatch != 1U))
                        {
                            result = 5;
                        }
                        else
                        {
                            /* the right one now ends it */
                            scope_trig_seq_uart_done(SCOPE_TRIG_U_USART1, 4243U);

                            if (SCOPE_TRIG_PIN_READ() != SCOPE_TRIG_LEVEL_IDLE)
                            {
                                result = 5;
                            }
                            else
                            {
                                /* All five checks passed. */
                            }
                        }
                    }
                }
#endif
            }
#else
            /* ---- 3. a received frame raises the pin and the counter ------ */
            scope_trig_test_rise();

            if ((SCOPE_TRIG_PIN_READ() != SCOPE_TRIG_LEVEL_ACTIVE) ||
                (scope_trig_inflight != 1U) ||
                (scope_trig_pulses   != 1U))
            {
                result = 3;
            }
            else
            {
                /* ---- 4. completion drops it again ----------------------- */
                scope_trig_tx_complete();

                if ((SCOPE_TRIG_PIN_READ() != SCOPE_TRIG_LEVEL_IDLE) ||
                    (scope_trig_inflight != 0U))
                {
                    result = 4;
                }
                else
                {
                    /* ---- 5. an unmatched completion does not wrap -------
                       The guard that stops a stray callback pinning the pin
                       active for the rest of the run. Verifies the counter
                       stays at 0 rather than becoming 0xFFFFFFFF. */
                    scope_trig_tx_complete();

                    if ((scope_trig_inflight != 0U) ||
                        (SCOPE_TRIG_PIN_READ() != SCOPE_TRIG_LEVEL_IDLE))
                    {
                        result = 5;
                    }
                    else
                    {
                        /* All five checks passed. */
                    }
                }
            }
#endif /* SCOPE_TRIG_FROM_ETH */
        }
    }

    /* Leave no trace of the test in the counters, or the first real frame would
       start from pulses == 1 and a non-zero underflow. The pin is returned to
       idle unconditionally, including on a failure path that left it active.

       NO SECOND scope_trig_lock() HERE. Interrupts have been masked since the
       top of the function and `primask` holds the state to restore at the end.
       Re-locking would overwrite it with "already masked", and the unlock below
       would then leave interrupts disabled for the rest of the run - the board
       would reach the DHCP wait with the Ethernet interrupt silenced and simply
       stop. */
    scope_trig_inflight     = 0U;
    scope_trig_inflight_max = 0U;
    scope_trig_pulses       = 0U;
    scope_trig_skipped      = 0U;
    scope_trig_underflow    = 0U;
#if SCOPE_TRIG_FROM_ETH
    scope_trig_eth_extra     = 0U;
    scope_trig_unbound       = 0U;
    scope_trig_seq_mismatch  = 0U;
    scope_trig_lead_us_last  = 0U;
    scope_trig_lead_us_max   = 0U;
    scope_trig_span_us_last  = 0U;
    scope_trig_span_us_max   = 0U;
    scope_trig_lead_over_1ms = 0U;

    /* The tracker itself, or the first real Ethernet interrupt would find a
       measurement already "running" from the test and be discarded. */
    Armed      = 0U;
    Bound      = 0U;
    Committed  = 0U;
    ExpectMask = 0U;
    DoneMask   = 0U;

    /* The test's own commits stamped a falling edge. Left set, the first live
       frame would spend up to SCOPE_TRIG_MIN_IDLE_US in scope_trig_hold_idle()
       paying off a pulse that was never on the wire. */
    DropCyc     = 0U;
    DropPending = 0U;
#endif

    SCOPE_TRIG_PIN_IDLE();

    /* Restores whatever the interrupt state was on entry - the single unlock
       matching the single lock at the top. */
    scope_trig_unlock(primask);

    return result;
}

#else /* SCOPE_TRIG_ENABLE == 0 */

/* Deliberately empty. The inline no-ops in scope_trig.h cover the call sites,
   and an empty translation unit is not valid C - this comment is the unit's
   only content, so a typedef keeps the compiler quiet about that. */
typedef int scope_trig_disabled_translation_unit_t;

#endif /* SCOPE_TRIG_ENABLE */
