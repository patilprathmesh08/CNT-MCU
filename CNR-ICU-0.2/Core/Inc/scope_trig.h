/**
  ******************************************************************************
  * @file    scope_trig.h
  * @brief   Oscilloscope timing trigger on PE9 (SCOPE_TRIG): HIGH when a frame
  *          is received, LOW when its UART transmission completes
  * @version 1.0 - 26-08-2026
  *
  * WHAT THIS MEASURES
  *
  *   ___________                                          ____________
  *              |________________________________________|
  *              ^                                        ^
  *              |                                        |
  *   frame accepted for transmission            last byte shifted out
  *   (uart_dispatch_send returns 0)             (HAL_UART_TxCpltCallback)
  *
  *              |<-------------- pulse width ----------->|
  *                 receive -> transmission complete
  *
  * Probe PE9 against any GND pin on the board. Trigger on the RISING edge and
  * read the width; the pin idles LOW, so the first rising edge after reset is a
  * genuine frame and not a startup artefact.
  *
  * WHY PE9. It is the only pin this project touches for nothing else. Every
  * other free pin on the NUCLEO-H753ZI is either an Ethernet RMII signal, one
  * of the four dispatch UARTs, the ST-LINK VCP that carries printf, an LED
  * owned by BSP_LED_Init(), the USER button, or SWD - and driving SWD would
  * cost the debugger. PE9 is also clear of the RMII group, so the 50 MHz
  * Ethernet clock does not couple into the trace.
  *
  * The pin is defined by CubeMX from the .ioc GPIO_Label, as SCOPE_TRIG_Pin and
  * SCOPE_TRIG_GPIO_Port in main.h. To move it, change the label's pin in CubeMX
  * and regenerate - nothing in this module names PE9 directly.
  *
  * ===========================================================================
  * WHERE THE TWO EDGES ARE SET - the answer to "where is it HIGH, where LOW"
  * ===========================================================================
  *
  *   RISING   uart_dispatch.c, at the successful return of uart_dispatch_send()
  *   FALLING  uart_dispatch.c, inside HAL_UART_TxCpltCallback() (ISR context)
  *
  * uart_dispatch_send() is deliberately the rising-edge site because it is the
  * ONE point both receive paths converge on:
  *
  *   HTTPS POST     http_server.c httpd_post_finished -> uart_dispatch_send()
  *   WebSocket/TLS  stream_client.c stream_dispatch_to_uart -> uart_dispatch_send()
  *
  * Hooking the two call sites separately would have worked today and silently
  * missed any third transport added later. Hooking the convergence point cannot.
  *
  * ===========================================================================
  * BACK-TO-BACK FRAMES - the case that decides the whole design
  * ===========================================================================
  *
  * A UART at 115200 baud carries 11520 B/s. The network delivers far faster, so
  * under any sustained load frames queue up and several are in flight at once.
  * A naive "HIGH on receive, LOW on transmit-complete" then lies: frame 2's
  * arrival is lost because the pin is already HIGH, and frame 1's completion
  * drops the pin while frame 2 is still waiting to go out.
  *
  * Two honest answers, selected by SCOPE_TRIG_MODE_BURST:
  *
  * BURST MODE (1, the default) - counts frames in flight. The pin is HIGH for
  * exactly as long as at least one frame is outstanding, LOW when none is.
  *   + Correct for EVERY frame; no frame is ever unaccounted for.
  *   + An isolated frame gives precisely receive -> transmit-complete.
  *   - Back-to-back frames merge into one wide pulse measuring the whole burst,
  *     not one frame. A continuously saturated link holds the pin HIGH, which
  *     is itself the useful reading: it says the UART cannot keep up.
  *
  * PER-FRAME MODE (0) - times one frame at a time. The pin goes HIGH only when
  * idle, and the next transmit-complete drops it.
  *   + Every pulse is a clean single-frame width, ideal for a scope histogram.
  *   - Frames arriving mid-pulse are NOT timed. They are counted in
  *     scope_trig_skipped so the number never has to be guessed.
  *
  * Start with BURST. Switch to PER-FRAME only when the trace is a solid block
  * and individual frame widths are wanted.
  *
  * A NOTE ON MULTI-PIECE FRAMES. stream_client.c splits anything larger than
  * UART_DISPATCH_MAX_PAYLOAD (128 B) into several uart_dispatch_send() calls, so
  * a 512-byte WebSocket frame is four counted messages. In BURST mode the pulse
  * correctly spans all four. In PER-FRAME mode it spans only the first piece.
  *
  * ===========================================================================
  * COST
  * ===========================================================================
  * One GPIO BSRR write and a guarded increment per frame, well under 1 us
  * against transmit times of 500-600 us. The BSRR write is a single store: no
  * read-modify-write, so it cannot tear against another port user.
  * Set SCOPE_TRIG_ENABLE to 0 to compile every call away to nothing.
  ******************************************************************************
  */

#ifndef __SCOPE_TRIG_H__
#define __SCOPE_TRIG_H__

#include "main.h"
#include <stdint.h>

/* ---------------------------------------------------------------------------
 * Configuration
 * ------------------------------------------------------------------------- */

/* Master switch. 0 removes the pin writes, the counters and every call site's
   code - the functions become empty static inlines the compiler discards. Left
   ON by default because this is a measurement build; turn it off for a release
   rather than deleting the call sites, so the instrumentation can come back
   without re-deriving where it went. */
#ifndef SCOPE_TRIG_ENABLE
#define SCOPE_TRIG_ENABLE  1
#endif

/* 1 = pin HIGH while any frame is in flight (see the header comment).
   0 = one frame timed at a time, others counted in scope_trig_skipped. */
#ifndef SCOPE_TRIG_MODE_BURST
#define SCOPE_TRIG_MODE_BURST  1
#endif

/* Inverts the output for a probe or logic analyser that wants active-low.
   0 = idle LOW, frame HIGH (what the .ioc initial level and the header
   diagram assume). 1 = idle HIGH, frame LOW. */
#ifndef SCOPE_TRIG_ACTIVE_LOW
#define SCOPE_TRIG_ACTIVE_LOW  0
#endif

/* WHICH DISPATCH UART THE TRIGGER FOLLOWS.  Added 27-08-2026.
   -------------------------------------------------------------------------
   Until now the trigger counted frames on ALL FOUR dispatch UARTs. That was
   correct while the stream fed only USART2, and became wrong the moment the
   JSON extractor started routing four fields to four different peripherals:
   the pin would rise on the first field queued and not fall until the LAST of
   the four had finished transmitting, on whichever UART that happened to be.
   The pulse would then measure "time to drain all four UARTs" - a real number,
   but not the receive-to-USART2 figure being asked for.

   Narrowing it to one selector makes the pulse mean exactly one thing again:
   ntp_time arrived -> ntp_time finished transmitting on USART2.

   The value must equal UART_SELECTOR_USART2 from uart_dispatch.h. It is a raw
   literal here so this header stays independent of uart_dispatch.h, and
   uart_dispatch.c carries a compile-time check that the two agree - a silent
   mismatch would leave the pin following the wrong peripheral, or nothing at
   all, and either looks identical to "no traffic" on a scope.

   Set to 0 to follow every dispatch UART again, as before. */
#ifndef SCOPE_TRIG_SELECTOR
#define SCOPE_TRIG_SELECTOR    0x02U
#endif

/* WHERE THE RISING EDGE COMES FROM.  Added 27-08-2026.
   -------------------------------------------------------------------------
   0 = UART DISPATCH. The pin rises when a value is handed to the UART bridge
       in uart_dispatch_send(). The pulse then measures only the UART half:
       queue wait, task wake, and the transmit itself. TLS decrypt, WebSocket
       framing and JSON extraction all happen BEFORE the edge and are invisible.

   1 = NETWORK ARRIVAL. The pin rises the instant a decrypted payload reaches
       stream_process_payload(), and falls when the followed UART finishes
       transmitting. The pulse then covers the WHOLE pipeline:

         mbedtls_ssl_read returns
              |
              +-- WebSocket frame unmask and parse
              +-- JSON reassembly, brace tracking
              +-- key search and value copy
              +-- uart_dispatch_send, queue, task wake
              +-- HAL_UART_Transmit_IT shifts the bytes out
                                                    |
                                          TX-complete interrupt

       That is "server frame in -> value out", which is the number worth
       knowing. Expect it to be substantially wider than mode 0: everything
       mode 0 hides is now inside the pulse.

   WHAT THE PULSE MEANS WHEN ONE FRAME CARRIES SEVERAL JSON OBJECTS. The pin
   rises once on arrival and falls on the FIRST followed-UART completion, so it
   measures the latency of the first value out of that frame. Later objects in
   the same frame are pipeline throughput, not arrival latency, and are counted
   in scope_trig_skipped rather than widening the pulse. Measuring to the LAST
   completion instead would blend the two and report neither.

   In this mode the counter is a latch holding 0 or 1, not a depth count, so
   SCOPE_TRIG_MODE_BURST has no effect. */
#ifndef SCOPE_TRIG_FROM_NETWORK
#define SCOPE_TRIG_FROM_NETWORK  1
#endif

/* ===========================================================================
 * SCOPE_TRIG_FROM_ETH - full Ethernet-to-all-four-UARTs measurement.
 * ===========================================================================
 * Added 27-08-2026. Takes precedence over SCOPE_TRIG_FROM_NETWORK and
 * SCOPE_TRIG_SELECTOR, both of which are ignored while this is 1.
 *
 *   RISING   ETH_IRQHandler, USER CODE 0, BEFORE HAL_ETH_IRQHandler() runs
 *   FALLING  when all four UARTs have reported transmit-complete for the SAME
 *            sequence_id
 *
 * So the pulse is:
 *
 *   ETH RX interrupt
 *        |  TLS record decrypt
 *        |  WebSocket unmask and parse
 *        |  JSON reassembly and field extraction
 *        |  four uart_dispatch_send() calls
 *        |  four FreeRTOS task wakes and four HAL_UART_Transmit_IT
 *        v
 *   last of the four TX-complete interrupts for that sequence_id
 *
 * ===========================================================================
 * WHAT "THE ETHERNET INTERRUPT FOR SEQUENCE N" ACTUALLY MEANS
 * ===========================================================================
 * The ETH ISR cannot know the sequence id. The frame is still encrypted at that
 * point; the id only exists after TLS decrypt, WebSocket parsing and JSON
 * extraction. The binding is therefore made LATER, when the parser reports the
 * id, and attached to whichever pulse is currently running.
 *
 * AND THE RX INTERRUPT FIRES FAR MORE OFTEN THAN OBJECTS ARRIVE. TCP
 * acknowledgements, TLS record boundaries, retransmissions, ARP and DHCP all
 * raise it, and none carries a JSON object. Raising the pin on every one would
 * hold it high permanently.
 *
 * So the pin rises on the FIRST RX interrupt after the previous sequence
 * completed, and further interrupts while a measurement is running are counted
 * in scope_trig_eth_extra rather than re-triggering. The pulse is then "first
 * Ethernet activity belonging to this frame -> all four UARTs done", which is
 * the honest reading of the request. If the link is idle between frames it is
 * also exactly the arrival of that frame's first packet; if the link carries
 * other traffic, an unrelated packet can start the pulse early, and
 * scope_trig_eth_extra climbing much faster than scope_trig_pulses is the sign
 * that this is happening.
 *
 * ===========================================================================
 * PER-SEQUENCE TRACKING - why a plain counter is not enough
 * ===========================================================================
 * Four UARTs finish at different times and at different rates. A completion
 * from sequence N-1, still in flight when sequence N started, must not count
 * towards N. Every queued message therefore CARRIES its sequence id, each UART
 * records the id it is currently transmitting, and the transmit-complete ISR
 * reports that id. A completion whose id does not match the bound sequence is
 * ignored - that is the whole guarantee.
 *
 * The expected set is built from the sends that actually SUCCEEDED, not assumed
 * to be all four. An object missing joystick_y, or a UART whose queue was full,
 * would otherwise leave the pin waiting for a completion that can never arrive.
 * ========================================================================= */
#ifndef SCOPE_TRIG_FROM_ETH
#define SCOPE_TRIG_FROM_ETH      1
#endif

/* ===========================================================================
 * WHERE THE PULSE ENDS.  Added 10-09-2026.
 * ===========================================================================
 * Only meaningful when SCOPE_TRIG_FROM_ETH is 1; it selects the FALLING edge.
 *
 *   1  PARSE COMPLETE. The pin drops the moment the JSON object has been
 *      parsed, its four values extracted, and all four handed to the UART
 *      queues - that is, when the frame is READY to transmit. The pulse then
 *      measures
 *
 *          ETH RX interrupt -> TLS decrypt -> WebSocket parse -> JSON extract
 *
 *      and nothing else. This is the software processing time.
 *
 *   0  TRANSMIT COMPLETE. The pin drops only after all four UARTs have
 *      finished shifting their values out, matched by sequence_id. The pulse
 *      then additionally covers the queueing, four task wake-ups and the
 *      transmit itself.
 *
 * WHICH TO USE. They answer different questions and neither is more correct.
 * Mode 1 asks "how long does the board take to understand a frame"; mode 0
 * asks "how long from the wire to the last byte leaving the board". Mode 0 is
 * dominated by the UART baud rate, so it moves when the payload size changes
 * even though the processing has not; mode 1 does not.
 *
 * The difference between the two, measured on the same traffic, is the UART
 * half on its own - which is a useful third number and needs no extra code,
 * just two runs.
 * ========================================================================= */
#ifndef SCOPE_TRIG_END_ON_PARSE
#define SCOPE_TRIG_END_ON_PARSE  1
#endif

/* ===========================================================================
 * RESTART THE MEASUREMENT ON A LATER PACKET, WHILE NOTHING HAS BOUND YET.
 * ===========================================================================
 * Added 10-09-2026, after the pin was observed sitting permanently HIGH.
 *
 * THE PROBLEM. scope_trig_eth_rx() has to arm on ANY receive interrupt - at
 * that point the packet is still encrypted and the HAL has not looked at the
 * descriptor, so there is no way to tell a WSS data frame from anything else.
 * But only a data frame ever reaches scope_trig_seq_commit() to drop the pin.
 * A stray packet therefore raises it and it stays raised until the NEXT JSON
 * object finishes parsing.
 *
 * That was always true and was documented as a caveat. It became the dominant
 * effect when mDNS was added: mDNS is MULTICAST, so this board now receives
 * every mDNS packet on the subnet from every device, on top of NTP replies,
 * ARP and TCP acknowledgements. Non-data interrupts arrive far faster than
 * objects, so the pin is essentially never low.
 *
 * WHAT THIS DOES. While a measurement is running but no sequence has bound -
 * meaning no data has arrived yet - a further receive interrupt DROPS the pin
 * and raises it again, restarting the window. Once a sequence binds, the pin
 * is left alone: the data is being processed and must not be disturbed.
 *
 * The effect on a scope is that stray packets appear as narrow pulses and the
 * LAST rising edge before the fall is the packet that actually carried the
 * data. Trigger on the rising edge and read the final pulse.
 *
 * WHY THIS IS AN APPROXIMATION, NOT A FIX. It assumes the last packet before a
 * completed parse is the one that carried it. That is true when a frame fits
 * in one packet, which it does here, and false for a frame split across
 * several - the window would then start at the last fragment rather than the
 * first. scope_trig_lead_us remains the honest check either way.
 *
 * Set to 0 for the previous behaviour: first packet arms, and the pulse spans
 * everything up to the next parse.
 *
 * WHY THIS DEFAULTS TO 0.  Corrected 10-09-2026, after the pin was measured
 * still sitting permanently HIGH with it enabled. The two writes are adjacent
 * stores to BSRR, so the LOW between them lasts a handful of nanoseconds - far
 * too narrow to see at any timebase that also shows a 200 us pulse, and far too
 * narrow to trigger on. The counters became more honest and the trace did not
 * change at all. SCOPE_TRIG_ARM_ON_SOCKET_DATA below replaces it properly by
 * removing the stray arming instead of trying to punctuate it.
 * ========================================================================= */
#ifndef SCOPE_TRIG_REARM_WHILE_UNBOUND
#define SCOPE_TRIG_REARM_WHILE_UNBOUND  0
#endif

/* ===========================================================================
 * WHERE THE PULSE STARTS - the fix for a permanently HIGH pin.
 * ===========================================================================
 * Added 10-09-2026. Only meaningful when SCOPE_TRIG_FROM_ETH is 1.
 *
 *   0  ETHERNET INTERRUPT. scope_trig_eth_rx() arms, from ETH_IRQHandler.
 *      The earliest edge this code can produce - and unusable as a scope
 *      trigger on this network, for a reason that is structural rather than a
 *      bug: AT THAT POINT THE PACKET IS STILL ENCRYPTED AND THE HAL HAS NOT
 *      READ THE DESCRIPTOR, so nothing can tell a WSS data frame from an mDNS
 *      multicast, an ARP, a TCP acknowledgement or an NTP reply. Every one of
 *      them arms the pin, and only a data frame can ever drop it. Since mDNS
 *      was added this board receives every mDNS packet on the subnet, so the
 *      pin is HIGH essentially always.
 *
 *   1  FIRST SOCKET BYTES OF THE FRAME. scope_trig_data_rx() arms, from
 *      stream_bio_recv() at the moment lwip_recv() hands over bytes belonging
 *      to the stream socket. Only real stream traffic can arm the pin, so it
 *      is genuinely LOW between frames and every pulse is a frame.
 *
 * WHAT MODE 1 COSTS, EXACTLY. The bytes are still CIPHERTEXT here - this is
 * the transport callback mbedTLS pulls through, below the TLS record layer -
 * so decryption, WebSocket unmasking and JSON parsing all remain INSIDE the
 * pulse. Nothing the requirement asks for is lost.
 *
 * What falls outside is only the stack hop: ETH RX interrupt -> DMA descriptor
 * -> tcpip_thread -> lwIP IP and TCP input -> socket receive queue -> the
 * task's lwip_recv(). Tens of microseconds, and near-constant, because it is
 * the same code path every time and carries no work proportional to the
 * payload. Measure it once if the absolute figure matters: build with mode 0,
 * read scope_trig_lead_us_last on a quiet link, and add it.
 *
 * WHY NOT ARM IN THE ISR AND CANCEL LATER. A cancel needs something to run
 * while no packet is arriving, and nothing here does - the pin is only ever
 * touched from scope_trig_eth_rx(), which by definition runs on a packet. Any
 * "retire the stale pulse" test placed there therefore fires on the NEXT
 * packet, producing the same nanosecond-wide LOW as the re-arm above. Cancelling
 * properly would need a dedicated periodic timer whose interrupt would itself
 * land inside the window being measured.
 * ========================================================================= */
#ifndef SCOPE_TRIG_ARM_ON_SOCKET_DATA
#define SCOPE_TRIG_ARM_ON_SOCKET_DATA   1
#endif

/* ===========================================================================
 * GUARANTEED MINIMUM IDLE TIME AFTER THE FALLING EDGE.  Added 10-09-2026.
 * ===========================================================================
 * Added after the pin measured 3.47 V mean on a 10 ms/div sweep - a 100% duty
 * cycle - while the tracker was in fact dropping it correctly once per JSON
 * object.
 *
 * WHY A CORRECT FALLING EDGE STILL DRAWS A FLAT LINE. Dropping the pin is not
 * enough; something has to KEEP it low long enough to see. Nothing here does.
 * The stream task drops the pin at parse-complete, loops straight back into
 * the next read, and lwip_recv() hands over the following frame immediately
 * because the socket already had it buffered. The pin is low for the few
 * microseconds that costs.
 *
 * A 3 us low on a 100 ms screen is well under one pixel column. The trace is
 * flat and the mean sits at VDD - INDISTINGUISHABLE from a pin that never
 * drops at all, which is why this was mistaken for a logic fault twice.
 *
 * This is a separate effect from stray-packet arming, and it survives
 * SCOPE_TRIG_ARM_ON_SOCKET_DATA: that macro removes pulses which are not ours,
 * but the ones that ARE ours still run back-to-back under load.
 *
 * WHAT THIS DOES. After the falling edge the pin is held idle for at least
 * this many microseconds before the next frame is allowed to raise it. 50 us
 * is two and a half divisions at 20 us/div and unmissable at any timebase fast
 * enough to read the pulse itself.
 *
 * WHY IT CANNOT CORRUPT THE MEASUREMENT. The wait runs AFTER the pin is
 * already low and AFTER scope_trig_record_span() has taken the reading, so the
 * pulse width is untouched. It delays the start of the NEXT frame's processing
 * by up to 50 us, and it is spent with INTERRUPTS ENABLED and outside every
 * critical section, so no packet and no transmit-complete is lost - they queue
 * as they always do.
 *
 * WHY IT IS NOT A LOSS OF THROUGHPUT WORTH CARING ABOUT. This is a measurement
 * build. If the frame rate is high enough that 50 us per frame matters, the
 * duty cycle is itself the reading and this macro should be set to 0.
 * ========================================================================= */
#ifndef SCOPE_TRIG_MIN_IDLE_US
#define SCOPE_TRIG_MIN_IDLE_US   50U
#endif

/* Bit positions used in the expect/done masks. Order is arbitrary but must
   match the mapping in stream_client.c and uart_dispatch.c. */
/* Sequence id the tracker refuses outright. Must equal UART_DISPATCH_SEQ_NONE
   in uart_dispatch.h; it is duplicated as a literal so this header stays
   independent of that one, and uart_dispatch.c carries a compile-time check
   that the two agree. */
#ifndef SCOPE_TRIG_SEQ_NONE
#define SCOPE_TRIG_SEQ_NONE      0xFFFFFFFFU
#endif

#define SCOPE_TRIG_U_USART1      0U
#define SCOPE_TRIG_U_USART2      1U
#define SCOPE_TRIG_U_UART4       2U
#define SCOPE_TRIG_U_UART5       3U
#define SCOPE_TRIG_U_COUNT       4U

/* ---------------------------------------------------------------------------
 * Counters - read these in the debugger's Live Expressions
 * ------------------------------------------------------------------------- */

#if SCOPE_TRIG_ENABLE

/* Frames currently accepted but not yet fully transmitted. The pin is HIGH iff
   this is non-zero in BURST mode. If it sits at a non-zero value with the pin
   stuck HIGH and no traffic, a UART transmit never completed - see
   scope_trig_tx_complete()'s note on the wedged-peripheral case. */
extern volatile uint32_t scope_trig_inflight;

/* Peak of scope_trig_inflight. How deep the backlog actually got, which is the
   number that says whether a merged BURST pulse covered 2 frames or 200. */
extern volatile uint32_t scope_trig_inflight_max;

/* Rising edges emitted - i.e. pulses on the wire, for cross-checking against
   the scope's own count. */
extern volatile uint32_t scope_trig_pulses;

/* Frames accepted while a pulse was already active, in PER-FRAME mode only.
   Always 0 in BURST mode, where nothing is ever skipped. A large value here
   means the scope is showing a small and possibly unrepresentative sample. */
extern volatile uint32_t scope_trig_skipped;

/* Transmit-completes that arrived with scope_trig_inflight already 0. Should
   stay 0. Non-zero means a completion was counted twice or came from a UART
   whose send was never counted - the bookkeeping is wrong and the pulse widths
   should not be trusted until it is understood. */
extern volatile uint32_t scope_trig_underflow;

/**
  * @brief  Drives the pin to its idle level and clears every counter.
  * @return None
  * @param  None
  *
  * Call once from main() after MX_GPIO_Init() and BEFORE osKernelStart().
  * MX_GPIO_Init() already leaves PE9 low, so this is not strictly required for
  * the pin - it exists to make the idle level explicit regardless of
  * SCOPE_TRIG_ACTIVE_LOW, and to zero the counters at a known point.
  */
void scope_trig_init(void);

/**
  * @brief  Marks a received frame - drives the pin to its ACTIVE level.
  * @return None
  * @param  None
  *
  * Called from task context (tcpip_thread for the HTTPS path, the stream task
  * for the WebSocket path) at the successful return of uart_dispatch_send().
  * Must be called ONLY when the frame really was queued: a call with no
  * matching transmit-complete leaves the pin active for ever in BURST mode.
  *
  * Compiled out when SCOPE_TRIG_FROM_NETWORK or SCOPE_TRIG_FROM_ETH is 1 - the
  * edge comes from elsewhere then, and having two sources raise one pin against
  * a single release would leave it permanently ACTIVE.
  *
  * DECLARED ONLY WHEN DEFINED, deliberately. An unconditional declaration lets
  * a stale call site compile and fail at LINK with an "unsupported relocation"
  * message that names neither the mode nor the mistake. Gating it here makes
  * the same error appear at the call site, in the file that is actually wrong.
  */
#if (!SCOPE_TRIG_FROM_NETWORK && !SCOPE_TRIG_FROM_ETH)
void scope_trig_frame_received(void);
#endif

/**
  * @brief  Marks a decrypted payload arriving from the network - drives the pin
  *         ACTIVE if no measurement is already running.
  * @return None
  * @param  None
  *
  * Only present when SCOPE_TRIG_FROM_NETWORK is 1. Call it as the FIRST thing
  * done with a newly received payload, before any parsing, or the parse time
  * lands outside the very window meant to contain it.
  *
  * A LATCH, NOT A COUNT. One arrival can yield no values (a fragment), one, or
  * several (a buffer holding many objects), so arrivals and completions do not
  * pair up one-for-one and a depth counter would drift. Instead the first
  * arrival while idle starts the pulse and the next followed-UART completion
  * ends it; arrivals during an active pulse are counted in scope_trig_skipped
  * and do not re-trigger.
  *
  * Declared only when defined - see the note on scope_trig_frame_received().
  */
#if (SCOPE_TRIG_FROM_NETWORK && !SCOPE_TRIG_FROM_ETH)
void scope_trig_net_arrival(void);
#endif

/* ---------------------------------------------------------------------------
 * SCOPE_TRIG_FROM_ETH API
 *
 * REAL FUNCTIONS IN THAT MODE, EMPTY INLINES OTHERWISE - see the #else at the
 * end of this block. The stubs exist so the call sites in stream_client.c can
 * read as plain calls instead of being wrapped in #if, and still cost nothing
 * when the mode is off. Declaring them unconditionally while defining them
 * conditionally is what produced the "unsupported relocation" link failure on
 * 27-08-2026; the pattern is not repeated here.
 * ------------------------------------------------------------------------- */
#if SCOPE_TRIG_FROM_ETH

/** Extra ETH receive interrupts that arrived while a measurement was already
    running. Expected to be non-zero - one frame takes several interrupts. If it
    climbs enormously faster than scope_trig_pulses, unrelated traffic is
    starting pulses early and the widths are inflated. */
extern volatile uint32_t scope_trig_eth_extra;

/** Objects whose sequence id could not be bound because no pulse was running.

    WHAT NON-ZERO MEANS DEPENDS ON THE ARMING MODE, and the two readings are
    opposite - so check SCOPE_TRIG_ARM_ON_SOCKET_DATA before drawing any
    conclusion from this number.

    ARM_ON_SOCKET_DATA == 0 (ISR arming): a FAULT. It should stay 0, and
    non-zero means the ETH hook is not firing at all, so the pin never moves.

    ARM_ON_SOCKET_DATA == 1 (socket arming): NORMAL under load. One socket read
    can deliver a TLS record holding several WebSocket frames. The first object
    commits and drops the pin; the rest are parsed with nothing armed and land
    here. They are extra objects that arrived free, not lost measurements. It
    climbing at a small fraction of scope_trig_pulses is expected; it climbing
    at roughly the same rate would mean the stream is consistently batching two
    objects per record and half the traffic is going unmeasured. */
extern volatile uint32_t scope_trig_unbound;

/** Transmit-completes discarded because their sequence id did not match the
    bound one. Non-zero is NORMAL and healthy - it is the per-sequence guard
    doing its job on a UART still draining an older sequence. */
extern volatile uint32_t scope_trig_seq_mismatch;

/* ---------------------------------------------------------------------------
 * LEAD TIME - the number that says whether a pulse can be trusted
 * ---------------------------------------------------------------------------
 * The Ethernet interrupt cannot know whether the packet that raised it carries
 * JSON. On a quiet link the first packet after the last pulse IS the frame, and
 * the pulse is honest. On a busy link an acknowledgement or a retransmission can
 * raise it first, and the pin then sits HIGH doing nothing until the real data
 * turns up - inflating the pulse by the whole idle gap.
 *
 * LEAD is the time from the rising edge to the moment the sequence id is
 * actually bound - that is, from "some packet arrived" to "the JSON for this
 * measurement is here". SPAN is the whole pulse.
 *
 *     lead ≈ 0        the packet that started the pulse WAS the data.
 *                     span is real processing time. Trust it.
 *
 *     lead ≈ span     the pulse was started by something unrelated and spent
 *                     nearly all its width waiting. The number is meaningless.
 *
 * So: subtract lead from span to get processing time, or read span alone only
 * while lead stays small. This is the practical test for whether
 * SCOPE_TRIG_FROM_ETH is usable on your network, and it replaces having to
 * judge scatter by eye on the scope.
 * ------------------------------------------------------------------------- */
extern volatile uint32_t scope_trig_lead_us_last;  /**< edge -> sequence bound */
extern volatile uint32_t scope_trig_lead_us_max;
extern volatile uint32_t scope_trig_span_us_last;  /**< whole pulse, edge->LOW */
extern volatile uint32_t scope_trig_span_us_max;

/** Pulses whose lead exceeded 1 ms - i.e. started by a packet that was almost
    certainly not the data. If this stays near 0 while scope_trig_pulses climbs,
    the link is quiet enough and the widths are honest. */
extern volatile uint32_t scope_trig_lead_over_1ms;

/** 0 if the cycle counter never started, in which case every microsecond figure
    above is a zero that means "not measured" rather than "instant". */
extern volatile uint8_t  scope_trig_dwt_ok;

/**
  * @brief  Starts a measurement - called from the Ethernet receive interrupt.
  * @return None
  * @param  None
  *
  * Call from ETH_IRQHandler USER CODE 0, before HAL_ETH_IRQHandler(), and only
  * when the interrupt really is a receive (test ETH_DMACSR_RI). Does nothing if
  * a measurement is already running.
  *
  * WHEN SCOPE_TRIG_ARM_ON_SOCKET_DATA IS 1 THIS NO LONGER ARMS. It still runs
  * and still counts, so scope_trig_eth_extra remains a live measure of how much
  * unrelated traffic the board is taking - which is the number that justifies
  * the mode. The call site in stm32h7xx_it.c is unchanged either way.
  */
void scope_trig_eth_rx(void);

/**
  * @brief  Starts a measurement at the first socket bytes of a stream frame.
  * @return None
  * @param  None
  *
  * Call from stream_bio_recv() immediately after lwip_recv() returns a positive
  * count, and only then. Does nothing if a measurement is already running, so
  * the several reads that make up one TLS record produce ONE pulse rather than
  * one each - the second and later reads are counted in scope_trig_eth_extra.
  *
  * The bytes are still ciphertext at this point; see SCOPE_TRIG_ARM_ON_SOCKET_
  * DATA above for exactly what this includes and what it leaves out.
  *
  * Compiled as a real function only when that switch is 1, for the same reason
  * the other mode-specific entry points are: an unconditional declaration lets
  * a stale call site fail at LINK rather than at the line that is wrong.
  */
#if SCOPE_TRIG_ARM_ON_SOCKET_DATA
void scope_trig_data_rx(void);
#else
static inline void scope_trig_data_rx(void) { }
#endif

/**
  * @brief  Binds a sequence id to the running measurement.
  * @return None
  * @param  seq: sequence_id just parsed out of a complete JSON object
  *
  * Called once per object, BEFORE any of its values are queued. Only the first
  * object after a rising edge binds; later ones are ignored until the pin drops.
  */
void scope_trig_seq_begin(uint32_t seq);

/**
  * @brief  Records that one UART accepted a message for the bound sequence.
  * @return None
  * @param  uart_idx: SCOPE_TRIG_U_*
  *
  * Call only when uart_dispatch_send() actually SUCCEEDED. The expected set is
  * built from real sends, so a dropped message cannot leave the pin waiting for
  * a completion that will never come.
  */
void scope_trig_seq_expect(uint8_t uart_idx);

/**
  * @brief  Marks the end of this object's sends - the expected set is complete.
  * @return None
  * @param  None
  *
  * Until this is called the tracker will not drop the pin, even if every
  * completion has already arrived. Without it, a UART that finished before the
  * remaining sends were queued would end the pulse early and report a latency
  * far shorter than reality.
  */
void scope_trig_seq_commit(void);

/**
  * @brief  Reports one UART's transmit-complete - called from ISR context.
  * @return None
  * @param  uart_idx: SCOPE_TRIG_U_*
  * @param  seq: sequence id the completing message carried
  *
  * Drops the pin when the bound sequence has been committed and every expected
  * UART has reported. A mismatched id is counted and discarded.
  */
void scope_trig_seq_uart_done(uint8_t uart_idx, uint32_t seq);

/**
  * @brief  Blocks until the pin has been idle for SCOPE_TRIG_MIN_IDLE_US.
  * @return None
  * @param  None
  *
  * Call from TASK CONTEXT ONLY, immediately after scope_trig_seq_commit(), and
  * never from an ISR - it spins.
  *
  * MUST NOT hold a critical section: this deliberately spins with interrupts
  * ENABLED so the Ethernet and transmit-complete interrupts continue to be
  * serviced throughout. Masking here would drop packets to make a trace look
  * tidy, which is the wrong trade in every direction.
  *
  * Returns immediately if no pulse has ended yet, if the required idle has
  * already elapsed, if the cycle counter is not running, or if
  * SCOPE_TRIG_MIN_IDLE_US is 0. The wait is therefore self-disabling rather
  * than something that can hang the stream task.
  */
void scope_trig_hold_idle(void);

#else /* SCOPE_TRIG_FROM_ETH == 0 - the tracker is not built */

/* Empty inlines, so every call site above compiles and vanishes. The counters
   are still declared as objects below rather than macros, because debugger
   expressions referencing them should not fail to resolve when the mode is off;
   they simply stay at zero. */
static inline void scope_trig_eth_rx(void)               { }
static inline void scope_trig_data_rx(void)              { }
static inline void scope_trig_hold_idle(void)            { }
static inline void scope_trig_seq_begin(uint32_t seq)    { (void)seq; }
static inline void scope_trig_seq_expect(uint8_t u)      { (void)u; }
static inline void scope_trig_seq_commit(void)           { }
static inline void scope_trig_seq_uart_done(uint8_t u, uint32_t s)
                                                         { (void)u; (void)s; }

#endif /* SCOPE_TRIG_FROM_ETH */

/**
  * @brief  Marks one transmission complete - drives the pin IDLE when the last
  *         outstanding frame is done.
  * @return None
  * @param  None
  *
  * Called from ISR context, inside HAL_UART_TxCpltCallback(). Does nothing but
  * a guarded decrement and at most one register write; no allocation, no
  * printf, nothing that could stretch the very window being measured.
  */
void scope_trig_tx_complete(void);

/**
  * @brief  Proves the pin and the bookkeeping actually work.
  * @return 0 if every check passed, otherwise the number of the first failing
  *         check (1..5)
  * @param  None
  *
  * WHY THIS EXISTS. A trigger that never moves looks exactly like a system with
  * no traffic, and a counter that never increments looks exactly like a quiet
  * link. Both failures are invisible on a scope: a flat line is the expected
  * picture until a frame arrives. This drives the pin both ways, reads it back
  * through the port's own register, and exercises the received/complete pair,
  * so a dead pin is reported at boot instead of being mistaken for silence.
  *
  * Leaves the pin at its idle level and all counters back at zero. Safe to call
  * before the scheduler starts; it must NOT be called while traffic is flowing,
  * because it deliberately moves the pin and resets the counters.
  */
int scope_trig_selftest(void);

#else /* SCOPE_TRIG_ENABLE == 0 */

/* Compiled out. Empty inlines rather than #defines so the call sites still have
   to be syntactically valid C, which stops the disabled build from rotting. */
static inline void scope_trig_init(void)           { }
static inline void scope_trig_frame_received(void) { }
static inline void scope_trig_net_arrival(void)    { }
static inline void scope_trig_tx_complete(void)    { }
static inline int  scope_trig_selftest(void)       { return 0; }
static inline void scope_trig_eth_rx(void)         { }
static inline void scope_trig_data_rx(void)        { }
static inline void scope_trig_hold_idle(void)      { }
static inline void scope_trig_seq_begin(uint32_t seq) { (void)seq; }
static inline void scope_trig_seq_expect(uint8_t u)   { (void)u; }
static inline void scope_trig_seq_commit(void)     { }
static inline void scope_trig_seq_uart_done(uint8_t u, uint32_t s) { (void)u; (void)s; }

#endif /* SCOPE_TRIG_ENABLE */

#endif /* __SCOPE_TRIG_H__ */
