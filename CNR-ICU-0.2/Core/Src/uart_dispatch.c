/**
  ******************************************************************************
  * @file    uart_dispatch.c
  * @brief   Generic per-UART worker loop + TLS-side dispatch entry point
  * @version 2.0 - 29-07-2026 (H573 -> H753 port, 2 UARTs -> 4)
  *
  * The peripheral handles and the RTOS object handles are all declared
  * (non-static) in main.c but not exposed via main.h - CubeMX's built-in
  * FreeRTOS generator does not emit externs for them anywhere. Same
  * situation mbedtls_platform_glue.c already had with hrng, solved the same
  * way: extern declarations right here rather than editing the
  * CubeMX-managed main.h.
  *
  * (The H573 original could #include "app_freertos.h" for the RTOS handles,
  * because that project used the X-CUBE-FREERTOS pack, which generates such
  * a header. This project uses CubeMX's built-in FreeRTOS middleware, which
  * does not - hence the explicit externs below.)
  ******************************************************************************
  */

#include "uart_dispatch.h"
#include "main.h"
#include "FreeRTOS.h"
#include "task.h"     /* taskENTER_CRITICAL / taskEXIT_CRITICAL - FreeRTOS.h on
                         its own only provides the lower-level portENTER_CRITICAL */
/* vcom_tx_on_tx_complete() - the console shares the single global
   HAL_UART_TxCpltCallback with the four dispatch UARTs, so this file has to
   hand it on. See the else branch of that callback. */
#include "vcom_tx.h"

#include "scope_trig.h"  /* PE9 oscilloscope trigger. This file owns BOTH edges:
                            rising at the successful return of
                            uart_dispatch_send(), falling in
                            HAL_UART_TxCpltCallback(). Compiles to nothing when
                            SCOPE_TRIG_ENABLE is 0. */
#include <stdio.h>
#include <string.h>

/* SCOPE_TRIG_SELECTOR is a raw literal in scope_trig.h so that header stays
   independent of this one. Check here, where both are visible, that it really
   names one of the four dispatch UARTs - or 0 for "follow them all". A typo
   would leave the trigger following a peripheral that never transmits, which on
   a scope is indistinguishable from a board with no traffic. Fails the BUILD
   instead. */
/* The two "not part of a measurement" sentinels are declared in different
   headers so neither has to include the other. They must be the same value, or
   untracked UART traffic would start satisfying scope measurements again -
   exactly the fault the sentinel was introduced to remove. Fails the BUILD. */
#if SCOPE_TRIG_ENABLE
typedef char scope_trig_seq_none_check
    [(UART_DISPATCH_SEQ_NONE == SCOPE_TRIG_SEQ_NONE) ? 1 : -1];

typedef char scope_trig_selector_check
    [((SCOPE_TRIG_SELECTOR == 0U) ||
      (SCOPE_TRIG_SELECTOR == UART_SELECTOR_USART1) ||
      (SCOPE_TRIG_SELECTOR == UART_SELECTOR_USART2) ||
      (SCOPE_TRIG_SELECTOR == UART_SELECTOR_UART4)  ||
      (SCOPE_TRIG_SELECTOR == UART_SELECTOR_UART5)) ? 1 : -1];
#endif

/* Peripherals - CubeMX names the handle after the instance. */
extern UART_HandleTypeDef huart1;
extern UART_HandleTypeDef huart2;
extern UART_HandleTypeDef huart4;
extern UART_HandleTypeDef huart5;

/* Request queues, one per dispatch UART (item type uint32_t - see the
   pointer-as-payload note in uart_dispatch_send() below). */
extern osMessageQueueId_t Usart1TxQueueHandle;
extern osMessageQueueId_t Usart2TxQueueHandle;
extern osMessageQueueId_t Uart4TxQueueHandle;
extern osMessageQueueId_t Uart5TxQueueHandle;

/* Rx/Tx-done binary semaphores, one pair per dispatch UART. The callbacks
   below run in ISR context and need to map a UART instance back to its own
   semaphore, so they reference these directly rather than receiving them as
   parameters the way uart_dispatch_task_run() does. */
extern osSemaphoreId_t Usart1RxSemaphoreHandle;
extern osSemaphoreId_t Usart1TxDoneSemaphoreHandle;
extern osSemaphoreId_t Usart2RxSemaphoreHandle;
extern osSemaphoreId_t Usart2TxDoneSemaphoreHandle;
extern osSemaphoreId_t Uart4RxSemaphoreHandle;
extern osSemaphoreId_t Uart4TxDoneSemaphoreHandle;
extern osSemaphoreId_t Uart5RxSemaphoreHandle;
extern osSemaphoreId_t Uart5TxDoneSemaphoreHandle;

#if (SCOPE_TRIG_ENABLE && SCOPE_TRIG_FROM_ETH)
/* THE SEQUENCE EACH UART IS CURRENTLY TRANSMITTING.  Added 27-08-2026.
   -------------------------------------------------------------------------
   Written by uart_dispatch_task_run() immediately before HAL_UART_Transmit_IT(),
   read by HAL_UART_TxCpltCallback() in ISR context. This is what lets the
   completion interrupt say WHICH sequence just finished - the peripheral itself
   carries no such information.

   NO LOCK IS NEEDED, and the reason is structural rather than lucky: the task
   waits on tx_done_sem before it can reach the next message for that UART, so
   the write and the read can never overlap for a given slot. Each slot has
   exactly one writer and one reader, strictly alternating.

   volatile because the writer is a task and the reader an ISR; without it the
   compiler is entitled to keep the value in a register across the transmit. */
static volatile uint32_t tx_seq[SCOPE_TRIG_U_COUNT];

/**
  * @brief  Maps a UART selector to its scope-tracker bit index.
  * @return SCOPE_TRIG_U_*, or SCOPE_TRIG_U_COUNT if the selector is unknown.
  * @param  selector: UART_SELECTOR_*
  */
static uint8_t scope_index_for_selector(uint8_t selector)
{
  uint8_t idx;

  switch (selector)
  {
    case UART_SELECTOR_USART1: idx = (uint8_t)SCOPE_TRIG_U_USART1; break;
    case UART_SELECTOR_USART2: idx = (uint8_t)SCOPE_TRIG_U_USART2; break;
    case UART_SELECTOR_UART4:  idx = (uint8_t)SCOPE_TRIG_U_UART4;  break;
    case UART_SELECTOR_UART5:  idx = (uint8_t)SCOPE_TRIG_U_UART5;  break;
    default:                   idx = (uint8_t)SCOPE_TRIG_U_COUNT;  break;
  }

  return idx;
}
#endif /* SCOPE_TRIG_ENABLE && SCOPE_TRIG_FROM_ETH */

/* Written by HAL_UARTEx_RxEventCallback() (ISR context) right before
   releasing the matching semaphore, read by uart_dispatch_task_run()
   right after acquiring it - the semaphore release/acquire pair is what
   makes this safe (release happens-after the write, acquire happens-
   before the read), not the volatile qualifier by itself. */
static volatile uint16_t usart1_rx_len;
static volatile uint16_t usart2_rx_len;
static volatile uint16_t uart4_rx_len;
static volatile uint16_t uart5_rx_len;

/* ===========================================================================
 * REPLY CAPTURE (added 07-08-2026) - see the rationale in uart_dispatch.h.
 * ===========================================================================
 * One slot per UART, indexed by selector-1. rx[] is what the HAL DMA/IT engine
 * writes into; last[] is the completed reply a client can read. They are kept
 * separate so a partially-received frame is never visible to a reader.
 * ======================================================================== */
typedef struct
{
  uint8_t  rx[UART_DISPATCH_MAX_REPLY];    /* HAL receives into this          */
  uint8_t  last[UART_DISPATCH_MAX_REPLY];  /* most recent COMPLETE reply      */
  uint16_t last_len;                        /* bytes valid in last[]           */
  uint32_t seq;                             /* ++ per capture; 0 = none yet    */
} uart_reply_slot_t;

static uart_reply_slot_t reply_slot[4];

/* Maps a peripheral instance to its slot index, for the ISR callbacks which
   only receive a UART_HandleTypeDef. Returns -1 for anything not a dispatch
   UART - notably USART3, which is the ST-LINK VCP printf console and must never
   be treated as a bridge target. */
static int slot_index_for(const UART_HandleTypeDef *huart)
{
  if (huart->Instance == USART1) { return 0; }
  if (huart->Instance == USART2) { return 1; }
  if (huart->Instance == UART4)  { return 2; }
  if (huart->Instance == UART5)  { return 3; }
  return -1;
}

/* Same mapping from the selector byte, for task-context callers. */
static int slot_index_for_selector(uint8_t selector)
{
  switch (selector)
  {
    case UART_SELECTOR_USART1: return 0;
    case UART_SELECTOR_USART2: return 1;
    case UART_SELECTOR_UART4:  return 2;
    case UART_SELECTOR_UART5:  return 3;
    default:                   return -1;
  }
}

int uart_dispatch_get_last(uint8_t selector, uint8_t *buf, size_t buf_len,
                           uint16_t *out_len, uint32_t *out_seq)
{
  int idx = slot_index_for_selector(selector);
  uint16_t n;

  if ((idx < 0) || (buf == NULL) || (out_len == NULL) || (out_seq == NULL))
  {
    return -1;
  }

  /* Critical section rather than a lock-free scheme: the writer is an ISR, the
     payload is at most 128 bytes, and this runs on tcpip_thread where a few
     microseconds of masked interrupts is harmless. taskENTER_CRITICAL() does
     mask the UART ISR because that ISR calls osSemaphoreRelease(), so its
     priority must already be at or below configMAX_SYSCALL_INTERRUPT_PRIORITY -
     if it were not, the existing semaphore release would already be a defect. */
  taskENTER_CRITICAL();
  n = reply_slot[idx].last_len;
  if (n > buf_len) { n = (uint16_t)buf_len; }
  memcpy(buf, reply_slot[idx].last, n);
  *out_seq = reply_slot[idx].seq;
  taskEXIT_CRITICAL();

  *out_len = n;
  return 0;
}

static const char *selector_name(uint8_t selector)
{
  switch (selector)
  {
    case UART_SELECTOR_USART1: return "USART1";
    case UART_SELECTOR_USART2: return "USART2";
    case UART_SELECTOR_UART4:  return "UART4";
    case UART_SELECTOR_UART5:  return "UART5";
    default:                   return "(unknown)";
  }
}

int uart_dispatch_send(uint8_t selector, const uint8_t *payload, size_t len, void *conn)
{
  /* Untagged send. UART_DISPATCH_SEQ_NONE rather than 0, because 0 is a real
     sequence_id in this stream - see the note on that macro. The HTTPS POST
     path and the NTP epoch lines both come through here and neither is part of
     the Ethernet-to-UART measurement. */
  return uart_dispatch_send_seq(selector, payload, len, conn,
                                UART_DISPATCH_SEQ_NONE);
}

int uart_dispatch_send_seq(uint8_t selector, const uint8_t *payload, size_t len,
                           void *conn, uint32_t seq)
{
  osMessageQueueId_t queue;
  uart_dispatch_msg_t *msg;
  uint32_t msg_ptr_value;

  if (len > UART_DISPATCH_MAX_PAYLOAD)
  {
    return -1;
  }

  switch (selector)
  {
    case UART_SELECTOR_USART1:
      queue = Usart1TxQueueHandle;
      break;
    case UART_SELECTOR_USART2:
      queue = Usart2TxQueueHandle;
      break;
    case UART_SELECTOR_UART4:
      queue = Uart4TxQueueHandle;
      break;
    case UART_SELECTOR_UART5:
      queue = Uart5TxQueueHandle;
      break;
    default:
      return -1;
  }

  msg = (uart_dispatch_msg_t *)pvPortMalloc(sizeof(uart_dispatch_msg_t));
  if (msg == NULL)
  {
    return -2;
  }

  msg->conn = conn;
  msg->seq  = seq;
  msg->len = (uint16_t)len;
  memcpy(msg->data, payload, len);

  /* Queue item type is uint32_t (see the .ioc queue config) - the pointer
     itself is the payload, valid on this 32-bit target since sizeof(void*)
     == sizeof(uint32_t) here. */
  msg_ptr_value = (uint32_t)msg;
  if (osMessageQueuePut(queue, &msg_ptr_value, 0, 0) != osOK)
  {
    vPortFree(msg);
    return -2;
  }

  /* ===== SCOPE TRIGGER: RISING EDGE - "a frame was received" ==============
     Deliberately HERE and not at the top of the function. Every failure path
     above returns before this point, so a frame that was rejected - oversized,
     unknown selector, out of heap, queue full - is never counted. That matters
     more than it looks: in BURST mode a count with no matching transmit-
     complete would hold the pin HIGH for the rest of the run, and the trace
     would show one endless pulse instead of a measurement.

     The cost of placing it here rather than at function entry is that the
     pvPortMalloc, the memcpy and the queue put fall outside the pulse. That is
     well under a microsecond against transmit times of 500-600 us, so it does
     not move the number being measured.

     THIS IS THE CONVERGENCE POINT OF BOTH RECEIVE PATHS - the HTTPS POST
     handler in http_server.c and the WebSocket reader in stream_client.c both
     arrive here, which is why one call covers every frame regardless of
     transport. See scope_trig.h.

     FILTERED TO ONE UART since 27-08-2026. With the JSON extractor routing four
     fields to four peripherals, counting all of them would hold the pin HIGH
     until the last of the four drained - measuring the wrong thing. The
     matching filter is in HAL_UART_TxCpltCallback(); the two MUST agree or the
     count never returns to zero.

     SUPPRESSED ENTIRELY when SCOPE_TRIG_FROM_NETWORK is 1. In that mode the
     rising edge comes from stream_process_payload(), the moment a decrypted
     payload arrives, so that TLS decrypt, WebSocket framing and JSON extraction
     all fall INSIDE the measured window. Raising the pin here as well would
     raise it twice per value against a single latch release, leaving it stuck
     ACTIVE for the rest of the run. */
#if (SCOPE_TRIG_ENABLE && !SCOPE_TRIG_FROM_NETWORK && !SCOPE_TRIG_FROM_ETH)
#if (SCOPE_TRIG_SELECTOR != 0U)
  if (selector == (uint8_t)SCOPE_TRIG_SELECTOR)
  {
    scope_trig_frame_received();
  }
  else
  {
    /* A different UART - not what the trigger is following. */
  }
#else
  scope_trig_frame_received();   /* 0 = follow every dispatch UART */
#endif
#endif

  return 0;
}

/**
  * @brief  Fires from ISR context (idle-line or buffer-full, whichever
  *         HAL_UARTEx_ReceiveToIdle_IT() was waiting for) with Size = the
  *         actual number of bytes received - unlike a bare
  *         HAL_UART_Receive_IT(), which only completes once the exact
  *         requested length has arrived and would never fire early for a
  *         short reply.
  */
void HAL_UARTEx_RxEventCallback(UART_HandleTypeDef *huart, uint16_t Size)
{
  int idx = slot_index_for(huart);

  if (huart->Instance == USART1)
  {
    usart1_rx_len = Size;
    osSemaphoreRelease(Usart1RxSemaphoreHandle);
  }
  else if (huart->Instance == USART2)
  {
    usart2_rx_len = Size;
    osSemaphoreRelease(Usart2RxSemaphoreHandle);
  }
  else if (huart->Instance == UART4)
  {
    uart4_rx_len = Size;
    osSemaphoreRelease(Uart4RxSemaphoreHandle);
  }
  else if (huart->Instance == UART5)
  {
    uart5_rx_len = Size;
    osSemaphoreRelease(Uart5RxSemaphoreHandle);
  }

  /* ---- Reply capture, added 07-08-2026 ----------------------------------
     Publish the completed frame into last[] and bump seq. This is the whole
     "handle it independently of the transmit loop's pace" half of the design:
     nothing waits for this, so a UART with no device attached costs nothing.

     The semaphore releases above are left untouched. Nothing acquires those
     semaphores any more (uart_dispatch_task_run() discards rx_done_sem), but
     they and the *_rx_len statics are retained exactly as the original author
     left them - a release on a semaphore with no waiter is a no-op, and keeping
     them means the .ioc object list and the call signatures stay stable. */
  if (idx >= 0)
  {
    uint16_t n = (Size <= UART_DISPATCH_MAX_REPLY) ? Size : UART_DISPATCH_MAX_REPLY;

    memcpy(reply_slot[idx].last, reply_slot[idx].rx, n);
    reply_slot[idx].last_len = n;
    reply_slot[idx].seq++;

    /* Re-arm immediately so unsolicited data - a device that talks without
       being asked - is captured too, not just replies to our own transmits.
       HAL_BUSY here is benign and expected if a receive is somehow already
       active; there is nothing useful to do about it from an ISR. */
    (void)HAL_UARTEx_ReceiveToIdle_IT(huart, reply_slot[idx].rx,
                                      (uint16_t)UART_DISPATCH_MAX_REPLY);
  }
}

/**
  * @brief  Fires from ISR context once HAL_UART_Transmit_IT() has shifted
  *         the last byte out (TC interrupt, per the HAL's own IT-mode
  *         state machine) - added 16-07-2026 (H573 original) alongside the
  *         switch away from blocking HAL_UART_Transmit(). Does the minimum
  *         possible: release the matching task's TX-done semaphore, drop the
  *         scope trigger if this was the last frame outstanding, and return.
  *
  *         THE INSTANCE TEST IS LOAD-BEARING FOR THE MEASUREMENT, not just
  *         tidiness. This callback is the HAL's single global TX-complete hook,
  *         so it fires for EVERY UART that transmits by interrupt - including
  *         USART3, the ST-LINK VCP that carries printf. Counting a VCP
  *         completion as a dispatch completion would decrement
  *         scope_trig_inflight for a frame that was never counted, dropping the
  *         pin mid-pulse and truncating the pulse width, every time anything
  *         printed. The matched flag below is what confines the scope call to
  *         the four dispatch UARTs.
  */
void HAL_UART_TxCpltCallback(UART_HandleTypeDef *huart)
{
  /* Set only for the UART the scope trigger is following, so the scope call
     below cannot be reached by a VCP - or, since 27-08-2026, by one of the
     other three dispatch UARTs now that four JSON fields go to four different
     peripherals. The selector filter in uart_dispatch_send() is the matching
     half; if the two ever disagree the in-flight count never returns to zero
     and the pin stays HIGH for the rest of the run. */
  uint8_t matched = 0U;

  /* IN FROM_ETH MODE ALL FOUR UARTs REPORT, so SCOPE_TRIG_SELECTOR is ignored -
     the pulse ends only when every one of them has finished. In the older modes
     exactly one UART is followed and the selector picks it. Getting this wrong
     the other way round - leaving the selector filter in place here - would let
     three of the four completions vanish, and the pin would stay HIGH for ever
     waiting for reports that were being discarded. */
#if SCOPE_TRIG_FROM_ETH
#define SCOPE_TRIG_MATCH(sel)   (1U)
#else
#define SCOPE_TRIG_MATCH(sel)   ((SCOPE_TRIG_SELECTOR == 0U) ||                \
                                 (SCOPE_TRIG_SELECTOR == (sel)))
#endif

  if (huart->Instance == USART1)
  {
    osSemaphoreRelease(Usart1TxDoneSemaphoreHandle);
    matched = (uint8_t)SCOPE_TRIG_MATCH(UART_SELECTOR_USART1);
  }
  else if (huart->Instance == USART2)
  {
    osSemaphoreRelease(Usart2TxDoneSemaphoreHandle);
    matched = (uint8_t)SCOPE_TRIG_MATCH(UART_SELECTOR_USART2);
  }
  else if (huart->Instance == UART4)
  {
    osSemaphoreRelease(Uart4TxDoneSemaphoreHandle);
    matched = (uint8_t)SCOPE_TRIG_MATCH(UART_SELECTOR_UART4);
  }
  else if (huart->Instance == UART5)
  {
    osSemaphoreRelease(Uart5TxDoneSemaphoreHandle);
    matched = (uint8_t)SCOPE_TRIG_MATCH(UART_SELECTOR_UART5);
  }
  else
  {
    /* Some other UART finished transmitting - USART3, the ST-LINK VCP, being
       the one that actually occurs. Not a dispatch frame, so neither the
       semaphores nor the scope counter have anything to do with it.

       IT IS NOT IGNORED, THOUGH. vcom_tx.c drives the console with
       HAL_UART_Transmit_IT and needs this completion to start its next chunk;
       without the call the console would send one chunk and stop for ever.
       vcom_tx_on_tx_complete() checks the instance itself, so passing every
       completion through is safe. */
    vcom_tx_on_tx_complete(huart);
  }

  if (matched != 0U)
  {
#if SCOPE_TRIG_FROM_ETH
    /* ===== SCOPE TRIGGER: ONE UART REPORTS IN =============================
       Reports WHICH UART finished and WHICH sequence its message carried. The
       tracker drops the pin only once every expected UART has reported for the
       bound sequence; a completion from an older sequence is discarded there.

       tx_seq[] was written by the task just before it started this transmit -
       see the note where it is declared for why no lock is needed. */
    {
      uint8_t sidx = (uint8_t)SCOPE_TRIG_U_COUNT;

      if      (huart->Instance == USART1) { sidx = (uint8_t)SCOPE_TRIG_U_USART1; }
      else if (huart->Instance == USART2) { sidx = (uint8_t)SCOPE_TRIG_U_USART2; }
      else if (huart->Instance == UART4)  { sidx = (uint8_t)SCOPE_TRIG_U_UART4;  }
      else if (huart->Instance == UART5)  { sidx = (uint8_t)SCOPE_TRIG_U_UART5;  }
      else                                { /* unreachable - matched is set */ }

      if (sidx < (uint8_t)SCOPE_TRIG_U_COUNT)
      {
        scope_trig_seq_uart_done(sidx, tx_seq[sidx]);
      }
      else
      {
        /* Cannot happen while matched is non-zero. */
      }
    }
#else
    /* ===== SCOPE TRIGGER: FALLING EDGE - "transmission completed" =========
       The pin drops only when this was the LAST frame outstanding; with more
       still queued the pulse continues. That is what makes the width meaningful
       under back-to-back reception instead of ending at the first completion.
       See the mode discussion in scope_trig.h. */
    scope_trig_tx_complete();
#endif
  }
  else
  {
    /* Not ours - see above. */
  }
}

void uart_dispatch_task_run(UART_HandleTypeDef *huart, osMessageQueueId_t queue,
                             osSemaphoreId_t rx_done_sem, osSemaphoreId_t tx_done_sem,
                             uint8_t selector)
{
  uint32_t msg_ptr_value;
  uart_dispatch_msg_t *req;
  const char *uart_name = selector_name(selector);
  const int   idx       = slot_index_for_selector(selector);  /* reply slot, -1 if unknown */

  /* rx_done_sem is unused: reply capture is now done entirely in
     HAL_UARTEx_RxEventCallback(), which publishes into reply_slot[] rather than
     waking anyone. The parameter is kept so main.c's four call sites and the
     .ioc semaphore list stay stable. */
  (void)rx_done_sem;

  /* ---- ARM THE RECEIVER ONCE, UP FRONT.  Added 07-08-2026. --------------
     Fixes a gap in the first version of this reply-capture work: the receive
     was armed only AFTER a transmit, at the bottom of the loop below. That
     meant a device which speaks first - a sensor that streams, or anything
     sending a banner at power-up - was completely inaudible until the host
     happened to POST something to that UART. Worse, it made the endpoint look
     broken in exactly the case where it should be most useful.

     Arming here means reception is live from the moment the scheduler starts.
     The UART itself is already initialised: MX_USART1_UART_Init() and friends
     run in main() before osKernelStart(), so the peripheral and its pins are
     configured before any task body executes.

     HAL_BUSY cannot occur on this first call, but it is tolerated for the same
     reason as at the bottom of the loop - it would simply mean reception is
     already running, which is the desired state either way. */
  if (idx >= 0)
  {
    HAL_StatusTypeDef rx_status =
      HAL_UARTEx_ReceiveToIdle_IT(huart, reply_slot[idx].rx,
                                  (uint16_t)UART_DISPATCH_MAX_REPLY);

    if ((rx_status != HAL_OK) && (rx_status != HAL_BUSY))
    {
      printf("%s: initial ReceiveToIdle_IT failed (status %d)\r\n",
             uart_name, (int)rx_status);
    }
  }

  for (;;)
  {
    if (osMessageQueueGet(queue, &msg_ptr_value, NULL, osWaitForever) != osOK)
    {
      continue;
    }
    req = (uart_dispatch_msg_t *)msg_ptr_value;

    {
      /* Explicitly null-terminated local copy rather than printf's "%.*s"
         (dynamic-width precision) - this build's minimal nano.specs printf
         already turned out not to support "%zu" earlier in this project,
         so avoiding another possibly-unsupported specifier here rather
         than assuming it works. req->data is NOT null-terminated on its
         own (pvPortMalloc doesn't zero-fill), hence the explicit copy. */
      char print_buf[UART_DISPATCH_MAX_PAYLOAD + 1];
      uint16_t print_len = (req->len < UART_DISPATCH_MAX_PAYLOAD) ? req->len : UART_DISPATCH_MAX_PAYLOAD;

      memcpy(print_buf, req->data, print_len);
      print_buf[print_len] = '\0';
//      printf("Transmitting %u bytes on %s: \"%s\"\r\n", (unsigned int)req->len, uart_name, print_buf);
    }

    /* Interrupt-driven TX (changed 16-07-2026 from blocking HAL_UART_
       Transmit()): starts the transmit and returns immediately, then
       waits on tx_done_sem, which HAL_UART_TxCpltCallback() releases
       once the ISR reports completion. This doesn't transmit any faster
       (still bounded by the UART's baud rate - 115200 baud here), but it
       frees the CPU during the ~500-600us a short frame takes to shift
       out, instead of busy-polling status flags for that whole window -
       time other equal-priority tasks (notably tcpip_thread) can now use
       instead. The 1000ms wait is a safety net against a wedged
       peripheral, not an expected wait time. */
#if (SCOPE_TRIG_ENABLE && SCOPE_TRIG_FROM_ETH)
    /* PUBLISH THE SEQUENCE BEFORE STARTING THE TRANSMIT, never after. The
       TX-complete interrupt can fire the moment Transmit_IT() has shifted the
       last byte - for a one-byte joystick value at 2 Mbaud that is about 5 us -
       so writing this afterwards would race the ISR and report whatever the
       previous message left behind. */
    {
      uint8_t sidx = scope_index_for_selector(selector);

      if (sidx < (uint8_t)SCOPE_TRIG_U_COUNT)
      {
        tx_seq[sidx] = req->seq;
      }
      else
      {
        /* Unknown selector - cannot happen, the task was started with one of
           the four. */
      }
    }
#endif

    if (HAL_UART_Transmit_IT(huart, req->data, req->len) != HAL_OK)
    {
      printf("HAL_UART_Transmit_IT failed on %s\r\n", uart_name);

      /* ===== SCOPE TRIGGER: RELEASE A FRAME THAT WILL NEVER COMPLETE =======
         The transmit never started, so HAL_UART_TxCpltCallback() will never
         fire for it - but uart_dispatch_send() already counted it. Without
         this the count would never return to zero and the pin would stay HIGH
         for the rest of the run, turning the whole trace into one endless
         pulse. Balancing it here keeps the bookkeeping exact through the
         failure path as well as the happy one.

         Filtered on the same selector as the increment: releasing here for a
         UART the trigger is not following would decrement a count this UART
         never contributed to, dropping the pin in the middle of another
         peripheral's pulse. */
#if (SCOPE_TRIG_ENABLE && SCOPE_TRIG_FROM_ETH)
      /* The transmit never started, so no TX-complete interrupt will ever fire
         for this message. The tracker is counting on a report from this UART
         and would otherwise hold the pin HIGH for ever, turning the whole trace
         into one endless pulse. Reporting it as done is the honest thing: the
         message is not going to arrive, and the measurement should not stall
         waiting for it. */
      {
        uint8_t sidx = scope_index_for_selector(selector);

        if (sidx < (uint8_t)SCOPE_TRIG_U_COUNT)
        {
          scope_trig_seq_uart_done(sidx, req->seq);
        }
        else
        {
          /* Unknown selector - cannot happen here. */
        }
      }
#elif SCOPE_TRIG_ENABLE
#if (SCOPE_TRIG_SELECTOR != 0U)
      if (selector == (uint8_t)SCOPE_TRIG_SELECTOR)
      {
        scope_trig_tx_complete();
      }
      else
      {
        /* Not the followed UART - nothing was counted for it. */
      }
#else
      scope_trig_tx_complete();
#endif
#endif
    }
    else if (osSemaphoreAcquire(tx_done_sem, 1000) != osOK)
    {
      printf("HAL_UART_TxCpltCallback timeout on %s\r\n", uart_name);

      /* NO scope release here, and that is deliberate. The transmit DID start,
         so the completion interrupt is still pending as far as the peripheral
         is concerned and may yet arrive - releasing now would let that late
         callback decrement a second time for one frame, dropping the pin during
         somebody else's pulse. The 1000 ms is a safety net for a wedged
         peripheral, not a normal outcome; if it really is wedged the pin stays
         HIGH, which is a visible fault. Cross-check scope_trig_inflight against
         a link that has gone quiet. */
    }
    else
    {
      /* Transmitted and confirmed. HAL_UART_TxCpltCallback() has already
         dropped the scope pin if this was the last frame outstanding. */
    }

    /* ---- Response handling RESTORED 07-08-2026, asynchronously ------------
       History: this was HAL_UARTEx_ReceiveToIdle_IT() followed by a blocking
       osSemaphoreAcquire() of up to 2000 ms, removed on 15-07-2026 because with
       no device attached that wait never succeeded and throttled this task to
       one request every two seconds - backwards from what is wanted.

       Its author left the condition for bringing it back: do NOT restore the
       blocking wait; start the receive, do not wait on it, and handle whatever
       HAL_UARTEx_RxEventCallback() reports independently of this loop's pace.

       That is exactly what happens now. We ARM the receive and immediately move
       on to the next queued request. The callback publishes any completed frame
       into the per-UART reply slot and re-arms itself, so this loop never blocks
       and a UART with nothing attached costs nothing at all.

       HAL_BUSY is the normal, expected return when the callback has already
       re-armed this UART - it means reception is running, which is what we want.
       Only a genuinely different error is worth reporting. */
    if (idx >= 0)
    {
      HAL_StatusTypeDef rx_status =
        HAL_UARTEx_ReceiveToIdle_IT(huart, reply_slot[idx].rx,
                                    (uint16_t)UART_DISPATCH_MAX_REPLY);

      if ((rx_status != HAL_OK) && (rx_status != HAL_BUSY))
      {
        printf("HAL_UARTEx_ReceiveToIdle_IT failed on %s (status %d)\r\n",
               uart_name, (int)rx_status);
      }
    }

    vPortFree(req);
  }
}
