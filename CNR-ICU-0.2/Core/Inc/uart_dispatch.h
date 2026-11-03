/**
  ******************************************************************************
  * @file    uart_dispatch.h
  * @brief   Shared message type + API bridging the TLS server (tcpip_thread)
  *          and the per-UART worker tasks
  * @version 2.0 - 29-07-2026 (H573 -> H753 port, 2 UARTs -> 4)
  *
  * Frame format (provisional - the actual project doesn't have a fixed
  * protocol decided yet, this is a deliberately simple placeholder that's
  * easy to change): the first byte of whatever a TLS client sends is a
  * UART selector, everything after it is the payload to transmit on that
  * UART:
  *     [1 byte: selector] [payload bytes...]
  *
  * Both directions (TLS -> UART request, UART -> TLS response) reuse the
  * SAME uart_dispatch_msg_t, heap-allocated by whichever side produces it
  * and freed by whichever side consumes it - this file only ever treats
  * the "conn" field as an opaque pointer; only tcp_echoserver.c actually
  * dereferences it (it owns the real struct tcp_echoserver_struct
  * definition), keeping this header genuinely independent of the TLS
  * connection's internal layout.
  *
  * PORTING NOTE (H573 -> H753): the H573 original dispatched to two UARTs,
  * USART3 and UART7. On the NUCLEO-H753ZI, USART3 (PD8/PD9) is wired to the
  * ST-LINK Virtual COM Port and is used as the printf debug console via
  * BSP_COM_Init(), so it is NOT available as a dispatch target. The four
  * dispatch UARTs below were chosen for having TX/RX pairs broken out on the
  * board's headers that do not collide with the Ethernet RMII pins, the
  * LEDs, or the USER button:
  *     USART1  PB6 / PB7
  *     USART2  PD5 / PD6
  *     UART4   PC10 / PC11
  *     UART5   PC12 / PD2
  ******************************************************************************
  */

#ifndef __UART_DISPATCH_H__
#define __UART_DISPATCH_H__

#include "cmsis_os2.h"
#include "stm32h7xx_hal.h"
#include <stdint.h>
#include <stddef.h>

/* Matches this project's other buffers (ECHO_BUF_SIZE=512 in
   tcp_echoserver.c) in spirit - comfortably larger than a short test
   command/response, not tuned against any real device's actual protocol
   yet since that isn't decided. Revisit once it is. */
#define UART_DISPATCH_MAX_PAYLOAD 128U

typedef struct
{
  void    *conn;                          /* opaque struct tcp_echoserver_struct* - only tcp_echoserver.c dereferences this */
  uint32_t seq;                            /* sequence id this message belongs to - see uart_dispatch_send_seq() */
  uint16_t len;                            /* valid bytes in data[] */
  uint8_t  data[UART_DISPATCH_MAX_PAYLOAD];
} uart_dispatch_msg_t;

/* First byte of every frame - which UART it's destined for/came from.
   0x01/0x02 kept from the H573 original (which used them for USART3/UART7)
   purely so existing PC-side test tooling that sends 0x01 still reaches
   *a* UART; 0x03/0x04 are new. Any PC-side script that assumed 0x01 ==
   USART3 needs updating - on this board 0x01 is USART1. */
#define UART_SELECTOR_USART1  0x01U
#define UART_SELECTOR_USART2  0x02U
#define UART_SELECTOR_UART4   0x03U
#define UART_SELECTOR_UART5   0x04U

/* Called from tcp_echoserver.c (tcpip_thread context) once a selector byte
   + payload have been split out of decrypted TLS data. Heap-allocates a
   uart_dispatch_msg_t and queues it to the matching UART task; that task
   owns freeing it once transmitted.
   Returns 0 on success; -1 for an unrecognized selector or oversized
   payload; -2 if allocation or the queue itself failed (queue full). */
/**
  * @brief Sequence id meaning "this message is not part of any measurement".
  *
  * WHY NOT 0.  Added 28-08-2026 with the NTP client. uart_dispatch_send() used
  * to tag untracked messages with 0, and 0 is a PERFECTLY VALID sequence_id -
  * the sample stream starts at "sequence_id":0 every time the server restarts.
  * An NTP epoch line finishing on USART1 would then have satisfied a scope
  * measurement bound to sequence 0, dropping PE9 early and reporting a latency
  * for a frame that had not finished. Rare, silent, and wrong.
  *
  * 0xFFFFFFFF is used instead and is rejected explicitly by the tracker. It is
  * not merely unlikely as a real id: it is the one value the tracker refuses.
  */
#define UART_DISPATCH_SEQ_NONE   0xFFFFFFFFU

int uart_dispatch_send(uint8_t selector, const uint8_t *payload, size_t len, void *conn);

/**
  * @brief  As uart_dispatch_send(), but tags the message with a sequence id.
  * @return 0 on success; -1 for an unrecognised selector or oversized payload;
  *         -2 if allocation or the queue failed.
  * @param  selector: UART_SELECTOR_*
  * @param  payload: bytes to transmit
  * @param  len: number of bytes at payload
  * @param  conn: opaque connection pointer, may be NULL
  * @param  seq: sequence id to carry with this message
  *
  * WHY THE ID HAS TO TRAVEL WITH THE MESSAGE. Added 27-08-2026 for the PE9
  * Ethernet-to-UART measurement, which ends its pulse only when ALL FOUR UARTs
  * have finished transmitting values from the SAME JSON object.
  *
  * The four finish at different times and at different rates, so when a
  * transmit-complete interrupt fires there is nothing in the peripheral to say
  * which object it belonged to. Without the tag, a UART still draining sequence
  * N-1 would end sequence N's pulse and report a latency for a sequence that
  * had not finished - producing a clean, plausible, wrong number.
  *
  * The task records this id before starting the transmit; the ISR reads it back
  * and reports it. No race: the task waits on the TX-done semaphore before
  * touching that slot again.
  *
  * uart_dispatch_send() is this function with seq 0, so the HTTPS POST path is
  * unchanged and untracked.
  */
int uart_dispatch_send_seq(uint8_t selector, const uint8_t *payload, size_t len,
                           void *conn, uint32_t seq);

/* Runs the generic "wait for a request -> transmit -> hand any response
   back to tcp_echoserver.c" loop for ONE UART. StartUsart1Task /
   StartUsart2Task / StartUart4Task / StartUart5Task in main.c each call
   this with their own peripheral/queue/semaphores/selector - the four tasks
   are otherwise identical, so the logic lives here once instead of being
   duplicated in each task body. Never returns.
   tx_done_sem: released by HAL_UART_TxCpltCallback() below once
   HAL_UART_Transmit_IT() actually finishes shifting the bytes out - added
   16-07-2026 (H573 original) to replace the previous blocking
   HAL_UART_Transmit() call, which busy-polled the CPU for the whole
   transmit time (~500-600us at 115200 baud) instead of letting other
   equal-priority tasks (notably tcpip_thread) run during that window. */
void uart_dispatch_task_run(UART_HandleTypeDef *huart, osMessageQueueId_t queue,
                             osSemaphoreId_t rx_done_sem, osSemaphoreId_t tx_done_sem,
                             uint8_t selector);

/* ===========================================================================
 * REPLY CAPTURE - added 07-08-2026 for the HTTP transport.
 * ===========================================================================
 * The H573 original's response path was removed on 15-07-2026 because it
 * blocked the transmit loop for up to 2000 ms waiting for a reply that never
 * came, throttling queue drain to one request every two seconds. Its author
 * left an explicit instruction for restoring it: do NOT reinstate the blocking
 * wait; start the receive, do not wait on it, and handle whatever
 * HAL_UARTEx_RxEventCallback() eventually reports independently of the
 * transmit loop's pace.
 *
 * This is that design. Each UART owns a "most recent reply" slot, filled from
 * the Rx callback in ISR context. Nothing ever waits for a reply, so the
 * transmit loop runs at full speed whether a device is attached or not.
 *
 * It also fits HTTP better than the original push model did. Over raw TCP the
 * connection stayed open and a late reply was written back onto it. httpd closes
 * after every response (LWIP_HTTPD_SUPPORT_11_KEEPALIVE is 0), so there is no
 * socket to push onto - a client polls GET /uart/last.json?sel=N instead, which
 * is exactly what a "last value" slot serves.
 * ======================================================================== */

/* A reply cannot be longer than a request payload - same buffer budget. */
#define UART_DISPATCH_MAX_REPLY  UART_DISPATCH_MAX_PAYLOAD

/**
  * @brief  Copies out the most recent reply received on one UART.
  * @param  selector: UART_SELECTOR_* identifying the UART
  * @param  buf: destination, at least buf_len bytes
  * @param  buf_len: capacity of buf
  * @param  out_len: receives the number of bytes copied
  * @param  out_seq: receives a counter that increments once per captured reply.
  *         A caller polling this endpoint uses it to tell "no new data yet"
  *         from "a new reply that happens to be identical to the last one" -
  *         comparing the payload alone cannot distinguish those.
  * @retval 0 on success (including "no reply yet", which yields len 0 and
  *         seq 0), -1 for an unrecognized selector.
  *
  * Safe to call from task context only. It briefly masks interrupts to copy the
  * slot, because the writer is HAL_UARTEx_RxEventCallback() in ISR context.
  */
int uart_dispatch_get_last(uint8_t selector, uint8_t *buf, size_t buf_len,
                           uint16_t *out_len, uint32_t *out_seq);

#endif /* __UART_DISPATCH_H__ */
