/**
  ******************************************************************************
  * @file    vcom_tx.h
  * @brief   Non-blocking, buffered console output on the ST-LINK VCP (USART3)
  * @version 1.0 - 28-08-2026
  *
  * Replaces the BSP's blocking console with a ring buffer and interrupt-driven
  * transmit, and optionally raises the VCP baud rate.
  *
  * ===========================================================================
  * WHAT WAS WRONG WITH THE STOCK CONSOLE
  * ===========================================================================
  * printf() reaches the VCP through _write() -> __io_putchar() in
  * stm32h7xx_nucleo.c, which calls the BLOCKING HAL_UART_Transmit(), one byte
  * at a time, with a poll timeout. The calling task therefore busy-waits for
  * the entire transmission:
  *
  *     one ~170-byte JSON frame at 115200 baud  =  14.8 ms of blocking
  *     the same frame at 2 Mbaud                =   0.85 ms
  *
  * At one frame a second that is 1.5 percent of the time and tolerable. At the
  * 100 frames a second this stream has previously run at, it is 1480 ms of
  * blocking per second - the task simply cannot keep up, and it blocks inside
  * the TLS receive path while failing to.
  *
  * ===========================================================================
  * WHAT THIS DOES INSTEAD
  * ===========================================================================
  * _write() copies into a ring buffer and returns. A transmit runs in the
  * background from the USART3 interrupt, one CONTIGUOUS CHUNK at a time rather
  * than one byte at a time, so a 170-byte line is one HAL_UART_Transmit_IT call
  * rather than 170 blocking ones.
  *
  * OVERFLOW DROPS, IT DOES NOT BLOCK. That is the whole point: a bounded buffer
  * that blocks when full is just a slower version of the original problem. Bytes
  * that do not fit are discarded and counted in vcom_tx_dropped. A console is
  * diagnostic output - losing some of it under load is the correct trade against
  * stalling the application that produced it.
  *
  * ===========================================================================
  * TWO THINGS THE BSP DOES NOT DO, WHICH THIS DEPENDS ON
  * ===========================================================================
  * 1. COM1_MspInit() in stm32h7xx_nucleo.c NEVER ENABLES THE USART3 NVIC
  *    INTERRUPT. It enables the clock and the pins and stops there, because the
  *    stock console is polled and does not need it.
  * 2. stm32h7xx_it.c CONTAINS NO USART3_IRQHandler, for the same reason.
  *
  * Without both, HAL_UART_Transmit_IT() starts a transmit, marks the handle
  * BUSY_TX, and never completes - every later call returns HAL_BUSY and the
  * console dies after the first line. vcom_tx_init() enables the interrupt, and
  * the handler lives in stm32h7xx_it.c USER CODE 1.
  *
  * Neither needs an .ioc change. USART3 is owned by the BSP and is not in the
  * pinout at all, so CubeMX will never generate a competing handler.
  ******************************************************************************
  */

#ifndef __VCOM_TX_H__
#define __VCOM_TX_H__

#include "main.h"
#include <stdint.h>

/* ---------------------------------------------------------------------------
 * Configuration
 * ------------------------------------------------------------------------- */

/* 1 installs the buffered console, 0 leaves the BSP's blocking one alone.
   Set to 0 to get the original behaviour back without removing this file. */
#ifndef VCOM_TX_ENABLE
#define VCOM_TX_ENABLE          1
#endif

/* Ring buffer size, bytes. Sized to hold a burst rather than a steady stream:
   at 2 Mbaud the UART drains 200 bytes per millisecond, so 4 KB is about 20 ms
   of backlog - comfortably more than any single burst of boot messages, and
   cheap in the 512 KB of AXI SRAM this part has. */
#ifndef VCOM_TX_RING_BYTES
#define VCOM_TX_RING_BYTES      4096U
#endif

/* Largest single HAL_UART_Transmit_IT. Bounds how long one transmit occupies
   the peripheral before the buffer is re-examined; smaller means newly queued
   output starts sooner, larger means fewer completion interrupts. */
#ifndef VCOM_TX_CHUNK_MAX
#define VCOM_TX_CHUNK_MAX       256U
#endif

/* VCP baud rate. 0 leaves whatever BSP_COM_Init() configured, currently 115200.
   2000000 verified safe on this bench: the ST-LINK is a V3E (USB PID 0x374E),
   which handles multi-megabaud VCP comfortably. An ST-LINK V2-1 (PID 0x374B)
   would NOT - 921600 is the safe ceiling there - so check before assuming this
   value travels to another board.

   Remember to change the terminal to match, or the log becomes line noise. */
#ifndef VCOM_TX_BAUD
#define VCOM_TX_BAUD            2000000U
#endif

/* ---------------------------------------------------------------------------
 * Counters - read in the debugger
 * ------------------------------------------------------------------------- */

extern volatile uint32_t vcom_tx_bytes;    /**< bytes accepted into the ring  */
extern volatile uint32_t vcom_tx_dropped;  /**< bytes discarded, ring full    */
extern volatile uint32_t vcom_tx_chunks;   /**< HAL_UART_Transmit_IT calls    */
extern volatile uint32_t vcom_tx_high;     /**< high-water ring occupancy     */

/**
  * @brief  Enables the USART3 interrupt, optionally re-bauds the VCP, and takes
  *         over console output.
  * @return None
  * @param  None
  *
  * Call BEFORE the first printf whose output matters - the top of USER CODE 5
  * in StartEthIfTask, ahead of the banner - so the whole log comes out at the
  * new rate rather than switching part way through.
  *
  * Until this runs, _write() falls back to the BSP's blocking path, so nothing
  * printed early is lost regardless of ordering.
  */
void vcom_tx_init(void);

/**
  * @brief  Feeds the USART3 transmit-complete event to the ring.
  * @return None
  * @param  huart: the completing UART; anything other than USART3 is ignored
  *
  * HAL_UART_TxCpltCallback() is a single global hook shared with the four
  * dispatch UARTs, so uart_dispatch.c owns it and calls this. Ignoring the
  * instance check there would let a dispatch completion advance the console
  * ring and corrupt the output.
  */
void vcom_tx_on_tx_complete(UART_HandleTypeDef *huart);

/**
  * @brief  Queues bytes for transmission without blocking.
  * @return Bytes accepted; less than len means the ring was full.
  * @param  data: bytes to send
  * @param  len: how many
  *
  * printf() reaches this through the _write() override, so calling it directly
  * is only needed to send bytes that are not text - a raw frame dump, say.
  */
uint32_t vcom_tx_write(const uint8_t *data, uint32_t len);

#endif /* __VCOM_TX_H__ */
