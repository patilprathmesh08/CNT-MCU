/**
  ******************************************************************************
  * @file    vcom_tx.c
  * @brief   Non-blocking buffered console on the ST-LINK VCP - implementation
  * @version 1.0 - 28-08-2026
  *
  * See vcom_tx.h for why this exists and what the BSP does not provide.
  ******************************************************************************
  */

/* Includes ------------------------------------------------------------------*/
#include "vcom_tx.h"
#include "stm32h7xx_nucleo.h"
#include <string.h>

#if VCOM_TX_ENABLE

/* The BSP's UART handle array. hcom_uart[COM1] is USART3 on this board. */
extern UART_HandleTypeDef hcom_uart[COMn];

/* Private variables ---------------------------------------------------------*/

static uint8_t  Ring[VCOM_TX_RING_BYTES];
static volatile uint32_t Head;      /* next write position, task context   */
static volatile uint32_t Tail;      /* next byte to send, advanced by ISR  */
static volatile uint32_t Sending;   /* bytes handed to the current transmit */
static volatile uint8_t  Busy;      /* a transmit is in flight             */
static volatile uint8_t  Ready;     /* vcom_tx_init() has run              */

volatile uint32_t vcom_tx_bytes;
volatile uint32_t vcom_tx_dropped;
volatile uint32_t vcom_tx_chunks;
volatile uint32_t vcom_tx_high;

/* Private function prototypes -----------------------------------------------*/
static uint32_t vcom_lock(void);
static void     vcom_unlock(uint32_t primask);
static uint32_t vcom_used(void);
static void     vcom_kick(void);

/* Private functions ---------------------------------------------------------*/

/**
  * @brief  Masks interrupts, returning the previous PRIMASK.
  * @return PRIMASK before masking.
  * @param  None
  *
  * Saved and restored rather than a bare disable/enable pair: this is reached
  * from task context and from the USART3 ISR, and a bare enable would drop a
  * caller's own mask.
  */
static uint32_t vcom_lock(void)
{
    uint32_t primask = __get_PRIMASK();

    __disable_irq();

    return primask;
}

/**
  * @brief  Restores a PRIMASK saved by vcom_lock().
  * @return None
  * @param  primask: value from the matching vcom_lock()
  */
static void vcom_unlock(uint32_t primask)
{
    __set_PRIMASK(primask);
}

/**
  * @brief  Bytes currently queued.
  * @return Occupancy, 0..VCOM_TX_RING_BYTES-1.
  * @param  None
  *
  * Caller must hold the lock. One byte is always left free so a full ring and
  * an empty ring are distinguishable without a separate count.
  */
static uint32_t vcom_used(void)
{
    return (Head - Tail) % (uint32_t)VCOM_TX_RING_BYTES;
}

/**
  * @brief  Starts a transmit if one is not already running.
  * @return None
  * @param  None
  *
  * Caller must hold the lock. Sends the largest CONTIGUOUS run available, so a
  * wrap costs one extra transmit rather than a byte-by-byte copy.
  */
static void vcom_kick(void)
{
    if ((Busy == 0U) && (Ready != 0U) && (Head != Tail))
    {
        uint32_t run;

        if (Head > Tail)
        {
            run = Head - Tail;
        }
        else
        {
            /* Wrapped - send only as far as the end of the buffer. */
            run = (uint32_t)VCOM_TX_RING_BYTES - Tail;
        }

        if (run > (uint32_t)VCOM_TX_CHUNK_MAX)
        {
            run = (uint32_t)VCOM_TX_CHUNK_MAX;
        }
        else
        {
            /* Whole run fits in one transmit. */
        }

        if (HAL_UART_Transmit_IT(&hcom_uart[COM1], &Ring[Tail],
                                 (uint16_t)run) == HAL_OK)
        {
            Busy    = 1U;
            Sending = run;
            vcom_tx_chunks++;
        }
        else
        {
            /* The peripheral refused - usually BUSY from a transmit this module
               did not start. Left queued; the next completion or write retries.
               NOT dropped here: the bytes are still valid and the ring is the
               thing that decides when to discard. */
        }
    }
    else
    {
        /* Already sending, not initialised yet, or nothing to send. */
    }
}

/* Exported functions --------------------------------------------------------*/

uint32_t vcom_tx_write(const uint8_t *data, uint32_t len)
{
    uint32_t taken = 0U;
    uint32_t primask;

    if ((data == NULL) || (len == 0U))
    {
        return 0U;
    }
    else
    {
        /* Normal case. */
    }

    primask = vcom_lock();

    {
        /* -1 so a full ring never looks identical to an empty one. */
        uint32_t space = ((uint32_t)VCOM_TX_RING_BYTES - 1U) - vcom_used();
        uint32_t n     = (len <= space) ? len : space;
        uint32_t i;

        for (i = 0U; i < n; i++)
        {
            Ring[Head] = data[i];
            Head = (Head + 1U) % (uint32_t)VCOM_TX_RING_BYTES;
        }

        taken = n;
        vcom_tx_bytes += n;

        if (n < len)
        {
            /* DROPPED, NOT BLOCKED. See the header: a bounded buffer that
               waits for space is just a slower version of the blocking console
               this replaces. */
            vcom_tx_dropped += (len - n);
        }
        else
        {
            /* All accepted. */
        }

        if (vcom_used() > vcom_tx_high)
        {
            vcom_tx_high = vcom_used();
        }
        else
        {
            /* Not a new high-water mark. */
        }

        vcom_kick();
    }

    vcom_unlock(primask);

    return taken;
}

void vcom_tx_on_tx_complete(UART_HandleTypeDef *huart)
{
    if (huart->Instance == USART3)
    {
        uint32_t primask = vcom_lock();

        Tail    = (Tail + Sending) % (uint32_t)VCOM_TX_RING_BYTES;
        Sending = 0U;
        Busy    = 0U;

        vcom_kick();   /* straight into the next chunk, if any */

        vcom_unlock(primask);
    }
    else
    {
        /* One of the four dispatch UARTs - not ours. Checking the instance is
           what stops a dispatch completion advancing this ring and shredding
           the console output. */
    }
}

void vcom_tx_init(void)
{
    uint32_t primask;

    /* ---- 1. the interrupt the BSP never enables -------------------------
       Without this HAL_UART_Transmit_IT() starts, marks the handle BUSY_TX and
       never completes. Priority is below configLIBRARY_MAX_SYSCALL_INTERRUPT_
       PRIORITY so the handler may not call FreeRTOS APIs - it does not, it only
       runs HAL_UART_IRQHandler. */
    HAL_NVIC_SetPriority(USART3_IRQn, 6, 0);
    HAL_NVIC_EnableIRQ(USART3_IRQn);

    /* ---- 2. optional re-baud ------------------------------------------- */
#if (VCOM_TX_BAUD > 0U)
    if (hcom_uart[COM1].Init.BaudRate != (uint32_t)VCOM_TX_BAUD)
    {
        /* De-init and re-init rather than poking BRR: the HAL recomputes the
           divider from the current clock tree, which this code has no business
           duplicating. */
        (void)HAL_UART_DeInit(&hcom_uart[COM1]);
        hcom_uart[COM1].Init.BaudRate = (uint32_t)VCOM_TX_BAUD;
        (void)HAL_UART_Init(&hcom_uart[COM1]);
    }
    else
    {
        /* Already at the requested rate. */
    }
#endif

    primask = vcom_lock();
    Head    = 0U;
    Tail    = 0U;
    Sending = 0U;
    Busy    = 0U;
    Ready   = 1U;
    vcom_unlock(primask);

    vcom_tx_bytes   = 0U;
    vcom_tx_dropped = 0U;
    vcom_tx_chunks  = 0U;
    vcom_tx_high    = 0U;
}

/**
  * @brief  Console output override - replaces the weak _write() in syscalls.c.
  * @return Characters consumed, which is always len.
  * @param  file: unused
  * @param  ptr: characters
  * @param  len: how many
  *
  * ALWAYS REPORTS SUCCESS, even when bytes were dropped. printf() has nothing
  * useful to do with a short write to a console, and reporting one would make
  * it retry - turning a dropped diagnostic into a stalled task, which is the
  * failure this module exists to prevent. The loss is visible in
  * vcom_tx_dropped instead.
  *
  * BEFORE vcom_tx_init() RUNS this falls back to the BSP's blocking transmit,
  * so early output cannot be lost to initialisation order.
  */
int _write(int file, char *ptr, int len)
{
    (void)file;

    if ((ptr == NULL) || (len <= 0))
    {
        return 0;
    }
    else
    {
        /* Normal case. */
    }

    if (Ready == 0U)
    {
        /* Not yet buffered - blocking, exactly as the BSP would have done. */
        (void)HAL_UART_Transmit(&hcom_uart[COM1], (uint8_t *)ptr,
                                (uint16_t)len, 100U);
    }
    else
    {
        (void)vcom_tx_write((const uint8_t *)ptr, (uint32_t)len);
    }

    return len;
}

#endif /* VCOM_TX_ENABLE */
