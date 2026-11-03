/* USER CODE BEGIN Header */
/**
  ******************************************************************************
  * @file           : main.c
  * @brief          : Main program body
  ******************************************************************************
  * @attention
  *
  * Copyright (c) 2026 STMicroelectronics.
  * All rights reserved.
  *
  * This software is licensed under terms that can be found in the LICENSE file
  * in the root directory of this software component.
  * If no LICENSE file comes with this software, it is provided AS-IS.
  *
  ******************************************************************************
  */
/* USER CODE END Header */
/* Includes ------------------------------------------------------------------*/
#include "main.h"
#include "FreeRTOS.h"
#include "cmsis_os2.h"
#include "mbedtls.h"

/* Private includes ----------------------------------------------------------*/
/* USER CODE BEGIN Includes */
#include "http_server.h"
#include "uart_dispatch.h"   /* uart_dispatch_task_run(), UART_SELECTOR_* */
#include "lwip.h"            /* MX_LWIP_Init(). CubeMX emitted this include ITSELF
                                until mbedTLS was enabled, then stopped - see the
                                long note in StartEthIfTask(). It lives inside USER
                                CODE from now on so it cannot be lost again. */
#include "lwip/netif.h"      /* netif_list - the double-init guard in StartEthIfTask() */
#include "lwip/opt.h"
#include "lwip/pbuf.h"
#include "lwip/stats.h"
#include "lwip/tcpip.h"      /* tcpip_callback() - httpd_init() must run on tcpip_thread */
#include "ethernetif.h"      /* ethernet_link_thread() - RTOS replacement for
                                ethernet_link_check_state() */
#include "lwip/dhcp.h"       /* dhcp_supplied_address() - the lease wait in
                                StartEthIfTask(). Added 24-08-2026 with DHCP; see
                                the note in LWIP/Target/lwipopts.h. */
#include "stream_client.h"   /* the outbound HTTPS stream client, added 24-08-2026 */
#include "mdns_service.h"    /* mDNS hostname resolution, added 10-09-2026. The
                                task and the policy live there; this file only
                                starts it. Compiles to a stub when
                                MDNS_RESOLVER_ENABLE is 0. */
#include "vcom_tx.h"        /* Buffered non-blocking console on the ST-LINK VCP,
                               added 28-08-2026. vcom_tx_init() is the FIRST
                               thing StartEthIfTask does, so the whole log comes
                               out at VCOM_TX_BAUD. */
#include "ntp_client.h"      /* SNTP client and the free-running epoch clock,
                                added 28-08-2026. Started from StartEthIfTask
                                after the address is up; needs no .ioc change,
                                because it rides the existing TIM6 HAL tick. */
#include "json_parser.h"     /* The boot self-test, added 27-08-2026. The field
                                table, the routing to the four UARTs and the
                                extraction itself all live in stream_client.c;
                                main.c only runs the test and reports it. */
#include "scope_trig.h"      /* PE9 oscilloscope trigger, added 26-08-2026. Only
                                init and the boot self-test are called from this
                                file; both signal edges belong to
                                uart_dispatch.c. */
#include <stdio.h>
/* USER CODE END Includes */

/* Private typedef -----------------------------------------------------------*/
/* USER CODE BEGIN PTD */

/* USER CODE END PTD */

/* Private define ------------------------------------------------------------*/
/* USER CODE BEGIN PD */

/* USER CODE END PD */

/* Private macro -------------------------------------------------------------*/
/* USER CODE BEGIN PM */

/* USER CODE END PM */

/* Private variables ---------------------------------------------------------*/

COM_InitTypeDef BspCOMInit;

RNG_HandleTypeDef hrng;

UART_HandleTypeDef huart4;
UART_HandleTypeDef huart5;
UART_HandleTypeDef huart1;
UART_HandleTypeDef huart2;

/* Definitions for EthIf */
osThreadId_t EthIfHandle;
const osThreadAttr_t EthIf_attributes = {
  .name = "EthIf",
  .stack_size = 512 * 4,
  .priority = (osPriority_t) osPriorityAboveNormal,
};
/* Definitions for Usart1Task */
osThreadId_t Usart1TaskHandle;
const osThreadAttr_t Usart1Task_attributes = {
  .name = "Usart1Task",
  .stack_size = 512 * 4,
  .priority = (osPriority_t) osPriorityNormal,
};
/* Definitions for Usart2Task */
osThreadId_t Usart2TaskHandle;
const osThreadAttr_t Usart2Task_attributes = {
  .name = "Usart2Task",
  .stack_size = 512 * 4,
  .priority = (osPriority_t) osPriorityNormal,
};
/* Definitions for Uart4Task */
osThreadId_t Uart4TaskHandle;
const osThreadAttr_t Uart4Task_attributes = {
  .name = "Uart4Task",
  .stack_size = 512 * 4,
  .priority = (osPriority_t) osPriorityNormal,
};
/* Definitions for Uart5Task */
osThreadId_t Uart5TaskHandle;
const osThreadAttr_t Uart5Task_attributes = {
  .name = "Uart5Task",
  .stack_size = 512 * 4,
  .priority = (osPriority_t) osPriorityNormal,
};
/* Definitions for Usart1TxQueue */
osMessageQueueId_t Usart1TxQueueHandle;
const osMessageQueueAttr_t Usart1TxQueue_attributes = {
  .name = "Usart1TxQueue"
};
/* Definitions for Usart2TxQueue */
osMessageQueueId_t Usart2TxQueueHandle;
const osMessageQueueAttr_t Usart2TxQueue_attributes = {
  .name = "Usart2TxQueue"
};
/* Definitions for Uart4TxQueue */
osMessageQueueId_t Uart4TxQueueHandle;
const osMessageQueueAttr_t Uart4TxQueue_attributes = {
  .name = "Uart4TxQueue"
};
/* Definitions for Uart5TxQueue */
osMessageQueueId_t Uart5TxQueueHandle;
const osMessageQueueAttr_t Uart5TxQueue_attributes = {
  .name = "Uart5TxQueue"
};
/* Definitions for DhcpFineTimer */
osTimerId_t DhcpFineTimerHandle;
const osTimerAttr_t DhcpFineTimer_attributes = {
  .name = "DhcpFineTimer"
};
/* Definitions for LinkCheckTimer */
osTimerId_t LinkCheckTimerHandle;
const osTimerAttr_t LinkCheckTimer_attributes = {
  .name = "LinkCheckTimer"
};
/* Definitions for EthRxSemaphore */
osSemaphoreId_t EthRxSemaphoreHandle;
const osSemaphoreAttr_t EthRxSemaphore_attributes = {
  .name = "EthRxSemaphore"
};
/* Definitions for Usart1RxSemaphore */
osSemaphoreId_t Usart1RxSemaphoreHandle;
const osSemaphoreAttr_t Usart1RxSemaphore_attributes = {
  .name = "Usart1RxSemaphore"
};
/* Definitions for Usart1TxDoneSemaphore */
osSemaphoreId_t Usart1TxDoneSemaphoreHandle;
const osSemaphoreAttr_t Usart1TxDoneSemaphore_attributes = {
  .name = "Usart1TxDoneSemaphore"
};
/* Definitions for Usart2RxSemaphore */
osSemaphoreId_t Usart2RxSemaphoreHandle;
const osSemaphoreAttr_t Usart2RxSemaphore_attributes = {
  .name = "Usart2RxSemaphore"
};
/* Definitions for Usart2TxDoneSemaphore */
osSemaphoreId_t Usart2TxDoneSemaphoreHandle;
const osSemaphoreAttr_t Usart2TxDoneSemaphore_attributes = {
  .name = "Usart2TxDoneSemaphore"
};
/* Definitions for Uart4RxSemaphore */
osSemaphoreId_t Uart4RxSemaphoreHandle;
const osSemaphoreAttr_t Uart4RxSemaphore_attributes = {
  .name = "Uart4RxSemaphore"
};
/* Definitions for Uart4TxDoneSemaphore */
osSemaphoreId_t Uart4TxDoneSemaphoreHandle;
const osSemaphoreAttr_t Uart4TxDoneSemaphore_attributes = {
  .name = "Uart4TxDoneSemaphore"
};
/* Definitions for Uart5RxSemaphore */
osSemaphoreId_t Uart5RxSemaphoreHandle;
const osSemaphoreAttr_t Uart5RxSemaphore_attributes = {
  .name = "Uart5RxSemaphore"
};
/* Definitions for Uart5TxDoneSemaphore */
osSemaphoreId_t Uart5TxDoneSemaphoreHandle;
const osSemaphoreAttr_t Uart5TxDoneSemaphore_attributes = {
  .name = "Uart5TxDoneSemaphore"
};
/* USER CODE BEGIN PV */
/* Defined in LWIP/App/lwip.c - the single network interface this project uses.
   Referenced here to report its address and link state, and to install the
   hardened Tx/Rx handlers (see USER CODE 3 in lwip.c). */
extern struct netif gnetif;

/* Defined in LWIP/Target/ethernetif.c (USER CODE 2). Tells us whether the
   LAN8742 was actually found over MDIO, which the stock code fails silently. */
extern volatile uint8_t eth_phy_detected;

/* ---- WHY THE OTHER eth_* COUNTERS ARE NOT DECLARED HERE ------------------
   Cleaned up 07-08-2026. This block used to carry 14 further externs -
   eth_rx_frames, eth_tx_frames, eth_tx_calls/ok/fail/err_code/dma_err/gstate,
   eth_input_calls/err, eth_arp_rx/for_us, eth_tx_chain_over, eth_tx_busy_wait.
   Every one of them was UNUSED: they existed for the ISR-era health printf in
   the bare-metal superloop, and that whole region went away with FreeRTOS
   (everything after osKernelStart() was unreachable).

   They are NOT being reinstated with a new printf, deliberately. printf() here
   is blocking on USART3 at 115200 and one ~98-character line costs about 8.5 ms
   - which would land directly on the RTT this project exists to measure. That
   mistake has already been made once in this codebase and produced a bogus 23x
   regression (8.441 ms measured against a true 0.362 ms).

   Read them in the debugger instead. They are plain globals in ethernetif.c, so
   STM32CubeIDE Live Expressions shows them with no firmware cost at all. The
   ones worth watching:
     eth_tx_busy_wait   Tx ring full of in-flight frames; each occurrence costs
                        up to ETH_TX_BUSY_WAIT_MS (20 ms) and blocks
                        tcpip_thread. Explains a ~20 ms latency tail.
     eth_tx_chain_over  pbuf chains longer than ETH_TX_DESC_CNT, linearised by
                        pbuf_clone(). Should stay 0 with a 24-deep ring.
     eth_rbu_isr        Receive-Buffer-Unavailable. Should stay 0 with 16/32.
     eth_tx_fail        transmits the HAL refused outright. Should stay 0.
   ---------------------------------------------------------------------- */
/* USER CODE END PV */

/* Private function prototypes -----------------------------------------------*/
void SystemClock_Config(void);
static void MPU_Config(void);
static void MX_GPIO_Init(void);
static void MX_UART4_Init(void);
static void MX_UART5_Init(void);
static void MX_USART1_UART_Init(void);
static void MX_USART2_UART_Init(void);
static void MX_RNG_Init(void);
void StartEthIfTask(void *argument);
void StartUsart1Task(void *argument);
void StartUsart2Task(void *argument);
void StartUart4Task(void *argument);
void StartUart5Task(void *argument);
void DhcpFineTimerCallback(void *argument);
void LinkCheckTimerCallback(void *argument);

/* USER CODE BEGIN PFP */

/* USER CODE END PFP */

/* Private user code ---------------------------------------------------------*/
/* USER CODE BEGIN 0 */

/* USER CODE END 0 */

/**
  * @brief  The application entry point.
  * @retval int
  */
int main(void)
{

  /* USER CODE BEGIN 1 */

  /* USER CODE END 1 */

  /* MPU Configuration--------------------------------------------------------*/
  MPU_Config();

  /* Enable the CPU Cache */

  /* Enable I-Cache---------------------------------------------------------*/
  SCB_EnableICache();

  /* Enable D-Cache---------------------------------------------------------*/
  SCB_EnableDCache();

  /* MCU Configuration--------------------------------------------------------*/

  /* Reset of all peripherals, Initializes the Flash interface and the Systick. */
  HAL_Init();

  /* USER CODE BEGIN Init */

  /* USER CODE END Init */

  /* Configure the system clock */
  SystemClock_Config();

  /* USER CODE BEGIN SysInit */

  /* USER CODE END SysInit */

  /* Initialize all configured peripherals */
  MX_GPIO_Init();
  MX_UART4_Init();
  MX_UART5_Init();
  MX_USART1_UART_Init();
  MX_USART2_UART_Init();
  MX_RNG_Init();
  /* Call PreOsInit function */
  MX_MBEDTLS_Init();
  /* USER CODE BEGIN 2 */
//  while(1)
//  {HAL_Delay(10);
//	  HAL_GPIO_WritePin(GPIOE, GPIO_PIN_9, SET);
//	  HAL_Delay(10);
//	  	  HAL_GPIO_WritePin(GPIOE, GPIO_PIN_9, RESET);
//  }
  /* USER CODE END 2 */

  /* Init scheduler */
  osKernelInitialize();

  /* USER CODE BEGIN RTOS_MUTEX */
  /* add mutexes, ... */
  /* USER CODE END RTOS_MUTEX */

  /* Create the semaphores(s) */
  /* creation of EthRxSemaphore */
  EthRxSemaphoreHandle = osSemaphoreNew(1, 0, &EthRxSemaphore_attributes);

  /* creation of Usart1RxSemaphore */
  Usart1RxSemaphoreHandle = osSemaphoreNew(1, 0, &Usart1RxSemaphore_attributes);

  /* creation of Usart1TxDoneSemaphore */
  Usart1TxDoneSemaphoreHandle = osSemaphoreNew(1, 0, &Usart1TxDoneSemaphore_attributes);

  /* creation of Usart2RxSemaphore */
  Usart2RxSemaphoreHandle = osSemaphoreNew(1, 0, &Usart2RxSemaphore_attributes);

  /* creation of Usart2TxDoneSemaphore */
  Usart2TxDoneSemaphoreHandle = osSemaphoreNew(1, 0, &Usart2TxDoneSemaphore_attributes);

  /* creation of Uart4RxSemaphore */
  Uart4RxSemaphoreHandle = osSemaphoreNew(1, 0, &Uart4RxSemaphore_attributes);

  /* creation of Uart4TxDoneSemaphore */
  Uart4TxDoneSemaphoreHandle = osSemaphoreNew(1, 0, &Uart4TxDoneSemaphore_attributes);

  /* creation of Uart5RxSemaphore */
  Uart5RxSemaphoreHandle = osSemaphoreNew(1, 0, &Uart5RxSemaphore_attributes);

  /* creation of Uart5TxDoneSemaphore */
  Uart5TxDoneSemaphoreHandle = osSemaphoreNew(1, 0, &Uart5TxDoneSemaphore_attributes);

  /* USER CODE BEGIN RTOS_SEMAPHORES */
  /* add semaphores, ... */
  /* USER CODE END RTOS_SEMAPHORES */

  /* Create the timer(s) */
  /* creation of DhcpFineTimer */
  DhcpFineTimerHandle = osTimerNew(DhcpFineTimerCallback, osTimerPeriodic, NULL, &DhcpFineTimer_attributes);

  /* creation of LinkCheckTimer */
  LinkCheckTimerHandle = osTimerNew(LinkCheckTimerCallback, osTimerPeriodic, NULL, &LinkCheckTimer_attributes);

  /* USER CODE BEGIN RTOS_TIMERS */
  /* start timers, add new ones, ... */
  /* USER CODE END RTOS_TIMERS */

  /* Create the queue(s) */
  /* creation of Usart1TxQueue */
  Usart1TxQueueHandle = osMessageQueueNew (8, sizeof(uint32_t), &Usart1TxQueue_attributes);

  /* creation of Usart2TxQueue */
  Usart2TxQueueHandle = osMessageQueueNew (8, sizeof(uint32_t), &Usart2TxQueue_attributes);

  /* creation of Uart4TxQueue */
  Uart4TxQueueHandle = osMessageQueueNew (8, sizeof(uint32_t), &Uart4TxQueue_attributes);

  /* creation of Uart5TxQueue */
  Uart5TxQueueHandle = osMessageQueueNew (8, sizeof(uint32_t), &Uart5TxQueue_attributes);

  /* USER CODE BEGIN RTOS_QUEUES */
  /* add queues, ... */
  /* USER CODE END RTOS_QUEUES */

  /* Create the thread(s) */
  /* creation of EthIf */
  EthIfHandle = osThreadNew(StartEthIfTask, NULL, &EthIf_attributes);

  /* creation of Usart1Task */
  Usart1TaskHandle = osThreadNew(StartUsart1Task, NULL, &Usart1Task_attributes);

  /* creation of Usart2Task */
  Usart2TaskHandle = osThreadNew(StartUsart2Task, NULL, &Usart2Task_attributes);

  /* creation of Uart4Task */
  Uart4TaskHandle = osThreadNew(StartUart4Task, NULL, &Uart4Task_attributes);

  /* creation of Uart5Task */
  Uart5TaskHandle = osThreadNew(StartUart5Task, NULL, &Uart5Task_attributes);

  /* USER CODE BEGIN RTOS_THREADS */
  /* add threads, ... */
  /* USER CODE END RTOS_THREADS */

  /* USER CODE BEGIN RTOS_EVENTS */
  /* add events, ... */
  /* USER CODE END RTOS_EVENTS */

  /* Initialize leds */
  BSP_LED_Init(LED_GREEN);
  BSP_LED_Init(LED_YELLOW);
  BSP_LED_Init(LED_RED);

  /* Initialize USER push-button, will be used to trigger an interrupt each time it's pressed.*/
  BSP_PB_Init(BUTTON_USER, BUTTON_MODE_EXTI);

  /* Initialize COM1 port (115200, 8 bits (7-bit data + 1 stop bit), no parity */
  BspCOMInit.BaudRate   = 115200;
  BspCOMInit.WordLength = COM_WORDLENGTH_8B;
  BspCOMInit.StopBits   = COM_STOPBITS_1;
  BspCOMInit.Parity     = COM_PARITY_NONE;
  BspCOMInit.HwFlowCtl  = COM_HWCONTROL_NONE;
  if (BSP_COM_Init(COM1, &BspCOMInit) != BSP_ERROR_NONE)
  {
    Error_Handler();
  }

  /* Start scheduler */
  osKernelStart();

  /* We should never get here as control is now taken by the scheduler */

  /* Infinite loop */
  /* USER CODE BEGIN WHILE */

  /* ======================================================================
   * THIS POINT IS UNREACHABLE.  Region rewritten 07-08-2026.
   * ======================================================================
   * osKernelStart() above never returns, so everything here runs only if the
   * scheduler failed to start. Roughly 350 lines of bare-metal code used to
   * sit in this block, carried over from HTTP_Server_H753_ISR_V00:
   *   - the startup banner and heap sanity check
   *   - http_server_start()            <-- so the HTTP server was NEVER STARTED
   *   - the flag-gated ISR superloop calling ethernetif_input(&gnetif)
   *   - a 250 ms receive watchdog and a 100 ms link poll
   *
   * All of it was dead under FreeRTOS, and two parts would not even compile:
   * ethernetif_input() is now "void ethernetif_input(void *argument)" - a task
   * body, not a callable function - and ethernet_link_check_state() no longer
   * exists in the RTOS ethernetif.c, which exposes ethernet_link_thread()
   * instead.
   *
   * Everything that genuinely needed doing moved to StartEthIfTask(), which is
   * where CubeMX now emits MX_LWIP_Init(). See USER CODE 5 in that task.
   * ==================================================================== */
  while (1)
  {
    /* Scheduler did not start. Blink the red LED slowly rather than spinning
       silently, so the failure is visible on the board without a debugger. */
    BSP_LED_Toggle(LED_RED);
    HAL_Delay(200);
  }
    /* USER CODE END WHILE */

    /* USER CODE BEGIN 3 */
  /* USER CODE END 3 */
}

/**
  * @brief System Clock Configuration
  * @retval None
  */
void SystemClock_Config(void)
{
  RCC_OscInitTypeDef RCC_OscInitStruct = {0};
  RCC_ClkInitTypeDef RCC_ClkInitStruct = {0};

  /** Supply configuration update enable
  */
  HAL_PWREx_ConfigSupply(PWR_LDO_SUPPLY);

  /** Configure the main internal regulator output voltage
  */
  __HAL_PWR_VOLTAGESCALING_CONFIG(PWR_REGULATOR_VOLTAGE_SCALE0);

  while(!__HAL_PWR_GET_FLAG(PWR_FLAG_VOSRDY)) {}

  /** Initializes the RCC Oscillators according to the specified parameters
  * in the RCC_OscInitTypeDef structure.
  */
  RCC_OscInitStruct.OscillatorType = RCC_OSCILLATORTYPE_HSI48|RCC_OSCILLATORTYPE_HSE;
  RCC_OscInitStruct.HSEState = RCC_HSE_BYPASS;
  RCC_OscInitStruct.HSI48State = RCC_HSI48_ON;
  RCC_OscInitStruct.PLL.PLLState = RCC_PLL_ON;
  RCC_OscInitStruct.PLL.PLLSource = RCC_PLLSOURCE_HSE;
  RCC_OscInitStruct.PLL.PLLM = 1;
  RCC_OscInitStruct.PLL.PLLN = 112;
  RCC_OscInitStruct.PLL.PLLP = 2;
  RCC_OscInitStruct.PLL.PLLQ = 4;
  RCC_OscInitStruct.PLL.PLLR = 2;
  RCC_OscInitStruct.PLL.PLLRGE = RCC_PLL1VCIRANGE_3;
  RCC_OscInitStruct.PLL.PLLVCOSEL = RCC_PLL1VCOWIDE;
  RCC_OscInitStruct.PLL.PLLFRACN = 4096;
  if (HAL_RCC_OscConfig(&RCC_OscInitStruct) != HAL_OK)
  {
    Error_Handler();
  }

  /** Initializes the CPU, AHB and APB buses clocks
  */
  RCC_ClkInitStruct.ClockType = RCC_CLOCKTYPE_HCLK|RCC_CLOCKTYPE_SYSCLK
                              |RCC_CLOCKTYPE_PCLK1|RCC_CLOCKTYPE_PCLK2
                              |RCC_CLOCKTYPE_D3PCLK1|RCC_CLOCKTYPE_D1PCLK1;
  RCC_ClkInitStruct.SYSCLKSource = RCC_SYSCLKSOURCE_PLLCLK;
  RCC_ClkInitStruct.SYSCLKDivider = RCC_SYSCLK_DIV1;
  RCC_ClkInitStruct.AHBCLKDivider = RCC_HCLK_DIV2;
  RCC_ClkInitStruct.APB3CLKDivider = RCC_APB3_DIV2;
  RCC_ClkInitStruct.APB1CLKDivider = RCC_APB1_DIV2;
  RCC_ClkInitStruct.APB2CLKDivider = RCC_APB2_DIV2;
  RCC_ClkInitStruct.APB4CLKDivider = RCC_APB4_DIV2;

  if (HAL_RCC_ClockConfig(&RCC_ClkInitStruct, FLASH_LATENCY_3) != HAL_OK)
  {
    Error_Handler();
  }
}

/**
  * @brief RNG Initialization Function
  * @param None
  * @retval None
  */
static void MX_RNG_Init(void)
{

  /* USER CODE BEGIN RNG_Init 0 */

  /* USER CODE END RNG_Init 0 */

  /* USER CODE BEGIN RNG_Init 1 */

  /* USER CODE END RNG_Init 1 */
  hrng.Instance = RNG;
  hrng.Init.ClockErrorDetection = RNG_CED_ENABLE;
  if (HAL_RNG_Init(&hrng) != HAL_OK)
  {
    Error_Handler();
  }
  /* USER CODE BEGIN RNG_Init 2 */

  /* USER CODE END RNG_Init 2 */

}

/**
  * @brief UART4 Initialization Function
  * @param None
  * @retval None
  */
static void MX_UART4_Init(void)
{

  /* USER CODE BEGIN UART4_Init 0 */

  /* USER CODE END UART4_Init 0 */

  /* USER CODE BEGIN UART4_Init 1 */

  /* USER CODE END UART4_Init 1 */
  huart4.Instance = UART4;
  huart4.Init.BaudRate = 115200;
  huart4.Init.WordLength = UART_WORDLENGTH_8B;
  huart4.Init.StopBits = UART_STOPBITS_1;
  huart4.Init.Parity = UART_PARITY_NONE;
  huart4.Init.Mode = UART_MODE_TX_RX;
  huart4.Init.HwFlowCtl = UART_HWCONTROL_NONE;
  huart4.Init.OverSampling = UART_OVERSAMPLING_16;
  huart4.Init.OneBitSampling = UART_ONE_BIT_SAMPLE_DISABLE;
  huart4.Init.ClockPrescaler = UART_PRESCALER_DIV1;
  huart4.AdvancedInit.AdvFeatureInit = UART_ADVFEATURE_NO_INIT;
  if (HAL_UART_Init(&huart4) != HAL_OK)
  {
    Error_Handler();
  }
  if (HAL_UARTEx_SetTxFifoThreshold(&huart4, UART_TXFIFO_THRESHOLD_1_8) != HAL_OK)
  {
    Error_Handler();
  }
  if (HAL_UARTEx_SetRxFifoThreshold(&huart4, UART_RXFIFO_THRESHOLD_1_8) != HAL_OK)
  {
    Error_Handler();
  }
  if (HAL_UARTEx_DisableFifoMode(&huart4) != HAL_OK)
  {
    Error_Handler();
  }
  /* USER CODE BEGIN UART4_Init 2 */

  /* USER CODE END UART4_Init 2 */

}

/**
  * @brief UART5 Initialization Function
  * @param None
  * @retval None
  */
static void MX_UART5_Init(void)
{

  /* USER CODE BEGIN UART5_Init 0 */

  /* USER CODE END UART5_Init 0 */

  /* USER CODE BEGIN UART5_Init 1 */

  /* USER CODE END UART5_Init 1 */
  huart5.Instance = UART5;
  huart5.Init.BaudRate = 115200;
  huart5.Init.WordLength = UART_WORDLENGTH_8B;
  huart5.Init.StopBits = UART_STOPBITS_1;
  huart5.Init.Parity = UART_PARITY_NONE;
  huart5.Init.Mode = UART_MODE_TX_RX;
  huart5.Init.HwFlowCtl = UART_HWCONTROL_NONE;
  huart5.Init.OverSampling = UART_OVERSAMPLING_16;
  huart5.Init.OneBitSampling = UART_ONE_BIT_SAMPLE_DISABLE;
  huart5.Init.ClockPrescaler = UART_PRESCALER_DIV1;
  huart5.AdvancedInit.AdvFeatureInit = UART_ADVFEATURE_NO_INIT;
  if (HAL_UART_Init(&huart5) != HAL_OK)
  {
    Error_Handler();
  }
  if (HAL_UARTEx_SetTxFifoThreshold(&huart5, UART_TXFIFO_THRESHOLD_1_8) != HAL_OK)
  {
    Error_Handler();
  }
  if (HAL_UARTEx_SetRxFifoThreshold(&huart5, UART_RXFIFO_THRESHOLD_1_8) != HAL_OK)
  {
    Error_Handler();
  }
  if (HAL_UARTEx_DisableFifoMode(&huart5) != HAL_OK)
  {
    Error_Handler();
  }
  /* USER CODE BEGIN UART5_Init 2 */

  /* USER CODE END UART5_Init 2 */

}

/**
  * @brief USART1 Initialization Function
  * @param None
  * @retval None
  */
static void MX_USART1_UART_Init(void)
{

  /* USER CODE BEGIN USART1_Init 0 */

  /* USER CODE END USART1_Init 0 */

  /* USER CODE BEGIN USART1_Init 1 */

  /* USER CODE END USART1_Init 1 */
  huart1.Instance = USART1;
  huart1.Init.BaudRate = 115200;
  huart1.Init.WordLength = UART_WORDLENGTH_8B;
  huart1.Init.StopBits = UART_STOPBITS_1;
  huart1.Init.Parity = UART_PARITY_NONE;
  huart1.Init.Mode = UART_MODE_TX_RX;
  huart1.Init.HwFlowCtl = UART_HWCONTROL_NONE;
  huart1.Init.OverSampling = UART_OVERSAMPLING_16;
  huart1.Init.OneBitSampling = UART_ONE_BIT_SAMPLE_DISABLE;
  huart1.Init.ClockPrescaler = UART_PRESCALER_DIV1;
  huart1.AdvancedInit.AdvFeatureInit = UART_ADVFEATURE_NO_INIT;
  if (HAL_UART_Init(&huart1) != HAL_OK)
  {
    Error_Handler();
  }
  if (HAL_UARTEx_SetTxFifoThreshold(&huart1, UART_TXFIFO_THRESHOLD_1_8) != HAL_OK)
  {
    Error_Handler();
  }
  if (HAL_UARTEx_SetRxFifoThreshold(&huart1, UART_RXFIFO_THRESHOLD_1_8) != HAL_OK)
  {
    Error_Handler();
  }
  if (HAL_UARTEx_DisableFifoMode(&huart1) != HAL_OK)
  {
    Error_Handler();
  }
  /* USER CODE BEGIN USART1_Init 2 */

  /* USER CODE END USART1_Init 2 */

}

/**
  * @brief USART2 Initialization Function
  * @param None
  * @retval None
  */
static void MX_USART2_UART_Init(void)
{

  /* USER CODE BEGIN USART2_Init 0 */

  /* USER CODE END USART2_Init 0 */

  /* USER CODE BEGIN USART2_Init 1 */

  /* USER CODE END USART2_Init 1 */
  huart2.Instance = USART2;
  huart2.Init.BaudRate = 115200;
  huart2.Init.WordLength = UART_WORDLENGTH_8B;
  huart2.Init.StopBits = UART_STOPBITS_1;
  huart2.Init.Parity = UART_PARITY_NONE;
  huart2.Init.Mode = UART_MODE_TX_RX;
  huart2.Init.HwFlowCtl = UART_HWCONTROL_NONE;
  huart2.Init.OverSampling = UART_OVERSAMPLING_16;
  huart2.Init.OneBitSampling = UART_ONE_BIT_SAMPLE_DISABLE;
  huart2.Init.ClockPrescaler = UART_PRESCALER_DIV1;
  huart2.AdvancedInit.AdvFeatureInit = UART_ADVFEATURE_NO_INIT;
  if (HAL_UART_Init(&huart2) != HAL_OK)
  {
    Error_Handler();
  }
  if (HAL_UARTEx_SetTxFifoThreshold(&huart2, UART_TXFIFO_THRESHOLD_1_8) != HAL_OK)
  {
    Error_Handler();
  }
  if (HAL_UARTEx_SetRxFifoThreshold(&huart2, UART_RXFIFO_THRESHOLD_1_8) != HAL_OK)
  {
    Error_Handler();
  }
  if (HAL_UARTEx_DisableFifoMode(&huart2) != HAL_OK)
  {
    Error_Handler();
  }
  /* USER CODE BEGIN USART2_Init 2 */

  /* USER CODE END USART2_Init 2 */

}

/**
  * @brief GPIO Initialization Function
  * @param None
  * @retval None
  */
static void MX_GPIO_Init(void)
{
  GPIO_InitTypeDef GPIO_InitStruct = {0};
  /* USER CODE BEGIN MX_GPIO_Init_1 */

  /* USER CODE END MX_GPIO_Init_1 */

  /* GPIO Ports Clock Enable */
  __HAL_RCC_GPIOH_CLK_ENABLE();
  __HAL_RCC_GPIOC_CLK_ENABLE();
  __HAL_RCC_GPIOA_CLK_ENABLE();
  __HAL_RCC_GPIOE_CLK_ENABLE();
  __HAL_RCC_GPIOB_CLK_ENABLE();
  __HAL_RCC_GPIOD_CLK_ENABLE();
  __HAL_RCC_GPIOG_CLK_ENABLE();

  /*Configure GPIO pin Output Level */
  HAL_GPIO_WritePin(SCOPE_TRIG_GPIO_Port, SCOPE_TRIG_Pin, GPIO_PIN_RESET);

  /*Configure GPIO pin : SCOPE_TRIG_Pin */
  GPIO_InitStruct.Pin = SCOPE_TRIG_Pin;
  GPIO_InitStruct.Mode = GPIO_MODE_OUTPUT_PP;
  GPIO_InitStruct.Pull = GPIO_NOPULL;
  GPIO_InitStruct.Speed = GPIO_SPEED_FREQ_HIGH;
  HAL_GPIO_Init(SCOPE_TRIG_GPIO_Port, &GPIO_InitStruct);

  /* USER CODE BEGIN MX_GPIO_Init_2 */

  /* Put the oscilloscope trigger at its idle level and zero its counters, now
     that PE9 is configured a few lines above. Placed HERE rather than in main()
     so it cannot end up running before the pin exists; the generated
     HAL_GPIO_WritePin() above already drives PE9 low, but that is the .ioc's
     idea of idle, which is only correct while SCOPE_TRIG_ACTIVE_LOW is 0.

     No printf: BSP_COM_Init() has not run yet, so nothing said here would be
     seen. The self-test result is reported from StartEthIfTask() instead, where
     the console is alive. */
  scope_trig_init();

  /* USER CODE END MX_GPIO_Init_2 */
}

/* USER CODE BEGIN 4 */

/**
  * @brief  Starts the HTTP server from inside tcpip_thread.
  *
  *         WHY THIS INDIRECTION IS MANDATORY. httpd_init() uses the lwIP raw
  *         API (tcp_new / tcp_bind / tcp_listen), and with NO_SYS=0 the raw API
  *         may only be touched from tcpip_thread. Calling http_server_start()
  *         from any other task is a data race on lwIP's internal PCB lists that
  *         will appear to work and then corrupt the stack under load.
  *
  *         In HTTP_Server_H753_ISR_V00 (NO_SYS=1) it was legal to call it
  *         straight from main(), because there was no separate stack thread.
  *         Two things changed with FreeRTOS: lwIP grew its own thread, and
  *         CubeMX moved MX_LWIP_Init() out of main() into StartEthIfTask - so
  *         lwIP does not even exist until the scheduler is running.
  *
  *         Same pattern as tcp_echoserver_init_callback() in
  *         TCP_Server_H753_RTOS__ES_V00, which is where it was learned.
  * @param  ctx: unused
  * @retval None
  */
static void http_server_init_callback(void *ctx)
{
  (void)ctx;
  http_server_start();
}

/* USER CODE END 4 */

/* USER CODE BEGIN Header_StartEthIfTask */
/**
  * @brief  Function implementing the EthIf thread.
  * @param  argument: Not used
  * @retval None
  */
/* USER CODE END Header_StartEthIfTask */
void StartEthIfTask(void *argument)
{
  /* USER CODE BEGIN 5 */

  /* ========================================================================
   * MX_LWIP_Init() IS CALLED HERE BY HAND.  Added 07-08-2026.  LOAD-BEARING.
   * ========================================================================
   * DO NOT DELETE THIS, and do not "clean it up" because CubeMX looks like it
   * ought to be doing it. In this project it is not.
   *
   * WHAT CUBEMX NORMALLY DOES. With LwIP + FreeRTOS, CubeMX emits the LwIP init
   * into the owning task itself, immediately ABOVE this USER CODE marker:
   *       void StartEthIfTask(void *argument)
   *       {
   *         / * init code for LWIP * /
   *         MX_LWIP_Init();
   *         / * USER CODE BEGIN 5 * /
   * That is still exactly what sibling project HTTP_Server_H753_RTOS_ES_V00 has
   * (its main.c line 747), and it is why that project works.
   *
   * WHAT ENABLING MBEDTLS DID. Turning mbedTLS on in the .ioc makes CubeMX hand
   * ownership of the LwIP init to the mbedTLS BSD-socket glue instead. It
   * generates MBEDTLS/App/net_sockets.c containing:
   *       void mbedtls_net_init(mbedtls_net_context *ctx) { MX_LWIP_Init(); }
   * and then REMOVES BOTH the MX_LWIP_Init() call from this task AND the
   * #include "lwip.h" from the top of main.c. It is not a lost USER CODE block -
   * it is generated code that CubeMX deliberately relocated, so none of the usual
   * USER CODE protections applied.
   *
   * WHY THAT BREAKS THIS PROJECT SPECIFICALLY. mbedtls_net_init() is for a TLS
   * client built on BSD sockets via mbedtls_net_connect(). This project is a TLS
   * SERVER built on altcp_tls, which sits directly on the lwIP raw API and never
   * calls mbedtls_net_init() at all. So the only remaining caller of
   * MX_LWIP_Init() in the entire image was unreachable, and lwIP was never
   * initialised.
   *
   * HOW IT PRESENTED - four symptoms, none of which points at a missing init:
   *     eth: PHY *** NOT DETECTED (MDIO failure) ***
   *     net: MAC 00:00:00:00:00:00 flags=0x00 up=0 link=0
   *     Assertion "Invalid mbox" failed at line 327 in tcpip.c
   *     http: *** tcpip_callback() FAILED - server not started ***
   * Note the assert does NOT stop the board: ST's LWIP_PLATFORM_ASSERT in
   * Middlewares/Third_Party/LwIP/system/arch/cc.h only printf()s. Execution
   * carries on into memp_malloc() on pools that were never memp_init()ed, which
   * returns NULL, hence ERR_MEM and the last line above.
   *
   * IT ALSO CAUSED THE LINKER FAILURE. With no reachable caller, ethernetif.o's
   * low_level_init() was dead code, so the Ethernet DMA sections it references
   * became unreachable and --gc-sections deleted 51 KB of RAM_D2 - the separate
   * fault fixed the same day by adding KEEP() to STM32H753ZITX_FLASH.ld. One root
   * cause, two unrelated-looking symptoms. Same trigger as the 31-07-2026
   * occurrence in TCP_Server_H753_RTOS__ES_MBEDTLS_V00.
   *
   * THE GUARD. If a future CubeMX version resumes emitting the generated call, it
   * lands ABOVE this marker and runs first, leaving gnetif on lwIP's interface
   * list. Testing netif_list makes this call a no-op in that case; MX_LWIP_Init()
   * is NOT idempotent (it would tcpip_init() and netif_add() a second time).
   * netif_list exists because LWIP_SINGLE_NETIF is 0 - opt.h's default, not
   * overridden in lwipopts.h. If that ever changes, switch the test to
   * netif_default.
   * ===================================================================== */

  /* ========================================================================
   * BUFFERED CONSOLE.  Added 28-08-2026. MUST BE FIRST IN THIS TASK.
   * ========================================================================
   * Enables the USART3 interrupt the BSP never enables, re-bauds the VCP to
   * VCOM_TX_BAUD, and switches printf from blocking to buffered.
   *
   * FIRST, ahead of the banner, so the ENTIRE log comes out at the new rate.
   * Called any later and the terminal would have to change baud part way
   * through the boot output, which in practice means missing the beginning.
   *
   * Nothing printed before this is lost: _write() falls back to the BSP's
   * blocking path until this runs. */
  vcom_tx_init();

  if (netif_list == NULL)
  {
    MX_LWIP_Init();
  }

  /* ========================================================================
   * THIS TASK MUST NEVER TOUCH THE RECEIVE PATH.  Written 07-08-2026,
   * lesson inherited from TCP_Server_H753_RTOS__ES_V00.
   * ========================================================================
   * The obvious-looking body for an "EthIf" task is:
   *     for(;;) { osSemaphoreAcquire(EthRxSemaphoreHandle, osWaitForever);
   *               ethernetif_input(&gnetif); }
   * That is wrong three times over:
   *   1. EthRxSemaphoreHandle is the CubeMX-created semaphore in THIS file and
   *      NOTHING ever releases it. The ETH receive ISR releases ethernetif.c's
   *      own RxPktSemaphore, a different object.
   *   2. low_level_init() ALREADY creates a dedicated osPriorityRealtime thread
   *      running ethernetif_input() (see the osThreadNew() call in
   *      ethernetif.c). Running the drain here too would put two tasks on the
   *      same semaphore, both calling low_level_input() on the same ETH handle
   *      - a real race on the DMA descriptor ring, not just wasted work.
   *   3. ethernetif_input() is a THREAD BODY under RTOS, "void f(void *)". It
   *      never returns, so any outer loop is dead code anyway.
   *
   * EthRxSemaphoreHandle is therefore unused. It is left created rather than
   * removed from the .ioc, so the RTOS object list stays stable across
   * regenerations.
   *
   * What this task does instead, being otherwise idle:
   *   1. Report link/interface state now that printf is backed by BSP_COM_Init()
   *      and lwIP exists. None of this could stay in main(): everything after
   *      osKernelStart() there is unreachable.
   *   2. Create the HTTP listener, marshalled onto tcpip_thread.
   *   3. Become the PHY link monitor. The RTOS ethernetif.c no longer provides
   *      ethernet_link_check_state(); it exposes ethernet_link_thread() as a
   *      thread body, which owns its own for(;;) with a 100 ms osDelay.
   * ===================================================================== */

  /* Keep this string matched to the project folder name. It was left reading
     "..._ES_V00 ... no TLS" after the copy, and on 07-08-2026 that cost real time:
     a board that was in fact running the new TLS image looked like it had been
     flashed with the old one. The banner is the only thing a serial log has to
     identify the firmware, so it has to be right. */
  printf("\r\n--- CNR-ICU-0.2 : WSS + JSON extract to 4 UARTs + SNTP epoch clock ---\r\n");
  /* Descriptor counts only. ETH_RX_BUFFER_CNT is a #define local to
     ethernetif.c (emitted there by ethernetif_h7.ftl), not a header symbol, so
     it is deliberately not printed here rather than duplicating the literal and
     letting the two drift apart. All three come from the .ioc: ETH -> Rx/Tx
     Descriptor Length, and LWIP -> Key Options -> ETH_RX_BUFFER_CNT. */
  printf("eth: rings rx=%u tx=%u   (RTOS, NO_SYS=0)\r\n",
         (unsigned)ETH_RX_DESC_CNT, (unsigned)ETH_TX_DESC_CNT);

  /* ========================================================================
   * OSCILLOSCOPE TRIGGER SELF-TEST.  Added 26-08-2026.
   * ========================================================================
   * Run here rather than in main() for the same reason the banner is here: the
   * console only exists after BSP_COM_Init(), and everything in main() after
   * osKernelStart() is unreachable.
   *
   * WHY IT IS WORTH THE LINES. A trigger pin that never moves is
   * indistinguishable on a scope from a board that simply has no traffic yet -
   * both are a flat line. A dead pin would therefore be discovered only after
   * wiring up the probe, sending traffic, seeing nothing, and suspecting the
   * firmware, the probe and the trigger settings in turn. This drives PE9 both
   * ways, reads it back through the port, and exercises the received/complete
   * pair, so the failure is named at boot instead.
   *
   * It moves the pin twice. If a scope is already armed on a rising edge it
   * will catch these; they are at boot, before any traffic, and the counters
   * are returned to zero afterwards. */
  {
    int scope_rc = scope_trig_selftest();

    if (scope_rc == 0)
    {
      printf("scope: PE9 trigger self-test PASSED  (mode=%s, %s)\r\n",
             (SCOPE_TRIG_MODE_BURST != 0) ? "BURST" : "PER-FRAME",
             (SCOPE_TRIG_ACTIVE_LOW != 0) ? "active LOW" : "active HIGH");
#if SCOPE_TRIG_FROM_ETH
#if SCOPE_TRIG_END_ON_PARSE
      /* THE ARMING SOURCE IS PRINTED BECAUSE THE TWO MODES ARE INDISTINGUISH-
         ABLE FROM THE TRACE. A permanently high pin means "arming on every
         Ethernet interrupt on a subnet full of mDNS multicast"; a pulsing one
         means "arming on stream socket data". Reading the mode off the console
         is the only way to know which binary is on the board without a
         debugger - which cost real time on 10-09-2026, when a scope photo
         could not settle whether the new firmware had been flashed. */
      printf("scope: arming on %s, min idle after falling edge %u us\r\n",
             (SCOPE_TRIG_ARM_ON_SOCKET_DATA != 0)
                 ? "STREAM SOCKET DATA (stray packets excluded)"
                 : "EVERY ETH RX INTERRUPT (stray packets included)",
             (unsigned)SCOPE_TRIG_MIN_IDLE_US);
      printf("scope: HIGH on frame reception -> LOW when JSON parsing is "
             "complete and the frame is ready to send\r\n");
      printf("scope: pulse = decrypt + WS parse + JSON extract "
             "(UART transmit NOT included)\r\n");
#else
      printf("scope: HIGH on ETH RX interrupt -> LOW when ALL FOUR UARTs "
             "finish the same sequence_id\r\n");
      printf("scope: pulse = ETH ISR + decrypt + WS parse + JSON extract + "
             "4x queue + 4x transmit\r\n");
#endif
      if (scope_trig_dwt_ok != 0U)
      {
        printf("scope: watch scope_trig_lead_us_max vs scope_trig_span_us_max "
               "- lead near 0 means the widths are honest\r\n");
      }
      else
      {
        printf("scope: *** cycle counter NOT running - lead/span will read 0, "
               "meaning NOT MEASURED ***\r\n");
      }
#elif SCOPE_TRIG_FROM_NETWORK
      printf("scope: HIGH on server frame arrival -> LOW on selector 0x%02X "
             "TX-complete\r\n", (unsigned)SCOPE_TRIG_SELECTOR);
      printf("scope: pulse = decrypt + WS parse + JSON extract + queue + "
             "transmit\r\n");
#else
      printf("scope: HIGH on UART dispatch -> LOW on selector 0x%02X "
             "TX-complete\r\n", (unsigned)SCOPE_TRIG_SELECTOR);
      printf("scope: pulse = queue + transmit only; decrypt and parse are "
             "OUTSIDE it\r\n");
#endif
    }
    else
    {
      printf("scope: *** PE9 TRIGGER SELF-TEST FAILED at check %d ***\r\n", scope_rc);
      printf("scope:     1/2 = pin will not drive or read back - check the .ioc\r\n");
      printf("scope:           still has PE9 as GPIO_Output labelled SCOPE_TRIG\r\n");
#if SCOPE_TRIG_FROM_ETH
      printf("scope:     3   = the ETH hook does not raise the pin\r\n");
      printf("scope:     4   = pulse ended on the wrong number of UARTs\r\n");
      printf("scope:     5   = a stale sequence_id ended the pulse\r\n");
#else
      printf("scope:     3/4 = the in-flight counter is not tracking frames\r\n");
      printf("scope:     5   = the underflow guard is not holding\r\n");
#endif
      printf("scope:     Pulse widths from this run cannot be trusted.\r\n");
    }
  }

#if STREAM_JSON_EXTRACT_ENABLE
  /* ========================================================================
   * JSON FIELD EXTRACTOR SELF-TEST.  Added 27-08-2026.
   * ========================================================================
   * The failure this guards against is not a crash. If the parser matched the
   * decoy key "controller_to_base_station_received_ntp_time" instead of
   * "ntp_time", USART2 would carry a perfectly well-formed timestamp that is
   * simply the WRONG FIELD, about 13 ms earlier than the right one. Nothing
   * downstream could tell, and neither could a person reading the serial
   * terminal. Check 2 of the self-test is the only thing that can.
   *
   * The checks also cover the fragmentation cases, which cannot be provoked on
   * demand from a live server: an object split mid-key across three receives,
   * and the whole object delivered one byte at a time. */
  {
    int json_rc = json_parser_selftest();

    if (json_rc == 0)
    {
      printf("json: extractor self-test PASSED - 9/9 checks\r\n");
      printf("json: motor_1_pos -> UART4  | motor_2_pos          -> UART5\r\n");
      printf("json: motor_3_pos -> USART1 | motor_4_insertion_pos -> USART2\r\n");
      /* Built in pieces so the format line always matches the three switches
         that actually decide it, rather than being a comment that drifts.
         Extended on 09-10-2026 when JSON_PARSER_EMIT_PREFIX was added: before
         that the opening half hard-coded "<sequence_id>," and would have gone
         on claiming a column this build no longer sends. */
      printf("json: each line is \"");
#if JSON_PARSER_EMIT_PREFIX
      printf("<sequence_id>,");
#endif
#if JSON_PARSER_EMIT_LABEL
      printf("<field_name>,");
#endif
      printf("<value>");
#if STREAM_JSON_APPEND_EPOCH
      printf(",<stm32_epoch>");
#endif
      printf("\" + CRLF\r\n");
    }
    else
    {
      printf("json: *** EXTRACTOR SELF-TEST FAILED at check %d ***\r\n", json_rc);
      printf("json:     1 = four-field extraction   2 = DECOY KEY MATCHED (wrong UART!)\r\n");
      printf("json:     3 = swapped field order     4 = split across receives\r\n");
      printf("json:     5 = two objects per buffer  6 = brace inside a string\r\n");
      printf("json:     7 = oversize recovery       8 = one byte per call\r\n");
      /* 9 WAS MISSING FROM THIS LIST until 09-10-2026, while the pass message
         above already said "9/9 checks". Check 9 was in fact failing on every
         boot - JSON_PARSER_LABEL_MAX was too small for the key it compares
         against - so the one number a reader actually saw was the one number
         with nothing to look it up under. */
      printf("json:     9 = label column\r\n");
      printf("json:     Values on the UARTs from this run cannot be trusted.\r\n");
    }
  }
#else
  printf("json: extraction OFF - USART2 carries the raw stream\r\n");
#endif

  /* ========================================================================
   * NTP EPOCH CLOCK SELF-TEST.  Added 28-08-2026.
   * ========================================================================
   * Every failure mode in this module produces a plausible number rather than
   * an obvious fault. A byte-order slip gives a wildly wrong but well-formed
   * date; the wrong epoch constant gives a time exactly 70 years out; a broken
   * anchor gives a clock that simply never advances. None of those looks like
   * an error on a terminal, so they are checked here instead.
   *
   * Runs before the task starts and needs no network - the vectors are built
   * from fixed timestamps. */
  {
    int ntp_rc = ntp_selftest();

    if (ntp_rc == 0)
    {
      printf("ntp: epoch clock self-test PASSED - 5/5 checks\r\n");
    }
    else
    {
      printf("ntp: *** EPOCH CLOCK SELF-TEST FAILED at check %d ***\r\n", ntp_rc);
      printf("ntp:     1 = request packet malformed\r\n");
      printf("ntp:     2 = epoch constant or byte order wrong\r\n");
      printf("ntp:     3 = fraction field not converted to ms\r\n");
      printf("ntp:     4 = a malformed reply was ACCEPTED\r\n");
      printf("ntp:     5 = the clock does not advance with the tick\r\n");
      printf("ntp:     Epoch values from this run cannot be trusted.\r\n");
    }
  }
  /* ========================================================================
   * WAIT FOR THE DHCP LEASE.  Added 24-08-2026.
   * ========================================================================
   * This line used to print the address straight away, which was right while
   * the address was the static 192.168.1.10 assigned in MX_LWIP_Init(). Under
   * DHCP it would now always print 0.0.0.0: dhcp_start() has only just been
   * called from USER CODE 3 in LWIP/App/lwip.c, and DISCOVER/OFFER/REQUEST/ACK
   * has not had time to complete. A banner that always reports 0.0.0.0 is
   * worse than no banner - it reads as a failure on a board that is fine.
   *
   * POLLED, NOT BLOCKED ON A SEMAPHORE. lwIP offers no "lease acquired" signal
   * that can be waited on from another thread without adding one, and the
   * osDelay here yields to the scheduler so tcpip_thread - which is what
   * actually drives the DHCP state machine - gets to run. Spinning without the
   * delay would starve the very thread this is waiting for, on a
   * priority-based scheduler.
   *
   * dhcp_supplied_address() rather than testing the address against 0: it
   * reports whether THIS netif's address came from a completed DHCP bind, so a
   * link-local or manually poked address cannot be mistaken for a lease.
   *
   * A TIMEOUT, NOT AN INFINITE WAIT. Start-up continues either way. With no
   * DHCP server on the segment the board still comes up, still prints its MAC
   * and PHY state, and still serves nothing - which is diagnosable. Blocking
   * here forever would leave a dead board with no console output past this
   * point and no clue that DHCP was the reason.
   * =====================================================================
   *
   * MADE CONDITIONAL 24-08-2026 on USE_DHCP in Core/Inc/main.h. With that at 0
   * there is no lease to wait for - the address was assigned in MX_LWIP_Init()
   * and is already live - so the whole poll is compiled out and the address is
   * simply reported. Leaving the wait in would cost NET_DHCP_WAIT_MAX_MS of
   * dead time at every boot and then print a "NO DHCP LEASE" alarm about a
   * board that was never asking for one.
   * ===================================================================== */
#if USE_DHCP
  {
    uint32_t waited_ms = 0U;

    printf("net: USE_DHCP = 1 - requesting an address by DHCP\r\n");

    while ((dhcp_supplied_address(&gnetif) == 0)
           && (waited_ms < NET_DHCP_WAIT_MAX_MS))
    {
      osDelay(NET_DHCP_POLL_MS);
      waited_ms += NET_DHCP_POLL_MS;
    }

    if (dhcp_supplied_address(&gnetif) != 0)
    {
      printf("net: DHCP lease acquired after %lu ms\r\n",
             (unsigned long)waited_ms);
      printf("net: IPv4 address %s\r\n",
             ip4addr_ntoa(netif_ip4_addr(&gnetif)));
      printf("net:      netmask %s\r\n",
             ip4addr_ntoa(netif_ip4_netmask(&gnetif)));
      printf("net:      gateway %s\r\n",
             ip4addr_ntoa(netif_ip4_gw(&gnetif)));
    }
    else
    {
      /* Say which of the two causes it is. "No lease" with the link down is a
         cable; with the link up it is the DHCP server or the VLAN. Reporting
         them as one message sends people to the wrong place. */
      printf("net: *** NO DHCP LEASE after %lu ms ***\r\n",
             (unsigned long)NET_DHCP_WAIT_MAX_MS);
      if (netif_is_link_up(&gnetif) == 0)
      {
        printf("net:     the PHY link is DOWN - check the cable first.\r\n");
      }
      else
      {
        printf("net:     the link is UP, so the cable is fine - no DHCP "
               "server answered on this segment.\r\n");
      }
      printf("net: IPv4 address %s  (unconfigured)\r\n",
             ip4addr_ntoa(netif_ip4_addr(&gnetif)));
    }
  }
#else
  /* Static addressing. The address came from NET_STATIC_* in main.h, applied
     in USER CODE IP_ADDRESSES of LWIP/App/lwip.c, and is live before this task
     runs - so there is nothing to wait for and nothing that can time out. */
  printf("net: USE_DHCP = 0 - using the static address from main.h\r\n");
  printf("net: IPv4 address %s\r\n", ip4addr_ntoa(netif_ip4_addr(&gnetif)));
  printf("net:      netmask %s\r\n", ip4addr_ntoa(netif_ip4_netmask(&gnetif)));
  printf("net:      gateway %s\r\n", ip4addr_ntoa(netif_ip4_gw(&gnetif)));
#endif

  /* Three preconditions etharp_input() needs before it will answer a request,
     all of which fail silently if wrong: a real MAC in hwaddr, NETIF_FLAG_ETHARP
     (0x08) in flags, and the netif administratively up. */
  printf("net: MAC %02X:%02X:%02X:%02X:%02X:%02X flags=0x%02X up=%d link=%d\r\n",
         gnetif.hwaddr[0], gnetif.hwaddr[1], gnetif.hwaddr[2],
         gnetif.hwaddr[3], gnetif.hwaddr[4], gnetif.hwaddr[5],
         (unsigned)gnetif.flags,
         netif_is_up(&gnetif) ? 1 : 0,
         netif_is_link_up(&gnetif) ? 1 : 0);

  /* Distinguishes "PHY never found over MDIO" from "PHY found but link down" -
     two very different faults that otherwise look identical, because
     low_level_init()'s LAN8742_Init() failure path returns early and silently. */
  printf("eth: PHY %s\r\n",
         eth_phy_detected ? "detected over MDIO" : "*** NOT DETECTED (MDIO failure) ***");

  /* Bring up httpd. See http_server_init_callback() above for why this cannot
     be a direct call. tcpip_callback() returns as soon as the message is posted;
     the listener is created a moment later on tcpip_thread. */
  if (tcpip_callback(http_server_init_callback, NULL) != ERR_OK)
  {
    printf("http: *** tcpip_callback() FAILED - server not started ***\r\n");
  }

  /* ========================================================================
   * START THE OUTBOUND STREAM CLIENT.  Added 24-08-2026.
   * ========================================================================
   * This board is a server everywhere else in this project. The stream client
   * is the one thing that dials OUT: it connects to STREAM_SERVER_HOST, reads
   * a continuous response body, and prints every byte of it to USART2. See
   * Core/Inc/stream_client.h.
   *
   * ORDER MATTERS, TWICE OVER.
   *
   * AFTER THE DHCP WAIT ABOVE. The client connects out, and a connect from
   * 0.0.0.0 fails at once. The backoff would then hide the mistake - the
   * console would show a reconnect loop against a server that was reachable
   * all along, and the real cause (started before the board had an address)
   * would not appear anywhere.
   *
   * AFTER http_server_init_callback() IS POSTED, not before. Both want the
   * lwIP heap, and the TLS session this client allocates is the larger of the
   * two. Posting the listener first means that if MEM_SIZE is too small, it is
   * the client's handshake that fails and says so, rather than the server
   * silently never starting.
   *
   * stream_client_init() only CREATES the task; it does not connect. The task
   * announces itself and reports every state change, so its absence from the
   * console is itself diagnostic.
   * ===================================================================== */
#if STREAM_CLIENT_ENABLE
  stream_client_init();

  /* ========================================================================
   * NTP CLIENT.  Added 28-08-2026.
   * ========================================================================
   * Started HERE, after the DHCP wait above, and not from main(). A poll sent
   * before the interface has an address goes out from 0.0.0.0 and fails - it
   * would recover on the next attempt, but it fills ntp_timeouts with noise
   * that then has to be explained.
   *
   * A DEDICATED TASK, NOT A SOFTWARE TIMER. The poll does blocking network I/O
   * (sendto, then select for up to NTP_RESPONSE_TIMEOUT_MS). Every FreeRTOS
   * software timer callback runs in the one timer service task, so blocking
   * inside a callback would stall every other timer in the system - here the
   * DHCP fine timer and the link check. */
  ntp_client_init();
#else
  printf("stream: client compiled out (STREAM_CLIENT_ENABLE = 0)\r\n");
#endif

  /* ========================================================================
   * mDNS RESOLVER.  Added 10-09-2026.
   * ========================================================================
   * Started HERE, after the DHCP wait, for the same reason as the NTP client:
   * a query sent from 0.0.0.0 cannot be answered, because the responder has no
   * address to send the unicast reply to. The task tolerates being started
   * early and waits for an address, but the console would then carry failures
   * that are an artefact of the start order rather than of the network.
   *
   * DELIBERATELY OUTSIDE THE STREAM_CLIENT_ENABLE BLOCK ABOVE. Name resolution
   * has nothing to do with whether the WSS client is compiled in, and nesting
   * it there would silently remove mDNS from a build that merely turned the
   * stream off. Its own switch is MDNS_RESOLVER_ENABLE in Core/Inc/mdns_config.h.
   *
   * RESOLVES AND REPORTS ONLY at this stage. It does not yet redirect the
   * stream client or the NTP client, which still use the literals in
   * stream_client.h and ntp_client.h. That is a separate step, to be taken once
   * the resolution is seen working against the live network - see the Module
   * Description in mdns_service.c.
   * ===================================================================== */
  mdns_service_init();

  /* ======================================================================
   * DO NOT call ethernet_link_thread() here.  Corrected 07-08-2026.
   * ======================================================================
   * This task briefly did exactly that, copied from
   * TCP_Server_H753_RTOS__ES_V00 where StartEthIfTask was repurposed as the PHY
   * link monitor. That was wrong for THIS project: LWIP/App/lwip.c line 108
   * already does
   *     osThreadNew(ethernet_link_thread, &gnetif, &attributes);
   * creating the "EthLink" task. Calling it here as well put TWO tasks inside
   * the same function, both driving LAN8742_GetLinkState() over MDIO and both
   * able to call HAL_ETH_Stop_IT()/HAL_ETH_Start_IT() - a genuine race on the
   * PHY and on the ETH peripheral's state machine.
   *
   * The reference project's advice did not transfer because its CubeMX version
   * did not generate that thread; this one does. The FreeRTOS Task List is what
   * settled it: an "EthLink" row existed at priority 16 that nothing in
   * ethernetif.c creates.
   *
   * So this task has nothing left to do once the listener is queued. Terminate
   * rather than idle in a for(;;): that returns its 2 KB stack and its TCB to
   * ucHeap instead of holding them for the life of the program.
   * ================================================================== */
  osThreadTerminate(osThreadGetId());

  /* Unreachable - osThreadTerminate() on self does not return. Present only so
     the function has no path that falls off the end, which FreeRTOS treats as a
     fatal error for a task body. */
  for (;;)
  {
    osDelay(1000);
  }

  /* USER CODE END 5 */
}

/* USER CODE BEGIN Header_StartUsart1Task */
/**
* @brief Function implementing the Usart1Task thread.
* @param argument: Not used
* @retval None
*/
/* USER CODE END Header_StartUsart1Task */
void StartUsart1Task(void *argument)
{
  /* USER CODE BEGIN StartUsart1Task */
  /* uart_dispatch_task_run() never returns - it IS the whole task body.
     All four UART tasks are identical apart from these five arguments, so
     the wait-for-request / transmit / free loop lives once in
     uart_dispatch.c rather than being copy-pasted here four times.
     USART1 on PB6/PB7, reached by selector byte UART_SELECTOR_USART1. */
  uart_dispatch_task_run(&huart1, Usart1TxQueueHandle, Usart1RxSemaphoreHandle,
                         Usart1TxDoneSemaphoreHandle, UART_SELECTOR_USART1);
  /* USER CODE END StartUsart1Task */
}

/* USER CODE BEGIN Header_StartUsart2Task */
/**
* @brief Function implementing the Usart2Task thread.
* @param argument: Not used
* @retval None
*/
/* USER CODE END Header_StartUsart2Task */
void StartUsart2Task(void *argument)
{
  /* USER CODE BEGIN StartUsart2Task */
  /* uart_dispatch_task_run() never returns - it IS the whole task body.
     All four UART tasks are identical apart from these five arguments, so
     the wait-for-request / transmit / free loop lives once in
     uart_dispatch.c rather than being copy-pasted here four times.
     USART2 on PD5/PD6, reached by selector byte UART_SELECTOR_USART2. */
  uart_dispatch_task_run(&huart2, Usart2TxQueueHandle, Usart2RxSemaphoreHandle,
                         Usart2TxDoneSemaphoreHandle, UART_SELECTOR_USART2);
  /* USER CODE END StartUsart2Task */
}

/* USER CODE BEGIN Header_StartUart4Task */
/**
* @brief Function implementing the Uart4Task thread.
* @param argument: Not used
* @retval None
*/
/* USER CODE END Header_StartUart4Task */
void StartUart4Task(void *argument)
{
  /* USER CODE BEGIN StartUart4Task */
  /* uart_dispatch_task_run() never returns - it IS the whole task body.
     All four UART tasks are identical apart from these five arguments, so
     the wait-for-request / transmit / free loop lives once in
     uart_dispatch.c rather than being copy-pasted here four times.
     UART4 on PC10/PC11, reached by selector byte UART_SELECTOR_UART4. */
  uart_dispatch_task_run(&huart4, Uart4TxQueueHandle, Uart4RxSemaphoreHandle,
                         Uart4TxDoneSemaphoreHandle, UART_SELECTOR_UART4);
  /* USER CODE END StartUart4Task */
}

/* USER CODE BEGIN Header_StartUart5Task */
/**
* @brief Function implementing the Uart5Task thread.
* @param argument: Not used
* @retval None
*/
/* USER CODE END Header_StartUart5Task */
void StartUart5Task(void *argument)
{
  /* USER CODE BEGIN StartUart5Task */
  /* uart_dispatch_task_run() never returns - it IS the whole task body.
     All four UART tasks are identical apart from these five arguments, so
     the wait-for-request / transmit / free loop lives once in
     uart_dispatch.c rather than being copy-pasted here four times.
     UART5 on PC12/PD2, reached by selector byte UART_SELECTOR_UART5. */
  uart_dispatch_task_run(&huart5, Uart5TxQueueHandle, Uart5RxSemaphoreHandle,
                         Uart5TxDoneSemaphoreHandle, UART_SELECTOR_UART5);
  /* USER CODE END StartUart5Task */
}

/* DhcpFineTimerCallback function */
void DhcpFineTimerCallback(void *argument)
{
  /* USER CODE BEGIN DhcpFineTimerCallback */

  /* USER CODE END DhcpFineTimerCallback */
}

/* LinkCheckTimerCallback function */
void LinkCheckTimerCallback(void *argument)
{
  /* USER CODE BEGIN LinkCheckTimerCallback */

  /* USER CODE END LinkCheckTimerCallback */
}

 /* MPU Configuration */

void MPU_Config(void)
{
  MPU_Region_InitTypeDef MPU_InitStruct = {0};

  /* Disables the MPU */
  HAL_MPU_Disable();

  /** Initializes and configures the Region and the memory to be protected
  */
  MPU_InitStruct.Enable = MPU_REGION_ENABLE;
  MPU_InitStruct.Number = MPU_REGION_NUMBER0;
  MPU_InitStruct.BaseAddress = 0x30000000 ;
  MPU_InitStruct.Size = MPU_REGION_SIZE_64KB;
  MPU_InitStruct.SubRegionDisable = 0x00;
  MPU_InitStruct.TypeExtField = MPU_TEX_LEVEL1;
  MPU_InitStruct.AccessPermission = MPU_REGION_FULL_ACCESS;
  MPU_InitStruct.DisableExec = MPU_INSTRUCTION_ACCESS_DISABLE;
  MPU_InitStruct.IsShareable = MPU_ACCESS_SHAREABLE;
  MPU_InitStruct.IsCacheable = MPU_ACCESS_NOT_CACHEABLE;
  MPU_InitStruct.IsBufferable = MPU_ACCESS_NOT_BUFFERABLE;

  HAL_MPU_ConfigRegion(&MPU_InitStruct);
  /* Enables the MPU */
  HAL_MPU_Enable(MPU_PRIVILEGED_DEFAULT);

}

/**
  * @brief  Period elapsed callback in non blocking mode
  * @note   This function is called  when TIM6 interrupt took place, inside
  * HAL_TIM_IRQHandler(). It makes a direct call to HAL_IncTick() to increment
  * a global variable "uwTick" used as application time base.
  * @param  htim : TIM handle
  * @retval None
  */
void HAL_TIM_PeriodElapsedCallback(TIM_HandleTypeDef *htim)
{
  /* USER CODE BEGIN Callback 0 */

  /* USER CODE END Callback 0 */
  if (htim->Instance == TIM6)
  {
    HAL_IncTick();
  }
  /* USER CODE BEGIN Callback 1 */

  /* USER CODE END Callback 1 */
}

/**
  * @brief  This function is executed in case of error occurrence.
  * @retval None
  */
void Error_Handler(void)
{
  /* USER CODE BEGIN Error_Handler_Debug */
  /* User can add his own implementation to report the HAL error return state */
  __disable_irq();
  while (1)
  {
  }
  /* USER CODE END Error_Handler_Debug */
}
#ifdef USE_FULL_ASSERT
/**
  * @brief  Reports the name of the source file and the source line number
  *         where the assert_param error has occurred.
  * @param  file: pointer to the source file name
  * @param  line: assert_param error line source number
  * @retval None
  */
void assert_failed(uint8_t *file, uint32_t line)
{
  /* USER CODE BEGIN 6 */
  /* User can add his own implementation to report the file name and line number,
     ex: printf("Wrong parameters value: file %s on line %d\r\n", file, line) */
  /* USER CODE END 6 */
}
#endif /* USE_FULL_ASSERT */
