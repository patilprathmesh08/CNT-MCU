/* USER CODE BEGIN Header */
/**
  ******************************************************************************
  * File Name          : freertos.c
  * Description        : Code for freertos applications
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
#include "FreeRTOS.h"
#include "task.h"
#include "main.h"

/* Private includes ----------------------------------------------------------*/
/* USER CODE BEGIN Includes */

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
/* USER CODE BEGIN Variables */

/* USER CODE END Variables */

/* Private function prototypes -----------------------------------------------*/
/* USER CODE BEGIN FunctionPrototypes */

/* USER CODE END FunctionPrototypes */

/* Hook prototypes */
void vApplicationStackOverflowHook(xTaskHandle xTask, char *pcTaskName);
void vApplicationMallocFailedHook(void);

/* USER CODE BEGIN 4 */

/* ==========================================================================
 * BOTH HOOKS BELOW WERE EMPTY UNTIL 07-08-2026.  THAT WAS A REAL DEFECT.
 * ==========================================================================
 * configCHECK_FOR_STACK_OVERFLOW is 2 and configUSE_MALLOC_FAILED_HOOK is on,
 * so FreeRTOS was DETECTING both faults and then calling a function that did
 * nothing - after which execution continued on a corrupted stack or with a NULL
 * from pvPortMalloc. Detection you cannot observe is worse than no detection:
 * it converts a precise, named failure into an arbitrary HardFault somewhere
 * else entirely, minutes later.
 *
 * This is not hypothetical here. A HardFault was observed on 07-08-2026 with the
 * stack ending in prvIdleTask -> prvCheckTasksWaitingTermination ->
 * uxListRemove, i.e. the idle task tripping over a corrupted list while freeing
 * a deleted task's TCB - exactly the shape of damage silent corruption produces.
 *
 * printf is blocking UART and is not ISR-safe, but both hooks are called from
 * task context and the system is already unrecoverable at this point, so the
 * cost does not matter. Reporting then halting is strictly better than
 * continuing.
 * ======================================================================== */

void vApplicationStackOverflowHook(xTaskHandle xTask, char *pcTaskName)
{
  /* Run time stack overflow checking is performed if
     configCHECK_FOR_STACK_OVERFLOW is defined to 1 or 2. This hook function is
     called if a stack overflow is detected. */
  (void)xTask;

  /* The task NAME is the whole value of this message - it says which
     .stack_size to raise. Sizes are in BYTES under CMSIS-RTOS2 (osThreadAttr_t
     .stack_size), not words as in the older FreeRTOS v1 API. */
  printf("\r\n*** STACK OVERFLOW in task '%s' ***\r\n",
         (pcTaskName != NULL) ? pcTaskName : "<unknown>");
  printf("*** raise its stack_size. free heap %u B, halting. ***\r\n",
         (unsigned)xPortGetFreeHeapSize());

  /* Halt deliberately. Returning would resume a task whose stack has already
     been written past, which is how a clean diagnosis becomes a random fault. */
  taskDISABLE_INTERRUPTS();
  for (;;)
  {
  }
}
/* USER CODE END 4 */

/* USER CODE BEGIN 5 */
void vApplicationMallocFailedHook(void)
{
  /* vApplicationMallocFailedHook() will only be called if
     configUSE_MALLOC_FAILED_HOOK is set to 1 in FreeRTOSConfig.h. It is a hook
     function that will get called if a call to pvPortMalloc() fails. */

  /* This is the hook that catches mbedTLS running out of memory:
     mbedtls_platform_calloc() in Core/Src/mbedtls_platform_glue.c routes every
     mbedTLS allocation through pvPortMalloc, so a TLS handshake that dies for
     want of heap arrives HERE rather than anywhere near the TLS code. */
  printf("\r\n*** pvPortMalloc FAILED - FreeRTOS heap exhausted ***\r\n");
  printf("*** free heap %u B of configTOTAL_HEAP_SIZE. halting. ***\r\n",
         (unsigned)xPortGetFreeHeapSize());

  taskDISABLE_INTERRUPTS();
  for (;;)
  {
  }
}
/* USER CODE END 5 */

/* Private application code --------------------------------------------------*/
/* USER CODE BEGIN Application */

/* USER CODE END Application */

