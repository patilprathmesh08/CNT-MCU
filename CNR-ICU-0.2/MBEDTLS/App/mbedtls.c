/* USER CODE BEGIN Header */
/**
  ******************************************************************************
  * File Name          : mbedtls.c
  * Description        : This file provides code for the configuration
  *                      of the mbedtls instances.
  ******************************************************************************
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
#include "mbedtls.h"

/* USER CODE BEGIN 0 */
#include "mbedtls_platform_glue.h"   /* mbedtls_platform_calloc / _free */
#include "mbedtls/platform.h"        /* mbedtls_platform_set_calloc_free */
/* USER CODE END 0 */

/* USER CODE BEGIN 1 */

/* USER CODE END 1 */

/* Global variables ---------------------------------------------------------*/
mbedtls_ssl_context ssl;
mbedtls_ssl_config conf;
mbedtls_x509_crt cert;
mbedtls_ctr_drbg_context ctr_drbg;
mbedtls_entropy_context entropy;

/* USER CODE BEGIN 2 */

/* USER CODE END 2 */

/* MBEDTLS init function */
void MX_MBEDTLS_Init(void)
{
   /**
  */
  mbedtls_ssl_init(&ssl);
  mbedtls_ssl_config_init(&conf);
  mbedtls_x509_crt_init(&cert);
  mbedtls_ctr_drbg_init(&ctr_drbg);
  mbedtls_entropy_init( &entropy );
  /* USER CODE BEGIN 3 */

  /* ======================================================================
   * REDIRECT mbedTLS ONTO THE FreeRTOS HEAP.  Added 07-08-2026.
   * ======================================================================
   * Without this line every handshake allocation silently returns NULL.
   *
   * WHY. This project does not use the compile-time
   * MBEDTLS_PLATFORM_CALLOC_MACRO / FREE_MACRO form, so mbedtls_calloc and
   * mbedtls_free keep their defaults until this RUNTIME call redirects them.
   * The MBEDTLS_PLATFORM_STD_CALLOC define that CubeMX writes into main.h does
   * NOT reach mbedTLS: mbedtls_config.h never includes main.h, so platform.c
   * compiles against plain calloc/free - i.e. newlib's sbrk heap, which this
   * project's linker script sizes at _Min_Heap_Size = 0x200, just 512 BYTES.
   * An mbedTLS session context is several kilobytes, so it cannot possibly fit.
   *
   * mbedtls_platform_calloc()/_free() in Core/Src/mbedtls_platform_glue.c wrap
   * pvPortMalloc/vPortFree, putting mbedTLS on the 64 KB FreeRTOS heap_4 where
   * configTOTAL_HEAP_SIZE actually applies.
   *
   * ORDERING: must run before any other mbedTLS call that can allocate.
   * MX_MBEDTLS_Init() is invoked from main() before osKernelStart(), which is
   * the earliest such point, so here is correct.
   *
   * REGENERATION: this is USER CODE 3 and survives, but the file itself is
   * CubeMX-generated - it was ABSENT in this project's first generation on
   * 07-08-2026 and had to be added by hand, exactly as recorded for
   * TCP_Server_H753_RTOS__ES_MBEDTLS_V00. Verify it after any regeneration:
   *   Select-String -Path .\MBEDTLS\App\mbedtls.c -Pattern 'set_calloc_free'
   *
   * ======================================================================
   * SUPERSEDED 07-08-2026 - THIS RUNTIME CALL WAS NOT ENOUGH.
   * ======================================================================
   * It ran correctly and was still defeated. lwIP's altcp_tls calls
   * mbedtls_platform_set_calloc_free(&tls_malloc, &tls_free) itself
   * (altcp_tls_mbedtls_mem.c line 167, from altcp_mbedtls_mem_init(), reached via
   * altcp_tls_create_config()). That happens LATER than this, so it won, and every
   * mbedTLS allocation went to lwIP's 20 KB MEM_SIZE heap instead of the 64 KB
   * FreeRTOS heap. The ECDSA signature then failed with
   * MBEDTLS_ERR_MPI_ALLOC_FAILED. Proof: an instrumented mbedtls_platform_calloc()
   * recorded ZERO calls (tls_alloc_calls == 0) across a whole boot and handshake.
   *
   * THE CALL IS KEPT ANYWAY, deliberately. It still governs every mbedTLS
   * allocation made BEFORE altcp_tls_create_config() runs, and it costs nothing.
   * It is simply not sufficient on its own.
   *
   * THE ACTUAL FIX is MEM_SIZE in LWIP/Target/lwipopts.h USER CODE 1: since altcp
   * routes mbedTLS onto lwIP's mem heap, MEM_SIZE - not configTOTAL_HEAP_SIZE - is
   * what decides whether a handshake can complete. See the notes there and in
   * MBEDTLS/App/mbedtls_config.h USER CODE 1, which also records why the
   * compile-time MBEDTLS_PLATFORM_CALLOC_MACRO form cannot be used instead
   * (check_config.h rejects it alongside platform.h's MBEDTLS_PLATFORM_STD_FREE).
   *
   * DO NOT re-install the allocator after altcp_tls_create_config() returns to
   * force mbedTLS back onto the FreeRTOS heap. The cert, key and CA are allocated
   * INSIDE that call by altcp's tls_malloc() (lwIP mem_malloc), so freeing the
   * config afterwards would route them to vPortFree and corrupt both heaps.
   * ================================================================== */
  (void)mbedtls_platform_set_calloc_free(mbedtls_platform_calloc, mbedtls_platform_free);

  /* USER CODE END 3 */

}

/* USER CODE BEGIN 4 */

/* USER CODE END 4 */

/**
  * @}
  */

/**
  * @}
  */

