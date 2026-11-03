/**
  ******************************************************************************
  * @file    mbedtls_platform_glue.h
  * @brief   Mbed TLS platform hook: FreeRTOS heap allocator
  ******************************************************************************
  */

#ifndef MBEDTLS_PLATFORM_GLUE_H
#define MBEDTLS_PLATFORM_GLUE_H

#include <stddef.h>
#include <stdint.h>

/* Wired to mbedTLS via mbedtls_platform_set_calloc_free() - see
   MBEDTLS/App/mbedtls.c's MX_MBEDTLS_Init(), USER CODE BEGIN 3. */
void *mbedtls_platform_calloc(size_t n, size_t size);
void mbedtls_platform_free(void *ptr);

/* ==========================================================================
 * ALLOCATOR DIAGNOSTIC COUNTERS.  07-08-2026.  Remove with TLS_ALLOC_DIAG.
 * ==========================================================================
 * WATCH THESE IN THE IDE'S "Live Expressions" VIEW - that is the intended way
 * to read them, and it needs no extra call site anywhere in the firmware. Add
 * all five and attempt one HTTPS connection.
 *
 * HOW TO READ THE RESULT, given the handshake fails with
 * mbedtls_pk_sign() = -0x0010 (MBEDTLS_ERR_MPI_ALLOC_FAILED):
 *
 *   tls_alloc_fail_null > 0   Genuine heap exhaustion. The console line names
 *                             the exact size and the free heap at that moment.
 *                             Expect it to be the last thing printed, because
 *                             FreeRTOS's malloc-failed hook halts the board.
 *   tls_alloc_fail_zero > 0   A zero-size request happened. Now satisfied
 *                             rather than failed, so this may already be the
 *                             fix - see the note in the .c file.
 *   BOTH still 0              Memory was never the problem. The -0x0010 then
 *                             came from bignum.c's "nblimbs > 10000" sanity
 *                             check, i.e. a corrupted mbedtls_mpi, which is a
 *                             different investigation entirely.
 *
 * tls_alloc_min_free is the low-water mark of the FreeRTOS heap across the
 * whole run - the number that says whether 65536 is actually enough.
 * ======================================================================== */
extern volatile uint32_t tls_alloc_calls;
extern volatile uint32_t tls_alloc_fail_null;
extern volatile uint32_t tls_alloc_fail_zero;
extern volatile uint32_t tls_alloc_peak_bytes;
extern volatile uint32_t tls_alloc_min_free;

/* Optional one-line dump of the counters above. Not called by the firmware -
   invoke it from the debugger, or add a call site if you prefer console output
   to Live Expressions. */
void mbedtls_platform_alloc_report(const char *tag);

#endif /* MBEDTLS_PLATFORM_GLUE_H */
