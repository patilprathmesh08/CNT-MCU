/**
  ******************************************************************************
  * @file    mbedtls_platform_glue.c
  * @brief   Mbed TLS platform hook: FreeRTOS heap allocator
  * @version 1.1 - 28-07-2026 (H753 port)
  *
  * Implements mbedtls_platform_calloc()/mbedtls_platform_free(), wired to
  * mbedTLS at runtime via mbedtls_platform_set_calloc_free() (see
  * MBEDTLS/App/mbedtls.c's MX_MBEDTLS_Init(), USER CODE BEGIN 3) - routes
  * Mbed TLS's dynamic allocations through FreeRTOS's heap_4
  * (pvPortMalloc/vPortFree) instead of newlib's separate, tiny (512 byte)
  * sbrk-based heap, which is nowhere near enough for TLS.
  *
  * PORTING NOTE (H573 -> H753): the original H573 project (vendored
  * mbedTLS 3.6.7, MBEDTLS_PLATFORM_MEMORY with the macro form unset) also
  * had this file provide mbedtls_hardware_poll() (the
  * MBEDTLS_ENTROPY_HARDWARE_ALT entropy source). This H753 project uses
  * CubeMX's native mbedTLS pack instead (user-confirmed choice), which
  * auto-generates its OWN mbedtls_hardware_poll() in
  * MBEDTLS/Target/hardware_rng.c - so that function is deliberately NOT
  * duplicated here; defining it in both files would be a linker error.
  * ST's auto-generated version had a real entropy-quality bug, fixed
  * directly in hardware_rng.c rather than replacing it wholesale.
  ******************************************************************************
  */

#include "mbedtls_platform_glue.h"
#include "FreeRTOS.h"
#include "main.h"        /* HAL_GetTick() for the time source below */
#include <string.h>
#include <time.h>        /* time_t */
#include <sys/time.h>    /* struct timeval, suseconds_t - for _gettimeofday() */

/* ==========================================================================
 * ALLOCATOR DIAGNOSTICS.  Added 07-08-2026 for the HTTPS handshake fault.
 * ==========================================================================
 * Set to 0 to remove entirely. See docs/https_bringup_diagnosis_v1.0_07082026.md.
 *
 * WHY THIS EXISTS. The handshake fails with
 *     ssl_srv.c:3249: mbedtls_pk_sign() returned -16 (-0x0010)
 * and -0x0010 is MBEDTLS_ERR_MPI_ALLOC_FAILED (bignum.h). That code has exactly
 * four origins, all in bignum.c, and each is either "nblimbs > 10000" or
 * "mbedtls_calloc() returned NULL".
 *
 * Neither should be possible here: MPI allocations in a P-256 signature are
 * about 36 bytes, 30344 B of FreeRTOS heap was free at boot, and
 * configUSE_MALLOC_FAILED_HOOK is 1 with a hook that now prints and halts - and
 * it did NOT fire, so pvPortMalloc() apparently never returned NULL. One of
 * those assumptions is wrong, and static analysis cannot say which.
 *
 * These counters answer it directly. If a NULL is reported here, it is a real
 * allocation failure and the printed size/free-heap says why. If NOTHING is
 * reported and pk_sign still fails with -0x0010, then the failure came from
 * bignum.c's "nblimbs > MBEDTLS_MPI_MAX_LIMBS" test instead, which would mean a
 * corrupted mbedtls_mpi rather than memory exhaustion - a completely different
 * investigation.
 * ========================================================================
 * ==========================================================================
 * SET TO 0 ON 11-08-2026 - THE ANSWER IT GAVE, AND WHY IT IS NOW USELESS.
 * ==========================================================================
 * It worked, decisively: tls_alloc_calls stayed at 0 across a whole boot and
 * handshake even though the cert, key and CA had demonstrably been parsed. That
 * proved mbedtls_platform_calloc() was never being called, which no amount of
 * reading the source could show - the disassembly of MX_MBEDTLS_Init correctly
 * passes it to mbedtls_platform_set_calloc_free(). lwIP's altcp_tls was
 * overwriting the allocator afterwards (altcp_tls_mbedtls_mem.c line 167) and
 * routing mbedTLS onto lwIP's MEM_SIZE heap. See the MEM_SIZE block in
 * LWIP/Target/lwipopts.h USER CODE 1.
 *
 * WHY THE COUNTERS ARE NOW MEANINGLESS RATHER THAN MERELY IDLE: altcp owns the
 * allocator by design, so tls_alloc_calls stays 0 forever. Left enabled it would
 * read as "no allocations happening", which is exactly the wrong conclusion. Off
 * is more honest than on.
 *
 * The zero-size handling below is NOT part of the diagnostics and stays active -
 * mbedtls_platform_calloc() must behave like calloc(), which returns a valid
 * pointer for a zero-size request rather than NULL.
 *
 * Re-enabling: the five counters and mbedtls_platform_alloc_report() are declared
 * unconditionally in Core/Inc/mbedtls_platform_glue.h but only DEFINED when this
 * is 1, so referencing them with it at 0 is a deliberate link error rather than a
 * silent zero.
 * ======================================================================== */
#define TLS_ALLOC_DIAG   0

#if TLS_ALLOC_DIAG
#include <stdio.h>

/* Cumulative, inspectable from the debugger as well as via the printfs. */
volatile uint32_t tls_alloc_calls      = 0U;  /* successful allocations */
volatile uint32_t tls_alloc_fail_null  = 0U;  /* pvPortMalloc returned NULL */
volatile uint32_t tls_alloc_fail_zero  = 0U;  /* zero-size request (see below) */
volatile uint32_t tls_alloc_peak_bytes = 0U;  /* largest single request seen */
volatile uint32_t tls_alloc_min_free   = 0xFFFFFFFFU; /* low-water free heap */
#endif

/**
  * @brief  calloc() replacement backed by FreeRTOS's heap_4.
  * @param  n: number of elements
  * @param  size: size of each element in bytes
  * @retval Pointer to zero-initialized memory, or NULL on failure
  */
void *mbedtls_platform_calloc(size_t n, size_t size)
{
  size_t total = n * size;
  void *ptr;

  /* ------------------------------------------------------------------------
   * ZERO-SIZE REQUESTS.  Behaviour corrected 07-08-2026.
   * ------------------------------------------------------------------------
   * This used to "return NULL" here. That was a real deviation from the
   * function this replaces: mbedTLS's own default allocator is plain calloc(),
   * and calloc(0, x) returns a unique non-NULL pointer rather than failing.
   * mbedTLS treats NULL strictly as out-of-memory, so a zero-size request was
   * being reported as MBEDTLS_ERR_MPI_ALLOC_FAILED - indistinguishable from
   * genuine exhaustion.
   *
   * Auditing bignum.c suggests no caller in the signature path can actually
   * ask for zero (mbedtls_mpi_grow only allocates when nblimbs >= 1), so this
   * is probably not the current fault. It is fixed regardless, because
   * "matches calloc()" is the contract, and counted separately so the
   * diagnostics can prove whether it ever happens.
   * -------------------------------------------------------------------- */
  if (total == 0U)
  {
#if TLS_ALLOC_DIAG
    tls_alloc_fail_zero++;
    printf("tls_alloc: ZERO-SIZE request n=%u size=%u (now satisfied, was NULL)\r\n",
           (unsigned)n, (unsigned)size);
#endif
    total = 1U;   /* smallest valid block, so the caller gets a real pointer */
  }

  ptr = pvPortMalloc(total);
  if (ptr != NULL)
  {
    /* pvPortMalloc doesn't zero-fill like calloc must. */
    memset(ptr, 0, total);

#if TLS_ALLOC_DIAG
    {
      uint32_t freeNow = (uint32_t)xPortGetFreeHeapSize();
      tls_alloc_calls++;
      if ((uint32_t)total > tls_alloc_peak_bytes)
      {
        tls_alloc_peak_bytes = (uint32_t)total;
      }
      if (freeNow < tls_alloc_min_free)
      {
        tls_alloc_min_free = freeNow;
      }
    }
#endif
  }
#if TLS_ALLOC_DIAG
  else
  {
    /* THE LINE THAT SETTLES IT. If this appears, the fault is genuine heap
       exhaustion and the numbers say by how much. Note the FreeRTOS
       malloc-failed hook fires immediately after pvPortMalloc returns NULL and
       halts the board, so expect this line to be the last thing printed. */
    tls_alloc_fail_null++;
    printf("tls_alloc: *** pvPortMalloc(%u) FAILED *** n=%u size=%u "
           "free=%u calls=%u peak=%u\r\n",
           (unsigned)total, (unsigned)n, (unsigned)size,
           (unsigned)xPortGetFreeHeapSize(),
           (unsigned)tls_alloc_calls, (unsigned)tls_alloc_peak_bytes);
  }
#endif

  return ptr;
}

#if TLS_ALLOC_DIAG
/**
  * @brief  Prints the allocator counters. Call after a handshake attempt.
  * @retval None
  *
  * Reading these after a FAILED handshake is the point: if fail_null and
  * fail_zero are both 0 while pk_sign reported -0x0010, memory was never the
  * problem and bignum.c's nblimbs sanity check is what tripped.
  */
void mbedtls_platform_alloc_report(const char *tag)
{
  printf("tls_alloc[%s]: calls=%u fail_null=%u fail_zero=%u peak=%u B "
         "min_free=%u B free_now=%u B\r\n",
         (tag != NULL) ? tag : "-",
         (unsigned)tls_alloc_calls, (unsigned)tls_alloc_fail_null,
         (unsigned)tls_alloc_fail_zero, (unsigned)tls_alloc_peak_bytes,
         (tls_alloc_min_free == 0xFFFFFFFFU) ? 0U : (unsigned)tls_alloc_min_free,
         (unsigned)xPortGetFreeHeapSize());
}
#endif

/**
  * @brief  free() replacement matching mbedtls_platform_calloc() above.
  * @param  ptr: pointer previously returned by mbedtls_platform_calloc()
  * @retval None
  */
void mbedtls_platform_free(void *ptr)
{
  vPortFree(ptr);
}

/* ==========================================================================
 * TIME SOURCE FOR MBEDTLS_HAVE_TIME.  Added 07-08-2026 for the HTTPS port.
 * ==========================================================================
 * WHY THIS IS NEEDED AT ALL. MBEDTLS_HAVE_TIME had to be enabled - not for any
 * feature we want, but because lwIP's altcp_tls port requires it to COMPILE:
 * altcp_tls_mbedtls.c line 695 reads session->data.start unguarded, and that
 * member exists only behind "#if defined(MBEDTLS_HAVE_TIME)" (ssl.h line 792).
 * With MBEDTLS_HAVE_TIME off, the file cannot build at all.
 *
 * All the redirect options in mbedtls_config.h are left commented out
 * (MBEDTLS_PLATFORM_TIME_MACRO / _ALT / STD_TIME), so mbedTLS calls plain
 * time(). newlib implements time() on top of _gettimeofday(), which this project
 * does not provide - so without the function below the link fails with an
 * undefined reference, or newlib's stub silently returns -1.
 *
 * WHAT THIS IS AND IS NOT. It is MONOTONIC, not wall clock: seconds since boot
 * plus a fixed epoch. That is deliberate and sufficient, because
 * MBEDTLS_HAVE_TIME_DATE is DELIBERATELY LEFT OFF, so mbedTLS never validates
 * certificate notBefore/notAfter and never compares this against a real date.
 * Client certificates are still fully verified against the CA - signature and
 * identity - which is what mutual TLS is for. Only expiry is unchecked.
 *
 * The only other consumer is mbedtls_ssl_session.start, used for
 * session-resumption ageing, and ALTCP_MBEDTLS_USE_SESSION_CACHE is 0.
 *
 * IF YOU LATER WANT EXPIRY ENFORCEMENT: enable MBEDTLS_HAVE_TIME_DATE and back
 * this with the RTC. Do NOT enable it while this stub is in place - every
 * handshake would fail against a 1970-relative clock, including with perfectly
 * valid certificates, which is a genuinely confusing fault to chase.
 *
 * HAL_GetTick() wraps after ~49.7 days. Only the difference matters here, and
 * nothing compares absolute values, so the wrap is harmless.
 * ======================================================================== */

/* Fixed epoch so the value is plausible rather than 1970: 01-01-2026 00:00 UTC.
   Chosen only to make timestamps readable if they ever surface in a debug log. */
#define TLS_TIME_EPOCH_BASE   ((time_t)1767225600)

/**
  * @brief  newlib time-of-day hook, used by time() and hence by mbedTLS.
  * @param  tv: receives seconds/microseconds since the fixed epoch
  * @param  tzp: timezone, unused (obsolete in POSIX)
  * @retval 0 always - reporting failure would make time() return -1
  */
int _gettimeofday(struct timeval *tv, void *tzp)
{
  uint32_t ms = HAL_GetTick();

  (void)tzp;

  if (tv != NULL)
  {
    tv->tv_sec  = TLS_TIME_EPOCH_BASE + (time_t)(ms / 1000U);
    tv->tv_usec = (suseconds_t)((ms % 1000U) * 1000U);
  }

  return 0;
}
