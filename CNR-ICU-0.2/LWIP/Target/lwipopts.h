/* USER CODE BEGIN Header */
/**
  ******************************************************************************
  * File Name          : Target/lwipopts.h
  * Description        : This file overrides LwIP stack default configuration
  *                      done in opt.h file.
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

/* Define to prevent recursive inclusion --------------------------------------*/
#ifndef __LWIPOPTS__H__
#define __LWIPOPTS__H__

#include "main.h"

/*-----------------------------------------------------------------------------*/
/* Current version of LwIP supported by CubeMx: 2.2.1 -*/
/*-----------------------------------------------------------------------------*/

/* Within 'USER CODE' section, code will be kept by default at each generation */
/* USER CODE BEGIN 0 */

/* USER CODE END 0 */

#ifdef __cplusplus
 extern "C" {
#endif

/* STM32CubeMX Specific Parameters (not defined in opt.h) ---------------------*/
/* Parameters set in STM32CubeMX LwIP Configuration GUI -*/
/*----- WITH_RTOS enabled (Since FREERTOS is set) -----*/
#define WITH_RTOS 1
/* Temporary workaround to avoid conflict on errno defined in STM32CubeIDE and lwip sys_arch.c errno */
#undef LWIP_PROVIDE_ERRNO
/*----- WITH_MBEDTLS enabled (Since MBEDTLS and FREERTOS are set) -----*/
#define WITH_MBEDTLS 1
/*----- CHECKSUM_BY_HARDWARE enabled -----*/
#define CHECKSUM_BY_HARDWARE 1
/*-----------------------------------------------------------------------------*/

/* LwIP Stack Parameters (modified compared to initialization value in opt.h) -*/
/* Parameters set in STM32CubeMX LwIP Configuration GUI -*/
/*----- Default value in ETH configuration GUI in CubeMx: 1524 -----*/
#define ETH_RX_BUFFER_SIZE 1536
/*----- Value in opt.h for LWIP_DNS: 0 -----*/
#define LWIP_DNS 1
/*----- Default Value for MEMP_NUM_TCP_PCB: 5 ---*/
#define MEMP_NUM_TCP_PCB 8
/*----- Value in opt.h for MEM_ALIGNMENT: 1 -----*/
#define MEM_ALIGNMENT 4
/*----- Default Value for MEM_SIZE: 1600 ---*/
#define MEM_SIZE 20480
/*----- Default Value for H7 devices: 0x30004000 -----*/
#define LWIP_RAM_HEAP_POINTER 0x30005000
/*----- Default Value for MEMP_NUM_TCP_SEG: 16 ---*/
#define MEMP_NUM_TCP_SEG 20
/*----- Value supported for H7 devices: 1 -----*/
#define LWIP_SUPPORT_CUSTOM_PBUF 1
/*----- Default Value for PBUF_POOL_BUFSIZE: 592 ---*/
#define PBUF_POOL_BUFSIZE 1536
/*----- Value in opt.h for LWIP_ETHERNET: LWIP_ARP || PPPOE_SUPPORT -*/
#define LWIP_ETHERNET 1
/*----- Value in opt.h for LWIP_DNS_SECURE: (LWIP_DNS_SECURE_RAND_XID | LWIP_DNS_SECURE_NO_MULTIPLE_OUTSTANDING | LWIP_DNS_SECURE_RAND_SRC_PORT) -*/
#define LWIP_DNS_SECURE 7
/*----- Default Value for TCP_MSS: 536 ---*/
#define TCP_MSS 1460
/*----- Default Value for TCP_SND_BUF: 2920 ---*/
#define TCP_SND_BUF 5840
/*----- Default Value for LWIP_ALTCP: 0 ---*/
#define LWIP_ALTCP 1
/*----- Default Value for LWIP_ALTCP_TLS: 0 ---*/
#define LWIP_ALTCP_TLS 1
/*----- Value in opt.h for LWIP_NETIF_LINK_CALLBACK: 0 -----*/
#define LWIP_NETIF_LINK_CALLBACK 1
/*----- Value in opt.h for TCPIP_THREAD_STACKSIZE: 0 -----*/
#define TCPIP_THREAD_STACKSIZE 8192
/*----- Value in opt.h for TCPIP_THREAD_PRIO: 1 -----*/
#define TCPIP_THREAD_PRIO 24
/*----- Value in opt.h for TCPIP_MBOX_SIZE: 0 -----*/
#define TCPIP_MBOX_SIZE 6
/*----- Value in opt.h for SLIPIF_THREAD_STACKSIZE: 0 -----*/
#define SLIPIF_THREAD_STACKSIZE 1024
/*----- Value in opt.h for SLIPIF_THREAD_PRIO: 1 -----*/
#define SLIPIF_THREAD_PRIO 3
/*----- Value in opt.h for DEFAULT_THREAD_STACKSIZE: 0 -----*/
#define DEFAULT_THREAD_STACKSIZE 1024
/*----- Value in opt.h for DEFAULT_THREAD_PRIO: 1 -----*/
#define DEFAULT_THREAD_PRIO 3
/*----- Value in opt.h for DEFAULT_UDP_RECVMBOX_SIZE: 0 -----*/
#define DEFAULT_UDP_RECVMBOX_SIZE 6
/*----- Value in opt.h for DEFAULT_TCP_RECVMBOX_SIZE: 0 -----*/
#define DEFAULT_TCP_RECVMBOX_SIZE 6
/*----- Value in opt.h for DEFAULT_ACCEPTMBOX_SIZE: 0 -----*/
#define DEFAULT_ACCEPTMBOX_SIZE 6
/*----- Value in opt.h for RECV_BUFSIZE_DEFAULT: INT_MAX -----*/
#define RECV_BUFSIZE_DEFAULT 2000000000
/*----- Value in opt.h for LWIP_USE_EXTERNAL_MBEDTLS: 0 -----*/
#define LWIP_USE_EXTERNAL_MBEDTLS 1
/*----- Default Value for LWIP_HTTPD: 0 ---*/
#define LWIP_HTTPD 1
/*----- Default Value for LWIP_HTTPD_SUPPORT_POST: 0 ---*/
#define LWIP_HTTPD_SUPPORT_POST 1
/*----- Default Value for LWIP_HTTPD_DYNAMIC_HEADERS: 0 ---*/
#define LWIP_HTTPD_DYNAMIC_HEADERS 1
/*----- Default Value for HTTPD_ENABLE_HTTPS: 0 ---*/
#define HTTPD_ENABLE_HTTPS 1
/*----- Default Value for LWIP_HTTPD_SUPPORT_11_KEEPALIVE: 0 ---*/
#define LWIP_HTTPD_SUPPORT_11_KEEPALIVE 1
/*----- Default Value for LWIP_HTTPD_CUSTOM_FILES: 0 ---*/
#define LWIP_HTTPD_CUSTOM_FILES 1
/*----- Value in opt.h for HTTPD_USE_CUSTOM_FSDATA: 0 -----*/
#define HTTPD_USE_CUSTOM_FSDATA 1
/*----- Value in opt.h for LWIP_STATS: 1 -----*/
#define LWIP_STATS 0
/*----- Value in opt.h for CHECKSUM_GEN_IP: 1 -----*/
#define CHECKSUM_GEN_IP 0
/*----- Value in opt.h for CHECKSUM_GEN_UDP: 1 -----*/
#define CHECKSUM_GEN_UDP 0
/*----- Value in opt.h for CHECKSUM_GEN_TCP: 1 -----*/
#define CHECKSUM_GEN_TCP 0
/*----- Value in opt.h for CHECKSUM_GEN_ICMP: 1 -----*/
#define CHECKSUM_GEN_ICMP 0
/*----- Value in opt.h for CHECKSUM_GEN_ICMP6: 1 -----*/
#define CHECKSUM_GEN_ICMP6 0
/*----- Value in opt.h for CHECKSUM_CHECK_IP: 1 -----*/
#define CHECKSUM_CHECK_IP 0
/*----- Value in opt.h for CHECKSUM_CHECK_UDP: 1 -----*/
#define CHECKSUM_CHECK_UDP 0
/*----- Value in opt.h for CHECKSUM_CHECK_TCP: 1 -----*/
#define CHECKSUM_CHECK_TCP 0
/*----- Value in opt.h for CHECKSUM_CHECK_ICMP: 1 -----*/
#define CHECKSUM_CHECK_ICMP 0
/*----- Value in opt.h for CHECKSUM_CHECK_ICMP6: 1 -----*/
#define CHECKSUM_CHECK_ICMP6 0
/*-----------------------------------------------------------------------------*/
/* USER CODE BEGIN 1 */

/**
  * @brief  Cancel the CubeMX-generated LWIP_RAM_HEAP_POINTER above.
  *         Re-applied 05-08-2026 after the HTTPD regeneration reinstated it.
  *
  * WHY THIS IS AN #undef AND NOT A DELETION
  * The .ioc carries LWIP.LWIP_RAM_HEAP_POINTER=0x30005000 and lists it in
  * LWIP.IPParameters, so every code generation re-emits the #define around
  * line 63 of this file. Deleting that line works exactly once. This block is
  * inside a USER CODE marker and sits AFTER the generated #define, so the
  * #undef wins permanently and no future regeneration can reintroduce the
  * fault. Removing the parameter from the .ioc GUI is not possible either:
  * CubeMX offers no "unset" for it on H7.
  *
  * WHAT THE FAULT WAS (diagnosed 30-07-2026)
  * Every mem_malloc() from a heap at this literal address failed:
  * pbuf_alloc(PBUF_RAM) returned NULL for all sizes, lwip_stats.mem showed
  * used=0/max=0 with err climbing, and etharp.memerr tracked every inbound ARP
  * request one-for-one. lwIP could therefore never build an ARP reply and
  * low_level_output() was never reached at all (tx_calls stayed 0).
  *
  * Root cause: because this is a bare address literal rather than a symbol,
  * lwIP's mem.c skips its own LWIP_DECLARE_MEMORY_ALIGNED(ram_heap, ...)
  * definition. The linker is then never told the memory is in use, and - unlike
  * the three ETH sections, which the linker script does place - nothing
  * reserves or verifies it. Letting mem.c declare ram_heap normally puts the
  * heap in .bss, where the linker allocates and accounts for it properly.
  *
  * CONSEQUENCE TO KEEP IN MIND
  * .bss lives in RAM_D1 (0x24000000), which is CACHEABLE and outside the
  * non-cacheable MPU region at 0x30000000. Tx pbufs are allocated from this
  * heap and read directly by the Ethernet DMA, so low_level_output() must clean
  * the D-cache before handing them over. That is the SCB_CleanDCache_by_Addr()
  * loop in ethernetif.c - the two edits are a matched pair. If you ever restore
  * LWIP_RAM_HEAP_POINTER, that cache clean becomes redundant; if you remove the
  * cache clean while this #undef stands, transmit silently sends stale bytes.
  */
#undef LWIP_RAM_HEAP_POINTER

/**
  * @brief  HTTPD settings mirrored from the .ioc, 05-08-2026.
  *
  * WHY THESE ARE HERE AND NOT LEFT TO CubeMX
  * The .ioc does hold all three (LWIP.LWIP_HTTPD=1,
  * LWIP.HTTPD_USE_CUSTOM_FSDATA=1, LWIP.MEMP_NUM_TCP_PCB=8) and code generation
  * does emit them into the generated section above. But restoring this file from
  * a pre-generation backup - which is exactly what had to be done on 05-08-2026
  * to recover the lwIP heap and Ethernet transmit fixes - silently rolls those
  * three lines back out again. Mirroring them inside USER CODE makes the file
  * correct in BOTH directions: after a regeneration and after a backup restore.
  *
  * The #ifndef guards mean the generated #define wins when it is present, so
  * changing a value in the CubeMX GUI still takes effect and there is never a
  * conflicting redefinition.
  */

/* Makes fs.c resolve HTTPD_FSDATA_FILE to "fsdata_custom.c" instead of
   "fsdata.c" (see httpd_opts.h). Two reasons this must stay 1:
     1. CubeMX never copies fsdata.c at all. Its database
        (db\mcu\config\LWIP-STM32H7xx_Configs.xml) asks for
        "src/apps/httpd/fsdata.c", but the real path in FW_H7 V1.13.0 is
        "src/apps/http/fsdata.c" - a directory named "httpd" does not exist.
        So the file has to be supplied by hand whatever this is set to.
     2. A file named fsdata_custom.c is not one CubeMX owns, so the web content
        cannot be clobbered by a future code generation. */
#ifndef HTTPD_USE_CUSTOM_FSDATA
#define HTTPD_USE_CUSTOM_FSDATA 1
#endif

/* Ceiling on simultaneous TCP connections. Raised from the lwIP default of 5.
   Comment corrected 07-08-2026: it used to say this was needed "because
   LWIP_HTTPD_SUPPORT_11_KEEPALIVE is 0", which is no longer true - that option
   is now 1. The headroom is still needed, for a narrower reason:

   Keep-alive is enabled but applies ONLY to the dynamic endpoints. The three
   static files in fsdata_custom.c deliberately do NOT carry
   FS_FILE_FLAGS_HEADER_PERSISTENT, because their makefsdata-baked headers say
   HTTP/1.0 with no Connection line - so httpd.c line 2448 forces keepalive=0 for
   them and they still close per request. A browser loading a page plus its
   stylesheet, script and image therefore still opens a connection per asset,
   each lingering in TIME_WAIT, which is what can exceed 5 PCBs. */
#ifndef MEMP_NUM_TCP_PCB
#define MEMP_NUM_TCP_PCB 8
#endif

/* Deliberately NOT mirrored: LWIP_HTTPD.
   It is a CubeMX invention, labelled "** CubeMX specific **" in the CubeMX
   database and confirmed by grep to appear nowhere in lwIP's httpd.c, fs.c or
   httpd_opts.h. Its only jobs are to tell CubeMX which files to copy and to
   gate emission of HTTPD_USE_CUSTOM_FSDATA. Defining it here would add a dead
   macro that reads as if it switched something on. */

/* ==========================================================================
 * TLS FOR HTTPD.  Added 07-08-2026.  NEITHER IS SETTABLE IN CubeMX.
 * ==========================================================================
 * LWIP_ALTCP and LWIP_ALTCP_TLS come from the .ioc and are emitted above
 * (lines 81 and 83). These two cannot be: LWIP_ALTCP_TLS_MBEDTLS appears in the
 * CubeMX database only inside a description string, never as a parameter, and
 * ALTCP_MBEDTLS_AUTHMODE is not in the database at all.
 * ======================================================================== */

/* Selects mbedTLS as the TLS backend for the altcp layer.
   WITHOUT THIS, altcp_tls_mbedtls.c COMPILES TO NOTHING. Its entire body sits
   behind "#if LWIP_ALTCP_TLS && LWIP_ALTCP_TLS_MBEDTLS", so the file builds
   clean, links clean, and then every altcp_tls_create_config_*() call returns
   NULL at runtime - httpd_inits() gets a NULL config and no HTTPS listener is
   ever created. Silent in every way that matters. */
#define LWIP_ALTCP_TLS_MBEDTLS   1

/* MUTUAL TLS. altcp_tls_mbedtls_opts.h line 106 defaults this to
   MBEDTLS_SSL_VERIFY_OPTIONAL, which means a client presenting NO certificate is
   ACCEPTED - the handshake completes and the request is served. For a project
   whose requirement is mutual TLS that is precisely the wrong default, and it
   fails open rather than closed, so nothing announces it.
   altcp_tls_mbedtls.c line 841 passes this straight to
   mbedtls_ssl_conf_authmode().

   REQUIRED is only half of mutual auth: the server also needs a CA chain to
   verify the client against, and altcp_tls_create_config_server() deliberately
   clears it (line 879: mbedtls_ssl_conf_ca_chain(&conf->conf, NULL, NULL)).
   http_server.c installs the CA afterwards - see the note there. Setting this to
   REQUIRED without that CA would reject every client. */
#define ALTCP_MBEDTLS_AUTHMODE   MBEDTLS_SSL_VERIFY_REQUIRED

/* ==========================================================================
 * TLS SESSION RESUMPTION.  Added 11-08-2026 to cut handshake cost.
 * ==========================================================================
 * WHY. A full handshake on this board costs about 1.55 s of pure software P-256
 * arithmetic, measured 11-08-2026 with a passive TCP relay that timestamps each
 * flight:
 *     451 ms  ECDHE keygen + ECDSA sign of ServerKeyExchange
 *    1101 ms  ECDH shared secret + verify client cert + verify CertificateVerify
 * The second phase is 71% of it and is dominated by the two ECDSA VERIFIES that
 * mutual TLS requires. Verifies use variable-base point multiplication and cannot
 * use the fixed-point precomputation that signing benefits from.
 *
 * A RESUMED handshake skips all of that - no ECDHE, no sign, no verifies - and
 * completes in milliseconds off the cached master secret. It does nothing for a
 * first-time connection; that is what -Os buys (see below).
 *
 * NOT hardware-fixable: the STM32H753 has CRYP and HASH but NO public-key
 * accelerator (zero PKA references in stm32h753xx.h), so ECC stays in software.
 * MBEDTLS_ECP_WINDOW_SIZE and MBEDTLS_ECP_FIXED_POINT_OPTIM are already at their
 * fastest library defaults (6 and 1) - changing them is a no-op, checked.
 *
 * SECURITY NOTE FOR A MUTUAL-TLS SERVER: on a resumed handshake the client
 * certificate is NOT re-sent and NOT re-verified. That is standard TLS behaviour
 * and safe - only a party holding the original session's master secret can resume,
 * and that session was fully authenticated - but it does mean client-certificate
 * verification happens once per session, not once per connection. Sessions expire
 * after ALTCP_MBEDTLS_SESSION_CACHE_TIMEOUT_SECONDS, which is 1 hour by default
 * and deliberately left at that.
 *
 * Requires MBEDTLS_SSL_CACHE_C (already enabled in mbedtls_config.h) and
 * ssl_cache.c (already in the build).
 * ======================================================================== */
#define ALTCP_MBEDTLS_USE_SESSION_CACHE   1

/* SIZE OVERRIDE IS NOT OPTIONAL - altcp defaults this to 30
 * (altcp_tls_mbedtls_opts.h line 77) and that default is dangerous here.
 * Cache entries are allocated by the mbedTLS allocator, which altcp routes onto
 * lwIP's MEM_SIZE heap (see the MEM_SIZE block below). In mbedTLS 2.16 a cached
 * session carries the peer certificate, so an entry is roughly 640 bytes; 30 of
 * them is about 19 KB out of a 48 KB heap that must ALSO hold the 12-16 KB a live
 * handshake needs. That is how the MEM_SIZE exhaustion fixed on 07-08-2026 would
 * come straight back, and it would present as an intermittent handshake failure
 * under load rather than anything pointing at the cache.
 *
 * 4 is ample for this application: it is a single-client test endpoint, and the
 * cache only needs to span the gap between one connection closing and the next
 * opening. Raise it only alongside MEM_SIZE, and re-run test_https.ps1 -Test
 * KeepAlive afterwards. */
#define ALTCP_MBEDTLS_SESSION_CACHE_SIZE  4

/* ==========================================================================
 * TCPIP_THREAD STACK, RAISED FOR TLS.  07-08-2026.
 * ==========================================================================
 * WHY THE GENERATED 8192 IS NOT ENOUGH ANY MORE. Before TLS, tcpip_thread only
 * ever ran lwIP itself. With altcp_tls it also runs THE ENTIRE TLS HANDSHAKE:
 * altcp_tls_mbedtls.c line 285 calls mbedtls_ssl_handshake() straight from the
 * lwIP recv callback, so every ECDHE key generation and ECDSA signature happens
 * on THIS stack. That path is deep and its frames are large - from the build's
 * own -fstack-usage data: mbedtls_mpi_exp_mod 1664 B, mpi_mul_hlp 680 B,
 * ecp_mul_comb_after_precomp 328 B, ssl_prepare_server_key_exchange 160 B, all
 * of which nest, on top of the lwIP frames already below them.
 *
 * Measured evidence that made this suspect: the board accepts the TCP connection
 * in 0.35 ms, sends exactly 566 bytes (ServerHello + Certificate), spends ~365 ms
 * - real ECC work, not a timeout - and then closes without sending
 * ServerKeyExchange. Identical behaviour from both OpenSSL and .NET, and
 * unchanged by a 94-byte minimal ClientHello, so it is entirely server-side.
 *
 * THIS IS A HYPOTHESIS-DRIVEN CHANGE, NOT A PROVEN FIX. It is cheap (8 KB of the
 * ~38 KB free in ucHeap) and it is now self-reporting: vApplicationStackOverflowHook
 * in Core/Src/freertos.c was EMPTY until 07-08-2026 and silently swallowed
 * overflows, which is why nothing was ever printed. It now names the task and
 * halts, so if this value is still short you will be told which task and can stop
 * guessing.
 *
 * #undef RATHER THAN EDIT ABOVE: CubeMX emits TCPIP_THREAD_STACKSIZE from the
 * .ioc (LWIP -> TCPIP_THREAD_STACKSIZE) into the generated block, so editing it
 * there works exactly once. Raise it in the GUI too so the two agree, but this
 * pair is what actually takes effect. Same technique as LWIP_RAM_HEAP_POINTER
 * at the top of this block. */
#undef  TCPIP_THREAD_STACKSIZE
#define TCPIP_THREAD_STACKSIZE   16384

/* ==========================================================================
 * TCPIP_THREAD_PRIO 24 -> 28.   12-08-2026.
 * ==========================================================================
 * THE BUG. The generated value above is 24, and the four UART dispatch tasks in
 * the .ioc are ALSO priority 24:
 *     FREERTOS.Tasks01= ... Usart1Task,24 ... Usart2Task,24 ... Uart4Task,24
 *                       ... Uart5Task,24
 * FreeRTOS has configUSE_PREEMPTION 1, but preemption only helps a HIGHER
 * priority task. configUSE_TIME_SLICING is not defined in FreeRTOSConfig.h, so it
 * defaults to 1, and equal-priority ready tasks therefore round-robin on the
 * 1 kHz tick. When a request arrives while a UART task is running, tcpip_thread
 * cannot preempt it - it waits for time slicing, up to one tick per equal-priority
 * task queued ahead of it. With four UART tasks that is several milliseconds.
 *
 * HOW IT WAS FOUND, and why the obvious suspect was wrong. DWT instrumentation in
 * http_server.c showed the whole application window is 18 us against a 13.8 ms
 * worst-case RTT - 0.13% - so the delay was outside the application entirely. A
 * 2x2 then separated payload size from UART involvement, 600 messages per arm at a
 * 5 ms interval, two passes in opposite order:
 *
 *     mean p95      9 B payload   21 B payload
 *     /echo     (no UART)  1.366 ms      1.340 ms
 *     /uartecho (UART)     7.864 ms      9.207 ms
 *
 * Payload size costs -0.027 ms with no UART and +1.343 ms with one, and merely
 * involving a UART costs +6.5 ms. A per-byte-interrupt explanation cannot account
 * for that: 9 B -> 21 B adds 12 interrupts for 1.343 ms, which would be 112 us per
 * ISR. Scheduling can - and the +6.5 ms fixed component is the signature.
 *
 * WHY 28 AND NOT MORE. osPriorityNormal4 (cmsis_os2.h:127). It must be above the
 * UART tasks at 24 so tcpip_thread preempts them, and below the EthIf task at 32,
 * which runs ethernetif_input and must stay the highest of the three - packets have
 * to be pulled off the DMA descriptors before anything can process them.
 *
 * STARVATION was considered and is not a risk: a UART task only runs briefly to
 * start a transfer and then blocks on tx_done_sem while the peripheral shifts
 * bytes out, so it needs the CPU for microseconds, not milliseconds.
 *
 * #undef RATHER THAN EDIT THE GENERATED VALUE, for the same reason as
 * TCPIP_THREAD_STACKSIZE above: CubeMX rewrites it from the .ioc. This pair is
 * what takes effect. The alternative - lowering the four UART tasks in the GUI -
 * needs a regeneration and would revert on the next one.
 *
 * EXPECTED, NOT YET CONFIRMED: /uartecho p95 should fall from ~7.9 ms toward the
 * ~1.35 ms that /echo already achieves. Measure before believing it. */
#undef  TCPIP_THREAD_PRIO
#define TCPIP_THREAD_PRIO        28

/* ==========================================================================
 * HTTPS BRING-UP DIAGNOSTICS.  07-08-2026.  REMOVE ONCE HTTPS IS VERIFIED.
 * ==========================================================================
 * WHY THE BOARD WAS SILENT ABOUT THE FAILED HANDSHAKE. altcp_tls_mbedtls.c
 * line 300 already reports the exact cause:
 *     LWIP_DEBUGF(ALTCP_MBEDTLS_DEBUG, ("mbedtls_ssl_handshake failed: %d\n", ret));
 * but LWIP_DEBUGF expands to NOTHING unless LWIP_DEBUG is defined, and this
 * project never defined it - not in lwipopts.h, not in opt.h, and not as a -D on
 * the command line. So the one message that identifies the fault was compiled
 * out. Turning LWIP_DEBUG on only enables the INFRASTRUCTURE; every per-module
 * flag still defaults to LWIP_DBG_OFF, so the two below are the only output.
 *
 * Output goes to printf via LWIP_PLATFORM_DIAG (lwip/arch.h line 81), i.e. the
 * ST-LINK VCP, same as every other banner.
 *
 * LEVEL_MIN 1 IS DELIBERATE - DO NOT RAISE IT CASUALLY. mbedTLS level 1 is
 * errors only, a handful of lines. Level 3+ is hundreds of lines, and printf here
 * is BLOCKING UART at roughly 8.5 ms per line - enough to change handshake
 * timing and turn this into a different bug. This project has already been bitten
 * once by a diagnostic printf distorting a measurement.
 *
 * mbedTLS additionally needs MBEDTLS_DEBUG_C (MBEDTLS/App/mbedtls_config.h USER
 * CODE 1) and a threshold set at runtime (mbedtls_debug_set_threshold() in
 * Core/Src/http_server.c). All three are required; any one missing yields silence.
 * ======================================================================== */
/* ==========================================================================
 * ALL FOUR DISABLED 11-08-2026 - HTTPS IS VERIFIED, THE DIAGNOSTICS ARE DONE.
 * ==========================================================================
 * UNCOMMENT ALL FOUR TOGETHER, never just one. LWIP_DEBUG is the master switch:
 * LWIP_DEBUGF expands to nothing without it, so the ALTCP_* flags below are inert
 * on their own and you would get silence and conclude the instrumentation was
 * broken. ALTCP_MBEDTLS_MEM_DEBUG above belongs to the same set.
 *
 * ALSO REQUIRED for the mbedTLS-level trace: MBEDTLS_DEBUG_C in
 * MBEDTLS/App/mbedtls_config.h USER CODE 1, plus mbedtls_debug_set_threshold()
 * in Core/Src/http_server.c. All three, or nothing is printed. Note
 * MBEDTLS_DEBUG_C additionally needs Middlewares/Third_Party/mbedTLS/library/
 * debug.c, which CubeMX does NOT copy - it was added by hand on 07-08-2026 and is
 * still there, so re-enabling costs nothing but flash.
 *
 * WHAT THESE FOUND, for the next person who needs them: the HTTPS handshake was
 * dying at ssl_srv.c:3249 with mbedtls_pk_sign() = -0x0010
 * (MBEDTLS_ERR_MPI_ALLOC_FAILED) and the board said NOTHING, because LWIP_DEBUG
 * had never been defined in this project and altcp_tls_mbedtls.c line 300 - the
 * one message that names the cause - was compiled out. Root cause turned out to
 * be MEM_SIZE; see the block below.
 *
 * Cost when enabled: roughly 39 KB of flash, almost all of it mbedTLS debug
 * strings. Keep at level 1: printf here is BLOCKING UART at about 8.5 ms a line,
 * and level 3+ emits hundreds of lines and changes handshake timing.
 * ======================================================================== */
/* #define LWIP_DEBUG */
/* #define ALTCP_MBEDTLS_DEBUG             LWIP_DBG_ON */
/* #define ALTCP_MBEDTLS_LIB_DEBUG         LWIP_DBG_ON */
/* #define ALTCP_MBEDTLS_LIB_DEBUG_LEVEL_MIN  1 */

/* Reports which lwIP-heap allocation failed, and its size, from altcp's own
   tls_malloc() (altcp_tls_mbedtls_mem.c line 123). This is the counterpart to
   MEM_SIZE below: if a handshake still fails for memory, this names the request
   that could not be satisfied. Cheap - it only prints on failure. */
/* #define ALTCP_MBEDTLS_MEM_DEBUG         LWIP_DBG_ON */

/* ==========================================================================
 * MEM_SIZE - THE FIX FOR THE HTTPS HANDSHAKE FAILURE.  07-08-2026.
 * ==========================================================================
 * THIS IS NOT NETWORK TUNING. It is the TLS session budget. Do not reduce it
 * without reading this.
 *
 * THE FAULT. Every HTTPS handshake died at
 *     ssl_srv.c:3249: mbedtls_pk_sign() returned -16 (-0x0010)
 * = MBEDTLS_ERR_MPI_ALLOC_FAILED, while signing the ServerKeyExchange - so the
 * client got ServerHello + Certificate (566 bytes) and then a closed connection.
 *
 * WHY IT LOOKED IMPOSSIBLE. 30,344 B of the FreeRTOS heap was free,
 * configUSE_MALLOC_FAILED_HOOK is 1 and its hook never fired, and an instrumented
 * mbedtls_platform_calloc() recorded ZERO calls across a whole boot and handshake
 * (tls_alloc_calls == 0) - even though the cert, key and CA had clearly been
 * parsed, which requires allocation.
 *
 * WHY. mbedTLS was not using the FreeRTOS heap at all. lwIP's altcp_tls installs
 * its OWN mbedTLS allocator - altcp_tls_mbedtls_mem.c line 167:
 *     mbedtls_platform_set_calloc_free(&tls_malloc, &tls_free);
 * from altcp_mbedtls_mem_init(), called at the top of altcp_tls_create_config()
 * (altcp_tls_mbedtls.c line 793). That runs AFTER MX_MBEDTLS_Init() has installed
 * mbedtls_platform_calloc(), so it wins. tls_malloc() calls lwIP's mem_malloc(),
 * so EVERY mbedTLS allocation - session context, the 2 KB in and 4 KB out record
 * buffers, handshake state, and the ECC temporaries - comes out of THIS heap,
 * which was 20480 B and already serving every pbuf, PCB and the HTTP server.
 * Parsing the credentials (~1 KB) fitted. The signature did not.
 *
 * So for a TLS build, MEM_SIZE - not configTOTAL_HEAP_SIZE - is the number that
 * decides whether a handshake can complete. That is genuinely counter-intuitive,
 * which is why it is also recorded in MBEDTLS/App/mbedtls_config.h USER CODE 1
 * and MBEDTLS/App/mbedtls.c USER CODE 3.
 *
 * SIZING. Per concurrent TLS session, roughly:
 *     in_buf  MBEDTLS_SSL_IN_CONTENT_LEN  2048 + record overhead  ~2.1 KB
 *     out_buf MBEDTLS_SSL_OUT_CONTENT_LEN 4096 + record overhead  ~4.2 KB
 *     ssl_context                                                 ~0.5 KB
 *     handshake params (incl. MBEDTLS_PREMASTER_SIZE 1024)        ~2.5 KB
 *     ECDHE/ECDSA comb tables and MPI temporaries                 ~2.5 KB
 *     plus 8 bytes of altcp helper header per allocation
 * about 12-16 KB peak, on top of the ~20 KB lwIP already wanted. 49152 leaves
 * room for one comfortable session plus normal traffic, and headroom for a
 * second. RAM_D1 is 512 KB and the heap lives in .bss, so the cost is only RAM
 * footprint - no MPU or cache implications (see the LWIP_RAM_HEAP_POINTER note at
 * the top of this block for why it must stay in .bss).
 *
 * Must stay below 65535 while lwIP's mem_size_t is u16_t, which it is here.
 *
 * #undef because CubeMX emits MEM_SIZE from the .ioc into the generated block
 * above, so editing it there works exactly once. Raise it in the GUI too so the
 * two agree, but this pair is what takes effect. Same technique as
 * LWIP_RAM_HEAP_POINTER and TCPIP_THREAD_STACKSIZE.
 * ======================================================================== */
#undef  MEM_SIZE
#define MEM_SIZE                        49152

/* ==========================================================================
 * DHCP.  Added 24-08-2026.
 * ==========================================================================
 * The board now takes its address from a DHCP server instead of the static
 * 192.168.1.10 it used from 07-08-2026 to 24-08-2026.
 *
 * WHY IT IS SET HERE AND NOT IN THE .ioc. The .ioc still says
 * LWIP.LWIP_DHCP=0, and that is deliberate. Turning it on in CubeMX would be
 * the tidier route on a fresh project, but it requires a regeneration, and
 * regeneration in this workspace has silently discarded USER CODE blocks four
 * times - twice on 05-08-2026 alone, each time producing firmware that built
 * cleanly and then failed on the wire. The two lines at USER CODE 3 in
 * LWIP/App/lwip.c that keep Ethernet transmitting are among what would be at
 * risk. Setting the macro here achieves the same result with no regeneration.
 *
 * WHY THIS COSTS NOTHING TO ENABLE. dhcp.c is ALREADY in the build - the
 * Debug tree carries dhcp.o - it is simply compiled to nothing while
 * LWIP_DHCP is 0, because the whole file sits inside #if LWIP_DHCP. So this
 * is a macro flip, not a change to the project's source list.
 *
 * IT MUST BE VISIBLE TO EVERY lwIP TRANSLATION UNIT, which is why lwipopts.h
 * is the only correct home for it: LWIP_DHCP changes the layout of struct
 * netif (it adds the dhcp pointer). Defining it in one .c file and not the
 * others would give different TUs different ideas of that structure's size -
 * a fault that does not appear at compile time and corrupts memory at run
 * time. Nothing about that failure would point back here.
 *
 * CubeMX does not emit LWIP_DHCP at all when the .ioc has it at 0 - it relies
 * on opt.h defaulting it to 0 - so there is no generated definition above to
 * collide with. The #undef is kept anyway so that if the .ioc is ever set to
 * 1 and regenerated, the generated line is superseded rather than duplicated.
 *
 * WHAT ELSE HAD TO CHANGE, recorded here because none of it is discoverable
 * from this macro alone:
 *   LWIP/App/lwip.c  USER CODE IP_ADDRESSES - the static address is zeroed, so
 *                    the board never briefly answers on 192.168.1.10
 *   LWIP/App/lwip.c  USER CODE 3            - dhcp_start() after netif_set_up()
 *   Core/Src/main.c  StartEthIfTask         - waits for the lease before it
 *                    prints the address or starts anything that needs one
 * ======================================================================= */
#ifdef  LWIP_DHCP
#undef  LWIP_DHCP
#endif
#define LWIP_DHCP                       1

/* ==========================================================================
 * WHERE THE EMBEDDED FILESYSTEM LIVES.  Added 24-08-2026.
 * ==========================================================================
 * fs.c line 39 is
 *     #include HTTPD_FSDATA_FILE
 * and httpd_opts.h defaults that to "fsdata_custom.c" whenever
 * HTTPD_USE_CUSTOM_FSDATA is 1, which it is (line 123 above, from the .ioc).
 *
 * THE BUILD FAILED ON 24-08-2026 because no such file existed. ST's CubeMX
 * database points the generated project at
 *     Middlewares/Third_Party/LwIP/src/apps/http/fsdata_custom.c
 * a path inside the vendor tree that regeneration does not preserve - and it
 * had been lost, leaving only a stale fsdata_custom.o in Debug/ from a build
 * when it still existed. The error surfaces as
 *     .../apps/http/subdir.mk: fs.o Error 1
 * which names fs.c, not the missing file, so it points at the wrong place.
 *
 * THE FIX IS THE LOCATION, NOT THE FILE. The filesystem now lives at
 * LWIP/App/fsdata_custom.h, beside lwip.c. That folder is USER code as far as
 * CubeMX is concerned - it is never rewritten - and ../LWIP/App is already on
 * the include path in .cproject, which is how "lwip.h" resolves.
 *
 * WHY .h AND NOT .c, WHICH LOOKS LIKE THE OBVIOUS NAME.
 * LWIP/App is a COMPILED source folder: lwip.c in it is built as its own
 * translation unit, and a fsdata_custom.c there would be too. fs.c also
 * #includes it. The file defines
 *     const struct fsdata_file file__index_html[]   (and two siblings)
 * with EXTERNAL linkage - no static - so it would be defined twice and the
 * link would fail with "multiple definition of file__index_html". The data
 * arrays are static and would merely be duplicated; the fsdata_file entries
 * are what breaks it. A .h is included and never compiled standalone, so the
 * problem cannot arise. The extension is load-bearing here, not cosmetic.
 *
 * Same arrangement as HTTP_Server_H753_RTOS_ES_MBEDTLS_mDNS_V00, where it has
 * been working since 21-08-2026.
 * ======================================================================= */
#ifdef  HTTPD_FSDATA_FILE
#undef  HTTPD_FSDATA_FILE
#endif
#define HTTPD_FSDATA_FILE               "fsdata_custom.h"

/* =========================================================================
 * mDNS QUERY SUPPORT.  Added 10-09-2026.
 * =========================================================================
 * @brief  Route ".local" hostname lookups to mDNS multicast instead of to the
 *         DNS server that DHCP supplied.  THIS IS THE ENTIRE mDNS MECHANISM.
 *
 * WHY THIS OPTION AND NOT LWIP_MDNS_RESPONDER
 * lwIP 2.2.1 offers two unrelated mDNS facilities and they are easily confused:
 *
 *   LWIP_MDNS_RESPONDER            a full responder plus DNS-SD service
 *                                  browsing, implemented in
 *                                  src/apps/mdns/mdns.c. THAT FILE IS NOT IN
 *                                  THIS PROJECT - the apps folder holds only
 *                                  altcp_tls, http and mqtt. Enabling it would
 *                                  also pull in LWIP_NUM_NETIF_CLIENT_DATA and
 *                                  LWIP_IGMP, and it answers queries, which
 *                                  this board has no reason to do.
 *
 *   LWIP_DNS_SUPPORT_MDNS_QUERIES  this option, implemented entirely inside
 *                                  the dns.c that is already compiled. It
 *                                  compares the tail of each name against
 *                                  ".local" and, on a match, sends the query to
 *                                  the mDNS multicast group instead of to the
 *                                  configured resolver.
 *
 * The board is a RESOLVER ONLY - it asks, it never answers. So the second
 * option is the whole requirement, at the cost of no new source files.
 *
 * THE SUFFIX DECIDES THE TRANSPORT, automatically and per-name. One consequence
 * is worth stating: a ".local" name can never be leaked to the unicast DNS
 * server, and conversely an ordinary name can never be asked over multicast.
 *
 * DERIVED FROM MDNS_RESOLVER_ENABLE rather than being a second switch, so the
 * two cannot drift apart. Leaving this on with the resolver off would compile
 * support that nothing calls; turning the resolver on with this off would send
 * ".local" queries to a unicast server that cannot answer them, and the failure
 * would look exactly like the host being absent.
 * ======================================================================= */
#include "mdns_config.h"

#ifndef LWIP_DNS_SUPPORT_MDNS_QUERIES
#define LWIP_DNS_SUPPORT_MDNS_QUERIES   MDNS_RESOLVER_ENABLE
#endif

/* The resolver is built on lwIP's DNS module. With LWIP_DNS off, dns.c compiles
   to nothing and dns_gethostbyname() does not exist - which surfaces as an
   undefined reference at LINK time, naming the call site rather than the cause.
   LWIP_DNS is 1 in the generated block above today; this guard is what makes a
   future .ioc change that clears it fail loudly and immediately instead. */
#if ((MDNS_RESOLVER_ENABLE != 0) && (LWIP_DNS == 0))
#error "MDNS_RESOLVER_ENABLE is 1 but LWIP_DNS is 0. The mDNS resolver is built \
on lwIP's DNS module, so enable LWIP.LWIP_DNS in the .ioc or set \
MDNS_RESOLVER_ENABLE to 0 in Core/Inc/mdns_config.h."
#endif

/* USER CODE END 1 */

#ifdef __cplusplus
}
#endif
#endif /*__LWIPOPTS__H__ */
