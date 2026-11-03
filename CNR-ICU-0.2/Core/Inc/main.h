/* USER CODE BEGIN Header */
/**
  ******************************************************************************
  * @file           : main.h
  * @brief          : Header for main.c file.
  *                   This file contains the common defines of the application.
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

/* Define to prevent recursive inclusion -------------------------------------*/
#ifndef __MAIN_H
#define __MAIN_H

#ifdef __cplusplus
extern "C" {
#endif

/* Includes ------------------------------------------------------------------*/
#include "stm32h7xx_hal.h"

#include "stm32h7xx_nucleo.h"
#include <stdio.h>

/* Private includes ----------------------------------------------------------*/
/* USER CODE BEGIN Includes */

/* mDNS resolver tuning constants. Added 10-09-2026.
*
* mdns_resolver.c includes main.h and reads MDNS_QUERY_TIMEOUT_MS and
* MDNS_MAX_RETRIES from it, so the settings have to be reachable from here.
* They live in their own header rather than being written out below, because
* lwipopts.h also needs MDNS_RESOLVER_ENABLE and cannot include main.h - see
* the Module Description in mdns_config.h.
***************************************************/
#include "mdns_config.h"

/* USER CODE END Includes */

/* Exported types ------------------------------------------------------------*/
/* USER CODE BEGIN ET */

/* USER CODE END ET */

/* Exported constants --------------------------------------------------------*/
/* USER CODE BEGIN EC */

/* USER CODE END EC */

/* Exported macro ------------------------------------------------------------*/
/* USER CODE BEGIN EM */

/* USER CODE END EM */

/* Exported functions prototypes ---------------------------------------------*/
void Error_Handler(void);

/* USER CODE BEGIN EFP */

/* USER CODE END EFP */

/* Private defines -----------------------------------------------------------*/
#define MBEDTLS_SSL_OUT_CONTENT_LEN 4096
#define MBEDTLS_PLATFORM_STD_CALLOC mbedtls_platform_calloc
#define MBEDTLS_SSL_IN_CONTENT_LEN 2048
#define MBEDTLS_PLATFORM_STD_FREE mbedtls_platform_free
#define SCOPE_TRIG_Pin GPIO_PIN_9
#define SCOPE_TRIG_GPIO_Port GPIOE

/* USER CODE BEGIN Private defines */

/* ==========================================================================
 * FEATURE SWITCHES.  Made modular 24-08-2026.
 * ==========================================================================
 * Before this date neither addressing nor mutual TLS could be changed without
 * editing code in three files, and one of the two was silently broken. Both
 * are now single #defines, and this block is the only place either is set.
 * ======================================================================= */

/**
  * @brief  1 = take the address from a DHCP server. 0 = use the static address
  *         configured below. Changing this line alone is sufficient.
  *
  * HOW EACH CASE WORKS, because it is not symmetrical.
  * MX_LWIP_Init() in LWIP/App/lwip.c is CubeMX's STATIC variant - the .ioc says
  * LWIP.LWIP_DHCP=0 - so the generated code already assigns a fixed address.
  *   USE_DHCP 0  lets that generated path stand, then overwrites the address
  *               with NET_STATIC_* below so it is controlled from here rather
  *               than from the .ioc. No dhcp_start() is called at all.
  *   USE_DHCP 1  zeroes the generated address in USER CODE IP_ADDRESSES, so
  *               the board never briefly answers on the stale static one, then
  *               calls dhcp_start() from USER CODE 3.
  * Both live inside USER CODE markers and survive a CubeMX regeneration.
  *
  * LWIP_DHCP in LWIP/Target/lwipopts.h STAYS AT 1 either way. It is what
  * compiles dhcp.c into the build; gating it on this switch would save a
  * couple of KB of flash and cost a link error the day someone sets USE_DHCP
  * back to 1 without rebuilding cleanly. Not worth it - and lwipopts.h cannot
  * see this header anyway, since every lwIP translation unit includes it.
  */
#define USE_DHCP 1

/**
  * @brief  The static address used when USE_DHCP is 0. Ignored when it is 1.
  *
  * Four octets each, so no byte-order question arises - IP4_ADDR() takes them
  * in written order and assembles the word itself.
  *
  * NOTE THE SUBNET. STREAM_SERVER_HOST in stream_client.h is on 192.168.40.x,
  * so a static address on the .ioc's original 192.168.1.x would need a router
  * between the board and the stream server. These default to the same /24 as
  * that server, which is what a direct bench connection needs.
  *     .ioc value, left unused here: 192.168.1.10 / 255.255.255.0 / 192.168.1.1
  */
#define NET_STATIC_IP_0     192
#define NET_STATIC_IP_1     168
#define NET_STATIC_IP_2       0
#define NET_STATIC_IP_3      50

#define NET_STATIC_MASK_0   255
#define NET_STATIC_MASK_1   255
#define NET_STATIC_MASK_2   255
#define NET_STATIC_MASK_3     0

#define NET_STATIC_GW_0     192
#define NET_STATIC_GW_1     168
#define NET_STATIC_GW_2       0
#define NET_STATIC_GW_3       1

/**
  * @brief  SERVER side. 1 = the board's own HTTPS server demands a client
  *         certificate signed by our CA. 0 = it accepts anonymous clients.
  *
  * This governs http_server.c only - what PCs must present when they connect
  * TO the board. It does NOT govern what the board presents when it connects
  * OUT; that is STREAM_CLIENT_MUTUAL_TLS below.
  *
  * WHY TWO SWITCHES AND NOT ONE. They are independent policies, and one shared
  * switch could not express the working configuration. Before 24-08-2026 the
  * server side was hard-wired to REQUIRED while the client side was off, and
  * setting a single switch to 1 would have broken the outbound stream (see the
  * note on STREAM_CLIENT_MUTUAL_TLS). Defaulting to 1 preserves exactly the
  * behaviour this project already had.
  *
  * At 0 the board still presents its OWN certificate and clients still verify
  * it - only the client's identity stops being demanded. ALTCP_MBEDTLS_AUTHMODE
  * in lwipopts.h is left alone; http_server.c sets the authmode explicitly from
  * this switch, so there is one source of truth rather than two that can
  * disagree.
  */
#define ENABLE_MUTUAL_TLS      0//1

/**
  * @brief  CLIENT side. 1 = the board presents its own certificate to the
  *         stream server it connects out to. 0 = it connects anonymously.
  *
  * MUST STAY 0 UNTIL A CLIENT IDENTITY IS COMPILED IN. At 1, stream_client.c
  * deliberately fails the connection with "no client identity is compiled in"
  * and returns -1, because tls_credentials.h carries only the CA, the SERVER
  * certificate and the SERVER key. The server certificate cannot be reused
  * here: its extendedKeyUsage is serverAuth only, so a server that checks EKU
  * will refuse it.
  *
  * To enable: embed certs/client.crt and certs/client.key as DER arrays in
  * tls_credentials.h, load them at the marked place in stream_client.c, then
  * set this to 1.
  *
  * The board ALWAYS verifies the server's certificate against the CA
  * regardless of this switch - authmode is MBEDTLS_SSL_VERIFY_REQUIRED in
  * stream_tls_setup(). This switch only controls our own identity.
  */
#define STREAM_CLIENT_MUTUAL_TLS 0

/**
  * @brief  How long StartEthIfTask() waits for a DHCP lease, and how often it
  *         looks, both in milliseconds. Added 24-08-2026 with DHCP.
  *
  * 15 s because a lease is normally granted in well under one second on a
  * quiet segment, but a server that is busy, or one reached through a DHCP
  * relay, can take several. Long enough not to give up on a working network;
  * short enough that a bench with no DHCP server at all still reaches the rest
  * of the start-up banner while somebody is watching.
  *
  * The poll interval is a compromise in one direction only. It costs nothing
  * but scheduler wake-ups, and a shorter one would report the lease sooner,
  * but each wake-up preempts tcpip_thread - the thread that actually drives
  * the DHCP exchange. 100 ms adds at most 100 ms of apparent delay to a figure
  * that is itself printed, so an inflated number cannot mislead silently.
  *
  * Waiting is NOT the same as requiring. Start-up continues after a timeout;
  * see the reasoning in StartEthIfTask().
  */
#define NET_DHCP_WAIT_MAX_MS   15000U
#define NET_DHCP_POLL_MS         100U

/**
  * @brief  Per-frame Ethernet diagnostic printf()s. 0 = off (normal running),
  *         1 = on (fault finding only).
  *
  * Keep this at 0 unless you are debugging. printf() goes to USART3 via
  * BSP_COM_Init() and is BLOCKING, and with NO_SYS=1 there is no task to
  * preempt it. One status block is roughly 190 characters, which at 115200 8N1
  * is 1900 bits / 115200 = ~16.5 ms of solid UART transmission. For all of that
  * time the superloop cannot reach ethernetif_input(), so an arriving frame
  * just waits in the DMA buffer.
  *
  * That is measured, not theoretical: with these prints enabled the TCP echo
  * RTT was 9-17 ms while an ICMP ping to the same board answered in <1 ms -
  * ping escapes the penalty because lwIP emits the reply inside
  * MX_LWIP_Process(), before the print block runs.
  *
  * Turning this on is still the right move if Ethernet ever misbehaves again:
  * it restores the frame/ARP decode and the lwIP statistics dump that located
  * the lwIP-heap fault. Just do not measure latency with it enabled.
  */
#define ETH_DIAG_VERBOSE 0

/* USER CODE END Private defines */

#ifdef __cplusplus
}
#endif

#endif /* __MAIN_H */
