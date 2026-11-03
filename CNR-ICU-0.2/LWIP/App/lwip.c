/* USER CODE BEGIN Header */
/**
 ******************************************************************************
  * File Name          : LWIP.c
  * Description        : This file provides initialization code for LWIP
  *                      middleWare.
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
#include "lwip.h"
#include "lwip/init.h"
#include "lwip/netif.h"
#if (defined ( __CC_ARM ) || defined (__ARMCC_VERSION))  /* MDK ARM Compiler */
#include "lwip/sio.h"
#endif /* MDK ARM Compiler */
#include "ethernetif.h"
#include <string.h>

/* USER CODE BEGIN 0 */
/* dhcp_start() at USER CODE 3. CubeMX only emits this include when the .ioc
   has LWIP_DHCP=1, and the .ioc here deliberately still says 0 - see the DHCP
   note in LWIP/Target/lwipopts.h. Without it dhcp_start() would be an implicit
   declaration returning int, which this toolchain warns about but still links,
   so the mistake would reach the board rather than the build log. */
#include "lwip/dhcp.h"

/* printf() for the dhcp_start() failure report below. */
#include <stdio.h>

/* USE_DHCP and the NET_STATIC_* octets, both used in USER CODE IP_ADDRESSES
   and USER CODE 3. CubeMX does not include main.h here, so this is needed. */
#include "main.h"

/* A MISSING USE_DHCP MUST NOT COMPILE. In #if, an undefined identifier is
   quietly treated as 0, so without this guard a lost include would silently
   select the STATIC branch on a build that asked for DHCP - and the only
   symptom would be a board sitting on 192.168.40.50 wondering why no lease
   arrived. The #error turns a silent behaviour change into a build failure
   that names the cause.

   This is not hypothetical: ENABLE_MUTUAL_TLS was used in stream_client.c and
   defined nowhere at all until 24-08-2026, and compiled clean as 0 for exactly
   this reason. */
#ifndef USE_DHCP
#error "USE_DHCP is not defined - Core/Inc/main.h is not being included here."
#endif
/* USER CODE END 0 */
/* Private function prototypes -----------------------------------------------*/
static void ethernet_link_status_updated(struct netif *netif);
/* ETH Variables initialization ----------------------------------------------*/
void Error_Handler(void);

/* USER CODE BEGIN 1 */

/* USER CODE END 1 */

/* Variables Initialization */
struct netif gnetif;
ip4_addr_t ipaddr;
ip4_addr_t netmask;
ip4_addr_t gw;
uint8_t IP_ADDRESS[4];
uint8_t NETMASK_ADDRESS[4];
uint8_t GATEWAY_ADDRESS[4];
/* USER CODE BEGIN OS_THREAD_ATTR_CMSIS_RTOS_V2 */

/* ==========================================================================
 * EthLink STACK: 1024 -> 4096 BYTES.  Fixed 12-08-2026.
 * ==========================================================================
 * THE BOARD REPORTED THIS ITSELF:
 *     *** STACK OVERFLOW in task 'EthLink' ***
 *     *** raise its stack_size. free heap 32576 B, halting. ***
 * from vApplicationStackOverflowHook() in Core/Src/freertos.c. That hook was
 * EMPTY until 07-08-2026, so this overflow was being detected and silently
 * discarded for an unknown length of time before it could ever be seen.
 *
 * WHY 1024 WAS WRONG. This macro is defined TWICE in the project, with different
 * values, in two files that both create a thread with it:
 *     LWIP/App/lwip.c:52       1024   -> used for "EthLink" (line ~106 below)
 *     LWIP/Target/ethernetif.c 4096   -> used for the input thread
 * Same name, same purpose, 4x apart. Nothing warns about this because they are
 * separate translation units. EthLink drew the short one.
 *
 * WHY EthLink NEEDS MORE THAN 1024 BYTES. ethernet_link_thread() declares
 *     ETH_MACConfigTypeDef MACConf = {0};
 * at function scope - a struct spanning 113 lines of fields in
 * stm32h7xx_hal_eth.h, so roughly 140 bytes, zero-initialised on every entry.
 * On top of that sit LAN8742_GetLinkState() -> LAN8742_ReadReg() ->
 * HAL_ETH_ReadPHYRegister(), and on a link CHANGE also HAL_ETH_GetMACConfig()
 * and HAL_ETH_SetMACConfig(), which is the deepest path in the task.
 *
 * NOTE THE TRIGGER: that deep path only runs when the link state changes - which
 * is exactly what replugging the Ethernet cable does. The board was replugged on
 * 12-08-2026 after it stopped answering, and this hook fired the same day.
 *
 * CONSEQUENCE OF LEAVING IT. The hook calls taskDISABLE_INTERRUPTS() and spins
 * forever, so the board stops dead the moment it is detected - no ping, no ARP,
 * nothing, until a reset. Worse, detection is by end-of-stack pattern check at a
 * context switch, so memory past the stack has ALREADY been written by the time
 * anything notices. Task stacks and TCBs all live in ucHeap, so the corruption
 * lands on whatever FreeRTOS allocated next.
 *
 * ANY LATENCY MEASUREMENT TAKEN WHILE THIS IS ACTIVE IS UNTRUSTWORTHY, which is
 * why this is fixed before the 14-17 ms RTT maximum is investigated further.
 *
 * 4096 matches ethernetif.c's value, so the two definitions now agree, and costs
 * 3 KB of a reported 32,576 B free heap. This block is USER CODE, so the change
 * survives CubeMX regeneration - unlike editing the generated attributes below.
 * ======================================================================== */
#define INTERFACE_THREAD_STACK_SIZE ( 4096 )
osThreadAttr_t attributes;
/* USER CODE END OS_THREAD_ATTR_CMSIS_RTOS_V2 */

/* USER CODE BEGIN 2 */

/* USER CODE END 2 */

/**
  * LwIP initialization function
  */
void MX_LWIP_Init(void)
{
  /* IP addresses initialization */
  IP_ADDRESS[0] = 192;
  IP_ADDRESS[1] = 168;
  IP_ADDRESS[2] = 1;
  IP_ADDRESS[3] = 10;
  NETMASK_ADDRESS[0] = 255;
  NETMASK_ADDRESS[1] = 255;
  NETMASK_ADDRESS[2] = 255;
  NETMASK_ADDRESS[3] = 0;
  GATEWAY_ADDRESS[0] = 192;
  GATEWAY_ADDRESS[1] = 168;
  GATEWAY_ADDRESS[2] = 1;
  GATEWAY_ADDRESS[3] = 1;

/* USER CODE BEGIN IP_ADDRESSES */
  /* ------------------------------------------------------------------------
   * ZERO THE STATIC ADDRESS - the board is a DHCP client from 24-08-2026.
   * ------------------------------------------------------------------------
   * The generated lines just above still assign 192.168.1.10 because the .ioc
   * is still set to a static address (see the DHCP note in
   * LWIP/Target/lwipopts.h for why it was not changed in CubeMX). Left as they
   * are, netif_add() below would bring the interface up on 192.168.1.10 and it
   * would answer ARP on that address for the few hundred milliseconds before
   * the lease arrives.
   *
   * That is not cosmetic. If any board on the bench still holds the old static
   * 192.168.1.10, both would answer for that window and the resulting address
   * conflict is intermittent and very hard to read from either end.
   *
   * dhcp_start() would overwrite the address anyway; zeroing it here means
   * there is never a moment where the wrong one is live.
   * ---------------------------------------------------------------------
   * MADE CONDITIONAL 24-08-2026. The zeroing is correct ONLY when DHCP is
   * going to supply an address. With USE_DHCP 0 the #else branch installs the
   * NET_STATIC_* values from main.h instead, which moves control of the static
   * address out of the .ioc and into the same header as the switch.
   * --------------------------------------------------------------------- */
#if USE_DHCP
  IP_ADDRESS[0] = 0;  IP_ADDRESS[1] = 0;  IP_ADDRESS[2] = 0;  IP_ADDRESS[3] = 0;
  NETMASK_ADDRESS[0] = 0;  NETMASK_ADDRESS[1] = 0;
  NETMASK_ADDRESS[2] = 0;  NETMASK_ADDRESS[3] = 0;
  GATEWAY_ADDRESS[0] = 0;  GATEWAY_ADDRESS[1] = 0;
  GATEWAY_ADDRESS[2] = 0;  GATEWAY_ADDRESS[3] = 0;
#else
  /* Static addressing. These overwrite the generated values a few lines above,
     which come from the .ioc and are 192.168.1.10 - the wrong subnet for the
     stream server. Setting them here rather than in CubeMX keeps the address
     and the switch that selects it in one file. */
  IP_ADDRESS[0] = NET_STATIC_IP_0;  IP_ADDRESS[1] = NET_STATIC_IP_1;
  IP_ADDRESS[2] = NET_STATIC_IP_2;  IP_ADDRESS[3] = NET_STATIC_IP_3;
  NETMASK_ADDRESS[0] = NET_STATIC_MASK_0;  NETMASK_ADDRESS[1] = NET_STATIC_MASK_1;
  NETMASK_ADDRESS[2] = NET_STATIC_MASK_2;  NETMASK_ADDRESS[3] = NET_STATIC_MASK_3;
  GATEWAY_ADDRESS[0] = NET_STATIC_GW_0;  GATEWAY_ADDRESS[1] = NET_STATIC_GW_1;
  GATEWAY_ADDRESS[2] = NET_STATIC_GW_2;  GATEWAY_ADDRESS[3] = NET_STATIC_GW_3;
#endif
/* USER CODE END IP_ADDRESSES */

  /* Initialize the LwIP stack with RTOS */
  tcpip_init( NULL, NULL );

  /* IP addresses initialization without DHCP (IPv4) */
  IP4_ADDR(&ipaddr, IP_ADDRESS[0], IP_ADDRESS[1], IP_ADDRESS[2], IP_ADDRESS[3]);
  IP4_ADDR(&netmask, NETMASK_ADDRESS[0], NETMASK_ADDRESS[1] , NETMASK_ADDRESS[2], NETMASK_ADDRESS[3]);
  IP4_ADDR(&gw, GATEWAY_ADDRESS[0], GATEWAY_ADDRESS[1], GATEWAY_ADDRESS[2], GATEWAY_ADDRESS[3]);

  /* add the network interface (IPv4/IPv6) with RTOS */
  netif_add(&gnetif, &ipaddr, &netmask, &gw, NULL, &ethernetif_init, &tcpip_input);

  /* Registers the default network interface */
  netif_set_default(&gnetif);

  /* We must always bring the network interface up connection or not... */
  netif_set_up(&gnetif);

  /* Set the link callback function, this function is called on change of link status*/
  netif_set_link_callback(&gnetif, ethernet_link_status_updated);

  /* Create the Ethernet link handler thread */
/* USER CODE BEGIN H7_OS_THREAD_NEW_CMSIS_RTOS_V2 */
  memset(&attributes, 0x0, sizeof(osThreadAttr_t));
  attributes.name = "EthLink";
  attributes.stack_size = INTERFACE_THREAD_STACK_SIZE;
  attributes.priority = osPriorityBelowNormal;
  osThreadNew(ethernet_link_thread, &gnetif, &attributes);
/* USER CODE END H7_OS_THREAD_NEW_CMSIS_RTOS_V2 */

/* USER CODE BEGIN 3 */

  /* ========================================================================
   * INSTALL THE HARDENED ETHERNET PATH.  Added 06-08-2026.
   * ========================================================================
   * netif_add() above has already run ethernetif_init(), which set
   *   netif->linkoutput = low_level_output     (ethernetif.c, generated)
   * and netif_add()'s own last argument set
   *   netif->input      = ethernet_input       (lwIP, unmodified)
   *
   * Both are replaced here. The two replacements are defined in USER CODE 6 of
   * ethernetif.c and carry four fixes the generated code does not have:
   *   1. over-long pbuf chains are linearised with pbuf_clone() instead of
   *      being silently discarded with "return ERR_IF"
   *   2. Tx payloads are cleaned out of the D-cache before the DMA reads them,
   *      required because the lwIP heap now lives in cacheable RAM_D1
   *   3. HAL_ETH_Transmit()'s return value is actually checked, so lwIP is told
   *      the truth and can retry
   *   4. HAL_ETH_ReleaseTxPacket() reclaims the descriptor, without which the
   *      4-entry ring jams permanently after four frames
   * plus receive-side counters via eth_rx_input().
   *
   * WHY HERE. Those fixes previously lived as edits inside the generated
   * functions, where no USER CODE marker protects them - and code generation
   * threw them away twice on 05-08-2026, each time producing firmware that
   * built cleanly and then failed on the wire with no error reported anywhere.
   * This block is inside a USER CODE marker, so it survives.
   *
   * ORDER MATTERS: these two lines must come AFTER netif_add(). Moving them
   * above it would assign to a netif that ethernetif_init() then overwrites.
   *
   * IF ETHERNET EVER BREAKS AFTER A REGENERATION, CHECK THESE TWO LINES FIRST.
   * They are now the only thing standing between the project and the generated
   * transmit path, which is known to fail after four frames.
   * ==================================================================== */
  gnetif.linkoutput = eth_tx_output;
  gnetif.input      = eth_rx_input;

  /* ========================================================================
   * START DHCP.  Added 24-08-2026.
   * ========================================================================
   * Must come AFTER netif_add() and netif_set_up(), both above: dhcp_start()
   * needs an interface that exists and is administratively up, and returns
   * ERR_ARG rather than doing anything if it is handed one that is not.
   *
   * The return value is checked. dhcp_start() fails when the DHCP state
   * structure cannot be allocated from the lwIP heap, and on this project that
   * heap is the same MEM_SIZE pool mbedTLS allocates its TLS sessions from -
   * so it is not a theoretical failure. Silently ignoring it would leave the
   * board with the 0.0.0.0 assigned in USER CODE IP_ADDRESSES above and no
   * indication anywhere of why the network never came up.
   *
   * NO WAIT LOOP HERE. This runs on the caller's thread inside MX_LWIP_Init(),
   * before the link is necessarily up, and blocking here would stall start-up
   * for as long as the cable is unplugged. StartEthIfTask() in main.c does the
   * waiting, where there is somewhere sensible to report a timeout.
   *
   * RENEWAL AND REBINDING need no code: lwIP's dhcp_fine_tmr/dhcp_coarse_tmr
   * are driven by tcpip_thread, which tcpip_init() started above. A cable
   * replug is handled by ethernet_link_status_updated(), which lwIP calls
   * through the netif link callback registered a few lines up.
   * =====================================================================
   *
   * MADE CONDITIONAL 24-08-2026 on USE_DHCP in Core/Inc/main.h. With that at 0
   * no DHCP client is created at all - not started and then stopped, simply
   * never started - and the static address installed in USER CODE IP_ADDRESSES
   * above is what the interface keeps. No DHCP packet is sent in that case.
   * ===================================================================== */
#if USE_DHCP
  {
    err_t dhcp_err = dhcp_start(&gnetif);

    if (dhcp_err != ERR_OK)
    {
      printf("net: *** dhcp_start() FAILED (err %d) - no address will be "
             "acquired ***\r\n", (int)dhcp_err);
      printf("net:     usually the lwIP heap (MEM_SIZE) is exhausted.\r\n");
    }
    else
    {
      /* Discovery is under way; StartEthIfTask() reports the result. */
    }
  }
#endif

/* USER CODE END 3 */
}

#ifdef USE_OBSOLETE_USER_CODE_SECTION_4
/* Kept to help code migration. (See new 4_1, 4_2... sections) */
/* Avoid to use this user section which will become obsolete. */
/* USER CODE BEGIN 4 */
/* USER CODE END 4 */
#endif

/**
  * @brief  Notify the User about the network interface config status
  * @param  netif: the network interface
  * @retval None
  */
static void ethernet_link_status_updated(struct netif *netif)
{
  if (netif_is_up(netif))
  {
/* USER CODE BEGIN 5 */
/* USER CODE END 5 */
  }
  else /* netif is down */
  {
/* USER CODE BEGIN 6 */
/* USER CODE END 6 */
  }
}

#if (defined ( __CC_ARM ) || defined (__ARMCC_VERSION))  /* MDK ARM Compiler */
/**
 * Opens a serial device for communication.
 *
 * @param devnum device number
 * @return handle to serial device if successful, NULL otherwise
 */
sio_fd_t sio_open(u8_t devnum)
{
  sio_fd_t sd;

/* USER CODE BEGIN 7 */
  sd = 0; // dummy code
/* USER CODE END 7 */

  return sd;
}

/**
 * Sends a single character to the serial device.
 *
 * @param c character to send
 * @param fd serial device handle
 *
 * @note This function will block until the character can be sent.
 */
void sio_send(u8_t c, sio_fd_t fd)
{
/* USER CODE BEGIN 8 */
/* USER CODE END 8 */
}

/**
 * Reads from the serial device.
 *
 * @param fd serial device handle
 * @param data pointer to data buffer for receiving
 * @param len maximum length (in bytes) of data to receive
 * @return number of bytes actually received - may be 0 if aborted by sio_read_abort
 *
 * @note This function will block until data can be received. The blocking
 * can be cancelled by calling sio_read_abort().
 */
u32_t sio_read(sio_fd_t fd, u8_t *data, u32_t len)
{
  u32_t recved_bytes;

/* USER CODE BEGIN 9 */
  recved_bytes = 0; // dummy code
/* USER CODE END 9 */
  return recved_bytes;
}

/**
 * Tries to read from the serial device. Same as sio_read but returns
 * immediately if no data is available and never blocks.
 *
 * @param fd serial device handle
 * @param data pointer to data buffer for receiving
 * @param len maximum length (in bytes) of data to receive
 * @return number of bytes actually received
 */
u32_t sio_tryread(sio_fd_t fd, u8_t *data, u32_t len)
{
  u32_t recved_bytes;

/* USER CODE BEGIN 10 */
  recved_bytes = 0; // dummy code
/* USER CODE END 10 */
  return recved_bytes;
}
#endif /* MDK ARM Compiler */

