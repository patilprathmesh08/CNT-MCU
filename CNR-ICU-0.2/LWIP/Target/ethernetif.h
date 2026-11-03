/* USER CODE BEGIN Header */
/**
 ******************************************************************************
  * File Name          : ethernetif.h
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

#ifndef __ETHERNETIF_H__
#define __ETHERNETIF_H__
#include "lwip/err.h"
#include "lwip/netif.h"
#include "cmsis_os.h"

/* Within 'USER CODE' section, code will be kept by default at each generation */
/* USER CODE BEGIN 0 */

/* USER CODE END 0 */

/* Exported functions ------------------------------------------------------- */
err_t ethernetif_init(struct netif *netif);

void ethernetif_input(void* argument);
void ethernet_link_thread(void* argument );

void Error_Handler(void);
u32_t sys_jiffies(void);
u32_t sys_now(void);

/* USER CODE BEGIN 1 */

/**
  * @brief  Hardened replacements for the generated low_level_output() and the
  *         generated netif->input hook. Both are DEFINED in USER CODE 6 of
  *         ethernetif.c and INSTALLED in USER CODE 3 of LWIP/App/lwip.c, which
  *         repoints gnetif at them immediately after netif_add().
  *
  * Declared here rather than in lwip.c so there is exactly one prototype and
  * the compiler can check the signatures against netif_linkoutput_fn and
  * netif_input_fn. Getting either signature wrong would otherwise be a silent
  * function-pointer mismatch that only shows up as a hard fault on the wire.
  *
  * Added 06-08-2026. Rationale: these two used to be hand-patches inside the
  * generated functions, outside any USER CODE marker, and code generation
  * discarded them twice on 05-08-2026. Everything now sits in USER CODE, so
  * regeneration cannot revert the transmit path.
  */
err_t eth_tx_output(struct netif *netif, struct pbuf *p);
err_t eth_rx_input(struct pbuf *p, struct netif *inp);

/* USER CODE END 1 */
#endif
