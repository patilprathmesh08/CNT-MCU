/**
  ******************************************************************************
  * @file    http_server.h
  * @brief   lwIP HTTPD bring-up for HTTP_Server_H753_V00
  * @version 1.0 - 05-08-2026
  *
  * Replaces tcp_echoserver.h. See http_server.c for the reasoning behind having
  * a wrapper at all rather than calling httpd_init() straight from main().
  ******************************************************************************
  */

/* Define to prevent recursive inclusion -------------------------------------*/
#ifndef __HTTP_SERVER_H
#define __HTTP_SERVER_H

#ifdef __cplusplus
extern "C" {
#endif

/**
  * @brief  Starts the lwIP HTTP server on HTTPD_SERVER_PORT (80).
  *
  * Call ONCE from main(), and specifically:
  *   - AFTER  MX_LWIP_Init(), because httpd needs the stack initialised
  *   - AFTER  BSP_COM_Init(), because this function printf()s its status and
  *            printf() is not backed by anything until USART3 is up
  *
  * There is no matching stop function. httpd has no teardown API, and nothing
  * in this project needs one.
  *
  * @retval None
  */
void http_server_start(void);

#ifdef __cplusplus
}
#endif

#endif /* __HTTP_SERVER_H */
