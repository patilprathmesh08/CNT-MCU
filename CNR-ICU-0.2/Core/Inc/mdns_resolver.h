/**
* \file    mdns_resolver.h
* \brief   Public interface of the mDNS hostname resolver.
*
* Module name: mdns_resolver.h
*
* Copyright 2026 \@PINETICS as an unpublished work.
* All Rights Reserved.
*
* The information contained herein is confidential property of PINETICS. The
* user is prohibited from copying, transfer or disclosure of such information
* except by express written agreement with PINETICS.
*
* First written on 17-AUG-2026 by
*
* Module Description:
* Resolves a ".local" hostname to an IPv4 address over mDNS, with a bounded
* timeout, a retry limit and re-resolution on demand. The H753 acts as an mDNS
* RESOLVER/CLIENT only - it never answers queries and is not a responder.
*
* HOW THE mDNS TRANSPORT IS SELECTED
* This module does not speak mDNS itself. It calls lwIP's dns_gethostbyname(),
* and lwIP routes the query to the mDNS multicast group because the name ends in
* ".local" - see the LWIP_DNS_SUPPORT_MDNS_QUERIES note in LWIP/Target/lwipopts.h
* USER CODE 1 for the mechanism and its one limitation. The consequence worth
* stating here is that a ".local" name can never be leaked to the unicast DNS
* server that DHCP supplied; the suffix decides the transport.
*
* THREADING - THE PART THAT MATTERS
* lwIP's DNS API is raw-API and may only be touched from tcpip_thread. Every
* call this module makes into lwIP is therefore marshalled with tcpip_callback(),
* the same pattern main.c already uses for httpd_init(). Nothing here ever blocks
* tcpip_thread: the query is fired and the answer arrives asynchronously in a
* callback, and the waiting is done by whichever task polls
* mdns_resolver_poll().
*
* Callers run on an ordinary task (StartEthIfTask). The resolved address is
* copied out under a short critical section, because the writer is the lwIP DNS
* callback running on tcpip_thread.
*
* ENDIANNESS (GL11-C 13.4)
* The Cortex-M7 core is configured LITTLE-ENDIAN. The resolved address is held
* as an lwIP ip4_addr_t, which stores it in NETWORK byte order. Callers must
* therefore use ip4addr_ntoa() or the ip4_addr_get_uN() accessors rather than
* reading the u32 directly, and this module never interprets it byte-wise.
*
* APPROVED EXCEPTIONS (GL11-C 1.1 and 1.5)
* 1. Integer types. GL11-C 13.1 mandates uint8 / int16 / uint32 style typedefs.
*    This project uses the C99 <stdint.h> names instead, because every ST HAL,
*    CMSIS, FreeRTOS and lwIP interface it calls is declared in those terms.
*    Ruled by the project owner on 12-08-2026.
*
* This block opens with two stars, not the four-star banner printed in GL11-C
* 2.4, and carries a \file tag. Doxygen ignores any comment block opening with
* three or more stars, so the 2.4 form as printed generates no documentation at
* all; and without \file it cannot attach a module description to its file.
* Measured on Doxygen 1.17.0. Everything else follows 2.4 unchanged.
****************************************************************/

/* Include section
* lwip/ip_addr.h for ip4_addr_t. stdint.h for the sized types.
***************************************************/
#include <stdint.h>
#include "lwip/ip_addr.h"

/* Defines section
* Include guard only. MDNS_RESOLVER_H carries no leading underscore: ANSI C and
* ISO-IEC 9899 reserve the pattern _[A-Z_][0-9A-Za-z_] for the implementation
* (GL11-C 3.10).
*
* The tuning macros - MDNS_TARGET_HOSTNAME, MDNS_QUERY_TIMEOUT_MS,
* MDNS_MAX_RETRIES and MDNS_RESOLVER_ENABLE - live in Core/Inc/main.h alongside
* NETWORK_USE_DHCP, so that all network configuration is in one place.
***************************************************/
#ifndef MDNS_RESOLVER_H
#define MDNS_RESOLVER_H

#ifdef __cplusplus
extern "C" {
#endif

/* Variables section
* This header defines no variables, as required by GL11-C 7.1.
***************************************************/

/**
* Resolver state, as reported by mdns_resolver_get_state().
*
* The sequence is IDLE -> RESOLVING -> RESOLVED, or IDLE -> RESOLVING -> FAILED
* once the retry budget is spent. A caller may return a FAILED resolver to
* RESOLVING by calling mdns_resolver_start() again - that is how the supervisor
* re-resolves after a link-up.
**************************************************/
typedef enum
{
    MDNS_RESOLVER_IDLE      = 0,    /**< Never started, or stopped.           */
    MDNS_RESOLVER_RESOLVING = 1,    /**< Query outstanding or retry pending.  */
    MDNS_RESOLVER_RESOLVED  = 2,    /**< Address available.                   */
    MDNS_RESOLVER_FAILED    = 3     /**< Retry budget spent without an answer.*/
} mdns_resolver_state_t;

/* Function Prototype Section
***************************************************/

/**
* \copyright 2026 \@PINETICS as an unpublished work.
* Function name: void mdns_resolver_init(void)
*    Return: None. There is nothing that can fail - the function only clears
*            module state and does not touch lwIP.
*    Parameters: void - the function takes no arguments.
* \author
* \date 17-AUG-2026
* \brief Clears resolver state. Call once before mdns_resolver_start(), from
*        any task, before or after the network is up.
**************************************************/
void mdns_resolver_init(void);

/**
* \copyright 2026 \@PINETICS as an unpublished work.
* Function name: int32_t mdns_resolver_start(char const *hostname)
*    \return 0 if the request was accepted, -1 if hostname is NULL or does not
*            end in ".local", -2 if the request could not be handed to
*            tcpip_thread. The name is an imperative command, so it returns an
*            error code rather than a boolean (GL11-C 10.8).
*    \param  hostname - the name to resolve, which MUST end in ".local". Its
*            storage must remain valid for the lifetime of the resolution,
*            so pass a string literal or a static buffer - the module keeps
*            the pointer rather than copying the text.
* \author
* \date 17-AUG-2026
* \brief Begins resolving a hostname, or restarts a failed resolution.
*
*        Returns IMMEDIATELY - it does not wait for the answer. The state
*        machine advances in mdns_resolver_poll(); the answer arrives in an lwIP
*        callback on tcpip_thread.
*
*        The ".local" suffix is checked here and rejected if absent, rather than
*        being left to lwIP. A name without it would be resolved by unicast DNS,
*        which would appear to work on a network whose DNS server happens to
*        know the name, and would be the wrong transport. Failing loudly is
*        better than silently using the wrong protocol.
*
*        Restriction: call from a task, never from an ISR or from tcpip_thread.
**************************************************/
int32_t mdns_resolver_start(char const *hostname);

/**
* \copyright 2026 \@PINETICS as an unpublished work.
* Function name: void mdns_resolver_poll(void)
*    Return: None. State is read with mdns_resolver_get_state().
*    Parameters: void - the function takes no arguments.
* \author
* \date 17-AUG-2026
* \brief Advances the timeout and retry logic. Call periodically from a task.
*
*        This is where the per-attempt timeout expires and the next attempt is
*        issued, up to MDNS_MAX_RETRIES. Calling it more often than
*        NETWORK_POLL_INTERVAL_MS is harmless; not calling it at all leaves a
*        lost query outstanding forever, because lwIP's own retry is bounded and
*        this module's outer retry is what recovers from a target that was not
*        yet up.
*
*        Restriction: call from a task, never from an ISR.
**************************************************/
void mdns_resolver_poll(void);

/**
* \copyright 2026 \@PINETICS as an unpublished work.
* Function name: mdns_resolver_state_t mdns_resolver_get_state(void)
*    \return The current state. This function is a query, so it returns the
*            value itself rather than an error code (GL11-C 10.8).
*    Parameters: void - the function takes no arguments.
* \author
* \date 17-AUG-2026
* \brief Reports whether an address is available yet.
**************************************************/
mdns_resolver_state_t mdns_resolver_get_state(void);

/**
* \copyright 2026 \@PINETICS as an unpublished work.
* Function name: int32_t mdns_resolver_get_target(ip4_addr_t *out_addr)
*    \return 0 and a valid address if the state is RESOLVED; -1 if out_addr is
*            NULL; -2 if no address has been resolved yet, in which case
*            out_addr is left untouched.
*    \param  out_addr - receives the resolved IPv4 address, in lwIP's network
*            byte order. Use ip4addr_ntoa() to print it.
* \author
* \date 17-AUG-2026
* \brief Copies out the resolved target address.
*
*        Takes a short critical section, because the writer is lwIP's DNS
*        callback on tcpip_thread and an ip4_addr_t is wider than a single
*        atomic access on this core. Safe to call from task context only.
**************************************************/
int32_t mdns_resolver_get_target(ip4_addr_t *out_addr);

/**
* \copyright 2026 \@PINETICS as an unpublished work.
* Function name: uint32_t mdns_resolver_get_attempts(void)
*    \return How many query attempts have been made since the last
*            mdns_resolver_start(). A query, so it returns the value.
*    Parameters: void - the function takes no arguments.
* \author
* \date 17-AUG-2026
* \brief Reports the attempt count, for logging and for the diagnostic
*        endpoint. Distinguishes "resolved first time" from "resolved after
*        four retries", which matters when the target is slow to appear.
**************************************************/
uint32_t mdns_resolver_get_attempts(void);

#ifdef __cplusplus
}
#endif

#endif /* MDNS_RESOLVER_H */
