/**
* \file    mdns_service.h
* \brief   FreeRTOS integration layer for the mDNS hostname resolver.
*
* Module name: mdns_service.h
*
* Copyright 2026 \@PINETICS as an unpublished work.
* All Rights Reserved.
*
* The information contained herein is confidential property of PINETICS. The
* user is prohibited from copying, transfer or disclosure of such information
* except by express written agreement with PINETICS.
*
* First written on 10-SEP-2026 by
*
* Module Description:
* Owns a FreeRTOS task that drives the resolver in mdns_resolver.c and publishes
* the address it finds. Nothing else in the project has to know that resolution
* is asynchronous, retried, or repeated after a link change.
*
* WHY THIS IS A SEPARATE MODULE FROM mdns_resolver
* mdns_resolver.c is generic: it resolves a name and reports a state, and knows
* nothing about this project. Everything project-specific is here - which task
* drives it, when resolution may begin, what happens on failure, and who is told
* about the answer. Keeping the two apart is what lets the resolver move to
* another project unchanged, and lets this file be rewritten for a project with
* a different startup sequence without touching the resolver.
*
* WHY A DEDICATED TASK AND NOT A CALL IN StartEthIfTask
* mdns_resolver_poll() must be called repeatedly while a query is outstanding,
* and a resolution can take MDNS_QUERY_TIMEOUT_MS x MDNS_MAX_RETRIES - 25
* seconds with the shipped settings. Polling inline in StartEthIfTask would hold
* up stream_client_init() and ntp_client_init() for that whole period, so a
* server that happened to be absent would delay the WSS connection that does not
* depend on mDNS at all. A task of its own resolves in the background and
* delays nothing.
*
* It is created at osPriorityLow, below the stream client and the UART workers,
* because nothing waits on the result in the present design - see
* mdns_service_get_address().
*
* ENDIANNESS (GL11-C 13.4)
* The Cortex-M7 core is configured LITTLE-ENDIAN. The published address is an
* lwIP ip4_addr_t, which holds it in NETWORK byte order. Callers must use
* ip4addr_ntoa() or the ip4_addr_get_uN() accessors rather than reading the u32
* field, and this module never interprets it byte-wise.
*
* APPROVED EXCEPTIONS (GL11-C 1.3)
* 1. Integer types. GL11-C 13.1 mandates uint8 / int16 / uint32 style typedefs.
*    This project uses the C99 <stdint.h> names instead, because every ST HAL,
*    CMSIS, FreeRTOS and lwIP interface it calls is declared in those terms.
*    Ruled by the project owner on 12-08-2026.
*
* This block opens with two stars, not the four-star banner printed in GL11-C
* 2.4, and carries a \file tag, for the reason recorded in mdns_resolver.h:
* Doxygen ignores a comment block opening with three or more stars, so the 2.4
* form as printed generates no documentation at all.
****************************************************************/

/* Include section
* mdns_config.h for MDNS_RESOLVER_ENABLE. lwip/ip_addr.h for ip4_addr_t.
* stdint.h for the sized types.
***************************************************/
#include <stdint.h>
#include "lwip/ip_addr.h"
#include "mdns_config.h"

/* Defines section
* Include guard only. MDNS_SERVICE_H carries no leading underscore: ANSI C and
* ISO-IEC 9899 reserve the pattern _[A-Z_][0-9A-Za-z_] for the implementation
* (GL11-C 3.10). All tuning constants are in mdns_config.h.
***************************************************/
#ifndef MDNS_SERVICE_H
#define MDNS_SERVICE_H

#ifdef __cplusplus
extern "C" {
#endif

/* Variables section
* This header defines no variables, as required by GL11-C 7.1.
***************************************************/

/* Function Prototype Section
***************************************************/

/**
* \copyright 2026 \@PINETICS as an unpublished work.
* Function name: void mdns_service_init(void)
*    Return: None. A failure to create the task is reported on the console; it
*            is not returned, because no caller could do anything about it and
*            the rest of the application runs unaffected without mDNS.
*    Parameters: void - the function takes no arguments.
* \author
* \date 10-SEP-2026
* \brief Creates the mDNS task. Call once, after the interface has an address.
*
*        Call it AFTER the DHCP wait. A query sent from 0.0.0.0 cannot be
*        answered - the responder has nowhere to send the unicast reply - so
*        starting earlier spends the retry budget on attempts that could never
*        have succeeded. The task tolerates being started early and waits, but
*        the console then carries failures that need explaining.
*
*        Does nothing at all when MDNS_RESOLVER_ENABLE is 0.
**************************************************/
void mdns_service_init(void);

/**
* \copyright 2026 \@PINETICS as an unpublished work.
* Function name: int32_t mdns_service_get_address(ip4_addr_t *out_addr)
*    Return: 0 when an address has been resolved and copied to out_addr.
*            -1 when no address is available, in which case out_addr is left
*            untouched. A caller that ignores the return would otherwise read
*            0.0.0.0 and treat it as a host.
*    Parameters: out_addr - receives the resolved address in NETWORK byte order.
*                Must not be NULL; a NULL pointer returns -1 and writes nothing.
* \author
* \date 10-SEP-2026
* \brief Copies out the most recently resolved address.
*
*        Safe to call from any task. The value is copied under a short critical
*        section because the writer is the mDNS task and the reader may be any
*        other.
**************************************************/
int32_t mdns_service_get_address(ip4_addr_t *out_addr);

/**
* \copyright 2026 \@PINETICS as an unpublished work.
* Function name: int32_t mdns_service_get_address_gen(ip4_addr_t *out_addr,
*                                                     uint32_t *out_gen)
*    Return: 0 when an address has been resolved and both outputs are written.
*            -1 when no address is available, in which case neither output is
*            touched.
*    Parameters: out_addr - receives the address in NETWORK byte order.
*                out_gen  - receives the generation counter for that address.
*                Neither may be NULL; a NULL pointer returns -1.
* \author
* \date 10-SEP-2026
* \brief Copies out the resolved address together with its generation.
*
*        THE GENERATION IS WHAT MAKES RE-RESOLUTION SAFE. It increments on every
*        successful publication, including one that produces the same address as
*        before. A caller that has requested a refresh compares the generation
*        against the one it adopted: unchanged means the answer is the OLD one
*        and the query it asked for has not been answered yet.
*
*        Without it, mdns_service_request_refresh() followed by
*        mdns_service_get_address() returns the previous address immediately and
*        looks exactly like a successful re-resolution - a rediscovery satisfied
*        by a stale result with no query on the wire. That precise fault cost
*        real time on hardware in mDNS_V00 on 21-08-2026 and is recorded at the
*        foot of stream_client.c.
*
*        Both values are read under one critical section, so the address and the
*        generation always belong to each other. Reading them with two separate
*        calls would reintroduce the race this exists to close.
**************************************************/
int32_t mdns_service_get_address_gen(ip4_addr_t *out_addr, uint32_t *out_gen);

/**
* \copyright 2026 \@PINETICS as an unpublished work.
* Function name: uint8_t mdns_service_is_resolved(void)
*    Return: 1 when an address has been resolved at least once, 0 otherwise.
*    Parameters: void - the function takes no arguments.
* \author
* \date 10-SEP-2026
* \brief Reports whether a resolved address is available.
*
*        Provided so a caller can test availability without supplying a buffer.
*        A caller that wants the address should call mdns_service_get_address()
*        and test its return instead - testing this first would be a race, as
*        the address can be published between the two calls.
**************************************************/
uint8_t mdns_service_is_resolved(void);

/**
* \copyright 2026 \@PINETICS as an unpublished work.
* Function name: void mdns_service_request_refresh(void)
*    Return: None.
*    Parameters: void - the function takes no arguments.
* \author
* \date 10-SEP-2026
* \brief Asks the task to resolve the name again at the next opportunity.
*
*        Intended for a link-up or a DHCP address change, after which a cached
*        address may belong to a different subnet and must not be trusted. The
*        previously resolved address stays published until a new answer
*        replaces it, so a caller mid-connection is never handed 0.0.0.0.
**************************************************/
void mdns_service_request_refresh(void);

#ifdef __cplusplus
}
#endif

#endif /* MDNS_SERVICE_H */
