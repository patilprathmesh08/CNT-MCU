/**
* \file    mdns_config.h
* \brief   Compile-time configuration for the mDNS hostname resolver.
*
* Module name: mdns_config.h
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
* Holds every tuning constant for the mDNS resolver in one place, so the module
* can be enabled, retargeted or disabled without editing any source file.
*
* WHY THIS IS A SEPARATE HEADER AND NOT PART OF main.h
* The settings have to be visible from two places that cannot see each other:
*
*   mdns_resolver.c  reaches them through main.h, which it already includes.
*   lwipopts.h       needs MDNS_RESOLVER_ENABLE to derive
*                    LWIP_DNS_SUPPORT_MDNS_QUERIES, and cannot include main.h -
*                    lwipopts.h is pulled in by lwIP itself, long before the
*                    application headers exist, and including main.h from it
*                    would drag the whole HAL into every lwIP translation unit.
*
* This header therefore includes NOTHING. It defines only preprocessor
* constants, so either side may include it at any point without ordering
* concerns and without cost. Keeping it dependency-free is the property that
* makes the arrangement work; adding an #include here would break lwipopts.h.
*
* It also means the module travels between projects as three files -
* mdns_config.h, mdns_resolver.h, mdns_resolver.c - with no shared
* project-specific header to port alongside them.
*
* APPROVED EXCEPTIONS (GL11-C 1.3)
* None. This header defines no types, variables or functions, so the integer
* type rules of GL11-C 13.1 do not arise here.
*
* This block opens with two stars, not the four-star banner printed in GL11-C
* 2.4, and carries a \file tag, for the reason recorded in mdns_resolver.h:
* Doxygen ignores a comment block opening with three or more stars, so the 2.4
* form as printed generates no documentation at all.
****************************************************************/

/* Include section
* Deliberately empty. See the Module Description above - this header must stay
* free of includes so that lwipopts.h can use it.
***************************************************/

/* Defines section
* Include guard plus the four tuning constants. MDNS_CONFIG_H carries no
* leading underscore: ANSI C and ISO-IEC 9899 reserve the pattern
* _[A-Z_][0-9A-Za-z_] for the implementation (GL11-C 3.10).
***************************************************/
#ifndef MDNS_CONFIG_H
#define MDNS_CONFIG_H

/**
* Master switch for the whole facility.
*
* 1 builds the resolver and turns on LWIP_DNS_SUPPORT_MDNS_QUERIES in
* lwipopts.h, which is what routes a ".local" lookup to multicast.
* 0 removes both, and the project behaves exactly as it did before mDNS was
* added.
*
* The two must move together. Leaving the lwIP option on with the resolver off
* would compile mDNS support that nothing calls; turning the resolver on with
* the option off would send ".local" queries to the unicast DNS server the DHCP
* lease supplied, which cannot answer them. lwipopts.h therefore DERIVES its
* setting from this one rather than carrying a second switch.
**************************************************/
#define MDNS_RESOLVER_ENABLE        1

/**
* The name to resolve, including the ".local" suffix.
*
* THE SUFFIX IS NOT DECORATION - IT SELECTS THE TRANSPORT. lwIP compares the
* tail of the name against ".local" and sends the query to the mDNS multicast
* group only on a match. A name without it goes to the unicast DNS server
* instead, where it will not be found, and the failure looks identical to the
* host being absent.
*
* This is the i.MX8 that also serves the WSS stream and NTP. Resolving it by
* name is what removes the hard-coded address in stream_client.h - an address
* that went stale on 28-08-2026 when the bench moved from 192.168.40.x to
* 192.168.0.x, and took the epoch clock down with it because the NTP literal
* did not move at the same time.
**************************************************/
#define MDNS_TARGET_HOSTNAME        "verdin-imx8mp.local"//"imx8.local"

/**
* How long to wait for an answer before counting the attempt as failed, in
* milliseconds.
*
* This bounds ONE attempt, not the whole resolution.
*
* THE VALUE IS NOT A PREFERENCE - IT IS A CONSTRAINT. lwIP runs its own retry
* chain inside a single dns_gethostbyname() call, and an entry in its DNS table
* stays in DNS_STATE_ASKING until that chain expires. Abandoning the query on
* our side does NOT free the slot. The table holds DNS_TABLE_SIZE entries, four
* by default, so an outer timeout shorter than lwIP's inner chain fills the
* table with abandoned entries and every further attempt is refused with
* ERR_MEM - burning the whole retry budget in a few hundred milliseconds
* without a single query reaching the network.
*
* 12000 ms is carried over from HTTP_Server_H753_RTOS_ES_MBEDTLS_mDNS_V00,
* where that failure was observed on the first hardware run and this is the
* value that fixed it. Do not lower it without re-checking lwIP's DNS retry
* schedule; MDNS_RETRY_INTERVAL_MS is the other half of the same fix.
**************************************************/
#define MDNS_QUERY_TIMEOUT_MS       12000U

/**
* How long to wait between one failed attempt and the next, in milliseconds.
*
* The second half of the ERR_MEM fix described above. Without a gap, a
* near-instant failure - which is exactly what an ERR_MEM refusal is - retries
* immediately and fills lwIP's DNS table again. This interval gives the
* abandoned entries time to age out before the next query is made.
*
* Measured from the moment of failure, not from the start of the attempt, so a
* refusal that arrives in microseconds still waits the full interval.
**************************************************/
#define MDNS_RETRY_INTERVAL_MS      5000U

/**
* How many attempts before the resolver reports MDNS_RESOLVER_FAILED.
*
* FAILED is not permanent - a caller may return the resolver to RESOLVING by
* calling mdns_resolver_start() again, which is how re-resolution after a
* link-up works. The budget exists so a permanently absent host produces a
* definite answer instead of querying for ever.
**************************************************/
#define MDNS_MAX_RETRIES            5U

#endif /* MDNS_CONFIG_H */

/* Variables section
* This header defines no variables, as required by GL11-C 7.1.
***************************************************/

/* Function Prototype Section
* This header declares no functions. The resolver's interface is in
* mdns_resolver.h.
***************************************************/
