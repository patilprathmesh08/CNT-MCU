/**
* \file    mdns_resolver.c
* \brief   mDNS hostname resolver - timeout, retry and re-resolution.
*
* Module name: mdns_resolver.c
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
* Resolves a ".local" hostname to an IPv4 address using lwIP's DNS module in
* mDNS mode. See mdns_resolver.h for the interface and the threading contract,
* and LWIP/Target/lwipopts.h USER CODE 1 for why LWIP_DNS_SUPPORT_MDNS_QUERIES
* rather than LWIP_MDNS_RESPONDER.
*
* WHAT THIS MODULE ADDS OVER dns_gethostbyname() ALONE
* lwIP's DNS client has its own internal retry, but it is bounded and it gives
* up. For a target device that may still be booting, or that may be absent for
* minutes, the useful behaviour is an OUTER retry with a bounded budget and a
* clear terminal state. That outer loop is what lives here, together with:
*   - a per-attempt timeout independent of lwIP's own
*   - an attempt counter, so a log can distinguish first-time success from
*     success after four failures
*   - a terminal FAILED state that a supervisor can re-arm on link-up
*   - safe hand-off of the result between tcpip_thread and the calling task
*
* THREADING
* Every entry into lwIP goes through tcpip_callback(), because dns_gethostbyname()
* is raw-API and may only run on tcpip_thread. The public functions are called
* from an ordinary task. The DNS answer arrives on tcpip_thread in
* mdns_dns_found_callback(), which is the only writer of the resolved address;
* readers take a short critical section.
*
* NOTHING HERE BLOCKS tcpip_thread. The callback does a handful of stores and
* returns.
*
* ENDIANNESS (GL11-C 13.4)
* The Cortex-M7 core is configured LITTLE-ENDIAN. The resolved address is stored
* as an lwIP ip4_addr_t, i.e. in NETWORK byte order, and is never interpreted
* byte-wise by this module - it is copied whole and printed with ip4addr_ntoa().
*
* OPEN NON-COMPLIANCE - DEFERRED, NOT APPROVED (GL11-C 11.4.1)
* This module calls printf() for its progress logging, which pulls newlib's heap
* into the image. The project owner ruled on 12-08-2026 that debug printf() calls
* are to be left alone for the time being. That is a DEFERRAL, deliberately
* recorded as such, and NOT a 1.3 exception. The logging here is specified
* behaviour rather than incidental - the whole point is to make a resolution
* failure diagnosable from the console - so if the deferral is ever closed, these
* calls should be routed through a Company console routine with a different name,
* not simply deleted.
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
* No absolute paths - GL11-C 14.2. main.h supplies the tuning macros;
* cmsis_os2.h supplies osKernelGetTickCount(); FreeRTOS task.h supplies the
* critical-section macros, which FreeRTOS.h alone does not.
***************************************************/
#include "mdns_resolver.h"
#include "main.h"

#include "cmsis_os2.h"
#include "FreeRTOS.h"
#include "task.h"

#include "lwip/dns.h"
#include "lwip/tcpip.h"
#include "lwip/err.h"

#include <stdio.h>
#include <string.h>

/* Defines section
* The tuning values themselves are in main.h. Only the strings this module owns
* are named here (GL11-C 14.3 - no magic values, and no literal repeated at two
* call sites where they could drift apart).
***************************************************/

/** Suffix that selects the mDNS transport. Six characters, checked in
    mdns_resolver_start(). Named because the length is derived from it below and
    the two must not disagree. */
#define MDNS_LOCAL_SUFFIX           ".local"

/** Log prefix, so every line this module emits is greppable as one group. */
#define MDNS_LOG                    "mdns: "

/* Variables section
* All module state lives in ONE structure, per GL11-C 7.14.4, rather than as
* seven separate file-scope objects. Static, so nothing outside this file can
* reach it - the public accessors in the header are the only way in.
*
* volatile because the DNS callback writes it on tcpip_thread while the poll and
* accessor functions read it on another task. Note that volatile alone does not
* make the ip4_addr_t copy atomic, which is why mdns_resolver_get_target() takes
* a critical section (GL11-C 9.7 - the object is wider than a native access).
***************************************************/
static struct Mdns_Variables
{
    mdns_resolver_state_t state;        /**< IDLE / RESOLVING / RESOLVED / FAILED */
    ip4_addr_t            target;       /**< Resolved address, network order.     */
    char const           *hostname;     /**< Name being resolved. Caller-owned.   */
    uint32_t              attempts;     /**< Query attempts since the last start. */
    uint32_t              attempt_tick; /**< osKernelGetTickCount() at the last
                                             attempt, for the timeout.           */
    uint8_t               request_busy; /**< 1 while a tcpip_callback is queued,
                                             so poll() cannot double-issue.      */
    uint8_t               lwip_gave_up; /**< Set by the DNS callback when lwIP
                                             reported failure (NULL address).
                                             Reported by poll(), because printf
                                             must not run on tcpip_thread.       */
} volatile Mdns = {0};

/* Function Prototype Section
* Static helpers. dns_gethostbyname(), tcpip_callback() and
* osKernelGetTickCount() are prototyped by the headers included above
* (GL11-C 10.4).
***************************************************/
static void mdns_dns_found_callback(char const *name, ip_addr_t const *ipaddr,
                                    void *callback_arg);
static void mdns_issue_query_on_tcpip(void *ctx);
static void mdns_begin_attempt(void);

/**
* \copyright 2026 \@PINETICS as an unpublished work.
* Function name: static void mdns_dns_found_callback(char const *name,
*                    ip_addr_t const *ipaddr, void *callback_arg)
*    Return: None. lwIP's dns_found_callback_t signature has no return value.
*    \param  name - the name that was resolved. Unused: this module has one
*            outstanding query at a time, so the answer cannot be ambiguous.
*    \param  ipaddr - the resolved address, or NULL if the lookup failed. NULL
*            is the normal failure indication from lwIP, not an error.
*    \param  callback_arg - unused; state is in the module structure.
* \author
* \date 17-AUG-2026
* \brief lwIP's answer, delivered on tcpip_thread.
*
*        Does the minimum: records the result and clears the busy flag. No
*        printf, no lwIP call, nothing that could block - this runs on the
*        thread that owns the whole stack.
*
*        A NULL ipaddr leaves the state at RESOLVING rather than moving it to
*        FAILED, deliberately: deciding whether the retry budget is spent belongs
*        to mdns_resolver_poll(), which is where the policy lives. Putting that
*        decision here would split it across two threads.
**************************************************/
static void mdns_dns_found_callback(char const *name, ip_addr_t const *ipaddr,
                                    void *callback_arg)
{
    (void)name;
    (void)callback_arg;

    if (ipaddr != NULL)
    {
        Mdns.target = *ip_2_ip4(ipaddr);
        Mdns.state  = MDNS_RESOLVER_RESOLVED;
    }
    else
    {
        /* lwIP has exhausted its OWN retry chain and given up on this lookup.
           The state stays RESOLVING; poll() owns the decision about whether any
           outer retry budget remains.

           THIS IS FLAGGED FOR THE NEXT ATTEMPT TO REPORT, not printed here.
           printf() is blocking UART and this callback runs on tcpip_thread - the
           thread that owns the whole lwIP stack - so logging from here would
           stall every connection and every lwIP timer for milliseconds. The flag
           costs a byte and the message comes out on the polling task instead.

           Leaving this path SILENT was a real observability defect, and it cost
           two rounds of misdiagnosis on 20-08-2026: the console showed attempts
           advancing with no timeout and no refusal line, which reads like broken
           retry logic when in fact lwIP was reporting a perfectly ordinary
           "no answer" for a target that was not on the network. An expected
           outcome still has to be visible. */
        Mdns.lwip_gave_up = 1U;
    }

    Mdns.request_busy = 0U;
}

/**
* \copyright 2026 \@PINETICS as an unpublished work.
* Function name: static void mdns_issue_query_on_tcpip(void *ctx)
*    Return: None. Runs as a tcpip_callback, which has no return path.
*    \param  ctx - unused; the hostname is in the module structure.
* \author
* \date 17-AUG-2026
* \brief Calls dns_gethostbyname() on tcpip_thread.
*
*        This indirection is MANDATORY, not stylistic. lwIP's DNS API is raw-API
*        and touching it from another task is a data race on lwIP's internal
*        tables that will appear to work and then corrupt the stack under load.
*        The same pattern is used for httpd_init() in main.c.
*
*        dns_gethostbyname() has three outcomes, and all three are handled:
*          ERR_OK          - the name was already cached, and ipaddr is valid
*                            immediately. The callback is NOT invoked in this
*                            case, so the result must be taken here
*          ERR_INPROGRESS  - a query was sent; the callback will fire later
*          anything else   - the request was refused outright
**************************************************/
static void mdns_issue_query_on_tcpip(void *ctx)
{
    ip_addr_t resolved;
    err_t     rc;

    (void)ctx;

    rc = dns_gethostbyname((char const *)Mdns.hostname, &resolved,
                           mdns_dns_found_callback, NULL);

    if (rc == ERR_OK)
    {
        /* Cache hit - the answer is available now and the callback will never
           be called. Taking it here is what stops a cached name looking like a
           timeout. */
        Mdns.target       = *ip_2_ip4(&resolved);
        Mdns.state        = MDNS_RESOLVER_RESOLVED;
        Mdns.request_busy = 0U;
    }
    else if (rc == ERR_INPROGRESS)
    {
        /* Nothing to do - the query is on the wire and the callback will
           report the outcome. request_busy stays set until it does. */
    }
    else
    {
        /* REFUSED OUTRIGHT - and this must be logged, not swallowed.
           On the first hardware run it was silent, and the console showed two
           "resolving" lines back to back with no timeout between them, which
           reads like a bug in the retry logic rather than what it is.

           ERR_MEM here means lwIP's DNS table is full. That table holds
           DNS_TABLE_SIZE entries (4 by default) and an entry stays in
           DNS_STATE_ASKING until lwIP's own retry chain expires - abandoning a
           query on our side does NOT free the slot. So this is the symptom of
           an outer retry that is faster than lwIP's inner one, which is why
           MDNS_QUERY_TIMEOUT_MS is now longer than that chain and
           MDNS_RETRY_INTERVAL_MS leaves the table time to clear.

           Recorded as a consumed attempt: the request genuinely failed, and
           pretending otherwise would let a full table loop forever. */
        printf(MDNS_LOG "query refused (rc %d, lwIP DNS table likely full) on"
                        " attempt %lu\r\n",
               (int)rc, (unsigned long)Mdns.attempts);
        Mdns.request_busy = 0U;

        /* Stamp the clock so the retry interval is measured from HERE, not from
           when the attempt started - otherwise a near-instant refusal would
           retry immediately and fill the table again. */
        Mdns.attempt_tick = (uint32_t)osKernelGetTickCount();
    }
}

/**
* \copyright 2026 \@PINETICS as an unpublished work.
* Function name: static void mdns_begin_attempt(void)
*    Return: None. Failure to queue leaves request_busy clear, so the next
*            poll() simply tries again - which is the desired behaviour.
*    Parameters: void - the function takes no arguments.
* \author
* \date 17-AUG-2026
* \brief Counts an attempt, stamps the clock and queues the query.
**************************************************/
static void mdns_begin_attempt(void)
{
    Mdns.attempts++;
    Mdns.attempt_tick = (uint32_t)osKernelGetTickCount();
    Mdns.request_busy = 1U;

    printf(MDNS_LOG "resolving %s (attempt %lu of %lu)\r\n",
           Mdns.hostname, (unsigned long)Mdns.attempts,
           (unsigned long)MDNS_MAX_RETRIES);

    if (tcpip_callback(mdns_issue_query_on_tcpip, NULL) != ERR_OK)
    {
        /* Could not hand the request to tcpip_thread - its mailbox is full.
           Clear the flag so the next poll() retries; do not consume the
           attempt budget for a failure that never reached the network. */
        Mdns.request_busy = 0U;
        Mdns.attempts--;
        printf(MDNS_LOG "*** tcpip_callback() failed, query not sent ***\r\n");
    }
    else
    {
        /* Nothing to do - the query is queued and the callback will report. */
    }
}

/**
* \copyright 2026 \@PINETICS as an unpublished work.
* Function name: void mdns_resolver_init(void)
*    Return: None. See mdns_resolver.h.
*    Parameters: void - the function takes no arguments.
* \author
* \date 17-AUG-2026
* \brief Clears module state. See mdns_resolver.h.
**************************************************/
void mdns_resolver_init(void)
{
    taskENTER_CRITICAL();
    Mdns.state        = MDNS_RESOLVER_IDLE;
    ip4_addr_set_any((ip4_addr_t *)&Mdns.target);
    Mdns.hostname     = NULL;
    Mdns.attempts     = 0U;
    Mdns.attempt_tick = 0U;
    Mdns.request_busy = 0U;
    Mdns.lwip_gave_up = 0U;
    taskEXIT_CRITICAL();

    printf(MDNS_LOG "resolver initialised\r\n");
}

/**
* \copyright 2026 \@PINETICS as an unpublished work.
* Function name: int32_t mdns_resolver_start(char const *hostname)
*    \return 0, -1 or -2. See mdns_resolver.h.
*    \param  hostname - name to resolve, must end in ".local" and must remain
*            valid for the lifetime of the resolution.
* \author
* \date 17-AUG-2026
* \brief Begins or restarts resolution. See mdns_resolver.h.
**************************************************/
int32_t mdns_resolver_start(char const *hostname)
{
    int32_t status = 0;
    size_t  name_len;
    size_t  suffix_len = strlen(MDNS_LOCAL_SUFFIX);

    if (hostname == NULL)
    {
        printf(MDNS_LOG "*** start refused: NULL hostname ***\r\n");
        status = -1;
    }
    else
    {
        name_len = strlen(hostname);

        /* Reject a name that does not end in ".local", rather than letting lwIP
           resolve it by unicast DNS. See the note in mdns_resolver.h: silently
           using the wrong transport is the failure mode worth preventing. */
        if ((name_len <= suffix_len)
            || (strcmp(&hostname[name_len - suffix_len], MDNS_LOCAL_SUFFIX) != 0))
        {
            printf(MDNS_LOG "*** start refused: '%s' does not end in %s ***\r\n",
                   hostname, MDNS_LOCAL_SUFFIX);
            status = -1;
        }
        else
        {
            taskENTER_CRITICAL();
            Mdns.hostname     = hostname;
            Mdns.state        = MDNS_RESOLVER_RESOLVING;
            Mdns.attempts     = 0U;
            Mdns.request_busy = 0U;
            Mdns.lwip_gave_up = 0U;
            ip4_addr_set_any((ip4_addr_t *)&Mdns.target);
            taskEXIT_CRITICAL();

            mdns_begin_attempt();
        }
    }

    return status;
}

/**
* \copyright 2026 \@PINETICS as an unpublished work.
* Function name: void mdns_resolver_poll(void)
*    Return: None. See mdns_resolver.h.
*    Parameters: void - the function takes no arguments.
* \author
* \date 17-AUG-2026
* \brief Advances timeout and retry. See mdns_resolver.h.
*
*        Only RESOLVING needs work. RESOLVED and FAILED are terminal until
*        someone calls mdns_resolver_start() again, and IDLE means nothing has
*        been asked for.
*
*        The tick comparison is written (now - then) >= limit rather than
*        now >= then + limit, so it stays correct across the 32-bit tick
*        wrap - unsigned subtraction wraps consistently, addition does not.
**************************************************/
void mdns_resolver_poll(void)
{
    uint32_t now;
    uint32_t elapsed;

    if (Mdns.state != MDNS_RESOLVER_RESOLVING)
    {
        /* Nothing to do - IDLE has no query outstanding, and RESOLVED and
           FAILED are terminal until start() is called again. */
    }
    else if (Mdns.request_busy != 0U)
    {
        /* A query is outstanding. Let it run until the timeout expires; the
           callback may still answer. */
        now     = (uint32_t)osKernelGetTickCount();
        elapsed = now - Mdns.attempt_tick;

        if (elapsed >= MDNS_QUERY_TIMEOUT_MS)
        {
            /* Timed out. Abandon this attempt - a late RESOLVED is still a
               correct answer and the callback will take it, because nothing in
               the callback is gated on request_busy except the flag itself.

               NOTE that this does NOT free lwIP's DNS table entry; that only
               clears when lwIP's own retry chain expires. MDNS_QUERY_TIMEOUT_MS
               is deliberately longer than that chain so this branch is a safety
               net rather than the normal path - see network_config.h. */
            Mdns.request_busy = 0U;
            Mdns.attempt_tick = (uint32_t)osKernelGetTickCount();
            printf(MDNS_LOG "timeout after %lu ms on attempt %lu\r\n",
                   (unsigned long)elapsed, (unsigned long)Mdns.attempts);
        }
        else
        {
            /* Nothing to do - still within the timeout for this attempt. */
        }
    }
    else if (Mdns.attempts >= MDNS_MAX_RETRIES)
    {
        /* Budget spent. Terminal until a supervisor re-arms us, which it does
           on link-up because the target may have moved or appeared. */
        Mdns.state = MDNS_RESOLVER_FAILED;
        printf(MDNS_LOG "*** resolution FAILED for %s after %lu attempts ***\r\n",
               Mdns.hostname, (unsigned long)Mdns.attempts);
    }
    else
    {
        /* Report lwIP's own give-up exactly once, here on the polling task
           rather than in the callback - see the note in
           mdns_dns_found_callback(). Without this the console shows attempts
           advancing with no explanation, which reads as a retry bug. */
        if (Mdns.lwip_gave_up != 0U)
        {
            Mdns.lwip_gave_up = 0U;
            printf(MDNS_LOG "no answer - lwIP gave up on attempt %lu\r\n",
                   (unsigned long)Mdns.attempts);
        }
        else
        {
            /* Nothing to do - this attempt ended by timeout or refusal,
               both of which log for themselves. */
        }

        /* Budget remains, but WAIT before retrying.
           Without this gap a near-instant failure - notably an ERR_MEM refusal
           when lwIP's DNS table is full - retries immediately and fills the
           table again, burning the whole attempt budget in a few hundred
           milliseconds. The first hardware run did exactly that. */
        now     = (uint32_t)osKernelGetTickCount();
        elapsed = now - Mdns.attempt_tick;

        if (elapsed >= MDNS_RETRY_INTERVAL_MS)
        {
            mdns_begin_attempt();
        }
        else
        {
            /* Nothing to do - still inside the gap between attempts. */
        }
    }
}

/**
* \copyright 2026 \@PINETICS as an unpublished work.
* Function name: mdns_resolver_state_t mdns_resolver_get_state(void)
*    \return The current state. See mdns_resolver.h.
*    Parameters: void - the function takes no arguments.
* \author
* \date 17-AUG-2026
* \brief Reports resolver state. Single enum read, so no critical section is
*        needed - it is a native-width object (GL11-C 9.7).
**************************************************/
mdns_resolver_state_t mdns_resolver_get_state(void)
{
    return Mdns.state;
}

/**
* \copyright 2026 \@PINETICS as an unpublished work.
* Function name: int32_t mdns_resolver_get_target(ip4_addr_t *out_addr)
*    \return 0, -1 or -2. See mdns_resolver.h.
*    \param  out_addr - receives the resolved address in network byte order.
* \author
* \date 17-AUG-2026
* \brief Copies out the resolved address. See mdns_resolver.h.
**************************************************/
int32_t mdns_resolver_get_target(ip4_addr_t *out_addr)
{
    int32_t status;

    if (out_addr == NULL)
    {
        status = -1;
    }
    else if (Mdns.state != MDNS_RESOLVER_RESOLVED)
    {
        /* Nothing resolved yet. out_addr is left untouched deliberately, so a
           caller that ignores the return value cannot mistake a zeroed address
           for a real one. */
        status = -2;
    }
    else
    {
        /* Critical section: an ip4_addr_t is wider than a single atomic access
           on this core and the writer is the DNS callback on tcpip_thread
           (GL11-C 9.7). The section is four bytes long, so the cost is
           negligible even on tcpip_thread. */
        taskENTER_CRITICAL();
        *out_addr = *(ip4_addr_t const *)&Mdns.target;
        taskEXIT_CRITICAL();

        status = 0;
    }

    return status;
}

/**
* \copyright 2026 \@PINETICS as an unpublished work.
* Function name: uint32_t mdns_resolver_get_attempts(void)
*    \return Attempt count since the last start(). See mdns_resolver.h.
*    Parameters: void - the function takes no arguments.
* \author
* \date 17-AUG-2026
* \brief Reports the attempt count. Single word, no critical section needed.
**************************************************/
uint32_t mdns_resolver_get_attempts(void)
{
    return Mdns.attempts;
}
