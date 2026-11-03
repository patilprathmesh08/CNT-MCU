/**
* \file    mdns_service.c
* \brief   FreeRTOS integration layer for the mDNS hostname resolver.
*
* Module name: mdns_service.c
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
* Drives mdns_resolver.c from a task of its own and publishes the address it
* finds. See mdns_service.h for why the policy lives here rather than in the
* resolver, and why it is a task rather than an inline loop.
*
* WHAT THIS MODULE DOES NOT DO, YET
* It resolves and reports. It does NOT redirect the WSS stream client or the
* NTP client at the address it finds - those still use the literals in
* stream_client.h and ntp_client.h. That separation is deliberate for the first
* integration step: mDNS can be proven against the live network without putting
* a working TLS connection at risk. mdns_service_get_address() is the hook for
* making that change once the resolution is trusted.
*
* THE PUBLISHED ADDRESS IS NEVER CLEARED
* Once resolved, the address stays available even while a refresh is in
* progress and even if that refresh fails. A caller mid-connection must never be
* handed 0.0.0.0 because a re-resolution happened to be running; a stale address
* that still works is strictly better than no address at all.
*
* ENDIANNESS (GL11-C 13.4)
* The Cortex-M7 core is configured LITTLE-ENDIAN. The published address is an
* lwIP ip4_addr_t, held in NETWORK byte order, and is never interpreted
* byte-wise here - it is copied whole and printed with ip4addr_ntoa().
*
* APPROVED EXCEPTIONS (GL11-C 1.3)
* 1. Integer types. GL11-C 13.1 mandates uint8 / int16 / uint32 style typedefs.
*    This project uses the C99 <stdint.h> names instead, because every ST HAL,
*    CMSIS, FreeRTOS and lwIP interface it calls is declared in those terms.
*    Ruled by the project owner on 12-08-2026.
****************************************************************/

/* Include section
* mdns_service.h for this module's own interface. mdns_resolver.h for the
* resolver being driven. cmsis_os2.h for the task and the delays. lwip/netif.h
* and the gnetif extern for the address-available test. stdio.h for printf.
***************************************************/
#include "mdns_service.h"
#include "mdns_resolver.h"

#include "cmsis_os2.h"
#include "lwip/netif.h"

#include <stdio.h>
#include <string.h>

#if (MDNS_RESOLVER_ENABLE != 0)

/* Defines section
***************************************************/

/**
* Stack for the mDNS task, in bytes.
*
* The task itself holds only a handful of locals, but it calls printf, whose
* newlib-nano implementation is the largest consumer on this path. 1024 bytes
* is the same figure the other low-priority tasks in this project use and has
* proven sufficient there.
**************************************************/
#define MDNS_TASK_STACK_BYTES       1024U

/**
* How often the task calls mdns_resolver_poll() while a query is outstanding.
*
* The resolver's timeout is measured in whole milliseconds and compared against
* an elapsed time, so the poll interval only bounds how late a timeout is
* noticed - it does not affect accuracy. 100 ms costs ten wake-ups a second
* during a resolution and nothing at all between them.
**************************************************/
#define MDNS_POLL_INTERVAL_MS       100U

/**
* How long to wait before resolving again after the retry budget is spent.
*
* A server that is switched on after the board is the ordinary case, so failure
* must not be permanent. Thirty seconds is long enough that a genuinely absent
* host does not fill the console, and short enough that a late-booting one is
* picked up without a reset.
**************************************************/
#define MDNS_RETRY_AFTER_FAIL_MS    30000U

/**
* How long to wait between checks for a usable interface address.
*
* Only used before the first resolution, while the DHCP lease is still being
* acquired.
**************************************************/
#define MDNS_ADDR_WAIT_MS           500U

/* Variables section
* Module state. Capitalised_Words per GL11-C 3.6 for objects with wider than
* function scope. All are static, so nothing here is a project-wide global and
* none of it appears in globals.c.
***************************************************/

/** The lwIP interface, created by MX_LWIP_Init() in LWIP/App/lwip.c. */
extern struct netif gnetif;

/** The most recently resolved address, in NETWORK byte order. */
static ip4_addr_t Mdns_Address;

/** Non-zero once Mdns_Address holds a genuine answer. Never cleared. */
static volatile uint8_t Mdns_Resolved;

/**
* Increments on every publication, including one that repeats the previous
* address.
*
* A consumer that has asked for a refresh uses this to tell a NEW answer from
* the OLD one still sitting in Mdns_Address. Comparing the addresses instead
* would not do: a server that moved away and came back, or a refresh that
* confirms the same address, both leave the value unchanged while genuinely
* being fresh answers.
**************************************************/
static volatile uint32_t Mdns_Generation;

/** Set by mdns_service_request_refresh(), cleared when the task acts on it. */
static volatile uint8_t Mdns_Refresh_Requested;

/** Successful resolutions since boot, for the console and the debugger. */
static volatile uint32_t Mdns_Resolve_Count;

/** Exhausted retry budgets since boot. */
static volatile uint32_t Mdns_Fail_Count;

static osThreadId_t Mdns_Task_Handle;

static const osThreadAttr_t Mdns_Task_Attributes =
{
    .name       = "MdnsService",
    .stack_size = MDNS_TASK_STACK_BYTES,
    .priority   = (osPriority_t)osPriorityLow
};

/* Function Prototype Section
***************************************************/
static uint32_t enter_critical_section(void);
static void     exit_critical_section(uint32_t primask);
static uint8_t  is_address_usable(void);
static void     publish_address(ip4_addr_t const *addr);
static void     run_mdns_task(void *argument);

/**
* \copyright 2026 \@PINETICS as an unpublished work.
* Function name: static uint32_t enter_critical_section(void)
*    \return The PRIMASK value in force before masking, to be handed back to
*            exit_critical_section().
*    \param  void - the function takes no arguments.
* \author
* \date 10-SEP-2026
* \brief Masks interrupts around an access to the published address.
*
*        PRIMASK is saved and restored rather than using a bare
*        __disable_irq()/__enable_irq() pair, so a caller that already holds a
*        critical section does not have it released underneath (GL11-C 14.7).
**************************************************/
static uint32_t enter_critical_section(void)
{
    uint32_t primask = __get_PRIMASK();

    __disable_irq();

    return primask;
}

/**
* \copyright 2026 \@PINETICS as an unpublished work.
* Function name: static void exit_critical_section(uint32_t primask)
*    \return None.
*    \param  primask - the value returned by the matching
*            enter_critical_section() call.
* \author
* \date 10-SEP-2026
* \brief Restores the interrupt state saved by enter_critical_section().
**************************************************/
static void exit_critical_section(uint32_t primask)
{
    __set_PRIMASK(primask);
}

/**
* \copyright 2026 \@PINETICS as an unpublished work.
* Function name: static uint8_t is_address_usable(void)
*    \return 1 when the interface holds a non-zero IPv4 address, 0 otherwise.
*    \param  void - the function takes no arguments.
* \author
* \date 10-SEP-2026
* \brief Reports whether a query could be answered.
*
*        An mDNS query sent from 0.0.0.0 cannot be answered: the responder has
*        no address to send the unicast reply to. Testing this before starting
*        is what stops the retry budget being spent on attempts that could never
*        have succeeded.
**************************************************/
static uint8_t is_address_usable(void)
{
    uint8_t usable;

    if (ip4_addr_isany_val(*netif_ip4_addr(&gnetif)) != 0)
    {
        usable = 0U;
    }
    else
    {
        usable = 1U;
    }

    return usable;
}

/**
* \copyright 2026 \@PINETICS as an unpublished work.
* Function name: static void publish_address(ip4_addr_t const *addr)
*    \return None.
*    \param  addr - the newly resolved address. Must not be NULL; the only
*            caller passes the address of a local, so no check is made here.
* \author
* \date 10-SEP-2026
* \brief Makes a resolved address visible to other tasks.
*
*        Written inside a critical section because an ip4_addr_t is wider than
*        the core can store atomically, and a reader in another task could
*        otherwise observe half of an old address and half of a new one
*        (GL11-C 14.7).
**************************************************/
static void publish_address(ip4_addr_t const *addr)
{
    uint32_t primask = enter_critical_section();

    Mdns_Address  = *addr;
    Mdns_Resolved = 1U;

    /* Bumped INSIDE the same critical section as the address, so a reader can
       never observe a new generation beside an old address or the reverse. */
    Mdns_Generation++;

    exit_critical_section(primask);

    Mdns_Resolve_Count++;
}

/**
* \copyright 2026 \@PINETICS as an unpublished work.
* Function name: static void run_mdns_task(void *argument)
*    \return None. The function never returns, as required of a FreeRTOS task
*            body.
*    \param  argument - unused; required by the osThreadFunc_t signature.
* \author
* \date 10-SEP-2026
* \brief Task body. Resolves the configured name and keeps it current.
*
*        The loop has three jobs: wait until a query could be answered, drive
*        the resolver to a conclusion, then wait for a reason to do it again.
*        A reason is either a refresh request from
*        mdns_service_request_refresh() or the expiry of the post-failure
*        delay.
**************************************************/
static void run_mdns_task(void *argument)
{
    (void)argument;

    mdns_resolver_init();

    for (;;)
    {
        /* ---- 1. wait until a query could be answered -------------------- */
        if (is_address_usable() == 0U)
        {
            osDelay(MDNS_ADDR_WAIT_MS);
        }
        else
        {
            int32_t start_status = mdns_resolver_start(MDNS_TARGET_HOSTNAME);

            if (start_status != 0)
            {
                /* -1 is a malformed name, which no amount of retrying fixes,
                   and -2 is a failure to reach tcpip_thread, which a later
                   attempt might survive. Both are reported once and retried on
                   the same schedule as an exhausted budget, because the
                   distinction does not change what this task can do about it. */
                printf("mdns: start(\"%s\") refused, status %ld\r\n",
                       MDNS_TARGET_HOSTNAME, (long)start_status);
                osDelay(MDNS_RETRY_AFTER_FAIL_MS);
            }
            else
            {
                /* ---- 2. drive it to a conclusion ------------------------ */
                mdns_resolver_state_t state = MDNS_RESOLVER_RESOLVING;

                while (state == MDNS_RESOLVER_RESOLVING)
                {
                    osDelay(MDNS_POLL_INTERVAL_MS);
                    mdns_resolver_poll();
                    state = mdns_resolver_get_state();
                }

                if (state == MDNS_RESOLVER_RESOLVED)
                {
                    ip4_addr_t resolved;

                    if (mdns_resolver_get_target(&resolved) == 0)
                    {
                        publish_address(&resolved);
                        printf("mdns: %s resolved to %s after %lu attempt(s)\r\n",
                               MDNS_TARGET_HOSTNAME, ip4addr_ntoa(&resolved),
                               (unsigned long)mdns_resolver_get_attempts());
                    }
                    else
                    {
                        /* The resolver reported RESOLVED but produced nothing.
                           Treated as a failure rather than trusted, because the
                           alternative is publishing whatever was in the local. */
                        Mdns_Fail_Count++;
                        printf("mdns: *** state RESOLVED but no address "
                               "returned ***\r\n");
                    }
                }
                else
                {
                    Mdns_Fail_Count++;
                    printf("mdns: *** %s not found after %lu attempt(s) ***\r\n",
                           MDNS_TARGET_HOSTNAME,
                           (unsigned long)mdns_resolver_get_attempts());
                    printf("mdns:     check the host advertises this name and "
                           "that both are on one subnet\r\n");
                }

                /* ---- 3. wait for a reason to resolve again -------------- */
                {
                    uint32_t waited = 0U;

                    while ((waited < MDNS_RETRY_AFTER_FAIL_MS) &&
                           (Mdns_Refresh_Requested == 0U))
                    {
                        osDelay(MDNS_POLL_INTERVAL_MS);
                        waited += MDNS_POLL_INTERVAL_MS;
                    }

                    Mdns_Refresh_Requested = 0U;
                }
            }
        }
    }
}

/* Exported functions
***************************************************/

void mdns_service_init(void)
{
    Mdns_Resolved          = 0U;
    Mdns_Refresh_Requested = 0U;
    Mdns_Generation        = 0U;
    Mdns_Resolve_Count     = 0U;
    Mdns_Fail_Count        = 0U;
    ip4_addr_set_zero(&Mdns_Address);

    Mdns_Task_Handle = osThreadNew(run_mdns_task, NULL, &Mdns_Task_Attributes);

    if (Mdns_Task_Handle == NULL)
    {
        printf("mdns: *** task creation FAILED - no name resolution ***\r\n");
    }
    else
    {
        printf("mdns: resolving %s, timeout %lu ms, %lu attempt(s)\r\n",
               MDNS_TARGET_HOSTNAME, (unsigned long)MDNS_QUERY_TIMEOUT_MS,
               (unsigned long)MDNS_MAX_RETRIES);
    }
}

int32_t mdns_service_get_address_gen(ip4_addr_t *out_addr, uint32_t *out_gen)
{
    int32_t  status;
    uint32_t primask;

    if ((out_addr == NULL) || (out_gen == NULL))
    {
        status = -1;
    }
    else
    {
        primask = enter_critical_section();

        if (Mdns_Resolved == 0U)
        {
            /* Nothing resolved yet. Both outputs are deliberately left
               untouched so a caller that ignores the return cannot mistake a
               zeroed buffer for an address. */
            status = -1;
        }
        else
        {
            /* Read together, under one lock, so the generation always describes
               the address returned beside it. */
            *out_addr = Mdns_Address;
            *out_gen  = Mdns_Generation;
            status = 0;
        }

        exit_critical_section(primask);
    }

    return status;
}

int32_t mdns_service_get_address(ip4_addr_t *out_addr)
{
    uint32_t ignored_generation;

    /* Thin wrapper for callers that only want the address. The NTP client is
       one: it re-reads before every poll, so an address that changed since the
       last one is picked up without it having to track anything. */
    return mdns_service_get_address_gen(out_addr, &ignored_generation);
}

uint8_t mdns_service_is_resolved(void)
{
    return Mdns_Resolved;
}

void mdns_service_request_refresh(void)
{
    Mdns_Refresh_Requested = 1U;
}

#else /* MDNS_RESOLVER_ENABLE == 0 */

/* The facility is compiled out. The four entry points are still defined, so
   every call site stays valid C and the disabled build cannot rot - a call site
   guarded only at the caller would compile today and fail the day someone adds
   an unguarded one. */

void mdns_service_init(void)
{
    printf("mdns: DISABLED (MDNS_RESOLVER_ENABLE = 0)\r\n");
}

int32_t mdns_service_get_address(ip4_addr_t *out_addr)
{
    (void)out_addr;

    return -1;
}

int32_t mdns_service_get_address_gen(ip4_addr_t *out_addr, uint32_t *out_gen)
{
    (void)out_addr;
    (void)out_gen;

    return -1;
}

uint8_t mdns_service_is_resolved(void)
{
    return 0U;
}

void mdns_service_request_refresh(void)
{
    /* Nothing to refresh. */
}

#endif /* MDNS_RESOLVER_ENABLE */
