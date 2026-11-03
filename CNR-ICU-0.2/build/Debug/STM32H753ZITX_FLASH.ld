/*
******************************************************************************
**
**  File        : LinkerScript.ld
**
**  Author      : STM32CubeIDE
**
**  Abstract    : Linker script for STM32H7 series
**                2048Kbytes FLASH and 1056Kbytes RAM
**
**                Set heap size, stack size and stack location according
**                to application requirements.
**
**                Set memory bank area and size if external memory is used.
**
**  Target      : STMicroelectronics STM32
**
**  Distribution: The file is distributed as is, without any warranty
**                of any kind.
**
*****************************************************************************
** @attention
**
** Copyright (c) 2026 STMicroelectronics.
** All rights reserved.
**
** This software is licensed under terms that can be found in the LICENSE file
** in the root directory of this software component.
** If no LICENSE file comes with this software, it is provided AS-IS.
**
****************************************************************************
*/

/* Entry Point */
ENTRY(Reset_Handler)

/* Highest address of the user mode stack */
_estack = ORIGIN(RAM_D1) + LENGTH(RAM_D1);    /* end of RAM */
/* Generate a link error if heap and stack don't fit into RAM */
_Min_Heap_Size = 0x200;      /* required amount of heap  */
_Min_Stack_Size = 0x2000; /* required amount of stack */

/* Specify the memory areas */
MEMORY
{
  FLASH (rx)     : ORIGIN = 0x08000000, LENGTH = 2048K
  DTCMRAM (xrw)  : ORIGIN = 0x20000000, LENGTH = 128K
  RAM_D1 (xrw)   : ORIGIN = 0x24000000, LENGTH = 512K
  RAM_D2 (xrw)   : ORIGIN = 0x30000000, LENGTH = 288K
  RAM_D3 (xrw)   : ORIGIN = 0x38000000, LENGTH = 64K
  ITCMRAM (xrw)  : ORIGIN = 0x00000000, LENGTH = 64K
}

/* Define output sections */
SECTIONS
{
  /* The startup code goes first into FLASH */
  .isr_vector :
  {
    . = ALIGN(4);
    KEEP(*(.isr_vector)) /* Startup code */
    . = ALIGN(4);
  } >FLASH

  /* The program code and other data goes into FLASH */
  .text :
  {
    . = ALIGN(4);
    *(.text)           /* .text sections (code) */
    *(.text*)          /* .text* sections (code) */
    *(.glue_7)         /* glue arm to thumb code */
    *(.glue_7t)        /* glue thumb to arm code */
    *(.eh_frame)

    KEEP (*(.init))
    KEEP (*(.fini))

    . = ALIGN(4);
    _etext = .;        /* define a global symbols at end of code */
  } >FLASH

  /* Constant data goes into FLASH */
  .rodata :
  {
    . = ALIGN(4);
    *(.rodata)         /* .rodata sections (constants, strings, etc.) */
    *(.rodata*)        /* .rodata* sections (constants, strings, etc.) */
    . = ALIGN(4);
  } >FLASH

  .ARM.extab (READONLY) : /* The READONLY keyword is only supported in GCC11 and later, remove it if using GCC10 or earlier. */
  {
    *(.ARM.extab* .gnu.linkonce.armextab.*)
  } >FLASH
  .ARM (READONLY) : /* The READONLY keyword is only supported in GCC11 and later, remove it if using GCC10 or earlier. */
  {
    __exidx_start = .;
    *(.ARM.exidx*)
    __exidx_end = .;
  } >FLASH

  .preinit_array (READONLY) : /* The READONLY keyword is only supported in GCC11 and later, remove it if using GCC10 or earlier. */
  {
    PROVIDE_HIDDEN (__preinit_array_start = .);
    KEEP (*(.preinit_array*))
    PROVIDE_HIDDEN (__preinit_array_end = .);
  } >FLASH

  .init_array (READONLY) : /* The READONLY keyword is only supported in GCC11 and later, remove it if using GCC10 or earlier. */
  {
    PROVIDE_HIDDEN (__init_array_start = .);
    KEEP (*(SORT(.init_array.*)))
    KEEP (*(.init_array*))
    PROVIDE_HIDDEN (__init_array_end = .);
  } >FLASH

  .fini_array (READONLY) : /* The READONLY keyword is only supported in GCC11 and later, remove it if using GCC10 or earlier. */
  {
    PROVIDE_HIDDEN (__fini_array_start = .);
    KEEP (*(SORT(.fini_array.*)))
    KEEP (*(.fini_array*))
    PROVIDE_HIDDEN (__fini_array_end = .);
  } >FLASH

  /* used by the startup to initialize data */
  _sidata = LOADADDR(.data);

  /* Initialized data sections goes into RAM, load LMA copy after code */
  .data :
  {
    . = ALIGN(4);
    _sdata = .;        /* create a global symbol at data start */
    *(.data)           /* .data sections */
    *(.data*)          /* .data* sections */
    *(.RamFunc)        /* .RamFunc sections */
    *(.RamFunc*)       /* .RamFunc* sections */

    . = ALIGN(4);
    _edata = .;        /* define a global symbol at data end */
  } >RAM_D1 AT> FLASH

  /* Uninitialized data section */
  . = ALIGN(4);
  .bss :
  {
    /* This is used by the startup in order to initialize the .bss section */
    _sbss = .;         /* define a global symbol at bss start */
    __bss_start__ = _sbss;
    *(.bss)
    *(.bss*)
    *(COMMON)

    . = ALIGN(4);
    _ebss = .;         /* define a global symbol at bss end */
    __bss_end__ = _ebss;
  } >RAM_D1

  /* User_heap_stack section, used to check that there is enough RAM left */
  ._user_heap_stack :
  {
    . = ALIGN(8);
    PROVIDE ( end = . );
    PROVIDE ( _end = . );
    . = . + _Min_Heap_Size;
    . = . + _Min_Stack_Size;
    . = ALIGN(8);
  } >RAM_D1

  /* Ethernet DMA descriptors and the zero-copy Rx buffer pool.
   * Must sit in RAM_D2 (0x30000000) so they fall inside the non-cacheable
   * MPU region set up by MPU_Config() - the Ethernet DMA and the CPU must
   * never hold different views of this memory.
   * NOLOAD: runtime-only buffers, never initialised from flash.
   * Section names must match ethernetif.c's __attribute__((section(...))).
   *
   * ======================================================================
   * KEEP() ADDED 07-08-2026 - THIS IS LOAD-BEARING, DO NOT REMOVE IT.
   * ======================================================================
   * Without KEEP(), --gc-sections (this project builds with
   * -ffunction-sections -fdata-sections -Wl,--gc-sections) is free to delete
   * these sections, and on 07-08-2026 it did exactly that. The map showed all
   * three in the "Discarded input sections" block:
   *     .Rx_PoolSection     0xc403   DISCARDED
   *     .RxDescripSection   0x180    DISCARDED
   *     .TxDescripSection   0x240    DISCARDED
   * while the output sections at 0x30000000 were left at size 0x0 and the
   * symbols DMARxDscrTab / DMATxDscrTab / memp_memory_RX_POOL_base vanished
   * from the map entirely.
   *
   * HOW IT PRESENTS - nothing points at the linker:
   *     eth: PHY *** NOT DETECTED (MDIO failure) ***
   *     net: MAC 00:00:00:00:00:00 flags=0x00 up=0 link=0
   *     Assertion "Invalid mbox" failed at line 327 in tcpip.c
   * HAL_ETH_Init() is handed descriptor pointers to nothing and fails, so
   * low_level_init() returns early, the netif is never populated, and every
   * later symptom is downstream of that. The build is completely clean.
   *
   * WHY GC CANNOT REASON ABOUT THESE: they are DMA buffers. Their real consumer
   * is the Ethernet peripheral, not the CPU, so the only thing keeping them
   * alive is an incidental reference from low_level_init(). Anything that weakens
   * that reference - a lost MX_LWIP_Init() call, inlining, a changed link order -
   * silently deletes 51 KB of DMA memory. KEEP() states the requirement outright
   * instead of relying on that reference surviving.
   *
   * WHAT ACTUALLY TRIGGERED IT HERE - correction, established later on 07-08-2026.
   * An earlier revision of this comment said the trigger "differed" from the
   * 31-07-2026 occurrence in TCP_Server_H753_RTOS__ES_MBEDTLS_V00 because
   * MX_LWIP_Init() was still being called. It was NOT being called. Enabling
   * mbedTLS makes CubeMX move the LwIP init out of StartEthIfTask() and into
   * mbedtls_net_init() in MBEDTLS/App/net_sockets.c, which an altcp_tls server
   * never calls - so low_level_init() genuinely was unreachable. The trigger is
   * therefore IDENTICAL in both projects: no reachable MX_LWIP_Init(). See the
   * long note at the top of StartEthIfTask() in Core/Src/main.c for the full
   * mechanism and the guarded hand-written call that fixes it.
   *
   * KEEP() is still worth having on its own merits - it removes the whole class
   * of failure rather than this one instance - but on its own it does NOT make
   * the board work. Restoring MX_LWIP_Init() is the actual fix; without it the
   * descriptors are merely correctly placed and never used.
   *
   * NOTE: the identical .ld in HTTP_Server_H753_V00, HTTP_Server_H753_ISR_V00
   * and HTTP_Server_H753_RTOS_ES_V00 does NOT yet carry this fix. They link
   * correctly today and are hardware-verified, so they were deliberately left
   * alone - but they carry the same latent hazard. If any of them ever reports
   * "PHY NOT DETECTED" after a regeneration, check the map for discarded
   * sections before anything else.
   * ==================================================================== */
  .RxDescripSection (NOLOAD) :
  {
    . = ALIGN(4);
    KEEP(*(.RxDescripSection))
  } >RAM_D2

  .TxDescripSection (NOLOAD) :
  {
    . = ALIGN(4);
    KEEP(*(.TxDescripSection))
  } >RAM_D2

  .Rx_PoolSection (NOLOAD) :
  {
    . = ALIGN(4);
    KEEP(*(.Rx_PoolSection))
  } >RAM_D2

  /* Remove information from the standard libraries */
  /DISCARD/ :
  {
    libc.a ( * )
    libm.a ( * )
    libgcc.a ( * )
  }

  .ARM.attributes 0 : { *(.ARM.attributes) }
}


