/*
 * Copyright (c) @CompanyNameMagicTag 2021-2021. All rights reserved.
 * Description:  Default memory configurations
 * Author: @CompanyNameTag
 * Create: 2021-03-09
 */

#ifndef ROM_MEMORY_CONFIG_H
#define ROM_MEMORY_CONFIG_H

#include "memory_config_common.h"
#include "chip_definitions.h"
#include "product.h"
/* Standard lengths
 */
#define VECTORS_LENGTH 360
#define VERSION_LENGTH 88
#define SSB_START_ADDR 0x16c

/*
 * ********************* ROM ALLOCATION ***********************
 *
 * Used solely by the Security Core ROM image built into the chip.
 */
/* ROM based application code */
#define ROM_VECTORS_ORIGIN (ROM_START)
#define ROM_VECTORS_LENGTH (VECTORS_LENGTH)

#define ROM_VERSION_ORIGIN (ROM_START)
#define ROM_PROGRAM_LENGTH (ROM_LENGTH - OTP_SIZE_IN_BYTES)

/* ----------------------------------------------------------------------------------------------------------------- */
/*
 * ********************* RAM ALLOCATION ***********************
 *
 * Mem Alloc: Stack + Romboot.Data + Romboot.Bss + Romboot.Heap + Romloader + Sec
 */
#define ROM_SRAM_START  (CHIP_SRAM_END - ROM_SRAM_LENGTH)
#define ROM_SRAM_LENGTH 0x18000
#define ROM_SRAM_END    CHIP_SRAM_END

/*
 * ********************* Stack Alloction ***********************
 */
/* stack for normal 7k */
#define ROM_USER_STACK_BASEADDR ROM_SRAM_START
#define ROM_USER_STACK_LEN      0x1c00
#define ROM_USER_STACK_LIMIT    (ROM_USER_STACK_BASEADDR + ROM_USER_STACK_LEN)

/* stack for irq 1k */
#define ROM_IRQ_STACK_BASEADDR  ROM_USER_STACK_LIMIT
#define ROM_IRQ_STACK_LEN      0x400
#define ROM_IRQ_STACK_LIMIT    (ROM_IRQ_STACK_BASEADDR + ROM_IRQ_STACK_LEN)

/* stack for exception 1k */
#define ROM_EXCP_STACK_BASEADDR ROM_IRQ_STACK_LIMIT
#define ROM_EXCP_STACK_LEN      0x400
#define ROM_EXCP_STACK_LIMIT    (ROM_EXCP_STACK_BASEADDR + ROM_EXCP_STACK_LEN)

#define ROM_STACK_START         ROM_SRAM_START
#define ROM_STACK_END           ROM_EXCP_STACK_LIMIT
#define ROM_STACK_LENGTH        (ROM_USER_STACK_LEN + ROM_IRQ_STACK_LEN + ROM_EXCP_STACK_LEN)

/*
 * ********************* Romboot data bss heap Alloction ***********************
 */
/* rom actually used sram */
#define ROM_DATA_BSS_HEAP_START     ROM_STACK_END
#define ROM_DATA_BSS_HEAP_LENGTH    (ROM_SRAM_LENGTH - ROM_STACK_LENGTH - ROMLOADER_USE_SRAM_LENGTH - \
                                     MCU_RSA_REGION_LENGTH - OTP_SIZE_IN_BYTES)
#define ROM_DATA_BSS_HEAP_END       ((ROM_DATA_BSS_HEAP_START) + (ROM_DATA_BSS_HEAP_LENGTH))
#endif
