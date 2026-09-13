/*
 * Copyright (c) @CompanyNameMagicTag 2021-2021. All rights reserved.
 * Description:  Default memory configurations
 * Author: @CompanyNameTag
 * Create: 2021-03-09
 */
#ifndef MEMORY_CONFIG_H
#define MEMORY_CONFIG_H

#include "product.h"

/* ----------------------------------------------------------------------------------------------------------------- */
/* MCU ITCM config */
#ifndef APP_ITCM_ORIGIN
#define APP_ITCM_ORIGIN 0x20000
#endif
#define APP_ITCM_LENGTH 0x10000

/* Boot Load RAM Addr */
#define BOOT_RAM_MIN    APP_ITCM_ORIGIN
#define BOOT_RAM_MAX    (APP_ITCM_ORIGIN + APP_ITCM_LENGTH)

/* MCU DTCM config */
#define APP_SRAM_ORIGIN (0x2006c000 - 0x18000)
#define APP_SRAM_LENGTH 0x18000

#define FLASH_PROGRAM_ORIGIN (0x28300)
#define FLASH_PROGRAM_LENGTH (0x10000)
/* stack for normal 7k */
#define USER_STACK_BASEADDR APP_DTCM_ORIGIN
#define USER_STACK_LEN      0x1c00
#define USER_STACK_LIMIT    (USER_STACK_BASEADDR + USER_STACK_LEN)

/* stack for irq 1k */
#define IRQ_STACK_BASEADDR USER_STACK_LIMIT
#define IRQ_STACK_LEN      0x400
#define IRQ_STACK_LIMIT    (IRQ_STACK_BASEADDR + IRQ_STACK_LEN)

/* stack for exception 1k */
#define EXCP_STACK_BASEADDR IRQ_STACK_LIMIT
#define EXCP_STACK_LEN      0x400
#define EXCP_STACK_LIMIT    (EXCP_STACK_BASEADDR + EXCP_STACK_LEN)

#define FLASH_STACK_LEN       (USER_STACK_LEN + IRQ_STACK_LEN + EXCP_STACK_LEN)

#endif
