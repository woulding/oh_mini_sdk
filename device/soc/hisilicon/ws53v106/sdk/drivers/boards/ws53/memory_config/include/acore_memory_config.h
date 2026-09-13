/*
 * Copyright (c) @CompanyNameMagicTag 2021-2021. All rights reserved.
 * Description:  Default memory configurations
 * Author: @CompanyNameTag
 * Create:  2021-06-16
 */

#ifndef ACORE_MEMORY_CONFIG_H
#define ACORE_MEMORY_CONFIG_H

#include "memory_config_common.h"

#define APP_START_ORIGIN (CHIP_SRAM_ORIGIN)
#define APP_START_LENGTH 0x200

#define APP_FLASH_STARTUP_ORIGIN FALSH_APP_PROGRAM_ORIGIN
#define APP_FLASH_STARTUP_LENGTH 0x400
#define APP_FLASH_STARTUP_END    (APP_FLASH_STARTUP_ORIGIN + APP_FLASH_STARTUP_LENGTH)

#define APP_FLASH_PROGRAM_ORIGIN APP_FLASH_STARTUP_END
#define APP_FLASH_PROGRAM_LENGTH (FALSH_APP_PROGRAM_LENGTH - APP_FLASH_STARTUP_LENGTH)
#define APP_FLASH_PROGRAM_END    (APP_FLASH_PROGRAM_ORIGIN + APP_FLASH_PROGRAM_LENGTH)

#define APP_SRAM_ORIGIN CHIP_SRAM_ORIGIN
#define APP_SRAM_LENGTH (CHIP_SRAM_LENGTH - PRESERVED_REGION_LENGTH)
#define APP_SRAM_END    (APP_SRAM_ORIGIN + APP_SRAM_LENGTH)

#define CCORE_RAM_START_ADDR     0x10010000
#define CCORE_RAM_START_LENGTH   0x80

#define IPC_BUFF_SHARE_ORIGIN       0x10080000

#define CCORE_ROM_START_ADDR     0x10040000
#define CCORE_ROM_START_LENGTH   0x340
#define CCORE_ROM_LENGTH         0x0

#define ACORE_ROM_START_ADDR        0x19C00
#define ACORE_ROM_LENGTH            0x6400

#define APP_ITCM_START_ADDR         0x20000
#if defined(CONFIG_MCU_MODE_4) || defined(CONFIG_MCU_MODE_2)
#define APP_DTCM_LENGTH             0x58000
#define APP_ITCM_LENGTH             0x10000
#define APP_DTCM_START_ADDR         0x20010000
#elif defined(CONFIG_MCU_MODE_3)
#define APP_DTCM_LENGTH             0x60000
#define APP_ITCM_LENGTH             0x8000
#define APP_DTCM_START_ADDR         0x20008000
#else
#define APP_DTCM_LENGTH             0x50000
#define APP_ITCM_LENGTH             0x10000
#define APP_DTCM_START_ADDR         0x20010000
#endif

/* ----------------------------------------------------------------------------------------------------------------- */
/* APP RAM defines
 */
/* 256K DTCM for APP core data */
/* stack for normal 8k */
#define APP_USER_STACK_LEN      0x1000
/* stack for irq 1k */
#define APP_IRQ_STACK_LEN       0x800
/* stack for exception 1k */
#define APP_EXCP_STACK_LEN      0x800
/* stack for nmi 1k */
#define APP_NMI_STACK_LEN       0x400
#define APP_STACK_LENGTH        (APP_USER_STACK_LEN + APP_IRQ_STACK_LEN + APP_EXCP_STACK_LEN + APP_NMI_STACK_LEN)

#define LOGGING_REGION_START     get_log_buff()
#define SYSTEM_CFG_REGION_START  0
#define SYSTEM_CFG_REGION_LENGTH 0

// device mode
#define DEVICE_MODE_ITCM_START 0x20000
#define DEVICE_MODE_ITCM_LEN 0x18000

#define DEVICE_MODE_STARTUP_LENGTH 0x400
#define DEVICE_MODE_DTCM_START_ADDR         0x20018000
#define DEVICE_MODE_DTCM_LEN         0x18000

#define DEVICE_MODE_ACORE_PRESERVE_LEN 0x100
#define DEVICE_MODE_ACORE_PRESERVE_START_ADDR \
        (DEVICE_MODE_DTCM_START_ADDR + DEVICE_MODE_DTCM_LEN - DEVICE_MODE_ACORE_PRESERVE_LEN)
#endif

