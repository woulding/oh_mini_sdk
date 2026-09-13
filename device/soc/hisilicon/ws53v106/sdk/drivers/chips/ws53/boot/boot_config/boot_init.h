/*
 * Copyright (c) HiSilicon (Shanghai) Technologies Co., Ltd. 2021-2021. All rights reserved.
 * Description: Common Boot for Standard Application Core
 *
 * Create: 2021-03-09
 */

#ifndef _BOOT_INIT_H_
#define _BOOT_INIT_H_
#include <stdint.h>
#include "memory_config.h"

#ifdef BOARD_FPGA
#define START_FROM_FLASH 0
#else
#define START_FROM_FLASH 1
#endif

#define FLASH_HEAD_ADDR             0x00400000
#define FLASH_MEM_SIZE_ROM          0x80000  /* rom default 512kb */
#define FLASH_MEM_SIZE              0x00400000

#define UART_ROMBOOT_INT_TIMEOUT_64MS       64
#define UART_ROMBOOT_INT_TIMEOUT_32MS       32
#define UART_ROMBOOT_INT_TIMEOUT_16MS       16
#define UART_ROMBOOT_INT_TIMEOUT_4MS        4
#define UART_ROMBOOT_INT_TIMEOUT_NUM        4

#define ATE_RAM_CODE_ADDR                   0x40000

#define KERNEL_START_ADDR           0x00600000

#define BOOT_HEAD_ADDR              0x00108000

#define LOAD_BOOT_ADDR              0x20000

#define RESET_COUNT_REG             0x57030014
#ifdef CONFIG_LOADERBOOT
#define BOOT_PORTING_RESET_REG      0x57030980
#else
#define BOOT_PORTING_RESET_REG      0x57004600
#endif
#define BOOT_PORTING_RESET_VALUE    0

#define STATUS_DEBUG_REG_ADDR       0x52000010

#define HIBURN_CODELOADER_UART              UART_BUS_1
#define HIBURN_UART_TX                      CHIP_FIXED_TX_PIN
#define HIBURN_UART_RX                      CHIP_FIXED_RX_PIN
#define UART_ROMBOOT_INT_TIMEOUT_DEFAULT    32

#define FLASHBOOT_MAX_SIZE          0x8000
#define SRAM_START_ADDR             0x80000000  /* SRAM 起始地址 */
#define LOADY_MAX_LENGTH            0x10000
#define LOADY_MAX_ADDR              (SRAM_START_ADDR + LOADY_MAX_LENGTH)   /* loady 命令可存储的最大地址(不包括该地址) */

#define RAM_MIN_ADDR                BOOT_RAM_MIN  /* SRAM 可设置的最小起始地址 */
#define RAM_MAX_ADDR                BOOT_RAM_MAX

#define LOAD_MAX_RAM_ADDR           (RAM_MAX_ADDR - 0x40)
#define LOAD_MIN_SIZE               0x0      /* 0x40(sha256 header len) + 0x20(hash len) + 0x10(tail len) */
#define LOAD_MAX_SIZE               0x1000000   /* 16M */

#define RESET_DELAY_MS              100

#define REPET_TIMES_2               2
#define REPET_TIMES_3               3
#define REBOOT_MAX_CNT              15
#define BOOT_STEP                   13

typedef union {
    struct {
        uint16_t fota_fix_app_cnt  : 4;     /* fota修复app计数使用 */
        uint16_t reset_cnt         : 4;     /* boot阶段软复位次数记录 */
        uint16_t resv              : 8;
    } bits;

    uint16_t  u16;
} gp_reg1_union;

#endif
