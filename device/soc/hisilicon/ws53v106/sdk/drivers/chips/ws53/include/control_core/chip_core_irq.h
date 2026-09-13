/*
 * Copyright (c) HiSilicon (Shanghai) Technologies Co., Ltd. 2021-2021. All rights reserved.
 * Description:   Chip core irq >= 0 define.
 *
 * Create:  2021-06-16
 */

#ifndef CHIP_CORE_IRQ_H
#define CHIP_CORE_IRQ_H

#define LOCAL_INTERRUPT0 26

typedef enum core_irq {
/* -------------------  Processor Interrupt Numbers  ------------------------------ */
    BT_INT0_IRQN                = LOCAL_INTERRUPT0 + 0,
    BT_INT1_IRQN                = LOCAL_INTERRUPT0 + 1,
    RTC_0_IRQN                  = LOCAL_INTERRUPT0 + 2,
    RTC_1_IRQN                  = LOCAL_INTERRUPT0 + 3,
    RESERVED4_IRQN              = LOCAL_INTERRUPT0 + 4,
    RESERVED5_IRQN              = LOCAL_INTERRUPT0 + 5,
    TIMER_0_IRQN                = LOCAL_INTERRUPT0 + 6,
    TIMER_1_IRQN                = LOCAL_INTERRUPT0 + 7,
    TIMER_2_IRQN                = LOCAL_INTERRUPT0 + 8,
    RESERVED9_IRQN              = LOCAL_INTERRUPT0 + 9,
    SFC_INT_IRQN                = LOCAL_INTERRUPT0 + 10,
    GPIO_0_IRQN                 = LOCAL_INTERRUPT0 + 11,
    GPIO_1_IRQN                 = LOCAL_INTERRUPT0 + 12,
    BCPU_PCLR_OK_INT_IRQN       = LOCAL_INTERRUPT0 + 13,
    UART_2_IRQN                 = LOCAL_INTERRUPT0 + 14, // UART_L1
    UART_1_IRQN                 = LOCAL_INTERRUPT0 + 15, // RESERVED15_IRQN
    UART_0_IRQN                 = LOCAL_INTERRUPT0 + 16, // RESERVED16_IRQN
    C_AON_WKUP_IRQN             = LOCAL_INTERRUPT0 + 17,
    RESERVED18_IRQN             = LOCAL_INTERRUPT0 + 18,
    OSC_EN_WKUP_IRQN            = LOCAL_INTERRUPT0 + 19,
    OSC_EN_SLEEP_IRQN           = LOCAL_INTERRUPT0 + 20,
    C_WAKEUP_IRQN               = LOCAL_INTERRUPT0 + 21,
    C_SLEEP_IRQN                = LOCAL_INTERRUPT0 + 22,
    AHB_MONITOR_INT0_IRQN       = LOCAL_INTERRUPT0 + 23,
    AHB_MONITOR_INT1_IRQN       = LOCAL_INTERRUPT0 + 24,
    CLK_32K_DET_DONE_INT_IRQN   = LOCAL_INTERRUPT0 + 25,
    C_DIAG_INT_IRQN             = LOCAL_INTERRUPT0 + 26,
    BT_BB_BLE_IRQN              = LOCAL_INTERRUPT0 + 27,
    BT_BB_GLE_IRQN              = LOCAL_INTERRUPT0 + 28,
    TSENSOR_IRQN                = LOCAL_INTERRUPT0 + 29,
    CSUB_SIMO09P_VSET_IRQN      = LOCAL_INTERRUPT0 + 30,
    CSUB_SIMO1P_VSET_IRQN       = LOCAL_INTERRUPT0 + 31,
    WLMAC_IRQ_IRQN              = LOCAL_INTERRUPT0 + 32,
    WLPHY_IRQ_IRQN              = LOCAL_INTERRUPT0 + 33,
    RESERVED34_IRQN             = LOCAL_INTERRUPT0 + 34,
    RESERVED35_IRQN             = LOCAL_INTERRUPT0 + 35,
    RESERVED36_IRQN             = LOCAL_INTERRUPT0 + 36,
    RESERVED37_IRQN             = LOCAL_INTERRUPT0 + 37,
    CACHE_COMBIN_INT_IRQN       = LOCAL_INTERRUPT0 + 38,
    RESERVED39_IRQN             = LOCAL_INTERRUPT0 + 39,
    MAC_MONITOR_INT_IRQN        = LOCAL_INTERRUPT0 + 40,
    MEMORY_LOAD_STORE_INT_IRQN  = LOCAL_INTERRUPT0 + 41,
    COEX_WL_INT                 = LOCAL_INTERRUPT0 + 42,
    COEX_BT_INT                 = LOCAL_INTERRUPT0 + 43,
    COEX_WL_RESUME_INT_IRQN     = LOCAL_INTERRUPT0 + 44,
    RESERVED45_IRQN             = LOCAL_INTERRUPT0 + 45,
    RESERVED46_IRQN             = LOCAL_INTERRUPT0 + 46,
    RESERVED47_IRQN             = LOCAL_INTERRUPT0 + 47,
    RESERVED48_IRQN             = LOCAL_INTERRUPT0 + 48,
    SOFT_INT1_IRQN              = LOCAL_INTERRUPT0 + 49,
    SOFT_INT2_IRQN              = LOCAL_INTERRUPT0 + 50,
    SOFT_INT3_IRQN              = LOCAL_INTERRUPT0 + 51,
    SOFT_INT4_IRQN              = LOCAL_INTERRUPT0 + 52,

    BUTT_IRQN
} core_irq_t;

#endif
