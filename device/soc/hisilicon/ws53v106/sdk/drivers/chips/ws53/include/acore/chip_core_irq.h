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
    AON_PMU_ERR_INT_IRQN        = LOCAL_INTERRUPT0 + 2,
    SGPIO_INT_IRQN              = LOCAL_INTERRUPT0 + 3,
    RESERVED4_IRQN              = LOCAL_INTERRUPT0 + 4,
    RESERVED5_IRQN              = LOCAL_INTERRUPT0 + 5,
    MCU_PCLR_LOCK_IRQN          = LOCAL_INTERRUPT0 + 6,
    GPIO_1_IRQN                 = LOCAL_INTERRUPT0 + 7,
    GPIO_0_IRQN                 = LOCAL_INTERRUPT0 + 8,
    RESERVED9_IRQN              = LOCAL_INTERRUPT0 + 9,
    BT_TOOGLE_POS_INT_IRQN      = LOCAL_INTERRUPT0 + 10,
    BT_TOOGLE_NEG_INT_IRQN      = LOCAL_INTERRUPT0 + 11,
    ULP_WKUP_TP_ACPU_INT_IRQN   = LOCAL_INTERRUPT0 + 12,
    UART_0_IRQN                 = LOCAL_INTERRUPT0 + 13, // UARTH1
    MCU_SIMO1P1_VSET_INT_IRQN   = LOCAL_INTERRUPT0 + 14,
    UART_1_IRQN                 = LOCAL_INTERRUPT0 + 15, // UARTH0
    UART_2_IRQN                 = LOCAL_INTERRUPT0 + 16, // UARTL
    QSPI0_2CS_IRQN              = LOCAL_INTERRUPT0 + 17,
    RESERVED18_IRQN             = LOCAL_INTERRUPT0 + 18,
    RESERVED19_IRQN             = LOCAL_INTERRUPT0 + 19,
    SDIO_IRQN                   = LOCAL_INTERRUPT0 + 20,
    M_WAKEUP_IRQN               = LOCAL_INTERRUPT0 + 21,
    M_SLEEP_IRQN                = LOCAL_INTERRUPT0 + 22,
    RTC_0_IRQN                  = LOCAL_INTERRUPT0 + 23,
    RTC_1_IRQN                  = LOCAL_INTERRUPT0 + 24,
    SEC_RTC_IRQN                = LOCAL_INTERRUPT0 + 25,
    RESERVED26_IRQN             = LOCAL_INTERRUPT0 + 26,
    TIMER_0_IRQN                = LOCAL_INTERRUPT0 + 27,
    TIMER_1_IRQN                = LOCAL_INTERRUPT0 + 28,
    RESERVED29_IRQN             = LOCAL_INTERRUPT0 + 29,
    SDIO_INTR0_FROM_CSUB_IRQN   = LOCAL_INTERRUPT0 + 30,
    SDIO_INTR1_FROM_CSUB_IRQN   = LOCAL_INTERRUPT0 + 31,
    M_DMA_IRQN                  = LOCAL_INTERRUPT0 + 32,
    SEC_INT1_IRQN               = LOCAL_INTERRUPT0 + 33,
    SEC_INT2_IRQN               = LOCAL_INTERRUPT0 + 34,
    SEC_INT3_IRQN               = LOCAL_INTERRUPT0 + 35,
    I2C_0_IRQN                  = LOCAL_INTERRUPT0 + 36,
    I2C_1_IRQN                  = LOCAL_INTERRUPT0 + 37,
    RESERVED38_IRQN             = LOCAL_INTERRUPT0 + 38,
    SPI_3_IRQN                  = LOCAL_INTERRUPT0 + 39,
    RESERVED40_IRQN             = LOCAL_INTERRUPT0 + 40,
    I2S_IRQN                    = LOCAL_INTERRUPT0 + 41,
    RESERVED42_IRQN             = LOCAL_INTERRUPT0 + 42,
    RESERVED43_IRQN             = LOCAL_INTERRUPT0 + 43,
    SEC_INT_IRQN                = LOCAL_INTERRUPT0 + 44,
    PWM_ABNOR_IRQN              = LOCAL_INTERRUPT0 + 45,
    PWM_CFG_IRQN                = LOCAL_INTERRUPT0 + 46,
    SPWM_ABNOR_IRQN             = LOCAL_INTERRUPT0 + 47,
    SPWM_CFG_IRQN               = LOCAL_INTERRUPT0 + 48,
    SOFT_INT0_IRQN              = LOCAL_INTERRUPT0 + 49,
    SOFT_INT1_IRQN              = LOCAL_INTERRUPT0 + 50,
    MCU_SIMO0P9_VSET_INT_IRQN   = LOCAL_INTERRUPT0 + 51,
    PMU_CMU_ERR_IRQN            = LOCAL_INTERRUPT0 + 52,
    RESERVED53_IRQN             = LOCAL_INTERRUPT0 + 53,
    LSADC_IRQN                  = LOCAL_INTERRUPT0 + 54,
    RESERVED55_IRQN             = LOCAL_INTERRUPT0 + 55,
    B_SUB_MONITOR_INT_IRQN      = LOCAL_INTERRUPT0 + 56,
    RESERVED57_IRQN             = LOCAL_INTERRUPT0 + 57,
    E2H_BRG_IRQN                = LOCAL_INTERRUPT0 + 58,
    CLK_32K_DET_DONE_STS_IRQN   = LOCAL_INTERRUPT0 + 59,
    B_WDT_IRQN                  = LOCAL_INTERRUPT0 + 60,
    TSENSOR_IRQN                = LOCAL_INTERRUPT0 + 61,
    RESERVED62_IRQN             = LOCAL_INTERRUPT0 + 62,
    RESERVED63_IRQN             = LOCAL_INTERRUPT0 + 63,
    BUTT_IRQN
} core_irq_t;

#endif
