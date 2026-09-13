/*
 * Copyright (c) HiSilicon (Shanghai) Technologies Co., Ltd. 2024-2024. All rights reserved.
 * Description: rf power recover
 *
 * Create: 2024-01-02
 */
#ifdef BOARD_ASIC
#include "chip_io.h"
#include "soc_osal.h"
#include "soc_errno.h"
#include "tcxo.h"
#include "hcc_cfg.h"
#if defined(__LITEOS__)
#include "los_task_pri.h"
#elif defined(__FREERTOS__)
#include "FreeRTOS.h"
#include "hwi.h"
#include "cache.h"
#endif
#include "clock_recover.h"

#define MCU_CORE_CR_CH1 0x5200057C
#define MCU_CORE_CR_CH0 0x52000578

#define USE_CHANNEL0    1
#define CLK_SEL         0x4
#define DIV_NUM         0x2

static void switch_ch_clock(bool pll, uint32_t ch_addr)
{
    reg_clrbit(ch_addr, 0, POS_4);
    reg_clrbit(ch_addr, 0, POS_0);

    if (pll == true) {
        reg16_setbits(ch_addr, POS_1, DATA_WIDTH_3, CLK_SEL);
        reg16_setbits(ch_addr, POS_5, DATA_WIDTH_4, DIV_NUM);
        cpu32m_udelay(DELAY_1_US);
        reg_setbit(ch_addr, 0, POS_4);
        reg_setbit(ch_addr, 0, POS_0);
        cpu32m_udelay(DELAY_1_US);
    } else {
        reg_clrbits(ch_addr, 0, POS_1, DATA_WIDTH_3);
        reg_clrbits(ch_addr, 0, POS_5, DATA_WIDTH_4);
        uapi_tcxo_delay_us(DELAY_1_US);
        reg_clrbit(ch_addr, 0, POS_4);
        reg_setbit(ch_addr, 0, POS_0);
        uapi_tcxo_delay_us(DELAY_1_US);
    }
}

static void switch_clock_from_ch0_to_ch1(bool pll)
{
    switch_ch_clock(pll, MCU_CORE_CR_CH1);
    reg_setbit(MSUB_NOR_CFG, 0, POS_6);
    reg_setbit(MSUB_SLP_CFG, 0, POS_6);
}

static void switch_clock_from_ch1_to_ch0(bool pll)
{
    switch_ch_clock(pll, MCU_CORE_CR_CH0);
    reg_clrbit(MSUB_NOR_CFG, 0, POS_6);
    reg_clrbit(MSUB_SLP_CFG, 0, POS_6);
}

static void acore_switch_pll_clock(bool pll)
{
    if (reg16_getbits(MCU_CORE_CR_CH1, POS_12, DATA_WIDTH_2) == USE_CHANNEL0) {
        switch_clock_from_ch0_to_ch1(pll);
    } else {
        switch_clock_from_ch1_to_ch0(pll);
    }
}

uint32_t system_switch_pll_clock(void)
{
    bool ret;

    while (readl(SEM1_STS_REG) != 0) {}
    ret = fnpll_init();
    acore_switch_pll_clock(true);
    cpu32m_udelay(DELAY_1_US);   // 1us delay
    if (ret) {
        sfc_switch_clock(true);
    }

    writel(SEM1_STS_REG, 0x1);
    return ret;
}

void system_set_pll_clock_flag(uint8_t close)
{
    if (close == true) {
        reg_setbit(ULP_PM_PLAT_ENABLE_REG, 0, PM_PLAT_FREQ_MODE_MASK);
    } else {
        reg_clrbit(ULP_PM_PLAT_ENABLE_REG, 0, PM_PLAT_FREQ_MODE_MASK);
    }
}

static void ccore_switch_xo_clock(void)
{
    reg_clrbit(MSUB_NOR_CFG, 0, POS_7);
    reg_clrbit(MSUB_SLP_CFG, 0, POS_7);
}

static void fnpll_close(void)
{
    reg32_clrbit(CMU_CLK_320M_WDBB, POS_1);
    reg32_clrbit(CMU_CLK_480M_WDBB, POS_1);
    reg32_clrbit(CMU_CLK_FLASH, POS_1);

    reg32_setbit(CMU_FNPLL_SIG, POS_15);
    reg32_setbit(CMU_LDO_PD, POS_0);
}

static void system_switch_freq(uint8_t switch_freq)
{
    if (switch_freq == FREQ_SWITCH_PLL) {
        /* 开PLL和A核/flash切高频 */
        system_switch_pll_clock();
        /* C核切高频 */
        ccore_switch_pll_clock();
        /* 设置状态用于低功耗切换 */
        system_set_pll_clock_flag(false);
    } else {
        /* flash切XO */
        sfc_switch_clock(false);
        /* A核通道切XO */
        acore_switch_pll_clock(false);
        uapi_tcxo_delay_us(DELAY_10_US);
        /* C核切XO */
        ccore_switch_xo_clock();
        uapi_tcxo_delay_us(DELAY_10_US);
        /* 关PLL时钟 */
        fnpll_close();
        /* 设置状态用于低功耗切换 */
        system_set_pll_clock_flag(true);
    }
}

uint32_t system_request_switch(uint8_t type, uint8_t *param)
{
    uint32_t irq_sts;
    uint64_t cur_us;
    uint64_t end_us;
    uint32_t b_lock_sts;
    bool lock_switch = true;

    irq_sts = osal_irq_lock();
    /* A核设开始状态 */
    reg32_setbit(M_SLP_STS, CORE_LOCK_BIT_MASK);
    cur_us = uapi_tcxo_get_us();
    end_us = cur_us + CLOCK_SWITCH_MAX_WAIT_TIME_US;
    /* 确认C核是否开始等待 */
    b_lock_sts = reg32_getbit(B_SLP_STS, CORE_LOCK_BIT_MASK);
    while (b_lock_sts == 0) {
        b_lock_sts = reg32_getbit(B_SLP_STS, CORE_LOCK_BIT_MASK);
        cur_us = uapi_tcxo_get_us();
        if (cur_us > end_us) {
            lock_switch = false;
            break;
        }
    }
    /* 切换 */
    if (lock_switch == true) {
        if (type == H2D_MSG_SWITCH_UDSLEEP) {
            pm_port_enter_udsleep();
        } else {
            cpu_cache_reset(); // clean cache before sfc switch freq
            system_switch_freq(param[0]);
        }
    }

    /* A核完成清理状态 */
    reg32_clrbit(M_SLP_STS, CORE_LOCK_BIT_MASK);
    osal_irq_restore(irq_sts);

    return lock_switch ? EXT_ERR_SUCCESS : EXT_ERR_FAILURE;
}

static uint32_t g_m_cken_0 = 0;
static uint32_t g_m_cken_1 = 0;
static uint32_t g_m_cken_2 = 0;
static uint32_t g_m_xip_clken0 = 0;
static uint32_t g_m_mcu_perp_spi_cr = 0;
static uint32_t g_m_xip_qspi_cr = 0;
static uint32_t g_m_pwm_m_div3 = 0;

void acore_suspend_ctl_rb(void)
{
    g_m_cken_0 = readl(M_CTL_RB_M_CLKEN0);
    g_m_cken_1 = readl(M_CTL_RB_M_CLKEN1);
    g_m_cken_2 = readl(M_CTL_RB_M_CLKEN2);
    g_m_xip_clken0 = readl(M_CTL_RB_XIP_CLKEN0);
    g_m_mcu_perp_spi_cr = readl(M_CTL_RB_MCU_PERP_SPI_CR);
    g_m_xip_qspi_cr = readl(M_CTL_RB_XIP_QSPI_CR);
    g_m_pwm_m_div3 = readl(M_CTL_RB_PWM_M_DIV3);
}

void acore_resume_ctl_rb(void)
{
    if (g_m_cken_0 != 0) {
        writel(M_CTL_RB_M_CLKEN0, g_m_cken_0);
    }
    if (g_m_cken_1 != 0) {
        writel(M_CTL_RB_M_CLKEN1, g_m_cken_1);
    }
    if (g_m_cken_2 != 0) {
        writel(M_CTL_RB_M_CLKEN2, g_m_cken_2);
    }
    if (g_m_xip_clken0 != 0) {
        writel(M_CTL_RB_XIP_CLKEN0, g_m_xip_clken0);
    }
    if (g_m_mcu_perp_spi_cr != 0) {
        writel(M_CTL_RB_MCU_PERP_SPI_CR, g_m_mcu_perp_spi_cr);
    }
    if (g_m_xip_qspi_cr != 0) {
        writel(M_CTL_RB_XIP_QSPI_CR, g_m_xip_qspi_cr);
    }
    if (g_m_pwm_m_div3 != 0) {
        writel(M_CTL_RB_PWM_M_DIV3, g_m_pwm_m_div3);
    }
}

void system_close_peripheral_crg(void)
{
    writel(M_CTL_RB_COM_DLL2, 0);
    system_crg_cfg();
}

void cpu_cache_reset(void)
{
    ArchICacheFlush();
    ArchDCacheInvalidate();
    ArchICacheEnable(CACHE_32KB);
    ArchICachePrefetchEnable(CACHE_PREF_4_LINES);
    ArchDCacheEnable(CACHE_4KB);
    return;
}
#endif

