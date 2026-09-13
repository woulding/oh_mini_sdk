/*
 * Copyright (c) HiSilicon (Shanghai) Technologies Co., Ltd. 2024-2024. All rights reserved.
 * Description: clock recover
 *
 * Create: 2024-01-02
 */
#ifdef BOARD_ASIC
#include "chip_io.h"
#include "arch_barrier.h"
#include "clock_recover.h"

#define XIP_SFC_CR                              0x52000570

#define CHIP_AUTO_CG_CFG_1                      0x570003F0
#define CHIP_AUTO_CG_CFG_2                      0x570003F4
#define M_CTL_RB_DAP_H2P_AUTOCG_BYPASS_REG      0x52000190
#define M_CTL_RB_COM_BUS_LP_CFG_REG             0x52000400
#define M_CTL_RB_DMA_AUTO_CG_CFG_REG            0x52001100
#define M_CTL_RB_UART_AUTO_CG_CFG_REG           0x52001104
#define M_CTL_RB_SPI_AUTO_CG_CFG_REG            0x52001108
#define M_CTL_RB_SPI_SSI_CLK_AUTO_CG_CFG_REG    0x5200110C
#define M_CTL_RB_PWM_AUTO_CG_CFG_REG            0x52001110
#define M_CTL_RB_SEC_AUTO_CG_CFG_REG            0x52001114
#define M_CTL_RB_SDIO_AUTO_CG_CFG_REG           0x52001118
#define M_CTL_RB_SPACC_COM_AUTO_CG_CFG_REG      0x5200111C

#define ULPPLL_LOCK_STS                         0x5700434C
#define LOCK_GRM_TIME                           0x57004378

#define XO_REG_H                                0x57008420
#define XO_REG_L                                0x57008424

#define LOCK_GRM_TIME_CFG       0x3
#define PLL_MAX_RETRY_TIMES     10
#define MAX_CHECK_LOCK_TIMES    250

#define FAMA_REMAP_SRC_BASE_ADDR                0x5208F800
#define FAMA_REMAP_LEN_BASE_ADDR                0x5208F820
#define FAMA_REMAP_DST_BASE_ADDR                0x5208F840
#define FAMA_REMAP_REGION_OFFSET                0x4
#define FAMA_REMAP_REGION_USED_NUM              2

static uint32_t g_fama_remap_src[FAMA_REMAP_REGION_USED_NUM] = {0};
static uint32_t g_fama_remap_len[FAMA_REMAP_REGION_USED_NUM] = {0};
static uint32_t g_fama_remap_dst[FAMA_REMAP_REGION_USED_NUM] = {0};

fnpll_delay_func g_fnpll_delay_func = NULL;
void cpu32m_udelay(uint32_t us_cnt)
{
    uint32_t loop_cnt = us_cnt * 0x7;    // 1us
    for (uint32_t i = 0; i < loop_cnt; i++) {
        nop();
    }
}

void system_pll_register_delay_func(fnpll_delay_func func)
{
    g_fnpll_delay_func = func;
}

static uint32_t fnpll_lock_check(void)
{
    uint32_t islocked = 0;
    for (uint32_t  retry_times = 0; retry_times < PLL_MAX_RETRY_TIMES; retry_times++) {
        if (g_fnpll_delay_func == NULL) {
            cpu32m_udelay(DELAY_130_US); // 实测需要180us等待，后续有最大250次查询可以满足要求
        } else {
            g_fnpll_delay_func();
        }
        for (uint32_t  lock_check_times = 0; lock_check_times < MAX_CHECK_LOCK_TIMES; lock_check_times++) {
            islocked = (reg16_getbits(ULPPLL_LOCK_STS, 0, 1) == 1) ? (islocked + 1) : 0;
            if (islocked == CONTUINUE_LOCKED_TIMES) {
                break;
            }
            cpu32m_udelay(DELAY_1_US);
        }
        if (islocked == CONTUINUE_LOCKED_TIMES) {
            break;
        }
    }
    return islocked;
}

bool fnpll_init(void)
{
    /* PLL已经锁定 */
    if ((reg_getbits(CMU_FNPLL_SIG, 0, POS_15, 1) == 0x0) &&
        (reg_getbits(ULPPLL_LOCK_STS, 0, POS_0, 1) == 0x1)) {
        return false;
    }

    writel(LOCK_GRM_TIME, LOCK_GRM_TIME_CFG);
    reg16_setbits(0x57031004, POS_4, DATA_WIDTH_3, 0x5);
    writel(0x5703103c, 0x08);
    writel(CMU_FNPLL_SIG, 0xe080);
    writel(CMU_LDO_PD, 0x3);
    writel(CMU_LDO1_CFG, 0x5000);
    writel(CMU_LDO2_CFG, 0x5000);
    writel(CMU_FNPLL_CFG0_H, 0x2843);
    writel(CMU_CLK_320M_WDBB, 0x2);
    writel(CMU_CLK_480M_WDBB, 0x6);
    writel(CMU_CLK_FLASH, 0x2);
    reg_setbit(XO_REG_H, 0, POS_11);
    reg_setbit(XO_CLK_OUT_EN, 0, POS_4);
    reg_setbit(XO_REG_L, 0, POS_13);
    reg_setbit(XO_REG_H, 0, POS_0);
    dsb();

    writel(CMU_LDO_PD, 0x0);
    cpu32m_udelay(DELAY_50_US);

    writel(CMU_FNPLL_SIG, 0x6080);
    cpu32m_udelay(DELAY_10_US);

    writel(CMU_LDO1_CFG, 0x1000);
    writel(CMU_LDO2_CFG, 0x1000);
    if (fnpll_lock_check() == CONTUINUE_LOCKED_TIMES) {
        return true;
    } else {
        return false;
    }
}

void ccore_switch_pll_clock(void)
{
    reg_clrbit(MSUB_NOR_CFG, 0, POS_7);
    reg_clrbit(MSUB_SLP_CFG, 0, POS_7);
    // 将ccore工作时钟切到120M
    writel(COM_BUS_CR_CH1, 0);
    cpu32m_udelay(DELAY_1_US);   // 1us delay
    writel(COM_BUS_CR_CH1, 0x59);
    cpu32m_udelay(DELAY_1_US);   // 1us delay
    reg_setbit(MSUB_NOR_CFG, 0, POS_7);
    reg_setbit(MSUB_SLP_CFG, 0, POS_7);
}

void sfc_switch_clock(bool pll)
{
    reg_clrbit(XIP_SFC_CR, 0, POS_0);
    if (pll == true) {
        reg16_setbits(XIP_SFC_CR, POS_1, DATA_WIDTH_3, 0x6);
    } else {
        reg16_clrbits(XIP_SFC_CR, POS_1, DATA_WIDTH_3);
    }
    cpu32m_udelay(DELAY_1_US);   // 1us delay
    reg_setbit(XIP_SFC_CR, 0, POS_0);
    if (readl(XIP_SFC_CR) != 0) {} // read sfc clock, ensure clock takes effect
}

void system_crg_cfg(void)
{
    /* 开启cbus_h2p_apb_pclk_en时钟和相关auto cg */
    writel(CHIP_AUTO_CG_CFG_1, 0x40);
    /* 开启mbus_apb_pclk_en和相关auto cg */
    writel(CHIP_AUTO_CG_CFG_2, 0xA00);
    /* 开启dap桥auto_cg */
    writel(M_CTL_RB_DAP_H2P_AUTOCG_BYPASS_REG, 0x0);
    /* 开启XIP EH2H橋的auto cg */
    writel(M_CTL_RB_COM_BUS_LP_CFG_REG, 0x0);
    /* 开启dma auto_cg */
    writel(M_CTL_RB_DMA_AUTO_CG_CFG_REG, 0x0);
    /* 开启uart auto_cg */
    writel(M_CTL_RB_UART_AUTO_CG_CFG_REG, 0x0);
    /* 开启SPI auto_cg */
    writel(M_CTL_RB_SPI_AUTO_CG_CFG_REG, 0x0);
    /* 开启SPI3 auto_cg */
    writel(M_CTL_RB_SPI_SSI_CLK_AUTO_CG_CFG_REG, 0x0);
    /* 开启PWM和SPWM auto_cg */
    writel(M_CTL_RB_PWM_AUTO_CG_CFG_REG, 0x0);
    /* 开启SEC_SUB内SPACC和PKE2CLDO auto_cg */
    writel(M_CTL_RB_SEC_AUTO_CG_CFG_REG, 0x0);
    /* 开启SDIO ICM2X1 auto_cg */
    writel(M_CTL_RB_SDIO_AUTO_CG_CFG_REG, 0x0);
    /* 开启SEC_SUB&COM_SUB ICM2X1 auto_cg */
    writel(M_CTL_RB_SPACC_COM_AUTO_CG_CFG_REG, 0x0);
}

// 保存AB面升级地址映射配置
static void dmmu_remap_reg_save(void)
{
    for (uint8_t i = 0; i < FAMA_REMAP_REGION_USED_NUM; i++) {
        g_fama_remap_src[i] = readl(FAMA_REMAP_SRC_BASE_ADDR + i * FAMA_REMAP_REGION_OFFSET);
        g_fama_remap_len[i] = readl(FAMA_REMAP_LEN_BASE_ADDR + i * FAMA_REMAP_REGION_OFFSET);
        g_fama_remap_dst[i] = readl(FAMA_REMAP_DST_BASE_ADDR + i * FAMA_REMAP_REGION_OFFSET);
    }
}

void dmmu_remap_reg_restore(void)
{
    for (uint8_t i = 0; i < FAMA_REMAP_REGION_USED_NUM; i++) {
        writel(FAMA_REMAP_SRC_BASE_ADDR + i * FAMA_REMAP_REGION_OFFSET, g_fama_remap_src[i]);
        writel(FAMA_REMAP_LEN_BASE_ADDR + i * FAMA_REMAP_REGION_OFFSET, g_fama_remap_len[i]);
        writel(FAMA_REMAP_DST_BASE_ADDR + i * FAMA_REMAP_REGION_OFFSET, g_fama_remap_dst[i]);
    }
}

void pm_gpio_cfg_suspend(clock_switch_core core_t)
{
    while (readl(SEM2_STS_REG) != 0) {}
    dmmu_remap_reg_save();
    reg32_setbit(GPIO_CFG_STS, core_t);
    if (readl(GPIO_CFG_STS) != 0x3) {
        writel(SEM2_STS_REG, 0x1);
        return;
    }

    reg_clrbit(EFUSE_ULP_SEL1, 0, POS_7); // 下电前CMU_XLDO_VOUT_CTRL_sel使用efuse配置
    writel(ULP_GPIO_CLK_CFG, 0x3); // GPIO切32K时钟
    writel(SEM2_STS_REG, 0x1);
}

uint8_t pm_peripheral_resume(clock_switch_core core_t)
{
    while (readl(SEM2_STS_REG) != 0) {}
    if (readl(GPIO_CFG_STS) != 0x3) {
        reg32_clrbit(GPIO_CFG_STS, core_t);
        writel(SEM2_STS_REG, 0x1);
        return false;
    }

    writel(ULP_GPIO_CLK_CFG, 0x1); // GPIO切PLL时钟
    reg32_clrbit(GPIO_CFG_STS, core_t);
    system_close_peripheral_crg();

    writel(SEM2_STS_REG, 0x1);
    return true;
}

uint8_t system_get_pll_clock_flag(void)
{
    return reg32_getbit(ULP_PM_PLAT_ENABLE_REG, PM_PLAT_FREQ_MODE_MASK);
}

uint8_t system_get_udsleep_flag(void)
{
    return reg32_getbit(ULP_PM_PLAT_ENABLE_REG, PM_PLAT_UDSLEEP_MASK);
}
#endif
