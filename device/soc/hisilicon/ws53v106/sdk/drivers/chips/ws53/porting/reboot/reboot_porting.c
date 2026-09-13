/**
 * Copyright (c) HiSilicon (Shanghai) Technologies Co., Ltd. 2022-2022. All rights reserved.
 *
 * Description: Provides pwm port \n
 *
 * History: \n
 * 2022-09-16， Create file. \n
 */
#include "arch_barrier.h"
#include "tcxo.h"
#include "chip_io.h"
#include "platform_core.h"
#include "osal_interrupt.h"
#include "securec.h"
#include "hal_reboot.h"
#include "exception.h"
#include "debug_print.h"
#include "sfc.h"
#ifdef CONFIG_SUPPORT_RST_RSN_SAVE_TO_FLASH
#include "osal_addr.h"
#endif
#include "clock_recover.h"
#include "reboot_porting.h"

#define HH503_MAC_WL0_EXT_TSF_CTRL_BASE         (0x57034000)
#define HH503_MAC_WL0_EXT_TSF_CTRL              (HH503_MAC_WL0_EXT_TSF_CTRL_BASE + 0x0)
#define ULP_AON_BT_OSC_EN_INT_CLR               (ULP_AON_CTL_RB_ADDR + 0x280)
#define ULP_AON_BT_OSC_EN_INT_EN                (ULP_AON_CTL_RB_ADDR + 0x284)
#define ULP_AON_CTL_ULP_WKUP_EVT_EN             (ULP_AON_CTL_RB_ADDR + 0x310)
#define ULP_AON_CTL_ULP_WKUP_EVT_CLR            (ULP_AON_CTL_RB_ADDR + 0x30C)
#define ULP_AON_CTL_ULP_WKUP_INT_EN             (ULP_AON_CTL_RB_ADDR + 0x314)
#define ULP_AON_CTL_ULP_WKUP_INT_CLR            (ULP_AON_CTL_RB_ADDR + 0x304)

#define ULP_AON_CTL_ULP_SLP_EVT_CLR_REG         (ULP_AON_CTL_RB_ADDR + 0x1CC)
#define ULP_AON_CTL_SYS_TICK_CFG_M              (ULP_AON_CTL_RB_ADDR + 0x330)
#define ULP_AON_CTL_TGLP_RESET_REG              (ULP_AON_CTL_RB_ADDR + 0x6F0)
#define ULP_AON_CTL_MCPU_POR_RST_PC_H_REG       (ULP_AON_CTL_RB_ADDR + 0x820)
#define ULP_AON_CTL_MCPU_POR_RST_PC_L_REG       (ULP_AON_CTL_RB_ADDR + 0x824)
#define ULP_AON_CTL_CCPU_SOFT_RST_REG           (ULP_AON_CTL_RB_ADDR + 0x96C)
#define PMU1_CTL_SYS_SOFT_RST_REG               (PMU1_CTL_RB_BASE + 0x600)
#define SEM0_FORCE_CLR                          (ULP_AON_CTL_RB_ADDR + 0x01204)
#define SEM1_FORCE_CLR                          (ULP_AON_CTL_RB_ADDR + 0x0120C)
#define SEM2_FORCE_CLR                          (ULP_AON_CTL_RB_ADDR + 0x01214)
#define SEM3_FORCE_CLR                          (ULP_AON_CTL_RB_ADDR + 0x0121C)
#define SEM4_FORCE_CLR                          (ULP_AON_CTL_RB_ADDR + 0x01224)
#define SEM5_FORCE_CLR                          (ULP_AON_CTL_RB_ADDR + 0x0122C)
#define SEM6_FORCE_CLR                          (ULP_AON_CTL_RB_ADDR + 0x01234)
#define SEM7_FORCE_CLR                          (ULP_AON_CTL_RB_ADDR + 0x0123C)
#define ULP_AON_GP_REG0                         (ULP_AON_CTL_RB_ADDR + 0x010)
#define ULP_AON_GP_REG00                        (ULP_AON_CTL_RB_ADDR + 0x5E4)
#define ULP_AON_GP_REG4                         (ULP_AON_CTL_RB_ADDR + 0x700)
#define ULP_AON_GP_REG11                        (ULP_AON_CTL_RB_ADDR + 0x71c)
#define ULP_RST_HISTORY                         (ULP_AON_CTL_RB_ADDR + 0x520)
#define ULP_RST_TIMES                           (ULP_AON_CTL_RB_ADDR + 0x524)
#define BRAM_SHARE_COM_REG                      (ULP_AON_CTL_RB_ADDR + 0x234)
#define BRAM_SHARE_MODE_SIZE                     4
#define ULP_AON_GP_REG_WIDTH                     4
#define ULP_AON_GP_REG0_SIZE                     4
#define ULP_AON_GP_REG00_SIZE                    9
#define ULP_AON_GP_REG4_SIZE                     6
#define ULP_AON_GP_REG11_SIZE                    5
#define DELAY_100_US                             100
#define ULP_PIN_RST_OFFSET                       5
#define ULP_WDT_RST_OFFSET                       4
#define ULP_WDT_RST_CNT_OFFSET                   8
#define SYS_WDT_RST_HIS                          0x10
#define SYS_PIN_RST_HIS                          0x20

#ifdef CONFIG_SUPPORT_RST_RSN_SAVE_TO_FLASH
static uint32_t g_reset_rsn_flag = NON_SOFTWARE_REBOOT;
static uint32_t g_reset_rsn = 0xFF;
#endif
static uint32_t g_reset_rsn_no_flash = 0xFF;

static void reboot_port_aon_resource_clr(void)
{
    /* 通用寄存器清零 */
    memset_s((void *)ULP_AON_GP_REG0, ULP_AON_GP_REG_WIDTH * ULP_AON_GP_REG0_SIZE, 0,
        ULP_AON_GP_REG_WIDTH * ULP_AON_GP_REG0_SIZE);
    memset_s((void *)ULP_AON_GP_REG00, ULP_AON_GP_REG_WIDTH * ULP_AON_GP_REG00_SIZE, 0,
        ULP_AON_GP_REG_WIDTH * ULP_AON_GP_REG00_SIZE);
    memset_s((void *)ULP_AON_GP_REG4, ULP_AON_GP_REG_WIDTH * ULP_AON_GP_REG4_SIZE, 0,
        ULP_AON_GP_REG_WIDTH * ULP_AON_GP_REG4_SIZE);
    memset_s((void *)ULP_AON_GP_REG11, ULP_AON_GP_REG_WIDTH * ULP_AON_GP_REG11_SIZE, 0,
        ULP_AON_GP_REG_WIDTH * ULP_AON_GP_REG11_SIZE);

    /* 信号量清零 */
    writew(SEM0_FORCE_CLR, 1);
    writew(SEM1_FORCE_CLR, 1);
    writew(SEM2_FORCE_CLR, 1);
    writew(SEM3_FORCE_CLR, 1);
    writew(SEM4_FORCE_CLR, 1);
    writew(SEM5_FORCE_CLR, 1);
    writew(SEM6_FORCE_CLR, 1);
    writew(SEM7_FORCE_CLR, 1);

    reg_clrbits(BRAM_SHARE_COM_REG, 0, 0, BRAM_SHARE_MODE_SIZE);
}

void reboot_port_soft_reboot_chip(void)
{
    uint32_t irq_sts = osal_irq_lock();

#ifdef CONFIG_SUPPORT_RST_RSN_SAVE_TO_FLASH
    reset_cause_set(REBOOT_BY_SOFT_RST);
    reset_cause_save();
#endif
    writew(SOFT_REBOOT_FLAG, 1);
    writew(ULP_AON_CTL_MCPU_POR_RST_PC_H_REG, 0x1);  /* 配置romboot入口地址为0x10000 */
    writew(ULP_AON_CTL_MCPU_POR_RST_PC_L_REG, 0);

    writew(ULP_AON_CTL_ULP_SLP_EVT_CLR_REG, 1);     /* event信号清除 */
    writel(ULP_AON_CTL_ULP_WKUP_EVT_EN, 0);         /* 唤醒事件清除 */
    writel(ULP_AON_CTL_ULP_WKUP_EVT_CLR, 0x1F);
    writel(ULP_AON_CTL_ULP_WKUP_INT_EN, 0);         /* 唤醒中断清除 */
    writel(ULP_AON_CTL_ULP_WKUP_INT_CLR, 0x1F);
    writew(ULP_AON_CTL_CCPU_SOFT_RST_REG, 0);       /* c核复位 */

    writel(HH503_MAC_WL0_EXT_TSF_CTRL, 0);          /* wifi tsf关闭 */
    writew(ULP_AON_CTL_TGLP_RESET_REG, 0);          /* bt tglp软复位 */
    uapi_tcxo_delay_us(DELAY_100_US);
    writew(ULP_AON_CTL_TGLP_RESET_REG, 1);
    writel(ULP_AON_BT_OSC_EN_INT_CLR, 0x3);         /* OSC中断清零 */
    writel(ULP_AON_BT_OSC_EN_INT_EN, 0);            /* OSC中断禁止 */

    reg_setbit(ULP_AON_CTL_SYS_TICK_CFG_M, 0, 1);  /* systick清零 */
    reboot_port_aon_resource_clr();
    dsb();
    writew(PMU1_CTL_SYS_SOFT_RST_REG, 0);           /* 软重启 */
    for (;;) { }

    osal_irq_restore(irq_sts);
}

void reboot_port_reboot_callback(int32_t core)
{
    unused(core);
#ifdef CONFIG_PLAT_SUPPORT_DFR
    hcc_send_panic_msg();
#endif
#ifdef CONFIG_SUPPORT_RST_RSN_SAVE_TO_FLASH
    reset_cause_set(REBOOT_BY_CCORE_EXCEPTION);
#endif
    hal_reboot_chip();
    return;
}

static td_bool g_reboot_soft_reboot_flag = TD_FALSE;

void reboot_port_switch_to_soft_reboot(void)
{
    g_reboot_soft_reboot_flag = TD_TRUE;
}

void reboot_port_reboot_chip(void)
{
#ifdef CONFIG_SUPPORT_RST_RSN_SAVE_TO_FLASH
    reset_cause_set(REBOOT_BY_RST);
    reset_cause_save();
#endif
    if (g_reboot_soft_reboot_flag == TD_TRUE) {
        reboot_port_soft_reboot_chip();
    } else {
        regw_clrbit(HAL_CHIP_RESET_REG, HAL_CHIP_RESET_REG_OFFSET, HAL_CHIP_RESET_REG_ENABLE_RESET_BIT);
    }
}

td_bool reboot_port_is_soft_reboot(void)
{
    return (readw(SOFT_REBOOT_FLAG) == 1) ? TD_TRUE : TD_FALSE;
}

#ifdef CONFIG_SUPPORT_RST_RSN_SAVE_TO_FLASH
static char *rst_reason[] = {
    "acore wdt",
    "acore exception",
    "ccore wdt",
    "ccore exception",
    "rst",
    "soft rst",
    "not software reboot"
};

td_bool reboot_port_is_software_reboot(rst_reason_t *reset_cause)
{
    uint32_t flash_save_addr = 0, flash_save_size = 0;
    if (g_reset_rsn == 0xFF) {
        if (crashinfo_flash_addr_get(&flash_save_addr, &flash_save_size) == false) {
            PRINT("Read Flash Failed\r\n");
            return TD_FALSE;
        }
        uapi_sfc_reg_read(flash_save_addr, (uint8_t *)&g_reset_rsn, sizeof(uint32_t));
    }
    *reset_cause = g_reset_rsn;
    return (*reset_cause != RST_REASON_NOT_SOFTWARE_REBOOT) ? TD_TRUE : TD_FALSE;
}
#endif

static char *main_rst_reason[] = {
    "hard rst or wdt",
    "soft rst",
    "power off rst",
    "pin rst",
};

uint32_t reboot_port_get_rst_reason(void)
{
    if (g_reset_rsn_no_flash == 0xFF) {
        g_reset_rsn_no_flash = RST_RSN_HARD_RST;

        if (reboot_port_is_soft_reboot() == TD_TRUE) {
            g_reset_rsn_no_flash = RST_RSN_SOFT_RST;
            return g_reset_rsn_no_flash;
        }

        uint16_t val = readw(ULP_RST_HISTORY);
        uint16_t cnt = readw(ULP_RST_TIMES);
        if ((val & SYS_WDT_RST_HIS) == SYS_WDT_RST_HIS) {
            g_reset_rsn_no_flash = RST_RSN_WDT_RST;
        } else if ((val & SYS_PIN_RST_HIS) == SYS_PIN_RST_HIS) {
            if (cnt != 1) { /* RST_TIMES初始值为1， = 1有掉电重启/复位管脚重启两种情况, RST_TIMES != 1, 只有可能是复位管脚重启 */
                g_reset_rsn_no_flash = RST_RSN_PIN_RST;
            }
        }
    }
    return g_reset_rsn_no_flash;
}

void reboot_port_rst_reason_dump(void)
{
    reboot_port_rst_reason_t main_rst = reboot_port_get_rst_reason();
    PRINT("rst_reason: %s\r\n", main_rst_reason[main_rst]);
#ifdef CONFIG_SUPPORT_RST_RSN_SAVE_TO_FLASH
    rst_reason_t reset_cause = RST_REASON_NOT_SOFTWARE_REBOOT;
    reboot_port_is_software_reboot(&reset_cause);
    if (reset_cause <= REBOOT_BY_SOFT_RST) {
        PRINT("details: %s\r\n", rst_reason[reset_cause]);
    }
    if (reset_cause != NON_SOFTWARE_REBOOT) {
        reset_cause_set(NON_SOFTWARE_REBOOT);
        reset_cause_save();
    }
#endif
}

#ifdef CONFIG_SUPPORT_RST_RSN_SAVE_TO_FLASH
static rst_reason_t reboot_port_rst_reason_get(uint32_t reset_rsn_flag)
{
    /* 需优先判断REBOOT_BY_ACORE_WDT、REBOOT_BY_ACORE_EXCEPTION、REBOOT_BY_CCORE_WDT、REBOOT_BY_CCORE_EXCEPTION
        对应的bit位是否置1，若有一个bit置1，则为内部硬重启 */
    if (reset_rsn_flag == NON_SOFTWARE_REBOOT) {
        return RST_REASON_NOT_SOFTWARE_REBOOT;
    } else if ((reset_rsn_flag & REBOOT_BY_ACORE_WDT) != 0) {
        return RST_REASON_ACORE_WDT;
    } else if ((reset_rsn_flag & REBOOT_BY_ACORE_EXCEPTION) != 0) {
        return RST_REASON_ACORE_EXCEPTION;
    } else if ((reset_rsn_flag & REBOOT_BY_CCORE_WDT) != 0) {
        return RST_REASON_CCORE_WDT;
    } else if ((reset_rsn_flag & REBOOT_BY_CCORE_EXCEPTION) != 0) {
        return RST_REASON_CCORE_EXCEPTION;
    } else if ((reset_rsn_flag & REBOOT_BY_RST) != 0) {
        return RST_REASON_RST;
    } else if ((reset_rsn_flag & REBOOT_BY_SOFT_RST) != 0) {
        return RST_REASON_SOFT_RST;
    }
    return RST_REASON_NOT_SOFTWARE_REBOOT;
}

void reset_cause_set(uint32_t rst_cause)
{
    g_reset_rsn_flag |= rst_cause;
    return;
}

#define CRASHINFO_MAX_LENGTH 4096
errcode_t reset_cause_save(void)
{
    uint32_t rst_cause = reboot_port_rst_reason_get(g_reset_rsn_flag);
    uint32_t flash_save_addr = 0, flash_save_size = 0;
    bool ret = crashinfo_flash_addr_get(&flash_save_addr, &flash_save_size);
    if (!ret) {
        PRINT("No Space to Save Reset Cause\r\n");
        return ERRCODE_FAIL;
    }
    flash_save_size = flash_save_size > CRASHINFO_MAX_LENGTH ? CRASHINFO_MAX_LENGTH : flash_save_size;
    uint8_t *crashinfo_buff = (uint8_t*)osal_kmalloc(flash_save_size, OSAL_GFP_KERNEL);
    if (crashinfo_buff == NULL) {
        if (uapi_sfc_reg_erase(flash_save_addr, flash_save_size) != ERRCODE_SUCC) {
            PRINT("Erase Flash Failed\r\n");
            return ERRCODE_FAIL;
        }
        return uapi_sfc_reg_write(flash_save_addr, (uint8_t *)(uintptr_t)&rst_cause, sizeof(uint32_t));
    }
    memset_s(crashinfo_buff, flash_save_size, 0, flash_save_size);
    if (uapi_sfc_reg_read(flash_save_addr, (uint8_t *)crashinfo_buff, flash_save_size) != ERRCODE_SUCC) {
        PRINT("Read Flash Failed\r\n");
        osal_kfree(crashinfo_buff);
        return ERRCODE_FAIL;
    }

    if (uapi_sfc_reg_erase(flash_save_addr, flash_save_size) != ERRCODE_SUCC) {
        PRINT("Erase Flash Failed\r\n");
        osal_kfree(crashinfo_buff);
        return ERRCODE_FAIL;
    }

    *(uint32_t*)crashinfo_buff = rst_cause;
    if (uapi_sfc_reg_write(flash_save_addr, (uint8_t *)crashinfo_buff, flash_save_size) != ERRCODE_SUCC) {
        PRINT("write Flash Failed\r\n");
        osal_kfree(crashinfo_buff);
        return ERRCODE_FAIL;
    }
    osal_kfree(crashinfo_buff);

    return ERRCODE_SUCC;
}
#endif
