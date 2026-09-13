/**
 * Copyright (c) @CompanyNameMagicTag 2023-2023. All rights reserved. \n
 *
 * Description: Provides pm port \n
 * Author: @CompanyNameTag \n
 * History: \n
 * 2023-01-13， Create file. \n
 */

#include "chip_io.h"
#include "pm_sleep.h"
#include "pm_veto.h"
#include "pm_dev.h"
#include "pm_sleep_porting.h"
#include "pm.h"
#include "uart.h"
#include "sdio_slave.h"
#include "tcxo.h"
#include "systick.h"
#include "errcode.h"
#include "hcc_if.h"
#include "hcc_cfg.h"
#include "soc_errno.h"
#include "flash_recover.h"
#include "clock_recover.h"
#include "pinctrl.h"
#include "gpio.h"

#ifdef __LITEOS__
#include "los_task_pri.h"
#endif
#define BUCK_CFG_REG_2                          (ULP_AON_CTL_RB_ADDR + 0x408)

#define ULP_AON_CTL_ULP_SLP_EVT_EN_REG          (ULP_AON_CTL_RB_ADDR + 0x1D0)
#define ULP_AON_ULP_TIMER_INT_EN_REG            (ULP_AON_CTL_RB_ADDR + 0x1FC)
#define ULP_TIMER_INT_EN_MASK                   0xF

#define AON_UART_RXD_SEL                        0x570301DC
#define AON_UART_RXD_SEL_MASK                   0x4

#define EFUSE_ULP_SEL0                          (ULP_AON_CTL_RB_ADDR + 0x1000)
#define PMU_TRIM_CTL_6                          (ULP_AON_CTL_RB_ADDR + 0x1028)
#define PMU_TRIM_CTL_4                          (ULP_AON_CTL_RB_ADDR + 0x1020)
#define PMU_TRIM_CTL_6_VAL                      0x8890
#define PMU_TRIM_CTL_4_VAL                      0x3E

/* 控制深睡唤醒SYSLDO升压到1.075V */
#define SYSLDO_VSET_NOR                         (ULP_AON_CTL_RB_ADDR + 0x88)
/* 控制SYSLDO软件降低压到0.925V */
#define SYSLDO_VSET_SOFT_SET_LOW                (ULP_AON_CTL_RB_ADDR + 0x8C)
/* 控制深睡唤醒SYSLDO升压步长为3格 */
#define SYSLDO_VSET_STEP                        (ULP_AON_CTL_RB_ADDR + 0x64)
/* 控制深睡pmu1 ibg最先开始上电 */
#define PMU_REF1_IBG_EN_BOOT_TIME               (ULP_AON_CTL_RB_ADDR + 0x154)
/* 控制深睡pmu1 uvlo en最先开始上电 */
#define PMU_UVLO_EN_BOOT_TIME                   (ULP_AON_CTL_RB_ADDR + 0x158)
/* 控制深睡唤醒SYSLDO解决ret时间 */
#define PMU_SYSLDO_ECO_EN_BOOT_TIME             (ULP_AON_CTL_RB_ADDR + 0x14C)
/* 深睡唤醒第一步进行SYSLDO升压 */
#define PMU_SYSLDO_LP_BOOT_TIME                 (ULP_AON_CTL_RB_ADDR + 0x150)
/* 深睡唤醒第二步进行Buck上电（buck快速上电耗时150us） */
#define BUCK_EN_BOOT_TIME                       (ULP_AON_CTL_RB_ADDR + 0x160)
/* 深睡唤醒第三步进行flashldo上电（flash ldo快速上电耗时150us） */
#define PMU_FLASHLDO_EN_BOOT_TIME               (ULP_AON_CTL_RB_ADDR + 0x18C)
#define PMU_FLASHLDO_EN_DELAY_TIME              (ULP_AON_CTL_RB_ADDR + 0x208)
/* 深睡唤醒第三步进行CLDO上电（cldo快速上电耗时150us） */
#define PMU_CLDO_SW_BOOT_TIME                   (ULP_AON_CTL_RB_ADDR + 0x174)
#define PMU_CLDO_EN_BOOT_TIME                   (ULP_AON_CTL_RB_ADDR + 0x178)
#define PMU_CLDO_EN_DELAY_TIME                  (ULP_AON_CTL_RB_ADDR + 0x200)
/* 深睡唤醒第四步等CLDO起来后切换SW */
#define PMU_SYS_OUT_SEL_BOOT_TIME               (ULP_AON_CTL_RB_ADDR + 0x170)
/* 深睡唤醒第五步解除ISO和MEM RET */
#define VDD0P7_TO_SYS_ISO_EN_BOOT_TIME          (ULP_AON_CTL_RB_ADDR + 0x180)
#define MEMORY_RET_CEOFF_BOOT_TIME              (ULP_AON_CTL_RB_ADDR + 0x15C)
/* 深睡唤醒第五步解除掉电域复位 */
#define RST_BOOT_32K_N_BOOT_TIME                (ULP_AON_CTL_RB_ADDR + 0x184)
#define ULP_WKUP_AON_BOOT_TIME                  (ULP_AON_CTL_RB_ADDR + 0x188)
/* 关闭efuse自动读取 */
#define EFUSE_AUTO_READ_EN                      (ULP_AON_CTL_RB_ADDR + 0x99C)
/* 关闭RC 27M启动 */
#define CMU_RC_PD_RC_CKOUT_EN                   (ULP_AON_CTL_RB_ADDR + 0x960)
/* COM SUB CRG 解复位 */
#define RST_AON_CRG_WKUP_TIME_SOC               (ULP_AON_CTL_RB_ADDR + 0x638)
/* CLK FORCE ON 配置 */
#define GLB_CLK_FORCE_ON_WKUP_TIME_SOC          (ULP_AON_CTL_RB_ADDR + 0x63C)
/* COM SUB LOGIC解复位 */
#define RST_AON_LGC_WKUP_TIME_SOC               (ULP_AON_CTL_RB_ADDR + 0x640)
/* PMU2 REF2和refbuffer最先启动 */
#define REF2_EN_BG_WKUP_TIME_SOC                (ULP_AON_CTL_RB_ADDR + 0x644)
#define EN_REFBUFFER_WKUP_TIME_SOC              (ULP_AON_CTL_RB_ADDR + 0x648)
/* REF2启动后3拍启动intldo */
#define EN_INTLDO2_WKUP_TIME_SOC                (ULP_AON_CTL_RB_ADDR + 0x64C)
#define EN_INTLDO_1P8_WKUP_TIME_SOC             (ULP_AON_CTL_RB_ADDR + 0x684)
/* Intldo启动后三拍启动基准 */
#define EN_IBG_WKUP_TIME_SOC                    (ULP_AON_CTL_RB_ADDR + 0x650)
#define EN_IPOLY_WKUP_TIME_SOC                  (ULP_AON_CTL_RB_ADDR + 0x654)
#define EN_ITUNE_WKUP_TIME_SOC                  (ULP_AON_CTL_RB_ADDR + 0x658)
/* 急诊启动后一拍启动XLDO，解除CMU PD */
#define CMU_PD_WKUP_TIME_SOC                    (ULP_AON_CTL_RB_ADDR + 0x670)
#define EN_XLDO_WKUP_TIME_SOC                   (ULP_AON_CTL_RB_ADDR + 0x65C)
/* XLDO启动后三拍关闭XLDO快起功能 */
#define XLDO_FAST_START_WKUP_TIME_SOC           (ULP_AON_CTL_RB_ADDR + 0x674)
/* XLDO稳定后使能XO CORE */
#define XO_CORE_PD_WKUP_TIME_SOC                (ULP_AON_CTL_RB_ADDR + 0x660)
#define RC_PD_WKUP_TIME_SOC                     (ULP_AON_CTL_RB_ADDR + 0x668)
#define RC_RSTN_WKUP_TIME_SOC                   (ULP_AON_CTL_RB_ADDR + 0x66C)
#define FAST_XO_LOOP_RSTN_WKUP_TIME_SOC         (ULP_AON_CTL_RB_ADDR + 0x678)
/* 等待250us后使能XO2DBB的输出 */
#define XO2DBB_CLKOUT_EN_WKUP_TIME_SOC          (ULP_AON_CTL_RB_ADDR + 0x67C)
/* 使能DBB中XOCG */
#define A32M_CLKEN_WKUP_TIME_SOC                (ULP_AON_CTL_RB_ADDR + 0x698)
/* 使能DBB中XOCG */
#define TCXO_EN_WKUP_TIME_SOC                   (ULP_AON_CTL_RB_ADDR + 0x69C)
/* 解除A核C核CRG LOGIC复位 */
#define RST_PWR_C1_CRG_N_WKUP_TIME_SOC          (ULP_AON_CTL_RB_ADDR + 0x6A4)
#define RST_PWR_C1_LGC_N_WKUP_TIME_SOC          (ULP_AON_CTL_RB_ADDR + 0x6A8)
/* 解除A核C核CPU复位 */
#define RST_PWR_C1_CPU_N_WKUP_TIME_SOC          (ULP_AON_CTL_RB_ADDR + 0x6AC)
/* A核waking完成时间 */
#define M_SYS_WKING_COMPLETE_TIME               (ULP_AON_CTL_RB_ADDR + 0x6B0)
/* C核waking完成时间 */
#define B_SYS_WKING_COMPLETE_TIME               (ULP_AON_CTL_RB_ADDR + 0x6B4)

/* XO 快起配置 */
#define CMU_XO_REG0_H                           (ULP_AON_CTL_RB_ADDR + 0x1050)
#define CMU_XO_REG0_L                           (ULP_AON_CTL_RB_ADDR + 0x1054)
#define CMU_XO_REG1_H                           (ULP_AON_CTL_RB_ADDR + 0x1058)
#define CMU_XO_REG1_L                           (ULP_AON_CTL_RB_ADDR + 0x105C)
#define CMU_XO_TRIM                             (ULP_AON_CTL_RB_ADDR + 0x108C)

/* 开启vbg_retation模式 */
#define PMU_REF1_BG_EN_RET_CFG_0                (ULP_AON_CTL_RB_ADDR + 0x4D0)
#define PMU_REF1_BG_EN_RET_CFG_1                (ULP_AON_CTL_RB_ADDR + 0x4D4)
#define PMU_SYSLDO_ECO_EN_CFG                   (ULP_AON_CTL_RB_ADDR + 0xFC)

#define SYSLDO_VSET_NOR_MASK                         0xC
#define SYSLDO_VSET_SOFT_SET_LOW_MASK                0x6
#define SYSLDO_VSET_STEP_MASK                        0x3
#define PMU_REF1_IBG_EN_BOOT_TIME_MASK               0x0
#define PMU_UVLO_EN_BOOT_TIME_MASK                   0x0
#define PMU_SYSLDO_ECO_EN_BOOT_TIME_MASK             0x0
#define PMU_SYSLDO_LP_BOOT_TIME_MASK                 0x0
#define BUCK_EN_BOOT_TIME_MASK                       0x4
#define PMU_FLASHLDO_EN_BOOT_TIME_MASK               0x4
#define PMU_FLASHLDO_EN_DELAY_TIME_MASK              0x4
#define PMU_CLDO_SW_BOOT_TIME_MASK                   0x8
#define PMU_CLDO_EN_BOOT_TIME_MASK                   0x8
#define PMU_CLDO_EN_DELAY_TIME_MASK                  0x4
#define PMU_SYS_OUT_SEL_BOOT_TIME_MASK               0xE
#define VDD0P7_TO_SYS_ISO_EN_BOOT_TIME_MASK          0xF
#define MEMORY_RET_CEOFF_BOOT_TIME_MASK              0xF
#define RST_BOOT_32K_N_BOOT_TIME_MASK                0xF
#define ULP_WKUP_AON_BOOT_TIME_MASK                  0xF

#define EFUSE_AUTO_READ_EN_MASK                      0x0

#define CMU_RC_PD_RC_CKOUT_EN_MASK                   0x0

#define RST_AON_CRG_WKUP_TIME_SOC_MASK               0x0
#define GLB_CLK_FORCE_ON_WKUP_TIME_SOC_MASK          0x1
#define RST_AON_LGC_WKUP_TIME_SOC_MASK               0x3
#define REF2_EN_BG_WKUP_TIME_SOC_MASK                0x0
#define EN_REFBUFFER_WKUP_TIME_SOC_MASK              0x0
#define EN_INTLDO2_WKUP_TIME_SOC_MASK                0x2
#define EN_INTLDO_1P8_WKUP_TIME_SOC_MASK             0x2
#define EN_IBG_WKUP_TIME_SOC_MASK                    0x6
#define EN_IPOLY_WKUP_TIME_SOC_MASK                  0x6
#define EN_ITUNE_WKUP_TIME_SOC_MASK                  0x6
#define CMU_PD_WKUP_TIME_SOC_MASK                    0x7
#define EN_XLDO_WKUP_TIME_SOC_MASK                   0x6
#define XLDO_FAST_START_WKUP_TIME_SOC_MASK           0xC
#define XO_CORE_PD_WKUP_TIME_SOC_MASK                0x9
#define RC_PD_WKUP_TIME_SOC_MASK                     0xA
#define RC_RSTN_WKUP_TIME_SOC_MASK                   0xA
#define FAST_XO_LOOP_RSTN_WKUP_TIME_SOC_MASK         0xB
#define XO2DBB_CLKOUT_EN_WKUP_TIME_SOC_MASK          0x13
#define A32M_CLKEN_WKUP_TIME_SOC_MASK                0x13
#define TCXO_EN_WKUP_TIME_SOC_MASK                   0x13
#define RST_PWR_C1_CRG_N_WKUP_TIME_SOC_MASK          0x13
#define RST_PWR_C1_LGC_N_WKUP_TIME_SOC_MASK          0x13
#define RST_PWR_C1_CPU_N_WKUP_TIME_SOC_MASK          0x15
#define M_SYS_WKING_COMPLETE_TIME_MASK               0x15
#define B_SYS_WKING_COMPLETE_TIME_MASK               0x15
#define XO2DBB_CLKOUT_EN_WKUP_TIME_SOC_MASK2         0x1C
#define A32M_CLKEN_WKUP_TIME_SOC_MASK2               0x1C
#define TCXO_EN_WKUP_TIME_SOC_MASK2                  0x1C
#define RST_PWR_C1_CRG_N_WKUP_TIME_SOC_MASK2         0x1C
#define RST_PWR_C1_LGC_N_WKUP_TIME_SOC_MASK2         0x1C
#define RST_PWR_C1_CPU_N_WKUP_TIME_SOC_MASK2         0x1D
#define M_SYS_WKING_COMPLETE_TIME_MASK2              0x1D
#define B_SYS_WKING_COMPLETE_TIME_MASK2              0x1D

#define CMU_XO_REG0_H_MASK                           0xdec9
#define CMU_XO_REG0_L_MASK                           0xe1e1
#define CMU_XO_REG1_H_MASK                           0x7200
#define CMU_XO_REG1_L_MASK                           0xca0c
#define CMU_XO_REG0_H_MASK2                          0x2709

#define PMU_REF1_BG_EN_RET_CFG_0_MASK                0x1F
#define PMU_REF1_BG_EN_RET_CFG_1_MASK                0x1FF
#define PMU_SYSLDO_ECO_EN_CFG_MASK                   0x1


#define WAKEUP_POS_0                                 0
#define WAKEUP_POS_1                                 1
#define WAKEUP_POS_4                                 4
#define WAKEUP_POS_12                                12

#define WAKEUP_OFFEST_1                              1
#define WAKEUP_OFFEST_4                              4
#define WAKEUP_OFFEST_8                              8
#define WAKEUP_OFFEST_9                              9
#define WAKEUP_OFFEST_16                             16

/* 控制cldo调压到1.0V的时间 */
#define PMU_CLDO_VSET_ECO_SLP_TIME                  (ULP_AON_CTL_RB_ADDR + 0xD4)
/* 控制rst掉电域的时间 */
#define RST_BOOT_32K_N_SLP_TIME                     (ULP_AON_CTL_RB_ADDR + 0xDC)
/* 控制com sub状态机复位时间 */
#define ULP_WKUP_AON_SLP_TIME                       (ULP_AON_CTL_RB_ADDR + 0xE0)
/* 控制掉电域到常电域的iso使能时间 */
#define VDD0P7_TO_SYS_ISO_EN_SLP_TIME               (ULP_AON_CTL_RB_ADDR + 0xD8)
/* 控制mem retention时间 */
#define MEMORY_RET_CEOFF_SLP_TIME                   (ULP_AON_CTL_RB_ADDR + 0x1B0)
/* 控制cldo 和 sysldo 电压切换开关时间 */
#define PMU_SYS_OUT_SEL_SLP_TIME                    (ULP_AON_CTL_RB_ADDR + 0xC4)
/* 控制buck下电时间 */
#define BUCK_EN_SLP_TIME                            (ULP_AON_CTL_RB_ADDR + 0x1B4)
/* 控制cldo下电时间 */
#define PMU_CLDO_EN_SLP_TIME                        (ULP_AON_CTL_RB_ADDR + 0xD0)
/* 控制flash ldo下电时间 */
#define PMU_FLASHLDO_EN_SLP_TIME                    (ULP_AON_CTL_RB_ADDR + 0xEC)
/* 控制ibg下电时间 */
#define PMU_REF1_IGB_EN_SLP_TIME                    (ULP_AON_CTL_RB_ADDR + 0x1A8)
/* 控制uvlo下电时间 */
#define PMU_UVLO_EN_SLP_TIME                        (ULP_AON_CTL_RB_ADDR + 0x1AC)
/* 控制cldo sw直通控制时间 */
#define PMU_CLDO_SW_SLP_TIME                        (ULP_AON_CTL_RB_ADDR + 0xC8)
/* 控制sysldo调压到0.7V开始的时间 */
#define PMU_SYSLDO_LP_SLP_TIME                      (ULP_AON_CTL_RB_ADDR + 0x1A4)
/* 控制vbg ret开始的时间 */
#define PMU_SYSLDO_ECO_EN_SLP_TIME                  (ULP_AON_CTL_RB_ADDR + 0xE4)
/* 控制slp hold状态持续时间 */
#define ULP_SLP_HLD_TIME                            (ULP_AON_CTL_RB_ADDR + 0x1A0)

#define PMU_CLDO_VSET_ECO_SLP_TIME_MASK             0x0
#define RST_BOOT_32K_N_SLP_TIME_MASK                0x0
#define ULP_WKUP_AON_SLP_TIME_MASK                  0x0
#define VDD0P7_TO_SYS_ISO_EN_SLP_TIME_MASK          0x1
#define MEMORY_RET_CEOFF_SLP_TIME_MASK              0x1
#define PMU_SYS_OUT_SEL_SLP_TIME_MASK               0x3
#define BUCK_EN_SLP_TIME_MASK                       0x4
#define PMU_CLDO_EN_SLP_TIME_MASK                   0x3
#define PMU_FLASHLDO_EN_SLP_TIME_MASK               0x3
#define PMU_REF1_IGB_EN_SLP_TIME_MASK               0x5
#define PMU_UVLO_EN_SLP_TIME_MASK                   0x5
#define PMU_CLDO_SW_SLP_TIME_MASK                   0x4
#define PMU_SYSLDO_LP_SLP_TIME_MASK                 0x8
#define PMU_SYSLDO_ECO_EN_SLP_TIME_MASK             0xd
#define ULP_SLP_HLD_TIME_MASK                       0x1

static void pm_port_switch_udsleep(void);

uint8_t pm_check_device_ready(void)
{
    return reg32_getbit(ULP_PM_PLAT_ENABLE_REG, PM_PLAT_LPC_MODE_MASK);
}

static void pm_port_config_quick_wkup_st3(void)
{
    reg32_setbits(RST_AON_CRG_WKUP_TIME_SOC, WAKEUP_POS_0, WAKEUP_OFFEST_9, RST_AON_CRG_WKUP_TIME_SOC_MASK);
    writel(GLB_CLK_FORCE_ON_WKUP_TIME_SOC, GLB_CLK_FORCE_ON_WKUP_TIME_SOC_MASK);
    reg32_setbits(RST_AON_LGC_WKUP_TIME_SOC, WAKEUP_POS_0, WAKEUP_OFFEST_9, RST_AON_LGC_WKUP_TIME_SOC_MASK);
    reg32_setbits(REF2_EN_BG_WKUP_TIME_SOC, WAKEUP_POS_0, WAKEUP_OFFEST_9, REF2_EN_BG_WKUP_TIME_SOC_MASK);
    reg32_setbits(EN_REFBUFFER_WKUP_TIME_SOC, WAKEUP_POS_0, WAKEUP_OFFEST_9, EN_REFBUFFER_WKUP_TIME_SOC_MASK);
    reg32_setbits(EN_INTLDO2_WKUP_TIME_SOC, WAKEUP_POS_0, WAKEUP_OFFEST_9, EN_INTLDO2_WKUP_TIME_SOC_MASK);
    reg32_setbits(EN_INTLDO_1P8_WKUP_TIME_SOC, WAKEUP_POS_0, WAKEUP_OFFEST_9, EN_INTLDO_1P8_WKUP_TIME_SOC_MASK);
    reg32_setbits(EN_IBG_WKUP_TIME_SOC, WAKEUP_POS_0, WAKEUP_OFFEST_9, EN_IBG_WKUP_TIME_SOC_MASK);
    reg32_setbits(EN_IPOLY_WKUP_TIME_SOC, WAKEUP_POS_0, WAKEUP_OFFEST_9, EN_IPOLY_WKUP_TIME_SOC_MASK);
    reg32_setbits(EN_ITUNE_WKUP_TIME_SOC, WAKEUP_POS_0, WAKEUP_OFFEST_9, EN_ITUNE_WKUP_TIME_SOC_MASK);
    reg32_setbits(CMU_PD_WKUP_TIME_SOC, WAKEUP_POS_0, WAKEUP_OFFEST_9, CMU_PD_WKUP_TIME_SOC_MASK);
    reg32_setbits(EN_XLDO_WKUP_TIME_SOC, WAKEUP_POS_0, WAKEUP_OFFEST_9, EN_XLDO_WKUP_TIME_SOC_MASK);
    reg32_setbits(XLDO_FAST_START_WKUP_TIME_SOC, WAKEUP_POS_0, WAKEUP_OFFEST_9, XLDO_FAST_START_WKUP_TIME_SOC_MASK);
    reg32_setbits(XO_CORE_PD_WKUP_TIME_SOC, WAKEUP_POS_0, WAKEUP_OFFEST_9, XO_CORE_PD_WKUP_TIME_SOC_MASK);
    reg32_setbits(RC_PD_WKUP_TIME_SOC, WAKEUP_POS_0, WAKEUP_OFFEST_9, RC_PD_WKUP_TIME_SOC_MASK);
    reg32_setbits(RC_RSTN_WKUP_TIME_SOC, WAKEUP_POS_0, WAKEUP_OFFEST_9, RC_RSTN_WKUP_TIME_SOC_MASK);
    reg32_setbits(FAST_XO_LOOP_RSTN_WKUP_TIME_SOC, WAKEUP_POS_0, WAKEUP_OFFEST_9, FAST_XO_LOOP_RSTN_WKUP_TIME_SOC_MASK);
    uint32_t val = readl(CMU_XO_TRIM);
    if (val == 0) {
        reg32_setbits(XO2DBB_CLKOUT_EN_WKUP_TIME_SOC, WAKEUP_POS_0, WAKEUP_OFFEST_9,
            XO2DBB_CLKOUT_EN_WKUP_TIME_SOC_MASK2);
        reg32_setbits(A32M_CLKEN_WKUP_TIME_SOC, WAKEUP_POS_0, WAKEUP_OFFEST_9, A32M_CLKEN_WKUP_TIME_SOC_MASK2);
        reg32_setbits(TCXO_EN_WKUP_TIME_SOC, WAKEUP_POS_0, WAKEUP_OFFEST_9, TCXO_EN_WKUP_TIME_SOC_MASK2);
        reg32_setbits(RST_PWR_C1_CRG_N_WKUP_TIME_SOC, WAKEUP_POS_0, WAKEUP_OFFEST_9,
            RST_PWR_C1_CRG_N_WKUP_TIME_SOC_MASK2);
        reg32_setbits(RST_PWR_C1_LGC_N_WKUP_TIME_SOC, WAKEUP_POS_0, WAKEUP_OFFEST_9,
            RST_PWR_C1_LGC_N_WKUP_TIME_SOC_MASK2);
        reg32_setbits(RST_PWR_C1_CPU_N_WKUP_TIME_SOC, WAKEUP_POS_0, WAKEUP_OFFEST_9,
            RST_PWR_C1_CPU_N_WKUP_TIME_SOC_MASK2);
        reg32_setbits(M_SYS_WKING_COMPLETE_TIME, WAKEUP_POS_0, WAKEUP_OFFEST_9, M_SYS_WKING_COMPLETE_TIME_MASK2);
        reg32_setbits(B_SYS_WKING_COMPLETE_TIME, WAKEUP_POS_0, WAKEUP_OFFEST_9, B_SYS_WKING_COMPLETE_TIME_MASK2);
    } else {
        reg32_setbits(XO2DBB_CLKOUT_EN_WKUP_TIME_SOC, WAKEUP_POS_0, WAKEUP_OFFEST_9,
            XO2DBB_CLKOUT_EN_WKUP_TIME_SOC_MASK);
        reg32_setbits(A32M_CLKEN_WKUP_TIME_SOC, WAKEUP_POS_0, WAKEUP_OFFEST_9, A32M_CLKEN_WKUP_TIME_SOC_MASK);
        reg32_setbits(TCXO_EN_WKUP_TIME_SOC, WAKEUP_POS_0, WAKEUP_OFFEST_9, TCXO_EN_WKUP_TIME_SOC_MASK);
        reg32_setbits(RST_PWR_C1_CRG_N_WKUP_TIME_SOC, WAKEUP_POS_0, WAKEUP_OFFEST_9,
            RST_PWR_C1_CRG_N_WKUP_TIME_SOC_MASK);
        reg32_setbits(RST_PWR_C1_LGC_N_WKUP_TIME_SOC, WAKEUP_POS_0, WAKEUP_OFFEST_9,
            RST_PWR_C1_LGC_N_WKUP_TIME_SOC_MASK);
        reg32_setbits(RST_PWR_C1_CPU_N_WKUP_TIME_SOC, WAKEUP_POS_0, WAKEUP_OFFEST_9,
            RST_PWR_C1_CPU_N_WKUP_TIME_SOC_MASK);
        reg32_setbits(M_SYS_WKING_COMPLETE_TIME, WAKEUP_POS_0, WAKEUP_OFFEST_9, M_SYS_WKING_COMPLETE_TIME_MASK);
        reg32_setbits(B_SYS_WKING_COMPLETE_TIME, WAKEUP_POS_0, WAKEUP_OFFEST_9, B_SYS_WKING_COMPLETE_TIME_MASK);
    }
}

static void pm_port_config_quick_sleep(void)
{
    writel(PMU_CLDO_VSET_ECO_SLP_TIME, PMU_CLDO_VSET_ECO_SLP_TIME_MASK);
    writel(RST_BOOT_32K_N_SLP_TIME, RST_BOOT_32K_N_SLP_TIME_MASK);
    writel(ULP_WKUP_AON_SLP_TIME, ULP_WKUP_AON_SLP_TIME_MASK);
    writel(VDD0P7_TO_SYS_ISO_EN_SLP_TIME, VDD0P7_TO_SYS_ISO_EN_SLP_TIME_MASK);
    writel(MEMORY_RET_CEOFF_SLP_TIME, MEMORY_RET_CEOFF_SLP_TIME_MASK);
    writel(PMU_SYS_OUT_SEL_SLP_TIME, PMU_SYS_OUT_SEL_SLP_TIME_MASK);
    writel(BUCK_EN_SLP_TIME, BUCK_EN_SLP_TIME_MASK);
    writel(PMU_CLDO_EN_SLP_TIME, PMU_CLDO_EN_SLP_TIME_MASK);
    writel(PMU_FLASHLDO_EN_SLP_TIME, PMU_FLASHLDO_EN_SLP_TIME_MASK);
    writel(PMU_REF1_IGB_EN_SLP_TIME, PMU_REF1_IGB_EN_SLP_TIME_MASK);
    writel(PMU_UVLO_EN_SLP_TIME, PMU_UVLO_EN_SLP_TIME_MASK);
    writel(PMU_CLDO_SW_SLP_TIME, PMU_CLDO_SW_SLP_TIME_MASK);
    writel(PMU_SYSLDO_LP_SLP_TIME, PMU_SYSLDO_LP_SLP_TIME_MASK);
    writel(PMU_SYSLDO_ECO_EN_SLP_TIME, PMU_SYSLDO_ECO_EN_SLP_TIME_MASK);
    writel(ULP_SLP_HLD_TIME, ULP_SLP_HLD_TIME_MASK);
}

static void pm_port_config_quick_wkup(void)
{
    /* STEP_0 */
    reg32_setbits(SYSLDO_VSET_NOR, WAKEUP_POS_0, WAKEUP_OFFEST_4, SYSLDO_VSET_NOR_MASK);
    reg32_setbits(SYSLDO_VSET_SOFT_SET_LOW, WAKEUP_POS_4, WAKEUP_OFFEST_4, SYSLDO_VSET_SOFT_SET_LOW_MASK);
    reg32_setbits(SYSLDO_VSET_STEP, WAKEUP_POS_0, WAKEUP_OFFEST_4, SYSLDO_VSET_STEP_MASK);
    reg32_setbits(PMU_REF1_IBG_EN_BOOT_TIME, WAKEUP_POS_0, WAKEUP_OFFEST_8, PMU_REF1_IBG_EN_BOOT_TIME_MASK);
    reg32_setbits(PMU_UVLO_EN_BOOT_TIME, WAKEUP_POS_0, WAKEUP_OFFEST_8, PMU_UVLO_EN_BOOT_TIME_MASK);
    reg32_setbits(PMU_SYSLDO_ECO_EN_BOOT_TIME, WAKEUP_POS_0, WAKEUP_OFFEST_8, PMU_SYSLDO_ECO_EN_BOOT_TIME_MASK);
    reg32_setbits(PMU_SYSLDO_LP_BOOT_TIME, WAKEUP_POS_0, WAKEUP_OFFEST_8, PMU_SYSLDO_LP_BOOT_TIME_MASK);
    reg32_setbits(BUCK_EN_BOOT_TIME, WAKEUP_POS_0, WAKEUP_OFFEST_8, BUCK_EN_BOOT_TIME_MASK);
    reg32_setbits(PMU_FLASHLDO_EN_BOOT_TIME, WAKEUP_POS_0, WAKEUP_OFFEST_8, PMU_FLASHLDO_EN_BOOT_TIME_MASK);
    reg32_setbits(PMU_FLASHLDO_EN_DELAY_TIME, WAKEUP_POS_12, WAKEUP_OFFEST_4, PMU_FLASHLDO_EN_DELAY_TIME_MASK);
    reg32_setbits(PMU_CLDO_SW_BOOT_TIME, WAKEUP_POS_0, WAKEUP_OFFEST_8, PMU_CLDO_SW_BOOT_TIME_MASK);
    reg32_setbits(PMU_CLDO_EN_BOOT_TIME, WAKEUP_POS_0, WAKEUP_OFFEST_8, PMU_CLDO_EN_BOOT_TIME_MASK);
    reg32_setbits(PMU_CLDO_EN_DELAY_TIME, WAKEUP_POS_12, WAKEUP_OFFEST_4, PMU_CLDO_EN_DELAY_TIME_MASK);
    reg32_setbits(PMU_SYS_OUT_SEL_BOOT_TIME, WAKEUP_POS_0, WAKEUP_OFFEST_8, PMU_SYS_OUT_SEL_BOOT_TIME_MASK);
    reg32_setbits(VDD0P7_TO_SYS_ISO_EN_BOOT_TIME, WAKEUP_POS_0, WAKEUP_OFFEST_8, VDD0P7_TO_SYS_ISO_EN_BOOT_TIME_MASK);
    reg32_setbits(MEMORY_RET_CEOFF_BOOT_TIME, WAKEUP_POS_0, WAKEUP_OFFEST_8, MEMORY_RET_CEOFF_BOOT_TIME_MASK);
    reg32_setbits(RST_BOOT_32K_N_BOOT_TIME, WAKEUP_POS_0, WAKEUP_OFFEST_8, RST_BOOT_32K_N_BOOT_TIME_MASK);
    reg32_setbits(ULP_WKUP_AON_BOOT_TIME, WAKEUP_POS_0, WAKEUP_OFFEST_8, ULP_WKUP_AON_BOOT_TIME_MASK);

    /* STEP_1 */
    reg32_setbits(EFUSE_AUTO_READ_EN, WAKEUP_POS_0, WAKEUP_OFFEST_1, EFUSE_AUTO_READ_EN_MASK);

    /* STEP_2 */
    reg32_setbits(CMU_RC_PD_RC_CKOUT_EN, WAKEUP_POS_0, WAKEUP_OFFEST_1, CMU_RC_PD_RC_CKOUT_EN_MASK);

    /* STEP_3 */
    pm_port_config_quick_wkup_st3();

    /* STEP_4 */
    uint32_t val = readl(CMU_XO_TRIM);
    if (val == 0) {
        reg32_setbits(CMU_XO_REG0_H, WAKEUP_POS_0, WAKEUP_OFFEST_16, CMU_XO_REG0_H_MASK);
    } else {
        reg32_setbits(CMU_XO_REG0_H, WAKEUP_POS_0, WAKEUP_OFFEST_16, CMU_XO_REG0_H_MASK2);
    }
    reg32_setbits(CMU_XO_REG0_L, WAKEUP_POS_0, WAKEUP_OFFEST_16, CMU_XO_REG0_L_MASK);
    reg32_setbits(CMU_XO_REG1_H, WAKEUP_POS_0, WAKEUP_OFFEST_16, CMU_XO_REG1_H_MASK);
    reg32_setbits(CMU_XO_REG1_L, WAKEUP_POS_0, WAKEUP_OFFEST_16, CMU_XO_REG1_L_MASK);

    /* STEP_5 */
    writel(PMU_REF1_BG_EN_RET_CFG_0, PMU_REF1_BG_EN_RET_CFG_0_MASK);
    writel(PMU_REF1_BG_EN_RET_CFG_1, PMU_REF1_BG_EN_RET_CFG_1_MASK);
    writel(PMU_SYSLDO_ECO_EN_CFG, PMU_SYSLDO_ECO_EN_CFG_MASK);

    pm_port_config_quick_sleep();
}

static void pm_port_modify_xo_trim(void)
{
    reg32_setbits(EFUSE_ULP_SEL0, WAKEUP_POS_0, 0x2, 0x3); // 把bit0和bit1置1
    writel(PMU_TRIM_CTL_6, PMU_TRIM_CTL_6_VAL);
    writel(PMU_TRIM_CTL_4, PMU_TRIM_CTL_4_VAL);
}

void uapi_pm_lpc_init(void)
{
    pm_sleep_funcs_t funcs = {
        .start_tickless            = pm_port_start_tickless,
        .stop_tickless             = pm_port_stop_tickless,
        .get_sleep_ms              = pm_port_get_sleep_ms,
        .start_wakeup_timer        = pm_port_start_wakeup_timer,
        .allow_deepsleep           = pm_port_allow_deepsleep,
        .lightsleep_config         = pm_port_lightsleep_config,
        .deepsleep_config          = pm_port_deepsleep_config,
        .light_wakeup_config       = pm_port_light_wakeup_config,
        .deep_wakeup_config        = pm_port_deep_wakeup_config,
        .enter_wfi                 = pm_port_enter_wfi,
#if defined(CONFIG_PM_POWER_GATING_ENABLE) && (CONFIG_PM_POWER_GATING_ENABLE == 1)
        .cpu_suspend               = pm_port_cpu_suspend,
        .cpu_resume                = pm_port_cpu_resume,
#endif
    };
    pm_port_config_quick_wkup();
    writel(ULP_AON_ULP_TIMER_INT_EN_REG, ULP_TIMER_INT_EN_MASK);
    writew(ULP_AON_CTL_ULP_SLP_EVT_EN_REG, 1);           // Enable.
    writel(AON_UART_RXD_SEL, AON_UART_RXD_SEL_MASK);   // Jlink 高电平有效,串口低电平有效
    reg_setbits(BUCK_CFG_REG_2, 0, POS_6, 0x2, 0x1); // BUCK频率BIT[6:7]由默认值2调整到1
    uapi_pm_register_sleep_funcs(&funcs);
    uapi_pm_veto_init();

#ifdef CONFIG_LPM_DISABLE_INT_BEFORE_SLEEP
    osal_irq_request(M_WAKEUP_IRQN, (osal_irq_handler)pm_wkup_irq, NULL, NULL, NULL);
    uint8_t *wakeupintpri = int_get_maucintpri();
    osal_irq_set_priority(M_WAKEUP_IRQN, wakeupintpri[M_WAKEUP_IRQN]);
    osal_irq_enable(M_WAKEUP_IRQN);
#endif

    sfc_init_pm_encry();
    pm_wakeup_rtc_init();
    pm_port_modify_xo_trim();

#ifdef CONFIG_UART_DEBUG_PORT_H1
    pm_port_skip_pull_down(S_MGPIO12); // uart h1 tx
#endif

#ifdef CONFIG_UART_H0_PINSET_1
    pm_port_skip_pull_down(S_MGPIO8); // uart h0 tx
    pm_port_skip_pull_down(S_MGPIO9); // uart h0 rx
#elif defined(CONFIG_UART_H0_PINSET_2) || defined(CONFIG_HSO_UART_SUPPORT)
    pm_port_skip_pull_down(S_MGPIO17); // uart h0 tx
    pm_port_skip_pull_down(S_MGPIO18); // uart h0 rx
#endif
    uapi_pm_register_enter_udsleep_func(pm_port_switch_udsleep);
}

#define AGPIO_INTR_STATUS_REG 0x57028028
static uint32_t g_udsleep_gpio_intr_status = 0;
void pm_port_save_udsleep_wakeup_src(void)
{
    writel(ULP_GPIO_CLK_CFG, 0x1); // GPIO切PLL时钟

    g_udsleep_gpio_intr_status = readl(AGPIO_INTR_STATUS_REG);
}

static clock_switch_freq g_cur_switch_freq = FREQ_SWITCH_PLL;
uint32_t pm_port_switch_system_freq(clock_switch_freq switch_freq)
{
    uint32_t ret;
    uint8_t param = (uint8_t)switch_freq;

    if (switch_freq == g_cur_switch_freq) {
        return EXT_ERR_SUCCESS;
    }

    if (hcc_send_message(HCC_CHANNEL_AP, H2D_MSG_SWITCH_FREQ, 0) != EXT_ERR_SUCCESS) {
        return EXT_ERR_FAILURE;
    }

    ret = system_request_switch(H2D_MSG_SWITCH_FREQ, &param);
    if (ret == EXT_ERR_SUCCESS) {
        g_cur_switch_freq = switch_freq;
    }
    return ret;
}

#define HH503_MAC_WL0_EXT_TSF_CTRL_BASE         (0x57034000)
#define HH503_MAC_WL0_EXT_TSF_CTRL              (HH503_MAC_WL0_EXT_TSF_CTRL_BASE + 0x0)

static void pm_port_switch_udsleep(void)
{
    uint8_t param = 0;
    if (hcc_send_message(HCC_CHANNEL_AP, H2D_MSG_SWITCH_UDSLEEP, 0) != EXT_ERR_SUCCESS) {
        return;
    }
    writel(HH503_MAC_WL0_EXT_TSF_CTRL, 0);          /* wifi tsf关闭 */

    reg32_setbit(ULP_PM_PLAT_ENABLE_REG, PM_PLAT_UDSLEEP_MASK);
    system_request_switch(H2D_MSG_SWITCH_UDSLEEP, &param);
}

int32_t pm_port_get_udsleep_wakeup_src(const uint8_t agpio_array[], uint8_t agpio_cnt, bool wakeup[])
{
    uint32_t i, j;
    uint8_t agpio_all_array[] = { S_AGPIO0, S_AGPIO1, S_AGPIO2, S_AGPIO3, S_AGPIO4, S_AGPIO5,
        S_AGPIO6, S_AGPIO7, S_AGPIO8, S_AGPIO9 };
    size_t agpio_all_cnt = sizeof(agpio_all_array) / sizeof(agpio_all_array[0]);
    uint8_t total_cnt = 0;

    for (i = 0; i < agpio_cnt; i++) {
        for (j = 0; j < agpio_all_cnt; j++) {
            if (agpio_array[i] == agpio_all_array[j]) {
                break;
            }
        }
        if (j == agpio_all_cnt) {
            wakeup[i] = false;
            continue;
        }

        if ((g_udsleep_gpio_intr_status & (1 << j)) != 0) {
            wakeup[i] = true;
            total_cnt++;
        } else {
            wakeup[i] = false;
        }
    }
    return total_cnt;
}

errcode_t pm_config_gpio_switch_udsleep(pin_t pin)
{
    uint32_t i;
    uint8_t agpio_all_array[] = { S_AGPIO0, S_AGPIO1, S_AGPIO2, S_AGPIO3, S_AGPIO4, S_AGPIO5,
        S_AGPIO6, S_AGPIO7, S_AGPIO8, S_AGPIO9 };
    size_t agpio_all_cnt = sizeof(agpio_all_array) / sizeof(agpio_all_array[0]);

    for (i = 0; i < agpio_all_cnt; i++) {
        if (pin == agpio_all_array[i]) {
            break;
        }
    }
    if (i == agpio_all_cnt) {
        return ERRCODE_FAIL;
    }

    /* 设置GPIO模式 */
    uapi_pin_set_mode(pin, PIN_MODE_0);
    /* 设置为输入模式 */
    uapi_gpio_set_dir(pin, GPIO_DIRECTION_INPUT);
    uapi_gpio_set_isr_mode(pin, GPIO_INTERRUPT_FALLING_EDGE);
    uapi_pm_enter_udsleep();
    return ERRCODE_SUCC;
}

void pm_config_xo32k_policy(uint8_t cfg)
{
    if (cfg == PM_FORCE_INNER_RC) {
        reg32_setbit(ULP_PM_PLAT_ENABLE_REG, PM_PLAT_RC32K_ONLY);
    }

    if (cfg == PM_XO32K_SW_CHECK_MASK) {
        reg32_setbit(ULP_PM_PLAT_ENABLE_REG, PM_PLAT_RC_SWITCH_MASK);
    }
}
