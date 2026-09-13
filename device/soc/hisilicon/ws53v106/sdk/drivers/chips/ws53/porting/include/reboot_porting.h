/**
 * Copyright (c) HiSilicon (Shanghai) Technologies Co., Ltd. 2022-2022. All rights reserved.
 *
 * Description: Provides pmp port template \n
 *
 * History: \n
 * 2022-09-26， Create file. \n
 */
#ifndef REBOOT_PORTING_H
#define REBOOT_PORTING_H

#include "errcode.h"
#include "td_type.h"

#ifdef __cplusplus
#if __cplusplus
extern "C" {
#endif
#endif

#define HAL_REBOOT_REASON_MCPU_WDT      0x2002
#define HAL_REBOOT_REASON_DSP_WDT       0x4002
#define HAL_REBOOT_REASON_BCPU_WDT      0x8002
#define HAL_REBOOT_REASON_BCPU_CHIP_WDT 0x8004

#if MASTER_BY_WS53_ONLY
#define HAL_CHIP_RESET_REG                  (ULP_AON_CTL_RB_ADDR + CHIP_RESET_OFF)
#else
#define HAL_CHIP_RESET_REG                  (PMU1_CTL_RB_BASE + CHIP_RESET_OFF)
#endif

#define HAL_CHIP_RESET_REG_OFFSET           0x0
#define HAL_CHIP_RESET_REG_ENABLE_RESET_BIT 0

#define HAL_PMU_PROTECT_STATUS_REG     (PMU1_CTL_RB_BASE + 0x370)
#define HAL_PMU_PROTECT_STATUS_CLR_REG (PMU1_CTL_RB_BASE + 0x370)

// buck short circuit protection, if this case occur, cpu can't read, only ssi can read the status.
#define HAL_PMU_PROTECT_BUCK2_SCP_BIT 2
#define HAL_PMU_PROTECT_BUCK1_SCP_BIT 3
#define HAL_PMU_PROTECT_CHIP_WDG_BIT  4
#define HAL_PMU_PROTECT_CHIP_WDG_BIT_CLR  0

#define HAL_BCPU_RESET_STS_REG (GLB_CTL_M_RB_BASE + 0x30)
#define HAL_MCPU_RESET_STS_REG (GLB_CTL_M_RB_BASE + 0x34)

// This status is valid when CLDO2 power on.
#define HAL_DSP_RESET_STS_REG            (GLB_CTL_B_RB_BASE + 0x38)
#define HAL_RESET_STS_COMMON_RESET_BIT   0 // Control by RST_PULSE0 at GLB_CTL_B + 0x70
#define HAL_RESET_STS_CORE_RESET_BIT     1 // Control by RST_PULSE0 at GLB_CTL_B + 0x70
#define HAL_RESET_STS_CORE_WDT_RESET_BIT 2
#define HAL_RESET_STS_CLEAR_REG (GLB_CTL_M_RB_BASE + 0x3c)
#define HAL_RESET_STS_CLEAR_ALL 0xFF

// Software dedicated whether a hard power failure occurs
#define HAL_ULP_AON_GENERAL_REG         (ULP_AON_CTL_RB_ADDR + 0x14)

#define HAL_ULP_AON_NO_POWEROFF_FLAG    0xA5A5

#define    NON_SOFTWARE_REBOOT            (0x0)
#define    REBOOT_BY_ACORE_WDT            (0x1)
#define    REBOOT_BY_ACORE_EXCEPTION      (0x1 << 1)
#define    REBOOT_BY_CCORE_WDT            (0x1 << 2)
#define    REBOOT_BY_CCORE_EXCEPTION      (0x1 << 3)
#define    REBOOT_BY_RST                  (0x1 << 4)
#define    REBOOT_BY_SOFT_RST             (0x1 << 5)

typedef enum {
    RST_REASON_ACORE_WDT,
    RST_REASON_ACORE_EXCEPTION,
    RST_REASON_CCORE_WDT,
    RST_REASON_CCORE_EXCEPTION,
    RST_REASON_RST,
    RST_REASON_SOFT_RST,
    RST_REASON_NOT_SOFTWARE_REBOOT,
} rst_reason_t;

typedef enum reboot_port_rst_reason {
    RST_RSN_WDT_RST = 0,             /* 看门狗重启或寄存器硬复位重启 */
    RST_RSN_SOFT_RST,                /* 寄存器软复位重启 */
    RST_RSN_HARD_RST,                /* 掉电重启 */
    RST_RSN_PIN_RST,                 /* 复位管脚重启 */
    RST_RSN_INVALID
} reboot_port_rst_reason_t;

/**
 * @defgroup drivers_port_reboot REBOOT
 * @ingroup  drivers_port
 * @{
 */

/**
 * @brief  寄存器硬复位重启。
 * @return 无。
 */
void reboot_port_reboot_chip(void);

/**
 * @brief  寄存器软复位重启。
 * @return 无。
 */
void reboot_port_soft_reboot_chip(void);

/**
 * @brief  重启回调函数。
 * @param  [in]  core  核心编号。
 * @return 无。
 */
void reboot_port_reboot_callback(int32_t core);

/**
 * @brief  重启原因输出。
 * @return 无。
 */
void reboot_port_rst_reason_dump(void);

/**
 * @brief  切换到寄存器软复位重启模式。
 * @return 无。
 */
void reboot_port_switch_to_soft_reboot(void);

/**
 * @brief  判断是否为寄存器软复位重启。
 * @return td_bool  返回是否为寄存器软复位重启。
 */
td_bool reboot_port_is_soft_reboot(void);

#ifdef CONFIG_SUPPORT_RST_RSN_SAVE_TO_FLASH
/**
 * @brief  设置重启原因。
 * @param  [in]  rst_cause  重启原因。
 * @return 无。
 */
void reset_cause_set(uint32_t rst_cause);

/**
 * @brief  保存重启原因。
 * @return 无。
 */
errcode_t reset_cause_save(void);

/**
 * @brief  判断是否为软件重启。软件重启包括看门狗重启、挂死异常重启、寄存器硬复位重启、寄存器软复位重启
 * @param  [out]  reset_cause  重启原因指针。
 * @return td_bool  返回是否为软件重启。
 */
td_bool reboot_port_is_software_reboot(rst_reason_t *reset_cause);
#endif

/**
 * @brief  获取重启原因。注意：当连续复位管脚重启255次，期间未发生掉电重启，此时下一次复位管脚重启会被识别成掉电重启
 * @return uint32_t  返回重启原因。
 */
uint32_t reboot_port_get_rst_reason(void);

#ifdef __cplusplus
#if __cplusplus
}
#endif /* __cplusplus */
#endif /* __cplusplus */
#endif