/*
 * Copyright (c) CompanyNameMagicTag 2020-2020. All rights reserved.
 * Description: Header file for hal_pm.c.
 * Create: 2020-7-3
 */

#ifndef __HAL_PM_H__
#define __HAL_PM_H__

/*****************************************************************************
  其他头文件包含
*****************************************************************************/
#include "osal_types.h"

#ifdef __cplusplus
#if __cplusplus
extern "C" {
#endif
#endif

/*****************************************************************************
  2 宏定义
*****************************************************************************/
#define SEC_TO_NSEC  1000000000  /* 1s为1 000 000 000ns */
#define USEC_TO_NSEC 1000     /* 1000.0ns */
#define CHECK_MAX_TIMES 5000  /* 最大5000次检查 */
#define CHECK_PER_TIME 1000   /* 每次1000us时延 */

typedef struct {
    osal_u16 clk_div5;                /* 0x40000050 MAC主时钟分频系数 */
    osal_u16 ch_sel;                  /* 0x40000140 模拟通道与主辅路链接关系选择 */
    osal_u16 clk_phy_sel;             /* 0x40000144 PHY时钟选择 */
    osal_u16 dtcm_mode;               /* 0x40000280 dtcm冲突选择模式 */
}hal_pm_w_ctl_stru;

typedef struct {
    osal_u32 powerdown_cnt;           /* 睡眠次数,用于判断投票期间芯片是否掉电 */
    osal_u8  state;                   /* 低功耗状态 */
    osal_u8  sta_exist;               /* sta是否存在 */
    osal_u8  tsf_flip;                /* 唤醒后tsf翻转次数 */
    osal_u8  wkup_cnt;                /* 唤醒次数 用于统计翻转比例 */
    osal_u8  enable_sleep;           /* 仅STA & D2D共存下使用 */
}hal_pm_ctrl_stru;

osal_u8 hal_wifi_pm_get_host_allow_sleep(osal_void);
osal_void hal_pm_set_host_pm_state(osal_u8 flag);
#ifdef __cplusplus
#if __cplusplus
}
#endif
#endif

#endif /* end of hal_pm.h */
