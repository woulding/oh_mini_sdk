/*
 * Copyright (c) CompanyNameMagicTag 2023. All rights reserved.
 * Description: Header file for hal_tbtt.c.
 * Create: 2023-1-17
 */

#ifndef HAL_TBTT_H
#define HAL_TBTT_H

/*****************************************************************************
  1 其他头文件包含
*****************************************************************************/
#include "hal_common_ops.h"
#include "hal_ext_if.h"
#include "hh503_phy_reg.h"
#include "mac_vap_ext.h"
#include "mac_resource_ext.h"

#ifdef __cplusplus
#if __cplusplus
extern "C" {
#endif
#endif

/*****************************************************************************
   宏定义
*****************************************************************************/
#define HH503_MAC_CFG_TSF_PULSE_SEL_VAP0 0
#define HH503_MAC_CFG_TSF_PULSE_SEL_VAP1 1
#define HH503_MAC_CFG_TSF_PULSE_SEL_VAP2 2

#define HH503_MAC_CFG_EXT0_TSF_EN_MSK           BIT1
#define HH503_MAC_CFG_EXT1_TSF_EN_MSK           BIT2
#define HH503_MAC_CFG_EXT2_TSF_EN_MSK           BIT3
#define HH503_MAC_CFG_EXT0_LISTEN_INTR_EN_MSK   BIT7
#define HH503_MAC_CFG_EXT1_LISTEN_INTR_EN_MSK   BIT8
#define HH503_MAC_CFG_EXT2_LISTEN_INTR_EN_MSK   BIT9
#define HH503_MAC_CFG_EXT0_DTIM_INTR_EN_MSK     BIT10
#define HH503_MAC_CFG_EXT1_DTIM_INTR_EN_MSK     BIT11
#define HH503_MAC_CFG_EXT2_DTIM_INTR_EN_MSK     BIT12

/*****************************************************************************
  STRUCT定义
*****************************************************************************/

/*****************************************************************************
  函数声明
*****************************************************************************/
osal_void hal_tsf_pulse_adjust(osal_void);
osal_void hh503_vap_ap_start_tsf(const hal_to_dmac_vap_stru *hal_vap);
osal_void hh503_enable_sta_tsf_tbtt(const hal_to_dmac_vap_stru *hal_vap);
osal_void hal_set_ext_tsf_int(osal_u8 hal_vap_id, osal_u8 enable);
osal_void hal_tsf_cal_mode_init(osal_void);
#ifdef __cplusplus
#if __cplusplus
}
#endif
#endif

#endif