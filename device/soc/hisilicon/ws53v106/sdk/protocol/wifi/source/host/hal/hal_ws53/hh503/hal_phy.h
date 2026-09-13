/*
 * Copyright (c) CompanyNameMagicTag 2020-2020. All rights reserved.
 * Description: Header file for hal_phy.c.
 * Create: 2020-7-3
 */

#ifndef __HAL_PHY_H__
#define __HAL_PHY_H__

/*****************************************************************************
  1 其他头文件包含
*****************************************************************************/
#include "hal_common_ops.h"
#include "hal_ext_if.h"
#include "hh503_phy_reg.h"

#ifdef __cplusplus
#if __cplusplus
extern "C" {
#endif
#endif

#undef  THIS_FILE_ID
#define THIS_FILE_ID OAM_FILE_ID_HAL_PHY_H

/*****************************************************************************
  STRUCT定义
*****************************************************************************/
typedef enum {
    WITP_PHY_BANK_0 = 0,
    WITP_PHY_BANK_1,
    WITP_PHY_BANK_2,
    WITP_PHY_BANK_3,
    WITP_PHY_BANK_4,
    WITP_PHY_BANK_5,
    WITP_PHY_BANK_6,
    WITP_PHY_BANK_7,
    WITP_PHY_PHY0_CTRL,

    WITP_PHY_BANK_BUTT
}hh503_phy_bank_idx_enum;

/*****************************************************************************
  带宽枚举对应phy寄存器的值
*****************************************************************************/
typedef struct {
    wlan_channel_bandwidth_enum_uint8 en_bandwidth; /* 带宽枚举 */
    osal_u8 bandwidth;                              /* 带宽，0->20M 1 */
    osal_char sec20_offset;                         /* 从20偏移 */
    osal_u8 rsv;
} hal_phy_bandwidth_stru;

typedef struct {
    osal_u32  cfg_pa_mode_11b_1m         : 2,
            cfg_pa_mode_11b_2m         : 2,
            cfg_pa_mode_11b_5d5m       : 2,
            cfg_pa_mode_11b_11m        : 2,
            cfg_pa_mode_11g_6m         : 2,
            cfg_pa_mode_11g_9m         : 2,
            cfg_pa_mode_11g_12m        : 2,
            cfg_pa_mode_11g_18m        : 2,
            cfg_pa_mode_11g_24m        : 2,
            cfg_pa_mode_11g_36m        : 2,
            cfg_pa_mode_11g_48m        : 2,
            cfg_pa_mode_11g_54m        : 2,
            cfg_pa_mode_11n_0mcs_2d4g  : 2,
            cfg_pa_mode_11n_1mcs_2d4g  : 2,
            cfg_pa_mode_11n_2mcs_2d4g  : 2,
            cfg_pa_mode_11n_3mcs_2d4g  : 2;
} hal_phy_pa_mode_0_code_stru;

typedef struct {
    osal_u32  cfg_pa_mode_11n_4mcs_2d4g     : 2,
            cfg_pa_mode_11n_5mcs_2d4g     : 2,
            cfg_pa_mode_11n_6mcs_2d4g     : 2,
            cfg_pa_mode_11n_7mcs_2d4g     : 2,
            cfg_pa_mode_11n40m_0mcs_2d4g  : 2,
            cfg_pa_mode_11n40m_1mcs_2d4g  : 2,
            cfg_pa_mode_11n40m_2mcs_2d4g  : 2,
            cfg_pa_mode_11n40m_3mcs_2d4g  : 2,
            cfg_pa_mode_11n40m_4mcs_2d4g  : 2,
            cfg_pa_mode_11n40m_5mcs_2d4g  : 2,
            cfg_pa_mode_11n40m_6mcs_2d4g  : 2,
            cfg_pa_mode_11n40m_7mcs_2d4g  : 2,
            cfg_pa_mode_11n40m_32mcs_2d4g : 2,
            cfg_pa_mode_11ac_0mcs_2d4g    : 2,
            cfg_pa_mode_11ac_1mcs_2d4g    : 2,
            cfg_pa_mode_11ac_2mcs_2d4g    : 2;
} hal_phy_pa_mode_1_code_stru;

typedef struct {
    osal_u32  cfg_pa_mode_11ac_3mcs_2d4g     : 2,
            cfg_pa_mode_11ac_4mcs_2d4g     : 2,
            cfg_pa_mode_11ac_5mcs_2d4g     : 2,
            cfg_pa_mode_11ac_6mcs_2d4g     : 2,
            cfg_pa_mode_11ac_7mcs_2d4g     : 2,
            cfg_pa_mode_11ac_8mcs_2d4g     : 2,
            cfg_pa_mode_11ac_9mcs_2d4g     : 2,
            cfg_pa_mode_11ac_10mcs_2d4g    : 2,
            cfg_pa_mode_11ac_11mcs_2d4g    : 2,
            cfg_pa_mode_11ac40m_0mcs_2d4g  : 2,
            cfg_pa_mode_11ac40m_1mcs_2d4g  : 2,
            cfg_pa_mode_11ac40m_2mcs_2d4g  : 2,
            cfg_pa_mode_11ac40m_3mcs_2d4g  : 2,
            cfg_pa_mode_11ac40m_4mcs_2d4g  : 2,
            cfg_pa_mode_11ac40m_5mcs_2d4g  : 2,
            cfg_pa_mode_11ac40m_6mcs_2d4g  : 2;
} hal_phy_pa_mode_2_code_stru;

typedef struct {
    osal_u32  cfg_pa_mode_11ac40m_7mcs_2d4g  : 2,
            cfg_pa_mode_11ac40m_8mcs_2d4g  : 2,
            cfg_pa_mode_11ac40m_9mcs_2d4g  : 2,
            cfg_pa_mode_11ac40m_10mcs_2d4g : 2,
            cfg_pa_mode_11ac40m_11mcs_2d4g : 2,
            reserved                   : 22;
} hal_phy_pa_mode_3_code_stru;

typedef struct {
    osal_u32  cfg_pa_mode_11ax20m_0mcs_2d4g : 2,
            cfg_pa_mode_11ax20m_1mcs_2d4g : 2,
            cfg_pa_mode_11ax20m_2mcs_2d4g : 2,
            cfg_pa_mode_11ax20m_3mcs_2d4g : 2,
            cfg_pa_mode_11ax20m_4mcs_2d4g : 2,
            cfg_pa_mode_11ax20m_5mcs_2d4g : 2,
            cfg_pa_mode_11ax20m_6mcs_2d4g : 2,
            cfg_pa_mode_11ax20m_7mcs_2d4g : 2,
            cfg_pa_mode_11ax40m_0mcs_2d4g : 2,
            cfg_pa_mode_11ax40m_1mcs_2d4g : 2,
            cfg_pa_mode_11ax40m_2mcs_2d4g : 2,
            cfg_pa_mode_11ax40m_3mcs_2d4g : 2,
            cfg_pa_mode_11ax40m_4mcs_2d4g : 2,
            cfg_pa_mode_11ax40m_5mcs_2d4g : 2,
            cfg_pa_mode_11ax40m_6mcs_2d4g : 2,
            cfg_pa_mode_11ax40m_7mcs_2d4g : 2;
} hal_phy_pa_mode_4_code_stru;

#if ((defined BOARD_FPGA_WIFI) || (defined BOARD_PILOT))
typedef union {
    struct {
        osal_u32 lpf_gain      : 4;
        osal_u32 mod_pga_unit  : 6;
        osal_u32 mod_gm_unit   : 6;
        osal_u32 mod_slice_tpc : 2;
        osal_u32 pa_unit       : 4;
        osal_u32 pa_slice_idx  : 2;
        osal_u32 r_comp_sel    : 4;
        osal_u32 c_comp_sel    : 4;
    } bits;
    osal_u32 u32;
} hal_phy_tpc_value_stru;
#else
typedef union {
    struct {
        osal_u32 lpf_gain      : 2;
        osal_u32 mod_pga_unit  : 6;
        osal_u32 mod_gm_unit   : 6;
        osal_u32 mod_slice_tpc : 2;
        osal_u32 pa_unit       : 4;
        osal_u32 pa_slice_idx  : 2;
        osal_u32 r_comp_sel    : 5;
        osal_u32 c_comp_sel    : 5;
    } bits;
    osal_u32 u32;
} hal_phy_tpc_value_stru;
#endif

/*****************************************************************************
  函数声明
*****************************************************************************/
osal_void hh503_initialize_phy_ext(osal_void);
osal_void hh503_set_phy_channel_num(osal_u8 channel_num);
osal_void hh503_set_phy_channel_freq_factor(osal_u32 freq_factor);
osal_void hh503_device_enable_ftm(osal_void);
osal_void hh503_device_disable_ftm(osal_void);
osal_void hh503_phy_cfg_big_aci(osal_u32 reg_val);
#ifdef _PRE_WLAN_FEATURE_DFS
    osal_void hh503_enable_radar_det_cb(osal_u8 enable);
#endif
osal_void hh503_phy_cfg_big_aci(osal_u32 reg_val);

osal_void hh503_radar_config_reg_ext(hal_dfs_radar_type_enum_uint8 radar_type);

#ifdef BOARD_FPGA_WIFI
osal_void hal_initialize_phy(osal_void);
osal_void hh503_set_phy_gain(osal_void);
osal_void hh503_phy_set_cfg_pa_mode_code(osal_void);
#endif

#ifdef _PRE_WLAN_FEATURE_INTRF_MODE
osal_void hal_phy_do_sgl_tone_notch_coef(osal_u32 notch_filter_coef1, osal_u32 notch_filter_coef2,
    osal_u32 sgl_tone_0_2_car_and_en, osal_u32 sgl_tone_3_car);
osal_void hal_phy_do_sgl_tone_notch_weight(osal_u32 sgl_tone_0_7_weight, osal_u8 notch_ch);
#endif

/*****************************************************************************
功能描述  : 读取PHY的信道测量结果寄存器
*****************************************************************************/
osal_void hal_get_ch_measurement_result_ram(hal_ch_statics_irq_event_stru *ch_statics);

/*****************************************************************************
功能描述  : 读取PHY的信道测量结果寄存器
*****************************************************************************/
osal_void hal_get_ch_measurement_result(hal_ch_statics_irq_event_stru *ch_statics);

/* 回调函数实现 */
typedef osal_void (*hh503_initialize_phy_ext_cb)(osal_void);
typedef osal_void (*hh503_update_phy_by_bandwith_cb)(wlan_channel_bandwidth_enum_uint8 bandwidth);
typedef osal_void (*hh503_radar_config_reg_cb)(hal_dfs_radar_type_enum_uint8 radar_type);
typedef osal_void (*hh503_get_single_psd_sample_cb)(osal_u16 index, osal_char *psd_val);
typedef osal_void (*hh503_set_psd_en_cb)(osal_u32 reg_value);

typedef osal_void (*hh503_set_machw_phy_adc_freq_ext_cb)(hal_to_dmac_device_stru *hal_device,
    wlan_channel_bandwidth_enum_uint8 bandwidth);

#ifdef __cplusplus
#if __cplusplus
}
#endif
#endif

#endif /* end of hal_phy.h */
