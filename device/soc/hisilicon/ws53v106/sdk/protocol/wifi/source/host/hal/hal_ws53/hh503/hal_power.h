/*
 * Copyright (c) CompanyNameMagicTag 2020-2020. All rights reserved.
 * Description: Header file for hal_power.c.
 * Create: 2020-7-3
 */

#ifndef __HAL_POWER_H__
#define __HAL_POWER_H__

/*****************************************************************************
  1 其他头文件包含
*****************************************************************************/
#include "hal_soc.h"
#include "hal_mac.h"
#include "hal_phy.h"
#include "hal_rf.h"
#include "oal_ext_if.h"
#include "hal_ext_if.h"
#include "wlan_types_common.h"

#ifdef __cplusplus
#if __cplusplus
extern "C" {
#endif
#endif

/*****************************************************************************
  2 宏定义
*************************************************************************/
/* 定制化相关宏 */
#define HAL_NUM_OF_CUST_TXPOWER_SCALING_TABLE      1024          /* 协议速率查询表最大发射功率参数的个数 */
#define HAL_INIT_NVM_MAX_TXPWR_BASE_2P4G           190           /* 基准最大发射功率初始值 0.1dbm */
#define HAL_INIT_NVM_MAX_TXPWR_BASE_5G             170
#define HAL_MAX_TXPOWER_MIN                        130           /* 最大发送功率的最小有效值:130 13.0dbm */
#define HAL_MAX_TXPOWER_MAX                        238           /* 最大发送功率的最大有效值:238 23.8dbm */

#define HH503_PHY_POWER_REF_2G_DEFAULT 0x14E8FC /* POWER REF 2G默认值取mt7对应值 */
#define HH503_PHY_POWER_REF_5G_DEFAULT 0x0ce0f4

/* tpc */
#define HAL_TPC_CH_NUM 32 /* tpc_ch档位总计有32档 */

/* PGA STEP */
#define HAL_PGA_STEP_NUM 64 /* PGA STEP档位总计有64档 */

/* PGA STEP */
#define HAL_POWER_CHANGE_COEF 10 /* POWER转换系数 */

/* 32档位UPC LUT的增益间隔粒度为0.5，扩大10倍用于计算,0.5*ALG_TPC_POW_PRECISION_SHIFT */
#define HAL_POW_LPF_LUT_NUM                 8          /* 筛选使用的LPF档位数目 */
#define HAL_POW_DAC_LUT_NUM                 4          /* 筛选使用的DAC档位数目 */

#define HAL_POW_DIST_5G_TABLE_LEN           13          /* 5G档位增益分配表长度 */
#define HAL_POW_DIST_2G_TABLE_LEN           16          /* 2G档位增益分配表长度 */

#ifdef _PRE_WLAN_ONLINE_DPD
#define HH503_DPD_OFF_CFR_ON               2
#define HH503_DPD_LVL_INVALID              3
#endif

#define HAL_RESP_POWER_REG_NUM              2

static inline osal_u8 hal_get_cfr_idx_from_tpc(osal_u32 tpc)
{
    return (osal_u8)(oal_get_bits(tpc, NUM_2_BITS, BIT_OFFSET_10));
}
static inline osal_u8 hal_get_dpd_tpc_lv_ch0_from_tpc(osal_u32 tpc)
{
    return (osal_u8)(oal_get_bits(tpc, NUM_2_BITS, BIT_OFFSET_8));
}
static inline osal_u8 hal_get_tpc_ch0_from_tpc(osal_u32 tpc)
{
    return (osal_u8)(oal_get_bits(tpc, NUM_8_BITS, BIT_OFFSET_0));
}

/*****************************************************************************
  3 枚举定义
*****************************************************************************/
/* 0~5的pow档位 */
typedef enum {
    HAL_POW_LEVEL_0 = 0,
    HAL_POW_LEVEL_1,
    HAL_POW_LEVEL_2,
    HAL_POW_LEVEL_3,
    HAL_POW_LEVEL_4,
    HAL_POW_LEVEL_5,
    HAL_POW_LEVEL_BUTT
} hal_pow_lvl_no_enum;

/*****************************************************************************
  4 全局变量声明
*****************************************************************************/

/*****************************************************************************
  7 STRUCT定义
*****************************************************************************/
/* pow code 参数结构体
  【22:22】：dpd_enable
  【21:12】：delta_dbb_scaling
  【11:10】：dac_gain
  【9:8】  ：pa_gain
  【7:5】  ：lpf_gain
  【4:4】  ：upc level
  【3:2】  ：cfr index
  【1:0】  ：dpd_tpc_lv */
typedef struct {
    osal_u32  dpd_tpc_lv        : 2,
            cfr_index         : 2,
            upc_level         : 1,
            lpf_gain          : 3,
            pa_gain           : 2,
            dac_gain          : 2,
            delta_dbb_scaling : 10,
            dpd_enable        : 1,
            bit_rsv               : 9;
} pow_code_params_stru;

typedef union {
    struct {
        osal_u16 tpc_ch0           : 8;
        osal_u16 dpd_tpc_lv_ch0    : 2;
        osal_u16 cfr_idx           : 2;
        osal_u16 bit_rsv           : 4;
    } bits;
    osal_u16 u16;
} tpc_code_params_stru;


typedef struct {
    wlan_channel_band_enum_uint8 freq_band; /* 2.4G or 5G */
    osal_u8 rate_idx;
    osal_u8 pwr_idx;
    osal_s16 tx_power; /* 发送功率 */
    osal_u8 resv[3];
} hal_tpc_set_stru;

/* 收到TRIGGER帧地带的参数 */
typedef struct {
    wlan_bw_cap_enum_uint8 rpt_trig_bw;          /* 上报trigger里的带宽 */
    osal_u8              rpt_trig_type;            /* trigger的类型 */
    osal_u8              rpt_trig_mcs;             /* mcs：0~7 */
    osal_u8              rpt_trig_nss;             /* nss：0~1 */
    osal_u8              rpt_trig_target_rssi;     /* trigger:0~90映射到-110dbm~-20dBm, trs:-90 + 2*Fval */
    osal_u8              rpt_trig_ap_tx_power;     /* trigger:0~60映射到-20dbm~40dBm, trs:-20 + 2*Fval */
    osal_u8              set_tpc;
    osal_u8              rate_idx;
} hal_rpt_trig_frm_params_stru;

typedef struct {
    osal_s16  max_pow  : 6,
            min_pow  : 6,
            offset   : 4;
} mcs_tx_pow_stru;

/* 档位分配占比的参数 */
typedef struct {
    osal_u8   dac_idx;
    osal_u8   lpf_idx;
    osal_u8   upc_idx;
    osal_u8   pa_idx;
} hal_pow_distri_ratio_stru;

typedef struct {
    osal_u8   cfr_idx;
    osal_u8   dpd_idx;
} hal_dpd_cfr_distri_ratio_stru;

typedef struct {
    osal_u32  dbb_scaling_2g    : 10;
    osal_u32  dpd_tpc_lv_ch1    : 2;
    osal_u32  dpd_update_en_ch1 : 1;
    osal_u32  dpd_tpc_lv_ch0    : 2;
    osal_u32  dpd_update_en_ch0 : 1;
    osal_u32  cfr_idx           : 2;
    osal_u32  dbb_scaling_5g    : 10;
    osal_u32  resv0             : 4;
    osal_s16   max_power_2g;
    osal_s16   max_power_5g;
} hal_pow_tpc_param_stru;

typedef struct {
    osal_u32  trig_phy_mode;
    osal_u32  trig_data_rate;
} hal_pow_trig_param_stru;

/*****************************************************************************
  10 函数声明
*****************************************************************************/
osal_void  hh503_calc_one_tpc_code(wlan_channel_band_enum_uint8 freq_band, osal_s16 pow_target_gain,
    pow_code_params_stru *pow_code_params, oal_bool_enum_uint8 is_dsss);

osal_void hh503_tb_mcs_tx_power_ext(wlan_channel_band_enum_uint8 band);
osal_void hh503_tb_tx_power_init_ext(wlan_channel_band_enum_uint8 band);
osal_void hh503_pow_sw_initialize_tx_power_ext(hal_to_dmac_device_stru *hal_device);
osal_void hh503_pow_init_vap_pow_code_ext(hal_to_dmac_device_stru *hal_device,
    hal_vap_pow_info_stru *vap_pow_info, hal_pow_set_type_enum_uint8 type, const mac_channel_stru *channel);
osal_void hal_tpc_rate_pow_print_rate_pow_table(osal_void);
/*****************************************************************************
  11 ROM回调函数类型定义
*****************************************************************************/
/* hal */
typedef osal_void (*hh503_get_cali_param_set_tpc_cb)(hal_to_dmac_device_stru *hal_device,
    wlan_channel_band_enum_uint8 band, osal_u8 channel_idx);
typedef osal_void (*hh503_tb_mcs_tx_power_cb)(wlan_channel_band_enum_uint8 band);
typedef osal_void (*hh503_tb_tx_power_init_cb)(wlan_channel_band_enum_uint8 band);

typedef osal_void (*hh503_set_tx_dscr_power_tpc_cb)(osal_u8 rate_idx, wlan_channel_band_enum_uint8 band,
    osal_s16 tx_power, tpc_code_params_stru *tpc_param);
typedef osal_void (*hh503_pow_sw_initialize_tx_power_cb)(hal_to_dmac_device_stru *hal_device);
typedef osal_void (*hh503_pow_initialize_tx_power_cb)(hal_to_dmac_device_stru *hal_device);
typedef osal_void (*hh503_pow_init_vap_pow_code_cb)(hal_to_dmac_device_stru *hal_device,
    hal_vap_pow_info_stru *vap_pow_info, hal_pow_set_type_enum_uint8 type, const mac_channel_stru *channel);

#ifdef __cplusplus
#if __cplusplus
}
#endif
#endif

#endif
