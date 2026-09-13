/*
 * Copyright (c) CompanyNameMagicTag 2020-2020. All rights reserved.
 * Description: Header file for hal_mac.c.
 * Create: 2020-7-3
 */

#ifndef __HAL_MAC_H__
#define __HAL_MAC_H__

/*****************************************************************************
  1 其他头文件包含
*****************************************************************************/
#include "wlan_types_common.h"
#include "oam_ext_if.h"
#include "hal_ext_if.h"
#include "frw_ext_if.h"
#include "hal_mac_reg.h"
#include "hal_mac_reg_field.h"
#include "hal_chip.h"
#include "hal_device.h"
#include "hal_soc.h"
#include "hal_reset.h"
#include "hal_device_fsm.h"
#include "hal_rf.h"
#include "hal_ext_if_device.h"
#include "hal_soc_reg.h"

#ifdef __cplusplus
#if __cplusplus
extern "C" {
#endif
#endif

#undef THIS_FILE_ID
#define THIS_FILE_ID OAM_FILE_ID_HAL_MAC_H

/*****************************************************************************
  2 宏定义
*****************************************************************************/
#define HH503_SIFSTIME 16
#define HH503_ACK_CTS_FRAME_LEN 14
#define HH503_LONG_PREAMBLE_LEN_A 16
#define HH503_LONG_PREAMBLE_LEN_B 144
#define HH503_PLCP_HEADER_LEN_A 4
#define HH503_PLCP_HEADER_LEN_B 48
/* 以下为PHY头时间 单位us */
#define HH503_LONG_PREAMBLE_TIME 192
#define HH503_SHORT_PREAMBLE_TIME 96
#define HH503_LEGACY_OFDM_TIME 20
#define HH503_HT_PHY_TIME 40
#define HH503_VHT_PHY_TIME 44

/* RTS时间定义，包括PHY头 帧长/速率+phy头时间 */
#define HH503_RTSTIME_11B_LONG 221
#define HH503_RTSTIME_NON_11B 27

/* CTS时间定义，包括PHY头帧长/速率+phy头时间 */
#define HH503_CTSACKTIME_11B_LONG 212
#define HH503_CTSACKTIME_NON_11B 25

/* BA时间定义，包括PHY头帧长/速率+phy头时间 */
#define HH503_BATIME_11B_LONG 238
#define HH503_BATIME_NON_11B 30

/* 过滤寄存器初始值 */
#define HH503_MAC_CFG_INIT 0xC7BDFEDA

#define HH503_EIFSTIME_GONLY \
    (HH503_SIFSTIME + HH503_ACK_CTS_FRAME_LEN * 8 + HH503_PLCP_HEADER_LEN_A + HH503_LONG_PREAMBLE_LEN_A)
#define HH503_EIFSTIME_GMIXED \
    (HH503_SIFSTIME + HH503_ACK_CTS_FRAME_LEN * 8 + HH503_PLCP_HEADER_LEN_B + HH503_LONG_PREAMBLE_LEN_B)

#define HH503_LUT_READ_OPERN 0x0
#define HH503_LUT_WRITE_OPERN 0x1
#define HH503_LUT_REMOVE_OPERN 0x2
/* Time (in units of 10us) to wait for CE-LUT update operation to complete */
#define HH503_NUM_CE_LUT_UPDATE_ATTEMPTS 2

/*****************************************************************************/
/* Channel Access Timer Management Registers                                 */
/*****************************************************************************/
#define HH503_MAC_SEC_CHAN_SLOT_COUNT_INIT_VAL_FREQ_5 0x00000001
#define HH503_MAC_SEC_CHAN_SLOT_COUNT_INIT_VAL_FREQ_2 0x00000002

#define HH503_PHY_TX_MODE_DEFAULT 0x00000000

#ifdef _PRE_WLAN_DFT_STAT
/* 维测需要读取硬件寄存器的值，函数定义放在DFT的预编译宏下 */
#define HAL_DFT_REG_OTA_LEN 1024 /* 寄存器OTA上报的最大限制 */
#endif

#define BSRP_VAP_MAX 2

#define HH503_PA_LUT_UPDATE_TIMEOUT 2000
#define HH503_TX_SUSPEND_UPDATE_TIMEOUT 5000

#ifdef _PRE_WLAN_FEATURE_P2P
#define P2P_PERIOD_NOA_COUNT 255
#endif

static INLINE__ osal_u16 GetLow16Bits(osal_u32 value)
{
    return (osal_u16)(value & 0x0000FFFF);
}

static INLINE__ osal_u16 GetHigh16Bits(osal_u32 value)
{
    return (osal_u16)((value & 0xFFFF0000) >> 16);
}

/*****************************************************************************
  3 枚举定义
*****************************************************************************/
typedef enum {
    MAC_CTRL0_BANK, /* MAC寄存器 CTRL0 信息 */
    MAC_CTRL1_BANK, /* MAC寄存器 CTRL1 信息 */
    MAC_CTRL2_BANK, /* MAC寄存器 CTRL2 信息 */
    MAC_VLD_BANK,   /* MAC寄存器 vld 信息 */
    MAC_RD0_BANK,   /* MAC寄存器 RD0 信息（存在几字节信息不能读取） */
    MAC_RD1_BANK,   /* MAC寄存器 RD1 信息 */
    MAC_LUT0_BANK,  /* MAC寄存器 LUT0 信息 */
    MAC_WLMAC_CTRL, /* MAC寄存器 wlmac_ctrl 信息 */

    WITP_MAC_BANK_BUTT
}hh503_mac_bank_idx_enum;

/*****************************************************************************
  4 全局变量声明
*****************************************************************************/
#ifdef _PRE_WLAN_FEATURE_P2P
osal_u16 *get_noa_count(osal_void);
#endif

/*****************************************************************************
  STRUCT定义
*****************************************************************************/
typedef union {
    /* Define the struct bits  */
    struct {
        osal_u32 mcu_core_ch1_cr_ctrl : 9; /* [8..0] */
        osal_u32 reserved_0           : 3; /* [11..9] */
        osal_u32 mcu_core_ch_sel_sts  : 2; /* [13..12] */
        osal_u32 reserved_1           : 2; /* [15..14] */
    } bits;

    /* Define an unsigned member */
    osal_u32    u16;
} u_mcu_core_cr_ch1;

typedef union {
    /* Define the struct bits  */
    struct {
        osal_u32 com_bus_ch1_cr_ctrl : 9; /* [8..0] */
        osal_u32 reserved_0          : 3; /* [11..9] */
        osal_u32 com_bus_ch_sel_sts  : 2; /* [13..12] */
        osal_u32 reserved_1          : 2; /* [15..14] */
    } bits;

    /* Define an unsigned member */
    osal_u32    u16;
} u_com_bus_cr_ch1;

/* 寄存器中发送beacon、rts、null data等帧时设定phy mode寄存器的结构。
与描述符的结构有些差别，定义独立的结构区分开来。 */
typedef struct {
    osal_u32 tpc_ch0 : 8,
             dpd_tpc_lv_ch0    : 2,
             cfr_idx           : 2,
             reseved           : 20;
} hh503_tx_resp_phy_mode_reg_stru;

typedef union {
    struct {
        osal_u32 tx_vector_tpc_ch0 : 8;
        osal_u32 tx_vector_freq_bandwidth_mode : 2;
        osal_u32 tx_vector_smoothing : 1;
        osal_u32 tx_vector_channel_code : 1;
        osal_u32 reserved : 20;
    } bits;
    osal_u32 u32;
} hh503_tx_phy_mode_reg_stru;

typedef union {
    struct {
        osal_u32 tx_vector_he_ltf_type : 2;
        osal_u32 tx_vector_ant_sel : 2;
        osal_u32 tx_vector_tpc_dpd_lv_0 : 2;
        osal_u32 tx_vector_pe_duration : 3;
        osal_u32 tx_vector_dcm : 1;
        osal_u32 tx_vector_mcs_rate : 4;
        osal_u32 tx_vector_protocol_mode : 2;
        osal_u32 tx_vector_he_flag : 1;
        osal_u32 tx_vector_preamble_boost_flag : 1;
        osal_u32 tx_vector_preamble : 1;
        osal_u32 tx_vector_gi_type : 2;
        osal_u32 tx_vector_cfr_idx : 2;
        osal_u32 reserve           : 9;
    } bits;
    osal_u32 u32;
} hh503_tx_phy_rate_stru;

typedef union {
    struct {
        osal_u32 mcs_rate : 4;
        osal_u32 protocol_mode : 2;
        osal_u32 reserve : 2;
    } bits;
    osal_u8 u8;
} hal_phy_rate_stru;

typedef osal_void (*p_hh503_dft_report_all_reg_state_cb)(hal_to_dmac_device_stru *hal_device);
typedef osal_void (*p_hh503_enable_radar_det_cb)(osal_u8 enable);
typedef osal_void (*p_hh503_set_psm_listen_interval_count_cb)(hal_to_dmac_vap_stru *hal_vap,
    osal_u16 interval_count);

typedef struct {
    p_hh503_dft_report_all_reg_state_cb hh503_dft_report_all_reg_state;
    p_hh503_enable_radar_det_cb hh503_enable_radar_det;
} hal_mac_rom_cb;

/*****************************************************************************
 函 数 名  : hh503_get_vap_internal
 功能描述  : HAL内部获取VAP
*****************************************************************************/
static INLINE__ osal_void hh503_get_vap_internal(const hal_device_stru *device, osal_u8 vap_id,
    hal_to_dmac_vap_stru **hal_vap)
{
    /* 检查传入的vap id是否合理 */
    if (vap_id >= HAL_MAX_VAP_NUM) {
        *hal_vap = OAL_PTR_NULL;
        return;
    }
    *hal_vap = (hal_to_dmac_vap_stru *)(void *)(device->vap_list[vap_id]);
}

/*****************************************************************************
 函 数 名  : hh503_get_subband_index
 功能描述  : 获取subband
 调用函数  : hh503_rf_get_subband_idx_cb hh503_rf_get_subband_idx
*****************************************************************************/
static INLINE__ osal_u32 hh503_get_subband_index(wlan_channel_band_enum_uint8 band, osal_u8 channel_idx,
    osal_u8 *subband_idx)
{
    if (band == WLAN_BAND_5G) {
        /* ws73不支持5G */
        return OAL_FAIL;
    }
    if ((band == WLAN_BAND_2G) && (channel_idx >= HH503_RF_FREQ_2_CHANNEL_NUM)) {
        return OAL_FAIL;
    }
    *subband_idx = channel_idx;
    return OAL_SUCC;
}

/*****************************************************************************
 ROM回调函数类型定义
*****************************************************************************/
typedef osal_void (*hh503_cb_mac_init_hw)(osal_void);
typedef osal_void (*hh503_set_prot_resp_frame_chain_ext_cb)(hal_to_dmac_device_stru *hal_device,
    osal_u8 chain_val);
typedef osal_void (*hh503_set_extlna_chg_cfg_ext_cb)(hal_to_dmac_device_stru *hal_device,
    oal_bool_enum_uint8 extlna_chg_bypass);

typedef osal_void (*hh503_set_primary_channel_ext_cb)(hal_to_dmac_device_stru *hal_device, osal_u8 channel_num,
    wlan_channel_band_enum_uint8 band, osal_u8 channel_idx, wlan_channel_bandwidth_enum_uint8 bandwidth);
typedef osal_void (*hh503_reset_hw_macphy_cb)(osal_bool hw_reset);

/*****************************************************************************
  10 函数声明
*****************************************************************************/
hal_device_stru *hh503_chip_get_device(osal_void);
osal_void hh503_ce_clear_all(osal_void);
osal_void hh503_get_freq_factor(osal_u8 freq_band, osal_u8 channel_num, osal_u32 *freq_factor);
#ifdef _PRE_WLAN_DFT_STAT
osal_void hh503_dft_report_all_reg_state_rom_cb(hal_to_dmac_device_stru *hal_device);
#endif

osal_void hh503_set_psm_dtim_count_cb(hal_to_dmac_vap_stru *hal_vap, osal_u8 dtim_count);
osal_u32  hh503_enable_ce(osal_void);
osal_void hh503_write_phy_upc_reg(osal_u32 start_addr, const osal_u8 *data);
osal_void hh503_set_ctrl_frm_pow_code(osal_u32 phy_mode_addr, osal_u32 data_rate_addr, osal_u32 pow_code);
osal_void hh503_set_resp_pow_level(osal_char near_distance_rssi, osal_char far_distance_rssi);
osal_void hh503_set_extlna_chg_cfg_ext(hal_to_dmac_device_stru *hal_device, oal_bool_enum_uint8 extlna_chg_bypass);

osal_u32 hh503_wait_mac_done_timeout(osal_u32 reg_addr, osal_u32 bitmask, osal_u32 reg_busy_value,
    osal_u32 wait_10us_cnt);
/*****************************************************************************
 功能描述  : 根据tx描述符更新beacon_rate寄存器域
*****************************************************************************/
osal_void hal_chan_update_beacon_rate(hh503_tx_phy_rate_stru *beacon_rate, const hal_tx_ctrl_desc_rate_stru *tx_dscr);

/*****************************************************************************
 功能描述  : 恢复PA(Protocol accelerator)
*****************************************************************************/
osal_void hal_set_machw_tx_resume(osal_void);

/*****************************************************************************
 功能描述  : 设置multi bssid相关寄存器
*****************************************************************************/
osal_void hal_vap_set_multi_bssid(osal_u8 *trans_bssid, osal_u8 maxbssid_indicator);

#ifdef _PRE_WLAN_FEATURE_DAQ
#define HAL_MAC_DIAG_DAQ_OFFSET 0x10000000
osal_void hal_pkt_ram_sample_deinit(osal_void);
osal_void hal_sample_daq_prepare_data(osal_void);
osal_u32 hal_sample_daq_get_data(osal_u32 diag_read_addr);
oal_bool_enum_uint8 hal_sample_daq_done(osal_void);
osal_void hal_show_mac_daq_reg_cfg_info(osal_void);
osal_void hal_show_daq_done_reg_info(osal_void);
#endif
osal_void hal_al_tx_cca_bypass_enable(osal_u8 enable);
#ifdef _PRE_WIFI_DEBUG
osal_void hal_show_linkloss_reg_info(osal_void);
#endif
osal_void hal_vap_set_noa(const hal_to_dmac_vap_stru *hal_vap, osal_u32 start_tsf,
    osal_u32 duration, osal_u32 interval, osal_u8 count);
osal_void hal_set_frequency(osal_void);
osal_void hal_clear_mac_rts_statistics_data(osal_void);
osal_void hal_get_mac_rts_statistics_data(osal_u32 *rx_rts_num, osal_u32 *tx_rts_num);

#ifdef __cplusplus
#if __cplusplus
}
#endif
#endif

#endif /* end of hal_mac.h */
