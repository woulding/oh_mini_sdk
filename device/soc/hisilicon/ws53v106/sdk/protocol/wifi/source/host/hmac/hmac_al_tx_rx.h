/*
 * Copyright (c) HiSilicon (Shanghai) Technologies Co., Ltd. 2020-2022. All rights reserved.
 * Description: hmac always tx or rx
 * Author:
 */

#ifndef __HMAC_AL_TX_RX_H__
#define __HMAC_AL_TX_RX_H__

#ifdef _PRE_WLAN_FEATURE_ALWAYS_TX
/*****************************************************************************
  1 其他头文件包含
*****************************************************************************/
#include "hmac_device.h"

#ifdef __cplusplus
#if __cplusplus
extern "C" {
#endif
#endif

osal_u32 hmac_config_send_qos_to_queue(hmac_vap_stru *hmac_vap, osal_u32 len, osal_u8 type);
oal_netbuf_stru* hmac_config_create_al_tx_packet(osal_u32 size, mac_rf_payload_enum_uint8 payload_flag);
osal_s32 hmac_al_tx_complete_event_handler(hmac_vap_stru *hmac_vap, frw_msg *msg);
osal_s32 hmac_config_set_always_rx(hmac_vap_stru *hmac_vap, frw_msg *msg);
osal_s32 hmac_config_set_always_tx(hmac_vap_stru *hmac_vap, frw_msg *msg);
osal_void hmac_set_al_tx_frame_type_switch(osal_u8 val);
osal_void hmac_set_al_tx_protocol(osal_u8 val);
osal_void hmac_set_al_tx_mcs(osal_u32 val);
osal_u8 hmac_get_al_tx_frame_type_switch(osal_void);
osal_u32 hmac_get_al_tx_mcs(osal_void);
osal_u8 hmac_get_al_tx_protocol(osal_void);
osal_s32 hmac_config_get_rx_ppdu_info(hmac_vap_stru *hmac_vap, frw_msg *msg);
static osal_u32 hmac_al_tx_rx_init_weakref(osal_void) __attribute__ ((weakref("hmac_al_tx_rx_init"), used));
static osal_void hmac_al_tx_rx_deinit_weakref(osal_void) __attribute__ ((weakref("hmac_al_tx_rx_deinit"), used));
osal_u32 hmac_config_set_pm_switch(const hmac_vap_stru *hmac_vap, osal_u8 len, const osal_u8 *param);
osal_void hmac_config_always_rx_set_hal(hal_to_dmac_device_stru *hal_device_base, osal_u8 switch_code);

#ifdef __cplusplus
#if __cplusplus
}
#endif
#endif

#endif
#endif
