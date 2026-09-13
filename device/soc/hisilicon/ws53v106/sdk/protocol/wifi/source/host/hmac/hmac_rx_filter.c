/*
 * Copyright (c) HiSilicon (Shanghai) Technologies Co., Ltd. 2014-2023. All rights reserved.
 * 文 件 名   : hmac_rx_filter.c
 * 生成日期   : 2014年7月14日
 * 功能描述   : 帧过滤处理文件
 */

/*****************************************************************************
  1 头文件包含
*****************************************************************************/
#include "wlan_spec.h"
#include "wlan_types_common.h"
#include "mac_device_ext.h"
#include "mac_resource_ext.h"
#include "dmac_ext_if_hcm.h"
#include "oal_netbuf_data.h"
#include "hmac_user.h"
#include "hmac_device.h"
#include "hmac_resource.h"
#include "hmac_rx_filter.h"

#ifdef __cplusplus
#if __cplusplus
extern "C" {
#endif
#endif

#undef THIS_FILE_ID
#define THIS_FILE_ID DIAG_FILE_ID_WIFI_HOST_HMAC_RX_FILTER_C

#undef THIS_MOD_ID
#define THIS_MOD_ID DIAG_MOD_ID_WIFI_HOST

/*****************************************************************************
  2 全局变量定义
*****************************************************************************/

/*****************************************************************************
  3 函数实现
*****************************************************************************/
/*****************************************************************************
 函 数 名  : hmac_calc_up_ap_num_etc
 功能描述  : 计算不处于inti状态的VAP个数
*****************************************************************************/
osal_u32 hmac_calc_up_ap_num_etc(hmac_device_stru *hmac_device)
{
    hmac_vap_stru                  *hmac_vap;
    osal_u8                      vap_idx;
    osal_u8                      up_ap_num = 0;

    for (vap_idx = 0; vap_idx < hmac_device->vap_num; vap_idx++) {
        hmac_vap = (hmac_vap_stru *)mac_res_get_hmac_vap(hmac_device->vap_id[vap_idx]);
        if (hmac_vap == OAL_PTR_NULL) {
            oam_error_log1(0, OAM_SF_SCAN, "{hmac_calc_up_ap_num_etc::hmac_vap null,vap_idx=%d.}",
                           hmac_device->vap_id[vap_idx]);
            continue;
        }

        if ((hmac_vap->vap_state != MAC_VAP_STATE_INIT) && (hmac_vap->vap_mode == WLAN_VAP_MODE_BSS_AP)) {
            up_ap_num++;
        } else if ((hmac_vap->vap_mode == WLAN_VAP_MODE_BSS_STA) && (hmac_vap->vap_state == MAC_VAP_STATE_UP)) {
            up_ap_num++;
        }
    }

    return up_ap_num;
}

/*****************************************************************************
 函 数 名  : hmac_rx_update_user_eapol_key_open
 功能描述  : 更新用户is_rx_eapol_key_open 标识。
             如果接收到的eapol-key 是open，设置is_rx_eapol_key_open OSAL_TRUE
             其他值，设置is_rx_eapol_key_open OSAL_FALSE
*****************************************************************************/
OSAL_STATIC osal_void hmac_rx_update_user_eapol_key_open(const hmac_vap_stru *hmac_vap, oal_netbuf_stru *netbuf)
{
    dmac_rx_ctl_stru *rx_cb;
    hmac_user_stru *hmac_user = OSAL_NULL;
    mac_eapol_header_stru *eapol_header = OSAL_NULL;

    rx_cb = (dmac_rx_ctl_stru *)oal_netbuf_cb(netbuf);
    if (is_sta(hmac_vap) && rx_cb->rx_status.dscr_status == HAL_RX_SUCCESS) {
        eapol_header = (mac_eapol_header_stru *)(oal_netbuf_rx_data(netbuf) + sizeof(mac_llc_snap_stru));
        if (hmac_is_eapol_key_ptk_etc(eapol_header) == OSAL_TRUE) {
            hmac_user = mac_res_get_hmac_user_etc(hmac_vap->assoc_vap_id);
            if (hmac_user == OSAL_NULL) {
                oam_warning_log2(0, OAM_SF_RX, "vap_id[%d] {hmac_rx_update_user_eapol_key_open::hmac_user:%d is null.}",
                                 hmac_vap->vap_id, hmac_vap->assoc_vap_id);
                return;
            }
            hmac_user->is_rx_eapol_key_open = (rx_cb->rx_status.cipher_protocol_type == HAL_NO_ENCRYP);

            oam_warning_log2(0, OAM_SF_RX, "vap_id[%d] hmac_rx_update_user_eapol_key_open::is_rx_eapol_key_open=%d",
                             hmac_vap->vap_id, hmac_user->is_rx_eapol_key_open);
        }
    }

    return;
}

/* VIP 关键帧上报 */
osal_void hmac_rx_process_frame_eapol_keyinfo(mac_ieee80211_frame_stru *frame_hdr,
    oal_netbuf_stru *curr_netbuf, const hmac_vap_stru *hmac_vap, const mac_rx_ctl_stru *rx_info,
    osal_u8 data_type)
{
    osal_u16 eapol_keyinfo = mac_get_eapol_keyinfo_etc(curr_netbuf);
    unref_param(frame_hdr);
    unref_param(rx_info);
    unref_param(eapol_keyinfo);

    if ((data_type == MAC_DATA_EAPOL) && (mac_get_eapol_type_etc(curr_netbuf) == OAL_EAPOL_TYPE_KEY)) {
        oam_warning_log2(0, OAM_SF_CONN, "vap_id[%d] {hmac_rx_process_frame_eapol_keyinfo::rx eapol, info is %x }",
                         hmac_vap->vap_id, oal_net2host_short(eapol_keyinfo));
        hmac_rx_update_user_eapol_key_open(hmac_vap, curr_netbuf);
    }
}

#ifdef __cplusplus
#if __cplusplus
}
#endif
#endif

