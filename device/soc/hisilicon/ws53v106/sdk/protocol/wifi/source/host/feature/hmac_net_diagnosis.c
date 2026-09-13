/*
 * Copyright (c) HiSilicon (Shanghai) Technologies Co., Ltd. 2024-2024. All rights reserved.
 * 文 件 名   : hmac_net_diagnosis.c
 * 生成日期   : 2024年11月7日
 * 功能描述   : 网络诊断模块
 */
#include "hmac_net_diagnosis.h"
#ifdef _PRE_WLAN_FEATURE_STA_CHANNEL_SCORING
#include "hmac_sta_channel_scoring.h"
#endif
#include "hmac_user.h"
#include "hmac_feature_interface.h"
#include "hal_mfg.h"
#include "hmac_stat.h"
#include "hmac_feature_dft.h"
#include "hmac_ccpriv.h"
#include "common_dft.h"
#include "frw_util_notifier.h"
#include "hal_mac.h"
#ifdef __cplusplus
#if __cplusplus
extern "C" {
#endif
#endif

#ifdef _PRE_WLAN_FEATURE_NET_DIAGNOSIS

osal_u32 g_tx_from_lan_pkts_num = 0;
hmac_beacon_count_stru g_bcn_cnt = {0};
hmac_usr_rx_info_stru *g_usr_rx_info = OSAL_NULL;
hmac_stat_throughput_stru g_throughput = {0};
#ifdef _PRE_WLAN_FEATURE_STA_CHANNEL_SCORING
osal_u32 g_channel_score[MAC_CHANNEL_FREQ_2_BUTT] = {0};
#endif

OSAL_STATIC osal_u32 hmac_net_diagnosis_get_usr_idx_by_macaddr(hmac_vap_stru **hmac_vap, osal_u8 vap_type,
    osal_u16 *usr_idx, osal_u8 *mac_addr)
{
    hmac_device_stru *hmac_device = hmac_res_get_mac_dev_etc(0);

    if (vap_type == 0) {
        /* 0:sta */
        *hmac_vap = mac_find_up_legacy_sta_vap();
    } else if (vap_type == 1) {
        /* 1:ap */
        mac_device_find_up_ap_etc(hmac_device, hmac_vap);
    }

    if (*hmac_vap == OSAL_NULL) {
        return OAL_FAIL;
    }

    if (hmac_vap_find_user_by_macaddr_etc(*hmac_vap, mac_addr, usr_idx) != OAL_SUCC) {
        return OAL_FAIL;
    }

    return OAL_SUCC;
}

osal_void hmac_net_diagnosis_get_rx_fail_cnt(osal_u32 *mpdu_inampdu_cnt, osal_u32 *mpdu_cnt)
{
    hal_mac_rx_mpdu_statis_info_stru mac_rx_statis = {0};

    hal_get_mac_rx_statistics_data(&mac_rx_statis);

    *mpdu_inampdu_cnt = mac_rx_statis.rx_err_mpdu_inampdu_cnt;
    *mpdu_cnt = mac_rx_statis.rx_err_mpdu_cnt;

    return;
}

osal_void hmac_net_diagnosis_tx_from_lan_pkts_stat(osal_u8 vap_id, osal_u32 msdu_num)
{
    hmac_vap_stru *hmac_vap = mac_find_up_legacy_sta_vap();
    if (hmac_vap == OSAL_NULL || hmac_vap->vap_id != vap_id) {
        return;
    }

    g_tx_from_lan_pkts_num += msdu_num;
}

osal_s32 hmac_net_diagnosis_get_mac_frame_trx_info(mac_frame_trx_info_stru *info)
{
    osal_s32 ret;
    frw_msg msg_to_device = {0};
    osal_u32 device_vap_stat[DEVICE_VAP_STAT_NUM] = {0};
    dft_device_statis_cnt_stru device_hw_stat = {0};
    hmac_vap_stru *hmac_vap = mac_find_up_legacy_sta_vap();

    if (info == OSAL_NULL || hmac_vap == OSAL_NULL) {
        return OAL_FAIL;
    }

    /* 获取dmac侧hw统计结果 */
    frw_msg_init(&(hmac_vap->vap_id), sizeof(osal_u8), (osal_u8 *)&device_hw_stat,
        sizeof(dft_device_statis_cnt_stru), &msg_to_device);
    ret = frw_send_msg_to_device(hmac_vap->vap_id, WLAN_MSG_H2D_C_CFG_GET_HW_STAT, &msg_to_device, OSAL_TRUE);
    if (ret != OAL_SUCC) {
        return OAL_FAIL;
    }

    /* 获取dmac侧vap统计结果 */
    frw_msg_init(&(hmac_vap->vap_id), sizeof(osal_u8), (osal_u8 *)device_vap_stat,
        DEVICE_VAP_STAT_NUM * sizeof(osal_u32), &msg_to_device);
    ret = frw_send_msg_to_device(hmac_vap->vap_id, WLAN_MSG_H2D_C_CFG_GET_VAP_STAT, &msg_to_device, OSAL_TRUE);
    if (ret != OAL_SUCC) {
        return OAL_FAIL;
    }

    // 所有接收帧总数
    info->rx_total_num = device_hw_stat.rx_from_hw_mpdu_cnt;
    // 接收数据帧总数
    info->rx_data_num = device_vap_stat[RX_DEVICE_D_FROM_HW_MPDU - HOST_PKTS_CNT_TYPE_END];
    // 接收管理帧总数
    info->rx_mgmt_num = device_vap_stat[RX_DEVICE_M_FROM_HW_MPDU - HOST_PKTS_CNT_TYPE_END];
    // 发送成功的数据帧总数
    info->tx_succ_data_num = device_vap_stat[TX_DEVICE_D_COMPLETE_SUCC - HOST_PKTS_CNT_TYPE_END];
    // 发送成功的管理帧总数
    info->tx_mgmt_num = device_vap_stat[TX_DEVICE_M_COMPLETE_SUCC - HOST_PKTS_CNT_TYPE_END];
    // TX方向丢数据包
    info->tx_drop_data_num = g_tx_from_lan_pkts_num -
        device_vap_stat[TX_DEVICE_D_FROM_HMAC_MPDU - HOST_PKTS_CNT_TYPE_END];
    // 所有需要发送帧总数
    info->tx_total_data_num = info->tx_succ_data_num + info->tx_drop_data_num;

    /* RTS统计 */
    hal_get_mac_rts_statistics_data(&(info->rx_rts_num), &(info->tx_rts_num));

    return OAL_SUCC;
}

osal_s32 hmac_net_diagnosis_mac_frame_trx_info_clear(osal_void)
{
    frw_msg msg_to_device = {0};
    osal_u8 hw_stat_enable = OSAL_TRUE;
    dft_vap_statis_command_stru vap_statis_command = {0};
    oal_net_device_stru *netdev = OSAL_NULL;
    osal_s32 ret;
    hmac_vap_stru *hmac_vap = mac_find_up_legacy_sta_vap();

    if (hmac_vap == OSAL_NULL) {
        return OAL_FAIL;
    }

    g_tx_from_lan_pkts_num = 0;

    /* hw统计清零，重复使能会清零 */
    frw_msg_init(&hw_stat_enable, sizeof(osal_u8), OSAL_NULL, 0, &msg_to_device);
    ret = frw_send_msg_to_device(hmac_vap->vap_id, WLAN_MSG_H2D_C_CFG_ENABLE_HW_STAT, &msg_to_device, OSAL_TRUE);
    if (ret != OAL_SUCC) {
        return OAL_FAIL;
    }

    /* vap统计清零，重复使能会清零 */
    vap_statis_command.enable = OSAL_TRUE;
    vap_statis_command.vap_id = hmac_vap->vap_id;
    frw_msg_init((osal_u8 *)&vap_statis_command, sizeof(dft_vap_statis_command_stru), OSAL_NULL, 0, &msg_to_device);
    ret = frw_send_msg_to_device(0, WLAN_MSG_H2D_C_CFG_ENABLE_VAP_STAT, &msg_to_device, OSAL_TRUE);
    if (ret != OAL_SUCC) {
        return OAL_FAIL;
    }

    /* RTS统计清零 */
    hal_clear_mac_rts_statistics_data();

    return OAL_SUCC;
}

osal_void hmac_net_diagnosis_clear_pm_bcn_cnt(osal_void)
{
    dft_pm_debug_info_stru bcn_stat;
    frw_msg msg_to_device = {0};
    osal_u8 flag = PM_DEBUG_CLEAR_BCN_DEBUG_INFO;

    (osal_void)memset_s(&bcn_stat, sizeof(dft_pm_debug_info_stru), 0, sizeof(dft_pm_debug_info_stru));
    frw_msg_init((osal_u8 *)&flag, sizeof(flag), (osal_u8 *)&bcn_stat, sizeof(bcn_stat), &msg_to_device);
    frw_send_msg_to_device(0, WLAN_MSG_H2D_C_CFG_GET_PM_DEBUG_INFO, &msg_to_device, OSAL_TRUE);
}

OSAL_STATIC osal_void hmac_diag_get_bcn_cnt_pm(const hmac_vap_stru *hmac_vap, osal_u64 *bcn_succ, osal_u64 *bcn_fail)
{
    dft_pm_debug_info_stru bcn_stat;
    frw_msg msg_to_device = {0};
    osal_u8 flag = PM_DEBUG_GET_DEBUG_INFO | PM_DEBUG_CLEAR_BCN_DEBUG_INFO;

    if ((hmac_vap == OSAL_NULL) || (bcn_succ == OSAL_NULL) || (bcn_fail == OSAL_NULL) ||
        (g_bcn_cnt.record_flag == OSAL_FALSE)) {
        return;
    }

    g_bcn_cnt.record_flag = OSAL_FALSE;

    (osal_void)memset_s(&bcn_stat, sizeof(dft_pm_debug_info_stru), 0, sizeof(dft_pm_debug_info_stru));
    frw_msg_init((osal_u8 *)&flag, sizeof(osal_u8), (osal_u8 *)&bcn_stat, sizeof(dft_pm_debug_info_stru),
        &msg_to_device);
    frw_send_msg_to_device(0, WLAN_MSG_H2D_C_CFG_GET_PM_DEBUG_INFO, &msg_to_device, OSAL_TRUE);

    *bcn_succ = (osal_u64)(bcn_stat.tbtt_cnt - bcn_stat.sleep_debug_cnt[HAL_PM_NOT_SLEEP_BCN_TIMEOUT]);
    *bcn_fail = (osal_u64)bcn_stat.sleep_debug_cnt[HAL_PM_NOT_SLEEP_BCN_TIMEOUT];
}

OSAL_STATIC osal_void hmac_diag_get_bcn_cnt_wake(const hmac_vap_stru *hmac_vap, osal_u64 *bcn_succ, osal_u64 *bcn_fail)
{
    osal_u64 curr_time = osal_get_time_stamp_ms();
    osal_u64 bcn_total_cnt = 0;
    osal_u64 bcn_fail_cnt = 0;
    osal_u32 time_h, time_l;

    if ((hmac_vap == OSAL_NULL) || (bcn_succ == OSAL_NULL) || (bcn_fail == OSAL_NULL) ||
        (g_bcn_cnt.record_flag == OSAL_FALSE)) {
        return;
    }

    g_bcn_cnt.record_flag = OSAL_FALSE;
    time_h = (osal_u32)((curr_time - g_bcn_cnt.start_timestamp) >> 32); /* 32:右移32位 */
    time_h /= mac_mib_get_beacon_period(hmac_vap);
    time_l = (osal_u32)((curr_time - g_bcn_cnt.start_timestamp) & 0xffffffff);
    time_l /= mac_mib_get_beacon_period(hmac_vap);
    bcn_total_cnt = osal_makeu64(time_l, time_h);
    /* 消除精度导致的误差 */
    if (bcn_total_cnt < g_bcn_cnt.bcn_cnt) {
        bcn_total_cnt = g_bcn_cnt.bcn_cnt;
    }
    bcn_fail_cnt = bcn_total_cnt - g_bcn_cnt.bcn_cnt;

    *bcn_succ = g_bcn_cnt.bcn_cnt;
    *bcn_fail = bcn_fail_cnt;

    return;
}

osal_void hmac_net_diagnosis_clear_bcn_cnt(osal_void)
{
    osal_u64 bcn_succ, bcn_total;
    hmac_vap_stru *hmac_vap = mac_find_up_legacy_sta_vap();

    if (mac_mib_get_powermanagementmode(hmac_vap) == WLAN_MIB_PWR_MGMT_MODE_PWRSAVE) {
        hmac_net_diagnosis_clear_pm_bcn_cnt();
    } else {
        g_bcn_cnt.bcn_cnt = 0;
        g_bcn_cnt.start_timestamp = osal_get_time_stamp_ms();
    }
}

osal_void hmac_net_diagnosis_update_bcn_stat(hmac_vap_stru *hmac_vap)
{
    if (g_bcn_cnt.record_flag == OSAL_FALSE) {
        return;
    }
    /* 只清host侧统计，device统计开关低功耗会自己清零 */
    if (mac_mib_get_powermanagementmode(hmac_vap) != WLAN_MIB_PWR_MGMT_MODE_PWRSAVE) {
        g_bcn_cnt.bcn_cnt = 0;
        g_bcn_cnt.start_timestamp = osal_get_time_stamp_ms();
    }
}

osal_bool hmac_net_diagnosis_bcn_cnt_inc(osal_void *notify_data)
{
    hmac_vap_stru *hmac_vap = (hmac_vap_stru *)notify_data;

    /* 非低功耗场景beacon接收个数统计 */
    if (g_bcn_cnt.record_flag == OSAL_TRUE &&
        mac_mib_get_powermanagementmode(hmac_vap) != WLAN_MIB_PWR_MGMT_MODE_PWRSAVE) {
        g_bcn_cnt.bcn_cnt++;
    }
    return OAL_TRUE;
}

osal_void hmac_net_diagnosis_start_record_bcn_cnt(osal_void)
{
    hmac_net_diagnosis_clear_bcn_cnt();
    g_bcn_cnt.record_flag = OSAL_TRUE;
    return;
}

osal_void hmac_net_diagnosis_get_bcn_stat(const hmac_vap_stru *hmac_vap, osal_u64 *bcn_succ, osal_u64 *bcn_fail)
{
    if (mac_mib_get_powermanagementmode(hmac_vap) == WLAN_MIB_PWR_MGMT_MODE_PWRSAVE) {
        hmac_diag_get_bcn_cnt_pm(hmac_vap, bcn_succ, bcn_fail);
    } else {
        hmac_diag_get_bcn_cnt_wake(hmac_vap, bcn_succ, bcn_fail);
    }
}

osal_bool hmac_net_diagnosis_update_throughput(osal_void *notify_data)
{
    hmac_stat_throughput_stru *throughput = (hmac_stat_throughput_stru *)notify_data;

    g_throughput.tx_throughput_mbps = throughput->tx_throughput_mbps;
    g_throughput.rx_throughput_mbps = throughput->rx_throughput_mbps;

    return OAL_TRUE;
}

osal_u32 hmac_net_diagnosis_get_tx_throughput(osal_void)
{
    return g_throughput.tx_throughput_mbps;
}

osal_u32 hmac_net_diagnosis_get_rx_throughput(osal_void)
{
    return g_throughput.rx_throughput_mbps;
}

#ifdef _PRE_WLAN_FEATURE_WS73
osal_s16 hmac_net_diagnosis_get_chip_temp(osal_void)
{
    osal_s16 temperature = 0;

    uapi_tsensor_read_temperature(&temperature);
    return temperature;
}
#endif

WIFI_HMAC_TCM_TEXT WIFI_TCM_TEXT OAL_STATIC osal_bool hmac_net_diagnosis_rx_info_record(osal_void *notify_data)
{
    hmac_user_stru *hmac_user = OSAL_NULL;
    dmac_rx_ctl_stru *cb_ctrl = (dmac_rx_ctl_stru *)notify_data;
    osal_u8 id = cb_ctrl->rx_info.ta_user_idx;

    if (id > WLAN_USER_MAX_USER_LIMIT || g_usr_rx_info == OSAL_NULL) {
        return OAL_TRUE;
    }

    hmac_user = (hmac_user_stru *)mac_res_get_hmac_user_etc(id);
    if (hmac_user == OSAL_NULL) {
        return OAL_TRUE;
    }

    if (cb_ctrl->rx_status.he_flag != 0) {
        g_usr_rx_info[id].protocol = WLAN_HE_SU_FORMAT;
        g_usr_rx_info[id].nss_mode = cb_ctrl->rx_statistic.nss_rate.he_nss_mcs.nss_mode;
    } else {
        g_usr_rx_info[id].protocol = cb_ctrl->rx_statistic.nss_rate.legacy_rate.protocol_mode;
    }

    if (g_usr_rx_info[id].protocol == WLAN_HT_PHY_PROTOCOL_MODE) {
        g_usr_rx_info[id].nss_rate = cb_ctrl->rx_statistic.nss_rate.ht_rate.ht_mcs;
    } else {
        g_usr_rx_info[id].nss_rate = cb_ctrl->rx_statistic.nss_rate.legacy_rate.legacy_rate;
    }
    g_usr_rx_info[id].snr_ant0 = cb_ctrl->rx_statistic.snr_ant0;

    return OAL_TRUE;
}

osal_void hmac_net_diagnosis_get_snr(osal_u8 *mac_addr, osal_s8 *snr, osal_u8 vap_type)
{
    hmac_vap_stru *hmac_vap = OSAL_NULL;
    osal_u16 usr_idx;

    if (hmac_net_diagnosis_get_usr_idx_by_macaddr(&hmac_vap, vap_type, &usr_idx, mac_addr) != OAL_SUCC) {
        return;
    }

    /* SNR单位需要做转换，从报文描述符中取出的SNR单位不是dBm */
    hal_phy_rx_get_snr_info(hal_chip_get_hal_device(), (uint8_t)g_usr_rx_info[usr_idx].protocol,
        (osal_u16)g_usr_rx_info[usr_idx].snr_ant0, snr);
    return;
}

osal_s32 hmac_net_diagnosis_get_rx_rate(osal_u8 *mac_addr, osal_u32 *rx_rate, osal_u8 vap_type)
{
    hmac_vap_stru *hmac_vap = OSAL_NULL;
    osal_u16 usr_idx;

    if (g_usr_rx_info == OSAL_NULL ||
        hmac_net_diagnosis_get_usr_idx_by_macaddr(&hmac_vap, vap_type, &usr_idx, mac_addr) != OAL_SUCC) {
        return OAL_FAIL;
    }

    *rx_rate = g_usr_rx_info[usr_idx].nss_rate;
    return OAL_SUCC;
}

osal_s32 hmac_net_diagnosis_enable_user_rate(osal_u8 enable)
{
    frw_msg tx_cfg_info;
    osal_s32 ret;

    if (enable == 0) {
        if (g_usr_rx_info != OSAL_NULL) {
            osal_kfree(g_usr_rx_info);
            g_usr_rx_info = OSAL_NULL;
        }

        frw_msg_init((osal_u8 *)&enable, sizeof(osal_u8), OSAL_NULL, 0, &tx_cfg_info);
        ret = send_cfg_to_device(0, WLAN_MSG_H2D_C_CFG_USER_RATE_ENABLE, &tx_cfg_info, OSAL_TRUE);
        if (OAL_UNLIKELY(ret != OAL_SUCC)) {
            return OAL_FAIL;
        }
        return OAL_SUCC;
    }

    if (g_usr_rx_info == OSAL_NULL) {
        g_usr_rx_info = (hmac_usr_rx_info_stru *)osal_kmalloc(
            WLAN_USER_MAX_USER_LIMIT * sizeof(hmac_usr_rx_info_stru), OAL_TRUE);
        if (OAL_UNLIKELY(g_usr_rx_info == OSAL_NULL)) {
            return OAL_FAIL;
        }
        (osal_void)memset_s((osal_u8 *)g_usr_rx_info, WLAN_USER_MAX_USER_LIMIT * sizeof(hmac_usr_rx_info_stru),
            0, WLAN_USER_MAX_USER_LIMIT * sizeof(hmac_usr_rx_info_stru));

        frw_msg_init((osal_u8 *)&enable, sizeof(osal_u8), OSAL_NULL, 0, &tx_cfg_info);
        ret = frw_send_msg_to_device(0, WLAN_MSG_H2D_C_CFG_USER_RATE_ENABLE, &tx_cfg_info, OSAL_TRUE);
        if (ret != OAL_SUCC) {
            osal_kfree(g_usr_rx_info);
            g_usr_rx_info = OSAL_NULL;
            return OAL_FAIL;
        }
    }
    return OAL_SUCC;
}

osal_s32 hmac_net_diagnosis_get_tx_rate(osal_u8 *mac_addr, osal_u32 *tx_rate, osal_u8 vap_type)
{
    osal_u16 usr_idx;
    mac_cfg_tx_user_rate_stru tx_user_rate_fill;
    frw_msg tx_cfg_info;
    hmac_vap_stru *hmac_vap = OSAL_NULL;
    osal_s32 ret;

    if (hmac_net_diagnosis_get_usr_idx_by_macaddr(&hmac_vap, vap_type, &usr_idx, mac_addr) != OAL_SUCC) {
        return OAL_FAIL;
    }

    (osal_void)memset_s(&tx_user_rate_fill, sizeof(mac_cfg_tx_user_rate_stru), 0, sizeof(mac_cfg_tx_user_rate_stru));

    frw_msg_init((osal_u8 *)&usr_idx, OAL_SIZEOF(osal_u16),
        (osal_u8 *)&tx_user_rate_fill, OAL_SIZEOF(mac_cfg_tx_user_rate_stru), &tx_cfg_info);
    ret = send_cfg_to_device(hmac_vap->vap_id, WLAN_MSG_H2D_C_CFG_GET_TX_USER_RATE_INFO, &tx_cfg_info, OSAL_TRUE);
    if (OAL_UNLIKELY(ret != OAL_SUCC)) {
        return OAL_FAIL;
    }
    *tx_rate = tx_user_rate_fill.nss_rate;
    return OAL_SUCC;
}

osal_u32 hmac_net_diagnosis_get_best_rate(osal_u8 *mac_addr, osal_u32 *phy_rate, osal_u8 vap_type)
{
    hmac_vap_stru *hmac_vap = OSAL_NULL;
    mac_cfg_ar_tx_params_stru ar_tx_params;
    mac_cfg_ar_tx_params_stru rsp_info;
    frw_msg cfg_info;
    osal_u16 user_id;
    osal_s32 ret;

    if (hmac_net_diagnosis_get_usr_idx_by_macaddr(&hmac_vap, vap_type, &user_id, mac_addr) != OAL_SUCC) {
        return OAL_FAIL;
    }

    (osal_void)memset_s(&ar_tx_params, sizeof(mac_cfg_ar_tx_params_stru), 0, sizeof(mac_cfg_ar_tx_params_stru));
    (osal_void)memset_s(&rsp_info, sizeof(mac_cfg_ar_tx_params_stru), 0, sizeof(mac_cfg_ar_tx_params_stru));

    ar_tx_params.user_id = user_id;
    frw_msg_init((osal_u8 *)&ar_tx_params, OAL_SIZEOF(mac_cfg_ar_tx_params_stru),
        (osal_u8 *)&rsp_info, OAL_SIZEOF(mac_cfg_ar_tx_params_stru), &cfg_info);
    ret = send_cfg_to_device(hmac_vap->vap_id, WLAN_MSG_H2D_C_CFG_GET_TX_PARAMS, &cfg_info, OSAL_TRUE);
    if ((ret != OAL_SUCC) || (cfg_info.rsp == OSAL_NULL)) {
        return (osal_u32)ret;
    }

    return rsp_info.tx_best_rate;
}

#ifdef _PRE_WLAN_FEATURE_STA_CHANNEL_SCORING
osal_bool hmac_net_diagnosis_update_channel_score(osal_void *notify_data)
{
    osal_u32 *channel_score = (osal_u32 *)notify_data;
    if (channel_score == OSAL_NULL) {
        return OAL_FALSE;
    }

    (osal_void)memcpy_s(g_channel_score, MAC_CHANNEL_FREQ_2_BUTT * sizeof(osal_u32), channel_score,
        MAC_CHANNEL_FREQ_2_BUTT * sizeof(osal_u32));
    return OAL_TRUE;
}

osal_void hmac_net_diagnosis_get_channel_score(osal_u32 *channel_score)
{
    hmac_vap_stru *hmac_vap = mac_find_up_legacy_sta_vap();

    if ((channel_score == OSAL_NULL) || (hmac_vap == OSAL_NULL)) {
        return;
    }
    /* 触发一次信道评分 60s内需要有一次全信道扫描 */
    if (hmac_cal_channel_score(hmac_vap, OSAL_NULL) != OAL_SUCC) {
        return;
    }

    (osal_void)memcpy_s(channel_score, MAC_CHANNEL_FREQ_2_BUTT * sizeof(osal_u32), g_channel_score,
        MAC_CHANNEL_FREQ_2_BUTT * sizeof(osal_u32));
    return;
}
#endif

OAL_STATIC osal_s32 hmac_net_diagnosis_get_retry_ratio(hmac_vap_stru *hmac_vap,
    retry_ratio_report_stru *retry_ratio_stat)
{
    frw_msg msg;

    frw_msg_init(OSAL_NULL, 0, (osal_u8 *)retry_ratio_stat, OAL_SIZEOF(retry_ratio_report_stru), &msg);
    if (frw_send_msg_to_device(hmac_vap->vap_id, WLAN_MSG_H2D_C_CFG_GET_RETRY_RATIO, &msg, OSAL_TRUE) != OAL_SUCC) {
        return OAL_FAIL;
    }

    return OAL_SUCC;
}

OAL_STATIC osal_s32 hmac_net_diagnosis_get_tid_info(osal_void)
{
    hmac_tid_stru *tid_queue = OAL_PTR_NULL;
    hmac_user_stru *hmac_user = OAL_PTR_NULL;
    struct osal_list_head *entry = OAL_PTR_NULL;
    struct osal_list_head *dlist_tmp = OAL_PTR_NULL;
    osal_u32 tid;
    hmac_vap_stru *hmac_vap = mac_find_up_legacy_sta_vap();

    /* 判断当前的vap_id下是否有user */
    if (hmac_vap == OSAL_NULL || hmac_vap->user_nums == 0) {
        return OAL_FAIL;
    }

    osal_list_for_each_safe(entry, dlist_tmp, &(hmac_vap->mac_user_list_head)) {
        hmac_user = osal_list_entry(entry, hmac_user_stru, user_dlist);
        if (hmac_user == OAL_PTR_NULL) {
            continue;
        }

        for (tid = 0; tid < WLAN_TID_MAX_NUM; tid++) {
            tid_queue = &(hmac_user->tx_tid_queue[tid]);
            wifi_printf_always("tid_info tid[%u]::mpdu_num[%u] tid_buffer_frame_len[%u].\r\n", tid, tid_queue->mpdu_num,
                tid_queue->tid_buffer_frame_len);
        }
    }
    return OAL_SUCC;
}

osal_s32 hmac_config_enable_stat(hmac_vap_stru *hmac_vap, frw_msg *msg)
{
    unref_param(hmac_vap);
    hmac_net_diagnosis_mac_frame_trx_info_clear();
    hmac_net_diagnosis_start_record_bcn_cnt();
    hmac_net_diagnosis_enable_user_rate(OSAL_TRUE);

    return OAL_SUCC;
}

osal_s32 hmac_config_get_stat(hmac_vap_stru *hmac_vap, frw_msg *msg)
{
    mac_statistics_stru info = {0};
    osal_u8 vap_type = 0;

    /* 报文tx/rx统计 */
    (osal_void)hmac_net_diagnosis_get_mac_frame_trx_info(&info.trx_info);

    /* beacon接收成功率统计 */
    hmac_net_diagnosis_get_bcn_stat(hmac_vap, &(info.bcn_stat.bcn_succ), &(info.bcn_stat.bcn_fail));

    /* 协商速率，信噪比统计 */
    hmac_net_diagnosis_get_snr(hmac_vap->bssid, &(info.user_rate_stat.snr), vap_type);
    hmac_net_diagnosis_get_rx_rate(hmac_vap->bssid, &(info.user_rate_stat.rx_rate), vap_type);
    hmac_net_diagnosis_get_tx_rate(hmac_vap->bssid, &(info.user_rate_stat.tx_rate), vap_type);

    /* 重传率统计 */
    hmac_net_diagnosis_get_retry_ratio(hmac_vap, &(info.retry_ratio_stat));

    /* 打印TID信息 */
    hmac_net_diagnosis_get_tid_info();

    msg->rsp_len = (osal_u16)sizeof(mac_statistics_stru);
    if (memcpy_s(msg->rsp, msg->rsp_buf_len, (osal_u8 *)&info,
        sizeof(mac_statistics_stru)) != EOK) {
        return OAL_FAIL;
    }

    /* beacon接收成功率重新统计 */
    hmac_net_diagnosis_start_record_bcn_cnt();
    return OAL_SUCC;
}

osal_u32 hmac_net_diagnosis_init(osal_void)
{
    g_bcn_cnt.record_flag = OSAL_FALSE;

    frw_util_notifier_register(WLAN_UTIL_NOTIFIER_EVENT_RX_BEACON, hmac_net_diagnosis_bcn_cnt_inc);
    frw_util_notifier_register(WLAN_UTIL_NOTIFIER_EVENT_USER_RATE_RX_INFO, hmac_net_diagnosis_rx_info_record);
    frw_util_notifier_register(WLAN_UTIL_NOTIFIER_EVENT_STAT_THROUGHPUT, hmac_net_diagnosis_update_throughput);
    frw_util_notifier_register(WLAN_UTIL_NOTIFIER_EVENT_CHANNEL_SCORE, hmac_net_diagnosis_update_channel_score);

    return OAL_SUCC;
}

osal_void hmac_net_diagnosis_deinit(osal_void)
{
    frw_util_notifier_unregister(WLAN_UTIL_NOTIFIER_EVENT_RX_BEACON, hmac_net_diagnosis_bcn_cnt_inc);
    frw_util_notifier_unregister(WLAN_UTIL_NOTIFIER_EVENT_USER_RATE_RX_INFO, hmac_net_diagnosis_rx_info_record);
    frw_util_notifier_unregister(WLAN_UTIL_NOTIFIER_EVENT_STAT_THROUGHPUT, hmac_net_diagnosis_update_throughput);
    frw_util_notifier_unregister(WLAN_UTIL_NOTIFIER_EVENT_CHANNEL_SCORE, hmac_net_diagnosis_update_channel_score);

    return;
}

#endif /* _PRE_WLAN_FEATURE_NET_DIAGNOSIS */

#ifdef __cplusplus
#if __cplusplus
}
#endif
#endif