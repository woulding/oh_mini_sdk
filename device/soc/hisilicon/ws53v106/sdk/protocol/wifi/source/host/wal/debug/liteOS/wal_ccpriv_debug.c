/*
 * Copyright (c) HiSilicon (Shanghai) Technologies Co., Ltd. 2019-2022. All rights reserved.
 * Description: Wal_ccpriv configuration command.
 */

/*****************************************************************************
  1 头文件包含
*****************************************************************************/
#include "wal_ccpriv.h"
#include "wifi_main.h"
#include "oal_ext_if.h"
#include "oam_ext_if.h"
#include "hmac_ext_if.h"

#ifdef _PRE_WLAN_CFGID_DEBUG
#include "wlan_msg.h"
#endif

#include "wal_common.h"
#include "wal_main.h"
#include "wal_ioctl.h"
#include "wal_event_msg.h"
#include "wal_11d.h"
#include "wal_net.h"
#include "oal_util.h"
#include "oal_net.h"
#include "soc_customize_wifi.h"
#include "hmac_config.h"
#include "wal_liteos_sdp.h"

#ifndef _PRE_WLAN_FEATURE_MFG_ONLY
#include "wal_cfg80211_apt.h"
#include "lwip/netifapi.h"
#endif
#include "soc_wifi_api.h"
#include "soc_wifi_mfg_test_if.h"

#include "soc_wifi_driver_wpa_if.h"
#include "hmac_scan.h"

#include "hmac_11v.h"

#ifdef _PRE_WLAN_FEATURE_WOW
#include "hmac_wow.h"
#endif
#include "hmac_m2u.h"
#ifdef _PRE_WLAN_FEATURE_DFX_CHR
#include "hmac_chr.h"
#endif
#include "hmac_feature_dft.h"
#ifdef _PRE_WLAN_FEATURE_FTM
#include "hmac_ftm.h"
#endif
#include "hmac_csa_ap.h"
#include "hmac_sdp.h"
#include "hmac_slp.h"
#ifdef _PRE_WLAN_FEATURE_DHCP_OFFLOAD
#include "msg_wow_rom.h"
#endif
#include "msg_dft_rom.h"
#include "msg_alg_rom.h"
#ifdef _PRE_WLAN_FEATURE_STA_PM
#include "msg_psm_rom.h"
#endif
#ifndef _PRE_WLAN_FEATURE_WS73
#include "debug_print.h"
#endif
#include "hmac_11k.h"

#ifdef __cplusplus
#if __cplusplus
extern "C" {
#endif
#endif

#undef  THIS_FILE_ID
#define THIS_FILE_ID DIAG_FILE_ID_WIFI_HOST_WAL_CCPRIV_DEBUG_C

#undef THIS_MOD_ID
#define THIS_MOD_ID DIAG_MOD_ID_WIFI_HOST

#ifdef _PRE_WLAN_CFGID_DEBUG
#define MAX_AP_USER_AGING_TIME 600
#define SET_APP_IE_CMD_PAYLOAD_LEN (MAC_IE_HDR_LEN + MAC_OUI_LEN + MAC_OUITYPE_LEN)
#define bw_enum_to_number(bw)  ((bw) == 0 ? 20 : (bw) == 1 ? 40 : 80)

OAL_STATIC osal_u32 ccpriv_addba_req_parse(osal_s8 *param, mac_cfg_addba_req_param_stru *addba_req)
{
    osal_u32 off_set;
    osal_u32 ret;
    osal_s8 name[WAL_CCPRIV_CMD_NAME_MAX_LEN] = {0};

    /* 获取mac地址 */
    ret = wal_get_cmd_one_arg(param, name, OAL_SIZEOF(name), &off_set);
    if (ret != OAL_SUCC) {
        oam_warning_log1(0, OAM_SF_ANY, "{ccpriv_addba_req_parse::wal_get_cmd_one_arg err_code [%u]!}", ret);
        return ret;
    }

    oal_strtoaddr((const osal_s8 *)name, addba_req->mac_addr);
    /* 偏移，取下一个参数 */
    param = param + off_set;

    /* 获取tid */
    ret = wal_cmd_get_u8_with_check_max(&param, WLAN_TID_MAX_NUM - 1, &addba_req->tidno);
    if (ret != OAL_SUCC) {
        oam_warning_log1(0, OAM_SF_ANY, "{ccpriv_addba_req_parse::error!tidno is [%u]!}", addba_req->tidno);
        return ret;
    }

    /* 获取ba_policy */
    ret = wal_get_cmd_one_arg(param, name, OAL_SIZEOF(name), &off_set);
    if (ret != OAL_SUCC) {
        oam_warning_log1(0, OAM_SF_ANY, "{ccpriv_addba_req_parse::wal_get_cmd_one_arg err_code [%u]!}", ret);
        return ret;
    }

    addba_req->ba_policy = (osal_u8)oal_atoi((const osal_s8 *)name);
    if (addba_req->ba_policy != MAC_BA_POLICY_IMMEDIATE) {
        oam_warning_log1(0, OAM_SF_ANY, "{ccpriv_addba_req_parse::error! ba_policy is[%u]!}", addba_req->ba_policy);
        return OAL_ERR_CODE_INVALID_CONFIG;
    }

    param = param + off_set;

    /* 获取buffsize */
    ret = wal_get_cmd_one_arg(param, name, OAL_SIZEOF(name), &off_set);
    if (ret != OAL_SUCC) {
        oam_warning_log1(0, OAM_SF_ANY, "{ccpriv_addba_req_parse::wal_get_cmd_one_arg err_code [%u]!}", ret);
        return ret;
    }

    addba_req->buff_size = (osal_u16)oal_atoi((const osal_s8 *)name);

    param = param + off_set;

    /* 获取timeout时间 */
    ret = wal_get_cmd_one_arg(param, name, OAL_SIZEOF(name), &off_set);
    if (ret != OAL_SUCC) {
        oam_warning_log1(0, OAM_SF_ANY, "{ccpriv_addba_req_parse::wal_get_cmd_one_arg err_code [%d]!}", ret);
        return ret;
    }

    addba_req->timeout = (osal_u16)oal_atoi((const osal_s8 *)name);
    return OAL_CONTINUE;
}

OAL_STATIC osal_u32 uapi_ccpriv_addba_req(oal_net_device_stru *net_dev, osal_s8 *param)
{
    osal_s32 l_ret;
    mac_cfg_addba_req_param_stru *addba_req = OAL_PTR_NULL;
    osal_u32 ret;
    mac_cfg_addba_req_param_stru cfg_addba_req;

    (osal_void)memset_s(&cfg_addba_req, OAL_SIZEOF(cfg_addba_req), 0, OAL_SIZEOF(cfg_addba_req));
    addba_req = &cfg_addba_req;

    /*
        "addba_req xx xx xx xx xx xx(mac地址) tidno ba_policy buffsize timeout"
    */
    ret = ccpriv_addba_req_parse(param, addba_req);
    if (ret != OAL_CONTINUE) {
        return ret;
    }

    l_ret = wal_sync_post2hmac_no_rsp(wal_util_get_vap_id(net_dev), WLAN_MSG_W2H_CFG_ADDBA_REQ,
        (osal_u8 *)&cfg_addba_req, OAL_SIZEOF(cfg_addba_req));
    if (OAL_UNLIKELY(l_ret != OAL_SUCC)) {
        oam_warning_log1(0, OAM_SF_ANY, "{uapi_ccpriv_addba_req::return err code[%d]!}", l_ret);
        return (osal_u32)l_ret;
    }

    return OAL_SUCC;
}

OAL_STATIC osal_u32 uapi_ccpriv_delba_req(oal_net_device_stru *net_dev, osal_s8 *param)
{
    osal_u32 off_set;
    osal_s8 name[WAL_CCPRIV_CMD_NAME_MAX_LEN] = {0};
    osal_s32 l_ret;
    osal_u32 ret;

    mac_cfg_delba_req_param_stru *delba_req_param = OAL_PTR_NULL;
    mac_cfg_delba_req_param_stru cfg_delba_req_param;

    (osal_void)memset_s(&cfg_delba_req_param, OAL_SIZEOF(cfg_delba_req_param), 0, OAL_SIZEOF(cfg_delba_req_param));
    delba_req_param = &cfg_delba_req_param;

    /* 获取mac地址 */
    ret = wal_get_cmd_one_arg(param, name, OAL_SIZEOF(name), &off_set);
    if (ret != OAL_SUCC) {
        oam_warning_log1(0, OAM_SF_ANY, "{uapi_ccpriv_delba_req::wal_get_cmd_one_arg err_code [%u]!}", ret);
        return ret;
    }

    oal_strtoaddr((const osal_s8 *)name, delba_req_param->mac_addr);
    /* 偏移，取下一个参数 */
    param = param + off_set;

    /* 获取tid */
    ret = wal_cmd_get_u8_with_check_max(&param, WLAN_TID_MAX_NUM - 1, &delba_req_param->tidno);
    if (ret != OAL_SUCC) {
        oam_warning_log1(0, OAM_SF_ANY, "{uapi_ccpriv_delba_req::tidno[%u] is error!}", delba_req_param->tidno);
        return ret;
    }

    /* 获取direction */
    ret = wal_get_cmd_one_arg(param, name, OAL_SIZEOF(name), &off_set);
    if (ret != OAL_SUCC) {
        oam_warning_log1(0, OAM_SF_ANY, "{uapi_ccpriv_delba_req::wal_get_cmd_one_arg err_code [%u]!}", ret);
        return ret;
    }

    delba_req_param->direction = (osal_u8)oal_atoi((const osal_s8 *)name);
    if (delba_req_param->direction >= MAC_BUTT_DELBA) {
        oam_warning_log1(0, OAM_SF_ANY, "{uapi_ccpriv_delba_req::direction[%u] is error!}",
            delba_req_param->direction);
        return OAL_ERR_CODE_INVALID_CONFIG;
    }

    /* **************************************************************************
                                抛事件到wal层处理
    ************************************************************************** */
    l_ret = wal_sync_post2hmac_no_rsp(wal_util_get_vap_id(net_dev), WLAN_MSG_W2H_CFG_DELBA_REQ,
        (osal_u8 *)&cfg_delba_req_param, OAL_SIZEOF(cfg_delba_req_param));
    if (OAL_UNLIKELY(l_ret != OAL_SUCC)) {
        oam_warning_log1(0, OAM_SF_ANY, "{uapi_ccpriv_delba_req::return err code[%d]!}", l_ret);
        return (osal_u32)l_ret;
    }

    return OAL_SUCC;
}

OAL_STATIC osal_u32 uapi_ccpriv_wmm_switch(oal_net_device_stru *net_dev, osal_s8 *param)
{
    osal_u32                      ul_ret;
    osal_s32                       l_cfg_rst;
    osal_s8                        ac_name[WAL_CCPRIV_CMD_NAME_MAX_LEN];
    osal_u32                      off_set = 0;
    osal_u8                       open_wmm;

    /* 获取设定的值 */
    ul_ret = wal_get_cmd_one_arg(param, ac_name, OAL_SIZEOF(ac_name), &off_set);
    if (ul_ret != OAL_SUCC) {
        oam_warning_log1(0, OAM_SF_ANY,
                         "{uapi_ccpriv_wmm_switch::wal_get_cmd_one_arg return err_code [%d]!}", ul_ret);
        return ul_ret;
    }
    open_wmm = (osal_u8)oal_atoi((const osal_s8 *)ac_name);
    param += off_set;

    l_cfg_rst = wal_sync_post2hmac_no_rsp(wal_util_get_vap_id(net_dev), WLAN_MSG_W2H_CFG_WMM_SWITCH,
        (osal_u8 *)&open_wmm, OAL_SIZEOF(open_wmm));
    if (OAL_UNLIKELY(l_cfg_rst != OAL_SUCC)) {
        oam_warning_log1(0, OAM_SF_ANY, "{uapi_ccpriv_wmm_switch::return err code [%d]!}", l_cfg_rst);
        return (osal_u32)l_cfg_rst;
    }

    return OAL_SUCC;
}

OAL_STATIC osal_u32 uapi_ccpriv_11v_cfg_bsst(oal_net_device_stru *cfg_net_dev, osal_s8 *param)
{
    osal_u8                   debug_switch;
    osal_s32                   l_ret;
    osal_u32                  ul_ret;

    /* 参数0为关闭能力位 1位打开能力位，其他参数不支持 */
    ul_ret = wal_cmd_get_u8_with_check_max(&param, 1, &debug_switch);
    if (ul_ret != OAL_SUCC) {
        oam_warning_log1(0, OAM_SF_CFG,
                         "{uapi_ccpriv_11v_cfg_bsst::wal_cmd_get_u8_with_check_max return err_code %d!}", ul_ret);
        return ul_ret;
    }
    /***************************************************************************
                              抛事件到wal层处理
    ***************************************************************************/
    l_ret = wal_sync_post2hmac_no_rsp(wal_util_get_vap_id(cfg_net_dev), WLAN_MSG_W2H_CFG_11V_BSST_SWITCH,
        (osal_u8 *)&debug_switch, OAL_SIZEOF(osal_u8));
    if (OAL_UNLIKELY(l_ret != OAL_SUCC)) {
        oam_warning_log2(0, OAM_SF_ANY, "vap_id[%d] {uapi_ccpriv_11v_cfg_bsst::return err code %d!}",
                         wal_util_get_vap_id(cfg_net_dev), l_ret);
        return (osal_u32)l_ret;
    }

    return OAL_SUCC;
}

#ifdef _PRE_WLAN_FEATURE_11K
OAL_STATIC osal_u32 uapi_ccpriv_send_radio_meas_rpt(oal_net_device_stru *net_dev, osal_s8 *param)
{
    osal_u32                       off_set = 0;
    osal_u32                       ret;
    osal_s8                        name[WAL_CCPRIV_CMD_NAME_MAX_LEN];
    osal_u8                        mac_addr[WLAN_MAC_ADDR_LEN] = {0};    /* MAC地址 */
    mac_cfg_radio_meas_info_stru  cfg_radio_meas_cfg;

    (osal_void)memset_s(&cfg_radio_meas_cfg, OAL_SIZEOF(cfg_radio_meas_cfg), 0, OAL_SIZEOF(cfg_radio_meas_cfg));

    /* wlan0 send_radio_meas_rpt [act_type] [对端地址] [meas type] [meas duration][chn_num] [BCN type] [BCN mac addr] */
    /* echo "wlan0 send_radio_meas_rpt 0 AA:BB:CC:11:22:26 5 100 149 1 ff:ff:ff:ff:ff:ff" */
    /* action type */
    ret = wal_get_cmd_one_arg(param, name, OAL_SIZEOF(name), &off_set);
    if (ret != OAL_SUCC) {
        oam_warning_log1(0, OAM_SF_ANY, "{uapi_ccpriv_send_radio_meas_rpt::action_type err_code [%d]!}", ret);
        return ret;
    }
    cfg_radio_meas_cfg.action_type = (osal_u8)oal_atoi((const osal_s8 *)name);

    /* 获取mac地址 */
    param = param + off_set;
    ret = wal_ccpriv_get_mac_addr_etc(param, (osal_u8 *)mac_addr, &off_set);
    if (ret != OAL_SUCC) {
        oam_warning_log0(0, OAM_SF_ANY, "{uapi_ccpriv_send_radio_meas_rpt::wal_ccpriv_get_mac_addr_etc failed!}");
        return ret;
    }
    oal_set_mac_addr(cfg_radio_meas_cfg.auc_mac_addr, (osal_u8 *)mac_addr);

    oam_warning_log4(0, OAM_SF_ANY, "{uapi_ccpriv_send_radio_meas_rpt::mac_addr=%x:%x:%x:%x:xx:xx}",
                     cfg_radio_meas_cfg.auc_mac_addr[0], cfg_radio_meas_cfg.auc_mac_addr[1],
                     cfg_radio_meas_cfg.auc_mac_addr[2], cfg_radio_meas_cfg.auc_mac_addr[3]); /* index: 2, 3 */

    param = param + off_set;
    ret = wal_handel_radio_meas_rpt_cmd(&cfg_radio_meas_cfg, param);
    if (ret != OAL_SUCC) {
        return ret;
    }

    ret = (osal_u32)wal_sync_post2hmac_no_rsp(wal_util_get_vap_id(net_dev), WLAN_MSG_W2H_CFG_SEND_RADIO_MEAS_RPT,
        (osal_u8 *)&cfg_radio_meas_cfg, OAL_SIZEOF(cfg_radio_meas_cfg));
    if (ret != OAL_SUCC) {
        oam_warning_log1(0, OAM_SF_ANY, "{uapi_ccpriv_send_radio_meas_rpt::return err code [%d]!}", ret);
        return ret;
    }
    return OAL_SUCC;
}

OAL_STATIC osal_u32 ccpriv_meas_req_parse(osal_s8 *param, mac_cfg_radio_meas_info_stru *meas_cfg)
{
    osal_u32 off_set = 0;
    osal_u32 ret;
    osal_s8 name[WAL_CCPRIV_CMD_NAME_MAX_LEN];

    ret = wal_get_cmd_one_arg(param, name, OAL_SIZEOF(name), &off_set);
    if (ret != OAL_SUCC) {
        oam_warning_log1(0, OAM_SF_ANY, "{ccpriv_meas_req_parse::means_type err_code [%d]!}", ret);
        return ret;
    }
    meas_cfg->means_type = (osal_u8)oal_atoi((const osal_s8 *)name);

    /* meas duration */
    param = param + off_set;
    ret = wal_get_cmd_one_arg(param, name, OAL_SIZEOF(name), &off_set);
    if (ret != OAL_SUCC) {
        oam_warning_log1(0, OAM_SF_ANY, "{ccpriv_meas_req_parse:: meas_duration err_code [%d]!}", ret);
        return ret;
    }
    meas_cfg->duration = (osal_u16)oal_atoi((const osal_s8 *)name);

    /* channum */
    param = param + off_set;
    ret = wal_get_cmd_one_arg(param, name, OAL_SIZEOF(name), &off_set);
    if (ret != OAL_SUCC) {
        oam_warning_log1(0, OAM_SF_ANY, "{ccpriv_meas_req_parse::channum err_code [%d]!}", ret);
        return ret;
    }
    meas_cfg->channum = (osal_u8)oal_atoi((const osal_s8 *)name);

    oam_warning_log3(0, OAM_SF_ANY, "{ccpriv_meas_req_parse::duration=%d, means_type=%d, channum=%d}",
        meas_cfg->duration, meas_cfg->means_type, meas_cfg->channum);

    if (meas_cfg->means_type == RM_RADIO_MEAS_BCN) {
        /* means_mode for bcn */
        param = param + off_set;
        ret = wal_get_cmd_one_arg(param, name, OAL_SIZEOF(name), &off_set);
        if (ret != OAL_SUCC) {
            oam_warning_log1(0, OAM_SF_ANY, "{ccpriv_meas_req_parse::bcn_mode err_code [%d]!}", ret);
            return ret;
        }
        meas_cfg->bcn_mode = (osal_u8)oal_atoi((const osal_s8 *)name);

        /* 获取BSSID */
        param = param + off_set;
        ret = wal_ccpriv_get_mac_addr_etc(param, meas_cfg->bssid, &off_set);
        if (ret != OAL_SUCC) {
            oam_warning_log0(0, OAM_SF_ANY, "{ccpriv_meas_req_parse::bssid failed!}");
            return ret;
        }
        oam_warning_log4(0, OAM_SF_ANY, "{ccpriv_meas_req_parse:: bssid=%x:%x:%x:%x:xx:xx}",
            /* 模糊打印，仅打印0 1 2 3位 */
            meas_cfg->bssid[0], meas_cfg->bssid[1], meas_cfg->bssid[2], meas_cfg->bssid[3]);
    }
    return OAL_CONTINUE;
}

OAL_STATIC osal_u32 uapi_ccpriv_send_radio_meas_req(oal_net_device_stru *net_dev, osal_s8 *param)
{
    osal_u32 off_set = 0;
    osal_u32 ret;
    osal_s32 send_ret;
    osal_s8 name[WAL_CCPRIV_CMD_NAME_MAX_LEN];
    mac_cfg_radio_meas_info_stru meas_cfg_info = {0};

    /* vap0 send_radio_meas_req [action_type] [对端mac地址] [meas type] [meas duration][chn_num]
       [BCN meas_type] [BCN mac addr] */

    /* action type */
    ret = wal_get_cmd_one_arg(param, name, OAL_SIZEOF(name), &off_set);
    if (ret != OAL_SUCC) {
        oam_warning_log1(0, OAM_SF_ANY, "{uapi_ccpriv_send_radio_meas_req::action_type err_code [%d]!}", ret);
        return ret;
    }
    meas_cfg_info.action_type = (osal_u8)oal_atoi((const osal_s8 *)name);

    /* 获取mac地址 */
    param = param + off_set;
    ret = wal_ccpriv_get_mac_addr_etc(param, meas_cfg_info.auc_mac_addr, &off_set);
    if (ret != OAL_SUCC) {
        oam_warning_log0(0, OAM_SF_ANY, "{uapi_ccpriv_send_radio_meas_req::wal_ccpriv_get_mac_addr_etc failed!}\r\n");
        return ret;
    }

    oam_warning_log4(0, OAM_SF_ANY, "{uapi_ccpriv_send_radio_meas_req::mac_addr=%x:%x:%x:%x:xx:xx}",
        meas_cfg_info.auc_mac_addr[0], meas_cfg_info.auc_mac_addr[1],
        meas_cfg_info.auc_mac_addr[2], meas_cfg_info.auc_mac_addr[3]); // 模糊打印打印第2 3位

    if (meas_cfg_info.action_type == MAC_RM_ACTION_RADIO_MEASUREMENT_REQUEST) {
        /* meas type */
        param = param + off_set;
        ret = ccpriv_meas_req_parse(param, &meas_cfg_info);
        if (ret != OAL_CONTINUE) {
            oam_warning_log1(0, OAM_SF_ANY, "{uapi_ccpriv_send_radio_meas_req::meas_req_parse err_code [%d]!}", ret);
            return ret;
        }
    }

    send_ret = wal_sync_post2hmac_no_rsp(wal_util_get_vap_id(net_dev), WLAN_MSG_W2H_CFG_SEND_RADIO_MEAS_REQ,
        (osal_u8 *)&meas_cfg_info, OAL_SIZEOF(meas_cfg_info));
    if (OAL_UNLIKELY(send_ret != OAL_SUCC)) {
        oam_warning_log1(0, OAM_SF_ANY, "{uapi_ccpriv_send_radio_meas_req::return err code [%d]!}", send_ret);
        return (osal_u32)send_ret;
    }
    return OAL_SUCC;
}

#endif

OAL_STATIC osal_u32 uapi_ccpriv_set_log_level(oal_net_device_stru *net_dev, osal_s8 *param)
{
    osal_s32 ret;
    osal_s32 level;
    osal_u32 off_set;
    osal_s8 val[WAL_CCPRIV_CMD_NAME_MAX_LEN];
    osal_u32 ul_ret;

    ul_ret = (osal_u32)wal_get_cmd_one_arg_digit(param, val, sizeof(val), &off_set, (osal_s32 *)&level);
    if (ul_ret != OAL_SUCC) {
        oam_warning_log1(0, OAM_SF_ANY, "{uapi_ccpriv_qos_enhance_on::wal_get_cmd_one_arg_digit return err_code [%d]!}",
            ul_ret);
        return ul_ret;
    }

    if (level < 0) { /* 参数异常: log level > 0 */
        wifi_printf("log_level err %d\r\n", level);
        return OAL_ERR_CODE_INVALID_CONFIG;
    }
    ret = wal_sync_post2hmac_no_rsp(wal_util_get_vap_id(net_dev), WLAN_MSG_W2H_CFG_SET_LOG_LEVEL,
        (osal_u8 *)&level, OAL_SIZEOF(level));
    if (OAL_UNLIKELY(ret != OAL_SUCC)) {
        oam_warning_log1(0, OAM_SF_ANY, "{wal_ccpriv_set_txpower::return err code %d!}", ret);
        return (osal_u32)ret;
    }

    return OAL_SUCC;
}

/* 向对端发送数据帧 */
STATIC osal_u32 uapi_ccpriv_packet_xmit(oal_net_device_stru *net_dev, osal_s8 *param)
{
    osal_u32 off_set, ret;
    osal_s8 name[WAL_CCPRIV_CMD_NAME_MAX_LEN] = {0};
    osal_s32 send_ret;
    mac_cfg_mpdu_ampdu_tx_param_stru *aggr_tx_on_param = OAL_PTR_NULL;
    mac_cfg_mpdu_ampdu_tx_param_stru cfg_aggr_tx_on_param;

    (osal_void)memset_s(&cfg_aggr_tx_on_param, OAL_SIZEOF(cfg_aggr_tx_on_param), 0, OAL_SIZEOF(cfg_aggr_tx_on_param));
    aggr_tx_on_param = &cfg_aggr_tx_on_param;

    ret = wal_cmd_get_u8_with_check_max(&param, WLAN_TID_MAX_NUM - 1, &aggr_tx_on_param->tid);
    if (ret != OAL_SUCC) {
        oam_warning_log1(0, OAM_SF_ANY, "{uapi_ccpriv_packet_xmit::wal_cmd_get_u8_with_check_max err_code [%d]!}", ret);
        return ret;
    }

    ret = wal_get_cmd_one_arg(param, name, OAL_SIZEOF(name), &off_set);
    if (ret != OAL_SUCC) {
        oam_warning_log1(0, OAM_SF_ANY, "{uapi_ccpriv_packet_xmit::wal_get_cmd_one_arg err_code [%d]!}", ret);
        return ret;
    }
    param = param + off_set;
    aggr_tx_on_param->packet_num = (osal_u8)oal_atoi((const osal_s8 *)name);

    ret = wal_get_cmd_one_arg(param, name, OAL_SIZEOF(name), &off_set);
    if (ret != OAL_SUCC) {
        oam_warning_log1(0, OAM_SF_ANY, "{uapi_ccpriv_packet_xmit::wal_get_cmd_one_arg err_code [%d]!}", ret);
        return ret;
    }
    aggr_tx_on_param->packet_len = (osal_u16)oal_atoi((const osal_s8 *)name);
    /* 长度不小于30 */
    if (aggr_tx_on_param->packet_len < 30) {
        return OAL_FAIL;
    }
    param += off_set;

    /* 获取MAC地址字符串 */
    ret = wal_get_cmd_one_arg(param, name, OAL_SIZEOF(name), &off_set);
    if (ret != OAL_SUCC) {
        oam_warning_log1(0, OAM_SF_ANY, "{uapi_ccpriv_packet_xmit::get mac err_code [%d]!}", ret);
        return ret;
    }
    /* 地址字符串转地址数组 */
    oal_strtoaddr((const osal_s8 *)name, aggr_tx_on_param->ra_mac);
    param += off_set;

    /* **************************************************************************
                             抛事件到wal层处理
    ************************************************************************** */
    send_ret = wal_sync_post2hmac_no_rsp(wal_util_get_vap_id(net_dev), WLAN_MSG_W2H_CFG_PACKET_XMIT,
        (osal_u8 *)&cfg_aggr_tx_on_param, OAL_SIZEOF(cfg_aggr_tx_on_param));
    if (OAL_UNLIKELY(send_ret != OAL_SUCC)) {
        oam_warning_log1(0, OAM_SF_ANY, "{uapi_ccpriv_packet_xmit::return err code [%d]!}", send_ret);
        return (osal_u32)send_ret;
    }

    return OAL_SUCC;
}

OAL_STATIC osal_u32 wal_ccpriv_del_vap_send_event(hmac_cfg_del_vap_param_stru *vap_info, oal_net_device_stru *net_dev)
{
    oal_wireless_dev_stru *wdev;
    osal_s32 ret;
#ifdef _PRE_WLAN_FEATURE_P2P
    wlan_p2p_mode_enum_uint8   p2p_mode = WLAN_LEGACY_VAP_MODE;
#endif

    vap_info->net_dev = net_dev;
    wdev = net_dev->ieee80211_ptr;
#ifdef _PRE_WLAN_FEATURE_P2P
    p2p_mode = wal_wireless_iftype_to_mac_p2p_mode_etc(wdev->iftype);
    if (p2p_mode == WLAN_P2P_BUTT) {
        oam_error_log0(0, OAM_SF_ANY,
            "{wal_ccpriv_del_vap_send_event::wal_wireless_iftype_to_mac_p2p_mode_etc return BUFF}");
        return OAL_ERR_CODE_INVALID_CONFIG;
    }
    vap_info->add_vap.p2p_mode = p2p_mode;
#endif

    ret = wal_sync_post2hmac_no_rsp(wal_util_get_vap_id(net_dev), WLAN_MSG_W2H_CFG_DEL_VAP,
        (osal_u8 *)vap_info, OAL_SIZEOF(hmac_cfg_del_vap_param_stru));
    if (OAL_UNLIKELY(ret != OAL_SUCC)) {
        oam_warning_log1(0, OAM_SF_ANY, "{wal_ccpriv_del_vap_send_event::return err code %d}", ret);
        wifi_printf("{wal_ccpriv_del_vap_send_event::return err code %d}\r\n", ret);
        /* 去注册 */
        oal_net_unregister_netdev(net_dev);
        oal_mem_free(wdev, OAL_TRUE);
        return (osal_u32)ret;
    }
    /* 去注册 */
    oal_net_unregister_netdev(net_dev);
    oal_mem_free(wdev, OAL_TRUE);
    return OAL_SUCC;
}

/*****************************************************************************
 功能描述  : 删除vap
*****************************************************************************/
static osal_u32  uapi_ccpriv_del_vap_etc(oal_net_device_stru *net_dev, osal_s8 *param)
{
    osal_u32                    l_ret;
    hmac_vap_stru                *hmac_vap;
    hmac_cfg_add_vap_param_stru vap_info;
    (osal_void)memset_s(&vap_info, OAL_SIZEOF(vap_info), 0, OAL_SIZEOF(vap_info));

    if (OAL_UNLIKELY((net_dev == OAL_PTR_NULL) || (param == OAL_PTR_NULL))) {
        // 访问网络接口的模块可能不止一个,需要上层保证可靠删除
        oam_warning_log2(0, OAM_SF_ANY, "{uapi_ccpriv_del_vap_etc::net_dev or pc_param null ptr error %p, %p!}",
                         net_dev, param);
        return OAL_ERR_CODE_PTR_NULL;
    }

    hmac_vap = (hmac_vap_stru *)net_dev->ml_priv;
    if (OAL_UNLIKELY(hmac_vap == NULL)) {
        oam_error_log0(0, OAM_SF_CFG, "{uapi_ccpriv_del_vap_etc::can't get mac vap from netdevice priv data!}");
        return OAL_ERR_CODE_PTR_NULL;
    }
    if (hmac_vap->vap_mode == WLAN_VAP_MODE_CONFIG) { /* 配置vap不走命令删除接口 */
        oam_warning_log1(0, OAM_SF_CFG, "{uapi_ccpriv_del_vap_etc::invalid parameters, mac vap mode: %d}",
                         hmac_vap->vap_mode);
        return OAL_ERR_CODE_INVALID_CONFIG;
    }

    /* 设备在up状态不允许删除，必须先down */
#ifdef _PRE_WLAN_FEATURE_P2P
    if ((hmac_vap->vap_state != MAC_VAP_STATE_INIT) && (hmac_vap->p2p_mode != WLAN_P2P_CL_MODE))
#else
    if (hmac_vap->vap_state != MAC_VAP_STATE_INIT)
#endif
    {
        oam_error_log1(0, OAM_SF_ANY, "{uapi_ccpriv_del_vap_etc:vap state[%d],down vap}", hmac_vap->vap_state);
        return OAL_ERR_CODE_CONFIG_BUSY;
    }
#if (defined(CONFIG_ATP_FASTIP) && defined(_PRE_WLAN_FASTIP_SUPPORT))
    fastip_detach_wifi(hmac_vap->fastip_idx);
#endif  /* (defined(CONFIG_ATP_FASTIP) && defined(_PRE_WLAN_FASTIP_SUPPORT)) */

    /* 删除vap对应的proc文件 */
#ifdef LINUX_VERSION_CODE
#if LINUX_VERSION_CODE <= KERNEL_VERSION(2,6,34)
    wal_del_vap_proc_file(net_dev);
#elif LINUX_VERSION_CODE >= KERNEL_VERSION(3,10,59)
    wal_del_vap_proc_file_sec(net_dev);
#endif
#endif

    /***************************************************************************
                                抛事件到wal层处理
    ***************************************************************************/
    // 删除vap 时需要将参数赋值。
    l_ret = wal_ccpriv_del_vap_send_event(&vap_info, net_dev);
    if (l_ret != OAL_SUCC) {
        return l_ret;
    }

    return OAL_SUCC;
}

#ifdef _PRE_WLAN_FEATURE_P2P
static uint32_t uapi_ccpriv_set_p2p_mode(oal_net_device_stru *net_dev, int8_t *param)
{
    uint32_t ret;
    uint32_t p2p_protocol;
    uint32_t p2p_band;
    uint32_t p2p_enable;
    int32_t  ret_val;
    p2p_common_info_stru p2p_common_info = {0};
    /*
     * 通用debug命令:
     * ccpriv "p2p0 set_p2p_mode para0 para1 para2"
     * para0 ---- enable  0:表示关闭设置    1:打开设置
     * para1 ---- protocol_mode  0:bgn      1:bgn+ax
     * para1 ---- band_width     0:20M      1:40M
    */

    /* 只能设置0和1表示使能和不使能 */
    ret = wal_cmd_get_digit_with_check_max(&param, 1, &p2p_enable);
    if (ret != OAL_SUCC) {
        oam_warning_log1(0, OAM_SF_ANY, "{uapi_ccpriv_set_p2p_mode::p2p_enable err[%d]!}", ret);
        return ret;
    }
    p2p_common_info.enable = (uint8_t)p2p_enable;

    ret = wal_cmd_get_digit_with_check_max(&param, P2P_PROTOCOL_AX, &p2p_protocol);
    if (ret != OAL_SUCC) {
        oam_warning_log1(0, OAM_SF_ANY, "{uapi_ccpriv_set_p2p_mode::p2p_protocol err[%d]!}", ret);
        return ret;
    }
    p2p_common_info.protocol_mode = (p2p_protocol_debug_enum_uint8)p2p_protocol;

    ret = wal_cmd_get_digit_with_check_max(&param, P2P_BAND_40M, &p2p_band);
    if (ret != OAL_SUCC) {
        oam_warning_log1(0, OAM_SF_ANY, "{uapi_ccpriv_set_p2p_mode::p2p_band err[%d]!}", ret);
        return ret;
    }
    p2p_common_info.band_width = (p2p_band_debug_enum_uint8)p2p_band;

    /* 当前11ax不支持40M带宽，加上限制 */
    if ((p2p_protocol == P2P_PROTOCOL_AX) && (p2p_band == P2P_BAND_40M)) {
        wifi_printf("uapi_ccpriv_set_p2p_mode protocol 11ax not support 40M bandwidth\r\n");
        return OAL_FAIL;
    }

    wifi_printf("set_p2p_mode p2p_enable[%d] p2p_protocol[%d] p2p_band[%d]\r\n", p2p_enable, p2p_protocol, p2p_band);
    ret_val = wal_sync_post2hmac_no_rsp(wal_util_get_vap_id(net_dev), WLAN_MSG_W2H_C_CFG_P2P_SET_MODE,
        (uint8_t *)&p2p_common_info, OAL_SIZEOF(p2p_common_info_stru));
    if (OAL_UNLIKELY(ret_val != OAL_SUCC)) {
        oam_warning_log1(0, OAM_SF_ANY, "{uapi_ccpriv_set_p2p_mode::return err code [%d]!}", ret);
    }
    return (uint32_t)ret_val;
}

static uint32_t uapi_ccpriv_get_p2p_mode(oal_net_device_stru *net_dev, int8_t *param)
{
    hmac_vap_stru         *hmac_vap = NULL;
    struct osal_list_head *entry, *dlist_tmp;
    hmac_user_stru        *hmac_user;
    uint8_t               *addr;
    int8_t                *pac_protocol2string[] = {"11a", "11b", "11g", "11g", "11g", "11n",
        "11ac", "11n", "11ac", "11n", "11ax", "error"};

    hmac_vap = (hmac_vap_stru *)net_dev->ml_priv;
    if (hmac_vap == NULL) {
        oam_error_log0(0, OAM_SF_ANY, "{uapi_ccpriv_get_p2p_mode::OAL_NET_DEV_PRIV, return null!}");
        return OAL_FAIL;
    }
    wifi_printf("P2P Channel_num [%d]\r\n", hmac_vap->channel.chan_number);
    osal_list_for_each_safe(entry, dlist_tmp, &(hmac_vap->mac_user_list_head)) {
        hmac_user = osal_list_entry(entry, hmac_user_stru, user_dlist);
        if (hmac_user == NULL) {
            continue;
        }
        addr = hmac_user->user_mac_addr;
        /* 1表示mac地址的第二位，2表示mac地址的第三位，3表示mac地址的第四位 */
        wifi_printf("P2P mac_addr[0x%x:0x%x:0x%x:0x%x:xx:xx]\r\n", addr[0], addr[1], addr[2], addr[3]);
        wifi_printf("P2P band_width [%d] protocol_mode[%s]\r\n",
            bw_enum_to_number(hmac_user->avail_bandwidth), pac_protocol2string[hmac_user->avail_protocol_mode]);
    }

    return OAL_SUCC;
}
#endif
static uint32_t uapi_ccpriv_set_app_ie_parse_cmd(oal_net_device_stru *net_dev, int8_t *param,
    uint8_t *buf, int32_t *len)
{
    uint32_t ret;
    uint32_t off_set;
    int32_t  payload;
    int8_t   name[WAL_CCPRIV_CMD_NAME_MAX_LEN] = {0};
    int32_t  i;

    ret = wal_get_cmd_one_arg(param, name, WAL_CCPRIV_CMD_NAME_MAX_LEN, &off_set);
    if (ret != OAL_SUCC) {
        oam_warning_log1(0, OAM_SF_CFG, "{uapi_ccpriv_set_app_ie_parse_cmd::wal_get_cmd_one_arg ret err %d}", ret);
        return ret;
    }

    *len = (int32_t)oal_atoi((const int8_t *)name);
    if ((*len < 0) || ((*len != 0) && (*len != SET_APP_IE_CMD_PAYLOAD_LEN))) {
        oam_warning_log1(0, OAM_SF_CFG, "{uapi_ccpriv_set_app_ie_parse_cmd:invalid len %d neither 0 nor 6}", *len);
        return OAL_ERR_CODE_INVALID_CONFIG;
    }

    for (i = 0; i < *len; i++) {
        param = param + off_set;
        ret = wal_get_cmd_one_arg(param, name, WAL_CCPRIV_CMD_NAME_MAX_LEN, &off_set);
        if (ret != OAL_SUCC) {
            oam_warning_log2(0, OAM_SF_CFG, "{uapi_ccpriv_set_app_ie_parse_cmd:payload[%d] ret err [%u]}", i, ret);
            return ret;
        }
        payload = (int32_t)oal_atoi((const int8_t *)name);
        /* payload 有效值校验 [0, 255] */
        if (payload < 0 || payload > 255) {
            oam_warning_log2(0, OAM_SF_CFG, "uapi_ccpriv_set_app_ie_parse_cmd:invalid payload[%d]:%d.", i, payload);
            return OAL_ERR_CODE_CONFIG_UNSUPPORT;
        }
        buf[i] = (uint8_t)payload;
    }

    /* 命令仅支持vendor IE. 因此LEN 后面的 payload[0]必须是221 */
    if ((*len == SET_APP_IE_CMD_PAYLOAD_LEN) && (buf[0] != MAC_EID_VENDOR)) {
        oam_warning_log1(0, OAM_SF_CFG, "{uapi_ccpriv_set_app_ie_parse_cmd::buf[0] = %d is not 221}", buf[0]);
        return OAL_ERR_CODE_CONFIG_UNSUPPORT;
    }

    /* 再解析一次,看看  payload实际长度是否超过len */
    param = param + off_set;
    ret = wal_get_cmd_one_arg(param, name, WAL_CCPRIV_CMD_NAME_MAX_LEN, &off_set);
    if (ret == OAL_SUCC) {
        oam_warning_log1(0, OAM_SF_CFG, "{uapi_ccpriv_set_app_ie_parse_cmd::payload len > cmd_len[%d]}", *len);
        return OAL_ERR_CODE_INVALID_CONFIG;
    }

    return OAL_SUCC;
}

/***************************************************************************************************
 功能描述  : vendor specific IE管理帧上报功能的命令下发
****************************************************************************************************/
static uint32_t uapi_ccpriv_set_app_ie(oal_net_device_stru *net_dev, int8_t *param)
{
    uint32_t        ret;
    int32_t         len;
    oal_app_ie_stru app_ie;
    uint8_t         buf[WAL_CCPRIV_CMD_NAME_MAX_LEN] = {0};

    /* ccpriv "wlan0 set_app_ie <LEN> <PAYLOAD[0]> <PAYLOAD[1]> ... <PAYLOAD[n]>" */
    /* 命令中所有字符有效性校验,必须是空格或数字 */
    for (uint32_t i = 0; i < osal_strlen(param); i++) {
        if (!((param[i] == ' ') || (param[i] >= '0' && param[i] <= '9'))) {
            oam_warning_log1(0, OAM_SF_CFG, "{uapi_ccpriv_set_app_ie::invalid char[%c] in cmd}", param[i]);
            return OAL_ERR_CODE_INVALID_CONFIG;
        }
    }

    ret = uapi_ccpriv_set_app_ie_parse_cmd(net_dev, param, buf, &len);
    if (ret != OAL_SUCC) {
        oam_warning_log1(0, OAM_SF_CFG, "{uapi_ccpriv_set_app_ie::parse cmd ret error[%d]}", ret);
        return ret;
    }

    memset_s(&app_ie, sizeof(oal_app_ie_stru), 0, sizeof(oal_app_ie_stru));
    app_ie.app_ie_type = OAL_APP_VENDOR_IE;
    app_ie.ie_len = (uint32_t)len;
    if (memcpy_s(app_ie.ie, sizeof(app_ie.ie), buf, (size_t)len) != EOK) {
        oam_warning_log0(0, OAM_SF_CFG, "{uapi_ccpriv_set_app_ie::memcpy_s() failed}");
        return OAL_FAIL;
    }

    ret = (uint32_t)wal_sync_post2hmac_no_rsp(wal_util_get_vap_id(net_dev), WLAN_MSG_W2H_CFG_SET_CUSTOMIZE_IE,
        (uint8_t *)&app_ie, OAL_SIZEOF(app_ie));
    if (OAL_UNLIKELY(ret != OAL_SUCC)) {
        oam_warning_log1(0, OAM_SF_CFG, "{uapi_ccpriv_set_app_ie::send msg failed[%d]!}", ret);
        return ret;
    }

    oam_warning_log1(0, OAM_SF_CFG, "{uapi_ccpriv_set_app_ie::set customize ie SUCC, len=%d}", app_ie.ie_len);
    return OAL_SUCC;
}

wal_ccpriv_cmd_entry_stru g_ast_ccpriv_debug_cmd[] = {
    {"addba_req",               uapi_ccpriv_addba_req},
    {"delba_req",               uapi_ccpriv_delba_req},
    {"destroy",                 uapi_ccpriv_del_vap_etc},
    {"set_log_level",           uapi_ccpriv_set_log_level},
    /* 向目标STA/AP发送数据帧: ccpriv "vap0 packet_xmit (tid_no) (报文个数) (报文长度) (RA MAC)" */
    {"packet_xmit",             uapi_ccpriv_packet_xmit},
    {"wmm_switch",              uapi_ccpriv_wmm_switch},
#ifdef _PRE_WLAN_FEATURE_11V
    {"11v_cfg_bsst",            uapi_ccpriv_11v_cfg_bsst},
#endif
#ifdef _PRE_WLAN_FEATURE_11K
    {"send_radio_meas_req",     uapi_ccpriv_send_radio_meas_req},
    {"send_radio_meas_rpt",     uapi_ccpriv_send_radio_meas_rpt},
#endif
#ifdef _PRE_WLAN_FEATURE_P2P
    {"set_p2p_mode",            uapi_ccpriv_set_p2p_mode},
    {"get_p2p_mode",            uapi_ccpriv_get_p2p_mode},
#endif
    {"set_app_ie",              uapi_ccpriv_set_app_ie},
};

osal_u32 wal_ccpriv_parse_cmd_debug(const td_char *cmd_name, td_u8 *ccpriv_cmd_id, wal_ccpriv_cmd_func *func)
{
    osal_u8 cmd_id;
    /* 根据命令名找到命令枚举 */
    for (cmd_id = 0; cmd_id < uapi_array_size(g_ast_ccpriv_debug_cmd); cmd_id++) {
        if (osal_strcmp(g_ast_ccpriv_debug_cmd[cmd_id].cmd_name, cmd_name) == 0) {
            *ccpriv_cmd_id = cmd_id;
            *func = g_ast_ccpriv_debug_cmd[cmd_id].func;
            return OAL_SUCC;
        }
    }
    return OAL_FAIL;
}
#endif


#ifdef __cplusplus
#if __cplusplus
    }
#endif
#endif
