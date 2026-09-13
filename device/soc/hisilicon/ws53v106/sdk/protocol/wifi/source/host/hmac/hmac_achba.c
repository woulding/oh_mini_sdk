/*
 * Copyright (c) HiSilicon (Shanghai) Technologies Co., Ltd. 2023-2023. All rights reserved.
 * 文 件 名   : hmac_achba.c
 * 生成日期   : 2023年4月17日
 * 功能描述   : achba模块
 */


/*****************************************************************************
  1 头文件包含
*****************************************************************************/
#include "hmac_achba.h"
#include "wal_utils.h"
#include "hmac_user.h"
#include "hmac_beacon.h"
#include "hmac_vap.h"
#include "wal_common.h"
#include "wal_ccpriv_common.h"
#include "hmac_feature_interface.h"

#ifdef __cplusplus
#if __cplusplus
extern "C" {
#endif
#endif

#undef THIS_FILE_ID
#define THIS_FILE_ID DIAG_FILE_ID_WIFI_HOST_HMAC_ACHBA_C

#undef THIS_MOD_ID
#define THIS_MOD_ID DIAG_MOD_ID_WIFI_HOST

oal_achba_get_chba_cap g_achba_get_chba_cap_func = NULL;
oal_achba_wifi_link_add g_achba_wifi_link_add_func = NULL;
oal_achba_wifi_link_del g_achba_wifi_link_del_func = NULL;
osal_s32 g_achba_link_id = 0;
osal_u32 g_achba_keepalive_ind = 0;

osal_s32 hmac_achba_get_achba_link_id(void)
{
    return g_achba_link_id;
}

osal_u32 hmac_achba_get_keepalive_ind(void)
{
    return g_achba_keepalive_ind;
}

/*****************************************************************************
 函 数 名  : hmac_ind_achba_keepalive
 功能描述 : 代为链路保活指示
*****************************************************************************/
OSAL_STATIC osal_s32 hmac_ind_achba_keepalive(oal_net_device_stru *net_dev, osal_s32 achba_link_id, osal_u32 keep_ind)
{
    mac_set_achba_link_ind achba_link;
    osal_s32 ret;

    if (net_dev == NULL) {
        oam_error_log0(0, OAM_SF_ACHBA, "wal_ind_achba_keepalive::net_dev is null.");
        return OAL_FAIL;
    }

    if ((achba_link_id <= 0) || (keep_ind > 1)) {
        oam_error_log2(0, OAM_SF_ACHBA, "wal_ind_achba_keepalive::achba_link_id[%d] or keep_ind[%u] is invalid.",
            achba_link_id, keep_ind);
        return OAL_FAIL;
    }
    memset_s(&achba_link, sizeof(mac_set_achba_link_ind), 0, sizeof(mac_set_achba_link_ind));
    achba_link.achba_link_id = achba_link_id;
    achba_link.keep_ind = keep_ind;
    /* 抛事件到wal层处理 */
    ret = wal_sync_post2hmac_no_rsp(wal_util_get_vap_id(net_dev), WLAN_MSG_W2H_CFG_IND_ACHBA_KEEPALILVE,
        (osal_u8 *)&achba_link, OAL_SIZEOF(mac_set_achba_link_ind));
    if (osal_unlikely(ret != OAL_SUCC)) {
        oam_warning_log1(0, OAM_SF_ANY, "{wal_ind_achba_keepalive::err[%d]!}", ret);
    }
    return ret;
}

/*****************************************************************************
 函 数 名  : oal_achba_register_wifi_intfs
 功能描述 : WiFi模块向接入CHBA模块提供注册接口，将与接入CHBA交互的配置接口进行相互关联
*****************************************************************************/
osal_s32 oal_achba_register_wifi_intfs(const struct hmac_achba_drv_to_wifi_ops *callee_intfs,
    struct oal_achba_caller_intfs *caller_intfs)
{
    if (callee_intfs == NULL || caller_intfs == NULL) {
        oam_error_log0(0, OAM_SF_ACHBA, "oal_achba_register_wifi_intfs::callee_intfs or caller_intfs is null.");
        return OAL_FAIL;
    }

    g_achba_get_chba_cap_func = callee_intfs->get_chba_cap;
    g_achba_wifi_link_add_func = callee_intfs->wifi_link_add;
    g_achba_wifi_link_del_func = callee_intfs->wifi_link_del;

    caller_intfs->achba_keepalive = hmac_ind_achba_keepalive;

    return OAL_SUCC;
}

/*****************************************************************************
 函 数 名  : hmac_set_achba_cap_ie
 功能描述 : 设置ACHBA info element
*****************************************************************************/
OSAL_STATIC osal_u8 hmac_set_achba_cap_ie(hmac_vap_stru *hmac_vap, osal_u8 *buffer)
{
    osal_u8 ie_len = 0;
    osal_u8 index = MAC_IE_HDR_LEN;
    osal_s8 chba_cap_info[MAC_CHBA_CAP_INFO_LEN] = {0};
    osal_s32 chba_cap_info_len = 0;

    if (hmac_vap == NULL || buffer == NULL) {
        oam_error_log0(0, OAM_SF_ACHBA, "hmac_set_achba_cap_ie::hmac_vap or buffer is null.");
        return 0;
    }

    if (g_achba_get_chba_cap_func == NULL) {
        oam_warning_log0(0, OAM_SF_ACHBA, "hmac_set_achba_cap_ie::g_achba_get_chba_cap_func is null.");
        return 0;
    }

    /********************************************************************************************
            ------------------------------------------------------------------------------------
            |ElementID | Length | Organization identifier| vendor-specific content|
            ------------------------------------------------------------------------------------
    Octets: |1         | 1      | 3                      | 12                     |
            -------------------------------------------------------------------------------------

    *********************************************************************************************/

   /* vendor-specific content */
   /********************************************************************************************
            ------------------------------------------------------------------------------------
            |Sub_type | chba capability info|
            ------------------------------------------------------------------------------------
    Octets: |1        | 11                   |
            -------------------------------------------------------------------------------------

    *********************************************************************************************/

    if (!is_legacy_sta(hmac_vap)) {
        oam_warning_log0(0, OAM_SF_ACHBA, "hmac_set_achba_cap_ie::hmac_vap is not legacy sta.");
        return 0;
    }

    chba_cap_info_len = g_achba_get_chba_cap_func(oal_get_achba_net(hmac_vap), chba_cap_info, MAC_CHBA_CAP_INFO_LEN);
    if ((chba_cap_info_len <= 0) || (chba_cap_info_len > MAC_CHBA_CAP_INFO_LEN)) {
        oam_error_log1(0, OAM_SF_ACHBA, "hmac_set_achba_cap_ie::chba_cap_info_len[%d] is invalid.", chba_cap_info_len);
        return 0;
    }

    buffer[0] = MAC_EID_VENDOR;
    buffer[1] = MAC_ORGANIZATION_IDENTIFIER_LEN + MAC_SUB_TYPE_LEN + chba_cap_info_len;

    buffer[index++] = (osal_u8)((MAC_EXT_VENDER_IE >> BIT_OFFSET_16) & 0xff); /* organization identifier的第0个字节 */
    buffer[index++] = (osal_u8)((MAC_EXT_VENDER_IE >> BIT_OFFSET_8) & 0xff); /* organization identifier的第1个字节 */
    buffer[index++] = (osal_u8)((MAC_EXT_VENDER_IE) & 0xff); /* organization identifier的第2个字节 */

    buffer[index++] = MAC_EXT_ACHBA_SUB_TYPE_IE;
    (osal_void)memcpy_s(&buffer[index], (size_t)chba_cap_info_len, chba_cap_info, (size_t)chba_cap_info_len);
    ie_len = MAC_IE_HDR_LEN + MAC_ORGANIZATION_IDENTIFIER_LEN + MAC_SUB_TYPE_LEN + chba_cap_info_len;

    return ie_len;
}

/*****************************************************************************
 函 数 名  : hmac_config_ind_achba_keepalive
 功能描述  : 调试命令接口, 入参为keep_ind 0:关闭 1：开启
*****************************************************************************/
osal_s32 hmac_config_ind_achba_keepalive(hmac_vap_stru *hmac_vap, frw_msg *msg)
{
    mac_set_achba_link_ind *achba_link = NULL;

    if ((hmac_vap == NULL) || (msg == NULL)) {
        oam_error_log0(0, OAM_SF_ACHBA, "hmac_config_ind_achba_keepalive::hmac_vap or msg is null.");
        return OAL_ERR_CODE_PTR_NULL;
    }

    achba_link = (mac_set_achba_link_ind *)msg->data;
    if (achba_link == NULL) {
        oam_error_log0(0, OAM_SF_ACHBA, "hmac_config_ind_achba_keepalive::hachba_link is null.");
        return OAL_ERR_CODE_PTR_NULL;
    }
    if ((achba_link->achba_link_id <= 0) ||
        (achba_link->achba_link_id != g_achba_link_id) ||
        (achba_link->keep_ind > 1)) {
        oam_warning_log2(0, OAM_SF_ACHBA,
            "hmac_config_ind_achba_keepalive::achba_link_id[%d] or keep_ind[%u] is invalid.",
            achba_link->achba_link_id, achba_link->keep_ind);
        return OAL_FAIL;
    }

    g_achba_keepalive_ind = achba_link->keep_ind;

    return OAL_SUCC;
}

/*****************************************************************************
 函 数 名  : hmac_proc_chba_cap_ie_etc
 功能描述  : 解析CHBA IE信息
*****************************************************************************/
OSAL_STATIC const osal_u8 *hmac_proc_chba_cap_ie_etc(const osal_u8 *chba_cap_ie, osal_s32 *chba_cap_info_len)
{
    osal_u8 organization_identifier[MAC_ORGANIZATION_IDENTIFIER_LEN] = {0};
    const osal_u8 *chba_cap_info = NULL;

    /* 解析chba cap IE */
    if ((chba_cap_ie[1] <= MAC_ORGANIZATION_IDENTIFIER_LEN + MAC_SUB_TYPE_LEN) ||
        (chba_cap_ie[1] > (MAC_ORGANIZATION_IDENTIFIER_LEN + MAC_SUB_TYPE_LEN + MAC_CHBA_CAP_INFO_LEN))) {
        oam_warning_log1(0, OAM_SF_ACHBA, "{hmac_proc_chba_cap_ie_etc::invalid chba_cap_ie len[%d].}", chba_cap_ie[1]);
        return NULL;
    }

    /* organization identifier的第0个字节 */
    organization_identifier[0] = (osal_u8)((MAC_EXT_VENDER_IE >> BIT_OFFSET_16) & 0xff);
    /* organization identifier的第1个字节 */
    organization_identifier[1] = (osal_u8)((MAC_EXT_VENDER_IE >> BIT_OFFSET_8) & 0xff);
    /* organization identifier的第2个字节 */
    organization_identifier[2] = (osal_u8)((MAC_EXT_VENDER_IE) & 0xff);

    if ((chba_cap_ie[MAC_IE_HDR_LEN] != organization_identifier[0]) || /* 比较organization identifier的第0个字节 */
        (chba_cap_ie[MAC_IE_HDR_LEN + 1] != organization_identifier[1]) || /* 比较organization identifier的第1个字节 */
        (chba_cap_ie[MAC_IE_HDR_LEN + 2] != organization_identifier[2])) { /* 比较organization identifier的第2个字节 */
        oam_warning_log0(0, OAM_SF_ACHBA, "{hmac_proc_chba_cap_ie_etc::invalid chba_cap_ie organization identifier.}");
        return NULL;
    }

    if (chba_cap_ie[MAC_IE_HDR_LEN + MAC_ORGANIZATION_IDENTIFIER_LEN] != MAC_EXT_ACHBA_SUB_TYPE_IE) {
        oam_warning_log0(0, OAM_SF_ACHBA, "{hmac_proc_chba_cap_ie_etc::invalid chba_cap_ie sub_type.}");
        return NULL;
    }

    *chba_cap_info_len = chba_cap_ie[1] - MAC_ORGANIZATION_IDENTIFIER_LEN - MAC_SUB_TYPE_LEN;
    chba_cap_info = chba_cap_ie + MAC_IE_HDR_LEN + MAC_ORGANIZATION_IDENTIFIER_LEN + MAC_SUB_TYPE_LEN;
    return chba_cap_info;
}

/*****************************************************************************
 函 数 名  : hmac_process_update_achba
 功能描述  : WiFi模块检查是否存在接入CHBA能力IE，如存在则向接入CHBA模块调用WiFi链路建立
*****************************************************************************/
OSAL_STATIC osal_void hmac_process_update_achba(hmac_vap_stru *hmac_vap, hmac_user_stru *hmac_user, osal_u8 *payload,
    osal_u16 msg_len)
{
    osal_u8 *chba_cap_ie = NULL;
    const osal_u8 *chba_cap_info = NULL;
    osal_s32 achba_link_id;
    osal_s32 chba_cap_info_len = 0;

    if (hmac_vap == NULL || hmac_user == NULL || payload == NULL) {
        oam_error_log0(0, OAM_SF_ACHBA, "hmac_process_update_achba::hmac_vap or payload is null.");
        return;
    }

    if (g_achba_wifi_link_add_func == NULL) {
        oam_warning_log0(0, OAM_SF_ACHBA, "hmac_process_update_achba::g_achba_wifi_link_add_func is null.");
        return;
    }

    if (!is_legacy_sta(hmac_vap)) {
        oam_warning_log0(0, OAM_SF_ACHBA, "hmac_process_update_achba::hmac_vap is not legacy sta.");
        return;
    }

    /* 解析 CHBA 能力 IE */
    chba_cap_ie =  hmac_find_vendor_ie_etc(MAC_EXT_VENDER_IE, MAC_EXT_ACHBA_SUB_TYPE_IE, payload, msg_len);
    if (chba_cap_ie != NULL) {
        chba_cap_info = hmac_proc_chba_cap_ie_etc(chba_cap_ie, &chba_cap_info_len);
        if (chba_cap_info == NULL || chba_cap_info_len <= 0 || chba_cap_info_len > MAC_CHBA_CAP_INFO_LEN) {
            oam_warning_log0(0, OAM_SF_ACHBA, "hmac_process_update_achba::chab_cap_ie process failed.");
        }
    }

    achba_link_id = g_achba_wifi_link_add_func(oal_get_achba_net(hmac_vap), hmac_user->user_mac_addr,
        WLAN_MAC_ADDR_LEN, chba_cap_info, (osal_u32)chba_cap_info_len);
    if (achba_link_id <= 0) {
        oam_error_log0(0, OAM_SF_ACHBA, "hmac_process_update_achba::achba_link_id is invalid.");
        g_achba_link_id = 0;
        return;
    }

    g_achba_link_id = achba_link_id;
}

/*****************************************************************************
 函 数 名  : hmac_user_del_achba
 功能描述  : wifi去关联时删除用户之前，删掉接入chba的WiFi链路
*****************************************************************************/
OSAL_STATIC osal_void hmac_user_del_achba(hmac_vap_stru *hmac_vap)
{
    osal_s32 ret;

    if (hmac_vap == NULL) {
        oam_error_log0(0, OAM_SF_ACHBA, "{hmac_user_del_achba::hmac_vap is null}");
        return;
    }

    if (g_achba_wifi_link_del_func == NULL) {
        oam_warning_log0(0, OAM_SF_ACHBA, "{hmac_user_del_achba::g_achba_wifi_link_del_func is null}");
        return;
    }

    if (!is_legacy_sta(hmac_vap)) {
        oam_warning_log0(0, OAM_SF_ACHBA, "hmac_user_del_achba::hmac_vap is not legacy sta.");
        return;
    }

    if (g_achba_link_id <= 0) { /* 小于等于0为异常值 */
        oam_error_log1(0, OAM_SF_ACHBA, "{hmac_user_del_achba::g_achba_link_id[%d] is invalid}", g_achba_link_id);
        return;
    }

    ret = g_achba_wifi_link_del_func(oal_get_achba_net(hmac_vap), g_achba_link_id);
    if (ret != OAL_SUCC) {
        oam_error_log0(0, OAM_SF_ACHBA, "{hmac_user_del_achba::link_del failed}");
    }
    g_achba_link_id = 0;
}

osal_u32 hmac_achba_init(osal_void)
{
    /* 注册对外接口 */
    hmac_feature_hook_register(HMAC_FHOOK_ACHBA_ADD_CHBA_INFO_IE, hmac_set_achba_cap_ie);
    hmac_feature_hook_register(HMAC_FHOOK_ACHBA_UPDATE_PROCESS, hmac_process_update_achba);
    hmac_feature_hook_register(HMAC_FHOOK_ACHBA_DEL_LINK_ID, hmac_user_del_achba);
    /* 注册消息 */
    frw_msg_hook_register(WLAN_MSG_W2H_CFG_IND_ACHBA_KEEPALILVE, hmac_config_ind_achba_keepalive);
    return OAL_SUCC;
}

osal_void hmac_achba_deinit(osal_void)
{
    /* 消息去注册 */
    hmac_feature_hook_unregister(HMAC_FHOOK_ACHBA_ADD_CHBA_INFO_IE);
    hmac_feature_hook_unregister(HMAC_FHOOK_ACHBA_UPDATE_PROCESS);
    hmac_feature_hook_unregister(HMAC_FHOOK_ACHBA_DEL_LINK_ID);
    return;
}

#ifdef __cplusplus
#if __cplusplus
}
#endif
#endif