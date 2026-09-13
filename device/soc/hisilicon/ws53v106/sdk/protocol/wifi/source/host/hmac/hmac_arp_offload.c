/*
 * Copyright (c) HiSilicon (Shanghai) Technologies Co., Ltd. 2015-2023. All rights reserved.
 * 文 件 名   : hmac_arp_offload.c
 * 生成日期   : 2015年5月14日
 * 功能描述   : ARP Offloading相关函数实现
 */


/*****************************************************************************
  1 头文件包含
*****************************************************************************/
#include "hmac_arp_offload.h"
#include "frw_ext_if.h"
#include "hmac_vap.h"
#include "frw_util_notifier.h"
#include "hmac_hook.h"
#include "msg_wow_rom.h"

#ifdef __cplusplus
#if __cplusplus
extern "C" {
#endif
#endif

#undef THIS_FILE_ID
#define THIS_FILE_ID DIAG_FILE_ID_WIFI_HOST_HMAC_ARP_OFFLOAD_C

#undef THIS_MOD_ID
#define THIS_MOD_ID DIAG_MOD_ID_WIFI_HOST

#ifdef _PRE_WLAN_FEATURE_WOW_OFFLOAD
#ifdef _PRE_WLAN_FEATURE_DYNAMIC_OFFLOAD
mac_vap_ip_entries_stru g_ip_addr = {0};
oal_bool_enum_uint8 g_arp_offload_switch = OSAL_TRUE;
osal_u16 g_free_arp_interval = FREE_ARP_INTERVAL_DEFAULT_VALUE;

osal_void hmac_arp_offload_get_param(mac_arp_offload_param_sync *arp_param)
{
    memcpy_s(&arp_param->ip_addr, sizeof(mac_vap_ip_entries_stru), &g_ip_addr, sizeof(mac_vap_ip_entries_stru));
    arp_param->arp_offload_switch = g_arp_offload_switch;
    arp_param->free_arp_interval = g_free_arp_interval;
}
#else
mac_cipher_info_stru g_hmac_cipher_info = {0};
#endif

/*****************************************************************************
  2 全局变量定义
*****************************************************************************/


/*****************************************************************************
  3 函数实现
*****************************************************************************/
OSAL_STATIC osal_s32 hmac_config_free_arp_interval(hmac_vap_stru *hmac_vap, frw_msg *msg)
{
#ifdef _PRE_WLAN_FEATURE_DYNAMIC_OFFLOAD
    g_free_arp_interval = *(osal_u16 *)msg->data;
#else
    (osal_void)frw_send_msg_to_device(hmac_vap->vap_id, WLAN_MSG_H2D_C_CFG_SET_FREE_ARP_INTERVAL, msg, OSAL_TRUE);
#endif
    return OAL_SUCC;
}

OSAL_STATIC osal_s32 hmac_config_enable_arp_offload(hmac_vap_stru *hmac_vap, frw_msg *msg)
{
    hmac_device_stru *hmac_device = hmac_res_get_mac_dev_etc(0);

    if (hmac_vap == OSAL_NULL || !is_legacy_sta(hmac_vap) || msg == OSAL_NULL) {
        return OAL_SUCC;
    }

    hmac_device->arp_offload_switch = *(msg->data) & BIT(0);
#ifdef _PRE_WLAN_FEATURE_DYNAMIC_OFFLOAD
    g_arp_offload_switch = *(osal_u16 *)msg->data;
#else
    (osal_void)frw_send_msg_to_device(hmac_vap->vap_id, WLAN_MSG_H2D_C_CFG_SET_ARP_OFFLOAD_SWITCH, msg, OSAL_TRUE);
#endif
    return OAL_SUCC;
}

OSAL_STATIC osal_s32 hmac_config_sync_ip_info(const hmac_vap_stru *hmac_vap)
{
#ifndef _PRE_WLAN_FEATURE_DYNAMIC_OFFLOAD
    mac_vap_ip_entries_stru ip_info;
    frw_msg msg_info = {0};

    memcpy_s(&ip_info, sizeof(mac_vap_ip_entries_stru), hmac_vap->ip_addr_info, sizeof(mac_vap_ip_entries_stru));

    /* 抛事件至Device侧DMAC，同步ip info */
    frw_msg_init((osal_u8 *)&ip_info, sizeof(mac_vap_ip_entries_stru), OSAL_NULL, 0, &msg_info);
    (osal_void)frw_send_msg_to_device(hmac_vap->vap_id, WLAN_MSG_H2D_C_CFG_SYNC_IP_INFO, &msg_info, OSAL_FALSE);
#else
    memcpy_s(&g_ip_addr, sizeof(mac_vap_ip_entries_stru), hmac_vap->ip_addr_info, sizeof(mac_vap_ip_entries_stru));
#endif
    return OAL_SUCC;
}

#ifdef _PRE_WIFI_DEBUG
OSAL_STATIC osal_void hmac_config_ip_print(const hmac_vap_stru *hmac_vap, const dmac_ip_addr_config_stru *ip_addr_info)
{
    osal_u16 ip_addr_temp;

    if (ip_addr_info->type == DMAC_CONFIG_IPV4) {
        oam_warning_log4(0, OAM_SF_PWR,
            "vap_id[%d] {hmac_config_ip_print::Add IPv4 address[%d.%d.%d.*] failed, no empty array.}",
            hmac_vap->vap_id,
            ((osal_u8 *)&(ip_addr_info->ip_addr))[0],   /* 0表示ipv4地址的第0位 */
            ((osal_u8 *)&(ip_addr_info->ip_addr))[1],   /* 1表示ipv4地址的第1位 */
            ((osal_u8 *)&(ip_addr_info->ip_addr))[2]);  /* 2表示ipv4地址的第2位 */
    } else if (ip_addr_info->type == DMAC_CONFIG_IPV6) {
        ip_addr_temp = oal_net2host_short(((osal_u16 *)&(ip_addr_info->ip_addr))[2]); /* 2表示ipv6地址的第2位 */
        ip_addr_temp = (ip_addr_temp & 0xff00) >> 8;    /* 取IPv6第2个地址的高8bit */
        oam_warning_log3(0, OAM_SF_PWR,
            "{hmac_config_ip_print::Add IPv6 address[%04x:%04x:%02x*:*:*:*:*:*] failed,no empty array}",
            oal_net2host_short(((osal_u16 *)&(ip_addr_info->ip_addr))[0]), /* 0表示ipv6地址的第0位 */
            oal_net2host_short(((osal_u16 *)&(ip_addr_info->ip_addr))[1]), /* 1表示ipv6地址的第1位 */
            ip_addr_temp);
    }
}
#endif

OSAL_STATIC osal_bool hmac_arp_offload_vap_add(osal_void *notify_data)
{
    hmac_vap_stru *hmac_vap = (hmac_vap_stru *)notify_data;

    if (!is_legacy_sta(hmac_vap)) {
        return OSAL_TRUE;
    }

    hmac_vap->ip_addr_info = oal_mem_alloc(OAL_MEM_POOL_ID_LOCAL, sizeof(mac_vap_ip_entries_stru), OAL_TRUE);
    if (osal_unlikely(hmac_vap->ip_addr_info == OSAL_NULL)) {
        oam_error_log1(0, 0, "vap_id[%d] {hmac_arp_offload_vap_add::Alloc ip_addr_info failed.}", hmac_vap->vap_id);
        return OSAL_FALSE;
    }
    (osal_void)memset_s(hmac_vap->ip_addr_info, sizeof(mac_vap_ip_entries_stru), 0, sizeof(mac_vap_ip_entries_stru));
#ifndef _PRE_WLAN_FEATURE_DYNAMIC_OFFLOAD
    (osal_void)memset_s(&g_hmac_cipher_info, sizeof(mac_cipher_info_stru), 0, sizeof(mac_cipher_info_stru));
#endif
    return OSAL_TRUE;
}

OSAL_STATIC osal_bool hmac_arp_offload_vap_del(osal_void *notify_data)
{
    hmac_vap_stru *hmac_vap = (hmac_vap_stru *)notify_data;

    if (!is_legacy_sta(hmac_vap)) {
        return OSAL_TRUE;
    }

    if (hmac_vap->ip_addr_info != OSAL_NULL) {
        oal_mem_free(hmac_vap->ip_addr_info, OAL_TRUE);
        hmac_vap->ip_addr_info = OSAL_NULL;
    }
#ifndef _PRE_WLAN_FEATURE_DYNAMIC_OFFLOAD
    (osal_void)memset_s(&g_hmac_cipher_info, sizeof(mac_cipher_info_stru), 0, sizeof(mac_cipher_info_stru));
#endif
    return OSAL_TRUE;
}

#ifndef _PRE_WLAN_FEATURE_DYNAMIC_OFFLOAD
OSAL_STATIC osal_bool hmac_arp_offload_cipher_init(osal_void *notify_data)
{
    hmac_user_stru *hmac_user = (hmac_user_stru *)notify_data;
    hmac_vap_stru *hmac_vap = OSAL_NULL;

    if (hmac_user == OSAL_NULL) {
        return OSAL_TRUE;
    }

    hmac_vap = mac_res_get_hmac_vap(hmac_user->vap_id);
    if (hmac_vap == OSAL_NULL || !is_legacy_sta(hmac_vap)) {
        return OSAL_TRUE;
    }

    (osal_void)memset_s(&g_hmac_cipher_info, sizeof(mac_cipher_info_stru), 0, sizeof(mac_cipher_info_stru));
    return OSAL_TRUE;
}

OSAL_STATIC osal_s32 hmac_config_cipher_info_sync(hmac_vap_stru *hmac_vap)
{
    osal_s32 ret;
    frw_msg msg = { 0 };

    msg.data = (osal_u8 *)&g_hmac_cipher_info;
    msg.data_len = (osal_u16)sizeof(mac_cipher_info_stru);
    ret = frw_send_msg_to_device(hmac_vap->vap_id, WLAN_MSG_H2D_C_CFG_WOW_PARAM_SYNC, &msg, OSAL_TRUE);
    if (ret != OAL_SUCC) {
        oam_error_log1(0, OAM_SF_ANY, "{hmac_config_wow_param_sync:send_msg_to_device failed[%d].}", ret);
    }
    return ret;
}

OSAL_STATIC osal_u32 hmac_arp_offload_process_tx_frame(hmac_vap_stru *hmac_vap, const oal_netbuf_stru *netbuf)
{
    mac_tx_ctl_stru *tx_ctl = (mac_tx_ctl_stru *)oal_netbuf_cb((oal_netbuf_stru *)netbuf);

    if (!is_legacy_sta(hmac_vap) || mac_get_is_data_frame(tx_ctl) == OSAL_FALSE) {
        return OAL_FAIL;
    }

   /* 学习单播数据报文的加密类型 */
    if (ether_is_multicast(((mac_ieee80211_frame_stru *)oal_netbuf_header(netbuf))->address1) == OSAL_FALSE) {
        if (g_hmac_cipher_info.cipher_key_type != tx_ctl->cipher_key_type ||
            g_hmac_cipher_info.cipher_protocol_type != tx_ctl->cipher_protocol_type ||
            g_hmac_cipher_info.cipher_key_id != tx_ctl->cipher_key_id ||
            g_hmac_cipher_info.ra_lut_index != tx_ctl->ra_lut_index) {
            g_hmac_cipher_info.cipher_key_type = tx_ctl->cipher_key_type;
            g_hmac_cipher_info.cipher_protocol_type = tx_ctl->cipher_protocol_type;
            g_hmac_cipher_info.cipher_key_id = tx_ctl->cipher_key_id;
            g_hmac_cipher_info.ra_lut_index = tx_ctl->ra_lut_index;
            hmac_config_cipher_info_sync(hmac_vap);
        }
    }

    return OAL_SUCC;
}

osal_u32 hmac_arp_offload_tx_hookfn(oal_netbuf_stru **netbuf, hmac_vap_stru *hmac_vap)
{
    if (hmac_vap == OSAL_NULL || netbuf == OSAL_NULL || *netbuf == OSAL_NULL) {
        return OAL_CONTINUE;
    }

    hmac_arp_offload_process_tx_frame(hmac_vap, *netbuf);

    return OAL_CONTINUE;
}

hmac_netbuf_hook_stru g_offload_tx_netbuf_hook = {
    .hooknum = HMAC_FRAME_DATA_TX_EVENT_H2D,
    .priority = HMAC_HOOK_PRI_MIDDLE,
    .hook_func = hmac_arp_offload_tx_hookfn,
};

/*****************************************************************************
 函 数 名  : hmac_config_ip_add
 功能描述  : 增加IP地址
*****************************************************************************/
OSAL_STATIC osal_u32 hmac_config_ip_add(const hmac_vap_stru *hmac_vap, const dmac_ip_addr_config_stru *ip_addr_info)
{
    mac_vap_ipv4_addr_stru *ipv4_addr = OSAL_NULL;
    mac_vap_ipv6_addr_stru *ipv6_addr = OSAL_NULL;

    if (osal_unlikely(hmac_vap->ip_addr_info == OSAL_NULL)) {
        oam_error_log1(0, 0, "vap_id[%d] {hmac_config_ip_add::IP record memory is not alloced.}", hmac_vap->vap_id);
        return OAL_FAIL;
    }

    ipv4_addr = &(hmac_vap->ip_addr_info->ipv4_entry[0]);
    ipv6_addr = &(hmac_vap->ip_addr_info->ipv6_entry[0]);

    if (ip_addr_info->type == DMAC_CONFIG_IPV4) {
        /* IP未变化，不更新 */
        if (oal_memcmp(ipv4_addr->local_ip.auc_value, ip_addr_info->ip_addr, OAL_IPV4_ADDR_SIZE) == 0) {
            return OAL_SUCC;
        }
        (osal_void)memcpy_s(ipv4_addr->local_ip.auc_value, OAL_IPV4_ADDR_SIZE, ip_addr_info->ip_addr,
            OAL_IPV4_ADDR_SIZE);
        (osal_void)memcpy_s(ipv4_addr->mask.auc_value, OAL_IPV4_ADDR_SIZE, ip_addr_info->mask_addr,
            OAL_IPV4_ADDR_SIZE);
    } else if (ip_addr_info->type == DMAC_CONFIG_IPV6) {
        (osal_void)memcpy_s(ipv6_addr->ip_addr, OAL_IPV6_ADDR_SIZE, ip_addr_info->ip_addr, OAL_IPV6_ADDR_SIZE);
    } else {
        return OAL_FAIL;
    }

    return (osal_u32)hmac_config_sync_ip_info(hmac_vap);
}

/*****************************************************************************
 函 数 名  : hmac_config_ip_del
 功能描述  : 删除IP地址
*****************************************************************************/
OSAL_STATIC osal_s32 hmac_config_ip_del(hmac_vap_stru *hmac_vap, const dmac_ip_addr_config_stru *ip_addr_info)
{
    if (ip_addr_info->type == DMAC_CONFIG_IPV4) {
        (osal_void)memset_s(hmac_vap->ip_addr_info->ipv4_entry[0].local_ip.auc_value,
            OAL_IPV4_ADDR_SIZE, 0, OAL_IPV4_ADDR_SIZE);
        (osal_void)memset_s(hmac_vap->ip_addr_info->ipv4_entry[0].mask.auc_value,
            OAL_IPV4_ADDR_SIZE, 0, OAL_IPV4_ADDR_SIZE);
    } else if (ip_addr_info->type == DMAC_CONFIG_IPV6) {
        (osal_void)memset_s(hmac_vap->ip_addr_info->ipv6_entry[0].ip_addr,
            OAL_IPV6_ADDR_SIZE, 0, OAL_IPV6_ADDR_SIZE);
    }

    hmac_config_sync_ip_info(hmac_vap);
    return OAL_SUCC;
}
#else
/*****************************************************************************
 函 数 名  : hmac_config_ip_add
 功能描述  : 增加IP地址
*****************************************************************************/
OSAL_STATIC osal_u32 hmac_config_ip_add(const hmac_vap_stru *hmac_vap, const dmac_ip_addr_config_stru *ip_addr_info)
{
    oal_bool_enum_uint8 comp = OSAL_FALSE;
    osal_u32 loop;

    if (osal_unlikely(hmac_vap->ip_addr_info == OSAL_NULL)) {
        oam_error_log1(0, 0, "vap_id[%d] {hmac_config_ip_add::IP record memory is not alloced.}", hmac_vap->vap_id);
        return OAL_FAIL;
    }

    oam_warning_log2(0, OAM_SF_PWR, "vap[%d] {hmac_config_ip_add::IP type[%d]}", hmac_vap->vap_id, ip_addr_info->type);

    if (ip_addr_info->type == DMAC_CONFIG_IPV4) {
        for (loop = 0; loop < MAC_MAX_IPV4_ENTRIES; loop++) {
            mac_vap_ipv4_addr_stru *ipv4_addr = &(hmac_vap->ip_addr_info->ipv4_entry[loop]);
            if ((comp == OSAL_FALSE) && ((hmac_vap->ip_addr_info->ipv4_entry[loop].local_ip.value) == 0)) {
                comp = OSAL_TRUE; /* 增加完成 */
                (osal_void)memcpy_s(ipv4_addr->local_ip.auc_value, OAL_IPV4_ADDR_SIZE, ip_addr_info->ip_addr,
                    OAL_IPV4_ADDR_SIZE);
                (osal_void)memcpy_s(ipv4_addr->mask.auc_value, OAL_IPV4_ADDR_SIZE, ip_addr_info->mask_addr,
                    OAL_IPV4_ADDR_SIZE);
                continue;
            } else if (oal_memcmp(ipv4_addr->local_ip.auc_value, ip_addr_info->ip_addr, OAL_IPV4_ADDR_SIZE) != 0) {
                continue;
            } else if (comp == OSAL_TRUE) {
                (osal_void)memset_s(ipv4_addr->local_ip.auc_value, OAL_IPV4_ADDR_SIZE, 0, OAL_IPV4_ADDR_SIZE);
                (osal_void)memset_s(ipv4_addr->mask.auc_value, OAL_IPV4_ADDR_SIZE, 0, OAL_IPV4_ADDR_SIZE);
            }
            comp = OSAL_TRUE;
        }
    } else if (ip_addr_info->type == DMAC_CONFIG_IPV6) {
        for (loop = 0; loop < MAC_MAX_IPV6_ENTRIES; loop++) {
            mac_vap_ipv6_addr_stru *ipv6_addr = &(hmac_vap->ip_addr_info->ipv6_entry[loop]);
            if ((comp == OSAL_FALSE) && oal_ipv6_is_unspecified_addr(ipv6_addr->ip_addr)) {
                comp = OSAL_TRUE; /* 增加完成 */
                (osal_void)memcpy_s(ipv6_addr->ip_addr, OAL_IPV6_ADDR_SIZE, ip_addr_info->ip_addr, OAL_IPV6_ADDR_SIZE);
                continue;
            } else if (oal_memcmp(ipv6_addr->ip_addr, ip_addr_info->ip_addr, OAL_IPV6_ADDR_SIZE) != 0) {
                continue;
            } else if (comp == OSAL_TRUE) {
                (osal_void)memset_s(ipv6_addr->ip_addr, OAL_IPV6_ADDR_SIZE, 0, OAL_IPV6_ADDR_SIZE);
            }
            comp = OSAL_TRUE;
        }
    } else {
        return OAL_FAIL;
    }

#ifdef _PRE_WIFI_DEBUG
    if (comp == OSAL_FALSE) {
        hmac_config_ip_print(hmac_vap, ip_addr_info);
    }
#endif

    return (osal_u32)hmac_config_sync_ip_info(hmac_vap);
}

/*****************************************************************************
 函 数 名  : hmac_config_ip_del
 功能描述  : 删除IP地址
*****************************************************************************/
OSAL_STATIC osal_s32 hmac_config_ip_del(hmac_vap_stru *hmac_vap, const dmac_ip_addr_config_stru *ip_addr_info)
{
    osal_u32 loop;
    oal_bool_enum_uint8 comp = OSAL_FALSE;

    if (ip_addr_info->type == DMAC_CONFIG_IPV4) {
        for (loop = 0; loop < MAC_MAX_IPV4_ENTRIES; loop++) {
            if ((comp == OSAL_FALSE) && (hmac_vap->ip_addr_info != OSAL_NULL) &&
                (oal_memcmp(hmac_vap->ip_addr_info->ipv4_entry[loop].local_ip.auc_value,
                ip_addr_info->ip_addr, OAL_IPV4_ADDR_SIZE) == 0)) {
                comp = OSAL_TRUE; /* 删除完成 */
                (osal_void)memset_s(hmac_vap->ip_addr_info->ipv4_entry[loop].local_ip.auc_value,
                    OAL_IPV4_ADDR_SIZE, 0, OAL_IPV4_ADDR_SIZE);
                (osal_void)memset_s(hmac_vap->ip_addr_info->ipv4_entry[loop].mask.auc_value,
                    OAL_IPV4_ADDR_SIZE, 0, OAL_IPV4_ADDR_SIZE);
                break;
            }
        }
    } else if (ip_addr_info->type == DMAC_CONFIG_IPV6) {
        for (loop = 0; loop < MAC_MAX_IPV6_ENTRIES; loop++) {
            if ((comp == OSAL_FALSE) && (hmac_vap->ip_addr_info != OSAL_NULL) &&
                (oal_memcmp(hmac_vap->ip_addr_info->ipv6_entry[loop].ip_addr,
                ip_addr_info->ip_addr, OAL_IPV6_ADDR_SIZE) == 0)) {
                comp = OSAL_TRUE; /* 删除完成 */
                (osal_void)memset_s(hmac_vap->ip_addr_info->ipv6_entry[loop].ip_addr,
                    OAL_IPV6_ADDR_SIZE, 0, OAL_IPV6_ADDR_SIZE);
                break;
            }
        }
    } else {
        oam_error_log2(0, OAM_SF_PWR, "vap_id[%d] {hmac_config_ip_del::IP type[%d] is wrong.}",
            hmac_vap->vap_id, ip_addr_info->type);
        return OAL_FAIL;
    }

    if (comp == OSAL_FALSE) {
        if (ip_addr_info->type == DMAC_CONFIG_IPV4) {
            oam_warning_log4(0, OAM_SF_ANY, "vap_id[%d] {hmac_config_ip_del::Delete IPv4 address[%d.%d.%d.*] failed}",
                hmac_vap->vap_id, ((osal_u8 *)&(ip_addr_info->ip_addr))[0], ((osal_u8 *)&(ip_addr_info->ip_addr))[1],
                ((osal_u8 *)&(ip_addr_info->ip_addr))[2]); /* 2表示ipv4地址的第2位 */
        } else if (ip_addr_info->type == DMAC_CONFIG_IPV6) {
            oam_warning_log3(0, OAM_SF_PWR,
                "{hmac_config_ip_del::Delete IPv6 address[%04x:%04x:%02x*:*:*:*:*:*] failed, not exist}",
                oal_net2host_short(((osal_u16 *)&(ip_addr_info->ip_addr))[0]),
                oal_net2host_short(((osal_u16 *)&(ip_addr_info->ip_addr))[1]),
                /* 第2字节取高8bit */
                (oal_net2host_short(((osal_u16 *)&(ip_addr_info->ip_addr))[2]) & 0xff00) >> 8);
        }
        return OAL_FAIL;
    }
    return OAL_SUCC;
}
#endif

/*****************************************************************************
 函 数 名  : hmac_config_ip_addr
 功能描述  : 配置IP地址信息
*****************************************************************************/
OSAL_STATIC osal_s32 hmac_config_set_ip_addr(hmac_vap_stru *hmac_vap, frw_msg *msg)
{
    dmac_ip_addr_config_stru *ip_addr_info = (dmac_ip_addr_config_stru *)msg->data;

    /* vap已经删除、非sta，不处理 */
    if (hmac_vap->vap_state == MAC_VAP_STATE_BUTT || (!is_legacy_sta(hmac_vap))) {
        oam_warning_log2(0, OAM_SF_PWR,
            "vap_id[%d] {hmac_config_set_ip_addr::IP [%d] proc has down.}", hmac_vap->vap_id, ip_addr_info->oper);
        return OAL_SUCC;
    }

    switch (ip_addr_info->oper) {
        case DMAC_IP_ADDR_ADD: {
            return (osal_s32)hmac_config_ip_add(hmac_vap, ip_addr_info);
        }
        case DMAC_IP_ADDR_DEL: {
            return hmac_config_ip_del(hmac_vap, ip_addr_info);
        }
        default: {
            oam_error_log2(0, OAM_SF_PWR,
                "vap_id[%d] {hmac_config_set_ip_addr::IP operation[%d] wrong.}", hmac_vap->vap_id, ip_addr_info->oper);
            break;
        }
    }
    return OAL_FAIL;
}

osal_u32 hmac_arp_offload_init(osal_void)
{
    frw_msg_hook_register(WLAN_MSG_W2H_C_CFG_FREE_ARP_INTERVAL, hmac_config_free_arp_interval);
    frw_msg_hook_register(WLAN_MSG_W2H_C_CFG_ENABLE_ARP_OFFLOAD, hmac_config_enable_arp_offload);
    frw_msg_hook_register(WLAN_MSG_W2H_CFG_SET_IPADDR, hmac_config_set_ip_addr);
    frw_util_notifier_register(WLAN_UTIL_NOTIFIER_EVENT_ADD_VAP, hmac_arp_offload_vap_add);
    frw_util_notifier_register(WLAN_UTIL_NOTIFIER_EVENT_DEL_VAP, hmac_arp_offload_vap_del);
#ifndef _PRE_WLAN_FEATURE_DYNAMIC_OFFLOAD
    frw_util_notifier_register(WLAN_UTIL_NOTIFIER_EVENT_ADD_USER, hmac_arp_offload_cipher_init);
    hmac_register_netbuf_hook(&g_offload_tx_netbuf_hook);
#endif
    return OAL_SUCC;
}

osal_void hmac_arp_offload_deinit(osal_void)
{
#ifndef _PRE_WLAN_FEATURE_DYNAMIC_OFFLOAD
    frw_util_notifier_unregister(WLAN_UTIL_NOTIFIER_EVENT_ADD_USER, hmac_arp_offload_cipher_init);
    hmac_unregister_netbuf_hook(&g_offload_tx_netbuf_hook);
#endif
    frw_msg_hook_unregister(WLAN_MSG_W2H_CFG_SET_IPADDR);
    frw_util_notifier_unregister(WLAN_UTIL_NOTIFIER_EVENT_ADD_VAP, hmac_arp_offload_vap_add);
    frw_util_notifier_unregister(WLAN_UTIL_NOTIFIER_EVENT_DEL_VAP, hmac_arp_offload_vap_del);
    frw_msg_hook_unregister(WLAN_MSG_W2H_C_CFG_FREE_ARP_INTERVAL);
    frw_msg_hook_unregister(WLAN_MSG_W2H_C_CFG_ENABLE_ARP_OFFLOAD);
    return;
}

#endif

#ifdef __cplusplus
#if __cplusplus
}
#endif
#endif

