/*
 * Copyright (c) HiSilicon (Shanghai) Technologies Co., Ltd. 2024-2024. All rights reserved.
 * Description: syschannel
 */

/*****************************************************************************
  1 头文件包含
*****************************************************************************/
#include "wal_net.h"
#include "securec.h"
#include "hcc_if.h"
#include "syschannel_host_adapt.h"

#ifdef __cplusplus
#if __cplusplus
extern "C" {
#endif
#endif

/* static 函数声明 */
STATIC oal_net_device_stats_stru* wal_netdev_get_stats(oal_net_device_stru *netdev);
STATIC osal_s32 wal_netdev_open(oal_net_device_stru *netdev);
STATIC osal_s32 wal_netdev_stop(oal_net_device_stru *netdev);
STATIC oal_net_dev_tx_enum wal_net_start_xmit(oal_netbuf_stru *netbuf, oal_net_device_stru *netdev);
STATIC osal_s32 wal_net_device_ioctl(oal_net_device_stru *netdev, oal_ifreq_stru *ifr, osal_s32 cmd);
STATIC osal_s32 wal_netdev_set_mac_addr(oal_net_device_stru *netdev, osal_void *addr);

#ifdef CONFIG_WEXT_PRIV
static osal_u32 wal_ioctl_get_param(oal_net_device_stru *netdev, oal_iw_request_info_stru *info, osal_void *iw,
    osal_s8 *pc_extra);
static osal_u32 wal_ioctl_set_param(oal_net_device_stru *netdev, oal_iw_request_info_stru *info, osal_void *iw,
    osal_s8 *pc_extra);

#define WAL_IOCTL_PRIV_SETPARAM             (OAL_SIOCIWFIRSTPRIV + 0)
#define WAL_IOCTL_PRIV_GETPARAM             (OAL_SIOCIWFIRSTPRIV + 1)
#define WAL_IOCTL_CMD_LEN                   512

/* 全局变量定义 */
static const oal_iw_priv_args_stru g_ast_iw_priv_args[] = {
    {WAL_IOCTL_PRIV_SETPARAM,    OAL_IW_PRIV_TYPE_CHAR | WAL_IOCTL_CMD_LEN, 0, "SET"}, /* 字符个数为512 */
    {WAL_IOCTL_PRIV_GETPARAM,    0, OAL_IW_PRIV_TYPE_CHAR | WAL_IOCTL_CMD_LEN, "GET"}, /* 字符个数为512 */
};

static const oal_iw_handler g_ast_iw_priv_handlers[] = {
    (oal_iw_handler)wal_ioctl_set_param,           /* SIOCWFIRSTPRIV+0 */  /* sub-ioctl set 入口 */
    (oal_iw_handler)wal_ioctl_get_param,           /* SIOCWFIRSTPRIV+1 */  /* sub-ioctl get 入口 */
};
#endif
oal_iw_handler_def_stru g_iw_handler_def = {
#ifdef CONFIG_WEXT_PRIV
    .private                = g_ast_iw_priv_handlers,
    .num_private            = osal_array_size(g_ast_iw_priv_handlers),
    .private_args           = g_ast_iw_priv_args,
    .num_private_args       = osal_array_size(g_ast_iw_priv_args),
#endif
    .get_wireless_stats     = OSAL_NULL
};

oal_net_device_ops_stru g_wal_net_dev_ops = {
    .ndo_get_stats          = wal_netdev_get_stats,
    .ndo_open               = wal_netdev_open,
    .ndo_stop               = wal_netdev_stop,
    .ndo_start_xmit         = wal_net_start_xmit,
    .ndo_do_ioctl           = wal_net_device_ioctl,
    .ndo_set_mac_address    = wal_netdev_set_mac_addr,
};

/* 函数定义 */
#ifdef CONFIG_WEXT_PRIV
/*****************************************************************************
 函 数 名  : wal_netdev_get_stats
 功能描述  : 获取统计信息
*****************************************************************************/
static osal_u32 wal_ioctl_get_param(oal_net_device_stru *netdev, oal_iw_request_info_stru *info, osal_void *iw,
    osal_s8 *pc_extra)
{
    unref_param(netdev);
    unref_param(info);
    unref_param(iw);
    unref_param(pc_extra);
    return OSAL_OK;
}

static osal_u32 wal_ioctl_set_param(oal_net_device_stru *netdev, oal_iw_request_info_stru *info, osal_void *iw,
    osal_s8 *pc_extra)
{
    unref_param(netdev);
    unref_param(info);
    unref_param(iw);
    unref_param(pc_extra);
    return OSAL_OK;
}
#endif

STATIC oal_net_device_stats_stru* wal_netdev_get_stats(oal_net_device_stru *netdev)
{
    oal_net_device_stats_stru  *stats = OSAL_NULL;

    if (netdev == OSAL_NULL) {
        return OSAL_NULL;
    }

    stats = (oal_net_device_stats_stru *)&(netdev->stats);
    stats->rx_packets = 10; /* rx_packets 10 */
    stats->rx_bytes   = 10; /* rx_bytes 10 */
    stats->tx_packets = 10; /* tx_packets 10 */
    stats->tx_bytes   = 10; /* tx_bytes 10 */

    return stats;
}

STATIC osal_s32 wal_netdev_open(oal_net_device_stru *netdev)
{
    if ((oal_netdevice_flags(netdev) & OAL_IFF_RUNNING) == 0) {
        oal_netdevice_flags(netdev) |= OAL_IFF_RUNNING;
    }
    return OSAL_OK;
}

STATIC osal_s32 wal_netdev_stop(oal_net_device_stru *netdev)
{
    if ((oal_netdevice_flags(netdev) & OAL_IFF_RUNNING) != 0) {
        oal_netdevice_flags(netdev) &= (~OAL_IFF_RUNNING);
    }
    return OSAL_OK;
}

/* syschannel与hcc适配发送接口 */
STATIC osal_u32 syschannel_netbuf_len_align(oal_netbuf_stru *netbuf, osal_u32 align_len)
{
    osal_s32 ret;
    osal_u32 len_algin;
    osal_u32 tail_room_len;
    osal_u32 len = oal_netbuf_len(netbuf);
    if ((len & (align_len - 1)) == 0) {
        return OSAL_OK;
    }

    /* align the netbuf */
    len_algin = channel_round_up(len, align_len);
    tail_room_len = len_algin - len;
    if (tail_room_len > oal_netbuf_tailroom(netbuf)) {
        /* tailroom not enough */
        ret = oal_netbuf_expand_head(netbuf, 0, (osal_s32)tail_room_len, OSAL_GFP_KERNEL);
        if (ret != OSAL_OK) {
            return OSAL_NOK;
        }
    }
    oal_netbuf_put(netbuf, tail_room_len);

    return OSAL_OK;
}

osal_u32 syschannel_linux_host_tx_data_adapt(oal_netbuf_stru *netbuf, syschannel_service_type type, osal_u32 sub_type)
{
    osal_u32 ret = OSAL_NOK;
    hcc_transfer_param param;
    osal_u16 fc_flag;
    osal_u8 queue_id;
    osal_u32 len_align = 0;
    osal_u16 data_len = 0;
    syschannel_hdr_stru *syschannel_hdr = OSAL_NULL;
    syschannel_handler *syschannel_handler = OSAL_NULL;
    syschannel_stat_stru *syschannel_stat = syschannel_host_get_trx_stat();

    if (netbuf == OSAL_NULL) {
        return OSAL_NOK;
    }

#ifdef _PRE_SYSCHANNEL_DEBUG
    osal_printk("syschannel_host_tx_data_adapt\r\n");
#endif
    syschannel_handler = syschannel_host_get_handler();
    if ((syschannel_handler == OSAL_NULL) || (syschannel_handler->inuse == OSAL_FALSE)) {
        osal_printk("syschannel_handler is inuse\r\n");
        return OSAL_NOK;
    }

    if (oal_netbuf_headroom(netbuf) < (SYSCHANNEL_HDR_LEN + sizeof(hcc_header))) {
        osal_printk("syschannel_host_tx_data_adapt:: headroom is not enough, headroom[%d]",
            oal_netbuf_headroom(netbuf));
        return OSAL_NOK;
    }

    syschannel_config_hcc_flowctrl_type(type, &fc_flag, &queue_id);
    syschannel_init_hcc_service_hdr(&param, type, sub_type, queue_id, fc_flag);
    param.user_param = (osal_u8 *)netbuf;
    data_len = (osal_u16)oal_netbuf_len(netbuf);

    /* 先push syschannel头，保存帧体真实长度 */
    oal_netbuf_push(netbuf, SYSCHANNEL_HDR_LEN);
    syschannel_hdr = (syschannel_hdr_stru *)oal_netbuf_data(netbuf);
    /* 转下字节序 */
    syschannel_hdr->date_len = syschannel_htons(data_len);
    syschannel_hdr->pad_offset = 0;
    oal_netbuf_push(netbuf, sizeof(hcc_header));
    len_align = SYSCHANNEL_DATA_ALIGN;
    if (syschannel_netbuf_len_align(netbuf, len_align) != OSAL_OK) {
        return OSAL_NOK;
    }

    ret = hcc_tx_data(syschannel_handler->hcc_id, oal_netbuf_data(netbuf), oal_netbuf_len(netbuf), &param);
    if (ret != OSAL_OK) {
        syschannel_stat->pkt_tx_fail++;
        return OSAL_NOK;
    }
    syschannel_stat->pkt_tx++;
#ifdef _PRE_SYSCHANNEL_DEBUG
    osal_printk("syschannel_host_tx_data_adapt::hcc_tx_data end\r\n");
#endif
    return OSAL_OK;
}

/* 注册给TCP/IP 协议栈的XMIT回调 */
STATIC oal_net_dev_tx_enum wal_net_start_xmit(oal_netbuf_stru *netbuf, oal_net_device_stru *netdev)
{
    osal_u32 ret;
    oal_netbuf_stru *skb_buff;
    if ((netbuf == OSAL_NULL) || (netdev == OSAL_NULL)) {
        osal_printk("wal_bridge_vap_xmit:: invalid params[%p][%p]\r\n", netbuf, netdev);
        return OAL_NETDEV_TX_OK;
    }

    if ((oal_netdevice_flags(netdev) & OAL_IFF_RUNNING) == 0) {
        osal_printk("wal_net_start_xmit:: netdev is not RUNNING");
        oal_netbuf_free(netbuf);
        return OAL_NETDEV_TX_OK;
    }

    skb_buff = oal_netbuf_alloc(oal_netbuf_len(netbuf), 0, 0);
    if (skb_buff == OSAL_NULL) {
        osal_printk("***wal_net_start_xmit:: alloc_sbk failed");
        oal_netbuf_free(netbuf);
        return OAL_NETDEV_TX_OK;
    }

    memcpy_s(oal_netbuf_data(skb_buff), oal_netbuf_len(netbuf), oal_netbuf_data(netbuf), oal_netbuf_len(netbuf));
    oal_netbuf_len(skb_buff) = oal_netbuf_len(netbuf);

    oal_netbuf_free(netbuf);

    oal_netbuf_next(skb_buff) = OSAL_NULL;
    oal_netbuf_prev(skb_buff) = OSAL_NULL;

    ret = syschannel_linux_host_tx_data_adapt(skb_buff, SYSCHANNEL_SERVICE_TYPE_PKT, 0);
    if (ret != OSAL_OK) {
        oal_netbuf_free(skb_buff);
    }

    return OAL_NETDEV_TX_OK;
}

STATIC osal_s32 wal_net_device_ioctl(oal_net_device_stru *netdev, oal_ifreq_stru *ifr, osal_s32 cmd)
{
    unref_param(cmd);
    osal_u32 ret = OSAL_OK;

    if ((netdev == OSAL_NULL) || (ifr == OSAL_NULL) || (ifr->ifr_data == OSAL_NULL)) {
        osal_printk("{wal_net_device_ioctl::pst_dev %p, pst_ifr %p!\r\n}", (uintptr_t)netdev, (uintptr_t)ifr);
        return OSAL_NOK;
    }
    return ret;
}

/*****************************************************************************
 函 数 名  : wal_netdev_set_mac_addr
 功能描述  : 设置mac地址
 输入参数  : netdev: 网络设备
             addr : 地址
*****************************************************************************/
STATIC osal_s32 wal_netdev_set_mac_addr(oal_net_device_stru *netdev, osal_void *addr)
{
    oal_sockaddr_stru *mac_addr = OSAL_NULL;

    if ((netdev == OSAL_NULL) || (addr == OSAL_NULL)) {
        osal_printk("{wal_netdev_set_mac_addr::pst_net_dev or p_addr null ptr error %p, %p!\r\n}", \
            (uintptr_t)netdev, (uintptr_t)addr);

        return OSAL_NOK;
    }

    if (oal_netif_running(netdev)) {
        osal_printk("{wal_netdev_set_mac_addr::cannot set address; device running!}");
        return OSAL_NOK;
    }

    mac_addr = (oal_sockaddr_stru *)addr;

    if (ether_is_multicast(mac_addr->sa_data)) {
        osal_printk("{wal_netdev_set_mac_addr::can not set group/broadcast addr!}");
        return OSAL_NOK;
    }

    if (memcpy_s((netdev->dev_addr), WLAN_MAC_ADDR_LEN, (mac_addr->sa_data), WLAN_MAC_ADDR_LEN) != EOK) {
        osal_printk("{wal_netdev_set_mac_addr::mem safe function err!}");
        return OSAL_NOK;
    }

    return OSAL_OK;
}

oal_net_device_ops_stru* wal_get_net_dev_ops(osal_void)
{
    return &g_wal_net_dev_ops;
}

oal_iw_handler_def_stru* wal_get_g_iw_handler_def(osal_void)
{
    return &g_iw_handler_def;
}

osal_u32 wal_net_register_netdev(oal_net_device_stru* netdev)
{
    if (netdev == OSAL_NULL) {
        return OSAL_NOK;
    }

    return oal_net_register_netdev(netdev);
}

STATIC osal_void syschannel_init_netdev(osal_u8 type, oal_net_device_stru *netdev)
{
    unref_param(type);
#ifdef CONFIG_WIRELESS_EXT
    netdev->wireless_handlers = wal_get_g_iw_handler_def();
#endif
    netdev->netdev_ops        = wal_get_net_dev_ops();

    oal_netdevice_destructor(netdev)      = wal_net_free_netdev;
    oal_netdevice_ifalias(netdev)         = OSAL_NULL;
    oal_netdevice_watchdog_timeo(netdev)  = 5; /* 固定设置为 5 */
    oal_netdevice_qdisc(netdev, OSAL_NULL);

    oal_netdevice_flags(netdev) &= ~OAL_IFF_RUNNING;   /* 将net device的flag设为down */

    return;
}

osal_s32 netdev_register(osal_void)
{
    oal_net_device_stru *netdev = OSAL_NULL;
    osal_char dev_name[OAL_IF_NAME_SIZE] = "wlan0";
    osal_s32 ret;
    netdev = wal_net_alloc_netdev(0, dev_name, oal_ether_setup);
    if (netdev == OSAL_NULL) {
        osal_printk("regiser_netdev:: netdev is NULL");
        return OSAL_NOK;
    }

    syschannel_init_netdev(NL80211_IFTYPE_STATION, netdev);

    ret = wal_net_register_netdev(netdev);
    if (ret != OSAL_OK) {
        osal_printk("{regiser_netdev:: wal_net_register_netdev failed[%d]}", ret);
        wal_net_free_netdev(netdev);
        return ret;
    }

    osal_printk("netdev_register SUCCESSFULLY");
    return OSAL_OK;
}

osal_void netdev_unregister(osal_void)
{
    oal_net_device_stru *netdev = oal_dev_get_by_name("wlan0");
    if (netdev == OSAL_NULL) {
        osal_printk("netdev_unregister:: netdev is NULL");
        return;
    }

    oal_dev_put(netdev);
    oal_netdevice_flags(netdev) &= ~OAL_IFF_RUNNING;
    oal_net_unregister_netdev(netdev);
}

osal_u32 syschannel_host_alloc_netbuf(hcc_queue_type queue_id, osal_u32 len, osal_u8 **buf, osal_u8 **user_param)
{
    unref_param(queue_id);
    oal_netbuf_stru *netbuf = OSAL_NULL;
    syschannel_stat_stru *syschannel_stat = syschannel_host_get_trx_stat();

    if (buf == OSAL_NULL || user_param == OSAL_NULL) {
        return OSAL_NOK;
    }

    netbuf = oal_netdev_alloc_skb(OSAL_NULL, len);
    if (netbuf == OSAL_NULL) {
        osal_printk("{[WIFI][E]rx no mem:%u}", len);
        *buf = OSAL_NULL;
        *user_param = OSAL_NULL;
        syschannel_stat->pkt_rx_alloc_fail++;
        return OSAL_NOK;
    }

    oal_netbuf_put(netbuf, len);
    *buf = oal_netbuf_data(netbuf);
    *user_param = (osal_u8 *)netbuf;
    return OSAL_OK;
}

osal_void syschannel_host_netbuf_free(hcc_queue_type queue_id, osal_u8 *buf, osal_u8 *user_param)
{
    unref_param(queue_id);
    unref_param(buf);
    if (user_param == OSAL_NULL) {
        return;
    }

    oal_netbuf_free((oal_netbuf_stru *)user_param);
}

STATIC osal_s32 wal_rx_data_proc(oal_netbuf_stru *netbuf)
{
    oal_net_device_stru *netdev = oal_dev_get_by_name("wlan0");
    if (netdev == OSAL_NULL) {
        osal_printk("wal_rx_data_proc:: netdev is NULL");
        oal_netbuf_free(netbuf);
        return OSAL_NOK;
    }

    oal_dev_put(netdev);
    /* 对protocol模式赋值 */
    oal_netbuf_protocol(netbuf) = oal_eth_type_trans(netbuf, netdev);
    return oal_netif_rx_ni(netbuf);
}

osal_u32 syschannel_host_rx_data_process(hcc_queue_type queue_id, osal_u8 stype,
    osal_u8 *buf, osal_u32 len, osal_u8 *user_param)
{
    unref_param(queue_id);
    unref_param(stype);
    unref_param(buf);
    unref_param(len);
    oal_netbuf_stru *netbuf = (oal_netbuf_stru *)user_param;
    syschannel_hdr_stru *syschannel_hdr = OSAL_NULL;
    syschannel_stat_stru *syschannel_stat = syschannel_host_get_trx_stat();
    osal_u16 data_len;
    osal_u8 pad_offset;

    oal_netbuf_next(netbuf) = OSAL_NULL;
    oal_netbuf_prev(netbuf) = OSAL_NULL;
    oal_netbuf_pull(netbuf, sizeof(hcc_header));
    syschannel_hdr = (syschannel_hdr_stru *)oal_netbuf_data(netbuf);
    data_len = syschannel_hdr->date_len;
    /* 转下字节序 */
    data_len = syschannel_ntohs(data_len);
    pad_offset = syschannel_hdr->pad_offset;
    oal_netbuf_pull(netbuf, SYSCHANNEL_HDR_LEN);
    /* 判断是否经过4字节对齐偏移 */
    if (pad_offset != 0) {
        oal_netbuf_pull(netbuf, pad_offset);
    }
    syschannel_stat->pkt_rx++;
    netbuf->tail = netbuf->data + data_len;
    oal_netbuf_len(netbuf) = data_len;
    if (wal_rx_data_proc(netbuf) != OSAL_OK) {
        osal_printk("syschannel_host_rx_data_process:: wal_rx_data_proc failed");
        return OSAL_NOK;
    }

    return OSAL_OK;
}

/* buf内容：msg_id | mac_addr */
osal_u32 syschannel_host_sync_mac_addr(osal_u8 *buf, osal_u32 len)
{
    return OSAL_OK;
}

/* buf内容：msg_id | ip_addr | mask_addr | gw_addr */
osal_u32 syschannel_host_sync_ip_addr(osal_u8 *buf, osal_u32 len)
{
    return OSAL_OK;
}

#ifdef __cplusplus
#if __cplusplus
}
#endif
#endif
