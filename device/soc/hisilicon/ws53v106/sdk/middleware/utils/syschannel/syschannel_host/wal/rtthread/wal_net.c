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
#include "lwip/tcpip.h"
#include "lwip/netifapi.h"
#include "lwip/etharp.h"
#include "netif/ethernetif.h"
#include "hcc_cfg.h"

#ifdef __cplusplus
#if __cplusplus
extern "C" {
#endif
#endif

#define WAL_DEBUG(fmt, arg...) osal_printk("[WAL] "fmt, ##arg)

oal_lwip_netif* g_lwip_netif = OSAL_NULL;

/*****************************************************************************
 函 数 名  : syschannel_host_alloc_netbuf
 功能描述  : 数据帧申请接口
*****************************************************************************/
osal_u32 syschannel_host_alloc_netbuf(hcc_queue_type queue_id, osal_u32 len, osal_u8 **buf, osal_u8 **user_param)
{
    oal_lwip_buf *pbuf = OSAL_NULL;
    syschannel_stat_stru *syschannel_stat = syschannel_host_get_trx_stat();

    unref_param(queue_id);
    if (buf == OSAL_NULL || user_param == OSAL_NULL) {
        return OSAL_NOK;
    }

    pbuf = pbuf_alloc(PBUF_RAW, (osal_u16)len, PBUF_RAM);
    if (pbuf == OSAL_NULL) {
        *buf = OSAL_NULL;
        *user_param = OSAL_NULL;
        syschannel_stat->pkt_rx_alloc_fail++;
        WAL_DEBUG("func %s line %d alloc fail\r\n", __func__, __LINE__);
        return OSAL_NOK;
    }

    *buf = (osal_u8 *)pbuf->payload;
    *user_param = (osal_u8 *)pbuf;
    return OSAL_OK;
}

/*****************************************************************************
 函 数 名  : syschannel_host_netbuf_free
 功能描述  : 数据帧释放接口
*****************************************************************************/
osal_void syschannel_host_netbuf_free(hcc_queue_type queue_id, osal_u8 *buf, osal_u8 *user_param)
{
    unref_param(queue_id);
    unref_param(buf);
    if (user_param == OSAL_NULL) {
        return;
    }
    pbuf_free((oal_lwip_buf *)user_param);
}

/*****************************************************************************
 函 数 名  : syschannel_host_rx_data_process
 功能描述  : 数据帧上报rtthread协议栈接口
*****************************************************************************/
osal_u32 syschannel_host_rx_data_process(hcc_queue_type queue_id, osal_u8 stype,
    osal_u8 *buf, osal_u32 len, osal_u8 *user_param)
{
    oal_lwip_buf *lwip_buf = OSAL_NULL;
    syschannel_hdr_stru *syschannel_hdr = OSAL_NULL;
    syschannel_stat_stru *syschannel_stat = syschannel_host_get_trx_stat();
    osal_u16 data_len;
    osal_u8 pad_offset;

    unref_param(queue_id);
    unref_param(stype);
    unref_param(buf);
    unref_param(len);

    if (user_param == OSAL_NULL || g_lwip_netif == OSAL_NULL) {
        WAL_DEBUG("syschannel_host_rx_data_process:: param/netif null!\r\n");
        return OSAL_NOK;
    }

    lwip_buf = (oal_lwip_buf *)user_param;
    if (pbuf_header(lwip_buf, (osal_s16)(-hcc_get_head_len())) != OSAL_OK) {
        WAL_DEBUG("syschannel_host_rx_data_process:: headroom is not enough\r\n");
        goto pbuf_fail;
    }

    syschannel_hdr = (syschannel_hdr_stru *)lwip_buf->payload;
    data_len = syschannel_hdr->date_len;
    /* 转下字节序 */
    data_len = syschannel_ntohs(data_len);
    pad_offset = syschannel_hdr->pad_offset;
    if (pbuf_header(lwip_buf, (osal_s16)(-SYSCHANNEL_HDR_LEN)) != OSAL_OK) {
        goto pbuf_fail;
    }
    /* 判断是否经过4字节对齐偏移 */
    if ((pad_offset != 0) && pbuf_header(lwip_buf, (osal_s16)(-pad_offset)) != OSAL_OK) {
        WAL_DEBUG("func %s line %d pbuf_header fail\r\n", __func__, __LINE__);
        goto pbuf_fail;
    }
    syschannel_stat->pkt_rx++;
    lwip_buf->len = data_len;
    lwip_buf->tot_len = data_len;
    /* 将payload地址前移2字节 */
#if defined(ETH_PAD_SIZE) && ETH_PAD_SIZE
    /* 赋值 */
    pbuf_header(lwip_buf, ETH_PAD_SIZE);
#endif
    /* 上报协议栈 */
    if (g_lwip_netif->input == OSAL_NULL) {
        goto pbuf_fail;
    }
    if (g_lwip_netif->input(lwip_buf, g_lwip_netif) != ERR_OK) {
        goto pbuf_fail;
    }
    return OSAL_OK;
pbuf_fail:
    pbuf_free(lwip_buf);
    return OSAL_NOK;
}

osal_u32 syschannel_pbuf_adapt(oal_lwip_buf *lwip_buf, osal_u16 data_len)
{
    osal_u32 old_addr;
    osal_u32 new_addr;
    osal_s8 pad_offset;
    syschannel_hdr_stru *syschannel_hdr = OSAL_NULL;

    /* 先进行地址4字节对齐，记录下偏移值 */
    old_addr = (uintptr_t)lwip_buf->payload;
    new_addr = channel_round_down(old_addr, SYSCHANNEL_ADDR_ALIGN); /* HCC需要4字节对齐 */
    pad_offset = (osal_s8)(old_addr - new_addr);
    if ((pad_offset != 0) && (pbuf_header(lwip_buf, (osal_s16)pad_offset) != OSAL_OK)) {
        WAL_DEBUG("syschannel_host_tx_data_adapt:: offset headroom is not enough\r\n");
        return OSAL_NOK;
    }

    /* 先push syschannel头，保存帧体真实长度 */
    if (pbuf_header(lwip_buf, (osal_s16)SYSCHANNEL_HDR_LEN) != OSAL_OK) {
        WAL_DEBUG("syschannel_host_tx_data_adapt:: syschannel headroom is not enough\r\n");
        return OSAL_NOK;
    }
    syschannel_hdr = (syschannel_hdr_stru *)lwip_buf->payload;
    /* 转下字节序 */
    syschannel_hdr->date_len = syschannel_htons(data_len);
    syschannel_hdr->pad_offset = pad_offset;

    /* 再push hcc头 */
    if (pbuf_header(lwip_buf, (osal_s16)sizeof(hcc_header)) != OSAL_OK) {
        WAL_DEBUG("syschannel_host_tx_data_adapt:: hcc headroom is not enough\r\n");
        return OSAL_NOK;
    }
    return OSAL_OK;
}

osal_u32 syschannel_liteos_host_tx_data_adapt(oal_lwip_buf *lwip_buf, syschannel_service_type type, osal_u32 sub_type)
{
    osal_u32 ret = OSAL_NOK;
    hcc_transfer_param param;
    osal_u16 fc_flag;
    osal_u8 queue_id;
    osal_u16 data_len = 0;
    osal_u32 payload_len = 0;
    syschannel_handler *syschannel_handler = OSAL_NULL;
    syschannel_stat_stru *syschannel_stat = syschannel_host_get_trx_stat();
    osal_u8 *payload = OSAL_NULL;

    syschannel_handler = syschannel_host_get_handler();
    if ((syschannel_handler == OSAL_NULL) || (syschannel_handler->inuse == OSAL_FALSE)) {
        WAL_DEBUG("syschannel_handler is inuse\r\n");
        return OSAL_NOK;
    }

    /* 记录帧体真实长度 */
    data_len = (osal_u16)lwip_buf->len;
    syschannel_config_hcc_flowctrl_type(type, &fc_flag, &queue_id);
    syschannel_init_hcc_service_hdr(&param, type, sub_type, queue_id, fc_flag);
    param.user_param = (osal_u8 *)lwip_buf;

    /* hcc + syschannel头填充 */
    if (syschannel_pbuf_adapt(lwip_buf, data_len) != OSAL_OK) {
        return OSAL_NOK;
    }

    payload_len = lwip_buf->len;
    payload_len = channel_round_up(payload_len, SYSCHANNEL_DATA_ALIGN);
    payload = (osal_u8 *)lwip_buf->payload;
    ret = hcc_tx_data(syschannel_handler->hcc_id, payload, (td_u16)payload_len, &param);
    if (ret != OSAL_OK) {
        syschannel_stat->pkt_tx_fail++;
        WAL_DEBUG("syschannel_liteos_host_tx_data_adapt::hcc_tx_data failed ret: 0x%x\r\n", ret);
        return OSAL_NOK;
    }
    syschannel_stat->pkt_tx++;
    return OSAL_OK;
}


/* 解决lwip层/主控发下的pbuf中ref>=2场景，重传会有1s时延的问题,通过二级指针修改外部原始lwip_buf指针 */
td_u32 wal_lwip_send_ref2(oal_lwip_buf **lwip_buf, td_u8 *is_add_ref)
{
    err_t err;
    oal_lwip_buf *copy_buf = OSAL_NULL;
    oal_lwip_buf *org_buf = (*lwip_buf);

    copy_buf = pbuf_alloc(PBUF_RAW, org_buf->tot_len + PBUF_LINK_ENCAPSULATION_HLEN, PBUF_RAM);
    if (copy_buf == OSAL_NULL) {
        return OSAL_NOK;
    }
    pbuf_header(copy_buf, (td_s16)-PBUF_LINK_ENCAPSULATION_HLEN);
    err = pbuf_copy(copy_buf, org_buf);
    if (err != ERR_OK) {
        pbuf_free(copy_buf);
        return OSAL_NOK;
    }

    *lwip_buf = copy_buf;
    *is_add_ref = OSAL_FALSE; /* pbuf_alloc申请内存的时候已经将ref设置为1，后面ref不能再增加1，否则释放不了 */
    return OSAL_OK;
}

/*****************************************************************************
 函 数 名  : wal_lwip_send
 功能描述  : 向LWIP协议栈注册的发送回调函数
*****************************************************************************/
err_t wal_lwip_send(oal_lwip_netif *netif, oal_lwip_buf *lwip_buf)
{
    osal_u32 ret;
    osal_u8 is_add_ref = OSAL_TRUE;
    if ((lwip_buf == OSAL_NULL) || (netif == OSAL_NULL)) {
        WAL_DEBUG("wal_lwip_send parameter NULL.\r\n");
        return ERR_IF;
    }
    /* wal_lwip_send_ref2为解决主控发下的pbuf中ref>=2场景，重传会有1s时延的问题 */
    if (lwip_buf->ref >= 2 && (wal_lwip_send_ref2(&lwip_buf, &is_add_ref) != OSAL_OK)) {
        return ERR_IF;
    }
    if (is_add_ref == OSAL_TRUE) {
        /* 引用计数+1,避免pbuf被重复释放 */
        pbuf_ref(lwip_buf);
    }

#ifndef LWIP_NETIF_TX_SINGLE_PBUF
    /* memcpy */
    oal_lwip_buf *new_buf = pbuf_alloc(PBUF_RAW, (osal_u16)lwip_buf->tot_len + PBUF_LINK_ENCAPSULATION_HLEN, PBUF_RAM);
    if (new_buf == NULL) {
        pbuf_free(lwip_buf);
        return ERR_IF;
    }

    pbuf_header(new_buf, ((osal_s16))-PBUF_LINK_ENCAPSULATION_HLEN);
    memcpy_s(new_buf->payload, new_buf->len, lwip_buf->payload, lwip_buf->len);
    osal_u8 *new_ptr = new_buf->payload + lwip_buf->len;
    oal_lwip_buf *tmp_lwip_buf = lwip_buf->next;
    while (tmp_lwip_buf != NULL) {
        memcpy_s(new_ptr, new_buf->len, tmp_lwip_buf->payload, tmp_lwip_buf->len);
        new_ptr += tmp_lwip_buf->len;
        tmp_lwip_buf = tmp_lwip_buf->next;
    }

    pbuf_free(lwip_buf);
    ret = syschannel_liteos_host_tx_data_adapt(new_buf, SYSCHANNEL_SERVICE_TYPE_PKT, 0);
    if (ret != OSAL_OK) {
        pbuf_free(new_buf);
        return ERR_IF;
    }
#else
    /* LWIP config: #define LWIP_NETIF_TX_SINGLE_PBUF (1) #define PBUF_LINK_ENCAPSULATION_HLEN (12) */
    ret = syschannel_liteos_host_tx_data_adapt(lwip_buf, SYSCHANNEL_SERVICE_TYPE_PKT, 0);
    if (ret != OSAL_OK) {
        pbuf_free(lwip_buf);
        return ERR_IF;
    }
#endif
    return ERR_OK;
}

/*****************************************************************************
 函 数 名  : wal_lwip_netif_alloc
 功能描述  : 申请netif
*****************************************************************************/
static oal_lwip_netif *wal_lwip_netif_alloc(osal_void)
{
    oal_lwip_netif *netif = (oal_lwip_netif *)rt_malloc(sizeof(oal_lwip_netif));
    if (netif == OSAL_NULL) {
        return OSAL_NULL;
    }
    g_lwip_netif = netif;
    memset_s(netif, sizeof(oal_lwip_netif), 0, sizeof(oal_lwip_netif));
    return netif;
}

static osal_void wal_lwip_netif_free(osal_void)
{
    rt_free(g_lwip_netif);
    g_lwip_netif = OSAL_NULL;
}

#define SYSCHANNEL_MTU_SIZE 1500
err_t net_netif_device_init(struct netif *netif)
{
    osal_u8 mac_addr[ETHER_ADDR_LEN] = {0x0, 0x0, 0x0, 0x0, 0x0, 0x0};
    netif->hwaddr_len = ETHER_ADDR_LEN;
#if LWIP_IPV4
    netif->output = etharp_output;
#endif /* LWIP_IPV4 */
#if LWIP_IPV6
    netif->output_ip6 = ethip6_output;
#endif /* LWIP_IPV6 */
    netif->linkoutput = wal_lwip_send;
    netif->mtu = SYSCHANNEL_MTU_SIZE;
    netif->flags = NETIF_FLAG_BROADCAST | NETIF_FLAG_ETHARP | NETIF_FLAG_IGMP | NETIF_FLAG_MLD6 | NETIF_FLAG_ETHERNET |
        NETIF_FLAG_LINK_UP;

    /* 初始化netif名称 */
    netif->name[0] = 'w'; /* 2 string最后一位 */
    netif->name[1] = '0'; /* 2 string最后一位 */

    if (memcpy_s(netif->hwaddr, ETHER_ADDR_LEN, &mac_addr[0], ETHER_ADDR_LEN) != EOK) {
        return ERR_IF;
    }
    return ERR_OK;
}

/*****************************************************************************
 函 数 名  : netdev_register
 功能描述  : rtthread协议栈注册
*****************************************************************************/
osal_s32 netdev_register(osal_void)
{
    osal_s32 ret;
    oal_ip_addr_t gw;
    oal_ip_addr_t ip;
    oal_ip_addr_t netmask;
    oal_lwip_netif *netif = OSAL_NULL;
    syschannel_handler *syschannel_handler = syschannel_host_get_handler();

    if ((syschannel_handler == OSAL_NULL) || (syschannel_handler->inuse == OSAL_FALSE)) {
        WAL_DEBUG("syschannel_handler is not inuse\r\n");
        return OSAL_NOK;
    }

    if (g_lwip_netif != OSAL_NULL) {
        WAL_DEBUG("g_lwip_netif is not NULL\r\n");
        return OSAL_NOK;
    }

    if (rt_thread_find("tcpip") == RT_NULL) {
        WAL_DEBUG("tcpip thread is not started\r\n");
        return OSAL_NOK;
    }

    netif = wal_lwip_netif_alloc();
    if (netif == OSAL_NULL) {
        WAL_DEBUG("netif_register:: netif is NULL\r\n");
        return OSAL_NOK;
    }

    OAL_IP4_ADDR(&gw, 0, 0, 0, 0);
    OAL_IP4_ADDR(&ip, 0, 0, 0, 0);
    OAL_IP4_ADDR(&netmask, 0, 0, 0, 0);

    if (netifapi_netif_add(netif, &ip, &netmask, &gw, OSAL_NULL, net_netif_device_init, tcpip_input) != OSAL_OK) {
        WAL_DEBUG("netifapi_netif_add failed.\r\n");
        goto failure;
    }

    WAL_DEBUG("netif_register SUCCESSFULLY\r\n");
    ret = hcc_send_message(syschannel_handler->hcc_id, H2D_MSG_SYNC_MAC_IP, 0);
    if (ret != OSAL_OK) {
        WAL_DEBUG("syschannel_sync_mac_ip tx failed\r\n");
        goto failure;
    }
    return OSAL_OK;
failure:
    wal_lwip_netif_free();
    return OSAL_NOK;
}

/*****************************************************************************
 函 数 名  : netdev_unregister
 功能描述  : rtthread协议栈去注册
*****************************************************************************/
osal_void netdev_unregister(osal_void)
{
    if (g_lwip_netif == OSAL_NULL) {
        return;
    }

    netifapi_netif_remove(g_lwip_netif);
    wal_lwip_netif_free();
}

/*****************************************************************************
 函 数 名  : syschannel_host_sync_mac_addr
 功能描述  : 同步MAC接口：msg_id | mac_addr
*****************************************************************************/
osal_u32 syschannel_host_sync_mac_addr(osal_u8 *buf, osal_u32 len)
{
    if (g_lwip_netif == OSAL_NULL || len <= SYSCHANNEL_MSG_TYPE_LEN) {
        return OSAL_NOK;
    }

    /* 同步dev mac地址 */
    if (memcpy_s(g_lwip_netif->hwaddr, ETHER_ADDR_LEN, (buf + 1), ETHER_ADDR_LEN) != OSAL_OK) {
        WAL_DEBUG("syschannel_host_sync_mac_addr fail\r\n");
        return OSAL_NOK;
    }
    return OSAL_OK;
}

#define MAKEU32(a, b, c, d) (((osal_u32)((a) & 0xff) << 24) | \
                            ((osal_u32)((b) & 0xff) << 16) | \
                            ((osal_u32)((c) & 0xff) << 8) | \
                            (osal_u32)((d) & 0xff))

/*****************************************************************************
 函 数 名  : syschannel_host_sync_ip_addr
 功能描述  : 同步ip接口：msg_id | ip_addr | mask_addr | gw_addr
*****************************************************************************/
osal_u32 syschannel_host_sync_ip_addr(osal_u8 *buf, osal_u32 len)
{
    ip_addr_sync_stru *ip_addr_stru = {0};
    ip4_addr_t ip;
    ip4_addr_t mask;
    ip4_addr_t gw;

    if (g_lwip_netif == OSAL_NULL || len <= SYSCHANNEL_MSG_TYPE_LEN) {
        return OSAL_NOK;
    }

    ip_addr_stru = (ip_addr_sync_stru *)(buf + SYSCHANNEL_MSG_TYPE_LEN);

    ip.addr = MAKEU32(ip_addr_stru->ip_addr[3], ip_addr_stru->ip_addr[2], ip_addr_stru->ip_addr[1],
        ip_addr_stru->ip_addr[0]);
    mask.addr = MAKEU32(ip_addr_stru->mask_addr[3], ip_addr_stru->mask_addr[2], ip_addr_stru->mask_addr[1],
        ip_addr_stru->mask_addr[0]);
    gw.addr = MAKEU32(ip_addr_stru->gw_addr[3], ip_addr_stru->gw_addr[2], ip_addr_stru->gw_addr[1],
        ip_addr_stru->gw_addr[0]);
    netif_set_addr(g_lwip_netif, &ip, &mask, &gw);
    (void)netifapi_netif_set_up(g_lwip_netif);
    return OSAL_OK;
}

ip_addr_t syschannel_host_get_ip_addr(osal_void)
{
    ip_addr_t ret = {0};
    if (g_lwip_netif == OSAL_NULL) {
        return ret;
    }
    return g_lwip_netif->ip_addr;
}

ip_addr_t syschannel_host_get_netmask_addr(osal_void)
{
    ip_addr_t ret = {0};
    if (g_lwip_netif == OSAL_NULL) {
        return ret;
    }
    return g_lwip_netif->netmask;
}

ip_addr_t syschannel_host_get_gw_addr(osal_void)
{
    ip_addr_t ret = {0};
    if (g_lwip_netif == OSAL_NULL) {
        return ret;
    }
    return g_lwip_netif->gw;
}

osal_u8* syschannel_host_get_mac_addr(osal_void)
{
    if (g_lwip_netif == OSAL_NULL) {
        return OSAL_NULL;
    }
    return g_lwip_netif->hwaddr;
}

#ifdef __cplusplus
#if __cplusplus
}
#endif
#endif
