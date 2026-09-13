/*
 * Copyright (c) HiSilicon (Shanghai) Technologies Co., Ltd. 2023. All rights reserved.
 * Author: IoT software develop group.
 * Create: 2023-03-17.
 */

#ifndef SYSCHANNEL_WAL_API_H
#define SYSCHANNEL_WAL_API_H
#include "syschannel_netbuf.h"
#include "lwip/netif.h"

#ifdef __cplusplus
#if __cplusplus
extern "C" {
#endif
#endif
#define MAC_MUTLTICAST  1

#ifndef WLAN_MAC_ADDR_LEN
#define WLAN_MAC_ADDR_LEN 6
#endif

typedef struct ether_header {
    osal_u8    auc_ether_dhost[WLAN_MAC_ADDR_LEN];
    osal_u8    auc_ether_shost[WLAN_MAC_ADDR_LEN];
    osal_u16   us_ether_type;
} ether_header_stru;

typedef struct {
    osal_void *netif;
    osal_u8 dst_mac_addr[WLAN_MAC_ADDR_LEN];
} syschannel_netif_name_mac_addr;

osal_void syschannel_driverif_send(syschannel_netbuf_stru *syschannel_netbuf);
osal_u32 syschannel_driverif_receive(osal_void *buf);
osal_void syschannel_netif_clear(const osal_void *netif);
osal_void syschannel_netif_create(osal_void);
osal_void* get_syschannel_netif(osal_void);
#ifdef __cplusplus
#if __cplusplus
    }
#endif
#endif
#endif