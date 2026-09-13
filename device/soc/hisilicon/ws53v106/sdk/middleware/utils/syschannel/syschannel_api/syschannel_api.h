/*
 * Copyright (c) HiSilicon (Shanghai) Technologies Co., Ltd. 2023. All rights reserved.
 * Description: Header file for syschannel.
 * Create: 2023-05-01
 */
#ifndef __SYSCHANNEL_API_H__
#define __SYSCHANNEL_API_H__

/*****************************************************************************
  其他头文件包含
*****************************************************************************/
#ifdef __cplusplus
#if __cplusplus
extern "C" {
#endif
#endif

/* 当前只支持SDIO_TYPE总线 */
typedef enum {
    SDIO_TYPE,
    SPI_TYPE,
    UNKNOWN_TYPE
} bus_type;

#define WIFI_FILTER_TYPE_IPV4   0
#define WIFI_FILTER_TYPE_IPV6   1

typedef enum {
    WIFI_FILTER_MASK_IP                = 0x01,
    WIFI_FILTER_MASK_PROTOCOL          = 0x02,
    WIFI_FILTER_MASK_LOCAL_PORT        = 0x04,
    WIFI_FILTER_MASK_LOCAL_PORT_RANGE  = 0x08,
    WIFI_FILTER_MASK_REMOTE_PORT       = 0x10,
    WIFI_FILTER_MASK_REMOTE_PORT_RANGE = 0x20,
    WIFI_FILTER_MASK_BUTT
} wifi_filter_field_enum;

typedef enum {
    WIFI_FILTER_LWIP             = 0,
    WIFI_FILTER_VLWIP            = 1,
    WIFI_FILTER_BOTH             = 2,
    WIFI_FILTER_BUTT
} wifi_filter_enum;

typedef struct {
    unsigned int   remote_ip;
    unsigned short local_port;
    unsigned short localp_min;
    unsigned short localp_max;
    unsigned short remote_port;
    unsigned short remotep_min;
    unsigned short remotep_max;
    unsigned char  packet_type;
    unsigned char  config_type;
    unsigned char  match_mask;
    unsigned char  channel_id; /* config_type为WIFI_FILTER_VLWIP时需要指定channel_id */
} syschannel_ipv4_filter;

#define WIFI_IPV6_ADDR_LEN   16
typedef struct {
    unsigned char  remote_ip[WIFI_IPV6_ADDR_LEN];
    unsigned short local_port;
    unsigned short localp_min;
    unsigned short localp_max;
    unsigned short remote_port;
    unsigned short remotep_min;
    unsigned short remotep_max;
    unsigned char  packet_type;
    unsigned char  config_type;
    unsigned char  match_mask;
    unsigned char  channel_id; /* config_type为WIFI_FILTER_VLWIP时需要指定channel_id */
} syschannel_ipv6_filter;

typedef struct tcp_header {
    unsigned short   us_sport;
    unsigned short   us_dport;
    unsigned int  seqnum;
    unsigned int  acknum;
    unsigned char   offset;
    unsigned char   flags;
    unsigned short   us_window;
    unsigned short   us_check;
    unsigned short   us_urgent;
} tcp_header_stru;

/* UDP Header structure */
typedef struct udp_header {
    unsigned short    us_src_port;
    unsigned short    us_des_port;
    unsigned short    us_udp_len;
    unsigned short    us_check_sum;
} udp_header_stru;

typedef struct ip_header {
    unsigned char    us_ihl : 4,            /* little endian */
             version_ihl : 4;
    /* liuming modifed proxyst end */
    unsigned char    tos;
    unsigned short    us_tot_len;
    unsigned short    us_id;
    unsigned short    us_frag_off;
    unsigned char    ttl;
    unsigned char    protocol;
    unsigned short    us_check;
    unsigned int   saddr;
    unsigned int   daddr;
    /* The options start here */
} ip_header_stru;

typedef struct {
    unsigned int pkt_tx;
    unsigned int pkt_rx;
    unsigned int pkt_tx_fail;
    unsigned int pkt_rx_alloc_fail;
    unsigned int app_msg_tx;
    unsigned int app_msg_rx;
    unsigned int app_msg_tx_fail;
    unsigned int mng_msg_tx;
    unsigned int mng_msg_rx;
    unsigned int mng_msg_tx_fail;
    unsigned int msg_rx_alloc_fail;
} syschannel_stat_stru;

/**
* @ingroup
* @brief Interface to configure default filter rule to filter table.CNcomment:设置默认过滤方向.CNend
*
* @par Description:
*        Interface to configure default filter rule to filter table.CNcomment:设置默认过滤方向.CNend
*
* @attention  NULL
* @param uc_type [IN] Type #unsigned char Direction of forwarding data.CNcomment:转发数据方向.CNend
*
* @retval #OSAL_OK        Execute successfully.
* @retval #OSAL_NOK      Execute failed.
* @par Dependency:
*            @li syschannel_api.h: SYS Channel API
* @see  NULL
*/
int uapi_syschannel_set_default_filter(unsigned char uc_type);
/**
* @ingroup
* @brief Interface to add specific filter rule to filter table.CNcomment:添加repeater过滤规则.CNend
*
* @par Description:
*        Interface to add specific filter rule to filter table.CNcomment:添加repeater过滤规则.CNend
*
* @attention  NULL
* @param filter [IN] Type #char filter data see syschannel_ipv4_filter.CNcomment:过滤数据.CNend
* @param len [IN] Type #int the length of filter data.CNcomment:过滤数据的长度.CNend
* @param type [IN] Type #unsigned char the type of filter data.CNcomment:过滤数据的类型.CNend
*
* @retval #OSAL_OK        Execute successfully.
* @retval #OSAL_NOK      Execute failed.
* @par Dependency:
*            @li syschannel_api.h: SYS Channel API
* @see  NULL
*/
int uapi_syschannel_add_filter(char *filter, int len, unsigned char type);
/**
* @ingroup
* @brief Interface to delete specific filter rule from filter table.CNcomment:删除过滤表.CNend
*
* @par Description:
*        Interface to delete specific filter rule from filter table.CNcomment:删除过滤表.CNend
*
* @attention  NULL
* @param filter [IN] Type #char filter data see syschannel_ipv4_filter.CNcomment:过滤数据.CNend
* @param len [IN] Type #int the length of filter data.CNcomment:过滤数据的长度.CNend
* @param type [IN] Type #unsigned char the type of filter data.CNcomment:过滤数据的类型.CNend
*
* @retval #OSAL_OK        Execute successfully.
* @retval #OSAL_NOK      Execute failed.
* @par Dependency:
*            @li syschannel_api.h: SYS Channel API
* @see  NULL
*/
int uapi_syschannel_del_filter(char *filter, int len, unsigned char type);
/**
* @ingroup
* @brief Interface to delete all filter rule from filter table.CNcomment:清空过滤表.CNend
*
* @par Description:
*        Interface to delete all filter rule from filter table.CNcomment:清空过滤表.CNend
*
* @attention  NULL
* @param NULL
*
* @retval NULL
* @par Dependency:
*            @li syschannel_api.h: SYS Channel API
* @see  NULL
*/
void uapi_syschannel_del_all_filter(void);
/**
* @ingroup
* @brief Interface to query filter rules from filter table.CNcomment:查询过滤表.CNend
*
* @par Description:
*        Interface to query filter rules from filter table.CNcomment:查询过滤表.CNend
*
* @attention  NULL
* @param filter [OUT] Type #char filter data see syschannel_ipv4_filter.CNcomment:过滤数据.CNend
* @param num [OUT] Type #int the length of filter data.CNcomment:过滤数据的长度.CNend
* @param type [IN] Type #unsigned char WIFI_FILTER_TYPE_IPV4
*        the type of filter data.CNcomment:过滤数据的类型.CNend
*
* @retval #OSAL_OK        Execute successfully.
* @retval #OSAL_NOK      Execute failed.
* @par Dependency:
*            @li syschannel_api.h: SYS Channel API
* @see  NULL
*/
int uapi_syschannel_query_filter(char **filter, int *num, unsigned char type);


/*****************************************************************************
  函数声明
*****************************************************************************/
typedef unsigned int (*syschannel_rx_func)(unsigned char* buf, int length);
typedef unsigned int (*syschannel_timeout_func)(void);
typedef void (*syschannel_suspend_func)(void);

/**
* @ingroup
* @brief Interface to init channel device.CNcomment:初始化channel device 侧必要资源.CNend
*
* @par Description:
*        Interface to init channel device.CNcomment:初始化channel device 侧必要资源.CNend
*
* @attention  NULL
* @param type [IN] Type #bus_type bus type CNcomment:总线类型.CNend
*
* @retval #OSAL_OK        Execute successfully.
* @retval #OSAL_NOK        Execute failed.
* @par Dependency:
*            @li syschannel_api.h: SYS Channel API
* @see  NULL
*/
unsigned int uapi_syschannel_dev_init(bus_type type);

/**
* @ingroup
* @brief Interface of send msg to host.CNcomment:发送消息.CNend
*
* @par Description:
*         Interface of send msg to host.CNcomment:发送消息.CNend
*
* @attention  NULL
* @param buf [IN] Type #char * address of buffer.CNcomment:消息内存首地址.CNend
* @param length [IN] Type #int length of buffer CNcomment:消息长度.CNend
*
* @retval #OSAL_OK        Execute successfully.
* @retval #OSAL_NOK        Execute failed.
* @par Dependency:
*            @li syschannel_api.h: SYS Channel API
* @see  NULL
*/
unsigned int uapi_syschannel_send_to_host(char* buf, int length);

/**
* @ingroup
* @brief Interface to deinit channel device.CNcomment:重新初始化channel device 侧必要资源.CNend
*
* @par Description:
*        Interface to deinit channel device.CNcomment:重新初始化channel device 侧必要资源.CNend
*
* @attention  NULL
* @param type [IN] Type #bus_type bus type.CNcomment:总线类型.CNend
*
* @retval #OSAL_OK        Execute successfully.
* @retval #OSAL_NOK        Execute failed.
* @par Dependency:
*            @li syschannel_api.h: SYS Channel API
* @see  NULL
*/
unsigned int uapi_syschannel_dev_reinit(bus_type type);

/**
* @ingroup
* @brief Interface to register msg rx callback.CNcomment:注册消息接收回调函数.CNend
*
* @par Description:
*        Interface to register msg rx callback.CNcomment:注册消息接收回调函数.CNend
*
* @attention  NULL
* @param rx_func [IN] Type #syschannel_rx_func callback function of receive message
                            CNcomment:消息接收回调函数函数指针.CNend
*
* @par Dependency:
*            @li syschannel_api.h: SYS Channel API
* @see  NULL
*/
void uapi_syschannel_register_rx_cb(syschannel_rx_func rx_func);

/**
* @ingroup
* @brief Interface to register timeout rx callback.CNcomment:注册心跳超时回调函数.CNend
*
* @par Description:
*        Interface to register timeout rx callback.CNcomment:注册心跳超时回调函数.CNend
*
* @attention  NULL
* @param rx_func [IN] Type #syschannel_timeout_func callback function of heartbeat timeout
                            CNcomment:心跳超时回调函数函数指针.CNend
*
* @par Dependency:
*            @li syschannel_api.h: SYS Channel API
* @see  NULL
*/
void uapi_syschannel_register_timeout_cb(syschannel_timeout_func timeout_func);
/**
* @ingroup
* @brief Interface to register suspend callback.CNcomment:注册suspend回调函数.CNend
*
* @par Description:
*        Interface to register suspend callback.CNcomment:注册suspend回调函数.CNend
*
* @attention  NULL
* @param suspend_func [IN] Type #syschannel_suspend_func callback function for suspend syschannel
                            CNcomment:suspend回调函数函数指针.CNend
*
* @par Dependency:
*            @li syschannel_api.h: SYS Channel API
* @see  NULL
*/
void uapi_syschannel_register_suspend_cb(syschannel_suspend_func suspend_func);

/**
* @ingroup
* @brief Interface to reset channel device.CNcomment:清空channel device资源.CNend
*
* @par Description:
*        Interface to reset channel device.CNcomment:清空channel device资源.CNend
*
* @attention  NULL
* @param type [IN] Type #bus_type bus type.CNcomment:总线类型.CNend
*
* @par Dependency:
*            @li syschannel_api.h: SYS Channel API
* @see  NULL
*/
void uapi_syschannel_dev_reset(bus_type type);

/**
* @ingroup
* @brief Interface to specifies the netif interface.CNcomment:指定netif.CNend
*
* @par Description:
*        Interface to specifies the netif interface:指定netif.CNend
*
* @attention  NULL
* @param netif_name [IN] Type #name of the specified netif interface.CNcomment:指定netif的name.CNend
*
* @par Dependency:
*            @li syschannel_api.h: SYS Channel API
* @see  NULL
*/
void uapi_syschannel_vlwip_netif_init(const char *netif_name);

/**
* @ingroup
* @brief Interface to record the dst MAC and VAP for syschannel to select paths.CNcomment:记录目的MAC地址和VAP.CNend
*
* @par Description:
*        Interface to specifies the netif interface:指定netif.CNend
*
* @attention  NULL
* @param netif_name [IN] Type #name of the record netif interface.CNcomment:记录netif的name.CNend
* @param dst_mac_addr [IN] Type #name of the record dst mac addr.CNcomment:记录netif对应的MAC地址.CNend
**
* @retval #OSAL_OK        Execute successfully.
* @retval #OSAL_NOK        Execute failed.
* @par Dependency:
*            @li syschannel_api.h: SYS Channel API
* @see  NULL
*/
unsigned int uapi_syschannel_set_mac_netif_mapping(const char* netif_name, const unsigned char* dst_mac_addr);

/**
* @ingroup
* @brief Get the sended and received pkt and message statistics information.CNcomment:获取device和host的收发报文和消息统计信息.CNend
* syschannel sdio通道要保障是正常的，出打流时由于sdio通道，数据统计可能有延迟
* @par NULL
*
* @retval #syschannel_stat_stru        Execute successfully.
* @retval #NULL                        Execute failed.
* @par Dependency:
*            @li syschannel_api.h: SYS Channel API
* @see  NULL
*/
syschannel_stat_stru* uapi_syschannel_get_trx_stat(void);

/**
* @ingroup
* @brief clean the sended and received pkt and message statistics information.CNcomment:清零device和host的收发报文和消息统计信息.CNend
*
* @par NULL
*
* @retval #OSAL_OK        Execute successfully.
* @retval #OSAL_NOK        Execute failed.
* @par Dependency:
*            @li syschannel_api.h: SYS Channel API
* @see  NULL
*/
unsigned int uapi_syschannel_clean_trx_stat(void);

/**
* @ingroup
* @brief Interface to record the dst MAC and VAP for syschannel to select paths.CNcomment:提供syschannel转发路径的回调.CNend
*
* @param dport [IN] Type #unsigned short of the record des port.CNcomment:目的端口.CNend
* @param sport [IN] Type #unsigned short of the record src port.CNcomment:源端口.CNend
* @param tcp_header [IN] Type #tcp_header_stru* of the record tcp header.CNcomment:tcp头.CNend
* @param ip_header [IN] Type #ip_header_stru* of the record ip header.CNcomment:ip头.CNend
* @param is_ipv6 [IN] Type #unsigned char whether the record is ipv6.CNcomment:是否IPV6，目前仅支持ipv4.CNend
**
* @retval WIFI_FILTER_LWIP        转发给host.
* @retval WIFI_FILTER_VLWIP       转发给device.
* @retval WIFI_FILTER_BOTH        转发给device 和 host.
* @retval WIFI_FILTER_BUTT        由syschannal原来的规则转发.
* @par Dependency:
*            @li syschannel_api.h: SYS Channel API
* @see  NULL
*/
typedef unsigned short (*syschannel_tcp_filter_cb)(unsigned short dport, unsigned short sport,
    tcp_header_stru *tcp_header, ip_header_stru *ip_header, unsigned char is_ipv6);
/**
* @ingroup
* @brief Interface to record the dst MAC and VAP for syschannel to select paths.CNcomment:提供syschannel转发路径的回调.CNend
*
* @param dport [IN] Type #unsigned short of the record des port.CNcomment:目的端口.CNend
* @param sport [IN] Type #unsigned short of the record src port.CNcomment:源端口.CNend
* @param udp_header [IN] Type #udp_header_stru* of the record tcp header.CNcomment:udp头.CNend
* @param ip_header [IN] Type #ip_header_stru* of the record ip header.CNcomment:ip头.CNend
* @param is_ipv6 [IN] Type #unsigned char whether the record is ipv6.CNcomment:否是IPV6.CNend
**
* @retval 0        转发给host.
* @retval 1        转发给device.
* @retval 2        转发给device 和 host.
* @retval 3        由syschannal原来的规则转发.
* @par Dependency:
*            @li syschannel_api.h: SYS Channel API
* @see  NULL
*/

typedef unsigned short (*syschannel_udp_filter_cb)(unsigned short dport, unsigned short sport,
    udp_header_stru *udp_header, ip_header_stru *ip_header, unsigned char is_ipv6);

/**
* @ingroup
* @brief Callback registration function for TCP filtering.CNcomment:tcp过滤的回调注册函数.CNend
*
* @param callback [IN] Type #Callback function.CNcomment:回调函数.CNend
**
* @retval NULL
* @par Dependency:
*            @li syschannel_api.h: SYS Channel API
* @see  NULL
*/
void uapi_syschannel_tcp_filter_regsiter(void *callback);

/**
* @ingroup
* @brief Callback registration function for UDP filtering.CNcomment:udp过滤的回调注册函数.CNend
*
* @param callback [IN] Type #Callback function.CNcomment:回调函数.CNend
**
* @retval NULL
* @par Dependency:
*            @li syschannel_api.h: SYS Channel API
* @see  NULL
*/
void uapi_syschannel_udp_filter_regsiter(void *callback);
#ifdef __cplusplus
#if __cplusplus
    }
#endif
#endif

#endif /* end of frw_task.h */

