/*
 * Copyright (c) HiSilicon (Shanghai) Technologies Co., Ltd. 2021-2021. All rights reserved.
 * Description: memory config
 * Create: 2021-11-22
 */
#ifndef __OAL_MEM_POOL_H__
#define __OAL_MEM_POOL_H__

#ifdef BUILD_UT
#include "wifi_ut_stub.h"
#endif

#ifdef BUILD_UT
#else
#if defined(_PRE_WLAN_FEATURE_DAQ) && defined(CONFIG_DIAG_MODE)
#define OAL_PKTRAM_ADDR_END             0x00027FFF    // 32k
#define OAL_PKTRAM_ADDR_BEGIN           0x00020000
#define OAL_ALWAYS_PKTRAM_ADDR_END      0x00027FFF    // 32k
#define OAL_ALWAYS_PKTRAM_ADDR_BEGIN    0x00020000
#elif defined(CONFIG_MCU_MODE_2)
#define OAL_PKTRAM_ADDR_END             0x0002DFFF    // 40k
#define OAL_PKTRAM_ADDR_BEGIN           0x00024000
#define OAL_ALWAYS_PKTRAM_ADDR_END      0x0002DFFF    // 40k
#define OAL_ALWAYS_PKTRAM_ADDR_BEGIN    0x00024000
#else
#define OAL_PKTRAM_ADDR_END             0x0002FFFF    // 48k
#define OAL_PKTRAM_ADDR_BEGIN           0x00024000
#define OAL_ALWAYS_PKTRAM_ADDR_END      0x0002FFFF    // 48k
#define OAL_ALWAYS_PKTRAM_ADDR_BEGIN    0x00024000
#endif
#endif
#define OAL_PKTRAM_CALI_RSV             (0 * 1024)  // do not rsv ram

/* 预先申请全局变量长度, 73本地内存使用osal接口申请 */
#define USE_OAL_MEM_TOTAL_ADDR          1

/* 各池起始地址 */
#define OAL_MEM_ADDR_TXBFEB_PKT         ((uintptr_t)NULL)
#define OAL_MEM_ADDR_TXBFEE_BUFF        (OAL_PKTRAM_ADDR_BEGIN)  /* pktram */
#define OAL_MEM_ADDR_PROTECT            (OAL_MEM_ADDR_TXBFEE_BUFF + WLAN_TXBFEE_BUFF_SIZE)
#define OAL_MEM_ADDR_COEX               (OAL_MEM_ADDR_PROTECT + WLAN_PROTECT_MAX_LEN)
#define OAL_MEM_ADDR_BEACON_PKT         (OAL_MEM_ADDR_COEX + WLAN_COEX_PKT_LEN)
#define OAL_MEM_ADDR_NETBUF             (OAL_MEM_ADDR_BEACON_PKT + WLAN_BEACON_PKT_LEN)
#define OAL_MEM_ADDR_LOCAL              ((uintptr_t)NULL) /* 全局变量 */

#define OAL_NETBUF_HIGH_PRIORITY_COUNT  5

/* 描述符个数的宏定义: (SMALL + NORMAL + HI RX-Q) <= WLAN_MEM_RX_DSCR_CNT */
#define WLAN_MEM_RX_DSCR_SIZE           64           /* 等于接收描述符结构体,13 * 4 + 12 = 64 */
#define WLAN_MEM_TX_DSCR_SIZE           92           /* 等于发送描述符结构体 19 * 4 + 16 = 92 */

#define WLAN_MEM_RX_DSCR_CNT            0            /* 包括小包，大包，管理帧 */
#define WLAN_MEM_TX_DSCR_CNT            0
#define WLAN_MEM_SMALL_RX_MAX_CNT       4
#if defined(_PRE_WLAN_FEATURE_DAQ) && defined(CONFIG_DIAG_MODE)
#define WLAN_MEM_NORMAL_RX_MAX_CNT      4
#else
#define WLAN_MEM_NORMAL_RX_MAX_CNT      8
#endif
#define WLAN_MEM_HIGH_RX_MAX_CNT        4

/* 本地变量内存池配置信息70k */
#define WLAN_MEM_LOCAL_SIZE1            12
#define WLAN_MEM_LOCAL_CNT1             128             /* TID 和HAL VAP */

#define WLAN_MEM_LOCAL_SIZE2            64
#define WLAN_MEM_LOCAL_CNT2             176             /* 200(杂用) */

#define WLAN_MEM_LOCAL_SIZE3            264
#define WLAN_MEM_LOCAL_CNT3             25

#define WLAN_MEM_LOCAL_SIZE4            512             /* 长度为128的事件队列用 */
#define WLAN_MEM_LOCAL_CNT4             4

#define WLAN_MEM_LOCAL_SIZE5            608             /* PNO扫描使用  hash桶初始化使用1 */
#define WLAN_MEM_LOCAL_CNT5             8               /* wps ie 增加1片, 实测SoftAp场景又有6次申请该内存，共8 */

#define WLAN_MEM_LOCAL_SIZE6            1024
#define WLAN_MEM_LOCAL_CNT6             0               /* dmac_reset_lut_init 使用1 */

#define WLAN_MEM_LOCAL_SIZE7            1528            /* dmac_user_stru 使用 */
#define WLAN_MEM_LOCAL_CNT7             ((WLAN_DTCM_RAM_ASSOC_USER_MAX_NUM) + (WLAN_MULTI_USER_MAX_NUM_LIMIT))

#define WLAN_MEM_LOCAL_SIZE8            4100          /* alg 使用、 msg初始化分配内存使用，msg id rom化由3260--->3800 */
#define WLAN_MEM_LOCAL_CNT8             WLAN_DTCM_RAM_ASSOC_USER_MAX_NUM

/* MIB内存池 */
#define WLAN_MEM_MIB_SIZE1              512             /* mib结构体大小 */
#define WLAN_MEM_MIB_CNT1               0               /* 配置VAP没有MIB WLAN_SERVICE_VAP_SUPPORT_MAX_NUM_LIMIT */

/* pktram不足时可从系统内存申请的大小 */
#define WLAN_RAM_NETBUF_MAX_SIZE        0

/* netbuf内存池 */
#define WLAN_SHORT_NETBUF_SIZE          180             /* 短帧长度 payload:180 */
#define WLAN_SMGMT_NETBUF_SIZE          400             /* 短管理帧长度 payload:400 */
#define WLAN_MGMT_NETBUF_SIZE           768             /* 管理帧长度 payload:768 */
#define WLAN_LARGE_NETBUF_SIZE          1600            /* 长帧长度 payload:1600 */

#if defined(_PRE_WLAN_FEATURE_DAQ) && defined(CONFIG_DIAG_MODE)
#define WLAN_SHORT_NETBUF_CNT           8               /* 短帧netbufpayload个数 */
#define WLAN_MGMT_NETBUF_CNT            7               /* 管理帧netbufpayload个数 */
#define WLAN_LARGE_NETBUF_CNT           11              /* 长帧netbufpayload个数 */
#elif defined(CONFIG_MCU_MODE_2)
#define WLAN_SHORT_NETBUF_CNT           14              /* 短帧netbufpayload个数 */
#define WLAN_MGMT_NETBUF_CNT            7               /* 管理帧netbufpayload个数 */
#define WLAN_LARGE_NETBUF_CNT           15              /* 长帧netbufpayload个数 */
#else
#define WLAN_SHORT_NETBUF_CNT           14              /* 短帧netbufpayload个数 */
#define WLAN_MGMT_NETBUF_CNT            8               /* 管理帧netbufpayload个数 */
#define WLAN_LARGE_NETBUF_CNT           19              /* 长帧netbufpayload个数 */
#endif
#define WLAN_SMGMT_NETBUF_CNT           0               /* 短管理帧netbufpayload个数 */
#define WLAN_ALWAYS_SHORT_NETBUF_CNT    6              /* 长发长收短帧netbufpayload个数 */
#define WLAN_ALWAYS_SMGMT_NETBUF_CNT    0               /* 长发长收短管理帧netbufpayload个数 */
#define WLAN_ALWAYS_MGMT_NETBUF_CNT     4               /* 长发长收管理帧netbufpayload个数 */
#if defined(CONFIG_MCU_MODE_2)
#define WLAN_ALWAYS_NETBUF_CNT          6
#else
#define WLAN_ALWAYS_NETBUF_CNT          8               /* 长发长收netbufpayload个数 */
#endif
#define ZERO_COPY_PBUF_HDR_LEN      0
#define ZERO_COPY_SKB_HDR_LEN       0
#define LWIP_ZERO_COPY_HDR    (ZERO_COPY_PBUF_HDR_LEN + ZERO_COPY_SKB_HDR_LEN)

#endif /* end of oal_mem_pool.h */
