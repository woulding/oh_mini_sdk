/**
 * Copyright (c) HiSilicon (Shanghai) Technologies Co., Ltd. 2022-2023. All rights reserved.
 *
 * Description: Application core main function for standard \n
 *
 * History: \n
 * 2022-07-27, Create file. \n
 */

#include "lwip/netifapi.h"
#include "wifi_hotspot.h"
#include "wifi_hotspot_config.h"
#include "td_base.h"
#include "td_type.h"
#include "stdlib.h"
#include "uart.h"
#include "cmsis_os2.h"
#include "app_init.h"
#include "soc_osal.h"
#include "lwip/sockets.h"
#include "los_task.h"
#include "los_mux.h"
#include "los_cpup.h"
#include "los_task_pri.h"

#define WIFI_IFNAME_MAX_SIZE             16
#define WIFI_MAX_SSID_LEN                33
#define WIFI_SCAN_AP_LIMIT               64
#define WIFI_MAC_LEN                     6
#define WIFI_STA_SAMPLE_LOG              "[WIFI_STA_SAMPLE]"
#define WIFI_NOT_AVALLIABLE              0
#define WIFI_AVALIABE                    1
#define WIFI_GET_IP_MAX_COUNT            300
#define WIFI_TASK_PRIO                  (osPriority_t)(13)
#define WIFI_TASK_DURATION_MS           2000
#define WIFI_TASK_STACK_SIZE            0x1000

#define WIFI_TCP_SAMPLE_LOG              "[WIFI_TCP_SAMPLE]"
#define WIFI_TCP_SAMPLE_DST_IP           "192.168.50.100"
#define WIFI_SSID                        "tcp_test"
#define WIFI_TEST                        "1a2b3c4d"  /* 用于demo WIFI连接调试 */

#define TCP_SAMPLE_OK   0
#define TCP_SAMPLE_FAIL (-1)
#define TCP_SAMPLE_INVALID_SOCKET (-1)

#define TCP_SAMPLE_DEFAULT_PORT 5001
#define TCP_SAMPLE_DEFAULT_UDP_BUFLEN   1470
#define TCP_SAMPLE_DEFAULT_TCP_SAMPLE_BUFLEN  100
#define TCP_SAMPLE_DEFAULT_RX_TIMEOUT 60 /* 60sec */
#define TCP_SAMPLE_DEFAULT_TX_TIMEOUT 10 /* 10sec */

#define TCP_SAMPLE_MASK_CLIENT (1U << 0)
#define TCP_SAMPLE_MASK_SERVER (1U << 1)
#define TCP_SAMPLE_MASK_UDP    (1U << 2)
#define TCP_SAMPLE_MASK_TCP    (1U << 3)

#define TCP_SAMPLE_TRAFFIC_NAME "TCP_SAMPLE_Traffic"
#define TCP_SAMPLE_TRAFFIC_CLIENT_PRIORITY 20
#define TCP_SAMPLE_TRAFFIC_SERVER_PRIORITY 5  /* TcpSample优先级保持与lwip wifi优先级一致，减少任务切换时间 */
#define TCP_SAMPLE_TRAFFIC_STACK_SIZE 0x2000 /* Must be greater than or equals 8K */
#define TCP_SAMPLE_REPORTER_NAME "TCP_SAMPLE_SendPacket"
#define TCP_SAMPLE_REPORTER_PRIORITY 2
#ifdef LOSCFG_KERNEL_SMP
#define TCP_SAMPLE_REPORTER_STACK_SIZE 0x2000 /* Must be greater than or equals 4K */
#else
#define TCP_SAMPLE_REPORTER_STACK_SIZE 0x2000 /* Must be greater than or equals 4K */
#endif

#define TCP_SAMPLE_IS_SERVER(mask) (((mask) & TCP_SAMPLE_MASK_SERVER) == TCP_SAMPLE_MASK_SERVER)
#define TCP_SAMPLE_IS_CLIENT(mask) (((mask) & TCP_SAMPLE_MASK_CLIENT) == TCP_SAMPLE_MASK_CLIENT)
#define TCP_SAMPLE_IS_UDP(mask)    (((mask) & TCP_SAMPLE_MASK_UDP)    == TCP_SAMPLE_MASK_UDP)
#define TCP_SAMPLE_IS_TCP(mask)    (((mask) & TCP_SAMPLE_MASK_TCP)    == TCP_SAMPLE_MASK_TCP)

static void wifi_scan_state_changed(int32_t state, int32_t size);
static void wifi_connection_changed(int32_t state, const wifi_linked_info_stru *info, int32_t reason_code);

wifi_event_stru wifi_event_cb = {
    .wifi_event_connection_changed      = wifi_connection_changed,
    .wifi_event_scan_state_changed      = wifi_scan_state_changed,
};

enum {
    WIFI_STA_SAMPLE_INIT = 0,       /* 0:初始态 */
    WIFI_STA_SAMPLE_SCANING,        /* 1:扫描中 */
    WIFI_STA_SAMPLE_SCAN_DONE,      /* 2:扫描完成 */
    WIFI_STA_SAMPLE_FOUND_TARGET,   /* 3:匹配到目标AP */
    WIFI_STA_SAMPLE_CONNECTING,     /* 4:连接中 */
    WIFI_STA_SAMPLE_CONNECT_DONE,   /* 5:关联成功 */
    WIFI_STA_SAMPLE_GET_IP,         /* 6:获取IP */
} wifi_state_enum;

typedef struct {
    union {
        struct in_addr srcIP4;
        struct in6_addr srcIP6;
    } u1;
    union {
        struct in_addr dstIP4;
        struct in6_addr dstIP6;
    } u2;
    uint16_t port;
    uint8_t  mask;
    uint64_t total;
    uint8_t *buffer;
    uint32_t bufLen;
} TcpSampleParams;

typedef struct {
    bool isFinish; /* TcpSample stopped normally */
    int32_t trafficSock;
    TcpSampleParams param;
} TcpSampleContext;

static uint8_t g_wifi_state = WIFI_STA_SAMPLE_INIT;
static TcpSampleContext *g_TcpSampleContext = NULL;
static uint32_t g_TcpSampleMutex = 0xFFFFFFFF;

static int32_t TcpSampleServerPhase1(TcpSampleContext *context, int32_t domain, socklen_t addrLen,
    struct sockaddr *local, struct sockaddr *remote);
static void TcpSampleServerPhase2(TcpSampleContext *context);
static uint32_t CmdTcpSample(void);
static int32_t TcpSampleClientPhase1(TcpSampleContext *context, int32_t domain, socklen_t addrLen,
    struct sockaddr *local, struct sockaddr *remote);
static void TcpSampleClientPhase2(void);
static void TcpSampleServerGo(TcpSampleContext *context);

/*****************************************************************************
  WIFI连接
*****************************************************************************/
/*****************************************************************************
  STA 扫描事件回调函数
*****************************************************************************/
static void wifi_scan_state_changed(int32_t state, int32_t size)
{
    UNUSED(state);
    UNUSED(size);
    PRINT("%s::Scan done!.\r\n", WIFI_STA_SAMPLE_LOG);
    g_wifi_state = WIFI_STA_SAMPLE_SCAN_DONE;
    return;
}

/*****************************************************************************
  STA 关联事件回调函数
*****************************************************************************/
static void wifi_connection_changed(int32_t state, const wifi_linked_info_stru *info, int32_t reason_code)
{
    UNUSED(info);
    UNUSED(reason_code);

    if (state == WIFI_NOT_AVALLIABLE) {
        PRINT("%s::Connect fail!. try agin !\r\n", WIFI_STA_SAMPLE_LOG);
        g_wifi_state = WIFI_STA_SAMPLE_INIT;
    } else {
        PRINT("%s::Connect succ!.\r\n", WIFI_STA_SAMPLE_LOG);
        g_wifi_state = WIFI_STA_SAMPLE_CONNECT_DONE;
    }
}

/*****************************************************************************
  STA 匹配目标AP
*****************************************************************************/
int32_t example_get_match_network(wifi_sta_config_stru *expected_bss)
{
    int32_t  ret;
    uint32_t  num = 64; /* 64:扫描到的Wi-Fi网络数量 */
    char expected_ssid[] = WIFI_SSID;
    char test[] = WIFI_TEST;
    bool find_ap = TD_FALSE;
    uint8_t   bss_index;
    /* 获取扫描结果 */
    uint32_t scan_len = sizeof(wifi_scan_info_stru) * WIFI_SCAN_AP_LIMIT;
    wifi_scan_info_stru *result = osal_kmalloc(scan_len, OSAL_GFP_ATOMIC);
    if (result == TD_NULL) {
        return -1;
    }
    memset_s(result, scan_len, 0, scan_len);
    ret = wifi_sta_get_scan_info(result, &num);
    if (ret != 0) {
        osal_kfree(result);
        return -1;
    }
    /* 筛选扫描到的Wi-Fi网络，选择待连接的网络 */
    for (bss_index = 0; bss_index < num; bss_index ++) {
        if (strlen(expected_ssid) == strlen(result[bss_index].ssid)) {
            if (memcmp(expected_ssid, result[bss_index].ssid, strlen(expected_ssid)) == 0) {
                find_ap = TD_TRUE;
                break;
            }
        }
    }
    /* 未找到待连接AP,可以继续尝试扫描或者退出 */
    if (find_ap == TD_FALSE) {
        osal_kfree(result);
        return -1;
    }
    /* 找到网络后复制网络信息和接入密码 */
    if (memcpy_s(expected_bss->ssid, WIFI_MAX_SSID_LEN, expected_ssid, strlen(expected_ssid)) != 0) {
        osal_kfree(result);
        return -1;
    }
    if (memcpy_s(expected_bss->bssid, WIFI_MAC_LEN, result[bss_index].bssid, WIFI_MAC_LEN) != 0) {
        osal_kfree(result);
        return -1;
    }
    expected_bss->security_type = result[bss_index].security_type;
    if (expected_bss->security_type != WIFI_SEC_TYPE_OPEN &&
        memcpy_s(expected_bss->pre_shared_key, WIFI_MAX_SSID_LEN, test, strlen(test)) != 0) {
        osal_kfree(result);
        return -1;
    }
    expected_bss->ip_type = 1; /* 1：IP类型为动态DHCP获取 */
    osal_kfree(result);
    return 0;
}

/*****************************************************************************
  STA 关联状态查询
*****************************************************************************/
bool example_check_connect_status(void)
{
    uint8_t index;
    wifi_linked_info_stru wifi_status;
    /* 获取网络连接状态，共查询5次，每次间隔500ms */
    for (index = 0; index < 5; index ++) {
        (void)osDelay(50); /* 50: 延时500ms */
        memset_s(&wifi_status, sizeof(wifi_linked_info_stru), 0, sizeof(wifi_linked_info_stru));
        if (wifi_sta_get_ap_info(&wifi_status) != 0) {
            continue;
        }
        if (wifi_status.conn_state == 1) {
            return 0; /* 连接成功退出循环 */
        }
    }
    return -1;
}

/*****************************************************************************
  STA DHCP状态查询
*****************************************************************************/
bool example_check_dhcp_status(struct netif *netif_p, uint32_t *wait_count)
{
    if ((ip_addr_isany(&(netif_p->ip_addr)) == 0) && (*wait_count <= WIFI_GET_IP_MAX_COUNT)) {
        /* DHCP成功 */
        PRINT("%s::STA DHCP success.\r\n", WIFI_STA_SAMPLE_LOG);
        return 0;
    }

    if (*wait_count > WIFI_GET_IP_MAX_COUNT) {
        PRINT("%s::STA DHCP timeout, try again !.\r\n", WIFI_STA_SAMPLE_LOG);
        *wait_count = 0;
        g_wifi_state = WIFI_STA_SAMPLE_INIT;
    }
    return -1;
}

static int32_t example_sta_function(void)
{
    char ifname[WIFI_IFNAME_MAX_SIZE + 1] = "wlan0"; /* 创建的STA接口名 */
    wifi_sta_config_stru expected_bss = {0}; /* 连接请求信息 */
    struct netif *netif_p = TD_NULL;
    uint32_t wait_count = 0;

    /* 创建STA接口 */
    if (wifi_sta_enable() != 0) {
        return -1;
    }
    PRINT("%s::STA enable succ.\r\n", WIFI_STA_SAMPLE_LOG);

    do {
        (void)osDelay(1); /* 1: 等待10ms后判断状态 */
        if (g_wifi_state == WIFI_STA_SAMPLE_INIT) {
            PRINT("%s::Scan start!\r\n", WIFI_STA_SAMPLE_LOG);
            g_wifi_state = WIFI_STA_SAMPLE_SCANING;
            /* 启动STA扫描 */
            if (wifi_sta_scan() != 0) {
                g_wifi_state = WIFI_STA_SAMPLE_INIT;
                continue;
            }
        } else if (g_wifi_state == WIFI_STA_SAMPLE_SCAN_DONE) {
            /* 获取待连接的网络 */
            if (example_get_match_network(&expected_bss) != 0) {
                PRINT("%s::Do not find AP, try again !\r\n", WIFI_STA_SAMPLE_LOG);
                g_wifi_state = WIFI_STA_SAMPLE_INIT;
                continue;
            }
            g_wifi_state = WIFI_STA_SAMPLE_FOUND_TARGET;
        } else if (g_wifi_state == WIFI_STA_SAMPLE_FOUND_TARGET) {
            PRINT("%s::Connect start.\r\n", WIFI_STA_SAMPLE_LOG);
            g_wifi_state = WIFI_STA_SAMPLE_CONNECTING;
            /* 启动连接 */
            if (wifi_sta_connect(&expected_bss) != 0) {
                g_wifi_state = WIFI_STA_SAMPLE_INIT;
                continue;
            }
        } else if (g_wifi_state == WIFI_STA_SAMPLE_CONNECT_DONE) {
            PRINT("%s::DHCP start.\r\n", WIFI_STA_SAMPLE_LOG);
            g_wifi_state = WIFI_STA_SAMPLE_GET_IP;
            netif_p = netifapi_netif_find(ifname);
            if (netif_p == TD_NULL || netifapi_dhcp_start(netif_p) != 0) {
                g_wifi_state = WIFI_STA_SAMPLE_INIT;
                continue;
            }
        } else if (g_wifi_state == WIFI_STA_SAMPLE_GET_IP) {
            if (example_check_dhcp_status(netif_p, &wait_count) == 0) {
                break;
            }
            wait_count++;
        }
    } while (1);

    // 开启TcpSample建立Tcp连接
    CmdTcpSample();

    return 0;
}

/*****************************************************************************
  TCP连接
*****************************************************************************/
/*****************************************************************************
  TCP Server创建
*****************************************************************************/
static void TcpSampleServerPhase2(TcpSampleContext *context)
{
    int32_t recvLen;

    while (context->isFinish == FALSE) {
        recvLen = recv(context->trafficSock, context->param.buffer, context->param.bufLen, 0);
        if (recvLen < 0) {
            if (errno == EAGAIN) {
                (void)osDelay(100); /* 100: 延时1s */
                continue;
            }
            PRINT("recv failed %d\r\n", errno);
        } else if (recvLen == 0) { /* TcpSample connection closed by peer side */
            context->isFinish = TRUE;
            PRINT("%s:TcpSample connection closed by peer side %d\r\n", WIFI_TCP_SAMPLE_LOG, errno);
            break;
        } else {
            context->param.total += (uint32_t)recvLen;
            /* 打印 */
            PRINT("%s:Recv Msg:%s\r\n", WIFI_TCP_SAMPLE_LOG, context->param.buffer);
        }
    }
}

static int32_t TcpSampleServerPhase1(TcpSampleContext *context, int32_t domain, socklen_t addrLen,
                                     struct sockaddr *local, struct sockaddr *remote)
{
    int32_t sock;
    struct timeval rcvTmo;

    sock = socket(domain, SOCK_STREAM, 0);
    if (sock < 0) {
        PRINT("socket failed %d\r\n", errno);
        return TCP_SAMPLE_FAIL;
    }

    int32_t reuse = 1;
    if (setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, &reuse, sizeof(reuse)) < 0) {
        PRINT("set reuse failed %d\r\n", errno);
        closesocket(sock);
        context->trafficSock = TCP_SAMPLE_INVALID_SOCKET;
        return TCP_SAMPLE_FAIL;
    }

    if (bind(sock, local, addrLen) < 0) {
        PRINT("bind failed %d\r\n", errno);
        closesocket(sock);
        context->trafficSock = TCP_SAMPLE_INVALID_SOCKET;
        return TCP_SAMPLE_FAIL;
    }

    if (listen(sock, 0) < 0) {
        PRINT("listen failed %d\r\n", errno);
        closesocket(sock);
        context->trafficSock = TCP_SAMPLE_INVALID_SOCKET;
        return TCP_SAMPLE_FAIL;
    }

    /* block to wait for new connection */
    int32_t ret = accept(sock, remote, &addrLen);
    if (ret < 0) {
        PRINT("accept failed %d\r\n", errno);
        closesocket(sock);
        context->trafficSock = TCP_SAMPLE_INVALID_SOCKET;
        return TCP_SAMPLE_FAIL;
    }

    context->trafficSock = sock;
    rcvTmo.tv_sec = TCP_SAMPLE_DEFAULT_RX_TIMEOUT / 1000; /* 1000 换算单位 */
    rcvTmo.tv_usec = (TCP_SAMPLE_DEFAULT_RX_TIMEOUT % 1000) * 1000; /* 1000 换算单位 */
    if (setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &rcvTmo, sizeof(rcvTmo)) < 0) {
        PRINT("set rcvtimeo failed %d\r\n", errno);
        closesocket(sock);
        context->trafficSock = TCP_SAMPLE_INVALID_SOCKET;
        return TCP_SAMPLE_FAIL;
    }
    return sock;
}

static void TcpSampleServerGo(TcpSampleContext *context)
{
    int32_t domain, sock;
    struct sockaddr_in local, remote;
    struct sockaddr *localAddr = NULL;
    struct sockaddr *remoteAddr = NULL;
    socklen_t addrLen;

    domain = AF_INET;
    (void)memset_s(&local, sizeof(local), 0, sizeof(local));
    local.sin_family = domain;
    local.sin_port = htons(context->param.port);
    local.sin_addr.s_addr = htonl(IPADDR_ANY);
    localAddr = (struct sockaddr *)&local;
    remoteAddr = (struct sockaddr *)&remote;
    addrLen = sizeof(struct sockaddr_in);

    sock = TcpSampleServerPhase1(context, domain, addrLen, localAddr, remoteAddr);
    if (sock < 0) {
        return;
    }

    TcpSampleServerPhase2(context);

    closesocket(context->trafficSock);
    context->trafficSock = TCP_SAMPLE_INVALID_SOCKET;
    context->isFinish = TRUE;
}

/*****************************************************************************
  TCP Client创建
*****************************************************************************/
static void TcpSampleClientPhase2(void)
{
    int32_t sendLen;
    TcpSampleContext *context = NULL;

    if (LOS_MuxPend(g_TcpSampleMutex, LOS_WAIT_FOREVER) != LOS_OK) {
        return;
    }
    context = g_TcpSampleContext;
    if (context == NULL) {
        LOS_MuxPost(g_TcpSampleMutex);
        return;
    }

    sendLen = send(context->trafficSock, context->param.buffer, context->param.bufLen, 0); /* 0: no flag */
    if (sendLen < 0) {
        PRINT("%s:Send Packet Failed %d\r\n", WIFI_TCP_SAMPLE_LOG, errno);
        return;
    }
    PRINT("%s:Send Packet Succ!.\r\n", WIFI_TCP_SAMPLE_LOG);
}

/*****************************************************************************
  TCP 保活（发包）Task创建
*****************************************************************************/
static int32_t TcpSampleSendPacket(void)
{
    uint32_t ret;
    uint32_t taskID;
    TSK_INIT_PARAM_S appTask = {0};

    appTask.pfnTaskEntry = (TSK_ENTRY_FUNC)TcpSampleClientPhase2;
    appTask.uwStackSize  = TCP_SAMPLE_REPORTER_STACK_SIZE;
    appTask.pcName = TCP_SAMPLE_REPORTER_NAME;
    appTask.usTaskPrio = TCP_SAMPLE_REPORTER_PRIORITY;
    appTask.uwResved   = LOS_TASK_STATUS_DETACHED;

    ret = LOS_TaskCreate(&taskID, &appTask);
    if (ret != 0) {
        PRINT("create reporter task failed %u\r\n", ret);
        return TCP_SAMPLE_FAIL;
    }
    return TCP_SAMPLE_OK;
}

int32_t TcpSampleClientPhase1(TcpSampleContext *context, int32_t domain, socklen_t addrLen,
                              struct sockaddr *local, struct sockaddr *remote)
{
    int32_t sock;

    sock = socket(domain, SOCK_STREAM, 0);
    PRINT("%s:sock=%d\r\n", WIFI_TCP_SAMPLE_LOG, sock);
    if (sock < 0) {
        PRINT("socket failed %d\r\n", errno);
        return TCP_SAMPLE_FAIL;
    }

    int32_t reuse = 1;
    if (setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, &reuse, sizeof(reuse)) < 0) {
        PRINT("%s:set reuseaddr failed %d\r\n", WIFI_TCP_SAMPLE_LOG, errno);
        closesocket(sock);
        if (context->trafficSock > 0) {
            context->trafficSock = TCP_SAMPLE_INVALID_SOCKET;
        }
        return TCP_SAMPLE_FAIL;
    }

    if (bind(sock, local, addrLen) < 0) {
        PRINT("%s:bind failed %d\r\n", WIFI_TCP_SAMPLE_LOG, errno);
        closesocket(sock);
        if (context->trafficSock > 0) {
            context->trafficSock = TCP_SAMPLE_INVALID_SOCKET;
        }
        return TCP_SAMPLE_FAIL;
    }

    context->trafficSock = sock; /* Must set traffic socket before connect */
    if (connect(sock, remote, addrLen) < 0) {
        PRINT("%s:connect failed %d\r\n", WIFI_TCP_SAMPLE_LOG, errno);
        closesocket(sock);
        if (context->trafficSock > 0) {
            context->trafficSock = TCP_SAMPLE_INVALID_SOCKET;
        }
        return TCP_SAMPLE_FAIL;
    }

    return sock;
}

void TcpSampleClientGo(TcpSampleContext *context)
{
    int32_t domain, sock;
    struct sockaddr_in local, remote;
    struct sockaddr *localAddr = NULL;
    struct sockaddr *remoteAddr = NULL;
    socklen_t addrLen;

    domain = AF_INET;
    (void)memset_s(&local, sizeof(local), 0, sizeof(local));
    (void)memset_s(&remote, sizeof(remote), 0, sizeof(remote));
    (void)memset_s(&local, sizeof(local), 0, sizeof(local));
    local.sin_family = domain;
    local.sin_port = htons(context->param.port);
    local.sin_addr.s_addr = htonl(IPADDR_ANY);
    remote.sin_family = domain;
    remote.sin_port = htons(context->param.port);
    remote.sin_addr = context->param.u2.dstIP4; /* 绑定tcp服务器ip */
    localAddr = (struct sockaddr *)&local;
    remoteAddr = (struct sockaddr *)&remote;
    addrLen = sizeof(struct sockaddr_in);

    sock = TcpSampleClientPhase1(context, domain, addrLen, localAddr, remoteAddr);
    if (sock < 0) {
        return;
    }

    struct timeval sndTmo;
    sndTmo.tv_sec = TCP_SAMPLE_DEFAULT_TX_TIMEOUT;
    sndTmo.tv_usec = 0;
    setsockopt(sock, SOL_SOCKET, SO_SNDTIMEO, &sndTmo, sizeof(sndTmo));

    while (context->isFinish == FALSE) {
        TcpSampleSendPacket();
        osDelay(30 * 100); /* 30s发一次包, 100表示 1s */
    }

    context->isFinish = true;
    closesocket(context->trafficSock);
    context->trafficSock = TCP_SAMPLE_INVALID_SOCKET;
}

/*****************************************************************************
  TCP Task创建
*****************************************************************************/
static bool TcpSampleBufferInit(TcpSampleContext *context)
{
    context->param.buffer = (uint8_t *)malloc(context->param.bufLen);
    if (context->param.buffer == NULL) {
        PRINT("Error: no free memory\r\n");
        return FALSE;
    }
    return TRUE;
}

void TcpSampleTrafficEntry(uint32_t p0)
{
    TcpSampleContext *context = (TcpSampleContext *)p0;

    if (LOS_MuxCreate(&g_TcpSampleMutex) != LOS_OK) {
        return;
    }
    if (TcpSampleBufferInit(context) == FALSE) {
        goto DONE;
    }

    for (uint32_t i = 0; i < context->param.bufLen; i++) {
        context->param.buffer[i] = (i % 10) + '0'; /* 10: TcpSample data is '0' to '9' */
    }

    (void)LOS_MuxPend(g_TcpSampleMutex, LOS_WAIT_FOREVER);
    g_TcpSampleContext = context;
    (void)LOS_MuxPost(g_TcpSampleMutex);

    if (TCP_SAMPLE_IS_SERVER(context->param.mask)) {
        PRINT("%s::Start TcpSample Server!.\r\n", WIFI_TCP_SAMPLE_LOG);
        TcpSampleServerGo(context);
    } else {
        PRINT("%s::Start TcpSample client!.\r\n", WIFI_TCP_SAMPLE_LOG);
        TcpSampleClientGo(context);
    }

DONE:
    LOS_MuxPend(g_TcpSampleMutex, LOS_WAIT_FOREVER);
    if (context->param.buffer != NULL) {
        free(context->param.buffer);
        context->param.buffer = NULL;
    }

    free(context);
    g_TcpSampleContext = NULL;
    LOS_MuxPost(g_TcpSampleMutex);

    uint32_t mtx = g_TcpSampleMutex;
    g_TcpSampleMutex = 0xFFFFFFFF; /* 0xFFFFFFFF: invalid handle */
    LOS_MuxDelete(mtx);
}

void TcpSampleSetDefaultParameter(TcpSampleContext *context)
{
    context->trafficSock = TCP_SAMPLE_INVALID_SOCKET;

#ifdef CONFIG_SUPPORT_TCP_CLIENT_SAMPLE
    context->param.mask |= (TCP_SAMPLE_MASK_CLIENT | TCP_SAMPLE_MASK_TCP);
#elif defined(CONFIG_SUPPORT_TCP_SERVER_SAMPLE)
    context->param.mask |= (TCP_SAMPLE_MASK_SERVER | TCP_SAMPLE_MASK_TCP);
#endif
    
    // 设置目的IP
    inet_pton(AF_INET, WIFI_TCP_SAMPLE_DST_IP, (void *)&context->param.u2.dstIP4);

    if (context->param.port == 0) {
        context->param.port = TCP_SAMPLE_DEFAULT_PORT;
    }

    if (context->param.bufLen == 0) {
        context->param.bufLen = ((TCP_SAMPLE_IS_UDP(context->param.mask)) ?
                                  TCP_SAMPLE_DEFAULT_UDP_BUFLEN : TCP_SAMPLE_DEFAULT_TCP_SAMPLE_BUFLEN);
    }
}

/*****************************************************************************
  建立TCP连接Task创建
*****************************************************************************/
static int32_t TcpSampleStart(TcpSampleContext *context)
{
    uint32_t ret;
    uint32_t taskID;
    TSK_INIT_PARAM_S appTask = {0};

    appTask.pfnTaskEntry = (TSK_ENTRY_FUNC)TcpSampleTrafficEntry;
    appTask.uwStackSize  = TCP_SAMPLE_TRAFFIC_STACK_SIZE;
    appTask.pcName = TCP_SAMPLE_TRAFFIC_NAME;
    if (TCP_SAMPLE_IS_SERVER(context->param.mask)) {
        appTask.usTaskPrio = TCP_SAMPLE_TRAFFIC_SERVER_PRIORITY;
    } else {
        appTask.usTaskPrio = TCP_SAMPLE_TRAFFIC_CLIENT_PRIORITY;
    }
    appTask.uwResved = LOS_TASK_STATUS_DETACHED;
    LOS_TASK_PARAM_INIT_ARG(appTask, (uint32_t)context);

    ret = LOS_TaskCreate(&taskID, &appTask);
    if (ret != 0) {
        PRINT("create traffic task failed %u\r\n", ret);
        free(context);
        return TCP_SAMPLE_FAIL;
    }
    return TCP_SAMPLE_OK;
}

uint32_t CmdTcpSample()
{
    if (LOS_MuxPend(g_TcpSampleMutex, LOS_WAIT_FOREVER) == LOS_OK) {
        /* mux available means TcpSample running. */
        PRINT("TcpSample is running\r\n");
        (void)LOS_MuxPost(g_TcpSampleMutex);
        return (uint32_t)TCP_SAMPLE_FAIL;
    }

    TcpSampleContext *context = malloc(sizeof(TcpSampleContext));
    if (context == NULL) {
        PRINT("no free memory\r\n");
        return (uint32_t)TCP_SAMPLE_FAIL;
    }
    (void)memset_s(context, sizeof(TcpSampleContext), 0, sizeof(TcpSampleContext));

    TcpSampleSetDefaultParameter(context);

    return (uint32_t)TcpSampleStart(context);
}

/*****************************************************************************
  WiFi初始化
*****************************************************************************/
int wifi_sta_sample_init(void *param)
{
    param = param;

    /* 注册事件回调 */
    if (wifi_register_event_cb(&wifi_event_cb) != 0) {
        PRINT("%s::wifi_event_cb register fail.\r\n", WIFI_STA_SAMPLE_LOG);
        return -1;
    }
    PRINT("%s::wifi_event_cb register succ.\r\n", WIFI_STA_SAMPLE_LOG);

    /* 等待wifi初始化完成 */
    while (wifi_is_wifi_inited() == 0) {
        (void)osDelay(10); /* 1: 等待100ms后判断状态 */
    }
    PRINT("%s::wifi init succ.\r\n", WIFI_STA_SAMPLE_LOG);

    if (example_sta_function() != 0) {
        PRINT("%s::example_sta_function fail.\r\n", WIFI_STA_SAMPLE_LOG);
        return -1;
    }
    return 0;
}

/*****************************************************************************
  APP TASK创建
*****************************************************************************/
static void tcp_sample_entry(void)
{
    osThreadAttr_t attr;
    attr.name       = "tcp_sample_task";
    attr.attr_bits  = 0U;
    attr.cb_mem     = NULL;
    attr.cb_size    = 0U;
    attr.stack_mem  = NULL;
    attr.stack_size = WIFI_TASK_STACK_SIZE;
    attr.priority   = WIFI_TASK_PRIO;
    if (osThreadNew((osThreadFunc_t)wifi_sta_sample_init, NULL, &attr) == NULL) {
        PRINT("%s::Create tcp_sample_task fail.\r\n", WIFI_TCP_SAMPLE_LOG);
    }
    PRINT("%s::Create tcp_sample_task succ.\r\n", WIFI_TCP_SAMPLE_LOG);
}

/* Run the tcp_sample_task. */
app_run(tcp_sample_entry);
