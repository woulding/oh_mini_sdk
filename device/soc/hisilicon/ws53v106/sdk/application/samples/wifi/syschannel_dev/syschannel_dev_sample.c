/**
 * Copyright (c) HiSilicon (Shanghai) Technologies Co., Ltd. 2023-2023. All rights reserved.
 * Description: syschannel dev Sample Source.
 *
 * History:
 * 2023-05-03, Create file.
 */
#include <malloc.h>
#include <stdio.h>
#include "lwip/netifapi.h"
#include "hal_sdio.h"
#include "syschannel_api.h"
#include "osal_types.h"
#include "soc_osal.h"
#include "gpio.h"
#include "sdio_slave.h"
#include "osal_task.h"
#include "app_init.h"
#include "pinctrl.h"
#include "idle_config.h"
#include "cmsis_os2.h"
#include "watchdog.h"
#include "syschannel_wal_api.h"
#include "mac_addr.h"
#include "idle_config.h"

#ifdef __cplusplus
#if __cplusplus
extern "C" {
#endif
#endif
/* 宏定义 */
#define DEMO_LENGTH                 10
#define MAX_CMD_LEN                 20
#define MAX_IPV4_LEN                13
#define SYSCHANNEL_MAC_ADDR_LEN     6
#define SYSCHANNEL_TASK_PRIO        1
#define SYSCHANNEL_TASK_STACK_SIZE  0x1000

enum {
    HOST_CMD_GET_MAC,
    HOST_CMD_GET_IP,
    HOST_CMD_SET_FILTER,
    HOST_CMD_TBTT
};

char cmd[][MAX_CMD_LEN] = {
    "cmd_get_mac",
    "cmd_get_ip",
    "cmd_set_filter"};

static int syschannel_set_ipv6_default_filter(void)
{
    int ret;
    syschannel_ipv6_filter filter_ipv6 = {0};
    filter_ipv6.local_port = 68;             /* 68 UDP port */
    filter_ipv6.packet_type = IPPROTO_UDP; /* UDP 17, TCP 6 */
    filter_ipv6.match_mask = WIFI_FILTER_MASK_LOCAL_PORT | WIFI_FILTER_MASK_PROTOCOL;
    filter_ipv6.config_type = WIFI_FILTER_LWIP; /* XX_VLWIP to T31, XX_LWIP to ws53 */
    ret = uapi_syschannel_add_filter((osal_char*)&filter_ipv6, sizeof(filter_ipv6), WIFI_FILTER_TYPE_IPV6);
    printf("add mcu dhcp filter6 ret %d\n", ret);
    return ret;
}

static int syschannel_set_ipv4_default_filter(void)
{
    int ret;
    syschannel_ipv4_filter filter_ipv4 = {0};
    filter_ipv4.local_port = 68;             /* 68 DHCP UDP port */
    filter_ipv4.packet_type = IPPROTO_UDP; /* UDP 17, TCP 6 */
    filter_ipv4.match_mask = WIFI_FILTER_MASK_LOCAL_PORT | WIFI_FILTER_MASK_PROTOCOL;
    filter_ipv4.config_type = WIFI_FILTER_LWIP; /* XX_VLWIP to T31, XX_LWIP to ws53 */
    ret = uapi_syschannel_add_filter((osal_char*)&filter_ipv4, sizeof(filter_ipv4), WIFI_FILTER_TYPE_IPV4);
    printf("add mcu listen 68 filter4 ret 0x%x\n", ret);

    (void)memset_s(&filter_ipv4, sizeof(filter_ipv4), 0, sizeof(filter_ipv4));
    filter_ipv4.local_port = 67;             /* 67 DHCP UDP port */
    filter_ipv4.packet_type = IPPROTO_UDP; /* UDP 17, TCP 6 */
    filter_ipv4.match_mask = WIFI_FILTER_MASK_LOCAL_PORT | WIFI_FILTER_MASK_PROTOCOL;
    filter_ipv4.config_type = WIFI_FILTER_LWIP; /* XX_VLWIP to T31, XX_LWIP to ws53 */
    ret = uapi_syschannel_add_filter((osal_char*)&filter_ipv4, sizeof(filter_ipv4), WIFI_FILTER_TYPE_IPV4);
    printf("add mcu listen 67 filter4 ret 0x%x\n", ret);

    (void)memset_s(&filter_ipv4, sizeof(filter_ipv4), 0, sizeof(filter_ipv4));
    filter_ipv4.local_port = 6001;          /* 6001 TCP port */
    filter_ipv4.packet_type = IPPROTO_TCP; /* UDP 17, TCP 6 */
    filter_ipv4.match_mask = WIFI_FILTER_MASK_PROTOCOL | WIFI_FILTER_MASK_LOCAL_PORT;
    filter_ipv4.config_type = WIFI_FILTER_LWIP; /* XX_VLWIP to T31, XX_LWIP to ws53 */
    ret = uapi_syschannel_add_filter((osal_char*)&filter_ipv4, sizeof(filter_ipv4), WIFI_FILTER_TYPE_IPV4);
    printf("add mcu listen 6001 filter4 ret 0x%x\n", ret);

    (void)memset_s(&filter_ipv4, sizeof(filter_ipv4), 0, sizeof(filter_ipv4));
    filter_ipv4.remote_port = 6002;          /* 6002 TCP port */
    filter_ipv4.packet_type = IPPROTO_TCP; /* UDP 17, TCP 6 */
    filter_ipv4.match_mask = WIFI_FILTER_MASK_PROTOCOL | WIFI_FILTER_MASK_REMOTE_PORT;
    filter_ipv4.config_type = WIFI_FILTER_LWIP; /* XX_VLWIP to T31, XX_LWIP to ws53 */
    ret = uapi_syschannel_add_filter((osal_char*)&filter_ipv4, sizeof(filter_ipv4), WIFI_FILTER_TYPE_IPV4);
    printf("add mcu listen 6002 filter4 ret 0x%x\n", ret);

    (void)memset_s(&filter_ipv4, sizeof(filter_ipv4), 0, sizeof(filter_ipv4));
    filter_ipv4.local_port = 7001;           /* 7001 UDP port */
    filter_ipv4.packet_type = IPPROTO_UDP; /* UDP 17, TCP 6 */
    filter_ipv4.match_mask = WIFI_FILTER_MASK_LOCAL_PORT | WIFI_FILTER_MASK_PROTOCOL;
    filter_ipv4.config_type = WIFI_FILTER_LWIP; /* XX_VLWIP to T31, XX_LWIP to ws53 */
    ret = uapi_syschannel_add_filter((osal_char*)&filter_ipv4, sizeof(filter_ipv4), WIFI_FILTER_TYPE_IPV4);
    printf("add mcu listen 7001 filter4 ret 0x%x\n", ret);

    (void)memset_s(&filter_ipv4, sizeof(filter_ipv4), 0, sizeof(filter_ipv4));
    filter_ipv4.remote_port = 7002;           /* 7002 UDP port */
    filter_ipv4.packet_type = IPPROTO_UDP; /* UDP 17, TCP 6 */
    filter_ipv4.match_mask = WIFI_FILTER_MASK_REMOTE_PORT | WIFI_FILTER_MASK_PROTOCOL;
    filter_ipv4.config_type = WIFI_FILTER_LWIP; /* XX_VLWIP to T31, XX_LWIP to ws53 */
    ret = uapi_syschannel_add_filter((osal_char*)&filter_ipv4, sizeof(filter_ipv4), WIFI_FILTER_TYPE_IPV4);
    printf("add mcu listen 7002 filter4 ret 0x%x\n", ret);
    return ret;
}

int syschannel_set_default_filter(void)
{
    int ret = uapi_syschannel_set_default_filter(WIFI_FILTER_VLWIP);
    printf("set all net packets foward to mcu default.\n");

    if (syschannel_set_ipv4_default_filter() != OSAL_OK) {
        ret = OSAL_NOK;
    }

    if (syschannel_set_ipv6_default_filter() != OSAL_OK) {
        ret = OSAL_NOK;
    }
    return ret;
}

osal_void syschannel_send_ip(osal_void *dev_if)
{
    osal_u8 i = 0;
    ip4_addr_t loop_ipaddr;
    ip4_addr_t loop_netmask;
    ip4_addr_t loop_gw;
    struct netif *netif = (struct netif *)dev_if;
    osal_char ip_str[MAX_IPV4_LEN + 1] = {0};

    if (netif == OSAL_NULL) {
        return;
    }

    err_t ret = netifapi_netif_get_addr(netif, &loop_ipaddr, &loop_netmask, &loop_gw);
    if (ret != ERR_OK) {
        return;
    }

    ip_str[i++] = HOST_CMD_GET_IP;
    ip_str[i++] = (((u8_t*)(&loop_ipaddr.addr))[0]);  /* ip addr 0 byte */
    ip_str[i++] = (((u8_t*)(&loop_ipaddr.addr))[1]);  /* ip addr 1 byte */
    ip_str[i++] = (((u8_t*)(&loop_ipaddr.addr))[2]);  /* ip addr 2 byte */
    ip_str[i++] = (((u8_t*)(&loop_ipaddr.addr))[3]);  /* ip addr 3 byte */

    ip_str[i++] = (((u8_t*)(&loop_netmask.addr))[0]);  /* ip addr 0 byte */
    ip_str[i++] = (((u8_t*)(&loop_netmask.addr))[1]);  /* ip addr 1 byte */
    ip_str[i++] = (((u8_t*)(&loop_netmask.addr))[2]);  /* ip addr 2 byte */
    ip_str[i++] = (((u8_t*)(&loop_netmask.addr))[3]);  /* ip addr 3 byte */

    ip_str[i++] = (((u8_t*)(&loop_gw.addr))[0]);  /* ip addr 0 byte */
    ip_str[i++] = (((u8_t*)(&loop_gw.addr))[1]);  /* ip addr 1 byte */
    ip_str[i++] = (((u8_t*)(&loop_gw.addr))[2]);  /* ip addr 2 byte */
    ip_str[i++] = (((u8_t*)(&loop_gw.addr))[3]);  /* ip addr 3 byte */

    if (i != MAX_IPV4_LEN) {
        printf("ip len = %d\n", i);
        return;
    }

    uapi_syschannel_send_to_host(ip_str, MAX_IPV4_LEN + 1);
}

/*****************************************************************************
 功能描述  : 客户发送消息给host侧示例
 函数参数  : buf: 信息缓存区 (用户负责申请和释放)
             length: 信息长度
*****************************************************************************/
unsigned int syschannel_tx_msg(osal_void)
{
    char *buf = (char *)malloc(sizeof(char) * DEMO_LENGTH);
    if (buf == OSAL_NULL) {
        printf("syschannel_tx_msg:: malloc failed");
        return OSAL_NOK;
    }

    for (int i = 0; i < DEMO_LENGTH; i++) {
        buf[i] = i;
    }

    uapi_syschannel_send_to_host(buf, sizeof(char) * DEMO_LENGTH);
    free(buf);
    return OSAL_OK;
}

osal_void syschannel_send_mac(osal_void *dev_if)
{
    osal_char mac_addr[SYSCHANNEL_MAC_ADDR_LEN + 1] = {0};
    struct netif *netif = (struct netif *)dev_if;

    if (netif == OSAL_NULL) {
        return;
    }
    if (memcpy_s(&mac_addr[1], NETIF_MAX_HWADDR_LEN, netif->hwaddr, SYSCHANNEL_MAC_ADDR_LEN) != OSAL_OK) {
        return;
    }
    mac_addr[0] = HOST_CMD_GET_MAC;
    uapi_syschannel_send_to_host(mac_addr, SYSCHANNEL_MAC_ADDR_LEN + 1);
}

/*****************************************************************************
 功能描述  : 提供给客户获取host侧传送的信息
 函数参数  : buf: 信息缓存区 (注: 该内存用户不可free，只可读)
             length: 信息长度
*****************************************************************************/
unsigned int syschannel_rx_callback(unsigned char *buf, int length)
{
    osal_u8 index;
    struct netif *netif = get_syschannel_netif();
    if ((buf == OSAL_NULL) || (length == 0) || (netif == OSAL_NULL)) {
        return OSAL_NOK;
    }

    for (index = HOST_CMD_GET_MAC; index < HOST_CMD_TBTT; index ++) {
        if (memcmp(buf, cmd[index], strlen(cmd[index])) == 0) {
            break;
        }
    }

    printf("Type:%d\n", index);
    if (index == HOST_CMD_GET_MAC) {
        syschannel_send_mac(netif);
    } else if (index == HOST_CMD_GET_IP) {
        syschannel_send_ip(netif);
    } else if (index == HOST_CMD_SET_FILTER) {
        syschannel_set_default_filter();
    }
    return OSAL_OK;
}

static osal_void app_demo_netif_ext_callback(struct netif *netif, netif_nsc_reason_t reason,
    const netif_ext_callback_args_t *args)
{
    unused(args);
    if (netif == OSAL_NULL) {
        return;
    }

    if ((reason & LWIP_NSC_IPV4_ADDRESS_CHANGED) ||
        (reason & LWIP_NSC_IPV4_NETMASK_CHANGED) ||
        (reason & LWIP_NSC_IPV4_GATEWAY_CHANGED) ||
        (reason & LWIP_NSC_IPV4_SETTINGS_CHANGED)) {
        syschannel_send_ip(netif);
        printf("LWIP_NSC_IPV4_ADDRESS_CHANGED:0x%x\n", reason);
    } else if (reason & LWIP_NSC_NETIF_ADDED) {
        printf("LWIP_NSC_NETIF_ADDED COME\n");
    } else if (reason & LWIP_NSC_LINK_CHANGED) {
        printf("LWIP_NSC_LINK_CHANGED COME\n");
    } else if (reason & LWIP_NSC_IPV6_ADDR_STATE_CHANGED) {
        printf("LWIP_NSC_IPV6_ADDR_STATE_CHANGED COME\n");
    } else if (reason & LWIP_NSC_NETIF_REMOVED) {
        printf("LWIP_NSC_NETIF_REMOVED COME\n");
    } else if (reason & LWIP_NSC_STATUS_CHANGED) {
        printf("LWIP_NSC_STATUS_CHANGED COME\n");
    } else if (reason & LWIP_NSC_IPV6_SET) {
        printf("LWIP_NSC_IPV6_SET COME\n");
    } else {
        printf("Netif status callback id:0x%x\n", reason);
    }
}

/* this api is used to cancle sdio wait card, should be called after sdio init by user */
osal_void app_sdio_cancel_wait(osal_void);
osal_void app_sdio_cancel_wait(osal_void)
{
    /* exit wait card */
    sdio_force_exit_wait_card();
}

static int sdio_reinit_task_body(osal_void *param);
osal_u32 app_sdio_reinit(osal_void)
{
    /* Create a task to init sdio */
    osal_task *task_handle = NULL;
    osal_kthread_lock();
    task_handle = osal_kthread_create((osal_kthread_handler)sdio_reinit_task_body, 0,
        "sdio reinit", SYSCHANNEL_TASK_STACK_SIZE);
    if (task_handle == NULL) {
        osal_kthread_unlock();
        printf("Falied to create sdio reinit task!\n");
        return OSAL_NOK;
    }
    osal_kthread_set_priority(task_handle, SYSCHANNEL_TASK_PRIO);
    osal_kthread_unlock();
    return OSAL_OK;
}

unsigned int syschannel_timeout_callback(void)
{
    // 示例一：非AOV场景，心跳超时后，先1. 重置sdio 2. 给主控下电，3. 重新等卡 4. 给主控上电发起探卡
    // 1. uapi_syschannel_dev_reset(SDIO_TYPE)
    // 2. soc_power_off
    // 3. app_sdio_reinit()
    // 4. soc power on, detect card

    // 示例二: AOV场景，心跳超时流程中恢复等卡
    // 1. 重置sdio，清除报文以及心跳
    // uapi_syschannel_dev_reset(SDIO_TYPE)
    // 2. 重新等卡, 注意需要通知另一个任务执行等卡操作，当前上下文是中断，不能直接等卡
    // app_sdio_reinit()
    return OSAL_OK;
}

static netif_ext_callback_t callback;
osal_s32 syschannel_dev_init_demo(osal_void)
{
    err_t ret = netifapi_netif_add_ext_callback(&callback, app_demo_netif_ext_callback);
    if (ret != ERR_OK) {
        printf("syschannel_dev_init_demo:: netifapi_netif_add_ext_callback failed!");
        return OSAL_NOK;
    }

    if (syschannel_set_default_filter() != OSAL_OK) {
        printf("syschannel_dev_init_demo:: set_default_filter failed\n");
        return OSAL_NOK;
    }

    uapi_syschannel_register_rx_cb(syschannel_rx_callback);
    uapi_syschannel_register_timeout_cb(syschannel_timeout_callback);
    printf("syschannel dev init success!\n");
    return OSAL_OK;
}

static int sdio_reinit_task_body(osal_void *param)
{
    unused(param);
    /* 初始化syschannel */
    if (syschannel_dev_init_demo() != OSAL_OK) {
        printf("syschannel dev init failed!\n");
    };
    uapi_watchdog_disable();
    if (uapi_syschannel_dev_reinit(SDIO_TYPE) != OSAL_OK) {
        printf("sdio_reinit_task_body:: syschannel_dev_init failed");
        uapi_watchdog_enable(WDT_MODE_INTERRUPT);
        return 0;
    }
    uapi_watchdog_enable(WDT_MODE_INTERRUPT);

    printf("sdio reinit finish\r\n");
    return 0;
}

static void syschannel_suspend_callback(void)
{
    // 示例一：AOV场景1，主控不下电，由主控主动控制dev suspend：1. 重置sdio  2. 再进入深睡，由主控自行控制后续等卡与探卡流程
    // 1. uapi_syschannel_dev_reset(SDIO_TYPE)
    // 2. uapi_lpc_set_type(PM_DEEP_SLEEP)

    // 示例二: AOV场景2，主控不下电，由主控主动控制dev suspend：1. 重置sdio 2. 直接发起重新等卡
    // 1. 重置sdio，清除报文以及心跳
    // uapi_syschannel_dev_reset(SDIO_TYPE)
    // 2. 重新等卡, 注意需要通知另一个任务执行等卡操作，当前上下文是中断，不能直接等卡
    // app_sdio_reinit()
}

osal_bool g_pm_open_status = OSAL_TRUE;
static int sdio_init_task_body(osal_void *param)
{
    unused(param);
    pm_lpc_type type = g_pm_open_status ? PM_DEEP_SLEEP : PM_NO_SLEEP;
    /* 初始化syschannel */
    if (syschannel_dev_init_demo() != OSAL_OK) {
        printf("syschannel dev init failed!\n");
    };
    uapi_watchdog_disable();
    if (uapi_syschannel_dev_init(SDIO_TYPE) != OSAL_OK) {
        printf("sdio_init_task_body:: syschannel_dev_init failed");
        uapi_lpc_set_type(type); /* 恢复低功耗 */
        uapi_watchdog_enable(WDT_MODE_INTERRUPT);
        return 0;
    }
    uapi_watchdog_enable(WDT_MODE_INTERRUPT);
    uapi_syschannel_register_suspend_cb(syschannel_suspend_callback);

    printf("sdio init finish\r\n");
    return 0;
}

osal_u32 app_sdio_init(osal_void)
{
    /* Create a task to init sdio */
    osal_task *task_handle = NULL;
    osal_kthread_lock();
    task_handle = osal_kthread_create((osal_kthread_handler)sdio_init_task_body, 0,
        "sdio init", SYSCHANNEL_TASK_STACK_SIZE);
    if (task_handle == NULL) {
        osal_kthread_unlock();
        printf("Falied to create sdio init task!\n");
        return OSAL_NOK;
    }
    osal_kthread_set_priority(task_handle, SYSCHANNEL_TASK_PRIO);
    osal_kthread_unlock();
    return OSAL_OK;
}

osal_void app_sdio_io_init(osal_void)
{
    uapi_pin_set_pull(S_MGPIO0, PIN_PULL_UP); // d2
    uapi_pin_set_pull(S_AGPIO6, PIN_PULL_UP); // d3
    uapi_pin_set_pull(S_MGPIO2, PIN_PULL_UP); // cmd
    uapi_pin_set_pull(S_MGPIO4, PIN_PULL_UP); // d0
    uapi_pin_set_pull(S_AGPIO5, PIN_PULL_UP); // d1

    uapi_pin_set_mode(S_MGPIO0, 1); // sdio data2
    uapi_pin_set_mode(S_AGPIO6, 1); // sdio data3
    uapi_pin_set_mode(S_MGPIO2, 1); // sdio cmd
    uapi_pin_set_mode(S_MGPIO3, 1); // sdio clk
    uapi_pin_set_mode(S_MGPIO4, 1); // sdio data0
    uapi_pin_set_mode(S_AGPIO5, 1); // sdio data1
}

osal_void peripheral_init_no_sleep(osal_void)
{
    app_sdio_io_init();
    /*
     * Example: To initialize a peripheral that does not need to be reinitialized
     * during deep sleep wakeup, call this API.
     */
    /* 设置sdio睡眠唤醒不需要重新初始化
    sdio_set_powerdown_when_deep_sleep 设为false */
    g_pm_open_status = idle_get_open_pm();
    uapi_lpc_set_type(PM_NO_SLEEP);   // 关A核低功耗流程
    osal_u32 ret = app_sdio_init();
    if (ret != OSAL_OK) {
        printf("sdio init failed\r\n");
    }
}

void syschannel_dev_entry(void)
{
    /* 进行起任务初始化sdio，初始化syschannel_dev在线程中执行 */
    peripheral_init_no_sleep();
}

/* Run the syschannel_dev_entry. */
app_run(syschannel_dev_entry);
#ifdef __cplusplus
#if __cplusplus
}
#endif
#endif
