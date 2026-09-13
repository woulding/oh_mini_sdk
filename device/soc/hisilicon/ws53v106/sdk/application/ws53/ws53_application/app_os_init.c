/**
 * Copyright (c) @CompanyNameMagicTag 2022-2023. All rights reserved. \n
 *
 * Description: Application core os initialize interface header for standard \n
 * Author: @CompanyNameTag \n
 * History: \n
 * 2022-07-27, Create file. \n
 */
#include "cmsis_os2.h"
#include "log_common.h"
#include "log_uart.h"
#include "log_reg_dump.h"
#include "los_memory.h"
#include "watchdog.h"
#include "preserve.h"
#include "hal_reboot.h"
#include "pinctrl_porting.h"
#include "pinctrl.h"
#include "app_init.h"
#include "test_suite.h"
#if defined(TEST_SUITE)
#include "test_auxiliary.h"
#endif
#include "test_suite_uart.h"
#include "test_suite.h"
#include "tcxo.h"

#include "ipc.h"
#include "ipc_porting.h"

#ifdef FTRACE
#include "test_ftrace.h"
#endif
#if defined(TEST_SUITE)
#include "test_pinctrl.h"
#endif
#ifdef COREMARK_TEST
#include "core_portme.h"
#endif

#ifdef AT_COMMAND
#include "at_config.h"
#include "at_product.h"
#include "test_suite_uart.h"
#ifdef CONFIG_SUPPORT_WIFI
#include "at_cmd_register.h"
#endif
#endif

#ifdef SUPPORT_HCC
#include "hcc_if.h"
#include "hcc_cfg.h"
#include "hcc_rom_callback.h"
#include "btc_hcc_msg.h"
#ifdef TEST_SUITE
#include "test_hcc.h"
#endif
#endif

#if defined(CONFIG_PM_DEBUG)
#include "pm_sleep_porting.h"
#endif /* CONFIG_PM_DEBUG */

#if defined(TEST_SUITE)
#include "test_uart.h"
#include "test_cpu_trace.h"
#include "test_watchdog.h"
#include "test_timer.h"
#include "test_tcxo.h"
#include "test_systick.h"
#include "test_rtc_unified.h"
#include "test_efuse.h"
#include "test_i2s.h"
#include "test_security_unified.h"
#include "test_mbedtls.h"
#include "test_gpio.h"
#include "test_dma.h"
#include "test_pwm.h"
#include "test_sfc.h"
#include "test_panic.h"
#include "test_nv.h"
#include "test_update.h"
#include "test_adc.h"
#include "test_i2c.h"
#endif
#if defined(CONFIG_SAMPLE_ENABLE)
#include "app_init.h"
#endif

#ifdef CONFIG_SUPPORT_WIFI
int wifi_host_task(void *param);
#endif
#ifdef _PRE_FEATURE_WS53_DEVICE_MODE
#include "hcc_agent.h"
#endif
#include "main.h"
#include "app_os_init.h"

#if defined(CONFIG_MIDDLEWARE_SUPPORT_NV) && defined(CONFIG_OTA_UPDATE_SUPPORT)
#include "nv_config.h"
#if (defined(CONFIG_NV_SUPPORT_OTA_UPDATE) && (defined(NV_YES)) && (CONFIG_NV_SUPPORT_OTA_UPDATE == NV_YES))
#include "nv_upg.h"
#endif
#endif

#define TASK_COMMON_APP_DELAY_MS 5000
#define OSDELAY  1000

typedef void (*CreateQueueFunction_t)(void);

#ifdef CONFIG_SUPPORT_OHOS_SUPPORT
#define TASK_PRIORITY_HIGH (osPriority_t)(30)
#define TASK_PRIORITY_CMD  (osPriority_t)(30)
#else
#define TASK_PRIORITY_HIGH (osPriority_t)(40)
#define TASK_PRIORITY_CMD  (osPriority_t)(40)
#endif
#define TASK_PRIORITY_LOG  (osPriority_t)(13)
#define TASK_PRIORITY_APP  (osPriority_t)(14)
#define TASK_PRIORITY_SDK  ((osPriority_t)17)
#define TASK_PRIORITY_SRV   ((osPriority_t)17)
#define TASK_PRIORITY_WIFI ((osPriority_t)16)
#define TASK_PRIORITY_BTH_SDK  ((osPriority_t)16)

#define APP_STACK_SIZE  0x800
#define LOG_STACK_SIZE  0x800
#define CMD_STACK_SIZE  0x1000
#define AT_STACK_SIZE   0x1000
#define WIFI_STACK_SIZE (8 * 1024)
#define STACK_SIZE_BASELINE 0x200
#define FS_EXTEND_STACK (STACK_SIZE_BASELINE * 3)
#define BT_STACK_SIZE (STACK_SIZE_BASELINE * 4 + FS_EXTEND_STACK)
#define BTH_SDK_STACK_SIZE 0x800
#define TASK_STAKDEPTH_BTH_SDK 0x600
#define BTH_SERVICE_STACK_SIZE (STACK_SIZE_BASELINE * 5)
#if defined(CONFIG_PM_DEBUG)
#define PM_DEBUG_INFO_DELAY_MS          5
#endif /* CONFIG_PM_DEBUG */

uint32_t *g_app_task_handle;
typedef struct {
    osThreadAttr_t attr;
    osThreadFunc_t func;
    CreateQueueFunction_t create_queue_fn_p;
} app_task_definition_t;

#define APP_MAIN_QUEUE_LEN 2

#define APP_MAIN_QUEUE_ITEM_SIZE (sizeof(uint32_t))
#ifdef CONFIG_SUPPORT_OHOS_SUPPORT
static void ohos_start(void *unused);
#endif
#if defined(CONFIG_SAMPLE_ENABLE)
static void app_sample(void *unused);
#endif
static void app_main(void *unused);
void cmd_processor_entry(void *args);
void cmd_main_add_functions(void);

#ifdef BTH_TASK_EXIST
void bt_acore_task_main(void);
void sdk_msg_thread(void);
void btsrv_task_body(const void *data);
#endif

static const app_task_definition_t g_app_tasks[] = {
    { { "app", 0, NULL, 0, NULL, APP_STACK_SIZE, TASK_PRIORITY_HIGH, 0, 0 },
      (osThreadFunc_t)app_main, NULL},
#if defined(CONFIG_SAMPLE_ENABLE)
    { { "app_sample", 0, NULL, 0, NULL, APP_STACK_SIZE, TASK_PRIORITY_HIGH, 0, 0 },
      (osThreadFunc_t)app_sample, NULL},
#endif
#ifndef _PRE_FEATURE_WS53_DEVICE_MODE
#if (USE_COMPRESS_LOG_INSTEAD_OF_SDT_LOG == NO)
    { { "log", 0, NULL, 0, NULL, LOG_STACK_SIZE, TASK_PRIORITY_LOG, 0, 0 },
      (osThreadFunc_t)log_main, NULL},
#endif
#endif
#ifdef TEST_SUITE
    { { "cmd_loop", 0, NULL, 0, NULL, CMD_STACK_SIZE, TASK_PRIORITY_CMD, 0, 0 },
      (osThreadFunc_t)cmd_processor_entry, (CreateQueueFunction_t)NULL },
#endif
#ifdef BTH_TASK_EXIST
#ifdef BTH_SDK_TASK_SUPPORT
    { { "bt_sdk", 0, NULL, 0, NULL, BTH_SDK_STACK_SIZE, TASK_PRIORITY_SDK, 0, 0 },
      (osThreadFunc_t)bt_acore_task_main, (CreateQueueFunction_t)NULL },
#endif
    { { "bt_service", 0, NULL, 0, NULL, BTH_SERVICE_STACK_SIZE, TASK_PRIORITY_SRV, 0, 0 },
      (osThreadFunc_t)btsrv_task_body, (CreateQueueFunction_t)NULL },
#endif
#ifdef AT_COMMAND
    { { "at", 0, NULL, 0, NULL, AT_STACK_SIZE, TASK_PRIORITY_CMD, 0, 0 },
      (osThreadFunc_t)uapi_at_msg_main, NULL},
#endif
#ifdef CONFIG_SUPPORT_WIFI
    { { "wifi", 0, NULL, 0, NULL, WIFI_STACK_SIZE, TASK_PRIORITY_WIFI, 0, 0 },
      (osThreadFunc_t)wifi_host_task, NULL},
#endif
#ifdef CONFIG_SUPPORT_OHOS_SUPPORT
    { { "ohos_start", 0, NULL, 0, NULL, AT_STACK_SIZE, TASK_PRIORITY_HIGH, 0, 0 },
      (osThreadFunc_t)ohos_start, NULL},
#endif
};

#define M_NUM_TASKS (sizeof(g_app_tasks) / sizeof(app_task_definition_t))

#ifdef CONFIG_SUPPORT_OHOS_SUPPORT
__attribute__((weak)) void OHOS_SystemInit(void)
{
    return;
}

static void ohos_start(void *unused)
{
    UNUSED(unused);
    PRINT("OHOS START\r\n");
    osal_msleep(3000); /* 3000:等待3s系统完成初始化 */

    OHOS_SystemInit();
}
#endif

void app_os_init(void *unused1, unsigned int unused2)
{
    UNUSED(unused1);
    UNUSED(unused2);
    uint32_t *task_handle = NULL;
    // Create queues before tasks in case they are used during initialisation.
    for (uint8_t i = 0; i < M_NUM_TASKS; i++) {
        if (g_app_tasks[i].create_queue_fn_p) {
            g_app_tasks[i].create_queue_fn_p();
        }
    }

    // Now create tasks

    for (uint8_t i = 0; i < M_NUM_TASKS; i++) {
        // You can't configure a task with a higher priority than the kernel
        // has been compiled to support. RTOS will clip the priority level,
        // which is probably not what you wanted.
        //
        // Similarly, if the watchdog kick is in the idle task and it's
        // intended to detect any other task being stuck, you don't want any
        // other task to have a priority <= the idle task.
        if (i == 0) {
            g_app_task_handle = osThreadNew(g_app_tasks[i].func, NULL, &(g_app_tasks[i].attr));
            if (g_app_task_handle == NULL) {
                panic(PANIC_TASK_CREATE_FAILED, i);
            }
        } else {
            task_handle = osThreadNew(g_app_tasks[i].func, NULL, &(g_app_tasks[i].attr));
            if (task_handle == NULL) {
                panic(PANIC_TASK_CREATE_FAILED, i);
            }
        }
    }
#if !defined(CONFIG_SAMPLE_ENABLE)
    app_tasks_init();
#endif
}
#if defined(TEST_SUITE)
void cmd_processor_entry(void *args)
{
    UNUSED(args);
    // UART Initialisation
    test_suite_uart_init();  // If this gets changed to a non-lp uart then a sleep veto should be added
    uapi_test_suite_init();
    cmd_main_add_functions();
}

void cmd_main_add_functions(void)
{
    add_auxiliary_functions();
    add_pinctrl_test_case();
#ifdef FTRACE
    add_ftrace_test_case();
#endif
#ifdef COREMARK_TEST
    uapi_test_suite_add_function("coremark", "Coremark test Function", coremark_test);
#endif

#if defined(SUPPORT_HCC)
    add_hcc_test_case();
#endif

    add_uart_test_case();
    add_dfx_panic_test_case();
    add_cpu_trace_test_case();
    add_watchdog_test_case();
    add_timer_test_case();
    add_tcxo_test_case();
    add_systick_test_case();
    add_rtc_test_case();
    add_efuse_test_case();
    add_adc_test_case();
    add_i2s_test_case();
    add_security_unified_test_case();
    add_mbedtls_self_test_case();
    add_gpio_test_case();
    add_dma_test_case();
    add_pwm_test_case();
    add_sfc_test_case();
    add_i2c_test_case();
    add_kv_functions();
    add_test_update();
}
#endif

#ifdef IPC_TEST_DEMO
static ipc_msg_info_t head;
static void test_handler(uint8_t *payload_addr, uint32_t payload_len)
{
    UNUSED(payload_len);
    PRINT("IPC UART LoopBack Ok!\n");
    PRINT("IPC UART Get Dat: %s!\n", payload_addr);
    return;
}

void ipc_access(void)
{
    ipc_rx_handler_info_t handler_info;
    handler_info.msg_id = IPC_MSG_CORE1_0_CMD;
    handler_info.cb = test_handler;
    uapi_ipc_register_rx_handler(&handler_info);
    PRINT("IPC_TEST_DEMO\r\n");
}
#endif

#ifdef SUPPORT_HCC
static hcc_rom_callback g_hcc_rom_func = {0};
static void hcc_regist_rom_callback(void)
{
    g_hcc_rom_func.watchdog = (hcc_thread_watchdog)uapi_watchdog_kick;
    g_hcc_rom_func.rx_enque = (hcc_rx_enqueue_cb)hcc_unc_buf_enqueue_cb;
    hcc_rom_cb_register(&g_hcc_rom_func);
}
#endif

#ifdef _PRE_FEATURE_WS53_DEVICE_MODE
#define S_MGPIO0 0x52008000
#define S_MGPIO1 0x570360b8
#define S_MGPIO2 0x52008008
#define S_MGPIO3 0x5200800c
#define S_MGPIO4 0x52008010
#define S_AGPIO5 0x57036014
#define SDIO_MODE 1
#endif
#ifdef SUPPORT_HCC
static void acore_hcc_init(void)
{
    hcc_channel_param channel_init;
    hcc_regist_rom_callback();
    channel_init.bus_type = HCC_BUS_IPC;
    channel_init.queue_cfg = (hcc_queue_cfg *)hcc_get_queue_cfg(&channel_init.queue_len);
    channel_init.unc_pool_size = HCC_UNC_POOL_SIZE_ACORE;
    channel_init.unc_pool_low_limit = HCC_UNC_POOL_SIZE_LOW_LIMIT;
    channel_init.service_max_cnt = HCC_SERVICE_TYPE_MAX;
    channel_init.task_name = "hcc_task";
    channel_init.task_pri = HCC_TASK_PRIORITY;
    channel_init.max_proc_packets_per_loop = HCC_UNC_POOL_SIZE_ACORE;
    channel_init.tx_fail_num_limit = HCC_TX_PROC_FAILED_MAX_NUM;
    if (hcc_init(&channel_init) == HCC_CHANNEL_INVALID) {
        PRINT("hcc init: fail\r\n");
    }
    btc_hcc_msg_init();
#ifdef _PRE_FEATURE_WS53_DEVICE_MODE
    hcc_test_ipc_agaent_init();
    hcc_wifi_ipc_agaent_init();
    hcc_customize_ipc_agaent_init();
    hcc_send_message(HCC_BUS_IPC, H2D_MSG_TEST_INIT, 0);
    writel(S_MGPIO0, SDIO_MODE);
    writel(S_MGPIO1, SDIO_MODE);
    writel(S_MGPIO2, SDIO_MODE);
    writel(S_MGPIO3, SDIO_MODE);
    writel(S_MGPIO4, SDIO_MODE);
    writel(S_AGPIO5, SDIO_MODE);

    hcc_channel_param sdio_channel_init;
    sdio_channel_init.bus_type = HCC_BUS_SDIO;
    sdio_channel_init.queue_cfg = (hcc_queue_cfg *)hcc_get_queue_cfg(&sdio_channel_init.queue_len);
    sdio_channel_init.unc_pool_size = HCC_UNC_POOL_SIZE_ACORE;
    sdio_channel_init.unc_pool_low_limit = HCC_UNC_POOL_SIZE_LOW_LIMIT;
    sdio_channel_init.service_max_cnt = HCC_SERVICE_TYPE_MAX;
    sdio_channel_init.task_name = "hcc_sdio_task";
    sdio_channel_init.task_pri = HCC_TASK_PRIORITY;
    sdio_channel_init.max_proc_packets_per_loop = HCC_UNC_POOL_SIZE_ACORE;
    sdio_channel_init.tx_fail_num_limit = HCC_TX_PROC_FAILED_MAX_NUM;
    if (hcc_init(&sdio_channel_init) == HCC_CHANNEL_INVALID) {
        PRINT("hcc init: fail\r\n");
    }
    hcc_test_sdio_agaent_init();
    hcc_wifi_sdio_agaent_init();
    hcc_customize_sdio_agaent_init();
#endif
}
#endif
#if defined(CONFIG_SAMPLE_ENABLE)
static void app_sample(void *unused)
{
    UNUSED(unused);
    app_tasks_init();
}
#endif

static void pm_port_wakeup_debug(void)
{
    char *wk_src_name[PM_WKUP_MAX] = { "sdio",  "gpio", "uart_l0", "uart_h1", "JL",  "sec",  "rtc",  "wdt"};
    for (uint32_t i = 0; i < PM_WKUP_MAX; i++) {
        uint32_t wakeup_cnt = pm_port_get_wakeup_cnt(i);
        if (wakeup_cnt > 0) {
            print_str("%s wakeup cnt:%u\r\n", wk_src_name[i], wakeup_cnt);
        }
    }
}

static void app_main(void *unused)
{
#ifndef TEST_SUITE
    LOS_MEM_POOL_STATUS status;
#endif
    UNUSED(unused);
#if defined(CONFIG_MIDDLEWARE_SUPPORT_NV) && defined(CONFIG_OTA_UPDATE_SUPPORT)
#if (defined(CONFIG_NV_SUPPORT_OTA_UPDATE) && (defined(NV_YES)) && (CONFIG_NV_SUPPORT_OTA_UPDATE == NV_YES))
    (void)nv_upg_upgrade_task_process();
#endif
#endif
#ifdef IPC_TEST_DEMO
    uint8_t dat[] = "A 2 C Test Message";
    head.dst_core = CORES_BT_CORE;
    head.priority = 1;
    head.msg_id = IPC_MSG_CORE0_1_CMD;
    head.buf_addr = dat;
    head.buf_len = sizeof(dat);
    ipc_access();
#endif

#ifdef SUPPORT_HCC
    acore_hcc_init();
#endif
    /* 等待初始化完以后切换APP MAIN到期待的优先级 */
    osThreadSetPriority(g_app_task_handle, TASK_PRIORITY_APP);
    (void)osDelay(100); // 100: 100tiks = 1s
    systick_cali_xclk_bottom_half();
    while (1) {  //lint !e716 Main Loop
        (void)osDelay(TASK_COMMON_APP_DELAY_MS);
#ifdef IPC_TEST_DEMO
        PRINT("Send Ipc Message!\n");
        uapi_ipc_send_msg_async(&head);
#endif
#if defined(CONFIG_PM_DEBUG)
        pm_sleep_debug_t pm_debug_info = pm_port_get_debug_info();
        PRINT("pm_ls_count : %d, pm_ds_count : %d, pm_all_wkup_count : %d \n",
              pm_debug_info.pm_ls_count, pm_debug_info.pm_ds_count, pm_debug_info.pm_all_wkup_count);
        pm_port_wakeup_debug();
#endif /* CONFIG_PM_DEBUG */
#ifndef TEST_SUITE
        LOS_MemInfoGet(m_aucSysMem0, &status);
        PRINT("[SYS INFO] mem: used:%u, free:%u.\r\n", status.uwTotalUsedSize, status.uwTotalFreeSize);
#endif
    }
}
