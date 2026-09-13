/*
 * Copyright (c) HiSilicon (Shanghai) Technologies Co., Ltd. 2018-2020. All rights reserved.
 * Description: los status
 * Author:
 * Create:
 */
#ifndef BUILD_APPLICATION_SSB
#include "systick.h"
#include "non_os.h"
#include "securec.h"
#include "pmu_interrupt.h"
#include "pmu.h"
#include "tcxo.h"
#if USE_RPC_MODE == YES
#include "rpc_auto_generated_bt.h"
#endif
#include "los_status.h"

#define WAIT_JLINK_CONNECT_TIME 300

static uint32_t g_enter_core_deep_sleep_time = 0;
static uint32_t g_enter_light_sleep_time = 0;
static uint64_t g_los_system_sleep_base_time = 0;
static uint64_t g_los_system_start_up_base_time = 0;
static uint32_t g_wakeup_source[WAKEUP_SOURCE_MAX] = {0};
static bool g_los_system_entered_deep_sleep = false;
static bool g_plt_entered_deep_sleep = false;

void los_system_start_up_init(void)
{
    g_los_system_start_up_base_time = uapi_systick_get_ms();
}

uint64_t los_system_system_run_time(void)
{
    return (uapi_systick_get_ms() - g_los_system_start_up_base_time);
}

uint32_t los_bt_core_deep_sleep_time(void)
{
    return g_enter_core_deep_sleep_time;
}

uint32_t los_bt_core_light_sleep_time(void)
{
    return g_enter_light_sleep_time;
}

void los_status_enter_sleep_time(void)
{
    pmu_system_sleep_history_clear();
    g_los_system_sleep_base_time = uapi_systick_get_ms();
}

bool los_get_enter_deepsleep_flag(void)
{
    non_os_enter_critical();
    if (g_los_system_entered_deep_sleep) {
        g_los_system_entered_deep_sleep = false;
        non_os_exit_critical();
        return true;
    } else {
        non_os_exit_critical();
        return false;
    }
}

bool los_plt_enter_deepsleep_flag(void)
{
    non_os_enter_critical();
    if (g_plt_entered_deep_sleep) {
        g_plt_entered_deep_sleep = false;
        non_os_exit_critical();
        return true;
    } else {
        non_os_exit_critical();
        return false;
    }
}

void los_status_exit_sleep_time(lpc_sleep_mode_e sleep_mode)
{
    uint16_t event_id;
    if (sleep_mode == LPC_SLEEP_MODE_LIGHT) {
        g_enter_light_sleep_time += (uint32_t)(uapi_systick_get_ms() - g_los_system_sleep_base_time);
    } else {
        // system deepsleep history while btc sleep
        g_los_system_entered_deep_sleep = g_los_system_entered_deep_sleep || pmu_system_sleep_history();
        g_plt_entered_deep_sleep = pmu_system_sleep_history();
        event_id = pmu_lpm_wakeup_get_all_status(LPM_EVT_ACTION);
        los_status_wakeup_source_statistics(event_id);
        g_enter_core_deep_sleep_time += (uint32_t)(uapi_systick_get_ms() - g_los_system_sleep_base_time);
    }
}

void los_status_sleep_time_clear(void)
{
    non_os_enter_critical();
    g_enter_light_sleep_time = 0;
    g_enter_core_deep_sleep_time = 0;
    g_los_system_start_up_base_time = uapi_systick_get_ms();
    non_os_exit_critical();
}

#if USE_RPC_MODE == YES
bool remote_command_get_system_sleep_count(cores_t core, uint32_t *system_sleep_time, uint32_t *bt_sleep_time)
{
    UNUSED(core);
    *system_sleep_time = los_bt_core_deep_sleep_time();
    *bt_sleep_time = los_bt_core_light_sleep_time();
    los_status_sleep_time_clear();
    return true;
}
#endif

void los_status_wakeup_source_statistics(uint16_t interrupt_id)
{
    uint8_t bit_count;
    for (bit_count = 0; bit_count < WAKEUP_SOURCE_MAX; bit_count++) {
        if ((interrupt_id & BIT(bit_count)) != 0) {
            g_wakeup_source[bit_count]++;
            break;
        }
    }

    if ((interrupt_id & BIT(BCPU_DAP_WAKEUP)) != 0) {
        uapi_tcxo_delay_ms((uint64_t)WAIT_JLINK_CONNECT_TIME);
    }
}

system_wakeup_source_t *los_status_get_wakeup_source_statistics(void)
{
    return (system_wakeup_source_t*)g_wakeup_source;
}

#if USE_RPC_MODE == YES
static void los_status_release_wakeup_src(const void *free_addr)
{
    UNUSED(free_addr);
    memset_s(g_wakeup_source, sizeof(system_wakeup_source_t), 0, sizeof(system_wakeup_source_t));
}

bool remote_command_get_wakeup_src(cores_t core, uint16_t *src_length, rpc_free_cb *src_free_cb, uint32_t **src)
{
    UNUSED(core);
    *src = g_wakeup_source;
    *src_length = sizeof(system_wakeup_source_t);
    *src_free_cb = los_status_release_wakeup_src;
    return true;
}
#endif
#endif
