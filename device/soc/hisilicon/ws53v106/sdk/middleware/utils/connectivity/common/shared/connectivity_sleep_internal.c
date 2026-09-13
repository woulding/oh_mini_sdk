/*
 * Copyright (c) HiSilicon (Shanghai) Technologies Co., Ltd. 2021-2021. All rights reserved.
 * Description: System sleep internal manager source.
 * Author:
 * Create:  2021-3-1
 */
#include "connectivity_sleep_internal.h"
#include "non_os.h"
#if defined(USE_CMSIS_OS)
#ifdef __LITEOS__
#include "los_config.h"
#endif
#if defined(LOSCFG_KERNEL_RUNSTOP) && (LOSCFG_KERNEL_RUNSTOP == YES)
#ifdef __LITEOS__
#include "los_task_pri.h"
#include "los_swtmr_pri.h"
#include "los_tick_pri.h"
#endif
#endif
#include "systick.h"
#include "tcxo.h"
#include "asm/platform.h"

#define CONNECTIVITY_SLEEP_US_PER_OS_TICK               1000

static uint64_t g_entry_sleep_time = 0;
static uint64_t g_exit_sleep_time = 0;
#if (ARCH == CM3) || (ARCH == CM7)
static uint32_t g_expected_sleep_time = 0;
static uint64_t g_rtc_time_calibrate = 0;
#endif
static bool g_is_sleep = false;

uint64_t connectivity_entry_sleep_time_get(void)
{
    return g_entry_sleep_time;
}

void connectivity_entry_sleep_time_set(uint64_t val)
{
    g_entry_sleep_time = val;
}

void connectivity_sys_is_sleep_set(bool val)
{
    non_os_enter_critical();
    g_is_sleep = val;
    non_os_exit_critical();
}

bool connectivity_sys_is_sleep_get(void)
{
    return g_is_sleep;
}

#if (ARCH == CM3) || (ARCH == CM7)
static uint32_t connectivity_sys_sleep_ticks_get(void)
{
#if defined(LOSCFG_KERNEL_RUNSTOP) && (LOSCFG_KERNEL_RUNSTOP == YES)
    /** Context guarantees that the interrupt has been closed */
    uint32_t tsk_sortlink_ticks = OsTaskNextSwitchTimeGet();
    uint32_t swtmr_sortlink_ticks = OsSwtmrGetNextTimeout();

    return (tsk_sortlink_ticks < swtmr_sortlink_ticks) ? tsk_sortlink_ticks : swtmr_sortlink_ticks;
#else
    return 0;
#endif
}

uint32_t connectivity_expected_sleep_time_get(void)
{
    return g_expected_sleep_time;
}

void connectivity_expected_sleep_time_set(void)
{
    g_expected_sleep_time = connectivity_sys_sleep_ticks_get();
}

/* Change Systick Count To Rtc Ms */
uint32_t connectivity_systick_count_to_rtc_ms(uint32_t systick_count)
{
    return systick_count;
}

static void los_system_adjust(uint32_t sleep_time)
{
#if defined(LOSCFG_KERNEL_RUNSTOP) && (LOSCFG_KERNEL_RUNSTOP == YES)
    if (sleep_time == 0) {
        return;
    }

    g_ullTickCount += sleep_time;

    if (sleep_time > connectivity_expected_sleep_time_get()) {
        sleep_time = connectivity_expected_sleep_time_get();
    }
#ifdef __LITEOS__
    OsSwtmrAdjust(sleep_time);
    OsTaskAdjust(sleep_time);
#endif
#else
    UNUSED(sleep_time);
#endif
}

void connectivity_sys_wakeup(void)
{
    non_os_enter_critical();
    SCB->SCR &= (uint32_t)~((uint32_t)SCB_SCR_SLEEPDEEP_Msk);
    if (connectivity_sys_is_sleep_get() == true) {
        connectivity_sys_is_sleep_set(false);

        // record exit sleep time and enable tick
        g_exit_sleep_time = systick_get_count();
        SysTick->CTRL |= SysTick_CTRL_ENABLE_Msk;
        // calibrate sleep ticks
        uint64_t rtc_sleep_time = ((g_exit_sleep_time - connectivity_entry_sleep_time_get()) *
                        LOSCFG_BASE_CORE_TICK_PER_SECOND) + g_rtc_time_calibrate;
        uint32_t elapsed_ticks = (uint32_t)(rtc_sleep_time >> 0xf); // divide 32768
        g_rtc_time_calibrate = rtc_sleep_time & 0x7FFF;
        // update system status in elaspedticks
#ifdef __LITEOS__
        los_system_adjust(elapsed_ticks);
#endif
    }
    non_os_exit_critical();
}
#else
void connectivity_sys_sleep_time_compensation(uint32_t sleep_ticks)
{
    non_os_enter_critical();
    if (connectivity_sys_is_sleep_get() == true) {
        connectivity_sys_is_sleep_set(false);

        g_exit_sleep_time = uapi_tcxo_get_us();
        uint32_t rtc_sleep_time = (uint32_t)((g_exit_sleep_time - connectivity_entry_sleep_time_get()) /
                                             CONNECTIVITY_SLEEP_US_PER_OS_TICK);
        // update os_systick
        if (rtc_sleep_time > sleep_ticks) {
            oal_ticks_restore(sleep_ticks);
        } else {
            oal_ticks_restore(rtc_sleep_time);
        }
    }
    non_os_exit_critical();
}
#endif
#endif