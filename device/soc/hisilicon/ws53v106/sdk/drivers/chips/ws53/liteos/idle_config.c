/*
 * Copyright (c) HiSilicon (Shanghai) Technologies Co., Ltd. 2021-2021. All rights reserved.
 * Description: RISCV31 idle task config for LiteOS
 *
 * Create: 2021-10-20
 */
#include "idle_config.h"
#include "core.h"
#include "los_task.h"

#include "cmsis_os2.h"
#include "watchdog.h"

#if CORE == MASTER_BY_ALL
#if ((USE_COMPRESS_LOG_INSTEAD_OF_SDT_LOG == NO) && defined(LIBLOG))
#include "log_oam_msg.h"
#endif
#endif
#include "pm_sleep.h"
#include "pm_porting.h"
#include "pm_veto.h"
#include "pm_veto_porting.h"

#ifdef __cplusplus
#if __cplusplus
extern "C" {
#endif /* __cplusplus */
#endif /* __cplusplus */

#if (ENABLE_LOW_POWER == YES)
#define PM_TIMEOUT_MAX 10000
uint64_t g_pm_timeout_timestamp = 0;
#if defined(_PRE_FEATURE_WS53_DEVICE_MODE) || defined(TEST_SUITE)
bool g_open_pm = false;
#else
bool g_open_pm = true;
#endif

static pm_lpc_type g_lp_stat = PM_DEEP_SLEEP;

void idle_set_open_pm(bool open)
{
    g_open_pm = open;
}

bool idle_get_open_pm(void)
{
    return g_open_pm;
}

void idle_pm_update_timeout(unsigned int delay_ms)
{
    g_pm_timeout_timestamp = PM_GET_CURRENT_MS + delay_ms;
}

static bool idle_pm_check(void)
{
    uint64_t cur_time;
    if (!g_open_pm) {
        return false;
    }
    cur_time = PM_GET_CURRENT_MS;
    if (g_pm_timeout_timestamp > cur_time) {
        if (PM_TIMEOUT_MAX + cur_time < g_pm_timeout_timestamp) {
            g_pm_timeout_timestamp = cur_time;
        }
        return false;
    }
    return true;
}
#endif

static watchdog_port_idle_kick_callback g_wdt_kick_callback = NULL;
void watchdog_port_idle_kick_register(watchdog_port_idle_kick_callback callback)
{
    g_wdt_kick_callback = callback;
}

static void idle_task_process(void)
{
#if ((USE_COMPRESS_LOG_INSTEAD_OF_SDT_LOG == NO) && defined(LIBLOG))
#if CORE == MASTER_BY_ALL
    log_oam_prase_message();
#endif
#endif

    if (g_wdt_kick_callback != NULL) {
        g_wdt_kick_callback();
    } else {
        uapi_watchdog_kick();
    }

#if (ENABLE_LOW_POWER == YES)
    if (idle_pm_check()) {
        uapi_pm_enter_sleep();
    }
#endif
}

void idle_task_config(void)
{
    LOS_IdleHandlerHookReg(idle_task_process);
}

uint32_t uapi_lpc_set_type(pm_lpc_type type)
{
    if (type > PM_DEEP_SLEEP) {
        return ERRCODE_FAIL;
    }

    if (g_lp_stat == type) {
        return ERRCODE_SUCC;
    }
    g_lp_stat = type;
    if (type == PM_NO_SLEEP) {
        idle_set_open_pm(false);
    } else if (type == PM_LIGHT_SLEEP) {
        idle_set_open_pm(true);
        uapi_pm_add_sleep_veto(PM_PLAT_VETO_ID);
    } else {
        idle_set_open_pm(true);
        uapi_pm_remove_sleep_veto(PM_PLAT_VETO_ID);
    }
    return ERRCODE_SUCC;
}

pm_lpc_type uapi_lpc_get_type(void)
{
    return g_lp_stat;
}

#ifdef __cplusplus
#if __cplusplus
}
#endif /* __cplusplus */
#endif /* __cplusplus */
