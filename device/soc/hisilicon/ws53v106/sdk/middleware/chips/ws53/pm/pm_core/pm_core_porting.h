/**
 * Copyright (c) @CompanyNameMagicTag 2023-2023. All rights reserved. \n
 *
 * Description: Provides PM port header \n
 * Author: @CompanyNameTag \n
 * History: \n
 * 2023-04-19, Create file. \n
 */
#ifndef PM_CORE_PORTING_H
#define PM_CORE_PORTING_H

#include <stdint.h>
#include "errcode.h"
#include "pm_core_defines.h"

#ifdef __cplusplus
#if __cplusplus
extern "C" {
#endif /* __cplusplus */
#endif /* __cplusplus */

/**
 * @defgroup middleware_port_pm_core PM Core Porting
 * @ingroup  middleware_port
 * @{
 */

#if defined(CONFIG_PM_DEBUG)
typedef struct pm_sleep_debug {
    uint32_t pm_ls_count;
    uint32_t pm_ls_wkup_count;
    uint32_t pm_ds_count;
    uint32_t pm_ds_wkup_count;
    uint32_t pm_all_wkup_count;
}pm_sleep_debug_t;
#endif /* CONFIG_PM_DEBUG */

/* uart debug bus */
extern uint8_t g_uart_debug_bus;

uint32_t pm_core_port_read_wkup_irq_register(void);
uint32_t pm_core_port_read_sleep_irq_register(void);
void pm_core_port_clear_wkup_irq_register(uint32_t mask);
void pm_core_port_clear_sleep_irq_register(uint32_t mask);
uint32_t pm_core_port_get_sleep_irqn(void);
uint32_t pm_core_port_get_wkup_irqn(void);
uint32_t pm_core_port_get_sleep_priority(void);
uint32_t pm_core_port_get_wkup_priority(void);
void pm_core_port_bootup_config(void);
void pm_core_port_enter_wfi(void);
errcode_t pm_core_port_serv_work_state_chg(uint32_t sid, uint32_t state);
void pm_core_port_pf_disallow_to_sleep(void);
void pm_core_port_pmu_wkup_config(void);
void pm_core_port_cmu_wkup_config(void);
void pm_core_port_wkup_prep_tcxo(void);
void pm_core_port_wakeup_sleep_evt_process(void);
void pm_core_port_switch_high_freq(void);
void pm_core_port_pf_enable_wkup_irq_only(void);
void pm_core_port_restore_interrupt(void);
void pm_core_port_pf_shutdown_device(void);
void pm_core_port_pf_switch_to_tcxo(void);
void pm_core_port_deep_sleep_mode(uint16_t sleep_mode);
void pm_core_porting_shutdown_config(void);
void pm_core_port_enable_int_src(void);
void pm_core_port_disable_int_src(void);
void pm_core_port_pf_after_suspend(void);
void pm_core_port_enter_deepsleep(void);
void pm_core_port_enter_lightsleep(void);
int32_t pm_core_work_check(void);
void pm_core_start_wakeup_rtc(void);
void pm_core_stop_wakeup_rtc(void);
void lowpower_cpu_suspend(void);
void lowpower_cpu_resume(void);
void pm_record_rtc_start(void);
void suspend_irq(void);
void resume_irq(void);
uint32_t pm_core_port_get_pf_id(void);
#if defined(CONFIG_PM_DEBUG)
pm_sleep_debug_t pm_port_get_debug_info(void);
#endif /* CONFIG_PM_DEBUG */

/**
 * @}
 */

#ifdef __cplusplus
#if __cplusplus
}
#endif /* __cplusplus */
#endif /* __cplusplus */

#endif