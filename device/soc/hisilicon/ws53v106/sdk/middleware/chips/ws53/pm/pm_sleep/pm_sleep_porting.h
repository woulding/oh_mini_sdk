/**
 * Copyright (c) @CompanyNameMagicTag 2023-2023. All rights reserved. \n
 *
 * Description: Provides pm sleep port \n
 * Author: @CompanyNameTag \n
 * History: \n
 * 2023-01-13， Create file. \n
 */
#ifndef PM_SLEEP_PORTING_H
#define PM_SLEEP_PORTING_H

#include <bits/alltypes.h>
#include "platform_core.h"
#ifdef __cplusplus
#if __cplusplus
extern "C" {
#endif /* __cplusplus */
#endif /* __cplusplus */

/**
 * @defgroup middleware_chips_pm_sleep_port PM sleep port
 * @ingroup  middleware_chips_pm
 * @{
 */

#ifndef CONFIG_PM_LIGHT_SLEEP_THRESHOLD_MS
#define CONFIG_PM_LIGHT_SLEEP_THRESHOLD_MS 10
#endif

#ifndef CONFIG_PM_DEEP_SLEEP_THRESHOLD_MS
#define CONFIG_PM_DEEP_SLEEP_THRESHOLD_MS 20
#endif

#define PM_WAKEUP_RTC_INT_ID                RTC_1_IRQN
#define PM_WAKEUP_RTC_BASE_REG              0x57024200
#define PM_WAKEUP_RTC_LOAD_COUNT_L_OFFSET   0x00
#define PM_WAKEUP_RTC_LOAD_COUNT_H_OFFSET   0x04
#define PM_WAKEUP_RTC_CONTROL_OFFSET        0x10
#define PM_WAKEUP_RTC_ENABLE_VALUE          0x1
#define PM_WAKEUP_RTC_DISABLE_VALUE         0x0
#define PM_WAKEUP_RTC_EOI_REN_OFFSET        0x14

#if defined(CONFIG_PM_DEBUG)
typedef struct pm_sleep_debug {
    uint32_t pm_ls_count;
    uint32_t pm_ls_wkup_count;
    uint32_t pm_ds_count;
    uint32_t pm_ds_wkup_count;
    uint32_t pm_all_wkup_count;
}pm_sleep_debug_t;
#endif /* CONFIG_PM_DEBUG */

enum {
    PM_WKUP_SDIO,
    PM_WKUP_GPIO,
    PM_WKUP_UART_L0,
    PM_WKUP_UART_H1,
    PM_WKUP_JLINK,
    PM_WKUP_SEC_RTC,
    PM_WKUP_RTC,
    PM_WKUP_WDT,
    PM_WKUP_MAX,
};

void pm_wakeup_rtc_init(void);
void pm_wakeup_rtc_start(uint32_t time_ms);

void pm_port_start_tickless(void);
void pm_port_stop_tickless(uint32_t sleep_ms);
uint32_t pm_port_get_sleep_ms(void);
void pm_port_allow_deepsleep(bool allow);
void pm_port_enter_wfi(void);
void pm_port_start_wakeup_timer(uint32_t sleep_ms);
void pm_port_lightsleep_config(void);
void pm_port_light_wakeup_config(void);
void pm_port_deepsleep_config(void);
void pm_port_deep_wakeup_config(void);
void lowpower_cpu_suspend(void);
void lowpower_cpu_resume(void);
void suspend_irq(void);
void resume_irq(void);
void pm_port_cpu_suspend(void);
void pm_port_cpu_resume(void);
uint16_t pm_port_get_sleep_event_status(void);
uint16_t pm_port_get_wakeup_event_status(void);
void pm_port_skip_pull_down(pin_t pin);
#if defined(CONFIG_PM_DEBUG)
pm_sleep_debug_t pm_port_get_debug_info(void);
uint32_t pm_port_get_wakeup_cnt(uint32_t index);
#endif /* CONFIG_PM_DEBUG */
#define PM_GET_SLEEP_EVENT_STATUS   pm_port_get_sleep_event_status()
#define PM_GET_WKUP_EVENT_STATUS  pm_port_get_wakeup_event_status()
void pm_record_rtc_start(void);
void pm_record_rtc_stop(void);
void pm_wkup_irq(void);
void pm_heartbeat_rtc1_irq(uintptr_t data);
/**
 * @}
 */

#ifdef __cplusplus
#if __cplusplus
}
#endif /* __cplusplus */
#endif /* __cplusplus */

#endif

