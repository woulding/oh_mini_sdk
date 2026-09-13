/*
 * Copyright (c) HiSilicon (Shanghai) Technologies Co., Ltd. 2021-2021. All rights reserved.
 * Description: RISCV31 idle task config interface for LiteOS
 *
 * Create:  2021-10-20
 */
#ifndef IDLE_CONFIG_H
#define IDLE_CONFIG_H
#include "stdbool.h"
#include "stdint.h"
/**
 * @brief  los idle task config
 */
typedef enum {
    PM_NO_SLEEP,    /** 不睡模式 */
    PM_LIGHT_SLEEP, /** 浅睡模式 */
    PM_DEEP_SLEEP,  /** 深睡模式     */
} pm_lpc_type;

pm_lpc_type uapi_lpc_get_type(void);
uint32_t uapi_lpc_set_type(pm_lpc_type type);
void idle_pm_update_timeout(unsigned int delay_ms);
void idle_task_config(void);
void idle_set_open_pm(bool open);
bool idle_get_open_pm(void);
typedef void (*watchdog_port_idle_kick_callback)(void);
void watchdog_port_idle_kick_register(watchdog_port_idle_kick_callback callback);
#endif
