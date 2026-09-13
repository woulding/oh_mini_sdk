/*
 * Copyright (c) HiSilicon (Shanghai) Technologies Co., Ltd. 2018-2020. All rights reserved.
 * Description:  TSENSOR DRIVER.
 *
 * Create:  2018-10-15
 */

#ifndef NON_OS_TSENSOR_H
#define NON_OS_TSENSOR_H

#include "std_def.h"

/**
 * @defgroup connectivity_drivers_non_os_tsensor TSENSOR
 * @ingroup  connectivity_drivers_non_os
 * @{
 */
typedef enum {
    TSENSOR_WORK_MODE_INQUIRE,    // can use TSENSOR_SAMP_MODE_AVERAGE_ONCE and TSENSOR_SAMP_MODE_AVERAGE_CYCLE.
    TSENSOR_WORK_MODE_INTERRUPT,  // only can use TSENSOR_SAMP_MODE_AVERAGE_CYCLE.
    TSENSOR_WORK_MODE_MAX_NUM,
    TSENSOR_WORK_MODE_NONE = TSENSOR_WORK_MODE_MAX_NUM,
} tsensor_work_mode_e;

typedef enum {
    TSENSOR_SAMP_MODE_AVERAGE_ONCE = 0,  // only can be used in TSENSOR_WORK_MODE_INQUIRE
    TSENSOR_SAMP_MODE_AVERAGE_CYCLE,     // can be used in TSENSOR_WORK_MODE_INQUIRE and TSENSOR_WORK_MODE_INTERRUPT.
    TSENSOR_SAMP_MODE_MAX_NUM,
    TSENSOR_SAMP_MODE_NONE = TSENSOR_SAMP_MODE_MAX_NUM,
} tsensor_samp_mode_e;

/**
 * @brief  bt notify app temperature change.
 * @param  below_zero_degree  true:<=0°， false:>0°
 */
void bt_notify_app_temperature_change(bool below_zero_degree);

/**
 * @brief  register tsensor interrupt.
 */
void tsensor_init(void);

/**
 * @brief  logout tsensor interrupt.
 */
void tsensor_deinit(void);

/**
 * @brief  enable tsensor inquire mode.
 * @param  samp_mode: TSENSOR_SAMP_MODE_AVERAGE_ONCE or TSENSOR_SAMP_MODE_AVERAGE_CYCLE.
 * @return ture: enable tsensor success.
 * @return false: enable tsensor faild.
 */
bool tsensor_enable_inquire_mode(tsensor_samp_mode_e samp_mode);

/**
 * @brief  enable tsensor inquire mode, samping mode is TSENSOR_SAMP_MODE_AVERAGE_CYCLE.
 * @param temp: temperature pointer, output parameter.
 * @param temp_limit_low: tsensor low limit, minimum value is -40C.
 * @param temp_limit_high: tsensor high limit, maximum value is 125C.
 * @return ture: enable tsensor success.
 * @return false: enable tsensor faild.
 */
bool tsensor_enable_interrupt_mode(int8_t *temp, int8_t temp_limit_low, int8_t temp_limit_high);

/**
 * @brief  get tsensor current temperature.
 * @param  temp: temperature pointer, output parameter.
 * @return ture: get tsensor temperature success, temperature is valid.
 * @return false: get tsensor temperature faild, temperature is invalid.
 */
bool tsensor_get_current_temp(int8_t *temp);

/**
 * @}
 */
#endif
