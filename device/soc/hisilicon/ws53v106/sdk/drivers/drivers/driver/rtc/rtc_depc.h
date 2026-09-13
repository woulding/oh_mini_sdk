/**
 * Copyright (c) HiSilicon (Shanghai) Technologies Co., Ltd. 2018-2020. All rights reserved.
 *
 * Description:  RTC DRIVER INTERFACE \n
 *
 * Create:  2018-10-15 \n
 */
#ifndef NON_OS_RTC_H
#define NON_OS_RTC_H

#include "std_def.h"

#ifdef __cplusplus
#if __cplusplus
extern "C" {
#endif
#endif

/**
 * @defgroup connectivity_drivers_non_os_rtc RTC
 * @ingroup  connectivity_drivers_non_os
 * @{
 */
#define RTC_CLOCK_SPEED   32768
#define RTC_ONE_SECOND    (RTC_CLOCK_SPEED)
#define MINIMUM_RTC_DELAY 4

/*
 * These defines are the magic numbers used to convert from MS to RTC
 */
#define RTC_MS_TIME_MULTIPLY     (RTC_CLOCK_SPEED >> 3)
#define RTC_MS_TIME_DIVIDE       (1000 >> 3)
#define rtc_ms_convert_to_rtc(x) (((uint64_t)(x) * RTC_MS_TIME_MULTIPLY) / RTC_MS_TIME_DIVIDE)

/**
 * @brief  Used to pass a timer handle around
 */
typedef void *rtc_handle;

typedef void (*rtc_timer_callback)(void);

typedef enum {
    RTC_FAILURE,
    RTC_SUCCESS,
} rtc_status;

typedef enum {
    CURRENT_TIME_FIELD_UPDATED = 0x01,
    CURRENT_TIME_ZONE_FIELD_UPDATED = 0x02,
    CURRENT_TIME_SAVING_TIME_FIELD_UPDATED = 0x04,
} updated_time_fields_e;

/**
 * @brief  RTC flag.
 */
typedef enum {
    RTC_FLAG_NORMAL = 0,
    RTC_FLAG_PERMANENT,  // the flag to make sure there is enough resource for caller
} rtc_flag_e;

/**
 * @brief  Initialises the timer, assumes that the core clock has already been set up
 * And that the clock speed will not get changed again
 */
void rtc_init(void);

/**
 * @brief  Unlike the bellow functions this will add a timer at the specified RTC time
 * @param  rtc_time The time rtc time to fire this timer
 * @param  callback_func the function to call once the wait is done
 * @param  flag the feature of rtc
 * @return the handler to the timer - NULL = failed
 */
rtc_handle rtc_add_at(uint64_t rtc_time, rtc_timer_callback callback_func, rtc_flag_e flag);

/**
 * @brief  Adds a new timer to the timer list
 * @param  callback_delay - how many clock cycles to wait
 * @param  callback_func the function to call once the wait is done
 * @param  flag - the feature of rtc
 * @return the handler to the timer - NULL = failed
 */
rtc_handle rtc_add(uint64_t callback_delay, rtc_timer_callback callback_func, rtc_flag_e flag);

/**
 * @brief  Adds a permanent timer to the timer list
 * @param  timer_id The timer id that you wish to reset
 * @param  callback_delay - how many clock cycles to wait
 * @param  callback_func the function to call once the wait is done
 * @return RTC_SUCCESS on success, RTC_FAILURE otherwise - a failure indicates that the timer did not exist
 */
rtc_status rtc_reset(rtc_handle timer_id, uint64_t callback_delay, rtc_timer_callback callback_func);

/**
 * @brief  Adds a permanent timer to the timer list
 * @param  timer_id The timer id that you wish to reset
 * @param  callback_delay - how many clock cycles to wait
 * @param  callback_func the function to call once the wait is done
 * @return RTC_SUCCESS on success, RTC_FAILURE otherwise - a failure indicates that the timer did not exist
 */
rtc_status rtc_reset_ms(rtc_handle timer_id, uint32_t callback_delay, rtc_timer_callback callback_func);

/**
 * @brief  Adds a permanent timer to the timer list
 * @param  timer_id The timer id that you wish to reset
 * @param  callback_delay - how many clock cycles to wait
 * @param  callback_func the function to call once the wait is done
 * @return RTC_SUCCESS on success, RTC_FAILURE otherwise - a failure indicates that the timer did not exist
 */
rtc_status rtc_reset_s(rtc_handle timer_id, uint32_t callback_delay, rtc_timer_callback callback_func);

/**
 * @brief  Adds a new timer to the timer list
 * @param  callback_delay - how many ms to wait
 * @param  callback_func the function to call once the wait is done
 * @param  flag - the feature of rtc
 * @return the handler to the timer - NULL = failed
 */
rtc_handle rtc_add_ms(uint32_t callback_delay, rtc_timer_callback callback_func, rtc_flag_e flag);

/**
 * @brief  Adds a new timer to the timer list
 * @param  callback_delay - how many seconds to wait
 * @param  callback_func the function to call once the wait is done
 * @param  flag - the feature of rtc
 * @return the handler to the timer - NULL = failed
 */
rtc_handle rtc_add_s(uint32_t callback_delay, rtc_timer_callback callback_func, rtc_flag_e flag);

/**
 * @brief  @param  timer_id The timer id that you wish to stop
 * @return RTC_SUCCESS on success, RTC_FAILURE otherwise - a failure indicates that the timer did not exist
 */
rtc_status rtc_stop(rtc_handle timer_id);

/**
 * @brief  @param  timer_id The timer id that you wish to delete
 * @return RTC_SUCCESS on success, RTC_FAILURE otherwise - a failure indicates that the timer did not exist
 */
rtc_status rtc_delete(rtc_handle timer_id);

/**
 * @brief  Converts the given time period, in microseconds, to the number of RTC ticks which are guaranteed
 * to cover that time period.  Takes into account that the request can occur anywhere within
 * the current RTC timer tick.
 * @param  time_period_in_us The time period, in microseconds, to convert into RTC ticks
 * @return The number of RTC ticks required to cover the specified timer period
 */
uint64_t rtc_convert_time_to_ticks(uint64_t time_period_in_us);

/**
 * @brief  Obtains the RTC clock tick for some specified time in the future
 * @param  time_period_in_ticks How long into the future to obtain an RTC time
 * @return The future RTC time, in ticks
 */
uint64_t rtc_get_future_time(uint64_t time_period_in_ticks);

/**
 * @brief  Get the count of RTC IRQ.
 * @return The count of RTC IRQ.
 */
uint32_t rtc_int_cnt_record_get(void);

#ifdef __cplusplus
#if __cplusplus
}
#endif
#endif

/**
 * @}
 */
#endif
