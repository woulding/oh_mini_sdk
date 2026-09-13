/**
 * Copyright (c) HiSilicon (Shanghai) Technologies Co., Ltd. 2022-2023. All rights reserved.
 *
 * Description: Provides systick port template \n
 *
 * History: \n
 * 2022-07-30， Create file. \n
 */
#ifndef SYSTICK_PORTING_H
#define SYSTICK_PORTING_H

#include <stdint.h>

#ifdef __cplusplus
#if __cplusplus
extern "C" {
#endif /* __cplusplus */
#endif /* __cplusplus */

/**
 * @defgroup drivers_port_systick Systick
 * @ingroup  drivers_port
 * @{
 */

#define HAL_SYSTICK_TICKS_PER_SEC_DEFAULT   32000
#define MS_PER_S                            1000
#define US_PER_MS                           1000

/**
 * @if Eng
 * @brief  Get the base address of a specified systick.
 * @return The base address of specified systick.
 * @else
 * @brief  获取指定SYSTICK的基地址。
 * @return 指定SYSTICK的基地址。
 * @endif
 */
uintptr_t systick_porting_base_addr_get(void);

/**
 * @if Eng
 * @brief  Cali XCLK.
 * @else
 * @brief  修正XCLK时钟
 * @endif
 */
void systick_port_cali_xclk(void);

/**
 * @if Eng
 * @brief  Get systick work clock speed, ticks per second.
 * @return Systick work clock speed, ticks per second.
 * @else
 * @brief  获取SYSTICK工作时钟速度, 每秒tick数。
 * @return SYSTICK工作时钟速度, 每秒tick数。
 * @endif
 */
uint64_t systick_porting_ticks_per_sec_get(void);

/**
 * @if Eng
 * @brief  Set systick work clock speed, ticks per second.
 * @param  [in]  ticks work clock speed, ticks per second.
 * @else
 * @brief  设置SYSTICK工作时钟速度, 每秒tick数。
 * @param  [in]  ticks 工作时钟速度, 每秒tick数。
 * @endif
 */
void systick_porting_ticks_per_sec_set(uint64_t ticks);

/**
 * @if Eng
 * @brief  Convert time second to systick count.
 * @param  [in]  time_s second.
 * @else
 * @brief  转换时间秒为SYSTICK计数。
 * @param  [in]  time_s 时间秒。
 * @endif
 */
static inline uint64_t convert_s_2_count(uint64_t time_s)
{
    return time_s * systick_porting_ticks_per_sec_get();
}

/**
 * @if Eng
 * @brief  Convert systick count to time second.
 * @return Time second.
 * @else
 * @brief  转换SYSTICK计数为时间秒。
 * @return 时间秒。
 * @endif
 */
static inline uint64_t convert_count_2_s(uint64_t count)
{
    return count / systick_porting_ticks_per_sec_get();
}

/**
 * @if Eng
 * @brief  Convert time millisecond to systick count.
 * @param  [in]  time_ms millisecond.
 * @else
 * @brief  转换时间毫秒为SYSTICK计数。
 * @param  [in]  time_ms 时间毫秒。
 * @endif
 */
static inline uint64_t convert_ms_2_count(uint64_t time_ms)
{
    return time_ms * systick_porting_ticks_per_sec_get() / MS_PER_S;
}

/**
 * @if Eng
 * @brief  Convert systick count to time millisecond.
 * @return Time millisecond.
 * @else
 * @brief  转换SYSTICK计数为时间毫秒。
 * @return 时间毫秒。
 * @endif
 */
static inline uint64_t convert_count_2_ms(uint64_t count)
{
    return count * MS_PER_S / systick_porting_ticks_per_sec_get();
}

/**
 * @if Eng
 * @brief  Convert time microsecond to systick count.
 * @param  [in]  time_us microsecond.
 * @else
 * @brief  转换时间微秒为SYSTICK计数。
 * @param  [in]  time_us 时间微秒。
 * @endif
 */
static inline uint64_t convert_us_2_count(uint64_t time_us)
{
    return time_us * systick_porting_ticks_per_sec_get() / (MS_PER_S * US_PER_MS);
}

/**
 * @if Eng
 * @brief  Convert systick count to time microsecond.
 * @return Time microsecond.
 * @else
 * @brief  转换SYSTICK计数为时间微秒。
 * @return 时间微秒。
 * @endif
 */
static inline uint64_t convert_count_2_us(uint64_t count)
{
    return count * (MS_PER_S * US_PER_MS) / systick_porting_ticks_per_sec_get();
}

/**
 * @}
 */

#ifdef __cplusplus
#if __cplusplus
}
#endif /* __cplusplus */
#endif /* __cplusplus */

#endif
