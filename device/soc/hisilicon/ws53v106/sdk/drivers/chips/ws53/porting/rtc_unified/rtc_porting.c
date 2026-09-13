/**
 * Copyright (c) HiSilicon (Shanghai) Technologies Co., Ltd. 2023-2023. All rights reserved.
 *
 * Description: Provide rtc port \n
 *
 * History: \n
 * 2023-03-02, Create file. \n
 */

#include "soc_osal.h"
#include "common_def.h"
#include "hal_rtc_v150.h"
#include "chip_core_irq.h"
#include "platform_core.h"
#include "rtc_porting.h"

// 减少64位除法计算时间优化, 在设置工作时间时先运算好, 在实际运算时只需进行乘法和位移运算
#define RTC_CLOCK_QUICK_CALC_OFFSET 10
static uint32_t g_rtc_clock_value = CONFIG_RTC_CLOCK_VALUE;
static uint64_t g_rtc_quick_calc_value_1 =
    ((uint64_t)CONFIG_RTC_CLOCK_VALUE << RTC_CLOCK_QUICK_CALC_OFFSET) / MS_PER_S;
static uint64_t g_rtc_quick_calc_value_2 =
    ((uint64_t)(MS_PER_S * US_PER_MS) << RTC_CLOCK_QUICK_CALC_OFFSET) / CONFIG_RTC_CLOCK_VALUE;

static uintptr_t g_rtc_base_addr[RTC_MAX_NUM] = {
    RTC_0_BASE_ADDR,
    RTC_1_BASE_ADDR,
};

uintptr_t rtc_porting_comm_addr_get(void)
{
    return RTC_BASE_ADDR;
}

uintptr_t rtc_porting_base_addr_get(rtc_index_t index)
{
    return g_rtc_base_addr[index];
}

static int rtc0_irq_handler(int i, void *p)
{
    unused(i);
    unused(p);
    hal_rtc_v150_irq_handler(RTC_0);
    osal_irq_clear(RTC_0_IRQN);
    return 0;
}

static int rtc1_irq_handler(int i, void *p)
{
    unused(i);
    unused(p);
    hal_rtc_v150_irq_handler(RTC_1);
    osal_irq_clear(RTC_1_IRQN);
    return 0;
}

static osal_irq_handler const rtc_irq_handler[RTC_MAX_NUM] = {
    rtc0_irq_handler,
    rtc1_irq_handler,
};

void rtc_port_register_irq(rtc_index_t index, uint32_t id, uint16_t priority)
{
    osal_irq_disable(id);
    osal_irq_request(id, rtc_irq_handler[index], NULL, NULL, NULL);
    osal_irq_set_priority(id, priority);
    osal_irq_enable(id);
}

void rtc_port_unregister_irq(rtc_index_t index, uint32_t id)
{
    unused(index);
    osal_irq_disable(id);
    osal_irq_free(id, NULL);
}

void rtc_porting_clock_value_update(uint32_t clock)
{
    g_rtc_clock_value = clock;
    g_rtc_quick_calc_value_1 = ((uint64_t)clock << RTC_CLOCK_QUICK_CALC_OFFSET) / MS_PER_S;
    g_rtc_quick_calc_value_2 = ((uint64_t)(MS_PER_S * US_PER_MS) << RTC_CLOCK_QUICK_CALC_OFFSET) / clock;
}

uint32_t rtc_porting_clock_value_get(void)
{
    return g_rtc_clock_value;
}

uint64_t rtc_porting_ms_2_cycle(uint32_t ms)
{
    return ((uint64_t)ms * g_rtc_quick_calc_value_1) >> RTC_CLOCK_QUICK_CALC_OFFSET;
}

uint64_t rtc_hw_porting_ms_2_cycle(uint64_t ms)
{
    return ((uint64_t)ms * g_rtc_quick_calc_value_1) >> RTC_CLOCK_QUICK_CALC_OFFSET;
}

uint32_t rtc_porting_cycle_2_us(uint64_t cycle)
{
    return (uint32_t)((cycle * g_rtc_quick_calc_value_2) >> RTC_CLOCK_QUICK_CALC_OFFSET);
}

uint64_t rtc_porting_compensat_by_tcxo(uint64_t diff)
{
    if (diff < RTC_COMPENSAT_1_CYCLE_BY_TCXO) {
        return 0;
    } else if (diff < RTC_COMPENSAT_2_CYCLE_BY_TCXO) {
        return RTC_1_CYCLE;
    } else if (diff < RTC_COMPENSAT_3_CYCLE_BY_TCXO) {
        return RTC_2_CYCLE;
    } else {
        return diff / RTC_COMPENSAT_1_CYCLE_BY_TCXO;
    }
}