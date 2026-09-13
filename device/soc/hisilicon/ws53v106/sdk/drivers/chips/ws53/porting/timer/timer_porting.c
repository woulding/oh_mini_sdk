/**
 * Copyright (c) HiSilicon (Shanghai) Technologies Co., Ltd. 2022-2023. All rights reserved.
 *
 * Description: Provides timer port \n
 *
 * History: \n
 * 2022-06-06， Create file. \n
 */
#include "interrupt/osal_interrupt.h"
#include "common_def.h"
#include "hal_timer_v150.h"
#include "timer.h"
#include "platform_core.h"
#include "chip_core_irq.h"
#include "timer_porting.h"

// 减少64位除法计算时间优化, 在设置工作时间时先运算好, 在实际运算时只需进行乘法和位移运算
#define TIMER_CLOCK_QUICK_CALC_OFFSET 10
static uint32_t g_timer_clock_value = CONFIG_TIMER_CLOCK_VALUE;
static uint64_t g_timer_quick_calc_value_1 =
    ((uint64_t)CONFIG_TIMER_CLOCK_VALUE << TIMER_CLOCK_QUICK_CALC_OFFSET) / (MS_PER_S * US_PER_MS);
static uint64_t g_timer_quick_calc_value_2 =
    ((uint64_t)(MS_PER_S * US_PER_MS) << TIMER_CLOCK_QUICK_CALC_OFFSET) / CONFIG_TIMER_CLOCK_VALUE;

static uintptr_t const g_timer_base_addr[TIMER_MAX_NUM] = {
    TIMER_0_BASE_ADDR,
    TIMER_1_BASE_ADDR,
#if defined(CONFIG_TIMER_MAX_NUM) && (CONFIG_TIMER_MAX_NUM > 2)
    TIMER_2_BASE_ADDR,
#endif
};

uintptr_t timer_porting_comm_addr_get(void)
{
    return TIMER_BASE_ADDR;
}

uintptr_t timer_porting_base_addr_get(timer_index_t index)
{
    return g_timer_base_addr[index];
}

STATIC int timer0_irq_handler(int i, void *p)
{
    unused(i);
    unused(p);
    hal_timer_v150_irq_handler(TIMER_INDEX_0);
    osal_irq_clear(TIMER_0_IRQN);
    return 0;
}

STATIC int timer1_irq_handler(int i, void *p)
{
    unused(i);
    unused(p);
    hal_timer_v150_irq_handler(TIMER_INDEX_1);
    osal_irq_clear(TIMER_1_IRQN);
    return 0;
}

#if defined(CONFIG_TIMER_MAX_NUM) && (CONFIG_TIMER_MAX_NUM > 2)
STATIC int timer2_irq_handler(int i, void *p)
{
    unused(i);
    unused(p);
    hal_timer_v150_irq_handler(TIMER_INDEX_2);
    osal_irq_clear(TIMER_2_IRQN);
    return 0;
}
#endif

static osal_irq_handler const timer_irq_handler[TIMER_MAX_NUM] = {
    timer0_irq_handler,
    timer1_irq_handler,
#if defined(CONFIG_TIMER_MAX_NUM) && (CONFIG_TIMER_MAX_NUM > 2)
    timer2_irq_handler,
#endif
};

void timer_port_register_irq(timer_index_t index, uint32_t id, uint16_t priority)
{
    osal_irq_disable(id);
    osal_irq_request(id, (osal_irq_handler)timer_irq_handler[index], NULL, NULL, NULL);
    osal_irq_set_priority(id, priority);
    osal_irq_enable(id);
}

void timer_port_unregister_irq(timer_index_t index, uint32_t id)
{
    unused(index);
    osal_irq_disable(id);
    osal_irq_free(id, NULL);
}

void timer_porting_clock_value_set(uint32_t clock)
{
    g_timer_clock_value = clock;
    g_timer_quick_calc_value_1 = ((uint64_t)clock << TIMER_CLOCK_QUICK_CALC_OFFSET) / (MS_PER_S * US_PER_MS);
    g_timer_quick_calc_value_2 = ((uint64_t)(MS_PER_S * US_PER_MS) << TIMER_CLOCK_QUICK_CALC_OFFSET) / clock;
}

uint32_t timer_porting_clock_value_get(void)
{
    return g_timer_clock_value;
}

uint64_t timer_porting_us_2_cycle(uint32_t us)
{
    return ((uint64_t)us * g_timer_quick_calc_value_1) >> TIMER_CLOCK_QUICK_CALC_OFFSET;
}

uint32_t timer_porting_cycle_2_us(uint64_t cycle)
{
    return (uint32_t)((cycle * g_timer_quick_calc_value_2) >> TIMER_CLOCK_QUICK_CALC_OFFSET);
}

uint64_t timer_porting_compensat_by_tcxo(uint64_t diff)
{
    if (diff < TIMER_COMPENSAT_1_CYCLE_BY_TCXO) {
        return 0;
    } else if (diff < TIMER_COMPENSAT_2_CYCLE_BY_TCXO) {
        return TIMER_1_CYCLE;
    } else if (diff < TIMER_COMPENSAT_3_CYCLE_BY_TCXO) {
        return TIMER_2_CYCLE;
    } else {
        return diff / TIMER_COMPENSAT_1_CYCLE_BY_TCXO;
    }
}