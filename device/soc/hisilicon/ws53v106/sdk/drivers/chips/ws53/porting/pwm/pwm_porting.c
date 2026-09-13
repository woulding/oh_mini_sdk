/**
 * Copyright (c) HiSilicon (Shanghai) Technologies Co., Ltd. 2022-2022. All rights reserved.
 *
 * Description: Provides pwm port \n
 *
 * History: \n
 * 2022-09-16， Create file. \n
 */

#include "soc_osal.h"
#include "common_def.h"
#include "platform_core.h"
#include "hal_pwm_v151.h"
#include "chip_core_irq.h"
#include "clock_recover.h"
#include "chip_io.h"
#include "pwm_porting.h"

#define BUS_CLOCK_TIME_32M      32000000UL
#define PWM_CLKEN0_OFFSET       7
#define PWM_DIV_CLOSE           0x0
#define BIT_WIDTH_LIMIT         0xFF
#define PWM_LOAD_DIV_EN_OFFSET  1
#define PWM_DIV_NUM_OFFSET      2
#define PWM_DIV_NUM_LEN         5
#define PWM_DIV_EN_OFFSET       0
#define PWM_DIV_NUM_VAL         0x10

static uintptr_t g_pwm_base_addr =  (uintptr_t)PWM_BASE_ADDR;

uintptr_t pwm_porting_base_addr_get(void)
{
    return g_pwm_base_addr;
}

static int pwm_handler(int a, const void *tmp)
{
    unused(a);
    unused(tmp);
    hal_pwm_v151_irq_handler();
    return 0;
}

void pwm_port_register_hal_funcs(void)
{
    hal_pwm_register_funcs(hal_pwm_v151_funcs_get());
}

void pwm_port_unregister_hal_funcs(void)
{
    hal_pwm_unregister_funcs();
}

void pwm_port_register_irq(pwm_channel_t channel)
{
    unused(channel);
    osal_irq_request((uintptr_t)PWM_ABNOR_IRQN, (osal_irq_handler)pwm_handler, NULL, NULL, NULL);
    osal_irq_request((uintptr_t)PWM_CFG_IRQN, (osal_irq_handler)pwm_handler, NULL, NULL, NULL);
    osal_irq_enable((uintptr_t)PWM_ABNOR_IRQN);
    osal_irq_enable((uintptr_t)PWM_CFG_IRQN);
}

void pwm_port_unregister_irq(pwm_channel_t channel)
{
    unused(channel);
    osal_irq_disable((uintptr_t)PWM_ABNOR_IRQN);
    osal_irq_disable((uintptr_t)PWM_CFG_IRQN);
    osal_irq_free((uintptr_t)PWM_ABNOR_IRQN, NULL);
    osal_irq_free((uintptr_t)PWM_CFG_IRQN, NULL);
}

void pwm_irq_lock(uint8_t channel)
{
    unused(channel);
    osal_irq_lock();
}

void pwm_irq_unlock(uint8_t channel)
{
    unused(channel);
    osal_irq_unlock();
}

void pwm_port_clock_enable(bool on)
{
    if (on) {
        reg16_setbit(M_CTL_RB_M_CLKEN0, PWM_CLKEN0_OFFSET);
        reg16_setbit(M_CTL_RB_PWM_M_DIV3, PWM_DIV_EN_OFFSET);
        reg16_clrbit(M_CTL_RB_PWM_M_DIV3, PWM_LOAD_DIV_EN_OFFSET);
        reg16_setbits(M_CTL_RB_PWM_M_DIV3, PWM_DIV_NUM_OFFSET, PWM_DIV_NUM_LEN, PWM_DIV_NUM_VAL);
        reg16_setbit(M_CTL_RB_PWM_M_DIV3, PWM_LOAD_DIV_EN_OFFSET);
    } else {
        reg16_clrbit(M_CTL_RB_M_CLKEN0, PWM_CLKEN0_OFFSET);
        writew(M_CTL_RB_PWM_M_DIV3, PWM_DIV_CLOSE);
    }
}

uint32_t pwm_port_get_clock_value(pwm_channel_t channel)
{
    if (channel >= CONFIG_PWM_CHANNEL_NUM) {
        return 0;
    }
    return BUS_CLOCK_TIME_32M;
}

errcode_t pwm_port_param_check(const pwm_config_t *cfg)
{
    if ((cfg->low_time + cfg->high_time > BIT_WIDTH_LIMIT) || (cfg->offset_time > cfg->low_time)) {
        return ERRCODE_PWM_INVALID_PARAMETER;
    }
    return ERRCODE_SUCC;
}