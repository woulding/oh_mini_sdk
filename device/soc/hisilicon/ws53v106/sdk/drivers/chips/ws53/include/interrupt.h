/*
 * Copyright (c) HiSilicon (Shanghai) Technologies Co., Ltd. 2021-2021. All rights reserved.
 * Description:  Interrupt DRIVER
 *
 * Create:  2021-06-30
 */
#ifndef INTERRUPT_H
#define INTERRUPT_H

#include "arch_port.h"
#ifdef __cplusplus
#if __cplusplus
extern "C" {
#endif /* __cplusplus */
#endif /* __cplusplus */

/**
 * @brief  interupt callback function declaration.
 */
typedef void (*isr_function)(void);

/**
 * @brief  Set interupt callback function
 * @param  irq_id External interrupt number.
 * @param  func Interupt callback function
 * @return Success or fail.
 */
uint32_t int_set_irq_func(uint32_t irq_num, isr_function callback);

/**
 * @brief  Enable external interrupt.
 * @param  irq_id External interrupt number.
 */
void int_enable_irq(uint32_t irq_id);

/**
 * @brief  Disable external interrupt.
 * @param  irq_id External interrupt number.
 */
void int_disable_irq(uint32_t irq_id);

/**
 * @brief  Get interrupt enable status
 * @param  irq_id External interrupt number.
 * @return Returns a device specific interrupt enable status from the interrupt controller.
 */
uint32_t int_get_enable_irq(uint32_t irq_id);

/**
 * @brief  Clear pending interrupt
 * @param  irq_id External interrupt number.
 */
void int_clear_pending_irq(uint32_t irq_id);

/**
 * @brief  Set interrupt priority
 * @param  irq_id External interrupt number.
 * @param  priority Priority to set.
 */
void int_set_priority(uint32_t irq_id, uint32_t priority);

/**
 * @brief  Get interrupt priority.
 * @param  irq_id External interrupt number.
 * @return Interrupt priority.
 */
uint32_t int_get_priority(uint32_t irq_id);

/**
 * @brief  Setup the interrupt for current core.
 */
void int_setup(void);

/**
 * @brief  Checks if we are currently in interrupt context.
 * @return If we are in interrupt context this will return true, false otherwise.
 */
bool int_is_interrupt_context(void);

/**
 * @brief  Gets the current IRQ that we are in.
 * @return The irq number.
 */
uint32_t int_get_current_irqn(void);

/**
 * @brief  Gets the current interrupt priority level.
 * @return The current interrupt priority level.
 */
uint32_t int_get_current_priority(void);

/**
 * @brief  Get interrupt number.
 * @return Interrupt number.
 */
uint32_t interrupt_number_get(void);
#ifdef __cplusplus
#if __cplusplus
}
#endif /* __cplusplus */
#endif /* __cplusplus */

#endif
