/*
 * Copyright (c) HiSilicon (Shanghai) Technologies Co., Ltd. 2023-2023. All rights reserved.
 * Description: nonos_isr for ccore
 */

#ifndef NONOS_ISR_H
#define NONOS_ISR_H

#include <bits/alltypes.h>

#ifdef __cplusplus
#if __cplusplus
extern "C" {
#endif /* __cplusplus */
#endif /* __cplusplus */

typedef void (*isr_function)(void);
uint32_t int_set_irq_func(uint32_t irq_num, isr_function callback);
uint32_t hal_register_nmi_irq(void);
#ifdef __cplusplus
#if __cplusplus
extern "C" {
#endif /* __cplusplus */
#endif /* __cplusplus */

#endif