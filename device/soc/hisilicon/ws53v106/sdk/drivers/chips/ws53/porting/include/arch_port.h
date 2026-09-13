/*
 * Copyright (c) HiSilicon (Shanghai) Technologies Co., Ltd. 2021-2021. All rights reserved.
 * Description: ARCH interface for project
 *
 * Create:  2021-07-06
 */
#ifndef ARCH_PORT_H
#define ARCH_PORT_H

#include <stdint.h>
#include <stdbool.h>
#include "chip_core_irq.h"
#include "memory_config.h"

#ifdef __cplusplus
#if __cplusplus
extern "C" {
#endif /* __cplusplus */
#endif /* __cplusplus */

#ifdef USE_CMSIS_OS
#define irq_prio(irq_id) int_get_maucintpri()[irq_id]
#else
#define irq_prio(irq_id) int_get_aucintpri()[irq_id]
#endif

uint8_t *int_get_aucintpri(void);
uint8_t *int_get_maucintpri(void);

extern uint8_t m_aucIntPri[BUTT_IRQN];
extern uint8_t g_aucIntPri[BUTT_IRQN];
#ifdef __cplusplus
#if __cplusplus
}
#endif /* __cplusplus */
#endif /* __cplusplus */

#endif
