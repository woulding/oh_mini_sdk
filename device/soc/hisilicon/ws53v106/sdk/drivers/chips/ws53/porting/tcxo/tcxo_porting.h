/**
 * Copyright (c) HiSilicon (Shanghai) Technologies Co., Ltd. 2022-2023. All rights reserved.
 *
 * Description: Provides tcxo port \n
 *
 * History: \n
 * 2022-08-16， Create file. \n
 */

#ifndef TCXO_PORTING_H
#define TCXO_PORTING_H

#include <stdint.h>
#include "platform_core.h"
#if TCXO_CLK_DYN_ADJUST == YES
#include "clocks_core_common.h"
#endif
#ifdef __cplusplus
#if __cplusplus
extern "C" {
#endif /* __cplusplus */
#endif /* __cplusplus */

/**
 * @defgroup drivers_port_tcxo TCXO
 * @ingroup  drivers_port
 * @{
 */

#define MS_PER_S    1000
#define US_PER_MS   1000
#define US_PER_S    (US_PER_MS * MS_PER_S)

#define TCXO_TICKS_PER_U_SECOND_DEFAULT 32
#define TCXO_LOCK_GET_ATTE 0xFFFFFFFF

#if TCXO_CLK_DYN_ADJUST == YES
#define HAL_TCXO_TICKS_PER_SECOND   (get_mcu_core_clk())
#define HAL_TCXO_TICKS_PER_M_SECOND (get_mcu_core_clk() / MS_PER_S)
#define HAL_TCXO_TICKS_PER_U_SECOND (get_mcu_core_clk() / US_PER_S)

#define TCXO_TICKS_PER_M_SECOND     (get_mcu_core_clk() / MS_PER_S)
#define TCXO_TICKS_PER_U_SECOND     (get_mcu_core_clk() / US_PER_S)
#else
#define HAL_TCXO_TICKS_PER_SECOND   (tcxo_porting_ticks_per_usec_get() * US_PER_S)
#define HAL_TCXO_TICKS_PER_M_SECOND (tcxo_porting_ticks_per_usec_get() * US_PER_MS)
#define HAL_TCXO_TICKS_PER_U_SECOND (tcxo_porting_ticks_per_usec_get())

#define TCXO_TICKS_PER_SECOND       (tcxo_porting_ticks_per_usec_get() * US_PER_S)
#define TCXO_TICKS_PER_M_SECOND     (tcxo_porting_ticks_per_usec_get() * US_PER_MS)
#define TCXO_TICKS_PER_U_SECOND     (tcxo_porting_ticks_per_usec_get())
#endif

/**
 * @brief  Get the base address of a specified TCXO.
 * @return The base address of specified TCXO.
 */
uintptr_t tcxo_porting_base_addr_get(void);

/**
 * @brief  get tcxo ticks per microseconds.
 */
uint32_t tcxo_porting_ticks_per_usec_get(void);

/**
 * @brief  set tcxo ticks per microseconds.
 */
void tcxo_porting_ticks_per_usec_set(uint32_t ticks);

/**
 * @}
 */

#ifdef __cplusplus
#if __cplusplus
}
#endif /* __cplusplus */
#endif /* __cplusplus */

#endif
