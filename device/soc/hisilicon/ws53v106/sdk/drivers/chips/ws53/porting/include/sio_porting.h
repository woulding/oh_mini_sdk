/*
 * Copyright (c) HiSilicon (Shanghai) Technologies Co., Ltd. 2020-2023. All rights reserved.
 * Description: I2S port for project
 *
 * Create: 2020-05-15
 */

#ifndef SIO_PORTING_H
#define SIO_PORTING_H

#include <stdint.h>
#include <stdbool.h>
#include "chip_io.h"
#include "product.h"
#include "platform_core.h"

#ifdef __cplusplus
#if __cplusplus
extern "C" {
#endif /* __cplusplus */
#endif /* __cplusplus */

/**
 * @defgroup drivers_port_sio SIO
 * @ingroup  drivers_port
 * @{
 */
#define I2S_S_CLK                       32000
#define M_CLKEN0                        0x40
#define I2S_CLKEN_BIT                   2
#define I2S_DUTY_CYCLE                  2
#define I2S_PARAM                       2
#define I2S_MCLK_DIV                    1
#define FREQ_OF_NEED                    25
#define CONFIG_DATA_LEN_MAX             8
#define CMU_DIV_AD_RSTN_SYNC_BIT        0

/**
 * @brief  Definition of the contorl ID of hal sio.
 */

typedef void (*i2s_irq_func_t)(void);

/**
 * @if Eng
 * @brief  Get the base address of a specified sio.
 * @param  [in]  bus The sio bus. see @ref sio_bus_t.
 * @return The base address of specified sio.
 * @else
 * @brief  获取指定SIO的基地址。
 * @return 指定SIO的基地址。
 * @endif
 */
uintptr_t sio_porting_base_addr_get(sio_bus_t bus);

/**
 * @if Eng
 * @brief  Register hal funcs objects into hal_sio module.
 * @param  [in]  bus The sio bus. see @ref sio_bus_t.
 * @else
 * @brief  将hal funcs对象注册到hal_sio模块中。
 * @endif
 */
void sio_porting_register_hal_funcs(sio_bus_t bus);

/**
 * @if Eng
 * @brief  Unregister hal funcs objects from hal_sio module.
 * @param  [in]  bus The sio bus. see @ref sio_bus_t.
 * @else
 * @brief  从hal_sio模块注销hal funcs对象。
 * @endif
 */
void sio_porting_unregister_hal_funcs(sio_bus_t bus);

/**
 * @if Eng
 * @brief  Register the interrupt of sio.
 * @param  [in]  bus The sio bus. see @ref sio_bus_t.
 * @else
 * @brief  注册sio中断。
 * @endif
 */
void sio_porting_register_irq(sio_bus_t bus);

/**
 * @if Eng
 * @brief  Unregister the interrupt of sio.
 * @param  [in]  bus The sio bus. see @ref sio_bus_t.
 * @else
 * @brief  注销sio中断。
 * @endif
 */
void sio_porting_unregister_irq(sio_bus_t bus);

/**
 * @if Eng
 * @brief  The interrupt handler of sio0.
 * @else
 * @brief  sio0中断处理。
 * @endif
 */
void irq_sio0_handler(void);

/**
 * @if Eng
 * @brief  SIO clock.
 * @param  [in]  enable Enable or not.
 * @else
 * @brief  sio时钟使能。
 * @endif
 */
void sio_porting_clock_enable(bool enable);

/**
 * @if Eng
 * @brief  Get the BCLK Div number.
 * @param  [in]  data_width sio data width.
 * @param  [in]  ch sio transmission Channels Number.
 * @return The BCLK Div number.
 * @else
 * @brief  获取sio bclk分频器的分频系数。
 * @endif
 */
uint32_t sio_porting_get_bclk_div_num(uint8_t data_width, uint32_t ch);

/**
 * @brief  Init i2s pin for test.
 */
void sio_porting_i2s_pinmux(void);

uintptr_t i2s_porting_tx_left_data_addr_get(sio_bus_t bus);

uintptr_t i2s_porting_tx_merge_data_addr_get(sio_bus_t bus);

uintptr_t i2s_porting_rx_merge_data_addr_get(sio_bus_t bus);

uintptr_t i2s_porting_tx_right_data_addr_get(sio_bus_t bus);

uintptr_t i2s_porting_rx_left_data_addr_get(sio_bus_t bus);

uintptr_t i2s_porting_rx_right_data_addr_get(sio_bus_t bus);

#if defined(CONFIG_I2S_SUPPORT_DMA)
uint32_t i2s_port_get_dma_trans_src_handshaking(sio_bus_t bus);

uint32_t i2s_port_get_dma_trans_dest_handshaking(sio_bus_t bus);
#endif

/**
 * @}
 */

#ifdef __cplusplus
#if __cplusplus
}
#endif /* __cplusplus */
#endif /* __cplusplus */

#endif