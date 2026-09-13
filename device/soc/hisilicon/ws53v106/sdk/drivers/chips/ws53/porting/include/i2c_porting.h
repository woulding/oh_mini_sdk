/**
 * Copyright (c) HiSilicon (Shanghai) Technologies Co., Ltd. 2022-2022. All rights reserved.
 *
 * Description: Provides i2c port template \n
 *
 * History: \n
 * 2022-08-15， Create file. \n
 */
#ifndef I2C_PORTING_H
#define I2C_PORTING_H

#include <stdint.h>
#include <stdbool.h>
#include "platform_core.h"

#ifdef __cplusplus
#if __cplusplus
extern "C" {
#endif /* __cplusplus */
#endif /* __cplusplus */

/**
 * @defgroup drivers_port_i2c_v151 I2C porting info.
 * @ingroup  drivers_port_i2c
 * @{
 */

#define CONFIG_I2C_TX_BUFFER_DEPTH 8
#define CONFIG_I2C_RX_BUFFER_DEPTH 8

#define I2C_BUS_MAX_NUM I2C_BUS_MAX_NUMBER

#define I2C_1_SCL_PIN                 S_MGPIO0
#define I2C_1_SDA_PIN                 S_MGPIO1
#define I2C_2_SCL_PIN                 S_AGPIO2
#define I2C_2_SDA_PIN                 S_AGPIO3

/**
 * @brief  Base address list for all of the IPs.
 */
extern uintptr_t g_i2c_base_addrs[I2C_BUS_MAX_NUM];

/**
 * @brief  Get the bus clock of specified i2c.
 * @param  [in]  bus The I2C bus. see @ref i2c_bus_t
 * @return The bus clock of specified I2C.
 */
uint32_t i2c_port_get_clock_value(i2c_bus_t bus);

/**
 * @brief  Register the interrupt of I2C.
 */
void i2c_port_register_irq(i2c_bus_t bus);

/**
 * @brief  Unregister the interrupt of I2C.
 */
void i2c_port_unregister_irq(i2c_bus_t bus);

/**
 * @brief  I2C lock.
 * @param [in]  bus The bus index of I2C.
 * @return The irq lock number of I2C.
 */
uint32_t i2c_porting_lock(i2c_bus_t bus);

/**
 * @brief  I2C unlock.
 * @param [in]  bus The bus index of I2C.
 * @param [in]  irq_sts The irq lock number of I2C.
 */
void i2c_porting_unlock(i2c_bus_t bus, uint32_t irq_sts);

#ifdef TEST_SUITE
/**
 * @brief  Init i2c pin for test.
 */
void i2c_port_test_i2c_init_pin(void);
#endif

void i2c_port_clock_enable(i2c_bus_t bus, bool flag);
/**
 * @}
 */
#if defined(CONFIG_I2C_SUPPORT_DMA) && (CONFIG_I2C_SUPPORT_DMA == 1)
/**
 * @brief  Get I2C dma transfer mode dest handshaking channel.
 * @param  [in]  bus The bus index of I2C.
 * @return The dest handshaking channel number of I2C.
 */
uint8_t i2c_port_get_dma_trans_dest_handshaking(i2c_bus_t bus);

/**
 * @brief  Get I2C dma transfer mode src handshaking channel.
 * @param  [in]  bus The bus index of I2C.
 * @return The src handshaking channel number of I2C.
 */
uint8_t i2c_port_get_dma_trans_src_handshaking(i2c_bus_t bus);
#endif
#ifdef __cplusplus
#if __cplusplus
}
#endif /* __cplusplus */
#endif /* __cplusplus */

#endif
