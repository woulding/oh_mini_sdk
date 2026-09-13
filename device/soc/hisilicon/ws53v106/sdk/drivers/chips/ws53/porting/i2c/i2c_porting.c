/**
 * Copyright (c) HiSilicon (Shanghai) Technologies Co., Ltd. 2022-2022. All rights reserved.
 *
 * Description: Provides i2c port template \n
 *
 * History: \n
 * 2022-08-15， Create file. \n
 */

#include "i2c_porting.h"
#include "hal_i2c.h"
#include "hal_i2c_v151.h"
#include "hal_i2c_v151_comm.h"
#include "osal_interrupt.h"
#include "chip_io.h"
#include "clock_recover.h"
#include "chip_core_irq.h"
#if defined(CONFIG_I2C_SUPPORT_DMA) && (CONFIG_I2C_SUPPORT_DMA == 1)
#include "dma_porting.h"
#endif

#define BUS_CLOCK_TIME_32M 32000000UL
#define I2C0_CLKEN_OFFSET  6
#define I2C1_CLKEN_OFFSET  7

typedef void (*i2c_porting_irq_handler)(void);

typedef struct i2c_irq_handler {
    uint32_t irq_id;
    i2c_porting_irq_handler irq_handler;
} i2c_irq_handler_t;


uintptr_t g_i2c_base_addrs[I2C_BUS_MAX_NUM] = {
    (uintptr_t)I2C_BUS_0_BASE_ADDR,
    (uintptr_t)I2C_BUS_1_BASE_ADDR,
#if I2C_BUS_MAX_NUM > 2
    (uintptr_t)I2C_BUS_2_BASE_ADDR,
#if I2C_BUS_MAX_NUM > 3
    (uintptr_t)I2C_BUS_3_BASE_ADDR,
#endif
#endif
};

static void irq_i2c0_handler(void)
{
    hal_i2c_v151_irq_handler(I2C_BUS_0);
}

static void irq_i2c1_handler(void)
{
    hal_i2c_v151_irq_handler(I2C_BUS_1);
}

#if I2C_BUS_MAX_NUM > 2
static void irq_i2c2_handler(void)
{
    hal_i2c_v151_irq_handler(I2C_BUS_2);
}
#endif

#if I2C_BUS_MAX_NUM > 3
static void irq_i2c3_handler(void)
{
    hal_i2c_v151_irq_handler(I2C_BUS_3);
}
#endif

static i2c_irq_handler_t g_i2c_irq_id[I2C_BUS_MAX_NUM] = {
    {
        I2C_0_IRQN,
        irq_i2c0_handler,
    },
    {
        I2C_1_IRQN,
        irq_i2c1_handler,
    },
#if I2C_BUS_MAX_NUM > 2
    {
        I2C_2_IRQN,
        irq_i2c2_handler,
    },
#if I2C_BUS_MAX_NUM > 3
    {
        I2C_3_IRQN,
        irq_i2c3_handler,
    },
#endif
#endif
};

uint32_t i2c_port_get_clock_value(i2c_bus_t bus)
{
    if (bus >= I2C_BUS_MAX_NUM) {
        return 0;
    }
    return BUS_CLOCK_TIME_32M;
}

void i2c_port_register_irq(i2c_bus_t bus)
{
    i2c_irq_handler_t irq = g_i2c_irq_id[bus];
    osal_irq_request(irq.irq_id, (osal_irq_handler)irq.irq_handler, NULL, NULL, NULL);
    osal_irq_enable(irq.irq_id);
}

void i2c_port_unregister_irq(i2c_bus_t bus)
{
    i2c_irq_handler_t irq = g_i2c_irq_id[bus];
    osal_irq_free(irq.irq_id, NULL);
}

uint32_t i2c_porting_lock(i2c_bus_t bus)
{
    unused(bus);
    return osal_irq_lock();
}

void i2c_porting_unlock(i2c_bus_t bus, uint32_t irq_sts)
{
    unused(bus);
    osal_irq_restore(irq_sts);
}

void i2c_port_clock_enable(i2c_bus_t bus, bool flag)
{
    if (bus == I2C_BUS_0) {
        if (flag) {
            reg16_setbit(M_CTL_RB_M_CLKEN1, I2C0_CLKEN_OFFSET);
        } else {
            reg16_clrbit(M_CTL_RB_M_CLKEN1, I2C0_CLKEN_OFFSET);
        }
    } else if (bus == I2C_BUS_1) {
        if (flag) {
            reg16_setbit(M_CTL_RB_M_CLKEN1, I2C1_CLKEN_OFFSET);
        } else {
            reg16_clrbit(M_CTL_RB_M_CLKEN1, I2C1_CLKEN_OFFSET);
        }
    }
}

#if defined(CONFIG_I2C_SUPPORT_DMA) && (CONFIG_I2C_SUPPORT_DMA == 1)
uint8_t i2c_port_get_dma_trans_dest_handshaking(i2c_bus_t bus)
{
    switch (bus) {
        case I2C_BUS_0:
            return (uint8_t)DMA_HANDSHAKE_I2C_BUS_0_TX;
        case I2C_BUS_1:
            return (uint8_t)DMA_HANDSHAKE_I2C_BUS_1_TX;
        default:
            return (uint8_t)HAL_DMA_HANDSHAKING_MAX_NUM;
    }
}

uint8_t i2c_port_get_dma_trans_src_handshaking(i2c_bus_t bus)
{
    switch (bus) {
        case I2C_BUS_0:
            return (uint8_t)DMA_HANDSHAKE_I2C_BUS_0_RX;
        case I2C_BUS_1:
            return (uint8_t)DMA_HANDSHAKE_I2C_BUS_1_RX;
        default:
            return (uint8_t)HAL_DMA_HANDSHAKING_MAX_NUM;
    }
}
#endif
#ifdef TEST_SUITE
#define I2C_0_SCL_PIN_CTRL_REG 0x52008254
#define I2C_0_SDA_PIN_CTRL_REG 0x52008258
#define I2C_1_SCL_PIN_CTRL_REG 0x5703600c
#define I2C_1_SDA_PIN_CTRL_REG 0x57036010
#define PIN_CTRL_MODE_2 0x3
void i2c_port_test_i2c_init_pin(void)
{
    uapi_reg_write32(I2C_1_SCL_PIN_CTRL_REG, 1);
    uapi_reg_write32(I2C_1_SDA_PIN_CTRL_REG, 1);
    uapi_reg_write32(I2C_0_SCL_PIN_CTRL_REG, PIN_CTRL_MODE_2);
    uapi_reg_write32(I2C_0_SDA_PIN_CTRL_REG, PIN_CTRL_MODE_2);
}
#endif