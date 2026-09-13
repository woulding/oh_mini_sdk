/**
 * Copyright (c) HiSilicon (Shanghai) Technologies Co., Ltd. 2024-2024. All rights reserved.
 *
 * Description: Provides v151_100 spi register operation api \n
 */
#ifdef CONFIG_DRIVER_SUPPORT_SPI
#include <stdint.h>
#include "common_def.h"
#include "hal_qspi_v151_100_regs_op.h"
#include "hal_spi_v151_100_regs_op.h"

volatile uint32_t *hal_spi_v151_100_int_set_reg(spi_bus_t bus, spi_v151_100_int_reg_t reg)
{
    volatile uint32_t *reg_addr = NULL;
    switch (reg) {
        case SPI_INMAR_REG:
            if (bus <= SPI_BUS_MAX) {
                reg_addr = &spis_v151_100_regs(bus)->spi_inmar;
            } else {
                reg_addr = &qspis_v151_100_regs(bus)->imr;
            }
            break;
        default:
            break;
    }
    return reg_addr;
}

volatile uint32_t *hal_spi_v151_100_int_get_reg(spi_bus_t bus, spi_v151_100_int_reg_t reg)
{
    volatile uint32_t *reg_addr = NULL;

    if (bus <= SPI_BUS_MAX) {
        switch (reg) {
            case SPI_INMAR_REG:
                reg_addr = &spis_v151_100_regs(bus)->spi_inmar;
                break;
            case SPI_INSR_REG:
                reg_addr = &spis_v151_100_regs(bus)->spi_insr;
                break;
            case SPI_RAINSR_REG:
                reg_addr = &spis_v151_100_regs(bus)->spi_rainsr;
                break;
        }
    } else {
        switch (reg) {
            case SPI_INMAR_REG:
                reg_addr = &qspis_v151_100_regs(bus)->imr;
                break;
            case SPI_INSR_REG:
                reg_addr = &qspis_v151_100_regs(bus)->isr;
                break;
            case SPI_RAINSR_REG:
                reg_addr = &qspis_v151_100_regs(bus)->risr;
                break;
        }
    }
    return reg_addr;
}
#endif // CONFIG_DRIVER_SUPPORT_SPI