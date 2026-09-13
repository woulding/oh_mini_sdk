/*
 * Copyright (c) HiSilicon (Shanghai) Technologies Co., Ltd. 2021-2021. All rights reserved.
 * Description: Low power management interface.
 * Author:
 * Create:  2021-5-25
 */


#include "panic.h"
#include "hal_pmu_ldo.h"
#include "securec.h"
#include "hal_clocks_application.h"
#include "hal_pmu_peripheral_application.h"
#include "hal_clocks.h"
#include "clocks_core.h"
#include "low_power_management.h"

static hal_pmu_mcpu_perips_type_t const g_i2c_mcpu_perips_type[I2C_BUS_MAX_NUMBER] = {
    HAL_PMU_MCPU_PERIP_I2C_BUS_0,
    HAL_PMU_MCPU_PERIP_I2C_BUS_1,
#if I2C_BUS_MAX_NUMBER > 2
    HAL_PMU_MCPU_PERIP_I2C_BUS_2,
#endif
#if I2C_BUS_MAX_NUMBER > 3
    HAL_PMU_MCPU_PERIP_I2C_BUS_3,
#endif
#if I2C_BUS_MAX_NUMBER > 4
    HAL_PMU_MCPU_PERIP_I2C_BUS_4,
#endif
#if I2C_BUS_MAX_NUMBER > 5
    HAL_PMU_MCPU_PERIP_I2C_BUS_5,
#endif
#if I2C_BUS_MAX_NUMBER > 6
    HAL_PMU_MCPU_PERIP_I2C_BUS_6,
#endif
};

int lpm_capsensor_power_config(bool on)
{
    hal_ulp_bbldo2_enable(on);
    return LPM_RET_OK;
}

int lpm_capsensor_power_status(void)
{
    if (hal_ulp_bbldo2_power_status()) {
        return LPM_RET_ON;
    } else {
        return LPM_RET_OFF;
    }
}

static bool lpm_capsensor_init(void)
{
    lpm_dev_ops_t ops;
    if (memset_s(&ops, sizeof(lpm_dev_ops_t), 0, sizeof(lpm_dev_ops_t)) != EOK) {
        return false;
    }
    ops.power_on = lpm_capsensor_power_config;
    ops.power_sts = lpm_capsensor_power_status;
    lpm_dev_ops_register(DEV_CAP, &ops);
    return true;
}

int lpm_adc_power_config(bool on)
{
    hal_pmu_auxldo_enable(on);
    return LPM_RET_OK;
}

int lpm_adc_power_status(void)
{
    if (hal_pmu_auxldo_power_status()) {
        return LPM_RET_ON;
    } else {
        return LPM_RET_OFF;
    }
}

int lpm_adc_clock_config(bool on)
{
    hal_clocks_mcrg_aux_adc_clk_en((switch_type_t)on);
    return LPM_RET_OK;
}

int lpm_adc_clock_status(void)
{
    if (hal_clocks_mcrg_aux_adc_clk_sts()) {
        return LPM_RET_ON;
    } else {
        return LPM_RET_OFF;
    }
}

int lpm_pwm_clock_status(void)
{
#if CHIP_LIBRA || CHIP_SOCMN1
    if (hal_clocks_app_perips_get_config(HAL_CLOCKS_APP_PWM_CLK)) {
        return LPM_RET_ON;
    }
#endif
    return LPM_RET_OFF;
}

int lpm_adc_set_div_num(int clk_div)
{
    hal_clocks_mcrg_aux_adc_div_set((uint8_t)clk_div);
    return LPM_RET_OK;
}

int lpm_adc_get_div_num(void)
{
    return (int)hal_clocks_mcrg_aux_adc_div_get();
}

static bool lpm_adc_init(void)
{
    lpm_dev_ops_t ops;
    if (memset_s(&ops, sizeof(lpm_dev_ops_t), 0, sizeof(lpm_dev_ops_t)) != EOK) {
        return false;
    }
    ops.power_on = lpm_adc_power_config;
    ops.power_sts = lpm_adc_power_status;
    ops.clock_en = lpm_adc_clock_config;
    ops.clock_sts = lpm_adc_clock_status;
    ops.set_div_num = lpm_adc_set_div_num;
    ops.get_div_num = lpm_adc_get_div_num;
    lpm_dev_ops_register(DEV_ADC, &ops);
    return true;
}

static int lpm_i2c_sub_bus_clken(int bus, bool en)
{
    hal_pmu_perip_request_type_t type = HAL_PMU_PERIP_REQUEST_ENTER_LOW_POWER;
    if (en) {
        type = HAL_PMU_PERIP_REQUEST_EXIT_LOW_POWER;
    }
    if (bus >= I2C_BUS_MAX_NUMBER) {
        return LPM_RET_ERR;
    }
    hal_pmu_mcpu_perip_config(g_i2c_mcpu_perips_type[bus], type);
    return LPM_RET_OK;
}

static bool lpm_i2c_init(void)
{
    lpm_dev_ops_t ops;
    if (memset_s(&ops, sizeof(lpm_dev_ops_t), 0, sizeof(lpm_dev_ops_t)) != EOK) {
        return false;
    }
    ops.sub_clken = lpm_i2c_sub_bus_clken;
    lpm_dev_ops_register(DEV_I2C, &ops);
    return true;
}

static int lpm_spi_sub_bus_clken(int bus, bool en)
{
    hal_pmu_perip_request_type_t type = HAL_PMU_PERIP_REQUEST_ENTER_LOW_POWER;
    if (en) {
        type = HAL_PMU_PERIP_REQUEST_EXIT_LOW_POWER;
    }

    switch (bus) {
        case SPI_BUS_0:
            hal_pmu_mcpu_perip_config(HAL_PMU_MCPU_PERIP_SPI_MST, type);
            break;
        case SPI_BUS_1:
            hal_pmu_mcpu_perip_config(HAL_PMU_MCPU_PERIP_SPI_MS_0, type);
            break;
        case SPI_BUS_2:
            hal_pmu_mcpu_perip_config(HAL_PMU_MCPU_PERIP_SPI_MS_1, type);
            break;
#if CHIP_SOCMN1
        case SPI_BUS_3:
            /* SPI_BUS_3: QSPI_0 for xip, can't enter low power */
            break;
#endif
#if CHIP_LIBRA
        case SPI_BUS_3:
            hal_pmu_mcpu_perip_config(HAL_PMU_MCPU_PERIP_SPI_M3, type);
            break;
#endif
        case SPI_BUS_4:
            hal_pmu_mem_perip_config(HAL_PMU_MEM_PERIP_QSPI1_2CS, type);
            break;
        case SPI_BUS_5:
            hal_pmu_mcpu_perip_config(HAL_PMU_MCPU_PERIP_QSPI2_1CS, type);
            break;
#if CHIP_LIBRA
        case SPI_BUS_6:
            hal_pmu_mem_perip_config(HAL_PMU_MEM_PERIP_QSPI3_2CS, type);
            break;
#endif
#if CHIP_SOCMN1
        case SPI_BUS_6:
            hal_pmu_mem_perip_config(HAL_PMU_MEM_PERIP_OPI, type);
            break;
#endif
        default:
            return LPM_RET_ERR;
    }
    return LPM_RET_OK;
}

static int lpm_spi_get_freq(void)
{
    return (int)clocks_get_spi_clock_value();
}

static bool lpm_spi_init(void)
{
    lpm_dev_ops_t ops;
    if (memset_s(&ops, sizeof(lpm_dev_ops_t), 0, sizeof(lpm_dev_ops_t)) != EOK) {
        return false;
    }
    ops.sub_clken = lpm_spi_sub_bus_clken;
    ops.get_freq = lpm_spi_get_freq;
    lpm_dev_ops_register(DEV_SPI, &ops);
    return true;
}

static int lpm_qspi_get_freq(void)
{
    return (int)clocks_get_xip_clock_value();
}

static bool lpm_qspi_init(void)
{
    lpm_dev_ops_t ops;
    if (memset_s(&ops, sizeof(lpm_dev_ops_t), 0, sizeof(lpm_dev_ops_t)) != EOK) {
        return false;
    }
    ops.get_freq = lpm_qspi_get_freq;
    lpm_dev_ops_register(DEV_QSPI, &ops);
    return true;
}

static int lpm_uart_sub_bus_clken(int bus, bool en)
{
    hal_pmu_perip_request_type_t type = HAL_PMU_PERIP_REQUEST_ENTER_LOW_POWER;
    if (en) {
        type = HAL_PMU_PERIP_REQUEST_EXIT_LOW_POWER;
    }
    switch (bus) {
        case UART_BUS_0:  // UART L0
            hal_pmu_mcpu_perip_config(HAL_PMU_MCPU_PERIP_UART_L0, type);
            break;
        case UART_BUS_1:  // UART H0
            hal_pmu_mcpu_perip_config(HAL_PMU_MCPU_PERIP_UART_H0, type);
            break;
#if UART_BUS_MAX_NUMBER > 2
        case UART_BUS_2:  // UART H1
            hal_pmu_mcpu_perip_config(HAL_PMU_MCPU_PERIP_UART_H1, type);
            break;
#endif
        default:
            return LPM_RET_ERR;
    }
    return LPM_RET_OK;
}

static bool lpm_uart_init(void)
{
    lpm_dev_ops_t ops;
    if (memset_s(&ops, sizeof(lpm_dev_ops_t), 0, sizeof(lpm_dev_ops_t)) != EOK) {
        return false;
    }
    ops.sub_clken = lpm_uart_sub_bus_clken;
    lpm_dev_ops_register(DEV_UART, &ops);
    return true;
}

static void lpm_display_freq_config(void)
{
#if CHIP_LIBRA
    system_display_set_freq(CLOCKS_DISPLAY_FREQ_2);
#endif
}

static bool lpm_display_init(void)
{
    lpm_display_clocks_init_register_callback(lpm_display_freq_config);
    return true;
}

static int lpm_pwm_clken(bool en)
{
#if CHIP_LIBRA || CHIP_SOCMN1
    hal_clocks_app_perips_config(HAL_CLOCKS_APP_PWM_CLK, (switch_type_t)en);
#else
    UNUSED(en);
#endif
    return LPM_RET_OK;
}

static bool lpm_pwm_init(void)
{
    lpm_dev_ops_t ops;
    if (memset_s(&ops, sizeof(lpm_dev_ops_t), 0, sizeof(lpm_dev_ops_t)) != EOK) {
        return false;
    }
    ops.clock_en = lpm_pwm_clken;
    lpm_dev_ops_register(DEV_PWM, &ops);
    return true;
}

void low_power_management_init(void)
{
    if (!lpm_dev_ops_init()) {
        panic(PANIC_LOW_POWER, __LINE__);
    }
    bool ret = true;
    ret = (ret && lpm_capsensor_init());
    ret = (ret && lpm_adc_init());
    ret = (ret && lpm_i2c_init());
    ret = (ret && lpm_spi_init());
    ret = (ret && lpm_qspi_init());
    ret = (ret && lpm_uart_init());
    ret = (ret && lpm_display_init());
    ret = (ret && lpm_pwm_init());
    if (!ret) {
        panic(PANIC_LOW_POWER, __LINE__);
    }
}
