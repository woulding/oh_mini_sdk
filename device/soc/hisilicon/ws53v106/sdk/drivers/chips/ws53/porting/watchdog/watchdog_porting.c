/**
 * Copyright (c) HiSilicon (Shanghai) Technologies Co., Ltd. 2022-2023. All rights reserved.
 *
 * Description: Provides watchdog port template \n
 *
 * History: \n
 * 2022-06-06， Create file. \n
 */
#include "watchdog.h"
#include "tcxo.h"
#include "platform_core.h"
#include "debug_print.h"
#include "non_os.h"
#include "chip_io.h"
#include "hal_watchdog_v151.h"
#include "soc_osal.h"
#include "watchdog_porting.h"

#define PARAM       0
#define WAIT_APPS_DUMP_DSP_DELAY_MS  15000
#define WDT_PORTING_ENABLE_DELAY     60uLL
#define DEFAULT_WDT_TIME             8

uintptr_t g_watchdog_base_addr = (uintptr_t)CHIP_WDT_BASE_ADDRESS;
static uint32_t g_watchdog_config = DEFAULT_WDT_TIME;
static uint32_t g_watchdog_clock = CONFIG_WDT_CLOCK;

void watchdog_port_register_hal_funcs(void)
{
    hal_watchdog_register_funcs(hal_watchdog_v151_funcs_get());
}

void watchdog_port_unregister_hal_funcs(void)
{
    hal_watchdog_unregister_funcs();
}

void watchdog_port_register_irq(void)
{
    return;
}

void irq_wdt_handler(void)
{
    hal_watchdog_v151_irq_handler((uintptr_t)PARAM);
}

/* ------------------------------------------------------------------------------*/
/* The following is the product adaptation section. */
/* ------------------------------------------------------------------------------*/


void watchdog_func_adapt(uint32_t time)
{
    non_os_nmi_config(NMI_CWDT, true);
    watchdog_set_configtime(time);
}

void watchdog_turnon_clk(void)
{
    reg_setbit(HAL_SOFT_RST_CTL_BASE, HAL_GLB_CTL_M_ATOP1_L_REG_OFFSET, HAL_CHIP_WDT_ATOP1_RST_BIT);
    uapi_tcxo_delay_us(WDT_PORTING_ENABLE_DELAY);
}

void watchdog_turnoff_clk(void)
{
    reg_clrbit(HAL_SOFT_RST_CTL_BASE, HAL_GLB_CTL_M_ATOP1_L_REG_OFFSET, HAL_CHIP_WDT_ATOP1_RST_BIT);
}

void watchdog_set_configtime(uint32_t time)
{
    g_watchdog_config = time;
}

uint32_t watchdog_get_configtime(void)
{
    return g_watchdog_config;
}

void watchdog_port_set_clock(uint32_t wdt_clock)
{
    uint32_t irq_sts = osal_irq_lock();
    g_watchdog_clock = wdt_clock;
    osal_irq_restore(irq_sts);
}

uint32_t watchdog_port_get_clock(void)
{
    return g_watchdog_clock;
}