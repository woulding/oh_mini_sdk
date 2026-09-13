/**
 * Copyright (c) HiSilicon (Shanghai) Technologies Co., Ltd. 2022-2022. All rights reserved.
 *
 * Description: Provides sfc port template \n
 *
 * History: \n
 * 2022-11-30， Create file. \n
 */

#include "common_def.h"
#include "errcode.h"
#include "platform_core.h"
#ifndef BUILD_NOOSAL
#include "soc_osal.h"
#endif
#ifdef CONFIG_DRIVER_SUPPORT_SFC
#include "hal_sfc_v150.h"
#endif
#include "sfc_porting.h"

#define SFC_REG_BASE_ADDR   0x53000000

#define SFC_DELAY_ONCE_US   100

#ifdef CONFIG_LOADERBOOT
#define SFC_DELAY_TIMES     410000
#else
#define SFC_DELAY_TIMES     50000
#endif

static uintptr_t g_sfc_start_addr = (uintptr_t)SFC_FLASH_START_ADDR;

static uintptr_t g_sfc_end_addr = (uintptr_t)SFC_FLASH_END_ADDR;

static uintptr_t g_sfc_global_conf_base_addr = SFC_REG_BASE_ADDR + 0x100;

static uintptr_t g_sfc_bus_regs_base_addr = SFC_REG_BASE_ADDR + 0x200;

static uintptr_t g_sfc_bus_dma_regs_base_addr = SFC_REG_BASE_ADDR + 0x240;

static uintptr_t g_sfc_cmd_regs_base_addr = SFC_REG_BASE_ADDR + 0x300;

static uintptr_t g_sfc_cmd_databuf_base_addr = SFC_REG_BASE_ADDR + 0x400;

uint32_t g_sfc_delay_once_us = SFC_DELAY_ONCE_US;

uint32_t g_sfc_delay_times = SFC_DELAY_TIMES;

#ifndef BUILD_NOOSAL
osal_mutex g_sfc_mutex = {NULL};

bool g_sfc_mutex_inited = false;
#endif

uintptr_t sfc_port_get_sfc_start_addr(void)
{
    return g_sfc_start_addr;
}

uintptr_t sfc_port_get_sfc_end_addr(void)
{
    return g_sfc_end_addr;
}

uintptr_t sfc_port_get_sfc_global_conf_base_addr(void)
{
    return g_sfc_global_conf_base_addr;
}

uintptr_t sfc_port_get_sfc_bus_regs_base_addr(void)
{
    return g_sfc_bus_regs_base_addr;
}

uintptr_t sfc_port_get_sfc_bus_dma_regs_base_addr(void)
{
    return g_sfc_bus_dma_regs_base_addr;
}

uintptr_t sfc_port_get_sfc_cmd_regs_base_addr(void)
{
    return g_sfc_cmd_regs_base_addr;
}

uintptr_t sfc_port_get_sfc_cmd_databuf_base_addr(void)
{
    return g_sfc_cmd_databuf_base_addr;
}

void sfc_port_set_delay_once_time(uint32_t delay_us)
{
    g_sfc_delay_once_us = delay_us;
}

uint32_t sfc_port_get_delay_once_time(void)
{
    return g_sfc_delay_once_us;
}

void sfc_port_set_delay_times(uint32_t delay_times)
{
    g_sfc_delay_times = delay_times;
}

uint32_t sfc_port_get_delay_times(void)
{
    return g_sfc_delay_times;
}

void sfc_port_lock_init(void)
{
#ifndef BUILD_NOOSAL
    if (!g_sfc_mutex_inited) {
        osal_mutex_init(&g_sfc_mutex);
        g_sfc_mutex_inited = true;
    }
#endif
    sfc_port_fix_protect_cfg();
}

uint32_t sfc_port_lock(void)
{
#ifndef BUILD_NOOSAL
    uint32_t lock_sts = osal_irq_lock();
    return lock_sts;
#else
    return 0;
#endif
}

void sfc_port_unlock(uint32_t lock_sts)
{
#ifndef BUILD_NOOSAL
    osal_irq_restore(lock_sts);
#else
    unused(lock_sts);
#endif
}
