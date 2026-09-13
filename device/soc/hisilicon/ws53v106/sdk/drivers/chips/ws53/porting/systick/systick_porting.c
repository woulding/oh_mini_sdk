/**
 * Copyright (c) HiSilicon (Shanghai) Technologies Co., Ltd. 2022-2023. All rights reserved.
 *
 * Description: Provides systick porting template \n
 *
 * History: \n
 * 2022-08-01， Create file. \n
 */
#include "hal_systick_v150.h"
#include "platform_core.h"
#include "systick_porting.h"

static uintptr_t const g_systick_base_addr =  (uintptr_t)SYSTICK_BASE_ADDR;

static uint64_t g_systick_ticks_per_sec = HAL_SYSTICK_TICKS_PER_SEC_DEFAULT;

uintptr_t systick_porting_base_addr_get(void)
{
    return g_systick_base_addr;
}

void systick_port_cali_xclk(void)
{
}

uint64_t systick_porting_ticks_per_sec_get(void)
{
    return g_systick_ticks_per_sec;
}

void systick_porting_ticks_per_sec_set(uint64_t ticks)
{
    g_systick_ticks_per_sec = ticks;
}
