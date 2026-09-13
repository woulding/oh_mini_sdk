/*
 * Copyright (c) HiSilicon (Shanghai) Technologies Co., Ltd. 2021-2021. All rights reserved.
 * Description: delay
 *
 * Create: 2021-03-09
 */

#include "boot_def.h"
#include "tcxo.h"

void delay_init(void)
{
    (void) uapi_tcxo_init();
}

void udelay(uint32_t us)
{
    (void) uapi_tcxo_delay_us(us);
}

void mdelay(uint32_t ms)
{
    (void) uapi_tcxo_delay_ms(ms);
}
