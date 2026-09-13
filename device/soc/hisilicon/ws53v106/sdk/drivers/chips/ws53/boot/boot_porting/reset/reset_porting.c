/*
 * Copyright (c) HiSilicon (Shanghai) Technologies Co., Ltd. 2023-2023. All rights reserved.
 * Description: reset
 *
 * Create: 2023-04-20
 */
#include "efuse_wrap.h"
#include "boot_init.h"
#include "watchdog.h"
#include "chip_io.h"
#include "boot_serial.h"
#include "tcxo.h"

#define SYS_SLP_ACK_FRC_ON 0x570048f0
#define LPM_MCU_ALW_TO_SLP 0x57004200
static void switch_to_wfi(void)
{
    reg_setbit(SYS_SLP_ACK_FRC_ON, 0, 1);
    reg_setbit(LPM_MCU_ALW_TO_SLP, 0, 0);
    __asm__ __volatile__("wfi;");
}

static uint8_t get_reset_count(void)
{
    gp_reg1_union gp;
    gp.u16 = (uint16_t)readl(RESET_COUNT_REG);
    return gp.bits.reset_cnt;
}

void set_reset_count(uint8_t cnt)
{
    gp_reg1_union gp;
    gp.u16 = (uint16_t)readl(RESET_COUNT_REG);
    gp.bits.reset_cnt = cnt & 0xF;
    writel(RESET_COUNT_REG, gp.u16);
}

void update_reset_count(void)
{
    uint8_t reset_cnt = get_reset_count();
    boot_msg1("update_reset_count ", reset_cnt + 1);
    uapi_tcxo_delay_ms(RESET_DELAY_MS);
    if (reset_cnt < REBOOT_MAX_CNT) {
        set_reset_count(reset_cnt + 1);
        return;
    }
    uapi_watchdog_disable();
    switch_to_wfi();
    for (;;) {
    }
}
