/*
 * Copyright (c) HiSilicon (Shanghai) Technologies Co., Ltd. 2018-2020. All rights reserved.
 * Description: low power control interface
 * Author:
 * Create:
 */
#ifndef BUILD_APPLICATION_SSB
#include "low_power_control.h"
#endif

#include "chip_io.h"
#include "memory_config.h"

#if (BTH_WITH_SMART_WEAR == YES)
#define PRODUCT_AW_GT_MODE_ADDR        0x87004A10 // save AW&GT mode addr for wear
#define PRODUCT_AW_MODE_FLAG           0xAAAA4157 // save AW&GT mode value for wear
// save board type flag V3 and before V3(12100/12101/12102/12104/12105/12106), when before v3(12103)
#define PRODUCT_BOARD_TYPE_BEFORE_V3   12103 // not V3 board flag
// reuse sys cfg share mem log region, now used 32byte, reserve 8Byte for it
#define PRODUCT_BOARD_TYPE_ADDR_SHM    (SYSTEM_CFG_REGION_START + 40)
#endif

bool remote_command_low_power_control(cores_t core, uint8_t type)
{
    UNUSED(core);
    UNUSED(type);
    return true;
}

bool low_power_codec_is_poweron(void)
{
    // Need add code
    return false;
}

#if (BTH_WITH_SMART_WEAR == YES)
product_mode_e get_aw_gt_mode(void)
{
    if (readl(PRODUCT_AW_GT_MODE_ADDR) == PRODUCT_AW_MODE_FLAG) {
        return PRODUCT_AW_MODE;
    } else {
        return PRODUCT_GT_MODE;
    }
}

board_type_e get_board_type(void)
{
    if (readl(PRODUCT_BOARD_TYPE_ADDR_SHM) == PRODUCT_BOARD_TYPE_BEFORE_V3) {
        return BOARD_TYPE_BEFORE_V3;
    } else {
        return BOARD_TYPE_V3;
    }
}
#endif
