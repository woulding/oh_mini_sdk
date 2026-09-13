/*
 * Copyright (c) @CompanyNameMagicTag 2020-2020. All rights reserved.
 *
 * Description: Header file of BT customization-related functions.
 *
 * Author: BGTP
 *
 * Create: 2020-3-9
 */

#ifndef BT_CUSTOMIZE_H
#define BT_CUSTOMIZE_H

#include <stdbool.h>
#include "stdint.h"
#include "errcode.h"
// nv struct统一一字节对齐
#pragma pack(1)
#ifdef CONFIG_MIDDLEWARE_SUPPORT_NV
#include "nv_common_cfg.h"
#else
typedef struct {
    uint8_t chnl_scan_switch;
    uint16_t intv_min; // unit: 10ms
} chnl_scan_cfg_t;
#endif
#pragma pack()

#pragma pack(1)
typedef struct {
    uint8_t  low_power_switch;
    uint8_t  device_sca;
    uint16_t wakeup_advance_time;
    uint16_t work_advance_time;
    uint8_t  dft_tx_power_level;
    uint8_t srrc_switch;
    uint8_t  sle_conn_duration;
    uint8_t sle_md_switch;
    chnl_scan_cfg_t chnl_scan_cfg;
} bfgn_bt_customization_stru;
#pragma pack()

typedef struct {
    uint16_t key_id;
    uint8_t offset;
    uint8_t value_len;
} bt_customize_config_t;

errcode_t bt_customize_config_update_req_proc(const uint16_t length, const uint8_t *data);

#endif
