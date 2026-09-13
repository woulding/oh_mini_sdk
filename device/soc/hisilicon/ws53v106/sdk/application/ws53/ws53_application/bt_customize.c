/*
 * Copyright (c) @CompanyNameMagicTag 2024-2024. All rights reserved.
 *
 * Description: bt customize.
 *
 * Author: BGTP
 *
 * Create: 2024-4-9
 */

#include "bt_customize.h"
#include "stdio.h"
#include "common_def.h"
#include "btc_hcc_msg.h"
#include "errcode.h"
#include "securec.h"
#ifdef CONFIG_MIDDLEWARE_SUPPORT_NV
#include "nv.h"
#include "key_id.h"
#endif

#define BT_CUSTOMIZE_VAL_LEN_MAX 4

// NV 项不存在时，使用默认值；
bfgn_bt_customization_stru g_bt_customize = {
    .low_power_switch = 1, // 0x20A0
    .device_sca = 1, // 0x20A1
    .wakeup_advance_time = 0, // 0x20A2
    .work_advance_time = 0, // 0x20A3
    .dft_tx_power_level = 0x7, // 0x20A4
    .srrc_switch = 1, // 0x20A5
    .sle_conn_duration  = 0x8, // 0x20A8
    .sle_md_switch = 0, // 0x20A9 default: 0
    .chnl_scan_cfg = { // 0x20AA
        .chnl_scan_switch = 1,
        .intv_min = 200, // default: 200 * 10ms
    },
};

#ifdef CONFIG_MIDDLEWARE_SUPPORT_NV
static const bt_customize_config_t g_bt_customize_config[] = {
    {NV_ID_BTC_LOWPOWER_SWITCH, offsetof(bfgn_bt_customization_stru, low_power_switch),
        sizeof(((bfgn_bt_customization_stru *)0)->low_power_switch)},
    {NV_ID_BTC_DEVICE_SCA, offsetof(bfgn_bt_customization_stru, device_sca),
        sizeof(((bfgn_bt_customization_stru *)0)->device_sca)},
    {NV_ID_BTC_WAKEUP_ADVANCE_TIME, offsetof(bfgn_bt_customization_stru, wakeup_advance_time),
        sizeof(((bfgn_bt_customization_stru *)0)->wakeup_advance_time)},
    {NV_ID_BTC_WORK_ADVANCE_TIME, offsetof(bfgn_bt_customization_stru, work_advance_time),
        sizeof(((bfgn_bt_customization_stru *)0)->work_advance_time)},
    {NV_ID_BTC_DFT_TX_POWER_LEVEL, offsetof(bfgn_bt_customization_stru, dft_tx_power_level),
        sizeof(((bfgn_bt_customization_stru *)0)->dft_tx_power_level)},
    {NV_ID_BTC_SRRC_SWITCH, offsetof(bfgn_bt_customization_stru, srrc_switch),
        sizeof(((bfgn_bt_customization_stru *)0)->srrc_switch)},
    {NV_ID_BTC_SLE_CONN_DURATION, offsetof(bfgn_bt_customization_stru, sle_conn_duration),
        sizeof(((bfgn_bt_customization_stru *)0)->sle_conn_duration)},
    {NV_ID_BTC_SLE_MD_SWITCH, offsetof(bfgn_bt_customization_stru, sle_md_switch),
        sizeof(((bfgn_bt_customization_stru *)0)->sle_md_switch)},
    {NV_ID_BTC_CHNL_SCAN_CFG, offsetof(bfgn_bt_customization_stru, chnl_scan_cfg),
        sizeof(((bfgn_bt_customization_stru *)0)->chnl_scan_cfg)},
};
#endif

errcode_t bt_customize_config_update_req_proc(const uint16_t length, const uint8_t *data)
{
    static bool first_recv_flag = true;

    if (first_recv_flag == false) {
        return ERRCODE_SUCC;
    }
    first_recv_flag = false;

    unused(length);
    unused(data);
#ifdef CONFIG_MIDDLEWARE_SUPPORT_NV
    uint16_t value_len;
    for (uint8_t i = 0; i < sizeof(g_bt_customize_config) / sizeof(g_bt_customize_config[0]); i++) {
        uapi_nv_read(g_bt_customize_config[i].key_id, g_bt_customize_config[i].value_len,
            &value_len, (uint8_t *)&g_bt_customize + g_bt_customize_config[i].offset);
    }
#endif
    btc_hcc_msg_send_to_btc(BSLE_MSG_HCC_TYPE_CUSTOMIZE_DATA_RSP, sizeof(g_bt_customize), (uint8_t *)&g_bt_customize);
    return ERRCODE_SUCC;
}