/**
 * Copyright (C) 2026 HiHope Open Source Organization.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

/* Ported from the LiteOS SDK sample:
 *   device/soc/hisilicon/bs2xv107/sdk/application/samples/products/sle_uart/sle_uart_server/
 * sle_uart_server_adv.c — device discovery / announce config for the OHOS sle_server demo.
 */

#include "securec.h"
#include "errcode.h"
#include "soc_osal.h"
#include "string.h"
#include "sle_common.h"
#include "sle_device_manager.h"
#include "sle_device_discovery.h"
#include "sle_errcode.h"
#include "sle_server_adv.h"
#include "sle_server.h"

/* sle device name */
#define NAME_MAX_LENGTH 16
/* 连接调度间隔12.5ms，单位125us */
#define SLE_CONN_INTV_MIN_DEFAULT                 0x64
/* 连接调度间隔12.5ms，单位125us */
#define SLE_CONN_INTV_MAX_DEFAULT                 0x64
/* 连接调度间隔25ms，单位125us */
#define SLE_ADV_INTERVAL_MIN_DEFAULT              0xC8
/* 连接调度间隔25ms，单位125us */
#define SLE_ADV_INTERVAL_MAX_DEFAULT              0xC8
/* 超时时间5000ms，单位10ms */
#define SLE_CONN_SUPERVISION_TIMEOUT_DEFAULT      0x1F4
/* 超时时间4990ms，单位10ms */
#define SLE_CONN_MAX_LATENCY                      0x1F3
/* 广播发送功率 */
#define SLE_ADV_TX_POWER                          6
/* 广播ID */
#define SLE_ADV_HANDLE_DEFAULT                    1
/* 最大广播数据长度 */
#define SLE_ADV_DATA_LEN_MAX                      251
/* 广播名称（星闪调试助手按此名称过滤） */
static uint8_t sle_local_name[NAME_MAX_LENGTH] = "sle_server";
#define sample_log_print(fmt, args...) osal_printk(fmt, ##args)
#define SLE_SERVER_LOG "[sle server]"

static uint16_t sle_set_adv_local_name(uint8_t *adv_data, uint16_t max_len)
{
    errno_t ret;
    uint8_t index = 0;

    uint8_t *local_name = sle_local_name;
    uint8_t local_name_len = strlen((const char *)local_name);
    /* SLE ADV TLV 格式: [type][length][value]，length 为 value 字节数（对齐 ble_sle_tag） */
    adv_data[index++] = SLE_ADV_DATA_TYPE_COMPLETE_LOCAL_NAME;
    adv_data[index++] = local_name_len;
    ret = memcpy_s(&adv_data[index], max_len - index, local_name, local_name_len);
    if (ret != EOK) {
        sample_log_print("%s sle_set_adv_local_name memcpy fail\r\n", SLE_SERVER_LOG);
        return 0;
    }
    return (uint16_t)index + local_name_len;
}

static uint16_t sle_set_adv_data(uint8_t *adv_data)
{
    size_t len = 0;
    uint16_t idx = 0;
    errno_t ret = 0;

    len = sizeof(struct sle_adv_common_value);
    struct sle_adv_common_value adv_disc_level = {
        .length = 1,
        .type = SLE_ADV_DATA_TYPE_DISCOVERY_LEVEL,
        .value = SLE_ANNOUNCE_LEVEL_NORMAL,
    };
    ret = memcpy_s(&adv_data[idx], SLE_ADV_DATA_LEN_MAX - idx, &adv_disc_level, len);
    if (ret != EOK) {
        sample_log_print("%s adv_disc_level memcpy fail\r\n", SLE_SERVER_LOG);
        return 0;
    }
    idx += len;

    len = sizeof(struct sle_adv_common_value);
    struct sle_adv_common_value adv_access_mode = {
        .length = 1,
        .type = SLE_ADV_DATA_TYPE_ACCESS_MODE,
        .value = 0,
    };
    ret = memcpy_s(&adv_data[idx], SLE_ADV_DATA_LEN_MAX - idx, &adv_access_mode, len);
    if (ret != EOK) {
        sample_log_print("%s adv_access_mode memcpy fail\r\n", SLE_SERVER_LOG);
        return 0;
    }
    idx += len;

    return idx;
}

static uint16_t sle_set_scan_response_data(uint8_t *scan_rsp_data)
{
    uint16_t idx = 0;
    errno_t ret;
    size_t scan_rsp_data_len = sizeof(struct sle_adv_common_value);

    struct sle_adv_common_value tx_power_level = {
        .length = 1,
        .type = SLE_ADV_DATA_TYPE_TX_POWER_LEVEL,
        .value = SLE_ADV_TX_POWER,
    };
    ret = memcpy_s(scan_rsp_data, SLE_ADV_DATA_LEN_MAX, &tx_power_level, scan_rsp_data_len);
    if (ret != EOK) {
        sample_log_print("%s sle scan response data memcpy fail\r\n", SLE_SERVER_LOG);
        return 0;
    }
    idx += scan_rsp_data_len;

    /* set local name */
    idx += sle_set_adv_local_name(&scan_rsp_data[idx], SLE_ADV_DATA_LEN_MAX - idx);
    return idx;
}

/* 显式设置本地 SLE 地址（对齐 ble_sle_tag）：不设时若模组未烧录地址，
 * 广播地址非法会导致手机/星闪调试助手扫描不到。 */
static void sle_server_set_local_addr(void)
{
    sle_addr_t cur = {0};
    if (sle_get_local_addr(&cur) == ERRCODE_SLE_SUCCESS) {
        sample_log_print("%s current local addr: %02x:**:**:**:%02x:%02x, type:%u\r\n", SLE_SERVER_LOG,
            cur.addr[0], cur.addr[4], cur.addr[5], cur.type);
    }
    static const uint8_t demo_addr[SLE_ADDR_LEN] = { 0x22, 0x33, 0x44, 0x55, 0x66, 0x77 };
    sle_addr_t addr = {0};
    addr.type = SLE_ADDRESS_TYPE_PUBLIC;
    if (memcpy_s(addr.addr, SLE_ADDR_LEN, demo_addr, SLE_ADDR_LEN) != EOK) {
        sample_log_print("%s local addr memcpy fail\r\n", SLE_SERVER_LOG);
        return;
    }
    errcode_t ret = sle_set_local_addr(&addr);
    sample_log_print("%s set local addr 22:33:44:55:66:77, ret:0x%x\r\n", SLE_SERVER_LOG, ret);
}

static int sle_set_default_announce_param(void)
{
    errno_t ret;
    sle_announce_param_t param = {0};
    uint8_t index;
    unsigned char local_addr[SLE_ADDR_LEN] = { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };
    sle_server_set_local_addr();
    param.announce_mode = SLE_ANNOUNCE_MODE_CONNECTABLE_SCANABLE;
    param.announce_handle = SLE_ADV_HANDLE_DEFAULT;
    param.announce_gt_role = SLE_ANNOUNCE_ROLE_T_CAN_NEGO;
    param.announce_level = SLE_ANNOUNCE_LEVEL_NORMAL;
    param.announce_channel_map = SLE_ADV_CHANNEL_MAP_DEFAULT;
    param.announce_interval_min = SLE_ADV_INTERVAL_MIN_DEFAULT;
    param.announce_interval_max = SLE_ADV_INTERVAL_MAX_DEFAULT;
    param.conn_interval_min = SLE_CONN_INTV_MIN_DEFAULT;
    param.conn_interval_max = SLE_CONN_INTV_MAX_DEFAULT;
    param.conn_max_latency = SLE_CONN_MAX_LATENCY;
    param.conn_supervision_timeout = SLE_CONN_SUPERVISION_TIMEOUT_DEFAULT;
    param.own_addr.type = 0;
    ret = memcpy_s(param.own_addr.addr, SLE_ADDR_LEN, local_addr, SLE_ADDR_LEN);
    if (ret != EOK) {
        sample_log_print("%s sle_set_default_announce_param memcpy fail\r\n", SLE_SERVER_LOG);
        return 0;
    }
    sample_log_print("%s local addr: ", SLE_SERVER_LOG);
    for (index = 0; index < SLE_ADDR_LEN; index++) {
        sample_log_print("0x%02x ", param.own_addr.addr[index]);
    }
    sample_log_print("\r\n");
    return sle_set_announce_param(param.announce_handle, &param);
}

static int sle_set_default_announce_data(void)
{
    errcode_t ret;
    uint16_t announce_data_len = 0;
    uint16_t seek_data_len = 0;
    sle_announce_data_t data = {0};
    uint8_t adv_handle = SLE_ADV_HANDLE_DEFAULT;
    uint8_t announce_data[SLE_ADV_DATA_LEN_MAX] = {0};
    uint8_t seek_rsp_data[SLE_ADV_DATA_LEN_MAX] = {0};
    uint16_t data_index = 0;

    announce_data_len = sle_set_adv_data(announce_data);
    data.announce_data = announce_data;
    data.announce_data_len = announce_data_len;

    sample_log_print("%s announce_data_len = %d\r\n", SLE_SERVER_LOG, data.announce_data_len);
    sample_log_print("%s announce_data: ", SLE_SERVER_LOG);
    for (data_index = 0; data_index < data.announce_data_len; data_index++) {
        sample_log_print("0x%02x ", data.announce_data[data_index]);
    }
    sample_log_print("\r\n");

    seek_data_len = sle_set_scan_response_data(seek_rsp_data);
    data.seek_rsp_data = seek_rsp_data;
    data.seek_rsp_data_len = seek_data_len;

    sample_log_print("%s seek_rsp_data_len = %d\r\n", SLE_SERVER_LOG, data.seek_rsp_data_len);
    sample_log_print("%s seek_rsp_data: ", SLE_SERVER_LOG);
    for (data_index = 0; data_index < data.seek_rsp_data_len; data_index++) {
        sample_log_print("0x%02x ", data.seek_rsp_data[data_index]);
    }
    sample_log_print("\r\n");

    ret = sle_set_announce_data(adv_handle, &data);
    if (ret == ERRCODE_SLE_SUCCESS) {
        sample_log_print("%s set announce data success.\r\n", SLE_SERVER_LOG);
    } else {
        sample_log_print("%s set announce data fail.\r\n", SLE_SERVER_LOG);
    }
    return ERRCODE_SLE_SUCCESS;
}

static void sle_announce_enable_cbk(uint32_t announce_id, errcode_t status)
{
    sample_log_print("%s sle announce enable cbk id:%02x, state:%x\r\n", SLE_SERVER_LOG, announce_id,
        status);
}

static void sle_announce_disable_cbk(uint32_t announce_id, errcode_t status)
{
    sample_log_print("%s sle announce disable cbk id:%02x, state:%x\r\n", SLE_SERVER_LOG, announce_id,
        status);
}

static void sle_announce_terminal_cbk(uint32_t announce_id)
{
    sample_log_print("%s sle announce terminal cbk id:%02x\r\n", SLE_SERVER_LOG, announce_id);
}

static uint8_t g_sle_enable_status = 0;

static void sle_enable_cbk(uint8_t status)
{
    /* 回调运行于 SLE service 线程：只置标志，业务放到任务上下文做 */
    g_sle_enable_status = SLE_ENABLE_STATUS_OK;
    sample_log_print("%s sle enable status:0x%02x\r\n", SLE_SERVER_LOG, status);
}

uint8_t sle_server_get_enable_status(void)
{
    return g_sle_enable_status;
}

/* 注册 dev manager(enable) 与 broadcast(seek) 回调（对齐 ble_sle_tag） */
errcode_t sle_announce_register_cbks(void)
{
    errcode_t ret = 0;
    sle_dev_manager_callbacks_t dev_mgr_cbks = {0};
    sle_announce_seek_callbacks_t seek_cbks = {0};
    dev_mgr_cbks.sle_enable_cb = sle_enable_cbk;
    seek_cbks.announce_enable_cb = sle_announce_enable_cbk;
    seek_cbks.announce_disable_cb = sle_announce_disable_cbk;
    seek_cbks.announce_terminal_cb = sle_announce_terminal_cbk;
    ret = sle_dev_manager_register_callbacks(&dev_mgr_cbks);
    if (ret != ERRCODE_SLE_SUCCESS) {
        sample_log_print("%s sle_dev_manager_register_callbacks fail :%x\r\n", SLE_SERVER_LOG, ret);
        return ret;
    }
    ret = sle_announce_seek_register_callbacks(&seek_cbks);
    if (ret != ERRCODE_SLE_SUCCESS) {
        sample_log_print("%s sle_announce_seek_register_callbacks fail :%x\r\n", SLE_SERVER_LOG, ret);
        return ret;
    }
    return ERRCODE_SLE_SUCCESS;
}

errcode_t sle_server_adv_init(void)
{
    errcode_t ret;
    sle_set_default_announce_param();
    sle_set_default_announce_data();
    ret = sle_start_announce(SLE_ADV_HANDLE_DEFAULT);
    if (ret != ERRCODE_SLE_SUCCESS) {
        sample_log_print("%s sle_server_adv_init, sle_start_announce fail :%x\r\n", SLE_SERVER_LOG, ret);
        return ret;
    }
    return ERRCODE_SLE_SUCCESS;
}
