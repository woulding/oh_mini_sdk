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
 * Differences: no UART transport, echo path via message queue, entry via OHOS
 * APP_FEATURE_INIT (see main.c).
 */

#include "securec.h"
#include "soc_osal.h"
#include "sle_errcode.h"
#include "sle_device_manager.h"
#include "sle_connection_manager.h"
#include "sle_transmition_manager.h"
#include "sle_device_discovery.h"
#include "sle_server_adv.h"
#include "sle_server.h"

#define OCTET_BIT_LEN           8
#define UUID_LEN_2              2
#define UUID_INDEX              14
#define BT_INDEX_4              4
#define BT_INDEX_0              0
#define NTF_BUFF_LENGTH         0x100

/* 广播ID */
#define SLE_ADV_HANDLE_DEFAULT  1
/* sle server app uuid for test */
static char g_sle_uuid_app_uuid[UUID_LEN_2] = { 0x12, 0x34 };
/* server notify property uuid for test */
static char g_sle_property_value[OCTET_BIT_LEN] = { 0x0, 0x0, 0x0, 0x0, 0x0, 0x0 };
/* sle connect acb handle */
static uint16_t g_conn_id = 0;
/* sle server handle */
static uint8_t g_server_id = 0;
/* sle service handle */
static uint16_t g_service_handle = 0;
/* sle ntf property handle */
static uint16_t g_property_handle = 0;
/* sle pair acb handle */
static uint16_t g_sle_pair_hdl = 0;

#define UUID_16BIT_LEN 2
#define UUID_128BIT_LEN 16
#define sample_log_print(fmt, args...) osal_printk(fmt, ##args)
#define SLE_SERVER_LOG "[sle server]"
#define SLE_SERVER_ENABLE_POLL_MS          200
#define SLE_SERVER_SEND_DATA_FLOW_DELAY_MS 35
static sle_server_msg_queue g_sle_server_msg_queue = NULL;
static uint8_t g_sle_server_base[] = { 0x37, 0xBE, 0xA8, 0x80, 0xFC, 0x70, 0x11, 0xEA, \
    0xB7, 0x20, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };

sle_link_state_info_t g_qos_link_info = {0};

uint16_t sle_server_get_conn_id(void)
{
    return g_conn_id;
}

static void encode2byte_little(uint8_t *_ptr, uint16_t data)
{
    *(uint8_t *)((_ptr) + 1) = (uint8_t)((data) >> 0x8);
    *(uint8_t *)(_ptr) = (uint8_t)(data);
}

static void sle_uuid_set_base(sle_uuid_t *out)
{
    errcode_t ret;
    ret = memcpy_s(out->uuid, SLE_UUID_LEN, g_sle_server_base, SLE_UUID_LEN);
    if (ret != EOK) {
        sample_log_print("%s sle_uuid_set_base memcpy fail\n", SLE_SERVER_LOG);
        out->len = 0;
        return;
    }
    out->len = UUID_LEN_2;
}

static void sle_uuid_setu2(uint16_t u2, sle_uuid_t *out)
{
    sle_uuid_set_base(out);
    out->len = UUID_LEN_2;
    encode2byte_little(&out->uuid[UUID_INDEX], u2);
}

static void sle_uuid_print(const sle_uuid_t *uuid)
{
    if (uuid == NULL) {
        sample_log_print("%s uuid_print, uuid is null\r\n", SLE_SERVER_LOG);
        return;
    }
    if (uuid->len == UUID_16BIT_LEN) {
        sample_log_print("%s uuid: %02x %02x.\n", SLE_SERVER_LOG,
            uuid->uuid[14], uuid->uuid[15]); /* 14 15: uuid index */
    } else if (uuid->len == UUID_128BIT_LEN) {
        sample_log_print("%s uuid: \n", SLE_SERVER_LOG);
        sample_log_print("%s 0x%02x 0x%02x 0x%02x \n", SLE_SERVER_LOG, uuid->uuid[0], uuid->uuid[1],
            uuid->uuid[2]);
        sample_log_print("%s 0x%02x 0x%02x 0x%02x \n", SLE_SERVER_LOG, uuid->uuid[4], uuid->uuid[5],
            uuid->uuid[6]);
        sample_log_print("%s 0x%02x 0x%02x 0x%02x \n", SLE_SERVER_LOG, uuid->uuid[8], uuid->uuid[9],
            uuid->uuid[10]);
        sample_log_print("%s 0x%02x 0x%02x 0x%02x \n", SLE_SERVER_LOG, uuid->uuid[12], uuid->uuid[13],
            uuid->uuid[14]);
    }
}

/* ---------------- SSAP server callbacks ---------------- */

static void ssaps_mtu_changed_cbk(uint8_t server_id, uint16_t conn_id, ssap_exchange_info_t *mtu_size,
    errcode_t status)
{
    sample_log_print("%s ssaps_mtu_changed_cbk server_id:0x%x, conn_id:0x%x, mtu_size:0x%x, status:0x%x\r\n",
        SLE_SERVER_LOG, server_id, conn_id, mtu_size->mtu_size, status);
}

static void ssaps_start_service_cbk(uint8_t server_id, uint16_t handle, errcode_t status)
{
    sample_log_print("%s start service cbk server_id:%d, handle:0x%x, status:0x%x\r\n", SLE_SERVER_LOG,
        server_id, handle, status);
}

static void ssaps_add_service_cbk(uint8_t server_id, sle_uuid_t *uuid, uint16_t handle, errcode_t status)
{
    sample_log_print("%s add service cbk server_id:0x%x, handle:0x%x, status:0x%x\r\n", SLE_SERVER_LOG,
        server_id, handle, status);
    sle_uuid_print(uuid);
}

static void ssaps_add_property_cbk(uint8_t server_id, sle_uuid_t *uuid, uint16_t service_handle,
    uint16_t handle, errcode_t status)
{
    sample_log_print("%s add property cbk server_id:0x%x, service_handle:0x%x, handle:0x%x, status:0x%x\r\n",
        SLE_SERVER_LOG, server_id, service_handle, handle, status);
    sle_uuid_print(uuid);
}

static void ssaps_add_descriptor_cbk(uint8_t server_id, sle_uuid_t *uuid, uint16_t service_handle,
    uint16_t property_handle, errcode_t status)
{
    sample_log_print("%s add descriptor cbk server_id:0x%x, service_handle:0x%x, property_handle:0x%x, \
        status:0x%x\r\n", SLE_SERVER_LOG, server_id, service_handle, property_handle, status);
    sle_uuid_print(uuid);
}

static void ssaps_delete_all_service_cbk(uint8_t server_id, errcode_t status)
{
    sample_log_print("%s delete all service cbk server_id:0x%x, status:0x%x\r\n", SLE_SERVER_LOG,
        server_id, status);
}

/* Remote (SLE debug assistant) read request: respond with the current property value. */
static void ssaps_server_read_request_cbk(uint8_t server_id, uint16_t conn_id, ssaps_req_read_cb_t *read_cb_para,
    errcode_t status)
{
    sample_log_print("%s ssaps read request cbk server_id:0x%x, conn_id:0x%x, handle:0x%x, status:0x%x\r\n",
        SLE_SERVER_LOG, server_id, conn_id, read_cb_para->handle, status);
}

/* Remote (SLE debug assistant) write request: forward to the demo task via msg queue. */
static void ssaps_server_write_request_cbk(uint8_t server_id, uint16_t conn_id, ssaps_req_write_cb_t *write_cb_para,
    errcode_t status)
{
    sample_log_print("%s ssaps write request cbk server_id:0x%x, conn_id:0x%x, handle:0x%x, status:0x%x\r\n",
        SLE_SERVER_LOG, server_id, conn_id, write_cb_para->handle, status);
    if (g_sle_server_msg_queue != NULL && write_cb_para->length > 0 && write_cb_para->value != NULL) {
        g_sle_server_msg_queue(write_cb_para->value, write_cb_para->length);
    }
}

static errcode_t sle_ssaps_register_cbks(void)
{
    errcode_t ret;
    ssaps_callbacks_t ssaps_cbk = {0};
    ssaps_cbk.add_service_cb = ssaps_add_service_cbk;
    ssaps_cbk.add_property_cb = ssaps_add_property_cbk;
    ssaps_cbk.add_descriptor_cb = ssaps_add_descriptor_cbk;
    ssaps_cbk.start_service_cb = ssaps_start_service_cbk;
    ssaps_cbk.delete_all_service_cb = ssaps_delete_all_service_cbk;
    ssaps_cbk.mtu_changed_cb = ssaps_mtu_changed_cbk;
    ssaps_cbk.read_request_cb = ssaps_server_read_request_cbk;
    ssaps_cbk.write_request_cb = ssaps_server_write_request_cbk;
    ret = ssaps_register_callbacks(&ssaps_cbk);
    if (ret != ERRCODE_SLE_SUCCESS) {
        sample_log_print("%s sle_ssaps_register_cbks, ssaps_register_callbacks fail :%x\r\n", SLE_SERVER_LOG,
            ret);
        return ret;
    }
    return ERRCODE_SLE_SUCCESS;
}

/* ---------------- Service / property database ---------------- */

static errcode_t sle_uuid_server_service_add(void)
{
    errcode_t ret;
    sle_uuid_t service_uuid = {0};
    sle_uuid_setu2(SLE_UUID_SERVER_SERVICE, &service_uuid);
    ret = ssaps_add_service_sync(g_server_id, &service_uuid, 1, &g_service_handle);
    if (ret != ERRCODE_SLE_SUCCESS) {
        sample_log_print("%s sle uuid add service fail, ret:%x\r\n", SLE_SERVER_LOG, ret);
        return ERRCODE_SLE_FAIL;
    }
    return ERRCODE_SLE_SUCCESS;
}

static errcode_t sle_uuid_server_property_add(void)
{
    errcode_t ret;
    ssaps_property_info_t property = {0};
    ssaps_desc_info_t descriptor = {0};
    uint8_t ntf_value[] = { 0x01, 0x00 };

    property.permissions = SLE_UUID_TEST_PROPERTIES;
    property.operate_indication = SLE_UUID_TEST_OPERATION_INDICATION;
    sle_uuid_setu2(SLE_UUID_SERVER_NTF_REPORT, &property.uuid);
    property.value_len = sizeof(g_sle_property_value);
    property.value = (uint8_t *)osal_vmalloc(sizeof(g_sle_property_value));
    if (property.value == NULL) {
        return ERRCODE_SLE_FAIL;
    }
    if (memcpy_s(property.value, sizeof(g_sle_property_value), g_sle_property_value,
        sizeof(g_sle_property_value)) != EOK) {
        osal_vfree(property.value);
        return ERRCODE_SLE_FAIL;
    }
    ret = ssaps_add_property_sync(g_server_id, g_service_handle, &property,  &g_property_handle);
    if (ret != ERRCODE_SLE_SUCCESS) {
        sample_log_print("%s sle add property fail, ret:%x\r\n", SLE_SERVER_LOG, ret);
        osal_vfree(property.value);
        return ERRCODE_SLE_FAIL;
    }
    descriptor.permissions = SLE_UUID_TEST_DESCRIPTOR;
    descriptor.type = SSAP_DESCRIPTOR_CLIENT_CONFIGURATION;
    descriptor.operate_indication = SSAP_OPERATE_INDICATION_BIT_READ |
        SSAP_OPERATE_INDICATION_BIT_WRITE | SSAP_OPERATE_INDICATION_BIT_DESCRIPTOR_CLIENT_CONFIGURATION_WRITE;
    descriptor.value_len = sizeof(ntf_value);
    descriptor.value = (uint8_t *)osal_vmalloc(sizeof(ntf_value));
    if (descriptor.value == NULL) {
        osal_vfree(property.value);
        return ERRCODE_SLE_FAIL;
    }
    if (memcpy_s(descriptor.value, sizeof(ntf_value), ntf_value, sizeof(ntf_value)) != EOK) {
        osal_vfree(property.value);
        osal_vfree(descriptor.value);
        return ERRCODE_SLE_FAIL;
    }
    ret = ssaps_add_descriptor_sync(g_server_id, g_service_handle, g_property_handle, &descriptor);
    if (ret != ERRCODE_SLE_SUCCESS) {
        sample_log_print("%s sle add descriptor fail, ret:%x\r\n", SLE_SERVER_LOG, ret);
        osal_vfree(property.value);
        osal_vfree(descriptor.value);
        return ERRCODE_SLE_FAIL;
    }
    osal_vfree(property.value);
    osal_vfree(descriptor.value);
    return ERRCODE_SLE_SUCCESS;
}

static errcode_t sle_server_add(void)
{
    errcode_t ret;
    sle_uuid_t app_uuid = {0};

    sample_log_print("%s sle add service in\r\n", SLE_SERVER_LOG);
    app_uuid.len = sizeof(g_sle_uuid_app_uuid);
    if (memcpy_s(app_uuid.uuid, app_uuid.len, g_sle_uuid_app_uuid, sizeof(g_sle_uuid_app_uuid)) != EOK) {
        return ERRCODE_SLE_FAIL;
    }
    ssaps_register_server(&app_uuid, &g_server_id);

    if (sle_uuid_server_service_add() != ERRCODE_SLE_SUCCESS) {
        ssaps_unregister_server(g_server_id);
        return ERRCODE_SLE_FAIL;
    }
    if (sle_uuid_server_property_add() != ERRCODE_SLE_SUCCESS) {
        ssaps_unregister_server(g_server_id);
        return ERRCODE_SLE_FAIL;
    }
    sample_log_print("%s sle add service, server_id:%x, service_handle:%x, property_handle:%x\r\n",
        SLE_SERVER_LOG, g_server_id, g_service_handle, g_property_handle);
    ret = ssaps_start_service(g_server_id, g_service_handle);
    if (ret != ERRCODE_SLE_SUCCESS) {
        sample_log_print("%s sle start service fail, ret:%x\r\n", SLE_SERVER_LOG, ret);
        return ERRCODE_SLE_FAIL;
    }
    sample_log_print("%s sle add service out\r\n", SLE_SERVER_LOG);
    return ERRCODE_SLE_SUCCESS;
}

/* ---------------- Notify ---------------- */

/* device通过handle向host发送数据：report */
errcode_t sle_server_send_report_by_handle(const uint8_t *data, uint16_t len)
{
    ssaps_ntf_ind_t param = {0};
    uint8_t send_buf[NTF_BUFF_LENGTH] = { 0 }; /* max send length. */
    if (len > NTF_BUFF_LENGTH) {
        return ERRCODE_SLE_PARAM_ERR;
    }
    param.handle = g_property_handle;
    param.type = SSAP_PROPERTY_TYPE_VALUE;
    param.value = send_buf;
    param.value_len = len;
    if (memcpy_s(param.value, param.value_len, data, len) != EOK) {
        return ERRCODE_SLE_FAIL;
    }
    if (g_qos_link_info.link_state == SLE_QOS_FLOWCTRL) {
        osal_msleep(SLE_SERVER_SEND_DATA_FLOW_DELAY_MS);
    } else if (g_qos_link_info.link_state == SLE_QOS_BUSY) {
        return ERRCODE_SLE_BUSY;
    }
    return ssaps_notify_indicate(g_server_id, g_conn_id, &param);
}

/* ---------------- Connection management ---------------- */

static void sle_connect_state_changed_cbk(uint16_t conn_id, const sle_addr_t *addr,
    sle_acb_state_t conn_state, sle_pair_state_t pair_state, sle_disc_reason_t disc_reason)
{
    uint8_t sle_connect_state[] = "sle_dis_connect";
    sample_log_print("%s connect state changed cbk conn_id:0x%02x, conn_state:0x%x, pair_state:0x%x, \
        disc_reason:0x%x\r\n", SLE_SERVER_LOG, conn_id, conn_state, pair_state, disc_reason);
    sample_log_print("%s connect state changed cbk addr:%02x:**:**:**:%02x:%02x\r\n", SLE_SERVER_LOG,
        addr->addr[BT_INDEX_0], addr->addr[BT_INDEX_4]);
    if (conn_state == SLE_ACB_STATE_CONNECTED) {
        g_conn_id = conn_id;
        g_qos_link_info.link_state = SLE_QOS_IDLE;
    }
    if (conn_state == SLE_ACB_STATE_DISCONNECTED) {
        g_conn_id = 0;
        g_sle_pair_hdl = 0;
        if (g_sle_server_msg_queue != NULL) {
            g_sle_server_msg_queue(sle_connect_state, sizeof(sle_connect_state));
        }
    }
}

static void sle_pair_complete_cbk(uint16_t conn_id, const sle_addr_t *addr, errcode_t status)
{
    sample_log_print("%s pair complete conn_id:0x%02x, status:0x%x\r\n", SLE_SERVER_LOG,
        conn_id, status);
    sample_log_print("%s pair complete addr:%02x:**:**:**:%02x:%02x\r\n", SLE_SERVER_LOG,
        addr->addr[BT_INDEX_0], addr->addr[BT_INDEX_4]);
    g_sle_pair_hdl = conn_id + 1;
}

static void sle_tm_send_data_busy_cbk(uint16_t conn_id, sle_link_qos_state_t link_state)
{
    sample_log_print("%s send data busy cbk conn_id:%u, link_state:%u\r\n", SLE_SERVER_LOG,
        conn_id, link_state);
    g_qos_link_info.conn_id = conn_id;
    g_qos_link_info.link_state = link_state;
}

static errcode_t sle_conn_register_cbks(void)
{
    errcode_t ret;
    sle_connection_callbacks_t conn_cbks = {0};
    conn_cbks.connect_state_changed_cb = sle_connect_state_changed_cbk;
    conn_cbks.pair_complete_cb = sle_pair_complete_cbk;
    ret = sle_connection_register_callbacks(&conn_cbks);
    if (ret != ERRCODE_SLE_SUCCESS) {
        sample_log_print("%s sle_conn_register_cbks, sle_connection_register_callbacks fail :%x\r\n",
            SLE_SERVER_LOG, ret);
        return ret;
    }
    return ERRCODE_SLE_SUCCESS;
}

static errcode_t sle_tm_register_cbks(void)
{
    sle_transmission_callbacks_t tm_cbks = {0};
    tm_cbks.send_data_cb = sle_tm_send_data_busy_cbk;
    errcode_t ret = sle_transmission_register_callbacks(&tm_cbks);
    if (ret != ERRCODE_SLE_SUCCESS) {
        sample_log_print("%s sle_tm_register_cbks, sle_transmission_register_callbacks fail :0x%x\r\n",
            SLE_SERVER_LOG, ret);
        return ret;
    }
    return ERRCODE_SLE_SUCCESS;
}

uint16_t sle_server_is_connected(void)
{
    return g_sle_pair_hdl;
}

/* 初始化 sle server：注册回调 → 使能 SLE → 等使能完成 → 加服务 → 启动广播。
 * 全部在应用任务上下文同步执行（对齐 ble_sle_tag/sle_server）。 */
errcode_t sle_server_init(void)
{
    errcode_t ret;
    ret = sle_tm_register_cbks();
    if (ret != ERRCODE_SLE_SUCCESS) {
        sample_log_print("%s sle_server_init, sle_tm_register_cbks fail :%x\r\n", SLE_SERVER_LOG, ret);
        return ret;
    }
    ret = sle_conn_register_cbks();
    if (ret != ERRCODE_SLE_SUCCESS) {
        sample_log_print("%s sle_server_init, sle_conn_register_cbks fail :%x\r\n", SLE_SERVER_LOG, ret);
        return ret;
    }
    ret = sle_ssaps_register_cbks();
    if (ret != ERRCODE_SLE_SUCCESS) {
        sample_log_print("%s sle_server_init, sle_ssaps_register_cbks fail :%x\r\n", SLE_SERVER_LOG, ret);
        return ret;
    }
    ret = sle_announce_register_cbks();
    if (ret != ERRCODE_SLE_SUCCESS) {
        sample_log_print("%s sle_server_init, sle_announce_register_cbks fail :%x\r\n", SLE_SERVER_LOG, ret);
        return ret;
    }
    ret = enable_sle();
    if (ret != ERRCODE_SLE_SUCCESS) {
        sample_log_print("%s sle_server_init, enable_sle fail :%x\r\n", SLE_SERVER_LOG, ret);
        return ret;
    }
    while (sle_server_get_enable_status() != SLE_ENABLE_STATUS_OK) {
        osal_msleep(SLE_SERVER_ENABLE_POLL_MS);
    }
    ret = sle_server_add();
    if (ret != ERRCODE_SLE_SUCCESS) {
        sample_log_print("%s sle_server_init, sle_server_add fail :0x%x\r\n", SLE_SERVER_LOG, ret);
        return ret;
    }
    ret = sle_server_adv_init();
    if (ret != ERRCODE_SLE_SUCCESS) {
        sample_log_print("%s sle_server_init, sle_server_adv_init fail :0x%x\r\n", SLE_SERVER_LOG, ret);
        return ret;
    }
    sample_log_print("%s init ok\r\n", SLE_SERVER_LOG);
    return ERRCODE_SLE_SUCCESS;
}

void sle_server_register_msg(sle_server_msg_queue msg_cb)
{
    g_sle_server_msg_queue = msg_cb;
}
