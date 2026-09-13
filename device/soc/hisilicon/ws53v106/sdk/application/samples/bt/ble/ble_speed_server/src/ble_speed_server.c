/*
 * Copyright (c) HiSilicon (Shanghai) Technologies Co., Ltd. 2022. All rights reserved.
 * Description: ble speed server sample.
 */

#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <los_memory.h>
#include "app_init.h"
#include "systick.h"
#include "soc_osal.h"
#include "cmsis_os2.h"
#include "securec.h"
#include "errcode.h"

#include "osal_addr.h"
#include "bts_def.h"
#include "bts_def.h"
#include "bts_device_manager.h"
#include "bts_le_gap.h"
#include "bts_gatt_stru.h"
#include "bts_gatt_server.h"
#include "bts_gatt_client.h"
#include "ble_speed_server_adv.h"
#include "ble_speed_server.h"


uint8_t g_server_id = 0;

/* server app uuid for test */
char g_uuid_app_uuid[] = {0x0, 0x0};

/* ble indication att handle */
uint16_t g_indication_characteristic_att_hdl = 0;

/* ble notification att handle */
uint16_t g_notification_characteristic_att_hdl = 0;

/* ble connect handle */
uint16_t g_conn_hdl = 0;

#define OCTET_BIT_LEN 8
#define UUID_LEN_2 2

bd_addr_t g_ble_speed_addr = {
    .type = 0,
    .addr = {0x11, 0x22, 0x33, 0x63, 0x88, 0x63},
};

#define DATA_LEN 236
unsigned char data[DATA_LEN];
uint64_t g_count_before_get_us;
uint64_t g_count_after_get_us;
#define SEND_PKT_TIMES 8
#define SEND_PKT_CNT 100
#define DEFAULT_BLE_SPEED_MTU_SIZE 500
#define GAP_MAX_TX_OCTETS 251
#define GAP_MAX_TX_TIME 2200
#define SPEED_DEFAULT_CONN_INTERVAL 0x50
#define SPEED_DEFAULT_SLAVE_LATENCY 0
#define SPEED_DEFAULT_TIMEOUT_MULTIPLIER 0x1f4

#define BLE_SPEED_TASK_PRIO 26
#define BLE_SPEED_STACK_SIZE 0x2000

extern uint16_t ble_get_tx_number_by_handle(uint16_t co_handle);

void send_data_thread_function(void)
{
    printf("start send notify info.\n");
    gap_le_set_phy_t phy_param = {
        .conn_handle    = g_conn_hdl,
        .all_phys       = 0,
        .tx_phys        = 1,
        .rx_phys        = 1,
        .phy_options    = 0,
    };
    gap_ble_set_phy(&phy_param);

    gap_le_set_data_length_t data_param = {
        .conn_handle    = g_conn_hdl,
        .maxtxoctets    = GAP_MAX_TX_OCTETS,
        .maxtxtime      = GAP_MAX_TX_TIME,
    };
    gap_ble_set_data_length(&data_param);

    int i = 0;
    g_count_before_get_us = uapi_systick_get_us();
    while (1) {
        data[0] = (i >> 8) & 0xFF;  /* offset 8bits */
        data[1] = i & 0xFF;
        uint8_t buffer_num = ble_get_tx_number_by_handle(g_conn_hdl);
        // buffer_num > 2为协议栈buffer数限制，可用buffer数最低为2
        if (buffer_num > 2) {
            i++;
            ble_uuid_server_send_report_by_uuid(data, DATA_LEN);
        }
        if (i == SEND_PKT_CNT) {
            i = 0;
            LOS_MEM_POOL_STATUS status;
            LOS_MemInfoGet(m_aucSysMem0, &status);
            osal_printk(" mem: used:%u, free:%u.\r\n", status.uwTotalUsedSize, status.uwTotalFreeSize);
        }
    }
}

/* 将uint16的uuid数字转化为bt_uuid_t */
void stream_data_to_uuid(uint16_t uuid_data, bt_uuid_t *out_uuid)
{
    char uuid[] = {(uint8_t)(uuid_data >> OCTET_BIT_LEN), (uint8_t)uuid_data};
    out_uuid->uuid_len = UUID_LEN_2;
    if (memcpy_s(out_uuid->uuid, out_uuid->uuid_len, uuid, UUID_LEN_2) != EOK) {
        return;
    }
}

errcode_t compare_service_uuid(bt_uuid_t *uuid1, bt_uuid_t *uuid2)
{
    if (uuid1->uuid_len != uuid2->uuid_len) {
        return ERRCODE_BT_FAIL;
    }
    if (memcmp(uuid1->uuid, uuid2->uuid, uuid1->uuid_len) != 0) {
        return ERRCODE_BT_FAIL;
    }
    return ERRCODE_BT_SUCCESS;
}

/* 添加描述符：客户端特性配置 */
static void ble_uuid_server_add_descriptor_ccc(uint32_t server_id, uint32_t srvc_handle)
{
    bt_uuid_t ccc_uuid = {0};
    uint8_t ccc_data_val[] = {0x01, 0x00};

    osal_printk("[uuid server] beginning add descriptors\r\n");
    stream_data_to_uuid(BLE_UUID_CLIENT_CHARACTERISTIC_CONFIGURATION, &ccc_uuid);
    gatts_add_desc_info_t descriptor;
    uint16_t handle;
    descriptor.desc_uuid = ccc_uuid;
    descriptor.permissions = GATT_ATTRIBUTE_PERMISSION_READ | GATT_ATTRIBUTE_PERMISSION_WRITE;
    descriptor.value_len = sizeof(ccc_data_val);
    descriptor.value = ccc_data_val;
    gatts_add_descriptor_sync(server_id, srvc_handle, &descriptor, &handle);
    gatts_start_service(server_id, srvc_handle);
    osal_vfree(ccc_uuid.uuid);
}

/* 添加服务的特征和描述符 */
static void ble_uuid_server_add_characters_and_descriptors(uint32_t server_id, uint32_t srvc_handle)
{
    bt_uuid_t server_uuid = {0};
    uint8_t server_value[] = {0x12, 0x34};
    osal_printk("[uuid server] beginning add characteristic\r\n");
    stream_data_to_uuid(BLE_UUID_UUID_SERVER_REPORT, &server_uuid);
    gatts_add_chara_info_t character;
    gatts_add_character_result_t result;
    character.chara_uuid = server_uuid;
    character.properties = UUID_SERVER_PROPERTIES;
    character.permissions = 0;
    character.value_len = sizeof(server_value);
    character.value = server_value;
    gatts_add_characteristic_sync(server_id, srvc_handle, &character, &result);
    g_notification_characteristic_att_hdl = result.value_handle;
    ble_uuid_server_add_descriptor_ccc(server_id, srvc_handle);
}

/* 开始服务回调 */
static void ble_uuid_server_service_start_cbk(uint8_t server_id, uint16_t handle, errcode_t status)
{
    osal_printk("[uuid server] start service cbk : server: %d status: %d srv_hdl: %d\n",
        server_id, status, handle);
}

static void ble_uuid_server_receive_write_req_cbk(uint8_t server_id, uint16_t conn_id,
    gatts_req_write_cb_t *write_cb_para, errcode_t status)
{
    osal_printk("[uuid server]ReceiveWriteReqCallback--server_id:%d conn_id:%d\n", server_id, conn_id);
    osal_printk("request_id:%d att_handle:%d offset:%d need_rsp:%d need_authorize:%d is_prep:%d\n",
        write_cb_para->request_id, write_cb_para->handle, write_cb_para->offset, write_cb_para->need_rsp,
        write_cb_para->need_authorize, write_cb_para->is_prep);
    osal_printk("data_len:%d data:\n", write_cb_para->length);
    for (uint8_t i = 0; i < write_cb_para->length; i++) {
        osal_printk("%02x ", write_cb_para->value[i]);
    }
    osal_printk("\n");
    osal_printk("status:%d\n", status);
}

static void ble_uuid_server_receive_read_req_cbk(uint8_t server_id, uint16_t conn_id,
    gatts_req_read_cb_t *read_cb_para, errcode_t status)
{
    osal_printk("[uuid server]ReceiveReadReq--server_id:%d conn_id:%d\n", server_id, conn_id);
    osal_printk("request_id:%d att_handle:%d offset:%d need_rsp:%d need_authorize:%d is_long:%d\n",
        read_cb_para->request_id, read_cb_para->handle, read_cb_para->offset, read_cb_para->need_rsp,
        read_cb_para->need_authorize, read_cb_para->is_long);
    osal_printk("status:%d\n", status);
}

static void ble_uuid_server_adv_enable_cbk(uint8_t adv_id, adv_status_t status)
{
    osal_printk("adv enable adv_id: %d, status:%d\n", adv_id, status);
}

static void ble_uuid_server_adv_disable_cbk(uint8_t adv_id, adv_status_t status)
{
    osal_printk("adv disable adv_id: %d, status:%d\n",
        adv_id, status);
}

void ble_uuid_server_connect_change_cbk(uint16_t conn_id, bd_addr_t *addr, gap_ble_conn_state_t conn_state,
    gap_ble_pair_state_t pair_state, gap_ble_disc_reason_t disc_reason)
{
    osal_printk("connect state change conn_id: %d, status: %d, pair_status:%d, disc_reason:0x%x\n",
        conn_id, conn_state, pair_state, disc_reason);
    osal_printk("addr:\n");
    for (uint8_t i = 0; i < BD_ADDR_LEN; i++) {
        osal_printk("0x%2x ", addr->addr[i]);
    }
    osal_printk("\n");
    g_conn_hdl = conn_id;

    if (conn_state == GAP_BLE_STATE_CONNECTED) {
        gap_conn_param_update_t conn_param = {0};
        conn_param.conn_handle  = conn_id;
        conn_param.interval_min = SPEED_DEFAULT_CONN_INTERVAL;
        conn_param.interval_max = SPEED_DEFAULT_CONN_INTERVAL;
        conn_param.slave_latency  = SPEED_DEFAULT_SLAVE_LATENCY;
        conn_param.timeout_multiplier = SPEED_DEFAULT_TIMEOUT_MULTIPLIER;
        gap_ble_connect_param_update(&conn_param);
    } else if (conn_state == GAP_BLE_STATE_DISCONNECTED) {
        gap_ble_start_adv(BTH_GAP_BLE_ADV_HANDLE_DEFAULT);
    }
}

void ble_uuid_server_mtu_changed_cbk(uint8_t server_id, uint16_t conn_id, uint16_t mtu_size, errcode_t status)
{
    osal_printk("mtu change change server_id: %d, conn_id: %d, mtu_size: %d, status:%d \n",
        server_id, conn_id, mtu_size, status);
}

void ble_uuid_server_pair_result_cbk(uint16_t conn_id, const bd_addr_t *addr, errcode_t status)
{
    osal_printk("pair state change conn_id: %d, status: 0x%x\n",
        conn_id, status);
    osal_printk("addr:\n");
    for (uint8_t i = 0; i < BD_ADDR_LEN; i++) {
        osal_printk("0x%2x ", addr->addr[i]);
    }
    osal_printk("\n");
    
    if (status == 0) {
        osal_task *task_handle = NULL;
        osal_kthread_lock();
        task_handle = osal_kthread_create((osal_kthread_handler)send_data_thread_function, 0,
            "SpeedTask", BLE_SPEED_STACK_SIZE);
        osal_kthread_set_priority(task_handle, BLE_SPEED_TASK_PRIO + 1);
        if (task_handle != NULL) {
            osal_kfree(task_handle);
        }
        osal_kthread_unlock();
    }
}

static void ble_uuid_server_conn_param_update_cbk(uint16_t conn_id, errcode_t status,
    const gap_ble_conn_param_update_t *param)
{
    osal_printk("%s conn_param_update conn_id: %d,status: %d \n", __FUNCTION__, conn_id, status);
    osal_printk("interval:%d latency:%d timeout:%d.\n", param->interval, param->latency, param->timeout);
    gatts_exchange_mtu_req(conn_id, DEFAULT_BLE_SPEED_MTU_SIZE);
}

static errcode_t ble_uuid_server_register_callbacks(void)
{
    errcode_t ret = 0;

    gap_ble_callbacks_t gap_cb = {0};
    gap_cb.start_adv_cb = ble_uuid_server_adv_enable_cbk;
    gap_cb.stop_adv_cb = ble_uuid_server_adv_disable_cbk;
    gap_cb.conn_state_change_cb = ble_uuid_server_connect_change_cbk;
    gap_cb.pair_result_cb = ble_uuid_server_pair_result_cbk;
    gap_cb.conn_param_update_cb = ble_uuid_server_conn_param_update_cbk;
    ret |= gap_ble_register_callbacks(&gap_cb);
    if (ret != ERRCODE_BT_SUCCESS) {
        osal_printk("[uuid server] reg gap cbk failed\r\n");
        return ERRCODE_BT_FAIL;
    }

    gatts_callbacks_t service_cb = {0};
    service_cb.start_service_cb = ble_uuid_server_service_start_cbk;
    service_cb.read_request_cb = ble_uuid_server_receive_read_req_cbk;
    service_cb.write_request_cb = ble_uuid_server_receive_write_req_cbk;
    service_cb.mtu_changed_cb = ble_uuid_server_mtu_changed_cbk;
    ret |= gatts_register_callbacks(&service_cb);
    if (ret != ERRCODE_BT_SUCCESS) {
        osal_printk("[uuid server] reg service cbk failed\r\n");
        return ERRCODE_BT_FAIL;
    }
    return ret;
}

uint8_t ble_uuid_add_service(void)
{
    osal_printk("[uuid server] ble uuid add service in\r\n");
    bt_uuid_t service_uuid = {0};
    stream_data_to_uuid(BLE_UUID_UUID_SERVER_SERVICE, &service_uuid);
    uint16_t handle;
    gatts_add_service_sync(BLE_UUID_SERVER_ID, &service_uuid, true, &handle);
    ble_uuid_server_add_characters_and_descriptors(BLE_UUID_SERVER_ID, handle);
    osal_printk("[uuid server] ble uuid add service out\r\n");
    return ERRCODE_BT_SUCCESS;
}

static errcode_t ble_uuid_gatts_register_server(void)
{
    bt_uuid_t app_uuid = {0};
    app_uuid.uuid_len = sizeof(g_uuid_app_uuid);
    if (memcpy_s(app_uuid.uuid, app_uuid.uuid_len, g_uuid_app_uuid, sizeof(g_uuid_app_uuid)) != EOK) {
        return ERRCODE_BT_FAIL;
    }
    return gatts_register_server(&app_uuid, &g_server_id);
}

/* 初始化uuid server service */
errcode_t ble_uuid_server_init(void)
{
    (void)osal_msleep(1000); /* 延时1000ms，等待BLE初始化完毕 */
    enable_ble();
    ble_uuid_server_register_callbacks();
    ble_uuid_gatts_register_server();
    ble_uuid_add_service();
    gap_ble_set_local_addr(&g_ble_speed_addr);
    osal_printk("[uuid server] init ok\r\n");
    ble_start_adv();
    osal_printk("[uuid server] adv ok\r\n");
    return ERRCODE_BT_SUCCESS;
}

/* device通过uuid向host发送数据：report */
errcode_t ble_uuid_server_send_report_by_uuid(uint8_t *data, uint16_t len)
{
    gatts_ntf_ind_by_uuid_t param = {0};
    uint16_t conn_id = g_conn_hdl;
    param.start_handle = 0;
    param.end_handle = 0xffff;
    stream_data_to_uuid(BLE_UUID_UUID_SERVER_REPORT, &param.chara_uuid);
    param.value_len = len;
    param.value = data;
    if (param.value == NULL) {
        osal_printk("[hid][ERROR]send report new fail\r\n");
        return ERRCODE_BT_FAIL;
    }
    gatts_notify_indicate_by_uuid(BLE_UUID_SERVER_ID, conn_id, &param);
    return ERRCODE_BT_SUCCESS;
}

/* device通过handle向host发送数据：report */
errcode_t ble_uuid_server_send_report_by_handle(uint16_t attr_handle, const uint8_t *data, uint8_t len)
{
    gatts_ntf_ind_t param = {0};
    uint16_t conn_id = g_conn_hdl;

    param.attr_handle = attr_handle;
    param.value = osal_vmalloc(len);
    param.value_len = len;

    if (param.value == NULL) {
        osal_printk("[hid][ERROR]send report new fail\r\n");
        return ERRCODE_BT_FAIL;
    }
    if (memcpy_s(param.value, param.value_len, data, len) != EOK) {
        osal_printk("[hid][ERROR]send input report memcpy fail\r\n");
        osal_vfree(param.value);
        return ERRCODE_BT_FAIL;
    }
    gatts_notify_indicate(BLE_UUID_SERVER_ID, conn_id, &param);
    osal_vfree(param.value);
    return ERRCODE_BT_SUCCESS;
}

static void ble_speed_entry(void)
{
    osal_task *task_handle = NULL;
    osal_kthread_lock();
    task_handle= osal_kthread_create((osal_kthread_handler)ble_uuid_server_init, 0, "ble_speed",
        BLE_SPEED_STACK_SIZE);
    if (task_handle != NULL) {
        osal_kthread_set_priority(task_handle, BLE_SPEED_TASK_PRIO);
        osal_kfree(task_handle);
    }
    osal_kthread_unlock();
}

/* Run the app entry. */
app_run(ble_speed_entry);