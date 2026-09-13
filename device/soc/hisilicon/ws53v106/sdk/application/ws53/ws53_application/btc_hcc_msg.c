/*
 * Copyright (c) @CompanyNameMagicTag 2024-2024. All rights reserved.
 *
 * Description: btc hcc msg
 *
 * Author: BGTP
 *
 * Create: 2024-04-09
 */
#include "btc_hcc_msg.h"
#include "hcc_if.h"
#include "securec.h"
#include "bt_customize.h"

hcc_adapt_ops g_hcc_msg_adapt = {0};

#define CO_ALIGN4_HI(val) (((val) + 3) & ~3)

bsle_msg_handle_t g_bsle_msg_handle_table[] = {
    {BSLE_MSG_HCC_TYPE_CUSTOMIZE_DATA_REQ, bt_customize_config_update_req_proc},
};

uint32_t btc_hcc_msg_recv(hcc_queue_type queue_id, uint8_t sub_type, uint8_t *buf, uint32_t len, uint8_t *user_param)
{
    UNUSED(sub_type);
    UNUSED(user_param);
    UNUSED(len);
    if (queue_id != BTC_MSG_QUEUE || buf == NULL) {
        return 1;
    }
    bsle_msg_t *bsle_msg = (bsle_msg_t *)(buf + hcc_get_head_len());
    for (uint8_t i = 0; i < (sizeof(g_bsle_msg_handle_table) / sizeof(bsle_msg_handle_t)); i++) {
        if (g_bsle_msg_handle_table[i].msg_type == bsle_msg->type) {
            g_bsle_msg_handle_table[i].handler(bsle_msg->len, bsle_msg->data);
            return 0;
        }
    }
    printf("btc_hcc_msg_recv: unkown msg_type:%u len:%u\r\n", bsle_msg->type, len);
    return 0;
}

void btc_hcc_msg_send_to_btc(bsle_msg_hcc_type msg_type, uint16_t data_len, uint8_t *data)
{
    int32_t ret;
    uint8_t *buf = NULL;
    bsle_msg_t *bsle_msg = NULL;
    uint16_t len = CO_ALIGN4_HI(data_len) + (uint16_t)sizeof(bsle_msg_t);

    hcc_transfer_param hcc_msg = { 0 };

    hcc_msg.service_type = HCC_ACTION_TYPE_BTC_MSG;
    hcc_msg.sub_type = 0;
    hcc_msg.queue_id = BTC_MSG_QUEUE;
    hcc_msg.fc_flag = 0;
    hcc_msg.user_param = NULL;
    buf = (uint8_t *)osal_kmalloc(len, OSAL_GFP_ATOMIC);
    if (buf == NULL) {
        return;
    }
    (void)memset_s(buf, len, 0, len);
    bsle_msg = (bsle_msg_t *)buf;
    bsle_msg->len = data_len;
    bsle_msg->type = msg_type;
    if (data_len > 0) {
        (void)memcpy_s(bsle_msg->data, data_len, data, data_len);
    }

    ret = hcc_bt_tx_data(HCC_CHANNEL_AP, buf, len, &hcc_msg);
    if (ret != EXT_ERR_SUCCESS) {
        osal_kfree(buf);
        return;
    }
    return;
}

uint32_t btc_hcc_msg_alloc(hcc_queue_type queue_id, uint32_t len, uint8_t **buf, uint8_t **user_param)
{
    UNUSED(user_param);
    UNUSED(queue_id);
    if (buf == NULL) {
        return 1;
    }

    *buf = (uint8_t *)osal_kmalloc(len, OSAL_GFP_ATOMIC);
    if (*buf == NULL) {
        return 1;
    }
    return 0;
}

void btc_hcc_msg_free(hcc_queue_type queue_id, uint8_t *buf, uint8_t *user_param)
{
    UNUSED(user_param);
    UNUSED(queue_id);
    if (buf == NULL) {
        return;
    }

    osal_kfree((void *)buf);
}

void btc_hcc_msg_init(void)
{
    g_hcc_msg_adapt.alloc = btc_hcc_msg_alloc;
    g_hcc_msg_adapt.free = btc_hcc_msg_free;
    g_hcc_msg_adapt.rx_proc = btc_hcc_msg_recv;
    g_hcc_msg_adapt.start_subq = NULL;
    g_hcc_msg_adapt.stop_subq = NULL;
    hcc_service_init(HCC_CHANNEL_AP, HCC_ACTION_TYPE_BTC_MSG, &g_hcc_msg_adapt);
}

void btc_hcc_msg_deinit(void)
{
    hcc_service_deinit(HCC_CHANNEL_AP, HCC_ACTION_TYPE_BTC_MSG);
    (void)memset_s(&g_hcc_msg_adapt, sizeof(hcc_adapt_ops), 0, sizeof(hcc_adapt_ops));
}
