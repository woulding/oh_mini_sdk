/**
 * Copyright (c) HiSilicon (Shanghai) Technologies Co., Ltd. 2023-2023. All rights reserved.
 * Description: register address related to product.
 *
 * Create: 2023-07-14
*/

#include "trng.h"
#include "ipc.h"
#include "ipc_porting.h"
#include "securec.h"
#include "common_def.h"

enum RANDOM_UPDATE_TYPE {
    SEC_TRNG2_RAND_BUF_UPDATA_ALL = 0,
    SEC_TRNG2_RAND_BUF_UPDATA_UP_SIDE,
    SEC_TRNG2_RAND_BUF_UPDATA_DOWN_SIDE
};
uint32_t g_region_start;
uint32_t g_region_length;
uint32_t g_region_half_start;
uint32_t g_region_half_length;

static void sec_trng2_random_buffer_init(enum RANDOM_UPDATE_TYPE updata)
{
    uint32_t trng_data_start;
    uint32_t trng_data_end;
    uint32_t buffer_length;
    uint32_t trng2_output = 0;
    switch (updata) {
        case SEC_TRNG2_RAND_BUF_UPDATA_ALL:
            trng_data_start = g_region_start;
            trng_data_end = g_region_start + g_region_length;
            buffer_length = g_region_length;
            break;
        case SEC_TRNG2_RAND_BUF_UPDATA_UP_SIDE:
            trng_data_start = g_region_start;
            trng_data_end = g_region_half_start;
            buffer_length = g_region_half_length;
            break;
        case SEC_TRNG2_RAND_BUF_UPDATA_DOWN_SIDE:
            trng_data_start = g_region_half_start;
            trng_data_end = g_region_start + g_region_length;
            buffer_length = g_region_half_length;
            break;
        default:
            return;
    }
    memset_s((void *)(uintptr_t)trng_data_start, buffer_length, 0, buffer_length);
    while ((trng_data_end - trng_data_start) >= sizeof(trng2_output)) {
        if (uapi_drv_cipher_trng_get_random(&trng2_output) != EOK) {
            return;
        }
        if (memcpy_s((void *)(uintptr_t)trng_data_start, trng_data_end - trng_data_start, &trng2_output,
                     sizeof(trng2_output)) != EOK) {
            return;
        }
        trng_data_start += sizeof(trng2_output);
    }
    if (memcpy_s((void *)(uintptr_t)trng_data_start, trng_data_end - trng_data_start, &trng2_output,
                 trng_data_end - trng_data_start) != EOK) {
        return;
    }
}
#define TYPE_INDEX 0
#define START_ADDR_INDEX 1
#define DATA_LEN_INDEX 2
#define CCORE_ADDR_TO_ADDR_OFFSET 0x10000000
static void sec_trng2_updata_handler(uint8_t *payload_addr, uint32_t payload_len)
{
    unused(payload_len);
    enum RANDOM_UPDATE_TYPE type = ((uint32_t *)(uintptr_t)payload_addr)[TYPE_INDEX];
    g_region_start = ((uint32_t *)(uintptr_t)payload_addr)[START_ADDR_INDEX] + CCORE_ADDR_TO_ADDR_OFFSET;
    g_region_length = ((uint32_t *)(uintptr_t)payload_addr)[DATA_LEN_INDEX];
    g_region_half_start = g_region_start + (g_region_length >> 1);
    g_region_half_length = g_region_length >> 1;

    switch (type) {
        case SEC_TRNG2_RAND_BUF_UPDATA_ALL:
            sec_trng2_random_buffer_init(SEC_TRNG2_RAND_BUF_UPDATA_ALL);
            break;
        case SEC_TRNG2_RAND_BUF_UPDATA_UP_SIDE:
            sec_trng2_random_buffer_init(SEC_TRNG2_RAND_BUF_UPDATA_UP_SIDE);
            break;
        case SEC_TRNG2_RAND_BUF_UPDATA_DOWN_SIDE:
            sec_trng2_random_buffer_init(SEC_TRNG2_RAND_BUF_UPDATA_DOWN_SIDE);
            break;
        default:
            return ;
    }
    return ;
}

void sec_trng2_updata_reigister(void)
{
    ipc_rx_handler_info_t handler_info;
    handler_info.msg_id = IPC_MSG_UPDATE_SHARE_RANDOM_NUMBER;
    handler_info.cb = sec_trng2_updata_handler;
    (void)uapi_ipc_register_rx_handler(&handler_info);
}