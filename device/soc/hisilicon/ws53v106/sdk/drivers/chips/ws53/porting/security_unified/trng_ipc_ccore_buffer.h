/**
 * Copyright (c) HiSilicon (Shanghai) Technologies Co., Ltd. 2023-2023. All rights reserved.
 *
 * Description: Provides tsensor port \n
 *
 * History: \n
 * 2023-07-20， Create file. \n
 */
#ifndef WS53_INCLUDE_TRNG_IPC_CCORE_BUFFER_H
#define WS53_INCLUDE_TRNG_IPC_CCORE_BUFFER_H

#include <stdint.h>
#include "errcode.h"

enum RANDOM_UPDATE_TYPE {
    SEC_TRNG2_RAND_BUF_UPDATA_ALL = 0,
    SEC_TRNG2_RAND_BUF_UPDATA_UP_SIDE,
    SEC_TRNG2_RAND_BUF_UPDATA_DOWN_SIDE
};

errcode_t sec_trng_random_buffer_init(uint32_t length, uint32_t once_get_max);
errcode_t sec_trng_random_get(uint8_t *trng_buffer, uint32_t trng_buffer_length);
errcode_t sec_trng_random_buffer_update(enum RANDOM_UPDATE_TYPE updata);

#endif