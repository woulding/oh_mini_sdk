/**
 * Copyright (c) HiSilicon (Shanghai) Technologies Co., Ltd. 2023-2023. All rights reserved.
 *
 * Description: Provides trng driver source \n
 *
 * History: \n
 * 2023-03-22, Create file. \n
 */

#include "trng.h"
#include "kapi_trng.h"

#include "sl_common.h"
#include "crypto_osal_adapt.h"

errcode_t uapi_drv_cipher_trng_get_random(uint32_t *randnum)
{
    crypto_service_preprocess();
    int32_t ret = kapi_cipher_trng_get_random(randnum);
    crypto_service_postprocess();
    return crypto_sl_common_get_errcode(ret);
}

errcode_t uapi_drv_cipher_trng_get_random_bytes(uint8_t *randnum, uint32_t size)
{
    crypto_service_preprocess();
    int32_t ret = kapi_cipher_trng_get_multi_random(size, randnum);
    crypto_service_postprocess();
    return crypto_sl_common_get_errcode(ret);
}