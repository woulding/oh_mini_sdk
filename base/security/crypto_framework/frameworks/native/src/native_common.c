/*
 * Copyright (C) 2024 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include "native_common.h"

OH_Crypto_ErrCode GetOhCryptoErrCode(HcfResult errCode)
{
    switch (errCode) {
        case HCF_SUCCESS:
            return CRYPTO_SUCCESS;
        case HCF_INVALID_PARAMS:
            return CRYPTO_INVALID_PARAMS;
        case HCF_NOT_SUPPORT:
            return CRYPTO_NOT_SUPPORTED;
        case HCF_ERR_MALLOC:
            return CRYPTO_MEMORY_ERROR;
        default:
            return CRYPTO_OPERTION_ERROR;
    }
}

OH_Crypto_ErrCode GetOhCryptoErrCodeNew(HcfResult errCode)
{
    switch (errCode) {
        case HCF_SUCCESS:
            return CRYPTO_SUCCESS;
        case HCF_INVALID_PARAMS:
            return CRYPTO_PARAMETER_CHECK_FAILED;
        case HCF_NOT_SUPPORT:
            return CRYPTO_NOT_SUPPORTED;
        case HCF_ERR_MALLOC:
            return CRYPTO_MEMORY_ERROR;
        default:
            return CRYPTO_OPERTION_ERROR;
    }
}

void ReverseUint8Arr(uint8_t *data, size_t len)
{
    for (size_t i = 0; i < (len >> 1); ++i) {
        uint8_t temp = data[i];
        data[i] = data[len - 1 - i];
        data[len - 1 - i] = temp;
    }
}

#define NATIVE_BITS_SIZE 8

uint32_t BigEndianArrToUint32(const uint8_t *data, size_t len)
{
    uint32_t value = 0;

    for (size_t i = 0; i < len; ++i) {
        value |= (uint32_t)(data[i] << ((sizeof(int32_t) - 1 - i) * NATIVE_BITS_SIZE));
    }
    return value;
}

void Uint32TobigEndianArr(uint32_t value, uint8_t *data, size_t len)
{
    for (size_t i = 0; i < len; ++i) {
        data[i] = (value >> ((sizeof(uint32_t) - i - 1) * NATIVE_BITS_SIZE)) & 0xFF;
    }
}
