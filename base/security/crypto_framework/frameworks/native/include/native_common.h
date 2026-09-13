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

#ifndef NATIVE_COMMON_H
#define NATIVE_COMMON_H

#include "result.h"
#include "crypto_common.h"

#ifdef __cplusplus
extern "C" {
#endif

OH_Crypto_ErrCode GetOhCryptoErrCode(HcfResult errCode);
OH_Crypto_ErrCode GetOhCryptoErrCodeNew(HcfResult errCode);

void ReverseUint8Arr(uint8_t *data, size_t len);
uint32_t BigEndianArrToUint32(const uint8_t *data, size_t len);
void Uint32TobigEndianArr(uint32_t value, uint8_t *data, size_t len);
#ifdef __cplusplus
}
#endif

#endif /* NATIVE_COMMON_H */