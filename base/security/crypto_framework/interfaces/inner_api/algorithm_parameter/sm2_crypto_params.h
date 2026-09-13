/*
 * Copyright (C) 2024 Huawei Device Co., Ltd.
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

#ifndef HCF_SM2_CRYPTO_PARAMS_H
#define HCF_SM2_CRYPTO_PARAMS_H

#include "big_integer.h"
#include "blob.h"

typedef struct Sm2CipherTextSpec {
    HcfBigInteger xCoordinate;
    HcfBigInteger yCoordinate;
    HcfBlob cipherTextData;
    HcfBlob hashData;
} Sm2CipherTextSpec;

typedef struct Sm2EcSignatureDataSpec {
    HcfBigInteger rCoordinate;
    HcfBigInteger sCoordinate;
} Sm2EcSignatureDataSpec;

#ifdef __cplusplus
extern "C" {
#endif

void DestroySm2CipherTextSpec(Sm2CipherTextSpec *spec);
void DestroySm2EcSignatureSpec(Sm2EcSignatureDataSpec *spec);

#ifdef __cplusplus
}
#endif
#endif