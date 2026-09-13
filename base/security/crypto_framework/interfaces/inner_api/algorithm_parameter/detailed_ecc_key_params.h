/*
 * Copyright (C) 2023-2024 Huawei Device Co., Ltd.
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

#ifndef HCF_DETAILED_ECC_KEY_PARAMS_H
#define HCF_DETAILED_ECC_KEY_PARAMS_H

#include <stdint.h>
#include <stdbool.h>

#include "asy_key_params.h"
#include "big_integer.h"

typedef struct HcfECField {
    char *fieldType;
} HcfECField;

typedef struct HcfECFieldFp {
    HcfECField base;
    HcfBigInteger p;
} HcfECFieldFp;

typedef struct HcfPoint HcfPoint;
struct HcfPoint {
    HcfBigInteger x;
    HcfBigInteger y;
};

typedef struct HcfEccCommParamsSpec {
    HcfAsyKeyParamsSpec base;
    HcfECField *field;
    HcfBigInteger a;
    HcfBigInteger b;
    HcfPoint g;
    HcfBigInteger n;
    int32_t h;
} HcfEccCommParamsSpec;

typedef struct HcfEccPubKeyParamsSpec {
    HcfEccCommParamsSpec base;
    HcfPoint pk;
} HcfEccPubKeyParamsSpec;

typedef struct HcfEccPriKeyParamsSpec {
    HcfEccCommParamsSpec base;
    HcfBigInteger sk;
} HcfEccPriKeyParamsSpec;

typedef struct HcfEccKeyPairParamsSpec {
    HcfEccCommParamsSpec base;
    HcfBigInteger sk;
    HcfPoint pk;
} HcfEccKeyPairParamsSpec;
#ifdef __cplusplus
extern "C" {
#endif

void FreeEcPointMem(HcfPoint *point);

void FreeEccCommParamsSpec(HcfEccCommParamsSpec *spec);

void DestroyEccPriKeySpec(HcfEccPriKeyParamsSpec *spec);

void DestroyEccPubKeySpec(HcfEccPubKeyParamsSpec *spec);

void DestroyEccKeyPairSpec(HcfEccKeyPairParamsSpec *spec);

#ifdef __cplusplus
}
#endif
#endif