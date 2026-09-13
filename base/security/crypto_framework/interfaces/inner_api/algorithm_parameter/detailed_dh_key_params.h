/*
 * Copyright (C) 2023 Huawei Device Co., Ltd.
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

#ifndef HCF_DETAILED_DH_KEY_PARAMS_H
#define HCF_DETAILED_DH_KEY_PARAMS_H

#include <stdint.h>
#include <stdbool.h>

#include "asy_key_params.h"
#include "big_integer.h"

typedef struct HcfDhCommParamsSpec {
    HcfAsyKeyParamsSpec base;
    HcfBigInteger p;
    HcfBigInteger g;
    int length;
} HcfDhCommParamsSpec;

typedef struct HcfDhPubKeyParamsSpec {
    HcfDhCommParamsSpec base;
    HcfBigInteger pk;
} HcfDhPubKeyParamsSpec;

typedef struct HcfDhPriKeyParamsSpec {
    HcfDhCommParamsSpec base;
    HcfBigInteger sk;
} HcfDhPriKeyParamsSpec;

typedef struct HcfDhKeyPairParamsSpec {
    HcfDhCommParamsSpec base;
    HcfBigInteger sk;
    HcfBigInteger pk;
} HcfDhKeyPairParamsSpec;
#ifdef __cplusplus
extern "C" {
#endif

void FreeDhCommParamsSpec(HcfDhCommParamsSpec *spec);

void DestroyDhPubKeySpec(HcfDhPubKeyParamsSpec *spec);

void DestroyDhPriKeySpec(HcfDhPriKeyParamsSpec *spec);

void DestroyDhKeyPairSpec(HcfDhKeyPairParamsSpec *spec);


#ifdef __cplusplus
}
#endif
#endif