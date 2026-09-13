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

#ifndef HCF_DETAILED_ALG_25519_KEY_PARAMS_H
#define HCF_DETAILED_ALG_25519_KEY_PARAMS_H

#include <stdint.h>
#include <stdbool.h>

#include "asy_key_params.h"
#include "big_integer.h"
#include "blob.h"

typedef struct HcfAlg25519PubKeyParamsSpec {
    HcfAsyKeyParamsSpec base;
    HcfBigInteger pk;
} HcfAlg25519PubKeyParamsSpec;

typedef struct HcfAlg25519PriKeyParamsSpec {
    HcfAsyKeyParamsSpec base;
    HcfBigInteger sk;
} HcfAlg25519PriKeyParamsSpec;

typedef struct HcfAlg25519KeyPairParamsSpec {
    HcfAsyKeyParamsSpec base;
    HcfBigInteger sk;
    HcfBigInteger pk;
} HcfAlg25519KeyPairParamsSpec;
#ifdef __cplusplus
extern "C" {
#endif

void DestroyAlg25519PriKeySpec(HcfAlg25519PriKeyParamsSpec *spec);

void DestroyAlg25519PubKeySpec(HcfAlg25519PubKeyParamsSpec *spec);

void DestroyAlg25519KeyPairSpec(HcfAlg25519KeyPairParamsSpec *spec);

#ifdef __cplusplus
}
#endif
#endif