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

#ifndef HCF_DETAILED_DSA_KEY_PARAMS_H
#define HCF_DETAILED_DSA_KEY_PARAMS_H

#include "asy_key_params.h"
#include "big_integer.h"

typedef struct HcfDsaCommParamsSpec HcfDsaCommParamsSpec;

struct HcfDsaCommParamsSpec {
    HcfAsyKeyParamsSpec base;
    HcfBigInteger p;
    HcfBigInteger q;
    HcfBigInteger g;
};

typedef struct HcfDsaPubKeyParamsSpec HcfDsaPubKeyParamsSpec;

struct HcfDsaPubKeyParamsSpec {
    HcfDsaCommParamsSpec base;
    HcfBigInteger pk;
};

typedef struct HcfDsaKeyPairParamsSpec HcfDsaKeyPairParamsSpec;

struct HcfDsaKeyPairParamsSpec {
    HcfDsaCommParamsSpec base;
    HcfBigInteger pk;
    HcfBigInteger sk;
};

#ifdef __cplusplus
extern "C" {
#endif

void FreeDsaCommParamsSpec(HcfDsaCommParamsSpec *spec);

void DestroyDsaPubKeySpec(HcfDsaPubKeyParamsSpec *spec);

void DestroyDsaKeyPairSpec(HcfDsaKeyPairParamsSpec *spec);

#ifdef __cplusplus
}
#endif
#endif
