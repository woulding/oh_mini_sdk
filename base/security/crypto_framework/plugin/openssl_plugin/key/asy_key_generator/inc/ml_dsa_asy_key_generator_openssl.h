/*
 * Copyright (C) 2026 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * *    http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#ifndef HCF_ML_DSA_ASY_KEY_GENERATOR_OPENSSL_H
#define HCF_ML_DSA_ASY_KEY_GENERATOR_OPENSSL_H

#include "asy_key_generator_spi.h"
#include "params_parser.h"
#include "result.h"

#ifdef __cplusplus
extern "C" {
#endif

HcfResult HcfAsyKeyGeneratorSpiMlDsaCreate(HcfAsyKeyGenParams *params, HcfAsyKeyGeneratorSpi **returnObj);

#define ML_DSA_PRIVATE_SEED 0
#define ML_DSA_PRIVATE_RAW 1
#define ML_DSA_PUBLIC_RAW 2

#ifdef __cplusplus
}
#endif
#endif
