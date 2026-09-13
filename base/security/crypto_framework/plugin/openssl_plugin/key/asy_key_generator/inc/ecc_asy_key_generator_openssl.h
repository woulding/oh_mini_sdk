/*
 * Copyright (C) 2022 Huawei Device Co., Ltd.
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

#ifndef HCF_ECC_ASY_KEY_GENERATOR_OPENSSL_H
#define HCF_ECC_ASY_KEY_GENERATOR_OPENSSL_H

#include "asy_key_generator_spi.h"
#include "params_parser.h"
#include "result.h"

#ifdef __cplusplus
extern "C" {
#endif

HcfResult HcfAsyKeyGeneratorSpiEccCreate(HcfAsyKeyGenParams *params, HcfAsyKeyGeneratorSpi **returnObj);

#ifdef __cplusplus
}
#endif
#endif
