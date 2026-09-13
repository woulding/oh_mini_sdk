/*
 * Copyright (C) 2023-2024 Huawei Device Co., Ltd.
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

#ifndef HCF_ECC_COMMON_PARAM_SPEC_GENERATOR_OPENSSL_H
#define HCF_ECC_COMMON_PARAM_SPEC_GENERATOR_OPENSSL_H

#include "blob.h"
#include "ecc_key_util_spi.h"
#include "params_parser.h"
#include "result.h"

#ifdef __cplusplus
extern "C" {
#endif

HcfResult HcfECCCommonParamSpecCreate(HcfAsyKeyGenParams *params, HcfEccCommParamsSpecSpi **returnCommonParamSpec);

HcfResult HcfEngineConvertPoint(const int32_t curveNameValue, HcfBlob *pointBlob, HcfPoint *returnPoint);

HcfResult HcfEngineGetEncodedPoint(const int32_t curveNameValue, HcfPoint *point,
                                   const int32_t formatValue, HcfBlob *returnBlob);

#ifdef __cplusplus
}
#endif
#endif
