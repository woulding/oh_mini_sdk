/*
 * Copyright (C) 2023 Huawei Device Co., Ltd.
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

#ifndef ECC_COMMON_PARAM_SPEC_H
#define ECC_COMMON_PARAM_SPEC_H

#include <stdint.h>
#include "detailed_ecc_key_params.h"
#include "key_pair.h"
#include "result.h"

#ifdef __cplusplus
extern "C" {
#endif

HcfResult ConstructEccKeyPairCommParamsSpec(const char *algoName, HcfEccCommParamsSpec **spec);
HcfResult ConstructEccKeyPairParamsSpec(const char *algoName, HcfEccCommParamsSpec *eccCommSpec,
    HcfAsyKeyParamsSpec **spec);
HcfResult ConstructEccPubKeyParamsSpec(const char *algoName, HcfEccCommParamsSpec *eccCommSpec,
    HcfAsyKeyParamsSpec **spec);
HcfResult ConstructEccPriKeyParamsSpec(const char *algoName, HcfEccCommParamsSpec *eccCommSpec,
    HcfAsyKeyParamsSpec **spec);
HcfResult GenerateBrainpoolP160r1KeyPair(HcfKeyPair **keyPair);

#ifdef __cplusplus
}
#endif
#endif
