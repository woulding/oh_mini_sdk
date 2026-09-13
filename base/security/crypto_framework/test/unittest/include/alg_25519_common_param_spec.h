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

#ifndef ALG_25519_COMMON_PARAM_SPEC_H
#define ALG_25519_COMMON_PARAM_SPEC_H

#include <stdint.h>
#include "asy_key_generator.h"
#include "detailed_alg_25519_key_params.h"
#include "result.h"

#ifdef __cplusplus
extern "C" {
#endif

HcfResult ConstructAlg25519KeyPairParamsSpec(const char *algoName, bool choose, HcfAsyKeyParamsSpec **spec);
HcfResult ConstructAlg25519PubKeyParamsSpec(const char *algoName, bool choose, HcfAsyKeyParamsSpec **spec);
HcfResult ConstructAlg25519PriKeyParamsSpec(const char *algoName, bool choose, HcfAsyKeyParamsSpec **spec);

HcfResult TestHcfAsyKeyGeneratorCreate(const char *algName, HcfAsyKeyGenerator **generator);
HcfResult TestGenerateKeyPair(HcfAsyKeyGenerator *generator, HcfKeyPair **keyPair);
HcfResult TestKeyGeneratorAndGenerateKeyPair(const char *algName, HcfAsyKeyGenerator **generator, HcfKeyPair **keyPair);
HcfResult TestGenerateConvertKey(HcfAsyKeyGenerator *generator, HcfBlob *pubKeyBlob, HcfBlob *priKeyBlob,
    HcfKeyPair **keyPair);
HcfResult TestGenerateKeyPairAndConvertKey(const char *algName, HcfAsyKeyGenerator **generator, HcfBlob *pubKeyBlob,
    HcfBlob *priKeyBlob, HcfKeyPair **keyPair);
HcfResult TestCreateKeyPairParamsSpecAndGeneratorBySpec(const char *algName, bool choose,
    HcfAsyKeyParamsSpec **paramSpec, HcfAsyKeyGeneratorBySpec **generator);
HcfResult TestCreatePubKeyParamsSpecAndGeneratorBySpec(const char *algName, bool choose,
    HcfAsyKeyParamsSpec **paramSpec, HcfAsyKeyGeneratorBySpec **generator);
HcfResult TestCreatePriKeyParamsSpecAndGeneratorBySpec(const char *algName, bool choose,
    HcfAsyKeyParamsSpec **paramSpec, HcfAsyKeyGeneratorBySpec **generator);

#ifdef __cplusplus
}
#endif
#endif
