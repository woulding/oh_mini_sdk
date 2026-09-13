/*
 * Copyright (C) 2023 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,s
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#ifndef ECC_ASY_KEY_COMMON_TEST_H
#define ECC_ASY_KEY_COMMON_TEST_H

#include "result.h"
#include "asy_key_params.h"

#ifdef __cplusplus
extern "C" {
#endif

HcfResult ConstructEcc192CommParamsSpec(HcfAsyKeyParamsSpec **spec);
HcfResult ConstructEcc224CommParamsSpec(HcfAsyKeyParamsSpec **spec);
HcfResult ConstructEcc224PubKeyParamsSpec(HcfAsyKeyParamsSpec **spec);
HcfResult ConstructEcc224PriKeyParamsSpec(HcfAsyKeyParamsSpec **spec);
HcfResult ConstructEcc224KeyPairParamsSpec(HcfAsyKeyParamsSpec **spec);
HcfResult ConstructEcc256CommParamsSpec(HcfAsyKeyParamsSpec **spec);
HcfResult ConstructEcc256PubKeyParamsSpec(HcfAsyKeyParamsSpec **spec);
HcfResult ConstructEcc256PriKeyParamsSpec(HcfAsyKeyParamsSpec **spec);
HcfResult ConstructEcc256KeyPairParamsSpec(HcfAsyKeyParamsSpec **spec);
HcfResult ConstructEcc384CommParamsSpec(HcfAsyKeyParamsSpec **spec);
HcfResult ConstructEcc384PubKeyParamsSpec(HcfAsyKeyParamsSpec **spec);
HcfResult ConstructEcc384PriKeyParamsSpec(HcfAsyKeyParamsSpec **spec);
HcfResult ConstructEcc384KeyPairParamsSpec(HcfAsyKeyParamsSpec **spec);
HcfResult ConstructEcc521CommParamsSpec(HcfAsyKeyParamsSpec **spec);
HcfResult ConstructEcc521PubKeyParamsSpec(HcfAsyKeyParamsSpec **spec);
HcfResult ConstructEcc521PriKeyParamsSpec(HcfAsyKeyParamsSpec **spec);
HcfResult ConstructEcc521KeyPairParamsSpec(HcfAsyKeyParamsSpec **spec);
HcfResult ConstructEcc224ErrCommParamsSpec(HcfAsyKeyParamsSpec **spec);
HcfResult ConstructEcc256ErrCommParamsSpec(HcfAsyKeyParamsSpec **spec);
HcfResult ConstructEcc384ErrCommParamsSpec(HcfAsyKeyParamsSpec **spec);
HcfResult ConstructEcc521ErrCommParamsSpec(HcfAsyKeyParamsSpec **spec);
HcfResult ConstructEcc384ErrKeyPairParamsSpec(HcfAsyKeyParamsSpec **spec);
HcfResult ConstructEcc521ErrKeyPairParamsSpec(HcfAsyKeyParamsSpec **spec);
HcfResult ConstructEcc224ErrPubKeyParamsSpec(HcfAsyKeyParamsSpec **spec);
HcfResult ConstructEcc224ErrPriKeyParamsSpec(HcfAsyKeyParamsSpec **spec);


#ifdef __cplusplus
}
#endif
#endif