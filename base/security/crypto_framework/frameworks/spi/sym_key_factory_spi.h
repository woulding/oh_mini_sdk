/*
 * Copyright (C) 2022 Huawei Device Co., Ltd.
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

#ifndef HCF_SYM_KEY_FACTORY_SPI_H
#define HCF_SYM_KEY_FACTORY_SPI_H

#include <stdint.h>
#include "result.h"
#include "sym_key.h"

typedef struct HcfSymKeyGeneratorSpi HcfSymKeyGeneratorSpi;

struct HcfSymKeyGeneratorSpi {
    HcfObjectBase base;
    HcfResult (*engineGenerateSymmKey)(HcfSymKeyGeneratorSpi *self, HcfSymKey **symmKey);
    HcfResult (*engineConvertSymmKey)(HcfSymKeyGeneratorSpi *self, const HcfBlob *key, HcfSymKey **symmKey);
};
#define OPENSSL_SYM_GENERATOR_CLASS "OPENSSL.SYM.KEYGENERATOR"
#define OPENSSL_SYM_KEY_CLASS "OPENSSL.SYM.KEY"

#endif // HCF_SYMM_KEY_FACTORY_SPI_H
