/*
 * Copyright (C) 2022-2023 Huawei Device Co., Ltd.
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

#ifndef HCF_CIPHER_FACTORY_SPI_H
#define HCF_CIPHER_FACTORY_SPI_H

#include <stdint.h>
#include "cipher.h"
#include "algorithm_parameter.h"
#include "key.h"
#include "blob.h"
#include "result.h"
#include "params_parser.h"

typedef struct HcfCipherGeneratorSpi HcfCipherGeneratorSpi;

struct HcfCipherGeneratorSpi {
    HcfObjectBase base;

    HcfResult (*init)(HcfCipherGeneratorSpi *self, enum HcfCryptoMode opMode,
        HcfKey *key, HcfParamsSpec *params);

    HcfResult (*update)(HcfCipherGeneratorSpi *self, HcfBlob *input, HcfBlob *output);

    HcfResult (*doFinal)(HcfCipherGeneratorSpi *self, HcfBlob *input, HcfBlob *output);

    HcfResult (*setCipherSpecUint8Array)(HcfCipherGeneratorSpi *self, CipherSpecItem item, HcfBlob pSource);

    HcfResult (*getCipherSpecString)(HcfCipherGeneratorSpi *self, CipherSpecItem item, char **returnString);

    HcfResult (*getCipherSpecUint8Array)(HcfCipherGeneratorSpi *self, CipherSpecItem item, HcfBlob *returnUint8Array);
};

#endif
