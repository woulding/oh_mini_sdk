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

#ifndef HCF_RAND_SPI_H
#define HCF_RAND_SPI_H

#include <stdint.h>
#include "result.h"
#include "blob.h"
#include "object_base.h"

#define OPENSSL_RAND_ALGORITHM "CTR_DRBG"
#define MBEDTLS_RAND_ALGORITHM "CTR_DRBG_MBEDTLS"

typedef struct HcfRandSpi HcfRandSpi;

struct HcfRandSpi {
    HcfObjectBase base;

    const char *(*engineGetAlgoName)(HcfRandSpi *self);

    HcfResult (*engineGenerateRandom)(HcfRandSpi *self, int32_t numBytes, HcfBlob *random);

    void (*engineSetSeed)(HcfRandSpi *self, HcfBlob *seed);

    HcfResult (*engineEnableHardwareEntropy)(HcfRandSpi *self);
};

#endif