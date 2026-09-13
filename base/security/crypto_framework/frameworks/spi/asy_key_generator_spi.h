/*
 * Copyright (C) 2022-2024 Huawei Device Co., Ltd.
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

#ifndef HCF_ASY_KEY_GENERATOR_SPI_H
#define HCF_ASY_KEY_GENERATOR_SPI_H

#include <stdint.h>
#include "algorithm_parameter.h"
#include "asy_key_params.h"
#include "result.h"
#include "key_pair.h"

#define OPENSSL_ASY_KEYGEN_PARAMS_TYPE "OPENSSL.ASY.KEYGENPARAMS"

#define OPENSSL_RSA_GENERATOR_CLASS "OPENSSL.RSA.KEYGENERATOR"

#define OPENSSL_RSA_PUBKEY_FORMAT "X.509"

#define OPENSSL_RSA_PRIKEY_FORMAT "PKCS#8"

#define OPENSSL_RSA_ALGORITHM "OPENSSL.RSA"

typedef struct HcfAsyKeyGeneratorSpi HcfAsyKeyGeneratorSpi;

struct HcfAsyKeyGeneratorSpi {
    HcfObjectBase base;

    HcfResult (*engineGenerateKeyPair)(HcfAsyKeyGeneratorSpi *self, HcfKeyPair **returnObj);

    HcfResult (*engineConvertKey)(HcfAsyKeyGeneratorSpi *self, HcfParamsSpec *params, HcfBlob *pubKeyBlob,
        HcfBlob *priKeyBlob, HcfKeyPair **returnKeyPair);

    HcfResult (*engineConvertPemKey)(HcfAsyKeyGeneratorSpi *self, HcfParamsSpec *params, const char *pubKeyStr,
        const char *priKeyStr, HcfKeyPair **returnKeyPair);

    HcfResult (*engineGenerateKeyPairBySpec)(const HcfAsyKeyGeneratorSpi *self, const HcfAsyKeyParamsSpec *paramsSpec,
        HcfKeyPair **returnKeyPair);

    HcfResult (*engineGeneratePubKeyBySpec)(const HcfAsyKeyGeneratorSpi *self, const HcfAsyKeyParamsSpec *paramsSpec,
        HcfPubKey **returnPubKey);

    HcfResult (*engineGeneratePriKeyBySpec)(const HcfAsyKeyGeneratorSpi *self, const HcfAsyKeyParamsSpec *paramsSpec,
        HcfPriKey **returnPriKey);
};

#endif
