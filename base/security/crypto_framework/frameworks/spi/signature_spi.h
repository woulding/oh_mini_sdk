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

#ifndef HCF_SIGNATURE_SPI_H
#define HCF_SIGNATURE_SPI_H

#include <stdbool.h>
#include "algorithm_parameter.h"
#include "pri_key.h"
#include "pub_key.h"
#include "result.h"
#include "signature.h"

#define OPENSSL_RSA_SIGN_CLASS "OPENSSL.RSA.SIGN"

#define OPENSSL_RSA_VERIFY_CLASS "OPENSSL.RSA.VERIFY"

typedef struct HcfSignSpi HcfSignSpi;

struct HcfSignSpi {
    HcfObjectBase base;

    HcfResult (*engineInit)(HcfSignSpi *self, HcfParamsSpec *params, HcfPriKey *privateKey);

    HcfResult (*engineUpdate)(HcfSignSpi *self, HcfBlob *data);

    HcfResult (*engineSign)(HcfSignSpi *self, HcfBlob *data, HcfBlob *returnSignatureData);

    HcfResult (*engineSetSignSpecInt)(HcfSignSpi *self, SignSpecItem item, int32_t saltLen);

    HcfResult (*engineGetSignSpecString)(HcfSignSpi *self, SignSpecItem item, char **returnString);

    HcfResult (*engineGetSignSpecInt)(HcfSignSpi *self, SignSpecItem item, int32_t *returnInt);

    HcfResult (*engineSetSignSpecUint8Array)(HcfSignSpi *self, SignSpecItem item, HcfBlob blob);

    HcfResult (*engineSetSignSpecBool)(HcfSignSpi *self, SignSpecItem item, bool flag);
};

typedef struct HcfVerifySpi HcfVerifySpi;

struct HcfVerifySpi {
    HcfObjectBase base;

    HcfResult (*engineInit)(HcfVerifySpi *self, HcfParamsSpec *params, HcfPubKey *publicKey);

    HcfResult (*engineUpdate)(HcfVerifySpi *self, HcfBlob *data);

    bool (*engineVerify)(HcfVerifySpi *self, HcfBlob *data, HcfBlob *signatureData);

    HcfResult (*engineRecover)(HcfVerifySpi *self, HcfBlob *signatureData, HcfBlob *rawSignatureData);

    HcfResult (*engineSetVerifySpecInt)(HcfVerifySpi *self, SignSpecItem item, int32_t saltLen);

    HcfResult (*engineGetVerifySpecString)(HcfVerifySpi *self, SignSpecItem item, char **returnString);

    HcfResult (*engineGetVerifySpecInt)(HcfVerifySpi *self, SignSpecItem item, int32_t *returnInt);

    HcfResult (*engineSetVerifySpecUint8Array)(HcfVerifySpi *self, SignSpecItem item, HcfBlob blob);

    HcfResult (*engineSetVerifySpecBool)(HcfVerifySpi *self, SignSpecItem item, bool flag);
};

#endif
