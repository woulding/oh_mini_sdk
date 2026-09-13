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

#include "x25519_openssl.h"

#include <openssl/bio.h>
#include <openssl/err.h>

#include "algorithm_parameter.h"
#include "openssl_adapter.h"
#include "openssl_class.h"
#include "openssl_common.h"
#include "log.h"
#include "memory.h"
#include "utils.h"

typedef struct {
    HcfKeyAgreementSpi base;
} HcfKeyAgreementSpiX25519OpensslImpl;

static const char *GetX25519Class(void)
{
    return "HcfKeyAgreement.HcfKeyAgreementSpiX25519OpensslImpl";
}

static void DestroyX25519(HcfObjectBase *self)
{
    if (self == NULL) {
        LOGE("Invalid input parameter.");
        return;
    }
    if (!HcfIsClassMatch(self, GetX25519Class())) {
        LOGE("Invalid class of self.");
        return;
    }
    HcfFree(self);
}

static HcfResult EngineGenerateSecret(HcfKeyAgreementSpi *self, HcfPriKey *priKey,
    HcfPubKey *pubKey, HcfBlob *returnSecret)
{
    if ((self == NULL) || (priKey == NULL) || (pubKey == NULL) || (returnSecret == NULL)) {
        LOGE("Invalid input parameter.");
        return HCF_INVALID_PARAMS;
    }
    if ((!HcfIsClassMatch((HcfObjectBase *)self, GetX25519Class())) ||
        (!HcfIsClassMatch((HcfObjectBase *)priKey, OPENSSL_ALG25519_PRIKEY_CLASS)) ||
        (!HcfIsClassMatch((HcfObjectBase *)pubKey, OPENSSL_ALG25519_PUBKEY_CLASS))) {
        LOGE("Invalid class of self.");
        return HCF_INVALID_PARAMS;
    }
    EVP_PKEY *pubPKey = OpensslEvpPkeyDup(((HcfOpensslAlg25519PubKey *)pubKey)->pkey);
    if (pubPKey == NULL) {
        LOGE("Failed to dup public pkey.");
        return HCF_ERR_CRYPTO_OPERATION;
    }
    EVP_PKEY *priPKey = OpensslEvpPkeyDup(((HcfOpensslAlg25519PriKey *)priKey)->pkey);
    if (priPKey == NULL) {
        LOGE("Failed to dup private pkey.");
        OpensslEvpPkeyFree(pubPKey);
        return HCF_ERR_CRYPTO_OPERATION;
    }
    HcfResult res = KeyDerive(priPKey, pubPKey, returnSecret);
    OpensslEvpPkeyFree(priPKey);
    OpensslEvpPkeyFree(pubPKey);
    return res;
}

HcfResult HcfKeyAgreementSpiX25519Create(HcfKeyAgreementParams *params, HcfKeyAgreementSpi **returnObj)
{
    (void)params;
    if ((params == NULL) || (returnObj == NULL)) {
        LOGE("Invalid input parameter.");
        return HCF_INVALID_PARAMS;
    }

    HcfKeyAgreementSpiX25519OpensslImpl *returnImpl = (HcfKeyAgreementSpiX25519OpensslImpl *)HcfMalloc(
        sizeof(HcfKeyAgreementSpiX25519OpensslImpl), 0);
    if (returnImpl == NULL) {
        LOGE("Failed to allocate returnImpl memroy!");
        return HCF_ERR_MALLOC;
    }
    returnImpl->base.base.getClass = GetX25519Class;
    returnImpl->base.base.destroy = DestroyX25519;
    returnImpl->base.engineGenerateSecret = EngineGenerateSecret;

    *returnObj = (HcfKeyAgreementSpi *)returnImpl;
    return HCF_SUCCESS;
}

