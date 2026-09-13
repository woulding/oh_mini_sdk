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

#include "ecdh_openssl.h"

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
} HcfKeyAgreementSpiEcdhOpensslImpl;

static EVP_PKEY *AssignEcKeyToPkey(EC_KEY *ecKey)
{
    EVP_PKEY *pKey = OpensslEvpPkeyNew();
    if (pKey == NULL) {
        HcfPrintOpensslError();
        return NULL;
    }
    if (OpensslEvpPkeyAssignEcKey(pKey, ecKey) != HCF_OPENSSL_SUCCESS) {
        HcfPrintOpensslError();
        OpensslEvpPkeyFree(pKey);
        return NULL;
    }
    return pKey;
}

static EVP_PKEY *NewPKeyByEccPubKey(HcfOpensslEccPubKey *publicKey)
{
    EC_KEY *ecKey = OpensslEcKeyDup(publicKey->ecKey);
    if (ecKey == NULL) {
        LOGE("ecKey is NULL.");
        return NULL;
    }
    EVP_PKEY *res = AssignEcKeyToPkey(ecKey);
    if (res == NULL) {
        LOGE("Failed to assign EC key to EVP_PKEY.");
        OpensslEcKeyFree(ecKey);
    }
    return res;
}

static EVP_PKEY *NewPKeyByEccPriKey(HcfOpensslEccPriKey *privateKey)
{
    EC_KEY *ecKey = OpensslEcKeyDup(privateKey->ecKey);
    if (ecKey == NULL) {
        LOGE("EcKey dup failed.");
        return NULL;
    }
    EVP_PKEY *res = AssignEcKeyToPkey(ecKey);
    if (res == NULL) {
        OpensslEcKeyFree(ecKey);
    }
    return res;
}

static const char *GetEcdhClass(void)
{
    return "HcfKeyAgreement.HcfKeyAgreementSpiEcdhOpensslImpl";
}

static void DestroyEcdh(HcfObjectBase *self)
{
    if (self == NULL) {
        return;
    }
    if (!HcfIsClassMatch(self, GetEcdhClass())) {
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
    if ((!HcfIsClassMatch((HcfObjectBase *)self, GetEcdhClass())) ||
        (!HcfIsClassMatch((HcfObjectBase *)priKey, HCF_OPENSSL_ECC_PRI_KEY_CLASS)) ||
        (!HcfIsClassMatch((HcfObjectBase *)pubKey, HCF_OPENSSL_ECC_PUB_KEY_CLASS))) {
        return HCF_INVALID_PARAMS;
    }

    EVP_PKEY *priPKey = NewPKeyByEccPriKey((HcfOpensslEccPriKey *)priKey);
    if (priPKey == NULL) {
        LOGE("Gen EVP_PKEY priKey failed");
        return HCF_ERR_CRYPTO_OPERATION;
    }
    EVP_PKEY *pubPKey = NewPKeyByEccPubKey((HcfOpensslEccPubKey *)pubKey);
    if (pubPKey == NULL) {
        LOGE("Gen EVP_PKEY pubKey failed");
        EVP_PKEY_free(priPKey);
        return HCF_ERR_CRYPTO_OPERATION;
    }

    HcfResult res = KeyDerive(priPKey, pubPKey, returnSecret);
    OpensslEvpPkeyFree(priPKey);
    OpensslEvpPkeyFree(pubPKey);
    return res;
}

HcfResult HcfKeyAgreementSpiEcdhCreate(HcfKeyAgreementParams *params, HcfKeyAgreementSpi **returnObj)
{
    (void)params;
    if ((params == NULL) || (returnObj == NULL)) {
        LOGE("Invalid input parameter.");
        return HCF_INVALID_PARAMS;
    }

    HcfKeyAgreementSpiEcdhOpensslImpl *returnImpl = (HcfKeyAgreementSpiEcdhOpensslImpl *)HcfMalloc(
        sizeof(HcfKeyAgreementSpiEcdhOpensslImpl), 0);
    if (returnImpl == NULL) {
        LOGE("Failed to allocate returnImpl memroy!");
        return HCF_ERR_MALLOC;
    }
    returnImpl->base.base.getClass = GetEcdhClass;
    returnImpl->base.base.destroy = DestroyEcdh;
    returnImpl->base.engineGenerateSecret = EngineGenerateSecret;

    *returnObj = (HcfKeyAgreementSpi *)returnImpl;
    return HCF_SUCCESS;
}
