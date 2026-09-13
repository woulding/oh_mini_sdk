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

#include "ed25519_openssl.h"

#include <openssl/bio.h>
#include <openssl/err.h>

#include "securec.h"

#include "algorithm_parameter.h"
#include "openssl_adapter.h"
#include "openssl_class.h"
#include "openssl_common.h"
#include "log.h"
#include "memory.h"
#include "utils.h"

#define OPENSSL_ED25519_SIGN_CLASS "OPENSSL.ED25519.SIGN"
#define OPENSSL_ED25519_VERIFY_CLASS "OPENSSL.ED25519.VERIFY"

typedef struct {
    HcfSignSpi base;

    EVP_MD_CTX *mdCtx;

    CryptoStatus status;
} HcfSignSpiEd25519OpensslImpl;

typedef struct {
    HcfVerifySpi base;

    EVP_MD_CTX *mdCtx;

    CryptoStatus status;
} HcfVerifySpiEd25519OpensslImpl;

static const char *GetEd25519SignClass(void)
{
    return OPENSSL_ED25519_SIGN_CLASS;
}

static const char *GetEd25519VerifyClass(void)
{
    return OPENSSL_ED25519_VERIFY_CLASS;
}

static void DestroyEd25519Sign(HcfObjectBase *self)
{
    if (self == NULL) {
        LOGE("Class is null.");
        return;
    }
    if (!HcfIsClassMatch(self, self->getClass())) {
        LOGE("Class not match.");
        return;
    }
    HcfSignSpiEd25519OpensslImpl *impl = (HcfSignSpiEd25519OpensslImpl *)self;
    if (impl->mdCtx != NULL) {
        OpensslEvpMdCtxFree(impl->mdCtx);
        impl->mdCtx = NULL;
    }
    HcfFree(impl);
}

static void DestroyEd25519Verify(HcfObjectBase *self)
{
    if (self == NULL) {
        LOGE("Class is null.");
        return;
    }
    if (!HcfIsClassMatch(self, self->getClass())) {
        LOGE("Class not match.");
        return;
    }
    HcfVerifySpiEd25519OpensslImpl *impl = (HcfVerifySpiEd25519OpensslImpl *)self;
    if (impl->mdCtx != NULL) {
        OpensslEvpMdCtxFree(impl->mdCtx);
        impl->mdCtx = NULL;
    }
    HcfFree(impl);
}

static HcfResult EngineSignInit(HcfSignSpi *self, HcfParamsSpec *params, HcfPriKey *privateKey)
{
    (void)params;
    if ((self == NULL) || (privateKey == NULL)) {
        LOGE("Invalid input parameter.");
        return HCF_INVALID_PARAMS;
    }
    if ((!HcfIsClassMatch((HcfObjectBase *)self, self->base.getClass())) ||
        (!HcfIsClassMatch((HcfObjectBase *)privateKey, OPENSSL_ALG25519_PRIKEY_CLASS))) {
        LOGE("Class not match.");
        return HCF_INVALID_PARAMS;
    }

    HcfSignSpiEd25519OpensslImpl *impl = (HcfSignSpiEd25519OpensslImpl *)self;
    if (impl->status != UNINITIALIZED) {
        LOGE("Repeated initialization is not allowed.");
        return HCF_INVALID_PARAMS;
    }

    if (OpensslEvpDigestSignInit(impl->mdCtx, NULL, NULL, NULL,
        ((HcfOpensslAlg25519PriKey *)privateKey)->pkey) != HCF_OPENSSL_SUCCESS) {
        HcfPrintOpensslError();
        LOGE("EVP_DigestSignInit failed.");
        return HCF_ERR_CRYPTO_OPERATION;
    }
    impl->status = INITIALIZED;
    return HCF_SUCCESS;
}

static HcfResult EngineSignUpdate(HcfSignSpi *self, HcfBlob *data)
{
    (void)self;
    (void)data;
    LOGE("Ed25519 sign update not supported.");
    return HCF_INVALID_PARAMS;
}

static HcfResult EngineSignDoFinal(HcfSignSpi *self, HcfBlob *data, HcfBlob *returnSignatureData)
{
    if ((self == NULL) || (returnSignatureData == NULL)) {
        LOGE("Invalid input parameter.");
        return HCF_INVALID_PARAMS;
    }
    if (!HcfIsClassMatch((HcfObjectBase *)self, self->base.getClass())) {
        LOGE("Class not match.");
        return HCF_INVALID_PARAMS;
    }
    if (!HcfIsBlobValid(data)) {
        LOGE("Invalid sign data.");
        return HCF_INVALID_PARAMS;
    }
    HcfSignSpiEd25519OpensslImpl *impl = (HcfSignSpiEd25519OpensslImpl *)self;
    if (impl->status != INITIALIZED) {
        LOGE("The message has not been initialized.");
        return HCF_INVALID_PARAMS;
    }
    size_t siglen;
    if (OpensslEvpDigestSign(impl->mdCtx, NULL, &siglen, data->data, data->len) != HCF_OPENSSL_SUCCESS) {
        HcfPrintOpensslError();
        LOGE("EVP_DigestSign failed.");
        return HCF_ERR_CRYPTO_OPERATION;
    }
    uint8_t *signatureData = (uint8_t *)HcfMalloc(siglen, 0);
    if (signatureData == NULL) {
        LOGE("Failed to allocate signatureData memory!");
        return HCF_ERR_MALLOC;
    }
    if (OpensslEvpDigestSign(impl->mdCtx, signatureData, &siglen, data->data, data->len) != HCF_OPENSSL_SUCCESS) {
        HcfPrintOpensslError();
        LOGE("EVP_DigestSign failed.");
        HcfFree(signatureData);
        signatureData = NULL;
        return HCF_ERR_CRYPTO_OPERATION;
    }
    returnSignatureData->data = signatureData;
    returnSignatureData->len = (uint32_t)siglen;
    return HCF_SUCCESS;
}

static HcfResult EngineVerifyInit(HcfVerifySpi *self, HcfParamsSpec *params, HcfPubKey *publicKey)
{
    (void)params;
    if ((self == NULL) || (publicKey == NULL)) {
        LOGE("Invalid input parameter.");
        return HCF_INVALID_PARAMS;
    }
    if ((!HcfIsClassMatch((HcfObjectBase *)self, self->base.getClass())) ||
        (!HcfIsClassMatch((HcfObjectBase *)publicKey, OPENSSL_ALG25519_PUBKEY_CLASS))) {
        LOGE("Class not match.");
        return HCF_INVALID_PARAMS;
    }

    HcfVerifySpiEd25519OpensslImpl *impl = (HcfVerifySpiEd25519OpensslImpl *)self;
    if (impl->status != UNINITIALIZED) {
        LOGE("Repeated initialization is not allowed.");
        return HCF_INVALID_PARAMS;
    }
    EVP_PKEY *pKey = OpensslEvpPkeyDup(((HcfOpensslAlg25519PubKey *)publicKey)->pkey);
    if (pKey == NULL) {
        HcfPrintOpensslError();
        LOGE("Dup pkey failed.");
        return HCF_ERR_CRYPTO_OPERATION;
    }
    if (OpensslEvpDigestVerifyInit(impl->mdCtx, NULL, NULL, NULL, pKey) != HCF_OPENSSL_SUCCESS) {
        HcfPrintOpensslError();
        LOGE("EVP_DigestVerifyInit failed.");
        OpensslEvpPkeyFree(pKey);
        return HCF_ERR_CRYPTO_OPERATION;
    }
    OpensslEvpPkeyFree(pKey);
    impl->status = INITIALIZED;
    return HCF_SUCCESS;
}

static HcfResult EngineVerifyUpdate(HcfVerifySpi *self, HcfBlob *data)
{
    (void)self;
    (void)data;
    LOGE("Ed25519 verify update not supported.");
    return HCF_INVALID_PARAMS;
}

static bool EngineVerifyDoFinal(HcfVerifySpi *self, HcfBlob *data, HcfBlob *signatureData)
{
    if ((self == NULL) || (!HcfIsBlobValid(signatureData))) {
        LOGE("Invalid input parameter.");
        return false;
    }
    if (!HcfIsClassMatch((HcfObjectBase *)self, self->base.getClass())) {
        LOGE("Class not match.");
        return false;
    }
    if (!HcfIsBlobValid(data)) {
        LOGE("Invalid verify data.");
        return false;
    }
    HcfVerifySpiEd25519OpensslImpl *impl = (HcfVerifySpiEd25519OpensslImpl *)self;
    if (impl->status != INITIALIZED) {
        LOGE("The message has not been initialized.");
        return false;
    }
    if (OpensslEvpDigestVerify(impl->mdCtx, signatureData->data, signatureData->len,
        data->data, data->len) != HCF_OPENSSL_SUCCESS) {
        HcfPrintOpensslError();
        LOGE("EVP_DigestVerify failed.");
        return false;
    }
    return true;
}

static HcfResult EngineGetSignSpecString(HcfSignSpi *self, SignSpecItem item, char **returnString)
{
    (void)self;
    (void)item;
    (void)returnString;
    return HCF_NOT_SUPPORT;
}

static HcfResult EngineSetSignSpecUint8Array(HcfSignSpi *self, SignSpecItem item, HcfBlob userId)
{
    (void)self;
    (void)item;
    (void)userId;
    return HCF_NOT_SUPPORT;
}

static HcfResult EngineGetSignSpecInt(HcfSignSpi *self, SignSpecItem item, int32_t *returnInt)
{
    (void)self;
    (void)item;
    (void)returnInt;
    return HCF_NOT_SUPPORT;
}

static HcfResult EngineSetSignSpecInt(HcfSignSpi *self, SignSpecItem item, int32_t saltLen)
{
    (void)self;
    (void)item;
    (void)saltLen;
    return HCF_NOT_SUPPORT;
}

static HcfResult EngineGetVerifySpecString(HcfVerifySpi *self, SignSpecItem item, char **returnString)
{
    (void)self;
    (void)item;
    (void)returnString;
    return HCF_NOT_SUPPORT;
}

static HcfResult EngineSetVerifySpecUint8Array(HcfVerifySpi *self, SignSpecItem item, HcfBlob userId)
{
    (void)self;
    (void)item;
    (void)userId;
    return HCF_NOT_SUPPORT;
}

static HcfResult EngineGetVerifySpecInt(HcfVerifySpi *self, SignSpecItem item, int32_t *returnInt)
{
    (void)self;
    (void)item;
    (void)returnInt;
    return HCF_NOT_SUPPORT;
}

static HcfResult EngineSetVerifySpecInt(HcfVerifySpi *self, SignSpecItem item, int32_t saltLen)
{
    (void)self;
    (void)item;
    (void)saltLen;
    return HCF_NOT_SUPPORT;
}

HcfResult HcfSignSpiEd25519Create(HcfSignatureParams *params, HcfSignSpi **returnObj)
{
    (void)params;
    if ((params == NULL) || (returnObj == NULL)) {
        LOGE("Invalid input parameter.");
        return HCF_INVALID_PARAMS;
    }

    HcfSignSpiEd25519OpensslImpl *returnImpl = (HcfSignSpiEd25519OpensslImpl *)HcfMalloc(
        sizeof(HcfSignSpiEd25519OpensslImpl), 0);
    if (returnImpl == NULL) {
        LOGE("Failed to allocate returnImpl memroy!");
        return HCF_ERR_MALLOC;
    }
    returnImpl->base.base.getClass = GetEd25519SignClass;
    returnImpl->base.base.destroy = DestroyEd25519Sign;
    returnImpl->base.engineInit = EngineSignInit;
    returnImpl->base.engineUpdate = EngineSignUpdate;
    returnImpl->base.engineSign = EngineSignDoFinal;
    returnImpl->base.engineGetSignSpecString = EngineGetSignSpecString;
    returnImpl->base.engineSetSignSpecUint8Array = EngineSetSignSpecUint8Array;
    returnImpl->base.engineGetSignSpecInt = EngineGetSignSpecInt;
    returnImpl->base.engineSetSignSpecInt = EngineSetSignSpecInt;
    returnImpl->status = UNINITIALIZED;
    returnImpl->mdCtx = OpensslEvpMdCtxNew();
    if (returnImpl->mdCtx == NULL) {
        LOGE("Failed to allocate mdCtx memory!");
        HcfFree(returnImpl);
        returnImpl = NULL;
        return HCF_ERR_MALLOC;
    }

    *returnObj = (HcfSignSpi *)returnImpl;
    return HCF_SUCCESS;
}

HcfResult HcfVerifySpiEd25519Create(HcfSignatureParams *params, HcfVerifySpi **returnObj)
{
    (void)params;
    if ((params == NULL) || (returnObj == NULL)) {
        LOGE("Invalid input parameter.");
        return HCF_INVALID_PARAMS;
    }

    HcfVerifySpiEd25519OpensslImpl *returnImpl = (HcfVerifySpiEd25519OpensslImpl *)HcfMalloc(
        sizeof(HcfVerifySpiEd25519OpensslImpl), 0);
    if (returnImpl == NULL) {
        LOGE("Failed to allocate returnImpl memroy!");
        return HCF_ERR_MALLOC;
    }
    returnImpl->base.base.getClass = GetEd25519VerifyClass;
    returnImpl->base.base.destroy = DestroyEd25519Verify;
    returnImpl->base.engineInit = EngineVerifyInit;
    returnImpl->base.engineUpdate = EngineVerifyUpdate;
    returnImpl->base.engineVerify = EngineVerifyDoFinal;
    returnImpl->base.engineGetVerifySpecString = EngineGetVerifySpecString;
    returnImpl->base.engineSetVerifySpecUint8Array = EngineSetVerifySpecUint8Array;
    returnImpl->base.engineGetVerifySpecInt = EngineGetVerifySpecInt;
    returnImpl->base.engineSetVerifySpecInt = EngineSetVerifySpecInt;
    returnImpl->status = UNINITIALIZED;
    returnImpl->mdCtx = OpensslEvpMdCtxNew();
    if (returnImpl->mdCtx == NULL) {
        LOGE("Failed to allocate mdCtx memory!");
        HcfFree(returnImpl);
        returnImpl = NULL;
        return HCF_ERR_MALLOC;
    }

    *returnObj = (HcfVerifySpi *)returnImpl;
    return HCF_SUCCESS;
}
