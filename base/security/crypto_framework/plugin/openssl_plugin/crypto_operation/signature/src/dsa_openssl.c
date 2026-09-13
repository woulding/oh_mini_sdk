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

#include "dsa_openssl.h"

#include <openssl/evp.h>

#include "log.h"
#include "memory.h"
#include "openssl_adapter.h"
#include "openssl_common.h"
#include "openssl_class.h"
#include "utils.h"

#define OPENSSL_DSA_SIGN_CLASS "OPENSSL.DSA.SIGN"
#define OPENSSL_DSA_VERIFY_CLASS "OPENSSL.DSA.VERIFY"

typedef struct {
    HcfSignSpi base;

    const EVP_MD *digestAlg;

    EVP_MD_CTX *mdCtx;

    EVP_PKEY_CTX *pkeyCtx;

    CryptoStatus status;
} HcfSignSpiDsaOpensslImpl;

typedef struct {
    HcfVerifySpi base;

    const EVP_MD *digestAlg;

    EVP_MD_CTX *mdCtx;

    EVP_PKEY_CTX *pkeyCtx;

    CryptoStatus status;
} HcfVerifySpiDsaOpensslImpl;

static const char *GetDsaSignClass(void)
{
    return OPENSSL_DSA_SIGN_CLASS;
}

static const char *GetDsaVerifyClass(void)
{
    return OPENSSL_DSA_VERIFY_CLASS;
}

static bool IsSignInitInputValid(HcfSignSpi *self, HcfPriKey *privateKey)
{
    if ((self == NULL) || (privateKey == NULL)) {
        LOGE("Invalid input parameter.");
        return false;
    }
    if ((!HcfIsClassMatch((HcfObjectBase *)self, GetDsaSignClass())) ||
        (!HcfIsClassMatch((HcfObjectBase *)privateKey, OPENSSL_DSA_PRIKEY_CLASS))) {
        return false;
    }
    HcfSignSpiDsaOpensslImpl *impl = (HcfSignSpiDsaOpensslImpl *)self;
    if (impl->status != UNINITIALIZED) {
        LOGE("Repeated initialization is not allowed.");
        return false;
    }
    return true;
}

static bool IsVerifyInitInputValid(HcfVerifySpi *self, HcfPubKey *publicKey)
{
    if ((self == NULL) || (publicKey == NULL)) {
        LOGE("Invalid input parameter.");
        return false;
    }
    if ((!HcfIsClassMatch((HcfObjectBase *)self, GetDsaVerifyClass())) ||
        (!HcfIsClassMatch((HcfObjectBase *)publicKey, OPENSSL_DSA_PUBKEY_CLASS))) {
        return false;
    }
    HcfVerifySpiDsaOpensslImpl *impl = (HcfVerifySpiDsaOpensslImpl *)self;
    if (impl->status != UNINITIALIZED) {
        LOGE("Repeated initialization is not allowed.");
        return false;
    }
    return true;
}

static bool IsSignDoFinalInputValid(HcfSignSpi *self, HcfBlob *returnSignatureData)
{
    if ((self == NULL) || (returnSignatureData == NULL)) {
        LOGE("Invalid input parameter.");
        return false;
    }
    if (!HcfIsClassMatch((HcfObjectBase *)self, GetDsaSignClass())) {
        return false;
    }
    return true;
}

static bool IsVerifyDoFinalInputValid(HcfVerifySpi *self, HcfBlob *signatureData)
{
    if ((self == NULL) || (!HcfIsBlobValid(signatureData))) {
        LOGE("Invalid input parameter.");
        return false;
    }
    if (!HcfIsClassMatch((HcfObjectBase *)self, GetDsaVerifyClass())) {
        return false;
    }
    return true;
}

static void DestroyDsaSign(HcfObjectBase *self)
{
    if (self == NULL) {
        return;
    }

    if (!HcfIsClassMatch(self, GetDsaSignClass())) {
        return;
    }
    HcfSignSpiDsaOpensslImpl *impl = (HcfSignSpiDsaOpensslImpl *)self;
    if (impl->mdCtx != NULL) {
        OpensslEvpMdCtxFree(impl->mdCtx);
        impl->mdCtx = NULL;
    }
    if (impl->pkeyCtx != NULL) {
        OpensslEvpPkeyCtxFree(impl->pkeyCtx);
        impl->pkeyCtx = NULL;
    }
    HcfFree(impl);
}

static void DestroyDsaVerify(HcfObjectBase *self)
{
    if (self == NULL) {
        return;
    }
    if (!HcfIsClassMatch(self, GetDsaVerifyClass())) {
        return;
    }
    HcfVerifySpiDsaOpensslImpl *impl = (HcfVerifySpiDsaOpensslImpl *)self;
    if (impl->mdCtx != NULL) {
        OpensslEvpMdCtxFree(impl->mdCtx);
        impl->mdCtx = NULL;
    }
    if (impl->pkeyCtx != NULL) {
        OpensslEvpPkeyCtxFree(impl->pkeyCtx);
        impl->pkeyCtx = NULL;
    }
    HcfFree(impl);
}

static EVP_PKEY *CreateDsaEvpKeyByDsa(HcfKey *key, bool isSign)
{
    EVP_PKEY *pKey = OpensslEvpPkeyNew();
    if (pKey == NULL) {
        LOGE("EVP_PKEY_new fail");
        HcfPrintOpensslError();
        return NULL;
    }
    DSA *dsa = isSign ? ((HcfOpensslDsaPriKey *)key)->sk : ((HcfOpensslDsaPubKey *)key)->pk;
    if (dsa == NULL) {
        LOGE("dsa has been cleared");
        EVP_PKEY_free(pKey);
        return NULL;
    }
    if (OpensslEvpPkeySet1Dsa(pKey, dsa) != HCF_OPENSSL_SUCCESS) {
        LOGE("EVP_PKEY_set1_DSA fail");
        HcfPrintOpensslError();
        EVP_PKEY_free(pKey);
        return NULL;
    }
    return pKey;
}

static HcfResult EngineDsaSignInit(HcfSignSpi *self, HcfParamsSpec *params, HcfPriKey *privateKey)
{
    (void)params;
    if (!IsSignInitInputValid(self, privateKey)) {
        return HCF_INVALID_PARAMS;
    }
    EVP_PKEY *pKey = CreateDsaEvpKeyByDsa((HcfKey *)privateKey, true);
    if (pKey == NULL) {
        LOGE("Create DSA evp key failed!");
        return HCF_ERR_CRYPTO_OPERATION;
    }
    HcfSignSpiDsaOpensslImpl *impl = (HcfSignSpiDsaOpensslImpl *)self;
    if (OpensslEvpDigestSignInit(impl->mdCtx, NULL, impl->digestAlg, NULL, pKey) != HCF_OPENSSL_SUCCESS) {
        LOGE("Failed to initialize digest signing.");
        HcfPrintOpensslError();
        OpensslEvpPkeyFree(pKey);
        return HCF_ERR_CRYPTO_OPERATION;
    }

    OpensslEvpPkeyFree(pKey);
    impl->status = INITIALIZED;
    return HCF_SUCCESS;
}

static HcfResult EngineDsaSignWithoutDigestInit(HcfSignSpi *self, HcfParamsSpec *params, HcfPriKey *privateKey)
{
    (void)params;
    if (!IsSignInitInputValid(self, privateKey)) {
        return HCF_INVALID_PARAMS;
    }
    EVP_PKEY *pKey = CreateDsaEvpKeyByDsa((HcfKey *)privateKey, true);
    if (pKey == NULL) {
        LOGE("Create DSA evp key failed!");
        return HCF_ERR_CRYPTO_OPERATION;
    }
    HcfSignSpiDsaOpensslImpl *impl = (HcfSignSpiDsaOpensslImpl *)self;

    impl->pkeyCtx = OpensslEvpPkeyCtxNew(pKey, NULL);
    if (impl->pkeyCtx == NULL) {
        LOGE("Failed to allocate pkeyCtx.");
        HcfPrintOpensslError();
        OpensslEvpPkeyFree(pKey);
        return HCF_ERR_CRYPTO_OPERATION;
    }
    if (OpensslEvpPkeySignInit(impl->pkeyCtx) != HCF_OPENSSL_SUCCESS) {
        LOGE("Failed to initialize DSA signing.");
        HcfPrintOpensslError();
        OpensslEvpPkeyFree(pKey);
        OpensslEvpPkeyCtxFree(impl->pkeyCtx);
        impl->pkeyCtx = NULL;
        return HCF_ERR_CRYPTO_OPERATION;
    }
    OpensslEvpPkeyFree(pKey);
    impl->status = READY;
    return HCF_SUCCESS;
}

static HcfResult EngineDsaVerifyInit(HcfVerifySpi *self, HcfParamsSpec *params, HcfPubKey *publicKey)
{
    (void)params;
    if (!IsVerifyInitInputValid(self, publicKey)) {
        return HCF_INVALID_PARAMS;
    }
    HcfVerifySpiDsaOpensslImpl *impl = (HcfVerifySpiDsaOpensslImpl *)self;
    EVP_PKEY *pKey = CreateDsaEvpKeyByDsa((HcfKey *)publicKey, false);
    if (pKey == NULL) {
        LOGE("Create DSA evp key failed!");
        return HCF_ERR_CRYPTO_OPERATION;
    }
    if (OpensslEvpDigestVerifyInit(impl->mdCtx, NULL, impl->digestAlg, NULL, pKey) != HCF_OPENSSL_SUCCESS) {
        LOGE("Failed to initialize digest verification.");
        HcfPrintOpensslError();
        OpensslEvpPkeyFree(pKey);
        return HCF_ERR_CRYPTO_OPERATION;
    }

    OpensslEvpPkeyFree(pKey);
    impl->status = INITIALIZED;
    return HCF_SUCCESS;
}

static HcfResult EngineDsaVerifyWithoutDigestInit(HcfVerifySpi *self, HcfParamsSpec *params, HcfPubKey *publicKey)
{
    (void)params;
    if (!IsVerifyInitInputValid(self, publicKey)) {
        return HCF_INVALID_PARAMS;
    }
    HcfVerifySpiDsaOpensslImpl *impl = (HcfVerifySpiDsaOpensslImpl *)self;
    EVP_PKEY *pKey = CreateDsaEvpKeyByDsa((HcfKey *)publicKey, false);
    if (pKey == NULL) {
        LOGE("Create dsa evp key failed!");
        return HCF_ERR_CRYPTO_OPERATION;
    }
    impl->pkeyCtx = OpensslEvpPkeyCtxNew(pKey, NULL);
    if (impl->pkeyCtx == NULL) {
        LOGE("Failed to allocate pkeyCtx.");
        HcfPrintOpensslError();
        OpensslEvpPkeyFree(pKey);
        return HCF_ERR_CRYPTO_OPERATION;
    }
    if (OpensslEvpPkeyVerifyInit(impl->pkeyCtx) != HCF_OPENSSL_SUCCESS) {
        LOGE("Failed to initialize DSA verification.");
        HcfPrintOpensslError();
        OpensslEvpPkeyFree(pKey);
        OpensslEvpPkeyCtxFree(impl->pkeyCtx);
        impl->pkeyCtx = NULL;
        return HCF_ERR_CRYPTO_OPERATION;
    }
    OpensslEvpPkeyFree(pKey);
    impl->status = READY;
    return HCF_SUCCESS;
}

static HcfResult EngineDsaSignUpdate(HcfSignSpi *self, HcfBlob *data)
{
    if ((self == NULL) || (!HcfIsBlobValid(data))) {
        LOGE("Invalid input parameter.");
        return HCF_INVALID_PARAMS;
    }
    if (!HcfIsClassMatch((HcfObjectBase *)self, GetDsaSignClass())) {
        return HCF_INVALID_PARAMS;
    }
    HcfSignSpiDsaOpensslImpl *impl = (HcfSignSpiDsaOpensslImpl *)self;
    if (impl->status == UNINITIALIZED) {
        LOGE("Sign object has not been initialized.");
        return HCF_INVALID_PARAMS;
    }
    if (OpensslEvpDigestSignUpdate(impl->mdCtx, data->data, data->len) != HCF_OPENSSL_SUCCESS) {
        LOGE("Failed to update digest sign data.");
        HcfPrintOpensslError();
        return HCF_ERR_CRYPTO_OPERATION;
    }
    impl->status = READY;
    return HCF_SUCCESS;
}

static HcfResult EngineDsaSignWithoutDigestUpdate(HcfSignSpi *self, HcfBlob *data)
{
    (void)self;
    (void)data;
    LOGE("SignWithoutDigestUpdate not supported.");
    return HCF_ERR_CRYPTO_OPERATION;
}

static HcfResult EngineDsaVerifyUpdate(HcfVerifySpi *self, HcfBlob *data)
{
    if ((self == NULL) || (!HcfIsBlobValid(data))) {
        LOGE("Invalid input parameter.");
        return HCF_INVALID_PARAMS;
    }
    if (!HcfIsClassMatch((HcfObjectBase *)self, GetDsaVerifyClass())) {
        return HCF_INVALID_PARAMS;
    }
    HcfVerifySpiDsaOpensslImpl *impl = (HcfVerifySpiDsaOpensslImpl *)self;
    if (impl->status == UNINITIALIZED) {
        LOGE("Verify object has not been initialized.");
        return HCF_INVALID_PARAMS;
    }

    if (OpensslEvpDigestVerifyUpdate(impl->mdCtx, data->data, data->len) != HCF_OPENSSL_SUCCESS) {
        LOGE("Failed to update digest verify data.");
        HcfPrintOpensslError();
        return HCF_ERR_CRYPTO_OPERATION;
    }
    impl->status = READY;
    return HCF_SUCCESS;
}

static HcfResult EngineDsaVerifyWithoutDigestUpdate(HcfVerifySpi *self, HcfBlob *data)
{
    (void)self;
    (void)data;
    LOGE("VerifyWithoutDigestUpdate not supported.");
    return HCF_ERR_CRYPTO_OPERATION;
}

static HcfResult EngineDsaSignDoFinal(HcfSignSpi *self, HcfBlob *data, HcfBlob *returnSignatureData)
{
    if (!IsSignDoFinalInputValid(self, returnSignatureData)) {
        return HCF_INVALID_PARAMS;
    }
    HcfSignSpiDsaOpensslImpl *impl = (HcfSignSpiDsaOpensslImpl *)self;
    if (impl->status == UNINITIALIZED) {
        LOGW("Sign instance may not have been initialized, "
            "ensure init interface of Sign instance is executed completely!");
    }
    if (HcfIsBlobValid(data)) {
        if (OpensslEvpDigestSignUpdate(impl->mdCtx, data->data, data->len) != HCF_OPENSSL_SUCCESS) {
            LOGE("Failed to update digest sign data.");
            HcfPrintOpensslError();
            return HCF_ERR_CRYPTO_OPERATION;
        }
        impl->status = READY;
    }
    if (impl->status != READY) {
        LOGE("The message has not been transferred.");
        return HCF_INVALID_PARAMS;
    }
    size_t maxLen;
    if (OpensslEvpDigestSignFinal(impl->mdCtx, NULL, &maxLen) != HCF_OPENSSL_SUCCESS) {
        LOGE("Failed to finalize digest signing.");
        HcfPrintOpensslError();
        return HCF_ERR_CRYPTO_OPERATION;
    }
    uint8_t *signatureData = (uint8_t *)HcfMalloc(maxLen, 0);
    if (signatureData == NULL) {
        LOGE("Failed to allocate signatureData memory!");
        return HCF_ERR_MALLOC;
    }

    if (OpensslEvpDigestSignFinal(impl->mdCtx, signatureData, &maxLen) != HCF_OPENSSL_SUCCESS) {
        LOGE("Failed to finalize digest signing.");
        HcfPrintOpensslError();
        HcfFree(signatureData);
        signatureData = NULL;
        return HCF_ERR_CRYPTO_OPERATION;
    }

    returnSignatureData->data = signatureData;
    returnSignatureData->len = (uint32_t)maxLen;
    return HCF_SUCCESS;
}

static HcfResult EngineDsaSignWithoutDigestDoFinal(HcfSignSpi *self, HcfBlob *data, HcfBlob *returnSignatureData)
{
    if (!IsSignDoFinalInputValid(self, returnSignatureData)) {
        return HCF_INVALID_PARAMS;
    }
    if (!HcfIsBlobValid(data)) {
        LOGE("Src data is invalid.");
        return HCF_INVALID_PARAMS;
    }
    HcfSignSpiDsaOpensslImpl *impl = (HcfSignSpiDsaOpensslImpl *)self;
    if (impl->status != READY) {
        LOGE("Not init yet.");
        return HCF_INVALID_PARAMS;
    }
    size_t maxLen;
    if (OpensslEvpPkeySign(impl->pkeyCtx, NULL, &maxLen,
        (const unsigned char *)data->data, data->len) != HCF_OPENSSL_SUCCESS) {
        LOGE("EvpPkeySign get maxLen failed.");
        HcfPrintOpensslError();
        return HCF_ERR_CRYPTO_OPERATION;
    }
    uint8_t *signatureData = (uint8_t *)HcfMalloc(maxLen, 0);
    if (signatureData == NULL) {
        LOGE("Failed to allocate signatureData memory!");
        return HCF_ERR_MALLOC;
    }
    size_t actualLen = maxLen;
    if (OpensslEvpPkeySign(impl->pkeyCtx, signatureData, &actualLen,
        (const unsigned char *)data->data, data->len) != HCF_OPENSSL_SUCCESS) {
        LOGE("Failed to sign data.");
        HcfPrintOpensslError();
        HcfFree(signatureData);
        signatureData = NULL;
        return HCF_ERR_CRYPTO_OPERATION;
    }
    if (actualLen > maxLen) {
        LOGE("Signature data too long.");
        HcfFree(signatureData);
        signatureData = NULL;
        return HCF_ERR_CRYPTO_OPERATION;
    }

    returnSignatureData->data = signatureData;
    returnSignatureData->len = (uint32_t)actualLen;
    return HCF_SUCCESS;
}

static bool EngineDsaVerifyDoFinal(HcfVerifySpi *self, HcfBlob *data, HcfBlob *signatureData)
{
    if (!IsVerifyDoFinalInputValid(self, signatureData)) {
        return false;
    }

    HcfVerifySpiDsaOpensslImpl *impl = (HcfVerifySpiDsaOpensslImpl *)self;
    if (impl->status == UNINITIALIZED) {
        LOGW("Verify instance may not have been initialized, "
            "ensure init interface of Verify instance is executed completely!");
    }
    if (HcfIsBlobValid(data)) {
        if (OpensslEvpDigestVerifyUpdate(impl->mdCtx, data->data, data->len) != HCF_OPENSSL_SUCCESS) {
            LOGE("Openssl update failed.");
            HcfPrintOpensslError();
            return false;
        }
        impl->status = READY;
    }
    if (impl->status != READY) {
        LOGE("The message has not been transferred.");
        return false;
    }

    if (OpensslEvpDigestVerifyFinal(impl->mdCtx, signatureData->data, signatureData->len) != HCF_OPENSSL_SUCCESS) {
        LOGE("Failed to finalize digest verification.");
        HcfPrintOpensslError();
        return false;
    }
    return true;
}

static bool EngineDsaVerifyWithoutDigestDoFinal(HcfVerifySpi *self, HcfBlob *data, HcfBlob *signatureData)
{
    if (!IsVerifyDoFinalInputValid(self, signatureData)) {
        return false;
    }
    if (!HcfIsBlobValid(data)) {
        LOGE("Src data is invalid.");
        return false;
    }
    HcfVerifySpiDsaOpensslImpl *impl = (HcfVerifySpiDsaOpensslImpl *)self;
    if (impl->status != READY) {
        LOGE("Not init yet.");
        return false;
    }

    if (OpensslEvpPkeyVerify(impl->pkeyCtx, signatureData->data,
        signatureData->len, data->data, data->len) != HCF_OPENSSL_SUCCESS) {
        LOGE("Failed to verify signature.");
        HcfPrintOpensslError();
        return false;
    }
    return true;
}

static HcfResult EngineSetSignDsaSpecInt(HcfSignSpi *self, SignSpecItem item, int32_t saltLen)
{
    (void)self;
    (void)item;
    (void)saltLen;
    LOGE("SetSignDsaSpecInt not supported.");
    return HCF_NOT_SUPPORT;
}

static HcfResult EngineSetVerifyDsaSpecInt(HcfVerifySpi *self, SignSpecItem item, int32_t saltLen)
{
    (void)self;
    (void)item;
    (void)saltLen;
    LOGE("SetVerifyDsaSpecInt not supported.");
    return HCF_NOT_SUPPORT;
}

static HcfResult EngineGetSignDsaSpecInt(HcfSignSpi *self, SignSpecItem item, int32_t *returnInt)
{
    (void)self;
    (void)item;
    (void)returnInt;
    LOGE("GetSignDsaSpecInt not supported.");
    return HCF_NOT_SUPPORT;
}

static HcfResult EngineGetVerifyDsaSpecInt(HcfVerifySpi *self, SignSpecItem item, int32_t *returnInt)
{
    (void)self;
    (void)item;
    (void)returnInt;
    LOGE("GetVerifyDsaSpecInt not supported.");
    return HCF_NOT_SUPPORT;
}

static HcfResult EngineGetSignDsaSpecString(HcfSignSpi *self, SignSpecItem item, char **returnString)
{
    (void)self;
    (void)item;
    (void)returnString;
    LOGE("GetSignDsaSpecString not supported.");
    return HCF_NOT_SUPPORT;
}

static HcfResult EngineSetSignDsaSpecUint8Array(HcfSignSpi *self, SignSpecItem item, HcfBlob blob)
{
    (void)self;
    (void)item;
    (void)blob;
    LOGE("SetSignDsaSpecUint8Array not supported.");
    return HCF_NOT_SUPPORT;
}

static HcfResult EngineGetVerifyDsaSpecString(HcfVerifySpi *self, SignSpecItem item, char **returnString)
{
    (void)self;
    (void)item;
    (void)returnString;
    LOGE("GetVerifyDsaSpecString not supported.");
    return HCF_NOT_SUPPORT;
}

static HcfResult EngineSetVerifyDsaSpecUint8Array(HcfVerifySpi *self, SignSpecItem item, HcfBlob blob)
{
    (void)self;
    (void)item;
    (void)blob;
    LOGE("SetVerifyDsaSpecUint8Array not supported.");
    return HCF_NOT_SUPPORT;
}

HcfResult HcfSignSpiDsaCreate(HcfSignatureParams *params, HcfSignSpi **returnObj)
{
    if ((params == NULL) || (returnObj == NULL)) {
        LOGE("Invalid input parameter.");
        return HCF_INVALID_PARAMS;
    }

    HcfSignSpiDsaOpensslImpl *impl = (HcfSignSpiDsaOpensslImpl *)HcfMalloc(sizeof(HcfSignSpiDsaOpensslImpl), 0);
    if (impl == NULL) {
        LOGE("Failed to allocate impl memroy!");
        return HCF_ERR_MALLOC;
    }

    EVP_MD *digestAlg = NULL;

    if (params->md == HCF_OPENSSL_DIGEST_NONE) {
        impl->base.engineInit = EngineDsaSignWithoutDigestInit;
        impl->base.engineUpdate = EngineDsaSignWithoutDigestUpdate;
        impl->base.engineSign = EngineDsaSignWithoutDigestDoFinal;
    } else {
        HcfResult ret = GetOpensslDigestAlg(params->md, &digestAlg);
        if (ret != HCF_SUCCESS) {
            LOGE("Failed to get OpenSSL digest algorithm.");
            HcfFree(impl);
            impl = NULL;
            return HCF_INVALID_PARAMS;
        }
        impl->base.engineInit = EngineDsaSignInit;
        impl->base.engineUpdate = EngineDsaSignUpdate;
        impl->base.engineSign = EngineDsaSignDoFinal;
        impl->mdCtx = OpensslEvpMdCtxNew();
        if (impl->mdCtx == NULL) {
            LOGE("Failed to allocate ctx memory!");
            HcfFree(impl);
            impl = NULL;
            return HCF_ERR_MALLOC;
        }
    }
    impl->base.base.getClass = GetDsaSignClass;
    impl->base.base.destroy = DestroyDsaSign;
    impl->base.engineSetSignSpecInt = EngineSetSignDsaSpecInt;
    impl->base.engineGetSignSpecInt = EngineGetSignDsaSpecInt;
    impl->base.engineGetSignSpecString = EngineGetSignDsaSpecString;
    impl->base.engineSetSignSpecUint8Array = EngineSetSignDsaSpecUint8Array;
    impl->status = UNINITIALIZED;
    impl->digestAlg = digestAlg;
    *returnObj = (HcfSignSpi *)impl;
    return HCF_SUCCESS;
}

HcfResult HcfVerifySpiDsaCreate(HcfSignatureParams *params, HcfVerifySpi **returnObj)
{
    if ((params == NULL) || (returnObj == NULL)) {
        LOGE("Invalid input parameter.");
        return HCF_INVALID_PARAMS;
    }

    HcfVerifySpiDsaOpensslImpl *impl = (HcfVerifySpiDsaOpensslImpl *)HcfMalloc(sizeof(HcfVerifySpiDsaOpensslImpl), 0);
    if (impl == NULL) {
        LOGE("Failed to allocate impl memroy!");
        return HCF_ERR_MALLOC;
    }

    EVP_MD *digestAlg = NULL;
    if (params->md == HCF_OPENSSL_DIGEST_NONE) {
        impl->base.engineInit = EngineDsaVerifyWithoutDigestInit;
        impl->base.engineUpdate = EngineDsaVerifyWithoutDigestUpdate;
        impl->base.engineVerify = EngineDsaVerifyWithoutDigestDoFinal;
    } else {
        HcfResult ret = GetOpensslDigestAlg(params->md, &digestAlg);
        if (ret != HCF_SUCCESS) {
            LOGE("Failed to get OpenSSL digest algorithm.");
            HcfFree(impl);
            impl = NULL;
            return HCF_INVALID_PARAMS;
        }
        impl->base.engineInit = EngineDsaVerifyInit;
        impl->base.engineUpdate = EngineDsaVerifyUpdate;
        impl->base.engineVerify = EngineDsaVerifyDoFinal;
        impl->mdCtx = OpensslEvpMdCtxNew();
        if (impl->mdCtx == NULL) {
            LOGE("Failed to allocate ctx memory!");
            HcfFree(impl);
            impl = NULL;
            return HCF_ERR_MALLOC;
        }
    }
    impl->base.base.getClass = GetDsaVerifyClass;
    impl->base.base.destroy = DestroyDsaVerify;
    impl->base.engineSetVerifySpecInt = EngineSetVerifyDsaSpecInt;
    impl->base.engineGetVerifySpecInt = EngineGetVerifyDsaSpecInt;
    impl->base.engineGetVerifySpecString = EngineGetVerifyDsaSpecString;
    impl->base.engineSetVerifySpecUint8Array = EngineSetVerifyDsaSpecUint8Array;
    impl->digestAlg = digestAlg;
    impl->status = UNINITIALIZED;

    *returnObj = (HcfVerifySpi *)impl;
    return HCF_SUCCESS;
}