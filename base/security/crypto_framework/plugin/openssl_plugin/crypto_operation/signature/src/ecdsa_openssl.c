/*
 * Copyright (C) 2022 Huawei Device Co., Ltd.
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

#include "ecdsa_openssl.h"

#include <openssl/bio.h>
#include <openssl/err.h>

#include "algorithm_parameter.h"
#include "openssl_adapter.h"
#include "openssl_class.h"
#include "openssl_common.h"
#include "log.h"
#include "memory.h"
#include "utils.h"

#define OPENSSL_ECC_SIGN_CLASS "OPENSSL.ECC.SIGN"
#define OPENSSL_ECC_VERIFY_CLASS "OPENSSL.ECC.VERIFY"

typedef struct {
    HcfSignSpi base;

    const EVP_MD *digestAlg;

    EVP_MD_CTX *ctx;
    
    EVP_PKEY_CTX *pkeyCtx;  // For OnlySign mode

    CryptoStatus status;

    int32_t operation;
} HcfSignSpiEcdsaOpensslImpl;

typedef struct {
    HcfVerifySpi base;

    const EVP_MD *digestAlg;

    EVP_MD_CTX *ctx;

    EVP_PKEY_CTX *pkeyCtx;  // For OnlyVerify mode

    CryptoStatus status;

    int32_t operation;
} HcfVerifySpiEcdsaOpensslImpl;

static bool IsDigestAlgValid(uint32_t alg)
{
    if ((alg == HCF_OPENSSL_DIGEST_SHA1) || (alg == HCF_OPENSSL_DIGEST_SHA224) ||
        (alg == HCF_OPENSSL_DIGEST_SHA256) ||(alg == HCF_OPENSSL_DIGEST_SHA384) ||
        (alg == HCF_OPENSSL_DIGEST_SHA512)) {
        return true;
    } else {
        LOGE("Invalid digest num is %{public}u.", alg);
        return false;
    }
}

static bool IsBrainPoolDigestAlgValid(uint32_t alg)
{
    if ((alg == HCF_OPENSSL_DIGEST_SHA1) || (alg == HCF_OPENSSL_DIGEST_SHA224) ||
        (alg == HCF_OPENSSL_DIGEST_SHA256) || (alg == HCF_OPENSSL_DIGEST_SHA384) ||
        (alg == HCF_OPENSSL_DIGEST_SHA512) || (alg == HCF_OPENSSL_DIGEST_MD5)) {
        return true;
    } else {
        LOGE("Invalid digest num is %{public}u.", alg);
        return false;
    }
}

// export interfaces
static const char *GetEcdsaSignClass(void)
{
    return OPENSSL_ECC_SIGN_CLASS;
}

static const char *GetEcdsaVerifyClass(void)
{
    return OPENSSL_ECC_VERIFY_CLASS;
}

static void DestroyEcdsaSign(HcfObjectBase *self)
{
    if (self == NULL) {
        LOGE("Class is null.");
        return;
    }
    if (!HcfIsClassMatch(self, GetEcdsaSignClass())) {
        LOGE("Class not match.");
        return;
    }
    HcfSignSpiEcdsaOpensslImpl *impl = (HcfSignSpiEcdsaOpensslImpl *)self;
    OpensslEvpMdCtxFree(impl->ctx);
    impl->ctx = NULL;
    // Free pkeyCtx if allocated (OnlySign mode)
    if (impl->pkeyCtx != NULL) {
        OpensslEvpPkeyCtxFree(impl->pkeyCtx);
        impl->pkeyCtx = NULL;
    }
    HcfFree(impl);
}

static void DestroyEcdsaVerify(HcfObjectBase *self)
{
    if (self == NULL) {
        LOGE("Class is null.");
        return;
    }
    if (!HcfIsClassMatch(self, GetEcdsaVerifyClass())) {
        LOGE("Class not match.");
        return;
    }
    HcfVerifySpiEcdsaOpensslImpl *impl = (HcfVerifySpiEcdsaOpensslImpl *)self;
    OpensslEvpMdCtxFree(impl->ctx);
    impl->ctx = NULL;
    if (impl->pkeyCtx != NULL) {
        OpensslEvpPkeyCtxFree(impl->pkeyCtx);
        impl->pkeyCtx = NULL;
    }
    HcfFree(impl);
}

static HcfResult CreateEcdsaOnlyPkeyCtx(EC_KEY *srcKey, const EVP_MD *digestAlg, bool isSign,
    EVP_PKEY_CTX **returnPkeyCtx)
{
    EC_KEY *ecKey = OpensslEcKeyDup(srcKey);
    if (ecKey == NULL) {
        HcfPrintOpensslError();
        LOGE("Dup ecKey failed.");
        return HCF_ERR_CRYPTO_OPERATION;
    }

    EVP_PKEY *pkey = OpensslEvpPkeyNew();
    if (pkey == NULL) {
        HcfPrintOpensslError();
        LOGE("New pkey failed.");
        OpensslEcKeyFree(ecKey);
        return HCF_ERR_CRYPTO_OPERATION;
    }
    if (OpensslEvpPkeyAssignEcKey(pkey, ecKey) != HCF_OPENSSL_SUCCESS) {
        HcfPrintOpensslError();
        LOGE("EVP_PKEY_assign_EC_KEY failed.");
        OpensslEcKeyFree(ecKey);
        OpensslEvpPkeyFree(pkey);
        return HCF_ERR_CRYPTO_OPERATION;
    }

    EVP_PKEY_CTX *pkeyCtx = OpensslEvpPkeyCtxNewFromPkey(NULL, pkey, NULL);
    OpensslEvpPkeyFree(pkey);
    if (pkeyCtx == NULL) {
        HcfPrintOpensslError();
        LOGE("EVP_PKEY_CTX_new_from_pkey failed.");
        return HCF_ERR_CRYPTO_OPERATION;
    }

    int32_t ret = isSign ? OpensslEvpPkeySignInit(pkeyCtx) : OpensslEvpPkeyVerifyInit(pkeyCtx);
    if (ret != HCF_OPENSSL_SUCCESS) {
        HcfPrintOpensslError();
        if (isSign) {
            LOGE("EVP_PKEY_sign_init failed.");
        } else {
            LOGE("EVP_PKEY_verify_init failed.");
        }
        OpensslEvpPkeyCtxFree(pkeyCtx);
        return HCF_ERR_CRYPTO_OPERATION;
    }
    if (OpensslEvpPkeyCtxSetSignatureMd(pkeyCtx, digestAlg) != HCF_OPENSSL_SUCCESS) {
        HcfPrintOpensslError();
        LOGE("EVP_PKEY_CTX_set_signature_md failed.");
        OpensslEvpPkeyCtxFree(pkeyCtx);
        return HCF_ERR_CRYPTO_OPERATION;
    }

    *returnPkeyCtx = pkeyCtx;
    return HCF_SUCCESS;
}

static HcfResult SetEcdsaOnlySignParams(HcfSignSpiEcdsaOpensslImpl *impl, HcfPriKey *privateKey)
{
    // OnlySign mode: sign digest directly without internal digest calculation
    // For ECDSA, use EVP_PKEY_sign interface to support direct digest signing
    EVP_PKEY_CTX *pkeyCtx = NULL;
    HcfResult ret = CreateEcdsaOnlyPkeyCtx(((HcfOpensslEccPriKey *)privateKey)->ecKey,
        impl->digestAlg, true, &pkeyCtx);
    if (ret != HCF_SUCCESS) {
        return ret;
    }

    // Store the pkey context for signing
    impl->pkeyCtx = pkeyCtx;
    return HCF_SUCCESS;
}

static HcfResult SetEcdsaOnlyVerifyParams(HcfVerifySpiEcdsaOpensslImpl *impl, HcfPubKey *publicKey)
{
    EVP_PKEY_CTX *pkeyCtx = NULL;
    HcfResult ret = CreateEcdsaOnlyPkeyCtx(((HcfOpensslEccPubKey *)publicKey)->ecKey,
        impl->digestAlg, false, &pkeyCtx);
    if (ret != HCF_SUCCESS) {
        return ret;
    }

    impl->pkeyCtx = pkeyCtx;
    return HCF_SUCCESS;
}

static HcfResult SetEcdsaVerifyParams(HcfVerifySpiEcdsaOpensslImpl *impl, HcfPubKey *publicKey)
{
    EC_KEY *ecKey = OpensslEcKeyDup(((HcfOpensslEccPubKey *)publicKey)->ecKey);
    if (ecKey == NULL) {
        HcfPrintOpensslError();
        LOGE("Dup ecKey failed.");
        return HCF_ERR_CRYPTO_OPERATION;
    }

    EVP_PKEY *pKey = OpensslEvpPkeyNew();
    if (pKey == NULL) {
        HcfPrintOpensslError();
        LOGE("New pKey failed.");
        OpensslEcKeyFree(ecKey);
        return HCF_ERR_CRYPTO_OPERATION;
    }
    if (OpensslEvpPkeyAssignEcKey(pKey, ecKey) != HCF_OPENSSL_SUCCESS) {
        HcfPrintOpensslError();
        LOGE("EVP_PKEY_assign_EC_KEY failed.");
        OpensslEcKeyFree(ecKey);
        OpensslEvpPkeyFree(pKey);
        return HCF_ERR_CRYPTO_OPERATION;
    }
    if (OpensslEvpDigestVerifyInit(impl->ctx, NULL, impl->digestAlg, NULL, pKey) != HCF_OPENSSL_SUCCESS) {
        HcfPrintOpensslError();
        LOGE("EVP_DigestVerifyInit failed.");
        OpensslEvpPkeyFree(pKey);
        return HCF_ERR_CRYPTO_OPERATION;
    }
    OpensslEvpPkeyFree(pKey);
    return HCF_SUCCESS;
}

static HcfResult SetEcdsaSignParams(HcfSignSpiEcdsaOpensslImpl *impl, HcfPriKey *privateKey)
{
    // dup will check if ecKey is NULL
    EC_KEY *ecKey = OpensslEcKeyDup(((HcfOpensslEccPriKey *)privateKey)->ecKey);
    if (ecKey == NULL) {
        HcfPrintOpensslError();
        LOGE("Dup ecKey failed.");
        return HCF_ERR_CRYPTO_OPERATION;
    }
    EVP_PKEY *pKey = OpensslEvpPkeyNew();
    if (pKey == NULL) {
        HcfPrintOpensslError();
        LOGE("Dup pKey failed.");
        OpensslEcKeyFree(ecKey);
        return HCF_ERR_CRYPTO_OPERATION;
    }
    if (OpensslEvpPkeyAssignEcKey(pKey, ecKey) != HCF_OPENSSL_SUCCESS) {
        HcfPrintOpensslError();
        LOGE("EVP_PKEY_assign_EC_KEY failed.");
        OpensslEcKeyFree(ecKey);
        OpensslEvpPkeyFree(pKey);
        return HCF_ERR_CRYPTO_OPERATION;
    }
    if (OpensslEvpDigestSignInit(impl->ctx, NULL, impl->digestAlg, NULL, pKey) != HCF_OPENSSL_SUCCESS) {
        HcfPrintOpensslError();
        LOGE("EVP_DigestSignInit failed.");
        OpensslEvpPkeyFree(pKey);
        return HCF_ERR_CRYPTO_OPERATION;
    }
    OpensslEvpPkeyFree(pKey);
    return HCF_SUCCESS;
}

static HcfResult EngineSignInit(HcfSignSpi *self, HcfParamsSpec *params, HcfPriKey *privateKey)
{
    (void)params;
    if ((self == NULL) || (privateKey == NULL)) {
        LOGE("Invalid input parameter.");
        return HCF_INVALID_PARAMS;
    }
    if ((!HcfIsClassMatch((HcfObjectBase *)self, GetEcdsaSignClass())) ||
        (!HcfIsClassMatch((HcfObjectBase *)privateKey, HCF_OPENSSL_ECC_PRI_KEY_CLASS))) {
        LOGE("Class not match.");
        return HCF_INVALID_PARAMS;
    }

    HcfSignSpiEcdsaOpensslImpl *impl = (HcfSignSpiEcdsaOpensslImpl *)self;
    if (impl->status != UNINITIALIZED) {
        LOGE("Repeated initialization is not allowed.");
        return HCF_INVALID_PARAMS;
    }

    HcfResult ret;
    if (impl->operation == HCF_OPERATION_ONLY_SIGN) {
        ret = SetEcdsaOnlySignParams(impl, privateKey);
        if (ret != HCF_SUCCESS) {
            LOGE("Failed to set ECDSA sign-only parameters.");
            return ret;
        }
        impl->status = READY;
        return HCF_SUCCESS;
    }

    ret = SetEcdsaSignParams(impl, privateKey);
    if (ret != HCF_SUCCESS) {
        return ret;
    }
    impl->status = INITIALIZED;
    return HCF_SUCCESS;
}

static HcfResult EngineSignUpdate(HcfSignSpi *self, HcfBlob *data)
{
    if (self == NULL) {
        LOGE("Invalid input parameter.");
        return HCF_INVALID_PARAMS;
    }
    if (!HcfIsClassMatch((HcfObjectBase *)self, GetEcdsaSignClass())) {
        LOGE("Class not match.");
        return HCF_INVALID_PARAMS;
    }
    HcfSignSpiEcdsaOpensslImpl *impl = (HcfSignSpiEcdsaOpensslImpl *)self;
    if (impl->status == UNINITIALIZED) {
        LOGE("Sign object has not been initialized.");
        return HCF_INVALID_PARAMS;
    }
    // OnlySign mode does not support update operation
    if (impl->operation == HCF_OPERATION_ONLY_SIGN) {
        LOGE("Update operation is not supported in OnlySign mode.");
        return HCF_ERR_INVALID_CALL;
    }
    if (!HcfIsBlobValid(data)) {
        LOGE("Invalid input parameter.");
        return HCF_INVALID_PARAMS;
    }
    if (OpensslEvpDigestSignUpdate(impl->ctx, data->data, data->len) != HCF_OPENSSL_SUCCESS) {
        HcfPrintOpensslError();
        LOGE("EVP_DigestSignUpdate failed.");
        return HCF_ERR_CRYPTO_OPERATION;
    }
    impl->status = READY;
    return HCF_SUCCESS;
}

static HcfResult EngineSignOnlySign(HcfSignSpiEcdsaOpensslImpl *impl, HcfBlob *data, HcfBlob *returnSignatureData)
{
    if (!HcfIsBlobValid(data)) {
        LOGE("OnlySign mode requires valid digest data.");
        return HCF_ERR_PARAMETER_CHECK_FAILED;
    }

    if (impl->status != READY) {
        LOGE("The message has not been transferred.");
        return HCF_ERR_PARAMETER_CHECK_FAILED;
    }

    // Get maximum signature length first
    size_t maxSigLen;
    if (OpensslEvpPkeySign(impl->pkeyCtx, NULL, &maxSigLen, data->data, data->len) != HCF_OPENSSL_SUCCESS) {
        HcfPrintOpensslError();
        LOGE("EVP_PKEY_sign get maxLen failed.");
        return HCF_ERR_CRYPTO_OPERATION;
    }
    // Allocate output buffer for signature
    uint8_t *outData = (uint8_t *)HcfMalloc(maxSigLen, 0);
    if (outData == NULL) {
        LOGE("Failed to allocate signature memory!");
        return HCF_ERR_MALLOC;
    }
    
    // Perform actual signing
    size_t actualSigLen = maxSigLen;
    if (OpensslEvpPkeySign(impl->pkeyCtx, outData, &actualSigLen, data->data, data->len) != HCF_OPENSSL_SUCCESS) {
        HcfPrintOpensslError();
        LOGE("EVP_PKEY_sign failed in OnlySign mode.");
        HcfFree(outData);
        return HCF_ERR_CRYPTO_OPERATION;
    }
    returnSignatureData->data = outData;
    returnSignatureData->len = (uint32_t)actualSigLen;
    return HCF_SUCCESS;
}

static HcfSignSpiEcdsaOpensslImpl *GetEcdsaSignImplForDoFinal(HcfSignSpi *self, HcfBlob *returnSignatureData)
{
    if ((self == NULL) || (returnSignatureData == NULL)) {
        LOGE("Invalid input parameter.");
        return NULL;
    }
    if (!HcfIsClassMatch((HcfObjectBase *)self, GetEcdsaSignClass())) {
        LOGE("Class not match.");
        return NULL;
    }
    HcfSignSpiEcdsaOpensslImpl *impl = (HcfSignSpiEcdsaOpensslImpl *)self;
    if (impl->status == UNINITIALIZED) {
        LOGW("Sign instance may not have been initialized, "
            "ensure init interface of Sign instance is executed completely!");
    }
    return impl;
}

static HcfResult EngineSignDoFinal(HcfSignSpi *self, HcfBlob *data, HcfBlob *returnSignatureData)
{
    HcfSignSpiEcdsaOpensslImpl *impl = GetEcdsaSignImplForDoFinal(self, returnSignatureData);
    if (impl == NULL) {
        return HCF_INVALID_PARAMS;
    }
    if (impl->operation == HCF_OPERATION_ONLY_SIGN) {
        return EngineSignOnlySign(impl, data, returnSignatureData);
    }

    if (HcfIsBlobValid(data)) {
        if (OpensslEvpDigestSignUpdate(impl->ctx, data->data, data->len) != HCF_OPENSSL_SUCCESS) {
            HcfPrintOpensslError();
            LOGE("EVP_DigestSignUpdate failed.");
            return HCF_ERR_CRYPTO_OPERATION;
        }
        impl->status = READY;
    }
    if (impl->status != READY) {
        LOGE("The message has not been transferred.");
        return HCF_INVALID_PARAMS;
    }
    size_t maxLen;
    if (OpensslEvpDigestSignFinal(impl->ctx, NULL, &maxLen) != HCF_OPENSSL_SUCCESS) {
        HcfPrintOpensslError();
        LOGE("EVP_DigestSignFinal failed.");
        return HCF_ERR_CRYPTO_OPERATION;
    }
    uint8_t *outData = (uint8_t *)HcfMalloc(maxLen, 0);
    if (outData == NULL) {
        LOGE("Failed to allocate outData memory!");
        return HCF_ERR_MALLOC;
    }

    if (OpensslEvpDigestSignFinal(impl->ctx, outData, &maxLen) != HCF_OPENSSL_SUCCESS) {
        HcfPrintOpensslError();
        LOGE("EVP_DigestSignFinal failed.");
        HcfFree(outData);
        outData = NULL;
        return HCF_ERR_CRYPTO_OPERATION;
    }

    returnSignatureData->data = outData;
    returnSignatureData->len = (uint32_t)maxLen;
    return HCF_SUCCESS;
}

static HcfResult EngineVerifyInit(HcfVerifySpi *self, HcfParamsSpec *params, HcfPubKey *publicKey)
{
    (void)params;
    if ((self == NULL) || (publicKey == NULL)) {
        LOGE("Invalid input parameter.");
        return HCF_INVALID_PARAMS;
    }
    if ((!HcfIsClassMatch((HcfObjectBase *)self, GetEcdsaVerifyClass())) ||
        (!HcfIsClassMatch((HcfObjectBase *)publicKey, HCF_OPENSSL_ECC_PUB_KEY_CLASS))) {
        LOGE("Class not match.");
        return HCF_INVALID_PARAMS;
    }

    HcfVerifySpiEcdsaOpensslImpl *impl = (HcfVerifySpiEcdsaOpensslImpl *)self;
    if (impl->status != UNINITIALIZED) {
        LOGE("Repeated initialization is not allowed.");
        return HCF_INVALID_PARAMS;
    }

    HcfResult ret;
    if (impl->operation == HCF_OPERATION_ONLY_VERIFY) {
        ret = SetEcdsaOnlyVerifyParams(impl, publicKey);
        if (ret != HCF_SUCCESS) {
            LOGE("Failed to set ECDSA only verify parameters.");
            return ret;
        }
        impl->status = READY;
        return HCF_SUCCESS;
    }

    ret = SetEcdsaVerifyParams(impl, publicKey);
    if (ret != HCF_SUCCESS) {
        return ret;
    }
    impl->status = INITIALIZED;
    return HCF_SUCCESS;
}

static HcfResult EngineVerifyUpdate(HcfVerifySpi *self, HcfBlob *data)
{
    if (self == NULL) {
        LOGE("Invalid input parameter.");
        return HCF_INVALID_PARAMS;
    }
    if (!HcfIsClassMatch((HcfObjectBase *)self, GetEcdsaVerifyClass())) {
        LOGE("Class not match.");
        return HCF_INVALID_PARAMS;
    }

    HcfVerifySpiEcdsaOpensslImpl *impl = (HcfVerifySpiEcdsaOpensslImpl *)self;
    if (impl->status == UNINITIALIZED) {
        LOGE("Verify object has not been initialized.");
        return HCF_INVALID_PARAMS;
    }
    if (impl->operation == HCF_OPERATION_ONLY_VERIFY) {
        LOGE("Update operation is not supported in OnlyVerify mode.");
        return HCF_ERR_INVALID_CALL;
    }
    if (!HcfIsBlobValid(data)) {
        LOGE("Invalid input parameter.");
        return HCF_INVALID_PARAMS;
    }
    if (OpensslEvpDigestVerifyUpdate(impl->ctx, data->data, data->len) != HCF_OPENSSL_SUCCESS) {
        HcfPrintOpensslError();
        LOGE("EVP_DigestVerifyUpdate failed.");
        return HCF_ERR_CRYPTO_OPERATION;
    }
    impl->status = READY;
    return HCF_SUCCESS;
}

static bool EngineVerifyDoFinal(HcfVerifySpi *self, HcfBlob *data, HcfBlob *signatureData)
{
    if ((self == NULL) || (!HcfIsBlobValid(signatureData))) {
        LOGE("Invalid input parameter.");
        return false;
    }
    if (!HcfIsClassMatch((HcfObjectBase *)self, GetEcdsaVerifyClass())) {
        LOGE("Class not match.");
        return false;
    }

    HcfVerifySpiEcdsaOpensslImpl *impl = (HcfVerifySpiEcdsaOpensslImpl *)self;
    if (impl->status == UNINITIALIZED) {
        LOGW("Verify instance may not have been initialized, "
            "ensure init interface of Verify instance is executed completely!");
    }
    if (impl->operation == HCF_OPERATION_ONLY_VERIFY) {
        if (!HcfIsBlobValid(data)) {
            LOGE("OnlyVerify mode requires valid digest data.");
            return false;
        }
        if (impl->status != READY) {
            LOGE("Not init yet.");
            return false;
        }
        if (OpensslEvpPkeyVerify(impl->pkeyCtx, signatureData->data,
            signatureData->len, data->data, data->len) != HCF_OPENSSL_SUCCESS) {
            HcfPrintOpensslError();
            LOGE("EVP_PKEY_verify failed.");
            return false;
        }
        return true;
    }
    if (HcfIsBlobValid(data)) {
        if (OpensslEvpDigestVerifyUpdate(impl->ctx, data->data, data->len) != HCF_OPENSSL_SUCCESS) {
            HcfPrintOpensslError();
            LOGE("EVP_DigestVerifyUpdate failed.");
            return false;
        }
        impl->status = READY;
    }
    if (impl->status != READY) {
        LOGE("The message has not been transferred.");
        return false;
    }
    if (OpensslEvpDigestVerifyFinal(impl->ctx, signatureData->data, signatureData->len) != HCF_OPENSSL_SUCCESS) {
        HcfPrintOpensslError();
        LOGE("EVP_DigestVerifyFinal failed.");
        return false;
    }
    return true;
}

static HcfResult EngineSetSignEcdsaSpecInt(HcfSignSpi *self, SignSpecItem item, int32_t saltLen)
{
    (void)self;
    (void)item;
    (void)saltLen;
    return HCF_NOT_SUPPORT;
}

static HcfResult EngineSetVerifyEcdsaSpecInt(HcfVerifySpi *self, SignSpecItem item, int32_t saltLen)
{
    (void)self;
    (void)item;
    (void)saltLen;
    return HCF_NOT_SUPPORT;
}

static HcfResult EngineGetSignEcdsaSpecInt(HcfSignSpi *self, SignSpecItem item, int32_t *returnInt)
{
    (void)self;
    (void)item;
    (void)returnInt;
    return HCF_NOT_SUPPORT;
}

static HcfResult EngineGetVerifyEcdsaSpecInt(HcfVerifySpi *self, SignSpecItem item, int32_t *returnInt)
{
    (void)self;
    (void)item;
    (void)returnInt;
    return HCF_NOT_SUPPORT;
}

static HcfResult EngineGetSignEcdsaSpecString(HcfSignSpi *self, SignSpecItem item, char **returnString)
{
    (void)self;
    (void)item;
    (void)returnString;
    return HCF_NOT_SUPPORT;
}

static HcfResult EngineSetSignEcdsaSpecUint8Array(HcfSignSpi *self, SignSpecItem item, HcfBlob blob)
{
    (void)self;
    (void)item;
    (void)blob;
    return HCF_NOT_SUPPORT;
}

static HcfResult EngineGetVerifyEcdsaSpecString(HcfVerifySpi *self, SignSpecItem item, char **returnString)
{
    (void)self;
    (void)item;
    (void)returnString;
    return HCF_NOT_SUPPORT;
}

static HcfResult EngineSetVerifyEcdsaSpecUint8Array(HcfVerifySpi *self, SignSpecItem item, HcfBlob blob)
{
    (void)self;
    (void)item;
    (void)blob;
    return HCF_NOT_SUPPORT;
}

static HcfResult InitEcdsaSignImpl(HcfSignatureParams *params, HcfSignSpiEcdsaOpensslImpl **returnImpl)
{
    if (params->algo == HCF_ALG_ECC_BRAINPOOL) {
        if (!IsBrainPoolDigestAlgValid(params->md)) {
            LOGE("Invalid md.");
            return HCF_INVALID_PARAMS;
        }
    } else {
        if (!IsDigestAlgValid(params->md)) {
            LOGE("Invalid md.");
            return HCF_INVALID_PARAMS;
        }
    }
    EVP_MD *opensslAlg = NULL;
    int32_t ret = GetOpensslDigestAlg(params->md, &opensslAlg);
    if (ret != HCF_SUCCESS || opensslAlg == NULL) {
        LOGE("Failed to Invalid digest!");
        return HCF_INVALID_PARAMS;
    }

    HcfSignSpiEcdsaOpensslImpl *impl = (HcfSignSpiEcdsaOpensslImpl *)HcfMalloc(
        sizeof(HcfSignSpiEcdsaOpensslImpl), 0);
    if (impl == NULL) {
        LOGE("Failed to allocate returnImpl memroy!");
        return HCF_ERR_MALLOC;
    }
    impl->base.base.getClass = GetEcdsaSignClass;
    impl->base.base.destroy = DestroyEcdsaSign;
    impl->base.engineInit = EngineSignInit;
    impl->base.engineUpdate = EngineSignUpdate;
    impl->base.engineSign = EngineSignDoFinal;
    impl->base.engineSetSignSpecInt = EngineSetSignEcdsaSpecInt;
    impl->base.engineGetSignSpecInt = EngineGetSignEcdsaSpecInt;
    impl->base.engineGetSignSpecString = EngineGetSignEcdsaSpecString;
    impl->base.engineSetSignSpecUint8Array = EngineSetSignEcdsaSpecUint8Array;
    impl->digestAlg = opensslAlg;
    impl->status = UNINITIALIZED;
    impl->ctx = OpensslEvpMdCtxNew();
    if (impl->ctx == NULL) {
        LOGE("Failed to allocate ctx memory!");
        HcfFree(impl);
        return HCF_ERR_MALLOC;
    }
    impl->pkeyCtx = NULL;
    impl->operation = (params->operation == HCF_ALG_ONLY_SIGN) ? HCF_OPERATION_ONLY_SIGN : HCF_OPERATION_SIGN;
    *returnImpl = impl;
    return HCF_SUCCESS;
}

HcfResult HcfSignSpiEcdsaCreate(HcfSignatureParams *params, HcfSignSpi **returnObj)
{
    if ((params == NULL) || (returnObj == NULL)) {
        LOGE("Invalid input parameter.");
        return HCF_INVALID_PARAMS;
    }
    HcfSignSpiEcdsaOpensslImpl *returnImpl = NULL;
    HcfResult ret = InitEcdsaSignImpl(params, &returnImpl);
    if (ret != HCF_SUCCESS) {
        return ret;
    }
    *returnObj = (HcfSignSpi *)returnImpl;
    return HCF_SUCCESS;
}

static HcfResult InitEcdsaVerifyImpl(HcfSignatureParams *params, HcfVerifySpiEcdsaOpensslImpl **returnImpl)
{
    if (params->algo == HCF_ALG_ECC_BRAINPOOL) {
        if (!IsBrainPoolDigestAlgValid(params->md)) {
            LOGE("Invalid md.");
            return HCF_INVALID_PARAMS;
        }
    } else {
        if (!IsDigestAlgValid(params->md)) {
            LOGE("Invalid md.");
            return HCF_INVALID_PARAMS;
        }
    }
    EVP_MD *opensslAlg = NULL;
    int32_t ret = GetOpensslDigestAlg(params->md, &opensslAlg);
    if (ret != HCF_SUCCESS || opensslAlg == NULL) {
        LOGE("Failed to Invalid digest!");
        return HCF_INVALID_PARAMS;
    }

    HcfVerifySpiEcdsaOpensslImpl *impl = (HcfVerifySpiEcdsaOpensslImpl *)HcfMalloc(
        sizeof(HcfVerifySpiEcdsaOpensslImpl), 0);
    if (impl == NULL) {
        LOGE("Failed to allocate returnImpl memroy!");
        return HCF_ERR_MALLOC;
    }
    impl->base.base.getClass = GetEcdsaVerifyClass;
    impl->base.base.destroy = DestroyEcdsaVerify;
    impl->base.engineInit = EngineVerifyInit;
    impl->base.engineUpdate = EngineVerifyUpdate;
    impl->base.engineVerify = EngineVerifyDoFinal;
    impl->base.engineSetVerifySpecInt = EngineSetVerifyEcdsaSpecInt;
    impl->base.engineGetVerifySpecInt = EngineGetVerifyEcdsaSpecInt;
    impl->base.engineGetVerifySpecString = EngineGetVerifyEcdsaSpecString;
    impl->base.engineSetVerifySpecUint8Array = EngineSetVerifyEcdsaSpecUint8Array;
    impl->digestAlg = opensslAlg;
    impl->status = UNINITIALIZED;
    impl->ctx = OpensslEvpMdCtxNew();
    if (impl->ctx == NULL) {
        LOGE("Failed to allocate ctx memory!");
        HcfFree(impl);
        return HCF_ERR_MALLOC;
    }
    impl->pkeyCtx = NULL;
    impl->operation =
        (params->operation == HCF_ALG_ONLY_VERIFY) ? HCF_OPERATION_ONLY_VERIFY : HCF_OPERATION_VERIFY;
    *returnImpl = impl;
    return HCF_SUCCESS;
}

HcfResult HcfVerifySpiEcdsaCreate(HcfSignatureParams *params, HcfVerifySpi **returnObj)
{
    if ((params == NULL) || (returnObj == NULL)) {
        LOGE("Invalid input parameter.");
        return HCF_INVALID_PARAMS;
    }

    HcfVerifySpiEcdsaOpensslImpl *returnImpl = NULL;
    HcfResult ret = InitEcdsaVerifyImpl(params, &returnImpl);
    if (ret != HCF_SUCCESS) {
        return ret;
    }
    *returnObj = (HcfVerifySpi *)returnImpl;
    return HCF_SUCCESS;
}
