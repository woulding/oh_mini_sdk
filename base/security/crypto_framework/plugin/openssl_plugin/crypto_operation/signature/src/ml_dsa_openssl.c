/*
 * Copyright (C) 2026 Huawei Device Co., Ltd.
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

#include "ml_dsa_openssl.h"

#include <openssl/core_names.h>
#include <openssl/err.h>
#include <openssl/params.h>

#include "securec.h"

#include "openssl_adapter.h"
#include "openssl_class.h"
#include "openssl_common.h"
#include "log.h"
#include "memory.h"
#include "utils.h"

#define OPENSSL_ML_DSA_SIGN_CLASS "OPENSSL.ML_DSA.SIGN"
#define OPENSSL_ML_DSA_VERIFY_CLASS "OPENSSL.ML_DSA.VERIFY"
#define MAX_CONTEXT_LENGTH 255

typedef struct {
    HcfSignSpi base;

    EVP_MD_CTX *mdCtx;

    CryptoStatus status;

    bool deterministic;

    bool mu;

    HcfBlob context;
} HcfSignSpiMlDsaOpensslImpl;

typedef struct {
    HcfVerifySpi base;

    EVP_MD_CTX *mdCtx;

    CryptoStatus status;

    bool deterministic;

    bool mu;

    HcfBlob context;
} HcfVerifySpiMlDsaOpensslImpl;

static const char *GetMlDsaSignClass(void)
{
    return OPENSSL_ML_DSA_SIGN_CLASS;
}

static const char *GetMlDsaVerifyClass(void)
{
    return OPENSSL_ML_DSA_VERIFY_CLASS;
}

static void MlDsaSignFreeContext(HcfSignSpiMlDsaOpensslImpl *impl)
{
    if (impl->context.data != NULL) {
        HcfFree(impl->context.data);
        impl->context.data = NULL;
    }
    impl->context.len = 0;
}

static void MlDsaVerifyFreeContext(HcfVerifySpiMlDsaOpensslImpl *impl)
{
    if (impl->context.data != NULL) {
        HcfFree(impl->context.data);
        impl->context.data = NULL;
    }
    impl->context.len = 0;
}

static void DestroyMlDsaSign(HcfObjectBase *self)
{
    if (self == NULL) {
        return;
    }
    if (!HcfIsClassMatch(self, self->getClass())) {
        return;
    }
    HcfSignSpiMlDsaOpensslImpl *impl = (HcfSignSpiMlDsaOpensslImpl *)self;
    if (impl->mdCtx != NULL) {
        OpensslEvpMdCtxFree(impl->mdCtx);
        impl->mdCtx = NULL;
    }
    MlDsaSignFreeContext(impl);
    HcfFree(impl);
}

static void DestroyMlDsaVerify(HcfObjectBase *self)
{
    if (self == NULL) {
        return;
    }
    if (!HcfIsClassMatch(self, self->getClass())) {
        return;
    }
    HcfVerifySpiMlDsaOpensslImpl *impl = (HcfVerifySpiMlDsaOpensslImpl *)self;
    if (impl->mdCtx != NULL) {
        OpensslEvpMdCtxFree(impl->mdCtx);
        impl->mdCtx = NULL;
    }
    MlDsaVerifyFreeContext(impl);
    HcfFree(impl);
}

static HcfResult SetMlDsaOsslParams(EVP_MD_CTX *ctx, bool deterministic, bool mu, const HcfBlob *context)
{
    EVP_PKEY_CTX *pkeyCtx = OpensslEvpMdCtxGetPkeyCtx(ctx);
    if (pkeyCtx == NULL) {
        LOGE("Failed to get pkey ctx.");
        return HCF_ERR_CRYPTO_OPERATION;
    }
    int detInt = deterministic ? 1 : 0;
    int muInt = mu ? 1 : 0;
    OSSL_PARAM params[4];
    int idx = 0;
    params[idx++] = OpensslOsslParamConstructInt(OSSL_SIGNATURE_PARAM_DETERMINISTIC, &detInt);
    params[idx++] = OpensslOsslParamConstructInt(OSSL_SIGNATURE_PARAM_MU, &muInt);
    if (context != NULL && context->data != NULL && context->len > 0) {
        params[idx++] = OpensslOsslParamConstructOctetString(OSSL_SIGNATURE_PARAM_CONTEXT_STRING,
            context->data, context->len);
    }
    params[idx] = OpensslOsslParamConstructEnd();
    if (OpensslEvpPkeyCtxSetParams(pkeyCtx, params) != HCF_OPENSSL_SUCCESS) {
        HcfPrintOpensslError();
        LOGE("EVP_PKEY_CTX_set_params failed.");
        return HCF_ERR_CRYPTO_OPERATION;
    }
    return HCF_SUCCESS;
}

static HcfResult EngineSignInit(HcfSignSpi *self, HcfParamsSpec *params, HcfPriKey *privateKey)
{
    (void)params;
    if ((self == NULL) || (privateKey == NULL)) {
        LOGE("Invalid input parameter.");
        return HCF_ERR_PARAMETER_CHECK_FAILED;
    }
    if ((!HcfIsClassMatch((HcfObjectBase *)self, self->base.getClass())) ||
        (!HcfIsClassMatch((HcfObjectBase *)privateKey, OPENSSL_ML_DSA_PRIKEY_CLASS))) {
        LOGE("Class not match.");
        return HCF_ERR_PARAMETER_CHECK_FAILED;
    }
    HcfSignSpiMlDsaOpensslImpl *impl = (HcfSignSpiMlDsaOpensslImpl *)self;
    if (impl->status != UNINITIALIZED) {
        LOGE("Repeated initialization is not allowed.");
        return HCF_ERR_INVALID_CALL;
    }
    if (OpensslEvpDigestSignInit(impl->mdCtx, NULL, NULL, NULL,
        ((HcfOpensslMlDsaPriKey *)privateKey)->pkey) != HCF_OPENSSL_SUCCESS) {
        HcfPrintOpensslError();
        LOGE("EVP_DigestSignInit failed.");
        return HCF_ERR_CRYPTO_OPERATION;
    }
    HcfResult ret = SetMlDsaOsslParams(impl->mdCtx, impl->deterministic, impl->mu, &impl->context);
    if (ret != HCF_SUCCESS) {
        return ret;
    }
    impl->status = INITIALIZED;
    return HCF_SUCCESS;
}

static HcfResult EngineSignUpdate(HcfSignSpi *self, HcfBlob *data)
{
    (void)self;
    (void)data;
    LOGE("MlDsa sign update not supported.");
    return HCF_ERR_INVALID_CALL;
}

static HcfResult EngineSignDoFinal(HcfSignSpi *self, HcfBlob *data, HcfBlob *returnSignatureData)
{
    if ((self == NULL) || (returnSignatureData == NULL)) {
        LOGE("Invalid input parameter.");
        return HCF_ERR_PARAMETER_CHECK_FAILED;
    }
    if (!HcfIsClassMatch((HcfObjectBase *)self, self->base.getClass())) {
        LOGE("Class not match.");
        return HCF_ERR_PARAMETER_CHECK_FAILED;
    }
    if (!HcfIsBlobValid(data)) {
        LOGE("Invalid sign data.");
        return HCF_ERR_PARAMETER_CHECK_FAILED;
    }
    HcfSignSpiMlDsaOpensslImpl *impl = (HcfSignSpiMlDsaOpensslImpl *)self;
    if (impl->status != INITIALIZED) {
        LOGE("The message has not been initialized.");
        return HCF_ERR_PARAMETER_CHECK_FAILED;
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
        return HCF_ERR_PARAMETER_CHECK_FAILED;
    }
    if ((!HcfIsClassMatch((HcfObjectBase *)self, self->base.getClass())) ||
        (!HcfIsClassMatch((HcfObjectBase *)publicKey, OPENSSL_ML_DSA_PUBKEY_CLASS))) {
        LOGE("Class not match.");
        return HCF_ERR_PARAMETER_CHECK_FAILED;
    }
    HcfVerifySpiMlDsaOpensslImpl *impl = (HcfVerifySpiMlDsaOpensslImpl *)self;
    if (impl->status != UNINITIALIZED) {
        LOGE("Repeated initialization is not allowed.");
        return HCF_ERR_INVALID_CALL;
    }
    EVP_PKEY *pKey = OpensslEvpPkeyDup(((HcfOpensslMlDsaPubKey *)publicKey)->pkey);
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
    HcfResult ret = SetMlDsaOsslParams(impl->mdCtx, impl->deterministic, impl->mu, &impl->context);
    if (ret != HCF_SUCCESS) {
        return ret;
    }
    impl->status = INITIALIZED;
    return HCF_SUCCESS;
}

static HcfResult EngineVerifyUpdate(HcfVerifySpi *self, HcfBlob *data)
{
    (void)self;
    (void)data;
    LOGE("MlDsa verify update not supported.");
    return HCF_ERR_INVALID_CALL;
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
    HcfVerifySpiMlDsaOpensslImpl *impl = (HcfVerifySpiMlDsaOpensslImpl *)self;
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

static HcfResult EngineRecover(HcfVerifySpi *self, HcfBlob *signatureData, HcfBlob *rawSignatureData)
{
    (void)self;
    (void)signatureData;
    (void)rawSignatureData;
    LOGE("MlDsa recover not supported.");
    return HCF_ERR_INVALID_CALL;
}

static HcfResult EngineGetSignSpecString(HcfSignSpi *self, SignSpecItem item, char **returnString)
{
    (void)self;
    (void)item;
    (void)returnString;
    LOGE("GetSignSpecString not supported.");
    return HCF_ERR_INVALID_CALL;
}

static HcfResult EngineSetSignSpecUint8Array(HcfSignSpi *self, SignSpecItem item, HcfBlob blob)
{
    if (self == NULL || !HcfIsBlobValid(&blob) || blob.len > MAX_CONTEXT_LENGTH) {
        LOGE("Invalid input parameter.");
        return HCF_ERR_PARAMETER_CHECK_FAILED;
    }
    if (!HcfIsClassMatch((HcfObjectBase *)self, OPENSSL_ML_DSA_SIGN_CLASS)) {
        LOGE("Class not match.");
        return HCF_ERR_PARAMETER_CHECK_FAILED;
    }
    if (item != ML_DSA_CONTEXT_UINT8ARR) {
        LOGE("Invalid sign spec item.");
        return HCF_ERR_PARAMETER_CHECK_FAILED;
    }
    HcfSignSpiMlDsaOpensslImpl *impl = (HcfSignSpiMlDsaOpensslImpl *)self;
    if (impl->status != UNINITIALIZED) {
        LOGE("Set sign spec not allowed after init.");
        return HCF_ERR_INVALID_CALL;
    }
    MlDsaSignFreeContext(impl);
    impl->context.data = (uint8_t *)HcfMalloc(blob.len, 0);
    if (impl->context.data == NULL) {
        LOGE("Failed to allocate context data memory.");
        return HCF_ERR_MALLOC;
    }
    if (memcpy_s(impl->context.data, blob.len, blob.data, blob.len) != EOK) {
        LOGE("memcpy context failed.");
        HcfFree(impl->context.data);
        impl->context.data = NULL;
        return HCF_ERR_CRYPTO_OPERATION;
    }
    impl->context.len = blob.len;
    return HCF_SUCCESS;
}

static HcfResult EngineGetSignSpecInt(HcfSignSpi *self, SignSpecItem item, int32_t *returnInt)
{
    (void)self;
    (void)item;
    (void)returnInt;
    LOGE("GetSignSpecInt not supported.");
    return HCF_ERR_INVALID_CALL;
}

static HcfResult EngineSetSignSpecInt(HcfSignSpi *self, SignSpecItem item, int32_t saltLen)
{
    (void)self;
    (void)item;
    (void)saltLen;
    LOGE("SetSignSpecInt not supported.");
    return HCF_ERR_INVALID_CALL;
}

static HcfResult EngineSetSignSpecBool(HcfSignSpi *self, SignSpecItem item, bool flag)
{
    if (self == NULL) {
        LOGE("Invalid input parameter.");
        return HCF_ERR_PARAMETER_CHECK_FAILED;
    }
    if (!HcfIsClassMatch((HcfObjectBase *)self, OPENSSL_ML_DSA_SIGN_CLASS)) {
        LOGE("Class not match.");
        return HCF_ERR_PARAMETER_CHECK_FAILED;
    }
    HcfSignSpiMlDsaOpensslImpl *impl = (HcfSignSpiMlDsaOpensslImpl *)self;
    if (impl->status != UNINITIALIZED) {
        LOGE("Set sign spec not allowed after init.");
        return HCF_ERR_INVALID_CALL;
    }
    if (item == ML_DSA_DETERMINISTIC_BOOL) {
        impl->deterministic = flag;
    } else if (item == ML_DSA_MU_BOOL) {
        impl->mu = flag;
    } else {
        LOGE("Invalid sign spec item.");
        return HCF_ERR_PARAMETER_CHECK_FAILED;
    }
    return HCF_SUCCESS;
}

static HcfResult EngineGetVerifySpecString(HcfVerifySpi *self, SignSpecItem item, char **returnString)
{
    (void)self;
    (void)item;
    (void)returnString;
    LOGE("GetVerifySpecString not supported.");
    return HCF_ERR_INVALID_CALL;
}

static HcfResult EngineSetVerifySpecUint8Array(HcfVerifySpi *self, SignSpecItem item, HcfBlob blob)
{
    if (self == NULL || !HcfIsBlobValid(&blob) || blob.len > MAX_CONTEXT_LENGTH) {
        LOGE("Invalid input parameter.");
        return HCF_ERR_PARAMETER_CHECK_FAILED;
    }
    if (!HcfIsClassMatch((HcfObjectBase *)self, OPENSSL_ML_DSA_VERIFY_CLASS)) {
        LOGE("Class not match.");
        return HCF_ERR_PARAMETER_CHECK_FAILED;
    }
    if (item != ML_DSA_CONTEXT_UINT8ARR) {
        LOGE("Invalid verify spec item.");
        return HCF_ERR_PARAMETER_CHECK_FAILED;
    }
    HcfVerifySpiMlDsaOpensslImpl *impl = (HcfVerifySpiMlDsaOpensslImpl *)self;
    if (impl->status != UNINITIALIZED) {
        LOGE("Set verify spec not allowed after init.");
        return HCF_ERR_INVALID_CALL;
    }
    MlDsaVerifyFreeContext(impl);
    impl->context.data = (uint8_t *)HcfMalloc(blob.len, 0);
    if (impl->context.data == NULL) {
        LOGE("Failed to allocate context data memory.");
        return HCF_ERR_MALLOC;
    }
    if (memcpy_s(impl->context.data, blob.len, blob.data, blob.len) != EOK) {
        LOGE("memcpy context failed.");
        HcfFree(impl->context.data);
        impl->context.data = NULL;
        return HCF_ERR_CRYPTO_OPERATION;
    }
    impl->context.len = blob.len;
    return HCF_SUCCESS;
}

static HcfResult EngineGetVerifySpecInt(HcfVerifySpi *self, SignSpecItem item, int32_t *returnInt)
{
    (void)self;
    (void)item;
    (void)returnInt;
    LOGE("GetVerifySpecInt not supported.");
    return HCF_ERR_INVALID_CALL;
}

static HcfResult EngineSetVerifySpecInt(HcfVerifySpi *self, SignSpecItem item, int32_t saltLen)
{
    (void)self;
    (void)item;
    (void)saltLen;
    LOGE("SetVerifySpecInt not supported.");
    return HCF_ERR_INVALID_CALL;
}

static HcfResult EngineSetVerifySpecBool(HcfVerifySpi *self, SignSpecItem item, bool flag)
{
    if (self == NULL) {
        LOGE("Invalid input parameter.");
        return HCF_ERR_PARAMETER_CHECK_FAILED;
    }
    if (!HcfIsClassMatch((HcfObjectBase *)self, OPENSSL_ML_DSA_VERIFY_CLASS)) {
        LOGE("Class not match.");
        return HCF_ERR_PARAMETER_CHECK_FAILED;
    }
    HcfVerifySpiMlDsaOpensslImpl *impl = (HcfVerifySpiMlDsaOpensslImpl *)self;
    if (impl->status != UNINITIALIZED) {
        LOGE("Set verify spec not allowed after init.");
        return HCF_ERR_INVALID_CALL;
    }
    if (item == ML_DSA_MU_BOOL) {
        impl->mu = flag;
    } else if (item == ML_DSA_DETERMINISTIC_BOOL) {
        impl->deterministic = flag;
    } else {
        LOGE("Invalid verify spec item.");
        return HCF_ERR_PARAMETER_CHECK_FAILED;
    }
    return HCF_SUCCESS;
}

HcfResult HcfSignSpiMlDsaCreate(HcfSignatureParams *params, HcfSignSpi **returnObj)
{
    (void)params;
    if (returnObj == NULL) {
        LOGE("Invalid input parameter.");
        return HCF_ERR_PARAMETER_CHECK_FAILED;
    }
    HcfSignSpiMlDsaOpensslImpl *returnImpl = (HcfSignSpiMlDsaOpensslImpl *)HcfMalloc(
        sizeof(HcfSignSpiMlDsaOpensslImpl), 0);
    if (returnImpl == NULL) {
        LOGE("Failed to allocate returnImpl memory!");
        return HCF_ERR_MALLOC;
    }
    returnImpl->base.base.getClass = GetMlDsaSignClass;
    returnImpl->base.base.destroy = DestroyMlDsaSign;
    returnImpl->base.engineInit = EngineSignInit;
    returnImpl->base.engineUpdate = EngineSignUpdate;
    returnImpl->base.engineSign = EngineSignDoFinal;
    returnImpl->base.engineGetSignSpecString = EngineGetSignSpecString;
    returnImpl->base.engineSetSignSpecUint8Array = EngineSetSignSpecUint8Array;
    returnImpl->base.engineGetSignSpecInt = EngineGetSignSpecInt;
    returnImpl->base.engineSetSignSpecInt = EngineSetSignSpecInt;
    returnImpl->base.engineSetSignSpecBool = EngineSetSignSpecBool;
    returnImpl->status = UNINITIALIZED;
    returnImpl->mdCtx = OpensslEvpMdCtxNew();
    if (returnImpl->mdCtx == NULL) {
        LOGE("Failed to allocate mdCtx memory!");
        HcfFree(returnImpl);
        return HCF_ERR_MALLOC;
    }
    *returnObj = (HcfSignSpi *)returnImpl;
    return HCF_SUCCESS;
}

HcfResult HcfVerifySpiMlDsaCreate(HcfSignatureParams *params, HcfVerifySpi **returnObj)
{
    (void)params;
    if (returnObj == NULL) {
        LOGE("Invalid input parameter.");
        return HCF_ERR_PARAMETER_CHECK_FAILED;
    }
    HcfVerifySpiMlDsaOpensslImpl *returnImpl = (HcfVerifySpiMlDsaOpensslImpl *)HcfMalloc(
        sizeof(HcfVerifySpiMlDsaOpensslImpl), 0);
    if (returnImpl == NULL) {
        LOGE("Failed to allocate returnImpl memory!");
        return HCF_ERR_MALLOC;
    }
    returnImpl->base.base.getClass = GetMlDsaVerifyClass;
    returnImpl->base.base.destroy = DestroyMlDsaVerify;
    returnImpl->base.engineInit = EngineVerifyInit;
    returnImpl->base.engineUpdate = EngineVerifyUpdate;
    returnImpl->base.engineVerify = EngineVerifyDoFinal;
    returnImpl->base.engineRecover = EngineRecover;
    returnImpl->base.engineGetVerifySpecString = EngineGetVerifySpecString;
    returnImpl->base.engineSetVerifySpecUint8Array = EngineSetVerifySpecUint8Array;
    returnImpl->base.engineGetVerifySpecInt = EngineGetVerifySpecInt;
    returnImpl->base.engineSetVerifySpecInt = EngineSetVerifySpecInt;
    returnImpl->base.engineSetVerifySpecBool = EngineSetVerifySpecBool;
    returnImpl->status = UNINITIALIZED;
    returnImpl->mdCtx = OpensslEvpMdCtxNew();
    if (returnImpl->mdCtx == NULL) {
        LOGE("Failed to allocate mdCtx memory!");
        HcfFree(returnImpl);
        return HCF_ERR_MALLOC;
    }
    *returnObj = (HcfVerifySpi *)returnImpl;
    return HCF_SUCCESS;
}
