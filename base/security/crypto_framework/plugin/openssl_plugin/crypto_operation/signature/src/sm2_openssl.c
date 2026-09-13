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

#include "sm2_openssl.h"

#include <limits.h>
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

#define OPENSSL_SM2_SIGN_CLASS "OPENSSL.SM2.SIGN"
#define OPENSSL_SM2_VERIFY_CLASS "OPENSSL.SM2.VERIFY"

typedef struct {
    HcfSignSpi base;

    HcfBlob userId;

    const EVP_MD *digestAlg;

    EVP_MD_CTX *mdCtx;

    CryptoStatus status;
} HcfSignSpiSm2OpensslImpl;

typedef struct {
    HcfVerifySpi base;

    HcfBlob userId;

    const EVP_MD *digestAlg;

    EVP_MD_CTX *mdCtx;

    CryptoStatus status;
} HcfVerifySpiSm2OpensslImpl;

static bool IsDigestAlgValid(uint32_t alg)
{
    if (alg == HCF_OPENSSL_DIGEST_SM3) {
        return true;
    } else {
        LOGE("Invalid digest num!");
        return false;
    }
}

// export interfaces
static const char *GetSm2SignClass(void)
{
    return OPENSSL_SM2_SIGN_CLASS;
}

static const char *GetSm2VerifyClass(void)
{
    return OPENSSL_SM2_VERIFY_CLASS;
}

static void DestroySm2Sign(HcfObjectBase *self)
{
    if (self == NULL) {
        LOGE("Class is null.");
        return;
    }
    if (!HcfIsClassMatch(self, self->getClass())) {
        LOGE("Class not match.");
        return;
    }
    HcfSignSpiSm2OpensslImpl *impl = (HcfSignSpiSm2OpensslImpl *)self;
    impl->digestAlg = NULL;
    if (impl->mdCtx != NULL) {
        OpensslEvpPkeyCtxFree(OpensslEvpMdCtxGetPkeyCtx(impl->mdCtx));
        OpensslEvpMdCtxFree(impl->mdCtx);
        impl->mdCtx = NULL;
    }
    HcfFree(impl->userId.data);
    impl->userId.data = NULL;
    HcfFree(impl);
}

static void DestroySm2Verify(HcfObjectBase *self)
{
    if (self == NULL) {
        LOGE("Class is null.");
        return;
    }
    if (!HcfIsClassMatch(self, self->getClass())) {
        LOGE("Class not match.");
        return;
    }
    HcfVerifySpiSm2OpensslImpl *impl = (HcfVerifySpiSm2OpensslImpl *)self;
    impl->digestAlg = NULL;
    if (impl->mdCtx != NULL) {
        OpensslEvpPkeyCtxFree(OpensslEvpMdCtxGetPkeyCtx(impl->mdCtx));
        OpensslEvpMdCtxFree(impl->mdCtx);
        impl->mdCtx = NULL;
    }
    HcfFree(impl->userId.data);
    impl->userId.data = NULL;
    HcfFree(impl);
}
static HcfResult SetUserIdFromBlob(HcfBlob userId, EVP_MD_CTX *mdCtx)
{
    EVP_PKEY_CTX *pKeyCtx = OpensslEvpMdCtxGetPkeyCtx(mdCtx);
    if (pKeyCtx == NULL) {
        LOGE("get pKey ctx fail.");
        HcfPrintOpensslError();
        return HCF_ERR_CRYPTO_OPERATION;
    }
    // If userId is NULL or len is 0, the userId will be cleared.
    if (userId.data == NULL || userId.len == 0) {
        if (OpensslEvpPkeyCtxSet1Id(pKeyCtx, NULL, 0) != HCF_OPENSSL_SUCCESS) {
            LOGE("Openssl Set userId fail");
            HcfPrintOpensslError();
            return HCF_ERR_CRYPTO_OPERATION;
        }
        OpensslEvpMdCtxSetPkeyCtx(mdCtx, pKeyCtx);
        return HCF_SUCCESS;
    }
    if (OpensslEvpPkeyCtxSet1Id(pKeyCtx, (const void*)userId.data,
        userId.len) != HCF_OPENSSL_SUCCESS) {
        LOGE("Set sm2 user id fail.");
        HcfPrintOpensslError();
        return HCF_ERR_CRYPTO_OPERATION;
    }
    OpensslEvpMdCtxSetPkeyCtx(mdCtx, pKeyCtx);
    return HCF_SUCCESS;
}

static HcfResult SetSM2Id(EVP_MD_CTX *mdCtx, EVP_PKEY *pKey, HcfBlob userId)
{
    EVP_PKEY_CTX *pKeyCtx = OpensslEvpPkeyCtxNew(pKey, NULL);
    if (pKeyCtx == NULL) {
        LOGE("new EVP_PKEY_CTX fail");
        HcfPrintOpensslError();
        return HCF_ERR_CRYPTO_OPERATION;
    }
    if (OpensslEvpPkeyCtxSet1Id(pKeyCtx, (const void*)userId.data,
        userId.len) != HCF_OPENSSL_SUCCESS) {
        LOGE("Set sm2 user id fail");
        HcfPrintOpensslError();
        OpensslEvpPkeyCtxFree(pKeyCtx);
        return HCF_ERR_CRYPTO_OPERATION;
    }
    OpensslEvpMdCtxSetPkeyCtx(mdCtx, pKeyCtx);
    return HCF_SUCCESS;
}

static bool IsSm2SignInitInputValid(HcfSignSpi *self, HcfPriKey *privateKey)
{
    if ((self == NULL) || (privateKey == NULL)) {
        LOGE("Invalid input parameter.");
        return false;
    }
    if ((!HcfIsClassMatch((HcfObjectBase *)self, self->base.getClass())) ||
        (!HcfIsClassMatch((HcfObjectBase *)privateKey, HCF_OPENSSL_SM2_PRI_KEY_CLASS))) {
        LOGE("Class not match.");
        return false;
    }
    HcfSignSpiSm2OpensslImpl *impl = (HcfSignSpiSm2OpensslImpl *)self;
    if (impl->status != UNINITIALIZED) {
        LOGE("Repeated initialization is not allowed.");
        return false;
    }
    return true;
}

static HcfResult EngineSignInit(HcfSignSpi *self, HcfParamsSpec *params, HcfPriKey *privateKey)
{
    (void)params;
    if (!IsSm2SignInitInputValid(self, privateKey)) {
        return HCF_INVALID_PARAMS;
    }

    EC_KEY *ecKey = OpensslEcKeyDup(((HcfOpensslSm2PriKey *)privateKey)->ecKey);
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

    HcfSignSpiSm2OpensslImpl *impl = (HcfSignSpiSm2OpensslImpl *)self;
    if (SetSM2Id(impl->mdCtx, pKey, impl->userId) != HCF_SUCCESS) {
        OpensslEvpPkeyFree(pKey);
        LOGE("Set sm2 user id failed.");
        return HCF_ERR_CRYPTO_OPERATION;
    }
    if (OpensslEvpDigestSignInit(impl->mdCtx, NULL, impl->digestAlg, NULL, pKey) != HCF_OPENSSL_SUCCESS) {
        HcfPrintOpensslError();
        LOGE("EVP_DigestSignInit failed.");
        OpensslEvpPkeyFree(pKey);
        return HCF_ERR_CRYPTO_OPERATION;
    }
    OpensslEvpPkeyFree(pKey);
    impl->status = INITIALIZED;
    return HCF_SUCCESS;
}

static HcfResult EngineSignUpdate(HcfSignSpi *self, HcfBlob *data)
{
    if ((self == NULL) || (!HcfIsBlobValid(data))) {
        LOGE("Invalid input parameter.");
        return HCF_INVALID_PARAMS;
    }
    if (!HcfIsClassMatch((HcfObjectBase *)self, self->base.getClass())) {
        LOGE("Class not match.");
        return HCF_INVALID_PARAMS;
    }
    HcfSignSpiSm2OpensslImpl *impl = (HcfSignSpiSm2OpensslImpl *)self;
    if (impl->status == UNINITIALIZED) {
        LOGE("Sign object has not been initialized.");
        return HCF_INVALID_PARAMS;
    }
    if (OpensslEvpDigestSignUpdate(impl->mdCtx, data->data, data->len) != HCF_OPENSSL_SUCCESS) {
        HcfPrintOpensslError();
        LOGE("EVP_DigestSignUpdate failed.");
        return HCF_ERR_CRYPTO_OPERATION;
    }
    impl->status = READY;
    return HCF_SUCCESS;
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

    HcfSignSpiSm2OpensslImpl *impl = (HcfSignSpiSm2OpensslImpl *)self;
    if (impl->status == UNINITIALIZED) {
        LOGW("Sign instance may not have been initialized, "
            "ensure init interface of Sign instance is executed completely!");
    }
    if (HcfIsBlobValid(data)) {
        if (OpensslEvpDigestSignUpdate(impl->mdCtx, data->data, data->len) != HCF_OPENSSL_SUCCESS) {
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
    if (OpensslEvpDigestSignFinal(impl->mdCtx, NULL, &maxLen) != HCF_OPENSSL_SUCCESS) {
        HcfPrintOpensslError();
        LOGE("EVP_DigestSignFinal failed.");
        return HCF_ERR_CRYPTO_OPERATION;
    }
    uint8_t *outData = (uint8_t *)HcfMalloc(maxLen, 0);
    if (outData == NULL) {
        LOGE("Failed to allocate outData memory!");
        return HCF_ERR_MALLOC;
    }

    if (OpensslEvpDigestSignFinal(impl->mdCtx, outData, &maxLen) != HCF_OPENSSL_SUCCESS) {
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

static bool IsSm2VerifyInitInputValid(HcfVerifySpi *self, HcfPubKey *publicKey)
{
    if ((self == NULL) || (publicKey == NULL)) {
        LOGE("Invalid input parameter.");
        return false;
    }
    if ((!HcfIsClassMatch((HcfObjectBase *)self, self->base.getClass())) ||
        (!HcfIsClassMatch((HcfObjectBase *)publicKey, HCF_OPENSSL_SM2_PUB_KEY_CLASS))) {
        LOGE("Class not match.");
        return false;
    }

    HcfVerifySpiSm2OpensslImpl *impl = (HcfVerifySpiSm2OpensslImpl *)self;
    if (impl->status != UNINITIALIZED) {
        LOGE("Repeated initialization is not allowed.");
        return false;
    }
    return true;
}

static HcfResult EngineVerifyInit(HcfVerifySpi *self, HcfParamsSpec *params, HcfPubKey *publicKey)
{
    (void)params;
    if (!IsSm2VerifyInitInputValid(self, publicKey)) {
        return HCF_INVALID_PARAMS;
    }

    EC_KEY *ecKey = OpensslEcKeyDup(((HcfOpensslSm2PubKey *)publicKey)->ecKey);
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
    HcfVerifySpiSm2OpensslImpl *impl = (HcfVerifySpiSm2OpensslImpl *)self;
    if (SetSM2Id(impl->mdCtx, pKey, impl->userId) != HCF_SUCCESS) {
        LOGE("Set sm2 user id failed.");
        OpensslEvpPkeyFree(pKey);
        return HCF_ERR_CRYPTO_OPERATION;
    }
    if (OpensslEvpDigestVerifyInit(impl->mdCtx, NULL, impl->digestAlg, NULL, pKey) != HCF_OPENSSL_SUCCESS) {
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
    if ((self == NULL) || (!HcfIsBlobValid(data))) {
        LOGE("Invalid input parameter.");
        return HCF_INVALID_PARAMS;
    }
    if (!HcfIsClassMatch((HcfObjectBase *)self, self->base.getClass())) {
        LOGE("Class not match.");
        return HCF_INVALID_PARAMS;
    }

    HcfVerifySpiSm2OpensslImpl *impl = (HcfVerifySpiSm2OpensslImpl *)self;
    if (impl->status == UNINITIALIZED) {
        LOGE("Verify object has not been initialized.");
        return HCF_INVALID_PARAMS;
    }
    if (OpensslEvpDigestVerifyUpdate(impl->mdCtx, data->data, data->len) != HCF_OPENSSL_SUCCESS) {
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
    if (!HcfIsClassMatch((HcfObjectBase *)self, self->base.getClass())) {
        LOGE("Class not match.");
        return false;
    }

    HcfVerifySpiSm2OpensslImpl *impl = (HcfVerifySpiSm2OpensslImpl *)self;
    if (impl->status == UNINITIALIZED) {
        LOGW("Verify instance may not have been initialized, "
            "ensure init interface of Verify instance is executed completely!");
    }
    if (HcfIsBlobValid(data)) {
        if (OpensslEvpDigestVerifyUpdate(impl->mdCtx, data->data, data->len) != HCF_OPENSSL_SUCCESS) {
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
    if (OpensslEvpDigestVerifyFinal(impl->mdCtx, signatureData->data, signatureData->len) != HCF_OPENSSL_SUCCESS) {
        HcfPrintOpensslError();
        LOGE("EVP_DigestVerifyFinal failed.");
        return false;
    }
    return true;
}

static HcfResult EngineGetSignSpecString(HcfSignSpi *self, SignSpecItem item, char **returnString)
{
    (void)self;
    (void)item;
    (void)returnString;
    LOGE("GetSignSpecString not supported.");
    return HCF_NOT_SUPPORT;
}

static HcfResult EngineSetSignSpecUint8Array(HcfSignSpi *self, SignSpecItem item, HcfBlob userId)
{
    if (self == NULL) {
        LOGE("Invalid input parameter");
        return HCF_INVALID_PARAMS;
    }
    if (!HcfIsClassMatch((HcfObjectBase *)self, OPENSSL_SM2_SIGN_CLASS)) {
        LOGE("Class not match.");
        return HCF_INVALID_PARAMS;
    }
    if (item != SM2_USER_ID_UINT8ARR) {
        LOGE("Invalid input spec");
        return HCF_INVALID_PARAMS;
    }
    if (userId.len > UINT32_MAX) {
        LOGE("Invalid userId len");
        return HCF_INVALID_PARAMS;
    }
    HcfSignSpiSm2OpensslImpl *impl = (HcfSignSpiSm2OpensslImpl *)self;
    // if it has userId from previous set, it should be free at first;
    if (impl->userId.data != NULL) {
        HcfFree(impl->userId.data);
        impl->userId.data = NULL;
    }
    // If userId is NULL or len is 0, the userId will be cleared.
    if (userId.data == NULL || userId.len == 0) {
        impl->userId.data = NULL;
        impl->userId.len = 0;
    } else {
        // deep copy two userId, one for impl struct and one for openssl.
        impl->userId.data = (uint8_t *)HcfMalloc(userId.len, 0);
        if (impl->userId.data == NULL) {
            LOGE("Failed to allocate userId data memory");
            return HCF_ERR_MALLOC;
        }
        if (memcpy_s(impl->userId.data, userId.len, userId.data, userId.len) != EOK) {
            LOGE("memcpy userId failed.");
            HcfFree(impl->userId.data);
            impl->userId.data = NULL;
            return HCF_ERR_MALLOC;
        }
        impl->userId.len = userId.len;
    }
    // if uninitliszed, userId should only be stored in the struct.
    // if initliszed, userId should have another copy and set the copy to the evp ctx.
    if (impl->status == INITIALIZED) {
        HcfResult ret = SetUserIdFromBlob(impl->userId, impl->mdCtx);
        if (ret != HCF_SUCCESS) {
            LOGE("Set userId fail");
            HcfFree(impl->userId.data);
            impl->userId.data = NULL;
            return ret;
        }
    }
    return HCF_SUCCESS;
}

static HcfResult EngineGetSignSpecInt(HcfSignSpi *self, SignSpecItem item, int32_t *returnInt)
{
    (void)self;
    (void)item;
    (void)returnInt;
    LOGE("GetSignSpecInt not supported.");
    return HCF_NOT_SUPPORT;
}

static HcfResult EngineSetSignSpecInt(HcfSignSpi *self, SignSpecItem item, int32_t saltLen)
{
    (void)self;
    (void)item;
    (void)saltLen;
    LOGE("SetSignSpecInt not supported.");
    return HCF_NOT_SUPPORT;
}

static HcfResult EngineGetVerifySpecString(HcfVerifySpi *self, SignSpecItem item, char **returnString)
{
    (void)self;
    (void)item;
    (void)returnString;
    LOGE("GetVerifySpecString not supported.");
    return HCF_NOT_SUPPORT;
}

static HcfResult EngineSetVerifySpecUint8Array(HcfVerifySpi *self, SignSpecItem item, HcfBlob userId)
{
    if (self == NULL) {
        LOGE("Invalid input parameter");
        return HCF_INVALID_PARAMS;
    }
    if (!HcfIsClassMatch((HcfObjectBase *)self, OPENSSL_SM2_VERIFY_CLASS)) {
        LOGE("Class not match.");
        return HCF_INVALID_PARAMS;
    }
    if (item != SM2_USER_ID_UINT8ARR) {
        LOGE("Invalid input spec");
        return HCF_INVALID_PARAMS;
    }
    if (userId.len > UINT32_MAX) {
        LOGE("Invalid userId len");
        return HCF_INVALID_PARAMS;
    }
    HcfVerifySpiSm2OpensslImpl *impl = (HcfVerifySpiSm2OpensslImpl *)self;
    // if it has userId from previous set, it should be free at first;
    if (impl->userId.data != NULL) {
        HcfFree(impl->userId.data);
        impl->userId.data = NULL;
    }
    // If userId is NULL or len is 0, the userId will be cleared.
    if (userId.data == NULL || userId.len == 0) {
        impl->userId.data = NULL;
        impl->userId.len = 0;
    } else {
        // deep copy two userId, one for impl struct and one for openssl.
        impl->userId.data = (uint8_t *)HcfMalloc(userId.len, 0);
        if (impl->userId.data == NULL) {
            LOGE("Failed to allocate userId data memory");
            return HCF_ERR_MALLOC;
        }
        if (memcpy_s(impl->userId.data, userId.len, userId.data, userId.len) != EOK) {
            LOGE("memcpy userId failed.");
            HcfFree(impl->userId.data);
            impl->userId.data = NULL;
            return HCF_ERR_MALLOC;
        }
        impl->userId.len = userId.len;
    }
    // if uninitliszed, userId should only be stored in the struct.
    // if initliszed, userId should have another copy and set the copy to the evp ctx.
    if (impl->status == INITIALIZED) {
        HcfResult ret = SetUserIdFromBlob(impl->userId, impl->mdCtx);
        if (ret != HCF_SUCCESS) {
            LOGE("Set userId fail");
            HcfFree(impl->userId.data);
            impl->userId.data = NULL;
            return ret;
        }
    }
    return HCF_SUCCESS;
}

static HcfResult EngineGetVerifySpecInt(HcfVerifySpi *self, SignSpecItem item, int32_t *returnInt)
{
    (void)self;
    (void)item;
    (void)returnInt;
    LOGE("GetVerifySpecInt not supported.");
    return HCF_NOT_SUPPORT;
}

static HcfResult EngineSetVerifySpecInt(HcfVerifySpi *self, SignSpecItem item, int32_t saltLen)
{
    (void)self;
    (void)item;
    (void)saltLen;
    LOGE("SetVerifySpecInt not supported.");
    return HCF_NOT_SUPPORT;
}

static HcfResult CheckSignInputParamsAndDigest(HcfSignatureParams *params, HcfSignSpi **returnObj)
{
    if ((params == NULL) || (returnObj == NULL)) {
        LOGE("Invalid input parameter.");
        return HCF_INVALID_PARAMS;
    }
    if (!IsDigestAlgValid(params->md)) {
        LOGE("Invalid input md parameter.");
        return HCF_INVALID_PARAMS;
    }
    return HCF_SUCCESS;
}

static HcfResult CheckVerifyInputParamsAndDigest(HcfSignatureParams *params, HcfVerifySpi **returnObj)
{
    if ((params == NULL) || (returnObj == NULL)) {
        LOGE("Invalid input parameter.");
        return HCF_INVALID_PARAMS;
    }
    if (!IsDigestAlgValid(params->md)) {
        LOGE("Invalid input md parameter.");
        return HCF_INVALID_PARAMS;
    }
    return HCF_SUCCESS;
}

HcfResult HcfSignSpiSm2Create(HcfSignatureParams *params, HcfSignSpi **returnObj)
{
    if (CheckSignInputParamsAndDigest(params, returnObj) != HCF_SUCCESS) {
        LOGE("Check input params and digest failed.");
        return HCF_INVALID_PARAMS;
    }
    EVP_MD *opensslAlg = NULL;
    int32_t ret = GetOpensslDigestAlg(params->md, &opensslAlg);
    if (ret != HCF_SUCCESS || opensslAlg == NULL) {
        LOGE("Failed to Invalid digest!");
        return HCF_INVALID_PARAMS;
    }

    HcfSignSpiSm2OpensslImpl *returnImpl = (HcfSignSpiSm2OpensslImpl *)HcfMalloc(
        sizeof(HcfSignSpiSm2OpensslImpl), 0);
    if (returnImpl == NULL) {
        LOGE("Failed to allocate returnImpl memroy!");
        return HCF_ERR_MALLOC;
    }
    returnImpl->base.base.getClass = GetSm2SignClass;
    returnImpl->base.base.destroy = DestroySm2Sign;
    returnImpl->base.engineInit = EngineSignInit;
    returnImpl->base.engineUpdate = EngineSignUpdate;
    returnImpl->base.engineSign = EngineSignDoFinal;
    returnImpl->base.engineGetSignSpecString = EngineGetSignSpecString;
    returnImpl->base.engineSetSignSpecUint8Array = EngineSetSignSpecUint8Array;
    returnImpl->base.engineGetSignSpecInt = EngineGetSignSpecInt;
    returnImpl->base.engineSetSignSpecInt = EngineSetSignSpecInt;
    returnImpl->digestAlg = opensslAlg;
    returnImpl->status = UNINITIALIZED;
    returnImpl->userId.data = (uint8_t *)HcfMalloc(strlen(SM2_DEFAULT_USERID) + 1, 0);
    if (returnImpl->userId.data == NULL) {
        LOGE("Failed to allocate userId data memory");
        HcfFree(returnImpl);
        returnImpl = NULL;
        return HCF_ERR_MALLOC;
    }
    (void)memcpy_s(returnImpl->userId.data, strlen(SM2_DEFAULT_USERID), SM2_DEFAULT_USERID, strlen(SM2_DEFAULT_USERID));
    returnImpl->userId.len = strlen(SM2_DEFAULT_USERID);
    returnImpl->mdCtx = OpensslEvpMdCtxNew();
    if (returnImpl->mdCtx == NULL) {
        LOGE("Failed to allocate mdCtx memory!");
        HcfFree(returnImpl->userId.data);
        returnImpl->userId.data = NULL;
        HcfFree(returnImpl);
        returnImpl = NULL;
        return HCF_ERR_MALLOC;
    }

    *returnObj = (HcfSignSpi *)returnImpl;
    return HCF_SUCCESS;
}

HcfResult HcfVerifySpiSm2Create(HcfSignatureParams *params, HcfVerifySpi **returnObj)
{
    if (CheckVerifyInputParamsAndDigest(params, returnObj) != HCF_SUCCESS) {
        LOGE("Check input params and digest failed.");
        return HCF_INVALID_PARAMS;
    }
    EVP_MD *opensslAlg = NULL;
    int32_t ret = GetOpensslDigestAlg(params->md, &opensslAlg);
    if (ret != HCF_SUCCESS || opensslAlg == NULL) {
        LOGE("Failed to Invalid digest!");
        return HCF_INVALID_PARAMS;
    }

    HcfVerifySpiSm2OpensslImpl *returnImpl = (HcfVerifySpiSm2OpensslImpl *)HcfMalloc(
        sizeof(HcfVerifySpiSm2OpensslImpl), 0);
    if (returnImpl == NULL) {
        LOGE("Failed to allocate returnImpl memroy!");
        return HCF_ERR_MALLOC;
    }
    returnImpl->base.base.getClass = GetSm2VerifyClass;
    returnImpl->base.base.destroy = DestroySm2Verify;
    returnImpl->base.engineInit = EngineVerifyInit;
    returnImpl->base.engineUpdate = EngineVerifyUpdate;
    returnImpl->base.engineVerify = EngineVerifyDoFinal;
    returnImpl->base.engineGetVerifySpecString = EngineGetVerifySpecString;
    returnImpl->base.engineSetVerifySpecUint8Array = EngineSetVerifySpecUint8Array;
    returnImpl->base.engineGetVerifySpecInt = EngineGetVerifySpecInt;
    returnImpl->base.engineSetVerifySpecInt = EngineSetVerifySpecInt;
    returnImpl->digestAlg = opensslAlg;
    returnImpl->status = UNINITIALIZED;
    returnImpl->userId.data = (uint8_t *)HcfMalloc(strlen(SM2_DEFAULT_USERID) + 1, 0);
    if (returnImpl->userId.data == NULL) {
        LOGE("Failed to allocate userId data memory");
        HcfFree(returnImpl);
        returnImpl = NULL;
        return HCF_ERR_MALLOC;
    }
    (void)memcpy_s(returnImpl->userId.data, strlen(SM2_DEFAULT_USERID), SM2_DEFAULT_USERID, strlen(SM2_DEFAULT_USERID));
    returnImpl->userId.len = strlen(SM2_DEFAULT_USERID);
    returnImpl->mdCtx = OpensslEvpMdCtxNew();
    if (returnImpl->mdCtx == NULL) {
        LOGE("Failed to allocate mdCtx memory!");
        HcfFree(returnImpl->userId.data);
        returnImpl->userId.data = NULL;
        HcfFree(returnImpl);
        returnImpl = NULL;
        return HCF_ERR_MALLOC;
    }

    *returnObj = (HcfVerifySpi *)returnImpl;
    return HCF_SUCCESS;
}
