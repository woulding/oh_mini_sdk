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

#include "signature_rsa_openssl.h"

#include <string.h>

#include <openssl/evp.h>

#include "securec.h"

#include "algorithm_parameter.h"
#include "log.h"
#include "memory.h"
#include "openssl_adapter.h"
#include "openssl_class.h"
#include "openssl_common.h"
#include "rsa_openssl_common.h"
#include "utils.h"

#define PSS_TRAILER_FIELD_SUPPORTED_INT 1
#define PSS_SALTLEN_INVALID_INIT (-9)

typedef struct {
    HcfSignSpi base;

    EVP_MD_CTX *mdctx;

    EVP_PKEY_CTX *ctx;

    int32_t padding;

    int32_t md;

    int32_t mgf1md;

    CryptoStatus initFlag;

    int32_t saltLen;

    int32_t operation;
} HcfSignSpiRsaOpensslImpl;

#define RSA_DIGEST_VERIFY  0
#define RSA_VERIFY_RECOVER 1
#define RSA_DIGEST_ONLY_VERIFY 2

typedef struct {
    HcfVerifySpi base;

    EVP_MD_CTX *mdctx;

    EVP_PKEY_CTX *ctx;

    int32_t padding;

    int32_t md;

    int32_t mgf1md;

    CryptoStatus initFlag;

    int32_t saltLen;

    int32_t operation;
} HcfVerifySpiRsaOpensslImpl;

static const char *GetRsaSignClass(void)
{
    return OPENSSL_RSA_SIGN_CLASS;
}

static const char *GetRsaVerifyClass(void)
{
    return OPENSSL_RSA_VERIFY_CLASS;
}

static void DestroyRsaSign(HcfObjectBase *self)
{
    if (self == NULL) {
        LOGE("Class is null");
        return;
    }
    if (!HcfIsClassMatch(self, OPENSSL_RSA_SIGN_CLASS)) {
        LOGE("Class not match.");
        return;
    }
    HcfSignSpiRsaOpensslImpl *impl = (HcfSignSpiRsaOpensslImpl *)self;
    OpensslEvpMdCtxFree(impl->mdctx);
    impl->mdctx = NULL;
    // ctx will be freed with mdctx unless only sign
    if (impl->operation == HCF_OPERATION_ONLY_SIGN) {
        OpensslEvpPkeyCtxFree(impl->ctx);
        impl->ctx = NULL;
    }
    HcfFree(impl);
}

static void DestroyRsaVerify(HcfObjectBase *self)
{
    if (self == NULL) {
        LOGE("Class is null");
        return;
    }
    if (!HcfIsClassMatch(self, OPENSSL_RSA_VERIFY_CLASS)) {
        LOGE("Class not match.");
        return;
    }
    HcfVerifySpiRsaOpensslImpl *impl = (HcfVerifySpiRsaOpensslImpl *)self;
    OpensslEvpMdCtxFree(impl->mdctx);
    impl->mdctx = NULL;
    if (impl->operation == RSA_VERIFY_RECOVER || impl->operation == RSA_DIGEST_ONLY_VERIFY) {
        OpensslEvpPkeyCtxFree(impl->ctx);
        impl->ctx = NULL;
    }
    HcfFree(impl);
}

static HcfResult CheckInitKeyType(HcfKey *key, bool signing)
{
    if (signing) {
        if (!HcfIsClassMatch((HcfObjectBase *)key, OPENSSL_RSA_PRIKEY_CLASS)) {
            LOGE("Input keyType dismatch with sign option, please use priKey.");
            return HCF_INVALID_PARAMS;
        }
    } else {
        if (!HcfIsClassMatch((HcfObjectBase *)key, OPENSSL_RSA_PUBKEY_CLASS)) {
            LOGE("Input keyType dismatch with sign option, please use pubKey.");
            return HCF_INVALID_PARAMS;
        }
    }
    return HCF_SUCCESS;
}

static EVP_PKEY *InitRsaEvpKey(const HcfKey *key, bool signing)
{
    RSA *rsa = NULL;
    if (signing == true) {
        // dup will check if rsa is NULL
        if (DuplicateRsa(((HcfOpensslRsaPriKey *)key)->sk, signing, &rsa) != HCF_SUCCESS) {
            LOGE("dup pri RSA fail");
            return NULL;
        }
    } else if (signing == false) {
        if (DuplicateRsa(((HcfOpensslRsaPubKey *)key)->pk, signing, &rsa) != HCF_SUCCESS) {
            LOGE("dup pub RSA fail");
            return NULL;
        }
    }
    if (rsa == NULL) {
        LOGE("The Key has lost.");
        return NULL;
    }
    EVP_PKEY *pkey = NewEvpPkeyByRsa(rsa, false);
    if (pkey == NULL) {
        LOGE("New evp pkey failed");
        HcfPrintOpensslError();
        OpensslRsaFree(rsa);
        return NULL;
    }
    return pkey;
}

// the params has been checked in the CheckSignatureParams
static HcfResult SetPaddingAndDigest(EVP_PKEY_CTX *ctx, int32_t hcfPadding, int32_t md, int32_t mgf1md)
{
    (void)md;
    int32_t opensslPadding = 0;
    (void)GetOpensslPadding(hcfPadding, &opensslPadding);
    if (OpensslEvpPkeyCtxSetRsaPadding(ctx, opensslPadding) != HCF_OPENSSL_SUCCESS) {
        LOGE("Failed to set RSA padding.");
        HcfPrintOpensslError();
        return HCF_ERR_CRYPTO_OPERATION;
    }
    if (hcfPadding == HCF_OPENSSL_RSA_PSS_PADDING) {
        LOGD("padding is pss, set mgf1 md");
        EVP_MD *opensslAlg = NULL;
        (void)GetOpensslDigestAlg(mgf1md, &opensslAlg);
        if (OpensslEvpPkeyCtxSetRsaMgf1Md(ctx, opensslAlg) != HCF_OPENSSL_SUCCESS) {
            LOGE("EVP_PKEY_CTX_set_rsa_mgf1_md fail");
            HcfPrintOpensslError();
            return HCF_ERR_CRYPTO_OPERATION;
        }
    }
    return HCF_SUCCESS;
}

static HcfResult SetOnlySignParams(HcfSignSpiRsaOpensslImpl *impl, HcfPriKey *privateKey)
{
    EVP_PKEY *dupKey = InitRsaEvpKey((HcfKey *)privateKey, true);
    if (dupKey == NULL) {
        LOGE("Failed to initialize RSA EVP_PKEY.");
        return HCF_ERR_CRYPTO_OPERATION;
    }
    EVP_PKEY_CTX *ctx = NULL;
    EVP_MD *opensslAlg = NULL;
    (void)GetOpensslDigestAlg(impl->md, &opensslAlg);
    ctx = OpensslEvpPkeyCtxNewFromPkey(NULL, dupKey, NULL);
    OpensslEvpPkeyFree(dupKey);
    if (ctx == NULL) {
        LOGE("Failed to create EVP_PKEY context.");
        return HCF_ERR_CRYPTO_OPERATION;
    }
    if (OpensslEvpPkeySignInit(ctx) != HCF_OPENSSL_SUCCESS) {
        LOGE("Failed to initialize signing operation.");
        OpensslEvpPkeyCtxFree(ctx);
        return HCF_ERR_CRYPTO_OPERATION;
    }
    if (opensslAlg != NULL) {
        if (OpensslEvpPkeyCtxSetSignatureMd(ctx, opensslAlg) != HCF_OPENSSL_SUCCESS) {
            LOGE("Failed to set signature message digest algorithm.");
            OpensslEvpPkeyCtxFree(ctx);
            return HCF_ERR_CRYPTO_OPERATION;
        }
    }

    if (SetPaddingAndDigest(ctx, impl->padding, impl->md, impl->mgf1md) != HCF_SUCCESS) {
        LOGE("set padding and digest fail");
        OpensslEvpPkeyCtxFree(ctx);
        return HCF_ERR_CRYPTO_OPERATION;
    }
    if (impl->saltLen != PSS_SALTLEN_INVALID_INIT) {
        if (OpensslEvpPkeyCtxSetRsaPssSaltLen(ctx, impl->saltLen) != HCF_OPENSSL_SUCCESS) {
            LOGE("Failed to set RSA-PSS salt length.");
            HcfPrintOpensslError();
            OpensslEvpPkeyCtxFree(ctx);
            return HCF_ERR_CRYPTO_OPERATION;
        }
    }
    impl->ctx = ctx;
    return HCF_SUCCESS;
}

static HcfResult SetSignParams(HcfSignSpiRsaOpensslImpl *impl, HcfPriKey *privateKey)
{
    if (impl->operation == HCF_OPERATION_ONLY_SIGN) {
        return SetOnlySignParams(impl, privateKey);
    }
    EVP_PKEY *dupKey = InitRsaEvpKey((HcfKey *)privateKey, true);
    if (dupKey == NULL) {
        LOGE("Failed to initialize RSA EVP_PKEY.");
        return HCF_ERR_CRYPTO_OPERATION;
    }
    EVP_PKEY_CTX *ctx = NULL;
    EVP_MD *opensslAlg = NULL;
    (void)GetOpensslDigestAlg(impl->md, &opensslAlg);
    if (opensslAlg == NULL) {
        OpensslEvpPkeyFree(dupKey);
        LOGE("Get openssl digest alg fail");
        return HCF_INVALID_PARAMS;
    }
    int ret = OpensslEvpDigestSignInit(impl->mdctx, &ctx, opensslAlg, NULL, dupKey);
    OpensslEvpPkeyFree(dupKey);
    if (ret != HCF_OPENSSL_SUCCESS) {
        LOGE("Failed to initialize digest signing.");
        return HCF_ERR_CRYPTO_OPERATION;
    }
    if (SetPaddingAndDigest(ctx, impl->padding, impl->md, impl->mgf1md) != HCF_SUCCESS) {
        LOGE("set padding and digest fail");
        return HCF_ERR_CRYPTO_OPERATION;
    }
    if (impl->saltLen != PSS_SALTLEN_INVALID_INIT) {
        if (OpensslEvpPkeyCtxSetRsaPssSaltLen(ctx, impl->saltLen) != HCF_OPENSSL_SUCCESS) {
            LOGE("get saltLen fail");
            return HCF_ERR_CRYPTO_OPERATION;
        }
    }
    impl->ctx = ctx;
    return HCF_SUCCESS;
}

static HcfResult EngineSignInit(HcfSignSpi *self, HcfParamsSpec *params, HcfPriKey *privateKey)
{
    (void)params;
    if (self == NULL || privateKey == NULL) {
        LOGE("Invalid input params");
        return HCF_INVALID_PARAMS;
    }
    if (!HcfIsClassMatch((HcfObjectBase *)self, OPENSSL_RSA_SIGN_CLASS)) {
        LOGE("Class not match.");
        return HCF_INVALID_PARAMS;
    }
    HcfSignSpiRsaOpensslImpl *impl = (HcfSignSpiRsaOpensslImpl *)self;
    if (impl->initFlag != UNINITIALIZED) {
        LOGE("Sign has been init");
        return HCF_INVALID_PARAMS;
    }
    if (CheckInitKeyType((HcfKey *)privateKey, true) != HCF_SUCCESS) {
        LOGE("KeyType dismatch.");
        return HCF_INVALID_PARAMS;
    }

    HcfResult ret = SetSignParams(impl, privateKey);
    if (ret == HCF_ERR_CRYPTO_OPERATION) {
        HcfPrintOpensslError();
    }
    if (ret != HCF_SUCCESS) {
        LOGE("Sign set padding or md fail");
        return ret;
    }
    impl->initFlag = INITIALIZED;
    return HCF_SUCCESS;
}

static HcfResult SetOnlyVerifyParams(HcfVerifySpiRsaOpensslImpl *impl, HcfPubKey *publicKey)
{
    EVP_PKEY *dupKey = InitRsaEvpKey((HcfKey *)publicKey, false);
    if (dupKey == NULL) {
        LOGE("Failed to initialize RSA EVP_PKEY.");
        return HCF_ERR_CRYPTO_OPERATION;
    }
    EVP_PKEY_CTX *ctx = NULL;
    EVP_MD *opensslAlg = NULL;
    (void)GetOpensslDigestAlg(impl->md, &opensslAlg);
    ctx = OpensslEvpPkeyCtxNewFromPkey(NULL, dupKey, NULL);
    OpensslEvpPkeyFree(dupKey);
    if (ctx == NULL) {
        LOGE("Failed to create EVP_PKEY context from key.");
        HcfPrintOpensslError();
        return HCF_ERR_CRYPTO_OPERATION;
    }
    if (OpensslEvpPkeyVerifyInit(ctx) != HCF_OPENSSL_SUCCESS) {
        LOGE("Failed to initialize verification operation.");
        HcfPrintOpensslError();
        OpensslEvpPkeyCtxFree(ctx);
        return HCF_ERR_CRYPTO_OPERATION;
    }
    if (opensslAlg != NULL) {
        if (OpensslEvpPkeyCtxSetSignatureMd(ctx, opensslAlg) != HCF_OPENSSL_SUCCESS) {
            LOGE("Failed to set signature message digest algorithm.");
            HcfPrintOpensslError();
            OpensslEvpPkeyCtxFree(ctx);
            return HCF_ERR_CRYPTO_OPERATION;
        }
    }

    if (SetPaddingAndDigest(ctx, impl->padding, impl->md, impl->mgf1md) != HCF_SUCCESS) {
        LOGE("set padding and digest fail.");
        OpensslEvpPkeyCtxFree(ctx);
        return HCF_ERR_CRYPTO_OPERATION;
    }
    if (impl->saltLen != PSS_SALTLEN_INVALID_INIT) {
        if (OpensslEvpPkeyCtxSetRsaPssSaltLen(ctx, impl->saltLen) != HCF_OPENSSL_SUCCESS) {
            LOGE("Failed to set RSA-PSS salt length.");
            HcfPrintOpensslError();
            OpensslEvpPkeyCtxFree(ctx);
            return HCF_ERR_CRYPTO_OPERATION;
        }
    }

    impl->ctx = ctx;
    return HCF_SUCCESS;
}

static HcfResult SetVerifyParams(HcfVerifySpiRsaOpensslImpl *impl, HcfPubKey *publicKey)
{
    if (impl->operation == RSA_DIGEST_ONLY_VERIFY) {
        // only verify
        return SetOnlyVerifyParams(impl, publicKey);
    }
    EVP_PKEY_CTX *ctx = NULL;
    EVP_PKEY *dupKey = InitRsaEvpKey((HcfKey *)publicKey, false);
    if (dupKey == NULL) {
        LOGE("Failed to initialize RSA EVP_PKEY.");
        return HCF_ERR_CRYPTO_OPERATION;
    }
    EVP_MD *opensslAlg = NULL;
    (void)GetOpensslDigestAlg(impl->md, &opensslAlg);
    if (opensslAlg == NULL) {
        OpensslEvpPkeyFree(dupKey);
        LOGE("Get openssl digest alg fail");
        return HCF_INVALID_PARAMS;
    }
    int ret = OpensslEvpDigestVerifyInit(impl->mdctx, &ctx, opensslAlg, NULL, dupKey);
    OpensslEvpPkeyFree(dupKey);
    if (ret != HCF_OPENSSL_SUCCESS) {
        LOGE("Failed to initialize digest verification.");
        HcfPrintOpensslError();
        return HCF_ERR_CRYPTO_OPERATION;
    }
    if (SetPaddingAndDigest(ctx, impl->padding, impl->md, impl->mgf1md) != HCF_SUCCESS) {
        LOGE("set padding and digest fail");
        return HCF_ERR_CRYPTO_OPERATION;
    }
    if (impl->saltLen != PSS_SALTLEN_INVALID_INIT) {
        if (OpensslEvpPkeyCtxSetRsaPssSaltLen(ctx, impl->saltLen) != HCF_OPENSSL_SUCCESS) {
            LOGE("get saltLen fail");
            return HCF_ERR_CRYPTO_OPERATION;
        }
    }
    impl->ctx = ctx;
    return HCF_SUCCESS;
}

static HcfResult SetVerifyRecoverParams(HcfVerifySpiRsaOpensslImpl *impl, HcfPubKey *publicKey)
{
    EVP_PKEY *dupKey = InitRsaEvpKey((HcfKey *)publicKey, false);
    if (dupKey == NULL) {
        LOGE("Failed to initialize RSA EVP_PKEY.");
        return HCF_ERR_CRYPTO_OPERATION;
    }

    EVP_PKEY_CTX *ctx = NULL;
    ctx = OpensslEvpPkeyCtxNewFromPkey(NULL, dupKey, NULL);
    OpensslEvpPkeyFree(dupKey);
    if (ctx == NULL) {
        LOGE("Failed to create EVP_PKEY context from key.");
        HcfPrintOpensslError();
        return HCF_ERR_CRYPTO_OPERATION;
    }

    if (OpensslEvpPkeyVerifyRecoverInit(ctx) != HCF_OPENSSL_SUCCESS) {
        LOGE("Failed to initialize verify-recover operation.");
        HcfPrintOpensslError();
        OpensslEvpPkeyCtxFree(ctx);
        return HCF_ERR_CRYPTO_OPERATION;
    }

    int32_t opensslPadding = 0;
    (void)GetOpensslPadding(impl->padding, &opensslPadding);
    if (OpensslEvpPkeyCtxSetRsaPadding(ctx, opensslPadding) != HCF_OPENSSL_SUCCESS) {
        LOGE("Failed to set RSA padding.");
        HcfPrintOpensslError();
        OpensslEvpPkeyCtxFree(ctx);
        return HCF_ERR_CRYPTO_OPERATION;
    }

    EVP_MD *opensslAlg = NULL;
    (void)GetOpensslDigestAlg(impl->md, &opensslAlg);
    if (opensslAlg != NULL) {
        if (OpensslEvpPkeyCtxSetSignatureMd(ctx, opensslAlg) != HCF_OPENSSL_SUCCESS) {
            LOGE("EVP_PKEY_CTX_set_rsa_mgf1_md fail");
            HcfPrintOpensslError();
            OpensslEvpPkeyCtxFree(ctx);
            return HCF_ERR_CRYPTO_OPERATION;
        }
    }

    impl->ctx = ctx;
    return HCF_SUCCESS;
}

static HcfResult EngineVerifyInit(HcfVerifySpi *self, HcfParamsSpec *params, HcfPubKey *publicKey)
{
    (void)params;
    if (self == NULL || publicKey == NULL) {
        LOGE("Invalid input params.");
        return HCF_INVALID_PARAMS;
    }
    if (!HcfIsClassMatch((HcfObjectBase *)self, OPENSSL_RSA_VERIFY_CLASS)) {
        LOGE("Class not match.");
        return HCF_INVALID_PARAMS;
    }
    HcfVerifySpiRsaOpensslImpl *impl = (HcfVerifySpiRsaOpensslImpl *)self;
    if (impl->initFlag != UNINITIALIZED) {
        LOGE("Verigy has been init.");
        return HCF_INVALID_PARAMS;
    }
    if (CheckInitKeyType((HcfKey *)publicKey, false) != HCF_SUCCESS) {
        LOGE("KeyType dismatch.");
        return HCF_INVALID_PARAMS;
    }

    if (impl->operation == RSA_DIGEST_VERIFY || impl->operation == RSA_DIGEST_ONLY_VERIFY) {
        if (SetVerifyParams(impl, publicKey) != HCF_SUCCESS) {
            LOGE("Verify set padding or md fail");
            return HCF_ERR_CRYPTO_OPERATION;
        }
    } else {
        if (SetVerifyRecoverParams(impl, publicKey) != HCF_SUCCESS) {
            LOGE("VerifyRecover set padding or md fail");
            return HCF_ERR_CRYPTO_OPERATION;
        }
    }

    impl->initFlag = INITIALIZED;
    return HCF_SUCCESS;
}

static HcfResult EngineSignUpdate(HcfSignSpi *self, HcfBlob *data)
{
    if ((self == NULL) || (data == NULL) || (data->data == NULL)) {
        LOGE("Invalid input parameter.");
        return HCF_INVALID_PARAMS;
    }
    if (!HcfIsClassMatch((HcfObjectBase *)self, OPENSSL_RSA_SIGN_CLASS)) {
        LOGE("Class not match.");
        return HCF_INVALID_PARAMS;
    }
    HcfSignSpiRsaOpensslImpl *impl = (HcfSignSpiRsaOpensslImpl *)self;
    if (impl->initFlag != INITIALIZED) {
        LOGE("The Sign has not been init");
        return HCF_INVALID_PARAMS;
    }
    if (impl->operation == HCF_OPERATION_ONLY_SIGN) {
        LOGE("Update cannot support in OnlySign");
        return HCF_ERR_CRYPTO_OPERATION;
    }
    if (OpensslEvpDigestSignUpdate(impl->mdctx, data->data, data->len) != HCF_OPENSSL_SUCCESS) {
        LOGE("Failed to update digest sign data.");
        return HCF_ERR_CRYPTO_OPERATION;
    }
    return HCF_SUCCESS;
}

static HcfResult EngineVerifyUpdate(HcfVerifySpi *self, HcfBlob *data)
{
    if (self == NULL) {
        LOGE("Invalid input parameter.");
        return HCF_INVALID_PARAMS;
    }
    if (!HcfIsClassMatch((HcfObjectBase *)self, OPENSSL_RSA_VERIFY_CLASS)) {
        LOGE("Class not match.");
        return HCF_INVALID_PARAMS;
    }
    HcfVerifySpiRsaOpensslImpl *impl = (HcfVerifySpiRsaOpensslImpl *)self;
    if (impl->initFlag != INITIALIZED) {
        LOGE("The Sign has not been init");
        return HCF_INVALID_PARAMS;
    }

    if (impl->operation == RSA_DIGEST_ONLY_VERIFY) {
        LOGE("Update cannot support in DigestOnlyVerify.");
        return HCF_ERR_INVALID_CALL;
    }

    if ((data == NULL) || (data->data == NULL)) {
        LOGE("Invalid input parameter.");
        return HCF_INVALID_PARAMS;
    }

    if (impl->operation != RSA_DIGEST_VERIFY) {
        LOGE("Invalid digest verify operation.");
        return HCF_ERR_CRYPTO_OPERATION;
    }

    if (OpensslEvpDigestVerifyUpdate(impl->mdctx, data->data, data->len) != HCF_OPENSSL_SUCCESS) {
        LOGE("Failed to update digest sign data.");
        return HCF_ERR_CRYPTO_OPERATION;
    }
    return HCF_SUCCESS;
}

static HcfResult EnginePkeySign(HcfSignSpiRsaOpensslImpl *impl, HcfBlob *data, HcfBlob *returnSignatureData)
{
    if (data == NULL || data->len == 0 || data->data == NULL) {
        LOGE("Invalid input params.");
        return HCF_INVALID_PARAMS;
    }
    size_t maxLen;
    if (OpensslEvpPkeySign(impl->ctx, NULL, &maxLen, data->data, data->len) != HCF_OPENSSL_SUCCESS) {
        LOGE("OpensslEvpPkeySign get maxLen fail");
        return HCF_ERR_CRYPTO_OPERATION;
    }
    LOGD("sign maxLen is %{public}zu", maxLen);
    uint8_t *outData = (uint8_t *)HcfMalloc(maxLen, 0);
    if (outData == NULL) {
        LOGE("Failed to allocate outData memory!");
        return HCF_ERR_MALLOC;
    }
    size_t actualLen = maxLen;
    if (OpensslEvpPkeySign(impl->ctx, outData, &actualLen, data->data, data->len) != HCF_OPENSSL_SUCCESS) {
        HcfPrintOpensslError();
        LOGE("Failed to sign data.");
        HcfFree(outData);
        outData = NULL;
        return HCF_ERR_CRYPTO_OPERATION;
    }
    returnSignatureData->data = outData;
    returnSignatureData->len = (uint32_t)actualLen;
    return HCF_SUCCESS;
}

static HcfResult EngineDigestSign(HcfSignSpiRsaOpensslImpl *impl, HcfBlob *data, HcfBlob *returnSignatureData)
{
    if (data != NULL && data->data != NULL) {
        if (OpensslEvpDigestSignUpdate(impl->mdctx, data->data, data->len) != HCF_OPENSSL_SUCCESS) {
            LOGE("Dofinal update data fail.");
            return HCF_ERR_CRYPTO_OPERATION;
        }
    }

    size_t maxLen;
    if (OpensslEvpDigestSignFinal(impl->mdctx, NULL, &maxLen) != HCF_OPENSSL_SUCCESS) {
        LOGE("Failed to finalize digest signing.");
        return HCF_ERR_CRYPTO_OPERATION;
    }
    LOGD("sign maxLen is %{public}zu", maxLen);
    uint8_t *outData = (uint8_t *)HcfMalloc(maxLen, 0);
    if (outData == NULL) {
        LOGE("Failed to allocate outData memory!");
        return HCF_ERR_MALLOC;
    }

    if (OpensslEvpDigestSignFinal(impl->mdctx, outData, &maxLen) != HCF_OPENSSL_SUCCESS) {
        LOGE("Failed to finalize digest signing.");
        HcfFree(outData);
        outData = NULL;
        HcfPrintOpensslError();
        return HCF_ERR_CRYPTO_OPERATION;
    }
    returnSignatureData->data = outData;
    returnSignatureData->len = (uint32_t)maxLen;
    return HCF_SUCCESS;
}

static HcfResult EngineSign(HcfSignSpi *self, HcfBlob *data, HcfBlob *returnSignatureData)
{
    if (self == NULL || returnSignatureData == NULL) {
        LOGE("Invalid input params.");
        return HCF_INVALID_PARAMS;
    }
    if (!HcfIsClassMatch((HcfObjectBase *)self, OPENSSL_RSA_SIGN_CLASS)) {
        LOGE("Class not match.");
        return HCF_INVALID_PARAMS;
    }
    HcfSignSpiRsaOpensslImpl *impl = (HcfSignSpiRsaOpensslImpl *)self;
    if (impl->initFlag != INITIALIZED) {
        LOGE("The Sign has not been init");
        return HCF_INVALID_PARAMS;
    }

    HcfResult ret;
    if (impl->operation == HCF_OPERATION_ONLY_SIGN) {
        ret = EnginePkeySign(impl, data, returnSignatureData);
    } else {
        ret = EngineDigestSign(impl, data, returnSignatureData);
    }

    return ret;
}

static bool EngineOnlyVerifyWithData(HcfVerifySpiRsaOpensslImpl *impl, HcfBlob *data, HcfBlob *signatureData)
{
    if (data == NULL || data->len == 0 || data->data == NULL) {
        LOGE("Invalid data params.");
        return false;
    }
    if (signatureData == NULL || signatureData->data == NULL) {
        LOGE("Invalid signature data.");
        return false;
    }
    
    int ret = OpensslEvpPkeyVerify(impl->ctx, signatureData->data, signatureData->len, data->data, data->len);
    if (ret != HCF_OPENSSL_SUCCESS) {
        LOGE("Failed to verify signature.");
        HcfPrintOpensslError();
        return false;
    }
    return true;
}

static bool EngineVerify(HcfVerifySpi *self, HcfBlob *data, HcfBlob *signatureData)
{
    if (self == NULL || signatureData == NULL || signatureData->data == NULL) {
        LOGE("Invalid input params");
        return false;
    }
    if (!HcfIsClassMatch((HcfObjectBase *)self, OPENSSL_RSA_VERIFY_CLASS)) {
        LOGE("Class not match.");
        return false;
    }

    HcfVerifySpiRsaOpensslImpl *impl = (HcfVerifySpiRsaOpensslImpl *)self;
    if (impl->initFlag != INITIALIZED) {
        LOGE("The Sign has not been init");
        return false;
    }

    if (impl->operation != RSA_DIGEST_VERIFY && impl->operation != RSA_DIGEST_ONLY_VERIFY) {
        LOGE("Invalid digest verify operation.");
        return false;
    }
    if (impl->operation == RSA_DIGEST_ONLY_VERIFY) {
        return EngineOnlyVerifyWithData(impl, data, signatureData);
    }

    if (data != NULL && data->data != NULL) {
        if (OpensslEvpDigestVerifyUpdate(impl->mdctx, data->data, data->len) != HCF_OPENSSL_SUCCESS) {
            LOGE("Failed to update digest verify data.");
            return false;
        }
    }
    if (OpensslEvpDigestVerifyFinal(impl->mdctx, signatureData->data, signatureData->len) != HCF_OPENSSL_SUCCESS) {
        LOGE("Failed to finalize digest verification.");
        return false;
    }
    return true;
}

static HcfResult EngineRecover(HcfVerifySpi *self, HcfBlob *signatureData, HcfBlob *rawSignatureData)
{
    if (self == NULL || signatureData == NULL || signatureData->data == NULL || rawSignatureData == NULL) {
        LOGE("Invalid input params");
        return HCF_INVALID_PARAMS;
    }
    if (!HcfIsClassMatch((HcfObjectBase *)self, OPENSSL_RSA_VERIFY_CLASS)) {
        LOGE("Class not match.");
        return HCF_INVALID_PARAMS;
    }

    HcfVerifySpiRsaOpensslImpl *impl = (HcfVerifySpiRsaOpensslImpl *)self;
    if (impl->initFlag != INITIALIZED) {
        LOGE("The Sign has not been init.");
        return HCF_ERR_CRYPTO_OPERATION;
    }
    if (impl->operation == RSA_DIGEST_ONLY_VERIFY) {
        LOGE("Recover cannot support in DigestOnlyVerify.");
        return HCF_ERR_INVALID_CALL;
    }

    if (impl->operation != RSA_VERIFY_RECOVER) {
        LOGE("Invalid verify recover operation.");
        return HCF_ERR_CRYPTO_OPERATION;
    }

    size_t bufLen = 0;
    if (OpensslEvpPkeyVerifyRecover(impl->ctx, NULL, &bufLen, signatureData->data, signatureData->len)
        != HCF_OPENSSL_SUCCESS) {
        LOGE("[error] OpensslEvpPkeyVerifyRecover get len fail.");
        HcfPrintOpensslError();
        return HCF_ERR_CRYPTO_OPERATION;
    }

    uint8_t *buf = (uint8_t *)HcfMalloc((uint32_t)bufLen, 0);
    if (buf == NULL) {
        LOGE("[error] HcfMalloc fail");
        return HCF_ERR_MALLOC;
    }

    if (OpensslEvpPkeyVerifyRecover(impl->ctx, buf, &bufLen, signatureData->data, signatureData->len)
        != HCF_OPENSSL_SUCCESS) {
        LOGE("[error] OpensslEvpPkeyVerifyRecover fail.");
        HcfPrintOpensslError();
        HcfFree(buf);
        buf = NULL;
        return HCF_ERR_CRYPTO_OPERATION;
    }

    rawSignatureData->data = buf;
    rawSignatureData->len = bufLen;
    return HCF_SUCCESS;
}

static HcfResult CheckOnlySignatureParams(HcfSignatureParams *params)
{
    int32_t opensslPadding = 0;
    if (GetOpensslPadding(params->padding, &opensslPadding) != HCF_SUCCESS) {
        LOGE("getpadding fail.");
        return HCF_INVALID_PARAMS;
    }
    if (opensslPadding != RSA_PKCS1_PADDING && opensslPadding != RSA_PKCS1_PSS_PADDING
        && opensslPadding != RSA_NO_PADDING) {
        LOGE("only signature cannot use that padding mode.");
        return HCF_INVALID_PARAMS;
    }
    EVP_MD *md = NULL;
    HcfResult ret = GetOpensslDigestAlg(params->md, &md);
    if (ret != HCF_SUCCESS) {
        LOGE("Md is invalid.");
        return HCF_INVALID_PARAMS;
    }

    if (opensslPadding == RSA_PKCS1_PSS_PADDING) {
        EVP_MD *mgf1md = NULL;
        (void)GetOpensslDigestAlg(params->mgf1md, &mgf1md);
        if (mgf1md == NULL) {
            LOGE("Use pss padding, but mgf1md is NULL.");
            return HCF_INVALID_PARAMS;
        }
    }

    return HCF_SUCCESS;
}

static HcfResult CheckSignatureParams(HcfSignatureParams *params)
{
    if (params->operation == HCF_ALG_ONLY_SIGN || params->operation == HCF_ALG_ONLY_VERIFY) {
        return CheckOnlySignatureParams(params);
    }
    int32_t opensslPadding = 0;
    if (GetOpensslPadding(params->padding, &opensslPadding) != HCF_SUCCESS) {
        LOGE("getpadding fail.");
        return HCF_INVALID_PARAMS;
    }
    if (opensslPadding != RSA_PKCS1_PADDING && opensslPadding != RSA_PKCS1_PSS_PADDING) {
        LOGE("signature cannot use that padding mode");
        return HCF_INVALID_PARAMS;
    }
    EVP_MD *md = NULL;
    (void)GetOpensslDigestAlg(params->md, &md);
    if (md == NULL) {
        LOGE("Md is NULL");
        return HCF_INVALID_PARAMS;
    }
    if (params->padding == HCF_OPENSSL_RSA_PSS_PADDING) {
        EVP_MD *mgf1md = NULL;
        (void)GetOpensslDigestAlg(params->mgf1md, &mgf1md);
        if (mgf1md == NULL) {
            LOGE("Use pss padding, but mgf1md is NULL");
            return HCF_ERR_PARAMETER_CHECK_FAILED;
        }
    }
    return HCF_SUCCESS;
}

static HcfResult EngineSetSignSpecInt(HcfSignSpi *self, SignSpecItem item, int32_t saltLen)
{
    if (self == NULL) {
        LOGE("Invalid input parameter");
        return HCF_INVALID_PARAMS;
    }
    if (item != PSS_SALT_LEN_INT) {
        LOGE("Invalid sign spec item");
        return HCF_INVALID_PARAMS;
    }
    if (!HcfIsClassMatch((HcfObjectBase *)self, OPENSSL_RSA_SIGN_CLASS)) {
        LOGE("Class not match.");
        return HCF_INVALID_PARAMS;
    }
    if (saltLen < 0) {
        // RSA_PSS_SALTLEN_MAX_SIGN: max sign is old compatible max salt length for sign only
        if (saltLen != RSA_PSS_SALTLEN_DIGEST && saltLen != RSA_PSS_SALTLEN_MAX_SIGN &&
            saltLen != RSA_PSS_SALTLEN_MAX) {
            LOGE("Invalid salt Len %{public}d", saltLen);
            return HCF_INVALID_PARAMS;
        }
    }
    HcfSignSpiRsaOpensslImpl *impl = (HcfSignSpiRsaOpensslImpl *)self;
    if (impl->padding != HCF_OPENSSL_RSA_PSS_PADDING) {
        LOGE("Only support pss parameter");
        return HCF_INVALID_PARAMS;
    }
    impl->saltLen = saltLen;
    if (impl->initFlag == INITIALIZED) {
        if (OpensslEvpPkeyCtxSetRsaPssSaltLen(impl->ctx, saltLen) != HCF_OPENSSL_SUCCESS) {
            LOGE("set saltLen fail");
            return HCF_ERR_CRYPTO_OPERATION;
        }
    }
    LOGD("Set sign saltLen success");
    return HCF_SUCCESS;
}

static HcfResult EngineGetSignSpecInt(HcfSignSpi *self, SignSpecItem item, int32_t *returnInt)
{
    if (self == NULL || returnInt == NULL) {
        LOGE("Invalid input parameter");
        return HCF_INVALID_PARAMS;
    }
    if (!HcfIsClassMatch((HcfObjectBase *)self, OPENSSL_RSA_SIGN_CLASS)) {
        LOGE("Class not match.");
        return HCF_INVALID_PARAMS;
    }
    if (item != PSS_TRAILER_FIELD_INT && item != PSS_SALT_LEN_INT) {
        LOGE("Invalid input spec");
        return HCF_INVALID_PARAMS;
    }
    HcfSignSpiRsaOpensslImpl *impl = (HcfSignSpiRsaOpensslImpl *)self;
    if (impl->padding != HCF_OPENSSL_RSA_PSS_PADDING) {
        LOGE("Only support pss parameter");
        return HCF_INVALID_PARAMS;
    }
    if (item == PSS_TRAILER_FIELD_INT) {
        *returnInt = PSS_TRAILER_FIELD_SUPPORTED_INT;
        return HCF_SUCCESS;
    }
    if (impl->saltLen != PSS_SALTLEN_INVALID_INIT) {
        *returnInt = impl->saltLen;
        return HCF_SUCCESS;
    }
    if (impl->initFlag == INITIALIZED) {
        if (OpensslEvpPkeyCtxGetRsaPssSaltLen(impl->ctx, returnInt) != HCF_OPENSSL_SUCCESS) {
            LOGE("get saltLen fail");
            return HCF_ERR_CRYPTO_OPERATION;
        }
        return HCF_SUCCESS;
    } else {
        LOGE("No set saltLen and not init!");
        return HCF_INVALID_PARAMS;
    }
}

static HcfResult EngineSetSignSpecUint8Array(HcfSignSpi *self, SignSpecItem item, HcfBlob pSource)
{
    (void)self;
    (void)item;
    (void)pSource;
    LOGE("Unsupported operation for RSA signature.");
    return HCF_NOT_SUPPORT;
}

static HcfResult EngineGetSignSpecString(HcfSignSpi *self, SignSpecItem item, char **returnString)
{
    if (self == NULL || returnString == NULL) {
        LOGE("Invalid input parameter");
        return HCF_INVALID_PARAMS;
    }
    if (!HcfIsClassMatch((HcfObjectBase *)self, OPENSSL_RSA_SIGN_CLASS)) {
        LOGE("Class not match.");
        return HCF_INVALID_PARAMS;
    }
    HcfSignSpiRsaOpensslImpl *impl = (HcfSignSpiRsaOpensslImpl *)self;
    if (impl->padding != HCF_OPENSSL_RSA_PSS_PADDING) {
        LOGE("Only support pss parameter");
        return HCF_INVALID_PARAMS;
    }
    HcfResult ret = HCF_INVALID_PARAMS;
    switch (item) {
        case PSS_MD_NAME_STR:
            ret = GetRsaSpecStringMd((const HcfAlgParaValue)(impl->md), returnString);
            break;
        case PSS_MGF_NAME_STR:
            // only support mgf1
            ret = GetRsaSpecStringMGF(returnString);
            break;
        case PSS_MGF1_MD_STR:
            ret = GetRsaSpecStringMd((const HcfAlgParaValue)(impl->mgf1md), returnString);
            break;
        default:
            LOGE("Invalid input sign spec item");
            return HCF_INVALID_PARAMS;
    }
    return ret;
}

static HcfResult EngineSetVerifySpecInt(HcfVerifySpi *self, SignSpecItem item, int32_t saltLen)
{
    if (self == NULL) {
        LOGE("Invalid input parameter");
        return HCF_INVALID_PARAMS;
    }
    if (item != PSS_SALT_LEN_INT) {
        LOGE("Invalid verify spec item");
        return HCF_INVALID_PARAMS;
    }
    if (!HcfIsClassMatch((HcfObjectBase *)self, OPENSSL_RSA_VERIFY_CLASS)) {
        LOGE("Class not match.");
        return HCF_INVALID_PARAMS;
    }
    if (saltLen < 0) {
        // RSA_PSS_SALTLEN_AUTO: Verify only: auto detect salt length(only support verify)
        if (saltLen != RSA_PSS_SALTLEN_DIGEST && saltLen != RSA_PSS_SALTLEN_AUTO &&
            saltLen != RSA_PSS_SALTLEN_MAX) {
            LOGE("Invalid salt Len %{public}d", saltLen);
            return HCF_INVALID_PARAMS;
        }
    }
    HcfVerifySpiRsaOpensslImpl *impl = (HcfVerifySpiRsaOpensslImpl *)self;
    if (impl->padding != HCF_OPENSSL_RSA_PSS_PADDING) {
        LOGE("Only support pss parameter");
        return HCF_INVALID_PARAMS;
    }
    impl->saltLen = saltLen;
    if (impl->initFlag == INITIALIZED) {
        if (OpensslEvpPkeyCtxSetRsaPssSaltLen(impl->ctx, saltLen) != HCF_OPENSSL_SUCCESS) {
            LOGE("set saltLen fail");
            return HCF_ERR_CRYPTO_OPERATION;
        }
    }
    return HCF_SUCCESS;
}

static HcfResult EngineGetVerifySpecInt(HcfVerifySpi *self, SignSpecItem item, int32_t *returnInt)
{
    if (self == NULL || returnInt == NULL) {
        LOGE("Invalid input parameter");
        return HCF_INVALID_PARAMS;
    }
    if (!HcfIsClassMatch((HcfObjectBase *)self, OPENSSL_RSA_VERIFY_CLASS)) {
        LOGE("Class not match.");
        return HCF_INVALID_PARAMS;
    }
    if (item != PSS_TRAILER_FIELD_INT && item != PSS_SALT_LEN_INT) {
        LOGE("Invalid input sign spec item");
        return HCF_INVALID_PARAMS;
    }
    HcfVerifySpiRsaOpensslImpl *impl = (HcfVerifySpiRsaOpensslImpl *)self;
    if (impl->padding != HCF_OPENSSL_RSA_PSS_PADDING) {
        LOGE("Only support pss parameter");
        return HCF_INVALID_PARAMS;
    }
    if (item == PSS_TRAILER_FIELD_INT) {
        *returnInt = PSS_TRAILER_FIELD_SUPPORTED_INT;
        return HCF_SUCCESS;
    }
    if (impl->saltLen != PSS_SALTLEN_INVALID_INIT) {
        *returnInt = impl->saltLen;
        return HCF_SUCCESS;
    }
    if (impl->initFlag == INITIALIZED) {
        if (OpensslEvpPkeyCtxGetRsaPssSaltLen(impl->ctx, returnInt) != HCF_OPENSSL_SUCCESS) {
            LOGE("get saltLen fail");
            return HCF_ERR_CRYPTO_OPERATION;
        }
        return HCF_SUCCESS;
    } else {
        LOGE("No set saltLen and not init!");
        return HCF_INVALID_PARAMS;
    }
}

static HcfResult EngineSetVerifySpecUint8Array(HcfVerifySpi *self, SignSpecItem item, HcfBlob pSource)
{
    (void)self;
    (void)item;
    (void)pSource;
    LOGE("Unsupported operation for RSA signature.");
    return HCF_NOT_SUPPORT;
}

static HcfResult EngineGetVerifySpecString(HcfVerifySpi *self, SignSpecItem item, char **returnString)
{
    if (self == NULL || returnString == NULL) {
        LOGE("Invalid input parameter");
        return HCF_INVALID_PARAMS;
    }
    if (!HcfIsClassMatch((HcfObjectBase *)self, OPENSSL_RSA_VERIFY_CLASS)) {
        LOGE("Class not match.");
        return HCF_INVALID_PARAMS;
    }
    HcfVerifySpiRsaOpensslImpl *impl = (HcfVerifySpiRsaOpensslImpl *)self;
    if (impl->padding != HCF_OPENSSL_RSA_PSS_PADDING) {
        LOGE("Only support pss parameter");
        return HCF_INVALID_PARAMS;
    }
    HcfResult ret = HCF_INVALID_PARAMS;
    switch (item) {
        case PSS_MD_NAME_STR:
            ret = GetRsaSpecStringMd((const HcfAlgParaValue)(impl->md), returnString);
            break;
        case PSS_MGF_NAME_STR:
            // only support mgf1
            ret = GetRsaSpecStringMGF(returnString);
            break;
        case PSS_MGF1_MD_STR:
            ret = GetRsaSpecStringMd((const HcfAlgParaValue)(impl->mgf1md), returnString);
            break;
        default:
            LOGE("Invalid input sign spec item");
            return HCF_INVALID_PARAMS;
    }
    return ret;
}

HcfResult HcfSignSpiRsaCreate(HcfSignatureParams *params, HcfSignSpi **returnObj)
{
    if (params == NULL || returnObj == NULL) {
        LOGE("Invalid input parameter.");
        return HCF_INVALID_PARAMS;
    }
    if (CheckSignatureParams(params) != HCF_SUCCESS) {
        LOGE("Failed to validate signature parameters.");
        return HCF_INVALID_PARAMS;
    }
    HcfSignSpiRsaOpensslImpl *returnImpl = (HcfSignSpiRsaOpensslImpl *)HcfMalloc(
        sizeof(HcfSignSpiRsaOpensslImpl), 0);
    if (returnImpl == NULL) {
        LOGE("Failed to allocate returnImpl memroy!");
        return HCF_ERR_MALLOC;
    }
    returnImpl->base.base.getClass = GetRsaSignClass;
    returnImpl->base.base.destroy = DestroyRsaSign;
    returnImpl->base.engineInit = EngineSignInit;
    returnImpl->base.engineUpdate = EngineSignUpdate;
    returnImpl->base.engineSign = EngineSign;
    returnImpl->base.engineSetSignSpecInt = EngineSetSignSpecInt;
    returnImpl->base.engineGetSignSpecInt = EngineGetSignSpecInt;
    returnImpl->base.engineGetSignSpecString = EngineGetSignSpecString;
    returnImpl->base.engineSetSignSpecUint8Array = EngineSetSignSpecUint8Array;
    returnImpl->md = params->md;
    returnImpl->padding = params->padding;
    returnImpl->mgf1md = params->mgf1md;
    returnImpl->mdctx = OpensslEvpMdCtxNew();
    if (returnImpl->mdctx == NULL) {
        LOGE("Failed to allocate md ctx!");
        HcfFree(returnImpl);
        returnImpl = NULL;
        return HCF_ERR_MALLOC;
    }
    returnImpl->initFlag = UNINITIALIZED;
    returnImpl->saltLen = PSS_SALTLEN_INVALID_INIT;
    returnImpl->operation = (params->operation == HCF_ALG_ONLY_SIGN) ? HCF_OPERATION_ONLY_SIGN : HCF_OPERATION_SIGN;
    *returnObj = (HcfSignSpi *)returnImpl;
    return HCF_SUCCESS;
}

static HcfResult CheckVerifyRecoverParams(HcfSignatureParams *params)
{
    int32_t opensslPadding = 0;
    if (GetOpensslPadding(params->padding, &opensslPadding) != HCF_SUCCESS) {
        LOGE("getpadding fail.");
        return HCF_INVALID_PARAMS;
    }
    if (opensslPadding != RSA_PKCS1_PADDING && opensslPadding != RSA_NO_PADDING) {
        LOGE("VerifyRecover cannot use that padding mode");
        return HCF_INVALID_PARAMS;
    }
    return HCF_SUCCESS;
}

static HcfResult InitRsaVerifyImpl(HcfSignatureParams *params, HcfVerifySpiRsaOpensslImpl **returnImpl)
{
    HcfVerifySpiRsaOpensslImpl *impl = (HcfVerifySpiRsaOpensslImpl *)HcfMalloc(
        sizeof(HcfVerifySpiRsaOpensslImpl), 0);
    if (impl == NULL) {
        LOGE("Failed to allocate returnImpl memroy!");
        return HCF_ERR_MALLOC;
    }
    impl->base.base.getClass = GetRsaVerifyClass;
    impl->base.base.destroy = DestroyRsaVerify;
    impl->base.engineInit = EngineVerifyInit;
    impl->base.engineUpdate = EngineVerifyUpdate;
    impl->base.engineVerify = EngineVerify;
    impl->base.engineRecover = EngineRecover;
    impl->base.engineSetVerifySpecInt = EngineSetVerifySpecInt;
    impl->base.engineGetVerifySpecInt = EngineGetVerifySpecInt;
    impl->base.engineGetVerifySpecString = EngineGetVerifySpecString;
    impl->base.engineSetVerifySpecUint8Array = EngineSetVerifySpecUint8Array;
    impl->md = params->md;
    impl->padding = params->padding;
    if (params->operation != HCF_ALG_VERIFY_RECOVER) {
        impl->mgf1md = params->mgf1md;
        impl->mdctx = OpensslEvpMdCtxNew();
        if (impl->mdctx == NULL) {
            LOGE("Failed to allocate md ctx!");
            HcfFree(impl);
            return HCF_ERR_MALLOC;
        }
        impl->saltLen = PSS_SALTLEN_INVALID_INIT;
        impl->operation = (params->operation == HCF_ALG_ONLY_VERIFY) ? RSA_DIGEST_ONLY_VERIFY : RSA_DIGEST_VERIFY;
    } else {
        impl->operation = RSA_VERIFY_RECOVER;
        impl->mdctx = NULL;
    }
    impl->initFlag = UNINITIALIZED;
    *returnImpl = impl;
    return HCF_SUCCESS;
}

HcfResult HcfVerifySpiRsaCreate(HcfSignatureParams *params, HcfVerifySpi **returnObj)
{
    if (params == NULL || returnObj == NULL) {
        LOGE("Invalid input parameter.");
        return HCF_INVALID_PARAMS;
    }
    if (params->operation != HCF_ALG_VERIFY_RECOVER) {
        if (CheckSignatureParams(params) != HCF_SUCCESS) {
            LOGE("Failed to validate signature parameters.");
            return HCF_INVALID_PARAMS;
        }
    } else {
        if (CheckVerifyRecoverParams(params) != HCF_SUCCESS) {
            LOGE("Failed to validate verify-recover parameters.");
            return HCF_INVALID_PARAMS;
        }
    }

    HcfVerifySpiRsaOpensslImpl *returnImpl = NULL;
    HcfResult ret = InitRsaVerifyImpl(params, &returnImpl);
    if (ret != HCF_SUCCESS) {
        return ret;
    }
    *returnObj = (HcfVerifySpi *)returnImpl;
    return HCF_SUCCESS;
}
