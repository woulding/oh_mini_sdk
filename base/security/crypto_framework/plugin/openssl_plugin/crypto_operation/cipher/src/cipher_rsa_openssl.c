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

#include "cipher_rsa_openssl.h"
#include "securec.h"
#include "openssl/rsa.h"
#include "rsa_openssl_common.h"
#include "log.h"
#include "memory.h"
#include "openssl_adapter.h"
#include "openssl_class.h"
#include "openssl_common.h"
#include "stdbool.h"
#include "string.h"
#include "utils.h"

static const char *EngineGetClass(void);

typedef struct {
    HcfCipherGeneratorSpi super;

    CipherAttr attr;

    CryptoStatus initFlag;

    EVP_PKEY_CTX *ctx;

    HcfBlob pSource;
} HcfCipherRsaGeneratorSpiImpl;

static HcfResult CheckCipherInitParams(enum HcfCryptoMode opMode, HcfKey *key)
{
    switch (opMode) {
        case ENCRYPT_MODE:
            if (!HcfIsClassMatch((HcfObjectBase *)key, OPENSSL_RSA_PUBKEY_CLASS)) {
                LOGE("Class not match");
                return HCF_INVALID_PARAMS;
            }
            break;
        case DECRYPT_MODE:
            if (!HcfIsClassMatch((HcfObjectBase *)key, OPENSSL_RSA_PRIKEY_CLASS)) {
                LOGE("Class not match");
                return HCF_INVALID_PARAMS;
            }
            break;
        default:
            LOGE("Invalid opMode %{public}u", opMode);
            return HCF_INVALID_PARAMS;
    }

    return HCF_SUCCESS;
}

static HcfResult DuplicateRsaFromKey(HcfKey *key, enum HcfCryptoMode opMode, RSA **dupRsa)
{
    HcfResult ret = HCF_SUCCESS;
    if (opMode == ENCRYPT_MODE) {
        ret = DuplicateRsa(((HcfOpensslRsaPubKey *)key)->pk, false, dupRsa);
        if (ret != HCF_SUCCESS) {
            LOGE("dup pub RSA fail.");
            return ret;
        }
    } else if (opMode == DECRYPT_MODE) {
        // dup will check if rsa is NULL
        ret = DuplicateRsa(((HcfOpensslRsaPriKey *)key)->sk, true, dupRsa);
        if (ret != HCF_SUCCESS) {
            LOGE("dup pri RSA fail.");
            return ret;
        }
    } else {
        LOGE("OpMode not match.");
        return HCF_INVALID_PARAMS;
    }
    return ret;
}

static HcfResult InitEvpPkeyCtx(HcfCipherRsaGeneratorSpiImpl *impl, HcfKey *key, enum HcfCryptoMode opMode)
{
    RSA *rsa = NULL;
    HcfResult ret = HCF_SUCCESS;
    ret = DuplicateRsaFromKey(key, opMode, &rsa);
    if (ret != HCF_SUCCESS) {
        LOGE("Failed to duplicate RSA key.");
        return ret;
    }
    EVP_PKEY *pkey = NewEvpPkeyByRsa(rsa, false);
    if (pkey == NULL) {
        LOGE("Failed to create EVP_PKEY from RSA key.");
        HcfPrintOpensslError();
        OpensslRsaFree(rsa);
        return HCF_ERR_CRYPTO_OPERATION;
    }
    impl->ctx = EVP_PKEY_CTX_new(pkey, NULL);
    if (impl->ctx == NULL) {
        LOGE("EVP_PKEY_CTX_new fail");
        HcfPrintOpensslError();
        OpensslEvpPkeyFree(pkey);
        return HCF_ERR_CRYPTO_OPERATION;
    }
    int32_t sslRet = HCF_OPENSSL_SUCCESS;
    if (opMode == ENCRYPT_MODE) {
        sslRet = OpensslEvpPkeyEncryptInit(impl->ctx);
    } else {
        sslRet = OpensslEvpPkeyDecryptInit(impl->ctx);
    }
    if (sslRet != HCF_OPENSSL_SUCCESS) {
        LOGE("Init EVP_PKEY fail");
        HcfPrintOpensslError();
        OpensslEvpPkeyFree(pkey);
        OpensslEvpPkeyCtxFree(impl->ctx);
        impl->ctx = NULL;
        return HCF_ERR_CRYPTO_OPERATION;
    }
    OpensslEvpPkeyFree(pkey);
    return HCF_SUCCESS;
}

static HcfResult SetPsourceFromBlob(HcfBlob pSource, EVP_PKEY_CTX *ctx)
{
    // If pSource is NULL or len is 0, the pSource will be cleared.
    if (pSource.data == NULL || pSource.len == 0) {
        if (OpensslEvpPkeyCtxSet0RsaOaepLabel(ctx, NULL, 0) != HCF_OPENSSL_SUCCESS) {
            LOGE("Openssl Set psource fail");
            HcfPrintOpensslError();
            return HCF_ERR_CRYPTO_OPERATION;
        }
    }
    // deep copy from pSource
    uint8_t *opensslPsource = (uint8_t *)HcfMalloc(pSource.len, 0);
    if (opensslPsource == NULL) {
        LOGE("Failed to allocate openssl pSource data memory");
        return HCF_ERR_MALLOC;
    }
    (void)memcpy_s(opensslPsource, pSource.len, pSource.data, pSource.len);

    if (OpensslEvpPkeyCtxSet0RsaOaepLabel(ctx, opensslPsource, pSource.len) != HCF_OPENSSL_SUCCESS) {
        LOGE("Openssl Set psource fail");
        HcfPrintOpensslError();
        HcfFree(opensslPsource);
        opensslPsource = NULL;
        return HCF_ERR_CRYPTO_OPERATION;
    }
    return HCF_SUCCESS;
}

// all parmas have been checked in CheckRsaCipherParams, this function does not need check.
static HcfResult SetDetailParams(HcfCipherRsaGeneratorSpiImpl *impl)
{
    CipherAttr attr = impl->attr;
    int32_t opensslPadding = 0;
    (void)GetOpensslPadding(attr.paddingMode, &opensslPadding);
    if (OpensslEvpPkeyCtxSetRsaPadding(impl->ctx, opensslPadding) != HCF_OPENSSL_SUCCESS) {
        LOGE("Cipher set padding fail.");
        HcfPrintOpensslError();
        return HCF_ERR_CRYPTO_OPERATION;
    }
    if (attr.paddingMode != HCF_OPENSSL_RSA_PKCS1_OAEP_PADDING) {
        return HCF_SUCCESS;
    }
    // pkcs oaep
    EVP_MD *md = NULL;
    EVP_MD *mgf1md = NULL;
    (void)GetOpensslDigestAlg(attr.md, &md);
    (void)GetOpensslDigestAlg(attr.mgf1md, &mgf1md);
    // set md and mgf1md
    if (OpensslEvpPkeyCtxSetRsaOaepMd(impl->ctx, md) != HCF_OPENSSL_SUCCESS ||
        OpensslEvpPkeyCtxSetRsaMgf1Md(impl->ctx, mgf1md) != HCF_OPENSSL_SUCCESS) {
        LOGE("Set md or mgf1md fail");
        HcfPrintOpensslError();
        return HCF_ERR_CRYPTO_OPERATION;
    }
    // default EVP pSource is NULL, need not set.
    if (impl->pSource.data != NULL && impl->pSource.len > 0) {
        HcfResult ret = SetPsourceFromBlob(impl->pSource, impl->ctx);
        if (ret != HCF_SUCCESS) {
            // check if clean the pSource when init fail at it.
            HcfFree(impl->pSource.data);
            impl->pSource.data = NULL;
            LOGE("Set pSource fail, clean the pSource");
            return ret;
        }
    }
    return HCF_SUCCESS;
}

// The EVP_PKEY_CTX_set0_rsa_oaep_label() macro sets the RSA OAEP label to label and its length to len.
// https://www.openssl.org/docs/man1.1.1/man3/EVP_PKEY_CTX_set0_rsa_oaep_label.html
static HcfResult SetRsaCipherSpecUint8Array(HcfCipherGeneratorSpi *self, CipherSpecItem item, HcfBlob pSource)
{
    // If pSource is NULL or len is 0, the pSource will be cleared.
    if (self == NULL) {
        LOGE("Param is invalid.");
        return HCF_INVALID_PARAMS;
    }
    if (item != OAEP_MGF1_PSRC_UINT8ARR) {
        LOGE("Invalid cipher spec item");
        return HCF_INVALID_PARAMS;
    }
    if (!HcfIsClassMatch((HcfObjectBase *)self, EngineGetClass())) {
        LOGE("Class not match");
        return HCF_INVALID_PARAMS;
    }
    HcfCipherRsaGeneratorSpiImpl *impl = (HcfCipherRsaGeneratorSpiImpl *)self;
    CipherAttr attr = impl->attr;
    if (attr.paddingMode != HCF_OPENSSL_RSA_PKCS1_OAEP_PADDING) {
        LOGE("Psource is not supported.");
        return HCF_INVALID_PARAMS;
    }
    // if it has pSource from previous set, it should be free at first;
    if (impl->pSource.data != NULL) {
        HcfFree(impl->pSource.data);
        impl->pSource.data = NULL;
    }
    // If pSource is NULL or len is 0, the pSource will be cleared.
    if (pSource.data == NULL || pSource.len == 0) {
        impl->pSource.data = NULL;
        impl->pSource.len = 0;
    } else {
        // deep copy two pSource, one for impl struct and one for openssl.
        impl->pSource.data = (uint8_t *)HcfMalloc(pSource.len, 0);
        if (impl->pSource.data == NULL) {
            LOGE("Failed to allocate pSource data memory");
            return HCF_ERR_MALLOC;
        }
        (void)memcpy_s(impl->pSource.data, pSource.len, pSource.data, pSource.len);
        impl->pSource.len = pSource.len;
    }
    // if uninitliszed, pSource should only be stored in the struct.
    // if initliszed, pSource should have another copy and set the copy to the evp ctx.
    if (impl->initFlag == INITIALIZED) {
        HcfResult ret = SetPsourceFromBlob(impl->pSource, impl->ctx);
        if (ret != HCF_SUCCESS) {
            LOGE("Set pSource fail");
            HcfFree(impl->pSource.data);
            impl->pSource.data = NULL;
            return ret;
        }
    }
    return HCF_SUCCESS;
}

static HcfResult GetRsaCipherSpecUint8Array(HcfCipherGeneratorSpi *self, CipherSpecItem item, HcfBlob* returnPSource)
{
    if (self == NULL || returnPSource == NULL) {
        LOGE("Param is invalid.");
        return HCF_INVALID_PARAMS;
    }
    if (item != OAEP_MGF1_PSRC_UINT8ARR) {
        LOGE("Invalid cipher spec item");
        return HCF_INVALID_PARAMS;
    }
    if (!HcfIsClassMatch((HcfObjectBase *)self, EngineGetClass())) {
        LOGE("Class not match");
        return HCF_INVALID_PARAMS;
    }
    HcfCipherRsaGeneratorSpiImpl *impl = (HcfCipherRsaGeneratorSpiImpl *)self;
    CipherAttr attr = impl->attr;
    if (attr.paddingMode != HCF_OPENSSL_RSA_PKCS1_OAEP_PADDING) {
        LOGE("Psource is not supported.");
        return HCF_INVALID_PARAMS;
    }
    // use the pSource from struct at first.
    if (impl->pSource.data != NULL && impl->pSource.len > 0) {
        uint8_t *pSource = (uint8_t *)HcfMalloc(impl->pSource.len, 0);
        if (pSource == NULL) {
            LOGE("Failed to allocate pSource memory!");
            return HCF_ERR_MALLOC;
        }
        (void)memcpy_s(pSource, impl->pSource.len, impl->pSource.data, impl->pSource.len);
        returnPSource->data = pSource;
        returnPSource->len = impl->pSource.len;
        return HCF_SUCCESS;
    }
    // without pSource in the struct, use the default get func of openssl after init.
    // default situation, the pSource is NULL and len is 0, return fail.
    LOGE("pSource is not available.");
    return HCF_INVALID_PARAMS;
}

static HcfResult GetRsaCipherSpecString(HcfCipherGeneratorSpi *self, CipherSpecItem item, char **returnString)
{
    if (self == NULL || returnString == NULL) {
        LOGE("Param is invalid.");
        return HCF_INVALID_PARAMS;
    }
    if (!HcfIsClassMatch((HcfObjectBase *)self, EngineGetClass())) {
        LOGE("Class not match");
        return HCF_INVALID_PARAMS;
    }
    HcfCipherRsaGeneratorSpiImpl *impl = (HcfCipherRsaGeneratorSpiImpl *)self;
    CipherAttr attr = impl->attr;
    if (attr.paddingMode != HCF_OPENSSL_RSA_PKCS1_OAEP_PADDING) {
        LOGE("cipher spec string is not supported.");
        return HCF_INVALID_PARAMS;
    }
    HcfResult ret = HCF_INVALID_PARAMS;
    switch (item) {
        case OAEP_MD_NAME_STR:
            ret = GetRsaSpecStringMd((const HcfAlgParaValue)(attr.md), returnString);
            break;
        case OAEP_MGF_NAME_STR:
            // only support mgf1
            ret = GetRsaSpecStringMGF(returnString);
            break;
        case OAEP_MGF1_MD_STR:
            ret = GetRsaSpecStringMd((const HcfAlgParaValue)(attr.mgf1md), returnString);
            break;
        default:
            LOGE("Invalid input cipher spec");
            return HCF_INVALID_PARAMS;
    }
    return ret;
}

static HcfResult EngineInit(HcfCipherGeneratorSpi *self, enum HcfCryptoMode opMode,
    HcfKey *key, HcfParamsSpec *params)
{
    (void)params;
    if (self == NULL || key == NULL) {
        LOGE("Param is invalid.");
        return HCF_INVALID_PARAMS;
    }
    if (!HcfIsClassMatch((HcfObjectBase *)self, EngineGetClass())) {
        LOGE("Class not match");
        return HCF_INVALID_PARAMS;
    }
    HcfCipherRsaGeneratorSpiImpl *impl = (HcfCipherRsaGeneratorSpiImpl *)self;
    if (impl->initFlag != UNINITIALIZED) {
        LOGE("The cipher has been initialize, don't init again.");
        return HCF_INVALID_PARAMS;
    }

    // check opMode is matched with Key
    if (CheckCipherInitParams(opMode, key) != HCF_SUCCESS) {
        LOGE("OpMode dismatch with keyType.");
        return HCF_INVALID_PARAMS;
    }
    impl->attr.mode = (int32_t)opMode;
    if (InitEvpPkeyCtx(impl, key, opMode) != HCF_SUCCESS) {
        LOGE("Failed to initialize EVP_PKEY context.");
        return HCF_ERR_CRYPTO_OPERATION;
    }

    if (SetDetailParams(impl) != HCF_SUCCESS) {
        OpensslEvpPkeyCtxFree(impl->ctx);
        impl->ctx = NULL;
        LOGE("Failed to set detailed RSA cipher parameters.");
        return HCF_ERR_CRYPTO_OPERATION;
    }
    impl->initFlag = INITIALIZED;
    return HCF_SUCCESS;
}

static HcfResult EngineUpdate(HcfCipherGeneratorSpi *self, HcfBlob *input, HcfBlob *output)
{
    LOGE("Openssl don't support update");
    (void)self;
    (void)input;
    (void)output;
    return HCF_NOT_SUPPORT;
}

static HcfResult DoRsaCrypt(EVP_PKEY_CTX *ctx, HcfBlob *input, HcfBlob *output, int32_t mode)
{
    int32_t ret = HCF_OPENSSL_SUCCESS;
    if (mode == ENCRYPT_MODE) {
        ret = OpensslEvpPkeyEncrypt(ctx, output->data, &output->len, input->data, input->len);
    } else if (mode == DECRYPT_MODE) {
        ret = OpensslEvpPkeyDecrypt(ctx, output->data, &output->len, input->data, input->len);
    } else {
        LOGE("OpMode is invalid.");
        return HCF_INVALID_PARAMS;
    }
    if (ret != HCF_OPENSSL_SUCCESS) {
        LOGE("RSA openssl error");
        HcfPrintOpensslError();
        return HCF_ERR_CRYPTO_OPERATION;
    }
    return HCF_SUCCESS;
}

static HcfResult EngineDoFinal(HcfCipherGeneratorSpi *self, HcfBlob *input, HcfBlob *output)
{
    if (self == NULL || !HcfIsBlobValid(input) || output == NULL) {
        LOGE("Param is invalid.");
        return HCF_INVALID_PARAMS;
    }
    if (!HcfIsClassMatch((HcfObjectBase *)self, EngineGetClass())) {
        LOGE("Class not match");
        return HCF_INVALID_PARAMS;
    }
    HcfCipherRsaGeneratorSpiImpl *impl = (HcfCipherRsaGeneratorSpiImpl *)self;
    if (impl->initFlag != INITIALIZED) {
        LOGE("RSACipher has not been init");
        return HCF_INVALID_PARAMS;
    }
    CipherAttr attr = impl->attr;
    output->len = 0;
    output->data = NULL;
    HcfResult ret = DoRsaCrypt(impl->ctx, input, output, attr.mode);
    if (ret != HCF_SUCCESS) {
        LOGE("Failed to get output length.");
        return HCF_ERR_CRYPTO_OPERATION;
    }

    output->data = (uint8_t *)HcfMalloc(sizeof(uint8_t) * output->len, 0);
    if (output->data == NULL) {
        LOGE("failed to allocate memory!");
        return HCF_ERR_MALLOC;
    }
    ret = DoRsaCrypt(impl->ctx, input, output, attr.mode);
    if (ret != HCF_SUCCESS) {
        HcfFree(output->data);
        output->data = NULL;
        output->len = 0;
        LOGE("RSA doFinal failed!");
        return HCF_ERR_CRYPTO_OPERATION;
    }
    return HCF_SUCCESS;
}

static void EngineDestroySpiImpl(HcfObjectBase *generator)
{
    if (generator == NULL) {
        return;
    }
    if (!HcfIsClassMatch((HcfObjectBase *)generator, EngineGetClass())) {
        LOGE("Class not match");
        return;
    }
    HcfCipherRsaGeneratorSpiImpl *impl = (HcfCipherRsaGeneratorSpiImpl *)generator;
    OpensslEvpPkeyCtxFree(impl->ctx);
    impl->ctx = NULL;
    HcfFree(impl->pSource.data);
    impl->pSource.data = NULL;
    HcfFree(impl);
    impl = NULL;
}

static const char *EngineGetClass(void)
{
    return OPENSSL_RSA_CIPHER_CLASS;
}

static HcfResult CheckRsaCipherParams(CipherAttr *params)
{
    int32_t opensslPadding = 0;
    if (params->algo != HCF_ALG_RSA) {
        LOGE("Cipher algo %{public}u is invalid.", params->algo);
        return HCF_INVALID_PARAMS;
    }
    if (GetOpensslPadding(params->paddingMode, &opensslPadding) != HCF_SUCCESS) {
        LOGE("Cipher create without padding mode");
        return HCF_INVALID_PARAMS;
    }
    // cannot use pss padding mode in RSA cipher.
    if (opensslPadding == RSA_PKCS1_PSS_PADDING) {
        LOGE("Cipher cannot use PSS mode");
        return HCF_INVALID_PARAMS;
    }
    if (params->paddingMode == HCF_OPENSSL_RSA_PKCS1_OAEP_PADDING) {
        EVP_MD *md = NULL;
        EVP_MD *mgf1md = NULL;
        (void)GetOpensslDigestAlg(params->md, &md);
        (void)GetOpensslDigestAlg(params->mgf1md, &mgf1md);
        if (md == NULL) {
            LOGE("Use pkcs1_oaep padding, but md is NULL");
            return HCF_INVALID_PARAMS;
        }
        if (mgf1md == NULL) {
            LOGE("Use pkcs1_oaep padding, but mgf1md is NULL");
            return HCF_INVALID_PARAMS;
        }
    }
    return HCF_SUCCESS;
}

HcfResult HcfCipherRsaCipherSpiCreate(CipherAttr *params, HcfCipherGeneratorSpi **generator)
{
    if (generator == NULL || params == NULL) {
        LOGE("Invalid input parameter.");
        return HCF_INVALID_PARAMS;
    }
    HcfCipherRsaGeneratorSpiImpl *returnImpl = (HcfCipherRsaGeneratorSpiImpl *)HcfMalloc(
        sizeof(HcfCipherRsaGeneratorSpiImpl), 0);
    if (returnImpl == NULL) {
        LOGE("Malloc rsa cipher fail.");
        return HCF_ERR_MALLOC;
    }
    (void)memcpy_s(&returnImpl->attr, sizeof(CipherAttr), params, sizeof(CipherAttr));

    if (CheckRsaCipherParams(&returnImpl->attr) != HCF_SUCCESS) {
        HcfFree(returnImpl);
        returnImpl = NULL;
        LOGE("Failed to validate RSA cipher parameters.");
        return HCF_INVALID_PARAMS;
    }

    returnImpl->super.init = EngineInit;
    returnImpl->super.update = EngineUpdate;
    returnImpl->super.doFinal = EngineDoFinal;
    returnImpl->super.setCipherSpecUint8Array = SetRsaCipherSpecUint8Array;
    returnImpl->super.getCipherSpecString = GetRsaCipherSpecString;
    returnImpl->super.getCipherSpecUint8Array = GetRsaCipherSpecUint8Array;
    returnImpl->super.base.destroy = EngineDestroySpiImpl;
    returnImpl->super.base.getClass = EngineGetClass;
    returnImpl->initFlag = UNINITIALIZED;
    *generator = (HcfCipherGeneratorSpi *)returnImpl;
    return HCF_SUCCESS;
}
