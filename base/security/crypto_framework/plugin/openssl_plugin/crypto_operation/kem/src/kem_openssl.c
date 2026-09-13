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

#include "kem_openssl.h"

#include <openssl/core_names.h>
#include <openssl/evp.h>
#include <securec.h>

#include "config.h"
#include "log.h"
#include "memory.h"
#include "openssl_adapter.h"
#include "openssl_class.h"
#include "openssl_common.h"
#include "utils.h"

typedef struct {
    HcfKemSpi base;
    char algoName[HCF_MAX_ALGO_NAME_LEN];
} HcfKemOpensslSpiImpl;

static const char *GetKemSpiClass(void)
{
    return "HcfKemOpensslSpi";
}

static const char *GetOpensslKemAlgoName(const char *hcfAlgoName)
{
    if (hcfAlgoName == NULL) {
        LOGE("HcfAlgoName is NULL.");
        return NULL;
    }
    if (strcmp(hcfAlgoName, "ML-KEM512") == 0) {
        return "ML-KEM-512";
    }
    if (strcmp(hcfAlgoName, "ML-KEM768") == 0) {
        return "ML-KEM-768";
    }
    if (strcmp(hcfAlgoName, "ML-KEM1024") == 0) {
        return "ML-KEM-1024";
    }
    LOGE("Unsupported KEM algorithm: %{public}s", hcfAlgoName);
    return NULL;
}

static HcfResult CheckKemAlgoMatch(EVP_PKEY *pkey, const char *opensslAlgoName)
{
    if (pkey == NULL || opensslAlgoName == NULL) {
        LOGE("Invalid params.");
        return HCF_ERR_PARAMETER_CHECK_FAILED;
    }
    if (OpensslEvpPkeyIsA(pkey, opensslAlgoName) != HCF_OPENSSL_SUCCESS) {
        LOGE("The key algorithm does not match KEM algorithm.");
        return HCF_ERR_PARAMETER_CHECK_FAILED;
    }
    return HCF_SUCCESS;
}

static HcfResult KemEncapsulateInit(EVP_PKEY_CTX *ctx, const HcfBlob *ikme)
{
    if (EVP_PKEY_encapsulate_init(ctx, NULL) != HCF_OPENSSL_SUCCESS) {
        LOGE("EVP_PKEY_encapsulate_init failed.");
        HcfPrintOpensslError();
        return HCF_ERR_CRYPTO_OPERATION;
    }
    if (ikme != NULL && HcfIsBlobValid(ikme)) {
        OSSL_PARAM params[] = {
            OpensslOsslParamConstructOctetString(OSSL_KEM_PARAM_IKME, (void *)ikme->data, ikme->len),
            OpensslOsslParamConstructEnd()
        };
        if (OpensslEvpPkeyCtxSetParams(ctx, params) != HCF_OPENSSL_SUCCESS) {
            LOGE("Set ikme parameter failed.");
            HcfPrintOpensslError();
            return HCF_ERR_CRYPTO_OPERATION;
        }
    }
    return HCF_SUCCESS;
}

static HcfResult KemEncapsulateExec(EVP_PKEY_CTX *ctx, HcfBlob *returnSharedSecret, HcfBlob *returnWrappedKey)
{
    size_t wrappedKeyLen = 0;
    size_t sharedSecretLen = 0;
    if (EVP_PKEY_encapsulate(ctx, NULL, &wrappedKeyLen, NULL, &sharedSecretLen) != HCF_OPENSSL_SUCCESS) {
        LOGE("Get ML-KEM output length failed.");
        HcfPrintOpensslError();
        return HCF_ERR_CRYPTO_OPERATION;
    }
    if (wrappedKeyLen == 0 || sharedSecretLen == 0) {
        LOGE("Invalid encapsulate output length.");
        return HCF_ERR_CRYPTO_OPERATION;
    }
    returnWrappedKey->data = (uint8_t *)HcfMalloc(wrappedKeyLen, 0);
    returnSharedSecret->data = (uint8_t *)HcfMalloc(sharedSecretLen, 0);
    if (returnWrappedKey->data == NULL || returnSharedSecret->data == NULL) {
        LOGE("Allocate encapsulate output memory failed.");
        return HCF_ERR_MALLOC;
    }
    returnWrappedKey->len = wrappedKeyLen;
    returnSharedSecret->len = sharedSecretLen;
    if (EVP_PKEY_encapsulate(ctx, returnWrappedKey->data, &returnWrappedKey->len,
        returnSharedSecret->data, &returnSharedSecret->len) != HCF_OPENSSL_SUCCESS) {
        LOGE("ML-KEM encapsulate failed.");
        HcfPrintOpensslError();
        HcfBlobDataClearAndFree(returnWrappedKey);
        HcfBlobDataClearAndFree(returnSharedSecret);
        return HCF_ERR_CRYPTO_OPERATION;
    }
    return HCF_SUCCESS;
}

static HcfResult KemEncapsulate(EVP_PKEY *pubPkey, const HcfBlob *ikme,
    HcfBlob *returnSharedSecret, HcfBlob *returnWrappedKey)
{
    EVP_PKEY_CTX *ctx = OpensslEvpPkeyCtxNewFromPkey(NULL, pubPkey, NULL);
    if (ctx == NULL) {
        LOGE("Failed to create EVP_PKEY_CTX.");
        return HCF_ERR_CRYPTO_OPERATION;
    }
    HcfResult ret = KemEncapsulateInit(ctx, ikme);
    if (ret == HCF_SUCCESS) {
        ret = KemEncapsulateExec(ctx, returnSharedSecret, returnWrappedKey);
    }
    OpensslEvpPkeyCtxFree(ctx);
    return ret;
}

static HcfResult KemDecapsulate(EVP_PKEY *priPkey, const HcfBlob *wrappedKey, HcfBlob *returnSharedSecret)
{
    EVP_PKEY_CTX *ctx = OpensslEvpPkeyCtxNewFromPkey(NULL, priPkey, NULL);
    if (ctx == NULL) {
        LOGE("Failed to create EVP_PKEY_CTX.");
        return HCF_ERR_CRYPTO_OPERATION;
    }
    HcfResult ret = HCF_ERR_CRYPTO_OPERATION;
    do {
        if (EVP_PKEY_decapsulate_init(ctx, NULL) != HCF_OPENSSL_SUCCESS) {
            LOGE("EVP_PKEY_decapsulate_init failed.");
            HcfPrintOpensslError();
            break;
        }

        size_t sharedSecretLen = 0;
        if (EVP_PKEY_decapsulate(ctx, NULL, &sharedSecretLen,
            wrappedKey->data, wrappedKey->len) != HCF_OPENSSL_SUCCESS) {
            LOGE("Get ML-KEM decapsulate output length failed.");
            HcfPrintOpensslError();
            break;
        }
        if (sharedSecretLen == 0) {
            LOGE("Invalid decapsulate output length.");
            break;
        }

        returnSharedSecret->data = (uint8_t *)HcfMalloc(sharedSecretLen, 0);
        if (returnSharedSecret->data == NULL) {
            LOGE("Allocate decapsulate output memory failed.");
            ret = HCF_ERR_MALLOC;
            break;
        }
        returnSharedSecret->len = sharedSecretLen;
        if (EVP_PKEY_decapsulate(ctx, returnSharedSecret->data, &returnSharedSecret->len,
            wrappedKey->data, wrappedKey->len) != HCF_OPENSSL_SUCCESS) {
            LOGE("ML-KEM decapsulate failed.");
            HcfPrintOpensslError();
            break;
        }
        ret = HCF_SUCCESS;
    } while (0);

    if (ret != HCF_SUCCESS) {
        HcfBlobDataClearAndFree(returnSharedSecret);
    }
    OpensslEvpPkeyCtxFree(ctx);
    return ret;
}

static HcfResult EngineEncapsulate(HcfKemSpi *self, HcfPubKey *pubKey, const HcfBlob *ikme,
    HcfBlob *returnSharedSecret, HcfBlob *returnWrappedKey)
{
    if (self == NULL || pubKey == NULL || returnSharedSecret == NULL || returnWrappedKey == NULL) {
        LOGE("Invalid input parameter.");
        return HCF_ERR_PARAMETER_CHECK_FAILED;
    }
    if (!HcfIsClassMatch((HcfObjectBase *)self, GetKemSpiClass())) {
        LOGE("Class is not match.");
        return HCF_ERR_PARAMETER_CHECK_FAILED;
    }
    if (!HcfIsClassMatch((HcfObjectBase *)pubKey, OPENSSL_ML_KEM_PUBKEY_CLASS)) {
        LOGE("Class is not match.");
        return HCF_ERR_PARAMETER_CHECK_FAILED;
    }
    EVP_PKEY *pubPkey = ((HcfOpensslMlKemPubKey *)pubKey)->pkey;
    const char *opensslAlgoName = GetOpensslKemAlgoName(((HcfKemOpensslSpiImpl *)self)->algoName);
    if (opensslAlgoName == NULL) {
        LOGE("Failed to get OpenSSL KEM algorithm name.");
        return HCF_ERR_PARAMETER_CHECK_FAILED;
    }
    HcfResult ret = CheckKemAlgoMatch(pubPkey, opensslAlgoName);
    if (ret != HCF_SUCCESS) {
        return ret;
    }
    ret = KemEncapsulate(pubPkey, ikme, returnSharedSecret, returnWrappedKey);
    return ret;
}

static HcfResult EngineDecapsulate(HcfKemSpi *self, HcfPriKey *priKey, const HcfBlob *wrappedKey,
    HcfBlob *returnSharedSecret)
{
    if (self == NULL || priKey == NULL || wrappedKey == NULL || returnSharedSecret == NULL) {
        LOGE("Invalid input parameter.");
        return HCF_ERR_PARAMETER_CHECK_FAILED;
    }
    if (!HcfIsClassMatch((HcfObjectBase *)self, GetKemSpiClass())) {
        LOGE("Class is not match.");
        return HCF_ERR_PARAMETER_CHECK_FAILED;
    }
    if (!HcfIsClassMatch((HcfObjectBase *)priKey, OPENSSL_ML_KEM_PRIKEY_CLASS)) {
        LOGE("Class is not match.");
        return HCF_ERR_PARAMETER_CHECK_FAILED;
    }
    if (!HcfIsBlobValid(wrappedKey)) {
        LOGE("Invalid wrappedKey.");
        return HCF_ERR_PARAMETER_CHECK_FAILED;
    }
    EVP_PKEY *priPkey = ((HcfOpensslMlKemPriKey *)priKey)->pkey;
    const char *opensslAlgoName = GetOpensslKemAlgoName(((HcfKemOpensslSpiImpl *)self)->algoName);
    if (opensslAlgoName == NULL) {
        LOGE("Failed to get OpenSSL KEM algorithm name.");
        return HCF_ERR_PARAMETER_CHECK_FAILED;
    }
    HcfResult ret = CheckKemAlgoMatch(priPkey, opensslAlgoName);
    if (ret != HCF_SUCCESS) {
        return ret;
    }
    ret = KemDecapsulate(priPkey, wrappedKey, returnSharedSecret);
    if (ret != HCF_SUCCESS) {
        LOGE("Kem decapsulate failed.");
    }
    return ret;
}

static void DestroyKemSpi(HcfObjectBase *self)
{
    if (self == NULL) {
        return;
    }
    if (!HcfIsClassMatch(self, GetKemSpiClass())) {
        return;
    }
    HcfFree(self);
}

HcfResult HcfKemSpiCreateOpenssl(const char *algoName, HcfKemSpi **returnObj)
{
    if (!HcfIsStrValid(algoName, HCF_MAX_ALGO_NAME_LEN) || returnObj == NULL) {
        LOGE("Invalid input parameter.");
        return HCF_ERR_PARAMETER_CHECK_FAILED;
    }

    HcfKemOpensslSpiImpl *impl = (HcfKemOpensslSpiImpl *)HcfMalloc(sizeof(HcfKemOpensslSpiImpl), 0);
    if (impl == NULL) {
        LOGE("Failed to allocate KEM openssl spi object.");
        return HCF_ERR_MALLOC;
    }
    if (strcpy_s(impl->algoName, HCF_MAX_ALGO_NAME_LEN, algoName) != EOK) {
        LOGE("Failed to copy algoName.");
        HcfFree(impl);
        return HCF_ERR_PARAMETER_CHECK_FAILED;
    }

    impl->base.base.getClass = GetKemSpiClass;
    impl->base.base.destroy = DestroyKemSpi;
    impl->base.engineEncapsulate = EngineEncapsulate;
    impl->base.engineDecapsulate = EngineDecapsulate;
    *returnObj = (HcfKemSpi *)impl;
    return HCF_SUCCESS;
}
