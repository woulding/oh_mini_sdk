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

#include "cipher_openssl.h"
#include <stdbool.h>
#include "securec.h"
#include "log.h"
#include "blob.h"
#include "memory.h"
#include "result.h"
#include "aes_openssl_common.h"
#include "sym_common_defines.h"
#include "openssl_adapter.h"
#include "openssl_common.h"
#include "openssl_class.h"
#include "utils.h"

typedef struct {
    HcfCipherGeneratorSpi base;
    CipherAttr attr;
    CipherData cipherData;
    CryptoStatus initFlag;
} HcfCipherSymAlgorithmGeneratorSpiOpensslImpl;

#define SYM_ALG_BLOCK_SIZE 8
#define SYM_ALG_IV_SIZE 8
#define RC4_40_KEY_BYTES 5

static const char *GetSymAlgorithmGeneratorClass(void)
{
    return "OPENSSL.CIPHER";
}

static const char *GetRc2FetchName(HcfAlgParaValue mode)
{
    switch (mode) {
        case HCF_ALG_MODE_ECB:
            return "RC2-ECB";
        case HCF_ALG_MODE_CBC:
            return "RC2-CBC";
        case HCF_ALG_MODE_OFB:
            return "RC2-OFB";
        case HCF_ALG_MODE_CFB:
            return "RC2-CFB";
        default:
            return "RC2-CBC";
    }
}

static const char *GetBlowfishFetchName(HcfAlgParaValue mode)
{
    switch (mode) {
        case HCF_ALG_MODE_ECB:
            return "BF-ECB";
        case HCF_ALG_MODE_CBC:
            return "BF-CBC";
        case HCF_ALG_MODE_OFB:
            return "BF-OFB";
        case HCF_ALG_MODE_CFB:
            return "BF-CFB";
        default:
            return "BF-CBC";
    }
}

static const char *GetCastFetchName(HcfAlgParaValue mode)
{
    switch (mode) {
        case HCF_ALG_MODE_ECB:
            return "CAST5-ECB";
        case HCF_ALG_MODE_CBC:
            return "CAST5-CBC";
        case HCF_ALG_MODE_OFB:
            return "CAST5-OFB";
        case HCF_ALG_MODE_CFB:
            return "CAST5-CFB";
        default:
            return "CAST5-CBC";
    }
}

static const char *GetSymAlgFetchName(HcfAlgValue algo, HcfAlgParaValue mode)
{
    switch (algo) {
        case HCF_ALG_RC2:
            return GetRc2FetchName(mode);
        case HCF_ALG_RC4:
            return "RC4";
        case HCF_ALG_BLOWFISH:
            return GetBlowfishFetchName(mode);
        case HCF_ALG_CAST:
            return GetCastFetchName(mode);
        default:
            LOGE("Unsupported algorithm!");
            return NULL;
    }
}

static void ClearCipherData(CipherData *cipherData)
{
    if (cipherData == NULL) {
        return;
    }
    if (cipherData->ctx != NULL) {
        OpensslEvpCipherCtxFree(cipherData->ctx);
        cipherData->ctx = NULL;
    }
}

static EVP_CIPHER *GetCipherType(HcfCipherSymAlgorithmGeneratorSpiOpensslImpl *impl)
{
    const char *name = GetSymAlgFetchName(impl->attr.algo, impl->attr.mode);
    if (name == NULL) {
        LOGE("Unsupported algorithm or mode.");
        return NULL;
    }
    EVP_CIPHER *cipher = OpensslEvpCipherFetch(NULL, name, NULL);
    if (cipher == NULL) {
        HcfPrintOpensslError();
        LOGE("EVP_CIPHER_fetch failed for %{public}s.", name);
    }
    return cipher;
}

static HcfResult InitCipherData(enum HcfCryptoMode opMode, CipherData *cipherData)
{
    if (cipherData == NULL) {
        LOGE("cipherData is null.");
        return HCF_ERR_PARAMETER_CHECK_FAILED;
    }
    cipherData->enc = opMode;
    cipherData->ctx = OpensslEvpCipherCtxNew();
    if (cipherData->ctx == NULL) {
        HcfPrintOpensslError();
        LOGE("Failed to allocate ctx memory.");
        return HCF_ERR_MALLOC;
    }
    return HCF_SUCCESS;
}

static HcfResult CheckCipherInitParams(HcfCipherGeneratorSpi *self, HcfKey *key)
{
    if ((self == NULL) || (key == NULL)) {
        LOGE("Invalid input parameter.");
        return HCF_ERR_PARAMETER_CHECK_FAILED;
    }
    if (!HcfIsClassMatch((const HcfObjectBase *)self, GetSymAlgorithmGeneratorClass())) {
        LOGE("Class is not match.");
        return HCF_ERR_PARAMETER_CHECK_FAILED;
    }
    if (!HcfIsClassMatch((const HcfObjectBase *)key, OPENSSL_SYM_KEY_CLASS)) {
        LOGE("Sym key class is not match.");
        return HCF_ERR_PARAMETER_CHECK_FAILED;
    }
    return HCF_SUCCESS;
}

static bool IsIvRequired(HcfCipherSymAlgorithmGeneratorSpiOpensslImpl *cipherImpl)
{
    return (cipherImpl->attr.algo != HCF_ALG_RC4) && (cipherImpl->attr.mode != HCF_ALG_MODE_ECB);
}

static const unsigned char *GetIvData(HcfCipherSymAlgorithmGeneratorSpiOpensslImpl *cipherImpl,
    HcfParamsSpec *params)
{
    if (cipherImpl == NULL) {
        LOGE("cipherImpl is NULL.");
        return NULL;
    }
    if (!IsIvRequired(cipherImpl)) {
        return NULL;
    }
    if (cipherImpl->attr.algo == HCF_ALG_RC4) {
        return NULL;
    }
    if (cipherImpl->attr.mode == HCF_ALG_MODE_ECB) {
        return NULL;
    }
    if (params == NULL) {
        LOGE("params is NULL, but IV is required for non-ECB modes.");
        return NULL;
    }
    HcfIvParamsSpec *spec = (HcfIvParamsSpec *)params;
    if (spec->iv.data == NULL || spec->iv.len != SYM_ALG_IV_SIZE) {
        LOGE("IV data is NULL or length invalid.");
        return NULL;
    }
    return spec->iv.data;
}

static HcfResult SetSymAlgCipherAttribute(HcfCipherSymAlgorithmGeneratorSpiOpensslImpl *cipherImpl,
    SymKeyImpl *keyImpl, int32_t enc, HcfParamsSpec *params)
{
    CipherData *data = &cipherImpl->cipherData;
    EVP_CIPHER *cipher = GetCipherType(cipherImpl);
    if (cipher == NULL) {
        LOGE("Failed to get cipher type.");
        return HCF_ERR_CRYPTO_OPERATION;
    }
    const unsigned char *iv = GetIvData(cipherImpl, params);
    if (OpensslEvpCipherInit(data->ctx, (const EVP_CIPHER *)cipher, NULL, NULL, enc) != HCF_OPENSSL_SUCCESS) {
        HcfPrintOpensslError();
        LOGE("EVP_CipherInit failed.");
        OpensslEvpCipherFree(cipher);
        return HCF_ERR_CRYPTO_OPERATION;
    }
    OpensslEvpCipherFree(cipher);
    if (OpensslEvpCipherCtxSetKeyLength(data->ctx, keyImpl->keyMaterial.len) != HCF_OPENSSL_SUCCESS) {
        HcfPrintOpensslError();
        LOGE("EVP_CIPHER_CTX_set_key_length failed.");
        return HCF_ERR_CRYPTO_OPERATION;
    }
    if (cipherImpl->attr.algo == HCF_ALG_RC2) {
        int keyBits = (int)(keyImpl->keyMaterial.len * 8);
        if (keyBits > 0 && OpensslEvpCipherCtxCtrl(data->ctx, EVP_CTRL_SET_RC2_KEY_BITS, keyBits, NULL)
            != HCF_OPENSSL_SUCCESS) {
            HcfPrintOpensslError();
            LOGE("EVP_CTRL_SET_RC2_KEY_BITS failed.");
            return HCF_ERR_CRYPTO_OPERATION;
        }
    }
    if (OpensslEvpCipherInit(data->ctx, NULL, keyImpl->keyMaterial.data, iv, enc) != HCF_OPENSSL_SUCCESS) {
        HcfPrintOpensslError();
        LOGE("EVP_CipherInit key/iv failed.");
        return HCF_ERR_CRYPTO_OPERATION;
    }
    int32_t padding = (cipherImpl->attr.paddingMode == HCF_ALG_NOPADDING) ? 0 : EVP_PADDING_PKCS7;
    if (OpensslEvpCipherCtxSetPadding(data->ctx, padding) != HCF_OPENSSL_SUCCESS) {
        HcfPrintOpensslError();
        LOGE("Set padding failed.");
        return HCF_ERR_CRYPTO_OPERATION;
    }
    return HCF_SUCCESS;
}

static HcfResult EngineCipherInit(HcfCipherGeneratorSpi *self, enum HcfCryptoMode opMode,
    HcfKey *key, HcfParamsSpec *params)
{
    HcfResult ret = CheckCipherInitParams(self, key);
    if (ret != HCF_SUCCESS) {
        return ret;
    }
    HcfCipherSymAlgorithmGeneratorSpiOpensslImpl *cipherImpl =
        (HcfCipherSymAlgorithmGeneratorSpiOpensslImpl *)self;
    SymKeyImpl *keyImpl = (SymKeyImpl *)key;
    if (opMode != ENCRYPT_MODE && opMode != DECRYPT_MODE) {
        LOGE("Invalid operation mode: %{public}d", opMode);
        return HCF_ERR_PARAMETER_CHECK_FAILED;
    }
    if (keyImpl->keyMaterial.data == NULL || keyImpl->keyMaterial.len == 0) {
        LOGE("Key material is empty.");
        return HCF_ERR_PARAMETER_CHECK_FAILED;
    }
    if (IsIvRequired(cipherImpl) && (params == NULL || GetIvData(cipherImpl, params) == NULL)) {
        LOGE("IV required for this mode.");
        return HCF_ERR_PARAMETER_CHECK_FAILED;
    }
    ret = InitCipherData(opMode, &cipherImpl->cipherData);
    if (ret != HCF_SUCCESS) {
        LOGE("Failed to initialize cipher data.");
        return ret;
    }
    ret = SetSymAlgCipherAttribute(cipherImpl, keyImpl, (opMode == ENCRYPT_MODE) ? 1 : 0, params);
    if (ret != HCF_SUCCESS) {
        LOGE("Failed to set symmetric algorithm cipher attribute.");
        ClearCipherData(&cipherImpl->cipherData);
        return ret;
    }
    cipherImpl->initFlag = INITIALIZED;
    return ret;
}

static HcfResult AllocateOutput(HcfBlob *input, HcfBlob *output, bool *isUpdateInput)
{
    uint32_t outLen = SYM_ALG_BLOCK_SIZE + SYM_ALG_BLOCK_SIZE;
    if (HcfIsBlobValid(input)) {
        if (outLen > UINT32_MAX - input->len) {
            LOGE("Input length overflow.");
            return HCF_ERR_PARAMETER_CHECK_FAILED;
        }
        outLen += input->len;
        if (isUpdateInput != NULL) {
            *isUpdateInput = true;
        }
    } else if (isUpdateInput != NULL) {
        *isUpdateInput = false;
    }
    output->data = (uint8_t *)HcfMalloc(outLen, 0);
    if (output->data == NULL) {
        LOGE("Malloc output failed.");
        return HCF_ERR_MALLOC;
    }
    output->len = outLen;
    return HCF_SUCCESS;
}

static HcfResult EngineUpdate(HcfCipherGeneratorSpi *self, HcfBlob *input, HcfBlob *output)
{
    if ((self == NULL) || (input == NULL) || (output == NULL)) {
        LOGE("Invalid input parameter.");
        return HCF_ERR_PARAMETER_CHECK_FAILED;
    }
    if (!HcfIsClassMatch((const HcfObjectBase *)self, GetSymAlgorithmGeneratorClass())) {
        LOGE("Class is not match.");
        return HCF_ERR_PARAMETER_CHECK_FAILED;
    }
    HcfCipherSymAlgorithmGeneratorSpiOpensslImpl *cipherImpl = (HcfCipherSymAlgorithmGeneratorSpiOpensslImpl *)self;
    if (cipherImpl->initFlag != INITIALIZED) {
        LOGW("Cipher instance may not have been initialized, "
            "ensure init interface of Cipher instance is executed completely!");
    }

    CipherData *data = &cipherImpl->cipherData;
    if (data->ctx == NULL) {
        LOGE("The ctx of Cipher instance is NULL, "
            "please check if init interface of Cipher instance is executed completely!");
        return HCF_ERR_PARAMETER_CHECK_FAILED;
    }
    bool isUpdateInput = false;
    HcfResult res = AllocateOutput(input, output, &isUpdateInput);
    if (res != HCF_SUCCESS) {
        LOGE("Failed to allocate output buffer.");
        return res;
    }
    int32_t ret = OpensslEvpCipherUpdate(data->ctx, output->data, (int *)&output->len,
        input->data, input->len);
    if (ret != HCF_OPENSSL_SUCCESS) {
        HcfPrintOpensslError();
        LOGE("Cipher update failed.");
        HcfBlobDataClearAndFree(output);
        ClearCipherData(&cipherImpl->cipherData);
        return HCF_ERR_CRYPTO_OPERATION;
    }
    FreeRedundantOutput(output);
    return HCF_SUCCESS;
}

static HcfResult SymAlgDoFinal(CipherData *data, HcfBlob *input, HcfBlob *output, bool isUpdateInput)
{
    int32_t ret;
    uint32_t updateLen = 0;
    if (isUpdateInput && HcfIsBlobValid(input)) {
        ret = OpensslEvpCipherUpdate(data->ctx, output->data, (int32_t *)&updateLen,
            input->data, input->len);
        if (ret != HCF_OPENSSL_SUCCESS) {
            HcfPrintOpensslError();
            LOGE("Cipher update failed.");
            return HCF_ERR_CRYPTO_OPERATION;
        }
    }
    ret = OpensslEvpCipherFinalEx(data->ctx, output->data + updateLen, (int32_t *)&output->len);
    if (ret != HCF_OPENSSL_SUCCESS) {
        HcfPrintOpensslError();
        LOGE("Cipher final failed.");
        return HCF_ERR_CRYPTO_OPERATION;
    }
    output->len += updateLen;
    return HCF_SUCCESS;
}

static HcfResult EngineDoFinal(HcfCipherGeneratorSpi *self, HcfBlob *input, HcfBlob *output)
{
    if ((self == NULL) || (output == NULL)) {
        LOGE("Invalid input parameter.");
        return HCF_ERR_PARAMETER_CHECK_FAILED;
    }
    if (!HcfIsClassMatch((const HcfObjectBase *)self, GetSymAlgorithmGeneratorClass())) {
        LOGE("Class is not match.");
        return HCF_ERR_PARAMETER_CHECK_FAILED;
    }
    HcfCipherSymAlgorithmGeneratorSpiOpensslImpl *cipherImpl = (HcfCipherSymAlgorithmGeneratorSpiOpensslImpl *)self;
    if (cipherImpl->initFlag != INITIALIZED) {
        LOGW("Cipher instance may not have been initialized, "
            "ensure init interface of Cipher instance is executed completely!");
    }

    CipherData *data = &cipherImpl->cipherData;
    if (data->ctx == NULL) {
        LOGE("The ctx of Cipher instance is NULL, "
            "please check if init interface of Cipher instance is executed completely!");
        return HCF_ERR_PARAMETER_CHECK_FAILED;
    }
    bool isUpdateInput = false;
    HcfResult res = AllocateOutput(input, output, &isUpdateInput);
    if (res != HCF_SUCCESS) {
        LOGE("Failed to allocate output buffer.");
        return res;
    }
    res = SymAlgDoFinal(data, input, output, isUpdateInput);
    ClearCipherData(&cipherImpl->cipherData);
    if (res != HCF_SUCCESS) {
        LOGE("Failed to finalize symmetric algorithm cipher operation.");
        HcfBlobDataClearAndFree(output);
        return res;
    }
    FreeRedundantOutput(output);
    return HCF_SUCCESS;
}

static void EngineSymAlgorithmGeneratorDestroy(HcfObjectBase *self)
{
    if (self == NULL) {
        return;
    }
    if (!HcfIsClassMatch(self, GetSymAlgorithmGeneratorClass())) {
        LOGE("Class is not match.");
        return;
    }
    HcfCipherSymAlgorithmGeneratorSpiOpensslImpl *impl =
        (HcfCipherSymAlgorithmGeneratorSpiOpensslImpl *)self;
    ClearCipherData(&impl->cipherData);
    HcfFree(impl);
}

static HcfResult GetSymAlgCipherSpecString(HcfCipherGeneratorSpi *self, CipherSpecItem item,
    char **returnString)
{
    (void)self;
    (void)item;
    (void)returnString;
    LOGE("Unsupported cipher spec!");
    return HCF_ERR_INVALID_CALL;
}

static HcfResult GetSymAlgCipherSpecUint8Array(HcfCipherGeneratorSpi *self, CipherSpecItem item,
    HcfBlob *returnUint8Array)
{
    (void)self;
    (void)item;
    (void)returnUint8Array;
    LOGE("Unsupported cipher spec!");
    return HCF_ERR_INVALID_CALL;
}

static HcfResult SetSymAlgCipherSpecUint8Array(HcfCipherGeneratorSpi *self, CipherSpecItem item,
    HcfBlob blob)
{
    (void)self;
    (void)item;
    (void)blob;
    LOGE("Unsupported cipher spec!");
    return HCF_ERR_INVALID_CALL;
}

HcfResult HcfCipherSymAlgorithmGeneratorSpiCreate(CipherAttr *attr, HcfCipherGeneratorSpi **generator)
{
    if ((attr == NULL) || (generator == NULL)) {
        LOGE("Invalid input parameter.");
        return HCF_ERR_PARAMETER_CHECK_FAILED;
    }

    HcfCipherSymAlgorithmGeneratorSpiOpensslImpl *returnImpl =
        (HcfCipherSymAlgorithmGeneratorSpiOpensslImpl *)HcfMalloc(
            sizeof(HcfCipherSymAlgorithmGeneratorSpiOpensslImpl), 0);
    if (returnImpl == NULL) {
        LOGE("Failed to allocate returnImpl memory.");
        return HCF_ERR_MALLOC;
    }
    (void)memcpy_s(&returnImpl->attr, sizeof(CipherAttr), attr, sizeof(CipherAttr));
    returnImpl->base.init = EngineCipherInit;
    returnImpl->base.update = EngineUpdate;
    returnImpl->base.doFinal = EngineDoFinal;
    returnImpl->base.getCipherSpecString = GetSymAlgCipherSpecString;
    returnImpl->base.getCipherSpecUint8Array = GetSymAlgCipherSpecUint8Array;
    returnImpl->base.setCipherSpecUint8Array = SetSymAlgCipherSpecUint8Array;
    returnImpl->base.base.destroy = EngineSymAlgorithmGeneratorDestroy;
    returnImpl->base.base.getClass = GetSymAlgorithmGeneratorClass;

    *generator = (HcfCipherGeneratorSpi *)returnImpl;
    return HCF_SUCCESS;
}
