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
#include "sm4_openssl.h"
#include <string.h>
#include "securec.h"
#include "blob.h"
#include "log.h"
#include "memory.h"
#include "result.h"
#include "utils.h"
#include "aes_openssl_common.h"
#include "sym_common_defines.h"
#include "openssl_adapter.h"
#include "openssl_common.h"
#include "openssl_class.h"

#define MAX_AAD_LEN 2048
#define SM4_BLOCK_SIZE 16
#define SM4_SIZE_128 16
#define GCM_IV_MIN_LEN 1
#define GCM_IV_MAX_LEN 128
#define GCM_TAG_SIZE 16
#define GCM_TAG_LEN_4 4
#define GCM_TAG_LEN_8 8
#define GCM_TAG_LEN_12 12
#define CBC_CTR_OFB_CFB_IV_LEN 16
#define AEAD_PARAMS_SPEC_TYPE "AeadParamsSpec"

typedef struct {
    HcfCipherGeneratorSpi base;
    CipherAttr attr;
    CipherData *cipherData;
    CryptoStatus initFlag;
} HcfCipherSm4GeneratorSpiOpensslImpl;

static const char *GetSm4GeneratorClass(void)
{
    return OPENSSL_SM4_CIPHER_CLASS;
}

static const EVP_CIPHER *CipherEcbType(SymKeyImpl *symKey)
{
    switch (symKey->keyMaterial.len) {
        case SM4_SIZE_128:
            return OpensslEvpSm4Ecb();
        default:
            break;
    }
    LOGE("Unsupported key length!");
    return NULL;
}

static const EVP_CIPHER *CipherCbcType(SymKeyImpl *symKey)
{
    switch (symKey->keyMaterial.len) {
        case SM4_SIZE_128:
            return OpensslEvpSm4Cbc();
        default:
            break;
    }
    LOGE("Unsupported key length!");
    return NULL;
}

static const EVP_CIPHER *CipherCtrType(SymKeyImpl *symKey)
{
    switch (symKey->keyMaterial.len) {
        case SM4_SIZE_128:
            return OpensslEvpSm4Ctr();
        default:
            break;
    }
    LOGE("Unsupported key length!");
    return NULL;
}

static const EVP_CIPHER *CipherOfbType(SymKeyImpl *symKey)
{
    switch (symKey->keyMaterial.len) {
        case SM4_SIZE_128:
            return OpensslEvpSm4Ofb();
        default:
            break;
    }
    LOGE("Unsupported key length!");
    return NULL;
}

static const EVP_CIPHER *CipherCfbType(SymKeyImpl *symKey)
{
    switch (symKey->keyMaterial.len) {
        case SM4_SIZE_128:
            return OpensslEvpSm4Cfb();
        default:
            break;
    }
    LOGE("Unsupported key length!");
    return NULL;
}

static const EVP_CIPHER *CipherCfb128Type(SymKeyImpl *symKey)
{
    switch (symKey->keyMaterial.len) {
        case SM4_SIZE_128:
            return OpensslEvpSm4Cfb128();
        default:
            break;
    }
    LOGE("Unsupported key length!");
    return NULL;
}

static const EVP_CIPHER *CipherGcmType(SymKeyImpl *symKey)
{
    (void)symKey;
    return (const EVP_CIPHER *)OpensslEvpCipherFetch(NULL, "SM4-GCM", NULL);
}

static const EVP_CIPHER *DefaultCipherType(SymKeyImpl *symKey)
{
    return CipherEcbType(symKey);
}

static const EVP_CIPHER *GetCipherType(HcfCipherSm4GeneratorSpiOpensslImpl *impl, SymKeyImpl *symKey)
{
    switch (impl->attr.mode) {
        case HCF_ALG_MODE_ECB:
            return CipherEcbType(symKey);
        case HCF_ALG_MODE_CBC:
            return CipherCbcType(symKey);
        case HCF_ALG_MODE_CTR:
            return CipherCtrType(symKey);
        case HCF_ALG_MODE_OFB:
            return CipherOfbType(symKey);
        case HCF_ALG_MODE_CFB:
            return CipherCfbType(symKey);
        case HCF_ALG_MODE_CFB128:
            return CipherCfb128Type(symKey);
        case HCF_ALG_MODE_GCM:
            return CipherGcmType(symKey);
        default:
            break;
    }
    return DefaultCipherType(symKey);
}

static HcfResult IsIvParamsValid(HcfIvParamsSpec *params)
{
    if (params == NULL) {
        LOGE("params is null!");
        return HCF_INVALID_PARAMS;
    }
    if ((params->iv.data == NULL) || (params->iv.len != CBC_CTR_OFB_CFB_IV_LEN)) {
        LOGE("iv is invalid!");
        return HCF_INVALID_PARAMS;
    }
    return HCF_SUCCESS;
}

static bool IsGcmParamsValid(HcfGcmParamsSpec *params)
{
    if (params == NULL) {
        LOGE("params is null!");
        return false;
    }
    if ((params->iv.data == NULL) || (params->iv.len < GCM_IV_MIN_LEN) || (params->iv.len > GCM_IV_MAX_LEN)) {
        LOGE("iv is invalid!");
        return false;
    }
    if ((params->tag.data == NULL) || (params->tag.len == 0)) {
        LOGE("tag is invalid!");
        return false;
    }
    return true;
}

static bool IsGcmAeadParamsValid(HcfAeadParamsSpec *params)
{
    if (params == NULL) {
        LOGE("params is null!");
        return false;
    }
    if ((params->nonce.data == NULL) || (params->nonce.len < GCM_IV_MIN_LEN) || (params->nonce.len > GCM_IV_MAX_LEN)) {
        LOGE("nonce is invalid!");
        return false;
    }
    int32_t tagLen = (params->tagLen == 0) ? GCM_TAG_SIZE : params->tagLen;
    if (!(tagLen == GCM_TAG_LEN_4 || tagLen == GCM_TAG_LEN_8 || (tagLen >= GCM_TAG_LEN_12 && tagLen <= GCM_TAG_SIZE))) {
        LOGE("tag len is invalid!");
        return false;
    }
    return true;
}

static HcfResult InitAadAndTagFromGcmParams(enum HcfCryptoMode opMode, HcfGcmParamsSpec *params, CipherData *data)
{
    if (!IsGcmParamsValid(params)) {
        LOGE("gcm params is invalid!");
        return HCF_INVALID_PARAMS;
    }

    if (params->aad.data != NULL && params->aad.len != 0) {
        data->aad = (uint8_t *)HcfMalloc(params->aad.len, 0);
        if (data->aad == NULL) {
            LOGE("aad malloc failed!");
            return HCF_ERR_MALLOC;
        }
        (void)memcpy_s(data->aad, params->aad.len, params->aad.data, params->aad.len);
        data->aadLen = params->aad.len;
        data->aead = true;
    } else {
        data->aad = NULL;
        data->aadLen = 0;
        data->aead = false;
    }
    data->tagLen = params->tag.len;
    if (opMode == ENCRYPT_MODE) {
        return HCF_SUCCESS;
    }
    data->tag = (uint8_t *)HcfMalloc(params->tag.len, 0);
    if (data->tag == NULL) {
        HcfFree(data->aad);
        data->aad = NULL;
        LOGE("tag malloc failed!");
        return HCF_ERR_MALLOC;
    }
    (void)memcpy_s(data->tag, params->tag.len, params->tag.data, params->tag.len);
    return HCF_SUCCESS;
}

static HcfResult InitAadAndTagFromAeadParams(enum HcfCryptoMode opMode, HcfAeadParamsSpec *params, CipherData *data)
{
    (void)opMode;
    if (!IsGcmAeadParamsValid(params)) {
        LOGE("aead params is invalid!");
        return HCF_INVALID_PARAMS;
    }
    if (params->aad.data != NULL && params->aad.len != 0) {
        data->aad = (uint8_t *)HcfMalloc(params->aad.len, 0);
        if (data->aad == NULL) {
            LOGE("aad malloc failed!");
            return HCF_ERR_MALLOC;
        }
        (void)memcpy_s(data->aad, params->aad.len, params->aad.data, params->aad.len);
        data->aadLen = params->aad.len;
        data->aead = true;
    } else {
        data->aad = NULL;
        data->aadLen = 0;
        data->aead = false;
    }
    data->tagLen = (params->tagLen == 0) ? GCM_TAG_SIZE : (uint32_t)params->tagLen;
    data->isNewCcmAead = true;
    return HCF_SUCCESS;
}

static HcfResult InitCipherData(HcfCipherGeneratorSpi* self, enum HcfCryptoMode opMode,
    HcfParamsSpec* params, CipherData **cipherData)
{
    HcfResult ret = HCF_ERR_MALLOC;
    *cipherData = (CipherData *)HcfMalloc(sizeof(CipherData), 0);
    if (*cipherData == NULL) {
        LOGE("malloc is failed!");
        return ret;
    }
    HcfCipherSm4GeneratorSpiOpensslImpl *cipherImpl = (HcfCipherSm4GeneratorSpiOpensslImpl *)self;
    HcfAlgParaValue mode = cipherImpl->attr.mode;

    (*cipherData)->enc = opMode;
    (*cipherData)->ctx = OpensslEvpCipherCtxNew();
    if ((*cipherData)->ctx == NULL) {
        HcfPrintOpensslError();
        LOGE("Failed to allocate ctx memory!");
        goto clearup;
    }

    ret = HCF_SUCCESS;
    switch (mode) {
        case HCF_ALG_MODE_CBC:
        case HCF_ALG_MODE_CTR:
        case HCF_ALG_MODE_OFB:
        case HCF_ALG_MODE_CFB:
        case HCF_ALG_MODE_CFB128:
            (void)IsIvParamsValid((HcfIvParamsSpec *)params);
            break;
        case HCF_ALG_MODE_GCM:
            if ((params != NULL) && (params->getType != NULL) &&
                (strcmp(params->getType(), AEAD_PARAMS_SPEC_TYPE) == 0)) {
                ret = InitAadAndTagFromAeadParams(opMode, (HcfAeadParamsSpec *)params, *cipherData);
            } else {
                ret = InitAadAndTagFromGcmParams(opMode, (HcfGcmParamsSpec *)params, *cipherData);
            }
            break;
        case HCF_ALG_MODE_CCM:
            ret = HCF_NOT_SUPPORT;
            break;
        default:
            break;
    }
    if (ret != HCF_SUCCESS) {
        LOGE("init cipher data failed!");
        goto clearup;
    }
    return ret;
clearup:
    FreeCipherData(cipherData);
    return ret;
}

static int GetPaddingMode(HcfCipherSm4GeneratorSpiOpensslImpl* cipherImpl)
{
    switch (cipherImpl->attr.paddingMode) {
        case HCF_ALG_NOPADDING:
            break;
        case HCF_ALG_PADDING_PKCS5:
            return EVP_PADDING_PKCS7;
        case HCF_ALG_PADDING_PKCS7:
            return EVP_PADDING_PKCS7;
        default:
            LOGE("No Params!");
            break;
    }
    return 0;
}

static HcfResult CheckParam(HcfCipherGeneratorSpi* self, enum HcfCryptoMode opMode, HcfKey* key)
{
    if ((self == NULL) || (key == NULL)) {
        LOGE("Invalid input parameter.");
        return HCF_INVALID_PARAMS;
    }
    if (!HcfIsClassMatch((HcfObjectBase *)self, self->base.getClass())) {
        LOGE("Class is not match.");
        return HCF_INVALID_PARAMS;
    }
    if (!HcfIsClassMatch((HcfObjectBase *)key, OPENSSL_SYM_KEY_CLASS)) {
        LOGE("Class is not match.");
        return HCF_INVALID_PARAMS;
    }
    if (opMode != ENCRYPT_MODE && opMode != DECRYPT_MODE) {
        LOGE("Invalid opMode %{public}d", opMode);
        return HCF_INVALID_PARAMS;
    }
    SymKeyImpl* keyImpl = (SymKeyImpl*)key;
    if (keyImpl->keyMaterial.len < SM4_SIZE_128) {
        LOGE("Init failed, the input key size is smaller than keySize specified in cipher.");
        return HCF_INVALID_PARAMS;
    }
    HcfCipherSm4GeneratorSpiOpensslImpl *cipherImpl = (HcfCipherSm4GeneratorSpiOpensslImpl *)self;
    if (cipherImpl->attr.mode == HCF_ALG_MODE_GCM) {
        cipherImpl->attr.paddingMode = HCF_ALG_NOPADDING;
        LOGD("Default paddingMode is %{public}u", HCF_ALG_NOPADDING);
    }
    if (cipherImpl->attr.paddingMode != HCF_ALG_NOPADDING && cipherImpl->attr.paddingMode != HCF_ALG_PADDING_PKCS5 &&
        cipherImpl->attr.paddingMode != HCF_ALG_PADDING_PKCS7) {
        LOGE("Invalid padding mode %{public}u", cipherImpl->attr.paddingMode);
        return HCF_INVALID_PARAMS;
    }
    return HCF_SUCCESS;
}

static bool SetCipherAttribute(HcfCipherSm4GeneratorSpiOpensslImpl *cipherImpl, SymKeyImpl *keyImpl,
    int enc, HcfParamsSpec *params)
{
    CipherData *data = cipherImpl->cipherData;
    HcfAlgParaValue mode = cipherImpl->attr.mode;
    const EVP_CIPHER *cipher = GetCipherType(cipherImpl, keyImpl);
    if (cipher == NULL) {
        HcfPrintOpensslError();
        LOGE("fetch cipher failed!");
        return false;
    }
    if (mode != HCF_ALG_MODE_GCM) {
        if (OpensslEvpCipherInit(data->ctx, cipher, keyImpl->keyMaterial.data,
            GetIv(params), enc) != HCF_OPENSSL_SUCCESS) {
            HcfPrintOpensslError();
            LOGE("EVP_CipherInit failed!");
            return false;
        }
        return true;
    }
    if (OpensslEvpCipherInit(data->ctx, cipher, NULL, NULL, enc) != HCF_OPENSSL_SUCCESS) {
        HcfPrintOpensslError();
        LOGE("EVP_CipherInit failed!");
        OpensslEvpCipherFree((EVP_CIPHER *)cipher);
        return false;
    }
    OpensslEvpCipherFree((EVP_CIPHER *)cipher);
    if (OpensslEvpCipherCtxCtrl(data->ctx, EVP_CTRL_AEAD_SET_IVLEN,
        GetIvLen(params), NULL) != HCF_OPENSSL_SUCCESS) {
        HcfPrintOpensslError();
        LOGE("EVP_Cipher set iv len failed!");
        return false;
    }
    if (OpensslEvpCipherInit(data->ctx, NULL, keyImpl->keyMaterial.data,
        GetIv(params), enc) != HCF_OPENSSL_SUCCESS) {
        HcfPrintOpensslError();
        LOGE("EVP_CipherInit failed!");
        return false;
    }
    return true;
}

static HcfResult EngineCipherInit(HcfCipherGeneratorSpi* self, enum HcfCryptoMode opMode,
    HcfKey* key, HcfParamsSpec* params)
{
    if (CheckParam(self, opMode, key) != HCF_SUCCESS) {
        return HCF_INVALID_PARAMS;
    }
    HcfCipherSm4GeneratorSpiOpensslImpl *cipherImpl = (HcfCipherSm4GeneratorSpiOpensslImpl *)self;
    SymKeyImpl* keyImpl = (SymKeyImpl*)key;
    int32_t enc = (opMode == ENCRYPT_MODE) ? 1 : 0;
    cipherImpl->attr.keySize = keyImpl->keyMaterial.len;
    HcfResult res = InitCipherData(self, opMode, params, &(cipherImpl->cipherData));
    if (res != HCF_SUCCESS) {
        LOGE("Failed to initialize cipher data.");
        return res;
    }
    CipherData *data = cipherImpl->cipherData;
    HcfResult ret = HCF_ERR_CRYPTO_OPERATION;
    if (!SetCipherAttribute(cipherImpl, keyImpl, enc, params)) {
        LOGE("Set cipher attribute failed!");
        goto clearup;
    }
    if (OpensslEvpCipherCtxSetPadding(data->ctx, GetPaddingMode(cipherImpl)) != HCF_OPENSSL_SUCCESS) {
        HcfPrintOpensslError();
        LOGE("Set padding failed.");
        goto clearup;
    }
    cipherImpl->initFlag = INITIALIZED;
    return HCF_SUCCESS;
clearup:
    FreeCipherData(&(cipherImpl->cipherData));
    return ret;
}

static HcfResult AllocateOutput(HcfBlob* input, HcfBlob* output, bool *isUpdateInput)
{
    uint32_t outLen = SM4_BLOCK_SIZE + SM4_BLOCK_SIZE;
    if (HcfIsBlobValid(input)) {
        if (outLen > UINT32_MAX - input->len) {
            LOGE("Input length overflow.");
            return HCF_ERR_PARAMETER_CHECK_FAILED;
        }
        outLen += input->len;
        *isUpdateInput = true;
    }
    output->data = (uint8_t*)HcfMalloc(outLen, 0);
    if (output->data == NULL) {
        LOGE("Malloc output failed.");
        return HCF_ERR_MALLOC;
    }
    output->len = outLen;
    return HCF_SUCCESS;
}

static HcfResult CommonUpdate(CipherData *data, HcfBlob *input, HcfBlob *output)
{
    int32_t ret = OpensslEvpCipherUpdate(data->ctx, output->data, (int *)&output->len,
        input->data, input->len);
    if (ret != HCF_OPENSSL_SUCCESS) {
        HcfPrintOpensslError();
        LOGE("cipher update failed!");
        return HCF_ERR_CRYPTO_OPERATION;
    }
    return HCF_SUCCESS;
}

static HcfResult AeadUpdate(CipherData *data, HcfAlgParaValue mode, HcfBlob *input, HcfBlob *output)
{
    int32_t ret = OpensslEvpCipherUpdate(data->ctx, NULL, (int *)&output->len, data->aad, data->aadLen);
    if (ret != HCF_OPENSSL_SUCCESS) {
        HcfPrintOpensslError();
        LOGE("aad cipher update failed!");
        return HCF_ERR_CRYPTO_OPERATION;
    }
    ret = OpensslEvpCipherUpdate(data->ctx, output->data, (int *)&output->len, input->data, input->len);
    if (ret != HCF_OPENSSL_SUCCESS) {
        HcfPrintOpensslError();
        LOGE("gcm cipher update failed!");
        return HCF_ERR_CRYPTO_OPERATION;
    }
    return HCF_SUCCESS;
}

static HcfResult EngineUpdate(HcfCipherGeneratorSpi *self, HcfBlob *input, HcfBlob *output)
{
    if ((self == NULL) || (input == NULL) || (output == NULL)) {
        LOGE("Invalid input parameter!");
        return HCF_INVALID_PARAMS;
    }
    if (!HcfIsClassMatch((HcfObjectBase *)self, self->base.getClass())) {
        LOGE("Class is not match.");
        return HCF_INVALID_PARAMS;
    }

    HcfCipherSm4GeneratorSpiOpensslImpl *cipherImpl = (HcfCipherSm4GeneratorSpiOpensslImpl *)self;
    if (cipherImpl->initFlag != INITIALIZED) {
        LOGW("Cipher instance may not have been initialized, "
            "ensure init interface of Cipher instance is executed completely!");
    }

    CipherData *data = cipherImpl->cipherData;
    if (data == NULL) {
        LOGE("The data of Cipher instance is NULL, "
            "please check if init interface of Cipher instance is executed completely!");
        return HCF_INVALID_PARAMS;
    }
    bool isUpdateInput = false;
    HcfResult ret = AllocateOutput(input, output, &isUpdateInput);
    if (ret != HCF_SUCCESS) {
        LOGE("Failed to allocate output buffer.");
        return ret;
    }

    if (!data->aead) {
        ret = CommonUpdate(data, input, output);
    } else {
        ret = AeadUpdate(data, cipherImpl->attr.mode, input, output);
    }
    if (ret != HCF_SUCCESS) {
        HcfBlobDataClearAndFree(output);
        FreeCipherData(&(cipherImpl->cipherData));
        return ret;
    }
    if (cipherImpl->attr.mode == HCF_ALG_MODE_GCM && data->isNewCcmAead) {
        data->updateLen = input->len;
    }
    data->aead = false;
    FreeRedundantOutput(output);
    return ret;
}

static HcfResult AllocateGcmOutput(CipherData *data, HcfBlob *input, HcfBlob *output, bool *isUpdateInput)
{
    uint32_t outLen = 0;
    if (HcfIsBlobValid(input)) {
        outLen += input->len;
        *isUpdateInput = true;
    }
    uint32_t authTagLen = (data->enc == ENCRYPT_MODE) ? GCM_TAG_SIZE : 0;
    outLen += data->updateLen + authTagLen + SM4_BLOCK_SIZE;
    if (outLen == 0) {
        LOGE("output size is invalid!");
        return HCF_INVALID_PARAMS;
    }
    output->data = (uint8_t *)HcfMalloc(outLen, 0);
    if (output->data == NULL) {
        LOGE("malloc output failed!");
        return HCF_ERR_MALLOC;
    }
    output->len = outLen;
    return HCF_SUCCESS;
}

static HcfResult GcmDecryptDoFinal(CipherData *data, HcfBlob *input, HcfBlob *output, uint32_t len)
{
    if (data->tag == NULL) {
        LOGE("gcm decrypt has not AuthTag!");
        return HCF_INVALID_PARAMS;
    }
    int32_t ret = OpensslEvpCipherCtxCtrl(data->ctx, EVP_CTRL_AEAD_SET_TAG, data->tagLen, (void *)data->tag);
    if (ret != HCF_OPENSSL_SUCCESS) {
        HcfPrintOpensslError();
        LOGE("gcm decrypt set AuthTag failed!");
        return HCF_ERR_CRYPTO_OPERATION;
    }
    ret = OpensslEvpCipherFinalEx(data->ctx, output->data + len, (int *)&output->len);
    if (ret != HCF_OPENSSL_SUCCESS) {
        HcfPrintOpensslError();
        LOGE("EVP_CipherFinal_ex failed!");
        return HCF_ERR_CRYPTO_OPERATION;
    }
    output->len = output->len + len;
    return HCF_SUCCESS;
}

static HcfResult GcmEncryptDoFinal(CipherData *data, HcfBlob *input, HcfBlob *output, uint32_t len)
{
    int32_t ret = OpensslEvpCipherFinalEx(data->ctx, output->data + len, (int *)&output->len);
    if (ret != HCF_OPENSSL_SUCCESS) {
        HcfPrintOpensslError();
        LOGE("EVP_CipherFinal_ex failed!");
        return HCF_ERR_CRYPTO_OPERATION;
    }
    output->len += len;
    ret = OpensslEvpCipherCtxCtrl(data->ctx, EVP_CTRL_AEAD_GET_TAG, data->tagLen,
        output->data + output->len);
    if (ret != HCF_OPENSSL_SUCCESS) {
        HcfPrintOpensslError();
        LOGE("get AuthTag failed!");
        return HCF_ERR_CRYPTO_OPERATION;
    }
    output->len += data->tagLen;
    return HCF_SUCCESS;
}

static HcfResult PrepareGcmAeadDecryptInput(CipherData *data, HcfBlob *input, bool isUpdateInput, HcfBlob *cipherInput,
    HcfBlob **updateInput)
{
    if (data->enc != DECRYPT_MODE || !data->isNewCcmAead || !isUpdateInput) {
        return HCF_SUCCESS;
    }
    if (input->len < data->tagLen) {
        LOGE("gcm aead decrypt input len invalid!");
        return HCF_INVALID_PARAMS;
    }
    uint32_t cipherLen = input->len - data->tagLen;
    if (data->tag == NULL) {
        data->tag = (uint8_t *)HcfMalloc(data->tagLen, 0);
        if (data->tag == NULL) {
            LOGE("malloc tag failed!");
            return HCF_ERR_MALLOC;
        }
    }
    (void)memcpy_s(data->tag, data->tagLen, input->data + cipherLen, data->tagLen);
    cipherInput->data = input->data;
    cipherInput->len = cipherLen;
    *updateInput = cipherInput;
    return HCF_SUCCESS;
}

/* New AeadParamsSpec: AAD is supplied at most once per operation, before payload updates. */
static HcfResult Sm4GcmNewAeadFeedAadIfPending(CipherData *data)
{
    if (!data->aead || data->aad == NULL || data->aadLen == 0) {
        return HCF_SUCCESS;
    }
    int32_t tmpLen = 0;
    int32_t ret = OpensslEvpCipherUpdate(data->ctx, NULL, &tmpLen, data->aad, data->aadLen);
    if (ret != HCF_OPENSSL_SUCCESS) {
        HcfPrintOpensslError();
        LOGE("aad cipher update failed!");
        return HCF_ERR_CRYPTO_OPERATION;
    }
    return HCF_SUCCESS;
}

static HcfResult GcmDoFinal(CipherData *data, HcfBlob *input, HcfBlob *output)
{
    uint32_t len = 0;
    bool isUpdateInput = false;
    HcfBlob *updateInput = input;
    HcfBlob cipherInput = {0};
    HcfResult res = AllocateGcmOutput(data, input, output, &isUpdateInput);
    if (res != HCF_SUCCESS) {
        LOGE("Failed to allocate GCM output buffer.");
        return res;
    }
    res = PrepareGcmAeadDecryptInput(data, input, isUpdateInput, &cipherInput, &updateInput);
    if (res != HCF_SUCCESS) {
        LOGE("Failed to prepare GCM AEAD decrypt input.");
        return res;
    }

    if (data->isNewCcmAead) {
        res = Sm4GcmNewAeadFeedAadIfPending(data);
        if (res != HCF_SUCCESS) {
            return res;
        }
        data->aead = false;
    }

    if (isUpdateInput) {
        if (data->isNewCcmAead) {
            res = CommonUpdate(data, updateInput, output);
        } else {
            res = (data->aad != NULL && data->aadLen != 0) ? AeadUpdate(data, HCF_ALG_MODE_GCM, updateInput, output)
                                  : CommonUpdate(data, updateInput, output);
        }
        if (res != HCF_SUCCESS) {
            LOGE("gcm update failed!");
            return res;
        }
        len = output->len;
    }
    if (data->enc == ENCRYPT_MODE) {
        return GcmEncryptDoFinal(data, input, output, len);
    } else if (data->enc == DECRYPT_MODE) {
        return GcmDecryptDoFinal(data, input, output, len);
    } else {
        LOGE("invalid encrypt mode in GCM!");
        return HCF_INVALID_PARAMS;
    }
}

static HcfResult CommonDoFinal(CipherData *data, HcfBlob *input, HcfBlob *output)
{
    int32_t ret;
    uint32_t len = 0;
    bool isUpdateInput = false;
    HcfResult res = AllocateOutput(input, output, &isUpdateInput);
    if (res != HCF_SUCCESS) {
        LOGE("Failed to allocate output buffer.");
        return res;
    }
    if (isUpdateInput) {
        ret = OpensslEvpCipherUpdate(data->ctx, output->data, (int*)&output->len,
            input->data, input->len);
        if (ret != HCF_OPENSSL_SUCCESS) {
            HcfPrintOpensslError();
            LOGE("EVP_CipherUpdate failed!");
            return HCF_ERR_CRYPTO_OPERATION;
        }
        len += output->len;
    }
    ret = OpensslEvpCipherFinalEx(data->ctx, output->data + len, (int *)&output->len);
    if (ret != HCF_OPENSSL_SUCCESS) {
        HcfPrintOpensslError();
        LOGE("EVP_CipherFinal_ex failed!");
        return HCF_ERR_CRYPTO_OPERATION;
    }
    output->len += len;
    return HCF_SUCCESS;
}

static HcfResult EngineDoFinal(HcfCipherGeneratorSpi* self, HcfBlob* input, HcfBlob* output)
{
    if ((self == NULL) || (output == NULL)) { /* input maybe is null */
        LOGE("Invalid input parameter.");
        return HCF_INVALID_PARAMS;
    }
    if (!HcfIsClassMatch((HcfObjectBase*)self, self->base.getClass())) {
        LOGE("Class is not match.");
        return HCF_INVALID_PARAMS;
    }

    HcfResult ret = HCF_ERR_CRYPTO_OPERATION;
    HcfCipherSm4GeneratorSpiOpensslImpl *cipherImpl = (HcfCipherSm4GeneratorSpiOpensslImpl *)self;
    if (cipherImpl->initFlag != INITIALIZED) {
        LOGW("Cipher instance may not have been initialized, "
            "ensure init interface of Cipher instance is executed completely!");
    }

    CipherData *data = cipherImpl->cipherData;
    if (data == NULL) {
        LOGE("The data of Cipher instance is NULL, "
            "please check if init interface of Cipher instance is executed completely!");
        return HCF_INVALID_PARAMS;
    }

    HcfAlgParaValue mode = cipherImpl->attr.mode;
    if (mode == HCF_ALG_MODE_GCM) {
        ret = GcmDoFinal(data, input, output);
    } else { /* only ECB CBC CTR CFB OFB support */
        ret = CommonDoFinal(data, input, output);
    }

    FreeCipherData(&(cipherImpl->cipherData));
    if (ret != HCF_SUCCESS) {
        HcfBlobDataClearAndFree(output);
    }
    FreeRedundantOutput(output);
    return ret;
}

static void EngineSm4GeneratorDestroy(HcfObjectBase *self)
{
    if (self == NULL) {
        return;
    }
    if (!HcfIsClassMatch(self, self->getClass())) {
        LOGE("Class is not match.");
        return;
    }

    HcfCipherSm4GeneratorSpiOpensslImpl *impl = (HcfCipherSm4GeneratorSpiOpensslImpl *)self;
    FreeCipherData(&(impl->cipherData));
    HcfFree(impl);
}

static HcfResult GetSm4CipherSpecString(HcfCipherGeneratorSpi *self, CipherSpecItem item, char **returnString)
{
    (void)self;
    (void)item;
    (void)returnString;
    return HCF_NOT_SUPPORT;
}

static HcfResult GetSm4CipherSpecUint8Array(HcfCipherGeneratorSpi *self, CipherSpecItem item, HcfBlob *returnUint8Array)
{
    (void)self;
    (void)item;
    (void)returnUint8Array;
    return HCF_NOT_SUPPORT;
}

static HcfResult SetSm4CipherSpecUint8Array(HcfCipherGeneratorSpi *self, CipherSpecItem item, HcfBlob blob)
{
    (void)self;
    (void)item;
    (void)blob;
    return HCF_NOT_SUPPORT;
}

HcfResult HcfCipherSm4GeneratorSpiCreate(CipherAttr *attr, HcfCipherGeneratorSpi **generator)
{
    if (attr == NULL || generator == NULL) {
        LOGE("Invalid input parameter.");
        return HCF_INVALID_PARAMS;
    }
    HcfCipherSm4GeneratorSpiOpensslImpl *returnImpl = (HcfCipherSm4GeneratorSpiOpensslImpl *)HcfMalloc(
        sizeof(HcfCipherSm4GeneratorSpiOpensslImpl), 0);
    if (returnImpl == NULL) {
        LOGE("Failed to allocate returnImpl memroy!");
        return HCF_ERR_MALLOC;
    }
    (void)memcpy_s(&returnImpl->attr, sizeof(CipherAttr), attr, sizeof(CipherAttr));
    returnImpl->base.init = EngineCipherInit;
    returnImpl->base.update = EngineUpdate;
    returnImpl->base.doFinal = EngineDoFinal;
    returnImpl->base.getCipherSpecString = GetSm4CipherSpecString;
    returnImpl->base.getCipherSpecUint8Array = GetSm4CipherSpecUint8Array;
    returnImpl->base.setCipherSpecUint8Array = SetSm4CipherSpecUint8Array;
    returnImpl->base.base.destroy = EngineSm4GeneratorDestroy;
    returnImpl->base.base.getClass = GetSm4GeneratorClass;

    *generator = (HcfCipherGeneratorSpi *)returnImpl;
    return HCF_SUCCESS;
}
