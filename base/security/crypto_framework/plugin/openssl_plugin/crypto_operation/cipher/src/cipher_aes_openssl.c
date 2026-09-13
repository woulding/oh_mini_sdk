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

#define CCM_AAD_MAX_LEN 2048
#define GCM_IV_MIN_LEN 1
#define GCM_IV_MAX_LEN 128
#define CCM_IV_MIN_LEN 7
#define CCM_IV_MAX_LEN 13
#define CBC_CTR_OFB_CFB_IV_LEN 16
#define AES_WRAP_IV_LEN 8
#define AES_BLOCK_SIZE 16
#define GCM_TAG_LEN_4 4
#define GCM_TAG_LEN_8 8
#define GCM_TAG_LEN_12 12
#define GCM_TAG_SIZE 16
#define CCM_TAG_SIZE 12
#define CCM_TAG_LEN_4 4
#define CCM_TAG_LEN_16 16
#define EVEN_NUM 2
#define AES_SIZE_128 16
#define AES_SIZE_192 24
#define AES_SIZE_256 32
#define XTS_NONCE_LEN 16
#define XTS_KEY_LEN_256 32
#define XTS_KEY_LEN_512 64

typedef struct {
    HcfCipherGeneratorSpi base;
    CipherAttr attr;
    CipherData *cipherData;
    CryptoStatus initFlag;
} HcfCipherAesGeneratorSpiOpensslImpl;

static const char *GetAesGeneratorClass(void)
{
    return OPENSSL_AES_CIPHER_CLASS;
}

static const EVP_CIPHER *CipherEcbType(SymKeyImpl *symKey)
{
    if (symKey->keyMaterial.len == AES_SIZE_192) {
        return OpensslEvpAes192Ecb();
    } else if (symKey->keyMaterial.len == AES_SIZE_256) {
        return OpensslEvpAes256Ecb();
    } else {
        return OpensslEvpAes128Ecb();
    }
}

static const EVP_CIPHER *CipherCbcType(SymKeyImpl *symKey)
{
    if (symKey->keyMaterial.len == AES_SIZE_192) {
        return OpensslEvpAes192Cbc();
    } else if (symKey->keyMaterial.len == AES_SIZE_256) {
        return OpensslEvpAes256Cbc();
    } else {
        return OpensslEvpAes128Cbc();
    }
}

static const EVP_CIPHER *CipherCtrType(SymKeyImpl *symKey)
{
    if (symKey->keyMaterial.len == AES_SIZE_192) {
        return OpensslEvpAes192Ctr();
    } else if (symKey->keyMaterial.len == AES_SIZE_256) {
        return OpensslEvpAes256Ctr();
    } else {
        return OpensslEvpAes128Ctr();
    }
}

static const EVP_CIPHER *CipherOfbType(SymKeyImpl *symKey)
{
    if (symKey->keyMaterial.len == AES_SIZE_192) {
        return OpensslEvpAes192Ofb();
    } else if (symKey->keyMaterial.len == AES_SIZE_256) {
        return OpensslEvpAes256Ofb();
    } else {
        return OpensslEvpAes128Ofb();
    }
}

static const EVP_CIPHER *CipherCfbType(SymKeyImpl *symKey)
{
    if (symKey->keyMaterial.len == AES_SIZE_192) {
        return OpensslEvpAes192Cfb();
    } else if (symKey->keyMaterial.len == AES_SIZE_256) {
        return OpensslEvpAes256Cfb();
    } else {
        return OpensslEvpAes128Cfb();
    }
}

static const EVP_CIPHER *CipherCfb1Type(SymKeyImpl *symKey)
{
    if (symKey->keyMaterial.len == AES_SIZE_192) {
        return OpensslEvpAes192Cfb1();
    } else if (symKey->keyMaterial.len == AES_SIZE_256) {
        return OpensslEvpAes256Cfb1();
    } else {
        return OpensslEvpAes128Cfb1();
    }
}

static const EVP_CIPHER *CipherCfb128Type(SymKeyImpl *symKey)
{
    if (symKey->keyMaterial.len == AES_SIZE_192) {
        return OpensslEvpAes192Cfb128();
    } else if (symKey->keyMaterial.len == AES_SIZE_256) {
        return OpensslEvpAes256Cfb128();
    } else {
        return OpensslEvpAes128Cfb128();
    }
}

static const EVP_CIPHER *CipherCfb8Type(SymKeyImpl *symKey)
{
    if (symKey->keyMaterial.len == AES_SIZE_192) {
        return OpensslEvpAes192Cfb8();
    } else if (symKey->keyMaterial.len == AES_SIZE_256) {
        return OpensslEvpAes256Cfb8();
    } else {
        return OpensslEvpAes128Cfb8();
    }
}


static const EVP_CIPHER *CipherCcmType(SymKeyImpl *symKey)
{
    if (symKey->keyMaterial.len == AES_SIZE_192) {
        return OpensslEvpAes192Ccm();
    } else if (symKey->keyMaterial.len == AES_SIZE_256) {
        return OpensslEvpAes256Ccm();
    } else {
        return OpensslEvpAes128Ccm();
    }
}

static const EVP_CIPHER *CipherGcmType(SymKeyImpl *symKey)
{
    if (symKey->keyMaterial.len == AES_SIZE_192) {
        return OpensslEvpAes192Gcm();
    } else if (symKey->keyMaterial.len == AES_SIZE_256) {
        return OpensslEvpAes256Gcm();
    } else {
        return OpensslEvpAes128Gcm();
    }
}

static const EVP_CIPHER *CipherWrapType(SymKeyImpl *symKey)
{
    if (symKey->keyMaterial.len == AES_SIZE_192) {
        return OpensslEvpAes192Wrap();
    } else if (symKey->keyMaterial.len == AES_SIZE_256) {
        return OpensslEvpAes256Wrap();
    } else {
        return OpensslEvpAes128Wrap();
    }
}

static const EVP_CIPHER *CipherXtsType(SymKeyImpl *symKey)
{
    if (symKey->keyMaterial.len == XTS_KEY_LEN_512) {
        return OpensslEvpAes256Xts();
    } else if (symKey->keyMaterial.len == XTS_KEY_LEN_256) {
        return OpensslEvpAes128Xts();
    } else {
        LOGE("invalid key length for AES-XTS!");
        return NULL;
    }
}

static const EVP_CIPHER *DefaultCipherType(SymKeyImpl *symKey)
{
    return CipherEcbType(symKey);
}

static const EVP_CIPHER *GetCipherType(HcfCipherAesGeneratorSpiOpensslImpl *impl, SymKeyImpl *symKey)
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
        case HCF_ALG_MODE_CFB1:
            return CipherCfb1Type(symKey);
        case HCF_ALG_MODE_CFB8:
            return CipherCfb8Type(symKey);
        case HCF_ALG_MODE_CFB128:
            return CipherCfb128Type(symKey);
        case HCF_ALG_MODE_CCM:
            return CipherCcmType(symKey);
        case HCF_ALG_MODE_GCM:
            return CipherGcmType(symKey);
        case HCF_ALG_MODE_XTS:
            return CipherXtsType(symKey);
        case HCF_ALG_MODE_WRAP:
            return CipherWrapType(symKey);
        default:
            break;
    }
    return DefaultCipherType(symKey);
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

static bool IsCcmParamsValid(HcfCcmParamsSpec *params)
{
    if (params == NULL) {
        LOGE("params is null!");
        return false;
    }
    if ((params->aad.data == NULL) || (params->aad.len == 0) || (params->aad.len > CCM_AAD_MAX_LEN)) {
        LOGE("aad is invalid!");
        return false;
    }
    if ((params->iv.data == NULL) || (params->iv.len < CCM_IV_MIN_LEN) || (params->iv.len > CCM_IV_MAX_LEN)) {
        LOGE("iv is invalid!");
        return false;
    }
    if ((params->tag.data == NULL) || (params->tag.len == 0)) {
        LOGE("tag is invalid!");
        return false;
    }
    return true;
}

static bool IsCcmNewParamsValid(HcfAeadParamsSpec *params)
{
    if (params == NULL) {
        LOGE("params is null!");
        return false;
    }
    if ((params->nonce.data == NULL) || (params->nonce.len < CCM_IV_MIN_LEN) || (params->nonce.len > CCM_IV_MAX_LEN)) {
        LOGE("nonce is invalid!");
        return false;
    }
    int32_t tagLen = (params->tagLen == 0) ? CCM_TAG_SIZE : params->tagLen;
    if (tagLen < CCM_TAG_LEN_4 || tagLen > CCM_TAG_LEN_16 || (tagLen % EVEN_NUM != 0)) {
        LOGE("tag len is invalid!");
        return false;
    }
    return true;
}

static bool IsGcmNewParamsValid(HcfAeadParamsSpec *params)
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

static HcfResult IsAesWrapIvParamsValid(HcfIvParamsSpec *params)
{
    if (params == NULL) {
        LOGI("Aes wrap iv can be null!");
        return HCF_SUCCESS;
    }
    if ((params->iv.data != NULL) && (params->iv.len != AES_WRAP_IV_LEN)) {
        LOGE("iv is invalid!");
        return HCF_ERR_PARAMETER_CHECK_FAILED;
    }
    return HCF_SUCCESS;
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

static HcfResult InitNewCcmFromAeadParams(enum HcfCryptoMode opMode, HcfAeadParamsSpec *params, CipherData *data)
{
    if (!IsCcmNewParamsValid(params)) {
        LOGE("ccm params is invalid!");
        return HCF_ERR_PARAMETER_CHECK_FAILED;
    }
    if (params->aad.data != NULL) {
        data->aad = (uint8_t *)HcfMalloc(params->aad.len, 0);
        if (data->aad == NULL) {
            LOGE("aad malloc failed!");
            return HCF_ERR_MALLOC;
        }
        (void)memcpy_s(data->aad, params->aad.len, params->aad.data, params->aad.len);
        data->aadLen = params->aad.len;
    } else {
        data->aad = NULL;
        data->aadLen = 0;
    }
    data->aead = true;
    data->tagLen = (params->tagLen == 0) ? CCM_TAG_SIZE : (uint32_t)params->tagLen;
    data->isNewCcmAead = true;
    return HCF_SUCCESS;
}

static HcfResult InitNewGcmFromAeadParams(enum HcfCryptoMode opMode, HcfAeadParamsSpec *params, CipherData *data)
{
    (void)opMode;
    if (!IsGcmNewParamsValid(params)) {
        LOGE("gcm params is invalid!");
        return HCF_ERR_PARAMETER_CHECK_FAILED;
    }
    if (params->aad.data != NULL && params->aad.len != 0) {
        data->aad = (uint8_t *)HcfMalloc(params->aad.len, 0);
        if (data->aad == NULL) {
            LOGE("aad malloc failed!");
            return HCF_ERR_MALLOC;
        }
        (void)memcpy_s(data->aad, params->aad.len, params->aad.data, params->aad.len);
        data->aadLen = params->aad.len;
    } else {
        data->aad = NULL;
        data->aadLen = 0;
    }
    data->aead = true;
    data->tagLen = (params->tagLen != 0) ? (uint32_t)params->tagLen : GCM_TAG_SIZE;
    data->isNewCcmAead = true;
    return HCF_SUCCESS;
}

static HcfResult InitAadAndTagFromCcmParams(enum HcfCryptoMode opMode, HcfCcmParamsSpec *params, CipherData *data)
{
    if (!IsCcmParamsValid(params)) {
        LOGE("ccm params is invalid!");
        return HCF_INVALID_PARAMS;
    }

    data->aad = (uint8_t *)HcfMalloc(params->aad.len, 0);
    if (data->aad == NULL) {
        LOGE("aad malloc failed!");
        return HCF_ERR_MALLOC;
    }
    (void)memcpy_s(data->aad, params->aad.len, params->aad.data, params->aad.len);
    data->aadLen = params->aad.len;
    data->aead = true;

    data->tagLen = params->tag.len;
    data->isNewCcmAead = false;
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

static HcfResult InitCipherDataByMode(HcfCipherAesGeneratorSpiOpensslImpl *cipherImpl,
    enum HcfCryptoMode opMode, HcfParamsSpec *params, CipherData *cipherData)
{
    HcfResult ret = HCF_SUCCESS;
    HcfAlgParaValue mode = cipherImpl->attr.mode;

    switch (mode) {
        case HCF_ALG_MODE_CBC:
        case HCF_ALG_MODE_CTR:
        case HCF_ALG_MODE_OFB:
        case HCF_ALG_MODE_CFB:
        case HCF_ALG_MODE_CFB1:
        case HCF_ALG_MODE_CFB8:
        case HCF_ALG_MODE_CFB128:
        case HCF_ALG_MODE_XTS: {
            ret = IsIvParamsValid((HcfIvParamsSpec *)params);
            break;
        }
        case HCF_ALG_MODE_WRAP:
            ret = IsAesWrapIvParamsValid((HcfIvParamsSpec *)params);
            break;
        case HCF_ALG_MODE_CCM: {
            const char *typeName = (params == NULL || params->getType == NULL) ? NULL : params->getType();
            if ((typeName != NULL) && (strcmp(typeName, "AeadParamsSpec") == 0)) {
                ret = InitNewCcmFromAeadParams(opMode, (HcfAeadParamsSpec *)params, cipherData);
            } else {
                ret = InitAadAndTagFromCcmParams(opMode, (HcfCcmParamsSpec *)params, cipherData);
            }
            break;
        }
        case HCF_ALG_MODE_GCM:
            if ((params != NULL) && (params->getType != NULL) && (strcmp(params->getType(), "AeadParamsSpec") == 0)) {
                ret = InitNewGcmFromAeadParams(opMode, (HcfAeadParamsSpec *)params, cipherData);
            } else {
                ret = InitAadAndTagFromGcmParams(opMode, (HcfGcmParamsSpec *)params, cipherData);
            }
            break;
        default:
            break;
    }
    return ret;
}

static HcfResult InitCipherData(HcfCipherGeneratorSpi *self, enum HcfCryptoMode opMode,
    HcfParamsSpec *params, CipherData **cipherData)
{
    HcfResult ret = HCF_ERR_MALLOC;
    *cipherData = (CipherData *)HcfMalloc(sizeof(CipherData), 0);
    if (*cipherData == NULL) {
        LOGE("malloc is failed!");
        return ret;
    }
    HcfCipherAesGeneratorSpiOpensslImpl *cipherImpl = (HcfCipherAesGeneratorSpiOpensslImpl *)self;

    (*cipherData)->enc = opMode;
    (*cipherData)->ctx = OpensslEvpCipherCtxNew();
    if ((*cipherData)->ctx == NULL) {
        HcfPrintOpensslError();
        LOGE(" Failed to allocate ctx memory!");
        goto clearup;
    }

    ret = InitCipherDataByMode(cipherImpl, opMode, params, *cipherData);
    if (ret != HCF_SUCCESS) {
        LOGE("gcm or ccm or iv or xts init failed!");
        goto clearup;
    }
    return ret;
clearup:
    FreeCipherData(cipherData);
    return ret;
}

static bool SetCipherAttribute(HcfCipherAesGeneratorSpiOpensslImpl *cipherImpl, SymKeyImpl *keyImpl,
    int enc, HcfParamsSpec *params)
{
    CipherData *data = cipherImpl->cipherData;
    HcfAlgParaValue mode = cipherImpl->attr.mode;
    if (mode != HCF_ALG_MODE_GCM && !data->isNewCcmAead) {
        if (OpensslEvpCipherInit(data->ctx, GetCipherType(cipherImpl, keyImpl), keyImpl->keyMaterial.data,
            GetIv(params), enc) != HCF_OPENSSL_SUCCESS) {
            HcfPrintOpensslError();
            LOGE("EVP_CipherInit failed!");
            return false;
        }
        return true;
    }
    if (OpensslEvpCipherInit(data->ctx, GetCipherType(cipherImpl, keyImpl),
        NULL, NULL, enc) != HCF_OPENSSL_SUCCESS) {
        HcfPrintOpensslError();
        LOGE("EVP_CipherInit failed!");
        return false;
    }
    if (OpensslEvpCipherCtxCtrl(data->ctx, EVP_CTRL_AEAD_SET_IVLEN,
        GetIvLen(params), NULL) != HCF_OPENSSL_SUCCESS) {
        HcfPrintOpensslError();
        LOGE("EVP_Cipher set iv len failed!");
        return false;
    }
    if (mode == HCF_ALG_MODE_CCM && data->isNewCcmAead && data->tagLen != 0) {
        if (OpensslEvpCipherCtxCtrl(data->ctx, EVP_CTRL_AEAD_SET_TAG, data->tagLen, NULL) != HCF_OPENSSL_SUCCESS) {
            HcfPrintOpensslError();
            LOGE("ccm aead set tag length failed!");
            return false;
        }
    }
    if (OpensslEvpCipherInit(data->ctx, NULL, keyImpl->keyMaterial.data,
        GetIv(params), enc) != HCF_OPENSSL_SUCCESS) {
        HcfPrintOpensslError();
        LOGE("EVP_CipherInit failed!");
        return false;
    }
    return true;
}

static HcfResult ValidateXtsKeyLength(HcfCipherAesGeneratorSpiOpensslImpl *cipherImpl, SymKeyImpl *keyImpl)
{
    if (cipherImpl->attr.mode != HCF_ALG_MODE_XTS) {
        return HCF_SUCCESS;
    }
    if (keyImpl->keyMaterial.len == XTS_KEY_LEN_256 || keyImpl->keyMaterial.len == XTS_KEY_LEN_512) {
        return HCF_SUCCESS;
    }
    LOGE("invalid key length for AES-XTS, only support AES128 and AES256.");
    return HCF_ERR_PARAMETER_CHECK_FAILED;
}

static HcfResult ConfigureCipherCtx(HcfCipherAesGeneratorSpiOpensslImpl *cipherImpl, SymKeyImpl *keyImpl,
    int enc, enum HcfCryptoMode opMode, HcfParamsSpec *params)
{
    CipherData *data = cipherImpl->cipherData;
    HcfResult ret = HCF_ERR_CRYPTO_OPERATION;

    if (!SetCipherAttribute(cipherImpl, keyImpl, enc, params)) {
        LOGE("Set cipher attribute failed!");
        FreeCipherData(&(cipherImpl->cipherData));
        return ret;
    }

    int32_t padding = (cipherImpl->attr.paddingMode == HCF_ALG_NOPADDING) ? 0 : EVP_PADDING_PKCS7;
    if (OpensslEvpCipherCtxSetPadding(data->ctx, padding) != HCF_OPENSSL_SUCCESS) {
        HcfPrintOpensslError();
        LOGE("set padding failed!");
        FreeCipherData(&(cipherImpl->cipherData));
        return ret;
    }

    /* CCM (AeadParamsSpec) encrypt tag length already set in SetCipherAttribute before key/iv Init */
    if (opMode == ENCRYPT_MODE || cipherImpl->attr.mode != HCF_ALG_MODE_CCM) {
        return HCF_SUCCESS;
    }

    /* CCM with HcfAeadParamsSpec: tag is not set in init, set in update */
    if (data->isNewCcmAead) {
        return HCF_SUCCESS;
    }

    /* ccm decrypt need set tag */
    if (OpensslEvpCipherCtxCtrl(data->ctx, EVP_CTRL_AEAD_SET_TAG, GetCcmTagLen(params),
        GetCcmTag(params)) != HCF_OPENSSL_SUCCESS) {
        HcfPrintOpensslError();
        LOGE("set AuthTag failed!");
        FreeCipherData(&(cipherImpl->cipherData));
        return ret;
    }

    return HCF_SUCCESS;
}

static HcfResult EngineCipherInit(HcfCipherGeneratorSpi *self, enum HcfCryptoMode opMode,
    HcfKey *key, HcfParamsSpec *params)
{
    // params spec may be null, do not check
    if ((self == NULL) || (key == NULL)) {
        LOGE("Invalid input parameter!");
        return HCF_INVALID_PARAMS;
    }
    if ((!HcfIsClassMatch((const HcfObjectBase *)self, GetAesGeneratorClass())) ||
        (!HcfIsClassMatch((const HcfObjectBase *)key, OPENSSL_SYM_KEY_CLASS))) {
        return HCF_INVALID_PARAMS;
    }

    HcfCipherAesGeneratorSpiOpensslImpl *cipherImpl = (HcfCipherAesGeneratorSpiOpensslImpl *)self;
    SymKeyImpl *keyImpl = (SymKeyImpl *)key;
    int enc = (opMode == ENCRYPT_MODE) ? 1 : 0;

    if (cipherImpl->attr.algo == HCF_ALG_AES_WRAP) {
        LOGI("Avoid aes-wrap mode is overridden.");
        cipherImpl->attr.mode = HCF_ALG_MODE_WRAP;
    }

    HcfResult ret = ValidateXtsKeyLength(cipherImpl, keyImpl);
    if (ret != HCF_SUCCESS) {
        return ret;
    }

    if (InitCipherData(self, opMode, params, &(cipherImpl->cipherData)) != HCF_SUCCESS) {
        LOGE("Failed to initialize cipher data.");
        return HCF_INVALID_PARAMS;
    }

    ret = ConfigureCipherCtx(cipherImpl, keyImpl, enc, opMode, params);
    if (ret == HCF_SUCCESS) {
        cipherImpl->initFlag = INITIALIZED;
    }
    return ret;
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
    if (mode == HCF_ALG_MODE_CCM) {
        if (OpensslEvpCipherUpdate(data->ctx, NULL, (int *)&output->len, NULL, input->len) != HCF_OPENSSL_SUCCESS) {
            HcfPrintOpensslError();
            LOGE("ccm cipher update failed!");
            return HCF_ERR_CRYPTO_OPERATION;
        }
    }

    int32_t ret = HCF_OPENSSL_SUCCESS;
    if (data->aad != NULL && data->aadLen != 0) {
        ret = OpensslEvpCipherUpdate(data->ctx, NULL, (int *)&output->len, data->aad, data->aadLen);
        if (ret != HCF_OPENSSL_SUCCESS) {
            HcfPrintOpensslError();
            LOGE("aad cipher update failed!");
            return HCF_ERR_CRYPTO_OPERATION;
        }
    }
    if (mode == HCF_ALG_MODE_CCM && data->enc == DECRYPT_MODE) {
        if (OpensslEvpCipherCtxCtrl(data->ctx, EVP_CTRL_AEAD_SET_TAG, data->tagLen, data->tag) !=
            HCF_OPENSSL_SUCCESS) {
            HcfPrintOpensslError();
            LOGE("ccm decrypt set AuthTag failed!");
            return HCF_ERR_CRYPTO_OPERATION;
        }
    }
    ret = OpensslEvpCipherUpdate(data->ctx, output->data, (int *)&output->len, input->data, input->len);
    if (ret != HCF_OPENSSL_SUCCESS) {
        HcfPrintOpensslError();
        LOGE("gcm or ccm cipher update failed!");
        return HCF_ERR_CRYPTO_OPERATION;
    }
    return HCF_SUCCESS;
}

static HcfResult AllocateOutput(HcfBlob *input, HcfBlob *output, bool *isUpdateInput)
{
    uint32_t outLen = AES_BLOCK_SIZE + AES_BLOCK_SIZE;
    if (HcfIsBlobValid(input)) {
        if (outLen > UINT32_MAX - input->len) {
            LOGE("Input length overflow.");
            return HCF_ERR_PARAMETER_CHECK_FAILED;
        }
        outLen += input->len;
        *isUpdateInput = true;
    }
    output->data = (uint8_t *)HcfMalloc(outLen, 0);
    if (output->data == NULL) {
        LOGE("malloc output failed!");
        return HCF_ERR_MALLOC;
    }
    output->len = outLen;
    return HCF_SUCCESS;
}

static HcfResult CheckAesWrapCipherName(const EVP_CIPHER *cipher)
{
    int nid = EVP_CIPHER_nid(cipher);
    if (nid == NID_undef) {
        LOGE("EVP_CIPHER_nid is undefined!");
        return HCF_ERR_CRYPTO_OPERATION;
    }
    const char *cipherName = OBJ_nid2sn(nid);
    if (cipherName == NULL) {
        LOGE("OBJ_nid2sn is null!");
        return HCF_ERR_CRYPTO_OPERATION;
    }
    if (strcmp(cipherName, "id-aes128-wrap") == 0 || strcmp(cipherName, "id-aes192-wrap") == 0 ||
        strcmp(cipherName, "id-aes256-wrap") == 0) {
        LOGE("Openssl don't support update in wrap mode!");
        return HCF_ERR_CRYPTO_OPERATION;
    }
    return HCF_SUCCESS;
}

static HcfResult EngineUpdateAead(HcfCipherAesGeneratorSpiOpensslImpl *cipherImpl, CipherData *data,
    HcfBlob *input, HcfBlob *output)
{
    bool isNewCcmAeadDecrypt = (cipherImpl->attr.mode == HCF_ALG_MODE_CCM && data->isNewCcmAead &&
        data->enc == DECRYPT_MODE);
    bool isNewGcmAeadDecrypt = (cipherImpl->attr.mode == HCF_ALG_MODE_GCM && data->isNewCcmAead &&
        data->enc == DECRYPT_MODE);
    if (!isNewCcmAeadDecrypt && !isNewGcmAeadDecrypt) {
        return AeadUpdate(data, cipherImpl->attr.mode, input, output);
    }

    if (isNewGcmAeadDecrypt && input->len < data->tagLen) {
        return AeadUpdate(data, cipherImpl->attr.mode, input, output);
    }

    if (input->len < data->tagLen) {
        LOGE("ccm aead decrypt input len invalid!");
        return HCF_ERR_PARAMETER_CHECK_FAILED;
    }

    uint32_t cipherLen = input->len - data->tagLen;
    if (OpensslEvpCipherCtxCtrl(data->ctx, EVP_CTRL_AEAD_SET_TAG, data->tagLen,
        (void *)input->data + cipherLen) != HCF_OPENSSL_SUCCESS) {
        HcfPrintOpensslError();
        LOGE("aead decrypt set AuthTag failed!");
        return HCF_ERR_CRYPTO_OPERATION;
    }

    HcfBlob cipherInput = {.data = input->data, .len = cipherLen};
    return AeadUpdate(data, cipherImpl->attr.mode, &cipherInput, output);
}

static HcfCipherAesGeneratorSpiOpensslImpl *GetAesCipherImplForUpdate(HcfCipherGeneratorSpi *self,
    HcfBlob *input, HcfBlob *output)
{
    if ((self == NULL) || (input == NULL) || (output == NULL)) {
        LOGE("Invalid input parameter!");
        return NULL;
    }
    if (!HcfIsClassMatch((const HcfObjectBase *)self, GetAesGeneratorClass())) {
        LOGE("Class is not match.");
        return NULL;
    }
    HcfCipherAesGeneratorSpiOpensslImpl *cipherImpl = (HcfCipherAesGeneratorSpiOpensslImpl *)self;
    if (cipherImpl->initFlag != INITIALIZED) {
        LOGW("Cipher instance may not have been initialized, "
            "ensure init interface of Cipher instance is executed completely!");
    }
    return cipherImpl;
}

static HcfResult EngineUpdate(HcfCipherGeneratorSpi *self, HcfBlob *input, HcfBlob *output)
{
    HcfCipherAesGeneratorSpiOpensslImpl *cipherImpl = GetAesCipherImplForUpdate(self, input, output);
    if (cipherImpl == NULL) {
        return HCF_INVALID_PARAMS;
    }

    CipherData *data = cipherImpl->cipherData;
    if (data == NULL) {
        LOGE("The data of Cipher instance is NULL, "
            "please check if init interface of Cipher instance is executed completely!");
        return HCF_INVALID_PARAMS;
    }

    const EVP_CIPHER *cipher = EVP_CIPHER_CTX_get0_cipher(data->ctx);
    if (cipher == NULL) {
        LOGE("The algorithm of Cipher instance is NULL, "
            "please check if init interface of Cipher instance is executed completely!");
        return HCF_ERR_CRYPTO_OPERATION;
    }
    HcfResult ret = CheckAesWrapCipherName(cipher);
    if (ret != HCF_SUCCESS) {
        LOGE("aes wrap not support update!");
        return ret;
    }
    bool isUpdateInput = false;
    ret = AllocateOutput(input, output, &isUpdateInput);
    if (ret != HCF_SUCCESS) {
        LOGE("Failed to allocate output buffer.");
        return ret;
    }

    if (!data->aead) {
        ret = CommonUpdate(data, input, output);
    } else {
        ret = EngineUpdateAead(cipherImpl, data, input, output);
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
        ret = OpensslEvpCipherUpdate(data->ctx, output->data, (int32_t *)&len, input->data, input->len);
        if (ret != HCF_OPENSSL_SUCCESS) {
            HcfPrintOpensslError();
            LOGE("EVP_CipherUpdate failed!");
            return HCF_ERR_CRYPTO_OPERATION;
        }
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

static HcfResult AllocateCcmOutput(CipherData *data, HcfBlob *input, HcfBlob *output, bool *isUpdateInput)
{
    uint32_t outLen = 0;
    if (HcfIsBlobValid(input)) {
        outLen += input->len;
        *isUpdateInput = true;
    }
    uint32_t authTagLen = (data->enc == ENCRYPT_MODE) ? data->tagLen : 0;
    outLen += authTagLen + AES_BLOCK_SIZE;
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

static HcfResult CcmDecryptDoFinal(HcfBlob *output, bool isUpdateInput)
{
    if (isUpdateInput) { /* DecryptFinal this does not occur in CCM mode */
        return HCF_SUCCESS;
    }
    if (output->data != NULL) {
        HcfBlobDataClearAndFree(output);
    }
    return HCF_SUCCESS;
}

static HcfResult CcmEncryptDoFinal(CipherData *data, HcfBlob *output, uint32_t len)
{
    int32_t ret = OpensslEvpCipherCtxCtrl(data->ctx, EVP_CTRL_AEAD_GET_TAG, data->tagLen, output->data + len);
    if (ret != HCF_OPENSSL_SUCCESS) {
        HcfPrintOpensslError();
        LOGE("get AuthTag failed!");
        return HCF_ERR_CRYPTO_OPERATION;
    }
    output->len = data->tagLen + len;
    return HCF_SUCCESS;
}

static HcfResult CcmDoFinal(CipherData *data, HcfBlob *input, HcfBlob *output)
{
    bool isUpdateInput = false;
    uint32_t len = 0;
    HcfResult res = AllocateCcmOutput(data, input, output, &isUpdateInput);
    if (res != HCF_SUCCESS) {
        LOGE("Failed to allocate CCM output buffer.");
        return res;
    }
    if (isUpdateInput) {
        HcfResult result = AeadUpdate(data, HCF_ALG_MODE_CCM, input, output);
        if (result != HCF_SUCCESS) {
            LOGE("Failed to update AEAD cipher data.");
            return result;
        }
        len = output->len;
    }
    if (data->enc == ENCRYPT_MODE) {
        return CcmEncryptDoFinal(data, output, len);
    } else if (data->enc == DECRYPT_MODE) {
        return CcmDecryptDoFinal(output, isUpdateInput);
    } else {
        LOGE("invalid encrypt mode in CCM!");
        return HCF_INVALID_PARAMS;
    }
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

static HcfResult AllocateGcmOutput(CipherData *data, HcfBlob *input, HcfBlob *output, bool *isUpdateInput)
{
    uint32_t outLen = 0;
    if (HcfIsBlobValid(input)) {
        outLen += input->len;
        *isUpdateInput = true;
    }
    uint32_t authTagLen = (data->enc == ENCRYPT_MODE) ? GCM_TAG_SIZE : 0;
    outLen += data->updateLen + authTagLen + AES_BLOCK_SIZE;
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

static HcfResult PrepareGcmAeadDecryptInput(CipherData *data, HcfBlob *input, bool isUpdateInput, HcfBlob *cipherInput,
    HcfBlob **updateInput)
{
    if (data->enc != DECRYPT_MODE || !data->isNewCcmAead || !isUpdateInput) {
        return HCF_SUCCESS;
    }
    if (input->len < data->tagLen) {
        LOGE("gcm aead decrypt input len invalid!");
        return HCF_ERR_PARAMETER_CHECK_FAILED;
    }
    uint32_t cipherLen = input->len - data->tagLen;
    if (data->tag == NULL) {
        data->tag = (uint8_t *)HcfMalloc(data->tagLen, 0);
        if (data->tag == NULL) {
            LOGE("gcm aead decrypt malloc tag failed!");
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
static HcfResult AesGcmNewAeadFeedAadIfPending(CipherData *data)
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
        res = AesGcmNewAeadFeedAadIfPending(data);
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

static HcfResult AllocateNewCcmOutput(CipherData *data, HcfBlob *input, HcfBlob *output, bool *isUpdateInput)
{
    uint32_t outLen = 0;
    if (HcfIsBlobValid(input)) {
        *isUpdateInput = true;
        if (data->enc == DECRYPT_MODE) {
            if (input->len < data->tagLen) {
                LOGE("new ccm decrypt input len invalid!");
                return HCF_ERR_PARAMETER_CHECK_FAILED;
            }
            outLen += (input->len - data->tagLen);
        } else {
            outLen += input->len;
        }
    }
    uint32_t authTagLen = (data->enc == ENCRYPT_MODE) ? data->tagLen : 0;
    outLen += data->updateLen + authTagLen;
    output->data = (uint8_t *)HcfMalloc(outLen, 0);
    if (output->data == NULL) {
        LOGE("malloc output failed!");
        return HCF_ERR_MALLOC;
    }
    output->len = outLen;
    return HCF_SUCCESS;
}

static HcfResult NewCcmFinal(CipherData *data, HcfBlob *output, uint32_t len)
{
    int32_t ret = OpensslEvpCipherFinalEx(data->ctx, output->data + len, (int *)&output->len);
    if (ret != HCF_OPENSSL_SUCCESS) {
        HcfPrintOpensslError();
        LOGE("EVP_CipherFinal_ex failed!");
        return HCF_ERR_CRYPTO_OPERATION;
    }
    if (data->enc == DECRYPT_MODE) {
        output->len = output->len + len;
        return HCF_SUCCESS;
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

static HcfResult NewCcmDoFinal(CipherData *data, HcfBlob *input, HcfBlob *output)
{
    uint32_t len = 0;
    bool isUpdateInput = false;
    HcfResult res = AllocateNewCcmOutput(data, input, output, &isUpdateInput);
    if (res != HCF_SUCCESS) {
        LOGE("Failed to allocate new CCM output buffer.");
        return res;
    }

    HcfBlob *updateInput = input;
    HcfBlob cipherInput;
    if (data->enc == DECRYPT_MODE && isUpdateInput && input->len >= data->tagLen) {
        uint32_t cipherLen = input->len - data->tagLen;
        if (data->tag == NULL) {
            data->tag = (uint8_t *)HcfMalloc(data->tagLen, 0);
            if (data->tag == NULL) {
                LOGE("new ccm decrypt malloc tag failed!");
                return HCF_ERR_MALLOC;
            }
        }
        (void)memcpy_s(data->tag, data->tagLen, input->data + cipherLen, data->tagLen);
        cipherInput.data = input->data;
        cipherInput.len = cipherLen;
        updateInput = &cipherInput;
    }

    if (isUpdateInput) {
        HcfResult result = AeadUpdate(data, HCF_ALG_MODE_CCM, updateInput, output);
        if (result != HCF_SUCCESS) {
            LOGE("Failed to update AEAD cipher data.");
            return result;
        }
        len = output->len;
    }
    return NewCcmFinal(data, output, len);
}

static HcfResult EngineDoFinal(HcfCipherGeneratorSpi *self, HcfBlob *input, HcfBlob *output)
{
    if ((self == NULL) || (output == NULL)) { /* input maybe is null */
        LOGE("Invalid input parameter!");
        return HCF_INVALID_PARAMS;
    }
    if (!HcfIsClassMatch((const HcfObjectBase *)self, GetAesGeneratorClass())) {
        LOGE("Class is not match.");
        return HCF_INVALID_PARAMS;
    }
    HcfResult ret = HCF_ERR_CRYPTO_OPERATION;
    HcfCipherAesGeneratorSpiOpensslImpl *cipherImpl = (HcfCipherAesGeneratorSpiOpensslImpl *)self;
    if (cipherImpl->initFlag != INITIALIZED) {
        LOGW("Cipher instance may not have been initialized, "
            "ensure init interface of Cipher instance is executed completely!");
    }

    CipherData *data = cipherImpl->cipherData;
    HcfAlgParaValue mode = cipherImpl->attr.mode;
    if (data == NULL) {
        LOGE("The data of Cipher instance is NULL, "
            "please check if init interface of Cipher instance is executed completely!");
        return HCF_INVALID_PARAMS;
    }

    if (mode == HCF_ALG_MODE_CCM) {
        if (data->isNewCcmAead) {
            ret = NewCcmDoFinal(data, input, output);
        } else {
            ret = CcmDoFinal(data, input, output);
        }
    } else if (mode == HCF_ALG_MODE_GCM) {
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

static void EngineAesGeneratorDestroy(HcfObjectBase *self)
{
    if (self == NULL) {
        return;
    }
    if (!HcfIsClassMatch(self, GetAesGeneratorClass())) {
        LOGE("Class is not match.");
        return;
    }

    HcfCipherAesGeneratorSpiOpensslImpl *impl = (HcfCipherAesGeneratorSpiOpensslImpl *)self;
    FreeCipherData(&(impl->cipherData));
    HcfFree(impl);
}

static HcfResult GetAesCipherSpecString(HcfCipherGeneratorSpi *self, CipherSpecItem item, char **returnString)
{
    (void)self;
    (void)item;
    (void)returnString;
    return HCF_NOT_SUPPORT;
}

static HcfResult GetAesCipherSpecUint8Array(HcfCipherGeneratorSpi *self, CipherSpecItem item, HcfBlob *returnUint8Array)
{
    (void)self;
    (void)item;
    (void)returnUint8Array;
    return HCF_NOT_SUPPORT;
}

static HcfResult SetAesCipherSpecUint8Array(HcfCipherGeneratorSpi *self, CipherSpecItem item, HcfBlob blob)
{
    (void)self;
    (void)item;
    (void)blob;
    return HCF_NOT_SUPPORT;
}

HcfResult HcfCipherAesGeneratorSpiCreate(CipherAttr *attr, HcfCipherGeneratorSpi **generator)
{
    if ((attr == NULL) || (generator == NULL)) {
        LOGE("Invalid input parameter.");
        return HCF_INVALID_PARAMS;
    }
    HcfCipherAesGeneratorSpiOpensslImpl *returnImpl = (HcfCipherAesGeneratorSpiOpensslImpl *)HcfMalloc(
        sizeof(HcfCipherAesGeneratorSpiOpensslImpl), 0);
    if (returnImpl == NULL) {
        LOGE("Failed to allocate returnImpl memroy!");
        return HCF_ERR_MALLOC;
    }
    (void)memcpy_s(&returnImpl->attr, sizeof(CipherAttr), attr, sizeof(CipherAttr));
    returnImpl->base.init = EngineCipherInit;
    returnImpl->base.update = EngineUpdate;
    returnImpl->base.doFinal = EngineDoFinal;
    returnImpl->base.getCipherSpecString = GetAesCipherSpecString;
    returnImpl->base.getCipherSpecUint8Array = GetAesCipherSpecUint8Array;
    returnImpl->base.setCipherSpecUint8Array = SetAesCipherSpecUint8Array;
    returnImpl->base.base.destroy = EngineAesGeneratorDestroy;
    returnImpl->base.base.getClass = GetAesGeneratorClass;

    *generator = (HcfCipherGeneratorSpi *)returnImpl;
    return HCF_SUCCESS;
}
