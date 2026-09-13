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

#include "des_openssl.h"
#include "log.h"
#include "blob.h"
#include "memory.h"
#include "result.h"
#include "utils.h"
#include "securec.h"
#include "aes_openssl_common.h"
#include "sym_common_defines.h"
#include "openssl_adapter.h"
#include "openssl_common.h"
#include "openssl_class.h"

#define DES_BLOCK_SIZE 8
#define DES_SIZE_64 8
#define DES_IV_SIZE 8
#define TRIPLE_DES_SIZE_192 24

typedef struct {
    HcfCipherGeneratorSpi base;
    CipherAttr attr;
    CipherData *cipherData;
    CryptoStatus initFlag;
} HcfCipherDesGeneratorSpiOpensslImpl;

static const char *GetDesGeneratorClass(void)
{
    return OPENSSL_3DES_CIPHER_CLASS;
}

static const EVP_CIPHER *DefaultCipherType(void)
{
    return OpensslEvpDesEde3Ecb();
}

static const EVP_CIPHER *Get3DesCipherType(HcfCipherDesGeneratorSpiOpensslImpl *impl)
{
    switch (impl->attr.mode) {
        case HCF_ALG_MODE_ECB:
            return OpensslEvpDesEde3Ecb();
        case HCF_ALG_MODE_CBC:
            return OpensslEvpDesEde3Cbc();
        case HCF_ALG_MODE_OFB:
            return OpensslEvpDesEde3Ofb();
        case HCF_ALG_MODE_CFB:
        case HCF_ALG_MODE_CFB64:
            return OpensslEvpDesEde3Cfb64();
        case HCF_ALG_MODE_CFB1:
            return OpensslEvpDesEde3Cfb1();
        case HCF_ALG_MODE_CFB8:
            return OpensslEvpDesEde3Cfb8();
        default:
            break;
    }
    return DefaultCipherType();
}

static const EVP_CIPHER *GetDesCipherType(HcfCipherDesGeneratorSpiOpensslImpl *impl)
{
    switch (impl->attr.mode) {
        case HCF_ALG_MODE_ECB:
            return OpensslEvpDesEcb();
        case HCF_ALG_MODE_CBC:
            return OpensslEvpDesCbc();
        case HCF_ALG_MODE_OFB:
            return OpensslEvpDesOfb();
        case HCF_ALG_MODE_CFB:
        case HCF_ALG_MODE_CFB64:
            return OpensslEvpDesCfb64();
        case HCF_ALG_MODE_CFB1:
            return OpensslEvpDesCfb1();
        case HCF_ALG_MODE_CFB8:
            return OpensslEvpDesCfb8();
        default:
            break;
    }
    return OpensslEvpDesEcb();
}

static HcfResult InitCipherData(enum HcfCryptoMode opMode, CipherData **cipherData)
{
    HcfResult ret = HCF_INVALID_PARAMS;

    *cipherData = (CipherData *)HcfMalloc(sizeof(CipherData), 0);
    if (*cipherData == NULL) {
        LOGE("malloc failed.");
        return HCF_ERR_MALLOC;
    }

    (*cipherData)->enc = opMode;
    (*cipherData)->ctx = OpensslEvpCipherCtxNew();
    if ((*cipherData)->ctx == NULL) {
        HcfPrintOpensslError();
        LOGE("Failed to allocate ctx memroy.");
        goto clearup;
    }

    ret = HCF_SUCCESS;
    return ret;
clearup:
    FreeCipherData(cipherData);
    return ret;
}

static HcfResult ValidateCipherInitParams(HcfCipherGeneratorSpi *self, HcfKey *key)
{
    if ((self == NULL) || (key == NULL)) {
        LOGE("Invalid input parameter.");
        return HCF_INVALID_PARAMS;
    }
    if (!HcfIsClassMatch((const HcfObjectBase *)self, GetDesGeneratorClass())) {
        LOGE("Class is not match.");
        return HCF_INVALID_PARAMS;
    }
    if (!HcfIsClassMatch((const HcfObjectBase *)key, OPENSSL_SYM_KEY_CLASS)) {
        LOGE("Class is not match.");
        return HCF_INVALID_PARAMS;
    }
    return HCF_SUCCESS;
}

static const EVP_CIPHER *GetCipherType(HcfCipherDesGeneratorSpiOpensslImpl *cipherImpl, SymKeyImpl *keyImpl)
{
    if (cipherImpl->attr.algo == HCF_ALG_3DES) {
        if (keyImpl->keyMaterial.len < TRIPLE_DES_SIZE_192) {
            LOGE("Init failed, the input key size is smaller than keySize specified in cipher.");
            return NULL;
        }
        return Get3DesCipherType(cipherImpl);
    } else if (cipherImpl->attr.algo == HCF_ALG_DES) {
        if (keyImpl->keyMaterial.len != DES_SIZE_64) {
            LOGE("Init failed, the input key size is smaller than keySize specified in cipher.");
            return NULL;
        }
        return GetDesCipherType(cipherImpl);
    }
    LOGE("Unsupported algorithm!");
    return NULL;
}

static const unsigned char *GetIvData(HcfCipherDesGeneratorSpiOpensslImpl *cipherImpl, HcfParamsSpec *params)
{
    if (cipherImpl == NULL) {
        LOGE("cipherImpl is NULL.");
        return NULL;
    }

    // ECB mode does not require an IV
    if (cipherImpl->attr.mode == HCF_ALG_MODE_ECB) {
        return NULL;
    }

    if (params == NULL) {
        LOGE("params is NULL, but IV is required for non-ECB modes.");
        return NULL;
    }

    HcfIvParamsSpec *spec = (HcfIvParamsSpec *)params;

    if (spec->iv.data == NULL) {
        LOGE("IV data is NULL, but IV is required for non-ECB modes.");
        return NULL;
    }

    if (cipherImpl->attr.algo == HCF_ALG_DES) {
        // Ensure IV length is exactly 8 bytes for DES
        if (spec->iv.len != DES_IV_SIZE) {
            LOGE("DES IV length is invalid.");
            return NULL;
        }
        return (const unsigned char *)spec->iv.data;
    } else if (cipherImpl->attr.algo == HCF_ALG_3DES) {
        // For 3DES, IV length is not strictly validated here
        return (const unsigned char *)spec->iv.data;
    } else {
        LOGE("Unsupported algorithm for IV retrieval.");
        return NULL;
    }
}

static HcfResult EngineCipherInit(HcfCipherGeneratorSpi *self, enum HcfCryptoMode opMode,
    HcfKey *key, HcfParamsSpec *params)
{
    HcfResult ret = ValidateCipherInitParams(self, key);
    if (ret != HCF_SUCCESS) {
        return ret;
    }

    HcfCipherDesGeneratorSpiOpensslImpl *cipherImpl = (HcfCipherDesGeneratorSpiOpensslImpl *)self;
    SymKeyImpl *keyImpl = (SymKeyImpl *)key;
    int32_t enc = (opMode == ENCRYPT_MODE) ? 1 : 0;

    const EVP_CIPHER *cipher = GetCipherType(cipherImpl, keyImpl);
    if (cipher == NULL) {
        return HCF_INVALID_PARAMS;
    }

    if (InitCipherData(opMode, &(cipherImpl->cipherData)) != HCF_SUCCESS) {
        LOGE("InitCipherData failed");
        return HCF_INVALID_PARAMS;
    }

    ret = HCF_ERR_CRYPTO_OPERATION;
    CipherData *data = cipherImpl->cipherData;

    if (OpensslEvpCipherInit(data->ctx, cipher, NULL, NULL, enc) != HCF_OPENSSL_SUCCESS) {
        HcfPrintOpensslError();
        LOGD("[error] Cipher init failed.");
        goto clearup;
    }
    const unsigned char *iv = GetIvData(cipherImpl, params);
    if ((iv == NULL) && (cipherImpl->attr.mode != HCF_ALG_MODE_ECB) && (cipherImpl->attr.algo == HCF_ALG_DES)) {
        LOGE("IV is required for non-ECB modes.");
        ret = HCF_INVALID_PARAMS;
        goto clearup;
    }
    if (OpensslEvpCipherInit(data->ctx, NULL, keyImpl->keyMaterial.data, iv, enc) != HCF_OPENSSL_SUCCESS) {
        HcfPrintOpensslError();
        LOGD("[error] Cipher init key and iv failed.");
        goto clearup;
    }
    int32_t padding = (cipherImpl->attr.paddingMode == HCF_ALG_NOPADDING) ? 0 : EVP_PADDING_PKCS7;
    if (OpensslEvpCipherCtxSetPadding(data->ctx, padding) != HCF_OPENSSL_SUCCESS) {
        HcfPrintOpensslError();
        LOGD("[error] Set padding failed.");
        goto clearup;
    }
    cipherImpl->initFlag = INITIALIZED;
    return HCF_SUCCESS;

clearup:
    if (cipherImpl->cipherData != NULL) {
        FreeCipherData(&(cipherImpl->cipherData));
    }
    return ret;
}

static HcfResult AllocateOutput(HcfBlob *input, HcfBlob *output)
{
    uint32_t outLen = DES_BLOCK_SIZE;
    if (HcfIsBlobValid(input)) {
        if (outLen > UINT32_MAX - input->len) {
            LOGE("Input length overflow.");
            return HCF_ERR_PARAMETER_CHECK_FAILED;
        }
        outLen += input->len;
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
        return HCF_INVALID_PARAMS;
    }
    if (!HcfIsClassMatch((const HcfObjectBase *)self, GetDesGeneratorClass())) {
        LOGE("Class is not match.");
        return HCF_INVALID_PARAMS;
    }

    HcfCipherDesGeneratorSpiOpensslImpl *cipherImpl = (HcfCipherDesGeneratorSpiOpensslImpl *)self;
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
    HcfResult res = AllocateOutput(input, output);
    if (res != HCF_SUCCESS) {
        LOGE("Failed to allocate output buffer.");
        goto clearup;
    }

    int32_t ret = OpensslEvpCipherUpdate(data->ctx, output->data, (int *)&output->len,
        input->data, input->len);
    if (ret != HCF_OPENSSL_SUCCESS) {
        HcfPrintOpensslError();
        LOGE("Cipher update failed.");
        res = HCF_ERR_CRYPTO_OPERATION;
        goto clearup;
    }
    res = HCF_SUCCESS;
clearup:
    if (res != HCF_SUCCESS) {
        HcfBlobDataClearAndFree(output);
        FreeCipherData(&(cipherImpl->cipherData));
    } else {
        FreeRedundantOutput(output);
    }
    return res;
}

static HcfResult DesDoFinal(CipherData *data, HcfBlob *input, HcfBlob *output)
{
    int32_t ret;
    uint32_t len = 0;

    if (HcfIsBlobValid(input)) {
        ret = OpensslEvpCipherUpdate(data->ctx, output->data, (int *)&output->len,
            input->data, input->len);
        if (ret != HCF_OPENSSL_SUCCESS) {
            HcfPrintOpensslError();
            LOGE("Cipher update failed.");
            return HCF_ERR_CRYPTO_OPERATION;
        }
        len += output->len;
    }
    ret = OpensslEvpCipherFinalEx(data->ctx, output->data + len, (int *)&output->len);
    if (ret != HCF_OPENSSL_SUCCESS) {
        HcfPrintOpensslError();
        LOGE("Cipher final filed.");
        return HCF_ERR_CRYPTO_OPERATION;
    }
    output->len += len;
    return HCF_SUCCESS;
}

static HcfResult EngineDoFinal(HcfCipherGeneratorSpi *self, HcfBlob *input, HcfBlob *output)
{
    if ((self == NULL) || (output == NULL)) { /* input maybe is null */
        LOGE("Invalid input parameter.");
        return HCF_INVALID_PARAMS;
    }
    if (!HcfIsClassMatch((const HcfObjectBase *)self, GetDesGeneratorClass())) {
        LOGE("Class is not match.");
        return HCF_INVALID_PARAMS;
    }
    HcfCipherDesGeneratorSpiOpensslImpl *cipherImpl = (HcfCipherDesGeneratorSpiOpensslImpl *)self;
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

    HcfResult res = AllocateOutput(input, output);
    if (res != HCF_SUCCESS) {
        LOGE("Failed to allocate output buffer.");
        goto clearup;
    }
    res = DesDoFinal(data, input, output);
    if (res != HCF_SUCCESS) {
        LOGE("Failed to finalize DES cipher operation.");
    }
clearup:
    if (res != HCF_SUCCESS) {
        HcfBlobDataClearAndFree(output);
    } else {
        FreeRedundantOutput(output);
    }
    FreeCipherData(&(cipherImpl->cipherData));
    return res;
}

static void EngineDesGeneratorDestroy(HcfObjectBase *self)
{
    if (self == NULL) {
        return;
    }
    if (!HcfIsClassMatch(self, GetDesGeneratorClass())) {
        LOGE("Class is not match.");
        return;
    }
    HcfCipherDesGeneratorSpiOpensslImpl *impl = (HcfCipherDesGeneratorSpiOpensslImpl *)self;
    FreeCipherData(&(impl->cipherData));
    HcfFree(impl);
}

static HcfResult GetDesCipherSpecString(HcfCipherGeneratorSpi *self, CipherSpecItem item, char **returnString)
{
    (void)self;
    (void)item;
    (void)returnString;
    return HCF_NOT_SUPPORT;
}

static HcfResult GetDesCipherSpecUint8Array(HcfCipherGeneratorSpi *self, CipherSpecItem item, HcfBlob *returnUint8Array)
{
    (void)self;
    (void)item;
    (void)returnUint8Array;
    return HCF_NOT_SUPPORT;
}

static HcfResult SetDesCipherSpecUint8Array(HcfCipherGeneratorSpi *self, CipherSpecItem item, HcfBlob blob)
{
    (void)self;
    (void)item;
    (void)blob;
    return HCF_NOT_SUPPORT;
}

HcfResult HcfCipherDesGeneratorSpiCreate(CipherAttr *attr, HcfCipherGeneratorSpi **generator)
{
    if ((attr == NULL) || (generator == NULL)) {
        LOGE("Invalid input parameter.");
        return HCF_INVALID_PARAMS;
    }
    HcfCipherDesGeneratorSpiOpensslImpl *returnImpl = (HcfCipherDesGeneratorSpiOpensslImpl *)HcfMalloc(
        sizeof(HcfCipherDesGeneratorSpiOpensslImpl), 0);
    if (returnImpl == NULL) {
        LOGE("Failed to allocate returnImpl memroy.");
        return HCF_ERR_MALLOC;
    }
    (void)memcpy_s(&returnImpl->attr, sizeof(CipherAttr), attr, sizeof(CipherAttr));
    returnImpl->base.init = EngineCipherInit;
    returnImpl->base.update = EngineUpdate;
    returnImpl->base.doFinal = EngineDoFinal;
    returnImpl->base.getCipherSpecString = GetDesCipherSpecString;
    returnImpl->base.getCipherSpecUint8Array = GetDesCipherSpecUint8Array;
    returnImpl->base.setCipherSpecUint8Array = SetDesCipherSpecUint8Array;
    returnImpl->base.base.destroy = EngineDesGeneratorDestroy;
    returnImpl->base.base.getClass = GetDesGeneratorClass;

    *generator = (HcfCipherGeneratorSpi *)returnImpl;
    return HCF_SUCCESS;
}
