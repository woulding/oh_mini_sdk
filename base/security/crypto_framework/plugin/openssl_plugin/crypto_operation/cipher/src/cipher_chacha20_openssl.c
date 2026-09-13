/*
 * Copyright (C) 2025 Huawei Device Co., Ltd.
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

#include "chacha20_openssl.h"
#include <string.h>
#include "log.h"
#include "blob.h"
#include "memory.h"
#include "result.h"
#include "utils.h"
#include "securec.h"
#include "sym_common_defines.h"
#include "openssl_adapter.h"
#include "openssl_common.h"
#include "openssl_class.h"
#include "aes_openssl_common.h"
#include "detailed_chacha20_params.h"

typedef struct {
    HcfCipherGeneratorSpi base;
    CipherAttr attr;
    CipherData *cipherData;
    CryptoStatus initFlag;
} HcfCipherChaCha20GeneratorSpiOpensslImpl;

#define CHACHA20_KEY_LEN 32
#define CHACHA20_IV_LEN 16
#define CHACHA20_POLY1305_IV_LEN 12
#define CHACHA20_BLOCK_SIZE 16
#define POLY1305_TAG_SIZE 16
#define AEAD_PARAMS_SPEC_TYPE "AeadParamsSpec"


static const char *GetChaCha20GeneratorClass(void)
{
    return OPENSSL_CHACHA20_CIPHER_CLASS;
}

static const EVP_CIPHER *GetCipherType(HcfCipherChaCha20GeneratorSpiOpensslImpl *cipherImpl)
{
    if (cipherImpl->attr.mode == HCF_ALG_MODE_POLY1305) {
        return OpensslEvpChaCha20Poly1305();
    } else {
        return OpensslEvpChaCha20();
    }
    LOGE("Invalid params.");
    return NULL;
}

static HcfResult ValidateCipherInitParams(HcfCipherGeneratorSpi *self, HcfKey *key)
{
    if ((self == NULL) || (key == NULL)) {
        LOGE("Invalid input parameter.");
        return HCF_ERR_PARAMETER_CHECK_FAILED;
    }
    if (!HcfIsClassMatch((const HcfObjectBase *)self, GetChaCha20GeneratorClass())) {
        LOGE("Class is not match.");
        return HCF_ERR_PARAMETER_CHECK_FAILED;
    }
    if (!HcfIsClassMatch((const HcfObjectBase *)key, OPENSSL_SYM_KEY_CLASS)) {
        LOGE("Class is not match.");
        return HCF_ERR_PARAMETER_CHECK_FAILED;
    }
    return HCF_SUCCESS;
}

static bool IsPoly1305ParamsValid(enum HcfCryptoMode opMode, HcfChaCha20ParamsSpec *params)
{
    if (params == NULL) {
        LOGE("params is null!");
        return false;
    }
    if (params->iv.data == NULL || params->iv.len != CHACHA20_POLY1305_IV_LEN) {
        LOGE("iv is null or iv len is not equal to CHACHA20_POLY1305_IV_LEN!");
        return false;
    }
    if (opMode == DECRYPT_MODE && (params->tag.data == NULL || params->tag.len == 0)) {
        LOGE("tag is null!");
        return false;
    }
    return true;
}

static bool IsPoly1305AeadParamsValid(HcfAeadParamsSpec *params)
{
    if (params == NULL) {
        LOGE("params is null!");
        return false;
    }
    if (params->nonce.data == NULL || params->nonce.len != CHACHA20_POLY1305_IV_LEN) {
        LOGE("nonce is null or nonce len is not equal to CHACHA20_POLY1305_IV_LEN!");
        return false;
    }
    if ((params->tagLen != 0) && (params->tagLen != POLY1305_TAG_SIZE)) {
        LOGE("tag len is invalid!");
        return false;
    }
    return true;
}

static HcfResult IsIvParamsValid(HcfIvParamsSpec *params)
{
    if (params == NULL) {
        LOGE("params is null!");
        return HCF_ERR_PARAMETER_CHECK_FAILED;
    }
    if ((params->iv.data == NULL) || (params->iv.len != CHACHA20_IV_LEN)) {
        LOGE("iv is invalid!");
        return HCF_ERR_PARAMETER_CHECK_FAILED;
    }
    return HCF_SUCCESS;
}

static HcfResult InitAadAndTagFromPoly1305Params(enum HcfCryptoMode opMode, HcfChaCha20ParamsSpec *params,
    CipherData *data)
{
    if (!IsPoly1305ParamsValid(opMode, params)) {
        LOGE("poly1305 params is invalid!");
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
    if (!IsPoly1305AeadParamsValid(params)) {
        LOGE("aead params is invalid!");
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
        data->aead = true;
    } else {
        data->aad = NULL;
        data->aadLen = 0;
        data->aead = false;
    }
    data->tagLen = (params->tagLen == 0) ? POLY1305_TAG_SIZE : (uint32_t)params->tagLen;
    data->isNewCcmAead = true;
    return HCF_SUCCESS;
}

static HcfResult InitCipherData(HcfCipherGeneratorSpi *self, enum HcfCryptoMode opMode,
    HcfParamsSpec *params, CipherData **cipherData)
{
    HcfResult ret = HCF_ERR_CRYPTO_OPERATION;
    *cipherData = (CipherData *)HcfMalloc(sizeof(CipherData), 0);
    if (*cipherData == NULL) {
        LOGE("malloc failed.");
        return HCF_ERR_MALLOC;
    }
    HcfCipherChaCha20GeneratorSpiOpensslImpl *cipherImpl = (HcfCipherChaCha20GeneratorSpiOpensslImpl *)self;
    HcfAlgParaValue mode = cipherImpl->attr.mode;
    (*cipherData)->enc = opMode;
    (*cipherData)->ctx = OpensslEvpCipherCtxNew();
    if ((*cipherData)->ctx == NULL) {
        HcfPrintOpensslError();
        LOGE("Failed to allocate ctx memroy.");
        goto clearup;
    }
    ret = HCF_SUCCESS;
    if (mode == HCF_ALG_MODE_POLY1305) {
        if ((params != NULL) && (params->getType != NULL) &&
            (strcmp(params->getType(), AEAD_PARAMS_SPEC_TYPE) == 0)) {
            ret = InitAadAndTagFromAeadParams(opMode, (HcfAeadParamsSpec *)params, *cipherData);
        } else {
            ret = InitAadAndTagFromPoly1305Params(opMode, (HcfChaCha20ParamsSpec *)params, *cipherData);
        }
    } else {
        ret = IsIvParamsValid((HcfIvParamsSpec *)params);
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

static bool SetCipherAttribute(HcfCipherChaCha20GeneratorSpiOpensslImpl *cipherImpl, SymKeyImpl *keyImpl,
    int enc, HcfParamsSpec *params)
{
    CipherData *data = cipherImpl->cipherData;
    HcfAlgParaValue mode = cipherImpl->attr.mode;
    const EVP_CIPHER *cipher = GetCipherType(cipherImpl);
    if (cipher == NULL) {
        HcfPrintOpensslError();
        LOGE("fetch cipher failed!");
        return false;
    }
    if (mode != HCF_ALG_MODE_POLY1305) {
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

static HcfResult EngineCipherInit(HcfCipherGeneratorSpi *self, enum HcfCryptoMode opMode,
    HcfKey *key, HcfParamsSpec *params)
{
    HcfResult ret = ValidateCipherInitParams(self, key);
    if (ret != HCF_SUCCESS) {
        return ret;
    }
    HcfCipherChaCha20GeneratorSpiOpensslImpl *cipherImpl = (HcfCipherChaCha20GeneratorSpiOpensslImpl *)self;
    SymKeyImpl *keyImpl = (SymKeyImpl *)key;
    if (opMode != ENCRYPT_MODE && opMode != DECRYPT_MODE) {
        LOGE("Invalid operation mode: %{public}d", opMode);
        return HCF_ERR_PARAMETER_CHECK_FAILED;
    }
    int32_t enc = (opMode == ENCRYPT_MODE) ? 1 : 0;
    HcfResult res = InitCipherData(self, opMode, params, &(cipherImpl->cipherData));
    if (res != HCF_SUCCESS) {
        LOGE("Failed to initialize cipher data.");
        return res;
    }
    ret = HCF_ERR_CRYPTO_OPERATION;
    if (!SetCipherAttribute(cipherImpl, keyImpl, enc, params)) {
        LOGE("Set cipher attribute failed!");
        goto clearup;
    }
    cipherImpl->initFlag = INITIALIZED;
    return HCF_SUCCESS;
clearup:
    FreeCipherData(&(cipherImpl->cipherData));
    return ret;
}

static HcfResult AllocateOutput(HcfBlob *input, HcfBlob *output, bool *isUpdateInput)
{
    uint32_t outLen = CHACHA20_BLOCK_SIZE + CHACHA20_BLOCK_SIZE;
    if (HcfIsBlobValid(input)) {
        // 检查输入长度溢出
        if (outLen > UINT32_MAX - input->len) {
            LOGE("Input length overflow detected!");
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
        LOGE("poly1305 cipher update failed!");
        return HCF_ERR_CRYPTO_OPERATION;
    }
    return HCF_SUCCESS;
}

static HcfResult EngineUpdate(HcfCipherGeneratorSpi *self, HcfBlob *input, HcfBlob *output)
{
    if ((self == NULL) || (input == NULL) || (output == NULL)) {
        LOGE("Invalid input parameter.");
        return HCF_ERR_PARAMETER_CHECK_FAILED;
    }
    if (!HcfIsClassMatch((HcfObjectBase *)self, self->base.getClass())) {
        LOGE("Class is not match.");
        return HCF_ERR_PARAMETER_CHECK_FAILED;
    }

    HcfCipherChaCha20GeneratorSpiOpensslImpl *cipherImpl = (HcfCipherChaCha20GeneratorSpiOpensslImpl *)self;
    if (cipherImpl->initFlag != INITIALIZED) {
        LOGW("Cipher instance may not have been initialized, "
            "ensure init interface of Cipher instance is executed completely!");
    }

    CipherData *data = cipherImpl->cipherData;
    if (data == NULL) {
        LOGE("The data of Cipher instance is NULL, "
            "please check if init interface of Cipher instance is executed completely!");
        return HCF_ERR_PARAMETER_CHECK_FAILED;
    }
    if (cipherImpl->attr.mode == HCF_ALG_MODE_POLY1305 && data->isNewCcmAead && data->updateLen != 0) {
        LOGE("aead params update can only input data once!");
        return HCF_ERR_PARAMETER_CHECK_FAILED;
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
    if (cipherImpl->attr.mode == HCF_ALG_MODE_POLY1305 && data->isNewCcmAead) {
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
        ret = OpensslEvpCipherUpdate(data->ctx, output->data, (int *)&output->len, input->data, input->len);
        if (ret != HCF_OPENSSL_SUCCESS) {
            HcfPrintOpensslError();
            LOGE("EVP_CipherUpdate failed!");
            return HCF_ERR_CRYPTO_OPERATION;
        }
        len = output->len;
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

static HcfResult AllocatePoly1305Output(CipherData *data, HcfBlob *input, HcfBlob *output, bool *isUpdateInput)
{
    uint32_t outLen = 0;
    if (HcfIsBlobValid(input)) {
        if (outLen > UINT32_MAX - input->len) {
            LOGE("Input length overflow detected!");
            return HCF_ERR_PARAMETER_CHECK_FAILED;
        }
        outLen += input->len;
        *isUpdateInput = true;
    }
    uint32_t authTagLen = (data->enc == ENCRYPT_MODE) ? POLY1305_TAG_SIZE : 0;
    uint32_t additionalLen = data->updateLen + authTagLen + CHACHA20_BLOCK_SIZE;
    if (outLen > UINT32_MAX - additionalLen) {
        LOGE("Output length calculation overflow detected!");
        return HCF_ERR_PARAMETER_CHECK_FAILED;
    }
    outLen += additionalLen;
    if (outLen == 0) {
        LOGE("output size is invalid!");
        return HCF_ERR_PARAMETER_CHECK_FAILED;
    }
    output->data = (uint8_t *)HcfMalloc(outLen, 0);
    if (output->data == NULL) {
        LOGE("malloc output failed!");
        return HCF_ERR_MALLOC;
    }
    output->len = outLen;
    return HCF_SUCCESS;
}
static HcfResult Poly1305EncryptDoFinal(CipherData *data, HcfBlob *output, uint32_t len)
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

static HcfResult Poly1305DecryptDoFinal(CipherData *data, HcfBlob *output, uint32_t len)
{
    if (data->tag == NULL) {
        LOGE("poly1305 decrypt has not AuthTag!");
        return HCF_ERR_PARAMETER_CHECK_FAILED;
    }
    int32_t ret = OpensslEvpCipherCtxCtrl(data->ctx, EVP_CTRL_AEAD_SET_TAG, data->tagLen, (void *)data->tag);
    if (ret != HCF_OPENSSL_SUCCESS) {
        HcfPrintOpensslError();
        LOGE("poly1305 decrypt set AuthTag failed!");
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

static HcfResult PreparePoly1305AeadDecryptInput(CipherData *data, HcfBlob *input, bool isUpdateInput,
    HcfBlob *cipherInput, HcfBlob **updateInput)
{
    if (data->enc != DECRYPT_MODE || !data->isNewCcmAead || !isUpdateInput) {
        return HCF_SUCCESS;
    }
    if (input->len < data->tagLen) {
        LOGE("poly1305 aead decrypt input len invalid!");
        return HCF_ERR_PARAMETER_CHECK_FAILED;
    }
    uint32_t cipherLen = input->len - data->tagLen;
    if (data->tag == NULL) {
        data->tag = (uint8_t *)HcfMalloc(data->tagLen, 0);
        if (data->tag == NULL) {
            LOGE("tag malloc failed!");
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
static HcfResult Poly1305NewAeadFeedAadIfPending(CipherData *data)
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

static HcfResult Poly1305DoFinal(CipherData *data, HcfBlob *input, HcfBlob *output)
{
    bool isUpdateInput = false;
    uint32_t len = 0;
    HcfBlob *updateInput = input;
    HcfBlob cipherInput = {0};
    HcfResult res = AllocatePoly1305Output(data, input, output, &isUpdateInput);
    if (res != HCF_SUCCESS) {
        LOGE("Failed to allocate output buffer.");
        return res;
    }
    res = PreparePoly1305AeadDecryptInput(data, input, isUpdateInput, &cipherInput, &updateInput);
    if (res != HCF_SUCCESS) {
        LOGE("PreparePoly1305AeadDecryptInput failed!");
        return res;
    }

    if (data->isNewCcmAead) {
        res = Poly1305NewAeadFeedAadIfPending(data);
        if (res != HCF_SUCCESS) {
            return res;
        }
        data->aead = false;
    }

    if (isUpdateInput) {
        if (data->isNewCcmAead) {
            res = CommonUpdate(data, updateInput, output);
        } else {
            res = (data->aead) ? AeadUpdate(data, HCF_ALG_MODE_POLY1305, updateInput, output)
                                  : CommonUpdate(data, updateInput, output);
        }
        if (res != HCF_SUCCESS) {
            LOGE("poly1305 update failed!");
            return res;
        }
        len = output->len;
    }
    if (data->enc == ENCRYPT_MODE) {
        return Poly1305EncryptDoFinal(data, output, len);
    } else if (data->enc == DECRYPT_MODE) {
        return Poly1305DecryptDoFinal(data, output, len);
    } else {
        LOGE("invalid encrypt mode!");
        return HCF_ERR_PARAMETER_CHECK_FAILED;
    }
}

static HcfResult EngineDoFinal(HcfCipherGeneratorSpi *self, HcfBlob *input, HcfBlob *output)
{
    if ((self == NULL) || (output == NULL)) { /* input maybe is null */
        LOGE("Invalid input parameter!");
        return HCF_ERR_PARAMETER_CHECK_FAILED;
    }
    if (!HcfIsClassMatch((HcfObjectBase *)self, self->base.getClass())) {
        LOGE("Class is not match.");
        return HCF_ERR_PARAMETER_CHECK_FAILED;
    }
    HcfCipherChaCha20GeneratorSpiOpensslImpl *cipherImpl = (HcfCipherChaCha20GeneratorSpiOpensslImpl *)self;
    if (cipherImpl->initFlag != INITIALIZED) {
        LOGW("Cipher instance may not have been initialized, "
            "ensure init interface of Cipher instance is executed completely!");
    }

    CipherData *data = cipherImpl->cipherData;
    if (data == NULL) {
        LOGE("The data of Cipher instance is NULL, "
            "please check if init interface of Cipher instance is executed completely!");
        return HCF_ERR_MALLOC;
    }

    HcfResult ret = HCF_ERR_CRYPTO_OPERATION;
    if (cipherImpl->attr.mode == HCF_ALG_MODE_POLY1305) {
        ret = Poly1305DoFinal(data, input, output);
    } else {
        ret = CommonDoFinal(data, input, output);
    }
    FreeCipherData(&(cipherImpl->cipherData));
    if (ret != HCF_SUCCESS) {
        HcfBlobDataClearAndFree(output);
    }
    FreeRedundantOutput(output);
    return ret;
}

static void EngineChaCha20GeneratorDestroy(HcfObjectBase *self)
{
    if (self == NULL) {
        return;
    }
    if (!HcfIsClassMatch(self, GetChaCha20GeneratorClass())) {
        LOGE("Class is not match.");
        return;
    }

    HcfCipherChaCha20GeneratorSpiOpensslImpl *impl = (HcfCipherChaCha20GeneratorSpiOpensslImpl *)self;
    FreeCipherData(&(impl->cipherData));
    HcfFree(impl);
}

static HcfResult GetChaCha20CipherSpecString(HcfCipherGeneratorSpi *self, CipherSpecItem item, char **returnString)
{
    (void)self;
    (void)item;
    (void)returnString;
    LOGE("unsupported cipher spec!");
    return HCF_ERR_PARAMETER_CHECK_FAILED;
}

static HcfResult GetChaCha20CipherSpecUint8Array(HcfCipherGeneratorSpi *self, CipherSpecItem item,
    HcfBlob *returnUint8Array)
{
    (void)self;
    (void)item;
    (void)returnUint8Array;
    LOGE("unsupported cipher spec!");
    return HCF_ERR_PARAMETER_CHECK_FAILED;
}

static HcfResult SetChaCha20CipherSpecUint8Array(HcfCipherGeneratorSpi *self, CipherSpecItem item, HcfBlob blob)
{
    (void)self;
    (void)item;
    (void)blob;
    LOGE("unsupported cipher spec!");
    return HCF_ERR_PARAMETER_CHECK_FAILED;
}

HcfResult HcfCipherChaCha20GeneratorSpiCreate(CipherAttr *attr, HcfCipherGeneratorSpi **generator)
{
    if ((attr == NULL) || (generator == NULL)) {
        LOGE("Invalid input parameter.");
        return HCF_ERR_PARAMETER_CHECK_FAILED;
    }
    HcfCipherChaCha20GeneratorSpiOpensslImpl *returnImpl = (HcfCipherChaCha20GeneratorSpiOpensslImpl *)HcfMalloc(
        sizeof(HcfCipherChaCha20GeneratorSpiOpensslImpl), 0);
    if (returnImpl == NULL) {
        LOGE("Failed to allocate returnImpl memory.");
        return HCF_ERR_MALLOC;
    }
    (void)memcpy_s(&returnImpl->attr, sizeof(CipherAttr), attr, sizeof(CipherAttr));
    returnImpl->base.init = EngineCipherInit;
    returnImpl->base.update = EngineUpdate;
    returnImpl->base.doFinal = EngineDoFinal;
    returnImpl->base.getCipherSpecString = GetChaCha20CipherSpecString;
    returnImpl->base.getCipherSpecUint8Array = GetChaCha20CipherSpecUint8Array;
    returnImpl->base.setCipherSpecUint8Array = SetChaCha20CipherSpecUint8Array;
    returnImpl->base.base.destroy = EngineChaCha20GeneratorDestroy;
    returnImpl->base.base.getClass = GetChaCha20GeneratorClass;

    *generator = (HcfCipherGeneratorSpi *)returnImpl;
    return HCF_SUCCESS;
}
