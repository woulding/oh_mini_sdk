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

#include "cipher_sm2_openssl.h"
#include <stdbool.h>
#include <string.h>
#include "log.h"
#include "memory.h"
#include "openssl_adapter.h"
#include "openssl_class.h"
#include "openssl_common.h"
#include "securec.h"
#include "utils.h"

typedef struct {
    HcfCipherGeneratorSpi super;

    CipherAttr attr;

    CryptoStatus initFlag;

    EC_KEY *sm2Key;

    EVP_MD *sm2Digest;
} HcfCipherSm2GeneratorSpiImpl;

static const char *EngineGetClass(void)
{
    return OPENSSL_SM2_CIPHER_CLASS;
}

static HcfResult CheckCipherInitParams(enum HcfCryptoMode opMode, HcfKey *key)
{
    switch (opMode) {
        case ENCRYPT_MODE:
            if (!HcfIsClassMatch((HcfObjectBase *)key, HCF_OPENSSL_SM2_PUB_KEY_CLASS)) {
                LOGE("Class not match");
                return HCF_INVALID_PARAMS;
            }
            break;
        case DECRYPT_MODE:
            if (!HcfIsClassMatch((HcfObjectBase *)key, HCF_OPENSSL_SM2_PRI_KEY_CLASS)) {
                LOGE("Class not match");
                return HCF_INVALID_PARAMS;
            }
            break;
        default:
            LOGE("Invalid opMode %{public}d", opMode);
            return HCF_INVALID_PARAMS;
    }

    return HCF_SUCCESS;
}

static HcfResult InitSm2Key(HcfCipherSm2GeneratorSpiImpl *impl, HcfKey *key, enum HcfCryptoMode opMode)
{
    if (opMode == ENCRYPT_MODE) {
        impl->sm2Key = OpensslEcKeyDup(((HcfOpensslSm2PubKey *)key)->ecKey);
    } else if (opMode == DECRYPT_MODE) {
        // dup will check if ecKey is NULL
        impl->sm2Key = OpensslEcKeyDup(((HcfOpensslSm2PriKey *)key)->ecKey);
    } else {
        LOGE("OpMode not match.");
        return HCF_INVALID_PARAMS;
    }
    if (impl->sm2Key == NULL) {
        HcfPrintOpensslError();
        LOGE("sm2Key is null!");
        return HCF_ERR_CRYPTO_OPERATION;
    }
    return HCF_SUCCESS;
}

static HcfResult GetSm2CipherSpecString(HcfCipherGeneratorSpi *self, CipherSpecItem item, char **returnString)
{
    if (self == NULL || returnString == NULL) {
        LOGE("Param is invalid.");
        return HCF_INVALID_PARAMS;
    }
    if (!HcfIsClassMatch((HcfObjectBase *)self, EngineGetClass())) {
        LOGE("Class not match");
        return HCF_INVALID_PARAMS;
    }
    if (item != SM2_MD_NAME_STR) {
        LOGE("Invalid input cipher spec");
        return HCF_INVALID_PARAMS;
    }
    // only support sm3
    return GetSm2SpecStringSm3(returnString);
}

static HcfResult GetSm2CipherSpecUint8Array(HcfCipherGeneratorSpi *self, CipherSpecItem item, HcfBlob *returnUint8Array)
{
    (void)self;
    (void)item;
    (void)returnUint8Array;
    LOGE("Unsupported cipher spec!");
    return HCF_NOT_SUPPORT;
}

static HcfResult SetSm2CipherSpecUint8Array(HcfCipherGeneratorSpi *self, CipherSpecItem item, HcfBlob blob)
{
    (void)self;
    (void)item;
    (void)blob;
    LOGE("Unsupported cipher spec!");
    return HCF_NOT_SUPPORT;
}

static HcfResult EngineInit(HcfCipherGeneratorSpi *self, enum HcfCryptoMode opMode,
    HcfKey *key, HcfParamsSpec *params)
{
    (void)params;
    if (self == NULL || key == NULL) {
        LOGE("Param is invalid.");
        return HCF_INVALID_PARAMS;
    }
    if (!HcfIsClassMatch((HcfObjectBase *)self, self->base.getClass())) {
        LOGE("Class not match");
        return HCF_INVALID_PARAMS;
    }
    HcfCipherSm2GeneratorSpiImpl *impl = (HcfCipherSm2GeneratorSpiImpl *)self;
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
    if (InitSm2Key(impl, key, opMode) != HCF_SUCCESS) {
        LOGE("InitSm2Key fail");
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

static size_t GetTextLen(HcfCipherSm2GeneratorSpiImpl *impl, HcfBlob *input, int32_t mode)
{
    size_t textLen = 0;
    if (mode == ENCRYPT_MODE) {
        if (OpensslSm2CipherTextSize(impl->sm2Key, impl->sm2Digest, input->len, &textLen) != HCF_OPENSSL_SUCCESS) {
            LOGE("Failed to get ciphertext size!");
            HcfPrintOpensslError();
            return 0;
        }
    } else if (mode == DECRYPT_MODE) {
        if (OpensslSm2PlainTextSize(input->data, input->len, &textLen) != HCF_OPENSSL_SUCCESS) {
            LOGE("Failed to get plaintext size!");
            HcfPrintOpensslError();
            return 0;
        }
    } else {
        LOGE("invalid ops!");
    }
    return textLen;
}

static HcfResult DoSm2EncryptAndDecrypt(HcfCipherSm2GeneratorSpiImpl *impl, HcfBlob *input, HcfBlob *output,
    int32_t mode, size_t textLen)
{
    uint8_t *outputText = (uint8_t *)HcfMalloc(sizeof(uint8_t) * textLen, 0);
    if (outputText == NULL) {
        LOGE("Failed to allocate plaintext memory!");
        return HCF_ERR_MALLOC;
    }
    int32_t ret = HCF_OPENSSL_SUCCESS;
    if (mode == ENCRYPT_MODE) {
        ret = OpensslOsslSm2Encrypt(impl->sm2Key, impl->sm2Digest, input->data, input->len, outputText, &textLen);
    } else if (mode == DECRYPT_MODE) {
        ret = OpensslOsslSm2Decrypt(impl->sm2Key, impl->sm2Digest, input->data, input->len, outputText, &textLen);
    } else {
        LOGE("OpMode is invalid.");
        HcfFree(outputText);
        return HCF_INVALID_PARAMS;
    }
    if (ret != HCF_OPENSSL_SUCCESS) {
        LOGE("SM2 openssl error");
        HcfFree(outputText);
        HcfPrintOpensslError();
        return HCF_ERR_CRYPTO_OPERATION;
    }
    output->data = outputText;
    output->len = textLen;
    return HCF_SUCCESS;
}

static HcfResult DoSm2Crypt(HcfCipherSm2GeneratorSpiImpl *impl, HcfBlob *input, HcfBlob *output, int32_t mode)
{
    size_t textLen = GetTextLen(impl, input, mode);
    if (textLen == 0) {
        LOGE("textLen is 0");
        return HCF_ERR_CRYPTO_OPERATION;
    }
    if (DoSm2EncryptAndDecrypt(impl, input, output, mode, textLen) != HCF_SUCCESS) {
        LOGE("DoSm2EncryptAndDecrypt failed!");
        return HCF_ERR_CRYPTO_OPERATION;
    }
    return HCF_SUCCESS;
}

static HcfResult EngineDoFinal(HcfCipherGeneratorSpi *self, HcfBlob *input, HcfBlob *output)
{
    if (self == NULL || input == NULL || input->data == NULL || output == NULL) {
        LOGE("Param is invalid.");
        return HCF_INVALID_PARAMS;
    }

    if (!HcfIsClassMatch((HcfObjectBase *)self, self->base.getClass())) {
        LOGE("Class not match");
        return HCF_INVALID_PARAMS;
    }

    HcfCipherSm2GeneratorSpiImpl *impl = (HcfCipherSm2GeneratorSpiImpl *)self;
    if (impl->initFlag != INITIALIZED) {
        LOGE("SM2Cipher has not been init");
        return HCF_INVALID_PARAMS;
    }
    CipherAttr attr = impl->attr;
    output->len = 0;
    output->data = NULL;
    HcfResult ret = DoSm2Crypt(impl, input, output, attr.mode);
    if (ret != HCF_SUCCESS) {
        LOGE("Failed to get output length.");
        return HCF_ERR_CRYPTO_OPERATION;
    }
    return HCF_SUCCESS;
}

static void EngineDestroySpiImpl(HcfObjectBase *generator)
{
    if (generator == NULL) {
        return;
    }
    if (!HcfIsClassMatch(generator, generator->getClass())) {
        return;
    }
    HcfCipherSm2GeneratorSpiImpl *impl = (HcfCipherSm2GeneratorSpiImpl *)generator;
    impl->sm2Digest = NULL;
    if (impl->sm2Key != NULL) {
        OpensslEcKeyFree(impl->sm2Key);
        impl->sm2Key = NULL;
    }
    HcfFree(impl);
    impl = NULL;
}

HcfResult HcfCipherSm2CipherSpiCreate(CipherAttr *params, HcfCipherGeneratorSpi **generator)
{
    if (generator == NULL || params == NULL) {
        LOGE("Invalid input parameter.");
        return HCF_INVALID_PARAMS;
    }
    HcfCipherSm2GeneratorSpiImpl *returnImpl = (HcfCipherSm2GeneratorSpiImpl *)HcfMalloc(
        sizeof(HcfCipherSm2GeneratorSpiImpl), 0);
    if (returnImpl == NULL) {
        LOGE("Malloc sm2 cipher fail.");
        return HCF_ERR_MALLOC;
    }
    (void)memcpy_s(&returnImpl->attr, sizeof(CipherAttr), params, sizeof(CipherAttr));

    EVP_MD *getMD = NULL;
    HcfResult ret = GetOpensslDigestAlg(returnImpl->attr.md, &getMD);
    if (ret != HCF_SUCCESS || getMD == NULL) {
        LOGE("get md failed");
        HcfFree(returnImpl);
        returnImpl = NULL;
        return HCF_INVALID_PARAMS;
    }
    returnImpl->sm2Digest = getMD;

    returnImpl->super.init = EngineInit;
    returnImpl->super.update = EngineUpdate;
    returnImpl->super.doFinal = EngineDoFinal;
    returnImpl->super.getCipherSpecString = GetSm2CipherSpecString;
    returnImpl->super.getCipherSpecUint8Array = GetSm2CipherSpecUint8Array;
    returnImpl->super.setCipherSpecUint8Array = SetSm2CipherSpecUint8Array;
    returnImpl->super.base.destroy = EngineDestroySpiImpl;
    returnImpl->super.base.getClass = EngineGetClass;
    returnImpl->initFlag = UNINITIALIZED;
    *generator = (HcfCipherGeneratorSpi *)returnImpl;
    LOGD("Sm2 Cipher create success.");
    return HCF_SUCCESS;
}