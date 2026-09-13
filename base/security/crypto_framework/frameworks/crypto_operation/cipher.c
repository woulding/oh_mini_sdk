/*
 * Copyright (C) 2022-2023 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include "cipher.h"
#include "aes_openssl.h"
#include "des_openssl.h"
#include "config.h"
#include "securec.h"
#include "result.h"
#include "string.h"
#include "log.h"
#include "memory.h"
#include "cipher_rsa_openssl.h"
#include "cipher_sm2_openssl.h"
#include "sm4_openssl.h"
#include "chacha20_openssl.h"
#include "cipher_openssl.h"
#include "utils.h"
#include "plugin_operation_err.h"

typedef HcfResult (*HcfCipherGeneratorSpiCreateFunc)(CipherAttr *, HcfCipherGeneratorSpi **);

typedef struct {
    HcfCipher super;
    HcfCipherGeneratorSpi *spiObj;
    char algoName[HCF_MAX_ALGO_NAME_LEN];
} CipherGenImpl;

typedef struct {
    HcfCipherGeneratorSpiCreateFunc createFunc;
} HcfCipherGenFuncSet;

typedef struct {
    HcfAlgValue algo;
    HcfCipherGenFuncSet funcSet;
} HcfCipherGenAbility;

static const HcfCipherGenAbility CIPHER_ABILITY_SET[] = {
    { HCF_ALG_RSA, { HcfCipherRsaCipherSpiCreate } },
    { HCF_ALG_SM2, { HcfCipherSm2CipherSpiCreate } },
    { HCF_ALG_AES, { HcfCipherAesGeneratorSpiCreate } },
    { HCF_ALG_3DES, { HcfCipherDesGeneratorSpiCreate } },
    { HCF_ALG_DES, { HcfCipherDesGeneratorSpiCreate } },
    { HCF_ALG_SM4, { HcfCipherSm4GeneratorSpiCreate } },
    { HCF_ALG_AES_WRAP, { HcfCipherAesGeneratorSpiCreate } },
    { HCF_ALG_CHACHA20, { HcfCipherChaCha20GeneratorSpiCreate } },
    { HCF_ALG_CHACHA20_POLY1305, { HcfCipherChaCha20GeneratorSpiCreate } },
    { HCF_ALG_RC2, { HcfCipherSymAlgorithmGeneratorSpiCreate } },
    { HCF_ALG_RC4, { HcfCipherSymAlgorithmGeneratorSpiCreate } },
    { HCF_ALG_BLOWFISH, { HcfCipherSymAlgorithmGeneratorSpiCreate } },
    { HCF_ALG_CAST, { HcfCipherSymAlgorithmGeneratorSpiCreate } }
};

static void SetKeyType(HcfAlgParaValue value, void *cipher)
{
    CipherAttr *cipherAttr = (CipherAttr *)cipher;

    cipherAttr->keySize = 0;

    switch (value) {
        case HCF_ALG_AES_DEFAULT:
            cipherAttr->algo = HCF_ALG_AES;
            break;
        case HCF_ALG_SM4_DEFAULT:
            cipherAttr->algo = HCF_ALG_SM4;
            break;
        case HCF_ALG_DES_DEFAULT:
            cipherAttr->algo = HCF_ALG_DES;
            break;
        case HCF_ALG_3DES_DEFAULT:
            cipherAttr->algo = HCF_ALG_3DES;
            break;
        case HCF_ALG_RSA_DEFAULT:
            cipherAttr->algo = HCF_ALG_RSA;
            break;
        case HCF_ALG_SM2_DEFAULT:
            cipherAttr->algo = HCF_ALG_SM2;
            break;
        case HCF_ALG_AES_WRAP_DEFAULT:
            cipherAttr->algo = HCF_ALG_AES_WRAP;
            break;
        case HCF_ALG_CHACHA20_DEFAULT:
            cipherAttr->algo = HCF_ALG_CHACHA20;
            break;
        case HCF_ALG_RC2_DEFAULT:
            cipherAttr->algo = HCF_ALG_RC2;
            break;
        case HCF_ALG_RC4_DEFAULT:
            cipherAttr->algo = HCF_ALG_RC4;
            break;
        case HCF_ALG_BLOWFISH_DEFAULT:
            cipherAttr->algo = HCF_ALG_BLOWFISH;
            break;
        case HCF_ALG_CAST_DEFAULT:
            cipherAttr->algo = HCF_ALG_CAST;
            break;
        default:
            LOGE("Invalid algo %{public}u.", value);
            break;
    }
}

static void SetKeyLength(HcfAlgParaValue value, void *cipher)
{
    CipherAttr *cipherAttr = (CipherAttr *)cipher;

    cipherAttr->keySize = value;

    switch (value) {
        case HCF_ALG_AES_128:
        case HCF_ALG_AES_192:
        case HCF_ALG_AES_256:
            cipherAttr->algo = HCF_ALG_AES;
            break;
        case HCF_ALG_AES_128_WRAP:
        case HCF_ALG_AES_192_WRAP:
        case HCF_ALG_AES_256_WRAP:
            cipherAttr->algo = HCF_ALG_AES_WRAP;
            break;
        case HCF_ALG_SM4_128:
            cipherAttr->algo = HCF_ALG_SM4;
            break;
        case HCF_ALG_3DES_192:
            cipherAttr->algo = HCF_ALG_3DES;
            break;
        case HCF_ALG_DES_64:
            cipherAttr->algo = HCF_ALG_DES;
            break;
        case HCF_OPENSSL_RSA_512:
        case HCF_OPENSSL_RSA_768:
        case HCF_OPENSSL_RSA_1024:
        case HCF_OPENSSL_RSA_2048:
        case HCF_OPENSSL_RSA_3072:
        case HCF_OPENSSL_RSA_4096:
        case HCF_OPENSSL_RSA_8192:
            cipherAttr->algo = HCF_ALG_RSA;
            break;
        case HCF_ALG_SM2_256:
            cipherAttr->algo = HCF_ALG_SM2;
            break;
        case HCF_ALG_CHACHA20_256:
            cipherAttr->algo = HCF_ALG_CHACHA20;
            break;
        default:
            LOGE("Invalid algo %{public}u.", value);
            break;
    }
}

static void SetMode(HcfAlgParaValue value, void *cipher)
{
    CipherAttr *cipherAttr = (CipherAttr *)cipher;
    cipherAttr->mode = value ;
}

static void SetPadding(HcfAlgParaValue value, void *cipher)
{
    CipherAttr *cipherAttr = (CipherAttr *)cipher;
    cipherAttr->paddingMode = value;
}

static void SetDigest(HcfAlgParaValue value, CipherAttr *cipher)
{
    cipher->md = value;
}

static void SetMgf1Digest(HcfAlgParaValue value, CipherAttr *cipher)
{
    cipher->mgf1md = value;
}

static HcfResult OnSetParameter(const HcfParaConfig *config, void *cipher)
{
    if ((config == NULL) || (cipher == NULL)) {
        LOGE("Invalid cipher params");
        return HCF_INVALID_PARAMS;
    }
    HcfResult ret = HCF_SUCCESS;
    LOGD("Set Parameter:%{public}s", config->tag);
    switch (config->paraType) {
        case HCF_ALG_TYPE:
            SetKeyType(config->paraValue, cipher);
            break;
        case HCF_ALG_KEY_TYPE:
            SetKeyLength(config->paraValue, cipher);
            break;
        case HCF_ALG_MODE:
            SetMode(config->paraValue, cipher);
            break;
        case HCF_ALG_PADDING_TYPE:
            SetPadding(config->paraValue, cipher);
            break;
        case HCF_ALG_DIGEST:
            SetDigest(config->paraValue, cipher);
            break;
        case HCF_ALG_MGF1_DIGEST:
            SetMgf1Digest(config->paraValue, cipher);
            break;
        case HCF_ALG_TEXT_FORMAT:
            if (config->paraValue == HCF_ALG_TEXT_FORMAT_C1C2C3) {
                LOGE("Not Support C1C2C3 Format");
                ret = HCF_INVALID_PARAMS;
            }
            break;
        default:
            LOGE("Unsupported parameter type in cipher params");
            ret = HCF_INVALID_PARAMS;
            break;
    }
    return ret;
}

static const char *GetCipherGeneratorClass(void)
{
    return "HcfCipherGenerator";
}

static const char *GetAlgorithm(HcfCipher *self)
{
    if (self == NULL) {
        LOGE("The input self ptr is NULL!");
        return NULL;
    }
    if (!HcfIsClassMatch((HcfObjectBase *)self, GetCipherGeneratorClass())) {
        LOGE("Class is not match.");
        return NULL;
    }
    return ((CipherGenImpl *)self)->algoName;
}

static void CipherDestroy(HcfObjectBase *self)
{
    if (self == NULL) {
        return;
    }
    if (!HcfIsClassMatch(self, GetCipherGeneratorClass())) {
        LOGE("Class not match.");
        return;
    }
    CipherGenImpl *impl = (CipherGenImpl *)self;
    HcfObjDestroy(impl->spiObj);
    impl->spiObj = NULL;
    HcfFree(impl);
}

static HcfResult SetCipherSpecUint8Array(HcfCipher *self, CipherSpecItem item, HcfBlob pSource)
{
    // only implemented for OAEP_MGF1_PSRC_UINT8ARR
    // if pSource == NULL or len == 0, it means cleaning the pSource
    if (self == NULL) {
        LOGE("Invalid input parameter.");
        return HCF_INVALID_PARAMS;
    }
    if (item != OAEP_MGF1_PSRC_UINT8ARR) {
        LOGE("Spec item not support.");
        return HCF_INVALID_PARAMS;
    }
    if (!HcfIsClassMatch((HcfObjectBase *)self, GetCipherGeneratorClass())) {
        LOGE("Class not match.");
        return HCF_INVALID_PARAMS;
    }
    CipherGenImpl *impl = (CipherGenImpl *)self;
    return impl->spiObj->setCipherSpecUint8Array(impl->spiObj, item, pSource);
}

static bool CheckCipherSpecString(CipherSpecItem item)
{
    return ((item == OAEP_MD_NAME_STR) || (item == OAEP_MGF_NAME_STR) ||
        (item == OAEP_MGF1_MD_STR) || (item == SM2_MD_NAME_STR));
}

static HcfResult GetCipherSpecString(HcfCipher *self, CipherSpecItem item, char **returnString)
{
    if (self == NULL || returnString == NULL) {
        LOGE("Invalid input parameter.");
        return HCF_INVALID_PARAMS;
    }
    if (!CheckCipherSpecString(item)) {
        LOGE("Spec item not support.");
        return HCF_INVALID_PARAMS;
    }
    if (!HcfIsClassMatch((HcfObjectBase *)self, GetCipherGeneratorClass())) {
        LOGE("Class not match.");
        return HCF_INVALID_PARAMS;
    }
    CipherGenImpl *impl = (CipherGenImpl *)self;
    return impl->spiObj->getCipherSpecString(impl->spiObj, item, returnString);
}

static HcfResult GetCipherSpecUint8Array(HcfCipher *self, CipherSpecItem item, HcfBlob *returnUint8Array)
{
    if (self == NULL || returnUint8Array == NULL) {
        LOGE("Invalid input parameter.");
        return HCF_INVALID_PARAMS;
    }
    if (item != OAEP_MGF1_PSRC_UINT8ARR) {
        LOGE("Spec item not support.");
        return HCF_INVALID_PARAMS;
    }
    if (!HcfIsClassMatch((HcfObjectBase *)self, GetCipherGeneratorClass())) {
        LOGE("Class not match.");
        return HCF_INVALID_PARAMS;
    }
    CipherGenImpl *impl = (CipherGenImpl *)self;
    return impl->spiObj->getCipherSpecUint8Array(impl->spiObj, item, returnUint8Array);
}

static HcfResult CipherInit(HcfCipher *self, enum HcfCryptoMode opMode,
    HcfKey *key, HcfParamsSpec *params)
{
    if (self == NULL || key == NULL) { /* params maybe is NULL */
        LOGE("Invalid input parameter.");
        return HCF_INVALID_PARAMS;
    }
    if (!HcfIsClassMatch((HcfObjectBase *)self, GetCipherGeneratorClass())) {
        LOGE("Class is not match.");
        return HCF_INVALID_PARAMS;
    }
    HcfClearPluginErrorMessage();
    CipherGenImpl *impl = (CipherGenImpl *)self;
    return impl->spiObj->init(impl->spiObj, opMode, key, params);
}

static HcfResult CipherUpdate(HcfCipher *self, HcfBlob *input, HcfBlob *output)
{
    if ((self == NULL) || (input == NULL) || (output == NULL)) {
        LOGE("Invalid input parameter.");
        return HCF_INVALID_PARAMS;
    }
    if (!HcfIsClassMatch((HcfObjectBase *)self, GetCipherGeneratorClass())) {
        LOGE("Class is not match.");
        return HCF_INVALID_PARAMS;
    }
    HcfClearPluginErrorMessage();
    CipherGenImpl *impl = (CipherGenImpl *)self;
    return impl->spiObj->update(impl->spiObj, input, output);
}

static HcfResult CipherFinal(HcfCipher *self, HcfBlob *input, HcfBlob *output)
{
    if ((self == NULL) || (output == NULL)) {
        LOGE("Invalid input parameter!");
        return HCF_INVALID_PARAMS;
    }
    if (!HcfIsClassMatch((HcfObjectBase *)self, GetCipherGeneratorClass())) {
        LOGE("Class is not match.");
        return HCF_INVALID_PARAMS;
    }
    HcfClearPluginErrorMessage();
    CipherGenImpl *impl = (CipherGenImpl *)self;
    return impl->spiObj->doFinal(impl->spiObj, input, output);
}

static void InitCipher(HcfCipherGeneratorSpi *spiObj, CipherGenImpl *cipher)
{
    cipher->super.init = CipherInit;
    cipher->super.update = CipherUpdate;
    cipher->super.doFinal = CipherFinal;
    cipher->super.getAlgorithm = GetAlgorithm;
    cipher->super.base.destroy = CipherDestroy;
    cipher->super.base.getClass = GetCipherGeneratorClass;
    cipher->super.getCipherSpecString = GetCipherSpecString;
    cipher->super.getCipherSpecUint8Array = GetCipherSpecUint8Array;
    cipher->super.setCipherSpecUint8Array = SetCipherSpecUint8Array;
}

static const HcfCipherGenFuncSet *FindAbility(CipherAttr *attr)
{
    if (attr == NULL) {
        LOGE("Attr is null");
        return NULL;
    }
    for (uint32_t i = 0; i < sizeof(CIPHER_ABILITY_SET) / sizeof(HcfCipherGenAbility); i++) {
        if (CIPHER_ABILITY_SET[i].algo == attr->algo) {
            return &(CIPHER_ABILITY_SET[i].funcSet);
        }
    }
    LOGE("Algo not support! [Algo]: %{public}d", attr->algo);
    return NULL;
}

HcfResult HcfCipherCreate(const char *transformation, HcfCipher **returnObj)
{
    CipherAttr attr = {0};
    if (!HcfIsStrValid(transformation, HCF_MAX_ALGO_NAME_LEN) || (returnObj == NULL)) {
        LOGE("Invalid input params while creating cipher!");
        return HCF_INVALID_PARAMS;
    }
    if (ParseAndSetParameter(transformation, (void *)&attr, OnSetParameter) != HCF_SUCCESS) {
        LOGE("ParseAndSetParameter failed!");
        return HCF_NOT_SUPPORT;
    }

    const HcfCipherGenFuncSet *funcSet = FindAbility(&attr);
    if (funcSet == NULL) {
        LOGE("FindAbility failed!");
        return HCF_NOT_SUPPORT;
    }
    CipherGenImpl *returnGenerator = (CipherGenImpl *)HcfMalloc(sizeof(CipherGenImpl), 0);
    if (returnGenerator == NULL) {
        LOGE("Failed to allocate returnGenerator memory!");
        return HCF_ERR_MALLOC;
    }
    if (strcpy_s(returnGenerator->algoName, HCF_MAX_ALGO_NAME_LEN, transformation) != EOK) {
        LOGE("Failed to copy algoName!");
        HcfFree(returnGenerator);
        returnGenerator = NULL;
        return HCF_INVALID_PARAMS;
    }
    HcfCipherGeneratorSpi *spiObj = NULL;
    HcfResult res = funcSet->createFunc(&attr, &spiObj);
    if (res != HCF_SUCCESS) {
        LOGE("Failed to create spi object!");
        HcfFree(returnGenerator);
        returnGenerator = NULL;
        return res;
    }
    returnGenerator->spiObj = spiObj;
    InitCipher(spiObj, returnGenerator);

    *returnObj = (HcfCipher *)returnGenerator;
    return res;
}
