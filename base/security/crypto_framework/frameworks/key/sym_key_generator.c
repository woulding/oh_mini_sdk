/*
 * Copyright (C) 2023-2024 Huawei Device Co., Ltd.
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

#include "sym_key_generator.h"
#include "sym_key_factory_spi.h"
#include "sym_common_defines.h"
#include "params_parser.h"
#include "utils.h"

#include <securec.h>
#include <string.h>
#include "log.h"
#include "memory.h"
#include "result.h"
#include "config.h"

#define AES_KEY_SIZE_128 128
#define AES_KEY_SIZE_192 192
#define AES_KEY_SIZE_256 256
#define SM4_KEY_SIZE_128 128
#define DES_KEY_SIZE_64 64
#define TRIPLE_DES_KEY_SIZE_192 192
#define HMAC_KEY_SIZE_SHA1 160
#define HMAC_KEY_SIZE_SHA224 224
#define HMAC_KEY_SIZE_SHA256 256
#define HMAC_KEY_SIZE_SHA384 384
#define HMAC_KEY_SIZE_SHA512 512
#define HMAC_KEY_SIZE_SM3 256
#define HMAC_KEY_SIZE_MD5 128
#define CHACHA20_KEY_SIZE_256 256
#define CHACHA20_POLY1305_KEY_SIZE_256 256

typedef HcfResult (*SymKeyGeneratorSpiCreateFunc)(SymKeyAttr *, HcfSymKeyGeneratorSpi **);

typedef struct {
    SymKeyGeneratorSpiCreateFunc createFunc;
} SymKeyGenFuncSet;

typedef struct {
    HcfAlgValue algo;
    SymKeyGenFuncSet funcSet;
} SymKeyGenAbility;

typedef struct {
    HcfSymKeyGenerator base;
    HcfSymKeyGeneratorSpi *spiObj;
    char algoName[HCF_MAX_ALGO_NAME_LEN];
} HcfSymmKeyGeneratorImpl;

static const SymKeyGenAbility SYMKEY_ABILITY_SET[] = {
    { HCF_ALG_AES, { HcfSymKeyGeneratorSpiCreate }},
    { HCF_ALG_SM4, { HcfSymKeyGeneratorSpiCreate }},
    { HCF_ALG_DES, { HcfSymKeyGeneratorSpiCreate }},
    { HCF_ALG_3DES, { HcfSymKeyGeneratorSpiCreate }},
    { HCF_ALG_HMAC, { HcfSymKeyGeneratorSpiCreate }},
    { HCF_ALG_CHACHA20, { HcfSymKeyGeneratorSpiCreate }},
    { HCF_ALG_CHACHA20_POLY1305, { HcfSymKeyGeneratorSpiCreate }},
    { HCF_ALG_RC2, { HcfSymKeyGeneratorSpiCreate }},
    { HCF_ALG_RC4, { HcfSymKeyGeneratorSpiCreate }},
    { HCF_ALG_BLOWFISH, { HcfSymKeyGeneratorSpiCreate }},
    { HCF_ALG_CAST, { HcfSymKeyGeneratorSpiCreate }},
};

static const SymKeyGenFuncSet *FindAbility(SymKeyAttr *attr)
{
    if (attr == NULL) {
        LOGE("Attr is null when looking up sym key ability");
        return NULL;
    }
    for (uint32_t i = 0; i < sizeof(SYMKEY_ABILITY_SET) / sizeof(SymKeyGenAbility); i++) {
        if (SYMKEY_ABILITY_SET[i].algo == attr->algo) {
            return &(SYMKEY_ABILITY_SET[i].funcSet);
        }
    }
    LOGE("Algo not support! [Algo]: %{public}d", attr->algo);
    return NULL;
}

static void SetKeyLength(HcfAlgParaValue value, void *attr)
{
    SymKeyAttr *keyAttr = (SymKeyAttr *)attr;

    switch (value) {
        case HCF_ALG_AES_128:
            keyAttr->algo = HCF_ALG_AES;
            keyAttr->keySize = AES_KEY_SIZE_128;
            break;
        case HCF_ALG_AES_192:
            keyAttr->algo = HCF_ALG_AES;
            keyAttr->keySize = AES_KEY_SIZE_192;
            break;
        case HCF_ALG_AES_256:
            keyAttr->algo = HCF_ALG_AES;
            keyAttr->keySize = AES_KEY_SIZE_256;
            break;
        case HCF_ALG_SM4_128:
            keyAttr->algo = HCF_ALG_SM4;
            keyAttr->keySize = SM4_KEY_SIZE_128;
            break;
        case HCF_ALG_3DES_192:
            keyAttr->algo = HCF_ALG_3DES;
            keyAttr->keySize = TRIPLE_DES_KEY_SIZE_192;
            break;
        case HCF_ALG_DES_64:
            keyAttr->algo = HCF_ALG_DES;
            keyAttr->keySize = DES_KEY_SIZE_64;
            break;
        case HCF_ALG_CHACHA20_256:
            keyAttr->algo = HCF_ALG_CHACHA20;
            keyAttr->keySize = CHACHA20_KEY_SIZE_256;
            break;
        default:
            break;
    }
}

static void SetKeyType(HcfAlgParaValue value, void *attr)
{
    SymKeyAttr *keyAttr = (SymKeyAttr *)attr;

    if (value == HCF_ALG_HMAC_DEFAULT) {
        keyAttr->algo = HCF_ALG_HMAC;
    } else if (value == HCF_ALG_RC2_DEFAULT) {
        keyAttr->algo = HCF_ALG_RC2;
        keyAttr->keySize = 0;
    } else if (value == HCF_ALG_RC4_DEFAULT) {
        keyAttr->algo = HCF_ALG_RC4;
        keyAttr->keySize = 0;
    } else if (value == HCF_ALG_BLOWFISH_DEFAULT) {
        keyAttr->algo = HCF_ALG_BLOWFISH;
        keyAttr->keySize = 0;
    } else if (value == HCF_ALG_CAST_DEFAULT) {
        keyAttr->algo = HCF_ALG_CAST;
        keyAttr->keySize = 0;
    }
}

static void SetKeyLenByDigest(HcfAlgParaValue value, void *attr)
{
    SymKeyAttr *keyAttr = (SymKeyAttr *)attr;

    switch (value) {
        case HCF_OPENSSL_DIGEST_SHA1:
            keyAttr->keySize = HMAC_KEY_SIZE_SHA1;
            break;
        case HCF_OPENSSL_DIGEST_SHA224:
            keyAttr->keySize = HMAC_KEY_SIZE_SHA224;
            break;
        case HCF_OPENSSL_DIGEST_SHA256:
        case HCF_OPENSSL_DIGEST_SHA3_256:
            keyAttr->keySize = HMAC_KEY_SIZE_SHA256;
            break;
        case HCF_OPENSSL_DIGEST_SHA384:
        case HCF_OPENSSL_DIGEST_SHA3_384:
            keyAttr->keySize = HMAC_KEY_SIZE_SHA384;
            break;
        case HCF_OPENSSL_DIGEST_SHA512:
        case HCF_OPENSSL_DIGEST_SHA3_512:
            keyAttr->keySize = HMAC_KEY_SIZE_SHA512;
            break;
        case HCF_OPENSSL_DIGEST_SM3:
            keyAttr->keySize = HMAC_KEY_SIZE_SM3;
            break;
        case HCF_OPENSSL_DIGEST_MD5:
            keyAttr->keySize = HMAC_KEY_SIZE_MD5;
            break;
        default:
            // We will ignore the and 'NoHash' inputs
            LOGE("Invalid digest input: NoHash");
            break;
    }
}

static HcfResult OnSetSymKeyParameter(const HcfParaConfig* config, void *attr)
{
    if ((config == NULL) || (attr == NULL)) {
        LOGE("Config or attr is null");
        return HCF_INVALID_PARAMS;
    }
    HcfResult ret = HCF_SUCCESS;
    LOGD("Set Parameter:%{public}s", config->tag);
    LOGD("Set Parameter:%{public}d", config->paraType);
    LOGD("Set Parameter:%{public}d", config->paraValue);
    switch (config->paraType) {
        case HCF_ALG_KEY_TYPE:
            SetKeyLength(config->paraValue, attr);
            break;
        case HCF_ALG_TYPE:
            SetKeyType(config->paraValue, attr);
            break;
        case HCF_ALG_DIGEST:
            SetKeyLenByDigest(config->paraValue, attr);
            break;
        default:
            LOGE("Unsupported parameter type in sym key gen params");
            ret = HCF_INVALID_PARAMS;
            break;
    }
    return ret;
}

static const char *GetSymKeyGeneratorClass(void)
{
    return "HcfSymKeyGenerator";
}

static const char *GetAlgoName(HcfSymKeyGenerator *self)
{
    if (self == NULL) {
        LOGE("The input self ptr is NULL!");
        return NULL;
    }
    if (!HcfIsClassMatch((HcfObjectBase *)self, GetSymKeyGeneratorClass())) {
        LOGE("Class is not match!");
        return NULL;
    }
    return ((HcfSymmKeyGeneratorImpl *)self)->algoName;
}

static void DestroySymmKeyGenerator(HcfObjectBase *base)
{
    if (base == NULL) {
        return;
    }
    if (!HcfIsClassMatch((HcfObjectBase *)base, GetSymKeyGeneratorClass())) {
        LOGE("Class is not match.");
        return;
    }
    HcfSymmKeyGeneratorImpl *impl = (HcfSymmKeyGeneratorImpl *)base;
    HcfObjDestroy(impl->spiObj);
    impl->spiObj = NULL;
    HcfFree(impl);
}

static HcfResult GenerateSymmKey(HcfSymKeyGenerator *self, HcfSymKey **symmKey)
{
    if ((self == NULL) || (symmKey == NULL)) {
        LOGE("Invalid input parameter.");
        return HCF_INVALID_PARAMS;
    }

    if (!HcfIsClassMatch((HcfObjectBase *)self, GetSymKeyGeneratorClass())) {
        LOGE("Class is not match.");
        return HCF_INVALID_PARAMS;
    }
    HcfSymmKeyGeneratorImpl *impl = (HcfSymmKeyGeneratorImpl *)self;
    if (strcmp(impl->algoName, "RC2") == 0 || strcmp(impl->algoName, "RC4") == 0 ||
        strcmp(impl->algoName, "CAST") == 0 || strcmp(impl->algoName, "Blowfish") == 0) {
        LOGE("Algorithm does not support generateSymKey, use convertSymKey only.");
        return HCF_ERR_INVALID_CALL;
    }
    if (impl->spiObj == NULL || impl->spiObj->engineGenerateSymmKey == NULL) {
        LOGE("Invalid input parameter.");
        return HCF_INVALID_PARAMS;
    }

    return impl->spiObj->engineGenerateSymmKey(impl->spiObj, symmKey);
}

static HcfResult ConvertSymmKey(HcfSymKeyGenerator *self, const HcfBlob *key, HcfSymKey **symmKey)
{
    if ((self == NULL) || (symmKey == NULL) || !HcfIsBlobValid(key)) {
        LOGE("Invalid input parameter.");
        return HCF_INVALID_PARAMS;
    }
    if (!HcfIsClassMatch((HcfObjectBase *)self, GetSymKeyGeneratorClass())) {
        LOGE("Class is not match.");
        return HCF_INVALID_PARAMS;
    }
    HcfSymmKeyGeneratorImpl *impl = (HcfSymmKeyGeneratorImpl *)self;
    if (impl->spiObj == NULL || impl->spiObj->engineConvertSymmKey == NULL) {
        LOGE("Invalid input parameter.");
        return HCF_INVALID_PARAMS;
    }
    return impl->spiObj->engineConvertSymmKey(impl->spiObj, key, symmKey);
}

HcfResult HcfSymKeyGeneratorCreate(const char *algoName, HcfSymKeyGenerator **returnObj)
{
    if (!HcfIsStrValid(algoName, HCF_MAX_ALGO_NAME_LEN) || (returnObj == NULL)) {
        LOGE("Invalid input params while creating symkey!");
        return HCF_INVALID_PARAMS;
    }

    SymKeyAttr attr = {0};
    if (ParseAndSetParameter(algoName, (void *)&attr, OnSetSymKeyParameter) != HCF_SUCCESS) {
        LOGE("ParseAndSetParameter Failed!");
        return HCF_NOT_SUPPORT;
    }

    const SymKeyGenFuncSet *funcSet = FindAbility(&attr);
    if (funcSet == NULL) {
        LOGE("FindAbility Failed!");
        return HCF_NOT_SUPPORT;
    }
    HcfSymmKeyGeneratorImpl *returnGenerator = (HcfSymmKeyGeneratorImpl *)HcfMalloc(sizeof(HcfSymmKeyGeneratorImpl), 0);
    if (returnGenerator == NULL) {
        LOGE("Failed to allocate returnGenerator memory!");
        return HCF_ERR_MALLOC;
    }
    if (strcpy_s(returnGenerator->algoName, HCF_MAX_ALGO_NAME_LEN, algoName) != EOK) {
        LOGE("Failed to copy algoName!");
        HcfFree(returnGenerator);
        returnGenerator = NULL;
        return HCF_INVALID_PARAMS;
    }
    HcfSymKeyGeneratorSpi *spiObj = NULL;
    HcfResult res = funcSet->createFunc(&attr, &spiObj);
    if (res != HCF_SUCCESS) {
        LOGE("Failed to create spi object!");
        HcfFree(returnGenerator);
        returnGenerator = NULL;
        return res;
    }
    returnGenerator->base.generateSymKey = GenerateSymmKey;
    returnGenerator->base.convertSymKey = ConvertSymmKey;
    returnGenerator->base.base.destroy = DestroySymmKeyGenerator;
    returnGenerator->base.base.getClass = GetSymKeyGeneratorClass;
    returnGenerator->base.getAlgoName = GetAlgoName;
    returnGenerator->spiObj = spiObj;

    *returnObj = (HcfSymKeyGenerator *)returnGenerator;
    return HCF_SUCCESS;
}
