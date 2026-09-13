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

#include <limits.h>
#include "log.h"
#include "memory.h"
#include "result.h"
#include "securec.h"
#include "utils.h"
#include "sym_common_defines.h"
#include "openssl_adapter.h"
#include "openssl_common.h"

#define MAX_KEY_STR_SIZE 12
#define MAX_KEY_LEN 4096
#define KEY_BIT 8
#define AES_ALG_NAME "AES"
#define SM4_ALG_NAME "SM4"
#define DES_ALG_NAME "DES"
#define TRIPLE_DES_ALG_NAME "3DES"
#define HMAC_ALG_NAME "HMAC"
#define CHACHA20_ALG_NAME "ChaCha20"
#define CHACHA20_POLY1305_ALG_NAME "ChaCha20_Poly1305"
#define RC2_ALG_NAME "RC2"
#define RC4_ALG_NAME "RC4"
#define BLOWFISH_ALG_NAME "Blowfish"
#define CAST_ALG_NAME "CAST"
#define RC2_KEY_BYTES_MIN  1
#define RC2_KEY_BYTES_MAX  128
#define RC4_KEY_BYTES_MIN  1
#define RC4_KEY_BYTES_MAX  512
#define BF_KEY_BYTES_MIN   4
#define BF_KEY_BYTES_MAX   56
#define CAST_KEY_BYTES_MIN 5
#define CAST_KEY_BYTES_MAX 16
#define BIT_PER_BYTE 8

typedef struct {
    HcfSymKeyGeneratorSpi base;
    SymKeyAttr attr;
} HcfSymKeyGeneratorSpiOpensslImpl;

static HcfResult GetEncoded(HcfKey *self, HcfBlob *key)
{
    if ((self == NULL) || (key == NULL)) {
        LOGE("Invalid input parameter!");
        return HCF_INVALID_PARAMS;
    }
    if (!HcfIsClassMatch((const HcfObjectBase *)self, OPENSSL_SYM_KEY_CLASS)) {
        LOGE("Class is not match.");
        return HCF_INVALID_PARAMS;
    }
    SymKeyImpl *impl = (SymKeyImpl *)self;
    if ((impl->keyMaterial.data == NULL) || (impl->keyMaterial.len == 0)) {
        LOGE("Invalid SymKeyImpl parameter!");
        return HCF_INVALID_PARAMS;
    }
    key->data = (uint8_t *)HcfMalloc(impl->keyMaterial.len, 0);
    if (key->data == NULL) {
        LOGE("malloc keyMaterial failed!");
        return HCF_ERR_MALLOC;
    }
    (void)memcpy_s(key->data, impl->keyMaterial.len, impl->keyMaterial.data, impl->keyMaterial.len);
    key->len = impl->keyMaterial.len;
    return HCF_SUCCESS;
}

static void ClearMem(HcfSymKey *self)
{
    if (self == NULL) {
        LOGE("symKey is NULL.");
        return;
    }
    if (!HcfIsClassMatch((const HcfObjectBase *)self, OPENSSL_SYM_KEY_CLASS)) {
        LOGE("Class is not match.");
        return;
    }
    SymKeyImpl *impl = (SymKeyImpl *)self;
    if ((impl->keyMaterial.data != NULL) && (impl->keyMaterial.len > 0)) {
        (void)memset_s(impl->keyMaterial.data, impl->keyMaterial.len, 0, impl->keyMaterial.len);
    }
}

static const char *GetFormat(HcfKey *self)
{
    if (self == NULL) {
        LOGE("Invalid input parameter!");
        return NULL;
    }
    if (!HcfIsClassMatch((const HcfObjectBase *)self, OPENSSL_SYM_KEY_CLASS)) {
        LOGE("Class is not match.");
        return NULL;
    }

    return "PKCS#8";
}

static const char *GetSymKeyGeneratorClass(void)
{
    return OPENSSL_SYM_GENERATOR_CLASS;
}

static const char *GetSymKeyClass(void)
{
    return OPENSSL_SYM_KEY_CLASS;
}

static const char *GetAlgorithm(HcfKey *self)
{
    if (self == NULL) {
        LOGE("Invalid input parameter!");
        return NULL;
    }
    if (!HcfIsClassMatch((const HcfObjectBase *)self, OPENSSL_SYM_KEY_CLASS)) {
        LOGE("Class is not match.");
        return NULL;
    }
    SymKeyImpl *impl = (SymKeyImpl *)self;
    return (const char *)impl->algoName;
}

static HcfResult GetSymKeySize(HcfKey *self, int *keySize)
{
    if (self == NULL || keySize == NULL) {
        LOGE("Invalid input parameter!");
        return HCF_ERR_PARAMETER_CHECK_FAILED;
    }
    if (!HcfIsClassMatch((const HcfObjectBase *)self, OPENSSL_SYM_KEY_CLASS)) {
        LOGE("Class is not match.");
        return HCF_ERR_PARAMETER_CHECK_FAILED;
    }
    SymKeyImpl *impl = (SymKeyImpl *)self;
    /* key size in bits = key material length (bytes) * 8 */
    if (impl->keyMaterial.len > (size_t)(INT_MAX / BIT_PER_BYTE)) {
        LOGE("Key material length overflow.");
        return HCF_ERR_PARAMETER_CHECK_FAILED;
    }
    *keySize = (int)(impl->keyMaterial.len * BIT_PER_BYTE);
    return HCF_SUCCESS;
}

static HcfResult RandomSymmKey(int32_t keyLen, HcfBlob *symmKey)
{
    uint8_t *keyMaterial = (uint8_t *)HcfMalloc(keyLen, 0);
    if (keyMaterial == NULL) {
        LOGE("keyMaterial malloc failed!");
        return HCF_ERR_MALLOC;
    }
    int ret = OpensslRandPrivBytesEx(NULL, keyMaterial, keyLen);
    if (ret != HCF_OPENSSL_SUCCESS) {
        LOGE("RAND_bytes failed!");
        HcfPrintOpensslError();
        HcfFree(keyMaterial);
        keyMaterial = NULL;
        return HCF_ERR_CRYPTO_OPERATION;
    }
    symmKey->data = keyMaterial;
    symmKey->len = keyLen;
    return HCF_SUCCESS;
}

static HcfResult HcfSymmKeySpiCreate(int32_t keyLen, SymKeyImpl *symKey)
{
    if ((keyLen == 0) || (symKey == NULL)) {
        LOGE("Invalid input parameter!");
        return HCF_INVALID_PARAMS;
    }
    HcfResult res = RandomSymmKey(keyLen, &symKey->keyMaterial);
    if (res != HCF_SUCCESS) {
        LOGE("Failed to generate random symmetric key.");
        return res;
    }
    return res;
}

static HcfResult HcfDesSymmKeySpiCreate(int32_t keyLen, SymKeyImpl *symKey)
{
    if ((keyLen == 0) || (symKey == NULL)) {
        LOGE("Invalid input parameter!");
        return HCF_INVALID_PARAMS;
    }
    uint8_t *keyMaterial = (uint8_t *)HcfMalloc(keyLen, 0);
    if (keyMaterial == NULL) {
        LOGE("keyMaterial malloc failed!");
        return HCF_ERR_MALLOC;
    }
    EVP_CIPHER_CTX *ctx = OpensslEvpCipherCtxNew();
    if (ctx == NULL) {
        LOGE("Failed to create EVP_CIPHER_CTX!");
        HcfFree(keyMaterial);
        keyMaterial = NULL;
        return HCF_ERR_CRYPTO_OPERATION;
    }
    if (OpensslEvpEncryptInit(ctx, OpensslEvpDesEcb(), NULL, NULL) != HCF_OPENSSL_SUCCESS) {
        HcfPrintOpensslError();
        HcfFree(keyMaterial);
        keyMaterial = NULL;
        EVP_CIPHER_CTX_free(ctx);
        LOGE("EVP_CipherInit failed!");
        return HCF_ERR_CRYPTO_OPERATION;
    }
    if (OpensslEvpCipherCtxCtrl(ctx, EVP_CTRL_RAND_KEY, 0, keyMaterial) != 1) {
        HcfPrintOpensslError();
        LOGE("EVP_CIPHER_CTX_ctrl failed to validate DES key!");
        EVP_CIPHER_CTX_free(ctx);
        HcfFree(keyMaterial);
        keyMaterial = NULL;
        return HCF_INVALID_PARAMS;
    }

    EVP_CIPHER_CTX_free(ctx);
    symKey->keyMaterial.data = keyMaterial;
    symKey->keyMaterial.len = (size_t)keyLen;
    return HCF_SUCCESS;
}

static void DestroySymKeyGeneratorSpi(HcfObjectBase *base)
{
    if (base == NULL) {
        LOGE("Invalid input parameter!");
        return;
    }
    if (!HcfIsClassMatch(base, GetSymKeyGeneratorClass())) {
        LOGE("Class is not match!");
        return;
    }
    HcfFree(base);
}

static void DestroySymKeySpi(HcfObjectBase *base)
{
    if (base == NULL) {
        LOGE("Invalid input parameter!");
        return;
    }
    if (!HcfIsClassMatch(base, OPENSSL_SYM_KEY_CLASS)) {
        LOGE("Class is not match.");
        return;
    }
    SymKeyImpl *impl = (SymKeyImpl *)base;
    if (impl->algoName != NULL) {
        HcfFree(impl->algoName);
        impl->algoName = NULL;
    }
    if (impl->keyMaterial.data != NULL) {
        (void)memset_s(impl->keyMaterial.data, impl->keyMaterial.len, 0, impl->keyMaterial.len);
        HcfFree(impl->keyMaterial.data);
        impl->keyMaterial.data = NULL;
        impl->keyMaterial.len = 0;
    }
    HcfFree(impl);
}

static char *GetAlgoNameType(HcfAlgValue type)
{
    switch (type) {
        case HCF_ALG_AES:
            return AES_ALG_NAME;
        case HCF_ALG_SM4:
            return SM4_ALG_NAME;
        case HCF_ALG_DES:
            return DES_ALG_NAME;
        case HCF_ALG_3DES:
            return TRIPLE_DES_ALG_NAME;
        case HCF_ALG_HMAC:
            return HMAC_ALG_NAME;
        case HCF_ALG_CHACHA20:
            return CHACHA20_ALG_NAME;
        case HCF_ALG_CHACHA20_POLY1305:
            return CHACHA20_POLY1305_ALG_NAME;
        case HCF_ALG_RC2:
            return RC2_ALG_NAME;
        case HCF_ALG_RC4:
            return RC4_ALG_NAME;
        case HCF_ALG_BLOWFISH:
            return BLOWFISH_ALG_NAME;
        case HCF_ALG_CAST:
            return CAST_ALG_NAME;
        default:
            LOGE("unsupport type!");
            break;
    }
    return NULL;
}

static char *GetAlgoName(HcfSymKeyGeneratorSpiOpensslImpl *impl, int keySize)
{
    char keySizeChar[MAX_KEY_STR_SIZE] = { 0 };
    if (sprintf_s(keySizeChar, MAX_KEY_STR_SIZE, "%d", keySize) < 0) {
        LOGE("Invalid input parameter!");
        return NULL;
    }
    char *nameType = GetAlgoNameType(impl->attr.algo);
    if (nameType == NULL) {
        LOGE("get algo name type failed!");
        return NULL;
    }
    int32_t nameSize = strlen(nameType);
    char *algoName = (char *)HcfMalloc(MAX_KEY_STR_SIZE, 0);
    if (algoName == NULL) {
        LOGE("algoName malloc failed!");
        return NULL;
    }
    if (strcpy_s(algoName, MAX_KEY_STR_SIZE, nameType) != EOK) {
        LOGE("algoName strcpy_s failed!");
        goto clearup;
    }
    if (impl->attr.algo == HCF_ALG_CHACHA20 || impl->attr.algo == HCF_ALG_RC4 ||
        impl->attr.algo == HCF_ALG_BLOWFISH || impl->attr.algo == HCF_ALG_CAST) {
        return algoName;
    }
    if (strcpy_s(algoName + nameSize, MAX_KEY_STR_SIZE - nameSize, keySizeChar) != EOK) {
        LOGE("algoName size strcpy_s failed!");
        goto clearup;
    }
    return algoName;
clearup:
    HcfFree(algoName);
    algoName = NULL;
    return NULL;
}

static HcfResult CopySymmKey(const HcfBlob *srcKey, HcfBlob *dstKey)
{
    if ((srcKey->data == NULL) || (srcKey->len == 0)) {
        LOGE("Invalid input parameter!");
        return HCF_INVALID_PARAMS;
    }
    uint8_t *keyMaterial = (uint8_t *)HcfMalloc(srcKey->len, 0);
    if (keyMaterial == NULL) {
        LOGE("keyMaterial malloc failed!");
        return HCF_ERR_MALLOC;
    }
    (void)memcpy_s(keyMaterial, srcKey->len, srcKey->data, srcKey->len);
    dstKey->data = keyMaterial;
    dstKey->len = srcKey->len;
    return HCF_SUCCESS;
}

static HcfResult GenerateSymmKey(HcfSymKeyGeneratorSpi *self, HcfSymKey **symmKey)
{
    if ((self == NULL) || (symmKey == NULL)) {
        LOGE("Invalid input parameter!");
        return HCF_INVALID_PARAMS;
    }
    if (!HcfIsClassMatch((const HcfObjectBase *)self, GetSymKeyGeneratorClass())) {
        LOGE("Class is not match!");
        return HCF_INVALID_PARAMS;
    }
    HcfSymKeyGeneratorSpiOpensslImpl *impl = (HcfSymKeyGeneratorSpiOpensslImpl *)self;

    if (impl->attr.algo == HCF_ALG_RC2 || impl->attr.algo == HCF_ALG_RC4 ||
        impl->attr.algo == HCF_ALG_CAST || impl->attr.algo == HCF_ALG_BLOWFISH) {
        LOGE("Algorithm does not support generateSymKey.");
        return HCF_ERR_INVALID_CALL;
    }
    SymKeyImpl *returnSymmKey = (SymKeyImpl *)HcfMalloc(sizeof(SymKeyImpl), 0);
    if (returnSymmKey == NULL) {
        LOGE("Failed to allocate returnKeyPair memory!");
        return HCF_ERR_MALLOC;
    }
    HcfResult res = HCF_SUCCESS;
    if (impl->attr.algo == HCF_ALG_DES) {
        res = HcfDesSymmKeySpiCreate(impl->attr.keySize / KEY_BIT, returnSymmKey);
        if (res != HCF_SUCCESS) {
            LOGE("Failed to create DES symmetric key SPI.");
            HcfFree(returnSymmKey);
            returnSymmKey = NULL;
            return res;
        }
    } else {
        res = HcfSymmKeySpiCreate(impl->attr.keySize / KEY_BIT, returnSymmKey);
        if (res != HCF_SUCCESS) {
            LOGE("Failed to create symmetric key SPI.");
            HcfFree(returnSymmKey);
            returnSymmKey = NULL;
            return res;
        }
    }

    returnSymmKey->algoName = GetAlgoName(impl, impl->attr.keySize);
    returnSymmKey->key.clearMem = ClearMem;
    returnSymmKey->key.key.getEncoded = GetEncoded;
    returnSymmKey->key.key.getFormat = GetFormat;
    returnSymmKey->key.key.getAlgorithm = GetAlgorithm;
    returnSymmKey->key.key.getKeySize = GetSymKeySize;
    returnSymmKey->key.key.base.destroy = DestroySymKeySpi;
    returnSymmKey->key.key.base.getClass = GetSymKeyClass;
    *symmKey = (HcfSymKey *)returnSymmKey;
    return res;
}

static bool IsBlobKeyLenValid(SymKeyAttr attr, const HcfBlob *key)
{
    if ((key->len == 0) || (key->len > MAX_KEY_LEN)) {
        return false;
    }

    if (attr.keySize == 0) {
        if (attr.algo == HCF_ALG_RC2) {
            return (key->len >= RC2_KEY_BYTES_MIN && key->len <= RC2_KEY_BYTES_MAX);
        }
        if (attr.algo == HCF_ALG_RC4) {
            return (key->len >= RC4_KEY_BYTES_MIN && key->len <= RC4_KEY_BYTES_MAX);
        }
        if (attr.algo == HCF_ALG_BLOWFISH) {
            return (key->len >= BF_KEY_BYTES_MIN && key->len <= BF_KEY_BYTES_MAX);
        }
        if (attr.algo == HCF_ALG_CAST) {
            return (key->len >= CAST_KEY_BYTES_MIN && key->len <= CAST_KEY_BYTES_MAX);
        }
    }

    if ((attr.keySize / KEY_BIT) == (int32_t)key->len) {
        return true;
    }

    if ((attr.algo == HCF_ALG_HMAC) && (attr.keySize == 0)) {
        return true;
    }

    return false;
}

static HcfResult ConvertSymmKey(HcfSymKeyGeneratorSpi *self, const HcfBlob *key, HcfSymKey **symmKey)
{
    if ((self == NULL) || (symmKey == NULL) || !HcfIsBlobValid(key)) {
        LOGE("Invalid input parameter.");
        return HCF_INVALID_PARAMS;
    }
    if (!HcfIsClassMatch((const HcfObjectBase *)self, GetSymKeyGeneratorClass())) {
        LOGE("Class is not match.");
        return HCF_INVALID_PARAMS;
    }
    HcfSymKeyGeneratorSpiOpensslImpl *impl = (HcfSymKeyGeneratorSpiOpensslImpl *)self;

    if (!IsBlobKeyLenValid(impl->attr, key)) {
        LOGE("Invalid param: input key length is invalid!");
        return HCF_INVALID_PARAMS;
    }

    SymKeyImpl *returnSymmKey = (SymKeyImpl *)HcfMalloc(sizeof(SymKeyImpl), 0);
    if (returnSymmKey == NULL) {
        LOGE("Failed to allocate returnKeyPair memory!");
        return HCF_ERR_MALLOC;
    }
    HcfResult res = CopySymmKey(key, &returnSymmKey->keyMaterial);
    if (res != HCF_SUCCESS) {
        LOGE("Failed to copy symmetric key.");
        HcfFree(returnSymmKey);
        returnSymmKey = NULL;
        return res;
    }
    int keySize = impl->attr.keySize;
    if (impl->attr.algo == HCF_ALG_HMAC && keySize == 0) {
        keySize = (int)returnSymmKey->keyMaterial.len * KEY_BIT;
    }

    if (keySize == 0 && (impl->attr.algo == HCF_ALG_RC2 || impl->attr.algo == HCF_ALG_RC4 ||
        impl->attr.algo == HCF_ALG_CAST || impl->attr.algo == HCF_ALG_BLOWFISH)) {
        keySize = (int)returnSymmKey->keyMaterial.len * KEY_BIT;
    }
    returnSymmKey->algoName = GetAlgoName(impl, keySize);
    returnSymmKey->key.clearMem = ClearMem;
    returnSymmKey->key.key.getEncoded = GetEncoded;
    returnSymmKey->key.key.getFormat = GetFormat;
    returnSymmKey->key.key.getAlgorithm = GetAlgorithm;
    returnSymmKey->key.key.getKeySize = GetSymKeySize;
    returnSymmKey->key.key.base.destroy = DestroySymKeySpi;
    returnSymmKey->key.key.base.getClass = GetSymKeyClass;
    *symmKey = (HcfSymKey *)returnSymmKey;
    return HCF_SUCCESS;
}

HcfResult HcfSymKeyGeneratorSpiCreate(SymKeyAttr *attr, HcfSymKeyGeneratorSpi **generator)
{
    if ((attr == NULL) || (generator == NULL)) {
        LOGE("Invalid input parameter.");
        return HCF_INVALID_PARAMS;
    }
    HcfSymKeyGeneratorSpiOpensslImpl *returnGenerator = (HcfSymKeyGeneratorSpiOpensslImpl *)HcfMalloc(
        sizeof(HcfSymKeyGeneratorSpiOpensslImpl), 0);
    if (returnGenerator == NULL) {
        LOGE("Failed to allocate returnGenerator memory!");
        return HCF_ERR_MALLOC;
    }
    (void)memcpy_s(&returnGenerator->attr, sizeof(SymKeyAttr), attr, sizeof(SymKeyAttr));
    returnGenerator->base.engineGenerateSymmKey = GenerateSymmKey;
    returnGenerator->base.engineConvertSymmKey = ConvertSymmKey;
    returnGenerator->base.base.destroy = DestroySymKeyGeneratorSpi;
    returnGenerator->base.base.getClass = GetSymKeyGeneratorClass;
    *generator = (HcfSymKeyGeneratorSpi *)returnGenerator;
    return HCF_SUCCESS;
}
