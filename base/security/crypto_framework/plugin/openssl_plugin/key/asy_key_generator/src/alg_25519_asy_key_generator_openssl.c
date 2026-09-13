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

#include "alg_25519_asy_key_generator_openssl.h"

#include "securec.h"

#include <openssl/evp.h>
#include <string.h>

#include "detailed_alg_25519_key_params.h"
#include "log.h"
#include "memory.h"
#include "openssl_adapter.h"
#include "openssl_class.h"
#include "openssl_common.h"
#include "utils.h"

#define OPENSSL_ED25519_GENERATOR_CLASS "OPENSSL.ED25519.KEYGENERATOR"
#define OPENSSL_X25519_GENERATOR_CLASS "OPENSSL.X25519.KEYGENERATOR"
#define OPENSSL_ALG_25519_PUBKEY_FORMAT "X.509"
#define OPENSSL_ALG_25519_PRIKEY_FORMAT "PKCS#8"
#define ALGORITHM_NAME_ALG25519 "Alg25519"
#define ALGORITHM_NAME_ED25519 "Ed25519"
#define ALGORITHM_NAME_X25519 "X25519"
#define ALG_25519_KEY_SIZE_BYTES 32
#define BIT_PER_BYTE 8

typedef struct {
    HcfAsyKeyGeneratorSpi base;
} HcfAsyKeyGeneratorSpiAlg25519OpensslImpl;

static const char *GetEd25519KeyGeneratorSpiClass(void)
{
    return OPENSSL_ED25519_GENERATOR_CLASS;
}

static const char *GetX25519KeyGeneratorSpiClass(void)
{
    return OPENSSL_X25519_GENERATOR_CLASS;
}

static const char *GetAlg25519KeyPairClass(void)
{
    return OPENSSL_ALG25519_KEYPAIR_CLASS;
}

static const char *GetAlg25519PubKeyClass(void)
{
    return OPENSSL_ALG25519_PUBKEY_CLASS;
}

static const char *GetAlg25519PriKeyClass(void)
{
    return OPENSSL_ALG25519_PRIKEY_CLASS;
}

static void DestroyAlg25519KeyGeneratorSpiImpl(HcfObjectBase *self)
{
    if ((self == NULL) || (self->getClass() == NULL)) {
        LOGE("Invalid input parameter.");
        return;
    }

    if (strcmp(self->getClass(), GetX25519KeyGeneratorSpiClass()) == 0) {
        HcfFree(self);
        return;
    }

    if (strcmp(self->getClass(), GetEd25519KeyGeneratorSpiClass()) == 0) {
        HcfFree(self);
        return;
    }
    LOGE("Invalid input parameter.");
}

static void DestroyAlg25519PubKey(HcfObjectBase *self)
{
    if (self == NULL) {
        LOGE("Invalid input parameter.");
        return;
    }
    if (!HcfIsClassMatch(self, GetAlg25519PubKeyClass())) {
        LOGE("Invalid class of self.");
        return;
    }
    HcfOpensslAlg25519PubKey *impl = (HcfOpensslAlg25519PubKey *)self;
    OpensslEvpPkeyFree(impl->pkey);
    impl->pkey = NULL;
    HcfFree(impl);
}

static void DestroyAlg25519PriKey(HcfObjectBase *self)
{
    if (self == NULL) {
        LOGE("Invalid input parameter.");
        return;
    }
    if (!HcfIsClassMatch(self, GetAlg25519PriKeyClass())) {
        LOGE("Invalid class of self.");
        return;
    }
    HcfOpensslAlg25519PriKey *impl = (HcfOpensslAlg25519PriKey *)self;
    OpensslEvpPkeyFree(impl->pkey);
    impl->pkey = NULL;
    HcfFree(impl);
}

static void DestroyAlg25519KeyPair(HcfObjectBase *self)
{
    if (self == NULL) {
        LOGE("Invalid input parameter.");
        return;
    }
    if (!HcfIsClassMatch(self, GetAlg25519KeyPairClass())) {
        LOGE("Invalid class of self.");
        return;
    }
    HcfOpensslAlg25519KeyPair *impl = (HcfOpensslAlg25519KeyPair *)self;
    DestroyAlg25519PubKey((HcfObjectBase *)impl->base.pubKey);
    impl->base.pubKey = NULL;
    DestroyAlg25519PriKey((HcfObjectBase *)impl->base.priKey);
    impl->base.priKey = NULL;
    HcfFree(self);
}

static const char *GetAlg25519PubKeyAlgorithm(HcfKey *self)
{
    if (self == NULL) {
        LOGE("Invalid input parameter.");
        return NULL;
    }
    if (!HcfIsClassMatch((HcfObjectBase *)self, GetAlg25519PubKeyClass())) {
        LOGE("Invalid class of self.");
        return NULL;
    }

    HcfOpensslAlg25519PubKey *impl = (HcfOpensslAlg25519PubKey *)self;
    if (impl->type == EVP_PKEY_ED25519) {
        return ALGORITHM_NAME_ED25519;
    }

    return ALGORITHM_NAME_X25519;
}

static const char *GetAlg25519PriKeyAlgorithm(HcfKey *self)
{
    if (self == NULL) {
        LOGE("Invalid input parameter.");
        return NULL;
    }
    if (!HcfIsClassMatch((HcfObjectBase *)self, GetAlg25519PriKeyClass())) {
        LOGE("Invalid class of self.");
        return NULL;
    }

    HcfOpensslAlg25519PriKey *impl = (HcfOpensslAlg25519PriKey *)self;
    if (impl->type == EVP_PKEY_ED25519) {
        return ALGORITHM_NAME_ED25519;
    }

    return ALGORITHM_NAME_X25519;
}

static HcfResult GetAlg25519PubKeyEncoded(HcfKey *self, HcfBlob *returnBlob)
{
    if ((self == NULL) || (returnBlob == NULL)) {
        LOGE("Invalid input parameter.");
        return HCF_INVALID_PARAMS;
    }
    if (!HcfIsClassMatch((HcfObjectBase *)self, GetAlg25519PubKeyClass())) {
        LOGE("Invalid class of self.");
        return HCF_INVALID_PARAMS;
    }
    HcfOpensslAlg25519PubKey *impl = (HcfOpensslAlg25519PubKey *)self;
    if (impl->pkey == NULL) {
        LOGE("pkey is NULL.");
        return HCF_INVALID_PARAMS;
    }
    unsigned char *returnData = NULL;
    int len = OpensslI2dPubKey(impl->pkey, &returnData);
    if (len <= 0) {
        LOGE("Call i2d_PUBKEY failed");
        HcfPrintOpensslError();
        return HCF_ERR_CRYPTO_OPERATION;
    }
    returnBlob->data = returnData;
    returnBlob->len = len;
    return HCF_SUCCESS;
}

static HcfResult GetAlg25519PubKeyEncodedPem(HcfKey *self, const char *format, char **returnString)
{
    (void)self;
    (void)format;
    (void)returnString;
    return HCF_INVALID_PARAMS;
}

static HcfResult GetAlg25519PriKeyEncoded(HcfKey *self, HcfBlob *returnBlob)
{
    if ((self == NULL) || (returnBlob == NULL)) {
        LOGE("Invalid input parameter.");
        return HCF_INVALID_PARAMS;
    }
    if (!HcfIsClassMatch((HcfObjectBase *)self, GetAlg25519PriKeyClass())) {
        LOGE("Invalid class of self.");
        return HCF_INVALID_PARAMS;
    }
    HcfOpensslAlg25519PriKey *impl = (HcfOpensslAlg25519PriKey *)self;
    if (impl->pkey == NULL) {
        LOGE("pkey is NULL.");
        return HCF_INVALID_PARAMS;
    }
    unsigned char *returnData = NULL;
    int len = OpensslI2dPrivateKey(impl->pkey, &returnData);
    if (len <= 0) {
        LOGE("Call i2d_PrivateKey failed");
        HcfPrintOpensslError();
        return HCF_ERR_CRYPTO_OPERATION;
    }
    returnBlob->data = returnData;
    returnBlob->len = len;
    return HCF_SUCCESS;
}

static HcfResult GetAlg25519PriKeyEncodedPem(const HcfPriKey *self, HcfParamsSpec *paramsSpec, const char *format,
    char **returnString)
{
    (void)self;
    (void)paramsSpec;
    (void)format;
    (void)returnString;
    return HCF_INVALID_PARAMS;
}

static HcfResult GetAlg25519PubKeySize(HcfKey *self, int *keySize)
{
    if (self == NULL || keySize == NULL) {
        LOGE("Invalid input parameter.");
        return HCF_ERR_PARAMETER_CHECK_FAILED;
    }
    if (!HcfIsClassMatch((HcfObjectBase *)self, GetAlg25519PubKeyClass())) {
        LOGE("Class not match.");
        return HCF_ERR_PARAMETER_CHECK_FAILED;
    }
    *keySize = ALG_25519_KEY_SIZE_BYTES * BIT_PER_BYTE;
    return HCF_SUCCESS;
}

static HcfResult GetAlg25519PriKeySize(HcfKey *self, int *keySize)
{
    if (self == NULL || keySize == NULL) {
        LOGE("Invalid input parameter.");
        return HCF_ERR_PARAMETER_CHECK_FAILED;
    }
    if (!HcfIsClassMatch((HcfObjectBase *)self, GetAlg25519PriKeyClass())) {
        LOGE("Class not match.");
        return HCF_ERR_PARAMETER_CHECK_FAILED;
    }
    *keySize = ALG_25519_KEY_SIZE_BYTES * BIT_PER_BYTE;
    return HCF_SUCCESS;
}

static const char *GetAlg25519PubKeyFormat(HcfKey *self)
{
    if (self == NULL) {
        LOGE("Invalid input parameter.");
        return NULL;
    }
    if (!HcfIsClassMatch((HcfObjectBase *)self, GetAlg25519PubKeyClass())) {
        LOGE("Invalid class of self.");
        return NULL;
    }
    return OPENSSL_ALG_25519_PUBKEY_FORMAT;
}

static const char *GetAlg25519PriKeyFormat(HcfKey *self)
{
    if (self == NULL) {
        LOGE("Invalid input parameter.");
        return NULL;
    }
    if (!HcfIsClassMatch((HcfObjectBase *)self, GetAlg25519PriKeyClass())) {
        LOGE("Invalid class of self.");
        return NULL;
    }
    return OPENSSL_ALG_25519_PRIKEY_FORMAT;
}

static HcfResult GetAlg25519PubKey(EVP_PKEY *pubKey, HcfBigInteger *returnBigInteger)
{
    size_t len = 0;
    if (!OpensslEvpPkeyGetRawPublicKey(pubKey, NULL, &len)) {
        LOGE("Get len failed.");
        return HCF_ERR_CRYPTO_OPERATION;
    }
    returnBigInteger->data = (unsigned char *)HcfMalloc(len, 0);
    if (returnBigInteger->data == NULL) {
        LOGE("Failed to allocate returnBigInteger memory.");
        return HCF_ERR_MALLOC;
    }
    if (!OpensslEvpPkeyGetRawPublicKey(pubKey, returnBigInteger->data, &len)) {
        LOGE("Get data failed.");
        HcfFree(returnBigInteger->data);
        returnBigInteger->data = NULL;
        return HCF_ERR_CRYPTO_OPERATION;
    }
    returnBigInteger->len = len;
    return HCF_SUCCESS;
}

static HcfResult CheckEvpKeyTypeFromAlg25519PubKey(EVP_PKEY *alg25519Pk, const AsyKeySpecItem item)
{
    int type = OpensslEvpPkeyBaseId(alg25519Pk);
    if (type != EVP_PKEY_ED25519 && type != EVP_PKEY_X25519) {
        LOGE("Invalid pkey type.");
        return HCF_INVALID_PARAMS;
    }
    if ((type == EVP_PKEY_ED25519 && item != ED25519_PK_BN) ||
        (type == EVP_PKEY_X25519 && item != X25519_PK_BN)) {
        LOGE("Invalid AsyKeySpecItem.");
        return HCF_INVALID_PARAMS;
    }
    return HCF_SUCCESS;
}

static HcfResult CheckEvpKeyTypeFromAlg25519PriKey(EVP_PKEY *alg25519Sk, const AsyKeySpecItem item)
{
    int type = OpensslEvpPkeyBaseId(alg25519Sk);
    if (type != EVP_PKEY_ED25519 && type != EVP_PKEY_X25519) {
        LOGE("Invalid pkey type.");
        return HCF_INVALID_PARAMS;
    }
    if ((type == EVP_PKEY_ED25519 && item != ED25519_SK_BN) ||
        (type == EVP_PKEY_X25519 && item != X25519_SK_BN)) {
        LOGE("Invalid AsyKeySpecItem.");
        return HCF_INVALID_PARAMS;
    }
    return HCF_SUCCESS;
}

static HcfResult GetBigIntegerSpecFromAlg25519PubKey(const HcfPubKey *self, const AsyKeySpecItem item,
    HcfBigInteger *returnBigInteger)
{
    if (self == NULL || returnBigInteger == NULL) {
        LOGE("Invalid input parameter.");
        return HCF_INVALID_PARAMS;
    }
    if (!HcfIsClassMatch((HcfObjectBase *)self, GetAlg25519PubKeyClass())) {
        LOGE("Invalid class of self.");
        return HCF_INVALID_PARAMS;
    }
    HcfResult ret = HCF_INVALID_PARAMS;
    HcfOpensslAlg25519PubKey *impl = (HcfOpensslAlg25519PubKey *)self;
    EVP_PKEY *alg25519Pk = impl->pkey;
    if (alg25519Pk == NULL) {
        LOGE("pKey is null.");
        return HCF_INVALID_PARAMS;
    }
    if (CheckEvpKeyTypeFromAlg25519PubKey(alg25519Pk, item) != HCF_SUCCESS) {
        LOGE("Check pKey type failed.");
        return HCF_INVALID_PARAMS;
    }
    if (item == ED25519_PK_BN || item == X25519_PK_BN) {
        ret = GetAlg25519PubKey(alg25519Pk, returnBigInteger);
    } else {
        LOGE("Input item is invalid");
    }
    return ret;
}

static HcfResult GetAlg25519PriKey(EVP_PKEY *priKey, HcfBigInteger *returnBigInteger)
{
    size_t len = 0;
    if (!OpensslEvpPkeyGetRawPrivateKey(priKey, NULL, &len)) {
        LOGE("Get private key length failed.");
        return HCF_ERR_CRYPTO_OPERATION;
    }
    returnBigInteger->data = (unsigned char *)HcfMalloc(len, 0);
    if (returnBigInteger->data == NULL) {
        LOGE("Failed to allocate returnBigInteger memory.");
        return HCF_ERR_MALLOC;
    }
    if (!OpensslEvpPkeyGetRawPrivateKey(priKey, returnBigInteger->data, &len)) {
        LOGE("Get data failed.");
        HcfFree(returnBigInteger->data);
        returnBigInteger->data = NULL;
        return HCF_ERR_CRYPTO_OPERATION;
    }
    returnBigInteger->len = len;
    return HCF_SUCCESS;
}

static HcfResult GetBigIntegerSpecFromAlg25519PriKey(const HcfPriKey *self, const AsyKeySpecItem item,
    HcfBigInteger *returnBigInteger)
{
    if (self == NULL || returnBigInteger == NULL) {
        LOGE("Invalid input parameter.");
        return HCF_INVALID_PARAMS;
    }
    if (!HcfIsClassMatch((HcfObjectBase *)self, GetAlg25519PriKeyClass())) {
        LOGE("Invalid class of self.");
        return HCF_INVALID_PARAMS;
    }
    HcfResult ret = HCF_INVALID_PARAMS;
    HcfOpensslAlg25519PriKey *impl = (HcfOpensslAlg25519PriKey *)self;
    EVP_PKEY *alg25519Sk = impl->pkey;
    if (alg25519Sk == NULL) {
        LOGE("pKey is null.");
        return HCF_INVALID_PARAMS;
    }
    if (CheckEvpKeyTypeFromAlg25519PriKey(alg25519Sk, item) != HCF_SUCCESS) {
        LOGE("Check pKey type failed.");
        return HCF_INVALID_PARAMS;
    }
    if (item == ED25519_SK_BN || item == X25519_SK_BN) {
        ret = GetAlg25519PriKey(alg25519Sk, returnBigInteger);
    } else {
        LOGE("Input item is invalid");
    }
    return ret;
}

static HcfResult GetIntSpecFromAlg25519PubKey(const HcfPubKey *self, const AsyKeySpecItem item, int *returnInt)
{
    (void)self;
    (void)returnInt;
    return HCF_NOT_SUPPORT;
}

static HcfResult GetIntSpecFromAlg25519PriKey(const HcfPriKey *self, const AsyKeySpecItem item, int *returnInt)
{
    (void)self;
    (void)returnInt;
    return HCF_NOT_SUPPORT;
}

static HcfResult GetStrSpecFromAlg25519PubKey(const HcfPubKey *self, const AsyKeySpecItem item, char **returnString)
{
    (void)self;
    (void)returnString;
    return HCF_NOT_SUPPORT;
}

static HcfResult GetStrSpecFromAlg25519PriKey(const HcfPriKey *self, const AsyKeySpecItem item, char **returnString)
{
    (void)self;
    (void)returnString;
    return HCF_NOT_SUPPORT;
}

static HcfResult GetAlg25519PriKeyEncodedDer(const HcfPriKey *self, const char *format, HcfBlob *returnBlob)
{
    (void)self;
    (void)format;
    (void)returnBlob;
    return HCF_INVALID_PARAMS;
}

static void ClearAlg25519PriKeyMem(HcfPriKey *self)
{
    if (self == NULL) {
        LOGE("Invalid params.");
        return;
    }
    if (!HcfIsClassMatch((HcfObjectBase *)self, GetAlg25519PriKeyClass())) {
        LOGE("Invalid class of self.");
        return;
    }
    HcfOpensslAlg25519PriKey *impl = (HcfOpensslAlg25519PriKey *)self;
    OpensslEvpPkeyFree(impl->pkey);
    impl->pkey = NULL;
}

static HcfResult GenerateAlg25519EvpKey(int type, EVP_PKEY **ppkey)
{
    EVP_PKEY_CTX *paramsCtx = NULL;
    HcfResult ret = HCF_SUCCESS;
    do {
        paramsCtx = OpensslEvpPkeyCtxNewId(type, NULL);
        if (paramsCtx == NULL) {
            LOGE("Create params ctx failed.");
            ret = HCF_ERR_MALLOC;
            break;
        }
        if (OpensslEvpPkeyKeyGenInit(paramsCtx) != HCF_OPENSSL_SUCCESS) {
            LOGE("Key ctx generate init failed.");
            ret = HCF_ERR_CRYPTO_OPERATION;
            break;
        }
        if (OpensslEvpPkeyKeyGen(paramsCtx, ppkey) != HCF_OPENSSL_SUCCESS) {
            LOGE("Generate pkey failed.");
            ret = HCF_ERR_CRYPTO_OPERATION;
            break;
        }
    } while (0);
    if (paramsCtx != NULL) {
        OpensslEvpPkeyCtxFree(paramsCtx);
    }
    return ret;
}

static HcfResult GetAlg25519PubKeyEncodedDer(const HcfPubKey *self, const char *format, HcfBlob *returnBlob)
{
    (void)self;
    (void)format;
    (void)returnBlob;
    return HCF_INVALID_PARAMS;
}

static HcfResult GetAlg25519PubKeyData(const HcfPubKey *self, uint32_t type, HcfBlob *returnBlob)
{
    (void)self;
    (void)type;
    (void)returnBlob;
    return HCF_ERR_INVALID_CALL;
}

static HcfResult GetAlg25519PriKeyData(const HcfPriKey *self, uint32_t type, HcfBlob *returnBlob)
{
    (void)self;
    (void)type;
    (void)returnBlob;
    return HCF_ERR_INVALID_CALL;
}

static void FillOpensslAlg25519PubKeyFunc(HcfOpensslAlg25519PubKey *pk)
{
    pk->base.base.base.destroy = DestroyAlg25519PubKey;
    pk->base.base.base.getClass = GetAlg25519PubKeyClass;
    pk->base.base.getAlgorithm = GetAlg25519PubKeyAlgorithm;
    pk->base.base.getEncoded = GetAlg25519PubKeyEncoded;
    pk->base.base.getEncodedPem = GetAlg25519PubKeyEncodedPem;
    pk->base.base.getFormat = GetAlg25519PubKeyFormat;
    pk->base.base.getKeySize = GetAlg25519PubKeySize;
    pk->base.getKeyData = GetAlg25519PubKeyData;
    pk->base.getAsyKeySpecBigInteger = GetBigIntegerSpecFromAlg25519PubKey;
    pk->base.getAsyKeySpecInt = GetIntSpecFromAlg25519PubKey;
    pk->base.getAsyKeySpecString = GetStrSpecFromAlg25519PubKey;
    pk->base.getEncodedDer = GetAlg25519PubKeyEncodedDer;
}

static HcfResult CreateAlg25519PubKeyByPrivateKey(EVP_PKEY *pubKey, HcfOpensslAlg25519PubKey **returnPubKey)
{
    HcfOpensslAlg25519PubKey *alg25519PubKey =
        (HcfOpensslAlg25519PubKey *)HcfMalloc(sizeof(HcfOpensslAlg25519PubKey), 0);
    if (alg25519PubKey == NULL) {
        LOGE("Failed to allocate alg25519 public key memory.");
        return HCF_ERR_MALLOC;
    }
    FillOpensslAlg25519PubKeyFunc(alg25519PubKey);
    alg25519PubKey->pkey = pubKey;
    *returnPubKey = alg25519PubKey;
    return HCF_SUCCESS;
}

static HcfResult GetAlg25519PubKeyFromPriKey(const HcfPriKey *self, HcfPubKey **returnPubKey)
{
    if (self == NULL || returnPubKey == NULL) {
        LOGE("Invalid input parameter.");
        return HCF_ERR_PARAMETER_CHECK_FAILED;
    }
    if (!HcfIsClassMatch((HcfObjectBase *)self, GetAlg25519PriKeyClass())) {
        LOGE("Invalid class of self.");
        return HCF_ERR_PARAMETER_CHECK_FAILED;
    }
    HcfOpensslAlg25519PriKey *impl = (HcfOpensslAlg25519PriKey *)self;
    EVP_PKEY *alg25519Sk = impl->pkey;
    if (alg25519Sk == NULL) {
        LOGE("pKey is null.");
        return HCF_ERR_PARAMETER_CHECK_FAILED;
    }
    HcfBigInteger bigInteger;
    if (GetAlg25519PubKey(alg25519Sk, &bigInteger) != HCF_SUCCESS) {
        LOGE("Get alg25519 pubKey failed.");
        return HCF_ERR_CRYPTO_OPERATION;
    }
    HcfOpensslAlg25519PubKey *pubKey = NULL;
    EVP_PKEY *evpPubKey = OpensslEvpPkeyNewRawPublicKey(impl->type, NULL, bigInteger.data, bigInteger.len);
    HcfFree(bigInteger.data);
    bigInteger.data = NULL;
    if (evpPubKey == NULL) {
        LOGE("Create alg25519 pubKey failed.");
        return HCF_ERR_CRYPTO_OPERATION;
    }
    HcfResult ret = CreateAlg25519PubKeyByPrivateKey(evpPubKey, &pubKey);
    if (ret != HCF_SUCCESS) {
        LOGE("Create alg25519 pubKey failed.");
        return ret;
    }
    *returnPubKey = (HcfPubKey *)pubKey;
    return ret;
}

static void FillOpensslAlg25519PriKeyFunc(HcfOpensslAlg25519PriKey *sk)
{
    sk->base.base.base.destroy = DestroyAlg25519PriKey;
    sk->base.base.base.getClass = GetAlg25519PriKeyClass;
    sk->base.base.getAlgorithm = GetAlg25519PriKeyAlgorithm;
    sk->base.base.getEncoded = GetAlg25519PriKeyEncoded;
    sk->base.getEncodedPem = GetAlg25519PriKeyEncodedPem;
    sk->base.getPubKey = GetAlg25519PubKeyFromPriKey;
    sk->base.base.getFormat = GetAlg25519PriKeyFormat;
    sk->base.base.getKeySize = GetAlg25519PriKeySize;
    sk->base.getKeyData = GetAlg25519PriKeyData;
    sk->base.getAsyKeySpecBigInteger = GetBigIntegerSpecFromAlg25519PriKey;
    sk->base.getAsyKeySpecInt = GetIntSpecFromAlg25519PriKey;
    sk->base.getAsyKeySpecString = GetStrSpecFromAlg25519PriKey;
    sk->base.getEncodedDer = GetAlg25519PriKeyEncodedDer;
    sk->base.clearMem = ClearAlg25519PriKeyMem;
}

static HcfResult CreateAlg25519PubKey(EVP_PKEY *pkey, HcfOpensslAlg25519PubKey **returnPubKey)
{
    HcfOpensslAlg25519PubKey *alg25519PubKey =
        (HcfOpensslAlg25519PubKey *)HcfMalloc(sizeof(HcfOpensslAlg25519PubKey), 0);
    if (alg25519PubKey == NULL) {
        LOGE("Failed to allocate alg25519 public key memory.");
        return HCF_ERR_MALLOC;
    }
    FillOpensslAlg25519PubKeyFunc(alg25519PubKey);
    alg25519PubKey->pkey = pkey;
    *returnPubKey = alg25519PubKey;
    return HCF_SUCCESS;
}

static HcfResult CreateAlg25519PriKey(EVP_PKEY *pkey, HcfOpensslAlg25519PriKey **returnPriKey)
{
    HcfOpensslAlg25519PriKey *alg25519PriKey =
        (HcfOpensslAlg25519PriKey *)HcfMalloc(sizeof(HcfOpensslAlg25519PriKey), 0);
    if (alg25519PriKey == NULL) {
        LOGE("Failed to allocate alg25519 private key memory.");
        return HCF_ERR_MALLOC;
    }
    FillOpensslAlg25519PriKeyFunc(alg25519PriKey);
    alg25519PriKey->pkey = pkey;
    *returnPriKey = alg25519PriKey;
    return HCF_SUCCESS;
}

static HcfResult CreateAlg25519KeyPair(const HcfOpensslAlg25519PubKey *pubKey,
    const HcfOpensslAlg25519PriKey *priKey, HcfKeyPair **returnKeyPair)
{
    HcfOpensslAlg25519KeyPair *keyPair =
        (HcfOpensslAlg25519KeyPair *)HcfMalloc(sizeof(HcfOpensslAlg25519KeyPair), 0);
    if (keyPair == NULL) {
        LOGE("Failed to allocate keyPair memory.");
        return HCF_ERR_MALLOC;
    }
    keyPair->base.base.getClass = GetAlg25519KeyPairClass;
    keyPair->base.base.destroy = DestroyAlg25519KeyPair;
    keyPair->base.pubKey = (HcfPubKey *)pubKey;
    keyPair->base.priKey = (HcfPriKey *)priKey;

    *returnKeyPair = (HcfKeyPair *)keyPair;
    return HCF_SUCCESS;
}

static HcfResult GeneratePubKeyByPkey(EVP_PKEY *pkey, HcfOpensslAlg25519PubKey **returnPubKey)
{
    EVP_PKEY *evpPkey = OpensslEvpPkeyDup(pkey);
    if (evpPkey == NULL) {
        LOGE("pkey dup failed");
        HcfPrintOpensslError();
        return HCF_ERR_CRYPTO_OPERATION;
    }
    HcfResult ret = CreateAlg25519PubKey(evpPkey, returnPubKey);
    if (ret != HCF_SUCCESS) {
        LOGE("Create alg25519 public key failed");
        OpensslEvpPkeyFree(evpPkey);
    }
    return ret;
}

static HcfResult GeneratePriKeyByPkey(EVP_PKEY *pkey, HcfOpensslAlg25519PriKey **returnPriKey)
{
    EVP_PKEY *evpPkey = OpensslEvpPkeyDup(pkey);
    if (evpPkey == NULL) {
        LOGE("pkey dup failed");
        HcfPrintOpensslError();
        return HCF_ERR_CRYPTO_OPERATION;
    }
    HcfResult ret = CreateAlg25519PriKey(evpPkey, returnPriKey);
    if (ret != HCF_SUCCESS) {
        LOGE("Create alg25519 private key failed");
        OpensslEvpPkeyFree(evpPkey);
    }
    return ret;
}

static HcfResult GenerateAlg25519PubAndPriKey(int type, HcfOpensslAlg25519PubKey **returnPubKey,
    HcfOpensslAlg25519PriKey **returnPriKey)
{
    EVP_PKEY *pkey = NULL;
    HcfResult ret = GenerateAlg25519EvpKey(type, &pkey);
    if (ret != HCF_SUCCESS) {
        LOGE("Generate alg25519 EVP_PKEY failed.");
        return ret;
    }

    ret = GeneratePubKeyByPkey(pkey, returnPubKey);
    if (ret != HCF_SUCCESS) {
        LOGE("Generate pubkey fail.");
        OpensslEvpPkeyFree(pkey);
        return ret;
    }

    ret = GeneratePriKeyByPkey(pkey, returnPriKey);
    if (ret != HCF_SUCCESS) {
        LOGE("Generate prikey fail.");
        HcfObjDestroy(*returnPubKey);
        *returnPubKey = NULL;
        OpensslEvpPkeyFree(pkey);
        return HCF_ERR_CRYPTO_OPERATION;
    }

    OpensslEvpPkeyFree(pkey);
    return ret;
}

static HcfResult ConvertAlg25519PubKey(const HcfBlob *pubKeyBlob, HcfOpensslAlg25519PubKey **returnPubKey)
{
    const unsigned char *tmpData = (const unsigned char *)(pubKeyBlob->data);
    EVP_PKEY *pkey = OpensslD2iPubKey(NULL, &tmpData, pubKeyBlob->len);
    if (pkey == NULL) {
        LOGE("Call d2i_PUBKEY fail.");
        HcfPrintOpensslError();
        return HCF_ERR_CRYPTO_OPERATION;
    }
    HcfResult ret = CreateAlg25519PubKey(pkey, returnPubKey);
    if (ret != HCF_SUCCESS) {
        LOGE("Create alg25519 public key failed");
        OpensslEvpPkeyFree(pkey);
    }
    return ret;
}

static HcfResult ConvertAlg25519PriKey(int type, const HcfBlob *priKeyBlob,
    HcfOpensslAlg25519PriKey **returnPriKey)
{
    const unsigned char *tmpData = (const unsigned char *)(priKeyBlob->data);
    EVP_PKEY *pkey = OpensslD2iPrivateKey(type, NULL, &tmpData, priKeyBlob->len);
    if (pkey == NULL) {
        LOGE("Call d2i_PrivateKey fail.");
        HcfPrintOpensslError();
        return HCF_ERR_CRYPTO_OPERATION;
    }
    HcfResult ret = CreateAlg25519PriKey(pkey, returnPriKey);
    if (ret != HCF_SUCCESS) {
        LOGE("Create alg25519 private key failed");
        OpensslEvpPkeyFree(pkey);
    }
    return ret;
}

static HcfResult ConvertAlg25519PubAndPriKey(int type, const HcfBlob *pubKeyBlob, const HcfBlob *priKeyBlob,
    HcfOpensslAlg25519PubKey **returnPubKey, HcfOpensslAlg25519PriKey **returnPriKey)
{
    if (pubKeyBlob != NULL) {
        if (ConvertAlg25519PubKey(pubKeyBlob, returnPubKey) != HCF_SUCCESS) {
            LOGE("Convert alg25519 public key failed.");
            return HCF_ERR_CRYPTO_OPERATION;
        }
    }
    if (priKeyBlob != NULL) {
        if (ConvertAlg25519PriKey(type, priKeyBlob, returnPriKey) != HCF_SUCCESS) {
            LOGE("Convert alg25519 private key failed.");
            HcfObjDestroy(*returnPubKey);
            *returnPubKey = NULL;
            return HCF_ERR_CRYPTO_OPERATION;
        }
    }
    return HCF_SUCCESS;
}

static HcfResult CheckClassMatch(HcfAsyKeyGeneratorSpi *self, int *type)
{
    if (HcfIsClassMatch((HcfObjectBase *)self, GetEd25519KeyGeneratorSpiClass())) {
        *type = EVP_PKEY_ED25519;
    } else if (HcfIsClassMatch((HcfObjectBase *)self, GetX25519KeyGeneratorSpiClass())) {
        *type = EVP_PKEY_X25519;
    } else {
        LOGE("Invalid class of self.");
        return HCF_INVALID_PARAMS;
    }
    return HCF_SUCCESS;
}

static HcfResult EngineGenerateAlg25519KeyPair(HcfAsyKeyGeneratorSpi *self, HcfKeyPair **returnKeyPair)
{
    if (self == NULL || returnKeyPair == NULL) {
        LOGE("Invalid params.");
        return HCF_INVALID_PARAMS;
    }
    int type = 0;
    if (CheckClassMatch(self, &type) != HCF_SUCCESS) {
        LOGE("Invalid class of self.");
        return HCF_INVALID_PARAMS;
    }

    HcfOpensslAlg25519PubKey *pubKey = NULL;
    HcfOpensslAlg25519PriKey *priKey = NULL;
    HcfResult ret = GenerateAlg25519PubAndPriKey(type, &pubKey, &priKey);
    if (ret != HCF_SUCCESS) {
        LOGE("Generate alg25519 pk and sk by openssl failed.");
        return ret;
    }

    if (pubKey != NULL) {
        pubKey->type = type;
    }

    if (priKey != NULL) {
        priKey->type = type;
    }

    ret = CreateAlg25519KeyPair(pubKey, priKey, returnKeyPair);
    if (ret != HCF_SUCCESS) {
        LOGE("Create alg25519 keyPair failed.");
        HcfObjDestroy(pubKey);
        pubKey = NULL;
        HcfObjDestroy(priKey);
        priKey = NULL;
        return ret;
    }
    return HCF_SUCCESS;
}

static HcfResult EngineConvertAlg25519Key(HcfAsyKeyGeneratorSpi *self, HcfParamsSpec *params, HcfBlob *pubKeyBlob,
    HcfBlob *priKeyBlob, HcfKeyPair **returnKeyPair)
{
    (void)params;
    if ((self == NULL) || (returnKeyPair == NULL)) {
        LOGE("Invalid input parameter.");
        return HCF_INVALID_PARAMS;
    }
    int type = 0;
    if (CheckClassMatch(self, &type) != HCF_SUCCESS) {
        LOGE("Invalid class of self.");
        return HCF_INVALID_PARAMS;
    }
    bool pubKeyValid = HcfIsBlobValid(pubKeyBlob);
    bool priKeyValid = HcfIsBlobValid(priKeyBlob);
    if ((!pubKeyValid) && (!priKeyValid)) {
        LOGE("The private key and public key cannot both be NULL.");
        return HCF_INVALID_PARAMS;
    }

    HcfOpensslAlg25519PubKey *pubKey = NULL;
    HcfOpensslAlg25519PriKey *priKey = NULL;
    HcfBlob *inputPk = pubKeyValid ? pubKeyBlob : NULL;
    HcfBlob *inputSk = priKeyValid ? priKeyBlob : NULL;
    HcfResult ret = ConvertAlg25519PubAndPriKey(type, inputPk, inputSk, &pubKey, &priKey);
    if (ret != HCF_SUCCESS) {
        LOGE("Convert alg25519 keyPair failed.");
        return ret;
    }

    if (pubKey != NULL) {
        pubKey->type = type;
    }

    if (priKey != NULL) {
        priKey->type = type;
    }

    ret = CreateAlg25519KeyPair(pubKey, priKey, returnKeyPair);
    if (ret != HCF_SUCCESS) {
        LOGE("Create alg25519 keyPair failed.");
        HcfObjDestroy(pubKey);
        pubKey = NULL;
        HcfObjDestroy(priKey);
        priKey = NULL;
    }
    return ret;
}

static HcfResult ConvertAlg25519PemPubKey(int type, const char *pubKeyStr, HcfOpensslAlg25519PubKey **returnPubKey)
{
    EVP_PKEY *pkey = NULL;
    const char *keyType = NULL;
    if (type == EVP_PKEY_ED25519) {
        keyType = "ED25519";
    }
    if (type == EVP_PKEY_X25519) {
        keyType = "X25519";
    }

    HcfResult ret = ConvertPubPemStrToKey(&pkey, keyType, EVP_PKEY_PUBLIC_KEY, pubKeyStr);
    if (ret != HCF_SUCCESS) {
        LOGE("Convert public key from pem to key failed.");
        return ret;
    }

    ret = CreateAlg25519PubKey(pkey, returnPubKey);
    if (ret != HCF_SUCCESS) {
        LOGE("Create alg25519 public key failed.");
        OpensslEvpPkeyFree(pkey);
    }

    return ret;
}

static HcfResult ConvertAlg25519PemPriKey(int type, const char *priKeyStr, HcfOpensslAlg25519PriKey **returnPriKey)
{
    EVP_PKEY *pkey = NULL;
    const char *keyType = NULL;
    if (type == EVP_PKEY_ED25519) {
        keyType = "ED25519";
    }
    if (type == EVP_PKEY_X25519) {
        keyType = "X25519";
    }

    HcfResult ret = ConvertPriPemStrToKey(priKeyStr, &pkey, keyType);
    if (ret != HCF_SUCCESS) {
        LOGE("Convert private key from pem to key failed.");
        return ret;
    }

    ret = CreateAlg25519PriKey(pkey, returnPriKey);
    if (ret != HCF_SUCCESS) {
        LOGE("Create alg25519 private key failed.");
        OpensslEvpPkeyFree(pkey);
    }
    return ret;
}

static HcfResult ConvertAlg25519PemPubAndPriKey(int type, const char *pubKeyStr, const char *priKeyStr,
    HcfOpensslAlg25519PubKey **returnPubKey, HcfOpensslAlg25519PriKey **returnPriKey)
{
    if (pubKeyStr != NULL && strlen(pubKeyStr) != 0) {
        if (ConvertAlg25519PemPubKey(type, pubKeyStr, returnPubKey) != HCF_SUCCESS) {
            LOGE("Convert alg25519 pem public key failed.");
            return HCF_ERR_CRYPTO_OPERATION;
        }
    }
    if (priKeyStr != NULL && strlen(priKeyStr) != 0) {
        if (ConvertAlg25519PemPriKey(type, priKeyStr, returnPriKey) != HCF_SUCCESS) {
            LOGE("Convert alg25519 pem private key failed.");
            HcfObjDestroy(*returnPubKey);
            *returnPubKey = NULL;
            return HCF_ERR_CRYPTO_OPERATION;
        }
    }
    return HCF_SUCCESS;
}

static HcfResult EngineConvertX25519PemKey(HcfAsyKeyGeneratorSpi *self, HcfParamsSpec *params, const char *pubKeyStr,
    const char *priKeyStr, HcfKeyPair **returnKeyPair)
{
    (void)params;
    if ((self == NULL) || (returnKeyPair == NULL) || ((pubKeyStr == NULL) && (priKeyStr == NULL))) {
        LOGE("Invalid input parameter.");
        return HCF_INVALID_PARAMS;
    }

    if (!HcfIsClassMatch((HcfObjectBase *)self, GetX25519KeyGeneratorSpiClass())) {
        LOGE("Class not match.");
        return HCF_INVALID_PARAMS;
    }

    HcfOpensslAlg25519PubKey *pubKey = NULL;
    HcfOpensslAlg25519PriKey *priKey = NULL;
    int type = EVP_PKEY_X25519;
    HcfResult ret = ConvertAlg25519PemPubAndPriKey(type, pubKeyStr, priKeyStr, &pubKey, &priKey);
    if (ret != HCF_SUCCESS) {
        LOGE("Convert alg25519 pem keyPair failed.");
        return ret;
    }

    if (pubKey != NULL) {
        pubKey->type = type;
    }
    if (priKey != NULL) {
        priKey->type = type;
    }
    ret = CreateAlg25519KeyPair(pubKey, priKey, returnKeyPair);
    if (ret != HCF_SUCCESS) {
        LOGE("Create alg25519 keyPair failed.");
        HcfObjDestroy(pubKey);
        pubKey = NULL;
        HcfObjDestroy(priKey);
        priKey = NULL;
    }
    return ret;
}

static HcfResult EngineConvertEd25519PemKey(HcfAsyKeyGeneratorSpi *self, HcfParamsSpec *params, const char *pubKeyStr,
    const char *priKeyStr, HcfKeyPair **returnKeyPair)
{
    (void)params;
    if ((self == NULL) || (returnKeyPair == NULL) || ((pubKeyStr == NULL) && (priKeyStr == NULL))) {
        LOGE("Invalid input parameter.");
        return HCF_INVALID_PARAMS;
    }

    if (!HcfIsClassMatch((HcfObjectBase *)self, GetEd25519KeyGeneratorSpiClass())) {
        LOGE("Class not match.");
        return HCF_INVALID_PARAMS;
    }

    HcfOpensslAlg25519PubKey *pubKey = NULL;
    HcfOpensslAlg25519PriKey *priKey = NULL;
    int type = EVP_PKEY_ED25519;
    HcfResult ret = ConvertAlg25519PemPubAndPriKey(type, pubKeyStr, priKeyStr, &pubKey, &priKey);
    if (ret != HCF_SUCCESS) {
        LOGE("Convert alg25519 pem keyPair failed.");
        return ret;
    }

    if (pubKey != NULL) {
        pubKey->type = type;
    }
    if (priKey != NULL) {
        priKey->type = type;
    }
    ret = CreateAlg25519KeyPair(pubKey, priKey, returnKeyPair);
    if (ret != HCF_SUCCESS) {
        LOGE("Create alg25519 keyPair failed.");
        HcfObjDestroy(pubKey);
        pubKey = NULL;
        HcfObjDestroy(priKey);
        priKey = NULL;
    }
    return ret;
}

static HcfResult CreateOpensslAlg25519PubKey(const HcfBigInteger *pk, const char *algName,
    EVP_PKEY **returnAlg25519)
{
    EVP_PKEY *pubkey = NULL;
    if (strcmp(algName, ALGORITHM_NAME_ED25519) == 0) {
        pubkey = OpensslEvpPkeyNewRawPublicKey(EVP_PKEY_ED25519, NULL, pk->data, pk->len);
    } else if (strcmp(algName, ALGORITHM_NAME_X25519) == 0) {
        pubkey = OpensslEvpPkeyNewRawPublicKey(EVP_PKEY_X25519, NULL, pk->data, pk->len);
    } else {
        LOGE("Invalid algName! [Algo]: %{public}s", algName);
        return HCF_INVALID_PARAMS;
    }
    if (pubkey == NULL) {
        LOGE("Set alg25519 pubKey failed.");
        HcfPrintOpensslError();
        return HCF_ERR_CRYPTO_OPERATION;
    }
    *returnAlg25519 = pubkey;
    return HCF_SUCCESS;
}

static HcfResult CreateOpensslAlg25519PriKey(const HcfBigInteger *sk, const char *algName,
    EVP_PKEY **returnAlg25519)
{
    EVP_PKEY *privkey = NULL;
    if (strcmp(algName, ALGORITHM_NAME_ED25519) == 0) {
        privkey = OpensslEvpPkeyNewRawPrivateKey(EVP_PKEY_ED25519, NULL, sk->data, sk->len);
    } else if (strcmp(algName, ALGORITHM_NAME_X25519) == 0) {
        privkey = OpensslEvpPkeyNewRawPrivateKey(EVP_PKEY_X25519, NULL, sk->data, sk->len);
    } else {
        LOGE("Invalid algName! [Algo]: %{public}s", algName);
        return HCF_INVALID_PARAMS;
    }
    if (privkey == NULL) {
        LOGE("Get alg25519 priKey failed.");
        HcfPrintOpensslError();
        return HCF_ERR_CRYPTO_OPERATION;
    }
    *returnAlg25519 = privkey;
    return HCF_SUCCESS;
}

static HcfResult CreateAlg25519PubKeyByKeyPairSpec(const HcfAlg25519KeyPairParamsSpec *paramsSpec,
    const char *algName, HcfOpensslAlg25519PubKey **returnPubKey)
{
    EVP_PKEY *alg25519 = NULL;
    if (CreateOpensslAlg25519PubKey(&(paramsSpec->pk), algName, &alg25519) != HCF_SUCCESS) {
        LOGE("Create openssl alg25519 pubKey failed.");
        return HCF_ERR_CRYPTO_OPERATION;
    }
    if (CreateAlg25519PubKey(alg25519, returnPubKey) != HCF_SUCCESS) {
        LOGE("Create alg25519 pubKey failed.");
        OpensslEvpPkeyFree(alg25519);
        return HCF_ERR_MALLOC;
    }
    return HCF_SUCCESS;
}

static HcfResult CreateAlg25519PriKeyByKeyPairSpec(const HcfAlg25519KeyPairParamsSpec *paramsSpec,
    const char *algName, HcfOpensslAlg25519PriKey **returnPriKey)
{
    EVP_PKEY *alg25519 = NULL;
    if (CreateOpensslAlg25519PriKey(&(paramsSpec->sk), algName, &alg25519) != HCF_SUCCESS) {
        LOGE("Create openssl alg25519 priKey failed.");
        return HCF_ERR_CRYPTO_OPERATION;
    }
    if (CreateAlg25519PriKey(alg25519, returnPriKey) != HCF_SUCCESS) {
        LOGE("Create alg25519 priKey failed.");
        OpensslEvpPkeyFree(alg25519);
        return HCF_ERR_MALLOC;
    }
    return HCF_SUCCESS;
}

static HcfResult CreateAlg25519KeyPairByKeyPairSpec(const HcfAlg25519KeyPairParamsSpec *paramsSpec,
    const char *algName, HcfKeyPair **returnKeyPair)
{
    HcfOpensslAlg25519PubKey *pubKey = NULL;
    HcfResult ret = CreateAlg25519PubKeyByKeyPairSpec(paramsSpec, algName, &pubKey);
    if (ret != HCF_SUCCESS) {
        LOGE("Create alg25519 pubKey failed.");
        return ret;
    }

    HcfOpensslAlg25519PriKey *priKey = NULL;
    ret = CreateAlg25519PriKeyByKeyPairSpec(paramsSpec, algName, &priKey);
    if (ret != HCF_SUCCESS) {
        LOGE("Create alg25519 priKey failed.");
        HcfObjDestroy(pubKey);
        pubKey = NULL;
        return ret;
    }
    ret = CreateAlg25519KeyPair(pubKey, priKey, returnKeyPair);
    if (ret != HCF_SUCCESS) {
        LOGE("Create alg25519 keyPair failed.");
        HcfObjDestroy(pubKey);
        pubKey = NULL;
        HcfObjDestroy(priKey);
        priKey = NULL;
        return ret;
    }
    return HCF_SUCCESS;
}

static HcfResult CreateAlg25519PubKeyByPubKeySpec(const HcfAlg25519PubKeyParamsSpec *paramsSpec,
    const char *algName, HcfOpensslAlg25519PubKey **returnPubKey)
{
    EVP_PKEY *alg25519 = NULL;
    if (CreateOpensslAlg25519PubKey(&(paramsSpec->pk), algName, &alg25519) != HCF_SUCCESS) {
        LOGE("Create openssl alg25519 pubKey failed.");
        return HCF_ERR_CRYPTO_OPERATION;
    }
    if (CreateAlg25519PubKey(alg25519, returnPubKey) != HCF_SUCCESS) {
        LOGE("Create alg25519 pubKey failed.");
        OpensslEvpPkeyFree(alg25519);
        return HCF_ERR_MALLOC;
    }
    return HCF_SUCCESS;
}

static HcfResult CreateAlg25519PriKeyByPriKeySpec(const HcfAlg25519PriKeyParamsSpec *paramsSpec,
    const char *algName, HcfOpensslAlg25519PriKey **returnPriKey)
{
    EVP_PKEY *alg25519 = NULL;
    if (CreateOpensslAlg25519PriKey(&(paramsSpec->sk), algName, &alg25519) != HCF_SUCCESS) {
        LOGE("Create openssl alg25519 priKey failed.");
        return HCF_ERR_CRYPTO_OPERATION;
    }
    if (CreateAlg25519PriKey(alg25519, returnPriKey) != HCF_SUCCESS) {
        LOGE("Create alg25519 priKey failed.");
        OpensslEvpPkeyFree(alg25519);
        return HCF_ERR_MALLOC;
    }
    return HCF_SUCCESS;
}

static HcfResult EngineGenerateAlg25519PubKeyBySpec(const HcfAsyKeyGeneratorSpi *self,
    const HcfAsyKeyParamsSpec *paramsSpec, HcfPubKey **returnPubKey)
{
    if ((self == NULL) || (paramsSpec == NULL) || (paramsSpec->algName == NULL) || (returnPubKey == NULL)) {
        LOGE("Invalid input parameter.");
        return HCF_INVALID_PARAMS;
    }

    int type = 0;
    if (CheckClassMatch((HcfAsyKeyGeneratorSpi *)self, &type) != HCF_SUCCESS) {
        LOGE("Invalid class of self.");
        return HCF_INVALID_PARAMS;
    }

    if (((strcmp(paramsSpec->algName, ALGORITHM_NAME_ED25519) != 0) &&
        (strcmp(paramsSpec->algName, ALGORITHM_NAME_X25519) != 0)) ||
        (paramsSpec->specType != HCF_PUBLIC_KEY_SPEC)) {
        LOGE("Invalid params spec.");
        return HCF_INVALID_PARAMS;
    }
    HcfOpensslAlg25519PubKey *alg25519Pk = NULL;
    HcfResult ret = CreateAlg25519PubKeyByPubKeySpec((const HcfAlg25519PubKeyParamsSpec *)paramsSpec,
        paramsSpec->algName, &alg25519Pk);
    if (ret != HCF_SUCCESS) {
        LOGE("Create alg25519 public key by spec failed.");
        return ret;
    }

    alg25519Pk->type = type;
    *returnPubKey = (HcfPubKey *)alg25519Pk;

    return ret;
}

static HcfResult EngineGenerateAlg25519PriKeyBySpec(const HcfAsyKeyGeneratorSpi *self,
    const HcfAsyKeyParamsSpec *paramsSpec, HcfPriKey **returnPriKey)
{
    if ((self == NULL) || (paramsSpec == NULL) || (paramsSpec->algName == NULL) || (returnPriKey == NULL)) {
        LOGE("Invalid input parameter.");
        return HCF_INVALID_PARAMS;
    }

    int type = 0;
    if (CheckClassMatch((HcfAsyKeyGeneratorSpi *)self, &type) != HCF_SUCCESS) {
        LOGE("Invalid class of self.");
        return HCF_INVALID_PARAMS;
    }

    if (((strcmp(paramsSpec->algName, ALGORITHM_NAME_ED25519) != 0) &&
        (strcmp(paramsSpec->algName, ALGORITHM_NAME_X25519) != 0)) ||
        (paramsSpec->specType != HCF_PRIVATE_KEY_SPEC)) {
        LOGE("Invalid params spec.");
        return HCF_INVALID_PARAMS;
    }
    HcfOpensslAlg25519PriKey *alg25519Sk = NULL;
    HcfResult ret = CreateAlg25519PriKeyByPriKeySpec((const HcfAlg25519PriKeyParamsSpec *)paramsSpec,
        paramsSpec->algName, &alg25519Sk);
    if (ret != HCF_SUCCESS) {
        LOGE("Create alg25519 private key by spec failed.");
        return ret;
    }

    alg25519Sk->type = type;
    *returnPriKey = (HcfPriKey *)alg25519Sk;

    return ret;
}

static HcfResult EngineGenerateAlg25519KeyPairBySpec(const HcfAsyKeyGeneratorSpi *self,
    const HcfAsyKeyParamsSpec *paramsSpec, HcfKeyPair **returnKeyPair)
{
    if ((self == NULL) || (paramsSpec == NULL) || (paramsSpec->algName == NULL) || (returnKeyPair == NULL)) {
        LOGE("Invalid input parameter.");
        return HCF_INVALID_PARAMS;
    }

    int type = 0;
    if (CheckClassMatch((HcfAsyKeyGeneratorSpi *)self, &type) != HCF_SUCCESS) {
        LOGE("Invalid class of self.");
        return HCF_INVALID_PARAMS;
    }

    if (((strcmp(paramsSpec->algName, ALGORITHM_NAME_ED25519) != 0) &&
        (strcmp(paramsSpec->algName, ALGORITHM_NAME_X25519) != 0)) ||
        (paramsSpec->specType != HCF_KEY_PAIR_SPEC)) {
        LOGE("Invalid params spec.");
        return HCF_INVALID_PARAMS;
    }
    HcfResult ret = CreateAlg25519KeyPairByKeyPairSpec((const HcfAlg25519KeyPairParamsSpec *)paramsSpec,
        paramsSpec->algName, returnKeyPair);
    if (ret != HCF_SUCCESS) {
        LOGE("Create alg25519 key pair by spec failed.");
        return ret;
    }

    HcfOpensslAlg25519KeyPair *keyPair = (HcfOpensslAlg25519KeyPair *)(*returnKeyPair);
    HcfOpensslAlg25519PubKey *pubKey = (HcfOpensslAlg25519PubKey *)(keyPair->base.pubKey);
    HcfOpensslAlg25519PriKey *priKey = (HcfOpensslAlg25519PriKey *)(keyPair->base.priKey);
    pubKey->type = type;
    priKey->type = type;
    return ret;
}

HcfResult HcfAsyKeyGeneratorSpiEd25519Create(HcfAsyKeyGenParams *params, HcfAsyKeyGeneratorSpi **returnObj)
{
    (void)params;
    if (params == NULL || returnObj == NULL) {
        LOGE("Invalid input parameter.");
        return HCF_INVALID_PARAMS;
    }
    HcfAsyKeyGeneratorSpiAlg25519OpensslImpl *impl = (HcfAsyKeyGeneratorSpiAlg25519OpensslImpl *)HcfMalloc(
        sizeof(HcfAsyKeyGeneratorSpiAlg25519OpensslImpl), 0);
    if (impl == NULL) {
        LOGE("Failed to allocate generator impl memroy.");
        return HCF_ERR_MALLOC;
    }
    impl->base.base.getClass = GetEd25519KeyGeneratorSpiClass;
    impl->base.base.destroy = DestroyAlg25519KeyGeneratorSpiImpl;
    impl->base.engineGenerateKeyPair = EngineGenerateAlg25519KeyPair;
    impl->base.engineConvertKey = EngineConvertAlg25519Key;
    impl->base.engineConvertPemKey = EngineConvertEd25519PemKey;
    impl->base.engineGenerateKeyPairBySpec = EngineGenerateAlg25519KeyPairBySpec;
    impl->base.engineGeneratePubKeyBySpec = EngineGenerateAlg25519PubKeyBySpec;
    impl->base.engineGeneratePriKeyBySpec = EngineGenerateAlg25519PriKeyBySpec;

    *returnObj = (HcfAsyKeyGeneratorSpi *)impl;
    return HCF_SUCCESS;
}

HcfResult HcfAsyKeyGeneratorSpiX25519Create(HcfAsyKeyGenParams *params, HcfAsyKeyGeneratorSpi **returnObj)
{
    (void)params;
    if (params == NULL || returnObj == NULL) {
        LOGE("Invalid input parameter.");
        return HCF_INVALID_PARAMS;
    }
    HcfAsyKeyGeneratorSpiAlg25519OpensslImpl *impl = (HcfAsyKeyGeneratorSpiAlg25519OpensslImpl *)HcfMalloc(
        sizeof(HcfAsyKeyGeneratorSpiAlg25519OpensslImpl), 0);
    if (impl == NULL) {
        LOGE("Failed to allocate generator impl memroy.");
        return HCF_ERR_MALLOC;
    }
    impl->base.base.getClass = GetX25519KeyGeneratorSpiClass;
    impl->base.base.destroy = DestroyAlg25519KeyGeneratorSpiImpl;
    impl->base.engineGenerateKeyPair = EngineGenerateAlg25519KeyPair;
    impl->base.engineConvertKey = EngineConvertAlg25519Key;
    impl->base.engineConvertPemKey = EngineConvertX25519PemKey;
    impl->base.engineGenerateKeyPairBySpec = EngineGenerateAlg25519KeyPairBySpec;
    impl->base.engineGeneratePubKeyBySpec = EngineGenerateAlg25519PubKeyBySpec;
    impl->base.engineGeneratePriKeyBySpec = EngineGenerateAlg25519PriKeyBySpec;

    *returnObj = (HcfAsyKeyGeneratorSpi *)impl;
    return HCF_SUCCESS;
}

