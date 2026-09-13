/*
 * Copyright (C) 2026 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * *    http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include "ml_kem_asy_key_generator_openssl.h"

#include "securec.h"

#include <openssl/evp.h>
#include <openssl/obj_mac.h>
#include <openssl/params.h>
#include <string.h>

#include "log.h"
#include "memory.h"
#include "openssl_adapter.h"
#include "openssl_class.h"
#include "openssl_common.h"
#include "utils.h"

#define OPENSSL_ML_KEM_GENERATOR_CLASS "OPENSSL.ML_KEM.KEYGENERATOR"
#define OPENSSL_ML_KEM_PUBKEY_FORMAT "X.509"
#define OPENSSL_ML_KEM_PRIKEY_FORMAT "PKCS#8"
#define ALGORITHM_NAME_ML_KEM "ML-KEM"
#define BIT_PER_BYTE 8

#define ML_KEM_512_PUBKEY_BYTES 800
#define ML_KEM_512_PRIKEY_BYTES 1632
#define ML_KEM_768_PUBKEY_BYTES 1184
#define ML_KEM_768_PRIKEY_BYTES 2400
#define ML_KEM_1024_PUBKEY_BYTES 1568
#define ML_KEM_1024_PRIKEY_BYTES 3168

#define ML_KEM_SEED_BYTES 64

#define ML_KEM_INDEX_512 0
#define ML_KEM_INDEX_768 1
#define ML_KEM_INDEX_1024 2

static const char *g_mlKemAlgNames[] = {
    "ML-KEM-512",
    "ML-KEM-768",
    "ML-KEM-1024",
};

static const int ML_KEM_PUB_KEY_BYTES[] = {
    ML_KEM_512_PUBKEY_BYTES,
    ML_KEM_768_PUBKEY_BYTES,
    ML_KEM_1024_PUBKEY_BYTES,
};

static const int ML_KEM_PRI_KEY_BYTES[] = {
    ML_KEM_512_PRIKEY_BYTES,
    ML_KEM_768_PRIKEY_BYTES,
    ML_KEM_1024_PRIKEY_BYTES,
};

static HcfResult GenerateMlKemEvpKey(int32_t bits, EVP_PKEY **ppkey);
static HcfResult GetMlKemPubKeyFromPriKey(const HcfPriKey *self, HcfPubKey **returnPubKey);

typedef struct {
    HcfAsyKeyGeneratorSpi base;

    int32_t bits;
} HcfAsyKeyGeneratorSpiMlKemOpensslImpl;

static const char *GetMlKemKeyGeneratorSpiClass(void)
{
    return OPENSSL_ML_KEM_GENERATOR_CLASS;
}

static const char *GetMlKemKeyPairClass(void)
{
    return OPENSSL_ML_KEM_KEYPAIR_CLASS;
}

static const char *GetMlKemPubKeyClass(void)
{
    return OPENSSL_ML_KEM_PUBKEY_CLASS;
}

static const char *GetMlKemPriKeyClass(void)
{
    return OPENSSL_ML_KEM_PRIKEY_CLASS;
}

static int GetMlKemIndex(int32_t bits)
{
    if (bits == HCF_ALG_ML_KEM_512) {
        return ML_KEM_INDEX_512;
    } else if (bits == HCF_ALG_ML_KEM_768) {
        return ML_KEM_INDEX_768;
    } else if (bits == HCF_ALG_ML_KEM_1024) {
        return ML_KEM_INDEX_1024;
    }
    return ML_KEM_INDEX_768;
}

static void DestroyMlKemKeyGeneratorSpiImpl(HcfObjectBase *self)
{
    if (self == NULL) {
        return;
    }
    if (HcfIsClassMatch(self, GetMlKemKeyGeneratorSpiClass())) {
        HcfFree(self);
        return;
    }
    LOGE("Invalid input parameter.");
}

static void DestroyMlKemPubKey(HcfObjectBase *self)
{
    if (self == NULL) {
        return;
    }
    if (!HcfIsClassMatch(self, GetMlKemPubKeyClass())) {
        LOGE("Class not match.");
        return;
    }
    HcfOpensslMlKemPubKey *impl = (HcfOpensslMlKemPubKey *)self;
    OpensslEvpPkeyFree(impl->pkey);
    impl->pkey = NULL;
    HcfFree(impl);
}

static void DestroyMlKemPriKey(HcfObjectBase *self)
{
    if (self == NULL) {
        return;
    }
    if (!HcfIsClassMatch(self, GetMlKemPriKeyClass())) {
        LOGE("Class not match.");
        return;
    }
    HcfOpensslMlKemPriKey *impl = (HcfOpensslMlKemPriKey *)self;
    OpensslEvpPkeyFree(impl->pkey);
    impl->pkey = NULL;
    HcfFree(impl);
}

static void DestroyMlKemKeyPair(HcfObjectBase *self)
{
    if (self == NULL) {
        return;
    }
    if (!HcfIsClassMatch(self, GetMlKemKeyPairClass())) {
        LOGE("Class not match.");
        return;
    }
    HcfOpensslMlKemKeyPair *impl = (HcfOpensslMlKemKeyPair *)self;
    DestroyMlKemPubKey((HcfObjectBase *)impl->base.pubKey);
    impl->base.pubKey = NULL;
    DestroyMlKemPriKey((HcfObjectBase *)impl->base.priKey);
    impl->base.priKey = NULL;
    HcfFree(self);
}

static const char *GetMlKemPubKeyAlgorithm(HcfKey *self)
{
    if (self == NULL) {
        LOGE("Invalid input parameter.");
        return NULL;
    }
    if (!HcfIsClassMatch((HcfObjectBase *)self, GetMlKemPubKeyClass())) {
        LOGE("Class not match.");
        return NULL;
    }
    return ALGORITHM_NAME_ML_KEM;
}

static const char *GetMlKemPriKeyAlgorithm(HcfKey *self)
{
    if (self == NULL) {
        LOGE("Invalid input parameter.");
        return NULL;
    }
    if (!HcfIsClassMatch((HcfObjectBase *)self, GetMlKemPriKeyClass())) {
        LOGE("Class not match.");
        return NULL;
    }
    return ALGORITHM_NAME_ML_KEM;
}

static HcfResult BioReadToStr(BIO *bio, char **returnString)
{
    int len = BIO_pending(bio);
    if (len <= 0) {
        LOGE("Bio len less than 0.");
        return HCF_ERR_PARAMETER_CHECK_FAILED;
    }
    *returnString = (char *)HcfMalloc(len + 1, 0);
    if (*returnString == NULL) {
        LOGE("Failed to allocate returnString memory.");
        return HCF_ERR_MALLOC;
    }
    if (OpensslBioRead(bio, *returnString, len) <= 0) {
        LOGE("Bio read failed.");
        HcfPrintOpensslError();
        HcfFree(*returnString);
        *returnString = NULL;
        return HCF_ERR_CRYPTO_OPERATION;
    }
    (*returnString)[len] = '\0';
    return HCF_SUCCESS;
}

static HcfResult BioReadToBlob(BIO *bio, HcfBlob *returnBlob)
{
    int len = BIO_pending(bio);
    if (len <= 0) {
        LOGE("Bio len less than 0.");
        return HCF_ERR_PARAMETER_CHECK_FAILED;
    }
    returnBlob->data = (uint8_t *)HcfMalloc(len, 0);
    if (returnBlob->data == NULL) {
        LOGE("Failed to allocate returnBlob memory.");
        return HCF_ERR_MALLOC;
    }
    if (OpensslBioRead(bio, returnBlob->data, len) <= 0) {
        LOGE("Bio read failed.");
        HcfPrintOpensslError();
        HcfFree(returnBlob->data);
        returnBlob->data = NULL;
        return HCF_ERR_CRYPTO_OPERATION;
    }
    returnBlob->len = len;
    return HCF_SUCCESS;
}

static HcfResult GetMlKemPubKeyEncoded(HcfKey *self, HcfBlob *returnBlob)
{
    if ((self == NULL) || (returnBlob == NULL)) {
        LOGE("Invalid input parameter.");
        return HCF_ERR_PARAMETER_CHECK_FAILED;
    }
    if (!HcfIsClassMatch((HcfObjectBase *)self, GetMlKemPubKeyClass())) {
        LOGE("Invalid class of self.");
        return HCF_ERR_PARAMETER_CHECK_FAILED;
    }
    HcfOpensslMlKemPubKey *impl = (HcfOpensslMlKemPubKey *)self;
    if (impl->pkey == NULL) {
        LOGE("pkey is null.");
        return HCF_ERR_PARAMETER_CHECK_FAILED;
    }
    unsigned char *returnData = NULL;
    int len = OpensslI2dPubKey(impl->pkey, &returnData);
    if (len <= 0) {
        LOGE("I2dPubKey failed.");
        HcfPrintOpensslError();
        return HCF_ERR_CRYPTO_OPERATION;
    }
    returnBlob->data = returnData;
    returnBlob->len = len;
    return HCF_SUCCESS;
}

static HcfResult GetMlKemPubKeyEncodedPem(HcfKey *self, const char *format, char **returnString)
{
    if (self == NULL || format == NULL || returnString == NULL) {
        LOGE("Invalid input parameter.");
        return HCF_ERR_PARAMETER_CHECK_FAILED;
    }
    if (strcmp(format, "X509") != 0) {
        LOGE("Unsupported ml-kem pub pem format.");
        return HCF_ERR_PARAMETER_CHECK_FAILED;
    }
    if (!HcfIsClassMatch((HcfObjectBase *)self, GetMlKemPubKeyClass())) {
        LOGE("Invalid class of self.");
        return HCF_ERR_PARAMETER_CHECK_FAILED;
    }
    HcfOpensslMlKemPubKey *impl = (HcfOpensslMlKemPubKey *)self;
    if (impl->pkey == NULL) {
        LOGE("pkey is null.");
        return HCF_ERR_PARAMETER_CHECK_FAILED;
    }
    BIO *bio = OpensslBioNew(OpensslBioSMem());
    if (bio == NULL) {
        LOGE("BIO new fail.");
        return HCF_ERR_CRYPTO_OPERATION;
    }
    HcfResult ret = HCF_ERR_CRYPTO_OPERATION;
    do {
        if (PEM_write_bio_PUBKEY(bio, impl->pkey) != HCF_OPENSSL_SUCCESS) {
            LOGE("PEM_write_bio_PUBKEY fail.");
            HcfPrintOpensslError();
            break;
        }
        ret = BioReadToStr(bio, returnString);
    } while (0);
    OpensslBioFreeAll(bio);
    return ret;
}

static HcfResult GetMlKemPriKeyEncoded(HcfKey *self, HcfBlob *returnBlob)
{
    if ((self == NULL) || (returnBlob == NULL)) {
        LOGE("Invalid input parameter.");
        return HCF_ERR_PARAMETER_CHECK_FAILED;
    }
    if (!HcfIsClassMatch((HcfObjectBase *)self, GetMlKemPriKeyClass())) {
        LOGE("Invalid class of self.");
        return HCF_ERR_PARAMETER_CHECK_FAILED;
    }
    HcfOpensslMlKemPriKey *impl = (HcfOpensslMlKemPriKey *)self;
    if (impl->pkey == NULL) {
        LOGE("pkey is null.");
        return HCF_ERR_PARAMETER_CHECK_FAILED;
    }
    unsigned char *returnData = NULL;
    int len = OpensslI2dPrivateKey(impl->pkey, &returnData);
    if (len <= 0) {
        LOGE("I2dPrivateKey failed.");
        HcfPrintOpensslError();
        return HCF_ERR_CRYPTO_OPERATION;
    }
    returnBlob->data = returnData;
    returnBlob->len = len;
    return HCF_SUCCESS;
}

static HcfResult GetMlKemPriKeyEncodedPem(const HcfPriKey *self, HcfParamsSpec *paramsSpec, const char *format,
    char **returnString)
{
    if (paramsSpec != NULL) {
        LOGE("Ml-kem pri key pem with params is not supported.");
        return HCF_ERR_INVALID_CALL;
    }
    if (self == NULL || format == NULL || returnString == NULL) {
        LOGE("Invalid input parameter.");
        return HCF_ERR_PARAMETER_CHECK_FAILED;
    }
    if (strcmp(format, "PKCS8") != 0) {
        LOGE("Unsupported ml-kem pri pem format.");
        return HCF_ERR_PARAMETER_CHECK_FAILED;
    }
    if (!HcfIsClassMatch((HcfObjectBase *)self, GetMlKemPriKeyClass())) {
        LOGE("Invalid class of self.");
        return HCF_ERR_PARAMETER_CHECK_FAILED;
    }
    HcfOpensslMlKemPriKey *impl = (HcfOpensslMlKemPriKey *)self;
    if (impl->pkey == NULL) {
        LOGE("pkey is null.");
        return HCF_ERR_PARAMETER_CHECK_FAILED;
    }
    BIO *bio = OpensslBioNew(OpensslBioSMem());
    if (bio == NULL) {
        LOGE("BIO new fail.");
        return HCF_ERR_CRYPTO_OPERATION;
    }
    HcfResult ret = HCF_ERR_CRYPTO_OPERATION;
    do {
        if (PEM_write_bio_PKCS8PrivateKey(bio, impl->pkey, NULL, NULL, 0, NULL, NULL) != HCF_OPENSSL_SUCCESS) {
            LOGE("PEM_write_bio_PKCS8PrivateKey fail.");
            HcfPrintOpensslError();
            break;
        }
        ret = BioReadToStr(bio, returnString);
    } while (0);
    OpensslBioFreeAll(bio);
    return ret;
}

static HcfResult GetMlKemPubKeySize(HcfKey *self, int *keySize)
{
    if (self == NULL || keySize == NULL) {
        LOGE("Invalid input parameter.");
        return HCF_ERR_PARAMETER_CHECK_FAILED;
    }
    if (!HcfIsClassMatch((HcfObjectBase *)self, GetMlKemPubKeyClass())) {
        LOGE("Invalid class of self.");
        return HCF_ERR_PARAMETER_CHECK_FAILED;
    }
    HcfOpensslMlKemPubKey *impl = (HcfOpensslMlKemPubKey *)self;
    int idx = GetMlKemIndex(impl->type);
    *keySize = ML_KEM_PUB_KEY_BYTES[idx] * BIT_PER_BYTE;
    return HCF_SUCCESS;
}

static HcfResult GetMlKemPriKeySize(HcfKey *self, int *keySize)
{
    if (self == NULL || keySize == NULL) {
        LOGE("Invalid input parameter.");
        return HCF_ERR_PARAMETER_CHECK_FAILED;
    }
    if (!HcfIsClassMatch((HcfObjectBase *)self, GetMlKemPriKeyClass())) {
        LOGE("Invalid class of self.");
        return HCF_ERR_PARAMETER_CHECK_FAILED;
    }
    HcfOpensslMlKemPriKey *impl = (HcfOpensslMlKemPriKey *)self;
    int idx = GetMlKemIndex(impl->type);
    *keySize = ML_KEM_PRI_KEY_BYTES[idx] * BIT_PER_BYTE;
    return HCF_SUCCESS;
}

static const char *GetMlKemPubKeyFormat(HcfKey *self)
{
    if (self == NULL) {
        LOGE("Invalid input parameter.");
        return NULL;
    }
    if (!HcfIsClassMatch((HcfObjectBase *)self, GetMlKemPubKeyClass())) {
        LOGE("Class not match.");
        return NULL;
    }
    return OPENSSL_ML_KEM_PUBKEY_FORMAT;
}

static const char *GetMlKemPriKeyFormat(HcfKey *self)
{
    if (self == NULL) {
        LOGE("Invalid input parameter.");
        return NULL;
    }
    if (!HcfIsClassMatch((HcfObjectBase *)self, GetMlKemPriKeyClass())) {
        LOGE("Class not match.");
        return NULL;
    }
    return OPENSSL_ML_KEM_PRIKEY_FORMAT;
}

static HcfResult GetMlKemPubKey(EVP_PKEY *pkey, HcfBigInteger *returnBigInteger)
{
    size_t len = 0;
    if (!OpensslEvpPkeyGetRawPublicKey(pkey, NULL, &len)) {
        LOGE("Get pub key len failed.");
        return HCF_ERR_CRYPTO_OPERATION;
    }
    returnBigInteger->data = (unsigned char *)HcfMalloc(len, 0);
    if (returnBigInteger->data == NULL) {
        LOGE("Failed to allocate bigInteger data memory.");
        return HCF_ERR_MALLOC;
    }
    if (!OpensslEvpPkeyGetRawPublicKey(pkey, returnBigInteger->data, &len)) {
        LOGE("Get pub key data failed.");
        HcfFree(returnBigInteger->data);
        returnBigInteger->data = NULL;
        return HCF_ERR_CRYPTO_OPERATION;
    }
    returnBigInteger->len = len;
    return HCF_SUCCESS;
}

static HcfResult GetBigIntegerSpecFromMlKemPubKey(const HcfPubKey *self, const AsyKeySpecItem item,
    HcfBigInteger *returnBigInteger)
{
    (void)self;
    (void)item;
    (void)returnBigInteger;
    return HCF_ERR_INVALID_CALL;
}

static HcfResult GetIntSpecFromMlKemPubKey(const HcfPubKey *self, const AsyKeySpecItem item, int *returnInt)
{
    (void)self;
    (void)item;
    (void)returnInt;
    return HCF_ERR_INVALID_CALL;
}

static HcfResult GetStrSpecFromMlKemPubKey(const HcfPubKey *self, const AsyKeySpecItem item, char **returnString)
{
    (void)self;
    (void)item;
    (void)returnString;
    return HCF_ERR_INVALID_CALL;
}

static HcfResult GetBigIntegerSpecFromMlKemPriKey(const HcfPriKey *self, const AsyKeySpecItem item,
    HcfBigInteger *returnBigInteger)
{
    (void)self;
    (void)item;
    (void)returnBigInteger;
    return HCF_ERR_INVALID_CALL;
}

static HcfResult GetIntSpecFromMlKemPriKey(const HcfPriKey *self, const AsyKeySpecItem item, int *returnInt)
{
    (void)self;
    (void)item;
    (void)returnInt;
    return HCF_ERR_INVALID_CALL;
}

static HcfResult GetStrSpecFromMlKemPriKey(const HcfPriKey *self, const AsyKeySpecItem item, char **returnString)
{
    (void)self;
    (void)item;
    (void)returnString;
    return HCF_ERR_INVALID_CALL;
}

static HcfResult GetMlKemPriKeyEncodedDer(const HcfPriKey *self, const char *format, HcfBlob *returnBlob)
{
    if (self == NULL || format == NULL || returnBlob == NULL) {
        LOGE("Invalid input parameter.");
        return HCF_ERR_PARAMETER_CHECK_FAILED;
    }
    if (strcmp(format, "PKCS8") != 0) {
        LOGE("Unsupported ml-kem pri der format.");
        return HCF_ERR_PARAMETER_CHECK_FAILED;
    }
    if (!HcfIsClassMatch((HcfObjectBase *)self, GetMlKemPriKeyClass())) {
        LOGE("Invalid class of self.");
        return HCF_ERR_PARAMETER_CHECK_FAILED;
    }
    HcfOpensslMlKemPriKey *impl = (HcfOpensslMlKemPriKey *)self;
    if (impl->pkey == NULL) {
        LOGE("pkey is null.");
        return HCF_ERR_PARAMETER_CHECK_FAILED;
    }
    BIO *bio = OpensslBioNew(OpensslBioSMem());
    if (bio == NULL) {
        LOGE("BIO new fail.");
        return HCF_ERR_CRYPTO_OPERATION;
    }
    HcfResult ret = HCF_ERR_CRYPTO_OPERATION;
    do {
        if (i2d_PKCS8PrivateKey_bio(bio, impl->pkey, NULL, NULL, 0, NULL, NULL) != HCF_OPENSSL_SUCCESS) {
            LOGE("i2d_PKCS8PrivateKey_bio fail.");
            HcfPrintOpensslError();
            break;
        }
        ret = BioReadToBlob(bio, returnBlob);
    } while (0);
    OpensslBioFreeAll(bio);
    return ret;
}

static HcfResult GetMlKemPubKeyEncodedDer(const HcfPubKey *self, const char *format, HcfBlob *returnBlob)
{
    if (self == NULL || format == NULL || returnBlob == NULL) {
        LOGE("Invalid input parameter.");
        return HCF_ERR_PARAMETER_CHECK_FAILED;
    }
    if (strcmp(format, "X509") != 0) {
        LOGE("Unsupported ml-kem pub der format.");
        return HCF_ERR_PARAMETER_CHECK_FAILED;
    }
    if (!HcfIsClassMatch((HcfObjectBase *)self, GetMlKemPubKeyClass())) {
        LOGE("Invalid class of self.");
        return HCF_ERR_PARAMETER_CHECK_FAILED;
    }
    HcfOpensslMlKemPubKey *impl = (HcfOpensslMlKemPubKey *)self;
    if (impl->pkey == NULL) {
        LOGE("pkey is null.");
        return HCF_ERR_PARAMETER_CHECK_FAILED;
    }
    unsigned char *returnData = NULL;
    int len = OpensslI2dPubKey(impl->pkey, &returnData);
    if (len <= 0) {
        LOGE("I2dPubKey for der failed.");
        HcfPrintOpensslError();
        return HCF_ERR_CRYPTO_OPERATION;
    }
    returnBlob->data = returnData;
    returnBlob->len = len;
    return HCF_SUCCESS;
}

static HcfResult GetMlKemPubKeyData(const HcfPubKey *self, uint32_t type, HcfBlob *returnBlob)
{
    if (self == NULL || returnBlob == NULL) {
        LOGE("Invalid input parameter.");
        return HCF_ERR_PARAMETER_CHECK_FAILED;
    }
    if (type != ML_KEM_PUBLIC_RAW) {
        LOGE("Invalid type for ml-kem pub key data.");
        return HCF_ERR_PARAMETER_CHECK_FAILED;
    }
    if (!HcfIsClassMatch((HcfObjectBase *)self, GetMlKemPubKeyClass())) {
        LOGE("Invalid class of self.");
        return HCF_ERR_PARAMETER_CHECK_FAILED;
    }
    HcfOpensslMlKemPubKey *impl = (HcfOpensslMlKemPubKey *)self;
    if (impl->pkey == NULL) {
        LOGE("pkey is null.");
        return HCF_ERR_PARAMETER_CHECK_FAILED;
    }
    size_t len = 0;
    if (!OpensslEvpPkeyGetRawPublicKey(impl->pkey, NULL, &len)) {
        LOGE("Get raw pub key len failed.");
        return HCF_ERR_CRYPTO_OPERATION;
    }
    returnBlob->data = (uint8_t *)HcfMalloc(len, 0);
    if (returnBlob->data == NULL) {
        LOGE("Failed to allocate pub key data memory.");
        return HCF_ERR_MALLOC;
    }
    if (!OpensslEvpPkeyGetRawPublicKey(impl->pkey, returnBlob->data, &len)) {
        LOGE("Get raw pub key data failed.");
        HcfFree(returnBlob->data);
        returnBlob->data = NULL;
        return HCF_ERR_CRYPTO_OPERATION;
    }
    returnBlob->len = len;
    return HCF_SUCCESS;
}

static HcfResult GetMlKemPriSeedData(EVP_PKEY *pkey, size_t rawLen, HcfBlob *returnBlob)
{
    if (rawLen < ML_KEM_SEED_BYTES) {
        LOGE("Raw pri key too short for seed extraction.");
        return HCF_ERR_CRYPTO_OPERATION;
    }
    returnBlob->data = (uint8_t *)HcfMalloc(ML_KEM_SEED_BYTES, 0);
    if (returnBlob->data == NULL) {
        LOGE("Failed to allocate seed data memory.");
        return HCF_ERR_MALLOC;
    }
    uint8_t *tmpBuf = (uint8_t *)HcfMalloc(rawLen, 0);
    if (tmpBuf == NULL) {
        LOGE("Failed to allocate tmpBuf memory.");
        HcfFree(returnBlob->data);
        returnBlob->data = NULL;
        return HCF_ERR_MALLOC;
    }
    if (!OpensslEvpPkeyGetRawPrivateKey(pkey, tmpBuf, &rawLen)) {
        LOGE("Get raw pri key data for seed failed.");
        (void)memset_s(tmpBuf, rawLen, 0, rawLen);
        HcfFree(tmpBuf);
        HcfFree(returnBlob->data);
        returnBlob->data = NULL;
        return HCF_ERR_CRYPTO_OPERATION;
    }
    if (memcpy_s(returnBlob->data, ML_KEM_SEED_BYTES, tmpBuf, ML_KEM_SEED_BYTES) != EOK) {
        LOGE("memcpy_s failed for seed.");
        (void)memset_s(tmpBuf, rawLen, 0, rawLen);
        HcfFree(tmpBuf);
        HcfFree(returnBlob->data);
        returnBlob->data = NULL;
        return HCF_ERR_CRYPTO_OPERATION;
    }
    (void)memset_s(tmpBuf, rawLen, 0, rawLen);
    HcfFree(tmpBuf);
    returnBlob->len = ML_KEM_SEED_BYTES;
    return HCF_SUCCESS;
}

static HcfResult GetMlKemPriKeyData(const HcfPriKey *self, uint32_t type, HcfBlob *returnBlob)
{
    if (self == NULL || returnBlob == NULL) {
        LOGE("Invalid input parameter.");
        return HCF_ERR_PARAMETER_CHECK_FAILED;
    }
    if (type != ML_KEM_PRIVATE_SEED && type != ML_KEM_PRIVATE_RAW) {
        LOGE("Invalid type for ml-kem pri key data.");
        return HCF_ERR_PARAMETER_CHECK_FAILED;
    }
    if (!HcfIsClassMatch((HcfObjectBase *)self, GetMlKemPriKeyClass())) {
        LOGE("Invalid class of self.");
        return HCF_ERR_PARAMETER_CHECK_FAILED;
    }
    HcfOpensslMlKemPriKey *impl = (HcfOpensslMlKemPriKey *)self;
    if (impl->pkey == NULL) {
        LOGE("pkey is null.");
        return HCF_ERR_PARAMETER_CHECK_FAILED;
    }
    size_t len = 0;
    if (!OpensslEvpPkeyGetRawPrivateKey(impl->pkey, NULL, &len)) {
        LOGE("Get raw pri key len failed.");
        return HCF_ERR_CRYPTO_OPERATION;
    }
    if (type == ML_KEM_PRIVATE_SEED) {
        return GetMlKemPriSeedData(impl->pkey, len, returnBlob);
    }
    returnBlob->data = (uint8_t *)HcfMalloc(len, 0);
    if (returnBlob->data == NULL) {
        LOGE("Failed to allocate pri key data memory.");
        return HCF_ERR_MALLOC;
    }
    if (!OpensslEvpPkeyGetRawPrivateKey(impl->pkey, returnBlob->data, &len)) {
        LOGE("Get raw pri key data failed.");
        HcfFree(returnBlob->data);
        returnBlob->data = NULL;
        return HCF_ERR_CRYPTO_OPERATION;
    }
    returnBlob->len = len;
    return HCF_SUCCESS;
}

static void ClearMlKemPriKeyMem(HcfPriKey *self)
{
    if (self == NULL) {
        return;
    }
    if (!HcfIsClassMatch((HcfObjectBase *)self, GetMlKemPriKeyClass())) {
        LOGE("Class not match.");
        return;
    }
    HcfOpensslMlKemPriKey *impl = (HcfOpensslMlKemPriKey *)self;
    OpensslEvpPkeyFree(impl->pkey);
    impl->pkey = NULL;
}

static void FillOpensslMlKemPubKeyFunc(HcfOpensslMlKemPubKey *pk)
{
    pk->base.base.base.destroy = DestroyMlKemPubKey;
    pk->base.base.base.getClass = GetMlKemPubKeyClass;
    pk->base.base.getAlgorithm = GetMlKemPubKeyAlgorithm;
    pk->base.base.getEncoded = GetMlKemPubKeyEncoded;
    pk->base.base.getEncodedPem = GetMlKemPubKeyEncodedPem;
    pk->base.base.getFormat = GetMlKemPubKeyFormat;
    pk->base.base.getKeySize = GetMlKemPubKeySize;
    pk->base.getKeyData = GetMlKemPubKeyData;
    pk->base.getAsyKeySpecBigInteger = GetBigIntegerSpecFromMlKemPubKey;
    pk->base.getAsyKeySpecInt = GetIntSpecFromMlKemPubKey;
    pk->base.getAsyKeySpecString = GetStrSpecFromMlKemPubKey;
    pk->base.getEncodedDer = GetMlKemPubKeyEncodedDer;
}

static void FillOpensslMlKemPriKeyFunc(HcfOpensslMlKemPriKey *sk)
{
    sk->base.base.base.destroy = DestroyMlKemPriKey;
    sk->base.base.base.getClass = GetMlKemPriKeyClass;
    sk->base.base.getAlgorithm = GetMlKemPriKeyAlgorithm;
    sk->base.base.getEncoded = GetMlKemPriKeyEncoded;
    sk->base.getEncodedPem = GetMlKemPriKeyEncodedPem;
    sk->base.getPubKey = GetMlKemPubKeyFromPriKey;
    sk->base.base.getFormat = GetMlKemPriKeyFormat;
    sk->base.base.getKeySize = GetMlKemPriKeySize;
    sk->base.getKeyData = GetMlKemPriKeyData;
    sk->base.getAsyKeySpecBigInteger = GetBigIntegerSpecFromMlKemPriKey;
    sk->base.getAsyKeySpecInt = GetIntSpecFromMlKemPriKey;
    sk->base.getAsyKeySpecString = GetStrSpecFromMlKemPriKey;
    sk->base.getEncodedDer = GetMlKemPriKeyEncodedDer;
    sk->base.clearMem = ClearMlKemPriKeyMem;
}

static HcfResult CreateMlKemPubKey(EVP_PKEY *pkey, int type, HcfOpensslMlKemPubKey **returnPubKey)
{
    HcfOpensslMlKemPubKey *mlKemPubKey =
        (HcfOpensslMlKemPubKey *)HcfMalloc(sizeof(HcfOpensslMlKemPubKey), 0);
    if (mlKemPubKey == NULL) {
        LOGE("Failed to allocate mlKemPubKey memory.");
        return HCF_ERR_MALLOC;
    }
    FillOpensslMlKemPubKeyFunc(mlKemPubKey);
    mlKemPubKey->pkey = pkey;
    mlKemPubKey->type = type;
    *returnPubKey = mlKemPubKey;
    return HCF_SUCCESS;
}

static HcfResult CreateMlKemPriKey(EVP_PKEY *pkey, int type, HcfOpensslMlKemPriKey **returnPriKey)
{
    HcfOpensslMlKemPriKey *mlKemPriKey =
        (HcfOpensslMlKemPriKey *)HcfMalloc(sizeof(HcfOpensslMlKemPriKey), 0);
    if (mlKemPriKey == NULL) {
        LOGE("Failed to allocate mlKemPriKey memory.");
        return HCF_ERR_MALLOC;
    }
    FillOpensslMlKemPriKeyFunc(mlKemPriKey);
    mlKemPriKey->pkey = pkey;
    mlKemPriKey->type = type;
    *returnPriKey = mlKemPriKey;
    return HCF_SUCCESS;
}

static HcfResult CreateMlKemKeyPair(const HcfOpensslMlKemPubKey *pubKey,
    const HcfOpensslMlKemPriKey *priKey, HcfKeyPair **returnKeyPair)
{
    HcfOpensslMlKemKeyPair *keyPair =
        (HcfOpensslMlKemKeyPair *)HcfMalloc(sizeof(HcfOpensslMlKemKeyPair), 0);
    if (keyPair == NULL) {
        LOGE("Failed to allocate keyPair memory.");
        return HCF_ERR_MALLOC;
    }
    keyPair->base.base.getClass = GetMlKemKeyPairClass;
    keyPair->base.base.destroy = DestroyMlKemKeyPair;
    keyPair->base.pubKey = (HcfPubKey *)pubKey;
    keyPair->base.priKey = (HcfPriKey *)priKey;
    *returnKeyPair = (HcfKeyPair *)keyPair;
    return HCF_SUCCESS;
}

static HcfResult GenerateMlKemEvpKey(int32_t bits, EVP_PKEY **ppkey)
{
    EVP_PKEY_CTX *paramsCtx = NULL;
    HcfResult ret = HCF_SUCCESS;
    int idx = GetMlKemIndex(bits);
    const char *algName = g_mlKemAlgNames[idx];
    do {
        paramsCtx = OpensslEvpPkeyCtxNewFromName(NULL, algName, NULL);
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

static HcfResult GeneratePubKeyByPkey(EVP_PKEY *pkey, int type, HcfOpensslMlKemPubKey **returnPubKey)
{
    size_t pubLen = 0;
    if (!OpensslEvpPkeyGetRawPublicKey(pkey, NULL, &pubLen)) {
        LOGE("GetRawPublicKey size failed.");
        HcfPrintOpensslError();
        return HCF_ERR_CRYPTO_OPERATION;
    }
    unsigned char *pubData = (unsigned char *)HcfMalloc(pubLen, 0);
    if (pubData == NULL) {
        LOGE("Failed to allocate pubData memory.");
        return HCF_ERR_MALLOC;
    }
    if (!OpensslEvpPkeyGetRawPublicKey(pkey, pubData, &pubLen)) {
        LOGE("GetRawPublicKey data failed.");
        HcfPrintOpensslError();
        HcfFree(pubData);
        return HCF_ERR_CRYPTO_OPERATION;
    }
    int idx = GetMlKemIndex(type);
    int nid = NID_ML_KEM_512 + idx;
    EVP_PKEY *evpPkey = OpensslEvpPkeyNewRawPublicKey(nid, NULL, pubData, pubLen);
    HcfFree(pubData);
    if (evpPkey == NULL) {
        LOGE("Failed to create raw public key for nid=%d", nid);
        HcfPrintOpensslError();
        return HCF_ERR_CRYPTO_OPERATION;
    }
    HcfResult ret = CreateMlKemPubKey(evpPkey, type, returnPubKey);
    if (ret != HCF_SUCCESS) {
        LOGE("Failed to create ML-KEM public key.");
        OpensslEvpPkeyFree(evpPkey);
    }
    return ret;
}

static HcfResult GeneratePriKeyByPkey(EVP_PKEY *pkey, int type, HcfOpensslMlKemPriKey **returnPriKey)
{
    HcfResult ret = CreateMlKemPriKey(pkey, type, returnPriKey);
    return ret;
}

static HcfResult GenerateMlKemPubAndPriKey(int32_t bits,
    HcfOpensslMlKemPubKey **returnPubKey, HcfOpensslMlKemPriKey **returnPriKey)
{
    EVP_PKEY *pkey = NULL;
    HcfResult ret = GenerateMlKemEvpKey(bits, &pkey);
    if (ret != HCF_SUCCESS) {
        return ret;
    }

    ret = GeneratePubKeyByPkey(pkey, bits, returnPubKey);
    if (ret != HCF_SUCCESS) {
        OpensslEvpPkeyFree(pkey);
        return ret;
    }

    ret = GeneratePriKeyByPkey(pkey, bits, returnPriKey);
    if (ret != HCF_SUCCESS) {
        LOGE("Failed to generate private key from EVP_PKEY.");
        HcfObjDestroy(*returnPubKey);
        *returnPubKey = NULL;
        OpensslEvpPkeyFree(pkey);
        return HCF_ERR_CRYPTO_OPERATION;
    }

    return ret;
}

static HcfResult ConvertMlKemPubKey(const HcfBlob *pubKeyBlob, int type, HcfOpensslMlKemPubKey **returnPubKey)
{
    const unsigned char *tmpData = (const unsigned char *)(pubKeyBlob->data);
    EVP_PKEY *pkey = OpensslD2iPubKey(NULL, &tmpData, pubKeyBlob->len);
    if (pkey == NULL) {
        int idx = GetMlKemIndex(type);
        int nid = NID_ML_KEM_512 + idx;
        pkey = OpensslEvpPkeyNewRawPublicKey(nid, NULL, pubKeyBlob->data, pubKeyBlob->len);
        if (pkey == NULL) {
            LOGE("Failed to create raw public key.");
            HcfPrintOpensslError();
            return HCF_ERR_CRYPTO_OPERATION;
        }
    }
    int idx = GetMlKemIndex(type);
    if (OpensslEvpPkeyIsA(pkey, g_mlKemAlgNames[idx]) != HCF_OPENSSL_SUCCESS) {
        LOGE("Invalid key type for ML-KEM convertKey.");
        OpensslEvpPkeyFree(pkey);
        return HCF_ERR_CRYPTO_OPERATION;
    }
    HcfResult ret = CreateMlKemPubKey(pkey, type, returnPubKey);
    if (ret != HCF_SUCCESS) {
        LOGE("Failed to create ML-KEM public key.");
        OpensslEvpPkeyFree(pkey);
    }
    return ret;
}

static EVP_PKEY *MlKemPkeyFromSeed(int type, const uint8_t *seed, size_t seedLen)
{
    int idx = GetMlKemIndex(type);
    EVP_PKEY_CTX *ctx = OpensslEvpPkeyCtxNewFromName(NULL, g_mlKemAlgNames[idx], NULL);
    if (ctx == NULL) {
        LOGE("Create evp pkey ctx failed.");
        return NULL;
    }
    EVP_PKEY *pkey = NULL;
    OSSL_PARAM params[2];
    params[0] = OSSL_PARAM_construct_octet_string("seed", (void *)seed, seedLen);
    params[1] = OSSL_PARAM_construct_end();
    if (OpensslEvpPkeyKeyGenInit(ctx) != HCF_OPENSSL_SUCCESS ||
        OpensslEvpPkeyCtxSetParams(ctx, params) != HCF_OPENSSL_SUCCESS ||
        OpensslEvpPkeyKeyGen(ctx, &pkey) != HCF_OPENSSL_SUCCESS) {
        LOGE("MlKem keygen from seed failed.");
        HcfPrintOpensslError();
        OpensslEvpPkeyCtxFree(ctx);
        return NULL;
    }
    OpensslEvpPkeyCtxFree(ctx);
    return pkey;
}

static HcfResult ConvertMlKemPriKey(const HcfBlob *priKeyBlob, int type, HcfOpensslMlKemPriKey **returnPriKey)
{
    const unsigned char *tmpData = (const unsigned char *)(priKeyBlob->data);
    EVP_PKEY *pkey = OpensslD2iAutoPrivateKey(NULL, &tmpData, priKeyBlob->len);
    if (pkey == NULL) {
        int idx = GetMlKemIndex(type);
        int nid = NID_ML_KEM_512 + idx;
        pkey = OpensslEvpPkeyNewRawPrivateKey(nid, NULL, priKeyBlob->data, priKeyBlob->len);
    }
    if (pkey == NULL && priKeyBlob->len == ML_KEM_SEED_BYTES) {
        pkey = MlKemPkeyFromSeed(type, priKeyBlob->data, priKeyBlob->len);
    }
    if (pkey == NULL) {
        LOGE("Convert ml-kem pri key failed.");
        HcfPrintOpensslError();
        return HCF_ERR_CRYPTO_OPERATION;
    }
    int idx = GetMlKemIndex(type);
    if (OpensslEvpPkeyIsA(pkey, g_mlKemAlgNames[idx]) != HCF_OPENSSL_SUCCESS) {
        LOGE("Invalid key type for ML-KEM convertKey.");
        OpensslEvpPkeyFree(pkey);
        return HCF_ERR_CRYPTO_OPERATION;
    }
    HcfResult ret = CreateMlKemPriKey(pkey, type, returnPriKey);
    if (ret != HCF_SUCCESS) {
        LOGE("Failed to create ML-KEM private key.");
        OpensslEvpPkeyFree(pkey);
    }
    return ret;
}

static HcfResult GetMlKemPubKeyFromPriKey(const HcfPriKey *self, HcfPubKey **returnPubKey)
{
    if (self == NULL || returnPubKey == NULL) {
        LOGE("Invalid input parameter.");
        return HCF_ERR_PARAMETER_CHECK_FAILED;
    }
    if (!HcfIsClassMatch((HcfObjectBase *)self, GetMlKemPriKeyClass())) {
        LOGE("Invalid class of self.");
        return HCF_ERR_PARAMETER_CHECK_FAILED;
    }
    HcfOpensslMlKemPriKey *impl = (HcfOpensslMlKemPriKey *)self;
    if (impl->pkey == NULL) {
        LOGE("pkey is null.");
        return HCF_ERR_PARAMETER_CHECK_FAILED;
    }
    HcfBigInteger bigInteger;
    if (GetMlKemPubKey(impl->pkey, &bigInteger) != HCF_SUCCESS) {
        LOGE("Get ml-kem pubKey from priKey failed.");
        return HCF_ERR_CRYPTO_OPERATION;
    }
    int idx = GetMlKemIndex(impl->type);
    int nid = NID_ML_KEM_512 + idx;
    EVP_PKEY *evpPubKey = OpensslEvpPkeyNewRawPublicKey(nid, NULL, bigInteger.data, bigInteger.len);
    HcfFree(bigInteger.data);
    if (evpPubKey == NULL) {
        LOGE("Create ml-kem pubKey failed.");
        return HCF_ERR_CRYPTO_OPERATION;
    }
    HcfResult ret = CreateMlKemPubKey(evpPubKey, impl->type, (HcfOpensslMlKemPubKey **)returnPubKey);
    if (ret != HCF_SUCCESS) {
        OpensslEvpPkeyFree(evpPubKey);
    }
    return ret;
}

static HcfResult EngineGenerateMlKemKeyPair(HcfAsyKeyGeneratorSpi *self, HcfKeyPair **returnKeyPair)
{
    if (self == NULL || returnKeyPair == NULL) {
        LOGE("Invalid input parameter.");
        return HCF_ERR_PARAMETER_CHECK_FAILED;
    }
    if (!HcfIsClassMatch((HcfObjectBase *)self, GetMlKemKeyGeneratorSpiClass())) {
        LOGE("Invalid class of self.");
        return HCF_ERR_PARAMETER_CHECK_FAILED;
    }
    HcfAsyKeyGeneratorSpiMlKemOpensslImpl *impl = (HcfAsyKeyGeneratorSpiMlKemOpensslImpl *)self;

    HcfOpensslMlKemPubKey *pubKey = NULL;
    HcfOpensslMlKemPriKey *priKey = NULL;
    HcfResult ret = GenerateMlKemPubAndPriKey(impl->bits, &pubKey, &priKey);
    if (ret != HCF_SUCCESS) {
        return ret;
    }

    ret = CreateMlKemKeyPair(pubKey, priKey, returnKeyPair);
    if (ret != HCF_SUCCESS) {
        LOGE("Failed to create ML-KEM key pair.");
        HcfObjDestroy(pubKey);
        HcfObjDestroy(priKey);
    }
    return ret;
}

static HcfResult EngineConvertMlKemKey(HcfAsyKeyGeneratorSpi *self, HcfParamsSpec *params, HcfBlob *pubKeyBlob,
    HcfBlob *priKeyBlob, HcfKeyPair **returnKeyPair)
{
    (void)params;
    if ((self == NULL) || (returnKeyPair == NULL)) {
        LOGE("Invalid input parameter.");
        return HCF_ERR_PARAMETER_CHECK_FAILED;
    }
    if (!HcfIsClassMatch((HcfObjectBase *)self, GetMlKemKeyGeneratorSpiClass())) {
        LOGE("Invalid class of self.");
        return HCF_ERR_PARAMETER_CHECK_FAILED;
    }
    HcfAsyKeyGeneratorSpiMlKemOpensslImpl *impl = (HcfAsyKeyGeneratorSpiMlKemOpensslImpl *)self;
    int type = impl->bits;

    bool pubKeyValid = HcfIsBlobValid(pubKeyBlob);
    bool priKeyValid = HcfIsBlobValid(priKeyBlob);
    if ((!pubKeyValid) && (!priKeyValid)) {
        LOGE("Both pubKeyBlob and priKeyBlob are invalid.");
        return HCF_ERR_PARAMETER_CHECK_FAILED;
    }

    HcfOpensslMlKemPubKey *pubKey = NULL;
    HcfOpensslMlKemPriKey *priKey = NULL;

    if (pubKeyValid) {
        HcfResult ret = ConvertMlKemPubKey(pubKeyBlob, type, &pubKey);
        if (ret != HCF_SUCCESS) {
            LOGE("Failed to convert ML-KEM public key.");
            return ret;
        }
    }
    if (priKeyValid) {
        HcfResult ret = ConvertMlKemPriKey(priKeyBlob, type, &priKey);
        if (ret != HCF_SUCCESS) {
            LOGE("Failed to convert ML-KEM private key.");
            HcfObjDestroy(pubKey);
            pubKey = NULL;
            return ret;
        }
    }

    HcfResult ret = CreateMlKemKeyPair(pubKey, priKey, returnKeyPair);
    if (ret != HCF_SUCCESS) {
        LOGE("Failed to create ML-KEM key pair.");
        HcfObjDestroy(pubKey);
        HcfObjDestroy(priKey);
    }
    return ret;
}

static HcfResult ConvertMlKemPemPubKey(const char *pubKeyStr, int type, HcfOpensslMlKemPubKey **returnPubKey)
{
    EVP_PKEY *pkey = NULL;
    int idx = GetMlKemIndex(type);
    HcfResult ret = ConvertPubPemStrToKey(&pkey, g_mlKemAlgNames[idx], EVP_PKEY_PUBLIC_KEY, pubKeyStr);
    if (ret != HCF_SUCCESS) {
        LOGE("Convert ML-KEM pem public key failed.");
        return ret;
    }
    ret = CreateMlKemPubKey(pkey, type, returnPubKey);
    if (ret != HCF_SUCCESS) {
        LOGE("Failed to create ML-KEM public key.");
        OpensslEvpPkeyFree(pkey);
    }
    return ret;
}

static HcfResult ConvertMlKemPemPriKey(const char *priKeyStr, int type, HcfOpensslMlKemPriKey **returnPriKey)
{
    EVP_PKEY *pkey = NULL;
    int idx = GetMlKemIndex(type);
    HcfResult ret = ConvertPriPemStrToKey(priKeyStr, &pkey, g_mlKemAlgNames[idx]);
    if (ret != HCF_SUCCESS) {
        LOGE("Convert ML-KEM pem private key failed.");
        return ret;
    }
    ret = CreateMlKemPriKey(pkey, type, returnPriKey);
    if (ret != HCF_SUCCESS) {
        LOGE("Failed to create ML-KEM private key.");
        OpensslEvpPkeyFree(pkey);
    }
    return ret;
}

static HcfResult EngineConvertMlKemPemKey(HcfAsyKeyGeneratorSpi *self, HcfParamsSpec *params, const char *pubKeyStr,
    const char *priKeyStr, HcfKeyPair **returnKeyPair)
{
    if ((self == NULL) || (returnKeyPair == NULL) || ((pubKeyStr == NULL) && (priKeyStr == NULL))) {
        LOGE("Invalid input parameter.");
        return HCF_ERR_PARAMETER_CHECK_FAILED;
    }
    if (params != NULL) {
        LOGE("ML-KEM does not support convertPemKey with password.");
        return HCF_ERR_INVALID_CALL;
    }
    if (!HcfIsClassMatch((HcfObjectBase *)self, GetMlKemKeyGeneratorSpiClass())) {
        LOGE("Class not match.");
        return HCF_ERR_PARAMETER_CHECK_FAILED;
    }
    HcfAsyKeyGeneratorSpiMlKemOpensslImpl *impl = (HcfAsyKeyGeneratorSpiMlKemOpensslImpl *)self;
    int type = impl->bits;

    HcfOpensslMlKemPubKey *pubKey = NULL;
    HcfOpensslMlKemPriKey *priKey = NULL;

    if (pubKeyStr != NULL && strlen(pubKeyStr) != 0) {
        HcfResult ret = ConvertMlKemPemPubKey(pubKeyStr, type, &pubKey);
        if (ret != HCF_SUCCESS) {
            LOGE("Convert ML-KEM pem pubKey failed.");
            return ret;
        }
    }
    if (priKeyStr != NULL && strlen(priKeyStr) != 0) {
        HcfResult ret = ConvertMlKemPemPriKey(priKeyStr, type, &priKey);
        if (ret != HCF_SUCCESS) {
            LOGE("Convert ML-KEM pem priKey failed.");
            HcfObjDestroy(pubKey);
            pubKey = NULL;
            return ret;
        }
    }

    HcfResult ret = CreateMlKemKeyPair(pubKey, priKey, returnKeyPair);
    if (ret != HCF_SUCCESS) {
        LOGE("Failed to create ML-KEM key pair.");
        HcfObjDestroy(pubKey);
        HcfObjDestroy(priKey);
    }
    return ret;
}

static HcfResult EngineGenerateMlKemKeyPairBySpec(const HcfAsyKeyGeneratorSpi *self,
    const HcfAsyKeyParamsSpec *paramsSpec, HcfKeyPair **returnKeyPair)
{
    (void)self;
    (void)paramsSpec;
    (void)returnKeyPair;
    return HCF_ERR_INVALID_CALL;
}

static HcfResult EngineGenerateMlKemPubKeyBySpec(const HcfAsyKeyGeneratorSpi *self,
    const HcfAsyKeyParamsSpec *paramsSpec, HcfPubKey **returnPubKey)
{
    (void)self;
    (void)paramsSpec;
    (void)returnPubKey;
    return HCF_ERR_INVALID_CALL;
}

static HcfResult EngineGenerateMlKemPriKeyBySpec(const HcfAsyKeyGeneratorSpi *self,
    const HcfAsyKeyParamsSpec *paramsSpec, HcfPriKey **returnPriKey)
{
    (void)self;
    (void)paramsSpec;
    (void)returnPriKey;
    return HCF_ERR_INVALID_CALL;
}

HcfResult HcfAsyKeyGeneratorSpiMlKemCreate(HcfAsyKeyGenParams *params, HcfAsyKeyGeneratorSpi **returnObj)
{
    if (params == NULL || returnObj == NULL) {
        LOGE("Invalid input parameter.");
        return HCF_ERR_PARAMETER_CHECK_FAILED;
    }
    HcfAsyKeyGeneratorSpiMlKemOpensslImpl *impl =
        (HcfAsyKeyGeneratorSpiMlKemOpensslImpl *)HcfMalloc(sizeof(HcfAsyKeyGeneratorSpiMlKemOpensslImpl), 0);
    if (impl == NULL) {
        LOGE("Failed to allocate impl memory.");
        return HCF_ERR_MALLOC;
    }
    impl->base.base.getClass = GetMlKemKeyGeneratorSpiClass;
    impl->base.base.destroy = DestroyMlKemKeyGeneratorSpiImpl;
    impl->base.engineGenerateKeyPair = EngineGenerateMlKemKeyPair;
    impl->base.engineConvertKey = EngineConvertMlKemKey;
    impl->base.engineConvertPemKey = EngineConvertMlKemPemKey;
    impl->base.engineGenerateKeyPairBySpec = EngineGenerateMlKemKeyPairBySpec;
    impl->base.engineGeneratePubKeyBySpec = EngineGenerateMlKemPubKeyBySpec;
    impl->base.engineGeneratePriKeyBySpec = EngineGenerateMlKemPriKeyBySpec;
    impl->bits = params->bits;

    *returnObj = (HcfAsyKeyGeneratorSpi *)impl;
    return HCF_SUCCESS;
}
