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

#include "ml_dsa_asy_key_generator_openssl.h"

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

#define OPENSSL_ML_DSA_GENERATOR_CLASS "OPENSSL.ML_DSA.KEYGENERATOR"
#define OPENSSL_ML_DSA_PUBKEY_FORMAT "X.509"
#define OPENSSL_ML_DSA_PRIKEY_FORMAT "PKCS#8"
#define ALGORITHM_NAME_ML_DSA "ML-DSA"
#define BIT_PER_BYTE 8

#define ML_DSA_44_PUBKEY_BYTES 1312
#define ML_DSA_44_PRIKEY_BYTES 2560
#define ML_DSA_65_PUBKEY_BYTES 1952
#define ML_DSA_65_PRIKEY_BYTES 4032
#define ML_DSA_87_PUBKEY_BYTES 2592
#define ML_DSA_87_PRIKEY_BYTES 4896

#define ML_DSA_SEED_BYTES 32

#define ML_DSA_INDEX_44 0
#define ML_DSA_INDEX_65 1
#define ML_DSA_INDEX_87 2

static const char *g_mlDsaAlgNames[] = {
    "ML-DSA-44",
    "ML-DSA-65",
    "ML-DSA-87",
};

static const int ML_DSA_PUB_KEY_BYTES[] = {
    ML_DSA_44_PUBKEY_BYTES,
    ML_DSA_65_PUBKEY_BYTES,
    ML_DSA_87_PUBKEY_BYTES,
};

static const int ML_DSA_PRI_KEY_BYTES[] = {
    ML_DSA_44_PRIKEY_BYTES,
    ML_DSA_65_PRIKEY_BYTES,
    ML_DSA_87_PRIKEY_BYTES,
};

static HcfResult GenerateMlDsaEvpKey(int32_t bits, EVP_PKEY **ppkey);
static HcfResult CreateMlDsaPubKey(EVP_PKEY *pkey, int type, HcfOpensslMlDsaPubKey **returnPubKey);

typedef struct {
    HcfAsyKeyGeneratorSpi base;

    int32_t bits;
} HcfAsyKeyGeneratorSpiMlDsaOpensslImpl;

static const char *GetMlDsaKeyGeneratorSpiClass(void)
{
    return OPENSSL_ML_DSA_GENERATOR_CLASS;
}

static const char *GetMlDsaKeyPairClass(void)
{
    return OPENSSL_ML_DSA_KEYPAIR_CLASS;
}

static const char *GetMlDsaPubKeyClass(void)
{
    return OPENSSL_ML_DSA_PUBKEY_CLASS;
}

static const char *GetMlDsaPriKeyClass(void)
{
    return OPENSSL_ML_DSA_PRIKEY_CLASS;
}

static int GetMlDsaIndex(int32_t bits)
{
    if (bits == HCF_ALG_ML_DSA_44) {
        return ML_DSA_INDEX_44;
    } else if (bits == HCF_ALG_ML_DSA_65) {
        return ML_DSA_INDEX_65;
    } else if (bits == HCF_ALG_ML_DSA_87) {
        return ML_DSA_INDEX_87;
    }
    return ML_DSA_INDEX_65;
}

static void DestroyMlDsaKeyGeneratorSpiImpl(HcfObjectBase *self)
{
    if (self == NULL) {
        return;
    }
    if (HcfIsClassMatch(self, GetMlDsaKeyGeneratorSpiClass())) {
        HcfFree(self);
        return;
    }
    LOGE("Invalid input parameter.");
}

static void DestroyMlDsaPubKey(HcfObjectBase *self)
{
    if (self == NULL) {
        return;
    }
    if (!HcfIsClassMatch(self, GetMlDsaPubKeyClass())) {
        LOGE("Class not match.");
        return;
    }
    HcfOpensslMlDsaPubKey *impl = (HcfOpensslMlDsaPubKey *)self;
    OpensslEvpPkeyFree(impl->pkey);
    impl->pkey = NULL;
    HcfFree(impl);
}

static void DestroyMlDsaPriKey(HcfObjectBase *self)
{
    if (self == NULL) {
        return;
    }
    if (!HcfIsClassMatch(self, GetMlDsaPriKeyClass())) {
        LOGE("Class not match.");
        return;
    }
    HcfOpensslMlDsaPriKey *impl = (HcfOpensslMlDsaPriKey *)self;
    OpensslEvpPkeyFree(impl->pkey);
    impl->pkey = NULL;
    HcfFree(impl);
}

static void DestroyMlDsaKeyPair(HcfObjectBase *self)
{
    if (self == NULL) {
        return;
    }
    if (!HcfIsClassMatch(self, GetMlDsaKeyPairClass())) {
        LOGE("Class not match.");
        return;
    }
    HcfOpensslMlDsaKeyPair *impl = (HcfOpensslMlDsaKeyPair *)self;
    DestroyMlDsaPubKey((HcfObjectBase *)impl->base.pubKey);
    impl->base.pubKey = NULL;
    DestroyMlDsaPriKey((HcfObjectBase *)impl->base.priKey);
    impl->base.priKey = NULL;
    HcfFree(self);
}

static const char *GetMlDsaPubKeyAlgorithm(HcfKey *self)
{
    if (self == NULL) {
        LOGE("Invalid input parameter.");
        return NULL;
    }
    if (!HcfIsClassMatch((HcfObjectBase *)self, GetMlDsaPubKeyClass())) {
        LOGE("Class not match.");
        return NULL;
    }
    return ALGORITHM_NAME_ML_DSA;
}

static const char *GetMlDsaPriKeyAlgorithm(HcfKey *self)
{
    if (self == NULL) {
        LOGE("Invalid input parameter.");
        return NULL;
    }
    if (!HcfIsClassMatch((HcfObjectBase *)self, GetMlDsaPriKeyClass())) {
        LOGE("Class not match.");
        return NULL;
    }
    return ALGORITHM_NAME_ML_DSA;
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

static HcfResult GetMlDsaPubKeyEncoded(HcfKey *self, HcfBlob *returnBlob)
{
    if ((self == NULL) || (returnBlob == NULL)) {
        LOGE("Invalid input parameter.");
        return HCF_ERR_PARAMETER_CHECK_FAILED;
    }
    if (!HcfIsClassMatch((HcfObjectBase *)self, GetMlDsaPubKeyClass())) {
        LOGE("Invalid class of self.");
        return HCF_ERR_PARAMETER_CHECK_FAILED;
    }
    HcfOpensslMlDsaPubKey *impl = (HcfOpensslMlDsaPubKey *)self;
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

static HcfResult GetMlDsaPubKeyEncodedPem(HcfKey *self, const char *format, char **returnString)
{
    if (self == NULL || format == NULL || returnString == NULL) {
        LOGE("Invalid input parameter.");
        return HCF_ERR_PARAMETER_CHECK_FAILED;
    }
    if (strcmp(format, "X509") != 0) {
        LOGE("Unsupported ml-dsa pub pem format.");
        return HCF_ERR_PARAMETER_CHECK_FAILED;
    }
    if (!HcfIsClassMatch((HcfObjectBase *)self, GetMlDsaPubKeyClass())) {
        LOGE("Invalid class of self.");
        return HCF_ERR_PARAMETER_CHECK_FAILED;
    }
    HcfOpensslMlDsaPubKey *impl = (HcfOpensslMlDsaPubKey *)self;
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

static HcfResult GetMlDsaPriKeyEncoded(HcfKey *self, HcfBlob *returnBlob)
{
    if ((self == NULL) || (returnBlob == NULL)) {
        LOGE("Invalid input parameter.");
        return HCF_ERR_PARAMETER_CHECK_FAILED;
    }
    if (!HcfIsClassMatch((HcfObjectBase *)self, GetMlDsaPriKeyClass())) {
        LOGE("Invalid class of self.");
        return HCF_ERR_PARAMETER_CHECK_FAILED;
    }
    HcfOpensslMlDsaPriKey *impl = (HcfOpensslMlDsaPriKey *)self;
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

static HcfResult GetMlDsaPriKeyEncodedPem(const HcfPriKey *self, HcfParamsSpec *paramsSpec, const char *format,
    char **returnString)
{
    if (paramsSpec != NULL) {
        LOGE("Ml-dsa pri key pem with params is not supported.");
        return HCF_ERR_INVALID_CALL;
    }
    if (self == NULL || format == NULL || returnString == NULL) {
        LOGE("Invalid input parameter.");
        return HCF_ERR_PARAMETER_CHECK_FAILED;
    }
    if (strcmp(format, "PKCS8") != 0) {
        LOGE("Unsupported ml-dsa pri pem format.");
        return HCF_ERR_PARAMETER_CHECK_FAILED;
    }
    if (!HcfIsClassMatch((HcfObjectBase *)self, GetMlDsaPriKeyClass())) {
        LOGE("Invalid class of self.");
        return HCF_ERR_PARAMETER_CHECK_FAILED;
    }
    HcfOpensslMlDsaPriKey *impl = (HcfOpensslMlDsaPriKey *)self;
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

static HcfResult GetMlDsaPubKeySize(HcfKey *self, int *keySize)
{
    if (self == NULL || keySize == NULL) {
        LOGE("Invalid input parameter.");
        return HCF_ERR_PARAMETER_CHECK_FAILED;
    }
    if (!HcfIsClassMatch((HcfObjectBase *)self, GetMlDsaPubKeyClass())) {
        LOGE("Invalid class of self.");
        return HCF_ERR_PARAMETER_CHECK_FAILED;
    }
    HcfOpensslMlDsaPubKey *impl = (HcfOpensslMlDsaPubKey *)self;
    int idx = GetMlDsaIndex(impl->type);
    *keySize = ML_DSA_PUB_KEY_BYTES[idx] * BIT_PER_BYTE;
    return HCF_SUCCESS;
}

static HcfResult GetMlDsaPriKeySize(HcfKey *self, int *keySize)
{
    if (self == NULL || keySize == NULL) {
        LOGE("Invalid input parameter.");
        return HCF_ERR_PARAMETER_CHECK_FAILED;
    }
    if (!HcfIsClassMatch((HcfObjectBase *)self, GetMlDsaPriKeyClass())) {
        LOGE("Invalid class of self.");
        return HCF_ERR_PARAMETER_CHECK_FAILED;
    }
    HcfOpensslMlDsaPriKey *impl = (HcfOpensslMlDsaPriKey *)self;
    int idx = GetMlDsaIndex(impl->type);
    *keySize = ML_DSA_PRI_KEY_BYTES[idx] * BIT_PER_BYTE;
    return HCF_SUCCESS;
}

static const char *GetMlDsaPubKeyFormat(HcfKey *self)
{
    if (self == NULL) {
        LOGE("Invalid input parameter.");
        return NULL;
    }
    if (!HcfIsClassMatch((HcfObjectBase *)self, GetMlDsaPubKeyClass())) {
        LOGE("Class not match.");
        return NULL;
    }
    return OPENSSL_ML_DSA_PUBKEY_FORMAT;
}

static const char *GetMlDsaPriKeyFormat(HcfKey *self)
{
    if (self == NULL) {
        LOGE("Invalid input parameter.");
        return NULL;
    }
    if (!HcfIsClassMatch((HcfObjectBase *)self, GetMlDsaPriKeyClass())) {
        LOGE("Class not match.");
        return NULL;
    }
    return OPENSSL_ML_DSA_PRIKEY_FORMAT;
}

static HcfResult GetMlDsaPubKey(EVP_PKEY *pkey, HcfBigInteger *returnBigInteger)
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

static HcfResult GetBigIntegerSpecFromMlDsaPubKey(const HcfPubKey *self, const AsyKeySpecItem item,
    HcfBigInteger *returnBigInteger)
{
    (void)self;
    (void)item;
    (void)returnBigInteger;
    return HCF_ERR_INVALID_CALL;
}

static HcfResult GetIntSpecFromMlDsaPubKey(const HcfPubKey *self, const AsyKeySpecItem item, int *returnInt)
{
    (void)self;
    (void)item;
    (void)returnInt;
    return HCF_ERR_INVALID_CALL;
}

static HcfResult GetStrSpecFromMlDsaPubKey(const HcfPubKey *self, const AsyKeySpecItem item, char **returnString)
{
    (void)self;
    (void)item;
    (void)returnString;
    return HCF_ERR_INVALID_CALL;
}

static HcfResult GetBigIntegerSpecFromMlDsaPriKey(const HcfPriKey *self, const AsyKeySpecItem item,
    HcfBigInteger *returnBigInteger)
{
    (void)self;
    (void)item;
    (void)returnBigInteger;
    return HCF_ERR_INVALID_CALL;
}

static HcfResult GetIntSpecFromMlDsaPriKey(const HcfPriKey *self, const AsyKeySpecItem item, int *returnInt)
{
    (void)self;
    (void)item;
    (void)returnInt;
    return HCF_ERR_INVALID_CALL;
}

static HcfResult GetStrSpecFromMlDsaPriKey(const HcfPriKey *self, const AsyKeySpecItem item, char **returnString)
{
    (void)self;
    (void)item;
    (void)returnString;
    return HCF_ERR_INVALID_CALL;
}

static HcfResult GetMlDsaPriKeyEncodedDer(const HcfPriKey *self, const char *format, HcfBlob *returnBlob)
{
    if (self == NULL || format == NULL || returnBlob == NULL) {
        LOGE("Invalid input parameter.");
        return HCF_ERR_PARAMETER_CHECK_FAILED;
    }
    if (strcmp(format, "PKCS8") != 0) {
        LOGE("Unsupported ml-dsa pri der format.");
        return HCF_ERR_PARAMETER_CHECK_FAILED;
    }
    if (!HcfIsClassMatch((HcfObjectBase *)self, GetMlDsaPriKeyClass())) {
        LOGE("Invalid class of self.");
        return HCF_ERR_PARAMETER_CHECK_FAILED;
    }
    HcfOpensslMlDsaPriKey *impl = (HcfOpensslMlDsaPriKey *)self;
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

static HcfResult GetMlDsaPubKeyEncodedDer(const HcfPubKey *self, const char *format, HcfBlob *returnBlob)
{
    if (self == NULL || format == NULL || returnBlob == NULL) {
        LOGE("Invalid input parameter.");
        return HCF_ERR_PARAMETER_CHECK_FAILED;
    }
    if (strcmp(format, "X509") != 0) {
        LOGE("Unsupported ml-dsa pub der format.");
        return HCF_ERR_PARAMETER_CHECK_FAILED;
    }
    if (!HcfIsClassMatch((HcfObjectBase *)self, GetMlDsaPubKeyClass())) {
        LOGE("Invalid class of self.");
        return HCF_ERR_PARAMETER_CHECK_FAILED;
    }
    HcfOpensslMlDsaPubKey *impl = (HcfOpensslMlDsaPubKey *)self;
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

static HcfResult GetMlDsaPubKeyData(const HcfPubKey *self, uint32_t type, HcfBlob *returnBlob)
{
    if (self == NULL || returnBlob == NULL) {
        LOGE("Invalid input parameter.");
        return HCF_ERR_PARAMETER_CHECK_FAILED;
    }
    if (type != ML_DSA_PUBLIC_RAW) {
        LOGE("Invalid type for ml-dsa pub key data.");
        return HCF_ERR_PARAMETER_CHECK_FAILED;
    }
    if (!HcfIsClassMatch((HcfObjectBase *)self, GetMlDsaPubKeyClass())) {
        LOGE("Invalid class of self.");
        return HCF_ERR_PARAMETER_CHECK_FAILED;
    }
    HcfOpensslMlDsaPubKey *impl = (HcfOpensslMlDsaPubKey *)self;
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

static HcfResult GetMlDsaPriSeedData(EVP_PKEY *pkey, size_t rawLen, HcfBlob *returnBlob)
{
    if (rawLen < ML_DSA_SEED_BYTES) {
        LOGE("Raw pri key too short for seed extraction.");
        return HCF_ERR_CRYPTO_OPERATION;
    }
    returnBlob->data = (uint8_t *)HcfMalloc(ML_DSA_SEED_BYTES, 0);
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
    if (memcpy_s(returnBlob->data, ML_DSA_SEED_BYTES, tmpBuf, ML_DSA_SEED_BYTES) != EOK) {
        LOGE("memcpy_s failed for seed.");
        (void)memset_s(tmpBuf, rawLen, 0, rawLen);
        HcfFree(tmpBuf);
        HcfFree(returnBlob->data);
        returnBlob->data = NULL;
        return HCF_ERR_CRYPTO_OPERATION;
    }
    (void)memset_s(tmpBuf, rawLen, 0, rawLen);
    HcfFree(tmpBuf);
    returnBlob->len = ML_DSA_SEED_BYTES;
    return HCF_SUCCESS;
}

static HcfResult GetMlDsaPriKeyData(const HcfPriKey *self, uint32_t type, HcfBlob *returnBlob)
{
    if (self == NULL || returnBlob == NULL) {
        LOGE("Invalid input parameter.");
        return HCF_ERR_PARAMETER_CHECK_FAILED;
    }
    if (type != ML_DSA_PRIVATE_SEED && type != ML_DSA_PRIVATE_RAW) {
        LOGE("Invalid type for ml-dsa pri key data.");
        return HCF_ERR_PARAMETER_CHECK_FAILED;
    }
    if (!HcfIsClassMatch((HcfObjectBase *)self, GetMlDsaPriKeyClass())) {
        LOGE("Invalid class of self.");
        return HCF_ERR_PARAMETER_CHECK_FAILED;
    }
    HcfOpensslMlDsaPriKey *impl = (HcfOpensslMlDsaPriKey *)self;
    if (impl->pkey == NULL) {
        LOGE("pkey is null.");
        return HCF_ERR_PARAMETER_CHECK_FAILED;
    }
    size_t len = 0;
    if (!OpensslEvpPkeyGetRawPrivateKey(impl->pkey, NULL, &len)) {
        LOGE("Get raw pri key len failed.");
        return HCF_ERR_CRYPTO_OPERATION;
    }
    if (type == ML_DSA_PRIVATE_SEED) {
        return GetMlDsaPriSeedData(impl->pkey, len, returnBlob);
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

static HcfResult GetMlDsaPubKeyFromPriKey(const HcfPriKey *self, HcfPubKey **returnPubKey)
{
    if (self == NULL || returnPubKey == NULL) {
        LOGE("Invalid input parameter.");
        return HCF_ERR_PARAMETER_CHECK_FAILED;
    }
    if (!HcfIsClassMatch((HcfObjectBase *)self, GetMlDsaPriKeyClass())) {
        LOGE("Invalid class of self.");
        return HCF_ERR_PARAMETER_CHECK_FAILED;
    }
    HcfOpensslMlDsaPriKey *impl = (HcfOpensslMlDsaPriKey *)self;
    if (impl->pkey == NULL) {
        LOGE("pkey is null.");
        return HCF_ERR_PARAMETER_CHECK_FAILED;
    }
    HcfBigInteger bigInteger;
    if (GetMlDsaPubKey(impl->pkey, &bigInteger) != HCF_SUCCESS) {
        LOGE("Get ml-dsa pubKey from priKey failed.");
        return HCF_ERR_CRYPTO_OPERATION;
    }
    int idx = GetMlDsaIndex(impl->type);
    int nid = NID_ML_DSA_44 + idx;
    EVP_PKEY *evpPubKey = OpensslEvpPkeyNewRawPublicKey(nid, NULL, bigInteger.data, bigInteger.len);
    HcfFree(bigInteger.data);
    if (evpPubKey == NULL) {
        LOGE("Create ml-dsa pubKey failed.");
        return HCF_ERR_CRYPTO_OPERATION;
    }
    HcfResult ret = CreateMlDsaPubKey(evpPubKey, impl->type, (HcfOpensslMlDsaPubKey **)returnPubKey);
    if (ret != HCF_SUCCESS) {
        OpensslEvpPkeyFree(evpPubKey);
    }
    return ret;
}

static void ClearMlDsaPriKeyMem(HcfPriKey *self)
{
    if (self == NULL) {
        return;
    }
    if (!HcfIsClassMatch((HcfObjectBase *)self, GetMlDsaPriKeyClass())) {
        LOGE("Class not match.");
        return;
    }
    HcfOpensslMlDsaPriKey *impl = (HcfOpensslMlDsaPriKey *)self;
    OpensslEvpPkeyFree(impl->pkey);
    impl->pkey = NULL;
}

static void FillOpensslMlDsaPubKeyFunc(HcfOpensslMlDsaPubKey *pk)
{
    pk->base.base.base.destroy = DestroyMlDsaPubKey;
    pk->base.base.base.getClass = GetMlDsaPubKeyClass;
    pk->base.base.getAlgorithm = GetMlDsaPubKeyAlgorithm;
    pk->base.base.getEncoded = GetMlDsaPubKeyEncoded;
    pk->base.base.getEncodedPem = GetMlDsaPubKeyEncodedPem;
    pk->base.base.getFormat = GetMlDsaPubKeyFormat;
    pk->base.base.getKeySize = GetMlDsaPubKeySize;
    pk->base.getKeyData = GetMlDsaPubKeyData;
    pk->base.getAsyKeySpecBigInteger = GetBigIntegerSpecFromMlDsaPubKey;
    pk->base.getAsyKeySpecInt = GetIntSpecFromMlDsaPubKey;
    pk->base.getAsyKeySpecString = GetStrSpecFromMlDsaPubKey;
    pk->base.getEncodedDer = GetMlDsaPubKeyEncodedDer;
}

static void FillOpensslMlDsaPriKeyFunc(HcfOpensslMlDsaPriKey *sk)
{
    sk->base.base.base.destroy = DestroyMlDsaPriKey;
    sk->base.base.base.getClass = GetMlDsaPriKeyClass;
    sk->base.base.getAlgorithm = GetMlDsaPriKeyAlgorithm;
    sk->base.base.getEncoded = GetMlDsaPriKeyEncoded;
    sk->base.getEncodedPem = GetMlDsaPriKeyEncodedPem;
    sk->base.getPubKey = GetMlDsaPubKeyFromPriKey;
    sk->base.base.getFormat = GetMlDsaPriKeyFormat;
    sk->base.base.getKeySize = GetMlDsaPriKeySize;
    sk->base.getKeyData = GetMlDsaPriKeyData;
    sk->base.getAsyKeySpecBigInteger = GetBigIntegerSpecFromMlDsaPriKey;
    sk->base.getAsyKeySpecInt = GetIntSpecFromMlDsaPriKey;
    sk->base.getAsyKeySpecString = GetStrSpecFromMlDsaPriKey;
    sk->base.getEncodedDer = GetMlDsaPriKeyEncodedDer;
    sk->base.clearMem = ClearMlDsaPriKeyMem;
}

static HcfResult CreateMlDsaPubKey(EVP_PKEY *pkey, int type, HcfOpensslMlDsaPubKey **returnPubKey)
{
    HcfOpensslMlDsaPubKey *mlDsaPubKey =
        (HcfOpensslMlDsaPubKey *)HcfMalloc(sizeof(HcfOpensslMlDsaPubKey), 0);
    if (mlDsaPubKey == NULL) {
        LOGE("Failed to allocate mlDsaPubKey memory.");
        return HCF_ERR_MALLOC;
    }
    FillOpensslMlDsaPubKeyFunc(mlDsaPubKey);
    mlDsaPubKey->pkey = pkey;
    mlDsaPubKey->type = type;
    *returnPubKey = mlDsaPubKey;
    return HCF_SUCCESS;
}

static HcfResult CreateMlDsaPriKey(EVP_PKEY *pkey, int type, HcfOpensslMlDsaPriKey **returnPriKey)
{
    HcfOpensslMlDsaPriKey *mlDsaPriKey =
        (HcfOpensslMlDsaPriKey *)HcfMalloc(sizeof(HcfOpensslMlDsaPriKey), 0);
    if (mlDsaPriKey == NULL) {
        LOGE("Failed to allocate mlDsaPriKey memory.");
        return HCF_ERR_MALLOC;
    }
    FillOpensslMlDsaPriKeyFunc(mlDsaPriKey);
    mlDsaPriKey->pkey = pkey;
    mlDsaPriKey->type = type;
    *returnPriKey = mlDsaPriKey;
    return HCF_SUCCESS;
}

static HcfResult CreateMlDsaKeyPair(const HcfOpensslMlDsaPubKey *pubKey,
    const HcfOpensslMlDsaPriKey *priKey, HcfKeyPair **returnKeyPair)
{
    HcfOpensslMlDsaKeyPair *keyPair =
        (HcfOpensslMlDsaKeyPair *)HcfMalloc(sizeof(HcfOpensslMlDsaKeyPair), 0);
    if (keyPair == NULL) {
        LOGE("Failed to allocate keyPair memory.");
        return HCF_ERR_MALLOC;
    }
    keyPair->base.base.getClass = GetMlDsaKeyPairClass;
    keyPair->base.base.destroy = DestroyMlDsaKeyPair;
    keyPair->base.pubKey = (HcfPubKey *)pubKey;
    keyPair->base.priKey = (HcfPriKey *)priKey;
    *returnKeyPair = (HcfKeyPair *)keyPair;
    return HCF_SUCCESS;
}

static HcfResult GenerateMlDsaEvpKey(int32_t bits, EVP_PKEY **ppkey)
{
    EVP_PKEY_CTX *paramsCtx = NULL;
    HcfResult ret = HCF_SUCCESS;
    int idx = GetMlDsaIndex(bits);
    const char *algName = g_mlDsaAlgNames[idx];
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

static HcfResult GeneratePubKeyByPkey(EVP_PKEY *pkey, int type, HcfOpensslMlDsaPubKey **returnPubKey)
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
    int idx = GetMlDsaIndex(type);
    int nid = NID_ML_DSA_44 + idx;
    EVP_PKEY *evpPkey = OpensslEvpPkeyNewRawPublicKey(nid, NULL, pubData, pubLen);
    HcfFree(pubData);
    if (evpPkey == NULL) {
        LOGE("Failed to create raw public key for nid=%d", nid);
        HcfPrintOpensslError();
        return HCF_ERR_CRYPTO_OPERATION;
    }
    HcfResult ret = CreateMlDsaPubKey(evpPkey, type, returnPubKey);
    if (ret != HCF_SUCCESS) {
        LOGE("Failed to create ML-DSA public key.");
        OpensslEvpPkeyFree(evpPkey);
    }
    return ret;
}

static HcfResult GeneratePriKeyByPkey(EVP_PKEY *pkey, int type, HcfOpensslMlDsaPriKey **returnPriKey)
{
    HcfResult ret = CreateMlDsaPriKey(pkey, type, returnPriKey);
    return ret;
}

static HcfResult GenerateMlDsaPubAndPriKey(int32_t bits,
    HcfOpensslMlDsaPubKey **returnPubKey, HcfOpensslMlDsaPriKey **returnPriKey)
{
    EVP_PKEY *pkey = NULL;
    HcfResult ret = GenerateMlDsaEvpKey(bits, &pkey);
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

static HcfResult ConvertMlDsaPubKey(const HcfBlob *pubKeyBlob, int type, HcfOpensslMlDsaPubKey **returnPubKey)
{
    const unsigned char *tmpData = (const unsigned char *)(pubKeyBlob->data);
    EVP_PKEY *pkey = OpensslD2iPubKey(NULL, &tmpData, pubKeyBlob->len);
    if (pkey == NULL) {
        int idx = GetMlDsaIndex(type);
        int nid = NID_ML_DSA_44 + idx;
        pkey = OpensslEvpPkeyNewRawPublicKey(nid, NULL, pubKeyBlob->data, pubKeyBlob->len);
        if (pkey == NULL) {
            LOGE("Failed to create raw public key.");
            HcfPrintOpensslError();
            return HCF_ERR_CRYPTO_OPERATION;
        }
    }
    int idx = GetMlDsaIndex(type);
    if (OpensslEvpPkeyIsA(pkey, g_mlDsaAlgNames[idx]) != HCF_OPENSSL_SUCCESS) {
        LOGE("Invalid key type for ML-DSA convertKey.");
        OpensslEvpPkeyFree(pkey);
        return HCF_ERR_CRYPTO_OPERATION;
    }
    HcfResult ret = CreateMlDsaPubKey(pkey, type, returnPubKey);
    if (ret != HCF_SUCCESS) {
        LOGE("Failed to create ML-DSA public key.");
        OpensslEvpPkeyFree(pkey);
    }
    return ret;
}

static EVP_PKEY *MlDsaPkeyFromSeed(int type, const uint8_t *seed, size_t seedLen)
{
    int idx = GetMlDsaIndex(type);
    EVP_PKEY_CTX *ctx = OpensslEvpPkeyCtxNewFromName(NULL, g_mlDsaAlgNames[idx], NULL);
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
        LOGE("MlDsa keygen from seed failed.");
        HcfPrintOpensslError();
        OpensslEvpPkeyCtxFree(ctx);
        return NULL;
    }
    OpensslEvpPkeyCtxFree(ctx);
    return pkey;
}

static HcfResult ConvertMlDsaPriKey(const HcfBlob *priKeyBlob, int type, HcfOpensslMlDsaPriKey **returnPriKey)
{
    const unsigned char *tmpData = (const unsigned char *)(priKeyBlob->data);
    EVP_PKEY *pkey = OpensslD2iAutoPrivateKey(NULL, &tmpData, priKeyBlob->len);
    if (pkey == NULL) {
        int idx = GetMlDsaIndex(type);
        int nid = NID_ML_DSA_44 + idx;
        pkey = OpensslEvpPkeyNewRawPrivateKey(nid, NULL, priKeyBlob->data, priKeyBlob->len);
    }
    if (pkey == NULL && priKeyBlob->len == ML_DSA_SEED_BYTES) {
        pkey = MlDsaPkeyFromSeed(type, priKeyBlob->data, priKeyBlob->len);
    }
    if (pkey == NULL) {
        LOGE("Convert ml-dsa pri key failed.");
        HcfPrintOpensslError();
        return HCF_ERR_CRYPTO_OPERATION;
    }
    int idx = GetMlDsaIndex(type);
    if (OpensslEvpPkeyIsA(pkey, g_mlDsaAlgNames[idx]) != HCF_OPENSSL_SUCCESS) {
        LOGE("Invalid key type for ML-DSA convertKey.");
        OpensslEvpPkeyFree(pkey);
        return HCF_ERR_CRYPTO_OPERATION;
    }
    HcfResult ret = CreateMlDsaPriKey(pkey, type, returnPriKey);
    if (ret != HCF_SUCCESS) {
        LOGE("Failed to create ML-DSA private key.");
        OpensslEvpPkeyFree(pkey);
    }
    return ret;
}

static HcfResult EngineGenerateMlDsaKeyPair(HcfAsyKeyGeneratorSpi *self, HcfKeyPair **returnKeyPair)
{
    if (self == NULL || returnKeyPair == NULL) {
        LOGE("Invalid input parameter.");
        return HCF_ERR_PARAMETER_CHECK_FAILED;
    }
    if (!HcfIsClassMatch((HcfObjectBase *)self, GetMlDsaKeyGeneratorSpiClass())) {
        LOGE("Invalid class of self.");
        return HCF_ERR_PARAMETER_CHECK_FAILED;
    }
    HcfAsyKeyGeneratorSpiMlDsaOpensslImpl *impl = (HcfAsyKeyGeneratorSpiMlDsaOpensslImpl *)self;

    HcfOpensslMlDsaPubKey *pubKey = NULL;
    HcfOpensslMlDsaPriKey *priKey = NULL;
    HcfResult ret = GenerateMlDsaPubAndPriKey(impl->bits, &pubKey, &priKey);
    if (ret != HCF_SUCCESS) {
        return ret;
    }

    ret = CreateMlDsaKeyPair(pubKey, priKey, returnKeyPair);
    if (ret != HCF_SUCCESS) {
        LOGE("Failed to create ML-DSA key pair.");
        HcfObjDestroy(pubKey);
        HcfObjDestroy(priKey);
    }
    return ret;
}

static HcfResult EngineConvertMlDsaKey(HcfAsyKeyGeneratorSpi *self, HcfParamsSpec *params, HcfBlob *pubKeyBlob,
    HcfBlob *priKeyBlob, HcfKeyPair **returnKeyPair)
{
    (void)params;
    if ((self == NULL) || (returnKeyPair == NULL)) {
        LOGE("Invalid input parameter.");
        return HCF_ERR_PARAMETER_CHECK_FAILED;
    }
    if (!HcfIsClassMatch((HcfObjectBase *)self, GetMlDsaKeyGeneratorSpiClass())) {
        LOGE("Invalid class of self.");
        return HCF_ERR_PARAMETER_CHECK_FAILED;
    }
    HcfAsyKeyGeneratorSpiMlDsaOpensslImpl *impl = (HcfAsyKeyGeneratorSpiMlDsaOpensslImpl *)self;
    int type = impl->bits;

    bool pubKeyValid = HcfIsBlobValid(pubKeyBlob);
    bool priKeyValid = HcfIsBlobValid(priKeyBlob);
    if ((!pubKeyValid) && (!priKeyValid)) {
        LOGE("Both pubKeyBlob and priKeyBlob are invalid.");
        return HCF_ERR_PARAMETER_CHECK_FAILED;
    }

    HcfOpensslMlDsaPubKey *pubKey = NULL;
    HcfOpensslMlDsaPriKey *priKey = NULL;

    if (pubKeyValid) {
        HcfResult ret = ConvertMlDsaPubKey(pubKeyBlob, type, &pubKey);
        if (ret != HCF_SUCCESS) {
            LOGE("Failed to convert ML-DSA public key.");
            return ret;
        }
    }
    if (priKeyValid) {
        HcfResult ret = ConvertMlDsaPriKey(priKeyBlob, type, &priKey);
        if (ret != HCF_SUCCESS) {
            LOGE("Failed to convert ML-DSA private key.");
            HcfObjDestroy(pubKey);
            pubKey = NULL;
            return ret;
        }
    }

    HcfResult ret = CreateMlDsaKeyPair(pubKey, priKey, returnKeyPair);
    if (ret != HCF_SUCCESS) {
        LOGE("Failed to create ML-DSA key pair.");
        HcfObjDestroy(pubKey);
        HcfObjDestroy(priKey);
    }
    return ret;
}

static HcfResult ConvertMlDsaPemPubKey(const char *pubKeyStr, int type, HcfOpensslMlDsaPubKey **returnPubKey)
{
    EVP_PKEY *pkey = NULL;
    int idx = GetMlDsaIndex(type);
    HcfResult ret = ConvertPubPemStrToKey(&pkey, g_mlDsaAlgNames[idx], EVP_PKEY_PUBLIC_KEY, pubKeyStr);
    if (ret != HCF_SUCCESS) {
        LOGE("Convert ML-DSA pem public key failed.");
        return ret;
    }
    ret = CreateMlDsaPubKey(pkey, type, returnPubKey);
    if (ret != HCF_SUCCESS) {
        LOGE("Failed to create ML-DSA public key.");
        OpensslEvpPkeyFree(pkey);
    }
    return ret;
}

static HcfResult ConvertMlDsaPemPriKey(const char *priKeyStr, int type, HcfOpensslMlDsaPriKey **returnPriKey)
{
    EVP_PKEY *pkey = NULL;
    int idx = GetMlDsaIndex(type);
    HcfResult ret = ConvertPriPemStrToKey(priKeyStr, &pkey, g_mlDsaAlgNames[idx]);
    if (ret != HCF_SUCCESS) {
        LOGE("Convert ML-DSA pem private key failed.");
        return ret;
    }
    ret = CreateMlDsaPriKey(pkey, type, returnPriKey);
    if (ret != HCF_SUCCESS) {
        LOGE("Failed to create ML-DSA private key.");
        OpensslEvpPkeyFree(pkey);
    }
    return ret;
}

static HcfResult EngineConvertMlDsaPemKey(HcfAsyKeyGeneratorSpi *self, HcfParamsSpec *params, const char *pubKeyStr,
    const char *priKeyStr, HcfKeyPair **returnKeyPair)
{
    if ((self == NULL) || (returnKeyPair == NULL) || ((pubKeyStr == NULL) && (priKeyStr == NULL))) {
        LOGE("Invalid input parameter.");
        return HCF_ERR_PARAMETER_CHECK_FAILED;
    }
    if (params != NULL) {
        LOGE("ML-DSA does not support convertPemKey with password.");
        return HCF_ERR_INVALID_CALL;
    }
    if (!HcfIsClassMatch((HcfObjectBase *)self, GetMlDsaKeyGeneratorSpiClass())) {
        LOGE("Class not match.");
        return HCF_ERR_PARAMETER_CHECK_FAILED;
    }
    HcfAsyKeyGeneratorSpiMlDsaOpensslImpl *impl = (HcfAsyKeyGeneratorSpiMlDsaOpensslImpl *)self;
    int type = impl->bits;

    HcfOpensslMlDsaPubKey *pubKey = NULL;
    HcfOpensslMlDsaPriKey *priKey = NULL;

    if (pubKeyStr != NULL && strlen(pubKeyStr) != 0) {
        HcfResult ret = ConvertMlDsaPemPubKey(pubKeyStr, type, &pubKey);
        if (ret != HCF_SUCCESS) {
            LOGE("Convert ML-DSA pem pubKey failed.");
            return ret;
        }
    }
    if (priKeyStr != NULL && strlen(priKeyStr) != 0) {
        HcfResult ret = ConvertMlDsaPemPriKey(priKeyStr, type, &priKey);
        if (ret != HCF_SUCCESS) {
            LOGE("Convert ML-DSA pem priKey failed.");
            HcfObjDestroy(pubKey);
            pubKey = NULL;
            return ret;
        }
    }

    HcfResult ret = CreateMlDsaKeyPair(pubKey, priKey, returnKeyPair);
    if (ret != HCF_SUCCESS) {
        LOGE("Failed to create ML-DSA key pair.");
        HcfObjDestroy(pubKey);
        HcfObjDestroy(priKey);
    }
    return ret;
}

static HcfResult EngineGenerateMlDsaKeyPairBySpec(const HcfAsyKeyGeneratorSpi *self,
    const HcfAsyKeyParamsSpec *paramsSpec, HcfKeyPair **returnKeyPair)
{
    (void)self;
    (void)paramsSpec;
    (void)returnKeyPair;
    return HCF_ERR_INVALID_CALL;
}

static HcfResult EngineGenerateMlDsaPubKeyBySpec(const HcfAsyKeyGeneratorSpi *self,
    const HcfAsyKeyParamsSpec *paramsSpec, HcfPubKey **returnPubKey)
{
    (void)self;
    (void)paramsSpec;
    (void)returnPubKey;
    return HCF_ERR_INVALID_CALL;
}

static HcfResult EngineGenerateMlDsaPriKeyBySpec(const HcfAsyKeyGeneratorSpi *self,
    const HcfAsyKeyParamsSpec *paramsSpec, HcfPriKey **returnPriKey)
{
    (void)self;
    (void)paramsSpec;
    (void)returnPriKey;
    return HCF_ERR_INVALID_CALL;
}

HcfResult HcfAsyKeyGeneratorSpiMlDsaCreate(HcfAsyKeyGenParams *params, HcfAsyKeyGeneratorSpi **returnObj)
{
    if (params == NULL || returnObj == NULL) {
        LOGE("Invalid input parameter.");
        return HCF_ERR_PARAMETER_CHECK_FAILED;
    }
    HcfAsyKeyGeneratorSpiMlDsaOpensslImpl *impl =
        (HcfAsyKeyGeneratorSpiMlDsaOpensslImpl *)HcfMalloc(sizeof(HcfAsyKeyGeneratorSpiMlDsaOpensslImpl), 0);
    if (impl == NULL) {
        LOGE("Failed to allocate impl memory.");
        return HCF_ERR_MALLOC;
    }
    impl->base.base.getClass = GetMlDsaKeyGeneratorSpiClass;
    impl->base.base.destroy = DestroyMlDsaKeyGeneratorSpiImpl;
    impl->base.engineGenerateKeyPair = EngineGenerateMlDsaKeyPair;
    impl->base.engineConvertKey = EngineConvertMlDsaKey;
    impl->base.engineConvertPemKey = EngineConvertMlDsaPemKey;
    impl->base.engineGenerateKeyPairBySpec = EngineGenerateMlDsaKeyPairBySpec;
    impl->base.engineGeneratePubKeyBySpec = EngineGenerateMlDsaPubKeyBySpec;
    impl->base.engineGeneratePriKeyBySpec = EngineGenerateMlDsaPriKeyBySpec;
    impl->bits = params->bits;

    *returnObj = (HcfAsyKeyGeneratorSpi *)impl;
    return HCF_SUCCESS;
}
