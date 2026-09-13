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

#include "securec.h"
#include "string.h"

#include "openssl_adapter.h"
#include "openssl_class.h"
#include "openssl_common.h"
#include "openssl/pem.h"
#include "openssl/x509.h"

#include "algorithm_parameter.h"
#include "asy_key_generator_spi.h"
#include "detailed_rsa_key_params.h"
#include "log.h"
#include "memory.h"
#include "rsa_openssl_common.h"
#include "utils.h"
#include "asy_key_generator.h"

#include "rsa_asy_key_generator_openssl.h"

#define OPENSSL_BITS_PER_BYTE 8
#define OPENSSL_RSA_KEYPAIR_CNT 3
#define OPENSSL_RSA_KEYGEN_DEFAULT_PRIMES 2
#define PASSWORD_MAX_LENGTH 4096
#define MAX_KEY_SIZE 8192
#define MIN_KEY_SIZE 512
#define PRIMES_2 2
#define PRIMES_3 3
#define PRIMES_4 4
#define PRIMES_5 5

enum OpensslRsaKeySize {
    OPENSSL_RSA_KEY_SIZE_BY_SPEC = 0,
    OPENSSL_RSA_KEY_SIZE_512 = 512,
    OPENSSL_RSA_KEY_SIZE_768 = 768,
    OPENSSL_RSA_KEY_SIZE_1024 = 1024,
    OPENSSL_RSA_KEY_SIZE_2048 = 2048,
    OPENSSL_RSA_KEY_SIZE_3072 = 3072,
    OPENSSL_RSA_KEY_SIZE_4096 = 4096,
    OPENSSL_RSA_KEY_SIZE_8192 = 8192,
};

enum OpensslRsaPrimesSize {
    OPENSSL_RSA_PRIMES_SIZE_2 = 2,
    OPENSSL_RSA_PRIMES_SIZE_3 = 3,
    OPENSSL_RSA_PRIMES_SIZE_4 = 4,
    OPENSSL_RSA_PRIMES_SIZE_5 = 5,
};

typedef struct {
    int32_t bits;
    int32_t primes;
    BIGNUM *pubExp;
} HcfAsyKeyGenSpiRsaParams;

typedef struct {
    HcfAsyKeyGeneratorSpi base;

    HcfAsyKeyGenSpiRsaParams *params;
} HcfAsyKeyGeneratorSpiRsaOpensslImpl;

#define CIPHER_LIST_SIZE 4

static const char *g_supportedCiphers[] = {
    "DES-EDE3-CBC",
    "AES-128-CBC",
    "AES-192-CBC",
    "AES-256-CBC"
};

static bool IsCipherSupported(const char *cipher)
{
    if (cipher == NULL) {
        LOGE("Cipher is NULL.");
        return false;
    }
    for (size_t i = 0; i < CIPHER_LIST_SIZE; i++) {
        if (strcmp(cipher, g_supportedCiphers[i]) == 0) {
            return true;
        }
    }
    return false;
}

static HcfResult CheckRsaKeyGenParams(HcfAsyKeyGenSpiRsaParams *params)
{
    switch (params->bits) {
        case OPENSSL_RSA_KEY_SIZE_BY_SPEC:
            break;
        case OPENSSL_RSA_KEY_SIZE_512:
        case OPENSSL_RSA_KEY_SIZE_768:
            if (params->primes != OPENSSL_RSA_PRIMES_SIZE_2) {
                LOGE("Set invalid primes %{public}d to Keygen bits %{public}d.", params->primes, params->bits);
                return HCF_INVALID_PARAMS;
            }
            break;
        case OPENSSL_RSA_KEY_SIZE_1024:
        case OPENSSL_RSA_KEY_SIZE_2048:
        case OPENSSL_RSA_KEY_SIZE_3072:
            if (params->primes > OPENSSL_RSA_PRIMES_SIZE_3 || params->primes < OPENSSL_RSA_PRIMES_SIZE_2) {
                LOGE("Set invalid primes %{public}d to Keygen bits %{public}d.", params->primes, params->bits);
                return HCF_INVALID_PARAMS;
            }
            break;
        case OPENSSL_RSA_KEY_SIZE_4096:
            if (params->primes > OPENSSL_RSA_PRIMES_SIZE_4 || params->primes < OPENSSL_RSA_PRIMES_SIZE_2) {
                LOGE("Set invalid primes %{public}d to Keygen bits %{public}d.", params->primes, params->bits);
                return HCF_INVALID_PARAMS;
            }
            break;
        case OPENSSL_RSA_KEY_SIZE_8192: // This keySize can use primes from 2 to 5.
            break;
        default:
            LOGE("The current bits %{public}d is invalid.", params->bits);
            return HCF_INVALID_PARAMS;
    }
    return HCF_SUCCESS;
}

static const char *GetOpensslPubkeyClass(void)
{
    return OPENSSL_RSA_PUBKEY_CLASS;
}

static const char *GetOpensslPrikeyClass(void)
{
    return OPENSSL_RSA_PRIKEY_CLASS;
}

static const char *GetOpensslKeyPairClass(void)
{
    return OPENSSL_RSA_KEYPAIR_CLASS;
}

static HcfResult GetRsaPubKeySpecString(const HcfPubKey *self, const AsyKeySpecItem item,
    char **returnString)
{
    (void)self;
    (void)returnString;
    LOGE("Rsa has no string attribute");
    return HCF_NOT_SUPPORT;
}

static HcfResult GetRsaPubKeySpecInt(const HcfPubKey *self, const AsyKeySpecItem item,
    int *returnInt)
{
    (void)self;
    (void)returnInt;
    LOGE("Rsa has no integer attribute");
    return HCF_NOT_SUPPORT;
}

static HcfResult GetRsaPriKeySpecString(const HcfPriKey *self, const AsyKeySpecItem item,
    char **returnString)
{
    (void)self;
    (void)returnString;
    LOGE("Rsa has no string attribute");
    return HCF_NOT_SUPPORT;
}

static HcfResult GetRsaPriKeySpecInt(const HcfPriKey *self, const AsyKeySpecItem item,
    int *returnInt)
{
    (void)self;
    (void)returnInt;
    LOGE("Rsa has no integer attribute");
    return HCF_NOT_SUPPORT;
}

static HcfResult GetRsaFromPriKey(RSA *priKey, RSA **returnRsa)
{
    if (priKey == NULL || returnRsa == NULL) {
        LOGE("Invalid input parameter.");
        return HCF_ERR_PARAMETER_CHECK_FAILED;
    }
    const BIGNUM *n = OpensslRsaGet0N(priKey);
    if (n == NULL) {
        LOGE("fail to get n");
        return HCF_ERR_CRYPTO_OPERATION;
    }
    const BIGNUM *e = OpensslRsaGet0E(priKey);
    if (e == NULL) {
        LOGE("fail to get e");
        return HCF_ERR_CRYPTO_OPERATION;
    }
    BIGNUM *dupN = OpensslBnDup(n);
    if (dupN == NULL) {
        LOGE("fail to dup n");
        return HCF_ERR_CRYPTO_OPERATION;
    }
    BIGNUM *dupE = OpensslBnDup(e);
    if (dupE == NULL) {
        LOGE("fail to dup e");
        OpensslBnFree(dupN);
        return HCF_ERR_CRYPTO_OPERATION;
    }
    RSA *rsa = OpensslRsaNew();
    if (rsa == NULL) {
        OpensslBnFree(dupN);
        OpensslBnFree(dupE);
        LOGE("new RSA fail");
        return HCF_ERR_CRYPTO_OPERATION;
    }
    if (OpensslRsaSet0Key(rsa, dupN, dupE, NULL) != HCF_OPENSSL_SUCCESS) {
        LOGE("set RSA fail");
        HcfPrintOpensslError();
        OpensslBnFree(dupN);
        OpensslBnFree(dupE);
        OpensslRsaFree(rsa);
        rsa = NULL;
        return HCF_ERR_CRYPTO_OPERATION;
    }
    *returnRsa = rsa;
    return HCF_SUCCESS;
}

static HcfResult GetRsaPriKeySpecBigInteger(const HcfPriKey *self, const AsyKeySpecItem item,
    HcfBigInteger *returnBigInteger)
{
    if (self == NULL || returnBigInteger == NULL) {
        LOGE("Input params is invalid.");
        return HCF_INVALID_PARAMS;
    }
    if (!HcfIsClassMatch((HcfObjectBase *)self, OPENSSL_RSA_PRIKEY_CLASS)) {
        LOGE("Class not match");
        return HCF_INVALID_PARAMS;
    }
    HcfOpensslRsaPriKey *impl = (HcfOpensslRsaPriKey *)self;
    if (impl->sk == NULL) {
        LOGE("Cannot use priKey after free");
        return HCF_INVALID_PARAMS;
    }
    HcfResult ret = HCF_INVALID_PARAMS;
    if (item == RSA_N_BN) {
        const BIGNUM *n = OpensslRsaGet0N(impl->sk);
        if (n == NULL) {
            LOGE("fail to get n");
            return HCF_ERR_CRYPTO_OPERATION;
        }
        ret = BigNumToBigInteger(n, returnBigInteger);
        if (ret != HCF_SUCCESS) {
            LOGE("fail get RSA Big Integer n");
            return ret;
        }
    } else if (item == RSA_SK_BN) {
        const BIGNUM *d = OpensslRsaGet0D(impl->sk);
        if (d == NULL) {
            LOGE("fail to get sk");
            return HCF_ERR_CRYPTO_OPERATION;
        }
        ret = BigNumToBigInteger(d, returnBigInteger);
        if (ret != HCF_SUCCESS) {
            LOGE("fail get RSA Big Integer d");
            return ret;
        }
    } else {
        LOGE("Invalid RSA pri key spec");
        return HCF_INVALID_PARAMS;
    }
    return ret;
}

static HcfResult GetRsaPubKeySpecBigInteger(const HcfPubKey *self, const AsyKeySpecItem item,
    HcfBigInteger *returnBigInteger)
{
    if (self == NULL || returnBigInteger == NULL) {
        LOGE("Input params is invalid.");
        return HCF_INVALID_PARAMS;
    }
    if (!HcfIsClassMatch((HcfObjectBase *)self, OPENSSL_RSA_PUBKEY_CLASS)) {
        LOGE("Class not match");
        return HCF_INVALID_PARAMS;
    }
    HcfOpensslRsaPubKey *impl = (HcfOpensslRsaPubKey *)self;
    HcfResult ret = HCF_INVALID_PARAMS;
    if (item == RSA_N_BN) {
        const BIGNUM *n = OpensslRsaGet0N(impl->pk);
        if (n == NULL) {
            LOGE("fail to get n");
            return HCF_ERR_CRYPTO_OPERATION;
        }
        ret = BigNumToBigInteger(n, returnBigInteger);
        if (ret != HCF_SUCCESS) {
            LOGE("fail get RSA Big Integer n");
            return ret;
        }
    } else if (item == RSA_PK_BN) {
        const BIGNUM *e = OpensslRsaGet0E(impl->pk);
        if (e == NULL) {
            LOGE("fail to get pk");
            return HCF_ERR_CRYPTO_OPERATION;
        }
        ret = BigNumToBigInteger(e, returnBigInteger);
        if (ret != HCF_SUCCESS) {
            LOGE("fail get RSA Big Integer e");
            return ret;
        }
    } else {
        LOGE("Invalid RSA pub key spec");
        return HCF_INVALID_PARAMS;
    }
    return ret;
}

static void DestroyPubKey(HcfObjectBase *self)
{
    if (self == NULL) {
        LOGE("Public key object is null.");
        return;
    }
    if (!HcfIsClassMatch(self, OPENSSL_RSA_PUBKEY_CLASS)) {
        LOGE("Class not match");
        return;
    }
    HcfOpensslRsaPubKey *impl = (HcfOpensslRsaPubKey *)self;
    OpensslRsaFree(impl->pk);
    impl->pk = NULL;
    HcfFree(self);
}

static void DestroyPriKey(HcfObjectBase *self)
{
    if (self == NULL) {
        LOGE("Private key object is null.");
        return;
    }
    if (!HcfIsClassMatch(self, OPENSSL_RSA_PRIKEY_CLASS)) {
        LOGE("Class not match");
        return;
    }
    HcfOpensslRsaPriKey *impl = (HcfOpensslRsaPriKey*)self;
    // RSA_free func will clear private information
    OpensslRsaFree(impl->sk);
    impl->sk = NULL;
    HcfFree(self);
}

static void DestroyKeyPair(HcfObjectBase *self)
{
    if (self == NULL) {
        LOGE("PubKey is NULL.");
        return;
    }
    if (!HcfIsClassMatch(self, OPENSSL_RSA_KEYPAIR_CLASS)) {
        LOGE("Class not match");
        return;
    }
    HcfOpensslRsaKeyPair *impl = (HcfOpensslRsaKeyPair*)self;
    if (impl->base.pubKey != NULL) {
        DestroyPubKey((HcfObjectBase *)impl->base.pubKey);
        impl->base.pubKey = NULL;
    }
    if (impl->base.priKey != NULL) {
        DestroyPriKey((HcfObjectBase *)impl->base.priKey);
        impl->base.priKey = NULL;
    }
    HcfFree(self);
}

static HcfResult CopyMemFromBIO(BIO *bio, HcfBlob *outBlob)
{
    if (bio == NULL || outBlob == NULL) {
        LOGE("Invalid input.");
        return HCF_INVALID_PARAMS;
    }
    int len = BIO_pending(bio);
    if (len < 0) {
        LOGE("Bio len less than 0.");
        return HCF_INVALID_PARAMS;
    }
    HcfBlob blob;
    blob.len = len;
    blob.data = (uint8_t *)HcfMalloc(sizeof(uint8_t) * len, 0);
    if (blob.data == NULL) {
        LOGE("Malloc mem for blob fail.");
        return HCF_ERR_MALLOC;
    }
    if (OpensslBioRead(bio, blob.data, blob.len) <= 0) {
        LOGE("Bio read fail");
        HcfPrintOpensslError();
        HcfFree(blob.data);
        blob.data = NULL;
        return HCF_ERR_CRYPTO_OPERATION;
    }
    outBlob->len = blob.len;
    outBlob->data = blob.data;
    return HCF_SUCCESS;
}

static HcfResult CopyStrFromBIO(BIO *bio, char **returnString)
{
    if (bio == NULL || returnString == NULL) {
        LOGE("Invalid input.");
        return HCF_INVALID_PARAMS;
    }
    int len = BIO_pending(bio);
    if (len < 0) {
        LOGE("Bio len less than 0.");
        return HCF_INVALID_PARAMS;
    }
    *returnString = (char *)HcfMalloc(len + 1, 0);
    if (*returnString == NULL) {
        LOGE("Malloc mem for blob fail.");
        return HCF_ERR_MALLOC;
    }
    if (OpensslBioRead(bio, *returnString, len) <= 0) {
        LOGE("Bio read fail");
        HcfPrintOpensslError();
        HcfFree(*returnString);
        *returnString = NULL;
        return HCF_ERR_CRYPTO_OPERATION;
    }
    return HCF_SUCCESS;
}

static HcfResult ConvertPubKeyFromX509(HcfBlob *x509Blob, RSA **rsa)
{
    const unsigned char *temp = (const unsigned char *)x509Blob->data;
    RSA *tempRsa = OpensslD2iRsaPubKey(NULL, &temp, x509Blob->len);
    if (tempRsa == NULL) {
        LOGE("d2i_RSA_PUBKEY fail.");
        return HCF_ERR_CRYPTO_OPERATION;
    }
    *rsa = tempRsa;
    return HCF_SUCCESS;
}

static HcfResult ConvertPubKeyFromPkcs1(HcfBlob *pkcs1Blob, RSA **rsa)
{
    const unsigned char *temp = (const unsigned char *)pkcs1Blob->data;
    RSA *tempRsa = OpensslD2iRsaPublicKey(NULL, &temp, pkcs1Blob->len);
    if (tempRsa == NULL) {
        LOGE("d2i_RSAPublicKey fail.");
        HcfPrintOpensslError();
        return HCF_ERR_CRYPTO_OPERATION;
    }
    *rsa = tempRsa;
    return HCF_SUCCESS;
}

static HcfResult ConvertPriKeyFromDer(HcfBlob *blob, RSA **rsa)
{
    const unsigned char *temp = (const unsigned char *)blob->data;
    EVP_PKEY *pKey = OpensslD2iAutoPrivateKey(NULL, &temp, blob->len);
    if (pKey == NULL) {
        LOGE("d2i_AutoPrivateKey fail.");
        HcfPrintOpensslError();
        return HCF_ERR_CRYPTO_OPERATION;
    }
    RSA *tmpRsa = OpensslEvpPkeyGet1Rsa(pKey);
    if (tmpRsa == NULL) {
        LOGE("EVP_PKEY_get1_RSA fail");
        HcfPrintOpensslError();
        OpensslEvpPkeyFree(pKey);
        return HCF_ERR_CRYPTO_OPERATION;
    }
    *rsa = tmpRsa;
    OpensslEvpPkeyFree(pKey);
    return HCF_SUCCESS;
}

static HcfResult EncodePubKeyToX509(RSA *rsa, HcfBlob *returnBlob)
{
    unsigned char *tempData = NULL;
    int len = OpensslI2dRsaPubKey(rsa, &tempData);
    if (len <= 0) {
        LOGE("i2d_RSA_PUBKEY fail");
        HcfPrintOpensslError();
        return HCF_ERR_CRYPTO_OPERATION;
    }
    returnBlob->data = tempData;
    returnBlob->len = len;
    return HCF_SUCCESS;
}

static HcfResult EncodePriKeyToPKCS8(RSA *rsa, HcfBlob *returnBlob)
{
    EVP_PKEY *pKey = NewEvpPkeyByRsa(rsa, true);
    if (pKey == NULL) {
        LOGE("Failed to create EVP_PKEY from RSA key.");
        return HCF_ERR_CRYPTO_OPERATION;
    }
    HcfResult ret = HCF_SUCCESS;
    BIO *bio = OpensslBioNew(OpensslBioSMem());
    if (bio == NULL) {
        LOGE("BIO new fail.");
        HcfPrintOpensslError();
        ret = HCF_ERR_CRYPTO_OPERATION;
        goto ERR2;
    }
    if (i2d_PKCS8PrivateKey_bio(bio, pKey, NULL, NULL, 0, NULL, NULL) != HCF_OPENSSL_SUCCESS) {
        LOGE("i2b_PrivateKey_bio fail.");
        HcfPrintOpensslError();
        ret = HCF_ERR_CRYPTO_OPERATION;
        goto ERR1;
    }
    if (CopyMemFromBIO(bio, returnBlob) != HCF_SUCCESS) {
        LOGE("Failed to copy data from BIO to output blob.");
        ret = HCF_ERR_CRYPTO_OPERATION;
        goto ERR1;
    }
ERR1:
    OpensslBioFreeAll(bio);
ERR2:
    OpensslEvpPkeyFree(pKey);
    return ret;
}

static HcfResult EncodePriKeyToPKCS1(RSA *rsa, HcfBlob *returnBlob)
{
    BIO *bio = OpensslBioNew(OpensslBioSMem());
    if (bio == NULL) {
        LOGE("BIO new fail.");
        HcfPrintOpensslError();
        return HCF_ERR_CRYPTO_OPERATION;
    }
    int ret = i2d_RSAPrivateKey_bio(bio, rsa);
    if (ret != HCF_OPENSSL_SUCCESS) {
        LOGE("i2d_RSAPrivateKey_bio fail.");
        HcfPrintOpensslError();
        OpensslBioFreeAll(bio);
        return HCF_ERR_CRYPTO_OPERATION;
    }
    HcfResult res = CopyMemFromBIO(bio, returnBlob);
    OpensslBioFreeAll(bio);
    return res;
}

static HcfResult GetRsaPriKeyEncodedDer(const HcfPriKey *self, const char *format, HcfBlob *returnBlob)
{
    if (self == NULL || format == NULL || returnBlob == NULL) {
        LOGE("param is null.");
        return HCF_INVALID_PARAMS;
    }
    if (!HcfIsClassMatch((HcfObjectBase *)self, OPENSSL_RSA_PRIKEY_CLASS)) {
        LOGE("Class not match.");
        return HCF_INVALID_PARAMS;
    }
    HcfOpensslRsaPriKey *impl = (HcfOpensslRsaPriKey *)self;
    RSA *rsa = impl->sk;
    if (rsa == NULL) {
        LOGE("Invalid input.");
        return HCF_INVALID_PARAMS;
    }
    const BIGNUM *p = NULL;
    const BIGNUM *q = NULL;
    OpensslRsaGet0Factors(rsa, &p, &q);
    if (p == NULL || q == NULL) {
        LOGE("RSA private key missing p, q, not support to encode der.");
        return HCF_INVALID_PARAMS;
    }
    if (strcmp(format, "PKCS8") == 0) {
        return EncodePriKeyToPKCS8(rsa, returnBlob);
    } else if (strcmp(format, "PKCS1") == 0) {
        return EncodePriKeyToPKCS1(rsa, returnBlob);
    } else {
        LOGE("format is invalid.");
        return HCF_INVALID_PARAMS;
    }
}

static HcfResult GetPubKeyEncoded(HcfKey *self, HcfBlob *returnBlob)
{
    if (self == NULL || returnBlob == NULL) {
        LOGE("Input params is invalid.");
        return HCF_INVALID_PARAMS;
    }
    if (!HcfIsClassMatch((HcfObjectBase *)self, OPENSSL_RSA_PUBKEY_CLASS)) {
        LOGE("Class not match.");
        return HCF_INVALID_PARAMS;
    }
    HcfOpensslRsaPubKey *impl = (HcfOpensslRsaPubKey *)self;
    return EncodePubKeyToX509(impl->pk, returnBlob);
}

static HcfResult GetPubKeyPkcs1Pem(RSA *pk, char **returnString)
{
    BIO *bio = OpensslBioNew(OpensslBioSMem());
    if (bio == NULL) {
        LOGE("BIO new fail.");
        HcfPrintOpensslError();
        return HCF_ERR_CRYPTO_OPERATION;
    }
    int ret = OpensslPemWriteBioRsaPublicKey(bio, pk);
    if (ret != HCF_OPENSSL_SUCCESS) {
        LOGE("Failed to write RSA public key in PKCS1 PEM format.");
        HcfPrintOpensslError();
        OpensslBioFreeAll(bio);
        return HCF_ERR_CRYPTO_OPERATION;
    }
    if (CopyStrFromBIO(bio, returnString) != HCF_SUCCESS) {
        LOGE("Failed to copy string from BIO.");
        OpensslBioFreeAll(bio);
        return HCF_ERR_CRYPTO_OPERATION;
    }
    OpensslBioFreeAll(bio);
    return HCF_SUCCESS;
}

static HcfResult GetPubKeyX509Pem(RSA *pk, char **returnString)
{
    BIO *bio = OpensslBioNew(OpensslBioSMem());
    if (bio == NULL) {
        LOGE("BIO new fail.");
        HcfPrintOpensslError();
        return HCF_ERR_CRYPTO_OPERATION;
    }
    int ret = OpensslPemWriteBioRsaPubKey(bio, pk);
    if (ret != HCF_OPENSSL_SUCCESS) {
        LOGE("Failed to write RSA public key in X509 PEM format.");
        HcfPrintOpensslError();
        OpensslBioFreeAll(bio);
        return HCF_ERR_CRYPTO_OPERATION;
    }
    if (CopyStrFromBIO(bio, returnString) != HCF_SUCCESS) {
        LOGE("Failed to copy string from BIO.");
        OpensslBioFreeAll(bio);
        return HCF_ERR_CRYPTO_OPERATION;
    }
    OpensslBioFreeAll(bio);
    return HCF_SUCCESS;
}

static HcfResult GetPubKeyPem(const char *format, RSA *pk, char **returnString)
{
    HcfResult result;
    if (strcmp(format, "PKCS1") == 0) {
        result = GetPubKeyPkcs1Pem(pk, returnString);
        if (result != HCF_SUCCESS) {
            return result;
        }
    }
    if (strcmp(format, "X509") == 0) {
        result = GetPubKeyX509Pem(pk, returnString);
        if (result != HCF_SUCCESS) {
            return result;
        }
    }
    return HCF_SUCCESS;
}

static HcfResult GetPubKeyEncodedPem(HcfKey *self, const char *format, char **returnString)
{
    if (self == NULL || format == NULL|| returnString == NULL) {
        LOGE("param is null.");
        return HCF_INVALID_PARAMS;
    }
    if (!HcfIsClassMatch((HcfObjectBase *)self, OPENSSL_RSA_PUBKEY_CLASS)) {
        LOGE("Class not match.");
        return HCF_INVALID_PARAMS;
    }
    const char *outPutStruct = NULL;
    if (strcmp(format, "PKCS1") == 0) {
        outPutStruct = "pkcs1";
    } else if (strcmp(format, "X509") == 0) {
        outPutStruct = "subjectPublicKeyInfo";
    } else {
        LOGE("format is invalid.");
        return HCF_INVALID_PARAMS;
    }
    HcfOpensslRsaPubKey *impl = (HcfOpensslRsaPubKey *)self;
    EVP_PKEY *pkey = NewEvpPkeyByRsa(impl->pk, true);
    if (pkey == NULL) {
        LOGE("Failed to create EVP_PKEY from RSA key.");
        return HCF_ERR_CRYPTO_OPERATION;
    }
    HcfBlob returnBlob = {};
    HcfResult result = GetKeyEncoded(pkey, outPutStruct, "PEM", EVP_PKEY_PUBLIC_KEY, &returnBlob);
    OpensslEvpPkeyFree(pkey);
    *returnString = (char *)returnBlob.data;
    if (result != HCF_SUCCESS) {
        if (GetPubKeyPem(format, impl->pk, returnString) != HCF_SUCCESS) {
            LOGE("Failed to get public key PEM encoding.");
            return HCF_ERR_CRYPTO_OPERATION;
        }
    }
    return HCF_SUCCESS;
}

static HcfResult GetPriKeyEncoded(HcfKey *self, HcfBlob *returnBlob)
{
    if (self == NULL || returnBlob == NULL) {
        LOGE("Key is null.");
        return HCF_INVALID_PARAMS;
    }

    if (!HcfIsClassMatch((HcfObjectBase *)self, OPENSSL_RSA_PRIKEY_CLASS)) {
        LOGE("Class not match.");
        return HCF_INVALID_PARAMS;
    }
    HcfOpensslRsaPriKey *impl = (HcfOpensslRsaPriKey *)self;
    const BIGNUM *p = NULL;
    const BIGNUM *q = NULL;
    OpensslRsaGet0Factors(impl->sk, &p, &q);
    if (p == NULL || q == NULL) {
        LOGE("RSA private key missing p, q, not support to get encoded PK");
        return HCF_NOT_SUPPORT;
    }
    return EncodePriKeyToPKCS8(impl->sk, returnBlob);
}

static HcfResult GetPrikeyPkcs8Pem(EVP_PKEY *pkey, const EVP_CIPHER *cipher, const char *passWord, char **returnString)
{
    BIO *bio = OpensslBioNew(OpensslBioSMem());
    if (bio == NULL) {
        LOGE("BIO new fail.");
        HcfPrintOpensslError();
        return HCF_ERR_CRYPTO_OPERATION;
    }

    size_t passLen = 0;
    if (passWord != NULL) {
        passLen = strlen(passWord);
    }

    int ret = PEM_write_bio_PKCS8PrivateKey(bio, pkey, cipher, passWord, passLen, NULL, NULL);
    if (ret != HCF_OPENSSL_SUCCESS) {
        LOGE("Failed to write private key in PKCS8 PEM format.");
        HcfPrintOpensslError();
        OpensslBioFreeAll(bio);
        return HCF_ERR_CRYPTO_OPERATION;
    }
    if (CopyStrFromBIO(bio, returnString) != HCF_SUCCESS) {
        LOGE("Failed to copy string from BIO.");
        OpensslBioFreeAll(bio);
        return HCF_ERR_CRYPTO_OPERATION;
    }
    OpensslBioFreeAll(bio);
    return HCF_SUCCESS;
}

static HcfResult GetPrikeyPkcs1Pem(EVP_PKEY *pkey, const EVP_CIPHER *cipher, const char *passWord, char **returnString)
{
    BIO *bio = OpensslBioNew(OpensslBioSMem());
    if (bio == NULL) {
        LOGE("BIO new fail.");
        HcfPrintOpensslError();
        return HCF_ERR_CRYPTO_OPERATION;
    }

    size_t passLen = 0;
    if (passWord != NULL) {
        passLen = strlen(passWord);
    }

    int ret = PEM_write_bio_PrivateKey_traditional(bio, pkey, cipher, (unsigned char *)passWord, passLen, NULL, NULL);
    if (ret != HCF_OPENSSL_SUCCESS) {
        LOGE("Failed to write RSA private key in traditional PEM format.");
        HcfPrintOpensslError();
        OpensslBioFreeAll(bio);
        return HCF_ERR_CRYPTO_OPERATION;
    }
    if (CopyStrFromBIO(bio, returnString) != HCF_SUCCESS) {
        LOGE("Failed to copy string from BIO.");
        OpensslBioFreeAll(bio);
        return HCF_ERR_CRYPTO_OPERATION;
    }
    OpensslBioFreeAll(bio);
    return HCF_SUCCESS;
}

static HcfResult GetPriKeyPem(const char *format, EVP_PKEY *pkey, const EVP_CIPHER *cipher,
    const char *passWord, char **returnString)
{
    HcfResult result;
    if (strcmp(format, "PKCS8") == 0) {
        result = GetPrikeyPkcs8Pem(pkey, cipher, passWord, returnString);
        if (result != HCF_SUCCESS) {
            return result;
        }
    } else if (strcmp(format, "PKCS1") == 0) {
        result = GetPrikeyPkcs1Pem(pkey, cipher, passWord, returnString);
        if (result != HCF_SUCCESS) {
            return result;
        }
    } else {
        LOGE("format is invalid.");
        return HCF_INVALID_PARAMS;
    }
    return HCF_SUCCESS;
}

static HcfResult ValidateInputParams(const HcfPriKey *self, const char *format, char **returnString)
{
    if (self == NULL || format == NULL || returnString == NULL) {
        LOGE("param is null.");
        return HCF_INVALID_PARAMS;
    }
    if (!HcfIsClassMatch((HcfObjectBase *)self, OPENSSL_RSA_PRIKEY_CLASS)) {
        LOGE("Class not match.");
        return HCF_INVALID_PARAMS;
    }
    return HCF_SUCCESS;
}

static HcfResult GetPriKeyEncodedPem(const HcfPriKey *self, HcfParamsSpec *params, const char *format,
    char **returnString)
{
    HcfResult result = ValidateInputParams(self, format, returnString);
    if (result != HCF_SUCCESS) {
        return result;
    }

    HcfOpensslRsaPriKey *impl = (HcfOpensslRsaPriKey *)self;
    EVP_PKEY *pkey = NewEvpPkeyByRsa(impl->sk, true);
    if (pkey == NULL) {
        LOGE("Failed to create EVP_PKEY from RSA key.");
        return HCF_ERR_CRYPTO_OPERATION;
    }

    if (params != NULL) {
        const EVP_CIPHER *cipher = NULL;
        const char *passWord = NULL;
        HcfKeyEncodingParamsSpec *spec = (HcfKeyEncodingParamsSpec *)params;
        const char *cipherStr = (const char *)spec->cipher;
        if (!IsCipherSupported(cipherStr)) {
            LOGE("Cipher algorithm %{public}s not supported", cipherStr);
            OpensslEvpPkeyFree(pkey);
            return HCF_NOT_SUPPORT;
        }
        passWord = (const char *)spec->password;
        if (passWord == NULL) {
            LOGE("passWord is NULL.");
            OpensslEvpPkeyFree(pkey);
            return HCF_ERR_PARAMETER_CHECK_FAILED;
        }
        if (strlen(passWord) == 0 || strlen(passWord) > PASSWORD_MAX_LENGTH) {
            LOGE("passWord is invalid.");
            OpensslEvpPkeyFree(pkey);
            return HCF_INVALID_PARAMS;
        }
        cipher = EVP_CIPHER_fetch(NULL, cipherStr, NULL);
        result = GetPriKeyPem(format, pkey, cipher, passWord, returnString);
        EVP_CIPHER_free((EVP_CIPHER *)cipher);
    } else {
        result = GetPriKeyPem(format, pkey, NULL, NULL, returnString);
    }

    if (result != HCF_SUCCESS) {
        LOGE("Failed to get private key PEM encoding.");
        OpensslEvpPkeyFree(pkey);
        return result;
    }
    OpensslEvpPkeyFree(pkey);
    return HCF_SUCCESS;
}

static HcfResult GetRsaPubKeySize(HcfKey *self, int *keySize)
{
    if (self == NULL || keySize == NULL) {
        LOGE("Invalid input parameter.");
        return HCF_ERR_PARAMETER_CHECK_FAILED;
    }
    if (!HcfIsClassMatch((HcfObjectBase *)self, OPENSSL_RSA_PUBKEY_CLASS)) {
        LOGE("Class not match.");
        return HCF_ERR_PARAMETER_CHECK_FAILED;
    }
    HcfOpensslRsaPubKey *impl = (HcfOpensslRsaPubKey *)self;
    if (impl->pk == NULL) {
        LOGE("RSA pubkey is NULL.");
        return HCF_ERR_PARAMETER_CHECK_FAILED;
    }
    *keySize = OpensslRsaBits(impl->pk);
    return HCF_SUCCESS;
}

static const char *GetPubKeyFormat(HcfKey *self)
{
    if (self == NULL) {
        LOGE("Invalid input parameter.");
        return NULL;
    }
    if (!HcfIsClassMatch((HcfObjectBase *)self, OPENSSL_RSA_PUBKEY_CLASS)) {
        return NULL;
    }
    return OPENSSL_RSA_PUBKEY_FORMAT;
}

static HcfResult GetRsaPriKeySize(HcfKey *self, int *keySize)
{
    if (self == NULL || keySize == NULL) {
        LOGE("Invalid input parameter.");
        return HCF_ERR_PARAMETER_CHECK_FAILED;
    }
    if (!HcfIsClassMatch((HcfObjectBase *)self, OPENSSL_RSA_PRIKEY_CLASS)) {
        LOGE("Class not match.");
        return HCF_ERR_PARAMETER_CHECK_FAILED;
    }
    HcfOpensslRsaPriKey *impl = (HcfOpensslRsaPriKey *)self;
    if (impl->sk == NULL) {
        LOGE("RSA prikey is NULL.");
        return HCF_ERR_PARAMETER_CHECK_FAILED;
    }
    *keySize = OpensslRsaBits(impl->sk);
    return HCF_SUCCESS;
}

static const char *GetPriKeyFormat(HcfKey *self)
{
    if (self == NULL) {
        LOGE("Invalid input parameter.");
        return NULL;
    }
    if (!HcfIsClassMatch((HcfObjectBase *)self, OPENSSL_RSA_PRIKEY_CLASS)) {
        return NULL;
    }
    return OPENSSL_RSA_PRIKEY_FORMAT;
}

static const char *GetPriKeyAlgorithm(HcfKey *self)
{
    if (self == NULL) {
        LOGE("Invalid input parameter.");
        return NULL;
    }
    if (!HcfIsClassMatch((HcfObjectBase *)self, OPENSSL_RSA_PRIKEY_CLASS)) {
        return NULL;
    }
    return OPENSSL_RSA_ALGORITHM;
}

static const char *GetPubKeyAlgorithm(HcfKey *self)
{
    if (self == NULL) {
        LOGE("Invalid input parameter.");
        return NULL;
    }
    if (!HcfIsClassMatch((HcfObjectBase *)self, OPENSSL_RSA_PUBKEY_CLASS)) {
        return NULL;
    }
    return OPENSSL_RSA_ALGORITHM;
}

static void ClearPriKeyMem(HcfPriKey *self)
{
    if (self == NULL) {
        LOGE("Private key object is null.");
        return;
    }
    if (!HcfIsClassMatch((HcfObjectBase *)self, OPENSSL_RSA_PRIKEY_CLASS)) {
        LOGE("Class not match");
        return;
    }
    HcfOpensslRsaPriKey *impl = (HcfOpensslRsaPriKey *)self;
    OpensslRsaFree(impl->sk);
    impl->sk = NULL;
}

static HcfResult GetPubKeyDer(const char *format, RSA *pk, HcfBlob *returnBlob)
{
    if (format == NULL || pk == NULL || returnBlob == NULL) {
        LOGE("param is null.");
        return HCF_INVALID_PARAMS;
    }

    unsigned char *data = NULL;
    int len = 0;
    if (strcmp(format, "PKCS1") == 0) {
        len = OpensslI2dRsaPublicKey(pk, &data);
    } else if (strcmp(format, "X509") == 0) {
        len = OpensslI2dRsaPubKey(pk, &data);
    } else {
        LOGE("format is invalid.");
        return HCF_INVALID_PARAMS;
    }

    if (len <= 0 || data == NULL) {
        LOGE("i2d pubkey failed.");
        HcfPrintOpensslError();
        return HCF_ERR_CRYPTO_OPERATION;
    }

    returnBlob->data = data;
    returnBlob->len = (size_t)len;
    return HCF_SUCCESS;
}

static HcfResult GetRsaPubKeyEncodedDer(const HcfPubKey *self, const char *format, HcfBlob *returnBlob)
{
    if (self == NULL || format == NULL || returnBlob == NULL) {
        LOGE("param is null.");
        return HCF_INVALID_PARAMS;
    }
    if (!HcfIsClassMatch((HcfObjectBase *)self, OPENSSL_RSA_PUBKEY_CLASS)) {
        LOGE("Class not match.");
        return HCF_INVALID_PARAMS;
    }
    const char *outPutStruct = NULL;
    if (strcmp(format, "PKCS1") == 0) {
        outPutStruct = "pkcs1";
    } else if (strcmp(format, "X509") == 0) {
        outPutStruct = "subjectPublicKeyInfo";
    } else {
        LOGE("format is invalid.");
        return HCF_INVALID_PARAMS;
    }
    HcfOpensslRsaPubKey *impl = (HcfOpensslRsaPubKey *)self;
    EVP_PKEY *pkey = NewEvpPkeyByRsa(impl->pk, true);
    if (pkey == NULL) {
        LOGE("Failed to create EVP_PKEY from RSA key.");
        return HCF_ERR_CRYPTO_OPERATION;
    }
    HcfResult result = GetKeyEncoded(pkey, outPutStruct, "DER", EVP_PKEY_PUBLIC_KEY, returnBlob);
    OpensslEvpPkeyFree(pkey);
    if (result != HCF_SUCCESS) {
        if (GetPubKeyDer(format, impl->pk, returnBlob) != HCF_SUCCESS) {
            LOGE("Failed to get public key DER encoding.");
            return HCF_ERR_CRYPTO_OPERATION;
        }
    }
    return HCF_SUCCESS;
}

static HcfResult GetRsaPubKeyData(const HcfPubKey *self, uint32_t type, HcfBlob *returnBlob)
{
    (void)self;
    (void)type;
    (void)returnBlob;
    return HCF_ERR_INVALID_CALL;
}

static HcfResult GetRsaPriKeyData(const HcfPriKey *self, uint32_t type, HcfBlob *returnBlob)
{
    (void)self;
    (void)type;
    (void)returnBlob;
    return HCF_ERR_INVALID_CALL;
}

static HcfResult PackPubKey(RSA *rsaPubKey, HcfOpensslRsaPubKey **retPubKey)
{
    if (retPubKey == NULL || rsaPubKey == NULL) {
        LOGE("Invalid params");
        return HCF_INVALID_PARAMS;
    }
    *retPubKey = (HcfOpensslRsaPubKey *)HcfMalloc(sizeof(HcfOpensslRsaPubKey), 0);
    if (*retPubKey == NULL) {
        LOGE("Malloc retPubKey fail");
        return HCF_ERR_MALLOC;
    }
    (*retPubKey)->pk = rsaPubKey;
    (*retPubKey)->bits = (uint32_t)OpensslRsaBits(rsaPubKey);
    (*retPubKey)->base.base.getAlgorithm = GetPubKeyAlgorithm;
    (*retPubKey)->base.base.getEncoded = GetPubKeyEncoded;
    (*retPubKey)->base.base.getEncodedPem = GetPubKeyEncodedPem;
    (*retPubKey)->base.base.getFormat = GetPubKeyFormat;
    (*retPubKey)->base.base.base.getClass = GetOpensslPubkeyClass;
    (*retPubKey)->base.base.base.destroy = DestroyPubKey;
    (*retPubKey)->base.base.getKeySize = GetRsaPubKeySize;
    (*retPubKey)->base.getAsyKeySpecBigInteger = GetRsaPubKeySpecBigInteger;
    (*retPubKey)->base.getAsyKeySpecString = GetRsaPubKeySpecString;
    (*retPubKey)->base.getAsyKeySpecInt = GetRsaPubKeySpecInt;
    (*retPubKey)->base.getEncodedDer = GetRsaPubKeyEncodedDer;
    (*retPubKey)->base.getKeyData = GetRsaPubKeyData;
    return HCF_SUCCESS;
}

static HcfResult GetRsaPubKeyFromPriKey(const HcfPriKey *self, HcfPubKey **returnPubKey)
{
    if (self == NULL || returnPubKey == NULL) {
        LOGE("Invalid input parameter.");
        return HCF_ERR_PARAMETER_CHECK_FAILED;
    }
    if (!HcfIsClassMatch((HcfObjectBase *)self, OPENSSL_RSA_PRIKEY_CLASS)) {
        LOGE("Invalid class of self.");
        return HCF_ERR_PARAMETER_CHECK_FAILED;
    }
    HcfOpensslRsaPriKey *impl = (HcfOpensslRsaPriKey *)self;
    RSA *rsaPubKey = NULL;
    if (GetRsaFromPriKey(impl->sk, &rsaPubKey) != HCF_SUCCESS) {
        LOGE("Get RSA from priKey fail.");
        return HCF_ERR_CRYPTO_OPERATION;
    }
    HcfOpensslRsaPubKey *pubKey = NULL;
    HcfResult ret = PackPubKey(rsaPubKey, &pubKey);
    if (ret != HCF_SUCCESS) {
        LOGE("Failed to pack RSA public key.");
        OpensslRsaFree(rsaPubKey);
        return ret;
    }
    *returnPubKey = (HcfPubKey *)pubKey;
    return ret;
}

// spec中，prikey只有n，e，d，没有p, q
static HcfResult PackPriKey(RSA *rsaPriKey, HcfOpensslRsaPriKey **retPriKey)
{
    if (retPriKey == NULL || rsaPriKey == NULL) {
        LOGE("Invalid params");
        return HCF_INVALID_PARAMS;
    }
    *retPriKey = (HcfOpensslRsaPriKey *)HcfMalloc(sizeof(HcfOpensslRsaPriKey), 0);
    if (*retPriKey == NULL) {
        LOGE("Malloc retPriKey fail");
        return HCF_ERR_MALLOC;
    }
    (*retPriKey)->sk = rsaPriKey;
    (*retPriKey)->bits = (uint32_t)OpensslRsaBits(rsaPriKey);
    (*retPriKey)->base.clearMem = ClearPriKeyMem;
    (*retPriKey)->base.base.getAlgorithm = GetPriKeyAlgorithm;
    (*retPriKey)->base.base.getEncoded = GetPriKeyEncoded;
    (*retPriKey)->base.getEncodedPem = GetPriKeyEncodedPem;
    (*retPriKey)->base.base.getFormat = GetPriKeyFormat;
    (*retPriKey)->base.base.base.getClass = GetOpensslPrikeyClass;
    (*retPriKey)->base.base.base.destroy = DestroyPriKey;
    (*retPriKey)->base.base.getKeySize = GetRsaPriKeySize;
    (*retPriKey)->base.getAsyKeySpecBigInteger = GetRsaPriKeySpecBigInteger;
    (*retPriKey)->base.getAsyKeySpecString = GetRsaPriKeySpecString;
    (*retPriKey)->base.getAsyKeySpecInt = GetRsaPriKeySpecInt;
    (*retPriKey)->base.getEncodedDer = GetRsaPriKeyEncodedDer;
    (*retPriKey)->base.getPubKey = GetRsaPubKeyFromPriKey;
    (*retPriKey)->base.getKeyData = GetRsaPriKeyData;
    return HCF_SUCCESS;
}

static HcfResult DuplicatePkAndSkFromRSA(RSA *rsa, RSA **pubKey, RSA **priKey)
{
    if (rsa == NULL) {
        LOGE("Rsa is NULL.");
        return HCF_INVALID_PARAMS;
    }
    if (DuplicateRsa(rsa, false, pubKey) != HCF_SUCCESS) {
        LOGE("Duplicate pubkey rsa fail");
        return HCF_ERR_CRYPTO_OPERATION;
    }
    if (DuplicateRsa(rsa, true, priKey) != HCF_SUCCESS) {
        LOGE("Duplicate prikey rsa fail");
        OpensslRsaFree(*pubKey);
        *pubKey = NULL;
        return HCF_ERR_CRYPTO_OPERATION;
    }
    return HCF_SUCCESS;
}

static HcfResult PackKeyPair(RSA *rsa, uint32_t realBits, HcfOpensslRsaKeyPair **retKeyPair)
{
    (void)realBits;
    if (retKeyPair == NULL || rsa == NULL) {
        LOGE("Invalid params");
        return HCF_INVALID_PARAMS;
    }
    RSA *pubKey = NULL;
    RSA *priKey = NULL;
    if (DuplicatePkAndSkFromRSA(rsa, &pubKey, &priKey) != HCF_SUCCESS) {
        LOGE("Failed to duplicate RSA public and private key components.");
        return HCF_ERR_CRYPTO_OPERATION;
    }
    HcfResult ret = HCF_SUCCESS;
    *retKeyPair = (HcfOpensslRsaKeyPair *)HcfMalloc(sizeof(HcfOpensslRsaKeyPair), 0);
    if (*retKeyPair == NULL) {
        LOGE("Malloc keypair fail");
        OpensslRsaFree(pubKey);
        OpensslRsaFree(priKey);
        return HCF_ERR_MALLOC;
    }
    HcfOpensslRsaPriKey *priKeyImpl = NULL;
    HcfOpensslRsaPubKey *pubKeyImpl = NULL;
    ret = PackPubKey(pubKey, &pubKeyImpl);
    if (ret != HCF_SUCCESS) {
        LOGE("Pack pubKey fail.");
        goto ERR2;
    }
    ret = PackPriKey(priKey, &priKeyImpl);
    if (ret != HCF_SUCCESS) {
        LOGE("Pack priKey fail.");
        goto ERR1;
    }
    (*retKeyPair)->base.priKey = (HcfPriKey *)priKeyImpl;
    (*retKeyPair)->base.pubKey = (HcfPubKey *)pubKeyImpl;
    (*retKeyPair)->base.base.getClass = GetOpensslKeyPairClass;
    (*retKeyPair)->base.base.destroy = DestroyKeyPair;
    return HCF_SUCCESS;
ERR1:
    HcfFree(pubKeyImpl);
    pubKeyImpl = NULL;
ERR2:
    OpensslRsaFree(pubKey);
    OpensslRsaFree(priKey);
    HcfFree(*retKeyPair);
    *retKeyPair = NULL;
    return ret;
}

static int32_t GetRealPrimes(int32_t primesFlag)
{
    switch (primesFlag) {
        case OPENSSL_RSA_PRIMES_SIZE_2:
            return PRIMES_2;
        case OPENSSL_RSA_PRIMES_SIZE_3:
            return PRIMES_3;
        case OPENSSL_RSA_PRIMES_SIZE_4:
            return PRIMES_4;
        case OPENSSL_RSA_PRIMES_SIZE_5:
            return PRIMES_5;
        default:
            LOGD("set default primes 2");
            return PRIMES_2;
    }
}

static HcfResult GenerateKeyPair(HcfAsyKeyGenSpiRsaParams *params, HcfKeyPair **keyPair)
{
    // check input params is valid
    HcfResult res = CheckRsaKeyGenParams(params);
    if (res != HCF_SUCCESS) {
        LOGE("Rsa CheckRsaKeyGenParams fail.");
        return HCF_INVALID_PARAMS;
    }
    // Generate keyPair RSA
    RSA *rsa = OpensslRsaNew();
    if (rsa == NULL) {
        LOGE("new RSA fail.");
        return HCF_ERR_MALLOC;
    }
    LOGD("keygen bits is %{public}d, primes is %{public}d", params->bits, GetRealPrimes(params->primes));
    if (GetRealPrimes(params->primes) != OPENSSL_RSA_KEYGEN_DEFAULT_PRIMES) {
        if (RSA_generate_multi_prime_key(rsa, params->bits, GetRealPrimes(params->primes), params->pubExp, NULL)
            != HCF_OPENSSL_SUCCESS) {
            LOGE("Generate multi-primes rsa key fail");
            HcfPrintOpensslError();
            OpensslRsaFree(rsa);
            return HCF_ERR_CRYPTO_OPERATION;
        }
    } else {
        if (RSA_generate_key_ex(rsa, params->bits, params->pubExp, NULL) != HCF_OPENSSL_SUCCESS) {
            LOGE("Generate rsa key fail");
            HcfPrintOpensslError();
            OpensslRsaFree(rsa);
            return HCF_ERR_CRYPTO_OPERATION;
        }
    }

    // devided to pk and sk;
    HcfOpensslRsaKeyPair *keyPairImpl = NULL;
    res = PackKeyPair(rsa, params->bits, &keyPairImpl);
    if (res != HCF_SUCCESS) {
        LOGE("Generate keyPair fail.");
        OpensslRsaFree(rsa);
        return res;
    }
    *keyPair = (HcfKeyPair *)keyPairImpl;
    OpensslRsaFree(rsa);
    LOGD("Generate keypair success.");
    return res;
}

static HcfResult EngineGenerateKeyPair(HcfAsyKeyGeneratorSpi *self, HcfKeyPair **keyPair)
{
    if (self == NULL || keyPair == NULL) {
        LOGE("Invalid params.");
        return HCF_INVALID_PARAMS;
    }
    if (!HcfIsClassMatch((HcfObjectBase *)self, OPENSSL_RSA_GENERATOR_CLASS)) {
        LOGE("Class not match.");
        return HCF_INVALID_PARAMS;
    }
    HcfAsyKeyGeneratorSpiRsaOpensslImpl *impl = (HcfAsyKeyGeneratorSpiRsaOpensslImpl *)self;
    return GenerateKeyPair(impl->params, keyPair);
}

static const char *GetKeyGeneratorClass(void)
{
    return OPENSSL_RSA_GENERATOR_CLASS;
}

static void DestroyKeyGeneratorSpiImpl(HcfObjectBase *self)
{
    if (self == NULL) {
        LOGE("Key generator SPI implementation is null.");
        return;
    }
    if (!HcfIsClassMatch(self, OPENSSL_RSA_GENERATOR_CLASS)) {
        LOGE("Class not match.");
        return;
    }
    // destroy pubExp first.
    HcfAsyKeyGeneratorSpiRsaOpensslImpl *impl = (HcfAsyKeyGeneratorSpiRsaOpensslImpl *)self;
    if (impl->params != NULL && impl->params->pubExp != NULL) {
        OpensslBnFree(impl->params->pubExp);
    }
    HcfFree(impl->params);
    impl->params = NULL;
    HcfFree(self);
}

static HcfResult ConvertPubKey(HcfBlob *pubKeyBlob, HcfOpensslRsaPubKey **pubkeyRet)
{
    RSA *rsaPk = NULL;
    // Try parse as X509 first, then fall back to PKCS1.
    if (ConvertPubKeyFromX509(pubKeyBlob, &rsaPk) != HCF_SUCCESS) {
        if (ConvertPubKeyFromPkcs1(pubKeyBlob, &rsaPk) != HCF_SUCCESS) {
            LOGE("Convert pubKey from X509 or PKCS1 der fail.");
            return HCF_ERR_CRYPTO_OPERATION;
        }
    }
    HcfOpensslRsaPubKey *pubKey = NULL;
    HcfResult ret = PackPubKey(rsaPk, &pubKey);
    if (ret != HCF_SUCCESS) {
        LOGE("Failed to pack RSA public key.");
        goto ERR;
    }
    *pubkeyRet = pubKey;
    return ret;
ERR:
    OpensslRsaFree(rsaPk);
    return ret;
}

static HcfResult ConvertPemKeyToKey(const char *keyStr, HcfParamsSpec *params, int selection, RSA **rsa)
{
    EVP_PKEY *pkey = NULL;
    OSSL_DECODER_CTX *ctx = OpensslOsslDecoderCtxNewForPkey(&pkey, "PEM", NULL, "RSA", selection, NULL, NULL);
    if (ctx == NULL) {
        LOGE("Failed to create OpenSSL decoder context for key.");
        HcfPrintOpensslError();
        return HCF_ERR_CRYPTO_OPERATION;
    }
    if (params != NULL) {
        HcfKeyDecodingParamsSpec *spec = (HcfKeyDecodingParamsSpec *)params;
        const unsigned char *passWd = (const unsigned char *)spec->password;
        if (OpensslOsslDecoderCtxSetPassPhrase(ctx, passWd, strlen(spec->password)) != HCF_OPENSSL_SUCCESS) {
            HcfPrintOpensslError();
            OpensslOsslDecoderCtxFree(ctx);
            OpensslEvpPkeyFree(pkey);
            LOGE("Params is not NULL unexpectedly.");
            return HCF_ERR_CRYPTO_OPERATION;
        }
    }
    size_t pdataLen = strlen(keyStr);
    const unsigned char *pdata = (const unsigned char *)keyStr;
    int ret = OpensslOsslDecoderFromData(ctx, &pdata, &pdataLen);
    OpensslOsslDecoderCtxFree(ctx);
    if (ret != HCF_OPENSSL_SUCCESS) {
        LOGE("Failed to decode key from PEM data.");
        HcfPrintOpensslError();
        OpensslEvpPkeyFree(pkey);
        return HCF_ERR_CRYPTO_OPERATION;
    }
    *rsa = OpensslEvpPkeyGet1Rsa(pkey);
    OpensslEvpPkeyFree(pkey);
    if (*rsa == NULL) {
        LOGE("Failed to extract RSA key from EVP_PKEY.");
        HcfPrintOpensslError();
        return HCF_ERR_CRYPTO_OPERATION;
    }
    return HCF_SUCCESS;
}

static HcfResult ConvertPemPubKey(const char *pubKeyStr, int selection, HcfOpensslRsaPubKey **pubKeyRet)
{
    RSA *rsaPk = NULL;
    HcfResult ret;
    ret = ConvertPemKeyToKey(pubKeyStr, NULL, selection, &rsaPk);
    if (ret != HCF_SUCCESS) {
        LOGE("Failed to convert PEM public key to key object.");
        return ret;
    }

    HcfOpensslRsaPubKey *pubKey = NULL;
    HcfResult result = PackPubKey(rsaPk, &pubKey);
    if (result != HCF_SUCCESS) {
        LOGE("Failed to pack RSA public key.");
        OpensslRsaFree(rsaPk);
        return result;
    }
    *pubKeyRet = pubKey;
    return HCF_SUCCESS;
}

static HcfResult ConvertPriKey(HcfBlob *priKeyBlob, HcfOpensslRsaPriKey **priKeyRet)
{
    RSA *rsaSk = NULL;
    if (ConvertPriKeyFromDer(priKeyBlob, &rsaSk) != HCF_SUCCESS) {
        LOGE("Convert private key from der fail.");
        return HCF_ERR_MALLOC;
    }
    HcfOpensslRsaPriKey *priKey = NULL;
    HcfResult ret = PackPriKey(rsaSk, &priKey);
    if (ret != HCF_SUCCESS) {
        LOGE("Failed to pack RSA private key.");
        goto ERR;
    }
    *priKeyRet = priKey;
    return ret;
ERR:
    OpensslRsaFree(rsaSk);
    return ret;
}

static HcfResult ConvertPemPriKey(const char *priKeyStr, HcfParamsSpec *params, int selection,
    HcfOpensslRsaPriKey **priKeyRet)
{
    RSA *rsaSk = NULL;
    HcfResult ret;
    ret = ConvertPemKeyToKey(priKeyStr, params, selection, &rsaSk);
    if (ret != HCF_SUCCESS) {
        LOGE("Failed to convert PEM private key to key object.");
        return ret;
    }
    HcfOpensslRsaPriKey *priKey = NULL;
    HcfResult result = PackPriKey(rsaSk, &priKey);
    if (result != HCF_SUCCESS) {
        LOGE("Failed to pack RSA private key.");
        OpensslRsaFree(rsaSk);
        return result;
    }
    *priKeyRet = priKey;
    return HCF_SUCCESS;
}

static HcfResult EngineConvertKey(HcfAsyKeyGeneratorSpi *self, HcfParamsSpec *params, HcfBlob *pubKeyBlob,
    HcfBlob *priKeyBlob, HcfKeyPair **returnKeyPair)
{
    (void)params;
    if ((self == NULL) || (returnKeyPair == NULL) || ((pubKeyBlob == NULL) && (priKeyBlob == NULL))) {
        LOGE("ConvertKeyParams is invalid.");
        return HCF_INVALID_PARAMS;
    }
    if (!HcfIsClassMatch((HcfObjectBase *)self, OPENSSL_RSA_GENERATOR_CLASS)) {
        LOGE("Class not match.");
        return HCF_INVALID_PARAMS;
    }

    HcfOpensslRsaPubKey *pubKey = NULL;
    if ((pubKeyBlob != NULL) && (pubKeyBlob->len != 0) && (pubKeyBlob->data != NULL)) {
        if (ConvertPubKey(pubKeyBlob, &pubKey) != HCF_SUCCESS) {
            LOGE("convert pubkey fail.");
            return HCF_INVALID_PARAMS;
        }
    }

    HcfOpensslRsaPriKey *priKey = NULL;
    if ((priKeyBlob != NULL) && (priKeyBlob->len != 0) && (priKeyBlob->data != NULL)) {
        if (ConvertPriKey(priKeyBlob, &priKey) != HCF_SUCCESS) {
            LOGE("convert prikey fail.");
            HcfObjDestroy((HcfObjectBase *)pubKey);
            pubKey = NULL;
            return HCF_INVALID_PARAMS;
        }
    }

    if (pubKey == NULL && priKey == NULL) {
        LOGE("Convert key failed with invalid blob");
        return HCF_INVALID_PARAMS;
    }

    HcfOpensslRsaKeyPair *keyPair = (HcfOpensslRsaKeyPair *)HcfMalloc(sizeof(HcfOpensslRsaKeyPair), 0);
    if (keyPair == NULL) {
        LOGE("Malloc keyPair fail.");
        HcfObjDestroy((HcfObjectBase *)pubKey);
        pubKey = NULL;
        HcfObjDestroy((HcfObjectBase *)priKey);
        priKey = NULL;
        return HCF_ERR_MALLOC;
    }

    keyPair->base.priKey = (HcfPriKey *)priKey;
    keyPair->base.pubKey = (HcfPubKey *)pubKey;
    keyPair->base.base.getClass = GetOpensslKeyPairClass;
    keyPair->base.base.destroy = DestroyKeyPair;
    *returnKeyPair = (HcfKeyPair *)keyPair;
    return HCF_SUCCESS;
}

static HcfResult EngineConvertPemKey(HcfAsyKeyGeneratorSpi *self, HcfParamsSpec *params, const char *pubKeyStr,
    const char *priKeyStr, HcfKeyPair **returnKeyPair)
{
    if ((self == NULL) || (returnKeyPair == NULL) || ((pubKeyStr == NULL) && (priKeyStr == NULL))) {
        LOGE("ConvertPemKeyParams is invalid.");
        return HCF_INVALID_PARAMS;
    }
    if (params != NULL) {
        HcfKeyDecodingParamsSpec *spec = (HcfKeyDecodingParamsSpec *)params;
        if (spec->password == NULL || strlen(spec->password) == 0 || strlen(spec->password) > PASSWORD_MAX_LENGTH) {
            LOGE("password is invalid.");
            return HCF_INVALID_PARAMS;
        }
    }
    if (!HcfIsClassMatch((HcfObjectBase *)self, OPENSSL_RSA_GENERATOR_CLASS)) {
        LOGE("Class not match.");
        return HCF_INVALID_PARAMS;
    }
    HcfOpensslRsaPubKey *pubKey = NULL;
    if (pubKeyStr != NULL && strlen(pubKeyStr) != 0) {
        if (ConvertPemPubKey(pubKeyStr, EVP_PKEY_PUBLIC_KEY, &pubKey) != HCF_SUCCESS) {
            LOGE("convert pubkey fail.");
            return HCF_ERR_CRYPTO_OPERATION;
        }
    }
    HcfOpensslRsaPriKey *priKey = NULL;
    if (priKeyStr != NULL && strlen(priKeyStr) != 0) {
        if (ConvertPemPriKey(priKeyStr, params, EVP_PKEY_KEYPAIR, &priKey) != HCF_SUCCESS) {
            LOGE("convert prikey fail.");
            HcfObjDestroy((HcfObjectBase *)pubKey);
            pubKey = NULL;
            return HCF_ERR_CRYPTO_OPERATION;
        }
    }

    HcfOpensslRsaKeyPair *keyPair = (HcfOpensslRsaKeyPair *)HcfMalloc(sizeof(HcfOpensslRsaKeyPair), 0);
    if (keyPair == NULL) {
        LOGE("Malloc keyPair fail.");
        HcfObjDestroy((HcfObjectBase *)pubKey);
        pubKey = NULL;
        HcfObjDestroy((HcfObjectBase *)priKey);
        priKey = NULL;
        return HCF_ERR_MALLOC;
    }
    keyPair->base.priKey = (HcfPriKey *)priKey;
    keyPair->base.pubKey = (HcfPubKey *)pubKey;
    keyPair->base.base.getClass = GetOpensslKeyPairClass;
    keyPair->base.base.destroy = DestroyKeyPair;
    *returnKeyPair = (HcfKeyPair *)keyPair;
    return HCF_SUCCESS;
}

static HcfResult ParseRsaBnFromBin(const HcfAsyKeyParamsSpec *paramsSpec, BIGNUM **n,
    BIGNUM **e, BIGNUM **d)
{
    // when meeting the fail situation, the BIGNUM will be NULL and other BIGNUM will be freeed in InitRsaStructByBin();
    if (BigIntegerToBigNum(&((HcfRsaCommParamsSpec *)paramsSpec)->n, n) != HCF_SUCCESS) {
        LOGE("Rsa new BN n fail.");
        return HCF_ERR_CRYPTO_OPERATION;
    }
    if (paramsSpec->specType == HCF_KEY_PAIR_SPEC) {
        if (BigIntegerToBigNum(&((HcfRsaKeyPairParamsSpec *)paramsSpec)->pk, e) != HCF_SUCCESS) {
            LOGE("Rsa new BN e fail.");
            OpensslBnFree(*n);
            *n = NULL;
            return HCF_ERR_CRYPTO_OPERATION;
        }
        if (BigIntegerToBigNum(&((HcfRsaKeyPairParamsSpec *)paramsSpec)->sk, d) != HCF_SUCCESS) {
            LOGE("Rsa new BN d fail.");
            OpensslBnFree(*n);
            *n = NULL;
            OpensslBnFree(*e);
            *e = NULL;
            return HCF_ERR_CRYPTO_OPERATION;
        }
    }
    if (paramsSpec->specType == HCF_PUBLIC_KEY_SPEC) {
        if (BigIntegerToBigNum(&((HcfRsaPubKeyParamsSpec *)paramsSpec)->pk, e) != HCF_SUCCESS) {
            LOGE("Rsa new BN e fail.");
            OpensslBnFree(*n);
            *n = NULL;
            return HCF_ERR_CRYPTO_OPERATION;
        }
    }
    return HCF_SUCCESS;
}

static RSA *InitRsaStructByBin(const HcfAsyKeyParamsSpec *paramsSpec)
{
    BIGNUM *n = NULL;
    BIGNUM *e = NULL;
    BIGNUM *d = NULL;
    RSA *rsa = NULL;

    if (ParseRsaBnFromBin(paramsSpec, &n, &e, &d) != HCF_SUCCESS) {
        LOGE("Failed to parse RSA BIGNUM values from binary data.");
        return rsa;
    }
    rsa = OpensslRsaNew();
    if (rsa == NULL) {
        OpensslBnFree(n);
        OpensslBnFree(e);
        OpensslBnClearFree(d);
        LOGE("new RSA fail");
        return rsa;
    }
    // if set0 success, RSA object will take the owner of n, e, d and will free them.
    // as a new RSA object, in RSA_set0_key(), n and e cannot be NULL.
    if (OpensslRsaSet0Key(rsa, n, e, d) != HCF_OPENSSL_SUCCESS) {
        LOGE("set RSA fail");
        HcfPrintOpensslError();
        OpensslBnFree(n);
        OpensslBnFree(e);
        OpensslBnClearFree(d);
        OpensslRsaFree(rsa);
        rsa = NULL;
        return rsa;
    }
    return rsa;
}

static HcfResult GenerateKeyPairBySpec(const HcfAsyKeyParamsSpec *paramsSpec, HcfKeyPair **keyPair)
{
    // Generate keyPair RSA by spec
    RSA *rsa = InitRsaStructByBin(paramsSpec);
    if (rsa == NULL) {
        LOGE("Generate RSA fail.");
        return HCF_ERR_CRYPTO_OPERATION;
    }
    HcfOpensslRsaKeyPair *keyPairImpl = (HcfOpensslRsaKeyPair *)HcfMalloc(sizeof(HcfOpensslRsaKeyPair), 0);
    if (keyPairImpl == NULL) {
        LOGE("Malloc keyPair fail.");
        OpensslRsaFree(rsa);
        return HCF_ERR_MALLOC;
    }
    // devided to pk and sk;
    HcfOpensslRsaPubKey *pubKeyImpl = NULL;
    HcfOpensslRsaPriKey *priKeyImpl = NULL;

    RSA *pubKeyRsa = NULL;
    if (DuplicateRsa(rsa, false, &pubKeyRsa) != HCF_SUCCESS) {
        LOGE("Duplicate pubKey rsa fail");
        OpensslRsaFree(rsa);
        HcfFree(keyPairImpl);
        keyPairImpl = NULL;
        return HCF_ERR_CRYPTO_OPERATION;
    }

    HcfResult res = PackPubKey(pubKeyRsa, &pubKeyImpl);
    if (res != HCF_SUCCESS) {
        LOGE("pack pup key fail.");
        OpensslRsaFree(rsa);
        OpensslRsaFree(pubKeyRsa);
        HcfFree(keyPairImpl);
        keyPairImpl = NULL;
        return res;
    }

    res = PackPriKey(rsa, &priKeyImpl);
    if (res != HCF_SUCCESS) {
        LOGE("pack pri key fail.");
        OpensslRsaFree(rsa);
        OpensslRsaFree(pubKeyRsa);
        HcfFree(keyPairImpl);
        keyPairImpl = NULL;
        HcfFree(pubKeyImpl);
        pubKeyImpl = NULL;
        return res;
    }
    keyPairImpl->base.priKey = (HcfPriKey *)priKeyImpl;
    keyPairImpl->base.pubKey = (HcfPubKey *)pubKeyImpl;
    keyPairImpl->base.base.getClass = GetOpensslKeyPairClass;
    keyPairImpl->base.base.destroy = DestroyKeyPair;
    *keyPair = (HcfKeyPair *)keyPairImpl;
    LOGD("Generate keypair success.");
    return res;
}

static HcfResult GeneratePubKeyBySpec(const HcfAsyKeyParamsSpec *paramsSpec, HcfPubKey **pubKey)
{
    RSA *rsa = InitRsaStructByBin(paramsSpec);
    if (rsa == NULL) {
        LOGE("Generate RSA fail.");
        return HCF_ERR_CRYPTO_OPERATION;
    }
    RSA *pubKeyRsa = NULL;
    if (DuplicateRsa(rsa, false, &pubKeyRsa) != HCF_SUCCESS) {
        LOGE("Duplicate pubKey rsa fail");
        OpensslRsaFree(rsa);
        return HCF_ERR_CRYPTO_OPERATION;
    }
    HcfOpensslRsaPubKey *pubKeyImpl = NULL;
    HcfResult res = PackPubKey(pubKeyRsa, &pubKeyImpl);
    if (res != HCF_SUCCESS) {
        LOGE("pack pup key fail.");
        OpensslRsaFree(rsa);
        OpensslRsaFree(pubKeyRsa);
        return res;
    }
    *pubKey = (HcfPubKey *)pubKeyImpl;
    OpensslRsaFree(rsa);
    LOGD("Generate pub key success.");
    return res;
}

static HcfResult GeneratePriKeyBySpec(const HcfAsyKeyParamsSpec *paramsSpec, HcfPriKey **priKey)
{
    RSA *rsa = InitRsaStructByBin(paramsSpec);
    if (rsa == NULL) {
        LOGE("Generate RSA fail.");
        return HCF_ERR_CRYPTO_OPERATION;
    }
    HcfOpensslRsaPriKey *priKeyImpl = NULL;
    HcfResult res = PackPriKey(rsa, &priKeyImpl);
    if (res != HCF_SUCCESS) {
        LOGE("pack pri key fail.");
        OpensslRsaFree(rsa);
        return res;
    }
    *priKey = (HcfPriKey *)priKeyImpl;
    LOGD("Generate pri key success.");
    return res;
}

static HcfResult EngineGenerateKeyPairBySpec(const HcfAsyKeyGeneratorSpi *self,
    const HcfAsyKeyParamsSpec *paramsSpec, HcfKeyPair **returnKeyPair)
{
    if ((self == NULL) || (returnKeyPair == NULL) || (paramsSpec == NULL) || (paramsSpec->algName == NULL)) {
        LOGE("GenerateKeyPairBySpec Params is invalid.");
        return HCF_INVALID_PARAMS;
    }
    if (!HcfIsClassMatch((HcfObjectBase *)self, OPENSSL_RSA_GENERATOR_CLASS)) {
        LOGE("Class not match.");
        return HCF_INVALID_PARAMS;
    }
    if (strcmp(paramsSpec->algName, RSA_ALG_NAME) != 0) {
        LOGE("Spec alg not match.");
        return HCF_INVALID_PARAMS;
    }
    if (paramsSpec->specType != HCF_KEY_PAIR_SPEC) {
        LOGE("Spec type not match.");
        return HCF_INVALID_PARAMS;
    }
    return GenerateKeyPairBySpec(paramsSpec, returnKeyPair);
}

static HcfResult EngineGeneratePubKeyBySpec(const HcfAsyKeyGeneratorSpi *self,
    const HcfAsyKeyParamsSpec *paramsSpec, HcfPubKey **returnPubKey)
{
    if ((self == NULL) || (returnPubKey == NULL) || (paramsSpec == NULL) || (paramsSpec->algName == NULL)) {
        LOGE("GeneratePubKeyBySpec Params is invalid.");
        return HCF_INVALID_PARAMS;
    }
    if (!HcfIsClassMatch((HcfObjectBase *)self, OPENSSL_RSA_GENERATOR_CLASS)) {
        LOGE("Class not match.");
        return HCF_INVALID_PARAMS;
    }
    if (strcmp(paramsSpec->algName, RSA_ALG_NAME) != 0) {
        LOGE("Spec alg not match.");
        return HCF_INVALID_PARAMS;
    }
    if (paramsSpec->specType != HCF_PUBLIC_KEY_SPEC && paramsSpec->specType != HCF_KEY_PAIR_SPEC) {
        LOGE("Spec not match.");
        return HCF_INVALID_PARAMS;
    }
    return GeneratePubKeyBySpec(paramsSpec, returnPubKey);
}

static HcfResult EngineGeneratePriKeyBySpec(const HcfAsyKeyGeneratorSpi *self,
    const HcfAsyKeyParamsSpec *paramsSpec, HcfPriKey **returnPriKey)
{
    if ((self == NULL) || (returnPriKey == NULL) || (paramsSpec == NULL) || (paramsSpec->algName == NULL)) {
        LOGE("GeneratePriKeyBySpec Params is invalid.");
        return HCF_INVALID_PARAMS;
    }
    if (!HcfIsClassMatch((HcfObjectBase *)self, OPENSSL_RSA_GENERATOR_CLASS)) {
        LOGE("Class not match.");
        return HCF_INVALID_PARAMS;
    }
    if (strcmp(paramsSpec->algName, RSA_ALG_NAME) != 0) {
        LOGE("Spec alg not match.");
        return HCF_INVALID_PARAMS;
    }
    if (paramsSpec->specType != HCF_KEY_PAIR_SPEC) {
        LOGE("Spec not match.");
        return HCF_INVALID_PARAMS;
    }
    return GeneratePriKeyBySpec(paramsSpec, returnPriKey);
}

static HcfResult SetDefaultValue(HcfAsyKeyGenSpiRsaParams *params)
{
    if (params->primes == 0) {
        LOGD("set default primes 2");
        params->primes = OPENSSL_RSA_PRIMES_SIZE_2;
    }
    if (params->pubExp != NULL) {
        LOGE("RSA has pubKey default unexpectedly.");
        return HCF_SUCCESS;
    }
    BIGNUM *e = OpensslBnNew();
    if (e == NULL) {
        LOGE("RSA new BN fail.");
        return HCF_ERR_CRYPTO_OPERATION;
    }
    if (OpensslBnSetWord(e, RSA_F4) != HCF_OPENSSL_SUCCESS) {
        LOGE("RSA keygen Bn_set_word fail.");
        OpensslBnFree(e);
        return HCF_ERR_CRYPTO_OPERATION;
    }
    params->pubExp = e;
    return HCF_SUCCESS;
}

static HcfResult DecodeParams(HcfAsyKeyGenParams *from, HcfAsyKeyGenSpiRsaParams **to)
{
    *to = (HcfAsyKeyGenSpiRsaParams *)HcfMalloc(sizeof(HcfAsyKeyGenSpiRsaParams), 0);
    if (*to == NULL) {
        LOGE("Malloc HcfAsyKeyGenSpiRsaParams fail");
        return HCF_ERR_MALLOC;
    }

    (*to)->bits = from->bits;
    (*to)->primes = from->primes;

    // set 2 as default primes, RSA_F4 as default pubExp
    if (SetDefaultValue(*to) != HCF_SUCCESS) {
        LOGE("Set default value fail.");
        HcfFree(*to);
        *to = NULL;
        return HCF_INVALID_PARAMS;
    }
    if (CheckRsaKeyGenParams(*to) != HCF_SUCCESS) {
        LOGE("Invalid keyGen params");
        OpensslBnFree((*to)->pubExp);
        HcfFree(*to);
        *to = NULL;
        return HCF_INVALID_PARAMS;
    }
    return HCF_SUCCESS;
}

HcfResult HcfAsyKeyGeneratorSpiRsaCreate(HcfAsyKeyGenParams *params, HcfAsyKeyGeneratorSpi **generator)
{
    if (params == NULL || generator == NULL) {
        LOGE("Invalid input, params is invalid or generator is null.");
        return HCF_INVALID_PARAMS;
    }
    HcfAsyKeyGeneratorSpiRsaOpensslImpl *impl = (HcfAsyKeyGeneratorSpiRsaOpensslImpl *)
        HcfMalloc(sizeof(HcfAsyKeyGeneratorSpiRsaOpensslImpl), 0);
    if (impl == NULL) {
        LOGE("Failed to allocate returnImpl memroy!");
        return HCF_ERR_MALLOC;
    }
    if (DecodeParams(params, &impl->params) != HCF_SUCCESS) {
        LOGE("Keygen params is invalid.");
        HcfFree(impl);
        impl = NULL;
        return HCF_INVALID_PARAMS;
    }
    impl->base.base.getClass = GetKeyGeneratorClass;
    impl->base.base.destroy = DestroyKeyGeneratorSpiImpl;
    impl->base.engineGenerateKeyPair = EngineGenerateKeyPair;
    impl->base.engineConvertKey = EngineConvertKey;
    impl->base.engineConvertPemKey = EngineConvertPemKey;
    impl->base.engineGenerateKeyPairBySpec = EngineGenerateKeyPairBySpec;
    impl->base.engineGeneratePubKeyBySpec = EngineGeneratePubKeyBySpec;
    impl->base.engineGeneratePriKeyBySpec = EngineGeneratePriKeyBySpec;
    *generator = (HcfAsyKeyGeneratorSpi *)impl;
    return HCF_SUCCESS;
}
