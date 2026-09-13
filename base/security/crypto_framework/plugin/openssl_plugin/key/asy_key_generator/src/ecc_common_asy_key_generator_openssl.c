/*
 * Copyright (C) 2026 Huawei Device Co., Ltd.
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

#include "ecc_common_asy_key_generator_openssl.h"

#include "securec.h"

#include "log.h"
#include "utils.h"
#include "memory.h"
#include "openssl_adapter.h"
#include "openssl_common.h"

#define BITS_PER_BYTE 8
#define ECC_COORDINATE_COUNT 2
#define ECC_COORDINATE_COUNT_3 3
#define ECC_OCTET_PREFIX_SIZE 1
#define EC_PRIVATE_K 6
#define EC_PRIVATE_04_X_Y_K 7
#define EC_PUBLIC_X_Y 8
#define EC_PUBLIC_04_X_Y 9
#define EC_PUBLIC_COMPRESS_X 10

HcfResult EccCopyPemFromBIO(BIO *bio, char **returnString)
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
        LOGE("Malloc mem for pem string fail.");
        return HCF_ERR_MALLOC;
    }
    if (OpensslBioRead(bio, *returnString, len) <= 0) {
        LOGE("Bio read fail");
        HcfPrintOpensslError();
        HcfFree(*returnString);
        *returnString = NULL;
        return HCF_ERR_CRYPTO_OPERATION;
    }
    (*returnString)[len] = '\0';
    return HCF_SUCCESS;
}

static void SetEcAsn1FlagByCurveId(EC_KEY *ecKey, int32_t curveId)
{
    if (curveId != 0) {
        OpensslEcKeySetAsn1Flag(ecKey, OPENSSL_EC_NAMED_CURVE);
    } else {
        OpensslEcKeySetAsn1Flag(ecKey, OPENSSL_EC_EXPLICIT_CURVE);
    }
}

static HcfResult BuildEvpPkeyFromEcKey(EC_KEY *ecKey, EVP_PKEY **outPkey)
{
    EVP_PKEY *localPkey = OpensslEvpPkeyNew();
    if (localPkey == NULL) {
        LOGE("New EVP_PKEY failed.");
        HcfPrintOpensslError();
        return HCF_ERR_CRYPTO_OPERATION;
    }
    if (OpensslEvpPkeySet1EcKey(localPkey, ecKey) != HCF_OPENSSL_SUCCESS) {
        OpensslEvpPkeyFree(localPkey);
        LOGE("Set EC_KEY to EVP_PKEY failed.");
        HcfPrintOpensslError();
        return HCF_ERR_CRYPTO_OPERATION;
    }
    *outPkey = localPkey;
    return HCF_SUCCESS;
}

static HcfResult EncodePubKeyPemByPkey(EVP_PKEY *pkey, char **returnString)
{
    BIO *bio = OpensslBioNew(OpensslBioSMem());
    if (bio == NULL) {
        LOGE("BIO new fail.");
        HcfPrintOpensslError();
        return HCF_ERR_CRYPTO_OPERATION;
    }
    if (PEM_write_bio_PUBKEY(bio, pkey) != HCF_OPENSSL_SUCCESS) {
        LOGE("PEM_write_bio_PUBKEY fail.");
        HcfPrintOpensslError();
        OpensslBioFreeAll(bio);
        return HCF_ERR_CRYPTO_OPERATION;
    }
    HcfResult ret = EccCopyPemFromBIO(bio, returnString);
    OpensslBioFreeAll(bio);
    return ret;
}

HcfResult GetEccPubKeyEncodedPemInCommon(HcfKey *self, const char *format, char **returnString)
{
    if (self == NULL || format == NULL || returnString == NULL) {
        LOGE("Invalid input parameter.");
        return HCF_INVALID_PARAMS;
    }
    if (!HcfIsClassMatch((HcfObjectBase *)self, HCF_OPENSSL_ECC_PUB_KEY_CLASS)) {
        LOGE("Invalid ecc pub key class.");
        return HCF_INVALID_PARAMS;
    }
    if (strcmp(format, "X509") != 0) {
        LOGE("Unsupported ecc pub pem format %{public}s.", format);
        return HCF_INVALID_PARAMS;
    }
    HcfOpensslEccPubKey *impl = (HcfOpensslEccPubKey *)self;
    if (impl->ecKey == NULL) {
        LOGE("Invalid ecc pub key.");
        return HCF_INVALID_PARAMS;
    }
    SetEcAsn1FlagByCurveId(impl->ecKey, impl->curveId);
    EVP_PKEY *pkey = NULL;
    HcfResult ret = BuildEvpPkeyFromEcKey(impl->ecKey, &pkey);
    if (ret != HCF_SUCCESS) {
        return ret;
    }
    ret = EncodePubKeyPemByPkey(pkey, returnString);
    OpensslEvpPkeyFree(pkey);
    return ret;
}

static HcfResult EncodePriKeyPkcs8Pem(EC_KEY *ecKey, char **returnString)
{
    EVP_PKEY *pkey = NULL;
    HcfResult ret = BuildEvpPkeyFromEcKey(ecKey, &pkey);
    if (ret != HCF_SUCCESS) {
        return ret;
    }
    BIO *bio = OpensslBioNew(OpensslBioSMem());
    if (bio == NULL) {
        LOGE("BIO new fail.");
        HcfPrintOpensslError();
        OpensslEvpPkeyFree(pkey);
        return HCF_ERR_CRYPTO_OPERATION;
    }
    int retCode = PEM_write_bio_PKCS8PrivateKey(bio, pkey, NULL, NULL, 0, NULL, NULL);
    OpensslEvpPkeyFree(pkey);
    if (retCode != HCF_OPENSSL_SUCCESS) {
        LOGE("PEM_write_bio_PKCS8PrivateKey fail.");
        HcfPrintOpensslError();
        OpensslBioFreeAll(bio);
        return HCF_ERR_CRYPTO_OPERATION;
    }
    ret = EccCopyPemFromBIO(bio, returnString);
    OpensslBioFreeAll(bio);
    return ret;
}

static HcfResult EncodePriKeyEcPem(EC_KEY *ecKey, char **returnString)
{
    BIO *bio = OpensslBioNew(OpensslBioSMem());
    if (bio == NULL) {
        LOGE("BIO new fail.");
        HcfPrintOpensslError();
        return HCF_ERR_CRYPTO_OPERATION;
    }
    int retCode = PEM_write_bio_ECPrivateKey(bio, ecKey, NULL, NULL, 0, NULL, NULL);
    if (retCode != HCF_OPENSSL_SUCCESS) {
        LOGE("PEM_write_bio_ECPrivateKey fail.");
        HcfPrintOpensslError();
        OpensslBioFreeAll(bio);
        return HCF_ERR_CRYPTO_OPERATION;
    }
    HcfResult ret = EccCopyPemFromBIO(bio, returnString);
    OpensslBioFreeAll(bio);
    return ret;
}

HcfResult GetEccPriKeyEncodedPemInCommon(const HcfPriKey *self, const char *format, char **returnString)
{
    HcfOpensslEccPriKey *impl = (HcfOpensslEccPriKey *)self;
    if (impl->ecKey == NULL) {
        LOGE("Invalid ecc pri key.");
        return HCF_ERR_PARAMETER_CHECK_FAILED;
    }
    SetEcAsn1FlagByCurveId(impl->ecKey, impl->curveId);
    OpensslEcKeySetEncFlags(impl->ecKey, EC_PKEY_NO_PUBKEY);

    if (strcmp(format, "PKCS8") == 0) {
        return EncodePriKeyPkcs8Pem(impl->ecKey, returnString);
    }
    if (strcmp(format, "EC") == 0) {
        return EncodePriKeyEcPem(impl->ecKey, returnString);
    }
    LOGE("Unsupported ecc pri pem format %{public}s.", format);
    return HCF_INVALID_PARAMS;
}

static HcfResult EccCurveIdGetKeyByteSize(int32_t curveId, size_t *keyBytes)
{
    EC_KEY *tmpEcKey = OpensslEcKeyNewByCurveName(curveId);
    if (tmpEcKey == NULL) {
        LOGE("Failed to create EC key by curve name.");
        return HCF_ERR_CRYPTO_OPERATION;
    }
    const EC_GROUP *group = OpensslEcKeyGet0Group(tmpEcKey);
    if (group == NULL) {
        LOGE("EC_GROUP is NULL.");
        OpensslEcKeyFree(tmpEcKey);
        return HCF_ERR_CRYPTO_OPERATION;
    }
    int degree = OpensslEcGroupGetDegree(group);
    OpensslEcKeyFree(tmpEcKey);
    if (degree < 0) {
        LOGE("Get degree failed.");
        return HCF_ERR_CRYPTO_OPERATION;
    }
    *keyBytes = (size_t)((degree + (BITS_PER_BYTE - ECC_OCTET_PREFIX_SIZE)) / BITS_PER_BYTE);
    return (*keyBytes == 0) ? HCF_ERR_PARAMETER_CHECK_FAILED : HCF_SUCCESS;
}

static EC_KEY *EccOct2KeyNew(int32_t curveId, const unsigned char *buf, size_t len)
{
    EC_KEY *ecKey = OpensslEcKeyNewByCurveName(curveId);
    if (ecKey == NULL) {
        LOGE("Failed to create EC key by curve name.");
        return NULL;
    }
    if (EC_KEY_oct2key(ecKey, buf, len, NULL) != HCF_OPENSSL_SUCCESS) {
        LOGE("EC_KEY_oct2key fail.");
        OpensslEcKeyFree(ecKey);
        return NULL;
    }
    return ecKey;
}

static EC_KEY *EccDecodePubUncompressedXYConcat(int32_t curveId, const unsigned char *octets,
    size_t octetsLen, size_t keyBytes)
{
    if (octetsLen != ECC_COORDINATE_COUNT * keyBytes) {
        LOGE("Invalid octets length for XY concat.");
        return NULL;
    }
    size_t pointLen = octetsLen + ECC_OCTET_PREFIX_SIZE;
    unsigned char *point = (unsigned char *)HcfMalloc(pointLen, 0);
    if (point == NULL) {
        LOGE("Failed to allocate memory for point.");
        return NULL;
    }
    point[0] = 0x04;
    if (memcpy_s(point + ECC_OCTET_PREFIX_SIZE, octetsLen, octets, octetsLen) != EOK) {
        HcfFree(point);
        LOGE("memcpy_s fail.");
        return NULL;
    }
    EC_KEY *ecKey = EccOct2KeyNew(curveId, point, pointLen);
    HcfFree(point);
    return ecKey;
}

static HcfResult ConvertEcPubKeyPackOrFree(int32_t curveId, EC_KEY *ecKey, HcfOpensslEccPubKey **returnPubKey)
{
    if (OpensslEcKeyCheckKey(ecKey) != HCF_OPENSSL_SUCCESS) {
        LOGE("EC_KEY_check_key fail.");
        OpensslEcKeyFree(ecKey);
        return HCF_ERR_CRYPTO_OPERATION;
    }
    HcfResult res = EccPackPubKeyForConvert(curveId, ecKey, returnPubKey);
    if (res != HCF_SUCCESS) {
        LOGE("Failed to pack ECC public key.");
        OpensslEcKeyFree(ecKey);
        return res;
    }
    return HCF_SUCCESS;
}

static HcfResult ConvertEcPubKeyFromDer(int32_t curveId, HcfBlob *pubKeyBlob, HcfOpensslEccPubKey **returnPubKey)
{
    const unsigned char *tmpData = (const unsigned char *)(pubKeyBlob->data);
    EC_KEY *ecKey = OpensslD2iEcPubKey(NULL, &tmpData, pubKeyBlob->len);
    if (ecKey == NULL) {
        LOGE("d2i_EC_PUBKEY fail.");
        HcfPrintOpensslError();
        return HCF_ERR_CRYPTO_OPERATION;
    }
    HcfResult res = EccPackPubKeyForConvert(curveId, ecKey, returnPubKey);
    if (res != HCF_SUCCESS) {
        LOGE("Failed to pack ECC public key.");
        OpensslEcKeyFree(ecKey);
        return res;
    }
    return HCF_SUCCESS;
}

static HcfResult TryConvertEcPubKeyRaw(int32_t curveId, HcfBlob *pubKeyBlob, size_t keyBytes,
    HcfOpensslEccPubKey **returnPubKey)
{
    const unsigned char *octets = (const unsigned char *)(pubKeyBlob->data);
    size_t len = pubKeyBlob->len;
    EC_KEY *ecKey = NULL;
    if (len == (ECC_COORDINATE_COUNT * keyBytes + ECC_OCTET_PREFIX_SIZE) && octets[0] == 0x04) {
        ecKey = EccOct2KeyNew(curveId, octets, ECC_COORDINATE_COUNT * keyBytes + ECC_OCTET_PREFIX_SIZE);
        if (ecKey == NULL) {
            LOGE("Failed to decode public key.");
            return HCF_ERR_CRYPTO_OPERATION;
        }
        return ConvertEcPubKeyPackOrFree(curveId, ecKey, returnPubKey);
    } else if (len == (keyBytes + ECC_OCTET_PREFIX_SIZE) && (octets[0] == 0x02 || octets[0] == 0x03)) {
        ecKey = EccOct2KeyNew(curveId, octets, keyBytes + ECC_OCTET_PREFIX_SIZE);
        if (ecKey == NULL) {
            LOGE("Failed to decode public key.");
            return HCF_ERR_CRYPTO_OPERATION;
        }
        return ConvertEcPubKeyPackOrFree(curveId, ecKey, returnPubKey);
    } else {
        HcfResult res = ConvertEcPubKeyFromDer(curveId, pubKeyBlob, returnPubKey);
        if (res != HCF_SUCCESS) {
            ecKey = EccDecodePubUncompressedXYConcat(curveId, octets, len, keyBytes);
            if (ecKey == NULL) {
                LOGE("Failed to decode public key.");
                return HCF_ERR_CRYPTO_OPERATION;
            }
            return ConvertEcPubKeyPackOrFree(curveId, ecKey, returnPubKey);
        }
        return res;
    }
}

HcfResult ConvertEcPubKey(int32_t curveId, HcfBlob *pubKeyBlob, HcfOpensslEccPubKey **returnPubKey)
{
    if ((curveId == 0) || (pubKeyBlob == NULL) || (returnPubKey == NULL)) {
        LOGE("Invalid input parameter.");
        return HCF_ERR_PARAMETER_CHECK_FAILED;
    }
    size_t keyBytes = 0;
    HcfResult res = HCF_ERR_CRYPTO_OPERATION;
    if (EccCurveIdGetKeyByteSize(curveId, &keyBytes) == HCF_SUCCESS && keyBytes > 0) {
        res = TryConvertEcPubKeyRaw(curveId, pubKeyBlob, keyBytes, returnPubKey);
        if (res != HCF_SUCCESS) {
            LOGD("TryConvertEcPubKeyRaw success.");
            return res;
        }
    }
    return res;
}

static HcfResult ConvertPriFromEncoded(EC_KEY **eckey, HcfBlob *priKeyBlob)
{
    const unsigned char *tmpData = (const unsigned char *)(priKeyBlob->data);
    EVP_PKEY *pkey = OpensslD2iPrivateKey(EVP_PKEY_EC, NULL, &tmpData, priKeyBlob->len);
    if (pkey == NULL) {
        HcfPrintOpensslError();
        LOGE("d2i pri key failed.");
        return HCF_ERR_CRYPTO_OPERATION;
    }
    *eckey = OpensslEvpPkeyGet1EcKey(pkey);
    OpensslEvpPkeyFree(pkey);
    if (*eckey == NULL) {
        LOGE("Get eckey failed");
        HcfPrintOpensslError();
        return HCF_ERR_CRYPTO_OPERATION;
    }
    return HCF_SUCCESS;
}

static HcfResult EccDeriveAndSetPublicKey(EC_KEY *ecKey)
{
    const BIGNUM *priv = OpensslEcKeyGet0PrivateKey(ecKey);
    const EC_GROUP *group = OpensslEcKeyGet0Group(ecKey);
    if (priv == NULL || group == NULL) {
        LOGE("Failed to get private key or group from EC key.");
        return HCF_ERR_CRYPTO_OPERATION;
    }
    EC_POINT *pubPoint = OpensslEcPointNew(group);
    if (pubPoint == NULL) {
        LOGE("Failed to create EC point.");
        return HCF_ERR_CRYPTO_OPERATION;
    }
    BN_CTX *bnCtx = OpensslBnCtxNew();
    if (bnCtx == NULL) {
        OpensslEcPointFree(pubPoint);
        LOGE("Failed to create BN context.");
        return HCF_ERR_CRYPTO_OPERATION;
    }
    if (OpensslEcPointMul(group, pubPoint, priv, NULL, NULL, bnCtx) != HCF_OPENSSL_SUCCESS) {
        LOGE("EC_POINT_mul fail.");
        OpensslBnCtxFree(bnCtx);
        OpensslEcPointFree(pubPoint);
        return HCF_ERR_CRYPTO_OPERATION;
    }
    if (OpensslEcKeySetPublicKey(ecKey, pubPoint) != HCF_OPENSSL_SUCCESS) {
        LOGE("Failed to set EC public key.");
        OpensslBnCtxFree(bnCtx);
        OpensslEcPointFree(pubPoint);
        return HCF_ERR_CRYPTO_OPERATION;
    }
    OpensslBnCtxFree(bnCtx);
    OpensslEcPointFree(pubPoint);
    return HCF_SUCCESS;
}

static EC_KEY *EccDecodePriScalarKOnly(int32_t curveId, const unsigned char *octets, size_t keyBytes)
{
    EC_KEY *ecKey = OpensslEcKeyNewByCurveName(curveId);
    if (ecKey == NULL) {
        LOGE("Failed to create EC key by curve name.");
        return NULL;
    }
    if (EC_KEY_oct2priv(ecKey, octets, keyBytes) != HCF_OPENSSL_SUCCESS) {
        LOGE("EC_KEY_oct2priv fail.");
        OpensslEcKeyFree(ecKey);
        return NULL;
    }
    if (EccDeriveAndSetPublicKey(ecKey) != HCF_SUCCESS) {
        OpensslEcKeyFree(ecKey);
        LOGE("Failed to derive and set ECC public key.");
        return NULL;
    }
    return ecKey;
}

static EC_KEY *EccDecodePri04XYK(int32_t curveId, const unsigned char *octets, size_t keyBytes)
{
    EC_KEY *ecKey = OpensslEcKeyNewByCurveName(curveId);
    if (ecKey == NULL) {
        LOGE("Failed to create EC key by curve name.");
        return NULL;
    }
    if (EC_KEY_oct2key(ecKey, octets, ECC_COORDINATE_COUNT * keyBytes + ECC_OCTET_PREFIX_SIZE, NULL) !=
        HCF_OPENSSL_SUCCESS) {
        LOGE("EC_KEY_oct2key fail.");
        OpensslEcKeyFree(ecKey);
        return NULL;
    }
    if (EC_KEY_oct2priv(ecKey, octets + (ECC_COORDINATE_COUNT * keyBytes + ECC_OCTET_PREFIX_SIZE), keyBytes) !=
        HCF_OPENSSL_SUCCESS) {
        LOGE("EC_KEY_oct2priv fail.");
        OpensslEcKeyFree(ecKey);
        return NULL;
    }
    return ecKey;
}

static HcfResult ConvertEcPriKeyPackOrFree(int32_t curveId, EC_KEY *ecKey, HcfOpensslEccPriKey **returnPriKey)
{
    if (OpensslEcKeyCheckKey(ecKey) != HCF_OPENSSL_SUCCESS) {
        LOGE("EC_KEY_check_key fail.");
        OpensslEcKeyFree(ecKey);
        return HCF_ERR_CRYPTO_OPERATION;
    }
    HcfResult res = EccPackPriKeyForConvert(curveId, ecKey, returnPriKey);
    if (res != HCF_SUCCESS) {
        LOGE("Pack ec pri key failed.");
        OpensslEcKeyFree(ecKey);
        return res;
    }
    return HCF_SUCCESS;
}

static HcfResult TryConvertEcPriKeyRaw(int32_t curveId, HcfBlob *priKeyBlob, size_t keyBytes,
    HcfOpensslEccPriKey **returnPriKey)
{
    const unsigned char *octets = (const unsigned char *)(priKeyBlob->data);
    size_t len = priKeyBlob->len;
    EC_KEY *ecKey = NULL;

    if (len == keyBytes) {
        ecKey = EccDecodePriScalarKOnly(curveId, octets, keyBytes);
        if (ecKey == NULL) {
            LOGE("Invalid key bytes length.");
            return HCF_ERR_CRYPTO_OPERATION;
        }
        return ConvertEcPriKeyPackOrFree(curveId, ecKey, returnPriKey);
    }
    if (len == (ECC_COORDINATE_COUNT_3 * keyBytes + ECC_OCTET_PREFIX_SIZE) && octets[0] == 0x04) {
        ecKey = EccDecodePri04XYK(curveId, octets, keyBytes);
        if (ecKey == NULL) {
            LOGE("Invalid coordinate length.");
            return HCF_ERR_CRYPTO_OPERATION;
        }
        return ConvertEcPriKeyPackOrFree(curveId, ecKey, returnPriKey);
    }
    return HCF_NOT_SUPPORT;
}

HcfResult ConvertEcPriKey(int32_t curveId, HcfBlob *priKeyBlob, HcfOpensslEccPriKey **returnPriKey)
{
    if ((curveId == 0) || (priKeyBlob == NULL) || (returnPriKey == NULL)) {
        LOGE("Invalid input parameter.");
        return HCF_INVALID_PARAMS;
    }
    size_t keyBytes = 0;
    if (EccCurveIdGetKeyByteSize(curveId, &keyBytes) == HCF_SUCCESS && keyBytes > 0) {
        HcfResult rawRes = TryConvertEcPriKeyRaw(curveId, priKeyBlob, keyBytes, returnPriKey);
        if (rawRes != HCF_NOT_SUPPORT) {
            return rawRes;
        }
    }
    EC_KEY *ecKey = NULL;
    HcfResult res = ConvertPriFromEncoded(&ecKey, priKeyBlob);
    if (res != HCF_SUCCESS) {
        LOGE("i2d for private key failed");
        HcfPrintOpensslError();
        return HCF_ERR_CRYPTO_OPERATION;
    }
    if (ecKey == NULL) {
        LOGE("d2i ec private key fail");
        HcfPrintOpensslError();
        return HCF_ERR_CRYPTO_OPERATION;
    }
    res = EccPackPriKeyForConvert(curveId, ecKey, returnPriKey);
    if (res != HCF_SUCCESS) {
        LOGE("Pack ec pri key failed.");
        OpensslEcKeyFree(ecKey);
        return res;
    }
    return HCF_SUCCESS;
}

static HcfResult EccEcKeyComputeKeyBytes(const EC_KEY *ecKey, size_t *keyBytes)
{
    const EC_GROUP *group = OpensslEcKeyGet0Group(ecKey);
    if (group == NULL) {
        LOGE("Failed to get EC group from key.");
        return HCF_ERR_CRYPTO_OPERATION;
    }
    int degree = OpensslEcGroupGetDegree(group);
    if (degree < 0) {
        LOGE("Get degree failed.");
        return HCF_ERR_CRYPTO_OPERATION;
    }
    *keyBytes = (size_t)((degree + (BITS_PER_BYTE - ECC_OCTET_PREFIX_SIZE)) / BITS_PER_BYTE);
    return (*keyBytes == 0) ? HCF_ERR_PARAMETER_CHECK_FAILED : HCF_SUCCESS;
}

static HcfResult EccCopyKey2bufUncompressed(EC_KEY *ecKey, size_t keyBytes, int strip04Prefix, HcfBlob *returnBlob)
{
    unsigned char *buf = NULL;
    size_t bufLen = EC_KEY_key2buf(ecKey, POINT_CONVERSION_UNCOMPRESSED, &buf, NULL);
    size_t expectedLen = ECC_COORDINATE_COUNT * keyBytes + ECC_OCTET_PREFIX_SIZE;
    if (bufLen != expectedLen || buf == NULL) {
        if (buf != NULL) {
            OPENSSL_free(buf);
        }
        LOGE("EC_KEY_key2buf fail.");
        return HCF_ERR_CRYPTO_OPERATION;
    }
    if (!strip04Prefix) {
        returnBlob->data = (uint8_t *)HcfMalloc(bufLen, 0);
        if (returnBlob->data == NULL) {
            LOGE("Failed to allocate memory for uncompressed EC public key blob");
            OPENSSL_free(buf);
            return HCF_ERR_MALLOC;
        }
        if (memcpy_s(returnBlob->data, bufLen, buf, bufLen) != EOK) {
            OPENSSL_free(buf);
            HcfFree(returnBlob->data);
            returnBlob->data = NULL;
            LOGE("memcpy_s fail.");
            return HCF_ERR_CRYPTO_OPERATION;
        }
        returnBlob->len = bufLen;
    } else {
        size_t outLen = ECC_COORDINATE_COUNT * keyBytes;
        returnBlob->data = (uint8_t *)HcfMalloc(outLen, 0);
        if (returnBlob->data == NULL) {
            LOGE("Failed to allocate memory for stripped uncompressed EC public key blob");
            OPENSSL_free(buf);
            return HCF_ERR_MALLOC;
        }
        if (memcpy_s(returnBlob->data, outLen, buf + ECC_OCTET_PREFIX_SIZE, outLen) != EOK) {
            OPENSSL_free(buf);
            HcfFree(returnBlob->data);
            returnBlob->data = NULL;
            LOGE("memcpy_s fail.");
            return HCF_ERR_CRYPTO_OPERATION;
        }
        returnBlob->len = outLen;
    }
    OPENSSL_free(buf);
    return HCF_SUCCESS;
}

static HcfResult EccCopyKey2bufCompressed(EC_KEY *ecKey, size_t keyBytes, HcfBlob *returnBlob)
{
    unsigned char *buf = NULL;
    size_t bufLen = EC_KEY_key2buf(ecKey, POINT_CONVERSION_COMPRESSED, &buf, NULL);
    size_t expectedLen = keyBytes + ECC_OCTET_PREFIX_SIZE;
    if (bufLen != expectedLen || buf == NULL) {
        if (buf != NULL) {
            OPENSSL_free(buf);
        }
        LOGE("EC_KEY_key2buf fail.");
        return HCF_ERR_CRYPTO_OPERATION;
    }
    returnBlob->data = (uint8_t *)HcfMalloc(bufLen, 0);
    if (returnBlob->data == NULL) {
        OPENSSL_free(buf);
        LOGE("Failed to allocate memory for EC public key data.");
        return HCF_ERR_MALLOC;
    }
    if (memcpy_s(returnBlob->data, bufLen, buf, bufLen) != EOK) {
        OPENSSL_free(buf);
        HcfFree(returnBlob->data);
        returnBlob->data = NULL;
        LOGE("memcpy_s fail.");
        return HCF_ERR_CRYPTO_OPERATION;
    }
    returnBlob->len = bufLen;
    OPENSSL_free(buf);
    return HCF_SUCCESS;
}

static HcfResult EccCopyPrivScalarToBlob(EC_KEY *ecKey, size_t keyBytes, HcfBlob *returnBlob)
{
    unsigned char *kBuf = NULL;
    size_t kLen = EC_KEY_priv2buf(ecKey, &kBuf);
    if (kLen != keyBytes || kBuf == NULL) {
        if (kBuf != NULL) {
            OPENSSL_clear_free(kBuf, kLen);
        }
        LOGE("EC_KEY_key2buf fail.");
        return HCF_ERR_CRYPTO_OPERATION;
    }
    returnBlob->data = (uint8_t *)HcfMalloc(kLen, 0);
    if (returnBlob->data == NULL) {
        OPENSSL_clear_free(kBuf, kLen);
        LOGE("Failed to allocate memory for EC private scalar data.");
        return HCF_ERR_MALLOC;
    }
    if (memcpy_s(returnBlob->data, kLen, kBuf, kLen) != EOK) {
        OPENSSL_clear_free(kBuf, kLen);
        HcfFree(returnBlob->data);
        returnBlob->data = NULL;
        LOGE("memcpy_s fail.");
        return HCF_ERR_CRYPTO_OPERATION;
    }
    returnBlob->len = kLen;
    OPENSSL_clear_free(kBuf, kLen);
    return HCF_SUCCESS;
}

static HcfResult EccCopyPriv04XYAndKToBlob(EC_KEY *ecKey, size_t keyBytes, HcfBlob *returnBlob)
{
    unsigned char *pBuf = NULL;
    size_t pLen = EC_KEY_key2buf(ecKey, POINT_CONVERSION_UNCOMPRESSED, &pBuf, NULL);
    size_t expectedP = ECC_COORDINATE_COUNT * keyBytes + ECC_OCTET_PREFIX_SIZE;
    if (pLen != expectedP || pBuf == NULL) {
        if (pBuf != NULL) {
            OPENSSL_clear_free(pBuf, pLen);
        }
        LOGE("EC_KEY_key2buf fail.");
        return HCF_ERR_CRYPTO_OPERATION;
    }
    unsigned char *kBuf = NULL;
    size_t kLen = EC_KEY_priv2buf(ecKey, &kBuf);
    if (kLen != keyBytes || kBuf == NULL) {
        OPENSSL_clear_free(pBuf, pLen);
        if (kBuf != NULL) {
            OPENSSL_clear_free(kBuf, kLen);
        }
        LOGE("EC_KEY_key2buf fail.");
        return HCF_ERR_CRYPTO_OPERATION;
    }
    size_t outLen = ECC_COORDINATE_COUNT_3 * keyBytes + ECC_OCTET_PREFIX_SIZE;
    uint8_t *out = (uint8_t *)HcfMalloc(outLen, 0);
    if (out == NULL) {
        OPENSSL_clear_free(pBuf, pLen);
        OPENSSL_clear_free(kBuf, kLen);
        LOGE("Failed to allocate memory.");
        return HCF_ERR_MALLOC;
    }
    if ((memcpy_s(out, outLen, pBuf, pLen) != EOK) || (memcpy_s(out + pLen, keyBytes, kBuf, kLen) != EOK)) {
        OPENSSL_clear_free(pBuf, pLen);
        OPENSSL_clear_free(kBuf, kLen);
        HcfFree(out);
        LOGE("memcpy_s fail.");
        return HCF_ERR_CRYPTO_OPERATION;
    }
    returnBlob->data = out;
    returnBlob->len = outLen;
    OPENSSL_clear_free(pBuf, pLen);
    OPENSSL_clear_free(kBuf, kLen);
    return HCF_SUCCESS;
}

HcfResult GetEccPubKeyDataInCommon(const HcfPubKey *self, uint32_t type, HcfBlob *returnBlob)
{
    if ((self == NULL) || (returnBlob == NULL)) {
        LOGE("Invalid input parameter.");
        return HCF_ERR_PARAMETER_CHECK_FAILED;
    }
    if (!HcfIsClassMatch((HcfObjectBase *)self, HCF_OPENSSL_ECC_PUB_KEY_CLASS)) {
        LOGE("Invalid input parameter type.");
        return HCF_ERR_PARAMETER_CHECK_FAILED;
    }
    if (type == EC_PRIVATE_K || type == EC_PRIVATE_04_X_Y_K) {
        LOGE("Invalid input parameter type.");
        return HCF_ERR_PARAMETER_CHECK_FAILED;
    }
    HcfOpensslEccPubKey *impl = (HcfOpensslEccPubKey *)self;
    if (impl->ecKey == NULL) {
        LOGE("Invalid input parameter.");
        return HCF_ERR_PARAMETER_CHECK_FAILED;
    }
    size_t keyBytes = 0;
    HcfResult res = EccEcKeyComputeKeyBytes(impl->ecKey, &keyBytes);
    if (res != HCF_SUCCESS) {
        LOGE("Failed to compute key bytes.");
        return res;
    }
    if (type == EC_PUBLIC_04_X_Y) {
        return EccCopyKey2bufUncompressed(impl->ecKey, keyBytes, 0, returnBlob);
    }
    if (type == EC_PUBLIC_X_Y) {
        return EccCopyKey2bufUncompressed(impl->ecKey, keyBytes, 1, returnBlob);
    }
    if (type == EC_PUBLIC_COMPRESS_X) {
        return EccCopyKey2bufCompressed(impl->ecKey, keyBytes, returnBlob);
    }
    return HCF_SUCCESS;
}

HcfResult GetEccPriKeyDataInCommon(const HcfPriKey *self, uint32_t type, HcfBlob *returnBlob)
{
    if ((self == NULL) || (returnBlob == NULL)) {
        LOGE("Invalid input parameter.");
        return HCF_ERR_PARAMETER_CHECK_FAILED;
    }
    if (!HcfIsClassMatch((HcfObjectBase *)self, HCF_OPENSSL_ECC_PRI_KEY_CLASS)) {
        LOGE("Invalid input parameter type.");
        return HCF_ERR_PARAMETER_CHECK_FAILED;
    }
    HcfOpensslEccPriKey *impl = (HcfOpensslEccPriKey *)self;
    if (impl->ecKey == NULL) {
        LOGE("Invalid input parameter.");
        return HCF_ERR_PARAMETER_CHECK_FAILED;
    }
    size_t keyBytes = 0;
    HcfResult res = EccEcKeyComputeKeyBytes(impl->ecKey, &keyBytes);
    if (res != HCF_SUCCESS) {
        LOGE("Failed to compute key bytes.");
        return res;
    }
    if (type == EC_PRIVATE_K) {
        return EccCopyPrivScalarToBlob(impl->ecKey, keyBytes, returnBlob);
    }
    if (type == EC_PRIVATE_04_X_Y_K) {
        return EccCopyPriv04XYAndKToBlob(impl->ecKey, keyBytes, returnBlob);
    }
    return HCF_SUCCESS;
}
