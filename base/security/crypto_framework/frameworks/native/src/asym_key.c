/*
 * Copyright (C) 2024 Huawei Device Co., Ltd.
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

#include "crypto_asym_key.h"
#include <string.h>
#include <stdlib.h>
#include <securec.h>
#include "key_pair.h"
#include "detailed_ecc_key_params.h"
#include "detailed_dh_key_params.h"
#include "detailed_rsa_key_params.h"
#include "detailed_dsa_key_params.h"
#include "detailed_alg_25519_key_params.h"
#include "params_parser.h"
#include "ecc_key_util.h"
#include "dh_key_util.h"
#include "key_utils.h"
#include "memory.h"
#include "pub_key.h"
#include "pri_key.h"
#include "result.h"
#include "blob.h"
#include "object_base.h"
#include "native_common.h"
#include "crypto_common.h"
#include "big_integer.h"
#include "asy_key_generator.h"

typedef struct OH_CryptoAsymKeyGenerator {
    HcfAsyKeyGenerator *base;
    HcfKeyDecodingParamsSpec *decSpec;
} OH_CryptoAsymKeyGenerator;

typedef struct OH_CryptoKeyPair {
    HcfObjectBase base;

    HcfPriKey *priKey;

    HcfPubKey *pubKey;
} OH_CryptoKeyPair;

typedef struct OH_CryptoPubKey {
    HcfKey base;

    HcfResult (*getAsyKeySpecBigInteger)(const HcfPubKey *self, const AsyKeySpecItem item,
        HcfBigInteger *returnBigInteger);

    HcfResult (*getAsyKeySpecString)(const HcfPubKey *self, const AsyKeySpecItem item, char **returnString);

    HcfResult (*getAsyKeySpecInt)(const HcfPubKey *self, const AsyKeySpecItem item, int *returnInt);

    HcfResult (*getEncodedDer)(const HcfPubKey *self, const char *format, HcfBlob *returnBlob);
} OH_CryptoPubKey;

typedef struct OH_CryptoPrivKey {
    HcfKey base;

    HcfResult (*getAsyKeySpecBigInteger)(const HcfPriKey *self, const AsyKeySpecItem item,
        HcfBigInteger *returnBigInteger);

    HcfResult (*getAsyKeySpecString)(const HcfPriKey *self, const AsyKeySpecItem item, char **returnString);

    HcfResult (*getAsyKeySpecInt)(const HcfPriKey *self, const AsyKeySpecItem item, int *returnInt);

    HcfResult (*getEncodedDer)(const HcfPriKey *self, const char *format, HcfBlob *returnBlob);

    HcfResult (*getEncodedPem)(const HcfPriKey *self, HcfParamsSpec *params, const char *format, char **returnString);

    HcfResult (*getPubKey)(const HcfPriKey *self, HcfPubKey **returnPubKey);

    void (*clearMem)(HcfPriKey *self);
} OH_CryptoPrivKey;

typedef struct OH_CryptoPrivKeyEncodingParams {
    HcfParamsSpec base;

    char *password;

    char *cipher;
} OH_CryptoPrivKeyEncodingParams;

typedef struct OH_CryptoAsymKeySpec {
    char *algName;
    HcfAsyKeySpecType specType;
} OH_CryptoAsymKeySpec;

typedef struct OH_CryptoAsymKeyGeneratorWithSpec {
    HcfAsyKeyGeneratorBySpec *generator;
    HcfAsyKeySpecType specType;
} OH_CryptoAsymKeyGeneratorWithSpec;

typedef struct OH_CryptoEcPoint {
    HcfPoint pointBase;
    char *curveName;
} OH_CryptoEcPoint;

static OH_Crypto_ErrCode CryptoAsymKeyGeneratorCreate(const char *algoName, OH_CryptoAsymKeyGenerator **ctx)
{
    if (ctx == NULL) {
        return CRYPTO_INVALID_PARAMS;
    }
    OH_CryptoAsymKeyGenerator *tmpCtx = HcfMalloc(sizeof(OH_CryptoAsymKeyGenerator), 0);
    if (tmpCtx == NULL) {
        return CRYPTO_MEMORY_ERROR;
    }
    HcfResult ret = HcfAsyKeyGeneratorCreate(algoName, &(tmpCtx->base));
    if (ret != HCF_SUCCESS) {
        HcfFree(tmpCtx);
        tmpCtx = NULL;
        return GetOhCryptoErrCode(ret);
    }
    *ctx = tmpCtx;
    return GetOhCryptoErrCode(ret);
}

OH_Crypto_ErrCode OH_CryptoAsymKeyGenerator_Create(const char *algoName, OH_CryptoAsymKeyGenerator **ctx)
{
    return CryptoAsymKeyGeneratorCreate(algoName, ctx);
}

static OH_Crypto_ErrCode CryptoAsymKeyGeneratorGenerate(OH_CryptoAsymKeyGenerator *ctx, OH_CryptoKeyPair **keyCtx)
{
    if ((ctx == NULL) || (ctx->base == NULL) || (ctx->base->generateKeyPair == NULL) || (keyCtx == NULL)) {
        return CRYPTO_INVALID_PARAMS;
    }
    HcfResult ret = ctx->base->generateKeyPair((HcfAsyKeyGenerator *)(ctx->base), NULL, (HcfKeyPair **)keyCtx);
    return GetOhCryptoErrCode(ret);
}

OH_Crypto_ErrCode OH_CryptoAsymKeyGenerator_Generate(OH_CryptoAsymKeyGenerator *ctx, OH_CryptoKeyPair **keyCtx)
{
    return CryptoAsymKeyGeneratorGenerate(ctx, keyCtx);
}

static void FreeDecParamsSpec(HcfKeyDecodingParamsSpec *decSpec)
{
    if (decSpec == NULL) {
        return;
    }

    if (decSpec->password != NULL) {
        (void)memset_s(decSpec->password, strlen(decSpec->password), 0, strlen(decSpec->password));
        HcfFree(decSpec->password);
        decSpec->password = NULL;
    }
    HcfFree(decSpec);
}

static OH_Crypto_ErrCode CryptoAsymKeyGeneratorSetPassword(OH_CryptoAsymKeyGenerator *ctx,
    const unsigned char *password, uint32_t passwordLen)
{
    if ((ctx == NULL) || (password == NULL) || (passwordLen == 0)) {
        return CRYPTO_PARAMETER_CHECK_FAILED;
    }
    if (passwordLen > UINT32_MAX - 1) {
        return CRYPTO_PARAMETER_CHECK_FAILED;
    }
    HcfKeyDecodingParamsSpec *decSpec = (HcfKeyDecodingParamsSpec *)HcfMalloc(sizeof(HcfKeyDecodingParamsSpec), 0);
    if (decSpec == NULL) {
        return CRYPTO_MEMORY_ERROR;
    }
    decSpec->password = (char *)HcfMalloc(passwordLen + 1, 0);
    if (decSpec->password == NULL) {
        HcfFree(decSpec);
        decSpec = NULL;
        return CRYPTO_MEMORY_ERROR;
    }
    (void)memcpy_s(decSpec->password, passwordLen, password, passwordLen);
    FreeDecParamsSpec(ctx->decSpec);
    ctx->decSpec = decSpec;
    return CRYPTO_SUCCESS;
}

OH_Crypto_ErrCode OH_CryptoAsymKeyGenerator_SetPassword(OH_CryptoAsymKeyGenerator *ctx, const unsigned char *password,
    uint32_t passwordLen)
{
    return CryptoAsymKeyGeneratorSetPassword(ctx, password, passwordLen);
}

static OH_Crypto_ErrCode ProcessPriKeyData(Crypto_DataBlob *priKeyData, char **priKeyStr)
{
    if (priKeyData == NULL) {
        return CRYPTO_SUCCESS;
    }

    *priKeyStr = (char *)HcfMalloc(priKeyData->len + 1, 0);
    if (*priKeyStr == NULL) {
        return CRYPTO_MEMORY_ERROR;
    }
    (void)memcpy_s(*priKeyStr, priKeyData->len, priKeyData->data, priKeyData->len);
    return CRYPTO_SUCCESS;
}

static OH_Crypto_ErrCode ProcessPubKeyData(Crypto_DataBlob *pubKeyData, char **pubKeyStr)
{
    if (pubKeyData == NULL) {
        return CRYPTO_SUCCESS;
    }

    *pubKeyStr = (char *)HcfMalloc(pubKeyData->len + 1, 0);
    if (*pubKeyStr == NULL) {
        return CRYPTO_MEMORY_ERROR;
    }
    (void)memcpy_s(*pubKeyStr, pubKeyData->len, pubKeyData->data, pubKeyData->len);
    return CRYPTO_SUCCESS;
}

static HcfResult ExecutePemConversion(OH_CryptoAsymKeyGenerator *ctx, char *pubKeyStr,
    char *priKeyStr, OH_CryptoKeyPair **keyCtx)
{
    return ctx->base->convertPemKey == NULL ? HCF_INVALID_PARAMS :
        ctx->base->convertPemKey((HcfAsyKeyGenerator *)(ctx->base), (HcfParamsSpec *)(ctx->decSpec),
            pubKeyStr, priKeyStr, (HcfKeyPair **)keyCtx);
}

static void CleanupPemMemory(char *priKeyStr, char *pubKeyStr)
{
    if (priKeyStr != NULL) {
        (void)memset_s(priKeyStr, strlen(priKeyStr), 0, strlen(priKeyStr));
        HcfFree(priKeyStr);
    }
    if (pubKeyStr != NULL) {
        (void)memset_s(pubKeyStr, strlen(pubKeyStr), 0, strlen(pubKeyStr));
        HcfFree(pubKeyStr);
    }
}

static OH_Crypto_ErrCode HandlePemConversion(OH_CryptoAsymKeyGenerator *ctx, Crypto_DataBlob *pubKeyData,
    Crypto_DataBlob *priKeyData, OH_CryptoKeyPair **keyCtx)
{
    char *priKeyStr = NULL;
    char *pubKeyStr = NULL;
    OH_Crypto_ErrCode ret = ProcessPriKeyData(priKeyData, &priKeyStr);
    if (ret != CRYPTO_SUCCESS) {
        return ret;
    }

    ret = ProcessPubKeyData(pubKeyData, &pubKeyStr);
    if (ret != CRYPTO_SUCCESS) {
        CleanupPemMemory(priKeyStr, pubKeyStr);
        priKeyStr = NULL;
        pubKeyStr = NULL;
        return ret;
    }

    HcfResult hcfRet = ExecutePemConversion(ctx, pubKeyStr, priKeyStr, keyCtx);
    CleanupPemMemory(priKeyStr, pubKeyStr);
    priKeyStr = NULL;
    pubKeyStr = NULL;
    return GetOhCryptoErrCode(hcfRet);
}

static OH_Crypto_ErrCode CryptoAsymKeyGeneratorConvert(OH_CryptoAsymKeyGenerator *ctx, Crypto_EncodingType type,
    Crypto_DataBlob *pubKeyData, Crypto_DataBlob *priKeyData, OH_CryptoKeyPair **keyCtx)
{
    if ((ctx == NULL) || (ctx->base == NULL) || (pubKeyData == NULL && priKeyData == NULL) || (keyCtx == NULL)) {
        return CRYPTO_INVALID_PARAMS;
    }

    OH_Crypto_ErrCode ret = CRYPTO_SUCCESS;
    switch (type) {
        case CRYPTO_PEM:
            ret = HandlePemConversion(ctx, pubKeyData, priKeyData, keyCtx);
            break;
        case CRYPTO_DER:
            ret = GetOhCryptoErrCode(ctx->base->convertKey == NULL ? HCF_INVALID_PARAMS :
                ctx->base->convertKey((HcfAsyKeyGenerator *)(ctx->base), (HcfParamsSpec *)(ctx->decSpec),
                    (HcfBlob *)pubKeyData, (HcfBlob *)priKeyData, (HcfKeyPair **)keyCtx));
            break;
        default:
            ret = CRYPTO_INVALID_PARAMS;
            break;
    }
    if (ret != CRYPTO_SUCCESS) {
        return ret;
    }
    if (*keyCtx != NULL && (*keyCtx)->pubKey == NULL && (*keyCtx)->priKey != NULL) {
        HcfResult retPubKey = (*keyCtx)->priKey->getPubKey((HcfPriKey *)(*keyCtx)->priKey, &(*keyCtx)->pubKey);
        if (retPubKey != HCF_SUCCESS) {
            HcfObjDestroy((*keyCtx)->pubKey);
            (*keyCtx)->pubKey = NULL;
            return GetOhCryptoErrCode(retPubKey);
        }
    }
    return ret;
}

OH_Crypto_ErrCode OH_CryptoAsymKeyGenerator_Convert(OH_CryptoAsymKeyGenerator *ctx, Crypto_EncodingType type,
    Crypto_DataBlob *pubKeyData, Crypto_DataBlob *priKeyData, OH_CryptoKeyPair **keyCtx)
{
    return CryptoAsymKeyGeneratorConvert(ctx, type, pubKeyData, priKeyData, keyCtx);
}

static const char *CryptoAsymKeyGeneratorGetAlgoName(OH_CryptoAsymKeyGenerator *ctx)
{
    if ((ctx == NULL) || (ctx->base == NULL) || (ctx->base->getAlgoName == NULL)) {
        return NULL;
    }
    return ctx->base->getAlgoName((HcfAsyKeyGenerator *)(ctx->base));
}

const char *OH_CryptoAsymKeyGenerator_GetAlgoName(OH_CryptoAsymKeyGenerator *ctx)
{
    const char *name = CryptoAsymKeyGeneratorGetAlgoName(ctx);
    return name;
}

static void CryptoAsymKeyGeneratorDestroy(OH_CryptoAsymKeyGenerator *ctx)
{
    if (ctx == NULL) {
        return;
    }
    HcfObjDestroy(ctx->base);
    ctx->base = NULL;
    FreeDecParamsSpec(ctx->decSpec);
    ctx->decSpec = NULL;
    HcfFree(ctx);
}

void OH_CryptoAsymKeyGenerator_Destroy(OH_CryptoAsymKeyGenerator *ctx)
{
    CryptoAsymKeyGeneratorDestroy(ctx);
}

static void CryptoKeyPairDestroy(OH_CryptoKeyPair *keyCtx)
{
    if (keyCtx == NULL) {
        return;
    }
    if (keyCtx->base.destroy != NULL) {
        keyCtx->base.destroy((HcfObjectBase *)keyCtx);
        return;
    }
    if ((keyCtx->priKey != NULL) && (keyCtx->priKey->base.base.destroy != NULL)) {
        HcfObjDestroy(keyCtx->priKey);
        keyCtx->priKey = NULL;
    }
    if ((keyCtx->pubKey != NULL) && (keyCtx->pubKey->base.base.destroy != NULL)) {
        HcfObjDestroy(keyCtx->pubKey);
        keyCtx->pubKey = NULL;
    }
    HcfFree(keyCtx);
}

void OH_CryptoKeyPair_Destroy(OH_CryptoKeyPair *keyCtx)
{
    CryptoKeyPairDestroy(keyCtx);
}

static OH_CryptoPubKey *CryptoKeyPairGetPubKey(OH_CryptoKeyPair *keyCtx)
{
    if (keyCtx == NULL) {
        return NULL;
    }
    return (OH_CryptoPubKey *)keyCtx->pubKey;
}

OH_CryptoPubKey *OH_CryptoKeyPair_GetPubKey(OH_CryptoKeyPair *keyCtx)
{
    OH_CryptoPubKey *pubKey = CryptoKeyPairGetPubKey(keyCtx);
    return pubKey;
}

static OH_CryptoPrivKey *CryptoKeyPairGetPrivKey(OH_CryptoKeyPair *keyCtx)
{
    if (keyCtx == NULL) {
        return NULL;
    }
    return (OH_CryptoPrivKey *)keyCtx->priKey;
}

OH_CryptoPrivKey *OH_CryptoKeyPair_GetPrivKey(OH_CryptoKeyPair *keyCtx)
{
    OH_CryptoPrivKey *priKey = CryptoKeyPairGetPrivKey(keyCtx);
    return priKey;
}

static OH_Crypto_ErrCode CryptoPubKeyEncode(OH_CryptoPubKey *key, Crypto_EncodingType type,
    const char *encodingStandard, Crypto_DataBlob *out)
{
    if ((key == NULL) || (out == NULL)) {
        return CRYPTO_INVALID_PARAMS;
    }
    HcfResult ret = HCF_SUCCESS;
    char *pemStr = NULL;
    switch (type) {
        case CRYPTO_PEM:
            if (key->base.getEncodedPem == NULL) {
                return CRYPTO_INVALID_PARAMS;
            }
            ret = key->base.getEncodedPem((HcfKey *)key, encodingStandard, &pemStr);
            if (ret != HCF_SUCCESS) {
                break;
            }
            out->data = (uint8_t *)pemStr;
            out->len = strlen(pemStr);
            break;
        case CRYPTO_DER:
            if (encodingStandard != NULL) {
                ret = key->getEncodedDer == NULL ? HCF_INVALID_PARAMS :
                    key->getEncodedDer((HcfPubKey *)key, encodingStandard, (HcfBlob *)out);
                break;
            } else {
                ret = key->base.getEncoded == NULL ? HCF_INVALID_PARAMS
                                                   : key->base.getEncoded((HcfKey *)key, (HcfBlob *)out);
                break;
            }
        default:
            return CRYPTO_INVALID_PARAMS;
    }

    return GetOhCryptoErrCode(ret);
}

OH_Crypto_ErrCode OH_CryptoPubKey_Encode(OH_CryptoPubKey *key, Crypto_EncodingType type,
    const char *encodingStandard, Crypto_DataBlob *out)
{
    return CryptoPubKeyEncode(key, type, encodingStandard, out);
}

static OH_Crypto_ErrCode CryptoPubKeyGetParam(OH_CryptoPubKey *key, CryptoAsymKey_ParamType item,
    Crypto_DataBlob *value)
{
    if ((key == NULL) || (value == NULL)) {
        return CRYPTO_INVALID_PARAMS;
    }
    HcfResult ret = HCF_SUCCESS;
    int32_t *returnInt = NULL;
    char *returnStr = NULL;
    HcfBigInteger bigIntValue = {0};
    switch (item) {
        case CRYPTO_DH_L_INT:
        case CRYPTO_ECC_H_INT:
        case CRYPTO_ECC_FIELD_SIZE_INT:
            returnInt = (int32_t *)HcfMalloc(sizeof(int32_t), 0);
            if (returnInt == NULL) {
                ret = HCF_ERR_MALLOC;
                break;
            }
            ret = key->getAsyKeySpecInt == NULL ? HCF_INVALID_PARAMS :
                key->getAsyKeySpecInt((HcfPubKey *)key, (AsyKeySpecItem)item, returnInt);
            if (ret != HCF_SUCCESS) {
                HCF_FREE_PTR(returnInt);
                break;
            }
            value->data = (uint8_t *)returnInt;
            value->len = sizeof(int32_t);
            ReverseUint8Arr(value->data, value->len);
            break;
        case CRYPTO_ECC_FIELD_TYPE_STR:
        case CRYPTO_ECC_CURVE_NAME_STR:
            ret = key->getAsyKeySpecString == NULL ? HCF_INVALID_PARAMS :
                key->getAsyKeySpecString((HcfPubKey *)key, (AsyKeySpecItem)item, &returnStr);
            if (ret != HCF_SUCCESS) {
                break;
            }
            value->data = (uint8_t *)returnStr;
            value->len = strlen(returnStr);
            break;
        default:
            ret = key->getAsyKeySpecBigInteger == NULL ? HCF_INVALID_PARAMS :
                key->getAsyKeySpecBigInteger((HcfPubKey *)key, (AsyKeySpecItem)item, &bigIntValue);
            if (ret != HCF_SUCCESS) {
                break;
            }
            value->data = (uint8_t *)bigIntValue.data;
            value->len = (size_t)bigIntValue.len;
            ReverseUint8Arr(value->data, value->len);
            break;
    }
    return GetOhCryptoErrCode(ret);
}

OH_Crypto_ErrCode OH_CryptoPubKey_GetParam(OH_CryptoPubKey *key, CryptoAsymKey_ParamType item, Crypto_DataBlob *value)
{
    return CryptoPubKeyGetParam(key, item, value);
}

static OH_Crypto_ErrCode CryptoPrivKeyEncodingParamsCreate(OH_CryptoPrivKeyEncodingParams **ctx)
{
    if (ctx == NULL) {
        return CRYPTO_PARAMETER_CHECK_FAILED;
    }
    *ctx = (OH_CryptoPrivKeyEncodingParams *)HcfMalloc(sizeof(OH_CryptoPrivKeyEncodingParams), 0);
    if (*ctx == NULL) {
        return CRYPTO_MEMORY_ERROR;
    }
    return CRYPTO_SUCCESS;
}

OH_Crypto_ErrCode OH_CryptoPrivKeyEncodingParams_Create(OH_CryptoPrivKeyEncodingParams **ctx)
{
    return CryptoPrivKeyEncodingParamsCreate(ctx);
}

static OH_Crypto_ErrCode CryptoPrivKeyEncodingParamsSetParam(OH_CryptoPrivKeyEncodingParams *ctx,
    CryptoPrivKeyEncoding_ParamType type, Crypto_DataBlob *value)
{
    if ((ctx == NULL) || (value == NULL) || (value->data == NULL) || (value->len == 0)) {
        return CRYPTO_PARAMETER_CHECK_FAILED;
    }
    char *data = (char *)HcfMalloc(value->len + 1, 0);
    if (data == NULL) {
        return CRYPTO_MEMORY_ERROR;
    }
    (void)memcpy_s(data, value->len, value->data, value->len);
    switch (type) {
        case CRYPTO_PRIVATE_KEY_ENCODING_PASSWORD_STR:
            if (ctx->password != NULL) {
                (void)memset_s(ctx->password, strlen(ctx->password), 0, strlen(ctx->password));
                HcfFree(ctx->password);
            }
            ctx->password = data;
            break;
        case CRYPTO_PRIVATE_KEY_ENCODING_SYMMETRIC_CIPHER_STR:
            HcfFree(ctx->cipher);
            ctx->cipher = data;
            break;
        default:
            HcfFree(data);
            data = NULL;
            return CRYPTO_PARAMETER_CHECK_FAILED;
    }
    return CRYPTO_SUCCESS;
}

OH_Crypto_ErrCode OH_CryptoPrivKeyEncodingParams_SetParam(OH_CryptoPrivKeyEncodingParams *ctx,
    CryptoPrivKeyEncoding_ParamType type, Crypto_DataBlob *value)
{
    return CryptoPrivKeyEncodingParamsSetParam(ctx, type, value);
}

static void CryptoPrivKeyEncodingParamsDestroy(OH_CryptoPrivKeyEncodingParams *ctx)
{
    if (ctx == NULL) {
        return;
    }
    if (ctx->password != NULL) {
        (void)memset_s(ctx->password, strlen(ctx->password), 0, strlen(ctx->password));
    }
    HcfFree(ctx->password);
    ctx->password = NULL;
    HcfFree(ctx->cipher);
    ctx->cipher = NULL;
    HcfFree(ctx);
}

void OH_CryptoPrivKeyEncodingParams_Destroy(OH_CryptoPrivKeyEncodingParams *ctx)
{
    CryptoPrivKeyEncodingParamsDestroy(ctx);
}

static OH_Crypto_ErrCode CryptoPrivKeyEncode(OH_CryptoPrivKey *key, Crypto_EncodingType type,
    const char *encodingStandard, OH_CryptoPrivKeyEncodingParams *params, Crypto_DataBlob *out)
{
    if ((key == NULL) || (out == NULL)) {
        return CRYPTO_PARAMETER_CHECK_FAILED;
    }
    HcfResult ret = HCF_SUCCESS;
    char *pemStr = NULL;
    switch (type) {
        case CRYPTO_PEM:
            if (key->getEncodedPem == NULL) {
                return CRYPTO_PARAMETER_CHECK_FAILED;
            }
            ret = key->getEncodedPem((HcfPriKey *)key, (HcfParamsSpec *)params, encodingStandard, &pemStr);
            if (ret != HCF_SUCCESS) {
                break;
            }
            out->data = (uint8_t *)pemStr;
            out->len = strlen(pemStr);
            break;
        case CRYPTO_DER:
            if (encodingStandard != NULL) {
                ret = key->getEncodedDer == NULL ? HCF_INVALID_PARAMS :
                    key->getEncodedDer((HcfPriKey *)key, encodingStandard, (HcfBlob *)out);
                break;
            } else {
                ret = key->base.getEncoded == NULL ? HCF_INVALID_PARAMS
                                                   : key->base.getEncoded((HcfKey *)key, (HcfBlob *)out);
                break;
            }
        default:
            return CRYPTO_PARAMETER_CHECK_FAILED;
    }

    return GetOhCryptoErrCodeNew(ret);
}

OH_Crypto_ErrCode OH_CryptoPrivKey_Encode(OH_CryptoPrivKey *key, Crypto_EncodingType type,
    const char *encodingStandard, OH_CryptoPrivKeyEncodingParams *params, Crypto_DataBlob *out)
{
    return CryptoPrivKeyEncode(key, type, encodingStandard, params, out);
}

static OH_Crypto_ErrCode CryptoPrivKeyGetParam(OH_CryptoPrivKey *key, CryptoAsymKey_ParamType item,
    Crypto_DataBlob *value)
{
    if ((key == NULL) || (value == NULL)) {
        return CRYPTO_PARAMETER_CHECK_FAILED;
    }
    HcfResult ret = HCF_SUCCESS;
    int32_t *returnInt = NULL;
    char *returnStr = NULL;
    HcfBigInteger bigIntValue = {0};
    switch (item) {
        case CRYPTO_DH_L_INT:
        case CRYPTO_ECC_H_INT:
        case CRYPTO_ECC_FIELD_SIZE_INT:
            returnInt = (int32_t *)HcfMalloc(sizeof(int32_t), 0);
            if (returnInt == NULL) {
                ret = HCF_ERR_MALLOC;
                break;
            }
            ret = key->getAsyKeySpecInt == NULL ? HCF_INVALID_PARAMS :
                key->getAsyKeySpecInt((HcfPriKey *)key, (AsyKeySpecItem)item, returnInt);
            if (ret != HCF_SUCCESS) {
                HCF_FREE_PTR(returnInt);
                break;
            }
            value->data = (uint8_t *)returnInt;
            value->len = sizeof(int32_t);
            ReverseUint8Arr(value->data, value->len);
            break;
        case CRYPTO_ECC_FIELD_TYPE_STR:
        case CRYPTO_ECC_CURVE_NAME_STR:
            ret = key->getAsyKeySpecString == NULL ? HCF_INVALID_PARAMS :
                key->getAsyKeySpecString((HcfPriKey *)key, (AsyKeySpecItem)item, &returnStr);
            if (ret != HCF_SUCCESS) {
                break;
            }
            value->data = (uint8_t *)returnStr;
            value->len = strlen(returnStr);
            break;
        default:
            ret = key->getAsyKeySpecBigInteger == NULL ? HCF_INVALID_PARAMS :
                key->getAsyKeySpecBigInteger((HcfPriKey *)key, (AsyKeySpecItem)item, &bigIntValue);
            if (ret != HCF_SUCCESS) {
                break;
            }
            value->data = (uint8_t *)bigIntValue.data;
            value->len = (size_t)bigIntValue.len;
            ReverseUint8Arr(value->data, value->len);
            break;
    }
    return GetOhCryptoErrCodeNew(ret);
}

OH_Crypto_ErrCode OH_CryptoPrivKey_GetParam(OH_CryptoPrivKey *key, CryptoAsymKey_ParamType item,
    Crypto_DataBlob *value)
{
    return CryptoPrivKeyGetParam(key, item, value);
}

static OH_Crypto_ErrCode CryptoAsymKeySpecGenEcCommonParamsSpec(const char *curveName, OH_CryptoAsymKeySpec **spec)
{
    if ((curveName == NULL) || (spec == NULL)) {
        return CRYPTO_PARAMETER_CHECK_FAILED;
    }

    HcfResult ret = HcfEccKeyUtilCreate(curveName, (HcfEccCommParamsSpec **)spec);
    return GetOhCryptoErrCodeNew(ret);
}

OH_Crypto_ErrCode OH_CryptoAsymKeySpec_GenEcCommonParamsSpec(const char *curveName, OH_CryptoAsymKeySpec **spec)
{
    return CryptoAsymKeySpecGenEcCommonParamsSpec(curveName, spec);
}

static OH_Crypto_ErrCode CryptoAsymKeySpecGenDhCommonParamsSpec(int pLen, int skLen, OH_CryptoAsymKeySpec **spec)
{
    if (spec == NULL) {
        return CRYPTO_PARAMETER_CHECK_FAILED;
    }
    HcfResult ret = HcfDhKeyUtilCreate(pLen, skLen, (HcfDhCommParamsSpec **)spec);
    return GetOhCryptoErrCodeNew(ret);
}

OH_Crypto_ErrCode OH_CryptoAsymKeySpec_GenDhCommonParamsSpec(int pLen, int skLen, OH_CryptoAsymKeySpec **spec)
{
    return CryptoAsymKeySpecGenDhCommonParamsSpec(pLen, skLen, spec);
}

typedef struct {
    CryptoAsymKeySpec_Type type;
    uint32_t memSize;
} OH_CryptoAsymKeySpecInfo;

typedef struct {
    HcfAlgValue algo;
    OH_CryptoAsymKeySpecInfo *specInfo;
    uint32_t specInfoSize;
} OH_CryptoAsymKeySpecInfoMap;

static OH_CryptoAsymKeySpecInfo g_rsaSpecInfo[] = {
    {CRYPTO_ASYM_KEY_PUBLIC_KEY_SPEC, sizeof(HcfRsaPubKeyParamsSpec)},
    {CRYPTO_ASYM_KEY_KEY_PAIR_SPEC, sizeof(HcfRsaKeyPairParamsSpec)},
};

static OH_CryptoAsymKeySpecInfo g_dsaSpecInfo[] = {
    {CRYPTO_ASYM_KEY_COMMON_PARAMS_SPEC, sizeof(HcfDsaCommParamsSpec)},
    {CRYPTO_ASYM_KEY_PUBLIC_KEY_SPEC, sizeof(HcfDsaPubKeyParamsSpec)},
    {CRYPTO_ASYM_KEY_KEY_PAIR_SPEC, sizeof(HcfDsaKeyPairParamsSpec)},
};

static OH_CryptoAsymKeySpecInfo g_eccSpecInfo[] = {
    {CRYPTO_ASYM_KEY_COMMON_PARAMS_SPEC, sizeof(HcfEccCommParamsSpec)},
    {CRYPTO_ASYM_KEY_PRIVATE_KEY_SPEC, sizeof(HcfEccPriKeyParamsSpec)},
    {CRYPTO_ASYM_KEY_PUBLIC_KEY_SPEC, sizeof(HcfEccPubKeyParamsSpec)},
    {CRYPTO_ASYM_KEY_KEY_PAIR_SPEC, sizeof(HcfEccKeyPairParamsSpec)},
};

static OH_CryptoAsymKeySpecInfo g_dhSpecInfo[] = {
    {CRYPTO_ASYM_KEY_COMMON_PARAMS_SPEC, sizeof(HcfDhCommParamsSpec)},
    {CRYPTO_ASYM_KEY_PRIVATE_KEY_SPEC, sizeof(HcfDhPriKeyParamsSpec)},
    {CRYPTO_ASYM_KEY_PUBLIC_KEY_SPEC, sizeof(HcfDhPubKeyParamsSpec)},
    {CRYPTO_ASYM_KEY_KEY_PAIR_SPEC, sizeof(HcfDhKeyPairParamsSpec)},
};

static OH_CryptoAsymKeySpecInfo g_alg25519SpecInfo[] = {
    {CRYPTO_ASYM_KEY_PRIVATE_KEY_SPEC, sizeof(HcfAlg25519PriKeyParamsSpec)},
    {CRYPTO_ASYM_KEY_PUBLIC_KEY_SPEC, sizeof(HcfAlg25519PubKeyParamsSpec)},
    {CRYPTO_ASYM_KEY_KEY_PAIR_SPEC, sizeof(HcfAlg25519KeyPairParamsSpec)},
};

static OH_CryptoAsymKeySpecInfoMap g_asymKeySpecInfoMap[] = {
    {HCF_ALG_RSA, g_rsaSpecInfo, sizeof(g_rsaSpecInfo) / sizeof(g_rsaSpecInfo[0])},
    {HCF_ALG_DSA, g_dsaSpecInfo, sizeof(g_dsaSpecInfo) / sizeof(g_dsaSpecInfo[0])},
    {HCF_ALG_SM2, g_eccSpecInfo, sizeof(g_eccSpecInfo) / sizeof(g_eccSpecInfo[0])},
    {HCF_ALG_ECC, g_eccSpecInfo, sizeof(g_eccSpecInfo) / sizeof(g_eccSpecInfo[0])},
    {HCF_ALG_DH, g_dhSpecInfo, sizeof(g_dhSpecInfo) / sizeof(g_dhSpecInfo[0])},
    {HCF_ALG_ED25519, g_alg25519SpecInfo, sizeof(g_alg25519SpecInfo) / sizeof(g_alg25519SpecInfo[0])},
    {HCF_ALG_X25519, g_alg25519SpecInfo, sizeof(g_alg25519SpecInfo) / sizeof(g_alg25519SpecInfo[0])},
};

static OH_Crypto_ErrCode CreateAsymKeySpec(const char *algoName, CryptoAsymKeySpec_Type type, uint32_t memSize,
    OH_CryptoAsymKeySpec **spec)
{
    OH_CryptoAsymKeySpec *tmpSpec = (OH_CryptoAsymKeySpec *)HcfMalloc(memSize, 0);
    if (tmpSpec == NULL) {
        return CRYPTO_MEMORY_ERROR;
    }
    char *algName = (char *)HcfMalloc(strlen(algoName) + 1, 0);
    if (algName == NULL) {
        HcfFree(tmpSpec);
        tmpSpec = NULL;
        return CRYPTO_MEMORY_ERROR;
    }
    (void)memcpy_s(algName, strlen(algoName), algoName, strlen(algoName));
    tmpSpec->specType = (HcfAsyKeySpecType)type;
    tmpSpec->algName = algName;
    *spec = tmpSpec;
    return CRYPTO_SUCCESS;
}

static const OH_CryptoAsymKeySpecInfoMap *FindAsymKeySpecInfoMapByAlgoName(const char *algoName)
{
    HcfAsyKeyGenParams params = { 0 };
    HcfResult ret = ParseAlgNameToParams(algoName, &params);
    if (ret != HCF_SUCCESS) {
        return NULL;
    }
    for (uint32_t i = 0; i < (sizeof(g_asymKeySpecInfoMap) / sizeof(OH_CryptoAsymKeySpecInfoMap)); ++i) {
        if (g_asymKeySpecInfoMap[i].algo == params.algo) {
            return &g_asymKeySpecInfoMap[i];
        }
    }
    return NULL;
}

static OH_Crypto_ErrCode CryptoAsymKeySpecCreate(const char *algoName, CryptoAsymKeySpec_Type type,
    OH_CryptoAsymKeySpec **spec)
{
    if ((algoName == NULL) || (spec == NULL)) {
        return CRYPTO_PARAMETER_CHECK_FAILED;
    }
    const OH_CryptoAsymKeySpecInfoMap *infoMap = FindAsymKeySpecInfoMapByAlgoName(algoName);
    if (infoMap == NULL) {
        return CRYPTO_PARAMETER_CHECK_FAILED;
    }
    for (uint32_t i = 0; i < infoMap->specInfoSize; ++i) {
        if (infoMap->specInfo[i].type == type) {
            return CreateAsymKeySpec(algoName, type, infoMap->specInfo[i].memSize, spec);
        }
    }
    return CRYPTO_PARAMETER_CHECK_FAILED;
}

OH_Crypto_ErrCode OH_CryptoAsymKeySpec_Create(const char *algoName, CryptoAsymKeySpec_Type type,
    OH_CryptoAsymKeySpec **spec)
{
    return CryptoAsymKeySpecCreate(algoName, type, spec);
}

static OH_Crypto_ErrCode SetDataBlob(uint8_t **dest, uint32_t *destLen, Crypto_DataBlob *value)
{
    if (value == NULL || value->data == NULL || value->len == 0) {
        return CRYPTO_PARAMETER_CHECK_FAILED;
    }
    uint8_t *tmp = (uint8_t *)HcfMalloc(value->len, 0);
    if (tmp == NULL) {
        return CRYPTO_MEMORY_ERROR;
    }
    (void)memcpy_s(tmp, value->len, value->data, value->len);
    HcfFree(*dest);
    *dest = NULL;
    *dest = tmp;
    *destLen = value->len;
    ReverseUint8Arr(*dest, *destLen);
    return CRYPTO_SUCCESS;
}

static OH_Crypto_ErrCode GetDataBlob(const uint8_t *src, uint32_t srcLen, Crypto_DataBlob *value)
{
    if (src == NULL || srcLen == 0) {
        return CRYPTO_PARAMETER_CHECK_FAILED;
    }
    value->data = (uint8_t *)HcfMalloc(srcLen, 0);
    if (value->data == NULL) {
        return CRYPTO_MEMORY_ERROR;
    }
    (void)memcpy_s(value->data, srcLen, src, srcLen);
    value->len = srcLen;
    ReverseUint8Arr(value->data, value->len);
    return CRYPTO_SUCCESS;
}

static OH_Crypto_ErrCode SetDsaCommSpec(HcfDsaCommParamsSpec *spec, CryptoAsymKey_ParamType type,
    Crypto_DataBlob *value)
{
    switch (type) {
        case CRYPTO_DSA_P_DATABLOB:
            return SetDataBlob(&(spec->p.data), &(spec->p.len), value);
        case CRYPTO_DSA_Q_DATABLOB:
            return SetDataBlob(&(spec->q.data), &(spec->q.len), value);
        case CRYPTO_DSA_G_DATABLOB:
            return SetDataBlob(&(spec->g.data), &(spec->g.len), value);
        default:
            return CRYPTO_PARAMETER_CHECK_FAILED;
    }
}

static OH_Crypto_ErrCode SetDsaPubKeySpec(HcfDsaPubKeyParamsSpec *spec, CryptoAsymKey_ParamType type,
    Crypto_DataBlob *value)
{
    switch (type) {
        case CRYPTO_DSA_PK_DATABLOB:
            return SetDataBlob(&(spec->pk.data), &(spec->pk.len), value);
        default:
            return CRYPTO_PARAMETER_CHECK_FAILED;
    }
}

static OH_Crypto_ErrCode SetDsaKeyPairSpec(HcfDsaKeyPairParamsSpec *spec, CryptoAsymKey_ParamType type,
    Crypto_DataBlob *value)
{
    switch (type) {
        case CRYPTO_DSA_SK_DATABLOB:
            return SetDataBlob(&(spec->sk.data), &(spec->sk.len), value);
        case CRYPTO_DSA_PK_DATABLOB:
            return SetDataBlob(&(spec->pk.data), &(spec->pk.len), value);
        default:
            return CRYPTO_PARAMETER_CHECK_FAILED;
    }
}

static OH_Crypto_ErrCode SetDsaSpec(OH_CryptoAsymKeySpec *spec, CryptoAsymKey_ParamType type, Crypto_DataBlob *value)
{
    if (SetDsaCommSpec((HcfDsaCommParamsSpec *)spec, type, value) == CRYPTO_SUCCESS) {
        return CRYPTO_SUCCESS;
    }
    switch (spec->specType) {
        case HCF_PUBLIC_KEY_SPEC:
            return SetDsaPubKeySpec((HcfDsaPubKeyParamsSpec *)spec, type, value);
        case HCF_KEY_PAIR_SPEC:
            return SetDsaKeyPairSpec((HcfDsaKeyPairParamsSpec *)spec, type, value);
        default:
            return CRYPTO_PARAMETER_CHECK_FAILED;
    }
}

static OH_Crypto_ErrCode SetRsaCommSpec(HcfRsaCommParamsSpec *spec, CryptoAsymKey_ParamType type,
    Crypto_DataBlob *value)
{
    switch (type) {
        case CRYPTO_RSA_N_DATABLOB:
            return SetDataBlob(&(spec->n.data), &(spec->n.len), value);
        default:
            return CRYPTO_PARAMETER_CHECK_FAILED;
    }
}

static OH_Crypto_ErrCode SetRsaPubKeySpec(HcfRsaPubKeyParamsSpec *spec, CryptoAsymKey_ParamType type,
    Crypto_DataBlob *value)
{
    switch (type) {
        case CRYPTO_RSA_E_DATABLOB:
            return SetDataBlob(&(spec->pk.data), &(spec->pk.len), value);
        default:
            return CRYPTO_PARAMETER_CHECK_FAILED;
    }
}

static OH_Crypto_ErrCode SetRsaKeyPairSpec(HcfRsaKeyPairParamsSpec *spec, CryptoAsymKey_ParamType type,
    Crypto_DataBlob *value)
{
    switch (type) {
        case CRYPTO_RSA_D_DATABLOB:
            return SetDataBlob(&(spec->sk.data), &(spec->sk.len), value);
        case CRYPTO_RSA_E_DATABLOB:
            return SetDataBlob(&(spec->pk.data), &(spec->pk.len), value);
        default:
            return CRYPTO_PARAMETER_CHECK_FAILED;
    }
}

static OH_Crypto_ErrCode SetRsaSpec(OH_CryptoAsymKeySpec *spec, CryptoAsymKey_ParamType type, Crypto_DataBlob *value)
{
    if (SetRsaCommSpec((HcfRsaCommParamsSpec *)spec, type, value) == CRYPTO_SUCCESS) {
        return CRYPTO_SUCCESS;
    }
    switch (spec->specType) {
        case HCF_PUBLIC_KEY_SPEC:
            return SetRsaPubKeySpec((HcfRsaPubKeyParamsSpec *)spec, type, value);
        case HCF_KEY_PAIR_SPEC:
            return SetRsaKeyPairSpec((HcfRsaKeyPairParamsSpec *)spec, type, value);
        default:
            return CRYPTO_PARAMETER_CHECK_FAILED;
    }
}

static OH_Crypto_ErrCode SetEccField(HcfEccCommParamsSpec *spec, Crypto_DataBlob *value)
{
    HcfECFieldFp *field = (HcfECFieldFp *)HcfMalloc(sizeof(HcfECFieldFp), 0);
    if (field == NULL) {
        return CRYPTO_MEMORY_ERROR;
    }
    char *fieldType = "Fp";
    size_t fieldTypeLen = strlen(fieldType);
    field->base.fieldType = (char *)HcfMalloc(fieldTypeLen + 1, 0);
    if (field->base.fieldType == NULL) {
        HcfFree(field);
        field = NULL;
        return CRYPTO_MEMORY_ERROR;
    }
    (void)memcpy_s(field->base.fieldType, fieldTypeLen, fieldType, fieldTypeLen);
    field->p.data = (uint8_t *)HcfMalloc(value->len, 0);
    if (field->p.data == NULL) {
        HcfFree(field->base.fieldType);
        field->base.fieldType = NULL;
        HcfFree(field);
        field = NULL;
        return CRYPTO_MEMORY_ERROR;
    }
    (void)memcpy_s(field->p.data, value->len, value->data, value->len);
    field->p.len = value->len;
    ReverseUint8Arr(field->p.data, field->p.len);
    spec->field = (HcfECField *)field;
    return CRYPTO_SUCCESS;
}

static OH_Crypto_ErrCode SetEccCommSpec(HcfEccCommParamsSpec *spec, CryptoAsymKey_ParamType type,
    Crypto_DataBlob *value)
{
    switch (type) {
        case CRYPTO_ECC_FP_P_DATABLOB:
            return SetEccField(spec, value);
        case CRYPTO_ECC_A_DATABLOB:
            return SetDataBlob(&(spec->a.data), &(spec->a.len), value);
        case CRYPTO_ECC_B_DATABLOB:
            return SetDataBlob(&(spec->b.data), &(spec->b.len), value);
        case CRYPTO_ECC_G_X_DATABLOB:
            return SetDataBlob(&(spec->g.x.data), &(spec->g.x.len), value);
        case CRYPTO_ECC_G_Y_DATABLOB:
            return SetDataBlob(&(spec->g.y.data), &(spec->g.y.len), value);
        case CRYPTO_ECC_N_DATABLOB:
            return SetDataBlob(&(spec->n.data), &(spec->n.len), value);
        case CRYPTO_ECC_H_INT:
            if (value->len != sizeof(spec->h)) {
                return CRYPTO_PARAMETER_CHECK_FAILED;
            }
            uint32_t tmp = BigEndianArrToUint32(value->data, value->len);
            if (tmp > INT32_MAX) {
                return CRYPTO_PARAMETER_CHECK_FAILED;
            }
            spec->h = (int32_t)tmp;
            break;
        default:
            return CRYPTO_PARAMETER_CHECK_FAILED;
    }
    return CRYPTO_SUCCESS;
}

static OH_Crypto_ErrCode SetEccPriSpec(HcfEccPriKeyParamsSpec *spec, CryptoAsymKey_ParamType type,
    Crypto_DataBlob *value)
{
    switch (type) {
        case CRYPTO_ECC_SK_DATABLOB:
            return SetDataBlob(&(spec->sk.data), &(spec->sk.len), value);
        default:
            return CRYPTO_PARAMETER_CHECK_FAILED;
    }
}

static OH_Crypto_ErrCode SetEccPubKeySpec(HcfEccPubKeyParamsSpec *spec, CryptoAsymKey_ParamType type,
    Crypto_DataBlob *value)
{
    switch (type) {
        case CRYPTO_ECC_PK_X_DATABLOB:
            return SetDataBlob(&(spec->pk.x.data), &(spec->pk.x.len), value);
        case CRYPTO_ECC_PK_Y_DATABLOB:
            return SetDataBlob(&(spec->pk.y.data), &(spec->pk.y.len), value);
        default:
            return CRYPTO_PARAMETER_CHECK_FAILED;
    }
}

static OH_Crypto_ErrCode SetEccKeyPairSpec(HcfEccKeyPairParamsSpec *spec, CryptoAsymKey_ParamType type,
    Crypto_DataBlob *value)
{
    switch (type) {
        case CRYPTO_ECC_SK_DATABLOB:
            return SetDataBlob(&(spec->sk.data), &(spec->sk.len), value);
        case CRYPTO_ECC_PK_X_DATABLOB:
            return SetDataBlob(&(spec->pk.x.data), &(spec->pk.x.len), value);
        case CRYPTO_ECC_PK_Y_DATABLOB:
            return SetDataBlob(&(spec->pk.y.data), &(spec->pk.y.len), value);
        default:
            return CRYPTO_PARAMETER_CHECK_FAILED;
    }
}

static OH_Crypto_ErrCode SetEccSpec(OH_CryptoAsymKeySpec *spec, CryptoAsymKey_ParamType type, Crypto_DataBlob *value)
{
    if (SetEccCommSpec((HcfEccCommParamsSpec *)spec, type, value) == CRYPTO_SUCCESS) {
        return CRYPTO_SUCCESS;
    }
    switch (spec->specType) {
        case HCF_PRIVATE_KEY_SPEC:
            return SetEccPriSpec((HcfEccPriKeyParamsSpec *)spec, type, value);
        case HCF_PUBLIC_KEY_SPEC:
            return SetEccPubKeySpec((HcfEccPubKeyParamsSpec *)spec, type, value);
        case HCF_KEY_PAIR_SPEC:
            return SetEccKeyPairSpec((HcfEccKeyPairParamsSpec *)spec, type, value);
        default:
            return CRYPTO_PARAMETER_CHECK_FAILED;
    }
}

static OH_Crypto_ErrCode SetDhCommSpec(HcfDhCommParamsSpec *spec, CryptoAsymKey_ParamType type, Crypto_DataBlob *value)
{
    switch (type) {
        case CRYPTO_DH_P_DATABLOB:
            return SetDataBlob(&(spec->p.data), &(spec->p.len), value);
        case CRYPTO_DH_G_DATABLOB:
            return SetDataBlob(&(spec->g.data), &(spec->g.len), value);
        case CRYPTO_DH_L_INT:
            if (value->len != sizeof(spec->length)) {
                return CRYPTO_PARAMETER_CHECK_FAILED;
            }
            uint32_t tmp = BigEndianArrToUint32(value->data, value->len);
            if (tmp > INT32_MAX) {
                return CRYPTO_PARAMETER_CHECK_FAILED;
            }
            spec->length = (int)tmp;
            break;
        default:
            return CRYPTO_PARAMETER_CHECK_FAILED;
    }
    return CRYPTO_SUCCESS;
}

static OH_Crypto_ErrCode SetDhPriSpec(HcfDhPriKeyParamsSpec *spec, CryptoAsymKey_ParamType type, Crypto_DataBlob *value)
{
    switch (type) {
        case CRYPTO_DH_SK_DATABLOB:
            return SetDataBlob(&(spec->sk.data), &(spec->sk.len), value);
        default:
            return CRYPTO_PARAMETER_CHECK_FAILED;
    }
}

static OH_Crypto_ErrCode SetDhPubKeySpec(HcfDhPubKeyParamsSpec *spec, CryptoAsymKey_ParamType type,
    Crypto_DataBlob *value)
{
    switch (type) {
        case CRYPTO_DH_PK_DATABLOB:
            return SetDataBlob(&(spec->pk.data), &(spec->pk.len), value);
        default:
            return CRYPTO_PARAMETER_CHECK_FAILED;
    }
}

static OH_Crypto_ErrCode SetDhKeyPairSpec(HcfDhKeyPairParamsSpec *spec, CryptoAsymKey_ParamType type,
    Crypto_DataBlob *value)
{
    switch (type) {
        case CRYPTO_DH_SK_DATABLOB:
            return SetDataBlob(&(spec->sk.data), &(spec->sk.len), value);
        case CRYPTO_DH_PK_DATABLOB:
            return SetDataBlob(&(spec->pk.data), &(spec->pk.len), value);
        default:
            return CRYPTO_PARAMETER_CHECK_FAILED;
    }
}

static OH_Crypto_ErrCode SetDhSpec(OH_CryptoAsymKeySpec *spec, CryptoAsymKey_ParamType type, Crypto_DataBlob *value)
{
    if (SetDhCommSpec((HcfDhCommParamsSpec *)spec, type, value) == CRYPTO_SUCCESS) {
        return CRYPTO_SUCCESS;
    }
    switch (spec->specType) {
        case HCF_PRIVATE_KEY_SPEC:
            return SetDhPriSpec((HcfDhPriKeyParamsSpec *)spec, type, value);
        case HCF_PUBLIC_KEY_SPEC:
            return SetDhPubKeySpec((HcfDhPubKeyParamsSpec *)spec, type, value);
        case HCF_KEY_PAIR_SPEC:
            return SetDhKeyPairSpec((HcfDhKeyPairParamsSpec *)spec, type, value);
        default:
            return CRYPTO_PARAMETER_CHECK_FAILED;
    }
}

static OH_Crypto_ErrCode SetAlg25519PriSpec(HcfAlg25519PriKeyParamsSpec *spec, CryptoAsymKey_ParamType type,
    Crypto_DataBlob *value)
{
    switch (type) {
        case CRYPTO_ED25519_SK_DATABLOB:
        case CRYPTO_X25519_SK_DATABLOB:
            return SetDataBlob(&(spec->sk.data), &(spec->sk.len), value);
        default:
            return CRYPTO_PARAMETER_CHECK_FAILED;
    }
}

static OH_Crypto_ErrCode SetAlg25519PubKeySpec(HcfAlg25519PubKeyParamsSpec *spec, CryptoAsymKey_ParamType type,
    Crypto_DataBlob *value)
{
    switch (type) {
        case CRYPTO_ED25519_PK_DATABLOB:
        case CRYPTO_X25519_PK_DATABLOB:
            return SetDataBlob(&(spec->pk.data), &(spec->pk.len), value);
        default:
            return CRYPTO_PARAMETER_CHECK_FAILED;
    }
}

static OH_Crypto_ErrCode SetAlg25519KeyPairSpec(HcfAlg25519KeyPairParamsSpec *spec, CryptoAsymKey_ParamType type,
    Crypto_DataBlob *value)
{
    switch (type) {
        case CRYPTO_ED25519_SK_DATABLOB:
        case CRYPTO_X25519_SK_DATABLOB:
            return SetDataBlob(&(spec->sk.data), &(spec->sk.len), value);
        case CRYPTO_ED25519_PK_DATABLOB:
        case CRYPTO_X25519_PK_DATABLOB:
            return SetDataBlob(&(spec->pk.data), &(spec->pk.len), value);
        default:
            return CRYPTO_PARAMETER_CHECK_FAILED;
    }
}

static OH_Crypto_ErrCode SetAlg25519Spec(OH_CryptoAsymKeySpec *spec, CryptoAsymKey_ParamType type,
    Crypto_DataBlob *value)
{
    switch (spec->specType) {
        case HCF_PRIVATE_KEY_SPEC:
            return SetAlg25519PriSpec((HcfAlg25519PriKeyParamsSpec *)spec, type, value);
        case HCF_PUBLIC_KEY_SPEC:
            return SetAlg25519PubKeySpec((HcfAlg25519PubKeyParamsSpec *)spec, type, value);
        case HCF_KEY_PAIR_SPEC:
            return SetAlg25519KeyPairSpec((HcfAlg25519KeyPairParamsSpec *)spec, type, value);
        default:
            return CRYPTO_PARAMETER_CHECK_FAILED;
    }
}

static OH_Crypto_ErrCode CryptoAsymKeySpecSetParam(OH_CryptoAsymKeySpec *spec, CryptoAsymKey_ParamType type,
    Crypto_DataBlob *value)
{
    if ((spec == NULL) || (value == NULL) || (value->data == NULL) || (value->len == 0)) {
        return CRYPTO_PARAMETER_CHECK_FAILED;
    }

    HcfAsyKeyGenParams params = { 0 };
    HcfResult ret = ParseAlgNameToParams(spec->algName, &params);
    if (ret != HCF_SUCCESS) {
        return GetOhCryptoErrCodeNew(ret);
    }

    switch (params.algo) {
        case HCF_ALG_DSA:
            return SetDsaSpec(spec, type, value);
        case HCF_ALG_RSA:
            return SetRsaSpec(spec, type, value);
        case HCF_ALG_ECC:
        case HCF_ALG_SM2:
            return SetEccSpec(spec, type, value);
        case HCF_ALG_DH:
            return SetDhSpec(spec, type, value);
        case HCF_ALG_ED25519:
        case HCF_ALG_X25519:
            return SetAlg25519Spec(spec, type, value);
        default:
            return CRYPTO_PARAMETER_CHECK_FAILED;
    }
}

OH_Crypto_ErrCode OH_CryptoAsymKeySpec_SetParam(OH_CryptoAsymKeySpec *spec, CryptoAsymKey_ParamType type,
    Crypto_DataBlob *value)
{
    return CryptoAsymKeySpecSetParam(spec, type, value);
}

static OH_Crypto_ErrCode SetDsaCommonSpec(HcfDsaCommParamsSpec *commonParamsSpec, HcfDsaCommParamsSpec *spec)
{
    spec->p.data = (unsigned char *)HcfMalloc(commonParamsSpec->p.len, 0);
    if (spec->p.data == NULL) {
        FreeDsaCommParamsSpec(spec);
        return CRYPTO_MEMORY_ERROR;
    }
    spec->q.data = (unsigned char *)HcfMalloc(commonParamsSpec->q.len, 0);
    if (spec->q.data == NULL) {
        FreeDsaCommParamsSpec(spec);
        return CRYPTO_MEMORY_ERROR;
    }
    spec->g.data = (unsigned char *)HcfMalloc(commonParamsSpec->g.len, 0);
    if (spec->g.data == NULL) {
        FreeDsaCommParamsSpec(spec);
        return CRYPTO_MEMORY_ERROR;
    }
    (void)memcpy_s(spec->p.data, commonParamsSpec->p.len, commonParamsSpec->p.data, commonParamsSpec->p.len);
    (void)memcpy_s(spec->q.data, commonParamsSpec->q.len, commonParamsSpec->q.data, commonParamsSpec->q.len);
    (void)memcpy_s(spec->g.data, commonParamsSpec->g.len, commonParamsSpec->g.data, commonParamsSpec->g.len);
    spec->p.len = commonParamsSpec->p.len;
    spec->q.len = commonParamsSpec->q.len;
    spec->g.len = commonParamsSpec->g.len;
    return CRYPTO_SUCCESS;
}

static OH_Crypto_ErrCode SetEccCommonSpec(HcfEccCommParamsSpec *commonParamsSpec, HcfEccCommParamsSpec *spec)
{
    HcfEccCommParamsSpec eccCommParamsSpec = {};
    HcfResult ret = CopyEccCommonSpec(commonParamsSpec, &eccCommParamsSpec);
    if (ret != HCF_SUCCESS) {
        return GetOhCryptoErrCodeNew(ret);
    }
    spec->field = eccCommParamsSpec.field;
    spec->field->fieldType = eccCommParamsSpec.field->fieldType;
    ((HcfECFieldFp *)(spec->field))->p.data = ((HcfECFieldFp *)(eccCommParamsSpec.field))->p.data;
    ((HcfECFieldFp *)(spec->field))->p.len = ((HcfECFieldFp *)(eccCommParamsSpec.field))->p.len;
    spec->a.data = eccCommParamsSpec.a.data;
    spec->a.len = eccCommParamsSpec.a.len;
    spec->b.data = eccCommParamsSpec.b.data;
    spec->b.len = eccCommParamsSpec.b.len;
    spec->g.x.data = eccCommParamsSpec.g.x.data;
    spec->g.x.len = eccCommParamsSpec.g.x.len;
    spec->g.y.data = eccCommParamsSpec.g.y.data;
    spec->g.y.len = eccCommParamsSpec.g.y.len;
    spec->n.data = eccCommParamsSpec.n.data;
    spec->n.len = eccCommParamsSpec.n.len;
    spec->h = eccCommParamsSpec.h;
    HcfFree(eccCommParamsSpec.base.algName);
    eccCommParamsSpec.base.algName = NULL;
    return CRYPTO_SUCCESS;
}

static OH_Crypto_ErrCode SetDhCommonSpec(HcfDhCommParamsSpec *commonParamsSpec, HcfDhCommParamsSpec *spec)
{
    HcfDhCommParamsSpec dhCommParamsSpec = {};
    HcfResult ret = CopyDhCommonSpec(commonParamsSpec, &dhCommParamsSpec);
    if (ret != HCF_SUCCESS) {
        return GetOhCryptoErrCodeNew(ret);
    }
    spec->p.data = dhCommParamsSpec.p.data;
    spec->p.len = dhCommParamsSpec.p.len;
    spec->g.data = dhCommParamsSpec.g.data;
    spec->g.len = dhCommParamsSpec.g.len;
    spec->length = dhCommParamsSpec.length;
    HcfFree(dhCommParamsSpec.base.algName);
    dhCommParamsSpec.base.algName = NULL;
    return CRYPTO_SUCCESS;
}

static OH_Crypto_ErrCode CryptoAsymKeySpecSetCommonParamsSpec(OH_CryptoAsymKeySpec *spec,
    OH_CryptoAsymKeySpec *commonParamsSpec)
{
    if ((spec == NULL) || (commonParamsSpec == NULL) || (commonParamsSpec->specType != HCF_COMMON_PARAMS_SPEC)) {
        return CRYPTO_PARAMETER_CHECK_FAILED;
    }
    HcfAsyKeyGenParams params = { 0 };
    HcfResult ret = ParseAlgNameToParams(spec->algName, &params);
    if (ret != HCF_SUCCESS) {
        return GetOhCryptoErrCodeNew(ret);
    }

    switch (params.algo) {
        case HCF_ALG_DSA:
            return SetDsaCommonSpec((HcfDsaCommParamsSpec *)commonParamsSpec, (HcfDsaCommParamsSpec *)spec);
        case HCF_ALG_ECC:
        case HCF_ALG_SM2:
            return SetEccCommonSpec((HcfEccCommParamsSpec *)commonParamsSpec, (HcfEccCommParamsSpec *)spec);
        case HCF_ALG_DH:
            return SetDhCommonSpec((HcfDhCommParamsSpec *)commonParamsSpec, (HcfDhCommParamsSpec *)spec);
        default:
            return CRYPTO_PARAMETER_CHECK_FAILED;
    }
}

OH_Crypto_ErrCode OH_CryptoAsymKeySpec_SetCommonParamsSpec(OH_CryptoAsymKeySpec *spec,
    OH_CryptoAsymKeySpec *commonParamsSpec)
{
    return CryptoAsymKeySpecSetCommonParamsSpec(spec, commonParamsSpec);
}

static OH_Crypto_ErrCode GetDsaCommSpec(HcfDsaCommParamsSpec *spec, CryptoAsymKey_ParamType type,
    Crypto_DataBlob *value)
{
    switch (type) {
        case CRYPTO_DSA_P_DATABLOB:
            return GetDataBlob(spec->p.data, spec->p.len, value);
        case CRYPTO_DSA_Q_DATABLOB:
            return GetDataBlob(spec->q.data, spec->q.len, value);
        case CRYPTO_DSA_G_DATABLOB:
            return GetDataBlob(spec->g.data, spec->g.len, value);
        default:
            return CRYPTO_PARAMETER_CHECK_FAILED;
    }
}

static OH_Crypto_ErrCode GetDsaPubKeySpec(HcfDsaPubKeyParamsSpec *spec, CryptoAsymKey_ParamType type,
    Crypto_DataBlob *value)
{
    switch (type) {
        case CRYPTO_DSA_PK_DATABLOB:
            return GetDataBlob(spec->pk.data, spec->pk.len, value);
        default:
            return CRYPTO_PARAMETER_CHECK_FAILED;
    }
}

static OH_Crypto_ErrCode GetDsaKeyPairSpec(HcfDsaKeyPairParamsSpec *spec, CryptoAsymKey_ParamType type,
    Crypto_DataBlob *value)
{
    switch (type) {
        case CRYPTO_DSA_SK_DATABLOB:
            return GetDataBlob(spec->sk.data, spec->sk.len, value);
        case CRYPTO_DSA_PK_DATABLOB:
            return GetDataBlob(spec->pk.data, spec->pk.len, value);
        default:
            return CRYPTO_PARAMETER_CHECK_FAILED;
    }
}

static OH_Crypto_ErrCode GetDsaSpec(OH_CryptoAsymKeySpec *spec, CryptoAsymKey_ParamType type, Crypto_DataBlob *value)
{
    if (GetDsaCommSpec((HcfDsaCommParamsSpec *)spec, type, value) == CRYPTO_SUCCESS) {
        return CRYPTO_SUCCESS;
    }
    switch (spec->specType) {
        case HCF_PUBLIC_KEY_SPEC:
            return GetDsaPubKeySpec((HcfDsaPubKeyParamsSpec *)spec, type, value);
        case HCF_KEY_PAIR_SPEC:
            return GetDsaKeyPairSpec((HcfDsaKeyPairParamsSpec *)spec, type, value);
        default:
            return CRYPTO_PARAMETER_CHECK_FAILED;
    }
}

static OH_Crypto_ErrCode GetRsaCommSpec(HcfRsaCommParamsSpec *spec, CryptoAsymKey_ParamType type,
    Crypto_DataBlob *value)
{
    switch (type) {
        case CRYPTO_RSA_N_DATABLOB:
            return GetDataBlob(spec->n.data, spec->n.len, value);
        default:
            return CRYPTO_PARAMETER_CHECK_FAILED;
    }
}

static OH_Crypto_ErrCode GetRsaPubKeySpec(HcfRsaPubKeyParamsSpec *spec, CryptoAsymKey_ParamType type,
    Crypto_DataBlob *value)
{
    switch (type) {
        case CRYPTO_RSA_E_DATABLOB:
            return GetDataBlob(spec->pk.data, spec->pk.len, value);
        default:
            return CRYPTO_PARAMETER_CHECK_FAILED;
    }
}

static OH_Crypto_ErrCode GetRsaKeyPairSpec(HcfRsaKeyPairParamsSpec *spec, CryptoAsymKey_ParamType type,
    Crypto_DataBlob *value)
{
    switch (type) {
        case CRYPTO_RSA_D_DATABLOB:
            return GetDataBlob(spec->sk.data, spec->sk.len, value);
        case CRYPTO_RSA_E_DATABLOB:
            return GetDataBlob(spec->pk.data, spec->pk.len, value);
        default:
            return CRYPTO_PARAMETER_CHECK_FAILED;
    }
}

static OH_Crypto_ErrCode GetRsaSpec(OH_CryptoAsymKeySpec *spec, CryptoAsymKey_ParamType type, Crypto_DataBlob *value)
{
    if (GetRsaCommSpec((HcfRsaCommParamsSpec *)spec, type, value) == CRYPTO_SUCCESS) {
        return CRYPTO_SUCCESS;
    }
    switch (spec->specType) {
        case HCF_PUBLIC_KEY_SPEC:
            return GetRsaPubKeySpec((HcfRsaPubKeyParamsSpec *)spec, type, value);
        case HCF_KEY_PAIR_SPEC:
            return GetRsaKeyPairSpec((HcfRsaKeyPairParamsSpec *)spec, type, value);
        default:
            return CRYPTO_PARAMETER_CHECK_FAILED;
    }
}

static OH_Crypto_ErrCode GetEccField(HcfEccCommParamsSpec *spec, Crypto_DataBlob *value)
{
    if ((spec->field == NULL) || (((HcfECFieldFp *)(spec->field))->p.data == NULL)) {
        return CRYPTO_PARAMETER_CHECK_FAILED;
    }
    return GetDataBlob(((HcfECFieldFp *)(spec->field))->p.data, ((HcfECFieldFp *)(spec->field))->p.len, value);
}

static OH_Crypto_ErrCode GetEccCommSpec(HcfEccCommParamsSpec *spec, CryptoAsymKey_ParamType type,
    Crypto_DataBlob *value)
{
    switch (type) {
        case CRYPTO_ECC_FP_P_DATABLOB:
            return GetEccField(spec, value);
        case CRYPTO_ECC_A_DATABLOB:
            return GetDataBlob(spec->a.data, spec->a.len, value);
        case CRYPTO_ECC_B_DATABLOB:
            return GetDataBlob(spec->b.data, spec->b.len, value);
        case CRYPTO_ECC_G_X_DATABLOB:
            return GetDataBlob(spec->g.x.data, spec->g.x.len, value);
        case CRYPTO_ECC_G_Y_DATABLOB:
            return GetDataBlob(spec->g.y.data, spec->g.y.len, value);
        case CRYPTO_ECC_N_DATABLOB:
            return GetDataBlob(spec->n.data, spec->n.len, value);
        case CRYPTO_ECC_H_INT:
            value->data = (uint8_t *)HcfMalloc(sizeof(spec->h), 0);
            if (value->data == NULL) {
                return CRYPTO_MEMORY_ERROR;
            }
            value->len = sizeof(spec->h);
            if (spec->h < 0) {
                HcfFree(value->data);
                value->data = NULL;
                return CRYPTO_PARAMETER_CHECK_FAILED;
            }
            uint32_t tmp = (uint32_t)spec->h;
            Uint32TobigEndianArr(tmp, value->data, value->len);
            break;
        default:
            return CRYPTO_PARAMETER_CHECK_FAILED;
    }
    return CRYPTO_SUCCESS;
}

static OH_Crypto_ErrCode GetEccPriSpec(HcfEccPriKeyParamsSpec *spec, CryptoAsymKey_ParamType type,
    Crypto_DataBlob *value)
{
    switch (type) {
        case CRYPTO_ECC_SK_DATABLOB:
            return GetDataBlob(spec->sk.data, spec->sk.len, value);
        default:
            return CRYPTO_PARAMETER_CHECK_FAILED;
    }
}

static OH_Crypto_ErrCode GetEccPubKeySpec(HcfEccPubKeyParamsSpec *spec, CryptoAsymKey_ParamType type,
    Crypto_DataBlob *value)
{
    switch (type) {
        case CRYPTO_ECC_PK_X_DATABLOB:
            return GetDataBlob(spec->pk.x.data, spec->pk.x.len, value);
        case CRYPTO_ECC_PK_Y_DATABLOB:
            return GetDataBlob(spec->pk.y.data, spec->pk.y.len, value);
        default:
            return CRYPTO_PARAMETER_CHECK_FAILED;
    }
}

static OH_Crypto_ErrCode GetEccKeyPairSpec(HcfEccKeyPairParamsSpec *spec, CryptoAsymKey_ParamType type,
    Crypto_DataBlob *value)
{
    switch (type) {
        case CRYPTO_ECC_SK_DATABLOB:
            return GetDataBlob(spec->sk.data, spec->sk.len, value);
        case CRYPTO_ECC_PK_X_DATABLOB:
            return GetDataBlob(spec->pk.x.data, spec->pk.x.len, value);
        case CRYPTO_ECC_PK_Y_DATABLOB:
            return GetDataBlob(spec->pk.y.data, spec->pk.y.len, value);
        default:
            return CRYPTO_PARAMETER_CHECK_FAILED;
    }
}

static OH_Crypto_ErrCode GetEccSpec(OH_CryptoAsymKeySpec *spec, CryptoAsymKey_ParamType type, Crypto_DataBlob *value)
{
    if (GetEccCommSpec((HcfEccCommParamsSpec *)spec, type, value) == CRYPTO_SUCCESS) {
        return CRYPTO_SUCCESS;
    }
    switch (spec->specType) {
        case HCF_PRIVATE_KEY_SPEC:
            return GetEccPriSpec((HcfEccPriKeyParamsSpec *)spec, type, value);
        case HCF_PUBLIC_KEY_SPEC:
            return GetEccPubKeySpec((HcfEccPubKeyParamsSpec *)spec, type, value);
        case HCF_KEY_PAIR_SPEC:
            return GetEccKeyPairSpec((HcfEccKeyPairParamsSpec *)spec, type, value);
        default:
            return CRYPTO_PARAMETER_CHECK_FAILED;
    }
}

static OH_Crypto_ErrCode GetDhCommSpec(HcfDhCommParamsSpec *spec, CryptoAsymKey_ParamType type, Crypto_DataBlob *value)
{
    switch (type) {
        case CRYPTO_DH_P_DATABLOB:
            return GetDataBlob(spec->p.data, spec->p.len, value);
        case CRYPTO_DH_G_DATABLOB:
            return GetDataBlob(spec->g.data, spec->g.len, value);
        case CRYPTO_DH_L_INT:
            value->data = (uint8_t *)HcfMalloc(sizeof(spec->length), 0);
            if (value->data == NULL) {
                return CRYPTO_MEMORY_ERROR;
            }
            value->len = sizeof(spec->length);
            if (spec->length < 0) {
                HcfFree(value->data);
                value->data = NULL;
                return CRYPTO_PARAMETER_CHECK_FAILED;
            }
            uint32_t tmp = (uint32_t)spec->length;
            Uint32TobigEndianArr(tmp, value->data, value->len);
            break;
        default:
            return CRYPTO_PARAMETER_CHECK_FAILED;
    }
    return CRYPTO_SUCCESS;
}

static OH_Crypto_ErrCode GetDhPriSpec(HcfDhPriKeyParamsSpec *spec, CryptoAsymKey_ParamType type, Crypto_DataBlob *value)
{
    switch (type) {
        case CRYPTO_DH_SK_DATABLOB:
            return GetDataBlob(spec->sk.data, spec->sk.len, value);
        default:
            return CRYPTO_PARAMETER_CHECK_FAILED;
    }
}

static OH_Crypto_ErrCode GetDhPubKeySpec(HcfDhPubKeyParamsSpec *spec, CryptoAsymKey_ParamType type,
    Crypto_DataBlob *value)
{
    switch (type) {
        case CRYPTO_DH_PK_DATABLOB:
            return GetDataBlob(spec->pk.data, spec->pk.len, value);
        default:
            return CRYPTO_PARAMETER_CHECK_FAILED;
    }
}

static OH_Crypto_ErrCode GetDhKeyPairSpec(HcfDhKeyPairParamsSpec *spec, CryptoAsymKey_ParamType type,
    Crypto_DataBlob *value)
{
    switch (type) {
        case CRYPTO_DH_SK_DATABLOB:
            return GetDataBlob(spec->sk.data, spec->sk.len, value);
        case CRYPTO_DH_PK_DATABLOB:
            return GetDataBlob(spec->pk.data, spec->pk.len, value);
        default:
            return CRYPTO_PARAMETER_CHECK_FAILED;
    }
}

static OH_Crypto_ErrCode GetDhSpec(OH_CryptoAsymKeySpec *spec, CryptoAsymKey_ParamType type, Crypto_DataBlob *value)
{
    if (GetDhCommSpec((HcfDhCommParamsSpec *)spec, type, value) == CRYPTO_SUCCESS) {
        return CRYPTO_SUCCESS;
    }
    switch (spec->specType) {
        case HCF_PRIVATE_KEY_SPEC:
            return GetDhPriSpec((HcfDhPriKeyParamsSpec *)spec, type, value);
        case HCF_PUBLIC_KEY_SPEC:
            return GetDhPubKeySpec((HcfDhPubKeyParamsSpec *)spec, type, value);
        case HCF_KEY_PAIR_SPEC:
            return GetDhKeyPairSpec((HcfDhKeyPairParamsSpec *)spec, type, value);
        default:
            return CRYPTO_PARAMETER_CHECK_FAILED;
    }
}

static OH_Crypto_ErrCode GetAlg25519PriSpec(HcfAlg25519PriKeyParamsSpec *spec, CryptoAsymKey_ParamType type,
    Crypto_DataBlob *value)
{
    switch (type) {
        case CRYPTO_ED25519_SK_DATABLOB:
        case CRYPTO_X25519_SK_DATABLOB:
            return GetDataBlob(spec->sk.data, spec->sk.len, value);
        default:
            return CRYPTO_PARAMETER_CHECK_FAILED;
    }
}

static OH_Crypto_ErrCode GetAlg25519PubKeySpec(HcfAlg25519PubKeyParamsSpec *spec, CryptoAsymKey_ParamType type,
    Crypto_DataBlob *value)
{
    switch (type) {
        case CRYPTO_ED25519_PK_DATABLOB:
        case CRYPTO_X25519_PK_DATABLOB:
            return GetDataBlob(spec->pk.data, spec->pk.len, value);
        default:
            return CRYPTO_PARAMETER_CHECK_FAILED;
    }
}

static OH_Crypto_ErrCode GetAlg25519KeyPairSpec(HcfAlg25519KeyPairParamsSpec *spec, CryptoAsymKey_ParamType type,
    Crypto_DataBlob *value)
{
    switch (type) {
        case CRYPTO_ED25519_SK_DATABLOB:
        case CRYPTO_X25519_SK_DATABLOB:
            return GetDataBlob(spec->sk.data, spec->sk.len, value);
        case CRYPTO_ED25519_PK_DATABLOB:
        case CRYPTO_X25519_PK_DATABLOB:
            return GetDataBlob(spec->pk.data, spec->pk.len, value);
        default:
            return CRYPTO_PARAMETER_CHECK_FAILED;
    }
}

static OH_Crypto_ErrCode GetAlg25519Spec(OH_CryptoAsymKeySpec *spec, CryptoAsymKey_ParamType type,
    Crypto_DataBlob *value)
{
    switch (spec->specType) {
        case HCF_PRIVATE_KEY_SPEC:
            return GetAlg25519PriSpec((HcfAlg25519PriKeyParamsSpec *)spec, type, value);
        case HCF_PUBLIC_KEY_SPEC:
            return GetAlg25519PubKeySpec((HcfAlg25519PubKeyParamsSpec *)spec, type, value);
        case HCF_KEY_PAIR_SPEC:
            return GetAlg25519KeyPairSpec((HcfAlg25519KeyPairParamsSpec *)spec, type, value);
        default:
            return CRYPTO_PARAMETER_CHECK_FAILED;
    }
}

static OH_Crypto_ErrCode CryptoAsymKeySpecGetParam(OH_CryptoAsymKeySpec *spec, CryptoAsymKey_ParamType type,
    Crypto_DataBlob *value)
{
    if ((spec == NULL) || (value == NULL)) {
        return CRYPTO_PARAMETER_CHECK_FAILED;
    }

    HcfAsyKeyGenParams params = { 0 };
    HcfResult ret = ParseAlgNameToParams(spec->algName, &params);
    if (ret != HCF_SUCCESS) {
        return GetOhCryptoErrCodeNew(ret);
    }

    switch (params.algo) {
        case HCF_ALG_DSA:
            return GetDsaSpec(spec, type, value);
        case HCF_ALG_RSA:
            return GetRsaSpec(spec, type, value);
        case HCF_ALG_ECC:
        case HCF_ALG_SM2:
            return GetEccSpec(spec, type, value);
        case HCF_ALG_DH:
            return GetDhSpec(spec, type, value);
        case HCF_ALG_ED25519:
        case HCF_ALG_X25519:
            return GetAlg25519Spec(spec, type, value);
        default:
            return CRYPTO_PARAMETER_CHECK_FAILED;
    }
}

OH_Crypto_ErrCode OH_CryptoAsymKeySpec_GetParam(OH_CryptoAsymKeySpec *spec, CryptoAsymKey_ParamType type,
    Crypto_DataBlob *value)
{
    return CryptoAsymKeySpecGetParam(spec, type, value);
}

static void CryptoAsymKeySpecDestroy(OH_CryptoAsymKeySpec *spec)
{
    if (spec == NULL) {
        return;
    }
    FreeAsyKeySpec((HcfAsyKeyParamsSpec *)spec);
}

void OH_CryptoAsymKeySpec_Destroy(OH_CryptoAsymKeySpec *spec)
{
    CryptoAsymKeySpecDestroy(spec);
}

static OH_Crypto_ErrCode CryptoAsymKeyGeneratorWithSpecCreate(OH_CryptoAsymKeySpec *keySpec,
    OH_CryptoAsymKeyGeneratorWithSpec **generator)
{
    if ((keySpec == NULL) || (generator == NULL)) {
        return CRYPTO_PARAMETER_CHECK_FAILED;
    }
    *generator = (OH_CryptoAsymKeyGeneratorWithSpec *)HcfMalloc(sizeof(OH_CryptoAsymKeyGeneratorWithSpec), 0);
    if (*generator == NULL) {
        return CRYPTO_MEMORY_ERROR;
    }
    HcfResult ret = HcfAsyKeyGeneratorBySpecCreate((HcfAsyKeyParamsSpec *)keySpec, &((*generator)->generator));
    if (ret != HCF_SUCCESS) {
        HcfFree(*generator);
        *generator = NULL;
        return GetOhCryptoErrCodeNew(ret);
    }
    (*generator)->specType = keySpec->specType;
    return CRYPTO_SUCCESS;
}

OH_Crypto_ErrCode OH_CryptoAsymKeyGeneratorWithSpec_Create(OH_CryptoAsymKeySpec *keySpec,
    OH_CryptoAsymKeyGeneratorWithSpec **generator)
{
    return CryptoAsymKeyGeneratorWithSpecCreate(keySpec, generator);
}

static OH_Crypto_ErrCode GenPriKeyPair(HcfAsyKeyGeneratorBySpec *generator, OH_CryptoKeyPair **keyPair)
{
    HcfPriKey *priKey = NULL;
    if (generator->generatePriKey == NULL) {
        return CRYPTO_NOT_SUPPORTED;
    }
    HcfResult ret = generator->generatePriKey(generator, &priKey);
    if (ret != HCF_SUCCESS) {
        return GetOhCryptoErrCodeNew(ret);
    }
    *keyPair = (OH_CryptoKeyPair *)HcfMalloc(sizeof(OH_CryptoKeyPair), 0);
    if (*keyPair == NULL) {
        HcfObjDestroy(priKey);
        priKey = NULL;
        return CRYPTO_MEMORY_ERROR;
    }

    HcfPubKey *pubKey = NULL;
    (void)priKey->getPubKey((HcfPriKey *)priKey, &pubKey);

    (*keyPair)->priKey = priKey;
    (*keyPair)->pubKey = pubKey;
    return CRYPTO_SUCCESS;
}

static OH_Crypto_ErrCode GenPubKeyPair(HcfAsyKeyGeneratorBySpec *generator, OH_CryptoKeyPair **keyPair)
{
    HcfPubKey *pubKey = NULL;
    if (generator->generatePubKey == NULL) {
        return CRYPTO_NOT_SUPPORTED;
    }
    HcfResult ret = generator->generatePubKey(generator, &pubKey);
    if (ret != HCF_SUCCESS) {
        return GetOhCryptoErrCodeNew(ret);
    }
    *keyPair = (OH_CryptoKeyPair *)HcfMalloc(sizeof(OH_CryptoKeyPair), 0);
    if (*keyPair == NULL) {
        HcfFree(pubKey);
        pubKey = NULL;
        return CRYPTO_MEMORY_ERROR;
    }
    (*keyPair)->pubKey = pubKey;
    return CRYPTO_SUCCESS;
}

static OH_Crypto_ErrCode GenKeyPair(HcfAsyKeyGeneratorBySpec *generator, OH_CryptoKeyPair **keyPair)
{
    if (generator->generateKeyPair == NULL) {
        return CRYPTO_NOT_SUPPORTED;
    }
    HcfResult ret = generator->generateKeyPair(generator, (HcfKeyPair **)keyPair);
    return GetOhCryptoErrCodeNew(ret);
}

static OH_Crypto_ErrCode CryptoAsymKeyGeneratorWithSpecGenKeyPair(OH_CryptoAsymKeyGeneratorWithSpec *generator,
    OH_CryptoKeyPair **keyPair)
{
    if ((generator == NULL) || (generator->generator == NULL) || (keyPair == NULL)) {
        return CRYPTO_PARAMETER_CHECK_FAILED;
    }
    switch (generator->specType) {
        case HCF_PRIVATE_KEY_SPEC:
            return GenPriKeyPair(generator->generator, keyPair);
        case HCF_PUBLIC_KEY_SPEC:
            return GenPubKeyPair(generator->generator, keyPair);
        case HCF_KEY_PAIR_SPEC:
        case HCF_COMMON_PARAMS_SPEC:
            return GenKeyPair(generator->generator, keyPair);
        default:
            return CRYPTO_PARAMETER_CHECK_FAILED;
    }
}

OH_Crypto_ErrCode OH_CryptoAsymKeyGeneratorWithSpec_GenKeyPair(OH_CryptoAsymKeyGeneratorWithSpec *generator,
    OH_CryptoKeyPair **keyPair)
{
    return CryptoAsymKeyGeneratorWithSpecGenKeyPair(generator, keyPair);
}

static void CryptoAsymKeyGeneratorWithSpecDestroy(OH_CryptoAsymKeyGeneratorWithSpec *generator)
{
    if (generator == NULL) {
        return;
    }
    HcfObjDestroy(generator->generator);
    generator->generator = NULL;
    HcfFree(generator);
}

void OH_CryptoAsymKeyGeneratorWithSpec_Destroy(OH_CryptoAsymKeyGeneratorWithSpec *generator)
{
    CryptoAsymKeyGeneratorWithSpecDestroy(generator);
}


static OH_Crypto_ErrCode CryptoEcPointCreate(const char *curveName, Crypto_DataBlob *ecKeyData,
    OH_CryptoEcPoint **point)
{
    if ((curveName == NULL) || (point == NULL)) {
        return CRYPTO_PARAMETER_CHECK_FAILED;
    }
    *point = (OH_CryptoEcPoint*)HcfMalloc(sizeof(OH_CryptoEcPoint), 0);
    if (*point == NULL) {
        return CRYPTO_MEMORY_ERROR;
    }
    (*point)->curveName = (char *)HcfMalloc(strlen(curveName) + 1, 0);
    if ((*point)->curveName == NULL) {
        HcfFree(*point);
        *point = NULL;
        return CRYPTO_MEMORY_ERROR;
    }
    (void)memcpy_s((*point)->curveName, strlen(curveName), curveName, strlen(curveName));
    if (ecKeyData == NULL) {
        return CRYPTO_SUCCESS;
    }
    HcfResult ret = HcfConvertPoint(curveName, (HcfBlob *)ecKeyData, &((*point)->pointBase));
    if (ret != HCF_SUCCESS) {
        OH_CryptoEcPoint_Destroy(*point);
        *point = NULL;
    }
    return GetOhCryptoErrCodeNew(ret);
}

OH_Crypto_ErrCode OH_CryptoEcPoint_Create(const char *curveName, Crypto_DataBlob *ecKeyData, OH_CryptoEcPoint **point)
{
    return CryptoEcPointCreate(curveName, ecKeyData, point);
}

static OH_Crypto_ErrCode CryptoEcPointGetCoordinate(OH_CryptoEcPoint *point, Crypto_DataBlob *x, Crypto_DataBlob *y)
{
    if ((point == NULL) || (x == NULL) || (y == NULL)) {
        return CRYPTO_PARAMETER_CHECK_FAILED;
    }
    HcfPoint dPoint = {};
    HcfResult ret = CopyPoint(&(point->pointBase), &dPoint);
    if (ret != HCF_SUCCESS) {
        return GetOhCryptoErrCodeNew(ret);
    }
    x->data = dPoint.x.data;
    y->data = dPoint.y.data;
    x->len = dPoint.x.len;
    y->len = dPoint.y.len;
    ReverseUint8Arr(x->data, x->len);
    ReverseUint8Arr(y->data, y->len);
    return CRYPTO_SUCCESS;
}

OH_Crypto_ErrCode OH_CryptoEcPoint_GetCoordinate(OH_CryptoEcPoint *point, Crypto_DataBlob *x, Crypto_DataBlob *y)
{
    return CryptoEcPointGetCoordinate(point, x, y);
}

static OH_Crypto_ErrCode CryptoEcPointSetCoordinate(OH_CryptoEcPoint *point, Crypto_DataBlob *x, Crypto_DataBlob *y)
{
    if ((point == NULL) || (x == NULL) || (y == NULL)) {
        return CRYPTO_PARAMETER_CHECK_FAILED;
    }
    HcfPoint sPoint = {};
    sPoint.x.data = x->data;
    sPoint.x.len = x->len;
    sPoint.y.data = y->data;
    sPoint.y.len = y->len;
    HcfPoint dPoint = {};
    HcfResult ret = CopyPoint(&sPoint, &dPoint);
    if (ret != HCF_SUCCESS) {
        return GetOhCryptoErrCodeNew(ret);
    }
    HcfFree(point->pointBase.x.data);
    point->pointBase.x.data = NULL;
    HcfFree(point->pointBase.y.data);
    point->pointBase.y.data = NULL;
    point->pointBase.x.data = dPoint.x.data;
    point->pointBase.x.len = dPoint.x.len;
    point->pointBase.y.data = dPoint.y.data;
    point->pointBase.y.len = dPoint.y.len;
    ReverseUint8Arr(point->pointBase.x.data, point->pointBase.x.len);
    ReverseUint8Arr(point->pointBase.y.data, point->pointBase.y.len);
    return CRYPTO_SUCCESS;
}

OH_Crypto_ErrCode OH_CryptoEcPoint_SetCoordinate(OH_CryptoEcPoint *point, Crypto_DataBlob *x, Crypto_DataBlob *y)
{
    return CryptoEcPointSetCoordinate(point, x, y);
}

static OH_Crypto_ErrCode CryptoEcPointEncode(OH_CryptoEcPoint *point, const char *format, Crypto_DataBlob *out)
{
    if ((point == NULL) || (format == NULL) || (out == NULL)) {
        return CRYPTO_PARAMETER_CHECK_FAILED;
    }
    HcfResult ret = HcfGetEncodedPoint(point->curveName, &(point->pointBase), format, (HcfBlob *)out);
    return GetOhCryptoErrCodeNew(ret);
}

OH_Crypto_ErrCode OH_CryptoEcPoint_Encode(OH_CryptoEcPoint *point, const char *format, Crypto_DataBlob *out)
{
    return CryptoEcPointEncode(point, format, out);
}

static void CryptoEcPointDestroy(OH_CryptoEcPoint *point)
{
    if (point == NULL) {
        return;
    }
    HcfFree(point->curveName);
    point->curveName = NULL;
    FreeEcPointMem(&(point->pointBase));
    HcfFree(point);
}

void OH_CryptoEcPoint_Destroy(OH_CryptoEcPoint *point)
{
    CryptoEcPointDestroy(point);
}
