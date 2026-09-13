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

#include "crypto_signature.h"
#include "sm2_ec_signature_data.h"
#include "securec.h"
#include <limits.h>
#include <string.h>
#include <stdlib.h>
#include "signature.h"
#include "memory.h"
#include "crypto_common.h"
#include "blob.h"
#include "object_base.h"
#include "result.h"
#include "native_common.h"

struct OH_CryptoVerify {
    HcfObjectBase base;

    HcfResult (*init)(HcfVerify *self, HcfParamsSpec *params, HcfPubKey *publicKey);

    HcfResult (*update)(HcfVerify *self, HcfBlob *data);

    bool (*verify)(HcfVerify *self, HcfBlob *data, HcfBlob *signatureData);

    HcfResult (*recover)(HcfVerify *self, HcfBlob *signatureData, HcfBlob *rawSignatureData);

    const char *(*getAlgoName)(HcfVerify *self);

    HcfResult (*setVerifySpecInt)(HcfVerify *self, SignSpecItem item, int32_t saltLen);

    HcfResult (*getVerifySpecString)(HcfVerify *self, SignSpecItem item, char **returnString);

    HcfResult (*getVerifySpecInt)(HcfVerify *self, SignSpecItem item, int32_t *returnInt);

    HcfResult (*setVerifySpecUint8Array)(HcfVerify *self, SignSpecItem item, HcfBlob blob);
};

struct OH_CryptoSign {
    HcfObjectBase base;

    HcfResult (*init)(HcfSign *self, HcfParamsSpec *params, HcfPriKey *privateKey);

    HcfResult (*update)(HcfSign *self, HcfBlob *data);

    HcfResult (*sign)(HcfSign *self, HcfBlob *data, HcfBlob *returnSignatureData);

    const char *(*getAlgoName)(HcfSign *self);

    HcfResult (*setSignSpecInt)(HcfSign *self, SignSpecItem item, int32_t saltLen);

    HcfResult (*getSignSpecString)(HcfSign *self, SignSpecItem item, char **returnString);

    HcfResult (*getSignSpecInt)(HcfSign *self, SignSpecItem item, int32_t *returnInt);

    HcfResult (*setSignSpecUint8Array)(HcfSign *self, SignSpecItem item, HcfBlob blob);
};

static OH_Crypto_ErrCode CryptoVerifyCreate(const char *algoName, OH_CryptoVerify **verify)
{
    if (verify == NULL) {
        return CRYPTO_INVALID_PARAMS;
    }
    HcfResult ret = HcfVerifyCreate(algoName, (HcfVerify **)verify);
    return GetOhCryptoErrCode(ret);
}

OH_Crypto_ErrCode OH_CryptoVerify_Create(const char *algoName, OH_CryptoVerify **verify)
{
    return CryptoVerifyCreate(algoName, verify);
}

static OH_Crypto_ErrCode CryptoVerifyInit(OH_CryptoVerify *ctx, OH_CryptoPubKey *pubKey)
{
    if ((ctx == NULL) || (ctx->init == NULL) || (pubKey == NULL)) {
        return CRYPTO_INVALID_PARAMS;
    }
    HcfResult ret = ctx->init((HcfVerify *)ctx, NULL, (HcfPubKey *)pubKey);
    return GetOhCryptoErrCode(ret);
}

OH_Crypto_ErrCode OH_CryptoVerify_Init(OH_CryptoVerify *ctx, OH_CryptoPubKey *pubKey)
{
    return CryptoVerifyInit(ctx, pubKey);
}

static OH_Crypto_ErrCode CryptoVerifyUpdate(OH_CryptoVerify *ctx, Crypto_DataBlob *in)
{
    if ((ctx == NULL) || (ctx->update == NULL) || (in == NULL)) {
        return CRYPTO_INVALID_PARAMS;
    }
    HcfResult ret = ctx->update((HcfVerify *)ctx, (HcfBlob *)in);
    return GetOhCryptoErrCode(ret);
}

OH_Crypto_ErrCode OH_CryptoVerify_Update(OH_CryptoVerify *ctx, Crypto_DataBlob *in)
{
    return CryptoVerifyUpdate(ctx, in);
}

static bool CryptoVerifyFinal(OH_CryptoVerify *ctx, Crypto_DataBlob *in, Crypto_DataBlob *signData)
{
    if ((ctx == NULL) || (ctx->verify == NULL) || (signData == NULL)) {
        return false;
    }
    bool ret = ctx->verify((HcfVerify *)ctx, (HcfBlob *)in, (HcfBlob *)signData);
    if (ret != true) {
        return false;
    }

    return ret;
}

bool OH_CryptoVerify_Final(OH_CryptoVerify *ctx, Crypto_DataBlob *in, Crypto_DataBlob *signData)
{
    bool result = CryptoVerifyFinal(ctx, in, signData);
    return result;
}

static OH_Crypto_ErrCode CryptoVerifyRecover(OH_CryptoVerify *ctx, Crypto_DataBlob *signData,
    Crypto_DataBlob *rawSignData)
{
    if ((ctx == NULL) || (ctx->recover == NULL) || (signData == NULL) || (rawSignData == NULL)) {
        return CRYPTO_INVALID_PARAMS;
    }
    HcfResult ret = ctx->recover((HcfVerify *)ctx, (HcfBlob *)signData, (HcfBlob *)rawSignData);
    return GetOhCryptoErrCode(ret);
}

OH_Crypto_ErrCode OH_CryptoVerify_Recover(OH_CryptoVerify *ctx, Crypto_DataBlob *signData,
    Crypto_DataBlob *rawSignData)
{
    return CryptoVerifyRecover(ctx, signData, rawSignData);
}

static const char *CryptoVerifyGetAlgoName(OH_CryptoVerify *ctx)
{
    if ((ctx == NULL) || (ctx->getAlgoName == NULL)) {
        return NULL;
    }
    return ctx->getAlgoName((HcfVerify *)ctx);
}

const char *OH_CryptoVerify_GetAlgoName(OH_CryptoVerify *ctx)
{
    const char *name = CryptoVerifyGetAlgoName(ctx);
    return name;
}

static OH_Crypto_ErrCode CryptoVerifySetParam(OH_CryptoVerify *ctx, CryptoSignature_ParamType type,
    Crypto_DataBlob *value)
{
    if ((ctx == NULL) || (value == NULL)) {
        return CRYPTO_INVALID_PARAMS;
    }
    HcfResult ret = HCF_INVALID_PARAMS;
    switch (type) {
        case CRYPTO_PSS_SALT_LEN_INT:
        case CRYPTO_PSS_TRAILER_FIELD_INT:
            if ((value->data == NULL) || (value->len != sizeof(int32_t)) || (ctx->setVerifySpecInt == NULL)) {
                ret = HCF_INVALID_PARAMS;
                break;
            }
            ret = ctx->setVerifySpecInt((HcfVerify *)ctx, (SignSpecItem)type, *((int32_t *)value->data));
            break;
        case CRYPTO_SM2_USER_ID_DATABLOB:
        case CRYPTO_PSS_MGF1_NAME_STR:
        case CRYPTO_PSS_MGF_NAME_STR:
        case CRYPTO_PSS_MD_NAME_STR:
            if (ctx->setVerifySpecUint8Array == NULL) {
                ret = HCF_INVALID_PARAMS;
                break;
            }
            ret = ctx->setVerifySpecUint8Array((HcfVerify *)ctx, (SignSpecItem)type, *((HcfBlob *)value));
            break;
        default:
            return CRYPTO_INVALID_PARAMS;
    }
    return GetOhCryptoErrCode(ret);
}

OH_Crypto_ErrCode OH_CryptoVerify_SetParam(OH_CryptoVerify *ctx, CryptoSignature_ParamType type,
    Crypto_DataBlob *value)
{
    return CryptoVerifySetParam(ctx, type, value);
}

static OH_Crypto_ErrCode CryptoVerifyGetParam(OH_CryptoVerify *ctx, CryptoSignature_ParamType type,
    Crypto_DataBlob *value)
{
    if ((ctx == NULL) || (value == NULL)) {
        return CRYPTO_INVALID_PARAMS;
    }
    int32_t *returnInt = NULL;
    char *returnStr = NULL;
    HcfResult ret = HCF_INVALID_PARAMS;
    switch (type) {
        case CRYPTO_PSS_SALT_LEN_INT:
        case CRYPTO_PSS_TRAILER_FIELD_INT:
        case CRYPTO_SM2_USER_ID_DATABLOB:
            if (ctx->getVerifySpecInt == NULL) {
                ret = HCF_INVALID_PARAMS;
                break;
            }
            returnInt = (int32_t *)HcfMalloc(sizeof(int32_t), 0);
            if (returnInt == NULL) {
                return CRYPTO_MEMORY_ERROR;
            }
            ret = ctx->getVerifySpecInt((HcfVerify *)ctx, (SignSpecItem)type, returnInt);
            if (ret != HCF_SUCCESS) {
                HcfFree(returnInt);
                returnInt = NULL;
                break;
            }
            value->data = (uint8_t *)returnInt;
            value->len = sizeof(int32_t);
            break;
        case CRYPTO_PSS_MD_NAME_STR:
        case CRYPTO_PSS_MGF_NAME_STR:
        case CRYPTO_PSS_MGF1_NAME_STR:
            if (ctx->getVerifySpecString == NULL) {
                ret = HCF_INVALID_PARAMS;
                break;
            }
            ret = ctx->getVerifySpecString((HcfVerify *)ctx, (SignSpecItem)type, &returnStr);
            if (ret != HCF_SUCCESS) {
                break;
            }
            value->data = (uint8_t *)returnStr;
            value->len = strlen(returnStr);
            break;
        default:
            return CRYPTO_INVALID_PARAMS;
    }
    return GetOhCryptoErrCode(ret);
}

OH_Crypto_ErrCode OH_CryptoVerify_GetParam(OH_CryptoVerify *ctx, CryptoSignature_ParamType type,
    Crypto_DataBlob *value)
{
    return CryptoVerifyGetParam(ctx, type, value);
}


static void CryptoVerifyDestroy(OH_CryptoVerify *ctx)
{
    if (ctx == NULL || ctx->base.destroy == NULL) {
        return;
    }
    ctx->base.destroy((HcfObjectBase *)ctx);
}

void OH_CryptoVerify_Destroy(OH_CryptoVerify *ctx)
{
    CryptoVerifyDestroy(ctx);
}

static OH_Crypto_ErrCode CryptoSignCreate(const char *algoName, OH_CryptoSign **sign)
{
    if (sign == NULL) {
        return CRYPTO_PARAMETER_CHECK_FAILED;
    }
    HcfResult ret = HcfSignCreate(algoName, (HcfSign **)sign);
    return GetOhCryptoErrCodeNew(ret);
}

OH_Crypto_ErrCode OH_CryptoSign_Create(const char *algoName, OH_CryptoSign **sign)
{
    return CryptoSignCreate(algoName, sign);
}

static OH_Crypto_ErrCode CryptoSignInit(OH_CryptoSign *ctx, OH_CryptoPrivKey *privKey)
{
    if ((ctx == NULL) || (ctx->init == NULL) || (privKey == NULL)) {
        return CRYPTO_PARAMETER_CHECK_FAILED;
    }
    HcfResult ret = ctx->init((HcfSign *)ctx, NULL, (HcfPriKey *)privKey);
    return GetOhCryptoErrCodeNew(ret);
}

OH_Crypto_ErrCode OH_CryptoSign_Init(OH_CryptoSign *ctx, OH_CryptoPrivKey *privKey)
{
    return CryptoSignInit(ctx, privKey);
}

static OH_Crypto_ErrCode CryptoSignUpdate(OH_CryptoSign *ctx, const Crypto_DataBlob *in)
{
    if ((ctx == NULL) || (ctx->update == NULL) || (in == NULL)) {
        return CRYPTO_PARAMETER_CHECK_FAILED;
    }
    HcfResult ret = ctx->update((HcfSign *)ctx, (HcfBlob *)in);
    return GetOhCryptoErrCodeNew(ret);
}

OH_Crypto_ErrCode OH_CryptoSign_Update(OH_CryptoSign *ctx, const Crypto_DataBlob *in)
{
    return CryptoSignUpdate(ctx, in);
}

static OH_Crypto_ErrCode CryptoSignFinal(OH_CryptoSign *ctx, const Crypto_DataBlob *in, Crypto_DataBlob *out)
{
    if ((ctx == NULL) || (ctx->sign == NULL) || (out == NULL)) {
        return CRYPTO_PARAMETER_CHECK_FAILED;
    }
    HcfResult ret = ctx->sign((HcfSign *)ctx, (HcfBlob *)in, (HcfBlob *)out);
    return GetOhCryptoErrCodeNew(ret);
}

OH_Crypto_ErrCode OH_CryptoSign_Final(OH_CryptoSign *ctx, const Crypto_DataBlob *in, Crypto_DataBlob *out)
{
    return CryptoSignFinal(ctx, in, out);
}

static const char *CryptoSignGetAlgoName(OH_CryptoSign *ctx)
{
    if ((ctx == NULL) || (ctx->getAlgoName == NULL)) {
        return NULL;
    }
    return ctx->getAlgoName((HcfSign *)ctx);
}

const char *OH_CryptoSign_GetAlgoName(OH_CryptoSign *ctx)
{
    const char *name = CryptoSignGetAlgoName(ctx);
    return name;
}

static OH_Crypto_ErrCode CryptoSignSetParam(OH_CryptoSign *ctx, CryptoSignature_ParamType type,
    const Crypto_DataBlob *value)
{
    if ((ctx == NULL) || (value == NULL)) {
        return CRYPTO_PARAMETER_CHECK_FAILED;
    }
    HcfResult ret = HCF_INVALID_PARAMS;
    switch (type) {
        case CRYPTO_PSS_SALT_LEN_INT:
        case CRYPTO_PSS_TRAILER_FIELD_INT:
            if ((value->data == NULL) || (value->len != sizeof(int32_t)) || (ctx->setSignSpecInt == NULL)) {
                ret = HCF_INVALID_PARAMS;
                break;
            }
            ret = ctx->setSignSpecInt((HcfSign *)ctx, (SignSpecItem)type, *((int32_t *)value->data));
            break;
        case CRYPTO_SM2_USER_ID_DATABLOB:
        case CRYPTO_PSS_MGF1_NAME_STR:
        case CRYPTO_PSS_MGF_NAME_STR:
        case CRYPTO_PSS_MD_NAME_STR:
            if (ctx->setSignSpecUint8Array == NULL) {
                ret = HCF_INVALID_PARAMS;
                break;
            }
            ret = ctx->setSignSpecUint8Array((HcfSign *)ctx, (SignSpecItem)type, *((HcfBlob *)value));
            break;
        default:
            return CRYPTO_PARAMETER_CHECK_FAILED;
    }
    return GetOhCryptoErrCodeNew(ret);
}

OH_Crypto_ErrCode OH_CryptoSign_SetParam(OH_CryptoSign *ctx, CryptoSignature_ParamType type,
    const Crypto_DataBlob *value)
{
    return CryptoSignSetParam(ctx, type, value);
}

static OH_Crypto_ErrCode CryptoSignGetParam(OH_CryptoSign *ctx, CryptoSignature_ParamType type, Crypto_DataBlob *value)
{
    if ((ctx == NULL) || (value == NULL)) {
        return CRYPTO_PARAMETER_CHECK_FAILED;
    }
    int32_t *returnInt = NULL;
    char *returnStr = NULL;
    HcfResult ret = HCF_INVALID_PARAMS;
    switch (type) {
        case CRYPTO_PSS_SALT_LEN_INT:
        case CRYPTO_PSS_TRAILER_FIELD_INT:
        case CRYPTO_SM2_USER_ID_DATABLOB:
            if (ctx->getSignSpecInt == NULL) {
                ret = HCF_INVALID_PARAMS;
                break;
            }
            returnInt = (int32_t *)HcfMalloc(sizeof(int32_t), 0);
            if (returnInt == NULL) {
                return CRYPTO_MEMORY_ERROR;
            }
            ret = ctx->getSignSpecInt((HcfSign *)ctx, (SignSpecItem)type, returnInt);
            if (ret != HCF_SUCCESS) {
                HcfFree(returnInt);
                returnInt = NULL;
                break;
            }
            value->data = (uint8_t *)returnInt;
            value->len = sizeof(int32_t);
            break;
        case CRYPTO_PSS_MD_NAME_STR:
        case CRYPTO_PSS_MGF_NAME_STR:
        case CRYPTO_PSS_MGF1_NAME_STR:
            if (ctx->getSignSpecString == NULL) {
                ret = HCF_INVALID_PARAMS;
                break;
            }
            ret = ctx->getSignSpecString((HcfSign *)ctx, (SignSpecItem)type, &returnStr);
            if (ret != HCF_SUCCESS) {
                break;
            }
            value->data = (uint8_t *)returnStr;
            value->len = strlen(returnStr);
            break;
        default:
            return CRYPTO_PARAMETER_CHECK_FAILED;
    }
    return GetOhCryptoErrCodeNew(ret);
}

OH_Crypto_ErrCode OH_CryptoSign_GetParam(OH_CryptoSign *ctx, CryptoSignature_ParamType type, Crypto_DataBlob *value)
{
    return CryptoSignGetParam(ctx, type, value);
}

static void CryptoSignDestroy(OH_CryptoSign *ctx)
{
    if (ctx == NULL || ctx->base.destroy == NULL) {
        return;
    }
    ctx->base.destroy((HcfObjectBase *)ctx);
}

void OH_CryptoSign_Destroy(OH_CryptoSign *ctx)
{
    CryptoSignDestroy(ctx);
}

struct OH_CryptoEccSignatureSpec {
    HcfBigInteger r;
    HcfBigInteger s;
};


static OH_Crypto_ErrCode CryptoEccSignatureSpecCreate(Crypto_DataBlob *eccSignature, OH_CryptoEccSignatureSpec **spec)
{
    if (spec == NULL) {
        return CRYPTO_PARAMETER_CHECK_FAILED;
    }
    HcfResult ret = HCF_INVALID_PARAMS;
    if (eccSignature == NULL) {
        *spec = (OH_CryptoEccSignatureSpec *)HcfMalloc(sizeof(OH_CryptoEccSignatureSpec), 0);
        if (*spec == NULL) {
            return CRYPTO_MEMORY_ERROR;
        }
        return GetOhCryptoErrCodeNew(HCF_SUCCESS);
    }
    ret = HcfGenEcSignatureSpecByData((HcfBlob *)eccSignature, (Sm2EcSignatureDataSpec **)spec);
    return GetOhCryptoErrCodeNew(ret);
}

OH_Crypto_ErrCode OH_CryptoEccSignatureSpec_Create(Crypto_DataBlob *eccSignature, OH_CryptoEccSignatureSpec **spec)
{
    return CryptoEccSignatureSpecCreate(eccSignature, spec);
}

static OH_Crypto_ErrCode CryptoEccSignatureSpecGetRAndS(OH_CryptoEccSignatureSpec *spec, Crypto_DataBlob *r,
    Crypto_DataBlob *s)
{
    if ((spec == NULL) || (r == NULL) || (s == NULL)) {
        return CRYPTO_PARAMETER_CHECK_FAILED;
    }
    if ((spec->r.data == NULL) || (spec->s.data == NULL)) {
        return CRYPTO_PARAMETER_CHECK_FAILED;
    }

    // Allocate memory for r->data
    r->data = (uint8_t *)HcfMalloc(spec->r.len, 0);
    if (r->data == NULL) {
        return CRYPTO_MEMORY_ERROR;
    }

    // Copy data for r
    if (memcpy_s(r->data, spec->r.len, spec->r.data, spec->r.len) != 0) {
        HcfFree(r->data);
        r->data = NULL; // Ensure pointer is null after freeing
        return CRYPTO_MEMORY_ERROR;
    }
    r->len = (size_t)spec->r.len;

    // Allocate memory for s->data
    s->data = (uint8_t *)HcfMalloc(spec->s.len, 0);
    if (s->data == NULL) {
        HcfFree(r->data);
        r->data = NULL; // Ensure pointer is null after freeing
        return CRYPTO_MEMORY_ERROR;
    }

    // Copy data for s
    if (memcpy_s(s->data, spec->s.len, spec->s.data, spec->s.len) != 0) {
        HcfFree(r->data);
        r->data = NULL; // Ensure pointer is null after freeing
        HcfFree(s->data);
        s->data = NULL; // Ensure pointer is null after freeing
        return CRYPTO_MEMORY_ERROR;
    }
    s->len = (size_t)spec->s.len;

    return GetOhCryptoErrCodeNew(HCF_SUCCESS);
}

OH_Crypto_ErrCode OH_CryptoEccSignatureSpec_GetRAndS(OH_CryptoEccSignatureSpec *spec, Crypto_DataBlob *r,
    Crypto_DataBlob *s)
{
    return CryptoEccSignatureSpecGetRAndS(spec, r, s);
}

static OH_Crypto_ErrCode CryptoEccSignatureSpecSetRAndS(OH_CryptoEccSignatureSpec *spec, Crypto_DataBlob *r,
    Crypto_DataBlob *s)
{
    if ((spec == NULL) || (r == NULL) || (s == NULL)) {
        return CRYPTO_PARAMETER_CHECK_FAILED;
    }
    if (r->data == NULL || s->data == NULL) {
        return CRYPTO_PARAMETER_CHECK_FAILED;
    }
    if (r->len > UINT32_MAX || s->len > UINT32_MAX) {
        return CRYPTO_PARAMETER_CHECK_FAILED;
    }

    // Allocate memory for r->data
    spec->r.data = (unsigned char *)HcfMalloc(r->len, 0);
    if (spec->r.data == NULL) {
        return CRYPTO_MEMORY_ERROR;
    }
    if (memcpy_s(spec->r.data, r->len, r->data, r->len) != 0) {
        HcfFree(spec->r.data);
        spec->r.data = NULL;
        return CRYPTO_MEMORY_ERROR;
    }
    spec->r.len = (uint32_t)r->len;

    // Allocate memory for s->data
    spec->s.data = (unsigned char *)HcfMalloc(s->len, 0);
    if (spec->s.data == NULL) {
        HcfFree(spec->r.data);
        spec->r.data = NULL;
        return CRYPTO_MEMORY_ERROR;
    }
    if (memcpy_s(spec->s.data, s->len, s->data, s->len) != 0) {
        HcfFree(spec->r.data);
        HcfFree(spec->s.data);
        spec->r.data = NULL;
        spec->s.data = NULL;
        return CRYPTO_MEMORY_ERROR;
    }
    spec->s.len = (uint32_t)s->len;

    return GetOhCryptoErrCodeNew(HCF_SUCCESS);
}

OH_Crypto_ErrCode OH_CryptoEccSignatureSpec_SetRAndS(OH_CryptoEccSignatureSpec *spec, Crypto_DataBlob *r,
    Crypto_DataBlob *s)
{
    return CryptoEccSignatureSpecSetRAndS(spec, r, s);
}

static OH_Crypto_ErrCode CryptoEccSignatureSpecEncode(OH_CryptoEccSignatureSpec *spec, Crypto_DataBlob *out)
{
    if ((spec == NULL) || (out == NULL)) {
        return CRYPTO_PARAMETER_CHECK_FAILED;
    }
    HcfBlob *outBlob = (HcfBlob *)HcfMalloc(sizeof(HcfBlob), 0);
    if (outBlob == NULL) {
        return CRYPTO_MEMORY_ERROR;
    }

    HcfResult ret = HcfGenEcSignatureDataBySpec((Sm2EcSignatureDataSpec *)spec, outBlob);
    if (ret != HCF_SUCCESS) {
        HcfFree(outBlob);
        outBlob = NULL;
        return GetOhCryptoErrCode(ret);
    }
    out->data = outBlob->data;
    out->len = outBlob->len;
    HcfFree(outBlob);
    outBlob = NULL;
    return GetOhCryptoErrCodeNew(HCF_SUCCESS);
}

OH_Crypto_ErrCode OH_CryptoEccSignatureSpec_Encode(OH_CryptoEccSignatureSpec *spec, Crypto_DataBlob *out)
{
    return CryptoEccSignatureSpecEncode(spec, out);
}

static void CryptoEccSignatureSpecDestroy(OH_CryptoEccSignatureSpec *spec)
{
    if (spec == NULL) {
        return;
    }
    if (spec->r.data != NULL) {
        HcfFree(spec->r.data);
        spec->r.data = NULL;
    }
    if (spec->s.data != NULL) {
        HcfFree(spec->s.data);
        spec->s.data = NULL;
    }
    HcfFree(spec);
}

void OH_CryptoEccSignatureSpec_Destroy(OH_CryptoEccSignatureSpec *spec)
{
    CryptoEccSignatureSpecDestroy(spec);
}
