/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
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

#include "crypto_mac.h"
#include <string.h>
#include <securec.h>
#include "memory.h"
#include "crypto_common.h"
#include "crypto_sym_key.h"
#include "native_common.h"
#include "mac.h"
#include "mac_params.h"
#include "detailed_cmac_params.h"
#include "detailed_hmac_params.h"

typedef struct OH_CryptoMac {
    HcfMacParamsSpec *paramsSpec;
    HcfMac *macObj;
} OH_CryptoMac;

static const char *CMAC_NAME = "CMAC";
static const char *HMAC_NAME = "HMAC";

static OH_Crypto_ErrCode CryptoMacCreate(const char *algoName, OH_CryptoMac **ctx)
{
    if ((algoName == NULL) || (ctx == NULL)) {
        return CRYPTO_PARAMETER_CHECK_FAILED;
    }
    OH_CryptoMac *tmpCtx = (OH_CryptoMac *)HcfMalloc(sizeof(OH_CryptoMac), 0);
    if (tmpCtx == NULL) {
        return CRYPTO_MEMORY_ERROR;
    }
    HcfMacParamsSpec *paramsSpec = NULL;
    const char *algName = NULL;
    if (strcmp(algoName, CMAC_NAME) == 0) {
        paramsSpec = (HcfMacParamsSpec *)HcfMalloc(sizeof(HcfCmacParamsSpec), 0);
        algName = CMAC_NAME;
    } else if (strcmp(algoName, HMAC_NAME) == 0) {
        paramsSpec = (HcfMacParamsSpec *)HcfMalloc(sizeof(HcfHmacParamsSpec), 0);
        algName = HMAC_NAME;
    } else {
        HcfFree(tmpCtx);
        tmpCtx = NULL;
        return CRYPTO_PARAMETER_CHECK_FAILED;
    }

    if (paramsSpec == NULL) {
        HcfFree(tmpCtx);
        tmpCtx = NULL;
        return CRYPTO_MEMORY_ERROR;
    }

    paramsSpec->algName = algName;
    tmpCtx->paramsSpec = paramsSpec;
    *ctx = tmpCtx;
    return CRYPTO_SUCCESS;
}

OH_Crypto_ErrCode OH_CryptoMac_Create(const char *algoName, OH_CryptoMac **ctx)
{
    return CryptoMacCreate(algoName, ctx);
}

static OH_Crypto_ErrCode SetCmacParam(HcfCmacParamsSpec *paramsSpec, CryptoMac_ParamType type,
    const Crypto_DataBlob *value)
{
    switch (type) {
        case CRYPTO_MAC_CIPHER_NAME_STR: {
            char *data = (char *)HcfMalloc(value->len + 1, 0);
            if (data == NULL) {
                return CRYPTO_MEMORY_ERROR;
            }
            (void)memcpy_s(data, value->len, value->data, value->len);
            HcfFree((void *)(paramsSpec->cipherName));
            paramsSpec->cipherName = data;
            return CRYPTO_SUCCESS;
        }
        default:
            return CRYPTO_PARAMETER_CHECK_FAILED;
    }
}

static OH_Crypto_ErrCode SetHmacParam(HcfHmacParamsSpec *paramsSpec, CryptoMac_ParamType type,
    const Crypto_DataBlob *value)
{
    switch (type) {
        case CRYPTO_MAC_DIGEST_NAME_STR: {
            char *data = (char *)HcfMalloc(value->len + 1, 0);
            if (data == NULL) {
                return CRYPTO_MEMORY_ERROR;
            }
            (void)memcpy_s(data, value->len, value->data, value->len);
            HcfFree((void *)(paramsSpec->mdName));
            paramsSpec->mdName = data;
            return CRYPTO_SUCCESS;
        }
        default:
            return CRYPTO_PARAMETER_CHECK_FAILED;
    }
}

static OH_Crypto_ErrCode CryptoMacSetParam(OH_CryptoMac *ctx, CryptoMac_ParamType type, const Crypto_DataBlob *value)
{
    if ((ctx == NULL) || (ctx->paramsSpec == NULL) || (ctx->paramsSpec->algName == NULL) || (value == NULL) ||
        (value->data == NULL)) {
        return CRYPTO_PARAMETER_CHECK_FAILED;
    }
    OH_Crypto_ErrCode res = CRYPTO_PARAMETER_CHECK_FAILED;
    if (strcmp(ctx->paramsSpec->algName, "CMAC") == 0) {
        res = SetCmacParam((HcfCmacParamsSpec*)(ctx->paramsSpec), type, value);
    } else if (strcmp(ctx->paramsSpec->algName, "HMAC") == 0) {
        res = SetHmacParam((HcfHmacParamsSpec*)(ctx->paramsSpec), type, value);
    }

    if (res != CRYPTO_SUCCESS) {
        return res;
    }

    HcfMac *macObj = NULL;
    HcfResult ret = HcfMacCreate(ctx->paramsSpec, &macObj);
    if (ret != HCF_SUCCESS) {
        return GetOhCryptoErrCodeNew(ret);
    }
    HcfObjDestroy(ctx->macObj);
    ctx->macObj = macObj;
    return CRYPTO_SUCCESS;
}

OH_Crypto_ErrCode OH_CryptoMac_SetParam(OH_CryptoMac *ctx, CryptoMac_ParamType type, const Crypto_DataBlob *value)
{
    return CryptoMacSetParam(ctx, type, value);
}

static OH_Crypto_ErrCode CryptoMacInit(OH_CryptoMac *ctx, const OH_CryptoSymKey *key)
{
    if ((ctx == NULL) || (ctx->macObj == NULL) || (ctx->macObj->init == NULL) || (key == NULL)) {
        return CRYPTO_PARAMETER_CHECK_FAILED;
    }
    HcfResult ret = ctx->macObj->init(ctx->macObj, (const HcfSymKey *)key);
    return GetOhCryptoErrCodeNew(ret);
}

OH_Crypto_ErrCode OH_CryptoMac_Init(OH_CryptoMac *ctx, const OH_CryptoSymKey *key)
{
    return CryptoMacInit(ctx, key);
}

static OH_Crypto_ErrCode CryptoMacUpdate(OH_CryptoMac *ctx, const Crypto_DataBlob *in)
{
    if ((ctx == NULL) || (ctx->macObj == NULL) || (ctx->macObj->update == NULL) || (in == NULL)) {
        return CRYPTO_PARAMETER_CHECK_FAILED;
    }
    HcfResult ret = ctx->macObj->update(ctx->macObj, (HcfBlob *)in);
    return GetOhCryptoErrCodeNew(ret);
}

OH_Crypto_ErrCode OH_CryptoMac_Update(OH_CryptoMac *ctx, const Crypto_DataBlob *in)
{
    return CryptoMacUpdate(ctx, in);
}

static OH_Crypto_ErrCode CryptoMacFinal(OH_CryptoMac *ctx, Crypto_DataBlob *out)
{
    if ((ctx == NULL) || (ctx->macObj == NULL) || (ctx->macObj->doFinal == NULL) || (out == NULL)) {
        return CRYPTO_PARAMETER_CHECK_FAILED;
    }
    HcfResult ret = ctx->macObj->doFinal(ctx->macObj, (HcfBlob *)out);
    return GetOhCryptoErrCodeNew(ret);
}

OH_Crypto_ErrCode OH_CryptoMac_Final(OH_CryptoMac *ctx, Crypto_DataBlob *out)
{
    return CryptoMacFinal(ctx, out);
}

static OH_Crypto_ErrCode CryptoMacGetLength(OH_CryptoMac *ctx, uint32_t *length)
{
    if ((ctx == NULL) || (ctx->macObj == NULL) || (ctx->macObj->getMacLength == NULL) || (length == NULL)) {
        return CRYPTO_PARAMETER_CHECK_FAILED;
    }
    *length = ctx->macObj->getMacLength(ctx->macObj);
    return CRYPTO_SUCCESS;
}

OH_Crypto_ErrCode OH_CryptoMac_GetLength(OH_CryptoMac *ctx, uint32_t *length)
{
    return CryptoMacGetLength(ctx, length);
}

static void FreeMacParams(HcfMacParamsSpec *params)
{
    if ((params == NULL) || (params->algName == NULL)) {
        return;
    }
    if (strcmp(params->algName, "CMAC") == 0) {
        HcfFree((void *)(((HcfCmacParamsSpec *)params)->cipherName));
        ((HcfCmacParamsSpec *)params)->cipherName = NULL;
    } else if (strcmp(params->algName, "HMAC") == 0) {
        HcfFree((void *)(((HcfHmacParamsSpec *)params)->mdName));
        ((HcfHmacParamsSpec *)params)->mdName = NULL;
    }
    params->algName = NULL;
    HcfFree(params);
}

static void CryptoMacDestroy(OH_CryptoMac *ctx)
{
    if (ctx == NULL) {
        return;
    }
    FreeMacParams(ctx->paramsSpec);
    ctx->paramsSpec = NULL;
    HcfObjDestroy(ctx->macObj);
    ctx->macObj = NULL;
    HcfFree(ctx);
}

void OH_CryptoMac_Destroy(OH_CryptoMac *ctx)
{
    CryptoMacDestroy(ctx);
}
