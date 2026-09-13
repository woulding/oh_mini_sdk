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

#include "crypto_sym_cipher.h"
#include "memory.h"
#include <stdlib.h>
#include "sym_key_generator.h"
#include "crypto_common.h"
#include "cipher.h"
#include "blob.h"
#include "object_base.h"
#include "result.h"
#include "native_common.h"

struct OH_CryptoSymCipher {
    HcfObjectBase base;

    HcfResult (*init)(HcfCipher *self, enum HcfCryptoMode opMode,
        HcfKey *key, HcfParamsSpec *params);

    HcfResult (*update)(HcfCipher *self, HcfBlob *input, HcfBlob *output);

    HcfResult (*doFinal)(HcfCipher *self, HcfBlob *input, HcfBlob *output);

    const char *(*getAlgorithm)(HcfCipher *self);

    HcfResult (*setCipherSpecUint8Array)(HcfCipher *self, CipherSpecItem item, HcfBlob blob);

    HcfResult (*getCipherSpecString)(HcfCipher *self, CipherSpecItem item, char **returnString);

    HcfResult (*getCipherSpecUint8Array)(HcfCipher *self, CipherSpecItem item, HcfBlob *returnUint8Array);
};

struct OH_CryptoSymCipherParams {
    HcfParamsSpec base;
    HcfBlob iv;
    HcfBlob aad;
    HcfBlob tag;
};

struct OH_CryptoSymKey {
    HcfKey key;

    void (*clearMem)(HcfSymKey *self);
};

static OH_Crypto_ErrCode CryptoSymCipherParamsCreate(OH_CryptoSymCipherParams **params)
{
    if (params == NULL) {
        return CRYPTO_INVALID_PARAMS;
    }
    *params = (OH_CryptoSymCipherParams *)HcfMalloc(sizeof(OH_CryptoSymCipherParams), 0);
    if (*params == NULL) {
        return CRYPTO_MEMORY_ERROR;
    }
    return CRYPTO_SUCCESS;
}

OH_Crypto_ErrCode OH_CryptoSymCipherParams_Create(OH_CryptoSymCipherParams **params)
{
    return CryptoSymCipherParamsCreate(params);
}

static OH_Crypto_ErrCode CryptoSymCipherParamsSetParam(OH_CryptoSymCipherParams *params,
    CryptoSymCipher_ParamsType paramsType, Crypto_DataBlob *value)
{
    if ((params == NULL) || (value == NULL)) {
        return CRYPTO_INVALID_PARAMS;
    }
    switch (paramsType) {
        case CRYPTO_IV_DATABLOB:
            params->iv.data = value->data;
            params->iv.len = value->len;
            break;
        case CRYPTO_AAD_DATABLOB:
            params->aad.data = value->data;
            params->aad.len = value->len;
            break;
        case CRYPTO_TAG_DATABLOB:
            params->tag.data = value->data;
            params->tag.len = value->len;
            break;
        default:
            return CRYPTO_INVALID_PARAMS;
    }
    return CRYPTO_SUCCESS;
}

OH_Crypto_ErrCode OH_CryptoSymCipherParams_SetParam(OH_CryptoSymCipherParams *params,
    CryptoSymCipher_ParamsType paramsType, Crypto_DataBlob *value)
{
    return CryptoSymCipherParamsSetParam(params, paramsType, value);
}

static void CryptoSymCipherParamsDestroy(OH_CryptoSymCipherParams *params)
{
    if (params == NULL) {
        return;
    }
    HcfFree(params);
}

void OH_CryptoSymCipherParams_Destroy(OH_CryptoSymCipherParams *params)
{
    CryptoSymCipherParamsDestroy(params);
}

static OH_Crypto_ErrCode CryptoSymCipherCreate(const char *algoName, OH_CryptoSymCipher **ctx)
{
    if (ctx == NULL) {
        return CRYPTO_INVALID_PARAMS;
    }
    HcfResult ret = HcfCipherCreate(algoName, (HcfCipher **)ctx);
    return GetOhCryptoErrCode(ret);
}

OH_Crypto_ErrCode OH_CryptoSymCipher_Create(const char *algoName, OH_CryptoSymCipher **ctx)
{
    return CryptoSymCipherCreate(algoName, ctx);
}

static OH_Crypto_ErrCode CryptoSymCipherInit(OH_CryptoSymCipher *ctx, Crypto_CipherMode mod,
    OH_CryptoSymKey *key, OH_CryptoSymCipherParams *params)
{
    if ((ctx == NULL) || (ctx->init == NULL) || (key == NULL)) {
        return CRYPTO_INVALID_PARAMS;
    }
    HcfResult ret = ctx->init((HcfCipher *)ctx, (enum HcfCryptoMode)mod, (HcfKey *)key, (HcfParamsSpec *)params);
    return GetOhCryptoErrCode(ret);
}

OH_Crypto_ErrCode OH_CryptoSymCipher_Init(OH_CryptoSymCipher *ctx, Crypto_CipherMode mod,
    OH_CryptoSymKey *key, OH_CryptoSymCipherParams *params)
{
    return CryptoSymCipherInit(ctx, mod, key, params);
}

static OH_Crypto_ErrCode CryptoSymCipherUpdate(OH_CryptoSymCipher *ctx, Crypto_DataBlob *in, Crypto_DataBlob *out)
{
    if ((ctx == NULL) || (ctx->update == NULL) || (in == NULL) || (out == NULL)) {
        return CRYPTO_INVALID_PARAMS;
    }
    HcfResult ret = ctx->update((HcfCipher *)ctx, (HcfBlob *)in, (HcfBlob *)out);
    return GetOhCryptoErrCode(ret);
}

OH_Crypto_ErrCode OH_CryptoSymCipher_Update(OH_CryptoSymCipher *ctx, Crypto_DataBlob *in, Crypto_DataBlob *out)
{
    return CryptoSymCipherUpdate(ctx, in, out);
}

static OH_Crypto_ErrCode CryptoSymCipherFinal(OH_CryptoSymCipher *ctx, Crypto_DataBlob *in, Crypto_DataBlob *out)
{
    if ((ctx == NULL) || (ctx->doFinal == NULL) || (out == NULL)) {
        return CRYPTO_INVALID_PARAMS;
    }
    HcfResult ret = ctx->doFinal((HcfCipher *)ctx, (HcfBlob *)in, (HcfBlob *)out);
    return GetOhCryptoErrCode(ret);
}

OH_Crypto_ErrCode OH_CryptoSymCipher_Final(OH_CryptoSymCipher *ctx, Crypto_DataBlob *in, Crypto_DataBlob *out)
{
    return CryptoSymCipherFinal(ctx, in, out);
}

static const char *CryptoSymCipherGetAlgoName(OH_CryptoSymCipher *ctx)
{
    if ((ctx == NULL) || (ctx->getAlgorithm == NULL)) {
        return NULL;
    }
    return ctx->getAlgorithm((HcfCipher *)ctx);
}

const char *OH_CryptoSymCipher_GetAlgoName(OH_CryptoSymCipher *ctx)
{
    const char *name = CryptoSymCipherGetAlgoName(ctx);
    return name;
}

static void CryptoSymCipherDestroy(OH_CryptoSymCipher *ctx)
{
    if ((ctx == NULL) || (ctx->base.destroy == NULL)) {
        return;
    }
    ctx->base.destroy((HcfObjectBase *)ctx);
}

void OH_CryptoSymCipher_Destroy(OH_CryptoSymCipher *ctx)
{
    CryptoSymCipherDestroy(ctx);
}
