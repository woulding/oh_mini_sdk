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

#include "crypto_digest.h"
#include "md.h"
#include "crypto_common.h"
#include "blob.h"
#include "object_base.h"
#include "result.h"
#include "native_common.h"

struct OH_CryptoDigest {
    HcfObjectBase base;

    HcfResult (*update)(HcfMd *self, HcfBlob *input);

    HcfResult (*doFinal)(HcfMd *self, HcfBlob *output);

    uint32_t (*getMdLength)(HcfMd *self);

    const char *(*getAlgoName)(HcfMd *self);
};

static OH_Crypto_ErrCode CryptoDigestCreate(const char *algoName, OH_CryptoDigest **ctx)
{
    if (ctx == NULL) {
        return CRYPTO_INVALID_PARAMS;
    }
    HcfResult ret = HcfMdCreate(algoName, (HcfMd **)ctx);
    return GetOhCryptoErrCode(ret);
}

OH_Crypto_ErrCode OH_CryptoDigest_Create(const char *algoName, OH_CryptoDigest **ctx)
{
    return CryptoDigestCreate(algoName, ctx);
}

static OH_Crypto_ErrCode CryptoDigestUpdate(OH_CryptoDigest *ctx, Crypto_DataBlob *in)
{
    if ((ctx == NULL) || (ctx->update == NULL) || (in == NULL)) {
        return CRYPTO_INVALID_PARAMS;
    }
    HcfResult ret = ctx->update((HcfMd *)ctx, (HcfBlob *)in);
    return GetOhCryptoErrCode(ret);
}

OH_Crypto_ErrCode OH_CryptoDigest_Update(OH_CryptoDigest *ctx, Crypto_DataBlob *in)
{
    return CryptoDigestUpdate(ctx, in);
}

static OH_Crypto_ErrCode CryptoDigestFinal(OH_CryptoDigest *ctx, Crypto_DataBlob *out)
{
    if ((ctx == NULL) || (ctx->doFinal == NULL) || (out == NULL)) {
        return CRYPTO_INVALID_PARAMS;
    }
    HcfResult ret = ctx->doFinal((HcfMd *)ctx, (HcfBlob *)out);
    return GetOhCryptoErrCode(ret);
}

OH_Crypto_ErrCode OH_CryptoDigest_Final(OH_CryptoDigest *ctx, Crypto_DataBlob *out)
{
    return CryptoDigestFinal(ctx, out);
}

static uint32_t CryptoDigestGetLength(OH_CryptoDigest *ctx)
{
    if ((ctx == NULL) || (ctx->getMdLength == NULL)) {
        return CRYPTO_INVALID_PARAMS;
    }
    return ctx->getMdLength((HcfMd *)ctx);
}

uint32_t OH_CryptoDigest_GetLength(OH_CryptoDigest *ctx)
{
    uint32_t result = CryptoDigestGetLength(ctx);
    return result;
}

static const char *CryptoDigestGetAlgoName(OH_CryptoDigest *ctx)
{
    if ((ctx == NULL) || (ctx->getAlgoName == NULL)) {
        return NULL;
    }
    return ctx->getAlgoName((HcfMd *)ctx);
}

const char *OH_CryptoDigest_GetAlgoName(OH_CryptoDigest *ctx)
{
    const char *name = CryptoDigestGetAlgoName(ctx);
    return name;
}

static void DigestCryptoDestroy(OH_CryptoDigest *ctx)
{
    if ((ctx == NULL) || (ctx->base.destroy == NULL)) {
        return;
    }
    ctx->base.destroy((HcfObjectBase *)ctx);
}

void OH_DigestCrypto_Destroy(OH_CryptoDigest *ctx)
{
    DigestCryptoDestroy(ctx);
}
