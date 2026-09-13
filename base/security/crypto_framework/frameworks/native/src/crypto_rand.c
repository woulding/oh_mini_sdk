/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include "crypto_rand.h"
#include <stdint.h>
#include "memory.h"
#include "result.h"
#include "blob.h"
#include "object_base.h"
#include "native_common.h"
#include "crypto_common.h"
#include "rand.h"

typedef struct OH_CryptoRand {
    HcfObjectBase base;

    const char *(*getAlgoName)(HcfRand *self);

    HcfResult (*generateRandom)(HcfRand *self, int32_t numBytes, HcfBlob *random);

    HcfResult (*setSeed)(HcfRand *self, HcfBlob *seed);

    HcfResult (*enableHardwareEntropy)(HcfRand *self);
} OH_CryptoRand;

static OH_Crypto_ErrCode CryptoRandCreate(OH_CryptoRand **ctx)
{
    if (ctx == NULL) {
        return CRYPTO_PARAMETER_CHECK_FAILED;
    }
    HcfResult ret = HcfRandCreate((HcfRand **)ctx);
    return GetOhCryptoErrCodeNew(ret);
}

OH_Crypto_ErrCode OH_CryptoRand_Create(OH_CryptoRand **ctx)
{
    return CryptoRandCreate(ctx);
}

static OH_Crypto_ErrCode CryptoRandGenerateRandom(OH_CryptoRand *ctx, int len, Crypto_DataBlob *out)
{
    if ((ctx == NULL) || (ctx->generateRandom == NULL) || (out == NULL)) {
        return CRYPTO_PARAMETER_CHECK_FAILED;
    }
    HcfResult ret = ctx->generateRandom((HcfRand *)ctx, len, (HcfBlob *)out);
    return GetOhCryptoErrCodeNew(ret);
}

OH_Crypto_ErrCode OH_CryptoRand_GenerateRandom(OH_CryptoRand *ctx, int len, Crypto_DataBlob *out)
{
    return CryptoRandGenerateRandom(ctx, len, out);
}

static const char *CryptoRandGetAlgoName(OH_CryptoRand *ctx)
{
    if ((ctx == NULL) || (ctx->getAlgoName == NULL)) {
        return NULL;
    }
    return ctx->getAlgoName((HcfRand *)ctx);
}

const char *OH_CryptoRand_GetAlgoName(OH_CryptoRand *ctx)
{
    const char *name = CryptoRandGetAlgoName(ctx);
    return name;
}

static OH_Crypto_ErrCode CryptoRandSetSeed(OH_CryptoRand *ctx, Crypto_DataBlob *seed)
{
    if ((ctx == NULL) || (ctx->setSeed == NULL)) {
        return CRYPTO_PARAMETER_CHECK_FAILED;
    }
    HcfResult ret = ctx->setSeed((HcfRand *)ctx, (HcfBlob *)seed);
    return GetOhCryptoErrCodeNew(ret);
}

OH_Crypto_ErrCode OH_CryptoRand_SetSeed(OH_CryptoRand *ctx, Crypto_DataBlob *seed)
{
    return CryptoRandSetSeed(ctx, seed);
}

static OH_Crypto_ErrCode CryptoRandEnableHardwareEntropy(OH_CryptoRand *ctx)
{
    if ((ctx == NULL) || (ctx->enableHardwareEntropy == NULL)) {
        return CRYPTO_PARAMETER_CHECK_FAILED;
    }
    HcfResult ret = ctx->enableHardwareEntropy((HcfRand *)ctx);
    return GetOhCryptoErrCodeNew(ret);
}

OH_Crypto_ErrCode OH_CryptoRand_EnableHardwareEntropy(OH_CryptoRand *ctx)
{
    return CryptoRandEnableHardwareEntropy(ctx);
}

static void CryptoRandDestroy(OH_CryptoRand *ctx)
{
    HcfObjDestroy((HcfRand *)ctx);
}

void OH_CryptoRand_Destroy(OH_CryptoRand *ctx)
{
    CryptoRandDestroy(ctx);
}
