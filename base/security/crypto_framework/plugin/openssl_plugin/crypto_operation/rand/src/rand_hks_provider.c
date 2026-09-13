/*
 * Copyright (C) 2025 Huawei Device Co., Ltd.
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

#include "rand_hks_provider.h"
#include <string.h>
#include <securec.h>
#include <openssl/core_dispatch.h>
#include <openssl/e_os2.h>
#include <openssl/params.h>
#include <openssl/core_names.h>
#include <openssl/evp.h>
#include <openssl/provider.h>
#include "log.h"
#include "memory.h"

#ifndef IS_ARKUI_X_TARGET
#include "hks_api.h"
#endif

#define MAX_REQUESTS 128
#define STRENGTH 1024
#define ENTROPY_RATE 7
#define INCREASE_OFFSET 7
#define HCF_OPENSSL_SUCCESS 1
#define HCF_OPENSSL_FAILURE 0

typedef struct {
    void *provCtx;
    int state;
} CryptoProSeedSrc;

#ifdef IS_ARKUI_X_TARGET
struct HksBlob {
    uint8_t *data;
    size_t size;
};

static int32_t HksGenerateRandom(void *provCtx, struct HksBlob *randomBlob)
{
    (void)provCtx;
    (void)randomBlob;
    return -1;
}
#endif

static void *CryptoSeedSrcNew(void *provCtx, void *parent, const OSSL_DISPATCH *parentDispatch)
{
    (void)parentDispatch;

    if (parent != NULL) {
        LOGE("parent should be NULL");
        return NULL;
    }

    CryptoProSeedSrc *seedSrc = (CryptoProSeedSrc *)HcfMalloc(sizeof(CryptoProSeedSrc), 0);
    if (seedSrc == NULL) {
        LOGE("Failed to allocate memory for seedSrc");
        return NULL;
    }

    seedSrc->provCtx = provCtx;
    seedSrc->state = EVP_RAND_STATE_UNINITIALISED;

    return seedSrc;
}

static void CryptoSeedSrcFree(void *seedSrc)
{
    HcfFree(seedSrc);
}

static int CryptoSeedSrcInstantiate(void *vSeed, unsigned int strength, int predictionResistance,
    const unsigned char *pStr, uint32_t pStrLen, ossl_unused const OSSL_PARAM params[])
{
    (void)strength;
    (void)predictionResistance;
    (void)pStr;
    (void)pStrLen;
    CryptoProSeedSrc *seedSrc = (CryptoProSeedSrc *)vSeed;
    seedSrc->state = EVP_RAND_STATE_READY;
    return HCF_OPENSSL_SUCCESS;
}

static int CryptoSeedSrcUninstantiate(void *vSeed)
{
    CryptoProSeedSrc *seedSrc = (CryptoProSeedSrc *)vSeed;
    seedSrc->state = EVP_RAND_STATE_UNINITIALISED;
    return HCF_OPENSSL_SUCCESS;
}

static int CryptoSeedSrcGenerate(void *vSeed, unsigned char *out, size_t outLen, unsigned int strength,
    ossl_unused int predictionResistance, ossl_unused const unsigned char *addIn, size_t addInLen)
{
    (void)strength;
    CryptoProSeedSrc *seedSrc = (CryptoProSeedSrc *)vSeed;
    if (seedSrc->state != EVP_RAND_STATE_READY) {
        LOGE("seedSrc is not ready");
        return HCF_OPENSSL_FAILURE;
    }

    if (out == NULL || outLen == 0)  {
        LOGE("out is NULL or outLen is 0");
        return HCF_OPENSSL_FAILURE;
    }

    struct HksBlob randomBlob;
    randomBlob.data = out;
    randomBlob.size = (uint32_t)outLen;
    int32_t result = HksGenerateRandom(NULL, &randomBlob);
    if (result != 0) {
        LOGE("Failed to generate random bytes with error: %{public}d", result);
        return HCF_OPENSSL_FAILURE;
    }
    return HCF_OPENSSL_SUCCESS;
}

static int CryptoSeedSrcReseed(void *vSeed, ossl_unused int predictionResistance, ossl_unused const unsigned char *ent,
    ossl_unused size_t entLen, ossl_unused const unsigned char *addIn, ossl_unused size_t addInLen)
{
    CryptoProSeedSrc *seedSrc = (CryptoProSeedSrc *)vSeed;
    if (seedSrc->state != EVP_RAND_STATE_READY) {
        LOGE("seedSrc is not ready");
        return HCF_OPENSSL_FAILURE;
    }
    return HCF_OPENSSL_SUCCESS;
}

static int CryptoSeedSrcGetCtxParams(void *vSeed, OSSL_PARAM params[])
{
    CryptoProSeedSrc *seedSrc = (CryptoProSeedSrc *)vSeed;
    OSSL_PARAM *p = OSSL_PARAM_locate(params, OSSL_RAND_PARAM_MAX_REQUEST);
    if (p != NULL && !OSSL_PARAM_set_size_t(p, MAX_REQUESTS)) {
        LOGE("Failed to set max requests");
        return HCF_OPENSSL_FAILURE;
    }

    p = OSSL_PARAM_locate(params, OSSL_RAND_PARAM_STRENGTH);
    if (p != NULL && !OSSL_PARAM_set_size_t(p, STRENGTH)) {
        LOGE("Failed to set strength");
        return HCF_OPENSSL_FAILURE;
    }

    p = OSSL_PARAM_locate(params, OSSL_RAND_PARAM_STATE);
    if (p != NULL && !OSSL_PARAM_set_int(p, seedSrc->state)) {
        LOGE("Failed to set state");
        return HCF_OPENSSL_FAILURE;
    }
    return HCF_OPENSSL_SUCCESS;
}

static const OSSL_PARAM *CryptoSeedSrcGettableCtxParams(ossl_unused void *vSeed, ossl_unused void *provCtx)
{
    static const OSSL_PARAM params[] = {
        OSSL_PARAM_uint(OSSL_RAND_PARAM_STRENGTH, NULL),
        OSSL_PARAM_uint(OSSL_RAND_PARAM_MAX_REQUEST, NULL),
        OSSL_PARAM_uint(OSSL_RAND_PARAM_STATE, NULL),
        OSSL_PARAM_END
    };
    return params;
}

static int CryptoSeedSrcVerifyZeroization(ossl_unused void *vSeed)
{
    return HCF_OPENSSL_SUCCESS;
}

static size_t CryptoSeedSrcGetSeed(void *vSeed, unsigned char **pOut, int entropy, size_t minLen, size_t maxLen,
    int predictionResistance, const unsigned char *addIn, size_t addInLen)
{
    size_t bytesNeeded = entropy >= 0 ? ((size_t)entropy + INCREASE_OFFSET) / ENTROPY_RATE : 0;
    if (bytesNeeded < minLen) {
        bytesNeeded = minLen;
    }
    if (bytesNeeded > maxLen) {
        LOGE("bytesNeeded is greater than maxLen");
        return 0;
    }
    unsigned char *p = (unsigned char *)HcfMalloc(bytesNeeded, 0);
    if (p == NULL) {
        LOGE("Failed to allocate memory for p");
        return 0;
    }
    if (CryptoSeedSrcGenerate(vSeed, p, bytesNeeded, 0, predictionResistance, addIn, addInLen) != 0) {
        *pOut = p;
        return bytesNeeded;
    }
    LOGE("Failed to generate crypto seed source.");
    HcfFree(p);
    return 0;
}

static void CryptoSeedSrcClearSeed(ossl_unused void *vdrbg, unsigned char *out, size_t outLen)
{
    (void)memset_s(out, outLen, 0, outLen);
    HcfFree(out);
}

OSSL_DISPATCH g_cryptoOsslSeedRrcFunctions[] = {
    { OSSL_FUNC_RAND_NEWCTX, (void (*)(void))CryptoSeedSrcNew },
    { OSSL_FUNC_RAND_FREECTX, (void (*)(void))CryptoSeedSrcFree },
    { OSSL_FUNC_RAND_INSTANTIATE, (void (*)(void))CryptoSeedSrcInstantiate },
    { OSSL_FUNC_RAND_UNINSTANTIATE, (void (*)(void))CryptoSeedSrcUninstantiate },
    { OSSL_FUNC_RAND_GENERATE, (void (*)(void))CryptoSeedSrcGenerate },
    { OSSL_FUNC_RAND_RESEED, (void (*)(void))CryptoSeedSrcReseed },
    { OSSL_FUNC_RAND_GET_CTX_PARAMS, (void (*)(void))CryptoSeedSrcGetCtxParams },
    { OSSL_FUNC_RAND_GETTABLE_CTX_PARAMS, (void (*)(void))CryptoSeedSrcGettableCtxParams },
    { OSSL_FUNC_RAND_VERIFY_ZEROIZATION, (void (*)(void))CryptoSeedSrcVerifyZeroization },
    { OSSL_FUNC_RAND_GET_SEED, (void (*)(void))CryptoSeedSrcGetSeed },
    { OSSL_FUNC_RAND_CLEAR_SEED, (void (*)(void))CryptoSeedSrcClearSeed },
    { 0, NULL }
};

static const OSSL_ALGORITHM g_gmSeedRrc[] = {
    { "HW-SEED-SRC", CRYPTO_SEED_PROVIDER, g_cryptoOsslSeedRrcFunctions, NULL},
    { NULL, NULL, NULL, NULL }
};

static const OSSL_ALGORITHM *CryptoSeedSrcRandSeedQuery(ossl_unused void *provCtx, int operationId, int *noCache)
{
    *noCache = 0;
    if (operationId == OSSL_OP_RAND) {
        return g_gmSeedRrc;
    }

    return NULL;
}

static const OSSL_DISPATCH RandSeedMethod[] = {
    { OSSL_FUNC_PROVIDER_QUERY_OPERATION, (void (*)(void))CryptoSeedSrcRandSeedQuery },
    { 0, NULL }
};

static int CryptoSeedSrcSeedProviderInit(ossl_unused const OSSL_CORE_HANDLE *handle,
    ossl_unused const OSSL_DISPATCH *in, const OSSL_DISPATCH **out, ossl_unused void **provCtx)
{
    *out = RandSeedMethod;
    return HCF_OPENSSL_SUCCESS;
}

int32_t HcfCryptoLoadSeedProvider(OSSL_LIB_CTX *libCtx, OSSL_PROVIDER **seedProvider)
{
    if (libCtx == NULL) {
        LOGE("Invalid parameters");
        return HCF_OPENSSL_FAILURE;
    }

    if (OSSL_PROVIDER_add_builtin(libCtx, CRYPTO_SEED_PROVIDER, CryptoSeedSrcSeedProviderInit) != 1) {
        LOGE("Failed to add seed provider");
        return HCF_OPENSSL_FAILURE;
    }

    *seedProvider = OSSL_PROVIDER_try_load(libCtx, CRYPTO_SEED_PROVIDER, 1);
    if (*seedProvider == NULL) {
        LOGE("Failed to load seed provider");
        return HCF_OPENSSL_FAILURE;
    }

    return HCF_OPENSSL_SUCCESS;
}

void HcfCryptoUnloadSeedProvider(OSSL_PROVIDER **seedProvider)
{
    if (seedProvider == NULL || *seedProvider == NULL) {
        return;
    }
    (void)OSSL_PROVIDER_unload(*seedProvider);
    *seedProvider = NULL;
}
