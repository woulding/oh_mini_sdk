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

#include "mbedtls_rand.h"

#include "mbedtls/entropy.h"
#include "mbedtls/ctr_drbg.h"
#include "securec.h"
#include "log.h"
#include "memory.h"
#include "utils.h"

typedef struct {
    HcfRandSpi base;
    mbedtls_entropy_context *entropy;
    mbedtls_ctr_drbg_context *ctrDrbg;
} HcfRandSpiImpl;

static const char *GetMbedtlsRandClass(void)
{
    return "RandMbedtls";
}

static mbedtls_entropy_context *MbedtlsGetMdEntropy(HcfRandSpi *self)
{
    if (!HcfIsClassMatch((HcfObjectBase *)self, GetMbedtlsRandClass())) {
        LOGE("Class is not match.");
        return NULL;
    }

    return ((HcfRandSpiImpl *)self)->entropy;
}

static mbedtls_ctr_drbg_context *MbedtlsGetMdCtrDrbg(HcfRandSpi *self)
{
    if (!HcfIsClassMatch((HcfObjectBase *)self, GetMbedtlsRandClass())) {
        LOGE("Class is not match.");
        return NULL;
    }
    return ((HcfRandSpiImpl *)self)->ctrDrbg;
}

static HcfResult MbedtlsGenerateRandom(HcfRandSpi *self, int32_t numBytes, HcfBlob *random)
{
    if ((self == NULL) || (random == NULL)) {
        LOGE("Invalid params!");
        return HCF_INVALID_PARAMS;
    }
    if (numBytes <= 0) {
        LOGE("Invalid numBytes!");
        return HCF_INVALID_PARAMS;
    }
    mbedtls_ctr_drbg_context *ctrDrbg = MbedtlsGetMdCtrDrbg(self);
    if (ctrDrbg == NULL) {
        LOGE("Invalid ctrDrbg null!");
        return HCF_INVALID_PARAMS;
    }
    random->data = (uint8_t *)HcfMalloc(numBytes, 0);
    if (random->data == NULL) {
        LOGE("Failed to allocate random->data memory!");
        return HCF_ERR_MALLOC;
    }
    int32_t ret = mbedtls_ctr_drbg_random(ctrDrbg, random->data, numBytes);
    if (ret != 0) {
        LOGE("RAND_bytes return is %d error!", ret);
        HcfFree(random->data);
        random->data = NULL;
        return HCF_ERR_CRYPTO_OPERATION;
    }
    random->len = numBytes;

    return HCF_SUCCESS;
}

static const char *MbedtlsGetRandAlgoName(HcfRandSpi *self)
{
    if (self == NULL) {
        LOGE("Invalid input parameter.");
        return NULL;
    }
    if (!HcfIsClassMatch((HcfObjectBase *)self, GetMbedtlsRandClass())) {
        LOGE("Class is not match.");
        return NULL;
    }

    return MBEDTLS_RAND_ALGORITHM;
}

static void MbedtlsSetSeed(HcfRandSpi *self, HcfBlob *seed)
{
    if ((self == NULL) || (seed == NULL)) {
        LOGE("Invalid params!");
        return;
    }
    if ((seed->data == NULL) || (seed->len == 0)) {
        LOGE("Invalid numBytes!");
        return;
    }
    mbedtls_ctr_drbg_context *ctrDrbg = MbedtlsGetMdCtrDrbg(self);
    if (ctrDrbg == NULL) {
        LOGE("Invalid ctrDrbg params!");
        return;
    }
    mbedtls_entropy_context *entropy = MbedtlsGetMdEntropy(self);
    if (entropy == NULL) {
        LOGE("Invalid entropy params!");
        return;
    }
    int32_t ret = mbedtls_ctr_drbg_seed(ctrDrbg, mbedtls_entropy_func, entropy,
        (const unsigned char *)seed->data, seed->len);
    if (ret != 0) {
        LOGE("seed return is %d error!", ret);
        return;
    }
}

static void DestroyMbedtlsRand(HcfObjectBase *self)
{
    if (self == NULL) {
        LOGE("Self ptr is NULL!");
        return;
    }
    if (!HcfIsClassMatch(self, GetMbedtlsRandClass())) {
        LOGE("Class is not match.");
        return;
    }
    mbedtls_ctr_drbg_context *ctrDrbg = MbedtlsGetMdCtrDrbg((HcfRandSpi *)self);
    if (ctrDrbg != NULL) {
        mbedtls_ctr_drbg_free(ctrDrbg);
        HcfFree(ctrDrbg);
        ctrDrbg = NULL;
    }
    mbedtls_entropy_context *entropy = MbedtlsGetMdEntropy((HcfRandSpi *)self);
    if (entropy != NULL) {
        mbedtls_entropy_free(entropy);
        HcfFree(entropy);
        entropy = NULL;
    }
    HcfFree(self);
}

static int32_t MbedtlsRandInitEx(mbedtls_entropy_context **entropy, mbedtls_ctr_drbg_context **ctrDrbg)
{
    if ((entropy == NULL) || (ctrDrbg == NULL)) {
        LOGE("Invalid input parameter.");
        return HCF_INVALID_PARAMS;
    }
    *entropy = (mbedtls_entropy_context *)HcfMalloc(sizeof(mbedtls_entropy_context), 0);
    if (*entropy == NULL) {
        LOGE("Failed to allocate *entropy memory!");
        return HCF_ERR_MALLOC;
    }
    *ctrDrbg = (mbedtls_ctr_drbg_context *)HcfMalloc(sizeof(mbedtls_ctr_drbg_context), 0);
    if (*ctrDrbg == NULL) {
        HcfFree(*entropy);
        *entropy = NULL;
        LOGE("Failed to allocate *ctrDrbg memory!");
        return HCF_ERR_MALLOC;
    }
    mbedtls_entropy_init(*entropy);
    mbedtls_ctr_drbg_init(*ctrDrbg);
    int32_t ret = mbedtls_ctr_drbg_seed(*ctrDrbg, mbedtls_entropy_func, *entropy, NULL, 0);
    if (ret != 0) {
        LOGE("Failed seed ret is %d!", ret);
        mbedtls_entropy_free(*entropy);
        mbedtls_ctr_drbg_free(*ctrDrbg);
        HcfFree(*entropy);
        *entropy = NULL;
        HcfFree(*ctrDrbg);
        *ctrDrbg = NULL;
        return HCF_ERR_CRYPTO_OPERATION;
    }

    return HCF_SUCCESS;
}

HcfResult MbedtlsRandSpiCreate(HcfRandSpi **spiObj)
{
    if (spiObj == NULL) {
        LOGE("Invalid input parameter.");
        return HCF_INVALID_PARAMS;
    }
    HcfRandSpiImpl *returnSpiImpl = (HcfRandSpiImpl *)HcfMalloc(sizeof(HcfRandSpiImpl), 0);
    if (returnSpiImpl == NULL) {
        LOGE("Failed to allocate *returnSpiImpl memory!");
        return HCF_ERR_MALLOC;
    }
    int32_t ret = MbedtlsRandInitEx(&(returnSpiImpl->entropy), &(returnSpiImpl->ctrDrbg));
    if (ret != HCF_SUCCESS) {
        LOGE("Failed to allocate entropy ctrDrbg memory!");
        HcfFree(returnSpiImpl);
        returnSpiImpl = NULL;
        return HCF_ERR_MALLOC;
    }
    returnSpiImpl->base.base.getClass = GetMbedtlsRandClass;
    returnSpiImpl->base.base.destroy = DestroyMbedtlsRand;
    returnSpiImpl->base.engineGenerateRandom = MbedtlsGenerateRandom;
    returnSpiImpl->base.engineSetSeed = MbedtlsSetSeed;
    returnSpiImpl->base.engineGetAlgoName = MbedtlsGetRandAlgoName;
    *spiObj = (HcfRandSpi *)returnSpiImpl;

    return HCF_SUCCESS;
}
