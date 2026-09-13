/*
 * Copyright (C) 2022-2023 Huawei Device Co., Ltd.
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

#include "rand.h"

#include <limits.h>
#include <securec.h>
#include "rand_spi.h"
#ifdef CRYPTO_MBEDTLS
#include "mbedtls_rand.h"
#else
#include "rand_openssl.h"
#endif
#include "log.h"
#include "config.h"
#include "memory.h"
#include "utils.h"

typedef HcfResult (*HcfRandSpiCreateFunc)(HcfRandSpi **);

typedef struct {
    HcfRand base;

    HcfRandSpi *spiObj;

    const char *algoName;
} HcfRandImpl;

typedef struct {
    char *algoName;

    HcfRandSpiCreateFunc createSpiFunc;
} HcfRandAbility;

static const char *GetRandClass(void)
{
    return "Rand";
}

static const HcfRandAbility RAND_ABILITY_SET[] = {
#ifdef CRYPTO_MBEDTLS
    { "MbedtlsRand", MbedtlsRandSpiCreate }
#else
    { "OpensslRand", HcfRandSpiCreate }
#endif
};

static HcfRandSpiCreateFunc FindAbility(const char *algoName)
{
    for (uint32_t i = 0; i < (sizeof(RAND_ABILITY_SET) / sizeof(RAND_ABILITY_SET[0])); i++) {
        if (strcmp(RAND_ABILITY_SET[i].algoName, algoName) == 0) {
            return RAND_ABILITY_SET[i].createSpiFunc;
        }
    }
    LOGE("Algo not support! [Algo]: %{public}s", algoName);
    return NULL;
}

static HcfResult GenerateRandom(HcfRand *self, int32_t numBytes, HcfBlob *random)
{
    if ((self == NULL) || (random == NULL)) {
        LOGE("Invalid params!");
        return HCF_INVALID_PARAMS;
    }
    if (numBytes <= 0) {
        LOGE("Invalid numBytes!");
        return HCF_INVALID_PARAMS;
    }
    if (!HcfIsClassMatch((HcfObjectBase *)self, GetRandClass())) {
        LOGE("Class is not match.");
        return HCF_INVALID_PARAMS;
    }
    return ((HcfRandImpl *)self)->spiObj->engineGenerateRandom(
        ((HcfRandImpl *)self)->spiObj, numBytes, random);
}

static const char *GetAlgoName(HcfRand *self)
{
    if (self == NULL) {
        LOGE("The input self ptr is NULL!");
        return NULL;
    }
    if (!HcfIsClassMatch((HcfObjectBase *)self, GetRandClass())) {
        LOGE("Class is not match!");
        return NULL;
    }
    return ((HcfRandImpl *)self)->spiObj->engineGetAlgoName(((HcfRandImpl *)self)->spiObj);
}

static HcfResult SetSeed(HcfRand *self, HcfBlob *seed)
{
    if ((self == NULL) || (!HcfIsBlobValid(seed)) || (seed->len > INT_MAX)) {
        LOGE("The input self ptr is NULL!");
        return HCF_INVALID_PARAMS;
    }
    if (!HcfIsClassMatch((HcfObjectBase *)self, GetRandClass())) {
        LOGE("Class is not match.");
        return HCF_INVALID_PARAMS;
    }
    ((HcfRandImpl *)self)->spiObj->engineSetSeed(
        ((HcfRandImpl *)self)->spiObj, seed);
    return HCF_SUCCESS;
}

static HcfResult EnableHardwareEntropy(HcfRand *self)
{
    if (self == NULL) {
        LOGE("The input self ptr is NULL!");
        return HCF_ERR_PARAMETER_CHECK_FAILED;
    }
    if (!HcfIsClassMatch((HcfObjectBase *)self, GetRandClass())) {
        LOGE("Class is not match.");
        return HCF_ERR_PARAMETER_CHECK_FAILED;
    }
    return ((HcfRandImpl *)self)->spiObj->engineEnableHardwareEntropy(
        ((HcfRandImpl *)self)->spiObj);
}

static void HcfRandDestroy(HcfObjectBase *self)
{
    if (self == NULL) {
        LOGE("The input self ptr is NULL!");
        return;
    }
    if (!HcfIsClassMatch((HcfObjectBase *)self, GetRandClass())) {
        LOGE("Class is not match.");
        return;
    }
    HcfRandImpl *impl = (HcfRandImpl *)self;
    HcfObjDestroy(impl->spiObj);
    impl->spiObj = NULL;
    HcfFree(impl);
}

HcfResult HcfRandCreate(HcfRand **random)
{
    if (random == NULL) {
        LOGE("Invalid input params while creating rand!");
        return HCF_INVALID_PARAMS;
    }
#ifdef CRYPTO_MBEDTLS
    HcfRandSpiCreateFunc createSpiFunc = FindAbility("MbedtlsRand");
#else
    HcfRandSpiCreateFunc createSpiFunc = FindAbility("OpensslRand");
#endif
    if (createSpiFunc == NULL) {
        LOGE("Algo not supported!");
        return HCF_NOT_SUPPORT;
    }
    HcfRandImpl *returnRandApi = (HcfRandImpl *)HcfMalloc(sizeof(HcfRandImpl), 0);
    if (returnRandApi == NULL) {
        LOGE("Failed to allocate Rand Obj memory!");
        return HCF_ERR_MALLOC;
    }
    HcfRandSpi *spiObj = NULL;
    HcfResult res = createSpiFunc(&spiObj);
    if (res != HCF_SUCCESS) {
        LOGE("Failed to create spi object!");
        HcfFree(returnRandApi);
        returnRandApi = NULL;
        return res;
    }
    returnRandApi->base.base.getClass = GetRandClass;
    returnRandApi->base.base.destroy = HcfRandDestroy;
    returnRandApi->base.generateRandom = GenerateRandom;
    returnRandApi->base.getAlgoName = GetAlgoName;
    returnRandApi->base.setSeed = SetSeed;
    returnRandApi->base.enableHardwareEntropy = EnableHardwareEntropy;
    returnRandApi->spiObj = spiObj;
    *random = (HcfRand *)returnRandApi;
    return HCF_SUCCESS;
}