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

#include "rand_openssl.h"

#include "openssl_adapter.h"
#include "openssl_common.h"
#include "securec.h"
#include "log.h"
#include "memory.h"
#include "utils.h"
#include "rand_hks_provider.h"

typedef struct {
    HcfRandSpi base;
    bool isHardwareEntropyEnabled;
} HcfRandSpiImpl;

static const char *GetRandOpenSSLClass(void)
{
    return "RandOpenssl";
}

static void FreeRandCtx(bool isHardwareEntropyEnabled, OSSL_LIB_CTX **libCtx, OSSL_PROVIDER **seedProvider)
{
    if (!isHardwareEntropyEnabled) {
        return;
    }
    HcfCryptoUnloadSeedProvider(seedProvider);
    if (libCtx != NULL && *libCtx != NULL) {
        OSSL_LIB_CTX_free(*libCtx);
        *libCtx = NULL;
    }
}

static HcfResult CreateRandCtx(bool isHardwareEntropyEnabled, OSSL_LIB_CTX **libCtx, OSSL_PROVIDER **seedProvider)
{
    if (!isHardwareEntropyEnabled) {
        LOGD("Hardware entropy is disabled");
        return HCF_SUCCESS;
    }

    *libCtx = OSSL_LIB_CTX_new();
    if (*libCtx == NULL) {
        LOGE("Failed to create context");
        return HCF_ERR_CRYPTO_OPERATION;
    }
    int32_t ret = HcfCryptoLoadSeedProvider(*libCtx, seedProvider);
    if (ret != HCF_OPENSSL_SUCCESS) {
        LOGE("Failed to load seed provider");
        OSSL_LIB_CTX_free(*libCtx);
        *libCtx = NULL;
        return HCF_ERR_CRYPTO_OPERATION;
    }
    ret = OpensslRandSetSeedSourceType(*libCtx, "HW-SEED-SRC", CRYPTO_SEED_PROVIDER);
    if (ret != HCF_OPENSSL_SUCCESS) {
        LOGE("Failed to set seed source type");
        FreeRandCtx(isHardwareEntropyEnabled, libCtx, seedProvider);
        return HCF_ERR_CRYPTO_OPERATION;
    }
    return HCF_SUCCESS;
}

static HcfResult OpensslGenerateRandom(HcfRandSpi *self, int32_t numBytes, HcfBlob *random)
{
    if ((self == NULL) || (random == NULL) || (numBytes <= 0)) {
        LOGE("Invalid params!");
        return HCF_INVALID_PARAMS;
    }

    OSSL_LIB_CTX *libCtx = NULL;
    OSSL_PROVIDER *seedProvider = NULL;
    bool isHardwareEntropyEnabled = ((HcfRandSpiImpl *)self)->isHardwareEntropyEnabled;
    HcfResult res = CreateRandCtx(isHardwareEntropyEnabled, &libCtx, &seedProvider);
    if (res != HCF_SUCCESS) {
        LOGE("Create random context failed!");
        return res;
    }

    random->data = (uint8_t *)HcfMalloc(numBytes, 0);
    if (random->data == NULL) {
        LOGE("Failed to allocate random->data memory!");
        FreeRandCtx(isHardwareEntropyEnabled, &libCtx, &seedProvider);
        return HCF_ERR_MALLOC;
    }

    int32_t ret = OpensslRandPrivBytesEx(libCtx, random->data, numBytes);
    FreeRandCtx(isHardwareEntropyEnabled, &libCtx, &seedProvider);
    if (ret != HCF_OPENSSL_SUCCESS) {
        LOGE("Failed to generate random bytes with %{public}s entropy", isHardwareEntropyEnabled ? "hardware" :
            "software");
        if (!isHardwareEntropyEnabled) {
            HcfPrintOpensslError();
        }
        HcfBlobDataFree(random);
        return HCF_ERR_CRYPTO_OPERATION;
    }
    LOGD("Successfully generated %{public}d random bytes with %{public}s entropy", numBytes,
        isHardwareEntropyEnabled ? "hardware" : "software");
    random->len = numBytes;
    return HCF_SUCCESS;
}

static HcfResult EnableHardwareEntropy(HcfRandSpi *self)
{
    if (self == NULL) {
        LOGE("Invalid input parameter.");
        return HCF_ERR_PARAMETER_CHECK_FAILED;
    }

    HcfRandSpiImpl *impl = (HcfRandSpiImpl *)self;
    impl->isHardwareEntropyEnabled = true;
    LOGD("Hardware entropy enabled successfully");
    return HCF_SUCCESS;
}

static const char *GetRandAlgoName(HcfRandSpi *self)
{
    if (self == NULL) {
        LOGE("Invalid input parameter.");
        return NULL;
    }
    if (!HcfIsClassMatch((HcfObjectBase *)self, GetRandOpenSSLClass())) {
        LOGE("Class is not match.");
        return NULL;
    }

    return OPENSSL_RAND_ALGORITHM;
}

static void OpensslSetSeed(HcfRandSpi *self, HcfBlob *seed)
{
    (void)self;
    if (seed == NULL) {
        LOGE("The seed is NULL!");
        return;
    }
    OpensslRandSeed(seed->data, seed->len);
}

static void DestroyRandOpenssl(HcfObjectBase *self)
{
    if (self == NULL) {
        LOGE("Self ptr is NULL!");
        return;
    }
    if (!HcfIsClassMatch(self, GetRandOpenSSLClass())) {
        LOGE("Class is not match.");
        return;
    }
    HcfFree(self);
}

HcfResult HcfRandSpiCreate(HcfRandSpi **spiObj)
{
    if (spiObj == NULL) {
        LOGE("Invalid input parameter.");
        return HCF_INVALID_PARAMS;
    }
    HcfRandSpiImpl *returnSpiImpl = (HcfRandSpiImpl *)HcfMalloc(sizeof(HcfRandSpiImpl), 0);
    if (returnSpiImpl == NULL) {
        LOGE("Failed to allocate returnImpl memory!");
        return HCF_ERR_MALLOC;
    }
    returnSpiImpl->base.base.getClass = GetRandOpenSSLClass;
    returnSpiImpl->base.base.destroy = DestroyRandOpenssl;
    returnSpiImpl->base.engineGenerateRandom = OpensslGenerateRandom;
    returnSpiImpl->base.engineSetSeed = OpensslSetSeed;
    returnSpiImpl->base.engineGetAlgoName = GetRandAlgoName;
    returnSpiImpl->base.engineEnableHardwareEntropy = EnableHardwareEntropy;
    returnSpiImpl->isHardwareEntropyEnabled = false;
    *spiObj = (HcfRandSpi *)returnSpiImpl;
    return HCF_SUCCESS;
}