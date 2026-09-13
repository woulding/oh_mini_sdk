/*
 * Copyright (C) 2026 Huawei Device Co., Ltd.
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

#include "kem.h"

#include <securec.h>
#include <string.h>

#include "config.h"
#include "kem_openssl.h"
#include "kem_spi.h"
#include "log.h"
#include "memory.h"
#include "utils.h"

typedef HcfResult (*HcfKemSpiCreateFunc)(const char *algoName, HcfKemSpi **returnObj);

typedef struct {
    HcfKem base;
    HcfKemSpi *spiObj;
    char algoName[HCF_MAX_ALGO_NAME_LEN];
} HcfKemImpl;

typedef struct {
    const char *algoName;
    HcfKemSpiCreateFunc createSpiFunc;
} HcfKemAbility;

static const HcfKemAbility KEM_ABILITY_SET[] = {
    { "ML-KEM512", HcfKemSpiCreateOpenssl },
    { "ML-KEM768", HcfKemSpiCreateOpenssl },
    { "ML-KEM1024", HcfKemSpiCreateOpenssl }
};

static HcfKemSpiCreateFunc FindAbility(const char *algoName)
{
    if (algoName == NULL) {
        LOGE("AlgoName is null");
        return NULL;
    }
    for (uint32_t i = 0; i < sizeof(KEM_ABILITY_SET) / sizeof(KEM_ABILITY_SET[0]); i++) {
        if (strcmp(KEM_ABILITY_SET[i].algoName, algoName) == 0) {
            return KEM_ABILITY_SET[i].createSpiFunc;
        }
    }
    LOGE("No matching KEM ability found");
    return NULL;
}

static const char *GetKemClass(void)
{
    return "HcfKem";
}

static HcfResult Encapsulate(HcfKem *self, HcfPubKey *pubKey, const HcfBlob *ikme,
    HcfBlob *returnSharedSecret, HcfBlob *returnWrappedKey)
{
    if (self == NULL || pubKey == NULL || returnSharedSecret == NULL || returnWrappedKey == NULL) {
        LOGE("Self, pubKey, returnSharedSecret or returnWrappedKey is null");
        return HCF_ERR_PARAMETER_CHECK_FAILED;
    }
    if (!HcfIsClassMatch((HcfObjectBase *)self, GetKemClass())) {
        return HCF_ERR_PARAMETER_CHECK_FAILED;
    }

    return ((HcfKemImpl *)self)->spiObj->engineEncapsulate(((HcfKemImpl *)self)->spiObj, pubKey, ikme,
        returnSharedSecret, returnWrappedKey);
}

static HcfResult Decapsulate(HcfKem *self, HcfPriKey *priKey, const HcfBlob *wrappedKey, HcfBlob *returnSharedSecret)
{
    if (self == NULL || priKey == NULL || wrappedKey == NULL || returnSharedSecret == NULL) {
        LOGE("Self, priKey, wrappedKey or returnSharedSecret is null");
        return HCF_ERR_PARAMETER_CHECK_FAILED;
    }
    if (!HcfIsClassMatch((HcfObjectBase *)self, GetKemClass())) {
        return HCF_ERR_PARAMETER_CHECK_FAILED;
    }
    if (!HcfIsBlobValid(wrappedKey)) {
        LOGE("WrappedKey data is invalid");
        return HCF_ERR_PARAMETER_CHECK_FAILED;
    }

    return ((HcfKemImpl *)self)->spiObj->engineDecapsulate(((HcfKemImpl *)self)->spiObj, priKey, wrappedKey,
        returnSharedSecret);
}

static void DestroyKem(HcfObjectBase *self)
{
    if (self == NULL) {
        return;
    }
    if (!HcfIsClassMatch(self, GetKemClass())) {
        return;
    }
    HcfKemImpl *impl = (HcfKemImpl *)self;
    HcfObjDestroy(impl->spiObj);
    impl->spiObj = NULL;
    HcfFree(impl);
}

HcfResult HcfKemCreate(const char *algoName, HcfKem **returnObj)
{
    if (!HcfIsStrValid(algoName, HCF_MAX_ALGO_NAME_LEN) || returnObj == NULL) {
        LOGE("AlgoName is invalid or returnObj is null");
        return HCF_ERR_PARAMETER_CHECK_FAILED;
    }

    HcfKemSpiCreateFunc createSpiFunc = FindAbility(algoName);
    if (createSpiFunc == NULL) {
        LOGE("Not support KEM algo: %{public}s", algoName);
        return HCF_ERR_PARAMETER_CHECK_FAILED;
    }

    HcfKemImpl *impl = (HcfKemImpl *)HcfMalloc(sizeof(HcfKemImpl), 0);
    if (impl == NULL) {
        LOGE("Failed to allocate KEM object.");
        return HCF_ERR_MALLOC;
    }
    if (strcpy_s(impl->algoName, HCF_MAX_ALGO_NAME_LEN, algoName) != EOK) {
        LOGE("Failed to copy algoName");
        HcfFree(impl);
        return HCF_ERR_PARAMETER_CHECK_FAILED;
    }

    HcfKemSpi *spiObj = NULL;
    HcfResult res = createSpiFunc(algoName, &spiObj);
    if (res != HCF_SUCCESS) {
        LOGE("Failed to create KEM spi object");
        HcfFree(impl);
        return res;
    }

    impl->base.base.getClass = GetKemClass;
    impl->base.base.destroy = DestroyKem;
    impl->base.encapsulate = Encapsulate;
    impl->base.decapsulate = Decapsulate;
    impl->spiObj = spiObj;
    *returnObj = (HcfKem *)impl;
    return HCF_SUCCESS;
}
