/*
 * Copyright (C) 2023-2024 Huawei Device Co., Ltd.
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

#include "mac.h"

#include <securec.h>

#include "mac_spi.h"
#include "mac_openssl.h"
#include "detailed_hmac_params.h"
#include "detailed_cmac_params.h"

#include "log.h"
#include "config.h"
#include "memory.h"
#include "utils.h"

typedef HcfResult (*HcfMacSpiCreateFunc)(HcfMacParamsSpec *, HcfMacSpi **);

typedef struct {
    HcfMac base;

    HcfMacSpi *spiObj;

    char algoName[HCF_MAX_ALGO_NAME_LEN];
} HcfMacImpl;

typedef struct {
    char *mdName;

    HcfMacSpiCreateFunc createSpiFunc;
} HcfHmacAbility;

static const HcfHmacAbility HMAC_ABILITY_SET[] = {
    { "SHA1", OpensslHmacSpiCreate },
    { "SHA224", OpensslHmacSpiCreate },
    { "SHA256", OpensslHmacSpiCreate },
    { "SHA384", OpensslHmacSpiCreate },
    { "SHA512", OpensslHmacSpiCreate },
    { "SHA3-256", OpensslHmacSpiCreate },
    { "SHA3-384", OpensslHmacSpiCreate },
    { "SHA3-512", OpensslHmacSpiCreate },
    { "SM3", OpensslHmacSpiCreate },
    { "MD5", OpensslHmacSpiCreate },
};

static const char *GetMacClass(void)
{
    return "HMAC";
}

static HcfMacSpiCreateFunc FindAbility(const char *mdName)
{
    if (mdName == NULL) {
        LOGE("Invalid mdName: null pointer.");
        return NULL;
    }
    for (uint32_t i = 0; i < (sizeof(HMAC_ABILITY_SET) / sizeof(HMAC_ABILITY_SET[0])); i++) {
        if (strcmp(HMAC_ABILITY_SET[i].mdName, mdName) == 0) {
            return HMAC_ABILITY_SET[i].createSpiFunc;
        }
    }
    LOGE("Algo not support! [Algo]: %{public}s", mdName);
    return NULL;
}

static HcfResult Init(HcfMac *self, const HcfSymKey *key)
{
    if ((self == NULL) || (key == NULL)) {
        LOGE("The input self ptr or key is NULL!");
        return HCF_INVALID_PARAMS;
    }
    if (!HcfIsClassMatch((HcfObjectBase *)self, GetMacClass())) {
        LOGE("Class is not match.");
        return HCF_INVALID_PARAMS;
    }
    return ((HcfMacImpl *)self)->spiObj->engineInitMac(
        ((HcfMacImpl *)self)->spiObj, key);
}

static HcfResult Update(HcfMac *self, HcfBlob *input)
{
    if ((self == NULL) || (!HcfIsBlobValid(input))) {
        LOGE("The input self ptr or dataBlob is NULL!");
        return HCF_INVALID_PARAMS;
    }
    if (!HcfIsClassMatch((HcfObjectBase *)self, GetMacClass())) {
        LOGE("Class is not match.");
        return HCF_INVALID_PARAMS;
    }
    return ((HcfMacImpl *)self)->spiObj->engineUpdateMac(
        ((HcfMacImpl *)self)->spiObj, input);
}

static HcfResult DoFinal(HcfMac *self, HcfBlob *output)
{
    if ((self == NULL) || (output == NULL)) {
        LOGE("The input self ptr or dataBlob is NULL!");
        return HCF_INVALID_PARAMS;
    }
    if (!HcfIsClassMatch((HcfObjectBase *)self, GetMacClass())) {
        LOGE("Class is not match.");
        return HCF_INVALID_PARAMS;
    }
    return ((HcfMacImpl *)self)->spiObj->engineDoFinalMac(
        ((HcfMacImpl *)self)->spiObj, output);
}

static uint32_t GetMacLength(HcfMac *self)
{
    if (self == NULL) {
        LOGE("The input self ptr is NULL!");
        return 0;
    }
    if (!HcfIsClassMatch((HcfObjectBase *)self, GetMacClass())) {
        LOGE("Class is not match.");
        return 0;
    }
    return ((HcfMacImpl *)self)->spiObj->engineGetMacLength(
        ((HcfMacImpl *)self)->spiObj);
}

static const char *GetAlgoName(HcfMac *self)
{
    if (self == NULL) {
        LOGE("The input self ptr is NULL!");
        return NULL;
    }
    if (!HcfIsClassMatch((HcfObjectBase *)self, GetMacClass())) {
        LOGE("Class is not match.");
        return NULL;
    }
    return ((HcfMacImpl *)self)->algoName;
}

static void MacDestroy(HcfObjectBase *self)
{
    if (self == NULL) {
        LOGE("The input self ptr is NULL!");
        return;
    }
    if (!HcfIsClassMatch((HcfObjectBase *)self, GetMacClass())) {
        LOGE("Class is not match.");
        return;
    }
    HcfMacImpl *impl = (HcfMacImpl *)self;
    HcfObjDestroy(impl->spiObj);
    impl->spiObj = NULL;
    HcfFree(impl);
}

static HcfResult SetMacAlgoName(HcfMacImpl *macImpl, const char *algoName)
{
    if (strcpy_s(macImpl->algoName, HCF_MAX_ALGO_NAME_LEN, algoName) != EOK) {
        LOGE("Failed to copy algoName!");
        return HCF_INVALID_PARAMS;
    }
    return HCF_SUCCESS;
}

static HcfResult HandleCmacAlgo(HcfMacImpl *macImpl, const HcfMacParamsSpec *paramsSpec,
    HcfMacSpiCreateFunc *createSpiFunc)
{
    const char *cipherName = ((HcfCmacParamsSpec *)paramsSpec)->cipherName;
    if (cipherName == NULL) {
        LOGE("Invalid cipher name: null pointer.");
        return HCF_INVALID_PARAMS;
    }

    if ((strcmp(cipherName, "AES128") != 0) && (strcmp(cipherName, "AES256") != 0)) {
        LOGE("Unsupported cipher name: %{public}s, only support AES128 and AES256.", cipherName);
        return HCF_INVALID_PARAMS;
    }
    *createSpiFunc = OpensslCmacSpiCreate;
    return SetMacAlgoName(macImpl, paramsSpec->algName);
}

static HcfResult HandleHmacAlgo(HcfMacImpl *macImpl, const HcfMacParamsSpec *paramsSpec,
    HcfMacSpiCreateFunc *createSpiFunc)
{
    const char *mdName = ((HcfHmacParamsSpec *)paramsSpec)->mdName;
    *createSpiFunc = FindAbility(mdName);
    if (*createSpiFunc == NULL) {
        LOGE("Unsupported HMAC algorithm: %{public}s", mdName);
        return HCF_INVALID_PARAMS;
    }
    return SetMacAlgoName(macImpl, paramsSpec->algName);
}

HcfResult HcfMacCreate(HcfMacParamsSpec *paramsSpec, HcfMac **mac)
{
    if (paramsSpec == NULL || !HcfIsStrValid(paramsSpec->algName, HCF_MAX_ALGO_NAME_LEN) || (mac == NULL)) {
        LOGE("Invalid input params while creating mac!");
        return HCF_INVALID_PARAMS;
    }
    HcfMacSpiCreateFunc createSpiFunc = NULL;
    HcfMacImpl *returnMacApi = (HcfMacImpl *)HcfMalloc(sizeof(HcfMacImpl), 0);
    if (returnMacApi == NULL) {
        LOGE("Failed to allocate Mac Obj memory!");
        return HCF_ERR_MALLOC;
    }

    HcfResult res = HCF_INVALID_PARAMS;
    if (strcmp(paramsSpec->algName, "CMAC") == 0) {
        res = HandleCmacAlgo(returnMacApi, paramsSpec, &createSpiFunc);
    } else if (strcmp(paramsSpec->algName, "HMAC") == 0) {
        res = HandleHmacAlgo(returnMacApi, paramsSpec, &createSpiFunc);
    } else {
        LOGE("Unsupported algorithm: %{public}s", paramsSpec->algName);
        HcfFree(returnMacApi);
        returnMacApi = NULL;
        return HCF_INVALID_PARAMS;
    }

    if (res != HCF_SUCCESS) {
        HcfFree(returnMacApi);
        returnMacApi = NULL;
        return res;
    }
    if (createSpiFunc == NULL) {
        LOGE("Algo name is error!");
        return HCF_INVALID_PARAMS;
    }
    HcfMacSpi *spiObj = NULL;
    res = createSpiFunc(paramsSpec, &spiObj);
    if (res != HCF_SUCCESS) {
        LOGE("Failed to create spi object!");
        HcfFree(returnMacApi);
        returnMacApi = NULL;
        return res;
    }
    returnMacApi->base.base.getClass = GetMacClass;
    returnMacApi->base.base.destroy = MacDestroy;
    returnMacApi->base.init = Init;
    returnMacApi->base.update = Update;
    returnMacApi->base.doFinal = DoFinal;
    returnMacApi->base.getMacLength = GetMacLength;
    returnMacApi->base.getAlgoName = GetAlgoName;
    returnMacApi->spiObj = spiObj;
    *mac = (HcfMac *)returnMacApi;
    return HCF_SUCCESS;
}