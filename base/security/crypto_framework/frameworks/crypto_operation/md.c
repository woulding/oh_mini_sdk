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

#include "md.h"

#include <securec.h>

#include "sym_key.h"
#include "md_spi.h"
#ifdef CRYPTO_MBEDTLS
#include "mbedtls_md.h"
#else
#include "md_openssl.h"
#endif

#include "log.h"
#include "config.h"
#include "memory.h"
#include "utils.h"

typedef HcfResult (*HcfMdSpiCreateFunc)(const char *, HcfMdSpi **);

typedef struct {
    HcfMd base;

    HcfMdSpi *spiObj;

    char algoName[HCF_MAX_ALGO_NAME_LEN];
} HcfMdImpl;

typedef struct {
    char *algoName;

    HcfMdSpiCreateFunc createSpiFunc;
} HcfMdAbility;

static const HcfMdAbility MD_ABILITY_SET[] = {
#ifdef CRYPTO_MBEDTLS
    { "SHA1", MbedtlsMdSpiCreate },
    { "SHA256", MbedtlsMdSpiCreate },
    { "SHA512", MbedtlsMdSpiCreate },
    { "MD5", MbedtlsMdSpiCreate },
#else
    { "SHA1", OpensslMdSpiCreate },
    { "SHA224", OpensslMdSpiCreate },
    { "SHA256", OpensslMdSpiCreate },
    { "SHA384", OpensslMdSpiCreate },
    { "SHA512", OpensslMdSpiCreate },
    { "SHA3-256", OpensslMdSpiCreate },
    { "SHA3-384", OpensslMdSpiCreate },
    { "SHA3-512", OpensslMdSpiCreate },
    { "MD2", OpensslMdSpiCreate },
    { "MD4", OpensslMdSpiCreate },
    { "RIPEMD160", OpensslMdSpiCreate },
    { "MD5", OpensslMdSpiCreate },
    { "SM3", OpensslMdSpiCreate },
#endif
};

static const char *GetMdClass(void)
{
    return "Md";
}

static HcfMdSpiCreateFunc FindAbility(const char *algoName)
{
    for (uint32_t i = 0; i < (sizeof(MD_ABILITY_SET) / sizeof(MD_ABILITY_SET[0])); i++) {
        if (strcmp(MD_ABILITY_SET[i].algoName, algoName) == 0) {
            return MD_ABILITY_SET[i].createSpiFunc;
        }
    }
    LOGE("Algo not support! [Algo]: %{public}s", algoName);
    return NULL;
}

static HcfResult Update(HcfMd *self, HcfBlob *input)
{
    if ((self == NULL) || (!HcfIsBlobValid(input))) {
        LOGE("The input self ptr or dataBlob is NULL!");
        return HCF_INVALID_PARAMS;
    }
    if (!HcfIsClassMatch((HcfObjectBase *)self, GetMdClass())) {
        LOGE("Class is not match.");
        return HCF_INVALID_PARAMS;
    }
    return ((HcfMdImpl *)self)->spiObj->engineUpdateMd(
        ((HcfMdImpl *)self)->spiObj, input);
}

static HcfResult DoFinal(HcfMd *self, HcfBlob *output)
{
    if ((self == NULL) || (output == NULL)) {
        LOGE("The input self ptr or dataBlob is NULL!");
        return HCF_INVALID_PARAMS;
    }
    if (!HcfIsClassMatch((HcfObjectBase *)self, GetMdClass())) {
        LOGE("Class is not match.");
        return HCF_INVALID_PARAMS;
    }
    return ((HcfMdImpl *)self)->spiObj->engineDoFinalMd(
        ((HcfMdImpl *)self)->spiObj, output);
}

static uint32_t GetMdLength(HcfMd *self)
{
    if (self == NULL) {
        LOGE("The input self ptr is NULL!");
        return 0;
    }
    if (!HcfIsClassMatch((HcfObjectBase *)self, GetMdClass())) {
        LOGE("Class is not match.");
        return 0;
    }
    return ((HcfMdImpl *)self)->spiObj->engineGetMdLength(
        ((HcfMdImpl *)self)->spiObj);
}

static const char *GetAlgoName(HcfMd *self)
{
    if (self == NULL) {
        LOGE("The input self ptr is NULL!");
        return NULL;
    }
    if (!HcfIsClassMatch((HcfObjectBase *)self, GetMdClass())) {
        LOGE("Class is not match.");
        return NULL;
    }
    return ((HcfMdImpl *)self)->algoName;
}

static void MdDestroy(HcfObjectBase *self)
{
    if (self == NULL) {
        LOGE("The input self ptr is NULL!");
        return;
    }
    if (!HcfIsClassMatch((HcfObjectBase *)self, GetMdClass())) {
        LOGE("Class is not match.");
        return;
    }
    HcfMdImpl *impl = (HcfMdImpl *)self;
    HcfObjDestroy(impl->spiObj);
    impl->spiObj = NULL;
    HcfFree(impl);
}

HcfResult HcfMdCreate(const char *algoName, HcfMd **md)
{
    if (!HcfIsStrValid(algoName, HCF_MAX_ALGO_NAME_LEN) || (md == NULL)) {
        LOGE("Invalid input params while creating md!");
        return HCF_INVALID_PARAMS;
    }
    HcfMdSpiCreateFunc createSpiFunc = FindAbility(algoName);
    if (createSpiFunc == NULL) {
        LOGE("Algo name is error!");
        return HCF_INVALID_PARAMS;
    }
    HcfMdImpl *returnMdApi = (HcfMdImpl *)HcfMalloc(sizeof(HcfMdImpl), 0);
    if (returnMdApi == NULL) {
        LOGE("Failed to allocate Md Obj memory!");
        return HCF_ERR_MALLOC;
    }
    if (strcpy_s(returnMdApi->algoName, HCF_MAX_ALGO_NAME_LEN, algoName) != EOK) {
        LOGE("Failed to copy algoName!");
        HcfFree(returnMdApi);
        returnMdApi = NULL;
        return HCF_INVALID_PARAMS;
    }
    HcfMdSpi *spiObj = NULL;
    HcfResult res = createSpiFunc(algoName, &spiObj);
    if (res != HCF_SUCCESS) {
        LOGE("Failed to create spi object!");
        HcfFree(returnMdApi);
        returnMdApi = NULL;
        return res;
    }
    returnMdApi->base.base.getClass = GetMdClass;
    returnMdApi->base.base.destroy = MdDestroy;
    returnMdApi->base.update = Update;
    returnMdApi->base.doFinal = DoFinal;
    returnMdApi->base.getMdLength = GetMdLength;
    returnMdApi->base.getAlgoName = GetAlgoName;
    returnMdApi->spiObj = spiObj;
    *md = (HcfMd *)returnMdApi;
    return HCF_SUCCESS;
}