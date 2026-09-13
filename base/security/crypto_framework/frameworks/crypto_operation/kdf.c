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

#include "kdf.h"

#include <securec.h>
#include "memory.h"

#include "config.h"
#include "kdf_spi.h"
#include "log.h"
#include "params_parser.h"
#include "pbkdf2_openssl.h"
#include "hkdf_openssl.h"
#include "scrypt_openssl.h"
#include "x963kdf_openssl.h"
#include "utils.h"

typedef HcfResult (*HcfKdfSpiCreateFunc)(HcfKdfDeriveParams *, HcfKdfSpi **);

typedef struct {
    HcfKdf base;
    HcfKdfSpi *spiObj;
    char algoName[HCF_MAX_ALGO_NAME_LEN];
} HcfKdfImpl;

typedef struct {
    HcfAlgValue algo;
    HcfKdfSpiCreateFunc createSpiFunc;
} HcfKdfGenAbility;

static void SetKdfType(HcfAlgParaValue value, HcfKdfDeriveParams *kdf)
{
    switch (value) {
        case HCF_ALG_PBKDF2_DEFAULT:
            kdf->algo = HCF_ALG_PKBDF2;
            break;
        case HCF_ALG_HKDF_DEFAULT:
            kdf->algo = HCF_ALG_HKDF;
            break;
        case HCF_ALG_SCRYPT_DEFAULT:
            kdf->algo = HCF_ALG_SCRYPT;
            break;
        case HCF_ALG_X963KDF_DEFAULT:
            kdf->algo = HCF_ALG_X963KDF;
            break;
        default:
            LOGE("Invalid algo %{public}u.", value);
            break;
    }
}

static void SetDigest(HcfAlgParaValue value, HcfKdfDeriveParams *kdf)
{
    kdf->md = value;
}

static void SetMode(HcfAlgParaValue value, HcfKdfDeriveParams *kdf)
{
    kdf->mode = value;
}

static HcfResult ParseKdfParams(const HcfParaConfig *config, void *params)
{
    if (config == NULL || params == NULL) {
        LOGE("Invalid Kdf params");
        return HCF_INVALID_PARAMS;
    }
    HcfResult ret = HCF_SUCCESS;
    HcfKdfDeriveParams *paramsObj = (HcfKdfDeriveParams *)params;
    LOGD("Set Parameter: %{public}s", config->tag);
    switch (config->paraType) {
        case HCF_ALG_TYPE:
            SetKdfType(config->paraValue, paramsObj);
            break;
        case HCF_ALG_DIGEST:
            SetDigest(config->paraValue, paramsObj);
            break;
        case HCF_ALG_MODE:
            SetMode(config->paraValue, paramsObj);
            break;
        default:
            LOGE("Unsupported parameter type in kdf params");
            ret = HCF_INVALID_PARAMS;
            break;
    }
    return ret;
}

static const HcfKdfGenAbility KDF_ABILITY_SET[] = {
    { HCF_ALG_PKBDF2, HcfKdfPBKDF2SpiCreate },
    { HCF_ALG_HKDF, HcfKdfHkdfSpiCreate},
    { HCF_ALG_SCRYPT, HcfKdfScryptSpiCreate },
    { HCF_ALG_X963KDF, HcfKdfX963SpiCreate },
};

static HcfKdfSpiCreateFunc FindAbility(HcfKdfDeriveParams* params)
{
    for (uint32_t i = 0; i < (sizeof(KDF_ABILITY_SET) / sizeof(KDF_ABILITY_SET[0])); i++) {
        if (KDF_ABILITY_SET[i].algo == params->algo) {
            return KDF_ABILITY_SET[i].createSpiFunc;
        }
    }
    LOGE("Algo not support! [Algo]: %{public}d", params->algo);
    return NULL;
}

// export interfaces
static const char *GetKdfGeneratorClass(void)
{
    return "HcfKdfGenerator";
}

static const char *GetAlgoName(HcfKdf *self)
{
    if (self == NULL) {
        LOGE("The input self ptr is NULL!");
        return NULL;
    }
    if (!HcfIsClassMatch((HcfObjectBase *)self, GetKdfGeneratorClass())) {
        return NULL;
    }
    return ((HcfKdfImpl *)self)->algoName;
}

static HcfResult GenerateSecret(HcfKdf *self, HcfKdfParamsSpec *paramsSpec)
{
    if (self == NULL || paramsSpec == NULL) {
        LOGE("Invalid input parameter.");
        return HCF_INVALID_PARAMS;
    }
    if (!HcfIsClassMatch((HcfObjectBase *)self, GetKdfGeneratorClass())) {
        return HCF_INVALID_PARAMS;
    }

    HcfKdfImpl *tmp = (HcfKdfImpl *)self;
    return tmp->spiObj->generateSecret(tmp->spiObj, paramsSpec);
}

static void DestroyKdf(HcfObjectBase *self)
{
    if (self == NULL) {
        return;
    }
    if (!HcfIsClassMatch((HcfObjectBase *)self, GetKdfGeneratorClass())) {
        return;
    }
    HcfKdfImpl *impl = (HcfKdfImpl *)self;
    HcfObjDestroy(impl->spiObj);
    impl->spiObj = NULL;
    HcfFree(impl);
}

HcfResult HcfKdfCreate(const char *transformation, HcfKdf **returnObj)
{
    if ((!HcfIsStrValid(transformation, HCF_MAX_ALGO_NAME_LEN)) || (returnObj == NULL)) {
        LOGE("Invalid input params while creating kdf!");
        return HCF_INVALID_PARAMS;
    }

    HcfKdfDeriveParams params = { 0 };
    if (ParseAndSetParameter(transformation, &params, ParseKdfParams) != HCF_SUCCESS) {
        LOGE("Failed to parse params!");
        return HCF_INVALID_PARAMS;
    }
    HcfKdfSpiCreateFunc createSpiFunc = FindAbility(&params);
    if (createSpiFunc == NULL) {
        LOGE("Not support this KDF func");
        return HCF_NOT_SUPPORT;
    }

    HcfKdfImpl *returnGenerator = (HcfKdfImpl *)HcfMalloc(sizeof(HcfKdfImpl), 0);
    if (returnGenerator == NULL) {
        LOGE("Failed to allocate returnGenerator memory!");
        return HCF_ERR_MALLOC;
    }
    if (strcpy_s(returnGenerator->algoName, HCF_MAX_ALGO_NAME_LEN, transformation) != EOK) {
        LOGE("Failed to copy algoName!");
        HcfFree(returnGenerator);
        returnGenerator = NULL;
        return HCF_INVALID_PARAMS;
    }
    HcfKdfSpi *spiObj = NULL;
    HcfResult res = createSpiFunc(&params, &spiObj);
    if (res != HCF_SUCCESS) {
        LOGE("Failed to create spi object!");
        HcfFree(returnGenerator);
        returnGenerator = NULL;
        return res;
    }
    returnGenerator->base.base.destroy = DestroyKdf;
    returnGenerator->base.base.getClass = GetKdfGeneratorClass;
    returnGenerator->base.generateSecret = GenerateSecret;
    returnGenerator->base.getAlgorithm = GetAlgoName;
    returnGenerator->spiObj = spiObj;

    *returnObj = (HcfKdf *)returnGenerator;
    return HCF_SUCCESS;
}
