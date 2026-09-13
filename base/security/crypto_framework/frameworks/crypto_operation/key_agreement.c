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

#include "key_agreement.h"

#include <securec.h>

#include "key_agreement_spi.h"
#include "config.h"
#include "dh_openssl.h"
#include "ecdh_openssl.h"
#include "x25519_openssl.h"
#include "log.h"
#include "memory.h"
#include "params_parser.h"
#include "utils.h"

typedef HcfResult (*HcfKeyAgreementSpiCreateFunc)(HcfKeyAgreementParams *, HcfKeyAgreementSpi **);

typedef struct {
    HcfKeyAgreement base;

    HcfKeyAgreementSpi *spiObj;

    char algoName[HCF_MAX_ALGO_NAME_LEN];
} HcfKeyAgreementImpl;

typedef struct {
    HcfAlgValue algo;

    HcfKeyAgreementSpiCreateFunc createSpiFunc;
} HcfKeyAgreementGenAbility;

static const HcfKeyAgreementGenAbility KEY_AGREEMENT_GEN_ABILITY_SET[] = {
    { HCF_ALG_ECC, HcfKeyAgreementSpiEcdhCreate },
    { HCF_ALG_X25519, HcfKeyAgreementSpiX25519Create },
    { HCF_ALG_DH, HcfKeyAgreementSpiDhCreate }
};

static HcfKeyAgreementSpiCreateFunc FindAbility(HcfKeyAgreementParams *params)
{
    for (uint32_t i = 0; i < sizeof(KEY_AGREEMENT_GEN_ABILITY_SET) / sizeof(KEY_AGREEMENT_GEN_ABILITY_SET[0]); i++) {
        if (KEY_AGREEMENT_GEN_ABILITY_SET[i].algo == params->algo) {
            return KEY_AGREEMENT_GEN_ABILITY_SET[i].createSpiFunc;
        }
    }
    LOGE("Algo not support! [Algo]: %{public}d", params->algo);
    return NULL;
}

static void SetKeyType(HcfAlgParaValue value, HcfKeyAgreementParams *paramsObj)
{
    switch (value) {
        case HCF_ALG_ECC_192:
        case HCF_ALG_ECC_224:
        case HCF_ALG_ECC_256:
        case HCF_ALG_ECC_384:
        case HCF_ALG_ECC_521:
        case HCF_ALG_ECC_BP160R1:
        case HCF_ALG_ECC_BP160T1:
        case HCF_ALG_ECC_BP192R1:
        case HCF_ALG_ECC_BP192T1:
        case HCF_ALG_ECC_BP224R1:
        case HCF_ALG_ECC_BP224T1:
        case HCF_ALG_ECC_BP256R1:
        case HCF_ALG_ECC_BP256T1:
        case HCF_ALG_ECC_BP320R1:
        case HCF_ALG_ECC_BP320T1:
        case HCF_ALG_ECC_BP384R1:
        case HCF_ALG_ECC_BP384T1:
        case HCF_ALG_ECC_BP512R1:
        case HCF_ALG_ECC_BP512T1:
        case HCF_ALG_ECC_SECP256K1:
            paramsObj->algo = HCF_ALG_ECC;
            break;
        case HCF_ALG_X25519_256:
            paramsObj->algo = HCF_ALG_X25519;
            break;
        case HCF_OPENSSL_DH_MODP_1536:
        case HCF_OPENSSL_DH_MODP_2048:
        case HCF_OPENSSL_DH_MODP_3072:
        case HCF_OPENSSL_DH_MODP_4096:
        case HCF_OPENSSL_DH_MODP_6144:
        case HCF_OPENSSL_DH_MODP_8192:
        case HCF_OPENSSL_DH_FFDHE_2048:
        case HCF_OPENSSL_DH_FFDHE_3072:
        case HCF_OPENSSL_DH_FFDHE_4096:
        case HCF_OPENSSL_DH_FFDHE_6144:
        case HCF_OPENSSL_DH_FFDHE_8192:
            paramsObj->algo = HCF_ALG_DH;
            break;
        default:
            LOGE("Invalid algo %{public}u.", value);
            break;
    }
}

static void SetKeyTypeDefault(HcfAlgParaValue value,  HcfKeyAgreementParams *paramsObj)
{
    switch (value) {
        case HCF_ALG_ECC_DEFAULT:
            paramsObj->algo = HCF_ALG_ECC;
            break;
        case HCF_ALG_X25519_DEFAULT:
            paramsObj->algo = HCF_ALG_X25519;
            break;
        case HCF_ALG_DH_DEFAULT:
            paramsObj->algo = HCF_ALG_DH;
            break;
        default:
            LOGE("Invalid algo %{public}u.", value);
            break;
    }
}

static HcfResult ParseKeyAgreementParams(const HcfParaConfig *config, void *params)
{
    if (config == NULL || params == NULL) {
        LOGE("Invalid key agreement params");
        return HCF_INVALID_PARAMS;
    }
    HcfResult ret = HCF_SUCCESS;
    HcfKeyAgreementParams *paramsObj = (HcfKeyAgreementParams *)params;
    LOGD("Set Parameter: %{public}s", config->tag);
    switch (config->paraType) {
        case HCF_ALG_TYPE:
            SetKeyTypeDefault(config->paraValue, paramsObj);
            break;
        case HCF_ALG_KEY_TYPE:
            SetKeyType(config->paraValue, paramsObj);
            break;
        default:
            LOGE("Unsupported parameter type in key agreement params");
            ret = HCF_INVALID_PARAMS;
            break;
    }
    return ret;
}

static const char *GetKeyAgreementClass(void)
{
    return "HcfKeyAgreement";
}

static const char *GetAlgoName(HcfKeyAgreement *self)
{
    if (self == NULL) {
        LOGE("The input self ptr is NULL!");
        return NULL;
    }
    if (!HcfIsClassMatch((HcfObjectBase *)self, GetKeyAgreementClass())) {
        return NULL;
    }
    return ((HcfKeyAgreementImpl *)self)->algoName;
}

static HcfResult GenerateSecret(HcfKeyAgreement *self, HcfPriKey *priKey,
    HcfPubKey *pubKey, HcfBlob *returnSecret)
{
    if (self == NULL) {
        LOGE("Invalid input parameter.");
        return HCF_INVALID_PARAMS;
    }
    if (!HcfIsClassMatch((HcfObjectBase *)self, GetKeyAgreementClass())) {
        return HCF_INVALID_PARAMS;
    }

    return ((HcfKeyAgreementImpl *)self)->spiObj->engineGenerateSecret(
        ((HcfKeyAgreementImpl *)self)->spiObj, priKey, pubKey, returnSecret);
}

static void DestroyKeyAgreement(HcfObjectBase *self)
{
    if (self == NULL) {
        return;
    }
    if (!HcfIsClassMatch((HcfObjectBase *)self, GetKeyAgreementClass())) {
        return;
    }
    HcfKeyAgreementImpl *impl = (HcfKeyAgreementImpl *)self;
    HcfObjDestroy(impl->spiObj);
    impl->spiObj = NULL;
    HcfFree(impl);
}

HcfResult HcfKeyAgreementCreate(const char *algoName, HcfKeyAgreement **returnObj)
{
    if ((!HcfIsStrValid(algoName, HCF_MAX_ALGO_NAME_LEN)) || (returnObj == NULL)) {
        LOGE("AlgoName is invalid or returnObj is null");
        return HCF_INVALID_PARAMS;
    }

    HcfKeyAgreementParams params = { 0 };
    if (ParseAndSetParameter(algoName, &params, ParseKeyAgreementParams) != HCF_SUCCESS) {
        LOGE("Failed to parse params!");
        return HCF_INVALID_PARAMS;
    }

    HcfKeyAgreementSpiCreateFunc createSpiFunc = FindAbility(&params);
    if (createSpiFunc == NULL) {
        LOGE("No matching key agreement ability found");
        return HCF_NOT_SUPPORT;
    }

    HcfKeyAgreementImpl *returnGenerator = (HcfKeyAgreementImpl *)HcfMalloc(sizeof(HcfKeyAgreementImpl), 0);
    if (returnGenerator == NULL) {
        LOGE("Failed to allocate returnGenerator memory!");
        return HCF_ERR_MALLOC;
    }
    if (strcpy_s(returnGenerator->algoName, HCF_MAX_ALGO_NAME_LEN, algoName) != EOK) {
        LOGE("Failed to copy algoName!");
        HcfFree(returnGenerator);
        returnGenerator = NULL;
        return HCF_INVALID_PARAMS;
    }
    HcfKeyAgreementSpi *spiObj = NULL;
    HcfResult res = createSpiFunc(&params, &spiObj);
    if (res != HCF_SUCCESS) {
        LOGE("Failed to create spi object!");
        HcfFree(returnGenerator);
        returnGenerator = NULL;
        return res;
    }
    returnGenerator->base.base.destroy = DestroyKeyAgreement;
    returnGenerator->base.base.getClass = GetKeyAgreementClass;
    returnGenerator->base.generateSecret = GenerateSecret;
    returnGenerator->base.getAlgoName = GetAlgoName;
    returnGenerator->spiObj = spiObj;

    *returnObj = (HcfKeyAgreement *)returnGenerator;
    return HCF_SUCCESS;
}
