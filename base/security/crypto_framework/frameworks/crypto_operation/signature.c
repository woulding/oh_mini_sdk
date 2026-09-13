/*
 * Copyright (C) 2022-2024 Huawei Device Co., Ltd.
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

#include "signature.h"

#include <securec.h>

#include "config.h"
#include "dsa_openssl.h"
#include "ecdsa_openssl.h"
#include "log.h"
#include "memory.h"
#include "params_parser.h"
#include "signature_spi.h"
#include "signature_rsa_openssl.h"
#include "sm2_openssl.h"
#include "ed25519_openssl.h"
#include "ml_dsa_openssl.h"
#include "utils.h"
#include "plugin_operation_err.h"

typedef HcfResult (*HcfSignSpiCreateFunc)(HcfSignatureParams *, HcfSignSpi **);
typedef HcfResult (*HcfVerifySpiCreateFunc)(HcfSignatureParams *, HcfVerifySpi **);

typedef struct {
    HcfSign base;

    HcfSignSpi *spiObj;

    char algoName[HCF_MAX_ALGO_NAME_LEN];
} HcfSignImpl;

typedef struct {
    HcfVerify base;

    HcfVerifySpi *spiObj;

    char algoName[HCF_MAX_ALGO_NAME_LEN];
} HcfVerifyImpl;

typedef struct {
    HcfAlgValue algo;

    HcfSignSpiCreateFunc createFunc;
} HcfSignGenAbility;

typedef struct {
    HcfAlgValue algo;

    HcfVerifySpiCreateFunc createFunc;
} HcfVerifyGenAbility;

static const HcfSignGenAbility SIGN_GEN_ABILITY_SET[] = {
    { HCF_ALG_ECC, HcfSignSpiEcdsaCreate },
    { HCF_ALG_RSA, HcfSignSpiRsaCreate },
    { HCF_ALG_DSA, HcfSignSpiDsaCreate },
    { HCF_ALG_SM2, HcfSignSpiSm2Create },
    { HCF_ALG_ECC_BRAINPOOL, HcfSignSpiEcdsaCreate },
    { HCF_ALG_ED25519, HcfSignSpiEd25519Create },
    { HCF_ALG_ML_DSA, HcfSignSpiMlDsaCreate },
};

static const HcfVerifyGenAbility VERIFY_GEN_ABILITY_SET[] = {
    { HCF_ALG_ECC, HcfVerifySpiEcdsaCreate },
    { HCF_ALG_RSA, HcfVerifySpiRsaCreate },
    { HCF_ALG_DSA, HcfVerifySpiDsaCreate },
    { HCF_ALG_SM2, HcfVerifySpiSm2Create },
    { HCF_ALG_ECC_BRAINPOOL, HcfVerifySpiEcdsaCreate },
    { HCF_ALG_ED25519, HcfVerifySpiEd25519Create },
    { HCF_ALG_ML_DSA, HcfVerifySpiMlDsaCreate },
};

static HcfSignSpiCreateFunc FindSignAbility(HcfSignatureParams *params)
{
    if (params->operation == HCF_ALG_ONLY_SIGN && (params->algo != HCF_ALG_RSA && params->algo != HCF_ALG_ECC &&
        params->algo != HCF_ALG_ECC_BRAINPOOL)) {
        LOGE("Algo not support in OnlySign! [Algo]: %{public}d", params->algo);
        return NULL;
    }

    for (uint32_t i = 0; i < sizeof(SIGN_GEN_ABILITY_SET) / sizeof(SIGN_GEN_ABILITY_SET[0]); i++) {
        if (SIGN_GEN_ABILITY_SET[i].algo == params->algo) {
            return SIGN_GEN_ABILITY_SET[i].createFunc;
        }
    }
    LOGE("Algo not support! [Algo]: %{public}d", params->algo);
    return NULL;
}

static HcfVerifySpiCreateFunc FindVerifyAbility(HcfSignatureParams *params)
{
    if (params->operation == HCF_ALG_VERIFY_RECOVER && params->algo != HCF_ALG_RSA) {
        LOGE("Failed to check recover params!");
        return NULL;
    }
    if (params->operation == HCF_ALG_ONLY_VERIFY && (params->algo != HCF_ALG_RSA && params->algo != HCF_ALG_ECC &&
        params->algo != HCF_ALG_ECC_BRAINPOOL)) {
        LOGE("Algo not support in OnlyVerify! [Algo]: %{public}d", params->algo);
        return NULL;
    }

    for (uint32_t i = 0; i < sizeof(VERIFY_GEN_ABILITY_SET) / sizeof(VERIFY_GEN_ABILITY_SET[0]); i++) {
        if (VERIFY_GEN_ABILITY_SET[i].algo == params->algo) {
            return VERIFY_GEN_ABILITY_SET[i].createFunc;
        }
    }
    LOGE("Algo not support! [Algo]: %{public}d", params->algo);
    return NULL;
}

static void SetKeyTypeDefault(HcfAlgParaValue value,  HcfSignatureParams *paramsObj)
{
    switch (value) {
        case HCF_ALG_ECC_DEFAULT:
            paramsObj->algo = HCF_ALG_ECC;
            break;
        case HCF_ALG_RSA_DEFAULT:
            paramsObj->algo = HCF_ALG_RSA;
            break;
        case HCF_ALG_DSA_DEFAULT:
            paramsObj->algo = HCF_ALG_DSA;
            break;
        case HCF_ALG_SM2_DEFAULT:
            paramsObj->algo = HCF_ALG_SM2;
            break;
        case HCF_ALG_ECC_BRAINPOOL_DEFAULT:
            paramsObj->algo = HCF_ALG_ECC_BRAINPOOL;
            break;
        case HCF_ALG_ML_DSA_DEFAULT:
            paramsObj->algo = HCF_ALG_ML_DSA;
            break;
        default:
            LOGE("Invalid algo %{public}u.", value);
            break;
    }
}

static bool SetEccKeyType(HcfAlgParaValue value, HcfSignatureParams *paramsObj)
{
    switch (value) {
        case HCF_ALG_ECC_192:
        case HCF_ALG_ECC_224:
        case HCF_ALG_ECC_256:
        case HCF_ALG_ECC_384:
        case HCF_ALG_ECC_521:
        case HCF_ALG_ECC_SECP256K1:
            paramsObj->algo = HCF_ALG_ECC;
            return true;
        default:
            LOGD("Unsupported ECC key type");
            return false;
    }
}

static bool SetEccBrainpoolKeyType(HcfAlgParaValue value, HcfSignatureParams *paramsObj)
{
    switch (value) {
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
            paramsObj->algo = HCF_ALG_ECC_BRAINPOOL;
            return true;
        default:
            LOGD("Unsupported ECC Brainpool key type");
            return false;
    }
}

static bool SetRsaKeyType(HcfAlgParaValue value, HcfSignatureParams *paramsObj)
{
    switch (value) {
        case HCF_OPENSSL_RSA_512:
        case HCF_OPENSSL_RSA_768:
        case HCF_OPENSSL_RSA_1024:
        case HCF_OPENSSL_RSA_2048:
        case HCF_OPENSSL_RSA_3072:
        case HCF_OPENSSL_RSA_4096:
        case HCF_OPENSSL_RSA_8192:
            paramsObj->algo = HCF_ALG_RSA;
            return true;
        default:
            LOGD("Unsupported RSA key type");
            return false;
    }
}

static bool SetDsaKeyType(HcfAlgParaValue value, HcfSignatureParams *paramsObj)
{
    switch (value) {
        case HCF_ALG_DSA_1024:
        case HCF_ALG_DSA_2048:
        case HCF_ALG_DSA_3072:
            paramsObj->algo = HCF_ALG_DSA;
            return true;
        default:
            LOGD("Unsupported DSA key type");
            return false;
    }
}

static bool SetSingleKeyType(HcfAlgParaValue value, HcfSignatureParams *paramsObj)
{
    switch (value) {
        case HCF_ALG_SM2_256:
            paramsObj->algo = HCF_ALG_SM2;
            return true;
        case HCF_ALG_ED25519_256:
            paramsObj->algo = HCF_ALG_ED25519;
            return true;
        default:
            LOGE("Unsupported single key type");
            return false;
    }
}

static void SetKeyType(HcfAlgParaValue value, HcfSignatureParams *paramsObj)
{
    if (SetEccKeyType(value, paramsObj)) {
        return;
    }
    if (SetEccBrainpoolKeyType(value, paramsObj)) {
        return;
    }
    if (SetRsaKeyType(value, paramsObj)) {
        return;
    }
    if (SetDsaKeyType(value, paramsObj)) {
        return;
    }
    if (SetSingleKeyType(value, paramsObj)) {
        return;
    }
    LOGE("There is not matched algorithm.");
}

static HcfResult ParseSignatureParams(const HcfParaConfig *config, void *params)
{
    if (config == NULL || params == NULL) {
        LOGE("Invalid signature params");
        return HCF_INVALID_PARAMS;
    }
    HcfResult ret = HCF_SUCCESS;
    HcfSignatureParams *paramsObj = (HcfSignatureParams *)params;
    LOGD("Set Parameter: %{public}s", config->tag);
    switch (config->paraType) {
        case HCF_ALG_TYPE:
            SetKeyTypeDefault(config->paraValue, paramsObj);
            break;
        case HCF_ALG_KEY_TYPE:
            SetKeyType(config->paraValue, paramsObj);
            break;
        case HCF_ALG_DIGEST:
            paramsObj->md = config->paraValue;
            break;
        case HCF_ALG_PADDING_TYPE:
            paramsObj->padding = config->paraValue;
            break;
        case HCF_ALG_MGF1_DIGEST:
            paramsObj->mgf1md = config->paraValue;
            break;
        case HCF_ALG_SIGN_TYPE:
            paramsObj->operation = config->paraValue;
            break;
        case HCF_ALG_VERIFY_TYPE:
            paramsObj->operation = config->paraValue;
            break;
        default:
            LOGE("Unsupported parameter type in signature params");
            ret = HCF_INVALID_PARAMS;
            break;
    }
    return ret;
}

static const char *GetSignClass(void)
{
    return "HcfSign";
}

static const char *GetVerifyClass(void)
{
    return "HcfVerify";
}

static const char *GetSignAlgoName(HcfSign *self)
{
    if (self == NULL) {
        LOGE("The input self ptr is NULL!");
        return NULL;
    }
    if (!HcfIsClassMatch((HcfObjectBase *)self, GetSignClass())) {
        LOGE("Class is not matched for GetSignAlgoName");
        return NULL;
    }
    return ((HcfSignImpl *)self)->algoName;
}

static const char *GetVerifyAlgoName(HcfVerify *self)
{
    if (self == NULL) {
        LOGE("The input self ptr is NULL!");
        return NULL;
    }
    if (!HcfIsClassMatch((HcfObjectBase *)self, GetVerifyClass())) {
        LOGE("Class is not matched for GetVerifyAlgoName");
        return NULL;
    }
    return ((HcfVerifyImpl *)self)->algoName;
}

static void DestroySign(HcfObjectBase *self)
{
    if (self == NULL) {
        return;
    }
    if (!HcfIsClassMatch(self, GetSignClass())) {
        LOGE("Class not match.");
        return;
    }
    HcfSignImpl *impl = (HcfSignImpl *)self;
    HcfObjDestroy(impl->spiObj);
    impl->spiObj = NULL;
    HcfFree(impl);
}

static void DestroyVerify(HcfObjectBase *self)
{
    if (self == NULL) {
        return;
    }
    if (!HcfIsClassMatch(self, GetVerifyClass())) {
        LOGE("Class not match.");
        return;
    }
    HcfVerifyImpl *impl = (HcfVerifyImpl *)self;
    HcfObjDestroy(impl->spiObj);
    impl->spiObj = NULL;
    HcfFree(impl);
}

static HcfResult SetSignSpecInt(HcfSign *self, SignSpecItem item, int32_t saltLen)
{
    if (self == NULL) {
        LOGE("Invalid input parameter.");
        return HCF_INVALID_PARAMS;
    }
    if (!HcfIsClassMatch((HcfObjectBase *)self, GetSignClass())) {
        LOGE("Class not match.");
        return HCF_INVALID_PARAMS;
    }
    HcfSignImpl *tmpSelf = (HcfSignImpl *)self;
    return tmpSelf->spiObj->engineSetSignSpecInt(tmpSelf->spiObj, item, saltLen);
}

static HcfResult GetSignSpecString(HcfSign *self, SignSpecItem item, char **returnString)
{
    if (self == NULL || returnString == NULL) {
        LOGE("Invalid input parameter.");
        return HCF_INVALID_PARAMS;
    }
    if (!HcfIsClassMatch((HcfObjectBase *)self, GetSignClass())) {
        LOGE("Class not match.");
        return HCF_INVALID_PARAMS;
    }
    HcfSignImpl *tmpSelf = (HcfSignImpl *)self;
    return tmpSelf->spiObj->engineGetSignSpecString(tmpSelf->spiObj, item, returnString);
}

static HcfResult SetSignSpecUint8Array(HcfSign *self, SignSpecItem item, HcfBlob blob)
{
    if (self == NULL) {
        LOGE("Invalid input parameter.");
        return HCF_INVALID_PARAMS;
    }
    if (!HcfIsClassMatch((HcfObjectBase *)self, GetSignClass())) {
        LOGE("Class not match.");
        return HCF_INVALID_PARAMS;
    }
    HcfSignImpl *tmpSelf = (HcfSignImpl *)self;
    return tmpSelf->spiObj->engineSetSignSpecUint8Array(tmpSelf->spiObj, item, blob);
}

static HcfResult SetSignSpecBool(HcfSign *self, SignSpecItem item, bool flag)
{
    if (self == NULL) {
        LOGE("Invalid input parameter.");
        return HCF_ERR_PARAMETER_CHECK_FAILED;
    }
    if (!HcfIsClassMatch((HcfObjectBase *)self, GetSignClass())) {
        LOGE("Class not match.");
        return HCF_ERR_PARAMETER_CHECK_FAILED;
    }
    HcfSignImpl *tmpSelf = (HcfSignImpl *)self;
    if (tmpSelf->spiObj->engineSetSignSpecBool == NULL) {
        LOGE("EngineSetSignSpecBool is NULL.");
        return HCF_ERR_INVALID_CALL;
    }
    return tmpSelf->spiObj->engineSetSignSpecBool(tmpSelf->spiObj, item, flag);
}

static HcfResult GetSignSpecInt(HcfSign *self, SignSpecItem item, int32_t *returnInt)
{
    if (self == NULL || returnInt == NULL) {
        LOGE("Invalid input parameter.");
        return HCF_INVALID_PARAMS;
    }
    if (!HcfIsClassMatch((HcfObjectBase *)self, GetSignClass())) {
        LOGE("Class not match.");
        return HCF_INVALID_PARAMS;
    }
    HcfSignImpl *tmpSelf = (HcfSignImpl *)self;
    return tmpSelf->spiObj->engineGetSignSpecInt(tmpSelf->spiObj, item, returnInt);
}

static HcfResult SignInit(HcfSign *self, HcfParamsSpec *params, HcfPriKey *privateKey)
{
    if (self == NULL) {
        LOGE("Invalid input parameter.");
        return HCF_INVALID_PARAMS;
    }

    if (!HcfIsClassMatch((HcfObjectBase *)self, GetSignClass())) {
        LOGE("Class not match.");
        return HCF_INVALID_PARAMS;
    }
    return ((HcfSignImpl *)self)->spiObj->engineInit(((HcfSignImpl *)self)->spiObj, params, privateKey);
}

static HcfResult SignUpdate(HcfSign *self, HcfBlob *data)
{
    if (self == NULL) {
        LOGE("Invalid input parameter.");
        return HCF_INVALID_PARAMS;
    }

    if (!HcfIsClassMatch((HcfObjectBase *)self, GetSignClass())) {
        LOGE("Class not match.");
        return HCF_INVALID_PARAMS;
    }
    return ((HcfSignImpl *)self)->spiObj->engineUpdate(((HcfSignImpl *)self)->spiObj, data);
}

static HcfResult SignDoFinal(HcfSign *self, HcfBlob *data, HcfBlob *returnSignatureData)
{
    if (self == NULL) {
        LOGE("Invalid input parameter.");
        return HCF_INVALID_PARAMS;
    }

    if (!HcfIsClassMatch((HcfObjectBase *)self, GetSignClass())) {
        LOGE("Class not match.");
        return HCF_INVALID_PARAMS;
    }
    return ((HcfSignImpl *)self)->spiObj->engineSign(((HcfSignImpl *)self)->spiObj, data, returnSignatureData);
}

static HcfResult SetVerifySpecInt(HcfVerify *self, SignSpecItem item, int32_t saltLen)
{
    if (self == NULL) {
        LOGE("Invalid input parameter.");
        return HCF_INVALID_PARAMS;
    }
    if (!HcfIsClassMatch((HcfObjectBase *)self, GetVerifyClass())) {
        LOGE("Class not match.");
        return HCF_INVALID_PARAMS;
    }
    HcfVerifyImpl *tmpSelf = (HcfVerifyImpl *)self;
    return tmpSelf->spiObj->engineSetVerifySpecInt(tmpSelf->spiObj, item, saltLen);
}

static HcfResult GetVerifySpecString(HcfVerify *self, SignSpecItem item, char **returnString)
{
    if (self == NULL || returnString == NULL) {
        LOGE("Invalid input parameter.");
        return HCF_INVALID_PARAMS;
    }
    if (!HcfIsClassMatch((HcfObjectBase *)self, GetVerifyClass())) {
        LOGE("Class not match.");
        return HCF_INVALID_PARAMS;
    }
    HcfVerifyImpl *tmpSelf = (HcfVerifyImpl *)self;
    return tmpSelf->spiObj->engineGetVerifySpecString(tmpSelf->spiObj, item, returnString);
}

static HcfResult SetVerifySpecUint8Array(HcfVerify *self, SignSpecItem item, HcfBlob blob)
{
    if (self == NULL) {
        LOGE("Invalid input parameter.");
        return HCF_INVALID_PARAMS;
    }
    if (!HcfIsClassMatch((HcfObjectBase *)self, GetVerifyClass())) {
        LOGE("Class not match.");
        return HCF_INVALID_PARAMS;
    }
    HcfVerifyImpl *tmpSelf = (HcfVerifyImpl *)self;
    return tmpSelf->spiObj->engineSetVerifySpecUint8Array(tmpSelf->spiObj, item, blob);
}

static HcfResult SetVerifySpecBool(HcfVerify *self, SignSpecItem item, bool flag)
{
    if (self == NULL) {
        LOGE("Invalid input parameter.");
        return HCF_ERR_PARAMETER_CHECK_FAILED;
    }
    if (!HcfIsClassMatch((HcfObjectBase *)self, GetVerifyClass())) {
        LOGE("Class not match.");
        return HCF_ERR_PARAMETER_CHECK_FAILED;
    }
    HcfVerifyImpl *tmpSelf = (HcfVerifyImpl *)self;
    if (tmpSelf->spiObj->engineSetVerifySpecBool == NULL) {
        LOGE("EngineSetVerifySpecBool is NULL.");
        return HCF_ERR_INVALID_CALL;
    }
    return tmpSelf->spiObj->engineSetVerifySpecBool(tmpSelf->spiObj, item, flag);
}

static HcfResult GetVerifySpecInt(HcfVerify *self, SignSpecItem item, int32_t *returnInt)
{
    if (self == NULL || returnInt == NULL) {
        LOGE("Invalid input parameter.");
        return HCF_INVALID_PARAMS;
    }
    if (!HcfIsClassMatch((HcfObjectBase *)self, GetVerifyClass())) {
        LOGE("Class not match.");
        return HCF_INVALID_PARAMS;
    }
    HcfVerifyImpl *tmpSelf = (HcfVerifyImpl *)self;
    return tmpSelf->spiObj->engineGetVerifySpecInt(tmpSelf->spiObj, item, returnInt);
}

static HcfResult VerifyInit(HcfVerify *self, HcfParamsSpec *params, HcfPubKey *publicKey)
{
    if (self == NULL) {
        LOGE("Invalid input parameter.");
        return HCF_INVALID_PARAMS;
    }

    if (!HcfIsClassMatch((HcfObjectBase *)self, GetVerifyClass())) {
        LOGE("Class not match.");
        return HCF_INVALID_PARAMS;
    }
    HcfClearPluginErrorMessage();
    return ((HcfVerifyImpl *)self)->spiObj->engineInit(((HcfVerifyImpl *)self)->spiObj, params, publicKey);
}

static HcfResult VerifyUpdate(HcfVerify *self, HcfBlob *data)
{
    if (self == NULL) {
        LOGE("Invalid input parameter.");
        return HCF_INVALID_PARAMS;
    }

    if (!HcfIsClassMatch((HcfObjectBase *)self, GetVerifyClass())) {
        LOGE("Class not match.");
        return HCF_INVALID_PARAMS;
    }
    HcfClearPluginErrorMessage();
    return ((HcfVerifyImpl *)self)->spiObj->engineUpdate(((HcfVerifyImpl *)self)->spiObj, data);
}

static bool VerifyDoFinal(HcfVerify *self, HcfBlob *data, HcfBlob *signatureData)
{
    if (self == NULL) {
        LOGE("Invalid input parameter.");
        return false;
    }
    if (!HcfIsClassMatch((HcfObjectBase *)self, GetVerifyClass())) {
        LOGE("Class not match.");
        return false;
    }
    HcfClearPluginErrorMessage();
    return ((HcfVerifyImpl *)self)->spiObj->engineVerify(((HcfVerifyImpl *)self)->spiObj, data, signatureData);
}

static HcfResult VerifyRecover(HcfVerify *self, HcfBlob *signatureData, HcfBlob *rawSignatureData)
{
    if (self == NULL) {
        LOGE("Invalid input parameter.");
        return HCF_INVALID_PARAMS;
    }
    if (!HcfIsClassMatch((HcfObjectBase *)self, GetVerifyClass())) {
        LOGE("Class not match.");
        return HCF_INVALID_PARAMS;
    }
    HcfVerifySpi *verifySpiObj = ((HcfVerifyImpl *)self)->spiObj;
    if (verifySpiObj->engineRecover == NULL) {
        LOGE("Not support verify recover operation.");
        return HCF_INVALID_PARAMS;
    }
    HcfClearPluginErrorMessage();
    return verifySpiObj->engineRecover(verifySpiObj, signatureData, rawSignatureData);
}

HcfResult HcfSignCreate(const char *algoName, HcfSign **returnObj)
{
    LOGD("HcfSignCreate start");
    if ((!HcfIsStrValid(algoName, HCF_MAX_ALGO_NAME_LEN)) || (returnObj == NULL)) {
        return HCF_INVALID_PARAMS;
    }

    HcfSignatureParams params = { 0 };
    if (ParseAndSetParameter(algoName, &params, ParseSignatureParams) != HCF_SUCCESS) {
        LOGE("Failed to parse params!");
        return HCF_INVALID_PARAMS;
    }

    HcfSignSpiCreateFunc createSpiFunc = FindSignAbility(&params);
    if (createSpiFunc == NULL) {
        LOGE("Can not find ability.");
        return HCF_NOT_SUPPORT;
    }

    HcfSignImpl *returnSign = (HcfSignImpl *)HcfMalloc(sizeof(HcfSignImpl), 0);
    if (returnSign == NULL) {
        LOGE("Failed to allocate returnSign memory!");
        return HCF_ERR_MALLOC;
    }
    if (strcpy_s(returnSign->algoName, HCF_MAX_ALGO_NAME_LEN, algoName) != EOK) {
        LOGE("Failed to copy algoName!");
        HcfFree(returnSign);
        returnSign = NULL;
        return HCF_INVALID_PARAMS;
    }
    HcfSignSpi *spiObj = NULL;
    HcfResult res = createSpiFunc(&params, &spiObj);
    if (res != HCF_SUCCESS) {
        LOGE("Failed to create spi object!");
        HcfFree(returnSign);
        returnSign = NULL;
        return res;
    }
    returnSign->base.base.destroy = DestroySign;
    returnSign->base.base.getClass = GetSignClass;
    returnSign->base.getAlgoName = GetSignAlgoName;
    returnSign->base.init = SignInit;
    returnSign->base.update = SignUpdate;
    returnSign->base.sign = SignDoFinal;
    returnSign->base.setSignSpecInt = SetSignSpecInt;
    returnSign->base.getSignSpecInt = GetSignSpecInt;
    returnSign->base.getSignSpecString = GetSignSpecString;
    returnSign->base.setSignSpecUint8Array = SetSignSpecUint8Array;
    returnSign->base.setSignSpecBool = SetSignSpecBool;
    returnSign->spiObj = spiObj;

    *returnObj = (HcfSign *)returnSign;
    LOGD("HcfSignCreate end");
    return HCF_SUCCESS;
}

HcfResult HcfVerifyCreate(const char *algoName, HcfVerify **returnObj)
{
    LOGD("HcfVerifyCreate start");
    if ((!HcfIsStrValid(algoName, HCF_MAX_ALGO_NAME_LEN)) || (returnObj == NULL)) {
        return HCF_INVALID_PARAMS;
    }
    HcfSignatureParams params = {0};
    if (ParseAndSetParameter(algoName, &params, ParseSignatureParams) != HCF_SUCCESS) {
        LOGE("Failed to parse params!");
        return HCF_INVALID_PARAMS;
    }

    HcfVerifySpiCreateFunc createSpiFunc = FindVerifyAbility(&params);
    if (createSpiFunc == NULL) {
        return HCF_NOT_SUPPORT;
    }

    HcfVerifyImpl *returnVerify = (HcfVerifyImpl *)HcfMalloc(sizeof(HcfVerifyImpl), 0);
    if (returnVerify == NULL) {
        LOGE("Failed to allocate returnVerify memory!");
        return HCF_ERR_MALLOC;
    }
    if (strcpy_s(returnVerify->algoName, HCF_MAX_ALGO_NAME_LEN, algoName) != EOK) {
        LOGE("Failed to copy algoName!");
        HcfFree(returnVerify);
        returnVerify = NULL;
        return HCF_INVALID_PARAMS;
    }
    HcfVerifySpi *spiObj = NULL;
    HcfResult res = createSpiFunc(&params, &spiObj);
    if (res != HCF_SUCCESS) {
        LOGE("Failed to create spi object!");
        HcfFree(returnVerify);
        returnVerify = NULL;
        return res;
    }
    returnVerify->base.base.destroy = DestroyVerify;
    returnVerify->base.base.getClass = GetVerifyClass;
    returnVerify->base.getAlgoName = GetVerifyAlgoName;
    returnVerify->base.init = VerifyInit;
    returnVerify->base.update = VerifyUpdate;
    returnVerify->base.verify = VerifyDoFinal;
    returnVerify->base.recover = VerifyRecover;
    returnVerify->base.setVerifySpecInt = SetVerifySpecInt;
    returnVerify->base.getVerifySpecInt = GetVerifySpecInt;
    returnVerify->base.getVerifySpecString = GetVerifySpecString;
    returnVerify->base.setVerifySpecUint8Array = SetVerifySpecUint8Array;
    returnVerify->base.setVerifySpecBool = SetVerifySpecBool;
    returnVerify->spiObj = spiObj;
    *returnObj = (HcfVerify *)returnVerify;
    LOGD("HcfVerifyCreate end");
    return HCF_SUCCESS;
}
