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

#include "ecc_key_util.h"
#include <securec.h>
#include "ecc_key_util_spi.h"
#include "config.h"
#include "ecc_common_param_spec_generator_openssl.h"
#include "key_utils.h"
#include "params_parser.h"
#include "log.h"
#include "memory.h"
#include "utils.h"

typedef HcfResult (*HcfEccCommParamsSpecCreateFunc)(HcfAsyKeyGenParams *, HcfEccCommParamsSpecSpi **);

typedef struct {
    HcfAlgValue algo;

    HcfEccCommParamsSpecCreateFunc createSpiFunc;
} HcfEccCommParamsSpecAbility;

static const HcfEccCommParamsSpecAbility ASY_KEY_GEN_ABILITY_SET[] = {
    { HCF_ALG_ECC, HcfECCCommonParamSpecCreate },
};

static HcfEccCommParamsSpecCreateFunc FindAbility(HcfAsyKeyGenParams *params)
{
    if (params == NULL) {
        LOGE("params is null");
        return NULL;
    }
    for (uint32_t i = 0; i < sizeof(ASY_KEY_GEN_ABILITY_SET) / sizeof(ASY_KEY_GEN_ABILITY_SET[0]); i++) {
        if (ASY_KEY_GEN_ABILITY_SET[i].algo == params->algo) {
            return ASY_KEY_GEN_ABILITY_SET[i].createSpiFunc;
        }
    }
    LOGE("Algo not support! [Algo]: %{public}d", params->algo);
    return NULL;
}

static bool IsBigIntegerValid(const HcfBigInteger *bigInt)
{
    if (bigInt == NULL) {
        LOGE("Invalid HcfBigInteger parameter");
        return false;
    }
    if (bigInt->data == NULL) {
        LOGE("BigInteger data is NULL");
        return false;
    }
    if (bigInt->len == 0) {
        LOGE("BigInteger length is 0");
        return false;
    }
    return true;
}

static bool IsPointValid(const HcfPoint *point)
{
    if (point == NULL) {
        LOGE("Invalid point parameter");
        return false;
    }
    if (!IsBigIntegerValid(&(point->x))) {
        LOGE("Invalid x coordinate parameter");
        return false;
    }
    if (!IsBigIntegerValid(&(point->y))) {
        LOGE("Invalid y coordinate parameter");
        return false;
    }
    return true;
}

HcfResult HcfConvertPoint(const char *curveName, HcfBlob *encodedPoint, HcfPoint *returnPoint)
{
    if (!HcfIsStrValid(curveName, HCF_MAX_ALGO_NAME_LEN)) {
        LOGE("Failed to parse params: curveName is invalid!");
        return HCF_INVALID_PARAMS;
    }

    if (!HcfIsBlobValid(encodedPoint)) {
        LOGE("Failed to parse params: encodedPoint is invalid!");
        return HCF_INVALID_PARAMS;
    }

    if (returnPoint == NULL) {
        LOGE("Failed to parse params: returnPoint is NULL!");
        return HCF_INVALID_PARAMS;
    }

    HcfAlgParaValue algValue = 0;
    HcfResult ret = GetAlgValueByCurveName(curveName, &algValue);
    if (ret != HCF_SUCCESS) {
        LOGE("Failed to get algValue.");
        return ret;
    }

    ret = HcfEngineConvertPoint(algValue, encodedPoint, returnPoint);
    if (ret != HCF_SUCCESS) {
        LOGE("Failed to create spi object!");
        return ret;
    }
    return HCF_SUCCESS;
}

HcfResult HcfGetEncodedPoint(const char *curveName, HcfPoint *point, const char *format, HcfBlob *returnBlob)
{
    if (!HcfIsStrValid(curveName, HCF_MAX_ALGO_NAME_LEN)) {
        LOGE("Failed to parse params: curveName is invalid!");
        return HCF_INVALID_PARAMS;
    }

    if (!IsPointValid(point)) {
        LOGE("Failed to parse params: point is invalid!");
        return HCF_INVALID_PARAMS;
    }

    if (format == NULL) {
        LOGE("Failed to parse params: format is NULL!");
        return HCF_INVALID_PARAMS;
    }

    HcfFormatValue formatValue = 0;
    HcfResult ret = GetFormatValueByFormatName(format, &formatValue);
    if (ret != HCF_SUCCESS) {
        LOGE("Failed to get formatValue.");
        return ret;
    }

    if (returnBlob == NULL) {
        LOGE("Failed to parse params: returnBlob is NULL!");
        return HCF_INVALID_PARAMS;
    }

    HcfAlgParaValue algValue = 0;
    ret = GetAlgValueByCurveName(curveName, &algValue);
    if (ret != HCF_SUCCESS) {
        LOGE("Failed to get algValue.");
        return ret;
    }

    ret = HcfEngineGetEncodedPoint(algValue, point, formatValue, returnBlob);
    if (ret != HCF_SUCCESS) {
        LOGE("Failed to create spi object!");
        return ret;
    }
    return HCF_SUCCESS;
}

HcfResult HcfEccKeyUtilCreate(const char *algName, HcfEccCommParamsSpec **returnCommonParamSpec)
{
    if ((!HcfIsStrValid(algName, HCF_MAX_ALGO_NAME_LEN)) || (returnCommonParamSpec == NULL)) {
        LOGE("Failed to parse params!");
        return HCF_INVALID_PARAMS;
    }
    HcfAsyKeyGenParams params = { 0 };
    if (ParseCurveNameToParams(algName, &params) != HCF_SUCCESS) {
        LOGE("Failed to parse params!");
        return HCF_INVALID_PARAMS;
    }

    HcfEccCommParamsSpecCreateFunc createSpiFunc = FindAbility(&params);
    if (createSpiFunc == NULL) {
        LOGE("Failed to find ability!");
        return HCF_NOT_SUPPORT;
    }

    HcfEccCommParamsSpecSpi *spiInstance = NULL;
    HcfResult ret = createSpiFunc(&params, &spiInstance);
    if (ret != HCF_SUCCESS) {
        LOGE("Failed to create spi object!");
        return ret;
    }
    ret = CreateEccCommonSpecImpl(&(spiInstance->paramsSpec), returnCommonParamSpec);
    if (ret != HCF_SUCCESS) {
        LOGE("Failed to create spi object!");
    }
    FreeEccCommParamsSpec(&(spiInstance->paramsSpec));
    HcfFree(spiInstance);
    spiInstance = NULL;
    return ret;
}
