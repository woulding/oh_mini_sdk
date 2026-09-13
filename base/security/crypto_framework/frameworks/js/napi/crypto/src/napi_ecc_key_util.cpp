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

#include "napi_ecc_key_util.h"
#include "securec.h"
#include "detailed_ecc_key_params.h"
#include "log.h"

#include "memory.h"
#include "napi_crypto_framework_defines.h"
#include "napi_utils.h"
#include "napi_key_pair.h"
#include "napi_pri_key.h"
#include "napi_pub_key.h"
#include "utils.h"

namespace OHOS {
namespace CryptoFramework {
NapiECCKeyUtil::NapiECCKeyUtil() {}

NapiECCKeyUtil::~NapiECCKeyUtil() {}

static bool CheckEccCommonParamSpecBase(napi_env env, HcfEccCommParamsSpec *blob)
{
    if (blob->a.data == nullptr || blob->a.len == 0) {
        LOGE("Invalid blob a!");
        return false;
    }
    if (blob->b.data == nullptr || blob->b.len == 0) {
        LOGE("Invalid blob b!");
        return false;
    }
    if (blob->n.data == nullptr || blob->n.len == 0) {
        LOGE("Invalid blob n!");
        return false;
    }
    return true;
}

static bool CheckEccCommonParamSpec(napi_env env, HcfEccCommParamsSpec *blob)
{
    if (blob == nullptr) {
        LOGE("Invalid blob!");
        return false;
    }
    if (!CheckEccCommonParamSpecBase(env, blob)) {
        LOGE("Invalid blob ecc commonParamSpec base!");
        return false;
    }
    if (blob->base.algName == nullptr) {
        LOGE("Invalid blob algName!");
        return false;
    }
    if (blob->field == nullptr) {
        LOGE("Invalid blob field!");
        return false;
    }
    if (blob->field->fieldType == nullptr) {
        LOGE("Invalid blob fieldType!");
        return false;
    }
    if (blob->g.x.data == nullptr || blob->g.x.len == 0) {
        LOGE("Invalid blob point x!");
        return false;
    }
    if (blob->g.y.data == nullptr || blob->g.y.len == 0) {
        LOGE("Invalid blob point y!");
        return false;
    }
    HcfECFieldFp *tmpField = reinterpret_cast<HcfECFieldFp *>(blob->field);
    if (tmpField->p.data == nullptr || tmpField->p.len == 0) {
        LOGE("Invalid blob p!");
        return false;
    }
    return true;
}

static napi_value ConvertEccCommonParamFieldFpToNapiValue(napi_env env, HcfEccCommParamsSpec *blob)
{
    napi_value fieldFp;
    napi_value fieldType;
    napi_status status = napi_create_object(env, &fieldFp);
    if (status != napi_ok) {
        LOGE("create fieldFp failed!");
        return NapiGetNull(env);
    }
    size_t fieldTypeLength = HcfStrlen(blob->field->fieldType);
    if (!fieldTypeLength) {
        LOGE("fieldType is empty!");
        return NapiGetNull(env);
    }
    status = napi_create_string_utf8(env, blob->field->fieldType, fieldTypeLength, &fieldType);
    if (status != napi_ok) {
        LOGE("create object failed!");
        return NapiGetNull(env);
    }
    status = napi_set_named_property(env, fieldFp, "fieldType", fieldType);
    if (status != napi_ok) {
        LOGE("create object failed!");
        return NapiGetNull(env);
    }
    HcfECFieldFp *tmpField = reinterpret_cast<HcfECFieldFp *>(blob->field);
    napi_value p = ConvertBigIntToNapiValue(env, &(tmpField->p));
    if (p == nullptr) {
        LOGE("p is null!");
        return NapiGetNull(env);
    }
    status = napi_set_named_property(env, fieldFp, "p", p);
    if (status != napi_ok) {
        LOGE("create object failed!");
        return NapiGetNull(env);
    }
    return fieldFp;
}

static bool IsNapiNull(napi_env env, napi_value value)
{
    napi_valuetype valueType;
    napi_typeof(env, value, &valueType);
    return (valueType == napi_null);
}

static napi_value ConvertEccPointToNapiValue(napi_env env, HcfPoint *p)
{
    if (p == nullptr) {
        NAPI_LOG_THROW(env, HCF_INVALID_PARAMS, "Invalid point data!");
        return nullptr;
    }

    napi_value point;
    napi_status status = napi_create_object(env, &point);
    if (status != napi_ok) {
        NAPI_LOG_THROW(env, HCF_ERR_MALLOC, "create object failed!");
        return nullptr;
    }

    napi_value x = ConvertBigIntToNapiValue(env, &(p->x));
    if (x == nullptr || IsNapiNull(env, x)) {
        LOGE("Failed to convert x to NapiValue!");
        return nullptr;
    }

    napi_value y = ConvertBigIntToNapiValue(env, &(p->y));
    if (y == nullptr || IsNapiNull(env, y)) {
        LOGE("Failed to convert y to NapiValue!");
        return nullptr;
    }

    status = napi_set_named_property(env, point, "x", x);
    if (status != napi_ok) {
        NAPI_LOG_THROW(env, HCF_INVALID_PARAMS, "set x property failed!");
        return nullptr;
    }

    status = napi_set_named_property(env, point, "y", y);
    if (status != napi_ok) {
        NAPI_LOG_THROW(env, HCF_INVALID_PARAMS, "set y property failed!");
        return nullptr;
    }

    return point;
}

static napi_value ConvertEccCommonParamPointToNapiValue(napi_env env, HcfEccCommParamsSpec *blob)
{
    napi_value point;
    napi_status status = napi_create_object(env, &point);
    if (status != napi_ok) {
        LOGE("create object failed!");
        return NapiGetNull(env);
    }
    napi_value x = ConvertBigIntToNapiValue(env, &(blob->g.x));
    if (x == nullptr) {
        LOGE("x is null!");
        return NapiGetNull(env);
    }

    napi_value y = ConvertBigIntToNapiValue(env, &(blob->g.y));
    if (y == nullptr) {
        LOGE("y is null!");
        return NapiGetNull(env);
    }
    status = napi_set_named_property(env, point, "x", x);
    if (status != napi_ok) {
        LOGE("create object failed!");
        return NapiGetNull(env);
    }
    status = napi_set_named_property(env, point, "y", y);
    if (status != napi_ok) {
        LOGE("create object failed!");
        return NapiGetNull(env);
    }
    return point;
}

static bool BuildIntancePartertoNapiValueSon(napi_env env, napi_status status, HcfEccCommParamsSpec *blob,
    napi_value *instance)
{
    if (!BuildSetNamedProperty(env, &(blob->a), "a", instance)) {
        LOGE("build setNamedProperty a failed!");
        return false;
    }
    if (!BuildSetNamedProperty(env, &(blob->b), "b", instance)) {
        LOGE("build setNamedProperty b failed!");
        return false;
    }
    if (!BuildSetNamedProperty(env, &(blob->n), "n", instance)) {
        LOGE("build setNamedProperty n failed!");
        return false;
    }
    napi_value h;
    status = napi_create_int32(env, blob->h, &h);
    if (status != napi_ok) {
        LOGE("create h uint32 failed!");
        return false;
    }
    status = napi_set_named_property(env, *instance, "h", h);
    if (status != napi_ok) {
        LOGE("create h uint32 failed!");
        return false;
    }
    return true;
}

static bool BuildInstanceParterToNapiValue(napi_env env, HcfEccCommParamsSpec *blob, napi_value *instance)
{
    napi_value algName;
    size_t algNameLength = HcfStrlen(blob->base.algName);
    if (!algNameLength) {
        LOGE("algName is empty!");
        return false;
    }
    napi_status status = napi_create_string_utf8(env, blob->base.algName, algNameLength, &algName);
    if (status != napi_ok) {
        LOGE("create algName failed!");
        return false;
    }
    napi_value specType;
    status = napi_create_uint32(env, blob->base.specType, &specType);
    if (status != napi_ok) {
        LOGE("create uint32 failed!");
        return false;
    }
    status = napi_set_named_property(env, *instance, "algName", algName);
    if (status != napi_ok) {
        LOGE("create set algName failed!");
        return false;
    }
    status = napi_set_named_property(env, *instance, "specType", specType);
    if (status != napi_ok) {
        LOGE("create set specType failed!");
        return false;
    }
    if (!BuildIntancePartertoNapiValueSon(env, status, blob, instance)) {
        LOGE("create intance parter napi value failed!");
        return false;
    }
    return true;
}

static napi_value ConvertEccCommParamsSpecToNapiValue(napi_env env, HcfEccCommParamsSpec *blob)
{
    if (!CheckEccCommonParamSpec(env, blob)) {
        NAPI_LOG_THROW(env, HCF_INVALID_PARAMS, "Invalid blob!");
        return NapiGetNull(env);
    }
    napi_value instance;
    napi_status status = napi_create_object(env, &instance);
    if (status != napi_ok) {
        NAPI_LOG_THROW(env, HCF_INVALID_PARAMS, "create object failed!");
        return NapiGetNull(env);
    }
    napi_value point = ConvertEccCommonParamPointToNapiValue(env, blob);
    if (point == NapiGetNull(env)) {
        NAPI_LOG_THROW(env, HCF_INVALID_PARAMS, "covert commonParam failed!");
        return NapiGetNull(env);
    }
    napi_value field = ConvertEccCommonParamFieldFpToNapiValue(env, blob);
    if (field == NapiGetNull(env)) {
        NAPI_LOG_THROW(env, HCF_INVALID_PARAMS, "covert commonParam fieldFp failed!");
        return NapiGetNull(env);
    }
    if (!BuildInstanceParterToNapiValue(env, blob, &instance)) {
        NAPI_LOG_THROW(env, HCF_INVALID_PARAMS, "build object failed!");
        return NapiGetNull(env);
    }
    status = napi_set_named_property(env, instance, "field", field);
    if (status != napi_ok) {
        NAPI_LOG_THROW(env, HCF_INVALID_PARAMS, "set fieldFp failed!");
        return NapiGetNull(env);
    }
    status = napi_set_named_property(env, instance, "g", point);
    if (status != napi_ok) {
        NAPI_LOG_THROW(env, HCF_INVALID_PARAMS, "set g failed!");
        return NapiGetNull(env);
    }
    return instance;
}

napi_value NapiECCKeyUtil::JsGenECCCommonParamsSpec(napi_env env, napi_callback_info info)
{
    size_t expectedArgc = ARGS_SIZE_ONE;
    size_t argc = ARGS_SIZE_ONE;
    napi_value argv[ARGS_SIZE_ONE] = { nullptr };
    napi_get_cb_info(env, info, &argc, argv, nullptr, nullptr);

    if (argc != expectedArgc) {
        NAPI_LOG_THROW(env, HCF_INVALID_PARAMS, "The input args num is invalid.");
        return nullptr;
    }

    std::string algName;
    if (!GetStringFromJSParams(env, argv[0], algName)) {
        NAPI_LOG_THROW(env, HCF_INVALID_PARAMS, "failed to get algoName.");
        return NapiGetNull(env);
    }

    HcfEccCommParamsSpec *eccCommParamsSpec = nullptr;
    if (HcfEccKeyUtilCreate(algName.c_str(), &eccCommParamsSpec) != HCF_SUCCESS) {
        NAPI_LOG_THROW(env, HCF_INVALID_PARAMS, "create c generator fail.");
        return NapiGetNull(env);
    }
    napi_value instance = ConvertEccCommParamsSpecToNapiValue(env, eccCommParamsSpec);
    FreeEccCommParamsSpec(eccCommParamsSpec);
    HCF_FREE_PTR(eccCommParamsSpec);
    return instance;
}

napi_value NapiECCKeyUtil::JsConvertPoint(napi_env env, napi_callback_info info)
{
    size_t expectedArgc = ARGS_SIZE_TWO;
    size_t argc = ARGS_SIZE_TWO;
    napi_value argv[ARGS_SIZE_TWO] = { nullptr };
    napi_get_cb_info(env, info, &argc, argv, nullptr, nullptr);

    if (argc != expectedArgc) {
        NAPI_LOG_THROW(env, HCF_INVALID_PARAMS, "The input args num is invalid.");
        return nullptr;
    }

    std::string curveName;
    if (!GetStringFromJSParams(env, argv[PARAM0], curveName)) {
        NAPI_LOG_THROW(env, HCF_INVALID_PARAMS, "failed to get curveName.");
        return nullptr;
    }

    HcfBlob *pointBlob = GetBlobFromNapiUint8Arr(env, argv[PARAM1]);
    if (pointBlob == nullptr) {
        NAPI_LOG_THROW(env, HCF_INVALID_PARAMS, "failed to get point blob.");
        return nullptr;
    }

    HcfPoint point;
    HcfResult ret = HcfConvertPoint(curveName.c_str(), pointBlob, &point);
    if (ret != HCF_SUCCESS) {
        HcfBlobDataFree(pointBlob);
        HcfFree(pointBlob);
        pointBlob = nullptr;
        NAPI_LOG_THROW(env, ret, "failed to convert point.");
        return nullptr;
    }
    napi_value instance = ConvertEccPointToNapiValue(env, &point);
    FreeEcPointMem(&point);
    HcfBlobDataFree(pointBlob);
    HcfFree(pointBlob);
    pointBlob = nullptr;
    return instance;
}

napi_value NapiECCKeyUtil::JsGetEncodedPoint(napi_env env, napi_callback_info info)
{
    size_t expectedArgc = ARGS_SIZE_THREE;
    size_t argc = ARGS_SIZE_THREE;
    napi_value argv[ARGS_SIZE_THREE] = { nullptr };
    napi_get_cb_info(env, info, &argc, argv, nullptr, nullptr);

    if (argc != expectedArgc) {
        NAPI_LOG_THROW(env, HCF_INVALID_PARAMS, "The input args num is invalid.");
        return nullptr;
    }

    std::string curveName;
    if (!GetStringFromJSParams(env, argv[PARAM0], curveName)) {
        NAPI_LOG_THROW(env, HCF_INVALID_PARAMS, "failed to get curveName.");
        return nullptr;
    }

    HcfPoint point;
    if (!GetPointFromNapiValue(env, argv[PARAM1], &point)) {
        NAPI_LOG_THROW(env, HCF_INVALID_PARAMS, "failed to get point.");
        return nullptr;
    }

    std::string format;
    if (!GetStringFromJSParams(env, argv[PARAM2], format)) {
        FreeEcPointMem(&point);
        NAPI_LOG_THROW(env, HCF_INVALID_PARAMS, "failed to get format.");
        return nullptr;
    }

    HcfBlob returnBlob;
    HcfResult ret = HcfGetEncodedPoint(curveName.c_str(), &point, format.c_str(), &returnBlob);
    if (ret != HCF_SUCCESS) {
        FreeEcPointMem(&point);
        NAPI_LOG_THROW(env, ret, "failed to get point data.");
        return nullptr;
    }
    napi_value instance = ConvertObjectBlobToNapiValue(env, &returnBlob);
    FreeEcPointMem(&point);
    HcfBlobDataFree(&returnBlob);
    return instance;
}

napi_value NapiECCKeyUtil::ECCKeyUtilConstructor(napi_env env, napi_callback_info info)
{
    napi_value thisVar = nullptr;
    size_t argc = ARGS_SIZE_ONE;
    napi_value argv[ARGS_SIZE_ONE] = { nullptr };
    NAPI_CALL(env, napi_get_cb_info(env, info, &argc, argv, &thisVar, nullptr));
    return thisVar;
}

napi_value NapiECCKeyUtil::GenECCCommonParamSpec(napi_env env)
{
    napi_value cons = nullptr;
    napi_property_descriptor clzDes[] = {
        DECLARE_NAPI_STATIC_FUNCTION("genECCCommonParamsSpec", NapiECCKeyUtil::JsGenECCCommonParamsSpec),
        DECLARE_NAPI_STATIC_FUNCTION("convertPoint", NapiECCKeyUtil::JsConvertPoint),
        DECLARE_NAPI_STATIC_FUNCTION("getEncodedPoint", NapiECCKeyUtil::JsGetEncodedPoint),
    };
    NAPI_CALL(env, napi_define_class(env, "ECCKeyUtil", NAPI_AUTO_LENGTH, NapiECCKeyUtil::ECCKeyUtilConstructor,
        nullptr, sizeof(clzDes) / sizeof(clzDes[0]), clzDes, &cons));
    return cons;
}

void NapiECCKeyUtil::DefineNapiECCKeyUtilJSClass(napi_env env, napi_value exports)
{
    napi_set_named_property(env, exports, "ECCKeyUtil", NapiECCKeyUtil::GenECCCommonParamSpec(env));
}
} // CryptoFramework
} // OHOS
