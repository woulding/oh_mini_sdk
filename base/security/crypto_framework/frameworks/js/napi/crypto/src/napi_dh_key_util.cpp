/*
 * Copyright (C) 2023 Huawei Device Co., Ltd.
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

#include "napi_dh_key_util.h"
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
NapiDHKeyUtil::NapiDHKeyUtil() {}

NapiDHKeyUtil::~NapiDHKeyUtil() {}


static bool BuildDhInstanceToNapiValueSub(napi_env env, HcfDhCommParamsSpec *blob, napi_value *instance)
{
    if (!BuildSetNamedProperty(env, &(blob->p), "p", instance)) {
        LOGE("build setNamedProperty a failed!");
        return false;
    }
    if (!BuildSetNamedProperty(env, &(blob->g), "g", instance)) {
        LOGE("build setNamedProperty b failed!");
        return false;
    }
    napi_value length;
    napi_status status = napi_create_int32(env, blob->length, &length);
    if (status != napi_ok) {
        LOGE("create length number failed!");
        return false;
    }
    status = napi_set_named_property(env, *instance, "l", length);
    if (status != napi_ok) {
        LOGE("create length number failed!");
        return false;
    }
    return true;
}

static bool BuildDhInstanceToNapiValue(napi_env env, HcfDhCommParamsSpec *blob, napi_value *instance)
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
    if (!BuildDhInstanceToNapiValueSub(env, blob, instance)) {
        LOGE("create intance parter napi value failed!");
        return false;
    }
    return true;
}

static bool CheckDhCommonParamSpec(napi_env env, HcfDhCommParamsSpec *blob)
{
    if (blob == nullptr) {
        LOGE("Invalid blob!");
        return false;
    }
    if (blob->base.algName == nullptr) {
        LOGE("Invalid blob algName!");
        return false;
    }
    if (blob->p.data == nullptr || blob->p.len == 0) {
        LOGE("Invalid blob a!");
        return false;
    }
    if (blob->g.data == nullptr || blob->g.len == 0) {
        LOGE("Invalid blob point x!");
        return false;
    }
    return true;
}

static napi_value ConvertDhCommParamsSpecToNapiValue(napi_env env, HcfDhCommParamsSpec *blob)
{
    if (!CheckDhCommonParamSpec(env, blob)) {
        NAPI_LOG_THROW(env, HCF_INVALID_PARAMS, "Invalid blob!");
        return NapiGetNull(env);
    }
    napi_value instance;
    napi_status status = napi_create_object(env, &instance);
    if (status != napi_ok) {
        NAPI_LOG_THROW(env, HCF_INVALID_PARAMS, "create object failed!");
        return NapiGetNull(env);
    }
    if (!BuildDhInstanceToNapiValue(env, blob, &instance)) {
        NAPI_LOG_THROW(env, HCF_INVALID_PARAMS, "build object failed!");
        return NapiGetNull(env);
    }
    return instance;
}

napi_value NapiDHKeyUtil::JsGenDHCommonParamsSpec(napi_env env, napi_callback_info info)
{
    size_t expectedArgc = PARAMS_NUM_TWO;
    size_t argc = ARGS_SIZE_TWO;
    napi_value argv[ARGS_SIZE_TWO] = { nullptr };
    napi_get_cb_info(env, info, &argc, argv, nullptr, nullptr);

    if ((argc != expectedArgc) && (argc != (expectedArgc - 1))) {
        NAPI_LOG_THROW(env, HCF_INVALID_PARAMS, "The input args num is invalid.");
        return nullptr;
    }

    int32_t pLen = 0;
    if (!GetInt32FromJSParams(env, argv[0], pLen)) {
        NAPI_LOG_THROW(env, HCF_INVALID_PARAMS, "failed to get pLen.");
        return NapiGetNull(env);
    }

    int32_t skLen = 0;
    if (argc == expectedArgc) {
        if (!GetInt32FromJSParams(env, argv[1], skLen)) {
            NAPI_LOG_THROW(env, HCF_INVALID_PARAMS, "failed to get skLen.");
            return NapiGetNull(env);
        }
    }
    HcfDhCommParamsSpec *dhCommParamsSpec = nullptr;
    if (HcfDhKeyUtilCreate(pLen, skLen, &dhCommParamsSpec) != HCF_SUCCESS) {
        NAPI_LOG_THROW(env, HCF_INVALID_PARAMS, "create c generator fail.");
        return NapiGetNull(env);
    }

    napi_value instance = ConvertDhCommParamsSpecToNapiValue(env, dhCommParamsSpec);
    FreeDhCommParamsSpec(dhCommParamsSpec);
    HCF_FREE_PTR(dhCommParamsSpec);
    return instance;
}

napi_value NapiDHKeyUtil::DHKeyUtilConstructor(napi_env env, napi_callback_info info)
{
    napi_value thisVar = nullptr;
    size_t argc = ARGS_SIZE_ONE;
    napi_value argv[ARGS_SIZE_ONE] = { nullptr };
    NAPI_CALL(env, napi_get_cb_info(env, info, &argc, argv, &thisVar, nullptr));
    return thisVar;
}

napi_value NapiDHKeyUtil::GenDHCommonParamSpec(napi_env env)
{
    napi_value cons = nullptr;
    napi_property_descriptor clzDes[] = {
        DECLARE_NAPI_STATIC_FUNCTION("genDHCommonParamsSpec", NapiDHKeyUtil::JsGenDHCommonParamsSpec),
    };
    NAPI_CALL(env, napi_define_class(env, "DHKeyUtil", NAPI_AUTO_LENGTH, NapiDHKeyUtil::DHKeyUtilConstructor,
        nullptr, sizeof(clzDes) / sizeof(clzDes[0]), clzDes, &cons));
    return cons;
}

void NapiDHKeyUtil::DefineNapiDHKeyUtilJSClass(napi_env env, napi_value exports)
{
    napi_set_named_property(env, exports, "DHKeyUtil", NapiDHKeyUtil::GenDHCommonParamSpec(env));
}
} // CryptoFramework
} // OHOS
