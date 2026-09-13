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

#include "napi_sm2_crypto_util.h"

#include <string>
#include "securec.h"
#include "log.h"
#include "memory.h"
#include "napi_crypto_framework_defines.h"
#include "napi_utils.h"

namespace OHOS {
namespace CryptoFramework {
NapiSm2CryptoUtil::NapiSm2CryptoUtil() {}
NapiSm2CryptoUtil::~NapiSm2CryptoUtil() {}

static HcfBlob *GetBlobFromNapi(napi_env env, napi_value arg, const std::string &name)
{
    // get uint8Array attribute
    napi_value data = nullptr;
    napi_valuetype valueType = napi_undefined;
    napi_status status = napi_get_named_property(env, arg, name.c_str(), &data);
    napi_typeof(env, data, &valueType);
    if ((status != napi_ok) || (data == nullptr) || (valueType == napi_undefined)) {
        LOGE("failed to get valid salt");
        return nullptr;
    }
    return GetBlobFromNapiUint8Arr(env, data);
}

static bool GetSm2CipherTextSpecFromNapiValue(napi_env env, napi_value arg, Sm2CipherTextSpec **returnSpec)
{
    if ((env == nullptr) || (arg == nullptr) || (returnSpec == nullptr)) {
        LOGE("Invalid params.");
        return false;
    }
    Sm2CipherTextSpec *tempSpec = static_cast<Sm2CipherTextSpec *>(HcfMalloc(sizeof(Sm2CipherTextSpec), 0));
    if (tempSpec == nullptr) {
        LOGE("Malloc failed!");
        return false;
    }
    napi_value xCoordinate = GetDetailAsyKeySpecValue(env, arg, SM2_UTIL_PARAM_X_COORDINATE);
    napi_value yCoordinate = GetDetailAsyKeySpecValue(env, arg, SM2_UTIL_PARAM_Y_COORDINATE);
    if ((xCoordinate == nullptr) || (yCoordinate == nullptr)) {
        LOGE("Invalid params!");
        DestroySm2CipherTextSpec(tempSpec);
        return false;
    }
    bool ret = GetBigIntFromNapiValue(env, xCoordinate, &tempSpec->xCoordinate);
    if (!ret) {
        LOGE("Failed to get valid x coordinate.");
        DestroySm2CipherTextSpec(tempSpec);
        return false;
    }
    ret = GetBigIntFromNapiValue(env, yCoordinate, &tempSpec->yCoordinate);
    if (!ret) {
        LOGE("Failed to get valid y coordinate.");
        DestroySm2CipherTextSpec(tempSpec);
        return false;
    }
    HcfBlob *cipherTextBlob = GetBlobFromNapi(env, arg, SM2_UTIL_PARAM_CIPHER_TEXT_DATA);
    if (cipherTextBlob == nullptr) {
        LOGE("Failed to get valid cipherTextData.");
        DestroySm2CipherTextSpec(tempSpec);
        return false;
    }
    HcfBlob *hashDataBlob = GetBlobFromNapi(env, arg, SM2_UTIL_PARAM_HASH_DATA);
    if (hashDataBlob == nullptr) {
        LOGE("Failed to get valid hashData.");
        HcfBlobDataFree(cipherTextBlob);
        HCF_FREE_PTR(cipherTextBlob);
        DestroySm2CipherTextSpec(tempSpec);
        return false;
    }
    tempSpec->cipherTextData = *cipherTextBlob;
    tempSpec->hashData = *hashDataBlob;
    *returnSpec = tempSpec;
    HCF_FREE_PTR(cipherTextBlob);
    HCF_FREE_PTR(hashDataBlob);
    return true;
}

static bool DealMode(napi_env env, napi_value arg, std::string &returnStr)
{
    napi_valuetype valueType;
    napi_typeof(env, arg, &valueType);
    if (valueType == napi_null || valueType == napi_undefined) {
        return true;
    }
    if (!GetStringFromJSParams(env, arg, returnStr)) {
        LOGE("Failed to get mode string from JS params");
        return false;
    }
    return true;
}

napi_value NapiSm2CryptoUtil::JsGenCipherTextBySpec(napi_env env, napi_callback_info info)
{
    size_t expectedArgc = PARAMS_NUM_TWO;
    size_t argc = ARGS_SIZE_TWO;
    napi_value argv[ARGS_SIZE_TWO] = { nullptr };
    napi_get_cb_info(env, info, &argc, argv, nullptr, nullptr);
    // second attribute mode can be null
    if ((argc != expectedArgc) && (argc != (expectedArgc - 1))) {
        NAPI_LOG_THROW(env, HCF_INVALID_PARAMS, "The input args num is invalid.");
        return nullptr;
    }
    Sm2CipherTextSpec *spec = nullptr;
    if (!GetSm2CipherTextSpecFromNapiValue(env, argv[0], &spec)) {
        NAPI_LOG_THROW(env, HCF_INVALID_PARAMS, "failed to get spec.");
        return nullptr;
    }
    std::string dataMode;
    if (argc == expectedArgc) {
        if (!DealMode(env, argv[1], dataMode)) {
            DestroySm2CipherTextSpec(spec);
            NAPI_LOG_THROW(env, HCF_INVALID_PARAMS, "failed to get mode.");
            return nullptr;
        }
    }
    HcfBlob *output = static_cast<HcfBlob *>(HcfMalloc(sizeof(HcfBlob), 0));
    if (output == NULL) {
        DestroySm2CipherTextSpec(spec);
        NAPI_LOG_THROW(env, HCF_ERR_MALLOC, "Failed to allocate memory.");
        return nullptr;
    }
    HcfResult res = HcfGenCipherTextBySpec(spec, dataMode.c_str(), output);
    if (res != HCF_SUCCESS) {
        HcfFree(output);
        output = nullptr;
        DestroySm2CipherTextSpec(spec);
        NAPI_LOG_THROW(env, res, "gen cipher text by spec fail.");
        return nullptr;
    }
    napi_value instance = ConvertBlobToNapiValue(env, output);
    HcfBlobDataFree(output);
    HcfFree(output);
    output = nullptr;
    DestroySm2CipherTextSpec(spec);
    return instance;
}

static bool CheckSm2CipherTextSpec(Sm2CipherTextSpec *spec)
{
    if (spec == nullptr) {
        LOGE("Invalid spec!");
        return false;
    }
    if (spec->xCoordinate.data == nullptr || spec->xCoordinate.len == 0) {
        LOGE("Invalid xCoordinate!");
        return false;
    }
    if (spec->yCoordinate.data == nullptr || spec->yCoordinate.len == 0) {
        LOGE("Invalid yCoordinate!");
        return false;
    }
    if (spec->cipherTextData.data == nullptr || spec->cipherTextData.len == 0) {
        LOGE("Invalid cipherTextData!");
        return false;
    }
    if (spec->hashData.data == nullptr || spec->hashData.len == 0) {
        LOGE("Invalid hashData!");
        return false;
    }
    return true;
}

static bool BuildBlobNapiValue(napi_env env, HcfBlob *blob, const char *name, napi_value *instance)
{
    napi_value napiData = ConvertObjectBlobToNapiValue(env, blob);
    napi_status status = napi_set_named_property(env, *instance, name, napiData);
    if (status != napi_ok) {
        LOGE("Build blob[napi_value] failed!");
        return false;
    }
    return true;
}

static bool BuildSm2CipherTextSpecToNapiValue(napi_env env, Sm2CipherTextSpec *spec, napi_value *instance)
{
    if (!BuildSetNamedProperty(env, &(spec->xCoordinate), SM2_UTIL_PARAM_X_COORDINATE.c_str(), instance)) {
        LOGE("Build xCoordinate failed!");
        return false;
    }
    if (!BuildSetNamedProperty(env, &(spec->yCoordinate), SM2_UTIL_PARAM_Y_COORDINATE.c_str(), instance)) {
        LOGE("Build yCoordinate failed!");
        return false;
    }
    if (!BuildBlobNapiValue(env, &(spec->cipherTextData), SM2_UTIL_PARAM_CIPHER_TEXT_DATA.c_str(), instance)) {
        LOGE("Build cipherTextData failed!");
        return false;
    }
    if (!BuildBlobNapiValue(env, &(spec->hashData), SM2_UTIL_PARAM_HASH_DATA.c_str(), instance)) {
        LOGE("Build hashData failed!");
        return false;
    }
    return true;
}

static napi_value ConvertSm2CipherTextSpecToNapiValue(napi_env env, Sm2CipherTextSpec *spec)
{
    if (!CheckSm2CipherTextSpec(spec)) {
        NAPI_LOG_THROW(env, HCF_INVALID_PARAMS, "Invalid spec!");
        return NapiGetNull(env);
    }
    napi_value instance;
    napi_status status = napi_create_object(env, &instance);
    if (status != napi_ok) {
        NAPI_LOG_THROW(env, HCF_ERR_MALLOC, "create object failed!");
        return NapiGetNull(env);
    }
    if (!BuildSm2CipherTextSpecToNapiValue(env, spec, &instance)) {
        NAPI_LOG_THROW(env, HCF_INVALID_PARAMS, "build object failed!");
        return NapiGetNull(env);
    }
    return instance;
}

napi_value NapiSm2CryptoUtil::JsGetCipherTextSpec(napi_env env, napi_callback_info info)
{
    size_t expectedArgc = PARAMS_NUM_TWO;
    size_t argc = ARGS_SIZE_TWO;
    napi_value argv[ARGS_SIZE_TWO] = { nullptr };
    napi_get_cb_info(env, info, &argc, argv, nullptr, nullptr);
    // second attribute mode can be null
    if ((argc != expectedArgc) && (argc != (expectedArgc - 1))) {
        NAPI_LOG_THROW(env, HCF_INVALID_PARAMS, "The input args num is invalid.");
        return nullptr;
    }
    HcfBlob *cipherText = GetBlobFromNapiDataBlob(env, argv[0]);
    if (cipherText == nullptr) {
        NAPI_LOG_THROW(env, HCF_INVALID_PARAMS, "failed to get cipherText.");
        return nullptr;
    }
    std::string dataMode;
    if (argc == expectedArgc) {
        if (!DealMode(env, argv[1], dataMode)) {
            HcfBlobDataFree(cipherText);
            HcfFree(cipherText);
            cipherText = nullptr;
            NAPI_LOG_THROW(env, HCF_INVALID_PARAMS, "failed to get mode.");
            return nullptr;
        }
    }
    Sm2CipherTextSpec *returnSpec = nullptr;
    HcfResult res = HcfGetCipherTextSpec(cipherText, dataMode.c_str(), &returnSpec);
    if (res != HCF_SUCCESS) {
        HcfBlobDataFree(cipherText);
        HcfFree(cipherText);
        cipherText = nullptr;
        NAPI_LOG_THROW(env, res, "get cipher text spec fail.");
        return nullptr;
    }
    napi_value instance = ConvertSm2CipherTextSpecToNapiValue(env, returnSpec);
    DestroySm2CipherTextSpec(returnSpec);
    HcfBlobDataFree(cipherText);
    HcfFree(cipherText);
    cipherText = nullptr;
    return instance;
}

napi_value NapiSm2CryptoUtil::Sm2CryptoUtilConstructor(napi_env env, napi_callback_info info)
{
    napi_value thisVar = nullptr;
    size_t argc = ARGS_SIZE_ONE;
    napi_value argv[ARGS_SIZE_ONE] = { nullptr };
    NAPI_CALL(env, napi_get_cb_info(env, info, &argc, argv, &thisVar, nullptr));
    return thisVar;
}

napi_value NapiSm2CryptoUtil::Sm2CryptoUtilConstructorClass(napi_env env)
{
    napi_value cons = nullptr;
    napi_property_descriptor clzDes[] = {
        DECLARE_NAPI_STATIC_FUNCTION("genCipherTextBySpec", NapiSm2CryptoUtil::JsGenCipherTextBySpec),
        DECLARE_NAPI_STATIC_FUNCTION("getCipherTextSpec", NapiSm2CryptoUtil::JsGetCipherTextSpec),
    };
    NAPI_CALL(env, napi_define_class(env, "SM2CryptoUtil", NAPI_AUTO_LENGTH,
        NapiSm2CryptoUtil::Sm2CryptoUtilConstructor,
        nullptr, sizeof(clzDes) / sizeof(clzDes[0]), clzDes, &cons));
    return cons;
}

void NapiSm2CryptoUtil::DefineNapiSm2CryptoUtilJSClass(napi_env env, napi_value exports)
{
    napi_set_named_property(env, exports, "SM2CryptoUtil", NapiSm2CryptoUtil::Sm2CryptoUtilConstructorClass(env));
}
} // CryptoFramework
} // OHOS
 