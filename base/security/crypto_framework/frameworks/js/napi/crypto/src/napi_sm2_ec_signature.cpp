/*
 * Copyright (C) 2025 Huawei Device Co., Ltd.
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

#include "napi_sm2_ec_signature.h"

#include <string>
#include "securec.h"
#include "log.h"
#include "memory.h"
#include "napi_crypto_framework_defines.h"
#include "napi_utils.h"

namespace OHOS {
namespace CryptoFramework {
NapiSm2EcSignature::NapiSm2EcSignature() {}
NapiSm2EcSignature::~NapiSm2EcSignature() {}

static bool GetSm2EcSignatureDataSpecFromNapiValue(napi_env env, napi_value arg, Sm2EcSignatureDataSpec **returnSpec)
{
    if ((env == nullptr) || (arg == nullptr) || (returnSpec == nullptr)) {
        LOGE("Invalid params.");
        return false;
    }
    Sm2EcSignatureDataSpec *tempSpec =
        static_cast<Sm2EcSignatureDataSpec *>(HcfMalloc(sizeof(Sm2EcSignatureDataSpec), 0));
    if (tempSpec == nullptr) {
        LOGE("Malloc failed!");
        return false;
    }
    napi_value rCoordinate = GetDetailAsyKeySpecValue(env, arg, SM2_EC_SIGNATURE_PARAM_R);
    napi_value sCoordinate = GetDetailAsyKeySpecValue(env, arg, SM2_EC_SIGNATURE_PARAM_S);
    if ((rCoordinate == nullptr) || (sCoordinate == nullptr)) {
        LOGE("Invalid params!");
        DestroySm2EcSignatureSpec(tempSpec);
        return false;
    }
    bool ret = GetBigIntFromNapiValue(env, rCoordinate, &tempSpec->rCoordinate);
    if (!ret) {
        LOGE("Failed to get valid r coordinate.");
        DestroySm2EcSignatureSpec(tempSpec);
        return false;
    }
    ret = GetBigIntFromNapiValue(env, sCoordinate, &tempSpec->sCoordinate);
    if (!ret) {
        LOGE("Failed to get valid s coordinate.");
        DestroySm2EcSignatureSpec(tempSpec);
        return false;
    }
    *returnSpec = tempSpec;
    return true;
}

napi_value NapiSm2EcSignature::JsGenEcSignatureData(napi_env env, napi_callback_info info)
{
    size_t expectedArgc = PARAMS_NUM_ONE;
    size_t argc = ARGS_SIZE_ONE;
    napi_value argv[ARGS_SIZE_ONE] = { nullptr };
    napi_get_cb_info(env, info, &argc, argv, nullptr, nullptr);
    if (argc != expectedArgc) {
        NAPI_LOG_THROW(env, HCF_INVALID_PARAMS, "The input args num is invalid.");
        return nullptr;
    }
    Sm2EcSignatureDataSpec *spec = nullptr;
    if (!GetSm2EcSignatureDataSpecFromNapiValue(env, argv[0], &spec)) {
        NAPI_LOG_THROW(env, HCF_INVALID_PARAMS, "failed to get spec.");
        return nullptr;
    }
    HcfBlob *output = static_cast<HcfBlob *>(HcfMalloc(sizeof(HcfBlob), 0));
    if (output == NULL) {
        DestroySm2EcSignatureSpec(spec);
        NAPI_LOG_THROW(env, HCF_ERR_MALLOC, "Failed to allocate memory.");
        return nullptr;
    }
    HcfResult res = HcfGenEcSignatureDataBySpec(spec, output);
    if (res != HCF_SUCCESS) {
        HcfFree(output);
        output = nullptr;
        DestroySm2EcSignatureSpec(spec);
        NAPI_LOG_THROW(env, res, "gen cipher text by spec fail.");
        return nullptr;
    }
    napi_value instance = ConvertObjectBlobToNapiValue(env, output);
    HcfBlobDataFree(output);
    HcfFree(output);
    output = nullptr;
    DestroySm2EcSignatureSpec(spec);
    return instance;
}

static bool CheckSm2CipherTextSpec(Sm2EcSignatureDataSpec *spec)
{
    if (spec == nullptr) {
        LOGE("Invalid spec!");
        return false;
    }
    if (spec->rCoordinate.data == nullptr || spec->rCoordinate.len == 0) {
        LOGE("Invalid rCoordinate!");
        return false;
    }
    if (spec->sCoordinate.data == nullptr || spec->sCoordinate.len == 0) {
        LOGE("Invalid sCoordinate!");
        return false;
    }
    return true;
}

static bool BuildSm2CipherTextSpecToNapiValue(napi_env env, Sm2EcSignatureDataSpec *spec, napi_value *instance)
{
    if (!BuildSetNamedProperty(env, &(spec->rCoordinate), SM2_EC_SIGNATURE_PARAM_R.c_str(), instance)) {
        LOGE("Build rCoordinate failed!");
        return false;
    }
    if (!BuildSetNamedProperty(env, &(spec->sCoordinate), SM2_EC_SIGNATURE_PARAM_S.c_str(), instance)) {
        LOGE("Build sCoordinate failed!");
        return false;
    }
    return true;
}

static napi_value ConvertSm2CipherTextSpecToNapiValue(napi_env env, Sm2EcSignatureDataSpec *spec)
{
    if (!CheckSm2CipherTextSpec(spec)) {
        NAPI_LOG_THROW(env, HCF_ERR_NAPI, "Invalid spec!");
        return NapiGetNull(env);
    }
    napi_value instance;
    napi_status status = napi_create_object(env, &instance);
    if (status != napi_ok) {
        NAPI_LOG_THROW(env, HCF_ERR_MALLOC, "create object failed!");
        return NapiGetNull(env);
    }
    if (!BuildSm2CipherTextSpecToNapiValue(env, spec, &instance)) {
        NAPI_LOG_THROW(env, HCF_ERR_NAPI, "build object failed!");
        return NapiGetNull(env);
    }
    return instance;
}

napi_value NapiSm2EcSignature::JsGenEcSignatureDataSpec(napi_env env, napi_callback_info info)
{
    size_t expectedArgc = PARAMS_NUM_ONE;
    size_t argc = ARGS_SIZE_ONE;
    napi_value argv[ARGS_SIZE_ONE] = { nullptr };
    napi_get_cb_info(env, info, &argc, argv, nullptr, nullptr);
    if (argc != expectedArgc) {
        NAPI_LOG_THROW(env, HCF_INVALID_PARAMS, "The input args num is invalid.");
        return nullptr;
    }
    HcfBlob *cipherText = GetBlobFromNapiUint8Arr(env, argv[0]);
    if (cipherText == nullptr) {
        NAPI_LOG_THROW(env, HCF_INVALID_PARAMS, "failed to get cipherText.");
        return nullptr;
    }
    Sm2EcSignatureDataSpec *returnSpec = nullptr;
    HcfResult res = HcfGenEcSignatureSpecByData(cipherText, &returnSpec);
    if (res != HCF_SUCCESS) {
        HcfBlobDataFree(cipherText);
        HcfFree(cipherText);
        cipherText = nullptr;
        NAPI_LOG_THROW(env, res, "get cipher text spec fail.");
        return nullptr;
    }
    napi_value instance = ConvertSm2CipherTextSpecToNapiValue(env, returnSpec);
    DestroySm2EcSignatureSpec(returnSpec);
    HcfBlobDataFree(cipherText);
    HcfFree(cipherText);
    cipherText = nullptr;
    return instance;
}

napi_value NapiSm2EcSignature::SignatureUtilsConstructor(napi_env env, napi_callback_info info)
{
    napi_value thisVar = nullptr;
    size_t argc = ARGS_SIZE_ONE;
    napi_value argv[ARGS_SIZE_ONE] = { nullptr };
    NAPI_CALL(env, napi_get_cb_info(env, info, &argc, argv, &thisVar, nullptr));
    return thisVar;
}

napi_value NapiSm2EcSignature::SignatureUtilsConstructorClass(napi_env env)
{
    napi_value cons = nullptr;
    napi_property_descriptor clzDes[] = {
        DECLARE_NAPI_STATIC_FUNCTION("genEccSignature", NapiSm2EcSignature::JsGenEcSignatureData),
        DECLARE_NAPI_STATIC_FUNCTION("genEccSignatureSpec", NapiSm2EcSignature::JsGenEcSignatureDataSpec),
    };
    NAPI_CALL(env, napi_define_class(env, "SignatureUtils", NAPI_AUTO_LENGTH,
        NapiSm2EcSignature::SignatureUtilsConstructor,
        nullptr, sizeof(clzDes) / sizeof(clzDes[0]), clzDes, &cons));
    return cons;
}

void NapiSm2EcSignature::DefineNapiSm2EcSignatureJSClass(napi_env env, napi_value exports)
{
    napi_set_named_property(env, exports, "SignatureUtils", NapiSm2EcSignature::SignatureUtilsConstructorClass(env));
}
} // CryptoFramework
} // OHOS
 