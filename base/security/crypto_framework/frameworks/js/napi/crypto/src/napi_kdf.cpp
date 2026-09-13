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

#include "napi_kdf.h"

#include "securec.h"
#include "memory.h"

#include "napi_utils.h"
#include "napi_crypto_framework_defines.h"
#include "detailed_pbkdf2_params.h"
#include "detailed_hkdf_params.h"
#include "detailed_scrypt_params.h"
#include "detailed_x963kdf_params.h"

#define PBKDF2_ALG_SIZE 6

namespace OHOS {
namespace CryptoFramework {
thread_local napi_ref NapiKdf::classRef_ = nullptr;

struct KdfCtx {
    napi_env env = nullptr;

    AsyncType asyncType = ASYNC_CALLBACK;
    napi_ref callback = nullptr;
    napi_deferred deferred = nullptr;
    napi_value promise = nullptr;
    napi_async_work asyncWork = nullptr;
    napi_ref kdfRef = nullptr;

    HcfResult errCode = HCF_SUCCESS;
    const char *errMsg = nullptr;
    HcfKdfParamsSpec *paramsSpec = nullptr;
    HcfKdf *kdf = nullptr;
};

static void FreeKdfParamsSpec(HcfKdfParamsSpec *params)
{
    if (params == nullptr) {
        return;
    }
    if (PBKDF2_ALG_NAME.compare(params->algName) == 0) {
        HcfPBKDF2ParamsSpec *tmp = reinterpret_cast<HcfPBKDF2ParamsSpec *>(params);
        HcfBlobDataClearAndFree(&(tmp->password));
        HcfBlobDataClearAndFree(&(tmp->salt));
        HcfBlobDataClearAndFree(&(tmp->output));
        tmp->base.algName = nullptr;
    } else if (HKDF_ALG_NAME.compare(params->algName) == 0) {
        HcfHkdfParamsSpec *tmp = reinterpret_cast<HcfHkdfParamsSpec *>(params);
        HcfBlobDataClearAndFree(&(tmp->key));
        HcfBlobDataClearAndFree(&(tmp->salt));
        HcfBlobDataClearAndFree(&(tmp->info));
        HcfBlobDataClearAndFree(&(tmp->output));
        tmp->base.algName = nullptr;
    } else if (SCRYPT_ALG_NAME.compare(params->algName) == 0) {
        HcfScryptParamsSpec *tmp = reinterpret_cast<HcfScryptParamsSpec *>(params);
        HcfBlobDataClearAndFree(&(tmp->passPhrase));
        HcfBlobDataClearAndFree(&(tmp->salt));
        HcfBlobDataClearAndFree(&(tmp->output));
        tmp->base.algName = nullptr;
    } else if (X963KDF_ALG_NAME.compare(params->algName) == 0) {
        HcfX963KDFParamsSpec *tmp = reinterpret_cast<HcfX963KDFParamsSpec *>(params);
        HcfBlobDataClearAndFree(&(tmp->key));
        HcfBlobDataClearAndFree(&(tmp->info));
        HcfBlobDataClearAndFree(&(tmp->output));
        tmp->base.algName = nullptr;
    }

    HcfFree(params);
}

static void FreeCryptoFwkCtx(napi_env env, KdfCtx *context)
{
    if (context == nullptr) {
        return;
    }
    if (context->asyncWork != nullptr) {
        napi_delete_async_work(env, context->asyncWork);
        context->asyncWork = nullptr;
    }

    if (context->callback != nullptr) {
        napi_delete_reference(env, context->callback);
        context->callback = nullptr;
    }

    if (context->kdfRef != nullptr) {
        napi_delete_reference(env, context->kdfRef);
        context->kdfRef = nullptr;
    }

    FreeKdfParamsSpec(context->paramsSpec);
    context->paramsSpec = nullptr;
    context->errMsg = nullptr;
    context->kdf = nullptr;
    HcfFree(context);
}

static void ReturnCallbackResult(napi_env env, KdfCtx *context, napi_value result)
{
    napi_value businessError = nullptr;
    if (context->errCode != HCF_SUCCESS) {
        businessError = GenerateBusinessError(env, context->errCode, context->errMsg);
    }
    napi_value params[ARGS_SIZE_TWO] = { businessError, result };

    napi_value func = nullptr;
    napi_get_reference_value(env, context->callback, &func);

    napi_value recv = nullptr;
    napi_value callFuncRet = nullptr;
    napi_get_undefined(env, &recv);
    napi_call_function(env, recv, func, ARGS_SIZE_TWO, params, &callFuncRet);
}

static void ReturnPromiseResult(napi_env env, KdfCtx *context, napi_value result)
{
    if (context->errCode == HCF_SUCCESS) {
        napi_resolve_deferred(env, context->deferred, result);
    } else {
        napi_reject_deferred(env, context->deferred,
            GenerateBusinessError(env, context->errCode, context->errMsg));
    }
}

static void KdfGenSecretExecute(napi_env env, void *data)
{
    KdfCtx *context = static_cast<KdfCtx *>(data);
    HcfKdf *kdf = context->kdf;
    context->errCode = kdf->generateSecret(kdf, context->paramsSpec);
    if (context->errCode != HCF_SUCCESS) {
        LOGE("KDF generateSecret failed!");
        context->errMsg = "KDF generateSecret failed";
        return;
    }
}

static void KdfGenSecretComplete(napi_env env, napi_status status, void *data)
{
    KdfCtx *context = static_cast<KdfCtx *>(data);
    napi_value returnBlob = nullptr;
    if (PBKDF2_ALG_NAME.compare(context->paramsSpec->algName) == 0) {
        HcfPBKDF2ParamsSpec *params = reinterpret_cast<HcfPBKDF2ParamsSpec *>(context->paramsSpec);
        returnBlob = ConvertBlobToNapiValue(env, &(params->output));
    } else if (HKDF_ALG_NAME.compare(context->paramsSpec->algName) == 0) {
        HcfHkdfParamsSpec *params = reinterpret_cast<HcfHkdfParamsSpec *>(context->paramsSpec);
        returnBlob = ConvertBlobToNapiValue(env, &(params->output));
    } else if (SCRYPT_ALG_NAME.compare(context->paramsSpec->algName) == 0) {
        HcfScryptParamsSpec *params = reinterpret_cast<HcfScryptParamsSpec *>(context->paramsSpec);
        returnBlob = ConvertBlobToNapiValue(env, &(params->output));
    } else if (X963KDF_ALG_NAME.compare(context->paramsSpec->algName) == 0) {
        HcfX963KDFParamsSpec *params = reinterpret_cast<HcfX963KDFParamsSpec *>(context->paramsSpec);
        returnBlob = ConvertBlobToNapiValue(env, &(params->output));
    }
    if (returnBlob == nullptr) {
        LOGE("returnOutBlob is nullptr!");
        returnBlob = NapiGetNull(env);
    }
    if (context->asyncType == ASYNC_CALLBACK) {
        ReturnCallbackResult(env, context, returnBlob);
    } else {
        ReturnPromiseResult(env, context, returnBlob);
    }
    FreeCryptoFwkCtx(env, context);
}

static bool GetInt32FromKdfParams(napi_env env, napi_value arg, const std::string &name, int32_t &retInt)
{
    // int attribute
    napi_value dataInt = nullptr;
    napi_valuetype valueType = napi_undefined;
    napi_status status = napi_get_named_property(env, arg, name.c_str(), &dataInt);
    napi_typeof(env, dataInt, &valueType);
    if ((status != napi_ok) || (dataInt == nullptr) || (valueType == napi_undefined)) {
        LOGE("failed to get valid napi int");
        return false;
    }
    return GetInt32FromJSParams(env, dataInt, retInt);
}

static bool GetUint64FromKdfParams(napi_env env, napi_value arg, const std::string &name, uint64_t &retInt)
{
    napi_value dataInt = nullptr;
    napi_valuetype valueType = napi_undefined;
    napi_status status = napi_get_named_property(env, arg, name.c_str(), &dataInt);
    napi_typeof(env, dataInt, &valueType);
    if ((status != napi_ok) || (dataInt == nullptr) || (valueType == napi_undefined)) {
        LOGE("failed to get valid napi int");
        return false;
    }
    return GetUint64FromJSParams(env, dataInt, retInt);
}

static bool GetCharArrayFromUint8Arr(napi_env env, napi_value data, HcfBlob *retBlob)
{
    size_t length = 0;
    size_t offset = 0;
    void *rawData = nullptr;
    napi_value arrayBuffer = nullptr;
    napi_typedarray_type arrayType;
    // Warning: Do not release the rawData returned by this interface because the rawData is managed by VM.
    napi_status status = napi_get_typedarray_info(env, data, &arrayType, &length,
        reinterpret_cast<void **>(&rawData), &arrayBuffer, &offset);
    if ((status != napi_ok)) {
        LOGE("failed to get valid rawData.");
        return false;
    }
    if (arrayType != napi_uint8_array) {
        LOGE("input data is not uint8 array.");
        return false;
    }
    // input empty uint8Arr, ex: new Uint8Arr(), the length is 0 and rawData is nullptr;
    if ((length == 0) || (rawData == nullptr)) {
        LOGD("napi Uint8Arr is null");
        return true;
    }
    if (length > INT_MAX) {
        LOGE("Beyond the size");
        return false;
    }
    uint8_t *tmp = static_cast<uint8_t *>(HcfMalloc(length, 0));
    if (tmp == nullptr) {
        LOGE("malloc blob data failed!");
        return false;
    }
    (void)memcpy_s(tmp, length, rawData, length);
    retBlob->data = tmp;
    retBlob->len = length;
    return true;
}

static bool GetCharArrayFromJsString(napi_env env, napi_value arg, HcfBlob *retBlob)
{
    size_t length = 0;
    if (napi_get_value_string_utf8(env, arg, nullptr, 0, &length) != napi_ok) {
        LOGE("can not get char string length");
        return false;
    }
    if (length > INT_MAX) {
        LOGE("password length should not exceed INT_MAX");
        return false;
    }
    if (length == 0) {
        LOGD("empty string");
        return true;
    }
    char *tmpPassword = static_cast<char *>(HcfMalloc(length + 1, 0));
    if (tmpPassword == nullptr) {
        LOGE("malloc string failed");
        return false;
    }
    if (napi_get_value_string_utf8(env, arg, tmpPassword, (length + 1), &length) != napi_ok) {
        LOGE("can not get char string value");
        HcfFree(tmpPassword);
        tmpPassword = nullptr;
        return false;
    }
    retBlob->data = reinterpret_cast<uint8_t *>(tmpPassword);
    retBlob->len = length;
    return true;
}

static bool GetKeyOrPwdFromKdfParams(napi_env env, napi_value arg, const std::string &name, HcfBlob *retBlob)
{
    napi_value data = nullptr;
    napi_valuetype valueType = napi_undefined;
    napi_status status = napi_get_named_property(env, arg, name.c_str(), &data);
    napi_typeof(env, data, &valueType);
    if ((status != napi_ok) || (data == nullptr) || (valueType == napi_undefined)) {
        LOGE("failed to get valid password");
        return false;
    }
    if (valueType == napi_string) {
        if (GetCharArrayFromJsString(env, data, retBlob) != true) {
            LOGE("get char string failed");
            return false;
        }
    } else {
        if (GetCharArrayFromUint8Arr(env, data, retBlob) != true) {
            LOGE("get uint8arr failed");
            return false;
        }
    }
    return true;
}

static HcfBlob *GetBlobFromKdfParamsSpec(napi_env env, napi_value arg, const std::string &name)
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

static void SetPBKDF2ParamsSpecAttribute(int iter, const HcfBlob &out, HcfBlob *salt, const HcfBlob &password,
    HcfPBKDF2ParamsSpec *tmp)
{
    tmp->iterations = iter;
    tmp->output = out;
    tmp->salt.data = salt->data;
    tmp->salt.len = salt->len;
    tmp->password = password;
    tmp->base.algName = PBKDF2_ALG_NAME.c_str();
}

static void SetHkdfParamsSpecAttribute(const HcfBlob &out, const HcfBlob *salt, const HcfBlob &key,
    const HcfBlob *info, HcfHkdfParamsSpec *tmpParams)
{
    tmpParams->output = out;
    tmpParams->salt = *salt;
    tmpParams->key = key;
    tmpParams->info = *info;
    tmpParams->base.algName = HKDF_ALG_NAME.c_str();
}

static void SetScryptParamsSpecAttribute(const HcfBlob &out, const HcfBlob *salt, const HcfBlob &passPhrase,
    HcfScryptParamsSpec *tmpParams)
{
    tmpParams->output = out;
    tmpParams->salt = *salt;
    tmpParams->passPhrase = passPhrase;
    tmpParams->base.algName = SCRYPT_ALG_NAME.c_str();
}

static void SetX963ParamsSpecAttribute(const HcfBlob &out, const HcfBlob &key, const HcfBlob *info,
    HcfX963KDFParamsSpec *tmpParams)
{
    tmpParams->output = out;
    tmpParams->key = key;
    tmpParams->info = *info;
    tmpParams->base.algName = X963KDF_ALG_NAME.c_str();
}

static bool GetPBKDF2ParamsSpec(napi_env env, napi_value arg, HcfKdfParamsSpec **params)
{
    // get attribute from params
    // int attribute
    int iter = -1;
    int keySize = -1;
    if (!GetInt32FromKdfParams(env, arg, PBKDF2_PARAMS_ITER, iter) ||
        !GetInt32FromKdfParams(env, arg, KDF_PARAMS_KEY_SIZE, keySize)) {
        LOGE("failed to get valid num");
        return false;
    }
    if (iter <= 0 || keySize <= 0) {
        LOGE("iter and keySize should larger than 0");
        return false;
    }
    HcfBlob out = { .data = static_cast<uint8_t *>(HcfMalloc(keySize, 0)), .len = keySize };
    if (out.data == nullptr) {
        LOGE("output malloc failed!");
        return false;
    }
    HcfBlob tmpPassword = { .data = nullptr, .len = 0 };
    HcfBlob *salt = nullptr;
    HcfPBKDF2ParamsSpec *tmp = nullptr;
    do {
        // get password
        if (!GetKeyOrPwdFromKdfParams(env, arg, PBKDF2_PARAMS_PASSWORD, &tmpPassword)) {
            LOGE("failed to get password");
            break;
        }
        // get salt attribute
        salt = GetBlobFromKdfParamsSpec(env, arg, KDF_PARAMS_SALT);
        if (salt == nullptr) {
            LOGE("fail to get salt");
            break;
        }
        // malloc params
        tmp = static_cast<HcfPBKDF2ParamsSpec *>(HcfMalloc(sizeof(HcfPBKDF2ParamsSpec), 0));
        if (tmp == nullptr) {
            LOGE("pbkdf2 spec malloc failed!");
            break;
        }
        SetPBKDF2ParamsSpecAttribute(iter, out, salt, tmpPassword, tmp);
        // only need the data and data length of the salt, so free the blob pointer.
        HcfFree(salt);
        salt = nullptr;
        *params = reinterpret_cast<HcfKdfParamsSpec *>(tmp);
        return true;
    } while (0);
    HcfBlobDataClearAndFree(&tmpPassword);
    HcfBlobDataClearAndFree(salt);
    HcfFree(salt);
    salt = nullptr;
    HcfFree(out.data);
    out.data = nullptr;
    return false;
}

static bool GetHkdfParamsSpec(napi_env env, napi_value arg, HcfKdfParamsSpec **params)
{
    int keySize = -1;
    if (!GetInt32FromKdfParams(env, arg, KDF_PARAMS_KEY_SIZE, keySize)) {
        LOGE("failed to get valid num");
        return false;
    }
    if (keySize <= 0) {
        LOGE("keySize should larger than 0");
        return false;
    }
    HcfBlob out = { .data = static_cast<uint8_t *>(HcfMalloc(keySize, 0)), .len = keySize };
    if (out.data == nullptr) {
        LOGE("output malloc failed!");
        return false;
    }

    HcfBlob *salt = nullptr;
    HcfBlob key = { .data = nullptr, .len = 0 };
    HcfBlob *info = nullptr;
    HcfHkdfParamsSpec *tmpParams = nullptr;
    do {
        // get key
        if (!GetKeyOrPwdFromKdfParams(env, arg, KDF_PARAMS_KEY, &key)) {
            LOGE("failed to get key");
            break;
        }

        // get info、salt
        info = GetBlobFromKdfParamsSpec(env, arg, KDF_PARAMS_INFO);
        salt = GetBlobFromKdfParamsSpec(env, arg, KDF_PARAMS_SALT);
        if (info == nullptr || salt == nullptr) {
            LOGE("fail to get info or salt");
            break;
        }

        // malloc tmpParams
        tmpParams = static_cast<HcfHkdfParamsSpec *>(HcfMalloc(sizeof(HcfHkdfParamsSpec), 0));
        if (tmpParams == nullptr) {
            LOGE("hkdf spec malloc failed!");
            break;
        }
        SetHkdfParamsSpecAttribute(out, salt, key, info, tmpParams);
        // only need the data and data length of the salt, so free the blob pointer.
        HCF_FREE_PTR(salt);
        HCF_FREE_PTR(info);
        *params = reinterpret_cast<HcfKdfParamsSpec *>(tmpParams);
        return true;
    } while (0);
    HcfBlobDataClearAndFree(salt);
    HcfBlobDataClearAndFree(&key);
    HcfBlobDataClearAndFree(info);
    HCF_FREE_PTR(salt);
    HCF_FREE_PTR(info);
    HCF_FREE_PTR(out.data);
    return false;
}

static bool AllocateAndSetScryptParams(napi_env env, napi_value arg, HcfBlob &out, HcfScryptParamsSpec *&tmpParams)
{
    HcfBlob *salt = nullptr;
    HcfBlob passPhrase = { .data = nullptr, .len = 0 };
    do {
        if (!GetKeyOrPwdFromKdfParams(env, arg, SCRYPT_PASSPHRASE, &passPhrase)) {
            LOGE("failed to get passPhrase");
            break;
        }

        salt = GetBlobFromKdfParamsSpec(env, arg, KDF_PARAMS_SALT);
        if (salt == nullptr) {
            LOGE("fail to get salt");
            break;
        }

        tmpParams = static_cast<HcfScryptParamsSpec *>(HcfMalloc(sizeof(HcfScryptParamsSpec), 0));
        if (tmpParams == nullptr) {
            LOGE("scrypt spec malloc failed!");
            break;
        }

        SetScryptParamsSpecAttribute(out, salt, passPhrase, tmpParams);
        HcfFree(salt);
        salt = nullptr;
        return true;
    } while (0);
    HcfBlobDataClearAndFree(salt);
    HcfBlobDataClearAndFree(&passPhrase);
    HcfFree(salt);
    salt = nullptr;

    return false;
}

static bool GetScryptParamsSpec(napi_env env, napi_value arg, HcfKdfParamsSpec **params)
{
    int keySize = -1;
    if (!GetInt32FromKdfParams(env, arg, KDF_PARAMS_KEY_SIZE, keySize)) {
        LOGE("failed to get valid num");
        return false;
    }
    if (keySize <= 0) {
        LOGE("keySize should larger than 0");
        return false;
    }

    uint64_t n = 0;
    uint64_t r = 0;
    uint64_t p = 0;
    uint64_t maxMemory = 0;
    if (!GetUint64FromKdfParams(env, arg, SCRYPT_N, n) || !GetUint64FromKdfParams(env, arg, SCRYPT_R, r) ||
        !GetUint64FromKdfParams(env, arg, SCRYPT_P, p) || !GetUint64FromKdfParams(env, arg, SCRYPT_MEMORY, maxMemory)) {
        LOGE("failed to get valid num");
        return false;
    }

    HcfBlob out = { .data = static_cast<uint8_t *>(HcfMalloc(keySize, 0)), .len = keySize };
    if (out.data == nullptr) {
        LOGE("output malloc failed!");
        return false;
    }

    HcfScryptParamsSpec *tmpParams = nullptr;
    if (!AllocateAndSetScryptParams(env, arg, out, tmpParams)) {
        HcfFree(out.data);
        out.data = nullptr;
        return false;
    }
    tmpParams->n = n;
    tmpParams->p = p;
    tmpParams->r = r;
    tmpParams->maxMem = maxMemory;

    *params = reinterpret_cast<HcfKdfParamsSpec *>(tmpParams);
    return true;
}

static bool GetX963ParamsSpec(napi_env env, napi_value arg, HcfKdfParamsSpec **params)
{
    int keySize = -1;
    if (!GetInt32FromKdfParams(env, arg, KDF_PARAMS_KEY_SIZE, keySize)) {
        LOGE("failed to get valid num");
        return false;
    }
    if (keySize <= 0 || keySize > X963KDF_MAX_KEY_SIZE) {
        LOGE("keySize should larger than 0");
        return false;
    }

    HcfBlob out = { .data = static_cast<uint8_t *>(HcfMalloc(keySize, 0)), .len = keySize };
    if (out.data == nullptr) {
        LOGE("output malloc failed!");
        return false;
    }

    HcfBlob key = { .data = nullptr, .len = 0 };
    HcfBlob *info = nullptr;
    HcfX963KDFParamsSpec *tmpParams = nullptr;
    do {
        if (!GetKeyOrPwdFromKdfParams(env, arg, KDF_PARAMS_KEY, &key)) {
            LOGE("failed to get key");
            break;
        }
        info = GetBlobFromKdfParamsSpec(env, arg, KDF_PARAMS_INFO);
        if (info == nullptr) {
            LOGE("fail to get info");
            break;
        }
        tmpParams = static_cast<HcfX963KDFParamsSpec *>(HcfMalloc(sizeof(HcfX963KDFParamsSpec), 0));
        if (tmpParams == nullptr) {
            LOGE("x963kdf spec malloc failed!");
            break;
        }
        SetX963ParamsSpecAttribute(out, key, info, tmpParams);
        HCF_FREE_PTR(info);
        *params = reinterpret_cast<HcfKdfParamsSpec *>(tmpParams);
        return true;
    } while (0);
    HcfBlobDataClearAndFree(info);
    HcfBlobDataClearAndFree(&key);
    HCF_FREE_PTR(info);
    HCF_FREE_PTR(out.data);
    return false;
}

static bool GetKdfParamsSpec(napi_env env, napi_value arg, HcfKdfParamsSpec **params)
{
    napi_value data = nullptr;
    napi_valuetype valueType = napi_undefined;
    if ((env == nullptr) || (arg == nullptr) || (params == nullptr)) {
        LOGE("Invalid params!");
        return false;
    }

    napi_status status = napi_get_named_property(env, arg, ALGO_PARAMS.c_str(), &data);
    napi_typeof(env, data, &valueType);
    if ((status != napi_ok) || (data == nullptr) || (valueType == napi_undefined)) {
        LOGE("failed to get valid algo name!");
        return false;
    }
    std::string algoName;
    if (!GetStringFromJSParams(env, data, algoName)) {
        LOGE("GetStringFromJSParams failed!");
        return false;
    }
    if (algoName.compare(PBKDF2_ALG_NAME) == 0) {
        return GetPBKDF2ParamsSpec(env, arg, params);
    } else if (algoName.compare(HKDF_ALG_NAME) == 0) {
        return GetHkdfParamsSpec(env, arg, params);
    } else if (algoName.compare(SCRYPT_ALG_NAME) == 0) {
        return GetScryptParamsSpec(env, arg, params);
    } else if (algoName.compare(X963KDF_ALG_NAME) == 0) {
        return GetX963ParamsSpec(env, arg, params);
    } else {
        LOGE("Not support that alg");
        return false;
    }
}

static bool BuildKdfGenSecretCtx(napi_env env, napi_callback_info info, KdfCtx *context)
{
    napi_value thisVar = nullptr;
    size_t expectedArgsCount = ARGS_SIZE_TWO;
    size_t argc = expectedArgsCount;
    napi_value argv[ARGS_SIZE_TWO] = { nullptr };
    napi_get_cb_info(env, info, &argc, argv, &thisVar, nullptr);
    if ((argc != expectedArgsCount) && (argc != expectedArgsCount - CALLBACK_SIZE)) {
        LOGE("The arguments count is not expected!");
        return false;
    }

    NapiKdf *napiKdf = nullptr;
    napi_status status = napi_unwrap(env, thisVar, reinterpret_cast<void **>(&napiKdf));
    if (status != napi_ok || napiKdf == nullptr) {
        LOGE("failed to unwrap NapiKdf obj!");
        return false;
    }

    context->kdf = napiKdf->GetKdf();
    if (!GetKdfParamsSpec(env, argv[PARAM0], &(context->paramsSpec))) {
        LOGE("get kdf paramsspec failed!");
        return false;
    }
    context->asyncType = isCallback(env, argv[expectedArgsCount - 1], argc, expectedArgsCount) ?
        ASYNC_CALLBACK : ASYNC_PROMISE;

    if (napi_create_reference(env, thisVar, 1, &context->kdfRef) != napi_ok) {
        LOGE("create kdf ref failed when derive secret key using kdf!");
        return false;
    }

    if (context->asyncType == ASYNC_PROMISE) {
        napi_create_promise(env, &context->deferred, &context->promise);
        return true;
    } else {
        return GetCallbackFromJSParams(env, argv[PARAM1], &context->callback);
    }
}

static napi_value NewKdfJsGenSecretAsyncWork(napi_env env, KdfCtx *context)
{
    napi_create_async_work(
        env, nullptr, GetResourceName(env, "KdfGenerateSecret"),
        [](napi_env env, void *data) {
            KdfGenSecretExecute(env, data);
            return;
        },
        [](napi_env env, napi_status status, void *data) {
            KdfGenSecretComplete(env, status, data);
            return;
        },
        static_cast<void *>(context),
        &context->asyncWork);

    napi_queue_async_work(env, context->asyncWork);
    if (context->asyncType == ASYNC_PROMISE) {
        return context->promise;
    } else {
        return NapiGetNull(env);
    }
}

NapiKdf::NapiKdf(HcfKdf *kdfObj)
{
    this->kdf = kdfObj;
}

NapiKdf::~NapiKdf()
{
    HcfObjDestroy(this->kdf);
    this->kdf = nullptr;
}

HcfKdf *NapiKdf::GetKdf() const
{
    return this->kdf;
}

napi_value NapiKdf::JsKdfGenerateSecret(napi_env env, napi_callback_info info)
{
    KdfCtx *context = static_cast<KdfCtx *>(HcfMalloc(sizeof(KdfCtx), 0));
    if (context == nullptr) {
        NAPI_LOG_THROW(env, HCF_ERR_MALLOC, "malloc context failed");
        return nullptr;
    }

    if (!BuildKdfGenSecretCtx(env, info, context)) {
        NAPI_LOG_THROW(env, HCF_INVALID_PARAMS, "build context fail.");
        FreeCryptoFwkCtx(env, context);
        return nullptr;
    }

    return NewKdfJsGenSecretAsyncWork(env, context);
}

static napi_value NewKdfJsGenSecretSyncWork(napi_env env, HcfKdfParamsSpec *paramsSpec)
{
    napi_value returnBlob = nullptr;
    if (PBKDF2_ALG_NAME.compare(paramsSpec->algName) == 0) {
        HcfPBKDF2ParamsSpec *params = reinterpret_cast<HcfPBKDF2ParamsSpec *>(paramsSpec);
        returnBlob = ConvertBlobToNapiValue(env, &(params->output));
    } else if (HKDF_ALG_NAME.compare(paramsSpec->algName) == 0) {
        HcfHkdfParamsSpec *params = reinterpret_cast<HcfHkdfParamsSpec *>(paramsSpec);
        returnBlob = ConvertBlobToNapiValue(env, &(params->output));
    } else if (SCRYPT_ALG_NAME.compare(paramsSpec->algName) == 0) {
        HcfScryptParamsSpec *params = reinterpret_cast<HcfScryptParamsSpec *>(paramsSpec);
        returnBlob = ConvertBlobToNapiValue(env, &(params->output));
    } else if (X963KDF_ALG_NAME.compare(paramsSpec->algName) == 0) {
        HcfX963KDFParamsSpec *params = reinterpret_cast<HcfX963KDFParamsSpec *>(paramsSpec);
        returnBlob = ConvertBlobToNapiValue(env, &(params->output));
    }
    if (returnBlob == nullptr) {
        NAPI_LOG_THROW(env, HCF_ERR_NAPI, "returnBlob is nullptr!");
        returnBlob = NapiGetNull(env);
    }
    FreeKdfParamsSpec(paramsSpec);
    paramsSpec = nullptr;
    return returnBlob;
}

napi_value NapiKdf::JsKdfGenerateSecretSync(napi_env env, napi_callback_info info)
{
    napi_value thisVar = nullptr;
    size_t argc = ARGS_SIZE_ONE;
    napi_value argv[ARGS_SIZE_ONE] = { nullptr };
    napi_get_cb_info(env, info, &argc, argv, &thisVar, nullptr);
    if (argc != ARGS_SIZE_ONE) {
        NAPI_LOG_THROW(env, HCF_INVALID_PARAMS, "The arguments count is not expected!");
        return nullptr;
    }
    NapiKdf *napiKdf = nullptr;
    napi_status status = napi_unwrap(env, thisVar, reinterpret_cast<void **>(&napiKdf));
    if (status != napi_ok || napiKdf == nullptr) {
        NAPI_LOG_THROW(env, HCF_ERR_NAPI, "failed to unwrap NapiKdf obj!");
        return nullptr;
    }
    HcfKdf *kdf = napiKdf->GetKdf();
    if (kdf == nullptr) {
        NAPI_LOG_THROW(env, HCF_INVALID_PARAMS, "fail to get kdf obj!");
        return nullptr;
    }
    HcfKdfParamsSpec *paramsSpec = nullptr;
    if (!GetKdfParamsSpec(env, argv[PARAM0], &paramsSpec)) {
        NAPI_LOG_THROW(env, HCF_INVALID_PARAMS, "get kdf paramsspec failed!");
        FreeKdfParamsSpec(paramsSpec);
        paramsSpec = nullptr;
        return nullptr;
    }
    HcfResult errCode = kdf->generateSecret(kdf, paramsSpec);
    if (errCode != HCF_SUCCESS) {
        NAPI_LOG_THROW(env, errCode, "KDF generateSecret failed!");
        FreeKdfParamsSpec(paramsSpec);
        return nullptr;
    }
    napi_value returnBlob = NewKdfJsGenSecretSyncWork(env, paramsSpec);
    return returnBlob;
}

napi_value NapiKdf::JsGetAlgorithm(napi_env env, napi_callback_info info)
{
    napi_value thisVar = nullptr;
    NapiKdf *napiKdf = nullptr;

    napi_get_cb_info(env, info, nullptr, nullptr, &thisVar, nullptr);
    napi_status status = napi_unwrap(env, thisVar, reinterpret_cast<void **>(&napiKdf));
    if (status != napi_ok || napiKdf == nullptr) {
        LOGE("failed to unwrap NapiKdf obj!");
        return nullptr;
    }

    HcfKdf *kdf = napiKdf->GetKdf();
    if (kdf == nullptr) {
        LOGE("fail to get kdf obj!");
        return nullptr;
    }

    const char *algoName = kdf->getAlgorithm(kdf);
    napi_value instance = nullptr;
    napi_create_string_utf8(env, algoName, NAPI_AUTO_LENGTH, &instance);
    return instance;
}

napi_value NapiKdf::KdfConstructor(napi_env env, napi_callback_info info)
{
    napi_value thisVar = nullptr;
    napi_get_cb_info(env, info, nullptr, nullptr, &thisVar, nullptr);
    return thisVar;
}

napi_value NapiKdf::CreateJsKdf(napi_env env, napi_callback_info info)
{
    size_t expectedArgc = ARGS_SIZE_ONE;
    size_t argc = expectedArgc;
    napi_value argv[ARGS_SIZE_ONE] = { nullptr };
    napi_get_cb_info(env, info, &argc, argv, nullptr, nullptr);
    if (argc != expectedArgc) {
        NAPI_LOG_THROW(env, HCF_INVALID_PARAMS, "The input args num is invalid.");
        return nullptr;
    }
    std::string algoName;
    if (!GetStringFromJSParams(env, argv[PARAM0], algoName)) {
        NAPI_LOG_THROW(env, HCF_INVALID_PARAMS, "Failed to get algorithm.");
        return nullptr;
    }
    HcfKdf *kdf = nullptr;
    HcfResult res = HcfKdfCreate(algoName.c_str(), &kdf);
    if (res != HCF_SUCCESS) {
        NAPI_LOG_THROW(env, res, "create C obj failed.");
        return nullptr;
    }
    napi_value instance = nullptr;
    napi_value constructor = nullptr;
    napi_get_reference_value(env, classRef_, &constructor);
    napi_new_instance(env, constructor, 0, nullptr, &instance);
    NapiKdf *napiKdf = new (std::nothrow) NapiKdf(kdf);
    if (napiKdf == nullptr) {
        HcfObjDestroy(kdf);
        kdf = nullptr;
        NAPI_LOG_THROW(env, HCF_ERR_MALLOC, "new kdf napi obj failed.");
        return nullptr;
    }
    napi_status status = napi_wrap(env, instance, napiKdf,
        [](napi_env env, void *data, void *hint) {
            delete(static_cast<NapiKdf *>(data));
        }, nullptr, nullptr);
    if (status != napi_ok) {
        delete napiKdf;
        NAPI_LOG_THROW(env, HCF_INVALID_PARAMS, "failed to wrap NapiKdf obj!");
        return nullptr;
    }
    return instance;
}

void NapiKdf::DefineKdfJSClass(napi_env env, napi_value exports)
{
    napi_property_descriptor desc[] = {
        DECLARE_NAPI_FUNCTION("createKdf", NapiKdf::CreateJsKdf),
    };
    napi_define_properties(env, exports, sizeof(desc) / sizeof(desc[0]), desc);
    napi_property_descriptor classDesc[] = {
        DECLARE_NAPI_FUNCTION("generateSecret", NapiKdf::JsKdfGenerateSecret),
        DECLARE_NAPI_FUNCTION("generateSecretSync", NapiKdf::JsKdfGenerateSecretSync),
        {.utf8name = "algName", .getter = NapiKdf::JsGetAlgorithm},
    };
    napi_value constructor = nullptr;
    napi_define_class(env, "Kdf", NAPI_AUTO_LENGTH, KdfConstructor, nullptr,
        sizeof(classDesc) / sizeof(classDesc[0]), classDesc, &constructor);
    napi_create_reference(env, constructor, 1, &classRef_);
}
} // CryptoFramework
} // OHOS
