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

#include "napi_cipher.h"
#include "napi_key.h"
#include "securec.h"
#include "log.h"
#include "memory.h"
#include "utils.h"

#include "cipher.h"
#include "napi_utils.h"
#include "napi_crypto_framework_defines.h"
#include "detailed_iv_params.h"
#include "detailed_gcm_params.h"
#include "detailed_ccm_params.h"
#include "detailed_aead_params.h"
#include "detailed_chacha20_params.h"

namespace OHOS {
namespace CryptoFramework {
thread_local napi_ref NapiCipher::classRef_ = nullptr;

struct CipherFwkCtxT {
    napi_env env = nullptr;
    AsyncType asyncType = ASYNC_CALLBACK;
    napi_ref callback = nullptr;
    napi_deferred deferred = nullptr;
    napi_value promise = nullptr;
    napi_async_work asyncWork = nullptr;
    napi_ref cipherRef = nullptr;
    napi_ref inputRef = nullptr;
    napi_ref keyRef = nullptr;

    HcfCipher *cipher = nullptr;
    HcfKey *key = nullptr;
    HcfParamsSpec *paramsSpec = nullptr;
    HcfBlob input = { .data = nullptr, .len = 0 };
    HcfBlob output = { .data = nullptr, .len = 0 };
    enum HcfCryptoMode opMode = ENCRYPT_MODE;

    HcfResult errCode = HCF_SUCCESS;
    const char *errMsg = nullptr;
    char *cryptoErrMsg = nullptr;
};

using CipherFwkCtx = CipherFwkCtxT *;

static void FreeParamsSpec(HcfParamsSpec *paramsSpec)
{
    if (paramsSpec == nullptr) {
        return;
    }
    if (IV_PARAMS_SPEC.compare(paramsSpec->getType()) == 0) {
        HcfIvParamsSpec *ivSpec = reinterpret_cast<HcfIvParamsSpec *>(paramsSpec);
        HcfBlobDataFree(&(ivSpec->iv));
    }
    if (GCM_PARAMS_SPEC.compare(paramsSpec->getType()) == 0) {
        HcfGcmParamsSpec *gcm = reinterpret_cast<HcfGcmParamsSpec *>(paramsSpec);
        HcfBlobDataFree(&(gcm->iv));
        HcfBlobDataFree(&(gcm->aad));
        HcfBlobDataFree(&(gcm->tag));
    }
    if (CCM_PARAMS_SPEC.compare(paramsSpec->getType()) == 0) {
        HcfCcmParamsSpec *ccm = reinterpret_cast<HcfCcmParamsSpec *>(paramsSpec);
        HcfBlobDataFree(&(ccm->iv));
        HcfBlobDataFree(&(ccm->aad));
        HcfBlobDataFree(&(ccm->tag));
    }
    if (POLY1305_PARAMS_SPEC.compare(paramsSpec->getType()) == 0) {
        HcfChaCha20ParamsSpec *poly1305 = reinterpret_cast<HcfChaCha20ParamsSpec *>(paramsSpec);
        HcfBlobDataFree(&(poly1305->iv));
        HcfBlobDataFree(&(poly1305->aad));
        HcfBlobDataFree(&(poly1305->tag));
    }
    if (AEAD_PARAMS_SPEC.compare(paramsSpec->getType()) == 0) {
        HcfAeadParamsSpec *aead = reinterpret_cast<HcfAeadParamsSpec *>(paramsSpec);
        HcfBlobDataFree(&(aead->nonce));
        HcfBlobDataFree(&(aead->aad));
    }
    HcfFree(paramsSpec);
}

static void FreeCipherFwkCtx(napi_env env, CipherFwkCtx &context)
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

    if (context->cipherRef != nullptr) {
        napi_delete_reference(env, context->cipherRef);
        context->cipherRef = nullptr;
    }

    if (context->inputRef != nullptr) {
        napi_delete_reference(env, context->inputRef);
        context->inputRef = nullptr;
    }

    if (context->keyRef != nullptr) {
        napi_delete_reference(env, context->keyRef);
        context->keyRef = nullptr;
    }

    if (context->output.data != nullptr) {
        HcfFree(context->output.data);
        context->output.data = nullptr;
        context->output.len = 0;
    }
    FreeParamsSpec(context->paramsSpec);
    context->paramsSpec = nullptr;

    context->cipher = nullptr;
    context->key = nullptr;
    context->errMsg = nullptr;
    HcfFree(context->cryptoErrMsg);
    HcfFree(context);
    context = nullptr;
}

static bool CreateCipherRef(napi_env env, napi_value thisVar, napi_value key, CipherFwkCtx ctx)
{
    if (napi_create_reference(env, thisVar, 1, &ctx->cipherRef) != napi_ok) {
        LOGE("create cipher ref failed when do cipher init!");
        return false;
    }

    if (napi_create_reference(env, key, 1, &ctx->keyRef) != napi_ok) {
        LOGE("create key ref failed when do cipher init!");
        return false;
    }

    return true;
}

static bool BuildContextForInit(napi_env env, napi_callback_info info, CipherFwkCtx context)
{
    napi_value thisVar = nullptr;
    NapiCipher *napiCipher = nullptr;
    NapiKey *napiKey = nullptr;
    size_t expectedArgc = ARGS_SIZE_FOUR;
    size_t argc = ARGS_SIZE_FOUR;
    napi_value argv[ARGS_SIZE_FOUR] = { nullptr };
    napi_get_cb_info(env, info, &argc, argv, &thisVar, nullptr);
    if (argc != expectedArgc && argc != expectedArgc - 1) {
        LOGE("wrong argument num. require 3 or 4 arguments. [Argc]: %{public}zu!", argc);
        return false;
    }
    context->asyncType = isCallback(env, argv[expectedArgc - 1], argc, expectedArgc) ? ASYNC_CALLBACK : ASYNC_PROMISE;

    napi_status status = napi_unwrap(env, thisVar, reinterpret_cast<void **>(&napiCipher));
    if (status != napi_ok || napiCipher == nullptr) {
        LOGE("failed to unwrap napi napiCipher obj!");
        return false;
    }
    context->cipher = napiCipher->GetCipher();

    // get opMode, type is uint32
    size_t index = 0;
    if (napi_get_value_uint32(env, argv[index++], reinterpret_cast<uint32_t *>(&(context->opMode))) != napi_ok) {
        LOGE("get opMode failed!");
        return false;
    }

    // get key, unwrap from JS
    status = napi_unwrap(env, argv[index++], reinterpret_cast<void **>(&napiKey));
    if (status != napi_ok || napiKey == nullptr) {
        LOGE("failed to unwrap napi napiSymKey obj!");
        return false;
    }
    context->key = napiKey->GetHcfKey();

    // get paramsSpec, unwrap from JS
    napi_valuetype valueType;
    napi_typeof(env, argv[index], &valueType);
    if (valueType != napi_null) {
        if (!GetParamsSpecFromNapiValue(env, argv[index], context->opMode, &context->paramsSpec)) {
            LOGE("Failed to parse cipher parameters spec from napi value.");
            return false;
        }
    }
    index++;

    if (!CreateCipherRef(env, thisVar, argv[PARAM1], context)) {
        return false;
    }

    if (context->asyncType == ASYNC_PROMISE) {
        napi_create_promise(env, &context->deferred, &context->promise);
        return true;
    } else {
        return GetCallbackFromJSParams(env, argv[index], &context->callback);
    }
}

static bool BuildContextForUpdate(napi_env env, napi_callback_info info, CipherFwkCtx context)
{
    napi_value thisVar = nullptr;
    NapiCipher *napiCipher = nullptr;
    size_t expectedArgc = ARGS_SIZE_TWO;
    size_t argc = ARGS_SIZE_TWO;
    napi_value argv[ARGS_SIZE_TWO] = { nullptr };
    napi_get_cb_info(env, info, &argc, argv, &thisVar, nullptr);
    // argc : in & out, receives the actual count of arguments
    if (argc != expectedArgc && argc != expectedArgc - 1) {
        LOGE("wrong argument num. require 1 or 2 arguments. [Argc]: %{public}zu!", argc);
        return false;
    }
    context->asyncType = isCallback(env, argv[expectedArgc - 1], argc, expectedArgc) ? ASYNC_CALLBACK : ASYNC_PROMISE;

    napi_status status = napi_unwrap(env, thisVar, reinterpret_cast<void **>(&napiCipher));
    if (status != napi_ok || napiCipher == nullptr) {
        LOGE("failed to unwrap napi napiCipher obj!");
        return false;
    }
    context->cipher = napiCipher->GetCipher();

    if (GetNapiUint8ArrayDataNoCopy(env, argv[0], &context->input) != HCF_SUCCESS) {
        LOGE("Failed to get uint8 array data without copy from napi value.");
        return false;
    }
    if (napi_create_reference(env, argv[0], 1, &context->inputRef) != napi_ok) {
        LOGE("create input ref failed when do cipher update!");
        return false;
    }

    if (napi_create_reference(env, thisVar, 1, &context->cipherRef) != napi_ok) {
        LOGE("create cipher ref failed when do cipher update!");
        return false;
    }

    if (context->asyncType == ASYNC_PROMISE) {
        napi_create_promise(env, &context->deferred, &context->promise);
        return true;
    } else {
        return GetCallbackFromJSParams(env, argv[1], &context->callback);
    }
}

static bool BuildContextForFinal(napi_env env, napi_callback_info info, CipherFwkCtx context)
{
    napi_value thisVar = nullptr;
    NapiCipher *napiCipher = nullptr;
    size_t expectedArgc = ARGS_SIZE_TWO;
    size_t argc = ARGS_SIZE_TWO;
    napi_value argv[ARGS_SIZE_TWO] = { nullptr };
    napi_get_cb_info(env, info, &argc, argv, &thisVar, nullptr);
    if (argc != expectedArgc && argc != expectedArgc - 1) {
        LOGE("wrong argument num. require 1 or 2 arguments. [Argc]: %{public}zu!", argc);
        return false;
    }
    context->asyncType = isCallback(env, argv[expectedArgc - 1], argc, expectedArgc) ? ASYNC_CALLBACK : ASYNC_PROMISE;

    napi_status status = napi_unwrap(env, thisVar, reinterpret_cast<void **>(&napiCipher));
    if (status != napi_ok || napiCipher == nullptr) {
        LOGE("failed to unwrap napi napiCipher obj!");
        return false;
    }
    context->cipher = napiCipher->GetCipher();

    // get input, type is blob
    napi_valuetype valueType;
    napi_typeof(env, argv[0], &valueType);
    if (valueType != napi_null) {
        if (GetNapiUint8ArrayDataNoCopy(env, argv[0], &context->input) != HCF_SUCCESS) {
            LOGE("Failed to get uint8 array data without copy from napi value.");
            return false;
        }
        if (napi_create_reference(env, argv[0], 1, &context->inputRef) != napi_ok) {
            LOGE("create input ref failed when do cipher final!");
            return false;
        }
    }

    if (napi_create_reference(env, thisVar, 1, &context->cipherRef) != napi_ok) {
        LOGE("create cipher ref failed when do cipher final!");
        return false;
    }

    if (context->asyncType == ASYNC_PROMISE) {
        napi_create_promise(env, &context->deferred, &context->promise);
        return true;
    } else {
        return GetCallbackFromJSParams(env, argv[1], &context->callback);
    }
}

static void ReturnCallbackResult(napi_env env, CipherFwkCtx context, napi_value result)
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

static void ReturnPromiseResult(napi_env env, CipherFwkCtx context, napi_value result)
{
    if (context->errCode == HCF_SUCCESS) {
        napi_resolve_deferred(env, context->deferred, result);
    } else {
        napi_reject_deferred(env, context->deferred,
            GenerateBusinessError(env, context->errCode, context->errMsg));
    }
}

// init execute
static void AsyncInitProcess(napi_env env, void *data)
{
    CipherFwkCtx context = static_cast<CipherFwkCtx>(data);
    HcfCipher *cipher = context->cipher;
    HcfParamsSpec *params = context->paramsSpec;
    HcfKey *key = context->key;

    context->errCode = cipher->init(cipher, context->opMode, key, params);
    if (context->errCode != HCF_SUCCESS) {
        LOGE("init ret:%{public}d", context->errCode);
        context->errMsg = "cipher init failed.";
        HcfGetCryptoOperationErrMsg(context->errCode, &context->errMsg, &context->cryptoErrMsg);
    }
}

// update execute
static void AsyncUpdateProcess(napi_env env, void *data)
{
    CipherFwkCtx context = static_cast<CipherFwkCtx>(data);
    HcfCipher *cipher = context->cipher;
    context->errCode = cipher->update(cipher, &context->input, &context->output);
    if (context->errCode != HCF_SUCCESS) {
        LOGE("Update ret:%{public}d!", context->errCode);
        context->errMsg = "cipher update failed.";
        HcfGetCryptoOperationErrMsg(context->errCode, &context->errMsg, &context->cryptoErrMsg);
    }
}

static void AsyncDoFinalProcess(napi_env env, void *data)
{
    CipherFwkCtx context = static_cast<CipherFwkCtx>(data);
    HcfCipher *cipher = context->cipher;

    context->errCode = cipher->doFinal(cipher, &context->input, &context->output);
    if (context->errCode != HCF_SUCCESS) {
        LOGE("doFinal ret:%{public}d!", context->errCode);
        context->errMsg = "cipher doFinal failed.";
        HcfGetCryptoOperationErrMsg(context->errCode, &context->errMsg, &context->cryptoErrMsg);
    }
}

static void AsyncInitReturn(napi_env env, napi_status status, void *data)
{
    CipherFwkCtx context = static_cast<CipherFwkCtx>(data);
    napi_value result = NapiGetNull(env);

    if (context->asyncType == ASYNC_CALLBACK) {
        ReturnCallbackResult(env, context, result);
    } else {
        ReturnPromiseResult(env, context, result);
    }
    FreeCipherFwkCtx(env, context);
}

static HcfResult CreateNapiUint8ArrayNoCopy(napi_env env, HcfBlob *blob, napi_value *napiValue)
{
    if (blob->data == nullptr || blob->len == 0) { // inner api, allow empty data
        *napiValue = NapiGetNull(env);
        return HCF_SUCCESS;
    }

    napi_value outBuffer = nullptr;
    napi_status status = napi_create_external_arraybuffer(
        env, blob->data, blob->len, [](napi_env env, void *data, void *hint) { HcfFree(data); }, nullptr, &outBuffer);
    if (status != napi_ok) {
        LOGE("create napi uint8 array buffer failed!");
        return HCF_ERR_NAPI;
    }

    napi_value outData = nullptr;
    napi_create_typedarray(env, napi_uint8_array, blob->len, outBuffer, 0, &outData);
    napi_value dataBlob = nullptr;
    napi_create_object(env, &dataBlob);
    napi_set_named_property(env, dataBlob, CRYPTO_TAG_DATA.c_str(), outData);
    *napiValue = dataBlob;

    blob->data = nullptr;
    blob->len = 0;
    return HCF_SUCCESS;
}

static void AsyncUpdateReturn(napi_env env, napi_status status, void *data)
{
    CipherFwkCtx context = static_cast<CipherFwkCtx>(data);
    napi_value instance = nullptr;
    if (CreateNapiUint8ArrayNoCopy(env, &context->output, &instance) != HCF_SUCCESS) {
        instance = NapiGetNull(env);
    }

    if (context->asyncType == ASYNC_CALLBACK) {
        ReturnCallbackResult(env, context, instance);
    } else {
        ReturnPromiseResult(env, context, instance);
    }
    FreeCipherFwkCtx(env, context);
}

static void AsyncDoFinalReturn(napi_env env, napi_status status, void *data)
{
    CipherFwkCtx context = static_cast<CipherFwkCtx>(data);
    napi_value instance = nullptr;
    if (CreateNapiUint8ArrayNoCopy(env, &context->output, &instance) != HCF_SUCCESS) {
        LOGE("Maybe in decrypt mode, or CCM crypto maybe occur!");
        instance = NapiGetNull(env);
    }

    if (context->asyncType == ASYNC_CALLBACK) {
        ReturnCallbackResult(env, context, instance);
    } else {
        ReturnPromiseResult(env, context, instance);
    }
    FreeCipherFwkCtx(env, context);
}

static napi_value NewAsyncInit(napi_env env, CipherFwkCtx context)
{
    napi_value resourceName = nullptr;
    napi_create_string_utf8(env, "init", NAPI_AUTO_LENGTH, &resourceName);

    napi_create_async_work(
        env, nullptr, resourceName,
        [](napi_env env, void *data) {
            AsyncInitProcess(env, data);
            return;
        },
        [](napi_env env, napi_status status, void *data) {
            AsyncInitReturn(env, status, data);
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

static napi_value NewAsyncUpdate(napi_env env, CipherFwkCtx context)
{
    napi_value resourceName = nullptr;
    napi_create_string_utf8(env, "update", NAPI_AUTO_LENGTH, &resourceName);

    napi_create_async_work(
        env, nullptr, resourceName,
        [](napi_env env, void *data) {
            AsyncUpdateProcess(env, data);
            return;
        },
        [](napi_env env, napi_status status, void *data) {
            AsyncUpdateReturn(env, status, data);
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

static napi_value NewAsyncDoFinal(napi_env env, CipherFwkCtx context)
{
    napi_value resourceName = nullptr;
    napi_create_string_utf8(env, "doFinal", NAPI_AUTO_LENGTH, &resourceName);

    napi_create_async_work(
        env, nullptr, resourceName,
        [](napi_env env, void *data) {
            AsyncDoFinalProcess(env, data);
            return;
        },
        [](napi_env env, napi_status status, void *data) {
            AsyncDoFinalReturn(env, status, data);
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

NapiCipher::NapiCipher(HcfCipher *cipher)
{
    this->cipher_ = cipher;
}

NapiCipher::~NapiCipher()
{
    HcfObjDestroy(this->cipher_);
    this->cipher_ = nullptr;
}

HcfCipher *NapiCipher::GetCipher() const
{
    return this->cipher_;
}

napi_value NapiCipher::JsCipherInit(napi_env env, napi_callback_info info)
{
    CipherFwkCtx context = static_cast<CipherFwkCtx>(HcfMalloc(sizeof(CipherFwkCtxT), 0));
    if (context == nullptr) {
        NAPI_LOG_THROW(env, HCF_ERR_MALLOC, "create context fail!");
        return nullptr;
    }

    if (!BuildContextForInit(env, info, context)) {
        NAPI_LOG_THROW(env, HCF_INVALID_PARAMS, "build context for init fail!");
        FreeCipherFwkCtx(env, context);
        return nullptr;
    }

    return NewAsyncInit(env, context);
}

static napi_value SyncInit(napi_env env, napi_value thisVar, napi_value argv[])
{
    NapiCipher *napiCipher = nullptr;
    napi_status status = napi_unwrap(env, thisVar, reinterpret_cast<void **>(&napiCipher));
    if (status != napi_ok || napiCipher == nullptr) {
        NAPI_LOG_THROW(env, HCF_ERR_NAPI, "unwrap napi napiCipher failed!");
        return nullptr;
    }
    HcfCipher *cipher = napiCipher->GetCipher();
    // get opMode, type is uint32
    size_t index = 0;
    enum HcfCryptoMode opMode = ENCRYPT_MODE;
    if (napi_get_value_uint32(env, argv[index++], reinterpret_cast<uint32_t *>(&opMode)) != napi_ok) {
        NAPI_LOG_THROW(env, HCF_INVALID_PARAMS, "get napi option mode failed!");
        return nullptr;
    }
    // get key, unwrap from JS
    NapiKey *napiKey = nullptr;
    status = napi_unwrap(env, argv[index++], reinterpret_cast<void **>(&napiKey));
    if (status != napi_ok || napiKey == nullptr) {
        NAPI_LOG_THROW(env, HCF_INVALID_PARAMS, "get napi key failed!");
        return nullptr;
    }
    HcfKey *key = napiKey->GetHcfKey();
    // get paramsSpec, unwrap from JS
    HcfParamsSpec *paramsSpec = nullptr;
    napi_valuetype valueType;
    napi_typeof(env, argv[index], &valueType);
    if (valueType != napi_null) {
        if (!GetParamsSpecFromNapiValue(env, argv[index], opMode, &paramsSpec)) {
            NAPI_LOG_THROW(env, HCF_INVALID_PARAMS, "get napi paramsSpec failed!");
            return nullptr;
        }
    }
    HcfResult res = cipher->init(cipher, opMode, key, paramsSpec);
    FreeParamsSpec(paramsSpec);
    paramsSpec = nullptr;
    if (res != HCF_SUCCESS) {
        NAPI_LOG_THROW_EX(env, res, "failed to cipher init.");
        return nullptr;
    }
    return NapiGetNull(env);
}

napi_value NapiCipher::JsCipherInitSync(napi_env env, napi_callback_info info)
{
    napi_value thisVar = nullptr;
    size_t argc = ARGS_SIZE_THREE;
    napi_value argv[ARGS_SIZE_THREE] = { nullptr };
    napi_get_cb_info(env, info, &argc, argv, &thisVar, nullptr);
    if (argc != ARGS_SIZE_THREE) {
        NAPI_LOG_THROW(env, HCF_INVALID_PARAMS, "invalid params count");
        return nullptr;
    }
    return SyncInit(env, thisVar, argv);
}

napi_value NapiCipher::JsCipherUpdate(napi_env env, napi_callback_info info)
{
    CipherFwkCtx context = static_cast<CipherFwkCtx>(HcfMalloc(sizeof(CipherFwkCtxT), 0));
    if (context == nullptr) {
        NAPI_LOG_THROW(env, HCF_ERR_MALLOC, "create context fail!");
        return nullptr;
    }

    if (!BuildContextForUpdate(env, info, context)) {
        NAPI_LOG_THROW(env, HCF_INVALID_PARAMS, "build context for update fail!");
        FreeCipherFwkCtx(env, context);
        return nullptr;
    }

    return NewAsyncUpdate(env, context);
}

napi_value NapiCipher::JsCipherUpdateSync(napi_env env, napi_callback_info info)
{
    napi_value thisVar = nullptr;
    NapiCipher *napiCipher = nullptr;
    size_t argc = ARGS_SIZE_ONE;
    napi_value argv[ARGS_SIZE_ONE] = { nullptr };
    napi_get_cb_info(env, info, &argc, argv, &thisVar, nullptr);
    if (argc != ARGS_SIZE_ONE) {
        NAPI_LOG_THROW(env, HCF_INVALID_PARAMS, "invalid params count");
        return nullptr;
    }
    HcfCipher *cipher = nullptr;
    napi_status status = napi_unwrap(env, thisVar, reinterpret_cast<void **>(&napiCipher));
    if (status != napi_ok || napiCipher == nullptr) {
        NAPI_LOG_THROW(env, HCF_ERR_NAPI, "unwrap napi cipher failed!");
        return nullptr;
    }
    cipher = napiCipher->GetCipher();
    // get input, type is blob
    HcfBlob input = { 0 };
    HcfResult errCode = GetNapiUint8ArrayDataNoCopy(env, argv[PARAM0], &input);
    if (errCode != HCF_SUCCESS) {
        NAPI_LOG_THROW(env, errCode, "get input blob failed!");
        return nullptr;
    }
    HcfBlob output = { .data = nullptr, .len = 0 };
    errCode = cipher->update(cipher, &input, &output);
    if (errCode != HCF_SUCCESS) {
        NAPI_LOG_THROW_EX(env, errCode, "failed to cipher update!");
        return nullptr;
    }

    napi_value instance = nullptr;
    errCode = CreateNapiUint8ArrayNoCopy(env, &output, &instance);
    if (errCode != HCF_SUCCESS) {
        HcfBlobDataClearAndFree(&output);
        NAPI_LOG_THROW(env, errCode, "cipher update convert dataBlob to napi_value failed!");
        return nullptr;
    }
    return instance;
}

napi_value NapiCipher::JsCipherDoFinal(napi_env env, napi_callback_info info)
{
    CipherFwkCtx context = static_cast<CipherFwkCtx>(HcfMalloc(sizeof(CipherFwkCtxT), 0));
    if (context == nullptr) {
        NAPI_LOG_THROW(env, HCF_ERR_MALLOC, "create context fail!");
        return nullptr;
    }

    if (!BuildContextForFinal(env, info, context)) {
        NAPI_LOG_THROW(env, HCF_INVALID_PARAMS, "build context for final fail!");
        FreeCipherFwkCtx(env, context);
        return nullptr;
    }

    return NewAsyncDoFinal(env, context);
}

napi_value NapiCipher::JsCipherDoFinalSync(napi_env env, napi_callback_info info)
{
    napi_value thisVar = nullptr;
    NapiCipher *napiCipher = nullptr;
    size_t argc = ARGS_SIZE_ONE;
    napi_value argv[ARGS_SIZE_ONE] = { nullptr };
    napi_get_cb_info(env, info, &argc, argv, &thisVar, nullptr);
    if (argc != ARGS_SIZE_ONE) {
        NAPI_LOG_THROW(env, HCF_INVALID_PARAMS, "invalid params count");
        return nullptr;
    }
    HcfCipher *cipher = nullptr;
    napi_status status = napi_unwrap(env, thisVar, reinterpret_cast<void **>(&napiCipher));
    if (status != napi_ok || napiCipher == nullptr) {
        NAPI_LOG_THROW(env, HCF_ERR_NAPI, "unwrap napi cipher failed");
        return nullptr;
    }
    cipher = napiCipher->GetCipher();
    // get input, type is blob
    napi_valuetype valueType;
    HcfBlob *input = nullptr;
    HcfBlob blob = { 0 };
    napi_typeof(env, argv[PARAM0], &valueType);
    if (valueType != napi_null) {
        HcfResult ret = GetNapiUint8ArrayDataNoCopy(env, argv[PARAM0], &blob);
        if (ret != HCF_SUCCESS) {
            NAPI_LOG_THROW(env, ret, "get input blob failed!");
            return nullptr;
        }
        input = &blob;
    }
    HcfBlob output = { .data = nullptr, .len = 0 };
    HcfResult res = cipher->doFinal(cipher, input, &output);
    if (res != HCF_SUCCESS) {
        NAPI_LOG_THROW_EX(env, res, "failed to do cipher final!");
        return nullptr;
    }

    napi_value instance = nullptr;
    res = CreateNapiUint8ArrayNoCopy(env, &output, &instance);
    if (res != HCF_SUCCESS) {
        HcfBlobDataClearAndFree(&output);
        NAPI_LOG_THROW(env, res, "cipher convert dataBlob to napi_value failed!");
        return nullptr;
    }
    return instance;
}

napi_value NapiCipher::JsGetAlgorithm(napi_env env, napi_callback_info info)
{
    napi_value thisVar = nullptr;
    NapiCipher *napiCipher = nullptr;

    napi_get_cb_info(env, info, nullptr, nullptr, &thisVar, nullptr);

    napi_status status = napi_unwrap(env, thisVar, reinterpret_cast<void **>(&napiCipher));
    if (status != napi_ok || napiCipher == nullptr) {
        LOGE("failed to unwrap napiCipher obj!");
        return nullptr;
    }

    HcfCipher *cipher = napiCipher->GetCipher();
    if (cipher == nullptr) {
        LOGE("failed to get cipher obj!");
        return nullptr;
    }

    // execute C function
    const char *algo = cipher->getAlgorithm(cipher);
    napi_value instance = nullptr;
    napi_create_string_utf8(env, algo, NAPI_AUTO_LENGTH, &instance);
    return instance;
}

napi_value NapiCipher::CipherConstructor(napi_env env, napi_callback_info info)
{
    napi_value thisVar = nullptr;
    napi_get_cb_info(env, info, nullptr, nullptr, &thisVar, nullptr);

    return thisVar;
}

napi_value NapiCipher::CreateCipher(napi_env env, napi_callback_info info)
{
    size_t argc = ARGS_SIZE_ONE;
    napi_value argv[ARGS_SIZE_ONE] = { nullptr };
    napi_get_cb_info(env, info, &argc, argv, nullptr, nullptr);

    if (argc != ARGS_SIZE_ONE) {
        NAPI_LOG_THROW(env, HCF_INVALID_PARAMS, "The input args num is invalid.");
        return nullptr;
    }

    // create instance according to input js object
    napi_value instance = nullptr;
    napi_value constructor = nullptr;
    napi_get_reference_value(env, classRef_, &constructor);
    napi_new_instance(env, constructor, argc, argv, &instance);

    // parse input string
    std::string algoName;
    if (!GetStringFromJSParams(env, argv[0], algoName)) {
        NAPI_LOG_THROW(env, HCF_INVALID_PARAMS, "failed to get algoName.");
        return nullptr;
    }

    // execute C function, generate C object
    HcfCipher *cipher = nullptr;
    HcfResult res = HcfCipherCreate(algoName.c_str(), &cipher);
    if (res != HCF_SUCCESS) {
        NAPI_LOG_THROW(env, res, "create C cipher fail!");
        return nullptr;
    }
    NapiCipher *napiCipher = new (std::nothrow) NapiCipher(cipher);
    if (napiCipher == nullptr) {
        NAPI_LOG_THROW(env, HCF_ERR_MALLOC, "new napiCipher failed!");
        HcfObjDestroy(cipher);
        cipher = nullptr;
        return nullptr;
    }

    napi_status status = napi_wrap(env, instance, napiCipher,
        [](napi_env env, void *data, void *hint) {
            delete(static_cast<NapiCipher *>(data));
        }, nullptr, nullptr);
    if (status != napi_ok) {
        NAPI_LOG_THROW(env, HCF_INVALID_PARAMS, "failed to wrap napiCipher obj.");
        delete napiCipher;
        return nullptr;
    }
    return instance;
}

napi_value NapiCipher::JsSetCipherSpec(napi_env env, napi_callback_info info)
{
    napi_value thisVar = nullptr;
    NapiCipher *napiCipher = nullptr;
    size_t expectedArgc = ARGS_SIZE_TWO;
    size_t argc = ARGS_SIZE_TWO;
    napi_value argv[ARGS_SIZE_TWO] = { nullptr };
    napi_get_cb_info(env, info, &argc, argv, &thisVar, nullptr);
    if (argc != expectedArgc) {
        NAPI_LOG_THROW(env, HCF_INVALID_PARAMS, "init failed for wrong argument num.");
        return nullptr;
    }
    CipherSpecItem item;
    if (napi_get_value_uint32(env, argv[0], reinterpret_cast<uint32_t *>(&item)) != napi_ok) {
        NAPI_LOG_THROW(env, HCF_INVALID_PARAMS, "get JsGetCipherSpecUint8Array failed!");
        return nullptr;
    }
    HcfBlob *pSource = GetBlobFromNapiUint8Arr(env, argv[1]);
    if (pSource == nullptr || pSource->len == 0) {
        HcfBlobDataFree(pSource);
        HCF_FREE_PTR(pSource);
        NAPI_LOG_THROW(env, HCF_INVALID_PARAMS, "[pSource]: must be of the DataBlob type.");
        return nullptr;
    }
    napi_status status = napi_unwrap(env, thisVar, reinterpret_cast<void **>(&napiCipher));
    if (status != napi_ok || napiCipher == nullptr) {
        HcfBlobDataFree(pSource);
        HCF_FREE_PTR(pSource);
        NAPI_LOG_THROW(env, HCF_INVALID_PARAMS, "failed to unwrap napiCipher obj!");
        return nullptr;
    }
    HcfCipher *cipher = napiCipher->GetCipher();
    HcfResult res = cipher->setCipherSpecUint8Array(cipher, item, *pSource);
    if (res != HCF_SUCCESS) {
        HcfBlobDataFree(pSource);
        HCF_FREE_PTR(pSource);
        NAPI_LOG_THROW(env, res, "c set cipher spec failed.");
        return nullptr;
    }
    HcfBlobDataFree(pSource);
    HCF_FREE_PTR(pSource);
    return thisVar;
}

static napi_value GetCipherSpecString(napi_env env, CipherSpecItem item, HcfCipher *cipher)
{
    char *returnString = nullptr;
    HcfResult res = cipher->getCipherSpecString(cipher, item, &returnString);
    if (res != HCF_SUCCESS) {
        NAPI_LOG_THROW(env, res, "c getCipherSpecString failed.");
        return nullptr;
    }

    napi_value instance = nullptr;
    napi_create_string_utf8(env, returnString, NAPI_AUTO_LENGTH, &instance);
    HcfFree(returnString);
    returnString = nullptr;
    return instance;
}

static napi_value GetCipherSpecUint8Array(napi_env env, CipherSpecItem item, HcfCipher *cipher)
{
    HcfBlob blob = { .data = nullptr, .len = 0 };
    HcfResult res = cipher->getCipherSpecUint8Array(cipher, item, &blob);
    if (res != HCF_SUCCESS) {
        NAPI_LOG_THROW(env, res, "c getCipherSpecUint8Array fail.");
        return nullptr;
    }

    napi_value instance = ConvertObjectBlobToNapiValue(env, &blob);
    HcfBlobDataClearAndFree(&blob);
    return instance;
}

napi_value NapiCipher::JsGetCipherSpec(napi_env env, napi_callback_info info)
{
    napi_value thisVar = nullptr;
    NapiCipher *napiCipher = nullptr;
    size_t expectedArgc = ARGS_SIZE_ONE;
    size_t argc = ARGS_SIZE_ONE;
    napi_value argv[ARGS_SIZE_ONE] = { nullptr };
    napi_get_cb_info(env, info, &argc, argv, &thisVar, nullptr);
    if (argc != expectedArgc) {
        NAPI_LOG_THROW(env, HCF_INVALID_PARAMS, "init failed for wrong argument num.");
        return nullptr;
    }
    CipherSpecItem item;
    if (napi_get_value_uint32(env, argv[0], reinterpret_cast<uint32_t *>(&item)) != napi_ok) {
        NAPI_LOG_THROW(env, HCF_INVALID_PARAMS, "get getCipherSpecString failed!");
        return nullptr;
    }

    napi_status status = napi_unwrap(env, thisVar, reinterpret_cast<void **>(&napiCipher));
    if (status != napi_ok || napiCipher == nullptr) {
        NAPI_LOG_THROW(env, HCF_INVALID_PARAMS, "failed to unwrap napiCipher obj!");
        return nullptr;
    }
    HcfCipher *cipher = napiCipher->GetCipher();
    if (cipher == nullptr) {
        NAPI_LOG_THROW(env, HCF_INVALID_PARAMS, "failed to get cipher obj!");
        return nullptr;
    }

    int32_t type = GetCipherSpecType(item);
    if (type == SPEC_ITEM_TYPE_STR) {
        return GetCipherSpecString(env, item, cipher);
    } else if (type == SPEC_ITEM_TYPE_UINT8ARR) {
        return GetCipherSpecUint8Array(env, item, cipher);
    } else {
        NAPI_LOG_THROW(env, HCF_INVALID_PARAMS, "CipherSpecItem not support!");
        return nullptr;
    }
}

void NapiCipher::DefineCipherJSClass(napi_env env, napi_value exports)
{
    napi_property_descriptor desc[] = {
        DECLARE_NAPI_FUNCTION("createCipher", CreateCipher),
    };
    napi_define_properties(env, exports, sizeof(desc) / sizeof(desc[0]), desc);

    napi_property_descriptor classDesc[] = {
        DECLARE_NAPI_FUNCTION("init", NapiCipher::JsCipherInit),
        DECLARE_NAPI_FUNCTION("update", NapiCipher::JsCipherUpdate),
        DECLARE_NAPI_FUNCTION("doFinal", NapiCipher::JsCipherDoFinal),
        DECLARE_NAPI_FUNCTION("initSync", NapiCipher::JsCipherInitSync),
        DECLARE_NAPI_FUNCTION("updateSync", NapiCipher::JsCipherUpdateSync),
        DECLARE_NAPI_FUNCTION("doFinalSync", NapiCipher::JsCipherDoFinalSync),
        DECLARE_NAPI_FUNCTION("setCipherSpec", NapiCipher::JsSetCipherSpec),
        DECLARE_NAPI_FUNCTION("getCipherSpec", NapiCipher::JsGetCipherSpec),
        { .utf8name = "algName", .getter = NapiCipher::JsGetAlgorithm },
    };
    napi_value constructor = nullptr;
    napi_define_class(env, "Cipher", NAPI_AUTO_LENGTH, NapiCipher::CipherConstructor, nullptr,
        sizeof(classDesc) / sizeof(classDesc[0]), classDesc, &constructor);
    napi_create_reference(env, constructor, 1, &classRef_);
}
} // CryptoFramework
} // OHOS
