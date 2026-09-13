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

#include "napi_verify.h"

#include "securec.h"
#include "log.h"
#include "memory.h"
#include "utils.h"

#include "napi_crypto_framework_defines.h"
#include "napi_pri_key.h"
#include "napi_pub_key.h"
#include "napi_utils.h"

namespace OHOS {
namespace CryptoFramework {
struct VerifyInitCtx {
    napi_env env = nullptr;

    AsyncType asyncType = ASYNC_CALLBACK;
    napi_ref callback = nullptr;
    napi_deferred deferred = nullptr;
    napi_value promise = nullptr;
    napi_async_work asyncWork = nullptr;
    napi_ref verifyRef = nullptr;
    napi_ref pubKeyRef = nullptr;

    HcfVerify *verify = nullptr;
    HcfParamsSpec *params = nullptr;
    HcfPubKey *pubKey = nullptr;

    HcfResult errCode = HCF_SUCCESS;
    const char *errMsg = nullptr;
    char *cryptoErrMsg = nullptr;
};

struct VerifyUpdateCtx {
    napi_env env = nullptr;

    AsyncType asyncType = ASYNC_CALLBACK;
    napi_ref callback = nullptr;
    napi_deferred deferred = nullptr;
    napi_value promise = nullptr;
    napi_async_work asyncWork = nullptr;
    napi_ref verifyRef = nullptr;

    HcfVerify *verify = nullptr;
    HcfBlob *data = nullptr;

    HcfResult errCode = HCF_SUCCESS;
    const char *errMsg = nullptr;
    char *cryptoErrMsg = nullptr;
};

struct VerifyDoFinalCtx {
    napi_env env = nullptr;

    AsyncType asyncType = ASYNC_CALLBACK;
    napi_ref callback = nullptr;
    napi_deferred deferred = nullptr;
    napi_value promise = nullptr;
    napi_async_work asyncWork = nullptr;
    napi_ref verifyRef = nullptr;

    HcfVerify *verify = nullptr;
    HcfBlob *data = nullptr;
    HcfBlob *signatureData = nullptr;

    HcfResult errCode = HCF_SUCCESS;
    const char *errMsg = nullptr;
    char *cryptoErrMsg = nullptr;
    bool isVerifySucc;
};

struct VerifyRecoverCtx {
    napi_env env = nullptr;

    napi_deferred deferred = nullptr;
    napi_value promise = nullptr;
    napi_async_work asyncWork = nullptr;
    napi_ref verifyRef = nullptr;

    HcfVerify *verify = nullptr;
    HcfBlob *signatureData = nullptr;

    HcfResult errCode = HCF_SUCCESS;
    const char *errMsg = nullptr;
    char *cryptoErrMsg = nullptr;
    HcfBlob rawSignatureData;
};

thread_local napi_ref NapiVerify::classRef_ = nullptr;

static bool IsMlDsaVerify(HcfVerify *verify, SignSpecItem item)
{
    if (item == ML_DSA_DETERMINISTIC_BOOL || item == ML_DSA_MU_BOOL || item == ML_DSA_CONTEXT_UINT8ARR) {
        return true;
    }
    if (verify == nullptr) {
        return false;
    }
    const char *algo = verify->getAlgoName(verify);
    return (algo != nullptr && strcmp(algo, "ML-DSA") == 0);
}

static void FreeVerifyInitCtx(napi_env env, VerifyInitCtx *ctx)
{
    if (ctx == nullptr) {
        return;
    }

    if (ctx->asyncWork != nullptr) {
        napi_delete_async_work(env, ctx->asyncWork);
        ctx->asyncWork = nullptr;
    }

    if (ctx->callback != nullptr) {
        napi_delete_reference(env, ctx->callback);
        ctx->callback = nullptr;
    }

    if (ctx->verifyRef != nullptr) {
        napi_delete_reference(env, ctx->verifyRef);
        ctx->verifyRef = nullptr;
    }

    if (ctx->pubKeyRef != nullptr) {
        napi_delete_reference(env, ctx->pubKeyRef);
        ctx->pubKeyRef = nullptr;
    }

    HcfFree(ctx->cryptoErrMsg);
    HcfFree(ctx);
}

static void FreeVerifyUpdateCtx(napi_env env, VerifyUpdateCtx *ctx)
{
    if (ctx == nullptr) {
        return;
    }

    if (ctx->asyncWork != nullptr) {
        napi_delete_async_work(env, ctx->asyncWork);
        ctx->asyncWork = nullptr;
    }

    if (ctx->callback != nullptr) {
        napi_delete_reference(env, ctx->callback);
        ctx->callback = nullptr;
    }

    if (ctx->verifyRef != nullptr) {
        napi_delete_reference(env, ctx->verifyRef);
        ctx->verifyRef = nullptr;
    }

    HcfBlobDataClearAndFree(ctx->data);
    HcfFree(ctx->data);
    ctx->data = nullptr;
    HcfFree(ctx->cryptoErrMsg);
    HcfFree(ctx);
}

static void FreeVerifyDoFinalCtx(napi_env env, VerifyDoFinalCtx *ctx)
{
    if (ctx == nullptr) {
        return;
    }

    if (ctx->asyncWork != nullptr) {
        napi_delete_async_work(env, ctx->asyncWork);
        ctx->asyncWork = nullptr;
    }

    if (ctx->callback != nullptr) {
        napi_delete_reference(env, ctx->callback);
        ctx->callback = nullptr;
    }

    if (ctx->verifyRef != nullptr) {
        napi_delete_reference(env, ctx->verifyRef);
        ctx->verifyRef = nullptr;
    }

    HcfBlobDataFree(ctx->data);
    HcfFree(ctx->data);
    ctx->data = nullptr;
    HcfBlobDataFree(ctx->signatureData);
    HcfFree(ctx->signatureData);
    ctx->signatureData = nullptr;
    HcfFree(ctx->cryptoErrMsg);
    HcfFree(ctx);
}

static void FreeVerifyRecoverCtx(napi_env env, VerifyRecoverCtx *ctx)
{
    if (ctx == nullptr) {
        return;
    }

    if (ctx->asyncWork != nullptr) {
        napi_delete_async_work(env, ctx->asyncWork);
        ctx->asyncWork = nullptr;
    }

    if (ctx->verifyRef != nullptr) {
        napi_delete_reference(env, ctx->verifyRef);
        ctx->verifyRef = nullptr;
    }

    if (ctx->rawSignatureData.data != nullptr) {
        (void)memset_s(ctx->rawSignatureData.data, ctx->rawSignatureData.len, 0, ctx->rawSignatureData.len);
        HcfFree(ctx->rawSignatureData.data);
        ctx->rawSignatureData.data = nullptr;
        ctx->rawSignatureData.len = 0;
    }

    HcfBlobDataFree(ctx->signatureData);
    HcfFree(ctx->signatureData);
    ctx->signatureData = nullptr;
    HcfFree(ctx->cryptoErrMsg);
    HcfFree(ctx);
}

static bool BuildVerifyJsInitCtx(napi_env env, napi_callback_info info, VerifyInitCtx *ctx)
{
    napi_value thisVar = nullptr;
    size_t expectedArgc = PARAMS_NUM_TWO;
    size_t argc = expectedArgc;
    napi_value argv[PARAMS_NUM_TWO] = { nullptr };
    napi_get_cb_info(env, info, &argc, argv, &thisVar, nullptr);
    if ((argc != expectedArgc) && (argc != expectedArgc - 1)) {
        LOGE("wrong argument num. require %{public}zu or %{public}zu arguments. [Argc]: %{public}zu!",
            expectedArgc - 1, expectedArgc, argc);
        return false;
    }
    ctx->asyncType = isCallback(env, argv[expectedArgc - 1], argc, expectedArgc) ? ASYNC_CALLBACK : ASYNC_PROMISE;

    NapiVerify *napiVerify = nullptr;
    napi_status status = napi_unwrap(env, thisVar, reinterpret_cast<void **>(&napiVerify));
    if (status != napi_ok || napiVerify == nullptr) {
        LOGE("failed to unwrap napi verify obj.");
        return false;
    }

    size_t index = 0;
    NapiPubKey *napiPubKey = nullptr;
    status = napi_unwrap(env, argv[index], reinterpret_cast<void **>(&napiPubKey));
    if (status != napi_ok || napiPubKey == nullptr) {
        LOGE("failed to unwrap napi pubKey obj.");
        return false;
    }

    ctx->verify = napiVerify->GetVerify();
    ctx->params = nullptr;
    ctx->pubKey = napiPubKey->GetPubKey();

    if (napi_create_reference(env, thisVar, 1, &ctx->verifyRef) != napi_ok) {
        LOGE("create verify ref failed when do verify init!");
        return false;
    }

    if (napi_create_reference(env, argv[PARAM0], 1, &ctx->pubKeyRef) != napi_ok) {
        LOGE("create verify ref failed when do verify init!");
        return false;
    }

    if (ctx->asyncType == ASYNC_PROMISE) {
        napi_create_promise(env, &ctx->deferred, &ctx->promise);
        return true;
    } else {
        return GetCallbackFromJSParams(env, argv[expectedArgc - 1], &ctx->callback);
    }
}

static bool BuildVerifyJsUpdateCtx(napi_env env, napi_callback_info info, VerifyUpdateCtx *ctx)
{
    napi_value thisVar = nullptr;
    size_t expectedArgc = PARAMS_NUM_TWO;
    size_t argc = expectedArgc;
    napi_value argv[PARAMS_NUM_TWO] = { nullptr };
    napi_get_cb_info(env, info, &argc, argv, &thisVar, nullptr);
    if ((argc != expectedArgc) && (argc != expectedArgc - 1)) {
        LOGE("wrong argument num. require %{public}zu or %{public}zu arguments. [Argc]: %{public}zu!",
            expectedArgc - 1, expectedArgc, argc);
        return false;
    }
    ctx->asyncType = isCallback(env, argv[expectedArgc - 1], argc, expectedArgc) ? ASYNC_CALLBACK : ASYNC_PROMISE;

    NapiVerify *napiVerify = nullptr;
    napi_status status = napi_unwrap(env, thisVar, reinterpret_cast<void **>(&napiVerify));
    if (status != napi_ok || napiVerify == nullptr) {
        LOGE("failed to unwrap napi verify obj.");
        return false;
    }

    size_t index = 0;
    HcfBlob *blob = GetBlobFromNapiDataBlob(env, argv[index]);
    if (blob == nullptr) {
        LOGE("failed to get blob data from napi.");
        return false;
    }

    ctx->verify = napiVerify->GetVerify();
    ctx->data = blob;

    if (napi_create_reference(env, thisVar, 1, &ctx->verifyRef) != napi_ok) {
        LOGE("create verify ref failed when do verify update!");
        return false;
    }

    if (ctx->asyncType == ASYNC_PROMISE) {
        napi_create_promise(env, &ctx->deferred, &ctx->promise);
        return true;
    } else {
        return GetCallbackFromJSParams(env, argv[expectedArgc - 1], &ctx->callback);
    }
}

static bool GetDataBlobAndSignatureFromInput(napi_env env, napi_value dataValue, napi_value signatureDataValue,
    HcfBlob **returnData, HcfBlob **returnSignatureData)
{
    napi_valuetype valueType;
    napi_typeof(env, dataValue, &valueType);
    HcfBlob *data = nullptr;
    if (valueType != napi_null) {
        data = GetBlobFromNapiDataBlob(env, dataValue);
        if (data == nullptr) {
            LOGE("failed to get data.");
            return false;
        }
    }

    HcfBlob *signatureData = GetBlobFromNapiDataBlob(env, signatureDataValue);
    if (signatureData == nullptr) {
        LOGE("failed to get signature.");
        HcfBlobDataFree(data);
        HcfFree(data);
        data = nullptr;
        return false;
    }

    *returnData = data;
    *returnSignatureData = signatureData;
    return true;
}

static HcfResult GetDataAndSignatureFromInput(napi_env env, napi_value dataValue, napi_value signatureDataValue,
    HcfBlob *returnData, HcfBlob *returnSignatureData)
{
    HcfResult ret = GetBlobFromNapiValue(env, signatureDataValue, returnSignatureData);
    if (ret != HCF_SUCCESS) {
        LOGE("failed to get signature.");
        return ret;
    }

    napi_valuetype valueType;
    napi_typeof(env, dataValue, &valueType);
    if (valueType == napi_null) {  // allow dataValue is empty
        returnData->data = nullptr;
        returnData->len = 0;
        return HCF_SUCCESS;
    }

    ret = GetBlobFromNapiValue(env, dataValue, returnData);
    if (ret != HCF_SUCCESS) {
        LOGE("failed to get data.");
        HcfBlobDataFree(returnSignatureData);
        returnSignatureData->data = nullptr;
        returnSignatureData->len = 0;
    }

    return ret;
}

static bool BuildVerifyJsDoFinalCtx(napi_env env, napi_callback_info info, VerifyDoFinalCtx *ctx)
{
    napi_value thisVar = nullptr;
    size_t expectedArgc = PARAMS_NUM_THREE;
    size_t argc = expectedArgc;
    napi_value argv[PARAMS_NUM_THREE] = { nullptr };
    napi_get_cb_info(env, info, &argc, argv, &thisVar, nullptr);
    if ((argc != expectedArgc) && (argc != expectedArgc - 1)) {
        LOGE("wrong argument num. require %{public}zu or %{public}zu arguments. [Argc]: %{public}zu!",
            expectedArgc - 1, expectedArgc, argc);
        return false;
    }
    ctx->asyncType = isCallback(env, argv[expectedArgc - 1], argc, expectedArgc) ? ASYNC_CALLBACK : ASYNC_PROMISE;

    NapiVerify *napiVerify = nullptr;
    napi_status status = napi_unwrap(env, thisVar, reinterpret_cast<void **>(&napiVerify));
    if (status != napi_ok || napiVerify == nullptr) {
        LOGE("failed to unwrap napi verify obj.");
        return false;
    }

    HcfBlob *data = nullptr;
    HcfBlob *signatureData = nullptr;
    if (!GetDataBlobAndSignatureFromInput(env, argv[PARAM0], argv[PARAM1], &data, &signatureData)) {
        return false;
    }

    ctx->verify = napiVerify->GetVerify();
    ctx->data = data;
    ctx->signatureData = signatureData;

    if (napi_create_reference(env, thisVar, 1, &ctx->verifyRef) != napi_ok) {
        LOGE("create verify ref failed when do verify final!");
        return false;
    }

    if (ctx->asyncType == ASYNC_PROMISE) {
        napi_create_promise(env, &ctx->deferred, &ctx->promise);
        return true;
    } else {
        return GetCallbackFromJSParams(env, argv[expectedArgc - 1], &ctx->callback);
    }
}

static void ReturnInitCallbackResult(napi_env env, VerifyInitCtx *ctx, napi_value result)
{
    napi_value businessError = nullptr;
    if (ctx->errCode != HCF_SUCCESS) {
        businessError = GenerateBusinessError(env, ctx->errCode, ctx->errMsg);
    }

    napi_value params[ARGS_SIZE_ONE] = { businessError };

    napi_value func = nullptr;
    napi_get_reference_value(env, ctx->callback, &func);

    napi_value recv = nullptr;
    napi_value callFuncRet = nullptr;
    napi_get_undefined(env, &recv);
    napi_call_function(env, recv, func, ARGS_SIZE_ONE, params, &callFuncRet);
}

static void ReturnInitPromiseResult(napi_env env, VerifyInitCtx *ctx, napi_value result)
{
    if (ctx->errCode == HCF_SUCCESS) {
        napi_resolve_deferred(env, ctx->deferred, result);
    } else {
        napi_reject_deferred(env, ctx->deferred,
            GenerateBusinessError(env, ctx->errCode, ctx->errMsg));
    }
}

static void ReturnUpdateCallbackResult(napi_env env, VerifyUpdateCtx *ctx, napi_value result)
{
    napi_value businessError = nullptr;
    if (ctx->errCode != HCF_SUCCESS) {
        businessError = GenerateBusinessError(env, ctx->errCode, ctx->errMsg);
    }

    napi_value params[ARGS_SIZE_ONE] = { businessError };

    napi_value func = nullptr;
    napi_get_reference_value(env, ctx->callback, &func);

    napi_value recv = nullptr;
    napi_value callFuncRet = nullptr;
    napi_get_undefined(env, &recv);
    napi_call_function(env, recv, func, ARGS_SIZE_ONE, params, &callFuncRet);
}

static void ReturnUpdatePromiseResult(napi_env env, VerifyUpdateCtx *ctx, napi_value result)
{
    if (ctx->errCode == HCF_SUCCESS) {
        napi_resolve_deferred(env, ctx->deferred, result);
    } else {
        napi_reject_deferred(env, ctx->deferred,
            GenerateBusinessError(env, ctx->errCode, ctx->errMsg));
    }
}

static void ReturnDoFinalCallbackResult(napi_env env, VerifyDoFinalCtx *ctx, napi_value result)
{
    napi_value businessError = nullptr;
    if (ctx->errCode != HCF_SUCCESS) {
        businessError = GenerateBusinessError(env, ctx->errCode, ctx->errMsg);
    }

    napi_value params[ARGS_SIZE_TWO] = { businessError, result };

    napi_value func = nullptr;
    napi_get_reference_value(env, ctx->callback, &func);

    napi_value recv = nullptr;
    napi_value callFuncRet = nullptr;
    napi_get_undefined(env, &recv);
    napi_call_function(env, recv, func, ARGS_SIZE_TWO, params, &callFuncRet);
}

static void ReturnDoFinalPromiseResult(napi_env env, VerifyDoFinalCtx *ctx, napi_value result)
{
    if (ctx->errCode == HCF_SUCCESS) {
        napi_resolve_deferred(env, ctx->deferred, result);
    } else {
        napi_reject_deferred(env, ctx->deferred,
            GenerateBusinessError(env, ctx->errCode, ctx->errMsg));
    }
}

static void ReturnRecoverPromiseResult(napi_env env, VerifyRecoverCtx *ctx, napi_value result)
{
    if (ctx->errCode == HCF_SUCCESS) {
        napi_resolve_deferred(env, ctx->deferred, result);
    } else {
        napi_reject_deferred(env, ctx->deferred, GenerateBusinessError(env, ctx->errCode, ctx->errMsg));
    }
}

static void VerifyJsInitAsyncWorkProcess(napi_env env, void *data)
{
    VerifyInitCtx *ctx = static_cast<VerifyInitCtx *>(data);

    ctx->errCode = ctx->verify->init(ctx->verify, ctx->params, ctx->pubKey);
    if (ctx->errCode != HCF_SUCCESS) {
        LOGE("verify init fail.");
        ctx->errMsg = "verify init fail.";
        HcfGetCryptoOperationErrMsg(ctx->errCode, &ctx->errMsg, &ctx->cryptoErrMsg);
    }
}

static void VerifyJsInitAsyncWorkReturn(napi_env env, napi_status status, void *data)
{
    VerifyInitCtx *ctx = static_cast<VerifyInitCtx *>(data);

    if (ctx->asyncType == ASYNC_CALLBACK) {
        ReturnInitCallbackResult(env, ctx, NapiGetNull(env));
    } else {
        ReturnInitPromiseResult(env, ctx, NapiGetNull(env));
    }
    FreeVerifyInitCtx(env, ctx);
}

static void VerifyJsUpdateAsyncWorkProcess(napi_env env, void *data)
{
    VerifyUpdateCtx *ctx = static_cast<VerifyUpdateCtx *>(data);

    ctx->errCode = ctx->verify->update(ctx->verify, ctx->data);
    if (ctx->errCode != HCF_SUCCESS) {
        LOGE("verify update fail.");
        ctx->errMsg = "verify update fail.";
        HcfGetCryptoOperationErrMsg(ctx->errCode, &ctx->errMsg, &ctx->cryptoErrMsg);
    }
}

static void VerifyJsUpdateAsyncWorkReturn(napi_env env, napi_status status, void *data)
{
    VerifyUpdateCtx *ctx = static_cast<VerifyUpdateCtx *>(data);

    if (ctx->asyncType == ASYNC_CALLBACK) {
        ReturnUpdateCallbackResult(env, ctx, NapiGetNull(env));
    } else {
        ReturnUpdatePromiseResult(env, ctx, NapiGetNull(env));
    }
    FreeVerifyUpdateCtx(env, ctx);
}

static void VerifyJsDoFinalAsyncWorkProcess(napi_env env, void *data)
{
    VerifyDoFinalCtx *ctx = static_cast<VerifyDoFinalCtx *>(data);

    ctx->isVerifySucc = ctx->verify->verify(ctx->verify, ctx->data, ctx->signatureData);
    ctx->errCode = HCF_SUCCESS;
    if (!ctx->isVerifySucc) {
        LOGE("verify doFinal fail.");
        return;
    }
}

static void VerifyJsDoFinalAsyncWorkReturn(napi_env env, napi_status status, void *data)
{
    VerifyDoFinalCtx *ctx = static_cast<VerifyDoFinalCtx *>(data);

    napi_value result = nullptr;
    if (ctx->errCode == HCF_SUCCESS) {
        napi_get_boolean(env, ctx->isVerifySucc, &result);
    }

    if (ctx->asyncType == ASYNC_CALLBACK) {
        ReturnDoFinalCallbackResult(env, ctx, result);
    } else {
        ReturnDoFinalPromiseResult(env, ctx, result);
    }
    FreeVerifyDoFinalCtx(env, ctx);
}

static void VerifyJsRecoverAsyncWorkProcess(napi_env env, void *data)
{
    VerifyRecoverCtx *ctx = static_cast<VerifyRecoverCtx *>(data);

    ctx->errCode = ctx->verify->recover(ctx->verify, ctx->signatureData, &ctx->rawSignatureData);
    if (ctx->errCode != HCF_SUCCESS) {
        LOGE("verify recover fail.");
        ctx->errMsg = "verify recover fail.";
        HcfGetCryptoOperationErrMsg(ctx->errCode, &ctx->errMsg, &ctx->cryptoErrMsg);
    }
}

static void VerifyJsRecoverAsyncWorkReturn(napi_env env, napi_status status, void *data)
{
    VerifyRecoverCtx *ctx = static_cast<VerifyRecoverCtx *>(data);

    napi_value dataBlob = nullptr;
    if (ctx->errCode == HCF_SUCCESS) {
        dataBlob = ConvertBlobToNapiValue(env, &ctx->rawSignatureData);
    }

    ReturnRecoverPromiseResult(env, ctx, dataBlob);

    FreeVerifyRecoverCtx(env, ctx);
}

static napi_value NewVerifyJsInitAsyncWork(napi_env env, VerifyInitCtx *ctx)
{
    napi_value resourceName = nullptr;
    napi_create_string_utf8(env, "init", NAPI_AUTO_LENGTH, &resourceName);

    napi_create_async_work(
        env, nullptr, resourceName,
        [](napi_env env, void *data) {
            VerifyJsInitAsyncWorkProcess(env, data);
            return;
        },
        [](napi_env env, napi_status status, void *data) {
            VerifyJsInitAsyncWorkReturn(env, status, data);
            return;
        },
        static_cast<void *>(ctx),
        &ctx->asyncWork);

    napi_queue_async_work(env, ctx->asyncWork);
    if (ctx->asyncType == ASYNC_PROMISE) {
        return ctx->promise;
    } else {
        return NapiGetNull(env);
    }
}

static napi_value NewVerifyJsUpdateAsyncWork(napi_env env, VerifyUpdateCtx *ctx)
{
    napi_value resourceName = nullptr;
    napi_create_string_utf8(env, "update", NAPI_AUTO_LENGTH, &resourceName);

    napi_create_async_work(
        env, nullptr, resourceName,
        [](napi_env env, void *data) {
            VerifyJsUpdateAsyncWorkProcess(env, data);
            return;
        },
        [](napi_env env, napi_status status, void *data) {
            VerifyJsUpdateAsyncWorkReturn(env, status, data);
            return;
        },
        static_cast<void *>(ctx),
        &ctx->asyncWork);

    napi_queue_async_work(env, ctx->asyncWork);
    if (ctx->asyncType == ASYNC_PROMISE) {
        return ctx->promise;
    } else {
        return NapiGetNull(env);
    }
}

static napi_value NewVerifyJsDoFinalAsyncWork(napi_env env, VerifyDoFinalCtx *ctx)
{
    napi_value resourceName = nullptr;
    napi_create_string_utf8(env, "verify", NAPI_AUTO_LENGTH, &resourceName);

    napi_create_async_work(
        env, nullptr, resourceName,
        [](napi_env env, void *data) {
            VerifyJsDoFinalAsyncWorkProcess(env, data);
            return;
        },
        [](napi_env env, napi_status status, void *data) {
            VerifyJsDoFinalAsyncWorkReturn(env, status, data);
            return;
        },
        static_cast<void *>(ctx),
        &ctx->asyncWork);

    napi_queue_async_work(env, ctx->asyncWork);
    if (ctx->asyncType == ASYNC_PROMISE) {
        return ctx->promise;
    } else {
        return NapiGetNull(env);
    }
}

static napi_value NewVerifyJsRecoverAsyncWork(napi_env env, VerifyRecoverCtx *ctx)
{
    napi_value resourceName = nullptr;
    napi_create_string_utf8(env, "verify", NAPI_AUTO_LENGTH, &resourceName);

    napi_create_async_work(
        env, nullptr, resourceName,
        [](napi_env env, void *data) {
            VerifyJsRecoverAsyncWorkProcess(env, data);
            return;
        },
        [](napi_env env, napi_status status, void *data) {
            VerifyJsRecoverAsyncWorkReturn(env, status, data);
            return;
        },
        static_cast<void *>(ctx),
        &ctx->asyncWork);

    napi_queue_async_work(env, ctx->asyncWork);
    return ctx->promise;
}

NapiVerify::NapiVerify(HcfVerify *verify)
{
    this->verify_ = verify;
}

NapiVerify::~NapiVerify()
{
    HcfObjDestroy(this->verify_);
    this->verify_ = nullptr;
}

HcfVerify *NapiVerify::GetVerify()
{
    return this->verify_;
}

napi_value NapiVerify::JsInit(napi_env env, napi_callback_info info)
{
    VerifyInitCtx *ctx = static_cast<VerifyInitCtx *>(HcfMalloc(sizeof(VerifyInitCtx), 0));
    if (ctx == nullptr) {
        NAPI_LOG_THROW(env, HCF_ERR_MALLOC, "create context fail.");
        return nullptr;
    }

    if (!BuildVerifyJsInitCtx(env, info, ctx)) {
        NAPI_LOG_THROW(env, HCF_INVALID_PARAMS, "build context fail.");
        FreeVerifyInitCtx(env, ctx);
        return nullptr;
    }

    return NewVerifyJsInitAsyncWork(env, ctx);
}

napi_value NapiVerify::JsInitSync(napi_env env, napi_callback_info info)
{
    napi_value thisVar = nullptr;
    size_t argc = PARAMS_NUM_ONE;
    napi_value argv[PARAMS_NUM_ONE] = { nullptr };
    napi_get_cb_info(env, info, &argc, argv, &thisVar, nullptr);
    if (argc != PARAMS_NUM_ONE) {
        NAPI_LOG_THROW(env, HCF_INVALID_PARAMS, "wrong argument num.");
        return nullptr;
    }

    NapiVerify *napiVerify = nullptr;
    napi_status status = napi_unwrap(env, thisVar, reinterpret_cast<void **>(&napiVerify));
    if (status != napi_ok || napiVerify == nullptr) {
        NAPI_LOG_THROW(env, HCF_ERR_NAPI, "failed to unwrap napi verify obj.");
        return nullptr;
    }

    NapiPubKey *napiPubKey = nullptr;
    status = napi_unwrap(env, argv[PARAM0], reinterpret_cast<void **>(&napiPubKey));
    if (status != napi_ok || napiPubKey == nullptr) {
        NAPI_LOG_THROW(env, HCF_ERR_NAPI, "failed to unwrap napi pubKey obj.");
        return nullptr;
    }

    HcfVerify *verify = napiVerify->GetVerify();
    HcfPubKey *pubKey = napiPubKey->GetPubKey();

    HcfResult ret = verify->init(verify, nullptr, pubKey);
    if (ret != HCF_SUCCESS) {
        NAPI_LOG_THROW_EX(env, ret, "verify init fail.");
        return nullptr;
    }
    napi_value instance = NapiGetNull(env);
    return instance;
}

napi_value NapiVerify::JsUpdate(napi_env env, napi_callback_info info)
{
    VerifyUpdateCtx *ctx = static_cast<VerifyUpdateCtx *>(HcfMalloc(sizeof(VerifyUpdateCtx), 0));
    if (ctx == nullptr) {
        NAPI_LOG_THROW(env, HCF_ERR_MALLOC, "create context fail.");
        return nullptr;
    }

    if (!BuildVerifyJsUpdateCtx(env, info, ctx)) {
        NAPI_LOG_THROW(env, HCF_INVALID_PARAMS, "build context fail.");
        FreeVerifyUpdateCtx(env, ctx);
        return nullptr;
    }

    return NewVerifyJsUpdateAsyncWork(env, ctx);
}

napi_value NapiVerify::JsUpdateSync(napi_env env, napi_callback_info info)
{
    napi_value thisVar = nullptr;
    size_t argc = PARAMS_NUM_ONE;
    napi_value argv[PARAMS_NUM_ONE] = { nullptr };
    napi_get_cb_info(env, info, &argc, argv, &thisVar, nullptr);
    if (argc != PARAMS_NUM_ONE) {
        NAPI_LOG_THROW(env, HCF_INVALID_PARAMS, "wrong argument num.");
        return nullptr;
    }

    NapiVerify *napiVerify = nullptr;
    napi_status status = napi_unwrap(env, thisVar, reinterpret_cast<void **>(&napiVerify));
    if (status != napi_ok || napiVerify == nullptr) {
        NAPI_LOG_THROW(env, HCF_ERR_NAPI, "failed to unwrap napi verify obj.");
        return nullptr;
    }

    HcfBlob blob = { 0 };
    HcfResult ret = GetBlobFromNapiValue(env, argv[PARAM0], &blob);
    if (ret != HCF_SUCCESS) {
        NAPI_LOG_THROW(env, ret, "failed to get input blob.");
        return nullptr;
    }

    HcfVerify *verify = napiVerify->GetVerify();
    if (verify == nullptr) {
        HcfBlobDataFree(&blob);
        NAPI_LOG_THROW(env, HCF_INVALID_PARAMS, "fail to get verify obj.");
        return nullptr;
    }
    ret = verify->update(verify, &blob);
    HcfBlobDataFree(&blob);
    if (ret != HCF_SUCCESS) {
        NAPI_LOG_THROW_EX(env, ret, "verify update fail.");
    }
    napi_value instance = NapiGetNull(env);
    return instance;
}

napi_value NapiVerify::JsVerify(napi_env env, napi_callback_info info)
{
    VerifyDoFinalCtx *ctx = static_cast<VerifyDoFinalCtx *>(HcfMalloc(sizeof(VerifyDoFinalCtx), 0));
    if (ctx == nullptr) {
        NAPI_LOG_THROW(env, HCF_ERR_MALLOC, "create context fail.");
        return nullptr;
    }

    if (!BuildVerifyJsDoFinalCtx(env, info, ctx)) {
        NAPI_LOG_THROW(env, HCF_INVALID_PARAMS, "build context fail.");
        FreeVerifyDoFinalCtx(env, ctx);
        return nullptr;
    }

    return NewVerifyJsDoFinalAsyncWork(env, ctx);
}

napi_value NapiVerify::JsVerifySync(napi_env env, napi_callback_info info)
{
    napi_value thisVar = nullptr;
    size_t argc = PARAMS_NUM_TWO;
    napi_value argv[PARAMS_NUM_TWO] = { nullptr };
    napi_get_cb_info(env, info, &argc, argv, &thisVar, nullptr);
    if (argc != PARAMS_NUM_TWO) {
        NAPI_LOG_THROW(env, HCF_INVALID_PARAMS, "wrong argument num.");
        return nullptr;
    }

    NapiVerify *napiVerify = nullptr;
    napi_status status = napi_unwrap(env, thisVar, reinterpret_cast<void **>(&napiVerify));
    if (status != napi_ok || napiVerify == nullptr) {
        NAPI_LOG_THROW(env, HCF_ERR_NAPI, "failed to unwrap napi verify obj.");
        return nullptr;
    }

    HcfBlob data = { 0 };
    HcfBlob signatureData = { 0 };
    HcfResult ret = GetDataAndSignatureFromInput(env, argv[PARAM0], argv[PARAM1], &data, &signatureData);
    if (ret != HCF_SUCCESS) {
        NAPI_LOG_THROW(env, ret, "failed to parse param1 or param2.");
        return nullptr;
    }

    HcfVerify *verify = napiVerify->GetVerify();
    bool isVerifySucc = verify->verify(verify, &data, &signatureData);
    HcfBlobDataFree(&data);
    HcfBlobDataFree(&signatureData);
    if (!isVerifySucc) {
        LOGD("verify doFinal fail.");
    }
    napi_value result = nullptr;
    napi_get_boolean(env, isVerifySucc, &result);
    return result;
}

HcfResult BuildVerifyJsRecoverCtx(napi_env env, napi_callback_info info, VerifyRecoverCtx *ctx)
{
    napi_value thisVar = nullptr;
    size_t expectedArgc = PARAMS_NUM_ONE;
    size_t argc = PARAMS_NUM_ONE;
    napi_value argv[PARAMS_NUM_ONE] = { nullptr };
    napi_get_cb_info(env, info, &argc, argv, &thisVar, nullptr);
    if (argc != expectedArgc) {
        LOGE("wrong argument num. require %{public}zu arguments. [Argc]: %{public}zu!", expectedArgc, argc);
        return HCF_INVALID_PARAMS;
    }

    NapiVerify *napiVerify = nullptr;
    napi_status status = napi_unwrap(env, thisVar, reinterpret_cast<void **>(&napiVerify));
    if (status != napi_ok || napiVerify == nullptr) {
        LOGE("failed to unwrap napi verify obj.");
        return HCF_ERR_NAPI;
    }

    ctx->verify = napiVerify->GetVerify();
    if (ctx->verify == nullptr) {
        LOGE("failed to get verify obj.");
        return HCF_INVALID_PARAMS;
    }

    ctx->signatureData = reinterpret_cast<HcfBlob *>(HcfMalloc(sizeof(HcfBlob), 0));
    if (ctx->signatureData == nullptr) {
        LOGE("failed to allocate newBlob memory!");
        return HCF_ERR_MALLOC;
    }

    HcfResult ret = GetBlobFromNapiValue(env, argv[PARAM0], ctx->signatureData);
    if (ret != HCF_SUCCESS) {
        return ret;
    }

    if (napi_create_reference(env, thisVar, 1, &ctx->verifyRef) != napi_ok) {
        LOGE("create verify ref failed when do verify recover!");
        return HCF_ERR_NAPI;
    }

    napi_create_promise(env, &ctx->deferred, &ctx->promise);
    return HCF_SUCCESS;
}

napi_value NapiVerify::JsRecover(napi_env env, napi_callback_info info)
{
    VerifyRecoverCtx *ctx = static_cast<VerifyRecoverCtx *>(HcfMalloc(sizeof(VerifyRecoverCtx), 0));
    if (ctx == nullptr) {
        NAPI_LOG_THROW(env, HCF_ERR_MALLOC, "create context fail.");
        return nullptr;
    }

    HcfResult ret = BuildVerifyJsRecoverCtx(env, info, ctx);
    if (ret != HCF_SUCCESS) {
        NAPI_LOG_THROW(env, ret, "build context fail.");
        FreeVerifyRecoverCtx(env, ctx);
        return nullptr;
    }

    return NewVerifyJsRecoverAsyncWork(env, ctx);
}

napi_value NapiVerify::JsRecoverSync(napi_env env, napi_callback_info info)
{
    napi_value thisVar = nullptr;
    size_t expectedArgc = PARAMS_NUM_ONE;
    size_t argc = PARAMS_NUM_ONE;
    napi_value argv[PARAMS_NUM_ONE] = { nullptr };
    napi_get_cb_info(env, info, &argc, argv, &thisVar, nullptr);
    if (argc != expectedArgc) {
        NAPI_LOG_THROW(env, HCF_INVALID_PARAMS, "wrong argument num.");
        return nullptr;
    }

    NapiVerify *napiVerify = nullptr;
    napi_status status = napi_unwrap(env, thisVar, reinterpret_cast<void **>(&napiVerify));
    if (status != napi_ok || napiVerify == nullptr) {
        NAPI_LOG_THROW(env, HCF_ERR_NAPI, "failed to unwrap napi verify obj.");
        return nullptr;
    }

    HcfVerify *verify = napiVerify->GetVerify();
    if (verify == nullptr) {
        NAPI_LOG_THROW(env, HCF_INVALID_PARAMS, "fail to get verify obj.");
        return nullptr;
    }

    HcfBlob signatureData = { 0 };
    HcfResult ret = GetBlobFromNapiValue(env, argv[PARAM0], &signatureData);
    if (ret != HCF_SUCCESS) {
        NAPI_LOG_THROW(env, ret, "failed to get signature data.");
        return nullptr;
    }

    HcfBlob rawSignatureData = { .data = nullptr, .len = 0};
    HcfResult res = verify->recover(verify, &signatureData, &rawSignatureData);
    HcfBlobDataFree(&signatureData);
    if (res != HCF_SUCCESS) {
        NAPI_LOG_THROW_EX(env, res, "failed to verify recover.");
        return nullptr;
    }

    napi_value instance = nullptr;
    res = ConvertDataBlobToNapiValue(env, &rawSignatureData, &instance);
    HcfBlobDataFree(&rawSignatureData);
    if (res != HCF_SUCCESS) {
        NAPI_LOG_THROW(env, res, "verify recover convert dataBlob to napi_value failed!");
        return nullptr;
    }

    return instance;
}

napi_value NapiVerify::VerifyConstructor(napi_env env, napi_callback_info info)
{
    napi_value thisVar = nullptr;
    napi_get_cb_info(env, info, nullptr, nullptr, &thisVar, nullptr);
    return thisVar;
}

static napi_value NapiWrapVerify(napi_env env, napi_value instance, NapiVerify *napiVerify)
{
    napi_status status = napi_wrap(
        env, instance, napiVerify,
        [](napi_env env, void *data, void *hint) {
            delete(static_cast<NapiVerify *>(data));
        }, nullptr, nullptr);
    if (status != napi_ok) {
        LOGE("failed to wrap napiVerify obj!");
        delete napiVerify;
        return nullptr;
    }
    return instance;
}

napi_value NapiVerify::CreateJsVerify(napi_env env, napi_callback_info info)
{
    size_t expectedArgc = PARAMS_NUM_ONE;
    size_t argc = expectedArgc;
    napi_value argv[PARAMS_NUM_ONE] = { nullptr };
    napi_get_cb_info(env, info, &argc, argv, nullptr, nullptr);

    if (argc != expectedArgc) {
        NAPI_LOG_THROW(env, HCF_INVALID_PARAMS, "The input args num is invalid.");
        return nullptr;
    }

    napi_value instance;
    napi_value constructor = nullptr;
    napi_get_reference_value(env, classRef_, &constructor);
    napi_new_instance(env, constructor, argc, argv, &instance);

    std::string algName;
    if (!GetStringFromJSParams(env, argv[0], algName)) {
        NAPI_LOG_THROW(env, HCF_INVALID_PARAMS, "failed to get algoName.");
        return nullptr;
    }

    HistogramScopeGuard guard(API_CREATE_VERIFY);
    if (!IsPqcSignVerifyAlgorithm(algName)) {
        guard.DisableScopeGuard();
    }

    HcfVerify *verify = nullptr;
    HcfResult ret = HcfVerifyCreate(algName.c_str(), &verify);
    if (ret != HCF_SUCCESS) {
        guard.SetErrorCode(ret);
        NAPI_LOG_THROW(env, ret, "create c verify fail.");
        return nullptr;
    }

    NapiVerify *napiVerify = new (std::nothrow) NapiVerify(verify);
    if (napiVerify == nullptr) {
        guard.SetErrorCode(HCF_ERR_MALLOC);
        NAPI_LOG_THROW(env, HCF_ERR_MALLOC, "new napi verify failed");
        HcfObjDestroy(verify);
        verify = nullptr;
        return nullptr;
    }

    napi_value napiAlgName = nullptr;
    napi_create_string_utf8(env, algName.c_str(), NAPI_AUTO_LENGTH, &napiAlgName);
    napi_set_named_property(env, instance, CRYPTO_TAG_ALG_NAME.c_str(), napiAlgName);

    return NapiWrapVerify(env, instance, napiVerify);
}

static HcfResult SetVerifySpecUint8Array(napi_env env, napi_value *argv, HcfVerify *verify)
{
    HcfBlob *blob = nullptr;
    blob = GetBlobFromNapiUint8Arr(env, argv[1]);
    if (blob == nullptr) {
        LOGE("failed to get blob.");
        return HCF_INVALID_PARAMS;
    }
    HcfResult ret = verify->setVerifySpecUint8Array(verify, SM2_USER_ID_UINT8ARR, *blob);
    if (ret != HCF_SUCCESS) {
        LOGE("Failed to set verify spec uint8 array in C layer.");
    }
    HcfBlobDataFree(blob);
    HcfFree(blob);
    blob = nullptr;
    return ret;
}

static HcfResult SetVerifySpecInt(napi_env env, napi_value *argv, HcfVerify *verify)
{
    int32_t saltLen = 0;
    if (napi_get_value_int32(env, argv[1], &saltLen) != napi_ok) {
        LOGE("get signSpec saltLen failed!");
        return HCF_INVALID_PARAMS;
    }
    HcfResult ret = verify->setVerifySpecInt(verify, PSS_SALT_LEN_INT, saltLen);
    if (ret != HCF_SUCCESS) {
        LOGE("Failed to set verify spec integer in C layer.");
    }
    return ret;
}

static HcfResult SetVerifyMlDsaContext(napi_env env, napi_value *argv, HcfVerify *verify)
{
    HcfBlob *blob = nullptr;
    blob = GetBlobFromNapiUint8Arr(env, argv[1]);
    if (blob == nullptr) {
        LOGE("failed to get blob.");
        return HCF_ERR_PARAMETER_CHECK_FAILED;
    }
    HcfResult ret = verify->setVerifySpecUint8Array(verify, ML_DSA_CONTEXT_UINT8ARR, *blob);
    if (ret != HCF_SUCCESS) {
        LOGE("Failed to set ML-DSA context for verify spec in C layer.");
    }
    HcfBlobDataFree(blob);
    HcfFree(blob);
    blob = nullptr;
    return ret;
}

static HcfResult SetVerifyMlDsaBool(napi_env env, napi_value *argv, SignSpecItem item, HcfVerify *verify)
{
    napi_valuetype valueType;
    napi_typeof(env, argv[1], &valueType);
    if (valueType != napi_boolean) {
        LOGE("valueType is not boolean.");
        return HCF_INVALID_PARAMS;
    }
    bool flag = false;
    if (napi_get_value_bool(env, argv[1], &flag) != napi_ok) {
        LOGE("get verifySpec bool failed!");
        return HCF_ERR_NAPI;
    }
    HcfResult ret = verify->setVerifySpecBool(verify, item, flag);
    if (ret != HCF_SUCCESS) {
        LOGE("Failed to set verify spec boolean in C layer.");
    }
    return ret;
}

static HcfResult SetDetailVerifySpec(napi_env env, napi_value *argv, SignSpecItem item, HcfVerify *verify)
{
    HcfResult result = HCF_INVALID_PARAMS;

    switch (item) {
        case SM2_USER_ID_UINT8ARR:
            result = SetVerifySpecUint8Array(env, argv, verify);
            break;
        case PSS_SALT_LEN_INT:
            result = SetVerifySpecInt(env, argv, verify);
            break;
        case ML_DSA_CONTEXT_UINT8ARR:
            result = SetVerifyMlDsaContext(env, argv, verify);
            break;
        case ML_DSA_MU_BOOL:
        case ML_DSA_DETERMINISTIC_BOOL:
            result = SetVerifyMlDsaBool(env, argv, item, verify);
            break;
        default:
            LOGE("specItem not support.");
            break;
    }
    return result;
}

// verify setVerifySpec(itemType :VerifySpecItem, itemValue : number|string)
napi_value NapiVerify::JsSetVerifySpec(napi_env env, napi_callback_info info)
{
    napi_value thisVar = nullptr;
    NapiVerify *napiVerify = nullptr;
    size_t expectedArgc = ARGS_SIZE_TWO;
    size_t argc = ARGS_SIZE_TWO;
    napi_value argv[ARGS_SIZE_TWO] = { nullptr };
    napi_get_cb_info(env, info, &argc, argv, &thisVar, nullptr);
    if (argc != expectedArgc) {
        NAPI_LOG_THROW(env, HCF_INVALID_PARAMS, "init failed for wrong argument num.");
        return nullptr;
    }
    SignSpecItem item;
    if (napi_get_value_uint32(env, argv[0], reinterpret_cast<uint32_t *>(&item)) != napi_ok) {
        NAPI_LOG_THROW(env, HCF_INVALID_PARAMS, "get signSpecItem failed!");
        return nullptr;
    }
    napi_status status = napi_unwrap(env, thisVar, reinterpret_cast<void **>(&napiVerify));
    if (status != napi_ok || napiVerify == nullptr) {
        NAPI_LOG_THROW(env, HCF_INVALID_PARAMS, "failed to unwrap napiVerify obj!");
        return nullptr;
    }
    HcfVerify *verify = napiVerify->GetVerify();
    HcfResult ret = SetDetailVerifySpec(env, argv, item, verify);
    if (ret != HCF_SUCCESS) {
        if (!IsMlDsaVerify(verify, item)) {
            ret = HCF_INVALID_PARAMS;
        }
        NAPI_LOG_THROW(env, ret, "failed to set verify spec!");
        return nullptr;
    }
    return thisVar;
}

static napi_value GetVerifySpecString(napi_env env, SignSpecItem item, HcfVerify *verify)
{
    char *returnString = nullptr;
    HcfResult ret = verify->getVerifySpecString(verify, item, &returnString);
    if (ret != HCF_SUCCESS) {
        NAPI_LOG_THROW(env, ret, "C getVerifySpecString failed.");
        return nullptr;
    }

    napi_value instance = nullptr;
    napi_create_string_utf8(env, returnString, NAPI_AUTO_LENGTH, &instance);
    HcfFree(returnString);
    returnString = nullptr;
    return instance;
}

static napi_value GetVerifySpecNumber(napi_env env, SignSpecItem item, HcfVerify *verify)
{
    int returnInt;
    HcfResult ret = verify->getVerifySpecInt(verify, item, &returnInt);
    if (ret != HCF_SUCCESS) {
        NAPI_LOG_THROW(env, ret, "C getVerifySpecInt failed.");
        return nullptr;
    }

    napi_value instance = nullptr;
    napi_create_int32(env, returnInt, &instance);
    return instance;
}

napi_value NapiVerify::JsGetVerifySpec(napi_env env, napi_callback_info info)
{
    napi_value thisVar = nullptr;
    NapiVerify *napiVerify = nullptr;
    size_t expectedArgc = ARGS_SIZE_ONE;
    size_t argc = ARGS_SIZE_ONE;
    napi_value argv[ARGS_SIZE_ONE] = { nullptr };
    napi_get_cb_info(env, info, &argc, argv, &thisVar, nullptr);
    if (argc != expectedArgc) {
        NAPI_LOG_THROW(env, HCF_INVALID_PARAMS, "init failed for wrong argument num.");
        return nullptr;
    }
    SignSpecItem item;
    if (napi_get_value_uint32(env, argv[0], reinterpret_cast<uint32_t *>(&item)) != napi_ok) {
        NAPI_LOG_THROW(env, HCF_INVALID_PARAMS, "get signSpecItem failed!");
        return nullptr;
    }

    napi_status status = napi_unwrap(env, thisVar, reinterpret_cast<void **>(&napiVerify));
    if (status != napi_ok || napiVerify == nullptr) {
        NAPI_LOG_THROW(env, HCF_INVALID_PARAMS, "failed to unwrap napiVerify obj!");
        return nullptr;
    }
    HcfVerify *verify = napiVerify->GetVerify();
    if (verify == nullptr) {
        NAPI_LOG_THROW(env, HCF_INVALID_PARAMS, "failed to get verify obj!");
        return nullptr;
    }

    int32_t type = GetSignSpecType(item);
    if (type == SPEC_ITEM_TYPE_STR) {
        return GetVerifySpecString(env, item, verify);
    } else if (type == SPEC_ITEM_TYPE_NUM) {
        return GetVerifySpecNumber(env, item, verify);
    } else {
        HcfResult ret = HCF_INVALID_PARAMS;
        if (IsMlDsaVerify(verify, item)) {
            ret = HCF_ERR_INVALID_CALL;
        }
        NAPI_LOG_THROW(env, ret, "VerifySpecItem not support!");
        return nullptr;
    }
}

void NapiVerify::DefineVerifyJSClass(napi_env env, napi_value exports)
{
    napi_property_descriptor desc[] = {
        DECLARE_NAPI_FUNCTION("createVerify", NapiVerify::CreateJsVerify),
    };
    napi_define_properties(env, exports, sizeof(desc) / sizeof(desc[0]), desc);

    napi_property_descriptor classDesc[] = {
        DECLARE_NAPI_FUNCTION("init", NapiVerify::JsInit),
        DECLARE_NAPI_FUNCTION("update", NapiVerify::JsUpdate),
        DECLARE_NAPI_FUNCTION("verify", NapiVerify::JsVerify),
        DECLARE_NAPI_FUNCTION("initSync", NapiVerify::JsInitSync),
        DECLARE_NAPI_FUNCTION("updateSync", NapiVerify::JsUpdateSync),
        DECLARE_NAPI_FUNCTION("verifySync", NapiVerify::JsVerifySync),
        DECLARE_NAPI_FUNCTION("recover", NapiVerify::JsRecover),
        DECLARE_NAPI_FUNCTION("recoverSync", NapiVerify::JsRecoverSync),
        DECLARE_NAPI_FUNCTION("setVerifySpec", NapiVerify::JsSetVerifySpec),
        DECLARE_NAPI_FUNCTION("getVerifySpec", NapiVerify::JsGetVerifySpec),
    };
    napi_value constructor = nullptr;
    napi_define_class(env, "Verify", NAPI_AUTO_LENGTH, NapiVerify::VerifyConstructor, nullptr,
        sizeof(classDesc) / sizeof(classDesc[0]), classDesc, &constructor);
    napi_create_reference(env, constructor, 1, &classRef_);
}
} // CryptoFramework
} // OHOS
