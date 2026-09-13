/*
 * Copyright (C) 2026 Huawei Device Co., Ltd.
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

#include "log.h"
#include "napi_kem.h"

#include "memory.h"
#include "napi_crypto_framework_defines.h"
#include "napi_pri_key.h"
#include "napi_pub_key.h"
#include "napi_utils.h"

namespace OHOS {
namespace CryptoFramework {

enum KemOpType {
    KEM_ENCAPSULATE = 1,
    KEM_DECAPSULATE = 2
};

struct KemCtx {
    napi_env env = nullptr;

    AsyncType asyncType = ASYNC_CALLBACK;
    napi_ref callback = nullptr;
    napi_deferred deferred = nullptr;
    napi_value promise = nullptr;
    napi_async_work asyncWork = nullptr;
    napi_ref kemRef = nullptr;
    napi_ref keyRef = nullptr;

    HcfKem *kem = nullptr;
    HcfPubKey *pubKey = nullptr;
    HcfPriKey *priKey = nullptr;
    HcfBlob *ikme = nullptr;
    HcfBlob *wrappedKey = nullptr;

    HcfResult errCode = HCF_SUCCESS;
    const char *errMsg = nullptr;
    HcfBlob returnSharedSecret = { .data = nullptr, .len = 0 };
    HcfBlob returnWrappedKey = { .data = nullptr, .len = 0 };
    KemOpType opType = KEM_ENCAPSULATE;
};

thread_local napi_ref NapiKem::classRef_ = nullptr;

static const char *GetKemAlgoNameById(HcfKemAlgNameId algId)
{
    switch (algId) {
        case ML_KEM_512:
            return "ML-KEM512";
        case ML_KEM_768:
            return "ML-KEM768";
        case ML_KEM_1024:
            return "ML-KEM1024";
        default:
            return nullptr;
    }
}

static bool IsNapiValueNullOrUndefined(napi_env env, napi_value value)
{
    napi_valuetype type = napi_undefined;
    napi_typeof(env, value, &type);
    return (type == napi_null || type == napi_undefined);
}

static void FreeKemCtx(napi_env env, KemCtx *ctx)
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
    if (ctx->kemRef != nullptr) {
        napi_delete_reference(env, ctx->kemRef);
        ctx->kemRef = nullptr;
    }
    if (ctx->keyRef != nullptr) {
        napi_delete_reference(env, ctx->keyRef);
        ctx->keyRef = nullptr;
    }
    HcfBlobDataClearAndFree(&ctx->returnSharedSecret);
    HcfBlobDataClearAndFree(&ctx->returnWrappedKey);
    if (ctx->ikme != nullptr) {
        HcfBlobDataClearAndFree(ctx->ikme);
        HCF_FREE_PTR(ctx->ikme);
    }
    if (ctx->wrappedKey != nullptr) {
        HcfBlobDataClearAndFree(ctx->wrappedKey);
        HCF_FREE_PTR(ctx->wrappedKey);
    }
    HcfFree(ctx);
}

static napi_value BuildEncapsulateResult(napi_env env, HcfBlob *sharedSecret, HcfBlob *wrappedKey)
{
    napi_value result = nullptr;
    napi_create_object(env, &result);
    napi_value sharedSecretData = ConvertObjectBlobToNapiValue(env, sharedSecret);
    napi_value wrappedKeyData = ConvertObjectBlobToNapiValue(env, wrappedKey);
    napi_set_named_property(env, result, "sharedSecret", sharedSecretData);
    napi_set_named_property(env, result, "wrappedKey", wrappedKeyData);
    return result;
}

static void ReturnCallbackResult(napi_env env, KemCtx *ctx, napi_value result)
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

static void ReturnPromiseResult(napi_env env, KemCtx *ctx, napi_value result)
{
    if (ctx->errCode == HCF_SUCCESS) {
        napi_resolve_deferred(env, ctx->deferred, result);
    } else {
        napi_reject_deferred(env, ctx->deferred, GenerateBusinessError(env, ctx->errCode, ctx->errMsg));
    }
}

static HcfResult SetupKemAsyncCtx(napi_env env, napi_value thisVar, napi_value keyArg,
    napi_value callbackArg, KemCtx *ctx)
{
    if (napi_create_reference(env, thisVar, 1, &ctx->kemRef) != napi_ok ||
        napi_create_reference(env, keyArg, 1, &ctx->keyRef) != napi_ok) {
        return HCF_ERR_NAPI;
    }

    if (ctx->asyncType == ASYNC_PROMISE) {
        napi_create_promise(env, &ctx->deferred, &ctx->promise);
        return HCF_SUCCESS;
    }
    if (!GetCallbackFromJSParams(env, callbackArg, &ctx->callback)) {
        return HCF_ERR_NAPI;
    }
    return HCF_SUCCESS;
}

static HcfResult BuildEncapsulateCtx(napi_env env, napi_callback_info info, KemCtx *ctx)
{
    napi_value thisVar = nullptr;
    size_t expectedArgc = PARAMS_NUM_THREE;
    size_t argc = expectedArgc;
    napi_value argv[PARAMS_NUM_THREE] = { nullptr };
    napi_get_cb_info(env, info, &argc, argv, &thisVar, nullptr);
    if (argc != expectedArgc && argc != expectedArgc - 1) {
        return HCF_INVALID_PARAMS;
    }
    ctx->asyncType = isCallback(env, argv[expectedArgc - 1], argc, expectedArgc) ? ASYNC_CALLBACK : ASYNC_PROMISE;

    NapiKem *napiKem = nullptr;
    napi_status status = napi_unwrap(env, thisVar, reinterpret_cast<void **>(&napiKem));
    if (status != napi_ok || napiKem == nullptr) {
        return HCF_ERR_NAPI;
    }
    if (IsNapiValueNullOrUndefined(env, argv[PARAM0])) {
        return HCF_ERR_PARAMETER_CHECK_FAILED;
    }
    NapiPubKey *napiPubKey = nullptr;
    status = napi_unwrap(env, argv[PARAM0], reinterpret_cast<void **>(&napiPubKey));
    if (status != napi_ok || napiPubKey == nullptr) {
        return HCF_ERR_NAPI;
    }

    napi_valuetype ikmeType = napi_undefined;
    napi_typeof(env, argv[PARAM1], &ikmeType);
    if (ikmeType != napi_null && ikmeType != napi_undefined) {
        ctx->ikme = GetBlobFromNapiUint8Arr(env, argv[PARAM1]);
        if (ctx->ikme == nullptr) {
            return HCF_ERR_NAPI;
        }
    }
    ctx->kem = napiKem->GetKem();
    ctx->pubKey = napiPubKey->GetPubKey();
    ctx->opType = KEM_ENCAPSULATE;

    return SetupKemAsyncCtx(env, thisVar, argv[PARAM0], argv[expectedArgc - 1], ctx);
}

static HcfResult BuildDecapsulateCtx(napi_env env, napi_callback_info info, KemCtx *ctx)
{
    napi_value thisVar = nullptr;
    size_t expectedArgc = PARAMS_NUM_THREE;
    size_t argc = expectedArgc;
    napi_value argv[PARAMS_NUM_THREE] = { nullptr };
    napi_get_cb_info(env, info, &argc, argv, &thisVar, nullptr);
    if (argc != expectedArgc && argc != expectedArgc - 1) {
        return HCF_INVALID_PARAMS;
    }
    ctx->asyncType = isCallback(env, argv[expectedArgc - 1], argc, expectedArgc) ? ASYNC_CALLBACK : ASYNC_PROMISE;

    NapiKem *napiKem = nullptr;
    napi_status status = napi_unwrap(env, thisVar, reinterpret_cast<void **>(&napiKem));
    if (status != napi_ok || napiKem == nullptr) {
        return HCF_ERR_NAPI;
    }
    if (IsNapiValueNullOrUndefined(env, argv[PARAM0])) {
        return HCF_ERR_PARAMETER_CHECK_FAILED;
    }
    NapiPriKey *napiPriKey = nullptr;
    status = napi_unwrap(env, argv[PARAM0], reinterpret_cast<void **>(&napiPriKey));
    if (status != napi_ok || napiPriKey == nullptr) {
        return HCF_ERR_NAPI;
    }
    if (IsNapiValueNullOrUndefined(env, argv[PARAM1])) {
        return HCF_ERR_PARAMETER_CHECK_FAILED;
    }
    ctx->wrappedKey = GetBlobFromNapiUint8Arr(env, argv[PARAM1]);
    if (ctx->wrappedKey == nullptr) {
        return HCF_ERR_NAPI;
    }

    ctx->kem = napiKem->GetKem();
    ctx->priKey = napiPriKey->GetPriKey();
    ctx->opType = KEM_DECAPSULATE;

    return SetupKemAsyncCtx(env, thisVar, argv[PARAM0], argv[expectedArgc - 1], ctx);
}

static void KemAsyncWorkProcess(napi_env env, void *data)
{
    (void)env;
    KemCtx *ctx = static_cast<KemCtx *>(data);
    if (ctx->opType == KEM_ENCAPSULATE) {
        HistogramScopeGuard guard(API_KEM_ENCAPSULATE);
        const HcfBlob *ikmePtr = (ctx->ikme == nullptr) ? nullptr : ctx->ikme;
        ctx->errCode = ctx->kem->encapsulate(ctx->kem, ctx->pubKey, ikmePtr,
            &ctx->returnSharedSecret, &ctx->returnWrappedKey);
        if (ctx->errCode != HCF_SUCCESS) {
            ctx->errMsg = "kem encapsulate failed.";
            guard.SetErrorCode(ctx->errCode);
        }
        return;
    } else {
        HistogramScopeGuard guard(API_KEM_DECAPSULATE);
        ctx->errCode = ctx->kem->decapsulate(ctx->kem, ctx->priKey, ctx->wrappedKey, &ctx->returnSharedSecret);
        if (ctx->errCode != HCF_SUCCESS) {
            ctx->errMsg = "kem decapsulate failed.";
            guard.SetErrorCode(ctx->errCode);
        }
    }
}

static void KemAsyncWorkReturn(napi_env env, napi_status status, void *data)
{
    (void)status;
    KemCtx *ctx = static_cast<KemCtx *>(data);
    napi_value result = NapiGetNull(env);
    if (ctx->errCode == HCF_SUCCESS) {
        if (ctx->opType == KEM_ENCAPSULATE) {
            result = BuildEncapsulateResult(env, &ctx->returnSharedSecret, &ctx->returnWrappedKey);
        } else {
            result = ConvertObjectBlobToNapiValue(env, &ctx->returnSharedSecret);
        }
    }
    if (ctx->asyncType == ASYNC_CALLBACK) {
        ReturnCallbackResult(env, ctx, result);
    } else {
        ReturnPromiseResult(env, ctx, result);
    }
    FreeKemCtx(env, ctx);
}

static napi_value NewKemAsyncWork(napi_env env, KemCtx *ctx, const char *name)
{
    napi_create_async_work(env, nullptr, GetResourceName(env, name),
        [](napi_env env, void *data) { KemAsyncWorkProcess(env, data); },
        [](napi_env env, napi_status status, void *data) { KemAsyncWorkReturn(env, status, data); },
        static_cast<void *>(ctx), &ctx->asyncWork);
    napi_queue_async_work(env, ctx->asyncWork);
    return (ctx->asyncType == ASYNC_PROMISE) ? ctx->promise : NapiGetNull(env);
}

NapiKem::NapiKem(HcfKem *kem)
{
    kem_ = kem;
}

NapiKem::~NapiKem()
{
    HcfObjDestroy(kem_);
    kem_ = nullptr;
}

HcfKem *NapiKem::GetKem() const
{
    return kem_;
}

napi_value NapiKem::JsEncapsulate(napi_env env, napi_callback_info info)
{
    HistogramScopeGuard guard(API_KEM_ENCAPSULATE);
    KemCtx *ctx = static_cast<KemCtx *>(HcfMalloc(sizeof(KemCtx), 0));
    if (ctx == nullptr) {
        guard.SetErrorCode(HCF_ERR_MALLOC);
        NAPI_LOG_THROW(env, HCF_ERR_MALLOC, "create context fail.");
        return nullptr;
    }
    HcfResult ret = BuildEncapsulateCtx(env, info, ctx);
    if (ret != HCF_SUCCESS) {
        guard.SetErrorCode(ret);
        NAPI_LOG_THROW(env, ret, "build encapsulate context fail.");
        FreeKemCtx(env, ctx);
        return nullptr;
    }
    guard.DisableScopeGuard();
    return NewKemAsyncWork(env, ctx, "KemEncapsulate");
}

napi_value NapiKem::JsDecapsulate(napi_env env, napi_callback_info info)
{
    HistogramScopeGuard guard(API_KEM_DECAPSULATE);
    KemCtx *ctx = static_cast<KemCtx *>(HcfMalloc(sizeof(KemCtx), 0));
    if (ctx == nullptr) {
        guard.SetErrorCode(HCF_ERR_MALLOC);
        NAPI_LOG_THROW(env, HCF_ERR_MALLOC, "create context fail.");
        return nullptr;
    }
    HcfResult ret = BuildDecapsulateCtx(env, info, ctx);
    if (ret != HCF_SUCCESS) {
        guard.SetErrorCode(ret);
        NAPI_LOG_THROW(env, ret, "Build decapsulate context fail.");
        FreeKemCtx(env, ctx);
        return nullptr;
    }
    guard.DisableScopeGuard();
    return NewKemAsyncWork(env, ctx, "KemDecapsulate");
}

napi_value NapiKem::JsEncapsulateSync(napi_env env, napi_callback_info info)
{
    HistogramScopeGuard guard(API_KEM_ENCAPSULATE_SYNC);
    napi_value thisVar = nullptr;
    size_t argc = PARAMS_NUM_TWO;
    napi_value argv[PARAMS_NUM_TWO] = { nullptr };
    napi_get_cb_info(env, info, &argc, argv, &thisVar, nullptr);
    if (argc != PARAMS_NUM_TWO) {
        guard.SetErrorCode(HCF_INVALID_PARAMS);
        NAPI_LOG_THROW(env, HCF_INVALID_PARAMS, "wrong argument num.");
        return nullptr;
    }
    if (IsNapiValueNullOrUndefined(env, argv[PARAM0])) {
        guard.SetErrorCode(HCF_ERR_PARAMETER_CHECK_FAILED);
        NAPI_LOG_THROW(env, HCF_ERR_PARAMETER_CHECK_FAILED, "pubKey is null or undefined.");
        return nullptr;
    }
    NapiKem *napiKem = nullptr;
    NapiPubKey *napiPubKey = nullptr;
    if (napi_unwrap(env, thisVar, reinterpret_cast<void **>(&napiKem)) != napi_ok || napiKem == nullptr ||
        napi_unwrap(env, argv[PARAM0], reinterpret_cast<void **>(&napiPubKey)) != napi_ok || napiPubKey == nullptr) {
        guard.SetErrorCode(HCF_ERR_NAPI);
        NAPI_LOG_THROW(env, HCF_ERR_NAPI, "unwrap napi object failed.");
        return nullptr;
    }

    HcfBlob *ikme = nullptr;
    if (!IsNapiValueNullOrUndefined(env, argv[PARAM1])) {
        ikme = GetBlobFromNapiUint8Arr(env, argv[PARAM1]);
        if (ikme == nullptr) {
            guard.SetErrorCode(HCF_ERR_NAPI);
            NAPI_LOG_THROW(env, HCF_ERR_NAPI, "parse ikme failed.");
            return nullptr;
        }
    }

    HcfBlob sharedSecret = { .data = nullptr, .len = 0 };
    HcfBlob wrappedKey = { .data = nullptr, .len = 0 };
    HcfResult ret = napiKem->GetKem()->encapsulate(napiKem->GetKem(), napiPubKey->GetPubKey(),
        (ikme == nullptr ? nullptr : ikme), &sharedSecret, &wrappedKey);
    HcfBlobDataClearAndFree(ikme);
    HCF_FREE_PTR(ikme);
    if (ret != HCF_SUCCESS) {
        guard.SetErrorCode(ret);
        NAPI_LOG_THROW(env, ret, "kem encapsulate failed.");
        return nullptr;
    }

    napi_value result = BuildEncapsulateResult(env, &sharedSecret, &wrappedKey);
    HcfBlobDataClearAndFree(&sharedSecret);
    HcfBlobDataClearAndFree(&wrappedKey);
    return result;
}

napi_value NapiKem::JsDecapsulateSync(napi_env env, napi_callback_info info)
{
    HistogramScopeGuard guard(API_KEM_DECAPSULATE_SYNC);
    napi_value thisVar = nullptr;
    size_t argc = PARAMS_NUM_TWO;
    napi_value argv[PARAMS_NUM_TWO] = { nullptr };
    napi_get_cb_info(env, info, &argc, argv, &thisVar, nullptr);
    if (argc != PARAMS_NUM_TWO) {
        guard.SetErrorCode(HCF_INVALID_PARAMS);
        NAPI_LOG_THROW(env, HCF_INVALID_PARAMS, "wrong argument num.");
        return nullptr;
    }
    if (IsNapiValueNullOrUndefined(env, argv[PARAM0])) {
        guard.SetErrorCode(HCF_ERR_PARAMETER_CHECK_FAILED);
        NAPI_LOG_THROW(env, HCF_ERR_PARAMETER_CHECK_FAILED, "priKey is null or undefined.");
        return nullptr;
    }
    if (IsNapiValueNullOrUndefined(env, argv[PARAM1])) {
        LOGE("WrappedKey is null or undefined.");
        guard.SetErrorCode(HCF_ERR_PARAMETER_CHECK_FAILED);
        NAPI_LOG_THROW(env, HCF_ERR_PARAMETER_CHECK_FAILED, "wrappedKey is null or undefined.");
        return nullptr;
    }
    NapiKem *napiKem = nullptr;
    NapiPriKey *napiPriKey = nullptr;
    if (napi_unwrap(env, thisVar, reinterpret_cast<void **>(&napiKem)) != napi_ok || napiKem == nullptr ||
        napi_unwrap(env, argv[PARAM0], reinterpret_cast<void **>(&napiPriKey)) != napi_ok || napiPriKey == nullptr) {
        guard.SetErrorCode(HCF_ERR_NAPI);
        NAPI_LOG_THROW(env, HCF_ERR_NAPI, "unwrap napi object failed.");
        return nullptr;
    }
    HcfBlob *wrappedKey = GetBlobFromNapiUint8Arr(env, argv[PARAM1]);
    if (wrappedKey == nullptr) {
        guard.SetErrorCode(HCF_ERR_NAPI);
        NAPI_LOG_THROW(env, HCF_ERR_NAPI, "parse wrappedKey failed.");
        return nullptr;
    }

    HcfBlob sharedSecret = { .data = nullptr, .len = 0 };
    HcfResult ret = napiKem->GetKem()->decapsulate(napiKem->GetKem(), napiPriKey->GetPriKey(),
        wrappedKey, &sharedSecret);
    HcfBlobDataClearAndFree(wrappedKey);
    HCF_FREE_PTR(wrappedKey);
    if (ret != HCF_SUCCESS) {
        guard.SetErrorCode(ret);
        NAPI_LOG_THROW(env, ret, "kem decapsulate failed.");
        return nullptr;
    }
    napi_value result = ConvertObjectBlobToNapiValue(env, &sharedSecret);
    HcfBlobDataClearAndFree(&sharedSecret);
    return result;
}

napi_value NapiKem::KemConstructor(napi_env env, napi_callback_info info)
{
    napi_value thisVar = nullptr;
    napi_get_cb_info(env, info, nullptr, nullptr, &thisVar, nullptr);
    return thisVar;
}

static HcfResult ParseKemAlgFromArgs(napi_env env, napi_callback_info info, HcfKem **kem)
{
    size_t argc = ARGS_SIZE_ONE;
    napi_value argv[ARGS_SIZE_ONE] = { nullptr };
    napi_get_cb_info(env, info, &argc, argv, nullptr, nullptr);
    if (argc != ARGS_SIZE_ONE) {
        NAPI_LOG_THROW(env, HCF_INVALID_PARAMS, "The input args num is invalid.");
        return HCF_INVALID_PARAMS;
    }
    HcfKemAlgNameId algId;
    if (napi_get_value_uint32(env, argv[PARAM0], reinterpret_cast<uint32_t *>(&algId)) != napi_ok) {
        NAPI_LOG_THROW(env, HCF_ERR_PARAMETER_CHECK_FAILED, "Invalid kem alg id.");
        return HCF_ERR_PARAMETER_CHECK_FAILED;
    }
    const char *algoName = GetKemAlgoNameById(algId);
    if (algoName == nullptr) {
        NAPI_LOG_THROW(env, HCF_ERR_PARAMETER_CHECK_FAILED, "Unsupported kem alg id.");
        return HCF_ERR_PARAMETER_CHECK_FAILED;
    }
    return HcfKemCreate(algoName, kem);
}

napi_value NapiKem::CreateJsKem(napi_env env, napi_callback_info info)
{
    HistogramScopeGuard guard(API_CREATE_KEM);
    HcfKem *kem = nullptr;
    HcfResult res = ParseKemAlgFromArgs(env, info, &kem);
    if (res != HCF_SUCCESS) {
        guard.SetErrorCode(res);
        NAPI_LOG_THROW(env, res, "create c kem failed.");
        return nullptr;
    }
    napi_value instance = nullptr;
    napi_value constructor = nullptr;
    napi_get_reference_value(env, classRef_, &constructor);
    napi_new_instance(env, constructor, 0, nullptr, &instance);
    NapiKem *napiKem = new (std::nothrow) NapiKem(kem);
    if (napiKem == nullptr) {
        HcfObjDestroy(kem);
        guard.SetErrorCode(HCF_ERR_MALLOC);
        NAPI_LOG_THROW(env, HCF_ERR_MALLOC, "new napi kem failed.");
        return nullptr;
    }
    napi_status status = napi_wrap(env, instance, napiKem,
        [](napi_env env, void *data, void *hint) {
            delete(static_cast<NapiKem *>(data));
        }, nullptr, nullptr);
    if (status != napi_ok) {
        delete napiKem;
        guard.SetErrorCode(HCF_ERR_NAPI);
        NAPI_LOG_THROW(env, HCF_ERR_NAPI, "wrap napi kem failed.");
        return nullptr;
    }
    return instance;
}

void NapiKem::DefineKemJSClass(napi_env env, napi_value exports)
{
    napi_property_descriptor desc[] = {
        DECLARE_NAPI_FUNCTION("createKem", NapiKem::CreateJsKem),
    };
    napi_define_properties(env, exports, sizeof(desc) / sizeof(desc[0]), desc);

    napi_property_descriptor classDesc[] = {
        DECLARE_NAPI_FUNCTION("encapsulate", NapiKem::JsEncapsulate),
        DECLARE_NAPI_FUNCTION("encapsulateSync", NapiKem::JsEncapsulateSync),
        DECLARE_NAPI_FUNCTION("decapsulate", NapiKem::JsDecapsulate),
        DECLARE_NAPI_FUNCTION("decapsulateSync", NapiKem::JsDecapsulateSync),
    };
    napi_value constructor = nullptr;
    napi_define_class(env, "Kem", NAPI_AUTO_LENGTH, NapiKem::KemConstructor, nullptr,
        sizeof(classDesc) / sizeof(classDesc[0]), classDesc, &constructor);
    napi_create_reference(env, constructor, 1, &classRef_);
}
}  // namespace CryptoFramework
}  // namespace OHOS
