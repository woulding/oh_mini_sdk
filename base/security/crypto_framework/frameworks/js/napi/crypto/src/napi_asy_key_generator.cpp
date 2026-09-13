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

#include "napi_asy_key_generator.h"

#include <limits>
#include "securec.h"
#include "log.h"
#include "memory.h"

#include "napi_crypto_framework_defines.h"
#include "napi_utils.h"
#include "napi_key_pair.h"
#include "napi_pri_key.h"
#include "napi_pub_key.h"

namespace OHOS {
namespace CryptoFramework {
struct GenKeyPairCtx {
    napi_env env = nullptr;

    AsyncType asyncType = ASYNC_CALLBACK;
    napi_ref callback = nullptr;
    napi_deferred deferred = nullptr;
    napi_value promise = nullptr;
    napi_async_work asyncWork = nullptr;
    napi_ref generatorRef = nullptr;

    HcfAsyKeyGenerator *generator = nullptr;
    HcfParamsSpec *params = nullptr;

    HcfResult errCode = HCF_SUCCESS;
    const char *errMsg = nullptr;
    HcfKeyPair *returnKeyPair = nullptr;
};

struct ConvertKeyCtx {
    napi_env env = nullptr;

    AsyncType asyncType = ASYNC_CALLBACK;
    napi_ref callback = nullptr;
    napi_deferred deferred = nullptr;
    napi_value promise = nullptr;
    napi_async_work asyncWork = nullptr;
    napi_ref generatorRef = nullptr;

    HcfAsyKeyGenerator *generator = nullptr;
    HcfParamsSpec *params = nullptr;
    HcfBlob *pubKey = nullptr;
    HcfBlob *priKey = nullptr;

    HcfResult errCode = HCF_SUCCESS;
    const char *errMsg = nullptr;
    HcfKeyPair *returnKeyPair = nullptr;
};

struct ConvertPemKeyCtx {
    napi_env env = nullptr;

    napi_deferred deferred = nullptr;
    napi_value promise = nullptr;
    napi_async_work asyncWork = nullptr;
    napi_ref generatorRef = nullptr;

    HcfAsyKeyGenerator *generator = nullptr;
    HcfParamsSpec *params = nullptr;
    HcfBlob *pubKey = nullptr;
    HcfBlob *priKey = nullptr;

    HcfResult errCode = HCF_SUCCESS;
    const char *errMsg = nullptr;
    HcfKeyPair *returnKeyPair = nullptr;
};

constexpr int PASSWORD_MAX_LENGTH = 4096;

thread_local napi_ref NapiAsyKeyGenerator::classRef_ = nullptr;

static void FreeGenKeyPairCtx(napi_env env, GenKeyPairCtx *ctx)
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

    if (ctx->generatorRef != nullptr) {
        napi_delete_reference(env, ctx->generatorRef);
        ctx->generatorRef = nullptr;
    }

    HcfFree(ctx);
}

static void FreeConvertKeyCtx(napi_env env, ConvertKeyCtx *ctx)
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

    if (ctx->generatorRef != nullptr) {
        napi_delete_reference(env, ctx->generatorRef);
        ctx->generatorRef = nullptr;
    }

    HcfBlobDataFree(ctx->pubKey);
    HcfFree(ctx->pubKey);
    ctx->pubKey = nullptr;
    HcfBlobDataClearAndFree(ctx->priKey);
    HcfFree(ctx->priKey);
    ctx->priKey = nullptr;
    HcfFree(ctx);
}

static void FreeDecodeParamsSpec(HcfParamsSpec *paramsSpec)
{
    if (paramsSpec == nullptr) {
        return;
    }
    HcfKeyDecodingParamsSpec *spec = reinterpret_cast<HcfKeyDecodingParamsSpec *>(paramsSpec);
    if (spec->password != nullptr) {
        size_t pwdLen = strlen(spec->password);
        (void)memset_s(static_cast<void *>(spec->password), pwdLen, 0, pwdLen);
        HcfFree(static_cast<void *>(spec->password));
        spec->password = nullptr;
    }
    HcfFree(paramsSpec);
    paramsSpec = nullptr;
}

static void FreeConvertPemKeyCtx(napi_env env, ConvertPemKeyCtx *ctx)
{
    if (ctx == nullptr) {
        return;
    }

    if (ctx->asyncWork != nullptr) {
        napi_delete_async_work(env, ctx->asyncWork);
        ctx->asyncWork = nullptr;
    }
    if (ctx->generatorRef != nullptr) {
        napi_delete_reference(env, ctx->generatorRef);
        ctx->generatorRef = nullptr;
    }
    FreeDecodeParamsSpec(ctx->params);

    ctx->errMsg = nullptr;
    if (ctx->pubKey != nullptr) {
        HcfBlobDataFree(ctx->pubKey);
        HcfFree(ctx->pubKey);
        ctx->pubKey = nullptr;
    }
    if (ctx->priKey != nullptr) {
        HcfBlobDataClearAndFree(ctx->priKey);
        HcfFree(ctx->priKey);
        ctx->priKey = nullptr;
    }
    HcfFree(ctx);
}

static void HcfFreePubKeyAndPriKey(HcfBlob *pubKey, HcfBlob *priKey)
{
    HcfBlobDataFree(pubKey);
    HCF_FREE_PTR(pubKey);
    HcfBlobDataClearAndFree(priKey);
    HCF_FREE_PTR(priKey);
}

static bool BuildGenKeyPairCtx(napi_env env, napi_callback_info info, GenKeyPairCtx *ctx)
{
    napi_value thisVar = nullptr;
    size_t expectedArgc = PARAMS_NUM_ONE;
    size_t argc = expectedArgc;
    napi_value argv[PARAMS_NUM_ONE] = { nullptr };
    napi_get_cb_info(env, info, &argc, argv, &thisVar, nullptr);
    if (argc != expectedArgc && argc != expectedArgc - 1) {
        LOGE("wrong argument num. require %{public}zu or %{public}zu arguments. [Argc]: %{public}zu!",
            expectedArgc - 1, expectedArgc, argc);
        return false;
    }
    ctx->asyncType = isCallback(env, argv[0], argc, expectedArgc) ? ASYNC_CALLBACK : ASYNC_PROMISE;

    NapiAsyKeyGenerator *napiGenerator = nullptr;
    napi_status status = napi_unwrap(env, thisVar, reinterpret_cast<void **>(&napiGenerator));
    if (status != napi_ok || napiGenerator == nullptr) {
        LOGE("failed to unwrap napi asyKeyGenerator obj.");
        return false;
    }

    ctx->generator = napiGenerator->GetAsyKeyGenerator();
    ctx->params = nullptr;

    if (napi_create_reference(env, thisVar, 1, &ctx->generatorRef) != napi_ok) {
        LOGE("create generator ref failed generator key pair!");
        return false;
    }

    if (ctx->asyncType == ASYNC_PROMISE) {
        napi_create_promise(env, &ctx->deferred, &ctx->promise);
        return true;
    } else {
        return GetCallbackFromJSParams(env, argv[expectedArgc - 1], &ctx->callback);
    }
}

static bool GetPkAndSkBlobFromNapiValueIfInput(napi_env env, napi_value pkValue, napi_value skValue,
    HcfBlob **returnPubKey, HcfBlob **returnPriKey)
{
    napi_valuetype valueType;
    napi_typeof(env, pkValue, &valueType);
    HcfBlob *pubKey = nullptr;
    if (valueType != napi_null) {
        pubKey = GetBlobFromNapiDataBlob(env, pkValue);
        if (pubKey == nullptr) {
            LOGE("failed to get pubKey.");
            return false;
        }
    }

    napi_typeof(env, skValue, &valueType);
    HcfBlob *priKey = nullptr;
    if (valueType != napi_null) {
        priKey = GetBlobFromNapiDataBlob(env, skValue);
        if (priKey == nullptr) {
            // if the prikey get func fails, the return pointer will not take the ownership of pubkey and not free it.
            HcfBlobDataFree(pubKey);
            HcfFree(pubKey);
            pubKey = nullptr;
            LOGE("failed to get priKey.");
            return false;
        }
    }

    *returnPubKey = pubKey;
    *returnPriKey = priKey;
    return true;
}

static HcfBlob *GetBlobFromStringJSParams(napi_env env, napi_value arg, bool allowEmpty)
{
    napi_valuetype valueType;
    napi_typeof(env, arg, &valueType);
    if (valueType != napi_string) {
        LOGE("wrong argument type. expect string type. [Type]: %{public}d", valueType);
        return nullptr;
    }

    size_t length = 0;
    if (napi_get_value_string_utf8(env, arg, nullptr, 0, &length) != napi_ok) {
        LOGE("can not get string length");
        return nullptr;
    }

    if (length == 0 && !allowEmpty) {
        LOGE("string length is 0");
        return nullptr;
    }
    if (length > (UINT32_MAX - 1)) {
        LOGE("string length exceeds maximum supported size");
        return nullptr;
    }

    HcfBlob *newBlob = static_cast<HcfBlob *>(HcfMalloc(sizeof(HcfBlob), 0));
    if (newBlob == nullptr) {
        LOGE("Failed to allocate newBlob memory!");
        return nullptr;
    }

    newBlob->len = length + 1;
    newBlob->data = static_cast<uint8_t *>(HcfMalloc(newBlob->len, 0));
    if (newBlob->data == nullptr) {
        LOGE("malloc blob data failed!");
        HcfFree(newBlob);
        newBlob = nullptr;
        return nullptr;
    }

    if (napi_get_value_string_utf8(env, arg, reinterpret_cast<char *>(newBlob->data), newBlob->len, &length) !=
        napi_ok) {
        LOGE("can not get string value");
        HcfBlobDataClearAndFree(newBlob);
        HcfFree(newBlob);
        newBlob = nullptr;
        return nullptr;
    }

    return newBlob;
}

static bool GetDecodingParamsSpec(napi_env env, napi_value arg, HcfParamsSpec **returnSpec)
{
    HcfKeyDecodingParamsSpec *decodingParamsSpec =
        reinterpret_cast<HcfKeyDecodingParamsSpec *>(HcfMalloc(sizeof(HcfKeyDecodingParamsSpec), 0));
    if (decodingParamsSpec == nullptr) {
        LOGE("decodingParamsSpec malloc failed!");
        return false;
    }

    HcfBlob *tmpPw = GetBlobFromStringJSParams(env, arg, false);
    if (tmpPw == nullptr) {
        LOGE("Failed to get passWord string from napi!");
        HcfFree(decodingParamsSpec);
        decodingParamsSpec = nullptr;
        return false;
    }
    if (tmpPw->len > PASSWORD_MAX_LENGTH) {
        LOGE("Password length exceeds max length limit of 4096 bytes!");
        HcfBlobDataClearAndFree(tmpPw);
        HcfFree(tmpPw);
        tmpPw = nullptr;
        HcfFree(decodingParamsSpec);
        decodingParamsSpec = nullptr;
        return false;
    }
    decodingParamsSpec->password = reinterpret_cast<char *>(tmpPw->data);

    *returnSpec = reinterpret_cast<HcfParamsSpec *>(decodingParamsSpec);
    HcfFree(tmpPw);
    tmpPw = nullptr;
    return true;
}

static bool GetPkAndSkStringFromNapiValueIfInput(napi_env env, napi_value pkValue, napi_value skValue,
    HcfBlob **returnPubKey, HcfBlob **returnPriKey)
{
    napi_valuetype valueTypePk;
    napi_valuetype valueTypeSk;
    napi_typeof(env, pkValue, &valueTypePk);
    napi_typeof(env, skValue, &valueTypeSk);
    if (valueTypePk == napi_null && valueTypeSk == napi_null) {
        LOGE("valueTypePk and valueTypeSk is all null.");
        return false;
    }
    HcfBlob *pubKey = nullptr;
    if (valueTypePk != napi_null) {
        pubKey = GetBlobFromStringJSParams(env, pkValue, true);
        if (pubKey == nullptr) {
            LOGE("GetBlobFromStringJSParams failed for pubKey.");
            return false;
        }
    }
    HcfBlob *priKey = nullptr;
    if (valueTypeSk != napi_null) {
        priKey = GetBlobFromStringJSParams(env, skValue, true);
        if (priKey == nullptr) {
            HcfBlobDataFree(pubKey);
            HcfFree(pubKey);
            pubKey = nullptr;
            LOGE("GetBlobFromStringJSParams failed for priKey.");
            return false;
        }
    }
    *returnPubKey = pubKey;
    *returnPriKey = priKey;
    return true;
}

static bool BuildConvertKeyCtx(napi_env env, napi_callback_info info, ConvertKeyCtx *ctx)
{
    napi_value thisVar = nullptr;
    size_t expectedArgc = PARAMS_NUM_THREE;
    size_t argc = expectedArgc;
    napi_value argv[PARAMS_NUM_THREE] = { nullptr };
    napi_get_cb_info(env, info, &argc, argv, &thisVar, nullptr);
    if (argc != expectedArgc && argc != expectedArgc - 1) {
        LOGE("wrong argument num. require %{public}zu or %{public}zu arguments. [Argc]: %{public}zu!",
            expectedArgc - 1, expectedArgc, argc);
        return false;
    }
    ctx->asyncType = isCallback(env, argv[expectedArgc - 1], argc, expectedArgc) ? ASYNC_CALLBACK : ASYNC_PROMISE;

    NapiAsyKeyGenerator *napiGenerator = nullptr;
    napi_status status = napi_unwrap(env, thisVar, reinterpret_cast<void **>(&napiGenerator));
    if (status != napi_ok || napiGenerator == nullptr) {
        LOGE("failed to unwrap napi asyKeyGenerator obj.");
        return false;
    }

    HcfBlob *pubKey = nullptr;
    HcfBlob *priKey = nullptr;
    if (!GetPkAndSkBlobFromNapiValueIfInput(env, argv[PARAM0], argv[PARAM1], &pubKey, &priKey)) {
        return false;
    }

    ctx->generator = napiGenerator->GetAsyKeyGenerator();
    ctx->params = nullptr;
    ctx->pubKey = pubKey;
    ctx->priKey = priKey;

    if (napi_create_reference(env, thisVar, 1, &ctx->generatorRef) != napi_ok) {
        LOGE("create generator ref failed when convert asym key!");
        return false;
    }

    if (ctx->asyncType == ASYNC_PROMISE) {
        napi_create_promise(env, &ctx->deferred, &ctx->promise);
        return true;
    } else {
        return GetCallbackFromJSParams(env, argv[expectedArgc - 1], &ctx->callback);
    }
}

static bool ValidateAndGetParams(napi_env env, napi_callback_info info, HcfBlob **pubKey, HcfBlob **priKey,
    HcfParamsSpec **paramsSpec)
{
    napi_value thisVar = nullptr;
    size_t expectedArgc = PARAMS_NUM_THREE;
    size_t argc = expectedArgc;
    napi_value argv[PARAMS_NUM_THREE] = { nullptr };
    napi_get_cb_info(env, info, &argc, argv, &thisVar, nullptr);
    if ((argc != expectedArgc) && (argc != (expectedArgc - 1))) {
        NAPI_LOG_THROW(env, HCF_INVALID_PARAMS, "invalid parameters.");
        return false;
    }

    if (!GetPkAndSkStringFromNapiValueIfInput(env, argv[PARAM0], argv[PARAM1], pubKey, priKey)) {
        NAPI_LOG_THROW(env, HCF_INVALID_PARAMS, "GetPkAndSkStringFromNapiValueIfInput failed.");
        return false;
    }

    if (argc == expectedArgc) {
        if (!GetDecodingParamsSpec(env, argv[PARAM2], paramsSpec)) {
            HcfFreePubKeyAndPriKey(*pubKey, *priKey);
            NAPI_LOG_THROW(env, HCF_INVALID_PARAMS, "get napi paramsSpec failed!");
            return false;
        }
    }
    return true;
}

static bool BuildConvertPemKeyCtx(napi_env env, napi_callback_info info, ConvertPemKeyCtx *ctx)
{
    napi_value thisVar = nullptr;
    napi_get_cb_info(env, info, nullptr, nullptr, &thisVar, nullptr);
    NapiAsyKeyGenerator *napiGenerator = nullptr;
    napi_status status = napi_unwrap(env, thisVar, reinterpret_cast<void **>(&napiGenerator));
    if (status != napi_ok || napiGenerator == nullptr) {
        LOGE("failed to unwrap napi asyKeyGenerator obj.");
        return false;
    }
    HcfBlob *pubKey = nullptr;
    HcfBlob *priKey = nullptr;
    HcfParamsSpec *paramsSpec = nullptr;
    if (!ValidateAndGetParams(env, info, &pubKey, &priKey, &paramsSpec)) {
        return false;
    }

    ctx->generator = napiGenerator->GetAsyKeyGenerator();
    ctx->params = paramsSpec;
    ctx->pubKey = pubKey;
    ctx->priKey = priKey;
    if (napi_create_reference(env, thisVar, 1, &ctx->generatorRef) != napi_ok) {
        LOGE("create generator ref failed when convert pem asym key!");
        return false;
    }
    napi_create_promise(env, &ctx->deferred, &ctx->promise);
    return true;
}

static void ReturnGenKeyPairCallbackResult(napi_env env, GenKeyPairCtx *ctx, napi_value result)
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

static void ReturnGenKeyPairPromiseResult(napi_env env, GenKeyPairCtx *ctx, napi_value result)
{
    if (ctx->errCode == HCF_SUCCESS) {
        napi_resolve_deferred(env, ctx->deferred, result);
    } else {
        napi_reject_deferred(env, ctx->deferred,
            GenerateBusinessError(env, ctx->errCode, ctx->errMsg));
    }
}

static void ReturnConvertKeyCallbackResult(napi_env env, ConvertKeyCtx *ctx, napi_value result)
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

static void ReturnConvertKeyPromiseResult(napi_env env, ConvertKeyCtx *ctx, napi_value result)
{
    if (ctx->errCode == HCF_SUCCESS) {
        napi_resolve_deferred(env, ctx->deferred, result);
    } else {
        napi_reject_deferred(env, ctx->deferred,
            GenerateBusinessError(env, ctx->errCode, ctx->errMsg));
    }
}

static void ReturnConvertPemKeyPromiseResult(napi_env env, ConvertPemKeyCtx *ctx, napi_value result)
{
    if (ctx->errCode == HCF_SUCCESS) {
        napi_resolve_deferred(env, ctx->deferred, result);
    } else {
        napi_reject_deferred(env, ctx->deferred,
            GenerateBusinessError(env, ctx->errCode, ctx->errMsg));
    }
}

static void GenKeyPairAsyncWorkProcess(napi_env env, void *data)
{
    GenKeyPairCtx *ctx = static_cast<GenKeyPairCtx *>(data);

    ctx->errCode = ctx->generator->generateKeyPair(ctx->generator, ctx->params, &(ctx->returnKeyPair));
    if (ctx->errCode != HCF_SUCCESS) {
        LOGE("generate key pair fail.");
        ctx->errMsg = "generate key pair fail.";
    }
}

static void GenKeyPairAsyncWorkReturn(napi_env env, napi_status status, void *data)
{
    GenKeyPairCtx *ctx = static_cast<GenKeyPairCtx *>(data);

    napi_value instance = nullptr;
    if (ctx->errCode == HCF_SUCCESS) {
        NapiKeyPair *napiKeyPair = new (std::nothrow) NapiKeyPair(ctx->returnKeyPair);
        if (napiKeyPair == nullptr) {
            NAPI_LOG_THROW(env, HCF_ERR_MALLOC, "new napi key pair failed!");
            FreeGenKeyPairCtx(env, ctx);
            return;
        }
        instance = napiKeyPair->ConvertToJsKeyPair(env);

        napi_status ret = napi_wrap(
            env, instance, napiKeyPair,
            [](napi_env env, void *data, void *hint) {
                delete(static_cast<NapiKeyPair *>(data));
            }, nullptr, nullptr);
        if (ret != napi_ok) {
            LOGE("failed to wrap napiKeyPair obj!");
            ctx->errCode = HCF_INVALID_PARAMS;
            ctx->errMsg = "failed to wrap napiKeyPair obj!";
            delete napiKeyPair;
        }
    }

    if (ctx->asyncType == ASYNC_CALLBACK) {
        ReturnGenKeyPairCallbackResult(env, ctx, instance);
    } else {
        ReturnGenKeyPairPromiseResult(env, ctx, instance);
    }
    FreeGenKeyPairCtx(env, ctx);
}

static void ConvertKeyAsyncWorkProcess(napi_env env, void *data)
{
    ConvertKeyCtx *ctx = static_cast<ConvertKeyCtx *>(data);

    ctx->errCode = ctx->generator->convertKey(ctx->generator, ctx->params,
        ctx->pubKey, ctx->priKey, &(ctx->returnKeyPair));
    if (ctx->errCode != HCF_SUCCESS) {
        LOGE("convert key fail.");
        ctx->errMsg = "convert key fail.";
    }
}

static void ConvertPemKeyAsyncWorkProcess(napi_env env, void *data)
{
    ConvertPemKeyCtx *ctx = static_cast<ConvertPemKeyCtx *>(data);
    const char *pubKeyStr = nullptr;
    const char *priKeyStr = nullptr;
    if (ctx->pubKey != nullptr) {
        pubKeyStr = reinterpret_cast<const char *>(ctx->pubKey->data);
    }
    if (ctx->priKey != nullptr) {
        priKeyStr = reinterpret_cast<const char *>(ctx->priKey->data);
    }
    ctx->errCode = ctx->generator->convertPemKey(ctx->generator, ctx->params,
            pubKeyStr, priKeyStr, &(ctx->returnKeyPair));
    if (ctx->errCode != HCF_SUCCESS) {
        LOGE("ConvertPemKey fail.");
        ctx->errMsg = "ConvertPemKey fail.";
    }
}

static void ConvertKeyAsyncWorkReturn(napi_env env, napi_status status, void *data)
{
    ConvertKeyCtx *ctx = static_cast<ConvertKeyCtx *>(data);

    napi_value instance = nullptr;
    if (ctx->errCode == HCF_SUCCESS) {
        NapiKeyPair *napiKeyPair = new (std::nothrow) NapiKeyPair(ctx->returnKeyPair);
        if (napiKeyPair == nullptr) {
            NAPI_LOG_THROW(env, HCF_ERR_MALLOC, "new napi key pair failed!");
            FreeConvertKeyCtx(env, ctx);
            return;
        }
        instance = napiKeyPair->ConvertToJsKeyPair(env);

        napi_status ret = napi_wrap(
            env, instance, napiKeyPair,
            [](napi_env env, void *data, void *hint) {
                delete(static_cast<NapiKeyPair *>(data));
            }, nullptr, nullptr);
        if (ret != napi_ok) {
            LOGE("failed to wrap napiKeyPair obj!");
            ctx->errCode = HCF_INVALID_PARAMS;
            ctx->errMsg = "failed to wrap napiKeyPair obj!";
            delete napiKeyPair;
        }
    }

    if (ctx->asyncType == ASYNC_CALLBACK) {
        ReturnConvertKeyCallbackResult(env, ctx, instance);
    } else {
        ReturnConvertKeyPromiseResult(env, ctx, instance);
    }
    FreeConvertKeyCtx(env, ctx);
}

static void ConvertPemKeyAsyncWorkReturn(napi_env env, napi_status status, void *data)
{
    ConvertPemKeyCtx *ctx = static_cast<ConvertPemKeyCtx *>(data);

    napi_value instance = nullptr;
    if (ctx->errCode == HCF_SUCCESS) {
        NapiKeyPair *napiKeyPair = new (std::nothrow) NapiKeyPair(ctx->returnKeyPair);
        if (napiKeyPair == nullptr) {
            NAPI_LOG_THROW(env, HCF_ERR_MALLOC, "new napi key pair failed!");
            HcfObjDestroy(ctx->returnKeyPair);
            ctx->returnKeyPair = nullptr;
            FreeConvertPemKeyCtx(env, ctx);
            return;
        }
        instance = napiKeyPair->ConvertToJsKeyPair(env);

        napi_status ret = napi_wrap(
            env, instance, napiKeyPair,
            [](napi_env env, void *data, void *hint) {
                delete(static_cast<NapiKeyPair *>(data));
            }, nullptr, nullptr);
        if (ret != napi_ok) {
            LOGE("failed to wrap napiKeyPair obj!");
            ctx->errCode = HCF_INVALID_PARAMS;
            ctx->errMsg = "failed to wrap napiKeyPair obj!";
            ctx->returnKeyPair = nullptr;
            delete napiKeyPair;
        }
    }

    ReturnConvertPemKeyPromiseResult(env, ctx, instance);
    FreeConvertPemKeyCtx(env, ctx);
}

static napi_value NewGenKeyPairAsyncWork(napi_env env, GenKeyPairCtx *ctx)
{
    napi_value resourceName = nullptr;
    napi_create_string_utf8(env, "generatorKeyPair", NAPI_AUTO_LENGTH, &resourceName);

    napi_create_async_work(
        env, nullptr, resourceName,
        [](napi_env env, void *data) {
            GenKeyPairAsyncWorkProcess(env, data);
            return;
        },
        [](napi_env env, napi_status status, void *data) {
            GenKeyPairAsyncWorkReturn(env, status, data);
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

static napi_value NewConvertKeyAsyncWork(napi_env env, ConvertKeyCtx *ctx)
{
    napi_value resourceName = nullptr;
    napi_create_string_utf8(env, "convertKey", NAPI_AUTO_LENGTH, &resourceName);

    napi_create_async_work(
        env, nullptr, resourceName,
        [](napi_env env, void *data) {
            ConvertKeyAsyncWorkProcess(env, data);
            return;
        },
        [](napi_env env, napi_status status, void *data) {
            ConvertKeyAsyncWorkReturn(env, status, data);
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

static napi_value NewConvertPemKeyAsyncWork(napi_env env, ConvertPemKeyCtx *ctx)
{
    napi_value resourceName = nullptr;
    napi_create_string_utf8(env, "convertPemKey", NAPI_AUTO_LENGTH, &resourceName);
    napi_create_async_work(
        env, nullptr, resourceName,
        [](napi_env env, void *data) {
            ConvertPemKeyAsyncWorkProcess(env, data);
            return;
        },
        [](napi_env env, napi_status status, void *data) {
            ConvertPemKeyAsyncWorkReturn(env, status, data);
            return;
        },
        static_cast<void *>(ctx),
        &ctx->asyncWork);

    napi_queue_async_work(env, ctx->asyncWork);
    return ctx->promise;
}

NapiAsyKeyGenerator::NapiAsyKeyGenerator(HcfAsyKeyGenerator *generator)
{
    this->generator_ = generator;
}

NapiAsyKeyGenerator::~NapiAsyKeyGenerator()
{
    HcfObjDestroy(this->generator_);
    this->generator_ = nullptr;
}

HcfAsyKeyGenerator *NapiAsyKeyGenerator::GetAsyKeyGenerator()
{
    return this->generator_;
}

napi_value NapiAsyKeyGenerator::JsGenerateKeyPair(napi_env env, napi_callback_info info)
{
    GenKeyPairCtx *ctx = static_cast<GenKeyPairCtx *>(HcfMalloc(sizeof(GenKeyPairCtx), 0));
    if (ctx == nullptr) {
        NAPI_LOG_THROW(env, HCF_ERR_MALLOC, "malloc ctx fail.");
        return nullptr;
    }

    if (!BuildGenKeyPairCtx(env, info, ctx)) {
        NAPI_LOG_THROW(env, HCF_INVALID_PARAMS, "build context fail.");
        FreeGenKeyPairCtx(env, ctx);
        return nullptr;
    }

    return NewGenKeyPairAsyncWork(env, ctx);
}

static bool GetHcfKeyPairInstance(napi_env env, HcfKeyPair *returnKeyPair, napi_value *instance)
{
    NapiKeyPair *napiKeyPair = new (std::nothrow) NapiKeyPair(returnKeyPair);
    if (napiKeyPair == nullptr) {
        HcfObjDestroy(returnKeyPair);
        returnKeyPair = nullptr;
        LOGE("new napi key pair failed");
        return false;
    }

    *instance = napiKeyPair->ConvertToJsKeyPair(env);
    napi_status ret = napi_wrap(
        env, *instance, napiKeyPair,
        [](napi_env env, void *data, void *hint) {
            delete(static_cast<NapiKeyPair *>(data));
        }, nullptr, nullptr);
    if (ret != napi_ok) {
        LOGE("failed to wrap napiKeyPair obj!");
        delete napiKeyPair;
        return false;
    }

    return true;
}

napi_value NapiAsyKeyGenerator::JsGenerateKeyPairSync(napi_env env, napi_callback_info info)
{
    napi_value thisVar = nullptr;
    napi_get_cb_info(env, info, nullptr, nullptr, &thisVar, nullptr);

    NapiAsyKeyGenerator *napiGenerator = nullptr;
    napi_status status = napi_unwrap(env, thisVar, reinterpret_cast<void **>(&napiGenerator));
    if (status != napi_ok || napiGenerator == nullptr) {
        NAPI_LOG_THROW(env, HCF_INVALID_PARAMS, "failed to unwrap napi asyKeyGenerator obj.");
        return nullptr;
    }

    HcfAsyKeyGenerator *generator = napiGenerator->GetAsyKeyGenerator();
    if (generator == nullptr) {
        NAPI_LOG_THROW(env, HCF_INVALID_PARAMS, "get generator fail!");
        return nullptr;
    }

    HcfParamsSpec *params = nullptr;
    HcfKeyPair *returnKeyPair = nullptr;
    HcfResult errCode = generator->generateKeyPair(generator, params, &returnKeyPair);
    if (errCode != HCF_SUCCESS) {
        NAPI_LOG_THROW(env, errCode, "generate key pair fail.");
        return nullptr;
    }

    napi_value instance = nullptr;
    if (!GetHcfKeyPairInstance(env, returnKeyPair, &instance)) {
        NAPI_LOG_THROW(env, HCF_ERR_MALLOC, "failed to get generate key pair instance!");
        return nullptr;
    }
    return instance;
}

napi_value NapiAsyKeyGenerator::JsConvertKey(napi_env env, napi_callback_info info)
{
    ConvertKeyCtx *ctx = static_cast<ConvertKeyCtx *>(HcfMalloc(sizeof(ConvertKeyCtx), 0));
    if (ctx == nullptr) {
        NAPI_LOG_THROW(env, HCF_ERR_MALLOC, "create context fail!");
        return nullptr;
    }

    if (!BuildConvertKeyCtx(env, info, ctx)) {
        NAPI_LOG_THROW(env, HCF_INVALID_PARAMS, "build context fail.");
        FreeConvertKeyCtx(env, ctx);
        return nullptr;
    }

    return NewConvertKeyAsyncWork(env, ctx);
}

napi_value NapiAsyKeyGenerator::JsConvertKeySync(napi_env env, napi_callback_info info)
{
    napi_value thisVar = nullptr;
    size_t argc = PARAMS_NUM_TWO;
    napi_value argv[PARAMS_NUM_TWO] = { nullptr };
    napi_get_cb_info(env, info, &argc, argv, &thisVar, nullptr);
    if (argc != PARAMS_NUM_TWO) {
        NAPI_LOG_THROW(env, HCF_INVALID_PARAMS, "wrong argument num.");
        return nullptr;
    }

    NapiAsyKeyGenerator *napiGenerator = nullptr;
    napi_status status = napi_unwrap(env, thisVar, reinterpret_cast<void **>(&napiGenerator));
    if (status != napi_ok || napiGenerator == nullptr) {
        NAPI_LOG_THROW(env, HCF_INVALID_PARAMS, "failed to unwrap napi asyKeyGenerator obj.");
        return nullptr;
    }

    HcfBlob *pubKey = nullptr;
    HcfBlob *priKey = nullptr;
    if (!GetPkAndSkBlobFromNapiValueIfInput(env, argv[PARAM0], argv[PARAM1], &pubKey, &priKey)) {
        NAPI_LOG_THROW(env, HCF_INVALID_PARAMS, "failed to unwrap napi asyKeyGenerator obj.");
        return nullptr;
    }

    HcfAsyKeyGenerator *generator = napiGenerator->GetAsyKeyGenerator();
    if (generator == nullptr) {
        HcfFreePubKeyAndPriKey(pubKey, priKey);
        NAPI_LOG_THROW(env, HCF_INVALID_PARAMS, "get generator fail!");
        return nullptr;
    }

    HcfParamsSpec *params = nullptr;
    HcfKeyPair *returnKeyPair = nullptr;
    HcfResult errCode = generator->convertKey(generator, params, pubKey, priKey, &(returnKeyPair));
    HcfFreePubKeyAndPriKey(pubKey, priKey);
    if (errCode != HCF_SUCCESS) {
        NAPI_LOG_THROW(env, errCode, "convert key fail.");
        return nullptr;
    }

    napi_value instance = nullptr;
    if (!GetHcfKeyPairInstance(env, returnKeyPair, &instance)) {
        NAPI_LOG_THROW(env, HCF_ERR_MALLOC, "failed to get convert key instance!");
        return nullptr;
    }

    return instance;
}

napi_value NapiAsyKeyGenerator::JsConvertPemKey(napi_env env, napi_callback_info info)
{
    ConvertPemKeyCtx *ctx = static_cast<ConvertPemKeyCtx *>(HcfMalloc(sizeof(ConvertPemKeyCtx), 0));
    if (ctx == nullptr) {
        NAPI_LOG_THROW(env, HCF_ERR_MALLOC, "create context fail!");
        return nullptr;
    }
    if (!BuildConvertPemKeyCtx(env, info, ctx)) {
        NAPI_LOG_THROW(env, HCF_INVALID_PARAMS, "build context fail.");
        FreeConvertPemKeyCtx(env, ctx);
        return nullptr;
    }
    return NewConvertPemKeyAsyncWork(env, ctx);
}

static HcfResult ConvertPemKeySync(HcfBlob *pubKey,  HcfBlob *priKey, HcfAsyKeyGenerator *generator,
    HcfParamsSpec *paramsSpec, HcfKeyPair **returnKeyPair)
{
    const char *pubKeyStr = nullptr;
    const char *priKeyStr = nullptr;
    if (pubKey != nullptr) {
        pubKeyStr = reinterpret_cast<const char *>(pubKey->data);
    }
    if (priKey != nullptr) {
        priKeyStr = reinterpret_cast<const char *>(priKey->data);
    }
    HcfResult errCode = generator->convertPemKey(generator, paramsSpec,
           pubKeyStr, priKeyStr, returnKeyPair);
    if (errCode != HCF_SUCCESS) {
        LOGE("convertPemKey error!");
        return errCode;
    }
    return HCF_SUCCESS;
}

napi_value NapiAsyKeyGenerator::JsConvertPemKeySync(napi_env env, napi_callback_info info)
{
    napi_value thisVar = nullptr;
    napi_get_cb_info(env, info, nullptr, nullptr, &thisVar, nullptr);
    HcfBlob *pubKey = nullptr;
    HcfBlob *priKey = nullptr;
    HcfParamsSpec *paramsSpec = nullptr;
    if (!ValidateAndGetParams(env, info, &pubKey, &priKey, &paramsSpec)) {
        FreeDecodeParamsSpec(paramsSpec);
        NAPI_LOG_THROW(env, HCF_INVALID_PARAMS, "invalid parameters.");
        return NapiGetNull(env);
    }

    NapiAsyKeyGenerator *napiGenerator = nullptr;
    napi_status status = napi_unwrap(env, thisVar, reinterpret_cast<void **>(&napiGenerator));
    if (status != napi_ok || napiGenerator == nullptr) {
        FreeDecodeParamsSpec(paramsSpec);
        HcfFreePubKeyAndPriKey(pubKey, priKey);
        NAPI_LOG_THROW(env, HCF_INVALID_PARAMS, "failed to unwrap napi asyKeyGenerator obj.");
        return nullptr;
    }

    HcfAsyKeyGenerator *generator = napiGenerator->GetAsyKeyGenerator();
    if (generator == nullptr) {
        FreeDecodeParamsSpec(paramsSpec);
        HcfFreePubKeyAndPriKey(pubKey, priKey);
        NAPI_LOG_THROW(env, HCF_INVALID_PARAMS, "GetAsyKeyGenerator failed!");
        return nullptr;
    }

    HcfKeyPair *returnKeyPair = nullptr;
    HcfResult errCode = ConvertPemKeySync(pubKey, priKey, generator, paramsSpec, &(returnKeyPair));
    HcfFreePubKeyAndPriKey(pubKey, priKey);
    if (errCode != HCF_SUCCESS) {
        FreeDecodeParamsSpec(paramsSpec);
        NAPI_LOG_THROW(env, errCode, "ConvertPemKeySync error!");
        return nullptr;
    }

    napi_value instance = nullptr;
    if (!GetHcfKeyPairInstance(env, returnKeyPair, &instance)) {
        FreeDecodeParamsSpec(paramsSpec);
        NAPI_LOG_THROW(env, HCF_ERR_MALLOC, "failed to get convert key instance!");
        return nullptr;
    }
    FreeDecodeParamsSpec(paramsSpec);
    return instance;
}

napi_value NapiAsyKeyGenerator::AsyKeyGeneratorConstructor(napi_env env, napi_callback_info info)
{
    napi_value thisVar = nullptr;
    napi_get_cb_info(env, info, nullptr, nullptr, &thisVar, nullptr);
    return thisVar;
}

static napi_value NapiWrapAsyKeyGen(napi_env env, napi_value instance, NapiAsyKeyGenerator *napiAsyKeyGenerator)
{
    napi_status status = napi_wrap(
        env, instance, napiAsyKeyGenerator,
        [](napi_env env, void *data, void *hint) {
            delete(static_cast<NapiAsyKeyGenerator *>(data));
        }, nullptr, nullptr);
    if (status != napi_ok) {
        delete napiAsyKeyGenerator;
        napiAsyKeyGenerator = nullptr;
        NAPI_LOG_THROW(env, HCF_INVALID_PARAMS, "failed to wrap napiAsyKeyGenerator obj!");
        return nullptr;
    }
    return instance;
}

napi_value NapiAsyKeyGenerator::CreateJsAsyKeyGenerator(napi_env env, napi_callback_info info)
{
    size_t expectedArgc = PARAMS_NUM_ONE;
    size_t argc = expectedArgc;
    napi_value argv[PARAMS_NUM_ONE] = { nullptr };
    napi_get_cb_info(env, info, &argc, argv, nullptr, nullptr);
    if (argc != expectedArgc) {
        NAPI_LOG_THROW(env, HCF_INVALID_PARAMS, "The input args num is invalid.");
        return NapiGetNull(env);
    }

    napi_value instance;
    napi_value constructor = nullptr;
    napi_get_reference_value(env, classRef_, &constructor);
    napi_new_instance(env, constructor, argc, argv, &instance);

    std::string algName;
    if (!GetStringFromJSParams(env, argv[0], algName)) {
        NAPI_LOG_THROW(env, HCF_INVALID_PARAMS, "failed to get algoName.");
        return NapiGetNull(env);
    }

    HistogramScopeGuard guard(API_CREATE_ASY_KEY_GENERATOR);
    if (!IsPqcAsyKeyAlgorithm(algName)) {
        guard.DisableScopeGuard();
    }

    HcfAsyKeyGenerator *generator = nullptr;
    HcfResult res = HcfAsyKeyGeneratorCreate(algName.c_str(), &generator);
    if (res != HCF_SUCCESS) {
        guard.SetErrorCode(HCF_INVALID_PARAMS);
        NAPI_LOG_THROW(env, HCF_INVALID_PARAMS, "create c generator fail.");
        return NapiGetNull(env);
    }

    NapiAsyKeyGenerator *napiAsyKeyGenerator = new (std::nothrow) NapiAsyKeyGenerator(generator);
    if (napiAsyKeyGenerator == nullptr) {
        guard.SetErrorCode(HCF_ERR_MALLOC);
        NAPI_LOG_THROW(env, HCF_ERR_MALLOC, "new napi asy key napi generator failed!");
        HcfObjDestroy(generator);
        generator = nullptr;
        return NapiGetNull(env);
    }

    napi_value napiAlgName = nullptr;
    napi_create_string_utf8(env, algName.c_str(), NAPI_AUTO_LENGTH, &napiAlgName);
    napi_set_named_property(env, instance, CRYPTO_TAG_ALG_NAME.c_str(), napiAlgName);

    return NapiWrapAsyKeyGen(env, instance, napiAsyKeyGenerator);
}

void NapiAsyKeyGenerator::DefineAsyKeyGeneratorJSClass(napi_env env, napi_value exports)
{
    napi_property_descriptor desc[] = {
        DECLARE_NAPI_FUNCTION("createAsyKeyGenerator", NapiAsyKeyGenerator::CreateJsAsyKeyGenerator),
    };
    napi_define_properties(env, exports, sizeof(desc) / sizeof(desc[0]), desc);

    napi_property_descriptor classDesc[] = {
        DECLARE_NAPI_FUNCTION("generateKeyPair", NapiAsyKeyGenerator::JsGenerateKeyPair),
        DECLARE_NAPI_FUNCTION("generateKeyPairSync", NapiAsyKeyGenerator::JsGenerateKeyPairSync),
        DECLARE_NAPI_FUNCTION("convertKey", NapiAsyKeyGenerator::JsConvertKey),
        DECLARE_NAPI_FUNCTION("convertKeySync", NapiAsyKeyGenerator::JsConvertKeySync),
        DECLARE_NAPI_FUNCTION("convertPemKey", NapiAsyKeyGenerator::JsConvertPemKey),
        DECLARE_NAPI_FUNCTION("convertPemKeySync", NapiAsyKeyGenerator::JsConvertPemKeySync),
    };
    napi_value constructor = nullptr;
    napi_define_class(env, "AsyKeyGenerator", NAPI_AUTO_LENGTH, NapiAsyKeyGenerator::AsyKeyGeneratorConstructor,
        nullptr, sizeof(classDesc) / sizeof(classDesc[0]), classDesc, &constructor);
    napi_create_reference(env, constructor, 1, &classRef_);
}
} // CryptoFramework
} // OHOS
