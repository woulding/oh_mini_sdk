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

#include "napi_sym_key_generator.h"

#include "securec.h"
#include "log.h"
#include "memory.h"
#include "napi_sym_key.h"
#include "napi_utils.h"
#include "napi_crypto_framework_defines.h"

namespace OHOS {
namespace CryptoFramework {
thread_local napi_ref NapiSymKeyGenerator::classRef_ = nullptr;

struct SymKeyGeneratorFwkCtxT {
    napi_env env = nullptr;
    AsyncType asyncType = ASYNC_CALLBACK;
    napi_ref callback = nullptr;
    napi_deferred deferred = nullptr;
    napi_value promise = nullptr;
    napi_async_work asyncWork = nullptr;
    napi_ref symKeyGeneratorRef = nullptr;

    HcfResult errCode = HCF_SUCCESS;
    HcfSymKey *returnSymKey = nullptr;
    const char *errMsg = nullptr;

    HcfSymKeyGenerator *generator = nullptr;
    HcfBlob keyMaterial = { .data = nullptr, .len = 0 };
};

using SymKeyGeneratorFwkCtx = SymKeyGeneratorFwkCtxT *;

static void FreeSymKeyGeneratorFwkCtx(napi_env env, SymKeyGeneratorFwkCtx &context)
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

    if (context->symKeyGeneratorRef != nullptr) {
        napi_delete_reference(env, context->symKeyGeneratorRef);
        context->symKeyGeneratorRef = nullptr;
    }

    if (context->keyMaterial.data != nullptr) {
        (void)memset_s(context->keyMaterial.data, context->keyMaterial.len, 0, context->keyMaterial.len);
        HcfFree(context->keyMaterial.data);
        context->keyMaterial.data = nullptr;
        context->keyMaterial.len = 0;
    }
    context->errMsg = nullptr;

    HcfFree(context);
    context = nullptr;
}

static bool BuildContextForGenerateKey(napi_env env, napi_callback_info info, SymKeyGeneratorFwkCtx context)
{
    napi_value thisVar = nullptr;
    size_t expectedArgc = ARGS_SIZE_ONE;
    size_t argc = ARGS_SIZE_ONE;
    napi_value argv[ARGS_SIZE_ONE] = { nullptr };
    napi_get_cb_info(env, info, &argc, argv, &thisVar, nullptr);
    if (argc != expectedArgc && argc != expectedArgc - 1) {
        LOGE("wrong argument num. require 0 or 1 arguments. [Argc]: %{public}zu!", argc);
        return false;
    }
    context->asyncType = isCallback(env, argv[expectedArgc - 1], argc, expectedArgc) ? ASYNC_CALLBACK : ASYNC_PROMISE;
    NapiSymKeyGenerator *napiGenerator = nullptr;
    napi_status status = napi_unwrap(env, thisVar, reinterpret_cast<void **>(&napiGenerator));
    if (status != napi_ok || napiGenerator == nullptr) {
        LOGE("failed to unwrap NapiSymKeyGenerator obj!");
        return false;
    }

    context->generator = napiGenerator->GetSymKeyGenerator();
    if (context->generator == nullptr) {
        LOGE("failed to get generator obj!");
        return false;
    }

    if (napi_create_reference(env, thisVar, 1, &context->symKeyGeneratorRef) != napi_ok) {
        LOGE("create sym key generator ref failed when generate sym key!");
        return false;
    }

    if (context->asyncType == ASYNC_PROMISE) {
        napi_create_promise(env, &context->deferred, &context->promise);
        return true;
    } else {
        return GetCallbackFromJSParams(env, argv[0], &context->callback);
    }
}

static bool BuildContextForConvertKey(napi_env env, napi_callback_info info, SymKeyGeneratorFwkCtx context)
{
    napi_value thisVar = nullptr;
    size_t expectedArgc = ARGS_SIZE_TWO;
    size_t argc = ARGS_SIZE_TWO;
    napi_value argv[ARGS_SIZE_TWO] = { nullptr };
    napi_get_cb_info(env, info, &argc, argv, &thisVar, nullptr);
    if (argc != expectedArgc && argc != expectedArgc - 1) {
        LOGE("wrong argument num. require 1 or 2 arguments. [Argc]: %{public}zu!", argc);
        return false;
    }
    context->asyncType = isCallback(env, argv[expectedArgc - 1], argc, expectedArgc) ? ASYNC_CALLBACK : ASYNC_PROMISE;

    NapiSymKeyGenerator *napiGenerator = nullptr;
    napi_status status = napi_unwrap(env, thisVar, reinterpret_cast<void **>(&napiGenerator));
    if (status != napi_ok || napiGenerator == nullptr) {
        LOGE("failed to unwrap NapiSymKeyGenerator obj!");
        return false;
    }

    context->generator = napiGenerator->GetSymKeyGenerator();
    if (context->generator == nullptr) {
        LOGE("failed to get generator obj!");
        return false;
    }

    size_t index = 0;
    HcfBlob *blob = GetBlobFromNapiDataBlob(env, argv[index++]);
    if (blob == nullptr) {
        LOGE("get keyMaterial failed!");
        return false;
    }
    context->keyMaterial = *blob;
    HcfFree(blob);
    blob = nullptr;

    if (napi_create_reference(env, thisVar, 1, &context->symKeyGeneratorRef) != napi_ok) {
        LOGE("create sym key generator ref failed when covert sym key!");
        return false;
    }

    if (context->asyncType == ASYNC_PROMISE) {
        napi_create_promise(env, &context->deferred, &context->promise);
        return true;
    } else {
        return GetCallbackFromJSParams(env, argv[index], &context->callback);
    }
}

static void ReturnPromiseResult(napi_env env, SymKeyGeneratorFwkCtx context, napi_value result)
{
    if (context->errCode == HCF_SUCCESS) {
        napi_resolve_deferred(env, context->deferred, result);
    } else {
        napi_reject_deferred(env, context->deferred,
            GenerateBusinessError(env, context->errCode, context->errMsg));
    }
}

static void ReturnCallbackResult(napi_env env, SymKeyGeneratorFwkCtx context, napi_value result)
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

static void AsyncGenKeyProcess(napi_env env, void *data)
{
    SymKeyGeneratorFwkCtx context = static_cast<SymKeyGeneratorFwkCtx>(data);
    HcfSymKeyGenerator *generator = context->generator;

    HcfSymKey *key = nullptr;
    context->errCode = generator->generateSymKey(generator, &key);
    if (context->errCode != HCF_SUCCESS) {
        LOGE("generate sym key failed.");
        context->errMsg = "generate sym key failed.";
        return;
    }

    context->errCode = HCF_SUCCESS;
    context->returnSymKey = key;
}

static void AsyncKeyReturn(napi_env env, napi_status status, void *data)
{
    napi_value instance = NapiSymKey::CreateSymKey(env);
    SymKeyGeneratorFwkCtx context = static_cast<SymKeyGeneratorFwkCtx>(data);
    NapiSymKey *napiSymKey = new (std::nothrow) NapiSymKey(context->returnSymKey);
    if (napiSymKey == nullptr) {
        FreeSymKeyGeneratorFwkCtx(env, context);
        NAPI_LOG_THROW(env, HCF_ERR_MALLOC, "new napi sym key failed.");
        return;
    }

    napi_status ret = napi_wrap(env, instance, napiSymKey,
        [](napi_env env, void *data, void *hint) {
            delete(static_cast<NapiSymKey *>(data));
        }, nullptr, nullptr);
    if (ret != napi_ok) {
        LOGE("failed to wrap napiSymKey obj!");
        context->errCode = HCF_INVALID_PARAMS;
        context->errMsg = "failed to wrap napiSymKey obj!";
        delete napiSymKey;
    }

    if (context->asyncType == ASYNC_CALLBACK) {
        ReturnCallbackResult(env, context, instance);
    } else {
        ReturnPromiseResult(env, context, instance);
    }
    FreeSymKeyGeneratorFwkCtx(env, context);
}

static void AsyncConvertKeyProcess(napi_env env, void *data)
{
    SymKeyGeneratorFwkCtx context = static_cast<SymKeyGeneratorFwkCtx>(data);
    HcfSymKeyGenerator *generator = context->generator;

    HcfSymKey *key = nullptr;
    context->errCode = generator->convertSymKey(generator, &context->keyMaterial, &key);
    if (context->errCode != HCF_SUCCESS) {
        LOGE("convertSymKey key failed!");
        context->errMsg = "convert sym key failed.";
        return;
    }

    context->returnSymKey = key;
}

static napi_value NewConvertKeyAsyncWork(napi_env env, SymKeyGeneratorFwkCtx context)
{
    napi_value resourceName = nullptr;
    napi_create_string_utf8(env, "convertSymKey", NAPI_AUTO_LENGTH, &resourceName);

    napi_create_async_work(
        env,
        nullptr,
        resourceName,
        [](napi_env env, void *data) {
            AsyncConvertKeyProcess(env, data);
            return;
        },
        [](napi_env env, napi_status status, void *data) {
            AsyncKeyReturn(env, status, data);
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

static napi_value NewGenKeyAsyncWork(napi_env env, SymKeyGeneratorFwkCtx context)
{
    napi_value resourceName = nullptr;
    napi_create_string_utf8(env, "generatorSymKey", NAPI_AUTO_LENGTH, &resourceName);

    napi_create_async_work(
        env,
        nullptr,
        resourceName,
        [](napi_env env, void *data) {
            AsyncGenKeyProcess(env, data);
            return;
        },
        [](napi_env env, napi_status status, void *data) {
            AsyncKeyReturn(env, status, data);
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

NapiSymKeyGenerator::NapiSymKeyGenerator(HcfSymKeyGenerator *generator)
{
    this->generator_ = generator;
}

NapiSymKeyGenerator::~NapiSymKeyGenerator()
{
    HcfObjDestroy(this->generator_);
    this->generator_ = nullptr;
}

HcfSymKeyGenerator *NapiSymKeyGenerator::GetSymKeyGenerator() const
{
    return this->generator_;
}

static bool napiGetInstance(napi_env env, HcfSymKey *key, napi_value instance)
{
    NapiSymKey *napiSymKey = new (std::nothrow) NapiSymKey(key);
    if (napiSymKey == nullptr) {
        NAPI_LOG_THROW(env, HCF_ERR_MALLOC, "new napi sym key failed.");
        HcfObjDestroy(key);
        key = nullptr;
        return false;
    }

    napi_status wrapStatus = napi_wrap(
        env, instance, napiSymKey,
        [](napi_env env, void *data, void *hint) {
            delete(static_cast<NapiSymKey *>(data));
        }, nullptr, nullptr);
    if (wrapStatus != napi_ok) {
        LOGE("failed to wrap napiSymKey obj!");
        delete napiSymKey;
        return false;
    }

    return true;
}

napi_value NapiSymKeyGenerator::JsGenerateSymKey(napi_env env, napi_callback_info info)
{
    SymKeyGeneratorFwkCtx context = static_cast<SymKeyGeneratorFwkCtx>(HcfMalloc(sizeof(SymKeyGeneratorFwkCtxT), 0));
    if (context == nullptr) {
        NAPI_LOG_THROW(env, HCF_ERR_MALLOC, "Create context failed!");
        return nullptr;
    }

    if (!BuildContextForGenerateKey(env, info, context)) {
        NAPI_LOG_THROW(env, HCF_INVALID_PARAMS, "Build context fail.");
        FreeSymKeyGeneratorFwkCtx(env, context);
        return nullptr;
    }

    napi_value result = NewGenKeyAsyncWork(env, context);
    if (result == nullptr) {
        LOGE("NewGenKeyAsyncWork failed!");
        FreeSymKeyGeneratorFwkCtx(env, context);
        return nullptr;
    }
    return result;
}

napi_value NapiSymKeyGenerator::JsGenerateSymKeySync(napi_env env, napi_callback_info info)
{
    napi_value thisVar = nullptr;
    napi_get_cb_info(env, info, nullptr, nullptr, &thisVar, nullptr);
    NapiSymKeyGenerator *napiGenerator = nullptr;
    napi_status unwrapStatus = napi_unwrap(env, thisVar, reinterpret_cast<void **>(&napiGenerator));
    if (unwrapStatus != napi_ok || napiGenerator == nullptr) {
        NAPI_LOG_THROW(env, HCF_ERR_MALLOC, "failed to unwrap NapiSymKeyGenerator obj.");
        return nullptr;
    }

    HcfSymKeyGenerator *generator = napiGenerator->GetSymKeyGenerator();
    if (generator == nullptr) {
        NAPI_LOG_THROW(env, HCF_ERR_MALLOC, "failed to get generator obj.");
        return nullptr;
    }

    HcfSymKey *key = nullptr;
    HcfResult ret = generator->generateSymKey(generator, &key);
    if (ret != HCF_SUCCESS) {
        NAPI_LOG_THROW(env, HCF_ERR_MALLOC, "generate sym key failed.");
        return nullptr;
    }

    napi_value instance = NapiSymKey::CreateSymKey(env);
    if (!napiGetInstance(env, key, instance)) {
        NAPI_LOG_THROW(env, HCF_ERR_MALLOC, "get instance failed!");
        return nullptr;
    }

    return instance;
}

napi_value NapiSymKeyGenerator::JsConvertKey(napi_env env, napi_callback_info info)
{
    SymKeyGeneratorFwkCtx context = static_cast<SymKeyGeneratorFwkCtx>(HcfMalloc(sizeof(SymKeyGeneratorFwkCtxT), 0));
    if (context == nullptr) {
        NAPI_LOG_THROW(env, HCF_ERR_MALLOC, "malloc SymKeyGeneratorFwkCtx failed!");
        return nullptr;
    }

    if (!BuildContextForConvertKey(env, info, context)) {
        NAPI_LOG_THROW(env, HCF_INVALID_PARAMS, "BuildContextForConvertKey failed!");
        FreeSymKeyGeneratorFwkCtx(env, context);
        return nullptr;
    }

    napi_value result = NewConvertKeyAsyncWork(env, context);
    if (result == nullptr) {
        LOGE("Get deviceauth async work failed!");
        FreeSymKeyGeneratorFwkCtx(env, context);
        return nullptr;
    }
    return result;
}

napi_value NapiSymKeyGenerator::JsConvertKeySync(napi_env env, napi_callback_info info)
{
    napi_value thisVar = nullptr;
    size_t argc = ARGS_SIZE_ONE;
    napi_value argv[ARGS_SIZE_ONE] = { nullptr };
    napi_get_cb_info(env, info, &argc, argv, &thisVar, nullptr);
    if (argc != ARGS_SIZE_ONE) {
        NAPI_LOG_THROW(env, HCF_INVALID_PARAMS, "the input args num is invalid!");
        return nullptr;
    }

    NapiSymKeyGenerator *napiGenerator = nullptr;
    napi_status unwrapStatus = napi_unwrap(env, thisVar, reinterpret_cast<void **>(&napiGenerator));
    if (unwrapStatus != napi_ok || napiGenerator == nullptr) {
        NAPI_LOG_THROW(env, HCF_INVALID_PARAMS, "failed to unwrap NapiSymKeyGenerator obj!");
        return nullptr;
    }

    HcfSymKeyGenerator *generator = napiGenerator->GetSymKeyGenerator();
    if (generator == nullptr) {
        NAPI_LOG_THROW(env, HCF_ERR_MALLOC, "failed to get generator obj!");
        return nullptr;
    }

    HcfBlob *keyMaterial = GetBlobFromNapiDataBlob(env, argv[PARAM0]);
    if (keyMaterial == nullptr) {
        NAPI_LOG_THROW(env, HCF_INVALID_PARAMS, "get keyMaterial failed!");
        return nullptr;
    }

    HcfSymKey *key = nullptr;
    HcfResult ret = generator->convertSymKey(generator, keyMaterial, &key);
    HcfBlobDataClearAndFree(keyMaterial);
    HcfFree(keyMaterial);
    keyMaterial = nullptr;
    if (ret != HCF_SUCCESS) {
        NAPI_LOG_THROW(env, ret, "convertSymKey key failed!");
        return nullptr;
    }

    napi_value instance = NapiSymKey::CreateSymKey(env);
    if (!napiGetInstance(env, key, instance)) {
        NAPI_LOG_THROW(env, HCF_ERR_MALLOC, "get instance failed!");
        return nullptr;
    }

    return instance;
}

napi_value NapiSymKeyGenerator::SymKeyGeneratorConstructor(napi_env env, napi_callback_info info)
{
    napi_value thisVar = nullptr;
    napi_get_cb_info(env, info, nullptr, nullptr, &thisVar, nullptr);
    return thisVar;
}

napi_value NapiSymKeyGenerator::CreateSymKeyGenerator(napi_env env, napi_callback_info info)
{
    size_t argc = ARGS_SIZE_ONE;
    napi_value argv[ARGS_SIZE_ONE] = { nullptr };
    napi_get_cb_info(env, info, &argc, argv, nullptr, nullptr);

    if (argc != ARGS_SIZE_ONE) {
        NAPI_LOG_THROW(env, HCF_INVALID_PARAMS, "The input args num is invalid.");
        return nullptr;
    }

    napi_value instance;
    napi_value constructor = nullptr;
    napi_get_reference_value(env, classRef_, &constructor);
    napi_new_instance(env, constructor, argc, argv, &instance);

    std::string algoName;
    if (!GetStringFromJSParams(env, argv[0], algoName)) {
        NAPI_LOG_THROW(env, HCF_INVALID_PARAMS, "failed to get algoName.");
        return nullptr;
    }

    HcfSymKeyGenerator *generator = nullptr;
    HcfResult res = HcfSymKeyGeneratorCreate(algoName.c_str(), &generator);
    if (res != HCF_SUCCESS) {
        NAPI_LOG_THROW(env, res, "create C generator fail.");
        return nullptr;
    }
    NapiSymKeyGenerator *napiSymKeyGenerator = new (std::nothrow) NapiSymKeyGenerator(generator);
    if (napiSymKeyGenerator == nullptr) {
        NAPI_LOG_THROW(env, HCF_ERR_MALLOC, "new napi sym key generator failed.");
        HcfObjDestroy(generator);
        generator = nullptr;
        return nullptr;
    }

    napi_status status = napi_wrap(env, instance, napiSymKeyGenerator,
        [](napi_env env, void *data, void *hint) {
            delete(static_cast<NapiSymKeyGenerator *>(data));
        }, nullptr, nullptr);
    if (status != napi_ok) {
        NAPI_LOG_THROW(env, HCF_INVALID_PARAMS, "failed to wrap napiSymKeyGenerator obj!");
        delete napiSymKeyGenerator;
        return nullptr;
    }
    return instance;
}

napi_value NapiSymKeyGenerator::JsGetAlgorithm(napi_env env, napi_callback_info info)
{
    napi_value thisVar = nullptr;
    NapiSymKeyGenerator *napiSymKeyGenerator = nullptr;
    napi_get_cb_info(env, info, nullptr, nullptr, &thisVar, nullptr);
    napi_status status = napi_unwrap(env, thisVar, reinterpret_cast<void **>(&napiSymKeyGenerator));
    if (status != napi_ok || napiSymKeyGenerator == nullptr) {
        NAPI_LOG_THROW(env, HCF_INVALID_PARAMS, "failed to unwrap napiSymKeyGenerator obj!");
        return nullptr;
    }
    HcfSymKeyGenerator *generator = napiSymKeyGenerator->GetSymKeyGenerator();

    const char *algo = generator->getAlgoName(generator);
    napi_value instance = nullptr;
    napi_create_string_utf8(env, algo, NAPI_AUTO_LENGTH, &instance);
    return instance;
}

void NapiSymKeyGenerator::DefineSymKeyGeneratorJSClass(napi_env env, napi_value exports)
{
    napi_property_descriptor desc[] = {
        DECLARE_NAPI_FUNCTION("createSymKeyGenerator", NapiSymKeyGenerator::CreateSymKeyGenerator),
    };
    napi_define_properties(env, exports, sizeof(desc) / sizeof(desc[0]), desc);

    napi_property_descriptor classDesc[] = {
        DECLARE_NAPI_FUNCTION("generateSymKey", NapiSymKeyGenerator::JsGenerateSymKey),
        DECLARE_NAPI_FUNCTION("generateSymKeySync", NapiSymKeyGenerator::JsGenerateSymKeySync),
        DECLARE_NAPI_FUNCTION("convertKey", NapiSymKeyGenerator::JsConvertKey),
        DECLARE_NAPI_FUNCTION("convertKeySync", NapiSymKeyGenerator::JsConvertKeySync),
        { .utf8name = "algName", .getter = NapiSymKeyGenerator::JsGetAlgorithm },
    };
    napi_value constructor = nullptr;
    napi_define_class(env, "SymKeyGenerator", NAPI_AUTO_LENGTH,
        NapiSymKeyGenerator::SymKeyGeneratorConstructor, nullptr,
        sizeof(classDesc) / sizeof(classDesc[0]), classDesc, &constructor);
    napi_create_reference(env, constructor, 1, &classRef_);
}
} // CryptoFramework
} // OHOS