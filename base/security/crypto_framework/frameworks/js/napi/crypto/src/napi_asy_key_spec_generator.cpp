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

#include "napi_asy_key_spec_generator.h"

#include "asy_key_params.h"
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
struct AsyKeyCtx {
    napi_env env = nullptr;

    AsyncType asyncType = ASYNC_CALLBACK;
    napi_ref callback = nullptr;
    napi_deferred deferred = nullptr;
    napi_value promise = nullptr;
    napi_async_work asyncWork = nullptr;
    napi_ref generatorRef = nullptr;

    HcfAsyKeyGeneratorBySpec *generator;
    HcfResult errCode = HCF_SUCCESS;
    const char *errMsg = nullptr;
    HcfKeyPair *returnKeyPair = nullptr;
    HcfPubKey *returnPubKey = nullptr;
    HcfPriKey *returnPriKey = nullptr;
};

thread_local napi_ref NapiAsyKeyGeneratorBySpec::classRef_ = nullptr;

static void FreeAsyKeyCtx(napi_env env, AsyKeyCtx *ctx)
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

static bool BuildAsyKeyCtx(napi_env env, napi_callback_info info, AsyKeyCtx *ctx)
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

    NapiAsyKeyGeneratorBySpec *napiGenerator = nullptr;
    napi_status status = napi_unwrap(env, thisVar, reinterpret_cast<void **>(&napiGenerator));
    if (status != napi_ok || napiGenerator == nullptr) {
        LOGE("failed to unwrap napi asyKeyGenerator obj.");
        return false;
    }
    ctx->generator = napiGenerator->GetAsyKeyGeneratorBySpec();

    if (napi_create_reference(env, thisVar, 1, &ctx->generatorRef) != napi_ok) {
        LOGE("create generator ref failed when generator asym key by spec!");
        return false;
    }

    if (ctx->asyncType == ASYNC_PROMISE) {
        napi_create_promise(env, &ctx->deferred, &ctx->promise);
        return true;
    } else {
        return GetCallbackFromJSParams(env, argv[expectedArgc - 1], &ctx->callback);
    }
}

static bool GetAsyKeyGenerator(napi_env env, napi_callback_info info, HcfAsyKeyGeneratorBySpec **generator)
{
    napi_value thisVar = nullptr;
    napi_get_cb_info(env, info, nullptr, nullptr, &thisVar, nullptr);

    NapiAsyKeyGeneratorBySpec *napiGenerator = nullptr;
    napi_status status = napi_unwrap(env, thisVar, reinterpret_cast<void **>(&napiGenerator));
    if (status != napi_ok || napiGenerator == nullptr) {
        LOGE("failed to unwrap napi asyKeyGenerator obj.");
        return false;
    }
    *generator = napiGenerator->GetAsyKeyGeneratorBySpec();
    return true;
}

static void ReturnAsyKeyCallbackResult(napi_env env, AsyKeyCtx *ctx, napi_value result)
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

static void ReturnAsyKeyPromiseResult(napi_env env, AsyKeyCtx *ctx, napi_value result)
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
    AsyKeyCtx *ctx = static_cast<AsyKeyCtx *>(data);

    ctx->errCode = ctx->generator->generateKeyPair(ctx->generator, &(ctx->returnKeyPair));
    if (ctx->errCode != HCF_SUCCESS) {
        LOGE(" generate key pair fail.");
        ctx->errMsg = "generate key pair fail.";
    }
}

static void GenKeyPairAsyncWorkReturn(napi_env env, napi_status status, void *data)
{
    AsyKeyCtx *ctx = static_cast<AsyKeyCtx *>(data);

    napi_value instance = nullptr;
    if (ctx->errCode == HCF_SUCCESS) {
        NapiKeyPair *napiKeyPair = new (std::nothrow) NapiKeyPair(ctx->returnKeyPair);
        if (napiKeyPair == nullptr) {
            NAPI_LOG_THROW(env, HCF_ERR_MALLOC, "new napi key pair failed!");
            HcfObjDestroy(ctx->returnKeyPair);
            ctx->returnKeyPair = nullptr;
            FreeAsyKeyCtx(env, ctx);
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
        ReturnAsyKeyCallbackResult(env, ctx, instance);
    } else {
        ReturnAsyKeyPromiseResult(env, ctx, instance);
    }
    FreeAsyKeyCtx(env, ctx);
}

static void PubKeyAsyncWorkProcess(napi_env env, void *data)
{
    AsyKeyCtx *ctx = static_cast<AsyKeyCtx *>(data);

    ctx->errCode = ctx->generator->generatePubKey(ctx->generator, &(ctx->returnPubKey));
    if (ctx->errCode != HCF_SUCCESS) {
        LOGE("generate PubKey fail.");
        ctx->errMsg = "generate PubKey fail.";
    }
}

static void PubKeyAsyncWorkReturn(napi_env env, napi_status status, void *data)
{
    AsyKeyCtx *ctx = static_cast<AsyKeyCtx *>(data);

    napi_value instance = nullptr;
    if (ctx->errCode == HCF_SUCCESS) {
        NapiPubKey *napiPubKey = new (std::nothrow) NapiPubKey(ctx->returnPubKey);
        if (napiPubKey == nullptr) {
            NAPI_LOG_THROW(env, HCF_ERR_MALLOC, "new napi pub key failed!");
            HcfObjDestroy(ctx->returnPubKey);
            ctx->returnPubKey = nullptr;
            FreeAsyKeyCtx(env, ctx);
            return;
        }
        instance = napiPubKey->ConvertToJsPubKey(env);

        napi_status ret = napi_wrap(
            env, instance, napiPubKey,
            [](napi_env env, void *data, void *hint) {
                NapiPubKey *napiPubKey = static_cast<NapiPubKey *>(data);
                HcfObjDestroy(napiPubKey->GetPubKey());
                delete napiPubKey;
            }, nullptr, nullptr);
        if (ret != napi_ok) {
            LOGE("failed to wrap napiPubKey obj!");
            ctx->errCode = HCF_INVALID_PARAMS;
            ctx->errMsg = "failed to wrap napiPubKey obj!";
            HcfObjDestroy(napiPubKey->GetPubKey());
            delete napiPubKey;
        }
    }

    if (ctx->asyncType == ASYNC_CALLBACK) {
        ReturnAsyKeyCallbackResult(env, ctx, instance);
    } else {
        ReturnAsyKeyPromiseResult(env, ctx, instance);
    }
    FreeAsyKeyCtx(env, ctx);
}

static void PriKeyAsyncWorkProcess(napi_env env, void *data)
{
    AsyKeyCtx *ctx = static_cast<AsyKeyCtx *>(data);

    ctx->errCode = ctx->generator->generatePriKey(ctx->generator, &(ctx->returnPriKey));
    if (ctx->errCode != HCF_SUCCESS) {
        LOGE("generate PriKey fail.");
        ctx->errMsg = "generate PriKey fail.";
    }
}

static void PriKeyAsyncWorkReturn(napi_env env, napi_status status, void *data)
{
    AsyKeyCtx *ctx = static_cast<AsyKeyCtx *>(data);

    napi_value instance = nullptr;
    if (ctx->errCode == HCF_SUCCESS) {
        NapiPriKey *napiPriKey = new (std::nothrow) NapiPriKey(ctx->returnPriKey);
        if (napiPriKey == nullptr) {
            NAPI_LOG_THROW(env, HCF_ERR_MALLOC, "new napi pri key failed!");
            HcfObjDestroy(ctx->returnPriKey);
            ctx->returnPriKey = nullptr;
            FreeAsyKeyCtx(env, ctx);
            return;
        }
        instance = napiPriKey->ConvertToJsPriKey(env);

        napi_status ret = napi_wrap(
            env, instance, napiPriKey,
            [](napi_env env, void *data, void *hint) {
                NapiPriKey *napiPriKey = static_cast<NapiPriKey *>(data);
                HcfObjDestroy(napiPriKey->GetPriKey());
                delete napiPriKey;
            }, nullptr, nullptr);
        if (ret != napi_ok) {
            LOGE("failed to wrap napiPriKey obj!");
            ctx->errCode = HCF_INVALID_PARAMS;
            ctx->errMsg = "failed to wrap napiPriKey obj!";
            HcfObjDestroy(napiPriKey->GetPriKey());
            delete napiPriKey;
        }
    }

    if (ctx->asyncType == ASYNC_CALLBACK) {
        ReturnAsyKeyCallbackResult(env, ctx, instance);
    } else {
        ReturnAsyKeyPromiseResult(env, ctx, instance);
    }
    FreeAsyKeyCtx(env, ctx);
}

static napi_value NewGenKeyPairAsyncWork(napi_env env, AsyKeyCtx *ctx)
{
    napi_value resourceName = nullptr;
    napi_create_string_utf8(env, "generateKeyPair", NAPI_AUTO_LENGTH, &resourceName);

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

static napi_value NewPubKeyAsyncWork(napi_env env, AsyKeyCtx *ctx)
{
    napi_value resourceName = nullptr;
    napi_create_string_utf8(env, "generatePubKey", NAPI_AUTO_LENGTH, &resourceName);

    napi_create_async_work(
        env, nullptr, resourceName,
        [](napi_env env, void *data) {
            PubKeyAsyncWorkProcess(env, data);
            return;
        },
        [](napi_env env, napi_status status, void *data) {
            PubKeyAsyncWorkReturn(env, status, data);
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

static napi_value NewPriKeyAsyncWork(napi_env env, AsyKeyCtx *ctx)
{
    napi_value resourceName = nullptr;
    napi_create_string_utf8(env, "generatePriKey", NAPI_AUTO_LENGTH, &resourceName);

    napi_create_async_work(
        env, nullptr, resourceName,
        [](napi_env env, void *data) {
            PriKeyAsyncWorkProcess(env, data);
            return;
        },
        [](napi_env env, napi_status status, void *data) {
            PriKeyAsyncWorkReturn(env, status, data);
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

NapiAsyKeyGeneratorBySpec::NapiAsyKeyGeneratorBySpec(HcfAsyKeyGeneratorBySpec *generator)
{
    this->generator_ = generator;
}

NapiAsyKeyGeneratorBySpec::~NapiAsyKeyGeneratorBySpec()
{
    HcfObjDestroy(this->generator_);
    this->generator_ = nullptr;
}

HcfAsyKeyGeneratorBySpec *NapiAsyKeyGeneratorBySpec::GetAsyKeyGeneratorBySpec()
{
    return this->generator_;
}

napi_value NapiAsyKeyGeneratorBySpec::JsGenerateKeyPair(napi_env env, napi_callback_info info)
{
    AsyKeyCtx *ctx = static_cast<AsyKeyCtx *>(HcfMalloc(sizeof(AsyKeyCtx), 0));
    if (ctx == nullptr) {
        NAPI_LOG_THROW(env, HCF_ERR_MALLOC, "create context fail!");
        return nullptr;
    }

    if (!BuildAsyKeyCtx(env, info, ctx)) {
        NAPI_LOG_THROW(env, HCF_INVALID_PARAMS, "build context fail!");
        FreeAsyKeyCtx(env, ctx);
        return nullptr;
    }

    return NewGenKeyPairAsyncWork(env, ctx);
}

napi_value NapiAsyKeyGeneratorBySpec::JsGenerateKeyPairSync(napi_env env, napi_callback_info info)
{
    HcfAsyKeyGeneratorBySpec *generator = nullptr;
    if (!GetAsyKeyGenerator(env, info, &generator) || generator == nullptr) {
        NAPI_LOG_THROW(env, HCF_INVALID_PARAMS, "build generator fail!");
        return nullptr;
    }

    HcfKeyPair *returnKeyPair = nullptr;
    HcfResult errCode = generator->generateKeyPair(generator, &(returnKeyPair));
    if (errCode != HCF_SUCCESS) {
        NAPI_LOG_THROW(env, errCode, "generate key pair fail.");
        return nullptr;
    }

    napi_value instance = nullptr;
    NapiKeyPair *napiKeyPair = new (std::nothrow) NapiKeyPair(returnKeyPair);
    if (napiKeyPair == nullptr) {
        HcfObjDestroy(returnKeyPair);
        returnKeyPair = nullptr;
        NAPI_LOG_THROW(env, HCF_ERR_MALLOC, "new napi key pair failed!");
        return nullptr;
    }

    instance = napiKeyPair->ConvertToJsKeyPair(env);
    napi_status ret = napi_wrap(
        env, instance, napiKeyPair,
        [](napi_env env, void *data, void *hint) {
            delete(static_cast<NapiKeyPair *>(data));
        }, nullptr, nullptr);
    if (ret != napi_ok) {
        delete napiKeyPair;
        NAPI_LOG_THROW(env, HCF_INVALID_PARAMS, "failed to wrap napiKeyPair obj!");
        return nullptr;
    }
    return instance;
}

napi_value NapiAsyKeyGeneratorBySpec::JsGeneratePubKey(napi_env env, napi_callback_info info)
{
    AsyKeyCtx *ctx = static_cast<AsyKeyCtx *>(HcfMalloc(sizeof(AsyKeyCtx), 0));
    if (ctx == nullptr) {
        NAPI_LOG_THROW(env, HCF_ERR_MALLOC, "create context fail!");
        return nullptr;
    }

    if (!BuildAsyKeyCtx(env, info, ctx)) {
        NAPI_LOG_THROW(env, HCF_INVALID_PARAMS, "build context fail!");
        FreeAsyKeyCtx(env, ctx);
        return nullptr;
    }

    return NewPubKeyAsyncWork(env, ctx);
}

napi_value NapiAsyKeyGeneratorBySpec::JsGeneratePubKeySync(napi_env env, napi_callback_info info)
{
    HcfAsyKeyGeneratorBySpec *generator = nullptr;
    if (!GetAsyKeyGenerator(env, info, &generator) || generator == nullptr) {
        NAPI_LOG_THROW(env, HCF_INVALID_PARAMS, "build generator fail!");
        return nullptr;
    }

    HcfPubKey *returnPubKey = nullptr;
    HcfResult errCode = generator->generatePubKey(generator, &(returnPubKey));
    if (errCode != HCF_SUCCESS) {
        NAPI_LOG_THROW(env, errCode, "generate PubKey fail.");
        return nullptr;
    }

    napi_value instance = nullptr;
    NapiPubKey *napiPubKey = new (std::nothrow) NapiPubKey(returnPubKey);
    if (napiPubKey == nullptr) {
        HcfObjDestroy(returnPubKey);
        returnPubKey = nullptr;
        NAPI_LOG_THROW(env, HCF_ERR_MALLOC, "new napi pub key failed!");
        return nullptr;
    }

    instance = napiPubKey->ConvertToJsPubKey(env);
    napi_status ret = napi_wrap(
        env, instance, napiPubKey,
        [](napi_env env, void *data, void *hint) {
            NapiPubKey *napiPubKey = static_cast<NapiPubKey *>(data);
            HcfObjDestroy(napiPubKey->GetPubKey());
            delete napiPubKey;
            return;
        }, nullptr, nullptr);
    if (ret != napi_ok) {
        HcfObjDestroy(napiPubKey->GetPubKey());
        delete napiPubKey;
        NAPI_LOG_THROW(env, HCF_ERR_MALLOC, "failed to wrap napiPubKey obj!");
        return nullptr;
    }

    return instance;
}

napi_value NapiAsyKeyGeneratorBySpec::JsGeneratePriKey(napi_env env, napi_callback_info info)
{
    AsyKeyCtx *ctx = static_cast<AsyKeyCtx *>(HcfMalloc(sizeof(AsyKeyCtx), 0));
    if (ctx == nullptr) {
        NAPI_LOG_THROW(env, HCF_ERR_MALLOC, "create context fail!");
        return nullptr;
    }

    if (!BuildAsyKeyCtx(env, info, ctx)) {
        NAPI_LOG_THROW(env, HCF_INVALID_PARAMS, "build context fail!");
        FreeAsyKeyCtx(env, ctx);
        return nullptr;
    }

    return NewPriKeyAsyncWork(env, ctx);
}

napi_value NapiAsyKeyGeneratorBySpec::JsGeneratePriKeySync(napi_env env, napi_callback_info info)
{
    HcfAsyKeyGeneratorBySpec *generator = nullptr;
    if (!GetAsyKeyGenerator(env, info, &generator) || generator == nullptr) {
        NAPI_LOG_THROW(env, HCF_INVALID_PARAMS, "build generator fail!");
        return nullptr;
    }

    HcfPriKey *returnPriKey = nullptr;
    HcfResult errCode = generator->generatePriKey(generator, &(returnPriKey));
    if (errCode != HCF_SUCCESS) {
        NAPI_LOG_THROW(env, errCode, "generate PriKey fail.");
        return nullptr;
    }

    napi_value instance = nullptr;
    NapiPriKey *napiPriKey = new (std::nothrow) NapiPriKey(returnPriKey);
    if (napiPriKey == nullptr) {
        HcfObjDestroy(returnPriKey);
        returnPriKey = nullptr;
        NAPI_LOG_THROW(env, HCF_ERR_MALLOC, "new napi pri key failed!");
        return nullptr;
    }

    instance = napiPriKey->ConvertToJsPriKey(env);
    napi_status ret = napi_wrap(
        env, instance, napiPriKey,
        [](napi_env env, void *data, void *hint) {
            NapiPriKey *napiPriKey = static_cast<NapiPriKey *>(data);
            HcfObjDestroy(napiPriKey->GetPriKey());
            delete napiPriKey;
        }, nullptr, nullptr);
    if (ret != napi_ok) {
        HcfObjDestroy(napiPriKey->GetPriKey());
        delete napiPriKey;
        NAPI_LOG_THROW(env, HCF_ERR_MALLOC, "failed to wrap napiPriKey obj!");
        return nullptr;
    }

    return instance;
}

napi_value NapiAsyKeyGeneratorBySpec::AsyKeyGeneratorBySpecConstructor(napi_env env, napi_callback_info info)
{
    napi_value thisVar = nullptr;
    napi_get_cb_info(env, info, nullptr, nullptr, &thisVar, nullptr);
    return thisVar;
}

napi_value NapiAsyKeyGeneratorBySpec::CreateJsAsyKeyGeneratorBySpec(napi_env env, napi_callback_info info)
{
    size_t argc = PARAMS_NUM_ONE;
    napi_value argv[PARAMS_NUM_ONE] = { nullptr };
    napi_get_cb_info(env, info, &argc, argv, nullptr, nullptr);

    if (argc != PARAMS_NUM_ONE) {
        NAPI_LOG_THROW(env, HCF_INVALID_PARAMS, "The input args num is invalid.");
        return nullptr;
    }

    napi_value instance;
    napi_value constructor = nullptr;
    napi_get_reference_value(env, classRef_, &constructor);
    napi_new_instance(env, constructor, argc, argv, &instance);

    HcfAsyKeyParamsSpec *asyKeySpec = nullptr;
    if (!GetAsyKeySpecFromNapiValue(env, argv[0], &asyKeySpec)) {
        NAPI_LOG_THROW(env, HCF_INVALID_PARAMS, "failed to get valid asyKeySpec!");
        return nullptr;
    }
    HcfAsyKeyGeneratorBySpec *generator = nullptr;
    HcfResult res = HcfAsyKeyGeneratorBySpecCreate(asyKeySpec, &generator);
    FreeAsyKeySpec(asyKeySpec);
    asyKeySpec = nullptr;
    if (res != HCF_SUCCESS) {
        NAPI_LOG_THROW(env, res, "create C generator by sepc fail.");
        return nullptr;
    }

    NapiAsyKeyGeneratorBySpec *napiAsyKeyGeneratorBySpec = new (std::nothrow) NapiAsyKeyGeneratorBySpec(generator);
    if (napiAsyKeyGeneratorBySpec == nullptr) {
        NAPI_LOG_THROW(env, HCF_ERR_MALLOC, "new napi asy key generator by spec failed!");
        HcfObjDestroy(generator);
        generator = nullptr;
        return nullptr;
    }

    napi_status status = napi_wrap(env, instance, napiAsyKeyGeneratorBySpec,
        [](napi_env env, void *data, void *hint) {
            delete(static_cast<NapiAsyKeyGeneratorBySpec *>(data));
        }, nullptr, nullptr);
    if (status != napi_ok) {
        NAPI_LOG_THROW(env, HCF_INVALID_PARAMS, "wrap napiAsyKeyGeneratorBySpec failed!");
        delete napiAsyKeyGeneratorBySpec;
        return nullptr;
    }
    return instance;
}

napi_value NapiAsyKeyGeneratorBySpec::JsGetAlgorithm(napi_env env, napi_callback_info info)
{
    napi_value thisVar = nullptr;
    NapiAsyKeyGeneratorBySpec *napiAsyKeyGeneratorBySpec = nullptr;
    napi_get_cb_info(env, info, nullptr, nullptr, &thisVar, nullptr);
    napi_status status = napi_unwrap(env, thisVar, reinterpret_cast<void **>(&napiAsyKeyGeneratorBySpec));
    if (status != napi_ok || napiAsyKeyGeneratorBySpec == nullptr) {
        NAPI_LOG_THROW(env, HCF_INVALID_PARAMS, "failed to unwrap napi asyKeyGenerator obj.");
        return nullptr;
    }
    HcfAsyKeyGeneratorBySpec *generator = napiAsyKeyGeneratorBySpec->GetAsyKeyGeneratorBySpec();
    if (generator == nullptr) {
        NAPI_LOG_THROW(env, HCF_INVALID_PARAMS, "fail to get generator by spec obj!");
        return nullptr;
    }

    const char *algo = generator->getAlgName(generator);
    napi_value instance = nullptr;
    napi_create_string_utf8(env, algo, NAPI_AUTO_LENGTH, &instance);
    return instance;
}

void NapiAsyKeyGeneratorBySpec::DefineAsyKeyGeneratorBySpecJSClass(napi_env env, napi_value exports)
{
    napi_property_descriptor desc[] = {
        DECLARE_NAPI_FUNCTION("createAsyKeyGeneratorBySpec", NapiAsyKeyGeneratorBySpec::CreateJsAsyKeyGeneratorBySpec),
    };
    napi_define_properties(env, exports, sizeof(desc) / sizeof(desc[0]), desc);

    napi_property_descriptor classDesc[] = {
        DECLARE_NAPI_FUNCTION("generateKeyPair", NapiAsyKeyGeneratorBySpec::JsGenerateKeyPair),
        DECLARE_NAPI_FUNCTION("generateKeyPairSync", NapiAsyKeyGeneratorBySpec::JsGenerateKeyPairSync),
        DECLARE_NAPI_FUNCTION("generatePriKey", NapiAsyKeyGeneratorBySpec::JsGeneratePriKey),
        DECLARE_NAPI_FUNCTION("generatePriKeySync", NapiAsyKeyGeneratorBySpec::JsGeneratePriKeySync),
        DECLARE_NAPI_FUNCTION("generatePubKey", NapiAsyKeyGeneratorBySpec::JsGeneratePubKey),
        DECLARE_NAPI_FUNCTION("generatePubKeySync", NapiAsyKeyGeneratorBySpec::JsGeneratePubKeySync),
        { .utf8name = "algName", .getter = NapiAsyKeyGeneratorBySpec::JsGetAlgorithm },
    };
    napi_value constructor = nullptr;
    napi_define_class(env, "AsyKeyGeneratorBySpec", NAPI_AUTO_LENGTH,
        NapiAsyKeyGeneratorBySpec::AsyKeyGeneratorBySpecConstructor,
        nullptr, sizeof(classDesc) / sizeof(classDesc[0]), classDesc, &constructor);
    napi_create_reference(env, constructor, 1, &classRef_);
}
} // CryptoFramework
} // OHOS
