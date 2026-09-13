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

#include "napi_rand.h"

#include "securec.h"
#include "log.h"
#include "memory.h"

#include "napi_utils.h"
#include "napi_crypto_framework_defines.h"

namespace OHOS {
namespace CryptoFramework {
thread_local napi_ref NapiRand::classRef_ = nullptr;

struct RandCtx {
    napi_env env = nullptr;

    AsyncType asyncType = ASYNC_CALLBACK;
    napi_ref callback = nullptr;
    napi_deferred deferred = nullptr;
    napi_value promise = nullptr;
    napi_async_work asyncWork = nullptr;
    napi_ref randomRef = nullptr;

    int32_t numBytes = 0;
    HcfBlob *seedBlob = nullptr;

    HcfResult errCode = HCF_SUCCESS;
    const char *errMsg = nullptr;
    HcfBlob *randBlob = nullptr;
    HcfRand *rand = nullptr;
};

static void FreeCryptoFwkCtx(napi_env env, RandCtx *context)
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
    if (context->randomRef != nullptr) {
        napi_delete_reference(env, context->randomRef);
        context->randomRef = nullptr;
    }
    if (context->seedBlob != nullptr) {
        HcfFree(context->seedBlob->data);
        context->seedBlob->data = nullptr;
        context->seedBlob->len = 0;
        HcfFree(context->seedBlob);
        context->seedBlob = nullptr;
    }
    if (context->randBlob != nullptr) {
        HcfFree(context->randBlob->data);
        context->randBlob->data = nullptr;
        context->randBlob->len = 0;
        HcfFree(context->randBlob);
        context->randBlob = nullptr;
    }
    context->errMsg = nullptr;
    context->rand = nullptr;
    HcfFree(context);
}

static void ReturnCallbackResult(napi_env env, RandCtx *context, napi_value result)
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

static void ReturnPromiseResult(napi_env env, RandCtx *context, napi_value result)
{
    if (context->errCode == HCF_SUCCESS) {
        napi_resolve_deferred(env, context->deferred, result);
    } else {
        napi_reject_deferred(env, context->deferred,
            GenerateBusinessError(env, context->errCode, context->errMsg));
    }
}

static void GenerateRandomExecute(napi_env env, void *data)
{
    RandCtx *context = static_cast<RandCtx *>(data);
    HcfRand *randObj = context->rand;
    HcfBlob *randBlob = reinterpret_cast<HcfBlob *>(HcfMalloc(sizeof(HcfBlob), 0));
    if (randBlob == nullptr) {
        LOGE("randBlob is null!");
        context->errCode = HCF_ERR_MALLOC;
        context->errMsg = "malloc data blob failed";
        return;
    }
    int32_t numBytes = context->numBytes;
    context->errCode = randObj->generateRandom(randObj, numBytes, randBlob);
    if (context->errCode != HCF_SUCCESS) {
        LOGE("GenerateRandom failed!");
        context->errMsg = "generateRandom failed";
        HcfFree(randBlob);
        randBlob = nullptr;
        return;
    }
    context->randBlob = randBlob;
}

static void GenerateRandomComplete(napi_env env, napi_status status, void *data)
{
    RandCtx *context = static_cast<RandCtx *>(data);
    napi_value returnRandBlob = ConvertBlobToNapiValue(env, context->randBlob);
    if (returnRandBlob == nullptr) {
        LOGE("returnOutBlob is nullptr!");
        returnRandBlob = NapiGetNull(env);
    }
    if (context->asyncType == ASYNC_CALLBACK) {
        ReturnCallbackResult(env, context, returnRandBlob);
    } else {
        ReturnPromiseResult(env, context, returnRandBlob);
    }
    FreeCryptoFwkCtx(env, context);
}

static bool BuildGenerateRandomCtx(napi_env env, napi_callback_info info, RandCtx *context)
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

    if (!GetInt32FromJSParams(env, argv[PARAM0], context->numBytes)) {
        LOGE("get numBytes failed!");
        return false;
    }
    context->asyncType = isCallback(env, argv[expectedArgsCount - 1], argc, expectedArgsCount) ?
        ASYNC_CALLBACK : ASYNC_PROMISE;

    NapiRand *napiRand = nullptr;
    napi_status status = napi_unwrap(env, thisVar, reinterpret_cast<void **>(&napiRand));
    if (status != napi_ok || napiRand == nullptr) {
        LOGE("failed to unwrap NapiRand obj!");
        return false;
    }

    context->rand = napiRand->GetRand();

    if (napi_create_reference(env, thisVar, 1, &context->randomRef) != napi_ok) {
        LOGE("create random ref failed when generate random!");
        return false;
    }

    if (context->asyncType == ASYNC_PROMISE) {
        napi_create_promise(env, &context->deferred, &context->promise);
        return true;
    } else {
        return GetCallbackFromJSParams(env, argv[PARAM1], &context->callback);
    }
}

static napi_value NewRandJsGenerateAsyncWork(napi_env env, RandCtx *context)
{
    napi_create_async_work(
        env, nullptr, GetResourceName(env, "GenerateRandom"),
        [](napi_env env, void *data) {
            GenerateRandomExecute(env, data);
            return;
        },
        [](napi_env env, napi_status status, void *data) {
            GenerateRandomComplete(env, status, data);
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

NapiRand::NapiRand(HcfRand *randObj)
{
    this->randObj_ = randObj;
}

NapiRand::~NapiRand()
{
    HcfObjDestroy(this->randObj_);
    this->randObj_ = nullptr;
}

HcfRand *NapiRand::GetRand()
{
    return this->randObj_;
}

napi_value NapiRand::JsGenerateRandom(napi_env env, napi_callback_info info)
{
    RandCtx *context = static_cast<RandCtx *>(HcfMalloc(sizeof(RandCtx), 0));
    if (context == nullptr) {
        NAPI_LOG_THROW(env, HCF_ERR_MALLOC, "malloc context failed");
        return nullptr;
    }

    if (!BuildGenerateRandomCtx(env, info, context)) {
        NAPI_LOG_THROW(env, HCF_INVALID_PARAMS, "build context fail.");
        FreeCryptoFwkCtx(env, context);
        return nullptr;
    }

    return NewRandJsGenerateAsyncWork(env, context);
}

napi_value NapiRand::JsGenerateRandomSync(napi_env env, napi_callback_info info)
{
    napi_value thisVar = nullptr;
    NapiRand *napiRand = nullptr;
    size_t expectedArgsCount = ARGS_SIZE_ONE;
    size_t argc = expectedArgsCount;
    napi_value argv[ARGS_SIZE_ONE] = { nullptr };

    napi_get_cb_info(env, info, &argc, argv, &thisVar, nullptr);
    if (argc != expectedArgsCount) {
        NAPI_LOG_THROW(env, HCF_INVALID_PARAMS, "invalid params count");
        return nullptr;
    }

    int32_t numBytes = 0;
    if (!GetInt32FromJSParams(env, argv[PARAM0], numBytes)) {
        NAPI_LOG_THROW(env, HCF_INVALID_PARAMS, "get numBytes failed!");
        return nullptr;
    }
    napi_status status = napi_unwrap(env, thisVar, reinterpret_cast<void **>(&napiRand));
    if (status != napi_ok || napiRand == nullptr) {
        NAPI_LOG_THROW(env, HCF_INVALID_PARAMS, "failed to unwrap NapiRand obj!");
        return nullptr;
    }
    HcfRand *rand = napiRand->GetRand();
    if (rand == nullptr) {
        NAPI_LOG_THROW(env, HCF_INVALID_PARAMS, "fail to get rand obj!");
        return nullptr;
    }

    HcfBlob randBlob = { .data = nullptr, .len = 0};
    HcfResult res = rand->generateRandom(rand, numBytes, &randBlob);
    if (res != HCF_SUCCESS) {
        NAPI_LOG_THROW(env, res, "generateRandom failed!");
        return nullptr;
    }

    napi_value instance = ConvertBlobToNapiValue(env, &randBlob);
    HcfBlobDataClearAndFree(&randBlob);
    return instance;
}

napi_value NapiRand::JsSetSeed(napi_env env, napi_callback_info info)
{
    napi_value thisVar = nullptr;
    NapiRand *napiRand = nullptr;
    size_t argc = ARGS_SIZE_ONE;
    napi_value argv[ARGS_SIZE_ONE] = { nullptr };

    napi_get_cb_info(env, info, &argc, argv, &thisVar, nullptr);
    if (argc != ARGS_SIZE_ONE) {
        NAPI_LOG_THROW(env, HCF_INVALID_PARAMS, "invalid params count");
        return nullptr;
    }
    HcfBlob *seedBlob = GetBlobFromNapiDataBlob(env, argv[PARAM0]);
    if (seedBlob == nullptr) {
        NAPI_LOG_THROW(env, HCF_INVALID_PARAMS, "failed to get seedBlob!");
        return nullptr;
    }
    napi_status status = napi_unwrap(env, thisVar, reinterpret_cast<void **>(&napiRand));
    if (status != napi_ok || napiRand == nullptr) {
        HcfBlobDataClearAndFree(seedBlob);
        HCF_FREE_PTR(seedBlob);
        NAPI_LOG_THROW(env, HCF_INVALID_PARAMS, "failed to unwrap NapiRand obj!");
        return nullptr;
    }
    HcfRand *rand = napiRand->GetRand();
    if (rand == nullptr) {
        HcfBlobDataClearAndFree(seedBlob);
        HCF_FREE_PTR(seedBlob);
        NAPI_LOG_THROW(env, HCF_INVALID_PARAMS, "fail to get rand obj!");
        return nullptr;
    }
    HcfResult res = rand->setSeed(rand, seedBlob);
    if (res != HCF_SUCCESS) {
        HcfBlobDataClearAndFree(seedBlob);
        HcfFree(seedBlob);
        seedBlob = nullptr;
        NAPI_LOG_THROW(env, res, "set seed failed.");
        return nullptr;
    }
    HcfBlobDataClearAndFree(seedBlob);
    HCF_FREE_PTR(seedBlob);
    return thisVar;
}

napi_value NapiRand::JsEnableHardwareEntropy(napi_env env, napi_callback_info info)
{
    napi_value thisVar = nullptr;
    napi_get_cb_info(env, info, nullptr, nullptr, &thisVar, nullptr);
    NapiRand *napiRand = nullptr;
    napi_status status = napi_unwrap(env, thisVar, reinterpret_cast<void **>(&napiRand));
    if (status != napi_ok || napiRand == nullptr) {
        NAPI_LOG_THROW(env, HCF_ERR_NAPI, "failed to unwrap NapiRand obj!");
        return nullptr;
    }
    HcfRand *rand = napiRand->GetRand();
    if (rand == nullptr) {
        NAPI_LOG_THROW(env, HCF_ERR_NAPI, "fail to get rand obj!");
        return nullptr;
    }
    HcfResult res = rand->enableHardwareEntropy(rand);
    if (res != HCF_SUCCESS) {
        NAPI_LOG_THROW(env, res, "enable hardware entropy failed.");
        return nullptr;
    }
    return thisVar;
}

napi_value NapiRand::JsGetAlgorithm(napi_env env, napi_callback_info info)
{
    napi_value thisVar = nullptr;
    NapiRand *napiRand = nullptr;

    napi_get_cb_info(env, info, nullptr, nullptr, &thisVar, nullptr);
    napi_status status = napi_unwrap(env, thisVar, reinterpret_cast<void **>(&napiRand));
    if (status != napi_ok || napiRand == nullptr) {
        NAPI_LOG_THROW(env, HCF_INVALID_PARAMS, "failed to unwrap NapiRand obj!");
        return nullptr;
    }

    HcfRand *rand = napiRand->GetRand();
    if (rand == nullptr) {
        NAPI_LOG_THROW(env, HCF_INVALID_PARAMS, "fail to get rand obj!");
        return nullptr;
    }

    const char *algoName = rand->getAlgoName(rand);
    napi_value instance = nullptr;
    napi_create_string_utf8(env, algoName, NAPI_AUTO_LENGTH, &instance);
    return instance;
}

napi_value NapiRand::RandConstructor(napi_env env, napi_callback_info info)
{
    napi_value thisVar = nullptr;
    napi_get_cb_info(env, info, nullptr, nullptr, &thisVar, nullptr);
    return thisVar;
}

napi_value NapiRand::CreateRand(napi_env env, napi_callback_info info)
{
    HcfRand *randObj = nullptr;
    HcfResult res = HcfRandCreate(&randObj);
    if (res != HCF_SUCCESS) {
        NAPI_LOG_THROW(env, res, "create C obj failed.");
        return nullptr;
    }
    napi_value instance = nullptr;
    napi_value constructor = nullptr;
    napi_get_reference_value(env, classRef_, &constructor);
    napi_new_instance(env, constructor, 0, nullptr, &instance);
    NapiRand *randNapiObj = new (std::nothrow) NapiRand(randObj);
    if (randNapiObj == nullptr) {
        HcfObjDestroy(randObj);
        randObj = nullptr;
        NAPI_LOG_THROW(env, HCF_ERR_MALLOC, "new rand napi obj failed.");
        return nullptr;
    }
    napi_status status = napi_wrap(
        env, instance, randNapiObj,
        [](napi_env env, void *data, void *hint) {
            delete(static_cast<NapiRand *>(data));
        }, nullptr, nullptr);
    if (status != napi_ok) {
        delete randNapiObj;
        NAPI_LOG_THROW(env, HCF_INVALID_PARAMS, "failed to wrap NapiRand obj!");
        return nullptr;
    }
    return instance;
}

void NapiRand::DefineRandJSClass(napi_env env, napi_value exports)
{
    napi_property_descriptor desc[] = {
        DECLARE_NAPI_FUNCTION("createRandom", NapiRand::CreateRand),
    };
    napi_define_properties(env, exports, sizeof(desc) / sizeof(desc[0]), desc);
    napi_property_descriptor classDesc[] = {
        DECLARE_NAPI_FUNCTION("generateRandom", NapiRand::JsGenerateRandom),
        DECLARE_NAPI_FUNCTION("generateRandomSync", NapiRand::JsGenerateRandomSync),
        DECLARE_NAPI_FUNCTION("setSeed", NapiRand::JsSetSeed),
        DECLARE_NAPI_FUNCTION("enableHardwareEntropy", NapiRand::JsEnableHardwareEntropy),
        {.utf8name = "algName", .getter = NapiRand::JsGetAlgorithm},
    };
    napi_value constructor = nullptr;
    napi_define_class(env, "Random", NAPI_AUTO_LENGTH, RandConstructor, nullptr,
        sizeof(classDesc) / sizeof(classDesc[0]), classDesc, &constructor);
    napi_create_reference(env, constructor, 1, &classRef_);
}
} // CryptoFramework
} // OHOS
