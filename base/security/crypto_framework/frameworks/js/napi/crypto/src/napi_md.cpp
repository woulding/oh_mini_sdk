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

#include "napi_md.h"

#include "securec.h"
#include "log.h"
#include "memory.h"

#include "napi_utils.h"
#include "napi_crypto_framework_defines.h"

namespace OHOS {
namespace CryptoFramework {
thread_local napi_ref NapiMd::classRef_ = nullptr;

struct MdCtx {
    napi_env env = nullptr;

    AsyncType asyncType = ASYNC_CALLBACK;
    napi_ref callback = nullptr;
    napi_deferred deferred = nullptr;
    napi_value promise = nullptr;
    napi_ref mdRef = nullptr;

    napi_async_work asyncWork = nullptr;

    std::string algoName = "";
    HcfBlob *inBlob = nullptr;

    HcfResult errCode = HCF_SUCCESS;
    const char *errMsg = nullptr;
    HcfBlob *outBlob = nullptr;
    HcfMd *md = nullptr;
};

static void FreeCryptoFwkCtx(napi_env env, MdCtx *context)
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
    if (context->mdRef != nullptr) {
        napi_delete_reference(env, context->mdRef);
        context->mdRef = nullptr;
    }
    if (context->inBlob != nullptr) {
        HcfFree(context->inBlob->data);
        context->inBlob->data = nullptr;
        context->inBlob->len = 0;
        HcfFree(context->inBlob);
        context->inBlob = nullptr;
    }
    if (context->outBlob != nullptr) {
        HcfFree(context->outBlob->data);
        context->outBlob->data = nullptr;
        context->outBlob->len = 0;
        HcfFree(context->outBlob);
        context->outBlob = nullptr;
    }
    context->errMsg = nullptr;
    context->md = nullptr;
    HcfFree(context);
}

static void ReturnCallbackResult(napi_env env, MdCtx *context, napi_value result)
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

static void ReturnPromiseResult(napi_env env, MdCtx *context, napi_value result)
{
    if (context->errCode == HCF_SUCCESS) {
        napi_resolve_deferred(env, context->deferred, result);
    } else {
        napi_reject_deferred(env, context->deferred,
            GenerateBusinessError(env, context->errCode, context->errMsg));
    }
}

static void MdUpdateExecute(napi_env env, void *data)
{
    MdCtx *context = static_cast<MdCtx *>(data);
    HcfMd *mdObj = context->md;
    context->errCode = mdObj->update(mdObj, context->inBlob);
    if (context->errCode != HCF_SUCCESS) {
        LOGE("update failed!");
        context->errMsg = "update failed";
    }
}

static void MdDoFinalExecute(napi_env env, void *data)
{
    MdCtx *context = static_cast<MdCtx *>(data);
    HcfMd *mdObj = context->md;
    HcfBlob *outBlob = reinterpret_cast<HcfBlob *>(HcfMalloc(sizeof(HcfBlob), 0));
    if (outBlob == nullptr) {
        LOGE("outBlob is null!");
        context->errCode = HCF_ERR_MALLOC;
        context->errMsg = "malloc data blob failed";
        return;
    }
    context->errCode = mdObj->doFinal(mdObj, outBlob);
    if (context->errCode != HCF_SUCCESS) {
        HcfFree(outBlob);
        outBlob = nullptr;
        LOGE("doFinal failed!");
        context->errMsg = "doFinal failed";
        return;
    }
    context->outBlob = outBlob;
}

static void MdUpdateComplete(napi_env env, napi_status status, void *data)
{
    MdCtx *context = static_cast<MdCtx *>(data);
    napi_value nullInstance = nullptr;
    napi_get_null(env, &nullInstance);
    if (context->asyncType == ASYNC_CALLBACK) {
        ReturnCallbackResult(env, context, nullInstance);
    } else {
        ReturnPromiseResult(env, context, nullInstance);
    }
    FreeCryptoFwkCtx(env, context);
}

static void MdDoFinalComplete(napi_env env, napi_status status, void *data)
{
    MdCtx *context = static_cast<MdCtx *>(data);
    napi_value returnOutBlob = ConvertBlobToNapiValue(env, context->outBlob);
    if (returnOutBlob == nullptr) {
        LOGE("returnOutBlob is nullptr!");
        returnOutBlob = NapiGetNull(env);
    }
    if (context->asyncType == ASYNC_CALLBACK) {
        ReturnCallbackResult(env, context, returnOutBlob);
    } else {
        ReturnPromiseResult(env, context, returnOutBlob);
    }
    FreeCryptoFwkCtx(env, context);
}

static bool BuildMdJsUpdateCtx(napi_env env, napi_callback_info info, MdCtx *context)
{
    napi_value thisVar = nullptr;
    NapiMd *napiMd = nullptr;
    size_t expectedArgsCount = ARGS_SIZE_TWO;
    size_t argc = expectedArgsCount;
    napi_value argv[ARGS_SIZE_TWO] = { nullptr };
    napi_get_cb_info(env, info, &argc, argv, &thisVar, nullptr);
    if (!CheckArgsCount(env, argc, ARGS_SIZE_TWO, false)) {
        return false;
    }

    context->asyncType = isCallback(env, argv[expectedArgsCount - 1], argc, expectedArgsCount) ?
        ASYNC_CALLBACK : ASYNC_PROMISE;
    context->inBlob = GetBlobFromNapiDataBlob(env, argv[PARAM0]);
    if (context->inBlob == nullptr) {
        LOGE("inBlob is null!");
        return false;
    }
    napi_status status = napi_unwrap(env, thisVar, reinterpret_cast<void **>(&napiMd));
    if (status != napi_ok || napiMd == nullptr) {
        LOGE("failed to unwrap NapiMd obj!");
        return false;
    }

    context->md = napiMd->GetMd();

    if (napi_create_reference(env, thisVar, 1, &context->mdRef) != napi_ok) {
        LOGE("create md ref failed when do md update!");
        return false;
    }

    if (context->asyncType == ASYNC_PROMISE) {
        napi_create_promise(env, &context->deferred, &context->promise);
        return true;
    } else {
        return GetCallbackFromJSParams(env, argv[PARAM1], &context->callback);
    }
}

static bool BuildMdJsDoFinalCtx(napi_env env, napi_callback_info info, MdCtx *context)
{
    napi_value thisVar = nullptr;
    NapiMd *napiMd = nullptr;
    size_t expectedArgsCount = ARGS_SIZE_ONE;
    size_t argc = expectedArgsCount;
    napi_value argv[ARGS_SIZE_ONE] = { nullptr };
    napi_get_cb_info(env, info, &argc, argv, &thisVar, nullptr);
    if (!CheckArgsCount(env, argc, ARGS_SIZE_ONE, false)) {
        return false;
    }

    context->asyncType = isCallback(env, argv[expectedArgsCount - 1], argc, expectedArgsCount) ?
        ASYNC_CALLBACK : ASYNC_PROMISE;

    napi_status status = napi_unwrap(env, thisVar, reinterpret_cast<void **>(&napiMd));
    if (status != napi_ok || napiMd == nullptr) {
        LOGE("failed to unwrap NapiMd obj!");
        return false;
    }

    context->md = napiMd->GetMd();

    if (napi_create_reference(env, thisVar, 1, &context->mdRef) != napi_ok) {
        LOGE("create md ref failed when do md final!");
        return false;
    }

    if (context->asyncType == ASYNC_PROMISE) {
        napi_create_promise(env, &context->deferred, &context->promise);
        return true;
    } else {
        return GetCallbackFromJSParams(env, argv[PARAM0], &context->callback);
    }
}

static napi_value NewMdJsUpdateAsyncWork(napi_env env, MdCtx *context)
{
    napi_create_async_work(
        env, nullptr, GetResourceName(env, "MdUpdate"),
        [](napi_env env, void *data) {
            MdUpdateExecute(env, data);
            return;
        },
        [](napi_env env, napi_status status, void *data) {
            MdUpdateComplete(env, status, data);
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

static napi_value NewMdJsDoFinalAsyncWork(napi_env env, MdCtx *context)
{
    napi_create_async_work(
        env, nullptr, GetResourceName(env, "MdDoFinal"),
        [](napi_env env, void *data) {
            MdDoFinalExecute(env, data);
            return;
        },
        [](napi_env env, napi_status status, void *data) {
            MdDoFinalComplete(env, status, data);
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

NapiMd::NapiMd(HcfMd *mdObj)
{
    this->mdObj_ = mdObj;
}

NapiMd::~NapiMd()
{
    HcfObjDestroy(this->mdObj_);
    this->mdObj_ = nullptr;
}

HcfMd *NapiMd::GetMd()
{
    return this->mdObj_;
}

napi_value NapiMd::JsMdUpdate(napi_env env, napi_callback_info info)
{
    MdCtx *context = static_cast<MdCtx *>(HcfMalloc(sizeof(MdCtx), 0));
    if (context == nullptr) {
        NAPI_LOG_THROW(env, HCF_ERR_MALLOC, "malloc context failed");
        return nullptr;
    }

    if (!BuildMdJsUpdateCtx(env, info, context)) {
        NAPI_LOG_THROW(env, HCF_INVALID_PARAMS, "build context fail.");
        FreeCryptoFwkCtx(env, context);
        return nullptr;
    }

    return NewMdJsUpdateAsyncWork(env, context);
}

napi_value NapiMd::JsMdUpdateSync(napi_env env, napi_callback_info info)
{
    napi_value thisVar = nullptr;
    NapiMd *napiMd = nullptr;
    size_t expectedArgsCount = ARGS_SIZE_ONE;
    size_t argc = expectedArgsCount;
    napi_value argv[ARGS_SIZE_ONE] = { nullptr };
    napi_get_cb_info(env, info, &argc, argv, &thisVar, nullptr);
    if (argc != expectedArgsCount) {
        NAPI_LOG_THROW(env, HCF_INVALID_PARAMS, "invalid parameters.");
        return nullptr;
    }
    HcfBlob *inBlob = GetBlobFromNapiDataBlob(env, argv[PARAM0]);
    if (inBlob == nullptr) {
        NAPI_LOG_THROW(env, HCF_INVALID_PARAMS, "invalid parameters.");
        return nullptr;
    }
    napi_status status = napi_unwrap(env, thisVar, reinterpret_cast<void **>(&napiMd));
    if (status != napi_ok || napiMd == nullptr) {
        NAPI_LOG_THROW(env, HCF_INVALID_PARAMS, "invalid parameters.");
        HcfBlobDataClearAndFree(inBlob);
        HCF_FREE_PTR(inBlob);
        return nullptr;
    }
    HcfMd *md = napiMd->GetMd();
    if (md == nullptr) {
        NAPI_LOG_THROW(env, HCF_INVALID_PARAMS, "md is nullptr!");
        HcfBlobDataClearAndFree(inBlob);
        HCF_FREE_PTR(inBlob);
        return nullptr;
    }
    HcfResult errCode = md->update(md, inBlob);
    if (errCode != HCF_SUCCESS) {
        NAPI_LOG_THROW(env, HCF_ERR_CRYPTO_OPERATION, "crypto operation error.");
        HcfBlobDataClearAndFree(inBlob);
        HCF_FREE_PTR(inBlob);
        return nullptr;
    }
    napi_value nullInstance = nullptr;
    napi_get_null(env, &nullInstance);
    HcfBlobDataClearAndFree(inBlob);
    HCF_FREE_PTR(inBlob);
    return nullInstance;
}

napi_value NapiMd::JsMdDoFinal(napi_env env, napi_callback_info info)
{
    MdCtx *context = static_cast<MdCtx *>(HcfMalloc(sizeof(MdCtx), 0));
    if (context == nullptr) {
        NAPI_LOG_THROW(env, HCF_ERR_MALLOC, "malloc context failed");
        return nullptr;
    }

    if (!BuildMdJsDoFinalCtx(env, info, context)) {
        NAPI_LOG_THROW(env, HCF_INVALID_PARAMS, "build context fail.");
        FreeCryptoFwkCtx(env, context);
        return nullptr;
    }

    return NewMdJsDoFinalAsyncWork(env, context);
}

napi_value NapiMd::JsMdDoFinalSync(napi_env env, napi_callback_info info)
{
    NapiMd *napiMd = nullptr;
    napi_value thisVar = nullptr;
    napi_get_cb_info(env, info, nullptr, nullptr, &thisVar, nullptr);

    napi_status status = napi_unwrap(env, thisVar, reinterpret_cast<void **>(&napiMd));
    if (status != napi_ok || napiMd == nullptr) {
        NAPI_LOG_THROW(env, HCF_ERR_NAPI, "failed to unwrap NapiMd obj!");
        return nullptr;
    }

    HcfMd *md = napiMd->GetMd();
    if (md == nullptr) {
        NAPI_LOG_THROW(env, HCF_INVALID_PARAMS, "md is nullptr!");
        return nullptr;
    }

    HcfBlob outBlob = { .data = nullptr, .len = 0 };
    HcfResult errCode = md->doFinal(md, &outBlob);
    if (errCode != HCF_SUCCESS) {
        NAPI_LOG_THROW(env, errCode, "md doFinal failed!");
        HcfBlobDataClearAndFree(&outBlob);
        return nullptr;
    }

    napi_value instance = nullptr;
    errCode = ConvertDataBlobToNapiValue(env, &outBlob, &instance);
    HcfBlobDataClearAndFree(&outBlob);
    if (errCode != HCF_SUCCESS) {
        NAPI_LOG_THROW(env, errCode, "md convert dataBlob to napi_value failed!");
        return nullptr;
    }
    return instance;
}

napi_value NapiMd::JsGetMdLength(napi_env env, napi_callback_info info)
{
    napi_value thisVar = nullptr;
    NapiMd *napiMd = nullptr;

    napi_get_cb_info(env, info, nullptr, nullptr, &thisVar, nullptr);

    napi_status status = napi_unwrap(env, thisVar, reinterpret_cast<void **>(&napiMd));
    if (status != napi_ok || napiMd == nullptr) {
        NAPI_LOG_THROW(env, HCF_INVALID_PARAMS, "failed to unwrap NapiMd obj!");
        return nullptr;
    }

    HcfMd *md = napiMd->GetMd();
    if (md == nullptr) {
        NAPI_LOG_THROW(env, HCF_INVALID_PARAMS, "fail to get md obj!");
        return nullptr;
    }

    uint32_t retLen = md->getMdLength(md);
    napi_value napiLen = nullptr;
    napi_create_uint32(env, retLen, &napiLen);
    return napiLen;
}

napi_value NapiMd::MdConstructor(napi_env env, napi_callback_info info)
{
    napi_value thisVar = nullptr;
    napi_get_cb_info(env, info, nullptr, nullptr, &thisVar, nullptr);
    return thisVar;
}

static napi_value NapiWrapMd(napi_env env, napi_value instance, NapiMd *mdNapiObj)
{
    napi_status status = napi_wrap(
        env, instance, mdNapiObj,
        [](napi_env env, void *data, void *hint) {
            delete(static_cast<NapiMd *>(data));
        }, nullptr, nullptr);
    if (status != napi_ok) {
        delete mdNapiObj;
        NAPI_LOG_THROW(env, HCF_INVALID_PARAMS, "failed to wrap NapiMd obj!");
        return nullptr;
    }
    return instance;
}

napi_value NapiMd::CreateMd(napi_env env, napi_callback_info info)
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
    HcfMd *mdObj = nullptr;
    HcfResult res = HcfMdCreate(algoName.c_str(), &mdObj);
    if (res != HCF_SUCCESS) {
        NAPI_LOG_THROW(env, res, "create C obj failed.");
        return nullptr;
    }
    napi_value napiAlgName = nullptr;
    napi_create_string_utf8(env, algoName.c_str(), NAPI_AUTO_LENGTH, &napiAlgName);
    napi_value instance = nullptr;
    napi_value constructor = nullptr;
    napi_get_reference_value(env, classRef_, &constructor);
    napi_new_instance(env, constructor, argc, argv, &instance);
    napi_set_named_property(env, instance, CRYPTO_TAG_ALG_NAME.c_str(), napiAlgName);
    NapiMd *mdNapiObj = new (std::nothrow) NapiMd(mdObj);
    if (mdNapiObj == nullptr) {
        HcfObjDestroy(mdObj);
        mdObj = nullptr;
        NAPI_LOG_THROW(env, HCF_ERR_MALLOC, "new md napi obj failed!");
        return nullptr;
    }

    return NapiWrapMd(env, instance, mdNapiObj);
}

void NapiMd::DefineMdJSClass(napi_env env, napi_value exports)
{
    napi_property_descriptor desc[] = {
        DECLARE_NAPI_FUNCTION("createMd", NapiMd::CreateMd),
    };
    napi_define_properties(env, exports, sizeof(desc) / sizeof(desc[0]), desc);
    napi_property_descriptor classDesc[] = {
        DECLARE_NAPI_FUNCTION("update", NapiMd::JsMdUpdate),
        DECLARE_NAPI_FUNCTION("updateSync", NapiMd::JsMdUpdateSync),
        DECLARE_NAPI_FUNCTION("digest", NapiMd::JsMdDoFinal),
        DECLARE_NAPI_FUNCTION("digestSync", NapiMd::JsMdDoFinalSync),
        DECLARE_NAPI_FUNCTION("getMdLength", NapiMd::JsGetMdLength),
    };
    napi_value constructor = nullptr;
    napi_define_class(env, "Md", NAPI_AUTO_LENGTH, MdConstructor, nullptr,
        sizeof(classDesc) / sizeof(classDesc[0]), classDesc, &constructor);
    napi_create_reference(env, constructor, 1, &classRef_);
}
} // CryptoFramework
} // OHOS