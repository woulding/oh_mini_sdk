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

#include "napi_key_agreement.h"

#include "securec.h"
#include "log.h"
#include "memory.h"

#include "napi_crypto_framework_defines.h"
#include "napi_pri_key.h"
#include "napi_pub_key.h"
#include "napi_utils.h"

namespace OHOS {
namespace CryptoFramework {
struct KeyAgreementCtx {
    napi_env env = nullptr;

    AsyncType asyncType = ASYNC_CALLBACK;
    napi_ref callback = nullptr;
    napi_deferred deferred = nullptr;
    napi_value promise = nullptr;
    napi_async_work asyncWork = nullptr;
    napi_ref keyAgreementRef = nullptr;
    napi_ref priKeyRef = nullptr;
    napi_ref pubKeyRef = nullptr;

    HcfKeyAgreement *keyAgreement = nullptr;
    HcfPriKey *priKey = nullptr;
    HcfPubKey *pubKey = nullptr;

    HcfResult errCode = HCF_SUCCESS;
    const char *errMsg = nullptr;
    HcfBlob returnSecret { .data = nullptr, .len = 0 };
};

thread_local napi_ref NapiKeyAgreement::classRef_ = nullptr;

static void FreeKeyAgreementCtx(napi_env env, KeyAgreementCtx *ctx)
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

    if (ctx->keyAgreementRef != nullptr) {
        napi_delete_reference(env, ctx->keyAgreementRef);
        ctx->keyAgreementRef = nullptr;
    }

    if (ctx->priKeyRef != nullptr) {
        napi_delete_reference(env, ctx->priKeyRef);
        ctx->priKeyRef = nullptr;
    }

    if (ctx->pubKeyRef != nullptr) {
        napi_delete_reference(env, ctx->pubKeyRef);
        ctx->pubKeyRef = nullptr;
    }

    if (ctx->returnSecret.data != nullptr) {
        HcfBlobDataClearAndFree(&ctx->returnSecret);
    }

    HcfFree(ctx);
}

static bool CreateKeyAgreementRef(napi_env env, napi_value thisVar, napi_value priKey, napi_value pubKey,
                                  KeyAgreementCtx *ctx)
{
    if (napi_create_reference(env, thisVar, 1, &ctx->keyAgreementRef) != napi_ok) {
        LOGE("create key agreement ref failed when derive secret key using key agreement!");
        return false;
    }

    if (napi_create_reference(env, priKey, 1, &ctx->priKeyRef) != napi_ok) {
        LOGE("create private key ref failed when derive secret key using key agreement!");
        return false;
    }

    if (napi_create_reference(env, pubKey, 1, &ctx->pubKeyRef) != napi_ok) {
        LOGE("create public key ref failed when derive secret key using key agreement!");
        return false;
    }

    return true;
}

static bool BuildKeyAgreementJsCtx(napi_env env, napi_callback_info info, KeyAgreementCtx *ctx)
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

    NapiKeyAgreement *napiKeyAgreement = nullptr;
    napi_status status = napi_unwrap(env, thisVar, reinterpret_cast<void **>(&napiKeyAgreement));
    if (status != napi_ok || napiKeyAgreement == nullptr) {
        LOGE("failed to unwrap napi verify obj.");
        return false;
    }

    size_t index = 0;
    NapiPriKey *napiPriKey = nullptr;
    status = napi_unwrap(env, argv[index], reinterpret_cast<void **>(&napiPriKey));
    if (status != napi_ok || napiPriKey == nullptr) {
        LOGE("failed to unwrap priKey verify obj.");
        return false;
    }

    index++;
    NapiPubKey *napiPubKey = nullptr;
    status = napi_unwrap(env, argv[index], reinterpret_cast<void **>(&napiPubKey));
    if (status != napi_ok || napiPubKey == nullptr) {
        LOGE("failed to unwrap napi pubKey obj.");
        return false;
    }

    ctx->keyAgreement = napiKeyAgreement->GetKeyAgreement();
    ctx->priKey = napiPriKey->GetPriKey();
    ctx->pubKey = napiPubKey->GetPubKey();

    if (!CreateKeyAgreementRef(env, thisVar, argv[PARAM0], argv[PARAM1], ctx)) {
        return false;
    }

    if (ctx->asyncType == ASYNC_PROMISE) {
        napi_create_promise(env, &ctx->deferred, &ctx->promise);
        return true;
    } else {
        return GetCallbackFromJSParams(env, argv[expectedArgc - 1], &ctx->callback);
    }
}

static void ReturnCallbackResult(napi_env env, KeyAgreementCtx *ctx, napi_value result)
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

static void ReturnPromiseResult(napi_env env, KeyAgreementCtx *ctx, napi_value result)
{
    if (ctx->errCode == HCF_SUCCESS) {
        napi_resolve_deferred(env, ctx->deferred, result);
    } else {
        napi_reject_deferred(env, ctx->deferred,
            GenerateBusinessError(env, ctx->errCode, ctx->errMsg));
    }
}

static void KeyAgreementAsyncWorkProcess(napi_env env, void *data)
{
    KeyAgreementCtx *ctx = static_cast<KeyAgreementCtx *>(data);

    ctx->errCode = ctx->keyAgreement->generateSecret(ctx->keyAgreement,
        ctx->priKey, ctx->pubKey, &ctx->returnSecret);
    if (ctx->errCode != HCF_SUCCESS) {
        LOGE("generate secret fail.");
        ctx->errMsg = "generate secret fail.";
    }
}

static void KeyAgreementAsyncWorkReturn(napi_env env, napi_status status, void *data)
{
    KeyAgreementCtx *ctx = static_cast<KeyAgreementCtx *>(data);

    napi_value dataBlob = nullptr;
    if (ctx->errCode == HCF_SUCCESS) {
        dataBlob = ConvertBlobToNapiValue(env, &ctx->returnSecret);
    }

    if (ctx->asyncType == ASYNC_CALLBACK) {
        ReturnCallbackResult(env, ctx, dataBlob);
    } else {
        ReturnPromiseResult(env, ctx, dataBlob);
    }
    FreeKeyAgreementCtx(env, ctx);
}

static napi_value NewKeyAgreementAsyncWork(napi_env env, KeyAgreementCtx *ctx)
{
    napi_value resourceName = nullptr;
    napi_create_string_utf8(env, "generateSecret", NAPI_AUTO_LENGTH, &resourceName);

    napi_create_async_work(
        env, nullptr, resourceName,
        [](napi_env env, void *data) {
            KeyAgreementAsyncWorkProcess(env, data);
            return;
        },
        [](napi_env env, napi_status status, void *data) {
            KeyAgreementAsyncWorkReturn(env, status, data);
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

NapiKeyAgreement::NapiKeyAgreement(HcfKeyAgreement *keyAgreement)
{
    this->keyAgreement_ = keyAgreement;
}

NapiKeyAgreement::~NapiKeyAgreement()
{
    HcfObjDestroy(this->keyAgreement_);
    this->keyAgreement_ = nullptr;
}

HcfKeyAgreement *NapiKeyAgreement::GetKeyAgreement()
{
    return this->keyAgreement_;
}

napi_value NapiKeyAgreement::JsGenerateSecret(napi_env env, napi_callback_info info)
{
    KeyAgreementCtx *ctx = static_cast<KeyAgreementCtx *>(HcfMalloc(sizeof(KeyAgreementCtx), 0));
    if (ctx == nullptr) {
        NAPI_LOG_THROW(env, HCF_ERR_MALLOC, "create context fail.");
        return nullptr;
    }

    if (!BuildKeyAgreementJsCtx(env, info, ctx)) {
        NAPI_LOG_THROW(env, HCF_INVALID_PARAMS, "build context fail.");
        FreeKeyAgreementCtx(env, ctx);
        return nullptr;
    }

    return NewKeyAgreementAsyncWork(env, ctx);
}

static HcfResult GetPriKeyAndPubKeyFromParam(napi_env env, napi_value priKeyParam,  napi_value pubKeyParam,
    NapiPriKey **napiPriKey, NapiPubKey **napiPubKey)
{
    napi_status status = napi_unwrap(env, priKeyParam, reinterpret_cast<void **>(napiPriKey));
    if (status != napi_ok) {
        LOGE("failed to unwrap priKey verify obj.");
        return HCF_ERR_NAPI;
    }

    if (*napiPriKey == nullptr) {
        LOGE("priKey param is nullptr.");
        return HCF_ERR_NAPI;
    }

    status = napi_unwrap(env, pubKeyParam, reinterpret_cast<void **>(napiPubKey));
    if (status != napi_ok) {
        LOGE("failed to unwrap pubKey verify obj.");
        return HCF_ERR_NAPI;
    }

    if (*napiPubKey == nullptr) {
        LOGE("pubKey param is nullptr.");
        return HCF_ERR_NAPI;
    }

    return HCF_SUCCESS;
}

napi_value NapiKeyAgreement::JsGenerateSecretSync(napi_env env, napi_callback_info info)
{
    napi_value thisVar = nullptr;
    size_t argc = PARAMS_NUM_TWO;
    napi_value argv[PARAMS_NUM_TWO] = { nullptr };
    napi_get_cb_info(env, info, &argc, argv, &thisVar, nullptr);
    if (argc != PARAMS_NUM_TWO) {
        NAPI_LOG_THROW(env, HCF_INVALID_PARAMS, "wrong argument num.");
        return nullptr;
    }

    NapiKeyAgreement *napiKeyAgreement = nullptr;
    napi_status status = napi_unwrap(env, thisVar, reinterpret_cast<void **>(&napiKeyAgreement));
    if (status != napi_ok || napiKeyAgreement == nullptr) {
        NAPI_LOG_THROW(env, HCF_ERR_NAPI, "failed to unwrap napi verify obj.");
        return nullptr;
    }

    NapiPriKey *napiPriKey = nullptr;
    NapiPubKey *napiPubKey = nullptr;
    HcfResult ret = GetPriKeyAndPubKeyFromParam(env, argv[PARAM0], argv[PARAM1], &napiPriKey, &napiPubKey);
    if (ret != HCF_SUCCESS) {
        NAPI_LOG_THROW(env, ret, "failed to parse priKey or pubKey.");
        return nullptr;
    }

    HcfKeyAgreement *keyAgreement = napiKeyAgreement->GetKeyAgreement();
    HcfPriKey *priKey = napiPriKey->GetPriKey();
    HcfPubKey *pubKey = napiPubKey->GetPubKey();
    HcfBlob returnSecret = { .data = nullptr, .len = 0 };
    ret = keyAgreement->generateSecret(keyAgreement, priKey, pubKey, &returnSecret);
    if (ret != HCF_SUCCESS) {
        NAPI_LOG_THROW(env, ret, "generate secret fail.");
        return nullptr;
    }

    napi_value instance = nullptr;
    ret = ConvertDataBlobToNapiValue(env, &returnSecret, &instance);
    HcfBlobDataClearAndFree(&returnSecret);
    if (ret != HCF_SUCCESS) {
        NAPI_LOG_THROW(env, ret, "key agreement convert dataBlob to napi_value failed!");
        return nullptr;
    }

    return instance;
}

napi_value NapiKeyAgreement::KeyAgreementConstructor(napi_env env, napi_callback_info info)
{
    napi_value thisVar = nullptr;
    napi_get_cb_info(env, info, nullptr, nullptr, &thisVar, nullptr);
    return thisVar;
}

napi_value NapiKeyAgreement::CreateJsKeyAgreement(napi_env env, napi_callback_info info)
{
    size_t argc = PARAMS_NUM_ONE;
    napi_value argv[PARAMS_NUM_ONE] = { nullptr };
    napi_get_cb_info(env, info, &argc, argv, nullptr, nullptr);
    if (argc != PARAMS_NUM_ONE) {
        NAPI_LOG_THROW(env, HCF_INVALID_PARAMS, "The input args num is invalid.");
        return nullptr;
    }

    napi_value instance = nullptr;
    napi_value constructor = nullptr;
    napi_get_reference_value(env, classRef_, &constructor);
    napi_new_instance(env, constructor, argc, argv, &instance);

    std::string algName;
    if (!GetStringFromJSParams(env, argv[0], algName)) {
        NAPI_LOG_THROW(env, HCF_INVALID_PARAMS, "Get algName is invalid.");
        return nullptr;
    }

    HcfKeyAgreement *keyAgreement = nullptr;
    HcfResult res = HcfKeyAgreementCreate(algName.c_str(), &keyAgreement);
    if (res != HCF_SUCCESS) {
        NAPI_LOG_THROW(env, res, "create c keyAgreement fail.");
        return nullptr;
    }

    NapiKeyAgreement *napiKeyAgreement = new (std::nothrow) NapiKeyAgreement(keyAgreement);
    if (napiKeyAgreement == nullptr) {
        NAPI_LOG_THROW(env, HCF_ERR_MALLOC, "new napi key agreement failed.");
        HcfObjDestroy(keyAgreement);
        keyAgreement = nullptr;
        return nullptr;
    }

    napi_status status = napi_wrap(env, instance, napiKeyAgreement,
        [](napi_env env, void *data, void *hint) {
            delete(static_cast<NapiKeyAgreement *>(data));
        }, nullptr, nullptr);
    if (status != napi_ok) {
        NAPI_LOG_THROW(env, HCF_INVALID_PARAMS, "failed to wrap napiKeyAgreement obj!");
        delete napiKeyAgreement;
        return nullptr;
    }

    return instance;
}

napi_value NapiKeyAgreement::JsGetAlgorithm(napi_env env, napi_callback_info info)
{
    napi_value thisVar = nullptr;
    NapiKeyAgreement *napiKeyAgreement = nullptr;
    napi_get_cb_info(env, info, nullptr, nullptr, &thisVar, nullptr);
    napi_status status = napi_unwrap(env, thisVar, reinterpret_cast<void **>(&napiKeyAgreement));
    if (status != napi_ok || napiKeyAgreement == nullptr) {
        NAPI_LOG_THROW(env, HCF_INVALID_PARAMS, "failed to unwrap napiKeyAgreement obj!");
        return nullptr;
    }
    HcfKeyAgreement *keyAgreement = napiKeyAgreement->GetKeyAgreement();

    const char *algo = keyAgreement->getAlgoName(keyAgreement);
    napi_value instance = nullptr;
    napi_create_string_utf8(env, algo, NAPI_AUTO_LENGTH, &instance);
    return instance;
}

void NapiKeyAgreement::DefineKeyAgreementJSClass(napi_env env, napi_value exports)
{
    napi_property_descriptor desc[] = {
        DECLARE_NAPI_FUNCTION("createKeyAgreement", NapiKeyAgreement::CreateJsKeyAgreement),
    };
    napi_define_properties(env, exports, sizeof(desc) / sizeof(desc[0]), desc);

    napi_property_descriptor classDesc[] = {
        DECLARE_NAPI_FUNCTION("generateSecret", NapiKeyAgreement::JsGenerateSecret),
        DECLARE_NAPI_FUNCTION("generateSecretSync", NapiKeyAgreement::JsGenerateSecretSync),
        {.utf8name = "algName", .getter = NapiKeyAgreement::JsGetAlgorithm},
    };
    napi_value constructor = nullptr;
    napi_define_class(env, "KeyAgreement", NAPI_AUTO_LENGTH, NapiKeyAgreement::KeyAgreementConstructor, nullptr,
        sizeof(classDesc) / sizeof(classDesc[0]), classDesc, &constructor);
    napi_create_reference(env, constructor, 1, &classRef_);
}
} // CryptoFramework
} // OHOS
