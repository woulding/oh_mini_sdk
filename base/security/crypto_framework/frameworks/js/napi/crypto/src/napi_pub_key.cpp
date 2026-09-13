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

#include "napi_pub_key.h"

#include "log.h"
#include "memory.h"
#include "napi_crypto_framework_defines.h"
#include "napi_utils.h"
#include "securec.h"
#include "key.h"

namespace OHOS {
namespace CryptoFramework {
thread_local napi_ref NapiPubKey::classRef_ = nullptr;

NapiPubKey::NapiPubKey(HcfPubKey *pubKey) : NapiKey(reinterpret_cast<HcfKey *>(pubKey)) {}

NapiPubKey::~NapiPubKey() {}

struct PubKeyCtx {
    napi_env env = nullptr;
    napi_ref pubKeyRef = nullptr;
    napi_deferred deferred = nullptr;
    napi_value promise = nullptr;
    napi_async_work asyncWork = nullptr;
    HcfPubKey *pubKey = nullptr;
    HcfBlob returnBlob = { .data = nullptr, .len = 0 };
    uint32_t keyDataType = 0;
    HcfResult errCode = HCF_SUCCESS;
    const char *errMsg = nullptr;
};

static void FreePubKeyCtx(napi_env env, PubKeyCtx *ctx)
{
    if (ctx == nullptr) {
        return;
    }
    if (ctx->asyncWork != nullptr) {
        napi_delete_async_work(env, ctx->asyncWork);
        ctx->asyncWork = nullptr;
    }
    if (ctx->pubKeyRef != nullptr) {
        napi_delete_reference(env, ctx->pubKeyRef);
        ctx->pubKeyRef = nullptr;
    }
    HcfBlobDataFree(&ctx->returnBlob);
    HcfFree(ctx);
}

static void ReturnPubKeyPromiseResult(napi_env env, PubKeyCtx *ctx, napi_value result)
{
    if (ctx->errCode == HCF_SUCCESS) {
        napi_resolve_deferred(env, ctx->deferred, result);
    } else {
        napi_reject_deferred(env, ctx->deferred, GenerateBusinessError(env, ctx->errCode, ctx->errMsg));
    }
}

static HcfResult BuildPubKeyJsGetKeyDataCtx(napi_env env, napi_callback_info info, PubKeyCtx *context)
{
    size_t expectedArgc = ARGS_SIZE_ONE;
    size_t argc = expectedArgc;
    napi_value argv[ARGS_SIZE_ONE] = { nullptr };
    napi_value thisVar = nullptr;
    NapiPubKey *napiPubKey = nullptr;
    napi_get_cb_info(env, info, &argc, argv, &thisVar, nullptr);
    if (argc != expectedArgc) {
        LOGE("wrong argument num.");
        return HCF_INVALID_PARAMS;
    }
    if (napi_get_value_uint32(env, argv[PARAM0], &context->keyDataType) != napi_ok) {
        LOGE("invalid AsyKeyDataItem.");
        return HCF_INVALID_PARAMS;
    }

    napi_status status = napi_unwrap(env, thisVar, reinterpret_cast<void **>(&napiPubKey));
    if (status != napi_ok || napiPubKey == nullptr) {
        LOGE("failed to unwrap napiPubKey obj!");
        return HCF_INVALID_PARAMS;
    }
    context->pubKey = napiPubKey->GetPubKey();
    if (context->pubKey == nullptr) {
        LOGE("failed to get pubKey obj!");
        return HCF_INVALID_PARAMS;
    }

    if (napi_create_reference(env, thisVar, 1, &context->pubKeyRef) != napi_ok) {
        LOGE("create pubKey ref failed when do getKeyData!");
        return HCF_ERR_NAPI;
    }
    if (napi_create_promise(env, &context->deferred, &context->promise) != napi_ok) {
        LOGE("create promise failed when do getKeyData!");
        return HCF_ERR_NAPI;
    }
    return HCF_SUCCESS;
}

static void PubKeyJsGetKeyDataAsyncWorkProcess(napi_env env, void *data)
{
    (void)env;
    PubKeyCtx *ctx = static_cast<PubKeyCtx *>(data);
    ctx->errCode = ctx->pubKey->getKeyData(ctx->pubKey, ctx->keyDataType, &ctx->returnBlob);
    if (ctx->errCode != HCF_SUCCESS) {
        LOGE("getKeyData failed.");
        ctx->errMsg = "getKeyData failed.";
    }
}

static void PubKeyJsGetKeyDataAsyncWorkReturn(napi_env env, napi_status status, void *data)
{
    (void)status;
    PubKeyCtx *ctx = static_cast<PubKeyCtx *>(data);
    napi_value result = nullptr;
    if (ctx->errCode == HCF_SUCCESS) {
        result = ConvertObjectBlobToNapiValue(env, &ctx->returnBlob);
        if (result == nullptr) {
            ctx->errCode = HCF_ERR_NAPI;
            ctx->errMsg = "convert blob to napi failed.";
        }
    }
    ReturnPubKeyPromiseResult(env, ctx, result);
    FreePubKeyCtx(env, ctx);
}

static napi_value NewPubKeyJsGetKeyDataAsyncWork(napi_env env, PubKeyCtx *ctx)
{
    napi_value resourceName = nullptr;
    napi_create_string_utf8(env, "getKeyData", NAPI_AUTO_LENGTH, &resourceName);

    napi_create_async_work(
        env, nullptr, resourceName,
        [](napi_env env, void *data) {
            PubKeyJsGetKeyDataAsyncWorkProcess(env, data);
            return;
        },
        [](napi_env env, napi_status status, void *data) {
            PubKeyJsGetKeyDataAsyncWorkReturn(env, status, data);
            return;
        },
        static_cast<void *>(ctx), &ctx->asyncWork);
    napi_queue_async_work(env, ctx->asyncWork);
    return ctx->promise;
}

HcfPubKey *NapiPubKey::GetPubKey()
{
    return reinterpret_cast<HcfPubKey *>(NapiKey::GetHcfKey());
}

napi_value NapiPubKey::PubKeyConstructor(napi_env env, napi_callback_info info)
{
    napi_value thisVar = nullptr;
    napi_get_cb_info(env, info, nullptr, nullptr, &thisVar, nullptr);
    return thisVar;
}

napi_value NapiPubKey::ConvertToJsPubKey(napi_env env)
{
    napi_value instance;
    napi_value constructor = nullptr;
    napi_get_reference_value(env, classRef_, &constructor);
    napi_new_instance(env, constructor, 0, nullptr, &instance);

    const char *algName = this->GetPubKey()->base.getAlgorithm(&(this->GetPubKey()->base));
    const char *format = this->GetPubKey()->base.getFormat(&(this->GetPubKey()->base));

    napi_value napiAlgName = nullptr;
    napi_create_string_utf8(env, algName, NAPI_AUTO_LENGTH, &napiAlgName);
    napi_set_named_property(env, instance, CRYPTO_TAG_ALG_NAME.c_str(), napiAlgName);

    napi_value napiFormat = nullptr;
    napi_create_string_utf8(env, format, NAPI_AUTO_LENGTH, &napiFormat);
    napi_set_named_property(env, instance, CRYPTO_TAG_FORMAT.c_str(), napiFormat);
    return instance;
}

napi_value NapiPubKey::JsGetEncoded(napi_env env, napi_callback_info info)
{
    napi_value thisVar = nullptr;
    napi_get_cb_info(env, info, nullptr, nullptr, &thisVar, nullptr);
    NapiPubKey *napiPubKey = nullptr;
    napi_status status = napi_unwrap(env, thisVar, reinterpret_cast<void **>(&napiPubKey));
    if (status != napi_ok || napiPubKey == nullptr) {
        NAPI_LOG_THROW(env, HCF_INVALID_PARAMS, "failed to unwrap napiPubKey obj!");
        return nullptr;
    }

    HcfPubKey *pubKey = napiPubKey->GetPubKey();
    if (pubKey == nullptr) {
        NAPI_LOG_THROW(env, HCF_INVALID_PARAMS, "failed to get pubKey obj!");
        return nullptr;
    }

    HcfBlob returnBlob;
    HcfResult res = pubKey->base.getEncoded(&pubKey->base, &returnBlob);
    if (res != HCF_SUCCESS) {
        NAPI_LOG_THROW(env, HCF_INVALID_PARAMS, "c getEncoded fail.");
        return nullptr;
    }

    napi_value instance = ConvertBlobToNapiValue(env, &returnBlob);
    if (instance == nullptr) {
        HcfBlobDataFree(&returnBlob);
        NAPI_LOG_THROW(env, res, "covert blob to napi value failed.");
        return nullptr;
    }
    HcfBlobDataFree(&returnBlob);
    return instance;
}

napi_value NapiPubKey::JsGetEncodedDer(napi_env env, napi_callback_info info)
{
    napi_value thisVar = nullptr;
    NapiPubKey *napiPubKey = nullptr;
    size_t expectedArgc = ARGS_SIZE_ONE;
    size_t argc = ARGS_SIZE_ONE;
    napi_value argv[ARGS_SIZE_ONE] = { nullptr };
    napi_get_cb_info(env, info, &argc, argv, &thisVar, nullptr);
    if (argc != expectedArgc) {
        NAPI_LOG_THROW(env, HCF_INVALID_PARAMS, "JsGetEncodedDer fail, wrong argument num.");
        return nullptr;
    }
    std::string format;
    if (!GetStringFromJSParams(env, argv[PARAM0], format)) {
        NAPI_LOG_THROW(env, HCF_INVALID_PARAMS, "failed to get format.");
        return nullptr;
    }
    napi_status status = napi_unwrap(env, thisVar, reinterpret_cast<void **>(&napiPubKey));
    if (status != napi_ok || napiPubKey == nullptr) {
        NAPI_LOG_THROW(env, HCF_INVALID_PARAMS, "failed to unwrap napiPubKeyDer obj!");
        return nullptr;
    }

    HcfPubKey *pubKey = napiPubKey->GetPubKey();
    if (pubKey == nullptr) {
        NAPI_LOG_THROW(env, HCF_INVALID_PARAMS, "failed to get pubKeyDer obj!");
        return nullptr;
    }

    HcfBlob returnBlob;
    HcfResult res = pubKey->getEncodedDer(pubKey, format.c_str(), &returnBlob);
    if (res != HCF_SUCCESS) {
        NAPI_LOG_THROW(env, res, "c getEncodedDer fail.");
        return nullptr;
    }

    napi_value instance = ConvertBlobToNapiValue(env, &returnBlob);
    if (instance == nullptr) {
        HcfBlobDataFree(&returnBlob);
        NAPI_LOG_THROW(env, res, "covert blob to napi value failed.");
        return nullptr;
    }
    HcfBlobDataFree(&returnBlob);
    return instance;
}

napi_value NapiPubKey::JsGetEncodedPem(napi_env env, napi_callback_info info)
{
    size_t expectedArgc = PARAMS_NUM_ONE;
    size_t argc = expectedArgc;
    napi_value argv[PARAMS_NUM_ONE] = { nullptr };
    napi_value thisVar = nullptr;
    napi_get_cb_info(env, info, &argc, argv, &thisVar, nullptr);
    if (argc != expectedArgc) {
        NAPI_LOG_THROW(env, HCF_INVALID_PARAMS, "The input args num is invalid.");
        return NapiGetNull(env);
    }

    std::string format = "";
    if (!GetStringFromJSParams(env, argv[0], format)) {
        NAPI_LOG_THROW(env, HCF_INVALID_PARAMS, "failed to get formatStr.");
        return NapiGetNull(env);
    }

    NapiPubKey *napiPubKey = nullptr;
    napi_status status = napi_unwrap(env, thisVar, reinterpret_cast<void **>(&napiPubKey));
    if (status != napi_ok || napiPubKey == nullptr) {
        NAPI_LOG_THROW(env, HCF_INVALID_PARAMS, "failed to unwrap napiPubKey obj!");
        return nullptr;
    }

    HcfPubKey *pubKey = napiPubKey->GetPubKey();
    if (pubKey == nullptr) {
        NAPI_LOG_THROW(env, HCF_INVALID_PARAMS, "failed to get pubKey obj!");
        return nullptr;
    }

    char *returnString = nullptr;
    HcfResult res = pubKey->base.getEncodedPem(&pubKey->base, format.c_str(), &returnString);
    if (res != HCF_SUCCESS) {
        NAPI_LOG_THROW(env, res, "getEncodedPem fail.");
        return nullptr;
    }
    napi_value instance = nullptr;
    napi_create_string_utf8(env, returnString, NAPI_AUTO_LENGTH, &instance);
    HcfFree(returnString);
    returnString = nullptr;
    return instance;
}

static napi_value GetAsyKeySpecBigInt(napi_env env, AsyKeySpecItem item, HcfPubKey *pubKey)
{
    HcfBigInteger returnBigInteger = { 0 };
    HcfResult res = pubKey->getAsyKeySpecBigInteger(pubKey, item, &returnBigInteger);
    if (res != HCF_SUCCESS) {
        NAPI_LOG_THROW(env, res, "C getAsyKeySpecBigInteger failed.");
        return nullptr;
    }

    napi_value instance = ConvertBigIntToNapiValue(env, &returnBigInteger);
    if (instance == nullptr) {
        HcfFree(returnBigInteger.data);
        returnBigInteger.data = nullptr;
        NAPI_LOG_THROW(env, res, "covert bigInt to napi value failed.");
        return nullptr;
    }
    HcfFree(returnBigInteger.data);
    returnBigInteger.data = nullptr;
    return instance;
}

static napi_value GetAsyKeySpecNumber(napi_env env, AsyKeySpecItem item, HcfPubKey *pubKey)
{
    int returnInt = 0;
    HcfResult res = pubKey->getAsyKeySpecInt(pubKey, item, &returnInt);
    if (res != HCF_SUCCESS) {
        NAPI_LOG_THROW(env, res, "C getAsyKeySpecInt failed.");
        return nullptr;
    }

    napi_value instance = nullptr;
    napi_create_int32(env, returnInt, &instance);
    return instance;
}

static napi_value GetAsyKeySpecString(napi_env env, AsyKeySpecItem item, HcfPubKey *pubKey)
{
    char *returnString = nullptr;
    HcfResult res = pubKey->getAsyKeySpecString(pubKey, item, &returnString);
    if (res != HCF_SUCCESS) {
        NAPI_LOG_THROW(env, res, "C getAsyKeySpecString failed.");
        return nullptr;
    }

    napi_value instance = nullptr;
    napi_create_string_utf8(env, returnString, NAPI_AUTO_LENGTH, &instance);
    HcfFree(returnString);
    returnString = nullptr;
    return instance;
}

napi_value NapiPubKey::JsGetAsyKeySpec(napi_env env, napi_callback_info info)
{
    napi_value thisVar = nullptr;
    NapiPubKey *napiPubKey = nullptr;
    size_t expectedArgc = ARGS_SIZE_ONE;
    size_t argc = ARGS_SIZE_ONE;
    napi_value argv[ARGS_SIZE_ONE] = { nullptr };
    napi_get_cb_info(env, info, &argc, argv, &thisVar, nullptr);
    if (argc != expectedArgc) {
        NAPI_LOG_THROW(env, HCF_INVALID_PARAMS, "JsGetAsyKeySpec fail, wrong argument num.");
        return nullptr;
    }
    AsyKeySpecItem item;
    if (napi_get_value_uint32(env, argv[0], reinterpret_cast<uint32_t *>(&item)) != napi_ok) {
        NAPI_LOG_THROW(env, HCF_INVALID_PARAMS, "JsGetAsyKeySpec failed!");
        return nullptr;
    }

    napi_status status = napi_unwrap(env, thisVar, reinterpret_cast<void **>(&napiPubKey));
    if (status != napi_ok || napiPubKey == nullptr) {
        NAPI_LOG_THROW(env, HCF_INVALID_PARAMS, "failed to unwrap napiPubKey obj!");
        return nullptr;
    }
    HcfPubKey *pubKey = napiPubKey->GetPubKey();
    if (pubKey == nullptr) {
        NAPI_LOG_THROW(env, HCF_INVALID_PARAMS, "failed to get pubKey obj!");
        return nullptr;
    }

    int32_t type = GetAsyKeySpecType(item);
    if (type == SPEC_ITEM_TYPE_BIG_INT) {
        return GetAsyKeySpecBigInt(env, item, pubKey);
    } else if (type == SPEC_ITEM_TYPE_NUM) {
        return GetAsyKeySpecNumber(env, item, pubKey);
    } else if (type == SPEC_ITEM_TYPE_STR) {
        return GetAsyKeySpecString(env, item, pubKey);
    } else {
        NAPI_LOG_THROW(env, HCF_INVALID_PARAMS, "AsyKeySpecItem not support!");
        return nullptr;
    }
}

napi_value NapiPubKey::JsGetKeySize(napi_env env, napi_callback_info info)
{
    napi_value thisVar = nullptr;
    napi_get_cb_info(env, info, nullptr, nullptr, &thisVar, nullptr);
    NapiPubKey *napiPubKey = nullptr;
    napi_status status = napi_unwrap(env, thisVar, reinterpret_cast<void **>(&napiPubKey));
    if (status != napi_ok || napiPubKey == nullptr) {
        NAPI_LOG_THROW(env, HCF_ERR_NAPI, "failed to unwrap napiPubKey obj!");
        return nullptr;
    }

    HcfPubKey *pubKey = napiPubKey->GetPubKey();
    if (pubKey == nullptr) {
        NAPI_LOG_THROW(env, HCF_ERR_PARAMETER_CHECK_FAILED, "failed to get pubKey obj!");
        return nullptr;
    }
    int keySize = 0;
    HcfResult res = pubKey->base.getKeySize(&(pubKey->base), &keySize);
    if (res != HCF_SUCCESS) {
        NAPI_LOG_THROW(env, res, "getKeySize failed.");
        return nullptr;
    }

    napi_value result = nullptr;
    napi_status value = napi_create_int32(env, keySize, &result);
    if (value != napi_ok) {
        NAPI_LOG_THROW(env, HCF_ERR_NAPI, "create result number failed!");
        return nullptr;
    }
    return result;
}

napi_value NapiPubKey::JsGetKeyData(napi_env env, napi_callback_info info)
{
    PubKeyCtx *context = static_cast<PubKeyCtx *>(HcfMalloc(sizeof(PubKeyCtx), 0));
    if (context == nullptr) {
        NAPI_LOG_THROW(env, HCF_ERR_MALLOC, "malloc context failed");
        return nullptr;
    }

    HcfResult res = BuildPubKeyJsGetKeyDataCtx(env, info, context);
    if (res != HCF_SUCCESS) {
        NAPI_LOG_THROW(env, res, "build context failed.");
        FreePubKeyCtx(env, context);
        return nullptr;
    }
    return NewPubKeyJsGetKeyDataAsyncWork(env, context);
}

napi_value NapiPubKey::JsGetKeyDataSync(napi_env env, napi_callback_info info)
{
    size_t expectedArgc = ARGS_SIZE_ONE;
    size_t argc = expectedArgc;
    napi_value argv[ARGS_SIZE_ONE] = { nullptr };
    napi_value thisVar = nullptr;
    napi_get_cb_info(env, info, &argc, argv, &thisVar, nullptr);
    if (argc != expectedArgc) {
        NAPI_LOG_THROW(env, HCF_INVALID_PARAMS, "wrong argument num.");
        return nullptr;
    }

    uint32_t type = 0;
    if (napi_get_value_uint32(env, argv[PARAM0], &type) != napi_ok) {
        NAPI_LOG_THROW(env, HCF_INVALID_PARAMS, "invalid AsyKeyDataItem.");
        return nullptr;
    }

    NapiPubKey *napiPubKey = nullptr;
    napi_status status = napi_unwrap(env, thisVar, reinterpret_cast<void **>(&napiPubKey));
    if (status != napi_ok || napiPubKey == nullptr) {
        NAPI_LOG_THROW(env, HCF_INVALID_PARAMS, "failed to unwrap napiPubKey obj!");
        return nullptr;
    }

    HcfPubKey *pubKey = napiPubKey->GetPubKey();
    if (pubKey == nullptr) {
        NAPI_LOG_THROW(env, HCF_INVALID_PARAMS, "failed to get pubKey obj!");
        return nullptr;
    }

    HcfBlob outBlob = { .data = nullptr, .len = 0 };
    HcfResult ret = pubKey->getKeyData(pubKey, type, &outBlob);
    if (ret != HCF_SUCCESS) {
        NAPI_LOG_THROW(env, ret, "getKeyData failed.");
        return nullptr;
    }

    napi_value out = ConvertObjectBlobToNapiValue(env, &outBlob);
    HcfBlobDataFree(&outBlob);
    return out;
}

void NapiPubKey::DefinePubKeyJSClass(napi_env env)
{
    napi_property_descriptor classDesc[] = {
        DECLARE_NAPI_FUNCTION("getEncoded", NapiPubKey::JsGetEncoded),
        DECLARE_NAPI_FUNCTION("getEncodedDer", NapiPubKey::JsGetEncodedDer),
        DECLARE_NAPI_FUNCTION("getEncodedPem", NapiPubKey::JsGetEncodedPem),
        DECLARE_NAPI_FUNCTION("getAsyKeySpec", NapiPubKey::JsGetAsyKeySpec),
        DECLARE_NAPI_FUNCTION("getKeySize", NapiPubKey::JsGetKeySize),
        DECLARE_NAPI_FUNCTION("getKeyData", NapiPubKey::JsGetKeyData),
        DECLARE_NAPI_FUNCTION("getKeyDataSync", NapiPubKey::JsGetKeyDataSync),
    };
    napi_value constructor = nullptr;
    napi_define_class(env, "PubKey", NAPI_AUTO_LENGTH, NapiPubKey::PubKeyConstructor, nullptr,
        sizeof(classDesc) / sizeof(classDesc[0]), classDesc, &constructor);
    napi_create_reference(env, constructor, 1, &classRef_);
}
} // CryptoFramework
} // OHOS
