/*
 * Copyright (C) 2022-2023 Huawei Device Co., Ltd.
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

#include "napi_key_pair.h"

#include "securec.h"
#include "log.h"
#include "napi_crypto_framework_defines.h"
#include "napi_pri_key.h"
#include "napi_pub_key.h"
#include "napi_utils.h"

namespace OHOS {
namespace CryptoFramework {
thread_local napi_ref NapiKeyPair::classRef_ = nullptr;

NapiKeyPair::NapiKeyPair(HcfKeyPair *keyPair)
{
    this->keyPair_ = keyPair;
}

NapiKeyPair::~NapiKeyPair()
{
    HcfObjDestroy(this->keyPair_);
    this->keyPair_ = nullptr;
}

napi_value NapiKeyPair::KeyPairConstructor(napi_env env, napi_callback_info info)
{
    napi_value thisVar = nullptr;
    napi_get_cb_info(env, info, nullptr, nullptr, &thisVar, nullptr);
    return thisVar;
}

static bool WrapPubKey(napi_env env, napi_value instance, HcfPubKey *key)
{
    NapiPubKey *napiPubKey = new (std::nothrow) NapiPubKey(key);
    if (napiPubKey == nullptr) {
        LOGE("new napi pub key failed");
        return false;
    }
    napi_value pubKey = napiPubKey->ConvertToJsPubKey(env);
    napi_status status =  napi_wrap(
        env, pubKey, napiPubKey,
        [](napi_env env, void *data, void *hint) {
            NapiPubKey *napiPubKey = static_cast<NapiPubKey *>(data);
            HcfObjDestroy(napiPubKey->GetPubKey());
            delete napiPubKey;
        }, nullptr, nullptr);
    if (status != napi_ok) {
        LOGE("failed to wrap napiPubKey obj!");
        delete napiPubKey;
        return false;
    }
    napi_set_named_property(env, instance, CRYPTO_TAG_PUB_KEY.c_str(), pubKey);
    return true;
}

static bool WrapPriKey(napi_env env, napi_value instance, HcfPriKey *key)
{
    NapiPriKey *napiPriKey = new (std::nothrow) NapiPriKey(key);
    if (napiPriKey == nullptr) {
        LOGE("new napi pri key failed");
        return false;
    }
    napi_value priKey = napiPriKey->ConvertToJsPriKey(env);
    napi_status status =  napi_wrap(
        env, priKey, napiPriKey,
        [](napi_env env, void *data, void *hint) {
            NapiPriKey *napiPriKey = static_cast<NapiPriKey *>(data);
            HcfObjDestroy(napiPriKey->GetPriKey());
            delete napiPriKey;
        }, nullptr, nullptr);
    if (status != napi_ok) {
        LOGE("failed to wrap napiPriKey obj!");
        delete napiPriKey;
        return false;
    }
    napi_set_named_property(env, instance, CRYPTO_TAG_PRI_KEY.c_str(), priKey);
    return true;
}

napi_value NapiKeyPair::ConvertToJsKeyPair(napi_env env)
{
    napi_value instance;
    napi_value constructor = nullptr;
    napi_get_reference_value(env, classRef_, &constructor);
    napi_new_instance(env, constructor, 0, nullptr, &instance);

    if (this->keyPair_->pubKey != nullptr) {
        if (WrapPubKey(env, instance, this->keyPair_->pubKey) == false) {
            return nullptr;
        }
        this->keyPair_->pubKey = nullptr;
    }

    if (this->keyPair_->priKey != nullptr) {
        if (WrapPriKey(env, instance, this->keyPair_->priKey) == false) {
            return nullptr;
        }
        this->keyPair_->priKey = nullptr;
    }
    return instance;
}

void NapiKeyPair::DefineKeyPairJSClass(napi_env env)
{
    napi_property_descriptor classDesc[] = {};
    napi_value constructor = nullptr;
    napi_define_class(env, "KeyPair", NAPI_AUTO_LENGTH, KeyPairConstructor, nullptr,
        sizeof(classDesc) / sizeof(classDesc[0]), classDesc, &constructor);
    napi_create_reference(env, constructor, 1, &classRef_);
}
} // CryptoFramework
} // OHOS
