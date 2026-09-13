/*
 * Copyright (C) 2022 Huawei Device Co., Ltd.
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

#ifndef HCF_NAPI_ASY_KEY_SPEC_GENERATOR_H
#define HCF_NAPI_ASY_KEY_SPEC_GENERATOR_H

#include <cstdint>
#include "asy_key_generator.h"
#include "log.h"
#include "napi/native_api.h"
#include "napi/native_common.h"

namespace OHOS {
namespace CryptoFramework {
class NapiAsyKeyGeneratorBySpec {
public:
    explicit NapiAsyKeyGeneratorBySpec(HcfAsyKeyGeneratorBySpec *generator);
    ~NapiAsyKeyGeneratorBySpec();

    HcfAsyKeyGeneratorBySpec *GetAsyKeyGeneratorBySpec();

    static void DefineAsyKeyGeneratorBySpecJSClass(napi_env env, napi_value exports);
    static napi_value AsyKeyGeneratorBySpecConstructor(napi_env env, napi_callback_info info);
    static napi_value CreateJsAsyKeyGeneratorBySpec(napi_env env, napi_callback_info info);

    static napi_value JsGenerateKeyPair(napi_env env, napi_callback_info info);
    static napi_value JsGenerateKeyPairSync(napi_env env, napi_callback_info info);
    static napi_value JsGeneratePubKey(napi_env env, napi_callback_info info);
    static napi_value JsGeneratePubKeySync(napi_env env, napi_callback_info info);
    static napi_value JsGeneratePriKey(napi_env env, napi_callback_info info);
    static napi_value JsGeneratePriKeySync(napi_env env, napi_callback_info info);
    static napi_value JsGetAlgorithm(napi_env env, napi_callback_info info);

    static thread_local napi_ref classRef_;

private:
    HcfAsyKeyGeneratorBySpec *generator_ = nullptr;
};
}  // namespace CryptoFramework
}  // namespace OHOS
#endif
