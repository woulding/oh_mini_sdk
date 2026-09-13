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

#ifndef HCF_NAPI_ASY_KEY_GENERATOR_H
#define HCF_NAPI_ASY_KEY_GENERATOR_H

#include <cstdint>
#include "asy_key_generator.h"
#include "log.h"
#include "napi/native_api.h"
#include "napi/native_common.h"

namespace OHOS {
namespace CryptoFramework {
class NapiAsyKeyGenerator {
public:
    explicit NapiAsyKeyGenerator(HcfAsyKeyGenerator *generator);
    ~NapiAsyKeyGenerator();

    HcfAsyKeyGenerator *GetAsyKeyGenerator();

    static void DefineAsyKeyGeneratorJSClass(napi_env env, napi_value exports);
    static napi_value AsyKeyGeneratorConstructor(napi_env env, napi_callback_info info);
    static napi_value CreateJsAsyKeyGenerator(napi_env env, napi_callback_info info);

    static napi_value JsGenerateKeyPair(napi_env env, napi_callback_info info);
    static napi_value JsGenerateKeyPairSync(napi_env env, napi_callback_info info);
    static napi_value JsConvertKey(napi_env env, napi_callback_info info);
    static napi_value JsConvertKeySync(napi_env env, napi_callback_info info);
    static napi_value JsConvertPemKey(napi_env env, napi_callback_info info);
    static napi_value JsConvertPemKeySync(napi_env env, napi_callback_info info);

    static thread_local napi_ref classRef_;

private:
    HcfAsyKeyGenerator *generator_ = nullptr;
};
}  // namespace CryptoFramework
}  // namespace OHOS
#endif
