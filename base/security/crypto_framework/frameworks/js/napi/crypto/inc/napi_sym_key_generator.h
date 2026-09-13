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

#ifndef HCF_NAPI_SYM_KEY_GENERATOR_H
#define HCF_NAPI_SYM_KEY_GENERATOR_H

#include <cstdint>
#include "log.h"
#include "napi/native_api.h"
#include "napi/native_common.h"
#include "sym_key_generator.h"

namespace OHOS {
namespace CryptoFramework {
class NapiSymKeyGenerator {
public:
    explicit NapiSymKeyGenerator(HcfSymKeyGenerator *generator);
    ~NapiSymKeyGenerator();
    HcfSymKeyGenerator *GetSymKeyGenerator() const;

    static void DefineSymKeyGeneratorJSClass(napi_env env, napi_value exports);
    static napi_value CreateSymKeyGenerator(napi_env env, napi_callback_info info);
    static napi_value SymKeyGeneratorConstructor(napi_env env, napi_callback_info info);
    static napi_value JsGenerateSymKey(napi_env env, napi_callback_info info);
    static napi_value JsGetAlgorithm(napi_env env, napi_callback_info info);
    static napi_value JsConvertKey(napi_env env, napi_callback_info info);
    static napi_value JsGenerateSymKeySync(napi_env env, napi_callback_info info);
    static napi_value JsConvertKeySync(napi_env env, napi_callback_info info);

    static thread_local napi_ref classRef_;
private:
    HcfSymKeyGenerator *generator_;
};
}  // namespace CryptoFramework
}  // namespace OHOS
#endif
