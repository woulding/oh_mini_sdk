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

#ifndef NAPI_RAND_H
#define NAPI_RAND_H

#include <string>

#include "napi/native_api.h"
#include "napi/native_common.h"

#include "rand.h"

namespace OHOS {
namespace CryptoFramework {
class NapiRand {
public:
    explicit NapiRand(HcfRand *randObj);
    ~NapiRand();
    HcfRand *GetRand();

    static thread_local napi_ref classRef_;

    static void DefineRandJSClass(napi_env env, napi_value exports);
    static napi_value CreateRand(napi_env env, napi_callback_info info);
    static napi_value RandConstructor(napi_env env, napi_callback_info info);

    static napi_value JsGetAlgorithm(napi_env env, napi_callback_info info);
    static napi_value JsGenerateRandom(napi_env env, napi_callback_info info);
    static napi_value JsGenerateRandomSync(napi_env env, napi_callback_info info);
    static napi_value JsSetSeed(napi_env env, napi_callback_info info);
    static napi_value JsEnableHardwareEntropy(napi_env env, napi_callback_info info);

private:
    HcfRand *randObj_ = nullptr;
};
}  // namespace CryptoFramework
}  // namespace OHOS
#endif
