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

#ifndef HCF_NAPI_VERIFY_H
#define HCF_NAPI_VERIFY_H

#include <cstdint>
#include "log.h"
#include "signature.h"
#include "napi/native_api.h"
#include "napi/native_common.h"

namespace OHOS {
namespace CryptoFramework {
class NapiVerify {
public:
    explicit NapiVerify(HcfVerify *verify);
    ~NapiVerify();

    HcfVerify *GetVerify();

    static void DefineVerifyJSClass(napi_env env, napi_value exports);
    static napi_value VerifyConstructor(napi_env env, napi_callback_info info);
    static napi_value CreateJsVerify(napi_env env, napi_callback_info info);

    static napi_value JsInit(napi_env env, napi_callback_info info);
    static napi_value JsUpdate(napi_env env, napi_callback_info info);
    static napi_value JsVerify(napi_env env, napi_callback_info info);
    static napi_value JsRecover(napi_env env, napi_callback_info info);
    static napi_value JsInitSync(napi_env env, napi_callback_info info);
    static napi_value JsUpdateSync(napi_env env, napi_callback_info info);
    static napi_value JsVerifySync(napi_env env, napi_callback_info info);
    static napi_value JsRecoverSync(napi_env env, napi_callback_info info);

    static napi_value JsSetVerifySpec(napi_env env, napi_callback_info info);
    static napi_value JsGetVerifySpec(napi_env env, napi_callback_info info);

    static thread_local napi_ref classRef_;

private:
    HcfVerify *verify_ = nullptr;
};
}  // namespace CryptoFramework
}  // namespace OHOS
#endif
