/*
 * Copyright (C) 2026 Huawei Device Co., Ltd.
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

#ifndef HCF_NAPI_KEM_H
#define HCF_NAPI_KEM_H

#include "kem.h"
#include "log.h"
#include "napi/native_api.h"
#include "napi/native_common.h"

namespace OHOS {
namespace CryptoFramework {
class NapiKem {
public:
    explicit NapiKem(HcfKem *kem);
    ~NapiKem();

    HcfKem *GetKem() const;

    static void DefineKemJSClass(napi_env env, napi_value exports);
    static napi_value KemConstructor(napi_env env, napi_callback_info info);
    static napi_value CreateJsKem(napi_env env, napi_callback_info info);

    static napi_value JsEncapsulate(napi_env env, napi_callback_info info);
    static napi_value JsEncapsulateSync(napi_env env, napi_callback_info info);
    static napi_value JsDecapsulate(napi_env env, napi_callback_info info);
    static napi_value JsDecapsulateSync(napi_env env, napi_callback_info info);
    static napi_value JsGetAlgorithm(napi_env env, napi_callback_info info);

    static thread_local napi_ref classRef_;

private:
    HcfKem *kem_ = nullptr;
};
}  // namespace CryptoFramework
}  // namespace OHOS

#endif
