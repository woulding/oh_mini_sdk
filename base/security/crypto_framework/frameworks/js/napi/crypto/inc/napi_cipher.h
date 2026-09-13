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

#ifndef NAPI_CIPHER_H
#define NAPI_CIPHER_H

#include <string>

#include "napi/native_api.h"
#include "napi/native_common.h"
#include "cipher.h"

namespace OHOS {
namespace CryptoFramework {
class NapiCipher {
public:
    explicit NapiCipher(HcfCipher *cipher);
    ~NapiCipher();

    static void DefineCipherJSClass(napi_env env, napi_value exports);
    static napi_value CreateCipher(napi_env env, napi_callback_info info);
    static napi_value CipherConstructor(napi_env env, napi_callback_info info);

    static napi_value JsCipherInit(napi_env env, napi_callback_info info);
    static napi_value JsCipherUpdate(napi_env env, napi_callback_info info);
    static napi_value JsCipherDoFinal(napi_env env, napi_callback_info info);
    static napi_value JsGetAlgorithm(napi_env env, napi_callback_info info);

    static napi_value JsCipherInitSync(napi_env env, napi_callback_info info);
    static napi_value JsCipherUpdateSync(napi_env env, napi_callback_info info);
    static napi_value JsCipherDoFinalSync(napi_env env, napi_callback_info info);

    static napi_value JsSetCipherSpec(napi_env env, napi_callback_info info);
    static napi_value JsGetCipherSpec(napi_env env, napi_callback_info info);
    HcfCipher *GetCipher() const;

    static thread_local napi_ref classRef_;
private:
    HcfCipher *cipher_;
};
}  // namespace CryptoFramework
}  // namespace OHOS
#endif