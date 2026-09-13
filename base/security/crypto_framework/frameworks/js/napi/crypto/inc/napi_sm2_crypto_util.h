/*
 * Copyright (C) 2024 Huawei Device Co., Ltd.
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

#ifndef HCF_NAPI_SM2_CRYPTO_UTIL_H
#define HCF_NAPI_SM2_CRYPTO_UTIL_H

#include <cstdint>

#include "napi/native_api.h"
#include "napi/native_common.h"
#include "sm2_crypto_util.h"

namespace OHOS {
namespace CryptoFramework {
class NapiSm2CryptoUtil {
public:
    explicit NapiSm2CryptoUtil();
    ~NapiSm2CryptoUtil();

    static napi_value JsGenCipherTextBySpec(napi_env env, napi_callback_info info);
    static napi_value JsGetCipherTextSpec(napi_env env, napi_callback_info info);
    static napi_value Sm2CryptoUtilConstructor(napi_env env, napi_callback_info info);
    static napi_value Sm2CryptoUtilConstructorClass(napi_env env);
    static void DefineNapiSm2CryptoUtilJSClass(napi_env env, napi_value exports);
};
}  // namespace CryptoFramework
}  // namespace OHOS
#endif
