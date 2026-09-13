/*
 * Copyright (C) 2023-2024 Huawei Device Co., Ltd.
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

#ifndef HCF_NAPI_ECC_KEY_UTIL_H
#define HCF_NAPI_ECC_KEY_UTIL_H

#include <cstdint>
#include "ecc_key_util.h"
#include "log.h"
#include "napi/native_api.h"
#include "napi/native_common.h"

namespace OHOS {
namespace CryptoFramework {
class NapiECCKeyUtil {
public:
    explicit NapiECCKeyUtil();
    ~NapiECCKeyUtil();

    static napi_value JsGenECCCommonParamsSpec(napi_env env, napi_callback_info info);
    static napi_value ECCKeyUtilConstructor(napi_env env, napi_callback_info info);
    static napi_value GenECCCommonParamSpec(napi_env env);
    static napi_value JsConvertPoint(napi_env env, napi_callback_info info);
    static napi_value JsGetEncodedPoint(napi_env env, napi_callback_info info);
    static void DefineNapiECCKeyUtilJSClass(napi_env env, napi_value exports);
};
}  // namespace CryptoFramework
}  // namespace OHOS
#endif
