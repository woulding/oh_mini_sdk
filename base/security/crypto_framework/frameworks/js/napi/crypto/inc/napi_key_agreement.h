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

#ifndef HCF_NAPI_KEY_AGREEMENT_H
#define HCF_NAPI_KEY_AGREEMENT_H

#include <cstdint>
#include "log.h"
#include "key_agreement.h"
#include "napi/native_api.h"
#include "napi/native_common.h"

namespace OHOS {
namespace CryptoFramework {
class NapiKeyAgreement {
public:
    explicit NapiKeyAgreement(HcfKeyAgreement *keyAgreement);
    ~NapiKeyAgreement();

    HcfKeyAgreement *GetKeyAgreement();

    static void DefineKeyAgreementJSClass(napi_env env, napi_value exports);
    static napi_value KeyAgreementConstructor(napi_env env, napi_callback_info info);
    static napi_value CreateJsKeyAgreement(napi_env env, napi_callback_info info);

    static napi_value JsGenerateSecret(napi_env env, napi_callback_info info);
    static napi_value JsGenerateSecretSync(napi_env env, napi_callback_info info);
    static napi_value JsGetAlgorithm(napi_env env, napi_callback_info info);

    static thread_local napi_ref classRef_;

private:
    HcfKeyAgreement *keyAgreement_ = nullptr;
};
}  // namespace CryptoFramework
}  // namespace OHOS
#endif
