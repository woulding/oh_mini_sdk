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

#ifndef HCF_NAPI_PUB_KEY_H
#define HCF_NAPI_PUB_KEY_H

#include <cstdint>
#include "log.h"
#include "pub_key.h"
#include "napi_key.h"
#include "napi/native_api.h"
#include "napi/native_common.h"

namespace OHOS {
namespace CryptoFramework {
class NapiPubKey : public NapiKey {
public:
    explicit NapiPubKey(HcfPubKey *pubKey);
    ~NapiPubKey() override;

    HcfPubKey *GetPubKey();
    napi_value ConvertToJsPubKey(napi_env env);

    static void DefinePubKeyJSClass(napi_env env);
    static napi_value PubKeyConstructor(napi_env env, napi_callback_info info);

    static napi_value JsGetEncoded(napi_env env, napi_callback_info info);
    static napi_value JsGetEncodedDer(napi_env env, napi_callback_info info);
    static napi_value JsGetEncodedPem(napi_env env, napi_callback_info info);
    static napi_value JsGetAsyKeySpec(napi_env env, napi_callback_info info);
    static napi_value JsGetKeySize(napi_env env, napi_callback_info info);
    static napi_value JsGetKeyData(napi_env env, napi_callback_info info);
    static napi_value JsGetKeyDataSync(napi_env env, napi_callback_info info);

    static thread_local napi_ref classRef_;
};
}  // namespace CryptoFramework
}  // namespace OHOS
#endif
