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

#ifndef HCF_NAPI_KEY_PAIR_H
#define HCF_NAPI_KEY_PAIR_H

#include <cstdint>
#include "log.h"
#include "key_pair.h"
#include "napi/native_api.h"
#include "napi/native_common.h"

namespace OHOS {
namespace CryptoFramework {
class NapiKeyPair {
public:
    explicit NapiKeyPair(HcfKeyPair *keyPair);
    ~NapiKeyPair();

    napi_value ConvertToJsKeyPair(napi_env env);

    static void DefineKeyPairJSClass(napi_env env);
    static napi_value KeyPairConstructor(napi_env env, napi_callback_info info);

    static thread_local napi_ref classRef_;

private:
    HcfKeyPair *keyPair_ = nullptr;
};
}  // namespace CryptoFramework
}  // namespace OHOS
#endif
