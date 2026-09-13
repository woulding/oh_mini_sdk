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

#ifndef HCF_NAPI_SYM_KEY_H
#define HCF_NAPI_SYM_KEY_H

#include <cstdint>
#include "log.h"
#include "napi_key.h"
#include "napi/native_api.h"
#include "napi/native_common.h"
#include "sym_key.h"

namespace OHOS {
namespace CryptoFramework {
class NapiSymKey : public NapiKey {
public:
    explicit NapiSymKey(HcfSymKey *symKey);
    ~NapiSymKey() override;
    HcfSymKey *GetSymKey() const;

    static void DefineSymKeyJSClass(napi_env env);
    static napi_value CreateSymKey(napi_env env);
    static napi_value SymKeyConstructor(napi_env env, napi_callback_info info);
    static napi_value JsClearMem(napi_env env, napi_callback_info info);

    static thread_local napi_ref classRef_;
};
}  // namespace CryptoFramework
}  // namespace OHOS
#endif
