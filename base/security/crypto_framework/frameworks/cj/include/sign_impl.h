/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#ifndef SIGN_IMPL_H
#define SIGN_IMPL_H

#include "ffi_remote_data.h"
#include "signature.h"
#include "blob.h"
#include "result.h"
#include "pri_key.h"

namespace OHOS {
namespace CryptoFramework {
class SignImpl : public OHOS::FFI::FFIData {
    DECL_TYPE(SignImpl, OHOS::FFI::FFIData)
public:
    explicit SignImpl(HcfSign *signObj);
    ~SignImpl();
    HcfResult Init(HcfPriKey *priKey);
    HcfResult Update(HcfBlob *input);
    HcfResult Sign(HcfBlob *input, HcfBlob *output);
    HcfResult SetSignSpecByNum(int32_t itemValue);
    HcfResult SetSignSpecByArr(HcfBlob itemValue);
    HcfResult GetSignSpecString(SignSpecItem item, char **itemValue);
    HcfResult GetSignSpecNum(SignSpecItem item, int32_t *itemValue);

private:
    HcfSign *signObj_ = nullptr;
};
}
}

#endif // SIGN_IMPL_H
