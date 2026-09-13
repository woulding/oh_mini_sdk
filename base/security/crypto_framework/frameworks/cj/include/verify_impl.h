/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
#ifndef VERIFY_IMPL_H
#define VERIFY_IMPL_H

#include "ffi_remote_data.h"
#include "pub_key.h"
#include "signature.h"

namespace OHOS {
namespace CryptoFramework {
class VerifyImpl : public OHOS::FFI::FFIData {
    DECL_TYPE(VerifyImpl, OHOS::FFI::FFIData)
public:
    explicit VerifyImpl(HcfVerify *verify);
    ~VerifyImpl();
    HcfVerify *GetVerify();
    HcfResult Init(HcfPubKey *pubKey);
    HcfResult Update(HcfBlob *input);
    bool Verify(HcfBlob *data, HcfBlob signatureData, int32_t *errCode);
    HcfResult Recover(HcfBlob input, HcfBlob *output);
    HcfResult SetVerifySpecByNum(int32_t itemValue);
    HcfResult SetVerifySpecByArr(HcfBlob itemValue);
    HcfResult GetVerifySpecString(SignSpecItem item, char **itemValue);
    HcfResult GetVerifySpecNum(SignSpecItem item, int32_t *itemValue);
private:
    HcfVerify *verify_ = nullptr;
};
}
}
#endif