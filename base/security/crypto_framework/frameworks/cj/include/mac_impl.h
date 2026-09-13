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

#ifndef MAC_IMPL_H
#define MAC_IMPL_H

#include "ffi_remote_data.h"
#include "mac.h"
#include "blob.h"
#include "log.h"
#include "result.h"

namespace OHOS {
namespace CryptoFramework {
class MacImpl : public OHOS::FFI::FFIData {
    DECL_TYPE(MacImpl, OHOS::FFI::FFIData)
public:
    explicit MacImpl(HcfMac *macObj);
    ~MacImpl();
    HcfResult MacInit(HcfSymKey *symKey);
    HcfResult MacUpdate(HcfBlob *input);
    HcfResult MacDoFinal(HcfBlob *output);
    uint32_t GetMacLength();

private:
    HcfMac *macObj_ = nullptr;
};
}
}

#endif // MAC_IMPL_H
