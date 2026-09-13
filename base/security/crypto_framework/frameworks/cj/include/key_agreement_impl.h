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
#ifndef KEY_AGREEMENT_IMPL_H
#define KEY_AGREEMENT_IMPL_H

#include "ffi_remote_data.h"
#include "key_agreement.h"
#include "pri_key.h"
#include "pub_key.h"

namespace OHOS {
namespace CryptoFramework {
class KeyAgreementImpl : public OHOS::FFI::FFIData {
    DECL_TYPE(KeyAgreementImpl, OHOS::FFI::FFIData)
public:
    explicit KeyAgreementImpl(HcfKeyAgreement *keyAgreement);
    ~KeyAgreementImpl();
    HcfKeyAgreement *GetKeyAgreement();
    HcfBlob GenerateSecret(HcfPriKey *priKey, HcfPubKey *pubKey, int32_t *errCode);
private:
    HcfKeyAgreement *keyAgreement_ = nullptr;
};
}
}
#endif
