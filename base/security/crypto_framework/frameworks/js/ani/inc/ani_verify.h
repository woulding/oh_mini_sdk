/*
 * Copyright (c) 2025-2025 Huawei Device Co., Ltd.
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

#ifndef ANI_VERIFY_H
#define ANI_VERIFY_H

#include "ani_common.h"
#include "signature.h"

namespace ANI::CryptoFramework {
class VerifyImpl {
public:
    VerifyImpl();
    explicit VerifyImpl(HcfVerify *verify);
    ~VerifyImpl();

    void InitSync(weak::PubKey pubKey);
    void UpdateSync(DataBlob const& input);
    bool VerifySync(OptDataBlob const& data, DataBlob const& signature);
    OptDataBlob RecoverSync(DataBlob const& signature);
    void SetVerifySpec(ThSignSpecItem itemType, OptIntUint8Arr const& itemValue);
    void SetVerifySpecBoolean(ThSignSpecItem itemType, bool itemValue);
    OptStrInt GetVerifySpec(ThSignSpecItem itemType);
    string GetAlgName();

private:
    HcfVerify *verify_ = nullptr;
};
} // namespace ANI::CryptoFramework

#endif // ANI_VERIFY_H
