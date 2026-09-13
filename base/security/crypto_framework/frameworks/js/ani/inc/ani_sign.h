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

#ifndef ANI_SIGN_H
#define ANI_SIGN_H

#include "ani_common.h"
#include "signature.h"

namespace ANI::CryptoFramework {
class SignImpl {
public:
    SignImpl();
    explicit SignImpl(HcfSign *sign);
    ~SignImpl();

    void InitSync(weak::PriKey priKey);
    void UpdateSync(DataBlob const& data);
    DataBlob SignSync(OptDataBlob const& data);
    void SetSignSpec(ThSignSpecItem itemType, OptIntUint8Arr const& itemValue);
    void SetSignSpecBoolean(ThSignSpecItem itemType, bool itemValue);
    OptStrInt GetSignSpec(ThSignSpecItem itemType);
    string GetAlgName();

private:
    HcfSign *sign_ = nullptr;
};
} // namespace ANI::CryptoFramework

#endif // ANI_SIGN_H
