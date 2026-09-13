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

#ifndef ANI_CIPHER_H
#define ANI_CIPHER_H

#include "ani_common.h"
#include "cipher.h"

namespace ANI::CryptoFramework {
class CipherImpl {
public:
    CipherImpl();
    explicit CipherImpl(HcfCipher *cipher);
    ~CipherImpl();

    void InitSync(CryptoMode opMode, weak::Key key, OptParamsSpec const& params);
    OptDataBlob UpdateSync(DataBlob const& input);
    OptDataBlob DoFinalSync(OptDataBlob const& input);
    void SetCipherSpec(ThCipherSpecItem itemType, array_view<uint8_t> itemValue);
    OptStrUint8Arr GetCipherSpec(ThCipherSpecItem itemType);
    string GetAlgName();

private:
    HcfCipher *cipher_ = nullptr;
};
} // namespace ANI::CryptoFramework

#endif // ANI_CIPHER_H
