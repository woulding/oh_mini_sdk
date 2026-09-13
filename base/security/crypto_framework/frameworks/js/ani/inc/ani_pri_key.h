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

#ifndef ANI_PRI_KEY_H
#define ANI_PRI_KEY_H

#include "ani_common.h"
#include "pri_key.h"

namespace ANI::CryptoFramework {
class PriKeyImpl {
public:
    PriKeyImpl();
    explicit PriKeyImpl(HcfPriKey *priKey, bool owner = true);
    ~PriKeyImpl();

    int64_t GetPriKeyObj();
    void ClearMem();
    OptKeySpec GetAsyKeySpec(ThAsyKeySpecItem itemType);
    DataBlob GetEncodedDer(string_view format);
    string GetEncodedPem(string_view format);
    string GetEncodedPemEx(string_view format, KeyEncodingConfig const& config);
    PubKey GetPubKeySync();
    int64_t GetKeyObj();
    DataBlob GetEncoded();
    int GetKeySize();
    array<uint8_t> GetKeyDataSync(AsyKeyDataItem itemType);
    string GetFormat();
    string GetAlgName();
private:
    HcfPriKey *priKey_ = nullptr;
    bool owner_ = false;
};
} // namespace ANI::CryptoFramework

#endif // ANI_PRI_KEY_H
