/*
 * Copyright (c) 2026 Huawei Device Co., Ltd.
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

#ifndef ANI_KEM_H
#define ANI_KEM_H

#include "ani_common.h"
#include "kem.h"

namespace ANI::CryptoFramework {
class KemImpl {
public:
    KemImpl();
    explicit KemImpl(HcfKem *kem);
    ~KemImpl();

    KemEncapResult EncapsulateSync(weak::PubKey pubKey, OptUint8Arr const& ikme);
    array<uint8_t> DecapsulateSync(weak::PriKey priKey, array_view<uint8_t> wrappedKey);

private:
    HcfKem *kem_ = nullptr;
};
} // namespace ANI::CryptoFramework

#endif // ANI_KEM_H
