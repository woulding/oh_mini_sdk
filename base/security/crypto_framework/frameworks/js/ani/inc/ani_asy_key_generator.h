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

#ifndef ANI_ASY_KEY_GENERATOR_H
#define ANI_ASY_KEY_GENERATOR_H

#include "ani_common.h"
#include "asy_key_generator.h"

namespace ANI::CryptoFramework {
class AsyKeyGeneratorImpl {
public:
    AsyKeyGeneratorImpl();
    explicit AsyKeyGeneratorImpl(HcfAsyKeyGenerator *generator);
    ~AsyKeyGeneratorImpl();

    KeyPair GenerateKeyPairSync();
    KeyPair ConvertKeySync(OptDataBlob const& pubKey, OptDataBlob const& priKey);
    KeyPair ConvertPemKeySync(OptString const& pubKey, OptString const& priKey);
    KeyPair ConvertPemKeySyncEx(OptString const& pubKey, OptString const& priKey, string_view password);
    string GetAlgName();

private:
    HcfAsyKeyGenerator *generator_ = nullptr;
};
} // namespace ANI::CryptoFramework

#endif // ANI_ASY_KEY_GENERATOR_H
