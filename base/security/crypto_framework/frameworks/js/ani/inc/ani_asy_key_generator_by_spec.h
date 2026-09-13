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

#ifndef ANI_ASY_KEY_GENERATOR_BY_SPEC_H
#define ANI_ASY_KEY_GENERATOR_BY_SPEC_H

#include "ani_common.h"
#include "asy_key_generator.h"

namespace ANI::CryptoFramework {
class AsyKeyGeneratorBySpecImpl {
public:
    AsyKeyGeneratorBySpecImpl();
    explicit AsyKeyGeneratorBySpecImpl(HcfAsyKeyGeneratorBySpec *generator);
    ~AsyKeyGeneratorBySpecImpl();

    KeyPair GenerateKeyPairSync();
    PriKey GeneratePriKeySync();
    PubKey GeneratePubKeySync();
    string GetAlgName();

private:
    HcfAsyKeyGeneratorBySpec *generator_ = nullptr;
};
} // namespace ANI::CryptoFramework

#endif // ANI_ASY_KEY_GENERATOR_BY_SPEC_H
