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

#ifndef ANI_RAND_H
#define ANI_RAND_H

#include "ani_common.h"
#include "rand.h"

namespace ANI::CryptoFramework {
class RandomImpl {
public:
    RandomImpl();
    explicit RandomImpl(HcfRand *rand);
    ~RandomImpl();

    DataBlob GenerateRandomSync(int32_t len);
    void SetSeed(DataBlob const& seed);
    void EnableHardwareEntropy();
    string GetAlgName();

private:
    HcfRand *rand_ = nullptr;
};
} // namespace ANI::CryptoFramework

#endif // ANI_RAND_H
