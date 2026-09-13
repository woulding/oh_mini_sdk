/*
 * Copyright (C) 2024 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#ifndef JSI_API_H
#define JSI_API_H

#include "jsi/jsi.h"
#include "jsi/jsi_types.h"

namespace OHOS {
namespace ACELite {
class CryptoFrameworkLiteModule final : public MemoryHeap {
public:
    CryptoFrameworkLiteModule() {}
    ~CryptoFrameworkLiteModule() {};

    static JSIValue CreateMd(const JSIValue thisVal, const JSIValue *args, uint8_t argsNum);
    static JSIValue CreateRandom(const JSIValue thisVal, const JSIValue *args, uint8_t argsNum);
    static void OnDestroy(void);

private:
    // Md
    static JSIValue Update(const JSIValue thisVal, const JSIValue *args, uint8_t argsNum);
    static JSIValue UpdateSync(const JSIValue thisVal, const JSIValue *args, uint8_t argsNum);
    static JSIValue Digest(const JSIValue thisVal, const JSIValue *args, uint8_t argsNum);
    static JSIValue DigestSync(const JSIValue thisVal, const JSIValue *args, uint8_t argsNum);
    static JSIValue GetMdLength(const JSIValue thisVal, const JSIValue *args, uint8_t argsNum);

    // Random
    static JSIValue GenerateRandom(const JSIValue thisVal, const JSIValue *args, uint8_t argsNum);
    static JSIValue GenerateRandomSync(const JSIValue thisVal, const JSIValue *args, uint8_t argsNum);
    static JSIValue SetSeed(const JSIValue thisVal, const JSIValue *args, uint8_t argsNum);
    static JSIValue EnableHardwareEntropy(const JSIValue thisVal, const JSIValue *args, uint8_t argsNum);
    static void MdDestroy(void);
    static void RandomDestroy(void);
};

void InitCryptoFrameworkModule(JSIValue exports);

}  // namespace ACELite
}  // namespace OHOS
#endif // JSI_API_H
