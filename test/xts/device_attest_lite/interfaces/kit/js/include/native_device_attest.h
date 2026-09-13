/*
 * Copyright (c) 2023 Huawei Device Co., Ltd.
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

#ifndef NATIVE_DEVICE_ATTEST_H
#define NATIVE_DEVICE_ATTEST_H

#include "jsi.h"

namespace OHOS {
namespace ACELite {
struct FuncParams {
    JSIValue args = JSI::CreateUndefined();
    JSIValue thisVal = JSI::CreateUndefined();
};

class NativeDeviceAttest {
public:
    NativeDeviceAttest() = default;
    ~NativeDeviceAttest() = default;
    static JSIValue GetAttestResultInfoSync(const JSIValue thisVal, const JSIValue *args, uint8_t argsNum);
    static JSIValue GetAttestResultInfoAsync(const JSIValue thisVal, const JSIValue *args, uint8_t argsNum);
};
} // namespace ACELite
} // namespace OHOS

#endif // NATIVE_DEVICE_ATTEST_H