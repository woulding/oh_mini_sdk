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

#ifndef JSI_API_ERRCODE_H
#define JSI_API_ERRCODE_H

#include "jsi/jsi.h"
#include "jsi/jsi_types.h"

namespace OHOS {
namespace ACELite {

void CallbackErrorCodeOrDataResult(const JSIValue thisVal, const JSIValue args, int32_t errCode, const JSIValue data);
JSIValue ThrowErrorCodeResult(int32_t errorCode);

}  // namespace ACELite
}  // namespace OHOS
#endif // JSI_API_ERRCODE_H
