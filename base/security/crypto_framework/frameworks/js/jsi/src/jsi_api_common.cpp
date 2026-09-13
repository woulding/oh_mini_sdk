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

#include "jsi_api_common.h"
#include "jsi_api_errcode.h"

namespace OHOS {
namespace ACELite {

void JsiAsyncCallback(const JSIValue thisVal, const JSIValue args, const JSIValue *params, uint8_t paramsNum)
{
    JSIValue para[ARRAY_MAX_SIZE] = { params[ARRAY_INDEX_ZERO], params[ARRAY_INDEX_ONE] };
    JSI::CallFunction(args, thisVal, para, paramsNum);
    JSI::ReleaseValue(para[ARRAY_INDEX_ZERO]);
    JSI::ReleaseValue(para[ARRAY_INDEX_ONE]);
}

}  // namespace ACELite
}  // namespace OHOS
