/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
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
#ifndef DH_KEY_UTIL_IMPL_H
#define DH_KEY_UTIL_IMPL_H

#include "dh_key_util.h"
#include "blob.h"

namespace OHOS {
namespace CryptoFramework {
class DHKeyUtilImpl {
public:
    explicit DHKeyUtilImpl();
    ~DHKeyUtilImpl();
    static HcfDhCommParamsSpec *GenDHCommonParamsSpec(int32_t pLen, int32_t skLen, int32_t *errCode);
};
}
}
#endif