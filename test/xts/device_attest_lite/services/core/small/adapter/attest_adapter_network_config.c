/*
 * Copyright (C) 2023 Huawei Device Co., Ltd.
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

#ifndef __LITEOS_M__

#include "attest_adapter_oem.h"
#include "attest_adapter.h"

int32_t AttestReadNetworkConfig(char* buffer, uint32_t bufferLen)
{
    return OEMReadNetworkConfig(buffer, bufferLen);
}

int32_t AttestWriteNetworkConfig(const char* data, uint32_t len)
{
    return OEMWriteNetworkConfig(data, len);
}
#endif
