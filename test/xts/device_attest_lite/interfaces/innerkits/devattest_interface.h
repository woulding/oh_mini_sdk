/*
 * Copyright (C) 2022 Huawei Device Co., Ltd.
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
#ifndef DEVATTEST_INTERFACE_H
#define DEVATTEST_INTERFACE_H

#include "attest_result_info.h"

#ifdef __cplusplus
#if __cplusplus
extern "C" {
#endif
#endif /* __cplusplus */

/**
 * @Desc Asynchronous interface, start device_attest task.
 * @Para Void.
 * @Return Returning 0 represents success, while returning other represents failure.
 */
int32_t StartDevAttestTask(void);

/**
 * @Desc Synchronous interface, get the result of device_attest. And it consume about 10ms.
 * @Para Pointer to the structure of result of device_attest.
 * @Return Returning 0 represents success, while returning other represents failure.
 */
int32_t GetAttestStatus(AttestResultInfo* attestResultInfo);

#ifdef __cplusplus
#if __cplusplus
}
#endif
#endif /* __cplusplus */

#endif