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
#ifndef ATTEST_FRAMEWORK_DEFINE_H
#define ATTEST_FRAMEWORK_DEFINE_H

#include "attest_result_info.h"

#ifdef __cplusplus
#if __cplusplus
extern "C" {
#endif
#endif

#define ATTEST_STACK_SIZE     0x1000
#define ATTEST_QUEUE_SIZE     20
#define ATTEST_SERVICE        "attest_service"
#define ATTEST_FEATURE        "attest_feature"

typedef enum {
    ATTEST_FRAMEWORK_MSG_PROC,
    ATTEST_FRAMEWORK_MSG_QUERY,
    ATTEST_FRAMEWORK_MSG_MAX
} AttestFrameworkFuncID;

typedef struct {
    int32_t result;
    AttestResultInfo *attestResultInfo;
} ServiceRspMsg;

#ifdef __cplusplus
#if __cplusplus
}
#endif
#endif

#endif