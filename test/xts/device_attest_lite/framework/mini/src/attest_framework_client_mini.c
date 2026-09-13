/*
 * Copyright (C) 2022 Huawei Device Co., Ltd.
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

#include <stdio.h>
#include "devattest_configuration.h"
#include "devattest_errno.h"
#include "devattest_interface.h"
#include "attest_entry.h"

int32_t StartDevAttestTask(void)
{
    osThreadAttr_t attr = {0};
    attr.stack_size = LITEOS_M_STACK_SIZE;
    attr.priority = osPriorityNormal;
    attr.name = ATTEST_TASK_THREAD_NAME;
    if (osThreadNew((osThreadFunc_t)AttestTask, NULL, &attr) == NULL) {
        return DEVATTEST_FAIL;
    }
    return DEVATTEST_SUCCESS;
}

int32_t GetAttestStatus(AttestResultInfo* attestResultInfo)
{
    return EntryGetAttestStatus(attestResultInfo);
}
