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

#include <securec.h>
#include "devattest_configuration.h"
#include "attest_type.h"
#include "attest_error.h"
#include "attest_utils_log.h"
#include "attest_utils_timer.h"
#include "attest_service.h"
#include "attest_entry.h"

static ATTEST_TIMER_ID g_ProcAttestTimerId = NULL;


int32_t AttestTask(void)
{
    ATTEST_LOG_INFO("[AttestTask] Begin.");
    // 执行主流程代码
    int32_t ret = ProcAttest();
    if (ret != ATTEST_OK) {
        ATTEST_LOG_ERROR("[AttestTask] Proc failed ret = %d.", ret);
    }
    ret = AttestCreateTimerTask();
    if (ret != ATTEST_OK) {
        ATTEST_LOG_ERROR("[AttestTask] TimerTask failed ret = %d.", ret);
    }
    ATTEST_LOG_INFO("[AttestTask] End.");
    return ret;
}

static int32_t CopyAttestResult(int32_t *resultArray, AttestResultInfo *attestResultInfo)
{
    if (resultArray == NULL) {
        return ATTEST_ERR;
    }
    int32_t *head = resultArray;
    attestResultInfo->authResult = *head;
    head++;
    attestResultInfo->softwareResult = *head;
    for (int i = 0; i < SOFTWARE_RESULT_DETAIL_SIZE; i++) {
        attestResultInfo->softwareResultDetail[i] = *(++head);
    }
    return ATTEST_OK;
}

int32_t EntryGetAttestStatus(AttestResultInfo* attestResultInfo)
{
    if (attestResultInfo == NULL) {
        return ATTEST_ERR;
    }
    int32_t resultArraySize = MAX_ATTEST_RESULT_SIZE * sizeof(int32_t);
    int32_t *resultArray = (int32_t *)malloc(resultArraySize);
    if (resultArray == NULL) {
        ATTEST_LOG_ERROR("malloc resultArray failed");
        return ATTEST_ERR;
    }
    (void)memset_s(resultArray, resultArraySize, 0, resultArraySize);
    int32_t ticketLength = 0;
    char* ticketStr = NULL;
    int32_t ret = ATTEST_OK;
    do {
        ret = QueryAttestStatus(&resultArray, MAX_ATTEST_RESULT_SIZE, &ticketStr, &ticketLength);
        if (ret != ATTEST_OK) {
            ATTEST_LOG_ERROR("QueryAttest failed");
            break;
        }
        ret = CopyAttestResult(resultArray,  attestResultInfo);
        if (ret != ATTEST_OK) {
            ATTEST_LOG_ERROR("copy attest result failed");
            break;
        }
        attestResultInfo->ticketLength = ticketLength;
        attestResultInfo->ticket = ticketStr;
    } while (0);
    free(resultArray);
    resultArray = NULL;
    ATTEST_LOG_INFO("GetAttestStatus end success");
    return ret;
}

int32_t AttestCreateTimerTask(void)
{
    return 0;
}

int32_t AttestDestroyTimerTask(void)
{
    return AttestStopTimerTask(g_ProcAttestTimerId);
}
