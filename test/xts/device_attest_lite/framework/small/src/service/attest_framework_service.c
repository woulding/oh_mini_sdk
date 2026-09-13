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

#include <stdio.h>
#include <unistd.h>
#include <samgr_lite.h>

#include "devattest_log.h"
#include "attest_utils_timer.h"

#define ATTEST_SLEEP_TIME 100

static ATTEST_TIMER_ID g_AttestSaTimerId = NULL;

static void ATTEST_SystemInit(void *argv)
{
    (void)argv;
    HILOGI("devattest-start");
    SAMGR_Bootstrap();
    return;
}

int main(void)
{
    // delay start to make sure register success
    int32_t ret = AttestStartTimerTask(ATTEST_TIMER_TYPE_ONCE, ATTEST_SLEEP_TIME,
        &ATTEST_SystemInit, NULL, &g_AttestSaTimerId);
    if (ret != 0) {
        HILOGE("[ATTEST SERVICE]Create TimerTask err");
    }
    while (1) {
        pause();
    }
    return 0;
}
