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
#include <stdlib.h>
#include <unistd.h>
#include <string.h>

#include "devattest_errno.h"
#include "devattest_interface.h"

#define ATTEST_SOFTWARE_RESULT_SIZE 5
#define ATTEST_ARGC_PARAM_2 2

int main(int argc, char *argv[])
{
    int32_t ret = DEVATTEST_SUCCESS;

    if (argc == ATTEST_ARGC_PARAM_2 && strcmp(argv[1], "start") == 0) {
        ret = StartDevAttestTask();
        printf("[CLIENT MAIN] StartDevAttestTask ret:%d.\n", ret);
    } else {
        AttestResultInfo attestResultInfo = { 0 };
        attestResultInfo.ticket = NULL;
        printf("[CLIENT MAIN] query.\n");
        ret = GetAttestStatus(&attestResultInfo);
        if (ret != DEVATTEST_SUCCESS) {
            printf("[CLIENT MAIN] wrong. ret:%d\n", ret);
        }

        printf("[CLIENT MAIN] auth:%d, software:%d\n",
            attestResultInfo.authResult, attestResultInfo.softwareResult);
        for (int32_t i = 0; i < ATTEST_SOFTWARE_RESULT_SIZE; i++) {
            printf("[CLIENT MAIN] softwareResultDetail[%d]:%d\n", i, attestResultInfo.softwareResultDetail[i]);
        }

        printf("[CLIENT MAIN] ticketLength:%d, ticket:%s\n",
            attestResultInfo.ticketLength, attestResultInfo.ticket);
        if (attestResultInfo.ticketLength != 0) {
            free(attestResultInfo.ticket);
            attestResultInfo.ticket = NULL;
        }
    }
    printf("[CLIENT MAIN] end.\n");
    while (1) {
        pause();
    }
    return 0;
}
