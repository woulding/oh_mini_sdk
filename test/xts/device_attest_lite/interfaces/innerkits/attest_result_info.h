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
#ifndef ATTEST_RESULT_INFO_H
#define ATTEST_RESULT_INFO_H

#include <stdint.h>

#ifdef __cplusplus
#if __cplusplus
extern "C" {
#endif
#endif

#define SOFTWARE_RESULT_DETAIL_SIZE   5
#define MAX_ATTEST_RESULT_SIZE        (SOFTWARE_RESULT_DETAIL_SIZE + 2)

typedef enum {
    SOFTWARE_RESULT_VERSIONID,
    SOFTWARE_RESULT_PATCHLEVEL,
    SOFTWARE_RESULT_ROOTHASH,
    SOFTWARE_RESULT_PCID,
    SOFTWARE_RESULT_RESERVE,
} SOFTWARE_RESULT_DETAIL_TYPE;

typedef struct {
    int32_t authResult;
    int32_t softwareResult;
    int32_t softwareResultDetail[SOFTWARE_RESULT_DETAIL_SIZE];
    int32_t ticketLength;
    char* ticket;
} AttestResultInfo;

#ifdef __cplusplus
#if __cplusplus
}
#endif
#endif

#endif // ATTEST_RESULT_INFO_H