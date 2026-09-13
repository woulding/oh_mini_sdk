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

#ifndef DEVATTEST_LOG_H
#define DEVATTEST_LOG_H

#include "hilog/log.h"

#ifdef __cplusplus
#if __cplusplus
extern "C" {
#endif
#endif

#define ATTEST_LOG_DOMAIN 0xD005D00
#define ATTEST_LOG_LABEL "DEVATTEST"

#define HILOGD(fmt, ...)    \
    ((void)HiLogPrint(LOG_CORE, LOG_DEBUG, ATTEST_LOG_DOMAIN, ATTEST_LOG_LABEL, fmt, ##__VA_ARGS__))
#define HILOGI(fmt, ...)    \
    ((void)HiLogPrint(LOG_CORE, LOG_INFO, ATTEST_LOG_DOMAIN, ATTEST_LOG_LABEL, fmt, ##__VA_ARGS__))
#define HILOGW(fmt, ...)    \
    ((void)HiLogPrint(LOG_CORE, LOG_WARN, ATTEST_LOG_DOMAIN, ATTEST_LOG_LABEL, fmt, ##__VA_ARGS__))
#define HILOGE(fmt, ...)    \
    ((void)HiLogPrint(LOG_CORE, LOG_ERROR, ATTEST_LOG_DOMAIN, ATTEST_LOG_LABEL, fmt, ##__VA_ARGS__))
#define HILOGT(fmt, ...)    \
    ((void)HiLogPrint(LOG_CORE, LOG_FATAL, ATTEST_LOG_DOMAIN, ATTEST_LOG_LABEL, fmt, ##__VA_ARGS__))

#ifdef __cplusplus
#if __cplusplus
}
#endif
#endif

#endif // DEVATTEST_LOG_H