/*
 * Copyright (c) 2022 Huawei Device Co., Ltd.
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

#ifndef HILOG_HILOG_WRAPPER_H
#define HILOG_HILOG_WRAPPER_H

#define LOG_TAG                 "HilogApiMgr"

#if defined(__LITEOS_M__)
#include "log.h"
#else
#include "hilog/log.h"
#endif

#ifdef __cplusplus
extern "C" {
#endif // __cplusplus

#define FILENAME            (__builtin_strrchr(__FILE__, '/') ? __builtin_strrchr(__FILE__, '/') + 1 : __FILE__)
#define FORMATED(fmt, ...)  "[%s] %s# " fmt, FILENAME, __FUNCTION__, ##__VA_ARGS__

#ifdef HILOG_HILOGD
#undef HILOG_HILOGD
#endif

#ifdef HILOG_HILOGI
#undef HILOG_HILOGI
#endif

#ifdef HILOG_HILOGW
#undef HILOG_HILOGW
#endif

#ifdef HILOG_HILOGE
#undef HILOG_HILOGE
#endif

#ifdef HILOG_HILOGF
#undef HILOG_HILOGF
#endif

#ifdef __LITEOS_M__
#define HILOG_HILOGD(...)   HILOG_DEBUG(HILOG_MODULE_POWERMGR, __VA_ARGS__)
#define HILOG_HILOGI(...)   HILOG_INFO(HILOG_MODULE_POWERMGR, __VA_ARGS__)
#define HILOG_HILOGW(...)   HILOG_WARN(HILOG_MODULE_POWERMGR, __VA_ARGS__)
#define HILOG_HILOGE(...)   HILOG_ERROR(HILOG_MODULE_POWERMGR, __VA_ARGS__)
#define HILOG_HILOGF(...)   HILOG_FATAL(HILOG_MODULE_POWERMGR, __VA_ARGS__)
#else // !__LITEOS_M__
#define HILOG_HILOGD(...)   HILOG_DEBUG(LOG_CORE, FORMATED(__VA_ARGS__))
#define HILOG_HILOGI(...)   HILOG_INFO(LOG_CORE, FORMATED(__VA_ARGS__))
#define HILOG_HILOGW(...)   HILOG_WARN(LOG_CORE, FORMATED(__VA_ARGS__))
#define HILOG_HILOGE(...)   HILOG_ERROR(LOG_CORE, FORMATED(__VA_ARGS__))
#define HILOG_HILOGF(...)   HILOG_FATAL(LOG_CORE, FORMATED(__VA_ARGS__))
#endif // __LITEOS_M__

#ifdef __cplusplus
}
#endif // __cplusplus
#endif // HILOG_HILOG_WRAPPER_H
