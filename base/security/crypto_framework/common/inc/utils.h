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

#ifndef HCF_UTILS_H
#define HCF_UTILS_H

#include <stdbool.h>
#include <stdint.h>
#include "blob.h"
#include "object_base.h"
#include "result.h"

#ifdef __cplusplus
extern "C" {
#endif

bool HcfIsStrValid(const char *str, uint32_t maxLen);
bool HcfIsBlobValid(const HcfBlob *blob);
bool HcfIsClassMatch(const HcfObjectBase *obj, const char *className);
size_t HcfStrlen(const char *str);

void HcfGetCryptoOperationErrMsg(HcfResult errCode, const char **oldMsg, char **newMsg);

#ifdef __cplusplus
}
#endif

#endif
