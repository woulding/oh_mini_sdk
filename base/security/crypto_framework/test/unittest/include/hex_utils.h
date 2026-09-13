/*
 * Copyright (C) 2026 Huawei Device Co., Ltd.
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

#ifndef HEX_UTILS_H
#define HEX_UTILS_H

#include "blob.h"
#include "result.h"

#ifdef __cplusplus
extern "C" {
#endif

int32_t HexCharToVal(char ch);
HcfResult HexStringToBlob(const char *hexStr, HcfBlob *blob);
void PrintfHex(const char *tag, uint8_t *in, size_t inLen);

#ifdef __cplusplus
}
#endif

#endif