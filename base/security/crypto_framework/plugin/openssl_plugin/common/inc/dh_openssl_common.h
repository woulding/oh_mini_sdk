/*
 * Copyright (C) 2023 Huawei Device Co., Ltd.
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

#ifndef HCF_DH_OPENSSL_COMMON_H
#define HCF_DH_OPENSSL_COMMON_H

#include <openssl/dh.h>
#include <openssl/evp.h>

#include "result.h"
#include "utils.h"

#ifdef __cplusplus
extern "C" {
#endif
EVP_PKEY *NewEvpPkeyByDh(DH *dh, bool withDuplicate);
char *GetNidNameByDhId(int32_t pLen);
char *GetNidNameByDhPLen(int32_t pLen);
#ifdef __cplusplus
}
#endif

#endif
