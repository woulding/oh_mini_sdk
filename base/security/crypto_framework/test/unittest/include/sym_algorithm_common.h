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

#ifndef SYM_ALGORITHM_COMMON_H
#define SYM_ALGORITHM_COMMON_H

#include "algorithm_parameter.h"
#include "blob.h"
#include "cipher.h"
#include "sym_key.h"

#ifdef __cplusplus
extern "C" {
#endif

static const int32_t SYM_ALG_IV_LEN = 8;
static const int32_t SYM_ALG_CIPHER_TEXT_MAX_LEN = 256;
static const int32_t SYM_ALG_PLAINTEXT_LEN = 27;

int32_t SymAlgGenerateSymKey(const char *algoName, HcfSymKey **key);

int32_t SymAlgConvertSymKey(const char *algoName, const uint8_t *keyMaterial, uint32_t keyLen,
    HcfSymKey **key);

int32_t SymAlgEncrypt(HcfCipher *cipher, HcfSymKey *key, HcfParamsSpec *params,
    uint8_t *cipherText, int *cipherTextLen);

int32_t SymAlgDecrypt(HcfCipher *cipher, HcfSymKey *key, HcfParamsSpec *params,
    uint8_t *cipherText, int cipherTextLen);

int32_t SymAlgNoUpdateEncrypt(HcfCipher *cipher, HcfSymKey *key, HcfParamsSpec *params,
    uint8_t *cipherText, int *cipherTextLen);

int32_t SymAlgNoUpdateDecrypt(HcfCipher *cipher, HcfSymKey *key, HcfParamsSpec *params,
    uint8_t *cipherText, int cipherTextLen);

#ifdef __cplusplus
}
#endif
#endif
