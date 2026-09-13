/*
 * Copyright (C) 2024 Huawei Device Co., Ltd.
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

#ifndef SM4_COMMON_H
#define SM4_COMMON_H

#include "algorithm_parameter.h"
#include "blob.h"
#include "cipher.h"
#include "sym_key.h"

#ifdef __cplusplus
extern "C" {
#endif

HcfResult GenerateSm4SymKey(HcfSymKey **key);
int32_t GenerateSymKeyForSm4(const char *algoName, HcfSymKey **key);

// use ECB, test abnormal input
int32_t Sm4EncryptWithInput(HcfCipher *cipher, HcfSymKey *key, HcfBlob *input,
    uint8_t *cipherText, int *cipherTextLen);

// test encrypt and decrypt with null plain text
int32_t Sm4DecryptEmptyMsg(HcfCipher *cipher, HcfSymKey *key, HcfParamsSpec *params,
    uint8_t *cipherText, int cipherTextLen);
int32_t Sm4Encrypt(HcfCipher *cipher, HcfSymKey *key, HcfParamsSpec *params,
    uint8_t *cipherText, int *cipherTextLen);
int32_t Sm4Decrypt(HcfCipher *cipher, HcfSymKey *key, HcfParamsSpec *params,
    uint8_t *cipherText, int cipherTextLen);
int32_t Sm4NoUpdateEncrypt(HcfCipher *cipher, HcfSymKey *key, HcfParamsSpec *params,
    uint8_t *cipherText, int *cipherTextLen);
int32_t Sm4NoUpdateDecrypt(HcfCipher *cipher, HcfSymKey *key, HcfParamsSpec *params,
    uint8_t *cipherText, int cipherTextLen);
const char *GetMockClass(void);

#ifdef __cplusplus
}
#endif
#endif
