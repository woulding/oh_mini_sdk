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

#ifndef AES_COMMON_H
#define AES_COMMON_H

#include "algorithm_parameter.h"
#include "blob.h"
#include "cipher.h"
#include "sym_key.h"

#ifdef __cplusplus
extern "C" {
#endif

static const int32_t FILE_BLOCK_SIZE = 1024;
static const int32_t RAND_MAX_NUM = 100;
static const bool IS_DEBUG = false;
static constexpr int32_t CIPHER_TEXT_LEN = 128;
static constexpr int32_t KEY_MATERIAL_LEN = 16;
static constexpr int32_t AES_IV_LEN = 16;   // iv for CBC|CTR|OFB|CFB mode
static constexpr int32_t GCM_IV_LEN = 12;   // GCM
static constexpr int32_t GCM_AAD_LEN = 8;
static constexpr int32_t GCM_TAG_LEN = 16;
static constexpr int32_t GCM_IV_LONG_LEN = 16;
static constexpr int32_t GCM_IV_SHORT_LEN = 9;
static constexpr int32_t GCM_AAD_LONG_LEN = 2049;
static constexpr int32_t GCM_AAD_SHORT_LEN = 1;
static constexpr int32_t CCM_IV_LEN = 7;    // CCM
static constexpr int32_t CCM_AAD_LEN = 8;
static constexpr int32_t CCM_TAG_LEN = 12;
static constexpr int32_t PLAINTEXT_LEN = 13;
static constexpr int32_t AES_KEY_SIZE = 128;

int32_t GenerateSymKey(const char *algoName, HcfSymKey **key);
int32_t ConvertSymKey(const char *algoName, HcfSymKey **key);

/* just rand data fill file for test */
int32_t GeneratorFile(const char *fileName, int32_t genFileSize);
int32_t CompareFileContent(void);
int32_t AesMultiBlockEncrypt(HcfCipher *cipher, HcfSymKey *key, HcfParamsSpec *params);
int32_t AesMultiBlockDecrypt(HcfCipher *cipher, HcfSymKey *key, HcfParamsSpec *params);

// use ECB, test abnormal input
int32_t AesEncryptWithInput(HcfCipher *cipher, HcfSymKey *key, HcfBlob *input,
    uint8_t *cipherText, int *cipherTextLen);
int32_t AesEncrypt(HcfCipher *cipher, HcfSymKey *key, HcfParamsSpec *params,
    uint8_t *cipherText, int *cipherTextLen);
int32_t AesDecrypt(HcfCipher *cipher, HcfSymKey *key, HcfParamsSpec *params,
    uint8_t *cipherText, int cipherTextLen);
int32_t AesNoUpdateEncWithInput(HcfCipher *cipher, HcfSymKey *key, HcfBlob *input,
    uint8_t *cipherText, int *cipherTextLen);

// test encrypt and decrypt with null plain text
int32_t AesDecryptEmptyMsg(HcfCipher *cipher, HcfSymKey *key, HcfParamsSpec *params,
    uint8_t *cipherText, int cipherTextLen);
int32_t AesNoUpdateEncrypt(HcfCipher *cipher, HcfSymKey *key, HcfParamsSpec *params,
    uint8_t *cipherText, int *cipherTextLen);
int32_t AesNoUpdateDecrypt(HcfCipher *cipher, HcfSymKey *key, HcfParamsSpec *params,
    uint8_t *cipherText, int cipherTextLen);

#ifdef __cplusplus
}
#endif
#endif