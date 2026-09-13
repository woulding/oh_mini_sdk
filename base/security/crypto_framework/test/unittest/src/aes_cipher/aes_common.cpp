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

#include "aes_common.h"
#include <fstream>
#include <iostream>
#include "securec.h"

#include "aes_openssl.h"
#include "blob.h"
#include "cipher.h"
#include "detailed_iv_params.h"
#include "detailed_gcm_params.h"
#include "detailed_ccm_params.h"
#include "log.h"
#include "memory.h"
#include "sym_common_defines.h"
#include "sym_key_generator.h"

using namespace std;

int32_t GenerateSymKey(const char *algoName, HcfSymKey **key)
{
    HcfSymKeyGenerator *generator = nullptr;

    int32_t ret = HcfSymKeyGeneratorCreate(algoName, &generator);
    if (ret != 0) {
        LOGE("HcfSymKeyGeneratorCreate failed!");
        return ret;
    }

    ret = generator->generateSymKey(generator, key);
    if (ret != 0) {
        LOGE("generateSymKey failed!");
    }
    HcfObjDestroy(reinterpret_cast<HcfObjectBase *>(generator));
    return ret;
}

int32_t ConvertSymKey(const char *algoName, HcfSymKey **key)
{
    HcfSymKeyGenerator *generator = nullptr;
    uint8_t keyMaterial[] = {
        0xba, 0x3b, 0xc2, 0x71, 0x21, 0x1e, 0x30, 0x56,
        0xad, 0x47, 0xfc, 0x5a, 0x46, 0x39, 0xee, 0x7c
    };
    HcfBlob keyTmpBlob = {.data = reinterpret_cast<uint8_t *>(keyMaterial), .len = 16};

    int32_t ret = HcfSymKeyGeneratorCreate(algoName, &generator);
    if (ret != 0) {
        LOGE("HcfSymKeyGeneratorCreate failed!%{public}d", ret);
        return ret;
    }

    ret = generator->convertSymKey(generator, &keyTmpBlob, key);
    if (ret != 0) {
        LOGE("generateSymKey failed!");
    }
    HcfObjDestroy(reinterpret_cast<HcfObjectBase *>(generator));
    return ret;
}

/* just rand data fill file for test */
int32_t GeneratorFile(const char *fileName, int32_t genFileSize)
{
    if (genFileSize == 0) {
        return 0;
    }
    std::ifstream file(fileName);

    if (file.good()) {
        file.close();
        return 0;
    }
    ofstream outfile(fileName, ios::out|ios::binary|ios::app);
    if (outfile.is_open()) {
        uint8_t buffer[FILE_BLOCK_SIZE] = {0};
        while (genFileSize) {
            for (uint32_t i = 0; i < FILE_BLOCK_SIZE; i++) {
                buffer[i] = (rand() % RAND_MAX_NUM) + 1;
            }
            genFileSize -= FILE_BLOCK_SIZE;
            outfile.write(reinterpret_cast<const char *>(buffer), FILE_BLOCK_SIZE);
        }
        outfile.close();
    }
    return 0;
}

int32_t CompareFileContent()
{
    int32_t ret = -1;
    ifstream infile1;
    ifstream infile2;
    infile1.open("/data/test_aes.txt", ios::in|ios::binary);
    infile1.seekg (0, infile1.end);
    uint32_t length1 = infile1.tellg();
    infile1.seekg (0, infile1.beg);

    infile2.open("/data/test_aes_new.txt", ios::in|ios::binary);
    infile2.seekg (0, infile2.end);
    uint32_t length2 = infile2.tellg();
    infile2.seekg (0, infile2.beg);
    if (length1 != length2) {
        return ret;
    }
    uint8_t buffer1[FILE_BLOCK_SIZE] = {0};
    uint8_t buffer2[FILE_BLOCK_SIZE] = {0};
    for (uint32_t i = 0; i < length1 / FILE_BLOCK_SIZE; i++) {
        infile1.read(reinterpret_cast<char *>(buffer1), FILE_BLOCK_SIZE);
        infile2.read(reinterpret_cast<char *>(buffer2), FILE_BLOCK_SIZE);
        ret = memcmp(buffer1, buffer2, FILE_BLOCK_SIZE);
        if (ret != 0) {
            goto CLEAR_UP;
        }
    }
CLEAR_UP:
    infile1.close();
    infile2.close();
    return ret;
}

int32_t AesMultiBlockEncrypt(HcfCipher *cipher, HcfSymKey *key, HcfParamsSpec *params)
{
    HcfBlob output = {};
    ifstream infile;
    ofstream outfile;
    infile.open("/data/test_aes.txt", ios::in|ios::binary);
    infile.seekg (0, infile.end);
    uint32_t length = infile.tellg();
    infile.seekg (0, infile.beg);
    uint8_t buffer[1024] = {0};
    outfile.open("/data/test_aes_enc.txt", ios::out|ios::binary);
    HcfBlob input = {.data = reinterpret_cast<uint8_t *>(buffer), .len = FILE_BLOCK_SIZE};
    uint32_t count = length / FILE_BLOCK_SIZE;

    int32_t ret = cipher->init(cipher, ENCRYPT_MODE, reinterpret_cast<HcfKey *>(key), params);
    if (ret != 0) {
        LOGE("init failed! %{public}d", ret);
        goto CLEAR_UP;
    }
    for (uint32_t i = 0; i < count; i++) {
        infile.read(reinterpret_cast<char *>(buffer), FILE_BLOCK_SIZE);
        ret = cipher->update(cipher, &input, &output);
        if (ret != 0) {
            LOGE("update failed!");
            goto CLEAR_UP;
        }
        if (output.data != nullptr && output.len > 0) {
            outfile.write(reinterpret_cast<const char *>(output.data), output.len);
        }
        if (output.data != nullptr) {
            HcfFree(output.data);
            output.data = nullptr;
        }
    }
    ret = cipher->doFinal(cipher, nullptr, &output);
    if (ret != 0) {
        LOGE("doFinal failed!");
        goto CLEAR_UP;
    }
    if (output.data != nullptr && output.len > 0) {
        outfile.write(reinterpret_cast<const char *>(output.data), output.len);
    }

    if (output.data != nullptr) {
        HcfFree(output.data);
        output.data = nullptr;
    }
CLEAR_UP:
    outfile.close();
    infile.close();

    return ret;
}

int32_t AesMultiBlockDecrypt(HcfCipher *cipher, HcfSymKey *key, HcfParamsSpec *params)
{
    HcfBlob output = {};
    ifstream infile;
    ofstream outfile;
    infile.open("/data/test_aes_enc.txt", ios::in|ios::binary);
    infile.seekg (0, infile.end);
    uint32_t length = infile.tellg();
    infile.seekg (0, infile.beg);
    uint8_t buffer[1024] = {0};
    outfile.open("/data/test_aes_new.txt", ios::out|ios::binary);
    HcfBlob input = {.data = reinterpret_cast<uint8_t *>(buffer), .len = FILE_BLOCK_SIZE};

    uint32_t count = length / FILE_BLOCK_SIZE;
    int32_t ret = cipher->init(cipher, DECRYPT_MODE, reinterpret_cast<HcfKey *>(key), params);
    if (ret != 0) {
        LOGE("init failed! %{public}d", ret);
        goto CLEAR_UP;
    }
    for (uint32_t i = 0; i < count; i++) {
        infile.read(reinterpret_cast<char *>(buffer), FILE_BLOCK_SIZE);
        ret = cipher->update(cipher, &input, &output);
        if (ret != 0) {
            LOGE("update failed!");
            goto CLEAR_UP;
        }
        if (output.data != nullptr && output.len > 0) {
            outfile.write(reinterpret_cast<const char *>(output.data), output.len);
        }
        if (output.data != nullptr) {
            HcfFree(output.data);
            output.data = nullptr;
        }
    }
    ret = cipher->doFinal(cipher, nullptr, &output);
    if (ret != 0) {
        LOGE("doFinal failed!");
        goto CLEAR_UP;
    }
    if (output.data != nullptr && output.len > 0) {
        outfile.write(reinterpret_cast<const char *>(output.data), output.len);
    }

    if (output.data != nullptr) {
        HcfFree(output.data);
        output.data = nullptr;
    }
CLEAR_UP:
    outfile.close();
    infile.close();

    return ret;
}

// use ECB, test abnormal input
int32_t AesEncryptWithInput(HcfCipher *cipher, HcfSymKey *key, HcfBlob *input,
    uint8_t *cipherText, int *cipherTextLen)
{
    HcfBlob output = { .data = nullptr, .len = 0 };
    int32_t maxLen = *cipherTextLen;
    int32_t ret = cipher->init(cipher, ENCRYPT_MODE, &(key->key), nullptr);
    if (ret != 0) {
        LOGE("init failed! %{public}d", ret);
        return ret;
    }

    ret = cipher->update(cipher, input, &output);
    if (ret != 0) {
        LOGE("update failed!");
        return ret;
    }
    *cipherTextLen = output.len;
    if (output.data != nullptr) {
        if (memcpy_s(cipherText, maxLen, output.data, output.len) != EOK) {
            HcfBlobDataFree(&output);
            return -1;
        }
        HcfBlobDataFree(&output);
    }

    ret = cipher->doFinal(cipher, nullptr, &output);
    if (ret != 0) {
        LOGE("doFinal failed!");
        return ret;
    }
    if (output.data != nullptr) {
        if (memcpy_s(cipherText + *cipherTextLen, maxLen - *cipherTextLen, output.data, output.len) != EOK) {
            HcfBlobDataFree(&output);
            return -1;
        }
        *cipherTextLen += output.len;
        HcfBlobDataFree(&output);
    }

    return 0;
}

int32_t AesEncrypt(HcfCipher *cipher, HcfSymKey *key, HcfParamsSpec *params,
    uint8_t *cipherText, int *cipherTextLen)
{
    uint8_t plainText[] = "this is test!";
    HcfBlob input = {.data = reinterpret_cast<uint8_t *>(plainText), .len = 13};
    HcfBlob output = {};
    int32_t maxLen = *cipherTextLen;
    int32_t ret = cipher->init(cipher, ENCRYPT_MODE, reinterpret_cast<HcfKey *>(key), params);
    if (ret != 0) {
        LOGE("init failed! %{public}d", ret);
        return ret;
    }

    ret = cipher->update(cipher, &input, &output);
    if (ret != 0) {
        LOGE("update failed!");
        return ret;
    }
    *cipherTextLen = output.len;
    if (output.data != nullptr) {
        if (memcpy_s(cipherText, maxLen, output.data, output.len) != EOK) {
            HcfBlobDataFree(&output);
            return -1;
        }
        HcfBlobDataFree(&output);
    }

    ret = cipher->doFinal(cipher, nullptr, &output);
    if (ret != 0) {
        LOGE("doFinal failed!");
        return ret;
    }
    if (output.data != nullptr) {
        if (memcpy_s(cipherText + *cipherTextLen, maxLen - *cipherTextLen, output.data, output.len) != EOK) {
            HcfBlobDataFree(&output);
            return -1;
        }
        *cipherTextLen += output.len;
        HcfBlobDataFree(&output);
    }

    return 0;
}

int32_t AesDecrypt(HcfCipher *cipher, HcfSymKey *key, HcfParamsSpec *params,
    uint8_t *cipherText, int cipherTextLen)
{
    uint8_t plainText[] = "this is test!";
    HcfBlob input = {.data = reinterpret_cast<uint8_t *>(cipherText), .len = static_cast<size_t>(cipherTextLen)};
    HcfBlob output = {};
    int32_t maxLen = cipherTextLen;
    int32_t ret = cipher->init(cipher, DECRYPT_MODE, reinterpret_cast<HcfKey *>(key), params);
    if (ret != 0) {
        LOGE("init failed! %{public}d", ret);
        return ret;
    }

    ret = cipher->update(cipher, &input, &output);
    if (ret != 0) {
        LOGE("update failed!");
        return ret;
    }
    cipherTextLen = output.len;
    if (output.data != nullptr) {
        if (memcpy_s(cipherText, maxLen, output.data, output.len) != EOK) {
            HcfBlobDataFree(&output);
            return -1;
        }
        HcfBlobDataFree(&output);
    }

    ret = cipher->doFinal(cipher, nullptr, &output);
    if (ret != 0) {
        LOGE("doFinal failed!");
        return ret;
    }
    if (output.data != nullptr) {
        if (memcpy_s(cipherText + cipherTextLen, maxLen - cipherTextLen, output.data, output.len) != EOK) {
            HcfBlobDataFree(&output);
            return -1;
        }
        cipherTextLen += output.len;
        HcfBlobDataFree(&output);
    }

    if (cipherTextLen != sizeof(plainText) - 1) {
        return -1;
    }
    return memcmp(cipherText, plainText, cipherTextLen);
}

int32_t AesNoUpdateEncWithInput(HcfCipher *cipher, HcfSymKey *key, HcfBlob *input,
    uint8_t *cipherText, int *cipherTextLen)
{
    HcfBlob output = { .data = nullptr, .len = 0 };
    int32_t maxLen = *cipherTextLen;
    int32_t ret = cipher->init(cipher, ENCRYPT_MODE, &(key->key), nullptr);
    if (ret != 0) {
        LOGE("init failed! %{public}d", ret);
        return ret;
    }

    *cipherTextLen = 0;
    ret = cipher->doFinal(cipher, input, &output);
    if (ret != 0) {
        LOGE("doFinal failed!");
        return ret;
    }
    if (output.data != nullptr) {
        if (memcpy_s(cipherText, maxLen, output.data, output.len) != EOK) {
            HcfBlobDataFree(&output);
            return -1;
        }
        *cipherTextLen += output.len;
        HcfBlobDataFree(&output);
    }

    return 0;
}

// test encrypt and decrypt with null plain text
int32_t AesDecryptEmptyMsg(HcfCipher *cipher, HcfSymKey *key, HcfParamsSpec *params,
    uint8_t *cipherText, int cipherTextLen)
{
    HcfBlob input = { .data = cipherText, .len = static_cast<size_t>(cipherTextLen) };
    HcfBlob output = { .data = nullptr, .len = 0 };
    int32_t ret = cipher->init(cipher, DECRYPT_MODE, &(key->key), params);
    if (ret != 0) {
        LOGE("init failed! %{public}d", ret);
        return ret;
    }

    ret = cipher->doFinal(cipher, &input, &output);
    if (ret != 0) {
        LOGE("doFinal failed!");
        return ret;
    }
    if (output.len == 0 && output.data == nullptr) {
        ret = 0;
    } else {
        ret = -1;
    }
    HcfBlobDataFree(&output);
    return ret;
}

int32_t AesNoUpdateEncrypt(HcfCipher *cipher, HcfSymKey *key, HcfParamsSpec *params,
    uint8_t *cipherText, int *cipherTextLen)
{
    uint8_t plainText[] = "this is test!";
    HcfBlob input = {.data = reinterpret_cast<uint8_t *>(plainText), .len = 13};
    HcfBlob output = {};
    int32_t maxLen = *cipherTextLen;
    int32_t ret = cipher->init(cipher, ENCRYPT_MODE, reinterpret_cast<HcfKey *>(key), params);
    if (ret != 0) {
        LOGE("init failed! %{public}d", ret);
        return ret;
    }

    *cipherTextLen = 0;
    ret = cipher->doFinal(cipher, &input, &output);
    if (ret != 0) {
        LOGE("doFinal failed!");
        return ret;
    }
    if (output.data != nullptr) {
        if (memcpy_s(cipherText, maxLen, output.data, output.len) != EOK) {
            HcfBlobDataFree(&output);
            return -1;
        }
        *cipherTextLen += output.len;
        HcfBlobDataFree(&output);
    }

    return 0;
}

int32_t AesNoUpdateDecrypt(HcfCipher *cipher, HcfSymKey *key, HcfParamsSpec *params,
    uint8_t *cipherText, int cipherTextLen)
{
    uint8_t plainText[] = "this is test!";
    HcfBlob input = {.data = reinterpret_cast<uint8_t *>(cipherText), .len = static_cast<size_t>(cipherTextLen)};
    HcfBlob output = {};
    int32_t maxLen = cipherTextLen;
    int32_t ret = cipher->init(cipher, DECRYPT_MODE, reinterpret_cast<HcfKey *>(key), params);
    if (ret != 0) {
        LOGE("init failed! %{public}d", ret);
        return ret;
    }

    cipherTextLen = 0;
    ret = cipher->doFinal(cipher, &input, &output);
    if (ret != 0) {
        LOGE("doFinal failed!");
        return ret;
    }
    if (output.data != nullptr) {
        if (memcpy_s(cipherText, maxLen, output.data, output.len) != EOK) {
            HcfBlobDataFree(&output);
            return -1;
        }
        cipherTextLen += output.len;
        HcfBlobDataFree(&output);
    }

    if (cipherTextLen != sizeof(plainText) - 1) {
        return -1;
    }
    return memcmp(cipherText, plainText, cipherTextLen);
}