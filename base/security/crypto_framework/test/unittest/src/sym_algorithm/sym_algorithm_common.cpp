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

#include "sym_algorithm_common.h"
#include "log.h"
#include "memory.h"
#include "securec.h"
#include "sym_key_generator.h"

#include <cstdint>
#include <cstring>

static const uint8_t DEFAULT_PLAIN_TEXT[] = "hello algorithem test!";
static const size_t DEFAULT_PLAIN_TEXTLEN = 22;

int32_t SymAlgGenerateSymKey(const char *algoName, HcfSymKey **key)
{
    if (algoName == nullptr || key == nullptr) {
        return -1;
    }
    HcfSymKeyGenerator *generator = nullptr;
    int32_t ret = HcfSymKeyGeneratorCreate(algoName, &generator);
    if (ret != 0) {
        LOGE("HcfSymKeyGeneratorCreate failed! algo=%{public}s", algoName);
        return ret;
    }
    ret = generator->generateSymKey(generator, key);
    if (ret != 0) {
        LOGE("generateSymKey failed!");
    }
    HcfObjDestroy(reinterpret_cast<HcfObjectBase *>(generator));
    return ret;
}

int32_t SymAlgConvertSymKey(const char *algoName, const uint8_t *keyMaterial, uint32_t keyLen,
    HcfSymKey **key)
{
    if (algoName == nullptr || keyMaterial == nullptr || keyLen == 0 || key == nullptr) {
        return -1;
    }
    HcfSymKeyGenerator *generator = nullptr;
    int32_t ret = HcfSymKeyGeneratorCreate(algoName, &generator);
    if (ret != 0) {
        LOGE("HcfSymKeyGeneratorCreate failed! algo=%{public}s", algoName);
        return ret;
    }
    HcfBlob keyBlob = {};
    keyBlob.data = const_cast<uint8_t *>(keyMaterial);
    keyBlob.len = keyLen;
    ret = generator->convertSymKey(generator, &keyBlob, key);
    if (ret != 0) {
        LOGE("convertSymKey failed!");
    }
    HcfObjDestroy(reinterpret_cast<HcfObjectBase *>(generator));
    return ret;
}

int32_t SymAlgEncrypt(HcfCipher *cipher, HcfSymKey *key, HcfParamsSpec *params,
    uint8_t *cipherText, int *cipherTextLen)
{
    if (cipher == nullptr || key == nullptr || cipherText == nullptr || cipherTextLen == nullptr) {
        return -1;
    }
    HcfBlob input = {};
    input.data = const_cast<uint8_t *>(DEFAULT_PLAIN_TEXT);
    input.len = DEFAULT_PLAIN_TEXTLEN;
    HcfBlob output = {};

    int32_t ret = cipher->init(cipher, ENCRYPT_MODE, reinterpret_cast<HcfKey *>(key), params);
    if (ret != 0) {
        LOGE("WeakAlgEncrypt init failed! ret=%{public}d", ret);
        return ret;
    }

    int32_t maxLen = *cipherTextLen;
    *cipherTextLen = 0;

    ret = cipher->update(cipher, &input, &output);
    if (ret != 0) {
        LOGE("WeakAlgEncrypt update failed!");
        return ret;
    }
    if (output.data != nullptr && output.len > 0) {
        if (memcpy_s(cipherText, maxLen, output.data, output.len) != EOK) {
            HcfBlobDataFree(&output);
            return -1;
        }
        *cipherTextLen = static_cast<int>(output.len);
        HcfBlobDataFree(&output);
        output.data = nullptr;
        output.len = 0;
    }

    ret = cipher->doFinal(cipher, nullptr, &output);
    if (ret != 0) {
        LOGE("WeakAlgEncrypt doFinal failed!");
        return ret;
    }
    if (output.data != nullptr && output.len > 0) {
        if (maxLen - *cipherTextLen < static_cast<int>(output.len) ||
            memcpy_s(cipherText + *cipherTextLen, maxLen - *cipherTextLen, output.data, output.len) != EOK) {
            HcfBlobDataFree(&output);
            return -1;
        }
        *cipherTextLen += static_cast<int>(output.len);
        HcfBlobDataFree(&output);
    }
    return 0;
}

int32_t SymAlgDecrypt(HcfCipher *cipher, HcfSymKey *key, HcfParamsSpec *params,
    uint8_t *cipherText, int cipherTextLen)
{
    if (cipher == nullptr || key == nullptr || cipherText == nullptr) {
        return -1;
    }
    HcfBlob input = {};
    input.data = cipherText;
    input.len = static_cast<size_t>(cipherTextLen);
    HcfBlob output = {};

    int32_t ret = cipher->init(cipher, DECRYPT_MODE, reinterpret_cast<HcfKey *>(key), params);
    if (ret != 0) {
        LOGE("WeakAlgDecrypt init failed! ret=%{public}d", ret);
        return ret;
    }

    int32_t decLen = 0;
    const int32_t maxLen = cipherTextLen;

    ret = cipher->update(cipher, &input, &output);
    if (ret != 0) {
        LOGE("WeakAlgDecrypt update failed!");
        return ret;
    }
    if (output.data != nullptr && output.len > 0) {
        if (memcpy_s(cipherText, maxLen, output.data, output.len) != EOK) {
            HcfBlobDataFree(&output);
            return -1;
        }
        decLen = static_cast<int>(output.len);
        HcfBlobDataFree(&output);
        output.data = nullptr;
        output.len = 0;
    }

    ret = cipher->doFinal(cipher, nullptr, &output);
    if (ret != 0) {
        LOGE("WeakAlgDecrypt doFinal failed!");
        return ret;
    }
    if (output.data != nullptr && output.len > 0) {
        if (maxLen - decLen < static_cast<int>(output.len) ||
            memcpy_s(cipherText + decLen, maxLen - decLen, output.data, output.len) != EOK) {
            HcfBlobDataFree(&output);
            return -1;
        }
        decLen += static_cast<int>(output.len);
        HcfBlobDataFree(&output);
    }

    if (decLen != static_cast<int>(DEFAULT_PLAIN_TEXTLEN)) {
        return -1;
    }
    return memcmp(cipherText, DEFAULT_PLAIN_TEXT, DEFAULT_PLAIN_TEXTLEN);
}

int32_t SymAlgNoUpdateEncrypt(HcfCipher *cipher, HcfSymKey *key, HcfParamsSpec *params,
    uint8_t *cipherText, int *cipherTextLen)
{
    if (cipher == nullptr || key == nullptr || cipherText == nullptr || cipherTextLen == nullptr) {
        return -1;
    }
    HcfBlob input = {};
    input.data = const_cast<uint8_t *>(DEFAULT_PLAIN_TEXT);
    input.len = DEFAULT_PLAIN_TEXTLEN;
    HcfBlob output = {};

    int32_t ret = cipher->init(cipher, ENCRYPT_MODE, reinterpret_cast<HcfKey *>(key), params);
    if (ret != 0) {
        LOGE("SymAlgNoUpdateEncrypt init failed! ret=%{public}d", ret);
        return ret;
    }

    int32_t maxLen = *cipherTextLen;
    *cipherTextLen = 0;
    ret = cipher->doFinal(cipher, &input, &output);
    if (ret != 0) {
        LOGE("SymAlgNoUpdateEncrypt doFinal failed!");
        return ret;
    }
    if (output.data != nullptr && output.len > 0) {
        if (static_cast<int>(output.len) > maxLen ||
            memcpy_s(cipherText, maxLen, output.data, output.len) != EOK) {
            HcfBlobDataFree(&output);
            return -1;
        }
        *cipherTextLen = static_cast<int>(output.len);
        HcfBlobDataFree(&output);
    }
    return 0;
}

int32_t SymAlgNoUpdateDecrypt(HcfCipher *cipher, HcfSymKey *key, HcfParamsSpec *params,
    uint8_t *cipherText, int cipherTextLen)
{
    if (cipher == nullptr || key == nullptr || cipherText == nullptr) {
        return -1;
    }
    HcfBlob input = {};
    input.data = cipherText;
    input.len = static_cast<size_t>(cipherTextLen);
    HcfBlob output = {};

    int32_t ret = cipher->init(cipher, DECRYPT_MODE, reinterpret_cast<HcfKey *>(key), params);
    if (ret != 0) {
        LOGE("SymAlgNoUpdateDecrypt init failed! ret=%{public}d", ret);
        return ret;
    }

    int32_t decLen = 0;
    ret = cipher->doFinal(cipher, &input, &output);
    if (ret != 0) {
        LOGE("SymAlgNoUpdateDecrypt doFinal failed!");
        return ret;
    }
    if (output.data != nullptr && output.len > 0) {
        if (memcpy_s(cipherText, cipherTextLen, output.data, output.len) != EOK) {
            HcfBlobDataFree(&output);
            return -1;
        }
        decLen = static_cast<int>(output.len);
        HcfBlobDataFree(&output);
    }

    if (decLen != static_cast<int>(DEFAULT_PLAIN_TEXTLEN)) {
        return -1;
    }
    return memcmp(cipherText, DEFAULT_PLAIN_TEXT, DEFAULT_PLAIN_TEXTLEN);
}
 