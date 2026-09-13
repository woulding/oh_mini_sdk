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

#include "hcfciphercreate_fuzzer.h"

#include <cstddef>
#include <cstdint>
#include <string>
#include "securec.h"

#include "asy_key_generator.h"
#include "blob.h"
#include "cipher.h"
#include "mac.h"
#include "result.h"
#include "memory.h"
#include "sym_key_generator.h"
#include "detailed_gcm_params.h"
#include <fuzzer/FuzzedDataProvider.h>

namespace OHOS {
    static int32_t AesEncrypt(HcfCipher *cipher, HcfSymKey *key, HcfBlob *input,
        uint8_t **cipherText, int *cipherTextLen)
    {
        HcfBlob output = {};
        int32_t maxLen = input->len + 16;
        int32_t ret = cipher->init(cipher, ENCRYPT_MODE, &(key->key), nullptr);
        if (ret != 0) {
            return ret;
        }

        ret = cipher->update(cipher, input, &output);
        if (ret != 0) {
            if (output.data != nullptr) {
                HcfBlobDataClearAndFree(&output);
            }
            return ret;
        }
        *cipherTextLen = output.len;
        *cipherText = static_cast<uint8_t *>(HcfMalloc(maxLen, 0));
        if (output.len > 0 && output.data != nullptr) {
            (void)memcpy_s(*cipherText, maxLen, output.data, output.len);
        }
        if (output.data != nullptr) {
            HcfBlobDataClearAndFree(&output);
            output.data = nullptr;
        }
        ret = cipher->doFinal(cipher, nullptr, &output);
        if (ret != 0) {
            HcfBlobDataClearAndFree(&output);
            return ret;
        }
        if (output.len > 0 && output.data != nullptr) {
            (void)memcpy_s(*cipherText + *cipherTextLen, output.len, output.data, output.len);
        }
        *cipherTextLen += output.len;
        if (output.data != nullptr) {
            HcfBlobDataClearAndFree(&output);
            output.data = nullptr;
        }
        return 0;
    }

    static int32_t AesDecrypt(HcfCipher *cipher, HcfSymKey *key, HcfBlob *input, uint8_t *cipherText, int cipherTextLen)
    {
        HcfBlob output = {};
        HcfBlob decryptedData = {};
        if (cipherTextLen <= 0) {
            return -1;
        }

        int32_t ret = cipher->init(cipher, DECRYPT_MODE, &(key->key), nullptr);
        if (ret != 0) {
            return ret;
        }

        HcfBlob cipherBlob = { .data = cipherText, .len = cipherTextLen };
        ret = cipher->update(cipher, &cipherBlob, &output);
        if (ret != 0) {
            goto EXIT;
        }
        decryptedData.data = (uint8_t *)HcfMalloc(cipherTextLen, 0);
        if (decryptedData.data == nullptr) {
            ret = -1;
            goto EXIT;
        }
        if (output.len > 0 && output.data != nullptr) {
            (void)memcpy_s(decryptedData.data, cipherTextLen, output.data, output.len);
            decryptedData.len = output.len;
        }
        HcfBlobDataClearAndFree(&output);
        ret = cipher->doFinal(cipher, nullptr, &output);
        if (ret != 0) {
            goto EXIT;
        }
        if (output.len > 0 && output.data != nullptr) {
            (void)memcpy_s(decryptedData.data + decryptedData.len, output.len, output.data, output.len);
            decryptedData.len += output.len;
        }
        if (decryptedData.len != input->len - 1 || memcmp(decryptedData.data, input->data, decryptedData.len) != 0) {
            ret = 1;
        } else {
            ret = 0;
        }
    EXIT:
        if (output.data != nullptr) {
            HcfBlobDataClearAndFree(&output);
        }
        if (decryptedData.data != nullptr) {
            HcfBlobDataClearAndFree(&decryptedData);
        }
        return ret;
    }

    static int32_t Sm4Encrypt(HcfCipher *cipher, HcfSymKey *key, HcfBlob *input,
        uint8_t **cipherText, int *cipherTextLen)
    {
        HcfBlob output = {};
        int32_t maxLen = input->len + 16;
        int32_t ret = cipher->init(cipher, ENCRYPT_MODE, reinterpret_cast<HcfKey *>(key), nullptr);
        if (ret != 0) {
            return ret;
        }

        ret = cipher->update(cipher, input, &output);
        if (ret != 0) {
            if (output.data != nullptr) {
                HcfBlobDataClearAndFree(&output);
            }
            return ret;
        }
        *cipherTextLen = output.len;
        *cipherText = static_cast<uint8_t *>(HcfMalloc(maxLen, 0));
        if (output.data != nullptr) {
            if (memcpy_s(*cipherText, output.len, output.data, output.len) != EOK) {
                HcfBlobDataFree(&output);
                return -1;
            }
            HcfBlobDataFree(&output);
        }

        ret = cipher->doFinal(cipher, nullptr, &output);
        if (ret != 0) {
            HcfFree(*cipherText);
            return ret;
        }
        if (output.len > 0 && output.data != nullptr) {
            if (memcpy_s(*cipherText + *cipherTextLen, output.len, output.data, output.len) != EOK) {
                HcfBlobDataFree(&output);
                return -1;
            }
            *cipherTextLen += output.len;
            HcfBlobDataFree(&output);
        }
        return 0;
    }

    static int32_t Sm4Decrypt(HcfCipher *cipher, HcfSymKey *key, HcfBlob *input,
        uint8_t *cipherText, int cipherTextLen)
    {
        HcfBlob output = {};
        HcfBlob decryptedData = {};
        int32_t ret;

        if (cipherTextLen <= 0) {
            return -1;
        }
        ret = cipher->init(cipher, DECRYPT_MODE, reinterpret_cast<HcfKey *>(key), nullptr);
        if (ret != 0) {
            return ret;
        }

        HcfBlob cipherBlob = { .data = cipherText, .len = cipherTextLen };
        ret = cipher->update(cipher, &cipherBlob, &output);
        if (ret != 0) {
            goto EXIT;
        }

        decryptedData.data = (uint8_t *)HcfMalloc(cipherTextLen, 0);
        if (decryptedData.data == nullptr) {
            ret = -1;
            goto EXIT;
        }

        if (output.len > 0 && output.data != nullptr) {
            (void)memcpy_s(decryptedData.data, output.len, output.data, output.len);
            decryptedData.len = output.len;
        }
        HcfBlobDataClearAndFree(&output);
        ret = cipher->doFinal(cipher, nullptr, &output);
        if (ret != 0) {
            goto EXIT;
        }

        if (output.len > 0 && output.data != nullptr) {
            (void)memcpy_s(decryptedData.data + decryptedData.len, output.len, output.data, output.len);
            decryptedData.len += output.len;
        }

        if (decryptedData.len != input->len - 1 ||
            memcmp(decryptedData.data, input->data, decryptedData.len) != 0) {
            ret = 1;
        } else {
            ret = 0;
        }

    EXIT:
        if (output.data != nullptr) {
            HcfBlobDataClearAndFree(&output);
        }
        if (decryptedData.data != nullptr) {
            HcfBlobDataClearAndFree(&decryptedData);
        }
        return ret;
    }

    static void TestAesCipher(FuzzedDataProvider &fdp)
    {
        int ret = 0;
        std::vector<uint8_t> inputData = fdp.ConsumeRemainingBytes<uint8_t>();
        HcfBlob input = { .data = inputData.empty() ? nullptr : inputData.data(), .len = inputData.size() };
        uint8_t *cipherText = nullptr;
        int cipherTextLen = 0;
        HcfSymKeyGenerator *generator = nullptr;
        HcfCipher *cipher = nullptr;
        HcfSymKey *key = nullptr;
        ret = HcfSymKeyGeneratorCreate("AES128", &generator);
        if (ret != HCF_SUCCESS) {
            return;
        }
        ret = generator->generateSymKey(generator, &key);
        if (ret != HCF_SUCCESS) {
            HcfObjDestroy(generator);
            return;
        }
        ret = HcfCipherCreate("AES128|ECB|NoPadding", &cipher);
        if (ret != HCF_SUCCESS) {
            HcfObjDestroy(generator);
            HcfObjDestroy(key);
            return;
        }
        (void)AesEncrypt(cipher, key, &input, &cipherText, &cipherTextLen);
        (void)AesDecrypt(cipher, key, &input, cipherText, cipherTextLen);
        HcfFree(cipherText);
        HcfObjDestroy(generator);
        HcfObjDestroy(key);
        HcfObjDestroy(cipher);
    }

    static void TestSm4Cipher(FuzzedDataProvider &fdp)
    {
        int ret = 0;
        std::vector<uint8_t> inputData = fdp.ConsumeRemainingBytes<uint8_t>();
        HcfBlob input = { .data = inputData.empty() ? nullptr : inputData.data(), .len = inputData.size() };
        uint8_t *cipherText = nullptr;
        int cipherTextLen = 0;
        HcfSymKeyGenerator *generator = nullptr;
        HcfCipher *cipher = nullptr;
        HcfSymKey *key = nullptr;
        ret = HcfSymKeyGeneratorCreate("SM4_128", &generator);
        if (ret != HCF_SUCCESS) {
            return;
        }
        ret = generator->generateSymKey(generator, &key);
        if (ret != HCF_SUCCESS) {
            HcfObjDestroy(generator);
            return;
        }
        ret = HcfCipherCreate("SM4_128|ECB|PKCS5", &cipher);
        if (ret != HCF_SUCCESS) {
            HcfObjDestroy(generator);
            HcfObjDestroy(key);
            return;
        }

        (void)Sm4Encrypt(cipher, key, &input, &cipherText, &cipherTextLen);
        (void)Sm4Decrypt(cipher, key, &input, cipherText, cipherTextLen);
        HcfFree(cipherText);
        HcfObjDestroy(generator);
        HcfObjDestroy(key);
        HcfObjDestroy(cipher);
    }

    static void TestSm4GcmCipher(FuzzedDataProvider &fdp)
    {
        int ret = 0;
        std::vector<uint8_t> inputData = fdp.ConsumeRemainingBytes<uint8_t>();
        HcfBlob input = { .data = inputData.empty() ? nullptr : inputData.data(), .len = inputData.size() };
        uint8_t aad[8] = {0};
        uint8_t tag[16] = {0};
        uint8_t iv[12] = {0}; // openssl only support nonce 12 bytes, tag 16bytes
        uint8_t *cipherText = nullptr;
        int cipherTextLen = 0;

        HcfGcmParamsSpec spec = {};
        spec.aad.data = aad;
        spec.aad.len = sizeof(aad);
        spec.tag.data = tag;
        spec.tag.len = sizeof(tag);
        spec.iv.data = iv;
        spec.iv.len = sizeof(iv);
        HcfSymKeyGenerator *generator = nullptr;
        HcfCipher *cipher = nullptr;
        HcfSymKey *key = nullptr;
        ret = HcfSymKeyGeneratorCreate("SM4_128", &generator);
        if (ret != HCF_SUCCESS) {
            return;
        }
        ret = generator->generateSymKey(generator, &key);
        if (ret != HCF_SUCCESS) {
            HcfObjDestroy(generator);
            return;
        }
        ret = HcfCipherCreate("SM4_128|GCM|PKCS5", &cipher);
        if (ret != HCF_SUCCESS) {
            HcfObjDestroy(generator);
            HcfObjDestroy(key);
            return;
        }

        (void)Sm4Encrypt(cipher, key, &input, &cipherText, &cipherTextLen);
        (void)Sm4Decrypt(cipher, key, &input, cipherText, cipherTextLen);
        HcfObjDestroy(generator);
        HcfObjDestroy(key);
        HcfObjDestroy(cipher);
    }

    static void TestRsaCipher(FuzzedDataProvider &fdp)
    {
        HcfResult res = HCF_SUCCESS;
        HcfAsyKeyGenerator *generator = nullptr;
        res = HcfAsyKeyGeneratorCreate("RSA1024|PRIMES_2", &generator);
        if (res != HCF_SUCCESS) {
            return;
        }
        HcfKeyPair *keyPair = nullptr;
        res = generator->generateKeyPair(generator, nullptr, &keyPair);
        if (res != HCF_SUCCESS) {
            HcfObjDestroy(generator);
            return;
        }

        std::vector<uint8_t> inputData = fdp.ConsumeRemainingBytes<uint8_t>();
        HcfBlob input = { .data = inputData.empty() ? nullptr : inputData.data(), .len = inputData.size() };
        HcfBlob encoutput = {.data = nullptr, .len = 0};
        HcfCipher *cipher = nullptr;
        res = HcfCipherCreate("RSA1024|PKCS1", &cipher);
        if (res != HCF_SUCCESS) {
            HcfObjDestroy(generator);
            HcfObjDestroy(keyPair);
            return;
        }

        (void)cipher->init(cipher, ENCRYPT_MODE, reinterpret_cast<HcfKey *>(keyPair->pubKey), nullptr);
        (void)cipher->doFinal(cipher, &input, &encoutput);
        HcfObjDestroy(cipher);

        HcfBlob decoutput = {.data = nullptr, .len = 0};
        cipher = nullptr;
        res = HcfCipherCreate("RSA1024|PKCS1", &cipher);
        if (res != HCF_SUCCESS) {
            HcfObjDestroy(generator);
            HcfObjDestroy(keyPair);
            HcfBlobDataClearAndFree(&encoutput);
            return;
        }
        (void)cipher->init(cipher, DECRYPT_MODE, reinterpret_cast<HcfKey *>(keyPair->priKey), nullptr);
        (void)cipher->doFinal(cipher, &encoutput, &decoutput);
        HcfBlobDataClearAndFree(&encoutput);
        HcfBlobDataClearAndFree(&decoutput);
        HcfObjDestroy(generator);
        HcfObjDestroy(keyPair);
        HcfObjDestroy(cipher);
    }

    bool HcfCipherCreateFuzzTest(const uint8_t* data, size_t size)
    {
        FuzzedDataProvider fdp(data, size);
        TestRsaCipher(fdp);
        TestAesCipher(fdp);
        TestSm4Cipher(fdp);
        TestSm4GcmCipher(fdp);
        HcfCipher *cipher = nullptr;
        std::string algoName = fdp.ConsumeRemainingBytesAsString();
        HcfResult res = HcfCipherCreate(algoName.c_str(), &cipher);
        if (res != HCF_SUCCESS) {
            return false;
        }
        HcfObjDestroy(cipher);
        return true;
    }
}

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    /* Run your code on data */
    OHOS::HcfCipherCreateFuzzTest(data, size);
    return 0;
}
