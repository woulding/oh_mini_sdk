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

#include <gtest/gtest.h>
#include <fstream>
#include <iostream>
#include "securec.h"

#include "aes_common.h"
#include "aes_openssl.h"
#include "blob.h"
#include "cipher.h"
#include "detailed_iv_params.h"
#include "detailed_gcm_params.h"
#include "detailed_ccm_params.h"
#include "memory.h"
#include "sym_common_defines.h"
#include "sym_key_generator.h"

using namespace std;
using namespace testing::ext;

namespace {
class CryptoAesEcbCipherTest : public testing::Test {
public:
    static void SetUpTestCase() {};
    static void TearDownTestCase() {};
    void SetUp() {};
    void TearDown() {};
};

/**
 * @tc.name: CryptoAesEcbCipherTest.CryptoAesEcbCipherTest001
 * @tc.desc: Verify whether the crypto framework is normal.
 * @tc.type: FUNC
 * @tc.require: I5QWEO
 */
HWTEST_F(CryptoAesEcbCipherTest, CryptoAesEcbCipherTest001, TestSize.Level0)
{
    uint8_t cipherText[128] = {0};
    int cipherTextLen = 128;

    HcfSymKeyGenerator *generator = nullptr;
    HcfCipher *cipher = nullptr;
    HcfSymKey *key = nullptr;

    int ret = HcfSymKeyGeneratorCreate("AES128", &generator);
    ASSERT_EQ(ret, 0);

    ret = generator->generateSymKey(generator, &key);
    ASSERT_EQ(ret, 0);

    ret = HcfCipherCreate("AES128|ECB|NoPadding", &cipher);
    ASSERT_EQ(ret, 0);

    ret = AesEncrypt(cipher, key, nullptr, cipherText, &cipherTextLen);
    ASSERT_NE(ret, 0);

    ret = AesDecrypt(cipher, key, nullptr, cipherText, cipherTextLen);
    ASSERT_NE(ret, 0);

    HcfObjDestroy((HcfObjectBase *)key);
    HcfObjDestroy((HcfObjectBase *)cipher);
    HcfObjDestroy((HcfObjectBase *)generator);
}

/**
 * @tc.name: CryptoAesEcbCipherTest.CryptoAesEcbCipherTest002
 * @tc.desc: Verify AES128 cipher algorithm.
 * @tc.type: FUNC
 * @tc.require: I5QWEG
 */
HWTEST_F(CryptoAesEcbCipherTest, CryptoAesEcbCipherTest002, TestSize.Level0)
{
    uint8_t cipherText[128] = {0};
    int cipherTextLen = 128;

    HcfSymKeyGenerator *generator = nullptr;
    HcfCipher *cipher = nullptr;
    HcfSymKey *key = nullptr;

    int ret = HcfSymKeyGeneratorCreate("AES128", &generator);
    ASSERT_EQ(ret, 0);

    ret = generator->generateSymKey(generator, &key);
    ASSERT_EQ(ret, 0);

    ret = HcfCipherCreate("AES128|ECB|PKCS5", &cipher);
    ASSERT_EQ(ret, 0);

    ret = AesEncrypt(cipher, key, nullptr, cipherText, &cipherTextLen);
    ASSERT_EQ(ret, 0);

    ret = AesDecrypt(cipher, key, nullptr, cipherText, cipherTextLen);
    ASSERT_EQ(ret, 0);

    HcfObjDestroy((HcfObjectBase *)key);
    HcfObjDestroy((HcfObjectBase *)cipher);
    HcfObjDestroy((HcfObjectBase *)generator);
}

HWTEST_F(CryptoAesEcbCipherTest, CryptoAesEcbCipherTest003, TestSize.Level0)
{
    uint8_t cipherText[128] = {0};
    int cipherTextLen = 128;

    HcfSymKeyGenerator *generator = nullptr;
    HcfCipher *cipher = nullptr;
    HcfSymKey *key = nullptr;
    int ret = HcfSymKeyGeneratorCreate("AES128", &generator);
    ASSERT_EQ(ret, 0);

    ret = generator->generateSymKey(generator, &key);
    ASSERT_EQ(ret, 0);

    ret = HcfCipherCreate("AES128|ECB|PKCS7", &cipher);
    ASSERT_EQ(ret, 0);

    ret = AesEncrypt(cipher, key, nullptr, cipherText, &cipherTextLen);
    ASSERT_EQ(ret, 0);

    ret = AesDecrypt(cipher, key, nullptr, cipherText, cipherTextLen);
    ASSERT_EQ(ret, 0);

    HcfObjDestroy((HcfObjectBase *)key);
    HcfObjDestroy((HcfObjectBase *)cipher);
    HcfObjDestroy((HcfObjectBase *)generator);
}

HWTEST_F(CryptoAesEcbCipherTest, CryptoAesEcbCipherTest004, TestSize.Level0)
{
    uint8_t cipherText[128] = {0};
    int cipherTextLen = 128;

    HcfCipher *cipher = nullptr;
    HcfSymKey *key = nullptr;
    uint8_t codeCipherText[] = {
        0xF5, 0x12, 0xA0, 0x33, 0xCD, 0xCF, 0x0D, 0x32,
        0x3E, 0xFF, 0x80, 0x53, 0x89, 0xB6, 0xE4, 0xFE
    };

    int ret = ConvertSymKey("AES128", &key);
    ASSERT_EQ(ret, 0);

    ret = HcfCipherCreate("AES128|ECB|PKCS7", &cipher);
    ASSERT_EQ(ret, 0);

    ret = AesEncrypt(cipher, key, nullptr, cipherText, &cipherTextLen);
    ASSERT_EQ(ret, 0);

    ret = memcmp(cipherText, codeCipherText, cipherTextLen);
    ASSERT_EQ(ret, 0);

    ret = AesDecrypt(cipher, key, nullptr, cipherText, cipherTextLen);
    ASSERT_EQ(ret, 0);

    HcfObjDestroy((HcfObjectBase *)key);
    HcfObjDestroy((HcfObjectBase *)cipher);
}

HWTEST_F(CryptoAesEcbCipherTest, CryptoAesEcbCipherTest005, TestSize.Level0)
{
    uint8_t cipherText[128] = {0};
    int cipherTextLen = 128;

    HcfSymKeyGenerator *generator = nullptr;
    HcfCipher *cipher = nullptr;
    HcfSymKey *key = nullptr;

    int ret = HcfSymKeyGeneratorCreate("AES128", &generator);
    ASSERT_EQ(ret, 0);

    ret = generator->generateSymKey(generator, &key);
    ASSERT_EQ(ret, 0);

    ret = HcfCipherCreate("AES128|ECB|NoPadding", &cipher);
    ASSERT_EQ(ret, 0);

    ret = AesNoUpdateEncrypt(cipher, key, nullptr, cipherText, &cipherTextLen);
    ASSERT_NE(ret, 0);

    ret = AesNoUpdateDecrypt(cipher, key, nullptr, cipherText, cipherTextLen);
    ASSERT_NE(ret, 0);

    HcfObjDestroy((HcfObjectBase *)key);
    HcfObjDestroy((HcfObjectBase *)cipher);
    HcfObjDestroy((HcfObjectBase *)generator);
}

HWTEST_F(CryptoAesEcbCipherTest, CryptoAesEcbCipherTest006, TestSize.Level0)
{
    uint8_t cipherText[128] = {0};
    int cipherTextLen = 128;

    HcfSymKeyGenerator *generator = nullptr;
    HcfCipher *cipher = nullptr;
    HcfSymKey *key = nullptr;

    int ret = HcfSymKeyGeneratorCreate("AES128", &generator);
    ASSERT_EQ(ret, 0);

    ret = generator->generateSymKey(generator, &key);
    ASSERT_EQ(ret, 0);

    ret = HcfCipherCreate("AES128|ECB|PKCS5", &cipher);
    ASSERT_EQ(ret, 0);

    ret = AesNoUpdateEncrypt(cipher, key, nullptr, cipherText, &cipherTextLen);
    ASSERT_EQ(ret, 0);

    ret = AesNoUpdateDecrypt(cipher, key, nullptr, cipherText, cipherTextLen);
    ASSERT_EQ(ret, 0);

    HcfObjDestroy((HcfObjectBase *)key);
    HcfObjDestroy((HcfObjectBase *)cipher);
    HcfObjDestroy((HcfObjectBase *)generator);
}

HWTEST_F(CryptoAesEcbCipherTest, CryptoAesEcbCipherTest007, TestSize.Level0)
{
    uint8_t cipherText[128] = {0};
    int cipherTextLen = 128;

    HcfSymKeyGenerator *generator = nullptr;
    HcfCipher *cipher = nullptr;
    HcfSymKey *key = nullptr;

    int ret = HcfSymKeyGeneratorCreate("AES128", &generator);
    ASSERT_EQ(ret, 0);

    ret = generator->generateSymKey(generator, &key);
    ASSERT_EQ(ret, 0);

    ret = HcfCipherCreate("AES128|ECB|PKCS7", &cipher);
    ASSERT_EQ(ret, 0);

    ret = AesNoUpdateEncrypt(cipher, key, nullptr, cipherText, &cipherTextLen);
    ASSERT_EQ(ret, 0);

    ret = AesNoUpdateDecrypt(cipher, key, nullptr, cipherText, cipherTextLen);
    ASSERT_EQ(ret, 0);

    HcfObjDestroy((HcfObjectBase *)key);
    HcfObjDestroy((HcfObjectBase *)cipher);
    HcfObjDestroy((HcfObjectBase *)generator);
}

HWTEST_F(CryptoAesEcbCipherTest, CryptoAesEcbCipherTest008, TestSize.Level0)
{
    uint8_t cipherText[128] = {0};
    int cipherTextLen = 128;

    HcfCipher *cipher = nullptr;
    HcfSymKey *key = nullptr;
    uint8_t codeCipherText[] = {
        0xF5, 0x12, 0xA0, 0x33, 0xCD, 0xCF, 0x0D, 0x32,
        0x3E, 0xFF, 0x80, 0x53, 0x89, 0xB6, 0xE4, 0xFE
    };

    int ret = ConvertSymKey("AES128", &key);
    ASSERT_EQ(ret, 0);

    ret = HcfCipherCreate("AES128|ECB|PKCS7", &cipher);
    ASSERT_EQ(ret, 0);

    ret = AesNoUpdateEncrypt(cipher, key, nullptr, cipherText, &cipherTextLen);
    ASSERT_EQ(ret, 0);

    ret = memcmp(cipherText, codeCipherText, cipherTextLen);
    ASSERT_EQ(ret, 0);

    ret = AesNoUpdateDecrypt(cipher, key, nullptr, cipherText, cipherTextLen);
    ASSERT_EQ(ret, 0);

    HcfObjDestroy((HcfObjectBase *)key);
    HcfObjDestroy((HcfObjectBase *)cipher);
}

HWTEST_F(CryptoAesEcbCipherTest, CryptoAesEcbCipherTest009, TestSize.Level0)
{
    HcfCipher *cipher = nullptr;
    HcfSymKey *key = nullptr;

    int ret = GeneratorFile("/data/test_aes.txt", 10 * FILE_BLOCK_SIZE);
    ASSERT_EQ(ret, 0);

    ret = ConvertSymKey("AES128", &key);
    ASSERT_EQ(ret, 0);

    ret = HcfCipherCreate("AES128|ECB|NoPadding", &cipher);
    ASSERT_EQ(ret, 0);

    ret = AesMultiBlockEncrypt(cipher, key, nullptr);
    ASSERT_EQ(ret, 0);

    ret = AesMultiBlockDecrypt(cipher, key, nullptr);
    ASSERT_EQ(ret, 0);

    ret = CompareFileContent();
    ASSERT_EQ(ret, 0);

    HcfObjDestroy((HcfObjectBase *)key);
    HcfObjDestroy((HcfObjectBase *)cipher);
}

HWTEST_F(CryptoAesEcbCipherTest, CryptoAesEcbCipherTest010, TestSize.Level0)
{
    uint8_t cipherText[CIPHER_TEXT_LEN] = { 0 };
    int cipherTextLen = CIPHER_TEXT_LEN;
    HcfCipher *cipher = nullptr;
    HcfSymKey *key = nullptr;

    int ret = GenerateSymKey("AES192", &key);
    ASSERT_EQ(ret, 0);

    ret = HcfCipherCreate("AES192|ECB|NoPadding", &cipher);
    ASSERT_EQ(ret, 0);

    ret = AesEncrypt(cipher, key, nullptr, cipherText, &cipherTextLen);
    ASSERT_NE(ret, 0);

    ret = AesDecrypt(cipher, key, nullptr, cipherText, cipherTextLen);
    ASSERT_NE(ret, 0);

    HcfObjDestroy(key);
    HcfObjDestroy(cipher);
}

HWTEST_F(CryptoAesEcbCipherTest, CryptoAesEcbCipherTest011, TestSize.Level0)
{
    uint8_t cipherText[CIPHER_TEXT_LEN] = { 0 };
    int cipherTextLen = CIPHER_TEXT_LEN;
    HcfCipher *cipher = nullptr;
    HcfSymKey *key = nullptr;

    int ret = GenerateSymKey("AES192", &key);
    ASSERT_EQ(ret, 0);

    ret = HcfCipherCreate("AES192|ECB|PKCS5", &cipher);
    ASSERT_EQ(ret, 0);

    ret = AesEncrypt(cipher, key, nullptr, cipherText, &cipherTextLen);
    ASSERT_EQ(ret, 0);

    ret = AesDecrypt(cipher, key, nullptr, cipherText, cipherTextLen);
    ASSERT_EQ(ret, 0);

    key->clearMem(key);
    HcfObjDestroy(key);
    HcfObjDestroy(cipher);
}

HWTEST_F(CryptoAesEcbCipherTest, CryptoAesEcbCipherTest012, TestSize.Level0)
{
    uint8_t cipherText[CIPHER_TEXT_LEN] = { 0 };
    int cipherTextLen = CIPHER_TEXT_LEN;
    HcfCipher *cipher = nullptr;
    HcfSymKey *key = nullptr;

    int ret = GenerateSymKey("AES256", &key);
    ASSERT_EQ(ret, 0);

    ret = HcfCipherCreate("AES256|ECB|PKCS7", &cipher);
    ASSERT_EQ(ret, 0);

    ret = AesEncrypt(cipher, key, nullptr, cipherText, &cipherTextLen);
    ASSERT_EQ(ret, 0);

    ret = AesDecrypt(cipher, key, nullptr, cipherText, cipherTextLen);
    ASSERT_EQ(ret, 0);

    key->clearMem(key);
    HcfObjDestroy(key);
    HcfObjDestroy(cipher);
}

HWTEST_F(CryptoAesEcbCipherTest, CryptoAesEcbCipherTest013, TestSize.Level0)
{
    HcfSymKeyGenerator *generator = nullptr;
    HcfSymKey *key = nullptr;
    HcfCipher *cipher = nullptr;

    int ret = HcfCipherCreate("AES128|ECB|PKCS5", &cipher);
    ASSERT_EQ(ret, 0);

    ret = HcfSymKeyGeneratorCreate("AES128", &generator);
    ASSERT_EQ(ret, 0);

    ret = generator->generateSymKey(reinterpret_cast<HcfSymKeyGenerator *>(cipher), &key);
    ASSERT_NE(ret, 0);

    HcfObjDestroy(key);
    HcfObjDestroy(generator);
    HcfObjDestroy(cipher);
}

HWTEST_F(CryptoAesEcbCipherTest, CryptoAesEcbCipherTest014, TestSize.Level0)
{
    HcfSymKeyGenerator *generator = nullptr;
    HcfSymKey *key = nullptr;
    uint8_t keyMaterial[] = {
        0xba, 0x3b, 0xc2, 0x71, 0x21, 0x1e, 0x30, 0x56,
        0xad, 0x47, 0xfc, 0x5a, 0x46, 0x39, 0xee, 0x7c
    };
    HcfBlob keyTmpBlob = { .data = keyMaterial, .len = KEY_MATERIAL_LEN };
    HcfCipher *cipher = nullptr;

    int ret = HcfCipherCreate("AES128|ECB|PKCS5", &cipher);
    ASSERT_EQ(ret, 0);

    ret = HcfSymKeyGeneratorCreate("AES128", &generator);
    ASSERT_EQ(ret, 0);

    ret = generator->convertSymKey(reinterpret_cast<HcfSymKeyGenerator *>(cipher), &keyTmpBlob, &key);
    ASSERT_NE(ret, 0);

    HcfObjDestroy(key);
    HcfObjDestroy(generator);
    HcfObjDestroy(cipher);
}

HWTEST_F(CryptoAesEcbCipherTest, CryptoAesEcbCipherTest015, TestSize.Level0)
{
    uint8_t cipherText[CIPHER_TEXT_LEN] = { 0 };
    int cipherTextLen = CIPHER_TEXT_LEN;
    HcfCipher *cipher = nullptr;
    HcfSymKey *key = nullptr;

    int ret = GenerateSymKey("AES128", &key);
    ASSERT_EQ(ret, 0);

    // allow input with more than one padding mode. It will pick the last PKCS5.
    ret = HcfCipherCreate("AES128|ECB|NoPadding|PKCS5", &cipher);
    ASSERT_EQ(ret, 0);

    ret = AesEncrypt(cipher, key, nullptr, cipherText, &cipherTextLen);
    ASSERT_EQ(ret, 0);

    ret = AesDecrypt(cipher, key, nullptr, cipherText, cipherTextLen);
    ASSERT_EQ(ret, 0);

    HcfObjDestroy(key);
    HcfObjDestroy(cipher);
}

HWTEST_F(CryptoAesEcbCipherTest, CryptoAesEcbCipherTest016, TestSize.Level0)
{
    uint8_t cipherText[CIPHER_TEXT_LEN] = { 0 };
    int cipherTextLen = CIPHER_TEXT_LEN;
    HcfCipher *cipher = nullptr;
    HcfSymKey *key = nullptr;

    int ret = GenerateSymKey("AES128", &key);
    ASSERT_EQ(ret, 0);

    ret = HcfCipherCreate("AES256|ECB|PKCS5", &cipher);
    ASSERT_EQ(ret, 0);

    // It is not allowed that AES128 in key is smaller AES256 in cipher. -> now only use the size of input key.
    ret = AesEncrypt(cipher, key, nullptr, cipherText, &cipherTextLen);
    ASSERT_EQ(ret, 0);

    ret = AesDecrypt(cipher, key, nullptr, cipherText, cipherTextLen);
    ASSERT_EQ(ret, 0);

    HcfObjDestroy(key);
    HcfObjDestroy(cipher);
}

HWTEST_F(CryptoAesEcbCipherTest, CryptoAesEcbCipherTest017, TestSize.Level0)
{
    uint8_t cipherText[CIPHER_TEXT_LEN] = { 0 };
    int cipherTextLen = CIPHER_TEXT_LEN;
    HcfCipher *cipher = nullptr;
    HcfSymKey *key = nullptr;

    int ret = GenerateSymKey("AES256", &key);
    ASSERT_EQ(ret, 0);

    ret = HcfCipherCreate("AES128|ECB|PKCS5", &cipher);
    ASSERT_EQ(ret, 0);

    ret = AesEncrypt(cipher, key, nullptr, cipherText, &cipherTextLen);
    ASSERT_EQ(ret, 0);

    ret = AesDecrypt(cipher, key, nullptr, cipherText, cipherTextLen);
    ASSERT_EQ(ret, 0);

    HcfObjDestroy(key);
    HcfObjDestroy(cipher);
}

HWTEST_F(CryptoAesEcbCipherTest, CryptoAesEcbCipherTest018, TestSize.Level0)
{
    HcfCipher *cipher = nullptr;
    HcfSymKey *key = nullptr;

    int ret = GenerateSymKey("AES128", &key);
    ASSERT_EQ(ret, 0);


    ret = HcfCipherCreate("AES128|ECB|PKCS5", &cipher);
    ASSERT_EQ(ret, 0);


    ret = cipher->init(nullptr, ENCRYPT_MODE, &(key->key), nullptr);
    ASSERT_NE(ret, 0);

    HcfObjDestroy(key);
    HcfObjDestroy(cipher);
}

HWTEST_F(CryptoAesEcbCipherTest, CryptoAesEcbCipherTest019, TestSize.Level0)
{
    HcfSymKeyGenerator *generator = nullptr;
    HcfCipher *cipher = nullptr;

    int ret = HcfCipherCreate("AES128|ECB|PKCS5", &cipher);
    ASSERT_EQ(ret, 0);

    ret = cipher->init(cipher, ENCRYPT_MODE, nullptr, nullptr);
    ASSERT_NE(ret, 0);

    HcfObjDestroy(cipher);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoAesEcbCipherTest, CryptoAesEcbCipherTest020, TestSize.Level0)
{
    HcfSymKeyGenerator *generator = nullptr;
    HcfSymKey *key = nullptr;
    HcfCipher *cipher = nullptr;

    int ret = HcfSymKeyGeneratorCreate("AES128", &generator);
    ASSERT_EQ(ret, 0);

    ret = generator->generateSymKey(generator, &key);
    ASSERT_EQ(ret, 0);

    ret = HcfCipherCreate("AES128|ECB|PKCS5", &cipher);
    ASSERT_EQ(ret, 0);

    ret = cipher->init(reinterpret_cast<HcfCipher *>(generator), ENCRYPT_MODE, &(key->key), nullptr);
    ASSERT_NE(ret, 0);

    HcfObjDestroy(key);
    HcfObjDestroy(cipher);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoAesEcbCipherTest, CryptoAesEcbCipherTest021, TestSize.Level0)
{
    HcfCipher *cipher = nullptr;
    HcfSymKey *key = nullptr;
    HcfBlob input = { .data = nullptr, .len = 0 };
    uint8_t cipherText[CIPHER_TEXT_LEN] = { 0 };
    int cipherTextLen = CIPHER_TEXT_LEN;

    int ret = GenerateSymKey("AES128", &key);
    ASSERT_EQ(ret, 0);

    ret = HcfCipherCreate("AES128|ECB|PKCS5", &cipher);
    ASSERT_EQ(ret, 0);

    ret = AesEncryptWithInput(cipher, key, &input, cipherText, &cipherTextLen);
    ASSERT_EQ(ret, 0);

    ret = AesDecryptEmptyMsg(cipher, key, nullptr, cipherText, cipherTextLen);
    ASSERT_EQ(ret, 0);

    HcfObjDestroy(key);
    HcfObjDestroy(cipher);
}

HWTEST_F(CryptoAesEcbCipherTest, CryptoAesEcbCipherTest022, TestSize.Level0)
{
    HcfCipher *cipher = nullptr;
    HcfSymKey *key = nullptr;
    HcfBlob input = { .data = nullptr, .len = 0 };
    uint8_t cipherText[CIPHER_TEXT_LEN] = { 0 };
    int cipherTextLen = CIPHER_TEXT_LEN;

    int ret = GenerateSymKey("AES128", &key);
    ASSERT_EQ(ret, 0);

    ret = HcfCipherCreate("AES128|ECB|PKCS5", &cipher);
    ASSERT_EQ(ret, 0);

    ret = AesEncryptWithInput(cipher, key, &input, cipherText, &cipherTextLen);
    ASSERT_EQ(ret, 0);

    ret = AesDecryptEmptyMsg(cipher, key, nullptr, cipherText, cipherTextLen);
    ASSERT_EQ(ret, 0);

    HcfObjDestroy(key);
    HcfObjDestroy(cipher);
}

HWTEST_F(CryptoAesEcbCipherTest, CryptoAesEcbCipherTest023, TestSize.Level0)
{
    HcfCipher *cipher = nullptr;
    HcfSymKey *key = nullptr;
    HcfBlob input = { .data = nullptr, .len = PLAINTEXT_LEN };
    HcfBlob output = { .data = nullptr, .len = 0 };

    int ret = GenerateSymKey("AES128", &key);
    ASSERT_EQ(ret, 0);

    ret = HcfCipherCreate("AES128|ECB|PKCS5", &cipher);
    ASSERT_EQ(ret, 0);

    ret = cipher->init(cipher, ENCRYPT_MODE, &(key->key), nullptr);
    ASSERT_EQ(ret, 0);

    ret = cipher->update(nullptr, &input, &output);
    ASSERT_NE(ret, 0);

    HcfObjDestroy(key);
    HcfObjDestroy(cipher);
    if (output.data != nullptr) {
        HcfFree(output.data);
        output.data = nullptr;
    }
}

HWTEST_F(CryptoAesEcbCipherTest, CryptoAesEcbCipherTest024, TestSize.Level0)
{
    HcfCipher *cipher = nullptr;
    HcfSymKey *key = nullptr;
    HcfBlob input = { .data = nullptr, .len = PLAINTEXT_LEN };
    HcfBlob output = { .data = nullptr, .len = 0 };

    int ret = GenerateSymKey("AES128", &key);
    ASSERT_EQ(ret, 0);

    ret = HcfCipherCreate("AES128|ECB|PKCS5", &cipher);
    ASSERT_EQ(ret, 0);

    ret = cipher->init(cipher, ENCRYPT_MODE, &(key->key), nullptr);
    ASSERT_EQ(ret, 0);

    ret = cipher->update(reinterpret_cast<HcfCipher *>(key), &input, &output);
    ASSERT_NE(ret, 0);

    HcfObjDestroy(key);
    HcfObjDestroy(cipher);
    if (output.data != nullptr) {
        HcfFree(output.data);
        output.data = nullptr;
    }
}

HWTEST_F(CryptoAesEcbCipherTest, CryptoAesEcbCipherTest025, TestSize.Level0)
{
    HcfCipher *cipher = nullptr;
    HcfSymKey *key = nullptr;
    uint8_t cipherText[CIPHER_TEXT_LEN] = { 0 };
    int cipherTextLen = CIPHER_TEXT_LEN;

    int ret = GenerateSymKey("AES128", &key);
    ASSERT_EQ(ret, 0);

    ret = HcfCipherCreate("AES128|ECB|PKCS5", &cipher);
    ASSERT_EQ(ret, 0);

    ret = AesNoUpdateEncWithInput(cipher, key, nullptr, cipherText, &cipherTextLen);
    ASSERT_EQ(ret, 0);

    ret = AesDecryptEmptyMsg(cipher, key, nullptr, cipherText, cipherTextLen);
    ASSERT_EQ(ret, 0);

    HcfObjDestroy(key);
    HcfObjDestroy(cipher);
}

HWTEST_F(CryptoAesEcbCipherTest, CryptoAesEcbCipherTest026, TestSize.Level0)
{
    HcfCipher *cipher = nullptr;
    HcfSymKey *key = nullptr;
    uint8_t plainText[] = "this is test!";
    HcfBlob input = { .data = plainText, .len = PLAINTEXT_LEN };

    int ret = GenerateSymKey("AES128", &key);
    ASSERT_EQ(ret, 0);

    ret = HcfCipherCreate("AES128|ECB|PKCS5", &cipher);
    ASSERT_EQ(ret, 0);

    ret = cipher->init(cipher, ENCRYPT_MODE, &(key->key), nullptr);
    ASSERT_EQ(ret, 0);

    ret = cipher->doFinal(cipher, &input, nullptr);
    ASSERT_NE(ret, 0);

    HcfObjDestroy(key);
    HcfObjDestroy(cipher);
}

HWTEST_F(CryptoAesEcbCipherTest, CryptoAesEcbCipherTest027, TestSize.Level0)
{
    HcfCipher *cipher = nullptr;
    HcfSymKey *key = nullptr;
    uint8_t plainText[] = "this is test!";
    HcfBlob input = { .data = plainText, .len = PLAINTEXT_LEN };
    HcfBlob output = { .data = nullptr, .len = 0 };

    int ret = GenerateSymKey("AES128", &key);
    ASSERT_EQ(ret, 0);

    ret = HcfCipherCreate("AES128|ECB|PKCS5", &cipher);
    ASSERT_EQ(ret, 0);

    ret = cipher->init(cipher, ENCRYPT_MODE, &(key->key), nullptr);
    ASSERT_EQ(ret, 0);

    ret = cipher->doFinal(reinterpret_cast<HcfCipher *>(key), &input, &output);
    ASSERT_NE(ret, 0);

    HcfObjDestroy(key);
    HcfObjDestroy(cipher);
    if (output.data != nullptr) {
        HcfFree(output.data);
        output.data = nullptr;
    }
}

HWTEST_F(CryptoAesEcbCipherTest, CryptoAesEcbCipherTest028, TestSize.Level0)
{
    HcfSymKeyGeneratorSpi *generator = nullptr;
    HcfSymKey *key = nullptr;
    HcfCipher *cipher = nullptr;
    SymKeyAttr attr = { .algo = HCF_ALG_AES, .keySize = AES_KEY_SIZE };

    int ret = HcfCipherCreate("AES128|ECB|PKCS5", &cipher);
    ASSERT_EQ(ret, 0);

    ret = HcfSymKeyGeneratorSpiCreate(&attr, &generator);
    ASSERT_EQ(ret, 0);

    ret = generator->engineGenerateSymmKey(reinterpret_cast<HcfSymKeyGeneratorSpi *>(cipher), &key);
    ASSERT_NE(ret, 0);

    HcfObjDestroy(key);
    HcfObjDestroy(generator);
    HcfObjDestroy(cipher);
}

HWTEST_F(CryptoAesEcbCipherTest, CryptoAesEcbCipherTest029, TestSize.Level0)
{
    HcfSymKeyGeneratorSpi *generator = nullptr;
    HcfSymKey *key = nullptr;
    uint8_t keyMaterial[] = {
        0xba, 0x3b, 0xc2, 0x71, 0x21, 0x1e, 0x30, 0x56,
        0xad, 0x47, 0xfc, 0x5a, 0x46, 0x39, 0xee, 0x7c
    };
    HcfBlob keyTmpBlob = { .data = keyMaterial, .len = KEY_MATERIAL_LEN };
    HcfCipher *cipher = nullptr;
    SymKeyAttr attr = { .algo = HCF_ALG_AES, .keySize = AES_KEY_SIZE };

    int ret = HcfCipherCreate("AES128|ECB|PKCS5", &cipher);
    ASSERT_EQ(ret, 0);

    ret = HcfSymKeyGeneratorSpiCreate(&attr, &generator);
    ASSERT_EQ(ret, 0);

    ret = generator->engineConvertSymmKey(reinterpret_cast<HcfSymKeyGeneratorSpi *>(cipher), &keyTmpBlob, &key);
    ASSERT_NE(ret, 0);

    HcfObjDestroy(key);
    HcfObjDestroy(generator);
    HcfObjDestroy(cipher);
}
}