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
#include "log.h"
#include "memory.h"
#include "sym_common_defines.h"
#include "sym_key_generator.h"

using namespace std;
using namespace testing::ext;

namespace {
class CryptoAesCipherTest : public testing::Test {
public:
    static void SetUpTestCase() {};
    static void TearDownTestCase() {};
    void SetUp() {};
    void TearDown() {};
};

HWTEST_F(CryptoAesCipherTest, CryptoAesCipherTest001, TestSize.Level0)
{
    HcfSymKeyGenerator *generator = nullptr;
    HcfSymKey *key = nullptr;
    const char *inputAlgoName = "AES128";
    const char *generatorAlgoName = nullptr;

    int ret = HcfSymKeyGeneratorCreate(inputAlgoName, &generator);
    ASSERT_EQ(ret, 0);

    ret = generator->generateSymKey(generator, &key);
    ASSERT_EQ(ret, 0);

    generatorAlgoName = generator->getAlgoName(generator);
    ASSERT_NE(generatorAlgoName, nullptr);
    ASSERT_EQ(strcmp(generatorAlgoName, inputAlgoName), 0);

    HcfObjDestroy(key);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoAesCipherTest, CryptoAesCipherTest002, TestSize.Level0)
{
    HcfSymKeyGenerator *generator = nullptr;
    const char *generatorAlgoName = nullptr;
    const char *inputAlgoName = "AES128";

    int ret = HcfSymKeyGeneratorCreate(inputAlgoName, &generator);
    ASSERT_EQ(ret, 0);

    generatorAlgoName = generator->getAlgoName(nullptr);
    ASSERT_EQ(generatorAlgoName, nullptr);

    HcfObjDestroy(generator);
}

HWTEST_F(CryptoAesCipherTest, CryptoAesCipherTest003, TestSize.Level0)
{
    HcfSymKeyGenerator *generator = nullptr;
    HcfSymKey *key = nullptr;
    const char *generatorAlgoName = nullptr;
    const char *inputAlgoName = "AES128";

    int ret = HcfSymKeyGeneratorCreate(inputAlgoName, &generator);
    ASSERT_EQ(ret, 0);

    ret = generator->generateSymKey(generator, &key);
    ASSERT_EQ(ret, 0);

    generatorAlgoName = generator->getAlgoName(reinterpret_cast<HcfSymKeyGenerator *>(key));
    ASSERT_EQ(generatorAlgoName, nullptr);

    HcfObjDestroy(key);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoAesCipherTest, CryptoAesCipherTest004, TestSize.Level0)
{
    HcfSymKey *key = nullptr;
    const char *inputAlgoName = "AES128";
    const char *keyAlgoName = nullptr;

    int ret = GenerateSymKey(inputAlgoName, &key);
    ASSERT_EQ(ret, 0);

    keyAlgoName = key->key.getAlgorithm(&(key->key));
    ASSERT_NE(keyAlgoName, nullptr);
    ASSERT_EQ(strcmp(keyAlgoName, inputAlgoName), 0);

    HcfObjDestroy(key);
}

HWTEST_F(CryptoAesCipherTest, CryptoAesCipherTest005, TestSize.Level0)
{
    HcfSymKey *key = nullptr;
    const char *inputAlgoName = "AES128";
    const char *keyAlgoName = nullptr;

    int ret = GenerateSymKey(inputAlgoName, &key);
    ASSERT_EQ(ret, 0);

    keyAlgoName = key->key.getAlgorithm(nullptr);
    ASSERT_EQ(keyAlgoName, nullptr);

    HcfObjDestroy(key);
}

HWTEST_F(CryptoAesCipherTest, CryptoAesCipherTest006, TestSize.Level0)
{
    HcfSymKeyGenerator *generator = nullptr;
    HcfSymKey *key = nullptr;
    const char *inputAlgoName = "AES128";
    const char *keyAlgoName = nullptr;

    int ret = HcfSymKeyGeneratorCreate(inputAlgoName, &generator);
    ASSERT_EQ(ret, 0);

    ret = generator->generateSymKey(generator, &key);
    ASSERT_EQ(ret, 0);

    keyAlgoName = key->key.getAlgorithm(reinterpret_cast<HcfKey *>(generator));
    ASSERT_EQ(keyAlgoName, nullptr);

    HcfObjDestroy(key);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoAesCipherTest, CryptoAesCipherTest007, TestSize.Level0)
{
    HcfSymKey *key = nullptr;
    const char *keyFormat = "PKCS#8";
    const char *retFormat = nullptr;

    int ret = GenerateSymKey("AES128", &key);
    ASSERT_EQ(ret, 0);

    retFormat = key->key.getFormat(&(key->key));
    ASSERT_NE(retFormat, nullptr);
    ASSERT_EQ(strcmp(retFormat, keyFormat), 0);

    HcfObjDestroy(key);
}

HWTEST_F(CryptoAesCipherTest, CryptoAesCipherTest008, TestSize.Level0)
{
    HcfSymKey *key = nullptr;
    const char *retFormat = nullptr;

    int ret = GenerateSymKey("AES128", &key);
    ASSERT_EQ(ret, 0);

    retFormat = key->key.getFormat(nullptr);
    ASSERT_EQ(retFormat, nullptr);

    HcfObjDestroy(key);
}

HWTEST_F(CryptoAesCipherTest, CryptoAesCipherTest009, TestSize.Level0)
{
    HcfSymKeyGenerator *generator = nullptr;
    HcfSymKey *key = nullptr;
    const char *retFormat = nullptr;

    int ret = HcfSymKeyGeneratorCreate("AES128", &generator);
    ASSERT_EQ(ret, 0);

    ret = generator->generateSymKey(generator, &key);
    ASSERT_EQ(ret, 0);

    retFormat = key->key.getFormat(reinterpret_cast<HcfKey *>(generator));
    ASSERT_EQ(retFormat, nullptr);

    HcfObjDestroy(key);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoAesCipherTest, CryptoAesCipherTest010, TestSize.Level0)
{
    HcfSymKeyGenerator *generator = nullptr;
    HcfSymKey *key = nullptr;
    HcfBlob encodedBlob = { 0 };
    uint8_t keyMaterial[] = {
        0xba, 0x3b, 0xc2, 0x71, 0x21, 0x1e, 0x30, 0x56,
        0xad, 0x47, 0xfc, 0x5a, 0x46, 0x39, 0xee, 0x7c
    };
    HcfBlob keyTmpBlob = { .data = keyMaterial, .len = KEY_MATERIAL_LEN };

    int ret = HcfSymKeyGeneratorCreate("AES128", &generator);
    ASSERT_EQ(ret, 0);

    ret = generator->convertSymKey(generator, &keyTmpBlob, &key);
    ASSERT_EQ(ret, 0);

    ret = key->key.getEncoded(&(key->key), &encodedBlob);
    ASSERT_EQ(ret, 0);

    ASSERT_EQ(encodedBlob.len, keyTmpBlob.len);
    ASSERT_EQ(memcmp(encodedBlob.data, keyTmpBlob.data, keyTmpBlob.len), 0);

    HcfObjDestroy(key);
    HcfObjDestroy(generator);
    if (encodedBlob.data != nullptr) {
        HcfFree(encodedBlob.data);
        encodedBlob.data = nullptr;
    }
}

HWTEST_F(CryptoAesCipherTest, CryptoAesCipherTest011, TestSize.Level0)
{
    HcfSymKeyGenerator *generator = nullptr;
    HcfSymKey *key = nullptr;
    HcfBlob encodedBlob = { 0 };
    uint8_t keyMaterial[] = {
        0xba, 0x3b, 0xc2, 0x71, 0x21, 0x1e, 0x30, 0x56,
        0xad, 0x47, 0xfc, 0x5a, 0x46, 0x39, 0xee, 0x7c
    };
    HcfBlob keyTmpBlob = { .data = keyMaterial, .len = KEY_MATERIAL_LEN };

    int ret = HcfSymKeyGeneratorCreate("AES128", &generator);
    ASSERT_EQ(ret, 0);

    ret = generator->convertSymKey(generator, &keyTmpBlob, &key);
    ASSERT_EQ(ret, 0);

    ret = key->key.getEncoded(nullptr, &encodedBlob);
    ASSERT_NE(ret, 0);

    HcfObjDestroy(key);
    HcfObjDestroy(generator);
    if (encodedBlob.data != nullptr) {
        HcfFree(encodedBlob.data);
        encodedBlob.data = nullptr;
    }
}

HWTEST_F(CryptoAesCipherTest, CryptoAesCipherTest012, TestSize.Level0)
{
    HcfSymKeyGenerator *generator = nullptr;
    HcfSymKey *key = nullptr;
    HcfBlob encodedBlob = { 0 };
    uint8_t keyMaterial[] = {
        0xba, 0x3b, 0xc2, 0x71, 0x21, 0x1e, 0x30, 0x56,
        0xad, 0x47, 0xfc, 0x5a, 0x46, 0x39, 0xee, 0x7c
    };
    HcfBlob keyTmpBlob = { .data = keyMaterial, .len = KEY_MATERIAL_LEN };

    int ret = HcfSymKeyGeneratorCreate("AES128", &generator);
    ASSERT_EQ(ret, 0);

    ret = generator->convertSymKey(generator, &keyTmpBlob, &key);
    ASSERT_EQ(ret, 0);

    ret = key->key.getEncoded(reinterpret_cast<HcfKey *>(generator), &encodedBlob);
    ASSERT_NE(ret, 0);

    HcfObjDestroy(key);
    HcfObjDestroy(generator);
    if (encodedBlob.data != nullptr) {
        HcfFree(encodedBlob.data);
        encodedBlob.data = nullptr;
    }
}

HWTEST_F(CryptoAesCipherTest, CryptoAesCipherTest013, TestSize.Level0)
{
    HcfSymKeyGenerator *generator = nullptr;
    HcfSymKey *key = nullptr;
    HcfBlob encodedBlob = { 0 };
    uint8_t keyMaterial[] = {
        0xba, 0x3b, 0xc2, 0x71, 0x21, 0x1e, 0x30, 0x56,
        0xad, 0x47, 0xfc, 0x5a, 0x46, 0x39, 0xee, 0x7c
    };
    HcfBlob keyTmpBlob = { .data = keyMaterial, .len = KEY_MATERIAL_LEN };
    SymKeyImpl *impl = nullptr;
    size_t tmpLen = 0;

    int ret = HcfSymKeyGeneratorCreate("AES128", &generator);
    ASSERT_EQ(ret, 0);

    ret = generator->convertSymKey(generator, &keyTmpBlob, &key);
    ASSERT_EQ(ret, 0);

    impl = reinterpret_cast<SymKeyImpl *>(key);
    tmpLen = impl->keyMaterial.len;
    impl->keyMaterial.len = 0;

    // key getEncoded
    ret = key->key.getEncoded(&(key->key), &encodedBlob);
    impl->keyMaterial.len = tmpLen;
    ASSERT_NE(ret, 0);

    HcfObjDestroy(key);
    HcfObjDestroy(generator);
    if (encodedBlob.data != nullptr) {
        HcfFree(encodedBlob.data);
        encodedBlob.data = nullptr;
    }
}

HWTEST_F(CryptoAesCipherTest, CryptoAesCipherTest014, TestSize.Level0)
{
    HcfSymKeyGenerator *generator = nullptr;
    HcfSymKey *key = nullptr;
    HcfBlob encodedBlob = { 0 };
    uint8_t keyMaterial[] = {
        0xba, 0x3b, 0xc2, 0x71, 0x21, 0x1e, 0x30, 0x56,
        0xad, 0x47, 0xfc, 0x5a, 0x46, 0x39, 0xee, 0x7c
    };
    HcfBlob keyTmpBlob = { .data = keyMaterial, .len = KEY_MATERIAL_LEN };

    int ret = HcfSymKeyGeneratorCreate("AES128", &generator);
    ASSERT_EQ(ret, 0);

    ret = generator->convertSymKey(generator, &keyTmpBlob, &key);
    ASSERT_EQ(ret, 0);

    key->clearMem(nullptr);

    ret = key->key.getEncoded(&(key->key), &encodedBlob);
    ASSERT_EQ(ret, 0);
    ASSERT_FALSE((encodedBlob.data == nullptr) || (encodedBlob.data[0] == '\0'));

    HcfObjDestroy(key);
    HcfObjDestroy(generator);
    if (encodedBlob.data != nullptr) {
        HcfFree(encodedBlob.data);
        encodedBlob.data = nullptr;
    }
}

HWTEST_F(CryptoAesCipherTest, CryptoAesCipherTest015, TestSize.Level0)
{
    HcfSymKeyGenerator *generator = nullptr;

    int ret = HcfSymKeyGeneratorCreate("RSA128", &generator);
    ASSERT_NE(ret, 0);

    HcfObjDestroy(generator);
}

HWTEST_F(CryptoAesCipherTest, CryptoAesCipherTest016, TestSize.Level0)
{
    HcfSymKeyGenerator *generator = nullptr;

    int ret = HcfSymKeyGeneratorCreate("RSA512", &generator);
    ASSERT_NE(ret, 0);

    HcfObjDestroy(generator);
}

HWTEST_F(CryptoAesCipherTest, CryptoAesCipherTest017, TestSize.Level0)
{
    HcfSymKeyGenerator *generator = nullptr;

    int ret = HcfSymKeyGeneratorCreate("", &generator);
    ASSERT_NE(ret, 0);

    HcfObjDestroy(generator);
}

HWTEST_F(CryptoAesCipherTest, CryptoAesCipherTest018, TestSize.Level0)
{
    HcfSymKeyGenerator *generator = nullptr;

    int ret = HcfSymKeyGeneratorCreate(nullptr, &generator);
    ASSERT_NE(ret, 0);

    HcfObjDestroy(generator);
}

HWTEST_F(CryptoAesCipherTest, CryptoAesCipherTest019, TestSize.Level0)
{
    HcfSymKeyGenerator *generator = nullptr;

    int ret = HcfSymKeyGeneratorSpiCreate(nullptr, nullptr);
    ASSERT_NE(ret, 0);

    HcfObjDestroy(generator);
}

HWTEST_F(CryptoAesCipherTest, CryptoAesCipherTest020, TestSize.Level0)
{
    HcfSymKeyGenerator *generator = nullptr;
    HcfSymKey *key = nullptr;

    int ret = HcfSymKeyGeneratorCreate("AES128", &generator);
    ASSERT_EQ(ret, 0);

    ret = generator->generateSymKey(nullptr, &key);
    ASSERT_NE(ret, 0);

    HcfObjDestroy(key);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoAesCipherTest, CryptoAesCipherTest021, TestSize.Level0)
{
    HcfSymKeyGenerator *generator = nullptr;
    HcfSymKey *key = nullptr;
    uint8_t keyMaterial[] = {
        0xba, 0x3b, 0xc2, 0x71, 0x21, 0x1e, 0x30, 0x56,
        0xad, 0x47, 0xfc, 0x5a, 0x46, 0x39, 0xee, 0x7c
    };
    HcfBlob keyTmpBlob = { .data = keyMaterial, .len = KEY_MATERIAL_LEN };

    int ret = HcfSymKeyGeneratorCreate("AES128", &generator);
    ASSERT_EQ(ret, 0);

    ret = generator->convertSymKey(nullptr, &keyTmpBlob, &key);
    ASSERT_NE(ret, 0);

    HcfObjDestroy(key);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoAesCipherTest, CryptoAesCipherTest022, TestSize.Level0)
{
    HcfSymKeyGenerator *generator = nullptr;
    HcfSymKey *key = nullptr;
    uint8_t keyMaterial[] = {
        0xba, 0x3b, 0xc2, 0x71, 0x21, 0x1e, 0x30, 0x56,
        0xad, 0x47, 0xfc, 0x5a, 0x46, 0x39, 0xee, 0x7c
    };
    HcfBlob keyTmpBlob = { .data = keyMaterial, .len = 0 };

    int ret = HcfSymKeyGeneratorCreate("AES128", &generator);
    ASSERT_EQ(ret, 0);

    ret = generator->convertSymKey(generator, &keyTmpBlob, &key);
    ASSERT_NE(ret, 0);

    HcfObjDestroy(key);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoAesCipherTest, CryptoAesCipherTest023, TestSize.Level0)
{
    uint8_t cipherText[CIPHER_TEXT_LEN] = { 0 };
    int cipherTextLen = CIPHER_TEXT_LEN;
    HcfCipher *cipher = nullptr;
    HcfSymKey *key = nullptr;

    int ret = GenerateSymKey("AES128", &key);
    ASSERT_EQ(ret, 0);

    ret = HcfCipherCreate("AES128|NoPadding|PKCS5", &cipher);
    ASSERT_EQ(ret, 0);

    ret = AesEncrypt(cipher, key, nullptr, cipherText, &cipherTextLen);
    ASSERT_EQ(ret, 0);

    ret = AesDecrypt(cipher, key, nullptr, cipherText, cipherTextLen);
    ASSERT_EQ(ret, 0);

    HcfObjDestroy(key);
    HcfObjDestroy(cipher);
}

HWTEST_F(CryptoAesCipherTest, CryptoAesCipherTest024, TestSize.Level0)
{
    uint8_t cipherText[CIPHER_TEXT_LEN] = { 0 };
    int cipherTextLen = CIPHER_TEXT_LEN;
    HcfCipher *cipher = nullptr;
    HcfSymKey *key = nullptr;

    int ret = GenerateSymKey("AES128", &key);
    ASSERT_EQ(ret, 0);

    ret = HcfCipherCreate("AES128|PKCS5", &cipher);
    ASSERT_EQ(ret, 0);

    ret = AesEncrypt(cipher, key, nullptr, cipherText, &cipherTextLen);
    ASSERT_EQ(ret, 0);

    ret = AesDecrypt(cipher, key, nullptr, cipherText, cipherTextLen);
    ASSERT_EQ(ret, 0);

    HcfObjDestroy(key);
    HcfObjDestroy(cipher);
}

HWTEST_F(CryptoAesCipherTest, CryptoAesCipherTest025, TestSize.Level0)
{
    uint8_t cipherText[CIPHER_TEXT_LEN] = { 0 };
    int cipherTextLen = CIPHER_TEXT_LEN;
    HcfCipher *cipher = nullptr;
    HcfSymKey *key = nullptr;

    int ret = GenerateSymKey("AES128", &key);
    ASSERT_EQ(ret, 0);

    ret = HcfCipherCreate("AES128", &cipher);
    ASSERT_EQ(ret, 0);

    ret = AesEncrypt(cipher, key, nullptr, cipherText, &cipherTextLen);
    ASSERT_EQ(ret, 0);

    ret = AesDecrypt(cipher, key, nullptr, cipherText, cipherTextLen);
    ASSERT_EQ(ret, 0);

    HcfObjDestroy(key);
    HcfObjDestroy(cipher);
}

HWTEST_F(CryptoAesCipherTest, CryptoAesCipherTest026, TestSize.Level0)
{
    int ret = 0;
    HcfCipher *cipher = nullptr;

    ret = HcfCipherCreate("", &cipher);
    if (ret != 0) {
        LOGE("HcfCipherCreate failed!");
    }

    HcfObjDestroy(cipher);
    EXPECT_NE(ret, 0);
}

HWTEST_F(CryptoAesCipherTest, CryptoAesCipherTest027, TestSize.Level0)
{
    int ret = 0;
    HcfCipher *cipher = nullptr;

    ret = HcfCipherCreate(nullptr, &cipher);
    if (ret != 0) {
        LOGE("HcfCipherCreate failed!");
    }

    HcfObjDestroy(cipher);
    EXPECT_NE(ret, 0);
}

HWTEST_F(CryptoAesCipherTest, CryptoAesCipherTest028, TestSize.Level0)
{
    int ret = HcfCipherAesGeneratorSpiCreate(nullptr, nullptr);
    if (ret != 0) {
        LOGE("HcfCipherAesGeneratorSpiCreate failed!");
    }
    EXPECT_NE(ret, 0);

    HcfCipherGeneratorSpi *cipher = nullptr;
    CipherAttr params = {
        .algo = HCF_ALG_AES,
        .mode = HCF_ALG_MODE_ECB,
        .paddingMode = HCF_ALG_PADDING_PKCS5,
    };
    ret = HcfCipherAesGeneratorSpiCreate(&params, &cipher);
    EXPECT_EQ(ret, HCF_SUCCESS);

    ret = cipher->init(nullptr, ENCRYPT_MODE, nullptr, nullptr);
    EXPECT_EQ(ret, HCF_INVALID_PARAMS);

    ret = cipher->update(nullptr, nullptr, nullptr);
    EXPECT_EQ(ret, HCF_INVALID_PARAMS);

    ret = cipher->doFinal(nullptr, nullptr, nullptr);
    EXPECT_EQ(ret, HCF_INVALID_PARAMS);

    HcfBlob dataArray = { .data = nullptr, .len = 0 };
    ret = cipher->getCipherSpecString(nullptr, OAEP_MGF1_MD_STR, nullptr);
    EXPECT_EQ(ret, HCF_NOT_SUPPORT);

    ret = cipher->getCipherSpecUint8Array(nullptr, OAEP_MGF1_MD_STR, &dataArray);
    EXPECT_EQ(ret, HCF_NOT_SUPPORT);

    HcfBlob dataUint8 = { .data = nullptr, .len = 0 };
    ret = cipher->setCipherSpecUint8Array(nullptr, OAEP_MGF1_MD_STR, dataUint8);
    EXPECT_EQ(ret, HCF_NOT_SUPPORT);

    (void)cipher->base.destroy(nullptr);

    HcfObjDestroy(cipher);
    HcfBlobDataFree(&dataArray);
}

HWTEST_F(CryptoAesCipherTest, CryptoAesCipherTest029, TestSize.Level0)
{
    HcfSymKeyGeneratorSpi *generator = nullptr;
    HcfSymKey *key = nullptr;
    SymKeyAttr attr = { .algo = HCF_ALG_AES, .keySize = AES_KEY_SIZE };

    int ret = HcfSymKeyGeneratorSpiCreate(&attr, &generator);
    ASSERT_EQ(ret, 0);

    ret = generator->engineGenerateSymmKey(nullptr, &key);
    ASSERT_NE(ret, 0);

    HcfObjDestroy(key);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoAesCipherTest, CryptoAesCipherTest030, TestSize.Level0)
{
    HcfSymKeyGeneratorSpi *generator = nullptr;
    HcfSymKey *key = nullptr;
    uint8_t keyMaterial[] = {
        0xba, 0x3b, 0xc2, 0x71, 0x21, 0x1e, 0x30, 0x56,
        0xad, 0x47, 0xfc, 0x5a, 0x46, 0x39, 0xee, 0x7c
    };
    HcfBlob keyTmpBlob = { .data = keyMaterial, .len = KEY_MATERIAL_LEN };
    SymKeyAttr attr = { .algo = HCF_ALG_AES, .keySize = AES_KEY_SIZE };

    int ret = HcfSymKeyGeneratorSpiCreate(&attr, &generator);
    ASSERT_EQ(ret, 0);

    ret = generator->engineConvertSymmKey(nullptr, &keyTmpBlob, &key);
    ASSERT_NE(ret, 0);

    HcfObjDestroy(key);
    HcfObjDestroy(generator);
}
}