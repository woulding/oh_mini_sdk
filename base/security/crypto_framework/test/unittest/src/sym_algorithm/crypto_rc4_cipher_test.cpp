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

#include <gtest/gtest.h>
#include "securec.h"

#include "cipher.h"
#include "memory.h"
#include "sym_key_generator.h"
#include "sym_algorithm_common.h"

using namespace testing::ext;

namespace {
class CryptoRc4CipherTest : public testing::Test {
public:
    static void SetUpTestCase() {};
    static void TearDownTestCase() {};
    void SetUp() {};
    void TearDown() {};
};

HWTEST_F(CryptoRc4CipherTest, CryptoRc4CipherTest001, TestSize.Level0)
{
    uint8_t cipherText[SYM_ALG_CIPHER_TEXT_MAX_LEN] = {0};
    int cipherTextLen = SYM_ALG_CIPHER_TEXT_MAX_LEN;

    HcfSymKey *key = nullptr;
    HcfCipher *cipher = nullptr;

    uint8_t keyMaterial[16] = {0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
                               0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10};
    int ret = SymAlgConvertSymKey("RC4", keyMaterial, sizeof(keyMaterial), &key);
    ASSERT_EQ(ret, 0);

    ret = HcfCipherCreate("RC4", &cipher);
    ASSERT_EQ(ret, 0);

    ret = SymAlgEncrypt(cipher, key, nullptr, cipherText, &cipherTextLen);
    ASSERT_EQ(ret, 0);

    ret = SymAlgDecrypt(cipher, key, nullptr, cipherText, cipherTextLen);
    ASSERT_EQ(ret, 0);

    HcfObjDestroy((HcfObjectBase *)key);
    HcfObjDestroy((HcfObjectBase *)cipher);
}

HWTEST_F(CryptoRc4CipherTest, CryptoRc4CipherTest002, TestSize.Level0)
{
    uint8_t cipherText[SYM_ALG_CIPHER_TEXT_MAX_LEN] = {0};
    int cipherTextLen = SYM_ALG_CIPHER_TEXT_MAX_LEN;

    HcfSymKey *key = nullptr;
    HcfCipher *cipher = nullptr;

    uint8_t keyMaterial[16] = {0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
                               0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10};
    int ret = SymAlgConvertSymKey("RC4", keyMaterial, sizeof(keyMaterial), &key);
    ASSERT_EQ(ret, 0);

    ret = HcfCipherCreate("RC4", &cipher);
    ASSERT_EQ(ret, 0);

    ret = SymAlgNoUpdateEncrypt(cipher, key, nullptr, cipherText, &cipherTextLen);
    ASSERT_EQ(ret, 0);

    ret = SymAlgNoUpdateDecrypt(cipher, key, nullptr, cipherText, cipherTextLen);
    ASSERT_EQ(ret, 0);

    HcfObjDestroy((HcfObjectBase *)key);
    HcfObjDestroy((HcfObjectBase *)cipher);
}

HWTEST_F(CryptoRc4CipherTest, CryptoRc4CipherTest003, TestSize.Level0)
{
    uint8_t keyMaterial[16] = {0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
                              0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10};
    uint8_t cipherText[SYM_ALG_CIPHER_TEXT_MAX_LEN] = {0};
    int cipherTextLen = SYM_ALG_CIPHER_TEXT_MAX_LEN;

    HcfSymKey *key = nullptr;
    HcfCipher *cipher = nullptr;

    int ret = SymAlgConvertSymKey("RC4", keyMaterial, 16, &key);
    ASSERT_EQ(ret, 0);

    ret = HcfCipherCreate("RC4", &cipher);
    ASSERT_EQ(ret, 0);

    ret = SymAlgEncrypt(cipher, key, nullptr, cipherText, &cipherTextLen);
    ASSERT_EQ(ret, 0);

    ret = SymAlgDecrypt(cipher, key, nullptr, cipherText, cipherTextLen);
    ASSERT_EQ(ret, 0);

    HcfObjDestroy((HcfObjectBase *)key);
    HcfObjDestroy((HcfObjectBase *)cipher);
}

HWTEST_F(CryptoRc4CipherTest, CryptoRc4CipherTest004, TestSize.Level0)
{
    uint8_t keyMaterial[8] = {0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08};
    uint8_t cipherText[SYM_ALG_CIPHER_TEXT_MAX_LEN] = {0};
    int cipherTextLen = SYM_ALG_CIPHER_TEXT_MAX_LEN;

    HcfSymKey *key = nullptr;
    HcfCipher *cipher = nullptr;

    int ret = SymAlgConvertSymKey("RC4", keyMaterial, sizeof(keyMaterial), &key);
    ASSERT_EQ(ret, 0);

    ret = HcfCipherCreate("RC4", &cipher);
    ASSERT_EQ(ret, 0);

    ret = SymAlgEncrypt(cipher, key, nullptr, cipherText, &cipherTextLen);
    ASSERT_EQ(ret, 0);

    ret = SymAlgDecrypt(cipher, key, nullptr, cipherText, cipherTextLen);
    ASSERT_EQ(ret, 0);

    HcfObjDestroy((HcfObjectBase *)key);
    HcfObjDestroy((HcfObjectBase *)cipher);
}

HWTEST_F(CryptoRc4CipherTest, CryptoRc4CipherTest005, TestSize.Level0)
{
    uint8_t cipherText[SYM_ALG_CIPHER_TEXT_MAX_LEN] = {0};
    int cipherTextLen = SYM_ALG_CIPHER_TEXT_MAX_LEN;

    HcfSymKey *key = nullptr;
    HcfCipher *cipher = nullptr;

    uint8_t keyMaterial256[256] = {0};
    for (size_t i = 0; i < sizeof(keyMaterial256); i++) {
        keyMaterial256[i] = (uint8_t)(i & 0xff);
    }
    int ret = SymAlgConvertSymKey("RC4", keyMaterial256, sizeof(keyMaterial256), &key);
    ASSERT_EQ(ret, 0);

    ret = HcfCipherCreate("RC4", &cipher);
    ASSERT_EQ(ret, 0);

    ret = SymAlgEncrypt(cipher, key, nullptr, cipherText, &cipherTextLen);
    ASSERT_EQ(ret, 0);

    ret = SymAlgDecrypt(cipher, key, nullptr, cipherText, cipherTextLen);
    ASSERT_EQ(ret, 0);

    HcfObjDestroy((HcfObjectBase *)key);
    HcfObjDestroy((HcfObjectBase *)cipher);
}

HWTEST_F(CryptoRc4CipherTest, CryptoRc4CipherTest006, TestSize.Level0)
{
    uint8_t keyMaterial[16] = {0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef,
                              0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef};
    uint8_t plaintext[8] = {0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef};
    uint8_t expected[8] = {0x75, 0xb7, 0x87, 0x80, 0x99, 0xe0, 0xc5, 0x96};
    HcfSymKey *key = nullptr;
    HcfCipher *cipher = nullptr;
    HcfBlob plainTextBlob = {.data = plaintext, .len = sizeof(plaintext)};
    HcfBlob cipherTextBlob = {};

    int res = SymAlgConvertSymKey("RC4", keyMaterial, sizeof(keyMaterial), &key);
    ASSERT_EQ(res, 0);
    HcfResult ret = HcfCipherCreate("RC4", &cipher);
    ASSERT_EQ(ret, HCF_SUCCESS);
    ret = cipher->init(cipher, ENCRYPT_MODE, (HcfKey *)key, nullptr);
    ASSERT_EQ(ret, HCF_SUCCESS);
    ret = cipher->doFinal(cipher, &plainTextBlob, &cipherTextBlob);
    ASSERT_EQ(ret, HCF_SUCCESS);
    EXPECT_EQ(cipherTextBlob.len, sizeof(expected));
    EXPECT_EQ(memcmp(cipherTextBlob.data, expected, sizeof(expected)), 0);
    if (cipherTextBlob.data != nullptr) {
        HcfBlobDataFree(&cipherTextBlob);
    }
    HcfObjDestroy((HcfObjectBase *)key);
    HcfObjDestroy((HcfObjectBase *)cipher);
}

HWTEST_F(CryptoRc4CipherTest, CryptoRc4CipherTest007, TestSize.Level0)
{
    uint8_t keyMaterial[16] = {0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef,
                              0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef};
    uint8_t plaintext[8] = {0};
    uint8_t expected[8] = {0x74, 0x94, 0xc2, 0xe7, 0x10, 0x4b, 0x08, 0x79};
    HcfSymKey *key = nullptr;
    HcfCipher *cipher = nullptr;
    HcfBlob plainTextBlob = {.data = plaintext, .len = sizeof(plaintext)};
    HcfBlob cipherTextBlob = {};

    int res = SymAlgConvertSymKey("RC4", keyMaterial, sizeof(keyMaterial), &key);
    ASSERT_EQ(res, 0);
    HcfResult ret = HcfCipherCreate("RC4", &cipher);
    ASSERT_EQ(ret, HCF_SUCCESS);
    ret = cipher->init(cipher, ENCRYPT_MODE, (HcfKey *)key, nullptr);
    ASSERT_EQ(ret, HCF_SUCCESS);
    ret = cipher->doFinal(cipher, &plainTextBlob, &cipherTextBlob);
    ASSERT_EQ(ret, HCF_SUCCESS);
    EXPECT_EQ(cipherTextBlob.len, sizeof(expected));
    EXPECT_EQ(memcmp(cipherTextBlob.data, expected, sizeof(expected)), 0);
    if (cipherTextBlob.data != nullptr) {
        HcfBlobDataFree(&cipherTextBlob);
    }
    HcfObjDestroy((HcfObjectBase *)key);
    HcfObjDestroy((HcfObjectBase *)cipher);
}

HWTEST_F(CryptoRc4CipherTest, CryptoRc4CipherTest008, TestSize.Level0)
{
    uint8_t keyMaterial[16] = {0};
    uint8_t plaintext[8] = {0};
    uint8_t expected[8] = {0xde, 0x18, 0x89, 0x41, 0xa3, 0x37, 0x5d, 0x3a};
    HcfSymKey *key = nullptr;
    HcfCipher *cipher = nullptr;
    HcfBlob plainTextBlob = {.data = plaintext, .len = sizeof(plaintext)};
    HcfBlob cipherTextBlob = {};

    int res = SymAlgConvertSymKey("RC4", keyMaterial, sizeof(keyMaterial), &key);
    ASSERT_EQ(res, 0);
    HcfResult ret = HcfCipherCreate("RC4", &cipher);
    ASSERT_EQ(ret, HCF_SUCCESS);
    ret = cipher->init(cipher, ENCRYPT_MODE, (HcfKey *)key, nullptr);
    ASSERT_EQ(ret, HCF_SUCCESS);
    ret = cipher->doFinal(cipher, &plainTextBlob, &cipherTextBlob);
    ASSERT_EQ(ret, HCF_SUCCESS);
    EXPECT_EQ(cipherTextBlob.len, sizeof(expected));
    EXPECT_EQ(memcmp(cipherTextBlob.data, expected, sizeof(expected)), 0);
    if (cipherTextBlob.data != nullptr) {
        HcfBlobDataFree(&cipherTextBlob);
    }
    HcfObjDestroy((HcfObjectBase *)key);
    HcfObjDestroy((HcfObjectBase *)cipher);
}

HWTEST_F(CryptoRc4CipherTest, CryptoRc4CipherTest009, TestSize.Level0)
{
    uint8_t keyMaterial[16] = {0xef, 0x01, 0x23, 0x45, 0xef, 0x01, 0x23, 0x45,
                              0xef, 0x01, 0x23, 0x45, 0xef, 0x01, 0x23, 0x45};
    uint8_t plaintext[20] = {0};
    uint8_t expected[20] = {0xd6, 0xa1, 0x41, 0xa7, 0xec, 0x3c, 0x38, 0xdf,
                            0xbd, 0x61, 0x5a, 0x11, 0x62, 0xe1, 0xc7, 0xba, 0x36, 0xb6, 0x78, 0x58};
    HcfSymKey *key = nullptr;
    HcfCipher *cipher = nullptr;
    HcfBlob plainTextBlob = {.data = plaintext, .len = sizeof(plaintext)};
    HcfBlob cipherTextBlob = {};

    int res = SymAlgConvertSymKey("RC4", keyMaterial, sizeof(keyMaterial), &key);
    ASSERT_EQ(res, 0);
    HcfResult ret = HcfCipherCreate("RC4", &cipher);
    ASSERT_EQ(ret, HCF_SUCCESS);
    ret = cipher->init(cipher, ENCRYPT_MODE, (HcfKey *)key, nullptr);
    ASSERT_EQ(ret, HCF_SUCCESS);
    ret = cipher->doFinal(cipher, &plainTextBlob, &cipherTextBlob);
    ASSERT_EQ(ret, HCF_SUCCESS);
    EXPECT_EQ(cipherTextBlob.len, sizeof(expected));
    EXPECT_EQ(memcmp(cipherTextBlob.data, expected, sizeof(expected)), 0);
    if (cipherTextBlob.data != nullptr) {
        HcfBlobDataFree(&cipherTextBlob);
    }
    HcfObjDestroy((HcfObjectBase *)key);
    HcfObjDestroy((HcfObjectBase *)cipher);
}

HWTEST_F(CryptoRc4CipherTest, CryptoRc4CipherTest010, TestSize.Level0)
{
    uint8_t keyMaterial[16] = {0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef,
                              0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef};
    uint8_t plaintext[28] = {0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC, 0xDE, 0xF0,
                            0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC, 0xDE, 0xF0,
                            0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC, 0xDE, 0xF0,
                            0x12, 0x34, 0x56, 0x78};
    uint8_t expected[28] = {0x66, 0xa0, 0x94, 0x9f, 0x8a, 0xf7, 0xd6, 0x89,
                           0x1f, 0x7f, 0x83, 0x2b, 0xa8, 0x33, 0xc0, 0x0c,
                           0x89, 0x2e, 0xbe, 0x30, 0x14, 0x3c, 0xe2, 0x87,
                           0x40, 0x01, 0x1e, 0xcf};
    HcfSymKey *key = nullptr;
    HcfCipher *cipher = nullptr;
    HcfBlob plainTextBlob = {.data = plaintext, .len = sizeof(plaintext)};
    HcfBlob cipherTextBlob = {};

    int res = SymAlgConvertSymKey("RC4", keyMaterial, sizeof(keyMaterial), &key);
    ASSERT_EQ(res, 0);
    HcfResult ret = HcfCipherCreate("RC4", &cipher);
    ASSERT_EQ(ret, HCF_SUCCESS);
    ret = cipher->init(cipher, ENCRYPT_MODE, (HcfKey *)key, nullptr);
    ASSERT_EQ(ret, HCF_SUCCESS);
    ret = cipher->doFinal(cipher, &plainTextBlob, &cipherTextBlob);
    ASSERT_EQ(ret, HCF_SUCCESS);
    EXPECT_EQ(cipherTextBlob.len, sizeof(expected));
    EXPECT_EQ(memcmp(cipherTextBlob.data, expected, sizeof(expected)), 0);
    if (cipherTextBlob.data != nullptr) {
        HcfBlobDataFree(&cipherTextBlob);
    }
    HcfObjDestroy((HcfObjectBase *)key);
    HcfObjDestroy((HcfObjectBase *)cipher);
}

HWTEST_F(CryptoRc4CipherTest, CryptoRc4CipherTest011, TestSize.Level0)
{
    uint8_t keyMaterial[16] = {0xef, 0x01, 0x23, 0x45, 0xef, 0x01, 0x23, 0x45,
                              0xef, 0x01, 0x23, 0x45, 0xef, 0x01, 0x23, 0x45};
    uint8_t plaintext[10] = {0};
    uint8_t expected[10] = {0xd6, 0xa1, 0x41, 0xa7, 0xec, 0x3c, 0x38, 0xdf, 0xbd, 0x61};
    HcfSymKey *key = nullptr;
    HcfCipher *cipher = nullptr;
    HcfBlob plainTextBlob = {.data = plaintext, .len = sizeof(plaintext)};
    HcfBlob cipherTextBlob = {};

    int res = SymAlgConvertSymKey("RC4", keyMaterial, sizeof(keyMaterial), &key);
    ASSERT_EQ(res, 0);
    HcfResult ret = HcfCipherCreate("RC4", &cipher);
    ASSERT_EQ(ret, HCF_SUCCESS);
    ret = cipher->init(cipher, ENCRYPT_MODE, (HcfKey *)key, nullptr);
    ASSERT_EQ(ret, HCF_SUCCESS);
    ret = cipher->doFinal(cipher, &plainTextBlob, &cipherTextBlob);
    ASSERT_EQ(ret, HCF_SUCCESS);
    EXPECT_EQ(cipherTextBlob.len, sizeof(expected));
    EXPECT_EQ(memcmp(cipherTextBlob.data, expected, sizeof(expected)), 0);
    if (cipherTextBlob.data != nullptr) {
        HcfBlobDataFree(&cipherTextBlob);
    }
    HcfObjDestroy((HcfObjectBase *)key);
    HcfObjDestroy((HcfObjectBase *)cipher);
}

HWTEST_F(CryptoRc4CipherTest, CryptoRc4CipherTest012, TestSize.Level0)
{
    uint8_t keyMaterial[5] = {0x01, 0x02, 0x03, 0x04, 0x05};
    uint8_t plaintext[16] = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                             0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
    uint8_t expected[16] = {0xb2, 0x39, 0x63, 0x05, 0xf0, 0x3d, 0xc0, 0x27,
                            0xcc, 0xc3, 0x52, 0x4a, 0x0a, 0x11, 0x18, 0xa8};
    HcfSymKey *key = nullptr;
    HcfCipher *cipher = nullptr;
    HcfBlob plainTextBlob = {.data = plaintext, .len = sizeof(plaintext)};
    HcfBlob cipherTextBlob = {};

    int res = SymAlgConvertSymKey("RC4", keyMaterial, sizeof(keyMaterial), &key);
    ASSERT_EQ(res, 0);
    HcfResult ret = HcfCipherCreate("RC4", &cipher);
    ASSERT_EQ(ret, HCF_SUCCESS);
    ret = cipher->init(cipher, ENCRYPT_MODE, (HcfKey *)key, nullptr);
    ASSERT_EQ(ret, HCF_SUCCESS);
    ret = cipher->doFinal(cipher, &plainTextBlob, &cipherTextBlob);
    ASSERT_EQ(ret, HCF_SUCCESS);
    EXPECT_EQ(cipherTextBlob.len, sizeof(expected));
    EXPECT_EQ(memcmp(cipherTextBlob.data, expected, sizeof(expected)), 0);
    if (cipherTextBlob.data != nullptr) {
        HcfBlobDataFree(&cipherTextBlob);
    }
    HcfObjDestroy((HcfObjectBase *)key);
    HcfObjDestroy((HcfObjectBase *)cipher);
}

HWTEST_F(CryptoRc4CipherTest, CryptoRc4CipherTest013, TestSize.Level0)
{
    uint8_t keyMaterial[5] = {0x83, 0x32, 0x22, 0x77, 0x2a};
    uint8_t plaintext[16] = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                             0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
    uint8_t expected[16] = {0x80, 0xad, 0x97, 0xbd, 0xc9, 0x73, 0xdf, 0x8a,
                            0x2e, 0x87, 0x9e, 0x92, 0xa4, 0x97, 0xef, 0xda};
    HcfSymKey *key = nullptr;
    HcfCipher *cipher = nullptr;
    HcfBlob plainTextBlob = {.data = plaintext, .len = sizeof(plaintext)};
    HcfBlob cipherTextBlob = {};

    int res = SymAlgConvertSymKey("RC4", keyMaterial, sizeof(keyMaterial), &key);
    ASSERT_EQ(res, 0);
    HcfResult ret = HcfCipherCreate("RC4", &cipher);
    ASSERT_EQ(ret, HCF_SUCCESS);
    ret = cipher->init(cipher, ENCRYPT_MODE, (HcfKey *)key, nullptr);
    ASSERT_EQ(ret, HCF_SUCCESS);
    ret = cipher->doFinal(cipher, &plainTextBlob, &cipherTextBlob);
    ASSERT_EQ(ret, HCF_SUCCESS);
    EXPECT_EQ(cipherTextBlob.len, sizeof(expected));
    EXPECT_EQ(memcmp(cipherTextBlob.data, expected, sizeof(expected)), 0);
    if (cipherTextBlob.data != nullptr) {
        HcfBlobDataFree(&cipherTextBlob);
    }
    HcfObjDestroy((HcfObjectBase *)key);
    HcfObjDestroy((HcfObjectBase *)cipher);
}

HWTEST_F(CryptoRc4CipherTest, CryptoRc4CipherTest014, TestSize.Level0)
{
    uint8_t keyMaterial[16] = {0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
                              0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10};
    uint8_t plaintext[16] = {0};
    uint8_t expected[16] = {0x9a, 0xc7, 0xcc, 0x9a, 0x60, 0x9d, 0x1e, 0xf7,
                            0xb2, 0x93, 0x28, 0x99, 0xcd, 0xe4, 0x1b, 0x97};
    HcfSymKey *key = nullptr;
    HcfCipher *cipher = nullptr;
    HcfBlob plainTextBlob = {.data = plaintext, .len = sizeof(plaintext)};
    HcfBlob cipherTextBlob = {};

    int res = SymAlgConvertSymKey("RC4", keyMaterial, sizeof(keyMaterial), &key);
    ASSERT_EQ(res, 0);
    HcfResult ret = HcfCipherCreate("RC4", &cipher);
    ASSERT_EQ(ret, HCF_SUCCESS);
    ret = cipher->init(cipher, ENCRYPT_MODE, (HcfKey *)key, nullptr);
    ASSERT_EQ(ret, HCF_SUCCESS);
    ret = cipher->doFinal(cipher, &plainTextBlob, &cipherTextBlob);
    ASSERT_EQ(ret, HCF_SUCCESS);
    EXPECT_EQ(cipherTextBlob.len, sizeof(expected));
    EXPECT_EQ(memcmp(cipherTextBlob.data, expected, sizeof(expected)), 0);
    if (cipherTextBlob.data != nullptr) {
        HcfBlobDataFree(&cipherTextBlob);
    }
    HcfObjDestroy((HcfObjectBase *)key);
    HcfObjDestroy((HcfObjectBase *)cipher);
}

HWTEST_F(CryptoRc4CipherTest, CryptoRc4CipherTest015, TestSize.Level0)
{
    uint8_t keyMaterial[16] = {0xeb, 0xb4, 0x62, 0x27, 0xc6, 0xcc, 0x8b, 0x37,
                              0x64, 0x19, 0x10, 0x83, 0x32, 0x22, 0x77, 0x2a};
    uint8_t plaintext[16] = {0};
    uint8_t expected[16] = {0x72, 0x0c, 0x94, 0xb6, 0x3e, 0xdf, 0x44, 0xe1,
                           0x31, 0xd9, 0x50, 0xca, 0x21, 0x1a, 0x5a, 0x30};
    HcfSymKey *key = nullptr;
    HcfCipher *cipher = nullptr;
    HcfBlob plainTextBlob = {.data = plaintext, .len = sizeof(plaintext)};
    HcfBlob cipherTextBlob = {};

    int res = SymAlgConvertSymKey("RC4", keyMaterial, sizeof(keyMaterial), &key);
    ASSERT_EQ(res, 0);
    HcfResult ret = HcfCipherCreate("RC4", &cipher);
    ASSERT_EQ(ret, HCF_SUCCESS);
    ret = cipher->init(cipher, ENCRYPT_MODE, (HcfKey *)key, nullptr);
    ASSERT_EQ(ret, HCF_SUCCESS);
    ret = cipher->doFinal(cipher, &plainTextBlob, &cipherTextBlob);
    ASSERT_EQ(ret, HCF_SUCCESS);
    EXPECT_EQ(cipherTextBlob.len, sizeof(expected));
    EXPECT_EQ(memcmp(cipherTextBlob.data, expected, sizeof(expected)), 0);
    if (cipherTextBlob.data != nullptr) {
        HcfBlobDataFree(&cipherTextBlob);
    }
    HcfObjDestroy((HcfObjectBase *)key);
    HcfObjDestroy((HcfObjectBase *)cipher);
}
}
