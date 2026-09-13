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
#include "detailed_iv_params.h"
#include "memory.h"
#include "sym_key_generator.h"
#include "sym_algorithm_common.h"

using namespace testing::ext;

namespace {
class CryptoBlowfishCipherTest : public testing::Test {
public:
    static void SetUpTestCase() {};
    static void TearDownTestCase() {};
    void SetUp() {};
    void TearDown() {};
};

HWTEST_F(CryptoBlowfishCipherTest, CryptoBlowfishCipherTest001, TestSize.Level0)
{
    uint8_t iv[SYM_ALG_IV_LEN] = {0};
    uint8_t keyMaterial[4] = {0x01, 0x02, 0x03, 0x04};
    uint8_t cipherText[SYM_ALG_CIPHER_TEXT_MAX_LEN] = {0};
    int cipherTextLen = SYM_ALG_CIPHER_TEXT_MAX_LEN;

    HcfIvParamsSpec ivSpec = {};
    ivSpec.iv.data = iv;
    ivSpec.iv.len = SYM_ALG_IV_LEN;

    HcfSymKey *key = nullptr;
    HcfCipher *cipher = nullptr;

    int ret = SymAlgConvertSymKey("Blowfish", keyMaterial, sizeof(keyMaterial), &key);
    ASSERT_EQ(ret, 0);

    ret = HcfCipherCreate("Blowfish|CBC|PKCS7", &cipher);
    ASSERT_EQ(ret, 0);

    ret = SymAlgEncrypt(cipher, key, (HcfParamsSpec *)&ivSpec, cipherText, &cipherTextLen);
    ASSERT_EQ(ret, 0);

    ret = SymAlgDecrypt(cipher, key, (HcfParamsSpec *)&ivSpec, cipherText, cipherTextLen);
    ASSERT_EQ(ret, 0);

    HcfObjDestroy((HcfObjectBase *)key);
    HcfObjDestroy((HcfObjectBase *)cipher);
}

HWTEST_F(CryptoBlowfishCipherTest, CryptoBlowfishCipherTest002, TestSize.Level0)
{
    uint8_t keyMaterial[4] = {0x01, 0x02, 0x03, 0x04};
    uint8_t cipherText[SYM_ALG_CIPHER_TEXT_MAX_LEN] = {0};
    int cipherTextLen = SYM_ALG_CIPHER_TEXT_MAX_LEN;

    HcfSymKey *key = nullptr;
    HcfCipher *cipher = nullptr;

    int ret = SymAlgConvertSymKey("Blowfish", keyMaterial, sizeof(keyMaterial), &key);
    ASSERT_EQ(ret, 0);

    ret = HcfCipherCreate("Blowfish|ECB|PKCS7", &cipher);
    ASSERT_EQ(ret, 0);

    ret = SymAlgEncrypt(cipher, key, nullptr, cipherText, &cipherTextLen);
    ASSERT_EQ(ret, 0);

    ret = SymAlgDecrypt(cipher, key, nullptr, cipherText, cipherTextLen);
    ASSERT_EQ(ret, 0);

    HcfObjDestroy((HcfObjectBase *)key);
    HcfObjDestroy((HcfObjectBase *)cipher);
}

HWTEST_F(CryptoBlowfishCipherTest, CryptoBlowfishCipherTest003, TestSize.Level0)
{
    uint8_t iv[SYM_ALG_IV_LEN] = {0};
    uint8_t keyMaterial[8] = {0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08};
    uint8_t cipherText[SYM_ALG_CIPHER_TEXT_MAX_LEN] = {0};
    int cipherTextLen = SYM_ALG_CIPHER_TEXT_MAX_LEN;

    HcfIvParamsSpec ivSpec = {};
    ivSpec.iv.data = iv;
    ivSpec.iv.len = SYM_ALG_IV_LEN;

    HcfSymKey *key = nullptr;
    HcfCipher *cipher = nullptr;

    int ret = SymAlgConvertSymKey("Blowfish", keyMaterial, sizeof(keyMaterial), &key);
    ASSERT_EQ(ret, 0);

    ret = HcfCipherCreate("Blowfish|CBC|PKCS7", &cipher);
    ASSERT_EQ(ret, 0);

    ret = SymAlgEncrypt(cipher, key, (HcfParamsSpec *)&ivSpec, cipherText, &cipherTextLen);
    ASSERT_EQ(ret, 0);

    ret = SymAlgDecrypt(cipher, key, (HcfParamsSpec *)&ivSpec, cipherText, cipherTextLen);
    ASSERT_EQ(ret, 0);

    HcfObjDestroy((HcfObjectBase *)key);
    HcfObjDestroy((HcfObjectBase *)cipher);
}

HWTEST_F(CryptoBlowfishCipherTest, CryptoBlowfishCipherTest004, TestSize.Level0)
{
    uint8_t iv[SYM_ALG_IV_LEN] = {0};
    uint8_t keyMaterial[4] = {0x01, 0x02, 0x03, 0x04};
    uint8_t cipherText[SYM_ALG_CIPHER_TEXT_MAX_LEN] = {0};
    int cipherTextLen = SYM_ALG_CIPHER_TEXT_MAX_LEN;

    HcfIvParamsSpec ivSpec = {};
    ivSpec.iv.data = iv;
    ivSpec.iv.len = SYM_ALG_IV_LEN;

    HcfSymKey *key = nullptr;
    HcfCipher *cipher = nullptr;

    int ret = SymAlgConvertSymKey("Blowfish", keyMaterial, sizeof(keyMaterial), &key);
    ASSERT_EQ(ret, 0);

    ret = HcfCipherCreate("Blowfish|CBC|PKCS7", &cipher);
    ASSERT_EQ(ret, 0);

    ret = SymAlgEncrypt(cipher, key, (HcfParamsSpec *)&ivSpec, cipherText, &cipherTextLen);
    ASSERT_EQ(ret, 0);

    ret = SymAlgDecrypt(cipher, key, (HcfParamsSpec *)&ivSpec, cipherText, cipherTextLen);
    ASSERT_EQ(ret, 0);

    HcfObjDestroy((HcfObjectBase *)key);
    HcfObjDestroy((HcfObjectBase *)cipher);
}

HWTEST_F(CryptoBlowfishCipherTest, CryptoBlowfishCipherTest005, TestSize.Level0)
{
    uint8_t iv[SYM_ALG_IV_LEN] = {0};
    uint8_t keyMaterial[32] = {0};
    for (size_t i = 0; i < sizeof(keyMaterial); i++) {
        keyMaterial[i] = (uint8_t)(i & 0xff);
    }
    uint8_t cipherText[SYM_ALG_CIPHER_TEXT_MAX_LEN] = {0};
    int cipherTextLen = SYM_ALG_CIPHER_TEXT_MAX_LEN;

    HcfIvParamsSpec ivSpec = {};
    ivSpec.iv.data = iv;
    ivSpec.iv.len = SYM_ALG_IV_LEN;

    HcfSymKey *key = nullptr;
    HcfCipher *cipher = nullptr;

    int ret = SymAlgConvertSymKey("Blowfish", keyMaterial, sizeof(keyMaterial), &key);
    ASSERT_EQ(ret, 0);

    ret = HcfCipherCreate("Blowfish|CBC|PKCS7", &cipher);
    ASSERT_EQ(ret, 0);

    ret = SymAlgEncrypt(cipher, key, (HcfParamsSpec *)&ivSpec, cipherText, &cipherTextLen);
    ASSERT_EQ(ret, 0);

    ret = SymAlgDecrypt(cipher, key, (HcfParamsSpec *)&ivSpec, cipherText, cipherTextLen);
    ASSERT_EQ(ret, 0);

    HcfObjDestroy((HcfObjectBase *)key);
    HcfObjDestroy((HcfObjectBase *)cipher);
}

HWTEST_F(CryptoBlowfishCipherTest, CryptoBlowfishCipherTest006, TestSize.Level0)
{
    uint8_t keyMaterial[16] = {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
                               0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f};
    uint8_t plaintext[16] = {0x0f, 0x0e, 0x0c, 0x0d, 0x0b, 0x0a, 0x09, 0x08,
                             0x07, 0x06, 0x05, 0x04, 0x03, 0x02, 0x01, 0x00};
    uint8_t expected[16] = {0x07, 0x95, 0x90, 0xe0, 0x01, 0x06, 0x26, 0x68,
                            0x56, 0x53, 0xb9, 0xb6, 0xc2, 0xa4, 0x06, 0xe0};
    HcfSymKey *key = nullptr;
    HcfCipher *cipher = nullptr;
    HcfBlob plainTextBlob = {.data = plaintext, .len = sizeof(plaintext)};
    HcfBlob cipherTextBlob = {};

    int res = SymAlgConvertSymKey("Blowfish", keyMaterial, sizeof(keyMaterial), &key);
    ASSERT_EQ(res, 0);
    HcfResult ret = HcfCipherCreate("Blowfish|ECB|NoPadding", &cipher);
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
    HcfObjDestroy(key);
    HcfObjDestroy(cipher);
}

HWTEST_F(CryptoBlowfishCipherTest, CryptoBlowfishCipherTest007, TestSize.Level0)
{
    uint8_t keyMaterial[] = {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
                              0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
                              0x00, 0x00, 0x00, 0x00};
    uint8_t plaintext[] = {0x0f, 0x0e, 0x0c, 0x0d, 0x0b, 0x0a, 0x09, 0x08,
                             0x07, 0x06, 0x05, 0x04, 0x03, 0x02, 0x01, 0x00};
    HcfSymKey *key = nullptr;
    HcfCipher *cipher = nullptr;
    HcfBlob plainTextBlob = {.data = plaintext, .len = sizeof(plaintext)};
    HcfBlob cipherTextBlob = {};
    HcfBlob decryptedBlob = {};

    int res = SymAlgConvertSymKey("Blowfish", keyMaterial, sizeof(keyMaterial), &key);
    ASSERT_EQ(res, 0);
    HcfResult ret = HcfCipherCreate("Blowfish|ECB|NoPadding", &cipher);
    ASSERT_EQ(ret, HCF_SUCCESS);
    ret = cipher->init(cipher, ENCRYPT_MODE, (HcfKey *)key, nullptr);
    ASSERT_EQ(ret, HCF_SUCCESS);
    ret = cipher->doFinal(cipher, &plainTextBlob, &cipherTextBlob);
    ASSERT_EQ(ret, HCF_SUCCESS);
    EXPECT_EQ(cipherTextBlob.len, sizeof(plaintext));

    ret = cipher->init(cipher, DECRYPT_MODE, (HcfKey *)key, nullptr);
    ASSERT_EQ(ret, HCF_SUCCESS);
    ret = cipher->doFinal(cipher, &cipherTextBlob, &decryptedBlob);
    ASSERT_EQ(ret, HCF_SUCCESS);
    EXPECT_EQ(decryptedBlob.len, sizeof(plaintext));
    EXPECT_EQ(memcmp(decryptedBlob.data, plaintext, sizeof(plaintext)), 0);

    if (cipherTextBlob.data != nullptr) {
        HcfBlobDataFree(&cipherTextBlob);
    }
    if (decryptedBlob.data != nullptr) {
        HcfBlobDataFree(&decryptedBlob);
    }
    HcfObjDestroy(key);
    HcfObjDestroy(cipher);
}

HWTEST_F(CryptoBlowfishCipherTest, CryptoBlowfishCipherTest008, TestSize.Level0)
{
    uint8_t keyMaterial[16] = {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
                               0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f};
    uint8_t iv[8] = {0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01};
    uint8_t plaintext[16] = {0x0f, 0x0e, 0x0c, 0x0d, 0x0b, 0x0a, 0x09, 0x08,
                             0x07, 0x06, 0x05, 0x04, 0x03, 0x02, 0x01, 0x00};
    uint8_t expected[16] = {0x39, 0xc6, 0x50, 0x06, 0x74, 0x2b, 0x62, 0xa4,
                            0x9f, 0x7a, 0x40, 0xff, 0x69, 0x74, 0x9c, 0x0a};
    HcfSymKey *key = nullptr;
    HcfCipher *cipher = nullptr;
    HcfIvParamsSpec ivSpec = {};
    ivSpec.iv.data = iv;
    ivSpec.iv.len = sizeof(iv);
    HcfBlob plainTextBlob = {.data = plaintext, .len = sizeof(plaintext)};
    HcfBlob cipherTextBlob = {};

    int res = SymAlgConvertSymKey("Blowfish", keyMaterial, sizeof(keyMaterial), &key);
    ASSERT_EQ(res, 0);
    HcfResult ret = HcfCipherCreate("Blowfish|CBC|NoPadding", &cipher);
    ASSERT_EQ(ret, HCF_SUCCESS);
    ret = cipher->init(cipher, ENCRYPT_MODE, (HcfKey *)key, (HcfParamsSpec *)&ivSpec);
    ASSERT_EQ(ret, HCF_SUCCESS);
    ret = cipher->doFinal(cipher, &plainTextBlob, &cipherTextBlob);
    ASSERT_EQ(ret, HCF_SUCCESS);
    EXPECT_EQ(cipherTextBlob.len, sizeof(expected));
    EXPECT_EQ(memcmp(cipherTextBlob.data, expected, sizeof(expected)), 0);
    if (cipherTextBlob.data != nullptr) {
        HcfBlobDataFree(&cipherTextBlob);
    }
    HcfObjDestroy(key);
    HcfObjDestroy(cipher);
}

HWTEST_F(CryptoBlowfishCipherTest, CryptoBlowfishCipherTest009, TestSize.Level0)
{
    uint8_t keyMaterial[] = {
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
        0x00, 0x00, 0x00, 0x00};
    uint8_t iv[] = {0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01};
    uint8_t plaintext[] = {0x0f, 0x0e, 0x0c, 0x0d, 0x0b, 0x0a, 0x09, 0x08,
                             0x07, 0x06, 0x05, 0x04, 0x03, 0x02, 0x01, 0x00};
    uint8_t expected[] = {0x3a, 0x5c, 0xef, 0xdb, 0x91, 0xe5, 0x6e, 0x7a,
                            0xab, 0x45, 0xe7, 0xea, 0x56, 0x2b, 0xd4, 0x65};
    HcfSymKey *key = nullptr;
    HcfCipher *cipher = nullptr;
    HcfIvParamsSpec ivSpec = {};
    ivSpec.iv.data = iv;
    ivSpec.iv.len = sizeof(iv);
    HcfBlob plainTextBlob = {.data = plaintext, .len = sizeof(plaintext)};
    HcfBlob cipherTextBlob = {};

    int res = SymAlgConvertSymKey("Blowfish", keyMaterial, sizeof(keyMaterial), &key);
    ASSERT_EQ(res, 0);
    HcfResult ret = HcfCipherCreate("Blowfish|CBC|NoPadding", &cipher);
    ASSERT_EQ(ret, HCF_SUCCESS);
    ret = cipher->init(cipher, ENCRYPT_MODE, (HcfKey *)key, (HcfParamsSpec *)&ivSpec);
    ASSERT_EQ(ret, HCF_SUCCESS);
    ret = cipher->doFinal(cipher, &plainTextBlob, &cipherTextBlob);
    ASSERT_EQ(ret, HCF_SUCCESS);
    EXPECT_EQ(cipherTextBlob.len, sizeof(expected));
    EXPECT_EQ(memcmp(cipherTextBlob.data, expected, sizeof(expected)), 0);
    if (cipherTextBlob.data != nullptr) {
        HcfBlobDataFree(&cipherTextBlob);
    }
    HcfObjDestroy(key);
    HcfObjDestroy(cipher);
}

HWTEST_F(CryptoBlowfishCipherTest, CryptoBlowfishCipherTest010, TestSize.Level0)
{
    uint8_t keyMaterial[] = {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07};
    uint8_t iv[] = {0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01};
    uint8_t plaintext[] = {0x0f, 0x0e, 0x0c, 0x0d, 0x0b, 0x0a, 0x09, 0x08,
                             0x07, 0x06, 0x05, 0x04, 0x03, 0x02, 0x01, 0x00};
    uint8_t expected[] = {0x27, 0xbe, 0x83, 0x31, 0xcd, 0xc5, 0x2d, 0xc6,
                            0x17, 0x24, 0x02, 0x9d, 0x30, 0x2b, 0x93, 0x58};
    HcfSymKey *key = nullptr;
    HcfCipher *cipher = nullptr;
    HcfIvParamsSpec ivSpec = {};
    ivSpec.iv.data = iv;
    ivSpec.iv.len = sizeof(iv);
    HcfBlob plainTextBlob = {.data = plaintext, .len = sizeof(plaintext)};
    HcfBlob cipherTextBlob = {};

    int res = SymAlgConvertSymKey("Blowfish", keyMaterial, sizeof(keyMaterial), &key);
    ASSERT_EQ(res, 0);
    HcfResult ret = HcfCipherCreate("Blowfish|OFB|NoPadding", &cipher);
    ASSERT_EQ(ret, HCF_SUCCESS);
    ret = cipher->init(cipher, ENCRYPT_MODE, (HcfKey *)key, (HcfParamsSpec *)&ivSpec);
    ASSERT_EQ(ret, HCF_SUCCESS);
    ret = cipher->doFinal(cipher, &plainTextBlob, &cipherTextBlob);
    ASSERT_EQ(ret, HCF_SUCCESS);
    EXPECT_EQ(cipherTextBlob.len, sizeof(expected));
    EXPECT_EQ(memcmp(cipherTextBlob.data, expected, sizeof(expected)), 0);
    if (cipherTextBlob.data != nullptr) {
        HcfBlobDataFree(&cipherTextBlob);
    }
    HcfObjDestroy(key);
    HcfObjDestroy(cipher);
}

HWTEST_F(CryptoBlowfishCipherTest, CryptoBlowfishCipherTest011, TestSize.Level0)
{
    uint8_t keyMaterial[] = {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x00, 0x00, 0x00, 0x00};
    uint8_t iv[] = {0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01};
    uint8_t plaintext[] = {0x0f, 0x0e, 0x0c, 0x0d, 0x0b, 0x0a, 0x09, 0x08,
                             0x07, 0x06, 0x05, 0x04, 0x03, 0x02, 0x01, 0x00};
    uint8_t expected[] = {0xf1, 0x08, 0xf2, 0x29, 0xcc, 0x1c, 0xbe, 0x22,
                            0x8a, 0xa3, 0xb2, 0x40, 0x79, 0x79, 0x28, 0x9a};
    HcfSymKey *key = nullptr;
    HcfCipher *cipher = nullptr;
    HcfIvParamsSpec ivSpec = {};
    ivSpec.iv.data = iv;
    ivSpec.iv.len = sizeof(iv);
    HcfBlob plainTextBlob = {.data = plaintext, .len = sizeof(plaintext)};
    HcfBlob cipherTextBlob = {};

    int res = SymAlgConvertSymKey("Blowfish", keyMaterial, sizeof(keyMaterial), &key);
    ASSERT_EQ(res, 0);
    HcfResult ret = HcfCipherCreate("Blowfish|OFB|NoPadding", &cipher);
    ASSERT_EQ(ret, HCF_SUCCESS);
    ret = cipher->init(cipher, ENCRYPT_MODE, (HcfKey *)key, (HcfParamsSpec *)&ivSpec);
    ASSERT_EQ(ret, HCF_SUCCESS);
    ret = cipher->doFinal(cipher, &plainTextBlob, &cipherTextBlob);
    ASSERT_EQ(ret, HCF_SUCCESS);
    EXPECT_EQ(cipherTextBlob.len, sizeof(expected));
    EXPECT_EQ(memcmp(cipherTextBlob.data, expected, sizeof(expected)), 0);
    if (cipherTextBlob.data != nullptr) {
        HcfBlobDataFree(&cipherTextBlob);
    }
    HcfObjDestroy(key);
    HcfObjDestroy(cipher);
}

HWTEST_F(CryptoBlowfishCipherTest, CryptoBlowfishCipherTest012, TestSize.Level0)
{
    uint8_t keyMaterial[] = {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07};
    uint8_t iv[] = {0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01};
    uint8_t plaintext[] = {0x0f, 0x0e, 0x0c, 0x0d, 0x0b, 0x0a, 0x09, 0x08,
                             0x07, 0x06, 0x05, 0x04, 0x03, 0x02, 0x01, 0x00};
    uint8_t expected[] = {0x27, 0xbe, 0x83, 0x31, 0xcd, 0xc5, 0x2d, 0xc6,
                            0x75, 0xa9, 0x36, 0x25, 0xf9, 0x0f, 0x5d, 0xb4};
    HcfSymKey *key = nullptr;
    HcfCipher *cipher = nullptr;
    HcfIvParamsSpec ivSpec = {};
    ivSpec.iv.data = iv;
    ivSpec.iv.len = sizeof(iv);
    HcfBlob plainTextBlob = {.data = plaintext, .len = sizeof(plaintext)};
    HcfBlob cipherTextBlob = {};

    int res = SymAlgConvertSymKey("Blowfish", keyMaterial, sizeof(keyMaterial), &key);
    ASSERT_EQ(res, 0);
    HcfResult ret = HcfCipherCreate("Blowfish|CFB|NoPadding", &cipher);
    ASSERT_EQ(ret, HCF_SUCCESS);
    ret = cipher->init(cipher, ENCRYPT_MODE, (HcfKey *)key, (HcfParamsSpec *)&ivSpec);
    ASSERT_EQ(ret, HCF_SUCCESS);
    ret = cipher->doFinal(cipher, &plainTextBlob, &cipherTextBlob);
    ASSERT_EQ(ret, HCF_SUCCESS);
    EXPECT_EQ(cipherTextBlob.len, sizeof(expected));
    EXPECT_EQ(memcmp(cipherTextBlob.data, expected, sizeof(expected)), 0);
    if (cipherTextBlob.data != nullptr) {
        HcfBlobDataFree(&cipherTextBlob);
    }
    HcfObjDestroy(key);
    HcfObjDestroy(cipher);
}

HWTEST_F(CryptoBlowfishCipherTest, CryptoBlowfishCipherTest013, TestSize.Level0)
{
    uint8_t keyMaterial[] = {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x00, 0x00, 0x00, 0x00};
    uint8_t iv[] = {0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01};
    uint8_t plaintext[] = {0x0f, 0x0e, 0x0c, 0x0d, 0x0b, 0x0a, 0x09, 0x08,
                             0x07, 0x06, 0x05, 0x04, 0x03, 0x02, 0x01, 0x00};
    uint8_t expected[] = {0xf1, 0x08, 0xf2, 0x29, 0xcc, 0x1c, 0xbe, 0x22,
                            0x14, 0xf0, 0x0c, 0x3a, 0x86, 0x11, 0xcb, 0x46};
    HcfSymKey *key = nullptr;
    HcfCipher *cipher = nullptr;
    HcfIvParamsSpec ivSpec = {};
    ivSpec.iv.data = iv;
    ivSpec.iv.len = sizeof(iv);
    HcfBlob plainTextBlob = {.data = plaintext, .len = sizeof(plaintext)};
    HcfBlob cipherTextBlob = {};

    int res = SymAlgConvertSymKey("Blowfish", keyMaterial, sizeof(keyMaterial), &key);
    ASSERT_EQ(res, 0);
    HcfResult ret = HcfCipherCreate("Blowfish|CFB|NoPadding", &cipher);
    ASSERT_EQ(ret, HCF_SUCCESS);
    ret = cipher->init(cipher, ENCRYPT_MODE, (HcfKey *)key, (HcfParamsSpec *)&ivSpec);
    ASSERT_EQ(ret, HCF_SUCCESS);
    ret = cipher->doFinal(cipher, &plainTextBlob, &cipherTextBlob);
    ASSERT_EQ(ret, HCF_SUCCESS);
    EXPECT_EQ(cipherTextBlob.len, sizeof(expected));
    EXPECT_EQ(memcmp(cipherTextBlob.data, expected, sizeof(expected)), 0);
    if (cipherTextBlob.data != nullptr) {
        HcfBlobDataFree(&cipherTextBlob);
    }
    HcfObjDestroy(key);
    HcfObjDestroy(cipher);
}
}
