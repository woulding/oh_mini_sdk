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
class CryptoCastCipherTest : public testing::Test {
public:
    static void SetUpTestCase() {};
    static void TearDownTestCase() {};
    void SetUp() {};
    void TearDown() {};
};

HWTEST_F(CryptoCastCipherTest, CryptoCastCipherTest001, TestSize.Level0)
{
    uint8_t iv[SYM_ALG_IV_LEN] = {0};
    uint8_t cipherText[SYM_ALG_CIPHER_TEXT_MAX_LEN] = {0};
    int cipherTextLen = SYM_ALG_CIPHER_TEXT_MAX_LEN;

    HcfIvParamsSpec ivSpec = {};
    ivSpec.iv.data = iv;
    ivSpec.iv.len = SYM_ALG_IV_LEN;

    HcfSymKey *key = nullptr;
    HcfCipher *cipher = nullptr;

    uint8_t keyMaterial[16] = {0};
    for (int i = 0; i < 16; i++) {
        keyMaterial[i] = (uint8_t)(i + 1);
    }
    int ret = SymAlgConvertSymKey("CAST", keyMaterial, sizeof(keyMaterial), &key);
    ASSERT_EQ(ret, 0);

    ret = HcfCipherCreate("CAST|CBC|PKCS7", &cipher);
    ASSERT_EQ(ret, 0);

    ret = SymAlgEncrypt(cipher, key, (HcfParamsSpec *)&ivSpec, cipherText, &cipherTextLen);
    ASSERT_EQ(ret, 0);

    ret = SymAlgDecrypt(cipher, key, (HcfParamsSpec *)&ivSpec, cipherText, cipherTextLen);
    ASSERT_EQ(ret, 0);

    HcfObjDestroy((HcfObjectBase *)key);
    HcfObjDestroy((HcfObjectBase *)cipher);
}

HWTEST_F(CryptoCastCipherTest, CryptoCastCipherTest002, TestSize.Level0)
{
    uint8_t cipherText[SYM_ALG_CIPHER_TEXT_MAX_LEN] = {0};
    int cipherTextLen = SYM_ALG_CIPHER_TEXT_MAX_LEN;

    HcfSymKey *key = nullptr;
    HcfCipher *cipher = nullptr;

    uint8_t keyMaterial[16] = {0};
    for (int i = 0; i < 16; i++) {
        keyMaterial[i] = (uint8_t)(i + 1);
    }
    int ret = SymAlgConvertSymKey("CAST", keyMaterial, sizeof(keyMaterial), &key);
    ASSERT_EQ(ret, 0);

    ret = HcfCipherCreate("CAST|ECB|PKCS7", &cipher);
    ASSERT_EQ(ret, 0);

    ret = SymAlgEncrypt(cipher, key, nullptr, cipherText, &cipherTextLen);
    ASSERT_EQ(ret, 0);

    ret = SymAlgDecrypt(cipher, key, nullptr, cipherText, cipherTextLen);
    ASSERT_EQ(ret, 0);

    HcfObjDestroy((HcfObjectBase *)key);
    HcfObjDestroy((HcfObjectBase *)cipher);
}

HWTEST_F(CryptoCastCipherTest, CryptoCastCipherTest003, TestSize.Level0)
{
    uint8_t iv[SYM_ALG_IV_LEN] = {0};
    uint8_t keyMaterial[16] = {0};
    for (int i = 0; i < 16; i++) {
        keyMaterial[i] = (uint8_t)(i + 1);
    }
    uint8_t cipherText[SYM_ALG_CIPHER_TEXT_MAX_LEN] = {0};
    int cipherTextLen = SYM_ALG_CIPHER_TEXT_MAX_LEN;

    HcfIvParamsSpec ivSpec = {};
    ivSpec.iv.data = iv;
    ivSpec.iv.len = SYM_ALG_IV_LEN;

    HcfSymKey *key = nullptr;
    HcfCipher *cipher = nullptr;

    int ret = SymAlgConvertSymKey("CAST", keyMaterial, 16, &key);
    ASSERT_EQ(ret, 0);

    ret = HcfCipherCreate("CAST|CBC|PKCS7", &cipher);
    ASSERT_EQ(ret, 0);

    ret = SymAlgEncrypt(cipher, key, (HcfParamsSpec *)&ivSpec, cipherText, &cipherTextLen);
    ASSERT_EQ(ret, 0);

    ret = SymAlgDecrypt(cipher, key, (HcfParamsSpec *)&ivSpec, cipherText, cipherTextLen);
    ASSERT_EQ(ret, 0);

    HcfObjDestroy((HcfObjectBase *)key);
    HcfObjDestroy((HcfObjectBase *)cipher);
}

HWTEST_F(CryptoCastCipherTest, CryptoCastCipherTest004, TestSize.Level0)
{
    uint8_t iv[SYM_ALG_IV_LEN] = {0};
    uint8_t keyMaterial[5] = {0x01, 0x02, 0x03, 0x04, 0x05};
    uint8_t cipherText[SYM_ALG_CIPHER_TEXT_MAX_LEN] = {0};
    int cipherTextLen = SYM_ALG_CIPHER_TEXT_MAX_LEN;

    HcfIvParamsSpec ivSpec = {};
    ivSpec.iv.data = iv;
    ivSpec.iv.len = SYM_ALG_IV_LEN;

    HcfSymKey *key = nullptr;
    HcfCipher *cipher = nullptr;

    int ret = SymAlgConvertSymKey("CAST", keyMaterial, 5, &key);
    ASSERT_EQ(ret, 0);

    ret = HcfCipherCreate("CAST|CBC|PKCS7", &cipher);
    ASSERT_EQ(ret, 0);

    ret = SymAlgEncrypt(cipher, key, (HcfParamsSpec *)&ivSpec, cipherText, &cipherTextLen);
    ASSERT_EQ(ret, 0);

    ret = SymAlgDecrypt(cipher, key, (HcfParamsSpec *)&ivSpec, cipherText, cipherTextLen);
    ASSERT_EQ(ret, 0);

    HcfObjDestroy((HcfObjectBase *)key);
    HcfObjDestroy((HcfObjectBase *)cipher);
}

HWTEST_F(CryptoCastCipherTest, CryptoCastCipherTest005, TestSize.Level0)
{
    uint8_t keyMaterial[16] = {0x01, 0x23, 0x45, 0x67, 0x12, 0x34, 0x56, 0x78,
                              0x23, 0x45, 0x67, 0x89, 0x34, 0x56, 0x78, 0x9a};
    uint8_t plaintext[8] = {0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef};
    uint8_t expected[8] = {0x23, 0x8b, 0x4f, 0xe5, 0x84, 0x7e, 0x44, 0xb2};
    HcfSymKey *key = nullptr;
    HcfCipher *cipher = nullptr;
    HcfBlob plainTextBlob = {.data = plaintext, .len = sizeof(plaintext)};
    HcfBlob cipherTextBlob = {};

    int res = SymAlgConvertSymKey("CAST", keyMaterial, sizeof(keyMaterial), &key);
    ASSERT_EQ(res, 0);
    HcfResult ret = HcfCipherCreate("CAST|ECB|NoPadding", &cipher);
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

HWTEST_F(CryptoCastCipherTest, CryptoCastCipherTest008, TestSize.Level0)
{
    uint8_t keyMaterial[16] = {0x1f, 0x8e, 0x49, 0x73, 0x95, 0x3f, 0x3f, 0xb0,
                              0xbd, 0x6b, 0x16, 0x66, 0x2e, 0x9a, 0x3c, 0x17};
    uint8_t iv[8] = {0x2f, 0xe2, 0xb3, 0x33, 0xce, 0xda, 0x8f, 0x98};
    uint8_t plaintext[16] = {0x45, 0xcf, 0x12, 0x96, 0x4f, 0xc8, 0x24, 0xab,
                             0x76, 0x61, 0x6a, 0xe2, 0xf4, 0xbf, 0x08, 0x22};
    uint8_t expected[16] = {0x32, 0x7c, 0x19, 0x8b, 0x9d, 0x0a, 0x59, 0x45,
                            0x6a, 0x21, 0x94, 0xbd, 0x21, 0xfc, 0x3f, 0xf0};
    HcfIvParamsSpec ivSpec = {};
    ivSpec.iv.data = iv;
    ivSpec.iv.len = sizeof(iv);
    HcfSymKey *key = nullptr;
    HcfCipher *cipher = nullptr;
    HcfBlob plainTextBlob = {.data = plaintext, .len = sizeof(plaintext)};
    HcfBlob cipherTextBlob = {};

    int res = SymAlgConvertSymKey("CAST", keyMaterial, sizeof(keyMaterial), &key);
    ASSERT_EQ(res, 0);
    HcfResult ret = HcfCipherCreate("CAST|CBC|NoPadding", &cipher);
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
    HcfObjDestroy((HcfObjectBase *)key);
    HcfObjDestroy((HcfObjectBase *)cipher);
}

HWTEST_F(CryptoCastCipherTest, CryptoCastCipherTest009, TestSize.Level0)
{
    uint8_t keyMaterial[16] = {0x07, 0x00, 0xd6, 0x03, 0xa1, 0xc5, 0x14, 0xe4,
                              0x6b, 0x61, 0x91, 0xba, 0x43, 0x0a, 0x3a, 0x0c};
    uint8_t iv[8] = {0xaa, 0xd1, 0x58, 0x3c, 0xd9, 0x13, 0x65, 0xe3};
    uint8_t plaintext[32] = {0x06, 0x8b, 0x25, 0xc7, 0xbf, 0xb1, 0xf8, 0xbd, 0xd4, 0xcf, 0xc9, 0x08,
                             0xf6, 0x9d, 0xff, 0xc5, 0xdd, 0xc7, 0x26, 0xa1, 0x97, 0xf0, 0xe5, 0xf7,
                             0x20, 0xf7, 0x30, 0x39, 0x32, 0x79, 0xbe, 0x91};
    uint8_t expected[32] = {0xf5, 0xce, 0x00, 0xa3, 0xba, 0x73, 0xe5, 0xa2, 0x89, 0x78, 0x97, 0x83,
                            0xc3, 0x47, 0x87, 0xe1, 0x1d, 0x27, 0x85, 0x9b, 0xea, 0xc2, 0x6b, 0xb5,
                            0x3d, 0xc7, 0x32, 0xf0, 0x3c, 0x80, 0xc5, 0x48};
    HcfIvParamsSpec ivSpec = {};
    ivSpec.iv.data = iv;
    ivSpec.iv.len = sizeof(iv);
    HcfSymKey *key = nullptr;
    HcfCipher *cipher = nullptr;
    HcfBlob plainTextBlob = {.data = plaintext, .len = sizeof(plaintext)};
    HcfBlob cipherTextBlob = {};

    int res = SymAlgConvertSymKey("CAST", keyMaterial, sizeof(keyMaterial), &key);
    ASSERT_EQ(res, 0);
    HcfResult ret = HcfCipherCreate("CAST|CBC|NoPadding", &cipher);
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
    HcfObjDestroy((HcfObjectBase *)key);
    HcfObjDestroy((HcfObjectBase *)cipher);
}

HWTEST_F(CryptoCastCipherTest, CryptoCastCipherTest010, TestSize.Level0)
{
    uint8_t keyMaterial[16] = {0x6a, 0x8f, 0x64, 0x87, 0xe7, 0x60, 0x58, 0xbc,
                              0x5a, 0x12, 0x62, 0x76, 0xe4, 0x8f, 0xdd, 0x77};
    uint8_t iv[8] = {0x6e, 0x75, 0xd8, 0xb8, 0xac, 0x09, 0x76, 0x14};
    uint8_t plaintext[48] = {
        0x42, 0x4d, 0xdc, 0x34, 0x30, 0x67, 0x61, 0x2f, 0xdb, 0x42, 0x69, 0x20, 0xf4, 0x0a, 0xb4, 0xd8,
        0x2e, 0x3d, 0x4f, 0x94, 0x85, 0xb0, 0x7f, 0xef, 0x91, 0x61, 0x75, 0x56, 0xd3, 0x09, 0x38, 0x74,
        0x84, 0x0e, 0x81, 0x10, 0xff, 0x37, 0x5b, 0x7a, 0x68, 0xf9, 0x8c, 0x47, 0x1c, 0xa1, 0x0a, 0xcc
    };
    uint8_t expected[48] = {
        0x79, 0x94, 0xf1, 0xbe, 0xec, 0x71, 0x26, 0xaa, 0x62, 0x69, 0x4e, 0x2b, 0x6e, 0x08, 0x74, 0xba,
        0x8d, 0x2d, 0xa9, 0x6f, 0x5b, 0xfc, 0x52, 0x05, 0x9d, 0x27, 0xaf, 0x0f, 0x93, 0xee, 0x47, 0x79,
        0x8a, 0x89, 0x4a, 0x2d, 0x6c, 0xb7, 0x93, 0x66, 0x7c, 0xa4, 0xb3, 0x08, 0xc4, 0x6b, 0x4d, 0xd7
    };
    HcfIvParamsSpec ivSpec = {};
    ivSpec.iv.data = iv;
    ivSpec.iv.len = sizeof(iv);
    HcfSymKey *key = nullptr;
    HcfCipher *cipher = nullptr;
    HcfBlob plainTextBlob = {.data = plaintext, .len = sizeof(plaintext)};
    HcfBlob cipherTextBlob = {};

    int res = SymAlgConvertSymKey("CAST", keyMaterial, sizeof(keyMaterial), &key);
    ASSERT_EQ(res, 0);
    HcfResult ret = HcfCipherCreate("CAST|OFB|NoPadding", &cipher);
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
    HcfObjDestroy((HcfObjectBase *)key);
    HcfObjDestroy((HcfObjectBase *)cipher);
}

HWTEST_F(CryptoCastCipherTest, CryptoCastCipherTest011, TestSize.Level0)
{
    uint8_t keyMaterial[16] = {0xc4, 0x66, 0x60, 0x81, 0xe0, 0xb0, 0xed, 0xdb,
                              0x10, 0xa9, 0xa6, 0x07, 0xc8, 0x07, 0x37, 0x8f};
    uint8_t iv[8] = {0x5f, 0x23, 0x62, 0x32, 0x88, 0xe4, 0xa4, 0x1b};
    uint8_t plaintext[32] = {
        0x2f, 0xd0, 0x2d, 0xab, 0x90, 0x54, 0x24, 0x80, 0x73, 0xeb, 0xc0, 0xb0, 0x7a, 0xed, 0x38, 0x37,
        0x56, 0xcc, 0xfa, 0x4f, 0xa6, 0x29, 0x87, 0x22, 0x77, 0x5b, 0xe6, 0xa9, 0xb4, 0xed, 0x27, 0xa5
    };
    uint8_t expected[32] = {
        0xcb, 0xa9, 0xc6, 0xb7, 0xa6, 0x67, 0x20, 0x71, 0x03, 0x1a, 0xa2, 0x37, 0xa6, 0x02, 0x99, 0x68,
        0x96, 0xe3, 0x1a, 0x11, 0x0b, 0xae, 0x18, 0x70, 0xd0, 0x00, 0x76, 0x8a, 0x79, 0xf6, 0x61, 0xaa
    };
    HcfIvParamsSpec ivSpec = {};
    ivSpec.iv.data = iv;
    ivSpec.iv.len = sizeof(iv);
    HcfSymKey *key = nullptr;
    HcfCipher *cipher = nullptr;
    HcfBlob plainTextBlob = {.data = plaintext, .len = sizeof(plaintext)};
    HcfBlob cipherTextBlob = {};

    int res = SymAlgConvertSymKey("CAST", keyMaterial, sizeof(keyMaterial), &key);
    ASSERT_EQ(res, 0);
    HcfResult ret = HcfCipherCreate("CAST|CFB|NoPadding", &cipher);
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
    HcfObjDestroy((HcfObjectBase *)key);
    HcfObjDestroy((HcfObjectBase *)cipher);
}
}
