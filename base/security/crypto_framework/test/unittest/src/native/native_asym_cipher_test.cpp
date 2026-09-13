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
#include "crypto_common.h"
#include "crypto_asym_cipher.h"
#include "memory.h"
#include "memory_mock.h"

using namespace std;
using namespace testing::ext;

class NativeAsymCipherTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp();
    void TearDown();
};

void NativeAsymCipherTest::SetUpTestCase() {}

void NativeAsymCipherTest::TearDownTestCase() {}

void NativeAsymCipherTest::SetUp()
{
}

void NativeAsymCipherTest::TearDown()
{
}

HWTEST_F(NativeAsymCipherTest, NativeAsymCipherTest001, TestSize.Level0)
{
    OH_CryptoAsymKeyGenerator *keyGen = nullptr;
    OH_Crypto_ErrCode ret = OH_CryptoAsymKeyGenerator_Create("RSA3072", &keyGen);
    EXPECT_EQ(ret, CRYPTO_SUCCESS);
    ASSERT_NE(keyGen, nullptr);

    OH_CryptoKeyPair *keyPair = nullptr;
    ret = OH_CryptoAsymKeyGenerator_Generate(keyGen, &keyPair);
    EXPECT_EQ(ret, CRYPTO_SUCCESS);
    ASSERT_NE(keyPair, nullptr);

    OH_CryptoAsymCipher *cipher = nullptr;
    ret = OH_CryptoAsymCipher_Create("RSA3072|PKCS1", &cipher);
    EXPECT_EQ(ret, CRYPTO_SUCCESS);
    ASSERT_NE(cipher, nullptr);

    ret = OH_CryptoAsymCipher_Init(cipher, CRYPTO_ENCRYPT_MODE, keyPair);
    EXPECT_EQ(ret, CRYPTO_SUCCESS);

    const char *testData = "Hello, RSA!";
    Crypto_DataBlob in = {
        .data = (uint8_t *)testData,
        .len = strlen(testData)
    };

    Crypto_DataBlob out = { 0 };
    ret = OH_CryptoAsymCipher_Final(cipher, &in, &out);
    EXPECT_EQ(ret, CRYPTO_SUCCESS);
    ASSERT_NE(out.data, nullptr);
    ASSERT_GT(out.len, 0);

    OH_CryptoAsymCipher_Destroy(cipher);
    cipher = nullptr;
    ret = OH_CryptoAsymCipher_Create("RSA3072|PKCS1", &cipher);
    EXPECT_EQ(ret, CRYPTO_SUCCESS);
    ASSERT_NE(cipher, nullptr);

    ret = OH_CryptoAsymCipher_Init(cipher, CRYPTO_DECRYPT_MODE, keyPair);
    EXPECT_EQ(ret, CRYPTO_SUCCESS);

    Crypto_DataBlob decrypted = { 0 };
    ret = OH_CryptoAsymCipher_Final(cipher, &out, &decrypted);
    EXPECT_EQ(ret, CRYPTO_SUCCESS);
    ASSERT_NE(decrypted.data, nullptr);
    ASSERT_EQ(decrypted.len, strlen(testData));
    EXPECT_EQ(memcmp(decrypted.data, testData, decrypted.len), 0);

    OH_Crypto_FreeDataBlob(&out);
    OH_Crypto_FreeDataBlob(&decrypted);
    OH_CryptoAsymCipher_Destroy(cipher);
    OH_CryptoAsymKeyGenerator_Destroy(keyGen);
    OH_CryptoKeyPair_Destroy(keyPair);
}

HWTEST_F(NativeAsymCipherTest, NativeAsymCipherTest002, TestSize.Level0)
{
    OH_CryptoAsymKeyGenerator *keyGen = nullptr;
    OH_Crypto_ErrCode ret = OH_CryptoAsymKeyGenerator_Create("SM2_256", nullptr);
    EXPECT_NE(ret, CRYPTO_SUCCESS);
    ret = OH_CryptoAsymKeyGenerator_Create(nullptr, &keyGen);
    EXPECT_NE(ret, CRYPTO_SUCCESS);
    ret = OH_CryptoAsymKeyGenerator_Create("SM2_256", &keyGen);
    EXPECT_EQ(ret, CRYPTO_SUCCESS);
    OH_CryptoAsymKeyGenerator_Destroy(keyGen);
}

HWTEST_F(NativeAsymCipherTest, NativeAsymCipherTest003, TestSize.Level0)
{
    OH_CryptoAsymKeyGenerator *keyGen = nullptr;
    OH_Crypto_ErrCode ret = OH_CryptoAsymKeyGenerator_Create("SM2_256", &keyGen);
    EXPECT_EQ(ret, CRYPTO_SUCCESS);

    OH_CryptoKeyPair *keyPair = nullptr;
    ret = OH_CryptoAsymKeyGenerator_Generate(nullptr, &keyPair);
    EXPECT_NE(ret, CRYPTO_SUCCESS);
    ASSERT_EQ(keyPair, nullptr);

    ret = OH_CryptoAsymKeyGenerator_Generate(keyGen, nullptr);
    EXPECT_NE(ret, CRYPTO_SUCCESS);

    ret = OH_CryptoAsymKeyGenerator_Generate(keyGen, &keyPair);
    EXPECT_EQ(ret, CRYPTO_SUCCESS);
    ASSERT_NE(keyPair, nullptr);

    OH_CryptoAsymKeyGenerator_Destroy(keyGen);
    OH_CryptoKeyPair_Destroy(keyPair);
}

HWTEST_F(NativeAsymCipherTest, NativeAsymCipherTest004, TestSize.Level0)
{
    OH_CryptoAsymKeyGenerator *keyGen = nullptr;
    OH_Crypto_ErrCode ret = OH_CryptoAsymKeyGenerator_Create("SM2_256", &keyGen);
    EXPECT_EQ(ret, CRYPTO_SUCCESS);

    OH_CryptoKeyPair *keyPair = nullptr;
    ret = OH_CryptoAsymKeyGenerator_Generate(keyGen, &keyPair);
    EXPECT_EQ(ret, CRYPTO_SUCCESS);

    OH_CryptoAsymCipher *cipher = nullptr;
    ret = OH_CryptoAsymCipher_Create(nullptr, &cipher);
    ASSERT_NE(ret, CRYPTO_SUCCESS);
    EXPECT_EQ(cipher, nullptr);

    ret = OH_CryptoAsymCipher_Create("SM2|SM3", nullptr);
    EXPECT_NE(ret, CRYPTO_SUCCESS);

    ret = OH_CryptoAsymCipher_Create("SM2|SM3", &cipher);
    EXPECT_EQ(ret, CRYPTO_SUCCESS);
    ASSERT_NE(cipher, nullptr);

    OH_CryptoAsymCipher_Destroy(cipher);
    OH_CryptoAsymKeyGenerator_Destroy(keyGen);
    OH_CryptoKeyPair_Destroy(keyPair);
}

HWTEST_F(NativeAsymCipherTest, NativeAsymCipherTest005, TestSize.Level0)
{
    OH_CryptoAsymKeyGenerator *keyGen = nullptr;
    OH_Crypto_ErrCode ret = OH_CryptoAsymKeyGenerator_Create("SM2_256", &keyGen);
    EXPECT_EQ(ret, CRYPTO_SUCCESS);

    OH_CryptoKeyPair *keyPair = nullptr;
    ret = OH_CryptoAsymKeyGenerator_Generate(keyGen, &keyPair);
    EXPECT_EQ(ret, CRYPTO_SUCCESS);

    OH_CryptoAsymCipher *cipher = nullptr;
    ret = OH_CryptoAsymCipher_Create("SM2|SM3", &cipher);
    EXPECT_EQ(ret, CRYPTO_SUCCESS);
    ASSERT_NE(cipher, nullptr);

    ret = OH_CryptoAsymCipher_Init(nullptr, CRYPTO_ENCRYPT_MODE, keyPair);
    EXPECT_NE(ret, CRYPTO_SUCCESS);

    ret = OH_CryptoAsymCipher_Init(cipher, CRYPTO_ENCRYPT_MODE, nullptr);
    EXPECT_NE(ret, CRYPTO_SUCCESS);

    ret = OH_CryptoAsymCipher_Init(cipher, (Crypto_CipherMode)2, nullptr);
    EXPECT_NE(ret, CRYPTO_SUCCESS);

    ret = OH_CryptoAsymCipher_Init(cipher, CRYPTO_ENCRYPT_MODE, keyPair);
    EXPECT_EQ(ret, CRYPTO_SUCCESS);

    const char *testData = "Hello, SM2!";
    Crypto_DataBlob in = {
        .data = (uint8_t *)testData,
        .len = strlen(testData)
    };

    Crypto_DataBlob out = { 0 };
    ret = OH_CryptoAsymCipher_Final(nullptr, &in, &out);
    EXPECT_NE(ret, CRYPTO_SUCCESS);

    ret = OH_CryptoAsymCipher_Final(cipher, &in, nullptr);
    EXPECT_NE(ret, CRYPTO_SUCCESS);

    ret = OH_CryptoAsymCipher_Final(cipher, &in, &out);
    EXPECT_EQ(ret, CRYPTO_SUCCESS);
    ASSERT_NE(out.data, nullptr);
    ASSERT_GT(out.len, 0);

    OH_Crypto_FreeDataBlob(&out);
    OH_CryptoAsymCipher_Destroy(cipher);
    OH_CryptoAsymKeyGenerator_Destroy(keyGen);
    OH_CryptoKeyPair_Destroy(keyPair);
}

HWTEST_F(NativeAsymCipherTest, NativeAsymCipherTest006, TestSize.Level0)
{
    OH_CryptoAsymKeyGenerator *keyGen = nullptr;
    OH_Crypto_ErrCode ret = OH_CryptoAsymKeyGenerator_Create("SM2_256", &keyGen);
    EXPECT_EQ(ret, CRYPTO_SUCCESS);

    OH_CryptoKeyPair *keyPair = nullptr;
    ret = OH_CryptoAsymKeyGenerator_Generate(keyGen, &keyPair);
    EXPECT_EQ(ret, CRYPTO_SUCCESS);

    OH_CryptoAsymCipher *cipher = nullptr;
    ret = OH_CryptoAsymCipher_Create("SM2|SM3", &cipher);
    EXPECT_EQ(ret, CRYPTO_SUCCESS);
    ASSERT_NE(cipher, nullptr);

    ret = OH_CryptoAsymCipher_Init(cipher, CRYPTO_ENCRYPT_MODE, keyPair);
    EXPECT_EQ(ret, CRYPTO_SUCCESS);

    const char *testData = "Hello, SM2!";
    Crypto_DataBlob in = {
        .data = (uint8_t *)testData,
        .len = strlen(testData)
    };

    Crypto_DataBlob out = { 0 };
    ret = OH_CryptoAsymCipher_Final(cipher, &in, &out);
    EXPECT_EQ(ret, CRYPTO_SUCCESS);
    ASSERT_NE(out.data, nullptr);
    ASSERT_GT(out.len, 0);

    OH_Crypto_FreeDataBlob(&out);
    OH_CryptoAsymCipher_Destroy(cipher);
    OH_CryptoAsymKeyGenerator_Destroy(keyGen);
    OH_CryptoKeyPair_Destroy(keyPair);
}

HWTEST_F(NativeAsymCipherTest, NativeAsymCipherTest007, TestSize.Level0)
{
    uint8_t testData[] = {
        48, 118, 2, 32, 45, 153, 88, 82, 104, 221, 226, 43, 174, 21, 122, 248, 5, 232, 105, 41, 92, 95, 102, 224, 216,
        149, 85, 236, 110, 6, 64, 188, 149, 70, 70, 183, 2, 32, 107, 93, 198, 247, 119, 18, 40, 110, 90, 156, 193, 158,
        205, 113, 170, 128, 146, 109, 75, 17, 181, 109, 110, 91, 149, 5, 110, 233, 209, 78, 229, 96, 4, 32, 87, 167,
        167, 247, 88, 146, 203, 234, 83, 126, 117, 129, 52, 142, 82, 54, 152, 226, 201, 111, 143, 115, 169, 125, 128,
        42, 157, 31, 114, 198, 109, 244, 4, 14, 100, 227, 78, 195, 249, 179, 43, 70, 242, 69, 169, 10, 65, 123
    };
    Crypto_DataBlob out = {
        .data = testData,
        .len = sizeof(testData)
    };

    OH_CryptoSm2CiphertextSpec *sm2CipherSpec = nullptr;
    OH_Crypto_ErrCode ret = OH_CryptoSm2CiphertextSpec_Create(&out, nullptr);
    EXPECT_NE(ret, CRYPTO_SUCCESS);
    ret = OH_CryptoSm2CiphertextSpec_Create(&out, &sm2CipherSpec);
    EXPECT_EQ(ret, CRYPTO_SUCCESS);
    ASSERT_NE(sm2CipherSpec, nullptr);

    Crypto_DataBlob c1x = { 0 };
    Crypto_DataBlob c1y = { 0 };
    Crypto_DataBlob c2 = { 0 };
    Crypto_DataBlob c3 = { 0 };
    ret = OH_CryptoSm2CiphertextSpec_GetItem(nullptr, CRYPTO_SM2_CIPHERTEXT_C1_X, &c1x);
    EXPECT_NE(ret, CRYPTO_SUCCESS);
    ret = OH_CryptoSm2CiphertextSpec_GetItem(sm2CipherSpec, (CryptoSm2CiphertextSpec_item)4, &c1x);
    EXPECT_NE(ret, CRYPTO_SUCCESS);
    ret = OH_CryptoSm2CiphertextSpec_GetItem(sm2CipherSpec, CRYPTO_SM2_CIPHERTEXT_C1_X, nullptr);
    EXPECT_NE(ret, CRYPTO_SUCCESS);

    ret = OH_CryptoSm2CiphertextSpec_GetItem(sm2CipherSpec, CRYPTO_SM2_CIPHERTEXT_C1_X, &c1x);
    EXPECT_EQ(ret, CRYPTO_SUCCESS);
    ret = OH_CryptoSm2CiphertextSpec_GetItem(sm2CipherSpec, CRYPTO_SM2_CIPHERTEXT_C1_Y, &c1y);
    EXPECT_EQ(ret, CRYPTO_SUCCESS);
    ret = OH_CryptoSm2CiphertextSpec_GetItem(sm2CipherSpec, CRYPTO_SM2_CIPHERTEXT_C2, &c2);
    EXPECT_EQ(ret, CRYPTO_SUCCESS);
    ret = OH_CryptoSm2CiphertextSpec_GetItem(sm2CipherSpec, CRYPTO_SM2_CIPHERTEXT_C3, &c3);
    EXPECT_EQ(ret, CRYPTO_SUCCESS);

    OH_Crypto_FreeDataBlob(&c1x);
    OH_Crypto_FreeDataBlob(&c1y);
    OH_Crypto_FreeDataBlob(&c2);
    OH_Crypto_FreeDataBlob(&c3);
    OH_CryptoSm2CiphertextSpec_Destroy(sm2CipherSpec);
}

static void InitCryptoDataBlobs(Crypto_DataBlob *c1x, Crypto_DataBlob *c1y, Crypto_DataBlob *c2, Crypto_DataBlob *c3)
{
    static uint8_t c1xData[] = {45, 153, 88, 82, 104, 221, 226, 43, 174, 21, 122, 248, 5, 232, 105, 41, 92, 95, 102,
        224, 216, 149, 85, 236, 110, 6, 64, 188, 149, 70, 70, 183};
    static uint8_t c1yData[] = {107, 93, 198, 247, 119, 18, 40, 110, 90, 156, 193, 158, 205, 113, 170, 128, 146, 109,
        75, 17, 181, 109, 110, 91, 149, 5, 110, 233, 209, 78, 229, 96};
    static uint8_t c2Data[] = {100, 227, 78, 195, 249, 179, 43, 70, 242, 69, 169, 10, 65, 123};
    static uint8_t c3Data[] = {87, 167, 167, 247, 88, 146, 203, 234, 83, 126, 117, 129, 52, 142, 82, 54, 152, 226, 201,
        111, 143, 115, 169, 125, 128, 42, 157, 31, 114, 198, 109, 244};

    c1x->data = c1xData;
    c1x->len = sizeof(c1xData);

    c1y->data = c1yData;
    c1y->len = sizeof(c1yData);

    c2->data = c2Data;
    c2->len = sizeof(c2Data);

    c3->data = c3Data;
    c3->len = sizeof(c3Data);
}

HWTEST_F(NativeAsymCipherTest, NativeAsymCipherTest008, TestSize.Level0)
{
    Crypto_DataBlob c1x = { 0 };
    Crypto_DataBlob c1y = { 0 };
    Crypto_DataBlob c2 = { 0 };
    Crypto_DataBlob c3 = { 0 };
    InitCryptoDataBlobs(&c1x, &c1y, &c2, &c3);

    OH_CryptoSm2CiphertextSpec *sm2CipherSpec = nullptr;
    OH_Crypto_ErrCode ret = OH_CryptoSm2CiphertextSpec_Create(nullptr, &sm2CipherSpec);
    EXPECT_EQ(ret, CRYPTO_SUCCESS);
    ASSERT_NE(sm2CipherSpec, nullptr);

    ret = OH_CryptoSm2CiphertextSpec_SetItem(nullptr, CRYPTO_SM2_CIPHERTEXT_C1_X, &c1x);
    EXPECT_NE(ret, CRYPTO_SUCCESS);
    ret = OH_CryptoSm2CiphertextSpec_SetItem(sm2CipherSpec, (CryptoSm2CiphertextSpec_item)4, &c1x);
    EXPECT_NE(ret, CRYPTO_SUCCESS);
    ret = OH_CryptoSm2CiphertextSpec_SetItem(sm2CipherSpec, CRYPTO_SM2_CIPHERTEXT_C1_X, nullptr);
    EXPECT_NE(ret, CRYPTO_SUCCESS);

    ret = OH_CryptoSm2CiphertextSpec_SetItem(sm2CipherSpec, CRYPTO_SM2_CIPHERTEXT_C1_X, &c1x);
    EXPECT_EQ(ret, CRYPTO_SUCCESS);
    ret = OH_CryptoSm2CiphertextSpec_SetItem(sm2CipherSpec, CRYPTO_SM2_CIPHERTEXT_C1_Y, &c1y);
    EXPECT_EQ(ret, CRYPTO_SUCCESS);
    ret = OH_CryptoSm2CiphertextSpec_SetItem(sm2CipherSpec, CRYPTO_SM2_CIPHERTEXT_C2, &c2);
    EXPECT_EQ(ret, CRYPTO_SUCCESS);
    ret = OH_CryptoSm2CiphertextSpec_SetItem(sm2CipherSpec, CRYPTO_SM2_CIPHERTEXT_C3, &c3);
    EXPECT_EQ(ret, CRYPTO_SUCCESS);

    Crypto_DataBlob encoded = { 0 };
    ret = OH_CryptoSm2CiphertextSpec_Encode(nullptr, &encoded);
    EXPECT_NE(ret, CRYPTO_SUCCESS);
    ret = OH_CryptoSm2CiphertextSpec_Encode(sm2CipherSpec, nullptr);
    EXPECT_NE(ret, CRYPTO_SUCCESS);

    ret = OH_CryptoSm2CiphertextSpec_Encode(sm2CipherSpec, &encoded);
    EXPECT_EQ(ret, CRYPTO_SUCCESS);
    ASSERT_NE(encoded.data, nullptr);
    ASSERT_GT(encoded.len, 0);

    OH_Crypto_FreeDataBlob(&encoded);
    OH_CryptoSm2CiphertextSpec_Destroy(sm2CipherSpec);
}