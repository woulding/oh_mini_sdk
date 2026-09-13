/*
 * Copyright (C) 2025 Huawei Device Co., Ltd.
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
#include "crypto_sym_key.h"
#include "crypto_mac.h"
#include "memory.h"
#include "memory_mock.h"

using namespace std;
using namespace testing::ext;

namespace {
class NativeMacTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp();
    void TearDown();
};

void NativeMacTest::SetUpTestCase() {}
void NativeMacTest::TearDownTestCase() {}

void NativeMacTest::SetUp() // add init here, this will be called before test.
{
}

void NativeMacTest::TearDown() // add destroy here, this will be called when test case done.
{
}

static OH_CryptoSymKey *GenSymKey(const char *algoName)
{
    OH_CryptoSymKeyGenerator *keyGen = nullptr;
    OH_Crypto_ErrCode ret = OH_CryptoSymKeyGenerator_Create(algoName, &keyGen);
    if (ret != CRYPTO_SUCCESS) {
        return nullptr;
    }
    OH_CryptoSymKey *keyCtx = nullptr;
    ret = OH_CryptoSymKeyGenerator_Generate(keyGen, &keyCtx);
    OH_CryptoSymKeyGenerator_Destroy(keyGen);
    if (ret != CRYPTO_SUCCESS) {
        return nullptr;
    }
    return keyCtx;
}

static OH_Crypto_ErrCode CalculateMacTest(OH_CryptoMac *ctx, OH_CryptoSymKey *keyCtx)
{
    OH_Crypto_ErrCode ret = OH_CryptoMac_Init(ctx, keyCtx);
    if (ret != CRYPTO_SUCCESS) {
        return ret;
    }
    const char *data = "hello world";
    const char *data2 = "hello openharmony";
    const Crypto_DataBlob in = {.data = reinterpret_cast<uint8_t *>(const_cast<char *>(data)), .len = strlen(data)};
    const Crypto_DataBlob in2 = {.data = reinterpret_cast<uint8_t *>(const_cast<char *>(data2)), .len = strlen(data2)};
    ret = OH_CryptoMac_Update(ctx, &in);
    if (ret != CRYPTO_SUCCESS) {
        return ret;
    }
    ret = OH_CryptoMac_Update(ctx, &in2);
    if (ret != CRYPTO_SUCCESS) {
        return ret;
    }

    Crypto_DataBlob out = {0};
    ret = OH_CryptoMac_Final(ctx, &out);
    if (ret != CRYPTO_SUCCESS) {
        return ret;
    }
    OH_Crypto_FreeDataBlob(&out);
    uint32_t macLen = 0;
    ret = OH_CryptoMac_GetLength(ctx, &macLen);
    if (ret != CRYPTO_SUCCESS) {
        return ret;
    }
    return CRYPTO_SUCCESS;
}

HWTEST_F(NativeMacTest, NativeMacTest001, TestSize.Level0)
{
    OH_CryptoSymKey *keyCtx = GenSymKey("HMAC|SM3");
    ASSERT_NE(keyCtx, nullptr);

    OH_CryptoMac *ctx = nullptr;
    OH_Crypto_ErrCode ret = OH_CryptoMac_Create("HMAC", &ctx);
    EXPECT_EQ(ret, CRYPTO_SUCCESS);
    const char *digestName = "SM3";
    Crypto_DataBlob digestNameData = {.data = reinterpret_cast<uint8_t *>(const_cast<char *>(digestName)),
        .len = strlen(digestName)};
    ret = OH_CryptoMac_SetParam(ctx, CRYPTO_MAC_DIGEST_NAME_STR, &digestNameData);
    EXPECT_EQ(ret, CRYPTO_SUCCESS);
    ret = OH_CryptoMac_SetParam(ctx, CRYPTO_MAC_DIGEST_NAME_STR, &digestNameData); // repeat set param
    EXPECT_EQ(ret, CRYPTO_SUCCESS);
    ret = CalculateMacTest(ctx, keyCtx);
    EXPECT_EQ(ret, CRYPTO_SUCCESS);

    OH_CryptoMac_Destroy(ctx);
    OH_CryptoSymKey_Destroy(keyCtx);
}

HWTEST_F(NativeMacTest, NativeMacTest002, TestSize.Level0)
{
    OH_CryptoSymKey *keyCtx = GenSymKey("AES128");
    ASSERT_NE(keyCtx, nullptr);

    OH_CryptoMac *ctx = nullptr;
    OH_Crypto_ErrCode ret = OH_CryptoMac_Create("CMAC", &ctx);
    EXPECT_EQ(ret, CRYPTO_SUCCESS);
    const char *cipherName = "AES128";
    Crypto_DataBlob cipherNameData = {.data = reinterpret_cast<uint8_t *>(const_cast<char *>(cipherName)),
        .len = strlen(cipherName)};
    ret = OH_CryptoMac_SetParam(ctx, CRYPTO_MAC_CIPHER_NAME_STR, &cipherNameData);
    EXPECT_EQ(ret, CRYPTO_SUCCESS);
    ret = CalculateMacTest(ctx, keyCtx);
    EXPECT_EQ(ret, CRYPTO_SUCCESS);

    OH_CryptoMac_Destroy(ctx);
    OH_CryptoSymKey_Destroy(keyCtx);
}

HWTEST_F(NativeMacTest, NativeMacTest003, TestSize.Level0)
{
    OH_CryptoMac *ctx = nullptr;
    OH_Crypto_ErrCode ret = OH_CryptoMac_Create(nullptr, &ctx);
    EXPECT_NE(ret, CRYPTO_SUCCESS);
    ret = OH_CryptoMac_Create("HMAC", nullptr);
    EXPECT_NE(ret, CRYPTO_SUCCESS);
    ret = OH_CryptoMac_Create("XMAC", &ctx);
    EXPECT_NE(ret, CRYPTO_SUCCESS);
    ret = OH_CryptoMac_Create("HMAC", &ctx);
    EXPECT_EQ(ret, CRYPTO_SUCCESS);

    OH_CryptoMac_Destroy(ctx);
}

HWTEST_F(NativeMacTest, NativeMacTest004, TestSize.Level0)
{
    OH_CryptoMac *ctx = nullptr;
    OH_Crypto_ErrCode ret = OH_CryptoMac_Create("HMAC", &ctx);
    EXPECT_EQ(ret, CRYPTO_SUCCESS);

    const char *cipherName = "AES128";
    Crypto_DataBlob cipherNameData = {.data = reinterpret_cast<uint8_t *>(const_cast<char *>(cipherName)),
        .len = strlen(cipherName)};
    ret = OH_CryptoMac_SetParam(ctx, CRYPTO_MAC_CIPHER_NAME_STR, &cipherNameData);
    EXPECT_NE(ret, CRYPTO_SUCCESS);
    const char *digestName = "SM3";
    Crypto_DataBlob digestNameData = {.data = reinterpret_cast<uint8_t *>(const_cast<char *>(digestName)),
        .len = strlen(digestName)};
    ret = OH_CryptoMac_SetParam(ctx, CRYPTO_MAC_DIGEST_NAME_STR, &digestNameData);
    EXPECT_EQ(ret, CRYPTO_SUCCESS);

    OH_CryptoMac_Destroy(ctx);
}

HWTEST_F(NativeMacTest, NativeMacTest005, TestSize.Level0)
{
    OH_CryptoMac *ctx = nullptr;
    OH_Crypto_ErrCode ret = OH_CryptoMac_Create("CMAC", &ctx);
    EXPECT_EQ(ret, CRYPTO_SUCCESS);

    const char *cipherName = "AES128";
    Crypto_DataBlob cipherNameData = {.data = reinterpret_cast<uint8_t *>(const_cast<char *>(cipherName)),
        .len = strlen(cipherName)};
    ret = OH_CryptoMac_SetParam(ctx, CRYPTO_MAC_CIPHER_NAME_STR, &cipherNameData);
    EXPECT_EQ(ret, CRYPTO_SUCCESS);
    const char *digestName = "SM3";
    Crypto_DataBlob digestNameData = {.data = reinterpret_cast<uint8_t *>(const_cast<char *>(digestName)),
        .len = strlen(digestName)};
    ret = OH_CryptoMac_SetParam(ctx, CRYPTO_MAC_DIGEST_NAME_STR, &digestNameData);
    EXPECT_NE(ret, CRYPTO_SUCCESS);

    OH_CryptoMac_Destroy(ctx);
}

HWTEST_F(NativeMacTest, NativeMacTest006, TestSize.Level0)
{
    OH_CryptoMac *ctx = nullptr;
    OH_Crypto_ErrCode ret = OH_CryptoMac_Create("CMAC", &ctx);
    EXPECT_EQ(ret, CRYPTO_SUCCESS);

    ret = OH_CryptoMac_Init(ctx, nullptr);
    EXPECT_NE(ret, CRYPTO_SUCCESS);
    ret = OH_CryptoMac_Update(ctx, nullptr);
    EXPECT_NE(ret, CRYPTO_SUCCESS);
    ret = OH_CryptoMac_Final(ctx, nullptr);
    EXPECT_NE(ret, CRYPTO_SUCCESS);
    ret = OH_CryptoMac_GetLength(ctx, nullptr);
    EXPECT_NE(ret, CRYPTO_SUCCESS);

    OH_CryptoMac_Destroy(ctx);
}
}