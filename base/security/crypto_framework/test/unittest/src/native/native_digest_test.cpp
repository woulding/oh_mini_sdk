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
#include "crypto_digest.h"
#include "memory.h"
#include "memory_mock.h"

using namespace std;
using namespace testing::ext;

constexpr uint32_t SHA1_LEN = 20;

namespace {
class NativeDigestTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp();
    void TearDown();
};

void NativeDigestTest::SetUpTestCase() {}
void NativeDigestTest::TearDownTestCase() {}

void NativeDigestTest::SetUp() // add init here, this will be called before test.
{
}

void NativeDigestTest::TearDown() // add destroy here, this will be called when test case done.
{
}

HWTEST_F(NativeDigestTest, NativeDigestTest001, TestSize.Level0)
{
    OH_CryptoDigest *mdObj = nullptr;
    OH_Crypto_ErrCode ret = OH_CryptoDigest_Create("SHA1", &mdObj);
    ASSERT_EQ(ret, CRYPTO_SUCCESS);
    // set input and output buf
    uint8_t testData[] = "My test data";
    // define input and output data in blob form
    Crypto_DataBlob inBlob = {.data = reinterpret_cast<uint8_t *>(testData), .len = sizeof(testData)};
    Crypto_DataBlob outBlob = { .data = nullptr, .len = 0 };
    // test api functions
    ret = OH_CryptoDigest_Update(mdObj, &inBlob);
    EXPECT_EQ(ret, CRYPTO_SUCCESS);
    ret = OH_CryptoDigest_Final(mdObj, &outBlob);
    EXPECT_EQ(ret, CRYPTO_SUCCESS);
    // destroy the API obj and blob data
    OH_Crypto_FreeDataBlob(&outBlob);
    OH_DigestCrypto_Destroy(mdObj);
}

HWTEST_F(NativeDigestTest, NativeDigestTest002, TestSize.Level0)
{
    // create a API obj with SHA1
    OH_CryptoDigest *mdObj = nullptr;
    OH_Crypto_ErrCode ret = OH_CryptoDigest_Create("SHA1", &mdObj);
    ASSERT_EQ(ret, CRYPTO_SUCCESS);
    // test api functions
    uint32_t len = OH_CryptoDigest_GetLength(mdObj);
    EXPECT_EQ(len, SHA1_LEN);
    OH_DigestCrypto_Destroy(mdObj);
}

HWTEST_F(NativeDigestTest, NativeDigestTest003, TestSize.Level0)
{
    // create a SHA1 obj
    OH_CryptoDigest *mdObj = nullptr;
    OH_Crypto_ErrCode ret = OH_CryptoDigest_Create("SHA1", &mdObj);
    ASSERT_EQ(ret, CRYPTO_SUCCESS);
    ASSERT_NE(mdObj, nullptr);
    // test api functions
    const char *algoName =  OH_CryptoDigest_GetAlgoName(mdObj);
    int32_t cmpRes = strcmp(algoName, "SHA1");
    EXPECT_EQ(cmpRes, CRYPTO_SUCCESS);
    OH_DigestCrypto_Destroy(mdObj);
}

HWTEST_F(NativeDigestTest, NativeDigestTest004, TestSize.Level0)
{
    OH_CryptoDigest *mdObj = nullptr;
    OH_Crypto_ErrCode ret = OH_CryptoDigest_Create("SHA3-512", &mdObj);
    ASSERT_EQ(ret, CRYPTO_SUCCESS);
    // set input and output buf
    uint8_t testData[] = "My test data";
    // define input and output data in blob form
    Crypto_DataBlob inBlob = {.data = reinterpret_cast<uint8_t *>(testData), .len = sizeof(testData)};
    Crypto_DataBlob outBlob = { .data = nullptr, .len = 0 };
    // test api functions
    ret = OH_CryptoDigest_Update(mdObj, &inBlob);
    EXPECT_EQ(ret, CRYPTO_SUCCESS);
    ret = OH_CryptoDigest_Final(mdObj, &outBlob);
    EXPECT_EQ(ret, CRYPTO_SUCCESS);
    // destroy the API obj and blob data
    OH_Crypto_FreeDataBlob(&outBlob);
    OH_DigestCrypto_Destroy(mdObj);
}

HWTEST_F(NativeDigestTest, NativeDigestTest005, TestSize.Level0)
{
    // create a SHA3_256 obj
    OH_CryptoDigest *mdObj = nullptr;
    OH_Crypto_ErrCode ret = OH_CryptoDigest_Create("SHA3-256", &mdObj);
    ASSERT_EQ(ret, CRYPTO_SUCCESS);
    ASSERT_NE(mdObj, nullptr);
    // test api functions
    const char *algoName =  OH_CryptoDigest_GetAlgoName(mdObj);
    int32_t cmpRes = strcmp(algoName, "SHA3-256");
    EXPECT_EQ(cmpRes, CRYPTO_SUCCESS);
    OH_DigestCrypto_Destroy(mdObj);
}
}