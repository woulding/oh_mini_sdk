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
#include "crypto_rand.h"
#include "memory.h"
#include "memory_mock.h"
#include "result.h"
#include "crypto_operation_err.h"

using namespace std;
using namespace testing::ext;

class NativeRandTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp();
    void TearDown();
};

void NativeRandTest::SetUpTestCase() {}

void NativeRandTest::TearDownTestCase() {}

void NativeRandTest::SetUp() {}

void NativeRandTest::TearDown() {}

HWTEST_F(NativeRandTest, NativeRandTest001, TestSize.Level0)
{
    OH_CryptoRand *rand = nullptr;
    OH_Crypto_ErrCode ret = OH_CryptoRand_Create(&rand);
    EXPECT_EQ(ret, CRYPTO_SUCCESS);
    ASSERT_NE(rand, nullptr);

    uint8_t seedData[12] = {0x25, 0x65, 0x58, 0x89, 0x85, 0x55, 0x66, 0x77, 0x88, 0x99, 0x11, 0x22};
    Crypto_DataBlob seed = {
        .data = seedData,
        .len = sizeof(seedData)
    };
    ret = OH_CryptoRand_SetSeed(rand, &seed);
    EXPECT_EQ(ret, CRYPTO_SUCCESS);

    Crypto_DataBlob out = { 0 };
    ret = OH_CryptoRand_GenerateRandom(rand, 10, &out);
    EXPECT_EQ(ret, CRYPTO_SUCCESS);
    ASSERT_NE(out.data, nullptr);
    ASSERT_EQ(out.len, 10);

    const char *algoName = OH_CryptoRand_GetAlgoName(rand);
    ASSERT_NE(algoName, nullptr);
    EXPECT_GT(strlen(algoName), 0);

    OH_Crypto_FreeDataBlob(&out);
    OH_CryptoRand_Destroy(rand);
}

HWTEST_F(NativeRandTest, NativeRandTest002, TestSize.Level0)
{
    OH_Crypto_ErrCode ret = OH_CryptoRand_Create(nullptr);
    EXPECT_NE(ret, CRYPTO_SUCCESS);
}

HWTEST_F(NativeRandTest, NativeRandTest003, TestSize.Level0)
{
    OH_CryptoRand *rand = nullptr;
    OH_Crypto_ErrCode ret = OH_CryptoRand_Create(&rand);
    EXPECT_EQ(ret, CRYPTO_SUCCESS);
    ASSERT_NE(rand, nullptr);

    uint8_t seedData[12] = {0x25, 0x65, 0x58, 0x89, 0x85, 0x55, 0x66, 0x77, 0x88, 0x99, 0x11, 0x22};
    Crypto_DataBlob seed = {
        .data = seedData,
        .len = sizeof(seedData)
    };
    ret = OH_CryptoRand_SetSeed(nullptr, &seed);
    EXPECT_NE(ret, CRYPTO_SUCCESS);
    ret = OH_CryptoRand_SetSeed(rand, nullptr);
    EXPECT_NE(ret, CRYPTO_SUCCESS);
    ret = OH_CryptoRand_SetSeed(rand, &seed);
    EXPECT_EQ(ret, CRYPTO_SUCCESS);

    OH_CryptoRand_Destroy(rand);
}

HWTEST_F(NativeRandTest, NativeRandTest004, TestSize.Level0)
{
    OH_CryptoRand *rand = nullptr;
    OH_Crypto_ErrCode ret = OH_CryptoRand_Create(&rand);
    EXPECT_EQ(ret, CRYPTO_SUCCESS);
    ASSERT_NE(rand, nullptr);

    uint8_t seedData[12] = {0x25, 0x65, 0x58, 0x89, 0x85, 0x55, 0x66, 0x77, 0x88, 0x99, 0x11, 0x22};
    Crypto_DataBlob seed = {
        .data = seedData,
        .len = sizeof(seedData)
    };
    ret = OH_CryptoRand_SetSeed(rand, &seed);
    EXPECT_EQ(ret, CRYPTO_SUCCESS);

    Crypto_DataBlob out = { 0 };
    ret = OH_CryptoRand_GenerateRandom(nullptr, 10, &out);
    EXPECT_NE(ret, CRYPTO_SUCCESS);
    ret = OH_CryptoRand_GenerateRandom(rand, 10, nullptr);
    EXPECT_NE(ret, CRYPTO_SUCCESS);
    ret = OH_CryptoRand_GenerateRandom(rand, 10, &out);
    EXPECT_EQ(ret, CRYPTO_SUCCESS);

    OH_Crypto_FreeDataBlob(&out);
    OH_CryptoRand_Destroy(rand);
}

HWTEST_F(NativeRandTest, NativeRandTest005, TestSize.Level0)
{
    const char *algoName = OH_CryptoRand_GetAlgoName(nullptr);
    EXPECT_EQ(algoName, nullptr);
}

HWTEST_F(NativeRandTest, CryptoRandEnableHardwareEntropyTest001, TestSize.Level0)
{
    OH_CryptoRand *rand = nullptr;
    OH_Crypto_ErrCode res = OH_CryptoRand_Create(&rand);
    ASSERT_EQ(res, CRYPTO_SUCCESS);
    ASSERT_NE(rand, nullptr);

    res = OH_CryptoRand_EnableHardwareEntropy(rand);
    EXPECT_EQ(res, CRYPTO_SUCCESS);

    OH_CryptoRand_Destroy(rand);
}

HWTEST_F(NativeRandTest, CryptoRandEnableHardwareEntropyNullTest001, TestSize.Level0)
{
    OH_Crypto_ErrCode res = OH_CryptoRand_EnableHardwareEntropy(nullptr);
    EXPECT_EQ(res, CRYPTO_PARAMETER_CHECK_FAILED);
}

HWTEST_F(NativeRandTest, CryptoRandSetSeedAndEnableHardwareEntropyTest001, TestSize.Level0)
{
    OH_Crypto_ErrCode res = OH_CryptoRand_EnableHardwareEntropy(nullptr);
    EXPECT_EQ(res, CRYPTO_PARAMETER_CHECK_FAILED);

    OH_CryptoRand *rand = nullptr;
    res = OH_CryptoRand_Create(&rand);
    ASSERT_EQ(res, CRYPTO_SUCCESS);

    uint8_t seedData[] = {0x01, 0x02};
    Crypto_DataBlob seed = {.data = seedData, .len = sizeof(seedData)};
    res = OH_CryptoRand_SetSeed(rand, &seed);
    EXPECT_EQ(res, CRYPTO_SUCCESS);

    res = OH_CryptoRand_EnableHardwareEntropy(rand);
    EXPECT_EQ(res, CRYPTO_SUCCESS);

    OH_CryptoRand_Destroy(rand);
}
