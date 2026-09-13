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
#include "crypto_sym_key.h"
#include "memory.h"
#include "memory_mock.h"
#include "securec.h"
#include "sym_key_generator.h"
#include "result.h"
#include "crypto_operation_err.h"

using namespace std;
using namespace testing::ext;

namespace {
class NativeSymKeyTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp();
    void TearDown();
};

void NativeSymKeyTest::SetUpTestCase() {}
void NativeSymKeyTest::TearDownTestCase() {}

void NativeSymKeyTest::SetUp() // add init here, this will be called before test.
{
}

void NativeSymKeyTest::TearDown() // add destroy here, this will be called when test case done.
{
}

HWTEST_F(NativeSymKeyTest, NativeSymKeyTest001, TestSize.Level0)
{
    OH_CryptoSymKeyGenerator *ctx = nullptr;
    OH_CryptoSymKey *convertKey = nullptr;
    uint8_t testKey[] = "abcdefghijklmnop";
    uint32_t testKeyLen = 16;
    Crypto_DataBlob keyMaterialBlob = {.data = reinterpret_cast<uint8_t *>(testKey), .len = testKeyLen};

    OH_Crypto_ErrCode ret = OH_CryptoSymKeyGenerator_Create("AES128", &ctx);
    EXPECT_EQ(ret, CRYPTO_SUCCESS);
    ret = OH_CryptoSymKeyGenerator_Convert(ctx, &keyMaterialBlob, &convertKey);
    EXPECT_EQ(ret, CRYPTO_SUCCESS);
    const char *algoName = OH_CryptoSymKeyGenerator_GetAlgoName(ctx);
    ASSERT_NE(algoName, nullptr);

    OH_CryptoSymKey_Destroy(convertKey);
    OH_CryptoSymKeyGenerator_Destroy(ctx);
}

HWTEST_F(NativeSymKeyTest, NativeSymKeyTest002, TestSize.Level0)
{
    OH_CryptoSymKeyGenerator *ctx = nullptr;
    OH_CryptoSymKey *symKey = nullptr;

    OH_Crypto_ErrCode ret = OH_CryptoSymKeyGenerator_Create("AES128", &ctx);
    EXPECT_EQ(ret, CRYPTO_SUCCESS);
    ret = OH_CryptoSymKeyGenerator_Generate(ctx, &symKey);
    EXPECT_EQ(ret, CRYPTO_SUCCESS);
    Crypto_DataBlob dataBlob = { .data = nullptr, .len = 0 };
    ret = OH_CryptoSymKey_GetKeyData(symKey, &dataBlob);

    EXPECT_EQ(ret, CRYPTO_SUCCESS);
    const char *algoName = OH_CryptoSymKeyGenerator_GetAlgoName(ctx);
    ASSERT_NE(algoName, nullptr);

    OH_CryptoSymKey_Destroy(symKey);
    OH_Crypto_FreeDataBlob(&dataBlob);
    OH_CryptoSymKeyGenerator_Destroy(ctx);
}

HWTEST_F(NativeSymKeyTest, CryptoSymKeyGeneratorNullTest001, TestSize.Level0)
{
    OH_Crypto_ErrCode res = OH_CryptoSymKeyGenerator_Create("AES128", nullptr);
    EXPECT_EQ(res, CRYPTO_INVALID_PARAMS);
}

HWTEST_F(NativeSymKeyTest, CryptoSymKeyGeneratorGenerateNullTest001, TestSize.Level0)
{
    OH_Crypto_ErrCode res = OH_CryptoSymKeyGenerator_Generate(nullptr, nullptr);
    EXPECT_EQ(res, CRYPTO_INVALID_PARAMS);
}

HWTEST_F(NativeSymKeyTest, CryptoSymKeyGeneratorConvertNullTest001, TestSize.Level0)
{
    OH_Crypto_ErrCode res = OH_CryptoSymKeyGenerator_Convert(nullptr, nullptr, nullptr);
    EXPECT_EQ(res, CRYPTO_INVALID_PARAMS);
}

HWTEST_F(NativeSymKeyTest, CryptoSymKeyGeneratorGetAlgoNameNullTest001, TestSize.Level0)
{
    const char *name = OH_CryptoSymKeyGenerator_GetAlgoName(nullptr);
    EXPECT_EQ(name, nullptr);

    OH_CryptoSymKeyGenerator_Destroy(nullptr);
}

HWTEST_F(NativeSymKeyTest, CryptoSymKeyGetAlgoNameNullTest001, TestSize.Level0)
{
    const char *name = OH_CryptoSymKey_GetAlgoName(nullptr);
    EXPECT_EQ(name, nullptr);
}

HWTEST_F(NativeSymKeyTest, CryptoSymKeyGetKeyDataNullTest001, TestSize.Level0)
{
    OH_Crypto_ErrCode res = OH_CryptoSymKey_GetKeyData(nullptr, nullptr);
    EXPECT_EQ(res, CRYPTO_INVALID_PARAMS);

    OH_CryptoSymKey_Destroy(nullptr);
}

HWTEST_F(NativeSymKeyTest, CryptoSymKeyGeneratorFullFlowTest001, TestSize.Level0)
{
    OH_CryptoSymKeyGenerator *keyGen = nullptr;
    OH_Crypto_ErrCode res = OH_CryptoSymKeyGenerator_Create("AES128", &keyGen);
    ASSERT_EQ(res, CRYPTO_SUCCESS);

    const char *algoName = OH_CryptoSymKeyGenerator_GetAlgoName(keyGen);
    EXPECT_NE(algoName, nullptr);

    OH_CryptoSymKey *symKey = nullptr;
    res = OH_CryptoSymKeyGenerator_Generate(keyGen, &symKey);
    ASSERT_EQ(res, CRYPTO_SUCCESS);

    const char *keyAlgoName = OH_CryptoSymKey_GetAlgoName(symKey);
    EXPECT_NE(keyAlgoName, nullptr);

    Crypto_DataBlob keyData = {.data = nullptr, .len = 0};
    res = OH_CryptoSymKey_GetKeyData(symKey, &keyData);
    EXPECT_EQ(res, CRYPTO_SUCCESS);
    EXPECT_NE(keyData.data, nullptr);
    EXPECT_GT(keyData.len, 0);

    OH_CryptoSymKey *convertedKey = nullptr;
    res = OH_CryptoSymKeyGenerator_Convert(keyGen, &keyData, &convertedKey);
    EXPECT_EQ(res, CRYPTO_SUCCESS);

    OH_Crypto_FreeDataBlob(&keyData);
    OH_CryptoSymKey_Destroy(convertedKey);
    OH_CryptoSymKey_Destroy(symKey);
    OH_CryptoSymKeyGenerator_Destroy(keyGen);
}
}
