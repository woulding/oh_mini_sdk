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
#include "crypto_asym_key.h"
#include "crypto_key_agreement.h"
#include "memory.h"
#include "memory_mock.h"

using namespace std;
using namespace testing::ext;

namespace {
class NativeKeyAgreementTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp();
    void TearDown();
};

void NativeKeyAgreementTest::SetUpTestCase() {}
void NativeKeyAgreementTest::TearDownTestCase() {}

void NativeKeyAgreementTest::SetUp() // add init here, this will be called before test.
{
}

void NativeKeyAgreementTest::TearDown() // add destroy here, this will be called when test case done.
{
}

HWTEST_F(NativeKeyAgreementTest, NativeKeyAgreementTest001, TestSize.Level0)
{
    OH_CryptoAsymKeyGenerator* generator = nullptr;
    OH_Crypto_ErrCode ret = OH_CryptoAsymKeyGenerator_Create("X25519", &generator);
    EXPECT_EQ(ret, CRYPTO_SUCCESS);
    OH_CryptoKeyPair *keyPairC = nullptr;
    ret = OH_CryptoAsymKeyGenerator_Generate(generator, &keyPairC);
    EXPECT_EQ(ret, CRYPTO_SUCCESS);
    OH_CryptoKeyPair *keyPairS = nullptr;
    ret = OH_CryptoAsymKeyGenerator_Generate(generator, &keyPairS);
    EXPECT_EQ(ret, CRYPTO_SUCCESS);
    OH_CryptoPrivKey *privkey = OH_CryptoKeyPair_GetPrivKey(keyPairC);
    ASSERT_NE(privkey, nullptr);
    OH_CryptoPubKey *pubkey = OH_CryptoKeyPair_GetPubKey(keyPairS);
    ASSERT_NE(pubkey, nullptr);

    OH_CryptoKeyAgreement *ctx = nullptr;
    ret = OH_CryptoKeyAgreement_Create("X25519", &ctx);
    EXPECT_EQ(ret, CRYPTO_SUCCESS);

    Crypto_DataBlob key = {0};
    ret = OH_CryptoKeyAgreement_GenerateSecret(nullptr, privkey, pubkey, &key);
    EXPECT_NE(ret, CRYPTO_SUCCESS);
    ret = OH_CryptoKeyAgreement_GenerateSecret(ctx, nullptr, pubkey, &key);
    EXPECT_NE(ret, CRYPTO_SUCCESS);
    ret = OH_CryptoKeyAgreement_GenerateSecret(ctx, privkey, nullptr, &key);
    EXPECT_NE(ret, CRYPTO_SUCCESS);
    ret = OH_CryptoKeyAgreement_GenerateSecret(ctx, privkey, pubkey, nullptr);
    EXPECT_NE(ret, CRYPTO_SUCCESS);
    ret = OH_CryptoKeyAgreement_GenerateSecret(ctx, privkey, pubkey, &key);
    EXPECT_EQ(ret, CRYPTO_SUCCESS);

    OH_Crypto_FreeDataBlob(&key);
    OH_CryptoKeyAgreement_Destroy(ctx);
    OH_CryptoKeyPair_Destroy(keyPairC);
    OH_CryptoKeyPair_Destroy(keyPairS);
    OH_CryptoAsymKeyGenerator_Destroy(generator);
}

HWTEST_F(NativeKeyAgreementTest, NativeKeyAgreementTest002, TestSize.Level0)
{
    OH_Crypto_ErrCode ret = OH_CryptoKeyAgreement_Create("X25519", nullptr);
    EXPECT_NE(ret, CRYPTO_SUCCESS);
}
}