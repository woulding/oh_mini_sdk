/*
 * Copyright (C) 2023 Huawei Device Co., Ltd.
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
#include <string>
#include "securec.h"

#include "asy_key_generator.h"
#include "detailed_ecc_key_params.h"
#include "ecc_asy_key_common.h"
#include "ecc_asy_key_generator_openssl.h"
#include "ecc_openssl_common.h"
#include "ecc_openssl_common_param_spec.h"
#include "ecc_common.h"
#include "blob.h"
#include "memory.h"
#include "memory_mock.h"
#include "openssl_adapter_mock.h"
#include "openssl_class.h"
#include "openssl_common.h"
#include "params_parser.h"

using namespace std;
using namespace testing::ext;

namespace {
class CryptoEccAsyKeyGeneratorBySpecSubTwoTest : public testing::Test {
public:
    static void SetUpTestCase() {};
    static void TearDownTestCase() {};
    void SetUp() {};
    void TearDown() {};
};

// for test:ECC_A_BN
HWTEST_F(CryptoEccAsyKeyGeneratorBySpecSubTwoTest, CryptoEccAsyKeyGeneratorBySpecSubTwoTest402_1, TestSize.Level0)
{
    HcfAsyKeyParamsSpec *paramSpec = nullptr;
    int32_t res = ConstructEcc224CommParamsSpec(&paramSpec);

    ASSERT_EQ(res, HCF_SUCCESS);

    HcfAsyKeyGeneratorBySpec *generator = nullptr;
    res = HcfAsyKeyGeneratorBySpecCreate(paramSpec, &generator);

    HcfKeyPair *keyPair = nullptr;
    res = generator->generateKeyPair(generator, &keyPair);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(keyPair, nullptr);

    HcfBigInteger retBigInt = { .data = nullptr, .len = 0 };
    AsyKeySpecItem item = ECC_A_BN;

    res = keyPair->pubKey->getAsyKeySpecBigInteger(keyPair->pubKey, item, &retBigInt);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(retBigInt.data, nullptr);
    ASSERT_NE(retBigInt.len, 0);

    HcfFree(retBigInt.data);

    HcfObjDestroy(keyPair);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoEccAsyKeyGeneratorBySpecSubTwoTest, CryptoEccAsyKeyGeneratorBySpecSubTwoTest402_2, TestSize.Level0)
{
    HcfAsyKeyParamsSpec *paramSpec = nullptr;
    int32_t res = ConstructEcc224CommParamsSpec(&paramSpec);

    ASSERT_EQ(res, HCF_SUCCESS);

    HcfAsyKeyGeneratorBySpec *generator = nullptr;
    res = HcfAsyKeyGeneratorBySpecCreate(paramSpec, &generator);

    HcfKeyPair *keyPair = nullptr;
    res = generator->generateKeyPair(generator, &keyPair);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(keyPair, nullptr);

    HcfBigInteger retBigInt = { .data = nullptr, .len = 0 };
    AsyKeySpecItem item = ECC_A_BN;

    res = keyPair->priKey->getAsyKeySpecBigInteger(keyPair->priKey, item, &retBigInt);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(retBigInt.data, nullptr);
    ASSERT_NE(retBigInt.len, 0);

    HcfFree(retBigInt.data);

    HcfObjDestroy(keyPair);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoEccAsyKeyGeneratorBySpecSubTwoTest, CryptoEccAsyKeyGeneratorBySpecSubTwoTest402_3, TestSize.Level0)
{
    HcfAsyKeyParamsSpec *paramSpec = nullptr;
    int32_t res = ConstructEcc224PubKeyParamsSpec(&paramSpec);

    ASSERT_EQ(res, HCF_SUCCESS);

    HcfAsyKeyGeneratorBySpec *generator = nullptr;
    res = HcfAsyKeyGeneratorBySpecCreate(paramSpec, &generator);

    HcfPubKey *pubKey = nullptr;
    res = generator->generatePubKey(generator, &pubKey);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(pubKey, nullptr);

    HcfBigInteger retBigInt = { .data = nullptr, .len = 0 };
    AsyKeySpecItem item = ECC_A_BN;

    res = pubKey->getAsyKeySpecBigInteger(pubKey, item, &retBigInt);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(retBigInt.data, nullptr);
    ASSERT_NE(retBigInt.len, 0);

    HcfFree(retBigInt.data);

    HcfObjDestroy(pubKey);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoEccAsyKeyGeneratorBySpecSubTwoTest, CryptoEccAsyKeyGeneratorBySpecSubTwoTest402_4, TestSize.Level0)
{
    HcfAsyKeyParamsSpec *paramSpec = nullptr;
    int32_t res = ConstructEcc224PriKeyParamsSpec(&paramSpec);

    ASSERT_EQ(res, HCF_SUCCESS);

    HcfAsyKeyGeneratorBySpec *generator = nullptr;
    res = HcfAsyKeyGeneratorBySpecCreate(paramSpec, &generator);

    HcfPriKey *priKey = nullptr;
    res = generator->generatePriKey(generator, &priKey);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(priKey, nullptr);

    HcfBigInteger retBigInt = { .data = nullptr, .len = 0 };
    AsyKeySpecItem item = ECC_A_BN;

    res = priKey->getAsyKeySpecBigInteger(priKey, item, &retBigInt);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(retBigInt.data, nullptr);
    ASSERT_NE(retBigInt.len, 0);

    HcfFree(retBigInt.data);

    HcfObjDestroy(priKey);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoEccAsyKeyGeneratorBySpecSubTwoTest, CryptoEccAsyKeyGeneratorBySpecSubTwoTest402_5, TestSize.Level0)
{
    HcfAsyKeyParamsSpec *paramSpec = nullptr;
    int32_t res = ConstructEcc224KeyPairParamsSpec(&paramSpec);

    ASSERT_EQ(res, HCF_SUCCESS);

    HcfAsyKeyGeneratorBySpec *generator = nullptr;
    res = HcfAsyKeyGeneratorBySpecCreate(paramSpec, &generator);

    HcfKeyPair *keyPair = nullptr;
    res = generator->generateKeyPair(generator, &keyPair);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(keyPair, nullptr);

    HcfBigInteger retBigInt = { .data = nullptr, .len = 0 };
    AsyKeySpecItem item = ECC_A_BN;

    res = keyPair->pubKey->getAsyKeySpecBigInteger(keyPair->pubKey, item, &retBigInt);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(retBigInt.data, nullptr);
    ASSERT_NE(retBigInt.len, 0);

    HcfFree(retBigInt.data);

    HcfObjDestroy(keyPair);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoEccAsyKeyGeneratorBySpecSubTwoTest, CryptoEccAsyKeyGeneratorBySpecSubTwoTest402_6, TestSize.Level0)
{
    HcfAsyKeyParamsSpec *paramSpec = nullptr;
    int32_t res = ConstructEcc224KeyPairParamsSpec(&paramSpec);

    ASSERT_EQ(res, HCF_SUCCESS);

    HcfAsyKeyGeneratorBySpec *generator = nullptr;
    res = HcfAsyKeyGeneratorBySpecCreate(paramSpec, &generator);

    HcfKeyPair *keyPair = nullptr;
    res = generator->generateKeyPair(generator, &keyPair);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(keyPair, nullptr);

    HcfBigInteger retBigInt = { .data = nullptr, .len = 0 };
    AsyKeySpecItem item = ECC_A_BN;

    res = keyPair->priKey->getAsyKeySpecBigInteger(keyPair->priKey, item, &retBigInt);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(retBigInt.data, nullptr);
    ASSERT_NE(retBigInt.len, 0);

    HcfFree(retBigInt.data);

    HcfObjDestroy(keyPair);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoEccAsyKeyGeneratorBySpecSubTwoTest, CryptoEccAsyKeyGeneratorBySpecSubTwoTest402_7, TestSize.Level0)
{
    HcfAsyKeyParamsSpec *paramSpec = nullptr;
    int32_t res = ConstructEcc224KeyPairParamsSpec(&paramSpec);

    ASSERT_EQ(res, HCF_SUCCESS);

    HcfAsyKeyGeneratorBySpec *generator = nullptr;
    res = HcfAsyKeyGeneratorBySpecCreate(paramSpec, &generator);

    HcfPubKey *pubKey = nullptr;
    res = generator->generatePubKey(generator, &pubKey);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(pubKey, nullptr);

    HcfBigInteger retBigInt = { .data = nullptr, .len = 0 };
    AsyKeySpecItem item = ECC_A_BN;

    res = pubKey->getAsyKeySpecBigInteger(pubKey, item, &retBigInt);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(retBigInt.data, nullptr);
    ASSERT_NE(retBigInt.len, 0);

    HcfFree(retBigInt.data);

    HcfObjDestroy(pubKey);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoEccAsyKeyGeneratorBySpecSubTwoTest, CryptoEccAsyKeyGeneratorBySpecSubTwoTest402_8, TestSize.Level0)
{
    HcfAsyKeyParamsSpec *paramSpec = nullptr;
    int32_t res = ConstructEcc224KeyPairParamsSpec(&paramSpec);

    ASSERT_EQ(res, HCF_SUCCESS);

    HcfAsyKeyGeneratorBySpec *generator = nullptr;
    res = HcfAsyKeyGeneratorBySpecCreate(paramSpec, &generator);

    HcfPriKey *priKey = nullptr;
    res = generator->generatePriKey(generator, &priKey);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(priKey, nullptr);

    HcfBigInteger retBigInt = { .data = nullptr, .len = 0 };
    AsyKeySpecItem item = ECC_A_BN;

    res = priKey->getAsyKeySpecBigInteger(priKey, item, &retBigInt);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(retBigInt.data, nullptr);
    ASSERT_NE(retBigInt.len, 0);

    HcfFree(retBigInt.data);

    HcfObjDestroy(priKey);
    HcfObjDestroy(generator);
}

// for test:ECC_B_BN
HWTEST_F(CryptoEccAsyKeyGeneratorBySpecSubTwoTest, CryptoEccAsyKeyGeneratorBySpecSubTwoTest403_1, TestSize.Level0)
{
    HcfAsyKeyParamsSpec *paramSpec = nullptr;
    int32_t res = ConstructEcc224CommParamsSpec(&paramSpec);

    ASSERT_EQ(res, HCF_SUCCESS);

    HcfAsyKeyGeneratorBySpec *generator = nullptr;
    res = HcfAsyKeyGeneratorBySpecCreate(paramSpec, &generator);

    HcfKeyPair *keyPair = nullptr;
    res = generator->generateKeyPair(generator, &keyPair);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(keyPair, nullptr);

    HcfBigInteger retBigInt = { .data = nullptr, .len = 0 };
    AsyKeySpecItem item = ECC_B_BN;

    res = keyPair->pubKey->getAsyKeySpecBigInteger(keyPair->pubKey, item, &retBigInt);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(retBigInt.data, nullptr);
    ASSERT_NE(retBigInt.len, 0);

    HcfFree(retBigInt.data);

    HcfObjDestroy(keyPair);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoEccAsyKeyGeneratorBySpecSubTwoTest, CryptoEccAsyKeyGeneratorBySpecSubTwoTest403_2, TestSize.Level0)
{
    HcfAsyKeyParamsSpec *paramSpec = nullptr;
    int32_t res = ConstructEcc224CommParamsSpec(&paramSpec);

    ASSERT_EQ(res, HCF_SUCCESS);

    HcfAsyKeyGeneratorBySpec *generator = nullptr;
    res = HcfAsyKeyGeneratorBySpecCreate(paramSpec, &generator);

    HcfKeyPair *keyPair = nullptr;
    res = generator->generateKeyPair(generator, &keyPair);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(keyPair, nullptr);

    HcfBigInteger retBigInt = { .data = nullptr, .len = 0 };
    AsyKeySpecItem item = ECC_B_BN;

    res = keyPair->priKey->getAsyKeySpecBigInteger(keyPair->priKey, item, &retBigInt);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(retBigInt.data, nullptr);
    ASSERT_NE(retBigInt.len, 0);

    HcfFree(retBigInt.data);

    HcfObjDestroy(keyPair);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoEccAsyKeyGeneratorBySpecSubTwoTest, CryptoEccAsyKeyGeneratorBySpecSubTwoTest403_3, TestSize.Level0)
{
    HcfAsyKeyParamsSpec *paramSpec = nullptr;
    int32_t res = ConstructEcc224PubKeyParamsSpec(&paramSpec);

    ASSERT_EQ(res, HCF_SUCCESS);

    HcfAsyKeyGeneratorBySpec *generator = nullptr;
    res = HcfAsyKeyGeneratorBySpecCreate(paramSpec, &generator);

    HcfPubKey *pubKey = nullptr;
    res = generator->generatePubKey(generator, &pubKey);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(pubKey, nullptr);

    HcfBigInteger retBigInt = { .data = nullptr, .len = 0 };
    AsyKeySpecItem item = ECC_B_BN;

    res = pubKey->getAsyKeySpecBigInteger(pubKey, item, &retBigInt);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(retBigInt.data, nullptr);
    ASSERT_NE(retBigInt.len, 0);

    HcfFree(retBigInt.data);

    HcfObjDestroy(pubKey);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoEccAsyKeyGeneratorBySpecSubTwoTest, CryptoEccAsyKeyGeneratorBySpecSubTwoTest403_4, TestSize.Level0)
{
    HcfAsyKeyParamsSpec *paramSpec = nullptr;
    int32_t res = ConstructEcc224PriKeyParamsSpec(&paramSpec);

    ASSERT_EQ(res, HCF_SUCCESS);

    HcfAsyKeyGeneratorBySpec *generator = nullptr;
    res = HcfAsyKeyGeneratorBySpecCreate(paramSpec, &generator);

    HcfPriKey *priKey = nullptr;
    res = generator->generatePriKey(generator, &priKey);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(priKey, nullptr);

    HcfBigInteger retBigInt = { .data = nullptr, .len = 0 };
    AsyKeySpecItem item = ECC_B_BN;

    res = priKey->getAsyKeySpecBigInteger(priKey, item, &retBigInt);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(retBigInt.data, nullptr);
    ASSERT_NE(retBigInt.len, 0);

    HcfFree(retBigInt.data);

    HcfObjDestroy(priKey);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoEccAsyKeyGeneratorBySpecSubTwoTest, CryptoEccAsyKeyGeneratorBySpecSubTwoTest403_5, TestSize.Level0)
{
    HcfAsyKeyParamsSpec *paramSpec = nullptr;
    int32_t res = ConstructEcc224KeyPairParamsSpec(&paramSpec);

    ASSERT_EQ(res, HCF_SUCCESS);

    HcfAsyKeyGeneratorBySpec *generator = nullptr;
    res = HcfAsyKeyGeneratorBySpecCreate(paramSpec, &generator);

    HcfKeyPair *keyPair = nullptr;
    res = generator->generateKeyPair(generator, &keyPair);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(keyPair, nullptr);

    HcfBigInteger retBigInt = { .data = nullptr, .len = 0 };
    AsyKeySpecItem item = ECC_B_BN;

    res = keyPair->pubKey->getAsyKeySpecBigInteger(keyPair->pubKey, item, &retBigInt);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(retBigInt.data, nullptr);
    ASSERT_NE(retBigInt.len, 0);

    HcfFree(retBigInt.data);

    HcfObjDestroy(keyPair);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoEccAsyKeyGeneratorBySpecSubTwoTest, CryptoEccAsyKeyGeneratorBySpecSubTwoTest403_6, TestSize.Level0)
{
    HcfAsyKeyParamsSpec *paramSpec = nullptr;
    int32_t res = ConstructEcc224KeyPairParamsSpec(&paramSpec);

    ASSERT_EQ(res, HCF_SUCCESS);

    HcfAsyKeyGeneratorBySpec *generator = nullptr;
    res = HcfAsyKeyGeneratorBySpecCreate(paramSpec, &generator);

    HcfKeyPair *keyPair = nullptr;
    res = generator->generateKeyPair(generator, &keyPair);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(keyPair, nullptr);

    HcfBigInteger retBigInt = { .data = nullptr, .len = 0 };
    AsyKeySpecItem item = ECC_B_BN;

    res = keyPair->priKey->getAsyKeySpecBigInteger(keyPair->priKey, item, &retBigInt);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(retBigInt.data, nullptr);
    ASSERT_NE(retBigInt.len, 0);

    HcfFree(retBigInt.data);

    HcfObjDestroy(keyPair);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoEccAsyKeyGeneratorBySpecSubTwoTest, CryptoEccAsyKeyGeneratorBySpecSubTwoTest403_7, TestSize.Level0)
{
    HcfAsyKeyParamsSpec *paramSpec = nullptr;
    int32_t res = ConstructEcc224KeyPairParamsSpec(&paramSpec);

    ASSERT_EQ(res, HCF_SUCCESS);

    HcfAsyKeyGeneratorBySpec *generator = nullptr;
    res = HcfAsyKeyGeneratorBySpecCreate(paramSpec, &generator);

    HcfPubKey *pubKey = nullptr;
    res = generator->generatePubKey(generator, &pubKey);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(pubKey, nullptr);

    HcfBigInteger retBigInt = { .data = nullptr, .len = 0 };
    AsyKeySpecItem item = ECC_B_BN;

    res = pubKey->getAsyKeySpecBigInteger(pubKey, item, &retBigInt);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(retBigInt.data, nullptr);
    ASSERT_NE(retBigInt.len, 0);

    HcfFree(retBigInt.data);

    HcfObjDestroy(pubKey);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoEccAsyKeyGeneratorBySpecSubTwoTest, CryptoEccAsyKeyGeneratorBySpecSubTwoTest403_8, TestSize.Level0)
{
    HcfAsyKeyParamsSpec *paramSpec = nullptr;
    int32_t res = ConstructEcc224KeyPairParamsSpec(&paramSpec);

    ASSERT_EQ(res, HCF_SUCCESS);

    HcfAsyKeyGeneratorBySpec *generator = nullptr;
    res = HcfAsyKeyGeneratorBySpecCreate(paramSpec, &generator);

    HcfPriKey *priKey = nullptr;
    res = generator->generatePriKey(generator, &priKey);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(priKey, nullptr);

    HcfBigInteger retBigInt = { .data = nullptr, .len = 0 };
    AsyKeySpecItem item = ECC_B_BN;

    res = priKey->getAsyKeySpecBigInteger(priKey, item, &retBigInt);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(retBigInt.data, nullptr);
    ASSERT_NE(retBigInt.len, 0);

    HcfFree(retBigInt.data);

    HcfObjDestroy(priKey);
    HcfObjDestroy(generator);
}

// for test:ECC_G_X_BN
HWTEST_F(CryptoEccAsyKeyGeneratorBySpecSubTwoTest, CryptoEccAsyKeyGeneratorBySpecSubTwoTest404_1, TestSize.Level0)
{
    HcfAsyKeyParamsSpec *paramSpec = nullptr;
    int32_t res = ConstructEcc224CommParamsSpec(&paramSpec);

    ASSERT_EQ(res, HCF_SUCCESS);

    HcfAsyKeyGeneratorBySpec *generator = nullptr;
    res = HcfAsyKeyGeneratorBySpecCreate(paramSpec, &generator);

    HcfKeyPair *keyPair = nullptr;
    res = generator->generateKeyPair(generator, &keyPair);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(keyPair, nullptr);

    HcfBigInteger retBigInt = { .data = nullptr, .len = 0 };
    AsyKeySpecItem item = ECC_G_X_BN;

    res = keyPair->pubKey->getAsyKeySpecBigInteger(keyPair->pubKey, item, &retBigInt);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(retBigInt.data, nullptr);
    ASSERT_NE(retBigInt.len, 0);

    HcfFree(retBigInt.data);

    HcfObjDestroy(keyPair);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoEccAsyKeyGeneratorBySpecSubTwoTest, CryptoEccAsyKeyGeneratorBySpecSubTwoTest404_2, TestSize.Level0)
{
    HcfAsyKeyParamsSpec *paramSpec = nullptr;
    int32_t res = ConstructEcc224CommParamsSpec(&paramSpec);

    ASSERT_EQ(res, HCF_SUCCESS);

    HcfAsyKeyGeneratorBySpec *generator = nullptr;
    res = HcfAsyKeyGeneratorBySpecCreate(paramSpec, &generator);

    HcfKeyPair *keyPair = nullptr;
    res = generator->generateKeyPair(generator, &keyPair);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(keyPair, nullptr);

    HcfBigInteger retBigInt = { .data = nullptr, .len = 0 };
    AsyKeySpecItem item = ECC_G_X_BN;

    res = keyPair->priKey->getAsyKeySpecBigInteger(keyPair->priKey, item, &retBigInt);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(retBigInt.data, nullptr);
    ASSERT_NE(retBigInt.len, 0);

    HcfFree(retBigInt.data);

    HcfObjDestroy(keyPair);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoEccAsyKeyGeneratorBySpecSubTwoTest, CryptoEccAsyKeyGeneratorBySpecSubTwoTest404_3, TestSize.Level0)
{
    HcfAsyKeyParamsSpec *paramSpec = nullptr;
    int32_t res = ConstructEcc224PubKeyParamsSpec(&paramSpec);

    ASSERT_EQ(res, HCF_SUCCESS);

    HcfAsyKeyGeneratorBySpec *generator = nullptr;
    res = HcfAsyKeyGeneratorBySpecCreate(paramSpec, &generator);

    HcfPubKey *pubKey = nullptr;
    res = generator->generatePubKey(generator, &pubKey);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(pubKey, nullptr);

    HcfBigInteger retBigInt = { .data = nullptr, .len = 0 };
    AsyKeySpecItem item = ECC_G_X_BN;

    res = pubKey->getAsyKeySpecBigInteger(pubKey, item, &retBigInt);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(retBigInt.data, nullptr);
    ASSERT_NE(retBigInt.len, 0);

    HcfFree(retBigInt.data);

    HcfObjDestroy(pubKey);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoEccAsyKeyGeneratorBySpecSubTwoTest, CryptoEccAsyKeyGeneratorBySpecSubTwoTest404_4, TestSize.Level0)
{
    HcfAsyKeyParamsSpec *paramSpec = nullptr;
    int32_t res = ConstructEcc224PriKeyParamsSpec(&paramSpec);

    ASSERT_EQ(res, HCF_SUCCESS);

    HcfAsyKeyGeneratorBySpec *generator = nullptr;
    res = HcfAsyKeyGeneratorBySpecCreate(paramSpec, &generator);

    HcfPriKey *priKey = nullptr;
    res = generator->generatePriKey(generator, &priKey);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(priKey, nullptr);

    HcfBigInteger retBigInt = { .data = nullptr, .len = 0 };
    AsyKeySpecItem item = ECC_G_X_BN;

    res = priKey->getAsyKeySpecBigInteger(priKey, item, &retBigInt);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(retBigInt.data, nullptr);
    ASSERT_NE(retBigInt.len, 0);

    HcfFree(retBigInt.data);

    HcfObjDestroy(priKey);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoEccAsyKeyGeneratorBySpecSubTwoTest, CryptoEccAsyKeyGeneratorBySpecSubTwoTest404_5, TestSize.Level0)
{
    HcfAsyKeyParamsSpec *paramSpec = nullptr;
    int32_t res = ConstructEcc224KeyPairParamsSpec(&paramSpec);

    ASSERT_EQ(res, HCF_SUCCESS);

    HcfAsyKeyGeneratorBySpec *generator = nullptr;
    res = HcfAsyKeyGeneratorBySpecCreate(paramSpec, &generator);

    HcfKeyPair *keyPair = nullptr;
    res = generator->generateKeyPair(generator, &keyPair);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(keyPair, nullptr);

    HcfBigInteger retBigInt = { .data = nullptr, .len = 0 };
    AsyKeySpecItem item = ECC_G_X_BN;

    res = keyPair->pubKey->getAsyKeySpecBigInteger(keyPair->pubKey, item, &retBigInt);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(retBigInt.data, nullptr);
    ASSERT_NE(retBigInt.len, 0);

    HcfFree(retBigInt.data);

    HcfObjDestroy(keyPair);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoEccAsyKeyGeneratorBySpecSubTwoTest, CryptoEccAsyKeyGeneratorBySpecSubTwoTest404_6, TestSize.Level0)
{
    HcfAsyKeyParamsSpec *paramSpec = nullptr;
    int32_t res = ConstructEcc224KeyPairParamsSpec(&paramSpec);

    ASSERT_EQ(res, HCF_SUCCESS);

    HcfAsyKeyGeneratorBySpec *generator = nullptr;
    res = HcfAsyKeyGeneratorBySpecCreate(paramSpec, &generator);

    HcfKeyPair *keyPair = nullptr;
    res = generator->generateKeyPair(generator, &keyPair);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(keyPair, nullptr);

    HcfBigInteger retBigInt = { .data = nullptr, .len = 0 };
    AsyKeySpecItem item = ECC_G_X_BN;

    res = keyPair->priKey->getAsyKeySpecBigInteger(keyPair->priKey, item, &retBigInt);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(retBigInt.data, nullptr);
    ASSERT_NE(retBigInt.len, 0);

    HcfFree(retBigInt.data);

    HcfObjDestroy(keyPair);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoEccAsyKeyGeneratorBySpecSubTwoTest, CryptoEccAsyKeyGeneratorBySpecSubTwoTest404_7, TestSize.Level0)
{
    HcfAsyKeyParamsSpec *paramSpec = nullptr;
    int32_t res = ConstructEcc224KeyPairParamsSpec(&paramSpec);

    ASSERT_EQ(res, HCF_SUCCESS);

    HcfAsyKeyGeneratorBySpec *generator = nullptr;
    res = HcfAsyKeyGeneratorBySpecCreate(paramSpec, &generator);

    HcfPubKey *pubKey = nullptr;
    res = generator->generatePubKey(generator, &pubKey);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(pubKey, nullptr);

    HcfBigInteger retBigInt = { .data = nullptr, .len = 0 };
    AsyKeySpecItem item = ECC_G_X_BN;

    res = pubKey->getAsyKeySpecBigInteger(pubKey, item, &retBigInt);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(retBigInt.data, nullptr);
    ASSERT_NE(retBigInt.len, 0);

    HcfFree(retBigInt.data);

    HcfObjDestroy(pubKey);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoEccAsyKeyGeneratorBySpecSubTwoTest, CryptoEccAsyKeyGeneratorBySpecSubTwoTest404_8, TestSize.Level0)
{
    HcfAsyKeyParamsSpec *paramSpec = nullptr;
    int32_t res = ConstructEcc224KeyPairParamsSpec(&paramSpec);

    ASSERT_EQ(res, HCF_SUCCESS);

    HcfAsyKeyGeneratorBySpec *generator = nullptr;
    res = HcfAsyKeyGeneratorBySpecCreate(paramSpec, &generator);

    HcfPriKey *priKey = nullptr;
    res = generator->generatePriKey(generator, &priKey);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(priKey, nullptr);

    HcfBigInteger retBigInt = { .data = nullptr, .len = 0 };
    AsyKeySpecItem item = ECC_G_X_BN;

    res = priKey->getAsyKeySpecBigInteger(priKey, item, &retBigInt);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(retBigInt.data, nullptr);
    ASSERT_NE(retBigInt.len, 0);

    HcfFree(retBigInt.data);

    HcfObjDestroy(priKey);
    HcfObjDestroy(generator);
}

// for test:ECC_G_Y_BN
HWTEST_F(CryptoEccAsyKeyGeneratorBySpecSubTwoTest, CryptoEccAsyKeyGeneratorBySpecSubTwoTest405_1, TestSize.Level0)
{
    HcfAsyKeyParamsSpec *paramSpec = nullptr;
    int32_t res = ConstructEcc224CommParamsSpec(&paramSpec);

    ASSERT_EQ(res, HCF_SUCCESS);

    HcfAsyKeyGeneratorBySpec *generator = nullptr;
    res = HcfAsyKeyGeneratorBySpecCreate(paramSpec, &generator);

    HcfKeyPair *keyPair = nullptr;
    res = generator->generateKeyPair(generator, &keyPair);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(keyPair, nullptr);

    HcfBigInteger retBigInt = { .data = nullptr, .len = 0 };
    AsyKeySpecItem item = ECC_G_Y_BN;

    res = keyPair->pubKey->getAsyKeySpecBigInteger(keyPair->pubKey, item, &retBigInt);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(retBigInt.data, nullptr);
    ASSERT_NE(retBigInt.len, 0);

    HcfFree(retBigInt.data);

    HcfObjDestroy(keyPair);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoEccAsyKeyGeneratorBySpecSubTwoTest, CryptoEccAsyKeyGeneratorBySpecSubTwoTest405_2, TestSize.Level0)
{
    HcfAsyKeyParamsSpec *paramSpec = nullptr;
    int32_t res = ConstructEcc224CommParamsSpec(&paramSpec);

    ASSERT_EQ(res, HCF_SUCCESS);

    HcfAsyKeyGeneratorBySpec *generator = nullptr;
    res = HcfAsyKeyGeneratorBySpecCreate(paramSpec, &generator);

    HcfKeyPair *keyPair = nullptr;
    res = generator->generateKeyPair(generator, &keyPair);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(keyPair, nullptr);

    HcfBigInteger retBigInt = { .data = nullptr, .len = 0 };
    AsyKeySpecItem item = ECC_G_Y_BN;

    res = keyPair->priKey->getAsyKeySpecBigInteger(keyPair->priKey, item, &retBigInt);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(retBigInt.data, nullptr);
    ASSERT_NE(retBigInt.len, 0);

    HcfFree(retBigInt.data);

    HcfObjDestroy(keyPair);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoEccAsyKeyGeneratorBySpecSubTwoTest, CryptoEccAsyKeyGeneratorBySpecSubTwoTest405_3, TestSize.Level0)
{
    HcfAsyKeyParamsSpec *paramSpec = nullptr;
    int32_t res = ConstructEcc224PubKeyParamsSpec(&paramSpec);

    ASSERT_EQ(res, HCF_SUCCESS);

    HcfAsyKeyGeneratorBySpec *generator = nullptr;
    res = HcfAsyKeyGeneratorBySpecCreate(paramSpec, &generator);

    HcfPubKey *pubKey = nullptr;
    res = generator->generatePubKey(generator, &pubKey);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(pubKey, nullptr);

    HcfBigInteger retBigInt = { .data = nullptr, .len = 0 };
    AsyKeySpecItem item = ECC_G_Y_BN;

    res = pubKey->getAsyKeySpecBigInteger(pubKey, item, &retBigInt);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(retBigInt.data, nullptr);
    ASSERT_NE(retBigInt.len, 0);

    HcfFree(retBigInt.data);

    HcfObjDestroy(pubKey);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoEccAsyKeyGeneratorBySpecSubTwoTest, CryptoEccAsyKeyGeneratorBySpecSubTwoTest405_4, TestSize.Level0)
{
    HcfAsyKeyParamsSpec *paramSpec = nullptr;
    int32_t res = ConstructEcc224PriKeyParamsSpec(&paramSpec);

    ASSERT_EQ(res, HCF_SUCCESS);

    HcfAsyKeyGeneratorBySpec *generator = nullptr;
    res = HcfAsyKeyGeneratorBySpecCreate(paramSpec, &generator);

    HcfPriKey *priKey = nullptr;
    res = generator->generatePriKey(generator, &priKey);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(priKey, nullptr);

    HcfBigInteger retBigInt = { .data = nullptr, .len = 0 };
    AsyKeySpecItem item = ECC_G_Y_BN;

    res = priKey->getAsyKeySpecBigInteger(priKey, item, &retBigInt);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(retBigInt.data, nullptr);
    ASSERT_NE(retBigInt.len, 0);

    HcfFree(retBigInt.data);

    HcfObjDestroy(priKey);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoEccAsyKeyGeneratorBySpecSubTwoTest, CryptoEccAsyKeyGeneratorBySpecSubTwoTest405_5, TestSize.Level0)
{
    HcfAsyKeyParamsSpec *paramSpec = nullptr;
    int32_t res = ConstructEcc224KeyPairParamsSpec(&paramSpec);

    ASSERT_EQ(res, HCF_SUCCESS);

    HcfAsyKeyGeneratorBySpec *generator = nullptr;
    res = HcfAsyKeyGeneratorBySpecCreate(paramSpec, &generator);

    HcfKeyPair *keyPair = nullptr;
    res = generator->generateKeyPair(generator, &keyPair);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(keyPair, nullptr);

    HcfBigInteger retBigInt = { .data = nullptr, .len = 0 };
    AsyKeySpecItem item = ECC_G_Y_BN;

    res = keyPair->pubKey->getAsyKeySpecBigInteger(keyPair->pubKey, item, &retBigInt);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(retBigInt.data, nullptr);
    ASSERT_NE(retBigInt.len, 0);

    HcfFree(retBigInt.data);

    HcfObjDestroy(keyPair);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoEccAsyKeyGeneratorBySpecSubTwoTest, CryptoEccAsyKeyGeneratorBySpecSubTwoTest405_6, TestSize.Level0)
{
    HcfAsyKeyParamsSpec *paramSpec = nullptr;
    int32_t res = ConstructEcc224KeyPairParamsSpec(&paramSpec);

    ASSERT_EQ(res, HCF_SUCCESS);

    HcfAsyKeyGeneratorBySpec *generator = nullptr;
    res = HcfAsyKeyGeneratorBySpecCreate(paramSpec, &generator);

    HcfKeyPair *keyPair = nullptr;
    res = generator->generateKeyPair(generator, &keyPair);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(keyPair, nullptr);

    HcfBigInteger retBigInt = { .data = nullptr, .len = 0 };
    AsyKeySpecItem item = ECC_G_Y_BN;

    res = keyPair->priKey->getAsyKeySpecBigInteger(keyPair->priKey, item, &retBigInt);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(retBigInt.data, nullptr);
    ASSERT_NE(retBigInt.len, 0);

    HcfFree(retBigInt.data);

    HcfObjDestroy(keyPair);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoEccAsyKeyGeneratorBySpecSubTwoTest, CryptoEccAsyKeyGeneratorBySpecSubTwoTest405_7, TestSize.Level0)
{
    HcfAsyKeyParamsSpec *paramSpec = nullptr;
    int32_t res = ConstructEcc224KeyPairParamsSpec(&paramSpec);

    ASSERT_EQ(res, HCF_SUCCESS);

    HcfAsyKeyGeneratorBySpec *generator = nullptr;
    res = HcfAsyKeyGeneratorBySpecCreate(paramSpec, &generator);

    HcfPubKey *pubKey = nullptr;
    res = generator->generatePubKey(generator, &pubKey);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(pubKey, nullptr);

    HcfBigInteger retBigInt = { .data = nullptr, .len = 0 };
    AsyKeySpecItem item = ECC_G_Y_BN;

    res = pubKey->getAsyKeySpecBigInteger(pubKey, item, &retBigInt);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(retBigInt.data, nullptr);
    ASSERT_NE(retBigInt.len, 0);

    HcfFree(retBigInt.data);

    HcfObjDestroy(pubKey);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoEccAsyKeyGeneratorBySpecSubTwoTest, CryptoEccAsyKeyGeneratorBySpecSubTwoTest405_8, TestSize.Level0)
{
    HcfAsyKeyParamsSpec *paramSpec = nullptr;
    int32_t res = ConstructEcc224KeyPairParamsSpec(&paramSpec);

    ASSERT_EQ(res, HCF_SUCCESS);

    HcfAsyKeyGeneratorBySpec *generator = nullptr;
    res = HcfAsyKeyGeneratorBySpecCreate(paramSpec, &generator);

    HcfPriKey *priKey = nullptr;
    res = generator->generatePriKey(generator, &priKey);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(priKey, nullptr);

    HcfBigInteger retBigInt = { .data = nullptr, .len = 0 };
    AsyKeySpecItem item = ECC_G_Y_BN;

    res = priKey->getAsyKeySpecBigInteger(priKey, item, &retBigInt);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(retBigInt.data, nullptr);
    ASSERT_NE(retBigInt.len, 0);

    HcfFree(retBigInt.data);

    HcfObjDestroy(priKey);
    HcfObjDestroy(generator);
}

// for test:ECC_N_BN
HWTEST_F(CryptoEccAsyKeyGeneratorBySpecSubTwoTest, CryptoEccAsyKeyGeneratorBySpecSubTwoTest406_1, TestSize.Level0)
{
    HcfAsyKeyParamsSpec *paramSpec = nullptr;
    int32_t res = ConstructEcc224CommParamsSpec(&paramSpec);

    ASSERT_EQ(res, HCF_SUCCESS);

    HcfAsyKeyGeneratorBySpec *generator = nullptr;
    res = HcfAsyKeyGeneratorBySpecCreate(paramSpec, &generator);

    HcfKeyPair *keyPair = nullptr;
    res = generator->generateKeyPair(generator, &keyPair);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(keyPair, nullptr);

    HcfBigInteger retBigInt = { .data = nullptr, .len = 0 };
    AsyKeySpecItem item = ECC_N_BN;

    res = keyPair->pubKey->getAsyKeySpecBigInteger(keyPair->pubKey, item, &retBigInt);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(retBigInt.data, nullptr);
    ASSERT_NE(retBigInt.len, 0);

    HcfFree(retBigInt.data);

    HcfObjDestroy(keyPair);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoEccAsyKeyGeneratorBySpecSubTwoTest, CryptoEccAsyKeyGeneratorBySpecSubTwoTest406_2, TestSize.Level0)
{
    HcfAsyKeyParamsSpec *paramSpec = nullptr;
    int32_t res = ConstructEcc224CommParamsSpec(&paramSpec);

    ASSERT_EQ(res, HCF_SUCCESS);

    HcfAsyKeyGeneratorBySpec *generator = nullptr;
    res = HcfAsyKeyGeneratorBySpecCreate(paramSpec, &generator);

    HcfKeyPair *keyPair = nullptr;
    res = generator->generateKeyPair(generator, &keyPair);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(keyPair, nullptr);

    HcfBigInteger retBigInt = { .data = nullptr, .len = 0 };
    AsyKeySpecItem item = ECC_N_BN;

    res = keyPair->priKey->getAsyKeySpecBigInteger(keyPair->priKey, item, &retBigInt);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(retBigInt.data, nullptr);
    ASSERT_NE(retBigInt.len, 0);

    HcfFree(retBigInt.data);

    HcfObjDestroy(keyPair);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoEccAsyKeyGeneratorBySpecSubTwoTest, CryptoEccAsyKeyGeneratorBySpecSubTwoTest406_3, TestSize.Level0)
{
    HcfAsyKeyParamsSpec *paramSpec = nullptr;
    int32_t res = ConstructEcc224PubKeyParamsSpec(&paramSpec);

    ASSERT_EQ(res, HCF_SUCCESS);

    HcfAsyKeyGeneratorBySpec *generator = nullptr;
    res = HcfAsyKeyGeneratorBySpecCreate(paramSpec, &generator);

    HcfPubKey *pubKey = nullptr;
    res = generator->generatePubKey(generator, &pubKey);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(pubKey, nullptr);

    HcfBigInteger retBigInt = { .data = nullptr, .len = 0 };
    AsyKeySpecItem item = ECC_N_BN;

    res = pubKey->getAsyKeySpecBigInteger(pubKey, item, &retBigInt);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(retBigInt.data, nullptr);
    ASSERT_NE(retBigInt.len, 0);

    HcfFree(retBigInt.data);

    HcfObjDestroy(pubKey);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoEccAsyKeyGeneratorBySpecSubTwoTest, CryptoEccAsyKeyGeneratorBySpecSubTwoTest406_4, TestSize.Level0)
{
    HcfAsyKeyParamsSpec *paramSpec = nullptr;
    int32_t res = ConstructEcc224PriKeyParamsSpec(&paramSpec);

    ASSERT_EQ(res, HCF_SUCCESS);

    HcfAsyKeyGeneratorBySpec *generator = nullptr;
    res = HcfAsyKeyGeneratorBySpecCreate(paramSpec, &generator);

    HcfPriKey *priKey = nullptr;
    res = generator->generatePriKey(generator, &priKey);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(priKey, nullptr);

    HcfBigInteger retBigInt = { .data = nullptr, .len = 0 };
    AsyKeySpecItem item = ECC_N_BN;

    res = priKey->getAsyKeySpecBigInteger(priKey, item, &retBigInt);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(retBigInt.data, nullptr);
    ASSERT_NE(retBigInt.len, 0);

    HcfFree(retBigInt.data);

    HcfObjDestroy(priKey);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoEccAsyKeyGeneratorBySpecSubTwoTest, CryptoEccAsyKeyGeneratorBySpecSubTwoTest406_5, TestSize.Level0)
{
    HcfAsyKeyParamsSpec *paramSpec = nullptr;
    int32_t res = ConstructEcc224KeyPairParamsSpec(&paramSpec);

    ASSERT_EQ(res, HCF_SUCCESS);

    HcfAsyKeyGeneratorBySpec *generator = nullptr;
    res = HcfAsyKeyGeneratorBySpecCreate(paramSpec, &generator);

    HcfKeyPair *keyPair = nullptr;
    res = generator->generateKeyPair(generator, &keyPair);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(keyPair, nullptr);

    HcfBigInteger retBigInt = { .data = nullptr, .len = 0 };
    AsyKeySpecItem item = ECC_N_BN;

    res = keyPair->pubKey->getAsyKeySpecBigInteger(keyPair->pubKey, item, &retBigInt);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(retBigInt.data, nullptr);
    ASSERT_NE(retBigInt.len, 0);

    HcfFree(retBigInt.data);

    HcfObjDestroy(keyPair);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoEccAsyKeyGeneratorBySpecSubTwoTest, CryptoEccAsyKeyGeneratorBySpecSubTwoTest406_6, TestSize.Level0)
{
    HcfAsyKeyParamsSpec *paramSpec = nullptr;
    int32_t res = ConstructEcc224KeyPairParamsSpec(&paramSpec);

    ASSERT_EQ(res, HCF_SUCCESS);

    HcfAsyKeyGeneratorBySpec *generator = nullptr;
    res = HcfAsyKeyGeneratorBySpecCreate(paramSpec, &generator);

    HcfKeyPair *keyPair = nullptr;
    res = generator->generateKeyPair(generator, &keyPair);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(keyPair, nullptr);

    HcfBigInteger retBigInt = { .data = nullptr, .len = 0 };
    AsyKeySpecItem item = ECC_N_BN;

    res = keyPair->priKey->getAsyKeySpecBigInteger(keyPair->priKey, item, &retBigInt);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(retBigInt.data, nullptr);
    ASSERT_NE(retBigInt.len, 0);

    HcfFree(retBigInt.data);

    HcfObjDestroy(keyPair);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoEccAsyKeyGeneratorBySpecSubTwoTest, CryptoEccAsyKeyGeneratorBySpecSubTwoTest406_7, TestSize.Level0)
{
    HcfAsyKeyParamsSpec *paramSpec = nullptr;
    int32_t res = ConstructEcc224KeyPairParamsSpec(&paramSpec);

    ASSERT_EQ(res, HCF_SUCCESS);

    HcfAsyKeyGeneratorBySpec *generator = nullptr;
    res = HcfAsyKeyGeneratorBySpecCreate(paramSpec, &generator);

    HcfPubKey *pubKey = nullptr;
    res = generator->generatePubKey(generator, &pubKey);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(pubKey, nullptr);

    HcfBigInteger retBigInt = { .data = nullptr, .len = 0 };
    AsyKeySpecItem item = ECC_N_BN;

    res = pubKey->getAsyKeySpecBigInteger(pubKey, item, &retBigInt);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(retBigInt.data, nullptr);
    ASSERT_NE(retBigInt.len, 0);

    HcfFree(retBigInt.data);

    HcfObjDestroy(pubKey);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoEccAsyKeyGeneratorBySpecSubTwoTest, CryptoEccAsyKeyGeneratorBySpecSubTwoTest406_8, TestSize.Level0)
{
    HcfAsyKeyParamsSpec *paramSpec = nullptr;
    int32_t res = ConstructEcc224KeyPairParamsSpec(&paramSpec);

    ASSERT_EQ(res, HCF_SUCCESS);

    HcfAsyKeyGeneratorBySpec *generator = nullptr;
    res = HcfAsyKeyGeneratorBySpecCreate(paramSpec, &generator);

    HcfPriKey *priKey = nullptr;
    res = generator->generatePriKey(generator, &priKey);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(priKey, nullptr);

    HcfBigInteger retBigInt = { .data = nullptr, .len = 0 };
    AsyKeySpecItem item = ECC_N_BN;

    res = priKey->getAsyKeySpecBigInteger(priKey, item, &retBigInt);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(retBigInt.data, nullptr);
    ASSERT_NE(retBigInt.len, 0);

    HcfFree(retBigInt.data);

    HcfObjDestroy(priKey);
    HcfObjDestroy(generator);
}

// for test:ECC_H_INT
HWTEST_F(CryptoEccAsyKeyGeneratorBySpecSubTwoTest, CryptoEccAsyKeyGeneratorBySpecSubTwoTest407_1, TestSize.Level0)
{
    HcfAsyKeyParamsSpec *paramSpec = nullptr;
    int32_t res = ConstructEcc224CommParamsSpec(&paramSpec);

    ASSERT_EQ(res, HCF_SUCCESS);

    HcfAsyKeyGeneratorBySpec *generator = nullptr;
    res = HcfAsyKeyGeneratorBySpecCreate(paramSpec, &generator);

    HcfKeyPair *keyPair = nullptr;
    res = generator->generateKeyPair(generator, &keyPair);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(keyPair, nullptr);

    int retInt = 0;
    AsyKeySpecItem item = ECC_H_INT;

    res = keyPair->pubKey->getAsyKeySpecInt(keyPair->pubKey, item, &retInt);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(retInt, 0);

    HcfObjDestroy(keyPair);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoEccAsyKeyGeneratorBySpecSubTwoTest, CryptoEccAsyKeyGeneratorBySpecSubTwoTest407_2, TestSize.Level0)
{
    HcfAsyKeyParamsSpec *paramSpec = nullptr;
    int32_t res = ConstructEcc224CommParamsSpec(&paramSpec);

    ASSERT_EQ(res, HCF_SUCCESS);

    HcfAsyKeyGeneratorBySpec *generator = nullptr;
    res = HcfAsyKeyGeneratorBySpecCreate(paramSpec, &generator);

    HcfKeyPair *keyPair = nullptr;
    res = generator->generateKeyPair(generator, &keyPair);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(keyPair, nullptr);

    int retInt = 0;
    AsyKeySpecItem item = ECC_H_INT;

    res = keyPair->priKey->getAsyKeySpecInt(keyPair->priKey, item, &retInt);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(retInt, 0);

    HcfObjDestroy(keyPair);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoEccAsyKeyGeneratorBySpecSubTwoTest, CryptoEccAsyKeyGeneratorBySpecSubTwoTest407_3, TestSize.Level0)
{
    HcfAsyKeyParamsSpec *paramSpec = nullptr;
    int32_t res = ConstructEcc224PubKeyParamsSpec(&paramSpec);

    ASSERT_EQ(res, HCF_SUCCESS);

    HcfAsyKeyGeneratorBySpec *generator = nullptr;
    res = HcfAsyKeyGeneratorBySpecCreate(paramSpec, &generator);

    HcfPubKey *pubKey = nullptr;
    res = generator->generatePubKey(generator, &pubKey);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(pubKey, nullptr);

    int retInt = 0;
    AsyKeySpecItem item = ECC_H_INT;

    res = pubKey->getAsyKeySpecInt(pubKey, item, &retInt);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(retInt, 0);

    HcfObjDestroy(pubKey);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoEccAsyKeyGeneratorBySpecSubTwoTest, CryptoEccAsyKeyGeneratorBySpecSubTwoTest407_4, TestSize.Level0)
{
    HcfAsyKeyParamsSpec *paramSpec = nullptr;
    int32_t res = ConstructEcc224PriKeyParamsSpec(&paramSpec);

    ASSERT_EQ(res, HCF_SUCCESS);

    HcfAsyKeyGeneratorBySpec *generator = nullptr;
    res = HcfAsyKeyGeneratorBySpecCreate(paramSpec, &generator);

    HcfPriKey *priKey = nullptr;
    res = generator->generatePriKey(generator, &priKey);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(priKey, nullptr);

    int retInt = 0;
    AsyKeySpecItem item = ECC_H_INT;

    res = priKey->getAsyKeySpecInt(priKey, item, &retInt);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(retInt, 0);

    HcfObjDestroy(priKey);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoEccAsyKeyGeneratorBySpecSubTwoTest, CryptoEccAsyKeyGeneratorBySpecSubTwoTest407_5, TestSize.Level0)
{
    HcfAsyKeyParamsSpec *paramSpec = nullptr;
    int32_t res = ConstructEcc224KeyPairParamsSpec(&paramSpec);

    ASSERT_EQ(res, HCF_SUCCESS);

    HcfAsyKeyGeneratorBySpec *generator = nullptr;
    res = HcfAsyKeyGeneratorBySpecCreate(paramSpec, &generator);

    HcfKeyPair *keyPair = nullptr;
    res = generator->generateKeyPair(generator, &keyPair);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(keyPair, nullptr);

    int retInt = 0;
    AsyKeySpecItem item = ECC_H_INT;

    res = keyPair->pubKey->getAsyKeySpecInt(keyPair->pubKey, item, &retInt);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(retInt, 0);

    HcfObjDestroy(keyPair);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoEccAsyKeyGeneratorBySpecSubTwoTest, CryptoEccAsyKeyGeneratorBySpecSubTwoTest407_6, TestSize.Level0)
{
    HcfAsyKeyParamsSpec *paramSpec = nullptr;
    int32_t res = ConstructEcc224KeyPairParamsSpec(&paramSpec);

    ASSERT_EQ(res, HCF_SUCCESS);

    HcfAsyKeyGeneratorBySpec *generator = nullptr;
    res = HcfAsyKeyGeneratorBySpecCreate(paramSpec, &generator);

    HcfKeyPair *keyPair = nullptr;
    res = generator->generateKeyPair(generator, &keyPair);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(keyPair, nullptr);

    int retInt = 0;
    AsyKeySpecItem item = ECC_H_INT;

    res = keyPair->priKey->getAsyKeySpecInt(keyPair->priKey, item, &retInt);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(retInt, 0);

    HcfObjDestroy(keyPair);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoEccAsyKeyGeneratorBySpecSubTwoTest, CryptoEccAsyKeyGeneratorBySpecSubTwoTest407_7, TestSize.Level0)
{
    HcfAsyKeyParamsSpec *paramSpec = nullptr;
    int32_t res = ConstructEcc224KeyPairParamsSpec(&paramSpec);

    ASSERT_EQ(res, HCF_SUCCESS);

    HcfAsyKeyGeneratorBySpec *generator = nullptr;
    res = HcfAsyKeyGeneratorBySpecCreate(paramSpec, &generator);

    HcfPubKey *pubKey = nullptr;
    res = generator->generatePubKey(generator, &pubKey);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(pubKey, nullptr);

    int retInt = 0;
    AsyKeySpecItem item = ECC_H_INT;

    res = pubKey->getAsyKeySpecInt(pubKey, item, &retInt);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(retInt, 0);

    HcfObjDestroy(pubKey);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoEccAsyKeyGeneratorBySpecSubTwoTest, CryptoEccAsyKeyGeneratorBySpecSubTwoTest407_8, TestSize.Level0)
{
    HcfAsyKeyParamsSpec *paramSpec = nullptr;
    int32_t res = ConstructEcc224KeyPairParamsSpec(&paramSpec);

    ASSERT_EQ(res, HCF_SUCCESS);

    HcfAsyKeyGeneratorBySpec *generator = nullptr;
    res = HcfAsyKeyGeneratorBySpecCreate(paramSpec, &generator);

    HcfPriKey *priKey = nullptr;
    res = generator->generatePriKey(generator, &priKey);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(priKey, nullptr);

    int retInt = 0;
    AsyKeySpecItem item = ECC_H_INT;

    res = priKey->getAsyKeySpecInt(priKey, item, &retInt);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(retInt, 0);

    HcfObjDestroy(priKey);
    HcfObjDestroy(generator);
}

// for test:ECC_FIELD_SIZE_INT
HWTEST_F(CryptoEccAsyKeyGeneratorBySpecSubTwoTest, CryptoEccAsyKeyGeneratorBySpecSubTwoTest408_1, TestSize.Level0)
{
    HcfAsyKeyParamsSpec *paramSpec = nullptr;
    int32_t res = ConstructEcc224CommParamsSpec(&paramSpec);

    ASSERT_EQ(res, HCF_SUCCESS);

    HcfAsyKeyGeneratorBySpec *generator = nullptr;
    res = HcfAsyKeyGeneratorBySpecCreate(paramSpec, &generator);

    HcfKeyPair *keyPair = nullptr;
    res = generator->generateKeyPair(generator, &keyPair);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(keyPair, nullptr);

    int retInt = 0;
    AsyKeySpecItem item = ECC_FIELD_SIZE_INT;

    res = keyPair->pubKey->getAsyKeySpecInt(keyPair->pubKey, item, &retInt);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(retInt, 0);

    HcfObjDestroy(keyPair);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoEccAsyKeyGeneratorBySpecSubTwoTest, CryptoEccAsyKeyGeneratorBySpecSubTwoTest408_2, TestSize.Level0)
{
    HcfAsyKeyParamsSpec *paramSpec = nullptr;
    int32_t res = ConstructEcc224CommParamsSpec(&paramSpec);

    ASSERT_EQ(res, HCF_SUCCESS);

    HcfAsyKeyGeneratorBySpec *generator = nullptr;
    res = HcfAsyKeyGeneratorBySpecCreate(paramSpec, &generator);

    HcfKeyPair *keyPair = nullptr;
    res = generator->generateKeyPair(generator, &keyPair);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(keyPair, nullptr);

    int retInt = 0;
    AsyKeySpecItem item = ECC_FIELD_SIZE_INT;

    res = keyPair->priKey->getAsyKeySpecInt(keyPair->priKey, item, &retInt);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(retInt, 0);

    HcfObjDestroy(keyPair);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoEccAsyKeyGeneratorBySpecSubTwoTest, CryptoEccAsyKeyGeneratorBySpecSubTwoTest408_3, TestSize.Level0)
{
    HcfAsyKeyParamsSpec *paramSpec = nullptr;
    int32_t res = ConstructEcc224PubKeyParamsSpec(&paramSpec);

    ASSERT_EQ(res, HCF_SUCCESS);

    HcfAsyKeyGeneratorBySpec *generator = nullptr;
    res = HcfAsyKeyGeneratorBySpecCreate(paramSpec, &generator);

    HcfPubKey *pubKey = nullptr;
    res = generator->generatePubKey(generator, &pubKey);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(pubKey, nullptr);

    int retInt = 0;
    AsyKeySpecItem item = ECC_FIELD_SIZE_INT;

    res = pubKey->getAsyKeySpecInt(pubKey, item, &retInt);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(retInt, 0);

    HcfObjDestroy(pubKey);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoEccAsyKeyGeneratorBySpecSubTwoTest, CryptoEccAsyKeyGeneratorBySpecSubTwoTest408_4, TestSize.Level0)
{
    HcfAsyKeyParamsSpec *paramSpec = nullptr;
    int32_t res = ConstructEcc224PriKeyParamsSpec(&paramSpec);

    ASSERT_EQ(res, HCF_SUCCESS);

    HcfAsyKeyGeneratorBySpec *generator = nullptr;
    res = HcfAsyKeyGeneratorBySpecCreate(paramSpec, &generator);

    HcfPriKey *priKey = nullptr;
    res = generator->generatePriKey(generator, &priKey);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(priKey, nullptr);

    int retInt = 0;
    AsyKeySpecItem item = ECC_FIELD_SIZE_INT;

    res = priKey->getAsyKeySpecInt(priKey, item, &retInt);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(retInt, 0);

    HcfObjDestroy(priKey);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoEccAsyKeyGeneratorBySpecSubTwoTest, CryptoEccAsyKeyGeneratorBySpecSubTwoTest408_5, TestSize.Level0)
{
    HcfAsyKeyParamsSpec *paramSpec = nullptr;
    int32_t res = ConstructEcc224KeyPairParamsSpec(&paramSpec);

    ASSERT_EQ(res, HCF_SUCCESS);

    HcfAsyKeyGeneratorBySpec *generator = nullptr;
    res = HcfAsyKeyGeneratorBySpecCreate(paramSpec, &generator);

    HcfKeyPair *keyPair = nullptr;
    res = generator->generateKeyPair(generator, &keyPair);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(keyPair, nullptr);

    int retInt = 0;
    AsyKeySpecItem item = ECC_FIELD_SIZE_INT;

    res = keyPair->pubKey->getAsyKeySpecInt(keyPair->pubKey, item, &retInt);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(retInt, 0);

    HcfObjDestroy(keyPair);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoEccAsyKeyGeneratorBySpecSubTwoTest, CryptoEccAsyKeyGeneratorBySpecSubTwoTest408_6, TestSize.Level0)
{
    HcfAsyKeyParamsSpec *paramSpec = nullptr;
    int32_t res = ConstructEcc224KeyPairParamsSpec(&paramSpec);

    ASSERT_EQ(res, HCF_SUCCESS);

    HcfAsyKeyGeneratorBySpec *generator = nullptr;
    res = HcfAsyKeyGeneratorBySpecCreate(paramSpec, &generator);

    HcfKeyPair *keyPair = nullptr;
    res = generator->generateKeyPair(generator, &keyPair);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(keyPair, nullptr);

    int retInt = 0;
    AsyKeySpecItem item = ECC_FIELD_SIZE_INT;

    res = keyPair->priKey->getAsyKeySpecInt(keyPair->priKey, item, &retInt);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(retInt, 0);

    HcfObjDestroy(keyPair);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoEccAsyKeyGeneratorBySpecSubTwoTest, CryptoEccAsyKeyGeneratorBySpecSubTwoTest408_7, TestSize.Level0)
{
    HcfAsyKeyParamsSpec *paramSpec = nullptr;
    int32_t res = ConstructEcc224KeyPairParamsSpec(&paramSpec);

    ASSERT_EQ(res, HCF_SUCCESS);

    HcfAsyKeyGeneratorBySpec *generator = nullptr;
    res = HcfAsyKeyGeneratorBySpecCreate(paramSpec, &generator);

    HcfPubKey *pubKey = nullptr;
    res = generator->generatePubKey(generator, &pubKey);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(pubKey, nullptr);

    int retInt = 0;
    AsyKeySpecItem item = ECC_FIELD_SIZE_INT;

    res = pubKey->getAsyKeySpecInt(pubKey, item, &retInt);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(retInt, 0);

    HcfObjDestroy(pubKey);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoEccAsyKeyGeneratorBySpecSubTwoTest, CryptoEccAsyKeyGeneratorBySpecSubTwoTest408_8, TestSize.Level0)
{
    HcfAsyKeyParamsSpec *paramSpec = nullptr;
    int32_t res = ConstructEcc224KeyPairParamsSpec(&paramSpec);

    ASSERT_EQ(res, HCF_SUCCESS);

    HcfAsyKeyGeneratorBySpec *generator = nullptr;
    res = HcfAsyKeyGeneratorBySpecCreate(paramSpec, &generator);

    HcfPriKey *priKey = nullptr;
    res = generator->generatePriKey(generator, &priKey);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(priKey, nullptr);

    int retInt = 0;
    AsyKeySpecItem item = ECC_FIELD_SIZE_INT;

    res = priKey->getAsyKeySpecInt(priKey, item, &retInt);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(retInt, 0);

    HcfObjDestroy(priKey);
    HcfObjDestroy(generator);
}
}
