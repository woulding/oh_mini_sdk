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
#include "securec.h"

#include "asy_key_generator.h"
#include "asy_key_generator_spi.h"
#include "blob.h"
#include "detailed_rsa_key_params.h"
#include "memory.h"
#include "openssl_class.h"
#include "openssl_common.h"
#include "rsa_common_param_spec.h"

using namespace std;
using namespace testing::ext;

namespace {
class CryptoRsa8192AsyKeyGeneratorBySpecTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp();
    void TearDown();
};

void CryptoRsa8192AsyKeyGeneratorBySpecTest::SetUpTestCase() {}

void CryptoRsa8192AsyKeyGeneratorBySpecTest::TearDownTestCase() {}

void CryptoRsa8192AsyKeyGeneratorBySpecTest::SetUp() {}

void CryptoRsa8192AsyKeyGeneratorBySpecTest::TearDown() {}

// basic generator create test
HWTEST_F(CryptoRsa8192AsyKeyGeneratorBySpecTest, CryptoRsa8192AsyKeyGeneratorBySpecTest481, TestSize.Level0)
{
    HcfRsaCommParamsSpec rsaCommSpec = {};
    unsigned char dataN[RSA_8192_N_BYTE_SIZE] = {0};
    GenerateRsa8192CorrectCommonKeySpec(dataN, &rsaCommSpec);

    HcfAsyKeyGeneratorBySpec *generator = nullptr;
    HcfResult res = HcfAsyKeyGeneratorBySpecCreate(reinterpret_cast<HcfAsyKeyParamsSpec *>(&rsaCommSpec), &generator);
    EXPECT_NE(res, HCF_SUCCESS);
    EXPECT_EQ(generator, nullptr);

    HcfObjDestroy(generator);
}

HWTEST_F(CryptoRsa8192AsyKeyGeneratorBySpecTest, CryptoRsa8192AsyKeyGeneratorBySpecTest482, TestSize.Level0)
{
    HcfRsaPubKeyParamsSpec rsaPubKeySpec = {};
    unsigned char dataN[RSA_8192_N_BYTE_SIZE] = {0};
    unsigned char dataE[RSA_8192_E_BYTE_SIZE] = {0};
    GenerateRsa8192CorrectPubKeySpec(dataN, dataE, &rsaPubKeySpec);

    HcfAsyKeyGeneratorBySpec *generator = nullptr;
    HcfResult res = HcfAsyKeyGeneratorBySpecCreate(reinterpret_cast<HcfAsyKeyParamsSpec *>(&rsaPubKeySpec), &generator);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(generator, nullptr);

    HcfObjDestroy(generator);
}

HWTEST_F(CryptoRsa8192AsyKeyGeneratorBySpecTest, CryptoRsa8192AsyKeyGeneratorBySpecTest483, TestSize.Level0)
{
    HcfRsaKeyPairParamsSpec rsaPairSpec = {};
    unsigned char dataN[RSA_8192_N_BYTE_SIZE] = {0};
    unsigned char dataE[RSA_8192_E_BYTE_SIZE] = {0};
    unsigned char dataD[RSA_8192_D_BYTE_SIZE] = {0};
    GenerateRsa8192CorrectKeyPairSpec(dataN, dataE, dataD, &rsaPairSpec);

    HcfAsyKeyGeneratorBySpec *generator = nullptr;
    HcfResult res = HcfAsyKeyGeneratorBySpecCreate(reinterpret_cast<HcfAsyKeyParamsSpec *>(&rsaPairSpec), &generator);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(generator, nullptr);

    HcfObjDestroy(generator);
}

// test generator by spec genrate key funciton not null
HWTEST_F(CryptoRsa8192AsyKeyGeneratorBySpecTest, CryptoRsa8192AsyKeyGeneratorBySpecTest484, TestSize.Level0)
{
    HcfRsaKeyPairParamsSpec rsaPairSpec = {};
    unsigned char dataN[RSA_8192_N_BYTE_SIZE] = {0};
    unsigned char dataE[RSA_8192_E_BYTE_SIZE] = {0};
    unsigned char dataD[RSA_8192_D_BYTE_SIZE] = {0};
    GenerateRsa8192CorrectKeyPairSpec(dataN, dataE, dataD, &rsaPairSpec);

    HcfAsyKeyGeneratorBySpec *generator = nullptr;
    HcfResult res = HcfAsyKeyGeneratorBySpecCreate(reinterpret_cast<HcfAsyKeyParamsSpec *>(&rsaPairSpec), &generator);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(generator, nullptr);

    EXPECT_EQ(CheckGeneratorBySpecKeyFunc(generator), true);
    HcfObjDestroy(generator);
}

// test generator by spec get class string test
HWTEST_F(CryptoRsa8192AsyKeyGeneratorBySpecTest, CryptoRsa8192AsyKeyGeneratorBySpecTest485, TestSize.Level0)
{
    HcfRsaPubKeyParamsSpec rsaPubKeySpec = {};
    unsigned char dataN[RSA_8192_N_BYTE_SIZE] = {0};
    unsigned char dataE[RSA_8192_E_BYTE_SIZE] = {0};
    GenerateRsa8192CorrectPubKeySpec(dataN, dataE, &rsaPubKeySpec);

    HcfAsyKeyGeneratorBySpec *generator = nullptr;
    HcfResult res = HcfAsyKeyGeneratorBySpecCreate(reinterpret_cast<HcfAsyKeyParamsSpec *>(&rsaPubKeySpec), &generator);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(generator, nullptr);

    const char *generatorBySpecClass = generator->base.getClass();
    EXPECT_STREQ(generatorBySpecClass, g_asyKeyGeneratorBySpecClass);
    HcfObjDestroy(generator);
}

// test generator by spec get getAlgName string test
HWTEST_F(CryptoRsa8192AsyKeyGeneratorBySpecTest, CryptoRsa8192AsyKeyGeneratorBySpecTest486, TestSize.Level0)
{
    HcfRsaPubKeyParamsSpec rsaPubKeySpec = {};
    unsigned char dataN[RSA_8192_N_BYTE_SIZE] = {0};
    unsigned char dataE[RSA_8192_E_BYTE_SIZE] = {0};
    GenerateRsa8192CorrectPubKeySpec(dataN, dataE, &rsaPubKeySpec);

    HcfAsyKeyGeneratorBySpec *generator = nullptr;
    HcfResult res = HcfAsyKeyGeneratorBySpecCreate(reinterpret_cast<HcfAsyKeyParamsSpec *>(&rsaPubKeySpec), &generator);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(generator, nullptr);

    const char *generatorBySpecAlgName = generator->getAlgName(generator);
    EXPECT_STREQ(generatorBySpecAlgName, g_rsaAlgName);
    HcfObjDestroy(generator);
}

// test generator by spec basic destroy
HWTEST_F(CryptoRsa8192AsyKeyGeneratorBySpecTest, CryptoRsa8192AsyKeyGeneratorBySpecTest487, TestSize.Level0)
{
    HcfRsaPubKeyParamsSpec rsaPubKeySpec = {};
    unsigned char dataN[RSA_8192_N_BYTE_SIZE] = {0};
    unsigned char dataE[RSA_8192_E_BYTE_SIZE] = {0};
    GenerateRsa8192CorrectPubKeySpec(dataN, dataE, &rsaPubKeySpec);


    HcfAsyKeyGeneratorBySpec *generator = nullptr;
    HcfResult res = HcfAsyKeyGeneratorBySpecCreate(reinterpret_cast<HcfAsyKeyParamsSpec *>(&rsaPubKeySpec), &generator);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(generator, nullptr);

    generator->base.destroy(&(generator->base));
}
// test correct spec and generate key pair, pri key, and pub key.
// pub spec
HWTEST_F(CryptoRsa8192AsyKeyGeneratorBySpecTest, CryptoRsa8192AsyKeyGeneratorBySpecTest488, TestSize.Level0)
{
    HcfRsaPubKeyParamsSpec rsaPubKeySpec = {};
    unsigned char dataN[RSA_8192_N_BYTE_SIZE] = {0};
    unsigned char dataE[RSA_8192_E_BYTE_SIZE] = {0};
    GenerateRsa8192CorrectPubKeySpec(dataN, dataE, &rsaPubKeySpec);

    HcfAsyKeyGeneratorBySpec *generator = nullptr;
    HcfResult res = HcfAsyKeyGeneratorBySpecCreate(reinterpret_cast<HcfAsyKeyParamsSpec *>(&rsaPubKeySpec), &generator);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(generator, nullptr);

    EXPECT_EQ(CheckGeneratorBySpecKeyFunc(generator), true);
    HcfKeyPair *keyPair = nullptr;
    res = generator->generateKeyPair(generator, &keyPair);
    EXPECT_EQ(res, HCF_INVALID_PARAMS);
    EXPECT_EQ(keyPair, nullptr);

    HcfObjDestroy(keyPair);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoRsa8192AsyKeyGeneratorBySpecTest, CryptoRsa8192AsyKeyGeneratorBySpecTest489, TestSize.Level0)
{
    HcfRsaPubKeyParamsSpec rsaPubKeySpec = {};
    unsigned char dataN[RSA_8192_N_BYTE_SIZE] = {0};
    unsigned char dataE[RSA_8192_E_BYTE_SIZE] = {0};
    GenerateRsa8192CorrectPubKeySpec(dataN, dataE, &rsaPubKeySpec);

    HcfAsyKeyGeneratorBySpec *generator = nullptr;
    HcfResult res = HcfAsyKeyGeneratorBySpecCreate(reinterpret_cast<HcfAsyKeyParamsSpec *>(&rsaPubKeySpec), &generator);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(generator, nullptr);

    EXPECT_EQ(CheckGeneratorBySpecKeyFunc(generator), true);
    HcfPubKey *pubKey = nullptr;
    res = generator->generatePubKey(generator, &pubKey);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(pubKey, nullptr);

    HcfObjDestroy(pubKey);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoRsa8192AsyKeyGeneratorBySpecTest, CryptoRsa8192AsyKeyGeneratorBySpecTest490, TestSize.Level0)
{
    HcfRsaPubKeyParamsSpec rsaPubKeySpec = {};
    unsigned char dataN[RSA_8192_N_BYTE_SIZE] = {0};
    unsigned char dataE[RSA_8192_E_BYTE_SIZE] = {0};
    GenerateRsa8192CorrectPubKeySpec(dataN, dataE, &rsaPubKeySpec);

    HcfAsyKeyGeneratorBySpec *generator = nullptr;
    HcfResult res = HcfAsyKeyGeneratorBySpecCreate(reinterpret_cast<HcfAsyKeyParamsSpec *>(&rsaPubKeySpec), &generator);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(generator, nullptr);

    EXPECT_EQ(CheckGeneratorBySpecKeyFunc(generator), true);
    HcfPriKey *priKey = nullptr;
    res = generator->generatePriKey(generator, &priKey);
    EXPECT_EQ(res, HCF_INVALID_PARAMS);
    EXPECT_EQ(priKey, nullptr);

    HcfObjDestroy(priKey);
    HcfObjDestroy(generator);
}

// key pair spec
HWTEST_F(CryptoRsa8192AsyKeyGeneratorBySpecTest, CryptoRsa8192AsyKeyGeneratorBySpecTest491, TestSize.Level0)
{
    HcfRsaKeyPairParamsSpec rsaPairSpec = {};
    unsigned char dataN[RSA_8192_N_BYTE_SIZE] = {0};
    unsigned char dataE[RSA_8192_E_BYTE_SIZE] = {0};
    unsigned char dataD[RSA_8192_D_BYTE_SIZE] = {0};
    GenerateRsa8192CorrectKeyPairSpec(dataN, dataE, dataD, &rsaPairSpec);

    HcfAsyKeyGeneratorBySpec *generator = nullptr;
    HcfResult res = HcfAsyKeyGeneratorBySpecCreate(reinterpret_cast<HcfAsyKeyParamsSpec *>(&rsaPairSpec), &generator);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(generator, nullptr);

    EXPECT_EQ(CheckGeneratorBySpecKeyFunc(generator), true);
    HcfKeyPair *keyPair = nullptr;
    res = generator->generateKeyPair(generator, &keyPair);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(keyPair, nullptr);

    HcfObjDestroy(keyPair);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoRsa8192AsyKeyGeneratorBySpecTest, CryptoRsa8192AsyKeyGeneratorBySpecTest492, TestSize.Level0)
{
    HcfRsaKeyPairParamsSpec rsaPairSpec = {};
    unsigned char dataN[RSA_8192_N_BYTE_SIZE] = {0};
    unsigned char dataE[RSA_8192_E_BYTE_SIZE] = {0};
    unsigned char dataD[RSA_8192_D_BYTE_SIZE] = {0};
    GenerateRsa8192CorrectKeyPairSpec(dataN, dataE, dataD, &rsaPairSpec);

    HcfAsyKeyGeneratorBySpec *generator = nullptr;
    HcfResult res = HcfAsyKeyGeneratorBySpecCreate(reinterpret_cast<HcfAsyKeyParamsSpec *>(&rsaPairSpec), &generator);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(generator, nullptr);

    EXPECT_EQ(CheckGeneratorBySpecKeyFunc(generator), true);
    HcfPubKey *pubKey = nullptr;
    res = generator->generatePubKey(generator, &pubKey);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(pubKey, nullptr);

    HcfObjDestroy(pubKey);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoRsa8192AsyKeyGeneratorBySpecTest, CryptoRsa8192AsyKeyGeneratorBySpecTest493, TestSize.Level0)
{
    HcfRsaKeyPairParamsSpec rsaPairSpec = {};
    unsigned char dataN[RSA_8192_N_BYTE_SIZE] = {0};
    unsigned char dataE[RSA_8192_E_BYTE_SIZE] = {0};
    unsigned char dataD[RSA_8192_D_BYTE_SIZE] = {0};
    GenerateRsa8192CorrectKeyPairSpec(dataN, dataE, dataD, &rsaPairSpec);

    HcfAsyKeyGeneratorBySpec *generator = nullptr;
    HcfResult res = HcfAsyKeyGeneratorBySpecCreate(reinterpret_cast<HcfAsyKeyParamsSpec *>(&rsaPairSpec), &generator);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(generator, nullptr);

    EXPECT_EQ(CheckGeneratorBySpecKeyFunc(generator), true);
    HcfPriKey *priKey = nullptr;
    res = generator->generatePriKey(generator, &priKey);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(priKey, nullptr);

    HcfObjDestroy(priKey);
    HcfObjDestroy(generator);
}

// check normal key function from key pairs of key pair spec
HWTEST_F(CryptoRsa8192AsyKeyGeneratorBySpecTest, CryptoRsa8192AsyKeyGeneratorBySpecTest494, TestSize.Level0)
{
    HcfRsaKeyPairParamsSpec rsaPairSpec = {};
    unsigned char dataN[RSA_8192_N_BYTE_SIZE] = {0};
    unsigned char dataE[RSA_8192_E_BYTE_SIZE] = {0};
    unsigned char dataD[RSA_8192_D_BYTE_SIZE] = {0};
    GenerateRsa8192CorrectKeyPairSpec(dataN, dataE, dataD, &rsaPairSpec);

    HcfAsyKeyGeneratorBySpec *generator = nullptr;
    HcfResult res = HcfAsyKeyGeneratorBySpecCreate(reinterpret_cast<HcfAsyKeyParamsSpec *>(&rsaPairSpec), &generator);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(generator, nullptr);

    EXPECT_EQ(CheckGeneratorBySpecKeyFunc(generator), true);
    HcfKeyPair *keyPair = nullptr;
    res = generator->generateKeyPair(generator, &keyPair);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(keyPair, nullptr);

    const char *keyPairClassName = keyPair->base.getClass();
    EXPECT_STREQ(keyPairClassName, OPENSSL_RSA_KEYPAIR_CLASS);

    HcfObjDestroy(keyPair);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoRsa8192AsyKeyGeneratorBySpecTest, CryptoRsa8192AsyKeyGeneratorBySpecTest495, TestSize.Level0)
{
    HcfRsaKeyPairParamsSpec rsaPairSpec = {};
    unsigned char dataN[RSA_8192_N_BYTE_SIZE] = {0};
    unsigned char dataE[RSA_8192_E_BYTE_SIZE] = {0};
    unsigned char dataD[RSA_8192_D_BYTE_SIZE] = {0};
    GenerateRsa8192CorrectKeyPairSpec(dataN, dataE, dataD, &rsaPairSpec);

    HcfAsyKeyGeneratorBySpec *generator = nullptr;
    HcfResult res = HcfAsyKeyGeneratorBySpecCreate(reinterpret_cast<HcfAsyKeyParamsSpec *>(&rsaPairSpec), &generator);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(generator, nullptr);

    EXPECT_EQ(CheckGeneratorBySpecKeyFunc(generator), true);
    HcfKeyPair *keyPair = nullptr;
    res = generator->generateKeyPair(generator, &keyPair);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(keyPair, nullptr);

    keyPair->base.destroy(&(keyPair->base));
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoRsa8192AsyKeyGeneratorBySpecTest, CryptoRsa8192AsyKeyGeneratorBySpecTest496, TestSize.Level0)
{
    HcfRsaKeyPairParamsSpec rsaPairSpec = {};
    unsigned char dataN[RSA_8192_N_BYTE_SIZE] = {0};
    unsigned char dataE[RSA_8192_E_BYTE_SIZE] = {0};
    unsigned char dataD[RSA_8192_D_BYTE_SIZE] = {0};
    GenerateRsa8192CorrectKeyPairSpec(dataN, dataE, dataD, &rsaPairSpec);

    HcfAsyKeyGeneratorBySpec *generator = nullptr;
    HcfResult res = HcfAsyKeyGeneratorBySpecCreate(reinterpret_cast<HcfAsyKeyParamsSpec *>(&rsaPairSpec), &generator);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(generator, nullptr);

    EXPECT_EQ(CheckGeneratorBySpecKeyFunc(generator), true);
    HcfKeyPair *keyPair = nullptr;
    res = generator->generateKeyPair(generator, &keyPair);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(keyPair, nullptr);

    const char *pkClassName = keyPair->pubKey->base.base.getClass();
    EXPECT_STREQ(pkClassName, OPENSSL_RSA_PUBKEY_CLASS);

    HcfObjDestroy(keyPair);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoRsa8192AsyKeyGeneratorBySpecTest, CryptoRsa8192AsyKeyGeneratorBySpecTest497, TestSize.Level0)
{
    HcfRsaKeyPairParamsSpec rsaPairSpec = {};
    unsigned char dataN[RSA_8192_N_BYTE_SIZE] = {0};
    unsigned char dataE[RSA_8192_E_BYTE_SIZE] = {0};
    unsigned char dataD[RSA_8192_D_BYTE_SIZE] = {0};
    GenerateRsa8192CorrectKeyPairSpec(dataN, dataE, dataD, &rsaPairSpec);

    HcfAsyKeyGeneratorBySpec *generator = nullptr;
    HcfResult res = HcfAsyKeyGeneratorBySpecCreate(reinterpret_cast<HcfAsyKeyParamsSpec *>(&rsaPairSpec), &generator);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(generator, nullptr);

    EXPECT_EQ(CheckGeneratorBySpecKeyFunc(generator), true);
    HcfKeyPair *keyPair = nullptr;
    res = generator->generateKeyPair(generator, &keyPair);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(keyPair, nullptr);

    keyPair->pubKey->base.base.destroy(&(keyPair->pubKey->base.base));
    keyPair->pubKey = nullptr;
    HcfObjDestroy(keyPair);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoRsa8192AsyKeyGeneratorBySpecTest, CryptoRsa8192AsyKeyGeneratorBySpecTest498, TestSize.Level0)
{
    HcfRsaKeyPairParamsSpec rsaPairSpec = {};
    unsigned char dataN[RSA_8192_N_BYTE_SIZE] = {0};
    unsigned char dataE[RSA_8192_E_BYTE_SIZE] = {0};
    unsigned char dataD[RSA_8192_D_BYTE_SIZE] = {0};
    GenerateRsa8192CorrectKeyPairSpec(dataN, dataE, dataD, &rsaPairSpec);

    HcfAsyKeyGeneratorBySpec *generator = nullptr;
    HcfResult res = HcfAsyKeyGeneratorBySpecCreate(reinterpret_cast<HcfAsyKeyParamsSpec *>(&rsaPairSpec), &generator);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(generator, nullptr);

    EXPECT_EQ(CheckGeneratorBySpecKeyFunc(generator), true);
    HcfKeyPair *keyPair = nullptr;
    res = generator->generateKeyPair(generator, &keyPair);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(keyPair, nullptr);

    const char *alg = keyPair->pubKey->base.getAlgorithm(&(keyPair->pubKey->base));
    EXPECT_STREQ(alg, OPENSSL_RSA_ALGORITHM);
    HcfObjDestroy(keyPair);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoRsa8192AsyKeyGeneratorBySpecTest, CryptoRsa8192AsyKeyGeneratorBySpecTest499, TestSize.Level0)
{
    HcfRsaKeyPairParamsSpec rsaPairSpec = {};
    unsigned char dataN[RSA_8192_N_BYTE_SIZE] = {0};
    unsigned char dataE[RSA_8192_E_BYTE_SIZE] = {0};
    unsigned char dataD[RSA_8192_D_BYTE_SIZE] = {0};
    GenerateRsa8192CorrectKeyPairSpec(dataN, dataE, dataD, &rsaPairSpec);

    HcfAsyKeyGeneratorBySpec *generator = nullptr;
    HcfResult res = HcfAsyKeyGeneratorBySpecCreate(reinterpret_cast<HcfAsyKeyParamsSpec *>(&rsaPairSpec), &generator);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(generator, nullptr);

    EXPECT_EQ(CheckGeneratorBySpecKeyFunc(generator), true);
    HcfKeyPair *keyPair = nullptr;
    res = generator->generateKeyPair(generator, &keyPair);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(keyPair, nullptr);

    HcfBlob blob = { .data = nullptr, .len = 0 };
    res = keyPair->pubKey->base.getEncoded(&(keyPair->pubKey->base), &blob);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(blob.data, nullptr);
    EXPECT_NE(blob.len, 0);
    HcfFree(blob.data);
    HcfObjDestroy(keyPair);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoRsa8192AsyKeyGeneratorBySpecTest, CryptoRsa8192AsyKeyGeneratorBySpecTest500, TestSize.Level0)
{
    HcfRsaKeyPairParamsSpec rsaPairSpec = {};
    unsigned char dataN[RSA_8192_N_BYTE_SIZE] = {0};
    unsigned char dataE[RSA_8192_E_BYTE_SIZE] = {0};
    unsigned char dataD[RSA_8192_D_BYTE_SIZE] = {0};
    GenerateRsa8192CorrectKeyPairSpec(dataN, dataE, dataD, &rsaPairSpec);

    HcfAsyKeyGeneratorBySpec *generator = nullptr;
    HcfResult res = HcfAsyKeyGeneratorBySpecCreate(reinterpret_cast<HcfAsyKeyParamsSpec *>(&rsaPairSpec), &generator);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(generator, nullptr);

    EXPECT_EQ(CheckGeneratorBySpecKeyFunc(generator), true);
    HcfKeyPair *keyPair = nullptr;
    res = generator->generateKeyPair(generator, &keyPair);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(keyPair, nullptr);

    const char *pkFormat = keyPair->pubKey->base.getFormat(&(keyPair->pubKey->base));
    EXPECT_STREQ(pkFormat, OPENSSL_RSA_PUBKEY_FORMAT);
    HcfObjDestroy(keyPair);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoRsa8192AsyKeyGeneratorBySpecTest, CryptoRsa8192AsyKeyGeneratorBySpecTest501, TestSize.Level0)
{
    HcfRsaKeyPairParamsSpec rsaPairSpec = {};
    unsigned char dataN[RSA_8192_N_BYTE_SIZE] = {0};
    unsigned char dataE[RSA_8192_E_BYTE_SIZE] = {0};
    unsigned char dataD[RSA_8192_D_BYTE_SIZE] = {0};
    GenerateRsa8192CorrectKeyPairSpec(dataN, dataE, dataD, &rsaPairSpec);

    HcfAsyKeyGeneratorBySpec *generator = nullptr;
    int32_t res = HcfAsyKeyGeneratorBySpecCreate(reinterpret_cast<HcfAsyKeyParamsSpec *>(&rsaPairSpec), &generator);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(generator, nullptr);

    EXPECT_EQ(CheckGeneratorBySpecKeyFunc(generator), true);
    HcfKeyPair *keyPair = nullptr;
    res = generator->generateKeyPair(generator, &keyPair);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(keyPair, nullptr);

    HcfBigInteger n = { .data = nullptr, .len = 0 };
    res = keyPair->pubKey->getAsyKeySpecBigInteger(keyPair->pubKey, RSA_N_BN, &n);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(n.data, nullptr);
    EXPECT_NE(n.len, 0);
    res = memcmp(n.data, dataN, RSA_8192_N_BYTE_SIZE);
    EXPECT_EQ(res, 0);

    HcfFree(n.data);
    HcfObjDestroy(keyPair);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoRsa8192AsyKeyGeneratorBySpecTest, CryptoRsa8192AsyKeyGeneratorBySpecTest502, TestSize.Level0)
{
    HcfRsaKeyPairParamsSpec rsaPairSpec = {};
    unsigned char dataN[RSA_8192_N_BYTE_SIZE] = {0};
    unsigned char dataE[RSA_8192_E_BYTE_SIZE] = {0};
    unsigned char dataD[RSA_8192_D_BYTE_SIZE] = {0};
    GenerateRsa8192CorrectKeyPairSpec(dataN, dataE, dataD, &rsaPairSpec);

    HcfAsyKeyGeneratorBySpec *generator = nullptr;
    int32_t res = HcfAsyKeyGeneratorBySpecCreate(reinterpret_cast<HcfAsyKeyParamsSpec *>(&rsaPairSpec), &generator);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(generator, nullptr);

    EXPECT_EQ(CheckGeneratorBySpecKeyFunc(generator), true);
    HcfKeyPair *keyPair = nullptr;
    res = generator->generateKeyPair(generator, &keyPair);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(keyPair, nullptr);

    HcfBigInteger e = { .data = nullptr, .len = 0 };
    res = keyPair->pubKey->getAsyKeySpecBigInteger(keyPair->pubKey, RSA_PK_BN, &e);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(e.data, nullptr);
    EXPECT_NE(e.len, 0);
    res = memcmp(e.data, dataE, RSA_8192_E_BYTE_SIZE);
    EXPECT_EQ(res, 0);

    HcfFree(e.data);
    HcfObjDestroy(keyPair);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoRsa8192AsyKeyGeneratorBySpecTest, CryptoRsa8192AsyKeyGeneratorBySpecTest503, TestSize.Level0)
{
    HcfRsaKeyPairParamsSpec rsaPairSpec = {};
    unsigned char dataN[RSA_8192_N_BYTE_SIZE] = {0};
    unsigned char dataE[RSA_8192_E_BYTE_SIZE] = {0};
    unsigned char dataD[RSA_8192_D_BYTE_SIZE] = {0};
    GenerateRsa8192CorrectKeyPairSpec(dataN, dataE, dataD, &rsaPairSpec);

    HcfAsyKeyGeneratorBySpec *generator = nullptr;
    HcfResult res = HcfAsyKeyGeneratorBySpecCreate(reinterpret_cast<HcfAsyKeyParamsSpec *>(&rsaPairSpec), &generator);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(generator, nullptr);

    EXPECT_EQ(CheckGeneratorBySpecKeyFunc(generator), true);
    HcfKeyPair *keyPair = nullptr;
    res = generator->generateKeyPair(generator, &keyPair);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(keyPair, nullptr);

    const char *skClassName = keyPair->priKey->base.base.getClass();
    EXPECT_STREQ(skClassName, OPENSSL_RSA_PRIKEY_CLASS);
    HcfObjDestroy(keyPair);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoRsa8192AsyKeyGeneratorBySpecTest, CryptoRsa8192AsyKeyGeneratorBySpecTest504, TestSize.Level0)
{
    HcfRsaKeyPairParamsSpec rsaPairSpec = {};
    unsigned char dataN[RSA_8192_N_BYTE_SIZE] = {0};
    unsigned char dataE[RSA_8192_E_BYTE_SIZE] = {0};
    unsigned char dataD[RSA_8192_D_BYTE_SIZE] = {0};
    GenerateRsa8192CorrectKeyPairSpec(dataN, dataE, dataD, &rsaPairSpec);

    HcfAsyKeyGeneratorBySpec *generator = nullptr;
    HcfResult res = HcfAsyKeyGeneratorBySpecCreate(reinterpret_cast<HcfAsyKeyParamsSpec *>(&rsaPairSpec), &generator);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(generator, nullptr);

    EXPECT_EQ(CheckGeneratorBySpecKeyFunc(generator), true);
    HcfKeyPair *keyPair = nullptr;
    res = generator->generateKeyPair(generator, &keyPair);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(keyPair, nullptr);

    keyPair->priKey->base.base.destroy(&(keyPair->priKey->base.base));
    keyPair->priKey = nullptr;

    HcfObjDestroy(keyPair);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoRsa8192AsyKeyGeneratorBySpecTest, CryptoRsa8192AsyKeyGeneratorBySpecTest505, TestSize.Level0)
{
    HcfRsaKeyPairParamsSpec rsaPairSpec = {};
    unsigned char dataN[RSA_8192_N_BYTE_SIZE] = {0};
    unsigned char dataE[RSA_8192_E_BYTE_SIZE] = {0};
    unsigned char dataD[RSA_8192_D_BYTE_SIZE] = {0};
    GenerateRsa8192CorrectKeyPairSpec(dataN, dataE, dataD, &rsaPairSpec);

    HcfAsyKeyGeneratorBySpec *generator = nullptr;
    HcfResult res = HcfAsyKeyGeneratorBySpecCreate(reinterpret_cast<HcfAsyKeyParamsSpec *>(&rsaPairSpec), &generator);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(generator, nullptr);

    EXPECT_EQ(CheckGeneratorBySpecKeyFunc(generator), true);
    HcfKeyPair *keyPair = nullptr;
    res = generator->generateKeyPair(generator, &keyPair);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(keyPair, nullptr);

    const char *alg = keyPair->priKey->base.getAlgorithm(&(keyPair->priKey->base));
    EXPECT_STREQ(alg, OPENSSL_RSA_ALGORITHM);

    HcfObjDestroy(keyPair);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoRsa8192AsyKeyGeneratorBySpecTest, CryptoRsa8192AsyKeyGeneratorBySpecTest506, TestSize.Level0)
{
    HcfRsaKeyPairParamsSpec rsaPairSpec = {};
    unsigned char dataN[RSA_8192_N_BYTE_SIZE] = {0};
    unsigned char dataE[RSA_8192_E_BYTE_SIZE] = {0};
    unsigned char dataD[RSA_8192_D_BYTE_SIZE] = {0};
    GenerateRsa8192CorrectKeyPairSpec(dataN, dataE, dataD, &rsaPairSpec);

    HcfAsyKeyGeneratorBySpec *generator = nullptr;
    HcfResult res = HcfAsyKeyGeneratorBySpecCreate(reinterpret_cast<HcfAsyKeyParamsSpec *>(&rsaPairSpec), &generator);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(generator, nullptr);

    EXPECT_EQ(CheckGeneratorBySpecKeyFunc(generator), true);
    HcfKeyPair *keyPair = nullptr;
    res = generator->generateKeyPair(generator, &keyPair);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(keyPair, nullptr);

    HcfBlob blob = { .data = nullptr, .len = 0 };
    res = keyPair->priKey->base.getEncoded(&(keyPair->priKey->base), &blob);
    EXPECT_EQ(res, HCF_NOT_SUPPORT);
    EXPECT_EQ(blob.data, nullptr);
    EXPECT_EQ(blob.len, 0);

    HcfFree(blob.data);
    HcfObjDestroy(keyPair);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoRsa8192AsyKeyGeneratorBySpecTest, CryptoRsa8192AsyKeyGeneratorBySpecTest507, TestSize.Level0)
{
    HcfRsaKeyPairParamsSpec rsaPairSpec = {};
    unsigned char dataN[RSA_8192_N_BYTE_SIZE] = {0};
    unsigned char dataE[RSA_8192_E_BYTE_SIZE] = {0};
    unsigned char dataD[RSA_8192_D_BYTE_SIZE] = {0};
    GenerateRsa8192CorrectKeyPairSpec(dataN, dataE, dataD, &rsaPairSpec);

    HcfAsyKeyGeneratorBySpec *generator = nullptr;
    HcfResult res = HcfAsyKeyGeneratorBySpecCreate(reinterpret_cast<HcfAsyKeyParamsSpec *>(&rsaPairSpec), &generator);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(generator, nullptr);

    EXPECT_EQ(CheckGeneratorBySpecKeyFunc(generator), true);
    HcfKeyPair *keyPair = nullptr;
    res = generator->generateKeyPair(generator, &keyPair);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(keyPair, nullptr);

    const char *pkFormat = keyPair->priKey->base.getFormat(&(keyPair->priKey->base));
    EXPECT_STREQ(pkFormat, OPENSSL_RSA_PRIKEY_FORMAT);

    HcfObjDestroy(keyPair);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoRsa8192AsyKeyGeneratorBySpecTest, CryptoRsa8192AsyKeyGeneratorBySpecTest508, TestSize.Level0)
{
    HcfRsaKeyPairParamsSpec rsaPairSpec = {};
    unsigned char dataN[RSA_8192_N_BYTE_SIZE] = {0};
    unsigned char dataE[RSA_8192_E_BYTE_SIZE] = {0};
    unsigned char dataD[RSA_8192_D_BYTE_SIZE] = {0};
    GenerateRsa8192CorrectKeyPairSpec(dataN, dataE, dataD, &rsaPairSpec);

    HcfAsyKeyGeneratorBySpec *generator = nullptr;
    HcfResult res = HcfAsyKeyGeneratorBySpecCreate(reinterpret_cast<HcfAsyKeyParamsSpec *>(&rsaPairSpec), &generator);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(generator, nullptr);

    EXPECT_EQ(CheckGeneratorBySpecKeyFunc(generator), true);
    HcfKeyPair *keyPair = nullptr;
    res = generator->generateKeyPair(generator, &keyPair);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(keyPair, nullptr);

    const char *pkFormat = keyPair->priKey->base.getFormat(&(keyPair->priKey->base));
    EXPECT_STREQ(pkFormat, OPENSSL_RSA_PRIKEY_FORMAT);

    HcfBigInteger n = { .data = nullptr, .len = 0 };
    res = keyPair->priKey->getAsyKeySpecBigInteger(keyPair->priKey, RSA_N_BN, &n);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(n.data, nullptr);
    EXPECT_NE(n.len, 0);

    HcfFree(n.data);
    HcfObjDestroy(keyPair);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoRsa8192AsyKeyGeneratorBySpecTest, CryptoRsa8192AsyKeyGeneratorBySpecTest509, TestSize.Level0)
{
    HcfRsaKeyPairParamsSpec rsaPairSpec = {};
    unsigned char dataN[RSA_8192_N_BYTE_SIZE] = {0};
    unsigned char dataE[RSA_8192_E_BYTE_SIZE] = {0};
    unsigned char dataD[RSA_8192_D_BYTE_SIZE] = {0};
    GenerateRsa8192CorrectKeyPairSpec(dataN, dataE, dataD, &rsaPairSpec);

    HcfAsyKeyGeneratorBySpec *generator = nullptr;
    HcfResult res = HcfAsyKeyGeneratorBySpecCreate(reinterpret_cast<HcfAsyKeyParamsSpec *>(&rsaPairSpec), &generator);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(generator, nullptr);

    EXPECT_EQ(CheckGeneratorBySpecKeyFunc(generator), true);
    HcfKeyPair *keyPair = nullptr;
    res = generator->generateKeyPair(generator, &keyPair);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(keyPair, nullptr);

    const char *pkFormat = keyPair->priKey->base.getFormat(&(keyPair->priKey->base));
    EXPECT_STREQ(pkFormat, OPENSSL_RSA_PRIKEY_FORMAT);

    HcfBigInteger d = { .data = nullptr, .len = 0 };
    res = keyPair->priKey->getAsyKeySpecBigInteger(keyPair->priKey, RSA_SK_BN, &d);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(d.data, nullptr);
    EXPECT_NE(d.len, 0);

    HcfFree(d.data);
    HcfObjDestroy(keyPair);
    HcfObjDestroy(generator);
}

// check key functions of pub key from key pair spec
HWTEST_F(CryptoRsa8192AsyKeyGeneratorBySpecTest, CryptoRsa8192AsyKeyGeneratorBySpecTest510, TestSize.Level0)
{
    HcfRsaKeyPairParamsSpec rsaPairSpec = {};
    unsigned char dataN[RSA_8192_N_BYTE_SIZE] = {0};
    unsigned char dataE[RSA_8192_E_BYTE_SIZE] = {0};
    unsigned char dataD[RSA_8192_D_BYTE_SIZE] = {0};
    GenerateRsa8192CorrectKeyPairSpec(dataN, dataE, dataD, &rsaPairSpec);

    HcfAsyKeyGeneratorBySpec *generator = nullptr;
    HcfResult res = HcfAsyKeyGeneratorBySpecCreate(reinterpret_cast<HcfAsyKeyParamsSpec *>(&rsaPairSpec), &generator);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(generator, nullptr);

    EXPECT_EQ(CheckGeneratorBySpecKeyFunc(generator), true);
    HcfPubKey *pubKey = nullptr;
    res = generator->generatePubKey(generator, &pubKey);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(pubKey, nullptr);

    const char *pkClassName = pubKey->base.base.getClass();
    EXPECT_STREQ(pkClassName, OPENSSL_RSA_PUBKEY_CLASS);

    HcfObjDestroy(pubKey);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoRsa8192AsyKeyGeneratorBySpecTest, CryptoRsa8192AsyKeyGeneratorBySpecTest511, TestSize.Level0)
{
    HcfRsaKeyPairParamsSpec rsaPairSpec = {};
    unsigned char dataN[RSA_8192_N_BYTE_SIZE] = {0};
    unsigned char dataE[RSA_8192_E_BYTE_SIZE] = {0};
    unsigned char dataD[RSA_8192_D_BYTE_SIZE] = {0};
    GenerateRsa8192CorrectKeyPairSpec(dataN, dataE, dataD, &rsaPairSpec);

    HcfAsyKeyGeneratorBySpec *generator = nullptr;
    HcfResult res = HcfAsyKeyGeneratorBySpecCreate(reinterpret_cast<HcfAsyKeyParamsSpec *>(&rsaPairSpec), &generator);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(generator, nullptr);

    EXPECT_EQ(CheckGeneratorBySpecKeyFunc(generator), true);
    HcfPubKey *pubKey = nullptr;
    res = generator->generatePubKey(generator, &pubKey);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(pubKey, nullptr);

    pubKey->base.base.destroy(&(pubKey->base.base));
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoRsa8192AsyKeyGeneratorBySpecTest, CryptoRsa8192AsyKeyGeneratorBySpecTest512, TestSize.Level0)
{
    HcfRsaKeyPairParamsSpec rsaPairSpec = {};
    unsigned char dataN[RSA_8192_N_BYTE_SIZE] = {0};
    unsigned char dataE[RSA_8192_E_BYTE_SIZE] = {0};
    unsigned char dataD[RSA_8192_D_BYTE_SIZE] = {0};
    GenerateRsa8192CorrectKeyPairSpec(dataN, dataE, dataD, &rsaPairSpec);

    HcfAsyKeyGeneratorBySpec *generator = nullptr;
    HcfResult res = HcfAsyKeyGeneratorBySpecCreate(reinterpret_cast<HcfAsyKeyParamsSpec *>(&rsaPairSpec), &generator);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(generator, nullptr);

    EXPECT_EQ(CheckGeneratorBySpecKeyFunc(generator), true);
    HcfPubKey *pubKey = nullptr;
    res = generator->generatePubKey(generator, &pubKey);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(pubKey, nullptr);

    const char *alg = pubKey->base.getAlgorithm(&(pubKey->base));
    EXPECT_STREQ(alg, OPENSSL_RSA_ALGORITHM);
    HcfObjDestroy(pubKey);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoRsa8192AsyKeyGeneratorBySpecTest, CryptoRsa8192AsyKeyGeneratorBySpecTest513, TestSize.Level0)
{
    HcfRsaKeyPairParamsSpec rsaPairSpec = {};
    unsigned char dataN[RSA_8192_N_BYTE_SIZE] = {0};
    unsigned char dataE[RSA_8192_E_BYTE_SIZE] = {0};
    unsigned char dataD[RSA_8192_D_BYTE_SIZE] = {0};
    GenerateRsa8192CorrectKeyPairSpec(dataN, dataE, dataD, &rsaPairSpec);

    HcfAsyKeyGeneratorBySpec *generator = nullptr;
    HcfResult res = HcfAsyKeyGeneratorBySpecCreate(reinterpret_cast<HcfAsyKeyParamsSpec *>(&rsaPairSpec), &generator);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(generator, nullptr);

    EXPECT_EQ(CheckGeneratorBySpecKeyFunc(generator), true);
    HcfPubKey *pubKey = nullptr;
    res = generator->generatePubKey(generator, &pubKey);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(pubKey, nullptr);

    HcfBlob blob = { .data = nullptr, .len = 0 };
    res = pubKey->base.getEncoded(&(pubKey->base), &blob);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(blob.data, nullptr);
    EXPECT_NE(blob.len, 0);
    HcfFree(blob.data);
    HcfObjDestroy(pubKey);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoRsa8192AsyKeyGeneratorBySpecTest, CryptoRsa8192AsyKeyGeneratorBySpecTest514, TestSize.Level0)
{
    HcfRsaKeyPairParamsSpec rsaPairSpec = {};
    unsigned char dataN[RSA_8192_N_BYTE_SIZE] = {0};
    unsigned char dataE[RSA_8192_E_BYTE_SIZE] = {0};
    unsigned char dataD[RSA_8192_D_BYTE_SIZE] = {0};
    GenerateRsa8192CorrectKeyPairSpec(dataN, dataE, dataD, &rsaPairSpec);

    HcfAsyKeyGeneratorBySpec *generator = nullptr;
    HcfResult res = HcfAsyKeyGeneratorBySpecCreate(reinterpret_cast<HcfAsyKeyParamsSpec *>(&rsaPairSpec), &generator);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(generator, nullptr);

    EXPECT_EQ(CheckGeneratorBySpecKeyFunc(generator), true);
    HcfPubKey *pubKey = nullptr;
    res = generator->generatePubKey(generator, &pubKey);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(pubKey, nullptr);

    const char *pkFormat = pubKey->base.getFormat(&(pubKey->base));
    EXPECT_STREQ(pkFormat, OPENSSL_RSA_PUBKEY_FORMAT);
    HcfObjDestroy(pubKey);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoRsa8192AsyKeyGeneratorBySpecTest, CryptoRsa8192AsyKeyGeneratorBySpecTest515, TestSize.Level0)
{
    HcfRsaKeyPairParamsSpec rsaPairSpec = {};
    unsigned char dataN[RSA_8192_N_BYTE_SIZE] = {0};
    unsigned char dataE[RSA_8192_E_BYTE_SIZE] = {0};
    unsigned char dataD[RSA_8192_D_BYTE_SIZE] = {0};
    GenerateRsa8192CorrectKeyPairSpec(dataN, dataE, dataD, &rsaPairSpec);

    HcfAsyKeyGeneratorBySpec *generator = nullptr;
    int32_t res = HcfAsyKeyGeneratorBySpecCreate(reinterpret_cast<HcfAsyKeyParamsSpec *>(&rsaPairSpec), &generator);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(generator, nullptr);

    EXPECT_EQ(CheckGeneratorBySpecKeyFunc(generator), true);
    HcfPubKey *pubKey = nullptr;
    res = generator->generatePubKey(generator, &pubKey);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(pubKey, nullptr);

    HcfBigInteger n = { .data = nullptr, .len = 0 };
    res = pubKey->getAsyKeySpecBigInteger(pubKey, RSA_N_BN, &n);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(n.data, nullptr);
    EXPECT_NE(n.len, 0);
    res = memcmp(n.data, dataN, RSA_8192_N_BYTE_SIZE);
    EXPECT_EQ(res, 0);

    HcfFree(n.data);
    HcfObjDestroy(pubKey);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoRsa8192AsyKeyGeneratorBySpecTest, CryptoRsa8192AsyKeyGeneratorBySpecTest516, TestSize.Level0)
{
    HcfRsaKeyPairParamsSpec rsaPairSpec = {};
    unsigned char dataN[RSA_8192_N_BYTE_SIZE] = {0};
    unsigned char dataE[RSA_8192_E_BYTE_SIZE] = {0};
    unsigned char dataD[RSA_8192_D_BYTE_SIZE] = {0};
    GenerateRsa8192CorrectKeyPairSpec(dataN, dataE, dataD, &rsaPairSpec);

    HcfAsyKeyGeneratorBySpec *generator = nullptr;
    int32_t res = HcfAsyKeyGeneratorBySpecCreate(reinterpret_cast<HcfAsyKeyParamsSpec *>(&rsaPairSpec), &generator);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(generator, nullptr);

    EXPECT_EQ(CheckGeneratorBySpecKeyFunc(generator), true);
    HcfPubKey *pubKey = nullptr;
    res = generator->generatePubKey(generator, &pubKey);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(pubKey, nullptr);

    HcfBigInteger e = { .data = nullptr, .len = 0 };
    res = pubKey->getAsyKeySpecBigInteger(pubKey, RSA_PK_BN, &e);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(e.data, nullptr);
    EXPECT_NE(e.len, 0);
    res = memcmp(e.data, dataE, RSA_8192_E_BYTE_SIZE);
    EXPECT_EQ(res, 0);

    HcfFree(e.data);
    HcfObjDestroy(pubKey);
    HcfObjDestroy(generator);
}

// check key function of pri key generated by key pair spec
HWTEST_F(CryptoRsa8192AsyKeyGeneratorBySpecTest, CryptoRsa8192AsyKeyGeneratorBySpecTest517, TestSize.Level0)
{
    HcfRsaKeyPairParamsSpec rsaPairSpec = {};
    unsigned char dataN[RSA_8192_N_BYTE_SIZE] = {0};
    unsigned char dataE[RSA_8192_E_BYTE_SIZE] = {0};
    unsigned char dataD[RSA_8192_D_BYTE_SIZE] = {0};
    GenerateRsa8192CorrectKeyPairSpec(dataN, dataE, dataD, &rsaPairSpec);

    HcfAsyKeyGeneratorBySpec *generator = nullptr;
    HcfResult res = HcfAsyKeyGeneratorBySpecCreate(reinterpret_cast<HcfAsyKeyParamsSpec *>(&rsaPairSpec), &generator);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(generator, nullptr);

    EXPECT_EQ(CheckGeneratorBySpecKeyFunc(generator), true);
    HcfPriKey *priKey = nullptr;
    res = generator->generatePriKey(generator, &priKey);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(priKey, nullptr);

    const char *pkClassName = priKey->base.base.getClass();
    EXPECT_STREQ(pkClassName, OPENSSL_RSA_PRIKEY_CLASS);

    HcfObjDestroy(priKey);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoRsa8192AsyKeyGeneratorBySpecTest, CryptoRsa8192AsyKeyGeneratorBySpecTest518, TestSize.Level0)
{
    HcfRsaKeyPairParamsSpec rsaPairSpec = {};
    unsigned char dataN[RSA_8192_N_BYTE_SIZE] = {0};
    unsigned char dataE[RSA_8192_E_BYTE_SIZE] = {0};
    unsigned char dataD[RSA_8192_D_BYTE_SIZE] = {0};
    GenerateRsa8192CorrectKeyPairSpec(dataN, dataE, dataD, &rsaPairSpec);

    HcfAsyKeyGeneratorBySpec *generator = nullptr;
    HcfResult res = HcfAsyKeyGeneratorBySpecCreate(reinterpret_cast<HcfAsyKeyParamsSpec *>(&rsaPairSpec), &generator);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(generator, nullptr);

    EXPECT_EQ(CheckGeneratorBySpecKeyFunc(generator), true);
    HcfPriKey *priKey = nullptr;
    res = generator->generatePriKey(generator, &priKey);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(priKey, nullptr);

    priKey->base.base.destroy(&(priKey->base.base));
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoRsa8192AsyKeyGeneratorBySpecTest, CryptoRsa8192AsyKeyGeneratorBySpecTest519, TestSize.Level0)
{
    HcfRsaKeyPairParamsSpec rsaPairSpec = {};
    unsigned char dataN[RSA_8192_N_BYTE_SIZE] = {0};
    unsigned char dataE[RSA_8192_E_BYTE_SIZE] = {0};
    unsigned char dataD[RSA_8192_D_BYTE_SIZE] = {0};
    GenerateRsa8192CorrectKeyPairSpec(dataN, dataE, dataD, &rsaPairSpec);

    HcfAsyKeyGeneratorBySpec *generator = nullptr;
    HcfResult res = HcfAsyKeyGeneratorBySpecCreate(reinterpret_cast<HcfAsyKeyParamsSpec *>(&rsaPairSpec), &generator);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(generator, nullptr);

    EXPECT_EQ(CheckGeneratorBySpecKeyFunc(generator), true);
    HcfPriKey *priKey = nullptr;
    res = generator->generatePriKey(generator, &priKey);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(priKey, nullptr);

    const char *alg = priKey->base.getAlgorithm(&(priKey->base));
    EXPECT_STREQ(alg, OPENSSL_RSA_ALGORITHM);
    HcfObjDestroy(priKey);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoRsa8192AsyKeyGeneratorBySpecTest, CryptoRsa8192AsyKeyGeneratorBySpecTest520, TestSize.Level0)
{
    HcfRsaKeyPairParamsSpec rsaPairSpec = {};
    unsigned char dataN[RSA_8192_N_BYTE_SIZE] = {0};
    unsigned char dataE[RSA_8192_E_BYTE_SIZE] = {0};
    unsigned char dataD[RSA_8192_D_BYTE_SIZE] = {0};
    GenerateRsa8192CorrectKeyPairSpec(dataN, dataE, dataD, &rsaPairSpec);

    HcfAsyKeyGeneratorBySpec *generator = nullptr;
    HcfResult res = HcfAsyKeyGeneratorBySpecCreate(reinterpret_cast<HcfAsyKeyParamsSpec *>(&rsaPairSpec), &generator);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(generator, nullptr);

    EXPECT_EQ(CheckGeneratorBySpecKeyFunc(generator), true);
    HcfPriKey *priKey = nullptr;
    res = generator->generatePriKey(generator, &priKey);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(priKey, nullptr);

    HcfBlob blob = { .data = nullptr, .len = 0 };
    res = priKey->base.getEncoded(&(priKey->base), &blob);
    EXPECT_EQ(res, HCF_NOT_SUPPORT);
    EXPECT_EQ(blob.data, nullptr);
    EXPECT_EQ(blob.len, 0);
    HcfFree(blob.data);
    HcfObjDestroy(priKey);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoRsa8192AsyKeyGeneratorBySpecTest, CryptoRsa8192AsyKeyGeneratorBySpecTest521, TestSize.Level0)
{
    HcfRsaKeyPairParamsSpec rsaPairSpec = {};
    unsigned char dataN[RSA_8192_N_BYTE_SIZE] = {0};
    unsigned char dataE[RSA_8192_E_BYTE_SIZE] = {0};
    unsigned char dataD[RSA_8192_D_BYTE_SIZE] = {0};
    GenerateRsa8192CorrectKeyPairSpec(dataN, dataE, dataD, &rsaPairSpec);

    HcfAsyKeyGeneratorBySpec *generator = nullptr;
    HcfResult res = HcfAsyKeyGeneratorBySpecCreate(reinterpret_cast<HcfAsyKeyParamsSpec *>(&rsaPairSpec), &generator);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(generator, nullptr);

    EXPECT_EQ(CheckGeneratorBySpecKeyFunc(generator), true);
    HcfPriKey *priKey = nullptr;
    res = generator->generatePriKey(generator, &priKey);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(priKey, nullptr);

    const char *pkFormat = priKey->base.getFormat(&(priKey->base));
    EXPECT_STREQ(pkFormat, OPENSSL_RSA_PRIKEY_FORMAT);
    HcfObjDestroy(priKey);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoRsa8192AsyKeyGeneratorBySpecTest, CryptoRsa8192AsyKeyGeneratorBySpecTest522, TestSize.Level0)
{
    HcfRsaKeyPairParamsSpec rsaPairSpec = {};
    unsigned char dataN[RSA_8192_N_BYTE_SIZE] = {0};
    unsigned char dataE[RSA_8192_E_BYTE_SIZE] = {0};
    unsigned char dataD[RSA_8192_D_BYTE_SIZE] = {0};
    GenerateRsa8192CorrectKeyPairSpec(dataN, dataE, dataD, &rsaPairSpec);

    HcfAsyKeyGeneratorBySpec *generator = nullptr;
    int32_t res = HcfAsyKeyGeneratorBySpecCreate(reinterpret_cast<HcfAsyKeyParamsSpec *>(&rsaPairSpec), &generator);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(generator, nullptr);

    EXPECT_EQ(CheckGeneratorBySpecKeyFunc(generator), true);
    HcfPriKey *priKey = nullptr;
    res = generator->generatePriKey(generator, &priKey);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(priKey, nullptr);

    HcfBigInteger n = { .data = nullptr, .len = 0 };
    res = priKey->getAsyKeySpecBigInteger(priKey, RSA_N_BN, &n);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(n.data, nullptr);
    EXPECT_NE(n.len, 0);
    res = memcmp(n.data, dataN, RSA_8192_N_BYTE_SIZE);
    EXPECT_EQ(res, 0);

    HcfFree(n.data);
    HcfObjDestroy(priKey);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoRsa8192AsyKeyGeneratorBySpecTest, CryptoRsa8192AsyKeyGeneratorBySpecTest523, TestSize.Level0)
{
    HcfRsaKeyPairParamsSpec rsaPairSpec = {};
    unsigned char dataN[RSA_8192_N_BYTE_SIZE] = {0};
    unsigned char dataE[RSA_8192_E_BYTE_SIZE] = {0};
    unsigned char dataD[RSA_8192_D_BYTE_SIZE] = {0};
    GenerateRsa8192CorrectKeyPairSpec(dataN, dataE, dataD, &rsaPairSpec);

    HcfAsyKeyGeneratorBySpec *generator = nullptr;
    int32_t res = HcfAsyKeyGeneratorBySpecCreate(reinterpret_cast<HcfAsyKeyParamsSpec *>(&rsaPairSpec), &generator);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(generator, nullptr);

    EXPECT_EQ(CheckGeneratorBySpecKeyFunc(generator), true);
    HcfPriKey *priKey = nullptr;
    res = generator->generatePriKey(generator, &priKey);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(priKey, nullptr);

    HcfBigInteger d = { .data = nullptr, .len = 0 };
    res = priKey->getAsyKeySpecBigInteger(priKey, RSA_SK_BN, &d);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(d.data, nullptr);
    EXPECT_NE(d.len, 0);
    res = memcmp(d.data, dataD, RSA_8192_D_BYTE_SIZE);
    EXPECT_EQ(res, 0);

    HcfFree(d.data);
    HcfObjDestroy(priKey);
    HcfObjDestroy(generator);
}

// check key functions of pub key from pub key spec
HWTEST_F(CryptoRsa8192AsyKeyGeneratorBySpecTest, CryptoRsa8192AsyKeyGeneratorBySpecTest524, TestSize.Level0)
{
    HcfRsaPubKeyParamsSpec rsaPubKeySpec = {};
    unsigned char dataN[RSA_8192_N_BYTE_SIZE] = {0};
    unsigned char dataE[RSA_8192_E_BYTE_SIZE] = {0};
    GenerateRsa8192CorrectPubKeySpec(dataN, dataE, &rsaPubKeySpec);
    HcfAsyKeyGeneratorBySpec *generator = nullptr;
    HcfResult res = HcfAsyKeyGeneratorBySpecCreate(reinterpret_cast<HcfAsyKeyParamsSpec *>(&rsaPubKeySpec), &generator);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(generator, nullptr);

    EXPECT_EQ(CheckGeneratorBySpecKeyFunc(generator), true);
    HcfPubKey *pubKey = nullptr;
    res = generator->generatePubKey(generator, &pubKey);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(pubKey, nullptr);

    const char *pkClassName = pubKey->base.base.getClass();
    EXPECT_STREQ(pkClassName, OPENSSL_RSA_PUBKEY_CLASS);

    HcfObjDestroy(pubKey);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoRsa8192AsyKeyGeneratorBySpecTest, CryptoRsa8192AsyKeyGeneratorBySpecTest525, TestSize.Level0)
{
    HcfRsaPubKeyParamsSpec rsaPubKeySpec = {};
    unsigned char dataN[RSA_8192_N_BYTE_SIZE] = {0};
    unsigned char dataE[RSA_8192_E_BYTE_SIZE] = {0};
    GenerateRsa8192CorrectPubKeySpec(dataN, dataE, &rsaPubKeySpec);
    HcfAsyKeyGeneratorBySpec *generator = nullptr;
    HcfResult res = HcfAsyKeyGeneratorBySpecCreate(reinterpret_cast<HcfAsyKeyParamsSpec *>(&rsaPubKeySpec), &generator);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(generator, nullptr);

    EXPECT_EQ(CheckGeneratorBySpecKeyFunc(generator), true);
    HcfPubKey *pubKey = nullptr;
    res = generator->generatePubKey(generator, &pubKey);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(pubKey, nullptr);

    pubKey->base.base.destroy(&(pubKey->base.base));
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoRsa8192AsyKeyGeneratorBySpecTest, CryptoRsa8192AsyKeyGeneratorBySpecTest526, TestSize.Level0)
{
    HcfRsaPubKeyParamsSpec rsaPubKeySpec = {};
    unsigned char dataN[RSA_8192_N_BYTE_SIZE] = {0};
    unsigned char dataE[RSA_8192_E_BYTE_SIZE] = {0};
    GenerateRsa8192CorrectPubKeySpec(dataN, dataE, &rsaPubKeySpec);
    HcfAsyKeyGeneratorBySpec *generator = nullptr;
    HcfResult res = HcfAsyKeyGeneratorBySpecCreate(reinterpret_cast<HcfAsyKeyParamsSpec *>(&rsaPubKeySpec), &generator);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(generator, nullptr);

    EXPECT_EQ(CheckGeneratorBySpecKeyFunc(generator), true);
    HcfPubKey *pubKey = nullptr;
    res = generator->generatePubKey(generator, &pubKey);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(pubKey, nullptr);

    const char *alg = pubKey->base.getAlgorithm(&(pubKey->base));
    EXPECT_STREQ(alg, OPENSSL_RSA_ALGORITHM);
    HcfObjDestroy(pubKey);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoRsa8192AsyKeyGeneratorBySpecTest, CryptoRsa8192AsyKeyGeneratorBySpecTest527, TestSize.Level0)
{
    HcfRsaPubKeyParamsSpec rsaPubKeySpec = {};
    unsigned char dataN[RSA_8192_N_BYTE_SIZE] = {0};
    unsigned char dataE[RSA_8192_E_BYTE_SIZE] = {0};
    GenerateRsa8192CorrectPubKeySpec(dataN, dataE, &rsaPubKeySpec);
    HcfAsyKeyGeneratorBySpec *generator = nullptr;
    HcfResult res = HcfAsyKeyGeneratorBySpecCreate(reinterpret_cast<HcfAsyKeyParamsSpec *>(&rsaPubKeySpec), &generator);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(generator, nullptr);

    EXPECT_EQ(CheckGeneratorBySpecKeyFunc(generator), true);
    HcfPubKey *pubKey = nullptr;
    res = generator->generatePubKey(generator, &pubKey);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(pubKey, nullptr);

    HcfBlob blob = { .data = nullptr, .len = 0 };
    res = pubKey->base.getEncoded(&(pubKey->base), &blob);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(blob.data, nullptr);
    EXPECT_NE(blob.len, 0);
    HcfFree(blob.data);
    HcfObjDestroy(pubKey);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoRsa8192AsyKeyGeneratorBySpecTest, CryptoRsa8192AsyKeyGeneratorBySpecTest528, TestSize.Level0)
{
    HcfRsaPubKeyParamsSpec rsaPubKeySpec = {};
    unsigned char dataN[RSA_8192_N_BYTE_SIZE] = {0};
    unsigned char dataE[RSA_8192_E_BYTE_SIZE] = {0};
    GenerateRsa8192CorrectPubKeySpec(dataN, dataE, &rsaPubKeySpec);
    HcfAsyKeyGeneratorBySpec *generator = nullptr;
    HcfResult res = HcfAsyKeyGeneratorBySpecCreate(reinterpret_cast<HcfAsyKeyParamsSpec *>(&rsaPubKeySpec), &generator);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(generator, nullptr);

    EXPECT_EQ(CheckGeneratorBySpecKeyFunc(generator), true);
    HcfPubKey *pubKey = nullptr;
    res = generator->generatePubKey(generator, &pubKey);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(pubKey, nullptr);

    const char *pkFormat = pubKey->base.getFormat(&(pubKey->base));
    EXPECT_STREQ(pkFormat, OPENSSL_RSA_PUBKEY_FORMAT);
    HcfObjDestroy(pubKey);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoRsa8192AsyKeyGeneratorBySpecTest, CryptoRsa8192AsyKeyGeneratorBySpecTest529, TestSize.Level0)
{
    HcfRsaPubKeyParamsSpec rsaPubKeySpec = {};
    unsigned char dataN[RSA_8192_N_BYTE_SIZE] = {0};
    unsigned char dataE[RSA_8192_E_BYTE_SIZE] = {0};
    GenerateRsa8192CorrectPubKeySpec(dataN, dataE, &rsaPubKeySpec);
    HcfAsyKeyGeneratorBySpec *generator = nullptr;
    int32_t res = HcfAsyKeyGeneratorBySpecCreate(reinterpret_cast<HcfAsyKeyParamsSpec *>(&rsaPubKeySpec), &generator);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(generator, nullptr);

    EXPECT_EQ(CheckGeneratorBySpecKeyFunc(generator), true);
    HcfPubKey *pubKey = nullptr;
    res = generator->generatePubKey(generator, &pubKey);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(pubKey, nullptr);

    HcfBigInteger n = { .data = nullptr, .len = 0 };
    res = pubKey->getAsyKeySpecBigInteger(pubKey, RSA_N_BN, &n);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(n.data, nullptr);
    EXPECT_NE(n.len, 0);
    res = memcmp(n.data, dataN, RSA_8192_N_BYTE_SIZE);
    EXPECT_EQ(res, 0);

    HcfFree(n.data);
    HcfObjDestroy(pubKey);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoRsa8192AsyKeyGeneratorBySpecTest, CryptoRsa8192AsyKeyGeneratorBySpecTest530, TestSize.Level0)
{
    HcfRsaPubKeyParamsSpec rsaPubKeySpec = {};
    unsigned char dataN[RSA_8192_N_BYTE_SIZE] = {0};
    unsigned char dataE[RSA_8192_E_BYTE_SIZE] = {0};
    GenerateRsa8192CorrectPubKeySpec(dataN, dataE, &rsaPubKeySpec);
    HcfAsyKeyGeneratorBySpec *generator = nullptr;
    int32_t res = HcfAsyKeyGeneratorBySpecCreate(reinterpret_cast<HcfAsyKeyParamsSpec *>(&rsaPubKeySpec), &generator);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(generator, nullptr);

    EXPECT_EQ(CheckGeneratorBySpecKeyFunc(generator), true);
    HcfPubKey *pubKey = nullptr;
    res = generator->generatePubKey(generator, &pubKey);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(pubKey, nullptr);

    HcfBigInteger e = { .data = nullptr, .len = 0 };
    res = pubKey->getAsyKeySpecBigInteger(pubKey, RSA_PK_BN, &e);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(e.data, nullptr);
    EXPECT_NE(e.len, 0);
    res = memcmp(e.data, dataE, RSA_8192_E_BYTE_SIZE);
    EXPECT_EQ(res, 0);

    HcfFree(e.data);
    HcfObjDestroy(pubKey);
    HcfObjDestroy(generator);
}

// check encoded key pair's pub key from key pair spec and convert to pub key object
HWTEST_F(CryptoRsa8192AsyKeyGeneratorBySpecTest, CryptoRsa8192AsyKeyGeneratorBySpecTest531, TestSize.Level0)
{
    HcfRsaKeyPairParamsSpec rsaPairSpec = {};
    unsigned char dataN[RSA_8192_N_BYTE_SIZE] = {0};
    unsigned char dataE[RSA_8192_E_BYTE_SIZE] = {0};
    unsigned char dataD[RSA_8192_D_BYTE_SIZE] = {0};
    GenerateRsa8192CorrectKeyPairSpec(dataN, dataE, dataD, &rsaPairSpec);

    HcfAsyKeyGeneratorBySpec *generator = nullptr;
    HcfResult res = HcfAsyKeyGeneratorBySpecCreate(reinterpret_cast<HcfAsyKeyParamsSpec *>(&rsaPairSpec), &generator);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(generator, nullptr);

    EXPECT_EQ(CheckGeneratorBySpecKeyFunc(generator), true);
    HcfKeyPair *keyPair = nullptr;
    res = generator->generateKeyPair(generator, &keyPair);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(keyPair, nullptr);

    // encoded and convert key pair's pubKey
    HcfPubKey *pubKey = keyPair->pubKey;
    HcfBlob blob = { .data = nullptr, .len = 0 };
    res = pubKey->base.getEncoded(&(pubKey->base), &blob);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(blob.data, nullptr);
    EXPECT_NE(blob.len, 0);

    HcfAsyKeyGenerator *generatorConvert = nullptr;
    res = HcfAsyKeyGeneratorCreate("RSA8192", &generatorConvert);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(generatorConvert, nullptr);

    HcfKeyPair *dupKeyPair = nullptr;
    res = generatorConvert->convertKey(generatorConvert, nullptr, &blob, nullptr, &dupKeyPair);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_EQ(dupKeyPair->priKey, nullptr);
    EXPECT_NE(dupKeyPair->pubKey, nullptr);

    HcfFree(blob.data);
    HcfObjDestroy(keyPair);
    HcfObjDestroy(dupKeyPair);
    HcfObjDestroy(generator);
    HcfObjDestroy(generatorConvert);
}

// check encoded pub key from key pair spec and convert to pub key object
HWTEST_F(CryptoRsa8192AsyKeyGeneratorBySpecTest, CryptoRsa8192AsyKeyGeneratorBySpecTest532, TestSize.Level0)
{
    HcfRsaKeyPairParamsSpec rsaPairSpec = {};
    unsigned char dataN[RSA_8192_N_BYTE_SIZE] = {0};
    unsigned char dataE[RSA_8192_E_BYTE_SIZE] = {0};
    unsigned char dataD[RSA_8192_D_BYTE_SIZE] = {0};
    GenerateRsa8192CorrectKeyPairSpec(dataN, dataE, dataD, &rsaPairSpec);

    HcfAsyKeyGeneratorBySpec *generator = nullptr;
    HcfResult res = HcfAsyKeyGeneratorBySpecCreate(reinterpret_cast<HcfAsyKeyParamsSpec *>(&rsaPairSpec), &generator);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(generator, nullptr);

    EXPECT_EQ(CheckGeneratorBySpecKeyFunc(generator), true);
    HcfPubKey *pubKey = nullptr;
    res = generator->generatePubKey(generator, &pubKey);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(pubKey, nullptr);

    // encoded and convert pubKey
    HcfBlob blob = { .data = nullptr, .len = 0 };
    res = pubKey->base.getEncoded(&(pubKey->base), &blob);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(blob.data, nullptr);
    EXPECT_NE(blob.len, 0);

    HcfAsyKeyGenerator *generatorConvert = nullptr;
    res = HcfAsyKeyGeneratorCreate("RSA8192", &generatorConvert);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(generatorConvert, nullptr);

    HcfKeyPair *dupKeyPair = nullptr;
    res = generatorConvert->convertKey(generatorConvert, nullptr, &blob, nullptr, &dupKeyPair);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_EQ(dupKeyPair->priKey, nullptr);
    EXPECT_NE(dupKeyPair->pubKey, nullptr);

    HcfFree(blob.data);
    HcfObjDestroy(dupKeyPair);
    HcfObjDestroy(pubKey);
    HcfObjDestroy(generator);
    HcfObjDestroy(generatorConvert);
}

// check encoded pub key from pub key spec and convert to pub key object
HWTEST_F(CryptoRsa8192AsyKeyGeneratorBySpecTest, CryptoRsa8192AsyKeyGeneratorBySpecTest533, TestSize.Level0)
{
    HcfRsaPubKeyParamsSpec rsaPubKeySpec = {};
    unsigned char dataN[RSA_8192_N_BYTE_SIZE] = {0};
    unsigned char dataE[RSA_8192_E_BYTE_SIZE] = {0};
    GenerateRsa8192CorrectPubKeySpec(dataN, dataE, &rsaPubKeySpec);
    HcfAsyKeyGeneratorBySpec *generator = nullptr;
    int32_t res = HcfAsyKeyGeneratorBySpecCreate(reinterpret_cast<HcfAsyKeyParamsSpec *>(&rsaPubKeySpec), &generator);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(generator, nullptr);

    EXPECT_EQ(CheckGeneratorBySpecKeyFunc(generator), true);
    HcfPubKey *pubKey = nullptr;
    res = generator->generatePubKey(generator, &pubKey);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(pubKey, nullptr);

    // encoded and convert pubKey
    HcfBlob blob = { .data = nullptr, .len = 0 };
    res = pubKey->base.getEncoded(&(pubKey->base), &blob);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(blob.data, nullptr);
    EXPECT_NE(blob.len, 0);

    HcfAsyKeyGenerator *generatorConvert = nullptr;
    res = HcfAsyKeyGeneratorCreate("RSA8192", &generatorConvert);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(generatorConvert, nullptr);

    HcfKeyPair *dupKeyPair = nullptr;
    res = generatorConvert->convertKey(generatorConvert, nullptr, &blob, nullptr, &dupKeyPair);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_EQ(dupKeyPair->priKey, nullptr);
    EXPECT_NE(dupKeyPair->pubKey, nullptr);

    HcfFree(blob.data);
    HcfObjDestroy(dupKeyPair);
    HcfObjDestroy(pubKey);
    HcfObjDestroy(generator);
    HcfObjDestroy(generatorConvert);
}

// check encoded key pair's pub key from key pair spec, convert to pub key object and check the get function
HWTEST_F(CryptoRsa8192AsyKeyGeneratorBySpecTest, CryptoRsa8192AsyKeyGeneratorBySpecTest534, TestSize.Level0)
{
    HcfRsaKeyPairParamsSpec rsaPairSpec = {};
    unsigned char dataN[RSA_8192_N_BYTE_SIZE] = {0};
    unsigned char dataE[RSA_8192_E_BYTE_SIZE] = {0};
    unsigned char dataD[RSA_8192_D_BYTE_SIZE] = {0};
    GenerateRsa8192CorrectKeyPairSpec(dataN, dataE, dataD, &rsaPairSpec);

    HcfAsyKeyGeneratorBySpec *generator = nullptr;
    int32_t res = HcfAsyKeyGeneratorBySpecCreate(reinterpret_cast<HcfAsyKeyParamsSpec *>(&rsaPairSpec), &generator);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(generator, nullptr);

    EXPECT_EQ(CheckGeneratorBySpecKeyFunc(generator), true);
    HcfKeyPair *keyPair = nullptr;
    res = generator->generateKeyPair(generator, &keyPair);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(keyPair, nullptr);

    // encoded and convert key pair's pubKey
    HcfPubKey *pubKey = keyPair->pubKey;
    HcfBlob blob = { .data = nullptr, .len = 0 };
    res = pubKey->base.getEncoded(&(pubKey->base), &blob);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(blob.data, nullptr);
    EXPECT_NE(blob.len, 0);

    HcfAsyKeyGenerator *generatorConvert = nullptr;
    res = HcfAsyKeyGeneratorCreate("RSA8192", &generatorConvert);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(generatorConvert, nullptr);

    HcfKeyPair *dupKeyPair = nullptr;
    res = generatorConvert->convertKey(generatorConvert, nullptr, &blob, nullptr, &dupKeyPair);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_EQ(dupKeyPair->priKey, nullptr);
    EXPECT_NE(dupKeyPair->pubKey, nullptr);

    HcfBigInteger dupE = { .data = nullptr, .len = 0 };
    res = pubKey->getAsyKeySpecBigInteger(dupKeyPair->pubKey, RSA_PK_BN, &dupE);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(dupE.data, nullptr);
    EXPECT_NE(dupE.len, 0);
    res = memcmp(dupE.data, dataE, RSA_8192_E_BYTE_SIZE);
    EXPECT_EQ(res, 0);

    HcfFree(blob.data);
    HcfFree(dupE.data);
    HcfObjDestroy(keyPair);
    HcfObjDestroy(dupKeyPair);
    HcfObjDestroy(generator);
    HcfObjDestroy(generatorConvert);
}

HWTEST_F(CryptoRsa8192AsyKeyGeneratorBySpecTest, CryptoRsa8192AsyKeyGeneratorBySpecTest535, TestSize.Level0)
{
    HcfRsaKeyPairParamsSpec rsaPairSpec = {};
    unsigned char dataN[RSA_8192_N_BYTE_SIZE] = {0};
    unsigned char dataE[RSA_8192_E_BYTE_SIZE] = {0};
    unsigned char dataD[RSA_8192_D_BYTE_SIZE] = {0};
    GenerateRsa8192CorrectKeyPairSpec(dataN, dataE, dataD, &rsaPairSpec);

    HcfAsyKeyGeneratorBySpec *generator = nullptr;
    int32_t res = HcfAsyKeyGeneratorBySpecCreate(reinterpret_cast<HcfAsyKeyParamsSpec *>(&rsaPairSpec), &generator);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(generator, nullptr);

    EXPECT_EQ(CheckGeneratorBySpecKeyFunc(generator), true);
    HcfKeyPair *keyPair = nullptr;
    res = generator->generateKeyPair(generator, &keyPair);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(keyPair, nullptr);

    // encoded and convert key pair's pubKey
    HcfPubKey *pubKey = keyPair->pubKey;
    HcfBlob blob = { .data = nullptr, .len = 0 };
    res = pubKey->base.getEncoded(&(pubKey->base), &blob);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(blob.data, nullptr);
    EXPECT_NE(blob.len, 0);

    HcfAsyKeyGenerator *generatorConvert = nullptr;
    res = HcfAsyKeyGeneratorCreate("RSA8192", &generatorConvert);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(generatorConvert, nullptr);

    HcfKeyPair *dupKeyPair = nullptr;
    res = generatorConvert->convertKey(generatorConvert, nullptr, &blob, nullptr, &dupKeyPair);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_EQ(dupKeyPair->priKey, nullptr);
    EXPECT_NE(dupKeyPair->pubKey, nullptr);

    HcfBigInteger dupN = { .data = nullptr, .len = 0 };
    res = pubKey->getAsyKeySpecBigInteger(dupKeyPair->pubKey, RSA_N_BN, &dupN);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(dupN.data, nullptr);
    EXPECT_NE(dupN.len, 0);
    res = memcmp(dupN.data, dataN, RSA_8192_N_BYTE_SIZE);
    EXPECT_EQ(res, 0);

    HcfFree(blob.data);
    HcfFree(dupN.data);
    HcfObjDestroy(keyPair);
    HcfObjDestroy(dupKeyPair);
    HcfObjDestroy(generator);
    HcfObjDestroy(generatorConvert);
}

// check encoded pub key from key pair spec, convert to pub key object and check the get function
HWTEST_F(CryptoRsa8192AsyKeyGeneratorBySpecTest, CryptoRsa8192AsyKeyGeneratorBySpecTest536, TestSize.Level0)
{
    HcfRsaKeyPairParamsSpec rsaPairSpec = {};
    unsigned char dataN[RSA_8192_N_BYTE_SIZE] = {0};
    unsigned char dataE[RSA_8192_E_BYTE_SIZE] = {0};
    unsigned char dataD[RSA_8192_D_BYTE_SIZE] = {0};
    GenerateRsa8192CorrectKeyPairSpec(dataN, dataE, dataD, &rsaPairSpec);

    HcfAsyKeyGeneratorBySpec *generator = nullptr;
    int32_t res = HcfAsyKeyGeneratorBySpecCreate(reinterpret_cast<HcfAsyKeyParamsSpec *>(&rsaPairSpec), &generator);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(generator, nullptr);

    EXPECT_EQ(CheckGeneratorBySpecKeyFunc(generator), true);
    HcfPubKey *pubKey = nullptr;
    res = generator->generatePubKey(generator, &pubKey);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(pubKey, nullptr);

    // encoded and convert key pair's pubKey
    HcfBlob blob = { .data = nullptr, .len = 0 };
    res = pubKey->base.getEncoded(&(pubKey->base), &blob);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(blob.data, nullptr);
    EXPECT_NE(blob.len, 0);

    HcfAsyKeyGenerator *generatorConvert = nullptr;
    res = HcfAsyKeyGeneratorCreate("RSA8192", &generatorConvert);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(generatorConvert, nullptr);

    HcfKeyPair *dupKeyPair = nullptr;
    res = generatorConvert->convertKey(generatorConvert, nullptr, &blob, nullptr, &dupKeyPair);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_EQ(dupKeyPair->priKey, nullptr);
    EXPECT_NE(dupKeyPair->pubKey, nullptr);

    HcfBigInteger dupE = { .data = nullptr, .len = 0 };
    res = pubKey->getAsyKeySpecBigInteger(dupKeyPair->pubKey, RSA_PK_BN, &dupE);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(dupE.data, nullptr);
    EXPECT_NE(dupE.len, 0);
    res = memcmp(dupE.data, dataE, RSA_8192_E_BYTE_SIZE);
    EXPECT_EQ(res, 0);

    HcfFree(blob.data);
    HcfFree(dupE.data);
    HcfObjDestroy(pubKey);
    HcfObjDestroy(dupKeyPair);
    HcfObjDestroy(generator);
    HcfObjDestroy(generatorConvert);
}

HWTEST_F(CryptoRsa8192AsyKeyGeneratorBySpecTest, CryptoRsa8192AsyKeyGeneratorBySpecTest537, TestSize.Level0)
{
    HcfRsaKeyPairParamsSpec rsaPairSpec = {};
    unsigned char dataN[RSA_8192_N_BYTE_SIZE] = {0};
    unsigned char dataE[RSA_8192_E_BYTE_SIZE] = {0};
    unsigned char dataD[RSA_8192_D_BYTE_SIZE] = {0};
    GenerateRsa8192CorrectKeyPairSpec(dataN, dataE, dataD, &rsaPairSpec);

    HcfAsyKeyGeneratorBySpec *generator = nullptr;
    int32_t res = HcfAsyKeyGeneratorBySpecCreate(reinterpret_cast<HcfAsyKeyParamsSpec *>(&rsaPairSpec), &generator);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(generator, nullptr);

    EXPECT_EQ(CheckGeneratorBySpecKeyFunc(generator), true);
    HcfPubKey *pubKey = nullptr;
    res = generator->generatePubKey(generator, &pubKey);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(pubKey, nullptr);

    // encoded and convert key pair's pubKey
    HcfBlob blob = { .data = nullptr, .len = 0 };
    res = pubKey->base.getEncoded(&(pubKey->base), &blob);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(blob.data, nullptr);
    EXPECT_NE(blob.len, 0);

    HcfAsyKeyGenerator *generatorConvert = nullptr;
    res = HcfAsyKeyGeneratorCreate("RSA8192", &generatorConvert);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(generatorConvert, nullptr);

    HcfKeyPair *dupKeyPair = nullptr;
    res = generatorConvert->convertKey(generatorConvert, nullptr, &blob, nullptr, &dupKeyPair);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_EQ(dupKeyPair->priKey, nullptr);
    EXPECT_NE(dupKeyPair->pubKey, nullptr);

    HcfBigInteger dupN = { .data = nullptr, .len = 0 };
    res = pubKey->getAsyKeySpecBigInteger(dupKeyPair->pubKey, RSA_N_BN, &dupN);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(dupN.data, nullptr);
    EXPECT_NE(dupN.len, 0);
    res = memcmp(dupN.data, dataN, RSA_8192_N_BYTE_SIZE);
    EXPECT_EQ(res, 0);

    HcfFree(blob.data);
    HcfFree(dupN.data);
    HcfObjDestroy(pubKey);
    HcfObjDestroy(dupKeyPair);
    HcfObjDestroy(generator);
    HcfObjDestroy(generatorConvert);
}

// check encoded pub key from pubKey spec, convert to pub key object and check the get function
HWTEST_F(CryptoRsa8192AsyKeyGeneratorBySpecTest, CryptoRsa8192AsyKeyGeneratorBySpecTest538, TestSize.Level0)
{
    HcfRsaPubKeyParamsSpec rsaPubKeySpec = {};
    unsigned char dataN[RSA_8192_N_BYTE_SIZE] = {0};
    unsigned char dataE[RSA_8192_E_BYTE_SIZE] = {0};
    GenerateRsa8192CorrectPubKeySpec(dataN, dataE, &rsaPubKeySpec);
    HcfAsyKeyGeneratorBySpec *generator = nullptr;
    int32_t res = HcfAsyKeyGeneratorBySpecCreate(reinterpret_cast<HcfAsyKeyParamsSpec *>(&rsaPubKeySpec), &generator);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(generator, nullptr);

    EXPECT_EQ(CheckGeneratorBySpecKeyFunc(generator), true);
    HcfPubKey *pubKey = nullptr;
    res = generator->generatePubKey(generator, &pubKey);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(pubKey, nullptr);

    // encoded and convert pubKey
    HcfBlob blob = { .data = nullptr, .len = 0 };
    res = pubKey->base.getEncoded(&(pubKey->base), &blob);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(blob.data, nullptr);
    EXPECT_NE(blob.len, 0);

    HcfAsyKeyGenerator *generatorConvert = nullptr;
    res = HcfAsyKeyGeneratorCreate("RSA8192", &generatorConvert);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(generatorConvert, nullptr);

    HcfKeyPair *dupKeyPair = nullptr;
    res = generatorConvert->convertKey(generatorConvert, nullptr, &blob, nullptr, &dupKeyPair);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_EQ(dupKeyPair->priKey, nullptr);
    EXPECT_NE(dupKeyPair->pubKey, nullptr);

    HcfBigInteger dupE = { .data = nullptr, .len = 0 };
    res = pubKey->getAsyKeySpecBigInteger(dupKeyPair->pubKey, RSA_PK_BN, &dupE);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(dupE.data, nullptr);
    EXPECT_NE(dupE.len, 0);
    res = memcmp(dupE.data, dataE, RSA_8192_E_BYTE_SIZE);
    EXPECT_EQ(res, 0);

    HcfFree(blob.data);
    HcfFree(dupE.data);
    HcfObjDestroy(dupKeyPair);
    HcfObjDestroy(pubKey);
    HcfObjDestroy(generator);
    HcfObjDestroy(generatorConvert);
}

HWTEST_F(CryptoRsa8192AsyKeyGeneratorBySpecTest, CryptoRsa8192AsyKeyGeneratorBySpecTest539, TestSize.Level0)
{
    HcfRsaPubKeyParamsSpec rsaPubKeySpec = {};
    unsigned char dataN[RSA_8192_N_BYTE_SIZE] = {0};
    unsigned char dataE[RSA_8192_E_BYTE_SIZE] = {0};
    GenerateRsa8192CorrectPubKeySpec(dataN, dataE, &rsaPubKeySpec);
    HcfAsyKeyGeneratorBySpec *generator = nullptr;
    int32_t res = HcfAsyKeyGeneratorBySpecCreate(reinterpret_cast<HcfAsyKeyParamsSpec *>(&rsaPubKeySpec), &generator);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(generator, nullptr);

    EXPECT_EQ(CheckGeneratorBySpecKeyFunc(generator), true);
    HcfPubKey *pubKey = nullptr;
    res = generator->generatePubKey(generator, &pubKey);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(pubKey, nullptr);

    // encoded and convert pubKey
    HcfBlob blob = { .data = nullptr, .len = 0 };
    res = pubKey->base.getEncoded(&(pubKey->base), &blob);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(blob.data, nullptr);
    EXPECT_NE(blob.len, 0);

    HcfAsyKeyGenerator *generatorConvert = nullptr;
    res = HcfAsyKeyGeneratorCreate("RSA8192", &generatorConvert);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(generatorConvert, nullptr);

    HcfKeyPair *dupKeyPair = nullptr;
    res = generatorConvert->convertKey(generatorConvert, nullptr, &blob, nullptr, &dupKeyPair);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_EQ(dupKeyPair->priKey, nullptr);
    EXPECT_NE(dupKeyPair->pubKey, nullptr);

    HcfBigInteger dupN = { .data = nullptr, .len = 0 };
    res = pubKey->getAsyKeySpecBigInteger(dupKeyPair->pubKey, RSA_N_BN, &dupN);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(dupN.data, nullptr);
    EXPECT_NE(dupN.len, 0);
    res = memcmp(dupN.data, dataN, RSA_8192_N_BYTE_SIZE);
    EXPECT_EQ(res, 0);

    HcfFree(blob.data);
    HcfFree(dupN.data);
    HcfObjDestroy(dupKeyPair);
    HcfObjDestroy(pubKey);
    HcfObjDestroy(generator);
    HcfObjDestroy(generatorConvert);
}

// check invalid get key functions of key pair's pub key from key pair spec
HWTEST_F(CryptoRsa8192AsyKeyGeneratorBySpecTest, CryptoRsa8192AsyKeyGeneratorBySpecTest540, TestSize.Level0)
{
    HcfRsaKeyPairParamsSpec rsaPairSpec = {};
    unsigned char dataN[RSA_8192_N_BYTE_SIZE] = {0};
    unsigned char dataE[RSA_8192_E_BYTE_SIZE] = {0};
    unsigned char dataD[RSA_8192_D_BYTE_SIZE] = {0};
    GenerateRsa8192CorrectKeyPairSpec(dataN, dataE, dataD, &rsaPairSpec);

    HcfAsyKeyGeneratorBySpec *generator = nullptr;
    HcfResult res = HcfAsyKeyGeneratorBySpecCreate(reinterpret_cast<HcfAsyKeyParamsSpec *>(&rsaPairSpec), &generator);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(generator, nullptr);

    EXPECT_EQ(CheckGeneratorBySpecKeyFunc(generator), true);
    HcfKeyPair *keyPair = nullptr;
    res = generator->generateKeyPair(generator, &keyPair);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(keyPair, nullptr);

    EXPECT_NE(keyPair->pubKey->getAsyKeySpecInt, nullptr);

    HcfObjDestroy(keyPair);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoRsa8192AsyKeyGeneratorBySpecTest, CryptoRsa8192AsyKeyGeneratorBySpecTest541, TestSize.Level0)
{
    HcfRsaKeyPairParamsSpec rsaPairSpec = {};
    unsigned char dataN[RSA_8192_N_BYTE_SIZE] = {0};
    unsigned char dataE[RSA_8192_E_BYTE_SIZE] = {0};
    unsigned char dataD[RSA_8192_D_BYTE_SIZE] = {0};
    GenerateRsa8192CorrectKeyPairSpec(dataN, dataE, dataD, &rsaPairSpec);

    HcfAsyKeyGeneratorBySpec *generator = nullptr;
    HcfResult res = HcfAsyKeyGeneratorBySpecCreate(reinterpret_cast<HcfAsyKeyParamsSpec *>(&rsaPairSpec), &generator);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(generator, nullptr);

    EXPECT_EQ(CheckGeneratorBySpecKeyFunc(generator), true);
    HcfKeyPair *keyPair = nullptr;
    res = generator->generateKeyPair(generator, &keyPair);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(keyPair, nullptr);

    EXPECT_NE(keyPair->pubKey->getAsyKeySpecString, nullptr);

    HcfObjDestroy(keyPair);
    HcfObjDestroy(generator);
}

// check invalid get key functions of key pair's pri key from key pair spec
HWTEST_F(CryptoRsa8192AsyKeyGeneratorBySpecTest, CryptoRsa8192AsyKeyGeneratorBySpecTest542, TestSize.Level0)
{
    HcfRsaKeyPairParamsSpec rsaPairSpec = {};
    unsigned char dataN[RSA_8192_N_BYTE_SIZE] = {0};
    unsigned char dataE[RSA_8192_E_BYTE_SIZE] = {0};
    unsigned char dataD[RSA_8192_D_BYTE_SIZE] = {0};
    GenerateRsa8192CorrectKeyPairSpec(dataN, dataE, dataD, &rsaPairSpec);

    HcfAsyKeyGeneratorBySpec *generator = nullptr;
    HcfResult res = HcfAsyKeyGeneratorBySpecCreate(reinterpret_cast<HcfAsyKeyParamsSpec *>(&rsaPairSpec), &generator);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(generator, nullptr);

    EXPECT_EQ(CheckGeneratorBySpecKeyFunc(generator), true);
    HcfKeyPair *keyPair = nullptr;
    res = generator->generateKeyPair(generator, &keyPair);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(keyPair, nullptr);

    EXPECT_NE(keyPair->priKey->getAsyKeySpecInt, nullptr);

    keyPair->priKey->clearMem((HcfPriKey *)keyPair->pubKey);
    HcfObjDestroy(keyPair);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoRsa8192AsyKeyGeneratorBySpecTest, CryptoRsa8192AsyKeyGeneratorBySpecTest543, TestSize.Level0)
{
    HcfRsaKeyPairParamsSpec rsaPairSpec = {};
    unsigned char dataN[RSA_8192_N_BYTE_SIZE] = {0};
    unsigned char dataE[RSA_8192_E_BYTE_SIZE] = {0};
    unsigned char dataD[RSA_8192_D_BYTE_SIZE] = {0};
    GenerateRsa8192CorrectKeyPairSpec(dataN, dataE, dataD, &rsaPairSpec);

    HcfAsyKeyGeneratorBySpec *generator = nullptr;
    HcfResult res = HcfAsyKeyGeneratorBySpecCreate(reinterpret_cast<HcfAsyKeyParamsSpec *>(&rsaPairSpec), &generator);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(generator, nullptr);

    EXPECT_EQ(CheckGeneratorBySpecKeyFunc(generator), true);
    HcfKeyPair *keyPair = nullptr;
    res = generator->generateKeyPair(generator, &keyPair);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(keyPair, nullptr);

    EXPECT_NE(keyPair->priKey->getAsyKeySpecString, nullptr);

    keyPair->priKey->clearMem(keyPair->priKey);
    HcfObjDestroy(keyPair);
    HcfObjDestroy(generator);
}

// check invalid get key functions of pub key from key pair spec
HWTEST_F(CryptoRsa8192AsyKeyGeneratorBySpecTest, CryptoRsa8192AsyKeyGeneratorBySpecTest544, TestSize.Level0)
{
    HcfRsaKeyPairParamsSpec rsaPairSpec = {};
    unsigned char dataN[RSA_8192_N_BYTE_SIZE] = {0};
    unsigned char dataE[RSA_8192_E_BYTE_SIZE] = {0};
    unsigned char dataD[RSA_8192_D_BYTE_SIZE] = {0};
    GenerateRsa8192CorrectKeyPairSpec(dataN, dataE, dataD, &rsaPairSpec);

    HcfAsyKeyGeneratorBySpec *generator = nullptr;
    HcfResult res = HcfAsyKeyGeneratorBySpecCreate(reinterpret_cast<HcfAsyKeyParamsSpec *>(&rsaPairSpec), &generator);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(generator, nullptr);

    EXPECT_EQ(CheckGeneratorBySpecKeyFunc(generator), true);
    HcfPubKey *pubKey = nullptr;
    res = generator->generatePubKey(generator, &pubKey);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(pubKey, nullptr);

    EXPECT_NE(pubKey->getAsyKeySpecInt, nullptr);

    HcfObjDestroy(pubKey);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoRsa8192AsyKeyGeneratorBySpecTest, CryptoRsa8192AsyKeyGeneratorBySpecTest545, TestSize.Level0)
{
    HcfRsaKeyPairParamsSpec rsaPairSpec = {};
    unsigned char dataN[RSA_8192_N_BYTE_SIZE] = {0};
    unsigned char dataE[RSA_8192_E_BYTE_SIZE] = {0};
    unsigned char dataD[RSA_8192_D_BYTE_SIZE] = {0};
    GenerateRsa8192CorrectKeyPairSpec(dataN, dataE, dataD, &rsaPairSpec);

    HcfAsyKeyGeneratorBySpec *generator = nullptr;
    HcfResult res = HcfAsyKeyGeneratorBySpecCreate(reinterpret_cast<HcfAsyKeyParamsSpec *>(&rsaPairSpec), &generator);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(generator, nullptr);

    EXPECT_EQ(CheckGeneratorBySpecKeyFunc(generator), true);
    HcfPubKey *pubKey = nullptr;
    res = generator->generatePubKey(generator, &pubKey);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(pubKey, nullptr);

    EXPECT_NE(pubKey->getAsyKeySpecString, nullptr);

    HcfObjDestroy(pubKey);
    HcfObjDestroy(generator);
}

// check invalid get key functions of pri key from key pair spec
HWTEST_F(CryptoRsa8192AsyKeyGeneratorBySpecTest, CryptoRsa8192AsyKeyGeneratorBySpecTest546, TestSize.Level0)
{
    HcfRsaKeyPairParamsSpec rsaPairSpec = {};
    unsigned char dataN[RSA_8192_N_BYTE_SIZE] = {0};
    unsigned char dataE[RSA_8192_E_BYTE_SIZE] = {0};
    unsigned char dataD[RSA_8192_D_BYTE_SIZE] = {0};
    GenerateRsa8192CorrectKeyPairSpec(dataN, dataE, dataD, &rsaPairSpec);

    HcfAsyKeyGeneratorBySpec *generator = nullptr;
    HcfResult res = HcfAsyKeyGeneratorBySpecCreate(reinterpret_cast<HcfAsyKeyParamsSpec *>(&rsaPairSpec), &generator);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(generator, nullptr);

    EXPECT_EQ(CheckGeneratorBySpecKeyFunc(generator), true);
    HcfPriKey *priKey = nullptr;
    res = generator->generatePriKey(generator, &priKey);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(priKey, nullptr);

    EXPECT_NE(priKey->getAsyKeySpecInt, nullptr);

    priKey->clearMem(priKey);
    HcfObjDestroy(priKey);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoRsa8192AsyKeyGeneratorBySpecTest, CryptoRsa8192AsyKeyGeneratorBySpecTest547, TestSize.Level0)
{
    HcfRsaKeyPairParamsSpec rsaPairSpec = {};
    unsigned char dataN[RSA_8192_N_BYTE_SIZE] = {0};
    unsigned char dataE[RSA_8192_E_BYTE_SIZE] = {0};
    unsigned char dataD[RSA_8192_D_BYTE_SIZE] = {0};
    GenerateRsa8192CorrectKeyPairSpec(dataN, dataE, dataD, &rsaPairSpec);

    HcfAsyKeyGeneratorBySpec *generator = nullptr;
    HcfResult res = HcfAsyKeyGeneratorBySpecCreate(reinterpret_cast<HcfAsyKeyParamsSpec *>(&rsaPairSpec), &generator);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(generator, nullptr);

    EXPECT_EQ(CheckGeneratorBySpecKeyFunc(generator), true);
    HcfPriKey *priKey = nullptr;
    res = generator->generatePriKey(generator, &priKey);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(priKey, nullptr);

    EXPECT_NE(priKey->getAsyKeySpecString, nullptr);

    priKey->clearMem(priKey);
    HcfObjDestroy(priKey);
    HcfObjDestroy(generator);
}

// HcfAsyKeyGeneratorCreate correct case: RSA 8192 generate keyPair get all big int
HWTEST_F(CryptoRsa8192AsyKeyGeneratorBySpecTest, CryptoRsa8192AsyKeyGeneratorBySpecTest548, TestSize.Level0)
{
    HcfRsaKeyPairParamsSpec rsaPairSpec = {};
    unsigned char dataN[RSA_8192_N_BYTE_SIZE] = {0};
    unsigned char dataE[RSA_8192_E_BYTE_SIZE] = {0};
    unsigned char dataD[RSA_8192_D_BYTE_SIZE] = {0};
    GenerateRsa8192CorrectKeyPairSpec(dataN, dataE, dataD, &rsaPairSpec);

    HcfAsyKeyGeneratorBySpec *generator = nullptr;
    HcfResult res = HcfAsyKeyGeneratorBySpecCreate(reinterpret_cast<HcfAsyKeyParamsSpec *>(&rsaPairSpec), &generator);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(generator, nullptr);

    HcfKeyPair *keyPair = nullptr;
    // generator key type from generator's spec
    res = generator->generateKeyPair(generator, &keyPair);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(keyPair, nullptr);
    HcfPriKey *priKey = keyPair->priKey;
    HcfPubKey *pubKey = keyPair->pubKey;

    HcfBigInteger returnPubN = { .data = nullptr, .len = 0 };
    HcfBigInteger returnPriN = { .data = nullptr, .len = 0 };
    HcfBigInteger returnE = { .data = nullptr, .len = 0 };
    HcfBigInteger returnD = { .data = nullptr, .len = 0 };
    res = priKey->getAsyKeySpecBigInteger(priKey, RSA_N_BN, &returnPriN);
    EXPECT_EQ(res, HCF_SUCCESS);
    res = priKey->getAsyKeySpecBigInteger(priKey, RSA_SK_BN, &returnD);
    EXPECT_EQ(res, HCF_SUCCESS);
    res = pubKey->getAsyKeySpecBigInteger(pubKey, RSA_N_BN, &returnPubN);
    EXPECT_EQ(res, HCF_SUCCESS);
    res = pubKey->getAsyKeySpecBigInteger(pubKey, RSA_PK_BN, &returnE);
    EXPECT_EQ(res, HCF_SUCCESS);

    // check the array data
    int memRes = 0;
    memRes = memcmp(returnPubN.data, dataN, RSA_8192_N_BYTE_SIZE);
    EXPECT_EQ(memRes, 0);
    memRes = memcmp(returnPriN.data, dataN, RSA_8192_N_BYTE_SIZE);
    EXPECT_EQ(memRes, 0);
    memRes = memcmp(returnD.data, dataD, RSA_8192_D_BYTE_SIZE);
    EXPECT_EQ(memRes, 0);
    memRes = memcmp(returnE.data, dataE, RSA_8192_E_BYTE_SIZE);
    EXPECT_EQ(memRes, 0);

    HcfFree(returnPubN.data);
    HcfFree(returnPriN.data);
    HcfFree(returnD.data);
    HcfFree(returnE.data);
    HcfObjDestroy(keyPair);
    HcfObjDestroy(generator);
}

// HcfAsyKeyGeneratorCreate correct case: RSA 8192 generate pub key get
HWTEST_F(CryptoRsa8192AsyKeyGeneratorBySpecTest, CryptoRsa8192AsyKeyGeneratorBySpecTest549, TestSize.Level0)
{
    HcfRsaPubKeyParamsSpec rsaPubKeySpec = {};
    unsigned char dataN[RSA_8192_N_BYTE_SIZE] = {0};
    unsigned char dataE[RSA_8192_E_BYTE_SIZE] = {0};
    GenerateRsa8192CorrectPubKeySpec(dataN, dataE, &rsaPubKeySpec);
    HcfAsyKeyGeneratorBySpec *generator = nullptr;
    HcfResult res = HcfAsyKeyGeneratorBySpecCreate(reinterpret_cast<HcfAsyKeyParamsSpec *>(&rsaPubKeySpec), &generator);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(generator, nullptr);

    HcfPubKey *pubKey = nullptr;
    res = generator->generatePubKey(generator, &pubKey);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(pubKey, nullptr);

    HcfBigInteger returnPubN = { .data = nullptr, .len = 0 };
    HcfBigInteger returnE = { .data = nullptr, .len = 0 };
    res = pubKey->getAsyKeySpecBigInteger(pubKey, RSA_N_BN, &returnPubN);
    EXPECT_EQ(res, HCF_SUCCESS);
    res = pubKey->getAsyKeySpecBigInteger(pubKey, RSA_PK_BN, &returnE);
    EXPECT_EQ(res, HCF_SUCCESS);

    int memRes = 0;
    memRes = memcmp(returnPubN.data, dataN, RSA_8192_N_BYTE_SIZE);
    EXPECT_EQ(memRes, 0);
    memRes = memcmp(returnE.data, dataE, RSA_8192_E_BYTE_SIZE);
    EXPECT_EQ(memRes, 0);
    HcfFree(returnPubN.data);
    HcfFree(returnE.data);
    HcfObjDestroy(pubKey);
    HcfObjDestroy(generator);
}

// HcfAsyKeyGeneratorCreate incorrect case: RSA 8192 generate common key spec (not support)
HWTEST_F(CryptoRsa8192AsyKeyGeneratorBySpecTest, CryptoRsa8192AsyKeyGeneratorBySpecTest550, TestSize.Level0)
{
    HcfRsaCommParamsSpec rsaCommSpec = {};

    unsigned char dataN[RSA_8192_N_BYTE_SIZE] = {0};
    GenerateRsa8192CorrectCommonKeySpec(dataN, &rsaCommSpec);

    HcfAsyKeyGeneratorBySpec *generator = nullptr;
    HcfResult res = HcfAsyKeyGeneratorBySpecCreate(reinterpret_cast<HcfAsyKeyParamsSpec *>(&rsaCommSpec), &generator);
    EXPECT_NE(res, HCF_SUCCESS);
    EXPECT_EQ(generator, nullptr);
    HcfObjDestroy(generator);
}
}