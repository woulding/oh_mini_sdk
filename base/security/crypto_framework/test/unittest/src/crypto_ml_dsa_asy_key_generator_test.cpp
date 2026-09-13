/*
 * Copyright (C) 2026 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * *    http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include <gtest/gtest.h>
#include "securec.h"

#include "blob.h"
#include "params_parser.h"
#include "key_pair.h"
#include "object_base.h"
#include "asy_key_generator.h"
#include "pub_key.h"
#include "pri_key.h"
#include "memory.h"
#include "big_integer.h"
#include "key.h"

#include "ml_dsa_asy_key_generator_openssl.h"

using namespace std;
using namespace testing::ext;

namespace {
class CryptoMlDsaAsyKeyGeneratorTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp();
    void TearDown();
};

void CryptoMlDsaAsyKeyGeneratorTest::SetUpTestCase() {}
void CryptoMlDsaAsyKeyGeneratorTest::TearDownTestCase() {}
void CryptoMlDsaAsyKeyGeneratorTest::SetUp() {}
void CryptoMlDsaAsyKeyGeneratorTest::TearDown() {}

static string g_mlDsa44AlgoName = "ML-DSA-44";
static string g_mlDsa65AlgoName = "ML-DSA-65";
static string g_mlDsa87AlgoName = "ML-DSA-87";
static string g_pubkeyformatName = "X.509";
static string g_prikeyformatName = "PKCS#8";

// ==================== Basic key generation tests ====================

HWTEST_F(CryptoMlDsaAsyKeyGeneratorTest, CryptoMlDsa44GeneratorTest001, TestSize.Level0)
{
    HcfAsyKeyGenerator *generator = nullptr;
    HcfResult res = HcfAsyKeyGeneratorCreate(g_mlDsa44AlgoName.c_str(), &generator);
    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(generator, nullptr);

    HcfKeyPair *keyPair = nullptr;
    res = generator->generateKeyPair(generator, nullptr, &keyPair);
    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(keyPair, nullptr);

    const char *algoName = keyPair->pubKey->base.getAlgorithm(&(keyPair->pubKey->base));
    EXPECT_STREQ(algoName, "ML-DSA");

    const char *pubFormat = keyPair->pubKey->base.getFormat(&(keyPair->pubKey->base));
    EXPECT_STREQ(pubFormat, g_pubkeyformatName.c_str());

    const char *priFormat = keyPair->priKey->base.getFormat(&(keyPair->priKey->base));
    EXPECT_STREQ(priFormat, g_prikeyformatName.c_str());

    HcfObjDestroy(keyPair);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoMlDsaAsyKeyGeneratorTest, CryptoMlDsa65GeneratorTest001, TestSize.Level0)
{
    HcfAsyKeyGenerator *generator = nullptr;
    HcfResult res = HcfAsyKeyGeneratorCreate(g_mlDsa65AlgoName.c_str(), &generator);
    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(generator, nullptr);

    HcfKeyPair *keyPair = nullptr;
    res = generator->generateKeyPair(generator, nullptr, &keyPair);
    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(keyPair, nullptr);

    const char *algoName = keyPair->pubKey->base.getAlgorithm(&(keyPair->pubKey->base));
    EXPECT_STREQ(algoName, "ML-DSA");

    HcfObjDestroy(keyPair);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoMlDsaAsyKeyGeneratorTest, CryptoMlDsa87GeneratorTest001, TestSize.Level0)
{
    HcfAsyKeyGenerator *generator = nullptr;
    HcfResult res = HcfAsyKeyGeneratorCreate(g_mlDsa87AlgoName.c_str(), &generator);
    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(generator, nullptr);

    HcfKeyPair *keyPair = nullptr;
    res = generator->generateKeyPair(generator, nullptr, &keyPair);
    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(keyPair, nullptr);

    const char *algoName = keyPair->pubKey->base.getAlgorithm(&(keyPair->pubKey->base));
    EXPECT_STREQ(algoName, "ML-DSA");

    HcfObjDestroy(keyPair);
    HcfObjDestroy(generator);
}

// ==================== getEncoded tests ====================

HWTEST_F(CryptoMlDsaAsyKeyGeneratorTest, CryptoMlDsa65GetEncodedTest001, TestSize.Level0)
{
    HcfAsyKeyGenerator *generator = nullptr;
    HcfResult res = HcfAsyKeyGeneratorCreate(g_mlDsa65AlgoName.c_str(), &generator);
    ASSERT_EQ(res, HCF_SUCCESS);

    HcfKeyPair *keyPair = nullptr;
    res = generator->generateKeyPair(generator, nullptr, &keyPair);
    ASSERT_EQ(res, HCF_SUCCESS);

    HcfBlob pubKeyBlob = { .data = nullptr, .len = 0 };
    res = keyPair->pubKey->base.getEncoded(&(keyPair->pubKey->base), &pubKeyBlob);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_GT(pubKeyBlob.len, 0);
    EXPECT_NE(pubKeyBlob.data, nullptr);

    HcfBlob priKeyBlob = { .data = nullptr, .len = 0 };
    res = keyPair->priKey->base.getEncoded(&(keyPair->priKey->base), &priKeyBlob);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_GT(priKeyBlob.len, 0);
    EXPECT_NE(priKeyBlob.data, nullptr);

    HcfFree(pubKeyBlob.data);
    HcfFree(priKeyBlob.data);
    HcfObjDestroy(keyPair);
    HcfObjDestroy(generator);
}

// ==================== getAlgoName / getKeySize tests ====================

HWTEST_F(CryptoMlDsaAsyKeyGeneratorTest, CryptoMlDsaGetAlgoNameTest001, TestSize.Level0)
{
    HcfAsyKeyGenerator *generator = nullptr;
    HcfResult res = HcfAsyKeyGeneratorCreate(g_mlDsa65AlgoName.c_str(), &generator);
    ASSERT_EQ(res, HCF_SUCCESS);

    const char *algoName = generator->getAlgoName(generator);
    EXPECT_STREQ(algoName, g_mlDsa65AlgoName.c_str());

    HcfObjDestroy(generator);
}

HWTEST_F(CryptoMlDsaAsyKeyGeneratorTest, CryptoMlDsaGetKeySizeTest001, TestSize.Level0)
{
    HcfAsyKeyGenerator *generator = nullptr;
    HcfResult res = HcfAsyKeyGeneratorCreate(g_mlDsa65AlgoName.c_str(), &generator);
    ASSERT_EQ(res, HCF_SUCCESS);

    HcfKeyPair *keyPair = nullptr;
    res = generator->generateKeyPair(generator, nullptr, &keyPair);
    ASSERT_EQ(res, HCF_SUCCESS);

    int pubKeySize = 0;
    res = keyPair->pubKey->base.getKeySize(&(keyPair->pubKey->base), &pubKeySize);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_GT(pubKeySize, 0);

    int priKeySize = 0;
    res = keyPair->priKey->base.getKeySize(&(keyPair->priKey->base), &priKeySize);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_GT(priKeySize, 0);

    HcfObjDestroy(keyPair);
    HcfObjDestroy(generator);
}

// ==================== convertKey tests ====================

HWTEST_F(CryptoMlDsaAsyKeyGeneratorTest, CryptoMlDsa65ConvertKeyTest001, TestSize.Level0)
{
    HcfAsyKeyGenerator *generator = nullptr;
    HcfResult res = HcfAsyKeyGeneratorCreate(g_mlDsa65AlgoName.c_str(), &generator);
    ASSERT_EQ(res, HCF_SUCCESS);

    HcfKeyPair *keyPair = nullptr;
    res = generator->generateKeyPair(generator, nullptr, &keyPair);
    ASSERT_EQ(res, HCF_SUCCESS);

    HcfBlob pubKeyBlob = { .data = nullptr, .len = 0 };
    res = keyPair->pubKey->base.getEncoded(&(keyPair->pubKey->base), &pubKeyBlob);
    ASSERT_EQ(res, HCF_SUCCESS);

    HcfBlob priKeyBlob = { .data = nullptr, .len = 0 };
    res = keyPair->priKey->base.getEncoded(&(keyPair->priKey->base), &priKeyBlob);
    ASSERT_EQ(res, HCF_SUCCESS);

    HcfKeyPair *convertedKeyPair = nullptr;
    res = generator->convertKey(generator, nullptr, &pubKeyBlob, &priKeyBlob, &convertedKeyPair);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(convertedKeyPair, nullptr);

    HcfFree(pubKeyBlob.data);
    HcfFree(priKeyBlob.data);
    HcfObjDestroy(keyPair);
    HcfObjDestroy(convertedKeyPair);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoMlDsaAsyKeyGeneratorTest, CryptoMlDsaConvertKeyBothNullTest001, TestSize.Level0)
{
    HcfAsyKeyGenerator *generator = nullptr;
    HcfResult res = HcfAsyKeyGeneratorCreate(g_mlDsa65AlgoName.c_str(), &generator);
    ASSERT_EQ(res, HCF_SUCCESS);

    HcfKeyPair *convertedKeyPair = nullptr;
    res = generator->convertKey(generator, nullptr, nullptr, nullptr, &convertedKeyPair);
    EXPECT_EQ(res, HCF_ERR_PARAMETER_CHECK_FAILED);

    HcfObjDestroy(generator);
}

// ==================== Error handling tests ====================

HWTEST_F(CryptoMlDsaAsyKeyGeneratorTest, CryptoMlDsaCreateInvalidAlgoTest001, TestSize.Level0)
{
    HcfAsyKeyGenerator *generator = nullptr;
    HcfResult res = HcfAsyKeyGeneratorCreate("ML-DSA-128", &generator);
    EXPECT_NE(res, HCF_SUCCESS);
}

HWTEST_F(CryptoMlDsaAsyKeyGeneratorTest, CryptoMlDsaCreateNullAlgoTest001, TestSize.Level0)
{
    HcfAsyKeyGenerator *generator = nullptr;
    HcfResult res = HcfAsyKeyGeneratorCreate(nullptr, &generator);
    EXPECT_NE(res, HCF_SUCCESS);
}

// ==================== getEncodedDer tests ====================

HWTEST_F(CryptoMlDsaAsyKeyGeneratorTest, CryptoMlDsa65GetEncodedDerPubKeyTest001, TestSize.Level0)
{
    HcfAsyKeyGenerator *generator = nullptr;
    HcfResult res = HcfAsyKeyGeneratorCreate(g_mlDsa65AlgoName.c_str(), &generator);
    ASSERT_EQ(res, HCF_SUCCESS);

    HcfKeyPair *keyPair = nullptr;
    res = generator->generateKeyPair(generator, nullptr, &keyPair);
    ASSERT_EQ(res, HCF_SUCCESS);

    HcfBlob pubDerBlob = { .data = nullptr, .len = 0 };
    res = keyPair->pubKey->getEncodedDer(keyPair->pubKey, "X509", &pubDerBlob);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_GT(pubDerBlob.len, 0);
    EXPECT_NE(pubDerBlob.data, nullptr);

    HcfFree(pubDerBlob.data);
    HcfObjDestroy(keyPair);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoMlDsaAsyKeyGeneratorTest, CryptoMlDsa65GetEncodedDerPriKeyTest001, TestSize.Level0)
{
    HcfAsyKeyGenerator *generator = nullptr;
    HcfResult res = HcfAsyKeyGeneratorCreate(g_mlDsa65AlgoName.c_str(), &generator);
    ASSERT_EQ(res, HCF_SUCCESS);

    HcfKeyPair *keyPair = nullptr;
    res = generator->generateKeyPair(generator, nullptr, &keyPair);
    ASSERT_EQ(res, HCF_SUCCESS);

    HcfBlob priDerBlob = { .data = nullptr, .len = 0 };
    res = keyPair->priKey->getEncodedDer(keyPair->priKey, "PKCS8", &priDerBlob);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_GT(priDerBlob.len, 0);
    EXPECT_NE(priDerBlob.data, nullptr);

    HcfFree(priDerBlob.data);
    HcfObjDestroy(keyPair);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoMlDsaAsyKeyGeneratorTest, CryptoMlDsaGetEncodedDerInvalidFormatTest001, TestSize.Level0)
{
    HcfAsyKeyGenerator *generator = nullptr;
    HcfResult res = HcfAsyKeyGeneratorCreate(g_mlDsa65AlgoName.c_str(), &generator);
    ASSERT_EQ(res, HCF_SUCCESS);

    HcfKeyPair *keyPair = nullptr;
    res = generator->generateKeyPair(generator, nullptr, &keyPair);
    ASSERT_EQ(res, HCF_SUCCESS);

    HcfBlob blob = { .data = nullptr, .len = 0 };
    res = keyPair->pubKey->getEncodedDer(keyPair->pubKey, "PKCS8", &blob);
    EXPECT_NE(res, HCF_SUCCESS);

    res = keyPair->priKey->getEncodedDer(keyPair->priKey, "X509", &blob);
    EXPECT_NE(res, HCF_SUCCESS);

    HcfObjDestroy(keyPair);
    HcfObjDestroy(generator);
}

// ==================== getEncodedPem tests ====================

HWTEST_F(CryptoMlDsaAsyKeyGeneratorTest, CryptoMlDsa65GetEncodedPemPubKeyTest001, TestSize.Level0)
{
    HcfAsyKeyGenerator *generator = nullptr;
    HcfResult res = HcfAsyKeyGeneratorCreate(g_mlDsa65AlgoName.c_str(), &generator);
    ASSERT_EQ(res, HCF_SUCCESS);

    HcfKeyPair *keyPair = nullptr;
    res = generator->generateKeyPair(generator, nullptr, &keyPair);
    ASSERT_EQ(res, HCF_SUCCESS);

    char *pemStr = nullptr;
    res = keyPair->pubKey->base.getEncodedPem(&(keyPair->pubKey->base), "X509", &pemStr);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(pemStr, nullptr);
    EXPECT_GT(strlen(pemStr), 0);
    EXPECT_NE(strstr(pemStr, "BEGIN PUBLIC KEY"), nullptr);

    HcfFree(pemStr);
    HcfObjDestroy(keyPair);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoMlDsaAsyKeyGeneratorTest, CryptoMlDsa65GetEncodedPemPriKeyTest001, TestSize.Level0)
{
    HcfAsyKeyGenerator *generator = nullptr;
    HcfResult res = HcfAsyKeyGeneratorCreate(g_mlDsa65AlgoName.c_str(), &generator);
    ASSERT_EQ(res, HCF_SUCCESS);

    HcfKeyPair *keyPair = nullptr;
    res = generator->generateKeyPair(generator, nullptr, &keyPair);
    ASSERT_EQ(res, HCF_SUCCESS);

    char *pemStr = nullptr;
    res = keyPair->priKey->getEncodedPem(keyPair->priKey, nullptr, "PKCS8", &pemStr);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(pemStr, nullptr);
    EXPECT_GT(strlen(pemStr), 0);
    EXPECT_NE(strstr(pemStr, "BEGIN PRIVATE KEY"), nullptr);

    HcfFree(pemStr);
    HcfObjDestroy(keyPair);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoMlDsaAsyKeyGeneratorTest, CryptoMlDsaGetEncodedPemInvalidFormatTest001, TestSize.Level0)
{
    HcfAsyKeyGenerator *generator = nullptr;
    HcfResult res = HcfAsyKeyGeneratorCreate(g_mlDsa65AlgoName.c_str(), &generator);
    ASSERT_EQ(res, HCF_SUCCESS);

    HcfKeyPair *keyPair = nullptr;
    res = generator->generateKeyPair(generator, nullptr, &keyPair);
    ASSERT_EQ(res, HCF_SUCCESS);

    char *pemStr = nullptr;
    res = keyPair->pubKey->base.getEncodedPem(&(keyPair->pubKey->base), "PKCS8", &pemStr);
    EXPECT_NE(res, HCF_SUCCESS);

    res = keyPair->priKey->getEncodedPem(keyPair->priKey, nullptr, "X509", &pemStr);
    EXPECT_NE(res, HCF_SUCCESS);

    HcfObjDestroy(keyPair);
    HcfObjDestroy(generator);
}

// ==================== getKeyData tests ====================

HWTEST_F(CryptoMlDsaAsyKeyGeneratorTest, CryptoMlDsa65GetKeyDataTest001, TestSize.Level0)
{
    HcfAsyKeyGenerator *generator = nullptr;
    HcfResult res = HcfAsyKeyGeneratorCreate(g_mlDsa65AlgoName.c_str(), &generator);
    ASSERT_EQ(res, HCF_SUCCESS);

    HcfKeyPair *keyPair = nullptr;
    res = generator->generateKeyPair(generator, nullptr, &keyPair);
    ASSERT_EQ(res, HCF_SUCCESS);

    HcfBlob pubRawBlob = { .data = nullptr, .len = 0 };
    res = keyPair->pubKey->getKeyData(keyPair->pubKey, ML_DSA_PUBLIC_RAW, &pubRawBlob);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_EQ(pubRawBlob.len, 1952);

    HcfBlob priRawBlob = { .data = nullptr, .len = 0 };
    res = keyPair->priKey->getKeyData(keyPair->priKey, ML_DSA_PRIVATE_RAW, &priRawBlob);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_EQ(priRawBlob.len, 4032);

    HcfFree(pubRawBlob.data);
    HcfFree(priRawBlob.data);
    HcfObjDestroy(keyPair);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoMlDsaAsyKeyGeneratorTest, CryptoMlDsa44GetKeyDataTest001, TestSize.Level0)
{
    HcfAsyKeyGenerator *generator = nullptr;
    HcfResult res = HcfAsyKeyGeneratorCreate(g_mlDsa44AlgoName.c_str(), &generator);
    ASSERT_EQ(res, HCF_SUCCESS);

    HcfKeyPair *keyPair = nullptr;
    res = generator->generateKeyPair(generator, nullptr, &keyPair);
    ASSERT_EQ(res, HCF_SUCCESS);

    HcfBlob pubRawBlob = { .data = nullptr, .len = 0 };
    res = keyPair->pubKey->getKeyData(keyPair->pubKey, ML_DSA_PUBLIC_RAW, &pubRawBlob);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_EQ(pubRawBlob.len, 1312);

    HcfBlob priRawBlob = { .data = nullptr, .len = 0 };
    res = keyPair->priKey->getKeyData(keyPair->priKey, ML_DSA_PRIVATE_RAW, &priRawBlob);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_EQ(priRawBlob.len, 2560);

    HcfFree(pubRawBlob.data);
    HcfFree(priRawBlob.data);
    HcfObjDestroy(keyPair);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoMlDsaAsyKeyGeneratorTest, CryptoMlDsa87GetKeyDataTest001, TestSize.Level0)
{
    HcfAsyKeyGenerator *generator = nullptr;
    HcfResult res = HcfAsyKeyGeneratorCreate(g_mlDsa87AlgoName.c_str(), &generator);
    ASSERT_EQ(res, HCF_SUCCESS);

    HcfKeyPair *keyPair = nullptr;
    res = generator->generateKeyPair(generator, nullptr, &keyPair);
    ASSERT_EQ(res, HCF_SUCCESS);

    HcfBlob pubRawBlob = { .data = nullptr, .len = 0 };
    res = keyPair->pubKey->getKeyData(keyPair->pubKey, ML_DSA_PUBLIC_RAW, &pubRawBlob);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_EQ(pubRawBlob.len, 2592);

    HcfBlob priRawBlob = { .data = nullptr, .len = 0 };
    res = keyPair->priKey->getKeyData(keyPair->priKey, ML_DSA_PRIVATE_RAW, &priRawBlob);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_EQ(priRawBlob.len, 4896);

    HcfFree(pubRawBlob.data);
    HcfFree(priRawBlob.data);
    HcfObjDestroy(keyPair);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoMlDsaAsyKeyGeneratorTest, CryptoMlDsaGetKeyDataInvalidTypeTest001, TestSize.Level0)
{
    HcfAsyKeyGenerator *generator = nullptr;
    HcfResult res = HcfAsyKeyGeneratorCreate(g_mlDsa65AlgoName.c_str(), &generator);
    ASSERT_EQ(res, HCF_SUCCESS);

    HcfKeyPair *keyPair = nullptr;
    res = generator->generateKeyPair(generator, nullptr, &keyPair);
    ASSERT_EQ(res, HCF_SUCCESS);

    HcfBlob blob = { .data = nullptr, .len = 0 };
    res = keyPair->pubKey->getKeyData(keyPair->pubKey, 99, &blob);
    EXPECT_NE(res, HCF_SUCCESS);

    res = keyPair->priKey->getKeyData(keyPair->priKey, 99, &blob);
    EXPECT_NE(res, HCF_SUCCESS);

    HcfObjDestroy(keyPair);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoMlDsaAsyKeyGeneratorTest, CryptoMlDsa65GetKeyDataPrivateSeedTest001, TestSize.Level0)
{
    HcfAsyKeyGenerator *generator = nullptr;
    HcfResult res = HcfAsyKeyGeneratorCreate(g_mlDsa65AlgoName.c_str(), &generator);
    ASSERT_EQ(res, HCF_SUCCESS);

    HcfKeyPair *keyPair = nullptr;
    res = generator->generateKeyPair(generator, nullptr, &keyPair);
    ASSERT_EQ(res, HCF_SUCCESS);

    HcfBlob seedBlob = { .data = nullptr, .len = 0 };
    res = keyPair->priKey->getKeyData(keyPair->priKey, ML_DSA_PRIVATE_SEED, &seedBlob);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_EQ(seedBlob.len, 32);
    EXPECT_NE(seedBlob.data, nullptr);

    HcfFree(seedBlob.data);
    HcfObjDestroy(keyPair);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoMlDsaAsyKeyGeneratorTest, CryptoMlDsa44GetKeyDataPrivateSeedTest001, TestSize.Level0)
{
    HcfAsyKeyGenerator *generator = nullptr;
    HcfResult res = HcfAsyKeyGeneratorCreate(g_mlDsa44AlgoName.c_str(), &generator);
    ASSERT_EQ(res, HCF_SUCCESS);

    HcfKeyPair *keyPair = nullptr;
    res = generator->generateKeyPair(generator, nullptr, &keyPair);
    ASSERT_EQ(res, HCF_SUCCESS);

    HcfBlob seedBlob = { .data = nullptr, .len = 0 };
    res = keyPair->priKey->getKeyData(keyPair->priKey, ML_DSA_PRIVATE_SEED, &seedBlob);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_EQ(seedBlob.len, 32);

    HcfFree(seedBlob.data);
    HcfObjDestroy(keyPair);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoMlDsaAsyKeyGeneratorTest, CryptoMlDsa87GetKeyDataPrivateSeedTest001, TestSize.Level0)
{
    HcfAsyKeyGenerator *generator = nullptr;
    HcfResult res = HcfAsyKeyGeneratorCreate(g_mlDsa87AlgoName.c_str(), &generator);
    ASSERT_EQ(res, HCF_SUCCESS);

    HcfKeyPair *keyPair = nullptr;
    res = generator->generateKeyPair(generator, nullptr, &keyPair);
    ASSERT_EQ(res, HCF_SUCCESS);

    HcfBlob seedBlob = { .data = nullptr, .len = 0 };
    res = keyPair->priKey->getKeyData(keyPair->priKey, ML_DSA_PRIVATE_SEED, &seedBlob);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_EQ(seedBlob.len, 32);

    HcfFree(seedBlob.data);
    HcfObjDestroy(keyPair);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoMlDsaAsyKeyGeneratorTest, CryptoMlDsa65SeedIsPrefixOfRawTest001, TestSize.Level0)
{
    HcfAsyKeyGenerator *generator = nullptr;
    HcfResult res = HcfAsyKeyGeneratorCreate(g_mlDsa65AlgoName.c_str(), &generator);
    ASSERT_EQ(res, HCF_SUCCESS);

    HcfKeyPair *keyPair = nullptr;
    res = generator->generateKeyPair(generator, nullptr, &keyPair);
    ASSERT_EQ(res, HCF_SUCCESS);

    HcfBlob seedBlob = { .data = nullptr, .len = 0 };
    res = keyPair->priKey->getKeyData(keyPair->priKey, ML_DSA_PRIVATE_SEED, &seedBlob);
    ASSERT_EQ(res, HCF_SUCCESS);

    HcfBlob rawBlob = { .data = nullptr, .len = 0 };
    res = keyPair->priKey->getKeyData(keyPair->priKey, ML_DSA_PRIVATE_RAW, &rawBlob);
    ASSERT_EQ(res, HCF_SUCCESS);

    EXPECT_EQ(memcmp(seedBlob.data, rawBlob.data, seedBlob.len), 0);

    HcfFree(seedBlob.data);
    HcfFree(rawBlob.data);
    HcfObjDestroy(keyPair);
    HcfObjDestroy(generator);
}

// ==================== getPubKey from priKey tests ====================

HWTEST_F(CryptoMlDsaAsyKeyGeneratorTest, CryptoMlDsa65GetPubKeyFromPriKeyTest001, TestSize.Level0)
{
    HcfAsyKeyGenerator *generator = nullptr;
    HcfResult res = HcfAsyKeyGeneratorCreate(g_mlDsa65AlgoName.c_str(), &generator);
    ASSERT_EQ(res, HCF_SUCCESS);

    HcfKeyPair *keyPair = nullptr;
    res = generator->generateKeyPair(generator, nullptr, &keyPair);
    ASSERT_EQ(res, HCF_SUCCESS);

    HcfBlob originalPubBlob = { .data = nullptr, .len = 0 };
    res = keyPair->pubKey->base.getEncoded(&(keyPair->pubKey->base), &originalPubBlob);
    ASSERT_EQ(res, HCF_SUCCESS);

    HcfPubKey *extractedPubKey = nullptr;
    res = keyPair->priKey->getPubKey(keyPair->priKey, &extractedPubKey);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(extractedPubKey, nullptr);

    HcfBlob extractedPubBlob = { .data = nullptr, .len = 0 };
    res = extractedPubKey->base.getEncoded(&(extractedPubKey->base), &extractedPubBlob);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_EQ(originalPubBlob.len, extractedPubBlob.len);
    EXPECT_EQ(memcmp(originalPubBlob.data, extractedPubBlob.data, originalPubBlob.len), 0);

    HcfFree(originalPubBlob.data);
    HcfFree(extractedPubBlob.data);
    HcfObjDestroy(extractedPubKey);
    HcfObjDestroy(keyPair);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoMlDsaAsyKeyGeneratorTest, CryptoMlDsaGetPubKeyFromPriKeyNullParamTest001, TestSize.Level0)
{
    HcfAsyKeyGenerator *generator = nullptr;
    HcfResult res = HcfAsyKeyGeneratorCreate(g_mlDsa65AlgoName.c_str(), &generator);
    ASSERT_EQ(res, HCF_SUCCESS);

    HcfKeyPair *keyPair = nullptr;
    res = generator->generateKeyPair(generator, nullptr, &keyPair);
    ASSERT_EQ(res, HCF_SUCCESS);

    HcfPubKey *pubKey = nullptr;
    res = keyPair->priKey->getPubKey(nullptr, &pubKey);
    EXPECT_NE(res, HCF_SUCCESS);

    res = keyPair->priKey->getPubKey(keyPair->priKey, nullptr);
    EXPECT_NE(res, HCF_SUCCESS);

    HcfObjDestroy(keyPair);
    HcfObjDestroy(generator);
}

// ==================== getAsyKeySpecBigInteger tests ====================

HWTEST_F(CryptoMlDsaAsyKeyGeneratorTest, CryptoMlDsa65GetAsyKeySpecBigIntegerTest001, TestSize.Level0)
{
    HcfAsyKeyGenerator *generator = nullptr;
    HcfResult res = HcfAsyKeyGeneratorCreate(g_mlDsa65AlgoName.c_str(), &generator);
    ASSERT_EQ(res, HCF_SUCCESS);

    HcfKeyPair *keyPair = nullptr;
    res = generator->generateKeyPair(generator, nullptr, &keyPair);
    ASSERT_EQ(res, HCF_SUCCESS);

    HcfBigInteger pubBigInt = { .data = nullptr, .len = 0 };
    res = keyPair->pubKey->getAsyKeySpecBigInteger(keyPair->pubKey, ML_DSA_65_PK_BN, &pubBigInt);
    EXPECT_EQ(res, HCF_ERR_INVALID_CALL);

    HcfBigInteger priBigInt = { .data = nullptr, .len = 0 };
    res = keyPair->priKey->getAsyKeySpecBigInteger(keyPair->priKey, ML_DSA_65_SK_BN, &priBigInt);
    EXPECT_EQ(res, HCF_ERR_INVALID_CALL);

    HcfObjDestroy(keyPair);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoMlDsaAsyKeyGeneratorTest, CryptoMlDsa44GetAsyKeySpecBigIntegerTest001, TestSize.Level0)
{
    HcfAsyKeyGenerator *generator = nullptr;
    HcfResult res = HcfAsyKeyGeneratorCreate(g_mlDsa44AlgoName.c_str(), &generator);
    ASSERT_EQ(res, HCF_SUCCESS);

    HcfKeyPair *keyPair = nullptr;
    res = generator->generateKeyPair(generator, nullptr, &keyPair);
    ASSERT_EQ(res, HCF_SUCCESS);

    HcfBigInteger pubBigInt = { .data = nullptr, .len = 0 };
    res = keyPair->pubKey->getAsyKeySpecBigInteger(keyPair->pubKey, ML_DSA_44_PK_BN, &pubBigInt);
    EXPECT_EQ(res, HCF_ERR_INVALID_CALL);

    HcfBigInteger priBigInt = { .data = nullptr, .len = 0 };
    res = keyPair->priKey->getAsyKeySpecBigInteger(keyPair->priKey, ML_DSA_44_SK_BN, &priBigInt);
    EXPECT_EQ(res, HCF_ERR_INVALID_CALL);

    HcfObjDestroy(keyPair);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoMlDsaAsyKeyGeneratorTest, CryptoMlDsa87GetAsyKeySpecBigIntegerTest001, TestSize.Level0)
{
    HcfAsyKeyGenerator *generator = nullptr;
    HcfResult res = HcfAsyKeyGeneratorCreate(g_mlDsa87AlgoName.c_str(), &generator);
    ASSERT_EQ(res, HCF_SUCCESS);

    HcfKeyPair *keyPair = nullptr;
    res = generator->generateKeyPair(generator, nullptr, &keyPair);
    ASSERT_EQ(res, HCF_SUCCESS);

    HcfBigInteger pubBigInt = { .data = nullptr, .len = 0 };
    res = keyPair->pubKey->getAsyKeySpecBigInteger(keyPair->pubKey, ML_DSA_87_PK_BN, &pubBigInt);
    EXPECT_EQ(res, HCF_ERR_INVALID_CALL);

    HcfBigInteger priBigInt = { .data = nullptr, .len = 0 };
    res = keyPair->priKey->getAsyKeySpecBigInteger(keyPair->priKey, ML_DSA_87_SK_BN, &priBigInt);
    EXPECT_EQ(res, HCF_ERR_INVALID_CALL);

    HcfObjDestroy(keyPair);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoMlDsaAsyKeyGeneratorTest, CryptoMlDsaGetAsyKeySpecBigIntegerInvalidItemTest001, TestSize.Level0)
{
    HcfAsyKeyGenerator *generator = nullptr;
    HcfResult res = HcfAsyKeyGeneratorCreate(g_mlDsa65AlgoName.c_str(), &generator);
    ASSERT_EQ(res, HCF_SUCCESS);

    HcfKeyPair *keyPair = nullptr;
    res = generator->generateKeyPair(generator, nullptr, &keyPair);
    ASSERT_EQ(res, HCF_SUCCESS);

    HcfBigInteger bigInt = { .data = nullptr, .len = 0 };
    res = keyPair->pubKey->getAsyKeySpecBigInteger(keyPair->pubKey, ML_DSA_44_PK_BN, &bigInt);
    EXPECT_EQ(res, HCF_ERR_INVALID_CALL);

    res = keyPair->priKey->getAsyKeySpecBigInteger(keyPair->priKey, ML_DSA_44_SK_BN, &bigInt);
    EXPECT_EQ(res, HCF_ERR_INVALID_CALL);

    HcfObjDestroy(keyPair);
    HcfObjDestroy(generator);
}

// ==================== getAsyKeySpecInt/String not support tests ====================

HWTEST_F(CryptoMlDsaAsyKeyGeneratorTest, CryptoMlDsaGetAsyKeySpecIntNotSupportTest001, TestSize.Level0)
{
    HcfAsyKeyGenerator *generator = nullptr;
    HcfResult res = HcfAsyKeyGeneratorCreate(g_mlDsa65AlgoName.c_str(), &generator);
    ASSERT_EQ(res, HCF_SUCCESS);

    HcfKeyPair *keyPair = nullptr;
    res = generator->generateKeyPair(generator, nullptr, &keyPair);
    ASSERT_EQ(res, HCF_SUCCESS);

    int returnInt = 0;
    res = keyPair->pubKey->getAsyKeySpecInt(keyPair->pubKey, ML_DSA_65_PK_BN, &returnInt);
    EXPECT_EQ(res, HCF_ERR_INVALID_CALL);

    res = keyPair->priKey->getAsyKeySpecInt(keyPair->priKey, ML_DSA_65_SK_BN, &returnInt);
    EXPECT_EQ(res, HCF_ERR_INVALID_CALL);

    HcfObjDestroy(keyPair);
    HcfObjDestroy(generator);
}

// ==================== DER round-trip test ====================

HWTEST_F(CryptoMlDsaAsyKeyGeneratorTest, CryptoMlDsa65DerRoundTripTest001, TestSize.Level0)
{
    HcfAsyKeyGenerator *generator = nullptr;
    HcfResult res = HcfAsyKeyGeneratorCreate(g_mlDsa65AlgoName.c_str(), &generator);
    ASSERT_EQ(res, HCF_SUCCESS);

    HcfKeyPair *keyPair = nullptr;
    res = generator->generateKeyPair(generator, nullptr, &keyPair);
    ASSERT_EQ(res, HCF_SUCCESS);

    HcfBlob pubDerBlob = { .data = nullptr, .len = 0 };
    res = keyPair->pubKey->getEncodedDer(keyPair->pubKey, "X509", &pubDerBlob);
    ASSERT_EQ(res, HCF_SUCCESS);

    HcfBlob priDerBlob = { .data = nullptr, .len = 0 };
    res = keyPair->priKey->getEncodedDer(keyPair->priKey, "PKCS8", &priDerBlob);
    ASSERT_EQ(res, HCF_SUCCESS);

    HcfKeyPair *restoredKeyPair = nullptr;
    res = generator->convertKey(generator, nullptr, &pubDerBlob, &priDerBlob, &restoredKeyPair);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(restoredKeyPair, nullptr);

    HcfBlob restoredPubDer = { .data = nullptr, .len = 0 };
    restoredKeyPair->pubKey->getEncodedDer(restoredKeyPair->pubKey, "X509", &restoredPubDer);
    EXPECT_EQ(pubDerBlob.len, restoredPubDer.len);
    EXPECT_EQ(memcmp(pubDerBlob.data, restoredPubDer.data, pubDerBlob.len), 0);

    HcfFree(pubDerBlob.data);
    HcfFree(priDerBlob.data);
    HcfFree(restoredPubDer.data);
    HcfObjDestroy(keyPair);
    HcfObjDestroy(restoredKeyPair);
    HcfObjDestroy(generator);
}

// ==================== Cross-validation: getPubKey matches getKeyData ====================

HWTEST_F(CryptoMlDsaAsyKeyGeneratorTest, CryptoMlDsa65GetPubKeyCrossValidateTest001, TestSize.Level0)
{
    HcfAsyKeyGenerator *generator = nullptr;
    HcfResult res = HcfAsyKeyGeneratorCreate(g_mlDsa65AlgoName.c_str(), &generator);
    ASSERT_EQ(res, HCF_SUCCESS);

    HcfKeyPair *keyPair = nullptr;
    res = generator->generateKeyPair(generator, nullptr, &keyPair);
    ASSERT_EQ(res, HCF_SUCCESS);

    HcfBlob originalRawPub = { .data = nullptr, .len = 0 };
    res = keyPair->pubKey->getKeyData(keyPair->pubKey, ML_DSA_PUBLIC_RAW, &originalRawPub);
    ASSERT_EQ(res, HCF_SUCCESS);

    HcfPubKey *extractedPubKey = nullptr;
    res = keyPair->priKey->getPubKey(keyPair->priKey, &extractedPubKey);
    ASSERT_EQ(res, HCF_SUCCESS);

    HcfBlob extractedRawPub = { .data = nullptr, .len = 0 };
    res = extractedPubKey->getKeyData(extractedPubKey, ML_DSA_PUBLIC_RAW, &extractedRawPub);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_EQ(originalRawPub.len, extractedRawPub.len);
    EXPECT_EQ(memcmp(originalRawPub.data, extractedRawPub.data, originalRawPub.len), 0);

    HcfFree(originalRawPub.data);
    HcfFree(extractedRawPub.data);
    HcfObjDestroy(extractedPubKey);
    HcfObjDestroy(keyPair);
    HcfObjDestroy(generator);
}

// ==================== clearMem test ====================

HWTEST_F(CryptoMlDsaAsyKeyGeneratorTest, CryptoMlDsaClearMemTest001, TestSize.Level0)
{
    HcfAsyKeyGenerator *generator = nullptr;
    HcfResult res = HcfAsyKeyGeneratorCreate(g_mlDsa65AlgoName.c_str(), &generator);
    ASSERT_EQ(res, HCF_SUCCESS);

    HcfKeyPair *keyPair = nullptr;
    res = generator->generateKeyPair(generator, nullptr, &keyPair);
    ASSERT_EQ(res, HCF_SUCCESS);

    keyPair->priKey->clearMem(keyPair->priKey);

    HcfObjDestroy(keyPair);
    HcfObjDestroy(generator);
}

// ==================== Generate key pair twice, verify different ====================

HWTEST_F(CryptoMlDsaAsyKeyGeneratorTest, CryptoMlDsaGenerateKeyPairTwiceTest001, TestSize.Level0)
{
    HcfAsyKeyGenerator *generator = nullptr;
    HcfResult res = HcfAsyKeyGeneratorCreate(g_mlDsa65AlgoName.c_str(), &generator);
    ASSERT_EQ(res, HCF_SUCCESS);

    HcfKeyPair *keyPair1 = nullptr;
    res = generator->generateKeyPair(generator, nullptr, &keyPair1);
    ASSERT_EQ(res, HCF_SUCCESS);

    HcfKeyPair *keyPair2 = nullptr;
    res = generator->generateKeyPair(generator, nullptr, &keyPair2);
    ASSERT_EQ(res, HCF_SUCCESS);

    HcfBlob pub1 = { .data = nullptr, .len = 0 };
    keyPair1->pubKey->base.getEncoded(&(keyPair1->pubKey->base), &pub1);

    HcfBlob pub2 = { .data = nullptr, .len = 0 };
    keyPair2->pubKey->base.getEncoded(&(keyPair2->pubKey->base), &pub2);

    EXPECT_EQ(pub1.len, pub2.len);
    bool keyDifferent = (memcmp(pub1.data, pub2.data, pub1.len) != 0);
    EXPECT_TRUE(keyDifferent);

    HcfFree(pub1.data);
    HcfFree(pub2.data);
    HcfObjDestroy(keyPair1);
    HcfObjDestroy(keyPair2);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoMlDsaAsyKeyGeneratorTest, CryptoMlDsaGetKeyDataECTypeTest001, TestSize.Level0)
{
    HcfAsyKeyGenerator *generator = nullptr;
    HcfResult res = HcfAsyKeyGeneratorCreate(g_mlDsa65AlgoName.c_str(), &generator);
    ASSERT_EQ(res, HCF_SUCCESS);

    HcfKeyPair *keyPair = nullptr;
    res = generator->generateKeyPair(generator, nullptr, &keyPair);
    ASSERT_EQ(res, HCF_SUCCESS);

    HcfBlob blob = { .data = nullptr, .len = 0 };
    res = keyPair->pubKey->getKeyData(keyPair->pubKey, 8, &blob);
    EXPECT_NE(res, HCF_SUCCESS);

    res = keyPair->priKey->getKeyData(keyPair->priKey, 6, &blob);
    EXPECT_NE(res, HCF_SUCCESS);

    res = keyPair->priKey->getKeyData(keyPair->priKey, 7, &blob);
    EXPECT_NE(res, HCF_SUCCESS);

    HcfObjDestroy(keyPair);
    HcfObjDestroy(generator);
}

// ==================== convertKey error tests (JS#21, JS#22) ====================

HWTEST_F(CryptoMlDsaAsyKeyGeneratorTest, CryptoMlDsaConvertKeyWrongLengthTest001, TestSize.Level0)
{
    HcfAsyKeyGenerator *generator = nullptr;
    HcfResult res = HcfAsyKeyGeneratorCreate(g_mlDsa65AlgoName.c_str(), &generator);
    ASSERT_EQ(res, HCF_SUCCESS);

    uint8_t fakeData[] = {0x01, 0x02, 0x03, 0x04};
    HcfBlob wrongPubBlob = { .data = fakeData, .len = sizeof(fakeData) };
    HcfKeyPair *keyPair = nullptr;
    res = generator->convertKey(generator, nullptr, &wrongPubBlob, nullptr, &keyPair);
    EXPECT_NE(res, HCF_SUCCESS);

    HcfBlob wrongPriBlob = { .data = fakeData, .len = sizeof(fakeData) };
    res = generator->convertKey(generator, nullptr, nullptr, &wrongPriBlob, &keyPair);
    EXPECT_NE(res, HCF_SUCCESS);

    HcfObjDestroy(generator);
}

HWTEST_F(CryptoMlDsaAsyKeyGeneratorTest, CryptoMlDsaConvertKeyCrossAlgoTest001, TestSize.Level0)
{
    HcfAsyKeyGenerator *mlDsaGen = nullptr;
    HcfResult res = HcfAsyKeyGeneratorCreate(g_mlDsa65AlgoName.c_str(), &mlDsaGen);
    ASSERT_EQ(res, HCF_SUCCESS);

    HcfKeyPair *mlDsaKeyPair = nullptr;
    res = mlDsaGen->generateKeyPair(mlDsaGen, nullptr, &mlDsaKeyPair);
    ASSERT_EQ(res, HCF_SUCCESS);

    HcfBlob mlDsaPubBlob = { .data = nullptr, .len = 0 };
    res = mlDsaKeyPair->pubKey->base.getEncoded(&(mlDsaKeyPair->pubKey->base), &mlDsaPubBlob);
    ASSERT_EQ(res, HCF_SUCCESS);

    HcfAsyKeyGenerator *mlKemGen = nullptr;
    res = HcfAsyKeyGeneratorCreate("ML-KEM-768", &mlKemGen);
    ASSERT_EQ(res, HCF_SUCCESS);

    HcfKeyPair *crossKeyPair = nullptr;
    res = mlKemGen->convertKey(mlKemGen, nullptr, &mlDsaPubBlob, nullptr, &crossKeyPair);
    EXPECT_NE(res, HCF_SUCCESS);

    HcfFree(mlDsaPubBlob.data);
    HcfObjDestroy(mlDsaKeyPair);
    HcfObjDestroy(mlDsaGen);
    HcfObjDestroy(mlKemGen);
}

// ==================== convertKey with RAW key data (JS#15, JS#18) ====================

HWTEST_F(CryptoMlDsaAsyKeyGeneratorTest, CryptoMlDsa65ConvertKeyRawPubKeyTest001, TestSize.Level0)
{
    HcfAsyKeyGenerator *gen1 = nullptr;
    HcfResult res = HcfAsyKeyGeneratorCreate(g_mlDsa65AlgoName.c_str(), &gen1);
    ASSERT_EQ(res, HCF_SUCCESS);

    HcfKeyPair *keyPair1 = nullptr;
    res = gen1->generateKeyPair(gen1, nullptr, &keyPair1);
    ASSERT_EQ(res, HCF_SUCCESS);

    HcfBlob pubRawBlob = { .data = nullptr, .len = 0 };
    res = keyPair1->pubKey->getKeyData(keyPair1->pubKey, ML_DSA_PUBLIC_RAW, &pubRawBlob);
    ASSERT_EQ(res, HCF_SUCCESS);

    HcfAsyKeyGenerator *gen2 = nullptr;
    res = HcfAsyKeyGeneratorCreate(g_mlDsa65AlgoName.c_str(), &gen2);
    ASSERT_EQ(res, HCF_SUCCESS);

    HcfKeyPair *keyPair2 = nullptr;
    res = gen2->convertKey(gen2, nullptr, &pubRawBlob, nullptr, &keyPair2);
    ASSERT_EQ(res, HCF_SUCCESS);

    HcfBlob convertedPubRaw = { .data = nullptr, .len = 0 };
    res = keyPair2->pubKey->getKeyData(keyPair2->pubKey, ML_DSA_PUBLIC_RAW, &convertedPubRaw);
    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_EQ(pubRawBlob.len, convertedPubRaw.len);
    ASSERT_EQ(memcmp(pubRawBlob.data, convertedPubRaw.data, pubRawBlob.len), 0);

    HcfFree(convertedPubRaw.data);
    HcfFree(pubRawBlob.data);
    HcfObjDestroy(keyPair2);
    HcfObjDestroy(keyPair1);
    HcfObjDestroy(gen1);
    HcfObjDestroy(gen2);
}

HWTEST_F(CryptoMlDsaAsyKeyGeneratorTest, CryptoMlDsa65ConvertKeyRawKeyPairTest001, TestSize.Level0)
{
    HcfAsyKeyGenerator *gen1 = nullptr;
    HcfResult res = HcfAsyKeyGeneratorCreate(g_mlDsa65AlgoName.c_str(), &gen1);
    ASSERT_EQ(res, HCF_SUCCESS);

    HcfKeyPair *keyPair1 = nullptr;
    res = gen1->generateKeyPair(gen1, nullptr, &keyPair1);
    ASSERT_EQ(res, HCF_SUCCESS);

    HcfBlob pubRawBlob = { .data = nullptr, .len = 0 };
    res = keyPair1->pubKey->getKeyData(keyPair1->pubKey, ML_DSA_PUBLIC_RAW, &pubRawBlob);
    ASSERT_EQ(res, HCF_SUCCESS);

    HcfBlob priRawBlob = { .data = nullptr, .len = 0 };
    res = keyPair1->priKey->getKeyData(keyPair1->priKey, ML_DSA_PRIVATE_RAW, &priRawBlob);
    ASSERT_EQ(res, HCF_SUCCESS);

    HcfAsyKeyGenerator *gen2 = nullptr;
    res = HcfAsyKeyGeneratorCreate(g_mlDsa65AlgoName.c_str(), &gen2);
    ASSERT_EQ(res, HCF_SUCCESS);

    HcfKeyPair *keyPair2 = nullptr;
    res = gen2->convertKey(gen2, nullptr, &pubRawBlob, &priRawBlob, &keyPair2);
    ASSERT_EQ(res, HCF_SUCCESS);

    HcfBlob convertedPubRaw = { .data = nullptr, .len = 0 };
    res = keyPair2->pubKey->getKeyData(keyPair2->pubKey, ML_DSA_PUBLIC_RAW, &convertedPubRaw);
    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_EQ(pubRawBlob.len, convertedPubRaw.len);
    ASSERT_EQ(memcmp(pubRawBlob.data, convertedPubRaw.data, pubRawBlob.len), 0);
    HcfFree(convertedPubRaw.data);

    HcfBlob convertedPriRaw = { .data = nullptr, .len = 0 };
    res = keyPair2->priKey->getKeyData(keyPair2->priKey, ML_DSA_PRIVATE_RAW, &convertedPriRaw);
    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_EQ(priRawBlob.len, convertedPriRaw.len);
    ASSERT_EQ(memcmp(priRawBlob.data, convertedPriRaw.data, priRawBlob.len), 0);
    HcfFree(convertedPriRaw.data);

    HcfFree(pubRawBlob.data);
    HcfFree(priRawBlob.data);
    HcfObjDestroy(keyPair2);
    HcfObjDestroy(keyPair1);
    HcfObjDestroy(gen1);
    HcfObjDestroy(gen2);
}

HWTEST_F(CryptoMlDsaAsyKeyGeneratorTest, CryptoMlDsa65ConvertKeySeedDataTest001, TestSize.Level0)
{
    HcfAsyKeyGenerator *gen1 = nullptr;
    HcfResult res = HcfAsyKeyGeneratorCreate(g_mlDsa65AlgoName.c_str(), &gen1);
    ASSERT_EQ(res, HCF_SUCCESS);

    HcfKeyPair *keyPair1 = nullptr;
    res = gen1->generateKeyPair(gen1, nullptr, &keyPair1);
    ASSERT_EQ(res, HCF_SUCCESS);

    HcfBlob pubRawBlob = { .data = nullptr, .len = 0 };
    res = keyPair1->pubKey->getKeyData(keyPair1->pubKey, ML_DSA_PUBLIC_RAW, &pubRawBlob);
    ASSERT_EQ(res, HCF_SUCCESS);

    HcfBlob seedBlob = { .data = nullptr, .len = 0 };
    res = keyPair1->priKey->getKeyData(keyPair1->priKey, ML_DSA_PRIVATE_SEED, &seedBlob);
    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_EQ(seedBlob.len, 32);

    HcfAsyKeyGenerator *gen2 = nullptr;
    res = HcfAsyKeyGeneratorCreate(g_mlDsa65AlgoName.c_str(), &gen2);
    ASSERT_EQ(res, HCF_SUCCESS);

    HcfKeyPair *keyPair2 = nullptr;
    res = gen2->convertKey(gen2, nullptr, &pubRawBlob, &seedBlob, &keyPair2);
    ASSERT_EQ(res, HCF_SUCCESS);

    HcfBlob convertedPubRaw = { .data = nullptr, .len = 0 };
    res = keyPair2->pubKey->getKeyData(keyPair2->pubKey, ML_DSA_PUBLIC_RAW, &convertedPubRaw);
    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_EQ(pubRawBlob.len, convertedPubRaw.len);
    ASSERT_EQ(memcmp(pubRawBlob.data, convertedPubRaw.data, pubRawBlob.len), 0);

    HcfFree(convertedPubRaw.data);
    HcfFree(pubRawBlob.data);
    HcfFree(seedBlob.data);
    HcfObjDestroy(keyPair2);
    HcfObjDestroy(keyPair1);
    HcfObjDestroy(gen1);
    HcfObjDestroy(gen2);
}

// ==================== convertKey seed length error (JS#24) ====================

HWTEST_F(CryptoMlDsaAsyKeyGeneratorTest, CryptoMlDsaConvertKeyWrongSeedLengthTest001, TestSize.Level0)
{
    HcfAsyKeyGenerator *gen = nullptr;
    HcfResult res = HcfAsyKeyGeneratorCreate(g_mlDsa65AlgoName.c_str(), &gen);
    ASSERT_EQ(res, HCF_SUCCESS);

    HcfKeyPair *keyPair = nullptr;
    res = gen->generateKeyPair(gen, nullptr, &keyPair);
    ASSERT_EQ(res, HCF_SUCCESS);

    HcfBlob pubRawBlob = { .data = nullptr, .len = 0 };
    res = keyPair->pubKey->getKeyData(keyPair->pubKey, ML_DSA_PUBLIC_RAW, &pubRawBlob);
    ASSERT_EQ(res, HCF_SUCCESS);

    uint8_t shortSeed[16] = {0};
    HcfBlob shortSeedBlob = { .data = shortSeed, .len = sizeof(shortSeed) };
    HcfKeyPair *badKeyPair = nullptr;
    res = gen->convertKey(gen, nullptr, &pubRawBlob, &shortSeedBlob, &badKeyPair);
    EXPECT_NE(res, HCF_SUCCESS);

    uint8_t longSeed[64] = {0};
    HcfBlob longSeedBlob = { .data = longSeed, .len = sizeof(longSeed) };
    res = gen->convertKey(gen, nullptr, &pubRawBlob, &longSeedBlob, &badKeyPair);
    EXPECT_NE(res, HCF_SUCCESS);

    HcfFree(pubRawBlob.data);
    HcfObjDestroy(keyPair);
    HcfObjDestroy(gen);
}

// ==================== getAsyKeySpecBigInteger all variants ====================

HWTEST_F(CryptoMlDsaAsyKeyGeneratorTest, CryptoMlDsaAllSizesGetAsyKeySpecBigIntegerTest001, TestSize.Level0)
{
    HcfAsyKeyGenerator *gen44 = nullptr;
    HcfResult res = HcfAsyKeyGeneratorCreate(g_mlDsa44AlgoName.c_str(), &gen44);
    ASSERT_EQ(res, HCF_SUCCESS);
    HcfKeyPair *kp44 = nullptr;
    res = gen44->generateKeyPair(gen44, nullptr, &kp44);
    ASSERT_EQ(res, HCF_SUCCESS);
    HcfBigInteger bigInt44 = { .data = nullptr, .len = 0 };
    res = kp44->pubKey->getAsyKeySpecBigInteger(kp44->pubKey, ML_DSA_44_PK_BN, &bigInt44);
    EXPECT_EQ(res, HCF_ERR_INVALID_CALL);
    HcfObjDestroy(kp44);
    HcfObjDestroy(gen44);

    HcfAsyKeyGenerator *gen87 = nullptr;
    res = HcfAsyKeyGeneratorCreate(g_mlDsa87AlgoName.c_str(), &gen87);
    ASSERT_EQ(res, HCF_SUCCESS);
    HcfKeyPair *kp87 = nullptr;
    res = gen87->generateKeyPair(gen87, nullptr, &kp87);
    ASSERT_EQ(res, HCF_SUCCESS);
    HcfBigInteger bigInt87 = { .data = nullptr, .len = 0 };
    res = kp87->pubKey->getAsyKeySpecBigInteger(kp87->pubKey, ML_DSA_87_PK_BN, &bigInt87);
    EXPECT_EQ(res, HCF_ERR_INVALID_CALL);
    HcfObjDestroy(kp87);
    HcfObjDestroy(gen87);
}

// ==================== convertPemKey round-trip tests ====================

HWTEST_F(CryptoMlDsaAsyKeyGeneratorTest, CryptoMlDsa65ConvertPemKeyTest001, TestSize.Level0)
{
    HcfAsyKeyGenerator *gen = nullptr;
    HcfResult res = HcfAsyKeyGeneratorCreate(g_mlDsa65AlgoName.c_str(), &gen);
    ASSERT_EQ(res, HCF_SUCCESS);

    HcfKeyPair *keyPair = nullptr;
    res = gen->generateKeyPair(gen, nullptr, &keyPair);
    ASSERT_EQ(res, HCF_SUCCESS);

    char *pubPemStr = nullptr;
    res = keyPair->pubKey->base.getEncodedPem(&(keyPair->pubKey->base), "X509", &pubPemStr);
    ASSERT_EQ(res, HCF_SUCCESS);

    char *priPemStr = nullptr;
    res = keyPair->priKey->getEncodedPem(keyPair->priKey, nullptr, "PKCS8", &priPemStr);
    ASSERT_EQ(res, HCF_SUCCESS);

    HcfKeyPair *dupKeyPair = nullptr;
    res = gen->convertPemKey(gen, nullptr, pubPemStr, priPemStr, &dupKeyPair);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(dupKeyPair, nullptr);

    HcfKeyPair *dupPubOnly = nullptr;
    res = gen->convertPemKey(gen, nullptr, pubPemStr, nullptr, &dupPubOnly);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(dupPubOnly, nullptr);

    HcfKeyPair *dupPriOnly = nullptr;
    res = gen->convertPemKey(gen, nullptr, nullptr, priPemStr, &dupPriOnly);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(dupPriOnly, nullptr);

    HcfFree(pubPemStr);
    HcfFree(priPemStr);
    HcfObjDestroy(keyPair);
    HcfObjDestroy(dupKeyPair);
    HcfObjDestroy(dupPubOnly);
    HcfObjDestroy(dupPriOnly);
    HcfObjDestroy(gen);
}

HWTEST_F(CryptoMlDsaAsyKeyGeneratorTest, CryptoMlDsa65ConvertPemKeyNegativeTest001, TestSize.Level0)
{
    HcfAsyKeyGenerator *gen = nullptr;
    HcfResult res = HcfAsyKeyGeneratorCreate(g_mlDsa65AlgoName.c_str(), &gen);
    ASSERT_EQ(res, HCF_SUCCESS);

    HcfKeyPair *keyPair = nullptr;
    res = gen->convertPemKey(gen, nullptr, nullptr, nullptr, &keyPair);
    EXPECT_NE(res, HCF_SUCCESS);

    res = gen->convertPemKey(gen, nullptr, "invalid_pub", "invalid_pri", &keyPair);
    EXPECT_NE(res, HCF_SUCCESS);

    HcfObjDestroy(gen);
}

HWTEST_F(CryptoMlDsaAsyKeyGeneratorTest, CryptoMlDsa44ConvertKeyRawPubKeyTest001, TestSize.Level0)
{
    HcfAsyKeyGenerator *gen1 = nullptr;
    HcfResult res = HcfAsyKeyGeneratorCreate(g_mlDsa44AlgoName.c_str(), &gen1);
    ASSERT_EQ(res, HCF_SUCCESS);

    HcfKeyPair *keyPair1 = nullptr;
    res = gen1->generateKeyPair(gen1, nullptr, &keyPair1);
    ASSERT_EQ(res, HCF_SUCCESS);

    HcfBlob pubRawBlob = { .data = nullptr, .len = 0 };
    res = keyPair1->pubKey->getKeyData(keyPair1->pubKey, ML_DSA_PUBLIC_RAW, &pubRawBlob);
    ASSERT_EQ(res, HCF_SUCCESS);

    HcfAsyKeyGenerator *gen2 = nullptr;
    res = HcfAsyKeyGeneratorCreate(g_mlDsa44AlgoName.c_str(), &gen2);
    ASSERT_EQ(res, HCF_SUCCESS);

    HcfKeyPair *keyPair2 = nullptr;
    res = gen2->convertKey(gen2, nullptr, &pubRawBlob, nullptr, &keyPair2);
    ASSERT_EQ(res, HCF_SUCCESS);

    HcfBlob convertedPubRaw = { .data = nullptr, .len = 0 };
    res = keyPair2->pubKey->getKeyData(keyPair2->pubKey, ML_DSA_PUBLIC_RAW, &convertedPubRaw);
    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_EQ(pubRawBlob.len, convertedPubRaw.len);
    ASSERT_EQ(memcmp(pubRawBlob.data, convertedPubRaw.data, pubRawBlob.len), 0);

    HcfFree(convertedPubRaw.data);
    HcfFree(pubRawBlob.data);
    HcfObjDestroy(keyPair2);
    HcfObjDestroy(keyPair1);
    HcfObjDestroy(gen1);
    HcfObjDestroy(gen2);
}

HWTEST_F(CryptoMlDsaAsyKeyGeneratorTest, CryptoMlDsa44ConvertKeyRawKeyPairTest001, TestSize.Level0)
{
    HcfAsyKeyGenerator *gen1 = nullptr;
    HcfResult res = HcfAsyKeyGeneratorCreate(g_mlDsa44AlgoName.c_str(), &gen1);
    ASSERT_EQ(res, HCF_SUCCESS);

    HcfKeyPair *keyPair1 = nullptr;
    res = gen1->generateKeyPair(gen1, nullptr, &keyPair1);
    ASSERT_EQ(res, HCF_SUCCESS);

    HcfBlob pubRawBlob = { .data = nullptr, .len = 0 };
    res = keyPair1->pubKey->getKeyData(keyPair1->pubKey, ML_DSA_PUBLIC_RAW, &pubRawBlob);
    ASSERT_EQ(res, HCF_SUCCESS);

    HcfBlob priRawBlob = { .data = nullptr, .len = 0 };
    res = keyPair1->priKey->getKeyData(keyPair1->priKey, ML_DSA_PRIVATE_RAW, &priRawBlob);
    ASSERT_EQ(res, HCF_SUCCESS);

    HcfAsyKeyGenerator *gen2 = nullptr;
    res = HcfAsyKeyGeneratorCreate(g_mlDsa44AlgoName.c_str(), &gen2);
    ASSERT_EQ(res, HCF_SUCCESS);

    HcfKeyPair *keyPair2 = nullptr;
    res = gen2->convertKey(gen2, nullptr, &pubRawBlob, &priRawBlob, &keyPair2);
    ASSERT_EQ(res, HCF_SUCCESS);

    HcfBlob convertedPubRaw = { .data = nullptr, .len = 0 };
    res = keyPair2->pubKey->getKeyData(keyPair2->pubKey, ML_DSA_PUBLIC_RAW, &convertedPubRaw);
    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_EQ(pubRawBlob.len, convertedPubRaw.len);
    ASSERT_EQ(memcmp(pubRawBlob.data, convertedPubRaw.data, pubRawBlob.len), 0);
    HcfFree(convertedPubRaw.data);

    HcfBlob convertedPriRaw = { .data = nullptr, .len = 0 };
    res = keyPair2->priKey->getKeyData(keyPair2->priKey, ML_DSA_PRIVATE_RAW, &convertedPriRaw);
    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_EQ(priRawBlob.len, convertedPriRaw.len);
    ASSERT_EQ(memcmp(priRawBlob.data, convertedPriRaw.data, priRawBlob.len), 0);
    HcfFree(convertedPriRaw.data);

    HcfFree(pubRawBlob.data);
    HcfFree(priRawBlob.data);
    HcfObjDestroy(keyPair2);
    HcfObjDestroy(keyPair1);
    HcfObjDestroy(gen1);
    HcfObjDestroy(gen2);
}

HWTEST_F(CryptoMlDsaAsyKeyGeneratorTest, CryptoMlDsa44ConvertKeySeedDataTest001, TestSize.Level0)
{
    HcfAsyKeyGenerator *gen1 = nullptr;
    HcfResult res = HcfAsyKeyGeneratorCreate(g_mlDsa44AlgoName.c_str(), &gen1);
    ASSERT_EQ(res, HCF_SUCCESS);

    HcfKeyPair *keyPair1 = nullptr;
    res = gen1->generateKeyPair(gen1, nullptr, &keyPair1);
    ASSERT_EQ(res, HCF_SUCCESS);

    HcfBlob pubRawBlob = { .data = nullptr, .len = 0 };
    res = keyPair1->pubKey->getKeyData(keyPair1->pubKey, ML_DSA_PUBLIC_RAW, &pubRawBlob);
    ASSERT_EQ(res, HCF_SUCCESS);

    HcfBlob seedBlob = { .data = nullptr, .len = 0 };
    res = keyPair1->priKey->getKeyData(keyPair1->priKey, ML_DSA_PRIVATE_SEED, &seedBlob);
    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_EQ(seedBlob.len, 32);

    HcfAsyKeyGenerator *gen2 = nullptr;
    res = HcfAsyKeyGeneratorCreate(g_mlDsa44AlgoName.c_str(), &gen2);
    ASSERT_EQ(res, HCF_SUCCESS);

    HcfKeyPair *keyPair2 = nullptr;
    res = gen2->convertKey(gen2, nullptr, &pubRawBlob, &seedBlob, &keyPair2);
    ASSERT_EQ(res, HCF_SUCCESS);

    HcfBlob convertedPubRaw = { .data = nullptr, .len = 0 };
    res = keyPair2->pubKey->getKeyData(keyPair2->pubKey, ML_DSA_PUBLIC_RAW, &convertedPubRaw);
    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_EQ(pubRawBlob.len, convertedPubRaw.len);
    ASSERT_EQ(memcmp(pubRawBlob.data, convertedPubRaw.data, pubRawBlob.len), 0);

    HcfFree(convertedPubRaw.data);
    HcfFree(pubRawBlob.data);
    HcfFree(seedBlob.data);
    HcfObjDestroy(keyPair2);
    HcfObjDestroy(keyPair1);
    HcfObjDestroy(gen1);
    HcfObjDestroy(gen2);
}

HWTEST_F(CryptoMlDsaAsyKeyGeneratorTest, CryptoMlDsa87ConvertKeyRawPubKeyTest001, TestSize.Level0)
{
    HcfAsyKeyGenerator *gen1 = nullptr;
    HcfResult res = HcfAsyKeyGeneratorCreate(g_mlDsa87AlgoName.c_str(), &gen1);
    ASSERT_EQ(res, HCF_SUCCESS);

    HcfKeyPair *keyPair1 = nullptr;
    res = gen1->generateKeyPair(gen1, nullptr, &keyPair1);
    ASSERT_EQ(res, HCF_SUCCESS);

    HcfBlob pubRawBlob = { .data = nullptr, .len = 0 };
    res = keyPair1->pubKey->getKeyData(keyPair1->pubKey, ML_DSA_PUBLIC_RAW, &pubRawBlob);
    ASSERT_EQ(res, HCF_SUCCESS);

    HcfAsyKeyGenerator *gen2 = nullptr;
    res = HcfAsyKeyGeneratorCreate(g_mlDsa87AlgoName.c_str(), &gen2);
    ASSERT_EQ(res, HCF_SUCCESS);

    HcfKeyPair *keyPair2 = nullptr;
    res = gen2->convertKey(gen2, nullptr, &pubRawBlob, nullptr, &keyPair2);
    ASSERT_EQ(res, HCF_SUCCESS);

    HcfBlob convertedPubRaw = { .data = nullptr, .len = 0 };
    res = keyPair2->pubKey->getKeyData(keyPair2->pubKey, ML_DSA_PUBLIC_RAW, &convertedPubRaw);
    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_EQ(pubRawBlob.len, convertedPubRaw.len);
    ASSERT_EQ(memcmp(pubRawBlob.data, convertedPubRaw.data, pubRawBlob.len), 0);

    HcfFree(convertedPubRaw.data);
    HcfFree(pubRawBlob.data);
    HcfObjDestroy(keyPair2);
    HcfObjDestroy(keyPair1);
    HcfObjDestroy(gen1);
    HcfObjDestroy(gen2);
}

HWTEST_F(CryptoMlDsaAsyKeyGeneratorTest, CryptoMlDsa87ConvertKeyRawKeyPairTest001, TestSize.Level0)
{
    HcfAsyKeyGenerator *gen1 = nullptr;
    HcfResult res = HcfAsyKeyGeneratorCreate(g_mlDsa87AlgoName.c_str(), &gen1);
    ASSERT_EQ(res, HCF_SUCCESS);

    HcfKeyPair *keyPair1 = nullptr;
    res = gen1->generateKeyPair(gen1, nullptr, &keyPair1);
    ASSERT_EQ(res, HCF_SUCCESS);

    HcfBlob pubRawBlob = { .data = nullptr, .len = 0 };
    res = keyPair1->pubKey->getKeyData(keyPair1->pubKey, ML_DSA_PUBLIC_RAW, &pubRawBlob);
    ASSERT_EQ(res, HCF_SUCCESS);

    HcfBlob priRawBlob = { .data = nullptr, .len = 0 };
    res = keyPair1->priKey->getKeyData(keyPair1->priKey, ML_DSA_PRIVATE_RAW, &priRawBlob);
    ASSERT_EQ(res, HCF_SUCCESS);

    HcfAsyKeyGenerator *gen2 = nullptr;
    res = HcfAsyKeyGeneratorCreate(g_mlDsa87AlgoName.c_str(), &gen2);
    ASSERT_EQ(res, HCF_SUCCESS);

    HcfKeyPair *keyPair2 = nullptr;
    res = gen2->convertKey(gen2, nullptr, &pubRawBlob, &priRawBlob, &keyPair2);
    ASSERT_EQ(res, HCF_SUCCESS);

    HcfBlob convertedPubRaw = { .data = nullptr, .len = 0 };
    res = keyPair2->pubKey->getKeyData(keyPair2->pubKey, ML_DSA_PUBLIC_RAW, &convertedPubRaw);
    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_EQ(pubRawBlob.len, convertedPubRaw.len);
    ASSERT_EQ(memcmp(pubRawBlob.data, convertedPubRaw.data, pubRawBlob.len), 0);
    HcfFree(convertedPubRaw.data);

    HcfBlob convertedPriRaw = { .data = nullptr, .len = 0 };
    res = keyPair2->priKey->getKeyData(keyPair2->priKey, ML_DSA_PRIVATE_RAW, &convertedPriRaw);
    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_EQ(priRawBlob.len, convertedPriRaw.len);
    ASSERT_EQ(memcmp(priRawBlob.data, convertedPriRaw.data, priRawBlob.len), 0);
    HcfFree(convertedPriRaw.data);

    HcfFree(pubRawBlob.data);
    HcfFree(priRawBlob.data);
    HcfObjDestroy(keyPair2);
    HcfObjDestroy(keyPair1);
    HcfObjDestroy(gen1);
    HcfObjDestroy(gen2);
}

HWTEST_F(CryptoMlDsaAsyKeyGeneratorTest, CryptoMlDsa87ConvertKeySeedDataTest001, TestSize.Level0)
{
    HcfAsyKeyGenerator *gen1 = nullptr;
    HcfResult res = HcfAsyKeyGeneratorCreate(g_mlDsa87AlgoName.c_str(), &gen1);
    ASSERT_EQ(res, HCF_SUCCESS);

    HcfKeyPair *keyPair1 = nullptr;
    res = gen1->generateKeyPair(gen1, nullptr, &keyPair1);
    ASSERT_EQ(res, HCF_SUCCESS);

    HcfBlob pubRawBlob = { .data = nullptr, .len = 0 };
    res = keyPair1->pubKey->getKeyData(keyPair1->pubKey, ML_DSA_PUBLIC_RAW, &pubRawBlob);
    ASSERT_EQ(res, HCF_SUCCESS);

    HcfBlob seedBlob = { .data = nullptr, .len = 0 };
    res = keyPair1->priKey->getKeyData(keyPair1->priKey, ML_DSA_PRIVATE_SEED, &seedBlob);
    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_EQ(seedBlob.len, 32);

    HcfAsyKeyGenerator *gen2 = nullptr;
    res = HcfAsyKeyGeneratorCreate(g_mlDsa87AlgoName.c_str(), &gen2);
    ASSERT_EQ(res, HCF_SUCCESS);

    HcfKeyPair *keyPair2 = nullptr;
    res = gen2->convertKey(gen2, nullptr, &pubRawBlob, &seedBlob, &keyPair2);
    ASSERT_EQ(res, HCF_SUCCESS);

    HcfBlob convertedPubRaw = { .data = nullptr, .len = 0 };
    res = keyPair2->pubKey->getKeyData(keyPair2->pubKey, ML_DSA_PUBLIC_RAW, &convertedPubRaw);
    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_EQ(pubRawBlob.len, convertedPubRaw.len);
    ASSERT_EQ(memcmp(pubRawBlob.data, convertedPubRaw.data, pubRawBlob.len), 0);

    HcfFree(convertedPubRaw.data);
    HcfFree(pubRawBlob.data);
    HcfFree(seedBlob.data);
    HcfObjDestroy(keyPair2);
    HcfObjDestroy(keyPair1);
    HcfObjDestroy(gen1);
    HcfObjDestroy(gen2);
}
}
