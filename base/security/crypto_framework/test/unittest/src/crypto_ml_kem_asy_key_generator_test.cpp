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

#include "ml_kem_asy_key_generator_openssl.h"

using namespace std;
using namespace testing::ext;

namespace {
class CryptoMlKemAsyKeyGeneratorTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp();
    void TearDown();
};

void CryptoMlKemAsyKeyGeneratorTest::SetUpTestCase() {}
void CryptoMlKemAsyKeyGeneratorTest::TearDownTestCase() {}
void CryptoMlKemAsyKeyGeneratorTest::SetUp() {}
void CryptoMlKemAsyKeyGeneratorTest::TearDown() {}

static string g_mlKem512AlgoName = "ML-KEM-512";
static string g_mlKem768AlgoName = "ML-KEM-768";
static string g_mlKem1024AlgoName = "ML-KEM-1024";
static string g_pubkeyformatName = "X.509";
static string g_prikeyformatName = "PKCS#8";

HWTEST_F(CryptoMlKemAsyKeyGeneratorTest, CryptoMlKem512GeneratorTest001, TestSize.Level0)
{
    HcfAsyKeyGenerator *generator = nullptr;
    HcfResult res = HcfAsyKeyGeneratorCreate(g_mlKem512AlgoName.c_str(), &generator);
    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(generator, nullptr);

    HcfKeyPair *keyPair = nullptr;
    res = generator->generateKeyPair(generator, nullptr, &keyPair);
    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(keyPair, nullptr);

    const char *algoName = keyPair->pubKey->base.getAlgorithm(&(keyPair->pubKey->base));
    EXPECT_STREQ(algoName, "ML-KEM");

    const char *pubFormat = keyPair->pubKey->base.getFormat(&(keyPair->pubKey->base));
    EXPECT_STREQ(pubFormat, g_pubkeyformatName.c_str());

    const char *priFormat = keyPair->priKey->base.getFormat(&(keyPair->priKey->base));
    EXPECT_STREQ(priFormat, g_prikeyformatName.c_str());

    HcfObjDestroy(keyPair);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoMlKemAsyKeyGeneratorTest, CryptoMlKem768GeneratorTest001, TestSize.Level0)
{
    HcfAsyKeyGenerator *generator = nullptr;
    HcfResult res = HcfAsyKeyGeneratorCreate(g_mlKem768AlgoName.c_str(), &generator);
    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(generator, nullptr);

    HcfKeyPair *keyPair = nullptr;
    res = generator->generateKeyPair(generator, nullptr, &keyPair);
    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(keyPair, nullptr);

    const char *algoName = keyPair->pubKey->base.getAlgorithm(&(keyPair->pubKey->base));
    EXPECT_STREQ(algoName, "ML-KEM");

    HcfObjDestroy(keyPair);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoMlKemAsyKeyGeneratorTest, CryptoMlKem1024GeneratorTest001, TestSize.Level0)
{
    HcfAsyKeyGenerator *generator = nullptr;
    HcfResult res = HcfAsyKeyGeneratorCreate(g_mlKem1024AlgoName.c_str(), &generator);
    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(generator, nullptr);

    HcfKeyPair *keyPair = nullptr;
    res = generator->generateKeyPair(generator, nullptr, &keyPair);
    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(keyPair, nullptr);

    const char *algoName = keyPair->pubKey->base.getAlgorithm(&(keyPair->pubKey->base));
    EXPECT_STREQ(algoName, "ML-KEM");

    HcfObjDestroy(keyPair);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoMlKemAsyKeyGeneratorTest, CryptoMlKem512GetEncodedTest001, TestSize.Level0)
{
    HcfAsyKeyGenerator *generator = nullptr;
    HcfResult res = HcfAsyKeyGeneratorCreate(g_mlKem512AlgoName.c_str(), &generator);
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

HWTEST_F(CryptoMlKemAsyKeyGeneratorTest, CryptoMlKem768GetEncodedTest001, TestSize.Level0)
{
    HcfAsyKeyGenerator *generator = nullptr;
    HcfResult res = HcfAsyKeyGeneratorCreate(g_mlKem768AlgoName.c_str(), &generator);
    ASSERT_EQ(res, HCF_SUCCESS);

    HcfKeyPair *keyPair = nullptr;
    res = generator->generateKeyPair(generator, nullptr, &keyPair);
    ASSERT_EQ(res, HCF_SUCCESS);

    HcfBlob pubKeyBlob = { .data = nullptr, .len = 0 };
    res = keyPair->pubKey->base.getEncoded(&(keyPair->pubKey->base), &pubKeyBlob);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_GT(pubKeyBlob.len, 0);

    HcfBlob priKeyBlob = { .data = nullptr, .len = 0 };
    res = keyPair->priKey->base.getEncoded(&(keyPair->priKey->base), &priKeyBlob);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_GT(priKeyBlob.len, 0);

    HcfFree(pubKeyBlob.data);
    HcfFree(priKeyBlob.data);
    HcfObjDestroy(keyPair);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoMlKemAsyKeyGeneratorTest, CryptoMlKem1024GetEncodedTest001, TestSize.Level0)
{
    HcfAsyKeyGenerator *generator = nullptr;
    HcfResult res = HcfAsyKeyGeneratorCreate(g_mlKem1024AlgoName.c_str(), &generator);
    ASSERT_EQ(res, HCF_SUCCESS);

    HcfKeyPair *keyPair = nullptr;
    res = generator->generateKeyPair(generator, nullptr, &keyPair);
    ASSERT_EQ(res, HCF_SUCCESS);

    HcfBlob pubKeyBlob = { .data = nullptr, .len = 0 };
    res = keyPair->pubKey->base.getEncoded(&(keyPair->pubKey->base), &pubKeyBlob);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_GT(pubKeyBlob.len, 0);

    HcfBlob priKeyBlob = { .data = nullptr, .len = 0 };
    res = keyPair->priKey->base.getEncoded(&(keyPair->priKey->base), &priKeyBlob);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_GT(priKeyBlob.len, 0);

    HcfFree(pubKeyBlob.data);
    HcfFree(priKeyBlob.data);
    HcfObjDestroy(keyPair);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoMlKemAsyKeyGeneratorTest, CryptoMlKem512ConvertKeyTest001, TestSize.Level0)
{
    HcfAsyKeyGenerator *generator = nullptr;
    HcfResult res = HcfAsyKeyGeneratorCreate(g_mlKem512AlgoName.c_str(), &generator);
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

    HcfBlob convertedPubKeyBlob = { .data = nullptr, .len = 0 };
    res = convertedKeyPair->pubKey->base.getEncoded(&(convertedKeyPair->pubKey->base), &convertedPubKeyBlob);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_EQ(pubKeyBlob.len, convertedPubKeyBlob.len);

    HcfFree(pubKeyBlob.data);
    HcfFree(priKeyBlob.data);
    HcfFree(convertedPubKeyBlob.data);
    HcfObjDestroy(keyPair);
    HcfObjDestroy(convertedKeyPair);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoMlKemAsyKeyGeneratorTest, CryptoMlKem768ConvertKeyTest001, TestSize.Level0)
{
    HcfAsyKeyGenerator *generator = nullptr;
    HcfResult res = HcfAsyKeyGeneratorCreate(g_mlKem768AlgoName.c_str(), &generator);
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

HWTEST_F(CryptoMlKemAsyKeyGeneratorTest, CryptoMlKem1024ConvertKeyTest001, TestSize.Level0)
{
    HcfAsyKeyGenerator *generator = nullptr;
    HcfResult res = HcfAsyKeyGeneratorCreate(g_mlKem1024AlgoName.c_str(), &generator);
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

HWTEST_F(CryptoMlKemAsyKeyGeneratorTest, CryptoMlKemGetAlgoNameTest001, TestSize.Level0)
{
    HcfAsyKeyGenerator *generator = nullptr;
    HcfResult res = HcfAsyKeyGeneratorCreate(g_mlKem768AlgoName.c_str(), &generator);
    ASSERT_EQ(res, HCF_SUCCESS);

    const char *algoName = generator->getAlgoName(generator);
    EXPECT_STREQ(algoName, g_mlKem768AlgoName.c_str());

    HcfObjDestroy(generator);
}

HWTEST_F(CryptoMlKemAsyKeyGeneratorTest, CryptoMlKemGetKeySizeTest001, TestSize.Level0)
{
    HcfAsyKeyGenerator *generator = nullptr;
    HcfResult res = HcfAsyKeyGeneratorCreate(g_mlKem768AlgoName.c_str(), &generator);
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

HWTEST_F(CryptoMlKemAsyKeyGeneratorTest, CryptoMlKemConvertKeyPubOnlyTest001, TestSize.Level0)
{
    HcfAsyKeyGenerator *generator = nullptr;
    HcfResult res = HcfAsyKeyGeneratorCreate(g_mlKem768AlgoName.c_str(), &generator);
    ASSERT_EQ(res, HCF_SUCCESS);

    HcfKeyPair *keyPair = nullptr;
    res = generator->generateKeyPair(generator, nullptr, &keyPair);
    ASSERT_EQ(res, HCF_SUCCESS);

    HcfBlob pubKeyBlob = { .data = nullptr, .len = 0 };
    res = keyPair->pubKey->base.getEncoded(&(keyPair->pubKey->base), &pubKeyBlob);
    ASSERT_EQ(res, HCF_SUCCESS);

    HcfKeyPair *convertedKeyPair = nullptr;
    res = generator->convertKey(generator, nullptr, &pubKeyBlob, nullptr, &convertedKeyPair);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(convertedKeyPair, nullptr);
    EXPECT_NE(convertedKeyPair->pubKey, nullptr);

    HcfFree(pubKeyBlob.data);
    HcfObjDestroy(keyPair);
    HcfObjDestroy(convertedKeyPair);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoMlKemAsyKeyGeneratorTest, CryptoMlKemConvertKeyPriOnlyTest001, TestSize.Level0)
{
    HcfAsyKeyGenerator *generator = nullptr;
    HcfResult res = HcfAsyKeyGeneratorCreate(g_mlKem768AlgoName.c_str(), &generator);
    ASSERT_EQ(res, HCF_SUCCESS);

    HcfKeyPair *keyPair = nullptr;
    res = generator->generateKeyPair(generator, nullptr, &keyPair);
    ASSERT_EQ(res, HCF_SUCCESS);

    HcfBlob priKeyBlob = { .data = nullptr, .len = 0 };
    res = keyPair->priKey->base.getEncoded(&(keyPair->priKey->base), &priKeyBlob);
    ASSERT_EQ(res, HCF_SUCCESS);

    HcfKeyPair *convertedKeyPair = nullptr;
    res = generator->convertKey(generator, nullptr, nullptr, &priKeyBlob, &convertedKeyPair);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(convertedKeyPair, nullptr);
    EXPECT_NE(convertedKeyPair->priKey, nullptr);

    HcfFree(priKeyBlob.data);
    HcfObjDestroy(keyPair);
    HcfObjDestroy(convertedKeyPair);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoMlKemAsyKeyGeneratorTest, CryptoMlKemConvertKeyBothNullTest001, TestSize.Level0)
{
    HcfAsyKeyGenerator *generator = nullptr;
    HcfResult res = HcfAsyKeyGeneratorCreate(g_mlKem768AlgoName.c_str(), &generator);
    ASSERT_EQ(res, HCF_SUCCESS);

    HcfKeyPair *convertedKeyPair = nullptr;
    res = generator->convertKey(generator, nullptr, nullptr, nullptr, &convertedKeyPair);
    EXPECT_EQ(res, HCF_ERR_PARAMETER_CHECK_FAILED);

    HcfObjDestroy(generator);
}

HWTEST_F(CryptoMlKemAsyKeyGeneratorTest, CryptoMlKemCreateInvalidAlgoTest001, TestSize.Level0)
{
    HcfAsyKeyGenerator *generator = nullptr;
    HcfResult res = HcfAsyKeyGeneratorCreate("ML-KEM-256", &generator);
    EXPECT_NE(res, HCF_SUCCESS);
}

HWTEST_F(CryptoMlKemAsyKeyGeneratorTest, CryptoMlKemCreateNullAlgoTest001, TestSize.Level0)
{
    HcfAsyKeyGenerator *generator = nullptr;
    HcfResult res = HcfAsyKeyGeneratorCreate(nullptr, &generator);
    EXPECT_NE(res, HCF_SUCCESS);
}

HWTEST_F(CryptoMlKemAsyKeyGeneratorTest, CryptoMlKemGenerateKeyPairTwiceTest001, TestSize.Level0)
{
    HcfAsyKeyGenerator *generator = nullptr;
    HcfResult res = HcfAsyKeyGeneratorCreate(g_mlKem768AlgoName.c_str(), &generator);
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

HWTEST_F(CryptoMlKemAsyKeyGeneratorTest, CryptoMlKem512EncodeDecodeRoundTripTest001, TestSize.Level0)
{
    HcfAsyKeyGenerator *generator = nullptr;
    HcfResult res = HcfAsyKeyGeneratorCreate(g_mlKem512AlgoName.c_str(), &generator);
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

    HcfKeyPair *restoredKeyPair = nullptr;
    res = generator->convertKey(generator, nullptr, &pubKeyBlob, &priKeyBlob, &restoredKeyPair);
    EXPECT_EQ(res, HCF_SUCCESS);

    HcfBlob restoredPubKeyBlob = { .data = nullptr, .len = 0 };
    restoredKeyPair->pubKey->base.getEncoded(&(restoredKeyPair->pubKey->base), &restoredPubKeyBlob);
    EXPECT_EQ(pubKeyBlob.len, restoredPubKeyBlob.len);
    EXPECT_EQ(memcmp(pubKeyBlob.data, restoredPubKeyBlob.data, pubKeyBlob.len), 0);

    HcfBlob restoredPriKeyBlob = { .data = nullptr, .len = 0 };
    restoredKeyPair->priKey->base.getEncoded(&(restoredKeyPair->priKey->base), &restoredPriKeyBlob);
    EXPECT_EQ(priKeyBlob.len, restoredPriKeyBlob.len);
    EXPECT_EQ(memcmp(priKeyBlob.data, restoredPriKeyBlob.data, priKeyBlob.len), 0);

    HcfFree(pubKeyBlob.data);
    HcfFree(priKeyBlob.data);
    HcfFree(restoredPubKeyBlob.data);
    HcfFree(restoredPriKeyBlob.data);
    HcfObjDestroy(keyPair);
    HcfObjDestroy(restoredKeyPair);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoMlKemAsyKeyGeneratorTest, CryptoMlKem768EncodeDecodeRoundTripTest001, TestSize.Level0)
{
    HcfAsyKeyGenerator *generator = nullptr;
    HcfResult res = HcfAsyKeyGeneratorCreate(g_mlKem768AlgoName.c_str(), &generator);
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

    HcfKeyPair *restoredKeyPair = nullptr;
    res = generator->convertKey(generator, nullptr, &pubKeyBlob, &priKeyBlob, &restoredKeyPair);
    EXPECT_EQ(res, HCF_SUCCESS);

    HcfBlob restoredPubKeyBlob = { .data = nullptr, .len = 0 };
    restoredKeyPair->pubKey->base.getEncoded(&(restoredKeyPair->pubKey->base), &restoredPubKeyBlob);
    EXPECT_EQ(pubKeyBlob.len, restoredPubKeyBlob.len);
    EXPECT_EQ(memcmp(pubKeyBlob.data, restoredPubKeyBlob.data, pubKeyBlob.len), 0);

    HcfBlob restoredPriKeyBlob = { .data = nullptr, .len = 0 };
    restoredKeyPair->priKey->base.getEncoded(&(restoredKeyPair->priKey->base), &restoredPriKeyBlob);
    EXPECT_EQ(priKeyBlob.len, restoredPriKeyBlob.len);
    EXPECT_EQ(memcmp(priKeyBlob.data, restoredPriKeyBlob.data, priKeyBlob.len), 0);

    HcfFree(pubKeyBlob.data);
    HcfFree(priKeyBlob.data);
    HcfFree(restoredPubKeyBlob.data);
    HcfFree(restoredPriKeyBlob.data);
    HcfObjDestroy(keyPair);
    HcfObjDestroy(restoredKeyPair);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoMlKemAsyKeyGeneratorTest, CryptoMlKem1024EncodeDecodeRoundTripTest001, TestSize.Level0)
{
    HcfAsyKeyGenerator *generator = nullptr;
    HcfResult res = HcfAsyKeyGeneratorCreate(g_mlKem1024AlgoName.c_str(), &generator);
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

    HcfKeyPair *restoredKeyPair = nullptr;
    res = generator->convertKey(generator, nullptr, &pubKeyBlob, &priKeyBlob, &restoredKeyPair);
    EXPECT_EQ(res, HCF_SUCCESS);

    HcfBlob restoredPubKeyBlob = { .data = nullptr, .len = 0 };
    restoredKeyPair->pubKey->base.getEncoded(&(restoredKeyPair->pubKey->base), &restoredPubKeyBlob);
    EXPECT_EQ(pubKeyBlob.len, restoredPubKeyBlob.len);
    EXPECT_EQ(memcmp(pubKeyBlob.data, restoredPubKeyBlob.data, pubKeyBlob.len), 0);

    HcfBlob restoredPriKeyBlob = { .data = nullptr, .len = 0 };
    restoredKeyPair->priKey->base.getEncoded(&(restoredKeyPair->priKey->base), &restoredPriKeyBlob);
    EXPECT_EQ(priKeyBlob.len, restoredPriKeyBlob.len);
    EXPECT_EQ(memcmp(priKeyBlob.data, restoredPriKeyBlob.data, priKeyBlob.len), 0);

    HcfFree(pubKeyBlob.data);
    HcfFree(priKeyBlob.data);
    HcfFree(restoredPubKeyBlob.data);
    HcfFree(restoredPriKeyBlob.data);
    HcfObjDestroy(keyPair);
    HcfObjDestroy(restoredKeyPair);
    HcfObjDestroy(generator);
}

// ==================== getEncodedDer tests ====================

HWTEST_F(CryptoMlKemAsyKeyGeneratorTest, CryptoMlKem768GetEncodedDerPubKeyTest001, TestSize.Level0)
{
    HcfAsyKeyGenerator *generator = nullptr;
    HcfResult res = HcfAsyKeyGeneratorCreate(g_mlKem768AlgoName.c_str(), &generator);
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

HWTEST_F(CryptoMlKemAsyKeyGeneratorTest, CryptoMlKem768GetEncodedDerPriKeyTest001, TestSize.Level0)
{
    HcfAsyKeyGenerator *generator = nullptr;
    HcfResult res = HcfAsyKeyGeneratorCreate(g_mlKem768AlgoName.c_str(), &generator);
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

HWTEST_F(CryptoMlKemAsyKeyGeneratorTest, CryptoMlKem512GetEncodedDerTest001, TestSize.Level0)
{
    HcfAsyKeyGenerator *generator = nullptr;
    HcfResult res = HcfAsyKeyGeneratorCreate(g_mlKem512AlgoName.c_str(), &generator);
    ASSERT_EQ(res, HCF_SUCCESS);

    HcfKeyPair *keyPair = nullptr;
    res = generator->generateKeyPair(generator, nullptr, &keyPair);
    ASSERT_EQ(res, HCF_SUCCESS);

    HcfBlob pubDerBlob = { .data = nullptr, .len = 0 };
    res = keyPair->pubKey->getEncodedDer(keyPair->pubKey, "X509", &pubDerBlob);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_GT(pubDerBlob.len, 0);

    HcfBlob priDerBlob = { .data = nullptr, .len = 0 };
    res = keyPair->priKey->getEncodedDer(keyPair->priKey, "PKCS8", &priDerBlob);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_GT(priDerBlob.len, 0);

    HcfFree(pubDerBlob.data);
    HcfFree(priDerBlob.data);
    HcfObjDestroy(keyPair);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoMlKemAsyKeyGeneratorTest, CryptoMlKem1024GetEncodedDerTest001, TestSize.Level0)
{
    HcfAsyKeyGenerator *generator = nullptr;
    HcfResult res = HcfAsyKeyGeneratorCreate(g_mlKem1024AlgoName.c_str(), &generator);
    ASSERT_EQ(res, HCF_SUCCESS);

    HcfKeyPair *keyPair = nullptr;
    res = generator->generateKeyPair(generator, nullptr, &keyPair);
    ASSERT_EQ(res, HCF_SUCCESS);

    HcfBlob pubDerBlob = { .data = nullptr, .len = 0 };
    res = keyPair->pubKey->getEncodedDer(keyPair->pubKey, "X509", &pubDerBlob);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_GT(pubDerBlob.len, 0);

    HcfBlob priDerBlob = { .data = nullptr, .len = 0 };
    res = keyPair->priKey->getEncodedDer(keyPair->priKey, "PKCS8", &priDerBlob);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_GT(priDerBlob.len, 0);

    HcfFree(pubDerBlob.data);
    HcfFree(priDerBlob.data);
    HcfObjDestroy(keyPair);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoMlKemAsyKeyGeneratorTest, CryptoMlKemGetEncodedDerInvalidFormatTest001, TestSize.Level0)
{
    HcfAsyKeyGenerator *generator = nullptr;
    HcfResult res = HcfAsyKeyGeneratorCreate(g_mlKem768AlgoName.c_str(), &generator);
    ASSERT_EQ(res, HCF_SUCCESS);

    HcfKeyPair *keyPair = nullptr;
    res = generator->generateKeyPair(generator, nullptr, &keyPair);
    ASSERT_EQ(res, HCF_SUCCESS);

    HcfBlob blob = { .data = nullptr, .len = 0 };
    res = keyPair->pubKey->getEncodedDer(keyPair->pubKey, "PKCS8", &blob);
    EXPECT_NE(res, HCF_SUCCESS);

    res = keyPair->priKey->getEncodedDer(keyPair->priKey, "X509", &blob);
    EXPECT_NE(res, HCF_SUCCESS);

    res = keyPair->pubKey->getEncodedDer(keyPair->pubKey, "PKCS1", &blob);
    EXPECT_NE(res, HCF_SUCCESS);

    HcfObjDestroy(keyPair);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoMlKemAsyKeyGeneratorTest, CryptoMlKemGetEncodedDerNullParamTest001, TestSize.Level0)
{
    HcfAsyKeyGenerator *generator = nullptr;
    HcfResult res = HcfAsyKeyGeneratorCreate(g_mlKem768AlgoName.c_str(), &generator);
    ASSERT_EQ(res, HCF_SUCCESS);

    HcfKeyPair *keyPair = nullptr;
    res = generator->generateKeyPair(generator, nullptr, &keyPair);
    ASSERT_EQ(res, HCF_SUCCESS);

    HcfBlob blob = { .data = nullptr, .len = 0 };
    res = keyPair->pubKey->getEncodedDer(nullptr, "X509", &blob);
    EXPECT_NE(res, HCF_SUCCESS);

    res = keyPair->pubKey->getEncodedDer(keyPair->pubKey, nullptr, &blob);
    EXPECT_NE(res, HCF_SUCCESS);

    res = keyPair->pubKey->getEncodedDer(keyPair->pubKey, "X509", nullptr);
    EXPECT_NE(res, HCF_SUCCESS);

    HcfObjDestroy(keyPair);
    HcfObjDestroy(generator);
}

// ==================== getEncodedPem tests ====================

HWTEST_F(CryptoMlKemAsyKeyGeneratorTest, CryptoMlKem768GetEncodedPemPubKeyTest001, TestSize.Level0)
{
    HcfAsyKeyGenerator *generator = nullptr;
    HcfResult res = HcfAsyKeyGeneratorCreate(g_mlKem768AlgoName.c_str(), &generator);
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

HWTEST_F(CryptoMlKemAsyKeyGeneratorTest, CryptoMlKem768GetEncodedPemPriKeyTest001, TestSize.Level0)
{
    HcfAsyKeyGenerator *generator = nullptr;
    HcfResult res = HcfAsyKeyGeneratorCreate(g_mlKem768AlgoName.c_str(), &generator);
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

HWTEST_F(CryptoMlKemAsyKeyGeneratorTest, CryptoMlKem512GetEncodedPemTest001, TestSize.Level0)
{
    HcfAsyKeyGenerator *generator = nullptr;
    HcfResult res = HcfAsyKeyGeneratorCreate(g_mlKem512AlgoName.c_str(), &generator);
    ASSERT_EQ(res, HCF_SUCCESS);

    HcfKeyPair *keyPair = nullptr;
    res = generator->generateKeyPair(generator, nullptr, &keyPair);
    ASSERT_EQ(res, HCF_SUCCESS);

    char *pubPem = nullptr;
    res = keyPair->pubKey->base.getEncodedPem(&(keyPair->pubKey->base), "X509", &pubPem);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(pubPem, nullptr);
    HcfFree(pubPem);

    char *priPem = nullptr;
    res = keyPair->priKey->getEncodedPem(keyPair->priKey, nullptr, "PKCS8", &priPem);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(priPem, nullptr);
    HcfFree(priPem);

    HcfObjDestroy(keyPair);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoMlKemAsyKeyGeneratorTest, CryptoMlKem1024GetEncodedPemTest001, TestSize.Level0)
{
    HcfAsyKeyGenerator *generator = nullptr;
    HcfResult res = HcfAsyKeyGeneratorCreate(g_mlKem1024AlgoName.c_str(), &generator);
    ASSERT_EQ(res, HCF_SUCCESS);

    HcfKeyPair *keyPair = nullptr;
    res = generator->generateKeyPair(generator, nullptr, &keyPair);
    ASSERT_EQ(res, HCF_SUCCESS);

    char *pubPem = nullptr;
    res = keyPair->pubKey->base.getEncodedPem(&(keyPair->pubKey->base), "X509", &pubPem);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(pubPem, nullptr);
    HcfFree(pubPem);

    char *priPem = nullptr;
    res = keyPair->priKey->getEncodedPem(keyPair->priKey, nullptr, "PKCS8", &priPem);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(priPem, nullptr);
    HcfFree(priPem);

    HcfObjDestroy(keyPair);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoMlKemAsyKeyGeneratorTest, CryptoMlKemGetEncodedPemInvalidFormatTest001, TestSize.Level0)
{
    HcfAsyKeyGenerator *generator = nullptr;
    HcfResult res = HcfAsyKeyGeneratorCreate(g_mlKem768AlgoName.c_str(), &generator);
    ASSERT_EQ(res, HCF_SUCCESS);

    HcfKeyPair *keyPair = nullptr;
    res = generator->generateKeyPair(generator, nullptr, &keyPair);
    ASSERT_EQ(res, HCF_SUCCESS);

    char *pemStr = nullptr;
    res = keyPair->pubKey->base.getEncodedPem(&(keyPair->pubKey->base), "PKCS8", &pemStr);
    EXPECT_NE(res, HCF_SUCCESS);

    res = keyPair->priKey->getEncodedPem(keyPair->priKey, nullptr, "X509", &pemStr);
    EXPECT_NE(res, HCF_SUCCESS);

    res = keyPair->priKey->getEncodedPem(keyPair->priKey, nullptr, "PKCS1", &pemStr);
    EXPECT_NE(res, HCF_SUCCESS);

    HcfObjDestroy(keyPair);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoMlKemAsyKeyGeneratorTest, CryptoMlKemGetEncodedPemNullParamTest001, TestSize.Level0)
{
    HcfAsyKeyGenerator *generator = nullptr;
    HcfResult res = HcfAsyKeyGeneratorCreate(g_mlKem768AlgoName.c_str(), &generator);
    ASSERT_EQ(res, HCF_SUCCESS);

    HcfKeyPair *keyPair = nullptr;
    res = generator->generateKeyPair(generator, nullptr, &keyPair);
    ASSERT_EQ(res, HCF_SUCCESS);

    char *pemStr = nullptr;
    res = keyPair->pubKey->base.getEncodedPem(nullptr, "X509", &pemStr);
    EXPECT_NE(res, HCF_SUCCESS);

    res = keyPair->pubKey->base.getEncodedPem(&(keyPair->pubKey->base), nullptr, &pemStr);
    EXPECT_NE(res, HCF_SUCCESS);

    res = keyPair->pubKey->base.getEncodedPem(&(keyPair->pubKey->base), "X509", nullptr);
    EXPECT_NE(res, HCF_SUCCESS);

    res = keyPair->priKey->getEncodedPem(nullptr, nullptr, "PKCS8", &pemStr);
    EXPECT_NE(res, HCF_SUCCESS);

    res = keyPair->priKey->getEncodedPem(keyPair->priKey, nullptr, nullptr, &pemStr);
    EXPECT_NE(res, HCF_SUCCESS);

    res = keyPair->priKey->getEncodedPem(keyPair->priKey, nullptr, "PKCS8", nullptr);
    EXPECT_NE(res, HCF_SUCCESS);

    HcfObjDestroy(keyPair);
    HcfObjDestroy(generator);
}

// ==================== getKeyData tests ====================

HWTEST_F(CryptoMlKemAsyKeyGeneratorTest, CryptoMlKem768GetKeyDataPubKeyTest001, TestSize.Level0)
{
    HcfAsyKeyGenerator *generator = nullptr;
    HcfResult res = HcfAsyKeyGeneratorCreate(g_mlKem768AlgoName.c_str(), &generator);
    ASSERT_EQ(res, HCF_SUCCESS);

    HcfKeyPair *keyPair = nullptr;
    res = generator->generateKeyPair(generator, nullptr, &keyPair);
    ASSERT_EQ(res, HCF_SUCCESS);

    HcfBlob rawBlob = { .data = nullptr, .len = 0 };
    res = keyPair->pubKey->getKeyData(keyPair->pubKey, ML_KEM_PUBLIC_RAW, &rawBlob);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_GT(rawBlob.len, 0);
    EXPECT_NE(rawBlob.data, nullptr);
    EXPECT_EQ(rawBlob.len, 1184);

    HcfFree(rawBlob.data);
    HcfObjDestroy(keyPair);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoMlKemAsyKeyGeneratorTest, CryptoMlKem768GetKeyDataPriKeyTest001, TestSize.Level0)
{
    HcfAsyKeyGenerator *generator = nullptr;
    HcfResult res = HcfAsyKeyGeneratorCreate(g_mlKem768AlgoName.c_str(), &generator);
    ASSERT_EQ(res, HCF_SUCCESS);

    HcfKeyPair *keyPair = nullptr;
    res = generator->generateKeyPair(generator, nullptr, &keyPair);
    ASSERT_EQ(res, HCF_SUCCESS);

    HcfBlob rawBlob = { .data = nullptr, .len = 0 };
    res = keyPair->priKey->getKeyData(keyPair->priKey, ML_KEM_PRIVATE_RAW, &rawBlob);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_GT(rawBlob.len, 0);
    EXPECT_NE(rawBlob.data, nullptr);
    EXPECT_EQ(rawBlob.len, 2400);

    HcfFree(rawBlob.data);
    HcfObjDestroy(keyPair);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoMlKemAsyKeyGeneratorTest, CryptoMlKem512GetKeyDataTest001, TestSize.Level0)
{
    HcfAsyKeyGenerator *generator = nullptr;
    HcfResult res = HcfAsyKeyGeneratorCreate(g_mlKem512AlgoName.c_str(), &generator);
    ASSERT_EQ(res, HCF_SUCCESS);

    HcfKeyPair *keyPair = nullptr;
    res = generator->generateKeyPair(generator, nullptr, &keyPair);
    ASSERT_EQ(res, HCF_SUCCESS);

    HcfBlob pubRawBlob = { .data = nullptr, .len = 0 };
    res = keyPair->pubKey->getKeyData(keyPair->pubKey, ML_KEM_PUBLIC_RAW, &pubRawBlob);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_EQ(pubRawBlob.len, 800);

    HcfBlob priRawBlob = { .data = nullptr, .len = 0 };
    res = keyPair->priKey->getKeyData(keyPair->priKey, ML_KEM_PRIVATE_RAW, &priRawBlob);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_EQ(priRawBlob.len, 1632);

    HcfFree(pubRawBlob.data);
    HcfFree(priRawBlob.data);
    HcfObjDestroy(keyPair);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoMlKemAsyKeyGeneratorTest, CryptoMlKem1024GetKeyDataTest001, TestSize.Level0)
{
    HcfAsyKeyGenerator *generator = nullptr;
    HcfResult res = HcfAsyKeyGeneratorCreate(g_mlKem1024AlgoName.c_str(), &generator);
    ASSERT_EQ(res, HCF_SUCCESS);

    HcfKeyPair *keyPair = nullptr;
    res = generator->generateKeyPair(generator, nullptr, &keyPair);
    ASSERT_EQ(res, HCF_SUCCESS);

    HcfBlob pubRawBlob = { .data = nullptr, .len = 0 };
    res = keyPair->pubKey->getKeyData(keyPair->pubKey, ML_KEM_PUBLIC_RAW, &pubRawBlob);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_EQ(pubRawBlob.len, 1568);

    HcfBlob priRawBlob = { .data = nullptr, .len = 0 };
    res = keyPair->priKey->getKeyData(keyPair->priKey, ML_KEM_PRIVATE_RAW, &priRawBlob);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_EQ(priRawBlob.len, 3168);

    HcfFree(pubRawBlob.data);
    HcfFree(priRawBlob.data);
    HcfObjDestroy(keyPair);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoMlKemAsyKeyGeneratorTest, CryptoMlKemGetKeyDataInvalidTypeTest001, TestSize.Level0)
{
    HcfAsyKeyGenerator *generator = nullptr;
    HcfResult res = HcfAsyKeyGeneratorCreate(g_mlKem768AlgoName.c_str(), &generator);
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

HWTEST_F(CryptoMlKemAsyKeyGeneratorTest, CryptoMlKemGetKeyDataNullParamTest001, TestSize.Level0)
{
    HcfAsyKeyGenerator *generator = nullptr;
    HcfResult res = HcfAsyKeyGeneratorCreate(g_mlKem768AlgoName.c_str(), &generator);
    ASSERT_EQ(res, HCF_SUCCESS);

    HcfKeyPair *keyPair = nullptr;
    res = generator->generateKeyPair(generator, nullptr, &keyPair);
    ASSERT_EQ(res, HCF_SUCCESS);

    HcfBlob blob = { .data = nullptr, .len = 0 };
    res = keyPair->pubKey->getKeyData(nullptr, ML_KEM_PUBLIC_RAW, &blob);
    EXPECT_NE(res, HCF_SUCCESS);

    res = keyPair->pubKey->getKeyData(keyPair->pubKey, ML_KEM_PUBLIC_RAW, nullptr);
    EXPECT_NE(res, HCF_SUCCESS);

    res = keyPair->priKey->getKeyData(nullptr, ML_KEM_PRIVATE_RAW, &blob);
    EXPECT_NE(res, HCF_SUCCESS);

    res = keyPair->priKey->getKeyData(keyPair->priKey, ML_KEM_PRIVATE_RAW, nullptr);
    EXPECT_NE(res, HCF_SUCCESS);

    HcfObjDestroy(keyPair);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoMlKemAsyKeyGeneratorTest, CryptoMlKem768GetKeyDataPrivateSeedTest001, TestSize.Level0)
{
    HcfAsyKeyGenerator *generator = nullptr;
    HcfResult res = HcfAsyKeyGeneratorCreate(g_mlKem768AlgoName.c_str(), &generator);
    ASSERT_EQ(res, HCF_SUCCESS);

    HcfKeyPair *keyPair = nullptr;
    res = generator->generateKeyPair(generator, nullptr, &keyPair);
    ASSERT_EQ(res, HCF_SUCCESS);

    HcfBlob seedBlob = { .data = nullptr, .len = 0 };
    res = keyPair->priKey->getKeyData(keyPair->priKey, ML_KEM_PRIVATE_SEED, &seedBlob);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_EQ(seedBlob.len, 64);
    EXPECT_NE(seedBlob.data, nullptr);

    HcfFree(seedBlob.data);
    HcfObjDestroy(keyPair);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoMlKemAsyKeyGeneratorTest, CryptoMlKem512GetKeyDataPrivateSeedTest001, TestSize.Level0)
{
    HcfAsyKeyGenerator *generator = nullptr;
    HcfResult res = HcfAsyKeyGeneratorCreate(g_mlKem512AlgoName.c_str(), &generator);
    ASSERT_EQ(res, HCF_SUCCESS);

    HcfKeyPair *keyPair = nullptr;
    res = generator->generateKeyPair(generator, nullptr, &keyPair);
    ASSERT_EQ(res, HCF_SUCCESS);

    HcfBlob seedBlob = { .data = nullptr, .len = 0 };
    res = keyPair->priKey->getKeyData(keyPair->priKey, ML_KEM_PRIVATE_SEED, &seedBlob);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_EQ(seedBlob.len, 64);

    HcfFree(seedBlob.data);
    HcfObjDestroy(keyPair);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoMlKemAsyKeyGeneratorTest, CryptoMlKem1024GetKeyDataPrivateSeedTest001, TestSize.Level0)
{
    HcfAsyKeyGenerator *generator = nullptr;
    HcfResult res = HcfAsyKeyGeneratorCreate(g_mlKem1024AlgoName.c_str(), &generator);
    ASSERT_EQ(res, HCF_SUCCESS);

    HcfKeyPair *keyPair = nullptr;
    res = generator->generateKeyPair(generator, nullptr, &keyPair);
    ASSERT_EQ(res, HCF_SUCCESS);

    HcfBlob seedBlob = { .data = nullptr, .len = 0 };
    res = keyPair->priKey->getKeyData(keyPair->priKey, ML_KEM_PRIVATE_SEED, &seedBlob);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_EQ(seedBlob.len, 64);

    HcfFree(seedBlob.data);
    HcfObjDestroy(keyPair);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoMlKemAsyKeyGeneratorTest, CryptoMlKem768SeedIsPrefixOfRawTest001, TestSize.Level0)
{
    HcfAsyKeyGenerator *generator = nullptr;
    HcfResult res = HcfAsyKeyGeneratorCreate(g_mlKem768AlgoName.c_str(), &generator);
    ASSERT_EQ(res, HCF_SUCCESS);

    HcfKeyPair *keyPair = nullptr;
    res = generator->generateKeyPair(generator, nullptr, &keyPair);
    ASSERT_EQ(res, HCF_SUCCESS);

    HcfBlob seedBlob = { .data = nullptr, .len = 0 };
    res = keyPair->priKey->getKeyData(keyPair->priKey, ML_KEM_PRIVATE_SEED, &seedBlob);
    ASSERT_EQ(res, HCF_SUCCESS);

    HcfBlob rawBlob = { .data = nullptr, .len = 0 };
    res = keyPair->priKey->getKeyData(keyPair->priKey, ML_KEM_PRIVATE_RAW, &rawBlob);
    ASSERT_EQ(res, HCF_SUCCESS);

    EXPECT_EQ(memcmp(seedBlob.data, rawBlob.data, seedBlob.len), 0);

    HcfFree(seedBlob.data);
    HcfFree(rawBlob.data);
    HcfObjDestroy(keyPair);
    HcfObjDestroy(generator);
}

// ==================== getPubKey from priKey tests ====================

HWTEST_F(CryptoMlKemAsyKeyGeneratorTest, CryptoMlKem768GetPubKeyFromPriKeyTest001, TestSize.Level0)
{
    HcfAsyKeyGenerator *generator = nullptr;
    HcfResult res = HcfAsyKeyGeneratorCreate(g_mlKem768AlgoName.c_str(), &generator);
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

HWTEST_F(CryptoMlKemAsyKeyGeneratorTest, CryptoMlKem512GetPubKeyFromPriKeyTest001, TestSize.Level0)
{
    HcfAsyKeyGenerator *generator = nullptr;
    HcfResult res = HcfAsyKeyGeneratorCreate(g_mlKem512AlgoName.c_str(), &generator);
    ASSERT_EQ(res, HCF_SUCCESS);

    HcfKeyPair *keyPair = nullptr;
    res = generator->generateKeyPair(generator, nullptr, &keyPair);
    ASSERT_EQ(res, HCF_SUCCESS);

    HcfPubKey *extractedPubKey = nullptr;
    res = keyPair->priKey->getPubKey(keyPair->priKey, &extractedPubKey);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(extractedPubKey, nullptr);

    const char *algo = extractedPubKey->base.getAlgorithm(&(extractedPubKey->base));
    EXPECT_STREQ(algo, "ML-KEM");

    HcfObjDestroy(extractedPubKey);
    HcfObjDestroy(keyPair);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoMlKemAsyKeyGeneratorTest, CryptoMlKem1024GetPubKeyFromPriKeyTest001, TestSize.Level0)
{
    HcfAsyKeyGenerator *generator = nullptr;
    HcfResult res = HcfAsyKeyGeneratorCreate(g_mlKem1024AlgoName.c_str(), &generator);
    ASSERT_EQ(res, HCF_SUCCESS);

    HcfKeyPair *keyPair = nullptr;
    res = generator->generateKeyPair(generator, nullptr, &keyPair);
    ASSERT_EQ(res, HCF_SUCCESS);

    HcfPubKey *extractedPubKey = nullptr;
    res = keyPair->priKey->getPubKey(keyPair->priKey, &extractedPubKey);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(extractedPubKey, nullptr);

    HcfBlob extractedPubBlob = { .data = nullptr, .len = 0 };
    res = extractedPubKey->getKeyData(extractedPubKey, ML_KEM_PUBLIC_RAW, &extractedPubBlob);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_EQ(extractedPubBlob.len, 1568);

    HcfFree(extractedPubBlob.data);
    HcfObjDestroy(extractedPubKey);
    HcfObjDestroy(keyPair);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoMlKemAsyKeyGeneratorTest, CryptoMlKemGetPubKeyFromPriKeyNullParamTest001, TestSize.Level0)
{
    HcfAsyKeyGenerator *generator = nullptr;
    HcfResult res = HcfAsyKeyGeneratorCreate(g_mlKem768AlgoName.c_str(), &generator);
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

HWTEST_F(CryptoMlKemAsyKeyGeneratorTest, CryptoMlKem768GetAsyKeySpecBigIntegerTest001, TestSize.Level0)
{
    HcfAsyKeyGenerator *generator = nullptr;
    HcfResult res = HcfAsyKeyGeneratorCreate(g_mlKem768AlgoName.c_str(), &generator);
    ASSERT_EQ(res, HCF_SUCCESS);

    HcfKeyPair *keyPair = nullptr;
    res = generator->generateKeyPair(generator, nullptr, &keyPair);
    ASSERT_EQ(res, HCF_SUCCESS);

    HcfBigInteger pubBigInt = { .data = nullptr, .len = 0 };
    res = keyPair->pubKey->getAsyKeySpecBigInteger(keyPair->pubKey, ML_KEM_768_PK_BN, &pubBigInt);
    EXPECT_EQ(res, HCF_ERR_INVALID_CALL);

    HcfBigInteger priBigInt = { .data = nullptr, .len = 0 };
    res = keyPair->priKey->getAsyKeySpecBigInteger(keyPair->priKey, ML_KEM_768_SK_BN, &priBigInt);
    EXPECT_EQ(res, HCF_ERR_INVALID_CALL);

    HcfObjDestroy(keyPair);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoMlKemAsyKeyGeneratorTest, CryptoMlKem512GetAsyKeySpecBigIntegerTest001, TestSize.Level0)
{
    HcfAsyKeyGenerator *generator = nullptr;
    HcfResult res = HcfAsyKeyGeneratorCreate(g_mlKem512AlgoName.c_str(), &generator);
    ASSERT_EQ(res, HCF_SUCCESS);

    HcfKeyPair *keyPair = nullptr;
    res = generator->generateKeyPair(generator, nullptr, &keyPair);
    ASSERT_EQ(res, HCF_SUCCESS);

    HcfBigInteger pubBigInt = { .data = nullptr, .len = 0 };
    res = keyPair->pubKey->getAsyKeySpecBigInteger(keyPair->pubKey, ML_KEM_512_PK_BN, &pubBigInt);
    EXPECT_EQ(res, HCF_ERR_INVALID_CALL);

    HcfBigInteger priBigInt = { .data = nullptr, .len = 0 };
    res = keyPair->priKey->getAsyKeySpecBigInteger(keyPair->priKey, ML_KEM_512_SK_BN, &priBigInt);
    EXPECT_EQ(res, HCF_ERR_INVALID_CALL);

    HcfObjDestroy(keyPair);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoMlKemAsyKeyGeneratorTest, CryptoMlKem1024GetAsyKeySpecBigIntegerTest001, TestSize.Level0)
{
    HcfAsyKeyGenerator *generator = nullptr;
    HcfResult res = HcfAsyKeyGeneratorCreate(g_mlKem1024AlgoName.c_str(), &generator);
    ASSERT_EQ(res, HCF_SUCCESS);

    HcfKeyPair *keyPair = nullptr;
    res = generator->generateKeyPair(generator, nullptr, &keyPair);
    ASSERT_EQ(res, HCF_SUCCESS);

    HcfBigInteger pubBigInt = { .data = nullptr, .len = 0 };
    res = keyPair->pubKey->getAsyKeySpecBigInteger(keyPair->pubKey, ML_KEM_1024_PK_BN, &pubBigInt);
    EXPECT_EQ(res, HCF_ERR_INVALID_CALL);

    HcfBigInteger priBigInt = { .data = nullptr, .len = 0 };
    res = keyPair->priKey->getAsyKeySpecBigInteger(keyPair->priKey, ML_KEM_1024_SK_BN, &priBigInt);
    EXPECT_EQ(res, HCF_ERR_INVALID_CALL);

    HcfObjDestroy(keyPair);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoMlKemAsyKeyGeneratorTest, CryptoMlKemGetAsyKeySpecBigIntegerInvalidItemTest001, TestSize.Level0)
{
    HcfAsyKeyGenerator *generator = nullptr;
    HcfResult res = HcfAsyKeyGeneratorCreate(g_mlKem768AlgoName.c_str(), &generator);
    ASSERT_EQ(res, HCF_SUCCESS);

    HcfKeyPair *keyPair = nullptr;
    res = generator->generateKeyPair(generator, nullptr, &keyPair);
    ASSERT_EQ(res, HCF_SUCCESS);

    HcfBigInteger bigInt = { .data = nullptr, .len = 0 };
    res = keyPair->pubKey->getAsyKeySpecBigInteger(keyPair->pubKey, ML_KEM_512_PK_BN, &bigInt);
    EXPECT_EQ(res, HCF_ERR_INVALID_CALL);

    res = keyPair->priKey->getAsyKeySpecBigInteger(keyPair->priKey, ML_KEM_512_SK_BN, &bigInt);
    EXPECT_EQ(res, HCF_ERR_INVALID_CALL);

    HcfObjDestroy(keyPair);
    HcfObjDestroy(generator);
}

// ==================== getAsyKeySpecInt/String not support tests ====================

HWTEST_F(CryptoMlKemAsyKeyGeneratorTest, CryptoMlKemGetAsyKeySpecIntNotSupportTest001, TestSize.Level0)
{
    HcfAsyKeyGenerator *generator = nullptr;
    HcfResult res = HcfAsyKeyGeneratorCreate(g_mlKem768AlgoName.c_str(), &generator);
    ASSERT_EQ(res, HCF_SUCCESS);

    HcfKeyPair *keyPair = nullptr;
    res = generator->generateKeyPair(generator, nullptr, &keyPair);
    ASSERT_EQ(res, HCF_SUCCESS);

    int returnInt = 0;
    res = keyPair->pubKey->getAsyKeySpecInt(keyPair->pubKey, ML_KEM_768_PK_BN, &returnInt);
    EXPECT_EQ(res, HCF_ERR_INVALID_CALL);

    res = keyPair->priKey->getAsyKeySpecInt(keyPair->priKey, ML_KEM_768_SK_BN, &returnInt);
    EXPECT_EQ(res, HCF_ERR_INVALID_CALL);

    HcfObjDestroy(keyPair);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoMlKemAsyKeyGeneratorTest, CryptoMlKemGetAsyKeySpecStringNotSupportTest001, TestSize.Level0)
{
    HcfAsyKeyGenerator *generator = nullptr;
    HcfResult res = HcfAsyKeyGeneratorCreate(g_mlKem768AlgoName.c_str(), &generator);
    ASSERT_EQ(res, HCF_SUCCESS);

    HcfKeyPair *keyPair = nullptr;
    res = generator->generateKeyPair(generator, nullptr, &keyPair);
    ASSERT_EQ(res, HCF_SUCCESS);

    char *returnStr = nullptr;
    res = keyPair->pubKey->getAsyKeySpecString(keyPair->pubKey, ML_KEM_768_PK_BN, &returnStr);
    EXPECT_EQ(res, HCF_ERR_INVALID_CALL);

    res = keyPair->priKey->getAsyKeySpecString(keyPair->priKey, ML_KEM_768_SK_BN, &returnStr);
    EXPECT_EQ(res, HCF_ERR_INVALID_CALL);

    HcfObjDestroy(keyPair);
    HcfObjDestroy(generator);
}

// ==================== clearMem test ====================

HWTEST_F(CryptoMlKemAsyKeyGeneratorTest, CryptoMlKemClearMemTest001, TestSize.Level0)
{
    HcfAsyKeyGenerator *generator = nullptr;
    HcfResult res = HcfAsyKeyGeneratorCreate(g_mlKem768AlgoName.c_str(), &generator);
    ASSERT_EQ(res, HCF_SUCCESS);

    HcfKeyPair *keyPair = nullptr;
    res = generator->generateKeyPair(generator, nullptr, &keyPair);
    ASSERT_EQ(res, HCF_SUCCESS);

    keyPair->priKey->clearMem(keyPair->priKey);

    HcfObjDestroy(keyPair);
    HcfObjDestroy(generator);
}

// ==================== DER round-trip tests ====================

HWTEST_F(CryptoMlKemAsyKeyGeneratorTest, CryptoMlKem768DerRoundTripTest001, TestSize.Level0)
{
    HcfAsyKeyGenerator *generator = nullptr;
    HcfResult res = HcfAsyKeyGeneratorCreate(g_mlKem768AlgoName.c_str(), &generator);
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

    HcfBlob restoredPriDer = { .data = nullptr, .len = 0 };
    restoredKeyPair->priKey->getEncodedDer(restoredKeyPair->priKey, "PKCS8", &restoredPriDer);
    EXPECT_EQ(priDerBlob.len, restoredPriDer.len);
    EXPECT_EQ(memcmp(priDerBlob.data, restoredPriDer.data, priDerBlob.len), 0);

    HcfFree(pubDerBlob.data);
    HcfFree(priDerBlob.data);
    HcfFree(restoredPubDer.data);
    HcfFree(restoredPriDer.data);
    HcfObjDestroy(keyPair);
    HcfObjDestroy(restoredKeyPair);
    HcfObjDestroy(generator);
}

// ==================== Cross-validation: getPubKey raw matches getKeyData raw ====================

HWTEST_F(CryptoMlKemAsyKeyGeneratorTest, CryptoMlKem768GetPubKeyCrossValidateTest001, TestSize.Level0)
{
    HcfAsyKeyGenerator *generator = nullptr;
    HcfResult res = HcfAsyKeyGeneratorCreate(g_mlKem768AlgoName.c_str(), &generator);
    ASSERT_EQ(res, HCF_SUCCESS);

    HcfKeyPair *keyPair = nullptr;
    res = generator->generateKeyPair(generator, nullptr, &keyPair);
    ASSERT_EQ(res, HCF_SUCCESS);

    HcfBlob originalRawPub = { .data = nullptr, .len = 0 };
    res = keyPair->pubKey->getKeyData(keyPair->pubKey, ML_KEM_PUBLIC_RAW, &originalRawPub);
    ASSERT_EQ(res, HCF_SUCCESS);

    HcfPubKey *extractedPubKey = nullptr;
    res = keyPair->priKey->getPubKey(keyPair->priKey, &extractedPubKey);
    ASSERT_EQ(res, HCF_SUCCESS);

    HcfBlob extractedRawPub = { .data = nullptr, .len = 0 };
    res = extractedPubKey->getKeyData(extractedPubKey, ML_KEM_PUBLIC_RAW, &extractedRawPub);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_EQ(originalRawPub.len, extractedRawPub.len);
    EXPECT_EQ(memcmp(originalRawPub.data, extractedRawPub.data, originalRawPub.len), 0);

    HcfFree(originalRawPub.data);
    HcfFree(extractedRawPub.data);
    HcfObjDestroy(extractedPubKey);
    HcfObjDestroy(keyPair);
    HcfObjDestroy(generator);
}

// ==================== getAsyKeySpecBigInteger matches getKeyData ====================

HWTEST_F(CryptoMlKemAsyKeyGeneratorTest, CryptoMlKem768BigIntegerMatchesKeyDataTest001, TestSize.Level0)
{
    HcfAsyKeyGenerator *generator = nullptr;
    HcfResult res = HcfAsyKeyGeneratorCreate(g_mlKem768AlgoName.c_str(), &generator);
    ASSERT_EQ(res, HCF_SUCCESS);

    HcfKeyPair *keyPair = nullptr;
    res = generator->generateKeyPair(generator, nullptr, &keyPair);
    ASSERT_EQ(res, HCF_SUCCESS);

    HcfBigInteger pubBigInt = { .data = nullptr, .len = 0 };
    res = keyPair->pubKey->getAsyKeySpecBigInteger(keyPair->pubKey, ML_KEM_768_PK_BN, &pubBigInt);
    EXPECT_EQ(res, HCF_ERR_INVALID_CALL);

    HcfObjDestroy(keyPair);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoMlKemAsyKeyGeneratorTest, CryptoMlKemGetKeyDataECTypeTest001, TestSize.Level0)
{
    HcfAsyKeyGenerator *generator = nullptr;
    HcfResult res = HcfAsyKeyGeneratorCreate(g_mlKem768AlgoName.c_str(), &generator);
    ASSERT_EQ(res, HCF_SUCCESS);

    HcfKeyPair *keyPair = nullptr;
    res = generator->generateKeyPair(generator, nullptr, &keyPair);
    ASSERT_EQ(res, HCF_SUCCESS);

    HcfBlob blob = { .data = nullptr, .len = 0 };
    res = keyPair->pubKey->getKeyData(keyPair->pubKey, 8, &blob);
    EXPECT_NE(res, HCF_SUCCESS);

    res = keyPair->pubKey->getKeyData(keyPair->pubKey, 9, &blob);
    EXPECT_NE(res, HCF_SUCCESS);

    res = keyPair->priKey->getKeyData(keyPair->priKey, 6, &blob);
    EXPECT_NE(res, HCF_SUCCESS);

    res = keyPair->priKey->getKeyData(keyPair->priKey, 7, &blob);
    EXPECT_NE(res, HCF_SUCCESS);

    HcfObjDestroy(keyPair);
    HcfObjDestroy(generator);
}

// ==================== convertKey error tests (JS#21, JS#22) ====================

HWTEST_F(CryptoMlKemAsyKeyGeneratorTest, CryptoMlKemConvertKeyWrongLengthTest001, TestSize.Level0)
{
    HcfAsyKeyGenerator *generator = nullptr;
    HcfResult res = HcfAsyKeyGeneratorCreate(g_mlKem768AlgoName.c_str(), &generator);
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

HWTEST_F(CryptoMlKemAsyKeyGeneratorTest, CryptoMlKemConvertKeyCrossAlgoTest001, TestSize.Level0)
{
    HcfAsyKeyGenerator *mlKemGen = nullptr;
    HcfResult res = HcfAsyKeyGeneratorCreate(g_mlKem768AlgoName.c_str(), &mlKemGen);
    ASSERT_EQ(res, HCF_SUCCESS);

    HcfKeyPair *mlKemKeyPair = nullptr;
    res = mlKemGen->generateKeyPair(mlKemGen, nullptr, &mlKemKeyPair);
    ASSERT_EQ(res, HCF_SUCCESS);

    HcfBlob mlKemPubBlob = { .data = nullptr, .len = 0 };
    res = mlKemKeyPair->pubKey->base.getEncoded(&(mlKemKeyPair->pubKey->base), &mlKemPubBlob);
    ASSERT_EQ(res, HCF_SUCCESS);

    HcfBlob mlKemPriBlob = { .data = nullptr, .len = 0 };
    res = mlKemKeyPair->priKey->base.getEncoded(&(mlKemKeyPair->priKey->base), &mlKemPriBlob);
    ASSERT_EQ(res, HCF_SUCCESS);

    HcfAsyKeyGenerator *mlDsaGen = nullptr;
    res = HcfAsyKeyGeneratorCreate("ML-DSA-65", &mlDsaGen);
    ASSERT_EQ(res, HCF_SUCCESS);

    HcfKeyPair *crossKeyPair = nullptr;
    res = mlDsaGen->convertKey(mlDsaGen, nullptr, &mlKemPubBlob, nullptr, &crossKeyPair);
    EXPECT_NE(res, HCF_SUCCESS);

    res = mlDsaGen->convertKey(mlDsaGen, nullptr, nullptr, &mlKemPriBlob, &crossKeyPair);
    EXPECT_NE(res, HCF_SUCCESS);

    HcfFree(mlKemPubBlob.data);
    HcfFree(mlKemPriBlob.data);
    HcfObjDestroy(mlKemKeyPair);
    HcfObjDestroy(mlKemGen);
    HcfObjDestroy(mlDsaGen);
}

// ==================== convertKey with RAW key data (JS#14, JS#17) ====================

HWTEST_F(CryptoMlKemAsyKeyGeneratorTest, CryptoMlKem768ConvertKeyRawPubKeyTest001, TestSize.Level0)
{
    HcfAsyKeyGenerator *gen1 = nullptr;
    HcfResult res = HcfAsyKeyGeneratorCreate(g_mlKem768AlgoName.c_str(), &gen1);
    ASSERT_EQ(res, HCF_SUCCESS);

    HcfKeyPair *keyPair1 = nullptr;
    res = gen1->generateKeyPair(gen1, nullptr, &keyPair1);
    ASSERT_EQ(res, HCF_SUCCESS);

    HcfBlob pubRawBlob = { .data = nullptr, .len = 0 };
    res = keyPair1->pubKey->getKeyData(keyPair1->pubKey, ML_KEM_PUBLIC_RAW, &pubRawBlob);
    ASSERT_EQ(res, HCF_SUCCESS);

    HcfAsyKeyGenerator *gen2 = nullptr;
    res = HcfAsyKeyGeneratorCreate(g_mlKem768AlgoName.c_str(), &gen2);
    ASSERT_EQ(res, HCF_SUCCESS);

    HcfKeyPair *keyPair2 = nullptr;
    res = gen2->convertKey(gen2, nullptr, &pubRawBlob, nullptr, &keyPair2);
    ASSERT_EQ(res, HCF_SUCCESS);

    HcfBlob convertedPubRaw = { .data = nullptr, .len = 0 };
    res = keyPair2->pubKey->getKeyData(keyPair2->pubKey, ML_KEM_PUBLIC_RAW, &convertedPubRaw);
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

HWTEST_F(CryptoMlKemAsyKeyGeneratorTest, CryptoMlKem768ConvertKeyRawKeyPairTest001, TestSize.Level0)
{
    HcfAsyKeyGenerator *gen1 = nullptr;
    HcfResult res = HcfAsyKeyGeneratorCreate(g_mlKem768AlgoName.c_str(), &gen1);
    ASSERT_EQ(res, HCF_SUCCESS);

    HcfKeyPair *keyPair1 = nullptr;
    res = gen1->generateKeyPair(gen1, nullptr, &keyPair1);
    ASSERT_EQ(res, HCF_SUCCESS);

    HcfBlob pubRawBlob = { .data = nullptr, .len = 0 };
    res = keyPair1->pubKey->getKeyData(keyPair1->pubKey, ML_KEM_PUBLIC_RAW, &pubRawBlob);
    ASSERT_EQ(res, HCF_SUCCESS);

    HcfBlob priRawBlob = { .data = nullptr, .len = 0 };
    res = keyPair1->priKey->getKeyData(keyPair1->priKey, ML_KEM_PRIVATE_RAW, &priRawBlob);
    ASSERT_EQ(res, HCF_SUCCESS);

    HcfAsyKeyGenerator *gen2 = nullptr;
    res = HcfAsyKeyGeneratorCreate(g_mlKem768AlgoName.c_str(), &gen2);
    ASSERT_EQ(res, HCF_SUCCESS);

    HcfKeyPair *keyPair2 = nullptr;
    res = gen2->convertKey(gen2, nullptr, &pubRawBlob, &priRawBlob, &keyPair2);
    ASSERT_EQ(res, HCF_SUCCESS);

    HcfBlob convertedPubRaw = { .data = nullptr, .len = 0 };
    res = keyPair2->pubKey->getKeyData(keyPair2->pubKey, ML_KEM_PUBLIC_RAW, &convertedPubRaw);
    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_EQ(pubRawBlob.len, convertedPubRaw.len);
    ASSERT_EQ(memcmp(pubRawBlob.data, convertedPubRaw.data, pubRawBlob.len), 0);
    HcfFree(convertedPubRaw.data);

    HcfBlob convertedPriRaw = { .data = nullptr, .len = 0 };
    res = keyPair2->priKey->getKeyData(keyPair2->priKey, ML_KEM_PRIVATE_RAW, &convertedPriRaw);
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

HWTEST_F(CryptoMlKemAsyKeyGeneratorTest, CryptoMlKem768ConvertKeySeedDataTest001, TestSize.Level0)
{
    HcfAsyKeyGenerator *gen1 = nullptr;
    HcfResult res = HcfAsyKeyGeneratorCreate(g_mlKem768AlgoName.c_str(), &gen1);
    ASSERT_EQ(res, HCF_SUCCESS);

    HcfKeyPair *keyPair1 = nullptr;
    res = gen1->generateKeyPair(gen1, nullptr, &keyPair1);
    ASSERT_EQ(res, HCF_SUCCESS);

    HcfBlob pubRawBlob = { .data = nullptr, .len = 0 };
    res = keyPair1->pubKey->getKeyData(keyPair1->pubKey, ML_KEM_PUBLIC_RAW, &pubRawBlob);
    ASSERT_EQ(res, HCF_SUCCESS);

    HcfBlob seedBlob = { .data = nullptr, .len = 0 };
    res = keyPair1->priKey->getKeyData(keyPair1->priKey, ML_KEM_PRIVATE_SEED, &seedBlob);
    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_EQ(seedBlob.len, 64);

    HcfAsyKeyGenerator *gen2 = nullptr;
    res = HcfAsyKeyGeneratorCreate(g_mlKem768AlgoName.c_str(), &gen2);
    ASSERT_EQ(res, HCF_SUCCESS);

    HcfKeyPair *keyPair2 = nullptr;
    res = gen2->convertKey(gen2, nullptr, &pubRawBlob, &seedBlob, &keyPair2);
    ASSERT_EQ(res, HCF_SUCCESS);

    HcfBlob convertedPubRaw = { .data = nullptr, .len = 0 };
    res = keyPair2->pubKey->getKeyData(keyPair2->pubKey, ML_KEM_PUBLIC_RAW, &convertedPubRaw);
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

// ==================== convertKey seed length error (JS#23) ====================

HWTEST_F(CryptoMlKemAsyKeyGeneratorTest, CryptoMlKemConvertKeyWrongSeedLengthTest001, TestSize.Level0)
{
    HcfAsyKeyGenerator *gen = nullptr;
    HcfResult res = HcfAsyKeyGeneratorCreate(g_mlKem768AlgoName.c_str(), &gen);
    ASSERT_EQ(res, HCF_SUCCESS);

    HcfKeyPair *keyPair = nullptr;
    res = gen->generateKeyPair(gen, nullptr, &keyPair);
    ASSERT_EQ(res, HCF_SUCCESS);

    HcfBlob pubRawBlob = { .data = nullptr, .len = 0 };
    res = keyPair->pubKey->getKeyData(keyPair->pubKey, ML_KEM_PUBLIC_RAW, &pubRawBlob);
    ASSERT_EQ(res, HCF_SUCCESS);

    uint8_t shortSeed[32] = {0};
    HcfBlob shortSeedBlob = { .data = shortSeed, .len = sizeof(shortSeed) };
    HcfKeyPair *badKeyPair = nullptr;
    res = gen->convertKey(gen, nullptr, &pubRawBlob, &shortSeedBlob, &badKeyPair);
    EXPECT_NE(res, HCF_SUCCESS);

    uint8_t longSeed[128] = {0};
    HcfBlob longSeedBlob = { .data = longSeed, .len = sizeof(longSeed) };
    res = gen->convertKey(gen, nullptr, &pubRawBlob, &longSeedBlob, &badKeyPair);
    EXPECT_NE(res, HCF_SUCCESS);

    HcfFree(pubRawBlob.data);
    HcfObjDestroy(keyPair);
    HcfObjDestroy(gen);
}

// ==================== getAsyKeySpecBigInteger all variants ====================

HWTEST_F(CryptoMlKemAsyKeyGeneratorTest, CryptoMlKem768GetAsyKeySpecBigIntegerAllSizesTest001, TestSize.Level0)
{
    HcfAsyKeyGenerator *gen512 = nullptr;
    HcfResult res = HcfAsyKeyGeneratorCreate(g_mlKem512AlgoName.c_str(), &gen512);
    ASSERT_EQ(res, HCF_SUCCESS);
    HcfKeyPair *kp512 = nullptr;
    res = gen512->generateKeyPair(gen512, nullptr, &kp512);
    ASSERT_EQ(res, HCF_SUCCESS);
    HcfBigInteger bigInt512 = { .data = nullptr, .len = 0 };
    res = kp512->pubKey->getAsyKeySpecBigInteger(kp512->pubKey, ML_KEM_512_PK_BN, &bigInt512);
    EXPECT_EQ(res, HCF_ERR_INVALID_CALL);
    HcfObjDestroy(kp512);
    HcfObjDestroy(gen512);

    HcfAsyKeyGenerator *gen1024 = nullptr;
    res = HcfAsyKeyGeneratorCreate(g_mlKem1024AlgoName.c_str(), &gen1024);
    ASSERT_EQ(res, HCF_SUCCESS);
    HcfKeyPair *kp1024 = nullptr;
    res = gen1024->generateKeyPair(gen1024, nullptr, &kp1024);
    ASSERT_EQ(res, HCF_SUCCESS);
    HcfBigInteger bigInt1024 = { .data = nullptr, .len = 0 };
    res = kp1024->pubKey->getAsyKeySpecBigInteger(kp1024->pubKey, ML_KEM_1024_PK_BN, &bigInt1024);
    EXPECT_EQ(res, HCF_ERR_INVALID_CALL);
    HcfObjDestroy(kp1024);
    HcfObjDestroy(gen1024);
}

// ==================== convertPemKey round-trip tests ====================

HWTEST_F(CryptoMlKemAsyKeyGeneratorTest, CryptoMlKem768ConvertPemKeyTest001, TestSize.Level0)
{
    HcfAsyKeyGenerator *gen = nullptr;
    HcfResult res = HcfAsyKeyGeneratorCreate(g_mlKem768AlgoName.c_str(), &gen);
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

HWTEST_F(CryptoMlKemAsyKeyGeneratorTest, CryptoMlKem768ConvertPemKeyNegativeTest001, TestSize.Level0)
{
    HcfAsyKeyGenerator *gen = nullptr;
    HcfResult res = HcfAsyKeyGeneratorCreate(g_mlKem768AlgoName.c_str(), &gen);
    ASSERT_EQ(res, HCF_SUCCESS);

    HcfKeyPair *keyPair = nullptr;
    res = gen->convertPemKey(gen, nullptr, nullptr, nullptr, &keyPair);
    EXPECT_NE(res, HCF_SUCCESS);

    res = gen->convertPemKey(gen, nullptr, "invalid_pub", "invalid_pri", &keyPair);
    EXPECT_NE(res, HCF_SUCCESS);

    HcfObjDestroy(gen);
}

HWTEST_F(CryptoMlKemAsyKeyGeneratorTest, CryptoMlKem512ConvertKeyRawPubKeyTest001, TestSize.Level0)
{
    HcfAsyKeyGenerator *gen1 = nullptr;
    HcfResult res = HcfAsyKeyGeneratorCreate(g_mlKem512AlgoName.c_str(), &gen1);
    ASSERT_EQ(res, HCF_SUCCESS);

    HcfKeyPair *keyPair1 = nullptr;
    res = gen1->generateKeyPair(gen1, nullptr, &keyPair1);
    ASSERT_EQ(res, HCF_SUCCESS);

    HcfBlob pubRawBlob = { .data = nullptr, .len = 0 };
    res = keyPair1->pubKey->getKeyData(keyPair1->pubKey, ML_KEM_PUBLIC_RAW, &pubRawBlob);
    ASSERT_EQ(res, HCF_SUCCESS);

    HcfAsyKeyGenerator *gen2 = nullptr;
    res = HcfAsyKeyGeneratorCreate(g_mlKem512AlgoName.c_str(), &gen2);
    ASSERT_EQ(res, HCF_SUCCESS);

    HcfKeyPair *keyPair2 = nullptr;
    res = gen2->convertKey(gen2, nullptr, &pubRawBlob, nullptr, &keyPair2);
    ASSERT_EQ(res, HCF_SUCCESS);

    HcfBlob convertedPubRaw = { .data = nullptr, .len = 0 };
    res = keyPair2->pubKey->getKeyData(keyPair2->pubKey, ML_KEM_PUBLIC_RAW, &convertedPubRaw);
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

HWTEST_F(CryptoMlKemAsyKeyGeneratorTest, CryptoMlKem512ConvertKeyRawKeyPairTest001, TestSize.Level0)
{
    HcfAsyKeyGenerator *gen1 = nullptr;
    HcfResult res = HcfAsyKeyGeneratorCreate(g_mlKem512AlgoName.c_str(), &gen1);
    ASSERT_EQ(res, HCF_SUCCESS);

    HcfKeyPair *keyPair1 = nullptr;
    res = gen1->generateKeyPair(gen1, nullptr, &keyPair1);
    ASSERT_EQ(res, HCF_SUCCESS);

    HcfBlob pubRawBlob = { .data = nullptr, .len = 0 };
    res = keyPair1->pubKey->getKeyData(keyPair1->pubKey, ML_KEM_PUBLIC_RAW, &pubRawBlob);
    ASSERT_EQ(res, HCF_SUCCESS);

    HcfBlob priRawBlob = { .data = nullptr, .len = 0 };
    res = keyPair1->priKey->getKeyData(keyPair1->priKey, ML_KEM_PRIVATE_RAW, &priRawBlob);
    ASSERT_EQ(res, HCF_SUCCESS);

    HcfAsyKeyGenerator *gen2 = nullptr;
    res = HcfAsyKeyGeneratorCreate(g_mlKem512AlgoName.c_str(), &gen2);
    ASSERT_EQ(res, HCF_SUCCESS);

    HcfKeyPair *keyPair2 = nullptr;
    res = gen2->convertKey(gen2, nullptr, &pubRawBlob, &priRawBlob, &keyPair2);
    ASSERT_EQ(res, HCF_SUCCESS);

    HcfBlob convertedPubRaw = { .data = nullptr, .len = 0 };
    res = keyPair2->pubKey->getKeyData(keyPair2->pubKey, ML_KEM_PUBLIC_RAW, &convertedPubRaw);
    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_EQ(pubRawBlob.len, convertedPubRaw.len);
    ASSERT_EQ(memcmp(pubRawBlob.data, convertedPubRaw.data, pubRawBlob.len), 0);
    HcfFree(convertedPubRaw.data);

    HcfBlob convertedPriRaw = { .data = nullptr, .len = 0 };
    res = keyPair2->priKey->getKeyData(keyPair2->priKey, ML_KEM_PRIVATE_RAW, &convertedPriRaw);
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

HWTEST_F(CryptoMlKemAsyKeyGeneratorTest, CryptoMlKem512ConvertKeySeedDataTest001, TestSize.Level0)
{
    HcfAsyKeyGenerator *gen1 = nullptr;
    HcfResult res = HcfAsyKeyGeneratorCreate(g_mlKem512AlgoName.c_str(), &gen1);
    ASSERT_EQ(res, HCF_SUCCESS);

    HcfKeyPair *keyPair1 = nullptr;
    res = gen1->generateKeyPair(gen1, nullptr, &keyPair1);
    ASSERT_EQ(res, HCF_SUCCESS);

    HcfBlob pubRawBlob = { .data = nullptr, .len = 0 };
    res = keyPair1->pubKey->getKeyData(keyPair1->pubKey, ML_KEM_PUBLIC_RAW, &pubRawBlob);
    ASSERT_EQ(res, HCF_SUCCESS);

    HcfBlob seedBlob = { .data = nullptr, .len = 0 };
    res = keyPair1->priKey->getKeyData(keyPair1->priKey, ML_KEM_PRIVATE_SEED, &seedBlob);
    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_EQ(seedBlob.len, 64);

    HcfAsyKeyGenerator *gen2 = nullptr;
    res = HcfAsyKeyGeneratorCreate(g_mlKem512AlgoName.c_str(), &gen2);
    ASSERT_EQ(res, HCF_SUCCESS);

    HcfKeyPair *keyPair2 = nullptr;
    res = gen2->convertKey(gen2, nullptr, &pubRawBlob, &seedBlob, &keyPair2);
    ASSERT_EQ(res, HCF_SUCCESS);

    HcfBlob convertedPubRaw = { .data = nullptr, .len = 0 };
    res = keyPair2->pubKey->getKeyData(keyPair2->pubKey, ML_KEM_PUBLIC_RAW, &convertedPubRaw);
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

HWTEST_F(CryptoMlKemAsyKeyGeneratorTest, CryptoMlKem1024ConvertKeyRawPubKeyTest001, TestSize.Level0)
{
    HcfAsyKeyGenerator *gen1 = nullptr;
    HcfResult res = HcfAsyKeyGeneratorCreate(g_mlKem1024AlgoName.c_str(), &gen1);
    ASSERT_EQ(res, HCF_SUCCESS);

    HcfKeyPair *keyPair1 = nullptr;
    res = gen1->generateKeyPair(gen1, nullptr, &keyPair1);
    ASSERT_EQ(res, HCF_SUCCESS);

    HcfBlob pubRawBlob = { .data = nullptr, .len = 0 };
    res = keyPair1->pubKey->getKeyData(keyPair1->pubKey, ML_KEM_PUBLIC_RAW, &pubRawBlob);
    ASSERT_EQ(res, HCF_SUCCESS);

    HcfAsyKeyGenerator *gen2 = nullptr;
    res = HcfAsyKeyGeneratorCreate(g_mlKem1024AlgoName.c_str(), &gen2);
    ASSERT_EQ(res, HCF_SUCCESS);

    HcfKeyPair *keyPair2 = nullptr;
    res = gen2->convertKey(gen2, nullptr, &pubRawBlob, nullptr, &keyPair2);
    ASSERT_EQ(res, HCF_SUCCESS);

    HcfBlob convertedPubRaw = { .data = nullptr, .len = 0 };
    res = keyPair2->pubKey->getKeyData(keyPair2->pubKey, ML_KEM_PUBLIC_RAW, &convertedPubRaw);
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

HWTEST_F(CryptoMlKemAsyKeyGeneratorTest, CryptoMlKem1024ConvertKeyRawKeyPairTest001, TestSize.Level0)
{
    HcfAsyKeyGenerator *gen1 = nullptr;
    HcfResult res = HcfAsyKeyGeneratorCreate(g_mlKem1024AlgoName.c_str(), &gen1);
    ASSERT_EQ(res, HCF_SUCCESS);

    HcfKeyPair *keyPair1 = nullptr;
    res = gen1->generateKeyPair(gen1, nullptr, &keyPair1);
    ASSERT_EQ(res, HCF_SUCCESS);

    HcfBlob pubRawBlob = { .data = nullptr, .len = 0 };
    res = keyPair1->pubKey->getKeyData(keyPair1->pubKey, ML_KEM_PUBLIC_RAW, &pubRawBlob);
    ASSERT_EQ(res, HCF_SUCCESS);

    HcfBlob priRawBlob = { .data = nullptr, .len = 0 };
    res = keyPair1->priKey->getKeyData(keyPair1->priKey, ML_KEM_PRIVATE_RAW, &priRawBlob);
    ASSERT_EQ(res, HCF_SUCCESS);

    HcfAsyKeyGenerator *gen2 = nullptr;
    res = HcfAsyKeyGeneratorCreate(g_mlKem1024AlgoName.c_str(), &gen2);
    ASSERT_EQ(res, HCF_SUCCESS);

    HcfKeyPair *keyPair2 = nullptr;
    res = gen2->convertKey(gen2, nullptr, &pubRawBlob, &priRawBlob, &keyPair2);
    ASSERT_EQ(res, HCF_SUCCESS);

    HcfBlob convertedPubRaw = { .data = nullptr, .len = 0 };
    res = keyPair2->pubKey->getKeyData(keyPair2->pubKey, ML_KEM_PUBLIC_RAW, &convertedPubRaw);
    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_EQ(pubRawBlob.len, convertedPubRaw.len);
    ASSERT_EQ(memcmp(pubRawBlob.data, convertedPubRaw.data, pubRawBlob.len), 0);
    HcfFree(convertedPubRaw.data);

    HcfBlob convertedPriRaw = { .data = nullptr, .len = 0 };
    res = keyPair2->priKey->getKeyData(keyPair2->priKey, ML_KEM_PRIVATE_RAW, &convertedPriRaw);
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

HWTEST_F(CryptoMlKemAsyKeyGeneratorTest, CryptoMlKem1024ConvertKeySeedDataTest001, TestSize.Level0)
{
    HcfAsyKeyGenerator *gen1 = nullptr;
    HcfResult res = HcfAsyKeyGeneratorCreate(g_mlKem1024AlgoName.c_str(), &gen1);
    ASSERT_EQ(res, HCF_SUCCESS);

    HcfKeyPair *keyPair1 = nullptr;
    res = gen1->generateKeyPair(gen1, nullptr, &keyPair1);
    ASSERT_EQ(res, HCF_SUCCESS);

    HcfBlob pubRawBlob = { .data = nullptr, .len = 0 };
    res = keyPair1->pubKey->getKeyData(keyPair1->pubKey, ML_KEM_PUBLIC_RAW, &pubRawBlob);
    ASSERT_EQ(res, HCF_SUCCESS);

    HcfBlob seedBlob = { .data = nullptr, .len = 0 };
    res = keyPair1->priKey->getKeyData(keyPair1->priKey, ML_KEM_PRIVATE_SEED, &seedBlob);
    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_EQ(seedBlob.len, 64);

    HcfAsyKeyGenerator *gen2 = nullptr;
    res = HcfAsyKeyGeneratorCreate(g_mlKem1024AlgoName.c_str(), &gen2);
    ASSERT_EQ(res, HCF_SUCCESS);

    HcfKeyPair *keyPair2 = nullptr;
    res = gen2->convertKey(gen2, nullptr, &pubRawBlob, &seedBlob, &keyPair2);
    ASSERT_EQ(res, HCF_SUCCESS);

    HcfBlob convertedPubRaw = { .data = nullptr, .len = 0 };
    res = keyPair2->pubKey->getKeyData(keyPair2->pubKey, ML_KEM_PUBLIC_RAW, &convertedPubRaw);
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
