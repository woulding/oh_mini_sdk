/*
 * Copyright (C) 2023 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file EXPECT in compliance with the License.
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
#include "big_integer.h"
#include "key.h"
#include "memory.h"
#include "openssl_adapter_mock.h"
#include "openssl_class.h"

using namespace std;
using namespace testing::ext;

namespace {
class CryptoDsaAsyKeyGeneratorTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp();
    void TearDown();

    static HcfKeyPair *dsa1024KeyPair_;
    static HcfKeyPair *dsa2048KeyPair_;
    static HcfKeyPair *dsa3072KeyPair_;
};

HcfKeyPair *CryptoDsaAsyKeyGeneratorTest::dsa1024KeyPair_ = nullptr;
HcfKeyPair *CryptoDsaAsyKeyGeneratorTest::dsa2048KeyPair_ = nullptr;
HcfKeyPair *CryptoDsaAsyKeyGeneratorTest::dsa3072KeyPair_ = nullptr;

static HcfResult GenerateDsa1024KeyPair(HcfKeyPair **returnKeyPair)
{
    HcfAsyKeyGenerator *generator = nullptr;
    HcfResult ret = HcfAsyKeyGeneratorCreate("DSA1024", &generator);
    if (ret != HCF_SUCCESS) {
        return ret;
    }
    HcfKeyPair *keyPair = nullptr;
    ret = generator->generateKeyPair(generator, nullptr, &keyPair);
    HcfObjDestroy(generator);
    if (ret != HCF_SUCCESS) {
        return ret;
    }
    *returnKeyPair = keyPair;
    return HCF_SUCCESS;
}

static HcfResult GenerateDsa2048KeyPair(HcfKeyPair **returnKeyPair)
{
    HcfAsyKeyGenerator *generator = nullptr;
    HcfResult ret = HcfAsyKeyGeneratorCreate("DSA2048", &generator);
    if (ret != HCF_SUCCESS) {
        return ret;
    }
    HcfKeyPair *keyPair = nullptr;
    ret = generator->generateKeyPair(generator, nullptr, &keyPair);
    HcfObjDestroy(generator);
    if (ret != HCF_SUCCESS) {
        return ret;
    }
    *returnKeyPair = keyPair;
    return HCF_SUCCESS;
}

static HcfResult GenerateDsa3072KeyPair(HcfKeyPair **returnKeyPair)
{
    HcfAsyKeyGenerator *generator = nullptr;
    HcfResult ret = HcfAsyKeyGeneratorCreate("DSA3072", &generator);
    if (ret != HCF_SUCCESS) {
        return ret;
    }
    HcfKeyPair *keyPair = nullptr;
    ret = generator->generateKeyPair(generator, nullptr, &keyPair);
    HcfObjDestroy(generator);
    if (ret != HCF_SUCCESS) {
        return ret;
    }
    *returnKeyPair = keyPair;
    return HCF_SUCCESS;
}

void CryptoDsaAsyKeyGeneratorTest::SetUpTestCase()
{
    HcfKeyPair *keyPair1024 = nullptr;
    HcfKeyPair *keyPair2048 = nullptr;
    HcfKeyPair *keyPair3072 = nullptr;
    EXPECT_EQ(GenerateDsa1024KeyPair(&keyPair1024), HCF_SUCCESS);
    EXPECT_EQ(GenerateDsa2048KeyPair(&keyPair2048), HCF_SUCCESS);
    EXPECT_EQ(GenerateDsa3072KeyPair(&keyPair3072), HCF_SUCCESS);
    dsa1024KeyPair_ = keyPair1024;
    dsa2048KeyPair_ = keyPair2048;
    dsa3072KeyPair_ = keyPair3072;
}

void CryptoDsaAsyKeyGeneratorTest::TearDownTestCase()
{
    HcfObjDestroy(dsa1024KeyPair_);
    HcfObjDestroy(dsa2048KeyPair_);
    HcfObjDestroy(dsa3072KeyPair_);
}
void CryptoDsaAsyKeyGeneratorTest::SetUp() {}
void CryptoDsaAsyKeyGeneratorTest::TearDown() {}

static const char *g_algNameDSA = "DSA";
static const char *g_opensslDsaPubKeyFormat = "X.509";
static const char *g_opensslDsaPriKeyFormat = "PKCS#8";

static const char *GetMockClass(void)
{
    return "HcfSymKeyGenerator";
}

HcfObjectBase g_obj = {
    .getClass = GetMockClass,
    .destroy = nullptr
};

static HcfResult GetKeyEncodedTest(HcfKeyPair *keyPair, HcfBlob *pkBlob, HcfBlob *skBlob)
{
    HcfResult ret = keyPair->pubKey->base.getEncoded(&(keyPair->pubKey->base), pkBlob);
    if (ret != HCF_SUCCESS) {
        return ret;
    }
    ret = keyPair->priKey->base.getEncoded(&(keyPair->priKey->base), skBlob);
    if (ret != HCF_SUCCESS) {
        HcfFree(pkBlob->data);
        return ret;
    }
    return HCF_SUCCESS;
}

HWTEST_F(CryptoDsaAsyKeyGeneratorTest, CryptoDsaAsyKeyGeneratorTest009, TestSize.Level0)
{
    HcfAsyKeyGenerator *generator = nullptr;
    HcfResult ret = HcfAsyKeyGeneratorCreate("DSA1024", &generator);

    ASSERT_EQ(ret, HCF_SUCCESS);
    ASSERT_NE(generator, nullptr);

    HcfObjDestroy(generator);
}

HWTEST_F(CryptoDsaAsyKeyGeneratorTest, CryptoDsaAsyKeyGeneratorTest010, TestSize.Level0)
{
    HcfAsyKeyGenerator *generator = nullptr;
    HcfResult ret = HcfAsyKeyGeneratorCreate("DSA2048", &generator);

    ASSERT_EQ(ret, HCF_SUCCESS);
    ASSERT_NE(generator, nullptr);

    HcfObjDestroy(generator);
}

HWTEST_F(CryptoDsaAsyKeyGeneratorTest, CryptoDsaAsyKeyGeneratorTest011, TestSize.Level0)
{
    HcfAsyKeyGenerator *generator = nullptr;
    HcfResult ret = HcfAsyKeyGeneratorCreate("DSA3072", &generator);

    ASSERT_EQ(ret, HCF_SUCCESS);
    ASSERT_NE(generator, nullptr);

    HcfObjDestroy(generator);
}

HWTEST_F(CryptoDsaAsyKeyGeneratorTest, CryptoDsaAsyKeyGeneratorTest012, TestSize.Level1)
{
    HcfAsyKeyGenerator *generator = nullptr;
    HcfResult ret = HcfAsyKeyGeneratorCreate("DSA", &generator);

    ASSERT_EQ(ret, HCF_INVALID_PARAMS);
}

HWTEST_F(CryptoDsaAsyKeyGeneratorTest, CryptoDsaAsyKeyGeneratorTest013, TestSize.Level1)
{
    HcfAsyKeyGenerator *generator = nullptr;
    HcfResult ret = HcfAsyKeyGeneratorCreate("DSA4096", &generator);

    ASSERT_EQ(ret, HCF_INVALID_PARAMS);
}

HWTEST_F(CryptoDsaAsyKeyGeneratorTest, CryptoDsaAsyKeyGeneratorTest101, TestSize.Level0)
{
    HcfAsyKeyGenerator *generator = nullptr;
    HcfResult ret = HcfAsyKeyGeneratorCreate("DSA1024", &generator);

    ASSERT_EQ(ret, HCF_SUCCESS);
    ASSERT_NE(generator, nullptr);

    const char *className = generator->base.getClass();
    ASSERT_NE(className, nullptr);

    HcfObjDestroy(generator);
}

HWTEST_F(CryptoDsaAsyKeyGeneratorTest, CryptoDsaAsyKeyGeneratorTest102, TestSize.Level0)
{
    HcfAsyKeyGenerator *generator = nullptr;
    HcfResult ret = HcfAsyKeyGeneratorCreate("DSA1024", &generator);

    ASSERT_EQ(ret, HCF_SUCCESS);
    ASSERT_NE(generator, nullptr);

    generator->base.destroy(&(generator->base));
}

HWTEST_F(CryptoDsaAsyKeyGeneratorTest, CryptoDsaAsyKeyGeneratorTest103, TestSize.Level0)
{
    HcfAsyKeyGenerator *generator = nullptr;
    HcfResult ret = HcfAsyKeyGeneratorCreate("DSA1024", &generator);

    ASSERT_EQ(ret, HCF_SUCCESS);
    ASSERT_NE(generator, nullptr);

    generator->base.destroy(&(generator->base));
}

HWTEST_F(CryptoDsaAsyKeyGeneratorTest, CryptoDsaAsyKeyGeneratorTest104, TestSize.Level0)
{
    HcfAsyKeyGenerator *generator = nullptr;
    HcfResult ret = HcfAsyKeyGeneratorCreate("DSA2048", &generator);

    ASSERT_EQ(ret, HCF_SUCCESS);
    ASSERT_NE(generator, nullptr);

    const char *algName = generator->getAlgoName(generator);

    EXPECT_STREQ(algName, "DSA2048");
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoDsaAsyKeyGeneratorTest, CryptoDsaAsyKeyGeneratorTest201, TestSize.Level1)
{
    HcfAsyKeyGenerator *generator = nullptr;
    HcfResult ret = HcfAsyKeyGeneratorCreate("DSA2048", &generator);

    ASSERT_EQ(ret, HCF_SUCCESS);
    ASSERT_NE(generator, nullptr);

    HcfKeyPair *keyPair = nullptr;
    ret = generator->generateKeyPair(nullptr, nullptr, &keyPair);

    HcfObjDestroy(generator);
    ASSERT_EQ(ret, HCF_INVALID_PARAMS);
    ASSERT_EQ(keyPair, nullptr);
}

HWTEST_F(CryptoDsaAsyKeyGeneratorTest, CryptoDsaAsyKeyGeneratorTest202, TestSize.Level1)
{
    HcfAsyKeyGenerator *generator = nullptr;
    HcfResult ret = HcfAsyKeyGeneratorCreate("DSA2048", &generator);

    ASSERT_EQ(ret, HCF_SUCCESS);
    ASSERT_NE(generator, nullptr);

    ret = generator->generateKeyPair(generator, nullptr, nullptr);

    HcfObjDestroy(generator);
    ASSERT_EQ(ret, HCF_INVALID_PARAMS);
}

HWTEST_F(CryptoDsaAsyKeyGeneratorTest, CryptoDsaAsyKeyGeneratorTest203, TestSize.Level1)
{
    HcfAsyKeyGenerator *generator = nullptr;
    HcfResult ret = HcfAsyKeyGeneratorCreate("DSA2048", &generator);

    ASSERT_EQ(ret, HCF_SUCCESS);
    ASSERT_NE(generator, nullptr);

    HcfKeyPair *keyPair = nullptr;
    ret = generator->generateKeyPair((HcfAsyKeyGenerator *)&g_obj, nullptr, &keyPair);

    HcfObjDestroy(generator);
    ASSERT_EQ(ret, HCF_INVALID_PARAMS);
    ASSERT_EQ(keyPair, nullptr);
}

HWTEST_F(CryptoDsaAsyKeyGeneratorTest, CryptoDsaAsyKeyGeneratorTest301, TestSize.Level0)
{
    const char *className = dsa2048KeyPair_->base.getClass();
    EXPECT_STREQ(className, OPENSSL_DSA_KEYPAIR_CLASS);
}

HWTEST_F(CryptoDsaAsyKeyGeneratorTest, CryptoDsaAsyKeyGeneratorTest302, TestSize.Level0)
{
    HcfAsyKeyGenerator *generator = nullptr;
    HcfResult ret = HcfAsyKeyGeneratorCreate("DSA1024", &generator);

    ASSERT_EQ(ret, HCF_SUCCESS);
    ASSERT_NE(generator, nullptr);

    HcfKeyPair *keyPair = nullptr;
    ret = generator->generateKeyPair(generator, nullptr, &keyPair);

    HcfObjDestroy(generator);
    ASSERT_EQ(ret, HCF_SUCCESS);
    ASSERT_NE(keyPair, nullptr);

    keyPair->base.destroy(&(keyPair->base));
}

HWTEST_F(CryptoDsaAsyKeyGeneratorTest, CryptoDsaAsyKeyGeneratorTest305, TestSize.Level0)
{
    dsa2048KeyPair_->base.destroy(nullptr);
    dsa2048KeyPair_->base.destroy((HcfObjectBase *)&g_obj);

    const char *pkClassName = dsa2048KeyPair_->pubKey->base.base.getClass();
    EXPECT_STREQ(pkClassName, OPENSSL_DSA_PUBKEY_CLASS);
}

HWTEST_F(CryptoDsaAsyKeyGeneratorTest, CryptoDsaAsyKeyGeneratorTest306, TestSize.Level0)
{
    HcfAsyKeyGenerator *generator = nullptr;
    HcfResult ret = HcfAsyKeyGeneratorCreate("DSA2048", &generator);

    ASSERT_EQ(ret, HCF_SUCCESS);
    ASSERT_NE(generator, nullptr);

    HcfKeyPair *keyPair = nullptr;
    ret = generator->generateKeyPair(generator, nullptr, &keyPair);

    HcfObjDestroy(generator);
    ASSERT_EQ(ret, HCF_SUCCESS);
    ASSERT_NE(keyPair, nullptr);

    keyPair->pubKey->base.base.destroy(&(keyPair->pubKey->base.base));
    keyPair->pubKey = nullptr;
    HcfObjDestroy(keyPair);
}

HWTEST_F(CryptoDsaAsyKeyGeneratorTest, CryptoDsaAsyKeyGeneratorTest309, TestSize.Level0)
{
    dsa2048KeyPair_->pubKey->base.base.destroy(nullptr);
    dsa2048KeyPair_->pubKey->base.base.destroy((HcfObjectBase *)&g_obj);

    const char *alg = dsa2048KeyPair_->pubKey->base.getAlgorithm(&(dsa2048KeyPair_->pubKey->base));
    EXPECT_STREQ(alg, g_algNameDSA);
}

HWTEST_F(CryptoDsaAsyKeyGeneratorTest, CryptoDsaAsyKeyGeneratorTest310, TestSize.Level1)
{
    const char *alg = dsa2048KeyPair_->pubKey->base.getAlgorithm(nullptr);
    ASSERT_EQ(alg, nullptr);
}

HWTEST_F(CryptoDsaAsyKeyGeneratorTest, CryptoDsaAsyKeyGeneratorTest311, TestSize.Level1)
{
    const char *alg = dsa2048KeyPair_->pubKey->base.getAlgorithm((HcfKey *)&g_obj);
    ASSERT_EQ(alg, nullptr);
}

HWTEST_F(CryptoDsaAsyKeyGeneratorTest, CryptoDsaAsyKeyGeneratorTest312, TestSize.Level0)
{
    HcfBlob blob = { .data = nullptr, .len = 0 };
    HcfResult ret = dsa2048KeyPair_->pubKey->base.getEncoded(&(dsa2048KeyPair_->pubKey->base), &blob);

    ASSERT_EQ(ret, HCF_SUCCESS);
    ASSERT_NE(blob.data, nullptr);
    ASSERT_NE(blob.len, 0);
    HcfFree(blob.data);
}

HWTEST_F(CryptoDsaAsyKeyGeneratorTest, CryptoDsaAsyKeyGeneratorTest313, TestSize.Level1)
{
    HcfBlob blob = { .data = nullptr, .len = 0 };
    HcfResult ret = dsa2048KeyPair_->pubKey->base.getEncoded(nullptr, &blob);

    ASSERT_EQ(ret, HCF_INVALID_PARAMS);
    ASSERT_EQ(blob.data, nullptr);
    ASSERT_EQ(blob.len, 0);
}

HWTEST_F(CryptoDsaAsyKeyGeneratorTest, CryptoDsaAsyKeyGeneratorTest314, TestSize.Level1)
{
    HcfResult ret = dsa2048KeyPair_->pubKey->base.getEncoded(&(dsa2048KeyPair_->pubKey->base), nullptr);
    ASSERT_EQ(ret, HCF_INVALID_PARAMS);
}

HWTEST_F(CryptoDsaAsyKeyGeneratorTest, CryptoDsaAsyKeyGeneratorTest315, TestSize.Level1)
{
    HcfBlob blob = { .data = nullptr, .len = 0 };
    HcfResult ret = dsa2048KeyPair_->pubKey->base.getEncoded((HcfKey *)&g_obj, &blob);

    ASSERT_EQ(ret, HCF_INVALID_PARAMS);
    ASSERT_EQ(blob.data, nullptr);
    ASSERT_EQ(blob.len, 0);
}

HWTEST_F(CryptoDsaAsyKeyGeneratorTest, CryptoDsaAsyKeyGeneratorTest316, TestSize.Level0)
{
    const char *pkFormat = dsa2048KeyPair_->pubKey->base.getFormat(&(dsa2048KeyPair_->pubKey->base));
    ASSERT_STREQ(pkFormat, g_opensslDsaPubKeyFormat);
}

HWTEST_F(CryptoDsaAsyKeyGeneratorTest, CryptoDsaAsyKeyGeneratorTest317, TestSize.Level1)
{
    const char *pkFormat = dsa2048KeyPair_->pubKey->base.getFormat(nullptr);
    ASSERT_EQ(pkFormat, nullptr);
}

HWTEST_F(CryptoDsaAsyKeyGeneratorTest, CryptoDsaAsyKeyGeneratorTest318, TestSize.Level0)
{
    HcfBigInteger p = { .data = nullptr, .len = 0 };
    HcfResult ret = dsa2048KeyPair_->pubKey->getAsyKeySpecBigInteger(dsa2048KeyPair_->pubKey, DSA_P_BN, &p);

    ASSERT_EQ(ret, HCF_SUCCESS);
    ASSERT_NE(p.data, nullptr);
    ASSERT_NE(p.len, 0);
    HcfFree(p.data);
}

HWTEST_F(CryptoDsaAsyKeyGeneratorTest, CryptoDsaAsyKeyGeneratorTest319, TestSize.Level0)
{
    HcfBigInteger q = { .data = nullptr, .len = 0 };
    HcfResult ret = dsa2048KeyPair_->pubKey->getAsyKeySpecBigInteger(dsa2048KeyPair_->pubKey, DSA_Q_BN, &q);

    ASSERT_EQ(ret, HCF_SUCCESS);
    ASSERT_NE(q.data, nullptr);
    ASSERT_NE(q.len, 0);
    HcfFree(q.data);
}

HWTEST_F(CryptoDsaAsyKeyGeneratorTest, CryptoDsaAsyKeyGeneratorTest320, TestSize.Level0)
{
    HcfBigInteger g = { .data = nullptr, .len = 0 };
    HcfResult ret = dsa2048KeyPair_->pubKey->getAsyKeySpecBigInteger(dsa2048KeyPair_->pubKey, DSA_G_BN, &g);

    ASSERT_EQ(ret, HCF_SUCCESS);
    ASSERT_NE(g.data, nullptr);
    ASSERT_NE(g.len, 0);
    HcfFree(g.data);
}

HWTEST_F(CryptoDsaAsyKeyGeneratorTest, CryptoDsaAsyKeyGeneratorTest321, TestSize.Level0)
{
    HcfBigInteger pk = { .data = nullptr, .len = 0 };
    HcfResult ret = dsa2048KeyPair_->pubKey->getAsyKeySpecBigInteger(dsa2048KeyPair_->pubKey, DSA_PK_BN, &pk);

    ASSERT_EQ(ret, HCF_SUCCESS);
    ASSERT_NE(pk.data, nullptr);
    ASSERT_NE(pk.len, 0);
    HcfFree(pk.data);
}

HWTEST_F(CryptoDsaAsyKeyGeneratorTest, CryptoDsaAsyKeyGeneratorTest322, TestSize.Level0)
{
    int testI;
    HcfResult ret = dsa2048KeyPair_->pubKey->getAsyKeySpecInt(dsa2048KeyPair_->pubKey, DSA_P_BN, &testI);
    ASSERT_EQ(ret, HCF_NOT_SUPPORT);
}

HWTEST_F(CryptoDsaAsyKeyGeneratorTest, CryptoDsaAsyKeyGeneratorTest323, TestSize.Level0)
{
    char *testC = nullptr;
    HcfResult ret = dsa2048KeyPair_->pubKey->getAsyKeySpecString(dsa2048KeyPair_->pubKey, DSA_P_BN, &testC);

    ASSERT_EQ(ret, HCF_NOT_SUPPORT);
    ASSERT_EQ(testC, nullptr);
}

HWTEST_F(CryptoDsaAsyKeyGeneratorTest, CryptoDsaAsyKeyGeneratorTest324, TestSize.Level0)
{
    const char *skClassName = dsa2048KeyPair_->priKey->base.base.getClass();
    EXPECT_STREQ(skClassName, OPENSSL_DSA_PRIKEY_CLASS);
}

HWTEST_F(CryptoDsaAsyKeyGeneratorTest, CryptoDsaAsyKeyGeneratorTest325, TestSize.Level0)
{
    HcfAsyKeyGenerator *generator = nullptr;
    HcfResult ret = HcfAsyKeyGeneratorCreate("DSA2048", &generator);

    ASSERT_EQ(ret, HCF_SUCCESS);
    ASSERT_NE(generator, nullptr);

    HcfKeyPair *keyPair = nullptr;
    ret = generator->generateKeyPair(generator, nullptr, &keyPair);

    HcfObjDestroy(generator);
    ASSERT_EQ(ret, HCF_SUCCESS);
    ASSERT_NE(keyPair, nullptr);

    keyPair->priKey->base.base.destroy(&(keyPair->priKey->base.base));
    keyPair->priKey = nullptr;
    HcfObjDestroy(keyPair);
}

HWTEST_F(CryptoDsaAsyKeyGeneratorTest, CryptoDsaAsyKeyGeneratorTest326, TestSize.Level0)
{
    const char *alg = dsa2048KeyPair_->priKey->base.getAlgorithm(&(dsa2048KeyPair_->priKey->base));
    EXPECT_STREQ(alg, g_algNameDSA);
}

HWTEST_F(CryptoDsaAsyKeyGeneratorTest, CryptoDsaAsyKeyGeneratorTest327, TestSize.Level0)
{
    HcfBlob blob = { .data = nullptr, .len = 0 };
    HcfResult ret = dsa2048KeyPair_->priKey->base.getEncoded(&(dsa2048KeyPair_->priKey->base), &blob);

    ASSERT_EQ(ret, HCF_SUCCESS);
    ASSERT_NE(blob.data, nullptr);
    ASSERT_NE(blob.len, 0);
    HcfFree(blob.data);
}

HWTEST_F(CryptoDsaAsyKeyGeneratorTest, CryptoDsaAsyKeyGeneratorTest328, TestSize.Level0)
{
    const char *skFormat = dsa2048KeyPair_->priKey->base.getFormat(&(dsa2048KeyPair_->priKey->base));
    ASSERT_STREQ(skFormat, g_opensslDsaPriKeyFormat);
}

HWTEST_F(CryptoDsaAsyKeyGeneratorTest, CryptoDsaAsyKeyGeneratorTest329, TestSize.Level0)
{
    HcfBigInteger p = { .data = nullptr, .len = 0 };
    HcfResult ret = dsa2048KeyPair_->priKey->getAsyKeySpecBigInteger(dsa2048KeyPair_->priKey, DSA_P_BN, &p);

    ASSERT_EQ(ret, HCF_SUCCESS);
    ASSERT_NE(p.data, nullptr);
    ASSERT_NE(p.len, 0);
    HcfFree(p.data);
}

HWTEST_F(CryptoDsaAsyKeyGeneratorTest, CryptoDsaAsyKeyGeneratorTest330, TestSize.Level0)
{
    HcfBigInteger q = { .data = nullptr, .len = 0 };
    HcfResult ret = dsa2048KeyPair_->priKey->getAsyKeySpecBigInteger(dsa2048KeyPair_->priKey, DSA_Q_BN, &q);

    ASSERT_EQ(ret, HCF_SUCCESS);
    ASSERT_NE(q.data, nullptr);
    ASSERT_NE(q.len, 0);
    HcfFree(q.data);
}

HWTEST_F(CryptoDsaAsyKeyGeneratorTest, CryptoDsaAsyKeyGeneratorTest331, TestSize.Level0)
{
    HcfBigInteger g = { .data = nullptr, .len = 0 };
    HcfResult ret = dsa2048KeyPair_->priKey->getAsyKeySpecBigInteger(dsa2048KeyPair_->priKey, DSA_G_BN, &g);

    ASSERT_EQ(ret, HCF_SUCCESS);
    ASSERT_NE(g.data, nullptr);
    ASSERT_NE(g.len, 0);
    HcfFree(g.data);
}

HWTEST_F(CryptoDsaAsyKeyGeneratorTest, CryptoDsaAsyKeyGeneratorTest332, TestSize.Level0)
{
    HcfBigInteger sk = { .data = nullptr, .len = 0 };
    HcfResult ret = dsa2048KeyPair_->priKey->getAsyKeySpecBigInteger(dsa2048KeyPair_->priKey, DSA_SK_BN, &sk);

    ASSERT_EQ(ret, HCF_SUCCESS);
    ASSERT_NE(sk.data, nullptr);
    ASSERT_NE(sk.len, 0);
    HcfFree(sk.data);
}

HWTEST_F(CryptoDsaAsyKeyGeneratorTest, CryptoDsaAsyKeyGeneratorTest333, TestSize.Level0)
{
    int testI;
    HcfResult ret = dsa2048KeyPair_->priKey->getAsyKeySpecInt(dsa2048KeyPair_->priKey, DSA_P_BN, &testI);
    ASSERT_EQ(ret, HCF_NOT_SUPPORT);
}

HWTEST_F(CryptoDsaAsyKeyGeneratorTest, CryptoDsaAsyKeyGeneratorTest334, TestSize.Level0)
{
    char *testC;
    HcfResult ret = dsa2048KeyPair_->priKey->getAsyKeySpecString(dsa2048KeyPair_->priKey, DSA_P_BN, &testC);
    ASSERT_EQ(ret, HCF_NOT_SUPPORT);
}

HWTEST_F(CryptoDsaAsyKeyGeneratorTest, CryptoDsaAsyKeyGeneratorTest335, TestSize.Level0)
{
    HcfAsyKeyGenerator *generator = nullptr;
    HcfResult ret = HcfAsyKeyGeneratorCreate("DSA2048", &generator);

    ASSERT_EQ(ret, HCF_SUCCESS);
    ASSERT_NE(generator, nullptr);

    HcfKeyPair *keyPair = nullptr;
    ret = generator->generateKeyPair(generator, nullptr, &keyPair);

    HcfObjDestroy(generator);
    ASSERT_EQ(ret, HCF_SUCCESS);
    ASSERT_NE(keyPair, nullptr);

    keyPair->priKey->clearMem(keyPair->priKey);
    HcfObjDestroy(keyPair);
}

HWTEST_F(CryptoDsaAsyKeyGeneratorTest, CryptoDsaAsyKeyGeneratorTest409, TestSize.Level0)
{
    HcfAsyKeyGenerator *generator = nullptr;
    HcfResult ret = HcfAsyKeyGeneratorCreate("DSA1024", &generator);
    ASSERT_EQ(ret, HCF_SUCCESS);
    ASSERT_NE(generator, nullptr);

    HcfBlob pkBlob = { .data = nullptr, .len = 0 };
    HcfBlob skBlob = { .data = nullptr, .len = 0 };
    EXPECT_EQ(GetKeyEncodedTest(dsa1024KeyPair_, &pkBlob, &skBlob), HCF_SUCCESS);

    HcfKeyPair *convertKeyPair = nullptr;
    ret = generator->convertKey(generator, nullptr, &pkBlob, &skBlob, &convertKeyPair);
    EXPECT_EQ(ret, HCF_SUCCESS);
    EXPECT_NE(convertKeyPair, nullptr);

    HcfObjDestroy(generator);
    HcfObjDestroy(convertKeyPair);
    HcfFree(pkBlob.data);
    HcfFree(skBlob.data);
}

HWTEST_F(CryptoDsaAsyKeyGeneratorTest, CryptoDsaAsyKeyGeneratorTest410, TestSize.Level0)
{
    HcfAsyKeyGenerator *generator = nullptr;
    HcfResult ret = HcfAsyKeyGeneratorCreate("DSA2048", &generator);
    ASSERT_EQ(ret, HCF_SUCCESS);
    ASSERT_NE(generator, nullptr);

    HcfBlob pkBlob = { .data = nullptr, .len = 0 };
    HcfBlob skBlob = { .data = nullptr, .len = 0 };
    EXPECT_EQ(GetKeyEncodedTest(dsa2048KeyPair_, &pkBlob, &skBlob), HCF_SUCCESS);

    HcfKeyPair *convertKeyPair = nullptr;
    ret = generator->convertKey(generator, nullptr, &pkBlob, &skBlob, &convertKeyPair);
    EXPECT_EQ(ret, HCF_SUCCESS);
    EXPECT_NE(convertKeyPair, nullptr);

    HcfObjDestroy(generator);
    HcfObjDestroy(convertKeyPair);
    HcfFree(pkBlob.data);
    HcfFree(skBlob.data);
}

HWTEST_F(CryptoDsaAsyKeyGeneratorTest, CryptoDsaAsyKeyGeneratorTest411, TestSize.Level0)
{
    HcfAsyKeyGenerator *generator = nullptr;
    HcfResult ret = HcfAsyKeyGeneratorCreate("DSA3072", &generator);
    ASSERT_EQ(ret, HCF_SUCCESS);
    ASSERT_NE(generator, nullptr);

    HcfBlob pkBlob = { .data = nullptr, .len = 0 };
    HcfBlob skBlob = { .data = nullptr, .len = 0 };
    EXPECT_EQ(GetKeyEncodedTest(dsa3072KeyPair_, &pkBlob, &skBlob), HCF_SUCCESS);

    HcfKeyPair *convertKeyPair = nullptr;
    ret = generator->convertKey(generator, nullptr, &pkBlob, &skBlob, &convertKeyPair);
    EXPECT_EQ(ret, HCF_SUCCESS);
    EXPECT_NE(convertKeyPair, nullptr);

    HcfObjDestroy(generator);
    HcfObjDestroy(convertKeyPair);
    HcfFree(pkBlob.data);
    HcfFree(skBlob.data);
}

HWTEST_F(CryptoDsaAsyKeyGeneratorTest, CryptoDsaAsyKeyGeneratorTest501, TestSize.Level0)
{
    HcfAsyKeyGenerator *generator = nullptr;
    HcfResult ret = HcfAsyKeyGeneratorCreate("DSA2048", &generator);
    ASSERT_EQ(ret, HCF_SUCCESS);
    ASSERT_NE(generator, nullptr);

    HcfBlob pkBlob = { .data = nullptr, .len = 0 };
    HcfBlob skBlob = { .data = nullptr, .len = 0 };
    EXPECT_EQ(GetKeyEncodedTest(dsa2048KeyPair_, &pkBlob, &skBlob), HCF_SUCCESS);

    HcfKeyPair *convertKeyPair = nullptr;
    ret = generator->convertKey(generator, nullptr, &pkBlob, &skBlob, &convertKeyPair);
    EXPECT_EQ(ret, HCF_SUCCESS);
    EXPECT_NE(convertKeyPair, nullptr);

    const char *keyPairClassName = convertKeyPair->base.getClass();
    EXPECT_STREQ(keyPairClassName, OPENSSL_DSA_KEYPAIR_CLASS);

    HcfObjDestroy(generator);
    HcfObjDestroy(convertKeyPair);
    HcfFree(pkBlob.data);
    HcfFree(skBlob.data);
}

HWTEST_F(CryptoDsaAsyKeyGeneratorTest, CryptoDsaAsyKeyGeneratorTest502, TestSize.Level0)
{
    HcfAsyKeyGenerator *generator = nullptr;
    HcfResult ret = HcfAsyKeyGeneratorCreate("DSA2048", &generator);
    ASSERT_EQ(ret, HCF_SUCCESS);
    ASSERT_NE(generator, nullptr);

    HcfBlob pkBlob = { .data = nullptr, .len = 0 };
    HcfBlob skBlob = { .data = nullptr, .len = 0 };
    EXPECT_EQ(GetKeyEncodedTest(dsa2048KeyPair_, &pkBlob, &skBlob), HCF_SUCCESS);

    HcfKeyPair *convertKeyPair = nullptr;
    ret = generator->convertKey(generator, nullptr, &pkBlob, &skBlob, &convertKeyPair);
    EXPECT_EQ(ret, HCF_SUCCESS);
    EXPECT_NE(convertKeyPair, nullptr);

    convertKeyPair->base.destroy(&(convertKeyPair->base));
    HcfObjDestroy(generator);
    HcfFree(pkBlob.data);
    HcfFree(skBlob.data);
}

HWTEST_F(CryptoDsaAsyKeyGeneratorTest, CryptoDsaAsyKeyGeneratorTest503, TestSize.Level0)
{
    HcfAsyKeyGenerator *generator = nullptr;
    HcfResult ret = HcfAsyKeyGeneratorCreate("DSA2048", &generator);
    ASSERT_EQ(ret, HCF_SUCCESS);
    ASSERT_NE(generator, nullptr);

    HcfBlob pkBlob = { .data = nullptr, .len = 0 };
    HcfBlob skBlob = { .data = nullptr, .len = 0 };
    EXPECT_EQ(GetKeyEncodedTest(dsa2048KeyPair_, &pkBlob, &skBlob), HCF_SUCCESS);

    HcfKeyPair *convertKeyPair = nullptr;
    ret = generator->convertKey(generator, nullptr, &pkBlob, &skBlob, &convertKeyPair);
    EXPECT_EQ(ret, HCF_SUCCESS);
    EXPECT_NE(convertKeyPair, nullptr);

    const char *pkClassName = convertKeyPair->pubKey->base.base.getClass();
    EXPECT_STREQ(pkClassName, OPENSSL_DSA_PUBKEY_CLASS);

    HcfObjDestroy(generator);
    HcfObjDestroy(convertKeyPair);
    HcfFree(pkBlob.data);
    HcfFree(skBlob.data);
}

HWTEST_F(CryptoDsaAsyKeyGeneratorTest, CryptoDsaAsyKeyGeneratorTest504, TestSize.Level0)
{
    HcfAsyKeyGenerator *generator = nullptr;
    HcfResult ret = HcfAsyKeyGeneratorCreate("DSA2048", &generator);
    ASSERT_EQ(ret, HCF_SUCCESS);
    ASSERT_NE(generator, nullptr);

    HcfBlob pkBlob = { .data = nullptr, .len = 0 };
    HcfBlob skBlob = { .data = nullptr, .len = 0 };
    EXPECT_EQ(GetKeyEncodedTest(dsa2048KeyPair_, &pkBlob, &skBlob), HCF_SUCCESS);

    HcfKeyPair *convertKeyPair = nullptr;
    ret = generator->convertKey(generator, nullptr, &pkBlob, &skBlob, &convertKeyPair);
    EXPECT_EQ(ret, HCF_SUCCESS);
    EXPECT_NE(convertKeyPair, nullptr);

    convertKeyPair->pubKey->base.base.destroy(&(convertKeyPair->pubKey->base.base));
    convertKeyPair->pubKey = nullptr;

    HcfObjDestroy(generator);
    HcfObjDestroy(convertKeyPair);
    HcfFree(pkBlob.data);
    HcfFree(skBlob.data);
}

HWTEST_F(CryptoDsaAsyKeyGeneratorTest, CryptoDsaAsyKeyGeneratorTest505, TestSize.Level0)
{
    HcfAsyKeyGenerator *generator = nullptr;
    HcfResult ret = HcfAsyKeyGeneratorCreate("DSA2048", &generator);
    ASSERT_EQ(ret, HCF_SUCCESS);
    ASSERT_NE(generator, nullptr);

    HcfBlob pkBlob = { .data = nullptr, .len = 0 };
    HcfBlob skBlob = { .data = nullptr, .len = 0 };
    EXPECT_EQ(GetKeyEncodedTest(dsa2048KeyPair_, &pkBlob, &skBlob), HCF_SUCCESS);

    HcfKeyPair *convertKeyPair = nullptr;
    ret = generator->convertKey(generator, nullptr, &pkBlob, &skBlob, &convertKeyPair);
    EXPECT_EQ(ret, HCF_SUCCESS);
    EXPECT_NE(convertKeyPair, nullptr);

    const char *alg = convertKeyPair->pubKey->base.getAlgorithm(&(convertKeyPair->pubKey->base));
    EXPECT_STREQ(alg, g_algNameDSA);

    HcfObjDestroy(generator);
    HcfObjDestroy(convertKeyPair);
    HcfFree(pkBlob.data);
    HcfFree(skBlob.data);
}

HWTEST_F(CryptoDsaAsyKeyGeneratorTest, CryptoDsaAsyKeyGeneratorTest506, TestSize.Level0)
{
    HcfAsyKeyGenerator *generator = nullptr;
    HcfResult ret = HcfAsyKeyGeneratorCreate("DSA2048", &generator);
    ASSERT_EQ(ret, HCF_SUCCESS);
    ASSERT_NE(generator, nullptr);

    HcfBlob pkBlob = { .data = nullptr, .len = 0 };
    HcfBlob skBlob = { .data = nullptr, .len = 0 };
    EXPECT_EQ(GetKeyEncodedTest(dsa2048KeyPair_, &pkBlob, &skBlob), HCF_SUCCESS);

    HcfKeyPair *convertKeyPair = nullptr;
    ret = generator->convertKey(generator, nullptr, &pkBlob, &skBlob, &convertKeyPair);
    EXPECT_EQ(ret, HCF_SUCCESS);
    EXPECT_NE(convertKeyPair, nullptr);

    HcfBlob blob = { .data = nullptr, .len = 0 };
    ret = convertKeyPair->pubKey->base.getEncoded(&(convertKeyPair->pubKey->base), &blob);

    HcfObjDestroy(generator);
    HcfObjDestroy(convertKeyPair);
    HcfFree(pkBlob.data);
    HcfFree(skBlob.data);
    ASSERT_EQ(ret, HCF_SUCCESS);
    ASSERT_NE(blob.data, nullptr);
    ASSERT_NE(blob.len, 0);
    HcfFree(blob.data);
}

HWTEST_F(CryptoDsaAsyKeyGeneratorTest, CryptoDsaAsyKeyGeneratorTest507, TestSize.Level0)
{
    HcfAsyKeyGenerator *generator = nullptr;
    HcfResult ret = HcfAsyKeyGeneratorCreate("DSA2048", &generator);
    ASSERT_EQ(ret, HCF_SUCCESS);
    ASSERT_NE(generator, nullptr);

    HcfBlob pkBlob = { .data = nullptr, .len = 0 };
    HcfBlob skBlob = { .data = nullptr, .len = 0 };
    EXPECT_EQ(GetKeyEncodedTest(dsa2048KeyPair_, &pkBlob, &skBlob), HCF_SUCCESS);

    HcfKeyPair *convertKeyPair = nullptr;
    ret = generator->convertKey(generator, nullptr, &pkBlob, &skBlob, &convertKeyPair);
    EXPECT_EQ(ret, HCF_SUCCESS);
    EXPECT_NE(convertKeyPair, nullptr);

    const char *pkFormat = convertKeyPair->pubKey->base.getFormat(&(convertKeyPair->pubKey->base));
    HcfObjDestroy(generator);
    HcfObjDestroy(convertKeyPair);
    HcfFree(pkBlob.data);
    HcfFree(skBlob.data);
    ASSERT_STREQ(pkFormat, g_opensslDsaPubKeyFormat);
}

HWTEST_F(CryptoDsaAsyKeyGeneratorTest, CryptoDsaAsyKeyGeneratorTest508, TestSize.Level0)
{
    HcfAsyKeyGenerator *generator = nullptr;
    HcfResult ret = HcfAsyKeyGeneratorCreate("DSA2048", &generator);
    ASSERT_EQ(ret, HCF_SUCCESS);
    ASSERT_NE(generator, nullptr);

    HcfBlob pkBlob = { .data = nullptr, .len = 0 };
    HcfBlob skBlob = { .data = nullptr, .len = 0 };
    EXPECT_EQ(GetKeyEncodedTest(dsa2048KeyPair_, &pkBlob, &skBlob), HCF_SUCCESS);

    HcfKeyPair *convertKeyPair = nullptr;
    ret = generator->convertKey(generator, nullptr, &pkBlob, &skBlob, &convertKeyPair);
    EXPECT_EQ(ret, HCF_SUCCESS);
    EXPECT_NE(convertKeyPair, nullptr);

    HcfBigInteger p = { .data = nullptr, .len = 0 };
    ret = convertKeyPair->pubKey->getAsyKeySpecBigInteger(convertKeyPair->pubKey, DSA_P_BN, &p);
    HcfObjDestroy(generator);
    HcfObjDestroy(convertKeyPair);
    HcfFree(pkBlob.data);
    HcfFree(skBlob.data);

    ASSERT_EQ(ret, HCF_SUCCESS);
    ASSERT_NE(p.data, nullptr);
    ASSERT_NE(p.len, 0);
    HcfFree(p.data);
}

HWTEST_F(CryptoDsaAsyKeyGeneratorTest, CryptoDsaAsyKeyGeneratorTest509, TestSize.Level0)
{
    HcfAsyKeyGenerator *generator = nullptr;
    HcfResult ret = HcfAsyKeyGeneratorCreate("DSA2048", &generator);
    ASSERT_EQ(ret, HCF_SUCCESS);
    ASSERT_NE(generator, nullptr);

    HcfBlob pkBlob = { .data = nullptr, .len = 0 };
    HcfBlob skBlob = { .data = nullptr, .len = 0 };
    EXPECT_EQ(GetKeyEncodedTest(dsa2048KeyPair_, &pkBlob, &skBlob), HCF_SUCCESS);

    HcfKeyPair *convertKeyPair = nullptr;
    ret = generator->convertKey(generator, nullptr, &pkBlob, &skBlob, &convertKeyPair);
    EXPECT_EQ(ret, HCF_SUCCESS);
    EXPECT_NE(convertKeyPair, nullptr);

    HcfBigInteger q = { .data = nullptr, .len = 0 };
    ret = convertKeyPair->pubKey->getAsyKeySpecBigInteger(convertKeyPair->pubKey, DSA_Q_BN, &q);
    HcfObjDestroy(generator);
    HcfObjDestroy(convertKeyPair);
    HcfFree(pkBlob.data);
    HcfFree(skBlob.data);

    ASSERT_EQ(ret, HCF_SUCCESS);
    ASSERT_NE(q.data, nullptr);
    ASSERT_NE(q.len, 0);
    HcfFree(q.data);
}

HWTEST_F(CryptoDsaAsyKeyGeneratorTest, CryptoDsaAsyKeyGeneratorTest510, TestSize.Level0)
{
    HcfAsyKeyGenerator *generator = nullptr;
    HcfResult ret = HcfAsyKeyGeneratorCreate("DSA2048", &generator);
    ASSERT_EQ(ret, HCF_SUCCESS);
    ASSERT_NE(generator, nullptr);

    HcfBlob pkBlob = { .data = nullptr, .len = 0 };
    HcfBlob skBlob = { .data = nullptr, .len = 0 };
    EXPECT_EQ(GetKeyEncodedTest(dsa2048KeyPair_, &pkBlob, &skBlob), HCF_SUCCESS);

    HcfKeyPair *convertKeyPair = nullptr;
    ret = generator->convertKey(generator, nullptr, &pkBlob, &skBlob, &convertKeyPair);
    EXPECT_EQ(ret, HCF_SUCCESS);
    EXPECT_NE(convertKeyPair, nullptr);

    HcfBigInteger g = { .data = nullptr, .len = 0 };
    ret = convertKeyPair->pubKey->getAsyKeySpecBigInteger(convertKeyPair->pubKey, DSA_G_BN, &g);
    HcfObjDestroy(generator);
    HcfObjDestroy(convertKeyPair);
    HcfFree(pkBlob.data);
    HcfFree(skBlob.data);

    ASSERT_EQ(ret, HCF_SUCCESS);
    ASSERT_NE(g.data, nullptr);
    ASSERT_NE(g.len, 0);
    HcfFree(g.data);
}

HWTEST_F(CryptoDsaAsyKeyGeneratorTest, CryptoDsaAsyKeyGeneratorTest511, TestSize.Level0)
{
    HcfAsyKeyGenerator *generator = nullptr;
    HcfResult ret = HcfAsyKeyGeneratorCreate("DSA2048", &generator);
    ASSERT_EQ(ret, HCF_SUCCESS);
    ASSERT_NE(generator, nullptr);

    HcfBlob pkBlob = { .data = nullptr, .len = 0 };
    HcfBlob skBlob = { .data = nullptr, .len = 0 };
    EXPECT_EQ(GetKeyEncodedTest(dsa2048KeyPair_, &pkBlob, &skBlob), HCF_SUCCESS);

    HcfKeyPair *convertKeyPair = nullptr;
    ret = generator->convertKey(generator, nullptr, &pkBlob, &skBlob, &convertKeyPair);
    EXPECT_EQ(ret, HCF_SUCCESS);
    EXPECT_NE(convertKeyPair, nullptr);

    HcfBigInteger pk = { .data = nullptr, .len = 0 };
    ret = convertKeyPair->pubKey->getAsyKeySpecBigInteger(convertKeyPair->pubKey, DSA_PK_BN, &pk);
    HcfObjDestroy(generator);
    HcfObjDestroy(convertKeyPair);
    HcfFree(pkBlob.data);
    HcfFree(skBlob.data);

    ASSERT_EQ(ret, HCF_SUCCESS);
    ASSERT_NE(pk.data, nullptr);
    ASSERT_NE(pk.len, 0);
    HcfFree(pk.data);
}

HWTEST_F(CryptoDsaAsyKeyGeneratorTest, CryptoDsaAsyKeyGeneratorTest512, TestSize.Level0)
{
    HcfAsyKeyGenerator *generator = nullptr;
    HcfResult ret = HcfAsyKeyGeneratorCreate("DSA2048", &generator);
    ASSERT_EQ(ret, HCF_SUCCESS);
    ASSERT_NE(generator, nullptr);

    HcfBlob pkBlob = { .data = nullptr, .len = 0 };
    HcfBlob skBlob = { .data = nullptr, .len = 0 };
    EXPECT_EQ(GetKeyEncodedTest(dsa2048KeyPair_, &pkBlob, &skBlob), HCF_SUCCESS);

    HcfKeyPair *convertKeyPair = nullptr;
    ret = generator->convertKey(generator, nullptr, &pkBlob, &skBlob, &convertKeyPair);
    EXPECT_EQ(ret, HCF_SUCCESS);
    EXPECT_NE(convertKeyPair, nullptr);

    const char *skClassName = convertKeyPair->priKey->base.base.getClass();
    EXPECT_STREQ(skClassName, OPENSSL_DSA_PRIKEY_CLASS);

    HcfObjDestroy(generator);
    HcfObjDestroy(convertKeyPair);
    HcfFree(pkBlob.data);
    HcfFree(skBlob.data);
}

HWTEST_F(CryptoDsaAsyKeyGeneratorTest, CryptoDsaAsyKeyGeneratorTest513, TestSize.Level0)
{
    HcfAsyKeyGenerator *generator = nullptr;
    HcfResult ret = HcfAsyKeyGeneratorCreate("DSA2048", &generator);
    ASSERT_EQ(ret, HCF_SUCCESS);
    ASSERT_NE(generator, nullptr);

    HcfBlob pkBlob = { .data = nullptr, .len = 0 };
    HcfBlob skBlob = { .data = nullptr, .len = 0 };
    EXPECT_EQ(GetKeyEncodedTest(dsa2048KeyPair_, &pkBlob, &skBlob), HCF_SUCCESS);

    HcfKeyPair *convertKeyPair = nullptr;
    ret = generator->convertKey(generator, nullptr, &pkBlob, &skBlob, &convertKeyPair);
    EXPECT_EQ(ret, HCF_SUCCESS);
    EXPECT_NE(convertKeyPair, nullptr);

    convertKeyPair->priKey->base.base.destroy(&(convertKeyPair->priKey->base.base));
    convertKeyPair->priKey = nullptr;
    HcfObjDestroy(generator);
    HcfObjDestroy(convertKeyPair);
    HcfFree(pkBlob.data);
    HcfFree(skBlob.data);
}

HWTEST_F(CryptoDsaAsyKeyGeneratorTest, CryptoDsaAsyKeyGeneratorTest514, TestSize.Level0)
{
    HcfAsyKeyGenerator *generator = nullptr;
    HcfResult ret = HcfAsyKeyGeneratorCreate("DSA2048", &generator);
    ASSERT_EQ(ret, HCF_SUCCESS);
    ASSERT_NE(generator, nullptr);

    HcfBlob pkBlob = { .data = nullptr, .len = 0 };
    HcfBlob skBlob = { .data = nullptr, .len = 0 };
    EXPECT_EQ(GetKeyEncodedTest(dsa2048KeyPair_, &pkBlob, &skBlob), HCF_SUCCESS);

    HcfKeyPair *convertKeyPair = nullptr;
    ret = generator->convertKey(generator, nullptr, &pkBlob, &skBlob, &convertKeyPair);
    EXPECT_EQ(ret, HCF_SUCCESS);
    EXPECT_NE(convertKeyPair, nullptr);

    const char *skAlg = convertKeyPair->priKey->base.getAlgorithm(&(convertKeyPair->priKey->base));
    EXPECT_STREQ(skAlg, g_algNameDSA);

    HcfObjDestroy(generator);
    HcfObjDestroy(convertKeyPair);
    HcfFree(pkBlob.data);
    HcfFree(skBlob.data);
}

HWTEST_F(CryptoDsaAsyKeyGeneratorTest, CryptoDsaAsyKeyGeneratorTest515, TestSize.Level0)
{
    HcfAsyKeyGenerator *generator = nullptr;
    HcfResult ret = HcfAsyKeyGeneratorCreate("DSA2048", &generator);
    ASSERT_EQ(ret, HCF_SUCCESS);
    ASSERT_NE(generator, nullptr);

    HcfBlob pkBlob = { .data = nullptr, .len = 0 };
    HcfBlob skBlob = { .data = nullptr, .len = 0 };
    EXPECT_EQ(GetKeyEncodedTest(dsa2048KeyPair_, &pkBlob, &skBlob), HCF_SUCCESS);

    HcfKeyPair *convertKeyPair = nullptr;
    ret = generator->convertKey(generator, nullptr, &pkBlob, &skBlob, &convertKeyPair);
    EXPECT_EQ(ret, HCF_SUCCESS);
    EXPECT_NE(convertKeyPair, nullptr);

    HcfBlob blob = { .data = nullptr, .len = 0 };
    ret = convertKeyPair->priKey->base.getEncoded(&(convertKeyPair->priKey->base), &blob);

    HcfObjDestroy(generator);
    HcfObjDestroy(convertKeyPair);
    HcfFree(pkBlob.data);
    HcfFree(skBlob.data);
    ASSERT_EQ(ret, HCF_SUCCESS);
    ASSERT_NE(blob.data, nullptr);
    ASSERT_NE(blob.len, 0);
    HcfFree(blob.data);
}

HWTEST_F(CryptoDsaAsyKeyGeneratorTest, CryptoDsaAsyKeyGeneratorTest516, TestSize.Level0)
{
    HcfAsyKeyGenerator *generator = nullptr;
    HcfResult ret = HcfAsyKeyGeneratorCreate("DSA2048", &generator);
    ASSERT_EQ(ret, HCF_SUCCESS);
    ASSERT_NE(generator, nullptr);

    HcfBlob pkBlob = { .data = nullptr, .len = 0 };
    HcfBlob skBlob = { .data = nullptr, .len = 0 };
    EXPECT_EQ(GetKeyEncodedTest(dsa2048KeyPair_, &pkBlob, &skBlob), HCF_SUCCESS);

    HcfKeyPair *convertKeyPair = nullptr;
    ret = generator->convertKey(generator, nullptr, &pkBlob, &skBlob, &convertKeyPair);
    EXPECT_EQ(ret, HCF_SUCCESS);
    EXPECT_NE(convertKeyPair, nullptr);

    const char *skFormat = convertKeyPair->priKey->base.getFormat(&(convertKeyPair->priKey->base));
    EXPECT_STREQ(skFormat, g_opensslDsaPriKeyFormat);

    HcfObjDestroy(generator);
    HcfObjDestroy(convertKeyPair);
    HcfFree(pkBlob.data);
    HcfFree(skBlob.data);
}

HWTEST_F(CryptoDsaAsyKeyGeneratorTest, CryptoDsaAsyKeyGeneratorTest517, TestSize.Level0)
{
    HcfAsyKeyGenerator *generator = nullptr;
    HcfResult ret = HcfAsyKeyGeneratorCreate("DSA2048", &generator);
    ASSERT_EQ(ret, HCF_SUCCESS);
    ASSERT_NE(generator, nullptr);

    HcfBlob pkBlob = { .data = nullptr, .len = 0 };
    HcfBlob skBlob = { .data = nullptr, .len = 0 };
    EXPECT_EQ(GetKeyEncodedTest(dsa2048KeyPair_, &pkBlob, &skBlob), HCF_SUCCESS);

    HcfKeyPair *convertKeyPair = nullptr;
    ret = generator->convertKey(generator, nullptr, &pkBlob, &skBlob, &convertKeyPair);
    EXPECT_EQ(ret, HCF_SUCCESS);
    EXPECT_NE(convertKeyPair, nullptr);

    HcfBigInteger p = { .data = nullptr, .len = 0 };
    ret = convertKeyPair->priKey->getAsyKeySpecBigInteger(convertKeyPair->priKey, DSA_P_BN, &p);
    HcfObjDestroy(generator);
    HcfObjDestroy(convertKeyPair);
    HcfFree(pkBlob.data);
    HcfFree(skBlob.data);

    ASSERT_EQ(ret, HCF_SUCCESS);
    ASSERT_NE(p.data, nullptr);
    ASSERT_NE(p.len, 0);
    HcfFree(p.data);
}

HWTEST_F(CryptoDsaAsyKeyGeneratorTest, CryptoDsaAsyKeyGeneratorTest518, TestSize.Level0)
{
    HcfAsyKeyGenerator *generator = nullptr;
    HcfResult ret = HcfAsyKeyGeneratorCreate("DSA2048", &generator);
    ASSERT_EQ(ret, HCF_SUCCESS);
    ASSERT_NE(generator, nullptr);

    HcfBlob pkBlob = { .data = nullptr, .len = 0 };
    HcfBlob skBlob = { .data = nullptr, .len = 0 };
    EXPECT_EQ(GetKeyEncodedTest(dsa2048KeyPair_, &pkBlob, &skBlob), HCF_SUCCESS);

    HcfKeyPair *convertKeyPair = nullptr;
    ret = generator->convertKey(generator, nullptr, &pkBlob, &skBlob, &convertKeyPair);
    EXPECT_EQ(ret, HCF_SUCCESS);
    EXPECT_NE(convertKeyPair, nullptr);

    HcfBigInteger q = { .data = nullptr, .len = 0 };
    ret = convertKeyPair->priKey->getAsyKeySpecBigInteger(convertKeyPair->priKey, DSA_Q_BN, &q);
    HcfObjDestroy(generator);
    HcfObjDestroy(convertKeyPair);
    HcfFree(pkBlob.data);
    HcfFree(skBlob.data);

    ASSERT_EQ(ret, HCF_SUCCESS);
    ASSERT_NE(q.data, nullptr);
    ASSERT_NE(q.len, 0);
    HcfFree(q.data);
}

HWTEST_F(CryptoDsaAsyKeyGeneratorTest, CryptoDsaAsyKeyGeneratorTest519, TestSize.Level0)
{
    HcfAsyKeyGenerator *generator = nullptr;
    HcfResult ret = HcfAsyKeyGeneratorCreate("DSA2048", &generator);
    ASSERT_EQ(ret, HCF_SUCCESS);
    ASSERT_NE(generator, nullptr);

    HcfBlob pkBlob = { .data = nullptr, .len = 0 };
    HcfBlob skBlob = { .data = nullptr, .len = 0 };
    EXPECT_EQ(GetKeyEncodedTest(dsa2048KeyPair_, &pkBlob, &skBlob), HCF_SUCCESS);

    HcfKeyPair *convertKeyPair = nullptr;
    ret = generator->convertKey(generator, nullptr, &pkBlob, &skBlob, &convertKeyPair);
    EXPECT_EQ(ret, HCF_SUCCESS);
    EXPECT_NE(convertKeyPair, nullptr);

    HcfBigInteger g = { .data = nullptr, .len = 0 };
    ret = convertKeyPair->priKey->getAsyKeySpecBigInteger(convertKeyPair->priKey, DSA_G_BN, &g);
    HcfObjDestroy(generator);
    HcfObjDestroy(convertKeyPair);
    HcfFree(pkBlob.data);
    HcfFree(skBlob.data);

    ASSERT_EQ(ret, HCF_SUCCESS);
    ASSERT_NE(g.data, nullptr);
    ASSERT_NE(g.len, 0);
    HcfFree(g.data);
}

HWTEST_F(CryptoDsaAsyKeyGeneratorTest, CryptoDsaAsyKeyGeneratorTest520, TestSize.Level0)
{
    HcfAsyKeyGenerator *generator = nullptr;
    HcfResult ret = HcfAsyKeyGeneratorCreate("DSA2048", &generator);
    ASSERT_EQ(ret, HCF_SUCCESS);
    ASSERT_NE(generator, nullptr);

    HcfBlob pkBlob = { .data = nullptr, .len = 0 };
    HcfBlob skBlob = { .data = nullptr, .len = 0 };
    EXPECT_EQ(GetKeyEncodedTest(dsa2048KeyPair_, &pkBlob, &skBlob), HCF_SUCCESS);

    HcfKeyPair *convertKeyPair = nullptr;
    ret = generator->convertKey(generator, nullptr, &pkBlob, &skBlob, &convertKeyPair);
    EXPECT_EQ(ret, HCF_SUCCESS);
    EXPECT_NE(convertKeyPair, nullptr);

    HcfBigInteger sk = { .data = nullptr, .len = 0 };
    ret = convertKeyPair->priKey->getAsyKeySpecBigInteger(convertKeyPair->priKey, DSA_SK_BN, &sk);
    HcfObjDestroy(generator);
    HcfObjDestroy(convertKeyPair);
    HcfFree(pkBlob.data);
    HcfFree(skBlob.data);

    ASSERT_EQ(ret, HCF_SUCCESS);
    ASSERT_NE(sk.data, nullptr);
    ASSERT_NE(sk.len, 0);
    HcfFree(sk.data);
}

HWTEST_F(CryptoDsaAsyKeyGeneratorTest, CryptoDsaAsyKeyGeneratorTest521, TestSize.Level0)
{
    HcfAsyKeyGenerator *generator = nullptr;
    HcfResult ret = HcfAsyKeyGeneratorCreate("DSA2048", &generator);
    ASSERT_EQ(ret, HCF_SUCCESS);
    ASSERT_NE(generator, nullptr);

    HcfBlob pkBlob = { .data = nullptr, .len = 0 };
    HcfBlob skBlob = { .data = nullptr, .len = 0 };
    EXPECT_EQ(GetKeyEncodedTest(dsa2048KeyPair_, &pkBlob, &skBlob), HCF_SUCCESS);

    HcfKeyPair *convertKeyPair = nullptr;
    ret = generator->convertKey(generator, nullptr, &pkBlob, &skBlob, &convertKeyPair);
    EXPECT_EQ(ret, HCF_SUCCESS);
    EXPECT_NE(convertKeyPair, nullptr);

    convertKeyPair->priKey->clearMem(convertKeyPair->priKey);
    HcfObjDestroy(generator);
    HcfObjDestroy(convertKeyPair);
    HcfFree(pkBlob.data);
    HcfFree(skBlob.data);
}

HWTEST_F(CryptoDsaAsyKeyGeneratorTest, CryptoDsaAsyKeyGeneratorTest522, TestSize.Level0)
{
    HcfAsyKeyGenerator *generator = nullptr;
    HcfResult ret = HcfAsyKeyGeneratorCreate("DSA2048", &generator);
    ASSERT_EQ(ret, HCF_SUCCESS);
    ASSERT_NE(generator, nullptr);

    HcfBlob pkBlob = { .data = nullptr, .len = 0 };
    HcfBlob skBlob = { .data = nullptr, .len = 0 };
    EXPECT_EQ(GetKeyEncodedTest(dsa2048KeyPair_, &pkBlob, &skBlob), HCF_SUCCESS);

    HcfKeyPair *convertKeyPair = nullptr;
    ret = generator->convertKey(generator, nullptr, &pkBlob, &skBlob, &convertKeyPair);
    EXPECT_EQ(ret, HCF_SUCCESS);
    EXPECT_NE(convertKeyPair, nullptr);

    int testI;
    ret = convertKeyPair->priKey->getAsyKeySpecInt(convertKeyPair->priKey, DSA_P_BN, &testI);
    EXPECT_EQ(ret, HCF_NOT_SUPPORT);

    HcfObjDestroy(generator);
    HcfObjDestroy(convertKeyPair);
    HcfFree(pkBlob.data);
    HcfFree(skBlob.data);
}

HWTEST_F(CryptoDsaAsyKeyGeneratorTest, CryptoDsaAsyKeyGeneratorTest523, TestSize.Level0)
{
    HcfAsyKeyGenerator *generator = nullptr;
    HcfResult ret = HcfAsyKeyGeneratorCreate("DSA2048", &generator);
    ASSERT_EQ(ret, HCF_SUCCESS);
    ASSERT_NE(generator, nullptr);

    HcfBlob pkBlob = { .data = nullptr, .len = 0 };
    HcfBlob skBlob = { .data = nullptr, .len = 0 };
    EXPECT_EQ(GetKeyEncodedTest(dsa2048KeyPair_, &pkBlob, &skBlob), HCF_SUCCESS);

    HcfKeyPair *convertKeyPair = nullptr;
    ret = generator->convertKey(generator, nullptr, &pkBlob, &skBlob, &convertKeyPair);
    EXPECT_EQ(ret, HCF_SUCCESS);
    EXPECT_NE(convertKeyPair, nullptr);

    char *testC;
    ret = convertKeyPair->priKey->getAsyKeySpecString(convertKeyPair->priKey, DSA_P_BN, &testC);
    HcfObjDestroy(generator);
    HcfObjDestroy(convertKeyPair);
    HcfFree(pkBlob.data);
    HcfFree(skBlob.data);
    ASSERT_EQ(ret, HCF_NOT_SUPPORT);
}

HWTEST_F(CryptoDsaAsyKeyGeneratorTest, CryptoDsaAsyKeyGeneratorTest524, TestSize.Level0)
{
    HcfAsyKeyGenerator *generator = nullptr;
    HcfResult ret = HcfAsyKeyGeneratorCreate("DSA2048", &generator);
    ASSERT_EQ(ret, HCF_SUCCESS);
    ASSERT_NE(generator, nullptr);

    HcfBlob pkBlob = { .data = nullptr, .len = 0 };
    HcfBlob skBlob = { .data = nullptr, .len = 0 };
    EXPECT_EQ(GetKeyEncodedTest(dsa2048KeyPair_, &pkBlob, &skBlob), HCF_SUCCESS);

    HcfKeyPair *convertKeyPair = nullptr;
    ret = generator->convertKey(generator, nullptr, &pkBlob, &skBlob, &convertKeyPair);
    EXPECT_EQ(ret, HCF_SUCCESS);
    EXPECT_NE(convertKeyPair, nullptr);

    int testI;
    ret = convertKeyPair->pubKey->getAsyKeySpecInt(convertKeyPair->pubKey, DSA_P_BN, &testI);
    HcfObjDestroy(generator);
    HcfObjDestroy(convertKeyPair);
    HcfFree(pkBlob.data);
    HcfFree(skBlob.data);
    ASSERT_EQ(ret, HCF_NOT_SUPPORT);
}

HWTEST_F(CryptoDsaAsyKeyGeneratorTest, CryptoDsaAsyKeyGeneratorTest525, TestSize.Level0)
{
    HcfAsyKeyGenerator *generator = nullptr;
    HcfResult ret = HcfAsyKeyGeneratorCreate("DSA2048", &generator);
    ASSERT_EQ(ret, HCF_SUCCESS);
    ASSERT_NE(generator, nullptr);

    HcfBlob pkBlob = { .data = nullptr, .len = 0 };
    HcfBlob skBlob = { .data = nullptr, .len = 0 };
    EXPECT_EQ(GetKeyEncodedTest(dsa2048KeyPair_, &pkBlob, &skBlob), HCF_SUCCESS);

    HcfKeyPair *convertKeyPair = nullptr;
    ret = generator->convertKey(generator, nullptr, &pkBlob, &skBlob, &convertKeyPair);
    EXPECT_EQ(ret, HCF_SUCCESS);
    EXPECT_NE(convertKeyPair, nullptr);

    char *testC;
    ret = convertKeyPair->pubKey->getAsyKeySpecString(convertKeyPair->pubKey, DSA_P_BN, &testC);
    HcfObjDestroy(generator);
    HcfObjDestroy(convertKeyPair);
    HcfFree(pkBlob.data);
    HcfFree(skBlob.data);
    ASSERT_EQ(ret, HCF_NOT_SUPPORT);
}

static void OpensslMockTestFuncGetPubKey(uint32_t mallocCount)
{
    for (uint32_t i = 0; i < mallocCount; i++) {
        ResetOpensslCallNum();
        SetOpensslCallMockIndex(i);

        HcfAsyKeyGenerator *tmpGenerator = nullptr;
        int32_t res = HcfAsyKeyGeneratorCreate("DSA2048", &tmpGenerator);
        if (res != HCF_SUCCESS) {
            continue;
        }

        HcfBlob pkBlob = { .data = nullptr, .len = 0 };
        HcfBlob skBlob = { .data = nullptr, .len = 0 };
        res = GetKeyEncodedTest(CryptoDsaAsyKeyGeneratorTest::dsa2048KeyPair_, &pkBlob, &skBlob);
        if (res != HCF_SUCCESS) {
            HcfObjDestroy(tmpGenerator);
            continue;
        }

        HcfKeyPair *tmpKeyPair = nullptr;
        res = tmpGenerator->convertKey(tmpGenerator, nullptr, &pkBlob, &skBlob, &tmpKeyPair);
        if (res != HCF_SUCCESS) {
            HcfObjDestroy(tmpGenerator);
            HcfFree(pkBlob.data);
            HcfFree(skBlob.data);
            continue;
        }

        HcfPubKey *tmpPubKey = nullptr;
        res = tmpKeyPair->priKey->getPubKey(tmpKeyPair->priKey, &tmpPubKey);
        if (res != HCF_SUCCESS) {
            HcfObjDestroy(tmpKeyPair);
            HcfObjDestroy(tmpGenerator);
            HcfFree(pkBlob.data);
            HcfFree(skBlob.data);
            continue;
        }

        HcfBlob pubKeyBlob = { .data = nullptr, .len = 0 };
        res = tmpPubKey->base.getEncoded(&(tmpPubKey->base), &pubKeyBlob);
        if (res == HCF_SUCCESS) {
            HcfFree(pubKeyBlob.data);
        }

        HcfObjDestroy(tmpPubKey);
        HcfObjDestroy(tmpKeyPair);
        HcfObjDestroy(tmpGenerator);
        HcfFree(pkBlob.data);
        HcfFree(skBlob.data);
    }
}

HWTEST_F(CryptoDsaAsyKeyGeneratorTest, CryptoDsaAsyKeyPubKeyFromPriKeyMockTest, TestSize.Level0)
{
    StartRecordOpensslCallNum();
    HcfAsyKeyGenerator *generator = nullptr;
    HcfResult ret = HcfAsyKeyGeneratorCreate("DSA2048", &generator);
    ASSERT_EQ(ret, HCF_SUCCESS);
    ASSERT_NE(generator, nullptr);

    HcfBlob pkBlob = { .data = nullptr, .len = 0 };
    HcfBlob skBlob = { .data = nullptr, .len = 0 };
    EXPECT_EQ(GetKeyEncodedTest(dsa2048KeyPair_, &pkBlob, &skBlob), HCF_SUCCESS);

    HcfKeyPair *convertKeyPair = nullptr;
    ret = generator->convertKey(generator, nullptr, &pkBlob, &skBlob, &convertKeyPair);
    EXPECT_EQ(ret, HCF_SUCCESS);
    EXPECT_NE(convertKeyPair, nullptr);

    HcfPubKey *pubKey = nullptr;
    ret = convertKeyPair->priKey->getPubKey(convertKeyPair->priKey, &pubKey);
    ASSERT_EQ(ret, HCF_SUCCESS);
    ASSERT_NE(pubKey, nullptr);

    HcfBlob pubKeyBlob = { .data = nullptr, .len = 0 };
    ret = pubKey->base.getEncoded(&(pubKey->base), &pubKeyBlob);
    ASSERT_EQ(ret, HCF_SUCCESS);
    ASSERT_NE(pubKeyBlob.data, nullptr);
    ASSERT_NE(pubKeyBlob.len, 0);
    HcfFree(pubKeyBlob.data);
    HcfObjDestroy(generator);
    HcfObjDestroy(convertKeyPair);
    HcfFree(pkBlob.data);
    HcfFree(skBlob.data);
    HcfObjDestroy(pubKey);

    uint32_t mallocCount = GetOpensslCallNum();
    OpensslMockTestFuncGetPubKey(mallocCount);

    EndRecordOpensslCallNum();
}
}