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
#include <cstring>

#include "alg_25519_common_param_spec.h"
#include "blob.h"
#include "ecdsa_openssl.h"
#include "memory.h"
#include "securec.h"
#include "openssl_common.h"
#include "asy_key_params.h"
#include "params_parser.h"
#include "alg_25519_asy_key_generator_openssl.h"
#include "memory_mock.h"
#include "openssl_adapter_mock.h"

using namespace std;
using namespace testing::ext;

namespace {
class CryptoEd25519AsyKeyGeneratorBySpecTest : public testing::Test {
public:
    static void SetUpTestCase() {};
    static void TearDownTestCase() {};
    void SetUp();
    void TearDown();
};

static string g_ed25519AlgoName = "Ed25519";
static string g_pubkeyformatName = "X.509";
static string g_prikeyformatName = "PKCS#8";

void CryptoEd25519AsyKeyGeneratorBySpecTest::SetUp() {}
void CryptoEd25519AsyKeyGeneratorBySpecTest::TearDown() {}

static const char *g_mockMessage = "hello world";
static HcfBlob g_mockInput = {
    .data = (uint8_t *)g_mockMessage,
    .len = 12
};

static const char *GetMockClass(void)
{
    return "ed25519generator";
}
HcfObjectBase g_obj = {
    .getClass = GetMockClass,
    .destroy = nullptr
};

HWTEST_F(CryptoEd25519AsyKeyGeneratorBySpecTest, CryptoEd25519AsyKeyGeneratorBySpecTest001_1, TestSize.Level0)
{
    HcfAsyKeyParamsSpec *paramSpec = nullptr;
    HcfAsyKeyGeneratorBySpec *returnObj = nullptr;
    HcfResult res = TestCreateKeyPairParamsSpecAndGeneratorBySpec(g_ed25519AlgoName.c_str(), true,
        &paramSpec, &returnObj);
    ASSERT_EQ(res, HCF_SUCCESS);
    HcfObjDestroy(returnObj);
    DestroyAlg25519KeyPairSpec(reinterpret_cast<HcfAlg25519KeyPairParamsSpec *>(paramSpec));
}

HWTEST_F(CryptoEd25519AsyKeyGeneratorBySpecTest, CryptoEd25519AsyKeyGeneratorBySpecTest001_2, TestSize.Level0)
{
    HcfAsyKeyParamsSpec *paramSpec = nullptr;
    HcfAsyKeyGeneratorBySpec *returnObj = nullptr;
    HcfResult res = TestCreatePubKeyParamsSpecAndGeneratorBySpec(g_ed25519AlgoName.c_str(), true,
        &paramSpec, &returnObj);
    ASSERT_EQ(res, HCF_SUCCESS);
    HcfObjDestroy(returnObj);
    DestroyAlg25519PubKeySpec(reinterpret_cast<HcfAlg25519PubKeyParamsSpec *>(paramSpec));
}

HWTEST_F(CryptoEd25519AsyKeyGeneratorBySpecTest, CryptoEd25519AsyKeyGeneratorBySpecTest001_3, TestSize.Level0)
{
    HcfAsyKeyParamsSpec *paramSpec = nullptr;
    HcfAsyKeyGeneratorBySpec *returnObj = nullptr;
    HcfResult res = TestCreatePriKeyParamsSpecAndGeneratorBySpec(g_ed25519AlgoName.c_str(), true,
        &paramSpec, &returnObj);
    ASSERT_EQ(res, HCF_SUCCESS);
    HcfObjDestroy(returnObj);
    DestroyAlg25519PriKeySpec(reinterpret_cast<HcfAlg25519PriKeyParamsSpec *>(paramSpec));
}

HWTEST_F(CryptoEd25519AsyKeyGeneratorBySpecTest, CryptoEd25519AsyKeyGeneratorBySpecTest002, TestSize.Level0)
{
    HcfAsyKeyParamsSpec *paramSpec = nullptr;
    HcfAsyKeyGeneratorBySpec *returnObj = nullptr;
    HcfResult res = TestCreateKeyPairParamsSpecAndGeneratorBySpec(g_ed25519AlgoName.c_str(), true,
        &paramSpec, &returnObj);
    ASSERT_EQ(res, HCF_SUCCESS);

    const char *className = returnObj->base.getClass();
    ASSERT_NE(className, nullptr);
    ASSERT_NE(returnObj, nullptr);
    HcfObjDestroy(returnObj);
    DestroyAlg25519KeyPairSpec(reinterpret_cast<HcfAlg25519KeyPairParamsSpec *>(paramSpec));
}

HWTEST_F(CryptoEd25519AsyKeyGeneratorBySpecTest, CryptoEd25519AsyKeyGeneratorBySpecTest003, TestSize.Level0)
{
    HcfAsyKeyParamsSpec *paramSpec = nullptr;
    HcfAsyKeyGeneratorBySpec *returnObj = nullptr;

    HcfResult res = TestCreateKeyPairParamsSpecAndGeneratorBySpec(g_ed25519AlgoName.c_str(), true,
        &paramSpec, &returnObj);
    ASSERT_EQ(res, HCF_SUCCESS);

    returnObj->base.destroy(&g_obj);
    HcfObjDestroy(returnObj);
    DestroyAlg25519KeyPairSpec(reinterpret_cast<HcfAlg25519KeyPairParamsSpec *>(paramSpec));
}

HWTEST_F(CryptoEd25519AsyKeyGeneratorBySpecTest, CryptoEd25519AsyKeyGeneratorBySpecTest004, TestSize.Level0)
{
    HcfAsyKeyParamsSpec *paramSpec = nullptr;
    HcfAsyKeyGeneratorBySpec *returnObj = nullptr;
    HcfResult res = TestCreateKeyPairParamsSpecAndGeneratorBySpec(g_ed25519AlgoName.c_str(), true,
        &paramSpec, &returnObj);
    ASSERT_EQ(res, HCF_SUCCESS);

    const char *algoName = returnObj->getAlgName(returnObj);
    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_EQ(algoName, g_ed25519AlgoName);

    HcfObjDestroy(returnObj);
    DestroyAlg25519KeyPairSpec(reinterpret_cast<HcfAlg25519KeyPairParamsSpec *>(paramSpec));
}

HWTEST_F(CryptoEd25519AsyKeyGeneratorBySpecTest, CryptoEd25519AsyKeyGeneratorBySpecTest005, TestSize.Level0)
{
    HcfAsyKeyParamsSpec *paramSpec = nullptr;
    HcfAsyKeyGeneratorBySpec *returnObj = nullptr;

    HcfResult res = TestCreateKeyPairParamsSpecAndGeneratorBySpec(g_ed25519AlgoName.c_str(), true,
        &paramSpec, &returnObj);
    ASSERT_EQ(res, HCF_SUCCESS);

    HcfKeyPair *keyPair = nullptr;
    res = returnObj->generateKeyPair(returnObj, &keyPair);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(keyPair, nullptr);

    HcfObjDestroy(keyPair);
    HcfObjDestroy(returnObj);
    DestroyAlg25519KeyPairSpec(reinterpret_cast<HcfAlg25519KeyPairParamsSpec *>(paramSpec));
}

HWTEST_F(CryptoEd25519AsyKeyGeneratorBySpecTest, CryptoEd25519AsyKeyGeneratorBySpecTest006, TestSize.Level0)
{
    HcfAsyKeyParamsSpec *paramSpec = nullptr;
    HcfAsyKeyGeneratorBySpec *returnObj = nullptr;
    HcfResult res = TestCreateKeyPairParamsSpecAndGeneratorBySpec(g_ed25519AlgoName.c_str(), true,
        &paramSpec, &returnObj);
    ASSERT_EQ(res, HCF_SUCCESS);

    HcfKeyPair *keyPair = nullptr;
    res = returnObj->generateKeyPair(returnObj, &keyPair);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(keyPair, nullptr);

    const char *className = keyPair->base.getClass();
    ASSERT_NE(className, nullptr);

    HcfObjDestroy(keyPair);
    HcfObjDestroy(returnObj);
    DestroyAlg25519KeyPairSpec(reinterpret_cast<HcfAlg25519KeyPairParamsSpec *>(paramSpec));
}

HWTEST_F(CryptoEd25519AsyKeyGeneratorBySpecTest, CryptoEd25519AsyKeyGeneratorBySpecTest007, TestSize.Level0)
{
    HcfAsyKeyParamsSpec *paramSpec = nullptr;
    HcfAsyKeyGeneratorBySpec *returnObj = nullptr;

    HcfResult res = TestCreateKeyPairParamsSpecAndGeneratorBySpec(g_ed25519AlgoName.c_str(), true,
        &paramSpec, &returnObj);
    ASSERT_EQ(res, HCF_SUCCESS);

    HcfKeyPair *keyPair = nullptr;
    res = returnObj->generateKeyPair(returnObj, &keyPair);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(keyPair, nullptr);

    keyPair->base.destroy(&(keyPair->base));
    HcfObjDestroy(returnObj);
    DestroyAlg25519KeyPairSpec(reinterpret_cast<HcfAlg25519KeyPairParamsSpec *>(paramSpec));
}

HWTEST_F(CryptoEd25519AsyKeyGeneratorBySpecTest, CryptoEd25519AsyKeyGeneratorBySpecTest008, TestSize.Level0)
{
    HcfAsyKeyParamsSpec *paramSpec = nullptr;
    HcfAsyKeyGeneratorBySpec *returnObj = nullptr;
    HcfResult res = TestCreateKeyPairParamsSpecAndGeneratorBySpec(g_ed25519AlgoName.c_str(), true,
        &paramSpec, &returnObj);
    ASSERT_EQ(res, HCF_SUCCESS);

    HcfKeyPair *keyPair = nullptr;
    res = returnObj->generateKeyPair(returnObj, &keyPair);
    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(keyPair, nullptr);

    const char *className = keyPair->pubKey->base.base.getClass();
    ASSERT_NE(className, nullptr);

    HcfObjDestroy(keyPair);
    HcfObjDestroy(returnObj);
    DestroyAlg25519KeyPairSpec(reinterpret_cast<HcfAlg25519KeyPairParamsSpec *>(paramSpec));
}

HWTEST_F(CryptoEd25519AsyKeyGeneratorBySpecTest, CryptoEd25519AsyKeyGeneratorBySpecTest009, TestSize.Level0)
{
    HcfAsyKeyParamsSpec *paramSpec = nullptr;
    HcfAsyKeyGeneratorBySpec *returnObj = nullptr;

    HcfResult res = TestCreateKeyPairParamsSpecAndGeneratorBySpec(g_ed25519AlgoName.c_str(), true,
        &paramSpec, &returnObj);
    ASSERT_EQ(res, HCF_SUCCESS);

    HcfKeyPair *keyPair = nullptr;
    res = returnObj->generateKeyPair(returnObj, &keyPair);
    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(keyPair, nullptr);

    keyPair->pubKey->base.base.destroy(&(keyPair->pubKey->base.base));
    keyPair->pubKey = nullptr;
    HcfObjDestroy(keyPair);
    HcfObjDestroy(returnObj);
    DestroyAlg25519KeyPairSpec(reinterpret_cast<HcfAlg25519KeyPairParamsSpec *>(paramSpec));
}

HWTEST_F(CryptoEd25519AsyKeyGeneratorBySpecTest, CryptoEd25519AsyKeyGeneratorBySpecTest010, TestSize.Level0)
{
    HcfAsyKeyParamsSpec *paramSpec = nullptr;
    HcfAsyKeyGeneratorBySpec *returnObj = nullptr;
    HcfResult res = TestCreateKeyPairParamsSpecAndGeneratorBySpec(g_ed25519AlgoName.c_str(), true,
        &paramSpec, &returnObj);
    ASSERT_EQ(res, HCF_SUCCESS);

    HcfKeyPair *keyPair = nullptr;
    res = returnObj->generateKeyPair(returnObj, &keyPair);
    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(keyPair, nullptr);

    const char *algorithmName = keyPair->pubKey->base.getAlgorithm(&(keyPair->pubKey->base));
    ASSERT_EQ(algorithmName, g_ed25519AlgoName);

    HcfBlob blob = { .data = nullptr, .len = 0 };
    res = keyPair->pubKey->base.getEncoded(&(keyPair->pubKey->base), &blob);
    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(blob.data, nullptr);
    ASSERT_NE(blob.len, 0);
    HcfFree(blob.data);
    const char *formatName = keyPair->pubKey->base.getFormat(&(keyPair->pubKey->base));
    ASSERT_EQ(formatName, g_pubkeyformatName);

    HcfObjDestroy(keyPair);
    HcfObjDestroy(returnObj);
    DestroyAlg25519KeyPairSpec(reinterpret_cast<HcfAlg25519KeyPairParamsSpec *>(paramSpec));
}

HWTEST_F(CryptoEd25519AsyKeyGeneratorBySpecTest, CryptoEd25519AsyKeyGeneratorBySpecTest011, TestSize.Level0)
{
    HcfAsyKeyParamsSpec *paramSpec = nullptr;
    HcfAsyKeyGeneratorBySpec *returnObj = nullptr;

    HcfResult res = TestCreateKeyPairParamsSpecAndGeneratorBySpec(g_ed25519AlgoName.c_str(), true,
        &paramSpec, &returnObj);
    ASSERT_EQ(res, HCF_SUCCESS);

    HcfKeyPair *keyPair = nullptr;
    res = returnObj->generateKeyPair(returnObj, &keyPair);
    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(keyPair, nullptr);

    const char *className = keyPair->priKey->base.base.getClass();
    ASSERT_NE(className, nullptr);

    HcfObjDestroy(keyPair);
    HcfObjDestroy(returnObj);
    DestroyAlg25519KeyPairSpec(reinterpret_cast<HcfAlg25519KeyPairParamsSpec *>(paramSpec));
}

HWTEST_F(CryptoEd25519AsyKeyGeneratorBySpecTest, CryptoEd25519AsyKeyGeneratorBySpecTest012, TestSize.Level0)
{
    HcfAsyKeyParamsSpec *paramSpec = nullptr;
    HcfAsyKeyGeneratorBySpec *returnObj = nullptr;
    HcfResult res = TestCreateKeyPairParamsSpecAndGeneratorBySpec(g_ed25519AlgoName.c_str(), true,
        &paramSpec, &returnObj);
    ASSERT_EQ(res, HCF_SUCCESS);

    HcfKeyPair *keyPair = nullptr;
    res = returnObj->generateKeyPair(returnObj, &keyPair);
    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(keyPair, nullptr);

    keyPair->priKey->base.base.destroy(&(keyPair->priKey->base.base));
    keyPair->priKey = nullptr;
    HcfObjDestroy(keyPair);
    HcfObjDestroy(returnObj);
    DestroyAlg25519KeyPairSpec(reinterpret_cast<HcfAlg25519KeyPairParamsSpec *>(paramSpec));
}

HWTEST_F(CryptoEd25519AsyKeyGeneratorBySpecTest, CryptoEd25519AsyKeyGeneratorBySpecTest013, TestSize.Level0)
{
    HcfAsyKeyParamsSpec *paramSpec = nullptr;
    HcfAsyKeyGeneratorBySpec *returnObj = nullptr;

    HcfResult res = TestCreateKeyPairParamsSpecAndGeneratorBySpec(g_ed25519AlgoName.c_str(), true,
        &paramSpec, &returnObj);
    ASSERT_EQ(res, HCF_SUCCESS);

    HcfKeyPair *keyPair = nullptr;
    res = returnObj->generateKeyPair(returnObj, &keyPair);
    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(keyPair, nullptr);

    const char *algorithmName = keyPair->priKey->base.getAlgorithm(&(keyPair->priKey->base));
    ASSERT_EQ(algorithmName, g_ed25519AlgoName);

    HcfBlob blob = { .data = nullptr, .len = 0 };
    res = keyPair->priKey->base.getEncoded(&(keyPair->priKey->base), &blob);
    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(blob.data, nullptr);
    ASSERT_NE(blob.len, 0);
    HcfFree(blob.data);
    const char *formatName = keyPair->priKey->base.getFormat(&(keyPair->priKey->base));
    ASSERT_EQ(formatName, g_prikeyformatName);

    HcfObjDestroy(keyPair);
    HcfObjDestroy(returnObj);
    DestroyAlg25519KeyPairSpec(reinterpret_cast<HcfAlg25519KeyPairParamsSpec *>(paramSpec));
}

HWTEST_F(CryptoEd25519AsyKeyGeneratorBySpecTest, CryptoEd25519GetPubKeyFromPriKey, TestSize.Level0)
{
    HcfAsyKeyParamsSpec *paramSpec = nullptr;
    HcfAsyKeyGeneratorBySpec *returnObj = nullptr;

    HcfResult res = TestCreateKeyPairParamsSpecAndGeneratorBySpec(g_ed25519AlgoName.c_str(), true,
        &paramSpec, &returnObj);
    ASSERT_EQ(res, HCF_SUCCESS);

    HcfKeyPair *keyPair = nullptr;
    res = returnObj->generateKeyPair(returnObj, &keyPair);
    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(keyPair, nullptr);
    HcfBlob pubKeyBlob1 = { .data = nullptr, .len = 0 };
    res = keyPair->pubKey->base.getEncoded(&(keyPair->pubKey->base), &pubKeyBlob1);
    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(pubKeyBlob1.data, nullptr);
    ASSERT_NE(pubKeyBlob1.len, 0);

    HcfPubKey *pubKey = nullptr;
    res = keyPair->priKey->getPubKey(keyPair->priKey, &pubKey);
    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(pubKey, nullptr);

    HcfBlob pubKeyBlob = { .data = nullptr, .len = 0 };
    res = pubKey->base.getEncoded(&(pubKey->base), &pubKeyBlob);
    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(pubKeyBlob.data, nullptr);
    ASSERT_NE(pubKeyBlob.len, 0);
    EXPECT_EQ(memcmp(pubKeyBlob.data, pubKeyBlob1.data, pubKeyBlob.len), 0);
    HcfFree(pubKeyBlob.data);
    HcfFree(pubKeyBlob1.data);
    HcfObjDestroy(pubKey);
    HcfObjDestroy(keyPair);
    HcfObjDestroy(returnObj);
    DestroyAlg25519KeyPairSpec(reinterpret_cast<HcfAlg25519KeyPairParamsSpec *>(paramSpec));
}

HWTEST_F(CryptoEd25519AsyKeyGeneratorBySpecTest, CryptoEd25519AsyKeyGeneratorBySpecTest014, TestSize.Level0)
{
    HcfAsyKeyParamsSpec *paramSpec = nullptr;
    HcfAsyKeyGeneratorBySpec *returnObj = nullptr;
    HcfResult res = TestCreateKeyPairParamsSpecAndGeneratorBySpec(g_ed25519AlgoName.c_str(), true,
        &paramSpec, &returnObj);
    ASSERT_EQ(res, HCF_SUCCESS);

    HcfKeyPair *keyPair = nullptr;
    res = returnObj->generateKeyPair(returnObj, &keyPair);
    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(keyPair, nullptr);

    keyPair->priKey->clearMem(keyPair->priKey);
    HcfBlob blob = { .data = nullptr, .len = 0 };
    res = keyPair->priKey->base.getEncoded(&(keyPair->priKey->base), &blob);
    ASSERT_EQ(res, HCF_INVALID_PARAMS);
    ASSERT_EQ(blob.data, nullptr);
    ASSERT_EQ(blob.len, 0);
    HcfFree(blob.data);
    HcfObjDestroy(keyPair);
    HcfObjDestroy(returnObj);
    DestroyAlg25519KeyPairSpec(reinterpret_cast<HcfAlg25519KeyPairParamsSpec *>(paramSpec));
}

HWTEST_F(CryptoEd25519AsyKeyGeneratorBySpecTest, CryptoEd25519AsyKeyGeneratorBySpecTest015, TestSize.Level0)
{
    HcfAsyKeyParamsSpec *pubparamSpec = nullptr;
    HcfAsyKeyGeneratorBySpec *returnpubObj = nullptr;
    HcfResult res = TestCreatePubKeyParamsSpecAndGeneratorBySpec(g_ed25519AlgoName.c_str(), true,
        &pubparamSpec, &returnpubObj);
    ASSERT_EQ(res, HCF_SUCCESS);

    HcfAsyKeyParamsSpec *priparamSpec = nullptr;
    HcfAsyKeyGeneratorBySpec *returnpriObj = nullptr;
    res = TestCreatePriKeyParamsSpecAndGeneratorBySpec(g_ed25519AlgoName.c_str(), true,
        &priparamSpec, &returnpriObj);
    ASSERT_EQ(res, HCF_SUCCESS);

    HcfPubKey *pubKey = nullptr;
    res = returnpubObj->generatePubKey(returnpubObj, &pubKey);
    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(pubKey, nullptr);

    HcfPriKey *priKey = nullptr;
    res = returnpriObj->generatePriKey(returnpriObj, &priKey);
    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(priKey, nullptr);

    HcfBigInteger returnBigInteger = { .data = nullptr, .len = 0 };
    res = pubKey->getAsyKeySpecBigInteger(pubKey, ED25519_PK_BN, &returnBigInteger);
    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(returnBigInteger.data, nullptr);
    ASSERT_NE(returnBigInteger.len, 0);
    HcfFree(returnBigInteger.data);

    res = priKey->getAsyKeySpecBigInteger(priKey, ED25519_SK_BN, &returnBigInteger);
    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(returnBigInteger.data, nullptr);
    ASSERT_NE(returnBigInteger.len, 0);
    HcfFree(returnBigInteger.data);
    HcfObjDestroy(pubKey);
    HcfObjDestroy(priKey);
    HcfObjDestroy(returnpubObj);
    HcfObjDestroy(returnpriObj);
    DestroyAlg25519PubKeySpec(reinterpret_cast<HcfAlg25519PubKeyParamsSpec *>(pubparamSpec));
    DestroyAlg25519PriKeySpec(reinterpret_cast<HcfAlg25519PriKeyParamsSpec *>(priparamSpec));
}

HWTEST_F(CryptoEd25519AsyKeyGeneratorBySpecTest, CryptoEd25519AsyKeyGeneratorBySpecTest016, TestSize.Level0)
{
    HcfAsyKeyParamsSpec *paramSpec = nullptr;
    HcfAsyKeyGeneratorBySpec *returnObj = nullptr;
    HcfResult res = TestCreateKeyPairParamsSpecAndGeneratorBySpec(g_ed25519AlgoName.c_str(), true,
        &paramSpec, &returnObj);
    ASSERT_EQ(res, HCF_SUCCESS);

    HcfKeyPair *keyPair = nullptr;
    res = returnObj->generateKeyPair(returnObj, &keyPair);
    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(keyPair, nullptr);

    HcfSign *sign = nullptr;
    res = HcfSignCreate("Ed25519", &sign);
    ASSERT_EQ(res, HCF_SUCCESS);
    res = sign->init(sign, nullptr, keyPair->priKey);
    ASSERT_EQ(res, HCF_SUCCESS);
    HcfBlob out = { .data = nullptr, .len = 0 };
    res = sign->sign(sign, &g_mockInput, &out);
    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(out.data, nullptr);
    ASSERT_NE(out.len, 0);

    HcfVerify *verify = nullptr;
    res = HcfVerifyCreate("Ed25519", &verify);
    ASSERT_EQ(res, HCF_SUCCESS);
    res = verify->init(verify, nullptr, keyPair->pubKey);
    ASSERT_EQ(res, HCF_SUCCESS);

    bool flag = verify->verify(verify, &g_mockInput, &out);
    ASSERT_EQ(flag, true);
    ASSERT_NE(out.data, nullptr);
    ASSERT_NE(out.len, 0);

    HcfFree(out.data);
    HcfObjDestroy(sign);
    HcfObjDestroy(verify);
    HcfObjDestroy(keyPair);
    HcfObjDestroy(returnObj);
    DestroyAlg25519KeyPairSpec(reinterpret_cast<HcfAlg25519KeyPairParamsSpec *>(paramSpec));
}

HWTEST_F(CryptoEd25519AsyKeyGeneratorBySpecTest, CryptoEd25519AsyKeyGeneratorBySpecTest017, TestSize.Level0)
{
    HcfAsyKeyGenParams params = {
        .algo = HCF_ALG_ED25519,
        .bits = HCF_ALG_ED25519_256,
        .primes = HCF_OPENSSL_PRIMES_2,
    };

    HcfAsyKeyGeneratorSpi *returnSpi = nullptr;
    HcfResult res = HcfAsyKeyGeneratorSpiEd25519Create(&params, &returnSpi);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(returnSpi, nullptr);
    HcfObjDestroy(returnSpi);
}

HWTEST_F(CryptoEd25519AsyKeyGeneratorBySpecTest, CryptoEd25519AsyKeyGeneratorBySpecTest018, TestSize.Level0)
{
    HcfAsyKeyGenParams params = {
        .algo = HCF_ALG_ED25519,
        .bits = HCF_ALG_ED25519_256,
        .primes = HCF_OPENSSL_PRIMES_2,
    };

    HcfAsyKeyGeneratorSpi *returnSpi = nullptr;
    HcfResult res = HcfAsyKeyGeneratorSpiEd25519Create(&params, &returnSpi);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(returnSpi, nullptr);

    HcfAsyKeyParamsSpec *paramsSpec = nullptr;
    res = ConstructAlg25519KeyPairParamsSpec(g_ed25519AlgoName.c_str(), true, &paramsSpec);
    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(returnSpi, nullptr);

    HcfKeyPair *keyPair = nullptr;
    res = returnSpi->engineGenerateKeyPairBySpec(returnSpi, paramsSpec, &keyPair);
    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(keyPair, nullptr);

    HcfObjDestroy(returnSpi);
    HcfObjDestroy(keyPair);
    DestroyAlg25519KeyPairSpec(reinterpret_cast<HcfAlg25519KeyPairParamsSpec *>(paramsSpec));
}

HWTEST_F(CryptoEd25519AsyKeyGeneratorBySpecTest, CryptoEd25519AsyKeyGeneratorBySpecTest019, TestSize.Level0)
{
    HcfAsyKeyGenParams params = {
        .algo = HCF_ALG_ED25519,
        .bits = HCF_ALG_ED25519_256,
        .primes = HCF_OPENSSL_PRIMES_2,
    };

    HcfAsyKeyGeneratorSpi *returnSpi = nullptr;
    HcfResult res = HcfAsyKeyGeneratorSpiEd25519Create(&params, &returnSpi);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(returnSpi, nullptr);

    HcfAsyKeyParamsSpec *paramsSpec = nullptr;
    res = ConstructAlg25519PubKeyParamsSpec(g_ed25519AlgoName.c_str(), true, &paramsSpec);
    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(returnSpi, nullptr);

    HcfPubKey *pubKey = nullptr;
    res = returnSpi->engineGeneratePubKeyBySpec(returnSpi, paramsSpec, &pubKey);
    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(pubKey, nullptr);

    HcfObjDestroy(returnSpi);
    HcfObjDestroy(pubKey);
    DestroyAlg25519PubKeySpec(reinterpret_cast<HcfAlg25519PubKeyParamsSpec *>(paramsSpec));
}

HWTEST_F(CryptoEd25519AsyKeyGeneratorBySpecTest, CryptoEd25519AsyKeyGeneratorBySpecTest020, TestSize.Level0)
{
    HcfAsyKeyGenParams params = {
        .algo = HCF_ALG_ED25519,
        .bits = HCF_ALG_ED25519_256,
        .primes = HCF_OPENSSL_PRIMES_2,
    };

    HcfAsyKeyGeneratorSpi *returnSpi = nullptr;
    HcfResult res = HcfAsyKeyGeneratorSpiEd25519Create(&params, &returnSpi);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(returnSpi, nullptr);

    HcfAsyKeyParamsSpec *paramsSpec = nullptr;
    res = ConstructAlg25519PriKeyParamsSpec(g_ed25519AlgoName.c_str(), true, &paramsSpec);
    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(returnSpi, nullptr);

    HcfPriKey *priKey = nullptr;
    res = returnSpi->engineGeneratePriKeyBySpec(returnSpi, paramsSpec, &priKey);
    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(priKey, nullptr);

    HcfObjDestroy(returnSpi);
    HcfObjDestroy(priKey);
    DestroyAlg25519PriKeySpec(reinterpret_cast<HcfAlg25519PriKeyParamsSpec *>(paramsSpec));
}

HWTEST_F(CryptoEd25519AsyKeyGeneratorBySpecTest, CryptoEd25519AsyKeyGeneratorBySpecTest021, TestSize.Level0)
{
    HcfAsyKeyParamsSpec *paramSpec = nullptr;
    HcfAsyKeyGeneratorBySpec *returnObj = nullptr;
    HcfResult res = TestCreatePubKeyParamsSpecAndGeneratorBySpec(g_ed25519AlgoName.c_str(), true,
        &paramSpec, &returnObj);
    ASSERT_EQ(res, HCF_SUCCESS);

    HcfPriKey *priKey = nullptr;
    res = returnObj->generatePriKey(returnObj, &priKey);
    ASSERT_EQ(res, HCF_INVALID_PARAMS);
    ASSERT_EQ(priKey, nullptr);

    HcfKeyPair *keyPair = nullptr;
    res = returnObj->generateKeyPair(returnObj, &keyPair);
    ASSERT_EQ(res, HCF_INVALID_PARAMS);
    ASSERT_EQ(keyPair, nullptr);

    HcfObjDestroy(returnObj);
    HcfObjDestroy(priKey);
    HcfObjDestroy(keyPair);
    DestroyAlg25519PubKeySpec(reinterpret_cast<HcfAlg25519PubKeyParamsSpec *>(paramSpec));
}

HWTEST_F(CryptoEd25519AsyKeyGeneratorBySpecTest, CryptoEd25519AsyKeyGeneratorBySpecTest022, TestSize.Level0)
{
    HcfAsyKeyParamsSpec *paramSpec = nullptr;
    HcfAsyKeyGeneratorBySpec *returnObj = nullptr;

    HcfResult res = TestCreatePriKeyParamsSpecAndGeneratorBySpec(g_ed25519AlgoName.c_str(), true,
        &paramSpec, &returnObj);
    ASSERT_EQ(res, HCF_SUCCESS);

    HcfKeyPair *keyPair = nullptr;
    res = returnObj->generateKeyPair(returnObj, &keyPair);
    ASSERT_EQ(res, HCF_INVALID_PARAMS);
    ASSERT_EQ(keyPair, nullptr);

    HcfPubKey *pubKey = nullptr;
    res = returnObj->generatePubKey(returnObj, &pubKey);
    ASSERT_EQ(res, HCF_INVALID_PARAMS);
    ASSERT_EQ(pubKey, nullptr);

    HcfObjDestroy(returnObj);
    HcfObjDestroy(keyPair);
    HcfObjDestroy(pubKey);
    DestroyAlg25519PriKeySpec(reinterpret_cast<HcfAlg25519PriKeyParamsSpec *>(paramSpec));
}

HWTEST_F(CryptoEd25519AsyKeyGeneratorBySpecTest, CryptoEd25519AsyKeyGeneratorBySpecTest023, TestSize.Level0)
{
    HcfAsyKeyGenerator *generator;
    HcfResult res = HcfAsyKeyGeneratorCreate(g_ed25519AlgoName.c_str(), &generator);
    ASSERT_EQ(res, HCF_SUCCESS);

    HcfKeyPair *keyPair = nullptr;
    res = generator->generateKeyPair(generator, nullptr, &keyPair);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(keyPair, nullptr);

    HcfBlob blob1 = { .data = nullptr, .len = 0 };
    res = keyPair->pubKey->base.getEncoded(&(keyPair->pubKey->base), &blob1);
    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(blob1.data, nullptr);
    ASSERT_NE(blob1.len, 0);

    HcfAsyKeyParamsSpec *paramSpec = nullptr;
    HcfAsyKeyGeneratorBySpec *returnObj = nullptr;
    res = TestCreatePubKeyParamsSpecAndGeneratorBySpec(g_ed25519AlgoName.c_str(), true,
        &paramSpec, &returnObj);
    ASSERT_EQ(res, HCF_SUCCESS);

    HcfPubKey *pubKey = nullptr;
    res = returnObj->generatePubKey(returnObj, &pubKey);
    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(pubKey, nullptr);

    HcfBlob blob2 = { .data = nullptr, .len = 0 };
    res = pubKey->base.getEncoded(&(pubKey->base), &blob2);
    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(blob2.data, nullptr);
    ASSERT_NE(blob2.len, 0);

    ASSERT_EQ(*(blob1.data), *(blob2.data));
    ASSERT_EQ(blob1.len, blob2.len);

    HcfFree(blob1.data);
    HcfFree(blob2.data);
    HcfObjDestroy(returnObj);
    HcfObjDestroy(pubKey);
    HcfObjDestroy(keyPair);
    DestroyAlg25519PubKeySpec(reinterpret_cast<HcfAlg25519PubKeyParamsSpec *>(paramSpec));
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoEd25519AsyKeyGeneratorBySpecTest, CryptoEd25519AsyKeyGeneratorBySpecTest024, TestSize.Level0)
{
    HcfAsyKeyGenerator *generator;
    HcfResult res = HcfAsyKeyGeneratorCreate(g_ed25519AlgoName.c_str(), &generator);
    ASSERT_EQ(res, HCF_SUCCESS);

    HcfKeyPair *keyPair = nullptr;
    res = generator->generateKeyPair(generator, nullptr, &keyPair);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(keyPair, nullptr);

    HcfBlob blob1 = { .data = nullptr, .len = 0 };
    res = keyPair->priKey->base.getEncoded(&(keyPair->priKey->base), &blob1);
    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(blob1.data, nullptr);
    ASSERT_NE(blob1.len, 0);

    HcfAsyKeyParamsSpec *paramSpec = nullptr;
    HcfAsyKeyGeneratorBySpec *returnObj = nullptr;

    res = TestCreatePriKeyParamsSpecAndGeneratorBySpec(g_ed25519AlgoName.c_str(), true,
        &paramSpec, &returnObj);
    ASSERT_EQ(res, HCF_SUCCESS);

    HcfPriKey *priKey = nullptr;
    res = returnObj->generatePriKey(returnObj, &priKey);
    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(priKey, nullptr);

    HcfBlob blob2 = { .data = nullptr, .len = 0 };
    res = priKey->base.getEncoded(&(priKey->base), &blob2);
    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(blob2.data, nullptr);
    ASSERT_NE(blob2.len, 0);

    ASSERT_EQ(*(blob1.data), *(blob2.data));
    ASSERT_EQ(blob1.len, blob2.len);

    HcfFree(blob1.data);
    HcfFree(blob2.data);
    HcfObjDestroy(returnObj);
    HcfObjDestroy(priKey);
    HcfObjDestroy(keyPair);
    DestroyAlg25519PriKeySpec(reinterpret_cast<HcfAlg25519PriKeyParamsSpec *>(paramSpec));
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoEd25519AsyKeyGeneratorBySpecTest, CryptoEd25519AsyKeyGeneratorBySpecTest025, TestSize.Level0)
{
    HcfAsyKeyParamsSpec *paramSpec = nullptr;
    HcfAsyKeyGeneratorBySpec *returnObj = nullptr;
    HcfResult res = TestCreatePriKeyParamsSpecAndGeneratorBySpec(g_ed25519AlgoName.c_str(), true,
        &paramSpec, &returnObj);
    ASSERT_EQ(res, HCF_SUCCESS);

    HcfPriKey *priKey = nullptr;
    res = returnObj->generatePriKey(returnObj, &priKey);
    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(priKey, nullptr);

    HcfBlob blob = { .data = nullptr, .len = 0 };
    res = priKey->base.getEncoded(&(priKey->base), &blob);
    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(blob.data, nullptr);
    ASSERT_NE(blob.len, 0);

    HcfAsyKeyGenerator *generator;
    res = HcfAsyKeyGeneratorCreate(g_ed25519AlgoName.c_str(), &generator);
    ASSERT_EQ(res, HCF_SUCCESS);

    HcfKeyPair *keyPair = nullptr;
    res = generator->convertKey(generator, nullptr, nullptr, &blob, &keyPair);

    HcfFree(blob.data);
    HcfObjDestroy(returnObj);
    HcfObjDestroy(priKey);
    HcfObjDestroy(keyPair);
    DestroyAlg25519PriKeySpec(reinterpret_cast<HcfAlg25519PriKeyParamsSpec *>(paramSpec));
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoEd25519AsyKeyGeneratorBySpecTest, CryptoEd25519AsyKeyGeneratorBySpecTest026, TestSize.Level0)
{
    HcfAsyKeyParamsSpec *paramSpec = nullptr;
    HcfAsyKeyGeneratorBySpec *returnObj = nullptr;

    HcfResult res = TestCreatePubKeyParamsSpecAndGeneratorBySpec(g_ed25519AlgoName.c_str(), true,
        &paramSpec, &returnObj);
    ASSERT_EQ(res, HCF_SUCCESS);

    HcfPubKey *pubKey = nullptr;
    res = returnObj->generatePubKey(returnObj, &pubKey);
    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(pubKey, nullptr);

    HcfBlob blob = { .data = nullptr, .len = 0 };
    res = pubKey->base.getEncoded(&(pubKey->base), &blob);
    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(blob.data, nullptr);
    ASSERT_NE(blob.len, 0);

    HcfAsyKeyGenerator *generator;
    res = HcfAsyKeyGeneratorCreate(g_ed25519AlgoName.c_str(), &generator);
    ASSERT_EQ(res, HCF_SUCCESS);

    HcfKeyPair *keyPair = nullptr;
    res = generator->convertKey(generator, nullptr, &blob, nullptr, &keyPair);
    HcfFree(blob.data);
    HcfObjDestroy(returnObj);
    HcfObjDestroy(pubKey);
    HcfObjDestroy(keyPair);
    DestroyAlg25519PubKeySpec(reinterpret_cast<HcfAlg25519PubKeyParamsSpec *>(paramSpec));
    HcfObjDestroy(generator);
}
}