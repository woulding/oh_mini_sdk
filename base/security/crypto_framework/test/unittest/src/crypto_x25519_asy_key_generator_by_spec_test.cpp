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
#include "securec.h"

#include "alg_25519_common_param_spec.h"
#include "asy_key_generator_spi.h"
#include "blob.h"
#include "signature.h"
#include "memory.h"
#include "openssl_class.h"
#include "openssl_common.h"
#include "asy_key_params.h"
#include "key_utils.h"
#include "key_pair.h"
#include "object_base.h"
#include "alg_25519_asy_key_generator_openssl.h"

using namespace std;
using namespace testing::ext;

namespace {
class CryptoX25519AsyKeyGeneratorBySpecTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp();
    void TearDown();
};

static string g_x25519AlgoName = "X25519";
static string g_pubkeyformatName = "X.509";
static string g_prikeyformatName = "PKCS#8";

void CryptoX25519AsyKeyGeneratorBySpecTest::SetUp() {}
void CryptoX25519AsyKeyGeneratorBySpecTest::TearDown() {}
void CryptoX25519AsyKeyGeneratorBySpecTest::SetUpTestCase() {}
void CryptoX25519AsyKeyGeneratorBySpecTest::TearDownTestCase() {}

HWTEST_F(CryptoX25519AsyKeyGeneratorBySpecTest, CryptoX25519AsyKeyGeneratorBySpecTest001_1, TestSize.Level0)
{
    HcfAsyKeyParamsSpec *paramSpec = nullptr;
    HcfAsyKeyGeneratorBySpec *returnObj = nullptr;
    HcfResult res = TestCreateKeyPairParamsSpecAndGeneratorBySpec(g_x25519AlgoName.c_str(), false,
        &paramSpec, &returnObj);
    ASSERT_EQ(res, HCF_SUCCESS);
    HcfObjDestroy(returnObj);
    DestroyAlg25519KeyPairSpec(reinterpret_cast<HcfAlg25519KeyPairParamsSpec *>(paramSpec));
}

HWTEST_F(CryptoX25519AsyKeyGeneratorBySpecTest, CryptoX25519AsyKeyGeneratorBySpecTest001_2, TestSize.Level0)
{
    HcfAsyKeyParamsSpec *paramSpec = nullptr;
    HcfAsyKeyGeneratorBySpec *returnObj = nullptr;
    HcfResult res = TestCreatePubKeyParamsSpecAndGeneratorBySpec(g_x25519AlgoName.c_str(), false,
        &paramSpec, &returnObj);
    ASSERT_EQ(res, HCF_SUCCESS);
    HcfObjDestroy(returnObj);
    DestroyAlg25519PubKeySpec(reinterpret_cast<HcfAlg25519PubKeyParamsSpec *>(paramSpec));
}

HWTEST_F(CryptoX25519AsyKeyGeneratorBySpecTest, CryptoX25519AsyKeyGeneratorBySpecTest001_3, TestSize.Level0)
{
    HcfAsyKeyParamsSpec *paramSpec = nullptr;
    HcfAsyKeyGeneratorBySpec *returnObj = nullptr;
    HcfResult res = TestCreatePriKeyParamsSpecAndGeneratorBySpec(g_x25519AlgoName.c_str(), false,
        &paramSpec, &returnObj);
    ASSERT_EQ(res, HCF_SUCCESS);
    HcfObjDestroy(returnObj);
    DestroyAlg25519PriKeySpec(reinterpret_cast<HcfAlg25519PriKeyParamsSpec *>(paramSpec));
}

HWTEST_F(CryptoX25519AsyKeyGeneratorBySpecTest, CryptoX25519AsyKeyGeneratorBySpecTest002, TestSize.Level0)
{
    HcfAsyKeyParamsSpec *paramSpec = nullptr;
    HcfAsyKeyGeneratorBySpec *returnObj = nullptr;
    HcfResult res = TestCreateKeyPairParamsSpecAndGeneratorBySpec(g_x25519AlgoName.c_str(), false,
        &paramSpec, &returnObj);
    ASSERT_EQ(res, HCF_SUCCESS);

    const char *className = returnObj->base.getClass();
    ASSERT_NE(className, nullptr);
    ASSERT_NE(returnObj, nullptr);
    HcfObjDestroy(returnObj);
    DestroyAlg25519KeyPairSpec(reinterpret_cast<HcfAlg25519KeyPairParamsSpec *>(paramSpec));
}

HWTEST_F(CryptoX25519AsyKeyGeneratorBySpecTest, CryptoX25519AsyKeyGeneratorBySpecTest003, TestSize.Level0)
{
    HcfAsyKeyParamsSpec *paramSpec = nullptr;
    HcfAsyKeyGeneratorBySpec *returnObj = nullptr;
    HcfResult res = TestCreateKeyPairParamsSpecAndGeneratorBySpec(g_x25519AlgoName.c_str(), false,
        &paramSpec, &returnObj);
    ASSERT_EQ(res, HCF_SUCCESS);

    returnObj->base.destroy((HcfObjectBase *)returnObj);
    DestroyAlg25519KeyPairSpec(reinterpret_cast<HcfAlg25519KeyPairParamsSpec *>(paramSpec));
}

HWTEST_F(CryptoX25519AsyKeyGeneratorBySpecTest, CryptoX25519AsyKeyGeneratorBySpecTest004, TestSize.Level0)
{
    HcfAsyKeyParamsSpec *paramSpec = nullptr;
    HcfAsyKeyGeneratorBySpec *returnObj = nullptr;
    HcfResult res = TestCreateKeyPairParamsSpecAndGeneratorBySpec(g_x25519AlgoName.c_str(), false,
        &paramSpec, &returnObj);
    ASSERT_EQ(res, HCF_SUCCESS);

    const char *algoName = returnObj->getAlgName(returnObj);
    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_EQ(algoName, g_x25519AlgoName);

    HcfObjDestroy(returnObj);
    DestroyAlg25519KeyPairSpec(reinterpret_cast<HcfAlg25519KeyPairParamsSpec *>(paramSpec));
}

HWTEST_F(CryptoX25519AsyKeyGeneratorBySpecTest, CryptoX25519AsyKeyGeneratorBySpecTest005, TestSize.Level0)
{
    HcfAsyKeyParamsSpec *paramSpec = nullptr;
    HcfAsyKeyGeneratorBySpec *returnObj = nullptr;
    HcfResult res = TestCreateKeyPairParamsSpecAndGeneratorBySpec(g_x25519AlgoName.c_str(), false,
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

HWTEST_F(CryptoX25519AsyKeyGeneratorBySpecTest, CryptoX25519AsyKeyGeneratorBySpecTest006, TestSize.Level0)
{
    HcfAsyKeyParamsSpec *paramSpec = nullptr;
    HcfAsyKeyGeneratorBySpec *returnObj = nullptr;
    HcfResult res = TestCreateKeyPairParamsSpecAndGeneratorBySpec(g_x25519AlgoName.c_str(), false,
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

HWTEST_F(CryptoX25519AsyKeyGeneratorBySpecTest, CryptoX25519AsyKeyGeneratorBySpecTest007, TestSize.Level0)
{
    HcfAsyKeyParamsSpec *paramSpec = nullptr;
    HcfAsyKeyGeneratorBySpec *returnObj = nullptr;
    HcfResult res = TestCreateKeyPairParamsSpecAndGeneratorBySpec(g_x25519AlgoName.c_str(), false,
        &paramSpec, &returnObj);
    ASSERT_EQ(res, HCF_SUCCESS);

    HcfKeyPair *keyPair = nullptr;
    res = returnObj->generateKeyPair(returnObj, &keyPair);
    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(keyPair, nullptr);

    keyPair->base.destroy(&(keyPair->base));
    ASSERT_NE(returnObj, nullptr);
    HcfObjDestroy(returnObj);
    DestroyAlg25519KeyPairSpec(reinterpret_cast<HcfAlg25519KeyPairParamsSpec *>(paramSpec));
}

HWTEST_F(CryptoX25519AsyKeyGeneratorBySpecTest, CryptoX25519AsyKeyGeneratorBySpecTest008, TestSize.Level0)
{
    HcfAsyKeyParamsSpec *paramSpec = nullptr;
    HcfAsyKeyGeneratorBySpec *returnObj = nullptr;
    HcfResult res = TestCreateKeyPairParamsSpecAndGeneratorBySpec(g_x25519AlgoName.c_str(), false,
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

HWTEST_F(CryptoX25519AsyKeyGeneratorBySpecTest, CryptoX25519AsyKeyGeneratorBySpecTest009, TestSize.Level0)
{
    HcfAsyKeyParamsSpec *paramSpec = nullptr;
    HcfAsyKeyGeneratorBySpec *returnObj = nullptr;
    HcfResult res = TestCreateKeyPairParamsSpecAndGeneratorBySpec(g_x25519AlgoName.c_str(), false,
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

HWTEST_F(CryptoX25519AsyKeyGeneratorBySpecTest, CryptoX25519AsyKeyGeneratorBySpecTest010, TestSize.Level0)
{
    HcfAsyKeyParamsSpec *paramSpec = nullptr;
    HcfAsyKeyGeneratorBySpec *returnObj = nullptr;
    HcfResult res = TestCreateKeyPairParamsSpecAndGeneratorBySpec(g_x25519AlgoName.c_str(), false,
        &paramSpec, &returnObj);
    ASSERT_EQ(res, HCF_SUCCESS);

    HcfKeyPair *keyPair = nullptr;
    res = returnObj->generateKeyPair(returnObj, &keyPair);
    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(keyPair, nullptr);

    const char *algorithmName = keyPair->pubKey->base.getAlgorithm(&(keyPair->pubKey->base));
    ASSERT_EQ(algorithmName, g_x25519AlgoName);

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

HWTEST_F(CryptoX25519AsyKeyGeneratorBySpecTest, CryptoX25519AsyKeyGeneratorBySpecTest011, TestSize.Level0)
{
    HcfAsyKeyParamsSpec *paramSpec = nullptr;
    HcfAsyKeyGeneratorBySpec *returnObj = nullptr;
    HcfResult res = TestCreateKeyPairParamsSpecAndGeneratorBySpec(g_x25519AlgoName.c_str(), false,
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

HWTEST_F(CryptoX25519AsyKeyGeneratorBySpecTest, CryptoX25519AsyKeyGeneratorBySpecTest012, TestSize.Level0)
{
    HcfAsyKeyParamsSpec *paramSpec = nullptr;
    HcfAsyKeyGeneratorBySpec *returnObj = nullptr;
    HcfResult res = TestCreateKeyPairParamsSpecAndGeneratorBySpec(g_x25519AlgoName.c_str(), false,
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

HWTEST_F(CryptoX25519AsyKeyGeneratorBySpecTest, CryptoX25519AsyKeyGeneratorBySpecTest013, TestSize.Level0)
{
    HcfAsyKeyParamsSpec *paramSpec = nullptr;
    HcfAsyKeyGeneratorBySpec *returnObj = nullptr;
    HcfResult res = TestCreateKeyPairParamsSpecAndGeneratorBySpec(g_x25519AlgoName.c_str(), false,
        &paramSpec, &returnObj);
    ASSERT_EQ(res, HCF_SUCCESS);

    HcfKeyPair *keyPair = nullptr;
    res = returnObj->generateKeyPair(returnObj, &keyPair);
    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(keyPair, nullptr);

    const char *algorithmName = keyPair->priKey->base.getAlgorithm(&(keyPair->priKey->base));
    ASSERT_EQ(algorithmName, g_x25519AlgoName);

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

HWTEST_F(CryptoX25519AsyKeyGeneratorBySpecTest, CryptoX25519AsyKeyGeneratorBySpecTest014, TestSize.Level0)
{
    HcfAsyKeyParamsSpec *paramSpec = nullptr;
    HcfAsyKeyGeneratorBySpec *returnObj = nullptr;
    HcfResult res = TestCreateKeyPairParamsSpecAndGeneratorBySpec(g_x25519AlgoName.c_str(), false,
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

HWTEST_F(CryptoX25519AsyKeyGeneratorBySpecTest, CryptoX25519AsyKeyGeneratorBySpecTest015, TestSize.Level0)
{
    HcfAsyKeyParamsSpec *pubparamSpec = nullptr;
    HcfAsyKeyGeneratorBySpec *returnpubObj = nullptr;
    HcfResult res = TestCreatePubKeyParamsSpecAndGeneratorBySpec(g_x25519AlgoName.c_str(), false,
        &pubparamSpec, &returnpubObj);
    ASSERT_EQ(res, HCF_SUCCESS);

    HcfAsyKeyParamsSpec *priparamSpec = nullptr;
    HcfAsyKeyGeneratorBySpec *returnpriObj = nullptr;
    res = TestCreatePriKeyParamsSpecAndGeneratorBySpec(g_x25519AlgoName.c_str(), false,
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
    res = pubKey->getAsyKeySpecBigInteger(pubKey, X25519_PK_BN, &returnBigInteger);
    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(returnBigInteger.data, nullptr);
    ASSERT_NE(returnBigInteger.len, 0);
    HcfFree(returnBigInteger.data);

    HcfBigInteger returnBigInteger1 = { .data = nullptr, .len = 0 };
    res = priKey->getAsyKeySpecBigInteger(priKey, X25519_SK_BN, &returnBigInteger1);
    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(returnBigInteger1.data, nullptr);
    ASSERT_NE(returnBigInteger1.len, 0);
    HcfFree(returnBigInteger1.data);
    HcfObjDestroy(pubKey);
    HcfObjDestroy(priKey);
    HcfObjDestroy(returnpubObj);
    HcfObjDestroy(returnpriObj);
    DestroyAlg25519PubKeySpec(reinterpret_cast<HcfAlg25519PubKeyParamsSpec *>(pubparamSpec));
    DestroyAlg25519PriKeySpec(reinterpret_cast<HcfAlg25519PriKeyParamsSpec *>(priparamSpec));
}

HWTEST_F(CryptoX25519AsyKeyGeneratorBySpecTest, CryptoX25519AsyKeyGeneratorBySpecTest016, TestSize.Level0)
{
    HcfAsyKeyGenParams params = {
        .algo = HCF_ALG_X25519,
        .bits = HCF_ALG_X25519_256,
        .primes = HCF_OPENSSL_PRIMES_2,
    };

    HcfAsyKeyGeneratorSpi *returnSpi = nullptr;
    HcfResult res = HcfAsyKeyGeneratorSpiX25519Create(&params, &returnSpi);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(returnSpi, nullptr);
    HcfObjDestroy(returnSpi);
}

HWTEST_F(CryptoX25519AsyKeyGeneratorBySpecTest, CryptoX25519AsyKeyGeneratorBySpecTest017, TestSize.Level0)
{
    HcfAsyKeyGenParams params = {
        .algo = HCF_ALG_X25519,
        .bits = HCF_ALG_X25519_256,
        .primes = HCF_OPENSSL_PRIMES_2,
    };

    HcfAsyKeyGeneratorSpi *returnSpi = nullptr;
    HcfResult res = HcfAsyKeyGeneratorSpiX25519Create(&params, &returnSpi);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(returnSpi, nullptr);

    HcfAsyKeyParamsSpec *paramsSpec = nullptr;
    res = ConstructAlg25519KeyPairParamsSpec(g_x25519AlgoName.c_str(), false, &paramsSpec);
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

HWTEST_F(CryptoX25519AsyKeyGeneratorBySpecTest, CryptoX25519AsyKeyGeneratorBySpecTest018, TestSize.Level0)
{
    HcfAsyKeyGenParams params = {
        .algo = HCF_ALG_X25519,
        .bits = HCF_ALG_X25519_256,
        .primes = HCF_OPENSSL_PRIMES_2,
    };

    HcfAsyKeyGeneratorSpi *returnSpi = nullptr;
    HcfResult res = HcfAsyKeyGeneratorSpiX25519Create(&params, &returnSpi);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(returnSpi, nullptr);

    HcfAsyKeyParamsSpec *paramSpec = nullptr;
    res = ConstructAlg25519PubKeyParamsSpec("X25519", false, &paramSpec);
    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(returnSpi, nullptr);

    HcfPubKey *pubKey = nullptr;
    res = returnSpi->engineGeneratePubKeyBySpec(returnSpi, paramSpec, &pubKey);
    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(pubKey, nullptr);

    HcfObjDestroy(returnSpi);
    HcfObjDestroy(pubKey);
    DestroyAlg25519PubKeySpec(reinterpret_cast<HcfAlg25519PubKeyParamsSpec *>(paramSpec));
}

HWTEST_F(CryptoX25519AsyKeyGeneratorBySpecTest, CryptoX25519AsyKeyGeneratorBySpecTest019, TestSize.Level0)
{
    HcfAsyKeyGenParams params = {
        .algo = HCF_ALG_X25519,
        .bits = HCF_ALG_X25519_256,
        .primes = HCF_OPENSSL_PRIMES_2,
    };

    HcfAsyKeyGeneratorSpi *returnSpi = nullptr;
    HcfResult res = HcfAsyKeyGeneratorSpiX25519Create(&params, &returnSpi);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(returnSpi, nullptr);

    HcfAsyKeyParamsSpec *paramSpec = nullptr;
    res = ConstructAlg25519PriKeyParamsSpec("X25519", false, &paramSpec);
    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(returnSpi, nullptr);

    HcfPriKey *priKey = nullptr;
    res = returnSpi->engineGeneratePriKeyBySpec(returnSpi, paramSpec, &priKey);
    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(priKey, nullptr);

    HcfObjDestroy(returnSpi);
    HcfObjDestroy(priKey);
    DestroyAlg25519PriKeySpec(reinterpret_cast<HcfAlg25519PriKeyParamsSpec *>(paramSpec));
}

HWTEST_F(CryptoX25519AsyKeyGeneratorBySpecTest, CryptoX25519AsyKeyGeneratorBySpecTest020, TestSize.Level0)
{
    HcfAsyKeyGenerator *generator = nullptr;
    HcfKeyPair *keyPair = nullptr;
    HcfResult res = TestKeyGeneratorAndGenerateKeyPair(g_x25519AlgoName.c_str(), &generator, &keyPair);
    ASSERT_EQ(res, HCF_SUCCESS);

    HcfBlob blob1 = { .data = nullptr, .len = 0 };
    res = keyPair->pubKey->base.getEncoded(&(keyPair->pubKey->base), &blob1);
    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(blob1.data, nullptr);
    ASSERT_NE(blob1.len, 0);

    HcfAsyKeyParamsSpec *paramSpec = nullptr;
    HcfAsyKeyGeneratorBySpec *returnObj = nullptr;
    res = TestCreatePubKeyParamsSpecAndGeneratorBySpec(g_x25519AlgoName.c_str(), false,
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
    HcfObjDestroy(generator);
    HcfObjDestroy(keyPair);
    DestroyAlg25519PubKeySpec(reinterpret_cast<HcfAlg25519PubKeyParamsSpec *>(paramSpec));
}

HWTEST_F(CryptoX25519AsyKeyGeneratorBySpecTest, CryptoX25519AsyKeyGeneratorBySpecTest021, TestSize.Level0)
{
    HcfAsyKeyGenerator *generator = nullptr;
    HcfKeyPair *keyPair = nullptr;
    HcfResult res = TestKeyGeneratorAndGenerateKeyPair(g_x25519AlgoName.c_str(), &generator, &keyPair);
    ASSERT_EQ(res, HCF_SUCCESS);

    HcfBlob blob1 = { .data = nullptr, .len = 0 };
    res = keyPair->priKey->base.getEncoded(&(keyPair->priKey->base), &blob1);
    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(blob1.data, nullptr);
    ASSERT_NE(blob1.len, 0);

    HcfAsyKeyParamsSpec *paramSpec = nullptr;
    HcfAsyKeyGeneratorBySpec *returnObj = nullptr;
    res = TestCreatePriKeyParamsSpecAndGeneratorBySpec(g_x25519AlgoName.c_str(), false,
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
    HcfObjDestroy(generator);
    HcfObjDestroy(keyPair);
    DestroyAlg25519PriKeySpec(reinterpret_cast<HcfAlg25519PriKeyParamsSpec *>(paramSpec));
}

HWTEST_F(CryptoX25519AsyKeyGeneratorBySpecTest, CryptoX25519AsyKeyGeneratorBySpecTest022, TestSize.Level0)
{
    HcfAsyKeyParamsSpec *paramSpec = nullptr;
    HcfAsyKeyGeneratorBySpec *returnObj = nullptr;
    HcfResult res = TestCreatePriKeyParamsSpecAndGeneratorBySpec(g_x25519AlgoName.c_str(), false,
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
    res = HcfAsyKeyGeneratorCreate("X25519", &generator);
    ASSERT_EQ(res, HCF_SUCCESS);

    HcfKeyPair *keyPair = nullptr;
    res = generator->convertKey(generator, nullptr, nullptr, &blob, &keyPair);

    HcfFree(blob.data);
    HcfObjDestroy(returnObj);
    HcfObjDestroy(generator);
    HcfObjDestroy(priKey);
    HcfObjDestroy(keyPair);
    DestroyAlg25519PriKeySpec(reinterpret_cast<HcfAlg25519PriKeyParamsSpec *>(paramSpec));
}

HWTEST_F(CryptoX25519AsyKeyGeneratorBySpecTest, CryptoX25519AsyKeyGeneratorBySpecTest023, TestSize.Level0)
{
    HcfAsyKeyParamsSpec *paramSpec = nullptr;
    HcfAsyKeyGeneratorBySpec *returnObj = nullptr;
    HcfResult res = TestCreatePubKeyParamsSpecAndGeneratorBySpec(g_x25519AlgoName.c_str(), false,
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
    res = HcfAsyKeyGeneratorCreate("X25519", &generator);
    ASSERT_EQ(res, HCF_SUCCESS);

    HcfKeyPair *keyPair = nullptr;
    res = generator->convertKey(generator, nullptr, &blob, nullptr, &keyPair);

    HcfFree(blob.data);
    HcfObjDestroy(generator);
    HcfObjDestroy(returnObj);
    HcfObjDestroy(pubKey);
    HcfObjDestroy(keyPair);
    DestroyAlg25519PubKeySpec(reinterpret_cast<HcfAlg25519PubKeyParamsSpec *>(paramSpec));
}
}