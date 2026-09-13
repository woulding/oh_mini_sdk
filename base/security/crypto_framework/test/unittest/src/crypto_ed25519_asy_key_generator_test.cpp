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
#include "blob.h"
#include "params_parser.h"
#include "key_pair.h"
#include "object_base.h"
#include "signature.h"
#include "alg_25519_asy_key_generator_openssl.h"
#include "detailed_alg_25519_key_params.h"
#include "memory.h"
#include "memory_mock.h"
#include "openssl_adapter_mock.h"

using namespace std;
using namespace testing::ext;

namespace {
class CryptoEd25519AsyKeyGeneratorTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp();
    void TearDown();
};

void CryptoEd25519AsyKeyGeneratorTest::TearDownTestCase() {}
void CryptoEd25519AsyKeyGeneratorTest::SetUp() {}
void CryptoEd25519AsyKeyGeneratorTest::TearDown() {}
static string g_ed25519AlgoName = "Ed25519";
static string g_pubkeyformatName = "X.509";
static string g_prikeyformatName = "PKCS#8";

HcfBlob g_mockEd25519PriKeyBlob = {
    .data = nullptr,
    .len = 0
};

HcfBlob g_mockEd25519PubKeyBlob = {
    .data = nullptr,
    .len = 0
};

HcfBlob g_mockECC_BrainPool160r1PriKeyBlob = {
    .data = nullptr,
    .len = 0
};

HcfBlob g_mockECC_BrainPool160r1PubKeyBlob = {
    .data = nullptr,
    .len = 0
};

static const char *GetMockClass(void)
{
    return "ed25519generator";
}
HcfObjectBase g_obj = {
    .getClass = GetMockClass,
    .destroy = nullptr
};

static const char *g_mockMessage = "hello world";
static HcfBlob g_mockInput = {
    .data = (uint8_t *)g_mockMessage,
    .len = 12
};

static HcfResult Ed25519KeyBlob(HcfBlob * priblob, HcfBlob *pubblob)
{
    HcfAsyKeyGenerator *generator = nullptr;
    HcfResult res = HcfAsyKeyGeneratorCreate("Ed25519", &generator);
    if (res != HCF_SUCCESS) {
        return HCF_INVALID_PARAMS;
    }

    HcfKeyPair *keyPair = nullptr;
    res = generator->generateKeyPair(generator, nullptr, &keyPair);
    if (res != HCF_SUCCESS) {
        HcfObjDestroy(generator);
        return res;
    }
    res = keyPair->priKey->base.getEncoded(&(keyPair->priKey->base), &g_mockEd25519PriKeyBlob);
    if (res != HCF_SUCCESS) {
        HcfObjDestroy(generator);
        HcfObjDestroy(keyPair);
        return res;
    }
    res = keyPair->pubKey->base.getEncoded(&(keyPair->pubKey->base), &g_mockEd25519PubKeyBlob);
    if (res != HCF_SUCCESS) {
        HcfObjDestroy(generator);
        HcfObjDestroy(keyPair);
        return res;
    }
    HcfObjDestroy(generator);
    HcfObjDestroy(keyPair);
    return HCF_SUCCESS;
}

static HcfResult ECC_BrainPool160r1KeyBlob(HcfBlob * priblob, HcfBlob *pubblob)
{
    HcfAsyKeyGenerator *generator = nullptr;
    HcfResult res = HcfAsyKeyGeneratorCreate("ECC_BrainPoolP160r1", &generator);
    if (res != HCF_SUCCESS) {
        return res;
    }

    HcfKeyPair *keyPair = nullptr;
    res = generator->generateKeyPair(generator, nullptr, &keyPair);
    if (res != HCF_SUCCESS) {
        HcfObjDestroy(generator);
        return res;
    }
    res = keyPair->priKey->base.getEncoded(&(keyPair->priKey->base), &g_mockECC_BrainPool160r1PriKeyBlob);
    if (res != HCF_SUCCESS) {
        HcfObjDestroy(generator);
        HcfObjDestroy(keyPair);
        return res;
    }
    res = keyPair->pubKey->base.getEncoded(&(keyPair->pubKey->base), &g_mockECC_BrainPool160r1PubKeyBlob);
    if (res != HCF_SUCCESS) {
        HcfObjDestroy(generator);
        HcfObjDestroy(keyPair);
        return res;
    }
    HcfObjDestroy(generator);
    HcfObjDestroy(keyPair);
    return HCF_SUCCESS;
}

void CryptoEd25519AsyKeyGeneratorTest::SetUpTestCase()
{
    HcfResult res = Ed25519KeyBlob(&g_mockEd25519PriKeyBlob, &g_mockEd25519PubKeyBlob);
    ASSERT_EQ(res, HCF_SUCCESS);
    res = ECC_BrainPool160r1KeyBlob(&g_mockECC_BrainPool160r1PriKeyBlob, &g_mockECC_BrainPool160r1PubKeyBlob);
    ASSERT_EQ(res, HCF_SUCCESS);
}

HWTEST_F(CryptoEd25519AsyKeyGeneratorTest, CryptoEd25519AsyKeyGeneratorTest001, TestSize.Level0)
{
    HcfAsyKeyGenerator *generator = nullptr;
    HcfResult res = TestHcfAsyKeyGeneratorCreate(g_ed25519AlgoName.c_str(), &generator);
    ASSERT_EQ(res, HCF_SUCCESS);

    HcfObjDestroy(generator);
}

HWTEST_F(CryptoEd25519AsyKeyGeneratorTest, CryptoEd25519AsyKeyGeneratorTest002, TestSize.Level0)
{
    HcfAsyKeyGenerator *generator = nullptr;
    HcfResult res = HcfAsyKeyGeneratorCreate("Ed25519", &generator);

    const char *className = generator->base.getClass();

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(className, nullptr);

    HcfObjDestroy(generator);
}

HWTEST_F(CryptoEd25519AsyKeyGeneratorTest, CryptoEd25519AsyKeyGeneratorTest003, TestSize.Level0)
{
    HcfAsyKeyGenerator *generator = nullptr;
    HcfResult res = TestHcfAsyKeyGeneratorCreate(g_ed25519AlgoName.c_str(), &generator);
    ASSERT_EQ(res, HCF_SUCCESS);

    generator->base.destroy((HcfObjectBase *)generator);
}

HWTEST_F(CryptoEd25519AsyKeyGeneratorTest, CryptoEd25519AsyKeyGeneratorTest004, TestSize.Level0)
{
    HcfAsyKeyGenerator *generator = nullptr;
    HcfResult res = HcfAsyKeyGeneratorCreate("Ed25519", &generator);

    const char *algoName = generator->getAlgoName(generator);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_EQ(algoName, g_ed25519AlgoName);

    HcfObjDestroy(generator);
}

HWTEST_F(CryptoEd25519AsyKeyGeneratorTest, CryptoEd25519AsyKeyGeneratorTest005, TestSize.Level0)
{
    HcfAsyKeyGenerator *generator = nullptr;
    HcfKeyPair *keyPair = nullptr;
    HcfResult res = TestKeyGeneratorAndGenerateKeyPair(g_ed25519AlgoName.c_str(), &generator, &keyPair);
    ASSERT_EQ(res, HCF_SUCCESS);

    HcfObjDestroy(keyPair);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoEd25519AsyKeyGeneratorTest, CryptoEd25519AsyKeyGeneratorTest006, TestSize.Level0)
{
    HcfAsyKeyGenerator *generator = nullptr;
    HcfKeyPair *keyPair = nullptr;

    HcfResult res = TestKeyGeneratorAndGenerateKeyPair(g_ed25519AlgoName.c_str(), &generator, &keyPair);
    ASSERT_EQ(res, HCF_SUCCESS);

    const char *className = keyPair->base.getClass();
    ASSERT_NE(className, nullptr);

    HcfObjDestroy(keyPair);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoEd25519AsyKeyGeneratorTest, CryptoEd25519AsyKeyGeneratorTest007, TestSize.Level0)
{
    HcfAsyKeyGenerator *generator = nullptr;
    HcfKeyPair *keyPair = nullptr;
    HcfResult res = TestKeyGeneratorAndGenerateKeyPair(g_ed25519AlgoName.c_str(), &generator, &keyPair);
    ASSERT_EQ(res, HCF_SUCCESS);

    keyPair->base.destroy(&(keyPair->base));

    HcfObjDestroy(generator);
}

HWTEST_F(CryptoEd25519AsyKeyGeneratorTest, CryptoEd25519AsyKeyGeneratorTest008, TestSize.Level0)
{
    HcfAsyKeyGenerator *generator = nullptr;
    HcfKeyPair *keyPair = nullptr;

    HcfResult res = TestKeyGeneratorAndGenerateKeyPair(g_ed25519AlgoName.c_str(), &generator, &keyPair);
    ASSERT_EQ(res, HCF_SUCCESS);

    const char *className = keyPair->pubKey->base.base.getClass();
    ASSERT_NE(className, nullptr);

    HcfObjDestroy(keyPair);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoEd25519AsyKeyGeneratorTest, CryptoEd25519AsyKeyGeneratorTest009, TestSize.Level0)
{
    HcfAsyKeyGenerator *generator = nullptr;
    HcfKeyPair *keyPair = nullptr;
    HcfResult res = TestKeyGeneratorAndGenerateKeyPair(g_ed25519AlgoName.c_str(), &generator, &keyPair);
    ASSERT_EQ(res, HCF_SUCCESS);

    keyPair->pubKey->base.base.destroy(&(keyPair->pubKey->base.base));
    keyPair->pubKey = nullptr;

    HcfObjDestroy(keyPair);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoEd25519AsyKeyGeneratorTest, CryptoEd25519AsyKeyGeneratorTest010, TestSize.Level0)
{
    HcfAsyKeyGenerator *generator = nullptr;
    HcfKeyPair *keyPair = nullptr;

    HcfResult res = TestKeyGeneratorAndGenerateKeyPair(g_ed25519AlgoName.c_str(), &generator, &keyPair);
    ASSERT_EQ(res, HCF_SUCCESS);

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

    HcfBigInteger returnBigInteger = { .data = nullptr, .len = 0 };
    res = keyPair->pubKey->getAsyKeySpecBigInteger(keyPair->pubKey, ED25519_PK_BN, &returnBigInteger);
    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(returnBigInteger.data, nullptr);
    ASSERT_NE(returnBigInteger.len, 0);
    HcfFree(returnBigInteger.data);
    HcfObjDestroy(keyPair);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoEd25519AsyKeyGeneratorTest, CryptoEd25519AsyKeyGeneratorTest011, TestSize.Level0)
{
    HcfAsyKeyGenerator *generator = nullptr;
    HcfKeyPair *keyPair = nullptr;
    HcfResult res = TestKeyGeneratorAndGenerateKeyPair(g_ed25519AlgoName.c_str(), &generator, &keyPair);
    ASSERT_EQ(res, HCF_SUCCESS);

    const char *className = keyPair->priKey->base.base.getClass();
    ASSERT_NE(className, nullptr);

    HcfObjDestroy(keyPair);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoEd25519AsyKeyGeneratorTest, CryptoEd25519AsyKeyGeneratorTest012, TestSize.Level0)
{
    HcfAsyKeyGenerator *generator = nullptr;
    HcfKeyPair *keyPair = nullptr;

    HcfResult res = TestKeyGeneratorAndGenerateKeyPair(g_ed25519AlgoName.c_str(), &generator, &keyPair);
    ASSERT_EQ(res, HCF_SUCCESS);

    keyPair->priKey->base.base.destroy(&(keyPair->priKey->base.base));
    keyPair->priKey = nullptr;
    HcfObjDestroy(keyPair);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoEd25519AsyKeyGeneratorTest, CryptoEd25519AsyKeyGeneratorTest013, TestSize.Level0)
{
    HcfAsyKeyGenerator *generator = nullptr;
    HcfKeyPair *keyPair = nullptr;
    HcfResult res = TestKeyGeneratorAndGenerateKeyPair(g_ed25519AlgoName.c_str(), &generator, &keyPair);
    ASSERT_EQ(res, HCF_SUCCESS);

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

    HcfBigInteger returnBigInteger = { .data = nullptr, .len = 0 };
    res = keyPair->priKey->getAsyKeySpecBigInteger(keyPair->priKey, ED25519_SK_BN, &returnBigInteger);
    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(returnBigInteger.data, nullptr);
    ASSERT_NE(returnBigInteger.len, 0);
    HcfFree(returnBigInteger.data);
    HcfObjDestroy(keyPair);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoEd25519AsyKeyGeneratorTest, CryptoEd25519AsyKeyGeneratorTest014, TestSize.Level0)
{
    HcfAsyKeyGenerator *generator = nullptr;
    HcfKeyPair *keyPair = nullptr;

    HcfResult res = TestKeyGeneratorAndGenerateKeyPair(g_ed25519AlgoName.c_str(), &generator, &keyPair);
    ASSERT_EQ(res, HCF_SUCCESS);

    keyPair->priKey->clearMem(keyPair->priKey);
    HcfBlob blob = { .data = nullptr, .len = 0 };
    res = keyPair->priKey->base.getEncoded(&(keyPair->priKey->base), &blob);
    ASSERT_EQ(res, HCF_INVALID_PARAMS);
    ASSERT_EQ(blob.data, nullptr);
    ASSERT_EQ(blob.len, 0);
    HcfFree(blob.data);
    HcfObjDestroy(keyPair);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoEd25519AsyKeyGeneratorTest, CryptoEd25519AsyKeyGeneratorTest015, TestSize.Level0)
{
    HcfAsyKeyGenerator *generator = nullptr;
    HcfKeyPair *keyPair = nullptr;
    HcfResult res = TestGenerateKeyPairAndConvertKey(g_ed25519AlgoName.c_str(), &generator, &g_mockEd25519PubKeyBlob,
        &g_mockEd25519PriKeyBlob, &keyPair);
    ASSERT_EQ(res, HCF_SUCCESS);
    HcfObjDestroy(keyPair);

    res = TestGenerateConvertKey(generator, nullptr, &g_mockEd25519PriKeyBlob, &keyPair);
    ASSERT_EQ(res, HCF_SUCCESS);
    HcfObjDestroy(keyPair);

    res = TestGenerateConvertKey(generator, &g_mockEd25519PubKeyBlob, nullptr, &keyPair);
    ASSERT_EQ(res, HCF_SUCCESS);

    HcfObjDestroy(keyPair);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoEd25519AsyKeyGeneratorTest, CryptoEd25519AsyKeyGeneratorTest016, TestSize.Level0)
{
    HcfAsyKeyGenerator *generator = nullptr;
    HcfKeyPair *keyPair = nullptr;

    HcfResult res = TestGenerateKeyPairAndConvertKey(g_ed25519AlgoName.c_str(), &generator, &g_mockEd25519PubKeyBlob,
        &g_mockEd25519PriKeyBlob, &keyPair);
    ASSERT_EQ(res, HCF_SUCCESS);

    const char *className = keyPair->base.getClass();
    ASSERT_NE(className, nullptr);

    HcfObjDestroy(keyPair);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoEd25519AsyKeyGeneratorTest, CryptoEd25519AsyKeyGeneratorTest017, TestSize.Level0)
{
    HcfAsyKeyGenerator *generator = nullptr;
    HcfKeyPair *keyPair = nullptr;
    HcfResult res = TestGenerateKeyPairAndConvertKey(g_ed25519AlgoName.c_str(), &generator, &g_mockEd25519PubKeyBlob,
        &g_mockEd25519PriKeyBlob, &keyPair);
    ASSERT_EQ(res, HCF_SUCCESS);

    keyPair->base.destroy(&(keyPair->base));

    HcfObjDestroy(generator);
}

HWTEST_F(CryptoEd25519AsyKeyGeneratorTest, CryptoEd25519AsyKeyGeneratorTest018, TestSize.Level0)
{
    HcfAsyKeyGenerator *generator = nullptr;
    HcfKeyPair *keyPair = nullptr;

    HcfResult res = TestGenerateKeyPairAndConvertKey(g_ed25519AlgoName.c_str(), &generator, &g_mockEd25519PubKeyBlob,
        &g_mockEd25519PriKeyBlob, &keyPair);
    ASSERT_EQ(res, HCF_SUCCESS);

    const char *className = keyPair->pubKey->base.base.getClass();
    ASSERT_NE(className, nullptr);

    HcfObjDestroy(keyPair);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoEd25519AsyKeyGeneratorTest, CryptoEd25519AsyKeyGeneratorTest019, TestSize.Level0)
{
    HcfAsyKeyGenerator *generator = nullptr;
    HcfKeyPair *keyPair = nullptr;
    HcfResult res = TestGenerateKeyPairAndConvertKey(g_ed25519AlgoName.c_str(), &generator, &g_mockEd25519PubKeyBlob,
        &g_mockEd25519PriKeyBlob, &keyPair);
    ASSERT_EQ(res, HCF_SUCCESS);

    keyPair->pubKey->base.base.destroy(&(keyPair->pubKey->base.base));
    keyPair->pubKey = nullptr;

    HcfObjDestroy(keyPair);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoEd25519AsyKeyGeneratorTest, CryptoEd25519AsyKeyGeneratorTest020, TestSize.Level0)
{
    HcfAsyKeyGenerator *generator = nullptr;
    HcfKeyPair *keyPair = nullptr;

    HcfResult res = TestGenerateKeyPairAndConvertKey(g_ed25519AlgoName.c_str(), &generator, &g_mockEd25519PubKeyBlob,
        &g_mockEd25519PriKeyBlob, &keyPair);
    ASSERT_EQ(res, HCF_SUCCESS);

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

    HcfBigInteger returnBigInteger = { .data = nullptr, .len = 0 };
    res = keyPair->pubKey->getAsyKeySpecBigInteger(keyPair->pubKey, ED25519_PK_BN, &returnBigInteger);
    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(returnBigInteger.data, nullptr);
    ASSERT_NE(returnBigInteger.len, 0);
    HcfFree(returnBigInteger.data);
    HcfObjDestroy(keyPair);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoEd25519AsyKeyGeneratorTest, CryptoEd25519AsyKeyGeneratorTest021, TestSize.Level0)
{
    HcfAsyKeyGenerator *generator = nullptr;
    HcfKeyPair *keyPair = nullptr;
    HcfResult res = TestGenerateKeyPairAndConvertKey(g_ed25519AlgoName.c_str(), &generator, &g_mockEd25519PubKeyBlob,
        &g_mockEd25519PriKeyBlob, &keyPair);
    ASSERT_EQ(res, HCF_SUCCESS);

    const char *className = keyPair->priKey->base.base.getClass();
    ASSERT_NE(className, nullptr);

    HcfObjDestroy(keyPair);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoEd25519AsyKeyGeneratorTest, CryptoEd25519AsyKeyGeneratorTest022, TestSize.Level0)
{
    HcfAsyKeyGenerator *generator = nullptr;
    HcfKeyPair *keyPair = nullptr;

    HcfResult res = TestGenerateKeyPairAndConvertKey(g_ed25519AlgoName.c_str(), &generator, &g_mockEd25519PubKeyBlob,
        &g_mockEd25519PriKeyBlob, &keyPair);
    ASSERT_EQ(res, HCF_SUCCESS);

    keyPair->priKey->base.base.destroy(&(keyPair->priKey->base.base));
    keyPair->priKey = nullptr;
    HcfObjDestroy(keyPair);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoEd25519AsyKeyGeneratorTest, CryptoEd25519AsyKeyGeneratorTest023, TestSize.Level0)
{
    HcfAsyKeyGenerator *generator = nullptr;
    HcfKeyPair *keyPair = nullptr;
    HcfResult res = TestGenerateKeyPairAndConvertKey(g_ed25519AlgoName.c_str(), &generator, &g_mockEd25519PubKeyBlob,
        &g_mockEd25519PriKeyBlob, &keyPair);
    ASSERT_EQ(res, HCF_SUCCESS);

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

    HcfBigInteger returnBigInteger = { .data = nullptr, .len = 0 };
    res = keyPair->priKey->getAsyKeySpecBigInteger(keyPair->priKey, ED25519_SK_BN, &returnBigInteger);
    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(returnBigInteger.data, nullptr);
    ASSERT_NE(returnBigInteger.len, 0);
    HcfFree(returnBigInteger.data);
    HcfObjDestroy(keyPair);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoEd25519AsyKeyGeneratorTest, CryptoEd25519AsyKeyGeneratorTest024, TestSize.Level0)
{
    HcfAsyKeyGenerator *generator = nullptr;
    HcfKeyPair *keyPair = nullptr;

    HcfResult res = TestGenerateKeyPairAndConvertKey(g_ed25519AlgoName.c_str(), &generator, &g_mockEd25519PubKeyBlob,
        &g_mockEd25519PriKeyBlob, &keyPair);
    ASSERT_EQ(res, HCF_SUCCESS);

    keyPair->priKey->clearMem(keyPair->priKey);
    HcfBlob blob = { .data = nullptr, .len = 0 };
    res = keyPair->priKey->base.getEncoded(&(keyPair->priKey->base), &blob);
    ASSERT_EQ(res, HCF_INVALID_PARAMS);
    ASSERT_EQ(blob.data, nullptr);
    ASSERT_EQ(blob.len, 0);
    HcfFree(blob.data);
    HcfObjDestroy(keyPair);
    HcfObjDestroy(generator);
}

static void MemoryMallocTestFunc(uint32_t mallocCount)
{
    for (uint32_t i = 0; i < mallocCount; i++) {
        ResetRecordMallocNum();
        SetMockMallocIndex(i);
        HcfAsyKeyGenerator *tmpGenerator = nullptr;
        HcfResult res = HcfAsyKeyGeneratorCreate("Ed25519", &tmpGenerator);
        if (res != HCF_SUCCESS) {
            continue;
        }
        HcfKeyPair *tmpKeyPair = nullptr;
        res = tmpGenerator->generateKeyPair(tmpGenerator, nullptr, &tmpKeyPair);
        if (res != HCF_SUCCESS) {
            HcfObjDestroy(tmpGenerator);
            continue;
        }
        HcfBlob tmpPubKeyBlob = {
            .data = nullptr,
            .len = 0
        };
        res = tmpKeyPair->pubKey->base.getEncoded(&(tmpKeyPair->pubKey->base), &tmpPubKeyBlob);
        if (res != HCF_SUCCESS) {
            HcfObjDestroy(tmpKeyPair);
            HcfObjDestroy(tmpGenerator);
            continue;
        }
        HcfBlob tmpPriKeyBlob = {
            .data = nullptr,
            .len = 0
        };
        res = tmpKeyPair->priKey->base.getEncoded(&(tmpKeyPair->priKey->base), &tmpPriKeyBlob);
        if (res != HCF_SUCCESS) {
            HcfFree(tmpPubKeyBlob.data);
            HcfObjDestroy(tmpKeyPair);
            HcfObjDestroy(tmpGenerator);
            continue;
        }
        HcfKeyPair *tmpOutKeyPair = nullptr;
        res = tmpGenerator->convertKey(tmpGenerator, nullptr, &tmpPubKeyBlob, &tmpPriKeyBlob, &tmpOutKeyPair);
        HcfFree(tmpPubKeyBlob.data);
        HcfFree(tmpPriKeyBlob.data);
        HcfObjDestroy(tmpKeyPair);
        HcfObjDestroy(tmpGenerator);
        if (res == HCF_SUCCESS) {
            HcfObjDestroy(tmpOutKeyPair);
        }
    }
}

HWTEST_F(CryptoEd25519AsyKeyGeneratorTest, CryptoEd25519AsyKeyGeneratorTest025, TestSize.Level0)
{
    StartRecordMallocNum();
    HcfAsyKeyGenerator *generator = nullptr;
    HcfResult res = HcfAsyKeyGeneratorCreate("Ed25519", &generator);

    HcfKeyPair *keyPair = nullptr;
    res = generator->generateKeyPair(generator, nullptr, &keyPair);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(keyPair, nullptr);

    HcfBlob pubKeyBlob = { .data = nullptr, .len = 0 };
    res = keyPair->pubKey->base.getEncoded(&(keyPair->pubKey->base), &pubKeyBlob);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(pubKeyBlob.data, nullptr);
    ASSERT_NE(pubKeyBlob.len, 0);

    HcfBlob priKeyBlob = { .data = nullptr, .len = 0 };
    res = keyPair->priKey->base.getEncoded(&(keyPair->priKey->base), &priKeyBlob);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(priKeyBlob.data, nullptr);
    ASSERT_NE(priKeyBlob.len, 0);

    HcfKeyPair *outKeyPair = nullptr;
    res = generator->convertKey(generator, nullptr, &pubKeyBlob, &priKeyBlob, &outKeyPair);

    HcfFree(pubKeyBlob.data);
    HcfFree(priKeyBlob.data);
    HcfObjDestroy(outKeyPair);
    HcfObjDestroy(keyPair);
    HcfObjDestroy(generator);

    uint32_t mallocCount = GetMallocNum();
    MemoryMallocTestFunc(mallocCount);

    EndRecordMallocNum();
}

static void OpensslMockTestFunc(uint32_t mallocCount)
{
    for (uint32_t i = 0; i < mallocCount; i++) {
        ResetOpensslCallNum();
        SetOpensslCallMockIndex(i);
        HcfAsyKeyGenerator *tmpGenerator = nullptr;
        HcfResult res = HcfAsyKeyGeneratorCreate("Ed25519", &tmpGenerator);
        if (res != HCF_SUCCESS) {
            continue;
        }
        HcfKeyPair *tmpKeyPair = nullptr;
        res = tmpGenerator->generateKeyPair(tmpGenerator, nullptr, &tmpKeyPair);
        if (res != HCF_SUCCESS) {
            HcfObjDestroy(tmpGenerator);
            continue;
        }
        HcfBlob tmpPubKeyBlob = {
            .data = nullptr,
            .len = 0
        };
        res = tmpKeyPair->pubKey->base.getEncoded(&(tmpKeyPair->pubKey->base), &tmpPubKeyBlob);
        if (res != HCF_SUCCESS) {
            HcfObjDestroy(tmpKeyPair);
            HcfObjDestroy(tmpGenerator);
            continue;
        }
        HcfBlob tmpPriKeyBlob = {
            .data = nullptr,
            .len = 0
        };
        res = tmpKeyPair->priKey->base.getEncoded(&(tmpKeyPair->priKey->base), &tmpPriKeyBlob);
        if (res != HCF_SUCCESS) {
            HcfFree(tmpPubKeyBlob.data);
            HcfObjDestroy(tmpKeyPair);
            HcfObjDestroy(tmpGenerator);
            continue;
        }
        HcfKeyPair *tmpOutKeyPair = nullptr;
        res = tmpGenerator->convertKey(tmpGenerator, nullptr, &tmpPubKeyBlob, &tmpPriKeyBlob, &tmpOutKeyPair);
        HcfFree(tmpPubKeyBlob.data);
        HcfFree(tmpPriKeyBlob.data);
        HcfObjDestroy(tmpKeyPair);
        HcfObjDestroy(tmpGenerator);
        if (res == HCF_SUCCESS) {
            HcfObjDestroy(tmpOutKeyPair);
        }
    }
}

HWTEST_F(CryptoEd25519AsyKeyGeneratorTest, CryptoEd25519AsyKeyGeneratorTest026, TestSize.Level0)
{
    StartRecordOpensslCallNum();
    HcfAsyKeyGenerator *generator = nullptr;
    HcfKeyPair *keyPair = nullptr;
    HcfResult res = TestKeyGeneratorAndGenerateKeyPair(g_ed25519AlgoName.c_str(), &generator, &keyPair);
    ASSERT_EQ(res, HCF_SUCCESS);

    HcfBlob pubKeyBlob = { .data = nullptr, .len = 0 };
    res = keyPair->pubKey->base.getEncoded(&(keyPair->pubKey->base), &pubKeyBlob);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(pubKeyBlob.data, nullptr);
    ASSERT_NE(pubKeyBlob.len, 0);

    HcfBlob priKeyBlob = { .data = nullptr, .len = 0 };
    res = keyPair->priKey->base.getEncoded(&(keyPair->priKey->base), &priKeyBlob);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(priKeyBlob.data, nullptr);
    ASSERT_NE(priKeyBlob.len, 0);

    HcfKeyPair *outKeyPair = nullptr;
    res = generator->convertKey(generator, nullptr, &pubKeyBlob, &priKeyBlob, &outKeyPair);

    HcfFree(pubKeyBlob.data);
    HcfFree(priKeyBlob.data);
    HcfObjDestroy(outKeyPair);
    HcfObjDestroy(keyPair);
    HcfObjDestroy(generator);

    uint32_t mallocCount = GetOpensslCallNum();
    OpensslMockTestFunc(mallocCount);

    EndRecordOpensslCallNum();
}

HWTEST_F(CryptoEd25519AsyKeyGeneratorTest, CryptoEd25519AsyKeyGeneratorTest0027, TestSize.Level0)
{
    HcfAsyKeyGenerator *generator = nullptr;

    HcfResult res = HcfAsyKeyGeneratorCreate("ED25519", &generator);

    ASSERT_EQ(res, HCF_INVALID_PARAMS);
    ASSERT_EQ(generator, nullptr);

    res = HcfAsyKeyGeneratorCreate(nullptr, &generator);

    ASSERT_EQ(res, HCF_INVALID_PARAMS);
    ASSERT_EQ(generator, nullptr);

    HcfObjDestroy(generator);
}

HWTEST_F(CryptoEd25519AsyKeyGeneratorTest, CryptoEd25519AsyKeyGeneratorTest028, TestSize.Level0)
{
    HcfAsyKeyGenerator *generator = nullptr;
    HcfResult res = HcfAsyKeyGeneratorCreate("Ed25519", &generator);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(generator, nullptr);

    const char *algoName = generator->getAlgoName(nullptr);
    ASSERT_EQ(algoName, nullptr);

    const char *algoName1 = generator->getAlgoName((HcfAsyKeyGenerator *)&g_obj);
    ASSERT_EQ(algoName1, nullptr);

    HcfObjDestroy(generator);
}

HWTEST_F(CryptoEd25519AsyKeyGeneratorTest, CryptoEd25519AsyKeyGeneratorTest029, TestSize.Level0)
{
    HcfAsyKeyGenerator *generator = nullptr;
    HcfResult res = HcfAsyKeyGeneratorCreate("Ed25519", &generator);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(generator, nullptr);

    generator->base.destroy(nullptr);

    HcfObjDestroy(generator);
}

HWTEST_F(CryptoEd25519AsyKeyGeneratorTest, CryptoEd25519AsyKeyGeneratorTest030, TestSize.Level0)
{
    HcfAsyKeyGenerator *generator = nullptr;
    HcfResult res = HcfAsyKeyGeneratorCreate("Ed25519", &generator);
    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(generator, nullptr);

    generator->base.destroy(&g_obj);

    HcfObjDestroy(generator);
}

HWTEST_F(CryptoEd25519AsyKeyGeneratorTest, CryptoEd25519AsyKeyGeneratorTest031, TestSize.Level0)
{
    HcfAsyKeyGenerator *generator = nullptr;
    HcfKeyPair *keyPair = nullptr;
    HcfResult res = TestKeyGeneratorAndGenerateKeyPair(g_ed25519AlgoName.c_str(), &generator, &keyPair);
    ASSERT_EQ(res, HCF_SUCCESS);

    HcfKeyPair *failKeyPair = nullptr;
    res = generator->generateKeyPair((HcfAsyKeyGenerator *)&g_obj, nullptr, &failKeyPair);
    ASSERT_EQ(res, HCF_INVALID_PARAMS);
    ASSERT_EQ(failKeyPair, nullptr);

    res = generator->generateKeyPair(generator, nullptr, nullptr);
    ASSERT_EQ(res, HCF_INVALID_PARAMS);

    HcfObjDestroy(keyPair);
    HcfObjDestroy(failKeyPair);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoEd25519AsyKeyGeneratorTest, CryptoEd25519AsyKeyGeneratorTest032, TestSize.Level0)
{
    HcfAsyKeyGenerator *generator = nullptr;
    HcfKeyPair *keyPair = nullptr;
    HcfResult res = TestKeyGeneratorAndGenerateKeyPair(g_ed25519AlgoName.c_str(), &generator, &keyPair);
    ASSERT_EQ(res, HCF_SUCCESS);

    const char *algorithmName = keyPair->pubKey->base.getAlgorithm(nullptr);
    ASSERT_EQ(algorithmName, nullptr);

    const char *algorithmName1 = keyPair->pubKey->base.getAlgorithm((HcfKey *)&g_obj);
    ASSERT_EQ(algorithmName1, nullptr);

    HcfObjDestroy(keyPair);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoEd25519AsyKeyGeneratorTest, CryptoEd25519AsyKeyGeneratorTest033, TestSize.Level0)
{
    HcfAsyKeyGenerator *generator = nullptr;
    HcfKeyPair *keyPair = nullptr;
    HcfResult res = TestKeyGeneratorAndGenerateKeyPair(g_ed25519AlgoName.c_str(), &generator, &keyPair);
    ASSERT_EQ(res, HCF_SUCCESS);

    HcfBlob blob = { .data = nullptr, .len = 0 };
    res = keyPair->pubKey->base.getEncoded(nullptr, &blob);
    ASSERT_EQ(res, HCF_INVALID_PARAMS);
    ASSERT_EQ(blob.data, nullptr);
    ASSERT_EQ(blob.len, 0);

    res = keyPair->pubKey->base.getEncoded(&(keyPair->pubKey->base), nullptr);
    ASSERT_EQ(res, HCF_INVALID_PARAMS);

    res = keyPair->pubKey->base.getEncoded((HcfKey *)&g_obj, &blob);
    ASSERT_EQ(res, HCF_INVALID_PARAMS);
    ASSERT_EQ(blob.data, nullptr);
    ASSERT_EQ(blob.len, 0);

    HcfFree(blob.data);
    HcfObjDestroy(keyPair);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoEd25519AsyKeyGeneratorTest, CryptoEd25519AsyKeyGeneratorTest034, TestSize.Level0)
{
    HcfAsyKeyGenerator *generator = nullptr;
    HcfKeyPair *keyPair = nullptr;
    HcfResult res = TestGenerateKeyPairAndConvertKey(g_ed25519AlgoName.c_str(), &generator, &g_mockEd25519PubKeyBlob,
        &g_mockEd25519PriKeyBlob, &keyPair);
    ASSERT_EQ(res, HCF_SUCCESS);

    const char *formatName = keyPair->pubKey->base.getFormat(nullptr);
    ASSERT_EQ(formatName, nullptr);

    const char *formatName1 = keyPair->pubKey->base.getFormat((HcfKey *)&g_obj);
    ASSERT_EQ(formatName1, nullptr);

    HcfObjDestroy(keyPair);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoEd25519AsyKeyGeneratorTest, CryptoEd25519AsyKeyGeneratorTest035, TestSize.Level0)
{
    HcfAsyKeyGenerator *generator = nullptr;
    HcfKeyPair *keyPair = nullptr;
    HcfResult res = TestKeyGeneratorAndGenerateKeyPair(g_ed25519AlgoName.c_str(), &generator, &keyPair);
    ASSERT_EQ(res, HCF_SUCCESS);

    HcfBigInteger returnBigInteger = { .data = nullptr, .len = 0 };
    res = keyPair->pubKey->getAsyKeySpecBigInteger(keyPair->pubKey, ED25519_SK_BN, nullptr);
    ASSERT_EQ(res, HCF_INVALID_PARAMS);
    ASSERT_EQ(returnBigInteger.data, nullptr);
    ASSERT_EQ(returnBigInteger.len, 0);

    res = keyPair->pubKey->getAsyKeySpecBigInteger(keyPair->pubKey, DSA_P_BN, &returnBigInteger);
    ASSERT_EQ(res, HCF_INVALID_PARAMS);
    ASSERT_EQ(returnBigInteger.data, nullptr);
    ASSERT_EQ(returnBigInteger.len, 0);

    res = keyPair->pubKey->getAsyKeySpecInt(keyPair->pubKey, ED25519_PK_BN, nullptr);
    ASSERT_EQ(res, HCF_NOT_SUPPORT);

    res = keyPair->pubKey->getAsyKeySpecString(keyPair->pubKey, ED25519_PK_BN, nullptr);
    ASSERT_EQ(res, HCF_NOT_SUPPORT);

    HcfFree(returnBigInteger.data);
    HcfObjDestroy(keyPair);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoEd25519AsyKeyGeneratorTest, CryptoEd25519AsyKeyGeneratorTest036, TestSize.Level0)
{
    HcfAsyKeyGenerator *generator = nullptr;
    HcfKeyPair *keyPair = nullptr;
    HcfResult res = TestKeyGeneratorAndGenerateKeyPair(g_ed25519AlgoName.c_str(), &generator, &keyPair);
    ASSERT_EQ(res, HCF_SUCCESS);

    const char *algorithmName = keyPair->priKey->base.getAlgorithm(nullptr);
    ASSERT_EQ(algorithmName, nullptr);

    const char *algorithmName1 = keyPair->priKey->base.getAlgorithm((HcfKey *)&g_obj);
    ASSERT_EQ(algorithmName1, nullptr);

    HcfObjDestroy(keyPair);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoEd25519AsyKeyGeneratorTest, CryptoEd25519AsyKeyGeneratorTest037, TestSize.Level0)
{
    HcfAsyKeyGenerator *generator = nullptr;
    HcfKeyPair *keyPair = nullptr;

    HcfResult res = TestKeyGeneratorAndGenerateKeyPair(g_ed25519AlgoName.c_str(), &generator, &keyPair);
    ASSERT_EQ(res, HCF_SUCCESS);

    HcfBlob blob = { .data = nullptr, .len = 0 };
    res = keyPair->priKey->base.getEncoded(nullptr, &blob);
    ASSERT_EQ(res, HCF_INVALID_PARAMS);
    ASSERT_EQ(blob.data, nullptr);
    ASSERT_EQ(blob.len, 0);

    res = keyPair->priKey->base.getEncoded(&(keyPair->priKey->base), nullptr);
    ASSERT_EQ(res, HCF_INVALID_PARAMS);

    res = keyPair->priKey->base.getEncoded((HcfKey *)&g_obj, &blob);
    ASSERT_EQ(res, HCF_INVALID_PARAMS);
    ASSERT_EQ(blob.data, nullptr);
    ASSERT_EQ(blob.len, 0);

    HcfFree(blob.data);
    HcfObjDestroy(keyPair);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoEd25519AsyKeyGeneratorTest, CryptoEd25519AsyKeyGeneratorTest038, TestSize.Level0)
{
    HcfAsyKeyGenerator *generator = nullptr;
    HcfKeyPair *keyPair = nullptr;

    HcfResult res = TestGenerateKeyPairAndConvertKey(g_ed25519AlgoName.c_str(), &generator, &g_mockEd25519PubKeyBlob,
        &g_mockEd25519PriKeyBlob, &keyPair);
    ASSERT_EQ(res, HCF_SUCCESS);

    const char *formatName = formatName = keyPair->priKey->base.getFormat(nullptr);
    ASSERT_EQ(formatName, nullptr);

    const char *formatName1 = keyPair->priKey->base.getFormat((HcfKey *)&g_obj);
    ASSERT_EQ(formatName1, nullptr);

    HcfObjDestroy(keyPair);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoEd25519AsyKeyGeneratorTest, CryptoEd25519AsyKeyGeneratorTest039, TestSize.Level0)
{
    HcfAsyKeyGenerator *generator = nullptr;
    HcfKeyPair *keyPair = nullptr;

    HcfResult res = TestKeyGeneratorAndGenerateKeyPair(g_ed25519AlgoName.c_str(), &generator, &keyPair);
    ASSERT_EQ(res, HCF_SUCCESS);

    res = keyPair->priKey->getAsyKeySpecBigInteger(keyPair->priKey, ED25519_PK_BN, nullptr);
    ASSERT_EQ(res, HCF_INVALID_PARAMS);
    HcfBigInteger returnBigInteger = { .data = nullptr, .len = 0 };
    res = keyPair->priKey->getAsyKeySpecBigInteger(keyPair->priKey, DSA_P_BN, &returnBigInteger);
    ASSERT_EQ(res, HCF_INVALID_PARAMS);
    ASSERT_EQ(returnBigInteger.data, nullptr);
    ASSERT_EQ(returnBigInteger.len, 0);
    HcfFree(returnBigInteger.data);
    res = keyPair->priKey->getAsyKeySpecInt(keyPair->priKey, ED25519_SK_BN, nullptr);
    ASSERT_EQ(res, HCF_NOT_SUPPORT);

    res = keyPair->priKey->getAsyKeySpecString(keyPair->priKey, ED25519_SK_BN, nullptr);
    ASSERT_EQ(res, HCF_NOT_SUPPORT);

    HcfObjDestroy(keyPair);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoEd25519AsyKeyGeneratorTest, CryptoEd25519AsyKeyGeneratorTest040, TestSize.Level0)
{
    HcfAsyKeyGenerator *generator = nullptr;
    HcfKeyPair *keyPair = nullptr;
    HcfResult res = TestGenerateKeyPairAndConvertKey(g_ed25519AlgoName.c_str(), &generator, &g_mockEd25519PubKeyBlob,
        &g_mockEd25519PriKeyBlob, &keyPair);
    ASSERT_EQ(res, HCF_SUCCESS);

    res = generator->convertKey(generator, nullptr, &g_mockEd25519PubKeyBlob, &g_mockEd25519PriKeyBlob, nullptr);
    ASSERT_EQ(res, HCF_INVALID_PARAMS);

    HcfKeyPair *failKeyPair = nullptr;
    res = generator->convertKey((HcfAsyKeyGenerator *)&g_obj, nullptr, &g_mockEd25519PubKeyBlob,
        &g_mockEd25519PriKeyBlob, &failKeyPair);
    ASSERT_EQ(res, HCF_INVALID_PARAMS);
    ASSERT_EQ(failKeyPair, nullptr);

    res = generator->convertKey(generator, nullptr, nullptr, nullptr, &failKeyPair);
    ASSERT_EQ(res, HCF_INVALID_PARAMS);
    ASSERT_EQ(failKeyPair, nullptr);

    res = generator->convertKey(generator, nullptr, &g_mockECC_BrainPool160r1PubKeyBlob,
        &g_mockECC_BrainPool160r1PriKeyBlob, &failKeyPair);
    ASSERT_EQ(res, HCF_ERR_CRYPTO_OPERATION);
    ASSERT_EQ(failKeyPair, nullptr);

    HcfObjDestroy(keyPair);
    HcfObjDestroy(failKeyPair);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoEd25519AsyKeyGeneratorTest, CryptoEd25519AsyKeyGeneratorTest041, TestSize.Level0)
{
    HcfAsyKeyGenerator *generator = nullptr;
    HcfKeyPair *keyPair = nullptr;

    HcfResult res = TestGenerateKeyPairAndConvertKey(g_ed25519AlgoName.c_str(), &generator, &g_mockEd25519PubKeyBlob,
        &g_mockEd25519PriKeyBlob, &keyPair);
    ASSERT_EQ(res, HCF_SUCCESS);

    const char *algorithmName = keyPair->pubKey->base.getAlgorithm(nullptr);
    ASSERT_EQ(algorithmName, nullptr);

    const char *algorithmName1 = keyPair->pubKey->base.getAlgorithm((HcfKey *)&g_obj);
    ASSERT_EQ(algorithmName1, nullptr);

    HcfObjDestroy(keyPair);
    HcfObjDestroy(generator);
}


HWTEST_F(CryptoEd25519AsyKeyGeneratorTest, CryptoEd25519AsyKeyGeneratorTest042, TestSize.Level0)
{
    HcfAsyKeyGenerator *generator = nullptr;
    HcfKeyPair *keyPair = nullptr;
    HcfResult res = TestGenerateKeyPairAndConvertKey(g_ed25519AlgoName.c_str(), &generator, &g_mockEd25519PubKeyBlob,
        &g_mockEd25519PriKeyBlob, &keyPair);
    ASSERT_EQ(res, HCF_SUCCESS);

    HcfBlob blob = { .data = nullptr, .len = 0 };
    res = keyPair->pubKey->base.getEncoded(nullptr, &blob);
    ASSERT_EQ(res, HCF_INVALID_PARAMS);
    ASSERT_EQ(blob.data, nullptr);
    ASSERT_EQ(blob.len, 0);

    res = keyPair->pubKey->base.getEncoded(&(keyPair->pubKey->base), nullptr);
    ASSERT_EQ(res, HCF_INVALID_PARAMS);

    res = keyPair->pubKey->base.getEncoded((HcfKey *)&g_obj, &blob);
    ASSERT_EQ(res, HCF_INVALID_PARAMS);
    ASSERT_EQ(blob.data, nullptr);
    ASSERT_EQ(blob.len, 0);
    HcfFree(blob.data);
    HcfObjDestroy(keyPair);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoEd25519AsyKeyGeneratorTest, CryptoEd25519AsyKeyGeneratorTest043, TestSize.Level0)
{
    HcfAsyKeyGenerator *generator = nullptr;
    HcfKeyPair *keyPair = nullptr;

    HcfResult res = TestGenerateKeyPairAndConvertKey(g_ed25519AlgoName.c_str(), &generator, &g_mockEd25519PubKeyBlob,
        &g_mockEd25519PriKeyBlob, &keyPair);
    ASSERT_EQ(res, HCF_SUCCESS);

    const char *formatName = formatName = keyPair->pubKey->base.getFormat(nullptr);
    ASSERT_EQ(formatName, nullptr);

    const char *formatName1 = keyPair->pubKey->base.getFormat((HcfKey *)&g_obj);
    ASSERT_EQ(formatName1, nullptr);

    HcfObjDestroy(keyPair);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoEd25519AsyKeyGeneratorTest, CryptoEd25519AsyKeyGeneratorTest044, TestSize.Level0)
{
    HcfAsyKeyGenerator *generator = nullptr;
    HcfKeyPair *keyPair = nullptr;
    HcfResult res = TestGenerateKeyPairAndConvertKey(g_ed25519AlgoName.c_str(), &generator, &g_mockEd25519PubKeyBlob,
        &g_mockEd25519PriKeyBlob, &keyPair);
    ASSERT_EQ(res, HCF_SUCCESS);

    const char *algorithmName = keyPair->priKey->base.getAlgorithm(nullptr);
    ASSERT_EQ(algorithmName, nullptr);

    const char *algorithmName1 = keyPair->priKey->base.getAlgorithm((HcfKey *)&g_obj);
    ASSERT_EQ(algorithmName1, nullptr);

    HcfObjDestroy(keyPair);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoEd25519AsyKeyGeneratorTest, CryptoEd25519AsyKeyGeneratorTest045, TestSize.Level0)
{
    HcfAsyKeyGenerator *generator = nullptr;
    HcfKeyPair *keyPair = nullptr;

    HcfResult res = TestGenerateKeyPairAndConvertKey(g_ed25519AlgoName.c_str(), &generator, &g_mockEd25519PubKeyBlob,
        &g_mockEd25519PriKeyBlob, &keyPair);
    ASSERT_EQ(res, HCF_SUCCESS);

    HcfBlob blob = { .data = nullptr, .len = 0 };
    res = keyPair->priKey->base.getEncoded(nullptr, &blob);
    ASSERT_EQ(res, HCF_INVALID_PARAMS);
    ASSERT_EQ(blob.data, nullptr);
    ASSERT_EQ(blob.len, 0);

    res = keyPair->priKey->base.getEncoded(&(keyPair->priKey->base), nullptr);
    ASSERT_EQ(res, HCF_INVALID_PARAMS);

    res = keyPair->priKey->base.getEncoded((HcfKey *)&g_obj, &blob);
    ASSERT_EQ(res, HCF_INVALID_PARAMS);
    ASSERT_EQ(blob.data, nullptr);
    ASSERT_EQ(blob.len, 0);

    HcfFree(blob.data);
    HcfObjDestroy(keyPair);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoEd25519AsyKeyGeneratorTest, CryptoEd25519AsyKeyGeneratorTest046, TestSize.Level0)
{
    HcfAsyKeyGenerator *generator = nullptr;
    HcfKeyPair *keyPair = nullptr;
    HcfResult res = TestGenerateKeyPairAndConvertKey(g_ed25519AlgoName.c_str(), &generator, &g_mockEd25519PubKeyBlob,
        &g_mockEd25519PriKeyBlob, &keyPair);
    ASSERT_EQ(res, HCF_SUCCESS);

    const char *formatName = formatName = keyPair->priKey->base.getFormat(nullptr);
    ASSERT_EQ(formatName, nullptr);

    const char *formatName1 = keyPair->priKey->base.getFormat((HcfKey *)&g_obj);
    ASSERT_EQ(formatName1, nullptr);

    HcfObjDestroy(keyPair);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoEd25519AsyKeyGeneratorTest, CryptoEd25519AsyKeyGeneratorTest047, TestSize.Level0)
{
    HcfAsyKeyGenerator *generator = nullptr;
    HcfKeyPair *keyPair = nullptr;

    HcfResult res = TestGenerateKeyPairAndConvertKey(g_ed25519AlgoName.c_str(), &generator, &g_mockEd25519PubKeyBlob,
        &g_mockEd25519PriKeyBlob, &keyPair);
    ASSERT_EQ(res, HCF_SUCCESS);

    keyPair->priKey->clearMem(nullptr);
    HcfBlob blob = { .data = nullptr, .len = 0 };
    res = keyPair->priKey->base.getEncoded(&(keyPair->priKey->base), &blob);
    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(blob.data, nullptr);
    ASSERT_NE(blob.len, 0);
    HcfFree(blob.data);
    HcfObjDestroy(keyPair);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoEd25519AsyKeyGeneratorTest, CryptoEd25519AsyKeyGeneratorTest048, TestSize.Level0)
{
    HcfAsyKeyGenerator *generator = nullptr;
    HcfKeyPair *keyPair = nullptr;
    HcfResult res = TestGenerateKeyPairAndConvertKey(g_ed25519AlgoName.c_str(), &generator, &g_mockEd25519PubKeyBlob,
        &g_mockEd25519PriKeyBlob, &keyPair);
    ASSERT_EQ(res, HCF_SUCCESS);

    keyPair->priKey->clearMem((HcfPriKey *)&g_obj);
    HcfBlob blob = { .data = nullptr, .len = 0 };
    res = keyPair->priKey->base.getEncoded(&(keyPair->priKey->base), &blob);
    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(blob.data, nullptr);
    ASSERT_NE(blob.len, 0);
    HcfFree(blob.data);
    HcfObjDestroy(keyPair);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoEd25519AsyKeyGeneratorTest, CryptoEd25519AsyKeyGeneratorTest049, TestSize.Level0)
{
    HcfAsyKeyGenerator *generator = nullptr;
    HcfKeyPair *keyPair = nullptr;

    HcfResult res = TestKeyGeneratorAndGenerateKeyPair(g_ed25519AlgoName.c_str(), &generator, &keyPair);
    ASSERT_EQ(res, HCF_SUCCESS);

    keyPair->pubKey->base.base.destroy(nullptr);
    HcfObjDestroy(keyPair);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoEd25519AsyKeyGeneratorTest, CryptoEd25519AsyKeyGeneratorTest050, TestSize.Level0)
{
    HcfAsyKeyGenerator *generator = nullptr;
    HcfKeyPair *keyPair = nullptr;
    HcfResult res = TestKeyGeneratorAndGenerateKeyPair(g_ed25519AlgoName.c_str(), &generator, &keyPair);
    ASSERT_EQ(res, HCF_SUCCESS);

    keyPair->pubKey->base.base.destroy(&g_obj);
    HcfObjDestroy(keyPair);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoEd25519AsyKeyGeneratorTest, CryptoEd25519AsyKeyGeneratorTest051, TestSize.Level0)
{
    HcfAsyKeyGenerator *generator = nullptr;
    HcfKeyPair *keyPair = nullptr;

    HcfResult res = TestKeyGeneratorAndGenerateKeyPair(g_ed25519AlgoName.c_str(), &generator, &keyPair);
    ASSERT_EQ(res, HCF_SUCCESS);

    keyPair->priKey->base.base.destroy(nullptr);
    HcfObjDestroy(keyPair);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoEd25519AsyKeyGeneratorTest, CryptoEd25519AsyKeyGeneratorTest052, TestSize.Level0)
{
    HcfAsyKeyGenerator *generator = nullptr;
    HcfKeyPair *keyPair = nullptr;
    HcfResult res = TestKeyGeneratorAndGenerateKeyPair(g_ed25519AlgoName.c_str(), &generator, &keyPair);
    ASSERT_EQ(res, HCF_SUCCESS);

    keyPair->priKey->base.base.destroy(&g_obj);
    HcfObjDestroy(keyPair);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoEd25519AsyKeyGeneratorTest, CryptoEd25519AsyKeyGeneratorTest053, TestSize.Level0)
{
    HcfAsyKeyGenerator *generator = nullptr;
    HcfKeyPair *keyPair = nullptr;

    HcfResult res = TestKeyGeneratorAndGenerateKeyPair(g_ed25519AlgoName.c_str(), &generator, &keyPair);
    ASSERT_EQ(res, HCF_SUCCESS);

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
    HcfObjDestroy(keyPair);
    HcfObjDestroy(generator);
    HcfObjDestroy(sign);
    HcfObjDestroy(verify);
}

static void OpensslMockTestFuncGetPubKey(uint32_t mallocCount)
{
    for (uint32_t i = 0; i < mallocCount; i++) {
        ResetOpensslCallNum();
        SetOpensslCallMockIndex(i);

        HcfAsyKeyGenerator *tmpGenerator = nullptr;
        HcfKeyPair *tmpKeyPair = nullptr;
        HcfResult res = TestKeyGeneratorAndGenerateKeyPair(g_ed25519AlgoName.c_str(), &tmpGenerator, &tmpKeyPair);
        if (res != HCF_SUCCESS) {
            continue;
        }

        HcfBlob tmpPubKeyBlob1 = { .data = nullptr, .len = 0 };
        res = tmpKeyPair->pubKey->base.getEncoded(&(tmpKeyPair->pubKey->base), &tmpPubKeyBlob1);
        if (res != HCF_SUCCESS) {
            HcfObjDestroy(tmpKeyPair);
            HcfObjDestroy(tmpGenerator);
            continue;
        }

        HcfPubKey *tmpPubKey = nullptr;
        res = tmpKeyPair->priKey->getPubKey(tmpKeyPair->priKey, &tmpPubKey);
        if (res != HCF_SUCCESS) {
            HcfFree(tmpPubKeyBlob1.data);
            HcfObjDestroy(tmpKeyPair);
            HcfObjDestroy(tmpGenerator);
            continue;
        }

        HcfBlob tmpPubKeyBlob = { .data = nullptr, .len = 0 };
        res = tmpPubKey->base.getEncoded(&(tmpPubKey->base), &tmpPubKeyBlob);
        if (res == HCF_SUCCESS) {
            HcfFree(tmpPubKeyBlob.data);
        }
        HcfFree(tmpPubKeyBlob1.data);
        HcfObjDestroy(tmpPubKey);
        HcfObjDestroy(tmpKeyPair);
        HcfObjDestroy(tmpGenerator);
    }
}

HWTEST_F(CryptoEd25519AsyKeyGeneratorTest, CryptoEd25519GetPubKeyFromPriKey, TestSize.Level0)
{
    HcfAsyKeyGenerator *generator = nullptr;
    HcfKeyPair *keyPair = nullptr;
    HcfResult res = TestKeyGeneratorAndGenerateKeyPair(g_ed25519AlgoName.c_str(), &generator, &keyPair);
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
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoEd25519AsyKeyGeneratorTest, CryptoEd25519GetPubKeyFromPriKeyMockTest, TestSize.Level0)
{
    StartRecordOpensslCallNum();
    HcfAsyKeyGenerator *generator = nullptr;
    HcfKeyPair *keyPair = nullptr;
    HcfResult res = TestKeyGeneratorAndGenerateKeyPair(g_ed25519AlgoName.c_str(), &generator, &keyPair);
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
    HcfObjDestroy(generator);

    uint32_t mallocCount = GetOpensslCallNum();
    OpensslMockTestFuncGetPubKey(mallocCount);

    EndRecordOpensslCallNum();
}

HWTEST_F(CryptoEd25519AsyKeyGeneratorTest, CryptoEd25519GetPubKeyFromPriKeyErrTest, TestSize.Level0)
{
    HcfAsyKeyGenerator *generator = nullptr;
    HcfKeyPair *keyPair = nullptr;
    HcfResult res = TestKeyGeneratorAndGenerateKeyPair(g_ed25519AlgoName.c_str(), &generator, &keyPair);
    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(keyPair, nullptr);

    HcfPubKey *pubKey = nullptr;
    res = keyPair->priKey->getPubKey(nullptr, &pubKey);
    ASSERT_NE(res, HCF_SUCCESS);
    ASSERT_EQ(pubKey, nullptr);

    res = keyPair->priKey->getPubKey(keyPair->priKey, nullptr);
    ASSERT_NE(res, HCF_SUCCESS);

    res = keyPair->priKey->getPubKey((HcfPriKey *)&g_obj, &pubKey);
    ASSERT_NE(res, HCF_SUCCESS);
    ASSERT_EQ(pubKey, nullptr);

    HcfObjDestroy(keyPair);
    HcfObjDestroy(generator);
}
}