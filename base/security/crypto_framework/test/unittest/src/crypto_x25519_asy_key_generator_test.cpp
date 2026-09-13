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
#include "ecc_asy_key_generator_openssl.h"
#include "blob.h"
#include "params_parser.h"
#include "key_utils.h"
#include "key_pair.h"
#include "object_base.h"
#include "memory.h"
#include "memory_mock.h"
#include "openssl_adapter_mock.h"

using namespace std;
using namespace testing::ext;

namespace {
class CryptoX25519AsyKeyGeneratorTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp();
    void TearDown();
};

void CryptoX25519AsyKeyGeneratorTest::TearDownTestCase() {}
void CryptoX25519AsyKeyGeneratorTest::SetUp() {}
void CryptoX25519AsyKeyGeneratorTest::TearDown() {}

static string g_x25519AlgoName = "X25519";
static string g_pubkeyformatName = "X.509";
static string g_prikeyformatName = "PKCS#8";

HcfBlob g_mockX25519PriKeyBlob = {
    .data = nullptr,
    .len = 0
};

HcfBlob g_mockX25519PubKeyBlob = {
    .data = nullptr,
    .len = 0
};

static HcfResult X25519KeyBlob(HcfBlob * priblob, HcfBlob *pubblob)
{
    HcfAsyKeyGenerator *generator = nullptr;
    HcfResult res = HcfAsyKeyGeneratorCreate("X25519", &generator);
    if (res != HCF_SUCCESS) {
        return res;
    }

    HcfKeyPair *keyPair = nullptr;
    res = generator->generateKeyPair(generator, nullptr, &keyPair);
    if (res != HCF_SUCCESS) {
        HcfObjDestroy(generator);
        return res;
    }
    res = keyPair->priKey->base.getEncoded(&(keyPair->priKey->base), &g_mockX25519PriKeyBlob);
    if (res != HCF_SUCCESS) {
        HcfObjDestroy(generator);
        HcfObjDestroy(keyPair);
        return res;
    }
    res = keyPair->pubKey->base.getEncoded(&(keyPair->pubKey->base), &g_mockX25519PubKeyBlob);
    if (res != HCF_SUCCESS) {
        HcfObjDestroy(generator);
        HcfObjDestroy(keyPair);
        return res;
    }
    HcfObjDestroy(generator);
    HcfObjDestroy(keyPair);
    return HCF_SUCCESS;
}

void CryptoX25519AsyKeyGeneratorTest::SetUpTestCase()
{
    HcfResult res = X25519KeyBlob(&g_mockX25519PriKeyBlob, &g_mockX25519PubKeyBlob);
    ASSERT_EQ(res, HCF_SUCCESS);
}

HWTEST_F(CryptoX25519AsyKeyGeneratorTest, CryptoX25519AsyKeyGeneratorTest001, TestSize.Level0)
{
    HcfAsyKeyGenerator *generator = nullptr;
    HcfResult res = TestHcfAsyKeyGeneratorCreate(g_x25519AlgoName.c_str(), &generator);
    ASSERT_EQ(res, HCF_SUCCESS);

    HcfObjDestroy(generator);
}

HWTEST_F(CryptoX25519AsyKeyGeneratorTest, CryptoX25519AsyKeyGeneratorTest002, TestSize.Level0)
{
    HcfAsyKeyGenerator *generator = nullptr;
    HcfResult res = HcfAsyKeyGeneratorCreate("X25519", &generator);

    const char *className = generator->base.getClass();

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(className, nullptr);

    HcfObjDestroy(generator);
}

HWTEST_F(CryptoX25519AsyKeyGeneratorTest, CryptoX25519AsyKeyGeneratorTest003, TestSize.Level0)
{
    HcfAsyKeyGenerator *generator = nullptr;
    HcfResult res = TestHcfAsyKeyGeneratorCreate(g_x25519AlgoName.c_str(), &generator);
    ASSERT_EQ(res, HCF_SUCCESS);

    generator->base.destroy((HcfObjectBase *)generator);
}

HWTEST_F(CryptoX25519AsyKeyGeneratorTest, CryptoX25519AsyKeyGeneratorTest004, TestSize.Level0)
{
    HcfAsyKeyGenerator *generator = nullptr;
    HcfResult res = TestHcfAsyKeyGeneratorCreate(g_x25519AlgoName.c_str(), &generator);
    ASSERT_EQ(res, HCF_SUCCESS);

    const char *algoName = generator->getAlgoName(generator);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_EQ(algoName, g_x25519AlgoName);

    HcfObjDestroy(generator);
}

HWTEST_F(CryptoX25519AsyKeyGeneratorTest, CryptoX25519AsyKeyGeneratorTest005, TestSize.Level0)
{
    HcfAsyKeyGenerator *generator = nullptr;
    HcfKeyPair *keyPair = nullptr;
    HcfResult res = TestKeyGeneratorAndGenerateKeyPair(g_x25519AlgoName.c_str(), &generator, &keyPair);
    ASSERT_EQ(res, HCF_SUCCESS);

    HcfObjDestroy(keyPair);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoX25519AsyKeyGeneratorTest, CryptoX25519AsyKeyGeneratorTest006, TestSize.Level0)
{
    HcfAsyKeyGenerator *generator = nullptr;
    HcfKeyPair *keyPair = nullptr;
    HcfResult res = TestKeyGeneratorAndGenerateKeyPair(g_x25519AlgoName.c_str(), &generator, &keyPair);
    ASSERT_EQ(res, HCF_SUCCESS);

    const char *className = keyPair->base.getClass();
    ASSERT_NE(className, nullptr);

    HcfObjDestroy(keyPair);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoX25519AsyKeyGeneratorTest, CryptoX25519AsyKeyGeneratorTest007, TestSize.Level0)
{
    HcfAsyKeyGenerator *generator = nullptr;
    HcfKeyPair *keyPair = nullptr;
    HcfResult res = TestKeyGeneratorAndGenerateKeyPair(g_x25519AlgoName.c_str(), &generator, &keyPair);
    ASSERT_EQ(res, HCF_SUCCESS);

    keyPair->base.destroy(&(keyPair->base));
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoX25519AsyKeyGeneratorTest, CryptoX25519AsyKeyGeneratorTest008, TestSize.Level0)
{
    HcfAsyKeyGenerator *generator = nullptr;
    HcfKeyPair *keyPair = nullptr;
    HcfResult res = TestKeyGeneratorAndGenerateKeyPair(g_x25519AlgoName.c_str(), &generator, &keyPair);
    ASSERT_EQ(res, HCF_SUCCESS);

    const char *className = keyPair->pubKey->base.base.getClass();
    ASSERT_NE(className, nullptr);

    HcfObjDestroy(keyPair);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoX25519AsyKeyGeneratorTest, CryptoX25519AsyKeyGeneratorTest009, TestSize.Level0)
{
    HcfAsyKeyGenerator *generator = nullptr;
    HcfKeyPair *keyPair = nullptr;
    HcfResult res = TestKeyGeneratorAndGenerateKeyPair(g_x25519AlgoName.c_str(), &generator, &keyPair);
    ASSERT_EQ(res, HCF_SUCCESS);

    keyPair->pubKey->base.base.destroy(&(keyPair->pubKey->base.base));
    keyPair->pubKey = nullptr;

    HcfObjDestroy(keyPair);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoX25519AsyKeyGeneratorTest, CryptoX25519AsyKeyGeneratorTest010, TestSize.Level0)
{
    HcfAsyKeyGenerator *generator = nullptr;
    HcfKeyPair *keyPair = nullptr;
    HcfResult res = TestKeyGeneratorAndGenerateKeyPair(g_x25519AlgoName.c_str(), &generator, &keyPair);
    ASSERT_EQ(res, HCF_SUCCESS);

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
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoX25519AsyKeyGeneratorTest, CryptoX25519AsyKeyGeneratorTest011, TestSize.Level0)
{
    HcfAsyKeyGenerator *generator = nullptr;
    HcfKeyPair *keyPair = nullptr;
    HcfResult res = TestKeyGeneratorAndGenerateKeyPair(g_x25519AlgoName.c_str(), &generator, &keyPair);
    ASSERT_EQ(res, HCF_SUCCESS);

    const char *className = keyPair->priKey->base.base.getClass();
    ASSERT_NE(className, nullptr);

    HcfObjDestroy(keyPair);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoX25519AsyKeyGeneratorTest, CryptoX25519AsyKeyGeneratorTest012, TestSize.Level0)
{
    HcfAsyKeyGenerator *generator = nullptr;
    HcfKeyPair *keyPair = nullptr;
    HcfResult res = TestKeyGeneratorAndGenerateKeyPair(g_x25519AlgoName.c_str(), &generator, &keyPair);
    ASSERT_EQ(res, HCF_SUCCESS);

    keyPair->priKey->base.base.destroy(&(keyPair->priKey->base.base));
    keyPair->priKey = nullptr;

    HcfObjDestroy(keyPair);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoX25519AsyKeyGeneratorTest, CryptoX25519AsyKeyGeneratorTest013, TestSize.Level0)
{
    HcfAsyKeyGenerator *generator = nullptr;
    HcfKeyPair *keyPair = nullptr;
    HcfResult res = TestKeyGeneratorAndGenerateKeyPair(g_x25519AlgoName.c_str(), &generator, &keyPair);
    ASSERT_EQ(res, HCF_SUCCESS);

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
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoX25519AsyKeyGeneratorTest, CryptoX25519AsyKeyGeneratorTest014, TestSize.Level0)
{
    HcfAsyKeyGenerator *generator = nullptr;
    HcfKeyPair *keyPair = nullptr;
    HcfResult res = TestKeyGeneratorAndGenerateKeyPair(g_x25519AlgoName.c_str(), &generator, &keyPair);
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

HWTEST_F(CryptoX25519AsyKeyGeneratorTest, CryptoX25519AsyKeyGeneratorTest015, TestSize.Level0)
{
    HcfAsyKeyGenerator *generator = nullptr;
    HcfKeyPair *keyPair = nullptr;
    HcfResult res = TestGenerateKeyPairAndConvertKey(g_x25519AlgoName.c_str(), &generator, &g_mockX25519PubKeyBlob,
        &g_mockX25519PriKeyBlob, &keyPair);
    ASSERT_EQ(res, HCF_SUCCESS);
    HcfObjDestroy(keyPair);

    res = TestGenerateConvertKey(generator, nullptr, &g_mockX25519PriKeyBlob, &keyPair);
    ASSERT_EQ(res, HCF_SUCCESS);
    HcfObjDestroy(keyPair);

    res = TestGenerateConvertKey(generator, &g_mockX25519PubKeyBlob, nullptr, &keyPair);
    ASSERT_EQ(res, HCF_SUCCESS);

    HcfObjDestroy(keyPair);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoX25519AsyKeyGeneratorTest, CryptoX25519AsyKeyGeneratorTest016, TestSize.Level0)
{
    HcfAsyKeyGenerator *generator = nullptr;
    HcfKeyPair *keyPair = nullptr;
    HcfResult res = TestGenerateKeyPairAndConvertKey(g_x25519AlgoName.c_str(), &generator, &g_mockX25519PubKeyBlob,
        &g_mockX25519PriKeyBlob, &keyPair);
    ASSERT_EQ(res, HCF_SUCCESS);

    const char *className = keyPair->base.getClass();
    ASSERT_NE(className, nullptr);

    HcfObjDestroy(keyPair);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoX25519AsyKeyGeneratorTest, CryptoX25519AsyKeyGeneratorTest017, TestSize.Level0)
{
    HcfAsyKeyGenerator *generator = nullptr;
    HcfKeyPair *keyPair = nullptr;
    HcfResult res = TestGenerateKeyPairAndConvertKey(g_x25519AlgoName.c_str(), &generator, &g_mockX25519PubKeyBlob,
        &g_mockX25519PriKeyBlob, &keyPair);
    ASSERT_EQ(res, HCF_SUCCESS);
    HcfObjDestroy(keyPair);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoX25519AsyKeyGeneratorTest, CryptoX25519AsyKeyGeneratorTest018, TestSize.Level0)
{
    HcfAsyKeyGenerator *generator = nullptr;
    HcfKeyPair *keyPair = nullptr;
    HcfResult res = TestGenerateKeyPairAndConvertKey(g_x25519AlgoName.c_str(), &generator, &g_mockX25519PubKeyBlob,
        &g_mockX25519PriKeyBlob, &keyPair);
    ASSERT_EQ(res, HCF_SUCCESS);

    const char *className = keyPair->pubKey->base.base.getClass();
    ASSERT_NE(className, nullptr);

    HcfObjDestroy(keyPair);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoX25519AsyKeyGeneratorTest, CryptoX25519AsyKeyGeneratorTest019, TestSize.Level0)
{
    HcfAsyKeyGenerator *generator = nullptr;
    HcfKeyPair *keyPair = nullptr;
    HcfResult res = TestGenerateKeyPairAndConvertKey(g_x25519AlgoName.c_str(), &generator, &g_mockX25519PubKeyBlob,
        &g_mockX25519PriKeyBlob, &keyPair);
    ASSERT_EQ(res, HCF_SUCCESS);

    keyPair->pubKey->base.base.destroy(&(keyPair->pubKey->base.base));
    keyPair->pubKey = nullptr;

    HcfObjDestroy(keyPair);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoX25519AsyKeyGeneratorTest, CryptoX25519AsyKeyGeneratorTest020, TestSize.Level0)
{
    HcfAsyKeyGenerator *generator = nullptr;
    HcfKeyPair *keyPair = nullptr;
    HcfResult res = TestGenerateKeyPairAndConvertKey(g_x25519AlgoName.c_str(), &generator, &g_mockX25519PubKeyBlob,
        &g_mockX25519PriKeyBlob, &keyPair);
    ASSERT_EQ(res, HCF_SUCCESS);

    const char *algorithmName = keyPair->pubKey->base.getAlgorithm(&(keyPair->pubKey->base));
    ASSERT_NE(algorithmName, nullptr);

    HcfBlob blob = { .data = nullptr, .len = 0 };
    res = keyPair->pubKey->base.getEncoded(&(keyPair->pubKey->base), &blob);
    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(blob.data, nullptr);
    ASSERT_NE(blob.len, 0);
    HcfFree(blob.data);

    const char *formatName = keyPair->pubKey->base.getFormat(&(keyPair->pubKey->base));
    ASSERT_NE(formatName, nullptr);

    HcfObjDestroy(keyPair);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoX25519AsyKeyGeneratorTest, CryptoX25519AsyKeyGeneratorTest021, TestSize.Level0)
{
    HcfAsyKeyGenerator *generator = nullptr;
    HcfKeyPair *keyPair = nullptr;
    HcfResult res = TestGenerateKeyPairAndConvertKey(g_x25519AlgoName.c_str(), &generator, &g_mockX25519PubKeyBlob,
        &g_mockX25519PriKeyBlob, &keyPair);
    ASSERT_EQ(res, HCF_SUCCESS);

    const char *className = keyPair->priKey->base.base.getClass();
    ASSERT_NE(className, nullptr);

    HcfObjDestroy(keyPair);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoX25519AsyKeyGeneratorTest, CryptoX25519AsyKeyGeneratorTest022, TestSize.Level0)
{
    HcfAsyKeyGenerator *generator = nullptr;
    HcfKeyPair *keyPair = nullptr;
    HcfResult res = TestGenerateKeyPairAndConvertKey(g_x25519AlgoName.c_str(), &generator, &g_mockX25519PubKeyBlob,
        &g_mockX25519PriKeyBlob, &keyPair);
    ASSERT_EQ(res, HCF_SUCCESS);

    keyPair->priKey->base.base.destroy(&(keyPair->priKey->base.base));
    keyPair->priKey = nullptr;

    HcfObjDestroy(keyPair);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoX25519AsyKeyGeneratorTest, CryptoX25519AsyKeyGeneratorTest023, TestSize.Level0)
{
    HcfAsyKeyGenerator *generator = nullptr;
    HcfKeyPair *keyPair = nullptr;
    HcfResult res = TestGenerateKeyPairAndConvertKey(g_x25519AlgoName.c_str(), &generator, &g_mockX25519PubKeyBlob,
        &g_mockX25519PriKeyBlob, &keyPair);
    ASSERT_EQ(res, HCF_SUCCESS);

    const char *algorithmName = keyPair->priKey->base.getAlgorithm(&(keyPair->priKey->base));
    ASSERT_NE(algorithmName, nullptr);

    HcfBlob blob = { .data = nullptr, .len = 0 };
    res = keyPair->priKey->base.getEncoded(&(keyPair->priKey->base), &blob);
    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(blob.data, nullptr);
    ASSERT_NE(blob.len, 0);
    HcfFree(blob.data);

    const char *formatName = keyPair->priKey->base.getFormat(&(keyPair->priKey->base));
    ASSERT_NE(formatName, nullptr);

    HcfObjDestroy(keyPair);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoX25519AsyKeyGeneratorTest, CryptoX25519AsyKeyGeneratorTest024, TestSize.Level0)
{
    HcfAsyKeyGenerator *generator = nullptr;
    HcfKeyPair *keyPair = nullptr;
    HcfResult res = TestGenerateKeyPairAndConvertKey(g_x25519AlgoName.c_str(), &generator, &g_mockX25519PubKeyBlob,
        &g_mockX25519PriKeyBlob, &keyPair);
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
        HcfResult res = HcfAsyKeyGeneratorCreate("X25519", &tmpGenerator);
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

HWTEST_F(CryptoX25519AsyKeyGeneratorTest, CryptoX25519AsyKeyGeneratorTest025, TestSize.Level0)
{
    StartRecordMallocNum();
    HcfAsyKeyGenerator *generator = nullptr;
    HcfKeyPair *keyPair = nullptr;
    HcfResult res = TestKeyGeneratorAndGenerateKeyPair(g_x25519AlgoName.c_str(), &generator, &keyPair);
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
        HcfResult res = HcfAsyKeyGeneratorCreate("X25519", &tmpGenerator);
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

HWTEST_F(CryptoX25519AsyKeyGeneratorTest, CryptoX25519AsyKeyGeneratorTest026, TestSize.Level0)
{
    StartRecordOpensslCallNum();
    HcfAsyKeyGenerator *generator = nullptr;
    HcfKeyPair *keyPair = nullptr;
    HcfResult res = TestKeyGeneratorAndGenerateKeyPair(g_x25519AlgoName.c_str(), &generator, &keyPair);
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

static void OpensslMockTestFuncGetPubKey(uint32_t mallocCount)
{
    for (uint32_t i = 0; i < mallocCount; i++) {
        ResetOpensslCallNum();
        SetOpensslCallMockIndex(i);

        HcfAsyKeyGenerator *tmpGenerator = nullptr;
        HcfResult res = HcfAsyKeyGeneratorCreate("X25519", &tmpGenerator);
        if (res != HCF_SUCCESS) {
            continue;
        }

        HcfKeyPair *tmpKeyPair = nullptr;
        res = TestGenerateKeyPair(tmpGenerator, &tmpKeyPair);
        if (res != HCF_SUCCESS) {
            HcfObjDestroy(tmpGenerator);
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

HWTEST_F(CryptoX25519AsyKeyGeneratorTest, CryptoX25519GetPubKeyFromPriKey, TestSize.Level0)
{
    HcfAsyKeyGenerator *generator = nullptr;
    HcfResult res = HcfAsyKeyGeneratorCreate("X25519", &generator);
    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(generator, nullptr);
    HcfKeyPair *keyPair = nullptr;
    res = TestGenerateKeyPair(generator, &keyPair);
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

HWTEST_F(CryptoX25519AsyKeyGeneratorTest, CryptoX25519GetPubKeyFromPriKeyMockTest, TestSize.Level0)
{
    StartRecordOpensslCallNum();
    HcfAsyKeyGenerator *generator = nullptr;
    HcfResult res = HcfAsyKeyGeneratorCreate("X25519", &generator);
    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(generator, nullptr);
    HcfKeyPair *keyPair = nullptr;
    res = TestGenerateKeyPair(generator, &keyPair);
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

HWTEST_F(CryptoX25519AsyKeyGeneratorTest, CryptoX25519GetPubKeyFromPriKeyErrTest, TestSize.Level0)
{
    HcfAsyKeyGenerator *generator = nullptr;
    HcfResult res = HcfAsyKeyGeneratorCreate("X25519", &generator);
    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(generator, nullptr);
    HcfKeyPair *keyPair = nullptr;
    res = TestGenerateKeyPair(generator, &keyPair);
    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(keyPair, nullptr);

    HcfPubKey *pubKey = nullptr;
    res = keyPair->priKey->getPubKey(nullptr, &pubKey);
    ASSERT_NE(res, HCF_SUCCESS);
    ASSERT_EQ(pubKey, nullptr);

    res = keyPair->priKey->getPubKey(keyPair->priKey, nullptr);
    ASSERT_NE(res, HCF_SUCCESS);

    HcfObjDestroy(keyPair);
    HcfObjDestroy(generator);
}
}