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

#include "alg_25519_asy_key_generator_openssl.h"
#include "alg_25519_common_param_spec.h"
#include "key_agreement.h"
#include "params_parser.h"
#include "x25519_openssl.h"
#include "memory.h"
#include "memory_mock.h"
#include "openssl_adapter_mock.h"

using namespace std;
using namespace testing::ext;

namespace {
class CryptoX25519KeyAgreementTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp();
    void TearDown();

    static HcfKeyPair *ed25519KeyPair_;
    static HcfKeyPair *x25519KeyPair_;
};

HcfKeyPair *CryptoX25519KeyAgreementTest::ed25519KeyPair_ = nullptr;
HcfKeyPair *CryptoX25519KeyAgreementTest::x25519KeyPair_ = nullptr;

static string g_ed25519AlgoName = "Ed25519";
static string g_x25519AlgoName = "X25519";

void CryptoX25519KeyAgreementTest::SetUp() {}
void CryptoX25519KeyAgreementTest::TearDown() {}

static const char *GetMockClass(void)
{
    return "HcfSymKeyGenerator";
}

static HcfObjectBase g_obj = {
    .getClass = GetMockClass,
    .destroy = nullptr
};

void CryptoX25519KeyAgreementTest::SetUpTestCase()
{
    HcfAsyKeyGenerator *ed25519Generator = nullptr;
    HcfResult ret = TestHcfAsyKeyGeneratorCreate(g_ed25519AlgoName.c_str(), &ed25519Generator);
    ASSERT_EQ(ret, HCF_SUCCESS);

    HcfKeyPair *keyPair = nullptr;
    ret = TestGenerateKeyPair(ed25519Generator, &keyPair);
    ASSERT_EQ(ret, HCF_SUCCESS);
    ed25519KeyPair_ = keyPair;

    HcfAsyKeyGenerator *x25519Generator = nullptr;
    ret = TestHcfAsyKeyGeneratorCreate(g_x25519AlgoName.c_str(), &x25519Generator);
    ASSERT_EQ(ret, HCF_SUCCESS);

    ret = TestGenerateKeyPair(x25519Generator, &keyPair);
    ASSERT_EQ(ret, HCF_SUCCESS);
    x25519KeyPair_ = keyPair;

    HcfObjDestroy(ed25519Generator);
    HcfObjDestroy(x25519Generator);
}

void CryptoX25519KeyAgreementTest::TearDownTestCase()
{
    HcfObjDestroy(ed25519KeyPair_);
    HcfObjDestroy(x25519KeyPair_);
}

static HcfResult TestHcfKeyAgreementCreate(const string &algName, HcfKeyAgreement **keyAgreement)
{
    HcfResult res = HcfKeyAgreementCreate(algName.c_str(), keyAgreement);
    if (res != HCF_SUCCESS) {
        return HCF_ERR_CRYPTO_OPERATION;
    }
    if (*keyAgreement == nullptr) {
        return HCF_ERR_CRYPTO_OPERATION;
    }
    return HCF_SUCCESS;
}

HWTEST_F(CryptoX25519KeyAgreementTest, CryptoX25519KeyAgreementTest001, TestSize.Level0)
{
    HcfKeyAgreement *keyAgreement = nullptr;
    HcfResult res = TestHcfKeyAgreementCreate(g_x25519AlgoName, &keyAgreement);
    ASSERT_EQ(res, HCF_SUCCESS);
    HcfObjDestroy(keyAgreement);
}

HWTEST_F(CryptoX25519KeyAgreementTest, CryptoX25519KeyAgreementTest002, TestSize.Level0)
{
    HcfKeyAgreement *keyAgreement = nullptr;
    HcfResult res = TestHcfKeyAgreementCreate(g_x25519AlgoName, &keyAgreement);
    ASSERT_EQ(res, HCF_SUCCESS);

    const char *className = keyAgreement->base.getClass();
    ASSERT_NE(className, nullptr);
    HcfObjDestroy(keyAgreement);
}

HWTEST_F(CryptoX25519KeyAgreementTest, CryptoX25519KeyAgreementTest003, TestSize.Level0)
{
    HcfKeyAgreement *keyAgreement = nullptr;
    HcfResult res = TestHcfKeyAgreementCreate(g_x25519AlgoName, &keyAgreement);
    ASSERT_EQ(res, HCF_SUCCESS);
    keyAgreement->base.destroy((HcfObjectBase *)keyAgreement);
}

HWTEST_F(CryptoX25519KeyAgreementTest, CryptoX25519KeyAgreementTest004, TestSize.Level0)
{
    HcfKeyAgreement *keyAgreement = nullptr;
    HcfResult res = TestHcfKeyAgreementCreate(g_x25519AlgoName, &keyAgreement);
    ASSERT_EQ(res, HCF_SUCCESS);

    const char *algName = keyAgreement->getAlgoName(keyAgreement);
    ASSERT_EQ(algName, g_x25519AlgoName);

    HcfAsyKeyParamsSpec *paramSpec = nullptr;
    res = ConstructAlg25519KeyPairParamsSpec(g_x25519AlgoName.c_str(), false, &paramSpec);
    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(paramSpec, nullptr);

    HcfAsyKeyGeneratorBySpec *generator = nullptr;
    res = HcfAsyKeyGeneratorBySpecCreate(paramSpec, &generator);
    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(generator, nullptr);

    HcfKeyPair *keyPair = nullptr;
    res = generator->generateKeyPair(generator, &keyPair);
    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(keyPair, nullptr);

    HcfBlob out = { .data = nullptr, .len = 0 };
    res = keyAgreement->generateSecret(keyAgreement, keyPair->priKey, keyPair->pubKey, &out);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(out.data, nullptr);
    ASSERT_NE(out.len, (const unsigned int)0);

    HcfFree(out.data);
    HcfObjDestroy(keyAgreement);
    HcfObjDestroy(generator);
    HcfObjDestroy(keyPair);
    DestroyAlg25519KeyPairSpec(reinterpret_cast<HcfAlg25519KeyPairParamsSpec *>(paramSpec));
}

HWTEST_F(CryptoX25519KeyAgreementTest, CryptoX25519KeyAgreementTest005, TestSize.Level0)
{
    HcfKeyAgreement *keyAgreement = nullptr;
    string algName = "x25519";
    HcfResult res = TestHcfKeyAgreementCreate(algName, &keyAgreement);
    ASSERT_NE(res, HCF_SUCCESS);
    HcfObjDestroy(keyAgreement);
}

HWTEST_F(CryptoX25519KeyAgreementTest, CryptoX25519KeyAgreementTest006, TestSize.Level0)
{
    HcfKeyAgreement *keyAgreement = nullptr;
    HcfResult res = TestHcfKeyAgreementCreate(g_x25519AlgoName, &keyAgreement);
    ASSERT_EQ(res, HCF_SUCCESS);
    keyAgreement->base.destroy(nullptr);
    keyAgreement->base.destroy(&g_obj);

    HcfObjDestroy(keyAgreement);
}

HWTEST_F(CryptoX25519KeyAgreementTest, CryptoX25519KeyAgreementTest007, TestSize.Level0)
{
    HcfKeyAgreement *keyAgreement = nullptr;
    HcfResult res = TestHcfKeyAgreementCreate(g_x25519AlgoName, &keyAgreement);
    ASSERT_EQ(res, HCF_SUCCESS);

    const char *algName = nullptr;
    algName = keyAgreement->getAlgoName(nullptr);
    ASSERT_EQ(algName, nullptr);

    algName = keyAgreement->getAlgoName((HcfKeyAgreement *)(&g_obj));
    ASSERT_EQ(algName, nullptr);

    HcfObjDestroy(keyAgreement);
}

HWTEST_F(CryptoX25519KeyAgreementTest, CryptoX25519KeyAgreementTest008, TestSize.Level0)
{
    HcfKeyAgreement *keyAgreement = nullptr;
    HcfResult res = HcfKeyAgreementCreate("X25519", &keyAgreement);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(keyAgreement, nullptr);

    HcfBlob out = { .data = nullptr, .len = 0 };
    res = keyAgreement->generateSecret(keyAgreement, x25519KeyPair_->priKey, nullptr, &out);
    ASSERT_EQ(res, HCF_INVALID_PARAMS);
    ASSERT_EQ(out.data, nullptr);
    ASSERT_EQ(out.len, (const unsigned int)0);

    res = keyAgreement->generateSecret(keyAgreement, nullptr, x25519KeyPair_->pubKey, &out);
    ASSERT_EQ(res, HCF_INVALID_PARAMS);
    ASSERT_EQ(out.data, nullptr);
    ASSERT_EQ(out.len, (const unsigned int)0);

    res = keyAgreement->generateSecret(keyAgreement, ed25519KeyPair_->priKey, ed25519KeyPair_->pubKey, &out);
    ASSERT_EQ(res, HCF_ERR_CRYPTO_OPERATION);
    ASSERT_EQ(out.data, nullptr);
    ASSERT_EQ(out.len, (const unsigned int)0);

    res = keyAgreement->generateSecret((HcfKeyAgreement *)&g_obj, ed25519KeyPair_->priKey,
    ed25519KeyPair_->pubKey, &out);
    ASSERT_EQ(res, HCF_INVALID_PARAMS);
    ASSERT_EQ(out.data, nullptr);
    ASSERT_EQ(out.len, (const unsigned int)0);

    HcfFree(out.data);
    HcfObjDestroy(keyAgreement);
}

static HcfResult TestHcfKeyAgreementSpiX25519Create(HcfResult result, HcfKeyAgreementSpi **spiObj)
{
    HcfKeyAgreementParams params = {
        .algo = HCF_ALG_X25519,
    };

    HcfResult res = HcfKeyAgreementSpiX25519Create(&params, spiObj);
    if (res != result) {
        return HCF_ERR_CRYPTO_OPERATION;
    }
    return HCF_SUCCESS;
}

HWTEST_F(CryptoX25519KeyAgreementTest, CryptoX25519KeyAgreementTest009, TestSize.Level0)
{
    HcfResult res = TestHcfKeyAgreementSpiX25519Create(HCF_INVALID_PARAMS, nullptr);
    ASSERT_EQ(res, HCF_SUCCESS);
}

HWTEST_F(CryptoX25519KeyAgreementTest, CryptoX25519KeyAgreementTest010, TestSize.Level0)
{
    HcfKeyAgreementSpi *spiObj = nullptr;
    HcfResult res = TestHcfKeyAgreementSpiX25519Create(HCF_SUCCESS, &spiObj);
    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(spiObj, nullptr);

    HcfBlob out = { .data = nullptr, .len = 0 };
    res = spiObj->engineGenerateSecret((HcfKeyAgreementSpi *)&g_obj, x25519KeyPair_->priKey, x25519KeyPair_->pubKey,
        &out);
    ASSERT_EQ(res, HCF_INVALID_PARAMS);

    res = spiObj->engineGenerateSecret(spiObj, (HcfPriKey *)&g_obj, x25519KeyPair_->pubKey, &out);
    ASSERT_EQ(res, HCF_INVALID_PARAMS);

    res = spiObj->engineGenerateSecret(spiObj, x25519KeyPair_->priKey, (HcfPubKey *)&g_obj, &out);
    ASSERT_EQ(res, HCF_INVALID_PARAMS);
    HcfFree(out.data);
    HcfObjDestroy(spiObj);
}

HWTEST_F(CryptoX25519KeyAgreementTest, CryptoX25519KeyAgreementTest011, TestSize.Level0)
{
    HcfKeyAgreementSpi *spiObj = nullptr;
    HcfResult res = TestHcfKeyAgreementSpiX25519Create(HCF_SUCCESS, &spiObj);
    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(spiObj, nullptr);

    spiObj->base.destroy(nullptr);
    HcfObjDestroy(spiObj);
}

HWTEST_F(CryptoX25519KeyAgreementTest, CryptoX25519KeyAgreementTest012, TestSize.Level0)
{
    HcfKeyAgreementSpi *spiObj = nullptr;
    HcfResult res = TestHcfKeyAgreementSpiX25519Create(HCF_SUCCESS, &spiObj);
    ASSERT_EQ(res, HCF_SUCCESS);

    spiObj->base.destroy(&g_obj);
    HcfObjDestroy(spiObj);
}

HWTEST_F(CryptoX25519KeyAgreementTest, CryptoX25519KeyAgreementTest013, TestSize.Level0)
{
    StartRecordMallocNum();
    HcfKeyAgreement *keyAgreement = nullptr;

    HcfResult res = TestHcfKeyAgreementCreate(g_x25519AlgoName, &keyAgreement);
    ASSERT_EQ(res, HCF_SUCCESS);

    HcfBlob out = { .data = nullptr, .len = 0 };
    res = keyAgreement->generateSecret(keyAgreement, x25519KeyPair_->priKey, x25519KeyPair_->pubKey, &out);
    ASSERT_EQ(res, HCF_SUCCESS);

    HcfObjDestroy(keyAgreement);
    HcfFree(out.data);
    uint32_t mallocCount = GetMallocNum();

    for (uint32_t i = 0; i < mallocCount; i++) {
        ResetRecordMallocNum();
        SetMockMallocIndex(i);
        keyAgreement = nullptr;
        res = HcfKeyAgreementCreate(g_x25519AlgoName.c_str(), &keyAgreement);

        if (res != HCF_SUCCESS) {
            continue;
        }

        HcfBlob tmpBlob = {
            .data = nullptr,
            .len = 0
        };
        res = keyAgreement->generateSecret(keyAgreement, x25519KeyPair_->priKey, x25519KeyPair_->pubKey, &tmpBlob);

        if (res != HCF_SUCCESS) {
            HcfObjDestroy(keyAgreement);
            continue;
        }

        HcfObjDestroy(keyAgreement);
        HcfFree(tmpBlob.data);
    }
    EndRecordMallocNum();
}

HWTEST_F(CryptoX25519KeyAgreementTest, CryptoX25519KeyAgreementTest014, TestSize.Level0)
{
    StartRecordOpensslCallNum();
    HcfKeyAgreement *keyAgreement = nullptr;

    HcfResult res = TestHcfKeyAgreementCreate(g_x25519AlgoName, &keyAgreement);
    ASSERT_EQ(res, HCF_SUCCESS);

    HcfBlob out = { .data = nullptr, .len = 0 };
    res = keyAgreement->generateSecret(keyAgreement, x25519KeyPair_->priKey, x25519KeyPair_->pubKey, &out);
    ASSERT_EQ(res, HCF_SUCCESS);

    HcfObjDestroy(keyAgreement);
    HcfFree(out.data);
    uint32_t mallocCount = GetOpensslCallNum();

    for (uint32_t i = 0; i < mallocCount; i++) {
        ResetOpensslCallNum();
        SetOpensslCallMockIndex(i);
        keyAgreement = nullptr;
        res = HcfKeyAgreementCreate(g_x25519AlgoName.c_str(), &keyAgreement);

        if (res != HCF_SUCCESS) {
            continue;
        }

        HcfBlob tmpBlob = {
            .data = nullptr,
            .len = 0
        };
        res = keyAgreement->generateSecret(keyAgreement, x25519KeyPair_->priKey, x25519KeyPair_->pubKey, &tmpBlob);

        if (res != HCF_SUCCESS) {
            HcfObjDestroy(keyAgreement);
            continue;
        }

        HcfObjDestroy(keyAgreement);
        HcfFree(tmpBlob.data);
    }
    EndRecordOpensslCallNum();
}

HWTEST_F(CryptoX25519KeyAgreementTest, CryptoX25519KeyAgreementTest015, TestSize.Level0)
{
    HcfAsyKeyGenerator *generator = nullptr;
    HcfResult res = TestHcfAsyKeyGeneratorCreate(g_x25519AlgoName.c_str(), &generator);
    ASSERT_EQ(res, HCF_SUCCESS);

    HcfKeyPair *x25519keyPair1 = nullptr;
    res = TestGenerateKeyPair(generator, &x25519keyPair1);
    ASSERT_EQ(res, HCF_SUCCESS);
    HcfKeyPair *x25519keyPair2 = nullptr;
    res = TestGenerateKeyPair(generator, &x25519keyPair2);
    ASSERT_EQ(res, HCF_SUCCESS);

    HcfKeyAgreement *keyAgreement = nullptr;
    res = TestHcfKeyAgreementCreate(g_x25519AlgoName, &keyAgreement);
    ASSERT_EQ(res, HCF_SUCCESS);

    HcfBlob outBlob1 = { .data = nullptr, .len = 0 };
    res = keyAgreement->generateSecret(keyAgreement, x25519keyPair1->priKey, x25519keyPair2->pubKey, &outBlob1);
    ASSERT_EQ(res, HCF_SUCCESS);

    HcfBlob outBlob2 = { .data = nullptr, .len = 0 };
    res = keyAgreement->generateSecret(keyAgreement, x25519keyPair2->priKey, x25519keyPair1->pubKey, &outBlob2);
    ASSERT_EQ(res, HCF_SUCCESS);

    bool flag = true;
    if (*(outBlob1.data) != *(outBlob2.data)) {
        flag = false;
    }
    EXPECT_EQ(flag, true);
    ASSERT_EQ(outBlob1.len, outBlob2.len);

    HcfObjDestroy(keyAgreement);
    HcfObjDestroy(generator);
    HcfObjDestroy(x25519keyPair1);
    HcfObjDestroy(x25519keyPair2);
    HcfFree(outBlob1.data);
    HcfFree(outBlob2.data);
}
}