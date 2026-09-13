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
#include <openssl/dh.h>
#include <openssl/evp.h>
#include "securec.h"

#include "asy_key_generator.h"
#include "alg_25519_asy_key_generator_openssl.h"
#include "detailed_alg_25519_key_params.h"
#include "key_agreement.h"
#include "ecc_key_util.h"
#include "params_parser.h"
#include "dh_asy_key_generator_openssl.h"
#include "detailed_dh_key_params.h"
#include "dh_key_util.h"
#include "dh_openssl.h"
#include "memory.h"
#include "memory_mock.h"
#include "openssl_adapter_mock.h"
#include "dh_openssl_common.h"
#include "openssl_class.h"

using namespace std;
using namespace testing::ext;

namespace {
constexpr int SKLEN_DH128 = 128;
constexpr int SKLEN_DH512 = 512;
constexpr int SKLEN_DH1024 = 1024;
constexpr int PLEN_DH512 = 512;
constexpr int PLEN_DH2048 = 2048;

class CryptoDHKeyAgreementTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp();
    void TearDown();

    static HcfKeyPair *dh1536KeyPair_;
    static HcfKeyPair *dh3072KeyPair1_;
    static HcfKeyPair *dh3072KeyPair2_;
};

HcfKeyPair *CryptoDHKeyAgreementTest::dh1536KeyPair_ = nullptr;
HcfKeyPair *CryptoDHKeyAgreementTest::dh3072KeyPair1_ = nullptr;
HcfKeyPair *CryptoDHKeyAgreementTest::dh3072KeyPair2_ = nullptr;

static string g_dh1536AlgoName = "DH_modp1536";
static string g_dh3072AlgoName = "DH_modp3072";

void CryptoDHKeyAgreementTest::SetUp() {}
void CryptoDHKeyAgreementTest::TearDown() {}

static const char *GetMockClass(void)
{
    return "HcfSymKeyGenerator";
}

static HcfObjectBase g_obj = {
    .getClass = GetMockClass,
    .destroy = nullptr
};

static HcfResult HcfKeyAgreementCreateTest(const char *algName)
{
    HcfKeyAgreement *keyAgreement = nullptr;
    HcfResult res = HcfKeyAgreementCreate(algName, &keyAgreement);
    if (res == HCF_SUCCESS) {
        HcfObjDestroy(keyAgreement);
    }
    return res;
}

static HcfResult ExchangekeyAgreementWithDiffSkLen(const int pLen, const int skLen, const int size)
{
    HcfResult res = HCF_ERR_CRYPTO_OPERATION;
    HcfDhCommParamsSpec *paramSpec = nullptr;
    HcfAsyKeyGeneratorBySpec *generator = nullptr;
    HcfKeyPair *keyPair = nullptr;
    HcfDhCommParamsSpec *paramSpec1 = nullptr;
    HcfAsyKeyGeneratorBySpec *generator1 = nullptr;
    HcfKeyPair *keyPair1 = nullptr;
    HcfBlob out = { .data = nullptr, .len = 0 };
    HcfKeyAgreement *keyAgreement = nullptr;
    do {
        if (HcfDhKeyUtilCreate(pLen, skLen, &paramSpec) != HCF_SUCCESS ||
            HcfAsyKeyGeneratorBySpecCreate(reinterpret_cast<HcfAsyKeyParamsSpec *>(paramSpec), &generator)
            != HCF_SUCCESS) {
            break;
        }
        if (generator->generateKeyPair(generator, &keyPair) != HCF_SUCCESS ||
            HcfDhKeyUtilCreate(pLen, size, &paramSpec1) != HCF_SUCCESS) {
            break;
        }
        if (HcfAsyKeyGeneratorBySpecCreate(reinterpret_cast<HcfAsyKeyParamsSpec *>(paramSpec1), &generator1)
            != HCF_SUCCESS) {
            break;
        }
        if (generator1->generateKeyPair(generator1, &keyPair1) != HCF_SUCCESS ||
            HcfKeyAgreementCreate("DH", &keyAgreement) != HCF_SUCCESS) {
            break;
        }
        if (keyAgreement->generateSecret(keyAgreement, keyPair->priKey, keyPair1->pubKey, &out) != HCF_SUCCESS) {
            break;
        }
        HcfFree(out.data);
        if (keyAgreement->generateSecret(keyAgreement, keyPair1->priKey, keyPair->pubKey, &out) != HCF_SUCCESS) {
            break;
        }
        res = HCF_SUCCESS;
    } while (0);
    HcfFree(out.data);
    HcfObjDestroy(keyAgreement);
    HcfObjDestroy(generator);
    HcfObjDestroy(generator1);
    HcfObjDestroy(keyPair);
    HcfObjDestroy(keyPair1);
    FreeDhCommParamsSpec(paramSpec);
    HcfFree(paramSpec);
    FreeDhCommParamsSpec(paramSpec1);
    HcfFree(paramSpec1);
    return res;
}

void CryptoDHKeyAgreementTest::SetUpTestCase()
{
    HcfAsyKeyGenerator *generator = nullptr;
    int32_t res = HcfAsyKeyGeneratorCreate("DH_modp1536", &generator);
    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(generator, nullptr);

    HcfKeyPair *keyPair = nullptr;
    res = generator->generateKeyPair(generator, nullptr, &keyPair);
    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(keyPair, nullptr);

    dh1536KeyPair_ = keyPair;
    HcfObjDestroy(generator);

    HcfAsyKeyGenerator *generator1 = nullptr;
    res = HcfAsyKeyGeneratorCreate("DH_modp3072", &generator1);
    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(generator1, nullptr);

    HcfKeyPair *keyPair1 = nullptr;
    res = generator1->generateKeyPair(generator1, nullptr, &keyPair1);
    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(keyPair1, nullptr);

    dh3072KeyPair1_ = keyPair1;
    HcfObjDestroy(generator1);

    HcfAsyKeyGenerator *generator2 = nullptr;
    res = HcfAsyKeyGeneratorCreate("DH_modp3072", &generator2);
    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(generator2, nullptr);

    HcfKeyPair *keyPair2 = nullptr;
    res = generator2->generateKeyPair(generator2, nullptr, &keyPair2);
    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(keyPair2, nullptr);

    dh3072KeyPair2_ = keyPair2;
    HcfObjDestroy(generator2);
}

void CryptoDHKeyAgreementTest::TearDownTestCase()
{
    HcfObjDestroy(dh1536KeyPair_);
    HcfObjDestroy(dh3072KeyPair1_);
    HcfObjDestroy(dh3072KeyPair2_);
}

HWTEST_F(CryptoDHKeyAgreementTest, CryptoDHKeyAgreementTest001_1, TestSize.Level0)
{
    HcfResult res = HcfKeyAgreementCreateTest("DH_modp1536");
    ASSERT_EQ(res, HCF_SUCCESS);
}

HWTEST_F(CryptoDHKeyAgreementTest, CryptoDHKeyAgreementTest001_2, TestSize.Level0)
{
    HcfResult res = HcfKeyAgreementCreateTest("DH_modp2048");
    ASSERT_EQ(res, HCF_SUCCESS);
}

HWTEST_F(CryptoDHKeyAgreementTest, CryptoDHKeyAgreementTest001_3, TestSize.Level0)
{
    HcfResult res = HcfKeyAgreementCreateTest("DH_modp3072");
    ASSERT_EQ(res, HCF_SUCCESS);
}

HWTEST_F(CryptoDHKeyAgreementTest, CryptoDHKeyAgreementTest001_4, TestSize.Level0)
{
    HcfResult res = HcfKeyAgreementCreateTest("DH_modp4096");
    ASSERT_EQ(res, HCF_SUCCESS);
}

HWTEST_F(CryptoDHKeyAgreementTest, CryptoDHKeyAgreementTest001_5, TestSize.Level0)
{
    HcfResult res = HcfKeyAgreementCreateTest("DH_modp6144");
    ASSERT_EQ(res, HCF_SUCCESS);
}

HWTEST_F(CryptoDHKeyAgreementTest, CryptoDHKeyAgreementTest001_6, TestSize.Level0)
{
    HcfResult res = HcfKeyAgreementCreateTest("DH_modp8192");
    ASSERT_EQ(res, HCF_SUCCESS);
}

HWTEST_F(CryptoDHKeyAgreementTest, CryptoDHKeyAgreementTest001_7, TestSize.Level0)
{
    HcfResult res = HcfKeyAgreementCreateTest("DH_ffdhe2048");
    ASSERT_EQ(res, HCF_SUCCESS);
}

HWTEST_F(CryptoDHKeyAgreementTest, CryptoDHKeyAgreementTest001_8, TestSize.Level0)
{
    HcfResult res = HcfKeyAgreementCreateTest("DH_ffdhe3072");
    ASSERT_EQ(res, HCF_SUCCESS);
}

HWTEST_F(CryptoDHKeyAgreementTest, CryptoDHKeyAgreementTest001_9, TestSize.Level0)
{
    HcfResult res = HcfKeyAgreementCreateTest("DH_ffdhe4096");
    ASSERT_EQ(res, HCF_SUCCESS);
}

HWTEST_F(CryptoDHKeyAgreementTest, CryptoDHKeyAgreementTest001_10, TestSize.Level0)
{
    HcfResult res = HcfKeyAgreementCreateTest("DH_ffdhe6144");
    ASSERT_EQ(res, HCF_SUCCESS);
}

HWTEST_F(CryptoDHKeyAgreementTest, CryptoDHKeyAgreementTest001_11, TestSize.Level0)
{
    HcfResult res = HcfKeyAgreementCreateTest("DH_ffdhe8192");
    ASSERT_EQ(res, HCF_SUCCESS);
}

HWTEST_F(CryptoDHKeyAgreementTest, CryptoDHKeyAgreementTest002, TestSize.Level0)
{
    HcfKeyAgreement *keyAgreement = nullptr;
    HcfResult res = HcfKeyAgreementCreate(g_dh1536AlgoName.c_str(), &keyAgreement);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(keyAgreement, nullptr);

    const char *className = keyAgreement->base.getClass();
    ASSERT_NE(className, nullptr);
    HcfObjDestroy(keyAgreement);
}

HWTEST_F(CryptoDHKeyAgreementTest, CryptoDHKeyAgreementTest003, TestSize.Level0)
{
    HcfKeyAgreement *keyAgreement = nullptr;
    HcfResult res = HcfKeyAgreementCreate(g_dh1536AlgoName.c_str(), &keyAgreement);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(keyAgreement, nullptr);
    keyAgreement->base.destroy((HcfObjectBase *)keyAgreement);
}

HWTEST_F(CryptoDHKeyAgreementTest, CryptoDHKeyAgreementTest004, TestSize.Level0)
{
    HcfKeyAgreement *keyAgreement = nullptr;
    HcfResult res = HcfKeyAgreementCreate(g_dh1536AlgoName.c_str(), &keyAgreement);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(keyAgreement, nullptr);

    const char *algName = keyAgreement->getAlgoName(keyAgreement);
    ASSERT_EQ(algName, g_dh1536AlgoName);

    HcfBlob out = { .data = nullptr, .len = 0 };
    res = keyAgreement->generateSecret(keyAgreement, dh1536KeyPair_->priKey, dh1536KeyPair_->pubKey, &out);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(out.data, nullptr);
    ASSERT_NE(out.len, (const unsigned int)0);

    HcfFree(out.data);
    HcfObjDestroy(keyAgreement);
}

HWTEST_F(CryptoDHKeyAgreementTest, CryptoDHKeyAgreementTest005, TestSize.Level0)
{
    HcfKeyAgreement *keyAgreement = nullptr;
    HcfResult res = HcfKeyAgreementCreate("DH_9999", &keyAgreement);

    ASSERT_EQ(res, HCF_INVALID_PARAMS);
    ASSERT_EQ(keyAgreement, nullptr);
    HcfObjDestroy(keyAgreement);
}

HWTEST_F(CryptoDHKeyAgreementTest, CryptoDHKeyAgreementTest006, TestSize.Level0)
{
    HcfKeyAgreement *keyAgreement = nullptr;
    HcfResult res = HcfKeyAgreementCreate(g_dh1536AlgoName.c_str(), &keyAgreement);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(keyAgreement, nullptr);
    keyAgreement->base.destroy(nullptr);
    keyAgreement->base.destroy(&g_obj);
    HcfObjDestroy(keyAgreement);
}

HWTEST_F(CryptoDHKeyAgreementTest, CryptoDHKeyAgreementTest007, TestSize.Level0)
{
    HcfKeyAgreement *keyAgreement = nullptr;
    HcfResult res = HcfKeyAgreementCreate(g_dh1536AlgoName.c_str(), &keyAgreement);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(keyAgreement, nullptr);

    const char *algName1 = keyAgreement->getAlgoName(nullptr);
    ASSERT_EQ(algName1, nullptr);

    const char *algName2 = keyAgreement->getAlgoName((HcfKeyAgreement *)(&g_obj));
    ASSERT_EQ(algName2, nullptr);
    HcfObjDestroy(keyAgreement);
}

HWTEST_F(CryptoDHKeyAgreementTest, CryptoDHKeyAgreementTest008, TestSize.Level0)
{
    HcfKeyAgreement *keyAgreement = nullptr;
    HcfResult res = HcfKeyAgreementCreate(g_dh1536AlgoName.c_str(), &keyAgreement);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(keyAgreement, nullptr);

    HcfBlob out = { .data = nullptr, .len = 0 };
    res = keyAgreement->generateSecret(keyAgreement, dh1536KeyPair_->priKey, nullptr, &out);
    ASSERT_EQ(res, HCF_INVALID_PARAMS);
    ASSERT_EQ(out.data, nullptr);
    ASSERT_EQ(out.len, (const unsigned int)0);

    res = keyAgreement->generateSecret(keyAgreement, nullptr, dh1536KeyPair_->pubKey, &out);
    ASSERT_EQ(res, HCF_INVALID_PARAMS);
    ASSERT_EQ(out.data, nullptr);
    ASSERT_EQ(out.len, (const unsigned int)0);

    res = keyAgreement->generateSecret((HcfKeyAgreement *)&g_obj, dh1536KeyPair_->priKey, dh1536KeyPair_->pubKey, &out);
    ASSERT_EQ(res, HCF_INVALID_PARAMS);
    ASSERT_EQ(out.data, nullptr);
    ASSERT_EQ(out.len, (const unsigned int)0);

    HcfFree(out.data);
    HcfObjDestroy(keyAgreement);
}

HcfKeyAgreementParams params = {
    .algo = HCF_ALG_DH,
};

HWTEST_F(CryptoDHKeyAgreementTest, CryptoDHKeyAgreementTest009, TestSize.Level0)
{
    HcfResult res = HcfKeyAgreementSpiDhCreate(&params, nullptr);

    ASSERT_EQ(res, HCF_INVALID_PARAMS);
}

HWTEST_F(CryptoDHKeyAgreementTest, CryptoDHKeyAgreementTest010, TestSize.Level0)
{
    HcfKeyAgreementSpi *spiObj = nullptr;
    HcfResult res = HcfKeyAgreementSpiDhCreate(&params, &spiObj);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(spiObj, nullptr);

    HcfBlob out = { .data = nullptr, .len = 0 };
    res = spiObj->engineGenerateSecret((HcfKeyAgreementSpi *)&g_obj, dh1536KeyPair_->priKey, dh1536KeyPair_->pubKey,
        &out);
    ASSERT_EQ(res, HCF_INVALID_PARAMS);
    res = spiObj->engineGenerateSecret(spiObj, (HcfPriKey *)&g_obj, dh1536KeyPair_->pubKey, &out);
    ASSERT_EQ(res, HCF_INVALID_PARAMS);
    res = spiObj->engineGenerateSecret(spiObj, dh1536KeyPair_->priKey, (HcfPubKey *)&g_obj, &out);
    ASSERT_EQ(res, HCF_INVALID_PARAMS);

    EVP_PKEY *pubPKey = NewEvpPkeyByDh(((HcfOpensslDhPubKey *)dh1536KeyPair_->pubKey)->pk, true);
    EXPECT_NE(pubPKey, nullptr);
    EVP_PKEY_free(pubPKey);
    HcfFree(out.data);
    HcfObjDestroy(spiObj);
}

HWTEST_F(CryptoDHKeyAgreementTest, CryptoDHKeyAgreementTest011, TestSize.Level0)
{
    HcfKeyAgreementSpi *spiObj = nullptr;
    HcfResult res = HcfKeyAgreementSpiDhCreate(&params, &spiObj);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(spiObj, nullptr);

    spiObj->base.destroy(nullptr);

    HcfObjDestroy(spiObj);
}

HWTEST_F(CryptoDHKeyAgreementTest, CryptoDHKeyAgreementTest012, TestSize.Level0)
{
    HcfKeyAgreementSpi *spiObj = nullptr;
    HcfResult res = HcfKeyAgreementSpiDhCreate(&params, &spiObj);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(spiObj, nullptr);

    spiObj->base.destroy(&g_obj);

    HcfObjDestroy(spiObj);
}

HWTEST_F(CryptoDHKeyAgreementTest, CryptoDHKeyAgreementTest013, TestSize.Level0)
{
    StartRecordMallocNum();
    HcfKeyAgreement *keyAgreement = nullptr;
    HcfResult res = HcfKeyAgreementCreate(g_dh1536AlgoName.c_str(), &keyAgreement);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(keyAgreement, nullptr);

    HcfBlob out = { .data = nullptr, .len = 0 };
    res = keyAgreement->generateSecret(keyAgreement, dh1536KeyPair_->priKey, dh1536KeyPair_->pubKey, &out);

    ASSERT_EQ(res, HCF_SUCCESS);
    HcfFree(out.data);
    HcfObjDestroy(keyAgreement);

    uint32_t mallocCount = GetMallocNum();

    for (uint32_t i = 0; i < mallocCount; i++) {
        ResetRecordMallocNum();
        SetMockMallocIndex(i);
        keyAgreement = nullptr;
        res = HcfKeyAgreementCreate(g_dh1536AlgoName.c_str(), &keyAgreement);

        if (res != HCF_SUCCESS) {
            continue;
        }

        HcfBlob tmpBlob = {
            .data = nullptr,
            .len = 0
        };
        res = keyAgreement->generateSecret(keyAgreement, dh1536KeyPair_->priKey, dh1536KeyPair_->pubKey, &tmpBlob);

        if (res != HCF_SUCCESS) {
            HcfObjDestroy(keyAgreement);
            continue;
        }

        HcfObjDestroy(keyAgreement);
        HcfFree(tmpBlob.data);
    }
    EndRecordMallocNum();
}

HWTEST_F(CryptoDHKeyAgreementTest, CryptoDHKeyAgreementTest014, TestSize.Level0)
{
    StartRecordOpensslCallNum();
    HcfKeyAgreement *keyAgreement = nullptr;
    HcfResult res = HcfKeyAgreementCreate(g_dh1536AlgoName.c_str(), &keyAgreement);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(keyAgreement, nullptr);

    HcfBlob out = { .data = nullptr, .len = 0 };
    res = keyAgreement->generateSecret(keyAgreement, dh1536KeyPair_->priKey, dh1536KeyPair_->pubKey, &out);

    ASSERT_EQ(res, HCF_SUCCESS);
    HcfFree(out.data);
    HcfObjDestroy(keyAgreement);

    uint32_t mallocCount = GetOpensslCallNum();

    for (uint32_t i = 0; i < mallocCount; i++) {
        ResetOpensslCallNum();
        SetOpensslCallMockIndex(i);
        keyAgreement = nullptr;
        res = HcfKeyAgreementCreate(g_dh1536AlgoName.c_str(), &keyAgreement);

        if (res != HCF_SUCCESS) {
            continue;
        }

        HcfBlob tmpBlob = {
            .data = nullptr,
            .len = 0
        };
        res = keyAgreement->generateSecret(keyAgreement, dh1536KeyPair_->priKey, dh1536KeyPair_->pubKey, &tmpBlob);

        if (res != HCF_SUCCESS) {
            HcfObjDestroy(keyAgreement);
            continue;
        }

        HcfObjDestroy(keyAgreement);
        HcfFree(tmpBlob.data);
    }
    EndRecordOpensslCallNum();
}

HWTEST_F(CryptoDHKeyAgreementTest, CryptoDHKeyAgreementTest015, TestSize.Level0)
{
    HcfKeyAgreement *keyAgreement = nullptr;
    HcfResult res = HcfKeyAgreementCreate(g_dh3072AlgoName.c_str(), &keyAgreement);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(keyAgreement, nullptr);

    HcfBlob out = { .data = nullptr, .len = 0 };
    res = keyAgreement->generateSecret(keyAgreement, dh3072KeyPair2_->priKey, dh3072KeyPair1_->pubKey, &out);

    ASSERT_EQ(res, HCF_SUCCESS);

    HcfObjDestroy(keyAgreement);
    HcfFree(out.data);
}

HWTEST_F(CryptoDHKeyAgreementTest, CryptoDHKeyAgreementTest016, TestSize.Level0)
{
    HcfAsyKeyGenerator *generator = nullptr;
    HcfResult res = HcfAsyKeyGeneratorCreate("DH_ffdhe3072", &generator);
    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(generator, nullptr);

    HcfKeyPair *ffdhe3072keyPair1 = nullptr;
    res = generator->generateKeyPair(generator, nullptr, &ffdhe3072keyPair1);
    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(ffdhe3072keyPair1, nullptr);

    HcfKeyPair *ffdhe3072keyPair2 = nullptr;
    res = generator->generateKeyPair(generator, nullptr, &ffdhe3072keyPair2);
    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(ffdhe3072keyPair2, nullptr);

    HcfKeyAgreement *keyAgreement = nullptr;
    res = HcfKeyAgreementCreate("DH_ffdhe3072", &keyAgreement);
    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(keyAgreement, nullptr);

    HcfBlob outBlob1 = { .data = nullptr, .len = 0 };
    res = keyAgreement->generateSecret(keyAgreement, ffdhe3072keyPair1->priKey, ffdhe3072keyPair2->pubKey, &outBlob1);
    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(outBlob1.data, nullptr);
    ASSERT_NE(outBlob1.len, (const unsigned int)0);

    HcfBlob outBlob2 = { .data = nullptr, .len = 0 };
    res = keyAgreement->generateSecret(keyAgreement, ffdhe3072keyPair2->priKey, ffdhe3072keyPair1->pubKey, &outBlob2);
    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(outBlob2.data, nullptr);
    ASSERT_NE(outBlob2.len, (const unsigned int)0);

    bool flag = true;
    if (*(outBlob1.data) != *(outBlob2.data)) {
        flag = false;
    }
    EXPECT_EQ(flag, true);
    ASSERT_EQ(outBlob1.len, outBlob2.len);

    HcfObjDestroy(keyAgreement);
    HcfObjDestroy(generator);
    HcfObjDestroy(ffdhe3072keyPair1);
    HcfObjDestroy(ffdhe3072keyPair2);
    HcfFree(outBlob1.data);
    HcfFree(outBlob2.data);
}

HWTEST_F(CryptoDHKeyAgreementTest, CryptoDHKeyAgreementTest017, TestSize.Level0)
{
    HcfDhCommParamsSpec *returnCommonParamSpec = nullptr;
    HcfResult res = HcfDhKeyUtilCreate(PLEN_DH512, SKLEN_DH128, &returnCommonParamSpec);
    ASSERT_EQ(res, HCF_SUCCESS);

    HcfAsyKeyGeneratorBySpec *generator = nullptr;
    res = HcfAsyKeyGeneratorBySpecCreate(reinterpret_cast<HcfAsyKeyParamsSpec *>(returnCommonParamSpec), &generator);
    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(generator, nullptr);

    HcfKeyPair *dh512KeyPair = nullptr;
    res = generator->generateKeyPair(generator, &dh512KeyPair);
    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(dh512KeyPair, nullptr);

    HcfKeyAgreement *keyAgreement = nullptr;
    res = HcfKeyAgreementCreate("DH", &keyAgreement);
    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(keyAgreement, nullptr);

    HcfBlob out = { .data = nullptr, .len = 0 };
    res = keyAgreement->generateSecret(keyAgreement, dh512KeyPair->priKey, dh512KeyPair->pubKey, &out);
    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(out.data, nullptr);
    ASSERT_NE(out.len, 0);

    HcfObjDestroy(keyAgreement);
    HcfObjDestroy(generator);
    HcfObjDestroy(dh512KeyPair);
    HcfFree(out.data);
    FreeDhCommParamsSpec(returnCommonParamSpec);
    HcfFree(returnCommonParamSpec);
}

HWTEST_F(CryptoDHKeyAgreementTest, CryptoDHKeyAgreementTest018, TestSize.Level0)
{
    HcfResult res = ExchangekeyAgreementWithDiffSkLen(PLEN_DH512, SKLEN_DH128, 0);
    ASSERT_EQ(res, HCF_ERR_CRYPTO_OPERATION);
}

HWTEST_F(CryptoDHKeyAgreementTest, CryptoDHKeyAgreementTest019, TestSize.Level0)
{
    HcfDhCommParamsSpec *returnCommonParamSpec = nullptr;
    HcfResult res = HcfDhKeyUtilCreate(PLEN_DH2048, 0, &returnCommonParamSpec);
    ASSERT_EQ(res, HCF_SUCCESS);

    HcfAsyKeyGeneratorBySpec *generator = nullptr;
    res = HcfAsyKeyGeneratorBySpecCreate(reinterpret_cast<HcfAsyKeyParamsSpec *>(returnCommonParamSpec), &generator);
    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(generator, nullptr);

    HcfKeyPair *dh2048KeyPair = nullptr;
    res = generator->generateKeyPair(generator, &dh2048KeyPair);
    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(dh2048KeyPair, nullptr);

    HcfKeyAgreement *keyAgreement = nullptr;
    res = HcfKeyAgreementCreate("DH", &keyAgreement);
    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(keyAgreement, nullptr);

    HcfBlob out = { .data = nullptr, .len = 0 };
    res = keyAgreement->generateSecret(keyAgreement, dh2048KeyPair->priKey, dh2048KeyPair->pubKey, &out);
    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(out.data, nullptr);
    ASSERT_NE(out.len, 0);

    HcfFree(out.data);
    HcfObjDestroy(keyAgreement);
    HcfObjDestroy(generator);
    HcfObjDestroy(dh2048KeyPair);
    FreeDhCommParamsSpec(returnCommonParamSpec);
    HcfFree(returnCommonParamSpec);
}

HWTEST_F(CryptoDHKeyAgreementTest, CryptoDHKeyAgreementTest020, TestSize.Level0)
{
    HcfResult res = ExchangekeyAgreementWithDiffSkLen(PLEN_DH2048, SKLEN_DH1024, SKLEN_DH512);
    ASSERT_EQ(res, HCF_SUCCESS);
}

HWTEST_F(CryptoDHKeyAgreementTest, CryptoDHKeyAgreementTest021, TestSize.Level0)
{
    HcfDhCommParamsSpec *paramSpec = nullptr;
    HcfResult res = HcfDhKeyUtilCreate(PLEN_DH512, 0, &paramSpec);
    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(paramSpec, nullptr);

    HcfAsyKeyGeneratorBySpec *generator = nullptr;
    res = HcfAsyKeyGeneratorBySpecCreate(reinterpret_cast<HcfAsyKeyParamsSpec *>(paramSpec), &generator);
    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(generator, nullptr);

    HcfKeyPair *dh512KeyPair = nullptr;
    res = generator->generateKeyPair(generator, &dh512KeyPair);
    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(dh512KeyPair, nullptr);

    paramSpec->length = SKLEN_DH128;
    HcfAsyKeyGeneratorBySpec *generator1 = nullptr;
    res = HcfAsyKeyGeneratorBySpecCreate(reinterpret_cast<HcfAsyKeyParamsSpec *>(paramSpec), &generator1);
    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(generator1, nullptr);

    HcfKeyPair *dh512KeyPair1 = nullptr;
    res = generator1->generateKeyPair(generator1, &dh512KeyPair1);
    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(dh512KeyPair1, nullptr);

    HcfKeyAgreement *keyAgreement = nullptr;
    res = HcfKeyAgreementCreate("DH", &keyAgreement);
    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(keyAgreement, nullptr);

    HcfBlob out = { .data = nullptr, .len = 0 };
    res = keyAgreement->generateSecret(keyAgreement, dh512KeyPair->priKey, dh512KeyPair1->pubKey, &out);
    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(out.data, nullptr);
    ASSERT_NE(out.len, 0);

    HcfBlob out1 = { .data = nullptr, .len = 0 };
    res = keyAgreement->generateSecret(keyAgreement, dh512KeyPair1->priKey, dh512KeyPair->pubKey, &out1);
    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(out1.data, nullptr);
    ASSERT_NE(out1.len, 0);

    HcfFree(out.data);
    HcfFree(out1.data);
    HcfObjDestroy(keyAgreement);
    HcfObjDestroy(generator);
    HcfObjDestroy(generator1);
    HcfObjDestroy(dh512KeyPair);
    HcfObjDestroy(dh512KeyPair1);
    FreeDhCommParamsSpec(paramSpec);
    HcfFree(paramSpec);
}

HWTEST_F(CryptoDHKeyAgreementTest, CryptoDHCommonTest01, TestSize.Level0)
{
    int32_t id = -1;
    EXPECT_EQ(GetNidNameByDhId(id), nullptr);
    EXPECT_EQ(GetNidNameByDhPLen(id), nullptr);
}
}
