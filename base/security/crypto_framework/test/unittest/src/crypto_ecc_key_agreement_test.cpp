/*
 * Copyright (C) 2022-2023 Huawei Device Co., Ltd.
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
#include "ecdh_openssl.h"
#include "key_agreement.h"
#include "memory.h"
#include "memory_mock.h"
#include "openssl_adapter_mock.h"
#include "params_parser.h"
#include "ecc_openssl_common.h"

using namespace std;
using namespace testing::ext;

static string g_testEccSecp256k1PriKey = "-----BEGIN PRIVATE KEY-----\n"
"MIGEAgEAMBAGByqGSM49AgEGBSuBBAAKBG0wawIBAQQgHCRzy0IcEx6CeA6ogNNK\n"
"SOfuTlHy4fE/LNxkANUS4k+hRANCAASDBmwKklX4OcbZSJJX9mxm1Wr7TPTLpbyp\n"
"xKcKRm0XKNxVlrZU8WQCl66GtX2DDyX+0+XiC3hbaRWcYtg7P6WO\n"
"-----END PRIVATE KEY-----\n";

static string g_testEccSecp256k1PubKey = "-----BEGIN PUBLIC KEY-----\n"
"MFYwEAYHKoZIzj0CAQYFK4EEAAoDQgAEBUKCHJHsvlcod0MCVlFHylzW241nveMm\n"
"RAFhryNgX6rVqooGReVUm+WiF7Uz0ZsIjdHKd9HHe+2BOWfnuWyR1A==\n"
"-----END PUBLIC KEY-----\n";

static uint8_t SharedSecret[] = {0xaf, 0x43, 0xb5, 0x27, 0x90, 0x08, 0x2f, 0xd8,
                                 0x7a, 0xfb, 0x1d, 0x14, 0xb8, 0x83, 0xc1, 0x2d,
                                 0x12, 0xbb, 0x9e, 0x55, 0x40, 0x80, 0xd1, 0xf8,
                                 0xe5, 0x27, 0x92, 0x06, 0x76, 0xe3, 0x1f, 0x3e};

namespace {
class CryptoEccKeyAgreementTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp();
    void TearDown();

    static HcfKeyPair *ecc224KeyPair_;
    static HcfKeyPair *ecc256KeyPair_;
    static HcfKeyPair *ecc384KeyPair_;
    static HcfKeyPair *ecc521KeyPair_;
};

HcfKeyPair *CryptoEccKeyAgreementTest::ecc224KeyPair_ = nullptr;
HcfKeyPair *CryptoEccKeyAgreementTest::ecc256KeyPair_ = nullptr;
HcfKeyPair *CryptoEccKeyAgreementTest::ecc384KeyPair_ = nullptr;
HcfKeyPair *CryptoEccKeyAgreementTest::ecc521KeyPair_ = nullptr;

void CryptoEccKeyAgreementTest::SetUp() {}
void CryptoEccKeyAgreementTest::TearDown() {}

void CryptoEccKeyAgreementTest::SetUpTestCase()
{
    HcfAsyKeyGenerator *generator = nullptr;
    int32_t res = HcfAsyKeyGeneratorCreate("ECC224", &generator);
    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(generator, nullptr);

    HcfKeyPair *keyPair = nullptr;
    res = generator->generateKeyPair(generator, nullptr, &keyPair);
    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(keyPair, nullptr);

    ecc224KeyPair_ = keyPair;

    HcfObjDestroy(generator);

    HcfAsyKeyGenerator *generator2 = nullptr;
    res = HcfAsyKeyGeneratorCreate("ECC256", &generator2);
    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(generator2, nullptr);

    HcfKeyPair *keyPair2 = nullptr;
    res = generator2->generateKeyPair(generator2, nullptr, &keyPair2);
    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(keyPair2, nullptr);

    ecc256KeyPair_ = keyPair2;

    HcfObjDestroy(generator2);

    HcfAsyKeyGenerator *generator3 = nullptr;
    res = HcfAsyKeyGeneratorCreate("ECC384", &generator3);
    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(generator3, nullptr);

    HcfKeyPair *keyPair3 = nullptr;
    res = generator3->generateKeyPair(generator3, nullptr, &keyPair3);
    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(keyPair3, nullptr);

    ecc384KeyPair_ = keyPair3;

    HcfObjDestroy(generator3);

    HcfAsyKeyGenerator *generator4 = nullptr;
    res = HcfAsyKeyGeneratorCreate("ECC521", &generator4);
    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(generator4, nullptr);

    HcfKeyPair *keyPair4 = nullptr;
    res = generator4->generateKeyPair(generator4, nullptr, &keyPair4);
    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(keyPair4, nullptr);

    ecc521KeyPair_ = keyPair4;

    HcfObjDestroy(generator4);
}

void CryptoEccKeyAgreementTest::TearDownTestCase()
{
    HcfObjDestroy(ecc224KeyPair_);
    HcfObjDestroy(ecc256KeyPair_);
    HcfObjDestroy(ecc384KeyPair_);
    HcfObjDestroy(ecc521KeyPair_);
}

static const char *GetMockClass(void)
{
    return "HcfSymKeyGenerator";
}

static HcfObjectBase obj = {
    .getClass = GetMockClass,
    .destroy = nullptr
};

HWTEST_F(CryptoEccKeyAgreementTest, CryptoEccKeyAgreementTest001, TestSize.Level0)
{
    HcfKeyAgreement *keyAgreement = nullptr;
    int32_t res = HcfKeyAgreementCreate("ECC224", &keyAgreement);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(keyAgreement, nullptr);

    HcfObjDestroy(keyAgreement);
}

HWTEST_F(CryptoEccKeyAgreementTest, CryptoEccKeyAgreementTest002, TestSize.Level0)
{
    HcfKeyAgreement *keyAgreement = nullptr;
    int32_t res = HcfKeyAgreementCreate("ECC256", &keyAgreement);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(keyAgreement, nullptr);

    HcfObjDestroy(keyAgreement);
}

HWTEST_F(CryptoEccKeyAgreementTest, CryptoEccKeyAgreementTest003, TestSize.Level0)
{
    HcfKeyAgreement *keyAgreement = nullptr;
    int32_t res = HcfKeyAgreementCreate("ECC384", &keyAgreement);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(keyAgreement, nullptr);

    HcfObjDestroy(keyAgreement);
}

HWTEST_F(CryptoEccKeyAgreementTest, CryptoEccKeyAgreementTest004, TestSize.Level0)
{
    HcfKeyAgreement *keyAgreement = nullptr;
    int32_t res = HcfKeyAgreementCreate("ECC521", &keyAgreement);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(keyAgreement, nullptr);

    HcfObjDestroy(keyAgreement);
}

HWTEST_F(CryptoEccKeyAgreementTest, CryptoEccKeyAgreementTest004Nistp192, TestSize.Level0)
{
    HcfKeyAgreement *keyAgreement = nullptr;
    int32_t res = HcfKeyAgreementCreate("ECC192", &keyAgreement);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(keyAgreement, nullptr);

    HcfObjDestroy(keyAgreement);
}

HWTEST_F(CryptoEccKeyAgreementTest, CryptoEccKeyAgreementTest005, TestSize.Level0)
{
    HcfKeyAgreement *keyAgreement = nullptr;
    int32_t res = HcfKeyAgreementCreate(nullptr, &keyAgreement);

    ASSERT_EQ(res, HCF_INVALID_PARAMS);
    ASSERT_EQ(keyAgreement, nullptr);
}

HWTEST_F(CryptoEccKeyAgreementTest, CryptoEccKeyAgreementTest006, TestSize.Level0)
{
    HcfKeyAgreement *keyAgreement = nullptr;
    int32_t res = HcfKeyAgreementCreate("ABCDABCDABCDABCDABCDABCDABCDABCDABCDABCDABCDABCDABCDABCDABCDABCDABCDABCD"
        "ABCDABCDABCDABCDABCDABCDABCDABCDABCDABCDABCDABCDABCDABCD", &keyAgreement);

    ASSERT_EQ(res, HCF_INVALID_PARAMS);
    ASSERT_EQ(keyAgreement, nullptr);
}

HWTEST_F(CryptoEccKeyAgreementTest, CryptoEccKeyAgreementTest007, TestSize.Level0)
{
    HcfKeyAgreement *keyAgreement = nullptr;
    int32_t res = HcfKeyAgreementCreate("ECC257", &keyAgreement);

    ASSERT_EQ(res, HCF_INVALID_PARAMS);
    ASSERT_EQ(keyAgreement, nullptr);
}

HWTEST_F(CryptoEccKeyAgreementTest, CryptoEccKeyAgreementTest008, TestSize.Level0)
{
    int32_t res = HcfKeyAgreementCreate("ECC256", nullptr);

    ASSERT_EQ(res, HCF_INVALID_PARAMS);
}

HWTEST_F(CryptoEccKeyAgreementTest, CryptoEccKeyAgreementTest101, TestSize.Level0)
{
    HcfKeyAgreement *keyAgreement = nullptr;
    int32_t res = HcfKeyAgreementCreate("ECC256", &keyAgreement);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(keyAgreement, nullptr);

    const char *className = keyAgreement->base.getClass();

    ASSERT_NE(className, nullptr);

    HcfObjDestroy(keyAgreement);
}

HWTEST_F(CryptoEccKeyAgreementTest, CryptoEccKeyAgreementTest102, TestSize.Level0)
{
    HcfKeyAgreement *keyAgreement = nullptr;
    int32_t res = HcfKeyAgreementCreate("ECC256", &keyAgreement);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(keyAgreement, nullptr);

    keyAgreement->base.destroy((HcfObjectBase *)keyAgreement);
}

HWTEST_F(CryptoEccKeyAgreementTest, CryptoEccKeyAgreementTest103, TestSize.Level0)
{
    HcfKeyAgreement *keyAgreement = nullptr;
    int32_t res = HcfKeyAgreementCreate("ECC256", &keyAgreement);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(keyAgreement, nullptr);

    keyAgreement->base.destroy(nullptr);

    HcfObjDestroy(keyAgreement);
}

HWTEST_F(CryptoEccKeyAgreementTest, CryptoEccKeyAgreementTest104, TestSize.Level0)
{
    HcfKeyAgreement *keyAgreement = nullptr;
    int32_t res = HcfKeyAgreementCreate("ECC256", &keyAgreement);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(keyAgreement, nullptr);

    keyAgreement->base.destroy(&obj);

    HcfObjDestroy(keyAgreement);
}

HWTEST_F(CryptoEccKeyAgreementTest, CryptoEccKeyAgreementTest105, TestSize.Level0)
{
    HcfKeyAgreement *keyAgreement = nullptr;
    int32_t res = HcfKeyAgreementCreate("ECC256", &keyAgreement);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(keyAgreement, nullptr);

    const char *algName = keyAgreement->getAlgoName(keyAgreement);

    ASSERT_NE(algName, nullptr);

    HcfObjDestroy(keyAgreement);
}

HWTEST_F(CryptoEccKeyAgreementTest, CryptoEccKeyAgreementTest106, TestSize.Level0)
{
    HcfKeyAgreement *keyAgreement = nullptr;
    int32_t res = HcfKeyAgreementCreate("ECC256", &keyAgreement);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(keyAgreement, nullptr);

    const char *algName = keyAgreement->getAlgoName(nullptr);

    ASSERT_EQ(algName, nullptr);

    HcfObjDestroy(keyAgreement);
}

HWTEST_F(CryptoEccKeyAgreementTest, CryptoEccKeyAgreementTest107, TestSize.Level0)
{
    HcfKeyAgreement *keyAgreement = nullptr;
    int32_t res = HcfKeyAgreementCreate("ECC256", &keyAgreement);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(keyAgreement, nullptr);

    const char *algName = keyAgreement->getAlgoName((HcfKeyAgreement *)(&obj));

    ASSERT_EQ(algName, nullptr);

    HcfObjDestroy(keyAgreement);
}

HWTEST_F(CryptoEccKeyAgreementTest, CryptoEccKeyAgreementTest201, TestSize.Level0)
{
    HcfKeyAgreement *keyAgreement = nullptr;
    int32_t res = HcfKeyAgreementCreate("ECC224", &keyAgreement);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(keyAgreement, nullptr);

    HcfBlob out = { .data = nullptr, .len = 0 };
    res = keyAgreement->generateSecret(keyAgreement, ecc224KeyPair_->priKey, ecc224KeyPair_->pubKey, &out);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(out.data, nullptr);
    ASSERT_NE(out.len, (const unsigned int)0);

    HcfFree(out.data);
    HcfObjDestroy(keyAgreement);
}

HWTEST_F(CryptoEccKeyAgreementTest, CryptoEccKeyAgreementTest202, TestSize.Level0)
{
    HcfKeyAgreement *keyAgreement = nullptr;
    int32_t res = HcfKeyAgreementCreate("ECC256", &keyAgreement);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(keyAgreement, nullptr);

    HcfBlob out = { .data = nullptr, .len = 0 };
    res = keyAgreement->generateSecret(keyAgreement, ecc256KeyPair_->priKey, ecc256KeyPair_->pubKey, &out);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(out.data, nullptr);
    ASSERT_NE(out.len, (const unsigned int)0);

    HcfFree(out.data);
    HcfObjDestroy(keyAgreement);
}

HWTEST_F(CryptoEccKeyAgreementTest, CryptoEccKeyAgreementTest203, TestSize.Level0)
{
    HcfKeyAgreement *keyAgreement = nullptr;
    int32_t res = HcfKeyAgreementCreate("ECC384", &keyAgreement);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(keyAgreement, nullptr);

    HcfBlob out = { .data = nullptr, .len = 0 };
    res = keyAgreement->generateSecret(keyAgreement, ecc384KeyPair_->priKey, ecc384KeyPair_->pubKey, &out);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(out.data, nullptr);
    ASSERT_NE(out.len, (const unsigned int)0);

    HcfFree(out.data);
    HcfObjDestroy(keyAgreement);
}

HWTEST_F(CryptoEccKeyAgreementTest, CryptoEccKeyAgreementTest204, TestSize.Level0)
{
    HcfKeyAgreement *keyAgreement = nullptr;
    int32_t res = HcfKeyAgreementCreate("ECC521", &keyAgreement);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(keyAgreement, nullptr);

    HcfBlob out = { .data = nullptr, .len = 0 };
    res = keyAgreement->generateSecret(keyAgreement, ecc521KeyPair_->priKey, ecc521KeyPair_->pubKey, &out);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(out.data, nullptr);
    ASSERT_NE(out.len, (const unsigned int)0);

    HcfFree(out.data);
    HcfObjDestroy(keyAgreement);
}

HWTEST_F(CryptoEccKeyAgreementTest, CryptoEccKeyAgreementTest205, TestSize.Level0)
{
    HcfKeyAgreement *keyAgreement = nullptr;
    int32_t res = HcfKeyAgreementCreate("ECC256", &keyAgreement);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(keyAgreement, nullptr);

    HcfBlob out = { .data = nullptr, .len = 0 };
    res = keyAgreement->generateSecret(nullptr, ecc256KeyPair_->priKey, ecc256KeyPair_->pubKey, &out);

    ASSERT_EQ(res, HCF_INVALID_PARAMS);
    ASSERT_EQ(out.data, nullptr);
    ASSERT_EQ(out.len, 0);

    HcfObjDestroy(keyAgreement);
}

HWTEST_F(CryptoEccKeyAgreementTest, CryptoEccKeyAgreementTest206, TestSize.Level0)
{
    HcfKeyAgreement *keyAgreement = nullptr;
    int32_t res = HcfKeyAgreementCreate("ECC256", &keyAgreement);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(keyAgreement, nullptr);

    HcfBlob out = { .data = nullptr, .len = 0 };
    res = keyAgreement->generateSecret((HcfKeyAgreement *)(&obj), ecc256KeyPair_->priKey, ecc256KeyPair_->pubKey, &out);

    ASSERT_EQ(res, HCF_INVALID_PARAMS);
    ASSERT_EQ(out.data, nullptr);
    ASSERT_EQ(out.len, 0);

    HcfObjDestroy(keyAgreement);
}

HWTEST_F(CryptoEccKeyAgreementTest, CryptoEccKeyAgreementTest207, TestSize.Level0)
{
    HcfKeyAgreement *keyAgreement = nullptr;
    int32_t res = HcfKeyAgreementCreate("ECC256", &keyAgreement);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(keyAgreement, nullptr);

    HcfBlob out = { .data = nullptr, .len = 0 };
    res = keyAgreement->generateSecret(keyAgreement, (HcfPriKey *)(&obj), ecc256KeyPair_->pubKey, &out);

    ASSERT_EQ(res, HCF_INVALID_PARAMS);
    ASSERT_EQ(out.data, nullptr);
    ASSERT_EQ(out.len, 0);

    HcfObjDestroy(keyAgreement);
}

HWTEST_F(CryptoEccKeyAgreementTest, CryptoEccKeyAgreementTest208, TestSize.Level0)
{
    HcfKeyAgreement *keyAgreement = nullptr;
    int32_t res = HcfKeyAgreementCreate("ECC256", &keyAgreement);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(keyAgreement, nullptr);

    HcfBlob out = { .data = nullptr, .len = 0 };
    res = keyAgreement->generateSecret(keyAgreement, ecc256KeyPair_->priKey, (HcfPubKey *)(&obj), &out);

    ASSERT_EQ(res, HCF_INVALID_PARAMS);
    ASSERT_EQ(out.data, nullptr);
    ASSERT_EQ(out.len, 0);

    HcfObjDestroy(keyAgreement);
}

HWTEST_F(CryptoEccKeyAgreementTest, CryptoEccKeyAgreementTest209, TestSize.Level0)
{
    HcfKeyAgreement *keyAgreement = nullptr;
    int32_t res = HcfKeyAgreementCreate("ECC256", &keyAgreement);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(keyAgreement, nullptr);

    HcfBlob out = { .data = nullptr, .len = 0 };
    res = keyAgreement->generateSecret(keyAgreement, nullptr, nullptr, &out);

    ASSERT_EQ(res, HCF_INVALID_PARAMS);
    ASSERT_EQ(out.data, nullptr);
    ASSERT_EQ(out.len, 0);

    HcfObjDestroy(keyAgreement);
}

HWTEST_F(CryptoEccKeyAgreementTest, CryptoEccKeyAgreementTest210, TestSize.Level0)
{
    HcfKeyAgreement *keyAgreement = nullptr;
    int32_t res = HcfKeyAgreementCreate("ECC256", &keyAgreement);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(keyAgreement, nullptr);

    res = keyAgreement->generateSecret(keyAgreement, ecc256KeyPair_->priKey, ecc256KeyPair_->pubKey, nullptr);

    ASSERT_EQ(res, HCF_INVALID_PARAMS);

    HcfObjDestroy(keyAgreement);
}

HWTEST_F(CryptoEccKeyAgreementTest, CryptoEccKeyAgreementTest301, TestSize.Level0)
{
    HcfKeyAgreementSpi *spiObj = nullptr;
    int32_t res = HcfKeyAgreementSpiEcdhCreate(nullptr, &spiObj);

    ASSERT_EQ(res, HCF_INVALID_PARAMS);
    ASSERT_EQ(spiObj, nullptr);
}

HWTEST_F(CryptoEccKeyAgreementTest, CryptoEccKeyAgreementTest302, TestSize.Level0)
{
    HcfKeyAgreementParams params = {
        .algo = HCF_ALG_ECC,
    };

    int32_t res = HcfKeyAgreementSpiEcdhCreate(&params, nullptr);

    ASSERT_EQ(res, HCF_INVALID_PARAMS);
}

HWTEST_F(CryptoEccKeyAgreementTest, CryptoEccKeyAgreementTest304, TestSize.Level0)
{
    HcfKeyAgreementParams params = {
        .algo = HCF_ALG_ECC,
    };

    HcfKeyAgreementSpi *spiObj = nullptr;
    int32_t res = HcfKeyAgreementSpiEcdhCreate(&params, &spiObj);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(spiObj, nullptr);

    HcfBlob out = { .data = nullptr, .len = 0 };
    res = spiObj->engineGenerateSecret((HcfKeyAgreementSpi *)&obj,
        ecc256KeyPair_->priKey, ecc256KeyPair_->pubKey, &out);
    ASSERT_EQ(res, HCF_INVALID_PARAMS);

    HcfObjDestroy(spiObj);
}

HWTEST_F(CryptoEccKeyAgreementTest, CryptoEccKeyAgreementTest305, TestSize.Level0)
{
    HcfKeyAgreementParams params = {
        .algo = HCF_ALG_ECC,
    };

    HcfKeyAgreementSpi *spiObj = nullptr;
    int32_t res = HcfKeyAgreementSpiEcdhCreate(&params, &spiObj);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(spiObj, nullptr);

    HcfBlob out = { .data = nullptr, .len = 0 };
    res = spiObj->engineGenerateSecret(spiObj, (HcfPriKey *)&obj, ecc256KeyPair_->pubKey, &out);
    ASSERT_EQ(res, HCF_INVALID_PARAMS);

    HcfObjDestroy(spiObj);
}

HWTEST_F(CryptoEccKeyAgreementTest, CryptoEccKeyAgreementTest306, TestSize.Level0)
{
    HcfKeyAgreementParams params = {
        .algo = HCF_ALG_ECC,
    };

    HcfKeyAgreementSpi *spiObj = nullptr;
    int32_t res = HcfKeyAgreementSpiEcdhCreate(&params, &spiObj);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(spiObj, nullptr);

    HcfBlob out = { .data = nullptr, .len = 0 };
    res = spiObj->engineGenerateSecret(spiObj, ecc256KeyPair_->priKey, (HcfPubKey *)&obj, &out);
    ASSERT_EQ(res, HCF_INVALID_PARAMS);

    HcfObjDestroy(spiObj);
}

HWTEST_F(CryptoEccKeyAgreementTest, CryptoEccKeyAgreementTest307, TestSize.Level0)
{
    HcfKeyAgreementParams params = {
        .algo = HCF_ALG_ECC,
    };

    HcfKeyAgreementSpi *spiObj = nullptr;
    int32_t res = HcfKeyAgreementSpiEcdhCreate(&params, &spiObj);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(spiObj, nullptr);

    spiObj->base.destroy(nullptr);

    HcfObjDestroy(spiObj);
}

HWTEST_F(CryptoEccKeyAgreementTest, CryptoEccKeyAgreementTest308, TestSize.Level0)
{
    HcfKeyAgreementParams params = {
        .algo = HCF_ALG_ECC,
    };

    HcfKeyAgreementSpi *spiObj = nullptr;
    int32_t res = HcfKeyAgreementSpiEcdhCreate(&params, &spiObj);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(spiObj, nullptr);

    spiObj->base.destroy(&obj);

    HcfObjDestroy(spiObj);
}

HWTEST_F(CryptoEccKeyAgreementTest, CryptoEccKeyAgreementTest309, TestSize.Level0)
{
    HcfKeyAgreementParams params = {
        .algo = HCF_ALG_ECC,
    };

    HcfKeyAgreementSpi *spiObj = nullptr;
    int32_t res = HcfKeyAgreementSpiEcdhCreate(&params, &spiObj);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(spiObj, nullptr);

    HcfBlob out = { .data = nullptr, .len = 0 };
    res = spiObj->engineGenerateSecret(spiObj, ecc256KeyPair_->priKey, nullptr, &out);
    ASSERT_EQ(res, HCF_INVALID_PARAMS);

    HcfObjDestroy(spiObj);
}

HWTEST_F(CryptoEccKeyAgreementTest, CryptoEccKeyAgreementTest310, TestSize.Level0)
{
    HcfKeyAgreementParams params = {
        .algo = HCF_ALG_ECC,
    };

    HcfKeyAgreementSpi *spiObj = nullptr;
    int32_t res = HcfKeyAgreementSpiEcdhCreate(&params, &spiObj);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(spiObj, nullptr);

    HcfBlob out = { .data = nullptr, .len = 0 };
    res = spiObj->engineGenerateSecret(nullptr, ecc256KeyPair_->priKey, nullptr, &out);
    ASSERT_EQ(res, HCF_INVALID_PARAMS);

    HcfObjDestroy(spiObj);
}

HWTEST_F(CryptoEccKeyAgreementTest, CryptoEccKeyAgreementTest401, TestSize.Level0)
{
    StartRecordMallocNum();
    HcfKeyAgreement *keyAgreement = nullptr;
    int32_t res = HcfKeyAgreementCreate("ECC256", &keyAgreement);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(keyAgreement, nullptr);

    HcfBlob out = { .data = nullptr, .len = 0 };
    res = keyAgreement->generateSecret(keyAgreement, ecc256KeyPair_->priKey, ecc256KeyPair_->pubKey, &out);

    ASSERT_EQ(res, HCF_SUCCESS);
    HcfFree(out.data);

    HcfObjDestroy(keyAgreement);

    uint32_t mallocCount = GetMallocNum();

    for (uint32_t i = 0; i < mallocCount; i++) {
        ResetRecordMallocNum();
        SetMockMallocIndex(i);
        keyAgreement = nullptr;
        res = HcfKeyAgreementCreate("ECC256", &keyAgreement);

        if (res != HCF_SUCCESS) {
            continue;
        }

        out = {
            .data = nullptr,
            .len = 0
        };
        res = keyAgreement->generateSecret(keyAgreement, ecc256KeyPair_->priKey, ecc256KeyPair_->pubKey, &out);

        if (res != HCF_SUCCESS) {
            HcfObjDestroy(keyAgreement);
            continue;
        }

        HcfObjDestroy(keyAgreement);
        HcfFree(out.data);
    }
    EndRecordMallocNum();
}

HWTEST_F(CryptoEccKeyAgreementTest, CryptoEccKeyAgreementTest402, TestSize.Level0)
{
    StartRecordOpensslCallNum();
    HcfKeyAgreement *keyAgreement = nullptr;
    int32_t res = HcfKeyAgreementCreate("ECC256", &keyAgreement);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(keyAgreement, nullptr);

    HcfBlob out = { .data = nullptr, .len = 0 };
    res = keyAgreement->generateSecret(keyAgreement, ecc256KeyPair_->priKey, ecc256KeyPair_->pubKey, &out);

    ASSERT_EQ(res, HCF_SUCCESS);
    HcfFree(out.data);

    HcfObjDestroy(keyAgreement);

    uint32_t mallocCount = GetOpensslCallNum();

    for (uint32_t i = 0; i < mallocCount; i++) {
        ResetOpensslCallNum();
        SetOpensslCallMockIndex(i);
        keyAgreement = nullptr;
        res = HcfKeyAgreementCreate("ECC256", &keyAgreement);

        if (res != HCF_SUCCESS) {
            continue;
        }

        out = {
            .data = nullptr,
            .len = 0
        };
        res = keyAgreement->generateSecret(keyAgreement, ecc256KeyPair_->priKey, ecc256KeyPair_->pubKey, &out);

        if (res != HCF_SUCCESS) {
            HcfObjDestroy(keyAgreement);
            continue;
        }

        HcfObjDestroy(keyAgreement);
        HcfFree(out.data);
    }
    EndRecordOpensslCallNum();
}

HWTEST_F(CryptoEccKeyAgreementTest, CryptoEccCommonTest01, TestSize.Level0)
{
    HcfResult ret = GenerateEcGroupWithParamsSpec(nullptr, nullptr);
    EXPECT_EQ(ret, HCF_INVALID_PARAMS);
}

HWTEST_F(CryptoEccKeyAgreementTest, CryptoEccKeyAgreementTest403, TestSize.Level0)
{
    HcfKeyAgreement *keyAgreement = nullptr;
    int32_t res = HcfKeyAgreementCreate("ECC_Secp256k1", &keyAgreement);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(keyAgreement, nullptr);
    HcfBlob out = { .data = nullptr, .len = 0 };
    HcfKeyPair *eccSecp256k1KeyPair = nullptr;
    HcfAsyKeyGenerator *generator = nullptr;
    res = HcfAsyKeyGeneratorCreate("ECC_Secp256k1", &generator);
    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(generator, nullptr);

    res = generator->convertPemKey(generator, nullptr, g_testEccSecp256k1PubKey.c_str(),
        g_testEccSecp256k1PriKey.c_str(), &eccSecp256k1KeyPair);
    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(eccSecp256k1KeyPair, nullptr);

    res = keyAgreement->generateSecret(keyAgreement, eccSecp256k1KeyPair->priKey, eccSecp256k1KeyPair->pubKey, &out);
    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_EQ(out.len, sizeof(SharedSecret));
    for (int i = 0; i < out.len; i++) {
        ASSERT_EQ(out.data[i], SharedSecret[i]);
    }
    HcfObjDestroy(keyAgreement);
    HcfObjDestroy(eccSecp256k1KeyPair);
    HcfFree(out.data);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoEccKeyAgreementTest, CryptoEccKeyAgreementTest404, TestSize.Level0)
{
    HcfAsyKeyGenerator *generator = nullptr;
    int32_t res = HcfAsyKeyGeneratorCreate("ECC_Secp256k1", &generator);

    HcfKeyPair *keyPair1 = nullptr;
    res = generator->generateKeyPair(generator, nullptr, &keyPair1);
    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(keyPair1, nullptr);

    HcfKeyPair *keyPair2 = nullptr;
    res = generator->generateKeyPair(generator, nullptr, &keyPair2);
    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(keyPair2, nullptr);

    HcfKeyAgreement *keyAgreement = nullptr;
    res = HcfKeyAgreementCreate("ECC_Secp256k1", &keyAgreement);
    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(keyAgreement, nullptr);

    HcfBlob out1 = { .data = nullptr, .len = 0 };
    HcfBlob out2 = { .data = nullptr, .len = 0 };
    res = keyAgreement->generateSecret(keyAgreement, keyPair1->priKey, keyPair2->pubKey, &out1);
    ASSERT_EQ(res, HCF_SUCCESS);
    res = keyAgreement->generateSecret(keyAgreement, keyPair2->priKey, keyPair1->pubKey, &out2);
    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_EQ(out1.len, out2.len);
    for (int i = 0; i < out1.len; i++) {
        ASSERT_EQ(out1.data[i], out2.data[i]);
    }
    HcfObjDestroy(keyAgreement);
    HcfFree(out1.data);
    HcfFree(out2.data);
    HcfObjDestroy(keyPair1);
    HcfObjDestroy(keyPair2);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoEccKeyAgreementTest, CryptoEccKeyAgreementTest405, TestSize.Level0)
{
    HcfAsyKeyGenerator *generator = nullptr;
    int32_t res = HcfAsyKeyGeneratorCreate("ECC192", &generator);

    HcfKeyPair *keyPair1 = nullptr;
    res = generator->generateKeyPair(generator, nullptr, &keyPair1);
    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(keyPair1, nullptr);

    HcfKeyPair *keyPair2 = nullptr;
    res = generator->generateKeyPair(generator, nullptr, &keyPair2);
    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(keyPair2, nullptr);

    HcfKeyAgreement *keyAgreement = nullptr;
    res = HcfKeyAgreementCreate("ECC192", &keyAgreement);
    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(keyAgreement, nullptr);

    HcfBlob out1 = { .data = nullptr, .len = 0 };
    HcfBlob out2 = { .data = nullptr, .len = 0 };
    res = keyAgreement->generateSecret(keyAgreement, keyPair1->priKey, keyPair2->pubKey, &out1);
    ASSERT_EQ(res, HCF_SUCCESS);
    res = keyAgreement->generateSecret(keyAgreement, keyPair2->priKey, keyPair1->pubKey, &out2);
    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_EQ(out1.len, out2.len);
    for (int i = 0; i < out1.len; i++) {
        ASSERT_EQ(out1.data[i], out2.data[i]);
    }
    HcfObjDestroy(keyAgreement);
    HcfFree(out1.data);
    HcfFree(out2.data);
    HcfObjDestroy(keyPair1);
    HcfObjDestroy(keyPair2);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoEccKeyAgreementTest, CryptoEccKeyAgreementTest406, TestSize.Level0)
{
    HcfAsyKeyGenerator *generator = nullptr;
    HcfResult res = HcfAsyKeyGeneratorCreate("ECC192", &generator);
    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(generator, nullptr);
    HcfKeyAgreement *keyAgreement = nullptr;
    res = HcfKeyAgreementCreate("ECC192", &keyAgreement);
    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(keyAgreement, nullptr);

    HcfKeyPair *keyPair = nullptr;
    res = generator->generateKeyPair(generator, nullptr, &keyPair);
    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(keyPair, nullptr);

    HcfBlob out = { .data = nullptr, .len = 0 };
    res = keyAgreement->generateSecret(keyAgreement, keyPair->priKey, keyPair->pubKey, &out);
    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(out.data, nullptr);
    ASSERT_NE(out.len, 0);

    HcfFree(out.data);
    HcfObjDestroy(keyAgreement);
    HcfObjDestroy(keyPair);
    HcfObjDestroy(generator);
}

static void OpensslMockTestFuncGetPubKey(uint32_t mallocCount)
{
    for (uint32_t i = 0; i < mallocCount; i++) {
        ResetOpensslCallNum();
        SetOpensslCallMockIndex(i);

        HcfAsyKeyGenerator *tmpGenerator = nullptr;
        int32_t res = HcfAsyKeyGeneratorCreate("ECC_Secp256k1", &tmpGenerator);
        if (res != HCF_SUCCESS) {
            continue;
        }

        HcfKeyPair *tmpKeyPair1 = nullptr;
        res = tmpGenerator->generateKeyPair(tmpGenerator, nullptr, &tmpKeyPair1);
        if (res != HCF_SUCCESS) {
            HcfObjDestroy(tmpGenerator);
            continue;
        }

        HcfPubKey *tmpPubKey1 = nullptr;
        res = tmpKeyPair1->priKey->getPubKey(tmpKeyPair1->priKey, &tmpPubKey1);
        if (res != HCF_SUCCESS) {
            HcfObjDestroy(tmpKeyPair1);
            HcfObjDestroy(tmpGenerator);
            continue;
        }

        HcfKeyAgreement *tmpKeyAgreement = nullptr;
        res = HcfKeyAgreementCreate("ECC_Secp256k1", &tmpKeyAgreement);
        if (res != HCF_SUCCESS) {
            HcfObjDestroy(tmpPubKey1);
            HcfObjDestroy(tmpKeyPair1);
            HcfObjDestroy(tmpGenerator);
            continue;
        }

        HcfBlob tmpOut1 = { .data = nullptr, .len = 0 };
        res = tmpKeyAgreement->generateSecret(tmpKeyAgreement, tmpKeyPair1->priKey, tmpKeyPair1->pubKey, &tmpOut1);
        if (res == HCF_SUCCESS) {
            HcfFree(tmpOut1.data);
        }

        HcfObjDestroy(tmpPubKey1);
        HcfObjDestroy(tmpKeyAgreement);
        HcfObjDestroy(tmpKeyPair1);
        HcfObjDestroy(tmpGenerator);
    }
}

HWTEST_F(CryptoEccKeyAgreementTest, CryptoEccKeyAgreementPubKeyFromPriKeyTest, TestSize.Level0)
{
    HcfAsyKeyGenerator *generator = nullptr;
    int32_t res = HcfAsyKeyGeneratorCreate("ECC_Secp256k1", &generator);

    HcfKeyPair *keyPair1 = nullptr;
    res = generator->generateKeyPair(generator, nullptr, &keyPair1);
    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(keyPair1, nullptr);

    HcfKeyPair *keyPair2 = nullptr;
    res = generator->generateKeyPair(generator, nullptr, &keyPair2);
    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(keyPair2, nullptr);

    HcfKeyAgreement *keyAgreement = nullptr;
    res = HcfKeyAgreementCreate("ECC_Secp256k1", &keyAgreement);
    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(keyAgreement, nullptr);

    HcfBlob out1 = { .data = nullptr, .len = 0 };
    HcfBlob out2 = { .data = nullptr, .len = 0 };
    HcfPubKey *pubKey1 = nullptr;
    res = keyPair1->priKey->getPubKey(keyPair1->priKey, &pubKey1);
    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(pubKey1, nullptr);
    HcfPubKey *pubKey2 = nullptr;
    res = keyPair2->priKey->getPubKey(keyPair2->priKey, &pubKey2);
    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(pubKey2, nullptr);
    res = keyAgreement->generateSecret(keyAgreement, keyPair1->priKey, pubKey2, &out1);
    ASSERT_EQ(res, HCF_SUCCESS);
    res = keyAgreement->generateSecret(keyAgreement, keyPair2->priKey, pubKey1, &out2);
    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_EQ(out1.len, out2.len);
    for (int i = 0; i < out1.len; i++) {
        ASSERT_EQ(out1.data[i], out2.data[i]);
    }
    HcfObjDestroy(keyAgreement);
    HcfFree(out1.data);
    HcfFree(out2.data);
    HcfObjDestroy(pubKey1);
    HcfObjDestroy(pubKey2);
    HcfObjDestroy(keyPair1);
    HcfObjDestroy(keyPair2);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoEccKeyAgreementTest, CryptoEccKeyAgreementPubKeyFromPriKeyMockTest, TestSize.Level0)
{
    StartRecordOpensslCallNum();
    HcfAsyKeyGenerator *generator = nullptr;
    int32_t res = HcfAsyKeyGeneratorCreate("ECC_Secp256k1", &generator);
    ASSERT_EQ(res, HCF_SUCCESS);

    HcfKeyPair *keyPair1 = nullptr;
    res = generator->generateKeyPair(generator, nullptr, &keyPair1);
    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(keyPair1, nullptr);

    HcfKeyPair *keyPair2 = nullptr;
    res = generator->generateKeyPair(generator, nullptr, &keyPair2);
    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(keyPair2, nullptr);

    HcfKeyAgreement *keyAgreement = nullptr;
    res = HcfKeyAgreementCreate("ECC_Secp256k1", &keyAgreement);
    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(keyAgreement, nullptr);

    HcfBlob out1 = { .data = nullptr, .len = 0 };
    HcfBlob out2 = { .data = nullptr, .len = 0 };
    HcfPubKey *pubKey1 = nullptr;
    res = keyPair1->priKey->getPubKey(keyPair1->priKey, &pubKey1);
    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(pubKey1, nullptr);
    HcfPubKey *pubKey2 = nullptr;
    res = keyPair2->priKey->getPubKey(keyPair2->priKey, &pubKey2);
    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(pubKey2, nullptr);
    res = keyAgreement->generateSecret(keyAgreement, keyPair1->priKey, pubKey2, &out1);
    ASSERT_EQ(res, HCF_SUCCESS);
    res = keyAgreement->generateSecret(keyAgreement, keyPair2->priKey, pubKey1, &out2);
    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_EQ(out1.len, out2.len);
    for (int i = 0; i < out1.len; i++) {
        ASSERT_EQ(out1.data[i], out2.data[i]);
    }
    HcfObjDestroy(keyAgreement);
    HcfFree(out1.data);
    HcfFree(out2.data);
    HcfObjDestroy(pubKey1);
    HcfObjDestroy(pubKey2);
    HcfObjDestroy(keyPair1);
    HcfObjDestroy(keyPair2);
    HcfObjDestroy(generator);

    uint32_t mallocCount = GetOpensslCallNum();
    OpensslMockTestFuncGetPubKey(mallocCount);

    EndRecordOpensslCallNum();
}

HWTEST_F(CryptoEccKeyAgreementTest, CryptoEccKeyAgreementPubKeyFromPriKeyErrTest, TestSize.Level0)
{
    HcfAsyKeyGenerator *generator = nullptr;
    int32_t res = HcfAsyKeyGeneratorCreate("ECC_Secp256k1", &generator);
    ASSERT_EQ(res, HCF_SUCCESS);

    HcfKeyPair *keyPair = nullptr;
    res = generator->generateKeyPair(generator, nullptr, &keyPair);
    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(keyPair, nullptr);

    HcfPubKey *pubKey = nullptr;
    res = keyPair->priKey->getPubKey(nullptr, &pubKey);
    ASSERT_NE(res, HCF_SUCCESS);
    ASSERT_EQ(pubKey, nullptr);

    res = keyPair->priKey->getPubKey(keyPair->priKey, nullptr);
    ASSERT_NE(res, HCF_SUCCESS);

    res = keyPair->priKey->getPubKey((HcfPriKey *)&obj, &pubKey);
    ASSERT_NE(res, HCF_SUCCESS);
    ASSERT_EQ(pubKey, nullptr);

    HcfObjDestroy(keyPair);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoEccKeyAgreementTest, CryptoEccKeyApiErrTest, TestSize.Level0)
{
    HcfResult res = HcfSetPubKeyDataToNewEcKey(nullptr, nullptr);
    ASSERT_EQ(res, HCF_ERR_PARAMETER_CHECK_FAILED);
}
}
