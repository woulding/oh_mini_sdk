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

#include "asy_key_generator.h"
#include "ecc_common_param_spec.h"
#include "ecdh_openssl.h"
#include "key_agreement.h"
#include "ecc_key_util.h"
#include "memory.h"
#include "memory_mock.h"
#include "openssl_adapter_mock.h"
#include "params_parser.h"

using namespace std;
using namespace testing::ext;

namespace {
class CryptoBrainPoolKeyAgreementTest : public testing::Test {
public:
    static void SetUpTestCase() {};
    static void TearDownTestCase() {};
    void SetUp();
    void TearDown();
};

void CryptoBrainPoolKeyAgreementTest::SetUp() {}
void CryptoBrainPoolKeyAgreementTest::TearDown() {}

static const char *GetMockClass(void)
{
    return "HcfSymKeyGenerator";
}

static HcfObjectBase obj = {
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

HWTEST_F(CryptoBrainPoolKeyAgreementTest, CryptoBrainPoolKeyAgreementTest001, TestSize.Level0)
{
    HcfResult res = HcfKeyAgreementCreateTest("ECC_BrainPoolP160r1");
    ASSERT_EQ(res, HCF_SUCCESS);
}

HWTEST_F(CryptoBrainPoolKeyAgreementTest, CryptoBrainPoolKeyAgreementTest002, TestSize.Level0)
{
    HcfResult res = HcfKeyAgreementCreateTest(nullptr);
    ASSERT_NE(res, HCF_SUCCESS);
}

HWTEST_F(CryptoBrainPoolKeyAgreementTest, CryptoBrainPoolKeyAgreementTest003, TestSize.Level0)
{
    HcfResult res = HcfKeyAgreementCreateTest("ABCDABCDABCDABCDABCDABCDABCDABCDABCDABCDABCDABCDABCDABCDABCD"
        "ABCDABCDABCDABCDABCDABCDABCDABCDABCDABCDABCDABCDABCDABCDABCDABCDABCD");
    ASSERT_NE(res, HCF_SUCCESS);
}

HWTEST_F(CryptoBrainPoolKeyAgreementTest, CryptoBrainPoolKeyAgreementTest004, TestSize.Level0)
{
    HcfResult res = HcfKeyAgreementCreateTest("SM257");
    ASSERT_NE(res, HCF_SUCCESS);
}

HWTEST_F(CryptoBrainPoolKeyAgreementTest, CryptoBrainPoolKeyAgreementTest005, TestSize.Level0)
{
    HcfResult res = HcfKeyAgreementCreate("ECC_BrainPoolP512t1", nullptr);
    ASSERT_NE(res, HCF_SUCCESS);
}

HWTEST_F(CryptoBrainPoolKeyAgreementTest, CryptoBrainPoolKeyAgreementTest006, TestSize.Level0)
{
    HcfKeyAgreement *keyAgreement = nullptr;
    HcfResult res = HcfKeyAgreementCreate("ECC_BrainPoolP160r1", &keyAgreement);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(keyAgreement, nullptr);

    const char *className = keyAgreement->base.getClass();
    ASSERT_NE(className, nullptr);
    HcfObjDestroy(keyAgreement);
}

HWTEST_F(CryptoBrainPoolKeyAgreementTest, CryptoBrainPoolKeyAgreementTest007, TestSize.Level0)
{
    HcfKeyAgreement *keyAgreement = nullptr;
    HcfResult res = HcfKeyAgreementCreate("ECC_BrainPoolP160r1", &keyAgreement);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(keyAgreement, nullptr);
    keyAgreement->base.destroy((HcfObjectBase *)keyAgreement);
}

HWTEST_F(CryptoBrainPoolKeyAgreementTest, CryptoBrainPoolKeyAgreementTest008, TestSize.Level0)
{
    HcfKeyAgreement *keyAgreement = nullptr;
    HcfResult res = HcfKeyAgreementCreate("ECC_BrainPoolP160r1", &keyAgreement);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(keyAgreement, nullptr);

    keyAgreement->base.destroy(nullptr);
    HcfObjDestroy(keyAgreement);
}

HWTEST_F(CryptoBrainPoolKeyAgreementTest, CryptoBrainPoolKeyAgreementTest009, TestSize.Level0)
{
    HcfKeyAgreement *keyAgreement = nullptr;
    HcfResult res = HcfKeyAgreementCreate("ECC_BrainPoolP160r1", &keyAgreement);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(keyAgreement, nullptr);

    keyAgreement->base.destroy(&obj);
    HcfObjDestroy(keyAgreement);
}

HWTEST_F(CryptoBrainPoolKeyAgreementTest, CryptoBrainPoolKeyAgreementTest010, TestSize.Level0)
{
    HcfKeyAgreement *keyAgreement = nullptr;
    HcfResult res = HcfKeyAgreementCreate("ECC_BrainPoolP160r1", &keyAgreement);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(keyAgreement, nullptr);

    const char *algName = keyAgreement->getAlgoName(keyAgreement);
    ASSERT_NE(algName, nullptr);
    HcfObjDestroy(keyAgreement);
}

HWTEST_F(CryptoBrainPoolKeyAgreementTest, CryptoBrainPoolKeyAgreementTest011, TestSize.Level0)
{
    HcfKeyAgreement *keyAgreement = nullptr;
    HcfResult res = HcfKeyAgreementCreate("ECC_BrainPoolP160r1", &keyAgreement);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(keyAgreement, nullptr);

    const char *algName = keyAgreement->getAlgoName(nullptr);
    ASSERT_EQ(algName, nullptr);
    HcfObjDestroy(keyAgreement);
}

HWTEST_F(CryptoBrainPoolKeyAgreementTest, CryptoBrainPoolKeyAgreementTest012, TestSize.Level0)
{
    HcfKeyAgreement *keyAgreement = nullptr;
    HcfResult res = HcfKeyAgreementCreate("ECC_BrainPoolP160r1", &keyAgreement);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(keyAgreement, nullptr);

    const char *algName = keyAgreement->getAlgoName((HcfKeyAgreement *)(&obj));
    ASSERT_EQ(algName, nullptr);
    HcfObjDestroy(keyAgreement);
}

HWTEST_F(CryptoBrainPoolKeyAgreementTest, CryptoBrainPoolKeyAgreementTest013, TestSize.Level0)
{
    HcfKeyAgreement *keyAgreement = nullptr;
    HcfResult res = HcfKeyAgreementCreate("ECC_BrainPoolP160r1", &keyAgreement);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(keyAgreement, nullptr);

    HcfKeyPair *keyPair = nullptr;
    res = GenerateBrainpoolP160r1KeyPair(&keyPair);
    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(keyPair, nullptr);

    HcfBlob out = { .data = nullptr, .len = 0 };
    res = keyAgreement->generateSecret(keyAgreement, keyPair->priKey, keyPair->pubKey, &out);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(out.data, nullptr);
    ASSERT_NE(out.len, (const unsigned int)0);

    HcfFree(out.data);
    HcfObjDestroy(keyPair);
    HcfObjDestroy(keyAgreement);
}

HWTEST_F(CryptoBrainPoolKeyAgreementTest, CryptoBrainPoolKeyAgreementTest014, TestSize.Level0)
{
    HcfKeyAgreement *keyAgreement = nullptr;
    HcfResult res = HcfKeyAgreementCreate("ECC_BrainPoolP160r1", &keyAgreement);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(keyAgreement, nullptr);

    HcfKeyPair *keyPair = nullptr;
    res = GenerateBrainpoolP160r1KeyPair(&keyPair);
    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(keyPair, nullptr);

    HcfBlob out = { .data = nullptr, .len = 0 };
    res = keyAgreement->generateSecret(nullptr, keyPair->priKey, keyPair->pubKey, &out);

    ASSERT_NE(res, HCF_SUCCESS);
    ASSERT_EQ(out.data, nullptr);
    ASSERT_EQ(out.len, (const unsigned int)0);

    HcfFree(out.data);
    HcfObjDestroy(keyPair);
    HcfObjDestroy(keyAgreement);
}

HWTEST_F(CryptoBrainPoolKeyAgreementTest, CryptoBrainPoolKeyAgreementTest015, TestSize.Level0)
{
    HcfKeyAgreement *keyAgreement = nullptr;
    HcfResult res = HcfKeyAgreementCreate("ECC_BrainPoolP160r1", &keyAgreement);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(keyAgreement, nullptr);

    HcfKeyPair *keyPair = nullptr;
    res = GenerateBrainpoolP160r1KeyPair(&keyPair);
    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(keyPair, nullptr);

    HcfBlob out = { .data = nullptr, .len = 0 };
    res = keyAgreement->generateSecret(keyAgreement, keyPair->priKey, nullptr, &out);

    ASSERT_NE(res, HCF_SUCCESS);
    ASSERT_EQ(out.data, nullptr);
    ASSERT_EQ(out.len, (const unsigned int)0);

    HcfFree(out.data);
    HcfObjDestroy(keyPair);
    HcfObjDestroy(keyAgreement);
}

HWTEST_F(CryptoBrainPoolKeyAgreementTest, CryptoBrainPoolKeyAgreementTest016, TestSize.Level0)
{
    HcfKeyAgreement *keyAgreement = nullptr;
    HcfResult res = HcfKeyAgreementCreate("ECC_BrainPoolP160r1", &keyAgreement);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(keyAgreement, nullptr);

    HcfKeyPair *keyPair = nullptr;
    res = GenerateBrainpoolP160r1KeyPair(&keyPair);
    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(keyPair, nullptr);

    HcfBlob out = { .data = nullptr, .len = 0 };
    res = keyAgreement->generateSecret(keyAgreement, nullptr, keyPair->pubKey, &out);

    ASSERT_NE(res, HCF_SUCCESS);
    ASSERT_EQ(out.data, nullptr);
    ASSERT_EQ(out.len, (const unsigned int)0);

    HcfFree(out.data);
    HcfObjDestroy(keyPair);
    HcfObjDestroy(keyAgreement);
}

HWTEST_F(CryptoBrainPoolKeyAgreementTest, CryptoBrainPoolKeyAgreementTest017, TestSize.Level0)
{
    HcfKeyAgreement *keyAgreement = nullptr;
    HcfResult res = HcfKeyAgreementCreate("ECC_BrainPoolP160r1", &keyAgreement);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(keyAgreement, nullptr);

    HcfKeyPair *keyPair = nullptr;
    res = GenerateBrainpoolP160r1KeyPair(&keyPair);
    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(keyPair, nullptr);

    res = keyAgreement->generateSecret(keyAgreement, keyPair->priKey, keyPair->pubKey, nullptr);
    ASSERT_NE(res, HCF_SUCCESS);
    HcfObjDestroy(keyPair);
    HcfObjDestroy(keyAgreement);
}

HWTEST_F(CryptoBrainPoolKeyAgreementTest, CryptoBrainPoolKeyAgreementTest018, TestSize.Level0)
{
    HcfAsyKeyGenerator *generator = nullptr;
    HcfResult res = HcfAsyKeyGeneratorCreate("ECC_BrainPoolP160r1", &generator);
    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(generator, nullptr);

    HcfKeyPair *keyPair1 = nullptr;
    res = generator->generateKeyPair(generator, nullptr, &keyPair1);
    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(keyPair1, nullptr);

    HcfKeyPair *keyPair2 = nullptr;
    res = generator->generateKeyPair(generator, nullptr, &keyPair2);
    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(keyPair2, nullptr);

    HcfKeyAgreement *keyAgreement = nullptr;
    res = HcfKeyAgreementCreate("ECC_BrainPoolP160r1", &keyAgreement);
    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(keyAgreement, nullptr);

    HcfBlob outBlob1 = { .data = nullptr, .len = 0 };
    res = keyAgreement->generateSecret(keyAgreement, keyPair1->priKey, keyPair2->pubKey, &outBlob1);
    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(outBlob1.data, nullptr);
    ASSERT_NE(outBlob1.len, (const unsigned int)0);

    HcfBlob outBlob2 = { .data = nullptr, .len = 0 };
    res = keyAgreement->generateSecret(keyAgreement, keyPair2->priKey, keyPair1->pubKey, &outBlob2);
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
    HcfObjDestroy(keyPair1);
    HcfObjDestroy(keyPair2);
    HcfFree(outBlob1.data);
    HcfFree(outBlob2.data);
}
}