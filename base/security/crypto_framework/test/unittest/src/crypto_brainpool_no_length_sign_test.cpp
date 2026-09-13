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

#include "asy_key_generator.h"
#include "ecc_common_param_spec.h"
#include "ecc_key_util.h"
#include "key_utils.h"
#include "blob.h"
#include "ecc_openssl_common.h"
#include "ecc_openssl_common_param_spec.h"
#include "ecc_common.h"
#include "ecdsa_openssl.h"
#include "memory.h"
#include "securec.h"
#include "signature.h"
#include "memory_mock.h"
#include "openssl_adapter_mock.h"
#include "openssl_common.h"
#include "object_base.h"
#include "ecc_common_param_spec_generator_openssl.h"

using namespace std;
using namespace testing::ext;

namespace {
class CryptoBrainPoolNoLengthSignTest : public testing::Test {
public:
    static void SetUpTestCase() {};
    static void TearDownTestCase() {};
    void SetUp();
    void TearDown();
};

static string g_brainpool160r1AlgName = "ECC_BrainPoolP160r1";
static string g_brainpool160r1CurveName = "NID_brainpoolP160r1";

void CryptoBrainPoolNoLengthSignTest::SetUp() {}
void CryptoBrainPoolNoLengthSignTest::TearDown() {}

static const char *g_mockMessage = "hello world";
static HcfBlob g_mockInput = {
    .data = (uint8_t *)g_mockMessage,
    .len = 12
};

static const char *GetMockClass(void)
{
    return "HcfSymKeyGenerator";
}

HcfObjectBase obj = {
    .getClass = GetMockClass,
    .destroy = nullptr
};

static HcfResult HcfSignCreateTest(const char *algName)
{
    HcfSign *sign = nullptr;
    HcfResult res = HcfSignCreate(algName, &sign);
    if (res == HCF_SUCCESS) {
        HcfObjDestroy(sign);
    }
    return res;
}

HWTEST_F(CryptoBrainPoolNoLengthSignTest, CryptoBrainPoolNoLengthSignTest001_1, TestSize.Level0)
{
    HcfResult res = HcfSignCreateTest("ECC_BrainPoolP160r1|SHA1");
    ASSERT_EQ(res, HCF_SUCCESS);
}

HWTEST_F(CryptoBrainPoolNoLengthSignTest, CryptoBrainPoolNoLengthSignTest001_2, TestSize.Level0)
{
    HcfResult res = HcfSignCreateTest("ECC_BrainPoolP160r1|SHA224");
    ASSERT_EQ(res, HCF_SUCCESS);
}

HWTEST_F(CryptoBrainPoolNoLengthSignTest, CryptoBrainPoolNoLengthSignTest001_3, TestSize.Level0)
{
    HcfResult res = HcfSignCreateTest("ECC_BrainPoolP160r1|SHA256");
    ASSERT_EQ(res, HCF_SUCCESS);
}

HWTEST_F(CryptoBrainPoolNoLengthSignTest, CryptoBrainPoolNoLengthSignTest001_4, TestSize.Level0)
{
    HcfResult res = HcfSignCreateTest("ECC_BrainPoolP160r1|SHA384");
    ASSERT_EQ(res, HCF_SUCCESS);
}

HWTEST_F(CryptoBrainPoolNoLengthSignTest, CryptoBrainPoolNoLengthSignTest001_5, TestSize.Level0)
{
    HcfResult res = HcfSignCreateTest("ECC_BrainPoolP160r1|SHA512");
    ASSERT_EQ(res, HCF_SUCCESS);
}

HWTEST_F(CryptoBrainPoolNoLengthSignTest, CryptoBrainPoolNoLengthSignTest001_6, TestSize.Level0)
{
    HcfResult res = HcfSignCreateTest("ECC_BrainPoolP160r1|MD5");
    ASSERT_EQ(res, HCF_SUCCESS);
}

HWTEST_F(CryptoBrainPoolNoLengthSignTest, CryptoBrainPoolNoLengthSignTest002, TestSize.Level0)
{
    HcfSign *sign = nullptr;
    HcfResult res = HcfSignCreate("ECC_BrainPoolP160r1|SHA256", &sign);
    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(sign, nullptr);

    const char *className = sign->base.getClass();
    ASSERT_NE(className, nullptr);
    HcfObjDestroy(sign);
}

HWTEST_F(CryptoBrainPoolNoLengthSignTest, CryptoBrainPoolNoLengthSignTest003, TestSize.Level0)
{
    HcfSign *sign = nullptr;
    HcfResult res = HcfSignCreate("ECC_BrainPoolP160r1|SHA256", &sign);
    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(sign, nullptr);
    sign->base.destroy((HcfObjectBase *)sign);
}

HWTEST_F(CryptoBrainPoolNoLengthSignTest, CryptoBrainPoolNoLengthSignTest004, TestSize.Level0)
{
    HcfSign *sign = nullptr;
    HcfResult res = HcfSignCreate("ECC_BrainPoolP160r1|SHA256", &sign);
    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(sign, nullptr);
    sign->base.destroy(nullptr);
    HcfObjDestroy(sign);
}

HWTEST_F(CryptoBrainPoolNoLengthSignTest, CryptoBrainPoolNoLengthSignTest005, TestSize.Level0)
{
    HcfSign *sign = nullptr;
    HcfResult res = HcfSignCreate("ECC_BrainPoolP160r1|SHA256", &sign);
    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(sign, nullptr);

    sign->base.destroy(&obj);
    HcfObjDestroy(sign);
}

HWTEST_F(CryptoBrainPoolNoLengthSignTest, CryptoBrainPoolNoLengthSignTest006, TestSize.Level0)
{
    HcfSign *sign = nullptr;
    HcfResult res = HcfSignCreate("ECC_BrainPoolP160r1|SHA256", &sign);
    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(sign, nullptr);

    const char *algName = sign->getAlgoName(sign);
    ASSERT_NE(algName, nullptr);
    HcfObjDestroy(sign);
}

HWTEST_F(CryptoBrainPoolNoLengthSignTest, CryptoBrainPoolNoLengthSignTest007, TestSize.Level0)
{
    HcfSign *sign = nullptr;
    HcfResult res = HcfSignCreate("ECC_BrainPoolP160r1|SHA256", &sign);
    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(sign, nullptr);

    const char *algName = sign->getAlgoName(nullptr);
    ASSERT_EQ(algName, nullptr);
    HcfObjDestroy(sign);
}

HWTEST_F(CryptoBrainPoolNoLengthSignTest, CryptoBrainPoolNoLengthSignTest008, TestSize.Level0)
{
    HcfSign *sign = nullptr;
    HcfResult res = HcfSignCreate("ECC_BrainPoolP160r1|SHA256", &sign);
    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(sign, nullptr);

    const char *algName = sign->getAlgoName((HcfSign *)&obj);
    ASSERT_EQ(algName, nullptr);
    HcfObjDestroy(sign);
}

HWTEST_F(CryptoBrainPoolNoLengthSignTest, CryptoBrainPoolNoLengthSignTest009, TestSize.Level0)
{
    HcfSign *sign = nullptr;
    HcfResult res = HcfSignCreate("ECC_BrainPoolP160r1|SHA256", &sign);
    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(sign, nullptr);

    HcfKeyPair *keyPair = nullptr;
    res = GenerateBrainpoolP160r1KeyPair(&keyPair);
    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(keyPair, nullptr);

    res = sign->init(sign, nullptr, keyPair->priKey);
    ASSERT_EQ(res, HCF_SUCCESS);

    HcfObjDestroy(sign);
    HcfObjDestroy(keyPair);
}

HWTEST_F(CryptoBrainPoolNoLengthSignTest, CryptoBrainPoolNoLengthSignTest010, TestSize.Level0)
{
    HcfSign *sign = nullptr;
    HcfResult res = HcfSignCreate("ECC_BrainPoolP160r1|SHA256", &sign);
    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(sign, nullptr);

    HcfKeyPair *keyPair = nullptr;
    res = GenerateBrainpoolP160r1KeyPair(&keyPair);
    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(keyPair, nullptr);

    res = sign->init(nullptr, nullptr, keyPair->priKey);
    ASSERT_NE(res, HCF_SUCCESS);

    HcfObjDestroy(sign);
    HcfObjDestroy(keyPair);
}

HWTEST_F(CryptoBrainPoolNoLengthSignTest, CryptoBrainPoolNoLengthSignTest011, TestSize.Level0)
{
    HcfSign *sign = nullptr;
    HcfResult res = HcfSignCreate("ECC_BrainPoolP160r1|SHA256", &sign);
    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(sign, nullptr);

    HcfKeyPair *keyPair = nullptr;
    res = GenerateBrainpoolP160r1KeyPair(&keyPair);
    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(keyPair, nullptr);

    res = sign->init((HcfSign *)(&obj), nullptr, keyPair->priKey);
    ASSERT_NE(res, HCF_SUCCESS);

    HcfObjDestroy(sign);
    HcfObjDestroy(keyPair);
}

HWTEST_F(CryptoBrainPoolNoLengthSignTest, CryptoBrainPoolNoLengthSignTest012, TestSize.Level0)
{
    HcfSign *sign = nullptr;
    HcfResult res = HcfSignCreate("ECC_BrainPoolP160r1|SHA256", &sign);
    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(sign, nullptr);

    HcfKeyPair *keyPair = nullptr;
    res = GenerateBrainpoolP160r1KeyPair(&keyPair);
    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(keyPair, nullptr);

    res = sign->init(sign, nullptr, keyPair->priKey);
    ASSERT_EQ(res, HCF_SUCCESS);

    res = sign->init(sign, nullptr, keyPair->priKey);
    ASSERT_NE(res, HCF_SUCCESS);

    HcfObjDestroy(sign);
    HcfObjDestroy(keyPair);
}

HWTEST_F(CryptoBrainPoolNoLengthSignTest, CryptoBrainPoolNoLengthSignTest013, TestSize.Level0)
{
    HcfSign *sign = nullptr;
    HcfResult res = HcfSignCreate("ECC_BrainPoolP160r1|SHA256", &sign);
    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(sign, nullptr);

    res = sign->init(sign, nullptr, nullptr);
    ASSERT_EQ(res, HCF_INVALID_PARAMS);
    HcfObjDestroy(sign);
}

HWTEST_F(CryptoBrainPoolNoLengthSignTest, CryptoBrainPoolNoLengthSignTest014, TestSize.Level0)
{
    HcfSign *sign = nullptr;
    HcfResult res = HcfSignCreate("ECC_BrainPoolP160r1|SHA256", &sign);
    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(sign, nullptr);

    res = sign->init(sign, nullptr, (HcfPriKey *)(&obj));
    ASSERT_EQ(res, HCF_INVALID_PARAMS);
    HcfObjDestroy(sign);
}

HWTEST_F(CryptoBrainPoolNoLengthSignTest, CryptoBrainPoolNoLengthSignTest015, TestSize.Level0)
{
    HcfSign *sign = nullptr;
    HcfResult res = HcfSignCreate("ECC_BrainPoolP160r1|SHA256", &sign);
    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(sign, nullptr);

    res = sign->init(sign, nullptr, (HcfPriKey *)(&obj));
    ASSERT_EQ(res, HCF_INVALID_PARAMS);

    HcfBlob mockInput = {
        .data = (uint8_t *)g_mockMessage,
        .len = 1
    };
    res = sign->update(sign, &mockInput);
    ASSERT_EQ(res, HCF_INVALID_PARAMS);
    HcfObjDestroy(sign);
}

HWTEST_F(CryptoBrainPoolNoLengthSignTest, CryptoBrainPoolNoLengthSignTest016, TestSize.Level0)
{
    HcfSign *sign = nullptr;
    HcfResult res = HcfSignCreate("ECC_BrainPoolP160r1|SHA256", &sign);
    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(sign, nullptr);

    res = sign->init(sign, nullptr, (HcfPriKey *)(&obj));
    ASSERT_EQ(res, HCF_INVALID_PARAMS);

    HcfBlob mockInput = {
        .data = (uint8_t *)g_mockMessage,
        .len = 1
    };
    res = sign->update(nullptr, &mockInput);
    ASSERT_EQ(res, HCF_INVALID_PARAMS);
    HcfObjDestroy(sign);
}

HWTEST_F(CryptoBrainPoolNoLengthSignTest, CryptoBrainPoolNoLengthSignTest017, TestSize.Level0)
{
    HcfSign *sign = nullptr;
    HcfResult res = HcfSignCreate("ECC_BrainPoolP160r1|SHA256", &sign);
    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(sign, nullptr);

    res = sign->init(sign, nullptr, (HcfPriKey *)(&obj));
    ASSERT_EQ(res, HCF_INVALID_PARAMS);
    HcfBlob mockInput = {
        .data = (uint8_t *)g_mockMessage,
        .len = 1
    };

    res = sign->update((HcfSign *)(&obj), &mockInput);
    ASSERT_EQ(res, HCF_INVALID_PARAMS);
    HcfObjDestroy(sign);
}

HWTEST_F(CryptoBrainPoolNoLengthSignTest, CryptoBrainPoolNoLengthSignTest018, TestSize.Level0)
{
    HcfSign *sign = nullptr;
    HcfResult res = HcfSignCreate("ECC_BrainPoolP160r1|SHA256", &sign);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(sign, nullptr);

    HcfBlob mockInput = {
        .data = (uint8_t *)g_mockMessage,
        .len = 1
    };

    res = sign->update(sign, &mockInput);
    ASSERT_EQ(res, HCF_INVALID_PARAMS);
    HcfObjDestroy(sign);
}


HWTEST_F(CryptoBrainPoolNoLengthSignTest, CryptoBrainPoolNoLengthSignTest019, TestSize.Level0)
{
    HcfSign *sign = nullptr;
    HcfResult res = HcfSignCreate("ECC_BrainPoolP160r1|SHA256", &sign);
    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(sign, nullptr);

    HcfKeyPair *keyPair = nullptr;
    res = GenerateBrainpoolP160r1KeyPair(&keyPair);
    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(keyPair, nullptr);

    res = sign->init(sign, nullptr, keyPair->priKey);
    ASSERT_EQ(res, HCF_SUCCESS);

    res = sign->update(sign, nullptr);
    ASSERT_EQ(res, HCF_INVALID_PARAMS);

    HcfObjDestroy(sign);
    HcfObjDestroy(keyPair);
}

HWTEST_F(CryptoBrainPoolNoLengthSignTest, CryptoBrainPoolNoLengthSignTest020, TestSize.Level0)
{
    HcfSign *sign = nullptr;
    HcfResult res = HcfSignCreate("ECC_BrainPoolP160r1|SHA256", &sign);
    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(sign, nullptr);

    HcfKeyPair *keyPair = nullptr;
    res = GenerateBrainpoolP160r1KeyPair(&keyPair);
    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(keyPair, nullptr);

    res = sign->init(sign, nullptr, keyPair->priKey);
    ASSERT_EQ(res, HCF_SUCCESS);

    HcfBlob input = {
        .data = nullptr,
        .len = 1
    };

    res = sign->update(sign, &input);
    ASSERT_EQ(res, HCF_INVALID_PARAMS);

    HcfObjDestroy(sign);
    HcfObjDestroy(keyPair);
    HcfBlobDataFree(&input);
}

HWTEST_F(CryptoBrainPoolNoLengthSignTest, CryptoBrainPoolNoLengthSignTest021, TestSize.Level0)
{
    HcfSign *sign = nullptr;
    HcfResult res = HcfSignCreate("ECC_BrainPoolP160r1|SHA256", &sign);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(sign, nullptr);

    HcfKeyPair *keyPair = nullptr;
    res = GenerateBrainpoolP160r1KeyPair(&keyPair);
    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(keyPair, nullptr);

    res = sign->init(sign, nullptr, keyPair->priKey);
    ASSERT_EQ(res, HCF_SUCCESS);

    HcfBlob input = {
        .data = (uint8_t *)g_mockMessage,
        .len = 0
    };

    res = sign->update(sign, &input);
    ASSERT_NE(res, HCF_SUCCESS);

    HcfObjDestroy(sign);
    HcfObjDestroy(keyPair);
}

HWTEST_F(CryptoBrainPoolNoLengthSignTest, CryptoBrainPoolNoLengthSignTest022, TestSize.Level0)
{
    HcfSign *sign = nullptr;
    HcfResult res = HcfSignCreate("ECC_BrainPoolP160r1|SHA256", &sign);
    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(sign, nullptr);

    HcfKeyPair *keyPair = nullptr;
    res = GenerateBrainpoolP160r1KeyPair(&keyPair);
    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(keyPair, nullptr);

    res = sign->init(sign, nullptr, keyPair->priKey);
    ASSERT_EQ(res, HCF_SUCCESS);

    res = sign->update(sign, &g_mockInput);
    ASSERT_EQ(res, HCF_SUCCESS);

    HcfBlob out = { .data = nullptr, .len = 0 };
    res = sign->sign(sign, nullptr, &out);
    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(out.data, nullptr);
    ASSERT_NE(out.len, (const unsigned int)0);

    HcfFree(out.data);
    HcfObjDestroy(sign);
    HcfObjDestroy(keyPair);
}

HWTEST_F(CryptoBrainPoolNoLengthSignTest, CryptoBrainPoolNoLengthSignTest023, TestSize.Level0)
{
    HcfSign *sign = nullptr;
    HcfResult res = HcfSignCreate("ECC_BrainPoolP160r1|SHA256", &sign);
    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(sign, nullptr);

    HcfKeyPair *keyPair = nullptr;
    res = GenerateBrainpoolP160r1KeyPair(&keyPair);
    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(keyPair, nullptr);

    res = sign->init(sign, nullptr, keyPair->priKey);
    ASSERT_EQ(res, HCF_SUCCESS);

    HcfBlob out = { .data = nullptr, .len = 0 };
    res = sign->sign(sign, &g_mockInput, &out);
    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(out.data, nullptr);
    ASSERT_NE(out.len, (const unsigned int)0);

    HcfFree(out.data);
    HcfObjDestroy(sign);
    HcfObjDestroy(keyPair);
}

HWTEST_F(CryptoBrainPoolNoLengthSignTest, CryptoBrainPoolNoLengthSignTest024, TestSize.Level0)
{
    HcfSign *sign = nullptr;
    HcfResult res = HcfSignCreate("ECC_BrainPoolP160r1|SHA256", &sign);
    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(sign, nullptr);

    HcfKeyPair *keyPair = nullptr;
    res = GenerateBrainpoolP160r1KeyPair(&keyPair);
    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(keyPair, nullptr);

    res = sign->init(sign, nullptr, keyPair->priKey);
    ASSERT_EQ(res, HCF_SUCCESS);

    res = sign->update(sign, &g_mockInput);
    ASSERT_EQ(res, HCF_SUCCESS);

    HcfBlob out = { .data = nullptr, .len = 0 };
    res = sign->sign(nullptr, nullptr, &out);
    ASSERT_EQ(res, HCF_INVALID_PARAMS);
    ASSERT_EQ(out.data, nullptr);
    ASSERT_EQ(out.len, (const unsigned int)0);

    HcfObjDestroy(sign);
    HcfObjDestroy(keyPair);
}

HWTEST_F(CryptoBrainPoolNoLengthSignTest, CryptoBrainPoolNoLengthSignTest025, TestSize.Level0)
{
    HcfSign *sign = nullptr;
    HcfResult res = HcfSignCreate("ECC_BrainPoolP160r1|SHA256", &sign);
    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(sign, nullptr);

    HcfKeyPair *keyPair = nullptr;
    res = GenerateBrainpoolP160r1KeyPair(&keyPair);
    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(keyPair, nullptr);

    res = sign->init(sign, nullptr, keyPair->priKey);
    ASSERT_EQ(res, HCF_SUCCESS);

    HcfBlob out = { .data = nullptr, .len = 0 };
    res = sign->sign((HcfSign *)(&obj), nullptr, &out);
    ASSERT_EQ(res, HCF_INVALID_PARAMS);
    ASSERT_EQ(out.data, nullptr);
    ASSERT_EQ(out.len, (const unsigned int)0);

    HcfObjDestroy(sign);
    HcfObjDestroy(keyPair);
}

HWTEST_F(CryptoBrainPoolNoLengthSignTest, CryptoBrainPoolNoLengthSignTest026, TestSize.Level0)
{
    HcfSign *sign = nullptr;
    HcfResult res = HcfSignCreate("ECC_BrainPoolP160r1|SHA256", &sign);
    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(sign, nullptr);

    HcfKeyPair *keyPair = nullptr;
    res = GenerateBrainpoolP160r1KeyPair(&keyPair);
    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(keyPair, nullptr);

    res = sign->init(sign, nullptr, keyPair->priKey);
    ASSERT_EQ(res, HCF_SUCCESS);

    HcfBlob out = {
        .data = nullptr,
        .len = 0
    };
    res = sign->sign(sign, nullptr, &out);
    ASSERT_EQ(res, HCF_INVALID_PARAMS);
    ASSERT_EQ(out.data, nullptr);
    ASSERT_EQ(out.len, (const unsigned int)0);

    HcfObjDestroy(sign);
    HcfObjDestroy(keyPair);
}

HWTEST_F(CryptoBrainPoolNoLengthSignTest, CryptoBrainPoolNoLengthSignTest027, TestSize.Level0)
{
    HcfSign *sign = nullptr;
    HcfResult res = HcfSignCreate("ECC_BrainPoolP160r1|SHA256", &sign);
    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(sign, nullptr);

    HcfKeyPair *keyPair = nullptr;
    res = GenerateBrainpoolP160r1KeyPair(&keyPair);
    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(keyPair, nullptr);

    res = sign->init(sign, nullptr, keyPair->priKey);
    ASSERT_EQ(res, HCF_SUCCESS);

    HcfBlob input = {
        .data = nullptr,
        .len = 1
    };
    HcfBlob out = {
        .data = nullptr,
        .len = 0
    };
    res = sign->sign(sign, &input, &out);
    ASSERT_EQ(res, HCF_INVALID_PARAMS);
    ASSERT_EQ(out.data, nullptr);
    ASSERT_EQ(out.len, (const unsigned int)0);

    HcfObjDestroy(sign);
    HcfObjDestroy(keyPair);
}

HWTEST_F(CryptoBrainPoolNoLengthSignTest, CryptoBrainPoolNoLengthSignTest028, TestSize.Level0)
{
    HcfSign *sign = nullptr;
    HcfResult res = HcfSignCreate("ECC_BrainPoolP160r1|SHA256", &sign);
    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(sign, nullptr);

    HcfKeyPair *keyPair = nullptr;
    res = GenerateBrainpoolP160r1KeyPair(&keyPair);
    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(keyPair, nullptr);

    res = sign->init(sign, nullptr, keyPair->priKey);
    ASSERT_EQ(res, HCF_SUCCESS);

    HcfBlob input = {
        .data = (uint8_t *)g_mockMessage,
        .len = 0
    };
    HcfBlob out = {
        .data = nullptr,
        .len = 0
    };
    res = sign->sign(sign, &input, &out);
    ASSERT_EQ(res, HCF_INVALID_PARAMS);
    ASSERT_EQ(out.data, nullptr);
    ASSERT_EQ(out.len, (const unsigned int)0);

    HcfObjDestroy(sign);
    HcfObjDestroy(keyPair);
}

HcfSignatureParams g_params = {
    .algo = HCF_ALG_ECC,
    .padding = HCF_ALG_NOPADDING,
    .md = HCF_OPENSSL_DIGEST_SHA256,
    .mgf1md = HCF_OPENSSL_DIGEST_SHA256,
};

HWTEST_F(CryptoBrainPoolNoLengthSignTest, CryptoBrainPoolNoLengthSignTest029, TestSize.Level0)
{
    HcfResult res = HcfSignSpiEcdsaCreate(&g_params, nullptr);
    ASSERT_EQ(res, HCF_INVALID_PARAMS);
}

HWTEST_F(CryptoBrainPoolNoLengthSignTest, CryptoBrainPoolNoLengthSignTest030, TestSize.Level0)
{
    HcfSignSpi *spiObj = nullptr;
    HcfResult res = HcfSignSpiEcdsaCreate(&g_params, &spiObj);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(spiObj, nullptr);

    HcfKeyPair *keyPair = nullptr;
    res = GenerateBrainpoolP160r1KeyPair(&keyPair);
    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(keyPair, nullptr);

    res = spiObj->engineInit((HcfSignSpi *)&obj, nullptr, keyPair->priKey);
    ASSERT_EQ(res, HCF_INVALID_PARAMS);

    HcfObjDestroy(spiObj);
    HcfObjDestroy(keyPair);
}

HWTEST_F(CryptoBrainPoolNoLengthSignTest, CryptoBrainPoolNoLengthSignTest031, TestSize.Level0)
{
    HcfSignSpi *spiObj = nullptr;
    HcfResult res = HcfSignSpiEcdsaCreate(&g_params, &spiObj);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(spiObj, nullptr);

    res = spiObj->engineInit(spiObj, nullptr, (HcfPriKey *)&obj);
    ASSERT_EQ(res, HCF_INVALID_PARAMS);
    HcfObjDestroy(spiObj);
}

HWTEST_F(CryptoBrainPoolNoLengthSignTest, CryptoBrainPoolNoLengthSignTest032, TestSize.Level0)
{
    HcfSignSpi *spiObj = nullptr;
    HcfResult res = HcfSignSpiEcdsaCreate(&g_params, &spiObj);
    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(spiObj, nullptr);

    const char *message = "hello world";
    HcfBlob input = {
        .data = (uint8_t *)message,
        .len = 12
    };
    res = spiObj->engineUpdate(nullptr, &input);
    ASSERT_EQ(res, HCF_INVALID_PARAMS);
    HcfObjDestroy(spiObj);
}

HWTEST_F(CryptoBrainPoolNoLengthSignTest, CryptoBrainPoolNoLengthSignTest033, TestSize.Level0)
{
    HcfSignSpi *spiObj = nullptr;
    HcfResult res = HcfSignSpiEcdsaCreate(&g_params, &spiObj);
    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(spiObj, nullptr);

    const char *message = "hello world";
    HcfBlob input = {
        .data = (uint8_t *)message,
        .len = 12
    };
    res = spiObj->engineUpdate((HcfSignSpi *)&obj, &input);
    ASSERT_EQ(res, HCF_INVALID_PARAMS);
    HcfObjDestroy(spiObj);
}

HWTEST_F(CryptoBrainPoolNoLengthSignTest, CryptoBrainPoolNoLengthSignTest034, TestSize.Level0)
{
    HcfSignSpi *spiObj = nullptr;
    HcfResult res = HcfSignSpiEcdsaCreate(&g_params, &spiObj);
    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(spiObj, nullptr);

    res = spiObj->engineUpdate(spiObj, nullptr);
    ASSERT_EQ(res, HCF_INVALID_PARAMS);
    HcfObjDestroy(spiObj);
}

HWTEST_F(CryptoBrainPoolNoLengthSignTest, CryptoBrainPoolNoLengthSignTest035, TestSize.Level0)
{
    HcfSignSpi *spiObj = nullptr;
    HcfResult res = HcfSignSpiEcdsaCreate(&g_params, &spiObj);
    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(spiObj, nullptr);

    const char *message = "hello world";
    HcfBlob input = {
        .data = (uint8_t *)message,
        .len = 12
    };
    HcfBlob out = { .data = nullptr, .len = 0 };
    res = spiObj->engineSign((HcfSignSpi *)&obj, &input, &out);
    ASSERT_EQ(res, HCF_INVALID_PARAMS);
    HcfObjDestroy(spiObj);
}

HWTEST_F(CryptoBrainPoolNoLengthSignTest, CryptoBrainPoolNoLengthSignTest036, TestSize.Level0)
{
    HcfSign *sign = nullptr;
    HcfResult ret = HcfSignCreate("ECC_BrainPoolP160r1|SHA1", &sign);
    ASSERT_EQ(ret, HCF_SUCCESS);
    ASSERT_NE(sign, nullptr);

    int32_t returnInt = 0;
    ret = sign->setSignSpecInt(sign, SM2_USER_ID_UINT8ARR, returnInt);
    ASSERT_EQ(ret, HCF_NOT_SUPPORT);
    ret = sign->getSignSpecInt(sign, SM2_USER_ID_UINT8ARR, &returnInt);
    ASSERT_EQ(ret, HCF_NOT_SUPPORT);
    HcfBlob returnBlob = { .data = nullptr, .len = 0};
    ret = sign->setSignSpecUint8Array(sign, SM2_USER_ID_UINT8ARR, returnBlob);
    ASSERT_EQ(ret, HCF_NOT_SUPPORT);
    char *itemName = nullptr;
    ret = sign->getSignSpecString(sign, SM2_USER_ID_UINT8ARR, &itemName);
    ASSERT_EQ(ret, HCF_NOT_SUPPORT);

    HcfObjDestroy(sign);
}
}