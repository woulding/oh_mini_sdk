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
#include "pub_key.h"

using namespace std;
using namespace testing::ext;
namespace {
class CryptoBrainPoolNoLengthVerifyTest : public testing::Test {
public:
    static void SetUpTestCase() {};
    static void TearDownTestCase() {};
    void SetUp();
    void TearDown();
};

static string g_brainpool160r1AlgName = "ECC_BrainPoolP160r1";
static string g_brainpool160r1CurveName = "NID_brainpoolP160r1";

void CryptoBrainPoolNoLengthVerifyTest::SetUp() {}
void CryptoBrainPoolNoLengthVerifyTest::TearDown() {}

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

static HcfResult HcfVerifyCreateTest(const char *algName)
{
    HcfVerify *verify = nullptr;
    HcfResult res = HcfVerifyCreate(algName, &verify);
    if (res == HCF_SUCCESS) {
        HcfObjDestroy(verify);
    }
    return res;
}

HWTEST_F(CryptoBrainPoolNoLengthVerifyTest, CryptoBrainPoolNoLengthVerifyTest001_1, TestSize.Level0)
{
    HcfResult res = HcfVerifyCreateTest("ECC_BrainPoolP160r1|SHA1");
    ASSERT_EQ(res, HCF_SUCCESS);
}

HWTEST_F(CryptoBrainPoolNoLengthVerifyTest, CryptoBrainPoolNoLengthVerifyTest001_2, TestSize.Level0)
{
    HcfResult res = HcfVerifyCreateTest("ECC_BrainPoolP160r1|SHA224");
    ASSERT_EQ(res, HCF_SUCCESS);
}

HWTEST_F(CryptoBrainPoolNoLengthVerifyTest, CryptoBrainPoolNoLengthVerifyTest001_3, TestSize.Level0)
{
    HcfResult res = HcfVerifyCreateTest("ECC_BrainPoolP160r1|SHA256");
    ASSERT_EQ(res, HCF_SUCCESS);
}

HWTEST_F(CryptoBrainPoolNoLengthVerifyTest, CryptoBrainPoolNoLengthVerifyTest001_4, TestSize.Level0)
{
    HcfResult res = HcfVerifyCreateTest("ECC_BrainPoolP160r1|SHA384");
    ASSERT_EQ(res, HCF_SUCCESS);
}

HWTEST_F(CryptoBrainPoolNoLengthVerifyTest, CryptoBrainPoolNoLengthVerifyTest001_5, TestSize.Level0)
{
    HcfResult res = HcfVerifyCreateTest("ECC_BrainPoolP160r1|SHA512");
    ASSERT_EQ(res, HCF_SUCCESS);
}

HWTEST_F(CryptoBrainPoolNoLengthVerifyTest, CryptoBrainPoolNoLengthVerifyTest001_6, TestSize.Level0)
{
    HcfResult res = HcfVerifyCreateTest("ECC_BrainPoolP160r1|MD5");
    ASSERT_EQ(res, HCF_SUCCESS);
}

HWTEST_F(CryptoBrainPoolNoLengthVerifyTest, CryptoBrainPoolNoLengthVerifyTest002, TestSize.Level0)
{
    HcfVerify *verify = nullptr;
    HcfResult res = HcfVerifyCreate("ECC_BrainPoolP160r1|SHA224", &verify);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(verify, nullptr);

    const char *className = verify->base.getClass();
    ASSERT_NE(className, nullptr);
    HcfObjDestroy(verify);
}

HWTEST_F(CryptoBrainPoolNoLengthVerifyTest, CryptoBrainPoolNoLengthVerifyTest003, TestSize.Level0)
{
    HcfVerify *verify = nullptr;
    HcfResult res = HcfVerifyCreate("ECC_BrainPoolP160r1|SHA224", &verify);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(verify, nullptr);
    verify->base.destroy((HcfObjectBase *)verify);
}

HWTEST_F(CryptoBrainPoolNoLengthVerifyTest, CryptoBrainPoolNoLengthVerifyTest004, TestSize.Level0)
{
    HcfVerify *verify = nullptr;
    HcfResult res = HcfVerifyCreate("ECC_BrainPoolP160r1|SHA224", &verify);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(verify, nullptr);
    verify->base.destroy(nullptr);
    HcfObjDestroy(verify);
}

HWTEST_F(CryptoBrainPoolNoLengthVerifyTest, CryptoBrainPoolNoLengthVerifyTest005, TestSize.Level0)
{
    HcfVerify *verify = nullptr;
    HcfResult res = HcfVerifyCreate("ECC_BrainPoolP160r1|SHA224", &verify);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(verify, nullptr);
    verify->base.destroy(&obj);
    HcfObjDestroy(verify);
}

HWTEST_F(CryptoBrainPoolNoLengthVerifyTest, CryptoBrainPoolNoLengthVerifyTest006, TestSize.Level0)
{
    HcfVerify *verify = nullptr;
    HcfResult res = HcfVerifyCreate("ECC_BrainPoolP160r1|SHA224", &verify);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(verify, nullptr);

    const char *algName = verify->getAlgoName(verify);
    ASSERT_NE(algName, nullptr);
    HcfObjDestroy(verify);
}

HWTEST_F(CryptoBrainPoolNoLengthVerifyTest, CryptoBrainPoolNoLengthVerifyTest007, TestSize.Level0)
{
    HcfVerify *verify = nullptr;
    HcfResult res = HcfVerifyCreate("ECC_BrainPoolP160r1|SHA224", &verify);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(verify, nullptr);

    const char *algName = verify->getAlgoName(nullptr);
    ASSERT_EQ(algName, nullptr);
    HcfObjDestroy(verify);
}

HWTEST_F(CryptoBrainPoolNoLengthVerifyTest, CryptoBrainPoolNoLengthVerifyTest008, TestSize.Level0)
{
    HcfVerify *verify = nullptr;
    HcfResult res = HcfVerifyCreate("ECC_BrainPoolP160r1|SHA224", &verify);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(verify, nullptr);

    const char *algName = verify->getAlgoName((HcfVerify *)(&obj));
    ASSERT_EQ(algName, nullptr);
    HcfObjDestroy(verify);
}

HWTEST_F(CryptoBrainPoolNoLengthVerifyTest, CryptoBrainPoolNoLengthVerifyTest009, TestSize.Level0)
{
    HcfVerify *verify = nullptr;
    HcfResult res = HcfVerifyCreate("ECC_BrainPoolP160r1|SHA224", &verify);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(verify, nullptr);

    HcfKeyPair *keyPair = nullptr;
    res = GenerateBrainpoolP160r1KeyPair(&keyPair);
    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(keyPair, nullptr);

    res = verify->init(verify, nullptr, keyPair->pubKey);
    ASSERT_EQ(res, HCF_SUCCESS);
    HcfObjDestroy(keyPair);
    HcfObjDestroy(verify);
}

HWTEST_F(CryptoBrainPoolNoLengthVerifyTest, CryptoBrainPoolNoLengthVerifyTest010, TestSize.Level0)
{
    HcfVerify *verify = nullptr;
    HcfResult res = HcfVerifyCreate("ECC_BrainPoolP160r1|SHA224", &verify);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(verify, nullptr);

    HcfKeyPair *keyPair = nullptr;
    res = GenerateBrainpoolP160r1KeyPair(&keyPair);
    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(keyPair, nullptr);

    res = verify->init(nullptr, nullptr, keyPair->pubKey);
    ASSERT_NE(res, HCF_SUCCESS);
    HcfObjDestroy(verify);
    HcfObjDestroy(keyPair);
}

HWTEST_F(CryptoBrainPoolNoLengthVerifyTest, CryptoBrainPoolNoLengthVerifyTest011, TestSize.Level0)
{
    HcfVerify *verify = nullptr;
    HcfResult res = HcfVerifyCreate("ECC_BrainPoolP160r1|SHA224", &verify);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(verify, nullptr);

    HcfKeyPair *keyPair = nullptr;
    res = GenerateBrainpoolP160r1KeyPair(&keyPair);
    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(keyPair, nullptr);

    res = verify->init((HcfVerify *)(&obj), nullptr, keyPair->pubKey);
    ASSERT_NE(res, HCF_SUCCESS);
    HcfObjDestroy(verify);
    HcfObjDestroy(keyPair);
}

HWTEST_F(CryptoBrainPoolNoLengthVerifyTest, CryptoBrainPoolNoLengthVerifyTest012, TestSize.Level0)
{
    HcfVerify *verify = nullptr;
    HcfResult res = HcfVerifyCreate("ECC_BrainPoolP160r1|SHA224", &verify);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(verify, nullptr);

    HcfKeyPair *keyPair = nullptr;
    res = GenerateBrainpoolP160r1KeyPair(&keyPair);
    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(keyPair, nullptr);

    res = verify->init(verify, nullptr, keyPair->pubKey);
    ASSERT_EQ(res, HCF_SUCCESS);

    res = verify->init(verify, nullptr, keyPair->pubKey);
    ASSERT_EQ(res, HCF_INVALID_PARAMS);

    HcfObjDestroy(verify);
    HcfObjDestroy(keyPair);
}

HWTEST_F(CryptoBrainPoolNoLengthVerifyTest, CryptoBrainPoolNoLengthVerifyTest013, TestSize.Level0)
{
    HcfVerify *verify = nullptr;
    HcfResult res = HcfVerifyCreate("ECC_BrainPoolP160r1|SHA224", &verify);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(verify, nullptr);

    HcfKeyPair *keyPair = nullptr;
    res = GenerateBrainpoolP160r1KeyPair(&keyPair);
    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(keyPair, nullptr);

    res = verify->init(verify, nullptr, nullptr);
    ASSERT_EQ(res, HCF_INVALID_PARAMS);

    HcfObjDestroy(verify);
    HcfObjDestroy(keyPair);
}

HWTEST_F(CryptoBrainPoolNoLengthVerifyTest, CryptoBrainPoolNoLengthVerifyTest014, TestSize.Level0)
{
    HcfVerify *verify = nullptr;
    HcfResult res = HcfVerifyCreate("ECC_BrainPoolP160r1|SHA224", &verify);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(verify, nullptr);

    HcfKeyPair *keyPair = nullptr;
    res = GenerateBrainpoolP160r1KeyPair(&keyPair);
    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(keyPair, nullptr);

    res = verify->init(verify, nullptr, (HcfPubKey *)&obj);
    ASSERT_EQ(res, HCF_INVALID_PARAMS);

    HcfObjDestroy(verify);
    HcfObjDestroy(keyPair);
}

HWTEST_F(CryptoBrainPoolNoLengthVerifyTest, CryptoBrainPoolNoLengthVerifyTest015, TestSize.Level0)
{
    HcfVerify *verify = nullptr;
    HcfResult res = HcfVerifyCreate("ECC_BrainPoolP160r1|SHA224", &verify);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(verify, nullptr);

    HcfKeyPair *keyPair = nullptr;
    res = GenerateBrainpoolP160r1KeyPair(&keyPair);
    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(keyPair, nullptr);

    res = verify->init(verify, nullptr, keyPair->pubKey);
    ASSERT_NE(res, HCF_INVALID_PARAMS);

    res = verify->update(verify, &g_mockInput);
    ASSERT_EQ(res, HCF_SUCCESS);

    HcfObjDestroy(verify);
    HcfObjDestroy(keyPair);
}

HWTEST_F(CryptoBrainPoolNoLengthVerifyTest, CryptoBrainPoolNoLengthVerifyTest016, TestSize.Level0)
{
    HcfVerify *verify = nullptr;
    HcfResult res = HcfVerifyCreate("ECC_BrainPoolP160r1|SHA224", &verify);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(verify, nullptr);

    HcfKeyPair *keyPair = nullptr;
    res = GenerateBrainpoolP160r1KeyPair(&keyPair);
    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(keyPair, nullptr);

    res = verify->init(verify, nullptr, keyPair->pubKey);
    ASSERT_NE(res, HCF_INVALID_PARAMS);

    res = verify->update(nullptr, &g_mockInput);
    ASSERT_NE(res, HCF_SUCCESS);

    HcfObjDestroy(verify);
    HcfObjDestroy(keyPair);
}

HWTEST_F(CryptoBrainPoolNoLengthVerifyTest, CryptoBrainPoolNoLengthVerifyTest017, TestSize.Level0)
{
    HcfVerify *verify = nullptr;
    HcfResult res = HcfVerifyCreate("ECC_BrainPoolP160r1|SHA224", &verify);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(verify, nullptr);

    HcfKeyPair *keyPair = nullptr;
    res = GenerateBrainpoolP160r1KeyPair(&keyPair);
    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(keyPair, nullptr);

    res = verify->init(verify, nullptr, keyPair->pubKey);
    ASSERT_NE(res, HCF_INVALID_PARAMS);

    res = verify->update((HcfVerify *)(&obj), &g_mockInput);
    ASSERT_NE(res, HCF_SUCCESS);

    HcfObjDestroy(verify);
    HcfObjDestroy(keyPair);
}

HWTEST_F(CryptoBrainPoolNoLengthVerifyTest, CryptoBrainPoolNoLengthVerifyTest018, TestSize.Level0)
{
    HcfVerify *verify = nullptr;
    HcfResult res = HcfVerifyCreate("ECC_BrainPoolP160r1|SHA224", &verify);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(verify, nullptr);

    HcfKeyPair *keyPair = nullptr;
    res = GenerateBrainpoolP160r1KeyPair(&keyPair);
    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(keyPair, nullptr);

    res = verify->init(verify, nullptr, keyPair->pubKey);
    ASSERT_NE(res, HCF_INVALID_PARAMS);

    res = verify->update(verify, nullptr);
    ASSERT_NE(res, HCF_SUCCESS);

    HcfObjDestroy(verify);
    HcfObjDestroy(keyPair);
}

HWTEST_F(CryptoBrainPoolNoLengthVerifyTest, CryptoBrainPoolNoLengthVerifyTest019, TestSize.Level0)
{
    HcfVerify *verify = nullptr;
    HcfResult res = HcfVerifyCreate("ECC_BrainPoolP160r1|SHA224", &verify);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(verify, nullptr);

    HcfKeyPair *keyPair = nullptr;
    res = GenerateBrainpoolP160r1KeyPair(&keyPair);
    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(keyPair, nullptr);

    res = verify->init(verify, nullptr, keyPair->pubKey);
    ASSERT_NE(res, HCF_INVALID_PARAMS);
    HcfBlob input = {
        .data = nullptr,
        .len = 1
    };
    res = verify->update(verify, &input);
    ASSERT_NE(res, HCF_SUCCESS);

    HcfObjDestroy(verify);
    HcfObjDestroy(keyPair);
}

HWTEST_F(CryptoBrainPoolNoLengthVerifyTest, CryptoBrainPoolNoLengthVerifyTest020, TestSize.Level0)
{
    HcfVerify *verify = nullptr;
    HcfResult res = HcfVerifyCreate("ECC_BrainPoolP160r1|SHA224", &verify);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(verify, nullptr);

    HcfKeyPair *keyPair = nullptr;
    res = GenerateBrainpoolP160r1KeyPair(&keyPair);
    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(keyPair, nullptr);

    res = verify->init(verify, nullptr, keyPair->pubKey);
    ASSERT_NE(res, HCF_INVALID_PARAMS);

    HcfBlob input = {
        .data = (uint8_t *)g_mockMessage,
        .len = 0
    };
    res = verify->update(verify, &input);
    ASSERT_NE(res, HCF_SUCCESS);

    HcfObjDestroy(verify);
    HcfObjDestroy(keyPair);
}

HWTEST_F(CryptoBrainPoolNoLengthVerifyTest, CryptoBrainPoolNoLengthVerifyTest021, TestSize.Level0)
{
    HcfSign *sign = nullptr;
    HcfResult res = HcfSignCreate("ECC_BrainPoolP160r1|SHA224", &sign);

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

    HcfVerify *verify = nullptr;
    res = HcfVerifyCreate("ECC_BrainPoolP160r1|SHA224", &verify);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(verify, nullptr);

    res = verify->init(verify, nullptr, keyPair->pubKey);
    ASSERT_EQ(res, HCF_SUCCESS);

    res = verify->update(verify, &g_mockInput);
    ASSERT_EQ(res, HCF_SUCCESS);

    bool flag = verify->verify(verify, nullptr, &out);
    ASSERT_EQ(flag, true);

    HcfFree(out.data);
    HcfObjDestroy(keyPair);
    HcfObjDestroy(sign);
    HcfObjDestroy(verify);
}

HWTEST_F(CryptoBrainPoolNoLengthVerifyTest, CryptoBrainPoolNoLengthVerifyTest022, TestSize.Level0)
{
    HcfSign *sign = nullptr;
    HcfResult res = HcfSignCreate("ECC_BrainPoolP160r1|SHA224", &sign);

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

    HcfVerify *verify = nullptr;
    res = HcfVerifyCreate("ECC_BrainPoolP160r1|SHA224", &verify);
    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(verify, nullptr);

    res = verify->init(verify, nullptr, keyPair->pubKey);
    ASSERT_EQ(res, HCF_SUCCESS);
    bool flag = verify->verify(verify, &g_mockInput, &out);
    ASSERT_EQ(flag, true);

    HcfFree(out.data);
    HcfObjDestroy(keyPair);
    HcfObjDestroy(sign);
    HcfObjDestroy(verify);
}

HWTEST_F(CryptoBrainPoolNoLengthVerifyTest, CryptoBrainPoolNoLengthVerifyTest023, TestSize.Level0)
{
    HcfSign *sign = nullptr;
    HcfResult res = HcfSignCreate("ECC_BrainPoolP160r1|SHA224", &sign);

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

    HcfVerify *verify = nullptr;
    res = HcfVerifyCreate("ECC_BrainPoolP160r1|SHA224", &verify);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(verify, nullptr);

    res = verify->init(verify, nullptr, keyPair->pubKey);
    ASSERT_EQ(res, HCF_SUCCESS);

    res = verify->update(verify, &g_mockInput);
    ASSERT_EQ(res, HCF_SUCCESS);

    bool flag = verify->verify(nullptr, nullptr, &out);
    ASSERT_NE(flag, true);

    HcfFree(out.data);
    HcfObjDestroy(keyPair);
    HcfObjDestroy(sign);
    HcfObjDestroy(verify);
}

HWTEST_F(CryptoBrainPoolNoLengthVerifyTest, CryptoBrainPoolNoLengthVerifyTest024, TestSize.Level0)
{
    HcfSign *sign = nullptr;
    HcfResult res = HcfSignCreate("ECC_BrainPoolP160r1|SHA224", &sign);

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

    HcfVerify *verify = nullptr;
    res = HcfVerifyCreate("ECC_BrainPoolP160r1|SHA224", &verify);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(verify, nullptr);

    res = verify->init(verify, nullptr, keyPair->pubKey);
    ASSERT_EQ(res, HCF_SUCCESS);

    res = verify->update(verify, &g_mockInput);
    ASSERT_EQ(res, HCF_SUCCESS);

    bool flag = verify->verify((HcfVerify *)&obj, nullptr, &out);
    ASSERT_NE(flag, true);

    HcfFree(out.data);
    HcfObjDestroy(keyPair);
    HcfObjDestroy(sign);
    HcfObjDestroy(verify);
}

HWTEST_F(CryptoBrainPoolNoLengthVerifyTest, CryptoBrainPoolNoLengthVerifyTest025, TestSize.Level0)
{
    HcfSign *sign = nullptr;
    HcfResult res = HcfSignCreate("ECC_BrainPoolP160r1|SHA224", &sign);

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

    HcfVerify *verify = nullptr;
    res = HcfVerifyCreate("ECC_BrainPoolP160r1|SHA224", &verify);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(verify, nullptr);

    res = verify->init(verify, nullptr, keyPair->pubKey);
    ASSERT_EQ(res, HCF_SUCCESS);

    bool flag = verify->verify((HcfVerify *)(&obj), nullptr, &out);
    ASSERT_NE(flag, true);

    HcfFree(out.data);
    HcfObjDestroy(keyPair);
    HcfObjDestroy(sign);
    HcfObjDestroy(verify);
}

HWTEST_F(CryptoBrainPoolNoLengthVerifyTest, CryptoBrainPoolNoLengthVerifyTest026, TestSize.Level0)
{
    HcfSign *sign = nullptr;
    HcfResult res = HcfSignCreate("ECC_BrainPoolP160r1|SHA224", &sign);

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

    HcfVerify *verify = nullptr;
    res = HcfVerifyCreate("ECC_BrainPoolP160r1|SHA224", &verify);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(verify, nullptr);

    res = verify->init(verify, nullptr, keyPair->pubKey);
    ASSERT_EQ(res, HCF_SUCCESS);

    HcfBlob input = {
        .data = nullptr,
        .len = 1
    };

    bool flag = verify->verify((HcfVerify *)(&obj), &input, &out);
    ASSERT_NE(flag, true);

    HcfFree(out.data);
    HcfObjDestroy(keyPair);
    HcfObjDestroy(sign);
    HcfObjDestroy(verify);
}

HcfSignatureParams g_params = {
    .algo = HCF_ALG_ECC,
    .padding = HCF_ALG_NOPADDING,
    .md = HCF_OPENSSL_DIGEST_SHA256,
    .mgf1md = HCF_OPENSSL_DIGEST_SHA256,
};

HWTEST_F(CryptoBrainPoolNoLengthVerifyTest, CryptoBrainPoolNoLengthVerifyTest027, TestSize.Level0)
{
    HcfResult res = HcfVerifySpiEcdsaCreate(&g_params, nullptr);
    ASSERT_EQ(res, HCF_INVALID_PARAMS);
}

HWTEST_F(CryptoBrainPoolNoLengthVerifyTest, CryptoBrainPoolNoLengthVerifyTest028, TestSize.Level0)
{
    HcfVerifySpi *spiObj = nullptr;
    HcfResult res = HcfVerifySpiEcdsaCreate(&g_params, &spiObj);
    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(spiObj, nullptr);

    HcfKeyPair *keyPair = nullptr;
    res = GenerateBrainpoolP160r1KeyPair(&keyPair);
    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(keyPair, nullptr);

    res = spiObj->engineInit((HcfVerifySpi *)&obj, nullptr, keyPair->pubKey);
    ASSERT_EQ(res, HCF_INVALID_PARAMS);

    HcfObjDestroy(spiObj);
    HcfObjDestroy(keyPair);
}

HWTEST_F(CryptoBrainPoolNoLengthVerifyTest, CryptoBrainPoolNoLengthVerifyTest029, TestSize.Level0)
{
    HcfVerifySpi *spiObj = nullptr;
    HcfResult res = HcfVerifySpiEcdsaCreate(&g_params, &spiObj);
    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(spiObj, nullptr);

    HcfKeyPair *keyPair = nullptr;
    res = GenerateBrainpoolP160r1KeyPair(&keyPair);
    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(keyPair, nullptr);

    res = spiObj->engineInit((HcfVerifySpi *)&obj, nullptr, (HcfPubKey *)&obj);
    ASSERT_EQ(res, HCF_INVALID_PARAMS);

    HcfObjDestroy(spiObj);
    HcfObjDestroy(keyPair);
}

HWTEST_F(CryptoBrainPoolNoLengthVerifyTest, CryptoBrainPoolNoLengthVerifyTest030, TestSize.Level0)
{
    HcfVerifySpi *spiObj = nullptr;
    HcfResult res = HcfVerifySpiEcdsaCreate(&g_params, &spiObj);

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

HWTEST_F(CryptoBrainPoolNoLengthVerifyTest, CryptoBrainPoolNoLengthVerifyTest031, TestSize.Level0)
{
    HcfVerifySpi *spiObj = nullptr;
    HcfResult res = HcfVerifySpiEcdsaCreate(&g_params, &spiObj);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(spiObj, nullptr);

    const char *message = "hello world";
    HcfBlob input = {
        .data = (uint8_t *)message,
        .len = 12
    };
    res = spiObj->engineUpdate((HcfVerifySpi *)&obj, &input);
    ASSERT_EQ(res, HCF_INVALID_PARAMS);
    HcfObjDestroy(spiObj);
}

HWTEST_F(CryptoBrainPoolNoLengthVerifyTest, CryptoBrainPoolNoLengthVerifyTest032, TestSize.Level0)
{
    HcfVerifySpi *spiObj = nullptr;
    HcfResult res = HcfVerifySpiEcdsaCreate(&g_params, &spiObj);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(spiObj, nullptr);

    res = spiObj->engineUpdate(spiObj, nullptr);
    ASSERT_EQ(res, HCF_INVALID_PARAMS);
    HcfObjDestroy(spiObj);
}

HWTEST_F(CryptoBrainPoolNoLengthVerifyTest, CryptoBrainPoolNoLengthVerifyTest033, TestSize.Level0)
{
    HcfVerifySpi *spiObj = nullptr;
    HcfResult res = HcfVerifySpiEcdsaCreate(&g_params, &spiObj);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(spiObj, nullptr);

    const char *message = "hello world";
    HcfBlob input = {
        .data = (uint8_t *)message,
        .len = 12
    };
    HcfBlob out = { .data = nullptr, .len = 0 };
    bool isOk = spiObj->engineVerify(nullptr, &input, &out);
    ASSERT_EQ(isOk, false);
    HcfObjDestroy(spiObj);
}

HWTEST_F(CryptoBrainPoolNoLengthVerifyTest, CryptoBrainPoolNoLengthVerifyTest034, TestSize.Level0)
{
    HcfVerifySpi *spiObj = nullptr;
    HcfResult res = HcfVerifySpiEcdsaCreate(&g_params, &spiObj);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(spiObj, nullptr);

    const char *message = "hello world";
    HcfBlob input = {
        .data = (uint8_t *)message,
        .len = 12
    };
    bool isOk = spiObj->engineVerify((HcfVerifySpi *)&obj, &input, &input);
    ASSERT_EQ(isOk, false);
    HcfObjDestroy(spiObj);
}

HWTEST_F(CryptoBrainPoolNoLengthVerifyTest, CryptoBrainPoolNoLengthVerifyTest035, TestSize.Level0)
{
    HcfVerifySpi *spiObj = nullptr;
    HcfResult res = HcfVerifySpiEcdsaCreate(&g_params, &spiObj);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(spiObj, nullptr);

    spiObj->base.destroy(nullptr);
    HcfObjDestroy(spiObj);
}

HWTEST_F(CryptoBrainPoolNoLengthVerifyTest, CryptoBrainPoolNoLengthVerifyTest036, TestSize.Level0)
{
    HcfVerifySpi *spiObj = nullptr;
    HcfResult res = HcfVerifySpiEcdsaCreate(&g_params, &spiObj);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(spiObj, nullptr);

    spiObj->base.destroy(&obj);
    HcfObjDestroy(spiObj);
}

static bool GetSignTestData(HcfBlob *out, HcfPriKey *priKey)
{
    HcfSign *sign = nullptr;

    HcfResult res = HcfSignCreate("ECC_BrainPoolP160r1|SHA224", &sign);
    if (res != HCF_SUCCESS) {
        return false;
    }
    res = sign->init(sign, nullptr, priKey);
    if (res != HCF_SUCCESS) {
        HcfObjDestroy(sign);
        return false;
    }
    res = sign->update(sign, &g_mockInput);
    if (res != HCF_SUCCESS) {
        HcfObjDestroy(sign);
        return false;
    }
    res = sign->sign(sign, &g_mockInput, out);
    HcfObjDestroy(sign);
    return res == HCF_SUCCESS;
}

static void MemoryMockTestFunc(uint32_t mallocCount, HcfBlob *out, HcfPubKey *pubKey)
{
    for (uint32_t i = 0; i < mallocCount; i++) {
        ResetRecordMallocNum();
        SetMockMallocIndex(i);
        HcfVerify *verify = nullptr;
        HcfResult res = HcfVerifyCreate("ECC_BrainPoolP160r1|SHA224", &verify);
        if (res != HCF_SUCCESS) {
            continue;
        }
        res = verify->init(verify, nullptr, pubKey);
        if (res != HCF_SUCCESS) {
            HcfObjDestroy(verify);
            continue;
        }
        res = verify->update(verify, &g_mockInput);
        if (res != HCF_SUCCESS) {
            HcfObjDestroy(verify);
            continue;
        }
        (void)verify->verify(verify, nullptr, out);
        HcfObjDestroy(verify);
    }
}

HWTEST_F(CryptoBrainPoolNoLengthVerifyTest, CryptoBrainPoolNoLengthVerifyTest037, TestSize.Level0)
{
    StartRecordMallocNum();

    HcfVerify *verify = nullptr;
    HcfResult res = HcfVerifyCreate("ECC_BrainPoolP160r1|SHA224", &verify);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(verify, nullptr);

    HcfKeyPair *keyPair = nullptr;
    res = GenerateBrainpoolP160r1KeyPair(&keyPair);
    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(keyPair, nullptr);

    res = verify->init(verify, nullptr, keyPair->pubKey);
    ASSERT_EQ(res, HCF_SUCCESS);

    res = verify->update(verify, &g_mockInput);
    ASSERT_EQ(res, HCF_SUCCESS);
    HcfBlob out = { .data = nullptr, .len = 0 };
    GetSignTestData(&out, keyPair->priKey);
    bool flag = verify->verify(verify, &g_mockInput, &out);

    ASSERT_EQ(flag, true);
    HcfObjDestroy(verify);

    uint32_t mallocCount = GetMallocNum();
    MemoryMockTestFunc(mallocCount, &out, keyPair->pubKey);
    EndRecordMallocNum();
    HcfFree(out.data);
    HcfObjDestroy(keyPair);
}

static void OpensslMockTestFunc(uint32_t mallocCount, HcfBlob *out, HcfPubKey *pubKey)
{
    for (uint32_t i = 0; i < mallocCount; i++) {
        ResetOpensslCallNum();
        SetOpensslCallMockIndex(i);
        HcfVerify *verify = nullptr;
        HcfResult res = HcfVerifyCreate("ECC_BrainPoolP160r1|SHA224", &verify);
        if (res != HCF_SUCCESS) {
            continue;
        }
        res = verify->init(verify, nullptr, pubKey);
        if (res != HCF_SUCCESS) {
            HcfObjDestroy(verify);
            continue;
        }
        res = verify->update(verify, &g_mockInput);
        if (res != HCF_SUCCESS) {
            HcfObjDestroy(verify);
            continue;
        }
        (void)verify->verify(verify, &g_mockInput, out);
        HcfObjDestroy(verify);
    }
}

HWTEST_F(CryptoBrainPoolNoLengthVerifyTest, CryptoBrainPoolNoLengthVerifyTest038, TestSize.Level0)
{
    StartRecordOpensslCallNum();
    HcfVerify *verify = nullptr;
    HcfResult res = HcfVerifyCreate("ECC_BrainPoolP160r1|SHA224", &verify);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(verify, nullptr);

    HcfKeyPair *keyPair = nullptr;
    res = GenerateBrainpoolP160r1KeyPair(&keyPair);
    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(keyPair, nullptr);

    res = verify->init(verify, nullptr, keyPair->pubKey);
    ASSERT_EQ(res, HCF_SUCCESS);

    res = verify->update(verify, &g_mockInput);
    ASSERT_EQ(res, HCF_SUCCESS);

    HcfBlob out = { .data = nullptr, .len = 0 };
    ASSERT_EQ(GetSignTestData(&out, keyPair->priKey), true);
    bool flag = verify->verify(verify, &g_mockInput, &out);

    ASSERT_EQ(flag, true);
    HcfObjDestroy(verify);

    uint32_t mallocCount = GetOpensslCallNum();
    OpensslMockTestFunc(mallocCount, &out, keyPair->pubKey);
    EndRecordOpensslCallNum();
    HcfFree(out.data);
    HcfObjDestroy(keyPair);
}

HWTEST_F(CryptoBrainPoolNoLengthVerifyTest, CryptoBrainPoolNoLengthVerifyTest039, TestSize.Level0)
{
    HcfVerify *verify = nullptr;
    HcfResult res = HcfVerifyCreate("ECC_BrainPoolP160r1|SHA224", &verify);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(verify, nullptr);

    int32_t returnInt = 0;
    res = verify->setVerifySpecInt(verify, SM2_USER_ID_UINT8ARR, returnInt);
    ASSERT_EQ(res, HCF_NOT_SUPPORT);
    res = verify->getVerifySpecInt(verify, SM2_USER_ID_UINT8ARR, &returnInt);
    ASSERT_EQ(res, HCF_NOT_SUPPORT);
    HcfBlob returnBlob = { .data = nullptr, .len = 0};
    res = verify->setVerifySpecUint8Array(verify, SM2_USER_ID_UINT8ARR, returnBlob);
    ASSERT_EQ(res, HCF_NOT_SUPPORT);
    char *itemName = nullptr;
    res = verify->getVerifySpecString(verify, SM2_USER_ID_UINT8ARR, &itemName);
    ASSERT_EQ(res, HCF_NOT_SUPPORT);

    HcfObjDestroy(verify);
}
}