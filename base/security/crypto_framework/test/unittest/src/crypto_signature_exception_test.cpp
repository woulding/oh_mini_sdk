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

#include "signature_rsa_openssl.c"

using namespace std;
using namespace testing::ext;

namespace {
class CryptoSignatureExceptionTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp();
    void TearDown();
};

void CryptoSignatureExceptionTest::SetUpTestCase() {}
void CryptoSignatureExceptionTest::TearDownTestCase() {}
void CryptoSignatureExceptionTest::SetUp() {}
void CryptoSignatureExceptionTest::TearDown() {}

static const char *GetMockClass(void)
{
    return "HcfAsyKeyGenerator";
}

HcfObjectBase g_obj = {
    .getClass = GetMockClass,
    .destroy = nullptr
};

HWTEST_F(CryptoSignatureExceptionTest, CryptoSignatureExceptionTest001, TestSize.Level0)
{
    HcfPriKey sk;
    HcfResult ret = EngineSignInit((HcfSignSpi *)&g_obj, nullptr, &sk);
    ASSERT_EQ(ret, HCF_INVALID_PARAMS);

    ret = EngineSignInit((HcfSignSpi *)&g_obj, nullptr, &sk);
    ASSERT_EQ(ret, HCF_INVALID_PARAMS);

    DestroyRsaSign(nullptr);
    DestroyRsaSign((HcfObjectBase *)&g_obj);

    DestroyRsaVerify(nullptr);
    DestroyRsaVerify((HcfObjectBase *)&g_obj);
}

HWTEST_F(CryptoSignatureExceptionTest, CryptoSignatureExceptionTest002, TestSize.Level0)
{
    HcfPubKey pk;
    HcfResult ret = EngineVerifyInit((HcfVerifySpi *)&g_obj, nullptr, &pk);
    ASSERT_EQ(ret, HCF_INVALID_PARAMS);

    ret = EngineVerifyInit((HcfVerifySpi *)&g_obj, nullptr, &pk);
    ASSERT_EQ(ret, HCF_INVALID_PARAMS);
}

HWTEST_F(CryptoSignatureExceptionTest, CryptoSignatureExceptionTest003, TestSize.Level0)
{
    HcfResult ret = EngineSignUpdate((HcfSignSpi *)&g_obj, nullptr);
    ASSERT_EQ(ret, HCF_INVALID_PARAMS);

    ret = EngineSignUpdate(nullptr, nullptr);
    ASSERT_EQ(ret, HCF_INVALID_PARAMS);

    HcfBlob blob = { .data = nullptr, .len = 0 };
    ret = EngineSignUpdate((HcfSignSpi *)&g_obj, &blob);
    ASSERT_EQ(ret, HCF_INVALID_PARAMS);

    uint8_t plan[] = "this is signature test!\0";
    HcfBlob input = {.data = (uint8_t *)plan, .len = strlen((char *)plan)};
    ret = EngineSignUpdate((HcfSignSpi *)&g_obj, &input);
    ASSERT_EQ(ret, HCF_INVALID_PARAMS);
}

HWTEST_F(CryptoSignatureExceptionTest, CryptoSignatureExceptionTest004, TestSize.Level0)
{
    HcfResult ret = EngineVerifyUpdate((HcfVerifySpi *)&g_obj, nullptr);
    ASSERT_EQ(ret, HCF_INVALID_PARAMS);

    ret = EngineVerifyUpdate(nullptr, nullptr);
    ASSERT_EQ(ret, HCF_INVALID_PARAMS);

    HcfBlob blob = { .data = nullptr, .len = 0 };
    ret = EngineSignUpdate((HcfSignSpi *)&g_obj, &blob);
    ASSERT_EQ(ret, HCF_INVALID_PARAMS);

    uint8_t plan[] = "this is verify test!\0";
    HcfBlob output = {.data = (uint8_t *)plan, .len = strlen((char *)plan)};
    ret = EngineSignUpdate((HcfSignSpi *)&g_obj, &output);
    ASSERT_EQ(ret, HCF_INVALID_PARAMS);
}

HWTEST_F(CryptoSignatureExceptionTest, CryptoSignatureExceptionTest005, TestSize.Level0)
{
    HcfResult ret = EngineSign((HcfSignSpi *)&g_obj, nullptr, nullptr);
    ASSERT_EQ(ret, HCF_INVALID_PARAMS);

    ret = EngineSign(nullptr, nullptr, nullptr);
    ASSERT_EQ(ret, HCF_INVALID_PARAMS);

    HcfBlob blob = { .data = nullptr, .len = 0 };
    ret = EngineSign((HcfSignSpi *)&g_obj, nullptr, &blob);
    ASSERT_EQ(ret, HCF_INVALID_PARAMS);
}

HWTEST_F(CryptoSignatureExceptionTest, CryptoSignatureExceptionTest006, TestSize.Level0)
{
    bool ret = EngineVerify(nullptr, nullptr, nullptr);
    ASSERT_EQ(ret, false);

    ret = EngineVerify((HcfVerifySpi *)&g_obj, nullptr, nullptr);
    ASSERT_EQ(ret, false);

    HcfBlob blob = { .data = nullptr, .len = 0 };
    ret = EngineVerify((HcfVerifySpi *)&g_obj, nullptr, &blob);
    ASSERT_EQ(ret, false);

    uint8_t plan[] = "this is verify test!\0";
    HcfBlob output = {.data = (uint8_t *)plan, .len = strlen((char *)plan)};
    ret = EngineVerify((HcfVerifySpi *)&g_obj, nullptr, &output);
    ASSERT_EQ(ret, false);
}

HWTEST_F(CryptoSignatureExceptionTest, CryptoSignatureExceptionTest007, TestSize.Level0)
{
    HcfResult ret = EngineSetSignSpecInt(nullptr, PSS_SALT_LEN_INT, 0);
    ASSERT_EQ(ret, HCF_INVALID_PARAMS);

    ret = EngineSetSignSpecInt((HcfSignSpi *)&g_obj, PSS_SALT_LEN_INT, 0);
    ASSERT_EQ(ret, HCF_INVALID_PARAMS);

    HcfSign *sign = nullptr;
    HcfResult res = HcfSignCreate("DSA1024|SHA256", &sign);
    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(sign, nullptr);

    HcfSignSpi signObj { .base = *(HcfObjectBase *)sign };

    ret = EngineSetSignSpecInt(&signObj, PSS_SALT_LEN_INT, RSA_PSS_SALTLEN_DIGEST);
    ASSERT_NE(ret, HCF_SUCCESS);

    ret = EngineSetSignSpecInt(&signObj, PSS_SALT_LEN_INT, RSA_PSS_SALTLEN_MAX_SIGN);
    ASSERT_NE(ret, HCF_SUCCESS);

    ret = EngineSetSignSpecInt(&signObj, PSS_SALT_LEN_INT, RSA_PSS_SALTLEN_MAX);
    ASSERT_NE(ret, HCF_SUCCESS);

    sign->base.destroy((HcfObjectBase *)sign);
}

HWTEST_F(CryptoSignatureExceptionTest, CryptoSignatureExceptionTest008, TestSize.Level0)
{
    HcfResult ret = EngineGetSignSpecInt(nullptr, PSS_SALT_LEN_INT, nullptr);
    ASSERT_EQ(ret, HCF_INVALID_PARAMS);

    ret = EngineGetSignSpecInt((HcfSignSpi *)&g_obj, PSS_SALT_LEN_INT, nullptr);
    ASSERT_EQ(ret, HCF_INVALID_PARAMS);

    int32_t returnInt = 0;
    ret = EngineGetSignSpecInt((HcfSignSpi *)&g_obj, PSS_SALT_LEN_INT, &returnInt);
    ASSERT_EQ(ret, HCF_INVALID_PARAMS);
}

HWTEST_F(CryptoSignatureExceptionTest, CryptoSignatureExceptionTest009, TestSize.Level0)
{
    HcfResult ret = EngineGetSignSpecString(nullptr, PSS_SALT_LEN_INT, nullptr);
    ASSERT_EQ(ret, HCF_INVALID_PARAMS);

    ret = EngineGetSignSpecString((HcfSignSpi *)&g_obj, PSS_SALT_LEN_INT, nullptr);
    ASSERT_EQ(ret, HCF_INVALID_PARAMS);

    char *returnString;
    ret = EngineGetSignSpecString((HcfSignSpi *)&g_obj, PSS_SALT_LEN_INT, &returnString);
    ASSERT_EQ(ret, HCF_INVALID_PARAMS);
}

HWTEST_F(CryptoSignatureExceptionTest, CryptoSignatureExceptionTest010, TestSize.Level0)
{
    HcfResult ret = EngineSetVerifySpecInt(nullptr, PSS_SALT_LEN_INT, 0);
    ASSERT_EQ(ret, HCF_INVALID_PARAMS);

    ret = EngineSetVerifySpecInt((HcfVerifySpi *)&g_obj, PSS_MD_NAME_STR, 0);
    ASSERT_EQ(ret, HCF_INVALID_PARAMS);

    HcfVerify *verify = nullptr;
    HcfResult res = HcfVerifyCreate("DSA1024|SHA256", &verify);
    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(verify, nullptr);

    HcfVerifySpi verifyObj { .base = *(HcfObjectBase *)verify };

    ret = EngineSetVerifySpecInt(&verifyObj, PSS_SALT_LEN_INT, RSA_PSS_SALTLEN_DIGEST);
    ASSERT_NE(ret, HCF_SUCCESS);

    ret = EngineSetVerifySpecInt(&verifyObj, PSS_SALT_LEN_INT, RSA_PSS_SALTLEN_AUTO);
    ASSERT_NE(ret, HCF_SUCCESS);

    ret = EngineSetVerifySpecInt(&verifyObj, PSS_SALT_LEN_INT, RSA_PSS_SALTLEN_MAX);
    ASSERT_NE(ret, HCF_SUCCESS);

    verify->base.destroy((HcfObjectBase *)verify);
}

HWTEST_F(CryptoSignatureExceptionTest, CryptoSignatureExceptionTest011, TestSize.Level0)
{
    HcfResult ret = EngineGetVerifySpecInt(nullptr, PSS_SALT_LEN_INT, nullptr);
    ASSERT_EQ(ret, HCF_INVALID_PARAMS);

    ret =EngineGetVerifySpecInt((HcfVerifySpi *)&g_obj, PSS_SALT_LEN_INT, nullptr);
    ASSERT_EQ(ret, HCF_INVALID_PARAMS);

    int32_t returnInt = 0;
    ret =EngineGetVerifySpecInt((HcfVerifySpi *)&g_obj, PSS_SALT_LEN_INT, &returnInt);
    ASSERT_EQ(ret, HCF_INVALID_PARAMS);
}

HWTEST_F(CryptoSignatureExceptionTest, CryptoSignatureExceptionTest012, TestSize.Level0)
{
    HcfResult ret = EngineGetVerifySpecString(nullptr, PSS_SALT_LEN_INT, nullptr);
    ASSERT_EQ(ret, HCF_INVALID_PARAMS);

    ret = EngineGetVerifySpecString((HcfVerifySpi *)&g_obj, PSS_SALT_LEN_INT, nullptr);
    ASSERT_EQ(ret, HCF_INVALID_PARAMS);

    char *returnString = nullptr;
    ret = EngineGetVerifySpecString((HcfVerifySpi *)&g_obj, PSS_SALT_LEN_INT, &returnString);
    ASSERT_EQ(ret, HCF_INVALID_PARAMS);
}

HWTEST_F(CryptoSignatureExceptionTest, CryptoSignatureExceptionTest013, TestSize.Level0)
{
    HcfResult ret = HcfSignSpiRsaCreate(nullptr, nullptr);
    ASSERT_EQ(ret, HCF_INVALID_PARAMS);

    ret = HcfSignSpiRsaCreate((HcfSignatureParams *)&g_obj, nullptr);
    ASSERT_EQ(ret, HCF_INVALID_PARAMS);

    HcfSignSpi *returnObj = nullptr;
    HcfSignatureParams obj = {};
    ret = HcfSignSpiRsaCreate((HcfSignatureParams *)&obj, &returnObj);
    ASSERT_EQ(ret, HCF_INVALID_PARAMS);
}

HWTEST_F(CryptoSignatureExceptionTest, CryptoSignatureExceptionTest014, TestSize.Level0)
{
    HcfResult ret = HcfVerifySpiRsaCreate(nullptr, nullptr);
    ASSERT_EQ(ret, HCF_INVALID_PARAMS);

    ret = HcfVerifySpiRsaCreate((HcfSignatureParams *)&g_obj, nullptr);
    ASSERT_EQ(ret, HCF_INVALID_PARAMS);

    HcfVerifySpi *returnObj = nullptr;
    HcfSignatureParams obj = {};
    ret = HcfVerifySpiRsaCreate((HcfSignatureParams *)&obj, &returnObj);
    ASSERT_EQ(ret, HCF_INVALID_PARAMS);
}
}