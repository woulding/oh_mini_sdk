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

#include "memory.h"
#include "signature.h"

using namespace std;
using namespace testing::ext;

namespace {
class CryptoDsaVerifyTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp();
    void TearDown();
};

void CryptoDsaVerifyTest::SetUpTestCase() {}
void CryptoDsaVerifyTest::TearDownTestCase() {}
void CryptoDsaVerifyTest::SetUp() {}
void CryptoDsaVerifyTest::TearDown() {}

static const char *g_hcfVerifyClass = "HcfVerify";

HWTEST_F(CryptoDsaVerifyTest, CryptoDsaVerifyTest001, TestSize.Level0)
{
    HcfVerify *verify = nullptr;
    HcfResult ret = HcfVerifyCreate("DSA2048|NoHash", &verify);

    ASSERT_EQ(ret, HCF_SUCCESS);
    ASSERT_NE(verify, nullptr);

    const char *verifyClassName = verify->base.getClass();
    HcfObjDestroy(verify);
    ASSERT_STREQ(verifyClassName, g_hcfVerifyClass);
}

HWTEST_F(CryptoDsaVerifyTest, CryptoDsaVerifyTest002, TestSize.Level0)
{
    HcfVerify *verify = nullptr;
    HcfResult ret = HcfVerifyCreate("DSA2048|NoHash", &verify);

    ASSERT_EQ(ret, HCF_SUCCESS);
    ASSERT_NE(verify, nullptr);

    verify->base.destroy(&(verify->base));
}

HWTEST_F(CryptoDsaVerifyTest, CryptoDsaVerifyTest003, TestSize.Level0)
{
    HcfVerify *verify = nullptr;
    HcfResult ret = HcfVerifyCreate("DSA2048|NoHash", &verify);

    ASSERT_EQ(ret, HCF_SUCCESS);
    ASSERT_NE(verify, nullptr);

    const char *alg = verify->getAlgoName(verify);
    ASSERT_STREQ(alg, "DSA2048|NoHash");
    HcfObjDestroy(verify);
}

HWTEST_F(CryptoDsaVerifyTest, CryptoDsaVerifyTest004, TestSize.Level0)
{
    HcfVerify *verify = nullptr;
    HcfResult ret = HcfVerifyCreate("DSA2048|NoHash", &verify);

    ASSERT_EQ(ret, HCF_SUCCESS);
    ASSERT_NE(verify, nullptr);

    ret = verify->setVerifySpecInt(verify, PSS_SALT_LEN_INT, 0);
    HcfObjDestroy(verify);
    ASSERT_EQ(ret, HCF_NOT_SUPPORT);
}

HWTEST_F(CryptoDsaVerifyTest, CryptoDsaVerifyTest105, TestSize.Level0)
{
    HcfVerify *verify = nullptr;
    HcfResult ret = HcfVerifyCreate("DSA2048|NoHash", &verify);

    ASSERT_EQ(ret, HCF_SUCCESS);
    ASSERT_NE(verify, nullptr);

    int32_t returnInt;
    ret = verify->getVerifySpecInt(verify, PSS_SALT_LEN_INT, &returnInt);
    HcfObjDestroy(verify);
    ASSERT_EQ(ret, HCF_NOT_SUPPORT);
}

HWTEST_F(CryptoDsaVerifyTest, CryptoDsaVerifyTest106, TestSize.Level0)
{
    HcfVerify *verify = nullptr;
    HcfResult ret = HcfVerifyCreate("DSA2048|NoHash", &verify);

    ASSERT_EQ(ret, HCF_SUCCESS);
    ASSERT_NE(verify, nullptr);

    char *returnC = nullptr;
    ret = verify->getVerifySpecString(verify, PSS_MGF_NAME_STR, &returnC);
    HcfObjDestroy(verify);
    ASSERT_EQ(ret, HCF_NOT_SUPPORT);
}
}