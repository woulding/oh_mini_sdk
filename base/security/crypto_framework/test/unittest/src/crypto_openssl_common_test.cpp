/*
 * Copyright (C) 2024 Huawei Device Co., Ltd.
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

#include "openssl_common.h"

#include <gtest/gtest.h>

using namespace std;
using namespace testing::ext;

namespace {
class CryptoOsslCommonTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp();
    void TearDown();
};

void CryptoOsslCommonTest::SetUpTestCase() {}
void CryptoOsslCommonTest::TearDownTestCase() {}
void CryptoOsslCommonTest::SetUp() {}
void CryptoOsslCommonTest::TearDown() {}

HWTEST_F(CryptoOsslCommonTest, CryptoOsslCommonTest01, TestSize.Level0)
{
    HcfResult ret = GetCurveNameByCurveId(0, nullptr);
    EXPECT_EQ(ret, HCF_INVALID_PARAMS);
}

HWTEST_F(CryptoOsslCommonTest, CryptoOsslCommonTest02, TestSize.Level0)
{
    HcfResult ret = GetNidByCurveNameValue(0, nullptr);
    EXPECT_EQ(ret, HCF_INVALID_PARAMS);
}

HWTEST_F(CryptoOsslCommonTest, CryptoOsslCommonTest03, TestSize.Level0)
{
    HcfResult ret = GetGroupNameByNid(0, nullptr);
    EXPECT_EQ(ret, HCF_INVALID_PARAMS);
}

HWTEST_F(CryptoOsslCommonTest, CryptoOsslCommonTest04, TestSize.Level0)
{
    HcfResult ret = GetFormatTypeByFormatValue(0, nullptr);
    EXPECT_EQ(ret, HCF_INVALID_PARAMS);
}

HWTEST_F(CryptoOsslCommonTest, CryptoOsslCommonTest05, TestSize.Level0)
{
    HcfResult ret = GetAlgNameByBits(0, nullptr);
    EXPECT_EQ(ret, HCF_INVALID_PARAMS);
}

HWTEST_F(CryptoOsslCommonTest, CryptoOsslCommonTest06, TestSize.Level0)
{
    HcfResult ret = GetOpensslCurveId(0, nullptr);
    EXPECT_EQ(ret, HCF_INVALID_PARAMS);
}

HWTEST_F(CryptoOsslCommonTest, CryptoOsslCommonTest07, TestSize.Level0)
{
    HcfResult ret = GetSm2SpecStringSm3(nullptr);
    EXPECT_EQ(ret, HCF_INVALID_PARAMS);
}
}