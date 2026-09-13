/*
 * Copyright (C) 2022 Huawei Device Co., Ltd.
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

#include "md.h"
#include "md_openssl.h"

#include "memory.h"

using namespace std;
using namespace testing::ext;

namespace {
class CryptoMdSM3Test : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp();
    void TearDown();
};
constexpr uint32_t SM3_LEN = 32;

void CryptoMdSM3Test::SetUpTestCase() {}
void CryptoMdSM3Test::TearDownTestCase() {}

void CryptoMdSM3Test::SetUp() // add init here, this will be called before test.
{
}

void CryptoMdSM3Test::TearDown() // add destroy here, this will be called when test case done.
{
}


HWTEST_F(CryptoMdSM3Test, CryptoFrameworkMdSM3CreateTest001, TestSize.Level0)
{
    // create a SM3 obj
    HcfResult ret = HcfMdCreate("SM3", nullptr);
    EXPECT_NE(ret, HCF_SUCCESS);
}

HWTEST_F(CryptoMdSM3Test, CryptoFrameworkMdSM3AlgoSuppTest001, TestSize.Level0)
{
    // create a SM3 obj
    HcfMd *mdObj = nullptr;
    HcfResult ret = HcfMdCreate("SM3", &mdObj);
    ASSERT_EQ(ret, HCF_SUCCESS);
    ASSERT_NE(mdObj, nullptr);
    HcfObjDestroy(mdObj);
}

HWTEST_F(CryptoMdSM3Test, CryptoFrameworkMdSM3AlgoNameTest001, TestSize.Level0)
{
    // create a SM3 obj
    HcfMd *mdObj = nullptr;
    HcfResult ret = HcfMdCreate("SM3", &mdObj);
    ASSERT_EQ(ret, HCF_SUCCESS);
    ASSERT_NE(mdObj, nullptr);
    // test api functions
    const char *algoName =  mdObj->getAlgoName(mdObj);
    int32_t cmpRes = strcmp(algoName, "SM3");
    EXPECT_EQ(cmpRes, HCF_SUCCESS);
    HcfObjDestroy(mdObj);
}

HWTEST_F(CryptoMdSM3Test, CryptoFrameworkMdSM3UpdateTest001, TestSize.Level0)
{
    // create a SM3 obj
    HcfMd *mdObj = nullptr;
    HcfResult ret = HcfMdCreate("SM3", &mdObj);
    ASSERT_EQ(ret, HCF_SUCCESS);
    // define input and output data in blob form
    HcfBlob *inBlob = nullptr;
    // test api functions
    ret = mdObj->update(mdObj, inBlob);
    EXPECT_NE(ret, HCF_SUCCESS);
    HcfObjDestroy(mdObj);
}

HWTEST_F(CryptoMdSM3Test, CryptoFrameworkMdSM3UpdateTest002, TestSize.Level0)
{
    // create a SM3 obj
    HcfMd *mdObj = nullptr;
    HcfResult ret = HcfMdCreate("SM3", &mdObj);
    ASSERT_EQ(ret, HCF_SUCCESS);
    // set input and output buf
    uint8_t testData[] = "My test data";
    // define input and output data in blob form
    HcfBlob inBlob = {.data = reinterpret_cast<uint8_t *>(testData), .len = sizeof(testData)};
    // test api functions
    ret = mdObj->update(mdObj, &inBlob);
    EXPECT_EQ(ret, HCF_SUCCESS);
    HcfObjDestroy(mdObj);
}

HWTEST_F(CryptoMdSM3Test, CryptoFrameworkMdSM3DoFinalTest001, TestSize.Level0)
{
    // create a SM3 obj
    HcfMd *mdObj = nullptr;
    HcfResult ret = HcfMdCreate("SM3", &mdObj);
    ASSERT_EQ(ret, HCF_SUCCESS);
    // set input and output buf
    HcfBlob outBlob = { .data = nullptr, .len = 0 };
    // test api functions
    ret = mdObj->doFinal(mdObj, &outBlob);
    EXPECT_EQ(ret, HCF_SUCCESS);
    // destroy the API obj and blob data
    HcfBlobDataClearAndFree(&outBlob);
    HcfObjDestroy(mdObj);
}

HWTEST_F(CryptoMdSM3Test, CryptoFrameworkMdSM3DoFinalTest002, TestSize.Level0)
{
    // create a SM3 obj
    HcfMd *mdObj = nullptr;
    HcfResult ret = HcfMdCreate("SM3", &mdObj);
    ASSERT_EQ(ret, HCF_SUCCESS);
    // set input and output buf
    uint8_t testData[] = "My test data";
    // define input and output data in blob form
    HcfBlob inBlob = {.data = reinterpret_cast<uint8_t *>(testData), .len = sizeof(testData)};
    HcfBlob outBlob = { .data = nullptr, .len = 0 };
    // test api functions
    ret = mdObj->update(mdObj, &inBlob);
    EXPECT_EQ(ret, HCF_SUCCESS);
    ret = mdObj->doFinal(mdObj, &outBlob);
    EXPECT_EQ(ret, HCF_SUCCESS);
    // destroy the API obj and blob data
    HcfBlobDataClearAndFree(&outBlob);
    HcfObjDestroy(mdObj);
}

HWTEST_F(CryptoMdSM3Test, CryptoFrameworkMdSM3LenTest001, TestSize.Level0)
{
    // create a API obj with SM3
    HcfMd *mdObj = nullptr;
    HcfResult ret = HcfMdCreate("SM3", &mdObj);
    ASSERT_EQ(ret, HCF_SUCCESS);
    // test api functions
    uint32_t len = mdObj->getMdLength(mdObj);
    EXPECT_EQ(len, SM3_LEN);
    HcfObjDestroy(mdObj);
}

HWTEST_F(CryptoMdSM3Test, CryptoFrameworkMdSM3AlgoTest002, TestSize.Level0)
{
    // create a API obj with SM3
    HcfMd *mdObj = nullptr;
    HcfResult ret = HcfMdCreate("SM3", &mdObj);
    ASSERT_EQ(ret, HCF_SUCCESS);
    // set input and output buf
    uint8_t testData[] = "My test data";
    // define input and output data in blob form
    struct HcfBlob inBlob = {.data = reinterpret_cast<uint8_t *>(testData), .len = sizeof(testData)};
    struct HcfBlob outBlob = { .data = nullptr, .len = 0 };
    // test api functions
    ret = mdObj->update(mdObj, &inBlob);
    EXPECT_EQ(ret, HCF_SUCCESS);
    ret = mdObj->doFinal(mdObj, &outBlob);
    EXPECT_EQ(ret, HCF_SUCCESS);
    uint32_t len = mdObj->getMdLength(mdObj);
    EXPECT_EQ(len, SM3_LEN);
    // destroy the API obj and blob data
    HcfBlobDataClearAndFree(&outBlob);
    HcfObjDestroy(mdObj);
}

HWTEST_F(CryptoMdSM3Test, CryptoFrameworkMdSM3AlgoTest003, TestSize.Level0)
{
    HcfMdSpi *spiObj = nullptr;
    HcfResult ret = OpensslMdSpiCreate("SM3", &spiObj);
    EXPECT_EQ(ret, HCF_SUCCESS);
    HcfObjDestroy(spiObj);
}

HWTEST_F(CryptoMdSM3Test, CryptoFrameworkMdSM3AlgoTest004, TestSize.Level0)
{
    HcfMdSpi *spiObj = nullptr;
    HcfResult ret = OpensslMdSpiCreate("SM2", &spiObj);
    EXPECT_NE(ret, HCF_SUCCESS);
}
}
