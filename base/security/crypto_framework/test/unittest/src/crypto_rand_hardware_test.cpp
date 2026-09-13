/*
 * Copyright (C) 2025 Huawei Device Co., Ltd.
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
#include <climits>
#include "securec.h"

#include "rand.h"
#include "rand_openssl.h"

#include "memory.h"

using namespace std;
using namespace testing::ext;

namespace {
class CryptoRandHardWareTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp();
    void TearDown();
};

void CryptoRandHardWareTest::SetUpTestCase() {}
void CryptoRandHardWareTest::TearDownTestCase() {}

void CryptoRandHardWareTest::SetUp() // add init here, this will be called before test.
{
}

void CryptoRandHardWareTest::TearDown() // add destroy here, this will be called when test case done.
{
}

HWTEST_F(CryptoRandHardWareTest, CryptoFrameworkRandGenerateTest001, TestSize.Level0)
{
    // create a rand obj
    HcfRand *randObj = nullptr;
    HcfResult ret = HcfRandCreate(&randObj);
    ASSERT_EQ(ret, HCF_SUCCESS);
    // preset params
    int32_t randomLen = 0;
    ret = randObj->enableHardwareEntropy(randObj);
    EXPECT_EQ(ret, HCF_SUCCESS);
    // define randomBlob and seedBlob
    struct HcfBlob randomBlob = {0};
    // test generate random with length 0
    ret = randObj->generateRandom(randObj, randomLen, &randomBlob);
    EXPECT_NE(ret, HCF_SUCCESS);
    HcfObjDestroy(randObj);
}

HWTEST_F(CryptoRandHardWareTest, CryptoFrameworkRandGenerateTest002, TestSize.Level0)
{
    // create a rand obj
    HcfRand *randObj = nullptr;
    HcfResult ret = HcfRandCreate(&randObj);
    ASSERT_EQ(ret, HCF_SUCCESS);
    ret = randObj->enableHardwareEntropy(randObj);
    EXPECT_EQ(ret, HCF_SUCCESS);
    // preset params
    int32_t randomLen = 32;
    // define randomBlob and seedBlob
    struct HcfBlob randomBlob = {0};
    // test generate random
    ret = randObj->generateRandom(randObj, randomLen, &randomBlob);
    EXPECT_EQ(ret, HCF_SUCCESS);
    // destroy the API obj and blob data
    HcfBlobDataClearAndFree(&randomBlob);
    HcfObjDestroy(randObj);
}

HWTEST_F(CryptoRandHardWareTest, CryptoFrameworkRandGenerateTest003, TestSize.Level0)
{
    // create a rand obj
    HcfRand *randObj = nullptr;
    HcfResult ret = HcfRandCreate(&randObj);
    ASSERT_EQ(ret, HCF_SUCCESS);
    ret = randObj->enableHardwareEntropy(randObj);
    EXPECT_EQ(ret, HCF_SUCCESS);
    // preset params
    int32_t randomLen = INT_MAX;
    // define randomBlob and seedBlob
    struct HcfBlob randomBlob = {0};
    // test generate random
    (void)randObj->generateRandom(randObj, randomLen, &randomBlob);
    // destroy the API obj and blob data
    HcfBlobDataClearAndFree(&randomBlob);
    HcfObjDestroy(randObj);
}

HWTEST_F(CryptoRandHardWareTest, CryptoFrameworkSetSeedTest002, TestSize.Level0)
{
    // create a rand obj
    HcfRand *randObj = nullptr;
    HcfResult ret = HcfRandCreate(&randObj);
    ASSERT_EQ(ret, HCF_SUCCESS);
    ret = randObj->enableHardwareEntropy(randObj);
    EXPECT_EQ(ret, HCF_SUCCESS);
    // preset params
    int32_t seedLen = 32;
    // define randomBlob and seedBlob
    struct HcfBlob seedBlob = { .data = nullptr, .len = 0 };
    // test generate seed
    ret = randObj->generateRandom(randObj, seedLen, &seedBlob);
    EXPECT_EQ(ret, HCF_SUCCESS);
    // test set seed
    ret = randObj->setSeed(randObj, &seedBlob);
    EXPECT_EQ(ret, HCF_SUCCESS);
    // destroy the API obj and blob data
    HcfBlobDataClearAndFree(&seedBlob);
    HcfObjDestroy(randObj);
}

HWTEST_F(CryptoRandHardWareTest, CryptoFrameworkSetSeedTest003, TestSize.Level0)
{
    // create a rand obj
    HcfRand *randObj = nullptr;
    HcfResult ret = HcfRandCreate(&randObj);
    ASSERT_EQ(ret, HCF_SUCCESS);
    ret = randObj->enableHardwareEntropy(randObj);
    EXPECT_EQ(ret, HCF_SUCCESS);
    // preset params
    int32_t seedLen = 1000;
    // define randomBlob and seedBlob
    struct HcfBlob seedBlob = { .data = nullptr, .len = 0 };
    // test generate seed
    ret = randObj->generateRandom(randObj, seedLen, &seedBlob);
    EXPECT_EQ(ret, HCF_SUCCESS);
    // test set seed
    ret = randObj->setSeed(randObj, &seedBlob);
    EXPECT_EQ(ret, HCF_SUCCESS);
    // destroy the API obj and blob data
    HcfBlobDataClearAndFree(&seedBlob);
    HcfObjDestroy(randObj);
}
}