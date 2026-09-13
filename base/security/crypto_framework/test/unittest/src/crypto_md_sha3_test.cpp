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
#include "securec.h"

#include "md.h"
#include "md_openssl.h"

#include "memory.h"

using namespace std;
using namespace testing::ext;

namespace {
class CryptoMdSha3Test : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp();
    void TearDown();
};

constexpr uint32_t MAX_MD_BLOB_LEN = 5000;
constexpr uint32_t SHA3_256_LEN = 32;
constexpr uint32_t SHA3_384_LEN = 48;
constexpr uint32_t SHA3_512_LEN = 64;

static char g_testBigData[] = "VqRH5dzdeeturr5zN5vE77DtqjV7kNKbDJqk4mNqyYRTXymhjR\r\n"
"Yz8c2pNvJiCxyFwvLvWfPh2Y2eDAuxbdm2Dt4UzKJtNqEpNYKVZLiyH4a4MhR4BpFhvhJVHy2ALbYq2rW\r\n"
"LqJfNzA6v8kHNaFypNDMgX35kifyCiYkq85XUKDJCdewUzCZ2N8twC8Z9kL37K67bkL35VYFZSXyrNTdV\r\n"
"pB6kqPjwZYrjx5tXzMMgJW8ePqmAhZUVjtPGXTLVt8BUnaVRuWjD97xjS3VH9EwFeyrqJ46B92rkuGexY\r\n"
"cjXuvhHTnQNPbYfake7KMEWG2wgGLmZmjnakULhFgjt6TQhvCWMJAHYn8Zgczd3C3HkPrQgUXJgAiwf3r\r\n"
"jJbgbBpQkkbcfMBZZ3SSLe2J9jw6MkdEf3eBQX9rFVQSgBQgZ9KEW8XLb5kCTcyhRZPBbiHD4qQRyrwKT\r\n"
"mnGZqP5Aru6GDkhFk78jfjtk35HyB7AY7UZXkczRfVYAxa5Mk256MhAHkE3uAvPZTyY7N3qk9U7cLTrce\r\n"
"wJLH6wrymrMvQWgpvrBevMghnURZUcZAWUznDn56WnwGAzYAWmJqdXqAfcvgZwCFTjxdiaEZGpEyUrcS8\r\n"
"nr48ZeXS5aytz5Y7RnU5SxcHbgF8PerWVdftxmghPAvGkQ6f3dcXr9w9bbGqg5KJHyQCxabp8bjZpyFdb\r\n"
"VTq8DpQ6AJjxdjn8cuLTf9giGFxDjtQncicUdqP7YvVDr5AFgWc83cddyryVLZEBGAFfqbbKWF9KnPjRZ\r\n"
"AbuZ7SqrkxhQHu87Hxh3xHUHB8Lb3DGZ4vhnqaLnJBxFK8Ve4F2FfbgfHfQtALFDUWp6dSz8Hvdpj4CGw\r\n"
"FaSb8b5hTemaQRguYAqaUwJVvZ7G2AwkFnV9PHUngmybAFxg8HMAT3K7yAiQJWWqPxdGq8jXPAqZFNkGu\r\n"
"2mnJ5xfnY3z63PFk6TXU9Ga2YmHvtycXxwqMBEctQRa3zVWGVSrh3NF6jXa\r\n";

void CryptoMdSha3Test::SetUpTestCase() {}
void CryptoMdSha3Test::TearDownTestCase() {}

void CryptoMdSha3Test::SetUp() // add init here, this will be called before test.
{
}

void CryptoMdSha3Test::TearDown() // add destroy here, this will be called when test case done.
{
}

/**
 * @tc.name: CryptoFrameworkMdTest.CryptoFrameworkMdCreateTest001
 * @tc.desc: Verify that the creation of the SHA1 Md obj is normal.
 * @tc.type: FUNC
 * @tc.require: I5QWEM
 */

HWTEST_F(CryptoMdSha3Test, CryptoFrameworkMdSha3Test001, TestSize.Level0)
{
    // create a SHA3_224 obj
    HcfMd *mdObj = nullptr;
    HcfResult ret = HcfMdCreate("SHA3-512", &mdObj);
    ASSERT_EQ(ret, HCF_SUCCESS);
    ASSERT_NE(mdObj, nullptr);
    HcfObjDestroy(mdObj);
}

HWTEST_F(CryptoMdSha3Test, CryptoFrameworkMdSha3Test002, TestSize.Level0)
{
    // create a SHA3_256 obj
    HcfMd *mdObj = nullptr;
    HcfResult ret = HcfMdCreate("SHA3-256", &mdObj);
    ASSERT_EQ(ret, HCF_SUCCESS);
    ASSERT_NE(mdObj, nullptr);
    HcfObjDestroy(mdObj);
}

HWTEST_F(CryptoMdSha3Test, CryptoFrameworkMdSha3Test003, TestSize.Level0)
{
    // create a SHA3_384 obj
    HcfMd *mdObj = nullptr;
    HcfResult ret = HcfMdCreate("SHA3-384", &mdObj);
    ASSERT_EQ(ret, HCF_SUCCESS);
    ASSERT_NE(mdObj, nullptr);
    HcfObjDestroy(mdObj);
}

HWTEST_F(CryptoMdSha3Test, CryptoFrameworkMdAlgoNameTest001, TestSize.Level0)
{
    // create a SHA3_224 obj
    HcfMd *mdObj = nullptr;
    HcfResult ret = HcfMdCreate("SHA3-512", &mdObj);
    ASSERT_EQ(ret, HCF_SUCCESS);
    ASSERT_NE(mdObj, nullptr);
    // test api functions
    const char *algoName =  mdObj->getAlgoName(mdObj);
    int32_t cmpRes = strcmp(algoName, "SHA3-512");
    EXPECT_EQ(cmpRes, HCF_SUCCESS);
    HcfObjDestroy(mdObj);
}

HWTEST_F(CryptoMdSha3Test, CryptoFrameworkMdAlgoNameTest002, TestSize.Level0)
{
    // create a SHA3_256 obj
    HcfMd *mdObj = nullptr;
    HcfResult ret = HcfMdCreate("SHA3-256", &mdObj);
    ASSERT_EQ(ret, HCF_SUCCESS);
    ASSERT_NE(mdObj, nullptr);
    // test api functions
    const char *algoName =  mdObj->getAlgoName(mdObj);
    int32_t cmpRes = strcmp(algoName, "SHA3-256");
    EXPECT_EQ(cmpRes, HCF_SUCCESS);
    HcfObjDestroy(mdObj);
}

HWTEST_F(CryptoMdSha3Test, CryptoFrameworkMdAlgoNameTest003, TestSize.Level0)
{
    // create a SHA3_384 obj
    HcfMd *mdObj = nullptr;
    HcfResult ret = HcfMdCreate("SHA3-384", &mdObj);
    ASSERT_EQ(ret, HCF_SUCCESS);
    ASSERT_NE(mdObj, nullptr);
    // test api functions
    const char *algoName =  mdObj->getAlgoName(mdObj);
    int32_t cmpRes = strcmp(algoName, "SHA3-384");
    EXPECT_EQ(cmpRes, HCF_SUCCESS);
    HcfObjDestroy(mdObj);
}

HWTEST_F(CryptoMdSha3Test, CryptoFrameworkMdUpdateTest001, TestSize.Level0)
{
    // create a SHA3_224 obj
    HcfMd *mdObj = nullptr;
    HcfResult ret = HcfMdCreate("SHA3-512", &mdObj);
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

HWTEST_F(CryptoMdSha3Test, CryptoFrameworkMdDoFinalTest001, TestSize.Level0)
{
    // create a SHA3_224 obj
    HcfMd *mdObj = nullptr;
    HcfResult ret = HcfMdCreate("SHA3-512", &mdObj);
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

HWTEST_F(CryptoMdSha3Test, CryptoFrameworkMdDoFinalTest002, TestSize.Level0)
{
    // create a SHA3_224 obj
    HcfMd *mdObj = nullptr;
    HcfResult ret = HcfMdCreate("SHA3-512", &mdObj);
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

HWTEST_F(CryptoMdSha3Test, CryptoFrameworkMdDoFinalTest003, TestSize.Level0)
{
    // create a SHA3_224 obj
    HcfMd *mdObj = nullptr;
    HcfResult ret = HcfMdCreate("SHA3-512", &mdObj);
    ASSERT_EQ(ret, HCF_SUCCESS);
    // define input and output data in blob form
    HcfBlob inBlob = { .data = nullptr, .len = 0 };
    inBlob.data = reinterpret_cast<uint8_t *>(g_testBigData);
    inBlob.len = strnlen(g_testBigData, MAX_MD_BLOB_LEN);
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

HWTEST_F(CryptoMdSha3Test, CryptoFrameworkMdLenTest001, TestSize.Level0)
{
    // create a API obj with SHA3_224
    HcfMd *mdObj = nullptr;
    HcfResult ret = HcfMdCreate("SHA3-512", &mdObj);
    ASSERT_EQ(ret, HCF_SUCCESS);
    // test api functions
    uint32_t len = mdObj->getMdLength(mdObj);
    EXPECT_EQ(len, SHA3_512_LEN);
    HcfObjDestroy(mdObj);
}

HWTEST_F(CryptoMdSha3Test, CryptoFrameworkMdLenTest002, TestSize.Level0)
{
    // create a API obj with SHA3_256
    HcfMd *mdObj = nullptr;
    HcfResult ret = HcfMdCreate("SHA3-256", &mdObj);
    ASSERT_EQ(ret, HCF_SUCCESS);
    // test api functions
    uint32_t len = mdObj->getMdLength(mdObj);
    EXPECT_EQ(len, SHA3_256_LEN);
    HcfObjDestroy(mdObj);
}

HWTEST_F(CryptoMdSha3Test, CryptoFrameworkMdLenTest003, TestSize.Level0)
{
    // create a API obj with SHA3_384
    HcfMd *mdObj = nullptr;
    HcfResult ret = HcfMdCreate("SHA3-384", &mdObj);
    ASSERT_EQ(ret, HCF_SUCCESS);
    // test api functions
    uint32_t len = mdObj->getMdLength(mdObj);
    EXPECT_EQ(len, SHA3_384_LEN);
    HcfObjDestroy(mdObj);
}

HWTEST_F(CryptoMdSha3Test, CryptoFrameworkMdAlgoTest001, TestSize.Level0)
{
    // create a API obj with SHA3_384
    HcfMd *mdObj = nullptr;
    HcfResult ret = HcfMdCreate("SHA3-384", &mdObj);
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
    EXPECT_EQ(len, SHA3_384_LEN);
    // destroy the API obj and blob data
    HcfBlobDataClearAndFree(&outBlob);
    HcfObjDestroy(mdObj);
}

HWTEST_F(CryptoMdSha3Test, CryptoFrameworkMdAlgoTest002, TestSize.Level0)
{
    // create a API obj with SHA3_256
    HcfMd *mdObj = nullptr;
    HcfResult ret = HcfMdCreate("SHA3-256", &mdObj);
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
    EXPECT_EQ(len, SHA3_256_LEN);
    // destroy the API obj and blob data
    HcfBlobDataClearAndFree(&outBlob);
    HcfObjDestroy(mdObj);
}

HWTEST_F(CryptoMdSha3Test, CryptoFrameworkMdAlgoTest003, TestSize.Level0)
{
    // create a API obj with SHA3_224
    HcfMd *mdObj = nullptr;
    HcfResult ret = HcfMdCreate("SHA3-512", &mdObj);
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
    EXPECT_EQ(len, SHA3_512_LEN);
    // destroy the API obj and blob data
    HcfBlobDataClearAndFree(&outBlob);
    HcfObjDestroy(mdObj);
}
}