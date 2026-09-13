/*
 * Copyright (C) 2023-2024 Huawei Device Co., Ltd.
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
#include <string>
#include <vector>
#include <algorithm>
#include "securec.h"

#include "mac.h"
#include "sym_key_generator.h"
#include "mac_openssl.h"
#include "mac_params.h"
#include "detailed_hmac_params.h"

#include "memory.h"

using namespace std;
using namespace testing::ext;

namespace {
class CryptoMacTest : public testing::TestWithParam<std::pair<std::string, uint32_t>> {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp();
    void TearDown();
};

constexpr uint32_t MAX_MAC_BLOB_LEN = 5000;
constexpr uint32_t INVALID_LEN = 0;
constexpr uint32_t SHA1_LEN = 20;
constexpr uint32_t SHA224_LEN = 28;
constexpr uint32_t SHA256_LEN = 32;
constexpr uint32_t SHA384_LEN = 48;
constexpr uint32_t SHA512_LEN = 64;
constexpr uint32_t MD5_LEN = 16;
constexpr uint32_t SM3_LEN = 32;

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

void CryptoMacTest::SetUpTestCase() {}
void CryptoMacTest::TearDownTestCase() {}

void CryptoMacTest::SetUp() // add init here, this will be called before test.
{
}

void CryptoMacTest::TearDown() // add destroy here, this will be called when test case done.
{
}

HWTEST_F(CryptoMacTest, CryptoFrameworkHmacCreateTest002, TestSize.Level0)
{
    HcfHmacParamsSpec params = {};
    params.base.algName = "HMAC";
    params.mdName = "SHA1";

    HcfResult ret = HcfMacCreate((HcfMacParamsSpec *)&params, nullptr);
    EXPECT_NE(ret, HCF_SUCCESS);
}

HWTEST_F(CryptoMacTest, CryptoFrameworkHmacAlgoSuppTest001, TestSize.Level0)
{
    // create a SHA obj
    HcfMac *macObj = nullptr;
    HcfHmacParamsSpec params = {};
    params.base.algName = "HMAC";
    params.mdName = "SHA1";

    HcfResult ret = HcfMacCreate((HcfMacParamsSpec *)&params, &macObj);
    ASSERT_EQ(ret, HCF_SUCCESS);
    EXPECT_NE(macObj, nullptr);
    HcfObjDestroy(macObj);
}

HWTEST_F(CryptoMacTest, CryptoFrameworkHmacAlgoSuppTest002, TestSize.Level0)
{
    // create a SHA obj
    HcfMac *macObj = nullptr;
    HcfHmacParamsSpec params = {};
    params.base.algName = "HMAC";
    params.mdName = "SHA3";

    HcfResult ret = HcfMacCreate((HcfMacParamsSpec *)&params, &macObj);
    EXPECT_NE(ret, HCF_SUCCESS);
    EXPECT_EQ(macObj, nullptr);
}

HWTEST_F(CryptoMacTest, CryptoFrameworkHmacAlgoSuppTest003, TestSize.Level0)
{
    // create a SHA obj
    HcfMac *macObj = nullptr;
    HcfResult ret = HcfMacCreate(nullptr, &macObj);
    EXPECT_EQ(ret, HCF_INVALID_PARAMS);
    EXPECT_EQ(macObj, nullptr);
}

HWTEST_F(CryptoMacTest, CryptoFrameworkHmacAlgoNameTest001, TestSize.Level0)
{
    // create a SHA obj
    HcfMac *macObj = nullptr;
    HcfHmacParamsSpec params = {};
    params.base.algName = "HMAC";
    params.mdName = "SHA1";

    HcfResult ret = HcfMacCreate((HcfMacParamsSpec *)&params, &macObj);
    ASSERT_EQ(ret, HCF_SUCCESS);
    EXPECT_NE(macObj, nullptr);
    // test api functions
    const char *algoName = macObj->getAlgoName(macObj);
    int32_t cmpRes = strcmp(algoName, params.base.algName);
    EXPECT_EQ(cmpRes, HCF_SUCCESS);
    HcfObjDestroy(macObj);
}

HWTEST_F(CryptoMacTest, CryptoFrameworkHmacInitTest001, TestSize.Level0)
{
    // create a SHA obj
    HcfMac *macObj = nullptr;
    HcfHmacParamsSpec params = {};
    params.base.algName = "HMAC";
    params.mdName = "SHA1";
    HcfResult ret = HcfMacCreate((HcfMacParamsSpec *)&params, &macObj);
    ASSERT_EQ(ret, HCF_SUCCESS);
    // set a nullptr key
    HcfSymKey *key = nullptr;
    // test api functions
    ret = macObj->init(macObj, key);
    EXPECT_NE(ret, HCF_SUCCESS);
    HcfObjDestroy(macObj);
}

HWTEST_F(CryptoMacTest, CryptoFrameworkHmacInitTest002, TestSize.Level0)
{
    // create a SHA obj
    HcfMac *macObj = nullptr;
    HcfHmacParamsSpec params = {};
    params.base.algName = "HMAC";
    params.mdName = "SHA1";
    HcfResult ret = HcfMacCreate((HcfMacParamsSpec *)&params, &macObj);
    ASSERT_EQ(ret, HCF_SUCCESS);
    // create a symKey generator
    HcfSymKeyGenerator *generator = nullptr;
    ret = HcfSymKeyGeneratorCreate("AES128", &generator);
    ASSERT_EQ(ret, HCF_SUCCESS);
    // get sym key from preset keyBlob
    uint8_t testKey[] = "abcdefghijklmnop";
    uint32_t testKeyLen = 16;
    HcfSymKey *key = nullptr;
    HcfBlob keyMaterialBlob = {.data = reinterpret_cast<uint8_t *>(testKey), .len = testKeyLen};
    generator->convertSymKey(generator, &keyMaterialBlob, &key);
    // test api functions
    ret = macObj->init(macObj, key);
    EXPECT_EQ(ret, HCF_SUCCESS);
    HcfObjDestroy(macObj);
    HcfObjDestroy(key);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoMacTest, CryptoFrameworkHmacUpdateTest001, TestSize.Level0)
{
    // create a SHA1 obj
    HcfMac *macObj = nullptr;
    HcfHmacParamsSpec params = {};
    params.base.algName = "HMAC";
    params.mdName = "SHA1";
    HcfResult ret = HcfMacCreate((HcfMacParamsSpec *)&params, &macObj);
    ASSERT_EQ(ret, HCF_SUCCESS);
    // set input and output buf
    uint8_t testData[] = "My test data";
    // define input and output data in blob form
    HcfBlob inBlob = {.data = reinterpret_cast<uint8_t *>(testData), .len = sizeof(testData)};
    // test api functions
    ret = macObj->update(macObj, &inBlob);
    EXPECT_NE(ret, HCF_SUCCESS);
    HcfObjDestroy(macObj);
}

HWTEST_F(CryptoMacTest, CryptoFrameworkHmacUpdateTest002, TestSize.Level0)
{
    // create a SHA1 obj
    HcfMac *macObj = nullptr;
    HcfHmacParamsSpec params = {};
    params.base.algName = "HMAC";
    params.mdName = "SHA1";
    HcfResult ret = HcfMacCreate((HcfMacParamsSpec *)&params, &macObj);
    ASSERT_EQ(ret, HCF_SUCCESS);
    // cteate key generator and set key text
    HcfSymKeyGenerator *generator = nullptr;
    ret = HcfSymKeyGeneratorCreate("AES128", &generator);
    ASSERT_EQ(ret, HCF_SUCCESS);
    // get sym key from preset keyBlob
    uint8_t testKey[] = "abcdefghijklmnop";
    uint32_t testKeyLen = 16;
    HcfSymKey *key = nullptr;
    HcfBlob keyMaterialBlob = {.data = reinterpret_cast<uint8_t *>(testKey), .len = testKeyLen};
    generator->convertSymKey(generator, &keyMaterialBlob, &key);
    // define input and output data in blob form
    HcfBlob *inBlob = nullptr;
    // test api functions
    ret = macObj->init(macObj, key);
    EXPECT_EQ(ret, HCF_SUCCESS);
    ret = macObj->update(macObj, inBlob);
    EXPECT_NE(ret, HCF_SUCCESS);
    HcfObjDestroy(macObj);
    HcfObjDestroy(key);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoMacTest, CryptoFrameworkHmacUpdateTest003, TestSize.Level0)
{
    // create a API obj with SHA1
    HcfMac *macObj = nullptr;
    HcfHmacParamsSpec params = {};
    params.base.algName = "HMAC";
    params.mdName = "SHA1";
    HcfResult ret = HcfMacCreate((HcfMacParamsSpec *)&params, &macObj);
    ASSERT_EQ(ret, HCF_SUCCESS);
    // cteate key generator and set key text
    HcfSymKeyGenerator *generator = nullptr;
    ret = HcfSymKeyGeneratorCreate("AES128", &generator);
    ASSERT_EQ(ret, HCF_SUCCESS);
    // get sym key from preset keyBlob
    uint8_t testKey[] = "abcdefghijklmnop";
    uint32_t testKeyLen = 16;
    HcfSymKey *key = nullptr;
    HcfBlob keyMaterialBlob = {.data = reinterpret_cast<uint8_t *>(testKey), .len = testKeyLen};
    generator->convertSymKey(generator, &keyMaterialBlob, &key);
    // set input and output buf
    uint8_t testData[] = "My test data";
    // define input and output data in blob form
    HcfBlob inBlob = {.data = reinterpret_cast<uint8_t *>(testData), .len = sizeof(testData)};
    // test api functions
    ret = macObj->init(macObj, key);
    EXPECT_EQ(ret, HCF_SUCCESS);
    ret = macObj->update(macObj, &inBlob);
    EXPECT_EQ(ret, HCF_SUCCESS);
    HcfObjDestroy(macObj);
    HcfObjDestroy(key);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoMacTest, CryptoFrameworkHmacDoFinalTest001, TestSize.Level0)
{
    // create a SHA1 obj
    HcfMac *macObj = nullptr;
    HcfHmacParamsSpec params = {};
    params.base.algName = "HMAC";
    params.mdName = "SHA1";
    HcfResult ret = HcfMacCreate((HcfMacParamsSpec *)&params, &macObj);
    ASSERT_EQ(ret, HCF_SUCCESS);
    // set input and output buf
    HcfBlob outBlob = { .data = nullptr, .len = 0 };
    // test api functions
    ret = macObj->doFinal(macObj, &outBlob);
    EXPECT_NE(ret, HCF_SUCCESS);
    // destroy the API obj and blob data
    HcfObjDestroy(macObj);
}

HWTEST_F(CryptoMacTest, CryptoFrameworkHmacDoFinalTest002, TestSize.Level0)
{
    // create a SHA1 obj
    HcfMac *macObj = nullptr;
    HcfHmacParamsSpec params = {};
    params.base.algName = "HMAC";
    params.mdName = "SHA1";
    HcfResult ret = HcfMacCreate((HcfMacParamsSpec *)&params, &macObj);
    ASSERT_EQ(ret, HCF_SUCCESS);
    // cteate key generator and set key text
    HcfSymKeyGenerator *generator = nullptr;
    ret = HcfSymKeyGeneratorCreate("AES128", &generator);
    ASSERT_EQ(ret, HCF_SUCCESS);
    // get sym key from preset keyBlob
    uint8_t testKey[] = "abcdefghijklmnop";
    uint32_t testKeyLen = 16;
    HcfSymKey *key = nullptr;
    HcfBlob keyMaterialBlob = {.data = reinterpret_cast<uint8_t *>(testKey), .len = testKeyLen};
    generator->convertSymKey(generator, &keyMaterialBlob, &key);
    // set input and output buf
    HcfBlob outBlob = { .data = nullptr, .len = 0 };
    // test api functions
    ret = macObj->init(macObj, key);
    EXPECT_EQ(ret, HCF_SUCCESS);
    ret = macObj->doFinal(macObj, &outBlob);
    EXPECT_EQ(ret, HCF_SUCCESS);
    // destroy the API obj and blob data
    HcfBlobDataClearAndFree(&outBlob);
    HcfObjDestroy(macObj);
    HcfObjDestroy(key);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoMacTest, CryptoFrameworkHmacDoFinalTest003, TestSize.Level0)
{
    // create a SHA1 obj
    HcfMac *macObj = nullptr;
    HcfHmacParamsSpec params = {};
    params.base.algName = "HMAC";
    params.mdName = "SHA1";
    HcfResult ret = HcfMacCreate((HcfMacParamsSpec *)&params, &macObj);
    ASSERT_EQ(ret, HCF_SUCCESS);
    // cteate key generator
    HcfSymKeyGenerator *generator = nullptr;
    ret = HcfSymKeyGeneratorCreate("AES128", &generator);
    ASSERT_EQ(ret, HCF_SUCCESS);
    // get sym key from preset keyBlob
    uint8_t testKey[] = "abcdefghijklmnop";
    uint32_t testKeyLen = 16;
    HcfSymKey *key = nullptr;
    HcfBlob keyMaterialBlob = {.data = reinterpret_cast<uint8_t *>(testKey), .len = testKeyLen};
    generator->convertSymKey(generator, &keyMaterialBlob, &key);
    // set input and output buf
    uint8_t testData[] = "My test data";
    // define input and output data in blob form
    HcfBlob inBlob = {.data = reinterpret_cast<uint8_t *>(testData), .len = sizeof(testData)};
    HcfBlob outBlob = { .data = nullptr, .len = 0 };
    // test api functions
    ret = macObj->init(macObj, key);
    EXPECT_EQ(ret, HCF_SUCCESS);
    ret = macObj->update(macObj, &inBlob);
    EXPECT_EQ(ret, HCF_SUCCESS);
    ret = macObj->doFinal(macObj, &outBlob);
    EXPECT_EQ(ret, HCF_SUCCESS);
    // destroy the API obj and blob data
    HcfBlobDataClearAndFree(&outBlob);
    HcfObjDestroy(macObj);
    HcfObjDestroy(key);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoMacTest, CryptoFrameworkHmacDoFinalTest004, TestSize.Level0)
{
    // create a SHA1 obj
    HcfMac *macObj = nullptr;
    HcfHmacParamsSpec params = {};
    params.base.algName = "HMAC";
    params.mdName = "SHA256";
    HcfResult ret = HcfMacCreate((HcfMacParamsSpec *)&params, &macObj);
    ASSERT_EQ(ret, HCF_SUCCESS);
    // cteate key generator
    HcfSymKeyGenerator *generator = nullptr;
    ret = HcfSymKeyGeneratorCreate("AES128", &generator);
    ASSERT_EQ(ret, HCF_SUCCESS);
    // get sym key from preset keyBlob
    uint8_t testKey[] = "abcdefghijklmnop";
    uint32_t testKeyLen = 16;
    HcfSymKey *key = nullptr;
    HcfBlob keyMaterialBlob = {.data = reinterpret_cast<uint8_t *>(testKey), .len = testKeyLen};
    generator->convertSymKey(generator, &keyMaterialBlob, &key);
    // define input and output data in blob form
    HcfBlob inBlob = {0};
    inBlob.data = reinterpret_cast<uint8_t *>(g_testBigData);
    inBlob.len = strnlen(g_testBigData, MAX_MAC_BLOB_LEN);
    HcfBlob outBlob = { .data = nullptr, .len = 0 };
    // test api functions
    ret = macObj->init(macObj, key);
    EXPECT_EQ(ret, HCF_SUCCESS);
    ret = macObj->update(macObj, &inBlob);
    EXPECT_EQ(ret, HCF_SUCCESS);
    ret = macObj->doFinal(macObj, &outBlob);
    EXPECT_EQ(ret, HCF_SUCCESS);
    // destroy the API obj and blob data
    HcfBlobDataClearAndFree(&outBlob);
    HcfObjDestroy(macObj);
    HcfObjDestroy(key);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoMacTest, CryptoFrameworkHmacLenTest001, TestSize.Level0)
{
    // create a SHA1 obj
    HcfMac *macObj = nullptr;
    HcfHmacParamsSpec params = {};
    params.base.algName = "HMAC";
    params.mdName = "SHA1";
    HcfResult ret = HcfMacCreate((HcfMacParamsSpec *)&params, &macObj);
    ASSERT_EQ(ret, HCF_SUCCESS);
    // test api functions
    uint32_t len = macObj->getMacLength(macObj);
    EXPECT_EQ(len, INVALID_LEN);
    HcfObjDestroy(macObj);
}

HWTEST_F(CryptoMacTest, CryptoFrameworkHmacLenTest002, TestSize.Level0)
{
    // create a SHA1 obj
    HcfMac *macObj = nullptr;
    HcfHmacParamsSpec params = {};
    params.base.algName = "HMAC";
    params.mdName = "SHA1";
    HcfResult ret = HcfMacCreate((HcfMacParamsSpec *)&params, &macObj);
    ASSERT_EQ(ret, HCF_SUCCESS);
    // cteate key generator
    HcfSymKeyGenerator *generator = nullptr;
    ret = HcfSymKeyGeneratorCreate("AES128", &generator);
    ASSERT_EQ(ret, HCF_SUCCESS);
    // get sym key from preset keyBlob
    uint8_t testKey[] = "abcdefghijklmnop";
    uint32_t testKeyLen = 16;
    HcfSymKey *key = nullptr;
    HcfBlob keyMaterialBlob = {.data = reinterpret_cast<uint8_t *>(testKey), .len = testKeyLen};
    generator->convertSymKey(generator, &keyMaterialBlob, &key);
    // test api functions
    ret = macObj->init(macObj, key);
    EXPECT_EQ(ret, HCF_SUCCESS);
    uint32_t len = macObj->getMacLength(macObj);
    EXPECT_EQ(len, SHA1_LEN);
    HcfObjDestroy(macObj);
    HcfObjDestroy(key);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoMacTest, CryptoFrameworkHmacAlgoTest001, TestSize.Level0)
{
    // create a SHA1 obj
    HcfMac *macObj = nullptr;
    HcfHmacParamsSpec params = {};
    params.base.algName = "HMAC";
    params.mdName = "SHA1";
    HcfResult ret = HcfMacCreate((HcfMacParamsSpec *)&params, &macObj);
    ASSERT_EQ(ret, HCF_SUCCESS);
    // create a symKey generator
    HcfSymKeyGenerator *generator = nullptr;
    ret = HcfSymKeyGeneratorCreate("AES128", &generator);
    ASSERT_EQ(ret, HCF_SUCCESS);
    // set key data and convert it to key obj
    uint8_t testKey[] = "abcdefghijklmnop";
    uint32_t testKeyLen = 16;
    HcfSymKey *key = nullptr;
    HcfBlob keyMaterialBlob = {.data = reinterpret_cast<uint8_t *>(testKey), .len = testKeyLen};
    generator->convertSymKey(generator, &keyMaterialBlob, &key);
    // set input and output blob
    uint8_t testData[] = "My test data";
    HcfBlob inBlob = {.data = reinterpret_cast<uint8_t *>(testData), .len = sizeof(testData)};
    HcfBlob outBlob = { .data = nullptr, .len = 0 };
    // test api funcitons
    ret = macObj->init(macObj, key);
    EXPECT_EQ(ret, HCF_SUCCESS);
    ret = macObj->update(macObj, &inBlob);
    EXPECT_EQ(ret, HCF_SUCCESS);
    ret = macObj->doFinal(macObj, &outBlob);
    EXPECT_EQ(ret, HCF_SUCCESS);
    uint32_t len = macObj->getMacLength(macObj);
    EXPECT_EQ(len, SHA1_LEN);
    // destroy the API obj and blob data
    HcfBlobDataClearAndFree(&outBlob);
    HcfObjDestroy(macObj);
    HcfObjDestroy(key);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoMacTest, CryptoFrameworkHmacAlgoTest002, TestSize.Level0)
{
    // create a SHA1 obj
    HcfMac *macObj = nullptr;
    HcfHmacParamsSpec params = {};
    params.base.algName = "HMAC";
    params.mdName = "SHA224";
    HcfResult ret = HcfMacCreate((HcfMacParamsSpec *)&params, &macObj);
    ASSERT_EQ(ret, HCF_SUCCESS);
    // create a symKey generator
    HcfSymKeyGenerator *generator = nullptr;
    ret = HcfSymKeyGeneratorCreate("AES128", &generator);
    ASSERT_EQ(ret, HCF_SUCCESS);
    // set key data and convert it to key obj
    uint8_t testKey[] = "abcdefghijklmnop";
    uint32_t testKeyLen = 16;
    HcfSymKey *key = nullptr;
    HcfBlob keyMaterialBlob = {.data = reinterpret_cast<uint8_t *>(testKey), .len = testKeyLen};
    generator->convertSymKey(generator, &keyMaterialBlob, &key);
    // set input and output blob
    uint8_t testData[] = "My test data";
    HcfBlob inBlob = {.data = reinterpret_cast<uint8_t *>(testData), .len = sizeof(testData)};
    HcfBlob outBlob = { .data = nullptr, .len = 0 };
    // test api funcitons
    ret = macObj->init(macObj, key);
    EXPECT_EQ(ret, HCF_SUCCESS);
    ret = macObj->update(macObj, &inBlob);
    EXPECT_EQ(ret, HCF_SUCCESS);
    ret = macObj->doFinal(macObj, &outBlob);
    EXPECT_EQ(ret, HCF_SUCCESS);
    uint32_t len = macObj->getMacLength(macObj);
    EXPECT_EQ(len, SHA224_LEN);
    // destroy the API obj and blob data
    HcfBlobDataClearAndFree(&outBlob);
    HcfObjDestroy(macObj);
    HcfObjDestroy(key);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoMacTest, CryptoFrameworkHmacAlgoTest003, TestSize.Level0)
{
    // create a SHA1 obj
    HcfMac *macObj = nullptr;
    HcfHmacParamsSpec params = {};
    params.base.algName = "HMAC";
    params.mdName = "SHA256";
    HcfResult ret = HcfMacCreate((HcfMacParamsSpec *)&params, &macObj);
    ASSERT_EQ(ret, HCF_SUCCESS);
    // create a symKey generator
    HcfSymKeyGenerator *generator = nullptr;
    ret = HcfSymKeyGeneratorCreate("AES128", &generator);
    ASSERT_EQ(ret, HCF_SUCCESS);
    // set key data and convert it to key obj
    uint8_t testKey[] = "abcdefghijklmnop";
    uint32_t testKeyLen = 16;
    HcfSymKey *key = nullptr;
    HcfBlob keyMaterialBlob = {.data = reinterpret_cast<uint8_t *>(testKey), .len = testKeyLen};
    generator->convertSymKey(generator, &keyMaterialBlob, &key);
    // set input and output blob
    uint8_t testData[] = "My test data";
    HcfBlob inBlob = {.data = reinterpret_cast<uint8_t *>(testData), .len = sizeof(testData)};
    HcfBlob outBlob = { .data = nullptr, .len = 0 };
    // test api funcitons
    ret = macObj->init(macObj, key);
    EXPECT_EQ(ret, HCF_SUCCESS);
    ret = macObj->update(macObj, &inBlob);
    EXPECT_EQ(ret, HCF_SUCCESS);
    ret = macObj->doFinal(macObj, &outBlob);
    EXPECT_EQ(ret, HCF_SUCCESS);
    uint32_t len = macObj->getMacLength(macObj);
    EXPECT_EQ(len, SHA256_LEN);
    // destroy the API obj and blob data
    HcfBlobDataClearAndFree(&outBlob);
    HcfObjDestroy(macObj);
    HcfObjDestroy(key);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoMacTest, CryptoFrameworkHmacAlgoTest004, TestSize.Level0)
{
    // create a SHA1 obj
    HcfMac *macObj = nullptr;
    HcfHmacParamsSpec params = {};
    params.base.algName = "HMAC";
    params.mdName = "SHA384";
    HcfResult ret = HcfMacCreate((HcfMacParamsSpec *)&params, &macObj);
    ASSERT_EQ(ret, HCF_SUCCESS);
    // create a symKey generator
    HcfSymKeyGenerator *generator = nullptr;
    ret = HcfSymKeyGeneratorCreate("AES128", &generator);
    ASSERT_EQ(ret, HCF_SUCCESS);
    // set key data and convert it to key obj
    uint8_t testKey[] = "abcdefghijklmnop";
    uint32_t testKeyLen = 16;
    HcfSymKey *key = nullptr;
    HcfBlob keyMaterialBlob = {.data = reinterpret_cast<uint8_t *>(testKey), .len = testKeyLen};
    generator->convertSymKey(generator, &keyMaterialBlob, &key);
    // set input and output blob
    uint8_t testData[] = "My test data";
    HcfBlob inBlob = {.data = reinterpret_cast<uint8_t *>(testData), .len = sizeof(testData)};
    HcfBlob outBlob = { .data = nullptr, .len = 0 };
    // test api funcitons
    ret = macObj->init(macObj, key);
    EXPECT_EQ(ret, HCF_SUCCESS);
    ret = macObj->update(macObj, &inBlob);
    EXPECT_EQ(ret, HCF_SUCCESS);
    ret = macObj->doFinal(macObj, &outBlob);
    EXPECT_EQ(ret, HCF_SUCCESS);
    uint32_t len = macObj->getMacLength(macObj);
    EXPECT_EQ(len, SHA384_LEN);
    // destroy the API obj and blob data
    HcfBlobDataClearAndFree(&outBlob);
    HcfObjDestroy(macObj);
    HcfObjDestroy(key);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoMacTest, CryptoFrameworkHmacAlgoTest005, TestSize.Level0)
{
    // create a SHA1 obj
    HcfMac *macObj = nullptr;
    HcfHmacParamsSpec params = {};
    params.base.algName = "HMAC";
    params.mdName = "SHA512";
    HcfResult ret = HcfMacCreate((HcfMacParamsSpec *)&params, &macObj);
    ASSERT_EQ(ret, HCF_SUCCESS);
    // create a symKey generator
    HcfSymKeyGenerator *generator = nullptr;
    ret = HcfSymKeyGeneratorCreate("AES128", &generator);
    ASSERT_EQ(ret, HCF_SUCCESS);
    // set key data and convert it to key obj
    uint8_t testKey[] = "abcdefghijklmnop";
    uint32_t testKeyLen = 16;
    HcfSymKey *key = nullptr;
    HcfBlob keyMaterialBlob = {.data = reinterpret_cast<uint8_t *>(testKey), .len = testKeyLen};
    generator->convertSymKey(generator, &keyMaterialBlob, &key);
    // set input and output blob
    uint8_t testData[] = "My test data";
    HcfBlob inBlob = {.data = reinterpret_cast<uint8_t *>(testData), .len = sizeof(testData)};
    HcfBlob outBlob = { .data = nullptr, .len = 0 };
    // test api funcitons
    ret = macObj->init(macObj, key);
    EXPECT_EQ(ret, HCF_SUCCESS);
    ret = macObj->update(macObj, &inBlob);
    EXPECT_EQ(ret, HCF_SUCCESS);
    ret = macObj->doFinal(macObj, &outBlob);
    EXPECT_EQ(ret, HCF_SUCCESS);
    uint32_t len = macObj->getMacLength(macObj);
    EXPECT_EQ(len, SHA512_LEN);
    // destroy the API obj and blob data
    HcfBlobDataClearAndFree(&outBlob);
    HcfObjDestroy(macObj);
    HcfObjDestroy(key);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoMacTest, CryptoFrameworkHmacAlgoTest006, TestSize.Level0)
{
    HcfMac *macObj = nullptr;
    HcfHmacParamsSpec params = {};
    params.base.algName = "HMAC";
    params.mdName = "SHA256";
    HcfResult ret = HcfMacCreate((HcfMacParamsSpec *)&params, &macObj);
    EXPECT_EQ(ret, HCF_SUCCESS);
    // create a symKey generator
    HcfSymKeyGenerator *generator = nullptr;
    ret = HcfSymKeyGeneratorCreate("HMAC", &generator);
    EXPECT_EQ(ret, HCF_SUCCESS);
    // set key data and convert it to key obj
    uint8_t testKey[] = "abcdefghijklmnopabcdefghijklmnop";
    uint32_t testKeyLen = 32;
    HcfSymKey *key = nullptr;
    HcfBlob keyMaterialBlob = {.data = reinterpret_cast<uint8_t *>(testKey), .len = testKeyLen};
    generator->convertSymKey(generator, &keyMaterialBlob, &key);
    // set input and output blob
    uint8_t testData[] = "My test data";
    HcfBlob inBlob = {.data = reinterpret_cast<uint8_t *>(testData), .len = sizeof(testData)};
    HcfBlob outBlob = { .data = nullptr, .len = 0 };
    // test api funcitons
    ret = macObj->init(macObj, key);
    EXPECT_EQ(ret, HCF_SUCCESS);
    ret = macObj->update(macObj, &inBlob);
    EXPECT_EQ(ret, HCF_SUCCESS);
    ret = macObj->doFinal(macObj, &outBlob);
    EXPECT_EQ(ret, HCF_SUCCESS);
    uint32_t len = macObj->getMacLength(macObj);
    EXPECT_EQ(len, SHA256_LEN);
    // destroy the API obj and blob data
    HcfBlobDataClearAndFree(&outBlob);
    HcfObjDestroy(macObj);
    HcfObjDestroy(key);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoMacTest, CryptoFrameworkHmacAlgoTest007, TestSize.Level0)
{
    HcfMac *macObj = nullptr;
    HcfHmacParamsSpec params = {};
    params.base.algName = "HMAC";
    params.mdName = "SHA1";
    HcfResult ret = HcfMacCreate((HcfMacParamsSpec *)&params, &macObj);
    EXPECT_EQ(ret, HCF_SUCCESS);
    // create a symKey generator
    HcfSymKeyGenerator *generator = nullptr;
    ret = HcfSymKeyGeneratorCreate("HMAC|SHA1", &generator);
    EXPECT_EQ(ret, HCF_SUCCESS);
    HcfSymKey *key = nullptr;
    generator->generateSymKey(generator, &key);
    // set input and output blob
    uint8_t testData[] = "My test data";
    HcfBlob inBlob = {.data = reinterpret_cast<uint8_t *>(testData), .len = sizeof(testData)};
    HcfBlob outBlob = { .data = nullptr, .len = 0 };
    // test api funcitons
    ret = macObj->init(macObj, key);
    EXPECT_EQ(ret, HCF_SUCCESS);
    ret = macObj->update(macObj, &inBlob);
    EXPECT_EQ(ret, HCF_SUCCESS);
    ret = macObj->doFinal(macObj, &outBlob);
    EXPECT_EQ(ret, HCF_SUCCESS);
    uint32_t len = macObj->getMacLength(macObj);
    EXPECT_EQ(len, SHA1_LEN);
    // destroy the API obj and blob data
    HcfBlobDataClearAndFree(&outBlob);
    HcfObjDestroy(macObj);
    HcfObjDestroy(key);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoMacTest, CryptoFrameworkHmacAlgoTest008, TestSize.Level0)
{
    HcfMac *macObj = nullptr;
    HcfHmacParamsSpec params = {};
    params.base.algName = "HMAC";
    params.mdName = "SHA224";
    HcfResult ret = HcfMacCreate((HcfMacParamsSpec *)&params, &macObj);
    EXPECT_EQ(ret, HCF_SUCCESS);
    // create a symKey generator
    HcfSymKeyGenerator *generator = nullptr;
    ret = HcfSymKeyGeneratorCreate("HMAC|SHA224", &generator);
    EXPECT_EQ(ret, HCF_SUCCESS);
    HcfSymKey *key = nullptr;
    generator->generateSymKey(generator, &key);
    // set input and output blob
    uint8_t testData[] = "My test data";
    HcfBlob inBlob = {.data = reinterpret_cast<uint8_t *>(testData), .len = sizeof(testData)};
    HcfBlob outBlob = { .data = nullptr, .len = 0 };
    // test api funcitons
    ret = macObj->init(macObj, key);
    EXPECT_EQ(ret, HCF_SUCCESS);
    ret = macObj->update(macObj, &inBlob);
    EXPECT_EQ(ret, HCF_SUCCESS);
    ret = macObj->doFinal(macObj, &outBlob);
    EXPECT_EQ(ret, HCF_SUCCESS);
    uint32_t len = macObj->getMacLength(macObj);
    EXPECT_EQ(len, SHA224_LEN);
    // destroy the API obj and blob data
    HcfBlobDataClearAndFree(&outBlob);
    HcfObjDestroy(macObj);
    HcfObjDestroy(key);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoMacTest, CryptoFrameworkHmacAlgoTest009, TestSize.Level0)
{
    HcfMac *macObj = nullptr;
    HcfHmacParamsSpec params = {};
    params.base.algName = "HMAC";
    params.mdName = "SHA256";
    HcfResult ret = HcfMacCreate((HcfMacParamsSpec *)&params, &macObj);
    EXPECT_EQ(ret, HCF_SUCCESS);
    // create a symKey generator
    HcfSymKeyGenerator *generator = nullptr;
    ret = HcfSymKeyGeneratorCreate("HMAC|SHA256", &generator);
    EXPECT_EQ(ret, HCF_SUCCESS);
    HcfSymKey *key = nullptr;
    generator->generateSymKey(generator, &key);
    // set input and output blob
    uint8_t testData[] = "My test data";
    HcfBlob inBlob = {.data = reinterpret_cast<uint8_t *>(testData), .len = sizeof(testData)};
    HcfBlob outBlob = { .data = nullptr, .len = 0 };
    // test api funcitons
    ret = macObj->init(macObj, key);
    EXPECT_EQ(ret, HCF_SUCCESS);
    ret = macObj->update(macObj, &inBlob);
    EXPECT_EQ(ret, HCF_SUCCESS);
    ret = macObj->doFinal(macObj, &outBlob);
    EXPECT_EQ(ret, HCF_SUCCESS);
    uint32_t len = macObj->getMacLength(macObj);
    EXPECT_EQ(len, SHA256_LEN);
    // destroy the API obj and blob data
    HcfBlobDataClearAndFree(&outBlob);
    HcfObjDestroy(macObj);
    HcfObjDestroy(key);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoMacTest, CryptoFrameworkHmacAlgoTest010, TestSize.Level0)
{
    HcfMac *macObj = nullptr;
    HcfHmacParamsSpec params = {};
    params.base.algName = "HMAC";
    params.mdName = "SHA384";
    HcfResult ret = HcfMacCreate((HcfMacParamsSpec *)&params, &macObj);
    EXPECT_EQ(ret, HCF_SUCCESS);
    // create a symKey generator
    HcfSymKeyGenerator *generator = nullptr;
    ret = HcfSymKeyGeneratorCreate("HMAC|SHA384", &generator);
    EXPECT_EQ(ret, HCF_SUCCESS);
    HcfSymKey *key = nullptr;
    generator->generateSymKey(generator, &key);
    // set input and output blob
    uint8_t testData[] = "My test data";
    HcfBlob inBlob = {.data = reinterpret_cast<uint8_t *>(testData), .len = sizeof(testData)};
    HcfBlob outBlob = { .data = nullptr, .len = 0 };
    // test api funcitons
    ret = macObj->init(macObj, key);
    EXPECT_EQ(ret, HCF_SUCCESS);
    ret = macObj->update(macObj, &inBlob);
    EXPECT_EQ(ret, HCF_SUCCESS);
    ret = macObj->doFinal(macObj, &outBlob);
    EXPECT_EQ(ret, HCF_SUCCESS);
    uint32_t len = macObj->getMacLength(macObj);
    EXPECT_EQ(len, SHA384_LEN);
    // destroy the API obj and blob data
    HcfBlobDataClearAndFree(&outBlob);
    HcfObjDestroy(macObj);
    HcfObjDestroy(key);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoMacTest, CryptoFrameworkHmacAlgoTest011, TestSize.Level0)
{
    HcfMac *macObj = nullptr;
    HcfHmacParamsSpec params = {};
    params.base.algName = "HMAC";
    params.mdName = "SHA512";
    HcfResult ret = HcfMacCreate((HcfMacParamsSpec *)&params, &macObj);
    EXPECT_EQ(ret, HCF_SUCCESS);
    // create a symKey generator
    HcfSymKeyGenerator *generator = nullptr;
    ret = HcfSymKeyGeneratorCreate("HMAC|SHA512", &generator);
    EXPECT_EQ(ret, HCF_SUCCESS);
    HcfSymKey *key = nullptr;
    generator->generateSymKey(generator, &key);
    // set input and output blob
    uint8_t testData[] = "My test data";
    HcfBlob inBlob = {.data = reinterpret_cast<uint8_t *>(testData), .len = sizeof(testData)};
    HcfBlob outBlob = { .data = nullptr, .len = 0 };
    // test api funcitons
    ret = macObj->init(macObj, key);
    EXPECT_EQ(ret, HCF_SUCCESS);
    ret = macObj->update(macObj, &inBlob);
    EXPECT_EQ(ret, HCF_SUCCESS);
    ret = macObj->doFinal(macObj, &outBlob);
    EXPECT_EQ(ret, HCF_SUCCESS);
    uint32_t len = macObj->getMacLength(macObj);
    EXPECT_EQ(len, SHA512_LEN);
    // destroy the API obj and blob data
    HcfBlobDataClearAndFree(&outBlob);
    HcfObjDestroy(macObj);
    HcfObjDestroy(key);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoMacTest, InvalidHmacTest001, TestSize.Level0)
{
    HcfSymKeyGenerator *generator = nullptr;
    HcfResult ret = HcfSymKeyGeneratorCreate(nullptr, &generator);
    EXPECT_NE(ret, HCF_SUCCESS);

    generator = nullptr;
    ret = HcfSymKeyGeneratorCreate("HMACC|SHA256", &generator);
    EXPECT_NE(ret, HCF_SUCCESS);

    generator = nullptr;
    ret = HcfSymKeyGeneratorCreate("HMAC|SHA123", &generator);
    EXPECT_NE(ret, HCF_SUCCESS);

    generator = nullptr;
    ret = HcfSymKeyGeneratorCreate("HMAC|MD5", &generator);
    EXPECT_EQ(ret, HCF_SUCCESS);

    HcfObjDestroy(generator);
}

HWTEST_F(CryptoMacTest, InvalidHmacTest002, TestSize.Level0)
{
    HcfSymKeyGenerator *generator = nullptr;
    HcfResult ret = HcfSymKeyGeneratorCreate("HMAC|SHA256", &generator);
    EXPECT_EQ(ret, HCF_SUCCESS);
    // set key data and convert it to key obj
    uint8_t testKey[] = "abcdefghijklmnop";
    uint32_t testKeyLen = 16;
    HcfSymKey *key = nullptr;
    HcfBlob keyMaterialBlob = {.data = reinterpret_cast<uint8_t *>(testKey), .len = testKeyLen};
    ret = generator->convertSymKey(generator, &keyMaterialBlob, &key);
    EXPECT_NE(ret, HCF_SUCCESS);
    // destroy the API obj and blob data
    HcfObjDestroy(generator);
}

static const char *GetInvalidMacClass(void)
{
    return "INVALID_MAC_CLASS";
}

HWTEST_F(CryptoMacTest, InvalidInputMacTest001, TestSize.Level0)
{
    HcfHmacParamsSpec params = {};
    params.base.algName = "HMAC";
    params.mdName = "SHA256";
    HcfResult ret = OpensslHmacSpiCreate((HcfMacParamsSpec *)&params, nullptr);
    EXPECT_NE(ret, HCF_SUCCESS);
    HcfMacSpi *spiObj = nullptr;
    ret = OpensslHmacSpiCreate(nullptr, &spiObj);
    EXPECT_EQ(ret, HCF_INVALID_PARAMS);
}

HWTEST_F(CryptoMacTest, NullParamMacTest001, TestSize.Level0)
{
    HcfMac *macObj = nullptr;
    HcfHmacParamsSpec params = {};
    params.base.algName = "HMAC";
    params.mdName = "SHA256";
    HcfResult ret = HcfMacCreate((HcfMacParamsSpec *)&params, &macObj);
    ASSERT_EQ(ret, HCF_SUCCESS);
    ret = macObj->init(nullptr, nullptr);
    EXPECT_NE(ret, HCF_SUCCESS);
    ret = macObj->update(nullptr, nullptr);
    EXPECT_NE(ret, HCF_SUCCESS);
    ret = macObj->doFinal(nullptr, nullptr);
    EXPECT_NE(ret, HCF_SUCCESS);
    uint32_t len = macObj->getMacLength(nullptr);
    EXPECT_EQ(len, HCF_OPENSSL_INVALID_MAC_LEN);
    const char *algoName = macObj->getAlgoName(nullptr);
    EXPECT_EQ(algoName, nullptr);
    macObj->base.destroy(nullptr);
    HcfObjDestroy(macObj);
}

HWTEST_F(CryptoMacTest, InvalidFrameworkClassMacTest001, TestSize.Level0)
{
    HcfMac *macObj = nullptr;
    HcfHmacParamsSpec params = {};
    params.base.algName = "HMAC";
    params.mdName = "SHA256";
    HcfResult ret = HcfMacCreate((HcfMacParamsSpec *)&params, &macObj);
    ASSERT_EQ(ret, HCF_SUCCESS);
    HcfMac invalidMacObj = {{0}};
    invalidMacObj.base.getClass = GetInvalidMacClass;
    HcfSymKeyGenerator *generator = nullptr;
    ret = HcfSymKeyGeneratorCreate("AES128", &generator);
    ASSERT_EQ(ret, HCF_SUCCESS);
    uint8_t testKey[] = "abcdefghijklmnop";
    uint32_t testKeyLen = sizeof(testKey) / sizeof(testKey[0]);
    HcfSymKey *key = nullptr;
    HcfBlob keyMaterialBlob = {.data = reinterpret_cast<uint8_t *>(testKey), .len = testKeyLen};
    generator->convertSymKey(generator, &keyMaterialBlob, &key);
    uint8_t testData[] = "My test data";
    HcfBlob inBlob = {.data = reinterpret_cast<uint8_t *>(testData), .len = sizeof(testData)};
    HcfBlob outBlob = { .data = nullptr, .len = 0 };
    ret = macObj->init(&invalidMacObj, key);
    EXPECT_NE(ret, HCF_SUCCESS);
    ret = macObj->update(&invalidMacObj, &inBlob);
    EXPECT_NE(ret, HCF_SUCCESS);
    ret = macObj->doFinal(&invalidMacObj, &outBlob);
    EXPECT_NE(ret, HCF_SUCCESS);
    uint32_t len = macObj->getMacLength(&invalidMacObj);
    EXPECT_EQ(len, HCF_OPENSSL_INVALID_MAC_LEN);
    const char *algoName = macObj->getAlgoName(&invalidMacObj);
    EXPECT_EQ(algoName, nullptr);
    HcfBlobDataClearAndFree(&outBlob);
    macObj->base.destroy(&(invalidMacObj.base));
    HcfObjDestroy(macObj);
    HcfObjDestroy(key);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoMacTest, InvalidSpiClassMacTest001, TestSize.Level0)
{
    HcfMacSpi *spiObj = nullptr;
    HcfMacSpi invalidSpi = {{0}};
    invalidSpi.base.getClass = GetInvalidMacClass;
    // create a symKey generator
    HcfSymKeyGenerator *generator = nullptr;
    HcfResult ret = HcfSymKeyGeneratorCreate("AES128", &generator);
    ASSERT_EQ(ret, HCF_SUCCESS);
    // set key data and convert it to key obj
    uint8_t testKey[] = "abcdefghijklmnop";
    uint32_t testKeyLen = 16;
    HcfSymKey *key = nullptr;
    HcfBlob keyMaterialBlob = {.data = reinterpret_cast<uint8_t *>(testKey), .len = testKeyLen};
    generator->convertSymKey(generator, &keyMaterialBlob, &key);
    // set input and output blob
    uint8_t testData[] = "My test data";
    HcfBlob inBlob = {.data = reinterpret_cast<uint8_t *>(testData), .len = sizeof(testData)};
    HcfBlob outBlob = { .data = nullptr, .len = 0 };

    HcfHmacParamsSpec params = {};
    params.base.algName = "HMAC";
    params.mdName = "SHA256";
    ret = OpensslHmacSpiCreate((HcfMacParamsSpec *)&params, &spiObj);
    EXPECT_EQ(ret, HCF_SUCCESS);
    ASSERT_NE(spiObj, nullptr);
    (void)spiObj->base.destroy(nullptr);
    (void)spiObj->base.destroy(&(invalidSpi.base));
    ret = spiObj->engineInitMac(&invalidSpi, key);
    EXPECT_NE(ret, HCF_SUCCESS);
    ret = spiObj->engineUpdateMac(&invalidSpi, &inBlob);
    EXPECT_NE(ret, HCF_SUCCESS);
    ret = spiObj->engineDoFinalMac(&invalidSpi, &outBlob);
    EXPECT_NE(ret, HCF_SUCCESS);
    uint32_t len = spiObj->engineGetMacLength(&invalidSpi);
    EXPECT_EQ(len, INVALID_LEN);
    HcfObjDestroy(spiObj);
    HcfObjDestroy(key);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoMacTest, CryptoFrameworkHmacAlgoTest012, TestSize.Level0)
{
    HcfMac *macObj = nullptr;
    HcfHmacParamsSpec params = {};
    params.base.algName = "HMAC";
    params.mdName = "MD5";
    HcfResult ret = HcfMacCreate((HcfMacParamsSpec *)&params, &macObj);
    EXPECT_EQ(ret, HCF_SUCCESS);
    // create a symKey generator
    HcfSymKeyGenerator *generator = nullptr;
    ret = HcfSymKeyGeneratorCreate("HMAC|MD5", &generator);
    EXPECT_EQ(ret, HCF_SUCCESS);
    HcfSymKey *key = nullptr;
    generator->generateSymKey(generator, &key);
    // set input and output blob
    uint8_t testData[] = "My test data";
    HcfBlob inBlob = {.data = reinterpret_cast<uint8_t *>(testData), .len = sizeof(testData)};
    HcfBlob outBlob = { .data = nullptr, .len = 0 };
    // test api funcitons
    ret = macObj->init(macObj, key);
    EXPECT_EQ(ret, HCF_SUCCESS);
    ret = macObj->update(macObj, &inBlob);
    EXPECT_EQ(ret, HCF_SUCCESS);
    ret = macObj->doFinal(macObj, &outBlob);
    EXPECT_EQ(ret, HCF_SUCCESS);
    uint32_t len = macObj->getMacLength(macObj);
    EXPECT_EQ(len, MD5_LEN);
    // destroy the API obj and blob data
    HcfBlobDataClearAndFree(&outBlob);
    HcfObjDestroy(macObj);
    HcfObjDestroy(key);
    HcfObjDestroy(generator);
}

static void TestCreateHmacKey(HcfSymKeyGenerator *generator, const char *hmacAlgName, int keyLen,
    const char *expectKeyAlgName)
{
    HcfResult ret;
    HcfSymKey *key = nullptr;
    HcfBlob keyMaterialBlob = {0};

    if (strlen(hmacAlgName) != strlen("HMAC")) {
        ret = generator->generateSymKey(generator, &key);
        ASSERT_EQ(ret, HCF_SUCCESS);
        EXPECT_STREQ(key->key.getAlgorithm(reinterpret_cast<HcfKey *>(key)), expectKeyAlgName);
        HcfObjDestroy(key);
        key = nullptr;
    }

    keyMaterialBlob.len = keyLen;
    keyMaterialBlob.data = reinterpret_cast<uint8_t *>(HcfMalloc(4096, 0)); // max keyLen is 4096
    ASSERT_NE(keyMaterialBlob.data, nullptr);

    ret = generator->convertSymKey(generator, &keyMaterialBlob, &key);
    HcfFree(keyMaterialBlob.data);
    ASSERT_EQ(ret, HCF_SUCCESS);
    EXPECT_STREQ(key->key.getAlgorithm(reinterpret_cast<HcfKey *>(key)), expectKeyAlgName);
    HcfObjDestroy(key);
}

static void TestHmacKeyAlgoName(const char *hmacAlgName, int keyLen, const char *expectKeyAlgName)
{
    HcfResult ret;
    HcfSymKeyGenerator *generator = nullptr;

    ret = HcfSymKeyGeneratorCreate(hmacAlgName, &generator);
    ASSERT_EQ(ret, HCF_SUCCESS);

    TestCreateHmacKey(generator, hmacAlgName, keyLen, expectKeyAlgName);

    HcfObjDestroy(generator);
}

HWTEST_F(CryptoMacTest, CryptoFrameworkHmacKeyAlgoNameTest001, TestSize.Level0)
{
    TestHmacKeyAlgoName("HMAC|SHA1", 20, "HMAC160");
    TestHmacKeyAlgoName("HMAC|SHA224", 28, "HMAC224");
    TestHmacKeyAlgoName("HMAC|SHA256", 32, "HMAC256");
    TestHmacKeyAlgoName("HMAC|SHA384", 48, "HMAC384");
    TestHmacKeyAlgoName("HMAC|SHA512", 64, "HMAC512");
    TestHmacKeyAlgoName("HMAC|SM3", 32, "HMAC256");
    TestHmacKeyAlgoName("HMAC|MD5", 16, "HMAC128");

    TestHmacKeyAlgoName("HMAC", 1, "HMAC8");
    TestHmacKeyAlgoName("HMAC", 2, "HMAC16");
    TestHmacKeyAlgoName("HMAC", 128, "HMAC1024");
    TestHmacKeyAlgoName("HMAC", 4096, "HMAC32768");

    TestHmacKeyAlgoName("HMAC|SHA3-256", 32, "HMAC256");
    TestHmacKeyAlgoName("HMAC|SHA3-384", 48, "HMAC384");
    TestHmacKeyAlgoName("HMAC|SHA3-512", 64, "HMAC512");
}

std::vector<std::pair<std::string, uint32_t>> macMdAlgoParams = {
    { "SHA1", SHA1_LEN },
    { "SHA224", SHA224_LEN },
    { "SHA256", SHA256_LEN },
    { "SHA384", SHA384_LEN },
    { "SHA512", SHA512_LEN },
    { "SHA3-256", SHA256_LEN },
    { "SHA3-384", SHA384_LEN },
    { "SHA3-512", SHA512_LEN },
    { "MD5", MD5_LEN },
    { "SM3", SM3_LEN },
};

INSTANTIATE_TEST_SUITE_P(CryptoMacTestParam, CryptoMacTest,
    ::testing::ValuesIn(macMdAlgoParams),
    [](const ::testing::TestParamInfo<std::pair<std::string, uint32_t>> &info) {
        std::string name = info.param.first;
        std::replace(name.begin(), name.end(), '-', '_'); // name not support '-'
        return name;
    }
);

HWTEST_P(CryptoMacTest, CryptoHmacAlgoTest, TestSize.Level0)
{
    HcfSymKeyGenerator *generator = nullptr;
    HcfSymKey *key = nullptr;
    HcfResult ret = HcfSymKeyGeneratorCreate("HMAC|SHA256", &generator);
    EXPECT_EQ(ret, HCF_SUCCESS);
    ret = generator->generateSymKey(generator, &key);
    EXPECT_EQ(ret, HCF_SUCCESS);

    std::string algoName = "HMAC";
    std::pair<std::string, uint32_t> param = GetParam();
    HcfMac *macObj = nullptr;
    HcfHmacParamsSpec spec = {};
    spec.base.algName = algoName.c_str();
    spec.mdName = param.first.c_str();
    ret = HcfMacCreate(&(spec.base), &macObj);
    EXPECT_EQ(ret, HCF_SUCCESS);

    uint8_t testData[] = "My test data";
    HcfBlob inBlob = { .data = testData, .len = sizeof(testData) };
    HcfBlob outBlob = {};

    ret = macObj->init(macObj, key);
    EXPECT_EQ(ret, HCF_SUCCESS);
    ret = macObj->update(macObj, &inBlob);
    EXPECT_EQ(ret, HCF_SUCCESS);
    ret = macObj->doFinal(macObj, &outBlob);
    EXPECT_EQ(ret, HCF_SUCCESS);

    uint32_t len = macObj->getMacLength(macObj);
    EXPECT_EQ(len, param.second);
    const char *name = macObj->getAlgoName(macObj);
    EXPECT_STREQ(name, algoName.c_str());

    HcfBlobDataClearAndFree(&outBlob);
    HcfObjDestroy(macObj);
    HcfObjDestroy(key);
    HcfObjDestroy(generator);
}
}