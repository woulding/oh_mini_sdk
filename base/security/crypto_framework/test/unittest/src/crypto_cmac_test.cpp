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
#include <string>
#include "securec.h"

#include "mac.h"
#include "sym_key_generator.h"
#include "mac_openssl.h"
#include "mac_params.h"
#include "detailed_cmac_params.h"

#include "memory.h"

using namespace std;
using namespace testing::ext;

namespace {
class CryptoCmacTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp();
    void TearDown();
};

constexpr uint32_t MAX_MAC_BLOB_LEN = 5000;
constexpr uint32_t INVALID_LEN = 0;
constexpr uint32_t AES128_LEN = 16;

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

void CryptoCmacTest::SetUpTestCase() {}
void CryptoCmacTest::TearDownTestCase() {}

void CryptoCmacTest::SetUp() // add init here, this will be called before test.
{
}

void CryptoCmacTest::TearDown() // add destroy here, this will be called when test case done.
{
}

HWTEST_F(CryptoCmacTest, CryptoCmacTest001, TestSize.Level0)
{
    HcfCmacParamsSpec params = {};
    params.base.algName = "CMAC";
    params.cipherName = "AES128";

    HcfResult ret = HcfMacCreate((HcfMacParamsSpec *)&params, nullptr);
    EXPECT_NE(ret, HCF_SUCCESS);
}

HWTEST_F(CryptoCmacTest, CryptoCmacTest002, TestSize.Level0)
{
    HcfMac *macObj = nullptr;
    HcfCmacParamsSpec params = {};
    params.base.algName = "CMAC";
    params.cipherName = "AES128";

    HcfResult ret = HcfMacCreate((HcfMacParamsSpec *)&params, &macObj);
    ASSERT_EQ(ret, HCF_SUCCESS);
    EXPECT_NE(macObj, nullptr);
    HcfObjDestroy(macObj);
}

HWTEST_F(CryptoCmacTest, CryptoCmacTest003, TestSize.Level0)
{
    HcfMac *macObj = nullptr;
    HcfCmacParamsSpec params = {};
    params.base.algName = "CMAC";
    params.cipherName = "AES256";

    HcfResult ret = HcfMacCreate((HcfMacParamsSpec *)&params, &macObj);
    EXPECT_EQ(ret, HCF_SUCCESS);
    EXPECT_NE(macObj, nullptr);
    HcfObjDestroy(macObj);
}

HWTEST_F(CryptoCmacTest, CryptoCmacTest004, TestSize.Level0)
{
    HcfMac *macObj = nullptr;
    HcfResult ret = HcfMacCreate(nullptr, &macObj);
    EXPECT_EQ(ret, HCF_INVALID_PARAMS);
    EXPECT_EQ(macObj, nullptr);
}

HWTEST_F(CryptoCmacTest, CryptoCmacTest005, TestSize.Level0)
{
    HcfMac *macObj = nullptr;
    HcfCmacParamsSpec params = {};
    params.base.algName = "CMAC";
    params.cipherName = "AES128";

    HcfResult ret = HcfMacCreate((HcfMacParamsSpec *)&params, &macObj);
    ASSERT_EQ(ret, HCF_SUCCESS);
    EXPECT_NE(macObj, nullptr);
    // test api functions
    const char *algoName = macObj->getAlgoName(macObj);
    int32_t cmpRes = strcmp(algoName, params.base.algName);
    EXPECT_EQ(cmpRes, HCF_SUCCESS);
    HcfObjDestroy(macObj);
}

HWTEST_F(CryptoCmacTest, CryptoCmacTest006, TestSize.Level0)
{
    HcfMac *macObj = nullptr;
    HcfCmacParamsSpec params = {};
    params.base.algName = "CMAC";
    params.cipherName = "AES128";
    HcfResult ret = HcfMacCreate((HcfMacParamsSpec *)&params, &macObj);
    ASSERT_EQ(ret, HCF_SUCCESS);
    // set a nullptr key
    HcfSymKey *key = nullptr;
    // test api functions
    ret = macObj->init(macObj, key);
    EXPECT_NE(ret, HCF_SUCCESS);
    HcfObjDestroy(macObj);
}

HWTEST_F(CryptoCmacTest, CryptoCmacTest007, TestSize.Level0)
{
    HcfMac *macObj = nullptr;
    HcfCmacParamsSpec params = {};
    params.base.algName = "CMAC";
    params.cipherName = "AES128";
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

HWTEST_F(CryptoCmacTest, CryptoCmacTest008, TestSize.Level0)
{
    HcfMac *macObj = nullptr;
    HcfCmacParamsSpec params = {};
    params.base.algName = "CMAC";
    params.cipherName = "AES128";
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

HWTEST_F(CryptoCmacTest, CryptoCmacTest009, TestSize.Level0)
{
    HcfMac *macObj = nullptr;
    HcfCmacParamsSpec params = {};
    params.base.algName = "CMAC";
    params.cipherName = "AES128";
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

HWTEST_F(CryptoCmacTest, CryptoCmacTest010, TestSize.Level0)
{
    HcfMac *macObj = nullptr;
    HcfCmacParamsSpec params = {};
    params.base.algName = "CMAC";
    params.cipherName = "AES128";
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

HWTEST_F(CryptoCmacTest, CryptoCmacTest012, TestSize.Level0)
{
    HcfMac *macObj = nullptr;
    HcfCmacParamsSpec params = {};
    params.base.algName = "CMAC";
    params.cipherName = "AES128";
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

HWTEST_F(CryptoCmacTest, CryptoCmacTest013, TestSize.Level0)
{
    HcfMac *macObj = nullptr;
    HcfCmacParamsSpec params = {};
    params.base.algName = "CMAC";
    params.cipherName = "AES128";
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

HWTEST_F(CryptoCmacTest, CryptoCmacTest014, TestSize.Level0)
{
    HcfMac *macObj = nullptr;
    HcfCmacParamsSpec params = {};
    params.base.algName = "CMAC";
    params.cipherName = "AES128";
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

HWTEST_F(CryptoCmacTest, CryptoCmacTest016, TestSize.Level0)
{
    HcfMac *macObj = nullptr;
    HcfCmacParamsSpec params = {};
    params.base.algName = "CMAC";
    params.cipherName = "AES128";
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
    EXPECT_EQ(len, AES128_LEN);
    HcfObjDestroy(macObj);
    HcfObjDestroy(key);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoCmacTest, CryptoCmacTest017, TestSize.Level0)
{
    HcfMac *macObj = nullptr;
    HcfCmacParamsSpec params = {};
    params.base.algName = "CMAC";
    params.cipherName = "AES128";
    HcfResult ret = HcfMacCreate((HcfMacParamsSpec *)&params, &macObj);
    EXPECT_EQ(ret, HCF_SUCCESS);
    // create a symKey generator
    HcfSymKeyGenerator *generator = nullptr;
    ret = HcfSymKeyGeneratorCreate("AES128", &generator);
    EXPECT_EQ(ret, HCF_SUCCESS);
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
    EXPECT_EQ(len, AES128_LEN);
    // destroy the API obj and blob data
    HcfBlobDataClearAndFree(&outBlob);
    HcfObjDestroy(macObj);
    HcfObjDestroy(key);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoCmacTest, CryptoCmacTest018, TestSize.Level0)
{
    HcfMac *macObj = nullptr;
    HcfCmacParamsSpec params = {};
    params.base.algName = "CMAC";
    params.cipherName = "AES128";
    HcfResult ret = HcfMacCreate((HcfMacParamsSpec *)&params, &macObj);
    EXPECT_EQ(ret, HCF_SUCCESS);
    // create a symKey generator
    HcfSymKeyGenerator *generator = nullptr;
    ret = HcfSymKeyGeneratorCreate("AES128", &generator);
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
    EXPECT_EQ(len, AES128_LEN);
    // destroy the API obj and blob data
    HcfBlobDataClearAndFree(&outBlob);
    HcfObjDestroy(macObj);
    HcfObjDestroy(key);
    HcfObjDestroy(generator);
}

static const char *GetInvalidMacClass(void)
{
    return "INVALID_MAC_CLASS";
}

HWTEST_F(CryptoCmacTest, CryptoCmacTest019, TestSize.Level0)
{
    HcfCmacParamsSpec params = {};
    params.base.algName = "CMAC";
    params.cipherName = "SHA256";
    HcfResult ret = OpensslHmacSpiCreate((HcfMacParamsSpec *)&params, nullptr);
    EXPECT_NE(ret, HCF_SUCCESS);
    HcfMacSpi *spiObj = nullptr;
    ret = OpensslHmacSpiCreate(nullptr, &spiObj);
    EXPECT_EQ(ret, HCF_INVALID_PARAMS);
}

HWTEST_F(CryptoCmacTest, CryptoCmacTest021, TestSize.Level0)
{
    HcfMac *macObj = nullptr;
    HcfCmacParamsSpec params = {};
    params.base.algName = "CMAC";
    params.cipherName = "AES128";
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

HWTEST_F(CryptoCmacTest, CryptoCmacTest022, TestSize.Level0)
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

    HcfCmacParamsSpec params = {};
    params.base.algName = "CMAC";
    params.cipherName = "AES128";
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

}