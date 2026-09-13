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

#include "scrypt_openssl.h"

#include <gtest/gtest.h>
#include "securec.h"

#include "detailed_scrypt_params.h"
#include "kdf.h"
#include "memory.h"

using namespace std;
using namespace testing::ext;

namespace {
class CryptoScryptTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp();
    void TearDown();
};

void CryptoScryptTest::SetUpTestCase() {}
void CryptoScryptTest::TearDownTestCase() {}

void CryptoScryptTest::SetUp() // add init here, this will be called before test.
{
}

void CryptoScryptTest::TearDown() // add destroy here, this will be called when test case done.
{
}

constexpr uint32_t OUT_PUT_MAX_LENGTH = 128;
constexpr uint32_t OUT_PUT_NORMAL_LENGTH = 32;
constexpr uint32_t SALT_NORMAL_LENGTH = 16;

HWTEST_F(CryptoScryptTest, CryptoScryptTest1, TestSize.Level0)
{
    HcfKdf *generator = nullptr;
    HcfResult ret = HcfKdfCreate("SCRYPT", &generator);
    EXPECT_EQ(ret, HCF_SUCCESS);
    uint8_t out[OUT_PUT_MAX_LENGTH] = {0};
    uint8_t saltData[SALT_NORMAL_LENGTH] = {0};
    HcfBlob output = {.data = out, .len = OUT_PUT_NORMAL_LENGTH};
    HcfBlob salt = {.data = saltData, .len = SALT_NORMAL_LENGTH};
    HcfBlob password = {.data = reinterpret_cast<uint8_t *>(const_cast<char *>("123456")),
        .len = strlen("123456")};
    HcfScryptParamsSpec params = {
        .base = { .algName = "SCRYPT", },
        .passPhrase = password,
        .salt = salt,
        .n = 1024,
        .r = 8,
        .p = 16,
        .maxMem = 1067008,
        .output = output,
    };
    ret = generator->generateSecret(generator, &(params.base));
    EXPECT_EQ(ret, HCF_SUCCESS);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoScryptTest, CryptoScryptErrTest1, TestSize.Level0)
{
    HcfKdf *generator = nullptr;
    HcfResult ret = HcfKdfCreate("SCRYPT", &generator);
    EXPECT_EQ(ret, HCF_SUCCESS);
    uint8_t out[OUT_PUT_MAX_LENGTH] = {0};
    uint8_t saltData[SALT_NORMAL_LENGTH] = {0};
    HcfBlob output = {.data = out, .len = OUT_PUT_NORMAL_LENGTH};
    HcfBlob salt = {.data = saltData, .len = SALT_NORMAL_LENGTH};
    HcfBlob password = {.data = reinterpret_cast<uint8_t *>(const_cast<char *>("123456")),
        .len = strlen("123456")};
    HcfScryptParamsSpec params = {
        .base = { .algName = "SCRYPT", },
        .passPhrase = password,
        .salt = salt,
        .n = 1024,
        .r = 8,
        .p = 16,
        .maxMem = 1067007,
        .output = output,
    };
    ret = generator->generateSecret(generator, &(params.base));
    EXPECT_NE(ret, HCF_SUCCESS);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoScryptTest, CryptoScryptErrTest2, TestSize.Level0)
{
    HcfKdf *generator = nullptr;
    HcfResult ret = HcfKdfCreate("SCRYPT", &generator);
    EXPECT_EQ(ret, HCF_SUCCESS);
    uint8_t out[OUT_PUT_MAX_LENGTH] = {0};
    uint8_t saltData[SALT_NORMAL_LENGTH] = {0};
    HcfBlob output = {.data = out, .len = OUT_PUT_NORMAL_LENGTH};
    HcfBlob salt = {.data = saltData, .len = SALT_NORMAL_LENGTH};
    HcfBlob password = {.data = reinterpret_cast<uint8_t *>(const_cast<char *>("123456")),
        .len = strlen("123456")};
    HcfScryptParamsSpec params = {
        .base = { .algName = "SCRYPT", },
        .passPhrase = password,
        .salt = salt,
        .n = 1024,
        .r = 8,
        .p = 16,
        .maxMem = 1067008,
        .output = output,
    };
    generator->base.destroy(nullptr);
    ret = generator->generateSecret(nullptr, &(params.base));
    EXPECT_EQ(ret, HCF_INVALID_PARAMS);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoScryptTest, CryptoScryptTest2, TestSize.Level0)
{
    HcfKdf *generator = nullptr;
    HcfResult ret = HcfKdfCreate("SCRYPT", &generator);
    EXPECT_EQ(ret, HCF_SUCCESS);
    uint8_t out[OUT_PUT_MAX_LENGTH] = {0};
    HcfBlob output = {.data = out, .len = OUT_PUT_NORMAL_LENGTH};
    HcfBlob salt = {.data = nullptr, .len = 0};
    HcfBlob password = {.data = nullptr, .len = 0};
    HcfScryptParamsSpec params = {
        .base = { .algName = "SCRYPT", },
        .passPhrase = password,
        .salt = salt,
        .n = 1024,
        .r = 8,
        .p = 16,
        .maxMem = 768,
        .output = output,
    };
    ret = generator->generateSecret(generator, &(params.base));
    EXPECT_NE(ret, HCF_SUCCESS);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoScryptTest, CryptoScryptTest3, TestSize.Level0)
{
    HcfKdf *generator = nullptr;
    HcfResult ret = HcfKdfCreate("SCRYPT", &generator);
    EXPECT_EQ(ret, HCF_SUCCESS);
    uint8_t out[OUT_PUT_MAX_LENGTH] = {0};
    HcfBlob output = {.data = out, .len = OUT_PUT_NORMAL_LENGTH};
    HcfBlob salt = {.data = nullptr, .len = 0};
    HcfBlob password = {.data = reinterpret_cast<uint8_t *>(const_cast<char *>("")),
    .len = strlen("")};
    HcfScryptParamsSpec params = {
        .base = { .algName = "SCRYPT", },
        .passPhrase = password,
        .salt = salt,
        .n = 1024,
        .r = 8,
        .p = 16,
        .maxMem = 1067008,
        .output = output,
    };
    ret = generator->generateSecret(generator, &(params.base));
    EXPECT_EQ(ret, HCF_SUCCESS);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoScryptTest, CryptoScryptTest4, TestSize.Level0)
{
    // long password (long than md length)
    HcfKdf *generator = nullptr;
    HcfResult ret = HcfKdfCreate("SCRYPT", &generator);
    EXPECT_EQ(ret, HCF_SUCCESS);
    uint8_t out[OUT_PUT_MAX_LENGTH] = {0};
    HcfBlob output = {.data = out, .len = OUT_PUT_NORMAL_LENGTH};
    uint8_t saltData[SALT_NORMAL_LENGTH] = {0};
    HcfBlob salt = {.data = saltData, .len = SALT_NORMAL_LENGTH};
    char longPass[] = "12345678123456781234567812345678123456781234567812345678123456781234567812345678";
    HcfBlob password = {.data = reinterpret_cast<uint8_t *>(const_cast<char *>(longPass)),
        .len = strlen(longPass)};
    HcfScryptParamsSpec params = {
        .base = { .algName = "SCRYPT", },
        .passPhrase = password,
        .salt = salt,
        .n = 1024,
        .r = 8,
        .p = 16,
        .maxMem = 1067008,
        .output = output,
    };
    ret = generator->generateSecret(generator, &(params.base));
    EXPECT_EQ(ret, HCF_SUCCESS);
    HcfObjDestroy(generator);
}


HWTEST_F(CryptoScryptTest, CryptoScryptTest6, TestSize.Level0)
{
    HcfKdf *generator = nullptr;
    HcfResult ret = HcfKdfCreate("SCRYPT", &generator);
    EXPECT_EQ(ret, HCF_SUCCESS);
    uint8_t out[OUT_PUT_MAX_LENGTH] = {0};
    uint8_t saltData[SALT_NORMAL_LENGTH] = {0};
    HcfBlob output = {.data = out, .len = OUT_PUT_NORMAL_LENGTH};
    HcfBlob salt = {.data = saltData, .len = SALT_NORMAL_LENGTH};
    HcfBlob password = {.data = reinterpret_cast<uint8_t *>(const_cast<char *>("123456")),
        .len = strlen("123456")};
    HcfScryptParamsSpec params = {
        .base = { .algName = "SCRYPT", },
        .passPhrase = password,
        .salt = salt,
        .n = 1024,
        .r = 8,
        .p = 16,
        .maxMem = 1067008,
        .output = output,
    };
    ret = generator->generateSecret(generator, &(params.base));
    EXPECT_EQ(ret, HCF_SUCCESS);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoScryptTest, CryptoScryptTestError8, TestSize.Level1)
{
    // use nullptr params
    HcfKdf *generator = nullptr;
    HcfResult ret = HcfKdfCreate("SCRYPT", &generator);
    EXPECT_EQ(ret, HCF_SUCCESS);
    ret = generator->generateSecret(generator, nullptr);
    EXPECT_NE(ret, HCF_SUCCESS);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoScryptTest, CryptoScryptTestError9, TestSize.Level1)
{
    HcfKdf *generator = nullptr;
    HcfResult ret = HcfKdfCreate("SCRYPT|abcd", &generator);
    EXPECT_NE(ret, HCF_SUCCESS);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoScryptTest, CryptoScryptTestError10, TestSize.Level1)
{
    HcfKdf *generator = nullptr;
    HcfResult ret = HcfKdfCreate("ABCD|SM3", &generator);
    EXPECT_NE(ret, HCF_SUCCESS);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoScryptTest, CryptoScryptTestError11, TestSize.Level1)
{
    HcfKdf *generator = nullptr;
    HcfResult ret = HcfKdfCreate(nullptr, &generator);
    EXPECT_NE(ret, HCF_SUCCESS);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoScryptTest, CryptoScryptTestError12, TestSize.Level1)
{
    HcfResult ret = HcfKdfCreate(nullptr, nullptr);
    EXPECT_NE(ret, HCF_SUCCESS);
}
}
