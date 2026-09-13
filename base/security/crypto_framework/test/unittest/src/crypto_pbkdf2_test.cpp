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

#include "pbkdf2_openssl.h"

#include <gtest/gtest.h>
#include <string>
#include <algorithm>
#include "securec.h"

#include "detailed_pbkdf2_params.h"
#include "kdf.h"
#include "memory.h"

using namespace std;
using namespace testing::ext;

namespace {
class CryptoPbkdf2Test : public testing::TestWithParam<std::string> {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp();
    void TearDown();
};

void CryptoPbkdf2Test::SetUpTestCase() {}
void CryptoPbkdf2Test::TearDownTestCase() {}

void CryptoPbkdf2Test::SetUp() // add init here, this will be called before test.
{
}

void CryptoPbkdf2Test::TearDown() // add destroy here, this will be called when test case done.
{
}

static const char *g_pbkdf2Name = "PBKDF2";
static const char *g_errorName = "abcd";
static const char *g_password = "123456";
static const char *g_passwordEmpty = "";
static const char *g_passwordLong = "12345678123456781234567812345678123456781234567812345678123456781234567812345678";

constexpr uint32_t OUT_PUT_MAX_LENGTH = 128;
constexpr uint32_t OUT_PUT_NORMAL_LENGTH = 32;
constexpr uint32_t SALT_NORMAL_LENGTH = 16;

HWTEST_F(CryptoPbkdf2Test, CryptoPbkdf2Test1, TestSize.Level0)
{
    HcfKdf *generator = nullptr;
    HcfResult ret = HcfKdfCreate("PBKDF2|SHA256", &generator);
    EXPECT_EQ(ret, HCF_SUCCESS);
    uint8_t out[OUT_PUT_MAX_LENGTH] = {0};
    uint8_t saltData[SALT_NORMAL_LENGTH] = {0};
    HcfBlob output = {.data = out, .len = OUT_PUT_NORMAL_LENGTH};
    HcfBlob salt = {.data = saltData, .len = SALT_NORMAL_LENGTH};
    HcfBlob password = {.data = reinterpret_cast<uint8_t *>(const_cast<char *>(g_password)),
        .len = strlen(g_password)};
    HcfPBKDF2ParamsSpec params = {
        .base = { .algName = g_pbkdf2Name },
        .password = password,
        .salt = salt,
        .iterations = 10000,
        .output = output,
    };
    ret = generator->generateSecret(generator, &(params.base));
    EXPECT_EQ(ret, HCF_SUCCESS);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoPbkdf2Test, CryptoPbkdf2ErrTest1, TestSize.Level0)
{
    HcfKdf *generator = nullptr;
    HcfResult ret = HcfKdfCreate("PBKDF2|SHA256", &generator);
    EXPECT_EQ(ret, HCF_SUCCESS);
    uint8_t out[OUT_PUT_MAX_LENGTH] = {0};
    uint8_t saltData[SALT_NORMAL_LENGTH] = {0};
    HcfBlob output = {.data = out, .len = OUT_PUT_NORMAL_LENGTH};
    HcfBlob salt = {.data = saltData, .len = SALT_NORMAL_LENGTH};
    HcfBlob password = {.data = reinterpret_cast<uint8_t *>(const_cast<char *>(g_password)),
        .len = strlen(g_password)};
    HcfPBKDF2ParamsSpec params = {
        .base = { .algName = g_pbkdf2Name },
        .password = password,
        .salt = salt,
        .iterations = 10000,
        .output = output,
    };
    generator->base.destroy(nullptr);
    ret = generator->generateSecret(nullptr, &(params.base));
    EXPECT_EQ(ret, HCF_INVALID_PARAMS);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoPbkdf2Test, CryptoPbkdf2Test2, TestSize.Level0)
{
    HcfKdf *generator = nullptr;
    HcfResult ret = HcfKdfCreate("PBKDF2|SHA256", &generator);
    EXPECT_EQ(ret, HCF_SUCCESS);
    uint8_t out[OUT_PUT_MAX_LENGTH] = {0};
    HcfBlob output = {.data = out, .len = OUT_PUT_NORMAL_LENGTH};
    HcfBlob salt = {.data = nullptr, .len = 0};
    HcfBlob password = {.data = nullptr, .len = 0};
    HcfPBKDF2ParamsSpec params = {
        .base = { .algName = g_pbkdf2Name },
        .password = password,
        .salt = salt,
        .iterations = 10000,
        .output = output,
    };
    ret = generator->generateSecret(generator, &(params.base));
    EXPECT_EQ(ret, HCF_SUCCESS);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoPbkdf2Test, CryptoPbkdf2Test3, TestSize.Level0)
{
    HcfKdf *generator = nullptr;
    HcfResult ret = HcfKdfCreate("PBKDF2|SHA256", &generator);
    EXPECT_EQ(ret, HCF_SUCCESS);
    uint8_t out[OUT_PUT_MAX_LENGTH] = {0};
    HcfBlob output = {.data = out, .len = OUT_PUT_NORMAL_LENGTH};
    HcfBlob salt = {.data = nullptr, .len = 0};
    HcfBlob password = {.data = reinterpret_cast<uint8_t *>(const_cast<char *>(g_passwordEmpty)),
    .len = strlen(g_passwordEmpty)};
    HcfPBKDF2ParamsSpec params = {
        .base = { .algName = g_pbkdf2Name },
        .password = password,
        .salt = salt,
        .iterations = 10000,
        .output = output,
    };
    ret = generator->generateSecret(generator, &(params.base));
    EXPECT_EQ(ret, HCF_SUCCESS);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoPbkdf2Test, CryptoPbkdf2Test4, TestSize.Level0)
{
    // long password (long than md length)
    HcfKdf *generator = nullptr;
    HcfResult ret = HcfKdfCreate("PBKDF2|SHA256", &generator);
    EXPECT_EQ(ret, HCF_SUCCESS);
    uint8_t out[OUT_PUT_MAX_LENGTH] = {0};
    HcfBlob output = {.data = out, .len = OUT_PUT_NORMAL_LENGTH};
    uint8_t saltData[SALT_NORMAL_LENGTH] = {0};
    HcfBlob salt = {.data = saltData, .len = SALT_NORMAL_LENGTH};
    HcfBlob password = {.data = reinterpret_cast<uint8_t *>(const_cast<char *>(g_passwordLong)),
    .len = strlen(g_passwordLong)};
    HcfPBKDF2ParamsSpec params = {
        .base = { .algName = g_pbkdf2Name },
        .password = password,
        .salt = salt,
        .iterations = 10000,
        .output = output,
    };
    ret = generator->generateSecret(generator, &(params.base));
    EXPECT_EQ(ret, HCF_SUCCESS);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoPbkdf2Test, CryptoPbkdf2Test5, TestSize.Level0)
{
    // password not empty but zero length
    HcfKdf *generator = nullptr;
    HcfResult ret = HcfKdfCreate("PBKDF2|SHA256", &generator);
    EXPECT_EQ(ret, HCF_SUCCESS);
    uint8_t out[OUT_PUT_MAX_LENGTH] = {0};
    uint8_t saltData[SALT_NORMAL_LENGTH] = {0};
    HcfBlob output = {.data = out, .len = OUT_PUT_NORMAL_LENGTH};
    HcfBlob salt = {.data = saltData, .len = SALT_NORMAL_LENGTH};
    HcfBlob password = {.data = reinterpret_cast<uint8_t *>(const_cast<char *>(g_passwordLong)),
    .len = 0};
    HcfPBKDF2ParamsSpec params = {
        .base = { .algName = g_pbkdf2Name },
        .password = password,
        .salt = salt,
        .iterations = 10000,
        .output = output,
    };
    ret = generator->generateSecret(generator, &(params.base));
    EXPECT_EQ(ret, HCF_SUCCESS);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoPbkdf2Test, CryptoPbkdf2Test6, TestSize.Level0)
{
    HcfKdf *generator = nullptr;
    HcfResult ret = HcfKdfCreate("PBKDF2|SHA1", &generator);
    EXPECT_EQ(ret, HCF_SUCCESS);
    uint8_t out[OUT_PUT_MAX_LENGTH] = {0};
    uint8_t saltData[SALT_NORMAL_LENGTH] = {0};
    HcfBlob output = {.data = out, .len = OUT_PUT_NORMAL_LENGTH};
    HcfBlob salt = {.data = saltData, .len = SALT_NORMAL_LENGTH};
    HcfBlob password = {.data = reinterpret_cast<uint8_t *>(const_cast<char *>(g_password)),
        .len = strlen(g_password)};
    HcfPBKDF2ParamsSpec params = {
        .base = { .algName = g_pbkdf2Name },
        .password = password,
        .salt = salt,
        .iterations = 10000,
        .output = output,
    };
    ret = generator->generateSecret(generator, &(params.base));
    EXPECT_EQ(ret, HCF_SUCCESS);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoPbkdf2Test, CryptoPbkdf2Test7, TestSize.Level0)
{
    HcfKdf *generator = nullptr;
    HcfResult ret = HcfKdfCreate("PBKDF2|SHA384", &generator);
    EXPECT_EQ(ret, HCF_SUCCESS);
    uint8_t out[OUT_PUT_MAX_LENGTH] = {0};
    uint8_t saltData[SALT_NORMAL_LENGTH] = {0};
    HcfBlob output = {.data = out, .len = OUT_PUT_NORMAL_LENGTH};
    HcfBlob salt = {.data = saltData, .len = SALT_NORMAL_LENGTH};
    HcfBlob password = {.data = reinterpret_cast<uint8_t *>(const_cast<char *>(g_password)),
        .len = strlen(g_password)};
    HcfPBKDF2ParamsSpec params = {
        .base = { .algName = g_pbkdf2Name },
        .password = password,
        .salt = salt,
        .iterations = 10000,
        .output = output,
    };
    ret = generator->generateSecret(generator, &(params.base));
    EXPECT_EQ(ret, HCF_SUCCESS);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoPbkdf2Test, CryptoPbkdf2Test8, TestSize.Level0)
{
    HcfKdf *generator = nullptr;
    HcfResult ret = HcfKdfCreate("PBKDF2|SHA512", &generator);
    EXPECT_EQ(ret, HCF_SUCCESS);
    uint8_t out[OUT_PUT_MAX_LENGTH] = {0};
    uint8_t saltData[SALT_NORMAL_LENGTH] = {0};
    HcfBlob output = {.data = out, .len = OUT_PUT_NORMAL_LENGTH};
    HcfBlob salt = {.data = saltData, .len = SALT_NORMAL_LENGTH};
    HcfBlob password = {.data = reinterpret_cast<uint8_t *>(const_cast<char *>(g_password)),
        .len = strlen(g_password)};
    HcfPBKDF2ParamsSpec params = {
        .base = { .algName = g_pbkdf2Name },
        .password = password,
        .salt = salt,
        .iterations = 10000,
        .output = output,
    };
    ret = generator->generateSecret(generator, &(params.base));
    EXPECT_EQ(ret, HCF_SUCCESS);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoPbkdf2Test, CryptoPbkdf2Test9, TestSize.Level0)
{
    HcfKdf *generator = nullptr;
    HcfResult ret = HcfKdfCreate("PBKDF2|SM3", &generator);
    EXPECT_EQ(ret, HCF_SUCCESS);
    uint8_t out[OUT_PUT_MAX_LENGTH] = {0};
    uint8_t saltData[SALT_NORMAL_LENGTH] = {0};
    HcfBlob output = {.data = out, .len = OUT_PUT_NORMAL_LENGTH};
    HcfBlob salt = {.data = saltData, .len = SALT_NORMAL_LENGTH};
    HcfBlob password = {.data = reinterpret_cast<uint8_t *>(const_cast<char *>(g_password)),
        .len = strlen(g_password)};
    HcfPBKDF2ParamsSpec params = {
        .base = { .algName = g_pbkdf2Name },
        .password = password,
        .salt = salt,
        .iterations = 10000,
        .output = output,
    };
    ret = generator->generateSecret(generator, &(params.base));
    EXPECT_EQ(ret, HCF_SUCCESS);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoPbkdf2Test, CryptoPbkdf2Test10, TestSize.Level0)
{
    HcfKdf *generator = nullptr;
    HcfResult ret = HcfKdfCreate("PBKDF2|SHA224", &generator);
    EXPECT_EQ(ret, HCF_SUCCESS);
    uint8_t out[OUT_PUT_MAX_LENGTH] = {0};
    uint8_t saltData[SALT_NORMAL_LENGTH] = {0};
    HcfBlob output = {.data = out, .len = OUT_PUT_NORMAL_LENGTH};
    HcfBlob salt = {.data = saltData, .len = SALT_NORMAL_LENGTH};
    HcfBlob password = {.data = reinterpret_cast<uint8_t *>(const_cast<char *>(g_password)),
        .len = strlen(g_password)};
    HcfPBKDF2ParamsSpec params = {
        .base = { .algName = g_pbkdf2Name },
        .password = password,
        .salt = salt,
        .iterations = 10000,
        .output = output,
    };
    ret = generator->generateSecret(generator, &(params.base));
    EXPECT_EQ(ret, HCF_SUCCESS);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoPbkdf2Test, CryptoPbkdf2TestError1, TestSize.Level1)
{
    // params iter = 0
    HcfKdf *generator = nullptr;
    HcfResult ret = HcfKdfCreate("PBKDF2|SHA256", &generator);
    EXPECT_EQ(ret, HCF_SUCCESS);
    uint8_t out[OUT_PUT_MAX_LENGTH] = {0};
    HcfBlob output = {.data = out, .len = OUT_PUT_NORMAL_LENGTH};
    HcfBlob salt = {.data = nullptr, .len = 0};
    HcfPBKDF2ParamsSpec params = {
        .base = { .algName = g_pbkdf2Name },
        .password = {.data = nullptr, .len = 0},
        .salt = salt,
        .iterations = 0,
        .output = output,
    };
    ret = generator->generateSecret(generator, &(params.base));
    EXPECT_NE(ret, HCF_SUCCESS);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoPbkdf2Test, CryptoPbkdf2TestError2, TestSize.Level1)
{
    // params algName is error
    HcfKdf *generator = nullptr;
    HcfResult ret = HcfKdfCreate("PBKDF2|SHA256", &generator);
    EXPECT_EQ(ret, HCF_SUCCESS);
    uint8_t out[OUT_PUT_MAX_LENGTH] = {0};
    HcfBlob output = {.data = out, .len = OUT_PUT_NORMAL_LENGTH};
    HcfBlob salt = {.data = nullptr, .len = 0};
    HcfBlob password = {.data = nullptr, .len = 0};
    HcfPBKDF2ParamsSpec params = {
        .base = { .algName = g_errorName },
        .password = password,
        .salt = salt,
        .iterations = 10000,
        .output = output,
    };
    ret = generator->generateSecret(generator, &(params.base));
    EXPECT_NE(ret, HCF_SUCCESS);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoPbkdf2Test, CryptoPbkdf2TestError3, TestSize.Level1)
{
    // params algName is nullptr
    HcfKdf *generator = nullptr;
    HcfResult ret = HcfKdfCreate("PBKDF2|SHA256", &generator);
    EXPECT_EQ(ret, HCF_SUCCESS);
    uint8_t out[OUT_PUT_MAX_LENGTH] = {0};
    HcfBlob output = {.data = out, .len = OUT_PUT_NORMAL_LENGTH};
    HcfBlob salt = {.data = nullptr, .len = 0};
    HcfPBKDF2ParamsSpec params = {
        .base = { .algName = nullptr },
        .password = {.data = nullptr, .len = 0},
        .salt = salt,
        .iterations = 10000,
        .output = output,
    };
    ret = generator->generateSecret(generator, &(params.base));
    EXPECT_NE(ret, HCF_SUCCESS);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoPbkdf2Test, CryptoPbkdf2TestError4, TestSize.Level1)
{
    // output len is 0 and data is nullptr
    HcfKdf *generator = nullptr;
    HcfResult ret = HcfKdfCreate("PBKDF2|SHA256", &generator);
    EXPECT_EQ(ret, HCF_SUCCESS);
    uint8_t saltData[SALT_NORMAL_LENGTH] = {0};
    HcfBlob output = {.data = nullptr, .len = 0};
    HcfBlob salt = {.data = saltData, .len = SALT_NORMAL_LENGTH};
    HcfPBKDF2ParamsSpec params = {
        .base = { .algName = g_pbkdf2Name },
        .password = {.data = nullptr, .len = 0},
        .salt = salt,
        .iterations = 10000,
        .output = output,
    };
    ret = generator->generateSecret(generator, &(params.base));
    EXPECT_NE(ret, HCF_SUCCESS);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoPbkdf2Test, CryptoPbkdf2TestError5, TestSize.Level1)
{
    // output data is nullptr
    HcfKdf *generator = nullptr;
    HcfResult ret = HcfKdfCreate("PBKDF2|SHA256", &generator);
    EXPECT_EQ(ret, HCF_SUCCESS);
    uint8_t saltData[SALT_NORMAL_LENGTH] = {0};
    HcfBlob output = {.data = nullptr, .len = OUT_PUT_NORMAL_LENGTH};
    HcfBlob salt = {.data = saltData, .len = SALT_NORMAL_LENGTH};
    HcfPBKDF2ParamsSpec params = {
        .base = { .algName = g_pbkdf2Name },
        .password = {.data = nullptr, .len = 0},
        .salt = salt,
        .iterations = 10000,
        .output = output,
    };
    ret = generator->generateSecret(generator, &(params.base));
    EXPECT_NE(ret, HCF_SUCCESS);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoPbkdf2Test, CryptoPbkdf2TestError6, TestSize.Level1)
{
    // output len is 0
    HcfKdf *generator = nullptr;
    HcfResult ret = HcfKdfCreate("PBKDF2|SHA256", &generator);
    EXPECT_EQ(ret, HCF_SUCCESS);
    uint8_t saltData[SALT_NORMAL_LENGTH] = {0};
    uint8_t out[OUT_PUT_MAX_LENGTH] = {1, 1};
    HcfBlob output = {.data = out, .len = 0};
    HcfBlob salt = {.data = saltData, .len = SALT_NORMAL_LENGTH};
    HcfPBKDF2ParamsSpec params = {
        .base = { .algName = g_pbkdf2Name },
        .password = {.data = nullptr, .len = 0},
        .salt = salt,
        .iterations = 10000,
        .output = output,
    };
    ret = generator->generateSecret(generator, &(params.base));
    EXPECT_NE(ret, HCF_SUCCESS);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoPbkdf2Test, CryptoPbkdf2TestError7, TestSize.Level1)
{
    // use basic params
    HcfKdf *generator = nullptr;
    HcfResult ret = HcfKdfCreate("PBKDF2|SHA256", &generator);
    EXPECT_EQ(ret, HCF_SUCCESS);
    HcfPBKDF2ParamsSpec params = {
        .base = { .algName = g_pbkdf2Name },
        .password = {.data = nullptr, .len = 0},
        .salt = {.data = nullptr, .len = 0},
        .iterations = 0,
        .output = {.data = nullptr, .len = 0},
    };
    ret = generator->generateSecret(generator, (HcfKdfParamsSpec *)&params);
    EXPECT_NE(ret, HCF_SUCCESS);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoPbkdf2Test, CryptoPbkdf2TestError8, TestSize.Level1)
{
    // use nullptr params
    HcfKdf *generator = nullptr;
    HcfResult ret = HcfKdfCreate("PBKDF2|SHA256", &generator);
    EXPECT_EQ(ret, HCF_SUCCESS);
    ret = generator->generateSecret(generator, nullptr);
    EXPECT_NE(ret, HCF_SUCCESS);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoPbkdf2Test, CryptoPbkdf2TestError9, TestSize.Level1)
{
    HcfKdf *generator = nullptr;
    HcfResult ret = HcfKdfCreate("PBKDF2|abcd", &generator);
    EXPECT_NE(ret, HCF_SUCCESS);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoPbkdf2Test, CryptoPbkdf2TestError10, TestSize.Level1)
{
    HcfKdf *generator = nullptr;
    HcfResult ret = HcfKdfCreate("ABCD|SM3", &generator);
    EXPECT_NE(ret, HCF_SUCCESS);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoPbkdf2Test, CryptoPbkdf2TestError11, TestSize.Level1)
{
    HcfKdf *generator = nullptr;
    HcfResult ret = HcfKdfCreate(nullptr, &generator);
    EXPECT_NE(ret, HCF_SUCCESS);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoPbkdf2Test, CryptoPbkdf2TestError12, TestSize.Level1)
{
    HcfResult ret = HcfKdfCreate(nullptr, nullptr);
    EXPECT_NE(ret, HCF_SUCCESS);
}

HWTEST_F(CryptoPbkdf2Test, CryptoPbkdf2TestError13, TestSize.Level0)
{
    HcfResult ret = HcfKdfPBKDF2SpiCreate(nullptr, nullptr);
    EXPECT_EQ(ret, HCF_INVALID_PARAMS);

    HcfKdfDeriveParams params = {};
    params.algo = HCF_ALG_PKBDF2;
    params.md = HCF_OPENSSL_DIGEST_SHA256;

    HcfKdfSpi *spiObj = nullptr;
    ret = HcfKdfPBKDF2SpiCreate(&params, &spiObj);
    EXPECT_EQ(ret, HCF_SUCCESS);

    (void)spiObj->base.destroy(nullptr);
    ret = spiObj->generateSecret(nullptr, nullptr);
    EXPECT_EQ(ret, HCF_INVALID_PARAMS);

    HcfObjDestroy(spiObj);
}

std::vector<std::string> pbkdf2MdAlgoParams = {
    "SHA1",
    "SHA224",
    "SHA256",
    "SHA384",
    "SHA512",
    "SHA3-256",
    "SHA3-384",
    "SHA3-512",
    "MD5",
    "SM3",
};

INSTANTIATE_TEST_SUITE_P(CryptoPbkdf2TestParam, CryptoPbkdf2Test,
    ::testing::ValuesIn(pbkdf2MdAlgoParams),
    [](const ::testing::TestParamInfo<std::string> &info) {
        std::string name = info.param;
        std::replace(name.begin(), name.end(), '-', '_'); // name not support '-'
        return name;
    }
);

HWTEST_P(CryptoPbkdf2Test, CryptoPbkdf2AlgoTest, TestSize.Level0)
{
    std::string kdfName = "PBKDF2";
    std::string mdName = GetParam();
    std::string algoName = kdfName + "|" + mdName;

    HcfKdf *generator = nullptr;
    HcfResult ret = HcfKdfCreate(algoName.c_str(), &generator);
    EXPECT_EQ(ret, HCF_SUCCESS);

    uint8_t buf[] = { 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F };
    HcfBlob blob = { .data = buf, .len = sizeof(buf) };
    uint8_t out[OUT_PUT_NORMAL_LENGTH] = {};
    HcfBlob output = { .data = out, .len = sizeof(out) };
    HcfPBKDF2ParamsSpec spec = {
        .base = { .algName = kdfName.c_str() },
        .password = blob,
        .salt = blob,
        .iterations = 10000,
        .output = output,
    };
    ret = generator->generateSecret(generator, &(spec.base));
    EXPECT_EQ(ret, HCF_SUCCESS);
    const char *name = generator->getAlgorithm(generator);
    EXPECT_STREQ(name, algoName.c_str());
    HcfObjDestroy(generator);
}
}
