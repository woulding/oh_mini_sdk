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

#include "x963kdf_openssl.h"

#include <gtest/gtest.h>
#include <string>
#include <algorithm>
#include "securec.h"

#include "detailed_x963kdf_params.h"
#include "kdf.h"
#include "memory.h"

using namespace std;
using namespace testing::ext;

namespace {
class CryptoX963KdfTest : public testing::TestWithParam<std::string> {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp();
    void TearDown();
};

void CryptoX963KdfTest::SetUpTestCase() {}
void CryptoX963KdfTest::TearDownTestCase() {}

void CryptoX963KdfTest::SetUp() // add init here, this will be called before test.
{
}

void CryptoX963KdfTest::TearDown() // add destroy here, this will be called when test case done.
{
}

static const char *g_keyData = "012345678901234567890123456789";
static const char *g_infoData = "infostring";


constexpr uint32_t OUT_PUT_MAX_LENGTH = 128;
constexpr uint32_t OUT_PUT_NORMAL_LENGTH = 32;

HWTEST_F(CryptoX963KdfTest, CryptoX963KdfTest1, TestSize.Level0)
{
    HcfKdf *generator = nullptr;
    HcfResult ret = HcfKdfCreate("X963KDF|SHA256", &generator);
    EXPECT_EQ(ret, HCF_SUCCESS);
    uint8_t out[OUT_PUT_MAX_LENGTH] = {0};
    HcfBlob output = {.data = out, .len = OUT_PUT_NORMAL_LENGTH};
    HcfBlob key = {.data = reinterpret_cast<uint8_t *>(const_cast<char *>(g_keyData)),
        .len = strlen(g_keyData)};
    HcfBlob info = {.data = reinterpret_cast<uint8_t *>(const_cast<char *>(g_infoData)),
        .len = strlen(g_infoData)};
    HcfX963KDFParamsSpec params = {
        .base = { .algName = "X963KDF", },
        .key = key,
        .info = info,
        .output = output,
    };
    ret = generator->generateSecret(generator, &(params.base));
    EXPECT_EQ(ret, HCF_SUCCESS);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoX963KdfTest, CryptoX963KdfErrTest1, TestSize.Level0)
{
    HcfKdf *generator = nullptr;
    HcfResult ret = HcfKdfCreate("X963KDF|SHA256", &generator);
    EXPECT_EQ(ret, HCF_SUCCESS);
    uint8_t out[OUT_PUT_MAX_LENGTH] = {0};
    HcfBlob output = {.data = out, .len = OUT_PUT_NORMAL_LENGTH};
    HcfBlob key = {.data = reinterpret_cast<uint8_t *>(const_cast<char *>(g_keyData)),
        .len = strlen(g_keyData)};
    HcfBlob info = {.data = reinterpret_cast<uint8_t *>(const_cast<char *>(g_infoData)),
        .len = strlen(g_infoData)};
    HcfX963KDFParamsSpec params = {
        .base = { .algName = "X963KDF", },
        .key = key,
        .info = info,
        .output = output,
    };
    generator->base.destroy(nullptr);
    ret = generator->generateSecret(nullptr, &(params.base));
    EXPECT_EQ(ret, HCF_INVALID_PARAMS);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoX963KdfTest, CryptoX963KdfTest2, TestSize.Level0)
{
    // mode is default, info data is nullptr
    HcfKdf *generator = nullptr;
    HcfResult ret = HcfKdfCreate("X963KDF|SHA256", &generator);
    EXPECT_EQ(ret, HCF_SUCCESS);
    uint8_t out[OUT_PUT_MAX_LENGTH] = {0};
    HcfBlob output = {.data = out, .len = OUT_PUT_NORMAL_LENGTH};
    HcfBlob key = {.data = reinterpret_cast<uint8_t *>(const_cast<char *>(g_keyData)),
        .len = strlen(g_keyData)};
    HcfBlob info = {.data = nullptr, .len = strlen(g_infoData)};
    HcfX963KDFParamsSpec params = {
        .base = { .algName = "X963KDF", },
        .key = key,
        .info = info,
        .output = output,
    };
    ret = generator->generateSecret(generator, &(params.base));
    EXPECT_EQ(ret, HCF_SUCCESS);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoX963KdfTest, CryptoX963KdfTest4, TestSize.Level0)
{
    HcfKdf *generator = nullptr;
    HcfResult ret = HcfKdfCreate("X963KDF|SHA384", &generator);
    EXPECT_EQ(ret, HCF_SUCCESS);
    uint8_t out[OUT_PUT_MAX_LENGTH] = {0};
    HcfBlob output = {.data = out, .len = OUT_PUT_NORMAL_LENGTH};
    HcfBlob key = {.data = reinterpret_cast<uint8_t *>(const_cast<char *>(g_keyData)),
        .len = strlen(g_keyData)};
    HcfX963KDFParamsSpec params = {
        .base = { .algName = "X963KDF", },
        .key = key,
        .output = output,
    };
    ret = generator->generateSecret(generator, &(params.base));
    EXPECT_EQ(ret, HCF_SUCCESS);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoX963KdfTest, CryptoX963KdfTest5, TestSize.Level0)
{
    HcfKdf *generator = nullptr;
    HcfResult ret = HcfKdfCreate("X963KDF|MD5", &generator);
    EXPECT_EQ(ret, HCF_SUCCESS);
    uint8_t out[OUT_PUT_MAX_LENGTH] = {0};
    HcfBlob output = {.data = out, .len = OUT_PUT_NORMAL_LENGTH};
    HcfBlob key = {.data = reinterpret_cast<uint8_t *>(const_cast<char *>(g_keyData)),
        .len = strlen(g_keyData)};
    HcfBlob info = {.data = reinterpret_cast<uint8_t *>(const_cast<char *>(g_infoData)),
        .len = strlen(g_infoData)};
    HcfX963KDFParamsSpec params = {
        .base = { .algName = "X963KDF", },
        .key = key,
        .info = info,
        .output = output,
    };
    ret = generator->generateSecret(generator, &(params.base));
    EXPECT_EQ(ret, HCF_ERR_PARAMETER_CHECK_FAILED);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoX963KdfTest, CryptoX963KdfTest6, TestSize.Level0)
{
    HcfKdf *generator = nullptr;
    HcfResult ret = HcfKdfCreate("X963KDF|SHA1", &generator);
    EXPECT_EQ(ret, HCF_SUCCESS);
    uint8_t out[OUT_PUT_MAX_LENGTH] = {0};
    HcfBlob output = {.data = out, .len = OUT_PUT_NORMAL_LENGTH};
    HcfBlob key = {.data = reinterpret_cast<uint8_t *>(const_cast<char *>(g_keyData)),
        .len = strlen(g_keyData)};
    HcfBlob info = {.data = reinterpret_cast<uint8_t *>(const_cast<char *>(g_infoData)),
        .len = strlen(g_infoData)};
    HcfX963KDFParamsSpec params = {
        .base = { .algName = "X963KDF", },
        .key = key,
        .info = info,
        .output = output,
    };
    ret = generator->generateSecret(generator, &(params.base));
    EXPECT_EQ(ret, HCF_SUCCESS);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoX963KdfTest, CryptoX963KdfTest7, TestSize.Level0)
{
    HcfKdf *generator = nullptr;
    HcfResult ret = HcfKdfCreate("X963KDF|SHA224", &generator);
    EXPECT_EQ(ret, HCF_SUCCESS);
    uint8_t out[OUT_PUT_MAX_LENGTH] = {0};
    HcfBlob output = {.data = out, .len = OUT_PUT_NORMAL_LENGTH};
    HcfBlob key = {.data = reinterpret_cast<uint8_t *>(const_cast<char *>(g_keyData)),
        .len = strlen(g_keyData)};
    HcfBlob info = {.data = reinterpret_cast<uint8_t *>(const_cast<char *>(g_infoData)),
        .len = strlen(g_infoData)};
    HcfX963KDFParamsSpec params = {
        .base = { .algName = "X963KDF", },
        .key = key,
        .info = info,
        .output = output,
    };
    ret = generator->generateSecret(generator, &(params.base));
    EXPECT_EQ(ret, HCF_SUCCESS);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoX963KdfTest, CryptoX963KdfTestError1, TestSize.Level1)
{
    // mode is default, data is nullptr
    HcfKdf *generator = nullptr;
    HcfResult ret = HcfKdfCreate("X963KDF|SHA256", &generator);
    EXPECT_EQ(ret, HCF_SUCCESS);
    uint8_t out[OUT_PUT_MAX_LENGTH] = {0};
    HcfBlob output = {.data = out, .len = OUT_PUT_NORMAL_LENGTH};
    HcfBlob key = {.data = nullptr, .len = 0};
    HcfBlob info = {.data = nullptr, .len = 0};
    HcfX963KDFParamsSpec params = {
        .base = { .algName = "X963KDF", },
        .key = key,
        .info = info,
        .output = output,
    };
    ret = generator->generateSecret(generator, &(params.base));
    EXPECT_NE(ret, HCF_SUCCESS);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoX963KdfTest, CryptoX963KdfTestError2, TestSize.Level1)
{
    // mode is default, key data is nullptr
    HcfKdf *generator = nullptr;
    HcfResult ret = HcfKdfCreate("X963KDF|SHA256", &generator);
    EXPECT_EQ(ret, HCF_SUCCESS);
    uint8_t out[OUT_PUT_MAX_LENGTH] = {0};
    HcfBlob output = {.data = out, .len = OUT_PUT_NORMAL_LENGTH};
    HcfBlob key = {.data = nullptr, .len = 0};
    HcfBlob info = {.data = reinterpret_cast<uint8_t *>(const_cast<char *>(g_infoData)),
        .len = strlen(g_infoData)};
    HcfX963KDFParamsSpec params = {
        .base = { .algName = "X963KDF", },
        .key = key,
        .info = info,
        .output = output,
    };
    ret = generator->generateSecret(generator, &(params.base));
    EXPECT_NE(ret, HCF_SUCCESS);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoX963KdfTest, CryptoX963KdfTestError5, TestSize.Level1)
{
    HcfKdf *generator = nullptr;
    HcfResult ret = HcfKdfCreate("X963KDF|SHA256", &generator);
    EXPECT_EQ(ret, HCF_SUCCESS);
    HcfBlob key = {.data = nullptr, .len = 0};
    HcfBlob info = {.data = nullptr, .len = 0};
    HcfBlob output = {.data = nullptr, .len = 0};
    HcfX963KDFParamsSpec params = {
        .base = { .algName = "X963KDF", },
        .key = key,
        .info = info,
        .output = output,
    };
    ret = generator->generateSecret(generator, (HcfKdfParamsSpec *)&params);
    EXPECT_NE(ret, HCF_SUCCESS);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoX963KdfTest, CryptoX963KdfTestError6, TestSize.Level1)
{
    HcfKdf *generator = nullptr;
    HcfResult ret = HcfKdfCreate("X963KDF|SHA256", &generator);
    EXPECT_EQ(ret, HCF_SUCCESS);
    ret = generator->generateSecret(generator, nullptr);
    EXPECT_NE(ret, HCF_SUCCESS);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoX963KdfTest, CryptoX963KdfTestError7, TestSize.Level1)
{
    HcfKdf *generator = nullptr;
    HcfResult ret = HcfKdfCreate("X963KDF|SHA224", &generator);
    EXPECT_EQ(ret, HCF_SUCCESS);
    ret = generator->generateSecret(generator, nullptr);
    EXPECT_NE(ret, HCF_SUCCESS);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoX963KdfTest, CryptoX963KdfTestError8, TestSize.Level1)
{
    HcfKdf *generator = nullptr;
    HcfResult ret = HcfKdfCreate("X963KDF|SHA512", &generator);
    EXPECT_EQ(ret, HCF_SUCCESS);
    ret = generator->generateSecret(generator, nullptr);
    EXPECT_NE(ret, HCF_SUCCESS);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoX963KdfTest, CryptoX963KdfTestError9, TestSize.Level1)
{
    HcfKdf *generator = nullptr;
    HcfResult ret = HcfKdfCreate("X963KDF|abcd", &generator);
    EXPECT_NE(ret, HCF_SUCCESS);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoX963KdfTest, CryptoX963KdfTestError10, TestSize.Level1)
{
    HcfKdf *generator = nullptr;
    HcfResult ret = HcfKdfCreate("X963KDF|NoHash", &generator);
    EXPECT_EQ(ret, HCF_SUCCESS);
    uint8_t out[OUT_PUT_MAX_LENGTH] = {0};
    HcfBlob output = {.data = out, .len = OUT_PUT_NORMAL_LENGTH};
    HcfBlob key = {.data = nullptr, .len = 0};
    HcfBlob info = {.data = reinterpret_cast<uint8_t *>(const_cast<char *>(g_infoData)),
        .len = strlen(g_infoData)};
    HcfX963KDFParamsSpec params = {
        .base = { .algName = "X963KDF", },
        .key = key,
        .info = info,
        .output = output,
    };
    ret = generator->generateSecret(generator, &(params.base));
    EXPECT_NE(ret, HCF_SUCCESS);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoX963KdfTest, CryptoX963KdfTestError11, TestSize.Level1)
{
    HcfKdf *generator = nullptr;
    HcfResult ret = HcfKdfCreate("ABCD|SM3", &generator);
    EXPECT_NE(ret, HCF_SUCCESS);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoX963KdfTest, CryptoX963KdfTestError12, TestSize.Level1)
{
    HcfKdf *generator = nullptr;
    HcfResult ret = HcfKdfCreate(nullptr, &generator);
    EXPECT_NE(ret, HCF_SUCCESS);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoX963KdfTest, CryptoX963KdfTestError13, TestSize.Level1)
{
    HcfResult ret = HcfKdfCreate(nullptr, nullptr);
    EXPECT_NE(ret, HCF_SUCCESS);
}

HWTEST_F(CryptoX963KdfTest, CryptoX963KdfTestVectors1, TestSize.Level1)
{
    uint8_t keyData[] = { 0x5e, 0xd0, 0x96, 0x51, 0x0e, 0x3f, 0xcf, 0x78, 0x2c, 0xee, 0xa9, 0x8e,
        0x97, 0x37, 0x99, 0x3e, 0x2b, 0x21, 0x37, 0x0f, 0x6c, 0xda, 0x2a, 0xb1 };
    uint8_t infoData[] = {};
    uint8_t expectSecret[] = { 0xec, 0x3e, 0x22, 0x44, 0x46, 0xbf, 0xd7, 0xb3, 0xbe, 0x1d, 0xf4,
        0x04, 0x10, 0x4a, 0xf9, 0x53 };

    HcfKdf *generator = nullptr;
    HcfResult ret = HcfKdfCreate("X963KDF|SHA1", &generator);
    EXPECT_EQ(ret, HCF_SUCCESS);
    uint8_t out[16] = {0};
    HcfBlob output = {.data = out, .len = 16};
    HcfBlob key = {.data = keyData, .len = sizeof(keyData)};
    HcfBlob info = {.data = infoData, .len = sizeof(infoData)};
    HcfX963KDFParamsSpec params = {
        .base = { .algName = "X963KDF", },
        .key = key,
        .info = info,
        .output = output,
    };
    ret = generator->generateSecret(generator, &(params.base));
    EXPECT_EQ(ret, HCF_SUCCESS);
    EXPECT_EQ(memcmp(params.output.data, expectSecret, sizeof(expectSecret)), 0);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoX963KdfTest, CryptoX963KdfTestVectors2, TestSize.Level1)
{
    uint8_t keyData[] = { 0xfd, 0x17, 0x19, 0x8b, 0x89, 0xab, 0x39, 0xc4, 0xab, 0x5d, 0x7c, 0xca, 0x36,
        0x3b, 0x82, 0xf9, 0xfd, 0x7e, 0x23, 0xc3, 0x98, 0x4d, 0xc8, 0xa2 };
    uint8_t infoData[] = { 0x85, 0x6a, 0x53, 0xf3, 0xe3, 0x6a, 0x26, 0xbb, 0xc5, 0x79, 0x28, 0x79, 0xf3,
        0x07, 0xcc, 0xe2 };
    uint8_t expectSecret[] = { 0x6e, 0x5f, 0xad, 0x86, 0x5c, 0xb4, 0xa5, 0x1c, 0x95, 0x20, 0x9b, 0x16,
        0xdf, 0x0c, 0xc4, 0x90, 0xbc, 0x2c, 0x90, 0x64, 0x40, 0x5c, 0x5b, 0xcc, 0xd4, 0xee, 0x48, 0x32,
        0xa5, 0x31, 0xfb, 0xe7, 0xf1, 0x0c, 0xb7, 0x9e, 0x2e, 0xab, 0x6a, 0xb1, 0x14, 0x9f, 0xbd, 0x5a,
        0x23, 0xcf, 0xda, 0xbc, 0x41, 0x24, 0x22, 0x69, 0xc9, 0xdf, 0x22, 0xf6, 0x28, 0xc4, 0x42, 0x43,
        0x33, 0x85, 0x5b, 0x64, 0xe9, 0x5e, 0x2d, 0x4f, 0xb8, 0x46, 0x9c, 0x66, 0x9f, 0x17, 0x17, 0x6c,
        0x07, 0xd1, 0x03, 0x37, 0x6b, 0x10, 0xb3, 0x84, 0xec, 0x57, 0x63, 0xd8, 0xb8, 0xc6, 0x10, 0x40,
        0x9f, 0x19, 0xac, 0xa8, 0xeb, 0x31, 0xf9, 0xd8, 0x5c, 0xc6, 0x1a, 0x8d, 0x6d, 0x4a, 0x03, 0xd0,
        0x3e, 0x5a, 0x50, 0x6b, 0x78, 0xd6, 0x84, 0x7e, 0x93, 0xd2, 0x95, 0xee, 0x54, 0x8c, 0x65, 0xaf,
        0xed, 0xd2, 0xef, 0xec };

    HcfKdf *generator = nullptr;
    HcfResult ret = HcfKdfCreate("X963KDF|SHA1", &generator);
    EXPECT_EQ(ret, HCF_SUCCESS);
    uint8_t out[128] = {0};
    HcfBlob output = {.data = out, .len = 128};
    HcfBlob key = {.data = keyData, .len = sizeof(keyData)};
    HcfBlob info = {.data = infoData, .len = sizeof(infoData)};
    HcfX963KDFParamsSpec params = {
        .base = { .algName = "X963KDF", },
        .key = key,
        .info = info,
        .output = output,
    };
    ret = generator->generateSecret(generator, &(params.base));
    EXPECT_EQ(ret, HCF_SUCCESS);
    EXPECT_EQ(memcmp(params.output.data, expectSecret, sizeof(expectSecret)), 0);
    HcfObjDestroy(generator);
}

std::vector<std::string> x963KdfMdAlgoParams = {
    "SHA1",
    "SHA224",
    "SHA256",
    "SHA384",
    "SHA512",
    "SHA3-256",
    "SHA3-384",
    "SHA3-512",
};

INSTANTIATE_TEST_SUITE_P(CryptoX963KdfTestParam, CryptoX963KdfTest,
    ::testing::ValuesIn(x963KdfMdAlgoParams),
    [](const ::testing::TestParamInfo<std::string> &info) {
        std::string name = info.param;
        std::replace(name.begin(), name.end(), '-', '_'); // name not support '-'
        return name;
    }
);

HWTEST_P(CryptoX963KdfTest, CryptoX963KdfAlgoTest, TestSize.Level0)
{
    std::string kdfName = "X963KDF";
    std::string mdName = GetParam();
    std::string algoName = kdfName + "|" + mdName;

    HcfKdf *generator = nullptr;
    HcfResult ret = HcfKdfCreate(algoName.c_str(), &generator);
    EXPECT_EQ(ret, HCF_SUCCESS);

    uint8_t buf[] = { 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F };
    HcfBlob blob = { .data = buf, .len = sizeof(buf) };
    uint8_t out[OUT_PUT_NORMAL_LENGTH] = {};
    HcfBlob output = { .data = out, .len = sizeof(out) };
    HcfX963KDFParamsSpec spec = {
        .base = { .algName = kdfName.c_str() },
        .key = blob,
        .info = blob,
        .output = output,
    };
    ret = generator->generateSecret(generator, &(spec.base));
    EXPECT_EQ(ret, HCF_SUCCESS);
    const char *name = generator->getAlgorithm(generator);
    EXPECT_STREQ(name, algoName.c_str());
    HcfObjDestroy(generator);
}
}
