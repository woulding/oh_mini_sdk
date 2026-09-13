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

#include <gtest/gtest.h>
#include "securec.h"
#include "blob.h"
#include "cipher_sm2_crypto_util_openssl.h"
#include "sm2_crypto_util.h"
#include "memory.h"
#include "cstring"

using namespace std;
using namespace testing::ext;

namespace {
class CryptoSm2UtilTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp();
    void TearDown();
};

void CryptoSm2UtilTest::SetUp() {}
void CryptoSm2UtilTest::TearDown() {}
void CryptoSm2UtilTest::SetUpTestCase() {}
void CryptoSm2UtilTest::TearDownTestCase() {}

static const char *g_sm2ModeC1C3C2 = "C1C3C2";
static const char *g_sm2ModeError = "C1C2C2";
static const int CORRECT_INPUT_LEN = 121;
static const int ERROR_INPUT_LEN = 12;
static const int INPUT_LEN_ZERO = 0;
static uint8_t g_mockCorrectInput[CORRECT_INPUT_LEN] = {
    48, 119, 2, 33, 0, 183, 70, 70, 149, 188, 64, 6, 110, 236, 85, 149, 216, 224, 102, 95, 92, 41, 105, 232, 5,
    248, 122, 21, 174, 43, 226, 221, 104, 82, 88, 153, 45, 2, 32, 96, 229, 78, 209, 233, 110, 5, 149, 91, 110,
    109, 181, 17, 75, 109, 146, 128, 170, 113, 205, 158, 193, 156, 90, 110, 40, 18, 119, 247, 198, 93, 107, 4,
    32, 87, 167, 167, 247, 88, 146, 203, 234, 83, 126, 117, 129, 52, 142, 82, 54, 152, 226, 201, 111, 143, 115,
    169, 125, 128, 42, 157, 31, 114, 198, 109, 244, 4, 14, 100, 227, 78, 195, 249, 179, 43, 70, 242, 69, 169, 10,
    65, 123
};
static HcfBlob g_correctInput = {
    .data = g_mockCorrectInput,
    .len = CORRECT_INPUT_LEN
};
static HcfBlob g_errorInput = {
    .data = g_mockCorrectInput,
    .len = ERROR_INPUT_LEN
};
static const int X_COORDINATE_LEN = 32;
static unsigned char g_xCoordinate[] = {
    45, 153, 88, 82, 104, 221, 226, 43, 174, 21, 122, 248, 5, 232, 105, 41, 92, 95, 102, 224, 216, 149, 85, 236,
    110, 6, 64, 188, 149, 70, 70, 183
};
static const int Y_COORDINATE_LEN = 32;
static unsigned char g_yCoordinate[] = {
    107, 93, 198, 247, 119, 18, 40, 110, 90, 156, 193, 158, 205, 113, 170, 128, 146, 109, 75, 17, 181, 109, 110,
    91, 149, 5, 110, 233, 209, 78, 229, 96
};
static const int HASH_DATA_LEN = 32;
static const int ERROR_HASH_DATA_LEN = 15;
static unsigned char g_hashData[] = {
    87, 167, 167, 247, 88, 146, 203, 234, 83, 126, 117, 129, 52, 142, 82, 54, 152, 226, 201, 111, 143, 115, 169,
    125, 128, 42, 157, 31, 114, 198, 109, 244
};
static const int CIPHER_TEXT_DATA_LEN = 14;
static unsigned char g_cipherTextData[] = {
    100, 227, 78, 195, 249, 179, 43, 70, 242, 69, 169, 10, 65, 123
};

HcfResult ConstructCorrectSm2CipherTextSpec(Sm2CipherTextSpec **spec)
{
    Sm2CipherTextSpec *tempSpec = static_cast<Sm2CipherTextSpec *>(HcfMalloc(sizeof(Sm2CipherTextSpec), 0));
    if (tempSpec == nullptr) {
        return HCF_ERR_MALLOC;
    }
    tempSpec->xCoordinate.data = g_xCoordinate;
    tempSpec->xCoordinate.len = X_COORDINATE_LEN;
    tempSpec->yCoordinate.data = g_yCoordinate;
    tempSpec->yCoordinate.len = Y_COORDINATE_LEN;
    tempSpec->cipherTextData.data = g_cipherTextData;
    tempSpec->cipherTextData.len = CIPHER_TEXT_DATA_LEN;
    tempSpec->hashData.data = g_hashData;
    tempSpec->hashData.len = HASH_DATA_LEN;
    *spec = tempSpec;
    return HCF_SUCCESS;
}

HcfResult ConstructMissYErrorSm2CipherTextSpec(Sm2CipherTextSpec **spec)
{
    Sm2CipherTextSpec *tempSpec = static_cast<Sm2CipherTextSpec *>(HcfMalloc(sizeof(Sm2CipherTextSpec), 0));
    if (tempSpec == nullptr) {
        return HCF_ERR_MALLOC;
    }
    tempSpec->xCoordinate.data = g_xCoordinate;
    tempSpec->xCoordinate.len = X_COORDINATE_LEN;
    tempSpec->cipherTextData.data = g_cipherTextData;
    tempSpec->cipherTextData.len = CIPHER_TEXT_DATA_LEN;
    tempSpec->hashData.data = g_hashData;
    tempSpec->hashData.len = HASH_DATA_LEN;
    *spec = tempSpec;
    return HCF_SUCCESS;
}

HcfResult ConstructMissXErrorSm2CipherTextSpec(Sm2CipherTextSpec **spec)
{
    Sm2CipherTextSpec *tempSpec = static_cast<Sm2CipherTextSpec *>(HcfMalloc(sizeof(Sm2CipherTextSpec), 0));
    if (tempSpec == nullptr) {
        return HCF_ERR_MALLOC;
    }
    tempSpec->yCoordinate.data = g_yCoordinate;
    tempSpec->yCoordinate.len = Y_COORDINATE_LEN;
    tempSpec->cipherTextData.data = g_cipherTextData;
    tempSpec->cipherTextData.len = CIPHER_TEXT_DATA_LEN;
    tempSpec->hashData.data = g_hashData;
    tempSpec->hashData.len = HASH_DATA_LEN;
    *spec = tempSpec;
    return HCF_SUCCESS;
}

HcfResult ConstructMissHashDataErrorSm2CipherTextSpec(Sm2CipherTextSpec **spec)
{
    Sm2CipherTextSpec *tempSpec = static_cast<Sm2CipherTextSpec *>(HcfMalloc(sizeof(Sm2CipherTextSpec), 0));
    if (tempSpec == nullptr) {
        return HCF_ERR_MALLOC;
    }
    tempSpec->xCoordinate.data = g_xCoordinate;
    tempSpec->xCoordinate.len = X_COORDINATE_LEN;
    tempSpec->yCoordinate.data = g_yCoordinate;
    tempSpec->yCoordinate.len = Y_COORDINATE_LEN;
    tempSpec->cipherTextData.data = g_cipherTextData;
    tempSpec->cipherTextData.len = CIPHER_TEXT_DATA_LEN;
    *spec = tempSpec;
    return HCF_SUCCESS;
}

HcfResult ConstructMissCipherDataErrorSm2CipherTextSpec(Sm2CipherTextSpec **spec)
{
    Sm2CipherTextSpec *tempSpec = static_cast<Sm2CipherTextSpec *>(HcfMalloc(sizeof(Sm2CipherTextSpec), 0));
    if (tempSpec == nullptr) {
        return HCF_ERR_MALLOC;
    }
    tempSpec->xCoordinate.data = g_xCoordinate;
    tempSpec->xCoordinate.len = X_COORDINATE_LEN;
    tempSpec->yCoordinate.data = g_yCoordinate;
    tempSpec->yCoordinate.len = Y_COORDINATE_LEN;
    tempSpec->hashData.data = g_hashData;
    tempSpec->hashData.len = HASH_DATA_LEN;
    *spec = tempSpec;
    return HCF_SUCCESS;
}

HcfResult ConstructLenErrorSm2CipherTextSpec(Sm2CipherTextSpec **spec)
{
    // hashData.len != 32
    Sm2CipherTextSpec *tempSpec = static_cast<Sm2CipherTextSpec *>(HcfMalloc(sizeof(Sm2CipherTextSpec), 0));
    if (tempSpec == nullptr) {
        return HCF_ERR_MALLOC;
    }
    tempSpec->xCoordinate.data = g_xCoordinate;
    tempSpec->xCoordinate.len = X_COORDINATE_LEN;
    tempSpec->yCoordinate.data = g_yCoordinate;
    tempSpec->yCoordinate.len = Y_COORDINATE_LEN;
    tempSpec->hashData.data = g_hashData;
    tempSpec->hashData.len = ERROR_HASH_DATA_LEN;
    tempSpec->cipherTextData.data = g_cipherTextData;
    tempSpec->cipherTextData.len = CIPHER_TEXT_DATA_LEN;
    *spec = tempSpec;
    return HCF_SUCCESS;
}

HcfResult ConstructLenZeroXSm2CipherTextSpec(Sm2CipherTextSpec **spec)
{
    Sm2CipherTextSpec *tempSpec = static_cast<Sm2CipherTextSpec *>(HcfMalloc(sizeof(Sm2CipherTextSpec), 0));
    if (tempSpec == nullptr) {
        return HCF_ERR_MALLOC;
    }
    tempSpec->xCoordinate.data = g_xCoordinate;
    tempSpec->xCoordinate.len = INPUT_LEN_ZERO;
    tempSpec->yCoordinate.data = g_yCoordinate;
    tempSpec->yCoordinate.len = Y_COORDINATE_LEN;
    tempSpec->cipherTextData.data = g_cipherTextData;
    tempSpec->cipherTextData.len = CIPHER_TEXT_DATA_LEN;
    tempSpec->hashData.data = g_hashData;
    tempSpec->hashData.len = HASH_DATA_LEN;
    *spec = tempSpec;
    return HCF_SUCCESS;
}

HcfResult ConstructLenZeroYSm2CipherTextSpec(Sm2CipherTextSpec **spec)
{
    Sm2CipherTextSpec *tempSpec = static_cast<Sm2CipherTextSpec *>(HcfMalloc(sizeof(Sm2CipherTextSpec), 0));
    if (tempSpec == nullptr) {
        return HCF_ERR_MALLOC;
    }
    tempSpec->xCoordinate.data = g_xCoordinate;
    tempSpec->xCoordinate.len = X_COORDINATE_LEN;
    tempSpec->yCoordinate.data = g_yCoordinate;
    tempSpec->yCoordinate.len = INPUT_LEN_ZERO;
    tempSpec->cipherTextData.data = g_cipherTextData;
    tempSpec->cipherTextData.len = CIPHER_TEXT_DATA_LEN;
    tempSpec->hashData.data = g_hashData;
    tempSpec->hashData.len = HASH_DATA_LEN;
    *spec = tempSpec;
    return HCF_SUCCESS;
}

HcfResult ConstructLenZeroCipherDataSm2CipherTextSpec(Sm2CipherTextSpec **spec)
{
    Sm2CipherTextSpec *tempSpec = static_cast<Sm2CipherTextSpec *>(HcfMalloc(sizeof(Sm2CipherTextSpec), 0));
    if (tempSpec == nullptr) {
        return HCF_ERR_MALLOC;
    }
    tempSpec->xCoordinate.data = g_xCoordinate;
    tempSpec->xCoordinate.len = X_COORDINATE_LEN;
    tempSpec->yCoordinate.data = g_yCoordinate;
    tempSpec->yCoordinate.len = Y_COORDINATE_LEN;
    tempSpec->cipherTextData.data = g_cipherTextData;
    tempSpec->cipherTextData.len = INPUT_LEN_ZERO;
    tempSpec->hashData.data = g_hashData;
    tempSpec->hashData.len = HASH_DATA_LEN;
    *spec = tempSpec;
    return HCF_SUCCESS;
}

HcfResult ConstructLenZeroHashDataSm2CipherTextSpec(Sm2CipherTextSpec **spec)
{
    Sm2CipherTextSpec *tempSpec = static_cast<Sm2CipherTextSpec *>(HcfMalloc(sizeof(Sm2CipherTextSpec), 0));
    if (tempSpec == nullptr) {
        return HCF_ERR_MALLOC;
    }
    tempSpec->xCoordinate.data = g_xCoordinate;
    tempSpec->xCoordinate.len = X_COORDINATE_LEN;
    tempSpec->yCoordinate.data = g_yCoordinate;
    tempSpec->yCoordinate.len = Y_COORDINATE_LEN;
    tempSpec->cipherTextData.data = g_cipherTextData;
    tempSpec->cipherTextData.len = CIPHER_TEXT_DATA_LEN;
    tempSpec->hashData.data = g_hashData;
    tempSpec->hashData.len = INPUT_LEN_ZERO;
    *spec = tempSpec;
    return HCF_SUCCESS;
}

HcfResult ConstructMissErrorSm2CipherTextSpec(Sm2CipherTextSpec **spec)
{
    Sm2CipherTextSpec *tempSpec = static_cast<Sm2CipherTextSpec *>(HcfMalloc(sizeof(Sm2CipherTextSpec), 0));
    if (tempSpec == nullptr) {
        return HCF_ERR_MALLOC;
    }
    *spec = tempSpec;
    return HCF_SUCCESS;
}

HWTEST_F(CryptoSm2UtilTest, CryptoSm2UtilTest001, TestSize.Level0)
{
    // test HcfGenCipherTextBySpec success, case mode = C1C3C2
    int res = 0;
    Sm2CipherTextSpec *spec = nullptr;
    res = ConstructCorrectSm2CipherTextSpec(&spec);
    EXPECT_EQ(res, HCF_SUCCESS);
    HcfBlob output = { .data = nullptr, .len = 0 };
    res = HcfGenCipherTextBySpec(spec, g_sm2ModeC1C3C2, &output);
    EXPECT_EQ(res, HCF_SUCCESS);
    res = memcmp(output.data, g_correctInput.data, g_correctInput.len);
    HcfBlobDataFree(&output);
    HcfFree(spec);
    EXPECT_EQ(res, 0);
}

HWTEST_F(CryptoSm2UtilTest, CryptoSm2UtilTest002, TestSize.Level0)
{
    // test HcfGenCipherTextBySpec success, case mode = null
    int res = 0;
    Sm2CipherTextSpec *spec = nullptr;
    res = ConstructCorrectSm2CipherTextSpec(&spec);
    EXPECT_EQ(res, HCF_SUCCESS);
    HcfBlob output = { .data = nullptr, .len = 0 };
    res = HcfGenCipherTextBySpec(spec, NULL, &output);
    EXPECT_EQ(res, HCF_SUCCESS);
    res = memcmp(output.data, g_correctInput.data, g_correctInput.len);
    HcfBlobDataFree(&output);
    HcfFree(spec);
    EXPECT_EQ(res, 0);
}

HWTEST_F(CryptoSm2UtilTest, CryptoSm2UtilTest003, TestSize.Level0)
{
    // test HcfGenCipherTextBySpec error, case mode = C1C2C2
    Sm2CipherTextSpec *spec = nullptr;
    HcfResult res = ConstructCorrectSm2CipherTextSpec(&spec);
    EXPECT_EQ(res, HCF_SUCCESS);
    HcfBlob output = { .data = nullptr, .len = 0 };
    res = HcfGenCipherTextBySpec(spec, g_sm2ModeError, &output);
    EXPECT_EQ(res, HCF_INVALID_PARAMS);
    HcfFree(spec);
}

HWTEST_F(CryptoSm2UtilTest, CryptoSm2UtilTest004, TestSize.Level0)
{
    // test HcfGenCipherTextBySpec error, case spec miss yCoordinate
    Sm2CipherTextSpec *spec = nullptr;
    HcfResult res = ConstructMissYErrorSm2CipherTextSpec(&spec);
    EXPECT_EQ(res, HCF_SUCCESS);
    HcfBlob output = { .data = nullptr, .len = 0 };
    res = HcfGenCipherTextBySpec(spec, g_sm2ModeC1C3C2, &output);
    EXPECT_EQ(res, HCF_INVALID_PARAMS);
    HcfFree(spec);
}

HWTEST_F(CryptoSm2UtilTest, CryptoSm2UtilTest005, TestSize.Level0)
{
    // test HcfGenCipherTextBySpec error, case spec hashData.len != 32
    Sm2CipherTextSpec *spec = nullptr;
    HcfResult res = ConstructLenErrorSm2CipherTextSpec(&spec);
    EXPECT_EQ(res, HCF_SUCCESS);
    HcfBlob output = { .data = nullptr, .len = 0 };
    res = HcfGenCipherTextBySpec(spec, g_sm2ModeC1C3C2, &output);
    EXPECT_EQ(res, HCF_INVALID_PARAMS);
    HcfFree(spec);
}

HWTEST_F(CryptoSm2UtilTest, CryptoSm2UtilTest006, TestSize.Level0)
{
    // test HcfGenCipherTextBySpec error, case spec miss xCoordinate
    Sm2CipherTextSpec *spec = nullptr;
    HcfResult res = ConstructMissXErrorSm2CipherTextSpec(&spec);
    EXPECT_EQ(res, HCF_SUCCESS);
    HcfBlob output = { .data = nullptr, .len = 0 };
    res = HcfGenCipherTextBySpec(spec, g_sm2ModeC1C3C2, &output);
    EXPECT_EQ(res, HCF_INVALID_PARAMS);
    HcfFree(spec);
}

HWTEST_F(CryptoSm2UtilTest, CryptoSm2UtilTest007, TestSize.Level0)
{
    // test HcfGenCipherTextBySpec error, case spec miss hashData
    Sm2CipherTextSpec *spec = nullptr;
    HcfResult res = ConstructMissHashDataErrorSm2CipherTextSpec(&spec);
    EXPECT_EQ(res, HCF_SUCCESS);
    HcfBlob output = { .data = nullptr, .len = 0 };
    res = HcfGenCipherTextBySpec(spec, g_sm2ModeC1C3C2, &output);
    EXPECT_EQ(res, HCF_INVALID_PARAMS);
    HcfFree(spec);
}

HWTEST_F(CryptoSm2UtilTest, CryptoSm2UtilTest008, TestSize.Level0)
{
    // test HcfGenCipherTextBySpec error, case spec miss cipherData
    Sm2CipherTextSpec *spec = nullptr;
    HcfResult res = ConstructMissCipherDataErrorSm2CipherTextSpec(&spec);
    EXPECT_EQ(res, HCF_SUCCESS);
    HcfBlob output = { .data = nullptr, .len = 0 };
    res = HcfGenCipherTextBySpec(spec, g_sm2ModeC1C3C2, &output);
    EXPECT_EQ(res, HCF_INVALID_PARAMS);
    HcfFree(spec);
}

HWTEST_F(CryptoSm2UtilTest, CryptoSm2UtilTest009, TestSize.Level0)
{
    // test HcfGenCipherTextBySpec error, case output is null
    Sm2CipherTextSpec *spec = nullptr;
    HcfResult res = ConstructCorrectSm2CipherTextSpec(&spec);
    EXPECT_EQ(res, HCF_SUCCESS);
    res = HcfGenCipherTextBySpec(spec, g_sm2ModeC1C3C2, NULL);
    EXPECT_EQ(res, HCF_INVALID_PARAMS);
    HcfFree(spec);
}

HWTEST_F(CryptoSm2UtilTest, CryptoSm2UtilTest010, TestSize.Level0)
{
    // test HcfGenCipherTextBySpec error, case spec is null
    HcfBlob output = { .data = nullptr, .len = 0 };
    HcfResult res = HcfGenCipherTextBySpec(nullptr, g_sm2ModeC1C3C2, &output);
    EXPECT_EQ(res, HCF_INVALID_PARAMS);
}

HWTEST_F(CryptoSm2UtilTest, CryptoSm2UtilTest011, TestSize.Level0)
{
    // test HcfGenCipherTextBySpec error, case spec xCoordinate.len = 0
    Sm2CipherTextSpec *spec = nullptr;
    HcfResult res = ConstructLenZeroXSm2CipherTextSpec(&spec);
    EXPECT_EQ(res, HCF_SUCCESS);
    HcfBlob output = { .data = nullptr, .len = 0 };
    res = HcfGenCipherTextBySpec(spec, g_sm2ModeC1C3C2, &output);
    EXPECT_EQ(res, HCF_INVALID_PARAMS);
    HcfFree(spec);
}

HWTEST_F(CryptoSm2UtilTest, CryptoSm2UtilTest012, TestSize.Level0)
{
    // test HcfGenCipherTextBySpec error, case spec yCoordinate.len = 0
    Sm2CipherTextSpec *spec = nullptr;
    HcfResult res = ConstructLenZeroYSm2CipherTextSpec(&spec);
    EXPECT_EQ(res, HCF_SUCCESS);
    HcfBlob output = { .data = nullptr, .len = 0 };
    res = HcfGenCipherTextBySpec(spec, g_sm2ModeC1C3C2, &output);
    EXPECT_EQ(res, HCF_INVALID_PARAMS);
    HcfFree(spec);
}

HWTEST_F(CryptoSm2UtilTest, CryptoSm2UtilTest013, TestSize.Level0)
{
    // test HcfGenCipherTextBySpec error, case spec cipherTextData.len = 0
    Sm2CipherTextSpec *spec = nullptr;
    HcfResult res = ConstructLenZeroCipherDataSm2CipherTextSpec(&spec);
    EXPECT_EQ(res, HCF_SUCCESS);
    HcfBlob output = { .data = nullptr, .len = 0 };
    res = HcfGenCipherTextBySpec(spec, g_sm2ModeC1C3C2, &output);
    EXPECT_EQ(res, HCF_INVALID_PARAMS);
    HcfFree(spec);
}

HWTEST_F(CryptoSm2UtilTest, CryptoSm2UtilTest014, TestSize.Level0)
{
    // test HcfGenCipherTextBySpec error, case spec hashData.len = 0
    Sm2CipherTextSpec *spec = nullptr;
    HcfResult res = ConstructLenZeroHashDataSm2CipherTextSpec(&spec);
    EXPECT_EQ(res, HCF_SUCCESS);
    HcfBlob output = { .data = nullptr, .len = 0 };
    res = HcfGenCipherTextBySpec(spec, g_sm2ModeC1C3C2, &output);
    EXPECT_EQ(res, HCF_INVALID_PARAMS);
    HcfFree(spec);
}

HWTEST_F(CryptoSm2UtilTest, CryptoSm2UtilTest015, TestSize.Level0)
{
    // test HcfGenCipherTextBySpec error, case spec null construct
    Sm2CipherTextSpec *spec = nullptr;
    HcfResult res = ConstructMissErrorSm2CipherTextSpec(&spec);
    EXPECT_EQ(res, HCF_SUCCESS);
    HcfBlob output = { .data = nullptr, .len = 0 };
    res = HcfGenCipherTextBySpec(spec, g_sm2ModeC1C3C2, &output);
    EXPECT_EQ(res, HCF_INVALID_PARAMS);
    HcfFree(spec);
}

HWTEST_F(CryptoSm2UtilTest, CryptoSm2UtilTest101, TestSize.Level0)
{
    // test HcfGetCipherTextSpec success, case mode = C1C3C2
    Sm2CipherTextSpec *spec = nullptr;
    HcfResult res = HcfGetCipherTextSpec(&g_correctInput, g_sm2ModeC1C3C2, &spec);
    EXPECT_EQ(res, HCF_SUCCESS);
    DestroySm2CipherTextSpec(spec);
}

HWTEST_F(CryptoSm2UtilTest, CryptoSm2UtilTest102, TestSize.Level0)
{
    // test HcfGenCipherTextBySpec success, case mode = null
    Sm2CipherTextSpec *spec = nullptr;
    HcfResult res = HcfGetCipherTextSpec(&g_correctInput, NULL, &spec);
    EXPECT_EQ(res, HCF_SUCCESS);
    DestroySm2CipherTextSpec(spec);
}

HWTEST_F(CryptoSm2UtilTest, CryptoSm2UtilTest103, TestSize.Level0)
{
    // test HcfGenCipherTextBySpec error, case mode = C1C2C2
    Sm2CipherTextSpec *spec = nullptr;
    HcfResult res = HcfGetCipherTextSpec(&g_correctInput, g_sm2ModeError, &spec);
    EXPECT_EQ(res, HCF_INVALID_PARAMS);
}

HWTEST_F(CryptoSm2UtilTest, CryptoSm2UtilTest104, TestSize.Level0)
{
    // test HcfGetCipherTextSpec error, case input null
    Sm2CipherTextSpec *spec = nullptr;
    HcfResult res = HcfGetCipherTextSpec(NULL, g_sm2ModeC1C3C2, &spec);
    EXPECT_EQ(res, HCF_INVALID_PARAMS);
}

HWTEST_F(CryptoSm2UtilTest, CryptoSm2UtilTest105, TestSize.Level0)
{
    // test HcfGetCipherTextSpec error, case input error len
    Sm2CipherTextSpec *spec = nullptr;
    HcfResult res = HcfGetCipherTextSpec(&g_errorInput, g_sm2ModeC1C3C2, &spec);
    EXPECT_EQ(res, HCF_ERR_CRYPTO_OPERATION);
}

HWTEST_F(CryptoSm2UtilTest, CryptoSm2UtilTest106, TestSize.Level0)
{
    // test HcfGetCipherTextSpec error, case returnSpec is null
    HcfResult res = HcfGetCipherTextSpec(&g_correctInput, g_sm2ModeC1C3C2, NULL);
    EXPECT_EQ(res, HCF_INVALID_PARAMS);
}

HWTEST_F(CryptoSm2UtilTest, CryptoSm2UtilTest201, TestSize.Level0)
{
    // test HcfSm2SpecToAsn1 success
    int res = 0;
    Sm2CipherTextSpec *spec = nullptr;
    res = ConstructCorrectSm2CipherTextSpec(&spec);
    EXPECT_EQ(res, HCF_SUCCESS);
    HcfBlob output = { .data = nullptr, .len = 0 };
    res = HcfSm2SpecToAsn1(spec, &output);
    EXPECT_EQ(res, HCF_SUCCESS);
    res = memcmp(output.data, g_correctInput.data, g_correctInput.len);
    HcfBlobDataFree(&output);
    HcfFree(spec);
    EXPECT_EQ(res, 0);
}

HWTEST_F(CryptoSm2UtilTest, CryptoSm2UtilTest202, TestSize.Level0)
{
    // test HcfSm2SpecToAsn1 success, case spec miss yCoordinate
    Sm2CipherTextSpec *spec = nullptr;
    HcfResult res = ConstructMissYErrorSm2CipherTextSpec(&spec);
    EXPECT_EQ(res, HCF_SUCCESS);
    HcfBlob output = { .data = nullptr, .len = 0 };
    res = HcfSm2SpecToAsn1(spec, &output);
    EXPECT_EQ(res, HCF_SUCCESS);
    HcfFree(spec);
    HcfBlobDataFree(&output);
}

HWTEST_F(CryptoSm2UtilTest, CryptoSm2UtilTest203, TestSize.Level0)
{
    // test HcfSm2SpecToAsn1 success, case spec miss xCoordinate
    Sm2CipherTextSpec *spec = nullptr;
    HcfResult res = ConstructMissXErrorSm2CipherTextSpec(&spec);
    EXPECT_EQ(res, HCF_SUCCESS);
    HcfBlob output = { .data = nullptr, .len = 0 };
    res = HcfSm2SpecToAsn1(spec, &output);
    EXPECT_EQ(res, HCF_SUCCESS);
    HcfBlobDataFree(&output);
    HcfFree(spec);
}

HWTEST_F(CryptoSm2UtilTest, CryptoSm2UtilTest204, TestSize.Level0)
{
    // test HcfSm2SpecToAsn1 success, case spec miss hashData
    Sm2CipherTextSpec *spec = nullptr;
    HcfResult res = ConstructMissHashDataErrorSm2CipherTextSpec(&spec);
    EXPECT_EQ(res, HCF_SUCCESS);
    HcfBlob output = { .data = nullptr, .len = 0 };
    res = HcfSm2SpecToAsn1(spec, &output);
    EXPECT_EQ(res, HCF_SUCCESS);
    HcfBlobDataFree(&output);
    HcfFree(spec);
}

HWTEST_F(CryptoSm2UtilTest, CryptoSm2UtilTest205, TestSize.Level0)
{
    // test HcfGenCipherTextBySpec success, case spec miss cipherData
    Sm2CipherTextSpec *spec = nullptr;
    HcfResult res = ConstructMissCipherDataErrorSm2CipherTextSpec(&spec);
    EXPECT_EQ(res, HCF_SUCCESS);
    HcfBlob output = { .data = nullptr, .len = 0 };
    res = HcfSm2SpecToAsn1(spec, &output);
    EXPECT_EQ(res, HCF_SUCCESS);
    HcfBlobDataFree(&output);
    HcfFree(spec);
}

HWTEST_F(CryptoSm2UtilTest, CryptoSm2UtilTest301, TestSize.Level0)
{
    // test HcfAsn1ToSm2Spec success
    Sm2CipherTextSpec *spec = nullptr;
    HcfResult res = HcfAsn1ToSm2Spec(&g_correctInput, &spec);
    EXPECT_EQ(res, HCF_SUCCESS);
    DestroySm2CipherTextSpec(spec);
}

HWTEST_F(CryptoSm2UtilTest, CryptoSm2UtilTest305, TestSize.Level0)
{
    // test HcfAsn1ToSm2Spec error, case input error len
    Sm2CipherTextSpec *spec = nullptr;
    HcfResult res = HcfAsn1ToSm2Spec(&g_errorInput, &spec);
    EXPECT_EQ(res, HCF_ERR_CRYPTO_OPERATION);
}
}