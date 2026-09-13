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
#include "blob.h"
#include "cipher_sm2_ecdsa_signature_openssl.h"
#include "sm2_crypto_util.h"
#include "sm2_crypto_params.h"
#include "memory.h"
#include "cstring"
#include "crypto_operation_err.h"

using namespace std;
using namespace testing::ext;

namespace {
class CryptoSm2EcdsaSignature : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp();
    void TearDown();
};

void CryptoSm2EcdsaSignature::SetUp() {}
void CryptoSm2EcdsaSignature::TearDown() {}
void CryptoSm2EcdsaSignature::SetUpTestCase() {}
void CryptoSm2EcdsaSignature::TearDownTestCase() {}

static unsigned char g_rCoordinate[] = {
    107, 93, 198, 247, 119, 18, 40, 110, 90, 156, 193, 158, 205, 113, 170, 128, 146, 109, 75, 17, 181, 109, 110,
    91, 149, 5, 110, 233, 209, 78, 229, 96
};

static unsigned char g_sCoordinate[] = {
    45, 153, 88, 82, 104, 221, 226, 43, 174, 21, 122, 248, 5, 232, 105, 41, 92, 95, 102, 224, 216, 149, 85, 236,
    110, 6, 64, 188, 149, 70, 70, 183
};

HcfResult ConstructCorrectSm2Spec(Sm2EcSignatureDataSpec **spec)
{
    Sm2EcSignatureDataSpec *tempSpec =
        static_cast<Sm2EcSignatureDataSpec *>(HcfMalloc(sizeof(Sm2EcSignatureDataSpec), 0));
    if (tempSpec == nullptr) {
        return HCF_ERR_MALLOC;
    }
    tempSpec->rCoordinate.data = g_rCoordinate;
    tempSpec->rCoordinate.len = sizeof(g_sCoordinate);
    tempSpec->sCoordinate.data = g_sCoordinate;
    tempSpec->sCoordinate.len = sizeof(g_sCoordinate);
    *spec = tempSpec;
    return HCF_SUCCESS;
}

HWTEST_F(CryptoSm2EcdsaSignature, HcfSm2SpecToDerDataAndBack, TestSize.Level0)
{
    Sm2EcSignatureDataSpec *spec = nullptr;
    ASSERT_EQ(ConstructCorrectSm2Spec(&spec), HCF_SUCCESS);

    // Convert SM2 spec to DER data
    HcfBlob derOutput = { .data = nullptr, .len = 0 };
    EXPECT_EQ(HcfSm2SpecToDerData(spec, &derOutput), HCF_SUCCESS);
    EXPECT_NE(derOutput.data, nullptr);
    EXPECT_GT(derOutput.len, 0);

    // Convert DER data back to SM2 spec
    Sm2EcSignatureDataSpec *returnSpec = nullptr;
    EXPECT_EQ(HcfDerDataToSm2Spec(&derOutput, &returnSpec), HCF_SUCCESS);
    EXPECT_NE(returnSpec, nullptr);

    // Validate the converted spec matches the original
    EXPECT_EQ(returnSpec->rCoordinate.len, spec->rCoordinate.len);
    EXPECT_EQ(memcmp(returnSpec->rCoordinate.data, spec->rCoordinate.data, spec->rCoordinate.len), 0);
    EXPECT_EQ(returnSpec->sCoordinate.len, spec->sCoordinate.len);
    EXPECT_EQ(memcmp(returnSpec->sCoordinate.data, spec->sCoordinate.data, spec->sCoordinate.len), 0);

    // Free allocated resources
    HcfBlobDataFree(&derOutput);
    DestroySm2EcSignatureSpec(returnSpec);
    HcfFree(spec);
}

HWTEST_F(CryptoSm2EcdsaSignature, HcfSm2SpecToDerData_NullInput, TestSize.Level0)
{
    HcfBlob derOutput = { .data = nullptr, .len = 0 };
    EXPECT_EQ(HcfSm2SpecToDerData(nullptr, &derOutput), HCF_ERR_PARAMETER_CHECK_FAILED);
}

HWTEST_F(CryptoSm2EcdsaSignature, HcfSm2SpecToDerData_NullOutput, TestSize.Level0)
{
    Sm2EcSignatureDataSpec *spec = nullptr;
    ASSERT_EQ(ConstructCorrectSm2Spec(&spec), HCF_SUCCESS);
    EXPECT_EQ(HcfSm2SpecToDerData(spec, nullptr), HCF_ERR_PARAMETER_CHECK_FAILED);
    HcfFree(spec);
}

HWTEST_F(CryptoSm2EcdsaSignature, HcfDerDataToSm2Spec_NullInput, TestSize.Level0)
{
    Sm2EcSignatureDataSpec *returnSpec = nullptr;
    EXPECT_EQ(HcfDerDataToSm2Spec(nullptr, &returnSpec), HCF_ERR_PARAMETER_CHECK_FAILED);
}

HWTEST_F(CryptoSm2EcdsaSignature, HcfDerDataToSm2Spec_NullOutput, TestSize.Level0)
{
    HcfBlob derInput = { .data = g_rCoordinate, .len = sizeof(g_rCoordinate) };
    EXPECT_EQ(HcfDerDataToSm2Spec(&derInput, nullptr), HCF_ERR_PARAMETER_CHECK_FAILED);
}

HWTEST_F(CryptoSm2EcdsaSignature, HcfDerDataToSm2Spec_InvalidData, TestSize.Level0)
{
    unsigned char invalidData[] = { 0x00, 0x01, 0x02, 0x03 };
    HcfBlob derInput = { .data = invalidData, .len = sizeof(invalidData) };
    Sm2EcSignatureDataSpec *returnSpec = nullptr;
    EXPECT_EQ(HcfDerDataToSm2Spec(&derInput, &returnSpec), HCF_ERR_CRYPTO_OPERATION);
}

}