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

#include "key_utils.h"
#include "ecc_key_util.h"

#include <gtest/gtest.h>
#include "blob.h"
#include "memory.h"
#include "memory_mock.h"
#include "openssl_common.h"
#include "detailed_ecc_key_params.h"
#include "ecc_common.h"
#include "ecc_openssl_common_param_spec.h"

using namespace std;
using namespace testing::ext;

namespace {
class CryptoKeyUtilsTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp();
    void TearDown();
};

void CryptoKeyUtilsTest::SetUpTestCase() {}
void CryptoKeyUtilsTest::TearDownTestCase() {}
void CryptoKeyUtilsTest::SetUp() {}
void CryptoKeyUtilsTest::TearDown() {}

static const bool IS_BIG_ENDIAN = IsBigEndian();

static HcfResult ConstructEcc224CommParamsSpec(HcfEccCommParamsSpec **spec)
{
    HcfEccCommParamsSpec *eccCommSpec =
        reinterpret_cast<HcfEccCommParamsSpec *>(HcfMalloc(sizeof(HcfEccCommParamsSpec), 0));
    if (eccCommSpec == nullptr) {
        return HCF_ERR_MALLOC;
    }
    HcfECFieldFp *tmpField = reinterpret_cast<HcfECFieldFp *>(HcfMalloc(sizeof(HcfECFieldFp), 0));
    if (tmpField == nullptr) {
        HcfFree(eccCommSpec);
        return HCF_ERR_MALLOC;
    }

    eccCommSpec->base.algName = const_cast<char *>(g_eccAlgName.c_str());
    eccCommSpec->base.specType = HCF_COMMON_PARAMS_SPEC;
    eccCommSpec->field = reinterpret_cast<HcfECField *>(tmpField);
    eccCommSpec->field->fieldType = const_cast<char *>(g_eccFieldType.c_str());
    ((HcfECFieldFp *)(eccCommSpec->field))->p.data = (IS_BIG_ENDIAN ? g_ecc224CorrectBigP : g_ecc224CorrectLittleP);
    ((HcfECFieldFp *)(eccCommSpec->field))->p.len = NID_secp224r1_len;
    eccCommSpec->a.data = (IS_BIG_ENDIAN ? g_ecc224CorrectBigA : g_ecc224CorrectLittleA);
    eccCommSpec->a.len = NID_secp224r1_len;
    eccCommSpec->b.data = (IS_BIG_ENDIAN ? g_ecc224CorrectBigB : g_ecc224CorrectLittleB);
    eccCommSpec->b.len = NID_secp224r1_len;
    eccCommSpec->g.x.data = (IS_BIG_ENDIAN ? g_ecc224CorrectBigGX : g_ecc224CorrectLittleGX);
    eccCommSpec->g.x.len = NID_secp224r1_len;
    eccCommSpec->g.y.data = (IS_BIG_ENDIAN ? g_ecc224CorrectBigGY : g_ecc224CorrectLittleGY);
    eccCommSpec->g.y.len = NID_secp224r1_len;
    eccCommSpec->n.data = (IS_BIG_ENDIAN ? g_ecc224CorrectBigN : g_ecc224CorrectLittleN);
    eccCommSpec->n.len = NID_secp224r1_len;
    eccCommSpec->h = g_ecc224CorrectH;

    *spec = eccCommSpec;
    return HCF_SUCCESS;
}

HWTEST_F(CryptoKeyUtilsTest, CryptoKeyUtilsTest01, TestSize.Level0)
{
    HcfResult ret = CopyAsyKeyParamsSpec(nullptr, nullptr);
    EXPECT_EQ(ret, HCF_INVALID_PARAMS);
}

HWTEST_F(CryptoKeyUtilsTest, CryptoKeyUtilsTest02, TestSize.Level0)
{
    HcfEccCommParamsSpec *srcSpec = nullptr;
    HcfResult ret = ConstructEcc224CommParamsSpec(&srcSpec);
    EXPECT_EQ(ret, HCF_SUCCESS);

    ret = CopyPoint(&(srcSpec->g), nullptr);
    EXPECT_EQ(ret, HCF_INVALID_PARAMS);
    HcfFree(srcSpec->field);
    HcfFree(srcSpec);
}

HWTEST_F(CryptoKeyUtilsTest, CryptoKeyUtilsTest03, TestSize.Level0)
{
    HcfEccCommParamsSpec *srcSpec = nullptr;
    HcfResult ret = ConstructEcc224CommParamsSpec(&srcSpec);
    EXPECT_EQ(ret, HCF_SUCCESS);

    ret = CopyEccCommonSpec(srcSpec, nullptr);
    EXPECT_EQ(ret, HCF_INVALID_PARAMS);
    HcfFree(srcSpec->field);
    HcfFree(srcSpec);
}

HWTEST_F(CryptoKeyUtilsTest, CryptoKeyUtilsTest04, TestSize.Level0)
{
    HcfEccCommParamsSpec *srcSpec = nullptr;
    HcfResult ret = ConstructEcc224CommParamsSpec(&srcSpec);
    EXPECT_EQ(ret, HCF_SUCCESS);

    ret = CreateEccCommonSpecImpl(srcSpec, nullptr);
    EXPECT_EQ(ret, HCF_INVALID_PARAMS);
    HcfFree(srcSpec->field);
    HcfFree(srcSpec);
}

HWTEST_F(CryptoKeyUtilsTest, CryptoKeyUtilsTest05, TestSize.Level0)
{
    HcfResult ret = CopyDhCommonSpec(nullptr, nullptr);
    EXPECT_EQ(ret, HCF_INVALID_PARAMS);
}

HWTEST_F(CryptoKeyUtilsTest, CryptoKeyUtilsTest06, TestSize.Level0)
{
    HcfResult ret = CreateDhCommonSpecImpl(nullptr, nullptr);
    EXPECT_EQ(ret, HCF_INVALID_PARAMS);
}

HWTEST_F(CryptoKeyUtilsTest, CryptoKeyUtilsTest07, TestSize.Level0)
{
    HcfBlob dataBlob = { .data = nullptr, .len = 0 };
    const char *curveName = nullptr;
    HcfResult ret = HcfConvertPoint(curveName, &dataBlob, nullptr);
    EXPECT_EQ(ret, HCF_INVALID_PARAMS);
}

HWTEST_F(CryptoKeyUtilsTest, CryptoKeyUtilsTest08, TestSize.Level0)
{
    HcfBlob dataBlob = { .data = nullptr, .len = 0 };
    const char *curveName = nullptr;
    HcfResult ret = HcfGetEncodedPoint(curveName, nullptr, nullptr, &dataBlob);
    EXPECT_EQ(ret, HCF_INVALID_PARAMS);
}
}