/*
 * Copyright (c) 2026-2026 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include "interfaces/innerkits/qrcode_rscode.h"
#include <gtest/gtest.h>
#include <cstring>
#include "securec.h"

using namespace testing::ext;

class QrcodeRscodeTest : public testing::Test {
public:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp();
    void TearDown();
};

void QrcodeRscodeTest::SetUpTestCase(void) {}

void QrcodeRscodeTest::TearDownTestCase(void) {}

void QrcodeRscodeTest::SetUp(void) {}

void QrcodeRscodeTest::TearDown(void) {}

/**
 * @tc.name: qrcode_rscode_init_001
 * @tc.desc: Verify initializing Reed-Solomon code.
 * @tc.type: FUNC
 * @tc.require: issueI000006
 */
HWTEST_F(QrcodeRscodeTest, qrcode_rscode_init_001, TestSize.Level1)
{
    ReedSolomonCodeData codeData = {8, 0x11d, 1, 1, 10, 0};
    ReedSolomonCode *rsCode = ReedSolomonCodeInit(codeData);
    EXPECT_NE(rsCode, nullptr);
    if (rsCode != nullptr) {
        ReedSolomonCodeFree(rsCode);
    }
}

/**
 * @tc.name: qrcode_rscode_encode_002
 * @tc.desc: Verify encoding with Reed-Solomon code.
 * @tc.type: FUNC
 * @tc.require: issueI000006
 */
HWTEST_F(QrcodeRscodeTest, qrcode_rscode_encode_002, TestSize.Level1)
{
    ReedSolomonCodeData codeData = {8, 0x11d, 1, 1, 10, 0};
    ReedSolomonCode *rsCode = ReedSolomonCodeInit(codeData);
    EXPECT_NE(rsCode, nullptr);
    if (rsCode != nullptr) {
        uint8_t data[10] = {0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A};
        uint8_t parity[10] = {0};
        ReedSolomonCodeEncode(rsCode, data, parity);
        ReedSolomonCodeFree(rsCode);
    }
}

/**
 * @tc.name: qrcode_rscode_free_null_003
 * @tc.desc: Verify freeing null Reed-Solomon code.
 * @tc.type: FUNC
 * @tc.require: issueI000006
 */
HWTEST_F(QrcodeRscodeTest, qrcode_rscode_free_null_003, TestSize.Level1)
{
    ReedSolomonCodeFree(nullptr);
}

/**
 * @tc.name: qrcode_rscode_free_cache_004
 * @tc.desc: Verify freeing Reed-Solomon cache.
 * @tc.type: FUNC
 * @tc.require: issueI000006
 */
HWTEST_F(QrcodeRscodeTest, qrcode_rscode_free_cache_004, TestSize.Level1)
{
    ReedSolomonCodeFreeCache();
}

/**
 * @tc.name: qrcode_rscode_init_different_params_005
 * @tc.desc: Verify initializing with different parameters.
 * @tc.type: FUNC
 * @tc.require: issueI000006
 */
HWTEST_F(QrcodeRscodeTest, qrcode_rscode_init_different_params_005, TestSize.Level1)
{
    ReedSolomonCodeData codeData = {8, 0x11d, 0, 1, 16, 0};
    ReedSolomonCode *rsCode = ReedSolomonCodeInit(codeData);
    EXPECT_NE(rsCode, nullptr);
    if (rsCode != nullptr) {
        ReedSolomonCodeFree(rsCode);
    }
}

/**
 * @tc.name: qrcode_rscode_encode_null_data_006
 * @tc.desc: Verify encoding with null data pointer.
 * @tc.type: FUNC
 * @tc.require: issueI000006
 */
HWTEST_F(QrcodeRscodeTest, qrcode_rscode_encode_null_data_006, TestSize.Level1)
{
    ReedSolomonCodeData codeData = {8, 0x11d, 1, 1, 10, 0};
    ReedSolomonCode *rsCode = ReedSolomonCodeInit(codeData);
    EXPECT_NE(rsCode, nullptr);
    if (rsCode != nullptr) {
        uint8_t parity[10] = {0};
        ReedSolomonCodeEncode(rsCode, nullptr, parity);
        ReedSolomonCodeFree(rsCode);
    }
}

/**
 * @tc.name: qrcode_rscode_encode_null_parity_007
 * @tc.desc: Verify encoding with null parity pointer.
 * @tc.type: FUNC
 * @tc.require: issueI000006
 */
HWTEST_F(QrcodeRscodeTest, qrcode_rscode_encode_null_parity_007, TestSize.Level1)
{
    ReedSolomonCodeData codeData = {8, 0x11d, 1, 1, 10, 0};
    ReedSolomonCode *rsCode = ReedSolomonCodeInit(codeData);
    EXPECT_NE(rsCode, nullptr);
    if (rsCode != nullptr) {
        uint8_t data[10] = {0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A};
        ReedSolomonCodeEncode(rsCode, data, nullptr);
        ReedSolomonCodeFree(rsCode);
    }
}

/**
 * @tc.name: qrcode_rscode_init_invalid_symsize_008
 * @tc.desc: Verify initializing with invalid symsize.
 * @tc.type: FUNC
 * @tc.require: issueI000006
 */
HWTEST_F(QrcodeRscodeTest, qrcode_rscode_init_invalid_symsize_008, TestSize.Level1)
{
    ReedSolomonCodeData codeData = {9, 0x11d, 1, 1, 10, 0};
    ReedSolomonCode *rsCode = ReedSolomonCodeInit(codeData);
    EXPECT_EQ(rsCode, nullptr);
}

/**
 * @tc.name: qrcode_rscode_init_invalid_fcr_009
 * @tc.desc: Verify initializing with invalid fcr.
 * @tc.type: FUNC
 * @tc.require: issueI000006
 */
HWTEST_F(QrcodeRscodeTest, qrcode_rscode_init_invalid_fcr_009, TestSize.Level1)
{
    ReedSolomonCodeData codeData = {8, 0x11d, 256, 1, 10, 0};
    ReedSolomonCode *rsCode = ReedSolomonCodeInit(codeData);
    EXPECT_EQ(rsCode, nullptr);
}

/**
 * @tc.name: qrcode_rscode_init_invalid_prim_010
 * @tc.desc: Verify initializing with invalid prim.
 * @tc.type: FUNC
 * @tc.require: issueI000006
 */
HWTEST_F(QrcodeRscodeTest, qrcode_rscode_init_invalid_prim_010, TestSize.Level1)
{
    ReedSolomonCodeData codeData = {8, 0x11d, 1, 256, 10, 0};
    ReedSolomonCode *rsCode = ReedSolomonCodeInit(codeData);
    EXPECT_EQ(rsCode, nullptr);
}

/**
 * @tc.name: qrcode_rscode_init_invalid_nroots_011
 * @tc.desc: Verify initializing with invalid nroots.
 * @tc.type: FUNC
 * @tc.require: issueI000006
 */
HWTEST_F(QrcodeRscodeTest, qrcode_rscode_init_invalid_nroots_011, TestSize.Level1)
{
    ReedSolomonCodeData codeData = {8, 0x11d, 1, 1, 256, 0};
    ReedSolomonCode *rsCode = ReedSolomonCodeInit(codeData);
    EXPECT_EQ(rsCode, nullptr);
}

/**
 * @tc.name: qrcode_rscode_init_invalid_pad_012
 * @tc.desc: Verify initializing with invalid pad.
 * @tc.type: FUNC
 * @tc.require: issueI000006
 */
HWTEST_F(QrcodeRscodeTest, qrcode_rscode_init_invalid_pad_012, TestSize.Level1)
{
    ReedSolomonCodeData codeData = {8, 0x11d, 1, 1, 10, 245};
    ReedSolomonCode *rsCode = ReedSolomonCodeInit(codeData);
    EXPECT_EQ(rsCode, nullptr);
}

/**
 * @tc.name: qrcode_rscode_init_different_gfpoly_013
 * @tc.desc: Verify initializing with different gfpoly.
 * @tc.type: FUNC
 * @tc.require: issueI000006
 */
HWTEST_F(QrcodeRscodeTest, qrcode_rscode_init_different_gfpoly_013, TestSize.Level1)
{
    ReedSolomonCodeData codeData = {8, 0x12d, 1, 1, 10, 0};
    ReedSolomonCode *rsCode = ReedSolomonCodeInit(codeData);
    EXPECT_NE(rsCode, nullptr);
    if (rsCode != nullptr) {
        ReedSolomonCodeFree(rsCode);
    }
}

/**
 * @tc.name: qrcode_rscode_encode_different_data_014
 * @tc.desc: Verify encoding with different data values.
 * @tc.type: FUNC
 * @tc.require: issueI000006
 */
HWTEST_F(QrcodeRscodeTest, qrcode_rscode_encode_different_data_014, TestSize.Level1)
{
    ReedSolomonCodeData codeData = {8, 0x11d, 1, 1, 10, 0};
    ReedSolomonCode *rsCode = ReedSolomonCodeInit(codeData);
    EXPECT_NE(rsCode, nullptr);
    if (rsCode != nullptr) {
        uint8_t data[10] = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF};
        uint8_t parity[10] = {0};
        ReedSolomonCodeEncode(rsCode, data, parity);
        ReedSolomonCodeFree(rsCode);
    }
}

/**
 * @tc.name: qrcode_rscode_encode_zero_data_015
 * @tc.desc: Verify encoding with zero data.
 * @tc.type: FUNC
 * @tc.require: issueI000006
 */
HWTEST_F(QrcodeRscodeTest, qrcode_rscode_encode_zero_data_015, TestSize.Level1)
{
    ReedSolomonCodeData codeData = {8, 0x11d, 1, 1, 10, 0};
    ReedSolomonCode *rsCode = ReedSolomonCodeInit(codeData);
    EXPECT_NE(rsCode, nullptr);
    if (rsCode != nullptr) {
        uint8_t data[10] = {0};
        uint8_t parity[10] = {0};
        ReedSolomonCodeEncode(rsCode, data, parity);
        ReedSolomonCodeFree(rsCode);
    }
}

/**
 * @tc.name: qrcode_rscode_init_small_nroots_016
 * @tc.desc: Verify initializing with small nroots.
 * @tc.type: FUNC
 * @tc.require: issueI000006
 */
HWTEST_F(QrcodeRscodeTest, qrcode_rscode_init_small_nroots_016, TestSize.Level1)
{
    ReedSolomonCodeData codeData = {8, 0x11d, 1, 1, 1, 0};
    ReedSolomonCode *rsCode = ReedSolomonCodeInit(codeData);
    EXPECT_NE(rsCode, nullptr);
    if (rsCode != nullptr) {
        ReedSolomonCodeFree(rsCode);
    }
}

/**
 * @tc.name: qrcode_rscode_init_large_nroots_017
 * @tc.desc: Verify initializing with large nroots.
 * @tc.type: FUNC
 * @tc.require: issueI000006
 */
HWTEST_F(QrcodeRscodeTest, qrcode_rscode_init_large_nroots_017, TestSize.Level1)
{
    ReedSolomonCodeData codeData = {8, 0x11d, 1, 1, 100, 0};
    ReedSolomonCode *rsCode = ReedSolomonCodeInit(codeData);
    EXPECT_NE(rsCode, nullptr);
    if (rsCode != nullptr) {
        ReedSolomonCodeFree(rsCode);
    }
}

/**
 * @tc.name: qrcode_rscode_free_middle_of_list_019
 * @tc.desc: Verify freeing RS code from middle of list.
 * @tc.type: FUNC
 * @tc.require: issueI000006
 */
HWTEST_F(QrcodeRscodeTest, qrcode_rscode_free_middle_of_list_019, TestSize.Level1)
{
    ReedSolomonCodeData codeData1 = {8, 0x11d, 1, 1, 10, 0};
    ReedSolomonCodeData codeData2 = {8, 0x11d, 1, 1, 15, 0};
    ReedSolomonCodeData codeData3 = {8, 0x11d, 1, 1, 20, 0};
    ReedSolomonCode *rsCode1 = ReedSolomonCodeInit(codeData1);
    ReedSolomonCode *rsCode2 = ReedSolomonCodeInit(codeData2);
    ReedSolomonCode *rsCode3 = ReedSolomonCodeInit(codeData3);
    EXPECT_NE(rsCode1, nullptr);
    EXPECT_NE(rsCode2, nullptr);
    EXPECT_NE(rsCode3, nullptr);
    if (rsCode2 != nullptr) {
        ReedSolomonCodeFree(rsCode2);
    }
    if (rsCode1 != nullptr) {
        ReedSolomonCodeFree(rsCode1);
    }
    if (rsCode3 != nullptr) {
        ReedSolomonCodeFree(rsCode3);
    }
}

/**
 * @tc.name: qrcode_rscode_encode_with_feedback_020
 * @tc.desc: Verify encoding with non-zero feedback.
 * @tc.type: FUNC
 * @tc.require: issueI000006
 */
HWTEST_F(QrcodeRscodeTest, qrcode_rscode_encode_with_feedback_020, TestSize.Level1)
{
    ReedSolomonCodeData codeData = {8, 0x11d, 1, 1, 10, 0};
    ReedSolomonCode *rsCode = ReedSolomonCodeInit(codeData);
    EXPECT_NE(rsCode, nullptr);
    if (rsCode != nullptr) {
        uint8_t data[10] = {0xFF, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09};
        uint8_t parity[10] = {0};
        ReedSolomonCodeEncode(rsCode, data, parity);
        ReedSolomonCodeFree(rsCode);
    }
}

/**
 * @tc.name: qrcode_rscode_encode_max_data_021
 * @tc.desc: Verify encoding with maximum data size.
 * @tc.type: FUNC
 * @tc.require: issueI000006
 */
HWTEST_F(QrcodeRscodeTest, qrcode_rscode_encode_max_data_021, TestSize.Level1)
{
    ReedSolomonCodeData codeData = {8, 0x11d, 1, 1, 10, 0};
    ReedSolomonCode *rsCode = ReedSolomonCodeInit(codeData);
    EXPECT_NE(rsCode, nullptr);
    if (rsCode != nullptr) {
        uint8_t data[245] = {0};
        uint8_t parity[10] = {0};
        memset_s(data, sizeof(data), 0xFF, sizeof(data));
        ReedSolomonCodeEncode(rsCode, data, parity);
        ReedSolomonCodeFree(rsCode);
    }
}

/**
 * @tc.name: qrcode_rscode_init_cache_hit_022
 * @tc.desc: Verify cache hit when initializing same parameters.
 * @tc.type: FUNC
 * @tc.require: issueI000006
 */
HWTEST_F(QrcodeRscodeTest, qrcode_rscode_init_cache_hit_022, TestSize.Level1)
{
    ReedSolomonCodeData codeData = {8, 0x11d, 1, 1, 10, 0};
    ReedSolomonCode *rsCode1 = ReedSolomonCodeInit(codeData);
    ReedSolomonCode *rsCode2 = ReedSolomonCodeInit(codeData);
    EXPECT_NE(rsCode1, nullptr);
    EXPECT_NE(rsCode2, nullptr);
    EXPECT_EQ(rsCode1, rsCode2);
    if (rsCode1 != nullptr) {
        ReedSolomonCodeFree(rsCode1);
    }
}

/**
 * @tc.name: qrcode_rscode_init_different_gfpoly_023
 * @tc.desc: Verify initializing with different gfpoly.
 * @tc.type: FUNC
 * @tc.require: issueI000006
 */
HWTEST_F(QrcodeRscodeTest, qrcode_rscode_init_different_gfpoly_023, TestSize.Level1)
{
    ReedSolomonCodeData codeData1 = {8, 0x11d, 1, 1, 10, 0};
    ReedSolomonCodeData codeData2 = {8, 0x12d, 1, 1, 10, 0};
    ReedSolomonCode *rsCode1 = ReedSolomonCodeInit(codeData1);
    ReedSolomonCode *rsCode2 = ReedSolomonCodeInit(codeData2);
    EXPECT_NE(rsCode1, nullptr);
    EXPECT_NE(rsCode2, nullptr);
    EXPECT_NE(rsCode1, rsCode2);
    if (rsCode1 != nullptr) {
        ReedSolomonCodeFree(rsCode1);
    }
    if (rsCode2 != nullptr) {
        ReedSolomonCodeFree(rsCode2);
    }
}

/**
 * @tc.name: qrcode_rscode_encode_alternating_data_024
 * @tc.desc: Verify encoding with alternating data pattern.
 * @tc.type: FUNC
 * @tc.require: issueI000006
 */
HWTEST_F(QrcodeRscodeTest, qrcode_rscode_encode_alternating_data_024, TestSize.Level1)
{
    ReedSolomonCodeData codeData = {8, 0x11d, 1, 1, 10, 0};
    ReedSolomonCode *rsCode = ReedSolomonCodeInit(codeData);
    EXPECT_NE(rsCode, nullptr);
    if (rsCode != nullptr) {
        uint8_t data[10] = {0xAA, 0x55, 0xAA, 0x55, 0xAA, 0x55, 0xAA, 0x55, 0xAA, 0x55};
        uint8_t parity[10] = {0};
        ReedSolomonCodeEncode(rsCode, data, parity);
        ReedSolomonCodeFree(rsCode);
    }
}

/**
 * @tc.name: qrcode_rscode_init_invalid_gfpoly_025
 * @tc.desc: Verify initializing with invalid gfpoly (sr != 1).
 * @tc.type: FUNC
 * @tc.require: issueI000006
 */
HWTEST_F(QrcodeRscodeTest, qrcode_rscode_init_invalid_gfpoly_025, TestSize.Level1)
{
    ReedSolomonCodeData codeData = {8, 0x100, 1, 1, 10, 0};
    ReedSolomonCode *rsCode = ReedSolomonCodeInit(codeData);
    EXPECT_EQ(rsCode, nullptr);
}

/**
 * @tc.name: qrcode_rscode_init_negative_symsize_026
 * @tc.desc: Verify initializing with negative symsize.
 * @tc.type: FUNC
 * @tc.require: issueI000006
 */
HWTEST_F(QrcodeRscodeTest, qrcode_rscode_init_negative_symsize_026, TestSize.Level1)
{
    ReedSolomonCodeData codeData = {-1, 0x11d, 1, 1, 10, 0};
    ReedSolomonCode *rsCode = ReedSolomonCodeInit(codeData);
    EXPECT_EQ(rsCode, nullptr);
}

/**
 * @tc.name: qrcode_rscode_init_negative_fcr_027
 * @tc.desc: Verify initializing with negative fcr.
 * @tc.type: FUNC
 * @tc.require: issueI000006
 */
HWTEST_F(QrcodeRscodeTest, qrcode_rscode_init_negative_fcr_027, TestSize.Level1)
{
    ReedSolomonCodeData codeData = {8, 0x11d, -1, 1, 10, 0};
    ReedSolomonCode *rsCode = ReedSolomonCodeInit(codeData);
    EXPECT_EQ(rsCode, nullptr);
}

/**
 * @tc.name: qrcode_rscode_init_zero_prim_028
 * @tc.desc: Verify initializing with zero prim.
 * @tc.type: FUNC
 * @tc.require: issueI000006
 */
HWTEST_F(QrcodeRscodeTest, qrcode_rscode_init_zero_prim_028, TestSize.Level1)
{
    ReedSolomonCodeData codeData = {8, 0x11d, 1, 0, 10, 0};
    ReedSolomonCode *rsCode = ReedSolomonCodeInit(codeData);
    EXPECT_EQ(rsCode, nullptr);
}

/**
 * @tc.name: qrcode_rscode_init_negative_nroots_029
 * @tc.desc: Verify initializing with negative nroots.
 * @tc.type: FUNC
 * @tc.require: issueI000006
 */
HWTEST_F(QrcodeRscodeTest, qrcode_rscode_init_negative_nroots_029, TestSize.Level1)
{
    ReedSolomonCodeData codeData = {8, 0x11d, 1, 1, -1, 0};
    ReedSolomonCode *rsCode = ReedSolomonCodeInit(codeData);
    EXPECT_EQ(rsCode, nullptr);
}

/**
 * @tc.name: qrcode_rscode_init_negative_pad_030
 * @tc.desc: Verify initializing with negative pad.
 * @tc.type: FUNC
 * @tc.require: issueI000006
 */
HWTEST_F(QrcodeRscodeTest, qrcode_rscode_init_negative_pad_030, TestSize.Level1)
{
    ReedSolomonCodeData codeData = {8, 0x11d, 1, 1, 10, -1};
    ReedSolomonCode *rsCode = ReedSolomonCodeInit(codeData);
    EXPECT_EQ(rsCode, nullptr);
}

/**
 * @tc.name: qrcode_rscode_init_max_pad_031
 * @tc.desc: Verify initializing with maximum valid pad.
 * @tc.type: FUNC
 * @tc.require: issueI000006
 */
HWTEST_F(QrcodeRscodeTest, qrcode_rscode_init_max_pad_031, TestSize.Level1)
{
    ReedSolomonCodeData codeData = {8, 0x11d, 1, 1, 10, 244};
    ReedSolomonCode *rsCode = ReedSolomonCodeInit(codeData);
    EXPECT_NE(rsCode, nullptr);
    if (rsCode != nullptr) {
        ReedSolomonCodeFree(rsCode);
    }
}

/**
 * @tc.name: qrcode_rscode_free_multiple_from_list_032
 * @tc.desc: Verify freeing multiple RS codes from list.
 * @tc.type: FUNC
 * @tc.require: issueI000006
 */
HWTEST_F(QrcodeRscodeTest, qrcode_rscode_free_multiple_from_list_032, TestSize.Level1)
{
    ReedSolomonCodeData codeData1 = {8, 0x11d, 1, 1, 10, 0};
    ReedSolomonCodeData codeData2 = {8, 0x11d, 1, 1, 15, 0};
    ReedSolomonCodeData codeData3 = {8, 0x11d, 1, 1, 20, 0};
    ReedSolomonCode *rsCode1 = ReedSolomonCodeInit(codeData1);
    ReedSolomonCode *rsCode2 = ReedSolomonCodeInit(codeData2);
    ReedSolomonCode *rsCode3 = ReedSolomonCodeInit(codeData3);
    EXPECT_NE(rsCode1, nullptr);
    EXPECT_NE(rsCode2, nullptr);
    EXPECT_NE(rsCode3, nullptr);
    if (rsCode3 != nullptr) {
        ReedSolomonCodeFree(rsCode3);
    }
    if (rsCode1 != nullptr) {
        ReedSolomonCodeFree(rsCode1);
    }
    if (rsCode2 != nullptr) {
        ReedSolomonCodeFree(rsCode2);
    }
}

/**
 * @tc.name: qrcode_rscode_init_cache_different_params_033
 * @tc.desc: Verify cache miss with different parameters.
 * @tc.type: FUNC
 * @tc.require: issueI000006
 */
HWTEST_F(QrcodeRscodeTest, qrcode_rscode_init_cache_different_params_033, TestSize.Level1)
{
    ReedSolomonCodeData codeData1 = {8, 0x11d, 1, 1, 10, 0};
    ReedSolomonCodeData codeData2 = {8, 0x11d, 0, 1, 10, 0};
    ReedSolomonCode *rsCode1 = ReedSolomonCodeInit(codeData1);
    ReedSolomonCode *rsCode2 = ReedSolomonCodeInit(codeData2);
    EXPECT_NE(rsCode1, nullptr);
    EXPECT_NE(rsCode2, nullptr);
    EXPECT_NE(rsCode1, rsCode2);
    if (rsCode1 != nullptr) {
        ReedSolomonCodeFree(rsCode1);
    }
    if (rsCode2 != nullptr) {
        ReedSolomonCodeFree(rsCode2);
    }
}

/**
 * @tc.name: qrcode_rscode_init_cache_different_nroots_034
 * @tc.desc: Verify cache miss with different nroots.
 * @tc.type: FUNC
 * @tc.require: issueI000006
 */
HWTEST_F(QrcodeRscodeTest, qrcode_rscode_init_cache_different_nroots_034, TestSize.Level1)
{
    ReedSolomonCodeData codeData1 = {8, 0x11d, 1, 1, 10, 0};
    ReedSolomonCodeData codeData2 = {8, 0x11d, 1, 1, 15, 0};
    ReedSolomonCode *rsCode1 = ReedSolomonCodeInit(codeData1);
    ReedSolomonCode *rsCode2 = ReedSolomonCodeInit(codeData2);
    EXPECT_NE(rsCode1, nullptr);
    EXPECT_NE(rsCode2, nullptr);
    EXPECT_NE(rsCode1, rsCode2);
    if (rsCode1 != nullptr) {
        ReedSolomonCodeFree(rsCode1);
    }
    if (rsCode2 != nullptr) {
        ReedSolomonCodeFree(rsCode2);
    }
}

/**
 * @tc.name: qrcode_rscode_init_cache_different_pad_035
 * @tc.desc: Verify cache miss with different pad.
 * @tc.type: FUNC
 * @tc.require: issueI000006
 */
HWTEST_F(QrcodeRscodeTest, qrcode_rscode_init_cache_different_pad_035, TestSize.Level1)
{
    ReedSolomonCodeData codeData1 = {8, 0x11d, 1, 1, 10, 0};
    ReedSolomonCodeData codeData2 = {8, 0x11d, 1, 1, 10, 1};
    ReedSolomonCode *rsCode1 = ReedSolomonCodeInit(codeData1);
    ReedSolomonCode *rsCode2 = ReedSolomonCodeInit(codeData2);
    EXPECT_NE(rsCode1, nullptr);
    EXPECT_NE(rsCode2, nullptr);
    EXPECT_NE(rsCode1, rsCode2);
    if (rsCode1 != nullptr) {
        ReedSolomonCodeFree(rsCode1);
    }
    if (rsCode2 != nullptr) {
        ReedSolomonCodeFree(rsCode2);
    }
}

/**
 * @tc.name: qrcode_rscode_init_cache_different_prim_036
 * @tc.desc: Verify cache miss with different prim.
 * @tc.type: FUNC
 * @tc.require: issueI000006
 */
HWTEST_F(QrcodeRscodeTest, qrcode_rscode_init_cache_different_prim_036, TestSize.Level1)
{
    ReedSolomonCodeData codeData1 = {8, 0x11d, 1, 1, 10, 0};
    ReedSolomonCodeData codeData2 = {8, 0x11d, 1, 3, 10, 0};
    ReedSolomonCode *rsCode1 = ReedSolomonCodeInit(codeData1);
    ReedSolomonCode *rsCode2 = ReedSolomonCodeInit(codeData2);
    EXPECT_NE(rsCode1, nullptr);
    EXPECT_NE(rsCode2, nullptr);
    EXPECT_NE(rsCode1, rsCode2);
    if (rsCode1 != nullptr) {
        ReedSolomonCodeFree(rsCode1);
    }
    if (rsCode2 != nullptr) {
        ReedSolomonCodeFree(rsCode2);
    }
}

/**
 * @tc.name: qrcode_rscode_init_cache_different_fcr_037
 * @tc.desc: Verify cache miss with different fcr.
 * @tc.type: FUNC
 * @tc.require: issueI000006
 */
HWTEST_F(QrcodeRscodeTest, qrcode_rscode_init_cache_different_fcr_037, TestSize.Level1)
{
    ReedSolomonCodeData codeData1 = {8, 0x11d, 1, 1, 10, 0};
    ReedSolomonCodeData codeData2 = {8, 0x11d, 0, 1, 10, 0};
    ReedSolomonCode *rsCode1 = ReedSolomonCodeInit(codeData1);
    ReedSolomonCode *rsCode2 = ReedSolomonCodeInit(codeData2);
    EXPECT_NE(rsCode1, nullptr);
    EXPECT_NE(rsCode2, nullptr);
    EXPECT_NE(rsCode1, rsCode2);
    if (rsCode1 != nullptr) {
        ReedSolomonCodeFree(rsCode1);
    }
    if (rsCode2 != nullptr) {
        ReedSolomonCodeFree(rsCode2);
    }
}

/**
 * @tc.name: qrcode_rscode_encode_null_rscode_038
 * @tc.desc: Verify encoding with null rsCode pointer.
 * @tc.type: FUNC
 * @tc.require: issueI000006
 */
HWTEST_F(QrcodeRscodeTest, qrcode_rscode_encode_null_rscode_038, TestSize.Level1)
{
    uint8_t data[10] = {0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A};
    uint8_t parity[10] = {0};
    ReedSolomonCodeEncode(nullptr, data, parity);
}

/**
 * @tc.name: qrcode_rscode_encode_all_null_039
 * @tc.desc: Verify encoding with all null pointers.
 * @tc.type: FUNC
 * @tc.require: issueI000006
 */
HWTEST_F(QrcodeRscodeTest, qrcode_rscode_encode_all_null_039, TestSize.Level1)
{
    ReedSolomonCodeEncode(nullptr, nullptr, nullptr);
}

/**
 * @tc.name: qrcode_rscode_free_cache_multiple_040
 * @tc.desc: Verify freeing cache with multiple RS codes.
 * @tc.type: FUNC
 * @tc.require: issueI000006
 */
HWTEST_F(QrcodeRscodeTest, qrcode_rscode_free_cache_multiple_040, TestSize.Level1)
{
    ReedSolomonCodeData codeData1 = {8, 0x11d, 1, 1, 10, 0};
    ReedSolomonCodeData codeData2 = {8, 0x11d, 0, 1, 15, 0};
    ReedSolomonCodeData codeData3 = {8, 0x11d, 1, 3, 20, 0};
    ReedSolomonCodeInit(codeData1);
    ReedSolomonCodeInit(codeData2);
    ReedSolomonCodeInit(codeData3);
    ReedSolomonCodeFreeCache();
}

/**
 * @tc.name: qrcode_rscode_init_zero_symsize_041
 * @tc.desc: Verify initializing with zero symsize.
 * @tc.type: FUNC
 * @tc.require: issueI000006
 */
HWTEST_F(QrcodeRscodeTest, qrcode_rscode_init_zero_symsize_041, TestSize.Level1)
{
    ReedSolomonCodeData codeData = {0, 0x11d, 1, 1, 10, 0};
    ReedSolomonCode *rsCode = ReedSolomonCodeInit(codeData);
    EXPECT_EQ(rsCode, nullptr);
}

/**
 * @tc.name: qrcode_rscode_init_max_symsize_042
 * @tc.desc: Verify initializing with maximum symsize.
 * @tc.type: FUNC
 * @tc.require: issueI000006
 */
HWTEST_F(QrcodeRscodeTest, qrcode_rscode_init_max_symsize_042, TestSize.Level1)
{
    ReedSolomonCodeData codeData = {8, 0x11d, 1, 1, 10, 0};
    ReedSolomonCode *rsCode = ReedSolomonCodeInit(codeData);
    EXPECT_NE(rsCode, nullptr);
    if (rsCode != nullptr) {
        ReedSolomonCodeFree(rsCode);
    }
}

/**
 * @tc.name: qrcode_rscode_init_max_fcr_043
 * @tc.desc: Verify initializing with maximum valid fcr.
 * @tc.type: FUNC
 * @tc.require: issueI000006
 */
HWTEST_F(QrcodeRscodeTest, qrcode_rscode_init_max_fcr_043, TestSize.Level1)
{
    ReedSolomonCodeData codeData = {8, 0x11d, 255, 1, 10, 0};
    ReedSolomonCode *rsCode = ReedSolomonCodeInit(codeData);
    EXPECT_NE(rsCode, nullptr);
    if (rsCode != nullptr) {
        ReedSolomonCodeFree(rsCode);
    }
}

/**
 * @tc.name: qrcode_rscode_init_max_prim_044
 * @tc.desc: Verify initializing with maximum valid prim.
 * @tc.type: FUNC
 * @tc.require: issueI000006
 */
HWTEST_F(QrcodeRscodeTest, qrcode_rscode_init_max_prim_044, TestSize.Level1)
{
    ReedSolomonCodeData codeData = {8, 0x11d, 1, 255, 10, 0};
    ReedSolomonCode *rsCode = ReedSolomonCodeInit(codeData);
    EXPECT_NE(rsCode, nullptr);
    if (rsCode != nullptr) {
        ReedSolomonCodeFree(rsCode);
    }
}

/**
 * @tc.name: qrcode_rscode_init_max_nroots_045
 * @tc.desc: Verify initializing with maximum valid nroots.
 * @tc.type: FUNC
 * @tc.require: issueI000006
 */
HWTEST_F(QrcodeRscodeTest, qrcode_rscode_init_max_nroots_045, TestSize.Level1)
{
    ReedSolomonCodeData codeData = {8, 0x11d, 1, 1, 255, 0};
    ReedSolomonCode *rsCode = ReedSolomonCodeInit(codeData);
    EXPECT_EQ(rsCode, nullptr);  // nroots=255 exceeds maximum allowed value
}

/**
 * @tc.name: qrcode_rscode_init_cache_hit_all_params_046
 * @tc.desc: Verify cache hit with all same parameters.
 * @tc.type: FUNC
 * @tc.require: issueI000006
 */
HWTEST_F(QrcodeRscodeTest, qrcode_rscode_init_cache_hit_all_params_046, TestSize.Level1)
{
    ReedSolomonCodeData codeData = {8, 0x11d, 1, 1, 10, 0};
    ReedSolomonCode *rsCode1 = ReedSolomonCodeInit(codeData);
    ReedSolomonCode *rsCode2 = ReedSolomonCodeInit(codeData);
    ReedSolomonCode *rsCode3 = ReedSolomonCodeInit(codeData);
    EXPECT_NE(rsCode1, nullptr);
    EXPECT_NE(rsCode2, nullptr);
    EXPECT_NE(rsCode3, nullptr);
    EXPECT_EQ(rsCode1, rsCode2);
    EXPECT_EQ(rsCode2, rsCode3);
    if (rsCode1 != nullptr) {
        ReedSolomonCodeFree(rsCode1);
    }
}

/**
 * @tc.name: qrcode_rscode_free_middle_of_list_047
 * @tc.desc: Verify freeing RS code from middle of list (non-head).
 * @tc.type: FUNC
 * @tc.require: issueI000006
 */
HWTEST_F(QrcodeRscodeTest, qrcode_rscode_free_middle_of_list_047, TestSize.Level1)
{
    ReedSolomonCodeData codeData1 = {8, 0x11d, 1, 1, 10, 0};
    ReedSolomonCodeData codeData2 = {8, 0x11d, 1, 1, 15, 0};
    ReedSolomonCodeData codeData3 = {8, 0x11d, 1, 1, 20, 0};
    ReedSolomonCode *rsCode1 = ReedSolomonCodeInit(codeData1);
    ReedSolomonCode *rsCode2 = ReedSolomonCodeInit(codeData2);
    ReedSolomonCode *rsCode3 = ReedSolomonCodeInit(codeData3);
    EXPECT_NE(rsCode1, nullptr);
    EXPECT_NE(rsCode2, nullptr);
    EXPECT_NE(rsCode3, nullptr);
    if (rsCode2 != nullptr) {
        ReedSolomonCodeFree(rsCode2);
    }
    if (rsCode1 != nullptr) {
        ReedSolomonCodeFree(rsCode1);
    }
    if (rsCode3 != nullptr) {
        ReedSolomonCodeFree(rsCode3);
    }
}

/**
 * @tc.name: qrcode_rscode_free_tail_of_list_048
 * @tc.desc: Verify freeing RS code from tail of list.
 * @tc.type: FUNC
 * @tc.require: issueI000006
 */
HWTEST_F(QrcodeRscodeTest, qrcode_rscode_free_tail_of_list_048, TestSize.Level1)
{
    ReedSolomonCodeData codeData1 = {8, 0x11d, 1, 1, 10, 0};
    ReedSolomonCodeData codeData2 = {8, 0x11d, 1, 1, 15, 0};
    ReedSolomonCodeData codeData3 = {8, 0x11d, 1, 1, 20, 0};
    ReedSolomonCode *rsCode1 = ReedSolomonCodeInit(codeData1);
    ReedSolomonCode *rsCode2 = ReedSolomonCodeInit(codeData2);
    ReedSolomonCode *rsCode3 = ReedSolomonCodeInit(codeData3);
    EXPECT_NE(rsCode1, nullptr);
    EXPECT_NE(rsCode2, nullptr);
    EXPECT_NE(rsCode3, nullptr);
    if (rsCode3 != nullptr) {
        ReedSolomonCodeFree(rsCode3);
    }
    if (rsCode2 != nullptr) {
        ReedSolomonCodeFree(rsCode2);
    }
    if (rsCode1 != nullptr) {
        ReedSolomonCodeFree(rsCode1);
    }
}

/**
 * @tc.name: qrcode_rscode_free_head_of_list_049
 * @tc.desc: Verify freeing RS code from head of list.
 * @tc.type: FUNC
 * @tc.require: issueI000006
 */
HWTEST_F(QrcodeRscodeTest, qrcode_rscode_free_head_of_list_049, TestSize.Level1)
{
    ReedSolomonCodeData codeData1 = {8, 0x11d, 1, 1, 10, 0};
    ReedSolomonCodeData codeData2 = {8, 0x11d, 1, 1, 15, 0};
    ReedSolomonCodeData codeData3 = {8, 0x11d, 1, 1, 20, 0};
    ReedSolomonCode *rsCode1 = ReedSolomonCodeInit(codeData1);
    ReedSolomonCode *rsCode2 = ReedSolomonCodeInit(codeData2);
    ReedSolomonCode *rsCode3 = ReedSolomonCodeInit(codeData3);
    EXPECT_NE(rsCode1, nullptr);
    EXPECT_NE(rsCode2, nullptr);
    EXPECT_NE(rsCode3, nullptr);
    if (rsCode1 != nullptr) {
        ReedSolomonCodeFree(rsCode1);
    }
    if (rsCode2 != nullptr) {
        ReedSolomonCodeFree(rsCode2);
    }
    if (rsCode3 != nullptr) {
        ReedSolomonCodeFree(rsCode3);
    }
}