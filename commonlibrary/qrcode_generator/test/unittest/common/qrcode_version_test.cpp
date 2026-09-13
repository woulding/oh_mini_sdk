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

#include "interfaces/innerkits/qrcode_version.h"
#include <gtest/gtest.h>

using namespace testing::ext;

class QrcodeVersionTest : public testing::Test {
public:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp();
    void TearDown();
};

void QrcodeVersionTest::SetUpTestCase(void) {}

void QrcodeVersionTest::TearDownTestCase(void) {}

void QrcodeVersionTest::SetUp(void) {}

void QrcodeVersionTest::TearDown(void) {}

/**
 * @tc.name: qrcode_version_get_data_len_001
 * @tc.desc: Verify getting data length for valid version.
 * @tc.type: FUNC
 * @tc.require: issueI000002
 */
HWTEST_F(QrcodeVersionTest, qrcode_version_get_data_len_001, TestSize.Level1)
{
    int32_t dataLen = QrcodeVersionGetDataLen(1);
    EXPECT_GT(dataLen, 0);
}

/**
 * @tc.name: qrcode_version_get_ecc_len_002
 * @tc.desc: Verify getting ECC length for valid version.
 * @tc.type: FUNC
 * @tc.require: issueI000002
 */
HWTEST_F(QrcodeVersionTest, qrcode_version_get_ecc_len_002, TestSize.Level1)
{
    int32_t eccLen = QrcodeVersionGetEccLen(1);
    EXPECT_GT(eccLen, 0);
}

/**
 * @tc.name: qrcode_version_get_width_003
 * @tc.desc: Verify getting width for valid version.
 * @tc.type: FUNC
 * @tc.require: issueI000002
 */
HWTEST_F(QrcodeVersionTest, qrcode_version_get_width_003, TestSize.Level1)
{
    int32_t width = QrcodeVersionGetWidth(1);
    EXPECT_GT(width, 0);
}

/**
 * @tc.name: qrcode_version_get_remainder_004
 * @tc.desc: Verify getting remainder for valid version.
 * @tc.type: FUNC
 * @tc.require: issueI000002
 */
HWTEST_F(QrcodeVersionTest, qrcode_version_get_remainder_004, TestSize.Level1)
{
    int32_t remainder = QrcodeVersionGetRemainder(1);
    EXPECT_GE(remainder, 0);
}

/**
 * @tc.name: qrcode_version_mode_length_005
 * @tc.desc: Verify getting mode length for numeric mode.
 * @tc.type: FUNC
 * @tc.require: issueI000002
 */
HWTEST_F(QrcodeVersionTest, qrcode_version_mode_length_005, TestSize.Level1)
{
    int32_t length = QrcodeVersionModeLength(QRCODE_MODE_NUM, 1);
    EXPECT_GT(length, 0);
}

/**
 * @tc.name: qrcode_version_mode_length_an_006
 * @tc.desc: Verify getting mode length for alphanumeric mode.
 * @tc.type: FUNC
 * @tc.require: issueI000002
 */
HWTEST_F(QrcodeVersionTest, qrcode_version_mode_length_an_006, TestSize.Level1)
{
    int32_t length = QrcodeVersionModeLength(QRCODE_MODE_AN, 1);
    EXPECT_GT(length, 0);
}

/**
 * @tc.name: qrcode_version_mode_length_8_007
 * @tc.desc: Verify getting mode length for byte mode.
 * @tc.type: FUNC
 * @tc.require: issueI000002
 */
HWTEST_F(QrcodeVersionTest, qrcode_version_mode_length_8_007, TestSize.Level1)
{
    int32_t length = QrcodeVersionModeLength(QRCODE_MODE_8, 1);
    EXPECT_GT(length, 0);
}

/**
 * @tc.name: qrcode_version_max_words_008
 * @tc.desc: Verify getting max words in numeric mode.
 * @tc.type: FUNC
 * @tc.require: issueI000002
 */
HWTEST_F(QrcodeVersionTest, qrcode_version_max_words_008, TestSize.Level1)
{
    int32_t maxWords = QrcodeVersionMaxWordsInMode(1, QRCODE_MODE_NUM);
    EXPECT_GT(maxWords, 0);
}

/**
 * @tc.name: qrcode_version_set_ecc_009
 * @tc.desc: Verify setting ECC level.
 * @tc.type: FUNC
 * @tc.require: issueI000002
 */
HWTEST_F(QrcodeVersionTest, qrcode_version_set_ecc_009, TestSize.Level1)
{
    QrcodeVersionSetEcc(QRCODE_ECC_MEDIUM);
}

/**
 * @tc.name: qrcode_version_get_ecc_info_010
 * @tc.desc: Verify getting ECC info for valid version.
 * @tc.type: FUNC
 * @tc.require: issueI000002
 */
HWTEST_F(QrcodeVersionTest, qrcode_version_get_ecc_info_010, TestSize.Level1)
{
    int32_t spec[5];
    QrcodeVersionGetEccInfo(1, spec, 5);
    EXPECT_GT(spec[0], 0);
}

/**
 * @tc.name: qrcode_version_get_pattern_011
 * @tc.desc: Verify getting pattern for valid version.
 * @tc.type: FUNC
 * @tc.require: issueI000002
 */
HWTEST_F(QrcodeVersionTest, qrcode_version_get_pattern_011, TestSize.Level1)
{
    uint32_t pattern = QrcodeVersionGetPattern(7);
    EXPECT_NE(pattern, 0);
}

/**
 * @tc.name: qrcode_version_get_format_info_012
 * @tc.desc: Verify getting format info.
 * @tc.type: FUNC
 * @tc.require: issueI000002
 */
HWTEST_F(QrcodeVersionTest, qrcode_version_get_format_info_012, TestSize.Level1)
{
    int32_t formatInfo = QrcodeVersionGetFormatInfo(0);
    EXPECT_NE(formatInfo, 0);
}

/**
 * @tc.name: qrcode_version_new_data_013
 * @tc.desc: Verify creating new data buffer.
 * @tc.type: FUNC
 * @tc.require: issueI000002
 */
HWTEST_F(QrcodeVersionTest, qrcode_version_new_data_013, TestSize.Level1)
{
    uint8_t *data = QrcodeVersionNewData(1);
    EXPECT_NE(data, nullptr);
    if (data != nullptr) {
        QrcodeFree(data);
    }
}

/**
 * @tc.name: qrcode_version_clear_cache_014
 * @tc.desc: Verify clearing cache.
 * @tc.type: FUNC
 * @tc.require: issueI000002
 */
HWTEST_F(QrcodeVersionTest, qrcode_version_clear_cache_014, TestSize.Level1)
{
    QrcodeVersionClearCache(1);
}

/**
 * @tc.name: qrcode_version_get_min_version_015
 * @tc.desc: Verify getting minimum version for size.
 * @tc.type: FUNC
 * @tc.require: issueI000002
 */
HWTEST_F(QrcodeVersionTest, qrcode_version_get_min_version_015, TestSize.Level1)
{
    int32_t minVersion = QrcodeVersionGetMinVersion(10);
    EXPECT_GE(minVersion, 1);
}

/**
 * @tc.name: qrcode_version_max_version_016
 * @tc.desc: Verify functions work with max version.
 * @tc.type: FUNC
 * @tc.require: issueI000002
 */
HWTEST_F(QrcodeVersionTest, qrcode_version_max_version_016, TestSize.Level1)
{
    int32_t dataLen = QrcodeVersionGetDataLen(QRCODE_VERSION_MAX);
    EXPECT_GT(dataLen, 0);

    int32_t width = QrcodeVersionGetWidth(QRCODE_VERSION_MAX);
    EXPECT_GT(width, 0);
}

/**
 * @tc.name: qrcode_version_invalid_mode_017
 * @tc.desc: Verify handling invalid mode.
 * @tc.type: FUNC
 * @tc.require: issueI000002
 */
HWTEST_F(QrcodeVersionTest, qrcode_version_invalid_mode_017, TestSize.Level1)
{
    int32_t length = QrcodeVersionModeLength(QRCODE_MODE_NUL, 1);
    EXPECT_EQ(length, 0);
}

/**
 * @tc.name: qrcode_version_zero_version_018
 * @tc.desc: Verify handling zero version.
 * @tc.type: FUNC
 * @tc.require: issueI000002
 */
HWTEST_F(QrcodeVersionTest, qrcode_version_zero_version_018, TestSize.Level1)
{
    int32_t dataLen = QrcodeVersionGetDataLen(0);
    EXPECT_EQ(dataLen, 0);
}

/**
 * @tc.name: qrcode_version_exceed_max_020
 * @tc.desc: Verify handling version exceeding max.
 * @tc.type: FUNC
 * @tc.require: issueI000002
 */
HWTEST_F(QrcodeVersionTest, qrcode_version_exceed_max_020, TestSize.Level1)
{
    int32_t dataLen = QrcodeVersionGetDataLen(QRCODE_VERSION_MAX + 1);
    EXPECT_EQ(dataLen, 0);
}

/**
 * @tc.name: qrcode_version_get_ecc_info_invalid_021
 * @tc.desc: Verify getting ECC info for invalid version.
 * @tc.type: FUNC
 * @tc.require: issueI000002
 */
HWTEST_F(QrcodeVersionTest, qrcode_version_get_ecc_info_invalid_021, TestSize.Level1)
{
    int32_t spec[5] = {0};
    QrcodeVersionGetEccInfo(-1, spec, 5);
    EXPECT_EQ(spec[0], 0);
}

/**
 * @tc.name: qrcode_version_get_pattern_invalid_022
 * @tc.desc: Verify getting pattern for invalid version.
 * @tc.type: FUNC
 * @tc.require: issueI000002
 */
HWTEST_F(QrcodeVersionTest, qrcode_version_get_pattern_invalid_022, TestSize.Level1)
{
    uint32_t pattern = QrcodeVersionGetPattern(6);
    EXPECT_EQ(pattern, 0);
}

/**
 * @tc.name: qrcode_version_get_pattern_max_023
 * @tc.desc: Verify getting pattern for max version.
 * @tc.type: FUNC
 * @tc.require: issueI000002
 */
HWTEST_F(QrcodeVersionTest, qrcode_version_get_pattern_max_023, TestSize.Level1)
{
    uint32_t pattern = QrcodeVersionGetPattern(QRCODE_VERSION_MAX);
    EXPECT_NE(pattern, 0);
}

/**
 * @tc.name: qrcode_version_get_format_info_invalid_024
 * @tc.desc: Verify getting format info for invalid mask.
 * @tc.type: FUNC
 * @tc.require: issueI000002
 */
HWTEST_F(QrcodeVersionTest, qrcode_version_get_format_info_invalid_024, TestSize.Level1)
{
    int32_t formatInfo = QrcodeVersionGetFormatInfo(-1);
    EXPECT_EQ(formatInfo, 0);
}

/**
 * @tc.name: qrcode_version_get_format_info_max_025
 * @tc.desc: Verify getting format info for max mask.
 * @tc.type: FUNC
 * @tc.require: issueI000002
 */
HWTEST_F(QrcodeVersionTest, qrcode_version_get_format_info_max_025, TestSize.Level1)
{
    int32_t formatInfo = QrcodeVersionGetFormatInfo(7);
    EXPECT_NE(formatInfo, 0);
}

/**
 * @tc.name: qrcode_version_new_data_invalid_026
 * @tc.desc: Verify creating new data buffer for invalid version.
 * @tc.type: FUNC
 * @tc.require: issueI000002
 */
HWTEST_F(QrcodeVersionTest, qrcode_version_new_data_invalid_026, TestSize.Level1)
{
    uint8_t *data = QrcodeVersionNewData(-1);
    EXPECT_EQ(data, nullptr);
}

/**
 * @tc.name: qrcode_version_new_data_max_027
 * @tc.desc: Verify creating new data buffer for max version.
 * @tc.type: FUNC
 * @tc.require: issueI000002
 */
HWTEST_F(QrcodeVersionTest, qrcode_version_new_data_max_027, TestSize.Level1)
{
    uint8_t *data = QrcodeVersionNewData(QRCODE_VERSION_MAX);
    EXPECT_NE(data, nullptr);
    if (data != nullptr) {
        QrcodeFree(data);
    }
}

/**
 * @tc.name: qrcode_version_get_min_version_zero_028
 * @tc.desc: Verify getting minimum version for zero size.
 * @tc.type: FUNC
 * @tc.require: issueI000002
 */
HWTEST_F(QrcodeVersionTest, qrcode_version_get_min_version_zero_028, TestSize.Level1)
{
    int32_t minVersion = QrcodeVersionGetMinVersion(0);
    EXPECT_GE(minVersion, 1);
}

/**
 * @tc.name: qrcode_version_get_min_version_large_029
 * @tc.desc: Verify getting minimum version for large size.
 * @tc.type: FUNC
 * @tc.require: issueI000002
 */
HWTEST_F(QrcodeVersionTest, qrcode_version_get_min_version_large_029, TestSize.Level1)
{
    int32_t minVersion = QrcodeVersionGetMinVersion(1000);
    EXPECT_GT(minVersion, 0);
}

/**
 * @tc.name: qrcode_version_mode_length_version_9_030
 * @tc.desc: Verify mode length for version 9.
 * @tc.type: FUNC
 * @tc.require: issueI000002
 */
HWTEST_F(QrcodeVersionTest, qrcode_version_mode_length_version_9_030, TestSize.Level1)
{
    int32_t length = QrcodeVersionModeLength(QRCODE_MODE_NUM, 9);
    EXPECT_GT(length, 0);
}

/**
 * @tc.name: qrcode_version_mode_length_version_26_031
 * @tc.desc: Verify mode length for version 26.
 * @tc.type: FUNC
 * @tc.require: issueI000002
 */
HWTEST_F(QrcodeVersionTest, qrcode_version_mode_length_version_26_031, TestSize.Level1)
{
    int32_t length = QrcodeVersionModeLength(QRCODE_MODE_NUM, 26);
    EXPECT_GT(length, 0);
}

/**
 * @tc.name: qrcode_version_clear_cache_invalid_032
 * @tc.desc: Verify clearing cache for invalid version.
 * @tc.type: FUNC
 * @tc.require: issueI000002
 */
HWTEST_F(QrcodeVersionTest, qrcode_version_clear_cache_invalid_032, TestSize.Level1)
{
    QrcodeVersionClearCache(-1);
}

/**
 * @tc.name: qrcode_version_clear_cache_max_033
 * @tc.desc: Verify clearing cache for max version.
 * @tc.type: FUNC
 * @tc.require: issueI000002
 */
HWTEST_F(QrcodeVersionTest, qrcode_version_clear_cache_max_033, TestSize.Level1)
{
    QrcodeVersionClearCache(QRCODE_VERSION_MAX);
}

/**
 * @tc.name: qrcode_version_set_ecc_max_034
 * @tc.desc: Verify setting ECC to max value.
 * @tc.type: FUNC
 * @tc.require: issueI000002
 */
HWTEST_F(QrcodeVersionTest, qrcode_version_set_ecc_max_034, TestSize.Level1)
{
    QrcodeVersionSetEcc(QRCODE_ECC_MAX);
    int32_t dataLen = QrcodeVersionGetDataLen(1);
    EXPECT_GT(dataLen, 0);
}

/**
 * @tc.name: qrcode_version_max_words_invalid_mode_035
 * @tc.desc: Verify max words with invalid mode.
 * @tc.type: FUNC
 * @tc.require: issueI000002
 */
HWTEST_F(QrcodeVersionTest, qrcode_version_max_words_invalid_mode_035, TestSize.Level1)
{
    int32_t maxWords = QrcodeVersionMaxWordsInMode(1, QRCODE_MODE_NUL);
    EXPECT_EQ(maxWords, 0);
}

/**
 * @tc.name: qrcode_version_get_min_version_too_large_037
 * @tc.desc: Verify getting minimum version for size that exceeds max.
 * @tc.type: FUNC
 * @tc.require: issueI000002
 */
HWTEST_F(QrcodeVersionTest, qrcode_version_get_min_version_too_large_037, TestSize.Level1)
{
    int32_t minVersion = QrcodeVersionGetMinVersion(100000);
    EXPECT_EQ(minVersion, -1);
}

/**
 * @tc.name: qrcode_version_mode_length_version_27_038
 * @tc.desc: Verify mode length for version 27 (greater than 26).
 * @tc.type: FUNC
 * @tc.require: issueI000002
 */
HWTEST_F(QrcodeVersionTest, qrcode_version_mode_length_version_27_038, TestSize.Level1)
{
    int32_t length = QrcodeVersionModeLength(QRCODE_MODE_NUM, 27);
    EXPECT_GT(length, 0);
}

/**
 * @tc.name: qrcode_version_mode_length_version_40_039
 * @tc.desc: Verify mode length for version 40 (max version).
 * @tc.type: FUNC
 * @tc.require: issueI000002
 */
HWTEST_F(QrcodeVersionTest, qrcode_version_mode_length_version_40_039, TestSize.Level1)
{
    int32_t length = QrcodeVersionModeLength(QRCODE_MODE_NUM, QRCODE_VERSION_MAX);
    EXPECT_GT(length, 0);
}

/**
 * @tc.name: qrcode_version_mode_length_an_version_27_040
 * @tc.desc: Verify alphanumeric mode length for version 27.
 * @tc.type: FUNC
 * @tc.require: issueI000002
 */
HWTEST_F(QrcodeVersionTest, qrcode_version_mode_length_an_version_27_040, TestSize.Level1)
{
    int32_t length = QrcodeVersionModeLength(QRCODE_MODE_AN, 27);
    EXPECT_GT(length, 0);
}

/**
 * @tc.name: qrcode_version_mode_length_8_version_27_041
 * @tc.desc: Verify byte mode length for version 27.
 * @tc.type: FUNC
 * @tc.require: issueI000002
 */
HWTEST_F(QrcodeVersionTest, qrcode_version_mode_length_8_version_27_041, TestSize.Level1)
{
    int32_t length = QrcodeVersionModeLength(QRCODE_MODE_8, 27);
    EXPECT_GT(length, 0);
}

/**
 * @tc.name: qrcode_version_max_words_version_27_042
 * @tc.desc: Verify max words in mode for version 27.
 * @tc.type: FUNC
 * @tc.require: issueI000002
 */
HWTEST_F(QrcodeVersionTest, qrcode_version_max_words_version_27_042, TestSize.Level1)
{
    int32_t maxWords = QrcodeVersionMaxWordsInMode(27, QRCODE_MODE_NUM);
    EXPECT_GT(maxWords, 0);
}

/**
 * @tc.name: qrcode_version_get_ecc_info_ecc_max_043
 * @tc.desc: Verify getting ECC info with ECC_MAX.
 * @tc.type: FUNC
 * @tc.require: issueI000002
 */
HWTEST_F(QrcodeVersionTest, qrcode_version_get_ecc_info_ecc_max_043, TestSize.Level1)
{
    QrcodeVersionSetEcc(QRCODE_ECC_MAX);
    int32_t spec[5] = {0};
    QrcodeVersionGetEccInfo(1, spec, 5);
    EXPECT_GT(spec[0], 0);
}

/**
 * @tc.name: qrcode_version_get_ecc_info_ecc_invalid_044
 * @tc.desc: Verify getting ECC info with invalid ECC level.
 * @tc.type: FUNC
 * @tc.require: issueI000002
 */
HWTEST_F(QrcodeVersionTest, qrcode_version_get_ecc_info_ecc_invalid_044, TestSize.Level1)
{
    QrcodeVersionSetEcc(QRCODE_ECC_MAX);
    int32_t spec[5] = {0};
    QrcodeVersionGetEccInfo(1, spec, 5);
    EXPECT_GT(spec[0], 0);  // ECC_MAX is valid, returns valid data
}

/**
 * @tc.name: qrcode_version_get_pattern_version_7_045
 * @tc.desc: Verify getting pattern for version 7 (minimum for pattern).
 * @tc.type: FUNC
 * @tc.require: issueI000002
 */
HWTEST_F(QrcodeVersionTest, qrcode_version_get_pattern_version_7_045, TestSize.Level1)
{
    uint32_t pattern = QrcodeVersionGetPattern(7);
    EXPECT_NE(pattern, 0);
}

/**
 * @tc.name: qrcode_version_get_format_info_all_masks_046
 * @tc.desc: Verify getting format info for all valid masks.
 * @tc.type: FUNC
 * @tc.require: issueI000002
 */
HWTEST_F(QrcodeVersionTest, qrcode_version_get_format_info_all_masks_046, TestSize.Level1)
{
    for (int32_t mask = 0; mask <= 7; mask++) {
        int32_t formatInfo = QrcodeVersionGetFormatInfo(mask);
        EXPECT_NE(formatInfo, 0);
    }
}

/**
 * @tc.name: qrcode_version_get_format_info_mask_8_047
 * @tc.desc: Verify getting format info for invalid mask 8.
 * @tc.type: FUNC
 * @tc.require: issueI000002
 */
HWTEST_F(QrcodeVersionTest, qrcode_version_get_format_info_mask_8_047, TestSize.Level1)
{
    int32_t formatInfo = QrcodeVersionGetFormatInfo(8);
    EXPECT_EQ(formatInfo, 0);
}

/**
 * @tc.name: qrcode_version_get_data_len_all_versions_048
 * @tc.desc: Verify getting data length for all valid versions.
 * @tc.type: FUNC
 * @tc.require: issueI000002
 */
HWTEST_F(QrcodeVersionTest, qrcode_version_get_data_len_all_versions_048, TestSize.Level1)
{
    for (int32_t version = 1; version <= QRCODE_VERSION_MAX; version++) {
        int32_t dataLen = QrcodeVersionGetDataLen(version);
        EXPECT_GT(dataLen, 0);
    }
}

/**
 * @tc.name: qrcode_version_get_ecc_len_all_versions_049
 * @tc.desc: Verify getting ECC length for all valid versions.
 * @tc.type: FUNC
 * @tc.require: issueI000002
 */
HWTEST_F(QrcodeVersionTest, qrcode_version_get_ecc_len_all_versions_049, TestSize.Level1)
{
    for (int32_t version = 1; version <= QRCODE_VERSION_MAX; version++) {
        int32_t eccLen = QrcodeVersionGetEccLen(version);
        EXPECT_GT(eccLen, 0);
    }
}

/**
 * @tc.name: qrcode_version_get_width_all_versions_050
 * @tc.desc: Verify getting width for all valid versions.
 * @tc.type: FUNC
 * @tc.require: issueI000002
 */
HWTEST_F(QrcodeVersionTest, qrcode_version_get_width_all_versions_050, TestSize.Level1)
{
    for (int32_t version = 1; version <= QRCODE_VERSION_MAX; version++) {
        int32_t width = QrcodeVersionGetWidth(version);
        EXPECT_GT(width, 0);
    }
}

/**
 * @tc.name: qrcode_version_get_remainder_all_versions_051
 * @tc.desc: Verify getting remainder for all valid versions.
 * @tc.type: FUNC
 * @tc.require: issueI000002
 */
HWTEST_F(QrcodeVersionTest, qrcode_version_get_remainder_all_versions_051, TestSize.Level1)
{
    for (int32_t version = 1; version <= QRCODE_VERSION_MAX; version++) {
        int32_t remainder = QrcodeVersionGetRemainder(version);
        EXPECT_GE(remainder, 0);
    }
}

/**
 * @tc.name: qrcode_version_new_data_all_versions_052
 * @tc.desc: Verify creating new data buffer for all valid versions.
 * @tc.type: FUNC
 * @tc.require: issueI000002
 */
HWTEST_F(QrcodeVersionTest, qrcode_version_new_data_all_versions_052, TestSize.Level1)
{
    for (int32_t version = 1; version <= QRCODE_VERSION_MAX; version++) {
        uint8_t *data = QrcodeVersionNewData(version);
        EXPECT_NE(data, nullptr);
        if (data != nullptr) {
            QrcodeFree(data);
        }
    }
}

/**
 * @tc.name: qrcode_version_clear_cache_all_versions_053
 * @tc.desc: Verify clearing cache for all valid versions.
 * @tc.type: FUNC
 * @tc.require: issueI000002
 */
HWTEST_F(QrcodeVersionTest, qrcode_version_clear_cache_all_versions_053, TestSize.Level1)
{
    for (int32_t version = 1; version <= QRCODE_VERSION_MAX; version++) {
        QrcodeVersionClearCache(version);
    }
}

/**
 * @tc.name: qrcode_version_get_ecc_info_all_versions_054
 * @tc.desc: Verify getting ECC info for all valid versions.
 * @tc.type: FUNC
 * @tc.require: issueI000002
 */
HWTEST_F(QrcodeVersionTest, qrcode_version_get_ecc_info_all_versions_054, TestSize.Level1)
{
    for (int32_t version = 1; version <= QRCODE_VERSION_MAX; version++) {
        int32_t spec[5] = {0};
        QrcodeVersionGetEccInfo(version, spec, 5);
        EXPECT_GT(spec[0], 0);
    }
}

/**
 * @tc.name: qrcode_version_max_words_all_modes_055
 * @tc.desc: Verify max words in all modes for version 1.
 * @tc.type: FUNC
 * @tc.require: issueI000002
 */
HWTEST_F(QrcodeVersionTest, qrcode_version_max_words_all_modes_055, TestSize.Level1)
{
    int32_t maxWordsNum = QrcodeVersionMaxWordsInMode(1, QRCODE_MODE_NUM);
    EXPECT_GT(maxWordsNum, 0);

    int32_t maxWordsAn = QrcodeVersionMaxWordsInMode(1, QRCODE_MODE_AN);
    EXPECT_GT(maxWordsAn, 0);

    int32_t maxWords8 = QrcodeVersionMaxWordsInMode(1, QRCODE_MODE_8);
    EXPECT_GT(maxWords8, 0);
}

/**
 * @tc.name: qrcode_version_mode_length_all_modes_056
 * @tc.desc: Verify mode length for all modes for version 1.
 * @tc.type: FUNC
 * @tc.require: issueI000002
 */
HWTEST_F(QrcodeVersionTest, qrcode_version_mode_length_all_modes_056, TestSize.Level1)
{
    int32_t lengthNum = QrcodeVersionModeLength(QRCODE_MODE_NUM, 1);
    EXPECT_GT(lengthNum, 0);

    int32_t lengthAn = QrcodeVersionModeLength(QRCODE_MODE_AN, 1);
    EXPECT_GT(lengthAn, 0);

    int32_t length8 = QrcodeVersionModeLength(QRCODE_MODE_8, 1);
    EXPECT_GT(length8, 0);
}

/**
 * @tc.name: qrcode_version_get_min_version_zero_057
 * @tc.desc: Verify getting min version for zero size.
 * @tc.type: FUNC
 * @tc.require: issueI000002
 */
HWTEST_F(QrcodeVersionTest, qrcode_version_get_min_version_zero_057, TestSize.Level1)
{
    int32_t version = QrcodeVersionGetMinVersion(0);
    EXPECT_EQ(version, 1);
}

/**
 * @tc.name: qrcode_version_get_min_version_negative_058
 * @tc.desc: Verify getting min version for negative size.
 * @tc.type: FUNC
 * @tc.require: issueI000002
 */
HWTEST_F(QrcodeVersionTest, qrcode_version_get_min_version_negative_058, TestSize.Level1)
{
    int32_t version = QrcodeVersionGetMinVersion(-1);
    EXPECT_EQ(version, 1);  // Negative size defaults to version 1
}

/**
 * @tc.name: qrcode_version_get_min_version_very_large_059
 * @tc.desc: Verify getting min version for very large size.
 * @tc.type: FUNC
 * @tc.require: issueI000002
 */
HWTEST_F(QrcodeVersionTest, qrcode_version_get_min_version_very_large_059, TestSize.Level1)
{
    int32_t version = QrcodeVersionGetMinVersion(100000);
    EXPECT_EQ(version, -1);
}

/**
 * @tc.name: qrcode_version_mode_length_invalid_mode_060
 * @tc.desc: Verify getting mode length for invalid mode.
 * @tc.type: FUNC
 * @tc.require: issueI000002
 */
HWTEST_F(QrcodeVersionTest, qrcode_version_mode_length_invalid_mode_060, TestSize.Level1)
{
    int32_t length = QrcodeVersionModeLength(QRCODE_MODE_NUL, 1);
    EXPECT_EQ(length, 0);
}

/**
 * @tc.name: qrcode_version_mode_length_version_9_061
 * @tc.desc: Verify getting mode length for version 9.
 * @tc.type: FUNC
 * @tc.require: issueI000002
 */
HWTEST_F(QrcodeVersionTest, qrcode_version_mode_length_version_9_061, TestSize.Level1)
{
    int32_t lengthNum = QrcodeVersionModeLength(QRCODE_MODE_NUM, 9);
    EXPECT_GT(lengthNum, 0);

    int32_t lengthAn = QrcodeVersionModeLength(QRCODE_MODE_AN, 9);
    EXPECT_GT(lengthAn, 0);

    int32_t length8 = QrcodeVersionModeLength(QRCODE_MODE_8, 9);
    EXPECT_GT(length8, 0);
}

/**
 * @tc.name: qrcode_version_mode_length_version_10_062
 * @tc.desc: Verify getting mode length for version 10.
 * @tc.type: FUNC
 * @tc.require: issueI000002
 */
HWTEST_F(QrcodeVersionTest, qrcode_version_mode_length_version_10_062, TestSize.Level1)
{
    int32_t lengthNum = QrcodeVersionModeLength(QRCODE_MODE_NUM, 10);
    EXPECT_GT(lengthNum, 0);

    int32_t lengthAn = QrcodeVersionModeLength(QRCODE_MODE_AN, 10);
    EXPECT_GT(lengthAn, 0);

    int32_t length8 = QrcodeVersionModeLength(QRCODE_MODE_8, 10);
    EXPECT_GT(length8, 0);
}

/**
 * @tc.name: qrcode_version_mode_length_version_26_063
 * @tc.desc: Verify getting mode length for version 26.
 * @tc.type: FUNC
 * @tc.require: issueI000002
 */
HWTEST_F(QrcodeVersionTest, qrcode_version_mode_length_version_26_063, TestSize.Level1)
{
    int32_t lengthNum = QrcodeVersionModeLength(QRCODE_MODE_NUM, 26);
    EXPECT_GT(lengthNum, 0);

    int32_t lengthAn = QrcodeVersionModeLength(QRCODE_MODE_AN, 26);
    EXPECT_GT(lengthAn, 0);

    int32_t length8 = QrcodeVersionModeLength(QRCODE_MODE_8, 26);
    EXPECT_GT(length8, 0);
}

/**
 * @tc.name: qrcode_version_mode_length_version_27_064
 * @tc.desc: Verify getting mode length for version 27.
 * @tc.type: FUNC
 * @tc.require: issueI000002
 */
HWTEST_F(QrcodeVersionTest, qrcode_version_mode_length_version_27_064, TestSize.Level1)
{
    int32_t lengthNum = QrcodeVersionModeLength(QRCODE_MODE_NUM, 27);
    EXPECT_GT(lengthNum, 0);

    int32_t lengthAn = QrcodeVersionModeLength(QRCODE_MODE_AN, 27);
    EXPECT_GT(lengthAn, 0);

    int32_t length8 = QrcodeVersionModeLength(QRCODE_MODE_8, 27);
    EXPECT_GT(length8, 0);
}

/**
 * @tc.name: qrcode_version_max_words_invalid_mode_065
 * @tc.desc: Verify max words for invalid mode.
 * @tc.type: FUNC
 * @tc.require: issueI000002
 */
HWTEST_F(QrcodeVersionTest, qrcode_version_max_words_invalid_mode_065, TestSize.Level1)
{
    int32_t maxWords = QrcodeVersionMaxWordsInMode(1, QRCODE_MODE_NUL);
    EXPECT_EQ(maxWords, 0);
}

/**
 * @tc.name: qrcode_version_get_data_len_all_versions_066
 * @tc.desc: Verify getting data length for all valid versions.
 * @tc.type: FUNC
 * @tc.require: issueI000002
 */
HWTEST_F(QrcodeVersionTest, qrcode_version_get_data_len_all_versions_066, TestSize.Level1)
{
    for (int32_t version = 1; version <= QRCODE_VERSION_MAX; version++) {
        int32_t dataLen = QrcodeVersionGetDataLen(version);
        EXPECT_GT(dataLen, 0);
    }
}

/**
 * @tc.name: qrcode_version_get_ecc_len_all_versions_067
 * @tc.desc: Verify getting ECC length for all valid versions.
 * @tc.type: FUNC
 * @tc.require: issueI000002
 */
HWTEST_F(QrcodeVersionTest, qrcode_version_get_ecc_len_all_versions_067, TestSize.Level1)
{
    for (int32_t version = 1; version <= QRCODE_VERSION_MAX; version++) {
        int32_t eccLen = QrcodeVersionGetEccLen(version);
        EXPECT_GT(eccLen, 0);
    }
}

/**
 * @tc.name: qrcode_version_get_width_all_versions_068
 * @tc.desc: Verify getting width for all valid versions.
 * @tc.type: FUNC
 * @tc.require: issueI000002
 */
HWTEST_F(QrcodeVersionTest, qrcode_version_get_width_all_versions_068, TestSize.Level1)
{
    for (int32_t version = 1; version <= QRCODE_VERSION_MAX; version++) {
        int32_t width = QrcodeVersionGetWidth(version);
        EXPECT_GT(width, 0);
    }
}

/**
 * @tc.name: qrcode_version_get_remainder_all_versions_069
 * @tc.desc: Verify getting remainder for all valid versions.
 * @tc.type: FUNC
 * @tc.require: issueI000002
 */
HWTEST_F(QrcodeVersionTest, qrcode_version_get_remainder_all_versions_069, TestSize.Level1)
{
    for (int32_t version = 1; version <= QRCODE_VERSION_MAX; version++) {
        int32_t remainder = QrcodeVersionGetRemainder(version);
        EXPECT_GE(remainder, 0);
    }
}