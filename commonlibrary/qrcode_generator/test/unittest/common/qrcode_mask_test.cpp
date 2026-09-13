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

#include "interfaces/innerkits/qrcode_mask.h"
#include "interfaces/innerkits/qrcode_inner.h"
#include <gtest/gtest.h>
#include <cstring>
#include "securec.h"

using namespace testing::ext;

class QrcodeMaskTest : public testing::Test {
public:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp();
    void TearDown();
};

void QrcodeMaskTest::SetUpTestCase(void) {}

void QrcodeMaskTest::TearDownTestCase(void) {}

void QrcodeMaskTest::SetUp(void) {}

void QrcodeMaskTest::TearDown(void) {}

/**
 * @tc.name: qrcode_mask_find_mask_001
 * @tc.desc: Verify finding mask for small QR code.
 * @tc.type: FUNC
 * @tc.require: issueI000005
 */
HWTEST_F(QrcodeMaskTest, qrcode_mask_find_mask_001, TestSize.Level1)
{
    int32_t width = 21;
    uint8_t *data = (uint8_t *)QrcodeMalloc(width * width);
    EXPECT_NE(data, nullptr);
    if (data != nullptr) {
        (void)memset_s(data, width * width, 0, width * width);
        uint8_t *mask = QrcodeMaskFindMask(width, data);
        EXPECT_NE(mask, nullptr);
        if (mask != nullptr) {
            QrcodeFree(mask);
        }
        QrcodeFree(data);
    }
}

/**
 * @tc.name: qrcode_mask_find_mask_medium_002
 * @tc.desc: Verify finding mask for medium QR code.
 * @tc.type: FUNC
 * @tc.require: issueI000005
 */
HWTEST_F(QrcodeMaskTest, qrcode_mask_find_mask_medium_002, TestSize.Level1)
{
    int32_t width = 25;
    uint8_t *data = (uint8_t *)QrcodeMalloc(width * width);
    EXPECT_NE(data, nullptr);
    if (data != nullptr) {
        (void)memset_s(data, width * width, 0, width * width);
        uint8_t *mask = QrcodeMaskFindMask(width, data);
        EXPECT_NE(mask, nullptr);
        if (mask != nullptr) {
            QrcodeFree(mask);
        }
        QrcodeFree(data);
    }
}

/**
 * @tc.name: qrcode_mask_find_mask_large_003
 * @tc.desc: Verify finding mask for large QR code.
 * @tc.type: FUNC
 * @tc.require: issueI000005
 */
HWTEST_F(QrcodeMaskTest, qrcode_mask_find_mask_large_003, TestSize.Level1)
{
    int32_t width = 29;
    uint8_t *data = (uint8_t *)QrcodeMalloc(width * width);
    EXPECT_NE(data, nullptr);
    if (data != nullptr) {
        (void)memset_s(data, width * width, 0, width * width);
        uint8_t *mask = QrcodeMaskFindMask(width, data);
        EXPECT_NE(mask, nullptr);
        if (mask != nullptr) {
            QrcodeFree(mask);
        }
        QrcodeFree(data);
    }
}

/**
 * @tc.name: qrcode_mask_find_mask_null_data_004
 * @tc.desc: Verify finding mask with null data.
 * @tc.type: FUNC
 * @tc.require: issueI000005
 */
HWTEST_F(QrcodeMaskTest, qrcode_mask_find_mask_null_data_004, TestSize.Level1)
{
    uint8_t *mask = QrcodeMaskFindMask(21, nullptr);
    EXPECT_EQ(mask, nullptr);
}

/**
 * @tc.name: qrcode_mask_find_mask_zero_width_005
 * @tc.desc: Verify finding mask with zero width.
 * @tc.type: FUNC
 * @tc.require: issueI000005
 */
HWTEST_F(QrcodeMaskTest, qrcode_mask_find_mask_zero_width_005, TestSize.Level1)
{
    uint8_t *mask = QrcodeMaskFindMask(0, nullptr);
    EXPECT_EQ(mask, nullptr);
}

/**
 * @tc.name: qrcode_mask_find_mask_with_data_006
 * @tc.desc: Verify finding mask with actual data.
 * @tc.type: FUNC
 * @tc.require: issueI000005
 */
HWTEST_F(QrcodeMaskTest, qrcode_mask_find_mask_with_data_006, TestSize.Level1)
{
    int32_t width = 21;
    uint8_t *data = (uint8_t *)QrcodeMalloc(width * width);
    EXPECT_NE(data, nullptr);
    if (data != nullptr) {
        for (int32_t i = 0; i < width * width; i++) {
            data[i] = i % 2;
        }
        uint8_t *mask = QrcodeMaskFindMask(width, data);
        EXPECT_NE(mask, nullptr);
        if (mask != nullptr) {
            QrcodeFree(mask);
        }
        QrcodeFree(data);
    }
}

/**
 * @tc.name: qrcode_mask_find_mask_version_1_007
 * @tc.desc: Verify finding mask for version 1 QR code.
 * @tc.type: FUNC
 * @tc.require: issueI000005
 */
HWTEST_F(QrcodeMaskTest, qrcode_mask_find_mask_version_1_007, TestSize.Level1)
{
    int32_t width = 21;
    uint8_t *data = (uint8_t *)QrcodeMalloc(width * width);
    EXPECT_NE(data, nullptr);
    if (data != nullptr) {
        (void)memset_s(data, width * width, 0, width * width);
        uint8_t *mask = QrcodeMaskFindMask(width, data);
        EXPECT_NE(mask, nullptr);
        if (mask != nullptr) {
            QrcodeFree(mask);
        }
        QrcodeFree(data);
    }
}

/**
 * @tc.name: qrcode_mask_find_mask_version_2_008
 * @tc.desc: Verify finding mask for version 2 QR code.
 * @tc.type: FUNC
 * @tc.require: issueI000005
 */
HWTEST_F(QrcodeMaskTest, qrcode_mask_find_mask_version_2_008, TestSize.Level1)
{
    int32_t width = 25;
    uint8_t *data = (uint8_t *)QrcodeMalloc(width * width);
    EXPECT_NE(data, nullptr);
    if (data != nullptr) {
        (void)memset_s(data, width * width, 0, width * width);
        uint8_t *mask = QrcodeMaskFindMask(width, data);
        EXPECT_NE(mask, nullptr);
        if (mask != nullptr) {
            QrcodeFree(mask);
        }
        QrcodeFree(data);
    }
}

/**
 * @tc.name: qrcode_mask_find_mask_all_zeros_009
 * @tc.desc: Verify finding mask with all zeros data.
 * @tc.type: FUNC
 * @tc.require: issueI000005
 */
HWTEST_F(QrcodeMaskTest, qrcode_mask_find_mask_all_zeros_009, TestSize.Level1)
{
    int32_t width = 21;
    uint8_t *data = (uint8_t *)QrcodeMalloc(width * width);
    EXPECT_NE(data, nullptr);
    if (data != nullptr) {
        (void)memset_s(data, width * width, 0, width * width);
        uint8_t *mask = QrcodeMaskFindMask(width, data);
        EXPECT_NE(mask, nullptr);
        if (mask != nullptr) {
            QrcodeFree(mask);
        }
        QrcodeFree(data);
    }
}

/**
 * @tc.name: qrcode_mask_find_mask_all_ones_010
 * @tc.desc: Verify finding mask with all ones data.
 * @tc.type: FUNC
 * @tc.require: issueI000005
 */
HWTEST_F(QrcodeMaskTest, qrcode_mask_find_mask_all_ones_010, TestSize.Level1)
{
    int32_t width = 21;
    uint8_t *data = (uint8_t *)QrcodeMalloc(width * width);
    EXPECT_NE(data, nullptr);
    if (data != nullptr) {
        (void)memset_s(data, width * width, 1, width * width);
        uint8_t *mask = QrcodeMaskFindMask(width, data);
        EXPECT_NE(mask, nullptr);
        if (mask != nullptr) {
            QrcodeFree(mask);
        }
        QrcodeFree(data);
    }
}

/**
 * @tc.name: qrcode_mask_find_mask_alternating_011
 * @tc.desc: Verify finding mask with alternating pattern.
 * @tc.type: FUNC
 * @tc.require: issueI000005
 */
HWTEST_F(QrcodeMaskTest, qrcode_mask_find_mask_alternating_011, TestSize.Level1)
{
    int32_t width = 21;
    uint8_t *data = (uint8_t *)QrcodeMalloc(width * width);
    EXPECT_NE(data, nullptr);
    if (data != nullptr) {
        for (int32_t i = 0; i < width * width; i++) {
            data[i] = i % 2;
        }
        uint8_t *mask = QrcodeMaskFindMask(width, data);
        EXPECT_NE(mask, nullptr);
        if (mask != nullptr) {
            QrcodeFree(mask);
        }
        QrcodeFree(data);
    }
}

/**
 * @tc.name: qrcode_mask_find_mask_large_version_012
 * @tc.desc: Verify finding mask for larger version QR code.
 * @tc.type: FUNC
 * @tc.require: issueI000005
 */
HWTEST_F(QrcodeMaskTest, qrcode_mask_find_mask_large_version_012, TestSize.Level1)
{
    int32_t width = 33;
    uint8_t *data = (uint8_t *)QrcodeMalloc(width * width);
    EXPECT_NE(data, nullptr);
    if (data != nullptr) {
        (void)memset_s(data, width * width, 0, width * width);
        uint8_t *mask = QrcodeMaskFindMask(width, data);
        EXPECT_NE(mask, nullptr);
        if (mask != nullptr) {
            QrcodeFree(mask);
        }
        QrcodeFree(data);
    }
}

/**
 * @tc.name: qrcode_mask_find_mask_version_40_013
 * @tc.desc: Verify finding mask for version 40 (largest) QR code.
 * @tc.type: FUNC
 * @tc.require: issueI000005
 */
HWTEST_F(QrcodeMaskTest, qrcode_mask_find_mask_version_40_013, TestSize.Level1)
{
    int32_t width = 177;
    uint8_t *data = (uint8_t *)QrcodeMalloc(width * width);
    EXPECT_NE(data, nullptr);
    if (data != nullptr) {
        (void)memset_s(data, width * width, 0, width * width);
        uint8_t *mask = QrcodeMaskFindMask(width, data);
        EXPECT_NE(mask, nullptr);
        if (mask != nullptr) {
            QrcodeFree(mask);
        }
        QrcodeFree(data);
    }
}

/**
 * @tc.name: qrcode_mask_find_mask_with_high_bits_014
 * @tc.desc: Verify finding mask with high bits set (0x80).
 * @tc.type: FUNC
 * @tc.require: issueI000005
 */
HWTEST_F(QrcodeMaskTest, qrcode_mask_find_mask_with_high_bits_014, TestSize.Level1)
{
    int32_t width = 21;
    uint8_t *data = (uint8_t *)QrcodeMalloc(width * width);
    EXPECT_NE(data, nullptr);
    if (data != nullptr) {
        for (int32_t i = 0; i < width * width; i++) {
            data[i] = 0x80 | (i % 2);
        }
        uint8_t *mask = QrcodeMaskFindMask(width, data);
        EXPECT_NE(mask, nullptr);
        if (mask != nullptr) {
            QrcodeFree(mask);
        }
        QrcodeFree(data);
    }
}

/**
 * @tc.name: qrcode_mask_find_mask_all_high_bits_015
 * @tc.desc: Verify finding mask with all high bits set (0x80).
 * @tc.type: FUNC
 * @tc.require: issueI000005
 */
HWTEST_F(QrcodeMaskTest, qrcode_mask_find_mask_all_high_bits_015, TestSize.Level1)
{
    int32_t width = 21;
    uint8_t *data = (uint8_t *)QrcodeMalloc(width * width);
    EXPECT_NE(data, nullptr);
    if (data != nullptr) {
        (void)memset_s(data, width * width, 0x80, width * width);
        uint8_t *mask = QrcodeMaskFindMask(width, data);
        EXPECT_NE(mask, nullptr);
        if (mask != nullptr) {
            QrcodeFree(mask);
        }
        QrcodeFree(data);
    }
}

/**
 * @tc.name: qrcode_mask_find_mask_checkerboard_016
 * @tc.desc: Verify finding mask with checkerboard pattern.
 * @tc.type: FUNC
 * @tc.require: issueI000005
 */
HWTEST_F(QrcodeMaskTest, qrcode_mask_find_mask_checkerboard_016, TestSize.Level1)
{
    int32_t width = 21;
    uint8_t *data = (uint8_t *)QrcodeMalloc(width * width);
    EXPECT_NE(data, nullptr);
    if (data != nullptr) {
        for (int32_t y = 0; y < width; y++) {
            for (int32_t x = 0; x < width; x++) {
                data[y * width + x] = (x + y) % 2;
            }
        }
        uint8_t *mask = QrcodeMaskFindMask(width, data);
        EXPECT_NE(mask, nullptr);
        if (mask != nullptr) {
            QrcodeFree(mask);
        }
        QrcodeFree(data);
    }
}

/**
 * @tc.name: qrcode_mask_find_mask_horizontal_stripes_017
 * @tc.desc: Verify finding mask with horizontal stripes pattern.
 * @tc.type: FUNC
 * @tc.require: issueI000005
 */
HWTEST_F(QrcodeMaskTest, qrcode_mask_find_mask_horizontal_stripes_017, TestSize.Level1)
{
    int32_t width = 21;
    uint8_t *data = (uint8_t *)QrcodeMalloc(width * width);
    EXPECT_NE(data, nullptr);
    if (data != nullptr) {
        for (int32_t y = 0; y < width; y++) {
            for (int32_t x = 0; x < width; x++) {
                data[y * width + x] = y % 2;
            }
        }
        uint8_t *mask = QrcodeMaskFindMask(width, data);
        EXPECT_NE(mask, nullptr);
        if (mask != nullptr) {
            QrcodeFree(mask);
        }
        QrcodeFree(data);
    }
}

/**
 * @tc.name: qrcode_mask_find_mask_vertical_stripes_018
 * @tc.desc: Verify finding mask with vertical stripes pattern.
 * @tc.type: FUNC
 * @tc.require: issueI000005
 */
HWTEST_F(QrcodeMaskTest, qrcode_mask_find_mask_vertical_stripes_018, TestSize.Level1)
{
    int32_t width = 21;
    uint8_t *data = (uint8_t *)QrcodeMalloc(width * width);
    EXPECT_NE(data, nullptr);
    if (data != nullptr) {
        for (int32_t y = 0; y < width; y++) {
            for (int32_t x = 0; x < width; x++) {
                data[y * width + x] = x % 2;
            }
        }
        uint8_t *mask = QrcodeMaskFindMask(width, data);
        EXPECT_NE(mask, nullptr);
        if (mask != nullptr) {
            QrcodeFree(mask);
        }
        QrcodeFree(data);
    }
}

/**
 * @tc.name: qrcode_mask_find_mask_random_data_019
 * @tc.desc: Verify finding mask with random-like data.
 * @tc.type: FUNC
 * @tc.require: issueI000005
 */
HWTEST_F(QrcodeMaskTest, qrcode_mask_find_mask_random_data_019, TestSize.Level1)
{
    int32_t width = 21;
    uint8_t *data = (uint8_t *)QrcodeMalloc(width * width);
    EXPECT_NE(data, nullptr);
    if (data != nullptr) {
        for (int32_t i = 0; i < width * width; i++) {
            data[i] = (i * 7) % 256;
        }
        uint8_t *mask = QrcodeMaskFindMask(width, data);
        EXPECT_NE(mask, nullptr);
        if (mask != nullptr) {
            QrcodeFree(mask);
        }
        QrcodeFree(data);
    }
}

/**
 * @tc.name: qrcode_mask_find_mask_block_pattern_020
 * @tc.desc: Verify finding mask with block pattern (2x2 blocks).
 * @tc.type: FUNC
 * @tc.require: issueI000005
 */
HWTEST_F(QrcodeMaskTest, qrcode_mask_find_mask_block_pattern_020, TestSize.Level1)
{
    int32_t width = 21;
    uint8_t *data = (uint8_t *)QrcodeMalloc(width * width);
    EXPECT_NE(data, nullptr);
    if (data != nullptr) {
        for (int32_t y = 0; y < width; y++) {
            for (int32_t x = 0; x < width; x++) {
                data[y * width + x] = ((y / 2) + (x / 2)) % 2;
            }
        }
        uint8_t *mask = QrcodeMaskFindMask(width, data);
        EXPECT_NE(mask, nullptr);
        if (mask != nullptr) {
            QrcodeFree(mask);
        }
        QrcodeFree(data);
    }
}

/**
 * @tc.name: qrcode_mask_find_mask_diagonal_021
 * @tc.desc: Verify finding mask with diagonal pattern.
 * @tc.type: FUNC
 * @tc.require: issueI000005
 */
HWTEST_F(QrcodeMaskTest, qrcode_mask_find_mask_diagonal_021, TestSize.Level1)
{
    int32_t width = 21;
    uint8_t *data = (uint8_t *)QrcodeMalloc(width * width);
    EXPECT_NE(data, nullptr);
    if (data != nullptr) {
        for (int32_t y = 0; y < width; y++) {
            for (int32_t x = 0; x < width; x++) {
                data[y * width + x] = (x - y) % 2;
            }
        }
        uint8_t *mask = QrcodeMaskFindMask(width, data);
        EXPECT_NE(mask, nullptr);
        if (mask != nullptr) {
            QrcodeFree(mask);
        }
        QrcodeFree(data);
    }
}

/**
 * @tc.name: qrcode_mask_find_mask_spiral_022
 * @tc.desc: Verify finding mask with spiral-like pattern.
 * @tc.type: FUNC
 * @tc.require: issueI000005
 */
HWTEST_F(QrcodeMaskTest, qrcode_mask_find_mask_spiral_022, TestSize.Level1)
{
    int32_t width = 21;
    uint8_t *data = (uint8_t *)QrcodeMalloc(width * width);
    EXPECT_NE(data, nullptr);
    if (data != nullptr) {
        for (int32_t i = 0; i < width * width; i++) {
            data[i] = (i % 3) ? 1 : 0;
        }
        uint8_t *mask = QrcodeMaskFindMask(width, data);
        EXPECT_NE(mask, nullptr);
        if (mask != nullptr) {
            QrcodeFree(mask);
        }
        QrcodeFree(data);
    }
}

/**
 * @tc.name: qrcode_mask_find_mask_edge_case_023
 * @tc.desc: Verify finding mask with edge case pattern (1 and 0 sequence).
 * @tc.type: FUNC
 * @tc.require: issueI000005
 */
HWTEST_F(QrcodeMaskTest, qrcode_mask_find_mask_edge_case_023, TestSize.Level1)
{
    int32_t width = 21;
    uint8_t *data = (uint8_t *)QrcodeMalloc(width * width);
    EXPECT_NE(data, nullptr);
    if (data != nullptr) {
        for (int32_t i = 0; i < width * width; i++) {
            data[i] = (i % 5) ? 0 : 1;
        }
        uint8_t *mask = QrcodeMaskFindMask(width, data);
        EXPECT_NE(mask, nullptr);
        if (mask != nullptr) {
            QrcodeFree(mask);
        }
        QrcodeFree(data);
    }
}

/**
 * @tc.name: qrcode_mask_find_mask_version_10_024
 * @tc.desc: Verify finding mask for version 10 QR code.
 * @tc.type: FUNC
 * @tc.require: issueI000005
 */
HWTEST_F(QrcodeMaskTest, qrcode_mask_find_mask_version_10_024, TestSize.Level1)
{
    int32_t width = 57;
    uint8_t *data = (uint8_t *)QrcodeMalloc(width * width);
    EXPECT_NE(data, nullptr);
    if (data != nullptr) {
        (void)memset_s(data, width * width, 0, width * width);
        uint8_t *mask = QrcodeMaskFindMask(width, data);
        EXPECT_NE(mask, nullptr);
        if (mask != nullptr) {
            QrcodeFree(mask);
        }
        QrcodeFree(data);
    }
}

/**
 * @tc.name: qrcode_mask_find_mask_version_20_025
 * @tc.desc: Verify finding mask for version 20 QR code.
 * @tc.type: FUNC
 * @tc.require: issueI000005
 */
HWTEST_F(QrcodeMaskTest, qrcode_mask_find_mask_version_20_025, TestSize.Level1)
{
    int32_t width = 97;
    uint8_t *data = (uint8_t *)QrcodeMalloc(width * width);
    EXPECT_NE(data, nullptr);
    if (data != nullptr) {
        (void)memset_s(data, width * width, 0, width * width);
        uint8_t *mask = QrcodeMaskFindMask(width, data);
        EXPECT_NE(mask, nullptr);
        if (mask != nullptr) {
            QrcodeFree(mask);
        }
        QrcodeFree(data);
    }
}

/**
 * @tc.name: qrcode_mask_find_mask_version_30_026
 * @tc.desc: Verify finding mask for version 30 QR code.
 * @tc.type: FUNC
 * @tc.require: issueI000005
 */
HWTEST_F(QrcodeMaskTest, qrcode_mask_find_mask_version_30_026, TestSize.Level1)
{
    int32_t width = 137;
    uint8_t *data = (uint8_t *)QrcodeMalloc(width * width);
    EXPECT_NE(data, nullptr);
    if (data != nullptr) {
        (void)memset_s(data, width * width, 0, width * width);
        uint8_t *mask = QrcodeMaskFindMask(width, data);
        EXPECT_NE(mask, nullptr);
        if (mask != nullptr) {
            QrcodeFree(mask);
        }
        QrcodeFree(data);
    }
}

/**
 * @tc.name: qrcode_mask_find_mask_negative_width_027
 * @tc.desc: Verify finding mask with negative width.
 * @tc.type: FUNC
 * @tc.require: issueI000005
 */
HWTEST_F(QrcodeMaskTest, qrcode_mask_find_mask_negative_width_027, TestSize.Level1)
{
    uint8_t *mask = QrcodeMaskFindMask(-1, nullptr);
    EXPECT_EQ(mask, nullptr);
}

/**
 * @tc.name: qrcode_mask_find_mask_mixed_bits_029
 * @tc.desc: Verify finding mask with mixed high and low bits.
 * @tc.type: FUNC
 * @tc.require: issueI000005
 */
HWTEST_F(QrcodeMaskTest, qrcode_mask_find_mask_mixed_bits_029, TestSize.Level1)
{
    int32_t width = 21;
    uint8_t *data = (uint8_t *)QrcodeMalloc(width * width);
    EXPECT_NE(data, nullptr);
    if (data != nullptr) {
        for (int32_t i = 0; i < width * width; i++) {
            data[i] = (i % 3 == 0) ? 0x80 : (i % 2);
        }
        uint8_t *mask = QrcodeMaskFindMask(width, data);
        EXPECT_NE(mask, nullptr);
        if (mask != nullptr) {
            QrcodeFree(mask);
        }
        QrcodeFree(data);
    }
}

/**
 * @tc.name: qrcode_mask_find_mask_consecutive_ones_030
 * @tc.desc: Verify finding mask with consecutive ones pattern.
 * @tc.type: FUNC
 * @tc.require: issueI000005
 */
HWTEST_F(QrcodeMaskTest, qrcode_mask_find_mask_consecutive_ones_030, TestSize.Level1)
{
    int32_t width = 21;
    uint8_t *data = (uint8_t *)QrcodeMalloc(width * width);
    EXPECT_NE(data, nullptr);
    if (data != nullptr) {
        for (int32_t i = 0; i < width * width; i++) {
            data[i] = (i % 10 < 5) ? 1 : 0;
        }
        uint8_t *mask = QrcodeMaskFindMask(width, data);
        EXPECT_NE(mask, nullptr);
        if (mask != nullptr) {
            QrcodeFree(mask);
        }
        QrcodeFree(data);
    }
}

/**
 * @tc.name: qrcode_mask_find_mask_pattern1_match_031
 * @tc.desc: Verify finding mask with pattern1 (10111010000) match.
 * @tc.type: FUNC
 * @tc.require: issueI000005
 */
HWTEST_F(QrcodeMaskTest, qrcode_mask_find_mask_pattern1_match_031, TestSize.Level1)
{
    int32_t width = 21;
    uint8_t *data = (uint8_t *)QrcodeMalloc(width * width);
    EXPECT_NE(data, nullptr);
    if (data != nullptr) {
        for (int32_t i = 0; i < width * width; i++) {
            data[i] = 0;
        }
        for (int32_t i = 0; i < 11 && i < width * width; i++) {
            data[i] = (i % 2 == 0) ? 1 : 0;
        }
        data[2] = 1;
        data[3] = 1;
        data[4] = 1;
        uint8_t *mask = QrcodeMaskFindMask(width, data);
        EXPECT_NE(mask, nullptr);
        if (mask != nullptr) {
            QrcodeFree(mask);
        }
        QrcodeFree(data);
    }
}

/**
 * @tc.name: qrcode_mask_find_mask_pattern2_match_032
 * @tc.desc: Verify finding mask with pattern2 (00001011101) match.
 * @tc.type: FUNC
 * @tc.require: issueI000005
 */
HWTEST_F(QrcodeMaskTest, qrcode_mask_find_mask_pattern2_match_032, TestSize.Level1)
{
    int32_t width = 21;
    uint8_t *data = (uint8_t *)QrcodeMalloc(width * width);
    EXPECT_NE(data, nullptr);
    if (data != nullptr) {
        for (int32_t i = 0; i < width * width; i++) {
            data[i] = 0;
        }
        for (int32_t i = 0; i < 11 && i < width * width; i++) {
            data[i] = (i % 2 == 1) ? 1 : 0;
        }
        data[4] = 1;
        data[5] = 1;
        data[6] = 1;
        uint8_t *mask = QrcodeMaskFindMask(width, data);
        EXPECT_NE(mask, nullptr);
        if (mask != nullptr) {
            QrcodeFree(mask);
        }
        QrcodeFree(data);
    }
}

/**
 * @tc.name: qrcode_mask_find_mask_all_same_color_033
 * @tc.desc: Verify finding mask with all same color (triggers N2 penalty).
 * @tc.type: FUNC
 * @tc.require: issueI000005
 */
HWTEST_F(QrcodeMaskTest, qrcode_mask_find_mask_all_same_color_033, TestSize.Level1)
{
    int32_t width = 21;
    uint8_t *data = (uint8_t *)QrcodeMalloc(width * width);
    EXPECT_NE(data, nullptr);
    if (data != nullptr) {
        (void)memset_s(data, width * width, 0, width * width);
        uint8_t *mask = QrcodeMaskFindMask(width, data);
        EXPECT_NE(mask, nullptr);
        if (mask != nullptr) {
            QrcodeFree(mask);
        }
        QrcodeFree(data);
    }
}

/**
 * @tc.name: qrcode_mask_find_mask_2x2_blocks_034
 * @tc.desc: Verify finding mask with 2x2 blocks (triggers N2 penalty).
 * @tc.type: FUNC
 * @tc.require: issueI000005
 */
HWTEST_F(QrcodeMaskTest, qrcode_mask_find_mask_2x2_blocks_034, TestSize.Level1)
{
    int32_t width = 21;
    uint8_t *data = (uint8_t *)QrcodeMalloc(width * width);
    EXPECT_NE(data, nullptr);
    if (data != nullptr) {
        for (int32_t y = 0; y < width; y++) {
            for (int32_t x = 0; x < width; x++) {
                data[y * width + x] = ((y / 2) % 2) * 2 + ((x / 2) % 2);
            }
        }
        uint8_t *mask = QrcodeMaskFindMask(width, data);
        EXPECT_NE(mask, nullptr);
        if (mask != nullptr) {
            QrcodeFree(mask);
        }
        QrcodeFree(data);
    }
}

/**
 * @tc.name: qrcode_mask_find_mask_long_run_035
 * @tc.desc: Verify finding mask with long run of same color (triggers N1 penalty).
 * @tc.type: FUNC
 * @tc.require: issueI000005
 */
HWTEST_F(QrcodeMaskTest, qrcode_mask_find_mask_long_run_035, TestSize.Level1)
{
    int32_t width = 21;
    uint8_t *data = (uint8_t *)QrcodeMalloc(width * width);
    EXPECT_NE(data, nullptr);
    if (data != nullptr) {
        for (int32_t i = 0; i < width * width; i++) {
            data[i] = (i / width) % 2;
        }
        uint8_t *mask = QrcodeMaskFindMask(width, data);
        EXPECT_NE(mask, nullptr);
        if (mask != nullptr) {
            QrcodeFree(mask);
        }
        QrcodeFree(data);
    }
}

/**
 * @tc.name: qrcode_mask_find_mask_vertical_long_run_036
 * @tc.desc: Verify finding mask with vertical long run (triggers N1 penalty).
 * @tc.type: FUNC
 * @tc.require: issueI000005
 */
HWTEST_F(QrcodeMaskTest, qrcode_mask_find_mask_vertical_long_run_036, TestSize.Level1)
{
    int32_t width = 21;
    uint8_t *data = (uint8_t *)QrcodeMalloc(width * width);
    EXPECT_NE(data, nullptr);
    if (data != nullptr) {
        for (int32_t i = 0; i < width * width; i++) {
            data[i] = (i % width) % 2;
        }
        uint8_t *mask = QrcodeMaskFindMask(width, data);
        EXPECT_NE(mask, nullptr);
        if (mask != nullptr) {
            QrcodeFree(mask);
        }
        QrcodeFree(data);
    }
}

/**
 * @tc.name: qrcode_mask_find_mask_version_5_037
 * @tc.desc: Verify finding mask for version 5 QR code.
 * @tc.type: FUNC
 * @tc.require: issueI000005
 */
HWTEST_F(QrcodeMaskTest, qrcode_mask_find_mask_version_5_037, TestSize.Level1)
{
    int32_t width = 37;
    uint8_t *data = (uint8_t *)QrcodeMalloc(width * width);
    EXPECT_NE(data, nullptr);
    if (data != nullptr) {
        (void)memset_s(data, width * width, 0, width * width);
        uint8_t *mask = QrcodeMaskFindMask(width, data);
        EXPECT_NE(mask, nullptr);
        if (mask != nullptr) {
            QrcodeFree(mask);
        }
        QrcodeFree(data);
    }
}

/**
 * @tc.name: qrcode_mask_find_mask_version_15_038
 * @tc.desc: Verify finding mask for version 15 QR code.
 * @tc.type: FUNC
 * @tc.require: issueI000005
 */
HWTEST_F(QrcodeMaskTest, qrcode_mask_find_mask_version_15_038, TestSize.Level1)
{
    int32_t width = 77;
    uint8_t *data = (uint8_t *)QrcodeMalloc(width * width);
    EXPECT_NE(data, nullptr);
    if (data != nullptr) {
        (void)memset_s(data, width * width, 0, width * width);
        uint8_t *mask = QrcodeMaskFindMask(width, data);
        EXPECT_NE(mask, nullptr);
        if (mask != nullptr) {
            QrcodeFree(mask);
        }
        QrcodeFree(data);
    }
}

/**
 * @tc.name: qrcode_mask_find_mask_version_25_039
 * @tc.desc: Verify finding mask for version 25 QR code.
 * @tc.type: FUNC
 * @tc.require: issueI000005
 */
HWTEST_F(QrcodeMaskTest, qrcode_mask_find_mask_version_25_039, TestSize.Level1)
{
    int32_t width = 117;
    uint8_t *data = (uint8_t *)QrcodeMalloc(width * width);
    EXPECT_NE(data, nullptr);
    if (data != nullptr) {
        (void)memset_s(data, width * width, 0, width * width);
        uint8_t *mask = QrcodeMaskFindMask(width, data);
        EXPECT_NE(mask, nullptr);
        if (mask != nullptr) {
            QrcodeFree(mask);
        }
        QrcodeFree(data);
    }
}

/**
 * @tc.name: qrcode_mask_find_mask_version_35_040
 * @tc.desc: Verify finding mask for version 35 QR code.
 * @tc.type: FUNC
 * @tc.require: issueI000005
 */
HWTEST_F(QrcodeMaskTest, qrcode_mask_find_mask_version_35_040, TestSize.Level1)
{
    int32_t width = 157;
    uint8_t *data = (uint8_t *)QrcodeMalloc(width * width);
    EXPECT_NE(data, nullptr);
    if (data != nullptr) {
        (void)memset_s(data, width * width, 0, width * width);
        uint8_t *mask = QrcodeMaskFindMask(width, data);
        EXPECT_NE(mask, nullptr);
        if (mask != nullptr) {
            QrcodeFree(mask);
        }
        QrcodeFree(data);
    }
}

/**
 * @tc.name: qrcode_mask_find_mask_with_data_variations_041
 * @tc.desc: Verify finding mask with various data patterns.
 * @tc.type: FUNC
 * @tc.require: issueI000005
 */
HWTEST_F(QrcodeMaskTest, qrcode_mask_find_mask_with_data_variations_041, TestSize.Level1)
{
    int32_t width = 21;
    uint8_t *data = (uint8_t *)QrcodeMalloc(width * width);
    EXPECT_NE(data, nullptr);
    if (data != nullptr) {
        for (int32_t i = 0; i < width * width; i++) {
            data[i] = (i * 13) % 2;
        }
        uint8_t *mask = QrcodeMaskFindMask(width, data);
        EXPECT_NE(mask, nullptr);
        if (mask != nullptr) {
            QrcodeFree(mask);
        }
        QrcodeFree(data);
    }
}

/**
 * @tc.name: qrcode_mask_find_mask_complex_pattern_042
 * @tc.desc: Verify finding mask with complex pattern.
 * @tc.type: FUNC
 * @tc.require: issueI000005
 */
HWTEST_F(QrcodeMaskTest, qrcode_mask_find_mask_complex_pattern_042, TestSize.Level1)
{
    int32_t width = 21;
    uint8_t *data = (uint8_t *)QrcodeMalloc(width * width);
    EXPECT_NE(data, nullptr);
    if (data != nullptr) {
        for (int32_t y = 0; y < width; y++) {
            for (int32_t x = 0; x < width; x++) {
                data[y * width + x] = ((x * y) % 7) % 2;
            }
        }
        uint8_t *mask = QrcodeMaskFindMask(width, data);
        EXPECT_NE(mask, nullptr);
        if (mask != nullptr) {
            QrcodeFree(mask);
        }
        QrcodeFree(data);
    }
}

/**
 * @tc.name: qrcode_mask_find_mask_edge_zeros_043
 * @tc.desc: Verify finding mask with zeros on edges.
 * @tc.type: FUNC
 * @tc.require: issueI000005
 */
HWTEST_F(QrcodeMaskTest, qrcode_mask_find_mask_edge_zeros_043, TestSize.Level1)
{
    int32_t width = 21;
    uint8_t *data = (uint8_t *)QrcodeMalloc(width * width);
    EXPECT_NE(data, nullptr);
    if (data != nullptr) {
        (void)memset_s(data, width * width, 1, width * width);
        for (int32_t i = 0; i < width; i++) {
            data[i] = 0;
            data[i * width] = 0;
            data[(width - 1) * width + i] = 0;
            data[i * width + (width - 1)] = 0;
        }
        uint8_t *mask = QrcodeMaskFindMask(width, data);
        EXPECT_NE(mask, nullptr);
        if (mask != nullptr) {
            QrcodeFree(mask);
        }
        QrcodeFree(data);
    }
}

/**
 * @tc.name: qrcode_mask_find_mask_center_pattern_044
 * @tc.desc: Verify finding mask with pattern in center.
 * @tc.type: FUNC
 * @tc.require: issueI000005
 */
HWTEST_F(QrcodeMaskTest, qrcode_mask_find_mask_center_pattern_044, TestSize.Level1)
{
    int32_t width = 21;
    uint8_t *data = (uint8_t *)QrcodeMalloc(width * width);
    EXPECT_NE(data, nullptr);
    if (data != nullptr) {
        (void)memset_s(data, width * width, 0, width * width);
        for (int32_t y = 7; y < 14; y++) {
            for (int32_t x = 7; x < 14; x++) {
                data[y * width + x] = 1;
            }
        }
        uint8_t *mask = QrcodeMaskFindMask(width, data);
        EXPECT_NE(mask, nullptr);
        if (mask != nullptr) {
            QrcodeFree(mask);
        }
        QrcodeFree(data);
    }
}

/**
 * @tc.name: qrcode_mask_find_mask_corner_pattern_045
 * @tc.desc: Verify finding mask with pattern in corners.
 * @tc.type: FUNC
 * @tc.require: issueI000005
 */
HWTEST_F(QrcodeMaskTest, qrcode_mask_find_mask_corner_pattern_045, TestSize.Level1)
{
    int32_t width = 21;
    uint8_t *data = (uint8_t *)QrcodeMalloc(width * width);
    EXPECT_NE(data, nullptr);
    if (data != nullptr) {
        (void)memset_s(data, width * width, 0, width * width);
        for (int32_t y = 0; y < 7; y++) {
            for (int32_t x = 0; x < 7; x++) {
                data[y * width + x] = 1;
                data[y * width + (width - 7 + x)] = 1;
                data[(width - 7 + y) * width + x] = 1;
            }
        }
        uint8_t *mask = QrcodeMaskFindMask(width, data);
        EXPECT_NE(mask, nullptr);
        if (mask != nullptr) {
            QrcodeFree(mask);
        }
        QrcodeFree(data);
    }
}

/**
 * @tc.name: qrcode_mask_find_mask_single_row_046
 * @tc.desc: Verify finding mask with single row of ones.
 * @tc.type: FUNC
 * @tc.require: issueI000005
 */
HWTEST_F(QrcodeMaskTest, qrcode_mask_find_mask_single_row_046, TestSize.Level1)
{
    int32_t width = 21;
    uint8_t *data = (uint8_t *)QrcodeMalloc(width * width);
    EXPECT_NE(data, nullptr);
    if (data != nullptr) {
        (void)memset_s(data, width * width, 0, width * width);
        for (int32_t x = 0; x < width; x++) {
            data[10 * width + x] = 1;
        }
        uint8_t *mask = QrcodeMaskFindMask(width, data);
        EXPECT_NE(mask, nullptr);
        if (mask != nullptr) {
            QrcodeFree(mask);
        }
        QrcodeFree(data);
    }
}

/**
 * @tc.name: qrcode_mask_find_mask_single_column_047
 * @tc.desc: Verify finding mask with single column of ones.
 * @tc.type: FUNC
 * @tc.require: issueI000005
 */
HWTEST_F(QrcodeMaskTest, qrcode_mask_find_mask_single_column_047, TestSize.Level1)
{
    int32_t width = 21;
    uint8_t *data = (uint8_t *)QrcodeMalloc(width * width);
    EXPECT_NE(data, nullptr);
    if (data != nullptr) {
        (void)memset_s(data, width * width, 0, width * width);
        for (int32_t y = 0; y < width; y++) {
            data[y * width + 10] = 1;
        }
        uint8_t *mask = QrcodeMaskFindMask(width, data);
        EXPECT_NE(mask, nullptr);
        if (mask != nullptr) {
            QrcodeFree(mask);
        }
        QrcodeFree(data);
    }
}

/**
 * @tc.name: qrcode_mask_find_mask_cross_pattern_048
 * @tc.desc: Verify finding mask with cross pattern.
 * @tc.type: FUNC
 * @tc.require: issueI000005
 */
HWTEST_F(QrcodeMaskTest, qrcode_mask_find_mask_cross_pattern_048, TestSize.Level1)
{
    int32_t width = 21;
    uint8_t *data = (uint8_t *)QrcodeMalloc(width * width);
    EXPECT_NE(data, nullptr);
    if (data != nullptr) {
        (void)memset_s(data, width * width, 0, width * width);
        for (int32_t i = 0; i < width; i++) {
            data[10 * width + i] = 1;
            data[i * width + 10] = 1;
        }
        uint8_t *mask = QrcodeMaskFindMask(width, data);
        EXPECT_NE(mask, nullptr);
        if (mask != nullptr) {
            QrcodeFree(mask);
        }
        QrcodeFree(data);
    }
}

/**
 * @tc.name: qrcode_mask_find_mask_diagonal_line_049
 * @tc.desc: Verify finding mask with diagonal line.
 * @tc.type: FUNC
 * @tc.require: issueI000005
 */
HWTEST_F(QrcodeMaskTest, qrcode_mask_find_mask_diagonal_line_049, TestSize.Level1)
{
    int32_t width = 21;
    uint8_t *data = (uint8_t *)QrcodeMalloc(width * width);
    EXPECT_NE(data, nullptr);
    if (data != nullptr) {
        (void)memset_s(data, width * width, 0, width * width);
        for (int32_t i = 0; i < width; i++) {
            data[i * width + i] = 1;
        }
        uint8_t *mask = QrcodeMaskFindMask(width, data);
        EXPECT_NE(mask, nullptr);
        if (mask != nullptr) {
            QrcodeFree(mask);
        }
        QrcodeFree(data);
    }
}

/**
 * @tc.name: qrcode_mask_find_mask_anti_diagonal_050
 * @tc.desc: Verify finding mask with anti-diagonal line.
 * @tc.type: FUNC
 * @tc.require: issueI000005
 */
HWTEST_F(QrcodeMaskTest, qrcode_mask_find_mask_anti_diagonal_050, TestSize.Level1)
{
    int32_t width = 21;
    uint8_t *data = (uint8_t *)QrcodeMalloc(width * width);
    EXPECT_NE(data, nullptr);
    if (data != nullptr) {
        (void)memset_s(data, width * width, 0, width * width);
        for (int32_t i = 0; i < width; i++) {
            data[i * width + (width - 1 - i)] = 1;
        }
        uint8_t *mask = QrcodeMaskFindMask(width, data);
        EXPECT_NE(mask, nullptr);
        if (mask != nullptr) {
            QrcodeFree(mask);
        }
        QrcodeFree(data);
    }
}

/**
 * @tc.name: qrcode_mask_find_mask_chessboard_051
 * @tc.desc: Verify finding mask with chessboard pattern.
 * @tc.type: FUNC
 * @tc.require: issueI000005
 */
HWTEST_F(QrcodeMaskTest, qrcode_mask_find_mask_chessboard_051, TestSize.Level1)
{
    int32_t width = 21;
    uint8_t *data = (uint8_t *)QrcodeMalloc(width * width);
    EXPECT_NE(data, nullptr);
    if (data != nullptr) {
        for (int32_t y = 0; y < width; y++) {
            for (int32_t x = 0; x < width; x++) {
                data[y * width + x] = ((y / 2) + (x / 2)) % 2;
            }
        }
        uint8_t *mask = QrcodeMaskFindMask(width, data);
        EXPECT_NE(mask, nullptr);
        if (mask != nullptr) {
            QrcodeFree(mask);
        }
        QrcodeFree(data);
    }
}

/**
 * @tc.name: qrcode_mask_find_mask_gradient_052
 * @tc.desc: Verify finding mask with gradient pattern.
 * @tc.type: FUNC
 * @tc.require: issueI000005
 */
HWTEST_F(QrcodeMaskTest, qrcode_mask_find_mask_gradient_052, TestSize.Level1)
{
    int32_t width = 21;
    uint8_t *data = (uint8_t *)QrcodeMalloc(width * width);
    EXPECT_NE(data, nullptr);
    if (data != nullptr) {
        for (int32_t y = 0; y < width; y++) {
            for (int32_t x = 0; x < width; x++) {
                data[y * width + x] = ((x + y) % 10) < 5 ? 1 : 0;
            }
        }
        uint8_t *mask = QrcodeMaskFindMask(width, data);
        EXPECT_NE(mask, nullptr);
        if (mask != nullptr) {
            QrcodeFree(mask);
        }
        QrcodeFree(data);
    }
}

/**
 * @tc.name: qrcode_mask_find_mask_ring_pattern_053
 * @tc.desc: Verify finding mask with ring pattern.
 * @tc.type: FUNC
 * @tc.require: issueI000005
 */
HWTEST_F(QrcodeMaskTest, qrcode_mask_find_mask_ring_pattern_053, TestSize.Level1)
{
    int32_t width = 21;
    uint8_t *data = (uint8_t *)QrcodeMalloc(width * width);
    EXPECT_NE(data, nullptr);
    if (data != nullptr) {
        (void)memset_s(data, width * width, 0, width * width);
        int32_t center = width / 2;
        for (int32_t y = 0; y < width; y++) {
            for (int32_t x = 0; x < width; x++) {
                int32_t dist = abs(x - center) + abs(y - center);
                if (dist == 5 || dist == 6) {
                    data[y * width + x] = 1;
                }
            }
        }
        uint8_t *mask = QrcodeMaskFindMask(width, data);
        EXPECT_NE(mask, nullptr);
        if (mask != nullptr) {
            QrcodeFree(mask);
        }
        QrcodeFree(data);
    }
}

/**
 * @tc.name: qrcode_mask_find_mask_isolated_ones_054
 * @tc.desc: Verify finding mask with isolated ones.
 * @tc.type: FUNC
 * @tc.require: issueI000005
 */
HWTEST_F(QrcodeMaskTest, qrcode_mask_find_mask_isolated_ones_054, TestSize.Level1)
{
    int32_t width = 21;
    uint8_t *data = (uint8_t *)QrcodeMalloc(width * width);
    EXPECT_NE(data, nullptr);
    if (data != nullptr) {
        (void)memset_s(data, width * width, 0, width * width);
        for (int32_t y = 2; y < width; y += 3) {
            for (int32_t x = 2; x < width; x += 3) {
                data[y * width + x] = 1;
            }
        }
        uint8_t *mask = QrcodeMaskFindMask(width, data);
        EXPECT_NE(mask, nullptr);
        if (mask != nullptr) {
            QrcodeFree(mask);
        }
        QrcodeFree(data);
    }
}

/**
 * @tc.name: qrcode_mask_find_mask_dense_ones_055
 * @tc.desc: Verify finding mask with dense ones.
 * @tc.type: FUNC
 * @tc.require: issueI000005
 */
HWTEST_F(QrcodeMaskTest, qrcode_mask_find_mask_dense_ones_055, TestSize.Level1)
{
    int32_t width = 21;
    uint8_t *data = (uint8_t *)QrcodeMalloc(width * width);
    EXPECT_NE(data, nullptr);
    if (data != nullptr) {
        for (int32_t i = 0; i < width * width; i++) {
            data[i] = (i % 2 == 0) ? 1 : 0;
        }
        uint8_t *mask = QrcodeMaskFindMask(width, data);
        EXPECT_NE(mask, nullptr);
        if (mask != nullptr) {
            QrcodeFree(mask);
        }
        QrcodeFree(data);
    }
}

/**
 * @tc.name: qrcode_mask_find_mask_sparse_ones_056
 * @tc.desc: Verify finding mask with sparse ones.
 * @tc.type: FUNC
 * @tc.require: issueI000005
 */
HWTEST_F(QrcodeMaskTest, qrcode_mask_find_mask_sparse_ones_056, TestSize.Level1)
{
    int32_t width = 21;
    uint8_t *data = (uint8_t *)QrcodeMalloc(width * width);
    EXPECT_NE(data, nullptr);
    if (data != nullptr) {
        (void)memset_s(data, width * width, 0, width * width);
        for (int32_t i = 0; i < width * width; i += 10) {
            data[i] = 1;
        }
        uint8_t *mask = QrcodeMaskFindMask(width, data);
        EXPECT_NE(mask, nullptr);
        if (mask != nullptr) {
            QrcodeFree(mask);
        }
        QrcodeFree(data);
    }
}

/**
 * @tc.name: qrcode_mask_find_mask_wave_pattern_057
 * @tc.desc: Verify finding mask with wave pattern.
 * @tc.type: FUNC
 * @tc.require: issueI000005
 */
HWTEST_F(QrcodeMaskTest, qrcode_mask_find_mask_wave_pattern_057, TestSize.Level1)
{
    int32_t width = 21;
    uint8_t *data = (uint8_t *)QrcodeMalloc(width * width);
    EXPECT_NE(data, nullptr);
    if (data != nullptr) {
        for (int32_t y = 0; y < width; y++) {
            for (int32_t x = 0; x < width; x++) {
                data[y * width + x] = (x + (y % 3)) % 2;
            }
        }
        uint8_t *mask = QrcodeMaskFindMask(width, data);
        EXPECT_NE(mask, nullptr);
        if (mask != nullptr) {
            QrcodeFree(mask);
        }
        QrcodeFree(data);
    }
}

/**
 * @tc.name: qrcode_mask_find_mask_triangle_pattern_058
 * @tc.desc: Verify finding mask with triangle pattern.
 * @tc.type: FUNC
 * @tc.require: issueI000005
 */
HWTEST_F(QrcodeMaskTest, qrcode_mask_find_mask_triangle_pattern_058, TestSize.Level1)
{
    int32_t width = 21;
    uint8_t *data = (uint8_t *)QrcodeMalloc(width * width);
    EXPECT_NE(data, nullptr);
    if (data != nullptr) {
        (void)memset_s(data, width * width, 0, width * width);
        for (int32_t y = 0; y < width / 2; y++) {
            for (int32_t x = width / 2 - y; x <= width / 2 + y; x++) {
                if (x >= 0 && x < width) {
                    data[y * width + x] = 1;
                }
            }
        }
        uint8_t *mask = QrcodeMaskFindMask(width, data);
        EXPECT_NE(mask, nullptr);
        if (mask != nullptr) {
            QrcodeFree(mask);
        }
        QrcodeFree(data);
    }
}

/**
 * @tc.name: qrcode_mask_find_mask_inverse_triangle_059
 * @tc.desc: Verify finding mask with inverse triangle pattern.
 * @tc.type: FUNC
 * @tc.require: issueI000005
 */
HWTEST_F(QrcodeMaskTest, qrcode_mask_find_mask_inverse_triangle_059, TestSize.Level1)
{
    int32_t width = 21;
    uint8_t *data = (uint8_t *)QrcodeMalloc(width * width);
    EXPECT_NE(data, nullptr);
    if (data != nullptr) {
        (void)memset_s(data, width * width, 0, width * width);
        for (int32_t y = width / 2; y < width; y++) {
            int32_t row = y - width / 2;
            for (int32_t x = row; x < width - row; x++) {
                data[y * width + x] = 1;
            }
        }
        uint8_t *mask = QrcodeMaskFindMask(width, data);
        EXPECT_NE(mask, nullptr);
        if (mask != nullptr) {
            QrcodeFree(mask);
        }
        QrcodeFree(data);
    }
}

/**
 * @tc.name: qrcode_mask_find_mask_diamond_pattern_060
 * @tc.desc: Verify finding mask with diamond pattern.
 * @tc.type: FUNC
 * @tc.require: issueI000005
 */
HWTEST_F(QrcodeMaskTest, qrcode_mask_find_mask_diamond_pattern_060, TestSize.Level1)
{
    int32_t width = 21;
    uint8_t *data = (uint8_t *)QrcodeMalloc(width * width);
    EXPECT_NE(data, nullptr);
    if (data != nullptr) {
        (void)memset_s(data, width * width, 0, width * width);
        int32_t center = width / 2;
        for (int32_t y = 0; y < width; y++) {
            int32_t dist = abs(y - center);
            for (int32_t x = center - dist; x <= center + dist; x++) {
                if (x >= 0 && x < width) {
                    data[y * width + x] = 1;
                }
            }
        }
        uint8_t *mask = QrcodeMaskFindMask(width, data);
        EXPECT_NE(mask, nullptr);
        if (mask != nullptr) {
            QrcodeFree(mask);
        }
        QrcodeFree(data);
    }
}

/**
 * @tc.name: qrcode_mask_find_mask_star_pattern_061
 * @tc.desc: Verify finding mask with star pattern.
 * @tc.type: FUNC
 * @tc.require: issueI000005
 */
HWTEST_F(QrcodeMaskTest, qrcode_mask_find_mask_star_pattern_061, TestSize.Level1)
{
    int32_t width = 21;
    uint8_t *data = (uint8_t *)QrcodeMalloc(width * width);
    EXPECT_NE(data, nullptr);
    if (data != nullptr) {
        (void)memset_s(data, width * width, 0, width * width);
        int32_t center = width / 2;
        for (int32_t y = 0; y < width; y++) {
            for (int32_t x = 0; x < width; x++) {
                int32_t dist = abs(x - center) + abs(y - center);
                if (dist <= 3 || dist >= 8) {
                    data[y * width + x] = 1;
                }
            }
        }
        uint8_t *mask = QrcodeMaskFindMask(width, data);
        EXPECT_NE(mask, nullptr);
        if (mask != nullptr) {
            QrcodeFree(mask);
        }
        QrcodeFree(data);
    }
}

/**
 * @tc.name: qrcode_mask_find_mask_zigzag_062
 * @tc.desc: Verify finding mask with zigzag pattern.
 * @tc.type: FUNC
 * @tc.require: issueI000005
 */
HWTEST_F(QrcodeMaskTest, qrcode_mask_find_mask_zigzag_062, TestSize.Level1)
{
    int32_t width = 21;
    uint8_t *data = (uint8_t *)QrcodeMalloc(width * width);
    EXPECT_NE(data, nullptr);
    if (data != nullptr) {
        for (int32_t y = 0; y < width; y++) {
            for (int32_t x = 0; x < width; x++) {
                data[y * width + x] = (x + (y % 2) * width) % 2;
            }
        }
        uint8_t *mask = QrcodeMaskFindMask(width, data);
        EXPECT_NE(mask, nullptr);
        if (mask != nullptr) {
            QrcodeFree(mask);
        }
        QrcodeFree(data);
    }
}

/**
 * @tc.name: qrcode_mask_find_mask_concentric_squares_063
 * @tc.desc: Verify finding mask with concentric squares.
 * @tc.type: FUNC
 * @tc.require: issueI000005
 */
HWTEST_F(QrcodeMaskTest, qrcode_mask_find_mask_concentric_squares_063, TestSize.Level1)
{
    int32_t width = 21;
    uint8_t *data = (uint8_t *)QrcodeMalloc(width * width);
    EXPECT_NE(data, nullptr);
    if (data != nullptr) {
        (void)memset_s(data, width * width, 0, width * width);
        for (int32_t i = 2; i < width / 2; i += 2) {
            for (int32_t y = i; y < width - i; y++) {
                for (int32_t x = i; x < width - i; x++) {
                    if (y == i || y == width - i - 1 || x == i || x == width - i - 1) {
                        data[y * width + x] = 1;
                    }
                }
            }
        }
        uint8_t *mask = QrcodeMaskFindMask(width, data);
        EXPECT_NE(mask, nullptr);
        if (mask != nullptr) {
            QrcodeFree(mask);
        }
        QrcodeFree(data);
    }
}

/**
 * @tc.name: qrcode_mask_find_mask_random_blocks_064
 * @tc.desc: Verify finding mask with random blocks.
 * @tc.type: FUNC
 * @tc.require: issueI000005
 */
HWTEST_F(QrcodeMaskTest, qrcode_mask_find_mask_random_blocks_064, TestSize.Level1)
{
    int32_t width = 21;
    uint8_t *data = (uint8_t *)QrcodeMalloc(width * width);
    EXPECT_NE(data, nullptr);
    if (data != nullptr) {
        (void)memset_s(data, width * width, 0, width * width);
        for (int32_t y = 0; y < width; y += 3) {
            for (int32_t x = 0; x < width; x += 3) {
                for (int32_t dy = 0; dy < 2 && y + dy < width; dy++) {
                    for (int32_t dx = 0; dx < 2 && x + dx < width; dx++) {
                        data[(y + dy) * width + (x + dx)] = 1;
                    }
                }
            }
        }
        uint8_t *mask = QrcodeMaskFindMask(width, data);
        EXPECT_NE(mask, nullptr);
        if (mask != nullptr) {
            QrcodeFree(mask);
        }
        QrcodeFree(data);
    }
}

/**
 * @tc.name: qrcode_mask_find_mask_mixed_high_low_bits_065
 * @tc.desc: Verify finding mask with mixed high and low bits.
 * @tc.type: FUNC
 * @tc.require: issueI000005
 */
HWTEST_F(QrcodeMaskTest, qrcode_mask_find_mask_mixed_high_low_bits_065, TestSize.Level1)
{
    int32_t width = 21;
    uint8_t *data = (uint8_t *)QrcodeMalloc(width * width);
    EXPECT_NE(data, nullptr);
    if (data != nullptr) {
        for (int32_t i = 0; i < width * width; i++) {
            data[i] = (i % 4 == 0) ? 0x80 : (i % 2);
        }
        uint8_t *mask = QrcodeMaskFindMask(width, data);
        EXPECT_NE(mask, nullptr);
        if (mask != nullptr) {
            QrcodeFree(mask);
        }
        QrcodeFree(data);
    }
}

/**
 * @tc.name: qrcode_mask_find_mask_null_data_repeated_066
 * @tc.desc: Verify finding mask with null data (repeated test).
 * @tc.type: FUNC
 * @tc.require: issueI000005
 */
HWTEST_F(QrcodeMaskTest, qrcode_mask_find_mask_null_data_repeated_066, TestSize.Level1)
{
    uint8_t *mask = QrcodeMaskFindMask(21, nullptr);
    EXPECT_EQ(mask, nullptr);
}

/**
 * @tc.name: qrcode_mask_find_mask_null_data_zero_width_067
 * @tc.desc: Verify finding mask with null data and zero width.
 * @tc.type: FUNC
 * @tc.require: issueI000005
 */
HWTEST_F(QrcodeMaskTest, qrcode_mask_find_mask_null_data_zero_width_067, TestSize.Level1)
{
    uint8_t *mask = QrcodeMaskFindMask(0, nullptr);
    EXPECT_EQ(mask, nullptr);
}

/**
 * @tc.name: qrcode_mask_find_mask_null_data_negative_width_068
 * @tc.desc: Verify finding mask with null data and negative width.
 * @tc.type: FUNC
 * @tc.require: issueI000005
 */
HWTEST_F(QrcodeMaskTest, qrcode_mask_find_mask_null_data_negative_width_068, TestSize.Level1)
{
    uint8_t *mask = QrcodeMaskFindMask(-5, nullptr);
    EXPECT_EQ(mask, nullptr);
}

/**
 * @tc.name: qrcode_mask_find_mask_null_data_large_width_069
 * @tc.desc: Verify finding mask with null data and large width.
 * @tc.type: FUNC
 * @tc.require: issueI000005
 */
HWTEST_F(QrcodeMaskTest, qrcode_mask_find_mask_null_data_large_width_069, TestSize.Level1)
{
    uint8_t *mask = QrcodeMaskFindMask(1000, nullptr);
    EXPECT_EQ(mask, nullptr);
}

/**
 * @tc.name: qrcode_mask_find_mask_null_data_min_width_070
 * @tc.desc: Verify finding mask with null data and minimum width.
 * @tc.type: FUNC
 * @tc.require: issueI000005
 */
HWTEST_F(QrcodeMaskTest, qrcode_mask_find_mask_null_data_min_width_070, TestSize.Level1)
{
    uint8_t *mask = QrcodeMaskFindMask(1, nullptr);
    EXPECT_EQ(mask, nullptr);
}

/**
 * @tc.name: qrcode_mask_find_mask_null_data_version_1_width_071
 * @tc.desc: Verify finding mask with null data and version 1 width.
 * @tc.type: FUNC
 * @tc.require: issueI000005
 */
HWTEST_F(QrcodeMaskTest, qrcode_mask_find_mask_null_data_version_1_width_071, TestSize.Level1)
{
    uint8_t *mask = QrcodeMaskFindMask(21, nullptr);
    EXPECT_EQ(mask, nullptr);
}

/**
 * @tc.name: qrcode_mask_find_mask_null_data_version_40_width_072
 * @tc.desc: Verify finding mask with null data and version 40 width.
 * @tc.type: FUNC
 * @tc.require: issueI000005
 */
HWTEST_F(QrcodeMaskTest, qrcode_mask_find_mask_null_data_version_40_width_072, TestSize.Level1)
{
    uint8_t *mask = QrcodeMaskFindMask(177, nullptr);
    EXPECT_EQ(mask, nullptr);
}

/**
 * @tc.name: qrcode_mask_find_mask_null_data_boundary_width_073
 * @tc.desc: Verify finding mask with null data and boundary width values.
 * @tc.type: FUNC
 * @tc.require: issueI000005
 */
HWTEST_F(QrcodeMaskTest, qrcode_mask_find_mask_null_data_boundary_width_073, TestSize.Level1)
{
    uint8_t *mask = QrcodeMaskFindMask(2, nullptr);
    EXPECT_EQ(mask, nullptr);
    mask = QrcodeMaskFindMask(3, nullptr);
    EXPECT_EQ(mask, nullptr);
    mask = QrcodeMaskFindMask(4, nullptr);
    EXPECT_EQ(mask, nullptr);
}

/**
 * @tc.name: qrcode_mask_find_mask_null_data_various_widths_074
 * @tc.desc: Verify finding mask with null data and various width values.
 * @tc.type: FUNC
 * @tc.require: issueI000005
 */
HWTEST_F(QrcodeMaskTest, qrcode_mask_find_mask_null_data_various_widths_074, TestSize.Level1)
{
    uint8_t *mask = QrcodeMaskFindMask(10, nullptr);
    EXPECT_EQ(mask, nullptr);
    mask = QrcodeMaskFindMask(15, nullptr);
    EXPECT_EQ(mask, nullptr);
    mask = QrcodeMaskFindMask(20, nullptr);
    EXPECT_EQ(mask, nullptr);
    mask = QrcodeMaskFindMask(25, nullptr);
    EXPECT_EQ(mask, nullptr);
    mask = QrcodeMaskFindMask(30, nullptr);
    EXPECT_EQ(mask, nullptr);
}

/**
 * @tc.name: qrcode_mask_find_mask_null_data_max_width_075
 * @tc.desc: Verify finding mask with null data and max width.
 * @tc.type: FUNC
 * @tc.require: issueI000005
 */
HWTEST_F(QrcodeMaskTest, qrcode_mask_find_mask_null_data_max_width_075, TestSize.Level1)
{
    uint8_t *mask = QrcodeMaskFindMask(INT32_MAX, nullptr);
    EXPECT_EQ(mask, nullptr);
}

/**
 * @tc.name: qrcode_mask_find_mask_null_data_min_int_width_076
 * @tc.desc: Verify finding mask with null data and min int width.
 * @tc.type: FUNC
 * @tc.require: issueI000005
 */
HWTEST_F(QrcodeMaskTest, qrcode_mask_find_mask_null_data_min_int_width_076, TestSize.Level1)
{
    uint8_t *mask = QrcodeMaskFindMask(INT32_MIN, nullptr);
    EXPECT_EQ(mask, nullptr);
}

/**
 * @tc.name: qrcode_mask_find_mask_null_data_odd_widths_077
 * @tc.desc: Verify finding mask with null data and odd width values.
 * @tc.type: FUNC
 * @tc.require: issueI000005
 */
HWTEST_F(QrcodeMaskTest, qrcode_mask_find_mask_null_data_odd_widths_077, TestSize.Level1)
{
    uint8_t *mask = QrcodeMaskFindMask(11, nullptr);
    EXPECT_EQ(mask, nullptr);
    mask = QrcodeMaskFindMask(13, nullptr);
    EXPECT_EQ(mask, nullptr);
    mask = QrcodeMaskFindMask(17, nullptr);
    EXPECT_EQ(mask, nullptr);
    mask = QrcodeMaskFindMask(19, nullptr);
    EXPECT_EQ(mask, nullptr);
    mask = QrcodeMaskFindMask(23, nullptr);
    EXPECT_EQ(mask, nullptr);
}

/**
 * @tc.name: qrcode_mask_find_mask_null_data_even_widths_078
 * @tc.desc: Verify finding mask with null data and even width values.
 * @tc.type: FUNC
 * @tc.require: issueI000005
 */
HWTEST_F(QrcodeMaskTest, qrcode_mask_find_mask_null_data_even_widths_078, TestSize.Level1)
{
    uint8_t *mask = QrcodeMaskFindMask(12, nullptr);
    EXPECT_EQ(mask, nullptr);
    mask = QrcodeMaskFindMask(14, nullptr);
    EXPECT_EQ(mask, nullptr);
    mask = QrcodeMaskFindMask(16, nullptr);
    EXPECT_EQ(mask, nullptr);
    mask = QrcodeMaskFindMask(18, nullptr);
    EXPECT_EQ(mask, nullptr);
    mask = QrcodeMaskFindMask(22, nullptr);
    EXPECT_EQ(mask, nullptr);
}

/**
 * @tc.name: qrcode_mask_find_mask_null_data_prime_widths_079
 * @tc.desc: Verify finding mask with null data and prime width values.
 * @tc.type: FUNC
 * @tc.require: issueI000005
 */
HWTEST_F(QrcodeMaskTest, qrcode_mask_find_mask_null_data_prime_widths_079, TestSize.Level1)
{
    uint8_t *mask = QrcodeMaskFindMask(7, nullptr);
    EXPECT_EQ(mask, nullptr);
    mask = QrcodeMaskFindMask(11, nullptr);
    EXPECT_EQ(mask, nullptr);
    mask = QrcodeMaskFindMask(13, nullptr);
    EXPECT_EQ(mask, nullptr);
    mask = QrcodeMaskFindMask(17, nullptr);
    EXPECT_EQ(mask, nullptr);
    mask = QrcodeMaskFindMask(19, nullptr);
    EXPECT_EQ(mask, nullptr);
}

/**
 * @tc.name: qrcode_mask_find_mask_null_data_composite_widths_080
 * @tc.desc: Verify finding mask with null data and composite width values.
 * @tc.type: FUNC
 * @tc.require: issueI000005
 */
HWTEST_F(QrcodeMaskTest, qrcode_mask_find_mask_null_data_composite_widths_080, TestSize.Level1)
{
    uint8_t *mask = QrcodeMaskFindMask(6, nullptr);
    EXPECT_EQ(mask, nullptr);
    mask = QrcodeMaskFindMask(8, nullptr);
    EXPECT_EQ(mask, nullptr);
    mask = QrcodeMaskFindMask(9, nullptr);
    EXPECT_EQ(mask, nullptr);
    mask = QrcodeMaskFindMask(10, nullptr);
    EXPECT_EQ(mask, nullptr);
    mask = QrcodeMaskFindMask(12, nullptr);
    EXPECT_EQ(mask, nullptr);
}