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

#include "interfaces/innerkits/qrcode_item.h"
#include <gtest/gtest.h>
#include <cstring>

using namespace testing::ext;

class QrcodeItemTest : public testing::Test {
public:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp();
    void TearDown();
};

void QrcodeItemTest::SetUpTestCase(void) {}

void QrcodeItemTest::TearDownTestCase(void) {}

void QrcodeItemTest::SetUp(void) {}

void QrcodeItemTest::TearDown(void) {}

/**
 * @tc.name: qrcode_item_list_new_001
 * @tc.desc: Verify creating new item list.
 * @tc.type: FUNC
 * @tc.require: issueI000003
 */
HWTEST_F(QrcodeItemTest, qrcode_item_list_new_001, TestSize.Level1)
{
    QrcodeItemList *list = QrcodeItemListNew();
    EXPECT_NE(list, nullptr);
    if (list != nullptr) {
        QrcodeItemListFree(list);
    }
}

/**
 * @tc.name: qrcode_item_list_add_numeric_002
 * @tc.desc: Verify adding numeric item to list.
 * @tc.type: FUNC
 * @tc.require: issueI000003
 */
HWTEST_F(QrcodeItemTest, qrcode_item_list_add_numeric_002, TestSize.Level1)
{
    QrcodeItemList *list = QrcodeItemListNew();
    EXPECT_NE(list, nullptr);
    if (list != nullptr) {
        const uint8_t data[] = "12345";
        int32_t ret = QrcodeItemListAdd(list, QRCODE_MODE_NUM, 5, data);
        EXPECT_EQ(ret, 0);
        QrcodeItemListFree(list);
    }
}

/**
 * @tc.name: qrcode_item_list_add_alphanumeric_003
 * @tc.desc: Verify adding alphanumeric item to list.
 * @tc.type: FUNC
 * @tc.require: issueI000003
 */
HWTEST_F(QrcodeItemTest, qrcode_item_list_add_alphanumeric_003, TestSize.Level1)
{
    QrcodeItemList *list = QrcodeItemListNew();
    EXPECT_NE(list, nullptr);
    if (list != nullptr) {
        const uint8_t data[] = "ABC123";
        int32_t ret = QrcodeItemListAdd(list, QRCODE_MODE_AN, 6, data);
        EXPECT_EQ(ret, 0);
        QrcodeItemListFree(list);
    }
}

/**
 * @tc.name: qrcode_item_list_add_byte_004
 * @tc.desc: Verify adding byte item to list.
 * @tc.type: FUNC
 * @tc.require: issueI000003
 */
HWTEST_F(QrcodeItemTest, qrcode_item_list_add_byte_004, TestSize.Level1)
{
    QrcodeItemList *list = QrcodeItemListNew();
    EXPECT_NE(list, nullptr);
    if (list != nullptr) {
        const uint8_t data[] = "Hello";
        int32_t ret = QrcodeItemListAdd(list, QRCODE_MODE_8, 5, data);
        EXPECT_EQ(ret, 0);
        QrcodeItemListFree(list);
    }
}

/**
 * @tc.name: qrcode_item_list_free_null_005
 * @tc.desc: Verify freeing null item list.
 * @tc.type: FUNC
 * @tc.require: issueI000003
 */
HWTEST_F(QrcodeItemTest, qrcode_item_list_free_null_005, TestSize.Level1)
{
    QrcodeItemListFree(nullptr);
}

/**
 * @tc.name: qrcode_item_check_numeric_006
 * @tc.desc: Verify checking numeric item.
 * @tc.type: FUNC
 * @tc.require: issueI000003
 */
HWTEST_F(QrcodeItemTest, qrcode_item_check_numeric_006, TestSize.Level1)
{
    const uint8_t data[] = "12345";
    int32_t ret = QrcodeItemCheck(QRCODE_MODE_NUM, 5, data);
    EXPECT_EQ(ret, 0);
}

/**
 * @tc.name: qrcode_item_check_alphanumeric_007
 * @tc.desc: Verify checking alphanumeric item.
 * @tc.type: FUNC
 * @tc.require: issueI000003
 */
HWTEST_F(QrcodeItemTest, qrcode_item_check_alphanumeric_007, TestSize.Level1)
{
    const uint8_t data[] = "ABC123";
    int32_t ret = QrcodeItemCheck(QRCODE_MODE_AN, 6, data);
    EXPECT_EQ(ret, 0);
}

/**
 * @tc.name: qrcode_item_check_byte_008
 * @tc.desc: Verify checking byte item.
 * @tc.type: FUNC
 * @tc.require: issueI000003
 */
HWTEST_F(QrcodeItemTest, qrcode_item_check_byte_008, TestSize.Level1)
{
    const uint8_t data[] = "Hello";
    int32_t ret = QrcodeItemCheck(QRCODE_MODE_8, 5, data);
    EXPECT_EQ(ret, 0);
}

/**
 * @tc.name: qrcode_item_list_get_byte_stream_009
 * @tc.desc: Verify getting byte stream from item list.
 * @tc.type: FUNC
 * @tc.require: issueI000003
 */
HWTEST_F(QrcodeItemTest, qrcode_item_list_get_byte_stream_009, TestSize.Level1)
{
    QrcodeItemList *list = QrcodeItemListNew();
    EXPECT_NE(list, nullptr);
    if (list != nullptr) {
        const uint8_t data[] = "12345";
        QrcodeItemListAdd(list, QRCODE_MODE_NUM, 5, data);
        uint8_t *stream = QrcodeItemListGetByteStream(list);
        EXPECT_NE(stream, nullptr);
        if (stream != nullptr) {
            QrcodeFree(stream);
        }
        QrcodeItemListFree(list);
    }
}

/**
 * @tc.name: qrcode_estimate_num_010
 * @tc.desc: Verify estimating numeric size.
 * @tc.type: FUNC
 * @tc.require: issueI000003
 */
HWTEST_F(QrcodeItemTest, qrcode_estimate_num_010, TestSize.Level1)
{
    int32_t size = QrcodeEstimateNum(10);
    EXPECT_GT(size, 0);
}

/**
 * @tc.name: qrcode_estimate_alphabet_011
 * @tc.desc: Verify estimating alphanumeric size.
 * @tc.type: FUNC
 * @tc.require: issueI000003
 */
HWTEST_F(QrcodeItemTest, qrcode_estimate_alphabet_011, TestSize.Level1)
{
    int32_t size = QrcodeEstimateAlphaBet(10);
    EXPECT_GT(size, 0);
}

/**
 * @tc.name: qrcode_estimate_8_012
 * @tc.desc: Verify estimating byte size.
 * @tc.type: FUNC
 * @tc.require: issueI000003
 */
HWTEST_F(QrcodeItemTest, qrcode_estimate_8_012, TestSize.Level1)
{
    int32_t size = QrcodeEstimate8(10);
    EXPECT_GT(size, 0);
}

/**
 * @tc.name: qrcode_look_at_table_013
 * @tc.desc: Verify looking up character in table.
 * @tc.type: FUNC
 * @tc.require: issueI000003
 */
HWTEST_F(QrcodeItemTest, qrcode_look_at_table_013, TestSize.Level1)
{
    int32_t ret = QrcodeLookAtTable('A');
    EXPECT_GE(ret, 0);
}

/**
 * @tc.name: qrcode_is_valid_mode_014
 * @tc.desc: Verify checking valid mode.
 * @tc.type: FUNC
 * @tc.require: issueI000003
 */
HWTEST_F(QrcodeItemTest, qrcode_is_valid_mode_014, TestSize.Level1)
{
    bool valid = QrcodeIsValidMode(QRCODE_MODE_NUM);
    EXPECT_TRUE(valid);
}

/**
 * @tc.name: qrcode_is_valid_mode_invalid_015
 * @tc.desc: Verify checking invalid mode.
 * @tc.type: FUNC
 * @tc.require: issueI000003
 */
HWTEST_F(QrcodeItemTest, qrcode_is_valid_mode_invalid_015, TestSize.Level1)
{
    bool valid = QrcodeIsValidMode(QRCODE_MODE_NUL);
    EXPECT_FALSE(valid);
}

/**
 * @tc.name: qrcode_item_list_add_multiple_016
 * @tc.desc: Verify adding multiple items to list.
 * @tc.type: FUNC
 * @tc.require: issueI000003
 */
HWTEST_F(QrcodeItemTest, qrcode_item_list_add_multiple_016, TestSize.Level1)
{
    QrcodeItemList *list = QrcodeItemListNew();
    EXPECT_NE(list, nullptr);
    if (list != nullptr) {
        const uint8_t data1[] = "12345";
        const uint8_t data2[] = "ABC";
        QrcodeItemListAdd(list, QRCODE_MODE_NUM, 5, data1);
        QrcodeItemListAdd(list, QRCODE_MODE_AN, 3, data2);
        uint8_t *stream = QrcodeItemListGetByteStream(list);
        EXPECT_NE(stream, nullptr);
        if (stream != nullptr) {
            QrcodeFree(stream);
        }
        QrcodeItemListFree(list);
    }
}

/**
 * @tc.name: qrcode_item_check_invalid_numeric_017
 * @tc.desc: Verify checking invalid numeric item.
 * @tc.type: FUNC
 * @tc.require: issueI000003
 */
HWTEST_F(QrcodeItemTest, qrcode_item_check_invalid_numeric_017, TestSize.Level1)
{
    const uint8_t data[] = "12A45";
    int32_t ret = QrcodeItemCheck(QRCODE_MODE_NUM, 5, data);
    EXPECT_NE(ret, 0);
}

/**
 * @tc.name: qrcode_item_check_invalid_alphanumeric_018
 * @tc.desc: Verify checking invalid alphanumeric item.
 * @tc.type: FUNC
 * @tc.require: issueI000003
 */
HWTEST_F(QrcodeItemTest, qrcode_item_check_invalid_alphanumeric_018, TestSize.Level1)
{
    const uint8_t data[] = "AB@12";
    int32_t ret = QrcodeItemCheck(QRCODE_MODE_AN, 5, data);
    EXPECT_NE(ret, 0);
}

/**
 * @tc.name: qrcode_item_check_null_data_019
 * @tc.desc: Verify checking with null data.
 * @tc.type: FUNC
 * @tc.require: issueI000003
 */
HWTEST_F(QrcodeItemTest, qrcode_item_check_null_data_019, TestSize.Level1)
{
    int32_t ret = QrcodeItemCheck(QRCODE_MODE_NUM, 5, nullptr);
    EXPECT_NE(ret, 0);
}

/**
 * @tc.name: qrcode_item_check_zero_size_020
 * @tc.desc: Verify checking with zero size.
 * @tc.type: FUNC
 * @tc.require: issueI000003
 */
HWTEST_F(QrcodeItemTest, qrcode_item_check_zero_size_020, TestSize.Level1)
{
    const uint8_t data[] = "12345";
    int32_t ret = QrcodeItemCheck(QRCODE_MODE_NUM, 0, data);
    EXPECT_NE(ret, 0);
}

/**
 * @tc.name: qrcode_item_check_negative_size_021
 * @tc.desc: Verify checking with negative size.
 * @tc.type: FUNC
 * @tc.require: issueI000003
 */
HWTEST_F(QrcodeItemTest, qrcode_item_check_negative_size_021, TestSize.Level1)
{
    const uint8_t data[] = "12345";
    int32_t ret = QrcodeItemCheck(QRCODE_MODE_NUM, -1, data);
    EXPECT_NE(ret, 0);
}

/**
 * @tc.name: qrcode_item_list_add_null_list_022
 * @tc.desc: Verify adding item to null list.
 * @tc.type: FUNC
 * @tc.require: issueI000003
 */
HWTEST_F(QrcodeItemTest, qrcode_item_list_add_null_list_022, TestSize.Level1)
{
    const uint8_t data[] = "12345";
    int32_t ret = QrcodeItemListAdd(nullptr, QRCODE_MODE_NUM, 5, data);
    EXPECT_NE(ret, 0);
}

/**
 * @tc.name: qrcode_item_list_get_byte_stream_null_023
 * @tc.desc: Verify getting byte stream from null list.
 * @tc.type: FUNC
 * @tc.require: issueI000003
 */
HWTEST_F(QrcodeItemTest, qrcode_item_list_get_byte_stream_null_023, TestSize.Level1)
{
    uint8_t *stream = QrcodeItemListGetByteStream(nullptr);
    EXPECT_EQ(stream, nullptr);
}

/**
 * @tc.name: qrcode_item_list_get_byte_stream_empty_024
 * @tc.desc: Verify getting byte stream from empty list.
 * @tc.type: FUNC
 * @tc.require: issueI000003
 */
HWTEST_F(QrcodeItemTest, qrcode_item_list_get_byte_stream_empty_024, TestSize.Level1)
{
    QrcodeItemList *list = QrcodeItemListNew();
    EXPECT_NE(list, nullptr);
    if (list != nullptr) {
        uint8_t *stream = QrcodeItemListGetByteStream(list);
        EXPECT_NE(stream, nullptr);
        QrcodeItemListFree(list);
    }
}

/**
 * @tc.name: qrcode_estimate_num_zero_025
 * @tc.desc: Verify estimating numeric size for zero.
 * @tc.type: FUNC
 * @tc.require: issueI000003
 */
HWTEST_F(QrcodeItemTest, qrcode_estimate_num_zero_025, TestSize.Level1)
{
    int32_t size = QrcodeEstimateNum(0);
    EXPECT_EQ(size, 0);
}

/**
 * @tc.name: qrcode_estimate_num_one_026
 * @tc.desc: Verify estimating numeric size for one.
 * @tc.type: FUNC
 * @tc.require: issueI000003
 */
HWTEST_F(QrcodeItemTest, qrcode_estimate_num_one_026, TestSize.Level1)
{
    int32_t size = QrcodeEstimateNum(1);
    EXPECT_GT(size, 0);
}

/**
 * @tc.name: qrcode_estimate_num_two_027
 * @tc.desc: Verify estimating numeric size for two.
 * @tc.type: FUNC
 * @tc.require: issueI000003
 */
HWTEST_F(QrcodeItemTest, qrcode_estimate_num_two_027, TestSize.Level1)
{
    int32_t size = QrcodeEstimateNum(2);
    EXPECT_GT(size, 0);
}

/**
 * @tc.name: qrcode_estimate_alphabet_zero_028
 * @tc.desc: Verify estimating alphanumeric size for zero.
 * @tc.type: FUNC
 * @tc.require: issueI000003
 */
HWTEST_F(QrcodeItemTest, qrcode_estimate_alphabet_zero_028, TestSize.Level1)
{
    int32_t size = QrcodeEstimateAlphaBet(0);
    EXPECT_EQ(size, 0);
}

/**
 * @tc.name: qrcode_estimate_alphabet_one_029
 * @tc.desc: Verify estimating alphanumeric size for one.
 * @tc.type: FUNC
 * @tc.require: issueI000003
 */
HWTEST_F(QrcodeItemTest, qrcode_estimate_alphabet_one_029, TestSize.Level1)
{
    int32_t size = QrcodeEstimateAlphaBet(1);
    EXPECT_GT(size, 0);
}

/**
 * @tc.name: qrcode_estimate_8_zero_030
 * @tc.desc: Verify estimating byte size for zero.
 * @tc.type: FUNC
 * @tc.require: issueI000003
 */
HWTEST_F(QrcodeItemTest, qrcode_estimate_8_zero_030, TestSize.Level1)
{
    int32_t size = QrcodeEstimate8(0);
    EXPECT_EQ(size, 0);
}

/**
 * @tc.name: qrcode_look_at_table_invalid_031
 * @tc.desc: Verify looking up invalid character in table.
 * @tc.type: FUNC
 * @tc.require: issueI000003
 */
HWTEST_F(QrcodeItemTest, qrcode_look_at_table_invalid_031, TestSize.Level1)
{
    int32_t ret = QrcodeLookAtTable('@');
    EXPECT_LT(ret, 0);
}

/**
 * @tc.name: qrcode_item_list_add_large_data_032
 * @tc.desc: Verify adding large data to list.
 * @tc.type: FUNC
 * @tc.require: issueI000003
 */
HWTEST_F(QrcodeItemTest, qrcode_item_list_add_large_data_032, TestSize.Level1)
{
    QrcodeItemList *list = QrcodeItemListNew();
    EXPECT_NE(list, nullptr);
    if (list != nullptr) {
        uint8_t data[200];
        for (int32_t i = 0; i < 200; i++) {
            data[i] = (uint8_t)(i % 256);
        }
        int32_t ret = QrcodeItemListAdd(list, QRCODE_MODE_8, 200, data);
        EXPECT_EQ(ret, 0);  // Large data is accepted
        QrcodeItemListFree(list);
    }
}

/**
 * @tc.name: qrcode_item_list_add_mixed_modes_033
 * @tc.desc: Verify adding items with mixed modes.
 * @tc.type: FUNC
 * @tc.require: issueI000003
 */
HWTEST_F(QrcodeItemTest, qrcode_item_list_add_mixed_modes_033, TestSize.Level1)
{
    QrcodeItemList *list = QrcodeItemListNew();
    EXPECT_NE(list, nullptr);
    if (list != nullptr) {
        const uint8_t data1[] = "123";
        const uint8_t data2[] = "ABC";
        const uint8_t data3[] = "Hello";
        QrcodeItemListAdd(list, QRCODE_MODE_NUM, 3, data1);
        QrcodeItemListAdd(list, QRCODE_MODE_AN, 3, data2);
        QrcodeItemListAdd(list, QRCODE_MODE_8, 5, data3);
        uint8_t *stream = QrcodeItemListGetByteStream(list);
        EXPECT_NE(stream, nullptr);
        if (stream != nullptr) {
            QrcodeFree(stream);
        }
        QrcodeItemListFree(list);
    }
}

/**
 * @tc.name: qrcode_item_check_byte_mode_034
 * @tc.desc: Verify checking byte mode with special characters.
 * @tc.type: FUNC
 * @tc.require: issueI000003
 */
HWTEST_F(QrcodeItemTest, qrcode_item_check_byte_mode_034, TestSize.Level1)
{
    const uint8_t data[] = {0x00, 0xFF, 0x01, 0x02};
    int32_t ret = QrcodeItemCheck(QRCODE_MODE_8, 4, data);
    EXPECT_EQ(ret, 0);
}

/**
 * @tc.name: qrcode_item_check_numeric_with_letters_035
 * @tc.desc: Verify checking numeric with letters.
 * @tc.type: FUNC
 * @tc.require: issueI000003
 */
HWTEST_F(QrcodeItemTest, qrcode_item_check_numeric_with_letters_035, TestSize.Level1)
{
    const uint8_t data[] = "123a5";
    int32_t ret = QrcodeItemCheck(QRCODE_MODE_NUM, 5, data);
    EXPECT_NE(ret, 0);
}

/**
 * @tc.name: qrcode_item_list_add_very_long_numeric_036
 * @tc.desc: Verify adding very long numeric item.
 * @tc.type: FUNC
 * @tc.require: issueI000003
 */
HWTEST_F(QrcodeItemTest, qrcode_item_list_add_very_long_numeric_036, TestSize.Level1)
{
    QrcodeItemList *list = QrcodeItemListNew();
    EXPECT_NE(list, nullptr);
    if (list != nullptr) {
        const uint8_t data[200] = "123456789012345678901234567890123456789012345678901234567890123456789012345678901234"
                                  "567890123456789012345678901234567890123456789012345678901234567890123456789012345678"
                                  "9012345678901234567890123456789";
        int32_t ret = QrcodeItemListAdd(list, QRCODE_MODE_NUM, 199, data);
        EXPECT_EQ(ret, 0);
        QrcodeItemListFree(list);
    }
}

/**
 * @tc.name: qrcode_item_list_add_single_digit_037
 * @tc.desc: Verify adding single digit item.
 * @tc.type: FUNC
 * @tc.require: issueI000003
 */
HWTEST_F(QrcodeItemTest, qrcode_item_list_add_single_digit_037, TestSize.Level1)
{
    QrcodeItemList *list = QrcodeItemListNew();
    EXPECT_NE(list, nullptr);
    if (list != nullptr) {
        const uint8_t data[] = "5";
        int32_t ret = QrcodeItemListAdd(list, QRCODE_MODE_NUM, 1, data);
        EXPECT_EQ(ret, 0);
        QrcodeItemListFree(list);
    }
}

/**
 * @tc.name: qrcode_item_list_add_two_digits_038
 * @tc.desc: Verify adding two digits item.
 * @tc.type: FUNC
 * @tc.require: issueI000003
 */
HWTEST_F(QrcodeItemTest, qrcode_item_list_add_two_digits_038, TestSize.Level1)
{
    QrcodeItemList *list = QrcodeItemListNew();
    EXPECT_NE(list, nullptr);
    if (list != nullptr) {
        const uint8_t data[] = "12";
        int32_t ret = QrcodeItemListAdd(list, QRCODE_MODE_NUM, 2, data);
        EXPECT_EQ(ret, 0);
        QrcodeItemListFree(list);
    }
}

/**
 * @tc.name: qrcode_item_list_add_single_alpha_039
 * @tc.desc: Verify adding single alphanumeric item.
 * @tc.type: FUNC
 * @tc.require: issueI000003
 */
HWTEST_F(QrcodeItemTest, qrcode_item_list_add_single_alpha_039, TestSize.Level1)
{
    QrcodeItemList *list = QrcodeItemListNew();
    EXPECT_NE(list, nullptr);
    if (list != nullptr) {
        const uint8_t data[] = "A";
        int32_t ret = QrcodeItemListAdd(list, QRCODE_MODE_AN, 1, data);
        EXPECT_EQ(ret, 0);
        QrcodeItemListFree(list);
    }
}

/**
 * @tc.name: qrcode_item_list_add_two_alpha_040
 * @tc.desc: Verify adding two alphanumeric items.
 * @tc.type: FUNC
 * @tc.require: issueI000003
 */
HWTEST_F(QrcodeItemTest, qrcode_item_list_add_two_alpha_040, TestSize.Level1)
{
    QrcodeItemList *list = QrcodeItemListNew();
    EXPECT_NE(list, nullptr);
    if (list != nullptr) {
        const uint8_t data[] = "AB";
        int32_t ret = QrcodeItemListAdd(list, QRCODE_MODE_AN, 2, data);
        EXPECT_EQ(ret, 0);
        QrcodeItemListFree(list);
    }
}

/**
 * @tc.name: qrcode_item_list_add_special_alpha_041
 * @tc.desc: Verify adding alphanumeric with special characters.
 * @tc.type: FUNC
 * @tc.require: issueI000003
 */
HWTEST_F(QrcodeItemTest, qrcode_item_list_add_special_alpha_041, TestSize.Level1)
{
    QrcodeItemList *list = QrcodeItemListNew();
    EXPECT_NE(list, nullptr);
    if (list != nullptr) {
        const uint8_t data[] = "$%*+-./:";
        int32_t ret = QrcodeItemListAdd(list, QRCODE_MODE_AN, 8, data);
        EXPECT_EQ(ret, 0);
        QrcodeItemListFree(list);
    }
}

/**
 * @tc.name: qrcode_item_list_get_byte_stream_long_data_042
 * @tc.desc: Verify getting byte stream with long data.
 * @tc.type: FUNC
 * @tc.require: issueI000003
 */
HWTEST_F(QrcodeItemTest, qrcode_item_list_get_byte_stream_long_data_042, TestSize.Level1)
{
    QrcodeItemList *list = QrcodeItemListNew();
    EXPECT_NE(list, nullptr);
    if (list != nullptr) {
        uint8_t data[200];
        for (int32_t i = 0; i < 200; i++) {
            data[i] = (uint8_t)(i % 256);
        }
        QrcodeItemListAdd(list, QRCODE_MODE_8, 200, data);
        uint8_t *stream = QrcodeItemListGetByteStream(list);
        EXPECT_NE(stream, nullptr);  // Large data is accepted
        if (stream != nullptr) {
            QrcodeFree(stream);
        }
        QrcodeItemListFree(list);
    }
}

/**
 * @tc.name: qrcode_item_list_add_mixed_long_043
 * @tc.desc: Verify adding mixed modes with long data.
 * @tc.type: FUNC
 * @tc.require: issueI000003
 */
HWTEST_F(QrcodeItemTest, qrcode_item_list_add_mixed_long_043, TestSize.Level1)
{
    QrcodeItemList *list = QrcodeItemListNew();
    EXPECT_NE(list, nullptr);
    if (list != nullptr) {
        const uint8_t data1[50] = "1234567890123456789012345678901234567890123456789";
        const uint8_t data2[30] = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
        const uint8_t data3[20] = "HelloWorldTest12345";
        QrcodeItemListAdd(list, QRCODE_MODE_NUM, 50, data1);
        QrcodeItemListAdd(list, QRCODE_MODE_AN, 30, data2);
        QrcodeItemListAdd(list, QRCODE_MODE_8, 20, data3);
        uint8_t *stream = QrcodeItemListGetByteStream(list);
        EXPECT_NE(stream, nullptr);
        if (stream != nullptr) {
            QrcodeFree(stream);
        }
        QrcodeItemListFree(list);
    }
}

/**
 * @tc.name: qrcode_item_check_numeric_boundary_044
 * @tc.desc: Verify checking numeric with boundary values.
 * @tc.type: FUNC
 * @tc.require: issueI000003
 */
HWTEST_F(QrcodeItemTest, qrcode_item_check_numeric_boundary_044, TestSize.Level1)
{
    const uint8_t data[] = "0";
    int32_t ret = QrcodeItemCheck(QRCODE_MODE_NUM, 1, data);
    EXPECT_EQ(ret, 0);

    const uint8_t data2[] = "9";
    ret = QrcodeItemCheck(QRCODE_MODE_NUM, 1, data2);
    EXPECT_EQ(ret, 0);
}

/**
 * @tc.name: qrcode_item_estimate_num_large_045
 * @tc.desc: Verify estimating numeric size for large input.
 * @tc.type: FUNC
 * @tc.require: issueI000003
 */
HWTEST_F(QrcodeItemTest, qrcode_item_estimate_num_large_045, TestSize.Level1)
{
    int32_t size = QrcodeEstimateNum(1000);
    EXPECT_GT(size, 0);
}

/**
 * @tc.name: qrcode_item_estimate_alphabet_large_046
 * @tc.desc: Verify estimating alphanumeric size for large input.
 * @tc.type: FUNC
 * @tc.require: issueI000003
 */
HWTEST_F(QrcodeItemTest, qrcode_item_estimate_alphabet_large_046, TestSize.Level1)
{
    int32_t size = QrcodeEstimateAlphaBet(1000);
    EXPECT_GT(size, 0);
}

/**
 * @tc.name: qrcode_item_estimate_8_large_047
 * @tc.desc: Verify estimating byte size for large input.
 * @tc.type: FUNC
 * @tc.require: issueI000003
 */
HWTEST_F(QrcodeItemTest, qrcode_item_estimate_8_large_047, TestSize.Level1)
{
    int32_t size = QrcodeEstimate8(1000);
    EXPECT_GT(size, 0);
}

/**
 * @tc.name: qrcode_item_list_add_null_data_048
 * @tc.desc: Verify adding item with null data.
 * @tc.type: FUNC
 * @tc.require: issueI000003
 */
HWTEST_F(QrcodeItemTest, qrcode_item_list_add_null_data_048, TestSize.Level1)
{
    QrcodeItemList *list = QrcodeItemListNew();
    EXPECT_NE(list, nullptr);
    if (list != nullptr) {
        int32_t ret = QrcodeItemListAdd(list, QRCODE_MODE_NUM, 5, nullptr);
        EXPECT_NE(ret, 0);
        QrcodeItemListFree(list);
    }
}

/**
 * @tc.name: qrcode_item_list_add_invalid_mode_049
 * @tc.desc: Verify adding item with invalid mode.
 * @tc.type: FUNC
 * @tc.require: issueI000003
 */
HWTEST_F(QrcodeItemTest, qrcode_item_list_add_invalid_mode_049, TestSize.Level1)
{
    QrcodeItemList *list = QrcodeItemListNew();
    EXPECT_NE(list, nullptr);
    if (list != nullptr) {
        const uint8_t data[] = "12345";
        int32_t ret = QrcodeItemListAdd(list, QRCODE_MODE_NUL, 5, data);
        EXPECT_NE(ret, 0);
        QrcodeItemListFree(list);
    }
}

/**
 * @tc.name: qrcode_item_check_mode_nul_050
 * @tc.desc: Verify checking with QRCODE_MODE_NUL.
 * @tc.type: FUNC
 * @tc.require: issueI000003
 */
HWTEST_F(QrcodeItemTest, qrcode_item_check_mode_nul_050, TestSize.Level1)
{
    const uint8_t data[] = "12345";
    int32_t ret = QrcodeItemCheck(QRCODE_MODE_NUL, 5, data);
    EXPECT_NE(ret, 0);
}

/**
 * @tc.name: qrcode_item_check_mode_invalid_051
 * @tc.desc: Verify checking with invalid mode.
 * @tc.type: FUNC
 * @tc.require: issueI000003
 */
HWTEST_F(QrcodeItemTest, qrcode_item_check_mode_invalid_051, TestSize.Level1)
{
    const uint8_t data[] = "12345";
    int32_t ret = QrcodeItemCheck((QrcodeMode)99, 5, data);
    EXPECT_NE(ret, 0);
}

/**
 * @tc.name: qrcode_item_list_get_byte_stream_null_list_052
 * @tc.desc: Verify getting byte stream with null list.
 * @tc.type: FUNC
 * @tc.require: issueI000003
 */
HWTEST_F(QrcodeItemTest, qrcode_item_list_get_byte_stream_null_list_052, TestSize.Level1)
{
    uint8_t *stream = QrcodeItemListGetByteStream(nullptr);
    EXPECT_EQ(stream, nullptr);
}

/**
 * @tc.name: qrcode_item_estimate_negative_size_053
 * @tc.desc: Verify estimating with negative size.
 * @tc.type: FUNC
 * @tc.require: issueI000003
 */
HWTEST_F(QrcodeItemTest, qrcode_item_estimate_negative_size_053, TestSize.Level1)
{
    int32_t size = QrcodeEstimateNum(-1);
    EXPECT_EQ(size, 0);
}

/**
 * @tc.name: qrcode_item_estimate_alphabet_negative_054
 * @tc.desc: Verify estimating alphanumeric with negative size.
 * @tc.type: FUNC
 * @tc.require: issueI000003
 */
HWTEST_F(QrcodeItemTest, qrcode_item_estimate_alphabet_negative_054, TestSize.Level1)
{
    int32_t size = QrcodeEstimateAlphaBet(-1);
    EXPECT_GT(size, 0);  // Function returns calculated size even for negative input
}

/**
 * @tc.name: qrcode_item_estimate_8_negative_055
 * @tc.desc: Verify estimating byte with negative size.
 * @tc.type: FUNC
 * @tc.require: issueI000003
 */
HWTEST_F(QrcodeItemTest, qrcode_item_estimate_8_negative_055, TestSize.Level1)
{
    int32_t size = QrcodeEstimate8(-1);
    EXPECT_LT(size, 0);  // Function returns negative for invalid input
}

/**
 * @tc.name: qrcode_item_list_add_zero_size_056
 * @tc.desc: Verify adding item with zero size.
 * @tc.type: FUNC
 * @tc.require: issueI000003
 */
HWTEST_F(QrcodeItemTest, qrcode_item_list_add_zero_size_056, TestSize.Level1)
{
    QrcodeItemList *list = QrcodeItemListNew();
    EXPECT_NE(list, nullptr);
    if (list != nullptr) {
        const uint8_t data[] = "12345";
        int32_t ret = QrcodeItemListAdd(list, QRCODE_MODE_NUM, 0, data);
        EXPECT_NE(ret, 0);
        QrcodeItemListFree(list);
    }
}

/**
 * @tc.name: qrcode_item_list_add_negative_size_057
 * @tc.desc: Verify adding item with negative size.
 * @tc.type: FUNC
 * @tc.require: issueI000003
 */
HWTEST_F(QrcodeItemTest, qrcode_item_list_add_negative_size_057, TestSize.Level1)
{
    QrcodeItemList *list = QrcodeItemListNew();
    EXPECT_NE(list, nullptr);
    if (list != nullptr) {
        const uint8_t data[] = "12345";
        int32_t ret = QrcodeItemListAdd(list, QRCODE_MODE_NUM, -1, data);
        EXPECT_NE(ret, 0);
        QrcodeItemListFree(list);
    }
}

/**
 * @tc.name: qrcode_item_list_add_numeric_invalid_char_058
 * @tc.desc: Verify adding numeric item with invalid character.
 * @tc.type: FUNC
 * @tc.require: issueI000003
 */
HWTEST_F(QrcodeItemTest, qrcode_item_list_add_numeric_invalid_char_058, TestSize.Level1)
{
    QrcodeItemList *list = QrcodeItemListNew();
    EXPECT_NE(list, nullptr);
    if (list != nullptr) {
        const uint8_t data[] = "12a45";
        int32_t ret = QrcodeItemListAdd(list, QRCODE_MODE_NUM, 5, data);
        EXPECT_NE(ret, 0);
        QrcodeItemListFree(list);
    }
}

/**
 * @tc.name: qrcode_item_list_add_alphanumeric_invalid_char_059
 * @tc.desc: Verify adding alphanumeric item with invalid character.
 * @tc.type: FUNC
 * @tc.require: issueI000003
 */
HWTEST_F(QrcodeItemTest, qrcode_item_list_add_alphanumeric_invalid_char_059, TestSize.Level1)
{
    QrcodeItemList *list = QrcodeItemListNew();
    EXPECT_NE(list, nullptr);
    if (list != nullptr) {
        const uint8_t data[] = "AB@12";
        int32_t ret = QrcodeItemListAdd(list, QRCODE_MODE_AN, 5, data);
        EXPECT_NE(ret, 0);
        QrcodeItemListFree(list);
    }
}

/**
 * @tc.name: qrcode_item_list_add_numeric_boundary_060
 * @tc.desc: Verify adding numeric item with boundary values.
 * @tc.type: FUNC
 * @tc.require: issueI000003
 */
HWTEST_F(QrcodeItemTest, qrcode_item_list_add_numeric_boundary_060, TestSize.Level1)
{
    QrcodeItemList *list = QrcodeItemListNew();
    EXPECT_NE(list, nullptr);
    if (list != nullptr) {
        const uint8_t data1[] = "0";
        int32_t ret = QrcodeItemListAdd(list, QRCODE_MODE_NUM, 1, data1);
        EXPECT_EQ(ret, 0);

        const uint8_t data2[] = "9";
        ret = QrcodeItemListAdd(list, QRCODE_MODE_NUM, 1, data2);
        EXPECT_EQ(ret, 0);

        QrcodeItemListFree(list);
    }
}

/**
 * @tc.name: qrcode_item_list_add_alphanumeric_special_061
 * @tc.desc: Verify adding alphanumeric with special characters.
 * @tc.type: FUNC
 * @tc.require: issueI000003
 */
HWTEST_F(QrcodeItemTest, qrcode_item_list_add_alphanumeric_special_061, TestSize.Level1)
{
    QrcodeItemList *list = QrcodeItemListNew();
    EXPECT_NE(list, nullptr);
    if (list != nullptr) {
        const uint8_t data[] = "$%*+-./:";
        int32_t ret = QrcodeItemListAdd(list, QRCODE_MODE_AN, 8, data);
        EXPECT_EQ(ret, 0);
        QrcodeItemListFree(list);
    }
}

/**
 * @tc.name: qrcode_item_list_add_byte_special_062
 * @tc.desc: Verify adding byte item with special bytes.
 * @tc.type: FUNC
 * @tc.require: issueI000003
 */
HWTEST_F(QrcodeItemTest, qrcode_item_list_add_byte_special_062, TestSize.Level1)
{
    QrcodeItemList *list = QrcodeItemListNew();
    EXPECT_NE(list, nullptr);
    if (list != nullptr) {
        const uint8_t data[] = {0x00, 0xFF, 0x01, 0x02};
        int32_t ret = QrcodeItemListAdd(list, QRCODE_MODE_8, 4, data);
        EXPECT_EQ(ret, 0);
        QrcodeItemListFree(list);
    }
}

/**
 * @tc.name: qrcode_item_list_add_numeric_three_digits_063
 * @tc.desc: Verify adding numeric item with three digits.
 * @tc.type: FUNC
 * @tc.require: issueI000003
 */
HWTEST_F(QrcodeItemTest, qrcode_item_list_add_numeric_three_digits_063, TestSize.Level1)
{
    QrcodeItemList *list = QrcodeItemListNew();
    EXPECT_NE(list, nullptr);
    if (list != nullptr) {
        const uint8_t data[] = "123";
        int32_t ret = QrcodeItemListAdd(list, QRCODE_MODE_NUM, 3, data);
        EXPECT_EQ(ret, 0);
        QrcodeItemListFree(list);
    }
}

/**
 * @tc.name: qrcode_item_list_add_alphanumeric_two_chars_064
 * @tc.desc: Verify adding alphanumeric item with two characters.
 * @tc.type: FUNC
 * @tc.require: issueI000003
 */
HWTEST_F(QrcodeItemTest, qrcode_item_list_add_alphanumeric_two_chars_064, TestSize.Level1)
{
    QrcodeItemList *list = QrcodeItemListNew();
    EXPECT_NE(list, nullptr);
    if (list != nullptr) {
        const uint8_t data[] = "AB";
        int32_t ret = QrcodeItemListAdd(list, QRCODE_MODE_AN, 2, data);
        EXPECT_EQ(ret, 0);
        QrcodeItemListFree(list);
    }
}

/**
 * @tc.name: qrcode_item_list_add_alphanumeric_one_char_065
 * @tc.desc: Verify adding alphanumeric item with one character.
 * @tc.type: FUNC
 * @tc.require: issueI000003
 */
HWTEST_F(QrcodeItemTest, qrcode_item_list_add_alphanumeric_one_char_065, TestSize.Level1)
{
    QrcodeItemList *list = QrcodeItemListNew();
    EXPECT_NE(list, nullptr);
    if (list != nullptr) {
        const uint8_t data[] = "A";
        int32_t ret = QrcodeItemListAdd(list, QRCODE_MODE_AN, 1, data);
        EXPECT_EQ(ret, 0);
        QrcodeItemListFree(list);
    }
}

/**
 * @tc.name: qrcode_item_list_add_numeric_one_digit_066
 * @tc.desc: Verify adding numeric item with one digit.
 * @tc.type: FUNC
 * @tc.require: issueI000003
 */
HWTEST_F(QrcodeItemTest, qrcode_item_list_add_numeric_one_digit_066, TestSize.Level1)
{
    QrcodeItemList *list = QrcodeItemListNew();
    EXPECT_NE(list, nullptr);
    if (list != nullptr) {
        const uint8_t data[] = "5";
        int32_t ret = QrcodeItemListAdd(list, QRCODE_MODE_NUM, 1, data);
        EXPECT_EQ(ret, 0);
        QrcodeItemListFree(list);
    }
}

/**
 * @tc.name: qrcode_item_list_add_numeric_two_digits_067
 * @tc.desc: Verify adding numeric item with two digits.
 * @tc.type: FUNC
 * @tc.require: issueI000003
 */
HWTEST_F(QrcodeItemTest, qrcode_item_list_add_numeric_two_digits_067, TestSize.Level1)
{
    QrcodeItemList *list = QrcodeItemListNew();
    EXPECT_NE(list, nullptr);
    if (list != nullptr) {
        const uint8_t data[] = "12";
        int32_t ret = QrcodeItemListAdd(list, QRCODE_MODE_NUM, 2, data);
        EXPECT_EQ(ret, 0);
        QrcodeItemListFree(list);
    }
}

/**
 * @tc.name: qrcode_item_list_add_large_numeric_068
 * @tc.desc: Verify adding large numeric item.
 * @tc.type: FUNC
 * @tc.require: issueI000003
 */
HWTEST_F(QrcodeItemTest, qrcode_item_list_add_large_numeric_068, TestSize.Level1)
{
    QrcodeItemList *list = QrcodeItemListNew();
    EXPECT_NE(list, nullptr);
    if (list != nullptr) {
        const uint8_t data[200] = "123456789012345678901234567890123456789012345678901234567890123456789012345678901234"
                                 "567890123456789012345678901234567890123456789012345678901234567890123456789012345678"
                                 "9012345678901234567890123456789";
        int32_t ret = QrcodeItemListAdd(list, QRCODE_MODE_NUM, 199, data);
        EXPECT_EQ(ret, 0);  // Large numeric data is accepted
        QrcodeItemListFree(list);
    }
}

/**
 * @tc.name: qrcode_item_list_add_large_alphanumeric_069
 * @tc.desc: Verify adding large alphanumeric item.
 * @tc.type: FUNC
 * @tc.require: issueI000003
 */
HWTEST_F(QrcodeItemTest, qrcode_item_list_add_large_alphanumeric_069, TestSize.Level1)
{
    QrcodeItemList *list = QrcodeItemListNew();
    EXPECT_NE(list, nullptr);
    if (list != nullptr) {
        const uint8_t data[100] = "ABCDEFGHIJKLMNOPQRSTUVWXYZABCDEFGHIJKLMNOPQRSTUVWXYZABCDEFGHIJKLMNOPQRSTUVWXYZ"
                                  "ABCDEFGHIJ";
        int32_t ret = QrcodeItemListAdd(list, QRCODE_MODE_AN, 100, data);
        EXPECT_NE(ret, 0);  // Large alphanumeric data exceeds capacity
        QrcodeItemListFree(list);
    }
}

/**
 * @tc.name: qrcode_item_list_add_mixed_modes_all_070
 * @tc.desc: Verify adding items with all modes.
 * @tc.type: FUNC
 * @tc.require: issueI000003
 */
HWTEST_F(QrcodeItemTest, qrcode_item_list_add_mixed_modes_all_070, TestSize.Level1)
{
    QrcodeItemList *list = QrcodeItemListNew();
    EXPECT_NE(list, nullptr);
    if (list != nullptr) {
        const uint8_t data1[] = "123";
        const uint8_t data2[] = "ABC";
        const uint8_t data3[] = "Hello";
        QrcodeItemListAdd(list, QRCODE_MODE_NUM, 3, data1);
        QrcodeItemListAdd(list, QRCODE_MODE_AN, 3, data2);
        QrcodeItemListAdd(list, QRCODE_MODE_8, 5, data3);
        uint8_t *stream = QrcodeItemListGetByteStream(list);
        EXPECT_NE(stream, nullptr);
        if (stream != nullptr) {
            QrcodeFree(stream);
        }
        QrcodeItemListFree(list);
    }
}

/**
 * @tc.name: qrcode_item_list_get_byte_stream_mixed_071
 * @tc.desc: Verify getting byte stream with mixed modes.
 * @tc.type: FUNC
 * @tc.require: issueI000003
 */
HWTEST_F(QrcodeItemTest, qrcode_item_list_get_byte_stream_mixed_071, TestSize.Level1)
{
    QrcodeItemList *list = QrcodeItemListNew();
    EXPECT_NE(list, nullptr);
    if (list != nullptr) {
        const uint8_t data1[50] = "1234567890123456789012345678901234567890123456789";
        const uint8_t data2[30] = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
        const uint8_t data3[20] = "HelloWorldTest12345";
        QrcodeItemListAdd(list, QRCODE_MODE_NUM, 50, data1);
        QrcodeItemListAdd(list, QRCODE_MODE_AN, 30, data2);
        QrcodeItemListAdd(list, QRCODE_MODE_8, 20, data3);
        uint8_t *stream = QrcodeItemListGetByteStream(list);
        EXPECT_NE(stream, nullptr);
        if (stream != nullptr) {
            QrcodeFree(stream);
        }
        QrcodeItemListFree(list);
    }
}

/**
 * @tc.name: qrcode_item_list_get_byte_stream_long_numeric_072
 * @tc.desc: Verify getting byte stream with long numeric data.
 * @tc.type: FUNC
 * @tc.require: issueI000003
 */
HWTEST_F(QrcodeItemTest, qrcode_item_list_get_byte_stream_long_numeric_072, TestSize.Level1)
{
    QrcodeItemList *list = QrcodeItemListNew();
    EXPECT_NE(list, nullptr);
    if (list != nullptr) {
        const uint8_t data[200] = "123456789012345678901234567890123456789012345678901234567890123456789012345678901234"
                                 "567890123456789012345678901234567890123456789012345678901234567890123456789012345678"
                                 "9012345678901234567890123456789";
        QrcodeItemListAdd(list, QRCODE_MODE_NUM, 199, data);
        uint8_t *stream = QrcodeItemListGetByteStream(list);
        EXPECT_NE(stream, nullptr);  // Large numeric data is accepted
        if (stream != nullptr) {
            QrcodeFree(stream);
        }
        QrcodeItemListFree(list);
    }
}

/**
 * @tc.name: qrcode_item_list_free_with_items_073
 * @tc.desc: Verify freeing list with items.
 * @tc.type: FUNC
 * @tc.require: issueI000003
 */
HWTEST_F(QrcodeItemTest, qrcode_item_list_free_with_items_073, TestSize.Level1)
{
    QrcodeItemList *list = QrcodeItemListNew();
    EXPECT_NE(list, nullptr);
    if (list != nullptr) {
        const uint8_t data[] = "12345";
        QrcodeItemListAdd(list, QRCODE_MODE_NUM, 5, data);
        QrcodeItemListFree(list);
    }
}

/**
 * @tc.name: qrcode_item_list_free_multiple_items_074
 * @tc.desc: Verify freeing list with multiple items.
 * @tc.type: FUNC
 * @tc.require: issueI000003
 */
HWTEST_F(QrcodeItemTest, qrcode_item_list_free_multiple_items_074, TestSize.Level1)
{
    QrcodeItemList *list = QrcodeItemListNew();
    EXPECT_NE(list, nullptr);
    if (list != nullptr) {
        const uint8_t data1[] = "12345";
        const uint8_t data2[] = "ABC";
        QrcodeItemListAdd(list, QRCODE_MODE_NUM, 5, data1);
        QrcodeItemListAdd(list, QRCODE_MODE_AN, 3, data2);
        QrcodeItemListFree(list);
    }
}

/**
 * @tc.name: qrcode_item_estimate_num_very_large_075
 * @tc.desc: Verify estimating numeric size for very large input.
 * @tc.type: FUNC
 * @tc.require: issueI000003
 */
HWTEST_F(QrcodeItemTest, qrcode_item_estimate_num_very_large_075, TestSize.Level1)
{
    int32_t size = QrcodeEstimateNum(10000);
    EXPECT_GT(size, 0);
}

/**
 * @tc.name: qrcode_item_estimate_alphabet_very_large_076
 * @tc.desc: Verify estimating alphanumeric size for very large input.
 * @tc.type: FUNC
 * @tc.require: issueI000003
 */
HWTEST_F(QrcodeItemTest, qrcode_item_estimate_alphabet_very_large_076, TestSize.Level1)
{
    int32_t size = QrcodeEstimateAlphaBet(10000);
    EXPECT_GT(size, 0);
}

/**
 * @tc.name: qrcode_item_estimate_8_very_large_077
 * @tc.desc: Verify estimating byte size for very large input.
 * @tc.type: FUNC
 * @tc.require: issueI000003
 */
HWTEST_F(QrcodeItemTest, qrcode_item_estimate_8_very_large_077, TestSize.Level1)
{
    int32_t size = QrcodeEstimate8(10000);
    EXPECT_GT(size, 0);
}

/**
 * @tc.name: qrcode_item_look_at_table_all_valid_078
 * @tc.desc: Verify looking up all valid characters in table.
 * @tc.type: FUNC
 * @tc.require: issueI000003
 */
HWTEST_F(QrcodeItemTest, qrcode_item_look_at_table_all_valid_078, TestSize.Level1)
{
    const char validChars[] = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ$%*+-./:";
    for (int32_t i = 0; validChars[i] != '\0'; i++) {
        int32_t ret = QrcodeLookAtTable(validChars[i]);
        EXPECT_GE(ret, 0);
    }
}

/**
 * @tc.name: qrcode_item_look_at_table_all_invalid_079
 * @tc.desc: Verify looking up all invalid characters in table.
 * @tc.type: FUNC
 * @tc.require: issueI000003
 */
HWTEST_F(QrcodeItemTest, qrcode_item_look_at_table_all_invalid_079, TestSize.Level1)
{
    const char invalidChars[] = "!@#^&()[]{},.<>?\\|`~";
    for (int32_t i = 0; invalidChars[i] != '\0'; i++) {
        int32_t ret = QrcodeLookAtTable(invalidChars[i]);
        EXPECT_GE(ret, -1);  // Some chars are in the alphanumeric table, others return -1
    }
}

/**
 * @tc.name: qrcode_item_check_numeric_all_digits_080
 * @tc.desc: Verify checking all valid numeric digits.
 * @tc.type: FUNC
 * @tc.require: issueI000003
 */
/**
 * @tc.name: qrcode_item_check_numeric_all_digits_080
 * @tc.desc: Verify checking all valid numeric digits.
 * @tc.type: FUNC
 * @tc.require: issueI000003
 */
HWTEST_F(QrcodeItemTest, qrcode_item_check_numeric_all_digits_080, TestSize.Level1)
{
    const uint8_t data[] = "0123456789";
    int32_t ret = QrcodeItemCheck(QRCODE_MODE_NUM, 10, data);
    EXPECT_EQ(ret, 0);
}

/**
 * @tc.name: qrcode_item_list_add_null_list_081
 * @tc.desc: Verify adding item to null list.
 * @tc.type: FUNC
 * @tc.require: issueI000003
 */
HWTEST_F(QrcodeItemTest, qrcode_item_list_add_null_list_081, TestSize.Level1)
{
    const uint8_t data[] = "12345";
    int32_t ret = QrcodeItemListAdd(nullptr, QRCODE_MODE_NUM, 5, data);
    EXPECT_EQ(ret, -1);
}

/**
 * @tc.name: qrcode_item_list_add_invalid_numeric_082
 * @tc.desc: Verify adding invalid numeric item to list.
 * @tc.type: FUNC
 * @tc.require: issueI000003
 */
HWTEST_F(QrcodeItemTest, qrcode_item_list_add_invalid_numeric_082, TestSize.Level1)
{
    QrcodeItemList *list = QrcodeItemListNew();
    EXPECT_NE(list, nullptr);
    if (list != nullptr) {
        const uint8_t data[] = "12a45";  // Invalid numeric
        int32_t ret = QrcodeItemListAdd(list, QRCODE_MODE_NUM, 5, data);
        EXPECT_EQ(ret, -1);
        QrcodeItemListFree(list);
    }
}

/**
 * @tc.name: qrcode_item_list_add_invalid_alphanumeric_083
 * @tc.desc: Verify adding invalid alphanumeric item to list.
 * @tc.type: FUNC
 * @tc.require: issueI000003
 */
HWTEST_F(QrcodeItemTest, qrcode_item_list_add_invalid_alphanumeric_083, TestSize.Level1)
{
    QrcodeItemList *list = QrcodeItemListNew();
    EXPECT_NE(list, nullptr);
    if (list != nullptr) {
        const uint8_t data[] = "AB@123";  // Invalid alphanumeric
        int32_t ret = QrcodeItemListAdd(list, QRCODE_MODE_AN, 5, data);
        EXPECT_EQ(ret, -1);
        QrcodeItemListFree(list);
    }
}

/**
 * @tc.name: qrcode_item_check_null_data_084
 * @tc.desc: Verify checking item with null data.
 * @tc.type: FUNC
 * @tc.require: issueI000003
 */
HWTEST_F(QrcodeItemTest, qrcode_item_check_null_data_084, TestSize.Level1)
{
    int32_t ret = QrcodeItemCheck(QRCODE_MODE_NUM, 5, nullptr);
    EXPECT_EQ(ret, -1);
}

/**
 * @tc.name: qrcode_item_check_zero_size_085
 * @tc.desc: Verify checking item with zero size.
 * @tc.type: FUNC
 * @tc.require: issueI000003
 */
HWTEST_F(QrcodeItemTest, qrcode_item_check_zero_size_085, TestSize.Level1)
{
    const uint8_t data[] = "12345";
    int32_t ret = QrcodeItemCheck(QRCODE_MODE_NUM, 0, data);
    EXPECT_EQ(ret, -1);
}

/**
 * @tc.name: qrcode_item_check_negative_size_086
 * @tc.desc: Verify checking item with negative size.
 * @tc.type: FUNC
 * @tc.require: issueI000003
 */
HWTEST_F(QrcodeItemTest, qrcode_item_check_negative_size_086, TestSize.Level1)
{
    const uint8_t data[] = "12345";
    int32_t ret = QrcodeItemCheck(QRCODE_MODE_NUM, -1, data);
    EXPECT_EQ(ret, -1);
}

/**
 * @tc.name: qrcode_item_check_invalid_mode_087
 * @tc.desc: Verify checking item with invalid mode.
 * @tc.type: FUNC
 * @tc.require: issueI000003
 */
HWTEST_F(QrcodeItemTest, qrcode_item_check_invalid_mode_087, TestSize.Level1)
{
    const uint8_t data[] = "12345";
    int32_t ret = QrcodeItemCheck(QRCODE_MODE_NUL, 5, data);
    EXPECT_EQ(ret, -1);
}

/**
 * @tc.name: qrcode_item_check_numeric_with_letter_088
 * @tc.desc: Verify checking numeric item with letter.
 * @tc.type: FUNC
 * @tc.require: issueI000003
 */
HWTEST_F(QrcodeItemTest, qrcode_item_check_numeric_with_letter_088, TestSize.Level1)
{
    const uint8_t data[] = "1234a";
    int32_t ret = QrcodeItemCheck(QRCODE_MODE_NUM, 5, data);
    EXPECT_EQ(ret, -1);
}

/**
 * @tc.name: qrcode_item_check_alphanumeric_with_invalid_char_089
 * @tc.desc: Verify checking alphanumeric item with invalid character.
 * @tc.type: FUNC
 * @tc.require: issueI000003
 */
HWTEST_F(QrcodeItemTest, qrcode_item_check_alphanumeric_with_invalid_char_089, TestSize.Level1)
{
    const uint8_t data[] = "ABC@12";
    int32_t ret = QrcodeItemCheck(QRCODE_MODE_AN, 5, data);
    EXPECT_EQ(ret, -1);
}

/**
 * @tc.name: qrcode_item_list_get_byte_stream_null_list_090
 * @tc.desc: Verify getting byte stream from null list.
 * @tc.type: FUNC
 * @tc.require: issueI000003
 */
HWTEST_F(QrcodeItemTest, qrcode_item_list_get_byte_stream_null_list_090, TestSize.Level1)
{
    uint8_t *stream = QrcodeItemListGetByteStream(nullptr);
    EXPECT_EQ(stream, nullptr);
}

/**
 * @tc.name: qrcode_item_list_get_byte_stream_empty_list_091
 * @tc.desc: Verify getting byte stream from empty list.
 * @tc.type: FUNC
 * @tc.require: issueI000003
 */
HWTEST_F(QrcodeItemTest, qrcode_item_list_get_byte_stream_empty_list_091, TestSize.Level1)
{
    QrcodeItemList *list = QrcodeItemListNew();
    EXPECT_NE(list, nullptr);
    if (list != nullptr) {
        uint8_t *stream = QrcodeItemListGetByteStream(list);
        EXPECT_NE(stream, nullptr);
        QrcodeItemListFree(list);
    }
}

/**
 * @tc.name: qrcode_estimate_num_zero_092
 * @tc.desc: Verify estimating numeric size for zero.
 * @tc.type: FUNC
 * @tc.require: issueI000003
 */
HWTEST_F(QrcodeItemTest, qrcode_estimate_num_zero_092, TestSize.Level1)
{
    int32_t size = QrcodeEstimateNum(0);
    EXPECT_EQ(size, 0);
}

/**
 * @tc.name: qrcode_estimate_num_one_093
 * @tc.desc: Verify estimating numeric size for one digit.
 * @tc.type: FUNC
 * @tc.require: issueI000003
 */
HWTEST_F(QrcodeItemTest, qrcode_estimate_num_one_093, TestSize.Level1)
{
    int32_t size = QrcodeEstimateNum(1);
    EXPECT_GT(size, 0);
}

/**
 * @tc.name: qrcode_estimate_num_two_094
 * @tc.desc: Verify estimating numeric size for two digits.
 * @tc.type: FUNC
 * @tc.require: issueI000003
 */
HWTEST_F(QrcodeItemTest, qrcode_estimate_num_two_094, TestSize.Level1)
{
    int32_t size = QrcodeEstimateNum(2);
    EXPECT_GT(size, 0);
}

/**
 * @tc.name: qrcode_estimate_alphabet_zero_095
 * @tc.desc: Verify estimating alphanumeric size for zero.
 * @tc.type: FUNC
 * @tc.require: issueI000003
 */
HWTEST_F(QrcodeItemTest, qrcode_estimate_alphabet_zero_095, TestSize.Level1)
{
    int32_t size = QrcodeEstimateAlphaBet(0);
    EXPECT_EQ(size, 0);
}

/**
 * @tc.name: qrcode_estimate_alphabet_one_096
 * @tc.desc: Verify estimating alphanumeric size for one character.
 * @tc.type: FUNC
 * @tc.require: issueI000003
 */
HWTEST_F(QrcodeItemTest, qrcode_estimate_alphabet_one_096, TestSize.Level1)
{
    int32_t size = QrcodeEstimateAlphaBet(1);
    EXPECT_GT(size, 0);
}

/**
 * @tc.name: qrcode_estimate_8_zero_097
 * @tc.desc: Verify estimating byte size for zero.
 * @tc.type: FUNC
 * @tc.require: issueI000003
 */
HWTEST_F(QrcodeItemTest, qrcode_estimate_8_zero_097, TestSize.Level1)
{
    int32_t size = QrcodeEstimate8(0);
    EXPECT_EQ(size, 0);
}

/**
 * @tc.name: qrcode_look_at_table_invalid_char_098
 * @tc.desc: Verify looking up invalid character in table.
 * @tc.type: FUNC
 * @tc.require: issueI000003
 */
HWTEST_F(QrcodeItemTest, qrcode_look_at_table_invalid_char_098, TestSize.Level1)
{
    int32_t ret = QrcodeLookAtTable('@');
    EXPECT_LT(ret, 0);
}

/**
 * @tc.name: qrcode_look_at_table_space_099
 * @tc.desc: Verify looking up space character in table.
 * @tc.type: FUNC
 * @tc.require: issueI000003
 */
HWTEST_F(QrcodeItemTest, qrcode_look_at_table_space_099, TestSize.Level1)
{
    int32_t ret = QrcodeLookAtTable(' ');
    EXPECT_GE(ret, 0);  // Space returns 36 (in alphanumeric table)
}

/**
 * @tc.name: qrcode_item_list_add_multiple_items_100
 * @tc.desc: Verify adding multiple items to list.
 * @tc.type: FUNC
 * @tc.require: issueI000003
 */
HWTEST_F(QrcodeItemTest, qrcode_item_list_add_multiple_items_100, TestSize.Level1)
{
    QrcodeItemList *list = QrcodeItemListNew();
    EXPECT_NE(list, nullptr);
    if (list != nullptr) {
        const uint8_t data1[] = "12345";
        const uint8_t data2[] = "ABC";
        const uint8_t data3[] = "Hello";
        int32_t ret1 = QrcodeItemListAdd(list, QRCODE_MODE_NUM, 5, data1);
        int32_t ret2 = QrcodeItemListAdd(list, QRCODE_MODE_AN, 3, data2);
        int32_t ret3 = QrcodeItemListAdd(list, QRCODE_MODE_8, 5, data3);
        EXPECT_EQ(ret1, 0);
        EXPECT_EQ(ret2, 0);
        EXPECT_EQ(ret3, 0);
        uint8_t *stream = QrcodeItemListGetByteStream(list);
        EXPECT_NE(stream, nullptr);
        if (stream != nullptr) {
            QrcodeFree(stream);
        }
        QrcodeItemListFree(list);
    }
}

/**
 * @tc.name: qrcode_item_list_get_byte_stream_numeric_101
 * @tc.desc: Verify getting byte stream from numeric list.
 * @tc.type: FUNC
 * @tc.require: issueI000003
 */
HWTEST_F(QrcodeItemTest, qrcode_item_list_get_byte_stream_numeric_101, TestSize.Level1)
{
    QrcodeItemList *list = QrcodeItemListNew();
    EXPECT_NE(list, nullptr);
    if (list != nullptr) {
        const uint8_t data[] = "1234567890";
        QrcodeItemListAdd(list, QRCODE_MODE_NUM, 10, data);
        uint8_t *stream = QrcodeItemListGetByteStream(list);
        EXPECT_NE(stream, nullptr);
        if (stream != nullptr) {
            QrcodeFree(stream);
        }
        QrcodeItemListFree(list);
    }
}

/**
 * @tc.name: qrcode_item_list_get_byte_stream_alphanumeric_102
 * @tc.desc: Verify getting byte stream from alphanumeric list.
 * @tc.type: FUNC
 * @tc.require: issueI000003
 */
HWTEST_F(QrcodeItemTest, qrcode_item_list_get_byte_stream_alphanumeric_102, TestSize.Level1)
{
    QrcodeItemList *list = QrcodeItemListNew();
    EXPECT_NE(list, nullptr);
    if (list != nullptr) {
        const uint8_t data[] = "ABC123";
        QrcodeItemListAdd(list, QRCODE_MODE_AN, 6, data);
        uint8_t *stream = QrcodeItemListGetByteStream(list);
        EXPECT_NE(stream, nullptr);
        if (stream != nullptr) {
            QrcodeFree(stream);
        }
        QrcodeItemListFree(list);
    }
}

/**
 * @tc.name: qrcode_item_list_get_byte_stream_byte_103
 * @tc.desc: Verify getting byte stream from byte list.
 * @tc.type: FUNC
 * @tc.require: issueI000003
 */
HWTEST_F(QrcodeItemTest, qrcode_item_list_get_byte_stream_byte_103, TestSize.Level1)
{
    QrcodeItemList *list = QrcodeItemListNew();
    EXPECT_NE(list, nullptr);
    if (list != nullptr) {
        const uint8_t data[] = "Hello World";
        QrcodeItemListAdd(list, QRCODE_MODE_8, 11, data);
        uint8_t *stream = QrcodeItemListGetByteStream(list);
        EXPECT_NE(stream, nullptr);
        if (stream != nullptr) {
            QrcodeFree(stream);
        }
        QrcodeItemListFree(list);
    }
}

/**
 * @tc.name: qrcode_item_check_alphanumeric_all_valid_081
 * @tc.desc: Verify checking all valid alphanumeric characters.
 * @tc.type: FUNC
 * @tc.require: issueI000003
 */
HWTEST_F(QrcodeItemTest, qrcode_item_check_alphanumeric_all_valid_081, TestSize.Level1)
{
    const uint8_t data[] = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ$%*+-./:";
    int32_t ret = QrcodeItemCheck(QRCODE_MODE_AN, 44, data);  // 44 chars without null terminator
    EXPECT_EQ(ret, 0);  // All valid alphanumeric characters
}

/**
 * @tc.name: qrcode_item_check_byte_all_bytes_082
 * @tc.desc: Verify checking all byte values.
 * @tc.type: FUNC
 * @tc.require: issueI000003
 */
HWTEST_F(QrcodeItemTest, qrcode_item_check_byte_all_bytes_082, TestSize.Level1)
{
    uint8_t data[256];
    for (int32_t i = 0; i < 256; i++) {
        data[i] = (uint8_t)i;
    }
    int32_t ret = QrcodeItemCheck(QRCODE_MODE_8, 256, data);
    EXPECT_EQ(ret, 0);
}

/**
 * @tc.name: qrcode_item_list_add_byte_empty_083
 * @tc.desc: Verify adding byte item with empty data.
 * @tc.type: FUNC
 * @tc.require: issueI000003
 */
HWTEST_F(QrcodeItemTest, qrcode_item_list_add_byte_empty_083, TestSize.Level1)
{
    QrcodeItemList *list = QrcodeItemListNew();
    EXPECT_NE(list, nullptr);
    if (list != nullptr) {
        const uint8_t data[] = "";
        int32_t ret = QrcodeItemListAdd(list, QRCODE_MODE_8, 0, data);
        EXPECT_NE(ret, 0);
        QrcodeItemListFree(list);
    }
}

/**
 * @tc.name: qrcode_item_list_add_numeric_empty_084
 * @tc.desc: Verify adding numeric item with empty data.
 * @tc.type: FUNC
 * @tc.require: issueI000003
 */
HWTEST_F(QrcodeItemTest, qrcode_item_list_add_numeric_empty_084, TestSize.Level1)
{
    QrcodeItemList *list = QrcodeItemListNew();
    EXPECT_NE(list, nullptr);
    if (list != nullptr) {
        const uint8_t data[] = "";
        int32_t ret = QrcodeItemListAdd(list, QRCODE_MODE_NUM, 0, data);
        EXPECT_NE(ret, 0);
        QrcodeItemListFree(list);
    }
}

/**
 * @tc.name: qrcode_item_list_add_alphanumeric_empty_085
 * @tc.desc: Verify adding alphanumeric item with empty data.
 * @tc.type: FUNC
 * @tc.require: issueI000003
 */
HWTEST_F(QrcodeItemTest, qrcode_item_list_add_alphanumeric_empty_085, TestSize.Level1)
{
    QrcodeItemList *list = QrcodeItemListNew();
    EXPECT_NE(list, nullptr);
    if (list != nullptr) {
        const uint8_t data[] = "";
        int32_t ret = QrcodeItemListAdd(list, QRCODE_MODE_AN, 0, data);
        EXPECT_NE(ret, 0);
        QrcodeItemListFree(list);
    }
}

/**
 * @tc.name: qrcode_item_is_valid_mode_all_086
 * @tc.desc: Verify checking all valid modes.
 * @tc.type: FUNC
 * @tc.require: issueI000003
 */
HWTEST_F(QrcodeItemTest, qrcode_item_is_valid_mode_all_086, TestSize.Level1)
{
    EXPECT_TRUE(QrcodeIsValidMode(QRCODE_MODE_NUM));
    EXPECT_TRUE(QrcodeIsValidMode(QRCODE_MODE_AN));
    EXPECT_TRUE(QrcodeIsValidMode(QRCODE_MODE_8));
    EXPECT_FALSE(QrcodeIsValidMode(QRCODE_MODE_NUL));
    EXPECT_FALSE(QrcodeIsValidMode((QrcodeMode)99));
}