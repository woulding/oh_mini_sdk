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
#include "interfaces/innerkits/qrcode_version.h"
#include <gtest/gtest.h>
#include <cstring>

using namespace testing::ext;

class QrcodeStringTest : public testing::Test {
public:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp();
    void TearDown();
};

void QrcodeStringTest::SetUpTestCase(void) {}

void QrcodeStringTest::TearDownTestCase(void) {}

void QrcodeStringTest::SetUp(void) {}

void QrcodeStringTest::TearDown(void) {}

/**
 * @tc.name: qrcode_str_to_item_list_numeric_only_001
 * @tc.desc: Verify converting numeric only string to item list.
 * @tc.type: FUNC
 * @tc.require: issueI000003
 */
HWTEST_F(QrcodeStringTest, qrcode_str_to_item_list_numeric_only_001, TestSize.Level1)
{
    QrcodeItemList *list = QrcodeItemListNew();
    EXPECT_NE(list, nullptr);
    if (list != nullptr) {
        const char *text = "1234567890";
        int32_t ret = QrcodeStrToItemList(text, list);
        EXPECT_EQ(ret, 0);
        QrcodeItemListFree(list);
    }
}

/**
 * @tc.name: qrcode_str_to_item_list_alpha_only_002
 * @tc.desc: Verify converting alphanumeric only string to item list.
 * @tc.type: FUNC
 * @tc.require: issueI000003
 */
HWTEST_F(QrcodeStringTest, qrcode_str_to_item_list_alpha_only_002, TestSize.Level1)
{
    QrcodeItemList *list = QrcodeItemListNew();
    EXPECT_NE(list, nullptr);
    if (list != nullptr) {
        const char *text = "ABC123XYZ";
        int32_t ret = QrcodeStrToItemList(text, list);
        EXPECT_EQ(ret, 0);
        QrcodeItemListFree(list);
    }
}

/**
 * @tc.name: qrcode_str_to_item_list_byte_only_003
 * @tc.desc: Verify converting byte mode string to item list.
 * @tc.type: FUNC
 * @tc.require: issueI000003
 */
HWTEST_F(QrcodeStringTest, qrcode_str_to_item_list_byte_only_003, TestSize.Level1)
{
    QrcodeItemList *list = QrcodeItemListNew();
    EXPECT_NE(list, nullptr);
    if (list != nullptr) {
        const char *text = "Hello@World";
        int32_t ret = QrcodeStrToItemList(text, list);
        EXPECT_EQ(ret, 0);
        QrcodeItemListFree(list);
    }
}

/**
 * @tc.name: qrcode_str_to_item_list_mixed_004
 * @tc.desc: Verify converting mixed mode string to item list.
 * @tc.type: FUNC
 * @tc.require: issueI000003
 */
HWTEST_F(QrcodeStringTest, qrcode_str_to_item_list_mixed_004, TestSize.Level1)
{
    QrcodeItemList *list = QrcodeItemListNew();
    EXPECT_NE(list, nullptr);
    if (list != nullptr) {
        const char *text = "123ABC@456";
        int32_t ret = QrcodeStrToItemList(text, list);
        EXPECT_EQ(ret, 0);
        QrcodeItemListFree(list);
    }
}

/**
 * @tc.name: qrcode_str_to_item_list_null_list_005
 * @tc.desc: Verify converting string with null list.
 * @tc.type: FUNC
 * @tc.require: issueI000003
 */
HWTEST_F(QrcodeStringTest, qrcode_str_to_item_list_null_list_005, TestSize.Level1)
{
    const char *text = "12345";
    int32_t ret = QrcodeStrToItemList(text, nullptr);
    EXPECT_NE(ret, 0);
}

/**
 * @tc.name: qrcode_str_to_item_list_null_string_006
 * @tc.desc: Verify converting null string to item list.
 * @tc.type: FUNC
 * @tc.require: issueI000003
 */
HWTEST_F(QrcodeStringTest, qrcode_str_to_item_list_null_string_006, TestSize.Level1)
{
    QrcodeItemList *list = QrcodeItemListNew();
    EXPECT_NE(list, nullptr);
    if (list != nullptr) {
        int32_t ret = QrcodeStrToItemList(nullptr, list);
        EXPECT_NE(ret, 0);
        QrcodeItemListFree(list);
    }
}

/**
 * @tc.name: qrcode_str_to_item_list_empty_string_007
 * @tc.desc: Verify converting empty string to item list.
 * @tc.type: FUNC
 * @tc.require: issueI000003
 */
HWTEST_F(QrcodeStringTest, qrcode_str_to_item_list_empty_string_007, TestSize.Level1)
{
    QrcodeItemList *list = QrcodeItemListNew();
    EXPECT_NE(list, nullptr);
    if (list != nullptr) {
        const char *text = "";
        int32_t ret = QrcodeStrToItemList(text, list);
        EXPECT_EQ(ret, 0);
        QrcodeItemListFree(list);
    }
}

/**
 * @tc.name: qrcode_str_to_item_list_long_numeric_008
 * @tc.desc: Verify converting long numeric string to item list.
 * @tc.type: FUNC
 * @tc.require: issueI000003
 */
HWTEST_F(QrcodeStringTest, qrcode_str_to_item_list_long_numeric_008, TestSize.Level1)
{
    QrcodeItemList *list = QrcodeItemListNew();
    EXPECT_NE(list, nullptr);
    if (list != nullptr) {
        const char *text = "1234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901"
                           "2345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012"
                           "345678901234567890123456789012345678901234567890";
        int32_t ret = QrcodeStrToItemList(text, list);
        EXPECT_EQ(ret, 0);
        QrcodeItemListFree(list);
    }
}

/**
 * @tc.name: qrcode_str_to_item_list_numeric_alpha_switch_009
 * @tc.desc: Verify converting string with numeric-alpha switches.
 * @tc.type: FUNC
 * @tc.require: issueI000003
 */
HWTEST_F(QrcodeStringTest, qrcode_str_to_item_list_numeric_alpha_switch_009, TestSize.Level1)
{
    QrcodeItemList *list = QrcodeItemListNew();
    EXPECT_NE(list, nullptr);
    if (list != nullptr) {
        const char *text = "123ABC456DEF789";
        int32_t ret = QrcodeStrToItemList(text, list);
        EXPECT_EQ(ret, 0);
        QrcodeItemListFree(list);
    }
}

/**
 * @tc.name: qrcode_str_to_item_list_alpha_byte_switch_010
 * @tc.desc: Verify converting string with alpha-byte switches.
 * @tc.type: FUNC
 * @tc.require: issueI000003
 */
HWTEST_F(QrcodeStringTest, qrcode_str_to_item_list_alpha_byte_switch_010, TestSize.Level1)
{
    QrcodeItemList *list = QrcodeItemListNew();
    EXPECT_NE(list, nullptr);
    if (list != nullptr) {
        const char *text = "ABC@123XYZ";
        int32_t ret = QrcodeStrToItemList(text, list);
        EXPECT_EQ(ret, 0);
        QrcodeItemListFree(list);
    }
}

/**
 * @tc.name: qrcode_str_to_item_list_complex_mixed_011
 * @tc.desc: Verify converting complex mixed string to item list.
 * @tc.type: FUNC
 * @tc.require: issueI000003
 */
HWTEST_F(QrcodeStringTest, qrcode_str_to_item_list_complex_mixed_011, TestSize.Level1)
{
    QrcodeItemList *list = QrcodeItemListNew();
    EXPECT_NE(list, nullptr);
    if (list != nullptr) {
        const char *text = "123ABC@456DEF$789GHI%012";
        int32_t ret = QrcodeStrToItemList(text, list);
        EXPECT_EQ(ret, 0);
        QrcodeItemListFree(list);
    }
}

/**
 * @tc.name: qrcode_str_to_item_list_single_char_012
 * @tc.desc: Verify converting single character string to item list.
 * @tc.type: FUNC
 * @tc.require: issueI000003
 */
HWTEST_F(QrcodeStringTest, qrcode_str_to_item_list_single_char_012, TestSize.Level1)
{
    QrcodeItemList *list = QrcodeItemListNew();
    EXPECT_NE(list, nullptr);
    if (list != nullptr) {
        const char *text = "A";
        int32_t ret = QrcodeStrToItemList(text, list);
        EXPECT_EQ(ret, 0);
        QrcodeItemListFree(list);
    }
}

/**
 * @tc.name: qrcode_str_to_item_list_special_chars_013
 * @tc.desc: Verify converting special characters string to item list.
 * @tc.type: FUNC
 * @tc.require: issueI000003
 */
HWTEST_F(QrcodeStringTest, qrcode_str_to_item_list_special_chars_013, TestSize.Level1)
{
    QrcodeItemList *list = QrcodeItemListNew();
    EXPECT_NE(list, nullptr);
    if (list != nullptr) {
        const char *text = "$%*+-./:";
        int32_t ret = QrcodeStrToItemList(text, list);
        EXPECT_EQ(ret, 0);
        QrcodeItemListFree(list);
    }
}

/**
 * @tc.name: qrcode_str_to_item_list_url_014
 * @tc.desc: Verify converting URL string to item list.
 * @tc.type: FUNC
 * @tc.require: issueI000003
 */
HWTEST_F(QrcodeStringTest, qrcode_str_to_item_list_url_014, TestSize.Level1)
{
    QrcodeItemList *list = QrcodeItemListNew();
    EXPECT_NE(list, nullptr);
    if (list != nullptr) {
        const char *text = "https://www.example.com/path?query=123";
        int32_t ret = QrcodeStrToItemList(text, list);
        EXPECT_EQ(ret, 0);
        QrcodeItemListFree(list);
    }
}

/**
 * @tc.name: qrcode_str_to_item_list_numeric_to_byte_015
 * @tc.desc: Verify converting numeric followed by byte character.
 * @tc.type: FUNC
 * @tc.require: issueI000003
 */
HWTEST_F(QrcodeStringTest, qrcode_str_to_item_list_numeric_to_byte_015, TestSize.Level1)
{
    QrcodeItemList *list = QrcodeItemListNew();
    EXPECT_NE(list, nullptr);
    if (list != nullptr) {
        const char *text = "1234@";
        int32_t ret = QrcodeStrToItemList(text, list);
        EXPECT_EQ(ret, 0);
        QrcodeItemListFree(list);
    }
}

/**
 * @tc.name: qrcode_str_to_item_list_alpha_to_byte_016
 * @tc.desc: Verify converting alpha followed by byte character.
 * @tc.type: FUNC
 * @tc.require: issueI000003
 */
HWTEST_F(QrcodeStringTest, qrcode_str_to_item_list_alpha_to_byte_016, TestSize.Level1)
{
    QrcodeItemList *list = QrcodeItemListNew();
    EXPECT_NE(list, nullptr);
    if (list != nullptr) {
        const char *text = "ABCD@";
        int32_t ret = QrcodeStrToItemList(text, list);
        EXPECT_EQ(ret, 0);
        QrcodeItemListFree(list);
    }
}

/**
 * @tc.name: qrcode_str_to_item_list_byte_with_numeric_017
 * @tc.desc: Verify converting byte string containing numeric characters.
 * @tc.type: FUNC
 * @tc.require: issueI000003
 */
HWTEST_F(QrcodeStringTest, qrcode_str_to_item_list_byte_with_numeric_017, TestSize.Level1)
{
    QrcodeItemList *list = QrcodeItemListNew();
    EXPECT_NE(list, nullptr);
    if (list != nullptr) {
        const char *text = "@1234@";
        int32_t ret = QrcodeStrToItemList(text, list);
        EXPECT_EQ(ret, 0);
        QrcodeItemListFree(list);
    }
}

/**
 * @tc.name: qrcode_str_to_item_list_byte_with_alpha_018
 * @tc.desc: Verify converting byte string containing alpha characters.
 * @tc.type: FUNC
 * @tc.require: issueI000003
 */
HWTEST_F(QrcodeStringTest, qrcode_str_to_item_list_byte_with_alpha_018, TestSize.Level1)
{
    QrcodeItemList *list = QrcodeItemListNew();
    EXPECT_NE(list, nullptr);
    if (list != nullptr) {
        const char *text = "@ABCD@";
        int32_t ret = QrcodeStrToItemList(text, list);
        EXPECT_EQ(ret, 0);
        QrcodeItemListFree(list);
    }
}

/**
 * @tc.name: qrcode_str_to_item_list_high_byte_019
 * @tc.desc: Verify converting string with high byte characters.
 * @tc.type: FUNC
 * @tc.require: issueI000003
 */
HWTEST_F(QrcodeStringTest, qrcode_str_to_item_list_high_byte_019, TestSize.Level1)
{
    QrcodeItemList *list = QrcodeItemListNew();
    EXPECT_NE(list, nullptr);
    if (list != nullptr) {
        const char *text = "ABC\x80XYZ";
        int32_t ret = QrcodeStrToItemList(text, list);
        EXPECT_EQ(ret, 0);
        QrcodeItemListFree(list);
    }
}

/**
 * @tc.name: qrcode_str_to_item_list_numeric_in_alpha_020
 * @tc.desc: Verify converting alpha string with numeric sequence.
 * @tc.type: FUNC
 * @tc.require: issueI000003
 */
HWTEST_F(QrcodeStringTest, qrcode_str_to_item_list_numeric_in_alpha_020, TestSize.Level1)
{
    QrcodeItemList *list = QrcodeItemListNew();
    EXPECT_NE(list, nullptr);
    if (list != nullptr) {
        const char *text = "AB123CD";
        int32_t ret = QrcodeStrToItemList(text, list);
        EXPECT_EQ(ret, 0);
        QrcodeItemListFree(list);
    }
}

/**
 * @tc.name: qrcode_str_to_item_list_long_alpha_021
 * @tc.desc: Verify converting long alpha string to item list.
 * @tc.type: FUNC
 * @tc.require: issueI000003
 */
HWTEST_F(QrcodeStringTest, qrcode_str_to_item_list_long_alpha_021, TestSize.Level1)
{
    QrcodeItemList *list = QrcodeItemListNew();
    EXPECT_NE(list, nullptr);
    if (list != nullptr) {
        const char *text = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789$%*+-./:";
        int32_t ret = QrcodeStrToItemList(text, list);
        EXPECT_EQ(ret, 0);
        QrcodeItemListFree(list);
    }
}

/**
 * @tc.name: qrcode_str_to_item_list_single_digit_022
 * @tc.desc: Verify converting single digit string to item list.
 * @tc.type: FUNC
 * @tc.require: issueI000003
 */
HWTEST_F(QrcodeStringTest, qrcode_str_to_item_list_single_digit_022, TestSize.Level1)
{
    QrcodeItemList *list = QrcodeItemListNew();
    EXPECT_NE(list, nullptr);
    if (list != nullptr) {
        const char *text = "1";
        int32_t ret = QrcodeStrToItemList(text, list);
        EXPECT_EQ(ret, 0);
        QrcodeItemListFree(list);
    }
}

/**
 * @tc.name: qrcode_str_to_item_list_two_digits_023
 * @tc.desc: Verify converting two digit string to item list.
 * @tc.type: FUNC
 * @tc.require: issueI000003
 */
HWTEST_F(QrcodeStringTest, qrcode_str_to_item_list_two_digits_023, TestSize.Level1)
{
    QrcodeItemList *list = QrcodeItemListNew();
    EXPECT_NE(list, nullptr);
    if (list != nullptr) {
        const char *text = "12";
        int32_t ret = QrcodeStrToItemList(text, list);
        EXPECT_EQ(ret, 0);
        QrcodeItemListFree(list);
    }
}

/**
 * @tc.name: qrcode_str_to_item_list_alpha_numeric_boundary_024
 * @tc.desc: Verify converting alpha-numeric at boundary.
 * @tc.type: FUNC
 * @tc.require: issueI000003
 */
HWTEST_F(QrcodeStringTest, qrcode_str_to_item_list_alpha_numeric_boundary_024, TestSize.Level1)
{
    QrcodeItemList *list = QrcodeItemListNew();
    EXPECT_NE(list, nullptr);
    if (list != nullptr) {
        const char *text = "AB12CD34";
        int32_t ret = QrcodeStrToItemList(text, list);
        EXPECT_EQ(ret, 0);
        QrcodeItemListFree(list);
    }
}

/**
 * @tc.name: qrcode_str_to_item_list_all_special_025
 * @tc.desc: Verify converting all special characters string to item list.
 * @tc.type: FUNC
 * @tc.require: issueI000003
 */
HWTEST_F(QrcodeStringTest, qrcode_str_to_item_list_all_special_025, TestSize.Level1)
{
    QrcodeItemList *list = QrcodeItemListNew();
    EXPECT_NE(list, nullptr);
    if (list != nullptr) {
        const char *text = "!@#$%^&*()_+-=[]{}|;':\",./<>?";
        int32_t ret = QrcodeStrToItemList(text, list);
        EXPECT_EQ(ret, 0);
        QrcodeItemListFree(list);
    }
}

/**
 * @tc.name: qrcode_str_to_item_list_mixed_case_026
 * @tc.desc: Verify converting mixed case string to item list.
 * @tc.type: FUNC
 * @tc.require: issueI000003
 */
HWTEST_F(QrcodeStringTest, qrcode_str_to_item_list_mixed_case_026, TestSize.Level1)
{
    QrcodeItemList *list = QrcodeItemListNew();
    EXPECT_NE(list, nullptr);
    if (list != nullptr) {
        const char *text = "AbCdEfGhIjKlMnOpQrStUvWxYz";
        int32_t ret = QrcodeStrToItemList(text, list);
        EXPECT_EQ(ret, 0);
        QrcodeItemListFree(list);
    }
}

/**
 * @tc.name: qrcode_str_to_item_list_space_char_027
 * @tc.desc: Verify converting string with space character to item list.
 * @tc.type: FUNC
 * @tc.require: issueI000003
 */
HWTEST_F(QrcodeStringTest, qrcode_str_to_item_list_space_char_027, TestSize.Level1)
{
    QrcodeItemList *list = QrcodeItemListNew();
    EXPECT_NE(list, nullptr);
    if (list != nullptr) {
        const char *text = "Hello World";
        int32_t ret = QrcodeStrToItemList(text, list);
        EXPECT_EQ(ret, 0);
        QrcodeItemListFree(list);
    }
}

/**
 * @tc.name: qrcode_str_to_item_list_numeric_alpha_numeric_028
 * @tc.desc: Verify converting numeric-alpha-numeric pattern to item list.
 * @tc.type: FUNC
 * @tc.require: issueI000003
 */
HWTEST_F(QrcodeStringTest, qrcode_str_to_item_list_numeric_alpha_numeric_028, TestSize.Level1)
{
    QrcodeItemList *list = QrcodeItemListNew();
    EXPECT_NE(list, nullptr);
    if (list != nullptr) {
        const char *text = "123ABC456";
        int32_t ret = QrcodeStrToItemList(text, list);
        EXPECT_EQ(ret, 0);
        QrcodeItemListFree(list);
    }
}

/**
 * @tc.name: qrcode_str_to_item_list_alpha_byte_alpha_029
 * @tc.desc: Verify converting alpha-byte-alpha pattern to item list.
 * @tc.type: FUNC
 * @tc.require: issueI000003
 */
HWTEST_F(QrcodeStringTest, qrcode_str_to_item_list_alpha_byte_alpha_029, TestSize.Level1)
{
    QrcodeItemList *list = QrcodeItemListNew();
    EXPECT_NE(list, nullptr);
    if (list != nullptr) {
        const char *text = "ABC@DEF";
        int32_t ret = QrcodeStrToItemList(text, list);
        EXPECT_EQ(ret, 0);
        QrcodeItemListFree(list);
    }
}

/**
 * @tc.name: qrcode_str_to_item_list_repeated_special_030
 * @tc.desc: Verify converting repeated special characters to item list.
 * @tc.type: FUNC
 * @tc.require: issueI000003
 */
HWTEST_F(QrcodeStringTest, qrcode_str_to_item_list_repeated_special_030, TestSize.Level1)
{
    QrcodeItemList *list = QrcodeItemListNew();
    EXPECT_NE(list, nullptr);
    if (list != nullptr) {
        const char *text = "@@@@";
        int32_t ret = QrcodeStrToItemList(text, list);
        EXPECT_EQ(ret, 0);
        QrcodeItemListFree(list);
    }
}

/**
 * @tc.name: qrcode_str_to_item_list_null_list_031
 * @tc.desc: Verify converting string with null list.
 * @tc.type: FUNC
 * @tc.require: issueI000003
 */
HWTEST_F(QrcodeStringTest, qrcode_str_to_item_list_null_list_031, TestSize.Level1)
{
    const char *text = "12345";
    int32_t ret = QrcodeStrToItemList(text, nullptr);
    EXPECT_EQ(ret, -1);
}

/**
 * @tc.name: qrcode_str_to_item_list_empty_string_032
 * @tc.desc: Verify converting empty string to item list.
 * @tc.type: FUNC
 * @tc.require: issueI000003
 */
HWTEST_F(QrcodeStringTest, qrcode_str_to_item_list_empty_string_032, TestSize.Level1)
{
    QrcodeItemList *list = QrcodeItemListNew();
    EXPECT_NE(list, nullptr);
    if (list != nullptr) {
        const char *text = "";
        int32_t ret = QrcodeStrToItemList(text, list);
        EXPECT_EQ(ret, 0);
        QrcodeItemListFree(list);
    }
}

/**
 * @tc.name: qrcode_str_to_item_list_single_numeric_033
 * @tc.desc: Verify converting single numeric character to item list.
 * @tc.type: FUNC
 * @tc.require: issueI000003
 */
HWTEST_F(QrcodeStringTest, qrcode_str_to_item_list_single_numeric_033, TestSize.Level1)
{
    QrcodeItemList *list = QrcodeItemListNew();
    EXPECT_NE(list, nullptr);
    if (list != nullptr) {
        const char *text = "1";
        int32_t ret = QrcodeStrToItemList(text, list);
        EXPECT_EQ(ret, 0);
        QrcodeItemListFree(list);
    }
}

/**
 * @tc.name: qrcode_str_to_item_list_single_alpha_034
 * @tc.desc: Verify converting single alphanumeric character to item list.
 * @tc.type: FUNC
 * @tc.require: issueI000003
 */
HWTEST_F(QrcodeStringTest, qrcode_str_to_item_list_single_alpha_034, TestSize.Level1)
{
    QrcodeItemList *list = QrcodeItemListNew();
    EXPECT_NE(list, nullptr);
    if (list != nullptr) {
        const char *text = "A";
        int32_t ret = QrcodeStrToItemList(text, list);
        EXPECT_EQ(ret, 0);
        QrcodeItemListFree(list);
    }
}

/**
 * @tc.name: qrcode_str_to_item_list_single_byte_035
 * @tc.desc: Verify converting single byte character to item list.
 * @tc.type: FUNC
 * @tc.require: issueI000003
 */
HWTEST_F(QrcodeStringTest, qrcode_str_to_item_list_single_byte_035, TestSize.Level1)
{
    QrcodeItemList *list = QrcodeItemListNew();
    EXPECT_NE(list, nullptr);
    if (list != nullptr) {
        const char *text = "@";
        int32_t ret = QrcodeStrToItemList(text, list);
        EXPECT_EQ(ret, 0);
        QrcodeItemListFree(list);
    }
}

/**
 * @tc.name: qrcode_str_to_item_list_numeric_followed_by_byte_036
 * @tc.desc: Verify converting numeric followed by byte to item list.
 * @tc.type: FUNC
 * @tc.require: issueI000003
 */
HWTEST_F(QrcodeStringTest, qrcode_str_to_item_list_numeric_followed_by_byte_036, TestSize.Level1)
{
    QrcodeItemList *list = QrcodeItemListNew();
    EXPECT_NE(list, nullptr);
    if (list != nullptr) {
        const char *text = "123@";
        int32_t ret = QrcodeStrToItemList(text, list);
        EXPECT_EQ(ret, 0);
        QrcodeItemListFree(list);
    }
}

/**
 * @tc.name: qrcode_str_to_item_list_alpha_followed_by_byte_037
 * @tc.desc: Verify converting alphanumeric followed by byte to item list.
 * @tc.type: FUNC
 * @tc.require: issueI000003
 */
HWTEST_F(QrcodeStringTest, qrcode_str_to_item_list_alpha_followed_by_byte_037, TestSize.Level1)
{
    QrcodeItemList *list = QrcodeItemListNew();
    EXPECT_NE(list, nullptr);
    if (list != nullptr) {
        const char *text = "ABC@";
        int32_t ret = QrcodeStrToItemList(text, list);
        EXPECT_EQ(ret, 0);
        QrcodeItemListFree(list);
    }
}

/**
 * @tc.name: qrcode_str_to_item_list_long_numeric_038
 * @tc.desc: Verify converting long numeric string to item list.
 * @tc.type: FUNC
 * @tc.require: issueI000003
 */
HWTEST_F(QrcodeStringTest, qrcode_str_to_item_list_long_numeric_038, TestSize.Level1)
{
    QrcodeItemList *list = QrcodeItemListNew();
    EXPECT_NE(list, nullptr);
    if (list != nullptr) {
        const char *text = "12345678901234567890";
        int32_t ret = QrcodeStrToItemList(text, list);
        EXPECT_EQ(ret, 0);
        QrcodeItemListFree(list);
    }
}

/**
 * @tc.name: qrcode_str_to_item_list_long_alpha_039
 * @tc.desc: Verify converting long alphanumeric string to item list.
 * @tc.type: FUNC
 * @tc.require: issueI000003
 */
HWTEST_F(QrcodeStringTest, qrcode_str_to_item_list_long_alpha_039, TestSize.Level1)
{
    QrcodeItemList *list = QrcodeItemListNew();
    EXPECT_NE(list, nullptr);
    if (list != nullptr) {
        const char *text = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
        int32_t ret = QrcodeStrToItemList(text, list);
        EXPECT_EQ(ret, 0);
        QrcodeItemListFree(list);
    }
}

/**
 * @tc.name: qrcode_str_to_item_list_mixed_with_special_chars_040
 * @tc.desc: Verify converting mixed string with special characters to item list.
 * @tc.type: FUNC
 * @tc.require: issueI000003
 */
HWTEST_F(QrcodeStringTest, qrcode_str_to_item_list_mixed_with_special_chars_040, TestSize.Level1)
{
    QrcodeItemList *list = QrcodeItemListNew();
    EXPECT_NE(list, nullptr);
    if (list != nullptr) {
        const char *text = "123ABC@456DEF$789";
        int32_t ret = QrcodeStrToItemList(text, list);
        EXPECT_EQ(ret, 0);
        QrcodeItemListFree(list);
    }
}
        EXPECT_EQ(ret, 0);
        QrcodeItemListFree(list);
    }
}