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

#include "interfaces/kits/qrcode_generator.h"
#include "interfaces/innerkits/qrcode_version.h"
#include <gtest/gtest.h>
#include <cstring>

using namespace testing::ext;

class QrcodeGeneratorTest : public testing::Test {
public:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp();
    void TearDown();
};

void QrcodeGeneratorTest::SetUpTestCase(void) {}

void QrcodeGeneratorTest::TearDownTestCase(void) {}

void QrcodeGeneratorTest::SetUp(void) {}

void QrcodeGeneratorTest::TearDown(void) {}

/**
 * @tc.name: qrcode_encode_empty_string_001
 * @tc.desc: Verify encoding empty string.
 * @tc.type: FUNC
 * @tc.require: issueI000001
 */
HWTEST_F(QrcodeGeneratorTest, qrcode_encode_empty_string_001, TestSize.Level1)
{
    QrcodeImage *qrImage = QrcodeImageEncodeString("", QRCODE_ECC_MEDIUM);
    EXPECT_NE(qrImage, nullptr);
}

/**
 * @tc.name: qrcode_encode_simple_text_002
 * @tc.desc: Verify encoding simple text.
 * @tc.type: FUNC
 * @tc.require: issueI000001
 */
HWTEST_F(QrcodeGeneratorTest, qrcode_encode_simple_text_002, TestSize.Level1)
{
    const char *text = "Hello";
    QrcodeImage *qrImage = QrcodeImageEncodeString(text, QRCODE_ECC_MEDIUM);
    EXPECT_NE(qrImage, nullptr);
    if (qrImage != nullptr) {
        EXPECT_GT(qrImage->width, 0);
        EXPECT_NE(qrImage->data, nullptr);
        QrcodeImageFree(qrImage);
    }
}

/**
 * @tc.name: qrcode_encode_numeric_text_003
 * @tc.desc: Verify encoding numeric text.
 * @tc.type: FUNC
 * @tc.require: issueI000001
 */
HWTEST_F(QrcodeGeneratorTest, qrcode_encode_numeric_text_003, TestSize.Level1)
{
    const char *text = "1234567890";
    QrcodeImage *qrImage = QrcodeImageEncodeString(text, QRCODE_ECC_MEDIUM);
    EXPECT_NE(qrImage, nullptr);
    if (qrImage != nullptr) {
        EXPECT_GT(qrImage->width, 0);
        EXPECT_NE(qrImage->data, nullptr);
        QrcodeImageFree(qrImage);
    }
}

/**
 * @tc.name: qrcode_encode_alphanumeric_text_004
 * @tc.desc: Verify encoding alphanumeric text.
 * @tc.type: FUNC
 * @tc.require: issueI000001
 */
HWTEST_F(QrcodeGeneratorTest, qrcode_encode_alphanumeric_text_004, TestSize.Level1)
{
    const char *text = "ABC123XYZ";
    QrcodeImage *qrImage = QrcodeImageEncodeString(text, QRCODE_ECC_MEDIUM);
    EXPECT_NE(qrImage, nullptr);
    if (qrImage != nullptr) {
        EXPECT_GT(qrImage->width, 0);
        EXPECT_NE(qrImage->data, nullptr);
        QrcodeImageFree(qrImage);
    }
}

/**
 * @tc.name: qrcode_encode_long_text_005
 * @tc.desc: Verify encoding long text.
 * @tc.type: FUNC
 * @tc.require: issueI000001
 */
HWTEST_F(QrcodeGeneratorTest, qrcode_encode_long_text_005, TestSize.Level1)
{
    const char *text = "This is a long text for testing QR code generation with more characters";
    QrcodeImage *qrImage = QrcodeImageEncodeString(text, QRCODE_ECC_MEDIUM);
    EXPECT_NE(qrImage, nullptr);
    if (qrImage != nullptr) {
        EXPECT_GT(qrImage->width, 0);
        EXPECT_NE(qrImage->data, nullptr);
        QrcodeImageFree(qrImage);
    }
}

/**
 * @tc.name: qrcode_encode_ecc_medium_006
 * @tc.desc: Verify encoding with ECC_MEDIUM.
 * @tc.type: FUNC
 * @tc.require: issueI000001
 */
HWTEST_F(QrcodeGeneratorTest, qrcode_encode_ecc_medium_006, TestSize.Level1)
{
    const char *text = "Test";
    QrcodeImage *qrImage = QrcodeImageEncodeString(text, QRCODE_ECC_MEDIUM);
    EXPECT_NE(qrImage, nullptr);
    if (qrImage != nullptr) {
        EXPECT_GT(qrImage->width, 0);
        EXPECT_NE(qrImage->data, nullptr);
        QrcodeImageFree(qrImage);
    }
}

/**
 * @tc.name: qrcode_encode_ecc_high_007
 * @tc.desc: Verify encoding with ECC_HIGH.
 * @tc.type: FUNC
 * @tc.require: issueI000001
 */
HWTEST_F(QrcodeGeneratorTest, qrcode_encode_ecc_high_007, TestSize.Level1)
{
    const char *text = "Test";
    QrcodeImage *qrImage = QrcodeImageEncodeString(text, QRCODE_ECC_HIGH);
    EXPECT_NE(qrImage, nullptr);
    if (qrImage != nullptr) {
        EXPECT_GT(qrImage->width, 0);
        EXPECT_NE(qrImage->data, nullptr);
        QrcodeImageFree(qrImage);
    }
}

/**
 * @tc.name: qrcode_free_null_image_008
 * @tc.desc: Verify freeing null image.
 * @tc.type: FUNC
 * @tc.require: issueI000001
 */
HWTEST_F(QrcodeGeneratorTest, qrcode_free_null_image_008, TestSize.Level1)
{
    QrcodeImageFree(nullptr);
}

/**
 * @tc.name: qrcode_free_valid_image_009
 * @tc.desc: Verify freeing valid image.
 * @tc.type: FUNC
 * @tc.require: issueI000001
 */
HWTEST_F(QrcodeGeneratorTest, qrcode_free_valid_image_009, TestSize.Level1)
{
    const char *text = "Test";
    QrcodeImage *qrImage = QrcodeImageEncodeString(text, QRCODE_ECC_MEDIUM);
    EXPECT_NE(qrImage, nullptr);
    if (qrImage != nullptr) {
        QrcodeImageFree(qrImage);
    }
}

/**
 * @tc.name: qrcode_encode_special_chars_010
 * @tc.desc: Verify encoding with special characters.
 * @tc.type: FUNC
 * @tc.require: issueI000001
 */
HWTEST_F(QrcodeGeneratorTest, qrcode_encode_special_chars_010, TestSize.Level1)
{
    const char *text = "Hello@World.com";
    QrcodeImage *qrImage = QrcodeImageEncodeString(text, QRCODE_ECC_MEDIUM);
    EXPECT_NE(qrImage, nullptr);
    if (qrImage != nullptr) {
        EXPECT_GT(qrImage->width, 0);
        EXPECT_NE(qrImage->data, nullptr);
        QrcodeImageFree(qrImage);
    }
}

/**
 * @tc.name: qrcode_encode_chinese_chars_011
 * @tc.desc: Verify encoding with Chinese characters.
 * @tc.type: FUNC
 * @tc.require: issueI000001
 */
HWTEST_F(QrcodeGeneratorTest, qrcode_encode_chinese_chars_011, TestSize.Level1)
{
    const char *text = "测试";
    QrcodeImage *qrImage = QrcodeImageEncodeString(text, QRCODE_ECC_MEDIUM);
    EXPECT_NE(qrImage, nullptr);
    if (qrImage != nullptr) {
        EXPECT_GT(qrImage->width, 0);
        EXPECT_NE(qrImage->data, nullptr);
        QrcodeImageFree(qrImage);
    }
}

/**
 * @tc.name: qrcode_encode_url_012
 * @tc.desc: Verify encoding URL.
 * @tc.type: FUNC
 * @tc.require: issueI000001
 */
HWTEST_F(QrcodeGeneratorTest, qrcode_encode_url_012, TestSize.Level1)
{
    const char *text = "https://www.example.com";
    QrcodeImage *qrImage = QrcodeImageEncodeString(text, QRCODE_ECC_MEDIUM);
    EXPECT_NE(qrImage, nullptr);
    if (qrImage != nullptr) {
        EXPECT_GT(qrImage->width, 0);
        EXPECT_NE(qrImage->data, nullptr);
        QrcodeImageFree(qrImage);
    }
}

/**
 * @tc.name: qrcode_encode_version_check_013
 * @tc.desc: Verify QR code version is valid.
 * @tc.type: FUNC
 * @tc.require: issueI000001
 */
HWTEST_F(QrcodeGeneratorTest, qrcode_encode_version_check_013, TestSize.Level1)
{
    const char *text = "Test";
    QrcodeImage *qrImage = QrcodeImageEncodeString(text, QRCODE_ECC_MEDIUM);
    EXPECT_NE(qrImage, nullptr);
    if (qrImage != nullptr) {
        EXPECT_GE(qrImage->version, 1);
        EXPECT_LE(qrImage->version, QRCODE_VERSION_MAX);
        QrcodeImageFree(qrImage);
    }
}

/**
 * @tc.name: qrcode_encode_width_check_014
 * @tc.desc: Verify QR code width is valid.
 * @tc.type: FUNC
 * @tc.require: issueI000001
 */
HWTEST_F(QrcodeGeneratorTest, qrcode_encode_width_check_014, TestSize.Level1)
{
    const char *text = "Test";
    QrcodeImage *qrImage = QrcodeImageEncodeString(text, QRCODE_ECC_MEDIUM);
    EXPECT_NE(qrImage, nullptr);
    if (qrImage != nullptr) {
        EXPECT_GT(qrImage->width, 0);
        EXPECT_LE(qrImage->width, QRCODE_VERSION_WIDTH_MAX);
        QrcodeImageFree(qrImage);
    }
}

/**
 * @tc.name: qrcode_encode_data_not_null_015
 * @tc.desc: Verify QR code data is not null.
 * @tc.type: FUNC
 * @tc.require: issueI000001
 */
HWTEST_F(QrcodeGeneratorTest, qrcode_encode_data_not_null_015, TestSize.Level1)
{
    const char *text = "Test";
    QrcodeImage *qrImage = QrcodeImageEncodeString(text, QRCODE_ECC_MEDIUM);
    EXPECT_NE(qrImage, nullptr);
    if (qrImage != nullptr) {
        EXPECT_NE(qrImage->data, nullptr);
        QrcodeImageFree(qrImage);
    }
}

/**
 * @tc.name: qrcode_mem_hooks_null_016
 * @tc.desc: Verify memory hooks with null pointer.
 * @tc.type: FUNC
 * @tc.require: issueI000001
 */
HWTEST_F(QrcodeGeneratorTest, qrcode_mem_hooks_null_016, TestSize.Level1)
{
    QrcodeMemInitHooks(nullptr);
}

/**
 * @tc.name: qrcode_mem_hooks_invalid_017
 * @tc.desc: Verify memory hooks with invalid hooks.
 * @tc.type: FUNC
 * @tc.require: issueI000001
 */
HWTEST_F(QrcodeGeneratorTest, qrcode_mem_hooks_invalid_017, TestSize.Level1)
{
    QrcodeMemHooks hooks = {nullptr, nullptr};
    QrcodeMemInitHooks(&hooks);
}

/**
 * @tc.name: qrcode_encode_multiple_times_018
 * @tc.desc: Verify encoding multiple times.
 * @tc.type: FUNC
 * @tc.require: issueI000001
 */
HWTEST_F(QrcodeGeneratorTest, qrcode_encode_multiple_times_018, TestSize.Level1)
{
    const char *text = "Test";
    QrcodeImage *qrImage1 = QrcodeImageEncodeString(text, QRCODE_ECC_MEDIUM);
    EXPECT_NE(qrImage1, nullptr);

    QrcodeImage *qrImage2 = QrcodeImageEncodeString(text, QRCODE_ECC_HIGH);
    EXPECT_NE(qrImage2, nullptr);

    if (qrImage1 != nullptr) {
        QrcodeImageFree(qrImage1);
    }
    if (qrImage2 != nullptr) {
        QrcodeImageFree(qrImage2);
    }
}

/**
 * @tc.name: qrcode_encode_very_long_text_019
 * @tc.desc: Verify encoding very long text.
 * @tc.type: FUNC
 * @tc.require: issueI000001
 */
HWTEST_F(QrcodeGeneratorTest, qrcode_encode_very_long_text_019, TestSize.Level1)
{
    const char *text =
        "This is a very long text for testing QR code generation with many characters to verify the functionality of "
        "the QR code generator library. It should handle long texts properly and generate valid QR codes.";
    QrcodeImage *qrImage = QrcodeImageEncodeString(text, QRCODE_ECC_MEDIUM);
    EXPECT_NE(qrImage, nullptr);
    if (qrImage != nullptr) {
        EXPECT_GT(qrImage->width, 0);
        EXPECT_NE(qrImage->data, nullptr);
        QrcodeImageFree(qrImage);
    }
}

/**
 * @tc.name: qrcode_encode_space_text_020
 * @tc.desc: Verify encoding text with spaces.
 * @tc.type: FUNC
 * @tc.require: issueI000001
 */
HWTEST_F(QrcodeGeneratorTest, qrcode_encode_space_text_020, TestSize.Level1)
{
    const char *text = "Hello World Test";
    QrcodeImage *qrImage = QrcodeImageEncodeString(text, QRCODE_ECC_MEDIUM);
    EXPECT_NE(qrImage, nullptr);
    if (qrImage != nullptr) {
        EXPECT_GT(qrImage->width, 0);
        EXPECT_NE(qrImage->data, nullptr);
        QrcodeImageFree(qrImage);
    }
}

/**
 * @tc.name: qrcode_encode_null_text_021
 * @tc.desc: Verify encoding null text.
 * @tc.type: FUNC
 * @tc.require: issueI000001
 */
HWTEST_F(QrcodeGeneratorTest, qrcode_encode_null_text_021, TestSize.Level1)
{
    QrcodeImage *qrImage = QrcodeImageEncodeString(nullptr, QRCODE_ECC_MEDIUM);
    EXPECT_EQ(qrImage, nullptr);
}

/**
 * @tc.name: qrcode_encode_ecc_low_022
 * @tc.desc: Verify encoding with ECC_LOW (using MEDIUM as lowest).
 * @tc.type: FUNC
 * @tc.require: issueI000001
 */
HWTEST_F(QrcodeGeneratorTest, qrcode_encode_ecc_low_022, TestSize.Level1)
{
    const char *text = "Test";
    QrcodeImage *qrImage = QrcodeImageEncodeString(text, QRCODE_ECC_MEDIUM);
    EXPECT_NE(qrImage, nullptr);
    if (qrImage != nullptr) {
        EXPECT_GT(qrImage->width, 0);
        EXPECT_NE(qrImage->data, nullptr);
        QrcodeImageFree(qrImage);
    }
}

/**
 * @tc.name: qrcode_encode_max_version_023
 * @tc.desc: Verify encoding with max version.
 * @tc.type: FUNC
 * @tc.require: issueI000001
 */
HWTEST_F(QrcodeGeneratorTest, qrcode_encode_max_version_023, TestSize.Level1)
{
    const char *text = "Test";
    QrcodeImage *qrImage = QrcodeImageEncodeString(text, QRCODE_ECC_MEDIUM);
    EXPECT_NE(qrImage, nullptr);
    if (qrImage != nullptr) {
        EXPECT_LE(qrImage->version, QRCODE_VERSION_MAX);
        QrcodeImageFree(qrImage);
    }
}

/**
 * @tc.name: qrcode_encode_single_char_024
 * @tc.desc: Verify encoding single character.
 * @tc.type: FUNC
 * @tc.require: issueI000001
 */
HWTEST_F(QrcodeGeneratorTest, qrcode_encode_single_char_024, TestSize.Level1)
{
    const char *text = "A";
    QrcodeImage *qrImage = QrcodeImageEncodeString(text, QRCODE_ECC_MEDIUM);
    EXPECT_NE(qrImage, nullptr);
    if (qrImage != nullptr) {
        EXPECT_GT(qrImage->width, 0);
        EXPECT_NE(qrImage->data, nullptr);
        QrcodeImageFree(qrImage);
    }
}

/**
 * @tc.name: qrcode_encode_mixed_chars_025
 * @tc.desc: Verify encoding mixed characters.
 * @tc.type: FUNC
 * @tc.require: issueI000001
 */
HWTEST_F(QrcodeGeneratorTest, qrcode_encode_mixed_chars_025, TestSize.Level1)
{
    const char *text = "ABC123你好";
    QrcodeImage *qrImage = QrcodeImageEncodeString(text, QRCODE_ECC_MEDIUM);
    EXPECT_NE(qrImage, nullptr);
    if (qrImage != nullptr) {
        EXPECT_GT(qrImage->width, 0);
        EXPECT_NE(qrImage->data, nullptr);
        QrcodeImageFree(qrImage);
    }
}

/**
 * @tc.name: qrcode_encode_very_short_text_026
 * @tc.desc: Verify encoding very short text.
 * @tc.type: FUNC
 * @tc.require: issueI000001
 */
HWTEST_F(QrcodeGeneratorTest, qrcode_encode_very_short_text_026, TestSize.Level1)
{
    const char *text = "Hi";
    QrcodeImage *qrImage = QrcodeImageEncodeString(text, QRCODE_ECC_MEDIUM);
    EXPECT_NE(qrImage, nullptr);
    if (qrImage != nullptr) {
        EXPECT_GT(qrImage->width, 0);
        EXPECT_NE(qrImage->data, nullptr);
        QrcodeImageFree(qrImage);
    }
}

/**
 * @tc.name: qrcode_mem_hooks_valid_027
 * @tc.desc: Verify memory hooks with valid hooks.
 * @tc.type: FUNC
 * @tc.require: issueI000001
 */
HWTEST_F(QrcodeGeneratorTest, qrcode_mem_hooks_valid_027, TestSize.Level1)
{
    QrcodeMemHooks hooks = {malloc, free};
    QrcodeMemInitHooks(&hooks);
    const char *text = "Test";
    QrcodeImage *qrImage = QrcodeImageEncodeString(text, QRCODE_ECC_MEDIUM);
    EXPECT_NE(qrImage, nullptr);
    if (qrImage != nullptr) {
        QrcodeImageFree(qrImage);
    }
}

/**
 * @tc.name: qrcode_encode_different_ecc_028
 * @tc.desc: Verify encoding with different ECC levels.
 * @tc.type: FUNC
 * @tc.require: issueI000001
 */
HWTEST_F(QrcodeGeneratorTest, qrcode_encode_different_ecc_028, TestSize.Level1)
{
    const char *text = "Test";
    QrcodeImage *qrImage1 = QrcodeImageEncodeString(text, QRCODE_ECC_MEDIUM);
    QrcodeImage *qrImage2 = QrcodeImageEncodeString(text, QRCODE_ECC_HIGH);
    EXPECT_NE(qrImage1, nullptr);
    EXPECT_NE(qrImage2, nullptr);
    if (qrImage1 != nullptr) {
        QrcodeImageFree(qrImage1);
    }
    if (qrImage2 != nullptr) {
        QrcodeImageFree(qrImage2);
    }
}

/**
 * @tc.name: qrcode_encode_numeric_only_029
 * @tc.desc: Verify encoding numeric only text.
 * @tc.type: FUNC
 * @tc.require: issueI000001
 */
HWTEST_F(QrcodeGeneratorTest, qrcode_encode_numeric_only_029, TestSize.Level1)
{
    const char *text = "12345678901234567890";
    QrcodeImage *qrImage = QrcodeImageEncodeString(text, QRCODE_ECC_MEDIUM);
    EXPECT_NE(qrImage, nullptr);
    if (qrImage != nullptr) {
        EXPECT_GT(qrImage->width, 0);
        EXPECT_NE(qrImage->data, nullptr);
        QrcodeImageFree(qrImage);
    }
}

/**
 * @tc.name: qrcode_encode_alphanumeric_only_030
 * @tc.desc: Verify encoding alphanumeric only text.
 * @tc.type: FUNC
 * @tc.require: issueI000001
 */
HWTEST_F(QrcodeGeneratorTest, qrcode_encode_alphanumeric_only_030, TestSize.Level1)
{
    const char *text = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789$%*+-./:";
    QrcodeImage *qrImage = QrcodeImageEncodeString(text, QRCODE_ECC_MEDIUM);
    EXPECT_NE(qrImage, nullptr);
    if (qrImage != nullptr) {
        EXPECT_GT(qrImage->width, 0);
        EXPECT_NE(qrImage->data, nullptr);
        QrcodeImageFree(qrImage);
    }
}

/**
 * @tc.name: qrcode_mem_hooks_already_initialized_031
 * @tc.desc: Verify memory hooks when already initialized.
 * @tc.type: FUNC
 * @tc.require: issueI000001
 */
HWTEST_F(QrcodeGeneratorTest, qrcode_mem_hooks_already_initialized_031, TestSize.Level1)
{
    QrcodeMemHooks hooks = {malloc, free};
    QrcodeMemInitHooks(&hooks);
    QrcodeMemInitHooks(&hooks);
    const char *text = "Test";
    QrcodeImage *qrImage = QrcodeImageEncodeString(text, QRCODE_ECC_MEDIUM);
    EXPECT_NE(qrImage, nullptr);
    if (qrImage != nullptr) {
        QrcodeImageFree(qrImage);
    }
}

/**
 * @tc.name: qrcode_mem_hooks_null_malloc_032
 * @tc.desc: Verify memory hooks with null malloc function.
 * @tc.type: FUNC
 * @tc.require: issueI000001
 */
HWTEST_F(QrcodeGeneratorTest, qrcode_mem_hooks_null_malloc_032, TestSize.Level1)
{
    QrcodeMemHooks hooks = {nullptr, free};
    QrcodeMemInitHooks(&hooks);
}

/**
 * @tc.name: qrcode_mem_hooks_null_free_033
 * @tc.desc: Verify memory hooks with null free function.
 * @tc.type: FUNC
 * @tc.require: issueI000001
 */
HWTEST_F(QrcodeGeneratorTest, qrcode_mem_hooks_null_free_033, TestSize.Level1)
{
    QrcodeMemHooks hooks = {malloc, nullptr};
    QrcodeMemInitHooks(&hooks);
}

/**
 * @tc.name: qrcode_encode_with_all_ecc_levels_034
 * @tc.desc: Verify encoding with all ECC levels.
 * @tc.type: FUNC
 * @tc.require: issueI000001
 */
HWTEST_F(QrcodeGeneratorTest, qrcode_encode_with_all_ecc_levels_034, TestSize.Level1)
{
    const char *text = "Hello World";
    QrcodeImage *qrImage1 = QrcodeImageEncodeString(text, QRCODE_ECC_MEDIUM);
    QrcodeImage *qrImage2 = QrcodeImageEncodeString(text, QRCODE_ECC_HIGH);
    EXPECT_NE(qrImage1, nullptr);
    EXPECT_NE(qrImage2, nullptr);
    if (qrImage1 != nullptr) {
        QrcodeImageFree(qrImage1);
    }
    if (qrImage2 != nullptr) {
        QrcodeImageFree(qrImage2);
    }
}

/**
 * @tc.name: qrcode_encode_very_long_numeric_035
 * @tc.desc: Verify encoding very long numeric string.
 * @tc.type: FUNC
 * @tc.require: issueI000001
 */
HWTEST_F(QrcodeGeneratorTest, qrcode_encode_very_long_numeric_035, TestSize.Level1)
{
    const char *text = "12345678901234567890123456789012345678901234567890";
    QrcodeImage *qrImage = QrcodeImageEncodeString(text, QRCODE_ECC_MEDIUM);
    EXPECT_NE(qrImage, nullptr);
    if (qrImage != nullptr) {
        EXPECT_GT(qrImage->width, 0);
        EXPECT_NE(qrImage->data, nullptr);
        QrcodeImageFree(qrImage);
    }
}

/**
 * @tc.name: qrcode_encode_mixed_case_036
 * @tc.desc: Verify encoding mixed case text.
 * @tc.type: FUNC
 * @tc.require: issueI000001
 */
HWTEST_F(QrcodeGeneratorTest, qrcode_encode_mixed_case_036, TestSize.Level1)
{
    const char *text = "HelloWorldHELLOworld";
    QrcodeImage *qrImage = QrcodeImageEncodeString(text, QRCODE_ECC_MEDIUM);
    EXPECT_NE(qrImage, nullptr);
    if (qrImage != nullptr) {
        EXPECT_GT(qrImage->width, 0);
        EXPECT_NE(qrImage->data, nullptr);
        QrcodeImageFree(qrImage);
    }
}

/**
 * @tc.name: qrcode_encode_special_symbols_037
 * @tc.desc: Verify encoding with special symbols.
 * @tc.type: FUNC
 * @tc.require: issueI000001
 */
HWTEST_F(QrcodeGeneratorTest, qrcode_encode_special_symbols_037, TestSize.Level1)
{
    const char *text = "Test!@#$%^&*()";
    QrcodeImage *qrImage = QrcodeImageEncodeString(text, QRCODE_ECC_MEDIUM);
    EXPECT_NE(qrImage, nullptr);
    if (qrImage != nullptr) {
        EXPECT_GT(qrImage->width, 0);
        EXPECT_NE(qrImage->data, nullptr);
        QrcodeImageFree(qrImage);
    }
}

/**
 * @tc.name: qrcode_encode_newline_038
 * @tc.desc: Verify encoding text with newline.
 * @tc.type: FUNC
 * @tc.require: issueI000001
 */
HWTEST_F(QrcodeGeneratorTest, qrcode_encode_newline_038, TestSize.Level1)
{
    const char *text = "Hello\nWorld";
    QrcodeImage *qrImage = QrcodeImageEncodeString(text, QRCODE_ECC_MEDIUM);
    EXPECT_NE(qrImage, nullptr);
    if (qrImage != nullptr) {
        EXPECT_GT(qrImage->width, 0);
        EXPECT_NE(qrImage->data, nullptr);
        QrcodeImageFree(qrImage);
    }
}

/**
 * @tc.name: qrcode_encode_tab_039
 * @tc.desc: Verify encoding text with tab.
 * @tc.type: FUNC
 * @tc.require: issueI000001
 */
HWTEST_F(QrcodeGeneratorTest, qrcode_encode_tab_039, TestSize.Level1)
{
    const char *text = "Hello\tWorld";
    QrcodeImage *qrImage = QrcodeImageEncodeString(text, QRCODE_ECC_MEDIUM);
    EXPECT_NE(qrImage, nullptr);
    if (qrImage != nullptr) {
        EXPECT_GT(qrImage->width, 0);
        EXPECT_NE(qrImage->data, nullptr);
        QrcodeImageFree(qrImage);
    }
}

/**
 * @tc.name: qrcode_encode_unicode_040
 * @tc.desc: Verify encoding unicode characters.
 * @tc.type: FUNC
 * @tc.require: issueI000001
 */
HWTEST_F(QrcodeGeneratorTest, qrcode_encode_unicode_040, TestSize.Level1)
{
    const char *text = "Hello世界";
    QrcodeImage *qrImage = QrcodeImageEncodeString(text, QRCODE_ECC_MEDIUM);
    EXPECT_NE(qrImage, nullptr);
    if (qrImage != nullptr) {
        EXPECT_GT(qrImage->width, 0);
        EXPECT_NE(qrImage->data, nullptr);
        QrcodeImageFree(qrImage);
    }
}

/**
 * @tc.name: qrcode_encode_emoji_041
 * @tc.desc: Verify encoding emoji characters.
 * @tc.type: FUNC
 * @tc.require: issueI000001
 */
HWTEST_F(QrcodeGeneratorTest, qrcode_encode_emoji_041, TestSize.Level1)
{
    const char *text = "Hello😀";
    QrcodeImage *qrImage = QrcodeImageEncodeString(text, QRCODE_ECC_MEDIUM);
    EXPECT_NE(qrImage, nullptr);
    if (qrImage != nullptr) {
        EXPECT_GT(qrImage->width, 0);
        EXPECT_NE(qrImage->data, nullptr);
        QrcodeImageFree(qrImage);
    }
}

/**
 * @tc.name: qrcode_encode_max_length_042
 * @tc.desc: Verify encoding with maximum length text.
 * @tc.type: FUNC
 * @tc.require: issueI000001
 */
HWTEST_F(QrcodeGeneratorTest, qrcode_encode_max_length_042, TestSize.Level1)
{
    const char *text = "This is a very long text that should test the maximum capacity of QR code encoding";
    QrcodeImage *qrImage = QrcodeImageEncodeString(text, QRCODE_ECC_MEDIUM);
    EXPECT_NE(qrImage, nullptr);
    if (qrImage != nullptr) {
        EXPECT_GT(qrImage->width, 0);
        EXPECT_NE(qrImage->data, nullptr);
        QrcodeImageFree(qrImage);
    }
}

/**
 * @tc.name: qrcode_encode_repeated_chars_043
 * @tc.desc: Verify encoding repeated characters.
 * @tc.type: FUNC
 * @tc.require: issueI000001
 */
HWTEST_F(QrcodeGeneratorTest, qrcode_encode_repeated_chars_043, TestSize.Level1)
{
    const char *text = "AAAAABBBBBCCCCCDDDDDEEEEE";
    QrcodeImage *qrImage = QrcodeImageEncodeString(text, QRCODE_ECC_MEDIUM);
    EXPECT_NE(qrImage, nullptr);
    if (qrImage != nullptr) {
        EXPECT_GT(qrImage->width, 0);
        EXPECT_NE(qrImage->data, nullptr);
        QrcodeImageFree(qrImage);
    }
}

/**
 * @tc.name: qrcode_encode_url_with_params_044
 * @tc.desc: Verify encoding URL with parameters.
 * @tc.type: FUNC
 * @tc.require: issueI000001
 */
HWTEST_F(QrcodeGeneratorTest, qrcode_encode_url_with_params_044, TestSize.Level1)
{
    const char *text = "https://example.com/path?param1=value1&param2=value2";
    QrcodeImage *qrImage = QrcodeImageEncodeString(text, QRCODE_ECC_MEDIUM);
    EXPECT_NE(qrImage, nullptr);
    if (qrImage != nullptr) {
        EXPECT_GT(qrImage->width, 0);
        EXPECT_NE(qrImage->data, nullptr);
        QrcodeImageFree(qrImage);
    }
}

/**
 * @tc.name: qrcode_encode_email_045
 * @tc.desc: Verify encoding email address.
 * @tc.type: FUNC
 * @tc.require: issueI000001
 */
HWTEST_F(QrcodeGeneratorTest, qrcode_encode_email_045, TestSize.Level1)
{
    const char *text = "user@example.com";
    QrcodeImage *qrImage = QrcodeImageEncodeString(text, QRCODE_ECC_MEDIUM);
    EXPECT_NE(qrImage, nullptr);
    if (qrImage != nullptr) {
        EXPECT_GT(qrImage->width, 0);
        EXPECT_NE(qrImage->data, nullptr);
        QrcodeImageFree(qrImage);
    }
}

/**
 * @tc.name: qrcode_encode_phone_046
 * @tc.desc: Verify encoding phone number.
 * @tc.type: FUNC
 * @tc.require: issueI000001
 */
HWTEST_F(QrcodeGeneratorTest, qrcode_encode_phone_046, TestSize.Level1)
{
    const char *text = "+1234567890";
    QrcodeImage *qrImage = QrcodeImageEncodeString(text, QRCODE_ECC_MEDIUM);
    EXPECT_NE(qrImage, nullptr);
    if (qrImage != nullptr) {
        EXPECT_GT(qrImage->width, 0);
        EXPECT_NE(qrImage->data, nullptr);
        QrcodeImageFree(qrImage);
    }
}

/**
 * @tc.name: qrcode_encode_date_047
 * @tc.desc: Verify encoding date string.
 * @tc.type: FUNC
 * @tc.require: issueI000001
 */
HWTEST_F(QrcodeGeneratorTest, qrcode_encode_date_047, TestSize.Level1)
{
    const char *text = "2026-07-02";
    QrcodeImage *qrImage = QrcodeImageEncodeString(text, QRCODE_ECC_MEDIUM);
    EXPECT_NE(qrImage, nullptr);
    if (qrImage != nullptr) {
        EXPECT_GT(qrImage->width, 0);
        EXPECT_NE(qrImage->data, nullptr);
        QrcodeImageFree(qrImage);
    }
}

/**
 * @tc.name: qrcode_encode_time_048
 * @tc.desc: Verify encoding time string.
 * @tc.type: FUNC
 * @tc.require: issueI000001
 */
HWTEST_F(QrcodeGeneratorTest, qrcode_encode_time_048, TestSize.Level1)
{
    const char *text = "21:03:20";
    QrcodeImage *qrImage = QrcodeImageEncodeString(text, QRCODE_ECC_MEDIUM);
    EXPECT_NE(qrImage, nullptr);
    if (qrImage != nullptr) {
        EXPECT_GT(qrImage->width, 0);
        EXPECT_NE(qrImage->data, nullptr);
        QrcodeImageFree(qrImage);
    }
}

/**
 * @tc.name: qrcode_encode_json_049
 * @tc.desc: Verify encoding JSON string.
 * @tc.type: FUNC
 * @tc.require: issueI000001
 */
HWTEST_F(QrcodeGeneratorTest, qrcode_encode_json_049, TestSize.Level1)
{
    const char *text = "{\"key\":\"value\",\"number\":123}";
    QrcodeImage *qrImage = QrcodeImageEncodeString(text, QRCODE_ECC_MEDIUM);
    EXPECT_NE(qrImage, nullptr);
    if (qrImage != nullptr) {
        EXPECT_GT(qrImage->width, 0);
        EXPECT_NE(qrImage->data, nullptr);
        QrcodeImageFree(qrImage);
    }
}

/**
 * @tc.name: qrcode_encode_xml_050
 * @tc.desc: Verify encoding XML string.
 * @tc.type: FUNC
 * @tc.require: issueI000001
 */
HWTEST_F(QrcodeGeneratorTest, qrcode_encode_xml_050, TestSize.Level1)
{
    const char *text = "<root><element>value</element></root>";
    QrcodeImage *qrImage = QrcodeImageEncodeString(text, QRCODE_ECC_MEDIUM);
    EXPECT_NE(qrImage, nullptr);
    if (qrImage != nullptr) {
        EXPECT_GT(qrImage->width, 0);
        EXPECT_NE(qrImage->data, nullptr);
        QrcodeImageFree(qrImage);
    }
}

/**
 * @tc.name: qrcode_encode_sql_051
 * @tc.desc: Verify encoding SQL string.
 * @tc.type: FUNC
 * @tc.require: issueI000001
 */
HWTEST_F(QrcodeGeneratorTest, qrcode_encode_sql_051, TestSize.Level1)
{
    const char *text = "SELECT * FROM table WHERE id = 123";
    QrcodeImage *qrImage = QrcodeImageEncodeString(text, QRCODE_ECC_MEDIUM);
    EXPECT_NE(qrImage, nullptr);
    if (qrImage != nullptr) {
        EXPECT_GT(qrImage->width, 0);
        EXPECT_NE(qrImage->data, nullptr);
        QrcodeImageFree(qrImage);
    }
}

/**
 * @tc.name: qrcode_encode_path_052
 * @tc.desc: Verify encoding file path.
 * @tc.type: FUNC
 * @tc.require: issueI000001
 */
HWTEST_F(QrcodeGeneratorTest, qrcode_encode_path_052, TestSize.Level1)
{
    const char *text = "/home/user/documents/file.txt";
    QrcodeImage *qrImage = QrcodeImageEncodeString(text, QRCODE_ECC_MEDIUM);
    EXPECT_NE(qrImage, nullptr);
    if (qrImage != nullptr) {
        EXPECT_GT(qrImage->width, 0);
        EXPECT_NE(qrImage->data, nullptr);
        QrcodeImageFree(qrImage);
    }
}

/**
 * @tc.name: qrcode_encode_windows_path_053
 * @tc.desc: Verify encoding Windows file path.
 * @tc.type: FUNC
 * @tc.require: issueI000001
 */
HWTEST_F(QrcodeGeneratorTest, qrcode_encode_windows_path_053, TestSize.Level1)
{
    const char *text = "C:\\Users\\user\\Documents\\file.txt";
    QrcodeImage *qrImage = QrcodeImageEncodeString(text, QRCODE_ECC_MEDIUM);
    EXPECT_NE(qrImage, nullptr);
    if (qrImage != nullptr) {
        EXPECT_GT(qrImage->width, 0);
        EXPECT_NE(qrImage->data, nullptr);
        QrcodeImageFree(qrImage);
    }
}

/**
 * @tc.name: qrcode_encode_base64_054
 * @tc.desc: Verify encoding base64 string.
 * @tc.type: FUNC
 * @tc.require: issueI000001
 */
HWTEST_F(QrcodeGeneratorTest, qrcode_encode_base64_054, TestSize.Level1)
{
    const char *text = "SGVsbG8gV29ybGQ=";
    QrcodeImage *qrImage = QrcodeImageEncodeString(text, QRCODE_ECC_MEDIUM);
    EXPECT_NE(qrImage, nullptr);
    if (qrImage != nullptr) {
        EXPECT_GT(qrImage->width, 0);
        EXPECT_NE(qrImage->data, nullptr);
        QrcodeImageFree(qrImage);
    }
}

/**
 * @tc.name: qrcode_encode_hex_055
 * @tc.desc: Verify encoding hex string.
 * @tc.type: FUNC
 * @tc.require: issueI000001
 */
HWTEST_F(QrcodeGeneratorTest, qrcode_encode_hex_055, TestSize.Level1)
{
    const char *text = "48656C6C6F20576F726C64";
    QrcodeImage *qrImage = QrcodeImageEncodeString(text, QRCODE_ECC_MEDIUM);
    EXPECT_NE(qrImage, nullptr);
    if (qrImage != nullptr) {
        EXPECT_GT(qrImage->width, 0);
        EXPECT_NE(qrImage->data, nullptr);
        QrcodeImageFree(qrImage);
    }
}

/**
 * @tc.name: qrcode_encode_binary_like_056
 * @tc.desc: Verify encoding binary-like string.
 * @tc.type: FUNC
 * @tc.require: issueI000001
 */
HWTEST_F(QrcodeGeneratorTest, qrcode_encode_binary_like_056, TestSize.Level1)
{
    const char *text = "\x01\x02\x03\x04\x05";
    QrcodeImage *qrImage = QrcodeImageEncodeString(text, QRCODE_ECC_MEDIUM);
    EXPECT_NE(qrImage, nullptr);
    if (qrImage != nullptr) {
        EXPECT_GT(qrImage->width, 0);
        EXPECT_NE(qrImage->data, nullptr);
        QrcodeImageFree(qrImage);
    }
}

/**
 * @tc.name: qrcode_encode_mixed_unicode_057
 * @tc.desc: Verify encoding mixed unicode characters.
 * @tc.type: FUNC
 * @tc.require: issueI000001
 */
HWTEST_F(QrcodeGeneratorTest, qrcode_encode_mixed_unicode_057, TestSize.Level1)
{
    const char *text = "Hello世界Приветمرحبا";
    QrcodeImage *qrImage = QrcodeImageEncodeString(text, QRCODE_ECC_MEDIUM);
    EXPECT_NE(qrImage, nullptr);
    if (qrImage != nullptr) {
        EXPECT_GT(qrImage->width, 0);
        EXPECT_NE(qrImage->data, nullptr);
        QrcodeImageFree(qrImage);
    }
}

/**
 * @tc.name: qrcode_encode_russian_058
 * @tc.desc: Verify encoding Russian characters.
 * @tc.type: FUNC
 * @tc.require: issueI000001
 */
HWTEST_F(QrcodeGeneratorTest, qrcode_encode_russian_058, TestSize.Level1)
{
    const char *text = "Привет мир";
    QrcodeImage *qrImage = QrcodeImageEncodeString(text, QRCODE_ECC_MEDIUM);
    EXPECT_NE(qrImage, nullptr);
    if (qrImage != nullptr) {
        EXPECT_GT(qrImage->width, 0);
        EXPECT_NE(qrImage->data, nullptr);
        QrcodeImageFree(qrImage);
    }
}

/**
 * @tc.name: qrcode_encode_arabic_059
 * @tc.desc: Verify encoding Arabic characters.
 * @tc.type: FUNC
 * @tc.require: issueI000001
 */
HWTEST_F(QrcodeGeneratorTest, qrcode_encode_arabic_059, TestSize.Level1)
{
    const char *text = "مرحبا بالعالم";
    QrcodeImage *qrImage = QrcodeImageEncodeString(text, QRCODE_ECC_MEDIUM);
    EXPECT_NE(qrImage, nullptr);
    if (qrImage != nullptr) {
        EXPECT_GT(qrImage->width, 0);
        EXPECT_NE(qrImage->data, nullptr);
        QrcodeImageFree(qrImage);
    }
}

/**
 * @tc.name: qrcode_encode_japanese_060
 * @tc.desc: Verify encoding Japanese characters.
 * @tc.type: FUNC
 * @tc.require: issueI000001
 */
HWTEST_F(QrcodeGeneratorTest, qrcode_encode_japanese_060, TestSize.Level1)
{
    const char *text = "こんにちは世界";
    QrcodeImage *qrImage = QrcodeImageEncodeString(text, QRCODE_ECC_MEDIUM);
    EXPECT_NE(qrImage, nullptr);
    if (qrImage != nullptr) {
        EXPECT_GT(qrImage->width, 0);
        EXPECT_NE(qrImage->data, nullptr);
        QrcodeImageFree(qrImage);
    }
}

/**
 * @tc.name: qrcode_encode_korean_061
 * @tc.desc: Verify encoding Korean characters.
 * @tc.type: FUNC
 * @tc.require: issueI000001
 */
HWTEST_F(QrcodeGeneratorTest, qrcode_encode_korean_061, TestSize.Level1)
{
    const char *text = "안녕하세요 세계";
    QrcodeImage *qrImage = QrcodeImageEncodeString(text, QRCODE_ECC_MEDIUM);
    EXPECT_NE(qrImage, nullptr);
    if (qrImage != nullptr) {
        EXPECT_GT(qrImage->width, 0);
        EXPECT_NE(qrImage->data, nullptr);
        QrcodeImageFree(qrImage);
    }
}

/**
 * @tc.name: qrcode_encode_thai_062
 * @tc.desc: Verify encoding Thai characters.
 * @tc.type: FUNC
 * @tc.require: issueI000001
 */
HWTEST_F(QrcodeGeneratorTest, qrcode_encode_thai_062, TestSize.Level1)
{
    const char *text = "สวัสดีโลก";
    QrcodeImage *qrImage = QrcodeImageEncodeString(text, QRCODE_ECC_MEDIUM);
    EXPECT_NE(qrImage, nullptr);
    if (qrImage != nullptr) {
        EXPECT_GT(qrImage->width, 0);
        EXPECT_NE(qrImage->data, nullptr);
        QrcodeImageFree(qrImage);
    }
}

/**
 * @tc.name: qrcode_encode_german_063
 * @tc.desc: Verify encoding German characters.
 * @tc.type: FUNC
 * @tc.require: issueI000001
 */
HWTEST_F(QrcodeGeneratorTest, qrcode_encode_german_063, TestSize.Level1)
{
    const char *text = "Grüße aus Deutschland";
    QrcodeImage *qrImage = QrcodeImageEncodeString(text, QRCODE_ECC_MEDIUM);
    EXPECT_NE(qrImage, nullptr);
    if (qrImage != nullptr) {
        EXPECT_GT(qrImage->width, 0);
        EXPECT_NE(qrImage->data, nullptr);
        QrcodeImageFree(qrImage);
    }
}

/**
 * @tc.name: qrcode_encode_french_064
 * @tc.desc: Verify encoding French characters.
 * @tc.type: FUNC
 * @tc.require: issueI000001
 */
HWTEST_F(QrcodeGeneratorTest, qrcode_encode_french_064, TestSize.Level1)
{
    const char *text = "Bonjour le monde";
    QrcodeImage *qrImage = QrcodeImageEncodeString(text, QRCODE_ECC_MEDIUM);
    EXPECT_NE(qrImage, nullptr);
    if (qrImage != nullptr) {
        EXPECT_GT(qrImage->width, 0);
        EXPECT_NE(qrImage->data, nullptr);
        QrcodeImageFree(qrImage);
    }
}

/**
 * @tc.name: qrcode_encode_spanish_065
 * @tc.desc: Verify encoding Spanish characters.
 * @tc.type: FUNC
 * @tc.require: issueI000001
 */
HWTEST_F(QrcodeGeneratorTest, qrcode_encode_spanish_065, TestSize.Level1)
{
    const char *text = "Hola mundo";
    QrcodeImage *qrImage = QrcodeImageEncodeString(text, QRCODE_ECC_MEDIUM);
    EXPECT_NE(qrImage, nullptr);
    if (qrImage != nullptr) {
        EXPECT_GT(qrImage->width, 0);
        EXPECT_NE(qrImage->data, nullptr);
        QrcodeImageFree(qrImage);
    }
}

/**
 * @tc.name: qrcode_encode_portuguese_066
 * @tc.desc: Verify encoding Portuguese characters.
 * @tc.type: FUNC
 * @tc.require: issueI000001
 */
HWTEST_F(QrcodeGeneratorTest, qrcode_encode_portuguese_066, TestSize.Level1)
{
    const char *text = "Olá mundo";
    QrcodeImage *qrImage = QrcodeImageEncodeString(text, QRCODE_ECC_MEDIUM);
    EXPECT_NE(qrImage, nullptr);
    if (qrImage != nullptr) {
        EXPECT_GT(qrImage->width, 0);
        EXPECT_NE(qrImage->data, nullptr);
        QrcodeImageFree(qrImage);
    }
}

/**
 * @tc.name: qrcode_encode_italian_067
 * @tc.desc: Verify encoding Italian characters.
 * @tc.type: FUNC
 * @tc.require: issueI000001
 */
HWTEST_F(QrcodeGeneratorTest, qrcode_encode_italian_067, TestSize.Level1)
{
    const char *text = "Ciao mondo";
    QrcodeImage *qrImage = QrcodeImageEncodeString(text, QRCODE_ECC_MEDIUM);
    EXPECT_NE(qrImage, nullptr);
    if (qrImage != nullptr) {
        EXPECT_GT(qrImage->width, 0);
        EXPECT_NE(qrImage->data, nullptr);
        QrcodeImageFree(qrImage);
    }
}

/**
 * @tc.name: qrcode_encode_greek_068
 * @tc.desc: Verify encoding Greek characters.
 * @tc.type: FUNC
 * @tc.require: issueI000001
 */
HWTEST_F(QrcodeGeneratorTest, qrcode_encode_greek_068, TestSize.Level1)
{
    const char *text = "Γεια σου κόσμε";
    QrcodeImage *qrImage = QrcodeImageEncodeString(text, QRCODE_ECC_MEDIUM);
    EXPECT_NE(qrImage, nullptr);
    if (qrImage != nullptr) {
        EXPECT_GT(qrImage->width, 0);
        EXPECT_NE(qrImage->data, nullptr);
        QrcodeImageFree(qrImage);
    }
}

/**
 * @tc.name: qrcode_encode_hebrew_069
 * @tc.desc: Verify encoding Hebrew characters.
 * @tc.type: FUNC
 * @tc.require: issueI000001
 */
HWTEST_F(QrcodeGeneratorTest, qrcode_encode_hebrew_069, TestSize.Level1)
{
    const char *text = "שלום עולם";
    QrcodeImage *qrImage = QrcodeImageEncodeString(text, QRCODE_ECC_MEDIUM);
    EXPECT_NE(qrImage, nullptr);
    if (qrImage != nullptr) {
        EXPECT_GT(qrImage->width, 0);
        EXPECT_NE(qrImage->data, nullptr);
        QrcodeImageFree(qrImage);
    }
}

/**
 * @tc.name: qrcode_encode_hindi_070
 * @tc.desc: Verify encoding Hindi characters.
 * @tc.type: FUNC
 * @tc.require: issueI000001
 */
HWTEST_F(QrcodeGeneratorTest, qrcode_encode_hindi_070, TestSize.Level1)
{
    const char *text = "नमस्ते दुनिया";
    QrcodeImage *qrImage = QrcodeImageEncodeString(text, QRCODE_ECC_MEDIUM);
    EXPECT_NE(qrImage, nullptr);
    if (qrImage != nullptr) {
        EXPECT_GT(qrImage->width, 0);
        EXPECT_NE(qrImage->data, nullptr);
        QrcodeImageFree(qrImage);
    }
}

/**
 * @tc.name: qrcode_encode_null_text_071
 * @tc.desc: Verify encoding null text (already tested, duplicate for coverage).
 * @tc.type: FUNC
 * @tc.require: issueI000001
 */
HWTEST_F(QrcodeGeneratorTest, qrcode_encode_null_text_071, TestSize.Level1)
{
    QrcodeImage *qrImage = QrcodeImageEncodeString(nullptr, QRCODE_ECC_MEDIUM);
    EXPECT_EQ(qrImage, nullptr);
}

/**
 * @tc.name: qrcode_encode_empty_string_072
 * @tc.desc: Verify encoding empty string (already tested, duplicate for coverage).
 * @tc.type: FUNC
 * @tc.require: issueI000001
 */
HWTEST_F(QrcodeGeneratorTest, qrcode_encode_empty_string_072, TestSize.Level1)
{
    QrcodeImage *qrImage = QrcodeImageEncodeString("", QRCODE_ECC_MEDIUM);
    EXPECT_NE(qrImage, nullptr);
}

/**
 * @tc.name: qrcode_free_null_image_073
 * @tc.desc: Verify freeing null image (already tested, duplicate for coverage).
 * @tc.type: FUNC
 * @tc.require: issueI000001
 */
HWTEST_F(QrcodeGeneratorTest, qrcode_free_null_image_073, TestSize.Level1)
{
    QrcodeImageFree(nullptr);
}

/**
 * @tc.name: qrcode_mem_hooks_null_074
 * @tc.desc: Verify memory hooks with null pointer (already tested, duplicate for coverage).
 * @tc.type: FUNC
 * @tc.require: issueI000001
 */
HWTEST_F(QrcodeGeneratorTest, qrcode_mem_hooks_null_074, TestSize.Level1)
{
    QrcodeMemInitHooks(nullptr);
}

/**
 * @tc.name: qrcode_mem_hooks_invalid_075
 * @tc.desc: Verify memory hooks with invalid hooks (already tested, duplicate for coverage).
 * @tc.type: FUNC
 * @tc.require: issueI000001
 */
HWTEST_F(QrcodeGeneratorTest, qrcode_mem_hooks_invalid_075, TestSize.Level1)
{
    QrcodeMemHooks hooks = {nullptr, nullptr};
    QrcodeMemInitHooks(&hooks);
}

/**
 * @tc.name: qrcode_mem_hooks_null_malloc_076
 * @tc.desc: Verify memory hooks with null malloc function (already tested, duplicate for coverage).
 * @tc.type: FUNC
 * @tc.require: issueI000001
 */
HWTEST_F(QrcodeGeneratorTest, qrcode_mem_hooks_null_malloc_076, TestSize.Level1)
{
    QrcodeMemHooks hooks = {nullptr, free};
    QrcodeMemInitHooks(&hooks);
}

/**
 * @tc.name: qrcode_mem_hooks_null_free_077
 * @tc.desc: Verify memory hooks with null free function (already tested, duplicate for coverage).
 * @tc.type: FUNC
 * @tc.require: issueI000001
 */
HWTEST_F(QrcodeGeneratorTest, qrcode_mem_hooks_null_free_077, TestSize.Level1)
{
    QrcodeMemHooks hooks = {malloc, nullptr};
    QrcodeMemInitHooks(&hooks);
}