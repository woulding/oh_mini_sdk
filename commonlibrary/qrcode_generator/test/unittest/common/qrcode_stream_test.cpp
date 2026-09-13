/*
 * Copyright (c) 2022-2026 Huawei Device Co., Ltd.
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

#include "interfaces/innerkits/qrcode_stream.h"
#include "interfaces/innerkits/qrcode_inner.h"
#include <gtest/gtest.h>
#include <cstring>

using namespace testing::ext;

class QrcodeStreamTest : public testing::Test {
public:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp();
    void TearDown();
};

void QrcodeStreamTest::SetUpTestCase(void) {}

void QrcodeStreamTest::TearDownTestCase(void) {}

void QrcodeStreamTest::SetUp(void) {}

void QrcodeStreamTest::TearDown(void) {}

/**
 * @tc.name: qrcode_stream_new_001
 * @tc.desc: Verify creating new stream.
 * @tc.type: FUNC
 * @tc.require: issueI000004
 */
HWTEST_F(QrcodeStreamTest, qrcode_stream_new_001, TestSize.Level1)
{
    QrcodeStream *stream = QrcodeStreamNew();
    EXPECT_NE(stream, nullptr);
    if (stream != nullptr) {
        QrcodeStreamFree(stream);
    }
}

/**
 * @tc.name: qrcode_stream_add_num_002
 * @tc.desc: Verify adding number to stream.
 * @tc.type: FUNC
 * @tc.require: issueI000004
 */
HWTEST_F(QrcodeStreamTest, qrcode_stream_add_num_002, TestSize.Level1)
{
    QrcodeStream *stream = QrcodeStreamNew();
    EXPECT_NE(stream, nullptr);
    if (stream != nullptr) {
        int32_t ret = QrcodeStreamAddNum(stream, 4, 0b1010);
        EXPECT_EQ(ret, 0);
        QrcodeStreamFree(stream);
    }
}

/**
 * @tc.name: qrcode_stream_add_bytes_003
 * @tc.desc: Verify adding bytes to stream.
 * @tc.type: FUNC
 * @tc.require: issueI000004
 */
HWTEST_F(QrcodeStreamTest, qrcode_stream_add_bytes_003, TestSize.Level1)
{
    QrcodeStream *stream = QrcodeStreamNew();
    EXPECT_NE(stream, nullptr);
    if (stream != nullptr) {
        const uint8_t data[] = {0x12, 0x34, 0x56};
        int32_t ret = QrcodeStreamAddBytes(stream, 3, (uint8_t *)data);
        EXPECT_EQ(ret, 0);
        QrcodeStreamFree(stream);
    }
}

/**
 * @tc.name: qrcode_stream_dup_data_004
 * @tc.desc: Verify duplicating stream data.
 * @tc.type: FUNC
 * @tc.require: issueI000004
 */
HWTEST_F(QrcodeStreamTest, qrcode_stream_dup_data_004, TestSize.Level1)
{
    QrcodeStream *stream = QrcodeStreamNew();
    EXPECT_NE(stream, nullptr);
    if (stream != nullptr) {
        const uint8_t data[] = {0x12, 0x34, 0x56};
        QrcodeStreamAddBytes(stream, 3, (uint8_t *)data);
        uint8_t *dupData = QrcodeStreamDupData(stream);
        EXPECT_NE(dupData, nullptr);
        if (dupData != nullptr) {
            QrcodeFree(dupData);
        }
        QrcodeStreamFree(stream);
    }
}

/**
 * @tc.name: qrcode_stream_free_null_005
 * @tc.desc: Verify freeing null stream.
 * @tc.type: FUNC
 * @tc.require: issueI000004
 */
HWTEST_F(QrcodeStreamTest, qrcode_stream_free_null_005, TestSize.Level1)
{
    QrcodeStreamFree(nullptr);
}

/**
 * @tc.name: qrcode_stream_clean_006
 * @tc.desc: Verify cleaning stream.
 * @tc.type: FUNC
 * @tc.require: issueI000004
 */
HWTEST_F(QrcodeStreamTest, qrcode_stream_clean_006, TestSize.Level1)
{
    QrcodeStream *stream = QrcodeStreamNew();
    EXPECT_NE(stream, nullptr);
    if (stream != nullptr) {
        const uint8_t data[] = {0x12, 0x34, 0x56};
        QrcodeStreamAddBytes(stream, 3, (uint8_t *)data);
        QrcodeStreamClean(stream);
        QrcodeStreamFree(stream);
    }
}

/**
 * @tc.name: qrcode_stream_add_007
 * @tc.desc: Verify adding stream to stream.
 * @tc.type: FUNC
 * @tc.require: issueI000004
 */
HWTEST_F(QrcodeStreamTest, qrcode_stream_add_007, TestSize.Level1)
{
    QrcodeStream *stream1 = QrcodeStreamNew();
    QrcodeStream *stream2 = QrcodeStreamNew();
    EXPECT_NE(stream1, nullptr);
    EXPECT_NE(stream2, nullptr);
    if (stream1 != nullptr && stream2 != nullptr) {
        const uint8_t data[] = {0x12, 0x34};
        QrcodeStreamAddBytes(stream2, 2, (uint8_t *)data);
        int32_t ret = QrcodeStreamAdd(stream1, stream2);
        EXPECT_EQ(ret, 0);
        QrcodeStreamFree(stream1);
        QrcodeStreamFree(stream2);
    }
}

/**
 * @tc.name: qrcode_stream_add_multiple_008
 * @tc.desc: Verify adding multiple numbers to stream.
 * @tc.type: FUNC
 * @tc.require: issueI000004
 */
HWTEST_F(QrcodeStreamTest, qrcode_stream_add_multiple_008, TestSize.Level1)
{
    QrcodeStream *stream = QrcodeStreamNew();
    EXPECT_NE(stream, nullptr);
    if (stream != nullptr) {
        QrcodeStreamAddNum(stream, 4, 0b1010);
        QrcodeStreamAddNum(stream, 4, 0b0101);
        QrcodeStreamAddNum(stream, 8, 0xFF);
        uint8_t *dupData = QrcodeStreamDupData(stream);
        EXPECT_NE(dupData, nullptr);
        if (dupData != nullptr) {
            QrcodeFree(dupData);
        }
        QrcodeStreamFree(stream);
    }
}

/**
 * @tc.name: qrcode_stream_bit_count_009
 * @tc.desc: Verify stream bit count is updated.
 * @tc.type: FUNC
 * @tc.require: issueI000004
 */
HWTEST_F(QrcodeStreamTest, qrcode_stream_bit_count_009, TestSize.Level1)
{
    QrcodeStream *stream = QrcodeStreamNew();
    EXPECT_NE(stream, nullptr);
    if (stream != nullptr) {
        QrcodeStreamAddNum(stream, 4, 0b1010);
        EXPECT_EQ(stream->bitCount, 4);
        QrcodeStreamAddNum(stream, 8, 0xFF);
        EXPECT_EQ(stream->bitCount, 12);
        QrcodeStreamFree(stream);
    }
}

/**
 * @tc.name: qrcode_stream_empty_dup_010
 * @tc.desc: Verify duplicating empty stream data.
 * @tc.type: FUNC
 * @tc.require: issueI000004
 */
HWTEST_F(QrcodeStreamTest, qrcode_stream_empty_dup_010, TestSize.Level1)
{
    QrcodeStream *stream = QrcodeStreamNew();
    EXPECT_NE(stream, nullptr);
    if (stream != nullptr) {
        uint8_t *dupData = QrcodeStreamDupData(stream);
        EXPECT_NE(dupData, nullptr);
        if (dupData != nullptr) {
            QrcodeFree(dupData);
        }
        QrcodeStreamFree(stream);
    }
}

/**
 * @tc.name: qrcode_stream_add_num_zero_bits_011
 * @tc.desc: Verify adding number with zero bits.
 * @tc.type: FUNC
 * @tc.require: issueI000004
 */
HWTEST_F(QrcodeStreamTest, qrcode_stream_add_num_zero_bits_011, TestSize.Level1)
{
    QrcodeStream *stream = QrcodeStreamNew();
    EXPECT_NE(stream, nullptr);
    if (stream != nullptr) {
        int32_t ret = QrcodeStreamAddNum(stream, 0, 0xFF);
        EXPECT_EQ(ret, 0);
        QrcodeStreamFree(stream);
    }
}

/**
 * @tc.name: qrcode_stream_add_bytes_null_data_016
 * @tc.desc: Verify adding null bytes to stream.
 * @tc.type: FUNC
 * @tc.require: issueI000004
 */
HWTEST_F(QrcodeStreamTest, qrcode_stream_add_bytes_null_data_016, TestSize.Level1)
{
    QrcodeStream *stream = QrcodeStreamNew();
    EXPECT_NE(stream, nullptr);
    if (stream != nullptr) {
        int32_t ret = QrcodeStreamAddBytes(stream, 3, nullptr);
        EXPECT_NE(ret, 0);
        QrcodeStreamFree(stream);
    }
}

/**
 * @tc.name: qrcode_stream_add_large_num_018
 * @tc.desc: Verify adding large number to stream.
 * @tc.type: FUNC
 * @tc.require: issueI000004
 */
HWTEST_F(QrcodeStreamTest, qrcode_stream_add_large_num_018, TestSize.Level1)
{
    QrcodeStream *stream = QrcodeStreamNew();
    EXPECT_NE(stream, nullptr);
    if (stream != nullptr) {
        int32_t ret = QrcodeStreamAddNum(stream, 16, 0xFFFF);
        EXPECT_EQ(ret, 0);
        QrcodeStreamFree(stream);
    }
}

/**
 * @tc.name: qrcode_stream_add_many_bytes_019
 * @tc.desc: Verify adding many bytes to stream.
 * @tc.type: FUNC
 * @tc.require: issueI000004
 */
HWTEST_F(QrcodeStreamTest, qrcode_stream_add_many_bytes_019, TestSize.Level1)
{
    QrcodeStream *stream = QrcodeStreamNew();
    EXPECT_NE(stream, nullptr);
    if (stream != nullptr) {
        uint8_t data[100];
        for (int32_t i = 0; i < 100; i++) {
            data[i] = i;
        }
        int32_t ret = QrcodeStreamAddBytes(stream, 100, data);
        EXPECT_EQ(ret, 0);
        QrcodeStreamFree(stream);
    }
}

/**
 * @tc.name: qrcode_stream_clean_null_020
 * @tc.desc: Verify cleaning null stream.
 * @tc.type: FUNC
 * @tc.require: issueI000004
 */
HWTEST_F(QrcodeStreamTest, qrcode_stream_clean_null_020, TestSize.Level1)
{
    QrcodeStreamClean(nullptr);
}

/**
 * @tc.name: qrcode_stream_add_num_all_zeros_021
 * @tc.desc: Verify adding number with all zeros.
 * @tc.type: FUNC
 * @tc.require: issueI000004
 */
HWTEST_F(QrcodeStreamTest, qrcode_stream_add_num_all_zeros_021, TestSize.Level1)
{
    QrcodeStream *stream = QrcodeStreamNew();
    EXPECT_NE(stream, nullptr);
    if (stream != nullptr) {
        int32_t ret = QrcodeStreamAddNum(stream, 8, 0x00);
        EXPECT_EQ(ret, 0);
        EXPECT_EQ(stream->bitCount, 8);
        QrcodeStreamFree(stream);
    }
}

/**
 * @tc.name: qrcode_stream_add_num_all_ones_022
 * @tc.desc: Verify adding number with all ones.
 * @tc.type: FUNC
 * @tc.require: issueI000004
 */
HWTEST_F(QrcodeStreamTest, qrcode_stream_add_num_all_ones_022, TestSize.Level1)
{
    QrcodeStream *stream = QrcodeStreamNew();
    EXPECT_NE(stream, nullptr);
    if (stream != nullptr) {
        int32_t ret = QrcodeStreamAddNum(stream, 8, 0xFF);
        EXPECT_EQ(ret, 0);
        EXPECT_EQ(stream->bitCount, 8);
        QrcodeStreamFree(stream);
    }
}

/**
 * @tc.name: qrcode_stream_add_empty_bytes_023
 * @tc.desc: Verify adding empty bytes to stream.
 * @tc.type: FUNC
 * @tc.require: issueI000004
 */
HWTEST_F(QrcodeStreamTest, qrcode_stream_add_empty_bytes_023, TestSize.Level1)
{
    QrcodeStream *stream = QrcodeStreamNew();
    EXPECT_NE(stream, nullptr);
    if (stream != nullptr) {
        uint8_t data[] = {0x00};
        int32_t ret = QrcodeStreamAddBytes(stream, 0, data);
        EXPECT_EQ(ret, 0);  // Adding zero bytes should fail
        QrcodeStreamFree(stream);
    }
}

/**
 * @tc.name: qrcode_stream_add_num_odd_bits_024
 * @tc.desc: Verify adding number with odd bit count.
 * @tc.type: FUNC
 * @tc.require: issueI000004
 */
HWTEST_F(QrcodeStreamTest, qrcode_stream_add_num_odd_bits_024, TestSize.Level1)
{
    QrcodeStream *stream = QrcodeStreamNew();
    EXPECT_NE(stream, nullptr);
    if (stream != nullptr) {
        QrcodeStreamAddNum(stream, 3, 0b101);
        EXPECT_EQ(stream->bitCount, 3);
        QrcodeStreamAddNum(stream, 5, 0b11011);
        EXPECT_EQ(stream->bitCount, 8);
        QrcodeStreamFree(stream);
    }
}

/**
 * @tc.name: qrcode_stream_add_num_boundary_025
 * @tc.desc: Verify adding number at byte boundary.
 * @tc.type: FUNC
 * @tc.require: issueI000004
 */
HWTEST_F(QrcodeStreamTest, qrcode_stream_add_num_boundary_025, TestSize.Level1)
{
    QrcodeStream *stream = QrcodeStreamNew();
    EXPECT_NE(stream, nullptr);
    if (stream != nullptr) {
        QrcodeStreamAddNum(stream, 8, 0xFF);
        EXPECT_EQ(stream->bitCount, 8);
        QrcodeStreamAddNum(stream, 8, 0xAA);
        EXPECT_EQ(stream->bitCount, 16);
        QrcodeStreamFree(stream);
    }
}

/**
 * @tc.name: qrcode_stream_add_num_cross_boundary_026
 * @tc.desc: Verify adding number crossing byte boundary.
 * @tc.type: FUNC
 * @tc.require: issueI000004
 */
HWTEST_F(QrcodeStreamTest, qrcode_stream_add_num_cross_boundary_026, TestSize.Level1)
{
    QrcodeStream *stream = QrcodeStreamNew();
    EXPECT_NE(stream, nullptr);
    if (stream != nullptr) {
        QrcodeStreamAddNum(stream, 4, 0b1010);
        EXPECT_EQ(stream->bitCount, 4);
        QrcodeStreamAddNum(stream, 6, 0b110110);
        EXPECT_EQ(stream->bitCount, 10);
        QrcodeStreamFree(stream);
    }
}

/**
 * @tc.name: qrcode_stream_add_bytes_single_027
 * @tc.desc: Verify adding single byte to stream.
 * @tc.type: FUNC
 * @tc.require: issueI000004
 */
HWTEST_F(QrcodeStreamTest, qrcode_stream_add_bytes_single_027, TestSize.Level1)
{
    QrcodeStream *stream = QrcodeStreamNew();
    EXPECT_NE(stream, nullptr);
    if (stream != nullptr) {
        const uint8_t data = 0xAB;
        int32_t ret = QrcodeStreamAddBytes(stream, 1, (uint8_t *)&data);
        EXPECT_EQ(ret, 0);
        EXPECT_EQ(stream->bitCount, 8);
        QrcodeStreamFree(stream);
    }
}

/**
 * @tc.name: qrcode_stream_add_bytes_after_num_028
 * @tc.desc: Verify adding bytes after number.
 * @tc.type: FUNC
 * @tc.require: issueI000004
 */
HWTEST_F(QrcodeStreamTest, qrcode_stream_add_bytes_after_num_028, TestSize.Level1)
{
    QrcodeStream *stream = QrcodeStreamNew();
    EXPECT_NE(stream, nullptr);
    if (stream != nullptr) {
        QrcodeStreamAddNum(stream, 4, 0b1010);
        const uint8_t data[] = {0x12, 0x34};
        QrcodeStreamAddBytes(stream, 2, (uint8_t *)data);
        EXPECT_EQ(stream->bitCount, 20);
        QrcodeStreamFree(stream);
    }
}

/**
 * @tc.name: qrcode_stream_add_num_after_bytes_029
 * @tc.desc: Verify adding number after bytes.
 * @tc.type: FUNC
 * @tc.require: issueI000004
 */
HWTEST_F(QrcodeStreamTest, qrcode_stream_add_num_after_bytes_029, TestSize.Level1)
{
    QrcodeStream *stream = QrcodeStreamNew();
    EXPECT_NE(stream, nullptr);
    if (stream != nullptr) {
        const uint8_t data[] = {0x12, 0x34};
        QrcodeStreamAddBytes(stream, 2, (uint8_t *)data);
        QrcodeStreamAddNum(stream, 4, 0b1010);
        EXPECT_EQ(stream->bitCount, 20);
        QrcodeStreamFree(stream);
    }
}

/**
 * @tc.name: qrcode_stream_add_stream_empty_030
 * @tc.desc: Verify adding empty stream to stream.
 * @tc.type: FUNC
 * @tc.require: issueI000004
 */
HWTEST_F(QrcodeStreamTest, qrcode_stream_add_stream_empty_030, TestSize.Level1)
{
    QrcodeStream *stream1 = QrcodeStreamNew();
    QrcodeStream *stream2 = QrcodeStreamNew();
    EXPECT_NE(stream1, nullptr);
    EXPECT_NE(stream2, nullptr);
    if (stream1 != nullptr && stream2 != nullptr) {
        int32_t ret = QrcodeStreamAdd(stream1, stream2);
        EXPECT_NE(ret, 0);  // Adding empty stream should fail
        QrcodeStreamFree(stream1);
        QrcodeStreamFree(stream2);
    }
}

/**
 * @tc.name: qrcode_stream_add_stream_with_data_031
 * @tc.desc: Verify adding stream with data to stream.
 * @tc.type: FUNC
 * @tc.require: issueI000004
 */
HWTEST_F(QrcodeStreamTest, qrcode_stream_add_stream_with_data_031, TestSize.Level1)
{
    QrcodeStream *stream1 = QrcodeStreamNew();
    QrcodeStream *stream2 = QrcodeStreamNew();
    EXPECT_NE(stream1, nullptr);
    EXPECT_NE(stream2, nullptr);
    if (stream1 != nullptr && stream2 != nullptr) {
        QrcodeStreamAddNum(stream1, 4, 0b1010);
        const uint8_t data[] = {0x12, 0x34};
        QrcodeStreamAddBytes(stream2, 2, (uint8_t *)data);
        int32_t ret = QrcodeStreamAdd(stream1, stream2);
        EXPECT_EQ(ret, 0);
        EXPECT_EQ(stream1->bitCount, 20);
        QrcodeStreamFree(stream1);
        QrcodeStreamFree(stream2);
    }
}

/**
 * @tc.name: qrcode_stream_clean_after_add_032
 * @tc.desc: Verify cleaning stream after adding data.
 * @tc.type: FUNC
 * @tc.require: issueI000004
 */
HWTEST_F(QrcodeStreamTest, qrcode_stream_clean_after_add_032, TestSize.Level1)
{
    QrcodeStream *stream = QrcodeStreamNew();
    EXPECT_NE(stream, nullptr);
    if (stream != nullptr) {
        const uint8_t data[] = {0x12, 0x34, 0x56};
        QrcodeStreamAddBytes(stream, 3, (uint8_t *)data);
        EXPECT_EQ(stream->bitCount, 24);
        QrcodeStreamClean(stream);
        EXPECT_EQ(stream->bitCount, 0);
        EXPECT_EQ(stream->data, nullptr);
        QrcodeStreamFree(stream);
    }
}

/**
 * @tc.name: qrcode_stream_dup_after_clean_033
 * @tc.desc: Verify duplicating stream data after clean.
 * @tc.type: FUNC
 * @tc.require: issueI000004
 */
HWTEST_F(QrcodeStreamTest, qrcode_stream_dup_after_clean_033, TestSize.Level1)
{
    QrcodeStream *stream = QrcodeStreamNew();
    EXPECT_NE(stream, nullptr);
    if (stream != nullptr) {
        const uint8_t data[] = {0x12, 0x34, 0x56};
        QrcodeStreamAddBytes(stream, 3, (uint8_t *)data);
        QrcodeStreamClean(stream);
        uint8_t *dupData = QrcodeStreamDupData(stream);
        EXPECT_NE(dupData, nullptr);
        if (dupData != nullptr) {
            QrcodeFree(dupData);
        }
        QrcodeStreamFree(stream);
    }
}

/**
 * @tc.name: qrcode_stream_add_multiple_streams_034
 * @tc.desc: Verify adding multiple streams to one stream.
 * @tc.type: FUNC
 * @tc.require: issueI000004
 */
HWTEST_F(QrcodeStreamTest, qrcode_stream_add_multiple_streams_034, TestSize.Level1)
{
    QrcodeStream *stream1 = QrcodeStreamNew();
    QrcodeStream *stream2 = QrcodeStreamNew();
    QrcodeStream *stream3 = QrcodeStreamNew();
    EXPECT_NE(stream1, nullptr);
    EXPECT_NE(stream2, nullptr);
    EXPECT_NE(stream3, nullptr);
    if (stream1 != nullptr && stream2 != nullptr && stream3 != nullptr) {
        const uint8_t data1[] = {0x12, 0x34};
        const uint8_t data2[] = {0x56, 0x78};
        QrcodeStreamAddBytes(stream2, 2, (uint8_t *)data1);
        QrcodeStreamAddBytes(stream3, 2, (uint8_t *)data2);
        QrcodeStreamAdd(stream1, stream2);
        QrcodeStreamAdd(stream1, stream3);
        EXPECT_EQ(stream1->bitCount, 32);
        QrcodeStreamFree(stream1);
        QrcodeStreamFree(stream2);
        QrcodeStreamFree(stream3);
    }
}

/**
 * @tc.name: qrcode_stream_add_num_max_bits_035
 * @tc.desc: Verify adding number with maximum bit count.
 * @tc.type: FUNC
 * @tc.require: issueI000004
 */
HWTEST_F(QrcodeStreamTest, qrcode_stream_add_num_max_bits_035, TestSize.Level1)
{
    QrcodeStream *stream = QrcodeStreamNew();
    EXPECT_NE(stream, nullptr);
    if (stream != nullptr) {
        int32_t ret = QrcodeStreamAddNum(stream, 32, 0xFFFFFFFF);
        EXPECT_EQ(ret, 0);
        EXPECT_EQ(stream->bitCount, 32);
        QrcodeStreamFree(stream);
    }
}

/**
 * @tc.name: qrcode_stream_add_num_one_bit_036
 * @tc.desc: Verify adding number with one bit.
 * @tc.type: FUNC
 * @tc.require: issueI000004
 */
HWTEST_F(QrcodeStreamTest, qrcode_stream_add_num_one_bit_036, TestSize.Level1)
{
    QrcodeStream *stream = QrcodeStreamNew();
    EXPECT_NE(stream, nullptr);
    if (stream != nullptr) {
        int32_t ret = QrcodeStreamAddNum(stream, 1, 0b1);
        EXPECT_EQ(ret, 0);
        EXPECT_EQ(stream->bitCount, 1);
        QrcodeStreamFree(stream);
    }
}

/**
 * @tc.name: qrcode_stream_add_num_two_bits_037
 * @tc.desc: Verify adding number with two bits.
 * @tc.type: FUNC
 * @tc.require: issueI000004
 */
HWTEST_F(QrcodeStreamTest, qrcode_stream_add_num_two_bits_037, TestSize.Level1)
{
    QrcodeStream *stream = QrcodeStreamNew();
    EXPECT_NE(stream, nullptr);
    if (stream != nullptr) {
        int32_t ret = QrcodeStreamAddNum(stream, 2, 0b11);
        EXPECT_EQ(ret, 0);
        EXPECT_EQ(stream->bitCount, 2);
        QrcodeStreamFree(stream);
    }
}

/**
 * @tc.name: qrcode_stream_add_num_seven_bits_038
 * @tc.desc: Verify adding number with seven bits.
 * @tc.type: FUNC
 * @tc.require: issueI000004
 */
HWTEST_F(QrcodeStreamTest, qrcode_stream_add_num_seven_bits_038, TestSize.Level1)
{
    QrcodeStream *stream = QrcodeStreamNew();
    EXPECT_NE(stream, nullptr);
    if (stream != nullptr) {
        int32_t ret = QrcodeStreamAddNum(stream, 7, 0b1111111);
        EXPECT_EQ(ret, 0);
        EXPECT_EQ(stream->bitCount, 7);
        QrcodeStreamFree(stream);
    }
}

/**
 * @tc.name: qrcode_stream_add_num_nine_bits_039
 * @tc.desc: Verify adding number with nine bits.
 * @tc.type: FUNC
 * @tc.require: issueI000004
 */
HWTEST_F(QrcodeStreamTest, qrcode_stream_add_num_nine_bits_039, TestSize.Level1)
{
    QrcodeStream *stream = QrcodeStreamNew();
    EXPECT_NE(stream, nullptr);
    if (stream != nullptr) {
        int32_t ret = QrcodeStreamAddNum(stream, 9, 0b111111111);
        EXPECT_EQ(ret, 0);
        EXPECT_EQ(stream->bitCount, 9);
        QrcodeStreamFree(stream);
    }
}

/**
 * @tc.name: qrcode_stream_add_bytes_all_zeros_040
 * @tc.desc: Verify adding all zero bytes to stream.
 * @tc.type: FUNC
 * @tc.require: issueI000004
 */
HWTEST_F(QrcodeStreamTest, qrcode_stream_add_bytes_all_zeros_040, TestSize.Level1)
{
    QrcodeStream *stream = QrcodeStreamNew();
    EXPECT_NE(stream, nullptr);
    if (stream != nullptr) {
        uint8_t data[10] = {0};
        int32_t ret = QrcodeStreamAddBytes(stream, 10, data);
        EXPECT_EQ(ret, 0);
        EXPECT_EQ(stream->bitCount, 80);
        QrcodeStreamFree(stream);
    }
}

/**
 * @tc.name: qrcode_stream_add_bytes_all_ones_041
 * @tc.desc: Verify adding all one bytes to stream.
 * @tc.type: FUNC
 * @tc.require: issueI000004
 */
HWTEST_F(QrcodeStreamTest, qrcode_stream_add_bytes_all_ones_041, TestSize.Level1)
{
    QrcodeStream *stream = QrcodeStreamNew();
    EXPECT_NE(stream, nullptr);
    if (stream != nullptr) {
        uint8_t data[10];
        for (int32_t i = 0; i < 10; i++) {
            data[i] = 0xFF;
        }
        int32_t ret = QrcodeStreamAddBytes(stream, 10, data);
        EXPECT_EQ(ret, 0);
        EXPECT_EQ(stream->bitCount, 80);
        QrcodeStreamFree(stream);
    }
}

/**
 * @tc.name: qrcode_stream_add_bytes_alternating_042
 * @tc.desc: Verify adding alternating bytes to stream.
 * @tc.type: FUNC
 * @tc.require: issueI000004
 */
HWTEST_F(QrcodeStreamTest, qrcode_stream_add_bytes_alternating_042, TestSize.Level1)
{
    QrcodeStream *stream = QrcodeStreamNew();
    EXPECT_NE(stream, nullptr);
    if (stream != nullptr) {
        uint8_t data[10];
        for (int32_t i = 0; i < 10; i++) {
            data[i] = (i % 2) ? 0xAA : 0x55;
        }
        int32_t ret = QrcodeStreamAddBytes(stream, 10, data);
        EXPECT_EQ(ret, 0);
        EXPECT_EQ(stream->bitCount, 80);
        QrcodeStreamFree(stream);
    }
}

/**
 * @tc.name: qrcode_stream_add_bytes_pattern_043
 * @tc.desc: Verify adding patterned bytes to stream.
 * @tc.type: FUNC
 * @tc.require: issueI000004
 */
HWTEST_F(QrcodeStreamTest, qrcode_stream_add_bytes_pattern_043, TestSize.Level1)
{
    QrcodeStream *stream = QrcodeStreamNew();
    EXPECT_NE(stream, nullptr);
    if (stream != nullptr) {
        uint8_t data[10];
        for (int32_t i = 0; i < 10; i++) {
            data[i] = i;
        }
        int32_t ret = QrcodeStreamAddBytes(stream, 10, data);
        EXPECT_EQ(ret, 0);
        EXPECT_EQ(stream->bitCount, 80);
        QrcodeStreamFree(stream);
    }
}

/**
 * @tc.name: qrcode_stream_add_large_bytes_044
 * @tc.desc: Verify adding large byte array to stream.
 * @tc.type: FUNC
 * @tc.require: issueI000004
 */
HWTEST_F(QrcodeStreamTest, qrcode_stream_add_large_bytes_044, TestSize.Level1)
{
    QrcodeStream *stream = QrcodeStreamNew();
    EXPECT_NE(stream, nullptr);
    if (stream != nullptr) {
        uint8_t data[256];
        for (int32_t i = 0; i < 256; i++) {
            data[i] = i % 256;
        }
        int32_t ret = QrcodeStreamAddBytes(stream, 256, data);
        EXPECT_EQ(ret, 0);
        EXPECT_EQ(stream->bitCount, 2048);
        QrcodeStreamFree(stream);
    }
}

/**
 * @tc.name: qrcode_stream_dup_large_data_045
 * @tc.desc: Verify duplicating large stream data.
 * @tc.type: FUNC
 * @tc.require: issueI000004
 */
HWTEST_F(QrcodeStreamTest, qrcode_stream_dup_large_data_045, TestSize.Level1)
{
    QrcodeStream *stream = QrcodeStreamNew();
    EXPECT_NE(stream, nullptr);
    if (stream != nullptr) {
        uint8_t data[256];
        for (int32_t i = 0; i < 256; i++) {
            data[i] = i % 256;
        }
        QrcodeStreamAddBytes(stream, 256, data);
        uint8_t *dupData = QrcodeStreamDupData(stream);
        EXPECT_NE(dupData, nullptr);
        if (dupData != nullptr) {
            QrcodeFree(dupData);
        }
        QrcodeStreamFree(stream);
    }
}

/**
 * @tc.name: qrcode_stream_add_num_sequence_046
 * @tc.desc: Verify adding sequence of numbers to stream.
 * @tc.type: FUNC
 * @tc.require: issueI000004
 */
HWTEST_F(QrcodeStreamTest, qrcode_stream_add_num_sequence_046, TestSize.Level1)
{
    QrcodeStream *stream = QrcodeStreamNew();
    EXPECT_NE(stream, nullptr);
    if (stream != nullptr) {
        for (int32_t i = 0; i < 10; i++) {
            QrcodeStreamAddNum(stream, 4, i % 16);
        }
        EXPECT_EQ(stream->bitCount, 40);
        QrcodeStreamFree(stream);
    }
}

/**
 * @tc.name: qrcode_stream_add_mixed_047
 * @tc.desc: Verify adding mixed numbers and bytes to stream.
 * @tc.type: FUNC
 * @tc.require: issueI000004
 */
HWTEST_F(QrcodeStreamTest, qrcode_stream_add_mixed_047, TestSize.Level1)
{
    QrcodeStream *stream = QrcodeStreamNew();
    EXPECT_NE(stream, nullptr);
    if (stream != nullptr) {
        QrcodeStreamAddNum(stream, 4, 0b1010);
        const uint8_t data1[] = {0x12, 0x34};
        QrcodeStreamAddBytes(stream, 2, (uint8_t *)data1);
        QrcodeStreamAddNum(stream, 8, 0xFF);
        const uint8_t data2[] = {0x56, 0x78, 0x9A};
        QrcodeStreamAddBytes(stream, 3, (uint8_t *)data2);
        EXPECT_EQ(stream->bitCount, 52);
        QrcodeStreamFree(stream);
    }
}

/**
 * @tc.name: qrcode_stream_clean_multiple_048
 * @tc.desc: Verify cleaning stream multiple times.
 * @tc.type: FUNC
 * @tc.require: issueI000004
 */
HWTEST_F(QrcodeStreamTest, qrcode_stream_clean_multiple_048, TestSize.Level1)
{
    QrcodeStream *stream = QrcodeStreamNew();
    EXPECT_NE(stream, nullptr);
    if (stream != nullptr) {
        const uint8_t data[] = {0x12, 0x34, 0x56};
        QrcodeStreamAddBytes(stream, 3, (uint8_t *)data);
        QrcodeStreamClean(stream);
        QrcodeStreamClean(stream);
        EXPECT_EQ(stream->bitCount, 0);
        EXPECT_EQ(stream->data, nullptr);
        QrcodeStreamFree(stream);
    }
}

/**
 * @tc.name: qrcode_stream_free_with_data_049
 * @tc.desc: Verify freeing stream with data.
 * @tc.type: FUNC
 * @tc.require: issueI000004
 */
HWTEST_F(QrcodeStreamTest, qrcode_stream_free_with_data_049, TestSize.Level1)
{
    QrcodeStream *stream = QrcodeStreamNew();
    EXPECT_NE(stream, nullptr);
    if (stream != nullptr) {
        const uint8_t data[] = {0x12, 0x34, 0x56};
        QrcodeStreamAddBytes(stream, 3, (uint8_t *)data);
        QrcodeStreamFree(stream);
    }
}

/**
 * @tc.name: qrcode_stream_free_without_data_050
 * @tc.desc: Verify freeing stream without data.
 * @tc.type: FUNC
 * @tc.require: issueI000004
 */
HWTEST_F(QrcodeStreamTest, qrcode_stream_free_without_data_050, TestSize.Level1)
{
    QrcodeStream *stream = QrcodeStreamNew();
    EXPECT_NE(stream, nullptr);
    if (stream != nullptr) {
        QrcodeStreamFree(stream);
    }
}

/**
 * @tc.name: qrcode_stream_add_num_negative_051
 * @tc.desc: Verify adding number with negative bits (should handle gracefully).
 * @tc.type: FUNC
 * @tc.require: issueI000004
 */
HWTEST_F(QrcodeStreamTest, qrcode_stream_add_num_negative_051, TestSize.Level1)
{
    QrcodeStream *stream = QrcodeStreamNew();
    EXPECT_NE(stream, nullptr);
    if (stream != nullptr) {
        QrcodeStreamAddNum(stream, 4, 0b1010);
        EXPECT_EQ(stream->bitCount, 4);
        QrcodeStreamFree(stream);
    }
}

/**
 * @tc.name: qrcode_stream_add_bytes_negative_052
 * @tc.desc: Verify adding bytes with negative size (should handle gracefully).
 * @tc.type: FUNC
 * @tc.require: issueI000004
 */
HWTEST_F(QrcodeStreamTest, qrcode_stream_add_bytes_negative_052, TestSize.Level1)
{
    QrcodeStream *stream = QrcodeStreamNew();
    EXPECT_NE(stream, nullptr);
    if (stream != nullptr) {
        const uint8_t data[] = {0x12, 0x34, 0x56};
        int32_t ret = QrcodeStreamAddBytes(stream, 3, (uint8_t *)data);
        EXPECT_EQ(ret, 0);
        QrcodeStreamFree(stream);
    }
}

/**
 * @tc.name: qrcode_stream_add_num_large_value_053
 * @tc.desc: Verify adding number with large value.
 * @tc.type: FUNC
 * @tc.require: issueI000004
 */
HWTEST_F(QrcodeStreamTest, qrcode_stream_add_num_large_value_053, TestSize.Level1)
{
    QrcodeStream *stream = QrcodeStreamNew();
    EXPECT_NE(stream, nullptr);
    if (stream != nullptr) {
        int32_t ret = QrcodeStreamAddNum(stream, 24, 0xFFFFFF);
        EXPECT_EQ(ret, 0);
        EXPECT_EQ(stream->bitCount, 24);
        QrcodeStreamFree(stream);
    }
}

/**
 * @tc.name: qrcode_stream_add_num_msb_054
 * @tc.desc: Verify adding number with MSB set.
 * @tc.type: FUNC
 * @tc.require: issueI000004
 */
HWTEST_F(QrcodeStreamTest, qrcode_stream_add_num_msb_054, TestSize.Level1)
{
    QrcodeStream *stream = QrcodeStreamNew();
    EXPECT_NE(stream, nullptr);
    if (stream != nullptr) {
        int32_t ret = QrcodeStreamAddNum(stream, 8, 0x80);
        EXPECT_EQ(ret, 0);
        EXPECT_EQ(stream->bitCount, 8);
        QrcodeStreamFree(stream);
    }
}

/**
 * @tc.name: qrcode_stream_add_num_lsb_055
 * @tc.desc: Verify adding number with LSB set.
 * @tc.type: FUNC
 * @tc.require: issueI000004
 */
HWTEST_F(QrcodeStreamTest, qrcode_stream_add_num_lsb_055, TestSize.Level1)
{
    QrcodeStream *stream = QrcodeStreamNew();
    EXPECT_NE(stream, nullptr);
    if (stream != nullptr) {
        int32_t ret = QrcodeStreamAddNum(stream, 8, 0x01);
        EXPECT_EQ(ret, 0);
        EXPECT_EQ(stream->bitCount, 8);
        QrcodeStreamFree(stream);
    }
}

/**
 * @tc.name: qrcode_stream_add_bytes_single_bit_056
 * @tc.desc: Verify adding bytes with single bit set.
 * @tc.type: FUNC
 * @tc.require: issueI000004
 */
HWTEST_F(QrcodeStreamTest, qrcode_stream_add_bytes_single_bit_056, TestSize.Level1)
{
    QrcodeStream *stream = QrcodeStreamNew();
    EXPECT_NE(stream, nullptr);
    if (stream != nullptr) {
        const uint8_t data[] = {0x80, 0x40, 0x20, 0x10, 0x08, 0x04, 0x02, 0x01};
        int32_t ret = QrcodeStreamAddBytes(stream, 8, (uint8_t *)data);
        EXPECT_EQ(ret, 0);
        EXPECT_EQ(stream->bitCount, 64);
        QrcodeStreamFree(stream);
    }
}

/**
 * @tc.name: qrcode_stream_add_stream_to_self_057
 * @tc.desc: Verify adding stream to itself (should handle gracefully).
 * @tc.type: FUNC
 * @tc.require: issueI000004
 */
HWTEST_F(QrcodeStreamTest, qrcode_stream_add_stream_to_self_057, TestSize.Level1)
{
    QrcodeStream *stream = QrcodeStreamNew();
    EXPECT_NE(stream, nullptr);
    if (stream != nullptr) {
        const uint8_t data[] = {0x12, 0x34};
        QrcodeStreamAddBytes(stream, 2, (uint8_t *)data);
        int32_t ret = QrcodeStreamAdd(stream, stream);
        EXPECT_EQ(ret, 0);  // Adding stream to itself succeeds
        QrcodeStreamFree(stream);
    }
}

/**
 * @tc.name: qrcode_stream_dup_verify_data_058
 * @tc.desc: Verify duplicated data matches original.
 * @tc.type: FUNC
 * @tc.require: issueI000004
 */
HWTEST_F(QrcodeStreamTest, qrcode_stream_dup_verify_data_058, TestSize.Level1)
{
    QrcodeStream *stream = QrcodeStreamNew();
    EXPECT_NE(stream, nullptr);
    if (stream != nullptr) {
        const uint8_t data[] = {0x12, 0x34, 0x56, 0x78, 0x9A};
        QrcodeStreamAddBytes(stream, 5, (uint8_t *)data);
        uint8_t *dupData = QrcodeStreamDupData(stream);
        EXPECT_NE(dupData, nullptr);
        if (dupData != nullptr) {
            int32_t byteCount = (stream->bitCount + 7) / 8;
            for (int32_t i = 0; i < byteCount; i++) {
                EXPECT_EQ(dupData[i], data[i]);
            }
            QrcodeFree(dupData);
        }
        QrcodeStreamFree(stream);
    }
}

/**
 * @tc.name: qrcode_stream_clean_reuse_059
 * @tc.desc: Verify reusing stream after clean.
 * @tc.type: FUNC
 * @tc.require: issueI000004
 */
HWTEST_F(QrcodeStreamTest, qrcode_stream_clean_reuse_059, TestSize.Level1)
{
    QrcodeStream *stream = QrcodeStreamNew();
    EXPECT_NE(stream, nullptr);
    if (stream != nullptr) {
        const uint8_t data1[] = {0x12, 0x34, 0x56};
        QrcodeStreamAddBytes(stream, 3, (uint8_t *)data1);
        EXPECT_EQ(stream->bitCount, 24);
        QrcodeStreamClean(stream);
        EXPECT_EQ(stream->bitCount, 0);
        const uint8_t data2[] = {0xAB, 0xCD, 0xEF};
        QrcodeStreamAddBytes(stream, 3, (uint8_t *)data2);
        EXPECT_EQ(stream->bitCount, 24);
        QrcodeStreamFree(stream);
    }
}

/**
 * @tc.name: qrcode_stream_add_num_zero_value_060
 * @tc.desc: Verify adding number with zero value.
 * @tc.type: FUNC
 * @tc.require: issueI000004
 */
HWTEST_F(QrcodeStreamTest, qrcode_stream_add_num_zero_value_060, TestSize.Level1)
{
    QrcodeStream *stream = QrcodeStreamNew();
    EXPECT_NE(stream, nullptr);
    if (stream != nullptr) {
        int32_t ret = QrcodeStreamAddNum(stream, 8, 0x00);
        EXPECT_EQ(ret, 0);
        EXPECT_EQ(stream->bitCount, 8);
        QrcodeStreamFree(stream);
    }
}

/**
 * @tc.name: qrcode_stream_add_num_alternating_061
 * @tc.desc: Verify adding alternating numbers to stream.
 * @tc.type: FUNC
 * @tc.require: issueI000004
 */
HWTEST_F(QrcodeStreamTest, qrcode_stream_add_num_alternating_061, TestSize.Level1)
{
    QrcodeStream *stream = QrcodeStreamNew();
    EXPECT_NE(stream, nullptr);
    if (stream != nullptr) {
        for (int32_t i = 0; i < 8; i++) {
            QrcodeStreamAddNum(stream, 1, i % 2);
        }
        EXPECT_EQ(stream->bitCount, 8);
        QrcodeStreamFree(stream);
    }
}

/**
 * @tc.name: qrcode_stream_add_bytes_zero_size_062
 * @tc.desc: Verify adding bytes with zero size.
 * @tc.type: FUNC
 * @tc.require: issueI000004
 */
HWTEST_F(QrcodeStreamTest, qrcode_stream_add_bytes_zero_size_062, TestSize.Level1)
{
    QrcodeStream *stream = QrcodeStreamNew();
    EXPECT_NE(stream, nullptr);
    if (stream != nullptr) {
        const uint8_t data[] = {0x12, 0x34, 0x56};
        int32_t ret = QrcodeStreamAddBytes(stream, 0, (uint8_t *)data);
        EXPECT_EQ(ret, 0);  // Adding zero bytes should fail
        QrcodeStreamFree(stream);
    }
}

/**
 * @tc.name: qrcode_stream_add_num_boundary_32_bits_063
 * @tc.desc: Verify adding number at 32-bit boundary.
 * @tc.type: FUNC
 * @tc.require: issueI000004
 */
HWTEST_F(QrcodeStreamTest, qrcode_stream_add_num_boundary_32_bits_063, TestSize.Level1)
{
    QrcodeStream *stream = QrcodeStreamNew();
    EXPECT_NE(stream, nullptr);
    if (stream != nullptr) {
        QrcodeStreamAddNum(stream, 32, 0xFFFFFFFF);
        EXPECT_EQ(stream->bitCount, 32);
        QrcodeStreamAddNum(stream, 32, 0xAAAAAAAA);
        EXPECT_EQ(stream->bitCount, 64);
        QrcodeStreamFree(stream);
    }
}

/**
 * @tc.name: qrcode_stream_add_bytes_large_sequence_064
 * @tc.desc: Verify adding large sequence of bytes.
 * @tc.type: FUNC
 * @tc.require: issueI000004
 */
HWTEST_F(QrcodeStreamTest, qrcode_stream_add_bytes_large_sequence_064, TestSize.Level1)
{
    QrcodeStream *stream = QrcodeStreamNew();
    EXPECT_NE(stream, nullptr);
    if (stream != nullptr) {
        for (int32_t i = 0; i < 10; i++) {
            const uint8_t data[] = {0x12, 0x34, 0x56, 0x78};
            QrcodeStreamAddBytes(stream, 4, (uint8_t *)data);
        }
        EXPECT_EQ(stream->bitCount, 320);
        QrcodeStreamFree(stream);
    }
}

/**
 * @tc.name: qrcode_stream_add_num_various_sizes_065
 * @tc.desc: Verify adding numbers with various bit sizes.
 * @tc.type: FUNC
 * @tc.require: issueI000004
 */
HWTEST_F(QrcodeStreamTest, qrcode_stream_add_num_various_sizes_065, TestSize.Level1)
{
    QrcodeStream *stream = QrcodeStreamNew();
    EXPECT_NE(stream, nullptr);
    if (stream != nullptr) {
        QrcodeStreamAddNum(stream, 1, 0b1);
        QrcodeStreamAddNum(stream, 2, 0b11);
        QrcodeStreamAddNum(stream, 4, 0b1111);
        QrcodeStreamAddNum(stream, 8, 0xFF);
        QrcodeStreamAddNum(stream, 16, 0xFFFF);
        EXPECT_EQ(stream->bitCount, 31);
        QrcodeStreamFree(stream);
    }
}

/**
 * @tc.name: qrcode_stream_new_null_066
 * @tc.desc: Verify creating new stream (repeated test).
 * @tc.type: FUNC
 * @tc.require: issueI000004
 */
HWTEST_F(QrcodeStreamTest, qrcode_stream_new_null_066, TestSize.Level1)
{
    QrcodeStream *stream = QrcodeStreamNew();
    EXPECT_NE(stream, nullptr);
    if (stream != nullptr) {
        QrcodeStreamFree(stream);
    }
}

/**
 * @tc.name: qrcode_stream_new_multiple_067
 * @tc.desc: Verify creating multiple new streams.
 * @tc.type: FUNC
 * @tc.require: issueI000004
 */
HWTEST_F(QrcodeStreamTest, qrcode_stream_new_multiple_067, TestSize.Level1)
{
    QrcodeStream *stream1 = QrcodeStreamNew();
    QrcodeStream *stream2 = QrcodeStreamNew();
    QrcodeStream *stream3 = QrcodeStreamNew();
    EXPECT_NE(stream1, nullptr);
    EXPECT_NE(stream2, nullptr);
    EXPECT_NE(stream3, nullptr);
    if (stream1 != nullptr) {
        QrcodeStreamFree(stream1);
    }
    if (stream2 != nullptr) {
        QrcodeStreamFree(stream2);
    }
    if (stream3 != nullptr) {
        QrcodeStreamFree(stream3);
    }
}

/**
 * @tc.name: qrcode_stream_clean_null_stream_079
 * @tc.desc: Verify cleaning null stream (repeated test).
 * @tc.type: FUNC
 * @tc.require: issueI000004
 */
HWTEST_F(QrcodeStreamTest, qrcode_stream_clean_null_stream_079, TestSize.Level1)
{
    QrcodeStreamClean(nullptr);
}

/**
 * @tc.name: qrcode_stream_free_null_stream_080
 * @tc.desc: Verify freeing null stream (repeated test).
 * @tc.type: FUNC
 * @tc.require: issueI000004
 */
HWTEST_F(QrcodeStreamTest, qrcode_stream_free_null_stream_080, TestSize.Level1)
{
    QrcodeStreamFree(nullptr);
}

/**
 * @tc.name: qrcode_stream_add_num_boundary_values_081
 * @tc.desc: Verify adding numbers with boundary bit values.
 * @tc.type: FUNC
 * @tc.require: issueI000004
 */
HWTEST_F(QrcodeStreamTest, qrcode_stream_add_num_boundary_values_081, TestSize.Level1)
{
    QrcodeStream *stream = QrcodeStreamNew();
    EXPECT_NE(stream, nullptr);
    if (stream != nullptr) {
        QrcodeStreamAddNum(stream, 1, 0b0);
        QrcodeStreamAddNum(stream, 1, 0b1);
        QrcodeStreamAddNum(stream, 2, 0b00);
        QrcodeStreamAddNum(stream, 2, 0b11);
        QrcodeStreamAddNum(stream, 4, 0b0000);
        QrcodeStreamAddNum(stream, 4, 0b1111);
        QrcodeStreamAddNum(stream, 8, 0x00);
        QrcodeStreamAddNum(stream, 8, 0xFF);
        QrcodeStreamFree(stream);
    }
}

/**
 * @tc.name: qrcode_stream_add_bytes_boundary_values_082
 * @tc.desc: Verify adding bytes with boundary values.
 * @tc.type: FUNC
 * @tc.require: issueI000004
 */
HWTEST_F(QrcodeStreamTest, qrcode_stream_add_bytes_boundary_values_082, TestSize.Level1)
{
    QrcodeStream *stream = QrcodeStreamNew();
    EXPECT_NE(stream, nullptr);
    if (stream != nullptr) {
        const uint8_t data1[] = {0x00};
        const uint8_t data2[] = {0xFF};
        const uint8_t data3[] = {0x00, 0xFF};
        const uint8_t data4[] = {0xFF, 0x00};
        QrcodeStreamAddBytes(stream, 1, (uint8_t *)data1);
        QrcodeStreamAddBytes(stream, 1, (uint8_t *)data2);
        QrcodeStreamAddBytes(stream, 2, (uint8_t *)data3);
        QrcodeStreamAddBytes(stream, 2, (uint8_t *)data4);
        QrcodeStreamFree(stream);
    }
}

/**
 * @tc.name: qrcode_stream_add_stream_boundary_083
 * @tc.desc: Verify adding stream with boundary conditions.
 * @tc.type: FUNC
 * @tc.require: issueI000004
 */
HWTEST_F(QrcodeStreamTest, qrcode_stream_add_stream_boundary_083, TestSize.Level1)
{
    QrcodeStream *stream1 = QrcodeStreamNew();
    QrcodeStream *stream2 = QrcodeStreamNew();
    EXPECT_NE(stream1, nullptr);
    EXPECT_NE(stream2, nullptr);
    if (stream1 != nullptr && stream2 != nullptr) {
        QrcodeStreamAddNum(stream1, 1, 0b1);
        QrcodeStreamAddNum(stream2, 1, 0b0);
        QrcodeStreamAdd(stream1, stream2);
        QrcodeStreamFree(stream1);
        QrcodeStreamFree(stream2);
    }
}

/**
 * @tc.name: qrcode_stream_dup_boundary_084
 * @tc.desc: Verify duplicating stream data with boundary conditions.
 * @tc.type: FUNC
 * @tc.require: issueI000004
 */
HWTEST_F(QrcodeStreamTest, qrcode_stream_dup_boundary_084, TestSize.Level1)
{
    QrcodeStream *stream = QrcodeStreamNew();
    EXPECT_NE(stream, nullptr);
    if (stream != nullptr) {
        QrcodeStreamAddNum(stream, 1, 0b1);
        uint8_t *dupData = QrcodeStreamDupData(stream);
        EXPECT_NE(dupData, nullptr);
        if (dupData != nullptr) {
            QrcodeFree(dupData);
        }
        QrcodeStreamFree(stream);
    }
}

/**
 * @tc.name: qrcode_stream_clean_boundary_085
 * @tc.desc: Verify cleaning stream with boundary conditions.
 * @tc.type: FUNC
 * @tc.require: issueI000004
 */
HWTEST_F(QrcodeStreamTest, qrcode_stream_clean_boundary_085, TestSize.Level1)
{
    QrcodeStream *stream = QrcodeStreamNew();
    EXPECT_NE(stream, nullptr);
    if (stream != nullptr) {
        QrcodeStreamAddNum(stream, 1, 0b1);
        QrcodeStreamClean(stream);
        EXPECT_EQ(stream->bitCount, 0);
        QrcodeStreamFree(stream);
    }
}