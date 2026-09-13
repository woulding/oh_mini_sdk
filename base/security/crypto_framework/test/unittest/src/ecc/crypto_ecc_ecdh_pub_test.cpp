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

#include "asy_key_generator.h"
#include "blob.h"
#include "detailed_ecc_key_params.h"
#include "ecc_key_util.h"
#include "ecc_common_param_spec_generator_openssl.h"
#include "key_agreement.h"
#include "memory.h"
#include "signature.h"
#include "openssl_class.h"


using namespace std;
using namespace testing::ext;

namespace {
class CryptoEccEcdhPubTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp();
    void TearDown();
};

void CryptoEccEcdhPubTest::SetUpTestCase() {}

void CryptoEccEcdhPubTest::TearDownTestCase() {}

void CryptoEccEcdhPubTest::SetUp() {}

void CryptoEccEcdhPubTest::TearDown() {}

static const char *g_pubKeyCompressedFormat = "X509|COMPRESSED";
static const char *g_pubKeyUnCompressedFormat = "X509|UNCOMPRESSED";
static const char *g_pointCompressedFormat = "COMPRESSED";
static const char *g_pointUnCompressedFormat = "UNCOMPRESSED";

// uncompressed point data size
constexpr size_t SECP224R1_POINT_UNCOMPRESSED_SIZE = 57;
constexpr size_t PRIME256V1_POINT_UNCOMPRESSED_SIZE = 65;
constexpr size_t SECP384R1_POINT_UNCOMPRESSED_SIZE = 97;
constexpr size_t SECP521R1_POINT_UNCOMPRESSED_SIZE = 133;
constexpr size_t P160R1_POINT_UNCOMPRESSED_SIZE = 41;
constexpr size_t P160T1_POINT_UNCOMPRESSED_SIZE = 41;
constexpr size_t P192R1_POINT_UNCOMPRESSED_SIZE = 49;
constexpr size_t P192T1_POINT_UNCOMPRESSED_SIZE = 49;
constexpr size_t P224R1_POINT_UNCOMPRESSED_SIZE = 57;
constexpr size_t P224T1_POINT_UNCOMPRESSED_SIZE = 57;
constexpr size_t P256R1_POINT_UNCOMPRESSED_SIZE = 65;
constexpr size_t P256T1_POINT_UNCOMPRESSED_SIZE = 65;
constexpr size_t P320R1_POINT_UNCOMPRESSED_SIZE = 81;
constexpr size_t P320T1_POINT_UNCOMPRESSED_SIZE = 81;
constexpr size_t P384R1_POINT_UNCOMPRESSED_SIZE = 97;
constexpr size_t P384T1_POINT_UNCOMPRESSED_SIZE = 97;
constexpr size_t P512R1_POINT_UNCOMPRESSED_SIZE = 129;
constexpr size_t P512T1_POINT_UNCOMPRESSED_SIZE = 129;

// uncompressed point data
static uint8_t g_secp224r1PointUncompressedBlobData[] = { 4, 56, 90, 25, 144, 206, 229, 109, 59, 65, 62, 249, 113,
    247, 239, 20, 63, 107, 72, 217, 43, 12, 124, 241, 209, 32, 66, 134, 239, 169, 154, 59, 182, 106, 163, 190,
    214, 232, 213, 73, 97, 57, 163, 137, 66, 59, 238, 12, 142, 87, 37, 182, 22, 60, 106, 235, 237 };

static uint8_t g_prime256v1PointUncompressedBlobData[] = { 4, 153, 228, 156, 119, 184, 185, 120, 237, 233, 181,
    77, 70, 183, 30, 68, 2, 70, 37, 251, 5, 22, 199, 84, 87, 222, 65, 103, 8, 26, 255, 137, 206, 80, 159, 163,
    46, 22, 104, 156, 169, 14, 149, 199, 35, 201, 3, 160, 81, 251, 235, 236, 75, 137, 196, 253, 200, 116, 167,
    59, 153, 241, 99, 90, 90 };

static uint8_t g_secp384r1PointUncompressedBlobData[] = { 4, 246, 157, 255, 226, 94, 109, 16, 243, 109, 34, 121,
    62, 12, 160, 181, 60, 89, 27, 60, 236, 118, 93, 113, 123, 64, 220, 231, 248, 113, 220, 130, 75, 164, 174, 128,
    84, 135, 212, 122, 99, 97, 167, 89, 56, 162, 60, 50, 185, 154, 231, 102, 187, 58, 105, 237, 215, 53, 88, 253,
    33, 45, 36, 25, 176, 112, 110, 132, 39, 33, 56, 224, 21, 225, 8, 108, 81, 106, 157, 33, 210, 105, 138, 130, 163,
    96, 112, 183, 179, 241, 25, 188, 121, 68, 180, 169, 149 };

static uint8_t g_secp521r1PointUncompressedBlobData[] = { 4, 0, 234, 87, 65, 173, 170, 194, 156, 174, 174,
    229, 236, 236, 195, 107, 24, 24, 169, 187, 160, 28, 11, 239, 70, 163, 131, 233, 157, 104, 41, 202, 208,
    166, 209, 217, 39, 225, 163, 33, 17, 134, 48, 150, 111, 225, 193, 219, 232, 234, 117, 100, 27, 169, 172,
    60, 186, 69, 246, 244, 218, 249, 188, 96, 49, 247, 125, 0, 70, 67, 187, 0, 72, 109, 99, 50, 173, 42, 250,
    10, 89, 166, 85, 64, 28, 145, 30, 130, 174, 147, 22, 232, 37, 17, 158, 165, 178, 11, 34, 58, 98, 98, 43, 32,
    146, 102, 178, 198, 176, 41, 150, 37, 43, 132, 232, 32, 98, 143, 125, 255, 173, 158, 227, 4, 238, 168, 113,
    194, 162, 74, 234, 239, 102 };

static uint8_t g_p160r1PointUncompressedBlobData[] = { 4, 162, 100, 90, 91, 16, 253, 183, 186, 164, 222, 247,
    223, 75, 228, 92, 253, 253, 250, 38, 30, 125, 172, 62, 13, 109, 61, 63, 160, 20, 103, 94, 7, 68, 115, 202,
    170, 157, 244, 174, 26 };

static uint8_t g_p160t1PointUncompressedBlobData[] = { 4, 73, 116, 114, 251, 6, 125, 11, 84, 159, 140, 0, 164,
    101, 40, 147, 227, 28, 143, 224, 160, 217, 185, 12, 197, 39, 34, 91, 119, 135, 123, 80, 45, 26, 156, 221,
    2, 79, 242, 45, 24 };

static uint8_t g_p192r1PointUncompressedBlobData[] = { 4, 72, 15, 250, 255, 107, 128, 70, 56, 144, 154, 23,
    141, 54, 19, 255, 134, 235, 12, 187, 128, 121, 41, 255, 141, 69, 81, 100, 94, 238, 15, 166, 184, 1, 214,
    220, 222, 12, 239, 145, 184, 143, 146, 165, 9, 107, 74, 199, 1 };

static uint8_t g_p192t1PointUncompressedBlobData[] = { 4, 131, 174, 50, 196, 198, 2, 164, 255, 193, 233, 237, 217,
    47, 191, 35, 6, 166, 69, 42, 38, 128, 134, 29, 97, 23, 242, 82, 96, 164, 135, 108, 120, 179, 105, 10, 32, 90,
    152, 99, 10, 2, 220, 184, 207, 8, 65, 168, 95 };

static uint8_t g_p224r1PointUncompressedBlobData[] = { 4, 179, 154, 82, 152, 164, 40, 37, 88, 133, 242, 75, 160,
    244, 155, 186, 103, 163, 44, 100, 137, 114, 124, 28, 27, 187, 99, 235, 123, 46, 127, 137, 234, 188, 6, 91, 68,
    250, 89, 231, 62, 179, 47, 119, 221, 5, 73, 128, 12, 241, 57, 101, 15, 9, 95, 11, 101 };

static uint8_t g_p224t1PointUncompressedBlobData[] = { 4, 187, 42, 38, 78, 26, 235, 23, 233, 222, 133, 167, 236,
    86, 95, 104, 44, 160, 133, 41, 92, 214, 174, 194, 43, 214, 123, 12, 188, 210, 117, 152, 50, 0, 136, 6, 92, 57,
    236, 246, 150, 145, 249, 150, 185, 255, 116, 28, 111, 22, 173, 25, 205, 96, 251, 61, 238 };

static uint8_t g_p256r1PointUncompressedBlobData[] = { 4, 0, 181, 254, 30, 31, 239, 138, 26, 134, 97, 46, 250, 9, 142,
    148, 201, 217, 224, 223, 68, 54, 180, 157, 30, 98, 140, 81, 237, 29, 242, 108, 3, 100, 127, 165, 176, 53, 73, 197,
    151, 79, 219, 204, 98, 116, 71, 97, 1, 127, 216, 38, 84, 18, 157, 250, 240, 109, 251, 105, 243, 73, 17, 153, 138 };

static uint8_t g_p256t1PointUncompressedBlobData[] = { 4, 134, 165, 93, 7, 187, 30, 225, 62, 157, 177, 229, 63, 104,
    217, 148, 68, 85, 152, 34, 185, 100, 81, 111, 233, 193, 108, 198, 74, 37, 188, 46, 19, 136, 157, 88, 166, 194,
    167, 157, 163, 173, 69, 7, 153, 48, 246, 3, 54, 127, 113, 145, 17, 128, 250, 210, 218, 249, 150, 249, 243, 178,
    136, 112, 192 };

static uint8_t g_p320r1PointUncompressedBlobData[] = { 4, 117, 229, 73, 102, 77, 218, 200, 35, 245, 163, 23, 219,
    50, 180, 7, 60, 219, 87, 135, 67, 214, 34, 71, 1, 75, 227, 143, 253, 203, 40, 246, 249, 210, 64, 255, 186, 202,
    161, 214, 203, 91, 159, 114, 252, 134, 230, 86, 188, 103, 223, 217, 12, 238, 118, 6, 232, 161, 198, 195, 139, 62,
    36, 98, 212, 129, 215, 178, 83, 137, 164, 95, 239, 238, 216, 222, 125, 246, 105, 66, 164 };

static uint8_t g_p320t1PointUncompressedBlobData[] = { 4, 188, 215, 24, 76, 167, 218, 220, 193, 3, 105, 145, 175,
    125, 17, 15, 227, 69, 120, 196, 97, 151, 3, 116, 23, 83, 71, 204, 133, 13, 225, 88, 31, 11, 168, 66, 57, 64, 233,
    125, 156, 12, 28, 241, 242, 224, 110, 133, 157, 230, 106, 16, 126, 66, 37, 8, 235, 230, 90, 20, 253, 2, 223, 157,
    135, 71, 161, 64, 111, 50, 212, 125, 187, 44, 181, 211, 76, 217, 53, 94, 162 };

static uint8_t g_p384r1PointUncompressedBlobData[] = { 4, 24, 149, 106, 30, 33, 152, 247, 126, 23, 231, 139, 197,
    240, 145, 3, 6, 38, 168, 157, 60, 153, 95, 41, 184, 110, 135, 222, 237, 86, 132, 255, 180, 245, 49, 41, 3, 223,
    122, 210, 203, 213, 55, 108, 251, 65, 181, 168, 25, 69, 50, 124, 233, 124, 121, 89, 187, 238, 186, 163, 169, 88,
    48, 7, 108, 206, 228, 141, 162, 127, 232, 67, 175, 95, 220, 178, 28, 152, 254, 148, 123, 46, 132, 222, 124, 11,
    51, 152, 113, 44, 14, 222, 126, 142, 114, 10, 124 };

static uint8_t g_p384t1PointUncompressedBlobData[] = { 4, 64, 192, 12, 47, 160, 35, 23, 244, 163, 108, 172, 235,
    185, 100, 0, 180, 112, 85, 105, 29, 120, 105, 164, 148, 59, 168, 183, 168, 142, 141, 14, 121, 240, 132, 168, 4,
    208, 142, 24, 226, 75, 169, 249, 46, 63, 61, 129, 154, 41, 6, 34, 81, 246, 230, 4, 227, 103, 106, 107, 216, 130,
    58, 248, 156, 101, 96, 85, 109, 43, 233, 229, 96, 165, 188, 222, 226, 113, 17, 213, 194, 57, 142, 117, 129, 151,
    187, 235, 43, 253, 132, 151, 96, 49, 85, 37, 101 };

static uint8_t g_p512r1PointUncompressedBlobData[] = { 4, 18, 25, 192, 69, 115, 54, 110, 174, 51, 48, 253, 129, 31,
    118, 237, 38, 1, 174, 8, 111, 74, 249, 149, 154, 119, 114, 59, 51, 160, 206, 70, 199, 202, 42, 98, 245, 170, 251,
    154, 22, 243, 137, 182, 239, 219, 166, 28, 202, 183, 229, 2, 83, 16, 244, 211, 100, 30, 179, 251, 17, 52, 117, 55,
    70, 114, 203, 60, 190, 163, 132, 156, 63, 246, 140, 173, 122, 80, 68, 155, 60, 74, 199, 248, 71, 134, 52, 228, 28,
    122, 72, 100, 26, 36, 148, 20, 187, 59, 137, 98, 191, 165, 174, 43, 2, 68, 222, 184, 34, 108, 8, 155, 150, 12,
    101, 120, 155, 164, 200, 52, 206, 240, 116, 158, 207, 180, 124, 210, 62 };

static uint8_t g_p512t1PointUncompressedBlobData[] = { 4, 119, 56, 81, 46, 40, 173, 156, 49, 235, 26, 193, 122, 32,
    201, 88, 18, 90, 55, 144, 84, 125, 90, 106, 169, 66, 124, 90, 44, 145, 100, 224, 192, 22, 241, 38, 185, 93, 163,
    146, 221, 126, 222, 57, 95, 136, 139, 231, 85, 250, 133, 140, 81, 138, 66, 148, 253, 192, 217, 210, 33, 157, 60,
    5, 113, 151, 65, 106, 113, 44, 250, 237, 139, 172, 190, 154, 142, 17, 77, 228, 232, 223, 31, 208, 83, 231, 120,
    127, 36, 129, 82, 186, 219, 207, 87, 130, 231, 224, 111, 210, 88, 19, 147, 0, 37, 194, 9, 217, 191, 162, 77,
    165, 32, 78, 141, 227, 44, 70, 156, 13, 250, 36, 93, 226, 178, 165, 61, 33, 63 };

static HcfBlob g_secp224r1PointUncompressedBlob = {
    .data = g_secp224r1PointUncompressedBlobData,
    .len = SECP224R1_POINT_UNCOMPRESSED_SIZE
};

static HcfBlob g_prime256v1PointUncompressedBlob = {
    .data = g_prime256v1PointUncompressedBlobData,
    .len = PRIME256V1_POINT_UNCOMPRESSED_SIZE
};

static HcfBlob g_secp384r1PointUncompressedBlob = {
    .data = g_secp384r1PointUncompressedBlobData,
    .len = SECP384R1_POINT_UNCOMPRESSED_SIZE
};

static HcfBlob g_secp521r1PointUncompressedBlob = {
    .data = g_secp521r1PointUncompressedBlobData,
    .len = SECP521R1_POINT_UNCOMPRESSED_SIZE
};

static HcfBlob g_p160r1PointUncompressedBlob = {
    .data = g_p160r1PointUncompressedBlobData,
    .len = P160R1_POINT_UNCOMPRESSED_SIZE
};

static HcfBlob g_p160t1PointUncompressedBlob = {
    .data = g_p160t1PointUncompressedBlobData,
    .len = P160T1_POINT_UNCOMPRESSED_SIZE
};

static HcfBlob g_p192r1PointUncompressedBlob = {
    .data = g_p192r1PointUncompressedBlobData,
    .len = P192R1_POINT_UNCOMPRESSED_SIZE
};

static HcfBlob g_p192t1PointUncompressedBlob = {
    .data = g_p192t1PointUncompressedBlobData,
    .len = P192T1_POINT_UNCOMPRESSED_SIZE
};

static HcfBlob g_p224r1PointUncompressedBlob = {
    .data = g_p224r1PointUncompressedBlobData,
    .len = P224R1_POINT_UNCOMPRESSED_SIZE
};

static HcfBlob g_p224t1PointUncompressedBlob = {
    .data = g_p224t1PointUncompressedBlobData,
    .len = P224T1_POINT_UNCOMPRESSED_SIZE
};

static HcfBlob g_p256r1PointUncompressedBlob = {
    .data = g_p256r1PointUncompressedBlobData,
    .len = P256R1_POINT_UNCOMPRESSED_SIZE
};

static HcfBlob g_p256t1PointUncompressedBlob = {
    .data = g_p256t1PointUncompressedBlobData,
    .len = P256T1_POINT_UNCOMPRESSED_SIZE
};

static HcfBlob g_p320r1PointUncompressedBlob = {
    .data = g_p320r1PointUncompressedBlobData,
    .len = P320R1_POINT_UNCOMPRESSED_SIZE
};

static HcfBlob g_p320t1PointUncompressedBlob = {
    .data = g_p320t1PointUncompressedBlobData,
    .len = P320T1_POINT_UNCOMPRESSED_SIZE
};

static HcfBlob g_p384r1PointUncompressedBlob = {
    .data = g_p384r1PointUncompressedBlobData,
    .len = P384R1_POINT_UNCOMPRESSED_SIZE
};

static HcfBlob g_p384t1PointUncompressedBlob = {
    .data = g_p384t1PointUncompressedBlobData,
    .len = P384T1_POINT_UNCOMPRESSED_SIZE
};

static HcfBlob g_p512r1PointUncompressedBlob = {
    .data = g_p512r1PointUncompressedBlobData,
    .len = P512R1_POINT_UNCOMPRESSED_SIZE
};

static HcfBlob g_p512t1PointUncompressedBlob = {
    .data = g_p512t1PointUncompressedBlobData,
    .len = P512T1_POINT_UNCOMPRESSED_SIZE
};

// compressed point data size
constexpr size_t SECP224R1_POINT_COMPRESSED_SIZE = 29;
constexpr size_t PRIME256V1_POINT_COMPRESSED_SIZE = 33;
constexpr size_t SECP384R1_POINT_COMPRESSED_SIZE = 49;
constexpr size_t SECP521R1_POINT_COMPRESSED_SIZE = 67;
constexpr size_t P160R1_POINT_COMPRESSED_SIZE = 21;
constexpr size_t P160T1_POINT_COMPRESSED_SIZE = 21;
constexpr size_t P192R1_POINT_COMPRESSED_SIZE = 25;
constexpr size_t P192T1_POINT_COMPRESSED_SIZE = 25;
constexpr size_t P224R1_POINT_COMPRESSED_SIZE = 29;
constexpr size_t P224T1_POINT_COMPRESSED_SIZE = 29;
constexpr size_t P256R1_POINT_COMPRESSED_SIZE = 33;
constexpr size_t P256T1_POINT_COMPRESSED_SIZE = 33;
constexpr size_t P320R1_POINT_COMPRESSED_SIZE = 41;
constexpr size_t P320T1_POINT_COMPRESSED_SIZE = 41;
constexpr size_t P384R1_POINT_COMPRESSED_SIZE = 49;
constexpr size_t P384T1_POINT_COMPRESSED_SIZE = 49;
constexpr size_t P512R1_POINT_COMPRESSED_SIZE = 65;
constexpr size_t P512T1_POINT_COMPRESSED_SIZE = 65;

// compressed point data
static uint8_t g_secp224r1PointCompressedBlobData[] = { 3, 56, 90, 25, 144, 206, 229, 109, 59, 65, 62, 249, 113,
    247, 239, 20, 63, 107, 72, 217, 43, 12, 124, 241, 209, 32, 66, 134, 239 };

static uint8_t g_prime256v1PointCompressedBlobData[] = { 2, 153, 228, 156, 119, 184, 185, 120, 237, 233, 181, 77,
    70, 183, 30, 68, 2, 70, 37, 251, 5, 22, 199, 84, 87, 222, 65, 103, 8, 26, 255, 137, 206 };

static uint8_t g_secp384r1PointCompressedBlobData[] = { 3, 246, 157, 255, 226, 94, 109, 16, 243, 109, 34, 121, 62,
    12, 160, 181, 60, 89, 27, 60, 236, 118, 93, 113, 123, 64, 220, 231, 248, 113, 220, 130, 75, 164, 174, 128,
    84, 135, 212, 122, 99, 97, 167, 89, 56, 162, 60, 50, 185 };

static uint8_t g_secp521r1PointCompressedBlobData[] = { 2, 0, 234, 87, 65, 173, 170, 194, 156, 174, 174, 229, 236,
    236, 195, 107, 24, 24, 169, 187, 160, 28, 11, 239, 70, 163, 131, 233, 157, 104, 41, 202, 208, 166, 209, 217, 39,
    225, 163, 33, 17, 134, 48, 150, 111, 225, 193, 219, 232, 234, 117, 100, 27, 169, 172, 60, 186, 69, 246, 244, 218,
    249, 188, 96, 49, 247, 125 };

static uint8_t g_p160r1PointCompressedBlobData[] = { 2, 162, 100, 90, 91, 16, 253, 183, 186, 164, 222, 247, 223,
    75, 228, 92, 253, 253, 250, 38, 30 };

static uint8_t g_p160t1PointCompressedBlobData[] = { 2, 73, 116, 114, 251, 6, 125, 11, 84, 159, 140, 0, 164, 101,
    40, 147, 227, 28, 143, 224, 160 };

static uint8_t g_p192r1PointCompressedBlobData[] = { 3, 72, 15, 250, 255, 107, 128, 70, 56, 144, 154, 23, 141, 54,
    19, 255, 134, 235, 12, 187, 128, 121, 41, 255, 141 };

static uint8_t g_p192t1PointCompressedBlobData[] = { 3, 131, 174, 50, 196, 198, 2, 164, 255, 193, 233, 237, 217, 47,
    191, 35, 6, 166, 69, 42, 38, 128, 134, 29, 97 };

static uint8_t g_p224r1PointCompressedBlobData[] = { 3, 179, 154, 82, 152, 164, 40, 37, 88, 133, 242, 75, 160, 244,
    155, 186, 103, 163, 44, 100, 137, 114, 124, 28, 27, 187, 99, 235, 123 };

static uint8_t g_p224t1PointCompressedBlobData[] = { 2, 187, 42, 38, 78, 26, 235, 23, 233, 222, 133, 167, 236, 86,
    95, 104, 44, 160, 133, 41, 92, 214, 174, 194, 43, 214, 123, 12, 188 };

static uint8_t g_p256r1PointCompressedBlobData[] = { 2, 0, 181, 254, 30, 31, 239, 138, 26, 134, 97, 46, 250, 9,
    142, 148, 201, 217, 224, 223, 68, 54, 180, 157, 30, 98, 140, 81, 237, 29, 242, 108, 3 };

static uint8_t g_p256t1PointCompressedBlobData[] = { 2, 134, 165, 93, 7, 187, 30, 225, 62, 157, 177, 229, 63, 104,
    217, 148, 68, 85, 152, 34, 185, 100, 81, 111, 233, 193, 108, 198, 74, 37, 188, 46, 19 };

static uint8_t g_p320r1PointCompressedBlobData[] = { 2, 117, 229, 73, 102, 77, 218, 200, 35, 245, 163, 23, 219,
    50, 180, 7, 60, 219, 87, 135, 67, 214, 34, 71, 1, 75, 227, 143, 253, 203, 40, 246, 249, 210, 64, 255,
    186, 202, 161, 214, 203 };

static uint8_t g_p320t1PointCompressedBlobData[] = { 2, 188, 215, 24, 76, 167, 218, 220, 193, 3, 105, 145, 175,
    125, 17, 15, 227, 69, 120, 196, 97, 151, 3, 116, 23, 83, 71, 204, 133, 13, 225, 88, 31, 11, 168,
    66, 57, 64, 233, 125, 156 };

static uint8_t g_p384r1PointCompressedBlobData[] = { 2, 24, 149, 106, 30, 33, 152, 247, 126, 23, 231, 139, 197,
    240, 145, 3, 6, 38, 168, 157, 60, 153, 95, 41, 184, 110, 135, 222, 237, 86, 132, 255, 180, 245, 49, 41, 3,
    223, 122, 210, 203, 213, 55, 108, 251, 65, 181, 168, 25 };

static uint8_t g_p384t1PointCompressedBlobData[] = { 3, 64, 192, 12, 47, 160, 35, 23, 244, 163, 108, 172, 235,
    185, 100, 0, 180, 112, 85, 105, 29, 120, 105, 164, 148, 59, 168, 183, 168, 142, 141, 14, 121, 240, 132, 168,
    4, 208, 142, 24, 226, 75, 169, 249, 46, 63, 61, 129, 154 };

static uint8_t g_p512r1PointCompressedBlobData[] = { 2, 18, 25, 192, 69, 115, 54, 110, 174, 51, 48, 253, 129,
    31, 118, 237, 38, 1, 174, 8, 111, 74, 249, 149, 154, 119, 114, 59, 51, 160, 206, 70, 199, 202, 42, 98, 245,
    170, 251, 154, 22, 243, 137, 182, 239, 219, 166, 28, 202, 183, 229, 2, 83, 16, 244, 211, 100, 30, 179, 251, 17,
    52, 117, 55, 70 };

static uint8_t g_p512t1PointCompressedBlobData[] = { 3, 119, 56, 81, 46, 40, 173, 156, 49, 235, 26, 193, 122, 32,
    201, 88, 18, 90, 55, 144, 84, 125, 90, 106, 169, 66, 124, 90, 44, 145, 100, 224, 192, 22, 241, 38, 185, 93,
    163, 146, 221, 126, 222, 57, 95, 136, 139, 231, 85, 250, 133, 140, 81, 138, 66, 148, 253, 192, 217, 210, 33,
    157, 60, 5, 113 };

static HcfBlob g_secp224r1PointCompressedBlob = {
    .data = g_secp224r1PointCompressedBlobData,
    .len = SECP224R1_POINT_COMPRESSED_SIZE
};

static HcfBlob g_prime256v1PointCompressedBlob = {
    .data = g_prime256v1PointCompressedBlobData,
    .len = PRIME256V1_POINT_COMPRESSED_SIZE
};

static HcfBlob g_secp384r1PointCompressedBlob = {
    .data = g_secp384r1PointCompressedBlobData,
    .len = SECP384R1_POINT_COMPRESSED_SIZE
};

static HcfBlob g_secp521r1PointCompressedBlob = {
    .data = g_secp521r1PointCompressedBlobData,
    .len = SECP521R1_POINT_COMPRESSED_SIZE
};

static HcfBlob g_p160r1PointCompressedBlob = {
    .data = g_p160r1PointCompressedBlobData,
    .len = P160R1_POINT_COMPRESSED_SIZE
};

static HcfBlob g_p160t1PointCompressedBlob = {
    .data = g_p160t1PointCompressedBlobData,
    .len = P160T1_POINT_COMPRESSED_SIZE
};

static HcfBlob g_p192r1PointCompressedBlob = {
    .data = g_p192r1PointCompressedBlobData,
    .len = P192R1_POINT_COMPRESSED_SIZE
};

static HcfBlob g_p192t1PointCompressedBlob = {
    .data = g_p192t1PointCompressedBlobData,
    .len = P192T1_POINT_COMPRESSED_SIZE
};

static HcfBlob g_p224r1PointCompressedBlob = {
    .data = g_p224r1PointCompressedBlobData,
    .len = P224R1_POINT_COMPRESSED_SIZE
};

static HcfBlob g_p224t1PointCompressedBlob = {
    .data = g_p224t1PointCompressedBlobData,
    .len = P224T1_POINT_COMPRESSED_SIZE
};

static HcfBlob g_p256r1PointCompressedBlob = {
    .data = g_p256r1PointCompressedBlobData,
    .len = P256R1_POINT_COMPRESSED_SIZE
};

static HcfBlob g_p256t1PointCompressedBlob = {
    .data = g_p256t1PointCompressedBlobData,
    .len = P256T1_POINT_COMPRESSED_SIZE
};

static HcfBlob g_p320r1PointCompressedBlob = {
    .data = g_p320r1PointCompressedBlobData,
    .len = P320R1_POINT_COMPRESSED_SIZE
};

static HcfBlob g_p320t1PointCompressedBlob = {
    .data = g_p320t1PointCompressedBlobData,
    .len = P320T1_POINT_COMPRESSED_SIZE
};

static HcfBlob g_p384r1PointCompressedBlob = {
    .data = g_p384r1PointCompressedBlobData,
    .len = P384R1_POINT_COMPRESSED_SIZE
};

static HcfBlob g_p384t1PointCompressedBlob = {
    .data = g_p384t1PointCompressedBlobData,
    .len = P384T1_POINT_COMPRESSED_SIZE
};

static HcfBlob g_p512r1PointCompressedBlob = {
    .data = g_p512r1PointCompressedBlobData,
    .len = P512R1_POINT_COMPRESSED_SIZE
};

static HcfBlob g_p512t1PointCompressedBlob = {
    .data = g_p512t1PointCompressedBlobData,
    .len = P512T1_POINT_COMPRESSED_SIZE
};

typedef struct {
    const char *curveName;
    HcfBlob *pointUncompressedBlob;
    HcfBlob *pointCompressedBlob;
} PointData;

static const PointData POINT_DATA_MAP[] = {
    { "NID_secp224r1", &g_secp224r1PointUncompressedBlob, &g_secp224r1PointCompressedBlob },
    { "NID_X9_62_prime256v1", &g_prime256v1PointUncompressedBlob, &g_prime256v1PointCompressedBlob },
    { "NID_secp384r1", &g_secp384r1PointUncompressedBlob, &g_secp384r1PointCompressedBlob },
    { "NID_secp521r1", &g_secp521r1PointUncompressedBlob, &g_secp521r1PointCompressedBlob },
    { "NID_brainpoolP160r1", &g_p160r1PointUncompressedBlob, &g_p160r1PointCompressedBlob },
    { "NID_brainpoolP160t1", &g_p160t1PointUncompressedBlob, &g_p160t1PointCompressedBlob },
    { "NID_brainpoolP192r1", &g_p192r1PointUncompressedBlob, &g_p192r1PointCompressedBlob },
    { "NID_brainpoolP192t1", &g_p192t1PointUncompressedBlob, &g_p192t1PointCompressedBlob },
    { "NID_brainpoolP224r1", &g_p224r1PointUncompressedBlob, &g_p224r1PointCompressedBlob },
    { "NID_brainpoolP224t1", &g_p224t1PointUncompressedBlob, &g_p224t1PointCompressedBlob },
    { "NID_brainpoolP256r1", &g_p256r1PointUncompressedBlob, &g_p256r1PointCompressedBlob },
    { "NID_brainpoolP256t1", &g_p256t1PointUncompressedBlob, &g_p256t1PointCompressedBlob },
    { "NID_brainpoolP320r1", &g_p320r1PointUncompressedBlob, &g_p320r1PointCompressedBlob },
    { "NID_brainpoolP320t1", &g_p320t1PointUncompressedBlob, &g_p320t1PointCompressedBlob },
    { "NID_brainpoolP384r1", &g_p384r1PointUncompressedBlob, &g_p384r1PointCompressedBlob },
    { "NID_brainpoolP384t1", &g_p384t1PointUncompressedBlob, &g_p384t1PointCompressedBlob },
    { "NID_brainpoolP512r1", &g_p512r1PointUncompressedBlob, &g_p512r1PointCompressedBlob },
    { "NID_brainpoolP512t1", &g_p512t1PointUncompressedBlob, &g_p512t1PointCompressedBlob }
};

// uncompressed pubkey data size
constexpr size_t SECP224R1_PUBKEY_UNCOMPRESSED_SIZE = 80;
constexpr size_t PRIME256V1_PUBKEY_UNCOMPRESSED_SIZE = 91;
constexpr size_t SECP384R1_PUBKEY_UNCOMPRESSED_SIZE = 120;
constexpr size_t SECP521R1_PUBKEY_UNCOMPRESSED_SIZE = 158;
constexpr size_t P160R1_PUBKEY_UNCOMPRESSED_SIZE = 68;
constexpr size_t P160T1_PUBKEY_UNCOMPRESSED_SIZE = 68;
constexpr size_t P192R1_PUBKEY_UNCOMPRESSED_SIZE = 76;
constexpr size_t P192T1_PUBKEY_UNCOMPRESSED_SIZE = 76;
constexpr size_t P224R1_PUBKEY_UNCOMPRESSED_SIZE = 84;
constexpr size_t P224T1_PUBKEY_UNCOMPRESSED_SIZE = 84;
constexpr size_t P256R1_PUBKEY_UNCOMPRESSED_SIZE = 92;
constexpr size_t P256T1_PUBKEY_UNCOMPRESSED_SIZE = 92;
constexpr size_t P320R1_PUBKEY_UNCOMPRESSED_SIZE = 108;
constexpr size_t P320T1_PUBKEY_UNCOMPRESSED_SIZE = 108;
constexpr size_t P384R1_PUBKEY_UNCOMPRESSED_SIZE = 124;
constexpr size_t P384T1_PUBKEY_UNCOMPRESSED_SIZE = 124;
constexpr size_t P512R1_PUBKEY_UNCOMPRESSED_SIZE = 158;
constexpr size_t P512T1_PUBKEY_UNCOMPRESSED_SIZE = 158;

// uncompressed pubkey data
static uint8_t g_secp224r1PubKeyUncompressedBlobData[] = { 48, 78, 48, 16, 6, 7, 42, 134, 72, 206, 61, 2, 1, 6, 5, 43,
    129, 4, 0, 33, 3, 58, 0, 4, 56, 90, 25, 144, 206, 229, 109, 59, 65, 62, 249, 113, 247, 239, 20, 63, 107, 72, 217,
    43, 12, 124, 241, 209, 32, 66, 134, 239, 169, 154, 59, 182, 106, 163, 190, 214, 232, 213, 73, 97, 57, 163, 137,
    66, 59, 238, 12, 142, 87, 37, 182, 22, 60, 106, 235, 237 };

static uint8_t g_prime256v1PubKeyUncompressedBlobData[] = { 48, 89, 48, 19, 6, 7, 42, 134, 72, 206, 61, 2, 1, 6, 8,
    42, 134, 72, 206, 61, 3, 1, 7, 3, 66, 0, 4, 153, 228, 156, 119, 184, 185, 120, 237, 233, 181, 77, 70, 183, 30,
    68, 2, 70, 37, 251, 5, 22, 199, 84, 87, 222, 65, 103, 8, 26, 255, 137, 206, 80, 159, 163, 46, 22, 104, 156, 169,
    14, 149, 199, 35, 201, 3, 160, 81, 251, 235, 236, 75, 137, 196, 253, 200, 116, 167, 59, 153, 241, 99, 90, 90 };

static uint8_t g_secp384r1PubKeyUncompressedBlobData[] = { 48, 118, 48, 16, 6, 7, 42, 134, 72, 206, 61, 2, 1, 6, 5,
    43, 129, 4, 0, 34, 3, 98, 0, 4, 246, 157, 255, 226, 94, 109, 16, 243, 109, 34, 121, 62, 12, 160, 181, 60, 89, 27,
    60, 236, 118, 93, 113, 123, 64, 220, 231, 248, 113, 220, 130, 75, 164, 174, 128, 84, 135, 212, 122, 99, 97, 167,
    89, 56, 162, 60, 50, 185, 154, 231, 102, 187, 58, 105, 237, 215, 53, 88, 253, 33, 45, 36, 25, 176, 112, 110, 132,
    39, 33, 56, 224, 21, 225, 8, 108, 81, 106, 157, 33, 210, 105, 138, 130, 163, 96, 112, 183, 179, 241, 25, 188,
    121, 68, 180, 169, 149 };

static uint8_t g_secp521r1PubKeyUncompressedBlobData[] = { 48, 129, 155, 48, 16, 6, 7, 42, 134, 72, 206, 61, 2, 1, 6,
    5, 43, 129, 4, 0, 35, 3, 129, 134, 0, 4, 0, 234, 87, 65, 173, 170, 194, 156, 174, 174, 229, 236, 236, 195, 107,
    24, 24, 169, 187, 160, 28, 11, 239, 70, 163, 131, 233, 157, 104, 41, 202, 208, 166, 209, 217, 39, 225, 163, 33,
    17, 134, 48, 150, 111, 225, 193, 219, 232, 234, 117, 100, 27, 169, 172, 60, 186, 69, 246, 244, 218, 249, 188, 96,
    49, 247, 125, 0, 70, 67, 187, 0, 72, 109, 99, 50, 173, 42, 250, 10, 89, 166, 85, 64, 28, 145, 30, 130, 174, 147,
    22, 232, 37, 17, 158, 165, 178, 11, 34, 58, 98, 98, 43, 32, 146, 102, 178, 198, 176, 41, 150, 37, 43, 132, 232,
    32, 98, 143, 125, 255, 173, 158, 227, 4, 238, 168, 113, 194, 162, 74, 234, 239, 102 };

static uint8_t g_p160r1PubKeyUncompressedBlobData[] = { 48, 66, 48, 20, 6, 7, 42, 134, 72, 206, 61, 2, 1, 6, 9, 43,
    36, 3, 3, 2, 8, 1, 1, 1, 3, 42, 0, 4, 162, 100, 90, 91, 16, 253, 183, 186, 164, 222, 247, 223, 75, 228, 92, 253,
    253, 250, 38, 30, 125, 172, 62, 13, 109, 61, 63, 160, 20, 103, 94, 7, 68, 115, 202, 170, 157, 244, 174, 26 };

static uint8_t g_p160t1PubKeyUncompressedBlobData[] = { 48, 66, 48, 20, 6, 7, 42, 134, 72, 206, 61, 2, 1, 6, 9, 43,
    36, 3, 3, 2, 8, 1, 1, 2, 3, 42, 0, 4, 73, 116, 114, 251, 6, 125, 11, 84, 159, 140, 0, 164, 101, 40, 147, 227, 28,
    143, 224, 160, 217, 185, 12, 197, 39, 34, 91, 119, 135, 123, 80, 45, 26, 156, 221, 2, 79, 242, 45, 24 };

static uint8_t g_p192r1PubKeyUncompressedBlobData[] = { 48, 74, 48, 20, 6, 7, 42, 134, 72, 206, 61, 2, 1, 6, 9, 43,
    36, 3, 3, 2, 8, 1, 1, 3, 3, 50, 0, 4, 72, 15, 250, 255, 107, 128, 70, 56, 144, 154, 23, 141, 54, 19, 255, 134,
    235, 12, 187, 128, 121, 41, 255, 141, 69, 81, 100, 94, 238, 15, 166, 184, 1, 214, 220, 222, 12, 239, 145, 184,
    143, 146, 165, 9, 107, 74, 199, 1 };

static uint8_t g_p192t1PubKeyUncompressedBlobData[] = { 48, 74, 48, 20, 6, 7, 42, 134, 72, 206, 61, 2, 1, 6, 9, 43,
    36, 3, 3, 2, 8, 1, 1, 4, 3, 50, 0, 4, 131, 174, 50, 196, 198, 2, 164, 255, 193, 233, 237, 217, 47, 191, 35, 6,
    166, 69, 42, 38, 128, 134, 29, 97, 23, 242, 82, 96, 164, 135, 108, 120, 179, 105, 10, 32, 90, 152, 99, 10, 2,
    220, 184, 207, 8, 65, 168, 95 };

static uint8_t g_p224r1PubKeyUncompressedBlobData[] = { 48, 82, 48, 20, 6, 7, 42, 134, 72, 206, 61, 2, 1, 6, 9, 43,
    36, 3, 3, 2, 8, 1, 1, 5, 3, 58, 0, 4, 179, 154, 82, 152, 164, 40, 37, 88, 133, 242, 75, 160, 244, 155, 186, 103,
    163, 44, 100, 137, 114, 124, 28, 27, 187, 99, 235, 123, 46, 127, 137, 234, 188, 6, 91, 68, 250, 89, 231, 62,
    179, 47, 119, 221, 5, 73, 128, 12, 241, 57, 101, 15, 9, 95, 11, 101 };

static uint8_t g_p224t1PubKeyUncompressedBlobData[] = { 48, 82, 48, 20, 6, 7, 42, 134, 72, 206, 61, 2, 1, 6, 9, 43,
    36, 3, 3, 2, 8, 1, 1, 6, 3, 58, 0, 4, 187, 42, 38, 78, 26, 235, 23, 233, 222, 133, 167, 236, 86, 95, 104, 44,
    160, 133, 41, 92, 214, 174, 194, 43, 214, 123, 12, 188, 210, 117, 152, 50, 0, 136, 6, 92, 57, 236, 246, 150, 145,
    249, 150, 185, 255, 116, 28, 111, 22, 173, 25, 205, 96, 251, 61, 238 };

static uint8_t g_p256r1PubKeyUncompressedBlobData[] = { 48, 90, 48, 20, 6, 7, 42, 134, 72, 206, 61, 2, 1, 6, 9, 43,
    36, 3, 3, 2, 8, 1, 1, 7, 3, 66, 0, 4, 0, 181, 254, 30, 31, 239, 138, 26, 134, 97, 46, 250, 9, 142, 148, 201,
    217, 224, 223, 68, 54, 180, 157, 30, 98, 140, 81, 237, 29, 242, 108, 3, 100, 127, 165, 176, 53, 73, 197, 151,
    79, 219, 204, 98, 116, 71, 97, 1, 127, 216, 38, 84, 18, 157, 250, 240, 109, 251, 105, 243, 73, 17, 153, 138 };

static uint8_t g_p256t1PubKeyUncompressedBlobData[] = { 48, 90, 48, 20, 6, 7, 42, 134, 72, 206, 61, 2, 1, 6, 9, 43,
    36, 3, 3, 2, 8, 1, 1, 8, 3, 66, 0, 4, 134, 165, 93, 7, 187, 30, 225, 62, 157, 177, 229, 63, 104, 217, 148, 68,
    85, 152, 34, 185, 100, 81, 111, 233, 193, 108, 198, 74, 37, 188, 46, 19, 136, 157, 88, 166, 194, 167, 157, 163,
    173, 69, 7, 153, 48, 246, 3, 54, 127, 113, 145, 17, 128, 250, 210, 218, 249, 150, 249, 243, 178, 136, 112, 192 };

static uint8_t g_p320r1PubKeyUncompressedBlobData[] = { 48, 106, 48, 20, 6, 7, 42, 134, 72, 206, 61, 2, 1, 6, 9, 43,
    36, 3, 3, 2, 8, 1, 1, 9, 3, 82, 0, 4, 117, 229, 73, 102, 77, 218, 200, 35, 245, 163, 23, 219, 50, 180, 7, 60,
    219, 87, 135, 67, 214, 34, 71, 1, 75, 227, 143, 253, 203, 40, 246, 249, 210, 64, 255, 186, 202, 161, 214, 203,
    91, 159, 114, 252, 134, 230, 86, 188, 103, 223, 217, 12, 238, 118, 6, 232, 161, 198, 195, 139, 62, 36, 98, 212,
    129, 215, 178, 83, 137, 164, 95, 239, 238, 216, 222, 125, 246, 105, 66, 164 };

static uint8_t g_p320t1PubKeyUncompressedBlobData[] = { 48, 106, 48, 20, 6, 7, 42, 134, 72, 206, 61, 2, 1, 6, 9, 43,
    36, 3, 3, 2, 8, 1, 1, 10, 3, 82, 0, 4, 188, 215, 24, 76, 167, 218, 220, 193, 3, 105, 145, 175, 125, 17, 15, 227,
    69, 120, 196, 97, 151, 3, 116, 23, 83, 71, 204, 133, 13, 225, 88, 31, 11, 168, 66, 57, 64, 233, 125, 156, 12, 28,
    241, 242, 224, 110, 133, 157, 230, 106, 16, 126, 66, 37, 8, 235, 230, 90, 20, 253, 2, 223, 157, 135, 71, 161, 64,
    111, 50, 212, 125, 187, 44, 181, 211, 76, 217, 53, 94, 162 };

static uint8_t g_p384r1PubKeyUncompressedBlobData[] = { 48, 122, 48, 20, 6, 7, 42, 134, 72, 206, 61, 2, 1, 6, 9, 43,
    36, 3, 3, 2, 8, 1, 1, 11, 3, 98, 0, 4, 24, 149, 106, 30, 33, 152, 247, 126, 23, 231, 139, 197, 240, 145, 3, 6, 38,
    168, 157, 60, 153, 95, 41, 184, 110, 135, 222, 237, 86, 132, 255, 180, 245, 49, 41, 3, 223, 122, 210, 203, 213,
    55, 108, 251, 65, 181, 168, 25, 69, 50, 124, 233, 124, 121, 89, 187, 238, 186, 163, 169, 88, 48, 7, 108, 206,
    228, 141, 162, 127, 232, 67, 175, 95, 220, 178, 28, 152, 254, 148, 123, 46, 132, 222, 124, 11, 51, 152, 113,
    44, 14, 222, 126, 142, 114, 10, 124 };

static uint8_t g_p384t1PubKeyUncompressedBlobData[] = { 48, 122, 48, 20, 6, 7, 42, 134, 72, 206, 61, 2, 1, 6, 9, 43,
    36, 3, 3, 2, 8, 1, 1, 12, 3, 98, 0, 4, 64, 192, 12, 47, 160, 35, 23, 244, 163, 108, 172, 235, 185, 100, 0, 180,
    112, 85, 105, 29, 120, 105, 164, 148, 59, 168, 183, 168, 142, 141, 14, 121, 240, 132, 168, 4, 208, 142, 24, 226,
    75, 169, 249, 46, 63, 61, 129, 154, 41, 6, 34, 81, 246, 230, 4, 227, 103, 106, 107, 216, 130, 58, 248, 156, 101,
    96, 85, 109, 43, 233, 229, 96, 165, 188, 222, 226, 113, 17, 213, 194, 57, 142, 117, 129, 151, 187, 235, 43, 253,
    132, 151, 96, 49, 85, 37, 101 };

static uint8_t g_p512r1PubKeyUncompressedBlobData[] = { 48, 129, 155, 48, 20, 6, 7, 42, 134, 72, 206, 61, 2, 1, 6, 9,
    43, 36, 3, 3, 2, 8, 1, 1, 13, 3, 129, 130, 0, 4, 18, 25, 192, 69, 115, 54, 110, 174, 51, 48, 253, 129, 31, 118,
    237, 38, 1, 174, 8, 111, 74, 249, 149, 154, 119, 114, 59, 51, 160, 206, 70, 199, 202, 42, 98, 245, 170, 251, 154,
    22, 243, 137, 182, 239, 219, 166, 28, 202, 183, 229, 2, 83, 16, 244, 211, 100, 30, 179, 251, 17, 52, 117, 55, 70,
    114, 203, 60, 190, 163, 132, 156, 63, 246, 140, 173, 122, 80, 68, 155, 60, 74, 199, 248, 71, 134, 52, 228, 28,
    122, 72, 100, 26, 36, 148, 20, 187, 59, 137, 98, 191, 165, 174, 43, 2, 68, 222, 184, 34, 108, 8, 155, 150, 12,
    101, 120, 155, 164, 200, 52, 206, 240, 116, 158, 207, 180, 124, 210, 62 };

static uint8_t g_p512t1PubKeyUncompressedBlobData[] = { 48, 129, 155, 48, 20, 6, 7, 42, 134, 72, 206, 61, 2, 1, 6, 9,
    43, 36, 3, 3, 2, 8, 1, 1, 14, 3, 129, 130, 0, 4, 119, 56, 81, 46, 40, 173, 156, 49, 235, 26, 193, 122, 32, 201,
    88, 18, 90, 55, 144, 84, 125, 90, 106, 169, 66, 124, 90, 44, 145, 100, 224, 192, 22, 241, 38, 185, 93, 163, 146,
    221, 126, 222, 57, 95, 136, 139, 231, 85, 250, 133, 140, 81, 138, 66, 148, 253, 192, 217, 210, 33, 157, 60, 5,
    113, 151, 65, 106, 113, 44, 250, 237, 139, 172, 190, 154, 142, 17, 77, 228, 232, 223, 31, 208, 83, 231, 120,
    127, 36, 129, 82, 186, 219, 207, 87, 130, 231, 224, 111, 210, 88, 19, 147, 0, 37, 194, 9, 217, 191, 162, 77,
    165, 32, 78, 141, 227, 44, 70, 156, 13, 250, 36, 93, 226, 178, 165, 61, 33, 63 };

static HcfBlob g_secp224r1PubKeyUncompressedBlob = {
    .data = g_secp224r1PubKeyUncompressedBlobData,
    .len = SECP224R1_PUBKEY_UNCOMPRESSED_SIZE
};

static HcfBlob g_prime256v1PubKeyUncompressedBlob = {
    .data = g_prime256v1PubKeyUncompressedBlobData,
    .len = PRIME256V1_PUBKEY_UNCOMPRESSED_SIZE
};

static HcfBlob g_secp384r1PubKeyUncompressedBlob = {
    .data = g_secp384r1PubKeyUncompressedBlobData,
    .len = SECP384R1_PUBKEY_UNCOMPRESSED_SIZE
};

static HcfBlob g_secp521r1PubKeyUncompressedBlob = {
    .data = g_secp521r1PubKeyUncompressedBlobData,
    .len = SECP521R1_PUBKEY_UNCOMPRESSED_SIZE
};

static HcfBlob g_p160r1PubKeyUncompressedBlob = {
    .data = g_p160r1PubKeyUncompressedBlobData,
    .len = P160R1_PUBKEY_UNCOMPRESSED_SIZE
};

static HcfBlob g_p160t1PubKeyUncompressedBlob = {
    .data = g_p160t1PubKeyUncompressedBlobData,
    .len = P160T1_PUBKEY_UNCOMPRESSED_SIZE
};

static HcfBlob g_p192r1PubKeyUncompressedBlob = {
    .data = g_p192r1PubKeyUncompressedBlobData,
    .len = P192R1_PUBKEY_UNCOMPRESSED_SIZE
};

static HcfBlob g_p192t1PubKeyUncompressedBlob = {
    .data = g_p192t1PubKeyUncompressedBlobData,
    .len = P192T1_PUBKEY_UNCOMPRESSED_SIZE
};

static HcfBlob g_p224r1PubKeyUncompressedBlob = {
    .data = g_p224r1PubKeyUncompressedBlobData,
    .len = P224R1_PUBKEY_UNCOMPRESSED_SIZE
};

static HcfBlob g_p224t1PubKeyUncompressedBlob = {
    .data = g_p224t1PubKeyUncompressedBlobData,
    .len = P224T1_PUBKEY_UNCOMPRESSED_SIZE
};

static HcfBlob g_p256r1PubKeyUncompressedBlob = {
    .data = g_p256r1PubKeyUncompressedBlobData,
    .len = P256R1_PUBKEY_UNCOMPRESSED_SIZE
};

static HcfBlob g_p256t1PubKeyUncompressedBlob = {
    .data = g_p256t1PubKeyUncompressedBlobData,
    .len = P256T1_PUBKEY_UNCOMPRESSED_SIZE
};

static HcfBlob g_p320r1PubKeyUncompressedBlob = {
    .data = g_p320r1PubKeyUncompressedBlobData,
    .len = P320R1_PUBKEY_UNCOMPRESSED_SIZE
};

static HcfBlob g_p320t1PubKeyUncompressedBlob = {
    .data = g_p320t1PubKeyUncompressedBlobData,
    .len = P320T1_PUBKEY_UNCOMPRESSED_SIZE
};

static HcfBlob g_p384r1PubKeyUncompressedBlob = {
    .data = g_p384r1PubKeyUncompressedBlobData,
    .len = P384R1_PUBKEY_UNCOMPRESSED_SIZE
};

static HcfBlob g_p384t1PubKeyUncompressedBlob = {
    .data = g_p384t1PubKeyUncompressedBlobData,
    .len = P384T1_PUBKEY_UNCOMPRESSED_SIZE
};

static HcfBlob g_p512r1PubKeyUncompressedBlob = {
    .data = g_p512r1PubKeyUncompressedBlobData,
    .len = P512R1_PUBKEY_UNCOMPRESSED_SIZE
};

static HcfBlob g_p512t1PubKeyUncompressedBlob = {
    .data = g_p512t1PubKeyUncompressedBlobData,
    .len = P512T1_PUBKEY_UNCOMPRESSED_SIZE
};

// compressed pubkey data size
constexpr size_t SECP224R1_PUBKEY_COMPRESSED_SIZE = 52;
constexpr size_t PRIME256V1_PUBKEY_COMPRESSED_SIZE = 59;
constexpr size_t SECP384R1_PUBKEY_COMPRESSED_SIZE = 72;
constexpr size_t SECP521R1_PUBKEY_COMPRESSED_SIZE = 90;
constexpr size_t P160R1_PUBKEY_COMPRESSED_SIZE = 48;
constexpr size_t P160T1_PUBKEY_COMPRESSED_SIZE = 48;
constexpr size_t P192R1_PUBKEY_COMPRESSED_SIZE = 52;
constexpr size_t P192T1_PUBKEY_COMPRESSED_SIZE = 52;
constexpr size_t P224R1_PUBKEY_COMPRESSED_SIZE = 56;
constexpr size_t P224T1_PUBKEY_COMPRESSED_SIZE = 56;
constexpr size_t P256R1_PUBKEY_COMPRESSED_SIZE = 60;
constexpr size_t P256T1_PUBKEY_COMPRESSED_SIZE = 60;
constexpr size_t P320R1_PUBKEY_COMPRESSED_SIZE = 68;
constexpr size_t P320T1_PUBKEY_COMPRESSED_SIZE = 68;
constexpr size_t P384R1_PUBKEY_COMPRESSED_SIZE = 76;
constexpr size_t P384T1_PUBKEY_COMPRESSED_SIZE = 76;
constexpr size_t P512R1_PUBKEY_COMPRESSED_SIZE = 92;
constexpr size_t P512T1_PUBKEY_COMPRESSED_SIZE = 92;

// compressed pubkey data
static uint8_t g_secp224r1PubKeyCompressedBlobData[] = { 48, 50, 48, 16, 6, 7, 42, 134, 72, 206, 61, 2, 1, 6, 5, 43,
    129, 4, 0, 33, 3, 30, 0, 3, 56, 90, 25, 144, 206, 229, 109, 59, 65, 62, 249, 113, 247, 239, 20, 63, 107, 72,
    217, 43, 12, 124, 241, 209, 32, 66, 134, 239 };

static uint8_t g_prime256v1PubKeyCompressedBlobData[] = { 48, 57, 48, 19, 6, 7, 42, 134, 72, 206, 61, 2, 1, 6, 8,
    42, 134, 72, 206, 61, 3, 1, 7, 3, 34, 0, 2, 153, 228, 156, 119, 184, 185, 120, 237, 233, 181, 77, 70, 183, 30,
    68, 2, 70, 37, 251, 5, 22, 199, 84, 87, 222, 65, 103, 8, 26, 255, 137, 206 };

static uint8_t g_secp384r1PubKeyCompressedBlobData[] = { 48, 70, 48, 16, 6, 7, 42, 134, 72, 206, 61, 2, 1, 6, 5, 43,
    129, 4, 0, 34, 3, 50, 0, 3, 246, 157, 255, 226, 94, 109, 16, 243, 109, 34, 121, 62, 12, 160, 181, 60, 89, 27, 60,
    236, 118, 93, 113, 123, 64, 220, 231, 248, 113, 220, 130, 75, 164, 174, 128, 84, 135, 212, 122, 99, 97, 167,
    89, 56, 162, 60, 50, 185 };

static uint8_t g_secp521r1PubKeyCompressedBlobData[] = { 48, 88, 48, 16, 6, 7, 42, 134, 72, 206, 61, 2, 1, 6, 5, 43,
    129, 4, 0, 35, 3, 68, 0, 2, 0, 234, 87, 65, 173, 170, 194, 156, 174, 174, 229, 236, 236, 195, 107, 24, 24, 169,
    187, 160, 28, 11, 239, 70, 163, 131, 233, 157, 104, 41, 202, 208, 166, 209, 217, 39, 225, 163, 33, 17, 134, 48,
    150, 111, 225, 193, 219, 232, 234, 117, 100, 27, 169, 172, 60, 186, 69, 246, 244, 218, 249, 188, 96, 49, 247, 125 };

static uint8_t g_p160r1PubKeyCompressedBlobData[] = { 48, 46, 48, 20, 6, 7, 42, 134, 72, 206, 61, 2, 1, 6, 9, 43,
    36, 3, 3, 2, 8, 1, 1, 1, 3, 22, 0, 2, 162, 100, 90, 91, 16, 253, 183, 186, 164, 222, 247, 223, 75, 228, 92,
    253, 253, 250, 38, 30 };

static uint8_t g_p160t1PubKeyCompressedBlobData[] = { 48, 46, 48, 20, 6, 7, 42, 134, 72, 206, 61, 2, 1, 6, 9, 43,
    36, 3, 3, 2, 8, 1, 1, 2, 3, 22, 0, 2, 73, 116, 114, 251, 6, 125, 11, 84, 159, 140, 0, 164, 101, 40, 147, 227,
    28, 143, 224, 160 };

static uint8_t g_p192r1PubKeyCompressedBlobData[] = { 48, 50, 48, 20, 6, 7, 42, 134, 72, 206, 61, 2, 1, 6, 9, 43,
    36, 3, 3, 2, 8, 1, 1, 3, 3, 26, 0, 3, 72, 15, 250, 255, 107, 128, 70, 56, 144, 154, 23, 141, 54, 19, 255, 134,
    235, 12, 187, 128, 121, 41, 255, 141 };

static uint8_t g_p192t1PubKeyCompressedBlobData[] = { 48, 50, 48, 20, 6, 7, 42, 134, 72, 206, 61, 2, 1, 6, 9, 43,
    36, 3, 3, 2, 8, 1, 1, 4, 3, 26, 0, 3, 131, 174, 50, 196, 198, 2, 164, 255, 193, 233, 237, 217, 47, 191, 35, 6,
    166, 69, 42, 38, 128, 134, 29, 97 };

static uint8_t g_p224r1PubKeyCompressedBlobData[] = { 48, 54, 48, 20, 6, 7, 42, 134, 72, 206, 61, 2, 1, 6, 9, 43,
    36, 3, 3, 2, 8, 1, 1, 5, 3, 30, 0, 3, 179, 154, 82, 152, 164, 40, 37, 88, 133, 242, 75, 160, 244, 155, 186, 103,
    163, 44, 100, 137, 114, 124, 28, 27, 187, 99, 235, 123 };

static uint8_t g_p224t1PubKeyCompressedBlobData[] = { 48, 54, 48, 20, 6, 7, 42, 134, 72, 206, 61, 2, 1, 6, 9, 43,
    36, 3, 3, 2, 8, 1, 1, 6, 3, 30, 0, 2, 187, 42, 38, 78, 26, 235, 23, 233, 222, 133, 167, 236, 86, 95, 104, 44,
    160, 133, 41, 92, 214, 174, 194, 43, 214, 123, 12, 188 };

static uint8_t g_p256r1PubKeyCompressedBlobData[] = { 48, 58, 48, 20, 6, 7, 42, 134, 72, 206, 61, 2, 1, 6, 9, 43, 36,
    3, 3, 2, 8, 1, 1, 7, 3, 34, 0, 2, 0, 181, 254, 30, 31, 239, 138, 26, 134, 97, 46, 250, 9, 142, 148, 201, 217, 224,
    223, 68, 54, 180, 157, 30, 98, 140, 81, 237, 29, 242, 108, 3 };

static uint8_t g_p256t1PubKeyCompressedBlobData[] = { 48, 58, 48, 20, 6, 7, 42, 134, 72, 206, 61, 2, 1, 6, 9, 43, 36,
    3, 3, 2, 8, 1, 1, 8, 3, 34, 0, 2, 134, 165, 93, 7, 187, 30, 225, 62, 157, 177, 229, 63, 104, 217, 148, 68, 85,
    152, 34, 185, 100, 81, 111, 233, 193, 108, 198, 74, 37, 188, 46, 19 };

static uint8_t g_p320r1PubKeyCompressedBlobData[] = { 48, 66, 48, 20, 6, 7, 42, 134, 72, 206, 61, 2, 1, 6, 9, 43, 36,
    3, 3, 2, 8, 1, 1, 9, 3, 42, 0, 2, 117, 229, 73, 102, 77, 218, 200, 35, 245, 163, 23, 219, 50, 180, 7, 60, 219,
    87, 135, 67, 214, 34, 71, 1, 75, 227, 143, 253, 203, 40, 246, 249, 210, 64, 255, 186, 202, 161, 214, 203 };

static uint8_t g_p320t1PubKeyCompressedBlobData[] = { 48, 66, 48, 20, 6, 7, 42, 134, 72, 206, 61, 2, 1, 6, 9, 43, 36,
    3, 3, 2, 8, 1, 1, 10, 3, 42, 0, 2, 188, 215, 24, 76, 167, 218, 220, 193, 3, 105, 145, 175, 125, 17, 15, 227, 69,
    120, 196, 97, 151, 3, 116, 23, 83, 71, 204, 133, 13, 225, 88, 31, 11, 168, 66, 57, 64, 233, 125, 156 };

static uint8_t g_p384r1PubKeyCompressedBlobData[] = { 48, 74, 48, 20, 6, 7, 42, 134, 72, 206, 61, 2, 1, 6, 9, 43, 36,
    3, 3, 2, 8, 1, 1, 11, 3, 50, 0, 2, 24, 149, 106, 30, 33, 152, 247, 126, 23, 231, 139, 197, 240, 145, 3, 6, 38,
    168, 157, 60, 153, 95, 41, 184, 110, 135, 222, 237, 86, 132, 255, 180, 245, 49, 41, 3, 223, 122, 210, 203, 213,
    55, 108, 251, 65, 181, 168, 25 };

static uint8_t g_p384t1PubKeyCompressedBlobData[] = { 48, 74, 48, 20, 6, 7, 42, 134, 72, 206, 61, 2, 1, 6, 9, 43, 36,
    3, 3, 2, 8, 1, 1, 12, 3, 50, 0, 3, 64, 192, 12, 47, 160, 35, 23, 244, 163, 108, 172, 235, 185, 100, 0, 180, 112,
    85, 105, 29, 120, 105, 164, 148, 59, 168, 183, 168, 142, 141, 14, 121, 240, 132, 168, 4, 208, 142, 24, 226, 75,
    169, 249, 46, 63, 61, 129, 154 };

static uint8_t g_p512r1PubKeyCompressedBlobData[] = { 48, 90, 48, 20, 6, 7, 42, 134, 72, 206, 61, 2, 1, 6, 9, 43, 36,
    3, 3, 2, 8, 1, 1, 13, 3, 66, 0, 2, 18, 25, 192, 69, 115, 54, 110, 174, 51, 48, 253, 129, 31, 118, 237, 38, 1, 174,
    8, 111, 74, 249, 149, 154, 119, 114, 59, 51, 160, 206, 70, 199, 202, 42, 98, 245, 170, 251, 154, 22, 243, 137,
    182, 239, 219, 166, 28, 202, 183, 229, 2, 83, 16, 244, 211, 100, 30, 179, 251, 17, 52, 117, 55, 70 };

static uint8_t g_p512t1PubKeyCompressedBlobData[] = { 48, 90, 48, 20, 6, 7, 42, 134, 72, 206, 61, 2, 1, 6, 9, 43,
    36, 3, 3, 2, 8, 1, 1, 14, 3, 66, 0, 3, 119, 56, 81, 46, 40, 173, 156, 49, 235, 26, 193, 122, 32, 201, 88, 18, 90,
    55, 144, 84, 125, 90, 106, 169, 66, 124, 90, 44, 145, 100, 224, 192, 22, 241, 38, 185, 93, 163, 146, 221, 126,
    222, 57, 95, 136, 139, 231, 85, 250, 133, 140, 81, 138, 66, 148, 253, 192, 217, 210, 33, 157, 60, 5, 113 };

static HcfBlob g_secp224r1PubKeyCompressedBlob = {
    .data = g_secp224r1PubKeyCompressedBlobData,
    .len = SECP224R1_PUBKEY_COMPRESSED_SIZE
};

static HcfBlob g_prime256v1PubKeyCompressedBlob = {
    .data = g_prime256v1PubKeyCompressedBlobData,
    .len = PRIME256V1_PUBKEY_COMPRESSED_SIZE
};

static HcfBlob g_secp384r1PubKeyCompressedBlob = {
    .data = g_secp384r1PubKeyCompressedBlobData,
    .len = SECP384R1_PUBKEY_COMPRESSED_SIZE
};

static HcfBlob g_secp521r1PubKeyCompressedBlob = {
    .data = g_secp521r1PubKeyCompressedBlobData,
    .len = SECP521R1_PUBKEY_COMPRESSED_SIZE
};

static HcfBlob g_p160r1PubKeyCompressedBlob = {
    .data = g_p160r1PubKeyCompressedBlobData,
    .len = P160R1_PUBKEY_COMPRESSED_SIZE
};

static HcfBlob g_p160t1PubKeyCompressedBlob = {
    .data = g_p160t1PubKeyCompressedBlobData,
    .len = P160T1_PUBKEY_COMPRESSED_SIZE
};

static HcfBlob g_p192r1PubKeyCompressedBlob = {
    .data = g_p192r1PubKeyCompressedBlobData,
    .len = P192R1_PUBKEY_COMPRESSED_SIZE
};

static HcfBlob g_p192t1PubKeyCompressedBlob = {
    .data = g_p192t1PubKeyCompressedBlobData,
    .len = P192T1_PUBKEY_COMPRESSED_SIZE
};

static HcfBlob g_p224r1PubKeyCompressedBlob = {
    .data = g_p224r1PubKeyCompressedBlobData,
    .len = P224R1_PUBKEY_COMPRESSED_SIZE
};

static HcfBlob g_p224t1PubKeyCompressedBlob = {
    .data = g_p224t1PubKeyCompressedBlobData,
    .len = P224T1_PUBKEY_COMPRESSED_SIZE
};

static HcfBlob g_p256r1PubKeyCompressedBlob = {
    .data = g_p256r1PubKeyCompressedBlobData,
    .len = P256R1_PUBKEY_COMPRESSED_SIZE
};

static HcfBlob g_p256t1PubKeyCompressedBlob = {
    .data = g_p256t1PubKeyCompressedBlobData,
    .len = P256T1_PUBKEY_COMPRESSED_SIZE
};

static HcfBlob g_p320r1PubKeyCompressedBlob = {
    .data = g_p320r1PubKeyCompressedBlobData,
    .len = P320R1_PUBKEY_COMPRESSED_SIZE
};

static HcfBlob g_p320t1PubKeyCompressedBlob = {
    .data = g_p320t1PubKeyCompressedBlobData,
    .len = P320T1_PUBKEY_COMPRESSED_SIZE
};

static HcfBlob g_p384r1PubKeyCompressedBlob = {
    .data = g_p384r1PubKeyCompressedBlobData,
    .len = P384R1_PUBKEY_COMPRESSED_SIZE
};

static HcfBlob g_p384t1PubKeyCompressedBlob = {
    .data = g_p384t1PubKeyCompressedBlobData,
    .len = P384T1_PUBKEY_COMPRESSED_SIZE
};

static HcfBlob g_p512r1PubKeyCompressedBlob = {
    .data = g_p512r1PubKeyCompressedBlobData,
    .len = P512R1_PUBKEY_COMPRESSED_SIZE
};

static HcfBlob g_p512t1PubKeyCompressedBlob = {
    .data = g_p512t1PubKeyCompressedBlobData,
    .len = P512T1_PUBKEY_COMPRESSED_SIZE
};

typedef struct {
    const char *algoName;
    HcfBlob *pubKeyUncompressedBlob;
    HcfBlob *pubKeyCompressedBlob;
} PubKeyData;

static const PubKeyData PUBKEY_DATA_MAP[] = {
    { "ECC224", &g_secp224r1PubKeyUncompressedBlob, &g_secp224r1PubKeyCompressedBlob },
    { "ECC256", &g_prime256v1PubKeyUncompressedBlob, &g_prime256v1PubKeyCompressedBlob },
    { "ECC384", &g_secp384r1PubKeyUncompressedBlob, &g_secp384r1PubKeyCompressedBlob },
    { "ECC521", &g_secp521r1PubKeyUncompressedBlob, &g_secp521r1PubKeyCompressedBlob },
    { "ECC_BrainPoolP160r1", &g_p160r1PubKeyUncompressedBlob, &g_p160r1PubKeyCompressedBlob },
    { "ECC_BrainPoolP160t1", &g_p160t1PubKeyUncompressedBlob, &g_p160t1PubKeyCompressedBlob },
    { "ECC_BrainPoolP192r1", &g_p192r1PubKeyUncompressedBlob, &g_p192r1PubKeyCompressedBlob },
    { "ECC_BrainPoolP192t1", &g_p192t1PubKeyUncompressedBlob, &g_p192t1PubKeyCompressedBlob },
    { "ECC_BrainPoolP224r1", &g_p224r1PubKeyUncompressedBlob, &g_p224r1PubKeyCompressedBlob },
    { "ECC_BrainPoolP224t1", &g_p224t1PubKeyUncompressedBlob, &g_p224t1PubKeyCompressedBlob },
    { "ECC_BrainPoolP256r1", &g_p256r1PubKeyUncompressedBlob, &g_p256r1PubKeyCompressedBlob },
    { "ECC_BrainPoolP256t1", &g_p256t1PubKeyUncompressedBlob, &g_p256t1PubKeyCompressedBlob },
    { "ECC_BrainPoolP320r1", &g_p320r1PubKeyUncompressedBlob, &g_p320r1PubKeyCompressedBlob },
    { "ECC_BrainPoolP320t1", &g_p320t1PubKeyUncompressedBlob, &g_p320t1PubKeyCompressedBlob },
    { "ECC_BrainPoolP384r1", &g_p384r1PubKeyUncompressedBlob, &g_p384r1PubKeyCompressedBlob },
    { "ECC_BrainPoolP384t1", &g_p384t1PubKeyUncompressedBlob, &g_p384t1PubKeyCompressedBlob },
    { "ECC_BrainPoolP512r1", &g_p512r1PubKeyUncompressedBlob, &g_p512r1PubKeyCompressedBlob },
    { "ECC_BrainPoolP512t1", &g_p512t1PubKeyUncompressedBlob, &g_p512t1PubKeyCompressedBlob }
};

static HcfResult CompareBlobEqual(const HcfBlob *returnBlob, const HcfBlob *dataBlob)
{
    if (returnBlob->len != dataBlob->len) {
        return HCF_INVALID_PARAMS;
    }
    for (size_t i = 0; i < returnBlob->len; ++i) {
        if (returnBlob->data[i] != dataBlob->data[i]) {
            return HCF_INVALID_PARAMS;
        }
    }
    return HCF_SUCCESS;
}

static const char *g_inputMessageOne = "This is Sign test plan1";
static const char *g_inputMessageTwo = "This is Sign test plan2";

static HcfBlob g_inputOne = {
    .data = (uint8_t *)g_inputMessageOne,
    .len = 24
};

static HcfBlob g_inputTwo = {
    .data = (uint8_t *)g_inputMessageTwo,
    .len = 24
};

// SM2_256 point data
constexpr size_t SM2_POINT_UNCOMPRESSED_SIZE = 65;
constexpr size_t SM2_POINT_COMPRESSED_SIZE = 33;

static uint8_t g_sm2PointUncompressedBlobData[] = { 4, 232, 131, 204, 172, 46, 67, 127, 51, 64, 4, 236, 190, 110, 155,
    221, 220, 226, 224, 249, 236, 223, 146, 39, 255, 109, 226, 6, 209, 45, 202, 86, 181, 160, 40, 124, 221, 226, 118,
    123, 183, 204, 45, 101, 225, 70, 63, 119, 206, 144, 7, 150, 144, 217, 99, 86, 72, 5, 201, 78, 229,
    209, 108, 112, 143 };

static HcfBlob g_sm2PointUncompressedBlob = {
    .data = g_sm2PointUncompressedBlobData,
    .len = SM2_POINT_UNCOMPRESSED_SIZE
};

static uint8_t g_sm2PointCompressedBlobData[] = { 3, 232, 131, 204, 172, 46, 67, 127, 51, 64, 4, 236, 190, 110, 155,
    221, 220, 226, 224, 249, 236, 223, 146, 39, 255, 109, 226, 6, 209, 45, 202, 86, 181 };

static HcfBlob g_sm2PointCompressedBlob = {
    .data = g_sm2PointCompressedBlobData,
    .len = SM2_POINT_COMPRESSED_SIZE
};

// ECC_BrainPoolP256r1 public and private key data
constexpr size_t P256R1_PUBKEY_DATA_SIZE = 92;
constexpr size_t P256R1_PRIKEY_DATA_SIZE = 52;
constexpr size_t P256R1_POINT_DATA_SIZE = 65;

static uint8_t g_p256r1PubKeyBlobData[] = { 48, 90, 48, 20, 6, 7, 42, 134, 72, 206, 61, 2, 1, 6, 9, 43, 36, 3, 3, 2,
    8, 1, 1, 7, 3, 66, 0, 4, 143, 39, 57, 249, 145, 50, 63, 222, 35, 70, 178, 121, 202, 154, 21, 146, 129, 75, 76, 63,
    8, 195, 157, 111, 40, 217, 215, 148, 120, 224, 205, 82, 83, 92, 185, 21, 211, 184, 5, 19, 114, 33, 86, 85, 228,
    123, 242, 206, 200, 98, 178, 184, 130, 35, 232, 45, 5, 202, 189, 11, 46, 163, 156, 152 };

static uint8_t g_p256r1PriKeyBlobData[] = { 48, 50, 2, 1, 1, 4, 32, 165, 118, 226, 8, 158, 142, 142, 244, 62, 181,
    245, 172, 27, 114, 153, 198, 201, 164, 46, 69, 119, 172, 231, 66, 110, 83, 17, 161, 225, 119, 127, 126, 160, 11,
    6, 9, 43, 36, 3, 3, 2, 8, 1, 1, 7 };

// Modify the first parameter of the x coordinate
static uint8_t g_p256r1ModifyPubKeyBlobData[] = { 48, 90, 48, 20, 6, 7, 42, 134, 72, 206, 61, 2, 1, 6, 9, 43, 36, 3,
    3, 2, 8, 1, 1, 7, 3, 66, 0, 4, 3, 39, 57, 249, 145, 50, 63, 222, 35, 70, 178, 121, 202, 154, 21, 146, 129, 75,
    76, 63, 8, 195, 157, 111, 40, 217, 215, 148, 120, 224, 205, 82, 83, 92, 185, 21, 211, 184, 5, 19, 114, 33, 86,
    85, 228, 123, 242, 206, 200, 98, 178, 184, 130, 35, 232, 45, 5, 202, 189, 11, 46, 163, 156, 152 };

static uint8_t g_p256r1ModifyPointBlobData[] = { 4, 3, 39, 57, 249, 145, 50, 63, 222, 35, 70, 178, 121, 202, 154,
    21, 146, 129, 75, 76, 63, 8, 195, 157, 111, 40, 217, 215, 148, 120, 224, 205, 82, 83, 92, 185, 21, 211, 184, 5,
    19, 114, 33, 86, 85, 228, 123, 242, 206, 200, 98, 178, 184, 130, 35, 232, 45, 5, 202, 189, 11, 46, 163, 156, 152 };

static HcfBlob g_p256r1PubKeyBlob = {
    .data = g_p256r1PubKeyBlobData,
    .len = P256R1_PUBKEY_DATA_SIZE
};

static HcfBlob g_p256r1PriKeyBlob = {
    .data = g_p256r1PriKeyBlobData,
    .len = P256R1_PRIKEY_DATA_SIZE
};

static HcfBlob g_p256r1ModifyPubKeyBlob = {
    .data = g_p256r1ModifyPubKeyBlobData,
    .len = P256R1_PUBKEY_DATA_SIZE
};

static HcfBlob g_p256r1ModifyPointBlob = {
    .data = g_p256r1ModifyPointBlobData,
    .len = P256R1_POINT_DATA_SIZE
};

HWTEST_F(CryptoEccEcdhPubTest, CryptoEccEcdhPubTest001, TestSize.Level0)
{
    HcfAsyKeyGenerator *generator = nullptr;
    HcfKeyPair *keyPair = nullptr;
    HcfSign *sign = nullptr;
    HcfVerify *verify = nullptr;
    HcfBlob returnBlob = { .data = nullptr, .len = 0 };
    HcfResult ret = HCF_INVALID_PARAMS;

    ret = HcfAsyKeyGeneratorCreate("ECC_BrainPoolP256r1", &generator);
    EXPECT_EQ(ret, HCF_SUCCESS);
    EXPECT_NE(generator, nullptr);

    ret = generator->convertKey(generator, nullptr, &g_p256r1PubKeyBlob, &g_p256r1PriKeyBlob, &keyPair);
    EXPECT_EQ(ret, HCF_SUCCESS);
    EXPECT_NE(keyPair, nullptr);

    ret = HcfSignCreate("ECC_BrainPoolP256r1|SHA256", &sign);
    EXPECT_EQ(ret, HCF_SUCCESS);
    EXPECT_NE(sign, nullptr);

    ret = sign->init(sign, nullptr, keyPair->priKey);
    EXPECT_EQ(ret, HCF_SUCCESS);

    ret = sign->update(sign, &g_inputOne);
    EXPECT_EQ(ret, HCF_SUCCESS);

    ret = sign->sign(sign, &g_inputTwo, &returnBlob);
    EXPECT_EQ(ret, HCF_SUCCESS);
    EXPECT_NE(returnBlob.len, 0);

    ret = HcfVerifyCreate("ECC_BrainPoolP256r1|SHA256", &verify);
    EXPECT_EQ(ret, HCF_SUCCESS);
    EXPECT_NE(verify, nullptr);

    ret = verify->init(verify, nullptr, keyPair->pubKey);
    EXPECT_EQ(ret, HCF_SUCCESS);

    ret = verify->update(verify, &g_inputOne);
    bool flag = verify->verify(verify, &g_inputTwo, &returnBlob);
    EXPECT_EQ(flag, true);

    HcfObjDestroy(keyPair);
    HcfObjDestroy(generator);
    HcfObjDestroy(sign);
    HcfObjDestroy(verify);
    HcfBlobDataFree(&returnBlob);
}

HWTEST_F(CryptoEccEcdhPubTest, CryptoEccEcdhPubTest002, TestSize.Level0)
{
    HcfAsyKeyGenerator *generator = nullptr;
    HcfKeyAgreement *keyAgreement = nullptr;
    HcfKeyPair *keyPair = nullptr;
    HcfKeyPair *outKeyPair = nullptr;
    HcfBlob returnBlob = { .data = nullptr, .len = 0 };
    HcfBlob outBlob = { .data = nullptr, .len = 0 };
    HcfResult ret = HCF_INVALID_PARAMS;
    ret = HcfAsyKeyGeneratorCreate("ECC_BrainPoolP256r1", &generator);
    EXPECT_EQ(ret, HCF_SUCCESS);
    EXPECT_NE(generator, nullptr);

    ret = generator->convertKey(generator, nullptr, &g_p256r1PubKeyBlob, &g_p256r1PriKeyBlob, &keyPair);
    EXPECT_EQ(ret, HCF_SUCCESS);
    EXPECT_NE(keyPair, nullptr);

    ret = generator->generateKeyPair(generator, nullptr, &outKeyPair);
    EXPECT_EQ(ret, HCF_SUCCESS);
    EXPECT_NE(outKeyPair, nullptr);

    ret = HcfKeyAgreementCreate("ECC_BrainPoolP256r1", &keyAgreement);
    EXPECT_EQ(ret, HCF_SUCCESS);
    EXPECT_NE(keyAgreement, nullptr);

    ret = keyAgreement->generateSecret(keyAgreement, outKeyPair->priKey, keyPair->pubKey, &returnBlob);
    EXPECT_EQ(ret, HCF_SUCCESS);
    EXPECT_NE(returnBlob.len, 0);

    ret = keyAgreement->generateSecret(keyAgreement, keyPair->priKey, outKeyPair->pubKey, &outBlob);
    EXPECT_EQ(ret, HCF_SUCCESS);
    EXPECT_NE(outBlob.len, 0);

    ret = CompareBlobEqual(&returnBlob, &outBlob);
    EXPECT_EQ(ret, HCF_SUCCESS);

    HcfObjDestroy(keyPair);
    HcfObjDestroy(outKeyPair);
    HcfObjDestroy(generator);
    HcfBlobDataFree(&returnBlob);
    HcfBlobDataFree(&outBlob);
    HcfObjDestroy(keyAgreement);
}

HWTEST_F(CryptoEccEcdhPubTest, CryptoEccEcdhPubTest003, TestSize.Level0)
{
    HcfPoint returnPoint = { .x = { .data = nullptr, .len = 0 }, .y = { .data = nullptr, .len = 0 } };
    HcfBlob returnBlob = { .data = nullptr, .len = 0 };
    HcfResult ret = HCF_INVALID_PARAMS;
    ret = HcfConvertPoint("NID_sm2", &g_sm2PointUncompressedBlob, &returnPoint);
    EXPECT_EQ(ret, HCF_SUCCESS);
    EXPECT_NE(returnPoint.x.len, 0);

    ret = HcfGetEncodedPoint("NID_sm2", &returnPoint, g_pointCompressedFormat, &returnBlob);
    EXPECT_EQ(ret, HCF_SUCCESS);
    EXPECT_NE(returnBlob.len, 0);

    ret = CompareBlobEqual(&returnBlob, &g_sm2PointCompressedBlob);
    EXPECT_EQ(ret, HCF_SUCCESS);

    FreeEcPointMem(&returnPoint);
    HcfBlobDataFree(&returnBlob);
}

HWTEST_F(CryptoEccEcdhPubTest, CryptoEccEcdhPubTest004, TestSize.Level0)
{
    HcfPoint returnPoint = { .x = { .data = nullptr, .len = 0 }, .y = { .data = nullptr, .len = 0 } };
    HcfBlob returnBlob = { .data = nullptr, .len = 0 };
    HcfResult ret = HCF_INVALID_PARAMS;
    ret = HcfConvertPoint("NID_sm2", &g_sm2PointCompressedBlob, &returnPoint);
    EXPECT_EQ(ret, HCF_SUCCESS);
    EXPECT_NE(returnPoint.x.len, 0);

    ret = HcfGetEncodedPoint("NID_sm2", &returnPoint, g_pointUnCompressedFormat, &returnBlob);
    EXPECT_EQ(ret, HCF_SUCCESS);
    EXPECT_NE(returnBlob.len, 0);

    ret = CompareBlobEqual(&returnBlob, &g_sm2PointUncompressedBlob);
    EXPECT_EQ(ret, HCF_SUCCESS);

    FreeEcPointMem(&returnPoint);
    HcfBlobDataFree(&returnBlob);
}

HWTEST_F(CryptoEccEcdhPubTest, CryptoEccEcdhPubTest005, TestSize.Level0)
{
    HcfPoint returnPoint = { .x = { .data = nullptr, .len = 0 }, .y = { .data = nullptr, .len = 0 } };
    HcfBlob returnBlob = { .data = nullptr, .len = 0 };
    HcfResult ret = HCF_INVALID_PARAMS;
    for (uint32_t i = 0; i < sizeof(POINT_DATA_MAP) / sizeof(POINT_DATA_MAP[0]); i++) {
        ret = HcfConvertPoint(POINT_DATA_MAP[i].curveName, POINT_DATA_MAP[i].pointUncompressedBlob, &returnPoint);
        EXPECT_EQ(ret, HCF_SUCCESS);
        EXPECT_NE(returnPoint.x.len, 0);

        ret = HcfGetEncodedPoint(POINT_DATA_MAP[i].curveName, &returnPoint, g_pointCompressedFormat, &returnBlob);
        EXPECT_EQ(ret, HCF_SUCCESS);
        EXPECT_NE(returnBlob.len, 0);

        ret = CompareBlobEqual(&returnBlob, POINT_DATA_MAP[i].pointCompressedBlob);
        EXPECT_EQ(ret, HCF_SUCCESS);

        FreeEcPointMem(&returnPoint);
        HcfBlobDataFree(&returnBlob);
    }
}

HWTEST_F(CryptoEccEcdhPubTest, CryptoEccEcdhPubTest006, TestSize.Level0)
{
    HcfPoint returnPoint = { .x = { .data = nullptr, .len = 0 }, .y = { .data = nullptr, .len = 0 } };
    HcfBlob returnBlob = { .data = nullptr, .len = 0 };
    HcfResult ret = HCF_INVALID_PARAMS;
    for (uint32_t i = 0; i < sizeof(POINT_DATA_MAP) / sizeof(POINT_DATA_MAP[0]); i++) {
        ret = HcfConvertPoint(POINT_DATA_MAP[i].curveName, POINT_DATA_MAP[i].pointUncompressedBlob, &returnPoint);
        EXPECT_EQ(ret, HCF_SUCCESS);
        EXPECT_NE(returnPoint.x.len, 0);

        ret = HcfGetEncodedPoint(POINT_DATA_MAP[i].curveName, &returnPoint, g_pointUnCompressedFormat, &returnBlob);
        EXPECT_EQ(ret, HCF_SUCCESS);
        EXPECT_NE(returnBlob.len, 0);

        ret = CompareBlobEqual(&returnBlob, POINT_DATA_MAP[i].pointUncompressedBlob);
        EXPECT_EQ(ret, HCF_SUCCESS);

        FreeEcPointMem(&returnPoint);
        HcfBlobDataFree(&returnBlob);
    }
}

HWTEST_F(CryptoEccEcdhPubTest, CryptoEccEcdhPubTest007, TestSize.Level0)
{
    HcfPoint returnPoint = { .x = { .data = nullptr, .len = 0 }, .y = { .data = nullptr, .len = 0 } };
    HcfBlob returnBlob = { .data = nullptr, .len = 0 };
    HcfResult ret = HCF_INVALID_PARAMS;
    for (uint32_t i = 0; i < sizeof(POINT_DATA_MAP) / sizeof(POINT_DATA_MAP[0]); i++) {
        ret = HcfConvertPoint(POINT_DATA_MAP[i].curveName, POINT_DATA_MAP[i].pointCompressedBlob, &returnPoint);
        EXPECT_EQ(ret, HCF_SUCCESS);
        EXPECT_NE(returnPoint.x.len, 0);

        ret = HcfGetEncodedPoint(POINT_DATA_MAP[i].curveName, &returnPoint, g_pointCompressedFormat, &returnBlob);
        EXPECT_EQ(ret, HCF_SUCCESS);
        EXPECT_NE(returnBlob.len, 0);

        ret = CompareBlobEqual(&returnBlob, POINT_DATA_MAP[i].pointCompressedBlob);
        EXPECT_EQ(ret, HCF_SUCCESS);

        FreeEcPointMem(&returnPoint);
        HcfBlobDataFree(&returnBlob);
    }
}

HWTEST_F(CryptoEccEcdhPubTest, CryptoEccEcdhPubTest008, TestSize.Level0)
{
    HcfPoint returnPoint = { .x = { .data = nullptr, .len = 0 }, .y = { .data = nullptr, .len = 0 } };
    HcfBlob returnBlob = { .data = nullptr, .len = 0 };
    HcfResult ret = HCF_INVALID_PARAMS;
    for (uint32_t i = 0; i < sizeof(POINT_DATA_MAP) / sizeof(POINT_DATA_MAP[0]); i++) {
        ret = HcfConvertPoint(POINT_DATA_MAP[i].curveName, POINT_DATA_MAP[i].pointCompressedBlob, &returnPoint);
        EXPECT_EQ(ret, HCF_SUCCESS);
        EXPECT_NE(returnPoint.x.len, 0);

        ret = HcfGetEncodedPoint(POINT_DATA_MAP[i].curveName, &returnPoint, g_pointUnCompressedFormat, &returnBlob);
        EXPECT_EQ(ret, HCF_SUCCESS);
        EXPECT_NE(returnBlob.len, 0);

        ret = CompareBlobEqual(&returnBlob, POINT_DATA_MAP[i].pointUncompressedBlob);
        EXPECT_EQ(ret, HCF_SUCCESS);

        FreeEcPointMem(&returnPoint);
        HcfBlobDataFree(&returnBlob);
    }
}

HWTEST_F(CryptoEccEcdhPubTest, CryptoEccEcdhPubTest009, TestSize.Level0)
{
    HcfAsyKeyGenerator *generator = nullptr;
    HcfKeyPair *keyPair = nullptr;
    HcfPoint returnPoint = { .x = { .data = nullptr, .len = 0 }, .y = { .data = nullptr, .len = 0 } };
    HcfPoint outPoint = { .x = { .data = nullptr, .len = 0 }, .y = { .data = nullptr, .len = 0 } };
    HcfBlob returnBlob = { .data = nullptr, .len = 0 };
    AsyKeySpecItem itemPkX = ECC_PK_X_BN;
    AsyKeySpecItem itemPkY = ECC_PK_Y_BN;
    HcfResult ret = HCF_INVALID_PARAMS;
    for (uint32_t i = 0; i < sizeof(PUBKEY_DATA_MAP) / sizeof(PUBKEY_DATA_MAP[0]); i++) {
        ret = HcfAsyKeyGeneratorCreate(PUBKEY_DATA_MAP[i].algoName, &generator);
        EXPECT_EQ(ret, HCF_SUCCESS);
        EXPECT_NE(generator, nullptr);

        ret = generator->generateKeyPair(generator, nullptr, &keyPair);
        EXPECT_EQ(ret, HCF_SUCCESS);
        EXPECT_NE(keyPair, nullptr);

        ret = keyPair->pubKey->getAsyKeySpecBigInteger(keyPair->pubKey, itemPkX, &(returnPoint.x));
        EXPECT_EQ(ret, HCF_SUCCESS);
        EXPECT_NE(returnPoint.x.len, 0);

        ret = keyPair->pubKey->getAsyKeySpecBigInteger(keyPair->pubKey, itemPkY, &(returnPoint.y));
        EXPECT_EQ(ret, HCF_SUCCESS);
        EXPECT_NE(returnPoint.y.len, 0);

        ret = HcfGetEncodedPoint(POINT_DATA_MAP[i].curveName, &returnPoint, g_pointUnCompressedFormat, &returnBlob);
        EXPECT_EQ(ret, HCF_SUCCESS);
        EXPECT_NE(returnBlob.len, 0);

        ret = HcfConvertPoint(POINT_DATA_MAP[i].curveName, &returnBlob, &outPoint);
        EXPECT_EQ(ret, HCF_SUCCESS);
        EXPECT_NE(outPoint.x.len, 0);

        HcfObjDestroy(keyPair);
        HcfObjDestroy(generator);
        FreeEcPointMem(&returnPoint);
        FreeEcPointMem(&outPoint);
        HcfBlobDataFree(&returnBlob);
    }
}

HWTEST_F(CryptoEccEcdhPubTest, CryptoEccEcdhPubTest010, TestSize.Level0)
{
    HcfAsyKeyGenerator *generator = nullptr;
    HcfKeyPair *keyPair = nullptr;
    HcfPoint returnPoint = { .x = { .data = nullptr, .len = 0 }, .y = { .data = nullptr, .len = 0 } };
    HcfPoint outPoint = { .x = { .data = nullptr, .len = 0 }, .y = { .data = nullptr, .len = 0 } };
    HcfBlob returnBlob = { .data = nullptr, .len = 0 };
    AsyKeySpecItem itemPkX = ECC_PK_X_BN;
    AsyKeySpecItem itemPkY = ECC_PK_Y_BN;
    HcfResult ret = HCF_INVALID_PARAMS;
    for (uint32_t i = 0; i < sizeof(PUBKEY_DATA_MAP) / sizeof(PUBKEY_DATA_MAP[0]); i++) {
        ret = HcfAsyKeyGeneratorCreate(PUBKEY_DATA_MAP[i].algoName, &generator);
        EXPECT_EQ(ret, HCF_SUCCESS);
        EXPECT_NE(generator, nullptr);

        ret = generator->generateKeyPair(generator, nullptr, &keyPair);
        EXPECT_EQ(ret, HCF_SUCCESS);
        EXPECT_NE(keyPair, nullptr);

        ret = keyPair->pubKey->getAsyKeySpecBigInteger(keyPair->pubKey, itemPkX, &(returnPoint.x));
        EXPECT_EQ(ret, HCF_SUCCESS);
        EXPECT_NE(returnPoint.x.len, 0);

        ret = keyPair->pubKey->getAsyKeySpecBigInteger(keyPair->pubKey, itemPkY, &(returnPoint.y));
        EXPECT_EQ(ret, HCF_SUCCESS);
        EXPECT_NE(returnPoint.y.len, 0);

        ret = HcfGetEncodedPoint(POINT_DATA_MAP[i].curveName, &returnPoint, g_pointCompressedFormat, &returnBlob);
        EXPECT_EQ(ret, HCF_SUCCESS);
        EXPECT_NE(returnBlob.len, 0);

        ret = HcfConvertPoint(POINT_DATA_MAP[i].curveName, &returnBlob, &outPoint);
        EXPECT_EQ(ret, HCF_SUCCESS);
        EXPECT_NE(outPoint.x.len, 0);

        HcfObjDestroy(keyPair);
        HcfObjDestroy(generator);
        FreeEcPointMem(&returnPoint);
        FreeEcPointMem(&outPoint);
        HcfBlobDataFree(&returnBlob);
    }
}

HWTEST_F(CryptoEccEcdhPubTest, CryptoEccEcdhPubTest011, TestSize.Level0)
{
    HcfAsyKeyGenerator *generator = nullptr;
    HcfKeyPair *keyPair = nullptr;
    HcfKeyPair *outKeyPair = nullptr;
    HcfBlob returnBlob = { .data = nullptr, .len = 0 };
    HcfResult ret = HCF_INVALID_PARAMS;
    for (uint32_t i = 0; i < sizeof(PUBKEY_DATA_MAP) / sizeof(PUBKEY_DATA_MAP[0]); i++) {
        ret = HcfAsyKeyGeneratorCreate(PUBKEY_DATA_MAP[i].algoName, &generator);
        EXPECT_EQ(ret, HCF_SUCCESS);
        EXPECT_NE(generator, nullptr);

        ret = generator->generateKeyPair(generator, nullptr, &keyPair);
        EXPECT_EQ(ret, HCF_SUCCESS);
        EXPECT_NE(keyPair, nullptr);

        ret = keyPair->pubKey->getEncodedDer(keyPair->pubKey, g_pubKeyUnCompressedFormat, &returnBlob);
        EXPECT_EQ(ret, HCF_SUCCESS);
        EXPECT_NE(returnBlob.len, 0);

        ret = generator->convertKey(generator, nullptr, &returnBlob, nullptr, &outKeyPair);
        EXPECT_EQ(ret, HCF_SUCCESS);
        EXPECT_NE(outKeyPair, nullptr);

        HcfObjDestroy(outKeyPair);
        HcfObjDestroy(keyPair);
        HcfObjDestroy(generator);
        HcfBlobDataFree(&returnBlob);
    }
}

HWTEST_F(CryptoEccEcdhPubTest, CryptoEccEcdhPubTest012, TestSize.Level0)
{
    HcfAsyKeyGenerator *generator = nullptr;
    HcfKeyPair *keyPair = nullptr;
    HcfKeyPair *outKeyPair = nullptr;
    HcfBlob returnBlob = { .data = nullptr, .len = 0 };
    HcfResult ret = HCF_INVALID_PARAMS;
    for (uint32_t i = 0; i < sizeof(PUBKEY_DATA_MAP) / sizeof(PUBKEY_DATA_MAP[0]); i++) {
        ret = HcfAsyKeyGeneratorCreate(PUBKEY_DATA_MAP[i].algoName, &generator);
        EXPECT_EQ(ret, HCF_SUCCESS);
        EXPECT_NE(generator, nullptr);

        ret = generator->generateKeyPair(generator, nullptr, &keyPair);
        EXPECT_EQ(ret, HCF_SUCCESS);
        EXPECT_NE(keyPair, nullptr);

        ret = keyPair->pubKey->getEncodedDer(keyPair->pubKey, g_pubKeyCompressedFormat, &returnBlob);
        EXPECT_EQ(ret, HCF_SUCCESS);
        EXPECT_NE(returnBlob.len, 0);

        ret = generator->convertKey(generator, nullptr, &returnBlob, nullptr, &outKeyPair);
        EXPECT_EQ(ret, HCF_SUCCESS);
        EXPECT_NE(outKeyPair, nullptr);

        HcfObjDestroy(outKeyPair);
        HcfObjDestroy(keyPair);
        HcfObjDestroy(generator);
        HcfBlobDataFree(&returnBlob);
    }
}

HWTEST_F(CryptoEccEcdhPubTest, CryptoEccEcdhPubTest013, TestSize.Level0)
{
    HcfAsyKeyGenerator *generator = nullptr;
    HcfKeyPair *keyPair = nullptr;
    HcfBlob returnBlob = { .data = nullptr, .len = 0 };
    HcfResult ret = HCF_INVALID_PARAMS;
    for (uint32_t i = 0; i < sizeof(PUBKEY_DATA_MAP) / sizeof(PUBKEY_DATA_MAP[0]); i++) {
        ret = HcfAsyKeyGeneratorCreate(PUBKEY_DATA_MAP[i].algoName, &generator);
        EXPECT_EQ(ret, HCF_SUCCESS);
        EXPECT_NE(generator, nullptr);

        ret = generator->convertKey(generator, nullptr, PUBKEY_DATA_MAP[i].pubKeyUncompressedBlob, nullptr, &keyPair);
        EXPECT_EQ(ret, HCF_SUCCESS);
        EXPECT_NE(keyPair, nullptr);

        ret = keyPair->pubKey->getEncodedDer(keyPair->pubKey, g_pubKeyCompressedFormat, &returnBlob);
        EXPECT_EQ(ret, HCF_SUCCESS);
        EXPECT_NE(returnBlob.len, 0);

        ret = CompareBlobEqual(&returnBlob, PUBKEY_DATA_MAP[i].pubKeyCompressedBlob);
        EXPECT_EQ(ret, HCF_SUCCESS);

        HcfObjDestroy(keyPair);
        HcfObjDestroy(generator);
        HcfBlobDataFree(&returnBlob);
    }
}

HWTEST_F(CryptoEccEcdhPubTest, CryptoEccEcdhPubTest014, TestSize.Level0)
{
    HcfAsyKeyGenerator *generator = nullptr;
    HcfKeyPair *keyPair = nullptr;
    HcfBlob returnBlob = { .data = nullptr, .len = 0 };
    HcfResult ret = HCF_INVALID_PARAMS;
    for (uint32_t i = 0; i < sizeof(PUBKEY_DATA_MAP) / sizeof(PUBKEY_DATA_MAP[0]); i++) {
        ret = HcfAsyKeyGeneratorCreate(PUBKEY_DATA_MAP[i].algoName, &generator);
        EXPECT_EQ(ret, HCF_SUCCESS);
        EXPECT_NE(generator, nullptr);

        ret = generator->convertKey(generator, nullptr, PUBKEY_DATA_MAP[i].pubKeyUncompressedBlob, nullptr, &keyPair);
        EXPECT_EQ(ret, HCF_SUCCESS);
        EXPECT_NE(keyPair, nullptr);

        ret = keyPair->pubKey->getEncodedDer(keyPair->pubKey, g_pubKeyUnCompressedFormat, &returnBlob);
        EXPECT_EQ(ret, HCF_SUCCESS);
        EXPECT_NE(returnBlob.len, 0);

        ret = CompareBlobEqual(&returnBlob, PUBKEY_DATA_MAP[i].pubKeyUncompressedBlob);
        EXPECT_EQ(ret, HCF_SUCCESS);

        HcfObjDestroy(keyPair);
        HcfObjDestroy(generator);
        HcfBlobDataFree(&returnBlob);
    }
}

HWTEST_F(CryptoEccEcdhPubTest, CryptoEccEcdhPubTest015, TestSize.Level0)
{
    HcfAsyKeyGenerator *generator = nullptr;
    HcfKeyPair *keyPair = nullptr;
    HcfBlob returnBlob = { .data = nullptr, .len = 0 };
    HcfResult ret = HCF_INVALID_PARAMS;
    for (uint32_t i = 0; i < sizeof(PUBKEY_DATA_MAP) / sizeof(PUBKEY_DATA_MAP[0]); i++) {
        ret = HcfAsyKeyGeneratorCreate(PUBKEY_DATA_MAP[i].algoName, &generator);
        EXPECT_EQ(ret, HCF_SUCCESS);
        EXPECT_NE(generator, nullptr);

        ret = generator->convertKey(generator, nullptr, PUBKEY_DATA_MAP[i].pubKeyCompressedBlob, nullptr, &keyPair);
        EXPECT_EQ(ret, HCF_SUCCESS);
        EXPECT_NE(keyPair, nullptr);

        ret = keyPair->pubKey->getEncodedDer(keyPair->pubKey, g_pubKeyCompressedFormat, &returnBlob);
        EXPECT_EQ(ret, HCF_SUCCESS);
        EXPECT_NE(returnBlob.len, 0);

        ret = CompareBlobEqual(&returnBlob, PUBKEY_DATA_MAP[i].pubKeyCompressedBlob);
        EXPECT_EQ(ret, HCF_SUCCESS);

        HcfObjDestroy(keyPair);
        HcfObjDestroy(generator);
        HcfBlobDataFree(&returnBlob);
    }
}

HWTEST_F(CryptoEccEcdhPubTest, CryptoEccEcdhPubTest016, TestSize.Level0)
{
    HcfAsyKeyGenerator *generator = nullptr;
    HcfKeyPair *keyPair = nullptr;
    HcfBlob returnBlob = { .data = nullptr, .len = 0 };
    HcfResult ret = HCF_INVALID_PARAMS;
    for (uint32_t i = 0; i < sizeof(PUBKEY_DATA_MAP) / sizeof(PUBKEY_DATA_MAP[0]); i++) {
        ret = HcfAsyKeyGeneratorCreate(PUBKEY_DATA_MAP[i].algoName, &generator);
        EXPECT_EQ(ret, HCF_SUCCESS);
        EXPECT_NE(generator, nullptr);

        ret = generator->convertKey(generator, nullptr, PUBKEY_DATA_MAP[i].pubKeyCompressedBlob, nullptr, &keyPair);
        EXPECT_EQ(ret, HCF_SUCCESS);
        EXPECT_NE(keyPair, nullptr);

        ret = keyPair->pubKey->getEncodedDer(keyPair->pubKey, g_pubKeyUnCompressedFormat, &returnBlob);
        EXPECT_EQ(ret, HCF_SUCCESS);
        EXPECT_NE(returnBlob.len, 0);

        ret = CompareBlobEqual(&returnBlob, PUBKEY_DATA_MAP[i].pubKeyUncompressedBlob);
        EXPECT_EQ(ret, HCF_SUCCESS);

        HcfObjDestroy(keyPair);
        HcfObjDestroy(generator);
        HcfBlobDataFree(&returnBlob);
    }
}

HWTEST_F(CryptoEccEcdhPubTest, CryptoEccEcdhPubTest017, TestSize.Level0)
{
    HcfAsyKeyGenerator *generator = nullptr;
    HcfKeyPair *keyPair = nullptr;
    HcfPoint returnPoint = { .x = { .data = nullptr, .len = 0 }, .y = { .data = nullptr, .len = 0 } };
    HcfBlob returnBlob = { .data = nullptr, .len = 0 };
    AsyKeySpecItem itemPkX = ECC_PK_X_BN;
    AsyKeySpecItem itemPkY = ECC_PK_Y_BN;
    HcfResult ret = HCF_INVALID_PARAMS;
    for (uint32_t i = 0; i < sizeof(PUBKEY_DATA_MAP) / sizeof(PUBKEY_DATA_MAP[0]); i++) {
        ret = HcfAsyKeyGeneratorCreate(PUBKEY_DATA_MAP[i].algoName, &generator);
        EXPECT_EQ(ret, HCF_SUCCESS);
        EXPECT_NE(generator, nullptr);

        ret = generator->convertKey(generator, nullptr, PUBKEY_DATA_MAP[i].pubKeyUncompressedBlob, nullptr, &keyPair);
        EXPECT_EQ(ret, HCF_SUCCESS);
        EXPECT_NE(keyPair, nullptr);

        ret = keyPair->pubKey->getAsyKeySpecBigInteger(keyPair->pubKey, itemPkX, &(returnPoint.x));
        EXPECT_EQ(ret, HCF_SUCCESS);
        EXPECT_NE(returnPoint.x.len, 0);

        ret = keyPair->pubKey->getAsyKeySpecBigInteger(keyPair->pubKey, itemPkY, &(returnPoint.y));
        EXPECT_EQ(ret, HCF_SUCCESS);
        EXPECT_NE(returnPoint.y.len, 0);

        ret = HcfGetEncodedPoint(POINT_DATA_MAP[i].curveName, &returnPoint, g_pointCompressedFormat, &returnBlob);
        EXPECT_EQ(ret, HCF_SUCCESS);
        EXPECT_NE(returnBlob.len, 0);

        ret = CompareBlobEqual(&returnBlob, POINT_DATA_MAP[i].pointCompressedBlob);
        EXPECT_EQ(ret, HCF_SUCCESS);

        HcfObjDestroy(keyPair);
        HcfObjDestroy(generator);
        FreeEcPointMem(&returnPoint);
        HcfBlobDataFree(&returnBlob);
    }
}

HWTEST_F(CryptoEccEcdhPubTest, CryptoEccEcdhPubTest018, TestSize.Level0)
{
    HcfAsyKeyGenerator *generator = nullptr;
    HcfKeyPair *keyPair = nullptr;
    HcfPoint returnPoint = { .x = { .data = nullptr, .len = 0 }, .y = { .data = nullptr, .len = 0 } };
    HcfBlob returnBlob = { .data = nullptr, .len = 0 };
    AsyKeySpecItem itemPkX = ECC_PK_X_BN;
    AsyKeySpecItem itemPkY = ECC_PK_Y_BN;
    HcfResult ret = HCF_INVALID_PARAMS;
    for (uint32_t i = 0; i < sizeof(PUBKEY_DATA_MAP) / sizeof(PUBKEY_DATA_MAP[0]); i++) {
        ret = HcfAsyKeyGeneratorCreate(PUBKEY_DATA_MAP[i].algoName, &generator);
        EXPECT_EQ(ret, HCF_SUCCESS);
        EXPECT_NE(generator, nullptr);

        ret = generator->convertKey(generator, nullptr, PUBKEY_DATA_MAP[i].pubKeyUncompressedBlob, nullptr, &keyPair);
        EXPECT_EQ(ret, HCF_SUCCESS);
        EXPECT_NE(keyPair, nullptr);

        ret = keyPair->pubKey->getAsyKeySpecBigInteger(keyPair->pubKey, itemPkX, &(returnPoint.x));
        EXPECT_EQ(ret, HCF_SUCCESS);
        EXPECT_NE(returnPoint.x.len, 0);

        ret = keyPair->pubKey->getAsyKeySpecBigInteger(keyPair->pubKey, itemPkY, &(returnPoint.y));
        EXPECT_EQ(ret, HCF_SUCCESS);
        EXPECT_NE(returnPoint.y.len, 0);

        ret = HcfGetEncodedPoint(POINT_DATA_MAP[i].curveName, &returnPoint, g_pointUnCompressedFormat, &returnBlob);
        EXPECT_EQ(ret, HCF_SUCCESS);
        EXPECT_NE(returnBlob.len, 0);

        ret = CompareBlobEqual(&returnBlob, POINT_DATA_MAP[i].pointUncompressedBlob);
        EXPECT_EQ(ret, HCF_SUCCESS);

        HcfObjDestroy(keyPair);
        HcfObjDestroy(generator);
        FreeEcPointMem(&returnPoint);
        HcfBlobDataFree(&returnBlob);
    }
}

HWTEST_F(CryptoEccEcdhPubTest, CryptoEccEcdhPubTest019, TestSize.Level0)
{
    HcfAsyKeyGenerator *generator = nullptr;
    HcfKeyPair *keyPair = nullptr;
    HcfPoint returnPoint = { .x = { .data = nullptr, .len = 0 }, .y = { .data = nullptr, .len = 0 } };
    HcfBlob returnBlob = { .data = nullptr, .len = 0 };
    AsyKeySpecItem itemPkX = ECC_PK_X_BN;
    AsyKeySpecItem itemPkY = ECC_PK_Y_BN;
    HcfResult ret = HCF_INVALID_PARAMS;
    for (uint32_t i = 0; i < sizeof(PUBKEY_DATA_MAP) / sizeof(PUBKEY_DATA_MAP[0]); i++) {
        ret = HcfAsyKeyGeneratorCreate(PUBKEY_DATA_MAP[i].algoName, &generator);
        EXPECT_EQ(ret, HCF_SUCCESS);
        EXPECT_NE(generator, nullptr);

        ret = generator->convertKey(generator, nullptr, PUBKEY_DATA_MAP[i].pubKeyCompressedBlob, nullptr, &keyPair);
        EXPECT_EQ(ret, HCF_SUCCESS);
        EXPECT_NE(keyPair, nullptr);

        ret = keyPair->pubKey->getAsyKeySpecBigInteger(keyPair->pubKey, itemPkX, &(returnPoint.x));
        EXPECT_EQ(ret, HCF_SUCCESS);
        EXPECT_NE(returnPoint.x.len, 0);

        ret = keyPair->pubKey->getAsyKeySpecBigInteger(keyPair->pubKey, itemPkY, &(returnPoint.y));
        EXPECT_EQ(ret, HCF_SUCCESS);
        EXPECT_NE(returnPoint.y.len, 0);

        ret = HcfGetEncodedPoint(POINT_DATA_MAP[i].curveName, &returnPoint, g_pointCompressedFormat, &returnBlob);
        EXPECT_EQ(ret, HCF_SUCCESS);
        EXPECT_NE(returnBlob.len, 0);

        ret = CompareBlobEqual(&returnBlob, POINT_DATA_MAP[i].pointCompressedBlob);
        EXPECT_EQ(ret, HCF_SUCCESS);

        HcfObjDestroy(keyPair);
        HcfObjDestroy(generator);
        FreeEcPointMem(&returnPoint);
        HcfBlobDataFree(&returnBlob);
    }
}

HWTEST_F(CryptoEccEcdhPubTest, CryptoEccEcdhPubTest020, TestSize.Level0)
{
    HcfAsyKeyGenerator *generator = nullptr;
    HcfKeyPair *keyPair = nullptr;
    HcfPoint returnPoint = { .x = { .data = nullptr, .len = 0 }, .y = { .data = nullptr, .len = 0 } };
    HcfBlob returnBlob = { .data = nullptr, .len = 0 };
    AsyKeySpecItem itemPkX = ECC_PK_X_BN;
    AsyKeySpecItem itemPkY = ECC_PK_Y_BN;
    HcfResult ret = HCF_INVALID_PARAMS;
    for (uint32_t i = 0; i < sizeof(PUBKEY_DATA_MAP) / sizeof(PUBKEY_DATA_MAP[0]); i++) {
        ret = HcfAsyKeyGeneratorCreate(PUBKEY_DATA_MAP[i].algoName, &generator);
        EXPECT_EQ(ret, HCF_SUCCESS);
        EXPECT_NE(generator, nullptr);

        ret = generator->convertKey(generator, nullptr, PUBKEY_DATA_MAP[i].pubKeyCompressedBlob, nullptr, &keyPair);
        EXPECT_EQ(ret, HCF_SUCCESS);
        EXPECT_NE(keyPair, nullptr);

        ret = keyPair->pubKey->getAsyKeySpecBigInteger(keyPair->pubKey, itemPkX, &(returnPoint.x));
        EXPECT_EQ(ret, HCF_SUCCESS);
        EXPECT_NE(returnPoint.x.len, 0);

        ret = keyPair->pubKey->getAsyKeySpecBigInteger(keyPair->pubKey, itemPkY, &(returnPoint.y));
        EXPECT_EQ(ret, HCF_SUCCESS);
        EXPECT_NE(returnPoint.y.len, 0);

        ret = HcfGetEncodedPoint(POINT_DATA_MAP[i].curveName, &returnPoint, g_pointUnCompressedFormat, &returnBlob);
        EXPECT_EQ(ret, HCF_SUCCESS);
        EXPECT_NE(returnBlob.len, 0);

        ret = CompareBlobEqual(&returnBlob, POINT_DATA_MAP[i].pointUncompressedBlob);
        EXPECT_EQ(ret, HCF_SUCCESS);

        HcfObjDestroy(keyPair);
        HcfObjDestroy(generator);
        FreeEcPointMem(&returnPoint);
        HcfBlobDataFree(&returnBlob);
    }
}

// Invalid input parameter
HWTEST_F(CryptoEccEcdhPubTest, CryptoEccEcdhPubTest031, TestSize.Level0)
{
    HcfAsyKeyGenerator *generator = nullptr;
    HcfKeyPair *keyPair = nullptr;
    HcfResult ret = HCF_INVALID_PARAMS;
    ret = HcfAsyKeyGeneratorCreate("ECC_BrainPoolP256r1", &generator);
    EXPECT_EQ(ret, HCF_SUCCESS);
    EXPECT_NE(generator, nullptr);

    ret = generator->convertKey(nullptr, nullptr, &g_p256r1PubKeyUncompressedBlob, nullptr, &keyPair);
    EXPECT_NE(ret, HCF_SUCCESS);
    EXPECT_EQ(keyPair, nullptr);

    HcfObjDestroy(keyPair);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoEccEcdhPubTest, CryptoEccEcdhPubTest032, TestSize.Level0)
{
    HcfAsyKeyGenerator *generator = nullptr;
    HcfKeyPair *keyPair = nullptr;
    HcfBlob returnBlob = { .data = nullptr, .len = 0 };
    HcfResult ret = HCF_INVALID_PARAMS;
    ret = HcfAsyKeyGeneratorCreate("RSA512", &generator);
    EXPECT_EQ(ret, HCF_SUCCESS);
    EXPECT_NE(generator, nullptr);

    ret = generator->generateKeyPair(generator, nullptr, &keyPair);
    EXPECT_EQ(ret, HCF_SUCCESS);
    EXPECT_NE(keyPair, nullptr);

    ret = keyPair->pubKey->getEncodedDer(keyPair->pubKey, g_pubKeyCompressedFormat, &returnBlob);
    EXPECT_NE(ret, HCF_SUCCESS);
    EXPECT_EQ(returnBlob.len, 0);

    HcfObjDestroy(keyPair);
    HcfObjDestroy(generator);
    HcfBlobDataFree(&returnBlob);
}

HWTEST_F(CryptoEccEcdhPubTest, CryptoEccEcdhPubTest033, TestSize.Level0)
{
    HcfAsyKeyGenerator *generator = nullptr;
    HcfKeyPair *keyPair = nullptr;
    HcfBlob returnBlob = { .data = nullptr, .len = 0 };
    HcfResult ret = HCF_INVALID_PARAMS;
    ret = HcfAsyKeyGeneratorCreate("DSA1024", &generator);
    EXPECT_EQ(ret, HCF_SUCCESS);
    EXPECT_NE(generator, nullptr);

    ret = generator->generateKeyPair(generator, nullptr, &keyPair);
    EXPECT_EQ(ret, HCF_SUCCESS);
    EXPECT_NE(keyPair, nullptr);

    ret = keyPair->pubKey->getEncodedDer(keyPair->pubKey, g_pubKeyCompressedFormat, &returnBlob);
    EXPECT_NE(ret, HCF_SUCCESS);
    EXPECT_EQ(returnBlob.len, 0);

    HcfObjDestroy(keyPair);
    HcfObjDestroy(generator);
    HcfBlobDataFree(&returnBlob);
}

HWTEST_F(CryptoEccEcdhPubTest, CryptoEccEcdhPubTest034, TestSize.Level0)
{
    HcfAsyKeyGenerator *generator = nullptr;
    HcfKeyPair *keyPair = nullptr;
    HcfBlob returnBlob = { .data = nullptr, .len = 0 };
    HcfResult ret = HCF_INVALID_PARAMS;
    for (uint32_t i = 0; i < sizeof(PUBKEY_DATA_MAP) / sizeof(PUBKEY_DATA_MAP[0]); i++) {
        ret = HcfAsyKeyGeneratorCreate(PUBKEY_DATA_MAP[i].algoName, &generator);
        EXPECT_EQ(ret, HCF_SUCCESS);
        EXPECT_NE(generator, nullptr);

        ret = generator->generateKeyPair(generator, nullptr, &keyPair);
        EXPECT_EQ(ret, HCF_SUCCESS);
        EXPECT_NE(keyPair, nullptr);

        ret = keyPair->pubKey->getEncodedDer(nullptr, g_pubKeyCompressedFormat, &returnBlob);
        EXPECT_NE(ret, HCF_SUCCESS);
        EXPECT_EQ(returnBlob.len, 0);

        HcfObjDestroy(keyPair);
        HcfObjDestroy(generator);
        HcfBlobDataFree(&returnBlob);
    }
}

HWTEST_F(CryptoEccEcdhPubTest, CryptoEccEcdhPubTest035, TestSize.Level0)
{
    HcfAsyKeyGenerator *generator = nullptr;
    HcfKeyPair *keyPair = nullptr;
    HcfBlob returnBlob = { .data = nullptr, .len = 0 };
    HcfResult ret = HCF_INVALID_PARAMS;
    for (uint32_t i = 0; i < sizeof(PUBKEY_DATA_MAP) / sizeof(PUBKEY_DATA_MAP[0]); i++) {
        ret = HcfAsyKeyGeneratorCreate(PUBKEY_DATA_MAP[i].algoName, &generator);
        EXPECT_EQ(ret, HCF_SUCCESS);
        EXPECT_NE(generator, nullptr);

        ret = generator->generateKeyPair(generator, nullptr, &keyPair);
        EXPECT_EQ(ret, HCF_SUCCESS);
        EXPECT_NE(keyPair, nullptr);

        ret = keyPair->pubKey->getEncodedDer(keyPair->pubKey, nullptr, &returnBlob);
        EXPECT_NE(ret, HCF_SUCCESS);
        EXPECT_EQ(returnBlob.len, 0);

        HcfObjDestroy(keyPair);
        HcfObjDestroy(generator);
        HcfBlobDataFree(&returnBlob);
    }
}

HWTEST_F(CryptoEccEcdhPubTest, CryptoEccEcdhPubTest036, TestSize.Level0)
{
    HcfAsyKeyGenerator *generator = nullptr;
    HcfKeyPair *keyPair = nullptr;
    HcfResult ret = HCF_INVALID_PARAMS;
    ret = HcfAsyKeyGeneratorCreate("ECC_BrainPoolP256r1", &generator);
    EXPECT_EQ(ret, HCF_SUCCESS);
    EXPECT_NE(generator, nullptr);

    ret = generator->convertKey(generator, nullptr, &g_p256r1ModifyPubKeyBlob, nullptr, &keyPair);
    EXPECT_NE(ret, HCF_SUCCESS);
    EXPECT_EQ(keyPair, nullptr);

    HcfObjDestroy(keyPair);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoEccEcdhPubTest, CryptoEccEcdhPubTest037, TestSize.Level0)
{
    HcfAsyKeyGenerator *generator = nullptr;
    HcfKeyPair *keyPair = nullptr;
    HcfBlob returnBlob = { .data = nullptr, .len = 0 };
    HcfResult ret = HCF_INVALID_PARAMS;
    ret = HcfAsyKeyGeneratorCreate("ECC_BrainPoolP256r1", &generator);
    EXPECT_EQ(ret, HCF_SUCCESS);
    EXPECT_NE(generator, nullptr);

    ret = generator->convertKey(generator, nullptr, &g_p256t1PubKeyUncompressedBlob, nullptr, &keyPair);
    EXPECT_EQ(ret, HCF_SUCCESS);
    EXPECT_NE(keyPair, nullptr);

    ret = keyPair->pubKey->getEncodedDer(keyPair->pubKey, g_pubKeyUnCompressedFormat, &returnBlob);
    EXPECT_NE(ret, HCF_SUCCESS);
    EXPECT_EQ(returnBlob.len, 0);

    HcfObjDestroy(keyPair);
    HcfObjDestroy(generator);
    HcfBlobDataFree(&returnBlob);
}

HWTEST_F(CryptoEccEcdhPubTest, CryptoEccEcdhPubTest038, TestSize.Level0)
{
    HcfPoint returnPoint = { .x = { .data = nullptr, .len = 0 }, .y = { .data = nullptr, .len = 0 } };
    HcfResult ret = HCF_INVALID_PARAMS;
    ret = HcfConvertPoint("NID_brainpoolP256r1", &g_p256r1ModifyPointBlob, &returnPoint);
    EXPECT_NE(ret, HCF_SUCCESS);
    EXPECT_EQ(returnPoint.x.len, 0);

    FreeEcPointMem(&returnPoint);
}

HWTEST_F(CryptoEccEcdhPubTest, CryptoEccEcdhPubTest039, TestSize.Level0)
{
    HcfPoint returnPoint = { .x = { .data = nullptr, .len = 0 }, .y = { .data = nullptr, .len = 0 } };
    HcfResult ret = HCF_INVALID_PARAMS;
    ret = HcfConvertPoint("NID_brainpoolP256t1", &g_p256r1PointUncompressedBlob, &returnPoint);
    EXPECT_NE(ret, HCF_SUCCESS);
    EXPECT_EQ(returnPoint.x.len, 0);

    FreeEcPointMem(&returnPoint);
}

HWTEST_F(CryptoEccEcdhPubTest, CryptoEccEcdhPubTest040, TestSize.Level0)
{
    HcfPoint returnPoint = { .x = { .data = nullptr, .len = 0 }, .y = { .data = nullptr, .len = 0 } };
    HcfResult ret = HCF_INVALID_PARAMS;
    ret = HcfConvertPoint("NID_brainpoolP256t1", &g_p256r1PointCompressedBlob, &returnPoint);
    EXPECT_NE(ret, HCF_SUCCESS);
    EXPECT_EQ(returnPoint.x.len, 0);

    FreeEcPointMem(&returnPoint);
}

HWTEST_F(CryptoEccEcdhPubTest, CryptoEccEcdhPubTest041, TestSize.Level0)
{
    HcfPoint returnPoint = { .x = { .data = nullptr, .len = 0 }, .y = { .data = nullptr, .len = 0 } };
    HcfResult ret = HCF_INVALID_PARAMS;
    for (uint32_t i = 0; i < sizeof(POINT_DATA_MAP) / sizeof(POINT_DATA_MAP[0]); i++) {
        ret = HcfConvertPoint(PUBKEY_DATA_MAP[i].algoName, POINT_DATA_MAP[i].pointUncompressedBlob, &returnPoint);
        EXPECT_NE(ret, HCF_SUCCESS);
        EXPECT_EQ(returnPoint.x.len, 0);

        FreeEcPointMem(&returnPoint);
    }
}

HWTEST_F(CryptoEccEcdhPubTest, CryptoEccEcdhPubTest042, TestSize.Level0)
{
    HcfPoint returnPoint = { .x = { .data = nullptr, .len = 0 }, .y = { .data = nullptr, .len = 0 } };
    HcfResult ret = HCF_INVALID_PARAMS;
    for (uint32_t i = 0; i < sizeof(POINT_DATA_MAP) / sizeof(POINT_DATA_MAP[0]); i++) {
        ret = HcfConvertPoint(POINT_DATA_MAP[i].curveName, PUBKEY_DATA_MAP[i].pubKeyUncompressedBlob, &returnPoint);
        EXPECT_NE(ret, HCF_SUCCESS);
        EXPECT_EQ(returnPoint.x.len, 0);

        FreeEcPointMem(&returnPoint);
    }
}

HWTEST_F(CryptoEccEcdhPubTest, CryptoEccEcdhPubTest043, TestSize.Level0)
{
    HcfPoint returnPoint = { .x = { .data = nullptr, .len = 0 }, .y = { .data = nullptr, .len = 0 } };
    HcfBlob returnBlob = { .data = nullptr, .len = 0 };
    HcfResult ret = HCF_INVALID_PARAMS;
    for (uint32_t i = 0; i < sizeof(POINT_DATA_MAP) / sizeof(POINT_DATA_MAP[0]); i++) {
        ret = HcfConvertPoint(POINT_DATA_MAP[i].curveName, POINT_DATA_MAP[i].pointUncompressedBlob, &returnPoint);
        EXPECT_EQ(ret, HCF_SUCCESS);
        EXPECT_NE(returnPoint.x.len, 0);

        ret = HcfGetEncodedPoint(PUBKEY_DATA_MAP[i].algoName, &returnPoint, g_pointCompressedFormat, &returnBlob);
        EXPECT_NE(ret, HCF_SUCCESS);
        EXPECT_EQ(returnBlob.len, 0);

        FreeEcPointMem(&returnPoint);
        HcfBlobDataFree(&returnBlob);
    }
}

HWTEST_F(CryptoEccEcdhPubTest, CryptoEccEcdhPubTest044, TestSize.Level0)
{
    HcfPoint returnPoint = { .x = { .data = nullptr, .len = 0 }, .y = { .data = nullptr, .len = 0 } };
    HcfBlob returnBlob = { .data = nullptr, .len = 0 };
    HcfResult ret = HCF_INVALID_PARAMS;
    for (uint32_t i = 0; i < sizeof(POINT_DATA_MAP) / sizeof(POINT_DATA_MAP[0]); i++) {
        ret = HcfConvertPoint(POINT_DATA_MAP[i].curveName, POINT_DATA_MAP[i].pointUncompressedBlob, &returnPoint);
        EXPECT_EQ(ret, HCF_SUCCESS);
        EXPECT_NE(returnPoint.x.len, 0);

        ret = HcfGetEncodedPoint(POINT_DATA_MAP[i].curveName, &returnPoint, "compress", &returnBlob);
        EXPECT_NE(ret, HCF_SUCCESS);
        EXPECT_EQ(returnBlob.len, 0);

        FreeEcPointMem(&returnPoint);
        HcfBlobDataFree(&returnBlob);
    }
}

HWTEST_F(CryptoEccEcdhPubTest, CryptoEccEcdhPubTest045, TestSize.Level0)
{
    HcfPoint returnPoint = { .x = { .data = nullptr, .len = 0 }, .y = { .data = nullptr, .len = 0 } };
    HcfBlob returnBlob = { .data = nullptr, .len = 0 };
    HcfResult ret = HCF_INVALID_PARAMS;
    for (uint32_t i = 0; i < sizeof(POINT_DATA_MAP) / sizeof(POINT_DATA_MAP[0]); i++) {
        ret = HcfConvertPoint(POINT_DATA_MAP[i].curveName, POINT_DATA_MAP[i].pointUncompressedBlob, &returnPoint);
        EXPECT_EQ(ret, HCF_SUCCESS);
        EXPECT_NE(returnPoint.x.len, 0);

        ret = HcfGetEncodedPoint(POINT_DATA_MAP[i].curveName, nullptr, g_pointCompressedFormat, &returnBlob);
        EXPECT_NE(ret, HCF_SUCCESS);
        EXPECT_EQ(returnBlob.len, 0);

        FreeEcPointMem(&returnPoint);
        HcfBlobDataFree(&returnBlob);
    }
}

HWTEST_F(CryptoEccEcdhPubTest, CryptoEccEcdhPubTest046, TestSize.Level0)
{
    HcfPoint returnPoint = { .x = { .data = nullptr, .len = 0 }, .y = { .data = nullptr, .len = 0 } };
    HcfBlob returnBlob = { .data = nullptr, .len = 0 };
    HcfResult ret = HCF_INVALID_PARAMS;
    for (uint32_t i = 0; i < sizeof(POINT_DATA_MAP) / sizeof(POINT_DATA_MAP[0]); i++) {
        ret = HcfConvertPoint(POINT_DATA_MAP[i].curveName, POINT_DATA_MAP[i].pointUncompressedBlob, &returnPoint);
        EXPECT_EQ(ret, HCF_SUCCESS);
        EXPECT_NE(returnPoint.x.len, 0);

        ret = HcfGetEncodedPoint(POINT_DATA_MAP[i].curveName, &returnPoint, g_pointCompressedFormat, nullptr);
        EXPECT_NE(ret, HCF_SUCCESS);
        EXPECT_EQ(returnBlob.len, 0);

        FreeEcPointMem(&returnPoint);
        HcfBlobDataFree(&returnBlob);
    }
}

}