/*
 * Copyright (C) 2023 Huawei Device Co., Ltd.
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
#include "detailed_rsa_key_params.h"
#include "detailed_dsa_key_params.h"
#include "detailed_ecc_key_params.h"
#include "ecc_openssl_common.h"
#include "ecc_openssl_common_param_spec.h"
#include "ecc_common.h"
#include "memory.h"
#include "openssl_class.h"
#include "openssl_common.h"

using namespace std;
using namespace testing::ext;

namespace {
class CryptoAsyKeyGeneratorCovTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp();
    void TearDown();
};

void CryptoAsyKeyGeneratorCovTest::SetUpTestCase() {}

void CryptoAsyKeyGeneratorCovTest::TearDownTestCase() {}

void CryptoAsyKeyGeneratorCovTest::SetUp() {}

void CryptoAsyKeyGeneratorCovTest::TearDown() {}

constexpr int32_t INVALID_SPEC_TYPE = 1024;
// DSA
constexpr uint32_t DSA2048_PRI_SIZE = 20;
constexpr uint32_t DSA2048_PUB_SIZE = 256;
constexpr uint32_t DSA2048_P_SIZE = 256;
constexpr uint32_t DSA2048_Q_SIZE = 20;
constexpr uint32_t DSA2048_G_SIZE = 256;

static const char *g_algNameDSA = "DSA";
static const char *g_invalidAlgName = "null";

static const bool IS_BIG_ENDIAN = IsBigEndian();

static unsigned char g_dsa2048PrivBigE[] = {
    0x83, 0x4C, 0x91, 0x2F, 0x4E, 0x68, 0xD2, 0x7B, 0x56, 0x3B, 0x3C, 0x8A,
    0x90, 0x4F, 0x7D, 0x53, 0x5B, 0x55, 0x59, 0x27, 0xEE, 0x18, 0xBD, 0x32,
    0xC3, 0xC9, 0xCF, 0xFB,
};

static unsigned char g_dsa2048PrivLittleE[] = {
    0xa7, 0x91, 0xcf, 0xee, 0xb0, 0x76, 0x8a, 0x0c, 0x45, 0x6b, 0x8b, 0xa0,
    0xe8, 0xe2, 0xe2, 0xc4, 0xf6, 0x92, 0x67, 0x32,
};

static unsigned char g_dsa2048PubBigE[] = {
    0x5B, 0x73, 0x9C, 0xC1, 0x3B, 0x56, 0x2B, 0x58, 0xD5, 0xBA, 0x35, 0xAA,
    0xA6, 0x0A, 0xA7, 0x63, 0xB1, 0xDB, 0x7D, 0xF3, 0x11, 0x7A, 0xF2, 0x61,
    0x7A, 0x11, 0x55, 0x0D, 0x7B, 0x57, 0xEF, 0x77, 0x79, 0x1C, 0x84, 0xC4,
    0xDB, 0x33, 0x03, 0x24, 0xC6, 0x79, 0xF2, 0xEC, 0xF5, 0xBD, 0xD4, 0xE9,
    0xB4, 0x1C, 0x9A, 0xC9, 0xD6, 0x40, 0x30, 0x8A, 0xF5, 0x21, 0xE2, 0xD5,
    0xDD, 0x50, 0x8E, 0x5C, 0xE5, 0x77, 0xC2, 0x9A, 0x71, 0xB2, 0x41, 0x15,
    0x79, 0xA2, 0x9E, 0x5E, 0x3B, 0xDF, 0x88, 0x1D, 0x03, 0x12, 0x42, 0x6B,
    0x35, 0x86, 0xB9, 0x56, 0x7D, 0x8D, 0x8C, 0x98, 0xC0, 0xEF, 0xB1, 0xF7,
    0x20, 0x76, 0x43, 0xBC, 0x44, 0x13, 0x8A, 0xCE, 0x12, 0x80, 0xF9, 0xE2,
    0x59, 0x83, 0xF9, 0xC6, 0xE7, 0x21, 0x36, 0xFA, 0x50, 0x3E, 0xD7, 0x37,
    0x54, 0xB8, 0x75, 0xB5, 0xDA, 0x93, 0x93, 0xB2, 0x27, 0xDD, 0x29, 0x3E,
    0xE1, 0x9C, 0x38, 0xE6, 0x3E, 0x2E, 0xA9, 0xD0, 0x4D, 0x95, 0x9F, 0xFB,
    0xEC, 0x20, 0x0B, 0x60, 0xFA, 0xE2, 0xB0, 0x2B, 0xCA, 0x0C, 0xC7, 0x0E,
    0x01, 0x5F, 0x3F, 0xB1, 0xC4, 0x04, 0x4F, 0x44, 0xCE, 0xC5, 0x3F, 0x5F,
    0xDA, 0xFD, 0xA2, 0x70, 0x67, 0xFE, 0xBE, 0x08, 0x86, 0x0D, 0x0D, 0xA6,
    0xEC, 0x88, 0x83, 0xD2, 0xDB, 0x74, 0xF4, 0x89, 0xA7, 0x98, 0xC1, 0xCD,
    0xEE, 0xA1, 0x66, 0x25, 0x17, 0xA3, 0x4A, 0x85, 0xF4, 0xD3, 0x79, 0x36,
    0xD6, 0xDC, 0xFF, 0x4A, 0xB8, 0x84, 0x3C, 0xEE, 0x72, 0xF4, 0x0D, 0x53,
    0xE1, 0x4E, 0x63, 0x2F, 0x91, 0xCB, 0x11, 0x6E, 0xE3, 0xFD, 0x4F, 0x53,
    0x24, 0x5F, 0x9B, 0xE9, 0x2B, 0xE4, 0x1A, 0x71, 0xFC, 0xC7, 0xB0, 0x20,
    0x8D, 0xD4, 0x4F, 0x0F, 0xE4, 0x53, 0x9E, 0x8F, 0x32, 0x1F, 0x15, 0x4C,
    0xD0, 0xD5, 0x28, 0x45,
};

static unsigned char g_dsa2048PubLittleE[] = {
    0xce, 0xb7, 0x33, 0x8b, 0x33, 0xf8, 0xc9, 0xf2, 0x7f, 0x16, 0x52, 0x8d,
    0xe6, 0x10, 0xf4, 0x72, 0x18, 0x01, 0x7e, 0xc2, 0xa1, 0x40, 0x97, 0x95,
    0x4f, 0x4d, 0x8e, 0x15, 0x1d, 0x70, 0xd7, 0x38, 0xc8, 0x23, 0x11, 0x26,
    0x9f, 0xb0, 0x67, 0x86, 0x51, 0x22, 0x7e, 0xc9, 0x14, 0x00, 0xb9, 0x78,
    0x13, 0x45, 0xd8, 0xa9, 0xf9, 0x79, 0xd7, 0xac, 0xcf, 0x2f, 0x89, 0x66,
    0x9b, 0xd8, 0x79, 0x9c, 0xd8, 0xda, 0x84, 0x4e, 0x4a, 0xea, 0xcc, 0x1b,
    0x28, 0xa7, 0x7b, 0x04, 0x04, 0xeb, 0xf7, 0xc3, 0x95, 0x52, 0xe1, 0x76,
    0x74, 0x83, 0x85, 0xee, 0x14, 0x63, 0xf5, 0xee, 0xf3, 0x54, 0xea, 0x9a,
    0x58, 0x50, 0x96, 0x9d, 0x34, 0xd4, 0xd7, 0x98, 0xd9, 0xf2, 0x2b, 0xa7,
    0xfc, 0xab, 0x20, 0xb4, 0x36, 0x99, 0x27, 0x57, 0x93, 0x5f, 0x88, 0x49,
    0xe7, 0x2e, 0xae, 0x2c, 0x03, 0x48, 0x50, 0x93, 0xe7, 0xf1, 0xdc, 0xd7,
    0x19, 0x18, 0xd9, 0xbc, 0x24, 0x8d, 0xbd, 0xc4, 0x21, 0x0d, 0x31, 0x26,
    0xcb, 0xc2, 0xcc, 0x6e, 0x5d, 0x21, 0x43, 0x92, 0x44, 0x85, 0x4e, 0xd8,
    0x1f, 0xfc, 0xf1, 0xa6, 0x0a, 0x46, 0x00, 0x38, 0xb7, 0x9f, 0xa4, 0xa0,
    0x56, 0x41, 0xef, 0x2b, 0xf9, 0x86, 0x85, 0xab, 0xba, 0xb7, 0xf5, 0xee,
    0xf0, 0x57, 0x8e, 0x56, 0x50, 0x74, 0x7b, 0xf8, 0x98, 0xab, 0x95, 0xb7,
    0x47, 0xa5, 0x7d, 0x8b, 0x9f, 0xd1, 0x18, 0x3a, 0x8a, 0x7f, 0x48, 0xb5,
    0xf0, 0xb7, 0x78, 0xf2, 0x53, 0xe0, 0xb9, 0xad, 0x72, 0xaf, 0x7a, 0x82,
    0x4c, 0x5c, 0xc5, 0xf0, 0x47, 0x51, 0x4c, 0xce, 0x5d, 0x74, 0xcc, 0x21,
    0x88, 0x88, 0x61, 0xe0, 0xcd, 0x3d, 0xd0, 0xd2, 0x79, 0x64, 0xa3, 0x37,
    0x20, 0x5a, 0xaf, 0x92, 0xb0, 0x6a, 0xc7, 0x47, 0x83, 0xec, 0x92, 0x84,
    0x11, 0xa8, 0x8f, 0x17,
};

static unsigned char g_dsa2048PBigE[] = {
    0x95, 0x80, 0xF5, 0x6C, 0xBF, 0x07, 0x87, 0x72, 0xAE, 0xBD, 0x1F, 0x22,
    0xF1, 0x1B, 0x39, 0x31, 0xB4, 0x4D, 0x56, 0xB2, 0x8E, 0x13, 0x8D, 0xE2,
    0xEB, 0x2E, 0xDB, 0x2D, 0x34, 0x39, 0x69, 0x9D, 0xEE, 0xC4, 0x44, 0x80,
    0x0C, 0x47, 0xC0, 0x82, 0x1E, 0x23, 0xC0, 0x14, 0x3C, 0x04, 0xCA, 0xE0,
    0x36, 0x02, 0x26, 0xCC, 0xEF, 0x73, 0x9D, 0x0B, 0x33, 0xC7, 0x5E, 0x77,
    0x0E, 0x0B, 0x9B, 0xA6, 0x2E, 0xE1, 0x63, 0x96, 0xF0, 0x10, 0x00, 0x72,
    0x1C, 0xE0, 0x24, 0xC3, 0xEC, 0x7E, 0xF9, 0xB7, 0xD1, 0x6A, 0x61, 0xF6,
    0x8C, 0x45, 0xD4, 0x12, 0xD4, 0x6D, 0xD8, 0x57, 0x82, 0xF9, 0xC5, 0xC3,
    0xC8, 0x10, 0x91, 0x98, 0x89, 0xE7, 0xE1, 0x1C, 0xF0, 0xB3, 0x90, 0xA0,
    0xD5, 0x43, 0xAB, 0xA1, 0xD2, 0x70, 0x63, 0xD6, 0xBD, 0x80, 0xFB, 0x24,
    0x78, 0x80, 0x83, 0x8F, 0x67, 0x92, 0x9A, 0x4F, 0xF9, 0xCC, 0xBE, 0x92,
    0x80, 0x4D, 0xDA, 0xFE, 0x43, 0x58, 0x54, 0xC6, 0x97, 0xBD, 0x9F, 0x4E,
    0x6D, 0xB0, 0xD2, 0xF2, 0x89, 0xBF, 0xD1, 0x2E, 0xE4, 0x09, 0x67, 0x2E,
    0xE0, 0xB0, 0x75, 0xFB, 0x1D, 0xA4, 0xEE, 0xBE, 0x98, 0x13, 0x81, 0x15,
    0x8B, 0xBE, 0x6D, 0x60, 0x3E, 0xAF, 0xF6, 0xBF, 0x56, 0x81, 0xAB, 0x19,
    0x12, 0x47, 0xA5, 0xBD, 0xF2, 0x6E, 0xE4, 0xF6, 0x27, 0x6B, 0x22, 0x71,
    0xF7, 0xB7, 0x19, 0x93, 0xF5, 0x3C, 0xF4, 0xA4, 0xAF, 0xA0, 0xB3, 0x32,
    0xEB, 0x68, 0x7E, 0x3A, 0xAA, 0x78, 0x0E, 0x2A, 0xD1, 0xFA, 0x1B, 0x65,
    0x60, 0x2F, 0xAB, 0x44, 0x96, 0x3D, 0xB1, 0x8E, 0x9C, 0x27, 0x16, 0xE1,
    0x01, 0x67, 0xAA, 0x73, 0xAB, 0x28, 0xAC, 0xBF, 0x74, 0x5B, 0x27, 0x71,
    0x9D, 0xC9, 0x37, 0xFA, 0xDE, 0xD6, 0xD9, 0x13, 0xC1, 0x47, 0x90, 0x40,
    0xDD, 0x27, 0x75, 0xC1,
};

static unsigned char g_dsa2048PLittleE[] = {
    0x9b, 0xcf, 0x68, 0xf8, 0xae, 0xbf, 0x1d, 0xb0, 0xc3, 0x7d, 0x65, 0xc3,
    0x54, 0xd8, 0xa7, 0x5d, 0x0a, 0x21, 0xb3, 0x05, 0x3f, 0x3f, 0x1d, 0x83,
    0x25, 0xf0, 0xb8, 0x09, 0x7f, 0x1c, 0xb4, 0x82, 0x47, 0x6c, 0xf9, 0xd8,
    0x5c, 0x14, 0x64, 0x51, 0xc8, 0xf9, 0xa0, 0x92, 0xd3, 0xbb, 0x88, 0xd2,
    0xff, 0x42, 0x2c, 0x12, 0xe4, 0x04, 0xd5, 0xe4, 0x77, 0x6a, 0x0f, 0x91,
    0x27, 0x26, 0x6b, 0x7b, 0xa5, 0x00, 0x3d, 0x06, 0x8b, 0xf1, 0x7e, 0x82,
    0x57, 0xe7, 0xdc, 0x87, 0x2c, 0x02, 0x19, 0xb5, 0xbd, 0xd9, 0x79, 0x95,
    0x46, 0xdf, 0x18, 0x51, 0x72, 0xc7, 0xd2, 0xc3, 0x23, 0x1d, 0xb0, 0xa3,
    0xf7, 0x46, 0x0f, 0xfc, 0x18, 0x5d, 0x21, 0xbb, 0x38, 0x0d, 0x8f, 0x1a,
    0x68, 0x7b, 0x40, 0x3b, 0x62, 0xa1, 0x7f, 0xdd, 0xaa, 0xa0, 0x7b, 0x57,
    0x2f, 0x77, 0x12, 0xdf, 0x51, 0x2c, 0x36, 0x8a, 0x89, 0x69, 0x3b, 0xd7,
    0x5f, 0x9a, 0xbc, 0x28, 0x56, 0x43, 0xa1, 0x84, 0x1a, 0xa1, 0xf2, 0xd1,
    0x26, 0xfe, 0x76, 0x8b, 0xbf, 0x40, 0x94, 0x0a, 0xe7, 0x69, 0x86, 0x67,
    0xfc, 0xf7, 0x7a, 0x08, 0x3c, 0x5b, 0x12, 0xf9, 0x4c, 0x67, 0x0e, 0xae,
    0x40, 0x6f, 0x54, 0xe6, 0x0b, 0x6e, 0x86, 0xb9, 0x7d, 0x67, 0xa3, 0xad,
    0x8e, 0x55, 0x5c, 0x16, 0x58, 0x8c, 0x4d, 0x11, 0x07, 0xd2, 0xed, 0x92,
    0x4b, 0x02, 0xff, 0x4e, 0x19, 0x4c, 0x63, 0x12, 0x58, 0xb1, 0xf5, 0xe9,
    0x21, 0x28, 0x5c, 0x68, 0x7e, 0xa2, 0xc2, 0x0c, 0xef, 0xfe, 0x1f, 0xb0,
    0x32, 0x41, 0x0b, 0x1d, 0xc2, 0xdc, 0x8e, 0x5c, 0x8b, 0x5d, 0xa0, 0xd9,
    0x13, 0xc4, 0xf8, 0xeb, 0x81, 0x6f, 0xaf, 0x30, 0xbf, 0x6f, 0xcf, 0x7e,
    0xe2, 0x34, 0x83, 0x4f, 0x6f, 0x5d, 0xf3, 0x99, 0xe5, 0xb9, 0x8e, 0xf4,
    0xad, 0xfa, 0x25, 0xa0,
};

static unsigned char g_dsa2048QBigE[] = {
    0xDB, 0xAE, 0x97, 0xED, 0xCF, 0x0F, 0xC0, 0x1A, 0x45, 0xBB, 0xD4, 0x6E,
    0xB5, 0xCC, 0xAF, 0x22, 0xDB, 0x6F, 0x37, 0x75, 0x68, 0xB1, 0x6C, 0xC8,
    0x24, 0x00, 0xBD, 0xED,
};

static unsigned char g_dsa2048QLittleE[] = {
    0x1b, 0x17, 0x75, 0xa3, 0x19, 0xdd, 0x08, 0xa1, 0xc6, 0x74, 0x62, 0xdb,
    0x0b, 0x3e, 0x94, 0xd3, 0x4d, 0x33, 0xe7, 0x97,
};

static unsigned char g_dsa2048GBigE[] = {
    0x54, 0x93, 0x60, 0x74, 0xF2, 0xC1, 0xFC, 0xCC, 0x1C, 0x8F, 0x6E, 0x14,
    0x3E, 0x1F, 0xD3, 0x91, 0x49, 0xD9, 0x25, 0xFA, 0x78, 0x29, 0x56, 0xE9,
    0x70, 0x04, 0x1C, 0x3E, 0x4E, 0xE6, 0x48, 0x6A, 0x4C, 0xFB, 0xC3, 0x80,
    0x02, 0x39, 0x56, 0x4A, 0xA5, 0xC5, 0xFE, 0x7C, 0x8B, 0x5C, 0xCC, 0x97,
    0xAB, 0x08, 0x9F, 0x5D, 0xFF, 0x87, 0xB7, 0xC6, 0x85, 0x6D, 0xFB, 0x9D,
    0xA3, 0xA8, 0x1D, 0x32, 0xE5, 0xE2, 0x7A, 0x2A, 0xE3, 0xA6, 0x38, 0x7E,
    0x08, 0xF6, 0x7F, 0xC7, 0xB3, 0xB2, 0x11, 0xE0, 0x7D, 0xB9, 0x9C, 0x8E,
    0x57, 0xE1, 0xD1, 0xE0, 0xDF, 0xE9, 0x7D, 0xF8, 0xD5, 0x33, 0xCA, 0x56,
    0x5A, 0x11, 0xF6, 0x06, 0x89, 0x9E, 0x93, 0x94, 0x72, 0xF0, 0x8B, 0x07,
    0xA2, 0x02, 0x3F, 0x25, 0xD0, 0x74, 0x2E, 0x42, 0x3A, 0xA8, 0xC7, 0xD9,
    0xE8, 0xBA, 0x5A, 0x82, 0x02, 0x68, 0x2D, 0x03, 0xBE, 0x3D, 0x8F, 0x1F,
    0x47, 0x41, 0x3B, 0x09, 0xB4, 0x63, 0x47, 0x44, 0x11, 0xC3, 0x05, 0xB8,
    0xDC, 0xAE, 0x91, 0x77, 0xFC, 0x4B, 0x8A, 0x31, 0xB9, 0x59, 0x23, 0xB3,
    0xC5, 0xB2, 0x61, 0x30, 0x75, 0xBA, 0xE3, 0xCC, 0xE3, 0xA5, 0x07, 0x61,
    0x09, 0x5E, 0x10, 0x2E, 0x94, 0xA3, 0x4E, 0xEF, 0xA8, 0xC2, 0x19, 0x2B,
    0xA7, 0x9D, 0xF3, 0x2B, 0x80, 0xF1, 0xB1, 0x12, 0x50, 0xC1, 0xE7, 0x1A,
    0x03, 0x05, 0x96, 0x5A, 0xE6, 0xE2, 0x5F, 0x1C, 0xC3, 0x6F, 0xE8, 0x2B,
    0xB4, 0xBA, 0x3A, 0xD8, 0x9A, 0x87, 0xFD, 0x21, 0xD7, 0xF1, 0xBA, 0x75,
    0xB9, 0x23, 0x3D, 0xA1, 0xD3, 0xB1, 0xFE, 0x26, 0x07, 0x37, 0xF2, 0xC0,
    0x77, 0xA9, 0xF8, 0x8F, 0x35, 0x34, 0xA4, 0x0F, 0xA4, 0xCF, 0x51, 0x72,
    0x0E, 0xF9, 0xE8, 0x9E, 0x99, 0x6F, 0x4D, 0x61, 0xA7, 0xFE, 0xA8, 0xBF,
    0xA0, 0x2C, 0xF8, 0xDD,
};

static unsigned char g_dsa2048GLittleE[] = {
    0x38, 0xe5, 0xb2, 0xf8, 0x9e, 0x52, 0x55, 0x65, 0xbd, 0x35, 0x78, 0x06,
    0x59, 0x70, 0x96, 0xd1, 0x99, 0x29, 0xa0, 0xc1, 0x36, 0x9f, 0xad, 0xd2,
    0xfd, 0xe7, 0xf4, 0xb6, 0x01, 0xbb, 0x66, 0x8e, 0xab, 0xdc, 0x43, 0xbf,
    0x8e, 0x4e, 0x69, 0x59, 0x64, 0x22, 0x71, 0xdd, 0x4a, 0x4c, 0xa5, 0x0d,
    0xed, 0x87, 0xdc, 0xef, 0x72, 0x3b, 0xea, 0x04, 0xca, 0xe4, 0xed, 0x9a,
    0xae, 0x8e, 0xc7, 0x93, 0xf5, 0xae, 0x26, 0x66, 0x80, 0xdb, 0x6f, 0x2b,
    0x96, 0x85, 0x6c, 0x7f, 0xa5, 0x76, 0x28, 0x30, 0xc7, 0xe1, 0x1e, 0x12,
    0x1e, 0x1c, 0xa9, 0xd1, 0xa6, 0x4c, 0x08, 0x1d, 0x87, 0xf3, 0x75, 0x0a,
    0x77, 0x84, 0x1d, 0xbf, 0x40, 0x89, 0x46, 0x3c, 0x3d, 0xaa, 0x46, 0xd4,
    0x4d, 0x36, 0x00, 0x46, 0xb7, 0xdc, 0x42, 0x6e, 0x7d, 0x0c, 0xc8, 0x17,
    0xb3, 0xe4, 0xa5, 0x00, 0x2e, 0xee, 0xe4, 0xa8, 0xe1, 0x18, 0x78, 0x70,
    0xf0, 0xa3, 0xde, 0x5f, 0x1b, 0xc3, 0x19, 0x30, 0x21, 0xf0, 0xed, 0x43,
    0x14, 0x93, 0x17, 0x48, 0x2f, 0x6c, 0xae, 0xd1, 0xa0, 0xd1, 0xc9, 0x34,
    0xba, 0x64, 0x96, 0xd3, 0x1a, 0x63, 0xdc, 0xf6, 0xc6, 0x48, 0xc1, 0xf5,
    0x9a, 0x5b, 0x4a, 0x2e, 0x3d, 0x37, 0x68, 0x61, 0x34, 0xd2, 0x10, 0x22,
    0x9f, 0x22, 0x8e, 0x39, 0xc8, 0xea, 0x5e, 0x30, 0x0c, 0xec, 0x85, 0xcb,
    0xd1, 0x46, 0xc0, 0xe3, 0x29, 0x09, 0x6a, 0xdf, 0x6a, 0xbc, 0x82, 0x31,
    0x02, 0x37, 0x42, 0x30, 0x9e, 0x6c, 0x58, 0xe8, 0x3a, 0x5b, 0x90, 0xba,
    0xec, 0xd9, 0x1c, 0x39, 0x0c, 0x80, 0x8e, 0xf5, 0x72, 0x90, 0x25, 0xae,
    0xa6, 0x96, 0xbf, 0x90, 0x7e, 0x3f, 0x38, 0xad, 0xae, 0x3c, 0xa4, 0x1c,
    0x2f, 0xde, 0x13, 0x4f, 0xa5, 0xb5, 0xfc, 0x92, 0xf3, 0xf4, 0x63, 0x34,
    0x59, 0x16, 0x78, 0x2c,
};

static HcfBigInteger g_dsaCorrectSkBn = {
    .data = IS_BIG_ENDIAN ? g_dsa2048PrivBigE : g_dsa2048PrivLittleE, .len = DSA2048_PRI_SIZE };
static HcfBigInteger g_dsaCorrectPkBn = {
    .data = IS_BIG_ENDIAN ? g_dsa2048PubBigE : g_dsa2048PubLittleE, .len = DSA2048_PUB_SIZE };
static HcfBigInteger g_dsaCorrectPBn = {
    .data = IS_BIG_ENDIAN ? g_dsa2048PBigE : g_dsa2048PLittleE, .len = DSA2048_P_SIZE };
static HcfBigInteger g_dsaCorrectQBn = {
    .data = IS_BIG_ENDIAN ? g_dsa2048QBigE : g_dsa2048QLittleE, .len = DSA2048_Q_SIZE };
static HcfBigInteger g_dsaCorrectGBn = {
    .data = IS_BIG_ENDIAN ? g_dsa2048GBigE : g_dsa2048GLittleE, .len = DSA2048_G_SIZE };
static HcfBigInteger g_dsaNullSkBn = {
    .data = nullptr, .len = DSA2048_PRI_SIZE };
static HcfBigInteger g_dsaNullPkBn = {
    .data = nullptr, .len = DSA2048_PUB_SIZE };
static HcfBigInteger g_dsaNullPBn = { .data = nullptr, .len = DSA2048_P_SIZE };
static HcfBigInteger g_dsaNullQBn = { .data = nullptr, .len = DSA2048_Q_SIZE };
static HcfBigInteger g_dsaNullGBn = { .data = nullptr, .len = DSA2048_G_SIZE };
static HcfBigInteger g_dsaNoLenSkBn = {
    .data = IS_BIG_ENDIAN ? g_dsa2048PrivBigE : g_dsa2048PrivLittleE, .len = 0 };
static HcfBigInteger g_dsaNoLenPkBn = {
    .data = IS_BIG_ENDIAN ? g_dsa2048PubBigE : g_dsa2048PubLittleE, .len = 0 };
static HcfBigInteger g_dsaNoLenPBn = { .data = IS_BIG_ENDIAN ? g_dsa2048PBigE : g_dsa2048PLittleE, .len = 0 };
static HcfBigInteger g_dsaNoLenQBn = { .data = IS_BIG_ENDIAN ? g_dsa2048QBigE : g_dsa2048QLittleE, .len = 0 };
static HcfBigInteger g_dsaNoLenGBn = { .data = IS_BIG_ENDIAN ? g_dsa2048GBigE : g_dsa2048GLittleE, .len = 0 };

static HcfAsyKeyParamsSpec dsaAsySpecCommCorrect = {
    .algName = const_cast<char *>(g_algNameDSA),
    .specType = HCF_COMMON_PARAMS_SPEC
};
static HcfAsyKeyParamsSpec dsaAsySpecPkCorrect = {
    .algName = const_cast<char *>(g_algNameDSA),
    .specType = HCF_PUBLIC_KEY_SPEC
};
static HcfAsyKeyParamsSpec dsaAsySpecKeyPairCorrect = {
    .algName = const_cast<char *>(g_algNameDSA),
    .specType = HCF_KEY_PAIR_SPEC
};
static HcfAsyKeyParamsSpec dsaAsySpecNoAlg = {
    .algName = nullptr,
    .specType = HCF_KEY_PAIR_SPEC
};
static HcfAsyKeyParamsSpec dsaAsySpecErrorAlg = {
    .algName = const_cast<char *>(g_invalidAlgName),
    .specType = HCF_KEY_PAIR_SPEC
};
static HcfAsyKeyParamsSpec dsaAsySpecKeyPairErrorSpecType = {
    .algName = const_cast<char *>(g_algNameDSA),
    .specType = HCF_PRIVATE_KEY_SPEC
};

static HcfDsaCommParamsSpec dsaCommonSpecNoAlg = {
    .base = dsaAsySpecNoAlg, .p = g_dsaCorrectPBn, .q = g_dsaCorrectQBn, .g = g_dsaCorrectGBn
};
static HcfDsaCommParamsSpec dsaCommonSpecErrorAlg = {
    .base = dsaAsySpecErrorAlg, .p = g_dsaCorrectPBn, .q = g_dsaCorrectQBn, .g = g_dsaCorrectGBn
};
static HcfDsaCommParamsSpec dsaCommonSpecNullP = {
    .base = dsaAsySpecCommCorrect, .p = g_dsaNullPBn, .q = g_dsaCorrectQBn, .g = g_dsaCorrectGBn
};
static HcfDsaCommParamsSpec dsaCommonSpecNoLenP = {
    .base = dsaAsySpecCommCorrect, .p = g_dsaNoLenPBn, .q = g_dsaCorrectQBn, .g = g_dsaCorrectGBn
};
static HcfDsaCommParamsSpec dsaCommonSpecNullQ = {
    .base = dsaAsySpecCommCorrect, .p = g_dsaCorrectPBn, .q = g_dsaNullQBn, .g = g_dsaCorrectGBn
};
static HcfDsaCommParamsSpec dsaCommonSpecNoLenQ = {
    .base = dsaAsySpecCommCorrect, .p = g_dsaCorrectPBn, .q = g_dsaNoLenQBn, .g = g_dsaCorrectGBn
};
static HcfDsaCommParamsSpec dsaCommonSpecNullG = {
    .base = dsaAsySpecCommCorrect, .p = g_dsaCorrectPBn, .q = g_dsaCorrectQBn, .g = g_dsaNullGBn
};
static HcfDsaCommParamsSpec dsaCommonSpecNoLenG = {
    .base = dsaAsySpecCommCorrect, .p = g_dsaCorrectPBn, .q = g_dsaCorrectQBn, .g = g_dsaNoLenGBn
};

static HcfDsaPubKeyParamsSpec dsaPkSpecErrorComm = {
    .base = {
        .base = dsaAsySpecPkCorrect,
        .p = g_dsaNullPBn,
        .q = g_dsaCorrectQBn,
        .g = g_dsaCorrectGBn
    },
    .pk = g_dsaCorrectPkBn
};
static HcfDsaPubKeyParamsSpec dsaPkSpecNullPk = {
    .base = {
        .base = dsaAsySpecPkCorrect,
        .p = g_dsaCorrectPBn,
        .q = g_dsaCorrectQBn,
        .g = g_dsaCorrectGBn
    },
    .pk = g_dsaNullPkBn
};
static HcfDsaPubKeyParamsSpec dsaPkSpecNoLenPk = {
    .base = {
        .base = dsaAsySpecPkCorrect,
        .p = g_dsaCorrectPBn,
        .q = g_dsaCorrectQBn,
        .g = g_dsaCorrectGBn
    },
    .pk = g_dsaNoLenPkBn
};

static HcfDsaKeyPairParamsSpec dsaKeyPairSpecErrorSpecType = {
    .base = {
        .base = dsaAsySpecKeyPairErrorSpecType,
        .p = g_dsaCorrectPBn,
        .q = g_dsaCorrectQBn,
        .g = g_dsaCorrectGBn
    },
    .pk = g_dsaCorrectPkBn,
    .sk = g_dsaCorrectSkBn
};
static HcfDsaKeyPairParamsSpec dsaKeyPairSpecErrorComm = {
    .base = {
        .base = dsaAsySpecKeyPairCorrect,
        .p = g_dsaNullPBn,
        .q = g_dsaCorrectQBn,
        .g = g_dsaCorrectGBn
    },
    .pk = g_dsaCorrectPkBn,
    .sk = g_dsaCorrectSkBn
};
static HcfDsaKeyPairParamsSpec dsaKeyPairSpecNullPk = {
    .base = {
        .base = dsaAsySpecKeyPairCorrect,
        .p = g_dsaCorrectPBn,
        .q = g_dsaCorrectQBn,
        .g = g_dsaCorrectGBn
    },
    .pk = g_dsaNullPkBn,
    .sk = g_dsaCorrectSkBn
};
static HcfDsaKeyPairParamsSpec dsaKeyPairSpecNoLenPk = {
    .base = {
        .base = dsaAsySpecKeyPairCorrect,
        .p = g_dsaCorrectPBn,
        .q = g_dsaCorrectQBn,
        .g = g_dsaCorrectGBn
    },
    .pk = g_dsaNoLenPkBn,
    .sk = g_dsaCorrectSkBn
};
static HcfDsaKeyPairParamsSpec dsaKeyPairSpecNullSk = {
    .base = {
        .base = dsaAsySpecKeyPairCorrect,
        .p = g_dsaCorrectPBn,
        .q = g_dsaCorrectQBn,
        .g = g_dsaCorrectGBn
    },
    .pk = g_dsaCorrectPkBn,
    .sk = g_dsaNullSkBn
};
static HcfDsaKeyPairParamsSpec dsaKeyPairSpecNoLenSk = {
    .base = {
        .base = dsaAsySpecKeyPairCorrect,
        .p = g_dsaCorrectPBn,
        .q = g_dsaCorrectQBn,
        .g = g_dsaCorrectGBn
    },
    .pk = g_dsaCorrectPkBn,
    .sk = g_dsaNoLenSkBn
};

// RSA SPEC
constexpr uint32_t RSA_2048_N_BYTE_SIZE = 256;
constexpr uint32_t RSA_2048_D_BYTE_SIZE = 256;
constexpr uint32_t RSA_2048_E_BYTE_SIZE = 3;

constexpr unsigned char RSA_2048_CORRECT_N[] =
    "\x92\x60\xd0\x75\x0a\xe1\x17\xee\xe5\x5c\x3f\x3d\xea\xba\x74\x91"
    "\x75\x21\xa2\x62\xee\x76\x00\x7c\xdf\x8a\x56\x75\x5a\xd7\x3a\x15"
    "\x98\xa1\x40\x84\x10\xa0\x14\x34\xc3\xf5\xbc\x54\xa8\x8b\x57\xfa"
    "\x19\xfc\x43\x28\xda\xea\x07\x50\xa4\xc4\x4e\x88\xcf\xf3\xb2\x38"
    "\x26\x21\xb8\x0f\x67\x04\x64\x43\x3e\x43\x36\xe6\xd0\x03\xe8\xcd"
    "\x65\xbf\xf2\x11\xda\x14\x4b\x88\x29\x1c\x22\x59\xa0\x0a\x72\xb7"
    "\x11\xc1\x16\xef\x76\x86\xe8\xfe\xe3\x4e\x4d\x93\x3c\x86\x81\x87"
    "\xbd\xc2\x6f\x7b\xe0\x71\x49\x3c\x86\xf7\xa5\x94\x1c\x35\x10\x80"
    "\x6a\xd6\x7b\x0f\x94\xd8\x8f\x5c\xf5\xc0\x2a\x09\x28\x21\xd8\x62"
    "\x6e\x89\x32\xb6\x5c\x5b\xd8\xc9\x20\x49\xc2\x10\x93\x2b\x7a\xfa"
    "\x7a\xc5\x9c\x0e\x88\x6a\xe5\xc1\xed\xb0\x0d\x8c\xe2\xc5\x76\x33"
    "\xdb\x26\xbd\x66\x39\xbf\xf7\x3c\xee\x82\xbe\x92\x75\xc4\x02\xb4"
    "\xcf\x2a\x43\x88\xda\x8c\xf8\xc6\x4e\xef\xe1\xc5\xa0\xf5\xab\x80"
    "\x57\xc3\x9f\xa5\xc0\x58\x9c\x3e\x25\x3f\x09\x60\x33\x23\x00\xf9"
    "\x4b\xea\x44\x87\x7b\x58\x8e\x1e\xdb\xde\x97\xcf\x23\x60\x72\x7a"
    "\x09\xb7\x75\x26\x2d\x7e\xe5\x52\xb3\x31\x9b\x92\x66\xf0\x5a\x25";

constexpr unsigned char RSA_2048_CORRECT_E[] = "\x01\x00\x01";

constexpr unsigned char RSA_2048_CORRECT_D[] =
    "\x6a\x7d\xf2\xca\x63\xea\xd4\xdd\xa1\x91\xd6\x14\xb6\xb3\x85\xe0"
    "\xd9\x05\x6a\x3d\x6d\x5c\xfe\x07\xdb\x1d\xaa\xbe\xe0\x22\xdb\x08"
    "\x21\x2d\x97\x61\x3d\x33\x28\xe0\x26\x7c\x9d\xd2\x3d\x78\x7a\xbd"
    "\xe2\xaf\xcb\x30\x6a\xeb\x7d\xfc\xe6\x92\x46\xcc\x73\xf5\xc8\x7f"
    "\xdf\x06\x03\x01\x79\xa2\x11\x4b\x76\x7d\xb1\xf0\x83\xff\x84\x1c"
    "\x02\x5d\x7d\xc0\x0c\xd8\x24\x35\xb9\xa9\x0f\x69\x53\x69\xe9\x4d"
    "\xf2\x3d\x2c\xe4\x58\xbc\x3b\x32\x83\xad\x8b\xba\x2b\x8f\xa1\xba"
    "\x62\xe2\xdc\xe9\xac\xcf\xf3\x79\x9a\xae\x7c\x84\x00\x16\xf3\xba"
    "\x8e\x00\x48\xc0\xb6\xcc\x43\x39\xaf\x71\x61\x00\x3a\x5b\xeb\x86"
    "\x4a\x01\x64\xb2\xc1\xc9\x23\x7b\x64\xbc\x87\x55\x69\x94\x35\x1b"
    "\x27\x50\x6c\x33\xd4\xbc\xdf\xce\x0f\x9c\x49\x1a\x7d\x6b\x06\x28"
    "\xc7\xc8\x52\xbe\x4f\x0a\x9c\x31\x32\xb2\xed\x3a\x2c\x88\x81\xe9"
    "\xaa\xb0\x7e\x20\xe1\x7d\xeb\x07\x46\x91\xbe\x67\x77\x76\xa7\x8b"
    "\x5c\x50\x2e\x05\xd9\xbd\xde\x72\x12\x6b\x37\x38\x69\x5e\x2d\xd1"
    "\xa0\xa9\x8a\x14\x24\x7c\x65\xd8\xa7\xee\x79\x43\x2a\x09\x2c\xb0"
    "\x72\x1a\x12\xdf\x79\x8e\x44\xf7\xcf\xce\x0c\x49\x81\x47\xa9\xb1";

const char *g_rsaAlgName = "RSA";

static void RemoveLastChar(const unsigned char *str, unsigned char *dest, uint32_t destLen)
{
    for (size_t i = 0; i < destLen; i++) {
        dest[i] = str[i];
    }
    return;
}

static void EndianSwap(unsigned char *pData, int startIndex, int length)
{
    int cnt = length / 2;
    int start = startIndex;
    int end  = startIndex + length - 1;
    unsigned char tmp;
    for (int i = 0; i < cnt; i++) {
        tmp = pData[start + i];
        pData[start + i] = pData[end - i];
        pData[end - i] = tmp;
    }
}

// 2048 defined the length of byte array
static void GenerateRsa2048CorrectCommonKeySpec(unsigned char *dataN, HcfRsaCommParamsSpec *returnSpec)
{
    RemoveLastChar(RSA_2048_CORRECT_N, dataN, RSA_2048_N_BYTE_SIZE);
    if (!IsBigEndian()) {
        // the device is not big endian
        EndianSwap(dataN, 0, RSA_2048_N_BYTE_SIZE);
    }
    returnSpec->n.data = dataN;
    returnSpec->n.len = RSA_2048_N_BYTE_SIZE;
    returnSpec->base.algName = const_cast<char *>(g_rsaAlgName);
    returnSpec->base.specType = HCF_COMMON_PARAMS_SPEC;
    return;
}

static void GenerateRsa2048CorrectPubKeySpec(unsigned char *dataN, unsigned char *dataE,
    HcfRsaPubKeyParamsSpec *returnPubSpec)
{
    HcfRsaCommParamsSpec rsaCommSpec = {};
    GenerateRsa2048CorrectCommonKeySpec(dataN, &rsaCommSpec);
    RemoveLastChar(RSA_2048_CORRECT_E, dataE, RSA_2048_E_BYTE_SIZE);
    if (!IsBigEndian()) {
        // the device is not big endian
        EndianSwap(dataE, 0, RSA_2048_E_BYTE_SIZE);
    }
    returnPubSpec->pk.data = dataE;
    returnPubSpec->pk.len = RSA_2048_E_BYTE_SIZE;
    returnPubSpec->base = rsaCommSpec;
    returnPubSpec->base.base.specType = HCF_PUBLIC_KEY_SPEC;
}

static void GenerateRsa2048CorrectKeyPairSpec(unsigned char *dataN, unsigned char *dataE, unsigned char *dataD,
    HcfRsaKeyPairParamsSpec *returnPairSpec)
{
    HcfRsaCommParamsSpec rsaCommSpec = {};
    GenerateRsa2048CorrectCommonKeySpec(dataN, &rsaCommSpec);
    RemoveLastChar(RSA_2048_CORRECT_E, dataE, RSA_2048_E_BYTE_SIZE);
    RemoveLastChar(RSA_2048_CORRECT_D, dataD, RSA_2048_D_BYTE_SIZE);
    if (!IsBigEndian()) {
        // the device is not big endian
        EndianSwap(dataE, 0, RSA_2048_E_BYTE_SIZE);
        EndianSwap(dataD, 0, RSA_2048_D_BYTE_SIZE);
    }
    returnPairSpec->pk.data = dataE;
    returnPairSpec->pk.len = RSA_2048_E_BYTE_SIZE;
    returnPairSpec->sk.data = dataD;
    returnPairSpec->sk.len = RSA_2048_D_BYTE_SIZE;
    returnPairSpec->base = rsaCommSpec;
    returnPairSpec->base.base.specType = HCF_KEY_PAIR_SPEC;
}

// ECC spec
static string g_eccAlgName = "ECC";
static string g_eccFieldType = "Fp";
static int32_t g_ecc224CorrectH = 1;

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

static HcfResult ConstructEcc224PubKeyParamsSpec(HcfEccPubKeyParamsSpec **spec)
{
    HcfEccPubKeyParamsSpec *eccPubKeySpec =
        reinterpret_cast<HcfEccPubKeyParamsSpec *>(HcfMalloc(sizeof(HcfEccPubKeyParamsSpec), 0));
    if (eccPubKeySpec == nullptr) {
        return HCF_ERR_MALLOC;
    }
    HcfECFieldFp *tmpField = reinterpret_cast<HcfECFieldFp *>(HcfMalloc(sizeof(HcfECFieldFp), 0));
    if (tmpField == nullptr) {
        HcfFree(eccPubKeySpec);
        return HCF_ERR_MALLOC;
    }

    eccPubKeySpec->base.base.algName = const_cast<char *>(g_eccAlgName.c_str());
    eccPubKeySpec->base.base.specType = HCF_PUBLIC_KEY_SPEC;
    eccPubKeySpec->base.field = reinterpret_cast<HcfECField *>(tmpField);
    eccPubKeySpec->base.field->fieldType = const_cast<char *>(g_eccFieldType.c_str());
    ((HcfECFieldFp *)(eccPubKeySpec->base.field))->p.data =
        (IS_BIG_ENDIAN ? g_ecc224CorrectBigP : g_ecc224CorrectLittleP);
    ((HcfECFieldFp *)(eccPubKeySpec->base.field))->p.len = NID_secp224r1_len;
    eccPubKeySpec->base.a.data = (IS_BIG_ENDIAN ? g_ecc224CorrectBigA : g_ecc224CorrectLittleA);
    eccPubKeySpec->base.a.len = NID_secp224r1_len;
    eccPubKeySpec->base.b.data = (IS_BIG_ENDIAN ? g_ecc224CorrectBigB : g_ecc224CorrectLittleB);
    eccPubKeySpec->base.b.len = NID_secp224r1_len;
    eccPubKeySpec->base.g.x.data = (IS_BIG_ENDIAN ? g_ecc224CorrectBigGX : g_ecc224CorrectLittleGX);
    eccPubKeySpec->base.g.x.len = NID_secp224r1_len;
    eccPubKeySpec->base.g.y.data = (IS_BIG_ENDIAN ? g_ecc224CorrectBigGY : g_ecc224CorrectLittleGY);
    eccPubKeySpec->base.g.y.len = NID_secp224r1_len;
    eccPubKeySpec->base.n.data = (IS_BIG_ENDIAN ? g_ecc224CorrectBigN : g_ecc224CorrectLittleN);
    eccPubKeySpec->base.n.len = NID_secp224r1_len;
    eccPubKeySpec->base.h = g_ecc224CorrectH;
    eccPubKeySpec->pk.x.data = (IS_BIG_ENDIAN ? g_ecc224CorrectBigPkX : g_ecc224CorrectLittlePkX);
    eccPubKeySpec->pk.x.len = NID_secp224r1_len;
    eccPubKeySpec->pk.y.data = (IS_BIG_ENDIAN ? g_ecc224CorrectBigPkY : g_ecc224CorrectLittlePkY);
    eccPubKeySpec->pk.y.len = NID_secp224r1_len;

    *spec = eccPubKeySpec;
    return HCF_SUCCESS;
}

static HcfResult ConstructEcc224PriKeyParamsSpec(HcfEccPriKeyParamsSpec **spec)
{
    HcfEccPriKeyParamsSpec *eccPriKeySpec =
        reinterpret_cast<HcfEccPriKeyParamsSpec *>(HcfMalloc(sizeof(HcfEccPriKeyParamsSpec), 0));
    if (eccPriKeySpec == nullptr) {
        return HCF_ERR_MALLOC;
    }
    HcfECFieldFp *tmpField = reinterpret_cast<HcfECFieldFp *>(HcfMalloc(sizeof(HcfECFieldFp), 0));
    if (tmpField == nullptr) {
        HcfFree(eccPriKeySpec);
        return HCF_ERR_MALLOC;
    }

    eccPriKeySpec->base.base.algName = const_cast<char *>(g_eccAlgName.c_str());
    eccPriKeySpec->base.base.specType = HCF_PRIVATE_KEY_SPEC;
    eccPriKeySpec->base.field = reinterpret_cast<HcfECField *>(tmpField);
    eccPriKeySpec->base.field->fieldType = const_cast<char *>(g_eccFieldType.c_str());
    ((HcfECFieldFp *)(eccPriKeySpec->base.field))->p.data =
        (IS_BIG_ENDIAN ? g_ecc224CorrectBigP : g_ecc224CorrectLittleP);
    ((HcfECFieldFp *)(eccPriKeySpec->base.field))->p.len = NID_secp224r1_len;
    eccPriKeySpec->base.a.data = (IS_BIG_ENDIAN ? g_ecc224CorrectBigA : g_ecc224CorrectLittleA);
    eccPriKeySpec->base.a.len = NID_secp224r1_len;
    eccPriKeySpec->base.b.data = (IS_BIG_ENDIAN ? g_ecc224CorrectBigB : g_ecc224CorrectLittleB);
    eccPriKeySpec->base.b.len = NID_secp224r1_len;
    eccPriKeySpec->base.g.x.data = (IS_BIG_ENDIAN ? g_ecc224CorrectBigGX : g_ecc224CorrectLittleGX);
    eccPriKeySpec->base.g.x.len = NID_secp224r1_len;
    eccPriKeySpec->base.g.y.data = (IS_BIG_ENDIAN ? g_ecc224CorrectBigGY : g_ecc224CorrectLittleGY);
    eccPriKeySpec->base.g.y.len = NID_secp224r1_len;
    eccPriKeySpec->base.n.data = (IS_BIG_ENDIAN ? g_ecc224CorrectBigN : g_ecc224CorrectLittleN);
    eccPriKeySpec->base.n.len = NID_secp224r1_len;
    eccPriKeySpec->base.h = g_ecc224CorrectH;
    eccPriKeySpec->sk.data = (IS_BIG_ENDIAN ? g_ecc224CorrectBigSk : g_ecc224CorrectLittleSk);
    eccPriKeySpec->sk.len = NID_secp224r1_len;

    *spec = eccPriKeySpec;
    return HCF_SUCCESS;
}

static HcfResult ConstructEcc224KeyPairParamsSpec(HcfEccKeyPairParamsSpec **spec)
{
    HcfEccKeyPairParamsSpec *eccKeyPairSpec =
        reinterpret_cast<HcfEccKeyPairParamsSpec *>(HcfMalloc(sizeof(HcfEccKeyPairParamsSpec), 0));
    if (eccKeyPairSpec == nullptr) {
        return HCF_ERR_MALLOC;
    }
    HcfECFieldFp *tmpField = reinterpret_cast<HcfECFieldFp *>(HcfMalloc(sizeof(HcfECFieldFp), 0));
    if (tmpField == nullptr) {
        HcfFree(eccKeyPairSpec);
        return HCF_ERR_MALLOC;
    }

    eccKeyPairSpec->base.base.algName = const_cast<char *>(g_eccAlgName.c_str());
    eccKeyPairSpec->base.base.specType = HCF_KEY_PAIR_SPEC;
    eccKeyPairSpec->base.field = reinterpret_cast<HcfECField *>(tmpField);
    eccKeyPairSpec->base.field->fieldType = const_cast<char *>(g_eccFieldType.c_str());
    ((HcfECFieldFp *)(eccKeyPairSpec->base.field))->p.data =
        (IS_BIG_ENDIAN ? g_ecc224CorrectBigP : g_ecc224CorrectLittleP);
    ((HcfECFieldFp *)(eccKeyPairSpec->base.field))->p.len = NID_secp224r1_len;
    eccKeyPairSpec->base.a.data = (IS_BIG_ENDIAN ? g_ecc224CorrectBigA : g_ecc224CorrectLittleA);
    eccKeyPairSpec->base.a.len = NID_secp224r1_len;
    eccKeyPairSpec->base.b.data = (IS_BIG_ENDIAN ? g_ecc224CorrectBigB : g_ecc224CorrectLittleB);
    eccKeyPairSpec->base.b.len = NID_secp224r1_len;
    eccKeyPairSpec->base.g.x.data = (IS_BIG_ENDIAN ? g_ecc224CorrectBigGX : g_ecc224CorrectLittleGX);
    eccKeyPairSpec->base.g.x.len = NID_secp224r1_len;
    eccKeyPairSpec->base.g.y.data = (IS_BIG_ENDIAN ? g_ecc224CorrectBigGY : g_ecc224CorrectLittleGY);
    eccKeyPairSpec->base.g.y.len = NID_secp224r1_len;
    eccKeyPairSpec->base.n.data = (IS_BIG_ENDIAN ? g_ecc224CorrectBigN : g_ecc224CorrectLittleN);
    eccKeyPairSpec->base.n.len = NID_secp224r1_len;
    eccKeyPairSpec->base.h = g_ecc224CorrectH;
    eccKeyPairSpec->pk.x.data = (IS_BIG_ENDIAN ? g_ecc224CorrectBigPkX : g_ecc224CorrectLittlePkX);
    eccKeyPairSpec->pk.x.len = NID_secp224r1_len;
    eccKeyPairSpec->pk.y.data = (IS_BIG_ENDIAN ? g_ecc224CorrectBigPkY : g_ecc224CorrectLittlePkY);
    eccKeyPairSpec->pk.y.len = NID_secp224r1_len;
    eccKeyPairSpec->sk.data = (IS_BIG_ENDIAN ? g_ecc224CorrectBigSk : g_ecc224CorrectLittleSk);
    eccKeyPairSpec->sk.len = NID_secp224r1_len;

    *spec = eccKeyPairSpec;
    return HCF_SUCCESS;
}

static void FreeEccCommSpec(HcfEccCommParamsSpec *spec)
{
    HcfFree(reinterpret_cast<HcfECFieldFp *>(spec->field));
    HcfFree(spec);
}

static void FreeEccPubSpec(HcfEccPubKeyParamsSpec *spec)
{
    HcfFree(reinterpret_cast<HcfECFieldFp *>(spec->base.field));
    HcfFree(spec);
}

static void FreeEccPriSpec(HcfEccPriKeyParamsSpec *spec)
{
    HcfFree(reinterpret_cast<HcfECFieldFp *>(spec->base.field));
    HcfFree(spec);
}

static void FreeEccKeyPairSpec(HcfEccKeyPairParamsSpec *spec)
{
    HcfFree(reinterpret_cast<HcfECFieldFp *>(spec->base.field));
    HcfFree(spec);
}

// invalid DSA comm spec
HWTEST_F(CryptoAsyKeyGeneratorCovTest, CryptoAsyKeyGeneratorTest001, TestSize.Level0)
{
    HcfAsyKeyGeneratorBySpec *generator = nullptr;
    HcfResult ret = HcfAsyKeyGeneratorBySpecCreate(reinterpret_cast<HcfAsyKeyParamsSpec *>(&dsaCommonSpecNoAlg),
        &generator);
    EXPECT_NE(ret, HCF_SUCCESS);
    EXPECT_EQ(generator, nullptr);
}

HWTEST_F(CryptoAsyKeyGeneratorCovTest, CryptoAsyKeyGeneratorTest002, TestSize.Level0)
{
    HcfAsyKeyGeneratorBySpec *generator = nullptr;
    HcfResult ret = HcfAsyKeyGeneratorBySpecCreate(reinterpret_cast<HcfAsyKeyParamsSpec *>(&dsaCommonSpecErrorAlg),
        &generator);
    EXPECT_NE(ret, HCF_SUCCESS);
    EXPECT_EQ(generator, nullptr);
}

HWTEST_F(CryptoAsyKeyGeneratorCovTest, CryptoAsyKeyGeneratorTest003, TestSize.Level0)
{
    HcfAsyKeyGeneratorBySpec *generator = nullptr;
    HcfResult ret = HcfAsyKeyGeneratorBySpecCreate(reinterpret_cast<HcfAsyKeyParamsSpec *>(&dsaCommonSpecNullG),
        &generator);
    EXPECT_NE(ret, HCF_SUCCESS);
    EXPECT_EQ(generator, nullptr);
}

HWTEST_F(CryptoAsyKeyGeneratorCovTest, CryptoAsyKeyGeneratorTest004, TestSize.Level0)
{
    HcfAsyKeyGeneratorBySpec *generator = nullptr;
    HcfResult ret = HcfAsyKeyGeneratorBySpecCreate(reinterpret_cast<HcfAsyKeyParamsSpec *>(&dsaCommonSpecNullP),
        &generator);
    EXPECT_NE(ret, HCF_SUCCESS);
    EXPECT_EQ(generator, nullptr);
}

HWTEST_F(CryptoAsyKeyGeneratorCovTest, CryptoAsyKeyGeneratorTest005, TestSize.Level0)
{
    HcfAsyKeyGeneratorBySpec *generator = nullptr;
    HcfResult ret = HcfAsyKeyGeneratorBySpecCreate(reinterpret_cast<HcfAsyKeyParamsSpec *>(&dsaCommonSpecNullQ),
        &generator);
    EXPECT_NE(ret, HCF_SUCCESS);
    EXPECT_EQ(generator, nullptr);
}

HWTEST_F(CryptoAsyKeyGeneratorCovTest, CryptoAsyKeyGeneratorTest006, TestSize.Level0)
{
    HcfAsyKeyGeneratorBySpec *generator = nullptr;
    HcfResult ret = HcfAsyKeyGeneratorBySpecCreate(reinterpret_cast<HcfAsyKeyParamsSpec *>(&dsaCommonSpecNoLenG),
        &generator);
    EXPECT_NE(ret, HCF_SUCCESS);
    EXPECT_EQ(generator, nullptr);
}

HWTEST_F(CryptoAsyKeyGeneratorCovTest, CryptoAsyKeyGeneratorTest007, TestSize.Level0)
{
    HcfAsyKeyGeneratorBySpec *generator = nullptr;
    HcfResult ret = HcfAsyKeyGeneratorBySpecCreate(reinterpret_cast<HcfAsyKeyParamsSpec *>(&dsaCommonSpecNoLenP),
        &generator);
    EXPECT_NE(ret, HCF_SUCCESS);
    EXPECT_EQ(generator, nullptr);
}

HWTEST_F(CryptoAsyKeyGeneratorCovTest, CryptoAsyKeyGeneratorTest008, TestSize.Level0)
{
    HcfAsyKeyGeneratorBySpec *generator = nullptr;
    HcfResult ret = HcfAsyKeyGeneratorBySpecCreate(reinterpret_cast<HcfAsyKeyParamsSpec *>(&dsaCommonSpecNoLenQ),
        &generator);
    EXPECT_NE(ret, HCF_SUCCESS);
    EXPECT_EQ(generator, nullptr);
}

// invalid DSA pub spec
HWTEST_F(CryptoAsyKeyGeneratorCovTest, CryptoAsyKeyGeneratorTest009, TestSize.Level0)
{
    HcfAsyKeyGeneratorBySpec *generator = nullptr;
    HcfResult ret = HcfAsyKeyGeneratorBySpecCreate(reinterpret_cast<HcfAsyKeyParamsSpec *>(&dsaPkSpecErrorComm),
        &generator);
    EXPECT_NE(ret, HCF_SUCCESS);
    EXPECT_EQ(generator, nullptr);
}

HWTEST_F(CryptoAsyKeyGeneratorCovTest, CryptoAsyKeyGeneratorTest010, TestSize.Level0)
{
    HcfAsyKeyGeneratorBySpec *generator = nullptr;
    HcfResult ret = HcfAsyKeyGeneratorBySpecCreate(reinterpret_cast<HcfAsyKeyParamsSpec *>(&dsaPkSpecNoLenPk),
        &generator);
    EXPECT_NE(ret, HCF_SUCCESS);
    EXPECT_EQ(generator, nullptr);
}

HWTEST_F(CryptoAsyKeyGeneratorCovTest, CryptoAsyKeyGeneratorTest011, TestSize.Level0)
{
    HcfAsyKeyGeneratorBySpec *generator = nullptr;
    HcfResult ret = HcfAsyKeyGeneratorBySpecCreate(reinterpret_cast<HcfAsyKeyParamsSpec *>(&dsaPkSpecNullPk),
        &generator);
    EXPECT_NE(ret, HCF_SUCCESS);
    EXPECT_EQ(generator, nullptr);
}

// invalid DSA keyPair spec
HWTEST_F(CryptoAsyKeyGeneratorCovTest, CryptoAsyKeyGeneratorTest012, TestSize.Level0)
{
    HcfAsyKeyGeneratorBySpec *generator = nullptr;
    HcfResult ret = HcfAsyKeyGeneratorBySpecCreate(reinterpret_cast<HcfAsyKeyParamsSpec *>(&dsaKeyPairSpecErrorComm),
        &generator);
    EXPECT_NE(ret, HCF_SUCCESS);
    EXPECT_EQ(generator, nullptr);
}

HWTEST_F(CryptoAsyKeyGeneratorCovTest, CryptoAsyKeyGeneratorTest013, TestSize.Level0)
{
    HcfAsyKeyGeneratorBySpec *generator = nullptr;
    HcfResult ret = HcfAsyKeyGeneratorBySpecCreate(
        reinterpret_cast<HcfAsyKeyParamsSpec *>(&dsaKeyPairSpecErrorSpecType), &generator);
    EXPECT_NE(ret, HCF_SUCCESS);
    EXPECT_EQ(generator, nullptr);
}

HWTEST_F(CryptoAsyKeyGeneratorCovTest, CryptoAsyKeyGeneratorTest014, TestSize.Level0)
{
    HcfAsyKeyGeneratorBySpec *generator = nullptr;
    HcfResult ret = HcfAsyKeyGeneratorBySpecCreate(reinterpret_cast<HcfAsyKeyParamsSpec *>(&dsaKeyPairSpecNoLenPk),
        &generator);
    EXPECT_NE(ret, HCF_SUCCESS);
    EXPECT_EQ(generator, nullptr);
}

HWTEST_F(CryptoAsyKeyGeneratorCovTest, CryptoAsyKeyGeneratorTest015, TestSize.Level0)
{
    HcfAsyKeyGeneratorBySpec *generator = nullptr;
    HcfResult ret = HcfAsyKeyGeneratorBySpecCreate(reinterpret_cast<HcfAsyKeyParamsSpec *>(&dsaKeyPairSpecNullPk),
        &generator);
    EXPECT_NE(ret, HCF_SUCCESS);
    EXPECT_EQ(generator, nullptr);
}

HWTEST_F(CryptoAsyKeyGeneratorCovTest, CryptoAsyKeyGeneratorTest016, TestSize.Level0)
{
    HcfAsyKeyGeneratorBySpec *generator = nullptr;
    HcfResult ret = HcfAsyKeyGeneratorBySpecCreate(reinterpret_cast<HcfAsyKeyParamsSpec *>(&dsaKeyPairSpecNoLenSk),
        &generator);
    EXPECT_NE(ret, HCF_SUCCESS);
    EXPECT_EQ(generator, nullptr);
}

HWTEST_F(CryptoAsyKeyGeneratorCovTest, CryptoAsyKeyGeneratorTest017, TestSize.Level0)
{
    HcfAsyKeyGeneratorBySpec *generator = nullptr;
    HcfResult ret = HcfAsyKeyGeneratorBySpecCreate(reinterpret_cast<HcfAsyKeyParamsSpec *>(&dsaKeyPairSpecNullSk),
        &generator);
    EXPECT_NE(ret, HCF_SUCCESS);
    EXPECT_EQ(generator, nullptr);
}

HWTEST_F(CryptoAsyKeyGeneratorCovTest, CryptoAsyKeyGeneratorTest018, TestSize.Level0)
{
    FreeAsyKeySpec(reinterpret_cast<HcfAsyKeyParamsSpec *>(&dsaKeyPairSpecErrorSpecType));
    EXPECT_NE(dsaKeyPairSpecErrorSpecType.base.base.algName, nullptr);
}

// invalid RSA spec type
HWTEST_F(CryptoAsyKeyGeneratorCovTest, CryptoAsyKeyGeneratorTest101, TestSize.Level0)
{
    HcfRsaCommParamsSpec rsaCommSpec = {};
    unsigned char dataN[RSA_2048_N_BYTE_SIZE] = {0};
    GenerateRsa2048CorrectCommonKeySpec(dataN, &rsaCommSpec);
    rsaCommSpec.base.specType = HCF_PRIVATE_KEY_SPEC;

    HcfAsyKeyGeneratorBySpec *generator = nullptr;
    HcfResult res = HcfAsyKeyGeneratorBySpecCreate(reinterpret_cast<HcfAsyKeyParamsSpec *>(&rsaCommSpec), &generator);
    EXPECT_NE(res, HCF_SUCCESS);
    EXPECT_EQ(generator, nullptr);

    HcfObjDestroy(generator);
}

// invalid RSA comm spec
HWTEST_F(CryptoAsyKeyGeneratorCovTest, CryptoAsyKeyGeneratorTest102, TestSize.Level0)
{
    HcfRsaCommParamsSpec rsaCommSpec = {};
    unsigned char dataN[RSA_2048_N_BYTE_SIZE] = {0};
    GenerateRsa2048CorrectCommonKeySpec(dataN, &rsaCommSpec);
    rsaCommSpec.n.data = nullptr;

    HcfAsyKeyGeneratorBySpec *generator = nullptr;
    HcfResult res = HcfAsyKeyGeneratorBySpecCreate(reinterpret_cast<HcfAsyKeyParamsSpec *>(&rsaCommSpec), &generator);
    EXPECT_NE(res, HCF_SUCCESS);
    EXPECT_EQ(generator, nullptr);

    HcfObjDestroy(generator);
}

HWTEST_F(CryptoAsyKeyGeneratorCovTest, CryptoAsyKeyGeneratorTest103, TestSize.Level0)
{
    HcfRsaCommParamsSpec rsaCommSpec = {};
    unsigned char dataN[RSA_2048_N_BYTE_SIZE] = {0};
    GenerateRsa2048CorrectCommonKeySpec(dataN, &rsaCommSpec);
    rsaCommSpec.n.len = 0;

    HcfAsyKeyGeneratorBySpec *generator = nullptr;
    HcfResult res = HcfAsyKeyGeneratorBySpecCreate(reinterpret_cast<HcfAsyKeyParamsSpec *>(&rsaCommSpec), &generator);
    EXPECT_NE(res, HCF_SUCCESS);
    EXPECT_EQ(generator, nullptr);

    HcfObjDestroy(generator);
}

// invalid RSA pubKey spec
HWTEST_F(CryptoAsyKeyGeneratorCovTest, CryptoAsyKeyGeneratorTest104, TestSize.Level0)
{
    HcfRsaPubKeyParamsSpec rsaPubKeySpec = {};
    unsigned char dataN[RSA_2048_N_BYTE_SIZE] = {0};
    unsigned char dataE[RSA_2048_E_BYTE_SIZE] = {0};
    GenerateRsa2048CorrectPubKeySpec(dataN, dataE, &rsaPubKeySpec);
    rsaPubKeySpec.base.n.data = nullptr;

    HcfAsyKeyGeneratorBySpec *generator = nullptr;
    HcfResult res = HcfAsyKeyGeneratorBySpecCreate(reinterpret_cast<HcfAsyKeyParamsSpec *>(&rsaPubKeySpec), &generator);
    EXPECT_NE(res, HCF_SUCCESS);
    EXPECT_EQ(generator, nullptr);

    HcfObjDestroy(generator);
}

HWTEST_F(CryptoAsyKeyGeneratorCovTest, CryptoAsyKeyGeneratorTest105, TestSize.Level0)
{
    HcfRsaPubKeyParamsSpec rsaPubKeySpec = {};
    unsigned char dataN[RSA_2048_N_BYTE_SIZE] = {0};
    unsigned char dataE[RSA_2048_E_BYTE_SIZE] = {0};
    GenerateRsa2048CorrectPubKeySpec(dataN, dataE, &rsaPubKeySpec);
    rsaPubKeySpec.pk.data = nullptr;

    HcfAsyKeyGeneratorBySpec *generator = nullptr;
    HcfResult res = HcfAsyKeyGeneratorBySpecCreate(reinterpret_cast<HcfAsyKeyParamsSpec *>(&rsaPubKeySpec), &generator);
    EXPECT_NE(res, HCF_SUCCESS);
    EXPECT_EQ(generator, nullptr);

    HcfObjDestroy(generator);
}

HWTEST_F(CryptoAsyKeyGeneratorCovTest, CryptoAsyKeyGeneratorTest106, TestSize.Level0)
{
    HcfRsaPubKeyParamsSpec rsaPubKeySpec = {};
    unsigned char dataN[RSA_2048_N_BYTE_SIZE] = {0};
    unsigned char dataE[RSA_2048_E_BYTE_SIZE] = {0};
    GenerateRsa2048CorrectPubKeySpec(dataN, dataE, &rsaPubKeySpec);
    rsaPubKeySpec.pk.len = 0;

    HcfAsyKeyGeneratorBySpec *generator = nullptr;
    HcfResult res = HcfAsyKeyGeneratorBySpecCreate(reinterpret_cast<HcfAsyKeyParamsSpec *>(&rsaPubKeySpec), &generator);
    EXPECT_NE(res, HCF_SUCCESS);
    EXPECT_EQ(generator, nullptr);

    HcfObjDestroy(generator);
}

// invalid RSA keyPair spec
HWTEST_F(CryptoAsyKeyGeneratorCovTest, CryptoAsyKeyGeneratorTest107, TestSize.Level0)
{
    HcfRsaKeyPairParamsSpec rsaPairSpec = {};
    unsigned char dataN[RSA_2048_N_BYTE_SIZE] = {0};
    unsigned char dataE[RSA_2048_E_BYTE_SIZE] = {0};
    unsigned char dataD[RSA_2048_D_BYTE_SIZE] = {0};
    GenerateRsa2048CorrectKeyPairSpec(dataN, dataE, dataD, &rsaPairSpec);
    rsaPairSpec.base.n.data = nullptr;

    HcfAsyKeyGeneratorBySpec *generator = nullptr;
    HcfResult res = HcfAsyKeyGeneratorBySpecCreate(reinterpret_cast<HcfAsyKeyParamsSpec *>(&rsaPairSpec), &generator);
    EXPECT_NE(res, HCF_SUCCESS);
    EXPECT_EQ(generator, nullptr);

    HcfObjDestroy(generator);
}

HWTEST_F(CryptoAsyKeyGeneratorCovTest, CryptoAsyKeyGeneratorTest108, TestSize.Level0)
{
    HcfRsaKeyPairParamsSpec rsaPairSpec = {};
    unsigned char dataN[RSA_2048_N_BYTE_SIZE] = {0};
    unsigned char dataE[RSA_2048_E_BYTE_SIZE] = {0};
    unsigned char dataD[RSA_2048_D_BYTE_SIZE] = {0};
    GenerateRsa2048CorrectKeyPairSpec(dataN, dataE, dataD, &rsaPairSpec);
    rsaPairSpec.pk.data = nullptr;

    HcfAsyKeyGeneratorBySpec *generator = nullptr;
    HcfResult res = HcfAsyKeyGeneratorBySpecCreate(reinterpret_cast<HcfAsyKeyParamsSpec *>(&rsaPairSpec), &generator);
    EXPECT_NE(res, HCF_SUCCESS);
    EXPECT_EQ(generator, nullptr);

    HcfObjDestroy(generator);
}

HWTEST_F(CryptoAsyKeyGeneratorCovTest, CryptoAsyKeyGeneratorTest109, TestSize.Level0)
{
    HcfRsaKeyPairParamsSpec rsaPairSpec = {};
    unsigned char dataN[RSA_2048_N_BYTE_SIZE] = {0};
    unsigned char dataE[RSA_2048_E_BYTE_SIZE] = {0};
    unsigned char dataD[RSA_2048_D_BYTE_SIZE] = {0};
    GenerateRsa2048CorrectKeyPairSpec(dataN, dataE, dataD, &rsaPairSpec);
    rsaPairSpec.pk.len = 0;

    HcfAsyKeyGeneratorBySpec *generator = nullptr;
    HcfResult res = HcfAsyKeyGeneratorBySpecCreate(reinterpret_cast<HcfAsyKeyParamsSpec *>(&rsaPairSpec), &generator);
    EXPECT_NE(res, HCF_SUCCESS);
    EXPECT_EQ(generator, nullptr);

    HcfObjDestroy(generator);
}

HWTEST_F(CryptoAsyKeyGeneratorCovTest, CryptoAsyKeyGeneratorTest110, TestSize.Level0)
{
    HcfRsaKeyPairParamsSpec rsaPairSpec = {};
    unsigned char dataN[RSA_2048_N_BYTE_SIZE] = {0};
    unsigned char dataE[RSA_2048_E_BYTE_SIZE] = {0};
    unsigned char dataD[RSA_2048_D_BYTE_SIZE] = {0};
    GenerateRsa2048CorrectKeyPairSpec(dataN, dataE, dataD, &rsaPairSpec);
    rsaPairSpec.sk.data = nullptr;

    HcfAsyKeyGeneratorBySpec *generator = nullptr;
    HcfResult res = HcfAsyKeyGeneratorBySpecCreate(reinterpret_cast<HcfAsyKeyParamsSpec *>(&rsaPairSpec), &generator);
    EXPECT_NE(res, HCF_SUCCESS);
    EXPECT_EQ(generator, nullptr);

    HcfObjDestroy(generator);
}

HWTEST_F(CryptoAsyKeyGeneratorCovTest, CryptoAsyKeyGeneratorTest111, TestSize.Level0)
{
    HcfRsaKeyPairParamsSpec rsaPairSpec = {};
    unsigned char dataN[RSA_2048_N_BYTE_SIZE] = {0};
    unsigned char dataE[RSA_2048_E_BYTE_SIZE] = {0};
    unsigned char dataD[RSA_2048_D_BYTE_SIZE] = {0};
    GenerateRsa2048CorrectKeyPairSpec(dataN, dataE, dataD, &rsaPairSpec);
    rsaPairSpec.sk.len = 0;

    HcfAsyKeyGeneratorBySpec *generator = nullptr;
    HcfResult res = HcfAsyKeyGeneratorBySpecCreate(reinterpret_cast<HcfAsyKeyParamsSpec *>(&rsaPairSpec), &generator);
    EXPECT_NE(res, HCF_SUCCESS);
    EXPECT_EQ(generator, nullptr);

    HcfObjDestroy(generator);
}

// invalid RSA free
HWTEST_F(CryptoAsyKeyGeneratorCovTest, CryptoAsyKeyGeneratorTest112, TestSize.Level0)
{
    HcfRsaCommParamsSpec rsaCommSpec = {};
    unsigned char dataN[RSA_2048_N_BYTE_SIZE] = {0};
    GenerateRsa2048CorrectCommonKeySpec(dataN, &rsaCommSpec);

    rsaCommSpec.base.specType = HCF_PRIVATE_KEY_SPEC;
    FreeAsyKeySpec(reinterpret_cast<HcfAsyKeyParamsSpec *>(&rsaCommSpec));
    EXPECT_NE(rsaCommSpec.base.algName, nullptr);
}

HWTEST_F(CryptoAsyKeyGeneratorCovTest, CryptoAsyKeyGeneratorTest113, TestSize.Level0)
{
    HcfRsaCommParamsSpec rsaCommSpec = {};
    unsigned char dataN[RSA_2048_N_BYTE_SIZE] = {0};
    GenerateRsa2048CorrectCommonKeySpec(dataN, &rsaCommSpec);

    rsaCommSpec.base.algName = const_cast<char *>(g_invalidAlgName);
    FreeAsyKeySpec(reinterpret_cast<HcfAsyKeyParamsSpec *>(&rsaCommSpec));
    EXPECT_NE(rsaCommSpec.base.algName, nullptr);
}

HWTEST_F(CryptoAsyKeyGeneratorCovTest, CryptoAsyKeyGeneratorTest114, TestSize.Level0)
{
    HcfRsaCommParamsSpec rsaCommSpec = {};
    unsigned char dataN[RSA_2048_N_BYTE_SIZE] = {0};
    GenerateRsa2048CorrectCommonKeySpec(dataN, &rsaCommSpec);

    rsaCommSpec.base.specType = HCF_PRIVATE_KEY_SPEC;
    FreeAsyKeySpec(reinterpret_cast<HcfAsyKeyParamsSpec *>(&rsaCommSpec));
    EXPECT_NE(rsaCommSpec.base.algName, nullptr);
}

HWTEST_F(CryptoAsyKeyGeneratorCovTest, CryptoAsyKeyGeneratorTest115, TestSize.Level0)
{
    HcfRsaCommParamsSpec rsaCommSpec = {};
    unsigned char dataN[RSA_2048_N_BYTE_SIZE] = {0};
    GenerateRsa2048CorrectCommonKeySpec(dataN, &rsaCommSpec);

    rsaCommSpec.base.algName = nullptr;
    FreeAsyKeySpec(reinterpret_cast<HcfAsyKeyParamsSpec *>(&rsaCommSpec));
    EXPECT_EQ(rsaCommSpec.base.algName, nullptr);
}

HWTEST_F(CryptoAsyKeyGeneratorCovTest, CryptoAsyKeyGeneratorTest116, TestSize.Level0)
{
    HcfRsaCommParamsSpec *rsaCommSpec = nullptr;
    FreeAsyKeySpec(reinterpret_cast<HcfAsyKeyParamsSpec *>(rsaCommSpec));
    EXPECT_EQ(rsaCommSpec, nullptr);
}

// invalid ECC spec type
HWTEST_F(CryptoAsyKeyGeneratorCovTest, CryptoAsyKeyGeneratorTest201, TestSize.Level0)
{
    HcfEccCommParamsSpec *eccCommSpec = nullptr;
    HcfResult res = ConstructEcc224CommParamsSpec(&eccCommSpec);
    EXPECT_EQ(res, HCF_SUCCESS);

    eccCommSpec->base.specType = HcfAsyKeySpecType(INVALID_SPEC_TYPE);
    HcfAsyKeyGeneratorBySpec *generator = nullptr;
    res = HcfAsyKeyGeneratorBySpecCreate(reinterpret_cast<HcfAsyKeyParamsSpec *>(eccCommSpec), &generator);
    EXPECT_NE(res, HCF_SUCCESS);
    EXPECT_EQ(generator, nullptr);

    FreeEccCommSpec(eccCommSpec);
    HcfObjDestroy(generator);
}

// invalid ECC Comm spec
HWTEST_F(CryptoAsyKeyGeneratorCovTest, CryptoAsyKeyGeneratorTest202, TestSize.Level0)
{
    HcfEccCommParamsSpec *eccCommSpec = nullptr;
    HcfResult res = ConstructEcc224CommParamsSpec(&eccCommSpec);
    EXPECT_EQ(res, HCF_SUCCESS);

    eccCommSpec->a.data = nullptr;
    HcfAsyKeyGeneratorBySpec *generator = nullptr;
    res = HcfAsyKeyGeneratorBySpecCreate(reinterpret_cast<HcfAsyKeyParamsSpec *>(eccCommSpec), &generator);
    EXPECT_NE(res, HCF_SUCCESS);
    EXPECT_EQ(generator, nullptr);

    FreeEccCommSpec(eccCommSpec);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoAsyKeyGeneratorCovTest, CryptoAsyKeyGeneratorTest203, TestSize.Level0)
{
    HcfEccCommParamsSpec *eccCommSpec = nullptr;
    HcfResult res = ConstructEcc224CommParamsSpec(&eccCommSpec);
    EXPECT_EQ(res, HCF_SUCCESS);

    eccCommSpec->a.len = 0;
    HcfAsyKeyGeneratorBySpec *generator = nullptr;
    res = HcfAsyKeyGeneratorBySpecCreate(reinterpret_cast<HcfAsyKeyParamsSpec *>(eccCommSpec), &generator);
    EXPECT_NE(res, HCF_SUCCESS);
    EXPECT_EQ(generator, nullptr);

    FreeEccCommSpec(eccCommSpec);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoAsyKeyGeneratorCovTest, CryptoAsyKeyGeneratorTest204, TestSize.Level0)
{
    HcfEccCommParamsSpec *eccCommSpec = nullptr;
    HcfResult res = ConstructEcc224CommParamsSpec(&eccCommSpec);
    EXPECT_EQ(res, HCF_SUCCESS);

    eccCommSpec->b.data = nullptr;
    HcfAsyKeyGeneratorBySpec *generator = nullptr;
    res = HcfAsyKeyGeneratorBySpecCreate(reinterpret_cast<HcfAsyKeyParamsSpec *>(eccCommSpec), &generator);
    EXPECT_NE(res, HCF_SUCCESS);
    EXPECT_EQ(generator, nullptr);

    FreeEccCommSpec(eccCommSpec);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoAsyKeyGeneratorCovTest, CryptoAsyKeyGeneratorTest205, TestSize.Level0)
{
    HcfEccCommParamsSpec *eccCommSpec = nullptr;
    HcfResult res = ConstructEcc224CommParamsSpec(&eccCommSpec);
    EXPECT_EQ(res, HCF_SUCCESS);

    eccCommSpec->b.len = 0;
    HcfAsyKeyGeneratorBySpec *generator = nullptr;
    res = HcfAsyKeyGeneratorBySpecCreate(reinterpret_cast<HcfAsyKeyParamsSpec *>(eccCommSpec), &generator);
    EXPECT_NE(res, HCF_SUCCESS);
    EXPECT_EQ(generator, nullptr);

    FreeEccCommSpec(eccCommSpec);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoAsyKeyGeneratorCovTest, CryptoAsyKeyGeneratorTest206, TestSize.Level0)
{
    HcfEccCommParamsSpec *eccCommSpec = nullptr;
    HcfResult res = ConstructEcc224CommParamsSpec(&eccCommSpec);
    EXPECT_EQ(res, HCF_SUCCESS);

    eccCommSpec->n.data = nullptr;
    HcfAsyKeyGeneratorBySpec *generator = nullptr;
    res = HcfAsyKeyGeneratorBySpecCreate(reinterpret_cast<HcfAsyKeyParamsSpec *>(eccCommSpec), &generator);
    EXPECT_NE(res, HCF_SUCCESS);
    EXPECT_EQ(generator, nullptr);

    FreeEccCommSpec(eccCommSpec);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoAsyKeyGeneratorCovTest, CryptoAsyKeyGeneratorTest207, TestSize.Level0)
{
    HcfEccCommParamsSpec *eccCommSpec = nullptr;
    HcfResult res = ConstructEcc224CommParamsSpec(&eccCommSpec);
    EXPECT_EQ(res, HCF_SUCCESS);

    eccCommSpec->n.len = 0;
    HcfAsyKeyGeneratorBySpec *generator = nullptr;
    res = HcfAsyKeyGeneratorBySpecCreate(reinterpret_cast<HcfAsyKeyParamsSpec *>(eccCommSpec), &generator);
    EXPECT_NE(res, HCF_SUCCESS);
    EXPECT_EQ(generator, nullptr);

    FreeEccCommSpec(eccCommSpec);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoAsyKeyGeneratorCovTest, CryptoAsyKeyGeneratorTest208, TestSize.Level0)
{
    HcfEccCommParamsSpec *eccCommSpec = nullptr;
    HcfResult res = ConstructEcc224CommParamsSpec(&eccCommSpec);
    EXPECT_EQ(res, HCF_SUCCESS);

    eccCommSpec->g.x.data = nullptr;
    HcfAsyKeyGeneratorBySpec *generator = nullptr;
    res = HcfAsyKeyGeneratorBySpecCreate(reinterpret_cast<HcfAsyKeyParamsSpec *>(eccCommSpec), &generator);
    EXPECT_NE(res, HCF_SUCCESS);
    EXPECT_EQ(generator, nullptr);

    FreeEccCommSpec(eccCommSpec);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoAsyKeyGeneratorCovTest, CryptoAsyKeyGeneratorTest209, TestSize.Level0)
{
    HcfEccCommParamsSpec *eccCommSpec = nullptr;
    HcfResult res = ConstructEcc224CommParamsSpec(&eccCommSpec);
    EXPECT_EQ(res, HCF_SUCCESS);

    eccCommSpec->g.x.len = 0;
    HcfAsyKeyGeneratorBySpec *generator = nullptr;
    res = HcfAsyKeyGeneratorBySpecCreate(reinterpret_cast<HcfAsyKeyParamsSpec *>(eccCommSpec), &generator);
    EXPECT_NE(res, HCF_SUCCESS);
    EXPECT_EQ(generator, nullptr);

    FreeEccCommSpec(eccCommSpec);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoAsyKeyGeneratorCovTest, CryptoAsyKeyGeneratorTest210, TestSize.Level0)
{
    HcfEccCommParamsSpec *eccCommSpec = nullptr;
    HcfResult res = ConstructEcc224CommParamsSpec(&eccCommSpec);
    EXPECT_EQ(res, HCF_SUCCESS);

    eccCommSpec->g.y.data = nullptr;
    HcfAsyKeyGeneratorBySpec *generator = nullptr;
    res = HcfAsyKeyGeneratorBySpecCreate(reinterpret_cast<HcfAsyKeyParamsSpec *>(eccCommSpec), &generator);
    EXPECT_NE(res, HCF_SUCCESS);
    EXPECT_EQ(generator, nullptr);

    FreeEccCommSpec(eccCommSpec);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoAsyKeyGeneratorCovTest, CryptoAsyKeyGeneratorTest211, TestSize.Level0)
{
    HcfEccCommParamsSpec *eccCommSpec = nullptr;
    HcfResult res = ConstructEcc224CommParamsSpec(&eccCommSpec);
    EXPECT_EQ(res, HCF_SUCCESS);

    eccCommSpec->g.y.len = 0;
    HcfAsyKeyGeneratorBySpec *generator = nullptr;
    res = HcfAsyKeyGeneratorBySpecCreate(reinterpret_cast<HcfAsyKeyParamsSpec *>(eccCommSpec), &generator);
    EXPECT_NE(res, HCF_SUCCESS);
    EXPECT_EQ(generator, nullptr);

    FreeEccCommSpec(eccCommSpec);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoAsyKeyGeneratorCovTest, CryptoAsyKeyGeneratorTest212, TestSize.Level0)
{
    HcfEccCommParamsSpec *eccCommSpec = nullptr;
    HcfResult res = ConstructEcc224CommParamsSpec(&eccCommSpec);
    EXPECT_EQ(res, HCF_SUCCESS);

    HcfFree(eccCommSpec->field);
    eccCommSpec->field = nullptr;
    HcfAsyKeyGeneratorBySpec *generator = nullptr;
    res = HcfAsyKeyGeneratorBySpecCreate(reinterpret_cast<HcfAsyKeyParamsSpec *>(eccCommSpec), &generator);
    EXPECT_NE(res, HCF_SUCCESS);
    EXPECT_EQ(generator, nullptr);

    FreeEccCommSpec(eccCommSpec);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoAsyKeyGeneratorCovTest, CryptoAsyKeyGeneratorTest213, TestSize.Level0)
{
    HcfEccCommParamsSpec *eccCommSpec = nullptr;
    HcfResult res = ConstructEcc224CommParamsSpec(&eccCommSpec);
    EXPECT_EQ(res, HCF_SUCCESS);

    eccCommSpec->field->fieldType = const_cast<char *>(g_eccAlgName.c_str());
    HcfAsyKeyGeneratorBySpec *generator = nullptr;
    res = HcfAsyKeyGeneratorBySpecCreate(reinterpret_cast<HcfAsyKeyParamsSpec *>(eccCommSpec), &generator);
    EXPECT_NE(res, HCF_SUCCESS);
    EXPECT_EQ(generator, nullptr);

    FreeEccCommSpec(eccCommSpec);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoAsyKeyGeneratorCovTest, CryptoAsyKeyGeneratorTest214, TestSize.Level0)
{
    HcfEccCommParamsSpec *eccCommSpec = nullptr;
    HcfResult res = ConstructEcc224CommParamsSpec(&eccCommSpec);
    EXPECT_EQ(res, HCF_SUCCESS);

    HcfECFieldFp *tmp = reinterpret_cast<HcfECFieldFp *>(eccCommSpec->field);
    tmp->p.data = nullptr;
    HcfAsyKeyGeneratorBySpec *generator = nullptr;
    res = HcfAsyKeyGeneratorBySpecCreate(reinterpret_cast<HcfAsyKeyParamsSpec *>(eccCommSpec), &generator);
    EXPECT_NE(res, HCF_SUCCESS);
    EXPECT_EQ(generator, nullptr);

    FreeEccCommSpec(eccCommSpec);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoAsyKeyGeneratorCovTest, CryptoAsyKeyGeneratorTest215, TestSize.Level0)
{
    HcfEccCommParamsSpec *eccCommSpec = nullptr;
    HcfResult res = ConstructEcc224CommParamsSpec(&eccCommSpec);
    EXPECT_EQ(res, HCF_SUCCESS);

    HcfECFieldFp *tmp = reinterpret_cast<HcfECFieldFp *>(eccCommSpec->field);
    tmp->p.len = 0;
    HcfAsyKeyGeneratorBySpec *generator = nullptr;
    res = HcfAsyKeyGeneratorBySpecCreate(reinterpret_cast<HcfAsyKeyParamsSpec *>(eccCommSpec), &generator);
    EXPECT_NE(res, HCF_SUCCESS);
    EXPECT_EQ(generator, nullptr);

    FreeEccCommSpec(eccCommSpec);
    HcfObjDestroy(generator);
}

// invalid ECC pubKey spec
HWTEST_F(CryptoAsyKeyGeneratorCovTest, CryptoAsyKeyGeneratorTest216, TestSize.Level0)
{
    HcfEccPubKeyParamsSpec *eccPubSpec = nullptr;
    HcfResult res = ConstructEcc224PubKeyParamsSpec(&eccPubSpec);
    EXPECT_EQ(res, HCF_SUCCESS);

    eccPubSpec->base.a.data = nullptr;
    HcfAsyKeyGeneratorBySpec *generator = nullptr;
    res = HcfAsyKeyGeneratorBySpecCreate(reinterpret_cast<HcfAsyKeyParamsSpec *>(eccPubSpec), &generator);
    EXPECT_NE(res, HCF_SUCCESS);
    EXPECT_EQ(generator, nullptr);

    FreeEccPubSpec(eccPubSpec);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoAsyKeyGeneratorCovTest, CryptoAsyKeyGeneratorTest217, TestSize.Level0)
{
    HcfEccPubKeyParamsSpec *eccPubSpec = nullptr;
    HcfResult res = ConstructEcc224PubKeyParamsSpec(&eccPubSpec);
    EXPECT_EQ(res, HCF_SUCCESS);

    eccPubSpec->pk.x.data = nullptr;
    HcfAsyKeyGeneratorBySpec *generator = nullptr;
    res = HcfAsyKeyGeneratorBySpecCreate(reinterpret_cast<HcfAsyKeyParamsSpec *>(eccPubSpec), &generator);
    EXPECT_NE(res, HCF_SUCCESS);
    EXPECT_EQ(generator, nullptr);

    FreeEccPubSpec(eccPubSpec);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoAsyKeyGeneratorCovTest, CryptoAsyKeyGeneratorTest218, TestSize.Level0)
{
    HcfEccPubKeyParamsSpec *eccPubSpec = nullptr;
    HcfResult res = ConstructEcc224PubKeyParamsSpec(&eccPubSpec);
    EXPECT_EQ(res, HCF_SUCCESS);

    eccPubSpec->pk.x.len = 0;
    HcfAsyKeyGeneratorBySpec *generator = nullptr;
    res = HcfAsyKeyGeneratorBySpecCreate(reinterpret_cast<HcfAsyKeyParamsSpec *>(eccPubSpec), &generator);
    EXPECT_NE(res, HCF_SUCCESS);
    EXPECT_EQ(generator, nullptr);

    FreeEccPubSpec(eccPubSpec);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoAsyKeyGeneratorCovTest, CryptoAsyKeyGeneratorTest219, TestSize.Level0)
{
    HcfEccPubKeyParamsSpec *eccPubSpec = nullptr;
    HcfResult res = ConstructEcc224PubKeyParamsSpec(&eccPubSpec);
    EXPECT_EQ(res, HCF_SUCCESS);

    eccPubSpec->pk.y.data = nullptr;
    HcfAsyKeyGeneratorBySpec *generator = nullptr;
    res = HcfAsyKeyGeneratorBySpecCreate(reinterpret_cast<HcfAsyKeyParamsSpec *>(eccPubSpec), &generator);
    EXPECT_NE(res, HCF_SUCCESS);
    EXPECT_EQ(generator, nullptr);

    FreeEccPubSpec(eccPubSpec);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoAsyKeyGeneratorCovTest, CryptoAsyKeyGeneratorTest220, TestSize.Level0)
{
    HcfEccPubKeyParamsSpec *eccPubSpec = nullptr;
    HcfResult res = ConstructEcc224PubKeyParamsSpec(&eccPubSpec);
    EXPECT_EQ(res, HCF_SUCCESS);

    eccPubSpec->pk.y.len = 0;
    HcfAsyKeyGeneratorBySpec *generator = nullptr;
    res = HcfAsyKeyGeneratorBySpecCreate(reinterpret_cast<HcfAsyKeyParamsSpec *>(eccPubSpec), &generator);
    EXPECT_NE(res, HCF_SUCCESS);
    EXPECT_EQ(generator, nullptr);

    FreeEccPubSpec(eccPubSpec);
    HcfObjDestroy(generator);
}

// invalid ECC priKey spec
HWTEST_F(CryptoAsyKeyGeneratorCovTest, CryptoAsyKeyGeneratorTest221, TestSize.Level0)
{
    HcfEccPriKeyParamsSpec *eccPriSpec = nullptr;
    HcfResult res = ConstructEcc224PriKeyParamsSpec(&eccPriSpec);
    EXPECT_EQ(res, HCF_SUCCESS);

    eccPriSpec->base.a.data = nullptr;
    HcfAsyKeyGeneratorBySpec *generator = nullptr;
    res = HcfAsyKeyGeneratorBySpecCreate(reinterpret_cast<HcfAsyKeyParamsSpec *>(eccPriSpec), &generator);
    EXPECT_NE(res, HCF_SUCCESS);
    EXPECT_EQ(generator, nullptr);

    FreeEccPriSpec(eccPriSpec);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoAsyKeyGeneratorCovTest, CryptoAsyKeyGeneratorTest222, TestSize.Level0)
{
    HcfEccPriKeyParamsSpec *eccPriSpec = nullptr;
    HcfResult res = ConstructEcc224PriKeyParamsSpec(&eccPriSpec);
    EXPECT_EQ(res, HCF_SUCCESS);

    eccPriSpec->sk.data = nullptr;
    HcfAsyKeyGeneratorBySpec *generator = nullptr;
    res = HcfAsyKeyGeneratorBySpecCreate(reinterpret_cast<HcfAsyKeyParamsSpec *>(eccPriSpec), &generator);
    EXPECT_NE(res, HCF_SUCCESS);
    EXPECT_EQ(generator, nullptr);

    FreeEccPriSpec(eccPriSpec);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoAsyKeyGeneratorCovTest, CryptoAsyKeyGeneratorTest223, TestSize.Level0)
{
    HcfEccPriKeyParamsSpec *eccPriSpec = nullptr;
    HcfResult res = ConstructEcc224PriKeyParamsSpec(&eccPriSpec);
    EXPECT_EQ(res, HCF_SUCCESS);

    eccPriSpec->sk.len = 0;
    HcfAsyKeyGeneratorBySpec *generator = nullptr;
    res = HcfAsyKeyGeneratorBySpecCreate(reinterpret_cast<HcfAsyKeyParamsSpec *>(eccPriSpec), &generator);
    EXPECT_NE(res, HCF_SUCCESS);
    EXPECT_EQ(generator, nullptr);

    FreeEccPriSpec(eccPriSpec);
    HcfObjDestroy(generator);
}

// invalid ECC keyPair spec
HWTEST_F(CryptoAsyKeyGeneratorCovTest, CryptoAsyKeyGeneratorTest224, TestSize.Level0)
{
    HcfEccKeyPairParamsSpec *eccKeyPairSpec = nullptr;
    HcfResult res = ConstructEcc224KeyPairParamsSpec(&eccKeyPairSpec);
    EXPECT_EQ(res, HCF_SUCCESS);

    eccKeyPairSpec->base.a.data = nullptr;
    HcfAsyKeyGeneratorBySpec *generator = nullptr;
    res = HcfAsyKeyGeneratorBySpecCreate(reinterpret_cast<HcfAsyKeyParamsSpec *>(eccKeyPairSpec), &generator);
    EXPECT_NE(res, HCF_SUCCESS);
    EXPECT_EQ(generator, nullptr);

    FreeEccKeyPairSpec(eccKeyPairSpec);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoAsyKeyGeneratorCovTest, CryptoAsyKeyGeneratorTest225, TestSize.Level0)
{
    HcfEccKeyPairParamsSpec *eccKeyPairSpec = nullptr;
    HcfResult res = ConstructEcc224KeyPairParamsSpec(&eccKeyPairSpec);
    EXPECT_EQ(res, HCF_SUCCESS);

    eccKeyPairSpec->pk.x.data = nullptr;
    HcfAsyKeyGeneratorBySpec *generator = nullptr;
    res = HcfAsyKeyGeneratorBySpecCreate(reinterpret_cast<HcfAsyKeyParamsSpec *>(eccKeyPairSpec), &generator);
    EXPECT_NE(res, HCF_SUCCESS);
    EXPECT_EQ(generator, nullptr);

    FreeEccKeyPairSpec(eccKeyPairSpec);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoAsyKeyGeneratorCovTest, CryptoAsyKeyGeneratorTest226, TestSize.Level0)
{
    HcfEccKeyPairParamsSpec *eccKeyPairSpec = nullptr;
    HcfResult res = ConstructEcc224KeyPairParamsSpec(&eccKeyPairSpec);
    EXPECT_EQ(res, HCF_SUCCESS);

    eccKeyPairSpec->pk.x.len = 0;
    HcfAsyKeyGeneratorBySpec *generator = nullptr;
    res = HcfAsyKeyGeneratorBySpecCreate(reinterpret_cast<HcfAsyKeyParamsSpec *>(eccKeyPairSpec), &generator);
    EXPECT_NE(res, HCF_SUCCESS);
    EXPECT_EQ(generator, nullptr);

    FreeEccKeyPairSpec(eccKeyPairSpec);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoAsyKeyGeneratorCovTest, CryptoAsyKeyGeneratorTest227, TestSize.Level0)
{
    HcfEccKeyPairParamsSpec *eccKeyPairSpec = nullptr;
    HcfResult res = ConstructEcc224KeyPairParamsSpec(&eccKeyPairSpec);
    EXPECT_EQ(res, HCF_SUCCESS);

    eccKeyPairSpec->pk.y.data = nullptr;
    HcfAsyKeyGeneratorBySpec *generator = nullptr;
    res = HcfAsyKeyGeneratorBySpecCreate(reinterpret_cast<HcfAsyKeyParamsSpec *>(eccKeyPairSpec), &generator);
    EXPECT_NE(res, HCF_SUCCESS);
    EXPECT_EQ(generator, nullptr);

    FreeEccKeyPairSpec(eccKeyPairSpec);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoAsyKeyGeneratorCovTest, CryptoAsyKeyGeneratorTest228, TestSize.Level0)
{
    HcfEccKeyPairParamsSpec *eccKeyPairSpec = nullptr;
    HcfResult res = ConstructEcc224KeyPairParamsSpec(&eccKeyPairSpec);
    EXPECT_EQ(res, HCF_SUCCESS);

    eccKeyPairSpec->pk.y.len = 0;
    HcfAsyKeyGeneratorBySpec *generator = nullptr;
    res = HcfAsyKeyGeneratorBySpecCreate(reinterpret_cast<HcfAsyKeyParamsSpec *>(eccKeyPairSpec), &generator);
    EXPECT_NE(res, HCF_SUCCESS);
    EXPECT_EQ(generator, nullptr);

    FreeEccKeyPairSpec(eccKeyPairSpec);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoAsyKeyGeneratorCovTest, CryptoAsyKeyGeneratorTest229, TestSize.Level0)
{
    HcfEccKeyPairParamsSpec *eccKeyPairSpec = nullptr;
    HcfResult res = ConstructEcc224KeyPairParamsSpec(&eccKeyPairSpec);
    EXPECT_EQ(res, HCF_SUCCESS);

    eccKeyPairSpec->sk.data = nullptr;
    HcfAsyKeyGeneratorBySpec *generator = nullptr;
    res = HcfAsyKeyGeneratorBySpecCreate(reinterpret_cast<HcfAsyKeyParamsSpec *>(eccKeyPairSpec), &generator);
    EXPECT_NE(res, HCF_SUCCESS);
    EXPECT_EQ(generator, nullptr);

    FreeEccKeyPairSpec(eccKeyPairSpec);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoAsyKeyGeneratorCovTest, CryptoAsyKeyGeneratorTest230, TestSize.Level0)
{
    HcfEccKeyPairParamsSpec *eccKeyPairSpec = nullptr;
    HcfResult res = ConstructEcc224KeyPairParamsSpec(&eccKeyPairSpec);
    EXPECT_EQ(res, HCF_SUCCESS);

    eccKeyPairSpec->sk.len = 0;
    HcfAsyKeyGeneratorBySpec *generator = nullptr;
    res = HcfAsyKeyGeneratorBySpecCreate(reinterpret_cast<HcfAsyKeyParamsSpec *>(eccKeyPairSpec), &generator);
    EXPECT_NE(res, HCF_SUCCESS);
    EXPECT_EQ(generator, nullptr);

    FreeEccKeyPairSpec(eccKeyPairSpec);
    HcfObjDestroy(generator);
}
}
