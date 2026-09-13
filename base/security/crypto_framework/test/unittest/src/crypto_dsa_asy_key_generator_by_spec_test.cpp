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

#include "asy_key_generator.h"
#include "big_integer.h"
#include "detailed_dsa_key_params.h"
#include "memory.h"
#include "openssl_class.h"
#include "openssl_common.h"
#include "openssl_adapter_mock.h"

using namespace std;
using namespace testing::ext;

namespace {
class CryptoDsaAsyKeyGeneratorBySpecTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp();
    void TearDown();
};

void CryptoDsaAsyKeyGeneratorBySpecTest::SetUpTestCase() {}
void CryptoDsaAsyKeyGeneratorBySpecTest::TearDownTestCase() {}
void CryptoDsaAsyKeyGeneratorBySpecTest::SetUp() {}
void CryptoDsaAsyKeyGeneratorBySpecTest::TearDown() {}

constexpr uint32_t DSA2048_PRI_SIZE = 20;
constexpr uint32_t DSA2048_PUB_SIZE = 256;
constexpr uint32_t DSA2048_P_SIZE = 256;
constexpr uint32_t DSA2048_Q_SIZE = 20;
constexpr uint32_t DSA2048_G_SIZE = 256;

static const char *g_algNameDSA = "DSA";
static const char *g_asyKeyGeneratorBySpecClass = "HcfAsyKeyGeneratorBySpec";
static const char *g_opensslDsaPubKeyFormat = "X.509";
static const char *g_opensslDsaPriKeyFormat = "PKCS#8";

static const bool IS_BIG_ENDIAN = IsBigEndian();

static unsigned char g_dsa2048PrivBigE[] = {
    0x32, 0x67, 0x92, 0xf6, 0xc4, 0xe2, 0xe2, 0xe8, 0xa0, 0x8b, 0x6b, 0x45,
    0x0c, 0x8a, 0x76, 0xb0, 0xee, 0xcf, 0x91, 0xa7,
};

static unsigned char g_dsa2048PrivLittleE[] = {
    0xa7, 0x91, 0xcf, 0xee, 0xb0, 0x76, 0x8a, 0x0c, 0x45, 0x6b, 0x8b, 0xa0,
    0xe8, 0xe2, 0xe2, 0xc4, 0xf6, 0x92, 0x67, 0x32,
};

static unsigned char g_dsa2048PubBigE[] = {
    0x17, 0x8f, 0xa8, 0x11, 0x84, 0x92, 0xec, 0x83, 0x47, 0xc7, 0x6a, 0xb0,
    0x92, 0xaf, 0x5a, 0x20, 0x37, 0xa3, 0x64, 0x79, 0xd2, 0xd0, 0x3d, 0xcd,
    0xe0, 0x61, 0x88, 0x88, 0x21, 0xcc, 0x74, 0x5d, 0xce, 0x4c, 0x51, 0x47,
    0xf0, 0xc5, 0x5c, 0x4c, 0x82, 0x7a, 0xaf, 0x72, 0xad, 0xb9, 0xe0, 0x53,
    0xf2, 0x78, 0xb7, 0xf0, 0xb5, 0x48, 0x7f, 0x8a, 0x3a, 0x18, 0xd1, 0x9f,
    0x8b, 0x7d, 0xa5, 0x47, 0xb7, 0x95, 0xab, 0x98, 0xf8, 0x7b, 0x74, 0x50,
    0x56, 0x8e, 0x57, 0xf0, 0xee, 0xf5, 0xb7, 0xba, 0xab, 0x85, 0x86, 0xf9,
    0x2b, 0xef, 0x41, 0x56, 0xa0, 0xa4, 0x9f, 0xb7, 0x38, 0x00, 0x46, 0x0a,
    0xa6, 0xf1, 0xfc, 0x1f, 0xd8, 0x4e, 0x85, 0x44, 0x92, 0x43, 0x21, 0x5d,
    0x6e, 0xcc, 0xc2, 0xcb, 0x26, 0x31, 0x0d, 0x21, 0xc4, 0xbd, 0x8d, 0x24,
    0xbc, 0xd9, 0x18, 0x19, 0xd7, 0xdc, 0xf1, 0xe7, 0x93, 0x50, 0x48, 0x03,
    0x2c, 0xae, 0x2e, 0xe7, 0x49, 0x88, 0x5f, 0x93, 0x57, 0x27, 0x99, 0x36,
    0xb4, 0x20, 0xab, 0xfc, 0xa7, 0x2b, 0xf2, 0xd9, 0x98, 0xd7, 0xd4, 0x34,
    0x9d, 0x96, 0x50, 0x58, 0x9a, 0xea, 0x54, 0xf3, 0xee, 0xf5, 0x63, 0x14,
    0xee, 0x85, 0x83, 0x74, 0x76, 0xe1, 0x52, 0x95, 0xc3, 0xf7, 0xeb, 0x04,
    0x04, 0x7b, 0xa7, 0x28, 0x1b, 0xcc, 0xea, 0x4a, 0x4e, 0x84, 0xda, 0xd8,
    0x9c, 0x79, 0xd8, 0x9b, 0x66, 0x89, 0x2f, 0xcf, 0xac, 0xd7, 0x79, 0xf9,
    0xa9, 0xd8, 0x45, 0x13, 0x78, 0xb9, 0x00, 0x14, 0xc9, 0x7e, 0x22, 0x51,
    0x86, 0x67, 0xb0, 0x9f, 0x26, 0x11, 0x23, 0xc8, 0x38, 0xd7, 0x70, 0x1d,
    0x15, 0x8e, 0x4d, 0x4f, 0x95, 0x97, 0x40, 0xa1, 0xc2, 0x7e, 0x01, 0x18,
    0x72, 0xf4, 0x10, 0xe6, 0x8d, 0x52, 0x16, 0x7f, 0xf2, 0xc9, 0xf8, 0x33,
    0x8b, 0x33, 0xb7, 0xce,
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
    0xA0, 0x25, 0xFA, 0xAD, 0xF4, 0x8E, 0xB9, 0xE5, 0x99, 0xF3, 0x5D, 0x6F,
    0x4F, 0x83, 0x34, 0xE2, 0x7E, 0xCF, 0x6F, 0xBF, 0x30, 0xAF, 0x6F, 0x81,
    0xEB, 0xF8, 0xC4, 0x13, 0xD9, 0xA0, 0x5D, 0x8B, 0x5C, 0x8E, 0xDC, 0xC2,
    0x1D, 0x0B, 0x41, 0x32, 0xB0, 0x1F, 0xFE, 0xEF, 0x0C, 0xC2, 0xA2, 0x7E,
    0x68, 0x5C, 0x28, 0x21, 0xE9, 0xF5, 0xB1, 0x58, 0x12, 0x63, 0x4C, 0x19,
    0x4E, 0xFF, 0x02, 0x4B, 0x92, 0xED, 0xD2, 0x07, 0x11, 0x4D, 0x8C, 0x58,
    0x16, 0x5C, 0x55, 0x8E, 0xAD, 0xA3, 0x67, 0x7D, 0xB9, 0x86, 0x6E, 0x0B,
    0xE6, 0x54, 0x6F, 0x40, 0xAE, 0x0E, 0x67, 0x4C, 0xF9, 0x12, 0x5B, 0x3C,
    0x08, 0x7A, 0xF7, 0xFC, 0x67, 0x86, 0x69, 0xE7, 0x0A, 0x94, 0x40, 0xBF,
    0x8B, 0x76, 0xFE, 0x26, 0xD1, 0xF2, 0xA1, 0x1A, 0x84, 0xA1, 0x43, 0x56,
    0x28, 0xBC, 0x9A, 0x5F, 0xD7, 0x3B, 0x69, 0x89, 0x8A, 0x36, 0x2C, 0x51,
    0xDF, 0x12, 0x77, 0x2F, 0x57, 0x7B, 0xA0, 0xAA, 0xDD, 0x7F, 0xA1, 0x62,
    0x3B, 0x40, 0x7B, 0x68, 0x1A, 0x8F, 0x0D, 0x38, 0xBB, 0x21, 0x5D, 0x18,
    0xFC, 0x0F, 0x46, 0xF7, 0xA3, 0xB0, 0x1D, 0x23, 0xC3, 0xD2, 0xC7, 0x72,
    0x51, 0x18, 0xDF, 0x46, 0x95, 0x79, 0xD9, 0xBD, 0xB5, 0x19, 0x02, 0x2C,
    0x87, 0xDC, 0xE7, 0x57, 0x82, 0x7E, 0xF1, 0x8B, 0x06, 0x3D, 0x00, 0xA5,
    0x7B, 0x6B, 0x26, 0x27, 0x91, 0x0F, 0x6A, 0x77, 0xE4, 0xD5, 0x04, 0xE4,
    0x12, 0x2C, 0x42, 0xFF, 0xD2, 0x88, 0xBB, 0xD3, 0x92, 0xA0, 0xF9, 0xC8,
    0x51, 0x64, 0x14, 0x5C, 0xD8, 0xF9, 0x6C, 0x47, 0x82, 0xB4, 0x1C, 0x7F,
    0x09, 0xB8, 0xF0, 0x25, 0x83, 0x1D, 0x3F, 0x3F, 0x05, 0xB3, 0x21, 0x0A,
    0x5D, 0xA7, 0xD8, 0x54, 0xC3, 0x65, 0x7D, 0xC3, 0xB0, 0x1D, 0xBF, 0xAE,
    0xF8, 0x68, 0xCF, 0x9B,
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
    0x97, 0xE7, 0x33, 0x4D, 0xD3, 0x94, 0x3E, 0x0B, 0xDB, 0x62, 0x74, 0xC6,
    0xA1, 0x08, 0xDD, 0x19, 0xA3, 0x75, 0x17, 0x1B,
};

static unsigned char g_dsa2048QLittleE[] = {
    0x1b, 0x17, 0x75, 0xa3, 0x19, 0xdd, 0x08, 0xa1, 0xc6, 0x74, 0x62, 0xdb,
    0x0b, 0x3e, 0x94, 0xd3, 0x4d, 0x33, 0xe7, 0x97,
};

static unsigned char g_dsa2048GBigE[] = {
    0x2C, 0x78, 0x16, 0x59, 0x34, 0x63, 0xF4, 0xF3, 0x92, 0xFC, 0xB5, 0xA5,
    0x4F, 0x13, 0xDE, 0x2F, 0x1C, 0xA4, 0x3C, 0xAE, 0xAD, 0x38, 0x3F, 0x7E,
    0x90, 0xBF, 0x96, 0xA6, 0xAE, 0x25, 0x90, 0x72, 0xF5, 0x8E, 0x80, 0x0C,
    0x39, 0x1C, 0xD9, 0xEC, 0xBA, 0x90, 0x5B, 0x3A, 0xE8, 0x58, 0x6C, 0x9E,
    0x30, 0x42, 0x37, 0x02, 0x31, 0x82, 0xBC, 0x6A, 0xDF, 0x6A, 0x09, 0x29,
    0xE3, 0xC0, 0x46, 0xD1, 0xCB, 0x85, 0xEC, 0x0C, 0x30, 0x5E, 0xEA, 0xC8,
    0x39, 0x8E, 0x22, 0x9F, 0x22, 0x10, 0xD2, 0x34, 0x61, 0x68, 0x37, 0x3D,
    0x2E, 0x4A, 0x5B, 0x9A, 0xF5, 0xC1, 0x48, 0xC6, 0xF6, 0xDC, 0x63, 0x1A,
    0xD3, 0x96, 0x64, 0xBA, 0x34, 0xC9, 0xD1, 0xA0, 0xD1, 0xAE, 0x6C, 0x2F,
    0x48, 0x17, 0x93, 0x14, 0x43, 0xED, 0xF0, 0x21, 0x30, 0x19, 0xC3, 0x1B,
    0x5F, 0xDE, 0xA3, 0xF0, 0x70, 0x78, 0x18, 0xE1, 0xA8, 0xE4, 0xEE, 0x2E,
    0x00, 0xA5, 0xE4, 0xB3, 0x17, 0xC8, 0x0C, 0x7D, 0x6E, 0x42, 0xDC, 0xB7,
    0x46, 0x00, 0x36, 0x4D, 0xD4, 0x46, 0xAA, 0x3D, 0x3C, 0x46, 0x89, 0x40,
    0xBF, 0x1D, 0x84, 0x77, 0x0A, 0x75, 0xF3, 0x87, 0x1D, 0x08, 0x4C, 0xA6,
    0xD1, 0xA9, 0x1C, 0x1E, 0x12, 0x1E, 0xE1, 0xC7, 0x30, 0x28, 0x76, 0xA5,
    0x7F, 0x6C, 0x85, 0x96, 0x2B, 0x6F, 0xDB, 0x80, 0x66, 0x26, 0xAE, 0xF5,
    0x93, 0xC7, 0x8E, 0xAE, 0x9A, 0xED, 0xE4, 0xCA, 0x04, 0xEA, 0x3B, 0x72,
    0xEF, 0xDC, 0x87, 0xED, 0x0D, 0xA5, 0x4C, 0x4A, 0xDD, 0x71, 0x22, 0x64,
    0x59, 0x69, 0x4E, 0x8E, 0xBF, 0x43, 0xDC, 0xAB, 0x8E, 0x66, 0xBB, 0x01,
    0xB6, 0xF4, 0xE7, 0xFD, 0xD2, 0xAD, 0x9F, 0x36, 0xC1, 0xA0, 0x29, 0x99,
    0xD1, 0x96, 0x70, 0x59, 0x06, 0x78, 0x35, 0xBD, 0x65, 0x55, 0x52, 0x9E,
    0xF8, 0xB2, 0xE5, 0x38,
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

static HcfBigInteger sk_BN = {
    .data = IS_BIG_ENDIAN ? g_dsa2048PrivBigE : g_dsa2048PrivLittleE, .len = DSA2048_PRI_SIZE };
static HcfBigInteger pk_BN = {
    .data = IS_BIG_ENDIAN ? g_dsa2048PubBigE : g_dsa2048PubLittleE, .len = DSA2048_PUB_SIZE };
static HcfBigInteger p_BN = { .data = IS_BIG_ENDIAN ? g_dsa2048PBigE : g_dsa2048PLittleE, .len = DSA2048_P_SIZE };
static HcfBigInteger q_BN = { .data = IS_BIG_ENDIAN ? g_dsa2048QBigE : g_dsa2048QLittleE, .len = DSA2048_Q_SIZE };
static HcfBigInteger g_BN = { .data = IS_BIG_ENDIAN ? g_dsa2048GBigE : g_dsa2048GLittleE, .len = DSA2048_G_SIZE };

static HcfAsyKeyParamsSpec asySpecComm = {
    .algName = const_cast<char *>(g_algNameDSA),
    .specType = HCF_COMMON_PARAMS_SPEC
};
static HcfAsyKeyParamsSpec asySpecPk = {
    .algName = const_cast<char *>(g_algNameDSA),
    .specType = HCF_PUBLIC_KEY_SPEC
};
static HcfAsyKeyParamsSpec asySpecKeyPair = {
    .algName = const_cast<char *>(g_algNameDSA),
    .specType = HCF_KEY_PAIR_SPEC
};

static HcfDsaCommParamsSpec dsaCommonSpec = { .base = asySpecComm, .p = p_BN, .q = q_BN, .g = g_BN };
static HcfDsaPubKeyParamsSpec dsaPkSpec = {
    .base = {
        .base = asySpecPk,
        .p = p_BN,
        .q = q_BN,
        .g = g_BN
    },
    .pk = pk_BN
};
static HcfDsaKeyPairParamsSpec dsaKeyPairSpec = {
    .base = {
        .base = asySpecKeyPair,
        .p = p_BN,
        .q = q_BN,
        .g = g_BN
    },
    .pk = pk_BN,
    .sk = sk_BN
};

HWTEST_F(CryptoDsaAsyKeyGeneratorBySpecTest, CryptoDsaAsyKeyGeneratorBySpecTest001, TestSize.Level0)
{
    HcfAsyKeyGeneratorBySpec *generator = nullptr;
    HcfResult ret = HcfAsyKeyGeneratorBySpecCreate(reinterpret_cast<HcfAsyKeyParamsSpec *>(&dsaCommonSpec), &generator);

    ASSERT_EQ(ret, HCF_SUCCESS);
    ASSERT_NE(generator, nullptr);

    HcfObjDestroy(generator);
}

HWTEST_F(CryptoDsaAsyKeyGeneratorBySpecTest, CryptoDsaAsyKeyGeneratorBySpecTest002, TestSize.Level0)
{
    HcfAsyKeyGeneratorBySpec *generator = nullptr;
    HcfResult ret = HcfAsyKeyGeneratorBySpecCreate(reinterpret_cast<HcfAsyKeyParamsSpec *>(&dsaPkSpec), &generator);

    ASSERT_EQ(ret, HCF_SUCCESS);
    ASSERT_NE(generator, nullptr);

    HcfObjDestroy(generator);
}

HWTEST_F(CryptoDsaAsyKeyGeneratorBySpecTest, CryptoDsaAsyKeyGeneratorBySpecTest003, TestSize.Level0)
{
    HcfAsyKeyGeneratorBySpec *generator = nullptr;
    HcfResult ret = HcfAsyKeyGeneratorBySpecCreate(reinterpret_cast<HcfAsyKeyParamsSpec *>(&dsaKeyPairSpec),
        &generator);

    ASSERT_EQ(ret, HCF_SUCCESS);
    ASSERT_NE(generator, nullptr);

    HcfObjDestroy(generator);
}

HWTEST_F(CryptoDsaAsyKeyGeneratorBySpecTest, CryptoDsaAsyKeyGeneratorBySpecTest101, TestSize.Level0)
{
    HcfAsyKeyGeneratorBySpec *generator = nullptr;
    HcfResult ret = HcfAsyKeyGeneratorBySpecCreate(reinterpret_cast<HcfAsyKeyParamsSpec *>(&dsaKeyPairSpec),
        &generator);
    ASSERT_EQ(ret, HCF_SUCCESS);
    ASSERT_NE(generator, nullptr);

    const char *className = generator->base.getClass();
    HcfObjDestroy(generator);
    ASSERT_EQ(strcmp(className, g_asyKeyGeneratorBySpecClass), 0);
}

HWTEST_F(CryptoDsaAsyKeyGeneratorBySpecTest, CryptoDsaAsyKeyGeneratorBySpecTest102, TestSize.Level0)
{
    HcfAsyKeyGeneratorBySpec *generator = nullptr;
    HcfResult ret = HcfAsyKeyGeneratorBySpecCreate(reinterpret_cast<HcfAsyKeyParamsSpec *>(&dsaKeyPairSpec),
        &generator);
    ASSERT_EQ(ret, HCF_SUCCESS);
    ASSERT_NE(generator, nullptr);

    generator->base.destroy(&(generator->base));
}

HWTEST_F(CryptoDsaAsyKeyGeneratorBySpecTest, CryptoDsaAsyKeyGeneratorBySpecTest103, TestSize.Level0)
{
    HcfAsyKeyGeneratorBySpec *generator = nullptr;
    HcfResult ret = HcfAsyKeyGeneratorBySpecCreate(reinterpret_cast<HcfAsyKeyParamsSpec *>(&dsaKeyPairSpec),
        &generator);
    ASSERT_EQ(ret, HCF_SUCCESS);
    ASSERT_NE(generator, nullptr);

    const char *algName = generator->getAlgName(generator);

    EXPECT_STREQ(algName, g_algNameDSA);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoDsaAsyKeyGeneratorBySpecTest, CryptoDsaAsyKeyGeneratorBySpecTest104, TestSize.Level0)
{
    HcfAsyKeyGeneratorBySpec *generator = nullptr;
    HcfResult ret = HcfAsyKeyGeneratorBySpecCreate(reinterpret_cast<HcfAsyKeyParamsSpec *>(&dsaCommonSpec), &generator);
    ASSERT_EQ(ret, HCF_SUCCESS);
    ASSERT_NE(generator, nullptr);

    HcfKeyPair *keyPair = nullptr;
    ret = generator->generateKeyPair(generator, &keyPair);
    HcfObjDestroy(generator);
    ASSERT_EQ(ret, HCF_SUCCESS);
    ASSERT_NE(keyPair, nullptr);

    keyPair->priKey->clearMem(keyPair->priKey);
    HcfObjDestroy(keyPair);
}

HWTEST_F(CryptoDsaAsyKeyGeneratorBySpecTest, CryptoDsaAsyKeyGeneratorBySpecTest105, TestSize.Level0)
{
    HcfAsyKeyGeneratorBySpec *generator = nullptr;
    HcfResult ret = HcfAsyKeyGeneratorBySpecCreate(reinterpret_cast<HcfAsyKeyParamsSpec *>(&dsaKeyPairSpec),
        &generator);
    ASSERT_EQ(ret, HCF_SUCCESS);
    ASSERT_NE(generator, nullptr);

    HcfKeyPair *keyPair = nullptr;
    ret = generator->generateKeyPair(generator, &keyPair);
    HcfObjDestroy(generator);
    ASSERT_EQ(ret, HCF_SUCCESS);
    ASSERT_NE(keyPair, nullptr);

    keyPair->priKey->clearMem(keyPair->priKey);
    HcfObjDestroy(keyPair);
}

HWTEST_F(CryptoDsaAsyKeyGeneratorBySpecTest, CryptoDsaAsyKeyGeneratorBySpecTest106, TestSize.Level1)
{
    HcfAsyKeyGeneratorBySpec *generator = nullptr;
    HcfResult ret = HcfAsyKeyGeneratorBySpecCreate(reinterpret_cast<HcfAsyKeyParamsSpec *>(&dsaPkSpec), &generator);
    ASSERT_EQ(ret, HCF_SUCCESS);
    ASSERT_NE(generator, nullptr);

    HcfKeyPair *keyPair = nullptr;
    ret = generator->generateKeyPair(generator, &keyPair);
    HcfObjDestroy(generator);
    ASSERT_EQ(ret, HCF_INVALID_PARAMS);
    ASSERT_EQ(keyPair, nullptr);
}

HWTEST_F(CryptoDsaAsyKeyGeneratorBySpecTest, CryptoDsaAsyKeyGeneratorBySpecTest107, TestSize.Level0)
{
    HcfAsyKeyGeneratorBySpec *generator = nullptr;
    HcfResult ret = HcfAsyKeyGeneratorBySpecCreate(reinterpret_cast<HcfAsyKeyParamsSpec *>(&dsaPkSpec), &generator);
    ASSERT_EQ(ret, HCF_SUCCESS);
    ASSERT_NE(generator, nullptr);

    HcfPubKey *pk = nullptr;
    ret = generator->generatePubKey(generator, &pk);
    HcfObjDestroy(generator);
    ASSERT_EQ(ret, HCF_SUCCESS);
    ASSERT_NE(pk, nullptr);

    HcfObjDestroy(pk);
}

HWTEST_F(CryptoDsaAsyKeyGeneratorBySpecTest, CryptoDsaAsyKeyGeneratorBySpecTest108, TestSize.Level0)
{
    HcfAsyKeyGeneratorBySpec *generator = nullptr;
    HcfResult ret = HcfAsyKeyGeneratorBySpecCreate(reinterpret_cast<HcfAsyKeyParamsSpec *>(&dsaKeyPairSpec),
        &generator);
    ASSERT_EQ(ret, HCF_SUCCESS);
    ASSERT_NE(generator, nullptr);

    HcfPubKey *pk = nullptr;
    ret = generator->generatePubKey(generator, &pk);
    HcfObjDestroy(generator);
    ASSERT_EQ(ret, HCF_SUCCESS);
    ASSERT_NE(pk, nullptr);

    HcfObjDestroy(pk);
}

HWTEST_F(CryptoDsaAsyKeyGeneratorBySpecTest, CryptoDsaAsyKeyGeneratorBySpecTest109, TestSize.Level1)
{
    HcfAsyKeyGeneratorBySpec *generator = nullptr;
    HcfResult ret = HcfAsyKeyGeneratorBySpecCreate(reinterpret_cast<HcfAsyKeyParamsSpec *>(&dsaCommonSpec), &generator);
    ASSERT_EQ(ret, HCF_SUCCESS);
    ASSERT_NE(generator, nullptr);

    HcfPubKey *pk = nullptr;
    ret = generator->generatePubKey(generator, &pk);
    HcfObjDestroy(generator);
    ASSERT_EQ(ret, HCF_INVALID_PARAMS);
    ASSERT_EQ(pk, nullptr);
}

HWTEST_F(CryptoDsaAsyKeyGeneratorBySpecTest, CryptoDsaAsyKeyGeneratorBySpecTest110, TestSize.Level0)
{
    HcfAsyKeyGeneratorBySpec *generator = nullptr;
    HcfResult ret = HcfAsyKeyGeneratorBySpecCreate(reinterpret_cast<HcfAsyKeyParamsSpec *>(&dsaKeyPairSpec),
        &generator);
    ASSERT_EQ(ret, HCF_SUCCESS);
    ASSERT_NE(generator, nullptr);

    HcfPriKey *sk = nullptr;
    ret = generator->generatePriKey(generator, &sk);
    HcfObjDestroy(generator);
    ASSERT_EQ(ret, HCF_SUCCESS);
    ASSERT_NE(sk, nullptr);

    sk->clearMem(sk);
    HcfObjDestroy(sk);
}

HWTEST_F(CryptoDsaAsyKeyGeneratorBySpecTest, CryptoDsaAsyKeyGeneratorBySpecTest201, TestSize.Level0)
{
    HcfAsyKeyGeneratorBySpec *generator = nullptr;
    HcfResult ret = HcfAsyKeyGeneratorBySpecCreate(reinterpret_cast<HcfAsyKeyParamsSpec *>(&dsaCommonSpec), &generator);
    ASSERT_EQ(ret, HCF_SUCCESS);
    ASSERT_NE(generator, nullptr);

    HcfKeyPair *keyPair = nullptr;
    ret = generator->generateKeyPair(generator, &keyPair);
    HcfObjDestroy(generator);
    ASSERT_EQ(ret, HCF_SUCCESS);
    ASSERT_NE(keyPair, nullptr);

    const char *keyPairClassName = keyPair->base.getClass();
    EXPECT_STREQ(keyPairClassName, OPENSSL_DSA_KEYPAIR_CLASS);
    HcfObjDestroy(keyPair);
}

HWTEST_F(CryptoDsaAsyKeyGeneratorBySpecTest, CryptoDsaAsyKeyGeneratorBySpecTest202, TestSize.Level0)
{
    HcfAsyKeyGeneratorBySpec *generator = nullptr;
    HcfResult ret = HcfAsyKeyGeneratorBySpecCreate(reinterpret_cast<HcfAsyKeyParamsSpec *>(&dsaCommonSpec), &generator);
    ASSERT_EQ(ret, HCF_SUCCESS);
    ASSERT_NE(generator, nullptr);

    HcfKeyPair *keyPair = nullptr;
    ret = generator->generateKeyPair(generator, &keyPair);
    HcfObjDestroy(generator);
    ASSERT_EQ(ret, HCF_SUCCESS);
    ASSERT_NE(keyPair, nullptr);
    keyPair->base.destroy(&(keyPair->base));
}

HWTEST_F(CryptoDsaAsyKeyGeneratorBySpecTest, CryptoDsaAsyKeyGeneratorBySpecTest203, TestSize.Level0)
{
    HcfAsyKeyGeneratorBySpec *generator = nullptr;
    HcfResult ret = HcfAsyKeyGeneratorBySpecCreate(reinterpret_cast<HcfAsyKeyParamsSpec *>(&dsaCommonSpec), &generator);
    ASSERT_EQ(ret, HCF_SUCCESS);
    ASSERT_NE(generator, nullptr);

    HcfKeyPair *keyPair = nullptr;
    ret = generator->generateKeyPair(generator, &keyPair);
    HcfObjDestroy(generator);
    ASSERT_EQ(ret, HCF_SUCCESS);
    ASSERT_NE(keyPair, nullptr);

    const char *pkClassName = keyPair->pubKey->base.base.getClass();
    EXPECT_STREQ(pkClassName, OPENSSL_DSA_PUBKEY_CLASS);
    HcfObjDestroy(keyPair);
}

HWTEST_F(CryptoDsaAsyKeyGeneratorBySpecTest, CryptoDsaAsyKeyGeneratorBySpecTest204, TestSize.Level0)
{
    HcfAsyKeyGeneratorBySpec *generator = nullptr;
    HcfResult ret = HcfAsyKeyGeneratorBySpecCreate(reinterpret_cast<HcfAsyKeyParamsSpec *>(&dsaCommonSpec), &generator);
    ASSERT_EQ(ret, HCF_SUCCESS);
    ASSERT_NE(generator, nullptr);

    HcfKeyPair *keyPair = nullptr;
    ret = generator->generateKeyPair(generator, &keyPair);
    HcfObjDestroy(generator);
    ASSERT_EQ(ret, HCF_SUCCESS);
    ASSERT_NE(keyPair, nullptr);

    keyPair->pubKey->base.base.destroy(&(keyPair->pubKey->base.base));
    keyPair->pubKey = nullptr;
    HcfObjDestroy(keyPair);
}

HWTEST_F(CryptoDsaAsyKeyGeneratorBySpecTest, CryptoDsaAsyKeyGeneratorBySpecTest205, TestSize.Level0)
{
    HcfAsyKeyGeneratorBySpec *generator = nullptr;
    HcfResult ret = HcfAsyKeyGeneratorBySpecCreate(reinterpret_cast<HcfAsyKeyParamsSpec *>(&dsaCommonSpec), &generator);
    ASSERT_EQ(ret, HCF_SUCCESS);
    ASSERT_NE(generator, nullptr);

    HcfKeyPair *keyPair = nullptr;
    ret = generator->generateKeyPair(generator, &keyPair);
    HcfObjDestroy(generator);
    ASSERT_EQ(ret, HCF_SUCCESS);
    ASSERT_NE(keyPair, nullptr);

    const char *alg = keyPair->pubKey->base.getAlgorithm(&(keyPair->pubKey->base));
    EXPECT_STREQ(alg, g_algNameDSA);
    HcfObjDestroy(keyPair);
}

HWTEST_F(CryptoDsaAsyKeyGeneratorBySpecTest, CryptoDsaAsyKeyGeneratorBySpecTest206, TestSize.Level0)
{
    HcfAsyKeyGeneratorBySpec *generator = nullptr;
    HcfResult ret = HcfAsyKeyGeneratorBySpecCreate(reinterpret_cast<HcfAsyKeyParamsSpec *>(&dsaCommonSpec), &generator);
    ASSERT_EQ(ret, HCF_SUCCESS);
    ASSERT_NE(generator, nullptr);

    HcfKeyPair *keyPair = nullptr;
    ret = generator->generateKeyPair(generator, &keyPair);
    HcfObjDestroy(generator);
    ASSERT_EQ(ret, HCF_SUCCESS);
    ASSERT_NE(keyPair, nullptr);

    HcfBlob blob = { .data = nullptr, .len = 0 };
    ret = keyPair->pubKey->base.getEncoded(&(keyPair->pubKey->base), &blob);
    HcfObjDestroy(keyPair);
    ASSERT_EQ(ret, HCF_SUCCESS);
    ASSERT_NE(blob.data, nullptr);
    ASSERT_NE(blob.len, 0);
    HcfFree(blob.data);
}

HWTEST_F(CryptoDsaAsyKeyGeneratorBySpecTest, CryptoDsaAsyKeyGeneratorBySpecTest207, TestSize.Level0)
{
    HcfAsyKeyGeneratorBySpec *generator = nullptr;
    HcfResult ret = HcfAsyKeyGeneratorBySpecCreate(reinterpret_cast<HcfAsyKeyParamsSpec *>(&dsaCommonSpec), &generator);
    ASSERT_EQ(ret, HCF_SUCCESS);
    ASSERT_NE(generator, nullptr);

    HcfKeyPair *keyPair = nullptr;
    ret = generator->generateKeyPair(generator, &keyPair);
    HcfObjDestroy(generator);
    ASSERT_EQ(ret, HCF_SUCCESS);
    ASSERT_NE(keyPair, nullptr);

    const char *pkFormat = keyPair->pubKey->base.getFormat(&(keyPair->pubKey->base));
    EXPECT_STREQ(pkFormat, g_opensslDsaPubKeyFormat);
    HcfObjDestroy(keyPair);
}

HWTEST_F(CryptoDsaAsyKeyGeneratorBySpecTest, CryptoDsaAsyKeyGeneratorBySpecTest208, TestSize.Level0)
{
    HcfAsyKeyGeneratorBySpec *generator = nullptr;
    HcfResult ret = HcfAsyKeyGeneratorBySpecCreate(reinterpret_cast<HcfAsyKeyParamsSpec *>(&dsaCommonSpec), &generator);
    ASSERT_EQ(ret, HCF_SUCCESS);
    ASSERT_NE(generator, nullptr);

    HcfKeyPair *keyPair = nullptr;
    ret = generator->generateKeyPair(generator, &keyPair);
    HcfObjDestroy(generator);
    ASSERT_EQ(ret, HCF_SUCCESS);
    ASSERT_NE(keyPair, nullptr);

    HcfBigInteger p = { .data = nullptr, .len = 0 };
    ret = keyPair->pubKey->getAsyKeySpecBigInteger(keyPair->pubKey, DSA_P_BN, &p);
    HcfObjDestroy(keyPair);
    ASSERT_EQ(ret, HCF_SUCCESS);
    ASSERT_NE(p.data, nullptr);
    ASSERT_NE(p.len, 0);
    HcfFree(p.data);
}

HWTEST_F(CryptoDsaAsyKeyGeneratorBySpecTest, CryptoDsaAsyKeyGeneratorBySpecTest209, TestSize.Level0)
{
    HcfAsyKeyGeneratorBySpec *generator = nullptr;
    HcfResult ret = HcfAsyKeyGeneratorBySpecCreate(reinterpret_cast<HcfAsyKeyParamsSpec *>(&dsaCommonSpec), &generator);
    ASSERT_EQ(ret, HCF_SUCCESS);
    ASSERT_NE(generator, nullptr);

    HcfKeyPair *keyPair = nullptr;
    ret = generator->generateKeyPair(generator, &keyPair);
    HcfObjDestroy(generator);
    ASSERT_EQ(ret, HCF_SUCCESS);
    ASSERT_NE(keyPair, nullptr);

    HcfBigInteger q = { .data = nullptr, .len = 0 };
    ret = keyPair->pubKey->getAsyKeySpecBigInteger(keyPair->pubKey, DSA_Q_BN, &q);
    HcfObjDestroy(keyPair);
    ASSERT_EQ(ret, HCF_SUCCESS);
    ASSERT_NE(q.data, nullptr);
    ASSERT_NE(q.len, 0);
    HcfFree(q.data);
}

HWTEST_F(CryptoDsaAsyKeyGeneratorBySpecTest, CryptoDsaAsyKeyGeneratorBySpecTest210, TestSize.Level0)
{
    HcfAsyKeyGeneratorBySpec *generator = nullptr;
    HcfResult ret = HcfAsyKeyGeneratorBySpecCreate(reinterpret_cast<HcfAsyKeyParamsSpec *>(&dsaCommonSpec), &generator);
    ASSERT_EQ(ret, HCF_SUCCESS);
    ASSERT_NE(generator, nullptr);

    HcfKeyPair *keyPair = nullptr;
    ret = generator->generateKeyPair(generator, &keyPair);
    HcfObjDestroy(generator);
    ASSERT_EQ(ret, HCF_SUCCESS);
    ASSERT_NE(keyPair, nullptr);

    HcfBigInteger g = { .data = nullptr, .len = 0 };
    ret = keyPair->pubKey->getAsyKeySpecBigInteger(keyPair->pubKey, DSA_G_BN, &g);
    HcfObjDestroy(keyPair);
    ASSERT_EQ(ret, HCF_SUCCESS);
    ASSERT_NE(g.data, nullptr);
    ASSERT_NE(g.len, 0);
    HcfFree(g.data);
}

HWTEST_F(CryptoDsaAsyKeyGeneratorBySpecTest, CryptoDsaAsyKeyGeneratorBySpecTest211, TestSize.Level0)
{
    HcfAsyKeyGeneratorBySpec *generator = nullptr;
    HcfResult ret = HcfAsyKeyGeneratorBySpecCreate(reinterpret_cast<HcfAsyKeyParamsSpec *>(&dsaCommonSpec), &generator);
    ASSERT_EQ(ret, HCF_SUCCESS);
    ASSERT_NE(generator, nullptr);

    HcfKeyPair *keyPair = nullptr;
    ret = generator->generateKeyPair(generator, &keyPair);
    HcfObjDestroy(generator);
    ASSERT_EQ(ret, HCF_SUCCESS);
    ASSERT_NE(keyPair, nullptr);

    HcfBigInteger pk = { .data = nullptr, .len = 0 };
    ret = keyPair->pubKey->getAsyKeySpecBigInteger(keyPair->pubKey, DSA_PK_BN, &pk);
    HcfObjDestroy(keyPair);
    ASSERT_EQ(ret, HCF_SUCCESS);
    ASSERT_NE(pk.data, nullptr);
    ASSERT_NE(pk.len, 0);
    HcfFree(pk.data);
}

HWTEST_F(CryptoDsaAsyKeyGeneratorBySpecTest, CryptoDsaAsyKeyGeneratorBySpecTest212, TestSize.Level0)
{
    HcfAsyKeyGeneratorBySpec *generator = nullptr;
    HcfResult ret = HcfAsyKeyGeneratorBySpecCreate(reinterpret_cast<HcfAsyKeyParamsSpec *>(&dsaCommonSpec), &generator);
    ASSERT_EQ(ret, HCF_SUCCESS);
    ASSERT_NE(generator, nullptr);

    HcfKeyPair *keyPair = nullptr;
    ret = generator->generateKeyPair(generator, &keyPair);
    HcfObjDestroy(generator);
    ASSERT_EQ(ret, HCF_SUCCESS);
    ASSERT_NE(keyPair, nullptr);

    const char *skClassName = keyPair->priKey->base.base.getClass();
    EXPECT_STREQ(skClassName, OPENSSL_DSA_PRIKEY_CLASS);
    HcfObjDestroy(keyPair);
}

HWTEST_F(CryptoDsaAsyKeyGeneratorBySpecTest, CryptoDsaAsyKeyGeneratorBySpecTest213, TestSize.Level0)
{
    HcfAsyKeyGeneratorBySpec *generator = nullptr;
    HcfResult ret = HcfAsyKeyGeneratorBySpecCreate(reinterpret_cast<HcfAsyKeyParamsSpec *>(&dsaCommonSpec), &generator);
    ASSERT_EQ(ret, HCF_SUCCESS);
    ASSERT_NE(generator, nullptr);

    HcfKeyPair *keyPair = nullptr;
    ret = generator->generateKeyPair(generator, &keyPair);
    HcfObjDestroy(generator);
    ASSERT_EQ(ret, HCF_SUCCESS);
    ASSERT_NE(keyPair, nullptr);

    keyPair->priKey->base.base.destroy(&(keyPair->priKey->base.base));
    keyPair->priKey = nullptr;

    HcfObjDestroy(keyPair);
}

HWTEST_F(CryptoDsaAsyKeyGeneratorBySpecTest, CryptoDsaAsyKeyGeneratorBySpecTest214, TestSize.Level0)
{
    HcfAsyKeyGeneratorBySpec *generator = nullptr;
    HcfResult ret = HcfAsyKeyGeneratorBySpecCreate(reinterpret_cast<HcfAsyKeyParamsSpec *>(&dsaCommonSpec), &generator);
    ASSERT_EQ(ret, HCF_SUCCESS);
    ASSERT_NE(generator, nullptr);

    HcfKeyPair *keyPair = nullptr;
    ret = generator->generateKeyPair(generator, &keyPair);
    HcfObjDestroy(generator);
    ASSERT_EQ(ret, HCF_SUCCESS);
    ASSERT_NE(keyPair, nullptr);

    const char *alg = keyPair->priKey->base.getAlgorithm(&(keyPair->priKey->base));
    EXPECT_STREQ(alg, g_algNameDSA);

    HcfObjDestroy(keyPair);
}

HWTEST_F(CryptoDsaAsyKeyGeneratorBySpecTest, CryptoDsaAsyKeyGeneratorBySpecTest215, TestSize.Level0)
{
    HcfAsyKeyGeneratorBySpec *generator = nullptr;
    HcfResult ret = HcfAsyKeyGeneratorBySpecCreate(reinterpret_cast<HcfAsyKeyParamsSpec *>(&dsaCommonSpec), &generator);
    ASSERT_EQ(ret, HCF_SUCCESS);
    ASSERT_NE(generator, nullptr);

    HcfKeyPair *keyPair = nullptr;
    ret = generator->generateKeyPair(generator, &keyPair);
    HcfObjDestroy(generator);
    ASSERT_EQ(ret, HCF_SUCCESS);
    ASSERT_NE(keyPair, nullptr);

    HcfBlob blob = { .data = nullptr, .len = 0 };
    ret = keyPair->priKey->base.getEncoded(&(keyPair->priKey->base), &blob);
    HcfObjDestroy(keyPair);
    ASSERT_EQ(ret, HCF_SUCCESS);
    ASSERT_NE(blob.data, nullptr);
    ASSERT_NE(blob.len, 0);
    HcfFree(blob.data);
}

HWTEST_F(CryptoDsaAsyKeyGeneratorBySpecTest, CryptoDsaAsyKeyGeneratorBySpecTest216, TestSize.Level0)
{
    HcfAsyKeyGeneratorBySpec *generator = nullptr;
    HcfResult ret = HcfAsyKeyGeneratorBySpecCreate(reinterpret_cast<HcfAsyKeyParamsSpec *>(&dsaCommonSpec), &generator);
    ASSERT_EQ(ret, HCF_SUCCESS);
    ASSERT_NE(generator, nullptr);

    HcfKeyPair *keyPair = nullptr;
    ret = generator->generateKeyPair(generator, &keyPair);
    HcfObjDestroy(generator);
    ASSERT_EQ(ret, HCF_SUCCESS);
    ASSERT_NE(keyPair, nullptr);

    const char *pkFormat = keyPair->priKey->base.getFormat(&(keyPair->priKey->base));
    EXPECT_STREQ(pkFormat, g_opensslDsaPriKeyFormat);
    HcfObjDestroy(keyPair);
}

HWTEST_F(CryptoDsaAsyKeyGeneratorBySpecTest, CryptoDsaAsyKeyGeneratorBySpecTest217, TestSize.Level0)
{
    HcfAsyKeyGeneratorBySpec *generator = nullptr;
    HcfResult ret = HcfAsyKeyGeneratorBySpecCreate(reinterpret_cast<HcfAsyKeyParamsSpec *>(&dsaCommonSpec), &generator);
    ASSERT_EQ(ret, HCF_SUCCESS);
    ASSERT_NE(generator, nullptr);

    HcfKeyPair *keyPair = nullptr;
    ret = generator->generateKeyPair(generator, &keyPair);
    HcfObjDestroy(generator);
    ASSERT_EQ(ret, HCF_SUCCESS);
    ASSERT_NE(keyPair, nullptr);

    HcfBigInteger p = { .data = nullptr, .len = 0 };
    ret = keyPair->priKey->getAsyKeySpecBigInteger(keyPair->priKey, DSA_P_BN, &p);
    HcfObjDestroy(keyPair);
    ASSERT_EQ(ret, HCF_SUCCESS);
    ASSERT_NE(p.data, nullptr);
    ASSERT_NE(p.len, 0);
    HcfFree(p.data);
}

HWTEST_F(CryptoDsaAsyKeyGeneratorBySpecTest, CryptoDsaAsyKeyGeneratorBySpecTest218, TestSize.Level0)
{
    HcfAsyKeyGeneratorBySpec *generator = nullptr;
    HcfResult ret = HcfAsyKeyGeneratorBySpecCreate(reinterpret_cast<HcfAsyKeyParamsSpec *>(&dsaCommonSpec), &generator);
    ASSERT_EQ(ret, HCF_SUCCESS);
    ASSERT_NE(generator, nullptr);

    HcfKeyPair *keyPair = nullptr;
    ret = generator->generateKeyPair(generator, &keyPair);
    HcfObjDestroy(generator);
    ASSERT_EQ(ret, HCF_SUCCESS);
    ASSERT_NE(keyPair, nullptr);

    HcfBigInteger q = { .data = nullptr, .len = 0 };
    ret = keyPair->priKey->getAsyKeySpecBigInteger(keyPair->priKey, DSA_Q_BN, &q);
    HcfObjDestroy(keyPair);
    ASSERT_EQ(ret, HCF_SUCCESS);
    ASSERT_NE(q.data, nullptr);
    ASSERT_NE(q.len, 0);
    HcfFree(q.data);
}

HWTEST_F(CryptoDsaAsyKeyGeneratorBySpecTest, CryptoDsaAsyKeyGeneratorBySpecTest219, TestSize.Level0)
{
    HcfAsyKeyGeneratorBySpec *generator = nullptr;
    HcfResult ret = HcfAsyKeyGeneratorBySpecCreate(reinterpret_cast<HcfAsyKeyParamsSpec *>(&dsaCommonSpec), &generator);
    ASSERT_EQ(ret, HCF_SUCCESS);
    ASSERT_NE(generator, nullptr);

    HcfKeyPair *keyPair = nullptr;
    ret = generator->generateKeyPair(generator, &keyPair);
    HcfObjDestroy(generator);
    ASSERT_EQ(ret, HCF_SUCCESS);
    ASSERT_NE(keyPair, nullptr);

    HcfBigInteger g = { .data = nullptr, .len = 0 };
    ret = keyPair->priKey->getAsyKeySpecBigInteger(keyPair->priKey, DSA_G_BN, &g);
    HcfObjDestroy(keyPair);
    ASSERT_EQ(ret, HCF_SUCCESS);
    ASSERT_NE(g.data, nullptr);
    ASSERT_NE(g.len, 0);
    HcfFree(g.data);
}

HWTEST_F(CryptoDsaAsyKeyGeneratorBySpecTest, CryptoDsaAsyKeyGeneratorBySpecTest220, TestSize.Level0)
{
    HcfAsyKeyGeneratorBySpec *generator = nullptr;
    HcfResult ret = HcfAsyKeyGeneratorBySpecCreate(reinterpret_cast<HcfAsyKeyParamsSpec *>(&dsaCommonSpec), &generator);
    ASSERT_EQ(ret, HCF_SUCCESS);
    ASSERT_NE(generator, nullptr);

    HcfKeyPair *keyPair = nullptr;
    ret = generator->generateKeyPair(generator, &keyPair);
    HcfObjDestroy(generator);
    ASSERT_EQ(ret, HCF_SUCCESS);
    ASSERT_NE(keyPair, nullptr);

    HcfBigInteger sk = { .data = nullptr, .len = 0 };
    ret = keyPair->priKey->getAsyKeySpecBigInteger(keyPair->priKey, DSA_SK_BN, &sk);
    HcfObjDestroy(keyPair);
    ASSERT_EQ(ret, HCF_SUCCESS);
    ASSERT_NE(sk.data, nullptr);
    ASSERT_NE(sk.len, 0);
    HcfFree(sk.data);
}

HWTEST_F(CryptoDsaAsyKeyGeneratorBySpecTest, CryptoDsaAsyKeyGeneratorBySpecTest301, TestSize.Level0)
{
    HcfAsyKeyGeneratorBySpec *generator = nullptr;
    HcfResult ret = HcfAsyKeyGeneratorBySpecCreate(reinterpret_cast<HcfAsyKeyParamsSpec *>(&dsaKeyPairSpec),
        &generator);
    ASSERT_EQ(ret, HCF_SUCCESS);
    ASSERT_NE(generator, nullptr);

    HcfKeyPair *keyPair = nullptr;
    ret = generator->generateKeyPair(generator, &keyPair);
    HcfObjDestroy(generator);
    ASSERT_EQ(ret, HCF_SUCCESS);
    ASSERT_NE(keyPair, nullptr);

    const char *keyPairClassName = keyPair->base.getClass();
    EXPECT_STREQ(keyPairClassName, OPENSSL_DSA_KEYPAIR_CLASS);
    HcfObjDestroy(keyPair);
}

HWTEST_F(CryptoDsaAsyKeyGeneratorBySpecTest, CryptoDsaAsyKeyGeneratorBySpecTest302, TestSize.Level0)
{
    HcfAsyKeyGeneratorBySpec *generator = nullptr;
    HcfResult ret = HcfAsyKeyGeneratorBySpecCreate(reinterpret_cast<HcfAsyKeyParamsSpec *>(&dsaKeyPairSpec),
        &generator);
    ASSERT_EQ(ret, HCF_SUCCESS);
    ASSERT_NE(generator, nullptr);

    HcfKeyPair *keyPair = nullptr;
    ret = generator->generateKeyPair(generator, &keyPair);
    HcfObjDestroy(generator);
    ASSERT_EQ(ret, HCF_SUCCESS);
    ASSERT_NE(keyPair, nullptr);
    keyPair->base.destroy(&(keyPair->base));
}

HWTEST_F(CryptoDsaAsyKeyGeneratorBySpecTest, CryptoDsaAsyKeyGeneratorBySpecTest303, TestSize.Level0)
{
    HcfAsyKeyGeneratorBySpec *generator = nullptr;
    HcfResult ret = HcfAsyKeyGeneratorBySpecCreate(reinterpret_cast<HcfAsyKeyParamsSpec *>(&dsaKeyPairSpec),
        &generator);
    ASSERT_EQ(ret, HCF_SUCCESS);
    ASSERT_NE(generator, nullptr);

    HcfKeyPair *keyPair = nullptr;
    ret = generator->generateKeyPair(generator, &keyPair);
    HcfObjDestroy(generator);
    ASSERT_EQ(ret, HCF_SUCCESS);
    ASSERT_NE(keyPair, nullptr);

    const char *pkClassName = keyPair->pubKey->base.base.getClass();
    EXPECT_STREQ(pkClassName, OPENSSL_DSA_PUBKEY_CLASS);
    HcfObjDestroy(keyPair);
}

HWTEST_F(CryptoDsaAsyKeyGeneratorBySpecTest, CryptoDsaAsyKeyGeneratorBySpecTest304, TestSize.Level0)
{
    HcfAsyKeyGeneratorBySpec *generator = nullptr;
    HcfResult ret = HcfAsyKeyGeneratorBySpecCreate(reinterpret_cast<HcfAsyKeyParamsSpec *>(&dsaKeyPairSpec),
        &generator);
    ASSERT_EQ(ret, HCF_SUCCESS);
    ASSERT_NE(generator, nullptr);

    HcfKeyPair *keyPair = nullptr;
    ret = generator->generateKeyPair(generator, &keyPair);
    HcfObjDestroy(generator);
    ASSERT_EQ(ret, HCF_SUCCESS);
    ASSERT_NE(keyPair, nullptr);

    keyPair->pubKey->base.base.destroy(&(keyPair->pubKey->base.base));
    keyPair->pubKey = nullptr;

    HcfObjDestroy(keyPair);
}

HWTEST_F(CryptoDsaAsyKeyGeneratorBySpecTest, CryptoDsaAsyKeyGeneratorBySpecTest305, TestSize.Level0)
{
    HcfAsyKeyGeneratorBySpec *generator = nullptr;
    HcfResult ret = HcfAsyKeyGeneratorBySpecCreate(reinterpret_cast<HcfAsyKeyParamsSpec *>(&dsaKeyPairSpec),
        &generator);
    ASSERT_EQ(ret, HCF_SUCCESS);
    ASSERT_NE(generator, nullptr);

    HcfKeyPair *keyPair = nullptr;
    ret = generator->generateKeyPair(generator, &keyPair);
    HcfObjDestroy(generator);
    ASSERT_EQ(ret, HCF_SUCCESS);
    ASSERT_NE(keyPair, nullptr);

    const char *alg = keyPair->pubKey->base.getAlgorithm(&(keyPair->pubKey->base));
    EXPECT_STREQ(alg, g_algNameDSA);

    HcfObjDestroy(keyPair);
}

HWTEST_F(CryptoDsaAsyKeyGeneratorBySpecTest, CryptoDsaAsyKeyGeneratorBySpecTest306, TestSize.Level0)
{
    HcfAsyKeyGeneratorBySpec *generator = nullptr;
    HcfResult ret = HcfAsyKeyGeneratorBySpecCreate(reinterpret_cast<HcfAsyKeyParamsSpec *>(&dsaKeyPairSpec),
        &generator);
    ASSERT_EQ(ret, HCF_SUCCESS);
    ASSERT_NE(generator, nullptr);

    HcfKeyPair *keyPair = nullptr;
    ret = generator->generateKeyPair(generator, &keyPair);
    HcfObjDestroy(generator);
    ASSERT_EQ(ret, HCF_SUCCESS);
    ASSERT_NE(keyPair, nullptr);

    HcfBlob blob = { .data = nullptr, .len = 0 };
    ret = keyPair->pubKey->base.getEncoded(&(keyPair->pubKey->base), &blob);
    HcfObjDestroy(keyPair);
    ASSERT_EQ(ret, HCF_SUCCESS);
    ASSERT_NE(blob.data, nullptr);
    ASSERT_NE(blob.len, 0);
    HcfFree(blob.data);
}

HWTEST_F(CryptoDsaAsyKeyGeneratorBySpecTest, CryptoDsaAsyKeyGeneratorBySpecTest307, TestSize.Level0)
{
    HcfAsyKeyGeneratorBySpec *generator = nullptr;
    HcfResult ret = HcfAsyKeyGeneratorBySpecCreate(reinterpret_cast<HcfAsyKeyParamsSpec *>(&dsaKeyPairSpec),
        &generator);
    ASSERT_EQ(ret, HCF_SUCCESS);
    ASSERT_NE(generator, nullptr);

    HcfKeyPair *keyPair = nullptr;
    ret = generator->generateKeyPair(generator, &keyPair);
    HcfObjDestroy(generator);
    ASSERT_EQ(ret, HCF_SUCCESS);
    ASSERT_NE(keyPair, nullptr);

    const char *pkFormat = keyPair->pubKey->base.getFormat(&(keyPair->pubKey->base));
    EXPECT_STREQ(pkFormat, g_opensslDsaPubKeyFormat);
    HcfObjDestroy(keyPair);
}

HWTEST_F(CryptoDsaAsyKeyGeneratorBySpecTest, CryptoDsaAsyKeyGeneratorBySpecTest308, TestSize.Level0)
{
    HcfAsyKeyGeneratorBySpec *generator = nullptr;
    HcfResult ret = HcfAsyKeyGeneratorBySpecCreate(reinterpret_cast<HcfAsyKeyParamsSpec *>(&dsaKeyPairSpec),
        &generator);
    ASSERT_EQ(ret, HCF_SUCCESS);
    ASSERT_NE(generator, nullptr);

    HcfKeyPair *keyPair = nullptr;
    ret = generator->generateKeyPair(generator, &keyPair);
    HcfObjDestroy(generator);
    ASSERT_EQ(ret, HCF_SUCCESS);
    ASSERT_NE(keyPair, nullptr);

    HcfBigInteger p = { .data = nullptr, .len = 0 };
    ret = keyPair->pubKey->getAsyKeySpecBigInteger(keyPair->pubKey, DSA_P_BN, &p);
    HcfObjDestroy(keyPair);
    ASSERT_EQ(ret, HCF_SUCCESS);
    ASSERT_NE(p.data, nullptr);
    ASSERT_NE(p.len, 0);
    HcfFree(p.data);
}

HWTEST_F(CryptoDsaAsyKeyGeneratorBySpecTest, CryptoDsaAsyKeyGeneratorBySpecTest309, TestSize.Level0)
{
    HcfAsyKeyGeneratorBySpec *generator = nullptr;
    HcfResult ret = HcfAsyKeyGeneratorBySpecCreate(reinterpret_cast<HcfAsyKeyParamsSpec *>(&dsaKeyPairSpec),
        &generator);
    ASSERT_EQ(ret, HCF_SUCCESS);
    ASSERT_NE(generator, nullptr);

    HcfKeyPair *keyPair = nullptr;
    ret = generator->generateKeyPair(generator, &keyPair);
    HcfObjDestroy(generator);
    ASSERT_EQ(ret, HCF_SUCCESS);
    ASSERT_NE(keyPair, nullptr);

    HcfBigInteger q = { .data = nullptr, .len = 0 };
    ret = keyPair->pubKey->getAsyKeySpecBigInteger(keyPair->pubKey, DSA_Q_BN, &q);
    HcfObjDestroy(keyPair);
    ASSERT_EQ(ret, HCF_SUCCESS);
    ASSERT_NE(q.data, nullptr);
    ASSERT_NE(q.len, 0);
    HcfFree(q.data);
}

HWTEST_F(CryptoDsaAsyKeyGeneratorBySpecTest, CryptoDsaAsyKeyGeneratorBySpecTest310, TestSize.Level0)
{
    HcfAsyKeyGeneratorBySpec *generator = nullptr;
    HcfResult ret = HcfAsyKeyGeneratorBySpecCreate(reinterpret_cast<HcfAsyKeyParamsSpec *>(&dsaKeyPairSpec),
        &generator);
    ASSERT_EQ(ret, HCF_SUCCESS);
    ASSERT_NE(generator, nullptr);

    HcfKeyPair *keyPair = nullptr;
    ret = generator->generateKeyPair(generator, &keyPair);
    HcfObjDestroy(generator);
    ASSERT_EQ(ret, HCF_SUCCESS);
    ASSERT_NE(keyPair, nullptr);

    HcfBigInteger g = { .data = nullptr, .len = 0 };
    ret = keyPair->pubKey->getAsyKeySpecBigInteger(keyPair->pubKey, DSA_G_BN, &g);
    HcfObjDestroy(keyPair);
    ASSERT_EQ(ret, HCF_SUCCESS);
    ASSERT_NE(g.data, nullptr);
    ASSERT_NE(g.len, 0);
    HcfFree(g.data);
}

HWTEST_F(CryptoDsaAsyKeyGeneratorBySpecTest, CryptoDsaAsyKeyGeneratorBySpecTest311, TestSize.Level0)
{
    HcfAsyKeyGeneratorBySpec *generator = nullptr;
    HcfResult ret = HcfAsyKeyGeneratorBySpecCreate(reinterpret_cast<HcfAsyKeyParamsSpec *>(&dsaKeyPairSpec),
        &generator);
    ASSERT_EQ(ret, HCF_SUCCESS);
    ASSERT_NE(generator, nullptr);

    HcfKeyPair *keyPair = nullptr;
    ret = generator->generateKeyPair(generator, &keyPair);
    HcfObjDestroy(generator);
    ASSERT_EQ(ret, HCF_SUCCESS);
    ASSERT_NE(keyPair, nullptr);

    HcfBigInteger pk = { .data = nullptr, .len = 0 };
    ret = keyPair->pubKey->getAsyKeySpecBigInteger(keyPair->pubKey, DSA_PK_BN, &pk);
    HcfObjDestroy(keyPair);
    ASSERT_EQ(ret, HCF_SUCCESS);
    ASSERT_NE(pk.data, nullptr);
    ASSERT_NE(pk.len, 0);
    HcfFree(pk.data);
}

HWTEST_F(CryptoDsaAsyKeyGeneratorBySpecTest, CryptoDsaAsyKeyGeneratorBySpecTest312, TestSize.Level0)
{
    HcfAsyKeyGeneratorBySpec *generator = nullptr;
    HcfResult ret = HcfAsyKeyGeneratorBySpecCreate(reinterpret_cast<HcfAsyKeyParamsSpec *>(&dsaKeyPairSpec),
        &generator);
    ASSERT_EQ(ret, HCF_SUCCESS);
    ASSERT_NE(generator, nullptr);

    HcfKeyPair *keyPair = nullptr;
    ret = generator->generateKeyPair(generator, &keyPair);
    HcfObjDestroy(generator);
    ASSERT_EQ(ret, HCF_SUCCESS);
    ASSERT_NE(keyPair, nullptr);

    const char *skClassName = keyPair->priKey->base.base.getClass();
    EXPECT_STREQ(skClassName, OPENSSL_DSA_PRIKEY_CLASS);
    HcfObjDestroy(keyPair);
}

HWTEST_F(CryptoDsaAsyKeyGeneratorBySpecTest, CryptoDsaAsyKeyGeneratorBySpecTest313, TestSize.Level0)
{
    HcfAsyKeyGeneratorBySpec *generator = nullptr;
    HcfResult ret = HcfAsyKeyGeneratorBySpecCreate(reinterpret_cast<HcfAsyKeyParamsSpec *>(&dsaKeyPairSpec),
        &generator);
    ASSERT_EQ(ret, HCF_SUCCESS);
    ASSERT_NE(generator, nullptr);

    HcfKeyPair *keyPair = nullptr;
    ret = generator->generateKeyPair(generator, &keyPair);
    HcfObjDestroy(generator);
    ASSERT_EQ(ret, HCF_SUCCESS);
    ASSERT_NE(keyPair, nullptr);

    keyPair->priKey->base.base.destroy(&(keyPair->priKey->base.base));
    keyPair->priKey = nullptr;

    HcfObjDestroy(keyPair);
}

HWTEST_F(CryptoDsaAsyKeyGeneratorBySpecTest, CryptoDsaAsyKeyGeneratorBySpecTest314, TestSize.Level0)
{
    HcfAsyKeyGeneratorBySpec *generator = nullptr;
    HcfResult ret = HcfAsyKeyGeneratorBySpecCreate(reinterpret_cast<HcfAsyKeyParamsSpec *>(&dsaKeyPairSpec),
        &generator);
    ASSERT_EQ(ret, HCF_SUCCESS);
    ASSERT_NE(generator, nullptr);

    HcfKeyPair *keyPair = nullptr;
    ret = generator->generateKeyPair(generator, &keyPair);
    HcfObjDestroy(generator);
    ASSERT_EQ(ret, HCF_SUCCESS);
    ASSERT_NE(keyPair, nullptr);

    const char *alg = keyPair->priKey->base.getAlgorithm(&(keyPair->priKey->base));
    EXPECT_STREQ(alg, g_algNameDSA);

    HcfObjDestroy(keyPair);
}

HWTEST_F(CryptoDsaAsyKeyGeneratorBySpecTest, CryptoDsaAsyKeyGeneratorBySpecTest315, TestSize.Level0)
{
    HcfAsyKeyGeneratorBySpec *generator = nullptr;
    HcfResult ret = HcfAsyKeyGeneratorBySpecCreate(reinterpret_cast<HcfAsyKeyParamsSpec *>(&dsaKeyPairSpec),
        &generator);
    ASSERT_EQ(ret, HCF_SUCCESS);
    ASSERT_NE(generator, nullptr);

    HcfKeyPair *keyPair = nullptr;
    ret = generator->generateKeyPair(generator, &keyPair);
    HcfObjDestroy(generator);
    ASSERT_EQ(ret, HCF_SUCCESS);
    ASSERT_NE(keyPair, nullptr);

    HcfBlob blob = { .data = nullptr, .len = 0 };
    ret = keyPair->priKey->base.getEncoded(&(keyPair->priKey->base), &blob);
    HcfObjDestroy(keyPair);
    ASSERT_EQ(ret, HCF_SUCCESS);
    ASSERT_NE(blob.data, nullptr);
    ASSERT_NE(blob.len, 0);
    HcfFree(blob.data);
}

HWTEST_F(CryptoDsaAsyKeyGeneratorBySpecTest, CryptoDsaAsyKeyGeneratorBySpecTest316, TestSize.Level0)
{
    HcfAsyKeyGeneratorBySpec *generator = nullptr;
    HcfResult ret = HcfAsyKeyGeneratorBySpecCreate(reinterpret_cast<HcfAsyKeyParamsSpec *>(&dsaKeyPairSpec),
        &generator);
    ASSERT_EQ(ret, HCF_SUCCESS);
    ASSERT_NE(generator, nullptr);

    HcfKeyPair *keyPair = nullptr;
    ret = generator->generateKeyPair(generator, &keyPair);
    HcfObjDestroy(generator);
    ASSERT_EQ(ret, HCF_SUCCESS);
    ASSERT_NE(keyPair, nullptr);

    const char *pkFormat = keyPair->priKey->base.getFormat(&(keyPair->priKey->base));
    EXPECT_STREQ(pkFormat, g_opensslDsaPriKeyFormat);
    HcfObjDestroy(keyPair);
}

HWTEST_F(CryptoDsaAsyKeyGeneratorBySpecTest, CryptoDsaAsyKeyGeneratorBySpecTest317, TestSize.Level0)
{
    HcfAsyKeyGeneratorBySpec *generator = nullptr;
    HcfResult ret = HcfAsyKeyGeneratorBySpecCreate(reinterpret_cast<HcfAsyKeyParamsSpec *>(&dsaKeyPairSpec),
        &generator);
    ASSERT_EQ(ret, HCF_SUCCESS);
    ASSERT_NE(generator, nullptr);

    HcfKeyPair *keyPair = nullptr;
    ret = generator->generateKeyPair(generator, &keyPair);
    HcfObjDestroy(generator);
    ASSERT_EQ(ret, HCF_SUCCESS);
    ASSERT_NE(keyPair, nullptr);

    HcfBigInteger p = { .data = nullptr, .len = 0 };
    ret = keyPair->priKey->getAsyKeySpecBigInteger(keyPair->priKey, DSA_P_BN, &p);
    HcfObjDestroy(keyPair);
    ASSERT_EQ(ret, HCF_SUCCESS);
    ASSERT_NE(p.data, nullptr);
    ASSERT_NE(p.len, 0);
    HcfFree(p.data);
}

HWTEST_F(CryptoDsaAsyKeyGeneratorBySpecTest, CryptoDsaAsyKeyGeneratorBySpecTest318, TestSize.Level0)
{
    HcfAsyKeyGeneratorBySpec *generator = nullptr;
    HcfResult ret = HcfAsyKeyGeneratorBySpecCreate(reinterpret_cast<HcfAsyKeyParamsSpec *>(&dsaKeyPairSpec),
        &generator);
    ASSERT_EQ(ret, HCF_SUCCESS);
    ASSERT_NE(generator, nullptr);

    HcfKeyPair *keyPair = nullptr;
    ret = generator->generateKeyPair(generator, &keyPair);
    HcfObjDestroy(generator);
    ASSERT_EQ(ret, HCF_SUCCESS);
    ASSERT_NE(keyPair, nullptr);

    HcfBigInteger q = { .data = nullptr, .len = 0 };
    ret = keyPair->priKey->getAsyKeySpecBigInteger(keyPair->priKey, DSA_Q_BN, &q);
    HcfObjDestroy(keyPair);
    ASSERT_EQ(ret, HCF_SUCCESS);
    ASSERT_NE(q.data, nullptr);
    ASSERT_NE(q.len, 0);
    HcfFree(q.data);
}

HWTEST_F(CryptoDsaAsyKeyGeneratorBySpecTest, CryptoDsaAsyKeyGeneratorBySpecTest319, TestSize.Level0)
{
    HcfAsyKeyGeneratorBySpec *generator = nullptr;
    HcfResult ret = HcfAsyKeyGeneratorBySpecCreate(reinterpret_cast<HcfAsyKeyParamsSpec *>(&dsaKeyPairSpec),
        &generator);
    ASSERT_EQ(ret, HCF_SUCCESS);
    ASSERT_NE(generator, nullptr);

    HcfKeyPair *keyPair = nullptr;
    ret = generator->generateKeyPair(generator, &keyPair);
    HcfObjDestroy(generator);
    ASSERT_EQ(ret, HCF_SUCCESS);
    ASSERT_NE(keyPair, nullptr);

    HcfBigInteger g = { .data = nullptr, .len = 0 };
    ret = keyPair->priKey->getAsyKeySpecBigInteger(keyPair->priKey, DSA_G_BN, &g);
    HcfObjDestroy(keyPair);
    ASSERT_EQ(ret, HCF_SUCCESS);
    ASSERT_NE(g.data, nullptr);
    ASSERT_NE(g.len, 0);
    HcfFree(g.data);
}

HWTEST_F(CryptoDsaAsyKeyGeneratorBySpecTest, CryptoDsaAsyKeyGeneratorBySpecTest320, TestSize.Level0)
{
    HcfAsyKeyGeneratorBySpec *generator = nullptr;
    HcfResult ret = HcfAsyKeyGeneratorBySpecCreate(reinterpret_cast<HcfAsyKeyParamsSpec *>(&dsaKeyPairSpec),
        &generator);
    ASSERT_EQ(ret, HCF_SUCCESS);
    ASSERT_NE(generator, nullptr);

    HcfKeyPair *keyPair = nullptr;
    ret = generator->generateKeyPair(generator, &keyPair);
    HcfObjDestroy(generator);
    ASSERT_EQ(ret, HCF_SUCCESS);
    ASSERT_NE(keyPair, nullptr);

    HcfBigInteger sk = { .data = nullptr, .len = 0 };
    ret = keyPair->priKey->getAsyKeySpecBigInteger(keyPair->priKey, DSA_SK_BN, &sk);
    HcfObjDestroy(keyPair);
    ASSERT_EQ(ret, HCF_SUCCESS);
    ASSERT_NE(sk.data, nullptr);
    ASSERT_NE(sk.len, 0);
    HcfFree(sk.data);
}

HWTEST_F(CryptoDsaAsyKeyGeneratorBySpecTest, CryptoDsaAsyKeyGeneratorBySpecTest401, TestSize.Level0)
{
    HcfAsyKeyGeneratorBySpec *generator = nullptr;
    HcfResult ret = HcfAsyKeyGeneratorBySpecCreate(reinterpret_cast<HcfAsyKeyParamsSpec *>(&dsaPkSpec), &generator);
    ASSERT_EQ(ret, HCF_SUCCESS);
    ASSERT_NE(generator, nullptr);

    HcfPubKey *pk = nullptr;
    ret = generator->generatePubKey(generator, &pk);
    HcfObjDestroy(generator);
    ASSERT_EQ(ret, HCF_SUCCESS);
    ASSERT_NE(pk, nullptr);

    const char *pkClassName = pk->base.base.getClass();
    EXPECT_STREQ(pkClassName, OPENSSL_DSA_PUBKEY_CLASS);
    HcfObjDestroy(pk);
}

HWTEST_F(CryptoDsaAsyKeyGeneratorBySpecTest, CryptoDsaAsyKeyGeneratorBySpecTest402, TestSize.Level0)
{
    HcfAsyKeyGeneratorBySpec *generator = nullptr;
    HcfResult ret = HcfAsyKeyGeneratorBySpecCreate(reinterpret_cast<HcfAsyKeyParamsSpec *>(&dsaPkSpec), &generator);
    ASSERT_EQ(ret, HCF_SUCCESS);
    ASSERT_NE(generator, nullptr);

    HcfPubKey *pk = nullptr;
    ret = generator->generatePubKey(generator, &pk);
    HcfObjDestroy(generator);
    ASSERT_EQ(ret, HCF_SUCCESS);
    ASSERT_NE(pk, nullptr);

    pk->base.base.destroy(&(pk->base.base));
}

HWTEST_F(CryptoDsaAsyKeyGeneratorBySpecTest, CryptoDsaAsyKeyGeneratorBySpecTest403, TestSize.Level0)
{
    HcfAsyKeyGeneratorBySpec *generator = nullptr;
    HcfResult ret = HcfAsyKeyGeneratorBySpecCreate(reinterpret_cast<HcfAsyKeyParamsSpec *>(&dsaPkSpec), &generator);
    ASSERT_EQ(ret, HCF_SUCCESS);
    ASSERT_NE(generator, nullptr);

    HcfPubKey *pk = nullptr;
    ret = generator->generatePubKey(generator, &pk);
    HcfObjDestroy(generator);
    ASSERT_EQ(ret, HCF_SUCCESS);
    ASSERT_NE(pk, nullptr);

    const char *alg = pk->base.getAlgorithm(&(pk->base));
    EXPECT_STREQ(alg, g_algNameDSA);

    HcfObjDestroy(pk);
}

HWTEST_F(CryptoDsaAsyKeyGeneratorBySpecTest, CryptoDsaAsyKeyGeneratorBySpecTest404, TestSize.Level0)
{
    HcfAsyKeyGeneratorBySpec *generator = nullptr;
    HcfResult ret = HcfAsyKeyGeneratorBySpecCreate(reinterpret_cast<HcfAsyKeyParamsSpec *>(&dsaPkSpec), &generator);
    ASSERT_EQ(ret, HCF_SUCCESS);
    ASSERT_NE(generator, nullptr);

    HcfPubKey *pk = nullptr;
    ret = generator->generatePubKey(generator, &pk);
    HcfObjDestroy(generator);
    ASSERT_EQ(ret, HCF_SUCCESS);
    ASSERT_NE(pk, nullptr);

    HcfBlob blob = { .data = nullptr, .len = 0 };
    ret = pk->base.getEncoded(&(pk->base), &blob);
    HcfObjDestroy(pk);
    ASSERT_EQ(ret, HCF_SUCCESS);
    ASSERT_NE(blob.data, nullptr);
    ASSERT_NE(blob.len, 0);
    HcfFree(blob.data);
}

HWTEST_F(CryptoDsaAsyKeyGeneratorBySpecTest, CryptoDsaAsyKeyGeneratorBySpecTest405, TestSize.Level0)
{
    HcfAsyKeyGeneratorBySpec *generator = nullptr;
    HcfResult ret = HcfAsyKeyGeneratorBySpecCreate(reinterpret_cast<HcfAsyKeyParamsSpec *>(&dsaPkSpec), &generator);
    ASSERT_EQ(ret, HCF_SUCCESS);
    ASSERT_NE(generator, nullptr);

    HcfPubKey *pk = nullptr;
    ret = generator->generatePubKey(generator, &pk);
    HcfObjDestroy(generator);
    ASSERT_EQ(ret, HCF_SUCCESS);
    ASSERT_NE(pk, nullptr);

    const char *pkFormat = pk->base.getFormat(&(pk->base));
    EXPECT_STREQ(pkFormat, g_opensslDsaPubKeyFormat);
    HcfObjDestroy(pk);
}

HWTEST_F(CryptoDsaAsyKeyGeneratorBySpecTest, CryptoDsaAsyKeyGeneratorBySpecTest406, TestSize.Level0)
{
    HcfAsyKeyGeneratorBySpec *generator = nullptr;
    HcfResult ret = HcfAsyKeyGeneratorBySpecCreate(reinterpret_cast<HcfAsyKeyParamsSpec *>(&dsaPkSpec), &generator);
    ASSERT_EQ(ret, HCF_SUCCESS);
    ASSERT_NE(generator, nullptr);

    HcfPubKey *pk = nullptr;
    ret = generator->generatePubKey(generator, &pk);
    HcfObjDestroy(generator);
    ASSERT_EQ(ret, HCF_SUCCESS);
    ASSERT_NE(pk, nullptr);

    HcfBigInteger p = { .data = nullptr, .len = 0 };
    ret = pk->getAsyKeySpecBigInteger(pk, DSA_P_BN, &p);
    HcfObjDestroy(pk);
    ASSERT_EQ(ret, HCF_SUCCESS);
    ASSERT_NE(p.data, nullptr);
    ASSERT_NE(p.len, 0);
    HcfFree(p.data);
}

HWTEST_F(CryptoDsaAsyKeyGeneratorBySpecTest, CryptoDsaAsyKeyGeneratorBySpecTest407, TestSize.Level0)
{
    HcfAsyKeyGeneratorBySpec *generator = nullptr;
    HcfResult ret = HcfAsyKeyGeneratorBySpecCreate(reinterpret_cast<HcfAsyKeyParamsSpec *>(&dsaPkSpec), &generator);
    ASSERT_EQ(ret, HCF_SUCCESS);
    ASSERT_NE(generator, nullptr);

    HcfPubKey *pk = nullptr;
    ret = generator->generatePubKey(generator, &pk);
    HcfObjDestroy(generator);
    ASSERT_EQ(ret, HCF_SUCCESS);
    ASSERT_NE(pk, nullptr);

    HcfBigInteger q = { .data = nullptr, .len = 0 };
    ret = pk->getAsyKeySpecBigInteger(pk, DSA_Q_BN, &q);
    HcfObjDestroy(pk);
    ASSERT_EQ(ret, HCF_SUCCESS);
    ASSERT_NE(q.data, nullptr);
    ASSERT_NE(q.len, 0);
    HcfFree(q.data);
}

HWTEST_F(CryptoDsaAsyKeyGeneratorBySpecTest, CryptoDsaAsyKeyGeneratorBySpecTest408, TestSize.Level0)
{
    HcfAsyKeyGeneratorBySpec *generator = nullptr;
    HcfResult ret = HcfAsyKeyGeneratorBySpecCreate(reinterpret_cast<HcfAsyKeyParamsSpec *>(&dsaKeyPairSpec),
        &generator);
    ASSERT_EQ(ret, HCF_SUCCESS);
    ASSERT_NE(generator, nullptr);

    HcfPubKey *pk = nullptr;
    ret = generator->generatePubKey(generator, &pk);
    HcfObjDestroy(generator);
    ASSERT_EQ(ret, HCF_SUCCESS);
    ASSERT_NE(pk, nullptr);

    HcfBigInteger g = { .data = nullptr, .len = 0 };
    ret = pk->getAsyKeySpecBigInteger(pk, DSA_G_BN, &g);
    HcfObjDestroy(pk);
    ASSERT_EQ(ret, HCF_SUCCESS);
    ASSERT_NE(g.data, nullptr);
    ASSERT_NE(g.len, 0);
    HcfFree(g.data);
}

HWTEST_F(CryptoDsaAsyKeyGeneratorBySpecTest, CryptoDsaAsyKeyGeneratorBySpecTest409, TestSize.Level0)
{
    HcfAsyKeyGeneratorBySpec *generator = nullptr;
    HcfResult ret = HcfAsyKeyGeneratorBySpecCreate(reinterpret_cast<HcfAsyKeyParamsSpec *>(&dsaKeyPairSpec),
        &generator);
    ASSERT_EQ(ret, HCF_SUCCESS);
    ASSERT_NE(generator, nullptr);

    HcfPubKey *pk = nullptr;
    ret = generator->generatePubKey(generator, &pk);
    HcfObjDestroy(generator);
    ASSERT_EQ(ret, HCF_SUCCESS);
    ASSERT_NE(pk, nullptr);

    HcfBigInteger pkBn = { .data = nullptr, .len = 0 };
    ret = pk->getAsyKeySpecBigInteger(pk, DSA_PK_BN, &pkBn);
    HcfObjDestroy(pk);
    ASSERT_EQ(ret, HCF_SUCCESS);
    ASSERT_NE(pkBn.data, nullptr);
    ASSERT_NE(pkBn.len, 0);
    HcfFree(pkBn.data);
}

HWTEST_F(CryptoDsaAsyKeyGeneratorBySpecTest, CryptoDsaAsyKeyGeneratorBySpecTest501, TestSize.Level0)
{
    HcfAsyKeyGeneratorBySpec *generator = nullptr;
    HcfResult ret = HcfAsyKeyGeneratorBySpecCreate(reinterpret_cast<HcfAsyKeyParamsSpec *>(&dsaKeyPairSpec),
        &generator);
    ASSERT_EQ(ret, HCF_SUCCESS);
    ASSERT_NE(generator, nullptr);

    HcfPriKey *sk = nullptr;
    ret = generator->generatePriKey(generator, &sk);
    HcfObjDestroy(generator);
    ASSERT_EQ(ret, HCF_SUCCESS);
    ASSERT_NE(sk, nullptr);

    const char *skClassName = sk->base.base.getClass();
    EXPECT_STREQ(skClassName, OPENSSL_DSA_PRIKEY_CLASS);
    HcfObjDestroy(sk);
}

HWTEST_F(CryptoDsaAsyKeyGeneratorBySpecTest, CryptoDsaAsyKeyGeneratorBySpecTest502, TestSize.Level0)
{
    HcfAsyKeyGeneratorBySpec *generator = nullptr;
    HcfResult ret = HcfAsyKeyGeneratorBySpecCreate(reinterpret_cast<HcfAsyKeyParamsSpec *>(&dsaKeyPairSpec),
        &generator);
    ASSERT_EQ(ret, HCF_SUCCESS);
    ASSERT_NE(generator, nullptr);

    HcfPriKey *sk = nullptr;
    ret = generator->generatePriKey(generator, &sk);
    HcfObjDestroy(generator);
    ASSERT_EQ(ret, HCF_SUCCESS);
    ASSERT_NE(sk, nullptr);

    sk->base.base.destroy(&(sk->base.base));
}

HWTEST_F(CryptoDsaAsyKeyGeneratorBySpecTest, CryptoDsaAsyKeyGeneratorBySpecTest503, TestSize.Level0)
{
    HcfAsyKeyGeneratorBySpec *generator = nullptr;
    HcfResult ret = HcfAsyKeyGeneratorBySpecCreate(reinterpret_cast<HcfAsyKeyParamsSpec *>(&dsaKeyPairSpec),
        &generator);
    ASSERT_EQ(ret, HCF_SUCCESS);
    ASSERT_NE(generator, nullptr);

    HcfPriKey *sk = nullptr;
    ret = generator->generatePriKey(generator, &sk);
    HcfObjDestroy(generator);
    ASSERT_EQ(ret, HCF_SUCCESS);
    ASSERT_NE(sk, nullptr);

    const char *alg = sk->base.getAlgorithm(&(sk->base));
    EXPECT_STREQ(alg, g_algNameDSA);

    HcfObjDestroy(sk);
}

HWTEST_F(CryptoDsaAsyKeyGeneratorBySpecTest, CryptoDsaAsyKeyGeneratorBySpecTest504, TestSize.Level0)
{
    HcfAsyKeyGeneratorBySpec *generator = nullptr;
    HcfResult ret = HcfAsyKeyGeneratorBySpecCreate(reinterpret_cast<HcfAsyKeyParamsSpec *>(&dsaKeyPairSpec),
        &generator);
    ASSERT_EQ(ret, HCF_SUCCESS);
    ASSERT_NE(generator, nullptr);

    HcfPriKey *sk = nullptr;
    ret = generator->generatePriKey(generator, &sk);
    HcfObjDestroy(generator);
    ASSERT_EQ(ret, HCF_SUCCESS);
    ASSERT_NE(sk, nullptr);

    HcfBlob blob = { .data = nullptr, .len = 0 };
    ret = sk->base.getEncoded(&(sk->base), &blob);
    HcfObjDestroy(sk);
    ASSERT_EQ(ret, HCF_SUCCESS);
    ASSERT_NE(blob.data, nullptr);
    ASSERT_NE(blob.len, 0);
    HcfFree(blob.data);
}

HWTEST_F(CryptoDsaAsyKeyGeneratorBySpecTest, CryptoDsaAsyKeyGeneratorBySpecTest505, TestSize.Level0)
{
    HcfAsyKeyGeneratorBySpec *generator = nullptr;
    HcfResult ret = HcfAsyKeyGeneratorBySpecCreate(reinterpret_cast<HcfAsyKeyParamsSpec *>(&dsaKeyPairSpec),
        &generator);
    ASSERT_EQ(ret, HCF_SUCCESS);
    ASSERT_NE(generator, nullptr);

    HcfPriKey *sk = nullptr;
    ret = generator->generatePriKey(generator, &sk);
    HcfObjDestroy(generator);
    ASSERT_EQ(ret, HCF_SUCCESS);
    ASSERT_NE(sk, nullptr);

    const char *skFormat = sk->base.getFormat(&(sk->base));
    EXPECT_STREQ(skFormat, g_opensslDsaPriKeyFormat);
    HcfObjDestroy(sk);
}

HWTEST_F(CryptoDsaAsyKeyGeneratorBySpecTest, CryptoDsaAsyKeyGeneratorBySpecTest506, TestSize.Level0)
{
    HcfAsyKeyGeneratorBySpec *generator = nullptr;
    HcfResult ret = HcfAsyKeyGeneratorBySpecCreate(reinterpret_cast<HcfAsyKeyParamsSpec *>(&dsaKeyPairSpec),
        &generator);
    ASSERT_EQ(ret, HCF_SUCCESS);
    ASSERT_NE(generator, nullptr);

    HcfPriKey *sk = nullptr;
    ret = generator->generatePriKey(generator, &sk);
    HcfObjDestroy(generator);
    ASSERT_EQ(ret, HCF_SUCCESS);
    ASSERT_NE(sk, nullptr);

    HcfBigInteger p = { .data = nullptr, .len = 0 };
    ret = sk->getAsyKeySpecBigInteger(sk, DSA_P_BN, &p);
    HcfObjDestroy(sk);
    ASSERT_EQ(ret, HCF_SUCCESS);
    ASSERT_NE(p.data, nullptr);
    ASSERT_NE(p.len, 0);
    HcfFree(p.data);
}

HWTEST_F(CryptoDsaAsyKeyGeneratorBySpecTest, CryptoDsaAsyKeyGeneratorBySpecTest507, TestSize.Level0)
{
    HcfAsyKeyGeneratorBySpec *generator = nullptr;
    HcfResult ret = HcfAsyKeyGeneratorBySpecCreate(reinterpret_cast<HcfAsyKeyParamsSpec *>(&dsaKeyPairSpec),
        &generator);
    ASSERT_EQ(ret, HCF_SUCCESS);
    ASSERT_NE(generator, nullptr);

    HcfPriKey *sk = nullptr;
    ret = generator->generatePriKey(generator, &sk);
    HcfObjDestroy(generator);
    ASSERT_EQ(ret, HCF_SUCCESS);
    ASSERT_NE(sk, nullptr);

    HcfBigInteger q = { .data = nullptr, .len = 0 };
    ret = sk->getAsyKeySpecBigInteger(sk, DSA_Q_BN, &q);
    HcfObjDestroy(sk);
    ASSERT_EQ(ret, HCF_SUCCESS);
    ASSERT_NE(q.data, nullptr);
    ASSERT_NE(q.len, 0);
    HcfFree(q.data);
}

HWTEST_F(CryptoDsaAsyKeyGeneratorBySpecTest, CryptoDsaAsyKeyGeneratorBySpecTest508, TestSize.Level0)
{
    HcfAsyKeyGeneratorBySpec *generator = nullptr;
    HcfResult ret = HcfAsyKeyGeneratorBySpecCreate(reinterpret_cast<HcfAsyKeyParamsSpec *>(&dsaKeyPairSpec),
        &generator);
    ASSERT_EQ(ret, HCF_SUCCESS);
    ASSERT_NE(generator, nullptr);

    HcfPriKey *sk = nullptr;
    ret = generator->generatePriKey(generator, &sk);
    HcfObjDestroy(generator);
    ASSERT_EQ(ret, HCF_SUCCESS);
    ASSERT_NE(sk, nullptr);

    HcfBigInteger g = { .data = nullptr, .len = 0 };
    ret = sk->getAsyKeySpecBigInteger(sk, DSA_G_BN, &g);
    HcfObjDestroy(sk);
    ASSERT_EQ(ret, HCF_SUCCESS);
    ASSERT_NE(g.data, nullptr);
    ASSERT_NE(g.len, 0);
    HcfFree(g.data);
}

HWTEST_F(CryptoDsaAsyKeyGeneratorBySpecTest, CryptoDsaAsyKeyGeneratorBySpecTest509, TestSize.Level0)
{
    HcfAsyKeyGeneratorBySpec *generator = nullptr;
    HcfResult ret = HcfAsyKeyGeneratorBySpecCreate(reinterpret_cast<HcfAsyKeyParamsSpec *>(&dsaKeyPairSpec),
        &generator);
    ASSERT_EQ(ret, HCF_SUCCESS);
    ASSERT_NE(generator, nullptr);

    HcfPriKey *sk = nullptr;
    ret = generator->generatePriKey(generator, &sk);
    HcfObjDestroy(generator);
    ASSERT_EQ(ret, HCF_SUCCESS);
    ASSERT_NE(sk, nullptr);

    HcfBigInteger skBn = { .data = nullptr, .len = 0 };
    ret = sk->getAsyKeySpecBigInteger(sk, DSA_SK_BN, &skBn);
    HcfObjDestroy(sk);
    ASSERT_EQ(ret, HCF_SUCCESS);
    ASSERT_NE(skBn.data, nullptr);
    ASSERT_NE(skBn.len, 0);
    HcfFree(skBn.data);
}

HWTEST_F(CryptoDsaAsyKeyGeneratorBySpecTest, CryptoDsaGetPubKeyFromPriKey, TestSize.Level0)
{
    HcfAsyKeyGeneratorBySpec *generator = nullptr;
    HcfResult ret = HcfAsyKeyGeneratorBySpecCreate(reinterpret_cast<HcfAsyKeyParamsSpec *>(&dsaCommonSpec), &generator);
    ASSERT_EQ(ret, HCF_SUCCESS);
    ASSERT_NE(generator, nullptr);

    HcfKeyPair *keyPair = nullptr;
    ret = generator->generateKeyPair(generator, &keyPair);
    ASSERT_EQ(ret, HCF_SUCCESS);
    ASSERT_NE(keyPair, nullptr);

    HcfBlob pubKeyBlob1 = { .data = nullptr, .len = 0 };
    ret = keyPair->pubKey->base.getEncoded(&(keyPair->pubKey->base), &pubKeyBlob1);
    ASSERT_EQ(ret, HCF_SUCCESS);
    ASSERT_NE(pubKeyBlob1.data, nullptr);
    ASSERT_NE(pubKeyBlob1.len, 0);
    HcfPubKey *pubKey = nullptr;
    ret = keyPair->priKey->getPubKey(keyPair->priKey, &pubKey);
    ASSERT_EQ(ret, HCF_SUCCESS);
    ASSERT_NE(pubKey, nullptr);
    HcfBlob pubKeyBlob = { .data = nullptr, .len = 0 };
    ret = pubKey->base.getEncoded(&(pubKey->base), &pubKeyBlob);
    ASSERT_EQ(ret, HCF_SUCCESS);
    ASSERT_NE(pubKeyBlob.data, nullptr);
    ASSERT_NE(pubKeyBlob.len, 0);
    EXPECT_EQ(memcmp(pubKeyBlob.data, pubKeyBlob1.data, pubKeyBlob.len), 0);
    HcfFree(pubKeyBlob.data);
    HcfFree(pubKeyBlob1.data);
    HcfObjDestroy(pubKey);
    HcfObjDestroy(keyPair);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoDsaAsyKeyGeneratorBySpecTest, CryptoDsaGetPubKeyFromPriKeyErrTest, TestSize.Level0)
{
    HcfAsyKeyGeneratorBySpec *generator = nullptr;
    HcfResult ret = HcfAsyKeyGeneratorBySpecCreate(reinterpret_cast<HcfAsyKeyParamsSpec *>(&dsaCommonSpec), &generator);
    ASSERT_EQ(ret, HCF_SUCCESS);
    ASSERT_NE(generator, nullptr);

    HcfKeyPair *keyPair = nullptr;
    ret = generator->generateKeyPair(generator, &keyPair);
    ASSERT_EQ(ret, HCF_SUCCESS);
    ASSERT_NE(keyPair, nullptr);

    HcfPubKey *pubKey = nullptr;
    ret = keyPair->priKey->getPubKey(nullptr, &pubKey);
    ASSERT_NE(ret, HCF_SUCCESS);
    ASSERT_EQ(pubKey, nullptr);

    ret = keyPair->priKey->getPubKey(keyPair->priKey, nullptr);
    ASSERT_NE(ret, HCF_SUCCESS);

    HcfObjDestroy(keyPair);
    HcfObjDestroy(generator);
}
}