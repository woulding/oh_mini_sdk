/*
 * Copyright (C) 2025 Huawei Device Co., Ltd.
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
#include "crypto_common.h"
#include "crypto_asym_key.h"
#include "crypto_kdf.h"
#include "memory.h"
#include "memory_mock.h"

using namespace std;
using namespace testing::ext;

namespace {
class NativeKdfest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp();
    void TearDown();
};

void NativeKdfest::SetUpTestCase() {}
void NativeKdfest::TearDownTestCase() {}

void NativeKdfest::SetUp() // add init here, this will be called before test.
{
}

void NativeKdfest::TearDown() // add destroy here, this will be called when test case done.
{
}

static const char *g_keyData = "012345678901234567890123456789";
static const char *g_infoData = "infostring";
static const char *g_saltData = "saltstring";
static const char *g_password = "123456";

constexpr uint32_t KEY_NORMAL_LENGTH = 32;

HWTEST_F(NativeKdfest, NativeKdfest001, TestSize.Level0)
{
    OH_CryptoKdfParams *params = nullptr;
    OH_Crypto_ErrCode ret = OH_CryptoKdfParams_Create("HKDF", &params);
    EXPECT_EQ(ret, CRYPTO_SUCCESS);
    Crypto_DataBlob key = {.data = reinterpret_cast<uint8_t *>(const_cast<char *>(g_keyData)),
        .len = strlen(g_keyData)};
    Crypto_DataBlob salt = {.data = reinterpret_cast<uint8_t *>(const_cast<char *>(g_saltData)),
        .len = strlen(g_saltData)};
    Crypto_DataBlob info = {.data = reinterpret_cast<uint8_t *>(const_cast<char *>(g_infoData)),
        .len = strlen(g_infoData)};
    ret = OH_CryptoKdfParams_SetParam(params, CRYPTO_KDF_KEY_DATABLOB, &key);
    EXPECT_EQ(ret, CRYPTO_SUCCESS);
    ret = OH_CryptoKdfParams_SetParam(params, CRYPTO_KDF_SALT_DATABLOB, &salt);
    EXPECT_EQ(ret, CRYPTO_SUCCESS);
    ret = OH_CryptoKdfParams_SetParam(params, CRYPTO_KDF_INFO_DATABLOB, &info);
    EXPECT_EQ(ret, CRYPTO_SUCCESS);

    Crypto_DataBlob out  = {0};
    OH_CryptoKdf *kdfCtx = nullptr;
    ret = OH_CryptoKdf_Create("HKDF|SHA256|EXTRACT_AND_EXPAND", &kdfCtx);
    EXPECT_EQ(ret, CRYPTO_SUCCESS);
    ret = OH_CryptoKdf_Derive(kdfCtx, params, KEY_NORMAL_LENGTH, &out);
    EXPECT_EQ(ret, CRYPTO_SUCCESS);

    OH_Crypto_FreeDataBlob(&out);
    OH_CryptoKdf_Destroy(kdfCtx);
    OH_CryptoKdfParams_Destroy(params);
}

HWTEST_F(NativeKdfest, NativeKdfest002, TestSize.Level0)
{
    OH_CryptoKdfParams *params = nullptr;
    OH_Crypto_ErrCode ret = OH_CryptoKdfParams_Create("PBKDF2", &params);
    EXPECT_EQ(ret, CRYPTO_SUCCESS);

    Crypto_DataBlob password = {.data = reinterpret_cast<uint8_t *>(const_cast<char *>(g_password)),
        .len = strlen(g_password)};
    Crypto_DataBlob salt = {.data = reinterpret_cast<uint8_t *>(const_cast<char *>(g_saltData)),
        .len = strlen(g_saltData)};
    int iterations = 10000;
    Crypto_DataBlob iterationsData = {.data = reinterpret_cast<uint8_t *>(&iterations), .len = sizeof(int)};

    ret = OH_CryptoKdfParams_SetParam(params, CRYPTO_KDF_KEY_DATABLOB, &password);
    EXPECT_EQ(ret, CRYPTO_SUCCESS);
    ret = OH_CryptoKdfParams_SetParam(params, CRYPTO_KDF_SALT_DATABLOB, &salt);
    EXPECT_EQ(ret, CRYPTO_SUCCESS);
    ret = OH_CryptoKdfParams_SetParam(params, CRYPTO_KDF_ITER_COUNT_INT, &iterationsData);
    EXPECT_EQ(ret, CRYPTO_SUCCESS);

    Crypto_DataBlob out  = {0};
    OH_CryptoKdf *kdfCtx = nullptr;
    ret = OH_CryptoKdf_Create("PBKDF2|SHA256", &kdfCtx);
    EXPECT_EQ(ret, CRYPTO_SUCCESS);
    ret = OH_CryptoKdf_Derive(kdfCtx, params, KEY_NORMAL_LENGTH, &out);
    EXPECT_EQ(ret, CRYPTO_SUCCESS);

    OH_Crypto_FreeDataBlob(&out);
    OH_CryptoKdf_Destroy(kdfCtx);
    OH_CryptoKdfParams_Destroy(params);
}

HWTEST_F(NativeKdfest, NativeKdfest003, TestSize.Level0)
{
    OH_CryptoKdfParams *params = nullptr;
    OH_Crypto_ErrCode ret = OH_CryptoKdfParams_Create("SCRYPT", &params);
    EXPECT_EQ(ret, CRYPTO_SUCCESS);

    Crypto_DataBlob password = {.data = reinterpret_cast<uint8_t *>(const_cast<char *>(g_password)),
        .len = strlen(g_password)};
    Crypto_DataBlob salt = {.data = reinterpret_cast<uint8_t *>(const_cast<char *>(g_saltData)),
        .len = strlen(g_saltData)};

    uint64_t n = 1024;
    uint64_t p = 16;
    uint64_t r = 8;
    uint64_t maxMem = 1067008;
    Crypto_DataBlob nData = {.data = reinterpret_cast<uint8_t *>(&n), .len = sizeof(uint64_t)};
    Crypto_DataBlob pData = {.data = reinterpret_cast<uint8_t *>(&p), .len = sizeof(uint64_t)};
    Crypto_DataBlob rData = {.data = reinterpret_cast<uint8_t *>(&r), .len = sizeof(uint64_t)};
    Crypto_DataBlob maxMemData = {.data = reinterpret_cast<uint8_t *>(&maxMem), .len = sizeof(uint64_t)};
    ret = OH_CryptoKdfParams_SetParam(params, CRYPTO_KDF_KEY_DATABLOB, &password);
    EXPECT_EQ(ret, CRYPTO_SUCCESS);
    ret = OH_CryptoKdfParams_SetParam(params, CRYPTO_KDF_SALT_DATABLOB, &salt);
    EXPECT_EQ(ret, CRYPTO_SUCCESS);
    ret = OH_CryptoKdfParams_SetParam(params, CRYPTO_KDF_SCRYPT_N_UINT64, &nData);
    EXPECT_EQ(ret, CRYPTO_SUCCESS);
    ret = OH_CryptoKdfParams_SetParam(params, CRYPTO_KDF_SCRYPT_P_UINT64, &pData);
    EXPECT_EQ(ret, CRYPTO_SUCCESS);
    ret = OH_CryptoKdfParams_SetParam(params, CRYPTO_KDF_SCRYPT_R_UINT64, &rData);
    EXPECT_EQ(ret, CRYPTO_SUCCESS);
    ret = OH_CryptoKdfParams_SetParam(params, CRYPTO_KDF_SCRYPT_MAX_MEM_UINT64, &maxMemData);
    EXPECT_EQ(ret, CRYPTO_SUCCESS);

    Crypto_DataBlob out  = {0};
    OH_CryptoKdf *kdfCtx = nullptr;
    ret = OH_CryptoKdf_Create("SCRYPT", &kdfCtx);
    EXPECT_EQ(ret, CRYPTO_SUCCESS);
    ret = OH_CryptoKdf_Derive(kdfCtx, params, KEY_NORMAL_LENGTH, &out);
    EXPECT_EQ(ret, CRYPTO_SUCCESS);

    OH_Crypto_FreeDataBlob(&out);
    OH_CryptoKdf_Destroy(kdfCtx);
    OH_CryptoKdfParams_Destroy(params);
}

HWTEST_F(NativeKdfest, NativeKdfest004, TestSize.Level0)
{
    OH_CryptoKdfParams *params = nullptr;
    OH_Crypto_ErrCode ret = OH_CryptoKdfParams_Create("SCRYPT", nullptr);
    EXPECT_NE(ret, CRYPTO_SUCCESS);
    ret = OH_CryptoKdfParams_Create("XXXX", &params);
    EXPECT_NE(ret, CRYPTO_SUCCESS);
}

HWTEST_F(NativeKdfest, NativeKdfest005, TestSize.Level0)
{
    Crypto_DataBlob out  = {0};
    OH_CryptoKdf *kdfCtx = nullptr;
    OH_Crypto_ErrCode ret = OH_CryptoKdf_Create("HKDF|SHA256|EXTRACT_AND_EXPAND", &kdfCtx);
    EXPECT_EQ(ret, CRYPTO_SUCCESS);
    ret = OH_CryptoKdf_Derive(kdfCtx, nullptr, KEY_NORMAL_LENGTH, &out);
    EXPECT_NE(ret, CRYPTO_SUCCESS);

    OH_Crypto_FreeDataBlob(&out);
    OH_CryptoKdf_Destroy(kdfCtx);
}

HWTEST_F(NativeKdfest, NativeKdfest006, TestSize.Level0)
{
    uint8_t keyData[] = { 0xfd, 0x17, 0x19, 0x8b, 0x89, 0xab, 0x39, 0xc4, 0xab, 0x5d, 0x7c,
        0xca, 0x36, 0x3b, 0x82, 0xf9, 0xfd, 0x7e, 0x23, 0xc3, 0x98, 0x4d, 0xc8, 0xa2 };
    uint8_t infoData[] = { 0x85, 0x6a, 0x53, 0xf3, 0xe3, 0x6a, 0x26, 0xbb, 0xc5, 0x79, 0x28,
        0x79, 0xf3, 0x07, 0xcc, 0xe2 };
    uint8_t expectSecret[] = { 0x6e, 0x5f, 0xad, 0x86, 0x5c, 0xb4, 0xa5, 0x1c, 0x95, 0x20,
        0x9b, 0x16, 0xdf, 0x0c, 0xc4, 0x90, 0xbc, 0x2c, 0x90, 0x64, 0x40, 0x5c, 0x5b, 0xcc,
        0xd4, 0xee, 0x48, 0x32, 0xa5, 0x31, 0xfb, 0xe7, 0xf1, 0x0c, 0xb7, 0x9e, 0x2e, 0xab,
        0x6a, 0xb1, 0x14, 0x9f, 0xbd, 0x5a, 0x23, 0xcf, 0xda, 0xbc, 0x41, 0x24, 0x22, 0x69,
        0xc9, 0xdf, 0x22, 0xf6, 0x28, 0xc4, 0x42, 0x43, 0x33, 0x85, 0x5b, 0x64, 0xe9, 0x5e,
        0x2d, 0x4f, 0xb8, 0x46, 0x9c, 0x66, 0x9f, 0x17, 0x17, 0x6c, 0x07, 0xd1, 0x03, 0x37,
        0x6b, 0x10, 0xb3, 0x84, 0xec, 0x57, 0x63, 0xd8, 0xb8, 0xc6, 0x10, 0x40, 0x9f, 0x19,
        0xac, 0xa8, 0xeb, 0x31, 0xf9, 0xd8, 0x5c, 0xc6, 0x1a, 0x8d, 0x6d, 0x4a, 0x03, 0xd0,
        0x3e, 0x5a, 0x50, 0x6b, 0x78, 0xd6, 0x84, 0x7e, 0x93, 0xd2, 0x95, 0xee, 0x54, 0x8c,
        0x65, 0xaf, 0xed, 0xd2, 0xef, 0xec };

    OH_CryptoKdf *generator = nullptr;
    OH_Crypto_ErrCode ret = OH_CryptoKdf_Create("X963KDF|SHA1", &generator);
    EXPECT_EQ(ret, CRYPTO_SUCCESS);
    uint8_t out[128] = {0};
    Crypto_DataBlob output = {.data = out, .len = 128};
    Crypto_DataBlob key = {.data = keyData, .len = sizeof(keyData)};
    Crypto_DataBlob info = {.data = infoData, .len = sizeof(infoData)};
    OH_CryptoKdfParams *params = nullptr;
    ret = OH_CryptoKdfParams_Create("X963KDF", &params);
    EXPECT_EQ(ret, CRYPTO_SUCCESS);
    ret = OH_CryptoKdfParams_SetParam(params, CRYPTO_KDF_KEY_DATABLOB, &key);
    EXPECT_EQ(ret, CRYPTO_SUCCESS);
    ret = OH_CryptoKdfParams_SetParam(params, CRYPTO_KDF_INFO_DATABLOB, &info);
    EXPECT_EQ(ret, CRYPTO_SUCCESS);
    ret = OH_CryptoKdf_Derive(generator, params, 128, &output);
    EXPECT_EQ(ret, CRYPTO_SUCCESS);
    EXPECT_EQ(memcmp(output.data, expectSecret, sizeof(expectSecret)), 0);
    OH_CryptoKdf_Destroy(generator);
    OH_CryptoKdfParams_Destroy(params);
    OH_Crypto_FreeDataBlob(&output);
}

HWTEST_F(NativeKdfest, NativeKdfest007, TestSize.Level0)
{
    static uint8_t x963_sha512_info[] = {
        /* SharedInfo for first vector - 16 bytes */
        0x1e, 0x60, 0xe5, 0x1c, 0x11, 0xa5, 0x38, 0xb0, 0xea, 0x89, 0x90, 0xd6, 0x9a, 0x4c, 0x63, 0x58
    };
    static uint8_t x963_sha512_key[] = {
        /* First vector Z (shared secret) - 65 bytes (128-byte output) */
        0x00, 0x9d, 0xcd, 0x6b, 0xa5, 0xc8, 0xc8, 0x03, 0xca, 0x21, 0xf9, 0x99, 0x6c, 0xa5, 0xdd,
        0x86, 0x04, 0x7d, 0x4d, 0xdc, 0x15, 0x0f, 0xdd, 0xac, 0xe1, 0xb1, 0xeb, 0xe9, 0x96, 0xc2,
        0x00, 0x7e, 0x3e, 0xe9, 0x07, 0xc8, 0xff, 0x03, 0xb9, 0xef, 0x76, 0x6e, 0x8c, 0xeb, 0x4d,
        0xed, 0xf7, 0x48, 0x9e, 0x51, 0x62, 0xe2, 0x27, 0x8c, 0x01, 0x85, 0xe4, 0xbe, 0x38, 0x1b,
        0xec, 0x17, 0xdd, 0x99, 0x2c, 0xf8
    };
    static uint8_t x963_sha512_expectSecret[] = {
        /* First vector expected derived key - 128 bytes (1024 bits) */
        0x4e, 0x55, 0x03, 0x6a, 0x32, 0xf3, 0x2f, 0xc9, 0x65, 0x04, 0x6f, 0xdf, 0xbf, 0x68, 0x6c,
        0x10, 0x8e, 0x43, 0xa6, 0x9f, 0x8f, 0xc1, 0xa6, 0x4f, 0xf1, 0xbd, 0x77, 0x76, 0x3f, 0x2e,
        0xed, 0xc8, 0xbf, 0x27, 0x7d, 0x78, 0xb4, 0xce, 0x31, 0x24, 0x3e, 0x1a, 0xdb, 0xe2, 0xc2,
        0xd5, 0xdd, 0x59, 0xb4, 0x75, 0x03, 0xb5, 0xb9, 0x0b, 0x54, 0xf9, 0xd7, 0xa9, 0xa5, 0xae,
        0xa4, 0x9c, 0x7f, 0x02, 0x83, 0xcb, 0x64, 0xc3, 0x84, 0x9a, 0x1d, 0x15, 0x70, 0x00, 0xfd,
        0x41, 0xef, 0x6c, 0x1d, 0x1a, 0x5b, 0x62, 0x73, 0x4e, 0x7c, 0x9a, 0x20, 0xdc, 0xfb, 0x57,
        0xf2, 0xda, 0x97, 0x49, 0x33, 0xf5, 0x7e, 0xe6, 0x19, 0xd7, 0x28, 0x98, 0xd0, 0xe9, 0x3d,
        0x9a, 0x42, 0x54, 0xaa, 0xdd, 0xf7, 0x39, 0x41, 0xd6, 0x26, 0x92, 0x98, 0xb4, 0xd4, 0x9c,
        0x0a, 0xc6, 0x4a, 0x33, 0x80, 0x2f, 0xe8, 0xf2
    };
    OH_CryptoKdf *generator = nullptr;
    OH_Crypto_ErrCode ret = OH_CryptoKdf_Create("X963KDF|SHA512", &generator);
    EXPECT_EQ(ret, CRYPTO_SUCCESS);
    uint8_t out[128] = {0};
    Crypto_DataBlob output = {.data = out, .len = 128};
    Crypto_DataBlob key = {.data = x963_sha512_key, .len = sizeof(x963_sha512_key)};
    Crypto_DataBlob info = {.data = x963_sha512_info, .len = sizeof(x963_sha512_info)};
    OH_CryptoKdfParams *params = nullptr;
    ret = OH_CryptoKdfParams_Create("X963KDF", &params);
    EXPECT_EQ(ret, CRYPTO_SUCCESS);
    ret = OH_CryptoKdfParams_SetParam(params, CRYPTO_KDF_KEY_DATABLOB, &key);
    EXPECT_EQ(ret, CRYPTO_SUCCESS);
    ret = OH_CryptoKdfParams_SetParam(params, CRYPTO_KDF_INFO_DATABLOB, &info);
    EXPECT_EQ(ret, CRYPTO_SUCCESS);
    ret = OH_CryptoKdf_Derive(generator, params, 128, &output);
    EXPECT_EQ(ret, CRYPTO_SUCCESS);
    EXPECT_EQ(memcmp(output.data, x963_sha512_expectSecret, sizeof(x963_sha512_expectSecret)), 0);
    OH_CryptoKdf_Destroy(generator);
    OH_CryptoKdfParams_Destroy(params);
    OH_Crypto_FreeDataBlob(&output);
}
}