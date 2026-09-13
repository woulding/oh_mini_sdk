/*
 * Copyright (C) 2022 Huawei Device Co., Ltd.
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

#include "asykeygenerator_fuzzer.h"
#include <cstddef>
#include <cstdint>
#include <string>
#include "securec.h"

#include "asy_key_generator.h"
#include "blob.h"
#include "detailed_alg_25519_key_params.h"
#include "detailed_dh_key_params.h"
#include "detailed_dsa_key_params.h"
#include "detailed_ecc_key_params.h"
#include "detailed_rsa_key_params.h"
#include "ecc_openssl_common_param_spec.h"
#include "ecc_common.h"
#include "ecc_key_util.h"
#include "dh_key_util.h"
#include "key_utils.h"
#include "memory.h"
#include "result.h"
#include <fuzzer/FuzzedDataProvider.h>

using namespace std;

namespace {
HcfEccCommParamsSpec *g_sm2256CommSpec = nullptr;
HcfEccCommParamsSpec *g_brainpoolP160r1CommSpec = nullptr;
HcfDhCommParamsSpec *g_dhCommSpec = nullptr;
static string g_ed25519AlgoName = "Ed25519";
static string g_x25519AlgoName = "X25519";
}

static const uint32_t ASCII_CODE_ZERO = 48;
static bool IsBigEndian(void)
{
    uint32_t *pointer = const_cast<uint32_t *>(&ASCII_CODE_ZERO);
    char firstChar = *reinterpret_cast<char *>(pointer);
    if (firstChar == '0') {
        return false;
    } else {
        return true;
    }
}

namespace OHOS {
    constexpr int32_t PLEN_BITS = 3072;
    constexpr int32_t SKLEN_BITS = 256;

    enum class GenerateType {
        FUZZ_COMMON = 0,
        FUZZ_PUBKEY = 1,
        FUZZ_PRIKEY = 2,
        FUZZ_KEYPAIR = 3,
    };
    static bool g_testFlag = true;
    static const int ECC224_PUB_KEY_LEN = 80;
    static const int ECC224_PRI_KEY_LEN = 44;
    static const int SM2256_PUB_KEY_LEN = 91;
    static const int SM2256_PRI_KEY_LEN = 51;
    static const int BRAINPOOLP160R1_PUB_KEY_LEN = 68;
    static const int BRAINPOOLP160R1_PRI_KEY_LEN = 40;
    static const int ED25519_PUB_KEY_LEN = 44;
    static const int ED25519_PRI_KEY_LEN = 48;
    static const int X25519_PUB_KEY_LEN = 44;
    static const int X25519_PRI_KEY_LEN = 48;
    static const int DH_PUB_KEY_LEN = 553;
    static const int DH_PRI_KEY_LEN = 323;
    static uint8_t g_mockEcc224PubKey[ECC224_PUB_KEY_LEN] = { 48, 78, 48, 16, 6, 7, 42, 134, 72, 206,
        61, 2, 1, 6, 5, 43, 129, 4, 0, 33, 3, 58, 0, 4, 252, 171, 11, 115, 79, 252, 109, 120, 46, 97, 131, 145, 207,
        141, 146, 235, 133, 37, 218, 180, 8, 149, 47, 244, 137, 238, 207, 95, 153, 65, 250, 32, 77, 184, 249, 181,
        172, 192, 2, 99, 194, 170, 25, 44, 255, 87, 246, 42, 133, 83, 66, 197, 97, 95, 12, 84 };

    static uint8_t g_mockEcc224PriKey[ECC224_PRI_KEY_LEN] = { 48, 42, 2, 1, 1, 4, 28, 250, 86, 6,
        147, 222, 43, 252, 139, 90, 139, 5, 33, 184, 230, 26, 68, 94, 57, 145, 229, 146, 49, 221, 119, 206, 32, 198,
        19, 160, 7, 6, 5, 43, 129, 4, 0, 33 };

    static uint8_t g_mockSm2256PubKey[SM2256_PUB_KEY_LEN] = { 48, 89, 48, 19, 6, 7, 42, 134, 72, 206, 61, 2, 1, 6, 8,
        42, 129, 28, 207, 85, 1, 130, 45, 3, 66, 0, 4, 84, 128, 137, 18, 201, 132, 210, 60, 20, 222, 30, 185, 219, 9,
        72, 46, 148, 231, 101, 110, 21, 148, 127, 148, 90, 64, 20, 254, 155, 69, 61, 249, 46, 238, 158, 218, 72, 159,
        102, 22, 2, 54, 42, 255, 37, 96, 92, 193, 152, 172, 86, 64, 228, 244, 125, 115, 97, 211, 232, 74, 79, 25,
        217, 239 };

    static uint8_t g_mockSm2256PriKey[SM2256_PRI_KEY_LEN] = { 48, 49, 2, 1, 1, 4, 32, 78, 6, 176, 182, 178, 223, 78,
        63, 118, 13, 15, 35, 44, 56, 78, 69, 212, 192, 65, 232, 103, 124, 247, 30, 211, 81, 139, 187, 28, 165, 8, 248,
        160, 10, 6, 8, 42, 129, 28, 207, 85, 1, 130, 45 };

    static uint8_t g_mockBrainpoolPubKey[BRAINPOOLP160R1_PUB_KEY_LEN] = { 48, 66, 48, 20, 6, 7, 42, 134, 72, 206, 61,
        2, 1, 6, 9, 43, 36, 3, 3, 2, 8, 1, 1, 1, 3, 42, 0, 4, 37, 67, 178, 178, 176, 241, 23, 119, 74, 231, 82, 88,
        215, 227, 37, 24, 129, 177, 152, 142, 144, 155, 44, 97, 145, 114, 242, 156, 129, 225, 186, 196, 113, 41, 198,
        85, 186, 69, 198, 146 };

    static uint8_t g_mockBrainpoolPriKey[BRAINPOOLP160R1_PRI_KEY_LEN] = { 48, 38, 2, 1, 1, 4, 20, 116, 221, 96, 238,
        46, 76, 111, 184, 30, 42, 223, 86, 187, 131, 127, 41, 28, 223, 93, 134, 160, 11, 6, 9, 43, 36, 3, 3, 2, 8, 1,
        1, 1 };

    static uint8_t g_mockEd25519PubKey[ED25519_PUB_KEY_LEN] = { 48, 42, 48, 5, 6, 3, 43, 101, 112, 3, 33, 0, 101, 94,
        172, 9, 171, 197, 147, 204, 102, 87, 132, 67, 59, 108, 68, 121, 150, 93, 83, 26, 173, 99, 63, 125, 86, 91, 77,
        207, 147, 216, 158, 5 };

    static uint8_t g_mockEd25519PriKey[ED25519_PRI_KEY_LEN] = { 48, 46, 2, 1, 0, 48, 5, 6, 3, 43, 101, 112, 4, 34, 4,
        32, 31, 229, 164, 209, 117, 143, 227, 85, 227, 67, 214, 165, 40, 220, 217, 105, 123, 246, 71, 104, 129, 79, 19,
        173, 36, 32, 69, 83, 25, 136, 92, 25 };

    static uint8_t g_mockX25519PubKey[X25519_PUB_KEY_LEN] = { 48, 42, 48, 5, 6, 3, 43, 101, 110, 3, 33, 0, 173, 38, 49,
        140, 12, 119, 139, 84, 170, 234, 223, 247, 240, 167, 79, 192, 41, 114, 211, 76, 38, 151, 123, 141, 209, 44, 31,
        97, 16, 137, 236, 5 };

    static uint8_t g_mockX25519PriKey[X25519_PRI_KEY_LEN] = { 48, 46, 2, 1, 0, 48, 5, 6, 3, 43, 101, 110, 4, 34, 4, 32,
        96, 70, 225, 130, 145, 57, 68, 247, 129, 6, 13, 185, 167, 100, 237, 166, 63, 125, 219, 75, 59, 27, 123, 100, 68,
        136, 52, 93, 100, 253, 222, 80 };

    static uint8_t g_mockDhPubKey[DH_PUB_KEY_LEN] = { 48, 130, 2, 37, 48, 130, 1, 23, 6, 9, 42, 134, 72, 134, 247, 13,
        1, 3, 1, 48, 130, 1, 8, 2, 130, 1, 1, 0, 255, 255, 255, 255, 255, 255, 255, 255, 201, 15, 218, 162, 33, 104,
        194, 52, 196, 198, 98, 139, 128, 220, 28, 209, 41, 2, 78, 8, 138, 103, 204, 116, 2, 11, 190, 166, 59, 19, 155,
        34, 81, 74, 8, 121, 142, 52, 4, 221, 239, 149, 25, 179, 205, 58, 67, 27, 48, 43, 10, 109, 242, 95, 20, 55, 79,
        225, 53, 109, 109, 81, 194, 69, 228, 133, 181, 118, 98, 94, 126, 198, 244, 76, 66, 233, 166, 55, 237, 107, 11,
        255, 92, 182, 244, 6, 183, 237, 238, 56, 107, 251, 90, 137, 159, 165, 174, 159, 36, 17, 124, 75, 31, 230, 73,
        40, 102, 81, 236, 228, 91, 61, 194, 0, 124, 184, 161, 99, 191, 5, 152, 218, 72, 54, 28, 85, 211, 154, 105, 22,
        63, 168, 253, 36, 207, 95, 131, 101, 93, 35, 220, 163, 173, 150, 28, 98, 243, 86, 32, 133, 82, 187, 158, 213,
        41, 7, 112, 150, 150, 109, 103, 12, 53, 78, 74, 188, 152, 4, 241, 116, 108, 8, 202, 24, 33, 124, 50, 144, 94,
        70, 46, 54, 206, 59, 227, 158, 119, 44, 24, 14, 134, 3, 155, 39, 131, 162, 236, 7, 162, 143, 181, 197, 93, 240,
        111, 76, 82, 201, 222, 43, 203, 246, 149, 88, 23, 24, 57, 149, 73, 124, 234, 149, 106, 229, 21, 210, 38, 24,
        152, 250, 5, 16, 21, 114, 142, 90, 138, 172, 170, 104, 255, 255, 255, 255, 255, 255, 255, 255, 2, 1, 2, 3, 130,
        1, 6, 0, 2, 130, 1, 1, 0, 228, 194, 161, 19, 145, 70, 104, 142, 66, 200, 1, 158, 107, 23, 93, 212, 19, 223,
        145, 196, 11, 179, 169, 69, 136, 163, 136, 142, 122, 230, 238, 249, 102, 227, 49, 92, 64, 255, 8, 185, 238, 5,
        97, 253, 174, 161, 140, 70, 40, 159, 105, 249, 76, 206, 35, 97, 16, 138, 185, 172, 90, 77, 248, 8, 242, 31,
        212, 84, 224, 226, 60, 71, 162, 47, 158, 148, 251, 118, 206, 151, 80, 23, 158, 241, 181, 139, 129, 240, 26,
        150, 180, 237, 252, 73, 84, 173, 63, 215, 130, 6, 124, 97, 118, 165, 133, 66, 235, 97, 143, 148, 105, 86, 174,
        71, 254, 169, 22, 172, 116, 130, 198, 237, 131, 230, 113, 12, 228, 21, 138, 128, 168, 40, 207, 205, 190, 160,
        114, 156, 90, 210, 114, 54, 42, 191, 167, 99, 100, 138, 145, 120, 165, 62, 162, 238, 62, 76, 162, 90, 97, 245,
        30, 55, 157, 139, 36, 118, 121, 242, 214, 79, 0, 27, 36, 4, 243, 62, 107, 34, 222, 110, 252, 24, 202, 3, 216,
        160, 83, 228, 254, 253, 87, 198, 235, 234, 210, 80, 124, 218, 188, 82, 116, 144, 70, 40, 231, 124, 172, 59,
        154, 6, 87, 22, 9, 198, 113, 142, 39, 64, 137, 34, 100, 195, 55, 75, 204, 185, 1, 222, 27, 245, 213, 22, 222,
        83, 0, 222, 8, 194, 21, 85, 90, 32, 236, 205, 86, 38, 70, 57, 171, 248, 168, 52, 85, 46, 1, 149 };

    static uint8_t g_mockDhPriKey[DH_PRI_KEY_LEN] = { 48, 130, 1, 63, 2, 1, 0, 48, 130, 1, 23, 6, 9, 42, 134, 72, 134,
        247, 13, 1, 3, 1, 48, 130, 1, 8, 2, 130, 1, 1, 0, 255, 255, 255, 255, 255, 255, 255, 255, 201, 15, 218, 162,
        33, 104, 194, 52, 196, 198, 98, 139, 128, 220, 28, 209, 41, 2, 78, 8, 138, 103, 204, 116, 2, 11, 190, 166, 59,
        19, 155, 34, 81, 74, 8, 121, 142, 52, 4, 221, 239, 149, 25, 179, 205, 58, 67, 27, 48, 43, 10, 109, 242, 95, 20,
        55, 79, 225, 53, 109, 109, 81, 194, 69, 228, 133, 181, 118, 98, 94, 126, 198, 244, 76, 66, 233, 166, 55, 237,
        107, 11, 255, 92, 182, 244, 6, 183, 237, 238, 56, 107, 251, 90, 137, 159, 165, 174, 159, 36, 17, 124, 75, 31,
        230, 73, 40, 102, 81, 236, 228, 91, 61, 194, 0, 124, 184, 161, 99, 191, 5, 152, 218, 72, 54, 28, 85, 211, 154,
        105, 22, 63, 168, 253, 36, 207, 95, 131, 101, 93, 35, 220, 163, 173, 150, 28, 98, 243, 86, 32, 133, 82, 187,
        158, 213, 41, 7, 112, 150, 150, 109, 103, 12, 53, 78, 74, 188, 152, 4, 241, 116, 108, 8, 202, 24, 33, 124, 50,
        144, 94, 70, 46, 54, 206, 59, 227, 158, 119, 44, 24, 14, 134, 3, 155, 39, 131, 162, 236, 7, 162, 143, 181, 197,
        93, 240, 111, 76, 82, 201, 222, 43, 203, 246, 149, 88, 23, 24, 57, 149, 73, 124, 234, 149, 106, 229, 21, 210,
        38, 24, 152, 250, 5, 16, 21, 114, 142, 90, 138, 172, 170, 104, 255, 255, 255, 255, 255, 255, 255, 255, 2, 1, 2,
        4, 31, 2, 29, 0, 237, 124, 61, 162, 122, 242, 226, 132, 236, 155, 58, 14, 154, 128, 233, 85, 121, 59, 252, 255,
        157, 145, 75, 251, 236, 154, 85, 203 };

    constexpr uint32_t DSA2048_PRI_SIZE = 20;
    constexpr uint32_t DSA2048_PUB_SIZE = 256;
    constexpr uint32_t DSA2048_P_SIZE = 256;
    constexpr uint32_t DSA2048_Q_SIZE = 20;
    constexpr uint32_t DSA2048_G_SIZE = 256;
    static const char *g_algNameDSA = "DSA";

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
        .data = IsBigEndian() ? g_dsa2048PrivBigE : g_dsa2048PrivLittleE, .len = DSA2048_PRI_SIZE };
    static HcfBigInteger pk_BN = {
        .data = IsBigEndian() ? g_dsa2048PubBigE : g_dsa2048PubLittleE, .len = DSA2048_PUB_SIZE };
    static HcfBigInteger p_BN = { .data = IsBigEndian() ? g_dsa2048PBigE : g_dsa2048PLittleE, .len = DSA2048_P_SIZE };
    static HcfBigInteger q_BN = { .data = IsBigEndian() ? g_dsa2048QBigE : g_dsa2048QLittleE, .len = DSA2048_Q_SIZE };
    static HcfBigInteger g_BN = { .data = IsBigEndian() ? g_dsa2048GBigE : g_dsa2048GLittleE, .len = DSA2048_G_SIZE };

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

    static string g_eccAlgName = "ECC";
    static string g_eccFieldType = "Fp";
    static int32_t g_ecc224CorrectH = 1;

    HcfEccCommParamsSpec g_ecc224CommSpec;
    HcfEccPubKeyParamsSpec g_ecc224PubKeySpec;
    HcfEccPriKeyParamsSpec g_ecc224PriKeySpec;
    HcfEccKeyPairParamsSpec g_ecc224KeyPairSpec;
    HcfECFieldFp g_fieldFp;

    constexpr uint32_t RSA_2048_N_BYTE_SIZE = 256;
    constexpr uint32_t RSA_2048_D_BYTE_SIZE = 256;
    constexpr uint32_t RSA_2048_E_BYTE_SIZE = 3;

    constexpr unsigned char CORRECT_N[] =
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

    constexpr unsigned char CORRECT_E[] = "\x01\x00\x01";

    constexpr unsigned char CORRECT_D[] =
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

    static void GenerateRsa2048CorrectCommonKeySpec(unsigned char *dataN, HcfRsaCommParamsSpec *returnSpec)
    {
        RemoveLastChar(CORRECT_N, dataN, RSA_2048_N_BYTE_SIZE);
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
        RemoveLastChar(CORRECT_E, dataE, RSA_2048_E_BYTE_SIZE);
        if (!IsBigEndian()) {
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
        RemoveLastChar(CORRECT_E, dataE, RSA_2048_E_BYTE_SIZE);
        RemoveLastChar(CORRECT_D, dataD, RSA_2048_D_BYTE_SIZE);
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

    static HcfResult ConstructEcc224CommParamsSpec(HcfAsyKeyParamsSpec **spec)
    {
        HcfEccCommParamsSpec *eccCommSpec = &g_ecc224CommSpec;
        HcfECField *tmpField = (HcfECField *)(&g_fieldFp);

        eccCommSpec->base.algName = const_cast<char *>(g_eccAlgName.c_str());
        eccCommSpec->base.specType = HCF_COMMON_PARAMS_SPEC;
        eccCommSpec->field = tmpField;
        eccCommSpec->field->fieldType = const_cast<char *>(g_eccFieldType.c_str());
        (reinterpret_cast<HcfECFieldFp *>(eccCommSpec->field))->p.data =
            (IsBigEndian() ? g_ecc224CorrectBigP : g_ecc224CorrectLittleP);
        (reinterpret_cast<HcfECFieldFp *>(eccCommSpec->field))->p.len = NID_secp224r1_len;
        eccCommSpec->a.data = (IsBigEndian() ? g_ecc224CorrectBigA : g_ecc224CorrectLittleA);
        eccCommSpec->a.len = NID_secp224r1_len;
        eccCommSpec->b.data = (IsBigEndian() ? g_ecc224CorrectBigB : g_ecc224CorrectLittleB);
        eccCommSpec->b.len = NID_secp224r1_len;
        eccCommSpec->g.x.data = (IsBigEndian() ? g_ecc224CorrectBigGX : g_ecc224CorrectLittleGX);
        eccCommSpec->g.x.len = NID_secp224r1_len;
        eccCommSpec->g.y.data = (IsBigEndian() ? g_ecc224CorrectBigGY : g_ecc224CorrectLittleGY);
        eccCommSpec->g.y.len = NID_secp224r1_len;
        eccCommSpec->n.data = (IsBigEndian() ? g_ecc224CorrectBigN : g_ecc224CorrectLittleN);
        eccCommSpec->n.len = NID_secp224r1_len;
        eccCommSpec->h = g_ecc224CorrectH;

        *spec = reinterpret_cast<HcfAsyKeyParamsSpec *>(eccCommSpec);
        return HCF_SUCCESS;
    }

    static HcfResult ConstructEcc224PubKeyParamsSpec(HcfAsyKeyParamsSpec **spec)
    {
        HcfEccPubKeyParamsSpec *eccPubKeySpec = &g_ecc224PubKeySpec;
        HcfECField *tmpField = (HcfECField *)(&g_fieldFp);

        eccPubKeySpec->base.base.algName = const_cast<char *>(g_eccAlgName.c_str());
        eccPubKeySpec->base.base.specType = HCF_PUBLIC_KEY_SPEC;
        eccPubKeySpec->base.field = tmpField;
        eccPubKeySpec->base.field->fieldType = const_cast<char *>(g_eccFieldType.c_str());
        (reinterpret_cast<HcfECFieldFp *>(eccPubKeySpec->base.field))->p.data =
            (IsBigEndian() ? g_ecc224CorrectBigP : g_ecc224CorrectLittleP);
        (reinterpret_cast<HcfECFieldFp *>(eccPubKeySpec->base.field))->p.len = NID_secp224r1_len;
        eccPubKeySpec->base.a.data = (IsBigEndian() ? g_ecc224CorrectBigA : g_ecc224CorrectLittleA);
        eccPubKeySpec->base.a.len = NID_secp224r1_len;
        eccPubKeySpec->base.b.data = (IsBigEndian() ? g_ecc224CorrectBigB : g_ecc224CorrectLittleB);
        eccPubKeySpec->base.b.len = NID_secp224r1_len;
        eccPubKeySpec->base.g.x.data = (IsBigEndian() ? g_ecc224CorrectBigGX : g_ecc224CorrectLittleGX);
        eccPubKeySpec->base.g.x.len = NID_secp224r1_len;
        eccPubKeySpec->base.g.y.data = (IsBigEndian() ? g_ecc224CorrectBigGY : g_ecc224CorrectLittleGY);
        eccPubKeySpec->base.g.y.len = NID_secp224r1_len;
        eccPubKeySpec->base.n.data = (IsBigEndian() ? g_ecc224CorrectBigN : g_ecc224CorrectLittleN);
        eccPubKeySpec->base.n.len = NID_secp224r1_len;
        eccPubKeySpec->base.h = g_ecc224CorrectH;
        eccPubKeySpec->pk.x.data = (IsBigEndian() ? g_ecc224CorrectBigPkX : g_ecc224CorrectLittlePkX);
        eccPubKeySpec->pk.x.len = NID_secp224r1_len;
        eccPubKeySpec->pk.y.data = (IsBigEndian() ? g_ecc224CorrectBigPkY : g_ecc224CorrectLittlePkY);
        eccPubKeySpec->pk.y.len = NID_secp224r1_len;

        *spec = reinterpret_cast<HcfAsyKeyParamsSpec *>(eccPubKeySpec);
        return HCF_SUCCESS;
    }

    static HcfResult ConstructEcc224PriKeyParamsSpec(HcfAsyKeyParamsSpec **spec)
    {
        HcfEccPriKeyParamsSpec *eccPriKeySpec = &g_ecc224PriKeySpec;
        HcfECField *tmpField = (HcfECField *)(&g_fieldFp);

        eccPriKeySpec->base.base.algName = const_cast<char *>(g_eccAlgName.c_str());
        eccPriKeySpec->base.base.specType = HCF_PRIVATE_KEY_SPEC;
        eccPriKeySpec->base.field = tmpField;
        eccPriKeySpec->base.field->fieldType = const_cast<char *>(g_eccFieldType.c_str());
        (reinterpret_cast<HcfECFieldFp *>(eccPriKeySpec->base.field))->p.data =
            (IsBigEndian() ? g_ecc224CorrectBigP : g_ecc224CorrectLittleP);
        (reinterpret_cast<HcfECFieldFp *>(eccPriKeySpec->base.field))->p.len = NID_secp224r1_len;
        eccPriKeySpec->base.a.data = (IsBigEndian() ? g_ecc224CorrectBigA : g_ecc224CorrectLittleA);
        eccPriKeySpec->base.a.len = NID_secp224r1_len;
        eccPriKeySpec->base.b.data = (IsBigEndian() ? g_ecc224CorrectBigB : g_ecc224CorrectLittleB);
        eccPriKeySpec->base.b.len = NID_secp224r1_len;
        eccPriKeySpec->base.g.x.data = (IsBigEndian() ? g_ecc224CorrectBigGX : g_ecc224CorrectLittleGX);
        eccPriKeySpec->base.g.x.len = NID_secp224r1_len;
        eccPriKeySpec->base.g.y.data = (IsBigEndian() ? g_ecc224CorrectBigGY : g_ecc224CorrectLittleGY);
        eccPriKeySpec->base.g.y.len = NID_secp224r1_len;
        eccPriKeySpec->base.n.data = (IsBigEndian() ? g_ecc224CorrectBigN : g_ecc224CorrectLittleN);
        eccPriKeySpec->base.n.len = NID_secp224r1_len;
        eccPriKeySpec->base.h = g_ecc224CorrectH;
        eccPriKeySpec->sk.data = (IsBigEndian() ? g_ecc224CorrectBigSk : g_ecc224CorrectLittleSk);
        eccPriKeySpec->sk.len = NID_secp224r1_len;

        *spec = reinterpret_cast<HcfAsyKeyParamsSpec *>(eccPriKeySpec);
        return HCF_SUCCESS;
    }

    static HcfResult ConstructEcc224KeyPairParamsSpec(HcfAsyKeyParamsSpec **spec)
    {
        HcfEccKeyPairParamsSpec *eccKeyPairSpec = &g_ecc224KeyPairSpec;
        HcfECField *tmpField = (HcfECField *)(&g_fieldFp);

        eccKeyPairSpec->base.base.algName = const_cast<char *>(g_eccAlgName.c_str());
        eccKeyPairSpec->base.base.specType = HCF_KEY_PAIR_SPEC;
        eccKeyPairSpec->base.field = tmpField;
        eccKeyPairSpec->base.field->fieldType = const_cast<char *>(g_eccFieldType.c_str());
        (reinterpret_cast<HcfECFieldFp *>(eccKeyPairSpec->base.field))->p.data =
            (IsBigEndian() ? g_ecc224CorrectBigP : g_ecc224CorrectLittleP);
        (reinterpret_cast<HcfECFieldFp *>(eccKeyPairSpec->base.field))->p.len = NID_secp224r1_len;
        eccKeyPairSpec->base.a.data = (IsBigEndian() ? g_ecc224CorrectBigA : g_ecc224CorrectLittleA);
        eccKeyPairSpec->base.a.len = NID_secp224r1_len;
        eccKeyPairSpec->base.b.data = (IsBigEndian() ? g_ecc224CorrectBigB : g_ecc224CorrectLittleB);
        eccKeyPairSpec->base.b.len = NID_secp224r1_len;
        eccKeyPairSpec->base.g.x.data = (IsBigEndian() ? g_ecc224CorrectBigGX : g_ecc224CorrectLittleGX);
        eccKeyPairSpec->base.g.x.len = NID_secp224r1_len;
        eccKeyPairSpec->base.g.y.data = (IsBigEndian() ? g_ecc224CorrectBigGY : g_ecc224CorrectLittleGY);
        eccKeyPairSpec->base.g.y.len = NID_secp224r1_len;
        eccKeyPairSpec->base.n.data = (IsBigEndian() ? g_ecc224CorrectBigN : g_ecc224CorrectLittleN);
        eccKeyPairSpec->base.n.len = NID_secp224r1_len;
        eccKeyPairSpec->base.h = g_ecc224CorrectH;
        eccKeyPairSpec->pk.x.data = (IsBigEndian() ? g_ecc224CorrectBigPkX : g_ecc224CorrectLittlePkX);
        eccKeyPairSpec->pk.x.len = NID_secp224r1_len;
        eccKeyPairSpec->pk.y.data = (IsBigEndian() ? g_ecc224CorrectBigPkY : g_ecc224CorrectLittlePkY);
        eccKeyPairSpec->pk.y.len = NID_secp224r1_len;
        eccKeyPairSpec->sk.data = (IsBigEndian() ? g_ecc224CorrectBigSk : g_ecc224CorrectLittleSk);
        eccKeyPairSpec->sk.len = NID_secp224r1_len;

        *spec = reinterpret_cast<HcfAsyKeyParamsSpec *>(eccKeyPairSpec);
        return HCF_SUCCESS;
    }

    static HcfResult ConstructSm2256CommParamsSpec(const std::string &algoName, HcfEccCommParamsSpec **spec)
    {
        HcfEccCommParamsSpec *eccCommSpec = nullptr;

        HcfEccKeyUtilCreate(algoName.c_str(), &eccCommSpec);
        if (eccCommSpec == nullptr) {
            return HCF_INVALID_PARAMS;
        }
        *spec = eccCommSpec;
        return HCF_SUCCESS;
    }

    static HcfResult ConstructSm2256PubKeyBigInt(HcfKeyPair *keyPair, HcfEccPubKeyParamsSpec *eccPubKeySpec)
    {
        HcfBigInteger retBigInt = { .data = nullptr, .len = 0 };
        HcfResult res = keyPair->pubKey->getAsyKeySpecBigInteger(keyPair->pubKey, ECC_PK_X_BN, &retBigInt);
        if (res != HCF_SUCCESS) {
            return res;
        }
        eccPubKeySpec->pk.x.data = retBigInt.data;
        eccPubKeySpec->pk.x.len = retBigInt.len;

        res = keyPair->pubKey->getAsyKeySpecBigInteger(keyPair->pubKey, ECC_PK_Y_BN, &retBigInt);
        if (res != HCF_SUCCESS) {
            HcfFree(eccPubKeySpec->pk.x.data);
            eccPubKeySpec->pk.x.data = nullptr;
            eccPubKeySpec->pk.x.len = 0;
            return res;
        }
        eccPubKeySpec->pk.y.data = retBigInt.data;
        eccPubKeySpec->pk.y.len = retBigInt.len;
        return HCF_SUCCESS;
    }

    HcfResult ConstructSm2256PubKeyParamsSpec(const std::string &algoName, HcfEccCommParamsSpec *eccCommSpec,
        HcfAsyKeyParamsSpec **spec)
    {
        HcfResult res = HCF_ERR_CRYPTO_OPERATION;
        HcfAsyKeyGenerator *generator = nullptr;
        if (HcfAsyKeyGeneratorCreate(algoName.c_str(), &generator) != HCF_SUCCESS) {
            return res;
        }

        HcfKeyPair *keyPair = nullptr;
        if (generator->generateKeyPair(generator, nullptr, &keyPair) != HCF_SUCCESS) {
            HcfObjDestroy(generator);
            return res;
        }

        auto eccPubKeySpec = reinterpret_cast<HcfEccPubKeyParamsSpec *>(HcfMalloc(sizeof(HcfEccPubKeyParamsSpec), 0));
        if (eccPubKeySpec != nullptr) {
            eccPubKeySpec->base.base.algName = eccCommSpec->base.algName;
            eccPubKeySpec->base.base.specType = HCF_PUBLIC_KEY_SPEC;
            eccPubKeySpec->base.field = eccCommSpec->field;
            eccPubKeySpec->base.field->fieldType = eccCommSpec->field->fieldType;
            (reinterpret_cast<HcfECFieldFp *>(eccPubKeySpec->base.field))->p.data =
                (reinterpret_cast<HcfECFieldFp *>(eccCommSpec->field))->p.data;
            (reinterpret_cast<HcfECFieldFp *>(eccPubKeySpec->base.field))->p.len =
                (reinterpret_cast<HcfECFieldFp *>(eccCommSpec->field))->p.len;
            eccPubKeySpec->base.a.data = eccCommSpec->a.data;
            eccPubKeySpec->base.a.len = eccCommSpec->a.len;
            eccPubKeySpec->base.b.data = eccCommSpec->b.data;
            eccPubKeySpec->base.b.len = eccCommSpec->b.len;
            eccPubKeySpec->base.g.x.data = eccCommSpec->g.x.data;
            eccPubKeySpec->base.g.x.len = eccCommSpec->g.x.len;
            eccPubKeySpec->base.g.y.data = eccCommSpec->g.y.data;
            eccPubKeySpec->base.g.y.len = eccCommSpec->g.y.len;
            eccPubKeySpec->base.n.data = eccCommSpec->n.data;
            eccPubKeySpec->base.n.len = eccCommSpec->n.len;
            eccPubKeySpec->base.h = eccCommSpec->h;
            if (ConstructSm2256PubKeyBigInt(keyPair, eccPubKeySpec) != HCF_SUCCESS) {
                HcfFree(eccPubKeySpec);
            } else {
                *spec = reinterpret_cast<HcfAsyKeyParamsSpec *>(eccPubKeySpec);
                res = HCF_SUCCESS;
            }
        }

        HcfObjDestroy(generator);
        HcfObjDestroy(keyPair);
        return res;
    }

    HcfResult ConstructSm2256PriKeyParamsSpec(const std::string &algoName, HcfEccCommParamsSpec *eccCommSpec,
        HcfAsyKeyParamsSpec **spec)
    {
        HcfResult res = HCF_ERR_CRYPTO_OPERATION;
        HcfAsyKeyGenerator *generator = nullptr;
        if (HcfAsyKeyGeneratorCreate(algoName.c_str(), &generator) != HCF_SUCCESS) {
            return res;
        }

        HcfKeyPair *keyPair = nullptr;
        if (generator->generateKeyPair(generator, nullptr, &keyPair) != HCF_SUCCESS) {
            HcfObjDestroy(generator);
            return res;
        }

        auto eccPriKeySpec = reinterpret_cast<HcfEccPriKeyParamsSpec *>(HcfMalloc(sizeof(HcfEccPriKeyParamsSpec), 0));
        if (eccPriKeySpec != nullptr) {
            eccPriKeySpec->base.base.algName = eccCommSpec->base.algName;
            eccPriKeySpec->base.base.specType = HCF_PRIVATE_KEY_SPEC;
            eccPriKeySpec->base.field = eccCommSpec->field;
            eccPriKeySpec->base.field->fieldType = eccCommSpec->field->fieldType;
            (reinterpret_cast<HcfECFieldFp *>(eccPriKeySpec->base.field))->p.data =
                (reinterpret_cast<HcfECFieldFp *>(eccCommSpec->field))->p.data;
            (reinterpret_cast<HcfECFieldFp *>(eccPriKeySpec->base.field))->p.len =
                (reinterpret_cast<HcfECFieldFp *>(eccCommSpec->field))->p.len;
            eccPriKeySpec->base.a.data = eccCommSpec->a.data;
            eccPriKeySpec->base.a.len = eccCommSpec->a.len;
            eccPriKeySpec->base.b.data = eccCommSpec->b.data;
            eccPriKeySpec->base.b.len = eccCommSpec->b.len;
            eccPriKeySpec->base.g.x.data = eccCommSpec->g.x.data;
            eccPriKeySpec->base.g.x.len = eccCommSpec->g.x.len;
            eccPriKeySpec->base.g.y.data = eccCommSpec->g.y.data;
            eccPriKeySpec->base.g.y.len = eccCommSpec->g.y.len;
            eccPriKeySpec->base.n.data = eccCommSpec->n.data;
            eccPriKeySpec->base.n.len = eccCommSpec->n.len;
            eccPriKeySpec->base.h = eccCommSpec->h;
            HcfBigInteger retBigInt = { .data = nullptr, .len = 0 };
            if (keyPair->priKey->getAsyKeySpecBigInteger(keyPair->priKey, ECC_SK_BN, &retBigInt) != HCF_SUCCESS) {
                HcfFree(eccPriKeySpec);
            } else {
                eccPriKeySpec->sk.data = retBigInt.data;
                eccPriKeySpec->sk.len = retBigInt.len;
                *spec = reinterpret_cast<HcfAsyKeyParamsSpec *>(eccPriKeySpec);
                res = HCF_SUCCESS;
            }
        }
        HcfObjDestroy(generator);
        HcfObjDestroy(keyPair);
        return res;
    }

    static HcfResult ConstructSm2256KeyPairBigInt(HcfKeyPair *keyPair, HcfEccKeyPairParamsSpec *eccKeyPairSpec)
    {
        HcfBigInteger retBigInt = { .data = nullptr, .len = 0 };
        HcfResult res = keyPair->pubKey->getAsyKeySpecBigInteger(keyPair->pubKey, ECC_PK_X_BN, &retBigInt);
        if (res != HCF_SUCCESS) {
            return res;
        }
        eccKeyPairSpec->pk.x.data = retBigInt.data;
        eccKeyPairSpec->pk.x.len = retBigInt.len;

        res = keyPair->pubKey->getAsyKeySpecBigInteger(keyPair->pubKey, ECC_PK_Y_BN, &retBigInt);
        if (res != HCF_SUCCESS) {
            HcfFree(eccKeyPairSpec->pk.x.data);
            eccKeyPairSpec->pk.x.data = nullptr;
            eccKeyPairSpec->pk.x.len = 0;
            return res;
        }
        eccKeyPairSpec->pk.y.data = retBigInt.data;
        eccKeyPairSpec->pk.y.len = retBigInt.len;

        res = keyPair->priKey->getAsyKeySpecBigInteger(keyPair->priKey, ECC_SK_BN, &retBigInt);
        if (res != HCF_SUCCESS) {
            HcfFree(eccKeyPairSpec->pk.x.data);
            eccKeyPairSpec->pk.x.data = nullptr;
            eccKeyPairSpec->pk.x.len = 0;
            HcfFree(eccKeyPairSpec->pk.y.data);
            eccKeyPairSpec->pk.y.data = nullptr;
            eccKeyPairSpec->pk.y.len = 0;
            return res;
        }
        eccKeyPairSpec->sk.data = retBigInt.data;
        eccKeyPairSpec->sk.len = retBigInt.len;
        return HCF_SUCCESS;
    }

    HcfResult ConstructSm2256KeyPairParamsSpec(const std::string &algoName,
        HcfEccCommParamsSpec *eccCommSpec, HcfAsyKeyParamsSpec **spec)
    {
        HcfAsyKeyGenerator *generator = nullptr;
        HcfResult res = HCF_ERR_CRYPTO_OPERATION;
        if (HcfAsyKeyGeneratorCreate(algoName.c_str(), &generator) != HCF_SUCCESS) {
            return res;
        }
        HcfKeyPair *keyPair = nullptr;
        if (generator->generateKeyPair(generator, nullptr, &keyPair) != HCF_SUCCESS) {
            HcfObjDestroy(generator);
            return res;
        }

        auto eccKeyPairSpec =
            reinterpret_cast<HcfEccKeyPairParamsSpec*>(HcfMalloc(sizeof(HcfEccKeyPairParamsSpec), 0));
        if (eccKeyPairSpec != nullptr) {
            eccKeyPairSpec->base.base.algName = eccCommSpec->base.algName;
            eccKeyPairSpec->base.base.specType = HCF_KEY_PAIR_SPEC;
            eccKeyPairSpec->base.field = eccCommSpec->field;
            eccKeyPairSpec->base.field->fieldType = eccCommSpec->field->fieldType;
            (reinterpret_cast<HcfECFieldFp *>(eccKeyPairSpec->base.field))->p.data =
                (reinterpret_cast<HcfECFieldFp *>(eccCommSpec->field))->p.data;
            (reinterpret_cast<HcfECFieldFp *>(eccKeyPairSpec->base.field))->p.len =
                (reinterpret_cast<HcfECFieldFp *>(eccCommSpec->field))->p.len;
            eccKeyPairSpec->base.a.data = eccCommSpec->a.data;
            eccKeyPairSpec->base.a.len = eccCommSpec->a.len;
            eccKeyPairSpec->base.b.data = eccCommSpec->b.data;
            eccKeyPairSpec->base.b.len = eccCommSpec->b.len;
            eccKeyPairSpec->base.g.x.data = eccCommSpec->g.x.data;
            eccKeyPairSpec->base.g.x.len = eccCommSpec->g.x.len;
            eccKeyPairSpec->base.g.y.data = eccCommSpec->g.y.data;
            eccKeyPairSpec->base.g.y.len = eccCommSpec->g.y.len;
            eccKeyPairSpec->base.n.data = eccCommSpec->n.data;
            eccKeyPairSpec->base.n.len = eccCommSpec->n.len;
            eccKeyPairSpec->base.h = eccCommSpec->h;
            if (ConstructSm2256KeyPairBigInt(keyPair, eccKeyPairSpec) != HCF_SUCCESS) {
                HcfFree(eccKeyPairSpec);
            } else {
                *spec = reinterpret_cast<HcfAsyKeyParamsSpec *>(eccKeyPairSpec);
                res = HCF_SUCCESS;
            }
        }
        HcfObjDestroy(generator);
        HcfObjDestroy(keyPair);
        return res;
    }

    static HcfResult CreateAlg25519KeyPairSpec(bool choose, HcfAlg25519KeyPairParamsSpec **alg25519KeyPairSpec)
    {
        *alg25519KeyPairSpec =
            reinterpret_cast<HcfAlg25519KeyPairParamsSpec *>(HcfMalloc(sizeof(HcfAlg25519KeyPairParamsSpec), 0));
        if (*alg25519KeyPairSpec == nullptr) {
            return HCF_ERR_MALLOC;
        }
        if (choose) {
            (*alg25519KeyPairSpec)->base.algName = static_cast<char *>(HcfMalloc(sizeof(g_ed25519AlgoName), 0));
            if ((*alg25519KeyPairSpec)->base.algName == nullptr) {
                HcfFree(*alg25519KeyPairSpec);
                *alg25519KeyPairSpec = nullptr;
                return HCF_ERR_MALLOC;
            }
            (void)memcpy_s((*alg25519KeyPairSpec)->base.algName, g_ed25519AlgoName.length(),
                g_ed25519AlgoName.data(), g_ed25519AlgoName.length());
        } else {
            (*alg25519KeyPairSpec)->base.algName = static_cast<char *>(HcfMalloc(sizeof(g_x25519AlgoName), 0));
            if ((*alg25519KeyPairSpec)->base.algName == nullptr) {
                HcfFree(*alg25519KeyPairSpec);
                *alg25519KeyPairSpec = nullptr;
                return HCF_ERR_MALLOC;
            }
            (void)memcpy_s((*alg25519KeyPairSpec)->base.algName, g_x25519AlgoName.length(),
                g_x25519AlgoName.data(), g_x25519AlgoName.length());
        }
        return HCF_SUCCESS;
    }

    static HcfResult ConstructAlg25519KeyPairParamsSpec(const string &algoName, bool choose,
        HcfAsyKeyParamsSpec **spec)
    {
        HcfResult res = HCF_ERR_CRYPTO_OPERATION;
        HcfAsyKeyGenerator *generator = nullptr;
        if (HcfAsyKeyGeneratorCreate(algoName.c_str(), &generator) != HCF_SUCCESS) {
            return res;
        }

        HcfKeyPair *keyPair = nullptr;
        if (generator->generateKeyPair(generator, nullptr, &keyPair) != HCF_SUCCESS) {
            HcfObjDestroy(generator);
            return res;
        }

        HcfAlg25519KeyPairParamsSpec *alg25519KeyPairSpec = nullptr;
        if (CreateAlg25519KeyPairSpec(choose, &alg25519KeyPairSpec) == HCF_SUCCESS) {
            HcfBigInteger retBigInt = { .data = nullptr, .len = 0 };
            alg25519KeyPairSpec->base.specType = HCF_KEY_PAIR_SPEC;
            if (choose) {
                res = keyPair->pubKey->getAsyKeySpecBigInteger(keyPair->pubKey, ED25519_PK_BN, &retBigInt);
            } else {
                res = keyPair->pubKey->getAsyKeySpecBigInteger(keyPair->pubKey, X25519_PK_BN, &retBigInt);
            }

            if (res == HCF_SUCCESS) {
                alg25519KeyPairSpec->pk.data = retBigInt.data;
                alg25519KeyPairSpec->pk.len = retBigInt.len;

                if (choose) {
                    res = keyPair->priKey->getAsyKeySpecBigInteger(keyPair->priKey, ED25519_SK_BN, &retBigInt);
                } else {
                    res = keyPair->priKey->getAsyKeySpecBigInteger(keyPair->priKey, X25519_SK_BN, &retBigInt);
                }
                if (res == HCF_SUCCESS) {
                    alg25519KeyPairSpec->sk.data = retBigInt.data;
                    alg25519KeyPairSpec->sk.len = retBigInt.len;
                    *spec = reinterpret_cast<HcfAsyKeyParamsSpec *>(alg25519KeyPairSpec);
                } else {
                    HcfFree(alg25519KeyPairSpec->pk.data);
                    alg25519KeyPairSpec->pk.data = nullptr;
                    alg25519KeyPairSpec->pk.len = 0;
                }
            }
            if (res != HCF_SUCCESS) {
                DestroyAlg25519KeyPairSpec(reinterpret_cast<HcfAlg25519KeyPairParamsSpec *>(alg25519KeyPairSpec));
            }
        }
        HcfObjDestroy(generator);
        HcfObjDestroy(keyPair);
        return res;
    }

    static HcfResult CreateAlg25519PubKeySpec(bool choose, HcfAlg25519PubKeyParamsSpec **alg25519PubKeySpec)
    {
        *alg25519PubKeySpec =
            reinterpret_cast<HcfAlg25519PubKeyParamsSpec *>(HcfMalloc(sizeof(HcfAlg25519PubKeyParamsSpec), 0));
        if (*alg25519PubKeySpec == nullptr) {
            return HCF_ERR_MALLOC;
        }
        if (choose) {
            (*alg25519PubKeySpec)->base.algName = static_cast<char *>(HcfMalloc(sizeof(g_ed25519AlgoName), 0));
            if ((*alg25519PubKeySpec)->base.algName == nullptr) {
                HcfFree(*alg25519PubKeySpec);
                *alg25519PubKeySpec = nullptr;
                return HCF_ERR_MALLOC;
            }
            (void)memcpy_s((*alg25519PubKeySpec)->base.algName, g_ed25519AlgoName.length(),
                g_ed25519AlgoName.data(), g_ed25519AlgoName.length());
        } else {
            (*alg25519PubKeySpec)->base.algName = static_cast<char *>(HcfMalloc(sizeof(g_x25519AlgoName), 0));
            if ((*alg25519PubKeySpec)->base.algName == nullptr) {
                HcfFree(*alg25519PubKeySpec);
                *alg25519PubKeySpec = nullptr;
                return HCF_ERR_MALLOC;
            }
            (void)memcpy_s((*alg25519PubKeySpec)->base.algName, g_x25519AlgoName.length(),
                g_x25519AlgoName.data(), g_x25519AlgoName.length());
        }
        return HCF_SUCCESS;
    }

    static HcfResult ConstructAlg25519PubKeyParamsSpec(const string &algoName, bool choose,
        HcfAsyKeyParamsSpec **spec)
    {
        HcfResult res = HCF_ERR_CRYPTO_OPERATION;
        HcfAsyKeyGenerator *generator = nullptr;
        if (HcfAsyKeyGeneratorCreate(algoName.c_str(), &generator) != HCF_SUCCESS) {
            return res;
        }

        HcfKeyPair *keyPair = nullptr;
        if (generator->generateKeyPair(generator, nullptr, &keyPair) != HCF_SUCCESS) {
            HcfObjDestroy(generator);
            return res;
        }

        HcfAlg25519PubKeyParamsSpec *alg25519PubKeySpec = nullptr;
        if (CreateAlg25519PubKeySpec(choose, &alg25519PubKeySpec) == HCF_SUCCESS) {
            HcfBigInteger retBigInt = { .data = nullptr, .len = 0 };
            alg25519PubKeySpec->base.specType = HCF_PUBLIC_KEY_SPEC;
            if (choose) {
                res = keyPair->pubKey->getAsyKeySpecBigInteger(keyPair->pubKey, ED25519_PK_BN, &retBigInt);
            } else {
                res = keyPair->pubKey->getAsyKeySpecBigInteger(keyPair->pubKey, X25519_PK_BN, &retBigInt);
            }
            if (res == HCF_SUCCESS) {
                alg25519PubKeySpec->pk.data = retBigInt.data;
                alg25519PubKeySpec->pk.len = retBigInt.len;
                *spec = reinterpret_cast<HcfAsyKeyParamsSpec *>(alg25519PubKeySpec);
            } else {
                DestroyAlg25519PubKeySpec(reinterpret_cast<HcfAlg25519PubKeyParamsSpec *>(alg25519PubKeySpec));
            }
        }

        HcfObjDestroy(generator);
        HcfObjDestroy(keyPair);
        return res;
    }

    static HcfResult CreateAlg25519PriKeySpec(bool choose, HcfAlg25519PriKeyParamsSpec **alg25519PriKeySpec)
    {
        *alg25519PriKeySpec =
            reinterpret_cast<HcfAlg25519PriKeyParamsSpec *>(HcfMalloc(sizeof(HcfAlg25519PriKeyParamsSpec), 0));
        if (*alg25519PriKeySpec == nullptr) {
            return HCF_ERR_MALLOC;
        }
        if (choose) {
            (*alg25519PriKeySpec)->base.algName = static_cast<char *>(HcfMalloc(sizeof(g_ed25519AlgoName), 0));
            if ((*alg25519PriKeySpec)->base.algName == nullptr) {
                HcfFree(*alg25519PriKeySpec);
                *alg25519PriKeySpec = nullptr;
                return HCF_ERR_MALLOC;
            }
            (void)memcpy_s((*alg25519PriKeySpec)->base.algName, g_ed25519AlgoName.length(),
                g_ed25519AlgoName.data(), g_ed25519AlgoName.length());
        } else {
            (*alg25519PriKeySpec)->base.algName = static_cast<char *>(HcfMalloc(sizeof(g_x25519AlgoName), 0));
            if ((*alg25519PriKeySpec)->base.algName == nullptr) {
                HcfFree(*alg25519PriKeySpec);
                *alg25519PriKeySpec = nullptr;
                return HCF_ERR_MALLOC;
            }
            (void)memcpy_s((*alg25519PriKeySpec)->base.algName, g_x25519AlgoName.length(),
                g_x25519AlgoName.data(), g_x25519AlgoName.length());
        }
        return HCF_SUCCESS;
    }

    static HcfResult ConstructAlg25519PriKeyParamsSpec(const string &algoName, bool choose,
        HcfAsyKeyParamsSpec **spec)
    {
        HcfResult res = HCF_ERR_CRYPTO_OPERATION;
        HcfAsyKeyGenerator *generator = nullptr;
        if (HcfAsyKeyGeneratorCreate(algoName.c_str(), &generator) != HCF_SUCCESS) {
            return res;
        }

        HcfKeyPair *keyPair = nullptr;
        if (generator->generateKeyPair(generator, nullptr, &keyPair) != HCF_SUCCESS) {
            HcfObjDestroy(generator);
            return res;
        }
        HcfAlg25519PriKeyParamsSpec *alg25519PriKeySpec = nullptr;
        if (CreateAlg25519PriKeySpec(choose, &alg25519PriKeySpec) == HCF_SUCCESS) {
            HcfBigInteger retBigInt = { .data = nullptr, .len = 0 };
            alg25519PriKeySpec->base.specType = HCF_PRIVATE_KEY_SPEC;
            if (choose) {
                res = keyPair->priKey->getAsyKeySpecBigInteger(keyPair->priKey, ED25519_SK_BN, &retBigInt);
            } else {
                res = keyPair->priKey->getAsyKeySpecBigInteger(keyPair->priKey, X25519_SK_BN, &retBigInt);
            }
            if (res == HCF_SUCCESS) {
                alg25519PriKeySpec->sk.data = retBigInt.data;
                alg25519PriKeySpec->sk.len = retBigInt.len;
                *spec = reinterpret_cast<HcfAsyKeyParamsSpec *>(alg25519PriKeySpec);
            } else {
                DestroyAlg25519PriKeySpec(reinterpret_cast<HcfAlg25519PriKeyParamsSpec *>(alg25519PriKeySpec));
            }
        }
        HcfObjDestroy(generator);
        HcfObjDestroy(keyPair);
        return res;
    }

    static HcfResult ConstructDhCommParamsSpec(int32_t pLen, int32_t skLen, HcfDhCommParamsSpec **spec)
    {
        HcfDhCommParamsSpec *dhCommSpec = nullptr;

        HcfDhKeyUtilCreate(pLen, skLen, &dhCommSpec);
        if (dhCommSpec == nullptr) {
            return HCF_INVALID_PARAMS;
        }
        *spec = dhCommSpec;
        return HCF_SUCCESS;
    }

    static HcfResult ConstructDhPubKeyParamsSpec(const std::string &algoName,
        HcfDhCommParamsSpec *dhCommParamsSpec, HcfAsyKeyParamsSpec **spec)
    {
        HcfAsyKeyGenerator *generator = nullptr;
        HcfResult res = HcfAsyKeyGeneratorCreate(algoName.c_str(), &generator);
        if (res != HCF_SUCCESS) {
            return res;
        }

        HcfKeyPair *keyPair = nullptr;
        res = generator->generateKeyPair(generator, nullptr, &keyPair);
        if (res != HCF_SUCCESS) {
            HcfObjDestroy(generator);
            return res;
        }

        HcfDhPubKeyParamsSpec *dhPubKeySpec =
            reinterpret_cast<HcfDhPubKeyParamsSpec *>(HcfMalloc(sizeof(HcfDhPubKeyParamsSpec), 0));
        if (dhPubKeySpec == nullptr) {
            HcfObjDestroy(generator);
            HcfObjDestroy(keyPair);
            return HCF_ERR_MALLOC;
        }
        dhPubKeySpec->base.base.algName = dhCommParamsSpec->base.algName;
        dhPubKeySpec->base.base.specType = HCF_PUBLIC_KEY_SPEC;
        dhPubKeySpec->base.p.data = dhCommParamsSpec->p.data;
        dhPubKeySpec->base.p.len = dhCommParamsSpec->p.len;
        dhPubKeySpec->base.g.data = dhCommParamsSpec->g.data;
        dhPubKeySpec->base.g.len = dhCommParamsSpec->g.len;
        dhPubKeySpec->base.length = dhCommParamsSpec->length;
        HcfBigInteger retBigInt = { .data = nullptr, .len = 0 };
        res = keyPair->pubKey->getAsyKeySpecBigInteger(keyPair->pubKey, DH_PK_BN, &retBigInt);
        if (res != HCF_SUCCESS) {
            HcfObjDestroy(generator);
            HcfObjDestroy(keyPair);
            HcfFree(dhPubKeySpec);
            return res;
        }
        dhPubKeySpec->pk.data = retBigInt.data;
        dhPubKeySpec->pk.len = retBigInt.len;

        *spec = reinterpret_cast<HcfAsyKeyParamsSpec *>(dhPubKeySpec);
        HcfObjDestroy(generator);
        HcfObjDestroy(keyPair);
        return HCF_SUCCESS;
    }

    static HcfResult ConstructDhPriKeyParamsSpec(const std::string &algoName,
        HcfDhCommParamsSpec *dhCommParamsSpec, HcfAsyKeyParamsSpec **spec)
    {
        HcfAsyKeyGenerator *generator = nullptr;
        HcfResult res = HcfAsyKeyGeneratorCreate(algoName.c_str(), &generator);
        if (res != HCF_SUCCESS) {
            return res;
        }
        HcfKeyPair *keyPair = nullptr;
        res = generator->generateKeyPair(generator, nullptr, &keyPair);
        if (res != HCF_SUCCESS) {
            HcfObjDestroy(generator);
            return res;
        }

        HcfDhPriKeyParamsSpec *dhPriKeySpec =
            reinterpret_cast<HcfDhPriKeyParamsSpec *>(HcfMalloc(sizeof(HcfDhPriKeyParamsSpec), 0));
        if (dhPriKeySpec == nullptr) {
            HcfObjDestroy(generator);
            HcfObjDestroy(keyPair);
            return HCF_ERR_MALLOC;
        }
        dhPriKeySpec->base.base.algName = dhCommParamsSpec->base.algName;
        dhPriKeySpec->base.base.specType = HCF_PRIVATE_KEY_SPEC;
        dhPriKeySpec->base.p.data = dhCommParamsSpec->p.data;
        dhPriKeySpec->base.p.len = dhCommParamsSpec->p.len;
        dhPriKeySpec->base.g.data = dhCommParamsSpec->g.data;
        dhPriKeySpec->base.g.len = dhCommParamsSpec->g.len;
        dhPriKeySpec->base.length = dhCommParamsSpec->length;
        HcfBigInteger retBigInt = { .data = nullptr, .len = 0 };
        res = keyPair->priKey->getAsyKeySpecBigInteger(keyPair->priKey, DH_SK_BN, &retBigInt);
        if (res != HCF_SUCCESS) {
            HcfObjDestroy(generator);
            HcfObjDestroy(keyPair);
            HcfFree(dhPriKeySpec);
            return res;
        }
        dhPriKeySpec->sk.data = retBigInt.data;
        dhPriKeySpec->sk.len = retBigInt.len;

        *spec = reinterpret_cast<HcfAsyKeyParamsSpec *>(dhPriKeySpec);
        HcfObjDestroy(generator);
        HcfObjDestroy(keyPair);
        return HCF_SUCCESS;
    }

    static HcfResult ConstructDhKeyPairBigInt(HcfKeyPair *keyPair, HcfDhKeyPairParamsSpec *dhKeyPairSpec)
    {
        HcfBigInteger retBigInt = { .data = nullptr, .len = 0 };
        HcfResult res = keyPair->pubKey->getAsyKeySpecBigInteger(keyPair->pubKey, DH_PK_BN, &retBigInt);
        if (res != HCF_SUCCESS) {
            return res;
        }
        dhKeyPairSpec->pk.data = retBigInt.data;
        dhKeyPairSpec->pk.len = retBigInt.len;

        res = keyPair->priKey->getAsyKeySpecBigInteger(keyPair->priKey, DH_SK_BN, &retBigInt);
        if (res != HCF_SUCCESS) {
            HcfFree(dhKeyPairSpec->pk.data);
            dhKeyPairSpec->pk.data = nullptr;
            dhKeyPairSpec->pk.len = 0;
            return res;
        }
        dhKeyPairSpec->sk.data = retBigInt.data;
        dhKeyPairSpec->sk.len = retBigInt.len;
        return HCF_SUCCESS;
    }

    static HcfResult ConstructDhKeyPairParamsSpec(const std::string &algoName,
        HcfDhCommParamsSpec *dhCommParamsSpec, HcfAsyKeyParamsSpec **spec)
    {
        HcfAsyKeyGenerator *generator = nullptr;
        HcfResult res = HcfAsyKeyGeneratorCreate(algoName.c_str(), &generator);
        if (res != HCF_SUCCESS) {
            return res;
        }

        HcfKeyPair *keyPair = nullptr;
        res = generator->generateKeyPair(generator, nullptr, &keyPair);
        if (res != HCF_SUCCESS) {
            HcfObjDestroy(generator);
            return res;
        }

        HcfDhKeyPairParamsSpec *dhKeyPairSpec =
            reinterpret_cast<HcfDhKeyPairParamsSpec*>(HcfMalloc(sizeof(HcfDhKeyPairParamsSpec), 0));
        if (dhKeyPairSpec != nullptr) {
            dhKeyPairSpec->base.base.algName = dhCommParamsSpec->base.algName;
            dhKeyPairSpec->base.base.specType = HCF_KEY_PAIR_SPEC;
            dhKeyPairSpec->base.p.data = dhCommParamsSpec->p.data;
            dhKeyPairSpec->base.p.len = dhCommParamsSpec->p.len;
            dhKeyPairSpec->base.g.data = dhCommParamsSpec->g.data;
            dhKeyPairSpec->base.g.len = dhCommParamsSpec->g.len;
            dhKeyPairSpec->base.length = dhCommParamsSpec->length;
            res = ConstructDhKeyPairBigInt(keyPair, dhKeyPairSpec);
            if (res != HCF_SUCCESS) {
                HcfObjDestroy(generator);
                HcfObjDestroy(keyPair);
                HcfFree(dhKeyPairSpec);
                return res;
            }
            *spec = reinterpret_cast<HcfAsyKeyParamsSpec *>(dhKeyPairSpec);
        }

        HcfObjDestroy(generator);
        HcfObjDestroy(keyPair);
        return HCF_SUCCESS;
    }

    static void TestEccKey(void)
    {
        HcfAsyKeyGenerator *generator = nullptr;
        HcfResult res = HcfAsyKeyGeneratorCreate("ECC224", &generator);
        if (res != HCF_SUCCESS) {
            return;
        }
        (void)generator->getAlgoName(generator);
        HcfKeyPair *keyPair = nullptr;
        res = generator->generateKeyPair(generator, nullptr, &keyPair);
        if (res != HCF_SUCCESS) {
            HcfObjDestroy(generator);
            return;
        }
        HcfKeyPair *convertKeyPair = nullptr;
        static HcfBlob mockEcc224PubKeyBlob = {
            .data = g_mockEcc224PubKey,
            .len = ECC224_PUB_KEY_LEN
        };

        static HcfBlob mockEcc224PriKeyBlob = {
            .data = g_mockEcc224PriKey,
            .len = ECC224_PRI_KEY_LEN
        };
        (void)generator->convertKey(generator, nullptr, &mockEcc224PubKeyBlob, &mockEcc224PriKeyBlob, &convertKeyPair);
        HcfObjDestroy(keyPair);
        HcfObjDestroy(generator);
        HcfObjDestroy(convertKeyPair);
    }

    static void TestRsaKey(void)
    {
        HcfAsyKeyGenerator *generator = nullptr;
        HcfResult res = HcfAsyKeyGeneratorCreate("RSA1024", &generator);
        if (res != HCF_SUCCESS) {
            return;
        }
        HcfKeyPair *keyPair = nullptr;
        res = generator->generateKeyPair(generator, nullptr, &keyPair);
        if (res != HCF_SUCCESS) {
            HcfObjDestroy(generator);
            return;
        }
        HcfBlob pubKeyBlob = {.data = nullptr, .len = 0};
        HcfBlob priKeyBlob = {.data = nullptr, .len = 0};
        (void)keyPair->pubKey->base.getEncoded(&(keyPair->pubKey->base), &pubKeyBlob);
        (void)keyPair->priKey->base.getEncoded(&(keyPair->priKey->base), &priKeyBlob);

        HcfKeyPair *dupKeyPair = nullptr;
        (void)generator->convertKey(generator, nullptr, &pubKeyBlob, &priKeyBlob, &dupKeyPair);
        HcfPubKey *pubKey = dupKeyPair->pubKey;
        (void)pubKey->base.getAlgorithm(&(pubKey->base));
        (void)pubKey->base.getFormat(&(pubKey->base));
        (void)pubKey->base.base.getClass();

        HcfBlobDataFree(&pubKeyBlob);
        HcfBlobDataFree(&priKeyBlob);
        HcfObjDestroy(generator);
        HcfObjDestroy(keyPair);
        HcfObjDestroy(dupKeyPair);
    }

    static void TestDsaKey(void)
    {
        HcfAsyKeyGenerator *generator = nullptr;
        HcfResult res = HcfAsyKeyGeneratorCreate("DSA2048", &generator);
        if (res != HCF_SUCCESS) {
            return;
        }
        HcfKeyPair *keyPair = nullptr;
        res = generator->generateKeyPair(generator, nullptr, &keyPair);
        if (res != HCF_SUCCESS) {
            HcfObjDestroy(generator);
            return;
        }
        HcfBlob pubKeyBlob = {.data = nullptr, .len = 0};
        HcfBlob priKeyBlob = {.data = nullptr, .len = 0};
        (void)keyPair->pubKey->base.getEncoded(&(keyPair->pubKey->base), &pubKeyBlob);
        (void)keyPair->priKey->base.getEncoded(&(keyPair->priKey->base), &priKeyBlob);

        HcfKeyPair *dupKeyPair = nullptr;
        (void)generator->convertKey(generator, nullptr, &pubKeyBlob, &priKeyBlob, &dupKeyPair);
        HcfPubKey *pubKey = dupKeyPair->pubKey;
        (void)pubKey->base.getAlgorithm(&(pubKey->base));
        (void)pubKey->base.getFormat(&(pubKey->base));
        (void)pubKey->base.base.getClass();

        HcfBlobDataFree(&pubKeyBlob);
        HcfBlobDataFree(&priKeyBlob);
        HcfObjDestroy(generator);
        HcfObjDestroy(keyPair);
        HcfObjDestroy(dupKeyPair);
    }

    static void TestSm2Key(void)
    {
        HcfAsyKeyGenerator *generator = nullptr;
        HcfResult res = HcfAsyKeyGeneratorCreate("SM2_256", &generator);
        if (res != HCF_SUCCESS) {
            return;
        }
        (void)generator->getAlgoName(generator);
        HcfKeyPair *keyPair = nullptr;
        res = generator->generateKeyPair(generator, nullptr, &keyPair);
        if (res != HCF_SUCCESS) {
            HcfObjDestroy(generator);
            return;
        }
        HcfKeyPair *convertKeyPair = nullptr;
        static HcfBlob mockEcc224PubKeyBlob = {
            .data = g_mockSm2256PubKey,
            .len = SM2256_PUB_KEY_LEN
        };

        static HcfBlob mockEcc224PriKeyBlob = {
            .data = g_mockSm2256PriKey,
            .len = SM2256_PRI_KEY_LEN
        };
        (void)generator->convertKey(generator, nullptr, &mockEcc224PubKeyBlob, &mockEcc224PriKeyBlob, &convertKeyPair);
        HcfObjDestroy(keyPair);
        HcfObjDestroy(generator);
        HcfObjDestroy(convertKeyPair);
    }

    static void TestBrainpoolKey(void)
    {
        HcfAsyKeyGenerator *generator = nullptr;
        HcfResult res = HcfAsyKeyGeneratorCreate("ECC_BrainPoolP160r1", &generator);
        if (res != HCF_SUCCESS) {
            return;
        }
        (void)generator->getAlgoName(generator);
        HcfKeyPair *keyPair = nullptr;
        res = generator->generateKeyPair(generator, nullptr, &keyPair);
        if (res != HCF_SUCCESS) {
            HcfObjDestroy(generator);
            return;
        }
        HcfKeyPair *convertKeyPair = nullptr;
        static HcfBlob mockBrainpoolPubKeyBlob = {
            .data = g_mockBrainpoolPubKey,
            .len = BRAINPOOLP160R1_PUB_KEY_LEN
        };

        static HcfBlob mockBrainpoolPriKeyBlob = {
            .data = g_mockBrainpoolPriKey,
            .len = BRAINPOOLP160R1_PRI_KEY_LEN
        };
        (void)generator->convertKey(generator, nullptr, &mockBrainpoolPubKeyBlob, &mockBrainpoolPriKeyBlob,
            &convertKeyPair);
        HcfObjDestroy(keyPair);
        HcfObjDestroy(generator);
        HcfObjDestroy(convertKeyPair);
    }

    static void TestEd25519Key(void)
    {
        HcfAsyKeyGenerator *generator = nullptr;
        HcfResult res = HcfAsyKeyGeneratorCreate("Ed25519", &generator);
        if (res != HCF_SUCCESS) {
            return;
        }
        (void)generator->getAlgoName(generator);
        HcfKeyPair *keyPair = nullptr;
        res = generator->generateKeyPair(generator, nullptr, &keyPair);
        if (res != HCF_SUCCESS) {
            HcfObjDestroy(generator);
            return;
        }
        HcfKeyPair *convertKeyPair = nullptr;
        static HcfBlob mockEd25519PubKeyBlob = {
            .data = g_mockEd25519PubKey,
            .len = ED25519_PUB_KEY_LEN
        };

        static HcfBlob mockEd25519PriKeyBlob = {
            .data = g_mockEd25519PriKey,
            .len = ED25519_PRI_KEY_LEN
        };
        (void)generator->convertKey(generator, nullptr, &mockEd25519PubKeyBlob, &mockEd25519PriKeyBlob,
            &convertKeyPair);
        HcfObjDestroy(keyPair);
        HcfObjDestroy(generator);
        HcfObjDestroy(convertKeyPair);
    }

    static void TestX25519Key(void)
    {
        HcfAsyKeyGenerator *generator = nullptr;
        HcfResult res = HcfAsyKeyGeneratorCreate("X25519", &generator);
        if (res != HCF_SUCCESS) {
            return;
        }
        (void)generator->getAlgoName(generator);
        HcfKeyPair *keyPair = nullptr;
        res = generator->generateKeyPair(generator, nullptr, &keyPair);
        if (res != HCF_SUCCESS) {
            HcfObjDestroy(generator);
            return;
        }
        HcfKeyPair *convertKeyPair = nullptr;
        static HcfBlob mockX25519PubKeyBlob = {
            .data = g_mockX25519PubKey,
            .len = X25519_PUB_KEY_LEN
        };

        static HcfBlob mockX25519PriKeyBlob = {
            .data = g_mockX25519PriKey,
            .len = X25519_PRI_KEY_LEN
        };
        (void)generator->convertKey(generator, nullptr, &mockX25519PubKeyBlob, &mockX25519PriKeyBlob,
            &convertKeyPair);
        HcfObjDestroy(keyPair);
        HcfObjDestroy(generator);
        HcfObjDestroy(convertKeyPair);
    }

    static void TestDhKey(void)
    {
        HcfAsyKeyGenerator *generator = nullptr;
        HcfResult res = HcfAsyKeyGeneratorCreate("DH_modp2048", &generator);
        if (res != HCF_SUCCESS) {
            return;
        }
        (void)generator->getAlgoName(generator);
        HcfKeyPair *keyPair = nullptr;
        res = generator->generateKeyPair(generator, nullptr, &keyPair);
        if (res != HCF_SUCCESS) {
            HcfObjDestroy(generator);
            return;
        }
        HcfKeyPair *convertKeyPair = nullptr;
        static HcfBlob mockDhPubKeyBlob = {
            .data = g_mockDhPubKey,
            .len = DH_PUB_KEY_LEN
        };

        static HcfBlob mockX25519PriKeyBlob = {
            .data = g_mockDhPriKey,
            .len = DH_PRI_KEY_LEN
        };
        (void)generator->convertKey(generator, nullptr, &mockDhPubKeyBlob, &mockX25519PriKeyBlob,
            &convertKeyPair);
        HcfObjDestroy(keyPair);
        HcfObjDestroy(generator);
        HcfObjDestroy(convertKeyPair);
    }

    static void GenEccKeyBySpec(GenerateType type)
    {
        HcfAsyKeyParamsSpec *paramSpec = nullptr;
        HcfAsyKeyGeneratorBySpec *generator = nullptr;
        HcfKeyPair *keyPair = nullptr;
        HcfPriKey *priKey = nullptr;
        HcfPubKey *pubKey = nullptr;
        HcfResult res = HCF_SUCCESS;
        switch (type) {
            case GenerateType::FUZZ_COMMON:
                res = ConstructEcc224CommParamsSpec(&paramSpec);
                break;
            case GenerateType::FUZZ_PRIKEY:
                res = ConstructEcc224PriKeyParamsSpec(&paramSpec);
                break;
            case GenerateType::FUZZ_PUBKEY:
                res = ConstructEcc224PubKeyParamsSpec(&paramSpec);
                break;
            case GenerateType::FUZZ_KEYPAIR:
                res = ConstructEcc224KeyPairParamsSpec(&paramSpec);
                break;
            default:
                return;
        }
        if (res != HCF_SUCCESS) {
            return;
        }
        res = HcfAsyKeyGeneratorBySpecCreate(paramSpec, &generator);
        if (res != HCF_SUCCESS) {
            return;
        }
        (void)generator->generateKeyPair(generator, &keyPair);
        (void)generator->generatePriKey(generator, &priKey);
        (void)generator->generatePubKey(generator, &pubKey);
        HcfObjDestroy(generator);
        HcfObjDestroy(keyPair);
        HcfObjDestroy(priKey);
        HcfObjDestroy(pubKey);
    }

    static void TestEccKeyBySpec(void)
    {
        GenEccKeyBySpec(GenerateType::FUZZ_COMMON);
        GenEccKeyBySpec(GenerateType::FUZZ_PRIKEY);
        GenEccKeyBySpec(GenerateType::FUZZ_PUBKEY);
        GenEccKeyBySpec(GenerateType::FUZZ_KEYPAIR);
    }

    static void GenRsaKeyBySpec(GenerateType type)
    {
        HcfRsaKeyPairParamsSpec rsaPairSpec = {};
        HcfRsaPubKeyParamsSpec rsaPubKeySpec = {};
        HcfRsaCommParamsSpec rsaCommSpec = {};
        unsigned char dataN[RSA_2048_N_BYTE_SIZE] = {0};
        unsigned char dataE[RSA_2048_E_BYTE_SIZE] = {0};
        unsigned char dataD[RSA_2048_D_BYTE_SIZE] = {0};
        HcfAsyKeyGeneratorBySpec *generator = nullptr;
        HcfKeyPair *keyPair = nullptr;
        HcfPriKey *priKey = nullptr;
        HcfPubKey *pubKey = nullptr;
        HcfResult res = HCF_SUCCESS;
        switch (type) {
            case GenerateType::FUZZ_COMMON:
                GenerateRsa2048CorrectCommonKeySpec(dataN, &rsaCommSpec);
                res = HcfAsyKeyGeneratorBySpecCreate(reinterpret_cast<HcfAsyKeyParamsSpec *>(&rsaCommSpec),
                    &generator);
                break;
            case GenerateType::FUZZ_PUBKEY:
                GenerateRsa2048CorrectPubKeySpec(dataN, dataE, &rsaPubKeySpec);
                res = HcfAsyKeyGeneratorBySpecCreate(reinterpret_cast<HcfAsyKeyParamsSpec *>(&rsaPubKeySpec),
                    &generator);
                break;
            case GenerateType::FUZZ_KEYPAIR:
                GenerateRsa2048CorrectKeyPairSpec(dataN, dataE, dataD, &rsaPairSpec);
                res = HcfAsyKeyGeneratorBySpecCreate(reinterpret_cast<HcfAsyKeyParamsSpec *>(&rsaPairSpec),
                    &generator);
                break;
            default:
                return;
        }
        if (res != HCF_SUCCESS) {
            return;
        }
        (void)generator->generateKeyPair(generator, &keyPair);
        (void)generator->generatePriKey(generator, &priKey);
        (void)generator->generatePubKey(generator, &pubKey);
        HcfObjDestroy(generator);
        HcfObjDestroy(keyPair);
        HcfObjDestroy(priKey);
        HcfObjDestroy(pubKey);
    }

    static void TestRsaKeyBySpec(void)
    {
        GenRsaKeyBySpec(GenerateType::FUZZ_COMMON);
        GenRsaKeyBySpec(GenerateType::FUZZ_PUBKEY);
        GenRsaKeyBySpec(GenerateType::FUZZ_KEYPAIR);
    }

    static void GenDsaKeyBySpec(GenerateType type)
    {
        HcfAsyKeyGeneratorBySpec *generator = nullptr;
        HcfKeyPair *keyPair = nullptr;
        HcfPriKey *priKey = nullptr;
        HcfPubKey *pubKey = nullptr;
        HcfResult res = HCF_SUCCESS;
        switch (type) {
            case GenerateType::FUZZ_COMMON:
                res = HcfAsyKeyGeneratorBySpecCreate(reinterpret_cast<HcfAsyKeyParamsSpec *>(&dsaCommonSpec),
                    &generator);
                break;
            case GenerateType::FUZZ_PUBKEY:
                res = HcfAsyKeyGeneratorBySpecCreate(reinterpret_cast<HcfAsyKeyParamsSpec *>(&dsaPkSpec),
                    &generator);
                break;
            case GenerateType::FUZZ_KEYPAIR:
                res = HcfAsyKeyGeneratorBySpecCreate(reinterpret_cast<HcfAsyKeyParamsSpec *>(&dsaKeyPairSpec),
                    &generator);
                break;
            default:
                return;
        }
        if (res != HCF_SUCCESS) {
            return;
        }
        (void)generator->generateKeyPair(generator, &keyPair);
        (void)generator->generatePriKey(generator, &priKey);
        (void)generator->generatePubKey(generator, &pubKey);
        HcfObjDestroy(generator);
        HcfObjDestroy(keyPair);
        HcfObjDestroy(priKey);
        HcfObjDestroy(pubKey);
    }

    static void TestDsaKeyBySpec(void)
    {
        GenDsaKeyBySpec(GenerateType::FUZZ_COMMON);
        GenDsaKeyBySpec(GenerateType::FUZZ_PUBKEY);
        GenDsaKeyBySpec(GenerateType::FUZZ_KEYPAIR);
    }

    static void GenSm2KeyBySpec(GenerateType type, const std::string &algoName,
        HcfEccCommParamsSpec *eccCommParamsSpec)
    {
        HcfAsyKeyParamsSpec *paramSpec = nullptr;
        HcfAsyKeyGeneratorBySpec *generator = nullptr;
        HcfKeyPair *keyPair = nullptr;
        HcfPriKey *priKey = nullptr;
        HcfPubKey *pubKey = nullptr;
        HcfResult res = HCF_SUCCESS;
        switch (type) {
            case GenerateType::FUZZ_PRIKEY:
                res = ConstructSm2256PriKeyParamsSpec(algoName, eccCommParamsSpec, &paramSpec);
                break;
            case GenerateType::FUZZ_PUBKEY:
                res = ConstructSm2256PubKeyParamsSpec(algoName, eccCommParamsSpec, &paramSpec);
                break;
            case GenerateType::FUZZ_KEYPAIR:
                res = ConstructSm2256KeyPairParamsSpec(algoName, eccCommParamsSpec, &paramSpec);
                break;
            default:
                break;
        }
        if ((res != HCF_SUCCESS) || (HcfAsyKeyGeneratorBySpecCreate(paramSpec, &generator) != HCF_SUCCESS)) {
            FreeEccCommParamsSpec(eccCommParamsSpec);
            return;
        }
        (void)generator->generateKeyPair(generator, &keyPair);
        (void)generator->generatePriKey(generator, &priKey);
        (void)generator->generatePubKey(generator, &pubKey);
        switch (type) {
            case GenerateType::FUZZ_PRIKEY:
                DestroyEccPriKeySpec(reinterpret_cast<HcfEccPriKeyParamsSpec *>(paramSpec));
                break;
            case GenerateType::FUZZ_PUBKEY:
                DestroyEccPubKeySpec(reinterpret_cast<HcfEccPubKeyParamsSpec *>(paramSpec));
                break;
            case GenerateType::FUZZ_KEYPAIR:
                DestroyEccKeyPairSpec(reinterpret_cast<HcfEccKeyPairParamsSpec *>(paramSpec));
                break;
            default:
                break;
        }
        HcfObjDestroy(pubKey);
        HcfObjDestroy(priKey);
        HcfObjDestroy(keyPair);
        HcfObjDestroy(generator);
    }

    static void GenSm2KeyCommonBySpec(HcfEccCommParamsSpec *eccCommSpec)
    {
        HcfAsyKeyGeneratorBySpec *generator = nullptr;
        HcfKeyPair *keyPair = nullptr;
        HcfPriKey *priKey = nullptr;
        HcfPubKey *pubKey = nullptr;
        HcfResult res = HCF_SUCCESS;
        res = HcfAsyKeyGeneratorBySpecCreate(reinterpret_cast<HcfAsyKeyParamsSpec *>(eccCommSpec), &generator);
        if (res != HCF_SUCCESS) {
            return;
        }
        (void)generator->generateKeyPair(generator, &keyPair);
        (void)generator->generatePriKey(generator, &priKey);
        (void)generator->generatePubKey(generator, &pubKey);
        HcfObjDestroy(generator);
        HcfObjDestroy(keyPair);
        HcfObjDestroy(priKey);
        HcfObjDestroy(pubKey);
    }

    static void TestSm2KeyBySpec(void)
    {
        if (ConstructSm2256CommParamsSpec("NID_sm2", &g_sm2256CommSpec) != HCF_SUCCESS) {
            return;
        }
        GenSm2KeyCommonBySpec(g_sm2256CommSpec);
        GenSm2KeyBySpec(GenerateType::FUZZ_PRIKEY, "SM2_256", g_sm2256CommSpec);
        if (ConstructSm2256CommParamsSpec("NID_sm2", &g_sm2256CommSpec) != HCF_SUCCESS) {
            return;
        }
        GenSm2KeyBySpec(GenerateType::FUZZ_PUBKEY, "SM2_256", g_sm2256CommSpec);
        if (ConstructSm2256CommParamsSpec("NID_sm2", &g_sm2256CommSpec) != HCF_SUCCESS) {
            return;
        }
        GenSm2KeyBySpec(GenerateType::FUZZ_KEYPAIR, "SM2_256", g_sm2256CommSpec);
    }

    static void TestBrainpoolKeyBySpec(void)
    {
        if (ConstructSm2256CommParamsSpec("NID_brainpoolP160r1", &g_brainpoolP160r1CommSpec) != HCF_SUCCESS) {
            return;
        }
        GenSm2KeyCommonBySpec(g_brainpoolP160r1CommSpec);
        GenSm2KeyBySpec(GenerateType::FUZZ_PRIKEY, "ECC_BrainPoolP160r1", g_brainpoolP160r1CommSpec);
        if (ConstructSm2256CommParamsSpec("NID_brainpoolP160r1", &g_brainpoolP160r1CommSpec) != HCF_SUCCESS) {
            return;
        }
        GenSm2KeyBySpec(GenerateType::FUZZ_PUBKEY, "ECC_BrainPoolP160r1", g_brainpoolP160r1CommSpec);
        if (ConstructSm2256CommParamsSpec("NID_brainpoolP160r1", &g_brainpoolP160r1CommSpec) != HCF_SUCCESS) {
            return;
        }
        GenSm2KeyBySpec(GenerateType::FUZZ_KEYPAIR, "ECC_BrainPoolP160r1", g_brainpoolP160r1CommSpec);
    }

    static void GenAlg25519KeyBySpec(GenerateType type, const std::string &algoName,
        bool choose)
    {
        HcfAsyKeyParamsSpec *paramSpec = nullptr;
        HcfAsyKeyGeneratorBySpec *generator = nullptr;
        HcfKeyPair *keyPair = nullptr;
        HcfPriKey *priKey = nullptr;
        HcfPubKey *pubKey = nullptr;
        HcfResult res = HCF_SUCCESS;
        switch (type) {
            case GenerateType::FUZZ_PRIKEY:
                res = ConstructAlg25519PriKeyParamsSpec(algoName, choose, &paramSpec);
                break;
            case GenerateType::FUZZ_PUBKEY:
                res = ConstructAlg25519PubKeyParamsSpec(algoName, choose, &paramSpec);
                break;
            case GenerateType::FUZZ_KEYPAIR:
                res = ConstructAlg25519KeyPairParamsSpec(algoName, choose, &paramSpec);
                break;
            default:
                break;
        }
        if (res != HCF_SUCCESS) {
            return;
        }
        res = HcfAsyKeyGeneratorBySpecCreate(paramSpec, &generator);
        if (res != HCF_SUCCESS) {
            return;
        }
        (void)generator->generateKeyPair(generator, &keyPair);
        (void)generator->generatePriKey(generator, &priKey);
        (void)generator->generatePubKey(generator, &pubKey);
        switch (type) {
            case GenerateType::FUZZ_PRIKEY:
                DestroyAlg25519PriKeySpec(reinterpret_cast<HcfAlg25519PriKeyParamsSpec *>(paramSpec));
                break;
            case GenerateType::FUZZ_PUBKEY:
                DestroyAlg25519PubKeySpec(reinterpret_cast<HcfAlg25519PubKeyParamsSpec *>(paramSpec));
                break;
            case GenerateType::FUZZ_KEYPAIR:
                DestroyAlg25519KeyPairSpec(reinterpret_cast<HcfAlg25519KeyPairParamsSpec *>(paramSpec));
                break;
            default:
                break;
        }
        HcfObjDestroy(pubKey);
        HcfObjDestroy(priKey);
        HcfObjDestroy(keyPair);
        HcfObjDestroy(generator);
    }

    static void TestEd25519KeyBySpec(void)
    {
        GenAlg25519KeyBySpec(GenerateType::FUZZ_PRIKEY, "Ed25519", true);
        GenAlg25519KeyBySpec(GenerateType::FUZZ_PUBKEY, "Ed25519", true);
        GenAlg25519KeyBySpec(GenerateType::FUZZ_KEYPAIR, "Ed25519", true);
    }

    static void TestX25519KeyBySpec(void)
    {
        GenAlg25519KeyBySpec(GenerateType::FUZZ_PRIKEY, "X25519", false);
        GenAlg25519KeyBySpec(GenerateType::FUZZ_PUBKEY, "X25519", false);
        GenAlg25519KeyBySpec(GenerateType::FUZZ_KEYPAIR, "X25519", false);
    }

    static void GenDhKeyBySpec(GenerateType type, const std::string &algoName,
        HcfDhCommParamsSpec *dhCommParamsSpec)
    {
        HcfAsyKeyParamsSpec *paramSpec = nullptr;
        HcfAsyKeyGeneratorBySpec *generator = nullptr;
        HcfKeyPair *keyPair = nullptr;
        HcfPriKey *priKey = nullptr;
        HcfPubKey *pubKey = nullptr;
        HcfResult res = HCF_SUCCESS;
        switch (type) {
            case GenerateType::FUZZ_PRIKEY:
                res = ConstructDhPriKeyParamsSpec(algoName, dhCommParamsSpec, &paramSpec);
                break;
            case GenerateType::FUZZ_PUBKEY:
                res = ConstructDhPubKeyParamsSpec(algoName, dhCommParamsSpec, &paramSpec);
                break;
            case GenerateType::FUZZ_KEYPAIR:
                res = ConstructDhKeyPairParamsSpec(algoName, dhCommParamsSpec, &paramSpec);
                break;
            default:
                break;
        }
        if ((res != HCF_SUCCESS) || (HcfAsyKeyGeneratorBySpecCreate(paramSpec, &generator) != HCF_SUCCESS)) {
            FreeDhCommParamsSpec(dhCommParamsSpec);
            return;
        }
        (void)generator->generateKeyPair(generator, &keyPair);
        (void)generator->generatePriKey(generator, &priKey);
        (void)generator->generatePubKey(generator, &pubKey);
        switch (type) {
            case GenerateType::FUZZ_PRIKEY:
                DestroyDhPriKeySpec(reinterpret_cast<HcfDhPriKeyParamsSpec *>(paramSpec));
                break;
            case GenerateType::FUZZ_PUBKEY:
                DestroyDhPubKeySpec(reinterpret_cast<HcfDhPubKeyParamsSpec *>(paramSpec));
                break;
            case GenerateType::FUZZ_KEYPAIR:
                DestroyDhKeyPairSpec(reinterpret_cast<HcfDhKeyPairParamsSpec *>(paramSpec));
                break;
            default:
                break;
        }
        HcfObjDestroy(pubKey);
        HcfObjDestroy(priKey);
        HcfObjDestroy(keyPair);
        HcfObjDestroy(generator);
    }

    static void GenDhKeyCommonBySpec(HcfDhCommParamsSpec *dhCommSpec)
    {
        HcfAsyKeyGeneratorBySpec *generator = nullptr;
        HcfKeyPair *keyPair = nullptr;
        HcfPriKey *priKey = nullptr;
        HcfPubKey *pubKey = nullptr;
        HcfResult res = HCF_SUCCESS;
        res = HcfAsyKeyGeneratorBySpecCreate(reinterpret_cast<HcfAsyKeyParamsSpec *>(dhCommSpec), &generator);
        if (res != HCF_SUCCESS) {
            return;
        }
        (void)generator->generateKeyPair(generator, &keyPair);
        (void)generator->generatePriKey(generator, &priKey);
        (void)generator->generatePubKey(generator, &pubKey);
        HcfObjDestroy(generator);
        HcfObjDestroy(keyPair);
        HcfObjDestroy(priKey);
        HcfObjDestroy(pubKey);
    }

    static void TestDhKeyBySpec(void)
    {
        if (ConstructDhCommParamsSpec(PLEN_BITS, SKLEN_BITS, &g_dhCommSpec) != HCF_SUCCESS) {
            return;
        }
        GenDhKeyCommonBySpec(g_dhCommSpec);
        GenDhKeyBySpec(GenerateType::FUZZ_PRIKEY, "DH_ffdhe3072", g_dhCommSpec);
        if (ConstructDhCommParamsSpec(PLEN_BITS, SKLEN_BITS, &g_dhCommSpec) != HCF_SUCCESS) {
            return;
        }
        GenDhKeyBySpec(GenerateType::FUZZ_PUBKEY, "DH_ffdhe3072", g_dhCommSpec);
        if (ConstructDhCommParamsSpec(PLEN_BITS, SKLEN_BITS, &g_dhCommSpec) != HCF_SUCCESS) {
            return;
        }
        GenDhKeyBySpec(GenerateType::FUZZ_KEYPAIR, "DH_ffdhe3072", g_dhCommSpec);
    }

    bool AsyKeyGeneratorFuzzTest(const uint8_t* data, size_t size)
    {
        if (g_testFlag) {
            TestEccKey();
            TestRsaKey();
            TestDsaKey();
            TestSm2Key();
            TestBrainpoolKey();
            TestEd25519Key();
            TestX25519Key();
            TestDhKey();
            TestEccKeyBySpec();
            TestRsaKeyBySpec();
            TestDsaKeyBySpec();
            TestSm2KeyBySpec();
            TestBrainpoolKeyBySpec();
            TestEd25519KeyBySpec();
            TestX25519KeyBySpec();
            TestDhKeyBySpec();
            g_testFlag = false;
        }
        HcfAsyKeyGenerator *generator = nullptr;
        FuzzedDataProvider fdp(data, size);
        std::string algoName = fdp.ConsumeRemainingBytesAsString();
        HcfResult res = HcfAsyKeyGeneratorCreate(algoName.c_str(), &generator);
        if (res != HCF_SUCCESS) {
            return false;
        }
        HcfObjDestroy(generator);
        return true;
    }
}

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    /* Run your code on data */
    OHOS::AsyKeyGeneratorFuzzTest(data, size);
    return 0;
}
