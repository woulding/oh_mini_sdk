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
#include "asy_key_generator_spi.h"
#include "blob.h"
#include "detailed_rsa_key_params.h"
#include "memory.h"
#include "openssl_adapter.h"
#include "openssl_class.h"
#include "openssl_common.h"
#include "rsa_asy_key_generator_openssl.h"

using namespace std;
using namespace testing::ext;

namespace {
class CryptoRsaAsyKeyGeneratorBySpecCovTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp();
    void TearDown();
};

void CryptoRsaAsyKeyGeneratorBySpecCovTest::SetUpTestCase() {}

void CryptoRsaAsyKeyGeneratorBySpecCovTest::TearDownTestCase() {}

void CryptoRsaAsyKeyGeneratorBySpecCovTest::SetUp() {}

void CryptoRsaAsyKeyGeneratorBySpecCovTest::TearDown() {}

namespace {
constexpr uint32_t RSA_2048_N_BYTE_SIZE = 256;
constexpr uint32_t RSA_2048_D_BYTE_SIZE = 256;
constexpr uint32_t RSA_2048_E_BYTE_SIZE = 3;
constexpr uint32_t OPENSSL_RSA_KEY_SIZE_2048 = 2048;
static const char *g_invalidAlgName = "null";

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
}

static const char *GetMockClass(void)
{
    return "Mock";
}

static HcfObjectBase obj = {
    .getClass = GetMockClass,
    .destroy = nullptr
};

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

// spec generator spi
HWTEST_F(CryptoRsaAsyKeyGeneratorBySpecCovTest, CryptoRsaAsyKeyGeneratorBySpecCovTest001, TestSize.Level0)
{
    HcfAsyKeyGeneratorSpi *spiObj = nullptr;
    HcfAsyKeyGenParams params = {
        .algo = HCF_ALG_RSA,
        .bits = OPENSSL_RSA_KEY_SIZE_2048,
        .primes = 0,
    };

    HcfResult res = HcfAsyKeyGeneratorSpiRsaCreate(&params, &spiObj);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(spiObj, nullptr);

    res = spiObj->engineGenerateKeyPairBySpec(nullptr, nullptr, nullptr);
    EXPECT_NE(res, HCF_SUCCESS);
    HcfObjDestroy(spiObj);
}

HWTEST_F(CryptoRsaAsyKeyGeneratorBySpecCovTest, CryptoRsaAsyKeyGeneratorBySpecCovTest002, TestSize.Level0)
{
    HcfAsyKeyGeneratorSpi *spiObj = nullptr;
    HcfAsyKeyGenParams params = {
        .algo = HCF_ALG_RSA,
        .bits = OPENSSL_RSA_KEY_SIZE_2048,
        .primes = 0,
    };

    HcfResult res = HcfAsyKeyGeneratorSpiRsaCreate(&params, &spiObj);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(spiObj, nullptr);

    res = spiObj->engineGenerateKeyPairBySpec(spiObj, nullptr, nullptr);
    EXPECT_NE(res, HCF_SUCCESS);
    HcfObjDestroy(spiObj);
}

HWTEST_F(CryptoRsaAsyKeyGeneratorBySpecCovTest, CryptoRsaAsyKeyGeneratorBySpecCovTest003, TestSize.Level0)
{
    HcfAsyKeyGeneratorSpi *spiObj = nullptr;
    HcfAsyKeyGenParams params = {
        .algo = HCF_ALG_RSA,
        .bits = OPENSSL_RSA_KEY_SIZE_2048,
        .primes = 0,
    };

    HcfResult res = HcfAsyKeyGeneratorSpiRsaCreate(&params, &spiObj);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(spiObj, nullptr);

    HcfKeyPair *keyPair = nullptr;
    res = spiObj->engineGenerateKeyPairBySpec(spiObj, nullptr, &keyPair);
    EXPECT_NE(res, HCF_SUCCESS);
    EXPECT_EQ(keyPair, nullptr);

    HcfObjDestroy(spiObj);
}

HWTEST_F(CryptoRsaAsyKeyGeneratorBySpecCovTest, CryptoRsaAsyKeyGeneratorBySpecCovTest004, TestSize.Level0)
{
    HcfRsaKeyPairParamsSpec rsaPairSpec = {};
    unsigned char dataN[RSA_2048_N_BYTE_SIZE] = {0};
    unsigned char dataE[RSA_2048_E_BYTE_SIZE] = {0};
    unsigned char dataD[RSA_2048_D_BYTE_SIZE] = {0};
    GenerateRsa2048CorrectKeyPairSpec(dataN, dataE, dataD, &rsaPairSpec);
    rsaPairSpec.base.base.algName = const_cast<char *>(g_invalidAlgName);

    HcfAsyKeyGeneratorSpi *spiObj = nullptr;
    HcfAsyKeyGenParams params = {
        .algo = HCF_ALG_RSA,
        .bits = OPENSSL_RSA_KEY_SIZE_2048,
        .primes = 0,
    };

    HcfResult res = HcfAsyKeyGeneratorSpiRsaCreate(&params, &spiObj);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(spiObj, nullptr);

    HcfKeyPair *keyPair = nullptr;
    res = spiObj->engineGenerateKeyPairBySpec(spiObj, reinterpret_cast<HcfAsyKeyParamsSpec *>(&rsaPairSpec), &keyPair);
    EXPECT_NE(res, HCF_SUCCESS);
    EXPECT_EQ(keyPair, nullptr);

    HcfObjDestroy(spiObj);
}

HWTEST_F(CryptoRsaAsyKeyGeneratorBySpecCovTest, CryptoRsaAsyKeyGeneratorBySpecCovTest005, TestSize.Level0)
{
    HcfRsaKeyPairParamsSpec rsaPairSpec = {};
    unsigned char dataN[RSA_2048_N_BYTE_SIZE] = {0};
    unsigned char dataE[RSA_2048_E_BYTE_SIZE] = {0};
    unsigned char dataD[RSA_2048_D_BYTE_SIZE] = {0};
    GenerateRsa2048CorrectKeyPairSpec(dataN, dataE, dataD, &rsaPairSpec);
    rsaPairSpec.base.base.specType = HCF_COMMON_PARAMS_SPEC;

    HcfAsyKeyGeneratorSpi *spiObj = nullptr;
    HcfAsyKeyGenParams params = {
        .algo = HCF_ALG_RSA,
        .bits = OPENSSL_RSA_KEY_SIZE_2048,
        .primes = 0,
    };

    HcfResult res = HcfAsyKeyGeneratorSpiRsaCreate(&params, &spiObj);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(spiObj, nullptr);

    HcfKeyPair *keyPair = nullptr;
    res = spiObj->engineGenerateKeyPairBySpec(spiObj, reinterpret_cast<HcfAsyKeyParamsSpec *>(&rsaPairSpec), &keyPair);
    EXPECT_NE(res, HCF_SUCCESS);
    EXPECT_EQ(keyPair, nullptr);
    HcfObjDestroy(spiObj);
}

HWTEST_F(CryptoRsaAsyKeyGeneratorBySpecCovTest, CryptoRsaAsyKeyGeneratorBySpecCovTest006, TestSize.Level0)
{
    HcfRsaKeyPairParamsSpec rsaPairSpec = {};
    unsigned char dataN[RSA_2048_N_BYTE_SIZE] = {0};
    unsigned char dataE[RSA_2048_E_BYTE_SIZE] = {0};
    unsigned char dataD[RSA_2048_D_BYTE_SIZE] = {0};
    GenerateRsa2048CorrectKeyPairSpec(dataN, dataE, dataD, &rsaPairSpec);
    rsaPairSpec.base.base.specType = HCF_COMMON_PARAMS_SPEC;

    HcfAsyKeyGeneratorSpi *spiObj = nullptr;
    HcfAsyKeyGenParams params = {
        .algo = HCF_ALG_RSA,
        .bits = OPENSSL_RSA_KEY_SIZE_2048,
        .primes = 0,
    };

    HcfResult res = HcfAsyKeyGeneratorSpiRsaCreate(&params, &spiObj);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(spiObj, nullptr);

    HcfKeyPair *keyPair = nullptr;
    res = spiObj->engineGenerateKeyPairBySpec(reinterpret_cast<HcfAsyKeyGeneratorSpi *>(&obj),
        reinterpret_cast<HcfAsyKeyParamsSpec *>(&rsaPairSpec), &keyPair);
    EXPECT_NE(res, HCF_SUCCESS);
    EXPECT_EQ(keyPair, nullptr);
    HcfObjDestroy(spiObj);
}

HWTEST_F(CryptoRsaAsyKeyGeneratorBySpecCovTest, CryptoRsaAsyKeyGeneratorBySpecCovTest007, TestSize.Level0)
{
    HcfAsyKeyGeneratorSpi *spiObj = nullptr;
    HcfAsyKeyGenParams params = {
        .algo = HCF_ALG_RSA,
        .bits = OPENSSL_RSA_KEY_SIZE_2048,
        .primes = 0,
    };

    HcfResult res = HcfAsyKeyGeneratorSpiRsaCreate(&params, &spiObj);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(spiObj, nullptr);

    res = spiObj->engineGeneratePriKeyBySpec(nullptr, nullptr, nullptr);
    EXPECT_NE(res, HCF_SUCCESS);
    HcfObjDestroy(spiObj);
}

HWTEST_F(CryptoRsaAsyKeyGeneratorBySpecCovTest, CryptoRsaAsyKeyGeneratorBySpecCovTest008, TestSize.Level0)
{
    HcfAsyKeyGeneratorSpi *spiObj = nullptr;
    HcfAsyKeyGenParams params = {
        .algo = HCF_ALG_RSA,
        .bits = OPENSSL_RSA_KEY_SIZE_2048,
        .primes = 0,
    };

    HcfResult res = HcfAsyKeyGeneratorSpiRsaCreate(&params, &spiObj);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(spiObj, nullptr);

    res = spiObj->engineGeneratePriKeyBySpec(spiObj, nullptr, nullptr);
    EXPECT_NE(res, HCF_SUCCESS);
    HcfObjDestroy(spiObj);
}

HWTEST_F(CryptoRsaAsyKeyGeneratorBySpecCovTest, CryptoRsaAsyKeyGeneratorBySpecCovTest009, TestSize.Level0)
{
    HcfAsyKeyGeneratorSpi *spiObj = nullptr;
    HcfAsyKeyGenParams params = {
        .algo = HCF_ALG_RSA,
        .bits = OPENSSL_RSA_KEY_SIZE_2048,
        .primes = 0,
    };

    HcfResult res = HcfAsyKeyGeneratorSpiRsaCreate(&params, &spiObj);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(spiObj, nullptr);

    HcfPriKey *priKey = nullptr;
    res = spiObj->engineGeneratePriKeyBySpec(spiObj, nullptr, &priKey);
    EXPECT_NE(res, HCF_SUCCESS);
    EXPECT_EQ(priKey, nullptr);

    HcfObjDestroy(spiObj);
}

HWTEST_F(CryptoRsaAsyKeyGeneratorBySpecCovTest, CryptoRsaAsyKeyGeneratorBySpecCovTest010, TestSize.Level0)
{
    HcfRsaKeyPairParamsSpec rsaPairSpec = {};
    unsigned char dataN[RSA_2048_N_BYTE_SIZE] = {0};
    unsigned char dataE[RSA_2048_E_BYTE_SIZE] = {0};
    unsigned char dataD[RSA_2048_D_BYTE_SIZE] = {0};
    GenerateRsa2048CorrectKeyPairSpec(dataN, dataE, dataD, &rsaPairSpec);
    rsaPairSpec.base.base.algName = const_cast<char *>(g_invalidAlgName);

    HcfAsyKeyGeneratorSpi *spiObj = nullptr;
    HcfAsyKeyGenParams params = {
        .algo = HCF_ALG_RSA,
        .bits = OPENSSL_RSA_KEY_SIZE_2048,
        .primes = 0,
    };

    HcfResult res = HcfAsyKeyGeneratorSpiRsaCreate(&params, &spiObj);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(spiObj, nullptr);

    HcfPriKey *priKey = nullptr;
    res = spiObj->engineGeneratePriKeyBySpec(spiObj, reinterpret_cast<HcfAsyKeyParamsSpec *>(&rsaPairSpec), &priKey);
    EXPECT_NE(res, HCF_SUCCESS);
    EXPECT_EQ(priKey, nullptr);

    HcfObjDestroy(spiObj);
}

HWTEST_F(CryptoRsaAsyKeyGeneratorBySpecCovTest, CryptoRsaAsyKeyGeneratorBySpecCovTest011, TestSize.Level0)
{
    HcfRsaKeyPairParamsSpec rsaPairSpec = {};
    unsigned char dataN[RSA_2048_N_BYTE_SIZE] = {0};
    unsigned char dataE[RSA_2048_E_BYTE_SIZE] = {0};
    unsigned char dataD[RSA_2048_D_BYTE_SIZE] = {0};
    GenerateRsa2048CorrectKeyPairSpec(dataN, dataE, dataD, &rsaPairSpec);
    rsaPairSpec.base.base.specType = HCF_COMMON_PARAMS_SPEC;

    HcfAsyKeyGeneratorSpi *spiObj = nullptr;
    HcfAsyKeyGenParams params = {
        .algo = HCF_ALG_RSA,
        .bits = OPENSSL_RSA_KEY_SIZE_2048,
        .primes = 0,
    };

    HcfResult res = HcfAsyKeyGeneratorSpiRsaCreate(&params, &spiObj);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(spiObj, nullptr);

    HcfPriKey *priKey = nullptr;
    res = spiObj->engineGeneratePriKeyBySpec(spiObj, reinterpret_cast<HcfAsyKeyParamsSpec *>(&rsaPairSpec), &priKey);
    EXPECT_NE(res, HCF_SUCCESS);
    EXPECT_EQ(priKey, nullptr);
    HcfObjDestroy(spiObj);
}

HWTEST_F(CryptoRsaAsyKeyGeneratorBySpecCovTest, CryptoRsaAsyKeyGeneratorBySpecCovTest012, TestSize.Level0)
{
    HcfRsaKeyPairParamsSpec rsaPairSpec = {};
    unsigned char dataN[RSA_2048_N_BYTE_SIZE] = {0};
    unsigned char dataE[RSA_2048_E_BYTE_SIZE] = {0};
    unsigned char dataD[RSA_2048_D_BYTE_SIZE] = {0};
    GenerateRsa2048CorrectKeyPairSpec(dataN, dataE, dataD, &rsaPairSpec);

    HcfAsyKeyGeneratorSpi *spiObj = nullptr;
    HcfAsyKeyGenParams params = {
        .algo = HCF_ALG_RSA,
        .bits = OPENSSL_RSA_KEY_SIZE_2048,
        .primes = 0,
    };

    HcfResult res = HcfAsyKeyGeneratorSpiRsaCreate(&params, &spiObj);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(spiObj, nullptr);

    HcfPriKey *priKey = nullptr;
    res = spiObj->engineGeneratePriKeyBySpec(reinterpret_cast<HcfAsyKeyGeneratorSpi *>(&obj),
        reinterpret_cast<HcfAsyKeyParamsSpec *>(&rsaPairSpec), &priKey);
    EXPECT_NE(res, HCF_SUCCESS);
    EXPECT_EQ(priKey, nullptr);
    HcfObjDestroy(spiObj);
}

HWTEST_F(CryptoRsaAsyKeyGeneratorBySpecCovTest, CryptoRsaAsyKeyGeneratorBySpecCovTest013, TestSize.Level0)
{
    HcfAsyKeyGeneratorSpi *spiObj = nullptr;
    HcfAsyKeyGenParams params = {
        .algo = HCF_ALG_RSA,
        .bits = OPENSSL_RSA_KEY_SIZE_2048,
        .primes = 0,
    };

    HcfResult res = HcfAsyKeyGeneratorSpiRsaCreate(&params, &spiObj);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(spiObj, nullptr);

    res = spiObj->engineGeneratePubKeyBySpec(nullptr, nullptr, nullptr);
    EXPECT_NE(res, HCF_SUCCESS);
    HcfObjDestroy(spiObj);
}

HWTEST_F(CryptoRsaAsyKeyGeneratorBySpecCovTest, CryptoRsaAsyKeyGeneratorBySpecCovTest014, TestSize.Level0)
{
    HcfAsyKeyGeneratorSpi *spiObj = nullptr;
    HcfAsyKeyGenParams params = {
        .algo = HCF_ALG_RSA,
        .bits = OPENSSL_RSA_KEY_SIZE_2048,
        .primes = 0,
    };

    HcfResult res = HcfAsyKeyGeneratorSpiRsaCreate(&params, &spiObj);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(spiObj, nullptr);

    res = spiObj->engineGeneratePubKeyBySpec(spiObj, nullptr, nullptr);
    EXPECT_NE(res, HCF_SUCCESS);
    HcfObjDestroy(spiObj);
}

HWTEST_F(CryptoRsaAsyKeyGeneratorBySpecCovTest, CryptoRsaAsyKeyGeneratorBySpecCovTest015, TestSize.Level0)
{
    HcfAsyKeyGeneratorSpi *spiObj = nullptr;
    HcfAsyKeyGenParams params = {
        .algo = HCF_ALG_RSA,
        .bits = OPENSSL_RSA_KEY_SIZE_2048,
        .primes = 0,
    };

    HcfResult res = HcfAsyKeyGeneratorSpiRsaCreate(&params, &spiObj);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(spiObj, nullptr);

    HcfPubKey *pubKey = nullptr;
    res = spiObj->engineGeneratePubKeyBySpec(spiObj, nullptr, &pubKey);
    EXPECT_NE(res, HCF_SUCCESS);
    EXPECT_EQ(pubKey, nullptr);

    HcfObjDestroy(spiObj);
}

HWTEST_F(CryptoRsaAsyKeyGeneratorBySpecCovTest, CryptoRsaAsyKeyGeneratorBySpecCovTest016, TestSize.Level0)
{
    HcfRsaKeyPairParamsSpec rsaPairSpec = {};
    unsigned char dataN[RSA_2048_N_BYTE_SIZE] = {0};
    unsigned char dataE[RSA_2048_E_BYTE_SIZE] = {0};
    unsigned char dataD[RSA_2048_D_BYTE_SIZE] = {0};
    GenerateRsa2048CorrectKeyPairSpec(dataN, dataE, dataD, &rsaPairSpec);
    rsaPairSpec.base.base.algName = const_cast<char *>(g_invalidAlgName);

    HcfAsyKeyGeneratorSpi *spiObj = nullptr;
    HcfAsyKeyGenParams params = {
        .algo = HCF_ALG_RSA,
        .bits = OPENSSL_RSA_KEY_SIZE_2048,
        .primes = 0,
    };

    HcfResult res = HcfAsyKeyGeneratorSpiRsaCreate(&params, &spiObj);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(spiObj, nullptr);

    HcfPubKey *pubKey = nullptr;
    res = spiObj->engineGeneratePubKeyBySpec(spiObj, reinterpret_cast<HcfAsyKeyParamsSpec *>(&rsaPairSpec), &pubKey);
    EXPECT_NE(res, HCF_SUCCESS);
    EXPECT_EQ(pubKey, nullptr);

    HcfObjDestroy(spiObj);
}

HWTEST_F(CryptoRsaAsyKeyGeneratorBySpecCovTest, CryptoRsaAsyKeyGeneratorBySpecCovTest017, TestSize.Level0)
{
    HcfRsaKeyPairParamsSpec rsaPairSpec = {};
    unsigned char dataN[RSA_2048_N_BYTE_SIZE] = {0};
    unsigned char dataE[RSA_2048_E_BYTE_SIZE] = {0};
    unsigned char dataD[RSA_2048_D_BYTE_SIZE] = {0};
    GenerateRsa2048CorrectKeyPairSpec(dataN, dataE, dataD, &rsaPairSpec);
    rsaPairSpec.base.base.specType = HCF_COMMON_PARAMS_SPEC;

    HcfAsyKeyGeneratorSpi *spiObj = nullptr;
    HcfAsyKeyGenParams params = {
        .algo = HCF_ALG_RSA,
        .bits = OPENSSL_RSA_KEY_SIZE_2048,
        .primes = 0,
    };

    HcfResult res = HcfAsyKeyGeneratorSpiRsaCreate(&params, &spiObj);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(spiObj, nullptr);

    HcfPubKey *pubKey = nullptr;
    res = spiObj->engineGeneratePubKeyBySpec(spiObj, reinterpret_cast<HcfAsyKeyParamsSpec *>(&rsaPairSpec), &pubKey);
    EXPECT_NE(res, HCF_SUCCESS);
    EXPECT_EQ(pubKey, nullptr);
    HcfObjDestroy(spiObj);
}

HWTEST_F(CryptoRsaAsyKeyGeneratorBySpecCovTest, CryptoRsaAsyKeyGeneratorBySpecCovTest018, TestSize.Level0)
{
    HcfRsaKeyPairParamsSpec rsaPairSpec = {};
    unsigned char dataN[RSA_2048_N_BYTE_SIZE] = {0};
    unsigned char dataE[RSA_2048_E_BYTE_SIZE] = {0};
    unsigned char dataD[RSA_2048_D_BYTE_SIZE] = {0};
    GenerateRsa2048CorrectKeyPairSpec(dataN, dataE, dataD, &rsaPairSpec);

    HcfAsyKeyGeneratorSpi *spiObj = nullptr;
    HcfAsyKeyGenParams params = {
        .algo = HCF_ALG_RSA,
        .bits = OPENSSL_RSA_KEY_SIZE_2048,
        .primes = 0,
    };

    HcfResult res = HcfAsyKeyGeneratorSpiRsaCreate(&params, &spiObj);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(spiObj, nullptr);

    HcfPubKey *pubKey = nullptr;
    res = spiObj->engineGeneratePubKeyBySpec(reinterpret_cast<HcfAsyKeyGeneratorSpi *>(&obj),
        reinterpret_cast<HcfAsyKeyParamsSpec *>(&rsaPairSpec), &pubKey);
    EXPECT_NE(res, HCF_SUCCESS);
    EXPECT_EQ(pubKey, nullptr);
    HcfObjDestroy(spiObj);
}

HWTEST_F(CryptoRsaAsyKeyGeneratorBySpecCovTest, CryptoRsaAsyKeyGeneratorBySpecCovTest019, TestSize.Level0)
{
    HcfRsaKeyPairParamsSpec rsaPairSpec = {};
    unsigned char dataN[RSA_2048_N_BYTE_SIZE] = {0};
    unsigned char dataE[RSA_2048_E_BYTE_SIZE] = {0};
    unsigned char dataD[RSA_2048_D_BYTE_SIZE] = {0};
    GenerateRsa2048CorrectKeyPairSpec(dataN, dataE, dataD, &rsaPairSpec);

    HcfAsyKeyGeneratorBySpec *generator = nullptr;
    HcfResult res = HcfAsyKeyGeneratorBySpecCreate(reinterpret_cast<HcfAsyKeyParamsSpec *>(&rsaPairSpec), &generator);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(generator, nullptr);

    HcfKeyPair *keyPair = nullptr;
    res = generator->generateKeyPair(generator, &keyPair);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(keyPair, nullptr);

    res = keyPair->pubKey->getAsyKeySpecBigInteger(nullptr, RSA_N_BN, nullptr);
    EXPECT_NE(res, HCF_SUCCESS);
    HcfObjDestroy(keyPair);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoRsaAsyKeyGeneratorBySpecCovTest, CryptoRsaAsyKeyGeneratorBySpecCovTest020, TestSize.Level0)
{
    HcfRsaKeyPairParamsSpec rsaPairSpec = {};
    unsigned char dataN[RSA_2048_N_BYTE_SIZE] = {0};
    unsigned char dataE[RSA_2048_E_BYTE_SIZE] = {0};
    unsigned char dataD[RSA_2048_D_BYTE_SIZE] = {0};
    GenerateRsa2048CorrectKeyPairSpec(dataN, dataE, dataD, &rsaPairSpec);

    HcfAsyKeyGeneratorBySpec *generator = nullptr;
    HcfResult res = HcfAsyKeyGeneratorBySpecCreate(reinterpret_cast<HcfAsyKeyParamsSpec *>(&rsaPairSpec), &generator);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(generator, nullptr);

    HcfKeyPair *keyPair = nullptr;
    res = generator->generateKeyPair(generator, &keyPair);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(keyPair, nullptr);

    res = keyPair->pubKey->getAsyKeySpecBigInteger(keyPair->pubKey, RSA_N_BN, nullptr);
    EXPECT_NE(res, HCF_SUCCESS);
    HcfObjDestroy(keyPair);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoRsaAsyKeyGeneratorBySpecCovTest, CryptoRsaAsyKeyGeneratorBySpecCovTest021, TestSize.Level0)
{
    HcfRsaKeyPairParamsSpec rsaPairSpec = {};
    unsigned char dataN[RSA_2048_N_BYTE_SIZE] = {0};
    unsigned char dataE[RSA_2048_E_BYTE_SIZE] = {0};
    unsigned char dataD[RSA_2048_D_BYTE_SIZE] = {0};
    GenerateRsa2048CorrectKeyPairSpec(dataN, dataE, dataD, &rsaPairSpec);

    HcfAsyKeyGeneratorBySpec *generator = nullptr;
    HcfResult res = HcfAsyKeyGeneratorBySpecCreate(reinterpret_cast<HcfAsyKeyParamsSpec *>(&rsaPairSpec), &generator);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(generator, nullptr);

    HcfKeyPair *keyPair = nullptr;
    res = generator->generateKeyPair(generator, &keyPair);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(keyPair, nullptr);

    HcfBigInteger retN = { .data = nullptr, .len = 0 };
    res = keyPair->pubKey->getAsyKeySpecBigInteger(keyPair->pubKey, RSA_SK_BN, &retN);
    EXPECT_NE(res, HCF_SUCCESS);
    EXPECT_EQ(retN.data, nullptr);
    HcfObjDestroy(keyPair);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoRsaAsyKeyGeneratorBySpecCovTest, CryptoRsaAsyKeyGeneratorBySpecCovTest022, TestSize.Level0)
{
    HcfRsaKeyPairParamsSpec rsaPairSpec = {};
    unsigned char dataN[RSA_2048_N_BYTE_SIZE] = {0};
    unsigned char dataE[RSA_2048_E_BYTE_SIZE] = {0};
    unsigned char dataD[RSA_2048_D_BYTE_SIZE] = {0};
    GenerateRsa2048CorrectKeyPairSpec(dataN, dataE, dataD, &rsaPairSpec);

    HcfAsyKeyGeneratorBySpec *generator = nullptr;
    HcfResult res = HcfAsyKeyGeneratorBySpecCreate(reinterpret_cast<HcfAsyKeyParamsSpec *>(&rsaPairSpec), &generator);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(generator, nullptr);

    HcfKeyPair *keyPair = nullptr;
    res = generator->generateKeyPair(generator, &keyPair);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(keyPair, nullptr);

    HcfBigInteger retN = { .data = nullptr, .len = 0 };
    res = keyPair->priKey->getAsyKeySpecBigInteger(keyPair->priKey, RSA_PK_BN, &retN);
    EXPECT_NE(res, HCF_SUCCESS);
    EXPECT_EQ(retN.data, nullptr);
    HcfObjDestroy(keyPair);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoRsaAsyKeyGeneratorBySpecCovTest, CryptoRsaAsyKeyGeneratorBySpecCovTest023, TestSize.Level0)
{
    HcfRsaKeyPairParamsSpec rsaPairSpec = {};
    unsigned char dataN[RSA_2048_N_BYTE_SIZE] = {0};
    unsigned char dataE[RSA_2048_E_BYTE_SIZE] = {0};
    unsigned char dataD[RSA_2048_D_BYTE_SIZE] = {0};
    GenerateRsa2048CorrectKeyPairSpec(dataN, dataE, dataD, &rsaPairSpec);

    HcfAsyKeyGeneratorBySpec *generator = nullptr;
    HcfResult res = HcfAsyKeyGeneratorBySpecCreate(reinterpret_cast<HcfAsyKeyParamsSpec *>(&rsaPairSpec), &generator);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(generator, nullptr);

    HcfKeyPair *keyPair = nullptr;
    res = generator->generateKeyPair(generator, &keyPair);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(keyPair, nullptr);

    HcfBigInteger retN = { .data = nullptr, .len = 0 };
    res = keyPair->priKey->getAsyKeySpecBigInteger(keyPair->priKey, RSA_PK_BN, nullptr);
    EXPECT_NE(res, HCF_SUCCESS);
    EXPECT_EQ(retN.data, nullptr);
    HcfObjDestroy(keyPair);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoRsaAsyKeyGeneratorBySpecCovTest, CryptoRsaAsyKeyGeneratorBySpecCovTest024, TestSize.Level0)
{
    HcfRsaKeyPairParamsSpec rsaPairSpec = {};
    unsigned char dataN[RSA_2048_N_BYTE_SIZE] = {0};
    unsigned char dataE[RSA_2048_E_BYTE_SIZE] = {0};
    unsigned char dataD[RSA_2048_D_BYTE_SIZE] = {0};
    GenerateRsa2048CorrectKeyPairSpec(dataN, dataE, dataD, &rsaPairSpec);

    HcfAsyKeyGeneratorBySpec *generator = nullptr;
    HcfResult res = HcfAsyKeyGeneratorBySpecCreate(reinterpret_cast<HcfAsyKeyParamsSpec *>(&rsaPairSpec), &generator);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(generator, nullptr);

    HcfKeyPair *keyPair = nullptr;
    res = generator->generateKeyPair(generator, &keyPair);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(keyPair, nullptr);

    HcfBigInteger retN = { .data = nullptr, .len = 0 };
    res = keyPair->priKey->getAsyKeySpecBigInteger(nullptr, RSA_PK_BN, &retN);
    EXPECT_NE(res, HCF_SUCCESS);
    EXPECT_EQ(retN.data, nullptr);
    HcfObjDestroy(keyPair);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoRsaAsyKeyGeneratorBySpecCovTest, CryptoRsaAsyKeyGeneratorBySpecCovTest025, TestSize.Level0)
{
    HcfRsaKeyPairParamsSpec rsaPairSpec = {};
    unsigned char dataN[RSA_2048_N_BYTE_SIZE] = {0};
    unsigned char dataE[RSA_2048_E_BYTE_SIZE] = {0};
    unsigned char dataD[RSA_2048_D_BYTE_SIZE] = {0};
    GenerateRsa2048CorrectKeyPairSpec(dataN, dataE, dataD, &rsaPairSpec);

    HcfAsyKeyGeneratorBySpec *generator = nullptr;
    HcfResult res = HcfAsyKeyGeneratorBySpecCreate(reinterpret_cast<HcfAsyKeyParamsSpec *>(&rsaPairSpec), &generator);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(generator, nullptr);

    HcfKeyPair *keyPair = nullptr;
    res = generator->generateKeyPair(generator, &keyPair);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(keyPair, nullptr);

    HcfAsyKeyGenerator *generatorEcc = nullptr;
    res = HcfAsyKeyGeneratorCreate("ECC256", &generatorEcc);
    EXPECT_EQ(res, HCF_SUCCESS);
    HcfKeyPair *keyPairEcc = nullptr;
    res = generatorEcc->generateKeyPair(generatorEcc, nullptr, &keyPairEcc);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(keyPairEcc, nullptr);

    HcfBigInteger retN = { .data = nullptr, .len = 0 };
    res = keyPair->priKey->getAsyKeySpecBigInteger(keyPairEcc->priKey, RSA_PK_BN, &retN);
    EXPECT_NE(res, HCF_SUCCESS);
    EXPECT_EQ(retN.data, nullptr);

    HcfObjDestroy(keyPair);
    HcfObjDestroy(generator);
    HcfObjDestroy(keyPairEcc);
    HcfObjDestroy(generatorEcc);
}

HWTEST_F(CryptoRsaAsyKeyGeneratorBySpecCovTest, CryptoRsaAsyKeyGeneratorBySpecCovTest026, TestSize.Level0)
{
    HcfRsaKeyPairParamsSpec rsaPairSpec = {};
    unsigned char dataN[RSA_2048_N_BYTE_SIZE] = {0};
    unsigned char dataE[RSA_2048_E_BYTE_SIZE] = {0};
    unsigned char dataD[RSA_2048_D_BYTE_SIZE] = {0};
    GenerateRsa2048CorrectKeyPairSpec(dataN, dataE, dataD, &rsaPairSpec);

    HcfAsyKeyGeneratorBySpec *generator = nullptr;
    HcfResult res = HcfAsyKeyGeneratorBySpecCreate(reinterpret_cast<HcfAsyKeyParamsSpec *>(&rsaPairSpec), &generator);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(generator, nullptr);

    HcfKeyPair *keyPair = nullptr;
    res = generator->generateKeyPair(generator, &keyPair);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(keyPair, nullptr);

    HcfAsyKeyGenerator *generatorEcc = nullptr;
    res = HcfAsyKeyGeneratorCreate("ECC256", &generatorEcc);
    EXPECT_EQ(res, HCF_SUCCESS);
    HcfKeyPair *keyPairEcc = nullptr;
    res = generatorEcc->generateKeyPair(generatorEcc, nullptr, &keyPairEcc);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(keyPairEcc, nullptr);


    HcfBigInteger retN = { .data = nullptr, .len = 0 };
    res = keyPair->pubKey->getAsyKeySpecBigInteger(keyPairEcc->pubKey, RSA_SK_BN, &retN);
    EXPECT_NE(res, HCF_SUCCESS);
    EXPECT_EQ(retN.data, nullptr);
    HcfObjDestroy(keyPair);
    HcfObjDestroy(generator);
    HcfObjDestroy(keyPairEcc);
    HcfObjDestroy(generatorEcc);
}

HWTEST_F(CryptoRsaAsyKeyGeneratorBySpecCovTest, CryptoRsaAsyKeyGeneratorBySpecCovTest033, TestSize.Level0)
{
    HcfAsyKeyGeneratorSpi *spiObj = nullptr;
    HcfAsyKeyGenParams params = {
        .algo = HCF_ALG_RSA,
        .bits = OPENSSL_RSA_KEY_SIZE_2048,
        .primes = 0,
    };

    HcfResult res = HcfAsyKeyGeneratorSpiRsaCreate(&params, &spiObj);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(spiObj, nullptr);

    HcfKeyPair *keyPair = nullptr;
    res = spiObj->engineGenerateKeyPair(reinterpret_cast<HcfAsyKeyGeneratorSpi *>(&obj), &keyPair);
    EXPECT_NE(res, HCF_SUCCESS);
    EXPECT_EQ(keyPair, nullptr);

    HcfObjDestroy(spiObj);
}

HWTEST_F(CryptoRsaAsyKeyGeneratorBySpecCovTest, CryptoRsaAsyKeyGeneratorBySpecCovTest034, TestSize.Level0)
{
    HcfAsyKeyGeneratorSpi *spiObj = nullptr;
    HcfAsyKeyGenParams params = {
        .algo = HCF_ALG_RSA,
        .bits = OPENSSL_RSA_KEY_SIZE_2048,
        .primes = 0,
    };

    HcfResult res = HcfAsyKeyGeneratorSpiRsaCreate(&params, &spiObj);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(spiObj, nullptr);

    res = spiObj->engineConvertKey(nullptr, nullptr, nullptr, nullptr, nullptr);
    EXPECT_NE(res, HCF_SUCCESS);

    HcfObjDestroy(spiObj);
}

HWTEST_F(CryptoRsaAsyKeyGeneratorBySpecCovTest, CryptoRsaAsyKeyGeneratorBySpecCovTest035, TestSize.Level0)
{
    HcfAsyKeyGeneratorSpi *spiObj = nullptr;
    HcfAsyKeyGenParams params = {
        .algo = HCF_ALG_RSA,
        .bits = OPENSSL_RSA_KEY_SIZE_2048,
        .primes = 0,
    };

    HcfResult res = HcfAsyKeyGeneratorSpiRsaCreate(&params, &spiObj);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(spiObj, nullptr);

    HcfKeyPair *keyPair = nullptr;
    res = spiObj->engineConvertKey(spiObj, nullptr, nullptr, nullptr, &keyPair);
    EXPECT_NE(res, HCF_SUCCESS);
    EXPECT_EQ(keyPair, nullptr);

    HcfObjDestroy(spiObj);
}

HWTEST_F(CryptoRsaAsyKeyGeneratorBySpecCovTest, CryptoRsaAsyKeyGeneratorBySpecCovTest036, TestSize.Level0)
{
    HcfAsyKeyGeneratorSpi *spiObj = nullptr;
    HcfAsyKeyGenParams params = {
        .algo = HCF_ALG_RSA,
        .bits = OPENSSL_RSA_KEY_SIZE_2048,
        .primes = 0,
    };

    HcfBlob pubBlob = { .data = nullptr, .len = 0 };
    HcfResult res = HcfAsyKeyGeneratorSpiRsaCreate(&params, &spiObj);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(spiObj, nullptr);

    HcfKeyPair *keyPair = nullptr;
    res = spiObj->engineConvertKey(reinterpret_cast<HcfAsyKeyGeneratorSpi *>(&obj),
        nullptr, &pubBlob, nullptr, &keyPair);
    EXPECT_NE(res, HCF_SUCCESS);
    EXPECT_EQ(keyPair, nullptr);

    HcfObjDestroy(spiObj);
}

HWTEST_F(CryptoRsaAsyKeyGeneratorBySpecCovTest, CryptoRsaAsyKeyGeneratorBySpecCovTest037, TestSize.Level0)
{
    HcfAsyKeyGeneratorSpi *spiObj = nullptr;
    HcfAsyKeyGenParams params = {
        .algo = HCF_ALG_RSA,
        .bits = OPENSSL_RSA_KEY_SIZE_2048,
        .primes = 0,
    };

    HcfBlob pubBlob = { .data = nullptr, .len = 0 };
    HcfResult res = HcfAsyKeyGeneratorSpiRsaCreate(&params, &spiObj);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(spiObj, nullptr);

    HcfKeyPair *keyPair = nullptr;
    res = spiObj->engineConvertKey(spiObj, nullptr, &pubBlob, nullptr, &keyPair);
    EXPECT_NE(res, HCF_SUCCESS);
    EXPECT_EQ(keyPair, nullptr);

    HcfObjDestroy(spiObj);
}

HWTEST_F(CryptoRsaAsyKeyGeneratorBySpecCovTest, CryptoRsaAsyKeyGeneratorBySpecCovTest038, TestSize.Level0)
{
    HcfAsyKeyGeneratorSpi *spiObj = nullptr;
    HcfAsyKeyGenParams params = {
        .algo = HCF_ALG_RSA,
        .bits = OPENSSL_RSA_KEY_SIZE_2048,
        .primes = 0,
    };

    HcfBlob pubBlob = { .data = nullptr, .len = OPENSSL_RSA_KEY_SIZE_2048 };
    HcfResult res = HcfAsyKeyGeneratorSpiRsaCreate(&params, &spiObj);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(spiObj, nullptr);

    HcfKeyPair *keyPair = nullptr;
    res = spiObj->engineConvertKey(spiObj, nullptr, &pubBlob, nullptr, &keyPair);
    EXPECT_NE(res, HCF_SUCCESS);
    EXPECT_EQ(keyPair, nullptr);

    HcfObjDestroy(spiObj);
}

HWTEST_F(CryptoRsaAsyKeyGeneratorBySpecCovTest, CryptoRsaAsyKeyGeneratorBySpecCovTest039, TestSize.Level0)
{
    HcfAsyKeyGeneratorSpi *spiObj = nullptr;
    HcfAsyKeyGenParams params = {
        .algo = HCF_ALG_RSA,
        .bits = OPENSSL_RSA_KEY_SIZE_2048,
        .primes = 0,
    };

    HcfBlob priBlob = { .data = nullptr, .len = 0 };
    HcfResult res = HcfAsyKeyGeneratorSpiRsaCreate(&params, &spiObj);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(spiObj, nullptr);

    HcfKeyPair *keyPair = nullptr;
    res = spiObj->engineConvertKey(spiObj, nullptr, nullptr, &priBlob, &keyPair);
    EXPECT_NE(res, HCF_SUCCESS);
    EXPECT_EQ(keyPair, nullptr);

    HcfObjDestroy(spiObj);
}

HWTEST_F(CryptoRsaAsyKeyGeneratorBySpecCovTest, CryptoRsaAsyKeyGeneratorBySpecCovTest040, TestSize.Level0)
{
    HcfAsyKeyGeneratorSpi *spiObj = nullptr;
    HcfAsyKeyGenParams params = {
        .algo = HCF_ALG_RSA,
        .bits = OPENSSL_RSA_KEY_SIZE_2048,
        .primes = 0,
    };

    HcfBlob priBlob = { .data = nullptr, .len = OPENSSL_RSA_KEY_SIZE_2048 };
    HcfResult res = HcfAsyKeyGeneratorSpiRsaCreate(&params, &spiObj);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(spiObj, nullptr);

    HcfKeyPair *keyPair = nullptr;
    res = spiObj->engineConvertKey(spiObj, nullptr, nullptr, &priBlob, &keyPair);
    EXPECT_NE(res, HCF_SUCCESS);
    EXPECT_EQ(keyPair, nullptr);

    HcfObjDestroy(spiObj);
}

HWTEST_F(CryptoRsaAsyKeyGeneratorBySpecCovTest, CryptoRsaAsyKeyGeneratorBySpecCovTest041, TestSize.Level0)
{
    HcfRsaKeyPairParamsSpec rsaPairSpec = {};
    unsigned char dataN[RSA_2048_N_BYTE_SIZE] = {0};
    unsigned char dataE[RSA_2048_E_BYTE_SIZE] = {0};
    unsigned char dataD[RSA_2048_D_BYTE_SIZE] = {0};
    GenerateRsa2048CorrectKeyPairSpec(dataN, dataE, dataD, &rsaPairSpec);

    HcfAsyKeyGeneratorBySpec *generator = nullptr;
    HcfResult res = HcfAsyKeyGeneratorBySpecCreate(reinterpret_cast<HcfAsyKeyParamsSpec *>(&rsaPairSpec), &generator);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(generator, nullptr);

    HcfKeyPair *keyPair = nullptr;
    res = generator->generateKeyPair(generator, &keyPair);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(keyPair, nullptr);

    res = keyPair->priKey->base.getEncoded(nullptr, nullptr);
    EXPECT_NE(res, HCF_SUCCESS);

    HcfObjDestroy(keyPair);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoRsaAsyKeyGeneratorBySpecCovTest, CryptoRsaAsyKeyGeneratorBySpecCovTest042, TestSize.Level0)
{
    HcfRsaKeyPairParamsSpec rsaPairSpec = {};
    unsigned char dataN[RSA_2048_N_BYTE_SIZE] = {0};
    unsigned char dataE[RSA_2048_E_BYTE_SIZE] = {0};
    unsigned char dataD[RSA_2048_D_BYTE_SIZE] = {0};
    GenerateRsa2048CorrectKeyPairSpec(dataN, dataE, dataD, &rsaPairSpec);

    HcfAsyKeyGeneratorBySpec *generator = nullptr;
    HcfResult res = HcfAsyKeyGeneratorBySpecCreate(reinterpret_cast<HcfAsyKeyParamsSpec *>(&rsaPairSpec), &generator);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(generator, nullptr);

    HcfKeyPair *keyPair = nullptr;
    res = generator->generateKeyPair(generator, &keyPair);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(keyPair, nullptr);

    res = keyPair->pubKey->base.getEncoded(nullptr, nullptr);
    EXPECT_NE(res, HCF_SUCCESS);

    HcfObjDestroy(keyPair);
    HcfObjDestroy(generator);
}
}
