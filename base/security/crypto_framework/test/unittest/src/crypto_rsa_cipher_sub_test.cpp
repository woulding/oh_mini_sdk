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
#include "cipher.h"
#include "cipher_rsa_openssl.h"
#include "detailed_rsa_key_params.h"
#include "key_pair.h"
#include "memory.h"
#include "cstring"
#include "openssl_common.h"

using namespace std;
using namespace testing::ext;

namespace {
class CryptoRsaCipherSubTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp();
    void TearDown();
};

void CryptoRsaCipherSubTest::SetUpTestCase() {}
void CryptoRsaCipherSubTest::TearDownTestCase() {}
void CryptoRsaCipherSubTest::SetUp() {}
void CryptoRsaCipherSubTest::TearDown() {}

namespace {
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

static const char *GetMockClass(void)
{
    return "Mock";
}

static HcfObjectBase g_obj = {
    .getClass = GetMockClass,
    .destroy = nullptr
};
}

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

HWTEST_F(CryptoRsaCipherSubTest, CryptoRsaCipherTest009, TestSize.Level0)
{
    uint8_t plan[] = "this is rsa cipher test!\0";
    HcfRsaKeyPairParamsSpec rsaPairSpec = {};
    unsigned char dataN[RSA_2048_N_BYTE_SIZE] = {0};
    unsigned char dataE[RSA_2048_E_BYTE_SIZE] = {0};
    unsigned char dataD[RSA_2048_D_BYTE_SIZE] = {0};
    GenerateRsa2048CorrectKeyPairSpec(dataN, dataE, dataD, &rsaPairSpec);

    HcfAsyKeyGeneratorBySpec *generator = nullptr;
    HcfResult res = HcfAsyKeyGeneratorBySpecCreate(reinterpret_cast<HcfAsyKeyParamsSpec *>(&rsaPairSpec), &generator);
    EXPECT_EQ(res, HCF_SUCCESS);
    HcfKeyPair *keyPair = nullptr;
    res = generator->generateKeyPair(generator, &keyPair);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(keyPair, nullptr);

    HcfBlob input = {.data = (uint8_t *)plan, .len = strlen((char *)plan)};
    HcfBlob encoutput = {.data = nullptr, .len = 0};
    HcfCipher *cipher = nullptr;
    res = HcfCipherCreate("RSA|PKCS1_OAEP|SHA256|MGF1_SHA256", &cipher);
    EXPECT_EQ(res, HCF_SUCCESS);
    res = cipher->init(cipher, ENCRYPT_MODE, (HcfKey *)keyPair->pubKey, nullptr);
    EXPECT_EQ(res, HCF_SUCCESS);

    uint8_t pSourceData[] = "123456\0";
    HcfBlob pSource = {.data = (uint8_t *)pSourceData, .len = strlen((char *)pSourceData)};
    // enum error
    res = cipher->setCipherSpecUint8Array(reinterpret_cast<HcfCipher *>(&g_obj),
        OAEP_MD_NAME_STR, pSource);
    EXPECT_NE(res, HCF_SUCCESS);
    res = cipher->doFinal(cipher, &input, &encoutput);
    EXPECT_EQ(res, HCF_SUCCESS);
    HcfObjDestroy(cipher);

    // free
    HcfFree(encoutput.data);

    HcfObjDestroy(keyPair);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoRsaCipherSubTest, CryptoRsaCipherTest013, TestSize.Level0)
{
    HcfRsaKeyPairParamsSpec rsaPairSpec = {};
    unsigned char dataN[RSA_2048_N_BYTE_SIZE] = {0};
    unsigned char dataE[RSA_2048_E_BYTE_SIZE] = {0};
    unsigned char dataD[RSA_2048_D_BYTE_SIZE] = {0};
    GenerateRsa2048CorrectKeyPairSpec(dataN, dataE, dataD, &rsaPairSpec);

    HcfAsyKeyGeneratorBySpec *generator = nullptr;
    HcfResult res = HcfAsyKeyGeneratorBySpecCreate(reinterpret_cast<HcfAsyKeyParamsSpec *>(&rsaPairSpec), &generator);
    EXPECT_EQ(res, HCF_SUCCESS);
    HcfKeyPair *keyPair = nullptr;
    res = generator->generateKeyPair(generator, &keyPair);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(keyPair, nullptr);

    HcfCipher *cipher = nullptr;
    char *ret = nullptr;
    res = HcfCipherCreate("RSA|PKCS1_OAEP|SHA256|MGF1_SHA256", &cipher);
    EXPECT_EQ(res, HCF_SUCCESS);
    res = cipher->getCipherSpecString(reinterpret_cast<HcfCipher *>(&g_obj), OAEP_MD_NAME_STR, &ret);
    EXPECT_NE(res, HCF_SUCCESS);
    EXPECT_EQ(ret, nullptr);

    HcfObjDestroy(cipher);

    HcfObjDestroy(keyPair);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoRsaCipherSubTest, CryptoRsaCipherTest017, TestSize.Level0)
{
    HcfRsaKeyPairParamsSpec rsaPairSpec = {};
    unsigned char dataN[RSA_2048_N_BYTE_SIZE] = {0};
    unsigned char dataE[RSA_2048_E_BYTE_SIZE] = {0};
    unsigned char dataD[RSA_2048_D_BYTE_SIZE] = {0};
    GenerateRsa2048CorrectKeyPairSpec(dataN, dataE, dataD, &rsaPairSpec);

    HcfAsyKeyGeneratorBySpec *generator = nullptr;
    HcfResult res = HcfAsyKeyGeneratorBySpecCreate(reinterpret_cast<HcfAsyKeyParamsSpec *>(&rsaPairSpec), &generator);
    EXPECT_EQ(res, HCF_SUCCESS);
    HcfKeyPair *keyPair = nullptr;
    res = generator->generateKeyPair(generator, &keyPair);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(keyPair, nullptr);

    HcfCipher *cipher = nullptr;
    HcfBlob retBlob = { .data = nullptr, .len = 0 };
    res = HcfCipherCreate("RSA|PKCS1_OAEP|SHA256|MGF1_SHA256", &cipher);
    EXPECT_EQ(res, HCF_SUCCESS);
    res = cipher->getCipherSpecUint8Array(reinterpret_cast<HcfCipher *>(&g_obj), OAEP_MGF1_PSRC_UINT8ARR, &retBlob);
    EXPECT_NE(res, HCF_SUCCESS);
    EXPECT_EQ(retBlob.data, nullptr);

    HcfObjDestroy(cipher);

    HcfObjDestroy(keyPair);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoRsaCipherSubTest, CryptoRsaCipherTest018, TestSize.Level0)
{
    HcfRsaKeyPairParamsSpec rsaPairSpec = {};
    unsigned char dataN[RSA_2048_N_BYTE_SIZE] = {0};
    unsigned char dataE[RSA_2048_E_BYTE_SIZE] = {0};
    unsigned char dataD[RSA_2048_D_BYTE_SIZE] = {0};
    GenerateRsa2048CorrectKeyPairSpec(dataN, dataE, dataD, &rsaPairSpec);

    HcfAsyKeyGeneratorBySpec *generator = nullptr;
    HcfResult res = HcfAsyKeyGeneratorBySpecCreate(reinterpret_cast<HcfAsyKeyParamsSpec *>(&rsaPairSpec), &generator);
    EXPECT_EQ(res, HCF_SUCCESS);
    HcfKeyPair *keyPair = nullptr;
    res = generator->generateKeyPair(generator, &keyPair);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(keyPair, nullptr);

    HcfCipher *cipher = nullptr;
    HcfBlob retBlob = { .data = nullptr, .len = 0 };
    res = HcfCipherCreate("RSA|PKCS1|SHA256", &cipher);
    EXPECT_EQ(res, HCF_SUCCESS);
    res = cipher->getCipherSpecUint8Array(cipher, OAEP_MGF1_PSRC_UINT8ARR, &retBlob);
    EXPECT_NE(res, HCF_SUCCESS);
    EXPECT_EQ(retBlob.data, nullptr);

    HcfObjDestroy(cipher);

    HcfObjDestroy(keyPair);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoRsaCipherSubTest, CryptoRsaCipherTest019, TestSize.Level0)
{
    HcfRsaKeyPairParamsSpec rsaPairSpec = {};
    unsigned char dataN[RSA_2048_N_BYTE_SIZE] = {0};
    unsigned char dataE[RSA_2048_E_BYTE_SIZE] = {0};
    unsigned char dataD[RSA_2048_D_BYTE_SIZE] = {0};
    GenerateRsa2048CorrectKeyPairSpec(dataN, dataE, dataD, &rsaPairSpec);

    HcfAsyKeyGeneratorBySpec *generator = nullptr;
    HcfResult res = HcfAsyKeyGeneratorBySpecCreate(reinterpret_cast<HcfAsyKeyParamsSpec *>(&rsaPairSpec), &generator);
    EXPECT_EQ(res, HCF_SUCCESS);
    HcfKeyPair *keyPair = nullptr;
    res = generator->generateKeyPair(generator, &keyPair);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(keyPair, nullptr);

    HcfCipher *cipher = nullptr;
    HcfBlob retBlob = { .data = nullptr, .len = 0 };
    res = HcfCipherCreate("RSA|PKCS1_OAEP|SHA256|MGF1_SHA256", &cipher);
    EXPECT_EQ(res, HCF_SUCCESS);
    res = cipher->setCipherSpecUint8Array(nullptr, OAEP_MD_NAME_STR, retBlob);
    EXPECT_NE(res, HCF_SUCCESS);

    HcfObjDestroy(cipher);

    HcfObjDestroy(keyPair);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoRsaCipherSubTest, CryptoRsaCipherTest020, TestSize.Level0)
{
    HcfRsaKeyPairParamsSpec rsaPairSpec = {};
    unsigned char dataN[RSA_2048_N_BYTE_SIZE] = {0};
    unsigned char dataE[RSA_2048_E_BYTE_SIZE] = {0};
    unsigned char dataD[RSA_2048_D_BYTE_SIZE] = {0};
    GenerateRsa2048CorrectKeyPairSpec(dataN, dataE, dataD, &rsaPairSpec);

    HcfAsyKeyGeneratorBySpec *generator = nullptr;
    HcfResult res = HcfAsyKeyGeneratorBySpecCreate(reinterpret_cast<HcfAsyKeyParamsSpec *>(&rsaPairSpec), &generator);
    EXPECT_EQ(res, HCF_SUCCESS);
    HcfKeyPair *keyPair = nullptr;
    res = generator->generateKeyPair(generator, &keyPair);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(keyPair, nullptr);

    HcfCipher *cipher = nullptr;
    HcfBlob retBlob = { .data = nullptr, .len = 0 };
    res = HcfCipherCreate("RSA|PKCS1_OAEP|SHA256|MGF1_SHA256", &cipher);
    EXPECT_EQ(res, HCF_SUCCESS);
    res = cipher->setCipherSpecUint8Array(cipher, OAEP_MD_NAME_STR, retBlob);
    EXPECT_NE(res, HCF_SUCCESS);

    HcfObjDestroy(cipher);

    HcfObjDestroy(keyPair);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoRsaCipherSubTest, CryptoRsaCipherTest021, TestSize.Level0)
{
    HcfRsaKeyPairParamsSpec rsaPairSpec = {};
    unsigned char dataN[RSA_2048_N_BYTE_SIZE] = {0};
    unsigned char dataE[RSA_2048_E_BYTE_SIZE] = {0};
    unsigned char dataD[RSA_2048_D_BYTE_SIZE] = {0};
    GenerateRsa2048CorrectKeyPairSpec(dataN, dataE, dataD, &rsaPairSpec);

    HcfAsyKeyGeneratorBySpec *generator = nullptr;
    HcfResult res = HcfAsyKeyGeneratorBySpecCreate(reinterpret_cast<HcfAsyKeyParamsSpec *>(&rsaPairSpec), &generator);
    EXPECT_EQ(res, HCF_SUCCESS);
    HcfKeyPair *keyPair = nullptr;
    res = generator->generateKeyPair(generator, &keyPair);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(keyPair, nullptr);

    HcfCipher *cipher = nullptr;
    HcfBlob retBlob = { .data = nullptr, .len = 0 };
    res = HcfCipherCreate("RSA|PKCS1_OAEP|SHA256|MGF1_SHA256", &cipher);
    EXPECT_EQ(res, HCF_SUCCESS);
    res = cipher->setCipherSpecUint8Array(reinterpret_cast<HcfCipher *>(&g_obj), OAEP_MGF1_PSRC_UINT8ARR, retBlob);
    EXPECT_NE(res, HCF_SUCCESS);

    HcfObjDestroy(cipher);

    HcfObjDestroy(keyPair);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoRsaCipherSubTest, CryptoRsaCipherTest022, TestSize.Level0)
{
    HcfRsaKeyPairParamsSpec rsaPairSpec = {};
    unsigned char dataN[RSA_2048_N_BYTE_SIZE] = {0};
    unsigned char dataE[RSA_2048_E_BYTE_SIZE] = {0};
    unsigned char dataD[RSA_2048_D_BYTE_SIZE] = {0};
    GenerateRsa2048CorrectKeyPairSpec(dataN, dataE, dataD, &rsaPairSpec);

    HcfAsyKeyGeneratorBySpec *generator = nullptr;
    HcfResult res = HcfAsyKeyGeneratorBySpecCreate(reinterpret_cast<HcfAsyKeyParamsSpec *>(&rsaPairSpec), &generator);
    EXPECT_EQ(res, HCF_SUCCESS);
    HcfKeyPair *keyPair = nullptr;
    res = generator->generateKeyPair(generator, &keyPair);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(keyPair, nullptr);

    HcfCipher *cipher = nullptr;
    HcfBlob retBlob = { .data = nullptr, .len = 0 };
    res = HcfCipherCreate("RSA|PKCS1|SHA256", &cipher);
    EXPECT_EQ(res, HCF_SUCCESS);
    res = cipher->setCipherSpecUint8Array(cipher, OAEP_MGF1_PSRC_UINT8ARR, retBlob);
    EXPECT_NE(res, HCF_SUCCESS);

    HcfObjDestroy(cipher);

    HcfObjDestroy(keyPair);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoRsaCipherSubTest, CryptoRsaCipherTest023, TestSize.Level0)
{
    HcfCipher *cipher = nullptr;
    HcfResult res = HcfCipherCreate("RSA|PKCS1|SHA256", &cipher);
    EXPECT_EQ(res, HCF_SUCCESS);
    res = cipher->update(cipher, nullptr, nullptr);
    EXPECT_NE(res, HCF_SUCCESS);

    HcfObjDestroy(cipher);
}

HWTEST_F(CryptoRsaCipherSubTest, CryptoRsaCipherTest024, TestSize.Level0)
{
    HcfCipher *cipher = nullptr;
    HcfResult res = HcfCipherCreate("RSA|PKCS1|SHA256", &cipher);
    EXPECT_EQ(res, HCF_SUCCESS);
    HcfBlob tmp = { .data = nullptr, .len = 0 };
    res = cipher->update(cipher, &tmp, nullptr);
    EXPECT_NE(res, HCF_SUCCESS);

    HcfObjDestroy(cipher);
}

// spi test
// create
HWTEST_F(CryptoRsaCipherSubTest, CryptoRsaCipherTest025, TestSize.Level0)
{
    HcfCipherGeneratorSpi *spiObj = nullptr;
    HcfResult res = HcfCipherRsaCipherSpiCreate(nullptr, &spiObj);

    ASSERT_NE(res, HCF_SUCCESS);
    ASSERT_EQ(spiObj, nullptr);
}

HWTEST_F(CryptoRsaCipherSubTest, CryptoRsaCipherTest026, TestSize.Level0)
{
    HcfCipherGeneratorSpi *spiObj = nullptr;
    HcfResult res = HcfCipherRsaCipherSpiCreate(nullptr, nullptr);

    ASSERT_NE(res, HCF_SUCCESS);
    ASSERT_EQ(spiObj, nullptr);
}

HWTEST_F(CryptoRsaCipherSubTest, CryptoRsaCipherTest027, TestSize.Level0)
{
    CipherAttr params = {
        .algo = HCF_ALG_ECC,
        .mode = HCF_ALG_MODE_NONE,
        .paddingMode = HCF_OPENSSL_RSA_PKCS1_PADDING,
        .md = HCF_OPENSSL_DIGEST_SHA256,
        .mgf1md = HCF_OPENSSL_DIGEST_SHA256,
    };
    HcfCipherGeneratorSpi *spiObj = nullptr;
    HcfResult res = HcfCipherRsaCipherSpiCreate(&params, &spiObj);

    ASSERT_NE(res, HCF_SUCCESS);
    ASSERT_EQ(spiObj, nullptr);
}

HWTEST_F(CryptoRsaCipherSubTest, CryptoRsaCipherTest028, TestSize.Level0)
{
    CipherAttr params = {
        .algo = HCF_ALG_RSA,
        .mode = HCF_ALG_MODE_NONE,
        .paddingMode = HCF_OPENSSL_RSA_PSS_PADDING,
        .md = HCF_OPENSSL_DIGEST_SHA256,
        .mgf1md = HCF_OPENSSL_DIGEST_SHA256,
    };
    HcfCipherGeneratorSpi *spiObj = nullptr;
    HcfResult res = HcfCipherRsaCipherSpiCreate(&params, &spiObj);

    ASSERT_NE(res, HCF_SUCCESS);
    ASSERT_EQ(spiObj, nullptr);
}

// init
HWTEST_F(CryptoRsaCipherSubTest, CryptoRsaCipherTest029, TestSize.Level0)
{
    CipherAttr params = {
        .algo = HCF_ALG_RSA,
        .mode = HCF_ALG_MODE_NONE,
        .paddingMode = HCF_OPENSSL_RSA_PKCS1_PADDING,
        .md = HCF_OPENSSL_DIGEST_SHA256,
        .mgf1md = HCF_OPENSSL_DIGEST_SHA256,
    };
    HcfCipherGeneratorSpi *spiObj = nullptr;
    HcfResult res = HcfCipherRsaCipherSpiCreate(&params, &spiObj);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(spiObj, nullptr);

    res = spiObj->init(nullptr, ENCRYPT_MODE, nullptr, nullptr);
    ASSERT_EQ(res, HCF_INVALID_PARAMS);

    HcfObjDestroy(spiObj);
}

HWTEST_F(CryptoRsaCipherSubTest, CryptoRsaCipherTest030, TestSize.Level0)
{
    CipherAttr params = {
        .algo = HCF_ALG_RSA,
        .mode = HCF_ALG_MODE_NONE,
        .paddingMode = HCF_OPENSSL_RSA_PKCS1_PADDING,
        .md = HCF_OPENSSL_DIGEST_SHA256,
        .mgf1md = HCF_OPENSSL_DIGEST_SHA256,
    };
    HcfCipherGeneratorSpi *spiObj = nullptr;
    HcfResult res = HcfCipherRsaCipherSpiCreate(&params, &spiObj);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(spiObj, nullptr);

    res = spiObj->init(spiObj, ENCRYPT_MODE, nullptr, nullptr);
    ASSERT_EQ(res, HCF_INVALID_PARAMS);

    HcfObjDestroy(spiObj);
}

HWTEST_F(CryptoRsaCipherSubTest, CryptoRsaCipherTest031, TestSize.Level0)
{
    HcfRsaKeyPairParamsSpec rsaPairSpec = {};
    unsigned char dataN[RSA_2048_N_BYTE_SIZE] = {0};
    unsigned char dataE[RSA_2048_E_BYTE_SIZE] = {0};
    unsigned char dataD[RSA_2048_D_BYTE_SIZE] = {0};
    GenerateRsa2048CorrectKeyPairSpec(dataN, dataE, dataD, &rsaPairSpec);

    HcfAsyKeyGeneratorBySpec *generator = nullptr;
    HcfResult res = HcfAsyKeyGeneratorBySpecCreate(reinterpret_cast<HcfAsyKeyParamsSpec *>(&rsaPairSpec), &generator);
    EXPECT_EQ(res, HCF_SUCCESS);
    HcfKeyPair *keyPair = nullptr;
    res = generator->generateKeyPair(generator, &keyPair);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(keyPair, nullptr);

    CipherAttr params = {
        .algo = HCF_ALG_RSA,
        .mode = HCF_ALG_MODE_NONE,
        .paddingMode = HCF_OPENSSL_RSA_PKCS1_PADDING,
        .md = HCF_OPENSSL_DIGEST_SHA256,
        .mgf1md = HCF_OPENSSL_DIGEST_SHA256,
    };
    HcfCipherGeneratorSpi *spiObj = nullptr;
    res = HcfCipherRsaCipherSpiCreate(&params, &spiObj);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(spiObj, nullptr);

    res = spiObj->init(reinterpret_cast<HcfCipherGeneratorSpi *>(&g_obj),
        ENCRYPT_MODE, reinterpret_cast<HcfKey *>(keyPair->priKey), nullptr);
    ASSERT_EQ(res, HCF_INVALID_PARAMS);

    HcfObjDestroy(keyPair);
    HcfObjDestroy(generator);
    HcfObjDestroy(spiObj);
}

// destroy
HWTEST_F(CryptoRsaCipherSubTest, CryptoRsaCipherTest032, TestSize.Level0)
{
    CipherAttr params = {
        .algo = HCF_ALG_RSA,
        .mode = HCF_ALG_MODE_NONE,
        .paddingMode = HCF_OPENSSL_RSA_PKCS1_PADDING,
        .md = HCF_OPENSSL_DIGEST_SHA256,
        .mgf1md = HCF_OPENSSL_DIGEST_SHA256,
    };
    HcfCipherGeneratorSpi *spiObj = nullptr;
    HcfResult res = HcfCipherRsaCipherSpiCreate(&params, &spiObj);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(spiObj, nullptr);

    spiObj->base.destroy(nullptr);
    ASSERT_NE(spiObj, nullptr);

    HcfObjDestroy(spiObj);
}

HWTEST_F(CryptoRsaCipherSubTest, CryptoRsaCipherTest033, TestSize.Level0)
{
    CipherAttr params = {
        .algo = HCF_ALG_RSA,
        .mode = HCF_ALG_MODE_NONE,
        .paddingMode = HCF_OPENSSL_RSA_PKCS1_PADDING,
        .md = HCF_OPENSSL_DIGEST_SHA256,
        .mgf1md = HCF_OPENSSL_DIGEST_SHA256,
    };
    HcfCipherGeneratorSpi *spiObj = nullptr;
    HcfResult res = HcfCipherRsaCipherSpiCreate(&params, &spiObj);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(spiObj, nullptr);

    spiObj->base.destroy(&g_obj);
    ASSERT_NE(spiObj, nullptr);

    HcfObjDestroy(spiObj);
}

// doFinal
HWTEST_F(CryptoRsaCipherSubTest, CryptoRsaCipherTest034, TestSize.Level0)
{
    CipherAttr params = {
        .algo = HCF_ALG_RSA,
        .mode = HCF_ALG_MODE_NONE,
        .paddingMode = HCF_OPENSSL_RSA_PKCS1_PADDING,
        .md = HCF_OPENSSL_DIGEST_SHA256,
        .mgf1md = HCF_OPENSSL_DIGEST_SHA256,
    };
    HcfCipherGeneratorSpi *spiObj = nullptr;
    HcfResult res = HcfCipherRsaCipherSpiCreate(&params, &spiObj);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(spiObj, nullptr);

    res = spiObj->doFinal(nullptr, nullptr, nullptr);
    ASSERT_EQ(res, HCF_INVALID_PARAMS);

    HcfObjDestroy(spiObj);
}

HWTEST_F(CryptoRsaCipherSubTest, CryptoRsaCipherTest035, TestSize.Level0)
{
    CipherAttr params = {
        .algo = HCF_ALG_RSA,
        .mode = HCF_ALG_MODE_NONE,
        .paddingMode = HCF_OPENSSL_RSA_PKCS1_PADDING,
        .md = HCF_OPENSSL_DIGEST_SHA256,
        .mgf1md = HCF_OPENSSL_DIGEST_SHA256,
    };
    HcfCipherGeneratorSpi *spiObj = nullptr;
    HcfResult res = HcfCipherRsaCipherSpiCreate(&params, &spiObj);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(spiObj, nullptr);

    res = spiObj->doFinal(spiObj, nullptr, nullptr);
    ASSERT_EQ(res, HCF_INVALID_PARAMS);

    HcfObjDestroy(spiObj);
}

HWTEST_F(CryptoRsaCipherSubTest, CryptoRsaCipherTest036, TestSize.Level0)
{
    uint8_t plan[] = "this is rsa cipher test!\0";
    CipherAttr params = {
        .algo = HCF_ALG_RSA,
        .mode = HCF_ALG_MODE_NONE,
        .paddingMode = HCF_OPENSSL_RSA_PKCS1_PADDING,
        .md = HCF_OPENSSL_DIGEST_SHA256,
        .mgf1md = HCF_OPENSSL_DIGEST_SHA256,
    };
    HcfCipherGeneratorSpi *spiObj = nullptr;
    HcfResult res = HcfCipherRsaCipherSpiCreate(&params, &spiObj);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(spiObj, nullptr);

    HcfBlob input = { .data = reinterpret_cast<uint8_t *>(plan),
        .len = strlen(reinterpret_cast<char *>(plan)) };
    res = spiObj->doFinal(spiObj, &input, nullptr);
    ASSERT_EQ(res, HCF_INVALID_PARAMS);

    HcfObjDestroy(spiObj);
}


HWTEST_F(CryptoRsaCipherSubTest, CryptoRsaCipherTest037, TestSize.Level0)
{
    uint8_t plan[] = "this is rsa cipher test!\0";
    CipherAttr params = {
        .algo = HCF_ALG_RSA,
        .mode = HCF_ALG_MODE_NONE,
        .paddingMode = HCF_OPENSSL_RSA_PKCS1_PADDING,
        .md = HCF_OPENSSL_DIGEST_SHA256,
        .mgf1md = HCF_OPENSSL_DIGEST_SHA256,
    };
    HcfCipherGeneratorSpi *spiObj = nullptr;
    HcfResult res = HcfCipherRsaCipherSpiCreate(&params, &spiObj);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(spiObj, nullptr);

    HcfBlob input = { .data = reinterpret_cast<uint8_t *>(plan),
        .len = strlen(reinterpret_cast<char *>(plan)) };
    HcfBlob output = { .data = nullptr, .len = 0 };
    res = spiObj->doFinal(reinterpret_cast<HcfCipherGeneratorSpi *>(&g_obj), &input, &output);
    ASSERT_EQ(res, HCF_INVALID_PARAMS);

    HcfObjDestroy(spiObj);
}

HWTEST_F(CryptoRsaCipherSubTest, CryptoRsaCipherTest038, TestSize.Level0)
{
    uint8_t plan[] = "this is rsa cipher test!\0";
    CipherAttr params = {
        .algo = HCF_ALG_RSA,
        .mode = HCF_ALG_MODE_NONE,
        .paddingMode = HCF_OPENSSL_RSA_PKCS1_PADDING,
        .md = HCF_OPENSSL_DIGEST_SHA256,
        .mgf1md = HCF_OPENSSL_DIGEST_SHA256,
    };
    HcfCipherGeneratorSpi *spiObj = nullptr;
    HcfResult res = HcfCipherRsaCipherSpiCreate(&params, &spiObj);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(spiObj, nullptr);

    HcfBlob input = { .data = reinterpret_cast<uint8_t *>(plan),
        .len = strlen(reinterpret_cast<char *>(plan)) };
    HcfBlob output = { .data = nullptr, .len = 0 };
    res = spiObj->doFinal(spiObj, &input, &output);
    ASSERT_EQ(res, HCF_INVALID_PARAMS);

    HcfObjDestroy(spiObj);
}
}
