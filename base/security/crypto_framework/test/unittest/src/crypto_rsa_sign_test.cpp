/*
 * Copyright (C) 2022-2023 Huawei Device Co., Ltd.
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
#include "cstring"
#include "securec.h"
#include "asy_key_generator.h"
#include "blob.h"
#include "detailed_rsa_key_params.h"
#include "memory.h"
#include "openssl_common.h"
#include "signature.h"

using namespace std;
using namespace testing::ext;

namespace {
class CryptoRsaSignTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp();
    void TearDown();
};

void CryptoRsaSignTest::SetUp() {}
void CryptoRsaSignTest::TearDown() {}
void CryptoRsaSignTest::SetUpTestCase() {}
void CryptoRsaSignTest::TearDownTestCase() {}

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
// check pss salt len in PSS padding
const char *g_sha256MdName = "SHA256";
const char *g_mgf1Name = "MGF1";
constexpr int32_t PSS_INVLAID_SALTLEN = -5;
constexpr int32_t PSS_NORMAL_SALTLEN = 32;
constexpr int32_t PSS_TRAILER_FIELD_LEN = 1;
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

static void GenerateRsa2048CorrectPubKeySpec(unsigned char *dataN, unsigned char *dataE,
    HcfRsaPubKeyParamsSpec *returnPubSpec)
{
    HcfRsaCommParamsSpec rsaCommSpec = {};
    GenerateRsa2048CorrectCommonKeySpec(dataN, &rsaCommSpec);
    RemoveLastChar(CORRECT_E, dataE, RSA_2048_E_BYTE_SIZE);
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
// HcfSignCreate correct_case
HWTEST_F(CryptoRsaSignTest, CryptoRsaSignTest100, TestSize.Level0)
{
    HcfResult res = HCF_SUCCESS;
    HcfSign *sign = nullptr;
    res = HcfSignCreate("RSA1024|PKCS1|MD5", &sign);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(sign, nullptr);
    EXPECT_NE(sign->base.getClass(), nullptr);
    EXPECT_NE(sign->base.destroy, nullptr);
    EXPECT_NE(sign->init, nullptr);
    EXPECT_NE(sign->update, nullptr);
    EXPECT_NE(sign->sign, nullptr);
    HcfObjDestroy(sign);
}

HWTEST_F(CryptoRsaSignTest, CryptoRsaSignTest110, TestSize.Level0)
{
    HcfResult res = HCF_SUCCESS;
    HcfSign *sign = nullptr;
    res = HcfSignCreate("RSA1024|PKCS1|SHA1", &sign);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(sign, nullptr);
    EXPECT_NE(sign->base.getClass(), nullptr);
    EXPECT_NE(sign->base.destroy, nullptr);
    EXPECT_NE(sign->init, nullptr);
    EXPECT_NE(sign->update, nullptr);
    EXPECT_NE(sign->sign, nullptr);
    HcfObjDestroy(sign);
}

HWTEST_F(CryptoRsaSignTest, CryptoRsaSignTest120, TestSize.Level0)
{
    HcfResult res = HCF_SUCCESS;
    HcfSign *sign = nullptr;
    res = HcfSignCreate("RSA1024|PKCS1|SHA256", &sign);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(sign, nullptr);
    EXPECT_NE(sign->base.getClass(), nullptr);
    EXPECT_NE(sign->base.destroy, nullptr);
    EXPECT_NE(sign->init, nullptr);
    EXPECT_NE(sign->update, nullptr);
    EXPECT_NE(sign->sign, nullptr);
    HcfObjDestroy(sign);
}

HWTEST_F(CryptoRsaSignTest, CryptoRsaSignTest130, TestSize.Level0)
{
    HcfResult res = HCF_SUCCESS;
    HcfSign *sign = nullptr;
    res = HcfSignCreate("RSA1024|PKCS1|SHA512", &sign);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(sign, nullptr);
    EXPECT_NE(sign->base.getClass(), nullptr);
    EXPECT_NE(sign->base.destroy, nullptr);
    EXPECT_NE(sign->init, nullptr);
    EXPECT_NE(sign->update, nullptr);
    EXPECT_NE(sign->sign, nullptr);
    HcfObjDestroy(sign);
}

HWTEST_F(CryptoRsaSignTest, CryptoRsaSignTest140, TestSize.Level0)
{
    HcfResult res = HCF_SUCCESS;
    HcfSign *sign = nullptr;
    res = HcfSignCreate("RSA1024|PSS|SHA1|MGF1_SHA1", &sign);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(sign, nullptr);
    EXPECT_NE(sign->base.getClass(), nullptr);
    EXPECT_NE(sign->base.destroy, nullptr);
    EXPECT_NE(sign->init, nullptr);
    EXPECT_NE(sign->update, nullptr);
    EXPECT_NE(sign->sign, nullptr);
    HcfObjDestroy(sign);
}

HWTEST_F(CryptoRsaSignTest, CryptoRsaSignTest150, TestSize.Level0)
{
    HcfResult res = HCF_SUCCESS;
    HcfSign *sign = nullptr;
    res = HcfSignCreate("RSA1024|PSS|SHA256|MGF1_SHA512", &sign);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(sign, nullptr);
    EXPECT_NE(sign->base.getClass(), nullptr);
    EXPECT_NE(sign->base.destroy, nullptr);
    EXPECT_NE(sign->init, nullptr);
    EXPECT_NE(sign->update, nullptr);
    EXPECT_NE(sign->sign, nullptr);
    HcfObjDestroy(sign);
}

HWTEST_F(CryptoRsaSignTest, CryptoRsaSignTest160, TestSize.Level0)
{
    HcfResult res = HCF_SUCCESS;
    HcfSign *sign = nullptr;
    res = HcfSignCreate("RSA1024|PSS|SHA256|MGF1_SHA256", &sign);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(sign, nullptr);
    EXPECT_NE(sign->base.getClass(), nullptr);
    EXPECT_NE(sign->base.destroy, nullptr);
    EXPECT_NE(sign->init, nullptr);
    EXPECT_NE(sign->update, nullptr);
    EXPECT_NE(sign->sign, nullptr);
    HcfObjDestroy(sign);
}

// HcfSignCreate Incorrect case
HWTEST_F(CryptoRsaSignTest, CryptoRsaSignTest200, TestSize.Level0)
{
    HcfResult res = HCF_SUCCESS;
    HcfSign *sign = nullptr;
    res = HcfSignCreate("RSA1024|PSSaa|SHA256|MGF1_SHA256", &sign);
    EXPECT_NE(res, HCF_SUCCESS);
    EXPECT_EQ(sign, nullptr);
}

HWTEST_F(CryptoRsaSignTest, CryptoRsaSignTest210, TestSize.Level0)
{
    HcfResult res = HCF_SUCCESS;
    HcfSign *sign = nullptr;
    res = HcfSignCreate(nullptr, &sign);
    EXPECT_NE(res, HCF_SUCCESS);
    EXPECT_EQ(sign, nullptr);
}

HWTEST_F(CryptoRsaSignTest, CryptoRsaSignTest220, TestSize.Level0)
{
    HcfResult res = HCF_SUCCESS;
    HcfSign *sign = nullptr;
    res = HcfSignCreate("RSA1024|PSS|SHA256|MGF1_SHA256|123123123123123123212312312321"
        "123123123123213asdasdasdasdasdasdasdasdasdasdasdasdasdsasdasds12", &sign);
    EXPECT_NE(res, HCF_SUCCESS);
    EXPECT_EQ(sign, nullptr);
}

HWTEST_F(CryptoRsaSignTest, CryptoRsaSignTest230, TestSize.Level0)
{
    HcfResult res = HCF_SUCCESS;
    HcfSign *sign = nullptr;
    res = HcfSignCreate("RSA1024|PSS|SHA256aa|MGF1_SHA256", &sign);
    EXPECT_NE(res, HCF_SUCCESS);
    EXPECT_EQ(sign, nullptr);
}

HWTEST_F(CryptoRsaSignTest, CryptoRsaSignTest240, TestSize.Level0)
{
    HcfResult res = HCF_SUCCESS;
    HcfSign *sign = nullptr;
    res = HcfSignCreate("RSA1024|PSS|SHA256aa|MGF1_SHA256asdasdas", &sign);
    EXPECT_NE(res, HCF_SUCCESS);
    EXPECT_EQ(sign, nullptr);
}

HWTEST_F(CryptoRsaSignTest, CryptoRsaSignTest250, TestSize.Level0)
{
    HcfResult res = HCF_SUCCESS;
    HcfSign *sign = nullptr;
    res = HcfSignCreate("RSA1024|PSS|SHA256aa|MGF1_SHA256", &sign);
    EXPECT_NE(res, HCF_SUCCESS);
    EXPECT_EQ(sign, nullptr);
}

HWTEST_F(CryptoRsaSignTest, CryptoRsaSignTest260, TestSize.Level0)
{
    HcfResult res = HCF_SUCCESS;
    res = HcfSignCreate("RSA1024|PSS|SHA256aa|MGF1_SHA256", nullptr);
    EXPECT_NE(res, HCF_SUCCESS);
}

// incorrect case : init signer with nullptr private key.
HWTEST_F(CryptoRsaSignTest, CryptoRsaSignTest270, TestSize.Level0)
{
    HcfResult res = HCF_SUCCESS;
    HcfSign *sign = nullptr;
    res = HcfSignCreate("RSA1024|PSS|SHA256|MGF1_SHA256", &sign);
    EXPECT_EQ(res, HCF_SUCCESS);

    res = sign->init(sign, nullptr, nullptr);
    EXPECT_NE(res, HCF_SUCCESS);

    HcfObjDestroy(sign);
}

// incorrect case : init signer with public Key.
HWTEST_F(CryptoRsaSignTest, CryptoRsaSignTest280, TestSize.Level0)
{
    HcfResult res = HCF_SUCCESS;
    HcfAsyKeyGenerator *generator = nullptr;
    res = HcfAsyKeyGeneratorCreate("RSA768|PRIMES_2", &generator);
    HcfKeyPair *keyPair = nullptr;
    res = generator->generateKeyPair(generator, nullptr, &keyPair);
    EXPECT_EQ(res, HCF_SUCCESS);

    HcfSign *sign = nullptr;
    res = HcfSignCreate("RSA1024|PSS|SHA256|MGF1_SHA256", &sign);
    EXPECT_EQ(res, HCF_SUCCESS);

    HcfPubKey *pubKey = keyPair->pubKey;

    res = sign->init(sign, nullptr, (HcfPriKey *)pubKey);
    EXPECT_NE(res, HCF_SUCCESS);

    HcfObjDestroy(sign);
    HcfObjDestroy(generator);
    HcfObjDestroy(keyPair);
}

// incorrect case : use update function before intialize.
HWTEST_F(CryptoRsaSignTest, CryptoRsaSignTest281, TestSize.Level0)
{
    HcfResult res = HCF_SUCCESS;
    HcfSign *sign = nullptr;
    res = HcfSignCreate("RSA1024|PSS|SHA256|MGF1_SHA256", &sign);
    EXPECT_EQ(res, HCF_SUCCESS);

    uint8_t plan[] = "this is rsa verify test.";
    HcfBlob input = {.data = plan, .len = strlen((char *)plan)};
    res = sign->update(sign, &input);
    EXPECT_NE(res, HCF_SUCCESS);

    HcfObjDestroy(sign);
}

// incorrect case : use sign function before intialize.
HWTEST_F(CryptoRsaSignTest, CryptoRsaSignTest290, TestSize.Level0)
{
    HcfResult res = HCF_SUCCESS;

    HcfSign *sign = nullptr;
    res = HcfSignCreate("RSA1024|PSS|SHA256|MGF1_SHA256", &sign);
    EXPECT_EQ(res, HCF_SUCCESS);

    uint8_t plan[] = "this is rsa verify test.";
    HcfBlob input = {.data = plan, .len = strlen((char *)plan)};
    HcfBlob signatureData = {.data = nullptr, .len = 0};
    res = sign->sign(sign, &input, &signatureData);
    EXPECT_NE(res, HCF_SUCCESS);

    HcfObjDestroy(sign);
}

// incorrect case : init with other class (not cipher).
HWTEST_F(CryptoRsaSignTest, CryptoRsaSignTest291, TestSize.Level0)
{
    HcfResult res = HCF_SUCCESS;
    HcfAsyKeyGenerator *generator = nullptr;
    res = HcfAsyKeyGeneratorCreate("RSA1024|PRIMES_2", &generator);
    HcfKeyPair *keyPair = nullptr;
    res = generator->generateKeyPair(generator, nullptr, &keyPair);
    EXPECT_EQ(res, HCF_SUCCESS);

    HcfSign *sign = nullptr;
    res = HcfSignCreate("RSA1024|PSS|SHA256|MGF1_SHA256", &sign);
    EXPECT_EQ(res, HCF_SUCCESS);

    res = sign->init((HcfSign *)generator, nullptr, keyPair->priKey);
    EXPECT_NE(res, HCF_SUCCESS);

    HcfObjDestroy(sign);
    HcfObjDestroy(generator);
    HcfObjDestroy(keyPair);
}

// incorrect case : update with other class (not cipher).
HWTEST_F(CryptoRsaSignTest, CryptoRsaSignTest292, TestSize.Level0)
{
    HcfResult res = HCF_SUCCESS;
    HcfAsyKeyGenerator *generator = nullptr;
    res = HcfAsyKeyGeneratorCreate("RSA1024|PRIMES_2", &generator);
    HcfKeyPair *keyPair = nullptr;
    res = generator->generateKeyPair(generator, nullptr, &keyPair);
    EXPECT_EQ(res, HCF_SUCCESS);

    HcfSign *sign = nullptr;
    res = HcfSignCreate("RSA1024|PSS|SHA256|MGF1_SHA256", &sign);
    EXPECT_EQ(res, HCF_SUCCESS);

    uint8_t plan[] = "this is rsa verify test.";
    HcfBlob input = {.data = plan, .len = strlen((char *)plan)};
    res = sign->update((HcfSign *)generator, &input);
    EXPECT_NE(res, HCF_SUCCESS);

    HcfObjDestroy(sign);
    HcfObjDestroy(generator);
    HcfObjDestroy(keyPair);
}

// incorrect case : sign with other class (not cipher).
HWTEST_F(CryptoRsaSignTest, CryptoRsaSignTest293, TestSize.Level0)
{
    HcfResult res = HCF_SUCCESS;
    HcfAsyKeyGenerator *generator = nullptr;
    res = HcfAsyKeyGeneratorCreate("RSA1024|PRIMES_2", &generator);

    HcfSign *sign = nullptr;
    res = HcfSignCreate("RSA1024|PSS|SHA256|MGF1_SHA256", &sign);
    EXPECT_EQ(res, HCF_SUCCESS);

    HcfBlob input;
    res = sign->sign((HcfSign *)generator, nullptr, &input);
    EXPECT_NE(res, HCF_SUCCESS);

    HcfObjDestroy(sign);
    HcfObjDestroy(generator);
}

// incorrect case : update with nullptr inputBlob.
HWTEST_F(CryptoRsaSignTest, CryptoRsaSignTest294, TestSize.Level0)
{
    HcfResult res = HCF_SUCCESS;
    HcfAsyKeyGenerator *generator = nullptr;
    res = HcfAsyKeyGeneratorCreate("RSA1024|PRIMES_2", &generator);

    HcfSign *sign = nullptr;
    res = HcfSignCreate("RSA1024|PSS|SHA256|MGF1_SHA256", &sign);
    EXPECT_EQ(res, HCF_SUCCESS);

    res = sign->update(sign, nullptr);
    EXPECT_NE(res, HCF_SUCCESS);

    HcfObjDestroy(sign);
    HcfObjDestroy(generator);
}

// incorrect case : sign with nullptr outputBlob.
HWTEST_F(CryptoRsaSignTest, CryptoRsaSignTest295, TestSize.Level0)
{
    HcfResult res = HCF_SUCCESS;
    HcfAsyKeyGenerator *generator = nullptr;
    res = HcfAsyKeyGeneratorCreate("RSA1024|PRIMES_2", &generator);

    HcfSign *sign = nullptr;
    res = HcfSignCreate("RSA1024|PSS|SHA256|MGF1_SHA256", &sign);
    EXPECT_EQ(res, HCF_SUCCESS);

    res = sign->sign(sign, nullptr, nullptr);
    EXPECT_NE(res, HCF_SUCCESS);

    HcfObjDestroy(sign);
    HcfObjDestroy(generator);
}


// correct case: sign and update
HWTEST_F(CryptoRsaSignTest, CryptoRsaSignTest300, TestSize.Level0)
{
    HcfResult res = HCF_SUCCESS;
    uint8_t plan[] = "this is rsa verify test.";
    HcfAsyKeyGenerator *generator = nullptr;
    res = HcfAsyKeyGeneratorCreate("RSA768|PRIMES_2", &generator);
    HcfKeyPair *keyPair = nullptr;
    res = generator->generateKeyPair(generator, nullptr, &keyPair);
    EXPECT_EQ(res, HCF_SUCCESS);

    HcfPriKey *prikey = keyPair->priKey;
    HcfBlob input = {.data = plan, .len = strlen((char *)plan)};
    HcfBlob verifyData = {.data = nullptr, .len = 0};
    HcfSign *sign = nullptr;
    res = HcfSignCreate("RSA768|PKCS1|SHA1", &sign);
    EXPECT_EQ(res, HCF_SUCCESS);
    res = sign->init(sign, nullptr, prikey);
    EXPECT_EQ(res, HCF_SUCCESS);
    res = sign->sign(sign, &input, &verifyData);

    HcfObjDestroy(sign);
    HcfFree(verifyData.data);
    HcfObjDestroy(keyPair);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoRsaSignTest, CryptoRsaSignTest310, TestSize.Level0)
{
    uint8_t plan[] = "this is rsa verify test.";
    HcfAsyKeyGenerator *generator = nullptr;
    HcfResult res = HcfAsyKeyGeneratorCreate("RSA1024|PRIMES_2", &generator);
    HcfKeyPair *keyPair = nullptr;
    res = generator->generateKeyPair(generator, nullptr, &keyPair);
    EXPECT_EQ(res, HCF_SUCCESS);

    HcfPriKey *prikey = keyPair->priKey;
    HcfBlob input = {.data = plan, .len = strlen((char *)plan)};
    HcfBlob verifyData = {.data = nullptr, .len = 0};
    HcfSign *sign = nullptr;
    res = HcfSignCreate("RSA1024|PKCS1|SHA256", &sign);
    EXPECT_EQ(res, HCF_SUCCESS);
    res = sign->init(sign, nullptr, prikey);
    EXPECT_EQ(res, HCF_SUCCESS);
    res = sign->sign(sign, &input, &verifyData);

    HcfObjDestroy(sign);
    HcfFree(verifyData.data);
    HcfObjDestroy(keyPair);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoRsaSignTest, CryptoRsaSignTest320, TestSize.Level0)
{
    uint8_t plan[] = "this is rsa verify test.";
    HcfAsyKeyGenerator *generator = nullptr;
    HcfResult res = HcfAsyKeyGeneratorCreate("RSA2048|PRIMES_2", &generator);
    HcfKeyPair *keyPair = nullptr;
    res = generator->generateKeyPair(generator, nullptr, &keyPair);
    EXPECT_EQ(res, HCF_SUCCESS);

    HcfPriKey *prikey = keyPair->priKey;
    HcfBlob input = {.data = plan, .len = strlen((char *)plan)};
    HcfBlob verifyData = {.data = nullptr, .len = 0};
    HcfSign *sign = nullptr;
    res = HcfSignCreate("RSA2048|PKCS1|SHA256", &sign);
    EXPECT_EQ(res, HCF_SUCCESS);
    res = sign->init(sign, nullptr, prikey);
    EXPECT_EQ(res, HCF_SUCCESS);
    res = sign->sign(sign, &input, &verifyData);

    HcfObjDestroy(sign);
    HcfFree(verifyData.data);
    HcfObjDestroy(keyPair);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoRsaSignTest, CryptoRsaSignTest330, TestSize.Level0)
{
    uint8_t plan[] = "this is rsa verify test.";
    HcfAsyKeyGenerator *generator = nullptr;
    HcfResult res = HcfAsyKeyGeneratorCreate("RSA4096|PRIMES_2", &generator);
    HcfKeyPair *keyPair = nullptr;
    res = generator->generateKeyPair(generator, nullptr, &keyPair);
    EXPECT_EQ(res, HCF_SUCCESS);

    HcfPriKey *prikey = keyPair->priKey;
    HcfBlob input = {.data = plan, .len = strlen((char *)plan)};
    HcfBlob verifyData = {.data = nullptr, .len = 0};
    HcfSign *sign = nullptr;
    res = HcfSignCreate("RSA4096|PKCS1|SHA256", &sign);
    EXPECT_EQ(res, HCF_SUCCESS);
    res = sign->init(sign, nullptr, prikey);
    EXPECT_EQ(res, HCF_SUCCESS);
    res = sign->sign(sign, &input, &verifyData);

    HcfObjDestroy(sign);
    HcfFree(verifyData.data);
    HcfObjDestroy(keyPair);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoRsaSignTest, CryptoRsaSignTest340, TestSize.Level0)
{
    uint8_t plan[] = "this is rsa verify test.";
    HcfAsyKeyGenerator *generator = nullptr;
    HcfResult res = HcfAsyKeyGeneratorCreate("RSA4096|PRIMES_2", &generator);
    HcfKeyPair *keyPair = nullptr;
    res = generator->generateKeyPair(generator, nullptr, &keyPair);
    EXPECT_EQ(res, HCF_SUCCESS);

    HcfPriKey *prikey = keyPair->priKey;
    HcfBlob input = {.data = plan, .len = strlen((char *)plan)};
    HcfBlob verifyData = {.data = nullptr, .len = 0};
    HcfSign *sign = nullptr;
    res = HcfSignCreate("RSA4096|PKCS1|SHA512", &sign);
    EXPECT_EQ(res, HCF_SUCCESS);
    res = sign->init(sign, nullptr, prikey);
    EXPECT_EQ(res, HCF_SUCCESS);
    res = sign->sign(sign, &input, &verifyData);

    HcfObjDestroy(sign);
    HcfFree(verifyData.data);
    HcfObjDestroy(keyPair);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoRsaSignTest, CryptoRsaSignTest350, TestSize.Level0)
{
    uint8_t plan[] = "this is rsa verify test.";
    HcfAsyKeyGenerator *generator = nullptr;
    HcfResult res = HcfAsyKeyGeneratorCreate("RSA1024|PRIMES_2", &generator);
    HcfKeyPair *keyPair = nullptr;
    res = generator->generateKeyPair(generator, nullptr, &keyPair);
    EXPECT_EQ(res, HCF_SUCCESS);

    HcfPriKey *prikey = keyPair->priKey;
    HcfBlob input = {.data = plan, .len = strlen((char *)plan)};
    HcfBlob verifyData = {.data = nullptr, .len = 0};
    HcfSign *sign = nullptr;
    res = HcfSignCreate("RSA1024|PSS|SHA256|MGF1_SHA256", &sign);
    EXPECT_EQ(res, HCF_SUCCESS);
    res = sign->init(sign, nullptr, prikey);
    EXPECT_EQ(res, HCF_SUCCESS);
    res = sign->sign(sign, &input, &verifyData);

    HcfObjDestroy(sign);
    HcfFree(verifyData.data);
    HcfObjDestroy(keyPair);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoRsaSignTest, CryptoRsaSignTest360, TestSize.Level0)
{
    uint8_t plan[] = "this is rsa verify test.";
    HcfAsyKeyGenerator *generator = nullptr;
    HcfResult res = HcfAsyKeyGeneratorCreate("RSA2048|PRIMES_2", &generator);
    HcfKeyPair *keyPair = nullptr;
    res = generator->generateKeyPair(generator, nullptr, &keyPair);
    EXPECT_EQ(res, HCF_SUCCESS);

    HcfPriKey *prikey = keyPair->priKey;
    HcfBlob input = {.data = plan, .len = strlen((char *)plan)};
    HcfBlob verifyData = {.data = nullptr, .len = 0};
    HcfSign *sign = nullptr;
    res = HcfSignCreate("RSA2048|PSS|SHA256|MGF1_SHA256", &sign);
    EXPECT_EQ(res, HCF_SUCCESS);
    res = sign->init(sign, nullptr, prikey);
    EXPECT_EQ(res, HCF_SUCCESS);
    res = sign->sign(sign, &input, &verifyData);

    HcfObjDestroy(sign);
    HcfFree(verifyData.data);
    HcfObjDestroy(keyPair);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoRsaSignTest, CryptoRsaSignTest370, TestSize.Level0)
{
    uint8_t plan[] = "this is rsa verify test.";
    HcfAsyKeyGenerator *generator = nullptr;
    HcfResult res = HcfAsyKeyGeneratorCreate("RSA3072|PRIMES_2", &generator);
    HcfKeyPair *keyPair = nullptr;
    res = generator->generateKeyPair(generator, nullptr, &keyPair);
    EXPECT_EQ(res, HCF_SUCCESS);

    HcfPriKey *prikey = keyPair->priKey;
    HcfBlob input = {.data = plan, .len = strlen((char *)plan)};
    HcfBlob verifyData = {.data = nullptr, .len = 0};
    HcfSign *sign = nullptr;
    res = HcfSignCreate("RSA3072|PSS|SHA256|MGF1_SHA256", &sign);
    EXPECT_EQ(res, HCF_SUCCESS);
    res = sign->init(sign, nullptr, prikey);
    EXPECT_EQ(res, HCF_SUCCESS);
    res = sign->sign(sign, &input, &verifyData);

    HcfObjDestroy(sign);
    HcfFree(verifyData.data);
    HcfObjDestroy(keyPair);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoRsaSignTest, CryptoRsaSignTest380, TestSize.Level0)
{
    uint8_t plan[] = "this is rsa verify test.";
    HcfAsyKeyGenerator *generator = nullptr;
    HcfResult res = HcfAsyKeyGeneratorCreate("RSA4096|PRIMES_2", &generator);
    HcfKeyPair *keyPair = nullptr;
    res = generator->generateKeyPair(generator, nullptr, &keyPair);
    EXPECT_EQ(res, HCF_SUCCESS);

    HcfPriKey *prikey = keyPair->priKey;
    HcfBlob input = {.data = plan, .len = strlen((char *)plan)};
    HcfBlob verifyData = {.data = nullptr, .len = 0};
    HcfSign *sign = nullptr;
    res = HcfSignCreate("RSA4096|PSS|SHA256|MGF1_SHA256", &sign);
    EXPECT_EQ(res, HCF_SUCCESS);
    res = sign->init(sign, nullptr, prikey);
    EXPECT_EQ(res, HCF_SUCCESS);
    res = sign->sign(sign, &input, &verifyData);

    HcfObjDestroy(sign);
    HcfFree(verifyData.data);
    HcfObjDestroy(keyPair);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoRsaSignTest, CryptoRsaSignTest390, TestSize.Level0)
{
    uint8_t plan[] = "this is rsa verify test.";
    HcfAsyKeyGenerator *generator = nullptr;
    HcfResult res = HcfAsyKeyGeneratorCreate("RSA4096|PRIMES_2", &generator);
    HcfKeyPair *keyPair = nullptr;
    res = generator->generateKeyPair(generator, nullptr, &keyPair);
    EXPECT_EQ(res, HCF_SUCCESS);

    HcfPriKey *prikey = keyPair->priKey;
    HcfBlob input = {.data = plan, .len = strlen((char *)plan)};
    HcfBlob verifyData = {.data = nullptr, .len = 0};
    HcfSign *sign = nullptr;
    res = HcfSignCreate("RSA4096|PSS|SHA512|MGF1_SHA256", &sign);
    EXPECT_EQ(res, HCF_SUCCESS);
    res = sign->init(sign, nullptr, prikey);
    EXPECT_EQ(res, HCF_SUCCESS);
    res = sign->sign(sign, &input, &verifyData);

    HcfObjDestroy(sign);
    HcfFree(verifyData.data);
    HcfObjDestroy(keyPair);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoRsaSignTest, CryptoRsaSignTest400, TestSize.Level0)
{
    uint8_t plan[] = "this is rsa verify test.";
    HcfAsyKeyGenerator *generator = nullptr;
    HcfResult res = HcfAsyKeyGeneratorCreate("RSA4096|PRIMES_2", &generator);
    HcfKeyPair *keyPair = nullptr;
    res = generator->generateKeyPair(generator, nullptr, &keyPair);
    EXPECT_EQ(res, HCF_SUCCESS);

    HcfPriKey *prikey = keyPair->priKey;
    HcfBlob input = {.data = plan, .len = strlen((char *)plan)};
    HcfBlob verifyData = {.data = nullptr, .len = 0};
    HcfSign *sign = nullptr;
    res = HcfSignCreate("RSA4096|PSS|SHA1|MGF1_SHA256", &sign);
    EXPECT_EQ(res, HCF_SUCCESS);
    res = sign->init(sign, nullptr, prikey);
    EXPECT_EQ(res, HCF_SUCCESS);
    res = sign->sign(sign, &input, &verifyData);

    HcfObjDestroy(sign);
    HcfFree(verifyData.data);
    HcfObjDestroy(keyPair);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoRsaSignTest, CryptoRsaSignTest410, TestSize.Level0)
{
    uint8_t plan[] = "this is rsa verify test.";
    HcfAsyKeyGenerator *generator = nullptr;
    HcfResult res = HcfAsyKeyGeneratorCreate("RSA4096|PRIMES_2", &generator);
    HcfKeyPair *keyPair = nullptr;
    res = generator->generateKeyPair(generator, nullptr, &keyPair);
    EXPECT_EQ(res, HCF_SUCCESS);

    HcfPriKey *prikey = keyPair->priKey;
    HcfBlob input = {.data = plan, .len = strlen((char *)plan)};
    HcfBlob verifyData = {.data = nullptr, .len = 0};
    HcfSign *sign = nullptr;
    res = HcfSignCreate("RSA4096|PSS|SHA256|MGF1_MD5", &sign);
    EXPECT_EQ(res, HCF_SUCCESS);
    res = sign->init(sign, nullptr, prikey);
    EXPECT_EQ(res, HCF_SUCCESS);
    res = sign->sign(sign, &input, &verifyData);

    HcfObjDestroy(sign);
    HcfFree(verifyData.data);
    HcfObjDestroy(keyPair);
    HcfObjDestroy(generator);
}

// incorrect case: double init sign
HWTEST_F(CryptoRsaSignTest, CryptoRsaSignTest500, TestSize.Level0)
{
    HcfAsyKeyGenerator *generator = nullptr;
    HcfResult res = HcfAsyKeyGeneratorCreate("RSA4096|PRIMES_2", &generator);
    HcfKeyPair *keyPair = nullptr;
    res = generator->generateKeyPair(generator, nullptr, &keyPair);
    EXPECT_EQ(res, HCF_SUCCESS);

    HcfPriKey *prikey = keyPair->priKey;
    HcfSign *sign = nullptr;
    res = HcfSignCreate("RSA4096|PKCS1|SHA512", &sign);
    EXPECT_EQ(res, HCF_SUCCESS);

    res = sign->init(sign, nullptr, prikey);
    EXPECT_EQ(res, HCF_SUCCESS);
    res = sign->init(sign, nullptr, prikey);
    EXPECT_NE(res, HCF_SUCCESS);

    HcfObjDestroy(sign);
    HcfObjDestroy(keyPair);
    HcfObjDestroy(generator);
}

// incorrect case : init signer with key pair's public Key by key pair spec.
HWTEST_F(CryptoRsaSignTest, CryptoRsaSignTest001, TestSize.Level0)
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

    HcfSign *sign = nullptr;
    res = HcfSignCreate("RSA1024|PSS|SHA256|MGF1_SHA256", &sign);
    EXPECT_EQ(res, HCF_SUCCESS);

    HcfPubKey *pubKey = keyPair->pubKey;

    res = sign->init(sign, nullptr, (HcfPriKey *)pubKey);
    EXPECT_NE(res, HCF_SUCCESS);

    HcfObjDestroy(sign);
    HcfObjDestroy(generator);
    HcfObjDestroy(keyPair);
}

// incorrect case : init signer with public Key by key pair spec.
HWTEST_F(CryptoRsaSignTest, CryptoRsaSignTest002, TestSize.Level0)
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

    HcfPubKey *pubKey = nullptr;
    res = generator->generatePubKey(generator, &pubKey);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(pubKey, nullptr);

    HcfSign *sign = nullptr;
    res = HcfSignCreate("RSA1024|PSS|SHA256|MGF1_SHA256", &sign);
    EXPECT_EQ(res, HCF_SUCCESS);

    res = sign->init(sign, nullptr, (HcfPriKey *)pubKey);
    EXPECT_NE(res, HCF_SUCCESS);

    HcfObjDestroy(sign);
    HcfObjDestroy(generator);
    HcfObjDestroy(pubKey);
}

// incorrect case : init signer with public Key by pub key spec.
HWTEST_F(CryptoRsaSignTest, CryptoRsaSignTest003, TestSize.Level0)
{
    HcfRsaPubKeyParamsSpec rsaPubKeySpec = {};
    unsigned char dataN[RSA_2048_N_BYTE_SIZE] = {0};
    unsigned char dataE[RSA_2048_E_BYTE_SIZE] = {0};
    GenerateRsa2048CorrectPubKeySpec(dataN, dataE, &rsaPubKeySpec);
    HcfAsyKeyGeneratorBySpec *generator = nullptr;
    HcfResult res = HcfAsyKeyGeneratorBySpecCreate(reinterpret_cast<HcfAsyKeyParamsSpec *>(&rsaPubKeySpec), &generator);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(generator, nullptr);

    HcfPubKey *pubKey = nullptr;
    res = generator->generatePubKey(generator, &pubKey);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(pubKey, nullptr);

    HcfSign *sign = nullptr;
    res = HcfSignCreate("RSA1024|PSS|SHA256|MGF1_SHA256", &sign);
    EXPECT_EQ(res, HCF_SUCCESS);

    res = sign->init(sign, nullptr, (HcfPriKey *)pubKey);
    EXPECT_NE(res, HCF_SUCCESS);

    HcfObjDestroy(sign);
    HcfObjDestroy(generator);
    HcfObjDestroy(pubKey);
}

// incorrect case : set pss saltLen before init -> correct
HWTEST_F(CryptoRsaSignTest, CryptoRsaSignTest004, TestSize.Level0)
{
    HcfSign *sign = nullptr;
    HcfResult res = HcfSignCreate("RSA2048|PSS|SHA256|MGF1_SHA256", &sign);
    EXPECT_EQ(res, HCF_SUCCESS);

    res = sign->setSignSpecInt(sign, PSS_SALT_LEN_INT, PSS_NORMAL_SALTLEN);
    EXPECT_EQ(res, HCF_SUCCESS);

    HcfObjDestroy(sign);
}

// incorrect case : set invalid pss saltLen
HWTEST_F(CryptoRsaSignTest, CryptoRsaSignTest005, TestSize.Level0)
{
    HcfAsyKeyGenerator *generator = nullptr;
    HcfResult res = HcfAsyKeyGeneratorCreate("RSA2048|PRIMES_2", &generator);
    HcfKeyPair *keyPair = nullptr;
    res = generator->generateKeyPair(generator, nullptr, &keyPair);
    EXPECT_EQ(res, HCF_SUCCESS);

    HcfPriKey *prikey = keyPair->priKey;
    HcfSign *sign = nullptr;
    res = HcfSignCreate("RSA2048|PSS|SHA256|MGF1_SHA256", &sign);
    EXPECT_EQ(res, HCF_SUCCESS);

    res = sign->init(sign, nullptr, prikey);
    EXPECT_EQ(res, HCF_SUCCESS);
    res = sign->setSignSpecInt(sign, PSS_SALT_LEN_INT, PSS_INVLAID_SALTLEN);
    EXPECT_NE(res, HCF_SUCCESS);

    HcfObjDestroy(sign);
    HcfObjDestroy(keyPair);
    HcfObjDestroy(generator);
}

// incorrect case : set invalid pss int item
HWTEST_F(CryptoRsaSignTest, CryptoRsaSignTest006, TestSize.Level0)
{
    HcfAsyKeyGenerator *generator = nullptr;
    HcfResult res = HcfAsyKeyGeneratorCreate("RSA2048|PRIMES_2", &generator);
    HcfKeyPair *keyPair = nullptr;
    res = generator->generateKeyPair(generator, nullptr, &keyPair);
    EXPECT_EQ(res, HCF_SUCCESS);

    HcfPriKey *prikey = keyPair->priKey;
    HcfSign *sign = nullptr;
    res = HcfSignCreate("RSA2048|PSS|SHA256|MGF1_SHA256", &sign);
    EXPECT_EQ(res, HCF_SUCCESS);

    res = sign->init(sign, nullptr, prikey);
    EXPECT_EQ(res, HCF_SUCCESS);
    res = sign->setSignSpecInt(sign, PSS_MD_NAME_STR, PSS_NORMAL_SALTLEN);
    EXPECT_NE(res, HCF_SUCCESS);

    HcfObjDestroy(sign);
    HcfObjDestroy(keyPair);
    HcfObjDestroy(generator);
}

// incorrect case : set pss saltLen when using pkcs1
HWTEST_F(CryptoRsaSignTest, CryptoRsaSignTest007, TestSize.Level0)
{
    HcfAsyKeyGenerator *generator = nullptr;
    HcfResult res = HcfAsyKeyGeneratorCreate("RSA2048|PRIMES_2", &generator);
    HcfKeyPair *keyPair = nullptr;
    res = generator->generateKeyPair(generator, nullptr, &keyPair);
    EXPECT_EQ(res, HCF_SUCCESS);

    HcfPriKey *prikey = keyPair->priKey;
    HcfSign *sign = nullptr;
    res = HcfSignCreate("RSA|PKCS1|SHA512", &sign);
    EXPECT_EQ(res, HCF_SUCCESS);

    res = sign->init(sign, nullptr, prikey);
    EXPECT_EQ(res, HCF_SUCCESS);
    res = sign->setSignSpecInt(sign, PSS_SALT_LEN_INT, PSS_NORMAL_SALTLEN);
    EXPECT_NE(res, HCF_SUCCESS);

    HcfObjDestroy(sign);
    HcfObjDestroy(keyPair);
    HcfObjDestroy(generator);
}

// incorrect case : get pss int before init and set;
HWTEST_F(CryptoRsaSignTest, CryptoRsaSignTest008, TestSize.Level0)
{
    HcfSign *sign = nullptr;
    HcfResult res = HcfSignCreate("RSA2048|PSS|SHA256|MGF1_SHA256", &sign);

    int32_t retInt = 0;
    res = sign->getSignSpecInt(sign, PSS_SALT_LEN_INT, &retInt);
    EXPECT_NE(res, HCF_SUCCESS);

    HcfObjDestroy(sign);
}

// incorrect case : get pss str before init -> correct
HWTEST_F(CryptoRsaSignTest, CryptoRsaSignTest009, TestSize.Level0)
{
    HcfSign *sign = nullptr;
    HcfResult res = HcfSignCreate("RSA2048|PSS|SHA256|MGF1_SHA256", &sign);
    EXPECT_EQ(res, HCF_SUCCESS);

    char *returnStr = nullptr;
    res = sign->getSignSpecString(sign, PSS_MD_NAME_STR, &returnStr);
    EXPECT_EQ(res, HCF_SUCCESS);

    HcfFree(returnStr);
    HcfObjDestroy(sign);
}

// incorrect case : get pss invalid int item
HWTEST_F(CryptoRsaSignTest, CryptoRsaSignTest090, TestSize.Level0)
{
    HcfAsyKeyGenerator *generator = nullptr;
    HcfResult res = HcfAsyKeyGeneratorCreate("RSA2048|PRIMES_2", &generator);
    HcfKeyPair *keyPair = nullptr;
    res = generator->generateKeyPair(generator, nullptr, &keyPair);
    EXPECT_EQ(res, HCF_SUCCESS);

    HcfPriKey *prikey = keyPair->priKey;
    HcfSign *sign = nullptr;
    res = HcfSignCreate("RSA2048|PSS|SHA256|MGF1_SHA256", &sign);
    EXPECT_EQ(res, HCF_SUCCESS);

    res = sign->init(sign, nullptr, prikey);
    EXPECT_EQ(res, HCF_SUCCESS);
    int32_t retInt = 0;
    res = sign->getSignSpecInt(sign, PSS_MD_NAME_STR, &retInt);
    EXPECT_NE(res, HCF_SUCCESS);

    HcfObjDestroy(sign);
    HcfObjDestroy(keyPair);
    HcfObjDestroy(generator);
}

// incorrect case : get pss int item with nullptr sign
HWTEST_F(CryptoRsaSignTest, CryptoRsaSignTest091, TestSize.Level0)
{
    HcfAsyKeyGenerator *generator = nullptr;
    HcfResult res = HcfAsyKeyGeneratorCreate("RSA2048|PRIMES_2", &generator);
    HcfKeyPair *keyPair = nullptr;
    res = generator->generateKeyPair(generator, nullptr, &keyPair);
    EXPECT_EQ(res, HCF_SUCCESS);

    HcfPriKey *prikey = keyPair->priKey;
    HcfSign *sign = nullptr;
    res = HcfSignCreate("RSA2048|PSS|SHA256|MGF1_SHA256", &sign);
    EXPECT_EQ(res, HCF_SUCCESS);

    res = sign->init(sign, nullptr, prikey);
    EXPECT_EQ(res, HCF_SUCCESS);
    int32_t retInt = 0;
    res = sign->getSignSpecInt(nullptr, PSS_SALT_LEN_INT, &retInt);
    EXPECT_NE(res, HCF_SUCCESS);

    HcfObjDestroy(sign);
    HcfObjDestroy(keyPair);
    HcfObjDestroy(generator);
}

// incorrect case : get pss int item with no sign object
HWTEST_F(CryptoRsaSignTest, CryptoRsaSignTest092, TestSize.Level0)
{
    HcfAsyKeyGenerator *generator = nullptr;
    HcfResult res = HcfAsyKeyGeneratorCreate("RSA2048|PRIMES_2", &generator);
    HcfKeyPair *keyPair = nullptr;
    res = generator->generateKeyPair(generator, nullptr, &keyPair);
    EXPECT_EQ(res, HCF_SUCCESS);

    HcfPriKey *prikey = keyPair->priKey;
    HcfSign *sign = nullptr;
    res = HcfSignCreate("RSA2048|PSS|SHA256|MGF1_SHA256", &sign);
    EXPECT_EQ(res, HCF_SUCCESS);

    res = sign->init(sign, nullptr, prikey);
    EXPECT_EQ(res, HCF_SUCCESS);
    int32_t retInt = 0;
    res = sign->getSignSpecInt(reinterpret_cast<HcfSign *>(generator), PSS_SALT_LEN_INT, &retInt);
    EXPECT_NE(res, HCF_SUCCESS);

    HcfObjDestroy(sign);
    HcfObjDestroy(keyPair);
    HcfObjDestroy(generator);
}

// incorrect case : get pss int item with nullptr int
HWTEST_F(CryptoRsaSignTest, CryptoRsaSignTest093, TestSize.Level0)
{
    HcfAsyKeyGenerator *generator = nullptr;
    HcfResult res = HcfAsyKeyGeneratorCreate("RSA2048|PRIMES_2", &generator);
    HcfKeyPair *keyPair = nullptr;
    res = generator->generateKeyPair(generator, nullptr, &keyPair);
    EXPECT_EQ(res, HCF_SUCCESS);

    HcfPriKey *prikey = keyPair->priKey;
    HcfSign *sign = nullptr;
    res = HcfSignCreate("RSA2048|PSS|SHA256|MGF1_SHA256", &sign);
    EXPECT_EQ(res, HCF_SUCCESS);

    res = sign->init(sign, nullptr, prikey);
    EXPECT_EQ(res, HCF_SUCCESS);

    res = sign->getSignSpecInt(sign, PSS_SALT_LEN_INT, nullptr);
    EXPECT_NE(res, HCF_SUCCESS);

    HcfObjDestroy(sign);
    HcfObjDestroy(keyPair);
    HcfObjDestroy(generator);
}

// incorrect case : get pss int item with PKCS1 mode
HWTEST_F(CryptoRsaSignTest, CryptoRsaSignTest094, TestSize.Level0)
{
    HcfAsyKeyGenerator *generator = nullptr;
    HcfResult res = HcfAsyKeyGeneratorCreate("RSA2048|PRIMES_2", &generator);
    HcfKeyPair *keyPair = nullptr;
    res = generator->generateKeyPair(generator, nullptr, &keyPair);
    EXPECT_EQ(res, HCF_SUCCESS);

    HcfPriKey *prikey = keyPair->priKey;
    HcfSign *sign = nullptr;
    res = HcfSignCreate("RSA|PKCS1|SHA1", &sign);
    EXPECT_EQ(res, HCF_SUCCESS);

    res = sign->init(sign, nullptr, prikey);
    EXPECT_EQ(res, HCF_SUCCESS);

    int32_t retInt = 0;
    res = sign->getSignSpecInt(sign, PSS_SALT_LEN_INT, &retInt);
    EXPECT_NE(res, HCF_SUCCESS);

    HcfObjDestroy(sign);
    HcfObjDestroy(keyPair);
    HcfObjDestroy(generator);
}

// incorrect case : get pss invalid string item
HWTEST_F(CryptoRsaSignTest, CryptoRsaSignTest095, TestSize.Level0)
{
    HcfAsyKeyGenerator *generator = nullptr;
    HcfResult res = HcfAsyKeyGeneratorCreate("RSA2048|PRIMES_2", &generator);
    HcfKeyPair *keyPair = nullptr;
    res = generator->generateKeyPair(generator, nullptr, &keyPair);
    EXPECT_EQ(res, HCF_SUCCESS);

    HcfPriKey *prikey = keyPair->priKey;
    HcfSign *sign = nullptr;
    res = HcfSignCreate("RSA2048|PSS|SHA256|MGF1_SHA256", &sign);
    EXPECT_EQ(res, HCF_SUCCESS);

    res = sign->init(sign, nullptr, prikey);
    EXPECT_EQ(res, HCF_SUCCESS);
    char *retStr = nullptr;
    res = sign->getSignSpecString(sign, PSS_SALT_LEN_INT, &retStr);
    EXPECT_NE(res, HCF_SUCCESS);

    HcfObjDestroy(sign);
    HcfObjDestroy(keyPair);
    HcfObjDestroy(generator);
}

// incorrect case : get pss string item with nullptr sign
HWTEST_F(CryptoRsaSignTest, CryptoRsaSignTest096, TestSize.Level0)
{
    HcfAsyKeyGenerator *generator = nullptr;
    HcfResult res = HcfAsyKeyGeneratorCreate("RSA2048|PRIMES_2", &generator);
    HcfKeyPair *keyPair = nullptr;
    res = generator->generateKeyPair(generator, nullptr, &keyPair);
    EXPECT_EQ(res, HCF_SUCCESS);

    HcfPriKey *prikey = keyPair->priKey;
    HcfSign *sign = nullptr;
    res = HcfSignCreate("RSA2048|PSS|SHA256|MGF1_SHA256", &sign);
    EXPECT_EQ(res, HCF_SUCCESS);

    res = sign->init(sign, nullptr, prikey);
    EXPECT_EQ(res, HCF_SUCCESS);
    char *retStr = nullptr;
    res = sign->getSignSpecString(nullptr, PSS_MD_NAME_STR, &retStr);
    EXPECT_NE(res, HCF_SUCCESS);

    HcfObjDestroy(sign);
    HcfObjDestroy(keyPair);
    HcfObjDestroy(generator);
}

// incorrect case : get pss string item with no sign object
HWTEST_F(CryptoRsaSignTest, CryptoRsaSignTest097, TestSize.Level0)
{
    HcfAsyKeyGenerator *generator = nullptr;
    HcfResult res = HcfAsyKeyGeneratorCreate("RSA2048|PRIMES_2", &generator);
    HcfKeyPair *keyPair = nullptr;
    res = generator->generateKeyPair(generator, nullptr, &keyPair);
    EXPECT_EQ(res, HCF_SUCCESS);

    HcfPriKey *prikey = keyPair->priKey;
    HcfSign *sign = nullptr;
    res = HcfSignCreate("RSA2048|PSS|SHA256|MGF1_SHA256", &sign);
    EXPECT_EQ(res, HCF_SUCCESS);

    res = sign->init(sign, nullptr, prikey);
    EXPECT_EQ(res, HCF_SUCCESS);
    char *retStr = nullptr;
    res = sign->getSignSpecString(reinterpret_cast<HcfSign *>(generator), PSS_MD_NAME_STR, &retStr);
    EXPECT_NE(res, HCF_SUCCESS);

    HcfObjDestroy(sign);
    HcfObjDestroy(keyPair);
    HcfObjDestroy(generator);
}

// incorrect case : get pss string item with nullptr int
HWTEST_F(CryptoRsaSignTest, CryptoRsaSignTest098, TestSize.Level0)
{
    HcfAsyKeyGenerator *generator = nullptr;
    HcfResult res = HcfAsyKeyGeneratorCreate("RSA2048|PRIMES_2", &generator);
    HcfKeyPair *keyPair = nullptr;
    res = generator->generateKeyPair(generator, nullptr, &keyPair);
    EXPECT_EQ(res, HCF_SUCCESS);

    HcfPriKey *prikey = keyPair->priKey;
    HcfSign *sign = nullptr;
    res = HcfSignCreate("RSA2048|PSS|SHA256|MGF1_SHA256", &sign);
    EXPECT_EQ(res, HCF_SUCCESS);

    res = sign->init(sign, nullptr, prikey);
    EXPECT_EQ(res, HCF_SUCCESS);

    res = sign->getSignSpecString(sign, PSS_MD_NAME_STR, nullptr);
    EXPECT_NE(res, HCF_SUCCESS);

    HcfObjDestroy(sign);
    HcfObjDestroy(keyPair);
    HcfObjDestroy(generator);
}

// incorrect case : get pss string item with PKCS1 mode
HWTEST_F(CryptoRsaSignTest, CryptoRsaSignTest099, TestSize.Level0)
{
    HcfAsyKeyGenerator *generator = nullptr;
    HcfResult res = HcfAsyKeyGeneratorCreate("RSA2048|PRIMES_2", &generator);
    HcfKeyPair *keyPair = nullptr;
    res = generator->generateKeyPair(generator, nullptr, &keyPair);
    EXPECT_EQ(res, HCF_SUCCESS);

    HcfPriKey *prikey = keyPair->priKey;
    HcfSign *sign = nullptr;
    res = HcfSignCreate("RSA|PKCS1|SHA1", &sign);
    EXPECT_EQ(res, HCF_SUCCESS);

    res = sign->init(sign, nullptr, prikey);
    EXPECT_EQ(res, HCF_SUCCESS);

    char *retStr = nullptr;
    res = sign->getSignSpecString(sign, PSS_MD_NAME_STR, &retStr);
    EXPECT_NE(res, HCF_SUCCESS);

    HcfObjDestroy(sign);
    HcfObjDestroy(keyPair);
    HcfObjDestroy(generator);
}

// correct case: sign and update with spec
// correct case: sign and update with key pair's private key by key pair spec
HWTEST_F(CryptoRsaSignTest, CryptoRsaSignTest010, TestSize.Level0)
{
    uint8_t plan[] = "this is rsa verify test.";
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

    HcfPriKey *prikey = keyPair->priKey;
    HcfBlob input = {.data = plan, .len = strlen((char *)plan)};
    HcfBlob verifyData = {.data = nullptr, .len = 0};
    HcfSign *sign = nullptr;
    res = HcfSignCreate("RSA|PKCS1|SHA1", &sign);
    EXPECT_EQ(res, HCF_SUCCESS);
    res = sign->init(sign, nullptr, prikey);
    EXPECT_EQ(res, HCF_SUCCESS);
    res = sign->sign(sign, &input, &verifyData);

    HcfObjDestroy(sign);
    HcfFree(verifyData.data);
    HcfObjDestroy(keyPair);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoRsaSignTest, CryptoRsaSignTest011, TestSize.Level0)
{
    uint8_t plan[] = "this is rsa verify test.";
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

    HcfPriKey *prikey = keyPair->priKey;
    HcfBlob input = {.data = plan, .len = strlen((char *)plan)};
    HcfBlob verifyData = {.data = nullptr, .len = 0};
    HcfSign *sign = nullptr;
    res = HcfSignCreate("RSA|PKCS1|SHA256", &sign);
    EXPECT_EQ(res, HCF_SUCCESS);
    res = sign->init(sign, nullptr, prikey);
    EXPECT_EQ(res, HCF_SUCCESS);
    res = sign->sign(sign, &input, &verifyData);

    HcfObjDestroy(sign);
    HcfFree(verifyData.data);
    HcfObjDestroy(keyPair);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoRsaSignTest, CryptoRsaSignTest012, TestSize.Level0)
{
    uint8_t plan[] = "this is rsa verify test.";
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

    HcfPriKey *prikey = keyPair->priKey;
    HcfBlob input = {.data = plan, .len = strlen((char *)plan)};
    HcfBlob verifyData = {.data = nullptr, .len = 0};
    HcfSign *sign = nullptr;
    res = HcfSignCreate("RSA|PKCS1|SHA512", &sign);
    EXPECT_EQ(res, HCF_SUCCESS);
    res = sign->init(sign, nullptr, prikey);
    EXPECT_EQ(res, HCF_SUCCESS);
    res = sign->sign(sign, &input, &verifyData);

    HcfObjDestroy(sign);
    HcfFree(verifyData.data);
    HcfObjDestroy(keyPair);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoRsaSignTest, CryptoRsaSignTest013, TestSize.Level0)
{
    uint8_t plan[] = "this is rsa verify test.";
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

    HcfPriKey *prikey = keyPair->priKey;
    HcfBlob input = {.data = plan, .len = strlen((char *)plan)};
    HcfBlob verifyData = {.data = nullptr, .len = 0};
    HcfSign *sign = nullptr;
    res = HcfSignCreate("RSA|PSS|SHA256|MGF1_SHA256", &sign);
    EXPECT_EQ(res, HCF_SUCCESS);
    res = sign->init(sign, nullptr, prikey);
    EXPECT_EQ(res, HCF_SUCCESS);
    res = sign->sign(sign, &input, &verifyData);

    HcfObjDestroy(sign);
    HcfFree(verifyData.data);
    HcfObjDestroy(keyPair);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoRsaSignTest, CryptoRsaSignTest014, TestSize.Level0)
{
    uint8_t plan[] = "this is rsa verify test.";
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

    HcfPriKey *prikey = keyPair->priKey;
    HcfBlob input = {.data = plan, .len = strlen((char *)plan)};
    HcfBlob verifyData = {.data = nullptr, .len = 0};
    HcfSign *sign = nullptr;
    res = HcfSignCreate("RSA|PSS|SHA512|MGF1_SHA256", &sign);
    EXPECT_EQ(res, HCF_SUCCESS);
    res = sign->init(sign, nullptr, prikey);
    EXPECT_EQ(res, HCF_SUCCESS);
    res = sign->sign(sign, &input, &verifyData);

    HcfObjDestroy(sign);
    HcfFree(verifyData.data);
    HcfObjDestroy(keyPair);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoRsaSignTest, CryptoRsaSignTest015, TestSize.Level0)
{
    uint8_t plan[] = "this is rsa verify test.";
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

    HcfPriKey *prikey = keyPair->priKey;
    HcfBlob input = {.data = plan, .len = strlen((char *)plan)};
    HcfBlob verifyData = {.data = nullptr, .len = 0};
    HcfSign *sign = nullptr;
    res = HcfSignCreate("RSA|PSS|SHA1|MGF1_SHA256", &sign);
    EXPECT_EQ(res, HCF_SUCCESS);
    res = sign->init(sign, nullptr, prikey);
    EXPECT_EQ(res, HCF_SUCCESS);
    res = sign->sign(sign, &input, &verifyData);

    HcfObjDestroy(sign);
    HcfFree(verifyData.data);
    HcfObjDestroy(keyPair);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoRsaSignTest, CryptoRsaSignTest016, TestSize.Level0)
{
    uint8_t plan[] = "this is rsa verify test.";
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

    HcfPriKey *prikey = keyPair->priKey;
    HcfBlob input = {.data = plan, .len = strlen((char *)plan)};
    HcfBlob verifyData = {.data = nullptr, .len = 0};
    HcfSign *sign = nullptr;
    res = HcfSignCreate("RSA|PSS|SHA256|MGF1_MD5", &sign);
    EXPECT_EQ(res, HCF_SUCCESS);
    res = sign->init(sign, nullptr, prikey);
    EXPECT_EQ(res, HCF_SUCCESS);
    res = sign->sign(sign, &input, &verifyData);

    HcfObjDestroy(sign);
    HcfFree(verifyData.data);
    HcfObjDestroy(keyPair);
    HcfObjDestroy(generator);
}

// correct case: sign and update with private key by key pair spec and sign RSA
HWTEST_F(CryptoRsaSignTest, CryptoRsaSignTest020, TestSize.Level0)
{
    uint8_t plan[] = "this is rsa verify test.";
    HcfRsaKeyPairParamsSpec rsaPairSpec = {};
    unsigned char dataN[RSA_2048_N_BYTE_SIZE] = {0};
    unsigned char dataE[RSA_2048_E_BYTE_SIZE] = {0};
    unsigned char dataD[RSA_2048_D_BYTE_SIZE] = {0};
    GenerateRsa2048CorrectKeyPairSpec(dataN, dataE, dataD, &rsaPairSpec);

    HcfAsyKeyGeneratorBySpec *generator = nullptr;
    HcfResult res = HcfAsyKeyGeneratorBySpecCreate(reinterpret_cast<HcfAsyKeyParamsSpec *>(&rsaPairSpec), &generator);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(generator, nullptr);

    HcfPriKey *prikey = nullptr;
    res = generator->generatePriKey(generator, &prikey);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(prikey, nullptr);

    HcfBlob input = {.data = plan, .len = strlen((char *)plan)};
    HcfBlob verifyData = {.data = nullptr, .len = 0};
    HcfSign *sign = nullptr;
    res = HcfSignCreate("RSA|PKCS1|SHA1", &sign);
    EXPECT_EQ(res, HCF_SUCCESS);
    res = sign->init(sign, nullptr, prikey);
    EXPECT_EQ(res, HCF_SUCCESS);
    res = sign->sign(sign, &input, &verifyData);

    HcfObjDestroy(sign);
    HcfFree(verifyData.data);
    HcfObjDestroy(prikey);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoRsaSignTest, CryptoRsaSignTest021, TestSize.Level0)
{
    uint8_t plan[] = "this is rsa verify test.";
    HcfRsaKeyPairParamsSpec rsaPairSpec = {};
    unsigned char dataN[RSA_2048_N_BYTE_SIZE] = {0};
    unsigned char dataE[RSA_2048_E_BYTE_SIZE] = {0};
    unsigned char dataD[RSA_2048_D_BYTE_SIZE] = {0};
    GenerateRsa2048CorrectKeyPairSpec(dataN, dataE, dataD, &rsaPairSpec);

    HcfAsyKeyGeneratorBySpec *generator = nullptr;
    HcfResult res = HcfAsyKeyGeneratorBySpecCreate(reinterpret_cast<HcfAsyKeyParamsSpec *>(&rsaPairSpec), &generator);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(generator, nullptr);

    HcfPriKey *prikey = nullptr;
    res = generator->generatePriKey(generator, &prikey);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(prikey, nullptr);

    HcfBlob input = {.data = plan, .len = strlen((char *)plan)};
    HcfBlob verifyData = {.data = nullptr, .len = 0};
    HcfSign *sign = nullptr;
    res = HcfSignCreate("RSA|PKCS1|SHA256", &sign);
    EXPECT_EQ(res, HCF_SUCCESS);
    res = sign->init(sign, nullptr, prikey);
    EXPECT_EQ(res, HCF_SUCCESS);
    res = sign->sign(sign, &input, &verifyData);

    HcfObjDestroy(sign);
    HcfFree(verifyData.data);
    HcfObjDestroy(prikey);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoRsaSignTest, CryptoRsaSignTest022, TestSize.Level0)
{
    uint8_t plan[] = "this is rsa verify test.";
    HcfRsaKeyPairParamsSpec rsaPairSpec = {};
    unsigned char dataN[RSA_2048_N_BYTE_SIZE] = {0};
    unsigned char dataE[RSA_2048_E_BYTE_SIZE] = {0};
    unsigned char dataD[RSA_2048_D_BYTE_SIZE] = {0};
    GenerateRsa2048CorrectKeyPairSpec(dataN, dataE, dataD, &rsaPairSpec);

    HcfAsyKeyGeneratorBySpec *generator = nullptr;
    HcfResult res = HcfAsyKeyGeneratorBySpecCreate(reinterpret_cast<HcfAsyKeyParamsSpec *>(&rsaPairSpec), &generator);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(generator, nullptr);

    HcfPriKey *prikey = nullptr;
    res = generator->generatePriKey(generator, &prikey);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(prikey, nullptr);

    HcfBlob input = {.data = plan, .len = strlen((char *)plan)};
    HcfBlob verifyData = {.data = nullptr, .len = 0};
    HcfSign *sign = nullptr;
    res = HcfSignCreate("RSA|PKCS1|SHA512", &sign);
    EXPECT_EQ(res, HCF_SUCCESS);
    res = sign->init(sign, nullptr, prikey);
    EXPECT_EQ(res, HCF_SUCCESS);
    res = sign->sign(sign, &input, &verifyData);

    HcfObjDestroy(sign);
    HcfFree(verifyData.data);
    HcfObjDestroy(prikey);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoRsaSignTest, CryptoRsaSignTest023, TestSize.Level0)
{
    uint8_t plan[] = "this is rsa verify test.";
    HcfRsaKeyPairParamsSpec rsaPairSpec = {};
    unsigned char dataN[RSA_2048_N_BYTE_SIZE] = {0};
    unsigned char dataE[RSA_2048_E_BYTE_SIZE] = {0};
    unsigned char dataD[RSA_2048_D_BYTE_SIZE] = {0};
    GenerateRsa2048CorrectKeyPairSpec(dataN, dataE, dataD, &rsaPairSpec);

    HcfAsyKeyGeneratorBySpec *generator = nullptr;
    HcfResult res = HcfAsyKeyGeneratorBySpecCreate(reinterpret_cast<HcfAsyKeyParamsSpec *>(&rsaPairSpec), &generator);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(generator, nullptr);

    HcfPriKey *prikey = nullptr;
    res = generator->generatePriKey(generator, &prikey);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(prikey, nullptr);

    HcfBlob input = {.data = plan, .len = strlen((char *)plan)};
    HcfBlob verifyData = {.data = nullptr, .len = 0};
    HcfSign *sign = nullptr;
    res = HcfSignCreate("RSA|PSS|SHA256|MGF1_SHA256", &sign);
    EXPECT_EQ(res, HCF_SUCCESS);
    res = sign->init(sign, nullptr, prikey);
    EXPECT_EQ(res, HCF_SUCCESS);
    res = sign->sign(sign, &input, &verifyData);

    HcfObjDestroy(sign);
    HcfFree(verifyData.data);
    HcfObjDestroy(prikey);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoRsaSignTest, CryptoRsaSignTest024, TestSize.Level0)
{
    uint8_t plan[] = "this is rsa verify test.";
    HcfRsaKeyPairParamsSpec rsaPairSpec = {};
    unsigned char dataN[RSA_2048_N_BYTE_SIZE] = {0};
    unsigned char dataE[RSA_2048_E_BYTE_SIZE] = {0};
    unsigned char dataD[RSA_2048_D_BYTE_SIZE] = {0};
    GenerateRsa2048CorrectKeyPairSpec(dataN, dataE, dataD, &rsaPairSpec);

    HcfAsyKeyGeneratorBySpec *generator = nullptr;
    HcfResult res = HcfAsyKeyGeneratorBySpecCreate(reinterpret_cast<HcfAsyKeyParamsSpec *>(&rsaPairSpec), &generator);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(generator, nullptr);

    HcfPriKey *prikey = nullptr;
    res = generator->generatePriKey(generator, &prikey);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(prikey, nullptr);

    HcfBlob input = {.data = plan, .len = strlen((char *)plan)};
    HcfBlob verifyData = {.data = nullptr, .len = 0};
    HcfSign *sign = nullptr;
    res = HcfSignCreate("RSA|PSS|SHA512|MGF1_SHA256", &sign);
    EXPECT_EQ(res, HCF_SUCCESS);
    res = sign->init(sign, nullptr, prikey);
    EXPECT_EQ(res, HCF_SUCCESS);
    res = sign->sign(sign, &input, &verifyData);

    HcfObjDestroy(sign);
    HcfFree(verifyData.data);
    HcfObjDestroy(prikey);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoRsaSignTest, CryptoRsaSignTest025, TestSize.Level0)
{
    uint8_t plan[] = "this is rsa verify test.";
    HcfRsaKeyPairParamsSpec rsaPairSpec = {};
    unsigned char dataN[RSA_2048_N_BYTE_SIZE] = {0};
    unsigned char dataE[RSA_2048_E_BYTE_SIZE] = {0};
    unsigned char dataD[RSA_2048_D_BYTE_SIZE] = {0};
    GenerateRsa2048CorrectKeyPairSpec(dataN, dataE, dataD, &rsaPairSpec);

    HcfAsyKeyGeneratorBySpec *generator = nullptr;
    HcfResult res = HcfAsyKeyGeneratorBySpecCreate(reinterpret_cast<HcfAsyKeyParamsSpec *>(&rsaPairSpec), &generator);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(generator, nullptr);

    HcfPriKey *prikey = nullptr;
    res = generator->generatePriKey(generator, &prikey);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(prikey, nullptr);

    HcfBlob input = {.data = plan, .len = strlen((char *)plan)};
    HcfBlob verifyData = {.data = nullptr, .len = 0};
    HcfSign *sign = nullptr;
    res = HcfSignCreate("RSA|PSS|SHA1|MGF1_SHA256", &sign);
    EXPECT_EQ(res, HCF_SUCCESS);
    res = sign->init(sign, nullptr, prikey);
    EXPECT_EQ(res, HCF_SUCCESS);
    res = sign->sign(sign, &input, &verifyData);

    HcfObjDestroy(sign);
    HcfFree(verifyData.data);
    HcfObjDestroy(prikey);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoRsaSignTest, CryptoRsaSignTest026, TestSize.Level0)
{
    uint8_t plan[] = "this is rsa verify test.";
    HcfRsaKeyPairParamsSpec rsaPairSpec = {};
    unsigned char dataN[RSA_2048_N_BYTE_SIZE] = {0};
    unsigned char dataE[RSA_2048_E_BYTE_SIZE] = {0};
    unsigned char dataD[RSA_2048_D_BYTE_SIZE] = {0};
    GenerateRsa2048CorrectKeyPairSpec(dataN, dataE, dataD, &rsaPairSpec);

    HcfAsyKeyGeneratorBySpec *generator = nullptr;
    HcfResult res = HcfAsyKeyGeneratorBySpecCreate(reinterpret_cast<HcfAsyKeyParamsSpec *>(&rsaPairSpec), &generator);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(generator, nullptr);

    HcfPriKey *prikey = nullptr;
    res = generator->generatePriKey(generator, &prikey);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(prikey, nullptr);

    HcfBlob input = {.data = plan, .len = strlen((char *)plan)};
    HcfBlob verifyData = {.data = nullptr, .len = 0};
    HcfSign *sign = nullptr;
    res = HcfSignCreate("RSA|PSS|SHA256|MGF1_MD5", &sign);
    EXPECT_EQ(res, HCF_SUCCESS);
    res = sign->init(sign, nullptr, prikey);
    EXPECT_EQ(res, HCF_SUCCESS);
    res = sign->sign(sign, &input, &verifyData);

    HcfObjDestroy(sign);
    HcfFree(verifyData.data);
    HcfObjDestroy(prikey);
    HcfObjDestroy(generator);
}

// correct case: set pss saltLen
HWTEST_F(CryptoRsaSignTest, CryptoRsaSignTest027, TestSize.Level0)
{
    uint8_t plan[] = "this is rsa verify test.";
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

    HcfPriKey *prikey = keyPair->priKey;
    HcfBlob input = {.data = plan, .len = strlen((char *)plan)};
    HcfBlob verifyData = {.data = nullptr, .len = 0};
    HcfSign *sign = nullptr;
    res = HcfSignCreate("RSA|PSS|SHA256|MGF1_SHA256", &sign);
    EXPECT_EQ(res, HCF_SUCCESS);
    res = sign->init(sign, nullptr, prikey);
    EXPECT_EQ(res, HCF_SUCCESS);

    res = sign->setSignSpecInt(sign, PSS_SALT_LEN_INT, PSS_NORMAL_SALTLEN);
    EXPECT_EQ(res, HCF_SUCCESS);
    res = sign->sign(sign, &input, &verifyData);
    EXPECT_EQ(res, HCF_SUCCESS);

    HcfObjDestroy(sign);
    HcfFree(verifyData.data);
    HcfObjDestroy(keyPair);
    HcfObjDestroy(generator);
}

// correct case: get pss saltLen
HWTEST_F(CryptoRsaSignTest, CryptoRsaSignTest028, TestSize.Level0)
{
    uint8_t plan[] = "this is rsa verify test.";
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

    HcfPriKey *prikey = keyPair->priKey;
    HcfBlob input = {.data = plan, .len = strlen((char *)plan)};
    HcfBlob verifyData = {.data = nullptr, .len = 0};
    HcfSign *sign = nullptr;
    res = HcfSignCreate("RSA|PSS|SHA256|MGF1_SHA256", &sign);
    EXPECT_EQ(res, HCF_SUCCESS);
    res = sign->init(sign, nullptr, prikey);
    EXPECT_EQ(res, HCF_SUCCESS);

    res = sign->setSignSpecInt(sign, PSS_SALT_LEN_INT, PSS_NORMAL_SALTLEN);
    EXPECT_EQ(res, HCF_SUCCESS);

    int32_t retInt = 0;
    res = sign->getSignSpecInt(sign, PSS_SALT_LEN_INT, &retInt);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_EQ(retInt, PSS_NORMAL_SALTLEN);

    res = sign->sign(sign, &input, &verifyData);
    EXPECT_EQ(res, HCF_SUCCESS);

    HcfObjDestroy(sign);
    HcfFree(verifyData.data);
    HcfObjDestroy(keyPair);
    HcfObjDestroy(generator);
}

// correct case: get pss trail field len
HWTEST_F(CryptoRsaSignTest, CryptoRsaSignTest029, TestSize.Level0)
{
    uint8_t plan[] = "this is rsa verify test.";
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

    HcfPriKey *prikey = keyPair->priKey;
    HcfBlob input = {.data = plan, .len = strlen((char *)plan)};
    HcfBlob verifyData = {.data = nullptr, .len = 0};
    HcfSign *sign = nullptr;
    res = HcfSignCreate("RSA|PSS|SHA256|MGF1_SHA256", &sign);
    EXPECT_EQ(res, HCF_SUCCESS);
    res = sign->init(sign, nullptr, prikey);
    EXPECT_EQ(res, HCF_SUCCESS);

    int32_t retInt = 0;
    res = sign->getSignSpecInt(sign, PSS_TRAILER_FIELD_INT, &retInt);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_EQ(retInt, PSS_TRAILER_FIELD_LEN);

    res = sign->sign(sign, &input, &verifyData);
    EXPECT_EQ(res, HCF_SUCCESS);

    HcfObjDestroy(sign);
    HcfFree(verifyData.data);
    HcfObjDestroy(keyPair);
    HcfObjDestroy(generator);
}

// correct case: get pss md string
HWTEST_F(CryptoRsaSignTest, CryptoRsaSignTest030, TestSize.Level0)
{
    uint8_t plan[] = "this is rsa verify test.";
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

    HcfPriKey *prikey = keyPair->priKey;
    HcfBlob input = {.data = plan, .len = strlen((char *)plan)};
    HcfBlob verifyData = {.data = nullptr, .len = 0};
    HcfSign *sign = nullptr;
    res = HcfSignCreate("RSA|PSS|SHA256|MGF1_SHA256", &sign);
    EXPECT_EQ(res, HCF_SUCCESS);
    res = sign->init(sign, nullptr, prikey);
    EXPECT_EQ(res, HCF_SUCCESS);

    char *retStr = nullptr;
    res = sign->getSignSpecString(sign, PSS_MD_NAME_STR, &retStr);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_STREQ(g_sha256MdName, retStr);

    res = sign->sign(sign, &input, &verifyData);
    EXPECT_EQ(res, HCF_SUCCESS);

    HcfObjDestroy(sign);
    HcfFree(retStr);
    HcfFree(verifyData.data);
    HcfObjDestroy(keyPair);
    HcfObjDestroy(generator);
}

// correct case: get pss mgf1 string
HWTEST_F(CryptoRsaSignTest, CryptoRsaSignTest031, TestSize.Level0)
{
    uint8_t plan[] = "this is rsa verify test.";
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

    HcfPriKey *prikey = keyPair->priKey;
    HcfBlob input = {.data = plan, .len = strlen((char *)plan)};
    HcfBlob verifyData = {.data = nullptr, .len = 0};
    HcfSign *sign = nullptr;
    res = HcfSignCreate("RSA|PSS|SHA256|MGF1_SHA256", &sign);
    EXPECT_EQ(res, HCF_SUCCESS);
    res = sign->init(sign, nullptr, prikey);
    EXPECT_EQ(res, HCF_SUCCESS);

    char *retStr = nullptr;
    res = sign->getSignSpecString(sign, PSS_MGF_NAME_STR, &retStr);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_STREQ(g_mgf1Name, retStr);

    res = sign->sign(sign, &input, &verifyData);
    EXPECT_EQ(res, HCF_SUCCESS);

    HcfObjDestroy(sign);
    HcfFree(retStr);
    HcfFree(verifyData.data);
    HcfObjDestroy(keyPair);
    HcfObjDestroy(generator);
}

// correct case: get pss mgf1 md string
HWTEST_F(CryptoRsaSignTest, CryptoRsaSignTest032, TestSize.Level0)
{
    uint8_t plan[] = "this is rsa verify test.";
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

    HcfPriKey *prikey = keyPair->priKey;
    HcfBlob input = {.data = plan, .len = strlen((char *)plan)};
    HcfBlob verifyData = {.data = nullptr, .len = 0};
    HcfSign *sign = nullptr;
    res = HcfSignCreate("RSA|PSS|SHA256|MGF1_SHA256", &sign);
    EXPECT_EQ(res, HCF_SUCCESS);
    res = sign->init(sign, nullptr, prikey);
    EXPECT_EQ(res, HCF_SUCCESS);

    char *retStr = nullptr;
    res = sign->getSignSpecString(sign, PSS_MGF1_MD_STR, &retStr);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_STREQ(g_sha256MdName, retStr);

    res = sign->sign(sign, &input, &verifyData);
    EXPECT_EQ(res, HCF_SUCCESS);

    HcfObjDestroy(sign);
    HcfFree(retStr);
    HcfFree(verifyData.data);
    HcfObjDestroy(keyPair);
    HcfObjDestroy(generator);
}
}
