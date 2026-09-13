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
#include "securec.h"
#include "asy_key_generator.h"
#include "blob.h"
#include "detailed_rsa_key_params.h"
#include "memory.h"
#include "openssl_common.h"
#include "signature.h"
#include "cstring"


using namespace std;
using namespace testing::ext;

namespace {
class CryptoRsaVerifyTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp();
    void TearDown();
};

void CryptoRsaVerifyTest::SetUp() {}
void CryptoRsaVerifyTest::TearDown() {}
void CryptoRsaVerifyTest::SetUpTestCase() {}
void CryptoRsaVerifyTest::TearDownTestCase() {}

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
constexpr int PSS_INVLAID_SALTLEN = -5;
constexpr int PSS_NORMAL_SALTLEN = 32;
constexpr int PSS_TRAILER_FIELD_LEN = 1;
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

HWTEST_F(CryptoRsaVerifyTest, CryptoRsaVerifyTest100, TestSize.Level0)
{
    HcfVerify *verify = nullptr;
    int32_t res = HcfVerifyCreate("RSA1024|PSS|SHA256", &verify);
    EXPECT_NE(res, HCF_SUCCESS);
    ASSERT_EQ(verify, nullptr);

    HcfObjDestroy(verify);
}

HWTEST_F(CryptoRsaVerifyTest, CryptoRsaVerifyTest110, TestSize.Level0)
{
    HcfVerify *verify = nullptr;
    int32_t res = HcfVerifyCreate("RSA1024|PSS|SHA256|MGF1_SHA256", &verify);
    EXPECT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(verify, nullptr);

    HcfObjDestroy(verify);
}

// incorrect case : init signer with nullptr public key.
HWTEST_F(CryptoRsaVerifyTest, CryptoRsaVerifyTest120, TestSize.Level0)
{
    HcfResult res = HCF_SUCCESS;
    HcfVerify *verify = nullptr;
    res = HcfVerifyCreate("RSA1024|PSS|SHA256|MGF1_SHA256", &verify);
    EXPECT_EQ(res, HCF_SUCCESS);
    res = verify->init(verify, nullptr, nullptr);
    EXPECT_NE(res, HCF_SUCCESS);

    HcfObjDestroy(verify);
}

// incorrect case : init signer with private Key.
HWTEST_F(CryptoRsaVerifyTest, CryptoRsaVerifyTest130, TestSize.Level0)
{
    HcfAsyKeyGenerator *generator = nullptr;
    HcfResult res = HcfAsyKeyGeneratorCreate("RSA2048|PRIMES_2", &generator);
    HcfKeyPair *keyPair = nullptr;
    res = generator->generateKeyPair(generator, nullptr, &keyPair);
    EXPECT_EQ(res, HCF_SUCCESS);

    HcfVerify *verify = nullptr;
    res = HcfVerifyCreate("RSA1024|PSS|SHA256|MGF1_SHA256", &verify);
    EXPECT_EQ(res, HCF_SUCCESS);
    res = verify->init(verify, nullptr, (HcfPubKey *)keyPair->priKey);
    EXPECT_NE(res, HCF_SUCCESS);

    HcfObjDestroy(keyPair);
    HcfObjDestroy(generator);
    HcfObjDestroy(verify);
}

// incorrect case : init with other class (not cipher).
HWTEST_F(CryptoRsaVerifyTest, CryptoRsaVerifyTest140, TestSize.Level0)
{
    HcfAsyKeyGenerator *generator = nullptr;
    HcfResult res = HcfAsyKeyGeneratorCreate("RSA2048|PRIMES_2", &generator);
    HcfKeyPair *keyPair = nullptr;
    res = generator->generateKeyPair(generator, nullptr, &keyPair);
    EXPECT_EQ(res, HCF_SUCCESS);

    HcfVerify *verify = nullptr;
    res = HcfVerifyCreate("RSA1024|PSS|SHA256|MGF1_SHA256", &verify);
    EXPECT_EQ(res, HCF_SUCCESS);
    res = verify->init((HcfVerify *)generator, nullptr, keyPair->pubKey);
    EXPECT_NE(res, HCF_SUCCESS);

    HcfObjDestroy(keyPair);
    HcfObjDestroy(generator);
    HcfObjDestroy(verify);
}

// incorrect case : update with other class (not cipher).
HWTEST_F(CryptoRsaVerifyTest, CryptoRsaVerifyTest150, TestSize.Level0)
{
    HcfResult res = HCF_SUCCESS;
    HcfAsyKeyGenerator *generator = nullptr;
    res = HcfAsyKeyGeneratorCreate("RSA2048|PRIMES_2", &generator);

    HcfVerify *verify = nullptr;
    res = HcfVerifyCreate("RSA1024|PSS|SHA256|MGF1_SHA256", &verify);
    EXPECT_EQ(res, HCF_SUCCESS);

    uint8_t plan[] = "this is rsa verify test.";
    HcfBlob input = {.data = plan, .len = strlen((char *)plan)};
    res = verify->update((HcfVerify *)generator, &input);
    EXPECT_NE(res, HCF_SUCCESS);

    HcfObjDestroy(verify);
    HcfObjDestroy(generator);
}

// incorrect case : verify with other class (not cipher).
HWTEST_F(CryptoRsaVerifyTest, CryptoRsaVerifyTest160, TestSize.Level0)
{
    HcfResult res = HCF_SUCCESS;
    HcfAsyKeyGenerator *generator = nullptr;
    res = HcfAsyKeyGeneratorCreate("RSA2048|PRIMES_2", &generator);

    HcfVerify *verify = nullptr;
    res = HcfVerifyCreate("RSA1024|PSS|SHA256|MGF1_SHA256", &verify);
    EXPECT_EQ(res, HCF_SUCCESS);

    uint8_t plan[] = "this is rsa verify test.";
    HcfBlob input = {.data = plan, .len = strlen((char *)plan)};
    bool result = verify->verify((HcfVerify *)generator, &input, &input);
    EXPECT_NE(result, true);

    HcfObjDestroy(verify);
    HcfObjDestroy(generator);
}

// incorrect case : use update function before intialize.
HWTEST_F(CryptoRsaVerifyTest, CryptoRsaVerifyTest170, TestSize.Level0)
{
    HcfResult res = HCF_SUCCESS;
    HcfVerify *verify = nullptr;
    res = HcfVerifyCreate("RSA1024|PSS|SHA256|MGF1_SHA256", &verify);
    EXPECT_EQ(res, HCF_SUCCESS);

    uint8_t plan[] = "this is rsa verify test.";
    HcfBlob input = {.data = plan, .len = strlen((char *)plan)};
    res = verify->update(verify, &input);
    EXPECT_NE(res, HCF_SUCCESS);

    HcfObjDestroy(verify);
}

// incorrect case : use verify function before intialize.
HWTEST_F(CryptoRsaVerifyTest, CryptoRsaVerifyTest180, TestSize.Level0)
{
    HcfResult res = HCF_SUCCESS;
    HcfVerify *verify = nullptr;
    res = HcfVerifyCreate("RSA1024|PSS|SHA256|MGF1_SHA256", &verify);
    EXPECT_EQ(res, HCF_SUCCESS);

    uint8_t plan[] = "this is rsa verify test.";
    HcfBlob input = {.data = plan, .len = strlen((char *)plan)};
    bool result = verify->verify(verify, nullptr, &input);
    EXPECT_NE(result, true);

    HcfObjDestroy(verify);
}

// incorrect case : update with nullptr inputBlob.
HWTEST_F(CryptoRsaVerifyTest, CryptoRsaVerifyTest190, TestSize.Level0)
{
    HcfAsyKeyGenerator *generator = nullptr;
    int32_t res = HcfAsyKeyGeneratorCreate("RSA2048|PRIMES_2", &generator);

    HcfKeyPair *keyPair = nullptr;
    res = generator->generateKeyPair(generator, nullptr, &keyPair);
    EXPECT_EQ(res, HCF_SUCCESS);

    HcfPubKey *pubkey = keyPair->pubKey;

    HcfVerify *verify = nullptr;
    res = HcfVerifyCreate("RSA1024|PSS|SHA256|MGF1_SHA512", &verify);
    EXPECT_EQ(res, HCF_SUCCESS);
    res = verify->init(verify, nullptr, pubkey);
    EXPECT_EQ(res, HCF_SUCCESS);
    res = verify->update(verify, nullptr);
    EXPECT_NE(res, 1);

    HcfObjDestroy(verify);
    HcfObjDestroy(keyPair);
    HcfObjDestroy(generator);
}

// incorrect case : verify with nullptr outputBlob.
HWTEST_F(CryptoRsaVerifyTest, CryptoRsaVerifyTest191, TestSize.Level0)
{
    HcfAsyKeyGenerator *generator = nullptr;
    int32_t res = HcfAsyKeyGeneratorCreate("RSA2048|PRIMES_2", &generator);

    HcfKeyPair *keyPair = nullptr;
    res = generator->generateKeyPair(generator, nullptr, &keyPair);
    EXPECT_EQ(res, HCF_SUCCESS);

    HcfPubKey *pubkey = keyPair->pubKey;

    HcfVerify *verify = nullptr;
    res = HcfVerifyCreate("RSA1024|PSS|SHA256|MGF1_SHA512", &verify);
    EXPECT_EQ(res, HCF_SUCCESS);
    res = verify->init(verify, nullptr, pubkey);
    EXPECT_EQ(res, HCF_SUCCESS);
    res = verify->verify(verify, nullptr, nullptr);
    EXPECT_NE(res, 1);

    HcfObjDestroy(verify);
    HcfObjDestroy(keyPair);
    HcfObjDestroy(generator);
}

// incorrect case : init verify twice
HWTEST_F(CryptoRsaVerifyTest, CryptoRsaVerifyTest192, TestSize.Level0)
{
    HcfAsyKeyGenerator *generator = nullptr;
    HcfResult res = HcfAsyKeyGeneratorCreate("RSA2048|PRIMES_2", &generator);
    HcfKeyPair *keyPair = nullptr;
    res = generator->generateKeyPair(generator, nullptr, &keyPair);
    EXPECT_EQ(res, HCF_SUCCESS);

    HcfPubKey *pubkey = keyPair->pubKey;
    HcfVerify *verify = nullptr;
    res = HcfVerifyCreate("RSA1024|PSS|SHA256|MGF1_SHA256", &verify);
    EXPECT_EQ(res, HCF_SUCCESS);

    res = verify->init(verify, nullptr, pubkey);
    EXPECT_EQ(res, HCF_SUCCESS);
    res = verify->init(verify, nullptr, pubkey);
    EXPECT_NE(res, HCF_SUCCESS);

    HcfObjDestroy(verify);
    HcfObjDestroy(keyPair);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoRsaVerifyTest, CryptoRsaVerifyTest200, TestSize.Level0)
{
    uint8_t plan[] = "this is rsa verify test.";
    HcfAsyKeyGenerator *generator = nullptr;
    HcfResult res = HcfAsyKeyGeneratorCreate("RSA2048|PRIMES_2", &generator);
    HcfKeyPair *keyPair = nullptr;
    res = generator->generateKeyPair(generator, nullptr, &keyPair);
    EXPECT_EQ(res, HCF_SUCCESS);

    HcfPubKey *pubkey = keyPair->pubKey;
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

    HcfVerify *verify = nullptr;
    res = HcfVerifyCreate("RSA1024|PSS|SHA256|MGF1_SHA256", &verify);
    EXPECT_EQ(res, HCF_SUCCESS);
    res = verify->init(verify, nullptr, pubkey);
    EXPECT_EQ(res, HCF_SUCCESS);
    bool result = verify->verify(verify, &input, &verifyData);
    EXPECT_EQ(result, true);
    HcfObjDestroy(verify);

    HcfFree(verifyData.data);
    HcfObjDestroy(keyPair);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoRsaVerifyTest, CryptoRsaVerifyTest210, TestSize.Level0)
{
    uint8_t plan[] = "this is rsa verify test aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa.";
    HcfAsyKeyGenerator *generator = nullptr;
    int32_t res = HcfAsyKeyGeneratorCreate("RSA2048|PRIMES_2", &generator);

    HcfKeyPair *keyPair = nullptr;
    res = generator->generateKeyPair(generator, nullptr, &keyPair);
    EXPECT_EQ(res, HCF_SUCCESS);

    HcfPubKey *pubkey = keyPair->pubKey;
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

    HcfVerify *verify = nullptr;
    res = HcfVerifyCreate("RSA1024|PSS|SHA256|MGF1_SHA256", &verify);
    EXPECT_EQ(res, HCF_SUCCESS);
    res = verify->init(verify, nullptr, pubkey);
    EXPECT_EQ(res, HCF_SUCCESS);
    res = verify->verify(verify, &input, &verifyData);
    EXPECT_EQ(res, 1);
    HcfObjDestroy(verify);

    HcfFree(verifyData.data);
    HcfObjDestroy(keyPair);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoRsaVerifyTest, CryptoRsaVerifyTest220, TestSize.Level0)
{
    uint8_t plan[] = "this is rsa verify test aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa.";
    HcfAsyKeyGenerator *generator = nullptr;
    int32_t res = HcfAsyKeyGeneratorCreate("RSA2048|PRIMES_2", &generator);

    HcfKeyPair *keyPair = nullptr;
    res = generator->generateKeyPair(generator, nullptr, &keyPair);
    EXPECT_EQ(res, HCF_SUCCESS);

    HcfPubKey *pubkey = keyPair->pubKey;
    HcfPriKey *prikey = keyPair->priKey;

    HcfBlob input = {.data = plan, .len = strlen((char *)plan)};
    HcfBlob verifyData = {.data = nullptr, .len = 0};
    HcfSign *sign = nullptr;
    res = HcfSignCreate("RSA1024|PSS|SHA256|MGF1_SHA512", &sign);
    EXPECT_EQ(res, HCF_SUCCESS);
    res = sign->init(sign, nullptr, prikey);
    EXPECT_EQ(res, HCF_SUCCESS);
    res = sign->sign(sign, &input, &verifyData);
    HcfObjDestroy(sign);

    HcfVerify *verify = nullptr;
    res = HcfVerifyCreate("RSA1024|PSS|SHA256|MGF1_SHA512", &verify);
    EXPECT_EQ(res, HCF_SUCCESS);
    res = verify->init(verify, nullptr, pubkey);
    EXPECT_EQ(res, HCF_SUCCESS);
    res = verify->verify(verify, &input, &verifyData);
    EXPECT_EQ(res, 1);
    HcfObjDestroy(verify);

    HcfFree(verifyData.data);
    HcfObjDestroy(keyPair);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoRsaVerifyTest, CryptoRsaVerifyTest230, TestSize.Level0)
{
    uint8_t plan[] = "this is rsa verify test aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa.";
    HcfAsyKeyGenerator *generator = nullptr;
    int32_t res = HcfAsyKeyGeneratorCreate("RSA2048|PRIMES_2", &generator);

    HcfKeyPair *keyPair = nullptr;
    res = generator->generateKeyPair(generator, nullptr, &keyPair);
    EXPECT_EQ(res, HCF_SUCCESS);

    HcfPubKey *pubkey = keyPair->pubKey;
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

    HcfVerify *verify = nullptr;
    res = HcfVerifyCreate("RSA1024|PKCS1|SHA256", &verify);
    EXPECT_EQ(res, HCF_SUCCESS);
    res = verify->init(verify, nullptr, pubkey);
    EXPECT_EQ(res, HCF_SUCCESS);
    res = verify->verify(verify, &input, &verifyData);
    EXPECT_EQ(res, 1);
    HcfObjDestroy(verify);

    HcfFree(verifyData.data);
    HcfObjDestroy(keyPair);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoRsaVerifyTest, CryptoRsaVerifyTest240, TestSize.Level0)
{
    uint8_t plan[] = "this is rsa verify test aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa.";
    uint8_t errorverify[] = "asdfasdfasdfasf";
    HcfAsyKeyGenerator *generator = nullptr;
    int32_t res = HcfAsyKeyGeneratorCreate("RSA2048|PRIMES_2", &generator);

    HcfKeyPair *keyPair = nullptr;
    res = generator->generateKeyPair(generator, nullptr, &keyPair);
    EXPECT_EQ(res, HCF_SUCCESS);

    HcfPubKey *pubkey = keyPair->pubKey;
    HcfPriKey *prikey = keyPair->priKey;

    HcfBlob input = {.data = plan, .len = strlen((char *)plan)};
    HcfBlob verifyData = {.data = nullptr, .len = 0};
    HcfBlob invalidverifyData = {.data = errorverify, .len = strlen((char *)errorverify)};
    HcfSign *sign = nullptr;
    res = HcfSignCreate("RSA1024|PKCS1|SHA256", &sign);
    EXPECT_EQ(res, HCF_SUCCESS);
    res = sign->init(sign, nullptr, prikey);
    EXPECT_EQ(res, HCF_SUCCESS);
    res = sign->sign(sign, &input, &verifyData);
    HcfObjDestroy(sign);

    HcfVerify *verify = nullptr;
    res = HcfVerifyCreate("RSA1024|PKCS1|SHA256", &verify);
    EXPECT_EQ(res, HCF_SUCCESS);
    res = verify->init(verify, nullptr, pubkey);
    EXPECT_EQ(res, HCF_SUCCESS);
    res = verify->verify(verify, &input, &invalidverifyData);
    EXPECT_EQ(res, 0);
    HcfObjDestroy(verify);

    HcfFree(verifyData.data);
    HcfObjDestroy(keyPair);
    HcfObjDestroy(generator);
}

// Incorrect case: different mode
HWTEST_F(CryptoRsaVerifyTest, CryptoRsaVerifyTest250, TestSize.Level0)
{
    uint8_t plan[] = "this is rsa verify test aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa.";
    HcfAsyKeyGenerator *generator = nullptr;
    int32_t res = HcfAsyKeyGeneratorCreate("RSA2048|PRIMES_2", &generator);

    HcfKeyPair *keyPair = nullptr;
    res = generator->generateKeyPair(generator, nullptr, &keyPair);
    EXPECT_EQ(res, HCF_SUCCESS);

    HcfPubKey *pubkey = keyPair->pubKey;
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

    HcfVerify *verify = nullptr;
    res = HcfVerifyCreate("RSA1024|PSS|SHA256|MGF1_SHA512", &verify);
    EXPECT_EQ(res, HCF_SUCCESS);
    res = verify->init(verify, nullptr, pubkey);
    EXPECT_EQ(res, HCF_SUCCESS);
    res = verify->verify(verify, &input, &verifyData);
    EXPECT_EQ(res, 0);
    HcfObjDestroy(verify);

    HcfFree(verifyData.data);
    HcfObjDestroy(keyPair);
    HcfObjDestroy(generator);
}

// Incorrect case: different mgf1md
HWTEST_F(CryptoRsaVerifyTest, CryptoRsaVerifyTest260, TestSize.Level0)
{
    uint8_t plan[] = "this is rsa verify test aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa.";
    HcfAsyKeyGenerator *generator = nullptr;
    int32_t res = HcfAsyKeyGeneratorCreate("RSA2048|PRIMES_2", &generator);

    HcfKeyPair *keyPair = nullptr;
    res = generator->generateKeyPair(generator, nullptr, &keyPair);
    EXPECT_EQ(res, HCF_SUCCESS);

    HcfPubKey *pubkey = keyPair->pubKey;
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

    HcfVerify *verify = nullptr;
    res = HcfVerifyCreate("RSA1024|PSS|SHA256|MGF1_SHA512", &verify);
    EXPECT_EQ(res, HCF_SUCCESS);
    res = verify->init(verify, nullptr, pubkey);
    EXPECT_EQ(res, HCF_SUCCESS);
    res = verify->verify(verify, &input, &verifyData);
    EXPECT_EQ(res, 0);
    HcfObjDestroy(verify);

    HcfFree(verifyData.data);
    HcfObjDestroy(keyPair);
    HcfObjDestroy(generator);
}


// Incorrect case: different pkcs1 md, verify fail
HWTEST_F(CryptoRsaVerifyTest, CryptoRsaVerifyTest270, TestSize.Level0)
{
    uint8_t plan[] = "this is rsa verify test aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa.";
    HcfAsyKeyGenerator *generator = nullptr;
    int32_t res = HcfAsyKeyGeneratorCreate("RSA2048|PRIMES_2", &generator);

    HcfKeyPair *keyPair = nullptr;
    res = generator->generateKeyPair(generator, nullptr, &keyPair);
    EXPECT_EQ(res, HCF_SUCCESS);

    HcfPubKey *pubkey = keyPair->pubKey;
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

    HcfVerify *verify = nullptr;
    res = HcfVerifyCreate("RSA1024|PKCS1|SHA512", &verify);
    EXPECT_EQ(res, HCF_SUCCESS);
    res = verify->init(verify, nullptr, pubkey);
    EXPECT_EQ(res, HCF_SUCCESS);
    res = verify->verify(verify, &input, &verifyData);
    EXPECT_EQ(res, 0);
    HcfObjDestroy(verify);

    HcfFree(verifyData.data);
    HcfObjDestroy(keyPair);
    HcfObjDestroy(generator);
}

// check update_func in PSS padding
HWTEST_F(CryptoRsaVerifyTest, CryptoRsaVerifyTest280, TestSize.Level0)
{
    uint8_t plan1[] = "this is rsa verify test plane1 aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa.";
    uint8_t plan2[] = "this is rsa verify test plane2 aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa.";
    HcfAsyKeyGenerator *generator = nullptr;
    int32_t res = HcfAsyKeyGeneratorCreate("RSA2048|PRIMES_2", &generator);

    HcfKeyPair *keyPair = nullptr;
    res = generator->generateKeyPair(generator, nullptr, &keyPair);
    EXPECT_EQ(res, HCF_SUCCESS);

    HcfPubKey *pubkey = keyPair->pubKey;
    HcfPriKey *prikey = keyPair->priKey;

    HcfBlob input = {.data = plan1, .len = strlen((char *)plan1)};
    HcfBlob inputEx = {.data = plan2, .len = strlen((char *)plan2)};
    HcfBlob verifyData = {.data = nullptr, .len = 0};
    HcfSign *sign = nullptr;
    res = HcfSignCreate("RSA1024|PSS|SHA256|MGF1_SHA256", &sign);
    EXPECT_EQ(res, HCF_SUCCESS);
    res = sign->init(sign, nullptr, prikey);
    EXPECT_EQ(res, HCF_SUCCESS);
    res = sign->update(sign, &input);
    EXPECT_EQ(res, HCF_SUCCESS);
    res = sign->sign(sign, &inputEx, &verifyData);
    EXPECT_EQ(res, HCF_SUCCESS);
    HcfObjDestroy(sign);

    HcfVerify *verify = nullptr;
    res = HcfVerifyCreate("RSA1024|PSS|SHA256|MGF1_SHA256", &verify);
    EXPECT_EQ(res, HCF_SUCCESS);
    res = verify->init(verify, nullptr, pubkey);
    EXPECT_EQ(res, HCF_SUCCESS);
    res = verify->update(verify, &input);
    EXPECT_EQ(res, HCF_SUCCESS);
    res = verify->verify(verify, &inputEx, &verifyData);
    EXPECT_EQ(res, 1);
    HcfObjDestroy(verify);

    HcfFree(verifyData.data);
    HcfObjDestroy(keyPair);
    HcfObjDestroy(generator);
}

// check update in PKCS1 padding
HWTEST_F(CryptoRsaVerifyTest, CryptoRsaVerifyTest290, TestSize.Level0)
{
    uint8_t plan1[] = "this is rsa verify test plane1 aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa.";
    uint8_t plan2[] = "this is rsa verify test plane2 aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa.";
    uint8_t plan3[] = "this is rsa verify test plane3 aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa.";

    HcfAsyKeyGenerator *generator = nullptr;
    int32_t res = HcfAsyKeyGeneratorCreate("RSA2048|PRIMES_2", &generator);

    HcfKeyPair *keyPair = nullptr;
    res = generator->generateKeyPair(generator, nullptr, &keyPair);
    EXPECT_EQ(res, HCF_SUCCESS);

    HcfPubKey *pubkey = keyPair->pubKey;
    HcfPriKey *prikey = keyPair->priKey;

    HcfBlob input1 = {.data = plan1, .len = strlen((char *)plan1)};
    HcfBlob input2 = {.data = plan2, .len = strlen((char *)plan2)};
    HcfBlob input3 = {.data = plan3, .len = strlen((char *)plan3)};
    HcfBlob verifyData = {.data = nullptr, .len = 0};
    HcfSign *sign = nullptr;
    res = HcfSignCreate("RSA1024|PKCS1|SHA256", &sign);
    EXPECT_EQ(res, HCF_SUCCESS);
    res = sign->init(sign, nullptr, prikey);
    EXPECT_EQ(res, HCF_SUCCESS);
    res = sign->update(sign, &input1);
    EXPECT_EQ(res, HCF_SUCCESS);
    res = sign->update(sign, &input2);
    EXPECT_EQ(res, HCF_SUCCESS);
    res = sign->sign(sign, &input3, &verifyData);
    EXPECT_EQ(res, HCF_SUCCESS);
    HcfObjDestroy(sign);

    HcfVerify *verify = nullptr;
    res = HcfVerifyCreate("RSA1024|PKCS1|SHA256", &verify);
    EXPECT_EQ(res, HCF_SUCCESS);
    res = verify->init(verify, nullptr, pubkey);
    EXPECT_EQ(res, HCF_SUCCESS);
    res = verify->update(verify, &input1);
    EXPECT_EQ(res, HCF_SUCCESS);
    res = verify->update(verify, &input2);
    EXPECT_EQ(res, HCF_SUCCESS);
    res = verify->verify(verify, &input3, &verifyData);
    EXPECT_EQ(res, 1);
    HcfObjDestroy(verify);

    HcfFree(verifyData.data);
    HcfObjDestroy(keyPair);
    HcfObjDestroy(generator);
}

// incorrect case : pss set before init -> fail -> success(new)
HWTEST_F(CryptoRsaVerifyTest, CryptoRsaVerifyTest300, TestSize.Level0)
{
    HcfAsyKeyGenerator *generator = nullptr;
    int32_t res = HcfAsyKeyGeneratorCreate("RSA2048|PRIMES_2", &generator);

    HcfKeyPair *keyPair = nullptr;
    res = generator->generateKeyPair(generator, nullptr, &keyPair);
    EXPECT_EQ(res, HCF_SUCCESS);

    HcfPubKey *pubkey = keyPair->pubKey;
    HcfVerify *verify = nullptr;
    res = HcfVerifyCreate("RSA1024|PSS|SHA256|MGF1_SHA512", &verify);
    EXPECT_EQ(res, HCF_SUCCESS);

    res = verify->setVerifySpecInt(verify, PSS_SALT_LEN_INT, PSS_NORMAL_SALTLEN);
    EXPECT_EQ(res, HCF_SUCCESS);
    res = verify->init(verify, nullptr, pubkey);
    EXPECT_EQ(res, HCF_SUCCESS);
    res = verify->update(verify, nullptr);
    EXPECT_NE(res, 1);

    HcfObjDestroy(verify);
    HcfObjDestroy(keyPair);
    HcfObjDestroy(generator);
}

// incorrect case : pss set abnormal len
HWTEST_F(CryptoRsaVerifyTest, CryptoRsaVerifyTest301, TestSize.Level0)
{
    HcfAsyKeyGenerator *generator = nullptr;
    int32_t res = HcfAsyKeyGeneratorCreate("RSA2048|PRIMES_2", &generator);

    HcfKeyPair *keyPair = nullptr;
    res = generator->generateKeyPair(generator, nullptr, &keyPair);
    EXPECT_EQ(res, HCF_SUCCESS);

    HcfPubKey *pubkey = keyPair->pubKey;
    HcfVerify *verify = nullptr;
    res = HcfVerifyCreate("RSA1024|PSS|SHA256|MGF1_SHA512", &verify);
    EXPECT_EQ(res, HCF_SUCCESS);

    res = verify->init(verify, nullptr, pubkey);
    EXPECT_EQ(res, HCF_SUCCESS);
    res = verify->setVerifySpecInt(verify, PSS_SALT_LEN_INT, PSS_INVLAID_SALTLEN);
    EXPECT_NE(res, HCF_SUCCESS);
    res = verify->update(verify, nullptr);
    EXPECT_NE(res, 1);

    HcfObjDestroy(verify);
    HcfObjDestroy(keyPair);
    HcfObjDestroy(generator);
}

// correct case : pss set abnormal len after init
HWTEST_F(CryptoRsaVerifyTest, CryptoRsaVerifyTest302, TestSize.Level0)
{
    HcfAsyKeyGenerator *generator = nullptr;
    int32_t res = HcfAsyKeyGeneratorCreate("RSA2048|PRIMES_2", &generator);

    HcfKeyPair *keyPair = nullptr;
    res = generator->generateKeyPair(generator, nullptr, &keyPair);
    EXPECT_EQ(res, HCF_SUCCESS);

    HcfPubKey *pubkey = keyPair->pubKey;
    HcfVerify *verify = nullptr;
    res = HcfVerifyCreate("RSA1024|PSS|SHA256|MGF1_SHA512", &verify);
    EXPECT_EQ(res, HCF_SUCCESS);

    res = verify->init(verify, nullptr, pubkey);
    EXPECT_EQ(res, HCF_SUCCESS);
    res = verify->setVerifySpecInt(verify, PSS_SALT_LEN_INT, PSS_NORMAL_SALTLEN);
    EXPECT_EQ(res, HCF_SUCCESS);
    res = verify->update(verify, nullptr);
    EXPECT_NE(res, 1);

    HcfObjDestroy(verify);
    HcfObjDestroy(keyPair);
    HcfObjDestroy(generator);
}

// correct case : pss get func after init except saltLen.
HWTEST_F(CryptoRsaVerifyTest, CryptoRsaVerifyTest303, TestSize.Level0)
{
    HcfAsyKeyGenerator *generator = nullptr;
    int32_t res = HcfAsyKeyGeneratorCreate("RSA2048|PRIMES_2", &generator);

    HcfKeyPair *keyPair = nullptr;
    res = generator->generateKeyPair(generator, nullptr, &keyPair);
    EXPECT_EQ(res, HCF_SUCCESS);

    HcfPubKey *pubkey = keyPair->pubKey;
    HcfVerify *verify = nullptr;
    res = HcfVerifyCreate("RSA1024|PSS|SHA256|MGF1_SHA256", &verify);
    EXPECT_EQ(res, HCF_SUCCESS);

    res = verify->init(verify, nullptr, pubkey);
    EXPECT_EQ(res, HCF_SUCCESS);
    int32_t retInt = 0;
    res = verify->getVerifySpecInt(verify, PSS_TRAILER_FIELD_INT, &retInt);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_EQ(retInt, PSS_TRAILER_FIELD_LEN);
    res = verify->update(verify, nullptr);
    EXPECT_NE(res, 1);

    HcfObjDestroy(verify);
    HcfObjDestroy(keyPair);
    HcfObjDestroy(generator);
}

// get string
HWTEST_F(CryptoRsaVerifyTest, CryptoRsaVerifyTest304, TestSize.Level0)
{
    HcfAsyKeyGenerator *generator = nullptr;
    int32_t res = HcfAsyKeyGeneratorCreate("RSA2048|PRIMES_2", &generator);

    HcfKeyPair *keyPair = nullptr;
    res = generator->generateKeyPair(generator, nullptr, &keyPair);
    EXPECT_EQ(res, HCF_SUCCESS);

    HcfPubKey *pubkey = keyPair->pubKey;
    HcfVerify *verify = nullptr;
    res = HcfVerifyCreate("RSA1024|PSS|SHA256|MGF1_SHA256", &verify);
    EXPECT_EQ(res, HCF_SUCCESS);

    res = verify->init(verify, nullptr, pubkey);
    EXPECT_EQ(res, HCF_SUCCESS);
    char *retStr = nullptr;
    res = verify->getVerifySpecString(verify, PSS_MD_NAME_STR, &retStr);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_STREQ(g_sha256MdName, retStr);
    res = verify->update(verify, nullptr);
    EXPECT_NE(res, 1);

    HcfFree(retStr);
    HcfObjDestroy(verify);
    HcfObjDestroy(keyPair);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoRsaVerifyTest, CryptoRsaVerifyTest305, TestSize.Level0)
{
    HcfAsyKeyGenerator *generator = nullptr;
    int32_t res = HcfAsyKeyGeneratorCreate("RSA2048|PRIMES_2", &generator);

    HcfKeyPair *keyPair = nullptr;
    res = generator->generateKeyPair(generator, nullptr, &keyPair);
    EXPECT_EQ(res, HCF_SUCCESS);

    HcfPubKey *pubkey = keyPair->pubKey;
    HcfVerify *verify = nullptr;
    res = HcfVerifyCreate("RSA1024|PSS|SHA256|MGF1_SHA256", &verify);
    EXPECT_EQ(res, HCF_SUCCESS);

    res = verify->init(verify, nullptr, pubkey);
    EXPECT_EQ(res, HCF_SUCCESS);
    char *retStr = nullptr;
    res = verify->getVerifySpecString(verify, PSS_MGF_NAME_STR, &retStr);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_STREQ(g_mgf1Name, retStr);
    res = verify->update(verify, nullptr);
    EXPECT_NE(res, 1);

    HcfFree(retStr);
    HcfObjDestroy(verify);
    HcfObjDestroy(keyPair);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoRsaVerifyTest, CryptoRsaVerifyTest306, TestSize.Level0)
{
    HcfAsyKeyGenerator *generator = nullptr;
    int32_t res = HcfAsyKeyGeneratorCreate("RSA2048|PRIMES_2", &generator);

    HcfKeyPair *keyPair = nullptr;
    res = generator->generateKeyPair(generator, nullptr, &keyPair);
    EXPECT_EQ(res, HCF_SUCCESS);

    HcfPubKey *pubkey = keyPair->pubKey;
    HcfVerify *verify = nullptr;
    res = HcfVerifyCreate("RSA1024|PSS|SHA256|MGF1_SHA256", &verify);
    EXPECT_EQ(res, HCF_SUCCESS);

    res = verify->init(verify, nullptr, pubkey);
    EXPECT_EQ(res, HCF_SUCCESS);
    char *retStr = nullptr;
    res = verify->getVerifySpecString(verify, PSS_MGF1_MD_STR, &retStr);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_STREQ(g_sha256MdName, retStr);
    res = verify->update(verify, nullptr);
    EXPECT_NE(res, 1);

    HcfFree(retStr);
    HcfObjDestroy(verify);
    HcfObjDestroy(keyPair);
    HcfObjDestroy(generator);
}

// incorrect case : pkcs1 set pss saltLen
HWTEST_F(CryptoRsaVerifyTest, CryptoRsaVerifyTest307, TestSize.Level3)
{
    HcfAsyKeyGenerator *generator = nullptr;
    int32_t res = HcfAsyKeyGeneratorCreate("RSA2048|PRIMES_2", &generator);

    HcfKeyPair *keyPair = nullptr;
    res = generator->generateKeyPair(generator, nullptr, &keyPair);
    EXPECT_EQ(res, HCF_SUCCESS);

    HcfPubKey *pubkey = keyPair->pubKey;
    HcfVerify *verify = nullptr;
    res = HcfVerifyCreate("RSA1024|PKCS1|SHA256", &verify);
    EXPECT_EQ(res, HCF_SUCCESS);

    res = verify->init(verify, nullptr, pubkey);
    EXPECT_EQ(res, HCF_SUCCESS);
    res = verify->setVerifySpecInt(verify, PSS_SALT_LEN_INT, PSS_NORMAL_SALTLEN);
    EXPECT_NE(res, HCF_SUCCESS);
    res = verify->update(verify, nullptr);
    EXPECT_NE(res, 1);

    HcfObjDestroy(verify);
    HcfObjDestroy(keyPair);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoRsaVerifyTest, CryptoRsaVerifyTest308, TestSize.Level0)
{
    uint8_t plan[] = "this is rsa verify test aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa.";
    HcfAsyKeyGenerator *generator = nullptr;
    int32_t res = HcfAsyKeyGeneratorCreate("RSA2048|PRIMES_2", &generator);

    HcfKeyPair *keyPair = nullptr;
    res = generator->generateKeyPair(generator, nullptr, &keyPair);
    EXPECT_EQ(res, HCF_SUCCESS);

    HcfPubKey *pubkey = keyPair->pubKey;
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

    HcfVerify *verify = nullptr;
    res = HcfVerifyCreate("RSA1024|PKCS1|SHA256", &verify);
    EXPECT_EQ(res, HCF_SUCCESS);
    res = verify->init(verify, nullptr, pubkey);
    EXPECT_EQ(res, HCF_SUCCESS);
    res = verify->verify(verify, &input, &verifyData);
    EXPECT_EQ(res, 1);
    HcfObjDestroy(verify);

    HcfFree(verifyData.data);
    HcfObjDestroy(keyPair);
    HcfObjDestroy(generator);
}
// old key and test update setSignSpecInt func
HWTEST_F(CryptoRsaVerifyTest, CryptoRsaVerifyTest001, TestSize.Level0)
{
    uint8_t plan1[] = "this is rsa verify test plane1 aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa.";
    uint8_t plan2[] = "this is rsa verify test plane2 aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa.";
    HcfAsyKeyGenerator *generator = nullptr;
    int32_t res = HcfAsyKeyGeneratorCreate("RSA2048|PRIMES_2", &generator);

    HcfKeyPair *keyPair = nullptr;
    res = generator->generateKeyPair(generator, nullptr, &keyPair);
    EXPECT_EQ(res, HCF_SUCCESS);

    HcfPubKey *pubkey = keyPair->pubKey;
    HcfPriKey *prikey = keyPair->priKey;

    HcfBlob input = {.data = plan1, .len = strlen((char *)plan1)};
    HcfBlob inputEx = {.data = plan2, .len = strlen((char *)plan2)};
    HcfBlob verifyData = {.data = nullptr, .len = 0};
    HcfSign *sign = nullptr;
    res = HcfSignCreate("RSA1024|PSS|SHA256|MGF1_SHA256", &sign);
    EXPECT_EQ(res, HCF_SUCCESS);
    res = sign->init(sign, nullptr, prikey);
    EXPECT_EQ(res, HCF_SUCCESS);

    // set sign pss saltlen
    res = sign->setSignSpecInt(sign, PSS_SALT_LEN_INT, PSS_NORMAL_SALTLEN);
    EXPECT_EQ(res, HCF_SUCCESS);
    res = sign->update(sign, &input);
    EXPECT_EQ(res, HCF_SUCCESS);
    res = sign->sign(sign, &inputEx, &verifyData);
    EXPECT_EQ(res, HCF_SUCCESS);
    HcfObjDestroy(sign);

    HcfVerify *verify = nullptr;
    res = HcfVerifyCreate("RSA1024|PSS|SHA256|MGF1_SHA256", &verify);
    EXPECT_EQ(res, HCF_SUCCESS);
    res = verify->init(verify, nullptr, pubkey);
    EXPECT_EQ(res, HCF_SUCCESS);

    // set verify attribute
    res = verify->setVerifySpecInt(verify, PSS_SALT_LEN_INT, PSS_NORMAL_SALTLEN);
    EXPECT_EQ(res, HCF_SUCCESS);

    res = verify->update(verify, &input);
    EXPECT_EQ(res, HCF_SUCCESS);
    res = verify->verify(verify, &inputEx, &verifyData);
    // true == 1
    EXPECT_EQ(res, 1);
    HcfObjDestroy(verify);

    HcfFree(verifyData.data);
    HcfObjDestroy(keyPair);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoRsaVerifyTest, CryptoRsaVerifyTest002, TestSize.Level0)
{
    uint8_t plan1[] = "this is rsa verify test plane1 aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa.";
    uint8_t plan2[] = "this is rsa verify test plane2 aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa.";
    int32_t res = HCF_SUCCESS;
    HcfRsaKeyPairParamsSpec rsaPairSpec = {};
    unsigned char dataN[RSA_2048_N_BYTE_SIZE] = {0};
    unsigned char dataE[RSA_2048_E_BYTE_SIZE] = {0};
    unsigned char dataD[RSA_2048_D_BYTE_SIZE] = {0};
    GenerateRsa2048CorrectKeyPairSpec(dataN, dataE, dataD, &rsaPairSpec);

    HcfAsyKeyGeneratorBySpec *generator = nullptr;
    res = HcfAsyKeyGeneratorBySpecCreate(reinterpret_cast<HcfAsyKeyParamsSpec *>(&rsaPairSpec), &generator);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(generator, nullptr);

    HcfKeyPair *keyPair = nullptr;
    res = generator->generateKeyPair(generator, &keyPair);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(keyPair, nullptr);

    HcfBlob input = {.data = plan1, .len = strlen((char *)plan1)};
    HcfBlob inputEx = {.data = plan2, .len = strlen((char *)plan2)};
    HcfBlob verifyData = {.data = nullptr, .len = 0};
    HcfSign *sign = nullptr;
    res = HcfSignCreate("RSA1024|PSS|SHA256|MGF1_SHA256", &sign);
    EXPECT_EQ(res, HCF_SUCCESS);
    // set sign pss saltlen
    res = sign->setSignSpecInt(sign, PSS_SALT_LEN_INT, PSS_NORMAL_SALTLEN);
    EXPECT_EQ(res, HCF_SUCCESS);
    res = sign->init(sign, nullptr, keyPair->priKey);
    EXPECT_EQ(res, HCF_SUCCESS);
    res = sign->update(sign, &input);
    EXPECT_EQ(res, HCF_SUCCESS);
    res = sign->sign(sign, &inputEx, &verifyData);
    EXPECT_EQ(res, HCF_SUCCESS);
    HcfObjDestroy(sign);

    HcfVerify *verify = nullptr;
    res = HcfVerifyCreate("RSA1024|PSS|SHA256|MGF1_SHA256", &verify);
    EXPECT_EQ(res, HCF_SUCCESS);
    res = verify->init(verify, nullptr, keyPair->pubKey);
    EXPECT_EQ(res, HCF_SUCCESS);
    // set verify attribute
    res = verify->setVerifySpecInt(verify, PSS_SALT_LEN_INT, PSS_NORMAL_SALTLEN);
    EXPECT_EQ(res, HCF_SUCCESS);
    res = verify->update(verify, &input);
    EXPECT_EQ(res, HCF_SUCCESS);
    res = verify->verify(verify, &inputEx, &verifyData);
    // true == 1
    EXPECT_EQ(res, 1);
    HcfObjDestroy(verify);

    HcfFree(verifyData.data);
    HcfObjDestroy(keyPair);
    HcfObjDestroy(generator);
}

// test verify pss signature, sign after init and verify before init.
HWTEST_F(CryptoRsaVerifyTest, CryptoRsaVerifyTest003, TestSize.Level0)
{
    uint8_t plan1[] = "this is rsa verify test plane1 aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa.";
    uint8_t plan2[] = "this is rsa verify test plane2 aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa.";
    int32_t res = HCF_SUCCESS;
    HcfRsaKeyPairParamsSpec rsaPairSpec = {};
    unsigned char dataN[RSA_2048_N_BYTE_SIZE] = {0};
    unsigned char dataE[RSA_2048_E_BYTE_SIZE] = {0};
    unsigned char dataD[RSA_2048_D_BYTE_SIZE] = {0};
    GenerateRsa2048CorrectKeyPairSpec(dataN, dataE, dataD, &rsaPairSpec);

    HcfAsyKeyGeneratorBySpec *generator = nullptr;
    res = HcfAsyKeyGeneratorBySpecCreate(reinterpret_cast<HcfAsyKeyParamsSpec *>(&rsaPairSpec), &generator);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(generator, nullptr);

    HcfKeyPair *keyPair = nullptr;
    res = generator->generateKeyPair(generator, &keyPair);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(keyPair, nullptr);

    HcfBlob input = {.data = plan1, .len = strlen((char *)plan1)};
    HcfBlob inputEx = {.data = plan2, .len = strlen((char *)plan2)};
    HcfBlob verifyData = {.data = nullptr, .len = 0};
    HcfSign *sign = nullptr;
    res = HcfSignCreate("RSA1024|PSS|SHA256|MGF1_SHA256", &sign);
    EXPECT_EQ(res, HCF_SUCCESS);

    res = sign->init(sign, nullptr, keyPair->priKey);
    EXPECT_EQ(res, HCF_SUCCESS);
    res = sign->setSignSpecInt(sign, PSS_SALT_LEN_INT, PSS_NORMAL_SALTLEN);
    EXPECT_EQ(res, HCF_SUCCESS);
    res = sign->update(sign, &input);
    EXPECT_EQ(res, HCF_SUCCESS);
    res = sign->sign(sign, &inputEx, &verifyData);
    EXPECT_EQ(res, HCF_SUCCESS);
    HcfObjDestroy(sign);

    HcfVerify *verify = nullptr;
    res = HcfVerifyCreate("RSA1024|PSS|SHA256|MGF1_SHA256", &verify);
    EXPECT_EQ(res, HCF_SUCCESS);
    // set verify attribute
    res = verify->setVerifySpecInt(verify, PSS_SALT_LEN_INT, PSS_NORMAL_SALTLEN);
    EXPECT_EQ(res, HCF_SUCCESS);
    res = verify->init(verify, nullptr, keyPair->pubKey);
    EXPECT_EQ(res, HCF_SUCCESS);
    res = verify->update(verify, &input);
    EXPECT_EQ(res, HCF_SUCCESS);
    res = verify->verify(verify, &inputEx, &verifyData);
    // true == 1
    EXPECT_EQ(res, 1);
    HcfObjDestroy(verify);

    HcfFree(verifyData.data);
    HcfObjDestroy(keyPair);
    HcfObjDestroy(generator);
}
}
