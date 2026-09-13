/*
 * Copyright (C) 2022-2024 Huawei Device Co., Ltd.
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
class CryptoRsaCipherTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp();
    void TearDown();
};

void CryptoRsaCipherTest::SetUpTestCase() {}
void CryptoRsaCipherTest::TearDownTestCase() {}
void CryptoRsaCipherTest::SetUp() {}
void CryptoRsaCipherTest::TearDown() {}

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
const char *g_mdName = "SHA256";
const char *g_mgf1Name = "MGF1";

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

static HcfResult RsaCipherSpec(HcfCipher *cipher)
{
    uint8_t pSourceData[] = "123456\0";
    HcfBlob pSource = {.data = (uint8_t *)pSourceData, .len = strlen((char *)pSourceData)};
    HcfResult res = cipher->setCipherSpecUint8Array(cipher, OAEP_MGF1_PSRC_UINT8ARR, pSource);
    EXPECT_EQ(res, HCF_SUCCESS);

    char *returnMdName = nullptr;
    res = cipher->getCipherSpecString(cipher, OAEP_MD_NAME_STR, &returnMdName);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_STREQ(g_mdName, returnMdName);
    char *returnMgF1Name = nullptr;
    res = cipher->getCipherSpecString(cipher, OAEP_MGF_NAME_STR, &returnMgF1Name);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_STREQ(g_mgf1Name, returnMgF1Name);
    char *returnMgf1MdName = nullptr;
    res = cipher->getCipherSpecString(cipher, OAEP_MGF1_MD_STR, &returnMgf1MdName);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_STREQ(g_mdName, returnMgf1MdName);

    HcfBlob pSourceReturn = {.data = nullptr, .len = 0};
    res = cipher->getCipherSpecUint8Array(cipher, OAEP_MGF1_PSRC_UINT8ARR, &pSourceReturn);
    EXPECT_EQ(res, HCF_SUCCESS);
    int resCmp = memcmp(pSourceReturn.data, pSourceData, pSourceReturn.len);
    EXPECT_EQ(resCmp, HCF_SUCCESS);

    HcfFree(pSourceReturn.data);
    HcfFree(returnMdName);
    HcfFree(returnMgF1Name);
    HcfFree(returnMgf1MdName);
    return res;
}

static HcfResult RsaSpecpSource(HcfCipher *cipher, uint8_t *pSourceData, HcfBlob pSource)
{
    HcfBlob cleanP = { .data = nullptr, .len = 0 };
    HcfBlob pSourceReturn = {.data = nullptr, .len = 0};
    // test cipher psource set、get before init & set clean.
    HcfResult res = cipher->setCipherSpecUint8Array(cipher, OAEP_MGF1_PSRC_UINT8ARR, pSource);
    EXPECT_EQ(res, HCF_SUCCESS);
    res = cipher->getCipherSpecUint8Array(cipher, OAEP_MGF1_PSRC_UINT8ARR, &pSourceReturn);
    EXPECT_EQ(res, HCF_SUCCESS);
    int resCmp = memcmp(pSourceReturn.data, pSourceData, pSourceReturn.len);
    EXPECT_EQ(resCmp, HCF_SUCCESS);

    res = cipher->setCipherSpecUint8Array(cipher, OAEP_MGF1_PSRC_UINT8ARR, cleanP);
    EXPECT_EQ(res, HCF_SUCCESS);
    res = cipher->getCipherSpecUint8Array(cipher, OAEP_MGF1_PSRC_UINT8ARR, &pSourceReturn);
    EXPECT_NE(res, HCF_SUCCESS) << "after clean, cannot get Psource";

    HcfBlob pSourceReturn2 = {.data = nullptr, .len = 0};
    res = cipher->setCipherSpecUint8Array(cipher, OAEP_MGF1_PSRC_UINT8ARR, pSource);
    EXPECT_EQ(res, HCF_SUCCESS);
    res = cipher->getCipherSpecUint8Array(cipher, OAEP_MGF1_PSRC_UINT8ARR, &pSourceReturn2);
    EXPECT_EQ(res, HCF_SUCCESS);
    resCmp = memcmp(pSourceReturn2.data, pSourceData, pSourceReturn.len);
    EXPECT_EQ(resCmp, 0);
    HcfFree(pSourceReturn2.data);
    HcfFree(pSourceReturn.data);
    return res;
}

HWTEST_F(CryptoRsaCipherTest, CryptoRsaCipherTest90, TestSize.Level0)
{
    HcfResult res = HCF_SUCCESS;
    HcfCipher *cipher = nullptr;
    res = HcfCipherCreate("RSA1024|NoPadding", &cipher);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(cipher, nullptr);
    EXPECT_NE(cipher->base.getClass(), nullptr);
    EXPECT_NE(cipher->base.destroy, nullptr);
    EXPECT_NE(cipher->init, nullptr);
    EXPECT_NE(cipher->update, nullptr);
    EXPECT_NE(cipher->doFinal, nullptr);
    EXPECT_NE(cipher->getAlgorithm, nullptr);
    HcfObjDestroy(cipher);
}


// HcfCipherCreate correct case: RSAXXX + padding
HWTEST_F(CryptoRsaCipherTest, CryptoRsaCipherTest100, TestSize.Level0)
{
    HcfResult res = HCF_SUCCESS;
    HcfCipher *cipher = nullptr;
    res = HcfCipherCreate("RSA1024|NoPadding", &cipher);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(cipher, nullptr);
    EXPECT_NE(cipher->base.getClass(), nullptr);
    EXPECT_NE(cipher->base.destroy, nullptr);
    EXPECT_NE(cipher->init, nullptr);
    EXPECT_NE(cipher->update, nullptr);
    EXPECT_NE(cipher->doFinal, nullptr);
    HcfObjDestroy(cipher);
}

HWTEST_F(CryptoRsaCipherTest, CryptoRsaCipherTest110, TestSize.Level0)
{
    HcfResult res = HCF_SUCCESS;
    HcfCipher *cipher = nullptr;
    res = HcfCipherCreate("RSA1024|NoPadding", &cipher);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(cipher, nullptr);
    EXPECT_NE(cipher->base.getClass(), nullptr);
    EXPECT_NE(cipher->base.destroy, nullptr);
    EXPECT_NE(cipher->init, nullptr);
    EXPECT_NE(cipher->update, nullptr);
    EXPECT_NE(cipher->doFinal, nullptr);
    HcfObjDestroy(cipher);
}

HWTEST_F(CryptoRsaCipherTest, CryptoRsaCipherTest120, TestSize.Level0)
{
    HcfResult res = HCF_SUCCESS;
    HcfCipher *cipher = nullptr;
    res = HcfCipherCreate("RSA1024|PKCS1", &cipher);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(cipher, nullptr);
    EXPECT_NE(cipher->base.getClass(), nullptr);
    EXPECT_NE(cipher->base.destroy, nullptr);
    EXPECT_NE(cipher->init, nullptr);
    EXPECT_NE(cipher->update, nullptr);
    EXPECT_NE(cipher->doFinal, nullptr);
    HcfObjDestroy(cipher);
}

HWTEST_F(CryptoRsaCipherTest, CryptoRsaCipherTest130, TestSize.Level0)
{
    HcfResult res = HCF_SUCCESS;
    HcfCipher *cipher = nullptr;
    res = HcfCipherCreate("RSA1024|PKCS1_OAEP|SHA1|MGF1_SHA1", &cipher);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(cipher, nullptr);
    EXPECT_NE(cipher->base.getClass(), nullptr);
    EXPECT_NE(cipher->base.destroy, nullptr);
    EXPECT_NE(cipher->init, nullptr);
    EXPECT_NE(cipher->update, nullptr);
    EXPECT_NE(cipher->doFinal, nullptr);
    HcfObjDestroy(cipher);
}

HWTEST_F(CryptoRsaCipherTest, CryptoRsaCipherTest140, TestSize.Level0)
{
    HcfResult res = HCF_SUCCESS;
    HcfCipher *cipher = nullptr;
    res = HcfCipherCreate("RSA1024|PKCS1_OAEP|SHA256|MGF1_SHA256", &cipher);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(cipher, nullptr);
    EXPECT_NE(cipher->base.getClass(), nullptr);
    EXPECT_NE(cipher->base.destroy, nullptr);
    EXPECT_NE(cipher->init, nullptr);
    EXPECT_NE(cipher->update, nullptr);
    EXPECT_NE(cipher->doFinal, nullptr);
    HcfObjDestroy(cipher);
}

HWTEST_F(CryptoRsaCipherTest, CryptoRsaCipherTest150, TestSize.Level0)
{
    HcfResult res = HCF_SUCCESS;
    HcfCipher *cipher = nullptr;
    res = HcfCipherCreate("RSA1024|PKCS1_OAEP|SHA512|MGF1_SHA256", &cipher);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(cipher, nullptr);
    EXPECT_NE(cipher->base.getClass(), nullptr);
    EXPECT_NE(cipher->base.destroy, nullptr);
    EXPECT_NE(cipher->init, nullptr);
    EXPECT_NE(cipher->update, nullptr);
    EXPECT_NE(cipher->doFinal, nullptr);
    HcfObjDestroy(cipher);
}

HWTEST_F(CryptoRsaCipherTest, CryptoRsaCipherTest160, TestSize.Level0)
{
    HcfResult res = HCF_SUCCESS;
    HcfCipher *cipher = nullptr;
    res = HcfCipherCreate("RSA1024|PKCS1_OAEP|SHA1|MGF1_SHA256", &cipher);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(cipher, nullptr);
    EXPECT_NE(cipher->base.getClass(), nullptr);
    EXPECT_NE(cipher->base.destroy, nullptr);
    EXPECT_NE(cipher->init, nullptr);
    EXPECT_NE(cipher->update, nullptr);
    EXPECT_NE(cipher->doFinal, nullptr);
    HcfObjDestroy(cipher);
}

HWTEST_F(CryptoRsaCipherTest, CryptoRsaCipherTest170, TestSize.Level0)
{
    HcfResult res = HCF_SUCCESS;
    HcfCipher *cipher = nullptr;
    res = HcfCipherCreate("RSA1024|PKCS1_OAEP|SHA1|MGF1_SHA1", &cipher);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(cipher, nullptr);
    EXPECT_NE(cipher->base.getClass(), nullptr);
    EXPECT_NE(cipher->base.destroy, nullptr);
    EXPECT_NE(cipher->init, nullptr);
    EXPECT_NE(cipher->update, nullptr);
    EXPECT_NE(cipher->doFinal, nullptr);
    HcfObjDestroy(cipher);
}

HWTEST_F(CryptoRsaCipherTest, CryptoRsaCipherTest180, TestSize.Level0)
{
    HcfResult res = HCF_SUCCESS;
    HcfCipher *cipher = nullptr;
    res = HcfCipherCreate("RSA1024|PKCS1_OAEP|SHA1|MGF1_MD5", &cipher);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(cipher, nullptr);
    EXPECT_NE(cipher->base.getClass(), nullptr);
    EXPECT_NE(cipher->base.destroy, nullptr);
    EXPECT_NE(cipher->init, nullptr);
    EXPECT_NE(cipher->update, nullptr);
    EXPECT_NE(cipher->doFinal, nullptr);
    HcfObjDestroy(cipher);
}

HWTEST_F(CryptoRsaCipherTest, CryptoRsaCipherTest190, TestSize.Level0)
{
    HcfResult res = HCF_SUCCESS;
    HcfCipher *cipher = nullptr;
    res = HcfCipherCreate("RSA1024|PKCS1_OAEP|SHA1|MGF1_SHA512", &cipher);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(cipher, nullptr);
    EXPECT_NE(cipher->base.getClass(), nullptr);
    EXPECT_NE(cipher->base.destroy, nullptr);
    EXPECT_NE(cipher->init, nullptr);
    EXPECT_NE(cipher->update, nullptr);
    EXPECT_NE(cipher->doFinal, nullptr);
    HcfObjDestroy(cipher);
}

HWTEST_F(CryptoRsaCipherTest, CryptoRsaCipherTest200, TestSize.Level0)
{
    HcfResult res = HCF_SUCCESS;
    HcfCipher *cipher = nullptr;
    res = HcfCipherCreate("RSA512|NoPadding", &cipher);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(cipher, nullptr);
    EXPECT_NE(cipher->base.getClass(), nullptr);
    EXPECT_NE(cipher->base.destroy, nullptr);
    EXPECT_NE(cipher->init, nullptr);
    EXPECT_NE(cipher->update, nullptr);
    EXPECT_NE(cipher->doFinal, nullptr);
    HcfObjDestroy(cipher);
}

HWTEST_F(CryptoRsaCipherTest, CryptoRsaCipherTest210, TestSize.Level0)
{
    HcfResult res = HCF_SUCCESS;
    HcfCipher *cipher = nullptr;
    res = HcfCipherCreate("RSA768|NoPadding", &cipher);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(cipher, nullptr);
    EXPECT_NE(cipher->base.getClass(), nullptr);
    EXPECT_NE(cipher->base.destroy, nullptr);
    EXPECT_NE(cipher->init, nullptr);
    EXPECT_NE(cipher->update, nullptr);
    EXPECT_NE(cipher->doFinal, nullptr);
    HcfObjDestroy(cipher);
}

HWTEST_F(CryptoRsaCipherTest, CryptoRsaCipherTest220, TestSize.Level0)
{
    HcfResult res = HCF_SUCCESS;
    HcfCipher *cipher = nullptr;
    res = HcfCipherCreate("RSA2048|NoPadding", &cipher);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(cipher, nullptr);
    EXPECT_NE(cipher->base.getClass(), nullptr);
    EXPECT_NE(cipher->base.destroy, nullptr);
    EXPECT_NE(cipher->init, nullptr);
    EXPECT_NE(cipher->update, nullptr);
    EXPECT_NE(cipher->doFinal, nullptr);
    HcfObjDestroy(cipher);
}

HWTEST_F(CryptoRsaCipherTest, CryptoRsaCipherTest230, TestSize.Level0)
{
    HcfResult res = HCF_SUCCESS;
    HcfCipher *cipher = nullptr;
    res = HcfCipherCreate("RSA512|PKCS1", &cipher);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(cipher, nullptr);
    EXPECT_NE(cipher->base.getClass(), nullptr);
    EXPECT_NE(cipher->base.destroy, nullptr);
    EXPECT_NE(cipher->init, nullptr);
    EXPECT_NE(cipher->update, nullptr);
    EXPECT_NE(cipher->doFinal, nullptr);
    HcfObjDestroy(cipher);
}

HWTEST_F(CryptoRsaCipherTest, CryptoRsaCipherTest240, TestSize.Level0)
{
    HcfResult res = HCF_SUCCESS;
    HcfCipher *cipher = nullptr;
    res = HcfCipherCreate("RSA768|PKCS1", &cipher);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(cipher, nullptr);
    EXPECT_NE(cipher->base.getClass(), nullptr);
    EXPECT_NE(cipher->base.destroy, nullptr);
    EXPECT_NE(cipher->init, nullptr);
    EXPECT_NE(cipher->update, nullptr);
    EXPECT_NE(cipher->doFinal, nullptr);
    HcfObjDestroy(cipher);
}

HWTEST_F(CryptoRsaCipherTest, CryptoRsaCipherTest250, TestSize.Level0)
{
    HcfResult res = HCF_SUCCESS;
    HcfCipher *cipher = nullptr;
    res = HcfCipherCreate("RSA2048|PKCS1", &cipher);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(cipher, nullptr);
    EXPECT_NE(cipher->base.getClass(), nullptr);
    EXPECT_NE(cipher->base.destroy, nullptr);
    EXPECT_NE(cipher->init, nullptr);
    EXPECT_NE(cipher->update, nullptr);
    EXPECT_NE(cipher->doFinal, nullptr);
    HcfObjDestroy(cipher);
}

HWTEST_F(CryptoRsaCipherTest, CryptoRsaCipherTest260, TestSize.Level0)
{
    HcfResult res = HCF_SUCCESS;
    HcfCipher *cipher = nullptr;
    res = HcfCipherCreate("RSA512|PKCS1_OAEP|SHA256|MGF1_SHA256", &cipher);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(cipher, nullptr);
    EXPECT_NE(cipher->base.getClass(), nullptr);
    EXPECT_NE(cipher->base.destroy, nullptr);
    EXPECT_NE(cipher->init, nullptr);
    EXPECT_NE(cipher->update, nullptr);
    EXPECT_NE(cipher->doFinal, nullptr);
    HcfObjDestroy(cipher);
}

HWTEST_F(CryptoRsaCipherTest, CryptoRsaCipherTest270, TestSize.Level0)
{
    HcfResult res = HCF_SUCCESS;
    HcfCipher *cipher = nullptr;
    res = HcfCipherCreate("RSA768|PKCS1_OAEP|SHA256|MGF1_SHA256", &cipher);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(cipher, nullptr);
    EXPECT_NE(cipher->base.getClass(), nullptr);
    EXPECT_NE(cipher->base.destroy, nullptr);
    EXPECT_NE(cipher->init, nullptr);
    EXPECT_NE(cipher->update, nullptr);
    EXPECT_NE(cipher->doFinal, nullptr);
    HcfObjDestroy(cipher);
}

HWTEST_F(CryptoRsaCipherTest, CryptoRsaCipherTest280, TestSize.Level0)
{
    HcfResult res = HCF_SUCCESS;
    HcfCipher *cipher = nullptr;
    res = HcfCipherCreate("RSA2048|PKCS1_OAEP|SHA256|MGF1_SHA256", &cipher);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(cipher, nullptr);
    EXPECT_NE(cipher->base.getClass(), nullptr);
    EXPECT_NE(cipher->base.destroy, nullptr);
    EXPECT_NE(cipher->init, nullptr);
    EXPECT_NE(cipher->update, nullptr);
    EXPECT_NE(cipher->doFinal, nullptr);
    HcfObjDestroy(cipher);
}

// HcfCipherCreate Incorrect case
HWTEST_F(CryptoRsaCipherTest, CryptoRsaCipherTest300, TestSize.Level0)
{
    HcfResult res = HCF_SUCCESS;
    res = HcfCipherCreate("RSA2048|PKCS1_OAEP|SHA256|MGF1_SHA256", nullptr);
    EXPECT_NE(res, HCF_SUCCESS);
}

HWTEST_F(CryptoRsaCipherTest, CryptoRsaCipherTest310, TestSize.Level0)
{
    HcfResult res = HCF_SUCCESS;
    HcfCipher *cipher = nullptr;
    res = HcfCipherCreate(nullptr, &cipher);
    EXPECT_NE(res, HCF_SUCCESS);
    EXPECT_EQ(cipher, nullptr);
}

HWTEST_F(CryptoRsaCipherTest, CryptoRsaCipherTest320, TestSize.Level0)
{
    HcfResult res = HCF_SUCCESS;
    HcfCipher *cipher = nullptr;
    res = HcfCipherCreate("RSA2048|PKCS1_OAEP|SHA256|MGF1_SHA256|2111111111111111111111111111111111111111111111"
        "111111111111123123", &cipher);
    EXPECT_NE(res, HCF_SUCCESS);
    EXPECT_EQ(cipher, nullptr);
}

HWTEST_F(CryptoRsaCipherTest, CryptoRsaCipherTest330, TestSize.Level0)
{
    HcfResult res = HCF_SUCCESS;
    HcfCipher *cipher = nullptr;
    res = HcfCipherCreate("RSA2048|PKCS1_OAEP|SHA256|MGF1_SHA333", &cipher);
    EXPECT_NE(res, HCF_SUCCESS);
    EXPECT_EQ(cipher, nullptr);
}

HWTEST_F(CryptoRsaCipherTest, CryptoRsaCipherTest340, TestSize.Level0)
{
    HcfResult res = HCF_SUCCESS;
    HcfCipher *cipher = nullptr;
    res = HcfCipherCreate("RSA2048|PKCS1_OAEP111|SHA256|MGF1_SHA333", &cipher);
    EXPECT_NE(res, HCF_SUCCESS);
    EXPECT_EQ(cipher, nullptr);
}

HWTEST_F(CryptoRsaCipherTest, CryptoRsaCipherTest350, TestSize.Level0)
{
    HcfResult res = HCF_SUCCESS;
    HcfCipher *cipher = nullptr;
    res = HcfCipherCreate("RSA2111048|PKCS1_OAEP|SHA256|MGF1_SHA256", &cipher);
    EXPECT_NE(res, HCF_SUCCESS);
    EXPECT_EQ(cipher, nullptr);
}

HWTEST_F(CryptoRsaCipherTest, CryptoRsaCipherTest360, TestSize.Level0)
{
    HcfResult res = HCF_SUCCESS;
    HcfCipher *cipher = nullptr;
    res = HcfCipherCreate("RSA2048|PKCS1_OAEP|SHA256111|MGF1_SHA256", &cipher);
    EXPECT_NE(res, HCF_SUCCESS);
    EXPECT_EQ(cipher, nullptr);
}

// Create Cipher without padding
HWTEST_F(CryptoRsaCipherTest, CryptoRsaCipherTest370, TestSize.Level0)
{
    HcfResult res = HCF_SUCCESS;
    HcfCipher *cipher = nullptr;
    res = HcfCipherCreate("RSA2048", &cipher);
    EXPECT_NE(res, HCF_SUCCESS);
}

// destroyCipher
HWTEST_F(CryptoRsaCipherTest, CryptoRsaCipherTest400, TestSize.Level0)
{
    HcfResult res = HCF_SUCCESS;
    HcfCipher *cipher = nullptr;
    res = HcfCipherCreate("RSA2048|PKCS1_OAEP|SHA256|MGF1_SHA256", &cipher);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(cipher, nullptr);
    HcfObjDestroy(cipher);
    cipher = nullptr;
    HcfObjDestroy(cipher);
}

// init correct case
HWTEST_F(CryptoRsaCipherTest, CryptoRsaCipherTest500, TestSize.Level0)
{
    HcfResult res = HCF_SUCCESS;
    HcfAsyKeyGenerator *generator = nullptr;
    res = HcfAsyKeyGeneratorCreate("RSA1024|PRIMES_2", &generator);
    EXPECT_EQ(res, HCF_SUCCESS);
    HcfKeyPair *keyPair = nullptr;
    res = generator->generateKeyPair(generator, nullptr, &keyPair);
    EXPECT_EQ(res, HCF_SUCCESS);

    HcfCipher *cipher = nullptr;
    res = HcfCipherCreate("RSA1024|PKCS1", &cipher);
    EXPECT_EQ(res, HCF_SUCCESS);
    res = cipher->init(cipher, ENCRYPT_MODE, (HcfKey *)keyPair->pubKey, nullptr);
    EXPECT_EQ(res, HCF_SUCCESS);

    HcfObjDestroy(keyPair);
    HcfObjDestroy(generator);
    HcfObjDestroy(cipher);
}

HWTEST_F(CryptoRsaCipherTest, CryptoRsaCipherTest501, TestSize.Level0)
{
    HcfResult res = HCF_SUCCESS;
    HcfAsyKeyGenerator *generator = nullptr;
    res = HcfAsyKeyGeneratorCreate("RSA1024|PRIMES_2", &generator);
    EXPECT_EQ(res, HCF_SUCCESS);
    HcfKeyPair *keyPair = nullptr;
    res = generator->generateKeyPair(generator, nullptr, &keyPair);
    EXPECT_EQ(res, HCF_SUCCESS);

    HcfCipher *cipher = nullptr;
    res = HcfCipherCreate("RSA1024|PKCS1", &cipher);
    EXPECT_EQ(res, HCF_SUCCESS);
    res = cipher->init(cipher, (enum HcfCryptoMode)123, (HcfKey *)keyPair->pubKey, nullptr);
    EXPECT_NE(res, HCF_SUCCESS);

    HcfObjDestroy(keyPair);
    HcfObjDestroy(generator);
    HcfObjDestroy(cipher);
}

HWTEST_F(CryptoRsaCipherTest, CryptoRsaCipherTest510, TestSize.Level0)
{
    HcfResult res = HCF_SUCCESS;
    HcfAsyKeyGenerator *generator = nullptr;
    res = HcfAsyKeyGeneratorCreate("RSA1024|PRIMES_2", &generator);
    EXPECT_EQ(res, HCF_SUCCESS);
    HcfKeyPair *keyPair = nullptr;
    res = generator->generateKeyPair(generator, nullptr, &keyPair);
    EXPECT_EQ(res, HCF_SUCCESS);

    HcfCipher *cipher = nullptr;
    res = HcfCipherCreate("RSA1024|PKCS1", &cipher);
    EXPECT_EQ(res, HCF_SUCCESS);
    res = cipher->init(cipher, DECRYPT_MODE, (HcfKey *)keyPair->priKey, nullptr);
    EXPECT_EQ(res, HCF_SUCCESS);

    HcfObjDestroy(keyPair);
    HcfObjDestroy(generator);
    HcfObjDestroy(cipher);
}

// init incorrect case
HWTEST_F(CryptoRsaCipherTest, CryptoRsaCipherTest600, TestSize.Level0)
{
    HcfResult res = HCF_SUCCESS;
    HcfAsyKeyGenerator *generator = nullptr;
    res = HcfAsyKeyGeneratorCreate("RSA1024|PRIMES_2", &generator);
    EXPECT_EQ(res, HCF_SUCCESS);
    HcfKeyPair *keyPair = nullptr;
    res = generator->generateKeyPair(generator, nullptr, &keyPair);
    EXPECT_EQ(res, HCF_SUCCESS);

    HcfCipher *cipher = nullptr;
    res = HcfCipherCreate("RSA1024|PKCS1", &cipher);
    EXPECT_EQ(res, HCF_SUCCESS);
    res = cipher->init(cipher, ENCRYPT_MODE, (HcfKey *)keyPair->priKey, nullptr);
    EXPECT_NE(res, HCF_SUCCESS);

    HcfObjDestroy(keyPair);
    HcfObjDestroy(generator);
    HcfObjDestroy(cipher);
}

HWTEST_F(CryptoRsaCipherTest, CryptoRsaCipherTest610, TestSize.Level0)
{
    HcfResult res = HCF_SUCCESS;
    HcfAsyKeyGenerator *generator = nullptr;
    res = HcfAsyKeyGeneratorCreate("RSA1024|PRIMES_2", &generator);
    EXPECT_EQ(res, HCF_SUCCESS);
    HcfKeyPair *keyPair = nullptr;
    res = generator->generateKeyPair(generator, nullptr, &keyPair);
    EXPECT_EQ(res, HCF_SUCCESS);

    HcfCipher *cipher = nullptr;
    res = HcfCipherCreate("RSA1024|PKCS1", &cipher);
    EXPECT_EQ(res, HCF_SUCCESS);
    res = cipher->init(cipher, DECRYPT_MODE, (HcfKey *)keyPair->pubKey, nullptr);
    EXPECT_NE(res, HCF_SUCCESS);

    HcfObjDestroy(keyPair);
    HcfObjDestroy(generator);
    HcfObjDestroy(cipher);
}

HWTEST_F(CryptoRsaCipherTest, CryptoRsaCipherTest620, TestSize.Level0)
{
    HcfResult res = HCF_SUCCESS;
    HcfAsyKeyGenerator *generator = nullptr;
    res = HcfAsyKeyGeneratorCreate("RSA1024|PRIMES_2", &generator);
    EXPECT_EQ(res, HCF_SUCCESS);
    HcfKeyPair *keyPair = nullptr;
    res = generator->generateKeyPair(generator, nullptr, &keyPair);
    EXPECT_EQ(res, HCF_SUCCESS);

    HcfCipher *cipher = nullptr;
    res = HcfCipherCreate("RSA1024|PKCS1", &cipher);
    EXPECT_EQ(res, HCF_SUCCESS);
    res = cipher->init(nullptr, DECRYPT_MODE, (HcfKey *)keyPair->pubKey, nullptr);
    EXPECT_NE(res, HCF_SUCCESS);

    HcfObjDestroy(keyPair);
    HcfObjDestroy(generator);
    HcfObjDestroy(cipher);
}

// incorrect case: use diff class, we ignore it in this version
HWTEST_F(CryptoRsaCipherTest, CryptoRsaCipherTest630, TestSize.Level0)
{
    HcfResult res = HCF_SUCCESS;
    HcfAsyKeyGenerator *generator = nullptr;
    res = HcfAsyKeyGeneratorCreate("RSA1024|PRIMES_2", &generator);
    EXPECT_EQ(res, HCF_SUCCESS);
    HcfKeyPair *keyPair = nullptr;
    res = generator->generateKeyPair(generator, nullptr, &keyPair);
    EXPECT_EQ(res, HCF_SUCCESS);

    HcfCipher *aesCipher = nullptr;
    res = HcfCipherCreate("AES128|ECB|PKCS7", &aesCipher);
    EXPECT_EQ(res, HCF_SUCCESS);

    HcfCipher *cipher = nullptr;
    res = HcfCipherCreate("RSA1024|PKCS1", &cipher);
    EXPECT_EQ(res, HCF_SUCCESS);
    res = cipher->init(aesCipher, DECRYPT_MODE, (HcfKey *)keyPair->pubKey, nullptr);
    EXPECT_NE(res, HCF_SUCCESS);

    HcfObjDestroy(keyPair);
    HcfObjDestroy(generator);
    HcfObjDestroy(cipher);
    HcfObjDestroy(aesCipher);
}

HWTEST_F(CryptoRsaCipherTest, CryptoRsaCipherTest640, TestSize.Level0)
{
    HcfResult res = HCF_SUCCESS;
    HcfCipher *cipher = nullptr;
    res = HcfCipherCreate("RSA1024|PKCS1", &cipher);
    EXPECT_EQ(res, HCF_SUCCESS);
    res = cipher->init(cipher, DECRYPT_MODE, nullptr, nullptr);
    EXPECT_NE(res, HCF_SUCCESS);
    HcfObjDestroy(cipher);
}

// correct case: update not support
HWTEST_F(CryptoRsaCipherTest, CryptoRsaCipherTest700, TestSize.Level0)
{
    uint8_t plan[] = "this is rsa cipher test!\0";
    HcfResult res = HCF_SUCCESS;
    HcfAsyKeyGenerator *generator = nullptr;
    res = HcfAsyKeyGeneratorCreate("RSA1024|PRIMES_2", &generator);
    EXPECT_EQ(res, HCF_SUCCESS);
    HcfKeyPair *keyPair = nullptr;
    res = generator->generateKeyPair(generator, nullptr, &keyPair);
    EXPECT_EQ(res, HCF_SUCCESS);

    HcfBlob input = {.data = (uint8_t *)plan, .len = strlen((char *)plan)};
    HcfBlob encoutput = {.data = nullptr, .len = 0};
    HcfCipher *cipher = nullptr;
    res = HcfCipherCreate("RSA1024|PKCS1", &cipher);
    EXPECT_EQ(res, HCF_SUCCESS);
    res = cipher->init(cipher, ENCRYPT_MODE, (HcfKey *)keyPair->pubKey, nullptr);
    EXPECT_EQ(res, HCF_SUCCESS);
    res = cipher->update(cipher, &input, &encoutput);
    EXPECT_NE(res, HCF_SUCCESS);
    EXPECT_EQ(encoutput.data, nullptr);

    HcfObjDestroy(keyPair);
    HcfObjDestroy(generator);
    HcfObjDestroy(cipher);
}

// dofinal correct case
HWTEST_F(CryptoRsaCipherTest, CryptoRsaCipherTest800, TestSize.Level0)
{
    HcfResult res = HCF_SUCCESS;
    uint8_t plan[] = "this is rsa cipher test!\0";
    HcfAsyKeyGenerator *generator = nullptr;
    res = HcfAsyKeyGeneratorCreate("RSA1024|PRIMES_2", &generator);
    EXPECT_EQ(res, HCF_SUCCESS);
    HcfKeyPair *keyPair = nullptr;
    res = generator->generateKeyPair(generator, nullptr, &keyPair);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(keyPair, nullptr);
    EXPECT_NE(keyPair->priKey, nullptr);
    EXPECT_NE(keyPair->pubKey, nullptr);

    HcfBlob input = {.data = (uint8_t *)plan, .len = strlen((char *)plan)};
    HcfBlob encoutput = {.data = nullptr, .len = 0};
    HcfCipher *cipher = nullptr;
    res = HcfCipherCreate("RSA1024|PKCS1", &cipher);
    EXPECT_EQ(res, HCF_SUCCESS);

    res = cipher->init(cipher, ENCRYPT_MODE, (HcfKey *)keyPair->pubKey, nullptr);
    EXPECT_EQ(res, HCF_SUCCESS);
    res = cipher->doFinal(cipher, &input, &encoutput);
    EXPECT_EQ(res, HCF_SUCCESS);
    HcfObjDestroy(cipher);

    HcfBlob decoutput = {.data = nullptr, .len = 0};
    cipher = nullptr;
    res = HcfCipherCreate("RSA1024|PKCS1", &cipher);
    EXPECT_EQ(res, HCF_SUCCESS);
    res = cipher->init(cipher, DECRYPT_MODE, (HcfKey *)keyPair->priKey, nullptr);
    EXPECT_EQ(res, HCF_SUCCESS);
    res = cipher->doFinal(cipher, &encoutput, &decoutput);
    EXPECT_EQ(res, HCF_SUCCESS);
    HcfObjDestroy(cipher);
    EXPECT_STREQ((char *)plan, (char *)decoutput.data);

    HcfFree(encoutput.data);
    HcfFree(decoutput.data);

    HcfObjDestroy(keyPair);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoRsaCipherTest, CryptoRsaCipherTest810, TestSize.Level0)
{
    HcfResult res = HCF_SUCCESS;
    uint8_t plan[] = "this is rsa cipher test!\0";
    HcfAsyKeyGenerator *generator = nullptr;
    res = HcfAsyKeyGeneratorCreate("RSA4096|PRIMES_3", &generator);
    EXPECT_EQ(res, HCF_SUCCESS);
    HcfKeyPair *keyPair = nullptr;
    res = generator->generateKeyPair(generator, nullptr, &keyPair);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(keyPair, nullptr);
    EXPECT_NE(keyPair->priKey, nullptr);
    EXPECT_NE(keyPair->pubKey, nullptr);

    HcfBlob input = {.data = (uint8_t *)plan, .len = strlen((char *)plan)};
    HcfBlob encoutput = {.data = nullptr, .len = 0};
    HcfCipher *cipher = nullptr;
    res = HcfCipherCreate("RSA1024|PKCS1", &cipher);
    EXPECT_EQ(res, HCF_SUCCESS);

    res = cipher->init(cipher, ENCRYPT_MODE, (HcfKey *)keyPair->pubKey, nullptr);
    EXPECT_EQ(res, HCF_SUCCESS);
    res = cipher->doFinal(cipher, &input, &encoutput);
    EXPECT_EQ(res, HCF_SUCCESS);
    HcfObjDestroy(cipher);

    HcfBlob decoutput = {.data = nullptr, .len = 0};
    cipher = nullptr;
    res = HcfCipherCreate("RSA1024|PKCS1", &cipher);
    EXPECT_EQ(res, HCF_SUCCESS);
    res = cipher->init(cipher, DECRYPT_MODE, (HcfKey *)keyPair->priKey, nullptr);
    EXPECT_EQ(res, HCF_SUCCESS);
    res = cipher->doFinal(cipher, &encoutput, &decoutput);
    EXPECT_EQ(res, HCF_SUCCESS);
    HcfObjDestroy(cipher);
    EXPECT_STREQ((char *)plan, (char *)decoutput.data);

    HcfFree(encoutput.data);
    HcfFree(decoutput.data);

    HcfObjDestroy(keyPair);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoRsaCipherTest, CryptoRsaCipherTest820, TestSize.Level0)
{
    HcfResult res = HCF_SUCCESS;
    uint8_t plan[] = "this is rsa cipher test!\0";
    HcfAsyKeyGenerator *generator = nullptr;
    res = HcfAsyKeyGeneratorCreate("RSA1024|PRIMES_2", &generator);

    HcfKeyPair *keyPair = nullptr;
    res = generator->generateKeyPair(generator, nullptr, &keyPair);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(keyPair, nullptr);
    EXPECT_NE(keyPair->priKey, nullptr);
    EXPECT_NE(keyPair->pubKey, nullptr);

    HcfBlob input = {.data = (uint8_t *)plan, .len = strlen((char *)plan)};
    HcfBlob encoutput = {.data = nullptr, .len = 0};
    HcfCipher *cipher = nullptr;
    res = HcfCipherCreate("RSA1024|PKCS1_OAEP|SHA256|MGF1_SHA256", &cipher);
    EXPECT_EQ(res, HCF_SUCCESS);

    res = cipher->init(cipher, ENCRYPT_MODE, (HcfKey *)keyPair->pubKey, nullptr);
    EXPECT_EQ(res, HCF_SUCCESS);
    res = cipher->doFinal(cipher, &input, &encoutput);
    EXPECT_EQ(res, HCF_SUCCESS);
    HcfObjDestroy(cipher);

    HcfBlob decoutput = {.data = nullptr, .len = 0};
    cipher = nullptr;
    res = HcfCipherCreate("RSA1024|PKCS1_OAEP|SHA256|MGF1_SHA256", &cipher);
    EXPECT_EQ(res, HCF_SUCCESS);
    res = cipher->init(cipher, DECRYPT_MODE, (HcfKey *)keyPair->priKey, nullptr);
    EXPECT_EQ(res, HCF_SUCCESS);
    res = cipher->doFinal(cipher, &encoutput, &decoutput);
    EXPECT_EQ(res, HCF_SUCCESS);
    HcfObjDestroy(cipher);
    EXPECT_STREQ((char *)plan, (char *)decoutput.data);

    HcfFree(encoutput.data);
    HcfFree(decoutput.data);

    HcfObjDestroy(keyPair);
    HcfObjDestroy(generator);
}

// incorrect case: algName out of boundary
HWTEST_F(CryptoRsaCipherTest, CryptoRsaCipherTest830, TestSize.Level0)
{
    HcfResult res = HCF_SUCCESS;
    uint8_t plan[] = "this is rsa cipher test aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa!\0";
    HcfAsyKeyGenerator *generator = nullptr;
    res = HcfAsyKeyGeneratorCreate("RSA1024|PRIMES_2", &generator);

    HcfKeyPair *keyPair = nullptr;
    res = generator->generateKeyPair(generator, nullptr, &keyPair);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(keyPair, nullptr);
    EXPECT_NE(keyPair->priKey, nullptr);
    EXPECT_NE(keyPair->pubKey, nullptr);

    HcfBlob input = {.data = (uint8_t *)plan, .len = strlen((char *)plan)};
    HcfBlob encoutput = {.data = nullptr, .len = 0};
    HcfCipher *cipher = nullptr;
    res = HcfCipherCreate("RSA1024|PKCS1_OAEP|SHA256|MGF1_SHA256", &cipher);
    EXPECT_EQ(res, HCF_SUCCESS);

    res = cipher->init(cipher, ENCRYPT_MODE, (HcfKey *)keyPair->pubKey, nullptr);
    EXPECT_EQ(res, HCF_SUCCESS);
    res = cipher->doFinal(cipher, &input, &encoutput);
    EXPECT_NE(res, HCF_SUCCESS);
    HcfObjDestroy(cipher);

    HcfBlob decoutput = {.data = nullptr, .len = 0};
    cipher = nullptr;
    res = HcfCipherCreate("RSA1024|PKCS1_OAEP|SHA256|MGF1_SHA256", &cipher);
    EXPECT_EQ(res, HCF_SUCCESS);
    res = cipher->init(cipher, DECRYPT_MODE, (HcfKey *)keyPair->priKey, nullptr);
    EXPECT_EQ(res, HCF_SUCCESS);
    res = cipher->doFinal(cipher, &encoutput, &decoutput);
    EXPECT_NE(res, HCF_SUCCESS);
    HcfObjDestroy(cipher);
    EXPECT_STRNE((char *)plan, (char *)decoutput.data);

    HcfFree(encoutput.data);
    HcfFree(decoutput.data);

    HcfObjDestroy(keyPair);
    HcfObjDestroy(generator);
}


// Incorrect case: use OAEP pading without mgf1md
HWTEST_F(CryptoRsaCipherTest, CryptoRsaCipherTest840, TestSize.Level0)
{
    HcfResult res = HCF_SUCCESS;

    HcfAsyKeyGenerator *generator = nullptr;
    res = HcfAsyKeyGeneratorCreate("RSA1024|PRIMES_2", &generator);

    HcfKeyPair *keyPair = nullptr;
    res = generator->generateKeyPair(generator, nullptr, &keyPair);
    HcfObjDestroy(generator);
    HcfObjDestroy(keyPair);

    HcfCipher *cipher = nullptr;
    res = HcfCipherCreate("RSA1024|PKCS1_OAEP|SHA256", &cipher);
    EXPECT_NE(res, HCF_SUCCESS);
    EXPECT_EQ(cipher, nullptr);
}

// Incorrect case: use OAEP pading without md
HWTEST_F(CryptoRsaCipherTest, CryptoRsaCipherTest845, TestSize.Level0)
{
    HcfResult res = HCF_SUCCESS;

    HcfAsyKeyGenerator *generator = nullptr;
    res = HcfAsyKeyGeneratorCreate("RSA1024|PRIMES_2", &generator);

    HcfKeyPair *keyPair = nullptr;
    res = generator->generateKeyPair(generator, nullptr, &keyPair);
    HcfObjDestroy(generator);
    HcfObjDestroy(keyPair);

    HcfCipher *cipher = nullptr;
    res = HcfCipherCreate("RSA1024|PKCS1_OAEP|MGF1_SHA256", &cipher);
    EXPECT_NE(res, HCF_SUCCESS);
    EXPECT_EQ(cipher, nullptr);
}

// Correct case: test genEncoded and convert key
HWTEST_F(CryptoRsaCipherTest, CryptoRsaCipherTest850, TestSize.Level0)
{
    uint8_t plan[] = "this is rsa cipher test!\0";
    HcfAsyKeyGenerator *generator = nullptr;
    HcfResult res = HcfAsyKeyGeneratorCreate("RSA1024", &generator);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(generator, nullptr);

    HcfKeyPair *keyPair = nullptr;
    res = generator->generateKeyPair(generator, nullptr, &keyPair);
    EXPECT_EQ(res, HCF_SUCCESS);
    HcfBlob pubKeyBlob = {.data = nullptr, .len = 0};
    HcfBlob priKeyBlob = {.data = nullptr, .len = 0};
    res = keyPair->pubKey->base.getEncoded((HcfKey *)keyPair->pubKey, &pubKeyBlob);
    EXPECT_EQ(res, HCF_SUCCESS);
    res = keyPair->priKey->base.getEncoded((HcfKey *)keyPair->priKey, &priKeyBlob);
    EXPECT_EQ(res, HCF_SUCCESS);

    HcfKeyPair *dupKeyPair = nullptr;
    res = generator->convertKey(generator, nullptr, &pubKeyBlob, &priKeyBlob, &dupKeyPair);
    EXPECT_EQ(res, HCF_SUCCESS);

    HcfObjDestroy(generator);
    HcfObjDestroy(keyPair);

    HcfBlob input = {.data = (uint8_t *)plan, .len = strlen((char *)plan)};
    HcfBlob encoutput = {.data = nullptr, .len = 0};
    HcfCipher *cipher = nullptr;
    res = HcfCipherCreate("RSA1024|PKCS1", &cipher);
    EXPECT_EQ(res, HCF_SUCCESS);

    res = cipher->init(cipher, ENCRYPT_MODE, (HcfKey *)dupKeyPair->pubKey, nullptr);
    EXPECT_EQ(res, HCF_SUCCESS);
    res = cipher->doFinal(cipher, &input, &encoutput);
    EXPECT_EQ(res, HCF_SUCCESS);
    HcfObjDestroy(cipher);

    HcfBlob decoutput = {.data = nullptr, .len = 0};
    cipher = nullptr;
    res = HcfCipherCreate("RSA1024|PKCS1", &cipher);
    EXPECT_EQ(res, HCF_SUCCESS);
    res = cipher->init(cipher, DECRYPT_MODE, (HcfKey *)dupKeyPair->priKey, nullptr);
    EXPECT_EQ(res, HCF_SUCCESS);
    res = cipher->doFinal(cipher, &encoutput, &decoutput);
    EXPECT_EQ(res, HCF_SUCCESS);
    HcfObjDestroy(cipher);
    EXPECT_STREQ((char *)plan, (char *)decoutput.data);

    HcfFree(encoutput.data);
    HcfFree(decoutput.data);
    HcfFree(pubKeyBlob.data);
    HcfFree(priKeyBlob.data);
    HcfObjDestroy(dupKeyPair);
}

// correct case: test OAEP Plaintext boundary:
// RSA_size - (md_result_len * mgf1md_result_len) - 2 = 128 - (32 + 32) - 2 = 62
HWTEST_F(CryptoRsaCipherTest, CryptoRsaCipherTest860, TestSize.Level0)
{
    HcfResult res = HCF_SUCCESS;
    uint8_t plan1[] = "00112233445566778899aabbccddeeff0aaaaaaaaaaaaaaaaaaaaaaaaaa";
    uint8_t plan2[] = "00112233445566778899aabbccddeeffaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    uint8_t plan3[] = "00112233445566778899aabbccddeeff00112233445566778899aaaaaaaaaa";
    HcfAsyKeyGenerator *generator = nullptr;
    res = HcfAsyKeyGeneratorCreate("RSA1024|PRIMES_2", &generator);

    HcfKeyPair *keyPair = nullptr;
    res = generator->generateKeyPair(generator, nullptr, &keyPair);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(keyPair, nullptr);
    EXPECT_NE(keyPair->priKey, nullptr);
    EXPECT_NE(keyPair->pubKey, nullptr);

    HcfCipher *cipher = nullptr;
    res = HcfCipherCreate("RSA1024|PKCS1_OAEP|SHA256|MGF1_SHA256", &cipher);
    EXPECT_EQ(res, HCF_SUCCESS);

    res = cipher->init(cipher, ENCRYPT_MODE, (HcfKey *)keyPair->pubKey, nullptr);
    EXPECT_EQ(res, HCF_SUCCESS);

    HcfBlob encoutput1 = {.data = nullptr, .len = 0};
    HcfBlob encoutput2 = {.data = nullptr, .len = 0};
    HcfBlob encoutput3 = {.data = nullptr, .len = 0};
    HcfBlob input1 = {.data = (uint8_t *)plan1, .len = strlen((char *)plan1)};
    HcfBlob input2 = {.data = (uint8_t *)plan2, .len = strlen((char *)plan2)};
    HcfBlob input3 = {.data = (uint8_t *)plan3, .len = strlen((char *)plan3)};
    res = cipher->doFinal(cipher, &input1, &encoutput1);
    EXPECT_EQ(res, HCF_SUCCESS);
    res = cipher->doFinal(cipher, &input2, &encoutput2);
    EXPECT_NE(res, HCF_SUCCESS);
    res = cipher->doFinal(cipher, &input3, &encoutput2);
    EXPECT_EQ(res, HCF_SUCCESS);


    HcfObjDestroy(cipher);
    HcfFree(encoutput1.data);
    HcfFree(encoutput2.data);
    HcfFree(encoutput3.data);
    HcfObjDestroy(keyPair);
    HcfObjDestroy(generator);
}

// correct case: test nopadding boundary < RSA_size(rsa)
HWTEST_F(CryptoRsaCipherTest, CryptoRsaCipherTest870, TestSize.Level0)
{
    HcfResult res = HCF_SUCCESS;
    uint8_t plan1[] = "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeffasdasdbccddeeff0011223344556600"
        "1122334455111111111116";
    uint8_t plan2[] = "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeffasdasdbccddeeff0011223344556600"
        "112233445511111111111611111111111";

    HcfAsyKeyGenerator *generator = nullptr;
    res = HcfAsyKeyGeneratorCreate("RSA1024|PRIMES_2", &generator);

    HcfKeyPair *keyPair = nullptr;
    res = generator->generateKeyPair(generator, nullptr, &keyPair);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(keyPair, nullptr);
    EXPECT_NE(keyPair->priKey, nullptr);
    EXPECT_NE(keyPair->pubKey, nullptr);

    HcfCipher *cipher = nullptr;
    res = HcfCipherCreate("RSA1024|NoPadding", &cipher);
    EXPECT_EQ(res, HCF_SUCCESS);

    res = cipher->init(cipher, ENCRYPT_MODE, (HcfKey *)keyPair->pubKey, nullptr);
    EXPECT_EQ(res, HCF_SUCCESS);


    HcfBlob encoutput1 = {.data = nullptr, .len = 0};
    HcfBlob encoutput2 = {.data = nullptr, .len = 0};

    HcfBlob input1 = {.data = (uint8_t *)plan1, .len = strlen((char *)plan1)};
    HcfBlob input2 = {.data = (uint8_t *)plan2, .len = strlen((char *)plan2)};

    res = cipher->doFinal(cipher, &input1, &encoutput1);
    EXPECT_NE(res, HCF_SUCCESS);
    res = cipher->doFinal(cipher, &input2, &encoutput2);
    EXPECT_EQ(res, HCF_SUCCESS);

    HcfObjDestroy(cipher);
    HcfFree(encoutput1.data);
    HcfFree(encoutput2.data);
    HcfObjDestroy(keyPair);
    HcfObjDestroy(generator);
}

// correct case: test PKCS1 boundary < RSA_size(rsa) - 11
HWTEST_F(CryptoRsaCipherTest, CryptoRsaCipherTest880, TestSize.Level0)
{
    HcfResult res = HCF_SUCCESS;
    uint8_t plan1[] = "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeffasdasdbccddeeff0011223344556600"
        "1122334455111111111116";
    uint8_t plan2[] = "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeffasdasdbccddeeff0011223344556600"
        "11223344551111111111161";

    HcfAsyKeyGenerator *generator = nullptr;
    res = HcfAsyKeyGeneratorCreate("RSA1024|PRIMES_2", &generator);

    HcfKeyPair *keyPair = nullptr;
    res = generator->generateKeyPair(generator, nullptr, &keyPair);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(keyPair, nullptr);
    EXPECT_NE(keyPair->priKey, nullptr);
    EXPECT_NE(keyPair->pubKey, nullptr);

    HcfCipher *cipher = nullptr;
    res = HcfCipherCreate("RSA1024|PKCS1", &cipher);
    EXPECT_EQ(res, HCF_SUCCESS);

    res = cipher->init(cipher, ENCRYPT_MODE, (HcfKey *)keyPair->pubKey, nullptr);
    EXPECT_EQ(res, HCF_SUCCESS);

    HcfBlob encoutput1 = {.data = nullptr, .len = 0};
    HcfBlob encoutput2 = {.data = nullptr, .len = 0};

    HcfBlob input1 = {.data = (uint8_t *)plan1, .len = strlen((char *)plan1)};
    HcfBlob input2 = {.data = (uint8_t *)plan2, .len = strlen((char *)plan2)};

    res = cipher->doFinal(cipher, &input1, &encoutput1);
    EXPECT_EQ(res, HCF_SUCCESS);
    res = cipher->doFinal(cipher, &input2, &encoutput2);
    EXPECT_NE(res, HCF_SUCCESS);

    HcfObjDestroy(cipher);
    HcfFree(encoutput1.data);
    HcfFree(encoutput2.data);
    HcfObjDestroy(keyPair);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoRsaCipherTest, CryptoRsaCipherTest890, TestSize.Level0)
{
    HcfResult res = HCF_SUCCESS;
    HcfAsyKeyGenerator *generator = nullptr;
    res = HcfAsyKeyGeneratorCreate("RSA1024|PRIMES_2", &generator);
    EXPECT_EQ(res, HCF_SUCCESS);

    HcfKeyPair *keyPair = nullptr;
    res = generator->generateKeyPair(generator, nullptr, &keyPair);
    HcfCipher *cipher = nullptr;
    res = HcfCipherCreate("RSA1024|PKCS1", &cipher);
    EXPECT_EQ(res, HCF_SUCCESS);

    res = cipher->init((HcfCipher *)generator, ENCRYPT_MODE, (HcfKey *)keyPair->pubKey, nullptr);
    EXPECT_NE(res, HCF_SUCCESS);

    HcfObjDestroy(generator);
    HcfObjDestroy(cipher);
    HcfObjDestroy(keyPair);
}

HWTEST_F(CryptoRsaCipherTest, CryptoRsaCipherTest900, TestSize.Level0)
{
    HcfResult res = HCF_SUCCESS;
    HcfAsyKeyGenerator *generator = nullptr;
    res = HcfAsyKeyGeneratorCreate("RSA1024|PRIMES_2", &generator);
    HcfKeyPair *keyPair = nullptr;
    res = generator->generateKeyPair(generator, nullptr, &keyPair);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(keyPair, nullptr);
    EXPECT_NE(keyPair->priKey, nullptr);
    EXPECT_NE(keyPair->pubKey, nullptr);

    HcfCipher *cipher = nullptr;
    res = HcfCipherCreate("RSA1024|PKCS1", &cipher);
    EXPECT_EQ(res, HCF_SUCCESS);

    uint8_t plan[] = "12312123123";
    HcfBlob input = {.data = (uint8_t *)plan, .len = strlen((char *)plan)};

    res = cipher->init(cipher, ENCRYPT_MODE, (HcfKey *)keyPair->pubKey, nullptr);
    EXPECT_EQ(res, HCF_SUCCESS);

    res = cipher->doFinal(cipher, &input, nullptr);
    EXPECT_NE(res, HCF_SUCCESS);

    HcfObjDestroy(keyPair);
    HcfObjDestroy(generator);
    HcfObjDestroy(cipher);
}

HWTEST_F(CryptoRsaCipherTest, CryptoRsaCipherTest910, TestSize.Level0)
{
    HcfResult res = HCF_SUCCESS;
    HcfAsyKeyGenerator *generator = nullptr;
    res = HcfAsyKeyGeneratorCreate("RSA1024|PRIMES_2", &generator);
    HcfKeyPair *keyPair = nullptr;
    res = generator->generateKeyPair(generator, nullptr, &keyPair);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(keyPair, nullptr);
    EXPECT_NE(keyPair->priKey, nullptr);
    EXPECT_NE(keyPair->pubKey, nullptr);

    HcfCipher *cipher = nullptr;
    res = HcfCipherCreate("RSA1024|PKCS1", &cipher);
    EXPECT_EQ(res, HCF_SUCCESS);

    uint8_t plan[] = "12312123123";
    HcfBlob input = {.data = (uint8_t *)plan, .len = strlen((char *)plan)};

    res = cipher->init(cipher, ENCRYPT_MODE, (HcfKey *)keyPair->pubKey, nullptr);
    EXPECT_EQ(res, HCF_SUCCESS);

    HcfBlob blob;
    res = cipher->doFinal((HcfCipher *)generator, &input, &blob);
    EXPECT_NE(res, HCF_SUCCESS);

    HcfObjDestroy(keyPair);
    HcfObjDestroy(generator);
    HcfObjDestroy(cipher);
}

HWTEST_F(CryptoRsaCipherTest, CryptoRsaCipherTest920, TestSize.Level0)
{
    HcfResult res = HCF_SUCCESS;
    HcfCipher *cipher = nullptr;
    res = HcfCipherCreate("RSA10|PK1", &cipher);
    EXPECT_NE(res, HCF_SUCCESS);
}

HWTEST_F(CryptoRsaCipherTest, CryptoRsaCipherTest930, TestSize.Level0)
{
    HcfResult res = HCF_SUCCESS;
    HcfCipher *cipher = nullptr;
    res = HcfCipherCreate("RSA1024|PKCS1|RSA1024|PKCS1|RSA1024|PKCS1|RSA1024|PKCS1|RSA1024|PKCS1|"
        "RSA1024|PKCS1|RSA1024|PKCS1|RSA1024|PKCS1|RSA1024|PKCS1|RSA1024|PKCS1", &cipher);
    EXPECT_NE(res, HCF_SUCCESS);
}

// incorrect : init Cipher twice
HWTEST_F(CryptoRsaCipherTest, CryptoRsaCipherTest940, TestSize.Level0)
{
    HcfResult res = HCF_SUCCESS;
    HcfAsyKeyGenerator *generator = nullptr;
    res = HcfAsyKeyGeneratorCreate("RSA1024|PRIMES_2", &generator);
    EXPECT_EQ(res, HCF_SUCCESS);
    HcfKeyPair *keyPair = nullptr;
    res = generator->generateKeyPair(generator, nullptr, &keyPair);
    EXPECT_EQ(res, HCF_SUCCESS);

    HcfCipher *cipher = nullptr;
    res = HcfCipherCreate("RSA1024|PKCS1", &cipher);
    EXPECT_EQ(res, HCF_SUCCESS);
    res = cipher->init(cipher, DECRYPT_MODE, (HcfKey *)keyPair->priKey, nullptr);
    EXPECT_EQ(res, HCF_SUCCESS);
    res = cipher->init(cipher, DECRYPT_MODE, (HcfKey *)keyPair->priKey, nullptr);
    EXPECT_NE(res, HCF_SUCCESS);

    HcfObjDestroy(keyPair);
    HcfObjDestroy(generator);
    HcfObjDestroy(cipher);
}

// correct: test oaep pSource normal.
HWTEST_F(CryptoRsaCipherTest, CryptoRsaCipherTest001, TestSize.Level0)
{
    uint8_t plan[] = "this is rsa cipher test!\0";
    HcfAsyKeyGenerator *generator = nullptr;
    HcfResult res = HcfAsyKeyGeneratorCreate("RSA1024|PRIMES_2", &generator);

    HcfKeyPair *keyPair = nullptr;
    res = generator->generateKeyPair(generator, nullptr, &keyPair);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(keyPair, nullptr);
    EXPECT_NE(keyPair->priKey, nullptr);
    EXPECT_NE(keyPair->pubKey, nullptr);

    HcfBlob input = {.data = (uint8_t *)plan, .len = strlen((char *)plan)};
    HcfBlob encoutput = {.data = nullptr, .len = 0};
    HcfCipher *cipher = nullptr;
    // remove 1024
    res = HcfCipherCreate("RSA|PKCS1_OAEP|SHA256|MGF1_SHA256", &cipher);
    EXPECT_EQ(res, HCF_SUCCESS);

    res = cipher->init(cipher, ENCRYPT_MODE, (HcfKey *)keyPair->pubKey, nullptr);
    EXPECT_EQ(res, HCF_SUCCESS);
    res = RsaCipherSpec(cipher);
    EXPECT_EQ(res, HCF_SUCCESS);
    res = cipher->doFinal(cipher, &input, &encoutput);
    EXPECT_EQ(res, HCF_SUCCESS);
    HcfObjDestroy(cipher);

    // decrypt
    HcfBlob decoutput = {.data = nullptr, .len = 0};
    cipher = nullptr;
    // has1024
    res = HcfCipherCreate("RSA1024|PKCS1_OAEP|SHA256|MGF1_SHA256", &cipher);
    EXPECT_EQ(res, HCF_SUCCESS);

    res = cipher->init(cipher, DECRYPT_MODE, (HcfKey *)keyPair->priKey, nullptr);
    EXPECT_EQ(res, HCF_SUCCESS);

    res = RsaCipherSpec(cipher);
    EXPECT_EQ(res, HCF_SUCCESS);

    res = cipher->doFinal(cipher, &encoutput, &decoutput);
    EXPECT_EQ(res, HCF_SUCCESS);
    HcfObjDestroy(cipher);

    EXPECT_STREQ((char *)plan, (char *)decoutput.data);

    HcfFree(encoutput.data);
    HcfFree(decoutput.data);

    HcfObjDestroy(keyPair);
    HcfObjDestroy(generator);
}

// test cipher by key generated by spec and set & get func after init.
HWTEST_F(CryptoRsaCipherTest, CryptoRsaCipherTest002, TestSize.Level0)
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
    EXPECT_NE(generator, nullptr);

    HcfKeyPair *keyPair = nullptr;
    // generator key type from generator's spec
    res = generator->generateKeyPair(generator, &keyPair);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(keyPair, nullptr);

    HcfBlob input = {.data = (uint8_t *)plan, .len = strlen((char *)plan)};
    HcfBlob encoutput = {.data = nullptr, .len = 0};
    HcfCipher *cipher = nullptr;
    // remove 1024
    res = HcfCipherCreate("RSA|PKCS1_OAEP|SHA256|MGF1_SHA256", &cipher);
    EXPECT_EQ(res, HCF_SUCCESS);

    res = cipher->init(cipher, ENCRYPT_MODE, (HcfKey *)keyPair->pubKey, nullptr);
    EXPECT_EQ(res, HCF_SUCCESS);
    res = RsaCipherSpec(cipher);
    EXPECT_EQ(res, HCF_SUCCESS);
    res = cipher->doFinal(cipher, &input, &encoutput);
    EXPECT_EQ(res, HCF_SUCCESS);
    HcfObjDestroy(cipher);

    // decrypt
    HcfBlob decoutput = {.data = nullptr, .len = 0};
    cipher = nullptr;
    // has1024
    res = HcfCipherCreate("RSA1024|PKCS1_OAEP|SHA256|MGF1_SHA256", &cipher);
    EXPECT_EQ(res, HCF_SUCCESS);

    res = cipher->init(cipher, DECRYPT_MODE, (HcfKey *)keyPair->priKey, nullptr);
    EXPECT_EQ(res, HCF_SUCCESS);

    res = RsaCipherSpec(cipher);
    EXPECT_EQ(res, HCF_SUCCESS);

    res = cipher->doFinal(cipher, &encoutput, &decoutput);
    EXPECT_EQ(res, HCF_SUCCESS);
    HcfObjDestroy(cipher);

    EXPECT_STREQ((char *)plan, (char *)decoutput.data);

    HcfFree(encoutput.data);
    HcfFree(decoutput.data);

    HcfObjDestroy(keyPair);
    HcfObjDestroy(generator);
}

// test in encrypt set pSource before init and in decrypt set pSource after init.
HWTEST_F(CryptoRsaCipherTest, CryptoRsaCipherTest003, TestSize.Level0)
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

    // test cipher encrypt psource set before cipher init.
    uint8_t pSourceData[] = "123456\0";
    HcfBlob pSource = {.data = (uint8_t *)pSourceData, .len = strlen((char *)pSourceData)};
    res = cipher->setCipherSpecUint8Array(cipher, OAEP_MGF1_PSRC_UINT8ARR, pSource);
    EXPECT_EQ(res, HCF_SUCCESS);
    res = cipher->doFinal(cipher, &input, &encoutput);
    EXPECT_EQ(res, HCF_SUCCESS);
    HcfObjDestroy(cipher);

    // decrypt
    HcfBlob decoutput = {.data = nullptr, .len = 0};
    cipher = nullptr;
    res = HcfCipherCreate("RSA1024|PKCS1_OAEP|SHA256|MGF1_SHA256", &cipher);
    EXPECT_EQ(res, HCF_SUCCESS);
    res = cipher->init(cipher, DECRYPT_MODE, (HcfKey *)keyPair->priKey, nullptr);
    EXPECT_EQ(res, HCF_SUCCESS);
    // test cipher decrypt psource set after init
    res = cipher->setCipherSpecUint8Array(cipher, OAEP_MGF1_PSRC_UINT8ARR, pSource);
    EXPECT_EQ(res, HCF_SUCCESS);
    res = cipher->doFinal(cipher, &encoutput, &decoutput);
    EXPECT_EQ(res, HCF_SUCCESS);
    HcfObjDestroy(cipher);

    EXPECT_STREQ((char *)plan, (char *)decoutput.data);

    // free decrpyt spec
    HcfFree(encoutput.data);
    HcfFree(decoutput.data);

    HcfObjDestroy(keyPair);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoRsaCipherTest, CryptoRsaCipherTest005, TestSize.Level0)
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
    EXPECT_NE(generator, nullptr);

    HcfKeyPair *keyPair = nullptr;
    // generator key type from generator's spec
    res = generator->generateKeyPair(generator, &keyPair);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(keyPair, nullptr);

    HcfBlob input = {.data = (uint8_t *)plan, .len = strlen((char *)plan)};
    HcfBlob encoutput = {.data = nullptr, .len = 0};
    HcfCipher *cipher = nullptr;
    // remove 1024
    res = HcfCipherCreate("RSA|PKCS1_OAEP|SHA256|MGF1_SHA256", &cipher);
    EXPECT_EQ(res, HCF_SUCCESS);
    res = RsaCipherSpec(cipher);
    EXPECT_EQ(res, HCF_SUCCESS);
    res = cipher->init(cipher, ENCRYPT_MODE, (HcfKey *)keyPair->pubKey, nullptr);
    EXPECT_EQ(res, HCF_SUCCESS);

    res = cipher->doFinal(cipher, &input, &encoutput);
    EXPECT_EQ(res, HCF_SUCCESS);
    HcfObjDestroy(cipher);

    // decrypt
    HcfBlob decoutput = {.data = nullptr, .len = 0};
    cipher = nullptr;
    // has1024
    res = HcfCipherCreate("RSA1024|PKCS1_OAEP|SHA256|MGF1_SHA256", &cipher);
    EXPECT_EQ(res, HCF_SUCCESS);

    res = cipher->init(cipher, DECRYPT_MODE, (HcfKey *)keyPair->priKey, nullptr);
    EXPECT_EQ(res, HCF_SUCCESS);

    res = RsaCipherSpec(cipher);
    EXPECT_EQ(res, HCF_SUCCESS);

    res = cipher->doFinal(cipher, &encoutput, &decoutput);
    EXPECT_EQ(res, HCF_SUCCESS);
    HcfObjDestroy(cipher);

    EXPECT_STREQ((char *)plan, (char *)decoutput.data);

    HcfFree(encoutput.data);
    HcfFree(decoutput.data);

    HcfObjDestroy(keyPair);
    HcfObjDestroy(generator);
}

// double set test
HWTEST_F(CryptoRsaCipherTest, CryptoRsaCipherTest004, TestSize.Level0)
{
    uint8_t plan[] = "This is cipher test.\0";
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
    EXPECT_NE(keyPair->priKey, nullptr);
    EXPECT_NE(keyPair->pubKey, nullptr);

    HcfBlob input = {.data = (uint8_t *)plan, .len = strlen((char *)plan)};
    HcfBlob encoutput = {.data = nullptr, .len = 0};
    HcfCipher *cipher = nullptr;
    res = HcfCipherCreate("RSA|PKCS1_OAEP|SHA256|MGF1_SHA256", &cipher);
    EXPECT_EQ(res, HCF_SUCCESS);

    uint8_t pSourceData[] = "123456\0";
    HcfBlob pSource = {.data = (uint8_t *)pSourceData, .len = strlen((char *)pSourceData)};
    res = RsaSpecpSource(cipher, pSourceData, pSource);
    EXPECT_EQ(res, HCF_SUCCESS);

    res = cipher->init(cipher, ENCRYPT_MODE, (HcfKey *)keyPair->pubKey, nullptr);
    EXPECT_EQ(res, HCF_SUCCESS);
    res = cipher->doFinal(cipher, &input, &encoutput);
    EXPECT_EQ(res, HCF_SUCCESS);
    HcfObjDestroy(cipher);

    HcfBlob decoutput = {.data = nullptr, .len = 0};
    cipher = nullptr;
    res = HcfCipherCreate("RSA|PKCS1_OAEP|SHA256|MGF1_SHA256", &cipher);
    EXPECT_EQ(res, HCF_SUCCESS);
    // decrypt set before init
    res = cipher->setCipherSpecUint8Array(cipher, OAEP_MGF1_PSRC_UINT8ARR, pSource);
    EXPECT_EQ(res, HCF_SUCCESS);

    res = cipher->init(cipher, DECRYPT_MODE, (HcfKey *)keyPair->priKey, nullptr);
    EXPECT_EQ(res, HCF_SUCCESS);
    res = cipher->doFinal(cipher, &encoutput, &decoutput);
    EXPECT_EQ(res, HCF_SUCCESS);
    HcfObjDestroy(cipher);
    EXPECT_STREQ((char *)plan, (char *)decoutput.data);

    HcfFree(encoutput.data);
    HcfFree(decoutput.data);

    HcfObjDestroy(keyPair);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoRsaCipherTest, CryptoRsaCipherTest007, TestSize.Level0)
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

    HcfBlob pSource = { .data = nullptr, .len = 0 };
    // self == nullptr
    res = cipher->setCipherSpecUint8Array(nullptr, OAEP_MGF1_PSRC_UINT8ARR, pSource);
    EXPECT_NE(res, HCF_SUCCESS);
    res = cipher->doFinal(cipher, &input, &encoutput);
    EXPECT_EQ(res, HCF_SUCCESS);
    HcfObjDestroy(cipher);

    // decrypt
    HcfBlob decoutput = {.data = nullptr, .len = 0};
    cipher = nullptr;
    res = HcfCipherCreate("RSA1024|PKCS1_OAEP|SHA256|MGF1_SHA256", &cipher);
    EXPECT_EQ(res, HCF_SUCCESS);
    res = cipher->init(cipher, DECRYPT_MODE, (HcfKey *)keyPair->priKey, nullptr);
    EXPECT_EQ(res, HCF_SUCCESS);
    res = cipher->doFinal(cipher, &encoutput, &decoutput);
    EXPECT_EQ(res, HCF_SUCCESS);
    HcfObjDestroy(cipher);

    EXPECT_STREQ((char *)plan, (char *)decoutput.data);

    // free decrpyt spec
    HcfFree(encoutput.data);
    HcfFree(decoutput.data);

    HcfObjDestroy(keyPair);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoRsaCipherTest, CryptoRsaCipherTest008, TestSize.Level0)
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
    res = cipher->setCipherSpecUint8Array(cipher, OAEP_MD_NAME_STR, pSource);
    EXPECT_NE(res, HCF_SUCCESS);
    res = cipher->doFinal(cipher, &input, &encoutput);
    EXPECT_EQ(res, HCF_SUCCESS);
    HcfObjDestroy(cipher);

    // decrypt
    HcfBlob decoutput = {.data = nullptr, .len = 0};
    cipher = nullptr;
    res = HcfCipherCreate("RSA1024|PKCS1_OAEP|SHA256|MGF1_SHA256", &cipher);
    EXPECT_EQ(res, HCF_SUCCESS);
    res = cipher->init(cipher, DECRYPT_MODE, (HcfKey *)keyPair->priKey, nullptr);
    EXPECT_EQ(res, HCF_SUCCESS);
    res = cipher->doFinal(cipher, &encoutput, &decoutput);
    EXPECT_EQ(res, HCF_SUCCESS);
    HcfObjDestroy(cipher);

    EXPECT_STREQ((char *)plan, (char *)decoutput.data);

    // free decrpyt spec
    HcfFree(encoutput.data);
    HcfFree(decoutput.data);

    HcfObjDestroy(keyPair);
    HcfObjDestroy(generator);
}

// get func exception
HWTEST_F(CryptoRsaCipherTest, CryptoRsaCipherTest010, TestSize.Level0)
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
    res = HcfCipherCreate("RSA|PKCS1_OAEP|SHA256|MGF1_SHA256", &cipher);
    EXPECT_EQ(res, HCF_SUCCESS);
    res = cipher->getCipherSpecString(cipher, OAEP_MD_NAME_STR, nullptr);
    EXPECT_NE(res, HCF_SUCCESS);
    HcfObjDestroy(cipher);

    HcfObjDestroy(keyPair);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoRsaCipherTest, CryptoRsaCipherTest011, TestSize.Level0)
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
    res = HcfCipherCreate("RSA|PKCS1_OAEP|SHA256|MGF1_SHA256", &cipher);
    EXPECT_EQ(res, HCF_SUCCESS);
    res = cipher->getCipherSpecString(nullptr, OAEP_MD_NAME_STR, nullptr);
    EXPECT_NE(res, HCF_SUCCESS);
    HcfObjDestroy(cipher);

    HcfObjDestroy(keyPair);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoRsaCipherTest, CryptoRsaCipherTest012, TestSize.Level0)
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
    res = cipher->getCipherSpecString(cipher, OAEP_MGF1_PSRC_UINT8ARR, &ret);
    EXPECT_NE(res, HCF_SUCCESS);
    EXPECT_EQ(ret, nullptr);

    HcfObjDestroy(cipher);

    HcfObjDestroy(keyPair);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoRsaCipherTest, CryptoRsaCipherTest014, TestSize.Level0)
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
    res = HcfCipherCreate("RSA|PKCS1_OAEP|SHA256|MGF1_SHA256", &cipher);
    EXPECT_EQ(res, HCF_SUCCESS);
    res = cipher->getCipherSpecUint8Array(cipher, OAEP_MD_NAME_STR, nullptr);
    EXPECT_NE(res, HCF_SUCCESS);
    HcfObjDestroy(cipher);

    HcfObjDestroy(keyPair);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoRsaCipherTest, CryptoRsaCipherTest015, TestSize.Level0)
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
    res = HcfCipherCreate("RSA|PKCS1_OAEP|SHA256|MGF1_SHA256", &cipher);
    EXPECT_EQ(res, HCF_SUCCESS);
    res = cipher->getCipherSpecUint8Array(nullptr, OAEP_MD_NAME_STR, nullptr);
    EXPECT_NE(res, HCF_SUCCESS);
    HcfObjDestroy(cipher);

    HcfObjDestroy(keyPair);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoRsaCipherTest, CryptoRsaCipherTest016, TestSize.Level0)
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
    res = cipher->getCipherSpecUint8Array(cipher, OAEP_MD_NAME_STR, &retBlob);
    EXPECT_NE(res, HCF_SUCCESS);
    EXPECT_EQ(retBlob.data, nullptr);

    HcfObjDestroy(cipher);

    HcfObjDestroy(keyPair);
    HcfObjDestroy(generator);
}
}
