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
#include "cstring"
#include "securec.h"
#include "asy_key_generator.h"
#include "blob.h"
#include "detailed_rsa_key_params.h"
#include "memory.h"
#include "openssl_common.h"
#include "md.h"
#include "signature.h"
#include "crypto_operation_err.h"
#include <gmock/gmock.h>
#include <string>

using namespace std;
using namespace testing::ext;

namespace {
class CryptoRsaOnlySignAndVerifyRecoverTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp();
    void TearDown();
};

void CryptoRsaOnlySignAndVerifyRecoverTest::SetUp() {}
void CryptoRsaOnlySignAndVerifyRecoverTest::TearDown() {}
void CryptoRsaOnlySignAndVerifyRecoverTest::SetUpTestCase() {}
void CryptoRsaOnlySignAndVerifyRecoverTest::TearDownTestCase() {}

static const char *const MGF_ALL6[] = {"MGF1_MD5", "MGF1_SHA1", "MGF1_SHA224", "MGF1_SHA256", "MGF1_SHA384",
    "MGF1_SHA512"};
static const char *const MGF_ALL4[] = {"MGF1_MD5", "MGF1_SHA1", "MGF1_SHA224", "MGF1_SHA256"};
static const char *const MGF_ALL3[] = {"MGF1_MD5", "MGF1_SHA1", "MGF1_SHA224"};
static const char *const MGF_768_SHA256[] = {"MGF1_MD5", "MGF1_SHA1", "MGF1_SHA224", "MGF1_SHA256", "MGF1_SHA384"};
static const char *const MGF_768_SHA384[] = {"MGF1_MD5", "MGF1_SHA1", "MGF1_SHA224", "MGF1_SHA256"};
static const char *const MGF_768_SHA512[] = {"MGF1_MD5", "MGF1_SHA1", "MGF1_SHA224"};
static const char *const MGF_1024_SHA512[] = {"MGF1_MD5", "MGF1_SHA1", "MGF1_SHA224", "MGF1_SHA256", "MGF1_SHA384"};

static const char *PUB_KEY_PEM = "-----BEGIN PUBLIC KEY-----\n"
    "MFwwDQYJKoZIhvcNAQEBBQADSwAwSAJBAMbBy16dEX7ro5/rRYmmXRbCZAng5sTf\n"
    "pGBTyCAzHDhGjsFOcMQbyh5TCc/kw11ws/MaKEn0bKvB9lnvCOOZ/isCAwEAAQ==\n"
    "-----END PUBLIC KEY-----\n";

static const char *PRI_KEY_PEM = "-----BEGIN PRIVATE KEY-----\n"
    "MIIBVQIBADANBgkqhkiG9w0BAQEFAASCAT8wggE7AgEAAkEAxsHLXp0Rfuujn+tF\n"
    "iaZdFsJkCeDmxN+kYFPIIDMcOEaOwU5wxBvKHlMJz+TDXXCz8xooSfRsq8H2We8I\n"
    "45n+KwIDAQABAkBZat4/lpJEc2aNj58dKkc+8f1npFKtx59/5rFmKxhLCEb1/b85\n"
    "52FfEo3aAJUj8ovfyYz35f1qNPDASZVb84KBAiEA/JKFvd1l1t2qiC/TlRZcTvs0\n"
    "mC9wfHyenpxctZW7nZsCIQDJdE8G0ElsTXCU9yaML1ObF98Py7hwjA6VNASKVsly\n"
    "sQIhAIP0DNlf1LfHwTM7QWAPeZRt21Fy32K6PKiC6lCX9JfnAiEAx3mIasnBeiDv\n"
    "8kELhVGzamXntJ9XIPI92lVojYbD7/ECIAjanPRYhn2VRgaINs1wkxNLoRX5T/p1\n"
    "kGn3cDeQIbhO\n"
    "-----END PRIVATE KEY-----\n";

static void RsaOnlySignCreateTest(const char *algoName)
{
    HcfResult res = HCF_SUCCESS;
    HcfSign *sign = nullptr;
    res = HcfSignCreate(algoName, &sign);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(sign, nullptr);
    EXPECT_NE(sign->base.getClass(), nullptr);
    EXPECT_NE(sign->base.destroy, nullptr);
    EXPECT_NE(sign->init, nullptr);
    EXPECT_NE(sign->update, nullptr);
    EXPECT_NE(sign->sign, nullptr);
    HcfObjDestroy(sign);
}

static void RsaOnlyVerifyCreateTest(const char *algoName)
{
    HcfResult res = HCF_SUCCESS;
    HcfVerify *verify = nullptr;
    res = HcfVerifyCreate(algoName, &verify);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(verify, nullptr);
    EXPECT_NE(verify->base.getClass(), nullptr);
    EXPECT_NE(verify->base.destroy, nullptr);
    EXPECT_NE(verify->init, nullptr);
    EXPECT_NE(verify->update, nullptr);
    EXPECT_NE(verify->verify, nullptr);
    HcfObjDestroy(verify);
}

static void RsaOnlySignCreateIncorrectTest(const char *algoName, HcfResult ret)
{
    HcfResult res = HCF_SUCCESS;
    HcfSign *sign = nullptr;
    res = HcfSignCreate(algoName, &sign);
    EXPECT_EQ(res, ret);
    EXPECT_EQ(sign, nullptr);
}

static void RsaOnlySignTest(const char *keyAlgoName, const char *algoName, const char *plan)
{
    HcfResult res = HCF_SUCCESS;
    HcfAsyKeyGenerator *generator = nullptr;
    res = HcfAsyKeyGeneratorCreate(keyAlgoName, &generator);
    HcfKeyPair *keyPair = nullptr;
    res = generator->generateKeyPair(generator, nullptr, &keyPair);
    EXPECT_EQ(res, HCF_SUCCESS);

    HcfPriKey *prikey = keyPair->priKey;
    HcfBlob input = {.data = (uint8_t *)plan, .len = strlen(plan)};
    HcfBlob verifyData = {.data = nullptr, .len = 0};
    HcfSign *sign = nullptr;
    res = HcfSignCreate(algoName, &sign);
    EXPECT_EQ(res, HCF_SUCCESS);
    res = sign->init(sign, nullptr, prikey);
    EXPECT_EQ(res, HCF_SUCCESS);
    res = sign->sign(sign, &input, &verifyData);
    EXPECT_EQ(res, HCF_SUCCESS);

    HcfObjDestroy(sign);
    HcfFree(verifyData.data);
    HcfObjDestroy(keyPair);
    HcfObjDestroy(generator);
}

static void RsaOnlySignIncorrectTest(const char *keyAlgoName, const char *algoName, const char *plan)
{
    HcfResult res = HCF_SUCCESS;
    HcfAsyKeyGenerator *generator = nullptr;
    res = HcfAsyKeyGeneratorCreate(keyAlgoName, &generator);
    HcfKeyPair *keyPair = nullptr;
    res = generator->generateKeyPair(generator, nullptr, &keyPair);
    EXPECT_EQ(res, HCF_SUCCESS);

    HcfPriKey *prikey = keyPair->priKey;
    HcfBlob input = {.data = (uint8_t *)plan, .len = strlen(plan)};
    HcfBlob verifyData = {.data = nullptr, .len = 0};
    HcfSign *sign = nullptr;
    res = HcfSignCreate(algoName, &sign);
    EXPECT_EQ(res, HCF_SUCCESS);
    res = sign->init(sign, nullptr, prikey);
    EXPECT_EQ(res, HCF_SUCCESS);
    res = sign->sign(sign, &input, &verifyData);
    EXPECT_EQ(res, HCF_ERR_CRYPTO_OPERATION);

    HcfObjDestroy(sign);
    HcfObjDestroy(keyPair);
    HcfObjDestroy(generator);
}

static void RsaOnlySignVerifyDigestTest(const char *keyAlgoName, const char *mdName,
    const char *signAlgoName, const char *verifyAlgoName)
{
    HcfResult res = HCF_SUCCESS;
    HcfAsyKeyGenerator *generator = nullptr;
    res = HcfAsyKeyGeneratorCreate(keyAlgoName, &generator);
    EXPECT_EQ(res, HCF_SUCCESS);

    HcfKeyPair *keyPair = nullptr;
    if (strcmp(keyAlgoName, "RSA512") == 0) {
        res = generator->convertPemKey(generator, nullptr, PUB_KEY_PEM, PRI_KEY_PEM, &keyPair);
    } else {
        res = generator->generateKeyPair(generator, nullptr, &keyPair);
    }
    EXPECT_EQ(res, HCF_SUCCESS);

    uint8_t plan[] = "this is rsa only sign verify test.";
    HcfBlob input = {.data = plan, .len = strlen((char *)plan)};
    HcfBlob digest = {.data = nullptr, .len = 0};

    HcfMd *mdObj = nullptr;
    res = HcfMdCreate(mdName, &mdObj);
    ASSERT_EQ(res, HCF_SUCCESS);
    res = mdObj->update(mdObj, &input);
    EXPECT_EQ(res, HCF_SUCCESS);
    res = mdObj->doFinal(mdObj, &digest);
    EXPECT_EQ(res, HCF_SUCCESS);

    HcfSign *sign = nullptr;
    res = HcfSignCreate(signAlgoName, &sign);
    EXPECT_EQ(res, HCF_SUCCESS);
    res = sign->init(sign, nullptr, keyPair->priKey);
    EXPECT_EQ(res, HCF_SUCCESS);
    res = sign->update(sign, &digest);
    EXPECT_EQ(res, HCF_ERR_CRYPTO_OPERATION);
    HcfBlob signatureData = {.data = nullptr, .len = 0};
    res = sign->sign(sign, &digest, &signatureData);
    EXPECT_EQ(res, HCF_SUCCESS);
    HcfObjDestroy(sign);

    HcfVerify *verify = nullptr;
    res = HcfVerifyCreate(verifyAlgoName, &verify);
    EXPECT_EQ(res, HCF_SUCCESS);
    res = verify->init(verify, nullptr, keyPair->pubKey);
    EXPECT_EQ(res, HCF_SUCCESS);
    res = verify->update(verify, &digest);
    EXPECT_EQ(res, HCF_ERR_INVALID_CALL);
    bool result = verify->verify(verify, &digest, &signatureData);
    EXPECT_EQ(result, true);

    HcfObjDestroy(verify);
    HcfObjDestroy(mdObj);
    HcfFree(signatureData.data);
    HcfBlobDataClearAndFree(&digest);
    HcfObjDestroy(keyPair);
    HcfObjDestroy(generator);
}

#define ERROR_MSG_BUFFER_LEN 256
static void RsaOnlySignVerifyDigestTestError(const char *keyAlgoName, const char *mdName,
    const char *signAlgoName, const char *verifyAlgoName)
{
    HcfResult res = HCF_SUCCESS;
    HcfAsyKeyGenerator *generator = nullptr;
    res = HcfAsyKeyGeneratorCreate(keyAlgoName, &generator);
    EXPECT_EQ(res, HCF_SUCCESS);

    HcfKeyPair *keyPair = nullptr;
    res = generator->generateKeyPair(generator, nullptr, &keyPair);
    EXPECT_EQ(res, HCF_SUCCESS);

    uint8_t plan[] = "this is rsa only sign verify test.";
    HcfBlob input = {.data = plan, .len = strlen((char *)plan)};
    HcfBlob digest = {.data = nullptr, .len = 0};

    HcfMd *mdObj = nullptr;
    res = HcfMdCreate(mdName, &mdObj);
    ASSERT_EQ(res, HCF_SUCCESS);
    res = mdObj->update(mdObj, &input);
    EXPECT_EQ(res, HCF_SUCCESS);
    res = mdObj->doFinal(mdObj, &digest);
    EXPECT_EQ(res, HCF_SUCCESS);

    HcfSign *sign = nullptr;
    res = HcfSignCreate(signAlgoName, &sign);
    EXPECT_EQ(res, HCF_SUCCESS);
    res = sign->init(sign, nullptr, keyPair->priKey);
    EXPECT_EQ(res, HCF_SUCCESS);
    res = sign->update(sign, &digest);
    EXPECT_EQ(res, HCF_ERR_CRYPTO_OPERATION);
    HcfBlob signatureData = {.data = nullptr, .len = 0};
    res = sign->sign(sign, &digest, &signatureData);
    EXPECT_EQ(res, HCF_ERR_CRYPTO_OPERATION);
    char buff[ERROR_MSG_BUFFER_LEN] = { 0 };
    (void)HcfGetOperationErrorMessage(buff, ERROR_MSG_BUFFER_LEN);
    EXPECT_NE(strlen(buff), 0);
    HcfObjDestroy(sign);

    HcfObjDestroy(mdObj);
    HcfBlobDataClearAndFree(&digest);
    HcfObjDestroy(keyPair);
    HcfObjDestroy(generator);
}

static bool RunRsaPssDigestCases(const char *size, const char *digest, const char *const *mgfList, size_t mgfCount)
{
    for (size_t i = 0; i < mgfCount; ++i) {
        bool hasFailureBefore = ::testing::Test::HasFailure();
        std::string signAlgo = std::string(size) + "|PSS|" + digest + "|" + mgfList[i] + "|OnlySign";
        std::string verifyAlgo = std::string(size) + "|PSS|" + digest + "|" + mgfList[i] + "|OnlyVerify";
        RsaOnlySignVerifyDigestTest(size, digest, signAlgo.c_str(), verifyAlgo.c_str());
        if (!hasFailureBefore && ::testing::Test::HasFailure()) {
            return false;
        }
    }
    return true;
}

// HcfSignCreate OnlySign correct_case
HWTEST_F(CryptoRsaOnlySignAndVerifyRecoverTest, CryptoRsaOnlySignTest100, TestSize.Level0)
{
    RsaOnlySignCreateTest("RSA512|PKCS1|NoHash|OnlySign");
    RsaOnlySignCreateTest("RSA512|PKCS1|MD5|OnlySign");
    RsaOnlySignCreateTest("RSA512|PKCS1|SHA1|OnlySign");
    RsaOnlySignCreateTest("RSA512|PKCS1|SHA224|OnlySign");
    RsaOnlySignCreateTest("RSA512|PKCS1|SHA256|OnlySign");
    RsaOnlySignCreateTest("RSA512|PKCS1|SHA384|OnlySign");
}

HWTEST_F(CryptoRsaOnlySignAndVerifyRecoverTest, CryptoRsaOnlySignTest110, TestSize.Level0)
{
    RsaOnlySignCreateTest("RSA768|PKCS1|NoHash|OnlySign");
    RsaOnlySignCreateTest("RSA768|PKCS1|MD5|OnlySign");
    RsaOnlySignCreateTest("RSA768|PKCS1|SHA1|OnlySign");
    RsaOnlySignCreateTest("RSA768|PKCS1|SHA224|OnlySign");
    RsaOnlySignCreateTest("RSA768|PKCS1|SHA256|OnlySign");
    RsaOnlySignCreateTest("RSA768|PKCS1|SHA384|OnlySign");
    RsaOnlySignCreateTest("RSA768|PKCS1|SHA512|OnlySign");
}

HWTEST_F(CryptoRsaOnlySignAndVerifyRecoverTest, CryptoRsaOnlySignTest120, TestSize.Level0)
{
    RsaOnlySignCreateTest("RSA1024|PKCS1|NoHash|OnlySign");
    RsaOnlySignCreateTest("RSA1024|PKCS1|MD5|OnlySign");
    RsaOnlySignCreateTest("RSA1024|PKCS1|SHA1|OnlySign");
    RsaOnlySignCreateTest("RSA1024|PKCS1|SHA224|OnlySign");
    RsaOnlySignCreateTest("RSA1024|PKCS1|SHA256|OnlySign");
    RsaOnlySignCreateTest("RSA1024|PKCS1|SHA384|OnlySign");
    RsaOnlySignCreateTest("RSA1024|PKCS1|SHA512|OnlySign");
}

HWTEST_F(CryptoRsaOnlySignAndVerifyRecoverTest, CryptoRsaOnlySignTest130, TestSize.Level0)
{
    RsaOnlySignCreateTest("RSA2048|PKCS1|NoHash|OnlySign");
    RsaOnlySignCreateTest("RSA2048|PKCS1|MD5|OnlySign");
    RsaOnlySignCreateTest("RSA2048|PKCS1|SHA1|OnlySign");
    RsaOnlySignCreateTest("RSA2048|PKCS1|SHA224|OnlySign");
    RsaOnlySignCreateTest("RSA2048|PKCS1|SHA256|OnlySign");
    RsaOnlySignCreateTest("RSA2048|PKCS1|SHA384|OnlySign");
    RsaOnlySignCreateTest("RSA2048|PKCS1|SHA512|OnlySign");
}

HWTEST_F(CryptoRsaOnlySignAndVerifyRecoverTest, CryptoRsaOnlySignTest140, TestSize.Level0)
{
    RsaOnlySignCreateTest("RSA3072|PKCS1|NoHash|OnlySign");
    RsaOnlySignCreateTest("RSA3072|PKCS1|MD5|OnlySign");
    RsaOnlySignCreateTest("RSA3072|PKCS1|SHA1|OnlySign");
    RsaOnlySignCreateTest("RSA3072|PKCS1|SHA224|OnlySign");
    RsaOnlySignCreateTest("RSA3072|PKCS1|SHA256|OnlySign");
    RsaOnlySignCreateTest("RSA3072|PKCS1|SHA384|OnlySign");
    RsaOnlySignCreateTest("RSA3072|PKCS1|SHA512|OnlySign");
}

HWTEST_F(CryptoRsaOnlySignAndVerifyRecoverTest, CryptoRsaOnlySignTest150, TestSize.Level0)
{
    RsaOnlySignCreateTest("RSA4096|PKCS1|NoHash|OnlySign");
    RsaOnlySignCreateTest("RSA4096|PKCS1|MD5|OnlySign");
    RsaOnlySignCreateTest("RSA4096|PKCS1|SHA1|OnlySign");
    RsaOnlySignCreateTest("RSA4096|PKCS1|SHA224|OnlySign");
    RsaOnlySignCreateTest("RSA4096|PKCS1|SHA256|OnlySign");
    RsaOnlySignCreateTest("RSA4096|PKCS1|SHA384|OnlySign");
    RsaOnlySignCreateTest("RSA4096|PKCS1|SHA512|OnlySign");
}

HWTEST_F(CryptoRsaOnlySignAndVerifyRecoverTest, CryptoRsaOnlySignTest160, TestSize.Level0)
{
    RsaOnlySignCreateTest("RSA8192|PKCS1|NoHash|OnlySign");
    RsaOnlySignCreateTest("RSA8192|PKCS1|MD5|OnlySign");
    RsaOnlySignCreateTest("RSA8192|PKCS1|SHA1|OnlySign");
    RsaOnlySignCreateTest("RSA8192|PKCS1|SHA224|OnlySign");
    RsaOnlySignCreateTest("RSA8192|PKCS1|SHA256|OnlySign");
    RsaOnlySignCreateTest("RSA8192|PKCS1|SHA384|OnlySign");
    RsaOnlySignCreateTest("RSA8192|PKCS1|SHA512|OnlySign");
}

HWTEST_F(CryptoRsaOnlySignAndVerifyRecoverTest, CryptoRsaOnlySignTest170, TestSize.Level0)
{
    RsaOnlySignCreateTest("RSA512|NoPadding|NoHash|OnlySign");
    RsaOnlySignCreateTest("RSA768|NoPadding|NoHash|OnlySign");
    RsaOnlySignCreateTest("RSA1024|NoPadding|NoHash|OnlySign");
    RsaOnlySignCreateTest("RSA2048|NoPadding|NoHash|OnlySign");
    RsaOnlySignCreateTest("RSA3072|NoPadding|NoHash|OnlySign");
    RsaOnlySignCreateTest("RSA4096|NoPadding|NoHash|OnlySign");
    RsaOnlySignCreateTest("RSA8192|NoPadding|NoHash|OnlySign");
}

// HcfSignCreate OnlySign Incorrect case
HWTEST_F(CryptoRsaOnlySignAndVerifyRecoverTest, CryptoRsaOnlySignTest180, TestSize.Level0)
{
    RsaOnlySignCreateIncorrectTest("RSA1024aa|PKCS1|SHA256|OnlySign", HCF_INVALID_PARAMS);
    RsaOnlySignCreateIncorrectTest("RSA1024|PKCS1aa|SHA256|OnlySign", HCF_INVALID_PARAMS);
    RsaOnlySignCreateIncorrectTest("RSA1024|PKCS1|SHA256aa|OnlySign", HCF_INVALID_PARAMS);
    RsaOnlySignCreateIncorrectTest("RSA1024|PKCS1|SHA256|OnlySignaa", HCF_INVALID_PARAMS);
    RsaOnlySignCreateIncorrectTest("RSA1024|PKCS1|SHA256|123123123123123123212312312321"
        "123123123123213asdasdasdasdasdasdasdasdasdasdasdasdasdsasdasds12|OnlySign", HCF_INVALID_PARAMS);
    RsaOnlySignCreateIncorrectTest("DSA1024|PKCS1|SHA256|OnlySign", HCF_NOT_SUPPORT);
}

// incorrect case : OnlySign init signer with nullptr private key.
HWTEST_F(CryptoRsaOnlySignAndVerifyRecoverTest, CryptoRsaOnlySignTest270, TestSize.Level0)
{
    HcfResult res = HCF_SUCCESS;
    HcfSign *sign = nullptr;
    res = HcfSignCreate("RSA1024|PKCS1|NoHash|OnlySign", &sign);
    EXPECT_EQ(res, HCF_SUCCESS);

    res = sign->init(sign, nullptr, nullptr);
    EXPECT_EQ(res, HCF_INVALID_PARAMS);

    HcfObjDestroy(sign);
}

// incorrect case : OnlySign init signer with public Key.
HWTEST_F(CryptoRsaOnlySignAndVerifyRecoverTest, CryptoRsaOnlySignTest280, TestSize.Level0)
{
    HcfResult res = HCF_SUCCESS;
    HcfAsyKeyGenerator *generator = nullptr;
    res = HcfAsyKeyGeneratorCreate("RSA1024|PRIMES_2", &generator);
    HcfKeyPair *keyPair = nullptr;
    res = generator->generateKeyPair(generator, nullptr, &keyPair);
    EXPECT_EQ(res, HCF_SUCCESS);

    HcfSign *sign = nullptr;
    res = HcfSignCreate("RSA1024|PKCS1|NoHash|OnlySign", &sign);
    EXPECT_EQ(res, HCF_SUCCESS);

    HcfPubKey *pubKey = keyPair->pubKey;

    res = sign->init(sign, nullptr, (HcfPriKey *)pubKey);
    EXPECT_EQ(res, HCF_INVALID_PARAMS);

    HcfObjDestroy(sign);
    HcfObjDestroy(generator);
    HcfObjDestroy(keyPair);
}

// incorrect case : OnlySign use update function.
HWTEST_F(CryptoRsaOnlySignAndVerifyRecoverTest, CryptoRsaOnlySignTest290, TestSize.Level0)
{
    HcfResult res = HCF_SUCCESS;
    HcfSign *sign = nullptr;
    res = HcfSignCreate("RSA1024|PKCS1|NoHash|OnlySign", &sign);
    EXPECT_EQ(res, HCF_SUCCESS);
    uint8_t plan[] = "this is rsa verify test.";
    HcfBlob input = {.data = plan, .len = strlen((char *)plan)};
    HcfAsyKeyGenerator *generator = nullptr;
    res = HcfAsyKeyGeneratorCreate("RSA1024|PRIMES_2", &generator);
    HcfKeyPair *keyPair = nullptr;
    res = generator->generateKeyPair(generator, nullptr, &keyPair);
    EXPECT_EQ(res, HCF_SUCCESS);

    HcfPriKey *prikey = keyPair->priKey;
    res = sign->init(sign, nullptr, prikey);
    EXPECT_EQ(res, HCF_SUCCESS);
    res = sign->update(sign, &input);
    EXPECT_EQ(res, HCF_ERR_CRYPTO_OPERATION);

    HcfObjDestroy(sign);
    HcfObjDestroy(keyPair);
    HcfObjDestroy(generator);
}

// incorrect case : use OnlySign sign function before intialize.
HWTEST_F(CryptoRsaOnlySignAndVerifyRecoverTest, CryptoRsaOnlySignTest291, TestSize.Level0)
{
    HcfResult res = HCF_SUCCESS;

    HcfSign *sign = nullptr;
    res = HcfSignCreate("RSA1024|PKCS1|NoHash|OnlySign", &sign);
    EXPECT_EQ(res, HCF_SUCCESS);

    uint8_t plan[] = "this is rsa verify test.";
    HcfBlob input = {.data = plan, .len = strlen((char *)plan)};
    HcfBlob signatureData = {.data = nullptr, .len = 0};
    res = sign->sign(sign, &input, &signatureData);
    EXPECT_EQ(res, HCF_INVALID_PARAMS);

    HcfObjDestroy(sign);
}

// incorrect case : OnlySign sign with nullptr outputBlob.
HWTEST_F(CryptoRsaOnlySignAndVerifyRecoverTest, CryptoRsaOnlySignTest292, TestSize.Level0)
{
    HcfResult res = HCF_SUCCESS;
    HcfSign *sign = nullptr;
    res = HcfSignCreate("RSA1024|PKCS1|NoHash|OnlySign", &sign);
    EXPECT_EQ(res, HCF_SUCCESS);
    HcfAsyKeyGenerator *generator = nullptr;
    res = HcfAsyKeyGeneratorCreate("RSA1024|PRIMES_2", &generator);
    HcfKeyPair *keyPair = nullptr;
    res = generator->generateKeyPair(generator, nullptr, &keyPair);
    EXPECT_EQ(res, HCF_SUCCESS);

    HcfPriKey *prikey = keyPair->priKey;
    res = sign->init(sign, nullptr, prikey);
    EXPECT_EQ(res, HCF_SUCCESS);
    res = sign->sign(sign, nullptr, nullptr);
    EXPECT_EQ(res, HCF_INVALID_PARAMS);

    HcfObjDestroy(sign);
    HcfObjDestroy(keyPair);
    HcfObjDestroy(generator);
}

// correct case: OnlySign init and sign
HWTEST_F(CryptoRsaOnlySignAndVerifyRecoverTest, CryptoRsaOnlySignTest300, TestSize.Level0)
{
    RsaOnlySignTest("RSA512|PRIMES_2", "RSA512|PKCS1|NoHash|OnlySign", "01234567890123456789");
    RsaOnlySignTest("RSA1024|PRIMES_2", "RSA1024|PKCS1|NoHash|OnlySign", "01234567890123456789");
    RsaOnlySignTest("RSA2048|PRIMES_2", "RSA2048|PKCS1|NoHash|OnlySign", "01234567890123456789");
    RsaOnlySignTest("RSA4096|PRIMES_2", "RSA4096|PKCS1|NoHash|OnlySign", "01234567890123456789");
}

HWTEST_F(CryptoRsaOnlySignAndVerifyRecoverTest, CryptoRsaOnlySignTest310, TestSize.Level0)
{
    RsaOnlySignTest("RSA1024|PRIMES_2", "RSA1024|NoPadding|NoHash|OnlySign",
        "0123456789012345678901234567890123456789012345678901234567890123456789"
        "0123456789012345678901234567890123456789012345678901234567");
}

HWTEST_F(CryptoRsaOnlySignAndVerifyRecoverTest, CryptoRsaOnlySignTest320, TestSize.Level0)
{
    RsaOnlySignTest("RSA1024|PRIMES_2", "RSA1024|PKCS1|MD5|OnlySign", "0123456789012345");
    RsaOnlySignTest("RSA1024|PRIMES_2", "RSA1024|PKCS1|SHA1|OnlySign", "01234567890123456789");
    RsaOnlySignTest("RSA1024|PRIMES_2", "RSA1024|PKCS1|SHA224|OnlySign",
        "0123456789012345678901234567");
    RsaOnlySignTest("RSA1024|PRIMES_2", "RSA1024|PKCS1|SHA256|OnlySign",
        "01234567890123456789012345678901");
    RsaOnlySignTest("RSA1024|PRIMES_2", "RSA1024|PKCS1|SHA384|OnlySign",
        "012345678901234567890123456789012345678901234567");
    RsaOnlySignTest("RSA1024|PRIMES_2", "RSA1024|PKCS1|SHA512|OnlySign",
        "0123456789012345678901234567890123456789012345678901234567890123");
}

// incorrect case: OnlySign init and sign
HWTEST_F(CryptoRsaOnlySignAndVerifyRecoverTest, CryptoRsaOnlySignTest330, TestSize.Level0)
{
    RsaOnlySignIncorrectTest("RSA1024|PRIMES_2", "RSA1024|PKCS1|MD5|OnlySign", "012345678901234");
    RsaOnlySignIncorrectTest("RSA1024|PRIMES_2", "RSA1024|PKCS1|MD5|OnlySign", "01234567890123456");

    RsaOnlySignIncorrectTest("RSA1024|PRIMES_2", "RSA1024|PKCS1|SHA1|OnlySign", "0123456789012345678");
    RsaOnlySignIncorrectTest("RSA1024|PRIMES_2", "RSA1024|PKCS1|SHA1|OnlySign", "012345678901234567890");

    RsaOnlySignIncorrectTest("RSA1024|PRIMES_2", "RSA1024|PKCS1|SHA224|OnlySign",
        "012345678901234567890123456");
    RsaOnlySignIncorrectTest("RSA1024|PRIMES_2", "RSA1024|PKCS1|SHA224|OnlySign",
        "01234567890123456789012345678");

    RsaOnlySignIncorrectTest("RSA1024|PRIMES_2", "RSA1024|PKCS1|SHA256|OnlySign",
        "0123456789012345678901234567890");
    RsaOnlySignIncorrectTest("RSA1024|PRIMES_2", "RSA1024|PKCS1|SHA256|OnlySign",
        "012345678901234567890123456789012");

    RsaOnlySignIncorrectTest("RSA1024|PRIMES_2", "RSA1024|PKCS1|SHA384|OnlySign",
        "01234567890123456789012345678901234567890123456");
    RsaOnlySignIncorrectTest("RSA1024|PRIMES_2", "RSA1024|PKCS1|SHA384|OnlySign",
        "0123456789012345678901234567890123456789012345678");

    RsaOnlySignIncorrectTest("RSA1024|PRIMES_2", "RSA1024|PKCS1|SHA512|OnlySign",
        "012345678901234567890123456789012345678901234567890123456789012");
    RsaOnlySignIncorrectTest("RSA1024|PRIMES_2", "RSA1024|PKCS1|SHA512|OnlySign",
        "01234567890123456789012345678901234567890123456789012345678901234");
}

// incorrect case: OnlySign double init sign
HWTEST_F(CryptoRsaOnlySignAndVerifyRecoverTest, CryptoRsaOnlySignTest500, TestSize.Level0)
{
    HcfAsyKeyGenerator *generator = nullptr;
    HcfResult res = HcfAsyKeyGeneratorCreate("RSA1024|PRIMES_2", &generator);
    HcfKeyPair *keyPair = nullptr;
    res = generator->generateKeyPair(generator, nullptr, &keyPair);
    EXPECT_EQ(res, HCF_SUCCESS);

    HcfPriKey *prikey = keyPair->priKey;
    HcfSign *sign = nullptr;
    res = HcfSignCreate("RSA1024|PKCS1|SHA512|OnlySign", &sign);
    EXPECT_EQ(res, HCF_SUCCESS);

    res = sign->init(sign, nullptr, prikey);
    EXPECT_EQ(res, HCF_SUCCESS);
    res = sign->init(sign, nullptr, prikey);
    EXPECT_EQ(res, HCF_INVALID_PARAMS);

    HcfObjDestroy(sign);
    HcfObjDestroy(keyPair);
    HcfObjDestroy(generator);
}

static void CryptoRsaVerifyRecoverCreateTest(const char *algoName)
{
    HcfResult res = HCF_SUCCESS;
    HcfVerify *verify = nullptr;
    res = HcfVerifyCreate(algoName, &verify);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(verify, nullptr);
    EXPECT_NE(verify->base.getClass(), nullptr);
    EXPECT_NE(verify->base.destroy, nullptr);
    EXPECT_NE(verify->init, nullptr);
    EXPECT_NE(verify->update, nullptr);
    EXPECT_NE(verify->verify, nullptr);
    EXPECT_NE(verify->recover, nullptr);
    HcfObjDestroy(verify);
}

static void RsaVerifyRecoverIncorrectTest(const char *algoName, HcfResult ret)
{
    HcfResult res = HCF_SUCCESS;
    HcfVerify *verify = nullptr;
    res = HcfVerifyCreate(algoName, &verify);
    EXPECT_EQ(res, ret);
    EXPECT_EQ(verify, nullptr);
}

// HcfVerifyCreate Recover correct_case
HWTEST_F(CryptoRsaOnlySignAndVerifyRecoverTest, CryptoRsaVerifyRecoverTest100, TestSize.Level0)
{
    CryptoRsaVerifyRecoverCreateTest("RSA512|PKCS1|NoHash|Recover");
    CryptoRsaVerifyRecoverCreateTest("RSA512|PKCS1|MD5|Recover");
    CryptoRsaVerifyRecoverCreateTest("RSA512|PKCS1|SHA1|Recover");
    CryptoRsaVerifyRecoverCreateTest("RSA512|PKCS1|SHA224|Recover");
    CryptoRsaVerifyRecoverCreateTest("RSA512|PKCS1|SHA256|Recover");
    CryptoRsaVerifyRecoverCreateTest("RSA512|PKCS1|SHA384|Recover");
}

HWTEST_F(CryptoRsaOnlySignAndVerifyRecoverTest, CryptoRsaVerifyRecoverTest110, TestSize.Level0)
{
    CryptoRsaVerifyRecoverCreateTest("RSA768|PKCS1|NoHash|Recover");
    CryptoRsaVerifyRecoverCreateTest("RSA768|PKCS1|MD5|Recover");
    CryptoRsaVerifyRecoverCreateTest("RSA768|PKCS1|SHA1|Recover");
    CryptoRsaVerifyRecoverCreateTest("RSA768|PKCS1|SHA224|Recover");
    CryptoRsaVerifyRecoverCreateTest("RSA768|PKCS1|SHA256|Recover");
    CryptoRsaVerifyRecoverCreateTest("RSA768|PKCS1|SHA384|Recover");
    CryptoRsaVerifyRecoverCreateTest("RSA768|PKCS1|SHA512|Recover");
}

HWTEST_F(CryptoRsaOnlySignAndVerifyRecoverTest, CryptoRsaVerifyRecoverTest120, TestSize.Level0)
{
    CryptoRsaVerifyRecoverCreateTest("RSA1024|PKCS1|NoHash|Recover");
    CryptoRsaVerifyRecoverCreateTest("RSA1024|PKCS1|MD5|Recover");
    CryptoRsaVerifyRecoverCreateTest("RSA1024|PKCS1|SHA1|Recover");
    CryptoRsaVerifyRecoverCreateTest("RSA1024|PKCS1|SHA224|Recover");
    CryptoRsaVerifyRecoverCreateTest("RSA1024|PKCS1|SHA256|Recover");
    CryptoRsaVerifyRecoverCreateTest("RSA1024|PKCS1|SHA384|Recover");
    CryptoRsaVerifyRecoverCreateTest("RSA1024|PKCS1|SHA512|Recover");
}

HWTEST_F(CryptoRsaOnlySignAndVerifyRecoverTest, CryptoRsaVerifyRecoverTest130, TestSize.Level0)
{
    CryptoRsaVerifyRecoverCreateTest("RSA2048|PKCS1|NoHash|Recover");
    CryptoRsaVerifyRecoverCreateTest("RSA2048|PKCS1|MD5|Recover");
    CryptoRsaVerifyRecoverCreateTest("RSA2048|PKCS1|SHA1|Recover");
    CryptoRsaVerifyRecoverCreateTest("RSA2048|PKCS1|SHA224|Recover");
    CryptoRsaVerifyRecoverCreateTest("RSA2048|PKCS1|SHA256|Recover");
    CryptoRsaVerifyRecoverCreateTest("RSA2048|PKCS1|SHA384|Recover");
    CryptoRsaVerifyRecoverCreateTest("RSA2048|PKCS1|SHA512|Recover");
}

HWTEST_F(CryptoRsaOnlySignAndVerifyRecoverTest, CryptoRsaVerifyRecoverTest140, TestSize.Level0)
{
    CryptoRsaVerifyRecoverCreateTest("RSA3072|PKCS1|NoHash|Recover");
    CryptoRsaVerifyRecoverCreateTest("RSA3072|PKCS1|MD5|Recover");
    CryptoRsaVerifyRecoverCreateTest("RSA3072|PKCS1|SHA1|Recover");
    CryptoRsaVerifyRecoverCreateTest("RSA3072|PKCS1|SHA224|Recover");
    CryptoRsaVerifyRecoverCreateTest("RSA3072|PKCS1|SHA256|Recover");
    CryptoRsaVerifyRecoverCreateTest("RSA3072|PKCS1|SHA384|Recover");
    CryptoRsaVerifyRecoverCreateTest("RSA3072|PKCS1|SHA512|Recover");
}

HWTEST_F(CryptoRsaOnlySignAndVerifyRecoverTest, CryptoRsaVerifyRecoverTest150, TestSize.Level0)
{
    CryptoRsaVerifyRecoverCreateTest("RSA4096|PKCS1|NoHash|Recover");
    CryptoRsaVerifyRecoverCreateTest("RSA4096|PKCS1|MD5|Recover");
    CryptoRsaVerifyRecoverCreateTest("RSA4096|PKCS1|SHA1|Recover");
    CryptoRsaVerifyRecoverCreateTest("RSA4096|PKCS1|SHA224|Recover");
    CryptoRsaVerifyRecoverCreateTest("RSA4096|PKCS1|SHA256|Recover");
    CryptoRsaVerifyRecoverCreateTest("RSA4096|PKCS1|SHA384|Recover");
    CryptoRsaVerifyRecoverCreateTest("RSA4096|PKCS1|SHA512|Recover");
}

HWTEST_F(CryptoRsaOnlySignAndVerifyRecoverTest, CryptoRsaVerifyRecoverTest160, TestSize.Level0)
{
    CryptoRsaVerifyRecoverCreateTest("RSA8192|PKCS1|NoHash|Recover");
    CryptoRsaVerifyRecoverCreateTest("RSA8192|PKCS1|MD5|Recover");
    CryptoRsaVerifyRecoverCreateTest("RSA8192|PKCS1|SHA1|Recover");
    CryptoRsaVerifyRecoverCreateTest("RSA8192|PKCS1|SHA224|Recover");
    CryptoRsaVerifyRecoverCreateTest("RSA8192|PKCS1|SHA256|Recover");
    CryptoRsaVerifyRecoverCreateTest("RSA8192|PKCS1|SHA384|Recover");
    CryptoRsaVerifyRecoverCreateTest("RSA8192|PKCS1|SHA512|Recover");
}

HWTEST_F(CryptoRsaOnlySignAndVerifyRecoverTest, CryptoRsaVerifyRecoverTest170, TestSize.Level0)
{
    CryptoRsaVerifyRecoverCreateTest("RSA512|NoPadding|NoHash|Recover");
    CryptoRsaVerifyRecoverCreateTest("RSA768|NoPadding|NoHash|Recover");
    CryptoRsaVerifyRecoverCreateTest("RSA1024|NoPadding|NoHash|Recover");
    CryptoRsaVerifyRecoverCreateTest("RSA2048|NoPadding|NoHash|Recover");
    CryptoRsaVerifyRecoverCreateTest("RSA3072|NoPadding|NoHash|Recover");
    CryptoRsaVerifyRecoverCreateTest("RSA4096|NoPadding|NoHash|Recover");
    CryptoRsaVerifyRecoverCreateTest("RSA8192|NoPadding|NoHash|Recover");
}

// HcfVerifyCreate OnlySign Incorrect case
HWTEST_F(CryptoRsaOnlySignAndVerifyRecoverTest, CryptoRsaVerifyRecoverTest180, TestSize.Level0)
{
    RsaVerifyRecoverIncorrectTest("RSA1024aa|PKCS1|SHA256|Recover", HCF_INVALID_PARAMS);
    RsaVerifyRecoverIncorrectTest("RSA1024|PKCS1aa|SHA256|Recover", HCF_INVALID_PARAMS);
    RsaVerifyRecoverIncorrectTest("RSA1024|PKCS1|SHA256aa|Recover", HCF_INVALID_PARAMS);
    RsaVerifyRecoverIncorrectTest("RSA1024|PKCS1|SHA256|Recoveraa", HCF_INVALID_PARAMS);
    RsaVerifyRecoverIncorrectTest("RSA1024|PKCS1|SHA256|123123123123123123212312312321"
        "123123123123213asdasdasdasdasdasdasdasdasdasdasdasdasdsasdasds12|Recover", HCF_INVALID_PARAMS);
    RsaVerifyRecoverIncorrectTest("RSA1024|PSS|SHA256|MGF1_SHA256|Recover", HCF_INVALID_PARAMS);
    RsaVerifyRecoverIncorrectTest("DSA1024|PKCS1|SHA256|Recover", HCF_NOT_SUPPORT);
}

// incorrect case : Recover init signer with nullptr public key.
HWTEST_F(CryptoRsaOnlySignAndVerifyRecoverTest, CryptoRsaVerifyRecoverTest270, TestSize.Level0)
{
    HcfResult res = HCF_SUCCESS;
    HcfVerify *verify = nullptr;
    res = HcfVerifyCreate("RSA1024|PKCS1|NoHash|Recover", &verify);
    EXPECT_EQ(res, HCF_SUCCESS);

    res = verify->init(verify, nullptr, nullptr);
    EXPECT_EQ(res, HCF_INVALID_PARAMS);

    HcfObjDestroy(verify);
}

// incorrect case : Recover init verifyer with private Key.
HWTEST_F(CryptoRsaOnlySignAndVerifyRecoverTest, CryptoRsaVerifyRecoverTest280, TestSize.Level0)
{
    HcfResult res = HCF_SUCCESS;
    HcfAsyKeyGenerator *generator = nullptr;
    res = HcfAsyKeyGeneratorCreate("RSA1024|PRIMES_2", &generator);
    HcfKeyPair *keyPair = nullptr;
    res = generator->generateKeyPair(generator, nullptr, &keyPair);
    EXPECT_EQ(res, HCF_SUCCESS);

    HcfVerify *verify = nullptr;
    res = HcfVerifyCreate("RSA1024|PKCS1|NoHash|Recover", &verify);
    EXPECT_EQ(res, HCF_SUCCESS);

    HcfPriKey *priKey = keyPair->priKey;

    res = verify->init(verify, nullptr, (HcfPubKey *)priKey);
    EXPECT_EQ(res, HCF_INVALID_PARAMS);

    HcfObjDestroy(verify);
    HcfObjDestroy(generator);
    HcfObjDestroy(keyPair);
}

// incorrect case : use Recover recover function before intialize.
HWTEST_F(CryptoRsaOnlySignAndVerifyRecoverTest, CryptoRsaVerifyRecoverTest291, TestSize.Level0)
{
    uint8_t plan[] = "01234567890123456789012345678901";
    HcfAsyKeyGenerator *generator = nullptr;
    int32_t res = HcfAsyKeyGeneratorCreate("RSA1024|PRIMES_2", &generator);

    HcfKeyPair *keyPair = nullptr;
    res = generator->generateKeyPair(generator, nullptr, &keyPair);
    EXPECT_EQ(res, HCF_SUCCESS);

    HcfPriKey *prikey = keyPair->priKey;

    HcfBlob input = {.data = plan, .len = strlen((char *)plan)};
    HcfBlob verifyData = {.data = nullptr, .len = 0};
    HcfBlob rawSignatureData = {.data = nullptr, .len = 0};
    HcfSign *sign = nullptr;
    res = HcfSignCreate("RSA1024|PKCS1|SHA256|OnlySign", &sign);
    EXPECT_EQ(res, HCF_SUCCESS);
    res = sign->init(sign, nullptr, prikey);
    EXPECT_EQ(res, HCF_SUCCESS);
    res = sign->sign(sign, &input, &verifyData);
    EXPECT_EQ(res, HCF_SUCCESS);
    HcfObjDestroy(sign);

    HcfVerify *verify = nullptr;
    res = HcfVerifyCreate("RSA1024|PKCS1|SHA256|Recover", &verify);
    EXPECT_EQ(res, HCF_SUCCESS);
    res = verify->recover(verify, &verifyData, &rawSignatureData);
    EXPECT_EQ(res, HCF_ERR_CRYPTO_OPERATION);

    HcfObjDestroy(verify);
    HcfFree(verifyData.data);
    HcfObjDestroy(keyPair);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoRsaOnlySignAndVerifyRecoverTest, CryptoRsaVerifyRecoverErrTest01, TestSize.Level0)
{
    uint8_t plan[] = "01234567890123456789012345678901";
    HcfAsyKeyGenerator *generator = nullptr;
    int32_t res = HcfAsyKeyGeneratorCreate("RSA1024|PRIMES_2", &generator);

    HcfKeyPair *keyPair = nullptr;
    res = generator->generateKeyPair(generator, nullptr, &keyPair);
    EXPECT_EQ(res, HCF_SUCCESS);

    HcfPriKey *prikey = keyPair->priKey;

    HcfBlob input = {.data = plan, .len = strlen((char *)plan)};
    HcfBlob verifyData = {.data = nullptr, .len = 0};
    HcfBlob rawSignatureData = {.data = nullptr, .len = 0};
    HcfSign *sign = nullptr;
    res = HcfSignCreate("RSA1024|PKCS1|SHA256|OnlySign", &sign);
    EXPECT_EQ(res, HCF_SUCCESS);
    res = sign->init(sign, nullptr, prikey);
    EXPECT_EQ(res, HCF_SUCCESS);
    res = sign->sign(sign, &input, &verifyData);
    EXPECT_EQ(res, HCF_SUCCESS);
    HcfObjDestroy(sign);

    HcfVerify *verify = nullptr;
    res = HcfVerifyCreate("RSA1024|PKCS1|SHA256|Recover", &verify);
    EXPECT_EQ(res, HCF_SUCCESS);
    res = verify->recover(nullptr, &verifyData, &rawSignatureData);
    EXPECT_EQ(res, HCF_INVALID_PARAMS);

    HcfObjDestroy(verify);
    HcfFree(verifyData.data);
    HcfObjDestroy(keyPair);
    HcfObjDestroy(generator);
}

// incorrect case : Recover recover with nullptr outputBlob.
HWTEST_F(CryptoRsaOnlySignAndVerifyRecoverTest, CryptoRsaVerifyRecoverTest292, TestSize.Level0)
{
    HcfResult res = HCF_SUCCESS;
    HcfAsyKeyGenerator *generator = nullptr;
    res = HcfAsyKeyGeneratorCreate("RSA1024|PRIMES_2", &generator);
    HcfKeyPair *keyPair = nullptr;
    res = generator->generateKeyPair(generator, nullptr, &keyPair);
    EXPECT_EQ(res, HCF_SUCCESS);

    HcfPubKey *pubkey = keyPair->pubKey;

    HcfBlob rawSignatureData = {.data = nullptr, .len = 0};
    HcfVerify *verify = nullptr;
    res = HcfVerifyCreate("RSA1024|PKCS1|SHA256|Recover", &verify);
    EXPECT_EQ(res, HCF_SUCCESS);
    res = verify->init(verify, nullptr, pubkey);
    EXPECT_EQ(res, HCF_SUCCESS);
    res = verify->recover(verify, nullptr, &rawSignatureData);
    EXPECT_EQ(res, HCF_INVALID_PARAMS);

    HcfObjDestroy(verify);
    HcfObjDestroy(keyPair);
    HcfObjDestroy(generator);
}

// incorrect case: recover double init verify
HWTEST_F(CryptoRsaOnlySignAndVerifyRecoverTest, CryptoRsaVerifyRecoverTest293, TestSize.Level0)
{
    HcfAsyKeyGenerator *generator = nullptr;
    HcfResult res = HcfAsyKeyGeneratorCreate("RSA1024|PRIMES_2", &generator);
    HcfKeyPair *keyPair = nullptr;
    res = generator->generateKeyPair(generator, nullptr, &keyPair);
    EXPECT_EQ(res, HCF_SUCCESS);

    HcfPubKey *pubkey = keyPair->pubKey;
    HcfVerify *verify = nullptr;
    res = HcfVerifyCreate("RSA1024|PKCS1|SHA256|Recover", &verify);
    EXPECT_EQ(res, HCF_SUCCESS);

    res = verify->init(verify, nullptr, pubkey);
    EXPECT_EQ(res, HCF_SUCCESS);
    res = verify->init(verify, nullptr, pubkey);
    EXPECT_EQ(res, HCF_INVALID_PARAMS);

    HcfObjDestroy(verify);
    HcfObjDestroy(keyPair);
    HcfObjDestroy(generator);
}

// correct case : sign and recover
HWTEST_F(CryptoRsaOnlySignAndVerifyRecoverTest, CryptoRsaVerifyRecoverTest300, TestSize.Level0)
{
    uint8_t plan[] = "01234567890123456789012345678901";
    HcfAsyKeyGenerator *generator = nullptr;
    int32_t res = HcfAsyKeyGeneratorCreate("RSA1024|PRIMES_2", &generator);

    HcfKeyPair *keyPair = nullptr;
    res = generator->generateKeyPair(generator, nullptr, &keyPair);
    EXPECT_EQ(res, HCF_SUCCESS);

    HcfPubKey *pubkey = keyPair->pubKey;
    HcfPriKey *prikey = keyPair->priKey;

    HcfBlob input = {.data = plan, .len = strlen((char *)plan)};
    HcfBlob verifyData = {.data = nullptr, .len = 0};
    HcfBlob rawSignatureData = {.data = nullptr, .len = 0};
    HcfSign *sign = nullptr;
    res = HcfSignCreate("RSA1024|PKCS1|SHA256|OnlySign", &sign);
    EXPECT_EQ(res, HCF_SUCCESS);
    res = sign->init(sign, nullptr, prikey);
    EXPECT_EQ(res, HCF_SUCCESS);
    res = sign->sign(sign, &input, &verifyData);
    EXPECT_EQ(res, HCF_SUCCESS);
    HcfObjDestroy(sign);

    HcfVerify *verify = nullptr;
    res = HcfVerifyCreate("RSA1024|PKCS1|SHA256|Recover", &verify);
    EXPECT_EQ(res, HCF_SUCCESS);
    res = verify->init(verify, nullptr, pubkey);
    EXPECT_EQ(res, HCF_SUCCESS);
    res = verify->recover(verify, &verifyData, &rawSignatureData);
    EXPECT_EQ(res, HCF_SUCCESS);
    HcfObjDestroy(verify);
    int resCmp = memcmp(input.data, rawSignatureData.data, rawSignatureData.len);
    EXPECT_EQ(resCmp, HCF_SUCCESS);

    HcfFree(verifyData.data);
    HcfFree(rawSignatureData.data);
    HcfObjDestroy(keyPair);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoRsaOnlySignAndVerifyRecoverTest, CryptoRsaVerifyRecoverTest310, TestSize.Level0)
{
    uint8_t plan[] = "01234567890123456789012345678901";
    HcfAsyKeyGenerator *generator = nullptr;
    int32_t res = HcfAsyKeyGeneratorCreate("RSA1024|PRIMES_2", &generator);

    HcfKeyPair *keyPair = nullptr;
    res = generator->generateKeyPair(generator, nullptr, &keyPair);
    EXPECT_EQ(res, HCF_SUCCESS);

    HcfPubKey *pubkey = keyPair->pubKey;
    HcfPriKey *prikey = keyPair->priKey;

    HcfBlob input = {.data = plan, .len = strlen((char *)plan)};
    HcfBlob verifyData = {.data = nullptr, .len = 0};
    HcfBlob rawSignatureData = {.data = nullptr, .len = 0};
    HcfSign *sign = nullptr;
    res = HcfSignCreate("RSA1024|PKCS1|SHA256", &sign);
    EXPECT_EQ(res, HCF_SUCCESS);
    res = sign->init(sign, nullptr, prikey);
    EXPECT_EQ(res, HCF_SUCCESS);
    res = sign->sign(sign, &input, &verifyData);
    EXPECT_EQ(res, HCF_SUCCESS);
    HcfObjDestroy(sign);

    HcfVerify *verify = nullptr;
    res = HcfVerifyCreate("RSA1024|PKCS1|SHA256|Recover", &verify);
    EXPECT_EQ(res, HCF_SUCCESS);
    res = verify->init(verify, nullptr, pubkey);
    EXPECT_EQ(res, HCF_SUCCESS);
    res = verify->recover(verify, &verifyData, &rawSignatureData);
    EXPECT_EQ(res, HCF_SUCCESS);
    HcfObjDestroy(verify);

    uint32_t sha256Len = 32;
    HcfMd *mdObj = nullptr;
    HcfResult ret = HcfMdCreate("SHA256", &mdObj);
    ASSERT_EQ(ret, HCF_SUCCESS);
    struct HcfBlob outBlob = { .data = nullptr, .len = 0 };
    ret = mdObj->update(mdObj, &input);
    EXPECT_EQ(ret, HCF_SUCCESS);
    ret = mdObj->doFinal(mdObj, &outBlob);
    EXPECT_EQ(ret, HCF_SUCCESS);
    uint32_t len = mdObj->getMdLength(mdObj);
    EXPECT_EQ(len, sha256Len);

    int resCmp = memcmp(outBlob.data, rawSignatureData.data, rawSignatureData.len);
    EXPECT_EQ(resCmp, HCF_SUCCESS);

    HcfObjDestroy(mdObj);
    HcfFree(verifyData.data);
    HcfFree(rawSignatureData.data);
    HcfBlobDataClearAndFree(&outBlob);
    HcfObjDestroy(keyPair);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoRsaOnlySignAndVerifyRecoverTest, CryptoRsaOnlySignTest600, TestSize.Level0)
{
    ASSERT_NO_FATAL_FAILURE(RsaOnlySignCreateTest("RSA512|PSS|MD5|MGF1_MD5|OnlySign"));
    ASSERT_NO_FATAL_FAILURE(RsaOnlySignCreateTest("RSA512|PSS|MD5|MGF1_SHA1|OnlySign"));
    ASSERT_NO_FATAL_FAILURE(RsaOnlySignCreateTest("RSA512|PSS|MD5|MGF1_SHA224|OnlySign"));
    ASSERT_NO_FATAL_FAILURE(RsaOnlySignCreateTest("RSA512|PSS|MD5|MGF1_SHA256|OnlySign"));
    ASSERT_NO_FATAL_FAILURE(RsaOnlySignCreateTest("RSA512|PSS|SHA1|MGF1_MD5|OnlySign"));
    ASSERT_NO_FATAL_FAILURE(RsaOnlySignCreateTest("RSA512|PSS|SHA1|MGF1_SHA1|OnlySign"));
    ASSERT_NO_FATAL_FAILURE(RsaOnlySignCreateTest("RSA512|PSS|SHA1|MGF1_SHA224|OnlySign"));
    ASSERT_NO_FATAL_FAILURE(RsaOnlySignCreateTest("RSA512|PSS|SHA1|MGF1_SHA256|OnlySign"));
    ASSERT_NO_FATAL_FAILURE(RsaOnlySignCreateTest("RSA512|PSS|SHA224|MGF1_MD5|OnlySign"));
    ASSERT_NO_FATAL_FAILURE(RsaOnlySignCreateTest("RSA512|PSS|SHA224|MGF1_SHA1|OnlySign"));
    ASSERT_NO_FATAL_FAILURE(RsaOnlySignCreateTest("RSA512|PSS|SHA224|MGF1_SHA224|OnlySign"));
    ASSERT_NO_FATAL_FAILURE(RsaOnlySignCreateTest("RSA512|PSS|SHA224|MGF1_SHA256|OnlySign"));
    ASSERT_NO_FATAL_FAILURE(RsaOnlySignCreateTest("RSA512|PSS|SHA256|MGF1_MD5|OnlySign"));
    ASSERT_NO_FATAL_FAILURE(RsaOnlySignCreateTest("RSA512|PSS|SHA256|MGF1_SHA1|OnlySign"));
    ASSERT_NO_FATAL_FAILURE(RsaOnlySignCreateTest("RSA512|PSS|SHA256|MGF1_SHA224|OnlySign"));
    ASSERT_NO_FATAL_FAILURE(RsaOnlySignCreateTest("RSA|PSS|SHA256|MGF1_SHA256|OnlySign"));
}

HWTEST_F(CryptoRsaOnlySignAndVerifyRecoverTest, CryptoRsaOnlySignTest601, TestSize.Level0)
{
    ASSERT_NO_FATAL_FAILURE(RsaOnlySignCreateTest("RSA768|PSS|MD5|MGF1_MD5|OnlySign"));
    ASSERT_NO_FATAL_FAILURE(RsaOnlySignCreateTest("RSA768|PSS|MD5|MGF1_SHA1|OnlySign"));
    ASSERT_NO_FATAL_FAILURE(RsaOnlySignCreateTest("RSA768|PSS|MD5|MGF1_SHA224|OnlySign"));
    ASSERT_NO_FATAL_FAILURE(RsaOnlySignCreateTest("RSA768|PSS|MD5|MGF1_SHA256|OnlySign"));
    ASSERT_NO_FATAL_FAILURE(RsaOnlySignCreateTest("RSA768|PSS|MD5|MGF1_SHA384|OnlySign"));
    ASSERT_NO_FATAL_FAILURE(RsaOnlySignCreateTest("RSA768|PSS|MD5|MGF1_SHA512|OnlySign"));
    ASSERT_NO_FATAL_FAILURE(RsaOnlySignCreateTest("RSA768|PSS|SHA1|MGF1_MD5|OnlySign"));
    ASSERT_NO_FATAL_FAILURE(RsaOnlySignCreateTest("RSA768|PSS|SHA1|MGF1_SHA1|OnlySign"));
    ASSERT_NO_FATAL_FAILURE(RsaOnlySignCreateTest("RSA768|PSS|SHA1|MGF1_SHA224|OnlySign"));
    ASSERT_NO_FATAL_FAILURE(RsaOnlySignCreateTest("RSA768|PSS|SHA1|MGF1_SHA256|OnlySign"));
    ASSERT_NO_FATAL_FAILURE(RsaOnlySignCreateTest("RSA768|PSS|SHA1|MGF1_SHA384|OnlySign"));
    ASSERT_NO_FATAL_FAILURE(RsaOnlySignCreateTest("RSA768|PSS|SHA1|MGF1_SHA512|OnlySign"));
    ASSERT_NO_FATAL_FAILURE(RsaOnlySignCreateTest("RSA768|PSS|SHA224|MGF1_MD5|OnlySign"));
    ASSERT_NO_FATAL_FAILURE(RsaOnlySignCreateTest("RSA768|PSS|SHA224|MGF1_SHA1|OnlySign"));
    ASSERT_NO_FATAL_FAILURE(RsaOnlySignCreateTest("RSA768|PSS|SHA224|MGF1_SHA224|OnlySign"));
    ASSERT_NO_FATAL_FAILURE(RsaOnlySignCreateTest("RSA768|PSS|SHA224|MGF1_SHA256|OnlySign"));
    ASSERT_NO_FATAL_FAILURE(RsaOnlySignCreateTest("RSA768|PSS|SHA224|MGF1_SHA384|OnlySign"));
    ASSERT_NO_FATAL_FAILURE(RsaOnlySignCreateTest("RSA768|PSS|SHA224|MGF1_SHA512|OnlySign"));
    ASSERT_NO_FATAL_FAILURE(RsaOnlySignCreateTest("RSA768|PSS|SHA256|MGF1_MD5|OnlySign"));
    ASSERT_NO_FATAL_FAILURE(RsaOnlySignCreateTest("RSA768|PSS|SHA256|MGF1_SHA1|OnlySign"));
    ASSERT_NO_FATAL_FAILURE(RsaOnlySignCreateTest("RSA768|PSS|SHA256|MGF1_SHA224|OnlySign"));
    ASSERT_NO_FATAL_FAILURE(RsaOnlySignCreateTest("RSA768|PSS|SHA256|MGF1_SHA256|OnlySign"));
    ASSERT_NO_FATAL_FAILURE(RsaOnlySignCreateTest("RSA768|PSS|SHA256|MGF1_SHA384|OnlySign"));
    ASSERT_NO_FATAL_FAILURE(RsaOnlySignCreateTest("RSA768|PSS|SHA384|MGF1_MD5|OnlySign"));
    ASSERT_NO_FATAL_FAILURE(RsaOnlySignCreateTest("RSA768|PSS|SHA384|MGF1_SHA1|OnlySign"));
    ASSERT_NO_FATAL_FAILURE(RsaOnlySignCreateTest("RSA768|PSS|SHA384|MGF1_SHA224|OnlySign"));
    ASSERT_NO_FATAL_FAILURE(RsaOnlySignCreateTest("RSA768|PSS|SHA384|MGF1_SHA256|OnlySign"));
    ASSERT_NO_FATAL_FAILURE(RsaOnlySignCreateTest("RSA768|PSS|SHA512|MGF1_MD5|OnlySign"));
    ASSERT_NO_FATAL_FAILURE(RsaOnlySignCreateTest("RSA768|PSS|SHA512|MGF1_SHA1|OnlySign"));
    ASSERT_NO_FATAL_FAILURE(RsaOnlySignCreateTest("RSA768|PSS|SHA512|MGF1_SHA224|OnlySign"));
}

HWTEST_F(CryptoRsaOnlySignAndVerifyRecoverTest, CryptoRsaOnlySignTest602, TestSize.Level0)
{
    ASSERT_NO_FATAL_FAILURE(RsaOnlySignCreateTest("RSA1024|PSS|MD5|MGF1_MD5|OnlySign"));
    ASSERT_NO_FATAL_FAILURE(RsaOnlySignCreateTest("RSA1024|PSS|MD5|MGF1_SHA1|OnlySign"));
    ASSERT_NO_FATAL_FAILURE(RsaOnlySignCreateTest("RSA1024|PSS|MD5|MGF1_SHA224|OnlySign"));
    ASSERT_NO_FATAL_FAILURE(RsaOnlySignCreateTest("RSA1024|PSS|MD5|MGF1_SHA256|OnlySign"));
    ASSERT_NO_FATAL_FAILURE(RsaOnlySignCreateTest("RSA1024|PSS|MD5|MGF1_SHA384|OnlySign"));
    ASSERT_NO_FATAL_FAILURE(RsaOnlySignCreateTest("RSA1024|PSS|MD5|MGF1_SHA512|OnlySign"));
    ASSERT_NO_FATAL_FAILURE(RsaOnlySignCreateTest("RSA1024|PSS|SHA1|MGF1_MD5|OnlySign"));
    ASSERT_NO_FATAL_FAILURE(RsaOnlySignCreateTest("RSA1024|PSS|SHA1|MGF1_SHA1|OnlySign"));
    ASSERT_NO_FATAL_FAILURE(RsaOnlySignCreateTest("RSA1024|PSS|SHA1|MGF1_SHA224|OnlySign"));
    ASSERT_NO_FATAL_FAILURE(RsaOnlySignCreateTest("RSA1024|PSS|SHA1|MGF1_SHA256|OnlySign"));
    ASSERT_NO_FATAL_FAILURE(RsaOnlySignCreateTest("RSA1024|PSS|SHA1|MGF1_SHA384|OnlySign"));
    ASSERT_NO_FATAL_FAILURE(RsaOnlySignCreateTest("RSA1024|PSS|SHA1|MGF1_SHA512|OnlySign"));
    ASSERT_NO_FATAL_FAILURE(RsaOnlySignCreateTest("RSA1024|PSS|SHA224|MGF1_MD5|OnlySign"));
    ASSERT_NO_FATAL_FAILURE(RsaOnlySignCreateTest("RSA1024|PSS|SHA224|MGF1_SHA1|OnlySign"));
    ASSERT_NO_FATAL_FAILURE(RsaOnlySignCreateTest("RSA1024|PSS|SHA224|MGF1_SHA224|OnlySign"));
    ASSERT_NO_FATAL_FAILURE(RsaOnlySignCreateTest("RSA1024|PSS|SHA224|MGF1_SHA256|OnlySign"));
    ASSERT_NO_FATAL_FAILURE(RsaOnlySignCreateTest("RSA1024|PSS|SHA224|MGF1_SHA384|OnlySign"));
    ASSERT_NO_FATAL_FAILURE(RsaOnlySignCreateTest("RSA1024|PSS|SHA224|MGF1_SHA512|OnlySign"));
    ASSERT_NO_FATAL_FAILURE(RsaOnlySignCreateTest("RSA1024|PSS|SHA256|MGF1_MD5|OnlySign"));
    ASSERT_NO_FATAL_FAILURE(RsaOnlySignCreateTest("RSA1024|PSS|SHA256|MGF1_SHA1|OnlySign"));
    ASSERT_NO_FATAL_FAILURE(RsaOnlySignCreateTest("RSA1024|PSS|SHA256|MGF1_SHA224|OnlySign"));
    ASSERT_NO_FATAL_FAILURE(RsaOnlySignCreateTest("RSA1024|PSS|SHA256|MGF1_SHA256|OnlySign"));
    ASSERT_NO_FATAL_FAILURE(RsaOnlySignCreateTest("RSA1024|PSS|SHA256|MGF1_SHA384|OnlySign"));
    ASSERT_NO_FATAL_FAILURE(RsaOnlySignCreateTest("RSA1024|PSS|SHA256|MGF1_SHA512|OnlySign"));
    ASSERT_NO_FATAL_FAILURE(RsaOnlySignCreateTest("RSA1024|PSS|SHA384|MGF1_MD5|OnlySign"));
    ASSERT_NO_FATAL_FAILURE(RsaOnlySignCreateTest("RSA1024|PSS|SHA384|MGF1_SHA1|OnlySign"));
    ASSERT_NO_FATAL_FAILURE(RsaOnlySignCreateTest("RSA1024|PSS|SHA384|MGF1_SHA224|OnlySign"));
    ASSERT_NO_FATAL_FAILURE(RsaOnlySignCreateTest("RSA1024|PSS|SHA384|MGF1_SHA256|OnlySign"));
    ASSERT_NO_FATAL_FAILURE(RsaOnlySignCreateTest("RSA1024|PSS|SHA384|MGF1_SHA384|OnlySign"));
    ASSERT_NO_FATAL_FAILURE(RsaOnlySignCreateTest("RSA1024|PSS|SHA384|MGF1_SHA512|OnlySign"));
    ASSERT_NO_FATAL_FAILURE(RsaOnlySignCreateTest("RSA1024|PSS|SHA512|MGF1_MD5|OnlySign"));
    ASSERT_NO_FATAL_FAILURE(RsaOnlySignCreateTest("RSA1024|PSS|SHA512|MGF1_SHA1|OnlySign"));
    ASSERT_NO_FATAL_FAILURE(RsaOnlySignCreateTest("RSA1024|PSS|SHA512|MGF1_SHA224|OnlySign"));
    ASSERT_NO_FATAL_FAILURE(RsaOnlySignCreateTest("RSA1024|PSS|SHA512|MGF1_SHA256|OnlySign"));
    ASSERT_NO_FATAL_FAILURE(RsaOnlySignCreateTest("RSA1024|PSS|SHA512|MGF1_SHA384|OnlySign"));
}

HWTEST_F(CryptoRsaOnlySignAndVerifyRecoverTest, CryptoRsaOnlySignTest603, TestSize.Level0)
{
    ASSERT_NO_FATAL_FAILURE(RsaOnlySignCreateTest("RSA2048|PSS|MD5|MGF1_MD5|OnlySign"));
    ASSERT_NO_FATAL_FAILURE(RsaOnlySignCreateTest("RSA2048|PSS|MD5|MGF1_SHA1|OnlySign"));
    ASSERT_NO_FATAL_FAILURE(RsaOnlySignCreateTest("RSA2048|PSS|MD5|MGF1_SHA224|OnlySign"));
    ASSERT_NO_FATAL_FAILURE(RsaOnlySignCreateTest("RSA2048|PSS|MD5|MGF1_SHA256|OnlySign"));
    ASSERT_NO_FATAL_FAILURE(RsaOnlySignCreateTest("RSA2048|PSS|MD5|MGF1_SHA384|OnlySign"));
    ASSERT_NO_FATAL_FAILURE(RsaOnlySignCreateTest("RSA2048|PSS|MD5|MGF1_SHA512|OnlySign"));
    ASSERT_NO_FATAL_FAILURE(RsaOnlySignCreateTest("RSA2048|PSS|SHA1|MGF1_MD5|OnlySign"));
    ASSERT_NO_FATAL_FAILURE(RsaOnlySignCreateTest("RSA2048|PSS|SHA1|MGF1_SHA1|OnlySign"));
    ASSERT_NO_FATAL_FAILURE(RsaOnlySignCreateTest("RSA2048|PSS|SHA1|MGF1_SHA224|OnlySign"));
    ASSERT_NO_FATAL_FAILURE(RsaOnlySignCreateTest("RSA2048|PSS|SHA1|MGF1_SHA256|OnlySign"));
    ASSERT_NO_FATAL_FAILURE(RsaOnlySignCreateTest("RSA2048|PSS|SHA1|MGF1_SHA384|OnlySign"));
    ASSERT_NO_FATAL_FAILURE(RsaOnlySignCreateTest("RSA2048|PSS|SHA1|MGF1_SHA512|OnlySign"));
    ASSERT_NO_FATAL_FAILURE(RsaOnlySignCreateTest("RSA2048|PSS|SHA224|MGF1_MD5|OnlySign"));
    ASSERT_NO_FATAL_FAILURE(RsaOnlySignCreateTest("RSA2048|PSS|SHA224|MGF1_SHA1|OnlySign"));
    ASSERT_NO_FATAL_FAILURE(RsaOnlySignCreateTest("RSA2048|PSS|SHA224|MGF1_SHA224|OnlySign"));
    ASSERT_NO_FATAL_FAILURE(RsaOnlySignCreateTest("RSA2048|PSS|SHA224|MGF1_SHA256|OnlySign"));
    ASSERT_NO_FATAL_FAILURE(RsaOnlySignCreateTest("RSA2048|PSS|SHA224|MGF1_SHA384|OnlySign"));
    ASSERT_NO_FATAL_FAILURE(RsaOnlySignCreateTest("RSA2048|PSS|SHA224|MGF1_SHA512|OnlySign"));
    ASSERT_NO_FATAL_FAILURE(RsaOnlySignCreateTest("RSA2048|PSS|SHA256|MGF1_MD5|OnlySign"));
    ASSERT_NO_FATAL_FAILURE(RsaOnlySignCreateTest("RSA2048|PSS|SHA256|MGF1_SHA1|OnlySign"));
    ASSERT_NO_FATAL_FAILURE(RsaOnlySignCreateTest("RSA2048|PSS|SHA256|MGF1_SHA224|OnlySign"));
    ASSERT_NO_FATAL_FAILURE(RsaOnlySignCreateTest("RSA2048|PSS|SHA256|MGF1_SHA256|OnlySign"));
    ASSERT_NO_FATAL_FAILURE(RsaOnlySignCreateTest("RSA2048|PSS|SHA256|MGF1_SHA384|OnlySign"));
    ASSERT_NO_FATAL_FAILURE(RsaOnlySignCreateTest("RSA2048|PSS|SHA256|MGF1_SHA512|OnlySign"));
    ASSERT_NO_FATAL_FAILURE(RsaOnlySignCreateTest("RSA2048|PSS|SHA384|MGF1_MD5|OnlySign"));
    ASSERT_NO_FATAL_FAILURE(RsaOnlySignCreateTest("RSA2048|PSS|SHA384|MGF1_SHA1|OnlySign"));
    ASSERT_NO_FATAL_FAILURE(RsaOnlySignCreateTest("RSA2048|PSS|SHA384|MGF1_SHA224|OnlySign"));
    ASSERT_NO_FATAL_FAILURE(RsaOnlySignCreateTest("RSA2048|PSS|SHA384|MGF1_SHA256|OnlySign"));
    ASSERT_NO_FATAL_FAILURE(RsaOnlySignCreateTest("RSA2048|PSS|SHA384|MGF1_SHA384|OnlySign"));
    ASSERT_NO_FATAL_FAILURE(RsaOnlySignCreateTest("RSA2048|PSS|SHA384|MGF1_SHA512|OnlySign"));
    ASSERT_NO_FATAL_FAILURE(RsaOnlySignCreateTest("RSA2048|PSS|SHA512|MGF1_MD5|OnlySign"));
    ASSERT_NO_FATAL_FAILURE(RsaOnlySignCreateTest("RSA2048|PSS|SHA512|MGF1_SHA1|OnlySign"));
    ASSERT_NO_FATAL_FAILURE(RsaOnlySignCreateTest("RSA2048|PSS|SHA512|MGF1_SHA224|OnlySign"));
    ASSERT_NO_FATAL_FAILURE(RsaOnlySignCreateTest("RSA2048|PSS|SHA512|MGF1_SHA256|OnlySign"));
    ASSERT_NO_FATAL_FAILURE(RsaOnlySignCreateTest("RSA2048|PSS|SHA512|MGF1_SHA384|OnlySign"));
    ASSERT_NO_FATAL_FAILURE(RsaOnlySignCreateTest("RSA2048|PSS|SHA512|MGF1_SHA512|OnlySign"));
}

HWTEST_F(CryptoRsaOnlySignAndVerifyRecoverTest, CryptoRsaOnlySignTest604, TestSize.Level0)
{
    ASSERT_NO_FATAL_FAILURE(RsaOnlySignCreateTest("RSA3072|PSS|MD5|MGF1_MD5|OnlySign"));
    ASSERT_NO_FATAL_FAILURE(RsaOnlySignCreateTest("RSA3072|PSS|MD5|MGF1_SHA1|OnlySign"));
    ASSERT_NO_FATAL_FAILURE(RsaOnlySignCreateTest("RSA3072|PSS|MD5|MGF1_SHA224|OnlySign"));
    ASSERT_NO_FATAL_FAILURE(RsaOnlySignCreateTest("RSA3072|PSS|MD5|MGF1_SHA256|OnlySign"));
    ASSERT_NO_FATAL_FAILURE(RsaOnlySignCreateTest("RSA3072|PSS|MD5|MGF1_SHA384|OnlySign"));
    ASSERT_NO_FATAL_FAILURE(RsaOnlySignCreateTest("RSA3072|PSS|MD5|MGF1_SHA512|OnlySign"));
    ASSERT_NO_FATAL_FAILURE(RsaOnlySignCreateTest("RSA3072|PSS|SHA1|MGF1_MD5|OnlySign"));
    ASSERT_NO_FATAL_FAILURE(RsaOnlySignCreateTest("RSA3072|PSS|SHA1|MGF1_SHA1|OnlySign"));
    ASSERT_NO_FATAL_FAILURE(RsaOnlySignCreateTest("RSA3072|PSS|SHA1|MGF1_SHA224|OnlySign"));
    ASSERT_NO_FATAL_FAILURE(RsaOnlySignCreateTest("RSA3072|PSS|SHA1|MGF1_SHA256|OnlySign"));
    ASSERT_NO_FATAL_FAILURE(RsaOnlySignCreateTest("RSA3072|PSS|SHA1|MGF1_SHA384|OnlySign"));
    ASSERT_NO_FATAL_FAILURE(RsaOnlySignCreateTest("RSA3072|PSS|SHA1|MGF1_SHA512|OnlySign"));
    ASSERT_NO_FATAL_FAILURE(RsaOnlySignCreateTest("RSA3072|PSS|SHA224|MGF1_MD5|OnlySign"));
    ASSERT_NO_FATAL_FAILURE(RsaOnlySignCreateTest("RSA3072|PSS|SHA224|MGF1_SHA1|OnlySign"));
    ASSERT_NO_FATAL_FAILURE(RsaOnlySignCreateTest("RSA3072|PSS|SHA224|MGF1_SHA224|OnlySign"));
    ASSERT_NO_FATAL_FAILURE(RsaOnlySignCreateTest("RSA3072|PSS|SHA224|MGF1_SHA256|OnlySign"));
    ASSERT_NO_FATAL_FAILURE(RsaOnlySignCreateTest("RSA3072|PSS|SHA224|MGF1_SHA384|OnlySign"));
    ASSERT_NO_FATAL_FAILURE(RsaOnlySignCreateTest("RSA3072|PSS|SHA224|MGF1_SHA512|OnlySign"));
    ASSERT_NO_FATAL_FAILURE(RsaOnlySignCreateTest("RSA3072|PSS|SHA256|MGF1_MD5|OnlySign"));
    ASSERT_NO_FATAL_FAILURE(RsaOnlySignCreateTest("RSA3072|PSS|SHA256|MGF1_SHA1|OnlySign"));
    ASSERT_NO_FATAL_FAILURE(RsaOnlySignCreateTest("RSA3072|PSS|SHA256|MGF1_SHA224|OnlySign"));
    ASSERT_NO_FATAL_FAILURE(RsaOnlySignCreateTest("RSA3072|PSS|SHA256|MGF1_SHA256|OnlySign"));
    ASSERT_NO_FATAL_FAILURE(RsaOnlySignCreateTest("RSA3072|PSS|SHA256|MGF1_SHA384|OnlySign"));
    ASSERT_NO_FATAL_FAILURE(RsaOnlySignCreateTest("RSA3072|PSS|SHA256|MGF1_SHA512|OnlySign"));
    ASSERT_NO_FATAL_FAILURE(RsaOnlySignCreateTest("RSA3072|PSS|SHA384|MGF1_MD5|OnlySign"));
    ASSERT_NO_FATAL_FAILURE(RsaOnlySignCreateTest("RSA3072|PSS|SHA384|MGF1_SHA1|OnlySign"));
    ASSERT_NO_FATAL_FAILURE(RsaOnlySignCreateTest("RSA3072|PSS|SHA384|MGF1_SHA224|OnlySign"));
    ASSERT_NO_FATAL_FAILURE(RsaOnlySignCreateTest("RSA3072|PSS|SHA384|MGF1_SHA256|OnlySign"));
    ASSERT_NO_FATAL_FAILURE(RsaOnlySignCreateTest("RSA3072|PSS|SHA384|MGF1_SHA384|OnlySign"));
    ASSERT_NO_FATAL_FAILURE(RsaOnlySignCreateTest("RSA3072|PSS|SHA384|MGF1_SHA512|OnlySign"));
    ASSERT_NO_FATAL_FAILURE(RsaOnlySignCreateTest("RSA3072|PSS|SHA512|MGF1_MD5|OnlySign"));
    ASSERT_NO_FATAL_FAILURE(RsaOnlySignCreateTest("RSA3072|PSS|SHA512|MGF1_SHA1|OnlySign"));
    ASSERT_NO_FATAL_FAILURE(RsaOnlySignCreateTest("RSA3072|PSS|SHA512|MGF1_SHA224|OnlySign"));
    ASSERT_NO_FATAL_FAILURE(RsaOnlySignCreateTest("RSA3072|PSS|SHA512|MGF1_SHA256|OnlySign"));
    ASSERT_NO_FATAL_FAILURE(RsaOnlySignCreateTest("RSA3072|PSS|SHA512|MGF1_SHA384|OnlySign"));
    ASSERT_NO_FATAL_FAILURE(RsaOnlySignCreateTest("RSA3072|PSS|SHA512|MGF1_SHA512|OnlySign"));
}

HWTEST_F(CryptoRsaOnlySignAndVerifyRecoverTest, CryptoRsaOnlySignTest605, TestSize.Level0)
{
    ASSERT_NO_FATAL_FAILURE(RsaOnlySignCreateTest("RSA4096|PSS|MD5|MGF1_MD5|OnlySign"));
    ASSERT_NO_FATAL_FAILURE(RsaOnlySignCreateTest("RSA4096|PSS|MD5|MGF1_SHA1|OnlySign"));
    ASSERT_NO_FATAL_FAILURE(RsaOnlySignCreateTest("RSA4096|PSS|MD5|MGF1_SHA224|OnlySign"));
    ASSERT_NO_FATAL_FAILURE(RsaOnlySignCreateTest("RSA4096|PSS|MD5|MGF1_SHA256|OnlySign"));
    ASSERT_NO_FATAL_FAILURE(RsaOnlySignCreateTest("RSA4096|PSS|MD5|MGF1_SHA384|OnlySign"));
    ASSERT_NO_FATAL_FAILURE(RsaOnlySignCreateTest("RSA4096|PSS|MD5|MGF1_SHA512|OnlySign"));
    ASSERT_NO_FATAL_FAILURE(RsaOnlySignCreateTest("RSA4096|PSS|SHA1|MGF1_MD5|OnlySign"));
    ASSERT_NO_FATAL_FAILURE(RsaOnlySignCreateTest("RSA4096|PSS|SHA1|MGF1_SHA1|OnlySign"));
    ASSERT_NO_FATAL_FAILURE(RsaOnlySignCreateTest("RSA4096|PSS|SHA1|MGF1_SHA224|OnlySign"));
    ASSERT_NO_FATAL_FAILURE(RsaOnlySignCreateTest("RSA4096|PSS|SHA1|MGF1_SHA256|OnlySign"));
    ASSERT_NO_FATAL_FAILURE(RsaOnlySignCreateTest("RSA4096|PSS|SHA1|MGF1_SHA384|OnlySign"));
    ASSERT_NO_FATAL_FAILURE(RsaOnlySignCreateTest("RSA4096|PSS|SHA1|MGF1_SHA512|OnlySign"));
    ASSERT_NO_FATAL_FAILURE(RsaOnlySignCreateTest("RSA4096|PSS|SHA224|MGF1_MD5|OnlySign"));
    ASSERT_NO_FATAL_FAILURE(RsaOnlySignCreateTest("RSA4096|PSS|SHA224|MGF1_SHA1|OnlySign"));
    ASSERT_NO_FATAL_FAILURE(RsaOnlySignCreateTest("RSA4096|PSS|SHA224|MGF1_SHA224|OnlySign"));
    ASSERT_NO_FATAL_FAILURE(RsaOnlySignCreateTest("RSA4096|PSS|SHA224|MGF1_SHA256|OnlySign"));
    ASSERT_NO_FATAL_FAILURE(RsaOnlySignCreateTest("RSA4096|PSS|SHA224|MGF1_SHA384|OnlySign"));
    ASSERT_NO_FATAL_FAILURE(RsaOnlySignCreateTest("RSA4096|PSS|SHA224|MGF1_SHA512|OnlySign"));
    ASSERT_NO_FATAL_FAILURE(RsaOnlySignCreateTest("RSA4096|PSS|SHA256|MGF1_MD5|OnlySign"));
    ASSERT_NO_FATAL_FAILURE(RsaOnlySignCreateTest("RSA4096|PSS|SHA256|MGF1_SHA1|OnlySign"));
    ASSERT_NO_FATAL_FAILURE(RsaOnlySignCreateTest("RSA4096|PSS|SHA256|MGF1_SHA224|OnlySign"));
    ASSERT_NO_FATAL_FAILURE(RsaOnlySignCreateTest("RSA4096|PSS|SHA256|MGF1_SHA256|OnlySign"));
    ASSERT_NO_FATAL_FAILURE(RsaOnlySignCreateTest("RSA4096|PSS|SHA256|MGF1_SHA384|OnlySign"));
    ASSERT_NO_FATAL_FAILURE(RsaOnlySignCreateTest("RSA4096|PSS|SHA256|MGF1_SHA512|OnlySign"));
    ASSERT_NO_FATAL_FAILURE(RsaOnlySignCreateTest("RSA4096|PSS|SHA384|MGF1_MD5|OnlySign"));
    ASSERT_NO_FATAL_FAILURE(RsaOnlySignCreateTest("RSA4096|PSS|SHA384|MGF1_SHA1|OnlySign"));
    ASSERT_NO_FATAL_FAILURE(RsaOnlySignCreateTest("RSA4096|PSS|SHA384|MGF1_SHA224|OnlySign"));
    ASSERT_NO_FATAL_FAILURE(RsaOnlySignCreateTest("RSA4096|PSS|SHA384|MGF1_SHA256|OnlySign"));
    ASSERT_NO_FATAL_FAILURE(RsaOnlySignCreateTest("RSA4096|PSS|SHA384|MGF1_SHA384|OnlySign"));
    ASSERT_NO_FATAL_FAILURE(RsaOnlySignCreateTest("RSA4096|PSS|SHA384|MGF1_SHA512|OnlySign"));
    ASSERT_NO_FATAL_FAILURE(RsaOnlySignCreateTest("RSA4096|PSS|SHA512|MGF1_MD5|OnlySign"));
    ASSERT_NO_FATAL_FAILURE(RsaOnlySignCreateTest("RSA4096|PSS|SHA512|MGF1_SHA1|OnlySign"));
    ASSERT_NO_FATAL_FAILURE(RsaOnlySignCreateTest("RSA4096|PSS|SHA512|MGF1_SHA224|OnlySign"));
    ASSERT_NO_FATAL_FAILURE(RsaOnlySignCreateTest("RSA4096|PSS|SHA512|MGF1_SHA256|OnlySign"));
    ASSERT_NO_FATAL_FAILURE(RsaOnlySignCreateTest("RSA4096|PSS|SHA512|MGF1_SHA384|OnlySign"));
    ASSERT_NO_FATAL_FAILURE(RsaOnlySignCreateTest("RSA4096|PSS|SHA512|MGF1_SHA512|OnlySign"));
}

HWTEST_F(CryptoRsaOnlySignAndVerifyRecoverTest, CryptoRsaOnlyVerifyTest600, TestSize.Level0)
{
    ASSERT_NO_FATAL_FAILURE(RsaOnlyVerifyCreateTest("RSA512|PSS|MD5|MGF1_MD5|OnlyVerify"));
    ASSERT_NO_FATAL_FAILURE(RsaOnlyVerifyCreateTest("RSA512|PSS|MD5|MGF1_SHA1|OnlyVerify"));
    ASSERT_NO_FATAL_FAILURE(RsaOnlyVerifyCreateTest("RSA512|PSS|MD5|MGF1_SHA224|OnlyVerify"));
    ASSERT_NO_FATAL_FAILURE(RsaOnlyVerifyCreateTest("RSA512|PSS|MD5|MGF1_SHA256|OnlyVerify"));
    ASSERT_NO_FATAL_FAILURE(RsaOnlyVerifyCreateTest("RSA512|PSS|SHA1|MGF1_MD5|OnlyVerify"));
    ASSERT_NO_FATAL_FAILURE(RsaOnlyVerifyCreateTest("RSA512|PSS|SHA1|MGF1_SHA1|OnlyVerify"));
    ASSERT_NO_FATAL_FAILURE(RsaOnlyVerifyCreateTest("RSA512|PSS|SHA1|MGF1_SHA224|OnlyVerify"));
    ASSERT_NO_FATAL_FAILURE(RsaOnlyVerifyCreateTest("RSA512|PSS|SHA1|MGF1_SHA256|OnlyVerify"));
    ASSERT_NO_FATAL_FAILURE(RsaOnlyVerifyCreateTest("RSA512|PSS|SHA224|MGF1_MD5|OnlyVerify"));
    ASSERT_NO_FATAL_FAILURE(RsaOnlyVerifyCreateTest("RSA512|PSS|SHA224|MGF1_SHA1|OnlyVerify"));
    ASSERT_NO_FATAL_FAILURE(RsaOnlyVerifyCreateTest("RSA512|PSS|SHA224|MGF1_SHA224|OnlyVerify"));
    ASSERT_NO_FATAL_FAILURE(RsaOnlyVerifyCreateTest("RSA512|PSS|SHA224|MGF1_SHA256|OnlyVerify"));
    ASSERT_NO_FATAL_FAILURE(RsaOnlyVerifyCreateTest("RSA512|PSS|SHA256|MGF1_MD5|OnlyVerify"));
    ASSERT_NO_FATAL_FAILURE(RsaOnlyVerifyCreateTest("RSA512|PSS|SHA256|MGF1_SHA1|OnlyVerify"));
    ASSERT_NO_FATAL_FAILURE(RsaOnlyVerifyCreateTest("RSA512|PSS|SHA256|MGF1_SHA224|OnlyVerify"));
    ASSERT_NO_FATAL_FAILURE(RsaOnlyVerifyCreateTest("RSA|PSS|SHA256|MGF1_SHA256|OnlyVerify"));
}

HWTEST_F(CryptoRsaOnlySignAndVerifyRecoverTest, CryptoRsaOnlyVerifyTest601, TestSize.Level0)
{
    ASSERT_NO_FATAL_FAILURE(RsaOnlyVerifyCreateTest("RSA768|PSS|MD5|MGF1_MD5|OnlyVerify"));
    ASSERT_NO_FATAL_FAILURE(RsaOnlyVerifyCreateTest("RSA768|PSS|MD5|MGF1_SHA1|OnlyVerify"));
    ASSERT_NO_FATAL_FAILURE(RsaOnlyVerifyCreateTest("RSA768|PSS|MD5|MGF1_SHA224|OnlyVerify"));
    ASSERT_NO_FATAL_FAILURE(RsaOnlyVerifyCreateTest("RSA768|PSS|MD5|MGF1_SHA256|OnlyVerify"));
    ASSERT_NO_FATAL_FAILURE(RsaOnlyVerifyCreateTest("RSA768|PSS|MD5|MGF1_SHA384|OnlyVerify"));
    ASSERT_NO_FATAL_FAILURE(RsaOnlyVerifyCreateTest("RSA768|PSS|MD5|MGF1_SHA512|OnlyVerify"));
    ASSERT_NO_FATAL_FAILURE(RsaOnlyVerifyCreateTest("RSA768|PSS|SHA1|MGF1_MD5|OnlyVerify"));
    ASSERT_NO_FATAL_FAILURE(RsaOnlyVerifyCreateTest("RSA768|PSS|SHA1|MGF1_SHA1|OnlyVerify"));
    ASSERT_NO_FATAL_FAILURE(RsaOnlyVerifyCreateTest("RSA768|PSS|SHA1|MGF1_SHA224|OnlyVerify"));
    ASSERT_NO_FATAL_FAILURE(RsaOnlyVerifyCreateTest("RSA768|PSS|SHA1|MGF1_SHA256|OnlyVerify"));
    ASSERT_NO_FATAL_FAILURE(RsaOnlyVerifyCreateTest("RSA768|PSS|SHA1|MGF1_SHA384|OnlyVerify"));
    ASSERT_NO_FATAL_FAILURE(RsaOnlyVerifyCreateTest("RSA768|PSS|SHA1|MGF1_SHA512|OnlyVerify"));
    ASSERT_NO_FATAL_FAILURE(RsaOnlyVerifyCreateTest("RSA768|PSS|SHA224|MGF1_MD5|OnlyVerify"));
    ASSERT_NO_FATAL_FAILURE(RsaOnlyVerifyCreateTest("RSA768|PSS|SHA224|MGF1_SHA1|OnlyVerify"));
    ASSERT_NO_FATAL_FAILURE(RsaOnlyVerifyCreateTest("RSA768|PSS|SHA224|MGF1_SHA224|OnlyVerify"));
    ASSERT_NO_FATAL_FAILURE(RsaOnlyVerifyCreateTest("RSA768|PSS|SHA224|MGF1_SHA256|OnlyVerify"));
    ASSERT_NO_FATAL_FAILURE(RsaOnlyVerifyCreateTest("RSA768|PSS|SHA224|MGF1_SHA384|OnlyVerify"));
    ASSERT_NO_FATAL_FAILURE(RsaOnlyVerifyCreateTest("RSA768|PSS|SHA224|MGF1_SHA512|OnlyVerify"));
    ASSERT_NO_FATAL_FAILURE(RsaOnlyVerifyCreateTest("RSA768|PSS|SHA256|MGF1_MD5|OnlyVerify"));
    ASSERT_NO_FATAL_FAILURE(RsaOnlyVerifyCreateTest("RSA768|PSS|SHA256|MGF1_SHA1|OnlyVerify"));
    ASSERT_NO_FATAL_FAILURE(RsaOnlyVerifyCreateTest("RSA768|PSS|SHA256|MGF1_SHA224|OnlyVerify"));
    ASSERT_NO_FATAL_FAILURE(RsaOnlyVerifyCreateTest("RSA768|PSS|SHA256|MGF1_SHA256|OnlyVerify"));
    ASSERT_NO_FATAL_FAILURE(RsaOnlyVerifyCreateTest("RSA768|PSS|SHA256|MGF1_SHA384|OnlyVerify"));
    ASSERT_NO_FATAL_FAILURE(RsaOnlyVerifyCreateTest("RSA768|PSS|SHA384|MGF1_MD5|OnlyVerify"));
    ASSERT_NO_FATAL_FAILURE(RsaOnlyVerifyCreateTest("RSA768|PSS|SHA384|MGF1_SHA1|OnlyVerify"));
    ASSERT_NO_FATAL_FAILURE(RsaOnlyVerifyCreateTest("RSA768|PSS|SHA384|MGF1_SHA224|OnlyVerify"));
    ASSERT_NO_FATAL_FAILURE(RsaOnlyVerifyCreateTest("RSA768|PSS|SHA384|MGF1_SHA256|OnlyVerify"));
    ASSERT_NO_FATAL_FAILURE(RsaOnlyVerifyCreateTest("RSA768|PSS|SHA512|MGF1_MD5|OnlyVerify"));
    ASSERT_NO_FATAL_FAILURE(RsaOnlyVerifyCreateTest("RSA768|PSS|SHA512|MGF1_SHA1|OnlyVerify"));
    ASSERT_NO_FATAL_FAILURE(RsaOnlyVerifyCreateTest("RSA768|PSS|SHA512|MGF1_SHA224|OnlyVerify"));
}

HWTEST_F(CryptoRsaOnlySignAndVerifyRecoverTest, CryptoRsaOnlyVerifyTest602, TestSize.Level0)
{
    ASSERT_NO_FATAL_FAILURE(RsaOnlyVerifyCreateTest("RSA1024|PSS|MD5|MGF1_MD5|OnlyVerify"));
    ASSERT_NO_FATAL_FAILURE(RsaOnlyVerifyCreateTest("RSA1024|PSS|MD5|MGF1_SHA1|OnlyVerify"));
    ASSERT_NO_FATAL_FAILURE(RsaOnlyVerifyCreateTest("RSA1024|PSS|MD5|MGF1_SHA224|OnlyVerify"));
    ASSERT_NO_FATAL_FAILURE(RsaOnlyVerifyCreateTest("RSA1024|PSS|MD5|MGF1_SHA256|OnlyVerify"));
    ASSERT_NO_FATAL_FAILURE(RsaOnlyVerifyCreateTest("RSA1024|PSS|MD5|MGF1_SHA384|OnlyVerify"));
    ASSERT_NO_FATAL_FAILURE(RsaOnlyVerifyCreateTest("RSA1024|PSS|MD5|MGF1_SHA512|OnlyVerify"));
    ASSERT_NO_FATAL_FAILURE(RsaOnlyVerifyCreateTest("RSA1024|PSS|SHA1|MGF1_MD5|OnlyVerify"));
    ASSERT_NO_FATAL_FAILURE(RsaOnlyVerifyCreateTest("RSA1024|PSS|SHA1|MGF1_SHA1|OnlyVerify"));
    ASSERT_NO_FATAL_FAILURE(RsaOnlyVerifyCreateTest("RSA1024|PSS|SHA1|MGF1_SHA224|OnlyVerify"));
    ASSERT_NO_FATAL_FAILURE(RsaOnlyVerifyCreateTest("RSA1024|PSS|SHA1|MGF1_SHA256|OnlyVerify"));
    ASSERT_NO_FATAL_FAILURE(RsaOnlyVerifyCreateTest("RSA1024|PSS|SHA1|MGF1_SHA384|OnlyVerify"));
    ASSERT_NO_FATAL_FAILURE(RsaOnlyVerifyCreateTest("RSA1024|PSS|SHA1|MGF1_SHA512|OnlyVerify"));
    ASSERT_NO_FATAL_FAILURE(RsaOnlyVerifyCreateTest("RSA1024|PSS|SHA224|MGF1_MD5|OnlyVerify"));
    ASSERT_NO_FATAL_FAILURE(RsaOnlyVerifyCreateTest("RSA1024|PSS|SHA224|MGF1_SHA1|OnlyVerify"));
    ASSERT_NO_FATAL_FAILURE(RsaOnlyVerifyCreateTest("RSA1024|PSS|SHA224|MGF1_SHA224|OnlyVerify"));
    ASSERT_NO_FATAL_FAILURE(RsaOnlyVerifyCreateTest("RSA1024|PSS|SHA224|MGF1_SHA256|OnlyVerify"));
    ASSERT_NO_FATAL_FAILURE(RsaOnlyVerifyCreateTest("RSA1024|PSS|SHA224|MGF1_SHA384|OnlyVerify"));
    ASSERT_NO_FATAL_FAILURE(RsaOnlyVerifyCreateTest("RSA1024|PSS|SHA224|MGF1_SHA512|OnlyVerify"));
    ASSERT_NO_FATAL_FAILURE(RsaOnlyVerifyCreateTest("RSA1024|PSS|SHA256|MGF1_MD5|OnlyVerify"));
    ASSERT_NO_FATAL_FAILURE(RsaOnlyVerifyCreateTest("RSA1024|PSS|SHA256|MGF1_SHA1|OnlyVerify"));
    ASSERT_NO_FATAL_FAILURE(RsaOnlyVerifyCreateTest("RSA1024|PSS|SHA256|MGF1_SHA224|OnlyVerify"));
    ASSERT_NO_FATAL_FAILURE(RsaOnlyVerifyCreateTest("RSA1024|PSS|SHA256|MGF1_SHA256|OnlyVerify"));
    ASSERT_NO_FATAL_FAILURE(RsaOnlyVerifyCreateTest("RSA1024|PSS|SHA256|MGF1_SHA384|OnlyVerify"));
    ASSERT_NO_FATAL_FAILURE(RsaOnlyVerifyCreateTest("RSA1024|PSS|SHA256|MGF1_SHA512|OnlyVerify"));
    ASSERT_NO_FATAL_FAILURE(RsaOnlyVerifyCreateTest("RSA1024|PSS|SHA384|MGF1_MD5|OnlyVerify"));
    ASSERT_NO_FATAL_FAILURE(RsaOnlyVerifyCreateTest("RSA1024|PSS|SHA384|MGF1_SHA1|OnlyVerify"));
    ASSERT_NO_FATAL_FAILURE(RsaOnlyVerifyCreateTest("RSA1024|PSS|SHA384|MGF1_SHA224|OnlyVerify"));
    ASSERT_NO_FATAL_FAILURE(RsaOnlyVerifyCreateTest("RSA1024|PSS|SHA384|MGF1_SHA256|OnlyVerify"));
    ASSERT_NO_FATAL_FAILURE(RsaOnlyVerifyCreateTest("RSA1024|PSS|SHA384|MGF1_SHA384|OnlyVerify"));
    ASSERT_NO_FATAL_FAILURE(RsaOnlyVerifyCreateTest("RSA1024|PSS|SHA384|MGF1_SHA512|OnlyVerify"));
    ASSERT_NO_FATAL_FAILURE(RsaOnlyVerifyCreateTest("RSA1024|PSS|SHA512|MGF1_MD5|OnlyVerify"));
    ASSERT_NO_FATAL_FAILURE(RsaOnlyVerifyCreateTest("RSA1024|PSS|SHA512|MGF1_SHA1|OnlyVerify"));
    ASSERT_NO_FATAL_FAILURE(RsaOnlyVerifyCreateTest("RSA1024|PSS|SHA512|MGF1_SHA224|OnlyVerify"));
    ASSERT_NO_FATAL_FAILURE(RsaOnlyVerifyCreateTest("RSA1024|PSS|SHA512|MGF1_SHA256|OnlyVerify"));
    ASSERT_NO_FATAL_FAILURE(RsaOnlyVerifyCreateTest("RSA1024|PSS|SHA512|MGF1_SHA384|OnlyVerify"));
}

HWTEST_F(CryptoRsaOnlySignAndVerifyRecoverTest, CryptoRsaOnlyVerifyTest603, TestSize.Level0)
{
    ASSERT_NO_FATAL_FAILURE(RsaOnlyVerifyCreateTest("RSA2048|PSS|MD5|MGF1_MD5|OnlyVerify"));
    ASSERT_NO_FATAL_FAILURE(RsaOnlyVerifyCreateTest("RSA2048|PSS|MD5|MGF1_SHA1|OnlyVerify"));
    ASSERT_NO_FATAL_FAILURE(RsaOnlyVerifyCreateTest("RSA2048|PSS|MD5|MGF1_SHA224|OnlyVerify"));
    ASSERT_NO_FATAL_FAILURE(RsaOnlyVerifyCreateTest("RSA2048|PSS|MD5|MGF1_SHA256|OnlyVerify"));
    ASSERT_NO_FATAL_FAILURE(RsaOnlyVerifyCreateTest("RSA2048|PSS|MD5|MGF1_SHA384|OnlyVerify"));
    ASSERT_NO_FATAL_FAILURE(RsaOnlyVerifyCreateTest("RSA2048|PSS|MD5|MGF1_SHA512|OnlyVerify"));
    ASSERT_NO_FATAL_FAILURE(RsaOnlyVerifyCreateTest("RSA2048|PSS|SHA1|MGF1_MD5|OnlyVerify"));
    ASSERT_NO_FATAL_FAILURE(RsaOnlyVerifyCreateTest("RSA2048|PSS|SHA1|MGF1_SHA1|OnlyVerify"));
    ASSERT_NO_FATAL_FAILURE(RsaOnlyVerifyCreateTest("RSA2048|PSS|SHA1|MGF1_SHA224|OnlyVerify"));
    ASSERT_NO_FATAL_FAILURE(RsaOnlyVerifyCreateTest("RSA2048|PSS|SHA1|MGF1_SHA256|OnlyVerify"));
    ASSERT_NO_FATAL_FAILURE(RsaOnlyVerifyCreateTest("RSA2048|PSS|SHA1|MGF1_SHA384|OnlyVerify"));
    ASSERT_NO_FATAL_FAILURE(RsaOnlyVerifyCreateTest("RSA2048|PSS|SHA1|MGF1_SHA512|OnlyVerify"));
    ASSERT_NO_FATAL_FAILURE(RsaOnlyVerifyCreateTest("RSA2048|PSS|SHA224|MGF1_MD5|OnlyVerify"));
    ASSERT_NO_FATAL_FAILURE(RsaOnlyVerifyCreateTest("RSA2048|PSS|SHA224|MGF1_SHA1|OnlyVerify"));
    ASSERT_NO_FATAL_FAILURE(RsaOnlyVerifyCreateTest("RSA2048|PSS|SHA224|MGF1_SHA224|OnlyVerify"));
    ASSERT_NO_FATAL_FAILURE(RsaOnlyVerifyCreateTest("RSA2048|PSS|SHA224|MGF1_SHA256|OnlyVerify"));
    ASSERT_NO_FATAL_FAILURE(RsaOnlyVerifyCreateTest("RSA2048|PSS|SHA224|MGF1_SHA384|OnlyVerify"));
    ASSERT_NO_FATAL_FAILURE(RsaOnlyVerifyCreateTest("RSA2048|PSS|SHA224|MGF1_SHA512|OnlyVerify"));
    ASSERT_NO_FATAL_FAILURE(RsaOnlyVerifyCreateTest("RSA2048|PSS|SHA256|MGF1_MD5|OnlyVerify"));
    ASSERT_NO_FATAL_FAILURE(RsaOnlyVerifyCreateTest("RSA2048|PSS|SHA256|MGF1_SHA1|OnlyVerify"));
    ASSERT_NO_FATAL_FAILURE(RsaOnlyVerifyCreateTest("RSA2048|PSS|SHA256|MGF1_SHA224|OnlyVerify"));
    ASSERT_NO_FATAL_FAILURE(RsaOnlyVerifyCreateTest("RSA2048|PSS|SHA256|MGF1_SHA256|OnlyVerify"));
    ASSERT_NO_FATAL_FAILURE(RsaOnlyVerifyCreateTest("RSA2048|PSS|SHA256|MGF1_SHA384|OnlyVerify"));
    ASSERT_NO_FATAL_FAILURE(RsaOnlyVerifyCreateTest("RSA2048|PSS|SHA256|MGF1_SHA512|OnlyVerify"));
    ASSERT_NO_FATAL_FAILURE(RsaOnlyVerifyCreateTest("RSA2048|PSS|SHA384|MGF1_MD5|OnlyVerify"));
    ASSERT_NO_FATAL_FAILURE(RsaOnlyVerifyCreateTest("RSA2048|PSS|SHA384|MGF1_SHA1|OnlyVerify"));
    ASSERT_NO_FATAL_FAILURE(RsaOnlyVerifyCreateTest("RSA2048|PSS|SHA384|MGF1_SHA224|OnlyVerify"));
    ASSERT_NO_FATAL_FAILURE(RsaOnlyVerifyCreateTest("RSA2048|PSS|SHA384|MGF1_SHA256|OnlyVerify"));
    ASSERT_NO_FATAL_FAILURE(RsaOnlyVerifyCreateTest("RSA2048|PSS|SHA384|MGF1_SHA384|OnlyVerify"));
    ASSERT_NO_FATAL_FAILURE(RsaOnlyVerifyCreateTest("RSA2048|PSS|SHA384|MGF1_SHA512|OnlyVerify"));
    ASSERT_NO_FATAL_FAILURE(RsaOnlyVerifyCreateTest("RSA2048|PSS|SHA512|MGF1_MD5|OnlyVerify"));
    ASSERT_NO_FATAL_FAILURE(RsaOnlyVerifyCreateTest("RSA2048|PSS|SHA512|MGF1_SHA1|OnlyVerify"));
    ASSERT_NO_FATAL_FAILURE(RsaOnlyVerifyCreateTest("RSA2048|PSS|SHA512|MGF1_SHA224|OnlyVerify"));
    ASSERT_NO_FATAL_FAILURE(RsaOnlyVerifyCreateTest("RSA2048|PSS|SHA512|MGF1_SHA256|OnlyVerify"));
    ASSERT_NO_FATAL_FAILURE(RsaOnlyVerifyCreateTest("RSA2048|PSS|SHA512|MGF1_SHA384|OnlyVerify"));
    ASSERT_NO_FATAL_FAILURE(RsaOnlyVerifyCreateTest("RSA2048|PSS|SHA512|MGF1_SHA512|OnlyVerify"));
}

HWTEST_F(CryptoRsaOnlySignAndVerifyRecoverTest, CryptoRsaOnlyVerifyTest604, TestSize.Level0)
{
    ASSERT_NO_FATAL_FAILURE(RsaOnlyVerifyCreateTest("RSA3072|PSS|MD5|MGF1_MD5|OnlyVerify"));
    ASSERT_NO_FATAL_FAILURE(RsaOnlyVerifyCreateTest("RSA3072|PSS|MD5|MGF1_SHA1|OnlyVerify"));
    ASSERT_NO_FATAL_FAILURE(RsaOnlyVerifyCreateTest("RSA3072|PSS|MD5|MGF1_SHA224|OnlyVerify"));
    ASSERT_NO_FATAL_FAILURE(RsaOnlyVerifyCreateTest("RSA3072|PSS|MD5|MGF1_SHA256|OnlyVerify"));
    ASSERT_NO_FATAL_FAILURE(RsaOnlyVerifyCreateTest("RSA3072|PSS|MD5|MGF1_SHA384|OnlyVerify"));
    ASSERT_NO_FATAL_FAILURE(RsaOnlyVerifyCreateTest("RSA3072|PSS|MD5|MGF1_SHA512|OnlyVerify"));
    ASSERT_NO_FATAL_FAILURE(RsaOnlyVerifyCreateTest("RSA3072|PSS|SHA1|MGF1_MD5|OnlyVerify"));
    ASSERT_NO_FATAL_FAILURE(RsaOnlyVerifyCreateTest("RSA3072|PSS|SHA1|MGF1_SHA1|OnlyVerify"));
    ASSERT_NO_FATAL_FAILURE(RsaOnlyVerifyCreateTest("RSA3072|PSS|SHA1|MGF1_SHA224|OnlyVerify"));
    ASSERT_NO_FATAL_FAILURE(RsaOnlyVerifyCreateTest("RSA3072|PSS|SHA1|MGF1_SHA256|OnlyVerify"));
    ASSERT_NO_FATAL_FAILURE(RsaOnlyVerifyCreateTest("RSA3072|PSS|SHA1|MGF1_SHA384|OnlyVerify"));
    ASSERT_NO_FATAL_FAILURE(RsaOnlyVerifyCreateTest("RSA3072|PSS|SHA1|MGF1_SHA512|OnlyVerify"));
    ASSERT_NO_FATAL_FAILURE(RsaOnlyVerifyCreateTest("RSA3072|PSS|SHA224|MGF1_MD5|OnlyVerify"));
    ASSERT_NO_FATAL_FAILURE(RsaOnlyVerifyCreateTest("RSA3072|PSS|SHA224|MGF1_SHA1|OnlyVerify"));
    ASSERT_NO_FATAL_FAILURE(RsaOnlyVerifyCreateTest("RSA3072|PSS|SHA224|MGF1_SHA224|OnlyVerify"));
    ASSERT_NO_FATAL_FAILURE(RsaOnlyVerifyCreateTest("RSA3072|PSS|SHA224|MGF1_SHA256|OnlyVerify"));
    ASSERT_NO_FATAL_FAILURE(RsaOnlyVerifyCreateTest("RSA3072|PSS|SHA224|MGF1_SHA384|OnlyVerify"));
    ASSERT_NO_FATAL_FAILURE(RsaOnlyVerifyCreateTest("RSA3072|PSS|SHA224|MGF1_SHA512|OnlyVerify"));
    ASSERT_NO_FATAL_FAILURE(RsaOnlyVerifyCreateTest("RSA3072|PSS|SHA256|MGF1_MD5|OnlyVerify"));
    ASSERT_NO_FATAL_FAILURE(RsaOnlyVerifyCreateTest("RSA3072|PSS|SHA256|MGF1_SHA1|OnlyVerify"));
    ASSERT_NO_FATAL_FAILURE(RsaOnlyVerifyCreateTest("RSA3072|PSS|SHA256|MGF1_SHA224|OnlyVerify"));
    ASSERT_NO_FATAL_FAILURE(RsaOnlyVerifyCreateTest("RSA3072|PSS|SHA256|MGF1_SHA256|OnlyVerify"));
    ASSERT_NO_FATAL_FAILURE(RsaOnlyVerifyCreateTest("RSA3072|PSS|SHA256|MGF1_SHA384|OnlyVerify"));
    ASSERT_NO_FATAL_FAILURE(RsaOnlyVerifyCreateTest("RSA3072|PSS|SHA256|MGF1_SHA512|OnlyVerify"));
    ASSERT_NO_FATAL_FAILURE(RsaOnlyVerifyCreateTest("RSA3072|PSS|SHA384|MGF1_MD5|OnlyVerify"));
    ASSERT_NO_FATAL_FAILURE(RsaOnlyVerifyCreateTest("RSA3072|PSS|SHA384|MGF1_SHA1|OnlyVerify"));
    ASSERT_NO_FATAL_FAILURE(RsaOnlyVerifyCreateTest("RSA3072|PSS|SHA384|MGF1_SHA224|OnlyVerify"));
    ASSERT_NO_FATAL_FAILURE(RsaOnlyVerifyCreateTest("RSA3072|PSS|SHA384|MGF1_SHA256|OnlyVerify"));
    ASSERT_NO_FATAL_FAILURE(RsaOnlyVerifyCreateTest("RSA3072|PSS|SHA384|MGF1_SHA384|OnlyVerify"));
    ASSERT_NO_FATAL_FAILURE(RsaOnlyVerifyCreateTest("RSA3072|PSS|SHA384|MGF1_SHA512|OnlyVerify"));
    ASSERT_NO_FATAL_FAILURE(RsaOnlyVerifyCreateTest("RSA3072|PSS|SHA512|MGF1_MD5|OnlyVerify"));
    ASSERT_NO_FATAL_FAILURE(RsaOnlyVerifyCreateTest("RSA3072|PSS|SHA512|MGF1_SHA1|OnlyVerify"));
    ASSERT_NO_FATAL_FAILURE(RsaOnlyVerifyCreateTest("RSA3072|PSS|SHA512|MGF1_SHA224|OnlyVerify"));
    ASSERT_NO_FATAL_FAILURE(RsaOnlyVerifyCreateTest("RSA3072|PSS|SHA512|MGF1_SHA256|OnlyVerify"));
    ASSERT_NO_FATAL_FAILURE(RsaOnlyVerifyCreateTest("RSA3072|PSS|SHA512|MGF1_SHA384|OnlyVerify"));
    ASSERT_NO_FATAL_FAILURE(RsaOnlyVerifyCreateTest("RSA3072|PSS|SHA512|MGF1_SHA512|OnlyVerify"));
}

HWTEST_F(CryptoRsaOnlySignAndVerifyRecoverTest, CryptoRsaOnlyVerifyTest605, TestSize.Level0)
{
    ASSERT_NO_FATAL_FAILURE(RsaOnlyVerifyCreateTest("RSA4096|PSS|MD5|MGF1_MD5|OnlyVerify"));
    ASSERT_NO_FATAL_FAILURE(RsaOnlyVerifyCreateTest("RSA4096|PSS|MD5|MGF1_SHA1|OnlyVerify"));
    ASSERT_NO_FATAL_FAILURE(RsaOnlyVerifyCreateTest("RSA4096|PSS|MD5|MGF1_SHA224|OnlyVerify"));
    ASSERT_NO_FATAL_FAILURE(RsaOnlyVerifyCreateTest("RSA4096|PSS|MD5|MGF1_SHA256|OnlyVerify"));
    ASSERT_NO_FATAL_FAILURE(RsaOnlyVerifyCreateTest("RSA4096|PSS|MD5|MGF1_SHA384|OnlyVerify"));
    ASSERT_NO_FATAL_FAILURE(RsaOnlyVerifyCreateTest("RSA4096|PSS|MD5|MGF1_SHA512|OnlyVerify"));
    ASSERT_NO_FATAL_FAILURE(RsaOnlyVerifyCreateTest("RSA4096|PSS|SHA1|MGF1_MD5|OnlyVerify"));
    ASSERT_NO_FATAL_FAILURE(RsaOnlyVerifyCreateTest("RSA4096|PSS|SHA1|MGF1_SHA1|OnlyVerify"));
    ASSERT_NO_FATAL_FAILURE(RsaOnlyVerifyCreateTest("RSA4096|PSS|SHA1|MGF1_SHA224|OnlyVerify"));
    ASSERT_NO_FATAL_FAILURE(RsaOnlyVerifyCreateTest("RSA4096|PSS|SHA1|MGF1_SHA256|OnlyVerify"));
    ASSERT_NO_FATAL_FAILURE(RsaOnlyVerifyCreateTest("RSA4096|PSS|SHA1|MGF1_SHA384|OnlyVerify"));
    ASSERT_NO_FATAL_FAILURE(RsaOnlyVerifyCreateTest("RSA4096|PSS|SHA1|MGF1_SHA512|OnlyVerify"));
    ASSERT_NO_FATAL_FAILURE(RsaOnlyVerifyCreateTest("RSA4096|PSS|SHA224|MGF1_MD5|OnlyVerify"));
    ASSERT_NO_FATAL_FAILURE(RsaOnlyVerifyCreateTest("RSA4096|PSS|SHA224|MGF1_SHA1|OnlyVerify"));
    ASSERT_NO_FATAL_FAILURE(RsaOnlyVerifyCreateTest("RSA4096|PSS|SHA224|MGF1_SHA224|OnlyVerify"));
    ASSERT_NO_FATAL_FAILURE(RsaOnlyVerifyCreateTest("RSA4096|PSS|SHA224|MGF1_SHA256|OnlyVerify"));
    ASSERT_NO_FATAL_FAILURE(RsaOnlyVerifyCreateTest("RSA4096|PSS|SHA224|MGF1_SHA384|OnlyVerify"));
    ASSERT_NO_FATAL_FAILURE(RsaOnlyVerifyCreateTest("RSA4096|PSS|SHA224|MGF1_SHA512|OnlyVerify"));
    ASSERT_NO_FATAL_FAILURE(RsaOnlyVerifyCreateTest("RSA4096|PSS|SHA256|MGF1_MD5|OnlyVerify"));
    ASSERT_NO_FATAL_FAILURE(RsaOnlyVerifyCreateTest("RSA4096|PSS|SHA256|MGF1_SHA1|OnlyVerify"));
    ASSERT_NO_FATAL_FAILURE(RsaOnlyVerifyCreateTest("RSA4096|PSS|SHA256|MGF1_SHA224|OnlyVerify"));
    ASSERT_NO_FATAL_FAILURE(RsaOnlyVerifyCreateTest("RSA4096|PSS|SHA256|MGF1_SHA256|OnlyVerify"));
    ASSERT_NO_FATAL_FAILURE(RsaOnlyVerifyCreateTest("RSA4096|PSS|SHA256|MGF1_SHA384|OnlyVerify"));
    ASSERT_NO_FATAL_FAILURE(RsaOnlyVerifyCreateTest("RSA4096|PSS|SHA256|MGF1_SHA512|OnlyVerify"));
    ASSERT_NO_FATAL_FAILURE(RsaOnlyVerifyCreateTest("RSA4096|PSS|SHA384|MGF1_MD5|OnlyVerify"));
    ASSERT_NO_FATAL_FAILURE(RsaOnlyVerifyCreateTest("RSA4096|PSS|SHA384|MGF1_SHA1|OnlyVerify"));
    ASSERT_NO_FATAL_FAILURE(RsaOnlyVerifyCreateTest("RSA4096|PSS|SHA384|MGF1_SHA224|OnlyVerify"));
    ASSERT_NO_FATAL_FAILURE(RsaOnlyVerifyCreateTest("RSA4096|PSS|SHA384|MGF1_SHA256|OnlyVerify"));
    ASSERT_NO_FATAL_FAILURE(RsaOnlyVerifyCreateTest("RSA4096|PSS|SHA384|MGF1_SHA384|OnlyVerify"));
    ASSERT_NO_FATAL_FAILURE(RsaOnlyVerifyCreateTest("RSA4096|PSS|SHA384|MGF1_SHA512|OnlyVerify"));
    ASSERT_NO_FATAL_FAILURE(RsaOnlyVerifyCreateTest("RSA4096|PSS|SHA512|MGF1_MD5|OnlyVerify"));
    ASSERT_NO_FATAL_FAILURE(RsaOnlyVerifyCreateTest("RSA4096|PSS|SHA512|MGF1_SHA1|OnlyVerify"));
    ASSERT_NO_FATAL_FAILURE(RsaOnlyVerifyCreateTest("RSA4096|PSS|SHA512|MGF1_SHA224|OnlyVerify"));
    ASSERT_NO_FATAL_FAILURE(RsaOnlyVerifyCreateTest("RSA4096|PSS|SHA512|MGF1_SHA256|OnlyVerify"));
    ASSERT_NO_FATAL_FAILURE(RsaOnlyVerifyCreateTest("RSA4096|PSS|SHA512|MGF1_SHA384|OnlyVerify"));
    ASSERT_NO_FATAL_FAILURE(RsaOnlyVerifyCreateTest("RSA4096|PSS|SHA512|MGF1_SHA512|OnlyVerify"));
}

HWTEST_F(CryptoRsaOnlySignAndVerifyRecoverTest, CryptoRsaOnlySignVerifyDigestPkcs1Test001, TestSize.Level0)
{
    ASSERT_NO_FATAL_FAILURE(RsaOnlySignVerifyDigestTest("RSA512", "SHA256",
        "RSA512|PKCS1|NoHash|OnlySign", "RSA512|PKCS1|NoHash|OnlyVerify"));
    ASSERT_NO_FATAL_FAILURE(RsaOnlySignVerifyDigestTest("RSA512", "MD5",
        "RSA512|PKCS1|MD5|OnlySign", "RSA512|PKCS1|MD5|OnlyVerify"));
    ASSERT_NO_FATAL_FAILURE(RsaOnlySignVerifyDigestTest("RSA512", "SHA1",
        "RSA512|PKCS1|SHA1|OnlySign", "RSA512|PKCS1|SHA1|OnlyVerify"));
    ASSERT_NO_FATAL_FAILURE(RsaOnlySignVerifyDigestTest("RSA512", "SHA224",
        "RSA512|PKCS1|SHA224|OnlySign", "RSA512|PKCS1|SHA224|OnlyVerify"));
    ASSERT_NO_FATAL_FAILURE(RsaOnlySignVerifyDigestTest("RSA512", "SHA256",
        "RSA512|PKCS1|SHA256|OnlySign", "RSA512|PKCS1|SHA256|OnlyVerify"));

    ASSERT_NO_FATAL_FAILURE(RsaOnlySignVerifyDigestTest("RSA768", "SHA256",
        "RSA768|PKCS1|NoHash|OnlySign", "RSA768|PKCS1|NoHash|OnlyVerify"));
    ASSERT_NO_FATAL_FAILURE(RsaOnlySignVerifyDigestTest("RSA768", "MD5",
        "RSA768|PKCS1|MD5|OnlySign", "RSA768|PKCS1|MD5|OnlyVerify"));
    ASSERT_NO_FATAL_FAILURE(RsaOnlySignVerifyDigestTest("RSA768", "SHA1",
        "RSA768|PKCS1|SHA1|OnlySign", "RSA768|PKCS1|SHA1|OnlyVerify"));
    ASSERT_NO_FATAL_FAILURE(RsaOnlySignVerifyDigestTest("RSA768", "SHA224",
        "RSA768|PKCS1|SHA224|OnlySign", "RSA768|PKCS1|SHA224|OnlyVerify"));
    ASSERT_NO_FATAL_FAILURE(RsaOnlySignVerifyDigestTest("RSA768", "SHA256",
        "RSA768|PKCS1|SHA256|OnlySign", "RSA768|PKCS1|SHA256|OnlyVerify"));
    ASSERT_NO_FATAL_FAILURE(RsaOnlySignVerifyDigestTest("RSA768", "SHA384",
        "RSA768|PKCS1|SHA384|OnlySign", "RSA768|PKCS1|SHA384|OnlyVerify"));
    ASSERT_NO_FATAL_FAILURE(RsaOnlySignVerifyDigestTest("RSA768", "SHA512",
        "RSA768|PKCS1|SHA512|OnlySign", "RSA768|PKCS1|SHA512|OnlyVerify"));
}

HWTEST_F(CryptoRsaOnlySignAndVerifyRecoverTest, CryptoRsaOnlySignVerifyDigestPkcs1Test002, TestSize.Level0)
{
    ASSERT_NO_FATAL_FAILURE(RsaOnlySignVerifyDigestTest("RSA768", "SHA256",
        "RSA768|PKCS1|NoHash|OnlySign", "RSA768|PKCS1|NoHash|OnlyVerify"));
    ASSERT_NO_FATAL_FAILURE(RsaOnlySignVerifyDigestTest("RSA768", "MD5",
        "RSA768|PKCS1|MD5|OnlySign", "RSA768|PKCS1|MD5|OnlyVerify"));
    ASSERT_NO_FATAL_FAILURE(RsaOnlySignVerifyDigestTest("RSA768", "SHA1",
        "RSA768|PKCS1|SHA1|OnlySign", "RSA768|PKCS1|SHA1|OnlyVerify"));
    ASSERT_NO_FATAL_FAILURE(RsaOnlySignVerifyDigestTest("RSA768", "SHA224",
        "RSA768|PKCS1|SHA224|OnlySign", "RSA768|PKCS1|SHA224|OnlyVerify"));
    ASSERT_NO_FATAL_FAILURE(RsaOnlySignVerifyDigestTest("RSA768", "SHA256",
        "RSA768|PKCS1|SHA256|OnlySign", "RSA768|PKCS1|SHA256|OnlyVerify"));
    ASSERT_NO_FATAL_FAILURE(RsaOnlySignVerifyDigestTest("RSA768", "SHA384",
        "RSA768|PKCS1|SHA384|OnlySign", "RSA768|PKCS1|SHA384|OnlyVerify"));
    ASSERT_NO_FATAL_FAILURE(RsaOnlySignVerifyDigestTest("RSA768", "SHA512",
        "RSA768|PKCS1|SHA512|OnlySign", "RSA768|PKCS1|SHA512|OnlyVerify"));
}

HWTEST_F(CryptoRsaOnlySignAndVerifyRecoverTest, CryptoRsaOnlySignVerifyDigestPkcs1Test003, TestSize.Level0)
{
    ASSERT_NO_FATAL_FAILURE(RsaOnlySignVerifyDigestTest("RSA1024", "SHA256",
        "RSA1024|PKCS1|NoHash|OnlySign", "RSA1024|PKCS1|NoHash|OnlyVerify"));
    ASSERT_NO_FATAL_FAILURE(RsaOnlySignVerifyDigestTest("RSA1024", "MD5",
        "RSA1024|PKCS1|MD5|OnlySign", "RSA1024|PKCS1|MD5|OnlyVerify"));
    ASSERT_NO_FATAL_FAILURE(RsaOnlySignVerifyDigestTest("RSA1024", "SHA1",
        "RSA1024|PKCS1|SHA1|OnlySign", "RSA1024|PKCS1|SHA1|OnlyVerify"));
    ASSERT_NO_FATAL_FAILURE(RsaOnlySignVerifyDigestTest("RSA1024", "SHA224",
        "RSA1024|PKCS1|SHA224|OnlySign", "RSA1024|PKCS1|SHA224|OnlyVerify"));
    ASSERT_NO_FATAL_FAILURE(RsaOnlySignVerifyDigestTest("RSA1024", "SHA256",
        "RSA1024|PKCS1|SHA256|OnlySign", "RSA1024|PKCS1|SHA256|OnlyVerify"));
    ASSERT_NO_FATAL_FAILURE(RsaOnlySignVerifyDigestTest("RSA1024", "SHA384",
        "RSA1024|PKCS1|SHA384|OnlySign", "RSA1024|PKCS1|SHA384|OnlyVerify"));
    ASSERT_NO_FATAL_FAILURE(RsaOnlySignVerifyDigestTest("RSA1024", "SHA512",
        "RSA1024|PKCS1|SHA512|OnlySign", "RSA1024|PKCS1|SHA512|OnlyVerify"));
}

HWTEST_F(CryptoRsaOnlySignAndVerifyRecoverTest, CryptoRsaOnlySignVerifyDigestPkcs1Test004, TestSize.Level0)
{
    ASSERT_NO_FATAL_FAILURE(RsaOnlySignVerifyDigestTest("RSA2048", "SHA256",
        "RSA2048|PKCS1|NoHash|OnlySign", "RSA2048|PKCS1|NoHash|OnlyVerify"));
    ASSERT_NO_FATAL_FAILURE(RsaOnlySignVerifyDigestTest("RSA2048", "MD5",
        "RSA2048|PKCS1|MD5|OnlySign", "RSA2048|PKCS1|MD5|OnlyVerify"));
    ASSERT_NO_FATAL_FAILURE(RsaOnlySignVerifyDigestTest("RSA2048", "SHA1",
        "RSA2048|PKCS1|SHA1|OnlySign", "RSA2048|PKCS1|SHA1|OnlyVerify"));
    ASSERT_NO_FATAL_FAILURE(RsaOnlySignVerifyDigestTest("RSA2048", "SHA224",
        "RSA2048|PKCS1|SHA224|OnlySign", "RSA2048|PKCS1|SHA224|OnlyVerify"));
    ASSERT_NO_FATAL_FAILURE(RsaOnlySignVerifyDigestTest("RSA2048", "SHA256",
        "RSA2048|PKCS1|SHA256|OnlySign", "RSA2048|PKCS1|SHA256|OnlyVerify"));
    ASSERT_NO_FATAL_FAILURE(RsaOnlySignVerifyDigestTest("RSA2048", "SHA384",
        "RSA2048|PKCS1|SHA384|OnlySign", "RSA2048|PKCS1|SHA384|OnlyVerify"));
    ASSERT_NO_FATAL_FAILURE(RsaOnlySignVerifyDigestTest("RSA2048", "SHA512",
        "RSA2048|PKCS1|SHA512|OnlySign", "RSA2048|PKCS1|SHA512|OnlyVerify"));
}

HWTEST_F(CryptoRsaOnlySignAndVerifyRecoverTest, CryptoRsaOnlySignVerifyDigestPkcs1Test005, TestSize.Level0)
{
    ASSERT_NO_FATAL_FAILURE(RsaOnlySignVerifyDigestTest("RSA3072", "SHA256",
        "RSA3072|PKCS1|NoHash|OnlySign", "RSA3072|PKCS1|NoHash|OnlyVerify"));
    ASSERT_NO_FATAL_FAILURE(RsaOnlySignVerifyDigestTest("RSA3072", "MD5",
        "RSA3072|PKCS1|MD5|OnlySign", "RSA3072|PKCS1|MD5|OnlyVerify"));
    ASSERT_NO_FATAL_FAILURE(RsaOnlySignVerifyDigestTest("RSA3072", "SHA1",
        "RSA3072|PKCS1|SHA1|OnlySign", "RSA3072|PKCS1|SHA1|OnlyVerify"));
    ASSERT_NO_FATAL_FAILURE(RsaOnlySignVerifyDigestTest("RSA3072", "SHA224",
        "RSA3072|PKCS1|SHA224|OnlySign", "RSA3072|PKCS1|SHA224|OnlyVerify"));
    ASSERT_NO_FATAL_FAILURE(RsaOnlySignVerifyDigestTest("RSA3072", "SHA256",
        "RSA3072|PKCS1|SHA256|OnlySign", "RSA3072|PKCS1|SHA256|OnlyVerify"));
    ASSERT_NO_FATAL_FAILURE(RsaOnlySignVerifyDigestTest("RSA3072", "SHA384",
        "RSA3072|PKCS1|SHA384|OnlySign", "RSA3072|PKCS1|SHA384|OnlyVerify"));
    ASSERT_NO_FATAL_FAILURE(RsaOnlySignVerifyDigestTest("RSA3072", "SHA512",
        "RSA3072|PKCS1|SHA512|OnlySign", "RSA3072|PKCS1|SHA512|OnlyVerify"));
}

HWTEST_F(CryptoRsaOnlySignAndVerifyRecoverTest, CryptoRsaOnlySignVerifyDigestPkcs1Test006, TestSize.Level0)
{
    ASSERT_NO_FATAL_FAILURE(RsaOnlySignVerifyDigestTest("RSA4096", "SHA256",
        "RSA4096|PKCS1|NoHash|OnlySign", "RSA4096|PKCS1|NoHash|OnlyVerify"));
    ASSERT_NO_FATAL_FAILURE(RsaOnlySignVerifyDigestTest("RSA4096", "MD5",
        "RSA4096|PKCS1|MD5|OnlySign", "RSA4096|PKCS1|MD5|OnlyVerify"));
    ASSERT_NO_FATAL_FAILURE(RsaOnlySignVerifyDigestTest("RSA4096", "SHA1",
        "RSA4096|PKCS1|SHA1|OnlySign", "RSA4096|PKCS1|SHA1|OnlyVerify"));
    ASSERT_NO_FATAL_FAILURE(RsaOnlySignVerifyDigestTest("RSA4096", "SHA224",
        "RSA4096|PKCS1|SHA224|OnlySign", "RSA4096|PKCS1|SHA224|OnlyVerify"));
    ASSERT_NO_FATAL_FAILURE(RsaOnlySignVerifyDigestTest("RSA4096", "SHA256",
        "RSA4096|PKCS1|SHA256|OnlySign", "RSA4096|PKCS1|SHA256|OnlyVerify"));
    ASSERT_NO_FATAL_FAILURE(RsaOnlySignVerifyDigestTest("RSA4096", "SHA384",
        "RSA4096|PKCS1|SHA384|OnlySign", "RSA4096|PKCS1|SHA384|OnlyVerify"));
    ASSERT_NO_FATAL_FAILURE(RsaOnlySignVerifyDigestTest("RSA4096", "SHA512",
        "RSA4096|PKCS1|SHA512|OnlySign", "RSA4096|PKCS1|SHA512|OnlyVerify"));
}

HWTEST_F(CryptoRsaOnlySignAndVerifyRecoverTest, CryptoRsaOnlySignVerifyDigestPkcs1Test008, TestSize.Level0)
{
    ASSERT_NO_FATAL_FAILURE(RsaOnlySignVerifyDigestTest("RSA1024", "SHA256",
        "RSA|PKCS1|NoHash|OnlySign", "RSA|PKCS1|NoHash|OnlyVerify"));
    ASSERT_NO_FATAL_FAILURE(RsaOnlySignVerifyDigestTest("RSA1024", "MD5",
        "RSA|PKCS1|MD5|OnlySign", "RSA|PKCS1|MD5|OnlyVerify"));
    ASSERT_NO_FATAL_FAILURE(RsaOnlySignVerifyDigestTest("RSA1024", "SHA1",
        "RSA|PKCS1|SHA1|OnlySign", "RSA|PKCS1|SHA1|OnlyVerify"));
    ASSERT_NO_FATAL_FAILURE(RsaOnlySignVerifyDigestTest("RSA1024", "SHA224",
        "RSA|PKCS1|SHA224|OnlySign", "RSA|PKCS1|SHA224|OnlyVerify"));
    ASSERT_NO_FATAL_FAILURE(RsaOnlySignVerifyDigestTest("RSA1024", "SHA256",
        "RSA|PKCS1|SHA256|OnlySign", "RSA|PKCS1|SHA256|OnlyVerify"));
    ASSERT_NO_FATAL_FAILURE(RsaOnlySignVerifyDigestTest("RSA1024", "SHA384",
        "RSA|PKCS1|SHA384|OnlySign", "RSA|PKCS1|SHA384|OnlyVerify"));
    ASSERT_NO_FATAL_FAILURE(RsaOnlySignVerifyDigestTest("RSA1024", "SHA512",
        "RSA|PKCS1|SHA512|OnlySign", "RSA|PKCS1|SHA512|OnlyVerify"));
}

HWTEST_F(CryptoRsaOnlySignAndVerifyRecoverTest, CryptoRsaOnlySignVerifyDigestPkcs1Test009, TestSize.Level0)
{
    ASSERT_NO_FATAL_FAILURE(RsaOnlySignVerifyDigestTest("RSA512", "SHA512",
        "RSA512|NoPadding|NoHash|OnlySign", "RSA512|NoPadding|NoHash|OnlyVerify"));
    ASSERT_NO_FATAL_FAILURE(RsaOnlySignVerifyDigestTest("RSA512", "SHA512",
        "RSA|NoPadding|NoHash|OnlySign", "RSA|NoPadding|NoHash|OnlyVerify"));
    ASSERT_NO_FATAL_FAILURE(RsaOnlySignVerifyDigestTestError("RSA768", "SHA512",
        "RSA768|NoPadding|NoHash|OnlySign", "RSA768|NoPadding|NoHash|OnlyVerify"));
    ASSERT_NO_FATAL_FAILURE(RsaOnlySignVerifyDigestTestError("RSA1024", "SHA512",
        "RSA1024|NoPadding|NoHash|OnlySign", "RSA1024|NoPadding|NoHash|OnlyVerify"));
    ASSERT_NO_FATAL_FAILURE(RsaOnlySignVerifyDigestTestError("RSA2048", "SHA512",
        "RSA2048|NoPadding|NoHash|OnlySign", "RSA2048|NoPadding|NoHash|OnlyVerify"));
    ASSERT_NO_FATAL_FAILURE(RsaOnlySignVerifyDigestTestError("RSA3072", "SHA512",
        "RSA3072|NoPadding|NoHash|OnlySign", "RSA3072|NoPadding|NoHash|OnlyVerify"));
    ASSERT_NO_FATAL_FAILURE(RsaOnlySignVerifyDigestTestError("RSA4096", "SHA512",
        "RSA4096|NoPadding|NoHash|OnlySign", "RSA4096|NoPadding|NoHash|OnlyVerify"));
}

HWTEST_F(CryptoRsaOnlySignAndVerifyRecoverTest, CryptoRsaOnlySignVerifyDigestPssTest001, TestSize.Level0)
{
    ASSERT_TRUE(RunRsaPssDigestCases("RSA512", "MD5", MGF_ALL4, sizeof(MGF_ALL4) / sizeof(MGF_ALL4[0])));
    ASSERT_TRUE(RunRsaPssDigestCases("RSA512", "SHA1", MGF_ALL4, sizeof(MGF_ALL4) / sizeof(MGF_ALL4[0])));
    ASSERT_TRUE(RunRsaPssDigestCases("RSA512", "SHA224", MGF_ALL4, sizeof(MGF_ALL4) / sizeof(MGF_ALL4[0])));
    ASSERT_TRUE(RunRsaPssDigestCases("RSA512", "SHA256", MGF_ALL3, sizeof(MGF_ALL3) / sizeof(MGF_ALL3[0])));
}

HWTEST_F(CryptoRsaOnlySignAndVerifyRecoverTest, CryptoRsaOnlySignVerifyDigestPssTest002, TestSize.Level0)
{
    ASSERT_TRUE(RunRsaPssDigestCases("RSA768", "MD5", MGF_ALL6, sizeof(MGF_ALL6) / sizeof(MGF_ALL6[0])));
    ASSERT_TRUE(RunRsaPssDigestCases("RSA768", "SHA1", MGF_ALL6, sizeof(MGF_ALL6) / sizeof(MGF_ALL6[0])));
    ASSERT_TRUE(RunRsaPssDigestCases("RSA768", "SHA224", MGF_ALL6, sizeof(MGF_ALL6) / sizeof(MGF_ALL6[0])));
    ASSERT_TRUE(RunRsaPssDigestCases("RSA768", "SHA256", MGF_768_SHA256,
        sizeof(MGF_768_SHA256) / sizeof(MGF_768_SHA256[0])));
    ASSERT_TRUE(RunRsaPssDigestCases("RSA768", "SHA384", MGF_768_SHA384,
        sizeof(MGF_768_SHA384) / sizeof(MGF_768_SHA384[0])));
    ASSERT_TRUE(RunRsaPssDigestCases("RSA768", "SHA512", MGF_768_SHA512,
        sizeof(MGF_768_SHA512) / sizeof(MGF_768_SHA512[0])));
}

HWTEST_F(CryptoRsaOnlySignAndVerifyRecoverTest, CryptoRsaOnlySignVerifyDigestPssTest003, TestSize.Level0)
{
    ASSERT_TRUE(RunRsaPssDigestCases("RSA1024", "MD5", MGF_ALL6, sizeof(MGF_ALL6) / sizeof(MGF_ALL6[0])));
    ASSERT_TRUE(RunRsaPssDigestCases("RSA1024", "SHA1", MGF_ALL6, sizeof(MGF_ALL6) / sizeof(MGF_ALL6[0])));
    ASSERT_TRUE(RunRsaPssDigestCases("RSA1024", "SHA224", MGF_ALL6, sizeof(MGF_ALL6) / sizeof(MGF_ALL6[0])));
    ASSERT_TRUE(RunRsaPssDigestCases("RSA1024", "SHA256", MGF_ALL6, sizeof(MGF_ALL6) / sizeof(MGF_ALL6[0])));
    ASSERT_TRUE(RunRsaPssDigestCases("RSA1024", "SHA384", MGF_ALL6, sizeof(MGF_ALL6) / sizeof(MGF_ALL6[0])));
    ASSERT_TRUE(RunRsaPssDigestCases("RSA1024", "SHA512", MGF_1024_SHA512,
        sizeof(MGF_1024_SHA512) / sizeof(MGF_1024_SHA512[0])));
}

HWTEST_F(CryptoRsaOnlySignAndVerifyRecoverTest, CryptoRsaOnlySignVerifyDigestPssTest004, TestSize.Level0)
{
    ASSERT_TRUE(RunRsaPssDigestCases("RSA2048", "MD5", MGF_ALL6, sizeof(MGF_ALL6) / sizeof(MGF_ALL6[0])));
    ASSERT_TRUE(RunRsaPssDigestCases("RSA2048", "SHA1", MGF_ALL6, sizeof(MGF_ALL6) / sizeof(MGF_ALL6[0])));
    ASSERT_TRUE(RunRsaPssDigestCases("RSA2048", "SHA224", MGF_ALL6, sizeof(MGF_ALL6) / sizeof(MGF_ALL6[0])));
    ASSERT_TRUE(RunRsaPssDigestCases("RSA2048", "SHA256", MGF_ALL6, sizeof(MGF_ALL6) / sizeof(MGF_ALL6[0])));
    ASSERT_TRUE(RunRsaPssDigestCases("RSA2048", "SHA384", MGF_ALL6, sizeof(MGF_ALL6) / sizeof(MGF_ALL6[0])));
    ASSERT_TRUE(RunRsaPssDigestCases("RSA2048", "SHA512", MGF_ALL6, sizeof(MGF_ALL6) / sizeof(MGF_ALL6[0])));
}

HWTEST_F(CryptoRsaOnlySignAndVerifyRecoverTest, CryptoRsaOnlySignVerifyDigestPssTest005, TestSize.Level0)
{
    ASSERT_TRUE(RunRsaPssDigestCases("RSA3072", "MD5", MGF_ALL6, sizeof(MGF_ALL6) / sizeof(MGF_ALL6[0])));
    ASSERT_TRUE(RunRsaPssDigestCases("RSA3072", "SHA1", MGF_ALL6, sizeof(MGF_ALL6) / sizeof(MGF_ALL6[0])));
    ASSERT_TRUE(RunRsaPssDigestCases("RSA3072", "SHA224", MGF_ALL6, sizeof(MGF_ALL6) / sizeof(MGF_ALL6[0])));
    ASSERT_TRUE(RunRsaPssDigestCases("RSA3072", "SHA256", MGF_ALL6, sizeof(MGF_ALL6) / sizeof(MGF_ALL6[0])));
    ASSERT_TRUE(RunRsaPssDigestCases("RSA3072", "SHA384", MGF_ALL6, sizeof(MGF_ALL6) / sizeof(MGF_ALL6[0])));
    ASSERT_TRUE(RunRsaPssDigestCases("RSA3072", "SHA512", MGF_ALL6, sizeof(MGF_ALL6) / sizeof(MGF_ALL6[0])));
}
}
