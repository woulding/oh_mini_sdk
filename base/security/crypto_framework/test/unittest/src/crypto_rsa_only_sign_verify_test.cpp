/*
 * Copyright (C) 2026 Huawei Device Co., Ltd.
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
#include <cstring>
#include "asy_key_generator.h"
#include "blob.h"
#include "ecdsa_openssl.h"
#include "md.h"
#include "memory.h"
#include "securec.h"
#include "signature.h"
#include "memory_mock.h"
#include "openssl_adapter_mock.h"
#include "mock.h"
#include "detailed_rsa_key_params.h"
#include "openssl_common.h"
#include "hex_utils.h"
#include <string>

using namespace std;
using namespace testing::ext;

using ::testing::_;
using ::testing::AnyNumber;
using ::testing::Invoke;
using ::testing::Return;

namespace {
class CryptoRSAOnlySignVerifyTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp();
    void TearDown();
public:
 	std::shared_ptr<HcfMock> mock_ = std::make_shared<HcfMock>();
};

void CryptoRSAOnlySignVerifyTest::SetUp()
{
    SetMock(mock_.get());
    // set default call function
    EXPECT_CALL(*mock_, HcfMalloc(_, _)).WillRepeatedly(Invoke(__real_HcfMalloc));
    EXPECT_CALL(*mock_, OpensslEvpMdCtxSize(_)).WillRepeatedly(Invoke(__real_OpensslEvpMdCtxSize));
    EXPECT_CALL(*mock_, HcfIsClassMatch(_, _)).WillRepeatedly(Invoke(__real_HcfIsClassMatch));
    EXPECT_CALL(*mock_, HcfIsStrValid(_, _)).WillRepeatedly(Invoke(__real_HcfIsStrValid));
    EXPECT_CALL(*mock_, OpensslEvpDigestInitEx(_, _, _)).WillRepeatedly(Invoke(__real_OpensslEvpDigestInitEx));
    EXPECT_CALL(*mock_, OpensslEvpPkeyNew()).WillRepeatedly(Invoke(__real_OpensslEvpPkeyNew));
    EXPECT_CALL(*mock_, OpensslEvpPkeyCtxNewFromPkey(_, _, _))
        .WillRepeatedly(Invoke(__real_OpensslEvpPkeyCtxNewFromPkey));
    EXPECT_CALL(*mock_, OpensslEvpPkeySignInit(_)).WillRepeatedly(Invoke(__real_OpensslEvpPkeySignInit));
    EXPECT_CALL(*mock_, OpensslEvpPkeySign(_, _, _, _, _)).WillRepeatedly(Invoke(__real_OpensslEvpPkeySign));
    EXPECT_CALL(*mock_, OpensslEvpPkeyVerifyInit(_)).WillRepeatedly(Invoke(__real_OpensslEvpPkeyVerifyInit));
    EXPECT_CALL(*mock_, OpensslEvpPkeyVerify(_, _, _, _, _)).WillRepeatedly(Invoke(__real_OpensslEvpPkeyVerify));
    EXPECT_CALL(*mock_, OpensslEvpPkeyCtxSetSignatureMd(_, _))
        .WillRepeatedly(Invoke(__real_OpensslEvpPkeyCtxSetSignatureMd));
    EXPECT_CALL(*mock_, OpensslEvpPkeyCtxSetRsaPadding(_, _))
        .WillRepeatedly(Invoke(__real_OpensslEvpPkeyCtxSetRsaPadding));
}

void CryptoRSAOnlySignVerifyTest::TearDown()
{
    ResetMock();
}

void CryptoRSAOnlySignVerifyTest::SetUpTestCase() {}
void CryptoRSAOnlySignVerifyTest::TearDownTestCase() {}

HWTEST_F(CryptoRSAOnlySignVerifyTest, CryptoRSAOnlySignVerifyTest001, TestSize.Level0)
{
    HcfResult res = HCF_SUCCESS;
    HcfAsyKeyGenerator *generator = nullptr;
    res = HcfAsyKeyGeneratorCreate("RSA2048", &generator);
    EXPECT_EQ(res, HCF_SUCCESS);

    HcfKeyPair *keyPair = nullptr;
    res = generator->generateKeyPair(generator, nullptr, &keyPair);
    EXPECT_EQ(res, HCF_SUCCESS);

    HcfVerify *verify = nullptr;
    // Test SetOnlyVerifyParams with InitRsaEvpKey failure
    verify = nullptr;
    res = HcfVerifyCreate("RSA2048|PKCS1|SHA256|OnlyVerify", &verify);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_CALL(*mock_, OpensslEvpPkeyNew())
             .WillOnce(Return(nullptr))
             .WillRepeatedly(Invoke(__real_OpensslEvpPkeyNew));
    res = verify->init(verify, nullptr, keyPair->pubKey);
    EXPECT_EQ(res, HCF_ERR_CRYPTO_OPERATION);
    HcfObjDestroy(verify);

    // Test SetOnlyVerifyParams with OpensslEvpPkeyCtxNewFromPkey failure
    verify = nullptr;
    res = HcfVerifyCreate("RSA2048|PKCS1|SHA256|OnlyVerify", &verify);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_CALL(*mock_, OpensslEvpPkeyCtxNewFromPkey(_, _, _))
             .WillOnce(Return(nullptr))
             .WillRepeatedly(Invoke(__real_OpensslEvpPkeyCtxNewFromPkey));
    res = verify->init(verify, nullptr, keyPair->pubKey);
    EXPECT_EQ(res, HCF_ERR_CRYPTO_OPERATION);
    HcfObjDestroy(verify);

    // Test SetOnlyVerifyParams with OpensslEvpPkeyVerifyInit failure
    verify = nullptr;
    res = HcfVerifyCreate("RSA2048|PKCS1|SHA256|OnlyVerify", &verify);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_CALL(*mock_, OpensslEvpPkeyVerifyInit(_))
             .WillOnce(Return(-1))
             .WillRepeatedly(Invoke(__real_OpensslEvpPkeyVerifyInit));
    res = verify->init(verify, nullptr, keyPair->pubKey);
    EXPECT_EQ(res, HCF_ERR_CRYPTO_OPERATION);
    HcfObjDestroy(verify);

    HcfObjDestroy(keyPair);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoRSAOnlySignVerifyTest, CryptoRSAOnlySignVerifyTest002, TestSize.Level0)
{
    HcfResult res = HCF_SUCCESS;
    HcfAsyKeyGenerator *generator = nullptr;
    res = HcfAsyKeyGeneratorCreate("RSA2048", &generator);
    EXPECT_EQ(res, HCF_SUCCESS);

    HcfKeyPair *keyPair = nullptr;
    res = generator->generateKeyPair(generator, nullptr, &keyPair);
    EXPECT_EQ(res, HCF_SUCCESS);

    // Test SetOnlyVerifyParams with OpensslEvpPkeyCtxSetSignatureMd failure
    HcfVerify *verify = nullptr;
    res = HcfVerifyCreate("RSA2048|PKCS1|SHA256|OnlyVerify", &verify);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_CALL(*mock_, OpensslEvpPkeyCtxSetSignatureMd(_, _))
             .WillOnce(Return(-1))
             .WillRepeatedly(Invoke(__real_OpensslEvpPkeyCtxSetSignatureMd));
    res = verify->init(verify, nullptr, keyPair->pubKey);
    EXPECT_EQ(res, HCF_ERR_CRYPTO_OPERATION);
    HcfObjDestroy(verify);

    // Test SetOnlyVerifyParams with OpensslEvpPkeyCtxSetRsaPadding failure
    verify = nullptr;
    res = HcfVerifyCreate("RSA2048|PKCS1|SHA256|OnlyVerify", &verify);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_CALL(*mock_, OpensslEvpPkeyCtxSetRsaPadding(_, _))
             .WillOnce(Return(-1))
             .WillRepeatedly(Invoke(__real_OpensslEvpPkeyCtxSetRsaPadding));
    res = verify->init(verify, nullptr, keyPair->pubKey);
    EXPECT_EQ(res, HCF_ERR_CRYPTO_OPERATION);
    HcfObjDestroy(verify);

    HcfObjDestroy(keyPair);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoRSAOnlySignVerifyTest, CryptoRSAOnlySignVerifyTest003, TestSize.Level0)
{
    HcfResult res = HCF_SUCCESS;
    HcfAsyKeyGenerator *generator = nullptr;
    res = HcfAsyKeyGeneratorCreate("RSA2048", &generator);
    EXPECT_EQ(res, HCF_SUCCESS);

    HcfKeyPair *keyPair = nullptr;
    res = generator->generateKeyPair(generator, nullptr, &keyPair);
    EXPECT_EQ(res, HCF_SUCCESS);

    uint8_t plan[] = "this is rsa only sign verify test.";
    HcfBlob input = {.data = plan, .len = strlen((char *)plan)};
    HcfBlob digest = {.data = nullptr, .len = 0};

    HcfMd *mdObj = nullptr;
    res = HcfMdCreate("SHA256", &mdObj);
    ASSERT_EQ(res, HCF_SUCCESS);
    res = mdObj->update(mdObj, &input);
    EXPECT_EQ(res, HCF_SUCCESS);
    res = mdObj->doFinal(mdObj, &digest);
    EXPECT_EQ(res, HCF_SUCCESS);

    HcfSign *sign = nullptr;
    res = HcfSignCreate("RSA2048|PKCS1|SHA256|OnlySign", &sign);
    EXPECT_EQ(res, HCF_SUCCESS);
    res = sign->init(sign, nullptr, keyPair->priKey);
    EXPECT_EQ(res, HCF_SUCCESS);

    HcfBlob signatureData = {.data = nullptr, .len = 0};
    res = sign->sign(sign, &digest, &signatureData);
    EXPECT_EQ(res, HCF_SUCCESS);

    // Test EngineOnlyVerifyWithData with OpensslEvpPkeyVerify failure
    HcfVerify *verify = nullptr;
    res = HcfVerifyCreate("RSA2048|PKCS1|SHA256|OnlyVerify", &verify);
    EXPECT_EQ(res, HCF_SUCCESS);
    res = verify->init(verify, nullptr, keyPair->pubKey);
    EXPECT_EQ(res, HCF_SUCCESS);

    EXPECT_CALL(*mock_, OpensslEvpPkeyVerify(_, _, _, _, _))
             .WillOnce(Return(-1))
             .WillRepeatedly(Invoke(__real_OpensslEvpPkeyVerify));
    bool result = verify->verify(verify, &digest, &signatureData);
    EXPECT_EQ(result, false);

    HcfObjDestroy(verify);
    HcfObjDestroy(sign);
    HcfBlobDataClearAndFree(&signatureData);
    HcfObjDestroy(mdObj);
    HcfBlobDataClearAndFree(&digest);
    HcfObjDestroy(keyPair);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoRSAOnlySignVerifyTest, CryptoRSAOnlySignVerifyTest004, TestSize.Level0)
{
    HcfResult res = HCF_SUCCESS;
    HcfAsyKeyGenerator *generator = nullptr;
    res = HcfAsyKeyGeneratorCreate("RSA2048", &generator);
    EXPECT_EQ(res, HCF_SUCCESS);

    HcfKeyPair *keyPair = nullptr;
    res = generator->generateKeyPair(generator, nullptr, &keyPair);
    EXPECT_EQ(res, HCF_SUCCESS);

    uint8_t plan[] = "this is rsa only sign verify test.";
    HcfBlob input = {.data = plan, .len = strlen((char *)plan)};
    HcfBlob digest = {.data = nullptr, .len = 0};

    HcfMd *mdObj = nullptr;
    res = HcfMdCreate("SHA256", &mdObj);
    ASSERT_EQ(res, HCF_SUCCESS);
    res = mdObj->update(mdObj, &input);
    EXPECT_EQ(res, HCF_SUCCESS);
    res = mdObj->doFinal(mdObj, &digest);
    EXPECT_EQ(res, HCF_SUCCESS);

    HcfSign *sign = nullptr;
    res = HcfSignCreate("RSA2048|PKCS1|SHA256|OnlySign", &sign);
    EXPECT_EQ(res, HCF_SUCCESS);
    res = sign->init(sign, nullptr, keyPair->priKey);
    EXPECT_EQ(res, HCF_SUCCESS);

    HcfBlob signatureData = {.data = nullptr, .len = 0};
    res = sign->sign(sign, &digest, &signatureData);
    EXPECT_EQ(res, HCF_SUCCESS);

    HcfVerify *verify = nullptr;
    res = HcfVerifyCreate("RSA2048|PKCS1|SHA256|OnlyVerify", &verify);
    EXPECT_EQ(res, HCF_SUCCESS);
    res = verify->init(verify, nullptr, keyPair->pubKey);
    EXPECT_EQ(res, HCF_SUCCESS);

    // Test with data = NULL
    bool result = verify->verify(verify, nullptr, &signatureData);
    EXPECT_EQ(result, false);

    HcfObjDestroy(verify);
    HcfObjDestroy(sign);
    HcfBlobDataClearAndFree(&signatureData);
    HcfObjDestroy(mdObj);
    HcfBlobDataClearAndFree(&digest);
    HcfObjDestroy(keyPair);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoRSAOnlySignVerifyTest, CryptoRSAOnlySignVerifyTest005, TestSize.Level0)
{
    HcfResult res = HCF_SUCCESS;
    HcfAsyKeyGenerator *generator = nullptr;
    res = HcfAsyKeyGeneratorCreate("RSA2048", &generator);
    EXPECT_EQ(res, HCF_SUCCESS);

    HcfKeyPair *keyPair = nullptr;
    res = generator->generateKeyPair(generator, nullptr, &keyPair);
    EXPECT_EQ(res, HCF_SUCCESS);

    uint8_t plan[] = "this is rsa only sign verify test.";
    HcfBlob input = {.data = plan, .len = strlen((char *)plan)};
    HcfBlob digest = {.data = nullptr, .len = 0};

    HcfMd *mdObj = nullptr;
    res = HcfMdCreate("SHA256", &mdObj);
    ASSERT_EQ(res, HCF_SUCCESS);
    res = mdObj->update(mdObj, &input);
    EXPECT_EQ(res, HCF_SUCCESS);
    res = mdObj->doFinal(mdObj, &digest);
    EXPECT_EQ(res, HCF_SUCCESS);

    HcfSign *sign = nullptr;
    res = HcfSignCreate("RSA2048|PKCS1|SHA256|OnlySign", &sign);
    EXPECT_EQ(res, HCF_SUCCESS);
    res = sign->init(sign, nullptr, keyPair->priKey);
    EXPECT_EQ(res, HCF_SUCCESS);
    
    HcfBlob signatureData = {.data = nullptr, .len = 0};
    res = sign->sign(sign, &digest, &signatureData);
    EXPECT_EQ(res, HCF_SUCCESS);

    HcfVerify *verify = nullptr;
    res = HcfVerifyCreate("RSA2048|PKCS1|SHA256|OnlyVerify", &verify);
    EXPECT_EQ(res, HCF_SUCCESS);
    res = verify->init(verify, nullptr, keyPair->pubKey);
    EXPECT_EQ(res, HCF_SUCCESS);

    // Test with data->len = 0
    HcfBlob emptyData = {.data = digest.data, .len = 0};
    bool result = verify->verify(verify, &emptyData, &signatureData);
    EXPECT_EQ(result, false);

    // Test with data->data = NULL
    HcfBlob nullDataPtr = {.data = nullptr, .len = digest.len};
    result = verify->verify(verify, &nullDataPtr, &signatureData);
    EXPECT_EQ(result, false);

    HcfObjDestroy(verify);
    HcfObjDestroy(sign);
    HcfBlobDataClearAndFree(&signatureData);
    HcfObjDestroy(mdObj);
    HcfBlobDataClearAndFree(&digest);
    HcfObjDestroy(keyPair);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoRSAOnlySignVerifyTest, CryptoRSAOnlySignVerifyTest006, TestSize.Level0)
{
    HcfResult res = HCF_SUCCESS;
    HcfAsyKeyGenerator *generator = nullptr;
    res = HcfAsyKeyGeneratorCreate("RSA2048", &generator);
    EXPECT_EQ(res, HCF_SUCCESS);

    HcfKeyPair *keyPair = nullptr;
    res = generator->generateKeyPair(generator, nullptr, &keyPair);
    EXPECT_EQ(res, HCF_SUCCESS);

    uint8_t plan[] = "this is rsa only sign verify test.";
    HcfBlob input = {.data = plan, .len = strlen((char *)plan)};
    HcfBlob digest = {.data = nullptr, .len = 0};

    HcfMd *mdObj = nullptr;
    res = HcfMdCreate("SHA256", &mdObj);
    ASSERT_EQ(res, HCF_SUCCESS);
    res = mdObj->update(mdObj, &input);
    EXPECT_EQ(res, HCF_SUCCESS);
    res = mdObj->doFinal(mdObj, &digest);
    EXPECT_EQ(res, HCF_SUCCESS);

    HcfSign *sign = nullptr;
    res = HcfSignCreate("RSA2048|PKCS1|SHA256|OnlySign", &sign);
    EXPECT_EQ(res, HCF_SUCCESS);
    res = sign->init(sign, nullptr, keyPair->priKey);
    EXPECT_EQ(res, HCF_SUCCESS);
    
    HcfBlob signatureData = {.data = nullptr, .len = 0};
    res = sign->sign(sign, &digest, &signatureData);
    EXPECT_EQ(res, HCF_SUCCESS);

    HcfVerify *verify = nullptr;
    res = HcfVerifyCreate("RSA2048|PKCS1|SHA256|OnlyVerify", &verify);
    EXPECT_EQ(res, HCF_SUCCESS);
    res = verify->init(verify, nullptr, keyPair->pubKey);
    EXPECT_EQ(res, HCF_SUCCESS);

    // Test with signatureData = NULL
    bool result = verify->verify(verify, &digest, nullptr);
    EXPECT_EQ(result, false);

    // Test with signatureData->data = NULL
    HcfBlob nullSigPtr = {.data = nullptr, .len = signatureData.len};
    result = verify->verify(verify, &digest, &nullSigPtr);
    EXPECT_EQ(result, false);

    HcfObjDestroy(verify);
    HcfObjDestroy(sign);
    HcfBlobDataClearAndFree(&signatureData);
    HcfObjDestroy(mdObj);
    HcfBlobDataClearAndFree(&digest);
    HcfObjDestroy(keyPair);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoRSAOnlySignVerifyTest, CryptoRSAOnlySignVerifyTest007, TestSize.Level0)
{
    HcfResult res = HCF_SUCCESS;
    HcfAsyKeyGenerator *generator = nullptr;
    res = HcfAsyKeyGeneratorCreate("RSA2048", &generator);
    EXPECT_EQ(res, HCF_SUCCESS);

    HcfKeyPair *keyPair = nullptr;
    res = generator->generateKeyPair(generator, nullptr, &keyPair);
    EXPECT_EQ(res, HCF_SUCCESS);

    uint8_t plan[] = "this is rsa only sign verify test.";
    HcfBlob input = {.data = plan, .len = strlen((char *)plan)};
    HcfBlob digest = {.data = nullptr, .len = 0};

    HcfMd *mdObj = nullptr;
    res = HcfMdCreate("SHA256", &mdObj);
    ASSERT_EQ(res, HCF_SUCCESS);
    res = mdObj->update(mdObj, &input);
    EXPECT_EQ(res, HCF_SUCCESS);
    res = mdObj->doFinal(mdObj, &digest);
    EXPECT_EQ(res, HCF_SUCCESS);

    HcfVerify *verify = nullptr;
    res = HcfVerifyCreate("RSA2048|PKCS1|SHA256|OnlyVerify", &verify);
    EXPECT_EQ(res, HCF_SUCCESS);
    res = verify->init(verify, nullptr, keyPair->pubKey);
    EXPECT_EQ(res, HCF_SUCCESS);

    // Test with signatureData = NULL
    bool result = verify->verify(verify, &digest, nullptr);
    EXPECT_EQ(result, false);

    // Test with signatureData->data = NULL
    HcfBlob nullSigPtr = {.data = nullptr, .len = 32};
    result = verify->verify(verify, &digest, &nullSigPtr);
    EXPECT_EQ(result, false);

    HcfObjDestroy(verify);
    HcfObjDestroy(mdObj);
    HcfBlobDataClearAndFree(&digest);
    HcfObjDestroy(keyPair);
    HcfObjDestroy(generator);
}

static void RsaOnlyVerifyVectorPkcs1Sha256Test(const char *pubKeyDerHex, const char *digestHex,
    const char *signatureHex, bool expectVerifyResult)
{
    HcfResult res = HCF_SUCCESS;
    HcfAsyKeyGenerator *generator = nullptr;
    res = HcfAsyKeyGeneratorCreate("RSA1024", &generator);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(generator, nullptr);

    HcfBlob pubKeyBlob = { .data = nullptr, .len = 0 };
    res = HexStringToBlob(pubKeyDerHex, &pubKeyBlob);
    EXPECT_EQ(res, HCF_SUCCESS);

    HcfKeyPair *keyPair = nullptr;
    res = generator->convertKey(generator, nullptr, &pubKeyBlob, nullptr, &keyPair);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(keyPair, nullptr);

    HcfBlob digest = { .data = nullptr, .len = 0 };
    res = HexStringToBlob(digestHex, &digest);
    EXPECT_EQ(res, HCF_SUCCESS);

    HcfBlob signature = { .data = nullptr, .len = 0 };
    res = HexStringToBlob(signatureHex, &signature);
    EXPECT_EQ(res, HCF_SUCCESS);

    HcfVerify *verify = nullptr;
    res = HcfVerifyCreate("RSA1024|PKCS1|SHA256|OnlyVerify", &verify);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(verify, nullptr);

    res = verify->init(verify, nullptr, keyPair->pubKey);
    EXPECT_EQ(res, HCF_SUCCESS);
    if (res == HCF_SUCCESS) {
        bool result = verify->verify(verify, &digest, &signature);
        EXPECT_EQ(result, expectVerifyResult);
    }

    HcfObjDestroy(verify);
    HcfFree(signature.data);
    HcfFree(digest.data);
    HcfObjDestroy(keyPair);
    HcfFree(pubKeyBlob.data);
    HcfObjDestroy(generator);
}

static void RsaOnlyVerifyVectorTest(const char *verifyAlgoName, const char *pubKeyDerHex, const char *digestHex,
    const char *signatureHex, bool expectVerifyResult)
{
    HcfResult res = HCF_SUCCESS;
    HcfAsyKeyGenerator *generator = nullptr;
    res = HcfAsyKeyGeneratorCreate("RSA1024", &generator);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(generator, nullptr);

    HcfBlob pubKeyBlob = { .data = nullptr, .len = 0 };
    res = HexStringToBlob(pubKeyDerHex, &pubKeyBlob);
    EXPECT_EQ(res, HCF_SUCCESS);

    HcfKeyPair *keyPair = nullptr;
    res = generator->convertKey(generator, nullptr, &pubKeyBlob, nullptr, &keyPair);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(keyPair, nullptr);

    HcfBlob digest = { .data = nullptr, .len = 0 };
    res = HexStringToBlob(digestHex, &digest);
    EXPECT_EQ(res, HCF_SUCCESS);

    HcfBlob signature = { .data = nullptr, .len = 0 };
    res = HexStringToBlob(signatureHex, &signature);
    EXPECT_EQ(res, HCF_SUCCESS);

    HcfVerify *verify = nullptr;
    res = HcfVerifyCreate(verifyAlgoName, &verify);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(verify, nullptr);

    res = verify->init(verify, nullptr, keyPair->pubKey);
    EXPECT_EQ(res, HCF_SUCCESS);
    if (res == HCF_SUCCESS) {
        bool result = verify->verify(verify, &digest, &signature);
        EXPECT_EQ(result, expectVerifyResult);
    }

    HcfObjDestroy(verify);
    HcfFree(signature.data);
    HcfFree(digest.data);
    HcfObjDestroy(keyPair);
    HcfFree(pubKeyBlob.data);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoRSAOnlySignVerifyTest, CryptoRSAOnlySignVerifyVectorTest001, TestSize.Level0)
{
    const char *pubKeyDerHex =
        "30819E300D06092A864886F70D010101050003818C003081880281805425A8919C0F1BAC"
        "C4C32F5D30383AEE38B0524C4BFA17F6411CF7E7F3E6E05AFE7DBD5401F7A2AC5A784062"
        "379E41AE76EBD926EC48BE662CD7AB66E50D9DA96C44A4B842E9C8EA77C82F97363B5A24"
        "C24F5A06C89AB43403B1C32B971BB009BEEF922DF0CC857A20D1C3E36B41FB0FE46CB076"
        "D97225EE775B6B216397EEF70203010001";
    const char *digestHex =
        "FD98A63CCDB75CBF061E8D4362529C911929D0CE133220E95506ADF554DDDB88";
    const char *signatureHex =
        "5005B9CD4EA24D45B0A7E7A12BDD13DC6F7A8EF2722CFEE55B62259137443AE80E453BCE"
        "36E46FEE5BB5F581B7946B1ED2EAA47D5D64D8490635BB0ECD4FC8A9B4814C847B92FC4A"
        "88C54ADB74669854B629621B9E9F2BA767B4575AEA7296E410F9222D574B6DB59BFE621D"
        "BCAA160567FC5F97DD32872295CA049AACBE0745";

    ASSERT_NO_FATAL_FAILURE(RsaOnlyVerifyVectorPkcs1Sha256Test(pubKeyDerHex, digestHex, signatureHex, true));
}

HWTEST_F(CryptoRSAOnlySignVerifyTest, CryptoRSAOnlySignVerifyVectorTest002, TestSize.Level0)
{
    const char *pubKeyDerHex =
        "30819E300D06092A864886F70D010101050003818C003081880281805425A8919C0F1BAC"
        "C4C32F5D30383AEE38B0524C4BFA17F6411CF7E7F3E6E05AFE7DBD5401F7A2AC5A784062"
        "379E41AE76EBD926EC48BE662CD7AB66E50D9DA96C44A4B842E9C8EA77C82F97363B5A24"
        "C24F5A06C89AB43403B1C32B971BB009BEEF922DF0CC857A20D1C3E36B41FB0FE46CB076"
        "D97225EE775B6B216397EEF70203010001";
    const char *digestHex =
        "FD98A63CCDB75CBF061E8D4362529C911929D0CE133220E95506ADF554DDDB88";
    const char *tamperedSignatureHex =
        "5005B9CD4EA24D45B0A7E7A12BDD13DC6F7A8EF2722CFEE55B62259137443AE80E453BCE"
        "36E46FEE5BB5F581B7946B1ED2EAA47D5D64D8490635BB0ECD4FC8A9B4814C847B92FC4A"
        "88C54ADB74669854B629621B9E9F2BA767B4575AEA7296E410F9222D574B6DB59BFE621D"
        "BCAA160567FC5F97DD32872295CA049AACBE0744";

    ASSERT_NO_FATAL_FAILURE(RsaOnlyVerifyVectorPkcs1Sha256Test(pubKeyDerHex, digestHex, tamperedSignatureHex,
        false));
}

HWTEST_F(CryptoRSAOnlySignVerifyTest, CryptoRSAOnlySignVerifyVectorTest003, TestSize.Level0)
{
    const char *pubKeyDerHex =
        "30819E300D06092A864886F70D010101050003818C003081880281805425A8919C0F1BAC"
        "C4C32F5D30383AEE38B0524C4BFA17F6411CF7E7F3E6E05AFE7DBD5401F7A2AC5A784062"
        "379E41AE76EBD926EC48BE662CD7AB66E50D9DA96C44A4B842E9C8EA77C82F97363B5A24"
        "C24F5A06C89AB43403B1C32B971BB009BEEF922DF0CC857A20D1C3E36B41FB0FE46CB076"
        "D97225EE775B6B216397EEF70203010001";
    const char *digestHex =
        "A11AF9E4B6BA056F9B620EDF9C137DBD788F75B3B437C3255AD9B7BCB16527F8";
    const char *signatureHex =
        "1B5AD5F6B61A77F7B9EE59F19FA6D34D60D5BCC68EAA4B867B3AABA638DBE31384A4"
        "8097F71AC75EB8B00AEB147E626C77A6B2B49D742A36C783F21A8C9A34C9DFB00DB0C4"
        "E65C805F13921337C9726381F7B9C3FFA23C2C6C6FF2FC108FCBF0F1F6F31F42D05359"
        "A558E8202FE2B9C6F77546BE039E7B05909981B7F9791B67";

    ASSERT_NO_FATAL_FAILURE(RsaOnlyVerifyVectorTest("RSA1024|PSS|SHA256|MGF1_SHA256|OnlyVerify",
        pubKeyDerHex, digestHex, signatureHex, true));
}

HWTEST_F(CryptoRSAOnlySignVerifyTest, CryptoRSAOnlySignVerifyVectorTest004, TestSize.Level0)
{
    const char *pubKeyDerHex =
        "30819E300D06092A864886F70D010101050003818C003081880281805425A8919C0F1BAC"
        "C4C32F5D30383AEE38B0524C4BFA17F6411CF7E7F3E6E05AFE7DBD5401F7A2AC5A784062"
        "379E41AE76EBD926EC48BE662CD7AB66E50D9DA96C44A4B842E9C8EA77C82F97363B5A24"
        "C24F5A06C89AB43403B1C32B971BB009BEEF922DF0CC857A20D1C3E36B41FB0FE46CB076"
        "D97225EE775B6B216397EEF70203010001";
    const char *digestHex =
        "A11AF9E4B6BA056F9B620EDF9C137DBD788F75B3B437C3255AD9B7BCB16527F8";
    const char *tamperedSignatureHex =
        "1B5AD5F6B61A77F7B9EE59F19FA6D34D60D5BCC68EAA4B867B3AABA638DBE31384A4"
        "8097F71AC75EB8B00AEB147E626C77A6B2B49D742A36C783F21A8C9A34C9DFB00DB0C4"
        "E65C805F13921337C9726381F7B9C3FFA23C2C6C6FF2FC108FCBF0F1F6F31F42D05359"
        "A558E8202FE2B9C6F77546BE039E7B05909981B7F9791B66";

    ASSERT_NO_FATAL_FAILURE(RsaOnlyVerifyVectorTest("RSA1024|PSS|SHA256|MGF1_SHA256|OnlyVerify",
        pubKeyDerHex, digestHex, tamperedSignatureHex, false));
}
}
