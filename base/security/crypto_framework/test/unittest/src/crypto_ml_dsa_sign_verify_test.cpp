/*
 * Copyright (C) 2026 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * *    http://www.apache.org/licenses/LICENSE-2.0
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
#include "memory.h"
#include "signature.h"
#include "params_parser.h"
#include "ml_dsa_openssl.h"
#include "ml_dsa_asy_key_generator_openssl.h"
#include "crypto_operation_err.h"
#include "object_base.h"

using namespace std;
using namespace testing::ext;

namespace {
class CryptoMlDsaSignVerifyTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp();
    void TearDown();

    static HcfKeyPair *mlDsa65KeyPair_;
    static HcfKeyPair *mlKem768KeyPair_;
};

HcfKeyPair *CryptoMlDsaSignVerifyTest::mlDsa65KeyPair_ = nullptr;
HcfKeyPair *CryptoMlDsaSignVerifyTest::mlKem768KeyPair_ = nullptr;

static const char *GetMockClass()
{
    return "WRONG_CLASS";
}

static HcfObjectBase g_obj = {
    .getClass = GetMockClass,
    .destroy = nullptr,
};

static string g_mlDsa65AlgoName = "ML-DSA-65";

#define ML_DSA_44_SIGN_LEN 2420
#define ML_DSA_65_SIGN_LEN 3309
#define ML_DSA_87_SIGN_LEN 4627

static const char *MOCK_MESSAGE = "hello world";
static HcfBlob g_mockInput = {
    .data = (uint8_t *)MOCK_MESSAGE,
    .len = 12
};

static const char *MOCK64_MESSAGE =
    "0123456789012345678901234567890123456789012345678901234567890123";
static HcfBlob g_mock64Input = {
    .data = (uint8_t *)MOCK64_MESSAGE,
    .len = 64
};

void CryptoMlDsaSignVerifyTest::SetUp() {}
void CryptoMlDsaSignVerifyTest::TearDown() {}

void CryptoMlDsaSignVerifyTest::SetUpTestCase()
{
    HcfAsyKeyGenerator *generator = nullptr;
    HcfResult ret = HcfAsyKeyGeneratorCreate(g_mlDsa65AlgoName.c_str(), &generator);
    ASSERT_EQ(ret, HCF_SUCCESS);
    ASSERT_NE(generator, nullptr);

    HcfKeyPair *keyPair = nullptr;
    ret = generator->generateKeyPair(generator, nullptr, &keyPair);
    ASSERT_EQ(ret, HCF_SUCCESS);
    ASSERT_NE(keyPair, nullptr);
    mlDsa65KeyPair_ = keyPair;
    HcfObjDestroy(generator);

    HcfAsyKeyGenerator *kemGen = nullptr;
    ret = HcfAsyKeyGeneratorCreate("ML-KEM-768", &kemGen);
    ASSERT_EQ(ret, HCF_SUCCESS);
    ASSERT_NE(kemGen, nullptr);

    HcfKeyPair *kemKeyPair = nullptr;
    ret = kemGen->generateKeyPair(kemGen, nullptr, &kemKeyPair);
    ASSERT_EQ(ret, HCF_SUCCESS);
    ASSERT_NE(kemKeyPair, nullptr);
    mlKem768KeyPair_ = kemKeyPair;
    HcfObjDestroy(kemGen);
}

void CryptoMlDsaSignVerifyTest::TearDownTestCase()
{
    HcfObjDestroy(mlDsa65KeyPair_);
    HcfObjDestroy(mlKem768KeyPair_);
}

HWTEST_F(CryptoMlDsaSignVerifyTest, CryptoMlDsaSignCreateTest001, TestSize.Level0)
{
    HcfSign *sign = nullptr;
    HcfResult ret = HcfSignCreate("ML-DSA", &sign);
    ASSERT_EQ(ret, HCF_SUCCESS);
    ASSERT_NE(sign, nullptr);
    HcfObjDestroy(sign);
}

HWTEST_F(CryptoMlDsaSignVerifyTest, CryptoMlDsaSignCreateVariantFailTest001, TestSize.Level0)
{
    HcfSign *sign = nullptr;
    HcfResult ret = HcfSignCreate("ML-DSA-44", &sign);
    ASSERT_NE(ret, HCF_SUCCESS);
    ASSERT_EQ(sign, nullptr);
}

HWTEST_F(CryptoMlDsaSignVerifyTest, CryptoMlDsaSignCreateVariantFailTest002, TestSize.Level0)
{
    HcfSign *sign = nullptr;
    HcfResult ret = HcfSignCreate("ML-DSA-87", &sign);
    ASSERT_NE(ret, HCF_SUCCESS);
    ASSERT_EQ(sign, nullptr);
}

HWTEST_F(CryptoMlDsaSignVerifyTest, CryptoMlDsaVerifyCreateVariantFailTest001, TestSize.Level0)
{
    HcfVerify *verify = nullptr;
    HcfResult ret = HcfVerifyCreate("ML-DSA-65", &verify);
    ASSERT_NE(ret, HCF_SUCCESS);
    ASSERT_EQ(verify, nullptr);
}

HWTEST_F(CryptoMlDsaSignVerifyTest, CryptoMlDsaSignGetAlgoNameTest001, TestSize.Level0)
{
    HcfSign *sign = nullptr;
    HcfResult ret = HcfSignCreate("ML-DSA", &sign);
    ASSERT_EQ(ret, HCF_SUCCESS);
    ASSERT_NE(sign, nullptr);

    const char *algName = sign->getAlgoName(sign);
    ASSERT_NE(algName, nullptr);
    ASSERT_STREQ(algName, "ML-DSA");

    HcfObjDestroy(sign);
}

HWTEST_F(CryptoMlDsaSignVerifyTest, CryptoMlDsaSignInitTest001, TestSize.Level0)
{
    HcfSign *sign = nullptr;
    HcfResult ret = HcfSignCreate("ML-DSA", &sign);
    ASSERT_EQ(ret, HCF_SUCCESS);
    ASSERT_NE(sign, nullptr);

    ret = sign->init(sign, nullptr, mlDsa65KeyPair_->priKey);
    ASSERT_EQ(ret, HCF_SUCCESS);

    HcfObjDestroy(sign);
}

HWTEST_F(CryptoMlDsaSignVerifyTest, CryptoMlDsaSignInitRepeatTest001, TestSize.Level0)
{
    HcfSign *sign = nullptr;
    HcfResult ret = HcfSignCreate("ML-DSA", &sign);
    ASSERT_EQ(ret, HCF_SUCCESS);
    ASSERT_NE(sign, nullptr);

    ret = sign->init(sign, nullptr, mlDsa65KeyPair_->priKey);
    ASSERT_EQ(ret, HCF_SUCCESS);

    ret = sign->init(sign, nullptr, mlDsa65KeyPair_->priKey);
    ASSERT_NE(ret, HCF_SUCCESS);

    HcfObjDestroy(sign);
}

HWTEST_F(CryptoMlDsaSignVerifyTest, CryptoMlDsaSignTest001, TestSize.Level0)
{
    HcfSign *sign = nullptr;
    HcfResult ret = HcfSignCreate("ML-DSA", &sign);
    ASSERT_EQ(ret, HCF_SUCCESS);
    ASSERT_NE(sign, nullptr);

    ret = sign->init(sign, nullptr, mlDsa65KeyPair_->priKey);
    ASSERT_EQ(ret, HCF_SUCCESS);

    HcfBlob out = { .data = nullptr, .len = 0 };
    ret = sign->sign(sign, &g_mockInput, &out);
    ASSERT_EQ(ret, HCF_SUCCESS);
    ASSERT_NE(out.data, nullptr);
    ASSERT_GT(out.len, (uint32_t)0);

    HcfFree(out.data);
    HcfObjDestroy(sign);
}

HWTEST_F(CryptoMlDsaSignVerifyTest, CryptoMlDsaSignVerifyTest001, TestSize.Level0)
{
    HcfSign *sign = nullptr;
    HcfResult ret = HcfSignCreate("ML-DSA", &sign);
    ASSERT_EQ(ret, HCF_SUCCESS);
    ASSERT_NE(sign, nullptr);

    ret = sign->init(sign, nullptr, mlDsa65KeyPair_->priKey);
    ASSERT_EQ(ret, HCF_SUCCESS);

    HcfBlob out = { .data = nullptr, .len = 0 };
    ret = sign->sign(sign, &g_mockInput, &out);
    ASSERT_EQ(ret, HCF_SUCCESS);
    ASSERT_NE(out.data, nullptr);
    ASSERT_GT(out.len, (uint32_t)0);

    HcfVerify *verify = nullptr;
    ret = HcfVerifyCreate("ML-DSA", &verify);
    ASSERT_EQ(ret, HCF_SUCCESS);
    ASSERT_NE(verify, nullptr);

    ret = verify->init(verify, nullptr, mlDsa65KeyPair_->pubKey);
    ASSERT_EQ(ret, HCF_SUCCESS);

    bool flag = verify->verify(verify, &g_mockInput, &out);
    ASSERT_EQ(flag, true);

    HcfFree(out.data);
    HcfObjDestroy(sign);
    HcfObjDestroy(verify);
}

HWTEST_F(CryptoMlDsaSignVerifyTest, CryptoMlDsaSignVerifyWrongDataTest001, TestSize.Level0)
{
    HcfSign *sign = nullptr;
    HcfResult ret = HcfSignCreate("ML-DSA", &sign);
    ASSERT_EQ(ret, HCF_SUCCESS);
    ASSERT_NE(sign, nullptr);

    ret = sign->init(sign, nullptr, mlDsa65KeyPair_->priKey);
    ASSERT_EQ(ret, HCF_SUCCESS);

    HcfBlob out = { .data = nullptr, .len = 0 };
    ret = sign->sign(sign, &g_mockInput, &out);
    ASSERT_EQ(ret, HCF_SUCCESS);

    HcfVerify *verify = nullptr;
    ret = HcfVerifyCreate("ML-DSA", &verify);
    ASSERT_EQ(ret, HCF_SUCCESS);
    ASSERT_NE(verify, nullptr);

    ret = verify->init(verify, nullptr, mlDsa65KeyPair_->pubKey);
    ASSERT_EQ(ret, HCF_SUCCESS);

    const char *wrongMsg = "wrong data";
    HcfBlob wrongInput = { .data = (uint8_t *)wrongMsg, .len = 10 };
    bool flag = verify->verify(verify, &wrongInput, &out);
    ASSERT_EQ(flag, false);

    HcfFree(out.data);
    HcfObjDestroy(sign);
    HcfObjDestroy(verify);
}

HWTEST_F(CryptoMlDsaSignVerifyTest, CryptoMlDsaSignUpdateNotSupportTest001, TestSize.Level0)
{
    HcfSign *sign = nullptr;
    HcfResult ret = HcfSignCreate("ML-DSA", &sign);
    ASSERT_EQ(ret, HCF_SUCCESS);
    ASSERT_NE(sign, nullptr);

    ret = sign->init(sign, nullptr, mlDsa65KeyPair_->priKey);
    ASSERT_EQ(ret, HCF_SUCCESS);

    ret = sign->update(sign, &g_mockInput);
    ASSERT_EQ(ret, HCF_ERR_INVALID_CALL);

    HcfObjDestroy(sign);
}

HWTEST_F(CryptoMlDsaSignVerifyTest, CryptoMlDsaVerifyUpdateNotSupportTest001, TestSize.Level0)
{
    HcfVerify *verify = nullptr;
    HcfResult ret = HcfVerifyCreate("ML-DSA", &verify);
    ASSERT_EQ(ret, HCF_SUCCESS);
    ASSERT_NE(verify, nullptr);

    ret = verify->init(verify, nullptr, mlDsa65KeyPair_->pubKey);
    ASSERT_EQ(ret, HCF_SUCCESS);

    ret = verify->update(verify, &g_mockInput);
    ASSERT_EQ(ret, HCF_ERR_INVALID_CALL);

    HcfObjDestroy(verify);
}

HWTEST_F(CryptoMlDsaSignVerifyTest, CryptoMlDsaRecoverNotSupportTest001, TestSize.Level0)
{
    HcfVerify *verify = nullptr;
    HcfResult ret = HcfVerifyCreate("ML-DSA", &verify);
    ASSERT_EQ(ret, HCF_SUCCESS);
    ASSERT_NE(verify, nullptr);

    HcfBlob sig = { .data = (uint8_t *)"sig", .len = 3 };
    HcfBlob out = { .data = nullptr, .len = 0 };
    ret = verify->recover(verify, &sig, &out);
    ASSERT_EQ(ret, HCF_ERR_INVALID_CALL);

    HcfObjDestroy(verify);
}

HWTEST_F(CryptoMlDsaSignVerifyTest, CryptoMlDsaSetSignSpecBoolDeterministicTest001, TestSize.Level0)
{
    HcfSign *sign = nullptr;
    HcfResult ret = HcfSignCreate("ML-DSA", &sign);
    ASSERT_EQ(ret, HCF_SUCCESS);
    ASSERT_NE(sign, nullptr);

    ret = sign->setSignSpecBool(sign, ML_DSA_DETERMINISTIC_BOOL, true);
    ASSERT_EQ(ret, HCF_SUCCESS);

    ret = sign->init(sign, nullptr, mlDsa65KeyPair_->priKey);
    ASSERT_EQ(ret, HCF_SUCCESS);

    HcfBlob out = { .data = nullptr, .len = 0 };
    ret = sign->sign(sign, &g_mockInput, &out);
    ASSERT_EQ(ret, HCF_SUCCESS);
    ASSERT_NE(out.data, nullptr);

    HcfFree(out.data);
    HcfObjDestroy(sign);
}

HWTEST_F(CryptoMlDsaSignVerifyTest, CryptoMlDsaSetSignSpecBoolMuTest001, TestSize.Level0)
{
    HcfSign *sign = nullptr;
    HcfResult ret = HcfSignCreate("ML-DSA", &sign);
    ASSERT_EQ(ret, HCF_SUCCESS);
    ASSERT_NE(sign, nullptr);

    ret = sign->setSignSpecBool(sign, ML_DSA_MU_BOOL, true);
    ASSERT_EQ(ret, HCF_SUCCESS);

    ret = sign->init(sign, nullptr, mlDsa65KeyPair_->priKey);
    ASSERT_EQ(ret, HCF_SUCCESS);

    HcfBlob out = { .data = nullptr, .len = 0 };
    ret = sign->sign(sign, &g_mockInput, &out);
    ASSERT_EQ(ret, HCF_ERR_CRYPTO_OPERATION);

    HcfObjDestroy(sign);
}

HWTEST_F(CryptoMlDsaSignVerifyTest, CryptoMlDsaSetSignSpecContextTest001, TestSize.Level0)
{
    HcfSign *sign = nullptr;
    HcfResult ret = HcfSignCreate("ML-DSA", &sign);
    ASSERT_EQ(ret, HCF_SUCCESS);
    ASSERT_NE(sign, nullptr);

    uint8_t contextData[] = { 0x01, 0x02, 0x03, 0x04 };
    HcfBlob contextBlob = { .data = contextData, .len = sizeof(contextData) };
    ret = sign->setSignSpecUint8Array(sign, ML_DSA_CONTEXT_UINT8ARR, contextBlob);
    ASSERT_EQ(ret, HCF_SUCCESS);

    ret = sign->init(sign, nullptr, mlDsa65KeyPair_->priKey);
    ASSERT_EQ(ret, HCF_SUCCESS);

    HcfBlob out = { .data = nullptr, .len = 0 };
    ret = sign->sign(sign, &g_mockInput, &out);
    ASSERT_EQ(ret, HCF_SUCCESS);
    ASSERT_NE(out.data, nullptr);

    HcfFree(out.data);
    HcfObjDestroy(sign);
}

HWTEST_F(CryptoMlDsaSignVerifyTest, CryptoMlDsaSetVerifySpecBoolMuTest001, TestSize.Level0)
{
    HcfVerify *verify = nullptr;
    HcfResult ret = HcfVerifyCreate("ML-DSA", &verify);
    ASSERT_EQ(ret, HCF_SUCCESS);
    ASSERT_NE(verify, nullptr);

    ret = verify->setVerifySpecBool(verify, ML_DSA_MU_BOOL, true);
    ASSERT_EQ(ret, HCF_SUCCESS);

    ret = verify->init(verify, nullptr, mlDsa65KeyPair_->pubKey);
    ASSERT_EQ(ret, HCF_SUCCESS);

    HcfObjDestroy(verify);
}

HWTEST_F(CryptoMlDsaSignVerifyTest, CryptoMlDsaSetVerifySpecContextTest001, TestSize.Level0)
{
    HcfVerify *verify = nullptr;
    HcfResult ret = HcfVerifyCreate("ML-DSA", &verify);
    ASSERT_EQ(ret, HCF_SUCCESS);
    ASSERT_NE(verify, nullptr);

    uint8_t contextData[] = { 0x01, 0x02, 0x03, 0x04 };
    HcfBlob contextBlob = { .data = contextData, .len = sizeof(contextData) };
    ret = verify->setVerifySpecUint8Array(verify, ML_DSA_CONTEXT_UINT8ARR, contextBlob);
    ASSERT_EQ(ret, HCF_SUCCESS);

    ret = verify->init(verify, nullptr, mlDsa65KeyPair_->pubKey);
    ASSERT_EQ(ret, HCF_SUCCESS);

    HcfObjDestroy(verify);
}

HWTEST_F(CryptoMlDsaSignVerifyTest, CryptoMlDsaSignVerifyWithMuTest001, TestSize.Level0)
{
    HcfSign *sign = nullptr;
    HcfResult ret = HcfSignCreate("ML-DSA", &sign);
    ASSERT_EQ(ret, HCF_SUCCESS);
    ASSERT_NE(sign, nullptr);

    ret = sign->setSignSpecBool(sign, ML_DSA_MU_BOOL, true);
    ASSERT_EQ(ret, HCF_SUCCESS);

    ret = sign->init(sign, nullptr, mlDsa65KeyPair_->priKey);
    ASSERT_EQ(ret, HCF_SUCCESS);

    HcfBlob out = { .data = nullptr, .len = 0 };
    ret = sign->sign(sign, &g_mockInput, &out);
    ASSERT_EQ(ret, HCF_ERR_CRYPTO_OPERATION);

    HcfObjDestroy(sign);
}

HWTEST_F(CryptoMlDsaSignVerifyTest, CryptoMlDsaSetSignSpecBoolAfterInitTest001, TestSize.Level0)
{
    HcfSign *sign = nullptr;
    HcfResult ret = HcfSignCreate("ML-DSA", &sign);
    ASSERT_EQ(ret, HCF_SUCCESS);
    ASSERT_NE(sign, nullptr);

    ret = sign->init(sign, nullptr, mlDsa65KeyPair_->priKey);
    ASSERT_EQ(ret, HCF_SUCCESS);

    ret = sign->setSignSpecBool(sign, ML_DSA_DETERMINISTIC_BOOL, true);
    ASSERT_EQ(ret, HCF_ERR_INVALID_CALL);

    HcfObjDestroy(sign);
}

HWTEST_F(CryptoMlDsaSignVerifyTest, CryptoMlDsaSpiCreateTest001, TestSize.Level0)
{
    HcfSignSpi *sign = nullptr;
    HcfSignatureParams params = { .algo = HCF_ALG_ML_DSA };
    HcfResult ret = HcfSignSpiMlDsaCreate(&params, &sign);
    ASSERT_EQ(ret, HCF_SUCCESS);
    ASSERT_NE(sign, nullptr);
    HcfObjDestroy(sign);
}

HWTEST_F(CryptoMlDsaSignVerifyTest, CryptoMlDsaSpiCreateNullTest001, TestSize.Level0)
{
    // params is unused in ML-DSA SPI create, NULL is allowed
    HcfSignSpi *sign = nullptr;
    HcfResult ret = HcfSignSpiMlDsaCreate(nullptr, &sign);
    ASSERT_EQ(ret, HCF_SUCCESS);
    HcfObjDestroy(sign);

    HcfSignatureParams params = { .algo = HCF_ALG_ML_DSA };
    ret = HcfSignSpiMlDsaCreate(&params, nullptr);
    ASSERT_NE(ret, HCF_SUCCESS);
}

HWTEST_F(CryptoMlDsaSignVerifyTest, CryptoMlDsaVerifySpiCreateTest001, TestSize.Level0)
{
    HcfVerifySpi *verify = nullptr;
    HcfSignatureParams params = { .algo = HCF_ALG_ML_DSA };
    HcfResult ret = HcfVerifySpiMlDsaCreate(&params, &verify);
    ASSERT_EQ(ret, HCF_SUCCESS);
    ASSERT_NE(verify, nullptr);
    HcfObjDestroy(verify);
}

HWTEST_F(CryptoMlDsaSignVerifyTest, CryptoMlDsa44SignVerifyTest001, TestSize.Level0)
{
    HcfAsyKeyGenerator *gen = nullptr;
    HcfResult res = HcfAsyKeyGeneratorCreate("ML-DSA-44", &gen);
    ASSERT_EQ(res, HCF_SUCCESS);

    HcfKeyPair *keyPair = nullptr;
    res = gen->generateKeyPair(gen, nullptr, &keyPair);
    ASSERT_EQ(res, HCF_SUCCESS);
    HcfObjDestroy(gen);

    HcfSign *sign = nullptr;
    res = HcfSignCreate("ML-DSA", &sign);
    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(sign, nullptr);

    res = sign->init(sign, nullptr, keyPair->priKey);
    ASSERT_EQ(res, HCF_SUCCESS);

    HcfBlob out = { .data = nullptr, .len = 0 };
    res = sign->sign(sign, &g_mockInput, &out);
    ASSERT_EQ(res, HCF_SUCCESS);

    HcfVerify *verify = nullptr;
    res = HcfVerifyCreate("ML-DSA", &verify);
    ASSERT_EQ(res, HCF_SUCCESS);

    res = verify->init(verify, nullptr, keyPair->pubKey);
    ASSERT_EQ(res, HCF_SUCCESS);

    bool flag = verify->verify(verify, &g_mockInput, &out);
    ASSERT_EQ(flag, true);
    ASSERT_EQ(out.len, ML_DSA_44_SIGN_LEN);

    HcfFree(out.data);
    HcfObjDestroy(sign);
    HcfObjDestroy(verify);
    HcfObjDestroy(keyPair);
}

HWTEST_F(CryptoMlDsaSignVerifyTest, CryptoMlDsa87SignVerifyTest001, TestSize.Level0)
{
    HcfAsyKeyGenerator *gen = nullptr;
    HcfResult res = HcfAsyKeyGeneratorCreate("ML-DSA-87", &gen);
    ASSERT_EQ(res, HCF_SUCCESS);

    HcfKeyPair *keyPair = nullptr;
    res = gen->generateKeyPair(gen, nullptr, &keyPair);
    ASSERT_EQ(res, HCF_SUCCESS);
    HcfObjDestroy(gen);

    HcfSign *sign = nullptr;
    res = HcfSignCreate("ML-DSA", &sign);
    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(sign, nullptr);

    res = sign->init(sign, nullptr, keyPair->priKey);
    ASSERT_EQ(res, HCF_SUCCESS);

    HcfBlob out = { .data = nullptr, .len = 0 };
    res = sign->sign(sign, &g_mockInput, &out);
    ASSERT_EQ(res, HCF_SUCCESS);

    HcfVerify *verify = nullptr;
    res = HcfVerifyCreate("ML-DSA", &verify);
    ASSERT_EQ(res, HCF_SUCCESS);

    res = verify->init(verify, nullptr, keyPair->pubKey);
    ASSERT_EQ(res, HCF_SUCCESS);

    bool flag = verify->verify(verify, &g_mockInput, &out);
    ASSERT_EQ(flag, true);
    ASSERT_EQ(out.len, ML_DSA_87_SIGN_LEN);

    HcfFree(out.data);
    HcfObjDestroy(sign);
    HcfObjDestroy(verify);
    HcfObjDestroy(keyPair);
}

HWTEST_F(CryptoMlDsaSignVerifyTest, CryptoMlDsaSignDestroyNullptrTest001, TestSize.Level0)
{
    HcfSign *sign = nullptr;
    HcfResult ret = HcfSignCreate("ML-DSA", &sign);
    ASSERT_EQ(ret, HCF_SUCCESS);
    ASSERT_NE(sign, nullptr);

    sign->base.destroy(nullptr);
    HcfObjDestroy(sign);
}

HWTEST_F(CryptoMlDsaSignVerifyTest, CryptoMlDsaSignDestroyWrongClassTest001, TestSize.Level0)
{
    HcfSign *sign = nullptr;
    HcfResult ret = HcfSignCreate("ML-DSA", &sign);
    ASSERT_EQ(ret, HCF_SUCCESS);
    ASSERT_NE(sign, nullptr);

    sign->base.destroy(&g_obj);
    HcfObjDestroy(sign);
}

HWTEST_F(CryptoMlDsaSignVerifyTest, CryptoMlDsaVerifyDestroyNullptrTest001, TestSize.Level0)
{
    HcfVerify *verify = nullptr;
    HcfResult ret = HcfVerifyCreate("ML-DSA", &verify);
    ASSERT_EQ(ret, HCF_SUCCESS);
    ASSERT_NE(verify, nullptr);

    verify->base.destroy(nullptr);
    HcfObjDestroy(verify);
}

HWTEST_F(CryptoMlDsaSignVerifyTest, CryptoMlDsaVerifyDestroyWrongClassTest001, TestSize.Level0)
{
    HcfVerify *verify = nullptr;
    HcfResult ret = HcfVerifyCreate("ML-DSA", &verify);
    ASSERT_EQ(ret, HCF_SUCCESS);
    ASSERT_NE(verify, nullptr);

    verify->base.destroy(&g_obj);
    HcfObjDestroy(verify);
}

HWTEST_F(CryptoMlDsaSignVerifyTest, CryptoMlDsaSignGetAlgoNameNullptrTest001, TestSize.Level0)
{
    HcfSign *sign = nullptr;
    HcfResult ret = HcfSignCreate("ML-DSA", &sign);
    ASSERT_EQ(ret, HCF_SUCCESS);
    ASSERT_NE(sign, nullptr);

    const char *algName = sign->getAlgoName(nullptr);
    ASSERT_EQ(algName, nullptr);

    algName = sign->getAlgoName((HcfSign *)&g_obj);
    ASSERT_EQ(algName, nullptr);

    HcfObjDestroy(sign);
}

HWTEST_F(CryptoMlDsaSignVerifyTest, CryptoMlDsaVerifyGetAlgoNameTest001, TestSize.Level0)
{
    HcfVerify *verify = nullptr;
    HcfResult ret = HcfVerifyCreate("ML-DSA", &verify);
    ASSERT_EQ(ret, HCF_SUCCESS);
    ASSERT_NE(verify, nullptr);

    const char *algName = verify->getAlgoName(verify);
    ASSERT_NE(algName, nullptr);
    ASSERT_STREQ(algName, "ML-DSA");

    HcfObjDestroy(verify);
}

HWTEST_F(CryptoMlDsaSignVerifyTest, CryptoMlDsaVerifyGetAlgoNameNullptrTest001, TestSize.Level0)
{
    HcfVerify *verify = nullptr;
    HcfResult ret = HcfVerifyCreate("ML-DSA", &verify);
    ASSERT_EQ(ret, HCF_SUCCESS);
    ASSERT_NE(verify, nullptr);

    const char *algName = verify->getAlgoName(nullptr);
    ASSERT_EQ(algName, nullptr);

    algName = verify->getAlgoName((HcfVerify *)&g_obj);
    ASSERT_EQ(algName, nullptr);

    HcfObjDestroy(verify);
}

HWTEST_F(CryptoMlDsaSignVerifyTest, CryptoMlDsaSignInitNullptrTest001, TestSize.Level0)
{
    HcfSign *sign = nullptr;
    HcfResult ret = HcfSignCreate("ML-DSA", &sign);
    ASSERT_EQ(ret, HCF_SUCCESS);
    ASSERT_NE(sign, nullptr);

    ret = sign->init(nullptr, nullptr, mlDsa65KeyPair_->priKey);
    ASSERT_NE(ret, HCF_SUCCESS);

    HcfObjDestroy(sign);
}

HWTEST_F(CryptoMlDsaSignVerifyTest, CryptoMlDsaSignInitWrongClassTest001, TestSize.Level0)
{
    HcfSign *sign = nullptr;
    HcfResult ret = HcfSignCreate("ML-DSA", &sign);
    ASSERT_EQ(ret, HCF_SUCCESS);
    ASSERT_NE(sign, nullptr);

    ret = sign->init((HcfSign *)&g_obj, nullptr, mlDsa65KeyPair_->priKey);
    ASSERT_NE(ret, HCF_SUCCESS);

    HcfObjDestroy(sign);
}

HWTEST_F(CryptoMlDsaSignVerifyTest, CryptoMlDsaSignInitCrossAlgoKeyTest001, TestSize.Level0)
{
    HcfSign *sign = nullptr;
    HcfResult ret = HcfSignCreate("ML-DSA", &sign);
    ASSERT_EQ(ret, HCF_SUCCESS);
    ASSERT_NE(sign, nullptr);

    ret = sign->init(sign, nullptr, mlKem768KeyPair_->priKey);
    ASSERT_NE(ret, HCF_SUCCESS);

    char buff[256] = { 0 };
    (void)HcfGetOperationErrorMessage(buff, sizeof(buff));

    HcfObjDestroy(sign);
}

HWTEST_F(CryptoMlDsaSignVerifyTest, CryptoMlDsaVerifyInitNullptrTest001, TestSize.Level0)
{
    HcfVerify *verify = nullptr;
    HcfResult ret = HcfVerifyCreate("ML-DSA", &verify);
    ASSERT_EQ(ret, HCF_SUCCESS);
    ASSERT_NE(verify, nullptr);

    ret = verify->init(nullptr, nullptr, mlDsa65KeyPair_->pubKey);
    ASSERT_NE(ret, HCF_SUCCESS);

    HcfObjDestroy(verify);
}

HWTEST_F(CryptoMlDsaSignVerifyTest, CryptoMlDsaVerifyInitWrongClassTest001, TestSize.Level0)
{
    HcfVerify *verify = nullptr;
    HcfResult ret = HcfVerifyCreate("ML-DSA", &verify);
    ASSERT_EQ(ret, HCF_SUCCESS);
    ASSERT_NE(verify, nullptr);

    ret = verify->init((HcfVerify *)&g_obj, nullptr, mlDsa65KeyPair_->pubKey);
    ASSERT_NE(ret, HCF_SUCCESS);

    HcfObjDestroy(verify);
}

HWTEST_F(CryptoMlDsaSignVerifyTest, CryptoMlDsaVerifyInitCrossAlgoKeyTest001, TestSize.Level0)
{
    HcfVerify *verify = nullptr;
    HcfResult ret = HcfVerifyCreate("ML-DSA", &verify);
    ASSERT_EQ(ret, HCF_SUCCESS);
    ASSERT_NE(verify, nullptr);

    ret = verify->init(verify, nullptr, mlKem768KeyPair_->pubKey);
    ASSERT_NE(ret, HCF_SUCCESS);

    HcfObjDestroy(verify);
}

HWTEST_F(CryptoMlDsaSignVerifyTest, CryptoMlDsaVerifyInitRepeatTest001, TestSize.Level0)
{
    HcfVerify *verify = nullptr;
    HcfResult ret = HcfVerifyCreate("ML-DSA", &verify);
    ASSERT_EQ(ret, HCF_SUCCESS);
    ASSERT_NE(verify, nullptr);

    ret = verify->init(verify, nullptr, mlDsa65KeyPair_->pubKey);
    ASSERT_EQ(ret, HCF_SUCCESS);

    ret = verify->init(verify, nullptr, mlDsa65KeyPair_->pubKey);
    ASSERT_NE(ret, HCF_SUCCESS);

    HcfObjDestroy(verify);
}

HWTEST_F(CryptoMlDsaSignVerifyTest, CryptoMlDsaSignWithoutInitTest001, TestSize.Level0)
{
    HcfSign *sign = nullptr;
    HcfResult ret = HcfSignCreate("ML-DSA", &sign);
    ASSERT_EQ(ret, HCF_SUCCESS);
    ASSERT_NE(sign, nullptr);

    HcfBlob out = { .data = nullptr, .len = 0 };
    ret = sign->sign(sign, &g_mockInput, &out);
    ASSERT_NE(ret, HCF_SUCCESS);
    ASSERT_EQ(out.data, nullptr);

    HcfObjDestroy(sign);
}

HWTEST_F(CryptoMlDsaSignVerifyTest, CryptoMlDsaSignNullOutputTest001, TestSize.Level0)
{
    HcfSign *sign = nullptr;
    HcfResult ret = HcfSignCreate("ML-DSA", &sign);
    ASSERT_EQ(ret, HCF_SUCCESS);
    ASSERT_NE(sign, nullptr);

    ret = sign->init(sign, nullptr, mlDsa65KeyPair_->priKey);
    ASSERT_EQ(ret, HCF_SUCCESS);

    ret = sign->sign(sign, &g_mockInput, nullptr);
    ASSERT_NE(ret, HCF_SUCCESS);

    HcfObjDestroy(sign);
}

HWTEST_F(CryptoMlDsaSignVerifyTest, CryptoMlDsaSignWrongClassTest001, TestSize.Level0)
{
    HcfSign *sign = nullptr;
    HcfResult ret = HcfSignCreate("ML-DSA", &sign);
    ASSERT_EQ(ret, HCF_SUCCESS);
    ASSERT_NE(sign, nullptr);

    ret = sign->init(sign, nullptr, mlDsa65KeyPair_->priKey);
    ASSERT_EQ(ret, HCF_SUCCESS);

    HcfBlob out = { .data = nullptr, .len = 0 };
    ret = sign->sign((HcfSign *)&g_obj, &g_mockInput, &out);
    ASSERT_NE(ret, HCF_SUCCESS);

    HcfObjDestroy(sign);
}

HWTEST_F(CryptoMlDsaSignVerifyTest, CryptoMlDsaSignTwiceTest001, TestSize.Level0)
{
    HcfSign *sign = nullptr;
    HcfResult ret = HcfSignCreate("ML-DSA", &sign);
    ASSERT_EQ(ret, HCF_SUCCESS);
    ASSERT_NE(sign, nullptr);

    ret = sign->init(sign, nullptr, mlDsa65KeyPair_->priKey);
    ASSERT_EQ(ret, HCF_SUCCESS);

    HcfBlob out1 = { .data = nullptr, .len = 0 };
    ret = sign->sign(sign, &g_mockInput, &out1);
    ASSERT_EQ(ret, HCF_SUCCESS);
    ASSERT_NE(out1.data, nullptr);
    HcfFree(out1.data);

    HcfBlob out2 = { .data = nullptr, .len = 0 };
    ret = sign->sign(sign, &g_mockInput, &out2);
    ASSERT_EQ(ret, HCF_SUCCESS);
    ASSERT_NE(out2.data, nullptr);
    ASSERT_GT(out2.len, (uint32_t)0);
    HcfFree(out2.data);

    HcfObjDestroy(sign);
}

HWTEST_F(CryptoMlDsaSignVerifyTest, CryptoMlDsaSign64ByteTest001, TestSize.Level0)
{
    HcfSign *sign = nullptr;
    HcfResult ret = HcfSignCreate("ML-DSA", &sign);
    ASSERT_EQ(ret, HCF_SUCCESS);
    ASSERT_NE(sign, nullptr);

    ret = sign->init(sign, nullptr, mlDsa65KeyPair_->priKey);
    ASSERT_EQ(ret, HCF_SUCCESS);

    HcfBlob out = { .data = nullptr, .len = 0 };
    ret = sign->sign(sign, &g_mockInput, &out);
    ASSERT_EQ(ret, HCF_SUCCESS);
    ASSERT_NE(out.data, nullptr);
    ASSERT_EQ(out.len, ML_DSA_65_SIGN_LEN);

    HcfFree(out.data);
    HcfObjDestroy(sign);
}

HWTEST_F(CryptoMlDsaSignVerifyTest, CryptoMlDsaVerifyWithoutInitTest001, TestSize.Level0)
{
    HcfVerify *verify = nullptr;
    HcfResult ret = HcfVerifyCreate("ML-DSA", &verify);
    ASSERT_EQ(ret, HCF_SUCCESS);
    ASSERT_NE(verify, nullptr);

    HcfBlob out = { .data = nullptr, .len = 0 };
    bool flag = verify->verify(verify, &g_mockInput, &out);
    ASSERT_EQ(flag, false);

    HcfFree(out.data);
    HcfObjDestroy(verify);
}

HWTEST_F(CryptoMlDsaSignVerifyTest, CryptoMlDsaVerifyNullInputTest001, TestSize.Level0)
{
    HcfVerify *verify = nullptr;
    HcfResult ret = HcfVerifyCreate("ML-DSA", &verify);
    ASSERT_EQ(ret, HCF_SUCCESS);
    ASSERT_NE(verify, nullptr);

    ret = verify->init(verify, nullptr, mlDsa65KeyPair_->pubKey);
    ASSERT_EQ(ret, HCF_SUCCESS);

    HcfBlob out = { .data = nullptr, .len = 0 };
    bool flag = verify->verify(verify, nullptr, &out);
    ASSERT_EQ(flag, false);

    HcfFree(out.data);
    HcfObjDestroy(verify);
}

HWTEST_F(CryptoMlDsaSignVerifyTest, CryptoMlDsaVerifyNullSignatureTest001, TestSize.Level0)
{
    HcfVerify *verify = nullptr;
    HcfResult ret = HcfVerifyCreate("ML-DSA", &verify);
    ASSERT_EQ(ret, HCF_SUCCESS);
    ASSERT_NE(verify, nullptr);

    ret = verify->init(verify, nullptr, mlDsa65KeyPair_->pubKey);
    ASSERT_EQ(ret, HCF_SUCCESS);

    bool flag = verify->verify(verify, &g_mockInput, nullptr);
    ASSERT_EQ(flag, false);

    HcfObjDestroy(verify);
}

HWTEST_F(CryptoMlDsaSignVerifyTest, CryptoMlDsaVerifyWrongSignatureTest001, TestSize.Level0)
{
    HcfVerify *verify = nullptr;
    HcfResult ret = HcfVerifyCreate("ML-DSA", &verify);
    ASSERT_EQ(ret, HCF_SUCCESS);
    ASSERT_NE(verify, nullptr);

    ret = verify->init(verify, nullptr, mlDsa65KeyPair_->pubKey);
    ASSERT_EQ(ret, HCF_SUCCESS);

    bool flag = verify->verify(verify, &g_mockInput, &g_mockInput);
    ASSERT_EQ(flag, false);

    HcfObjDestroy(verify);
}

HWTEST_F(CryptoMlDsaSignVerifyTest, CryptoMlDsaVerifyTwiceTest001, TestSize.Level0)
{
    HcfSign *sign = nullptr;
    HcfResult ret = HcfSignCreate("ML-DSA", &sign);
    ASSERT_EQ(ret, HCF_SUCCESS);
    ASSERT_NE(sign, nullptr);

    ret = sign->init(sign, nullptr, mlDsa65KeyPair_->priKey);
    ASSERT_EQ(ret, HCF_SUCCESS);

    HcfBlob out = { .data = nullptr, .len = 0 };
    ret = sign->sign(sign, &g_mockInput, &out);
    ASSERT_EQ(ret, HCF_SUCCESS);
    ASSERT_NE(out.data, nullptr);

    HcfVerify *verify = nullptr;
    ret = HcfVerifyCreate("ML-DSA", &verify);
    ASSERT_EQ(ret, HCF_SUCCESS);
    ASSERT_NE(verify, nullptr);

    ret = verify->init(verify, nullptr, mlDsa65KeyPair_->pubKey);
    ASSERT_EQ(ret, HCF_SUCCESS);

    bool flag = verify->verify(verify, &g_mockInput, &out);
    ASSERT_EQ(flag, true);

    flag = verify->verify(verify, &g_mockInput, &out);
    ASSERT_EQ(flag, true);

    HcfFree(out.data);
    HcfObjDestroy(sign);
    HcfObjDestroy(verify);
}

HWTEST_F(CryptoMlDsaSignVerifyTest, CryptoMlDsaSignVerify64ByteTest001, TestSize.Level0)
{
    HcfSign *sign = nullptr;
    HcfResult ret = HcfSignCreate("ML-DSA", &sign);
    ASSERT_EQ(ret, HCF_SUCCESS);
    ASSERT_NE(sign, nullptr);

    ret = sign->init(sign, nullptr, mlDsa65KeyPair_->priKey);
    ASSERT_EQ(ret, HCF_SUCCESS);

    HcfBlob out = { .data = nullptr, .len = 0 };
    ret = sign->sign(sign, &g_mock64Input, &out);
    ASSERT_EQ(ret, HCF_SUCCESS);
    ASSERT_NE(out.data, nullptr);

    HcfVerify *verify = nullptr;
    ret = HcfVerifyCreate("ML-DSA", &verify);
    ASSERT_EQ(ret, HCF_SUCCESS);

    ret = verify->init(verify, nullptr, mlDsa65KeyPair_->pubKey);
    ASSERT_EQ(ret, HCF_SUCCESS);

    bool flag = verify->verify(verify, &g_mock64Input, &out);
    ASSERT_EQ(flag, true);

    HcfFree(out.data);
    HcfObjDestroy(sign);
    HcfObjDestroy(verify);
}

HWTEST_F(CryptoMlDsaSignVerifyTest, CryptoMlDsaSignSpiDestroyNullptrTest001, TestSize.Level0)
{
    HcfSignSpi *sign = nullptr;
    HcfSignatureParams params = { .algo = HCF_ALG_ML_DSA };
    HcfResult ret = HcfSignSpiMlDsaCreate(&params, &sign);
    ASSERT_EQ(ret, HCF_SUCCESS);
    ASSERT_NE(sign, nullptr);

    sign->base.destroy(nullptr);
    HcfObjDestroy(sign);
}

HWTEST_F(CryptoMlDsaSignVerifyTest, CryptoMlDsaSignSpiEngineInitNullKeyTest001, TestSize.Level0)
{
    HcfSignSpi *sign = nullptr;
    HcfSignatureParams params = { .algo = HCF_ALG_ML_DSA };
    HcfResult ret = HcfSignSpiMlDsaCreate(&params, &sign);
    ASSERT_EQ(ret, HCF_SUCCESS);
    ASSERT_NE(sign, nullptr);

    ret = sign->engineInit(sign, nullptr, nullptr);
    ASSERT_NE(ret, HCF_SUCCESS);
    HcfObjDestroy(sign);
}

HWTEST_F(CryptoMlDsaSignVerifyTest, CryptoMlDsaSignSpiEngineSignTest001, TestSize.Level0)
{
    HcfSignSpi *sign = nullptr;
    HcfSignatureParams params = { .algo = HCF_ALG_ML_DSA };
    HcfResult ret = HcfSignSpiMlDsaCreate(&params, &sign);
    ASSERT_EQ(ret, HCF_SUCCESS);
    ASSERT_NE(sign, nullptr);

    ret = sign->engineInit(sign, nullptr, mlDsa65KeyPair_->priKey);
    ASSERT_EQ(ret, HCF_SUCCESS);

    HcfBlob out = { .data = nullptr, .len = 0 };
    ret = sign->engineSign(sign, &g_mockInput, &out);
    ASSERT_EQ(ret, HCF_SUCCESS);
    ASSERT_NE(out.data, nullptr);
    HcfFree(out.data);
    HcfObjDestroy(sign);
}

HWTEST_F(CryptoMlDsaSignVerifyTest, CryptoMlDsaVerifySpiNullTest001, TestSize.Level0)
{
    // params is unused in ML-DSA SPI create, NULL is allowed
    HcfVerifySpi *verify = nullptr;
    HcfResult ret = HcfVerifySpiMlDsaCreate(nullptr, &verify);
    ASSERT_EQ(ret, HCF_SUCCESS);
    HcfObjDestroy(verify);

    HcfSignatureParams params = { .algo = HCF_ALG_ML_DSA };
    ret = HcfVerifySpiMlDsaCreate(&params, nullptr);
    ASSERT_NE(ret, HCF_SUCCESS);
}

HWTEST_F(CryptoMlDsaSignVerifyTest, CryptoMlDsaVerifySpiDestroyNullptrTest001, TestSize.Level0)
{
    HcfVerifySpi *verify = nullptr;
    HcfSignatureParams params = { .algo = HCF_ALG_ML_DSA };
    HcfResult ret = HcfVerifySpiMlDsaCreate(&params, &verify);
    ASSERT_EQ(ret, HCF_SUCCESS);
    ASSERT_NE(verify, nullptr);

    verify->base.destroy(nullptr);
    HcfObjDestroy(verify);
}

HWTEST_F(CryptoMlDsaSignVerifyTest, CryptoMlDsaVerifySpiEngineInitNullKeyTest001, TestSize.Level0)
{
    HcfVerifySpi *verify = nullptr;
    HcfSignatureParams params = { .algo = HCF_ALG_ML_DSA };
    HcfResult ret = HcfVerifySpiMlDsaCreate(&params, &verify);
    ASSERT_EQ(ret, HCF_SUCCESS);
    ASSERT_NE(verify, nullptr);

    ret = verify->engineInit(verify, nullptr, nullptr);
    ASSERT_NE(ret, HCF_SUCCESS);
    HcfObjDestroy(verify);
}

HWTEST_F(CryptoMlDsaSignVerifyTest, CryptoMlDsaVerifySpiEngineVerifyWithoutInitTest001, TestSize.Level0)
{
    HcfVerifySpi *verify = nullptr;
    HcfSignatureParams params = { .algo = HCF_ALG_ML_DSA };
    HcfResult ret = HcfVerifySpiMlDsaCreate(&params, &verify);
    ASSERT_EQ(ret, HCF_SUCCESS);
    ASSERT_NE(verify, nullptr);

    bool flag = verify->engineVerify(verify, &g_mockInput, &g_mockInput);
    ASSERT_EQ(flag, false);

    flag = verify->engineVerify(verify, nullptr, &g_mockInput);
    ASSERT_EQ(flag, false);

    HcfObjDestroy(verify);
}

HWTEST_F(CryptoMlDsaSignVerifyTest, CryptoMlDsaSignUnsupportedSpecTest001, TestSize.Level0)
{
    HcfSign *sign = nullptr;
    HcfResult ret = HcfSignCreate("ML-DSA", &sign);
    ASSERT_EQ(ret, HCF_SUCCESS);
    ASSERT_NE(sign, nullptr);

    int32_t returnInt = 0;
    ret = sign->setSignSpecInt(sign, SM2_USER_ID_UINT8ARR, returnInt);
    ASSERT_EQ(ret, HCF_ERR_INVALID_CALL);

    ret = sign->getSignSpecInt(sign, SM2_USER_ID_UINT8ARR, &returnInt);
    ASSERT_EQ(ret, HCF_ERR_INVALID_CALL);

    HcfBlob returnBlob = { .data = nullptr, .len = 0 };
    ret = sign->setSignSpecUint8Array(sign, SM2_USER_ID_UINT8ARR, returnBlob);
    ASSERT_EQ(ret, HCF_ERR_PARAMETER_CHECK_FAILED);

    char *itemName = nullptr;
    ret = sign->getSignSpecString(sign, SM2_USER_ID_UINT8ARR, &itemName);
    ASSERT_EQ(ret, HCF_ERR_INVALID_CALL);

    HcfObjDestroy(sign);
}

HWTEST_F(CryptoMlDsaSignVerifyTest, CryptoMlDsaVerifyUnsupportedSpecTest001, TestSize.Level0)
{
    HcfVerify *verify = nullptr;
    HcfResult ret = HcfVerifyCreate("ML-DSA", &verify);
    ASSERT_EQ(ret, HCF_SUCCESS);
    ASSERT_NE(verify, nullptr);

    int32_t returnInt = 0;
    ret = verify->setVerifySpecInt(verify, SM2_USER_ID_UINT8ARR, returnInt);
    ASSERT_EQ(ret, HCF_ERR_INVALID_CALL);

    ret = verify->getVerifySpecInt(verify, SM2_USER_ID_UINT8ARR, &returnInt);
    ASSERT_EQ(ret, HCF_ERR_INVALID_CALL);

    HcfBlob returnBlob = { .data = nullptr, .len = 0 };
    ret = verify->setVerifySpecUint8Array(verify, SM2_USER_ID_UINT8ARR, returnBlob);
    ASSERT_EQ(ret, HCF_ERR_PARAMETER_CHECK_FAILED);

    char *itemName = nullptr;
    ret = verify->getVerifySpecString(verify, SM2_USER_ID_UINT8ARR, &itemName);
    ASSERT_EQ(ret, HCF_ERR_INVALID_CALL);

    HcfObjDestroy(verify);
}

HWTEST_F(CryptoMlDsaSignVerifyTest, CryptoMlDsaSetSignSpecUint8ArrayAfterInitTest001, TestSize.Level0)
{
    HcfSign *sign = nullptr;
    HcfResult ret = HcfSignCreate("ML-DSA", &sign);
    ASSERT_EQ(ret, HCF_SUCCESS);
    ASSERT_NE(sign, nullptr);

    ret = sign->init(sign, nullptr, mlDsa65KeyPair_->priKey);
    ASSERT_EQ(ret, HCF_SUCCESS);

    uint8_t contextData[] = { 0x01, 0x02 };
    HcfBlob contextBlob = { .data = contextData, .len = sizeof(contextData) };
    ret = sign->setSignSpecUint8Array(sign, ML_DSA_CONTEXT_UINT8ARR, contextBlob);
    ASSERT_EQ(ret, HCF_ERR_INVALID_CALL);

    HcfObjDestroy(sign);
}

HWTEST_F(CryptoMlDsaSignVerifyTest, CryptoMlDsaSetVerifySpecUint8ArrayAfterInitTest001, TestSize.Level0)
{
    HcfVerify *verify = nullptr;
    HcfResult ret = HcfVerifyCreate("ML-DSA", &verify);
    ASSERT_EQ(ret, HCF_SUCCESS);
    ASSERT_NE(verify, nullptr);

    ret = verify->init(verify, nullptr, mlDsa65KeyPair_->pubKey);
    ASSERT_EQ(ret, HCF_SUCCESS);

    uint8_t contextData[] = { 0x01, 0x02 };
    HcfBlob contextBlob = { .data = contextData, .len = sizeof(contextData) };
    ret = verify->setVerifySpecUint8Array(verify, ML_DSA_CONTEXT_UINT8ARR, contextBlob);
    ASSERT_EQ(ret, HCF_ERR_INVALID_CALL);

    HcfObjDestroy(verify);
}

HWTEST_F(CryptoMlDsaSignVerifyTest, CryptoMlDsaSetVerifySpecBoolAfterInitTest001, TestSize.Level0)
{
    HcfVerify *verify = nullptr;
    HcfResult ret = HcfVerifyCreate("ML-DSA", &verify);
    ASSERT_EQ(ret, HCF_SUCCESS);
    ASSERT_NE(verify, nullptr);

    ret = verify->init(verify, nullptr, mlDsa65KeyPair_->pubKey);
    ASSERT_EQ(ret, HCF_SUCCESS);

    ret = verify->setVerifySpecBool(verify, ML_DSA_MU_BOOL, true);
    ASSERT_EQ(ret, HCF_ERR_INVALID_CALL);

    HcfObjDestroy(verify);
}

HWTEST_F(CryptoMlDsaSignVerifyTest, CryptoMlDsaDeterministicSignVerifyTest001, TestSize.Level0)
{
    HcfSign *sign = nullptr;
    HcfResult ret = HcfSignCreate("ML-DSA", &sign);
    ASSERT_EQ(ret, HCF_SUCCESS);
    ASSERT_NE(sign, nullptr);

    ret = sign->setSignSpecBool(sign, ML_DSA_DETERMINISTIC_BOOL, true);
    ASSERT_EQ(ret, HCF_SUCCESS);

    ret = sign->init(sign, nullptr, mlDsa65KeyPair_->priKey);
    ASSERT_EQ(ret, HCF_SUCCESS);

    HcfBlob out1 = { .data = nullptr, .len = 0 };
    ret = sign->sign(sign, &g_mockInput, &out1);
    ASSERT_EQ(ret, HCF_SUCCESS);

    HcfBlob out2 = { .data = nullptr, .len = 0 };
    ret = sign->sign(sign, &g_mockInput, &out2);
    ASSERT_EQ(ret, HCF_SUCCESS);

    ASSERT_EQ(out1.len, out2.len);
    ASSERT_EQ(memcmp(out1.data, out2.data, out1.len), 0);

    HcfVerify *verify = nullptr;
    ret = HcfVerifyCreate("ML-DSA", &verify);
    ASSERT_EQ(ret, HCF_SUCCESS);

    ret = verify->init(verify, nullptr, mlDsa65KeyPair_->pubKey);
    ASSERT_EQ(ret, HCF_SUCCESS);

    bool flag = verify->verify(verify, &g_mockInput, &out1);
    ASSERT_EQ(flag, true);

    HcfFree(out1.data);
    HcfFree(out2.data);
    HcfObjDestroy(sign);
    HcfObjDestroy(verify);
}

HWTEST_F(CryptoMlDsaSignVerifyTest, CryptoMlDsaContextSignVerifyTest001, TestSize.Level0)
{
    HcfSign *sign = nullptr;
    HcfResult ret = HcfSignCreate("ML-DSA", &sign);
    ASSERT_EQ(ret, HCF_SUCCESS);
    ASSERT_NE(sign, nullptr);

    uint8_t contextData[] = { 0xAA, 0xBB, 0xCC };
    HcfBlob contextBlob = { .data = contextData, .len = sizeof(contextData) };
    ret = sign->setSignSpecUint8Array(sign, ML_DSA_CONTEXT_UINT8ARR, contextBlob);
    ASSERT_EQ(ret, HCF_SUCCESS);

    ret = sign->init(sign, nullptr, mlDsa65KeyPair_->priKey);
    ASSERT_EQ(ret, HCF_SUCCESS);

    HcfBlob out = { .data = nullptr, .len = 0 };
    ret = sign->sign(sign, &g_mockInput, &out);
    ASSERT_EQ(ret, HCF_SUCCESS);

    HcfVerify *verify = nullptr;
    ret = HcfVerifyCreate("ML-DSA", &verify);
    ASSERT_EQ(ret, HCF_SUCCESS);

    ret = verify->setVerifySpecUint8Array(verify, ML_DSA_CONTEXT_UINT8ARR, contextBlob);
    ASSERT_EQ(ret, HCF_SUCCESS);

    ret = verify->init(verify, nullptr, mlDsa65KeyPair_->pubKey);
    ASSERT_EQ(ret, HCF_SUCCESS);

    bool flag = verify->verify(verify, &g_mockInput, &out);
    ASSERT_EQ(flag, true);

    HcfFree(out.data);
    HcfObjDestroy(sign);
    HcfObjDestroy(verify);
}

HWTEST_F(CryptoMlDsaSignVerifyTest, CryptoMlDsaContextMismatchVerifyTest001, TestSize.Level0)
{
    HcfSign *sign = nullptr;
    HcfResult ret = HcfSignCreate("ML-DSA", &sign);
    ASSERT_EQ(ret, HCF_SUCCESS);
    ASSERT_NE(sign, nullptr);

    uint8_t contextData[] = { 0x01 };
    HcfBlob contextBlob = { .data = contextData, .len = sizeof(contextData) };
    ret = sign->setSignSpecUint8Array(sign, ML_DSA_CONTEXT_UINT8ARR, contextBlob);
    ASSERT_EQ(ret, HCF_SUCCESS);

    ret = sign->init(sign, nullptr, mlDsa65KeyPair_->priKey);
    ASSERT_EQ(ret, HCF_SUCCESS);

    HcfBlob out = { .data = nullptr, .len = 0 };
    ret = sign->sign(sign, &g_mockInput, &out);
    ASSERT_EQ(ret, HCF_SUCCESS);

    HcfVerify *verify = nullptr;
    ret = HcfVerifyCreate("ML-DSA", &verify);
    ASSERT_EQ(ret, HCF_SUCCESS);

    ret = verify->init(verify, nullptr, mlDsa65KeyPair_->pubKey);
    ASSERT_EQ(ret, HCF_SUCCESS);

    bool flag = verify->verify(verify, &g_mockInput, &out);
    ASSERT_EQ(flag, false);

    HcfFree(out.data);
    HcfObjDestroy(sign);
    HcfObjDestroy(verify);
}
}
