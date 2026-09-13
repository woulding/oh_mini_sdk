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
#include <cstring>

#include "asy_key_generator.h"
#include "blob.h"
#include "ecdsa_openssl.h"
#include "memory.h"
#include "securec.h"
#include "openssl_common.h"
#include "asy_key_params.h"
#include "params_parser.h"
#include "detailed_alg_25519_key_params.h"
#include "alg_25519_asy_key_generator_openssl.h"
#include "ed25519_openssl.h"
#include "memory_mock.h"
#include "openssl_adapter_mock.h"

using namespace std;
using namespace testing::ext;

namespace {
class CryptoEd25519VerifyTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp();
    void TearDown();
    static HcfKeyPair *ed25519KeyPair_;
    static HcfKeyPair *x25519KeyPair_;
};

HcfKeyPair *CryptoEd25519VerifyTest::ed25519KeyPair_ = nullptr;
HcfKeyPair *CryptoEd25519VerifyTest::x25519KeyPair_ = nullptr;

static string g_ed25519AlgoName = "Ed25519";
static string g_x25519AlgoName = "X25519";

void CryptoEd25519VerifyTest::SetUp() {}
void CryptoEd25519VerifyTest::TearDown() {}

static const char *g_mockMessage = "hello world";
static HcfBlob g_mockInput = {
    .data = (uint8_t *)g_mockMessage,
    .len = 12
};

static const char *GetMockClass(void)
{
    return "Ed25519Verifytest";
}
HcfObjectBase g_obj = {
    .getClass = GetMockClass,
    .destroy = nullptr
};

static const char *g_mock64Message = "ABCDABCDACBDABCDABCDABCDACBDABCDABCDABCDACBDABCDABCDABCDACBDABCD";
static HcfBlob g_mock64Input = {
    .data = (uint8_t *)g_mock64Message,
    .len = 65
};

void CryptoEd25519VerifyTest::SetUpTestCase()
{
    HcfAsyKeyGenerator *generator = nullptr;
    HcfResult ret = HcfAsyKeyGeneratorCreate(g_ed25519AlgoName.c_str(), &generator);
    ASSERT_EQ(ret, HCF_SUCCESS);
    ASSERT_NE(generator, nullptr);

    HcfKeyPair *keyPair = nullptr;
    ret = generator->generateKeyPair(generator, nullptr, &keyPair);
    ASSERT_EQ(ret, HCF_SUCCESS);
    ASSERT_NE(keyPair, nullptr);
    HcfObjDestroy(generator);

    ed25519KeyPair_ = keyPair;

    ret = HcfAsyKeyGeneratorCreate(g_x25519AlgoName.c_str(), &generator);
    ASSERT_EQ(ret, HCF_SUCCESS);
    ASSERT_NE(generator, nullptr);

    ret = generator->generateKeyPair(generator, nullptr, &keyPair);
    ASSERT_EQ(ret, HCF_SUCCESS);
    ASSERT_NE(keyPair, nullptr);

    x25519KeyPair_ = keyPair;

    HcfObjDestroy(generator);
}

void CryptoEd25519VerifyTest::TearDownTestCase()
{
    HcfObjDestroy(ed25519KeyPair_);
    HcfObjDestroy(x25519KeyPair_);
}

HWTEST_F(CryptoEd25519VerifyTest, CryptoEd25519VerifyTest001, TestSize.Level0)
{
    HcfVerify *verify = nullptr;
    HcfResult ret = HcfVerifyCreate("Ed25519", &verify);
    ASSERT_EQ(ret, HCF_SUCCESS);
    ASSERT_NE(verify, nullptr);

    HcfObjDestroy(verify);
}

HWTEST_F(CryptoEd25519VerifyTest, CryptoEd25519VerifyTest002, TestSize.Level0)
{
    HcfVerify *verify = nullptr;
    HcfResult ret = HcfVerifyCreate("Ed25519", &verify);
    ASSERT_EQ(ret, HCF_SUCCESS);
    ASSERT_NE(verify, nullptr);

    const char *className = verify->base.getClass();
    ASSERT_NE(className, nullptr);

    HcfObjDestroy(verify);
}

HWTEST_F(CryptoEd25519VerifyTest, CryptoEd25519VerifyTest003, TestSize.Level0)
{
    HcfVerify *verify = nullptr;
    HcfResult ret = HcfVerifyCreate("Ed25519", &verify);
    ASSERT_EQ(ret, HCF_SUCCESS);
    ASSERT_NE(verify, nullptr);

    verify->base.destroy((HcfObjectBase *)verify);
}

HWTEST_F(CryptoEd25519VerifyTest, CryptoEd25519VerifyTest004, TestSize.Level0)
{
    HcfVerify *verify = nullptr;
    HcfResult ret = HcfVerifyCreate("Ed25519", &verify);
    ASSERT_EQ(ret, HCF_SUCCESS);
    ASSERT_NE(verify, nullptr);

    const char *algName = verify->getAlgoName(verify);
    ASSERT_EQ(algName, g_ed25519AlgoName);

    HcfObjDestroy(verify);
}

HWTEST_F(CryptoEd25519VerifyTest, CryptoEd25519VerifyTest005, TestSize.Level0)
{
    HcfVerify *verify = nullptr;
    HcfResult ret = HcfVerifyCreate("Ed25519", &verify);
    ASSERT_EQ(ret, HCF_SUCCESS);
    ASSERT_NE(verify, nullptr);

    ret = verify->init(verify, nullptr, ed25519KeyPair_->pubKey);
    ASSERT_EQ(ret, HCF_SUCCESS);

    HcfObjDestroy(verify);
}

HWTEST_F(CryptoEd25519VerifyTest, CryptoEd25519VerifyTest006, TestSize.Level0)
{
    HcfSign *sign = nullptr;
    HcfResult ret = HcfSignCreate("Ed25519", &sign);
    ASSERT_EQ(ret, HCF_SUCCESS);
    ASSERT_NE(sign, nullptr);

    ret = sign->init(sign, nullptr, ed25519KeyPair_->priKey);
    ASSERT_EQ(ret, HCF_SUCCESS);

    HcfBlob out = { .data = nullptr, .len = 0 };
    ret = sign->sign(sign, &g_mockInput, &out);
    ASSERT_EQ(ret, HCF_SUCCESS);
    ASSERT_NE(out.data, nullptr);
    ASSERT_NE(out.len, (const unsigned int)0);

    HcfVerify *verify = nullptr;
    ret = HcfVerifyCreate("Ed25519", &verify);
    ASSERT_EQ(ret, HCF_SUCCESS);
    ASSERT_NE(verify, nullptr);

    ret = verify->init(verify, nullptr, ed25519KeyPair_->pubKey);
    ASSERT_EQ(ret, HCF_SUCCESS);

    bool flag = verify->verify(verify, &g_mockInput, &out);
    ASSERT_EQ(flag, true);
    ASSERT_NE(out.data, nullptr);
    ASSERT_NE(out.len, (const unsigned int)0);

    HcfFree(out.data);
    HcfObjDestroy(sign);
    HcfObjDestroy(verify);
}

HWTEST_F(CryptoEd25519VerifyTest, CryptoEd25519VerifyTest007, TestSize.Level0)
{
    HcfSign *sign = nullptr;
    HcfResult ret = HcfSignCreate("Ed25519", &sign);
    ASSERT_EQ(ret, HCF_SUCCESS);
    ASSERT_NE(sign, nullptr);

    ret = sign->init(sign, nullptr, ed25519KeyPair_->priKey);
    ASSERT_EQ(ret, HCF_SUCCESS);

    HcfBlob out = { .data = nullptr, .len = 0 };
    ret = sign->sign(sign, &g_mockInput, &out);
    ASSERT_EQ(ret, HCF_SUCCESS);
    ASSERT_NE(out.data, nullptr);
    ASSERT_NE(out.len, (const unsigned int)0);

    HcfVerify *verify = nullptr;
    ret = HcfVerifyCreate("Ed25519", &verify);
    ASSERT_EQ(ret, HCF_SUCCESS);
    ASSERT_NE(verify, nullptr);

    ret = verify->init(verify, nullptr, ed25519KeyPair_->pubKey);
    ASSERT_EQ(ret, HCF_SUCCESS);

    bool flag = verify->verify(verify, &g_mockInput, &out);
    ASSERT_EQ(flag, true);

    HcfFree(out.data);
    HcfObjDestroy(sign);
    HcfObjDestroy(verify);
}

static bool GetSignTestData(HcfBlob *out)
{
    HcfSign *sign = nullptr;
    int32_t res = HcfSignCreate("Ed25519", &sign);
    if (res != HCF_SUCCESS) {
        return false;
    }
    res = sign->init(sign, nullptr, CryptoEd25519VerifyTest::ed25519KeyPair_->priKey);
    if (res != HCF_SUCCESS) {
        HcfObjDestroy(sign);
        return false;
    }
    res = sign->sign(sign, &g_mockInput, out);
    HcfObjDestroy(sign);
    return res == HCF_SUCCESS;
}

static void OpensslMockTestFunc(uint32_t mallocCount, HcfBlob *out)
{
    for (uint32_t i = 0; i < mallocCount; i++) {
        ResetOpensslCallNum();
        SetOpensslCallMockIndex(i);
        HcfVerify *verify = nullptr;
        int32_t res = HcfVerifyCreate("Ed25519", &verify);
        if (res != HCF_SUCCESS) {
            continue;
        }
        res = verify->init(verify, nullptr, CryptoEd25519VerifyTest::ed25519KeyPair_->pubKey);
        if (res != HCF_SUCCESS) {
            HcfObjDestroy(verify);
            continue;
        }
        res = verify->verify(verify, &g_mockInput, out);
        if (res != HCF_SUCCESS) {
            HcfObjDestroy(verify);
            continue;
        }
        HcfObjDestroy(verify);
    }
}

HWTEST_F(CryptoEd25519VerifyTest, CryptoEd25519VerifyTest008, TestSize.Level0)
{
    HcfBlob out = { .data = nullptr, .len = 0 };
    ASSERT_EQ(GetSignTestData(&out), true);
    StartRecordOpensslCallNum();

    HcfVerify *verify = nullptr;
    int32_t res = HcfVerifyCreate("Ed25519", &verify);
    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(verify, nullptr);
    res = verify->init(verify, nullptr, ed25519KeyPair_->pubKey);
    ASSERT_EQ(res, HCF_SUCCESS);
    bool flag = verify->verify(verify, &g_mockInput, &out);
    ASSERT_EQ(flag, true);
    HcfObjDestroy(verify);

    uint32_t mallocCount = GetOpensslCallNum();
    OpensslMockTestFunc(mallocCount, &out);
    HcfBlobDataFree(&out);
    EndRecordOpensslCallNum();
}

HcfSignatureParams g_params = {
    .algo = HCF_ALG_ED25519,
};

HWTEST_F(CryptoEd25519VerifyTest, CryptoEd25519VerifyTest009, TestSize.Level0)
{
    HcfVerifySpi *verify = nullptr;
    HcfResult ret = HcfVerifySpiEd25519Create(nullptr, &verify);
    ASSERT_EQ(ret, HCF_INVALID_PARAMS);
    ASSERT_EQ(verify, nullptr);
    ret = HcfVerifySpiEd25519Create(&g_params, &verify);
    ASSERT_EQ(ret, HCF_SUCCESS);
    ASSERT_NE(verify, nullptr);

    HcfObjDestroy(verify);
}

HWTEST_F(CryptoEd25519VerifyTest, CryptoEd25519VerifyTest010, TestSize.Level0)
{
    HcfVerifySpi *verify = nullptr;
    HcfResult ret = HcfVerifySpiEd25519Create(&g_params, &verify);
    ASSERT_EQ(ret, HCF_SUCCESS);
    ASSERT_NE(verify, nullptr);

    verify->base.destroy(nullptr);
    HcfObjDestroy(verify);
}

HWTEST_F(CryptoEd25519VerifyTest, CryptoEd25519VerifyTest011, TestSize.Level0)
{
    HcfVerifySpi *verify = nullptr;
    HcfResult ret = HcfVerifySpiEd25519Create(&g_params, &verify);
    ASSERT_EQ(ret, HCF_SUCCESS);
    ASSERT_NE(verify, nullptr);

    ret = verify->engineInit(verify, nullptr, nullptr);
    ASSERT_EQ(ret, HCF_INVALID_PARAMS);
    HcfObjDestroy(verify);
}

HWTEST_F(CryptoEd25519VerifyTest, CryptoEd25519VerifyTest012, TestSize.Level0)
{
    HcfVerifySpi *verify = nullptr;
    int32_t ret = HcfVerifySpiEd25519Create(&g_params, &verify);
    ASSERT_EQ(ret, HCF_SUCCESS);
    ASSERT_NE(verify, nullptr);

    ret = verify->engineVerify(verify, &g_mockInput, &g_mockInput);
    ASSERT_EQ(ret, false);
    ret = verify->engineVerify(verify, nullptr, &g_mockInput);
    ASSERT_EQ(ret, false);
    HcfObjDestroy(verify);
}

HWTEST_F(CryptoEd25519VerifyTest, CryptoEd25519VerifyTest013, TestSize.Level0)
{
    HcfVerify *verify = nullptr;
    HcfResult ret = HcfVerifyCreate("Ed25519", &verify);
    ASSERT_EQ(ret, HCF_SUCCESS);
    ASSERT_NE(verify, nullptr);

    int32_t returnInt = 0;
    ret = verify->setVerifySpecInt(verify, SM2_USER_ID_UINT8ARR, returnInt);
    ASSERT_EQ(ret, HCF_NOT_SUPPORT);
    ret = verify->getVerifySpecInt(verify, SM2_USER_ID_UINT8ARR, &returnInt);
    ASSERT_EQ(ret, HCF_NOT_SUPPORT);
    HcfBlob returnBlob = { .data = nullptr, .len = 0};
    ret = verify->setVerifySpecUint8Array(verify, SM2_USER_ID_UINT8ARR, returnBlob);
    ASSERT_EQ(ret, HCF_NOT_SUPPORT);
    char *itemName = nullptr;
    ret = verify->getVerifySpecString(verify, SM2_USER_ID_UINT8ARR, &itemName);
    ASSERT_EQ(ret, HCF_NOT_SUPPORT);
    ret = verify->update(verify, &g_mockInput);
    ASSERT_EQ(ret, HCF_INVALID_PARAMS);

    HcfObjDestroy(verify);
}

HWTEST_F(CryptoEd25519VerifyTest, CryptoEd25519VerifyErrTest01, TestSize.Level0)
{
    HcfVerify *verify = nullptr;
    HcfResult ret = HcfVerifyCreate("Ed25519", &verify);
    ASSERT_EQ(ret, HCF_SUCCESS);
    ASSERT_NE(verify, nullptr);

    int32_t returnInt = 0;
    ret = verify->setVerifySpecInt(nullptr, SM2_USER_ID_UINT8ARR, returnInt);
    ASSERT_EQ(ret, HCF_INVALID_PARAMS);
    HcfObjDestroy(verify);
}

HWTEST_F(CryptoEd25519VerifyTest, CryptoEd25519VerifyTest014, TestSize.Level0)
{
    HcfVerify *verify = nullptr;
    HcfResult ret = HcfVerifyCreate("Ed25519", &verify);
    ASSERT_EQ(ret, HCF_SUCCESS);
    ASSERT_NE(verify, nullptr);

    verify->base.destroy(nullptr);
    HcfObjDestroy(verify);
}

HWTEST_F(CryptoEd25519VerifyTest, CryptoEd25519VerifyTest015, TestSize.Level0)
{
    HcfVerify *verify = nullptr;
    HcfResult ret = HcfVerifyCreate("Ed25519", &verify);
    ASSERT_EQ(ret, HCF_SUCCESS);
    ASSERT_NE(verify, nullptr);

    verify->base.destroy(&g_obj);
    HcfObjDestroy(verify);
}

HWTEST_F(CryptoEd25519VerifyTest, CryptoEd25519VerifyTest016, TestSize.Level0)
{
    HcfVerify *verify = nullptr;
    HcfResult ret = HcfVerifyCreate("Ed25519", &verify);
    ASSERT_EQ(ret, HCF_SUCCESS);
    ASSERT_NE(verify, nullptr);

    const char *algoName = verify->getAlgoName(nullptr);
    ASSERT_EQ(algoName, nullptr);

    algoName = verify->getAlgoName((HcfVerify *)&g_obj);
    ASSERT_EQ(algoName, nullptr);

    HcfObjDestroy(verify);
}

HWTEST_F(CryptoEd25519VerifyTest, CryptoEd25519VerifyTest017, TestSize.Level0)
{
    HcfVerify *verify = nullptr;
    HcfResult ret = HcfVerifyCreate("Ed25519", &verify);
    ASSERT_EQ(ret, HCF_SUCCESS);
    ASSERT_NE(verify, nullptr);

    ret = verify->init(nullptr, nullptr, ed25519KeyPair_->pubKey);
    ASSERT_EQ(ret, HCF_INVALID_PARAMS);

    HcfObjDestroy(verify);
}

HWTEST_F(CryptoEd25519VerifyTest, CryptoEd25519VerifyTest018, TestSize.Level0)
{
    HcfVerify *verify = nullptr;
    HcfResult ret = HcfVerifyCreate("Ed25519", &verify);
    ASSERT_EQ(ret, HCF_SUCCESS);
    ASSERT_NE(verify, nullptr);

    ret = verify->init((HcfVerify *)&g_obj, nullptr, ed25519KeyPair_->pubKey);
    ASSERT_EQ(ret, HCF_INVALID_PARAMS);

    HcfObjDestroy(verify);
}

HWTEST_F(CryptoEd25519VerifyTest, CryptoEd25519VerifyTest019, TestSize.Level0)
{
    HcfVerify *verify = nullptr;
    HcfResult ret = HcfVerifyCreate("Ed25519", &verify);
    ASSERT_EQ(ret, HCF_SUCCESS);
    ASSERT_NE(verify, nullptr);

    ret = verify->init(verify, nullptr, x25519KeyPair_->pubKey);
    ASSERT_EQ(ret, HCF_ERR_CRYPTO_OPERATION);

    HcfObjDestroy(verify);
}

HWTEST_F(CryptoEd25519VerifyTest, CryptoEd25519VerifyTest020, TestSize.Level0)
{
    HcfVerify *verify = nullptr;
    HcfResult ret = HcfVerifyCreate("Ed25519", &verify);
    ASSERT_EQ(ret, HCF_SUCCESS);
    ASSERT_NE(verify, nullptr);

    ret = verify->init(verify, nullptr, ed25519KeyPair_->pubKey);
    ret = verify->init(verify, nullptr, ed25519KeyPair_->pubKey);
    ASSERT_NE(ret, HCF_SUCCESS);

    HcfObjDestroy(verify);
}

HWTEST_F(CryptoEd25519VerifyTest, CryptoEd25519VerifyTest021, TestSize.Level0)
{
    HcfVerify *verify = nullptr;
    HcfResult ret = HcfVerifyCreate("Ed25519", &verify);
    ASSERT_EQ(ret, HCF_SUCCESS);
    ASSERT_NE(verify, nullptr);

    HcfBlob out = { .data = nullptr, .len = 0 };
    bool flag = verify->verify(verify, &g_mockInput, &out);
    ASSERT_EQ(flag, false);

    HcfFree(out.data);
    HcfObjDestroy(verify);
}

HWTEST_F(CryptoEd25519VerifyTest, CryptoEd25519VerifyTest022, TestSize.Level0)
{
    HcfVerify *verify = nullptr;
    HcfResult ret = HcfVerifyCreate("Ed25519", &verify);
    ASSERT_EQ(ret, HCF_SUCCESS);
    ASSERT_NE(verify, nullptr);

    ret = verify->init(verify, nullptr, ed25519KeyPair_->pubKey);
    ASSERT_EQ(ret, HCF_SUCCESS);
    HcfBlob out = { .data = nullptr, .len = 0 };
    bool flag = verify->verify(verify, nullptr, &out);
    ASSERT_EQ(flag, false);

    HcfFree(out.data);
    HcfObjDestroy(verify);
}

HWTEST_F(CryptoEd25519VerifyTest, CryptoEd25519VerifyTest023, TestSize.Level0)
{
    HcfVerify *verify = nullptr;
    HcfResult ret = HcfVerifyCreate("Ed25519", &verify);
    ASSERT_EQ(ret, HCF_SUCCESS);
    ASSERT_NE(verify, nullptr);

    ret = verify->init(verify, nullptr, ed25519KeyPair_->pubKey);
    ASSERT_EQ(ret, HCF_SUCCESS);
    bool flag = verify->verify(verify, &g_mockInput, nullptr);
    ASSERT_EQ(flag, false);

    HcfObjDestroy(verify);
}

HWTEST_F(CryptoEd25519VerifyTest, CryptoEd25519VerifyTest024, TestSize.Level0)
{
    HcfVerify *verify = nullptr;
    HcfResult ret = HcfVerifyCreate("Ed25519", &verify);
    ASSERT_EQ(ret, HCF_SUCCESS);
    ASSERT_NE(verify, nullptr);

    ret = verify->init(verify, nullptr, ed25519KeyPair_->pubKey);
    ASSERT_EQ(ret, HCF_SUCCESS);
    bool flag = verify->verify(verify, &g_mockInput, &g_mockInput);
    ASSERT_EQ(flag, false);

    HcfObjDestroy(verify);
}

HWTEST_F(CryptoEd25519VerifyTest, CryptoEd25519VerifyTest025, TestSize.Level0)
{
    HcfSign *sign = nullptr;
    HcfResult ret = HcfSignCreate("Ed25519", &sign);
    ASSERT_EQ(ret, HCF_SUCCESS);
    ASSERT_NE(sign, nullptr);

    ret = sign->init(sign, nullptr, ed25519KeyPair_->priKey);
    ASSERT_EQ(ret, HCF_SUCCESS);

    HcfBlob out = { .data = nullptr, .len = 0 };
    ret = sign->sign(sign, &g_mockInput, &out);
    ASSERT_EQ(ret, HCF_SUCCESS);
    ASSERT_NE(out.data, nullptr);
    ASSERT_NE(out.len, (const unsigned int)0);

    HcfVerify *verify = nullptr;
    ret = HcfVerifyCreate("Ed25519", &verify);
    ASSERT_EQ(ret, HCF_SUCCESS);
    ASSERT_NE(verify, nullptr);

    ret = verify->init(verify, nullptr, ed25519KeyPair_->pubKey);
    ASSERT_EQ(ret, HCF_SUCCESS);

    bool flag = verify->verify(verify, &g_mockInput, &out);
    flag = verify->verify(verify, &g_mockInput, &out);
    ASSERT_EQ(flag, true);
    ASSERT_NE(out.data, nullptr);
    ASSERT_NE(out.len, (const unsigned int)0);

    HcfFree(out.data);
    HcfObjDestroy(sign);
    HcfObjDestroy(verify);
}

HWTEST_F(CryptoEd25519VerifyTest, CryptoEd25519VerifyTest026, TestSize.Level0)
{
    HcfSign *sign = nullptr;
    HcfResult ret = HcfSignCreate("Ed25519", &sign);
    ASSERT_EQ(ret, HCF_SUCCESS);
    ASSERT_NE(sign, nullptr);

    ret = sign->init(sign, nullptr, ed25519KeyPair_->priKey);
    ASSERT_EQ(ret, HCF_SUCCESS);

    HcfBlob out = { .data = nullptr, .len = 0 };
    ret = sign->sign(sign, &g_mock64Input, &out);
    ASSERT_EQ(ret, HCF_SUCCESS);
    ASSERT_NE(out.data, nullptr);
    ASSERT_NE(out.len, (const unsigned int)0);

    HcfVerify *verify = nullptr;
    ret = HcfVerifyCreate("Ed25519", &verify);
    ASSERT_EQ(ret, HCF_SUCCESS);
    ASSERT_NE(verify, nullptr);

    ret = verify->init(verify, nullptr, ed25519KeyPair_->pubKey);
    ASSERT_EQ(ret, HCF_SUCCESS);

    bool flag = verify->verify(verify, &g_mock64Input, &out);
    ASSERT_EQ(flag, true);
    ASSERT_NE(out.data, nullptr);
    ASSERT_NE(out.len, (const unsigned int)0);

    HcfFree(out.data);
    HcfObjDestroy(sign);
    HcfObjDestroy(verify);
}
}