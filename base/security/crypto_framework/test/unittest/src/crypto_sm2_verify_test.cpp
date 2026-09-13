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
#include "sm2_openssl.h"
#include "memory.h"
#include "securec.h"
#include "signature.h"
#include "memory_mock.h"
#include "openssl_adapter_mock.h"

using namespace std;
using namespace testing::ext;

namespace {
class CryptoSm2VerifyTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp();
    void TearDown();

    static HcfKeyPair *g_sm2256KeyPair_;
};

HcfKeyPair *CryptoSm2VerifyTest::g_sm2256KeyPair_ = nullptr;

static const char *g_mockMessage = "hello world";
static HcfBlob g_mockInput = {
    .data = (uint8_t *)g_mockMessage,
    .len = 12
};

void CryptoSm2VerifyTest::SetUp() {}
void CryptoSm2VerifyTest::TearDown() {}

void CryptoSm2VerifyTest::SetUpTestCase()
{
    HcfAsyKeyGenerator *generator = nullptr;
    int32_t res = HcfAsyKeyGeneratorCreate("SM2_256", &generator);
    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(generator, nullptr);

    HcfKeyPair *keyPair = nullptr;
    res = generator->generateKeyPair(generator, nullptr, &keyPair);
    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(keyPair, nullptr);

    g_sm2256KeyPair_ = keyPair;

    HcfObjDestroy(generator);
}

void CryptoSm2VerifyTest::TearDownTestCase()
{
    HcfObjDestroy(g_sm2256KeyPair_);
}

static const char *GetMockClass(void)
{
    return "HcfMock";
}

static HcfObjectBase obj = {
    .getClass = GetMockClass,
    .destroy = nullptr
};

HWTEST_F(CryptoSm2VerifyTest, CryptoSm2VerifyTest001, TestSize.Level0)
{
    HcfVerify *verify = nullptr;
    int32_t res = HcfVerifyCreate("SM2|SM3", &verify);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(verify, nullptr);

    HcfObjDestroy(verify);
}

HWTEST_F(CryptoSm2VerifyTest, CryptoSm2VerifyTest002, TestSize.Level0)
{
    HcfVerify *verify = nullptr;
    int32_t res = HcfVerifyCreate(nullptr, &verify);

    ASSERT_EQ(res, HCF_INVALID_PARAMS);
    ASSERT_EQ(verify, nullptr);
}

HWTEST_F(CryptoSm2VerifyTest, CryptoSm2VerifyTest003, TestSize.Level0)
{
    HcfVerify *verify = nullptr;
    int32_t res = HcfVerifyCreate("ABCDABCDABCDABCDABCDABCDABCDABCDABCDABCDABCDABCDABCDABCDABCDABCDABCDABCDABCD"
        "ABCDABCDABCDABCDABCDABCDABCDABCDABCDABCDABCDABCDABCD", &verify);

    ASSERT_EQ(res, HCF_INVALID_PARAMS);
    ASSERT_EQ(verify, nullptr);
}

HWTEST_F(CryptoSm2VerifyTest, CryptoSm2VerifyTest004, TestSize.Level0)
{
    HcfVerify *verify = nullptr;
    int32_t res = HcfVerifyCreate("SM5|SM3", &verify);

    ASSERT_NE(res, HCF_SUCCESS);
    ASSERT_EQ(verify, nullptr);
}

HWTEST_F(CryptoSm2VerifyTest, CryptoSm2VerifyTest005, TestSize.Level0)
{
    HcfVerify *verify = nullptr;
    int32_t res = HcfVerifyCreate("SM2|SM5", &verify);

    ASSERT_NE(res, HCF_SUCCESS);
    ASSERT_EQ(verify, nullptr);
}

HWTEST_F(CryptoSm2VerifyTest, CryptoSm2VerifyTest006, TestSize.Level0)
{
    HcfVerify *verify = nullptr;
    int32_t res = HcfVerifyCreate("SM2|MD5", &verify);

    ASSERT_NE(res, HCF_SUCCESS);
    ASSERT_EQ(verify, nullptr);
}

HWTEST_F(CryptoSm2VerifyTest, CryptoSm2VerifyTest007, TestSize.Level0)
{
    HcfVerify *verify = nullptr;
    int32_t res = HcfVerifyCreate("SM2SM3", &verify);

    ASSERT_NE(res, HCF_SUCCESS);
    ASSERT_EQ(verify, nullptr);
}

HWTEST_F(CryptoSm2VerifyTest, CryptoSm2VerifyTest008, TestSize.Level0)
{
    int32_t res = HcfVerifyCreate("SM2|SM3", nullptr);

    ASSERT_EQ(res, HCF_INVALID_PARAMS);
}

HWTEST_F(CryptoSm2VerifyTest, CryptoSm2VerifyTest009, TestSize.Level0)
{
    HcfVerify *verify = nullptr;
    int32_t res = HcfVerifyCreate("SM2|SM3", &verify);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(verify, nullptr);

    const char *className = verify->base.getClass();

    ASSERT_NE(className, nullptr);

    HcfObjDestroy(verify);
}

HWTEST_F(CryptoSm2VerifyTest, CryptoSm2VerifyTest010, TestSize.Level0)
{
    HcfVerify *verify = nullptr;
    int32_t res = HcfVerifyCreate("SM2|SM3", &verify);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(verify, nullptr);

    verify->base.destroy((HcfObjectBase *)verify);
}

HWTEST_F(CryptoSm2VerifyTest, CryptoSm2VerifyTest011, TestSize.Level0)
{
    HcfVerify *verify = nullptr;
    int32_t res = HcfVerifyCreate("SM2|SM3", &verify);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(verify, nullptr);

    verify->base.destroy(nullptr);

    HcfObjDestroy(verify);
}

HWTEST_F(CryptoSm2VerifyTest, CryptoSm2VerifyTest012, TestSize.Level0)
{
    HcfVerify *verify = nullptr;
    int32_t res = HcfVerifyCreate("SM2|SM3", &verify);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(verify, nullptr);

    verify->base.destroy(&obj);

    HcfObjDestroy(verify);
}

HWTEST_F(CryptoSm2VerifyTest, CryptoSm2VerifyTest013, TestSize.Level0)
{
    HcfVerify *verify = nullptr;
    int32_t res = HcfVerifyCreate("SM2|SM3", &verify);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(verify, nullptr);

    const char *algName = verify->getAlgoName(verify);

    ASSERT_NE(algName, nullptr);

    HcfObjDestroy(verify);
}

HWTEST_F(CryptoSm2VerifyTest, CryptoSm2VerifyTest014, TestSize.Level0)
{
    HcfVerify *verify = nullptr;
    int32_t res = HcfVerifyCreate("SM2|SM3", &verify);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(verify, nullptr);

    const char *algName = verify->getAlgoName(nullptr);

    ASSERT_EQ(algName, nullptr);

    HcfObjDestroy(verify);
}

HWTEST_F(CryptoSm2VerifyTest, CryptoSm2VerifyTest015, TestSize.Level0)
{
    HcfVerify *verify = nullptr;
    int32_t res = HcfVerifyCreate("SM2|SM3", &verify);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(verify, nullptr);

    res = verify->init(verify, nullptr, g_sm2256KeyPair_->pubKey);

    ASSERT_EQ(res, HCF_SUCCESS);

    HcfObjDestroy(verify);
}

HWTEST_F(CryptoSm2VerifyTest, CryptoSm2VerifyTest016, TestSize.Level0)
{
    HcfVerify *verify = nullptr;
    int32_t res = HcfVerifyCreate("SM2|SM3", &verify);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(verify, nullptr);

    res = verify->init(nullptr, nullptr, g_sm2256KeyPair_->pubKey);

    ASSERT_EQ(res, HCF_INVALID_PARAMS);

    HcfObjDestroy(verify);
}

HWTEST_F(CryptoSm2VerifyTest, CryptoSm2VerifyTest017, TestSize.Level0)
{
    HcfVerify *verify = nullptr;
    int32_t res = HcfVerifyCreate("SM2|SM3", &verify);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(verify, nullptr);

    res = verify->init(verify, nullptr, g_sm2256KeyPair_->pubKey);

    ASSERT_EQ(res, HCF_SUCCESS);

    res = verify->init(verify, nullptr, g_sm2256KeyPair_->pubKey);

    ASSERT_EQ(res, HCF_INVALID_PARAMS);

    HcfObjDestroy(verify);
}

HWTEST_F(CryptoSm2VerifyTest, CryptoSm2VerifyTest018, TestSize.Level0)
{
    HcfVerify *verify = nullptr;
    int32_t res = HcfVerifyCreate("SM2|SM3", &verify);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(verify, nullptr);

    res = verify->init(verify, nullptr, nullptr);

    ASSERT_EQ(res, HCF_INVALID_PARAMS);

    HcfObjDestroy(verify);
}

HWTEST_F(CryptoSm2VerifyTest, CryptoSm2VerifyTest019, TestSize.Level0)
{
    HcfVerify *verify = nullptr;
    int32_t res = HcfVerifyCreate("SM2|SM3", &verify);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(verify, nullptr);

    res = verify->init(verify, nullptr, g_sm2256KeyPair_->pubKey);

    ASSERT_EQ(res, HCF_SUCCESS);

    res = verify->update(verify, &g_mockInput);

    ASSERT_EQ(res, HCF_SUCCESS);

    HcfObjDestroy(verify);
}

HWTEST_F(CryptoSm2VerifyTest, CryptoSm2VerifyTest020, TestSize.Level0)
{
    HcfVerify *verify = nullptr;
    int32_t res = HcfVerifyCreate("SM2|SM3", &verify);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(verify, nullptr);

    res = verify->init(verify, nullptr, g_sm2256KeyPair_->pubKey);

    ASSERT_EQ(res, HCF_SUCCESS);

    res = verify->update(nullptr, &g_mockInput);

    ASSERT_EQ(res, HCF_INVALID_PARAMS);

    HcfObjDestroy(verify);
}

HWTEST_F(CryptoSm2VerifyTest, CryptoSm2VerifyTest021, TestSize.Level0)
{
    HcfVerify *verify = nullptr;
    int32_t res = HcfVerifyCreate("SM2|SM3", &verify);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(verify, nullptr);

    res = verify->update(verify, &g_mockInput);

    ASSERT_EQ(res, HCF_INVALID_PARAMS);

    HcfObjDestroy(verify);
}

HWTEST_F(CryptoSm2VerifyTest, CryptoSm2VerifyTest022, TestSize.Level0)
{
    HcfVerify *verify = nullptr;
    int32_t res = HcfVerifyCreate("SM2|SM3", &verify);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(verify, nullptr);

    res = verify->init(verify, nullptr, g_sm2256KeyPair_->pubKey);

    ASSERT_EQ(res, HCF_SUCCESS);

    res = verify->update(verify, nullptr);

    ASSERT_EQ(res, HCF_INVALID_PARAMS);

    HcfObjDestroy(verify);
}

HWTEST_F(CryptoSm2VerifyTest, CryptoSm2VerifyTest023, TestSize.Level0)
{
    HcfVerify *verify = nullptr;
    int32_t res = HcfVerifyCreate("SM2|SM3", &verify);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(verify, nullptr);

    res = verify->init(verify, nullptr, g_sm2256KeyPair_->pubKey);

    ASSERT_EQ(res, HCF_SUCCESS);

    HcfBlob input = {
        .data = nullptr,
        .len = 1
    };
    res = verify->update(verify, &input);

    ASSERT_EQ(res, HCF_INVALID_PARAMS);

    HcfObjDestroy(verify);
}

HWTEST_F(CryptoSm2VerifyTest, CryptoSm2VerifyTest024, TestSize.Level0)
{
    HcfVerify *verify = nullptr;
    int32_t res = HcfVerifyCreate("SM2|SM3", &verify);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(verify, nullptr);

    res = verify->init(verify, nullptr, g_sm2256KeyPair_->pubKey);

    ASSERT_EQ(res, HCF_SUCCESS);

    HcfBlob input = {
        .data = (uint8_t *)g_mockMessage,
        .len = 0
    };
    res = verify->update(verify, &input);

    ASSERT_EQ(res, HCF_INVALID_PARAMS);

    HcfObjDestroy(verify);
}

HWTEST_F(CryptoSm2VerifyTest, CryptoSm2VerifyTest025, TestSize.Level0)
{
    HcfSign *sign = nullptr;
    int32_t res = HcfSignCreate("SM2|SM3", &sign);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(sign, nullptr);

    res = sign->init(sign, nullptr, g_sm2256KeyPair_->priKey);

    ASSERT_EQ(res, HCF_SUCCESS);

    res = sign->update(sign, &g_mockInput);

    ASSERT_EQ(res, HCF_SUCCESS);

    HcfBlob out = { .data = nullptr, .len = 0 };
    res = sign->sign(sign, nullptr, &out);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(out.data, nullptr);
    ASSERT_NE(out.len, (const unsigned int)0);

    HcfVerify *verify = nullptr;
    res = HcfVerifyCreate("SM2|SM3", &verify);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(verify, nullptr);

    res = verify->init(verify, nullptr, g_sm2256KeyPair_->pubKey);

    ASSERT_EQ(res, HCF_SUCCESS);

    res = verify->update(verify, &g_mockInput);

    ASSERT_EQ(res, HCF_SUCCESS);

    bool flag = verify->verify(verify, nullptr, &out);

    ASSERT_EQ(flag, true);

    HcfFree(out.data);
    HcfObjDestroy(sign);
    HcfObjDestroy(verify);
}

HWTEST_F(CryptoSm2VerifyTest, CryptoSm2VerifyTest026, TestSize.Level0)
{
    HcfSign *sign = nullptr;
    int32_t res = HcfSignCreate("SM2|SM3", &sign);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(sign, nullptr);

    res = sign->init(sign, nullptr, g_sm2256KeyPair_->priKey);

    ASSERT_EQ(res, HCF_SUCCESS);

    HcfBlob out = { .data = nullptr, .len = 0 };
    res = sign->sign(sign, &g_mockInput, &out);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(out.data, nullptr);
    ASSERT_NE(out.len, (const unsigned int)0);

    HcfVerify *verify = nullptr;
    res = HcfVerifyCreate("SM2|SM3", &verify);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(verify, nullptr);

    res = verify->init(verify, nullptr, g_sm2256KeyPair_->pubKey);

    ASSERT_EQ(res, HCF_SUCCESS);

    bool flag = verify->verify(verify, &g_mockInput, &out);

    ASSERT_EQ(flag, true);

    HcfFree(out.data);
    HcfObjDestroy(sign);
    HcfObjDestroy(verify);
}

HWTEST_F(CryptoSm2VerifyTest, CryptoSm2VerifyTest027, TestSize.Level0)
{
    HcfSign *sign = nullptr;
    int32_t res = HcfSignCreate("SM2|SM3", &sign);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(sign, nullptr);

    res = sign->init(sign, nullptr, g_sm2256KeyPair_->priKey);

    ASSERT_EQ(res, HCF_SUCCESS);

    res = sign->update(sign, &g_mockInput);

    ASSERT_EQ(res, HCF_SUCCESS);

    HcfBlob out = { .data = nullptr, .len = 0 };
    res = sign->sign(sign, nullptr, &out);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(out.data, nullptr);
    ASSERT_NE(out.len, (const unsigned int)0);

    HcfVerify *verify = nullptr;
    res = HcfVerifyCreate("SM2|SM3", &verify);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(verify, nullptr);

    res = verify->init(verify, nullptr, g_sm2256KeyPair_->pubKey);

    ASSERT_EQ(res, HCF_SUCCESS);

    res = verify->update(verify, &g_mockInput);

    ASSERT_EQ(res, HCF_SUCCESS);

    bool flag = verify->verify(nullptr, nullptr, &out);

    ASSERT_EQ(flag, false);

    HcfFree(out.data);
    HcfObjDestroy(sign);
    HcfObjDestroy(verify);
}

HWTEST_F(CryptoSm2VerifyTest, CryptoSm2VerifyTest028, TestSize.Level0)
{
    HcfSign *sign = nullptr;
    int32_t res = HcfSignCreate("SM2|SM3", &sign);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(sign, nullptr);

    res = sign->init(sign, nullptr, g_sm2256KeyPair_->priKey);

    ASSERT_EQ(res, HCF_SUCCESS);

    res = sign->update(sign, &g_mockInput);

    ASSERT_EQ(res, HCF_SUCCESS);

    HcfBlob out = { .data = nullptr, .len = 0 };
    res = sign->sign(sign, nullptr, &out);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(out.data, nullptr);
    ASSERT_NE(out.len, (const unsigned int)0);

    HcfVerify *verify = nullptr;
    res = HcfVerifyCreate("SM2|SM3", &verify);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(verify, nullptr);

    res = verify->init(verify, nullptr, g_sm2256KeyPair_->pubKey);

    ASSERT_EQ(res, HCF_SUCCESS);

    res = verify->update(verify, &g_mockInput);

    ASSERT_EQ(res, HCF_SUCCESS);

    bool flag = verify->verify((HcfVerify *)(&obj), nullptr, &out);

    ASSERT_EQ(flag, false);

    HcfFree(out.data);
    HcfObjDestroy(sign);
    HcfObjDestroy(verify);
}

HWTEST_F(CryptoSm2VerifyTest, CryptoSm2VerifyTest029, TestSize.Level0)
{
    HcfSign *sign = nullptr;
    int32_t res = HcfSignCreate("SM2|SM3", &sign);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(sign, nullptr);

    res = sign->init(sign, nullptr, g_sm2256KeyPair_->priKey);

    ASSERT_EQ(res, HCF_SUCCESS);

    res = sign->update(sign, &g_mockInput);

    ASSERT_EQ(res, HCF_SUCCESS);

    HcfBlob out = { .data = nullptr, .len = 0 };
    res = sign->sign(sign, nullptr, &out);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(out.data, nullptr);
    ASSERT_NE(out.len, (const unsigned int)0);

    HcfVerify *verify = nullptr;
    res = HcfVerifyCreate("SM2|SM3", &verify);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(verify, nullptr);

    res = verify->init(verify, nullptr, g_sm2256KeyPair_->pubKey);

    ASSERT_EQ(res, HCF_SUCCESS);

    bool flag = verify->verify(verify, nullptr, &out);

    ASSERT_EQ(flag, false);

    HcfFree(out.data);
    HcfObjDestroy(sign);
    HcfObjDestroy(verify);
}

HWTEST_F(CryptoSm2VerifyTest, CryptoSm2VerifyTest030, TestSize.Level0)
{
    HcfSign *sign = nullptr;
    int32_t res = HcfSignCreate("SM2|SM3", &sign);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(sign, nullptr);

    res = sign->init(sign, nullptr, g_sm2256KeyPair_->priKey);

    ASSERT_EQ(res, HCF_SUCCESS);

    res = sign->update(sign, &g_mockInput);

    ASSERT_EQ(res, HCF_SUCCESS);

    HcfBlob out = { .data = nullptr, .len = 0 };
    res = sign->sign(sign, nullptr, &out);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(out.data, nullptr);
    ASSERT_NE(out.len, (const unsigned int)0);

    HcfVerify *verify = nullptr;
    res = HcfVerifyCreate("SM2|SM3", &verify);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(verify, nullptr);

    res = verify->init(verify, nullptr, g_sm2256KeyPair_->pubKey);

    ASSERT_EQ(res, HCF_SUCCESS);

    HcfBlob input = {
        .data = nullptr,
        .len = 1
    };
    bool flag = verify->verify(verify, &input, &out);

    ASSERT_EQ(flag, false);

    HcfFree(out.data);
    HcfObjDestroy(sign);
    HcfObjDestroy(verify);
}

HWTEST_F(CryptoSm2VerifyTest, CryptoSm2VerifyTest031, TestSize.Level0)
{
    HcfSign *sign = nullptr;
    int32_t res = HcfSignCreate("SM2|SM3", &sign);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(sign, nullptr);

    res = sign->init(sign, nullptr, g_sm2256KeyPair_->priKey);

    ASSERT_EQ(res, HCF_SUCCESS);

    res = sign->update(sign, &g_mockInput);

    ASSERT_EQ(res, HCF_SUCCESS);

    HcfBlob out = { .data = nullptr, .len = 0 };
    res = sign->sign(sign, nullptr, &out);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(out.data, nullptr);
    ASSERT_NE(out.len, (const unsigned int)0);

    HcfVerify *verify = nullptr;
    res = HcfVerifyCreate("SM2|SM3", &verify);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(verify, nullptr);

    res = verify->init(verify, nullptr, g_sm2256KeyPair_->pubKey);

    ASSERT_EQ(res, HCF_SUCCESS);

    HcfBlob input = {
        .data = (uint8_t *)g_mockMessage,
        .len = 0
    };
    bool flag = verify->verify(verify, &input, &out);

    ASSERT_EQ(flag, false);

    HcfFree(out.data);
    HcfObjDestroy(sign);
    HcfObjDestroy(verify);
}

HWTEST_F(CryptoSm2VerifyTest, CryptoSm2VerifyTest032, TestSize.Level0)
{
    HcfVerify *verify = nullptr;
    int32_t res = HcfVerifyCreate("SM2|SM3", &verify);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(verify, nullptr);

    res = verify->init(verify, nullptr, g_sm2256KeyPair_->pubKey);

    ASSERT_EQ(res, HCF_SUCCESS);

    res = verify->update(verify, &g_mockInput);

    ASSERT_EQ(res, HCF_SUCCESS);

    bool flag = verify->verify(verify, nullptr, nullptr);

    ASSERT_EQ(flag, false);

    HcfObjDestroy(verify);
}

HWTEST_F(CryptoSm2VerifyTest, CryptoSm2VerifyTest033, TestSize.Level0)
{
    HcfVerify *verify = nullptr;
    int32_t res = HcfVerifyCreate("SM2|SM3", &verify);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(verify, nullptr);

    res = verify->init(verify, nullptr, g_sm2256KeyPair_->pubKey);

    ASSERT_EQ(res, HCF_SUCCESS);

    res = verify->update(verify, &g_mockInput);

    ASSERT_EQ(res, HCF_SUCCESS);

    HcfBlob mockOut = {
        .data = nullptr,
        .len = 1
    };
    bool flag = verify->verify(verify, nullptr, &mockOut);

    ASSERT_EQ(flag, false);

    HcfObjDestroy(verify);
}

HWTEST_F(CryptoSm2VerifyTest, CryptoSm2VerifyTest034, TestSize.Level0)
{
    HcfVerify *verify = nullptr;
    int32_t res = HcfVerifyCreate("SM2|SM3", &verify);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(verify, nullptr);

    res = verify->init(verify, nullptr, g_sm2256KeyPair_->pubKey);

    ASSERT_EQ(res, HCF_SUCCESS);

    res = verify->update(verify, &g_mockInput);

    ASSERT_EQ(res, HCF_SUCCESS);

    HcfBlob mockOut = {
        .data = (uint8_t *)g_mockMessage,
        .len = 0
    };
    bool flag = verify->verify(verify, nullptr, &mockOut);

    ASSERT_EQ(flag, false);

    HcfObjDestroy(verify);
}

HWTEST_F(CryptoSm2VerifyTest, CryptoSm2VerifyTest035, TestSize.Level0)
{
    HcfVerifySpi *spiObj = nullptr;
    int32_t res = HcfVerifySpiSm2Create(nullptr, &spiObj);

    ASSERT_EQ(res, HCF_INVALID_PARAMS);
    ASSERT_EQ(spiObj, nullptr);
}

HWTEST_F(CryptoSm2VerifyTest, CryptoSm2VerifyTest036, TestSize.Level0)
{
    HcfSignatureParams params = {
        .algo = HCF_ALG_SM2,
        .md = HCF_OPENSSL_DIGEST_SM3,
    };
    int32_t res = HcfVerifySpiSm2Create(&params, nullptr);

    ASSERT_EQ(res, HCF_INVALID_PARAMS);
}

HWTEST_F(CryptoSm2VerifyTest, CryptoSm2VerifyTest037, TestSize.Level0)
{
    HcfSignatureParams params = {
        .algo = HCF_ALG_SM2,
        .md = HCF_OPENSSL_DIGEST_SM3,
    };
    HcfVerifySpi *spiObj = nullptr;
    int32_t res = HcfVerifySpiSm2Create(&params, &spiObj);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(spiObj, nullptr);

    const char *message = "hello world";
    HcfBlob input = {
        .data = (uint8_t *)message,
        .len = 12
    };
    res = spiObj->engineUpdate(nullptr, &input);
    ASSERT_EQ(res, HCF_INVALID_PARAMS);

    HcfObjDestroy(spiObj);
}

HWTEST_F(CryptoSm2VerifyTest, CryptoSm2VerifyTest038, TestSize.Level0)
{
    HcfSignatureParams params = {
        .algo = HCF_ALG_SM2,
        .md = HCF_OPENSSL_DIGEST_SM3,
    };
    HcfVerifySpi *spiObj = nullptr;
    int32_t res = HcfVerifySpiSm2Create(&params, &spiObj);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(spiObj, nullptr);

    res = spiObj->engineUpdate(spiObj, nullptr);
    ASSERT_EQ(res, HCF_INVALID_PARAMS);

    HcfObjDestroy(spiObj);
}

HWTEST_F(CryptoSm2VerifyTest, CryptoSm2VerifyTest039, TestSize.Level0)
{
    HcfSignatureParams params = {
        .algo = HCF_ALG_SM2,
        .md = HCF_OPENSSL_DIGEST_SM3,
    };
    HcfVerifySpi *spiObj = nullptr;
    int32_t res = HcfVerifySpiSm2Create(&params, &spiObj);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(spiObj, nullptr);

    const char *message = "hello world";
    HcfBlob input = {
        .data = (uint8_t *)message,
        .len = 12
    };
    HcfBlob out = { .data = nullptr, .len = 0 };
    bool isOk = spiObj->engineVerify(nullptr, &input, &out);
    ASSERT_EQ(isOk, false);

    HcfObjDestroy(spiObj);
}

HWTEST_F(CryptoSm2VerifyTest, CryptoSm2VerifyTest040, TestSize.Level0)
{
    HcfSignatureParams params = {
        .algo = HCF_ALG_SM2,
        .md = HCF_OPENSSL_DIGEST_SM3,
    };
    HcfVerifySpi *spiObj = nullptr;
    int32_t res = HcfVerifySpiSm2Create(&params, &spiObj);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(spiObj, nullptr);

    spiObj->base.destroy(nullptr);

    HcfObjDestroy(spiObj);
}

static bool GetSignTestData(HcfBlob *out)
{
    HcfSign *sign = nullptr;
    int32_t res = HcfSignCreate("SM2|SM3", &sign);
    if (res != HCF_SUCCESS) {
        return false;
    }
    res = sign->init(sign, nullptr, CryptoSm2VerifyTest::g_sm2256KeyPair_->priKey);
    if (res != HCF_SUCCESS) {
        HcfObjDestroy(sign);
        return false;
    }
    res = sign->update(sign, &g_mockInput);
    if (res != HCF_SUCCESS) {
        HcfObjDestroy(sign);
        return false;
    }
    res = sign->sign(sign, &g_mockInput, out);
    HcfObjDestroy(sign);
    return res == HCF_SUCCESS;
}

static void MemoryMockTestFunc(uint32_t mallocCount, HcfBlob *out)
{
    for (int i = 0; i < mallocCount; i++) {
        ResetRecordMallocNum();
        SetMockMallocIndex(i);
        HcfVerify *verify = nullptr;
        int32_t res = HcfVerifyCreate("SM2|SM3", &verify);
        if (res != HCF_SUCCESS) {
            continue;
        }
        res = verify->init(verify, nullptr, CryptoSm2VerifyTest::g_sm2256KeyPair_->pubKey);
        if (res != HCF_SUCCESS) {
            HcfObjDestroy(verify);
            continue;
        }
        res = verify->update(verify, &g_mockInput);
        if (res != HCF_SUCCESS) {
            HcfObjDestroy(verify);
            continue;
        }
        (void)verify->verify(verify, nullptr, out);
        HcfObjDestroy(verify);
    }
}

HWTEST_F(CryptoSm2VerifyTest, CryptoSm2VerifyTest041, TestSize.Level0)
{
    HcfBlob out = { .data = nullptr, .len = 0 };
    GetSignTestData(&out);
    StartRecordMallocNum();

    HcfVerify *verify = nullptr;
    int32_t res = HcfVerifyCreate("SM2|SM3", &verify);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(verify, nullptr);

    res = verify->init(verify, nullptr, g_sm2256KeyPair_->pubKey);

    ASSERT_EQ(res, HCF_SUCCESS);

    res = verify->update(verify, &g_mockInput);

    ASSERT_EQ(res, HCF_SUCCESS);

    bool flag = verify->verify(verify, &g_mockInput, &out);

    ASSERT_EQ(flag, true);
    HcfObjDestroy(verify);

    uint32_t mallocCount = GetMallocNum();
    MemoryMockTestFunc(mallocCount, &out);
    EndRecordMallocNum();
    HcfBlobDataFree(&out);
}

static void OpensslMockTestFunc(uint32_t mallocCount, HcfBlob *out)
{
    for (int i = 0; i < mallocCount; i++) {
        ResetOpensslCallNum();
        SetOpensslCallMockIndex(i);
        HcfVerify *verify = nullptr;
        int32_t res = HcfVerifyCreate("SM2|SM3", &verify);
        if (res != HCF_SUCCESS) {
            continue;
        }
        res = verify->init(verify, nullptr, CryptoSm2VerifyTest::g_sm2256KeyPair_->pubKey);
        if (res != HCF_SUCCESS) {
            HcfObjDestroy(verify);
            continue;
        }
        uint8_t pSourceData[] = "1234567812345678\0";
        HcfBlob pSource = {.data = (uint8_t *)pSourceData, .len = strlen((char *)pSourceData)};
        res = verify->setVerifySpecUint8Array(verify, SM2_USER_ID_UINT8ARR, pSource);
        if (res != HCF_SUCCESS) {
            HcfObjDestroy(verify);
            continue;
        }
        res = verify->update(verify, &g_mockInput);
        if (res != HCF_SUCCESS) {
            HcfObjDestroy(verify);
            continue;
        }
        (void)verify->verify(verify, &g_mockInput, out);
        HcfObjDestroy(verify);
    }
}

HWTEST_F(CryptoSm2VerifyTest, CryptoSm2VerifyTest042, TestSize.Level0)
{
    HcfBlob out = { .data = nullptr, .len = 0 };
    ASSERT_EQ(GetSignTestData(&out), true);
    StartRecordOpensslCallNum();

    HcfVerify *verify = nullptr;
    int32_t res = HcfVerifyCreate("SM2|SM3", &verify);
    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(verify, nullptr);

    uint8_t pSourceData[] = "1234567812345678\0";
    HcfBlob pSource = {.data = (uint8_t *)pSourceData, .len = strlen((char *)pSourceData)};
    res = verify->setVerifySpecUint8Array(verify, SM2_USER_ID_UINT8ARR, pSource);
    ASSERT_EQ(res, HCF_SUCCESS);

    res = verify->init(verify, nullptr, g_sm2256KeyPair_->pubKey);
    ASSERT_EQ(res, HCF_SUCCESS);

    res = verify->update(verify, &g_mockInput);
    ASSERT_EQ(res, HCF_SUCCESS);

    bool flag = verify->verify(verify, &g_mockInput, &out);
    ASSERT_EQ(flag, true);
    HcfObjDestroy(verify);

    uint32_t mallocCount = GetOpensslCallNum();
    OpensslMockTestFunc(mallocCount, &out);
    EndRecordOpensslCallNum();
    HcfBlobDataFree(&out);
}

HWTEST_F(CryptoSm2VerifyTest, CryptoSm2VerifyTest043, TestSize.Level0)
{
    HcfVerify *verify = nullptr;
    int32_t res = HcfVerifyCreate("SM2|SM3", &verify);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(verify, nullptr);

    uint8_t pSourceData[] = "1234567812345678\0";
    HcfBlob pSource = {.data = (uint8_t *)pSourceData, .len = strlen((char *)pSourceData)};
    res = verify->setVerifySpecUint8Array(verify, SM2_USER_ID_UINT8ARR, pSource);

    ASSERT_EQ(res, HCF_SUCCESS);

    HcfObjDestroy(verify);
}

HWTEST_F(CryptoSm2VerifyTest, CryptoSm2VerifyTest044, TestSize.Level0)
{
    HcfVerify *verify = nullptr;
    int32_t res = HcfVerifyCreate("SM2|SM3", &verify);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(verify, nullptr);

    HcfBlob pSource = {.data = nullptr, .len = 0};
    res = verify->setVerifySpecUint8Array(verify, SM2_USER_ID_UINT8ARR, pSource);

    ASSERT_EQ(res, HCF_SUCCESS);

    HcfObjDestroy(verify);
}

HWTEST_F(CryptoSm2VerifyTest, CryptoSm2VerifyTest045, TestSize.Level0)
{
    HcfVerify *verify = nullptr;
    int32_t res = HcfVerifyCreate("SM2|SM3", &verify);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(verify, nullptr);

    uint8_t pSourceData[] = "1234567812345678\0";
    HcfBlob pSource = {.data = (uint8_t *)pSourceData, .len = strlen((char *)pSourceData)};
    res = verify->setVerifySpecUint8Array(nullptr, SM2_USER_ID_UINT8ARR, pSource);

    ASSERT_EQ(res, HCF_INVALID_PARAMS);

    HcfObjDestroy(verify);
}

HWTEST_F(CryptoSm2VerifyTest, CryptoSm2VerifyTest046, TestSize.Level0)
{
    HcfVerify *verify = nullptr;
    int32_t res = HcfVerifyCreate("SM2|SM3", &verify);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(verify, nullptr);

    uint8_t pSourceData[] = "1234567812345678\0";
    HcfBlob pSource = {.data = (uint8_t *)pSourceData, .len = strlen((char *)pSourceData)};
    res = verify->setVerifySpecUint8Array(verify, PSS_SALT_LEN_INT, pSource);

    ASSERT_EQ(res, HCF_INVALID_PARAMS);

    HcfObjDestroy(verify);
}

HWTEST_F(CryptoSm2VerifyTest, CryptoSm2VerifyTest047, TestSize.Level0)
{
    HcfVerify *verify = nullptr;
    int32_t res = HcfVerifyCreate("SM2|SM3", &verify);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(verify, nullptr);

    res = verify->init(verify, nullptr, g_sm2256KeyPair_->pubKey);
    ASSERT_EQ(res, HCF_SUCCESS);

    uint8_t pSourceData[] = "1234567812345678\0";
    HcfBlob pSource = {.data = (uint8_t *)pSourceData, .len = strlen((char *)pSourceData)};
    res = verify->setVerifySpecUint8Array(verify, SM2_USER_ID_UINT8ARR, pSource);

    ASSERT_EQ(res, HCF_SUCCESS);

    HcfObjDestroy(verify);
}

HWTEST_F(CryptoSm2VerifyTest, CryptoSm2VerifyTest048, TestSize.Level0)
{
    HcfVerify *verify = nullptr;
    int32_t res = HcfVerifyCreate("SM2|SM3", &verify);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(verify, nullptr);

    res = verify->init(verify, nullptr, g_sm2256KeyPair_->pubKey);
    ASSERT_EQ(res, HCF_SUCCESS);

    HcfBlob pSource = {.data = nullptr, .len = 0};
    res = verify->setVerifySpecUint8Array(verify, SM2_USER_ID_UINT8ARR, pSource);

    ASSERT_EQ(res, HCF_SUCCESS);

    HcfObjDestroy(verify);
}

HWTEST_F(CryptoSm2VerifyTest, CryptoSm2VerifyTest049, TestSize.Level0)
{
    HcfVerify *verify = nullptr;
    int32_t res = HcfVerifyCreate("SM2|SM3", &verify);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(verify, nullptr);

    res = verify->init(verify, nullptr, g_sm2256KeyPair_->pubKey);
    ASSERT_EQ(res, HCF_SUCCESS);

    uint8_t pSourceData[] = "1234567812345678\0";
    HcfBlob pSource = {.data = (uint8_t *)pSourceData, .len = strlen((char *)pSourceData)};
    res = verify->setVerifySpecUint8Array(nullptr, SM2_USER_ID_UINT8ARR, pSource);

    ASSERT_NE(res, HCF_SUCCESS);

    HcfObjDestroy(verify);
}

HWTEST_F(CryptoSm2VerifyTest, CryptoSm2VerifyTest050, TestSize.Level0)
{
    HcfVerify *verify = nullptr;
    int32_t res = HcfVerifyCreate("SM2|SM3", &verify);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(verify, nullptr);

    res = verify->init(verify, nullptr, g_sm2256KeyPair_->pubKey);
    ASSERT_EQ(res, HCF_SUCCESS);

    uint8_t pSourceData[] = "1234567812345678\0";
    HcfBlob pSource = {.data = (uint8_t *)pSourceData, .len = strlen((char *)pSourceData)};
    res = verify->setVerifySpecUint8Array(verify, PSS_SALT_LEN_INT, pSource);

    ASSERT_NE(res, HCF_SUCCESS);

    HcfObjDestroy(verify);
}

HWTEST_F(CryptoSm2VerifyTest, CryptoSm2VerifyTest051, TestSize.Level0)
{
    HcfVerify *verify = nullptr;
    int32_t res = HcfVerifyCreate("SM2|SM3", &verify);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(verify, nullptr);

    res = verify->init(verify, nullptr, g_sm2256KeyPair_->pubKey);
    ASSERT_EQ(res, HCF_SUCCESS);

    int32_t saltlen = 0;
    res = verify->setVerifySpecInt(verify, PSS_SALT_LEN_INT, saltlen);

    ASSERT_EQ(res, HCF_NOT_SUPPORT);

    HcfObjDestroy(verify);
}

HWTEST_F(CryptoSm2VerifyTest, CryptoSm2VerifyTest052, TestSize.Level0)
{
    HcfVerify *verify = nullptr;
    int32_t res = HcfVerifyCreate("SM2|SM3", &verify);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(verify, nullptr);

    res = verify->init(verify, nullptr, g_sm2256KeyPair_->pubKey);
    ASSERT_EQ(res, HCF_SUCCESS);

    int32_t *returnInt = nullptr;
    res = verify->getVerifySpecInt(verify, PSS_SALT_LEN_INT, returnInt);

    ASSERT_EQ(res, HCF_INVALID_PARAMS);

    HcfObjDestroy(verify);
}

HWTEST_F(CryptoSm2VerifyTest, CryptoSm2VerifyTest053, TestSize.Level0)
{
    HcfVerify *verify = nullptr;
    int32_t res = HcfVerifyCreate("SM2|SM3", &verify);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(verify, nullptr);

    res = verify->init(verify, nullptr, g_sm2256KeyPair_->pubKey);
    ASSERT_EQ(res, HCF_SUCCESS);

    int32_t returnInt = 0;
    res = verify->getVerifySpecInt(verify, PSS_SALT_LEN_INT, &returnInt);

    ASSERT_EQ(res, HCF_NOT_SUPPORT);

    HcfObjDestroy(verify);
}

HWTEST_F(CryptoSm2VerifyTest, CryptoSm2VerifyTest054, TestSize.Level0)
{
    HcfVerify *verify = nullptr;
    int32_t res = HcfVerifyCreate("SM2|SM3", &verify);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(verify, nullptr);

    res = verify->init(verify, nullptr, g_sm2256KeyPair_->pubKey);
    ASSERT_EQ(res, HCF_SUCCESS);

    char *returnStr = nullptr;
    res = verify->getVerifySpecString(verify, SM2_USER_ID_UINT8ARR, &returnStr);

    ASSERT_EQ(res, HCF_NOT_SUPPORT);

    HcfObjDestroy(verify);
}

HWTEST_F(CryptoSm2VerifyTest, CryptoSm2VerifyTest055, TestSize.Level0)
{
    HcfVerify *verify = nullptr;
    int32_t res = HcfVerifyCreate("SM2|SM3", &verify);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(verify, nullptr);

    res = verify->init(verify, nullptr, g_sm2256KeyPair_->pubKey);
    ASSERT_EQ(res, HCF_SUCCESS);

    res = verify->getVerifySpecString(verify, SM2_USER_ID_UINT8ARR, nullptr);

    ASSERT_EQ(res, HCF_INVALID_PARAMS);

    HcfObjDestroy(verify);
}

HWTEST_F(CryptoSm2VerifyTest, CryptoSm2VerifyTest056, TestSize.Level0)
{
    HcfVerify *verify = nullptr;
    int32_t res = HcfVerifyCreate("SM2|SM3", &verify);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(verify, nullptr);

    res = verify->init(verify, nullptr, g_sm2256KeyPair_->pubKey);
    ASSERT_EQ(res, HCF_SUCCESS);

    char *returnStr = nullptr;
    res = verify->getVerifySpecString(nullptr, SM2_USER_ID_UINT8ARR, &returnStr);

    ASSERT_NE(res, HCF_SUCCESS);

    HcfObjDestroy(verify);
}

HWTEST_F(CryptoSm2VerifyTest, CryptoSm2VerifyTest057, TestSize.Level0)
{
    HcfVerify *verify = nullptr;
    int32_t res = HcfVerifyCreate("SM2|SM3", &verify);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(verify, nullptr);

    res = verify->init(verify, nullptr, g_sm2256KeyPair_->pubKey);
    ASSERT_EQ(res, HCF_SUCCESS);

    char *returnStr = nullptr;
    res = verify->getVerifySpecString(verify, PSS_MD_NAME_STR, &returnStr);

    ASSERT_EQ(res, HCF_NOT_SUPPORT);

    HcfObjDestroy(verify);
}

HWTEST_F(CryptoSm2VerifyTest, CryptoSm2VerifyTest058, TestSize.Level0)
{
    HcfSignatureParams params = {
        .algo = HCF_ALG_SM2,
        .md = HCF_OPENSSL_DIGEST_SM3,
    };
    HcfVerifySpi *spiObj = nullptr;
    int32_t res = HcfVerifySpiSm2Create(&params, &spiObj);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(spiObj, nullptr);
    uint8_t pSourceData[] = "1234567812345678\0";
    HcfBlob pSource = {.data = (uint8_t *)pSourceData, .len = strlen((char *)pSourceData)};
    res = spiObj->engineSetVerifySpecUint8Array(nullptr, SM2_USER_ID_UINT8ARR, pSource);
    ASSERT_EQ(res, HCF_INVALID_PARAMS);

    HcfObjDestroy(spiObj);
}

// Test verify signData from third-Party
HWTEST_F(CryptoSm2VerifyTest, CryptoSm2VerifyTest059, TestSize.Level0)
{
    uint8_t pk[] = {
        0x30, 0x59, 0x30, 0x13, 0x06, 0x07, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x02, 0x01, 0x06, 0x08, 0x2A,
        0x81, 0x1C, 0xCF, 0x55, 0x01, 0x82, 0x2D, 0x03, 0x42, 0x00, 0x04, 0x5A, 0x98, 0xC1, 0x3F, 0x5F,
        0xFF, 0x09, 0x42, 0xAB, 0x56, 0xCF, 0x79, 0x92, 0x50, 0x90, 0xB3, 0x7A, 0x48, 0x79, 0x62, 0xBA,
        0xCD, 0x3B, 0xA9, 0xE4, 0xA9, 0x7E, 0x44, 0x51, 0x39, 0xFF, 0x2D, 0xB1, 0xCF, 0x80, 0xA9, 0x12,
        0x02, 0x28, 0x09, 0x27, 0x8D, 0x98, 0xC4, 0x0F, 0xEF, 0x46, 0x65, 0x53, 0xD8, 0x86, 0x18, 0xF2,
        0x4B, 0x7E, 0x16, 0xE2, 0x63, 0xFB, 0x1E, 0xA8, 0x83, 0x88, 0xEE
     };

    uint8_t signData[] = {
        0x30, 0x45, 0x02, 0x21, 0x00, 0xC2, 0x6E, 0x69, 0x1B, 0xBB, 0xB0, 0xEF, 0xB7, 0x29, 0xB5, 0x37,
        0x57, 0x6E, 0xDA, 0x1E, 0x67, 0x84, 0x9C, 0xD7, 0x00, 0x2E, 0x01, 0x85, 0x11, 0x54, 0xC3, 0x1A,
        0x58, 0xC6, 0xA9, 0x71, 0xEA, 0x02, 0x20, 0x7E, 0xB3, 0x76, 0x27, 0x84, 0x4F, 0x31, 0x1D, 0x64,
        0x71, 0xD7, 0xFE, 0x96, 0xD1, 0x5A, 0x83, 0xA0, 0x89, 0xC6, 0x3B, 0x84, 0xB6, 0x26, 0x88, 0x2A,
        0xF0, 0x71, 0x17, 0x6F, 0x06, 0x28, 0x11
    };
    const char *plainText = "hello world";
    HcfBlob plainTextBlob = { .data = (uint8_t *)plainText, .len = strlen(plainText) };
    HcfBlob pubKey = { .data = pk, .len = 91 };
    HcfBlob signDataBlob = { .data = signData, .len = 71};

    HcfAsyKeyGenerator *generator = nullptr;
    int32_t res = HcfAsyKeyGeneratorCreate("SM2_256", &generator);
    HcfKeyPair *outKeyPair = nullptr;
    res = generator->convertKey(generator, nullptr, &pubKey, nullptr, &outKeyPair);
    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(outKeyPair, nullptr);
    HcfObjDestroy(generator);

    HcfVerify *verify = nullptr;
    res = HcfVerifyCreate("SM2|SM3", &verify);
    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(verify, nullptr);

    res = verify->init(verify, nullptr, outKeyPair->pubKey);
    ASSERT_EQ(res, HCF_SUCCESS);

    res = verify->update(verify, &plainTextBlob);
    ASSERT_EQ(res, HCF_SUCCESS);

    bool flag = verify->verify(verify, nullptr, &signDataBlob);
    ASSERT_EQ(flag, true);
    HcfObjDestroy(verify);
    HcfObjDestroy(outKeyPair);
}
}
