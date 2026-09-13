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
#include "ed25519_openssl.h"
#include "detailed_alg_25519_key_params.h"
#include "alg_25519_asy_key_generator_openssl.h"
#include "crypto_operation_err.h"
#include "memory_mock.h"
#include "openssl_adapter_mock.h"


using namespace std;
using namespace testing::ext;

namespace {
class CryptoEd25519SignTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp();
    void TearDown();

    static HcfKeyPair *ed25519KeyPair_;
    static HcfKeyPair *x25519KeyPair_;
};

HcfKeyPair *CryptoEd25519SignTest::ed25519KeyPair_ = nullptr;
HcfKeyPair *CryptoEd25519SignTest::x25519KeyPair_ = nullptr;

static string g_ed25519AlgoName = "Ed25519";
static string g_x25519AlgoName = "X25519";

void CryptoEd25519SignTest::SetUp() {}
void CryptoEd25519SignTest::TearDown() {}

static const char *g_mockMessage = "hello world";
static HcfBlob g_mockInput = {
    .data = (uint8_t *)g_mockMessage,
    .len = 12
};

static const char *g_mock64Message = "ABCDABCDACBDABCDABCDABCDACBDABCDABCDABCDACBDABCDABCDABCDACBDABCD";
static HcfBlob g_mock64Input = {
    .data = (uint8_t *)g_mock64Message,
    .len = 65
};

static const char *GetMockClass(void)
{
    return "Ed25519Sign";
}
HcfObjectBase g_obj = {
    .getClass = GetMockClass,
    .destroy = nullptr
};

void CryptoEd25519SignTest::SetUpTestCase()
{
    HcfAsyKeyGenerator *generator = nullptr;
    int32_t ret = HcfAsyKeyGeneratorCreate(g_ed25519AlgoName.c_str(), &generator);
    ASSERT_EQ(ret, HCF_SUCCESS);
    ASSERT_NE(generator, nullptr);

    HcfKeyPair *keyPair = nullptr;
    ret = generator->generateKeyPair(generator, nullptr, &keyPair);
    ASSERT_EQ(ret, HCF_SUCCESS);
    ASSERT_NE(keyPair, nullptr);
    ed25519KeyPair_ = keyPair;
    HcfObjDestroy(generator);

    ret = HcfAsyKeyGeneratorCreate(g_x25519AlgoName.c_str(), &generator);
    ASSERT_EQ(ret, HCF_SUCCESS);
    ASSERT_NE(generator, nullptr);

    ret = generator->generateKeyPair(generator, nullptr, &keyPair);
    ASSERT_EQ(ret, HCF_SUCCESS);
    ASSERT_NE(keyPair, nullptr);

    x25519KeyPair_ = keyPair;

    HcfObjDestroy(generator);
}

void CryptoEd25519SignTest::TearDownTestCase()
{
    HcfObjDestroy(ed25519KeyPair_);
    HcfObjDestroy(x25519KeyPair_);
}

HWTEST_F(CryptoEd25519SignTest, CryptoEd25519SignTest001, TestSize.Level0)
{
    HcfSign *sign = nullptr;
    HcfResult ret = HcfSignCreate("Ed25519", &sign);
    ASSERT_EQ(ret, HCF_SUCCESS);
    ASSERT_NE(sign, nullptr);

    HcfObjDestroy(sign);
}

HWTEST_F(CryptoEd25519SignTest, CryptoEd25519SignTest002, TestSize.Level0)
{
    HcfSign *sign = nullptr;
    HcfResult ret = HcfSignCreate("Ed25519", &sign);
    ASSERT_EQ(ret, HCF_SUCCESS);
    ASSERT_NE(sign, nullptr);

    const char *className = sign->base.getClass();
    ASSERT_NE(className, nullptr);

    HcfObjDestroy(sign);
}

HWTEST_F(CryptoEd25519SignTest, CryptoEd25519SignTest003, TestSize.Level0)
{
    HcfSign *sign = nullptr;
    HcfResult ret = HcfSignCreate("Ed25519", &sign);
    ASSERT_EQ(ret, HCF_SUCCESS);
    ASSERT_NE(sign, nullptr);

    sign->base.destroy((HcfObjectBase *)sign);
}

HWTEST_F(CryptoEd25519SignTest, CryptoEd25519SignTest004, TestSize.Level0)
{
    HcfSign *sign = nullptr;
    HcfResult ret = HcfSignCreate("Ed25519", &sign);
    ASSERT_EQ(ret, HCF_SUCCESS);
    ASSERT_NE(sign, nullptr);

    const char *algName = sign->getAlgoName(sign);
    ASSERT_EQ(algName, g_ed25519AlgoName);

    HcfObjDestroy(sign);
}

HWTEST_F(CryptoEd25519SignTest, CryptoEd25519SignTest005, TestSize.Level0)
{
    HcfSign *sign = nullptr;
    HcfResult ret = HcfSignCreate("Ed25519", &sign);
    ASSERT_EQ(ret, HCF_SUCCESS);
    ASSERT_NE(sign, nullptr);

    ret = sign->init(sign, nullptr, ed25519KeyPair_->priKey);
    ASSERT_EQ(ret, HCF_SUCCESS);

    HcfObjDestroy(sign);
}

HWTEST_F(CryptoEd25519SignTest, CryptoEd25519SignTest006, TestSize.Level0)
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

    HcfFree(out.data);
    HcfObjDestroy(sign);
}

HWTEST_F(CryptoEd25519SignTest, CryptoEd25519SignTest007, TestSize.Level0)
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

static void MemoryMallocTestFunc(uint32_t mallocCount, HcfBlob *input)
{
    for (uint32_t i = 0; i < mallocCount; i++) {
        ResetRecordMallocNum();
        SetMockMallocIndex(i);
        HcfAsyKeyGenerator *generator = nullptr;
        HcfResult ret = HcfAsyKeyGeneratorCreate("Ed25519", &generator);
        if (ret != HCF_SUCCESS) {
            continue;
        }
        HcfKeyPair *keyPair = nullptr;
        ret = generator->generateKeyPair(generator, nullptr, &keyPair);
        HcfObjDestroy(generator);
        if (ret != HCF_SUCCESS) {
            continue;
        }
        HcfSign *sign = nullptr;
        ret = HcfSignCreate("Ed25519", &sign);
        if (ret != HCF_SUCCESS) {
            HcfObjDestroy(keyPair);
            continue;
        }
        ret = sign->init(sign, nullptr, keyPair->priKey);
        if (ret != HCF_SUCCESS) {
            HcfObjDestroy(sign);
            HcfObjDestroy(keyPair);
            continue;
        }
        ret = sign->update(sign, input);
        if (ret != HCF_SUCCESS) {
            HcfObjDestroy(sign);
            HcfObjDestroy(keyPair);
            continue;
        }
        HcfBlob out = {
            .data = nullptr,
            .len = 0
        };
        ret = sign->sign(sign, nullptr, &out);
        HcfObjDestroy(sign);
        HcfObjDestroy(keyPair);
        if (ret == HCF_SUCCESS) {
            HcfFree(out.data);
        }
    }
}

HWTEST_F(CryptoEd25519SignTest, CryptoEd25519SignTest008, TestSize.Level0)
{
    StartRecordMallocNum();
    HcfAsyKeyGenerator *generator = nullptr;
    HcfResult ret = HcfAsyKeyGeneratorCreate("Ed25519", &generator);
    ASSERT_EQ(ret, HCF_SUCCESS);
    ASSERT_NE(generator, nullptr);

    HcfKeyPair *keyPair = nullptr;
    ret = generator->generateKeyPair(generator, nullptr, &keyPair);
    ASSERT_EQ(ret, HCF_SUCCESS);
    ASSERT_NE(keyPair, nullptr);

    HcfObjDestroy(generator);

    HcfSign *sign = nullptr;
    ret = HcfSignCreate("Ed25519", &sign);
    ASSERT_EQ(ret, HCF_SUCCESS);
    ASSERT_NE(sign, nullptr);

    HcfParamsSpec params;
    ret = sign->init(sign, &params, keyPair->priKey);
    ASSERT_EQ(ret, HCF_SUCCESS);

    const char *message = "hello world";
    HcfBlob input = {
        .data = (uint8_t *)message,
        .len = 12
    };
    HcfBlob out = { .data = nullptr, .len = 0 };
    ret = sign->sign(sign, &g_mockInput, &out);
    ASSERT_EQ(ret, HCF_SUCCESS);
    ASSERT_NE(out.data, nullptr);
    ASSERT_NE(out.len, (const unsigned int)0);

    HcfFree(out.data);
    HcfObjDestroy(sign);
    HcfObjDestroy(keyPair);

    uint32_t mallocCount = GetMallocNum();
    MemoryMallocTestFunc(mallocCount, &input);

    EndRecordMallocNum();
}

static void OpensslMockTestFunc(uint32_t mallocCount, HcfBlob *input)
{
    for (uint32_t i = 0; i < mallocCount; i++) {
        ResetOpensslCallNum();
        SetOpensslCallMockIndex(i);
        HcfAsyKeyGenerator *generator = nullptr;
        HcfResult ret = HcfAsyKeyGeneratorCreate("Ed25519", &generator);
        if (ret != HCF_SUCCESS) {
            continue;
        }
        HcfKeyPair *keyPair = nullptr;
        ret = generator->generateKeyPair(generator, nullptr, &keyPair);
        HcfObjDestroy(generator);
        if (ret != HCF_SUCCESS) {
            continue;
        }
        HcfSign *sign = nullptr;
        ret = HcfSignCreate("Ed25519", &sign);
        if (ret != HCF_SUCCESS) {
            HcfObjDestroy(keyPair);
            continue;
        }
        ret = sign->init(sign, nullptr, keyPair->priKey);
        if (ret != HCF_SUCCESS) {
            HcfObjDestroy(sign);
            HcfObjDestroy(keyPair);
            continue;
        }
        HcfBlob out = {
            .data = nullptr,
            .len = 0
        };
        ret = sign->sign(sign, input, &out);
        HcfObjDestroy(sign);
        HcfObjDestroy(keyPair);
        if (ret == HCF_SUCCESS) {
            HcfFree(out.data);
        }
    }
}

HWTEST_F(CryptoEd25519SignTest, CryptoEd25519SignTest009, TestSize.Level0)
{
    StartRecordOpensslCallNum();
    HcfAsyKeyGenerator *generator = nullptr;
    HcfResult ret = HcfAsyKeyGeneratorCreate("Ed25519", &generator);
    ASSERT_EQ(ret, HCF_SUCCESS);
    ASSERT_NE(generator, nullptr);

    HcfKeyPair *keyPair = nullptr;
    ret = generator->generateKeyPair(generator, nullptr, &keyPair);
    ASSERT_EQ(ret, HCF_SUCCESS);
    ASSERT_NE(keyPair, nullptr);

    HcfObjDestroy(generator);

    HcfSign *sign = nullptr;
    ret = HcfSignCreate("Ed25519", &sign);
    ASSERT_EQ(ret, HCF_SUCCESS);
    ASSERT_NE(sign, nullptr);

    HcfParamsSpec params;
    ret = sign->init(sign, &params, keyPair->priKey);
    ASSERT_EQ(ret, HCF_SUCCESS);

    const char *message = "hello world";
    HcfBlob input = {
        .data = (uint8_t *)message,
        .len = 12
    };
    ret = sign->update(sign, &input);
    ASSERT_EQ(ret, HCF_INVALID_PARAMS);

    HcfBlob out = { .data = nullptr, .len = 0 };
    ret = sign->sign(sign, &input, &out);
    ASSERT_EQ(ret, HCF_SUCCESS);
    ASSERT_NE(out.data, nullptr);
    ASSERT_NE(out.len, (const unsigned int)0);

    HcfFree(out.data);
    HcfObjDestroy(sign);
    HcfObjDestroy(keyPair);

    uint32_t mallocCount = GetOpensslCallNum();
    OpensslMockTestFunc(mallocCount, &input);

    EndRecordOpensslCallNum();
}

HcfSignatureParams g_params = {
    .algo = HCF_ALG_ED25519,
};

HWTEST_F(CryptoEd25519SignTest, CryptoEd25519SignTest010, TestSize.Level0)
{
    HcfSignSpi *sign = nullptr;
    HcfResult ret = HcfSignSpiEd25519Create(nullptr, &sign);
    ASSERT_EQ(ret, HCF_INVALID_PARAMS);
    ASSERT_EQ(sign, nullptr);
    ret = HcfSignSpiEd25519Create(&g_params, &sign);
    ASSERT_EQ(ret, HCF_SUCCESS);
    ASSERT_NE(sign, nullptr);

    HcfObjDestroy(sign);
}

HWTEST_F(CryptoEd25519SignTest, CryptoEd25519SignTest011, TestSize.Level0)
{
    HcfSignSpi *sign = nullptr;
    HcfResult ret = HcfSignSpiEd25519Create(&g_params, &sign);
    ASSERT_EQ(ret, HCF_SUCCESS);
    ASSERT_NE(sign, nullptr);

    sign->base.destroy(nullptr);
    HcfObjDestroy(sign);
}

HWTEST_F(CryptoEd25519SignTest, CryptoEd25519SignTest012, TestSize.Level0)
{
    HcfSignSpi *sign = nullptr;
    HcfResult ret = HcfSignSpiEd25519Create(&g_params, &sign);
    ASSERT_EQ(ret, HCF_SUCCESS);
    ASSERT_NE(sign, nullptr);

    ret = sign->engineInit(sign, nullptr, nullptr);
    ASSERT_EQ(ret, HCF_INVALID_PARAMS);
    HcfObjDestroy(sign);
}

HWTEST_F(CryptoEd25519SignTest, CryptoEd25519SignTest013, TestSize.Level0)
{
    HcfSignSpi *sign = nullptr;
    HcfResult ret = HcfSignSpiEd25519Create(&g_params, &sign);
    ASSERT_EQ(ret, HCF_SUCCESS);
    ASSERT_NE(sign, nullptr);

    ret = sign->engineInit(sign, nullptr, ed25519KeyPair_->priKey);
    ASSERT_EQ(ret, HCF_SUCCESS);

    HcfBlob out = { .data = nullptr, .len = 0 };
    ret = sign->engineSign(sign, &g_mockInput, &out);
    ASSERT_EQ(ret, HCF_SUCCESS);
    HcfFree(out.data);
    HcfObjDestroy(sign);
}

HWTEST_F(CryptoEd25519SignTest, CryptoEd25519SignTest014, TestSize.Level0)
{
    HcfSign *sign = nullptr;
    HcfResult ret = HcfSignCreate("Ed25519", &sign);
    ASSERT_EQ(ret, HCF_SUCCESS);
    ASSERT_NE(sign, nullptr);

    int32_t returnInt = 0;
    ret = sign->setSignSpecInt(sign, SM2_USER_ID_UINT8ARR, returnInt);
    ASSERT_EQ(ret, HCF_NOT_SUPPORT);
    ret = sign->getSignSpecInt(sign, SM2_USER_ID_UINT8ARR, &returnInt);
    ASSERT_EQ(ret, HCF_NOT_SUPPORT);
    HcfBlob returnBlob = { .data = nullptr, .len = 0};
    ret = sign->setSignSpecUint8Array(sign, SM2_USER_ID_UINT8ARR, returnBlob);
    ASSERT_EQ(ret, HCF_NOT_SUPPORT);
    char *itemName = nullptr;
    ret = sign->getSignSpecString(sign, SM2_USER_ID_UINT8ARR, &itemName);
    ASSERT_EQ(ret, HCF_NOT_SUPPORT);

    HcfObjDestroy(sign);
}

HWTEST_F(CryptoEd25519SignTest, CryptoEd25519SignTest015, TestSize.Level0)
{
    HcfSign *sign = nullptr;
    HcfResult ret = HcfSignCreate("Ed25519", &sign);
    ASSERT_EQ(ret, HCF_SUCCESS);
    ASSERT_NE(sign, nullptr);

    sign->base.destroy(nullptr);
    HcfObjDestroy(sign);
}

HWTEST_F(CryptoEd25519SignTest, CryptoEd25519SignTest016, TestSize.Level0)
{
    HcfSign *sign = nullptr;
    HcfResult ret = HcfSignCreate("Ed25519", &sign);
    ASSERT_EQ(ret, HCF_SUCCESS);
    ASSERT_NE(sign, nullptr);

    sign->base.destroy(&g_obj);
    HcfObjDestroy(sign);
}

HWTEST_F(CryptoEd25519SignTest, CryptoEd25519SignTest017, TestSize.Level0)
{
    HcfSign *sign = nullptr;
    HcfResult ret = HcfSignCreate("Ed25519", &sign);
    ASSERT_EQ(ret, HCF_SUCCESS);
    ASSERT_NE(sign, nullptr);

    const char *algoName = sign->getAlgoName(nullptr);
    ASSERT_EQ(algoName, nullptr);

    algoName = sign->getAlgoName((HcfSign *)&g_obj);
    ASSERT_EQ(algoName, nullptr);

    HcfObjDestroy(sign);
}

HWTEST_F(CryptoEd25519SignTest, CryptoEd25519SignTest018, TestSize.Level0)
{
    HcfSign *sign = nullptr;
    HcfResult ret = HcfSignCreate("Ed25519", &sign);
    ASSERT_EQ(ret, HCF_SUCCESS);
    ASSERT_NE(sign, nullptr);

    ret = sign->init(nullptr, nullptr, ed25519KeyPair_->priKey);
    ASSERT_EQ(ret, HCF_INVALID_PARAMS);

    HcfObjDestroy(sign);
}

HWTEST_F(CryptoEd25519SignTest, CryptoEd25519SignTest019, TestSize.Level0)
{
    HcfSign *sign = nullptr;
    HcfResult ret = HcfSignCreate("Ed25519", &sign);
    ASSERT_EQ(ret, HCF_SUCCESS);
    ASSERT_NE(sign, nullptr);

    ret = sign->init((HcfSign *)&g_obj, nullptr, ed25519KeyPair_->priKey);
    ASSERT_EQ(ret, HCF_INVALID_PARAMS);

    HcfObjDestroy(sign);
}

#define ERROR_MSG_BUFFER_LEN 256
HWTEST_F(CryptoEd25519SignTest, CryptoEd25519SignTest020, TestSize.Level0)
{
    HcfSign *sign = nullptr;
    HcfResult ret = HcfSignCreate("Ed25519", &sign);
    ASSERT_EQ(ret, HCF_SUCCESS);
    ASSERT_NE(sign, nullptr);

    ret = sign->init(sign, nullptr, x25519KeyPair_->priKey);
    ASSERT_EQ(ret, HCF_ERR_CRYPTO_OPERATION);
    char buff[ERROR_MSG_BUFFER_LEN] = { 0 };
    (void)HcfGetOperationErrorMessage(buff, ERROR_MSG_BUFFER_LEN);
    EXPECT_NE(strlen(buff), 0);
    HcfObjDestroy(sign);
}

HWTEST_F(CryptoEd25519SignTest, CryptoEd25519SignTest021, TestSize.Level0)
{
    HcfSign *sign = nullptr;
    HcfResult ret = HcfSignCreate("Ed25519", &sign);
    ASSERT_EQ(ret, HCF_SUCCESS);
    ASSERT_NE(sign, nullptr);

    ret = sign->init(sign, nullptr, ed25519KeyPair_->priKey);
    ret = sign->init(sign, nullptr, ed25519KeyPair_->priKey);
    ASSERT_NE(ret, HCF_SUCCESS);

    HcfObjDestroy(sign);
}

HWTEST_F(CryptoEd25519SignTest, CryptoEd25519SignTest022, TestSize.Level0)
{
    HcfSign *sign = nullptr;
    HcfResult ret = HcfSignCreate("Ed25519", &sign);
    ASSERT_EQ(ret, HCF_SUCCESS);
    ASSERT_NE(sign, nullptr);

    ret = sign->sign(sign, &g_mockInput, nullptr);
    ASSERT_EQ(ret, HCF_INVALID_PARAMS);

    HcfBlob out = { .data = nullptr, .len = 0 };
    ret = sign->sign((HcfSign*)&g_obj, &g_mockInput, &out);
    ASSERT_EQ(ret, HCF_INVALID_PARAMS);

    ret = sign->sign(sign, &g_mockInput, &out);
    ASSERT_EQ(ret, HCF_INVALID_PARAMS);
    HcfFree(out.data);
    HcfObjDestroy(sign);
}

HWTEST_F(CryptoEd25519SignTest, CryptoEd25519SignTest023, TestSize.Level0)
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
    HcfFree(out.data);
    ret = sign->sign(sign, &g_mockInput, &out);
    ASSERT_EQ(ret, HCF_SUCCESS);
    ASSERT_NE(out.data, nullptr);
    ASSERT_NE(out.len, (const unsigned int)0);
    HcfFree(out.data);
    HcfObjDestroy(sign);
}

HWTEST_F(CryptoEd25519SignTest, CryptoEd25519SignTest024, TestSize.Level0)
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
    HcfFree(out.data);
    HcfObjDestroy(sign);
}

HWTEST_F(CryptoEd25519SignTest, CryptoEd25519SignTest025, TestSize.Level0)
{
    HcfSign *sign = nullptr;
    HcfResult ret = HcfSignCreate("Ed25519", &sign);
    ASSERT_EQ(ret, HCF_SUCCESS);
    ASSERT_NE(sign, nullptr);

    HcfBlob out = { .data = nullptr, .len = 0 };
    ret = sign->sign(sign, &g_mockInput, &out);
    ASSERT_NE(ret, HCF_SUCCESS);
    ASSERT_EQ(out.data, nullptr);
    ASSERT_EQ(out.len, (const unsigned int)0);
    HcfFree(out.data);
    HcfObjDestroy(sign);
}
}