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
#include <string>
#include "securec.h"

#include "asy_key_generator.h"
#include "detailed_ecc_key_params.h"
#include "ecc_asy_key_common.h"
#include "ecc_asy_key_generator_openssl.h"
#include "ecc_openssl_common.h"
#include "ecc_openssl_common_param_spec.h"
#include "ecc_common.h"
#include "blob.h"
#include "memory.h"
#include "memory_mock.h"
#include "openssl_adapter_mock.h"
#include "openssl_class.h"
#include "openssl_common.h"
#include "params_parser.h"

using namespace std;
using namespace testing::ext;

namespace {
class CryptoEccAsyKeyGeneratorBySpecSubThreeTest : public testing::Test {
public:
    static void SetUpTestCase() {};
    static void TearDownTestCase() {};
    void SetUp() {};
    void TearDown() {};
};

HcfBlob g_mockEcc224PubKeyBlob = {
    .data = g_mockEcc224PubKeyBlobData,
    .len = ECC224_PUB_KEY_LEN
};

HcfBlob g_mockEcc224PriKeyBlob = {
    .data = g_mockEcc224PriKeyBlobData,
    .len = ECC224_PRI_KEY_LEN
};

static const char *GetMockClass(void)
{
    return "HcfSymKeyGenerator";
}

HcfObjectBase g_obj = {
    .getClass = GetMockClass,
    .destroy = nullptr
};

// for test:ECC_FIELD_TYPE_STR
HWTEST_F(CryptoEccAsyKeyGeneratorBySpecSubThreeTest, CryptoEccAsyKeyGeneratorBySpecSubThreeTest409_1, TestSize.Level0)
{
    HcfAsyKeyParamsSpec *paramSpec = nullptr;
    int32_t res = ConstructEcc224CommParamsSpec(&paramSpec);

    ASSERT_EQ(res, HCF_SUCCESS);

    HcfAsyKeyGeneratorBySpec *generator = nullptr;
    res = HcfAsyKeyGeneratorBySpecCreate(paramSpec, &generator);

    HcfKeyPair *keyPair = nullptr;
    res = generator->generateKeyPair(generator, &keyPair);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(keyPair, nullptr);

    char *retStr = nullptr;
    AsyKeySpecItem item = ECC_FIELD_TYPE_STR;

    res = keyPair->pubKey->getAsyKeySpecString(keyPair->pubKey, item, &retStr);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(retStr, nullptr);

    HcfFree(retStr);

    HcfObjDestroy(keyPair);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoEccAsyKeyGeneratorBySpecSubThreeTest, CryptoEccAsyKeyGeneratorBySpecSubThreeTest409_2, TestSize.Level0)
{
    HcfAsyKeyParamsSpec *paramSpec = nullptr;
    int32_t res = ConstructEcc224CommParamsSpec(&paramSpec);

    ASSERT_EQ(res, HCF_SUCCESS);

    HcfAsyKeyGeneratorBySpec *generator = nullptr;
    res = HcfAsyKeyGeneratorBySpecCreate(paramSpec, &generator);

    HcfKeyPair *keyPair = nullptr;
    res = generator->generateKeyPair(generator, &keyPair);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(keyPair, nullptr);

    char *retStr = nullptr;
    AsyKeySpecItem item = ECC_FIELD_TYPE_STR;

    res = keyPair->priKey->getAsyKeySpecString(keyPair->priKey, item, &retStr);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(retStr, nullptr);

    HcfFree(retStr);

    HcfObjDestroy(keyPair);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoEccAsyKeyGeneratorBySpecSubThreeTest, CryptoEccAsyKeyGeneratorBySpecSubThreeTest409_3, TestSize.Level0)
{
    HcfAsyKeyParamsSpec *paramSpec = nullptr;
    int32_t res = ConstructEcc224PubKeyParamsSpec(&paramSpec);

    ASSERT_EQ(res, HCF_SUCCESS);

    HcfAsyKeyGeneratorBySpec *generator = nullptr;
    res = HcfAsyKeyGeneratorBySpecCreate(paramSpec, &generator);

    HcfPubKey *pubKey = nullptr;
    res = generator->generatePubKey(generator, &pubKey);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(pubKey, nullptr);

    char *retStr = nullptr;
    AsyKeySpecItem item = ECC_FIELD_TYPE_STR;

    res = pubKey->getAsyKeySpecString(pubKey, item, &retStr);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(retStr, nullptr);

    HcfFree(retStr);

    HcfObjDestroy(pubKey);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoEccAsyKeyGeneratorBySpecSubThreeTest, CryptoEccAsyKeyGeneratorBySpecSubThreeTest409_4, TestSize.Level0)
{
    HcfAsyKeyParamsSpec *paramSpec = nullptr;
    int32_t res = ConstructEcc224PriKeyParamsSpec(&paramSpec);

    ASSERT_EQ(res, HCF_SUCCESS);

    HcfAsyKeyGeneratorBySpec *generator = nullptr;
    res = HcfAsyKeyGeneratorBySpecCreate(paramSpec, &generator);

    HcfPriKey *priKey = nullptr;
    res = generator->generatePriKey(generator, &priKey);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(priKey, nullptr);

    char *retStr = nullptr;
    AsyKeySpecItem item = ECC_FIELD_TYPE_STR;

    res = priKey->getAsyKeySpecString(priKey, item, &retStr);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(retStr, nullptr);

    HcfFree(retStr);

    HcfObjDestroy(priKey);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoEccAsyKeyGeneratorBySpecSubThreeTest, CryptoEccAsyKeyGeneratorBySpecSubThreeTest409_5, TestSize.Level0)
{
    HcfAsyKeyParamsSpec *paramSpec = nullptr;
    int32_t res = ConstructEcc224KeyPairParamsSpec(&paramSpec);

    ASSERT_EQ(res, HCF_SUCCESS);

    HcfAsyKeyGeneratorBySpec *generator = nullptr;
    res = HcfAsyKeyGeneratorBySpecCreate(paramSpec, &generator);

    HcfKeyPair *keyPair = nullptr;
    res = generator->generateKeyPair(generator, &keyPair);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(keyPair, nullptr);

    char *retStr = nullptr;
    AsyKeySpecItem item = ECC_FIELD_TYPE_STR;

    res = keyPair->pubKey->getAsyKeySpecString(keyPair->pubKey, item, &retStr);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(retStr, nullptr);

    HcfFree(retStr);

    HcfObjDestroy(keyPair);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoEccAsyKeyGeneratorBySpecSubThreeTest, CryptoEccAsyKeyGeneratorBySpecSubThreeTest409_6, TestSize.Level0)
{
    HcfAsyKeyParamsSpec *paramSpec = nullptr;
    int32_t res = ConstructEcc224KeyPairParamsSpec(&paramSpec);

    ASSERT_EQ(res, HCF_SUCCESS);

    HcfAsyKeyGeneratorBySpec *generator = nullptr;
    res = HcfAsyKeyGeneratorBySpecCreate(paramSpec, &generator);

    HcfKeyPair *keyPair = nullptr;
    res = generator->generateKeyPair(generator, &keyPair);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(keyPair, nullptr);

    char *retStr = nullptr;
    AsyKeySpecItem item = ECC_FIELD_TYPE_STR;

    res = keyPair->priKey->getAsyKeySpecString(keyPair->priKey, item, &retStr);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(retStr, nullptr);

    HcfFree(retStr);

    HcfObjDestroy(keyPair);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoEccAsyKeyGeneratorBySpecSubThreeTest, CryptoEccAsyKeyGeneratorBySpecSubThreeTest409_7, TestSize.Level0)
{
    HcfAsyKeyParamsSpec *paramSpec = nullptr;
    int32_t res = ConstructEcc224KeyPairParamsSpec(&paramSpec);

    ASSERT_EQ(res, HCF_SUCCESS);

    HcfAsyKeyGeneratorBySpec *generator = nullptr;
    res = HcfAsyKeyGeneratorBySpecCreate(paramSpec, &generator);

    HcfPubKey *pubKey = nullptr;
    res = generator->generatePubKey(generator, &pubKey);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(pubKey, nullptr);

    char *retStr = nullptr;
    AsyKeySpecItem item = ECC_FIELD_TYPE_STR;

    res = pubKey->getAsyKeySpecString(pubKey, item, &retStr);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(retStr, nullptr);

    HcfFree(retStr);

    HcfObjDestroy(pubKey);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoEccAsyKeyGeneratorBySpecSubThreeTest, CryptoEccAsyKeyGeneratorBySpecSubThreeTest409_8, TestSize.Level0)
{
    HcfAsyKeyParamsSpec *paramSpec = nullptr;
    int32_t res = ConstructEcc224KeyPairParamsSpec(&paramSpec);

    ASSERT_EQ(res, HCF_SUCCESS);

    HcfAsyKeyGeneratorBySpec *generator = nullptr;
    res = HcfAsyKeyGeneratorBySpecCreate(paramSpec, &generator);

    HcfPriKey *priKey = nullptr;
    res = generator->generatePriKey(generator, &priKey);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(priKey, nullptr);

    char *retStr = nullptr;
    AsyKeySpecItem item = ECC_FIELD_TYPE_STR;

    res = priKey->getAsyKeySpecString(priKey, item, &retStr);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(retStr, nullptr);

    HcfFree(retStr);

    HcfObjDestroy(priKey);
    HcfObjDestroy(generator);
}

// for test:ECC_CURVE_NAME_STR
HWTEST_F(CryptoEccAsyKeyGeneratorBySpecSubThreeTest, CryptoEccAsyKeyGeneratorBySpecSubThreeTest410_1, TestSize.Level0)
{
    HcfAsyKeyParamsSpec *paramSpec = nullptr;
    int32_t res = ConstructEcc224CommParamsSpec(&paramSpec);

    ASSERT_EQ(res, HCF_SUCCESS);

    HcfAsyKeyGeneratorBySpec *generator = nullptr;
    res = HcfAsyKeyGeneratorBySpecCreate(paramSpec, &generator);

    HcfKeyPair *keyPair = nullptr;
    res = generator->generateKeyPair(generator, &keyPair);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(keyPair, nullptr);

    char *retStr = nullptr;
    AsyKeySpecItem item = ECC_CURVE_NAME_STR;

    res = keyPair->pubKey->getAsyKeySpecString(keyPair->pubKey, item, &retStr);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(retStr, nullptr);

    HcfFree(retStr);

    HcfObjDestroy(keyPair);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoEccAsyKeyGeneratorBySpecSubThreeTest, CryptoEccAsyKeyGeneratorBySpecSubThreeTest410_2, TestSize.Level0)
{
    HcfAsyKeyParamsSpec *paramSpec = nullptr;
    int32_t res = ConstructEcc224CommParamsSpec(&paramSpec);

    ASSERT_EQ(res, HCF_SUCCESS);

    HcfAsyKeyGeneratorBySpec *generator = nullptr;
    res = HcfAsyKeyGeneratorBySpecCreate(paramSpec, &generator);

    HcfKeyPair *keyPair = nullptr;
    res = generator->generateKeyPair(generator, &keyPair);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(keyPair, nullptr);

    char *retStr = nullptr;
    AsyKeySpecItem item = ECC_CURVE_NAME_STR;

    res = keyPair->priKey->getAsyKeySpecString(keyPair->priKey, item, &retStr);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(retStr, nullptr);

    HcfFree(retStr);

    HcfObjDestroy(keyPair);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoEccAsyKeyGeneratorBySpecSubThreeTest, CryptoEccAsyKeyGeneratorBySpecSubThreeTest410_3, TestSize.Level0)
{
    HcfAsyKeyParamsSpec *paramSpec = nullptr;
    int32_t res = ConstructEcc224PubKeyParamsSpec(&paramSpec);

    ASSERT_EQ(res, HCF_SUCCESS);

    HcfAsyKeyGeneratorBySpec *generator = nullptr;
    res = HcfAsyKeyGeneratorBySpecCreate(paramSpec, &generator);

    HcfPubKey *pubKey = nullptr;
    res = generator->generatePubKey(generator, &pubKey);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(pubKey, nullptr);

    char *retStr = nullptr;
    AsyKeySpecItem item = ECC_CURVE_NAME_STR;

    res = pubKey->getAsyKeySpecString(pubKey, item, &retStr);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(retStr, nullptr);

    HcfFree(retStr);

    HcfObjDestroy(pubKey);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoEccAsyKeyGeneratorBySpecSubThreeTest, CryptoEccAsyKeyGeneratorBySpecSubThreeTest410_4, TestSize.Level0)
{
    HcfAsyKeyParamsSpec *paramSpec = nullptr;
    int32_t res = ConstructEcc224PriKeyParamsSpec(&paramSpec);

    ASSERT_EQ(res, HCF_SUCCESS);

    HcfAsyKeyGeneratorBySpec *generator = nullptr;
    res = HcfAsyKeyGeneratorBySpecCreate(paramSpec, &generator);

    HcfPriKey *priKey = nullptr;
    res = generator->generatePriKey(generator, &priKey);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(priKey, nullptr);

    char *retStr = nullptr;
    AsyKeySpecItem item = ECC_CURVE_NAME_STR;

    res = priKey->getAsyKeySpecString(priKey, item, &retStr);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(retStr, nullptr);

    HcfFree(retStr);

    HcfObjDestroy(priKey);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoEccAsyKeyGeneratorBySpecSubThreeTest, CryptoEccAsyKeyGeneratorBySpecSubThreeTest410_5, TestSize.Level0)
{
    HcfAsyKeyParamsSpec *paramSpec = nullptr;
    int32_t res = ConstructEcc224KeyPairParamsSpec(&paramSpec);

    ASSERT_EQ(res, HCF_SUCCESS);

    HcfAsyKeyGeneratorBySpec *generator = nullptr;
    res = HcfAsyKeyGeneratorBySpecCreate(paramSpec, &generator);

    HcfKeyPair *keyPair = nullptr;
    res = generator->generateKeyPair(generator, &keyPair);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(keyPair, nullptr);

    char *retStr = nullptr;
    AsyKeySpecItem item = ECC_CURVE_NAME_STR;

    res = keyPair->pubKey->getAsyKeySpecString(keyPair->pubKey, item, &retStr);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(retStr, nullptr);

    HcfFree(retStr);

    HcfObjDestroy(keyPair);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoEccAsyKeyGeneratorBySpecSubThreeTest, CryptoEccAsyKeyGeneratorBySpecSubThreeTest410_6, TestSize.Level0)
{
    HcfAsyKeyParamsSpec *paramSpec = nullptr;
    int32_t res = ConstructEcc224KeyPairParamsSpec(&paramSpec);

    ASSERT_EQ(res, HCF_SUCCESS);

    HcfAsyKeyGeneratorBySpec *generator = nullptr;
    res = HcfAsyKeyGeneratorBySpecCreate(paramSpec, &generator);

    HcfKeyPair *keyPair = nullptr;
    res = generator->generateKeyPair(generator, &keyPair);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(keyPair, nullptr);

    char *retStr = nullptr;
    AsyKeySpecItem item = ECC_CURVE_NAME_STR;

    res = keyPair->priKey->getAsyKeySpecString(keyPair->priKey, item, &retStr);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(retStr, nullptr);

    HcfFree(retStr);

    HcfObjDestroy(keyPair);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoEccAsyKeyGeneratorBySpecSubThreeTest, CryptoEccAsyKeyGeneratorBySpecSubThreeTest410_7, TestSize.Level0)
{
    HcfAsyKeyParamsSpec *paramSpec = nullptr;
    int32_t res = ConstructEcc224KeyPairParamsSpec(&paramSpec);

    ASSERT_EQ(res, HCF_SUCCESS);

    HcfAsyKeyGeneratorBySpec *generator = nullptr;
    res = HcfAsyKeyGeneratorBySpecCreate(paramSpec, &generator);

    HcfPubKey *pubKey = nullptr;
    res = generator->generatePubKey(generator, &pubKey);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(pubKey, nullptr);

    char *retStr = nullptr;
    AsyKeySpecItem item = ECC_CURVE_NAME_STR;

    res = pubKey->getAsyKeySpecString(pubKey, item, &retStr);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(retStr, nullptr);

    HcfFree(retStr);

    HcfObjDestroy(pubKey);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoEccAsyKeyGeneratorBySpecSubThreeTest, CryptoEccAsyKeyGeneratorBySpecSubThreeTest410_8, TestSize.Level0)
{
    HcfAsyKeyParamsSpec *paramSpec = nullptr;
    int32_t res = ConstructEcc224KeyPairParamsSpec(&paramSpec);

    ASSERT_EQ(res, HCF_SUCCESS);

    HcfAsyKeyGeneratorBySpec *generator = nullptr;
    res = HcfAsyKeyGeneratorBySpecCreate(paramSpec, &generator);

    HcfPriKey *priKey = nullptr;
    res = generator->generatePriKey(generator, &priKey);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(priKey, nullptr);

    char *retStr = nullptr;
    AsyKeySpecItem item = ECC_CURVE_NAME_STR;

    res = priKey->getAsyKeySpecString(priKey, item, &retStr);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(retStr, nullptr);

    HcfFree(retStr);

    HcfObjDestroy(priKey);
    HcfObjDestroy(generator);
}

// 192 has no curve name
HWTEST_F(CryptoEccAsyKeyGeneratorBySpecSubThreeTest, CryptoEccAsyKeyGeneratorBySpecSubThreeTest410_9, TestSize.Level0)
{
    HcfAsyKeyParamsSpec *paramSpec = nullptr;
    int32_t res = ConstructEcc192CommParamsSpec(&paramSpec);

    ASSERT_EQ(res, HCF_SUCCESS);

    HcfAsyKeyGeneratorBySpec *generator = nullptr;
    res = HcfAsyKeyGeneratorBySpecCreate(paramSpec, &generator);

    HcfKeyPair *keyPair = nullptr;
    res = generator->generateKeyPair(generator, &keyPair);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(keyPair, nullptr);

    char *retStr = nullptr;
    AsyKeySpecItem item = ECC_CURVE_NAME_STR;

    res = keyPair->priKey->getAsyKeySpecString(keyPair->priKey, item, &retStr);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(retStr, nullptr);

    HcfFree(retStr);

    HcfObjDestroy(keyPair);
    HcfObjDestroy(generator);
}

// 256
HWTEST_F(CryptoEccAsyKeyGeneratorBySpecSubThreeTest, CryptoEccAsyKeyGeneratorBySpecSubThreeTest410_10, TestSize.Level0)
{
    HcfAsyKeyParamsSpec *paramSpec = nullptr;
    int32_t res = ConstructEcc256KeyPairParamsSpec(&paramSpec);

    ASSERT_EQ(res, HCF_SUCCESS);

    HcfAsyKeyGeneratorBySpec *generator = nullptr;
    res = HcfAsyKeyGeneratorBySpecCreate(paramSpec, &generator);

    HcfPriKey *priKey = nullptr;
    res = generator->generatePriKey(generator, &priKey);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(priKey, nullptr);

    char *retStr = nullptr;
    AsyKeySpecItem item = ECC_CURVE_NAME_STR;

    res = priKey->getAsyKeySpecString(priKey, item, &retStr);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(retStr, nullptr);

    HcfFree(retStr);

    HcfObjDestroy(priKey);
    HcfObjDestroy(generator);
}

// 384
HWTEST_F(CryptoEccAsyKeyGeneratorBySpecSubThreeTest, CryptoEccAsyKeyGeneratorBySpecSubThreeTest410_11, TestSize.Level0)
{
    HcfAsyKeyParamsSpec *paramSpec = nullptr;
    int32_t res = ConstructEcc384KeyPairParamsSpec(&paramSpec);

    ASSERT_EQ(res, HCF_SUCCESS);

    HcfAsyKeyGeneratorBySpec *generator = nullptr;
    res = HcfAsyKeyGeneratorBySpecCreate(paramSpec, &generator);

    HcfPriKey *priKey = nullptr;
    res = generator->generatePriKey(generator, &priKey);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(priKey, nullptr);

    char *retStr = nullptr;
    AsyKeySpecItem item = ECC_CURVE_NAME_STR;

    res = priKey->getAsyKeySpecString(priKey, item, &retStr);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(retStr, nullptr);

    HcfFree(retStr);

    HcfObjDestroy(priKey);
    HcfObjDestroy(generator);
}

// 521
HWTEST_F(CryptoEccAsyKeyGeneratorBySpecSubThreeTest, CryptoEccAsyKeyGeneratorBySpecSubThreeTest410_12, TestSize.Level0)
{
    HcfAsyKeyParamsSpec *paramSpec = nullptr;
    int32_t res = ConstructEcc521KeyPairParamsSpec(&paramSpec);

    ASSERT_EQ(res, HCF_SUCCESS);

    HcfAsyKeyGeneratorBySpec *generator = nullptr;
    res = HcfAsyKeyGeneratorBySpecCreate(paramSpec, &generator);

    HcfPriKey *priKey = nullptr;
    res = generator->generatePriKey(generator, &priKey);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(priKey, nullptr);

    char *retStr = nullptr;
    AsyKeySpecItem item = ECC_CURVE_NAME_STR;

    res = priKey->getAsyKeySpecString(priKey, item, &retStr);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(retStr, nullptr);

    HcfFree(retStr);

    HcfObjDestroy(priKey);
    HcfObjDestroy(generator);
}
// for test:ECC_PK_X_BN
HWTEST_F(CryptoEccAsyKeyGeneratorBySpecSubThreeTest, CryptoEccAsyKeyGeneratorBySpecSubThreeTest411_1, TestSize.Level0)
{
    HcfAsyKeyParamsSpec *paramSpec = nullptr;
    int32_t res = ConstructEcc224CommParamsSpec(&paramSpec);

    ASSERT_EQ(res, HCF_SUCCESS);

    HcfAsyKeyGeneratorBySpec *generator = nullptr;
    res = HcfAsyKeyGeneratorBySpecCreate(paramSpec, &generator);

    HcfKeyPair *keyPair = nullptr;
    res = generator->generateKeyPair(generator, &keyPair);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(keyPair, nullptr);

    HcfBigInteger retBigInt = { .data = nullptr, .len = 0 };
    AsyKeySpecItem item = ECC_PK_X_BN;

    res = keyPair->pubKey->getAsyKeySpecBigInteger(keyPair->pubKey, item, &retBigInt);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(retBigInt.data, nullptr);
    ASSERT_NE(retBigInt.len, 0);

    HcfFree(retBigInt.data);

    HcfObjDestroy(keyPair);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoEccAsyKeyGeneratorBySpecSubThreeTest, CryptoEccAsyKeyGeneratorBySpecSubThreeTest411_2, TestSize.Level0)
{
    HcfAsyKeyParamsSpec *paramSpec = nullptr;
    int32_t res = ConstructEcc224PubKeyParamsSpec(&paramSpec);

    ASSERT_EQ(res, HCF_SUCCESS);

    HcfAsyKeyGeneratorBySpec *generator = nullptr;
    res = HcfAsyKeyGeneratorBySpecCreate(paramSpec, &generator);

    HcfPubKey *pubKey = nullptr;
    res = generator->generatePubKey(generator, &pubKey);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(pubKey, nullptr);

    HcfBigInteger retBigInt = { .data = nullptr, .len = 0 };
    AsyKeySpecItem item = ECC_PK_X_BN;

    res = pubKey->getAsyKeySpecBigInteger(pubKey, item, &retBigInt);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(retBigInt.data, nullptr);
    ASSERT_NE(retBigInt.len, 0);

    HcfFree(retBigInt.data);

    HcfObjDestroy(pubKey);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoEccAsyKeyGeneratorBySpecSubThreeTest, CryptoEccAsyKeyGeneratorBySpecSubThreeTest411_3, TestSize.Level0)
{
    HcfAsyKeyParamsSpec *paramSpec = nullptr;
    int32_t res = ConstructEcc224KeyPairParamsSpec(&paramSpec);

    ASSERT_EQ(res, HCF_SUCCESS);

    HcfAsyKeyGeneratorBySpec *generator = nullptr;
    res = HcfAsyKeyGeneratorBySpecCreate(paramSpec, &generator);

    HcfKeyPair *keyPair = nullptr;
    res = generator->generateKeyPair(generator, &keyPair);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(keyPair, nullptr);

    HcfBigInteger retBigInt = { .data = nullptr, .len = 0 };
    AsyKeySpecItem item = ECC_PK_X_BN;

    res = keyPair->pubKey->getAsyKeySpecBigInteger(keyPair->pubKey, item, &retBigInt);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(retBigInt.data, nullptr);
    ASSERT_NE(retBigInt.len, 0);

    HcfFree(retBigInt.data);

    HcfObjDestroy(keyPair);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoEccAsyKeyGeneratorBySpecSubThreeTest, CryptoEccAsyKeyGeneratorBySpecSubThreeTest411_4, TestSize.Level0)
{
    HcfAsyKeyParamsSpec *paramSpec = nullptr;
    int32_t res = ConstructEcc224KeyPairParamsSpec(&paramSpec);

    ASSERT_EQ(res, HCF_SUCCESS);

    HcfAsyKeyGeneratorBySpec *generator = nullptr;
    res = HcfAsyKeyGeneratorBySpecCreate(paramSpec, &generator);

    HcfPubKey *pubKey = nullptr;
    res = generator->generatePubKey(generator, &pubKey);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(pubKey, nullptr);

    HcfBigInteger retBigInt = { .data = nullptr, .len = 0 };
    AsyKeySpecItem item = ECC_PK_X_BN;

    res = pubKey->getAsyKeySpecBigInteger(pubKey, item, &retBigInt);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(retBigInt.data, nullptr);
    ASSERT_NE(retBigInt.len, 0);

    HcfFree(retBigInt.data);

    HcfObjDestroy(pubKey);
    HcfObjDestroy(generator);
}

// for test:ECC_PK_Y_BN
HWTEST_F(CryptoEccAsyKeyGeneratorBySpecSubThreeTest, CryptoEccAsyKeyGeneratorBySpecSubThreeTest412_1, TestSize.Level0)
{
    HcfAsyKeyParamsSpec *paramSpec = nullptr;
    int32_t res = ConstructEcc224CommParamsSpec(&paramSpec);

    ASSERT_EQ(res, HCF_SUCCESS);

    HcfAsyKeyGeneratorBySpec *generator = nullptr;
    res = HcfAsyKeyGeneratorBySpecCreate(paramSpec, &generator);

    HcfKeyPair *keyPair = nullptr;
    res = generator->generateKeyPair(generator, &keyPair);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(keyPair, nullptr);

    HcfBigInteger retBigInt = { .data = nullptr, .len = 0 };
    AsyKeySpecItem item = ECC_PK_Y_BN;

    res = keyPair->pubKey->getAsyKeySpecBigInteger(keyPair->pubKey, item, &retBigInt);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(retBigInt.data, nullptr);
    ASSERT_NE(retBigInt.len, 0);

    HcfFree(retBigInt.data);

    HcfObjDestroy(keyPair);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoEccAsyKeyGeneratorBySpecSubThreeTest, CryptoEccAsyKeyGeneratorBySpecSubThreeTest412_2, TestSize.Level0)
{
    HcfAsyKeyParamsSpec *paramSpec = nullptr;
    int32_t res = ConstructEcc224PubKeyParamsSpec(&paramSpec);

    ASSERT_EQ(res, HCF_SUCCESS);

    HcfAsyKeyGeneratorBySpec *generator = nullptr;
    res = HcfAsyKeyGeneratorBySpecCreate(paramSpec, &generator);

    HcfPubKey *pubKey = nullptr;
    res = generator->generatePubKey(generator, &pubKey);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(pubKey, nullptr);

    HcfBigInteger retBigInt = { .data = nullptr, .len = 0 };
    AsyKeySpecItem item = ECC_PK_Y_BN;

    res = pubKey->getAsyKeySpecBigInteger(pubKey, item, &retBigInt);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(retBigInt.data, nullptr);
    ASSERT_NE(retBigInt.len, 0);

    HcfFree(retBigInt.data);

    HcfObjDestroy(pubKey);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoEccAsyKeyGeneratorBySpecSubThreeTest, CryptoEccAsyKeyGeneratorBySpecSubThreeTest412_3, TestSize.Level0)
{
    HcfAsyKeyParamsSpec *paramSpec = nullptr;
    int32_t res = ConstructEcc224KeyPairParamsSpec(&paramSpec);

    ASSERT_EQ(res, HCF_SUCCESS);

    HcfAsyKeyGeneratorBySpec *generator = nullptr;
    res = HcfAsyKeyGeneratorBySpecCreate(paramSpec, &generator);

    HcfKeyPair *keyPair = nullptr;
    res = generator->generateKeyPair(generator, &keyPair);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(keyPair, nullptr);

    HcfBigInteger retBigInt = { .data = nullptr, .len = 0 };
    AsyKeySpecItem item = ECC_PK_Y_BN;

    res = keyPair->pubKey->getAsyKeySpecBigInteger(keyPair->pubKey, item, &retBigInt);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(retBigInt.data, nullptr);
    ASSERT_NE(retBigInt.len, 0);

    HcfFree(retBigInt.data);

    HcfObjDestroy(keyPair);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoEccAsyKeyGeneratorBySpecSubThreeTest, CryptoEccAsyKeyGeneratorBySpecSubThreeTest412_4, TestSize.Level0)
{
    HcfAsyKeyParamsSpec *paramSpec = nullptr;
    int32_t res = ConstructEcc224KeyPairParamsSpec(&paramSpec);

    ASSERT_EQ(res, HCF_SUCCESS);

    HcfAsyKeyGeneratorBySpec *generator = nullptr;
    res = HcfAsyKeyGeneratorBySpecCreate(paramSpec, &generator);

    HcfPubKey *pubKey = nullptr;
    res = generator->generatePubKey(generator, &pubKey);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(pubKey, nullptr);

    HcfBigInteger retBigInt = { .data = nullptr, .len = 0 };
    AsyKeySpecItem item = ECC_PK_Y_BN;

    res = pubKey->getAsyKeySpecBigInteger(pubKey, item, &retBigInt);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(retBigInt.data, nullptr);
    ASSERT_NE(retBigInt.len, 0);

    HcfFree(retBigInt.data);

    HcfObjDestroy(pubKey);
    HcfObjDestroy(generator);
}

// for test:ECC_SK_BN
HWTEST_F(CryptoEccAsyKeyGeneratorBySpecSubThreeTest, CryptoEccAsyKeyGeneratorBySpecSubThreeTest413_1, TestSize.Level0)
{
    HcfAsyKeyParamsSpec *paramSpec = nullptr;
    int32_t res = ConstructEcc224CommParamsSpec(&paramSpec);

    ASSERT_EQ(res, HCF_SUCCESS);

    HcfAsyKeyGeneratorBySpec *generator = nullptr;
    res = HcfAsyKeyGeneratorBySpecCreate(paramSpec, &generator);

    HcfKeyPair *keyPair = nullptr;
    res = generator->generateKeyPair(generator, &keyPair);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(keyPair, nullptr);

    HcfBigInteger retBigInt = { .data = nullptr, .len = 0 };
    AsyKeySpecItem item = ECC_SK_BN;

    res = keyPair->priKey->getAsyKeySpecBigInteger(keyPair->priKey, item, &retBigInt);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(retBigInt.data, nullptr);
    ASSERT_NE(retBigInt.len, 0);

    HcfFree(retBigInt.data);

    HcfObjDestroy(keyPair);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoEccAsyKeyGeneratorBySpecSubThreeTest, CryptoEccAsyKeyGeneratorBySpecSubThreeTest413_2, TestSize.Level0)
{
    HcfAsyKeyParamsSpec *paramSpec = nullptr;
    int32_t res = ConstructEcc224PriKeyParamsSpec(&paramSpec);

    ASSERT_EQ(res, HCF_SUCCESS);

    HcfAsyKeyGeneratorBySpec *generator = nullptr;
    res = HcfAsyKeyGeneratorBySpecCreate(paramSpec, &generator);

    HcfPriKey *priKey = nullptr;
    res = generator->generatePriKey(generator, &priKey);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(priKey, nullptr);

    HcfBigInteger retBigInt = { .data = nullptr, .len = 0 };
    AsyKeySpecItem item = ECC_SK_BN;

    res = priKey->getAsyKeySpecBigInteger(priKey, item, &retBigInt);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(retBigInt.data, nullptr);
    ASSERT_NE(retBigInt.len, 0);

    HcfFree(retBigInt.data);

    HcfObjDestroy(priKey);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoEccAsyKeyGeneratorBySpecSubThreeTest, CryptoEccAsyKeyGeneratorBySpecSubThreeTest413_3, TestSize.Level0)
{
    HcfAsyKeyParamsSpec *paramSpec = nullptr;
    int32_t res = ConstructEcc224KeyPairParamsSpec(&paramSpec);

    ASSERT_EQ(res, HCF_SUCCESS);

    HcfAsyKeyGeneratorBySpec *generator = nullptr;
    res = HcfAsyKeyGeneratorBySpecCreate(paramSpec, &generator);

    HcfKeyPair *keyPair = nullptr;
    res = generator->generateKeyPair(generator, &keyPair);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(keyPair, nullptr);

    HcfBigInteger retBigInt = { .data = nullptr, .len = 0 };
    AsyKeySpecItem item = ECC_SK_BN;

    res = keyPair->priKey->getAsyKeySpecBigInteger(keyPair->priKey, item, &retBigInt);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(retBigInt.data, nullptr);
    ASSERT_NE(retBigInt.len, 0);

    HcfFree(retBigInt.data);

    HcfObjDestroy(keyPair);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoEccAsyKeyGeneratorBySpecSubThreeTest, CryptoEccAsyKeyGeneratorBySpecSubThreeTest413_4, TestSize.Level0)
{
    HcfAsyKeyParamsSpec *paramSpec = nullptr;
    int32_t res = ConstructEcc224KeyPairParamsSpec(&paramSpec);

    ASSERT_EQ(res, HCF_SUCCESS);

    HcfAsyKeyGeneratorBySpec *generator = nullptr;
    res = HcfAsyKeyGeneratorBySpecCreate(paramSpec, &generator);

    HcfPriKey *priKey = nullptr;
    res = generator->generatePriKey(generator, &priKey);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(priKey, nullptr);

    HcfBigInteger retBigInt = { .data = nullptr, .len = 0 };
    AsyKeySpecItem item = ECC_SK_BN;

    res = priKey->getAsyKeySpecBigInteger(priKey, item, &retBigInt);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(retBigInt.data, nullptr);
    ASSERT_NE(retBigInt.len, 0);

    HcfFree(retBigInt.data);

    HcfObjDestroy(priKey);
    HcfObjDestroy(generator);
}

// get spec exception test
// get string
HWTEST_F(CryptoEccAsyKeyGeneratorBySpecSubThreeTest, CryptoEccAsyKeyGeneratorBySpecSubThreeTest414_1, TestSize.Level0)
{
    HcfAsyKeyParamsSpec *paramSpec = nullptr;
    int32_t res = ConstructEcc224KeyPairParamsSpec(&paramSpec);

    ASSERT_EQ(res, HCF_SUCCESS);

    HcfAsyKeyGeneratorBySpec *generator = nullptr;
    res = HcfAsyKeyGeneratorBySpecCreate(paramSpec, &generator);

    HcfKeyPair *keyPair = nullptr;
    res = generator->generateKeyPair(generator, &keyPair);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(keyPair, nullptr);

    AsyKeySpecItem item = ECC_CURVE_NAME_STR;
    res = keyPair->priKey->getAsyKeySpecString(nullptr, item, nullptr);

    ASSERT_NE(res, HCF_SUCCESS);

    HcfObjDestroy(keyPair);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoEccAsyKeyGeneratorBySpecSubThreeTest, CryptoEccAsyKeyGeneratorBySpecSubThreeTest414_2, TestSize.Level0)
{
    HcfAsyKeyParamsSpec *paramSpec = nullptr;
    int32_t res = ConstructEcc224KeyPairParamsSpec(&paramSpec);

    ASSERT_EQ(res, HCF_SUCCESS);

    HcfAsyKeyGeneratorBySpec *generator = nullptr;
    res = HcfAsyKeyGeneratorBySpecCreate(paramSpec, &generator);

    HcfKeyPair *keyPair = nullptr;
    res = generator->generateKeyPair(generator, &keyPair);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(keyPair, nullptr);

    char *ret = nullptr;
    AsyKeySpecItem item = ECC_CURVE_NAME_STR;
    res = keyPair->priKey->getAsyKeySpecString(reinterpret_cast<HcfPriKey *>(&g_obj), item, &ret);

    ASSERT_NE(res, HCF_SUCCESS);
    ASSERT_EQ(ret, nullptr);

    HcfObjDestroy(keyPair);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoEccAsyKeyGeneratorBySpecSubThreeTest, CryptoEccAsyKeyGeneratorBySpecSubThreeTest414_3, TestSize.Level0)
{
    HcfAsyKeyParamsSpec *paramSpec = nullptr;
    int32_t res = ConstructEcc224KeyPairParamsSpec(&paramSpec);

    ASSERT_EQ(res, HCF_SUCCESS);

    HcfAsyKeyGeneratorBySpec *generator = nullptr;
    res = HcfAsyKeyGeneratorBySpecCreate(paramSpec, &generator);

    HcfKeyPair *keyPair = nullptr;
    res = generator->generateKeyPair(generator, &keyPair);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(keyPair, nullptr);

    AsyKeySpecItem item = ECC_CURVE_NAME_STR;
    res = keyPair->priKey->getAsyKeySpecString(keyPair->priKey, item, nullptr);

    ASSERT_NE(res, HCF_SUCCESS);

    HcfObjDestroy(keyPair);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoEccAsyKeyGeneratorBySpecSubThreeTest, CryptoEccAsyKeyGeneratorBySpecSubThreeTest414_4, TestSize.Level0)
{
    HcfAsyKeyParamsSpec *paramSpec = nullptr;
    int32_t res = ConstructEcc224KeyPairParamsSpec(&paramSpec);

    ASSERT_EQ(res, HCF_SUCCESS);

    HcfAsyKeyGeneratorBySpec *generator = nullptr;
    res = HcfAsyKeyGeneratorBySpecCreate(paramSpec, &generator);

    HcfKeyPair *keyPair = nullptr;
    res = generator->generateKeyPair(generator, &keyPair);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(keyPair, nullptr);

    char *ret = nullptr;
    AsyKeySpecItem item = ECC_A_BN;
    res = keyPair->priKey->getAsyKeySpecString(keyPair->priKey, item, &ret);

    ASSERT_NE(res, HCF_SUCCESS);
    ASSERT_EQ(ret, nullptr);

    HcfObjDestroy(keyPair);
    HcfObjDestroy(generator);
}

// get int
HWTEST_F(CryptoEccAsyKeyGeneratorBySpecSubThreeTest, CryptoEccAsyKeyGeneratorBySpecSubThreeTest415_1, TestSize.Level0)
{
    HcfAsyKeyParamsSpec *paramSpec = nullptr;
    int32_t res = ConstructEcc224KeyPairParamsSpec(&paramSpec);

    ASSERT_EQ(res, HCF_SUCCESS);

    HcfAsyKeyGeneratorBySpec *generator = nullptr;
    res = HcfAsyKeyGeneratorBySpecCreate(paramSpec, &generator);

    HcfKeyPair *keyPair = nullptr;
    res = generator->generateKeyPair(generator, &keyPair);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(keyPair, nullptr);

    res = keyPair->priKey->getAsyKeySpecInt(nullptr, ECC_H_INT, nullptr);

    ASSERT_NE(res, HCF_SUCCESS);

    HcfObjDestroy(keyPair);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoEccAsyKeyGeneratorBySpecSubThreeTest, CryptoEccAsyKeyGeneratorBySpecSubThreeTest415_2, TestSize.Level0)
{
    HcfAsyKeyParamsSpec *paramSpec = nullptr;
    int32_t res = ConstructEcc224KeyPairParamsSpec(&paramSpec);

    ASSERT_EQ(res, HCF_SUCCESS);

    HcfAsyKeyGeneratorBySpec *generator = nullptr;
    res = HcfAsyKeyGeneratorBySpecCreate(paramSpec, &generator);

    HcfKeyPair *keyPair = nullptr;
    res = generator->generateKeyPair(generator, &keyPair);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(keyPair, nullptr);

    int ret = 0;
    AsyKeySpecItem item = ECC_H_INT;
    res = keyPair->priKey->getAsyKeySpecInt(reinterpret_cast<HcfPriKey *>(&g_obj), item, &ret);

    ASSERT_NE(res, HCF_SUCCESS);
    ASSERT_EQ(ret, 0);

    HcfObjDestroy(keyPair);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoEccAsyKeyGeneratorBySpecSubThreeTest, CryptoEccAsyKeyGeneratorBySpecSubThreeTest415_3, TestSize.Level0)
{
    HcfAsyKeyParamsSpec *paramSpec = nullptr;
    int32_t res = ConstructEcc224KeyPairParamsSpec(&paramSpec);

    ASSERT_EQ(res, HCF_SUCCESS);

    HcfAsyKeyGeneratorBySpec *generator = nullptr;
    res = HcfAsyKeyGeneratorBySpecCreate(paramSpec, &generator);

    HcfKeyPair *keyPair = nullptr;
    res = generator->generateKeyPair(generator, &keyPair);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(keyPair, nullptr);

    AsyKeySpecItem item = ECC_H_INT;
    res = keyPair->priKey->getAsyKeySpecInt(keyPair->priKey, item, nullptr);

    ASSERT_NE(res, HCF_SUCCESS);

    HcfObjDestroy(keyPair);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoEccAsyKeyGeneratorBySpecSubThreeTest, CryptoEccAsyKeyGeneratorBySpecSubThreeTest415_4, TestSize.Level0)
{
    HcfAsyKeyParamsSpec *paramSpec = nullptr;
    int32_t res = ConstructEcc224KeyPairParamsSpec(&paramSpec);

    ASSERT_EQ(res, HCF_SUCCESS);

    HcfAsyKeyGeneratorBySpec *generator = nullptr;
    res = HcfAsyKeyGeneratorBySpecCreate(paramSpec, &generator);

    HcfKeyPair *keyPair = nullptr;
    res = generator->generateKeyPair(generator, &keyPair);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(keyPair, nullptr);

    int ret = 0;
    AsyKeySpecItem item = ECC_A_BN;
    res = keyPair->priKey->getAsyKeySpecInt(keyPair->priKey, item, &ret);

    ASSERT_NE(res, HCF_SUCCESS);
    ASSERT_EQ(ret, 0);

    HcfObjDestroy(keyPair);
    HcfObjDestroy(generator);
}

// get Big Int
HWTEST_F(CryptoEccAsyKeyGeneratorBySpecSubThreeTest, CryptoEccAsyKeyGeneratorBySpecSubThreeTest416_1, TestSize.Level0)
{
    HcfAsyKeyParamsSpec *paramSpec = nullptr;
    int32_t res = ConstructEcc224KeyPairParamsSpec(&paramSpec);

    ASSERT_EQ(res, HCF_SUCCESS);

    HcfAsyKeyGeneratorBySpec *generator = nullptr;
    res = HcfAsyKeyGeneratorBySpecCreate(paramSpec, &generator);

    HcfPriKey *priKey = nullptr;
    res = generator->generatePriKey(generator, &priKey);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(priKey, nullptr);

    HcfBigInteger retBigInt = { .data = nullptr, .len = 0 };
    AsyKeySpecItem item = ECC_SK_BN;

    res = priKey->getAsyKeySpecBigInteger(nullptr, item, &retBigInt);

    ASSERT_NE(res, HCF_SUCCESS);
    ASSERT_EQ(retBigInt.data, nullptr);
    ASSERT_EQ(retBigInt.len, 0);

    HcfObjDestroy(priKey);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoEccAsyKeyGeneratorBySpecSubThreeTest, CryptoEccAsyKeyGeneratorBySpecSubThreeTest416_2, TestSize.Level0)
{
    HcfAsyKeyParamsSpec *paramSpec = nullptr;
    int32_t res = ConstructEcc224KeyPairParamsSpec(&paramSpec);

    ASSERT_EQ(res, HCF_SUCCESS);

    HcfAsyKeyGeneratorBySpec *generator = nullptr;
    res = HcfAsyKeyGeneratorBySpecCreate(paramSpec, &generator);

    HcfPriKey *priKey = nullptr;
    res = generator->generatePriKey(generator, &priKey);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(priKey, nullptr);

    AsyKeySpecItem item = ECC_SK_BN;

    res = priKey->getAsyKeySpecBigInteger(priKey, item, nullptr);

    ASSERT_NE(res, HCF_SUCCESS);

    HcfObjDestroy(priKey);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoEccAsyKeyGeneratorBySpecSubThreeTest, CryptoEccAsyKeyGeneratorBySpecSubThreeTest416_3, TestSize.Level0)
{
    HcfAsyKeyParamsSpec *paramSpec = nullptr;
    int32_t res = ConstructEcc224KeyPairParamsSpec(&paramSpec);

    ASSERT_EQ(res, HCF_SUCCESS);

    HcfAsyKeyGeneratorBySpec *generator = nullptr;
    res = HcfAsyKeyGeneratorBySpecCreate(paramSpec, &generator);

    HcfPriKey *priKey = nullptr;
    res = generator->generatePriKey(generator, &priKey);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(priKey, nullptr);

    HcfBigInteger retBigInt = { .data = nullptr, .len = 0 };
    AsyKeySpecItem item = ECC_SK_BN;

    res = priKey->getAsyKeySpecBigInteger(reinterpret_cast<HcfPriKey *>(&g_obj), item, &retBigInt);

    ASSERT_NE(res, HCF_SUCCESS);
    ASSERT_EQ(retBigInt.data, nullptr);
    ASSERT_EQ(retBigInt.len, 0);

    HcfObjDestroy(priKey);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoEccAsyKeyGeneratorBySpecSubThreeTest, CryptoEccAsyKeyGeneratorBySpecSubThreeTest416_4, TestSize.Level0)
{
    HcfAsyKeyParamsSpec *paramSpec = nullptr;
    int32_t res = ConstructEcc224KeyPairParamsSpec(&paramSpec);

    ASSERT_EQ(res, HCF_SUCCESS);

    HcfAsyKeyGeneratorBySpec *generator = nullptr;
    res = HcfAsyKeyGeneratorBySpecCreate(paramSpec, &generator);

    HcfPriKey *priKey = nullptr;
    res = generator->generatePriKey(generator, &priKey);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(priKey, nullptr);

    HcfBigInteger retBigInt = { .data = nullptr, .len = 0 };
    AsyKeySpecItem item = ECC_H_INT;

    res = priKey->getAsyKeySpecBigInteger(priKey, item, &retBigInt);

    ASSERT_NE(res, HCF_SUCCESS);
    ASSERT_EQ(retBigInt.data, nullptr);
    ASSERT_EQ(retBigInt.len, 0);

    HcfObjDestroy(priKey);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoEccAsyKeyGeneratorBySpecSubThreeTest, CryptoEccAsyKeyGeneratorBySpecSubThreeTest416_5, TestSize.Level0)
{
    HcfAsyKeyParamsSpec *paramSpec = nullptr;
    int32_t res = ConstructEcc224KeyPairParamsSpec(&paramSpec);

    ASSERT_EQ(res, HCF_SUCCESS);

    HcfAsyKeyGeneratorBySpec *generator = nullptr;
    res = HcfAsyKeyGeneratorBySpecCreate(paramSpec, &generator);

    HcfPriKey *priKey = nullptr;
    res = generator->generatePriKey(generator, &priKey);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(priKey, nullptr);

    HcfBigInteger retBigInt = { .data = nullptr, .len = 0 };
    AsyKeySpecItem item = ECC_PK_X_BN;

    res = priKey->getAsyKeySpecBigInteger(priKey, item, &retBigInt);

    ASSERT_NE(res, HCF_SUCCESS);
    ASSERT_EQ(retBigInt.data, nullptr);
    ASSERT_EQ(retBigInt.len, 0);

    HcfObjDestroy(priKey);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoEccAsyKeyGeneratorBySpecSubThreeTest, CryptoEccAsyKeyGeneratorBySpecSubThreeTest416_6, TestSize.Level0)
{
    HcfAsyKeyParamsSpec *paramSpec = nullptr;
    int32_t res = ConstructEcc224KeyPairParamsSpec(&paramSpec);

    ASSERT_EQ(res, HCF_SUCCESS);

    HcfAsyKeyGeneratorBySpec *generator = nullptr;
    res = HcfAsyKeyGeneratorBySpecCreate(paramSpec, &generator);

    HcfPubKey *pubKey = nullptr;
    res = generator->generatePubKey(generator, &pubKey);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(pubKey, nullptr);

    HcfBigInteger retBigInt = { .data = nullptr, .len = 0 };
    AsyKeySpecItem item = ECC_SK_BN;

    res = pubKey->getAsyKeySpecBigInteger(pubKey, item, &retBigInt);

    ASSERT_NE(res, HCF_SUCCESS);
    ASSERT_EQ(retBigInt.data, nullptr);
    ASSERT_EQ(retBigInt.len, 0);

    HcfObjDestroy(pubKey);
    HcfObjDestroy(generator);
}
// for test:测试Convert功能（新增的BySpec无此convert函数，但是需要测试旧版convert后密钥Key的get方法，因此先保留此部分，后续改动）
// for test:测试convertKey以后的函数指针功能
HWTEST_F(CryptoEccAsyKeyGeneratorBySpecSubThreeTest, CryptoEccAsyKeyGeneratorBySpecSubThreeTest501, TestSize.Level0)
{
    HcfAsyKeyGenerator *generator = nullptr;
    int32_t res = HcfAsyKeyGeneratorCreate("ECC224", &generator);

    HcfKeyPair *keyPair = nullptr;
    res = generator->convertKey(generator, nullptr, &g_mockEcc224PubKeyBlob, &g_mockEcc224PriKeyBlob, &keyPair);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(keyPair, nullptr);

    HcfBigInteger retBigInt = { .data = nullptr, .len = 0 };
    AsyKeySpecItem item = ECC_FP_P_BN;

    res = keyPair->pubKey->getAsyKeySpecBigInteger(keyPair->pubKey, item, &retBigInt);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(retBigInt.data, nullptr);
    ASSERT_NE(retBigInt.len, 0);

    HcfFree(retBigInt.data);

    HcfObjDestroy(keyPair);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoEccAsyKeyGeneratorBySpecSubThreeTest, CryptoEccAsyKeyGeneratorBySpecSubThreeTest502, TestSize.Level0)
{
    HcfAsyKeyGenerator *generator = nullptr;
    int32_t res = HcfAsyKeyGeneratorCreate("ECC224", &generator);

    HcfKeyPair *keyPair = nullptr;
    res = generator->convertKey(generator, nullptr, &g_mockEcc224PubKeyBlob, &g_mockEcc224PriKeyBlob, &keyPair);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(keyPair, nullptr);

    HcfBigInteger retBigInt = { .data = nullptr, .len = 0 };
    AsyKeySpecItem item = ECC_FP_P_BN;

    res = keyPair->priKey->getAsyKeySpecBigInteger(keyPair->priKey, item, &retBigInt);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(retBigInt.data, nullptr);
    ASSERT_NE(retBigInt.len, 0);

    HcfFree(retBigInt.data);

    HcfObjDestroy(keyPair);
    HcfObjDestroy(generator);
}

// for test:ECC_A_BN
HWTEST_F(CryptoEccAsyKeyGeneratorBySpecSubThreeTest, CryptoEccAsyKeyGeneratorBySpecSubThreeTest503, TestSize.Level0)
{
    HcfAsyKeyGenerator *generator = nullptr;
    int32_t res = HcfAsyKeyGeneratorCreate("ECC224", &generator);

    HcfKeyPair *keyPair = nullptr;
    res = generator->convertKey(generator, nullptr, &g_mockEcc224PubKeyBlob, &g_mockEcc224PriKeyBlob, &keyPair);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(keyPair, nullptr);

    HcfBigInteger retBigInt = { .data = nullptr, .len = 0 };
    AsyKeySpecItem item = ECC_A_BN;

    res = keyPair->pubKey->getAsyKeySpecBigInteger(keyPair->pubKey, item, &retBigInt);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(retBigInt.data, nullptr);
    ASSERT_NE(retBigInt.len, 0);

    HcfFree(retBigInt.data);

    HcfObjDestroy(keyPair);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoEccAsyKeyGeneratorBySpecSubThreeTest, CryptoEccAsyKeyGeneratorBySpecSubThreeTest504, TestSize.Level0)
{
    HcfAsyKeyGenerator *generator = nullptr;
    int32_t res = HcfAsyKeyGeneratorCreate("ECC224", &generator);

    HcfKeyPair *keyPair = nullptr;
    res = generator->convertKey(generator, nullptr, &g_mockEcc224PubKeyBlob, &g_mockEcc224PriKeyBlob, &keyPair);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(keyPair, nullptr);

    HcfBigInteger retBigInt = { .data = nullptr, .len = 0 };
    AsyKeySpecItem item = ECC_A_BN;

    res = keyPair->priKey->getAsyKeySpecBigInteger(keyPair->priKey, item, &retBigInt);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(retBigInt.data, nullptr);
    ASSERT_NE(retBigInt.len, 0);

    HcfFree(retBigInt.data);

    HcfObjDestroy(keyPair);
    HcfObjDestroy(generator);
}

// for test:ECC_B_BN
HWTEST_F(CryptoEccAsyKeyGeneratorBySpecSubThreeTest, CryptoEccAsyKeyGeneratorBySpecSubThreeTest505, TestSize.Level0)
{
    HcfAsyKeyGenerator *generator = nullptr;
    int32_t res = HcfAsyKeyGeneratorCreate("ECC224", &generator);

    HcfKeyPair *keyPair = nullptr;
    res = generator->convertKey(generator, nullptr, &g_mockEcc224PubKeyBlob, &g_mockEcc224PriKeyBlob, &keyPair);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(keyPair, nullptr);

    HcfBigInteger retBigInt = { .data = nullptr, .len = 0 };
    AsyKeySpecItem item = ECC_B_BN;

    res = keyPair->pubKey->getAsyKeySpecBigInteger(keyPair->pubKey, item, &retBigInt);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(retBigInt.data, nullptr);
    ASSERT_NE(retBigInt.len, 0);

    HcfFree(retBigInt.data);

    HcfObjDestroy(keyPair);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoEccAsyKeyGeneratorBySpecSubThreeTest, CryptoEccAsyKeyGeneratorBySpecSubThreeTest506, TestSize.Level0)
{
    HcfAsyKeyGenerator *generator = nullptr;
    int32_t res = HcfAsyKeyGeneratorCreate("ECC224", &generator);

    HcfKeyPair *keyPair = nullptr;
    res = generator->convertKey(generator, nullptr, &g_mockEcc224PubKeyBlob, &g_mockEcc224PriKeyBlob, &keyPair);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(keyPair, nullptr);

    HcfBigInteger retBigInt = { .data = nullptr, .len = 0 };
    AsyKeySpecItem item = ECC_B_BN;

    res = keyPair->priKey->getAsyKeySpecBigInteger(keyPair->priKey, item, &retBigInt);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(retBigInt.data, nullptr);
    ASSERT_NE(retBigInt.len, 0);

    HcfFree(retBigInt.data);

    HcfObjDestroy(keyPair);
    HcfObjDestroy(generator);
}

// for test:ECC_G_X_BN
HWTEST_F(CryptoEccAsyKeyGeneratorBySpecSubThreeTest, CryptoEccAsyKeyGeneratorBySpecSubThreeTest507, TestSize.Level0)
{
    HcfAsyKeyGenerator *generator = nullptr;
    int32_t res = HcfAsyKeyGeneratorCreate("ECC224", &generator);

    HcfKeyPair *keyPair = nullptr;
    res = generator->convertKey(generator, nullptr, &g_mockEcc224PubKeyBlob, &g_mockEcc224PriKeyBlob, &keyPair);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(keyPair, nullptr);

    HcfBigInteger retBigInt = { .data = nullptr, .len = 0 };
    AsyKeySpecItem item = ECC_G_X_BN;

    res = keyPair->pubKey->getAsyKeySpecBigInteger(keyPair->pubKey, item, &retBigInt);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(retBigInt.data, nullptr);
    ASSERT_NE(retBigInt.len, 0);

    HcfFree(retBigInt.data);

    HcfObjDestroy(keyPair);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoEccAsyKeyGeneratorBySpecSubThreeTest, CryptoEccAsyKeyGeneratorBySpecSubThreeTest508, TestSize.Level0)
{
    HcfAsyKeyGenerator *generator = nullptr;
    int32_t res = HcfAsyKeyGeneratorCreate("ECC224", &generator);

    HcfKeyPair *keyPair = nullptr;
    res = generator->convertKey(generator, nullptr, &g_mockEcc224PubKeyBlob, &g_mockEcc224PriKeyBlob, &keyPair);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(keyPair, nullptr);

    HcfBigInteger retBigInt = { .data = nullptr, .len = 0 };
    AsyKeySpecItem item = ECC_G_X_BN;

    res = keyPair->priKey->getAsyKeySpecBigInteger(keyPair->priKey, item, &retBigInt);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(retBigInt.data, nullptr);
    ASSERT_NE(retBigInt.len, 0);

    HcfFree(retBigInt.data);

    HcfObjDestroy(keyPair);
    HcfObjDestroy(generator);
}

// for test:ECC_G_Y_BN
HWTEST_F(CryptoEccAsyKeyGeneratorBySpecSubThreeTest, CryptoEccAsyKeyGeneratorBySpecSubThreeTest509, TestSize.Level0)
{
    HcfAsyKeyGenerator *generator = nullptr;
    int32_t res = HcfAsyKeyGeneratorCreate("ECC224", &generator);

    HcfKeyPair *keyPair = nullptr;
    res = generator->convertKey(generator, nullptr, &g_mockEcc224PubKeyBlob, &g_mockEcc224PriKeyBlob, &keyPair);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(keyPair, nullptr);

    HcfBigInteger retBigInt = { .data = nullptr, .len = 0 };
    AsyKeySpecItem item = ECC_G_Y_BN;

    res = keyPair->pubKey->getAsyKeySpecBigInteger(keyPair->pubKey, item, &retBigInt);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(retBigInt.data, nullptr);
    ASSERT_NE(retBigInt.len, 0);

    HcfFree(retBigInt.data);

    HcfObjDestroy(keyPair);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoEccAsyKeyGeneratorBySpecSubThreeTest, CryptoEccAsyKeyGeneratorBySpecSubThreeTest510, TestSize.Level0)
{
    HcfAsyKeyGenerator *generator = nullptr;
    int32_t res = HcfAsyKeyGeneratorCreate("ECC224", &generator);

    HcfKeyPair *keyPair = nullptr;
    res = generator->convertKey(generator, nullptr, &g_mockEcc224PubKeyBlob, &g_mockEcc224PriKeyBlob, &keyPair);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(keyPair, nullptr);

    HcfBigInteger retBigInt = { .data = nullptr, .len = 0 };
    AsyKeySpecItem item = ECC_G_Y_BN;

    res = keyPair->priKey->getAsyKeySpecBigInteger(keyPair->priKey, item, &retBigInt);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(retBigInt.data, nullptr);
    ASSERT_NE(retBigInt.len, 0);

    HcfFree(retBigInt.data);

    HcfObjDestroy(keyPair);
    HcfObjDestroy(generator);
}

// for test:ECC_N_BN
HWTEST_F(CryptoEccAsyKeyGeneratorBySpecSubThreeTest, CryptoEccAsyKeyGeneratorBySpecSubThreeTest511, TestSize.Level0)
{
    HcfAsyKeyGenerator *generator = nullptr;
    int32_t res = HcfAsyKeyGeneratorCreate("ECC224", &generator);

    HcfKeyPair *keyPair = nullptr;
    res = generator->convertKey(generator, nullptr, &g_mockEcc224PubKeyBlob, &g_mockEcc224PriKeyBlob, &keyPair);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(keyPair, nullptr);

    HcfBigInteger retBigInt = { .data = nullptr, .len = 0 };
    AsyKeySpecItem item = ECC_N_BN;

    res = keyPair->pubKey->getAsyKeySpecBigInteger(keyPair->pubKey, item, &retBigInt);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(retBigInt.data, nullptr);
    ASSERT_NE(retBigInt.len, 0);

    HcfFree(retBigInt.data);

    HcfObjDestroy(keyPair);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoEccAsyKeyGeneratorBySpecSubThreeTest, CryptoEccAsyKeyGeneratorBySpecSubThreeTest512, TestSize.Level0)
{
    HcfAsyKeyGenerator *generator = nullptr;
    int32_t res = HcfAsyKeyGeneratorCreate("ECC224", &generator);

    HcfKeyPair *keyPair = nullptr;
    res = generator->convertKey(generator, nullptr, &g_mockEcc224PubKeyBlob, &g_mockEcc224PriKeyBlob, &keyPair);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(keyPair, nullptr);

    HcfBigInteger retBigInt = { .data = nullptr, .len = 0 };
    AsyKeySpecItem item = ECC_N_BN;

    res = keyPair->priKey->getAsyKeySpecBigInteger(keyPair->priKey, item, &retBigInt);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(retBigInt.data, nullptr);
    ASSERT_NE(retBigInt.len, 0);

    HcfFree(retBigInt.data);

    HcfObjDestroy(keyPair);
    HcfObjDestroy(generator);
}

// for test:ECC_H_INT
HWTEST_F(CryptoEccAsyKeyGeneratorBySpecSubThreeTest, CryptoEccAsyKeyGeneratorBySpecSubThreeTest513, TestSize.Level0)
{
    HcfAsyKeyGenerator *generator = nullptr;
    int32_t res = HcfAsyKeyGeneratorCreate("ECC224", &generator);

    HcfKeyPair *keyPair = nullptr;
    res = generator->convertKey(generator, nullptr, &g_mockEcc224PubKeyBlob, &g_mockEcc224PriKeyBlob, &keyPair);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(keyPair, nullptr);

    int retInt = 0;
    AsyKeySpecItem item = ECC_H_INT;

    res = keyPair->pubKey->getAsyKeySpecInt(keyPair->pubKey, item, &retInt);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(retInt, 0);

    HcfObjDestroy(keyPair);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoEccAsyKeyGeneratorBySpecSubThreeTest, CryptoEccAsyKeyGeneratorBySpecSubThreeTest514, TestSize.Level0)
{
    HcfAsyKeyGenerator *generator = nullptr;
    int32_t res = HcfAsyKeyGeneratorCreate("ECC224", &generator);

    HcfKeyPair *keyPair = nullptr;
    res = generator->convertKey(generator, nullptr, &g_mockEcc224PubKeyBlob, &g_mockEcc224PriKeyBlob, &keyPair);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(keyPair, nullptr);

    int retInt = 0;
    AsyKeySpecItem item = ECC_H_INT;

    res = keyPair->priKey->getAsyKeySpecInt(keyPair->priKey, item, &retInt);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(retInt, 0);

    HcfObjDestroy(keyPair);
    HcfObjDestroy(generator);
}

// for test:ECC_FIELD_SIZE_INT
HWTEST_F(CryptoEccAsyKeyGeneratorBySpecSubThreeTest, CryptoEccAsyKeyGeneratorBySpecSubThreeTest515, TestSize.Level0)
{
    HcfAsyKeyGenerator *generator = nullptr;
    int32_t res = HcfAsyKeyGeneratorCreate("ECC224", &generator);

    HcfKeyPair *keyPair = nullptr;
    res = generator->convertKey(generator, nullptr, &g_mockEcc224PubKeyBlob, &g_mockEcc224PriKeyBlob, &keyPair);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(keyPair, nullptr);

    int retInt = 0;
    AsyKeySpecItem item = ECC_FIELD_SIZE_INT;

    res = keyPair->pubKey->getAsyKeySpecInt(keyPair->pubKey, item, &retInt);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(retInt, 0);

    HcfObjDestroy(keyPair);
    HcfObjDestroy(generator);
}
}
