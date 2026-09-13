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
class CryptoEccAsyKeyGeneratorBySpecSubOneTest : public testing::Test {
public:
    static void SetUpTestCase() {};
    static void TearDownTestCase() {};
    void SetUp() {};
    void TearDown() {};
};

static const char *GetMockClass(void)
{
    return "HcfSymKeyGenerator";
}

HcfObjectBase g_obj = {
    .getClass = GetMockClass,
    .destroy = nullptr
};

HWTEST_F(CryptoEccAsyKeyGeneratorBySpecSubOneTest, CryptoEccAsyKeyGeneratorBySpecSubOneTest314_1, TestSize.Level0)
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

    HcfBlob blob = { .data = nullptr, .len = 0 };
    res = keyPair->pubKey->base.getEncoded(&(keyPair->pubKey->base), &blob);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(blob.data, nullptr);
    ASSERT_NE(blob.len, 0);

    HcfFree(blob.data);

    HcfObjDestroy(keyPair);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoEccAsyKeyGeneratorBySpecSubOneTest, CryptoEccAsyKeyGeneratorBySpecSubOneTest314_2, TestSize.Level0)
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

    HcfBlob blob = { .data = nullptr, .len = 0 };
    res = pubKey->base.getEncoded(&(pubKey->base), &blob);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(blob.data, nullptr);
    ASSERT_NE(blob.len, 0);

    HcfFree(blob.data);

    HcfObjDestroy(pubKey);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoEccAsyKeyGeneratorBySpecSubOneTest, CryptoEccAsyKeyGeneratorBySpecSubOneTest314_3, TestSize.Level0)
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

    HcfBlob blob = { .data = nullptr, .len = 0 };
    res = priKey->base.getEncoded(&(priKey->base), &blob);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(blob.data, nullptr);
    ASSERT_NE(blob.len, 0);

    HcfFree(blob.data);

    HcfObjDestroy(priKey);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoEccAsyKeyGeneratorBySpecSubOneTest, CryptoEccAsyKeyGeneratorBySpecSubOneTest314_4, TestSize.Level0)
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

    HcfBlob blob = { .data = nullptr, .len = 0 };
    res = keyPair->pubKey->base.getEncoded(&(keyPair->pubKey->base), &blob);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(blob.data, nullptr);
    ASSERT_NE(blob.len, 0);

    HcfFree(blob.data);

    HcfObjDestroy(keyPair);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoEccAsyKeyGeneratorBySpecSubOneTest, CryptoEccAsyKeyGeneratorBySpecSubOneTest314_5, TestSize.Level0)
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

    HcfBlob blob = { .data = nullptr, .len = 0 };
    res = pubKey->base.getEncoded(&(pubKey->base), &blob);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(blob.data, nullptr);
    ASSERT_NE(blob.len, 0);

    HcfFree(blob.data);

    HcfObjDestroy(pubKey);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoEccAsyKeyGeneratorBySpecSubOneTest, CryptoEccAsyKeyGeneratorBySpecSubOneTest314_6, TestSize.Level0)
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

    HcfBlob blob = { .data = nullptr, .len = 0 };
    res = priKey->base.getEncoded(&(priKey->base), &blob);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(blob.data, nullptr);
    ASSERT_NE(blob.len, 0);

    HcfFree(blob.data);

    HcfObjDestroy(priKey);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoEccAsyKeyGeneratorBySpecSubOneTest, CryptoEccAsyKeyGeneratorBySpecSubOneTest314_7, TestSize.Level0)
{
    HcfAsyKeyParamsSpec *paramSpec = nullptr;
    int32_t res = ConstructEcc256CommParamsSpec(&paramSpec);

    ASSERT_EQ(res, HCF_SUCCESS);

    HcfAsyKeyGeneratorBySpec *generator = nullptr;
    res = HcfAsyKeyGeneratorBySpecCreate(paramSpec, &generator);

    HcfKeyPair *keyPair = nullptr;
    res = generator->generateKeyPair(generator, &keyPair);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(keyPair, nullptr);

    HcfBlob blob = { .data = nullptr, .len = 0 };
    res = keyPair->pubKey->base.getEncoded(&(keyPair->pubKey->base), &blob);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(blob.data, nullptr);
    ASSERT_NE(blob.len, 0);

    HcfFree(blob.data);

    HcfObjDestroy(keyPair);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoEccAsyKeyGeneratorBySpecSubOneTest, CryptoEccAsyKeyGeneratorBySpecSubOneTest314_8, TestSize.Level0)
{
    HcfAsyKeyParamsSpec *paramSpec = nullptr;
    int32_t res = ConstructEcc256PubKeyParamsSpec(&paramSpec);

    ASSERT_EQ(res, HCF_SUCCESS);

    HcfAsyKeyGeneratorBySpec *generator = nullptr;
    res = HcfAsyKeyGeneratorBySpecCreate(paramSpec, &generator);

    HcfPubKey *pubKey = nullptr;
    res = generator->generatePubKey(generator, &pubKey);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(pubKey, nullptr);

    HcfBlob blob = { .data = nullptr, .len = 0 };
    res = pubKey->base.getEncoded(&(pubKey->base), &blob);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(blob.data, nullptr);
    ASSERT_NE(blob.len, 0);

    HcfFree(blob.data);

    HcfObjDestroy(pubKey);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoEccAsyKeyGeneratorBySpecSubOneTest, CryptoEccAsyKeyGeneratorBySpecSubOneTest314_9, TestSize.Level0)
{
    HcfAsyKeyParamsSpec *paramSpec = nullptr;
    int32_t res = ConstructEcc256PriKeyParamsSpec(&paramSpec);

    ASSERT_EQ(res, HCF_SUCCESS);

    HcfAsyKeyGeneratorBySpec *generator = nullptr;
    res = HcfAsyKeyGeneratorBySpecCreate(paramSpec, &generator);

    HcfPriKey *priKey = nullptr;
    res = generator->generatePriKey(generator, &priKey);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(priKey, nullptr);

    HcfBlob blob = { .data = nullptr, .len = 0 };
    res = priKey->base.getEncoded(&(priKey->base), &blob);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(blob.data, nullptr);
    ASSERT_NE(blob.len, 0);

    HcfFree(blob.data);

    HcfObjDestroy(priKey);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoEccAsyKeyGeneratorBySpecSubOneTest, CryptoEccAsyKeyGeneratorBySpecSubOneTest314_10, TestSize.Level0)
{
    HcfAsyKeyParamsSpec *paramSpec = nullptr;
    int32_t res = ConstructEcc256KeyPairParamsSpec(&paramSpec);

    ASSERT_EQ(res, HCF_SUCCESS);

    HcfAsyKeyGeneratorBySpec *generator = nullptr;
    res = HcfAsyKeyGeneratorBySpecCreate(paramSpec, &generator);

    HcfKeyPair *keyPair = nullptr;
    res = generator->generateKeyPair(generator, &keyPair);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(keyPair, nullptr);

    HcfBlob blob = { .data = nullptr, .len = 0 };
    res = keyPair->pubKey->base.getEncoded(&(keyPair->pubKey->base), &blob);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(blob.data, nullptr);
    ASSERT_NE(blob.len, 0);

    HcfFree(blob.data);

    HcfObjDestroy(keyPair);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoEccAsyKeyGeneratorBySpecSubOneTest, CryptoEccAsyKeyGeneratorBySpecSubOneTest314_11, TestSize.Level0)
{
    HcfAsyKeyParamsSpec *paramSpec = nullptr;
    int32_t res = ConstructEcc256KeyPairParamsSpec(&paramSpec);

    ASSERT_EQ(res, HCF_SUCCESS);

    HcfAsyKeyGeneratorBySpec *generator = nullptr;
    res = HcfAsyKeyGeneratorBySpecCreate(paramSpec, &generator);

    HcfPubKey *pubKey = nullptr;
    res = generator->generatePubKey(generator, &pubKey);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(pubKey, nullptr);

    HcfBlob blob = { .data = nullptr, .len = 0 };
    res = pubKey->base.getEncoded(&(pubKey->base), &blob);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(blob.data, nullptr);
    ASSERT_NE(blob.len, 0);

    HcfFree(blob.data);

    HcfObjDestroy(pubKey);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoEccAsyKeyGeneratorBySpecSubOneTest, CryptoEccAsyKeyGeneratorBySpecSubOneTest314_12, TestSize.Level0)
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

    HcfBlob blob = { .data = nullptr, .len = 0 };
    res = priKey->base.getEncoded(&(priKey->base), &blob);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(blob.data, nullptr);
    ASSERT_NE(blob.len, 0);

    HcfFree(blob.data);

    HcfObjDestroy(priKey);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoEccAsyKeyGeneratorBySpecSubOneTest, CryptoEccAsyKeyGeneratorBySpecSubOneTest314_13, TestSize.Level0)
{
    HcfAsyKeyParamsSpec *paramSpec = nullptr;
    int32_t res = ConstructEcc384CommParamsSpec(&paramSpec);

    ASSERT_EQ(res, HCF_SUCCESS);

    HcfAsyKeyGeneratorBySpec *generator = nullptr;
    res = HcfAsyKeyGeneratorBySpecCreate(paramSpec, &generator);

    HcfKeyPair *keyPair = nullptr;
    res = generator->generateKeyPair(generator, &keyPair);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(keyPair, nullptr);

    HcfBlob blob = { .data = nullptr, .len = 0 };
    res = keyPair->pubKey->base.getEncoded(&(keyPair->pubKey->base), &blob);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(blob.data, nullptr);
    ASSERT_NE(blob.len, 0);

    HcfFree(blob.data);

    HcfObjDestroy(keyPair);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoEccAsyKeyGeneratorBySpecSubOneTest, CryptoEccAsyKeyGeneratorBySpecSubOneTest314_14, TestSize.Level0)
{
    HcfAsyKeyParamsSpec *paramSpec = nullptr;
    int32_t res = ConstructEcc384PubKeyParamsSpec(&paramSpec);

    ASSERT_EQ(res, HCF_SUCCESS);

    HcfAsyKeyGeneratorBySpec *generator = nullptr;
    res = HcfAsyKeyGeneratorBySpecCreate(paramSpec, &generator);

    HcfPubKey *pubKey = nullptr;
    res = generator->generatePubKey(generator, &pubKey);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(pubKey, nullptr);

    HcfBlob blob = { .data = nullptr, .len = 0 };
    res = pubKey->base.getEncoded(&(pubKey->base), &blob);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(blob.data, nullptr);
    ASSERT_NE(blob.len, 0);

    HcfFree(blob.data);

    HcfObjDestroy(pubKey);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoEccAsyKeyGeneratorBySpecSubOneTest, CryptoEccAsyKeyGeneratorBySpecSubOneTest314_15, TestSize.Level0)
{
    HcfAsyKeyParamsSpec *paramSpec = nullptr;
    int32_t res = ConstructEcc384PriKeyParamsSpec(&paramSpec);

    ASSERT_EQ(res, HCF_SUCCESS);

    HcfAsyKeyGeneratorBySpec *generator = nullptr;
    res = HcfAsyKeyGeneratorBySpecCreate(paramSpec, &generator);

    HcfPriKey *priKey = nullptr;
    res = generator->generatePriKey(generator, &priKey);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(priKey, nullptr);

    HcfBlob blob = { .data = nullptr, .len = 0 };
    res = priKey->base.getEncoded(&(priKey->base), &blob);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(blob.data, nullptr);
    ASSERT_NE(blob.len, 0);

    HcfFree(blob.data);

    HcfObjDestroy(priKey);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoEccAsyKeyGeneratorBySpecSubOneTest, CryptoEccAsyKeyGeneratorBySpecSubOneTest314_16, TestSize.Level0)
{
    HcfAsyKeyParamsSpec *paramSpec = nullptr;
    int32_t res = ConstructEcc384KeyPairParamsSpec(&paramSpec);

    ASSERT_EQ(res, HCF_SUCCESS);

    HcfAsyKeyGeneratorBySpec *generator = nullptr;
    res = HcfAsyKeyGeneratorBySpecCreate(paramSpec, &generator);

    HcfKeyPair *keyPair = nullptr;
    res = generator->generateKeyPair(generator, &keyPair);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(keyPair, nullptr);

    HcfBlob blob = { .data = nullptr, .len = 0 };
    res = keyPair->pubKey->base.getEncoded(&(keyPair->pubKey->base), &blob);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(blob.data, nullptr);
    ASSERT_NE(blob.len, 0);

    HcfFree(blob.data);

    HcfObjDestroy(keyPair);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoEccAsyKeyGeneratorBySpecSubOneTest, CryptoEccAsyKeyGeneratorBySpecSubOneTest314_17, TestSize.Level0)
{
    HcfAsyKeyParamsSpec *paramSpec = nullptr;
    int32_t res = ConstructEcc384KeyPairParamsSpec(&paramSpec);

    ASSERT_EQ(res, HCF_SUCCESS);

    HcfAsyKeyGeneratorBySpec *generator = nullptr;
    res = HcfAsyKeyGeneratorBySpecCreate(paramSpec, &generator);

    HcfPubKey *pubKey = nullptr;
    res = generator->generatePubKey(generator, &pubKey);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(pubKey, nullptr);

    HcfBlob blob = { .data = nullptr, .len = 0 };
    res = pubKey->base.getEncoded(&(pubKey->base), &blob);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(blob.data, nullptr);
    ASSERT_NE(blob.len, 0);

    HcfFree(blob.data);

    HcfObjDestroy(pubKey);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoEccAsyKeyGeneratorBySpecSubOneTest, CryptoEccAsyKeyGeneratorBySpecSubOneTest314_18, TestSize.Level0)
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

    HcfBlob blob = { .data = nullptr, .len = 0 };
    res = priKey->base.getEncoded(&(priKey->base), &blob);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(blob.data, nullptr);
    ASSERT_NE(blob.len, 0);

    HcfFree(blob.data);

    HcfObjDestroy(priKey);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoEccAsyKeyGeneratorBySpecSubOneTest, CryptoEccAsyKeyGeneratorBySpecSubOneTest314_19, TestSize.Level0)
{
    HcfAsyKeyParamsSpec *paramSpec = nullptr;
    int32_t res = ConstructEcc521CommParamsSpec(&paramSpec);

    ASSERT_EQ(res, HCF_SUCCESS);

    HcfAsyKeyGeneratorBySpec *generator = nullptr;
    res = HcfAsyKeyGeneratorBySpecCreate(paramSpec, &generator);

    HcfKeyPair *keyPair = nullptr;
    res = generator->generateKeyPair(generator, &keyPair);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(keyPair, nullptr);

    HcfBlob blob = { .data = nullptr, .len = 0 };
    res = keyPair->pubKey->base.getEncoded(&(keyPair->pubKey->base), &blob);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(blob.data, nullptr);
    ASSERT_NE(blob.len, 0);

    HcfFree(blob.data);

    HcfObjDestroy(keyPair);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoEccAsyKeyGeneratorBySpecSubOneTest, CryptoEccAsyKeyGeneratorBySpecSubOneTest314_20, TestSize.Level0)
{
    HcfAsyKeyParamsSpec *paramSpec = nullptr;
    int32_t res = ConstructEcc521PubKeyParamsSpec(&paramSpec);

    ASSERT_EQ(res, HCF_SUCCESS);

    HcfAsyKeyGeneratorBySpec *generator = nullptr;
    res = HcfAsyKeyGeneratorBySpecCreate(paramSpec, &generator);

    HcfPubKey *pubKey = nullptr;
    res = generator->generatePubKey(generator, &pubKey);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(pubKey, nullptr);

    HcfBlob blob = { .data = nullptr, .len = 0 };
    res = pubKey->base.getEncoded(&(pubKey->base), &blob);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(blob.data, nullptr);
    ASSERT_NE(blob.len, 0);

    HcfFree(blob.data);

    HcfObjDestroy(pubKey);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoEccAsyKeyGeneratorBySpecSubOneTest, CryptoEccAsyKeyGeneratorBySpecSubOneTest314_21, TestSize.Level0)
{
    HcfAsyKeyParamsSpec *paramSpec = nullptr;
    int32_t res = ConstructEcc521PriKeyParamsSpec(&paramSpec);

    ASSERT_EQ(res, HCF_SUCCESS);

    HcfAsyKeyGeneratorBySpec *generator = nullptr;
    res = HcfAsyKeyGeneratorBySpecCreate(paramSpec, &generator);

    HcfPriKey *priKey = nullptr;
    res = generator->generatePriKey(generator, &priKey);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(priKey, nullptr);

    HcfBlob blob = { .data = nullptr, .len = 0 };
    res = priKey->base.getEncoded(&(priKey->base), &blob);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(blob.data, nullptr);
    ASSERT_NE(blob.len, 0);

    HcfFree(blob.data);

    HcfObjDestroy(priKey);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoEccAsyKeyGeneratorBySpecSubOneTest, CryptoEccAsyKeyGeneratorBySpecSubOneTest314_22, TestSize.Level0)
{
    HcfAsyKeyParamsSpec *paramSpec = nullptr;
    int32_t res = ConstructEcc521KeyPairParamsSpec(&paramSpec);

    ASSERT_EQ(res, HCF_SUCCESS);

    HcfAsyKeyGeneratorBySpec *generator = nullptr;
    res = HcfAsyKeyGeneratorBySpecCreate(paramSpec, &generator);

    HcfKeyPair *keyPair = nullptr;
    res = generator->generateKeyPair(generator, &keyPair);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(keyPair, nullptr);

    HcfBlob blob = { .data = nullptr, .len = 0 };
    res = keyPair->pubKey->base.getEncoded(&(keyPair->pubKey->base), &blob);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(blob.data, nullptr);
    ASSERT_NE(blob.len, 0);

    HcfFree(blob.data);

    HcfObjDestroy(keyPair);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoEccAsyKeyGeneratorBySpecSubOneTest, CryptoEccAsyKeyGeneratorBySpecSubOneTest314_23, TestSize.Level0)
{
    HcfAsyKeyParamsSpec *paramSpec = nullptr;
    int32_t res = ConstructEcc521KeyPairParamsSpec(&paramSpec);

    ASSERT_EQ(res, HCF_SUCCESS);

    HcfAsyKeyGeneratorBySpec *generator = nullptr;
    res = HcfAsyKeyGeneratorBySpecCreate(paramSpec, &generator);

    HcfPubKey *pubKey = nullptr;
    res = generator->generatePubKey(generator, &pubKey);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(pubKey, nullptr);

    HcfBlob blob = { .data = nullptr, .len = 0 };
    res = pubKey->base.getEncoded(&(pubKey->base), &blob);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(blob.data, nullptr);
    ASSERT_NE(blob.len, 0);

    HcfFree(blob.data);

    HcfObjDestroy(pubKey);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoEccAsyKeyGeneratorBySpecSubOneTest, CryptoEccAsyKeyGeneratorBySpecSubOneTest314_24, TestSize.Level0)
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

    HcfBlob blob = { .data = nullptr, .len = 0 };
    res = priKey->base.getEncoded(&(priKey->base), &blob);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(blob.data, nullptr);
    ASSERT_NE(blob.len, 0);

    HcfFree(blob.data);

    HcfObjDestroy(priKey);
    HcfObjDestroy(generator);
}

// for test:测试keyPair的函数指针（异常）
HWTEST_F(CryptoEccAsyKeyGeneratorBySpecSubOneTest, CryptoEccAsyKeyGeneratorBySpecSubOneTest315, TestSize.Level0)
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

    HcfBlob blob = { .data = nullptr, .len = 0 };
    res = keyPair->pubKey->base.getEncoded(nullptr, &blob);

    ASSERT_NE(res, HCF_SUCCESS);
    ASSERT_EQ(blob.data, nullptr);
    ASSERT_EQ(blob.len, 0);

    HcfObjDestroy(keyPair);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoEccAsyKeyGeneratorBySpecSubOneTest, CryptoEccAsyKeyGeneratorBySpecSubOneTest316, TestSize.Level0)
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

    HcfBlob blob = { .data = nullptr, .len = 0 };
    res = keyPair->pubKey->base.getEncoded((HcfKey *)&g_obj, &blob);

    ASSERT_NE(res, HCF_SUCCESS);
    ASSERT_EQ(blob.data, nullptr);
    ASSERT_EQ(blob.len, 0);

    HcfObjDestroy(keyPair);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoEccAsyKeyGeneratorBySpecSubOneTest, CryptoEccAsyKeyGeneratorBySpecSubOneTest317, TestSize.Level0)
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

    res = keyPair->pubKey->base.getEncoded(&(keyPair->pubKey->base), nullptr);

    ASSERT_NE(res, HCF_SUCCESS);

    HcfObjDestroy(keyPair);
    HcfObjDestroy(generator);
}

// for test:测试keyPair的函数指针（正常）
HWTEST_F(CryptoEccAsyKeyGeneratorBySpecSubOneTest, CryptoEccAsyKeyGeneratorBySpecSubOneTest318_1, TestSize.Level0)
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

    keyPair->priKey->clearMem(keyPair->priKey);

    HcfObjDestroy(keyPair);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoEccAsyKeyGeneratorBySpecSubOneTest, CryptoEccAsyKeyGeneratorBySpecSubOneTest318_2, TestSize.Level0)
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

    priKey->clearMem(priKey);

    HcfObjDestroy(priKey);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoEccAsyKeyGeneratorBySpecSubOneTest, CryptoEccAsyKeyGeneratorBySpecSubOneTest318_3, TestSize.Level0)
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

    keyPair->priKey->clearMem(keyPair->priKey);

    HcfObjDestroy(keyPair);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoEccAsyKeyGeneratorBySpecSubOneTest, CryptoEccAsyKeyGeneratorBySpecSubOneTest318_4, TestSize.Level0)
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

    priKey->clearMem(priKey);

    HcfObjDestroy(priKey);
    HcfObjDestroy(generator);
}

// for test:测试keyPair的函数指针（异常）
HWTEST_F(CryptoEccAsyKeyGeneratorBySpecSubOneTest, CryptoEccAsyKeyGeneratorBySpecSubOneTest319, TestSize.Level0)
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

    keyPair->priKey->clearMem(nullptr);

    HcfObjDestroy(keyPair);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoEccAsyKeyGeneratorBySpecSubOneTest, CryptoEccAsyKeyGeneratorBySpecSubOneTest320, TestSize.Level0)
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

    keyPair->priKey->clearMem((HcfPriKey *)&g_obj);

    HcfObjDestroy(keyPair);
    HcfObjDestroy(generator);
}

// for test:测试keyPair的函数指针（正常）
HWTEST_F(CryptoEccAsyKeyGeneratorBySpecSubOneTest, CryptoEccAsyKeyGeneratorBySpecSubOneTest321_1, TestSize.Level0)
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

    const char *algName = keyPair->priKey->base.base.getClass();

    ASSERT_NE(algName, nullptr);

    HcfObjDestroy(keyPair);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoEccAsyKeyGeneratorBySpecSubOneTest, CryptoEccAsyKeyGeneratorBySpecSubOneTest321_2, TestSize.Level0)
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

    const char *algName = keyPair->priKey->base.base.getClass();

    ASSERT_NE(algName, nullptr);

    HcfObjDestroy(keyPair);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoEccAsyKeyGeneratorBySpecSubOneTest, CryptoEccAsyKeyGeneratorBySpecSubOneTest322_3, TestSize.Level0)
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

    keyPair->priKey->base.base.destroy((HcfObjectBase *)(&(keyPair->priKey->base.base)));
    keyPair->priKey = nullptr;

    HcfObjDestroy(keyPair);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoEccAsyKeyGeneratorBySpecSubOneTest, CryptoEccAsyKeyGeneratorBySpecSubOneTest322_4, TestSize.Level0)
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

    keyPair->priKey->base.base.destroy((HcfObjectBase *)(&(keyPair->priKey->base.base)));
    keyPair->priKey = nullptr;

    HcfObjDestroy(keyPair);
    HcfObjDestroy(generator);
}

// for test:测试keyPair的函数指针（异常）
HWTEST_F(CryptoEccAsyKeyGeneratorBySpecSubOneTest, CryptoEccAsyKeyGeneratorBySpecSubOneTest323, TestSize.Level0)
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

    keyPair->priKey->base.base.destroy(nullptr);

    HcfObjDestroy(keyPair);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoEccAsyKeyGeneratorBySpecSubOneTest, CryptoEccAsyKeyGeneratorBySpecSubOneTest324, TestSize.Level0)
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

    keyPair->priKey->base.base.destroy(&g_obj);

    HcfObjDestroy(keyPair);
    HcfObjDestroy(generator);
}

// for test:测试keyPair的函数指针（正常）
HWTEST_F(CryptoEccAsyKeyGeneratorBySpecSubOneTest, CryptoEccAsyKeyGeneratorBySpecSubOneTest325_1, TestSize.Level0)
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

    const char *format = keyPair->priKey->base.getFormat(&keyPair->priKey->base);

    ASSERT_NE(format, nullptr);

    HcfObjDestroy(keyPair);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoEccAsyKeyGeneratorBySpecSubOneTest, CryptoEccAsyKeyGeneratorBySpecSubOneTest325_2, TestSize.Level0)
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

    const char *format = keyPair->priKey->base.getFormat(&keyPair->priKey->base);

    ASSERT_NE(format, nullptr);

    HcfObjDestroy(keyPair);
    HcfObjDestroy(generator);
}

// for test:测试keyPair的函数指针（异常）
HWTEST_F(CryptoEccAsyKeyGeneratorBySpecSubOneTest, CryptoEccAsyKeyGeneratorBySpecSubOneTest326, TestSize.Level0)
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

    const char *format = keyPair->priKey->base.getFormat(nullptr);

    ASSERT_EQ(format, nullptr);

    HcfObjDestroy(keyPair);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoEccAsyKeyGeneratorBySpecSubOneTest, CryptoEccAsyKeyGeneratorBySpecSubOneTest327, TestSize.Level0)
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

    const char *format = keyPair->priKey->base.getFormat((HcfKey *)&g_obj);

    ASSERT_EQ(format, nullptr);

    HcfObjDestroy(keyPair);
    HcfObjDestroy(generator);
}

// for test:测试keyPair的函数指针（正常）
HWTEST_F(CryptoEccAsyKeyGeneratorBySpecSubOneTest, CryptoEccAsyKeyGeneratorBySpecSubOneTest328_1, TestSize.Level0)
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

    const char *algName = keyPair->priKey->base.getAlgorithm(&keyPair->priKey->base);

    ASSERT_NE(algName, nullptr);

    HcfObjDestroy(keyPair);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoEccAsyKeyGeneratorBySpecSubOneTest, CryptoEccAsyKeyGeneratorBySpecSubOneTest328_2, TestSize.Level0)
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

    const char *algName = keyPair->priKey->base.getAlgorithm(&keyPair->priKey->base);

    ASSERT_NE(algName, nullptr);

    HcfObjDestroy(keyPair);
    HcfObjDestroy(generator);
}

// for test:测试keyPair的函数指针（异常）
HWTEST_F(CryptoEccAsyKeyGeneratorBySpecSubOneTest, CryptoEccAsyKeyGeneratorBySpecSubOneTest329, TestSize.Level0)
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

    const char *algName = keyPair->priKey->base.getAlgorithm(nullptr);

    ASSERT_EQ(algName, nullptr);

    HcfObjDestroy(keyPair);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoEccAsyKeyGeneratorBySpecSubOneTest, CryptoEccAsyKeyGeneratorBySpecSubOneTest330, TestSize.Level0)
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

    const char *algName = keyPair->priKey->base.getAlgorithm((HcfKey *)&g_obj);

    ASSERT_EQ(algName, nullptr);

    HcfObjDestroy(keyPair);
    HcfObjDestroy(generator);
}

// for test:测试keyPair的函数指针（正常）
HWTEST_F(CryptoEccAsyKeyGeneratorBySpecSubOneTest, CryptoEccAsyKeyGeneratorBySpecSubOneTest331_1, TestSize.Level0)
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

    HcfBlob blob = { .data = nullptr, .len = 0 };
    res = keyPair->priKey->base.getEncoded(&(keyPair->priKey->base), &blob);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(blob.data, nullptr);
    ASSERT_NE(blob.len, 0);

    HcfFree(blob.data);

    HcfObjDestroy(keyPair);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoEccAsyKeyGeneratorBySpecSubOneTest, CryptoEccAsyKeyGeneratorBySpecSubOneTest331_2, TestSize.Level0)
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

    HcfBlob blob = { .data = nullptr, .len = 0 };
    res = keyPair->priKey->base.getEncoded(&(keyPair->priKey->base), &blob);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(blob.data, nullptr);
    ASSERT_NE(blob.len, 0);

    HcfFree(blob.data);

    HcfObjDestroy(keyPair);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoEccAsyKeyGeneratorBySpecSubOneTest, CryptoEccAsyKeyGeneratorBySpecSubOneTest331_3, TestSize.Level0)
{
    HcfAsyKeyParamsSpec *paramSpec = nullptr;
    int32_t res = ConstructEcc256CommParamsSpec(&paramSpec);

    ASSERT_EQ(res, HCF_SUCCESS);

    HcfAsyKeyGeneratorBySpec *generator = nullptr;
    res = HcfAsyKeyGeneratorBySpecCreate(paramSpec, &generator);

    HcfKeyPair *keyPair = nullptr;
    res = generator->generateKeyPair(generator, &keyPair);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(keyPair, nullptr);

    HcfBlob blob = { .data = nullptr, .len = 0 };
    res = keyPair->priKey->base.getEncoded(&(keyPair->priKey->base), &blob);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(blob.data, nullptr);
    ASSERT_NE(blob.len, 0);

    HcfFree(blob.data);

    HcfObjDestroy(keyPair);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoEccAsyKeyGeneratorBySpecSubOneTest, CryptoEccAsyKeyGeneratorBySpecSubOneTest331_4, TestSize.Level0)
{
    HcfAsyKeyParamsSpec *paramSpec = nullptr;
    int32_t res = ConstructEcc256KeyPairParamsSpec(&paramSpec);

    ASSERT_EQ(res, HCF_SUCCESS);

    HcfAsyKeyGeneratorBySpec *generator = nullptr;
    res = HcfAsyKeyGeneratorBySpecCreate(paramSpec, &generator);

    HcfKeyPair *keyPair = nullptr;
    res = generator->generateKeyPair(generator, &keyPair);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(keyPair, nullptr);

    HcfBlob blob = { .data = nullptr, .len = 0 };
    res = keyPair->priKey->base.getEncoded(&(keyPair->priKey->base), &blob);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(blob.data, nullptr);
    ASSERT_NE(blob.len, 0);

    HcfFree(blob.data);

    HcfObjDestroy(keyPair);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoEccAsyKeyGeneratorBySpecSubOneTest, CryptoEccAsyKeyGeneratorBySpecSubOneTest331_5, TestSize.Level0)
{
    HcfAsyKeyParamsSpec *paramSpec = nullptr;
    int32_t res = ConstructEcc384CommParamsSpec(&paramSpec);

    ASSERT_EQ(res, HCF_SUCCESS);

    HcfAsyKeyGeneratorBySpec *generator = nullptr;
    res = HcfAsyKeyGeneratorBySpecCreate(paramSpec, &generator);

    HcfKeyPair *keyPair = nullptr;
    res = generator->generateKeyPair(generator, &keyPair);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(keyPair, nullptr);

    HcfBlob blob = { .data = nullptr, .len = 0 };
    res = keyPair->priKey->base.getEncoded(&(keyPair->priKey->base), &blob);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(blob.data, nullptr);
    ASSERT_NE(blob.len, 0);

    HcfFree(blob.data);

    HcfObjDestroy(keyPair);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoEccAsyKeyGeneratorBySpecSubOneTest, CryptoEccAsyKeyGeneratorBySpecSubOneTest331_6, TestSize.Level0)
{
    HcfAsyKeyParamsSpec *paramSpec = nullptr;
    int32_t res = ConstructEcc384KeyPairParamsSpec(&paramSpec);

    ASSERT_EQ(res, HCF_SUCCESS);

    HcfAsyKeyGeneratorBySpec *generator = nullptr;
    res = HcfAsyKeyGeneratorBySpecCreate(paramSpec, &generator);

    HcfKeyPair *keyPair = nullptr;
    res = generator->generateKeyPair(generator, &keyPair);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(keyPair, nullptr);

    HcfBlob blob = { .data = nullptr, .len = 0 };
    res = keyPair->priKey->base.getEncoded(&(keyPair->priKey->base), &blob);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(blob.data, nullptr);
    ASSERT_NE(blob.len, 0);

    HcfFree(blob.data);

    HcfObjDestroy(keyPair);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoEccAsyKeyGeneratorBySpecSubOneTest, CryptoEccAsyKeyGeneratorBySpecSubOneTest331_7, TestSize.Level0)
{
    HcfAsyKeyParamsSpec *paramSpec = nullptr;
    int32_t res = ConstructEcc521CommParamsSpec(&paramSpec);

    ASSERT_EQ(res, HCF_SUCCESS);

    HcfAsyKeyGeneratorBySpec *generator = nullptr;
    res = HcfAsyKeyGeneratorBySpecCreate(paramSpec, &generator);

    HcfKeyPair *keyPair = nullptr;
    res = generator->generateKeyPair(generator, &keyPair);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(keyPair, nullptr);

    HcfBlob blob = { .data = nullptr, .len = 0 };
    res = keyPair->priKey->base.getEncoded(&(keyPair->priKey->base), &blob);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(blob.data, nullptr);
    ASSERT_NE(blob.len, 0);

    HcfFree(blob.data);

    HcfObjDestroy(keyPair);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoEccAsyKeyGeneratorBySpecSubOneTest, CryptoEccAsyKeyGeneratorBySpecSubOneTest331_8, TestSize.Level0)
{
    HcfAsyKeyParamsSpec *paramSpec = nullptr;
    int32_t res = ConstructEcc521KeyPairParamsSpec(&paramSpec);

    ASSERT_EQ(res, HCF_SUCCESS);

    HcfAsyKeyGeneratorBySpec *generator = nullptr;
    res = HcfAsyKeyGeneratorBySpecCreate(paramSpec, &generator);

    HcfKeyPair *keyPair = nullptr;
    res = generator->generateKeyPair(generator, &keyPair);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(keyPair, nullptr);

    HcfBlob blob = { .data = nullptr, .len = 0 };
    res = keyPair->priKey->base.getEncoded(&(keyPair->priKey->base), &blob);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(blob.data, nullptr);
    ASSERT_NE(blob.len, 0);

    HcfFree(blob.data);

    HcfObjDestroy(keyPair);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoEccAsyKeyGeneratorBySpecSubOneTest, CryptoEccAsyKeyGeneratorBySpecSubOneTest332, TestSize.Level0)
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

    HcfBlob blob = { .data = nullptr, .len = 0 };
    res = keyPair->priKey->base.getEncoded(nullptr, &blob);

    ASSERT_NE(res, HCF_SUCCESS);
    ASSERT_EQ(blob.data, nullptr);
    ASSERT_EQ(blob.len, 0);

    HcfObjDestroy(keyPair);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoEccAsyKeyGeneratorBySpecSubOneTest, CryptoEccAsyKeyGeneratorBySpecSubOneTest333, TestSize.Level0)
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

    HcfBlob blob = { .data = nullptr, .len = 0 };
    res = keyPair->priKey->base.getEncoded((HcfKey *)&g_obj, &blob);

    ASSERT_NE(res, HCF_SUCCESS);
    ASSERT_EQ(blob.data, nullptr);
    ASSERT_EQ(blob.len, 0);

    HcfObjDestroy(keyPair);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoEccAsyKeyGeneratorBySpecSubOneTest, CryptoEccAsyKeyGeneratorBySpecSubOneTest334, TestSize.Level0)
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

    res = keyPair->priKey->base.getEncoded(&(keyPair->priKey->base), nullptr);

    ASSERT_NE(res, HCF_SUCCESS);

    HcfObjDestroy(keyPair);
    HcfObjDestroy(generator);
}

// for test:ECC_FP_P_BN
HWTEST_F(CryptoEccAsyKeyGeneratorBySpecSubOneTest, CryptoEccAsyKeyGeneratorBySpecSubOneTest401_1, TestSize.Level0)
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
    AsyKeySpecItem item = ECC_FP_P_BN;

    res = keyPair->pubKey->getAsyKeySpecBigInteger(keyPair->pubKey, item, &retBigInt);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(retBigInt.data, nullptr);
    ASSERT_NE(retBigInt.len, 0);

    HcfFree(retBigInt.data);

    HcfObjDestroy(keyPair);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoEccAsyKeyGeneratorBySpecSubOneTest, CryptoEccAsyKeyGeneratorBySpecSubOneTest401_2, TestSize.Level0)
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
    AsyKeySpecItem item = ECC_FP_P_BN;

    res = keyPair->priKey->getAsyKeySpecBigInteger(keyPair->priKey, item, &retBigInt);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(retBigInt.data, nullptr);
    ASSERT_NE(retBigInt.len, 0);

    HcfFree(retBigInt.data);

    HcfObjDestroy(keyPair);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoEccAsyKeyGeneratorBySpecSubOneTest, CryptoEccAsyKeyGeneratorBySpecSubOneTest401_3, TestSize.Level0)
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
    AsyKeySpecItem item = ECC_FP_P_BN;

    res = pubKey->getAsyKeySpecBigInteger(pubKey, item, &retBigInt);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(retBigInt.data, nullptr);
    ASSERT_NE(retBigInt.len, 0);

    HcfFree(retBigInt.data);

    HcfObjDestroy(pubKey);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoEccAsyKeyGeneratorBySpecSubOneTest, CryptoEccAsyKeyGeneratorBySpecSubOneTest401_4, TestSize.Level0)
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
    AsyKeySpecItem item = ECC_FP_P_BN;

    res = priKey->getAsyKeySpecBigInteger(priKey, item, &retBigInt);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(retBigInt.data, nullptr);
    ASSERT_NE(retBigInt.len, 0);

    HcfFree(retBigInt.data);

    HcfObjDestroy(priKey);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoEccAsyKeyGeneratorBySpecSubOneTest, CryptoEccAsyKeyGeneratorBySpecSubOneTest401_5, TestSize.Level0)
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
    AsyKeySpecItem item = ECC_FP_P_BN;

    res = keyPair->pubKey->getAsyKeySpecBigInteger(keyPair->pubKey, item, &retBigInt);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(retBigInt.data, nullptr);
    ASSERT_NE(retBigInt.len, 0);

    HcfFree(retBigInt.data);

    HcfObjDestroy(keyPair);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoEccAsyKeyGeneratorBySpecSubOneTest, CryptoEccAsyKeyGeneratorBySpecSubOneTest401_6, TestSize.Level0)
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
    AsyKeySpecItem item = ECC_FP_P_BN;

    res = keyPair->priKey->getAsyKeySpecBigInteger(keyPair->priKey, item, &retBigInt);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(retBigInt.data, nullptr);
    ASSERT_NE(retBigInt.len, 0);

    HcfFree(retBigInt.data);

    HcfObjDestroy(keyPair);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoEccAsyKeyGeneratorBySpecSubOneTest, CryptoEccAsyKeyGeneratorBySpecSubOneTest401_7, TestSize.Level0)
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
    AsyKeySpecItem item = ECC_FP_P_BN;

    res = pubKey->getAsyKeySpecBigInteger(pubKey, item, &retBigInt);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(retBigInt.data, nullptr);
    ASSERT_NE(retBigInt.len, 0);

    HcfFree(retBigInt.data);

    HcfObjDestroy(pubKey);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoEccAsyKeyGeneratorBySpecSubOneTest, CryptoEccAsyKeyGeneratorBySpecSubOneTest401_8, TestSize.Level0)
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
    AsyKeySpecItem item = ECC_FP_P_BN;

    res = priKey->getAsyKeySpecBigInteger(priKey, item, &retBigInt);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(retBigInt.data, nullptr);
    ASSERT_NE(retBigInt.len, 0);

    HcfFree(retBigInt.data);

    HcfObjDestroy(priKey);
    HcfObjDestroy(generator);
}
}
