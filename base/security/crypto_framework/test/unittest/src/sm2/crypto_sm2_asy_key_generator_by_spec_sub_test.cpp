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
#include "sm2_asy_key_generator_openssl.h"
#include "ecc_openssl_common.h"
#include "ecc_openssl_common_param_spec.h"
#include "ecc_common.h"
#include "ecc_common_param_spec.h"
#include "ecc_key_util.h"
#include "key_utils.h"
#include "blob.h"
#include "cipher.h"
#include "cipher_sm2_openssl.h"
#include "sm2_openssl.h"
#include "signature.h"
#include "key_pair.h"
#include "memory.h"
#include "memory_mock.h"
#include "openssl_adapter_mock.h"
#include "openssl_class.h"
#include "openssl_common.h"
#include "params_parser.h"

using namespace std;
using namespace testing::ext;

namespace {
constexpr int ZERO = 0;
constexpr int ONE = 1;
constexpr int TWO = 2;
constexpr int THREE = 3;
constexpr int FOUR = 4;
constexpr int FIVE = 5;
constexpr int SIX = 6;
constexpr int SEVEN = 7;
constexpr int EIGHT = 8;

class CryptoSm2AsyKeyGeneratorBySpecSubTest : public testing::Test {
public:
    static void SetUpTestCase(){};
    static void TearDownTestCase(){};
    void SetUp();
    void TearDown();
};

void CryptoSm2AsyKeyGeneratorBySpecSubTest::SetUp() {}
void CryptoSm2AsyKeyGeneratorBySpecSubTest::TearDown() {}

static const char *GetMockClass(void)
{
    return "HcfSymKeyGenerator";
}

HcfObjectBase g_obj = {
    .getClass = GetMockClass,
    .destroy = nullptr
};

static const char *g_mockMessage = "hello world";
static HcfBlob g_mockInput = {
    .data = (uint8_t *)g_mockMessage,
    .len = 12
};

static string g_sm2AlgName = "SM2_256";
static string g_sm2CurveName = "NID_sm2";

HcfEccCommParamsSpec *g_eccCommSpec = nullptr;

static HcfResult ConstructSm2256CommParamsSpec(HcfAsyKeyParamsSpec **spec)
{
    HcfEccCommParamsSpec *eccCommSpec = nullptr;
    HcfEccKeyUtilCreate(g_sm2CurveName.c_str(), &eccCommSpec);
    if (eccCommSpec == nullptr) {
        return HCF_INVALID_PARAMS;
    }
    *spec = (HcfAsyKeyParamsSpec *)eccCommSpec;
    return HCF_SUCCESS;
}

HWTEST_F(CryptoSm2AsyKeyGeneratorBySpecSubTest, CryptoSm2AsyKeyGeneratorBySpecTest066, TestSize.Level0)
{
    ConstructEccKeyPairCommParamsSpec("NID_sm2", &g_eccCommSpec);
    ASSERT_NE(g_eccCommSpec, nullptr);
    HcfAsyKeyParamsSpec *paramSpec = nullptr;
    HcfResult res = ConstructEccPubKeyParamsSpec(g_sm2AlgName.c_str(), g_eccCommSpec, &paramSpec);
    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(paramSpec, nullptr);

    HcfAsyKeyGeneratorBySpec *generator = nullptr;
    res = HcfAsyKeyGeneratorBySpecCreate(paramSpec, &generator);
    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(generator, nullptr);

    HcfPubKey *pubKey = nullptr;
    res = generator->generatePubKey(generator, &pubKey);
    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(pubKey, nullptr);

    HcfBlob blob = { .data = nullptr, .len = 0 };
    res = pubKey->base.getEncoded((HcfKey *)&g_obj, &blob);
    ASSERT_NE(res, HCF_SUCCESS);
    ASSERT_EQ(blob.data, nullptr);
    ASSERT_EQ(blob.len, 0);

    HcfFree(blob.data);
    HcfObjDestroy(pubKey);
    HcfObjDestroy(generator);
    HcfFree(g_eccCommSpec);
    DestroyEccPubKeySpec(reinterpret_cast<HcfEccPubKeyParamsSpec *>(paramSpec));
}

HWTEST_F(CryptoSm2AsyKeyGeneratorBySpecSubTest, CryptoSm2AsyKeyGeneratorBySpecTest067, TestSize.Level0)
{
    ConstructEccKeyPairCommParamsSpec("NID_sm2", &g_eccCommSpec);
    ASSERT_NE(g_eccCommSpec, nullptr);
    HcfAsyKeyParamsSpec *paramSpec = nullptr;
    HcfResult res = ConstructEccPubKeyParamsSpec(g_sm2AlgName.c_str(), g_eccCommSpec, &paramSpec);
    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(paramSpec, nullptr);

    HcfAsyKeyGeneratorBySpec *generator = nullptr;
    res = HcfAsyKeyGeneratorBySpecCreate(paramSpec, &generator);
    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(generator, nullptr);

    HcfPubKey *pubKey = nullptr;
    res = generator->generatePubKey(generator, &pubKey);
    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(pubKey, nullptr);

    res = pubKey->base.getEncoded(&(pubKey->base), nullptr);
    ASSERT_NE(res, HCF_SUCCESS);

    HcfObjDestroy(pubKey);
    HcfObjDestroy(generator);
    HcfFree(g_eccCommSpec);
    DestroyEccPubKeySpec(reinterpret_cast<HcfEccPubKeyParamsSpec *>(paramSpec));
}

HWTEST_F(CryptoSm2AsyKeyGeneratorBySpecSubTest, CryptoSm2AsyKeyGeneratorBySpecTest068, TestSize.Level0)
{
    ConstructEccKeyPairCommParamsSpec("NID_sm2", &g_eccCommSpec);
    ASSERT_NE(g_eccCommSpec, nullptr);
    HcfAsyKeyParamsSpec *paramSpec = nullptr;
    HcfResult res = ConstructEccPriKeyParamsSpec(g_sm2AlgName.c_str(), g_eccCommSpec, &paramSpec);
    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(paramSpec, nullptr);

    HcfAsyKeyGeneratorBySpec *generator = nullptr;
    res = HcfAsyKeyGeneratorBySpecCreate(paramSpec, &generator);
    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(generator, nullptr);

    HcfPriKey *priKey = nullptr;
    res = generator->generatePriKey(generator, &priKey);
    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(priKey, nullptr);

    HcfObjDestroy(priKey);
    HcfObjDestroy(generator);
    HcfFree(g_eccCommSpec);
    DestroyEccPriKeySpec(reinterpret_cast<HcfEccPriKeyParamsSpec *>(paramSpec));
}

HWTEST_F(CryptoSm2AsyKeyGeneratorBySpecSubTest, CryptoSm2AsyKeyGeneratorBySpecTest069, TestSize.Level0)
{
    ConstructEccKeyPairCommParamsSpec("NID_sm2", &g_eccCommSpec);
    ASSERT_NE(g_eccCommSpec, nullptr);
    HcfAsyKeyParamsSpec *paramSpec = nullptr;
    HcfResult res = ConstructEccPriKeyParamsSpec(g_sm2AlgName.c_str(), g_eccCommSpec, &paramSpec);
    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(paramSpec, nullptr);

    HcfAsyKeyGeneratorBySpec *generator = nullptr;
    res = HcfAsyKeyGeneratorBySpecCreate(paramSpec, &generator);
    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(generator, nullptr);

    HcfPriKey *priKey = nullptr;
    res = generator->generatePriKey(nullptr, &priKey);
    ASSERT_NE(res, HCF_SUCCESS);
    ASSERT_EQ(priKey, nullptr);

    HcfObjDestroy(priKey);
    HcfObjDestroy(generator);
    HcfFree(g_eccCommSpec);
    DestroyEccPriKeySpec(reinterpret_cast<HcfEccPriKeyParamsSpec *>(paramSpec));
}

HWTEST_F(CryptoSm2AsyKeyGeneratorBySpecSubTest, CryptoSm2AsyKeyGeneratorBySpecTest070, TestSize.Level0)
{
    ConstructEccKeyPairCommParamsSpec("NID_sm2", &g_eccCommSpec);
    ASSERT_NE(g_eccCommSpec, nullptr);
    HcfAsyKeyParamsSpec *paramSpec = nullptr;
    HcfResult res = ConstructEccPriKeyParamsSpec(g_sm2AlgName.c_str(), g_eccCommSpec, &paramSpec);
    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(paramSpec, nullptr);

    HcfAsyKeyGeneratorBySpec *generator = nullptr;
    res = HcfAsyKeyGeneratorBySpecCreate(paramSpec, &generator);
    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(generator, nullptr);

    res = generator->generatePriKey(generator, nullptr);
    ASSERT_NE(res, HCF_SUCCESS);

    HcfObjDestroy(generator);
    HcfFree(g_eccCommSpec);
    DestroyEccPriKeySpec(reinterpret_cast<HcfEccPriKeyParamsSpec *>(paramSpec));
}

HWTEST_F(CryptoSm2AsyKeyGeneratorBySpecSubTest, CryptoSm2AsyKeyGeneratorBySpecTest071, TestSize.Level0)
{
    ConstructEccKeyPairCommParamsSpec("NID_sm2", &g_eccCommSpec);
    ASSERT_NE(g_eccCommSpec, nullptr);
    HcfAsyKeyParamsSpec *paramSpec = nullptr;
    HcfResult res = ConstructEccPriKeyParamsSpec(g_sm2AlgName.c_str(), g_eccCommSpec, &paramSpec);
    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(paramSpec, nullptr);

    HcfAsyKeyGeneratorBySpec *generator = nullptr;
    res = HcfAsyKeyGeneratorBySpecCreate(paramSpec, &generator);
    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(generator, nullptr);

    res = generator->generatePriKey(nullptr, nullptr);
    ASSERT_NE(res, HCF_SUCCESS);

    HcfObjDestroy(generator);
    HcfFree(g_eccCommSpec);
    DestroyEccPriKeySpec(reinterpret_cast<HcfEccPriKeyParamsSpec *>(paramSpec));
}

HWTEST_F(CryptoSm2AsyKeyGeneratorBySpecSubTest, CryptoSm2AsyKeyGeneratorBySpecTest072, TestSize.Level0)
{
    ConstructEccKeyPairCommParamsSpec("NID_sm2", &g_eccCommSpec);
    ASSERT_NE(g_eccCommSpec, nullptr);
    HcfAsyKeyParamsSpec *paramSpec = nullptr;
    HcfResult res = ConstructEccPriKeyParamsSpec(g_sm2AlgName.c_str(), g_eccCommSpec, &paramSpec);
    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(paramSpec, nullptr);

    HcfAsyKeyGeneratorBySpec *generator = nullptr;
    res = HcfAsyKeyGeneratorBySpecCreate(paramSpec, &generator);
    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(generator, nullptr);

    HcfPriKey *priKey = nullptr;
    res = generator->generatePriKey(generator, &priKey);
    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(priKey, nullptr);

    const char *className = priKey->base.base.getClass();
    ASSERT_NE(className, nullptr);

    HcfObjDestroy(priKey);
    HcfObjDestroy(generator);
    HcfFree(g_eccCommSpec);
    DestroyEccPriKeySpec(reinterpret_cast<HcfEccPriKeyParamsSpec *>(paramSpec));
}

HWTEST_F(CryptoSm2AsyKeyGeneratorBySpecSubTest, CryptoSm2AsyKeyGeneratorBySpecTest073, TestSize.Level0)
{
    ConstructEccKeyPairCommParamsSpec("NID_sm2", &g_eccCommSpec);
    ASSERT_NE(g_eccCommSpec, nullptr);
    HcfAsyKeyParamsSpec *paramSpec = nullptr;
    HcfResult res = ConstructEccPriKeyParamsSpec(g_sm2AlgName.c_str(), g_eccCommSpec, &paramSpec);
    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(paramSpec, nullptr);

    HcfAsyKeyGeneratorBySpec *generator = nullptr;
    res = HcfAsyKeyGeneratorBySpecCreate(paramSpec, &generator);
    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(generator, nullptr);

    HcfPriKey *priKey = nullptr;
    res = generator->generatePriKey(generator, &priKey);
    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(priKey, nullptr);

    priKey->base.base.destroy((HcfObjectBase *)(&(priKey->base.base)));
    HcfObjDestroy(generator);
    HcfFree(g_eccCommSpec);
    DestroyEccPriKeySpec(reinterpret_cast<HcfEccPriKeyParamsSpec *>(paramSpec));
}

HWTEST_F(CryptoSm2AsyKeyGeneratorBySpecSubTest, CryptoSm2AsyKeyGeneratorBySpecTest074, TestSize.Level0)
{
    ConstructEccKeyPairCommParamsSpec("NID_sm2", &g_eccCommSpec);
    ASSERT_NE(g_eccCommSpec, nullptr);
    HcfAsyKeyParamsSpec *paramSpec = nullptr;
    HcfResult res = ConstructEccPriKeyParamsSpec(g_sm2AlgName.c_str(), g_eccCommSpec, &paramSpec);
    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(paramSpec, nullptr);

    HcfAsyKeyGeneratorBySpec *generator = nullptr;
    res = HcfAsyKeyGeneratorBySpecCreate(paramSpec, &generator);
    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(generator, nullptr);

    HcfPriKey *priKey = nullptr;
    res = generator->generatePriKey(generator, &priKey);
    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(priKey, nullptr);

    priKey->base.base.destroy(nullptr);
    HcfObjDestroy(priKey);
    HcfObjDestroy(generator);
    DestroyEccPriKeySpec(reinterpret_cast<HcfEccPriKeyParamsSpec *>(paramSpec));
    HcfFree(g_eccCommSpec);
}

HWTEST_F(CryptoSm2AsyKeyGeneratorBySpecSubTest, CryptoSm2AsyKeyGeneratorBySpecTest075, TestSize.Level0)
{
    ConstructEccKeyPairCommParamsSpec("NID_sm2", &g_eccCommSpec);
    ASSERT_NE(g_eccCommSpec, nullptr);
    HcfAsyKeyParamsSpec *paramSpec = nullptr;
    HcfResult res = ConstructEccPriKeyParamsSpec(g_sm2AlgName.c_str(), g_eccCommSpec, &paramSpec);
    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(paramSpec, nullptr);

    HcfAsyKeyGeneratorBySpec *generator = nullptr;
    res = HcfAsyKeyGeneratorBySpecCreate(paramSpec, &generator);
    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(generator, nullptr);

    HcfPriKey *priKey = nullptr;
    res = generator->generatePriKey(generator, &priKey);
    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(priKey, nullptr);

    priKey->base.base.destroy(&g_obj);
    HcfObjDestroy(priKey);
    HcfObjDestroy(generator);
    HcfFree(g_eccCommSpec);
    DestroyEccPriKeySpec(reinterpret_cast<HcfEccPriKeyParamsSpec *>(paramSpec));
}

HWTEST_F(CryptoSm2AsyKeyGeneratorBySpecSubTest, CryptoSm2AsyKeyGeneratorBySpecTest076, TestSize.Level0)
{
    ConstructEccKeyPairCommParamsSpec("NID_sm2", &g_eccCommSpec);
    ASSERT_NE(g_eccCommSpec, nullptr);
    HcfAsyKeyParamsSpec *paramSpec = nullptr;
    HcfResult res = ConstructEccPriKeyParamsSpec(g_sm2AlgName.c_str(), g_eccCommSpec, &paramSpec);
    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(paramSpec, nullptr);

    HcfAsyKeyGeneratorBySpec *generator = nullptr;
    res = HcfAsyKeyGeneratorBySpecCreate(paramSpec, &generator);
    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(generator, nullptr);

    HcfPriKey *priKey = nullptr;
    res = generator->generatePriKey(generator, &priKey);
    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(priKey, nullptr);

    res = priKey->base.getEncoded(&(priKey->base), nullptr);
    ASSERT_NE(res, HCF_SUCCESS);

    HcfObjDestroy(priKey);
    HcfObjDestroy(generator);
    HcfFree(g_eccCommSpec);
    DestroyEccPriKeySpec(reinterpret_cast<HcfEccPriKeyParamsSpec *>(paramSpec));
}

HWTEST_F(CryptoSm2AsyKeyGeneratorBySpecSubTest, CryptoSm2AsyKeyGeneratorBySpecTest077, TestSize.Level0)
{
    ConstructEccKeyPairCommParamsSpec("NID_sm2", &g_eccCommSpec);
    ASSERT_NE(g_eccCommSpec, nullptr);
    HcfAsyKeyParamsSpec *paramSpec = nullptr;
    HcfResult res = ConstructEccPriKeyParamsSpec(g_sm2AlgName.c_str(), g_eccCommSpec, &paramSpec);
    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(paramSpec, nullptr);

    HcfAsyKeyGeneratorBySpec *generator = nullptr;
    res = HcfAsyKeyGeneratorBySpecCreate(paramSpec, &generator);
    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(generator, nullptr);

    HcfPriKey *priKey = nullptr;
    res = generator->generatePriKey(generator, &priKey);
    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(priKey, nullptr);

    priKey->clearMem(priKey);
    HcfObjDestroy(priKey);
    HcfObjDestroy(generator);
    HcfFree(g_eccCommSpec);
    DestroyEccPriKeySpec(reinterpret_cast<HcfEccPriKeyParamsSpec *>(paramSpec));
}

HWTEST_F(CryptoSm2AsyKeyGeneratorBySpecSubTest, CryptoSm2AsyKeyGeneratorBySpecTest078, TestSize.Level0)
{
    ConstructEccKeyPairCommParamsSpec("NID_sm2", &g_eccCommSpec);
    ASSERT_NE(g_eccCommSpec, nullptr);
    HcfAsyKeyParamsSpec *paramSpec = nullptr;
    HcfResult res = ConstructEccPriKeyParamsSpec(g_sm2AlgName.c_str(), g_eccCommSpec, &paramSpec);
    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(paramSpec, nullptr);

    HcfAsyKeyGeneratorBySpec *generator = nullptr;
    res = HcfAsyKeyGeneratorBySpecCreate(paramSpec, &generator);
    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(generator, nullptr);

    HcfPriKey *priKey = nullptr;
    res = generator->generatePriKey(generator, &priKey);
    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(priKey, nullptr);

    priKey->clearMem(nullptr);
    HcfObjDestroy(priKey);
    HcfObjDestroy(generator);
    HcfFree(g_eccCommSpec);
    DestroyEccPriKeySpec(reinterpret_cast<HcfEccPriKeyParamsSpec *>(paramSpec));
}

HWTEST_F(CryptoSm2AsyKeyGeneratorBySpecSubTest, CryptoSm2AsyKeyGeneratorBySpecTest079, TestSize.Level0)
{
    ConstructEccKeyPairCommParamsSpec("NID_sm2", &g_eccCommSpec);
    ASSERT_NE(g_eccCommSpec, nullptr);
    HcfAsyKeyParamsSpec *paramSpec = nullptr;
    HcfResult res = ConstructEccPriKeyParamsSpec(g_sm2AlgName.c_str(), g_eccCommSpec, &paramSpec);
    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(paramSpec, nullptr);

    HcfAsyKeyGeneratorBySpec *generator = nullptr;
    res = HcfAsyKeyGeneratorBySpecCreate(paramSpec, &generator);
    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(generator, nullptr);

    HcfPriKey *priKey = nullptr;
    res = generator->generatePriKey(generator, &priKey);
    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(priKey, nullptr);

    const char *format = priKey->base.getFormat(&priKey->base);
    ASSERT_NE(format, nullptr);

    HcfObjDestroy(priKey);
    HcfObjDestroy(generator);
    HcfFree(g_eccCommSpec);
    DestroyEccPriKeySpec(reinterpret_cast<HcfEccPriKeyParamsSpec *>(paramSpec));
}

HWTEST_F(CryptoSm2AsyKeyGeneratorBySpecSubTest, CryptoSm2AsyKeyGeneratorBySpecTest080, TestSize.Level0)
{
    ConstructEccKeyPairCommParamsSpec("NID_sm2", &g_eccCommSpec);
    ASSERT_NE(g_eccCommSpec, nullptr);
    HcfAsyKeyParamsSpec *paramSpec = nullptr;
    HcfResult res = ConstructEccPriKeyParamsSpec(g_sm2AlgName.c_str(), g_eccCommSpec, &paramSpec);
    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(paramSpec, nullptr);

    HcfAsyKeyGeneratorBySpec *generator = nullptr;
    res = HcfAsyKeyGeneratorBySpecCreate(paramSpec, &generator);
    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(generator, nullptr);

    HcfPriKey *priKey = nullptr;
    res = generator->generatePriKey(generator, &priKey);
    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(priKey, nullptr);

    const char *format = priKey->base.getFormat(nullptr);
    ASSERT_EQ(format, nullptr);

    HcfObjDestroy(priKey);
    HcfObjDestroy(generator);
    HcfFree(g_eccCommSpec);
    DestroyEccPriKeySpec(reinterpret_cast<HcfEccPriKeyParamsSpec *>(paramSpec));
}

HWTEST_F(CryptoSm2AsyKeyGeneratorBySpecSubTest, CryptoSm2AsyKeyGeneratorBySpecTest081, TestSize.Level0)
{
    ConstructEccKeyPairCommParamsSpec("NID_sm2", &g_eccCommSpec);
    ASSERT_NE(g_eccCommSpec, nullptr);
    HcfAsyKeyParamsSpec *paramSpec = nullptr;
    HcfResult res = ConstructEccPriKeyParamsSpec(g_sm2AlgName.c_str(), g_eccCommSpec, &paramSpec);
    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(paramSpec, nullptr);

    HcfAsyKeyGeneratorBySpec *generator = nullptr;
    res = HcfAsyKeyGeneratorBySpecCreate(paramSpec, &generator);
    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(generator, nullptr);

    HcfPriKey *priKey = nullptr;
    res = generator->generatePriKey(generator, &priKey);
    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(priKey, nullptr);

    const char *format = priKey->base.getFormat((HcfKey *)&g_obj);
    ASSERT_EQ(format, nullptr);

    HcfObjDestroy(priKey);
    HcfObjDestroy(generator);
    HcfFree(g_eccCommSpec);
    DestroyEccPriKeySpec(reinterpret_cast<HcfEccPriKeyParamsSpec *>(paramSpec));
}

HWTEST_F(CryptoSm2AsyKeyGeneratorBySpecSubTest, CryptoSm2AsyKeyGeneratorBySpecTest082, TestSize.Level0)
{
    ConstructEccKeyPairCommParamsSpec("NID_sm2", &g_eccCommSpec);
    ASSERT_NE(g_eccCommSpec, nullptr);
    HcfAsyKeyParamsSpec *paramSpec = nullptr;
    HcfResult res = ConstructEccPriKeyParamsSpec(g_sm2AlgName.c_str(), g_eccCommSpec, &paramSpec);
    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(paramSpec, nullptr);

    HcfAsyKeyGeneratorBySpec *generator = nullptr;
    res = HcfAsyKeyGeneratorBySpecCreate(paramSpec, &generator);
    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(generator, nullptr);

    HcfPriKey *priKey = nullptr;
    res = generator->generatePriKey(generator, &priKey);
    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(priKey, nullptr);

    const char *algName = priKey->base.getAlgorithm(&priKey->base);
    ASSERT_NE(algName, nullptr);

    HcfObjDestroy(priKey);
    HcfObjDestroy(generator);
    HcfFree(g_eccCommSpec);
    DestroyEccPriKeySpec(reinterpret_cast<HcfEccPriKeyParamsSpec *>(paramSpec));
}

HWTEST_F(CryptoSm2AsyKeyGeneratorBySpecSubTest, CryptoSm2AsyKeyGeneratorBySpecTest083, TestSize.Level0)
{
    ConstructEccKeyPairCommParamsSpec("NID_sm2", &g_eccCommSpec);
    ASSERT_NE(g_eccCommSpec, nullptr);
    HcfAsyKeyParamsSpec *paramSpec = nullptr;
    HcfResult res = ConstructEccPriKeyParamsSpec(g_sm2AlgName.c_str(), g_eccCommSpec, &paramSpec);
    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(paramSpec, nullptr);

    HcfAsyKeyGeneratorBySpec *generator = nullptr;
    res = HcfAsyKeyGeneratorBySpecCreate(paramSpec, &generator);
    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(generator, nullptr);

    HcfPriKey *priKey = nullptr;
    res = generator->generatePriKey(generator, &priKey);
    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(priKey, nullptr);

    const char *algName = priKey->base.getAlgorithm(nullptr);
    ASSERT_EQ(algName, nullptr);

    HcfObjDestroy(priKey);
    HcfObjDestroy(generator);
    HcfFree(g_eccCommSpec);
    DestroyEccPriKeySpec(reinterpret_cast<HcfEccPriKeyParamsSpec *>(paramSpec));
}

HWTEST_F(CryptoSm2AsyKeyGeneratorBySpecSubTest, CryptoSm2AsyKeyGeneratorBySpecTest084, TestSize.Level0)
{
    ConstructEccKeyPairCommParamsSpec("NID_sm2", &g_eccCommSpec);
    ASSERT_NE(g_eccCommSpec, nullptr);
    HcfAsyKeyParamsSpec *paramSpec = nullptr;
    HcfResult res = ConstructEccPriKeyParamsSpec(g_sm2AlgName.c_str(), g_eccCommSpec, &paramSpec);
    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(paramSpec, nullptr);

    HcfAsyKeyGeneratorBySpec *generator = nullptr;
    res = HcfAsyKeyGeneratorBySpecCreate(paramSpec, &generator);
    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(generator, nullptr);

    HcfPriKey *priKey = nullptr;
    res = generator->generatePriKey(generator, &priKey);
    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(priKey, nullptr);

    const char *algName = priKey->base.getAlgorithm((HcfKey *)&g_obj);
    ASSERT_EQ(algName, nullptr);

    HcfObjDestroy(priKey);
    HcfObjDestroy(generator);
    DestroyEccPriKeySpec(reinterpret_cast<HcfEccPriKeyParamsSpec *>(paramSpec));
    HcfFree(g_eccCommSpec);
}

HWTEST_F(CryptoSm2AsyKeyGeneratorBySpecSubTest, CryptoSm2AsyKeyGeneratorBySpecTest085, TestSize.Level0)
{
    ConstructEccKeyPairCommParamsSpec("NID_sm2", &g_eccCommSpec);
    ASSERT_NE(g_eccCommSpec, nullptr);
    HcfAsyKeyParamsSpec *paramSpec = nullptr;
    HcfResult res = ConstructEccPriKeyParamsSpec(g_sm2AlgName.c_str(), g_eccCommSpec, &paramSpec);
    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(paramSpec, nullptr);
    HcfAsyKeyGeneratorBySpec *generator = nullptr;
    res = HcfAsyKeyGeneratorBySpecCreate(paramSpec, &generator);
    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(generator, nullptr);

    HcfPriKey *priKey = nullptr;
    res = generator->generatePriKey(generator, &priKey);
    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(priKey, nullptr);

    HcfBlob blob = {.data = nullptr, .len = 0};
    res = priKey->base.getEncoded(&(priKey->base), &blob);
    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(blob.data, nullptr);
    ASSERT_NE(blob.len, 0);

    HcfFree(blob.data);
    HcfObjDestroy(priKey);
    HcfObjDestroy(generator);
    HcfFree(g_eccCommSpec);
    DestroyEccPriKeySpec(reinterpret_cast<HcfEccPriKeyParamsSpec *>(paramSpec));
}

HWTEST_F(CryptoSm2AsyKeyGeneratorBySpecSubTest, CryptoSm2AsyKeyGeneratorBySpecTest086, TestSize.Level0)
{
    ConstructEccKeyPairCommParamsSpec("NID_sm2", &g_eccCommSpec);
    ASSERT_NE(g_eccCommSpec, nullptr);
    HcfAsyKeyParamsSpec *paramSpec = nullptr;
    HcfResult res = ConstructEccPriKeyParamsSpec(g_sm2AlgName.c_str(), g_eccCommSpec, &paramSpec);
    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(paramSpec, nullptr);

    HcfAsyKeyGeneratorBySpec *generator = nullptr;
    res = HcfAsyKeyGeneratorBySpecCreate(paramSpec, &generator);
    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(generator, nullptr);

    HcfPriKey *priKey = nullptr;
    res = generator->generatePriKey(generator, &priKey);
    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(priKey, nullptr);

    HcfBlob blob = {.data = nullptr, .len = 0};
    res = priKey->base.getEncoded(nullptr, &blob);

    ASSERT_NE(res, HCF_SUCCESS);
    ASSERT_EQ(blob.data, nullptr);
    ASSERT_EQ(blob.len, 0);

    HcfFree(blob.data);
    HcfObjDestroy(priKey);
    HcfObjDestroy(generator);
    HcfFree(g_eccCommSpec);
    DestroyEccPriKeySpec(reinterpret_cast<HcfEccPriKeyParamsSpec *>(paramSpec));
}

HWTEST_F(CryptoSm2AsyKeyGeneratorBySpecSubTest, CryptoSm2AsyKeyGeneratorBySpecTest087, TestSize.Level0)
{
    ConstructEccKeyPairCommParamsSpec("NID_sm2", &g_eccCommSpec);
    ASSERT_NE(g_eccCommSpec, nullptr);
    HcfAsyKeyParamsSpec *paramSpec = nullptr;
    HcfResult res = ConstructEccPriKeyParamsSpec(g_sm2AlgName.c_str(), g_eccCommSpec, &paramSpec);
    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(paramSpec, nullptr);

    HcfAsyKeyGeneratorBySpec *generator = nullptr;
    res = HcfAsyKeyGeneratorBySpecCreate(paramSpec, &generator);
    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(generator, nullptr);

    HcfPriKey *priKey = nullptr;
    res = generator->generatePriKey(generator, &priKey);
    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(priKey, nullptr);

    HcfBlob blob = {.data = nullptr, .len = 0};
    res = priKey->base.getEncoded((HcfKey *)&g_obj, &blob);
    ASSERT_NE(res, HCF_SUCCESS);
    ASSERT_EQ(blob.data, nullptr);
    ASSERT_EQ(blob.len, 0);

    HcfFree(blob.data);
    HcfObjDestroy(priKey);
    HcfObjDestroy(generator);
    HcfFree(g_eccCommSpec);
    DestroyEccPriKeySpec(reinterpret_cast<HcfEccPriKeyParamsSpec *>(paramSpec));
}

HWTEST_F(CryptoSm2AsyKeyGeneratorBySpecSubTest, CryptoSm2AsyKeyGeneratorBySpecTest088, TestSize.Level0)
{
    ConstructEccKeyPairCommParamsSpec("NID_sm2", &g_eccCommSpec);
    ASSERT_NE(g_eccCommSpec, nullptr);
    HcfAsyKeyParamsSpec *paramSpec = nullptr;
    HcfResult res = ConstructEccPriKeyParamsSpec(g_sm2AlgName.c_str(), g_eccCommSpec, &paramSpec);
    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(paramSpec, nullptr);

    HcfAsyKeyGeneratorBySpec *generator = nullptr;
    res = HcfAsyKeyGeneratorBySpecCreate(paramSpec, &generator);
    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(generator, nullptr);

    HcfPriKey *priKey = nullptr;
    res = generator->generatePriKey(generator, &priKey);
    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(priKey, nullptr);

    res = priKey->base.getEncoded(&(priKey->base), nullptr);
    ASSERT_NE(res, HCF_SUCCESS);

    HcfObjDestroy(priKey);
    HcfObjDestroy(generator);
    HcfFree(g_eccCommSpec);
    DestroyEccPriKeySpec(reinterpret_cast<HcfEccPriKeyParamsSpec *>(paramSpec));
}

HWTEST_F(CryptoSm2AsyKeyGeneratorBySpecSubTest, CryptoSm2AsyKeyGeneratorBySpecTest089, TestSize.Level0)
{
    ConstructEccKeyPairCommParamsSpec("NID_sm2", &g_eccCommSpec);
    ASSERT_NE(g_eccCommSpec, nullptr);
    HcfAsyKeyParamsSpec *paramSpec = nullptr;
    HcfResult res = ConstructEccKeyPairParamsSpec(g_sm2AlgName.c_str(), g_eccCommSpec, &paramSpec);
    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(paramSpec, nullptr);

    HcfAsyKeyGeneratorBySpec *generatorBySpec = nullptr;
    res = HcfAsyKeyGeneratorBySpecCreate(paramSpec, &generatorBySpec);
    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(generatorBySpec, nullptr);

    HcfKeyPair *keyPair = nullptr;
    res = generatorBySpec->generateKeyPair(generatorBySpec, &keyPair);
    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(keyPair, nullptr);

    HcfBlob pubKeyBlob = {.data = nullptr, .len = 0};
    HcfBlob priKeyBlob = {.data = nullptr, .len = 0};
    res = keyPair->pubKey->base.getEncoded(&(keyPair->pubKey->base), &pubKeyBlob);
    ASSERT_EQ(res, HCF_SUCCESS);
    res = keyPair->priKey->base.getEncoded(&(keyPair->priKey->base), &priKeyBlob);
    ASSERT_EQ(res, HCF_SUCCESS);

    HcfAsyKeyGenerator *generator = nullptr;
    res = HcfAsyKeyGeneratorCreate("SM2_256", &generator);
    HcfKeyPair *outKeyPair = nullptr;
    res = generator->convertKey(generator, nullptr, &pubKeyBlob, &priKeyBlob, &outKeyPair);
    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(outKeyPair, nullptr);
    HcfBlob outPubKeyBlob = { .data = nullptr, .len = 0 };
    res = outKeyPair->pubKey->base.getEncoded(&(outKeyPair->pubKey->base), &outPubKeyBlob);
    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(outPubKeyBlob.data, nullptr);
    ASSERT_NE(outPubKeyBlob.len, 0);
    HcfBlob outPriKeyBlob = { .data = nullptr, .len = 0 };
    res = outKeyPair->priKey->base.getEncoded(&(outKeyPair->priKey->base), &outPriKeyBlob);
    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(outPriKeyBlob.data, nullptr);
    ASSERT_NE(outPriKeyBlob.len, 0);
    HcfFree(pubKeyBlob.data);
    HcfFree(priKeyBlob.data);
    HcfFree(outPubKeyBlob.data);
    HcfFree(outPriKeyBlob.data);
    HcfObjDestroy(keyPair);
    HcfObjDestroy(outKeyPair);
    HcfObjDestroy(generator);
    HcfObjDestroy(generatorBySpec);
    HcfFree(g_eccCommSpec);
    DestroyEccKeyPairSpec(reinterpret_cast<HcfEccKeyPairParamsSpec *>(paramSpec));
}

HWTEST_F(CryptoSm2AsyKeyGeneratorBySpecSubTest, CryptoSm2AsyKeyGeneratorBySpecTest090, TestSize.Level0)
{
    ConstructEccKeyPairCommParamsSpec("NID_sm2", &g_eccCommSpec);
    ASSERT_NE(g_eccCommSpec, nullptr);
    HcfAsyKeyParamsSpec *paramSpec = nullptr;
    HcfResult res = ConstructEccKeyPairParamsSpec(g_sm2AlgName.c_str(), g_eccCommSpec, &paramSpec);
    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(paramSpec, nullptr);
    HcfAsyKeyGeneratorBySpec *generator = nullptr;
    res = HcfAsyKeyGeneratorBySpecCreate(paramSpec, &generator);
    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(generator, nullptr);
    HcfKeyPair *keyPair = nullptr;
    res = generator->generateKeyPair(generator, &keyPair);
    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(keyPair, nullptr);

    uint8_t plan[] = "this is sm2 cipher test!\0";
    HcfBlob input = {.data = (uint8_t *)plan, .len = strlen((char *)plan) + 1};
    HcfBlob encoutput = {.data = nullptr, .len = 0};
    HcfCipher *cipher = nullptr;
    res = HcfCipherCreate("SM2|SM3", &cipher);
    EXPECT_EQ(res, HCF_SUCCESS);

    res = cipher->init(cipher, ENCRYPT_MODE, (HcfKey *)keyPair->pubKey, nullptr);
    EXPECT_EQ(res, HCF_SUCCESS);
    res = cipher->doFinal(cipher, &input, &encoutput);
    EXPECT_EQ(res, HCF_SUCCESS);
    HcfObjDestroy(cipher);

    HcfBlob decoutput = {.data = nullptr, .len = 0};
    cipher = nullptr;
    res = HcfCipherCreate("SM2|SM3", &cipher);
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
    HcfFree(g_eccCommSpec);
    DestroyEccKeyPairSpec(reinterpret_cast<HcfEccKeyPairParamsSpec *>(paramSpec));
}

HWTEST_F(CryptoSm2AsyKeyGeneratorBySpecSubTest, CryptoSm2AsyKeyGeneratorBySpecTest091, TestSize.Level0)
{
    ConstructEccKeyPairCommParamsSpec("NID_sm2", &g_eccCommSpec);
    ASSERT_NE(g_eccCommSpec, nullptr);
    HcfAsyKeyParamsSpec *paramSpec = nullptr;
    HcfResult res = ConstructEccKeyPairParamsSpec(g_sm2AlgName.c_str(), g_eccCommSpec, &paramSpec);
    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(paramSpec, nullptr);
    HcfAsyKeyGeneratorBySpec *generator = nullptr;
    res = HcfAsyKeyGeneratorBySpecCreate(paramSpec, &generator);
    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(generator, nullptr);
    HcfKeyPair *keyPair = nullptr;
    res = generator->generateKeyPair(generator, &keyPair);
    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(keyPair, nullptr);

    HcfSign *sign = nullptr;
    res = HcfSignCreate("SM2|SM3", &sign);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(sign, nullptr);

    res = sign->init(sign, nullptr, keyPair->priKey);
    ASSERT_EQ(res, HCF_SUCCESS);

    uint8_t pSourceData[] = "1234567812345678\0";
    HcfBlob pSource = {.data = (uint8_t *)pSourceData, .len = strlen((char *)pSourceData)};
    res = sign->setSignSpecUint8Array(sign, SM2_USER_ID_UINT8ARR, pSource);
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

    res = verify->init(verify, nullptr, keyPair->pubKey);
    ASSERT_EQ(res, HCF_SUCCESS);

    bool flag = verify->verify(verify, &g_mockInput, &out);
    ASSERT_EQ(flag, true);

    HcfFree(out.data);
    HcfObjDestroy(sign);
    HcfObjDestroy(verify);

    HcfObjDestroy(keyPair);
    HcfObjDestroy(generator);
    HcfFree(g_eccCommSpec);
    DestroyEccKeyPairSpec(reinterpret_cast<HcfEccKeyPairParamsSpec *>(paramSpec));
}

HWTEST_F(CryptoSm2AsyKeyGeneratorBySpecSubTest, CryptoSm2AsyKeyGeneratorBySpecTest092, TestSize.Level0)
{
    HcfAsyKeyGenParams params = {
        .algo = HCF_ALG_SM2,
        .bits = HCF_ALG_SM2_256,
        .primes = HCF_OPENSSL_PRIMES_2,
    };

    HcfAsyKeyGeneratorSpi *spiObj = nullptr;
    HcfResult res = HcfAsyKeyGeneratorSpiSm2Create(&params, &spiObj);
    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(spiObj, nullptr);

    ConstructEccKeyPairCommParamsSpec("NID_sm2", &g_eccCommSpec);
    ASSERT_NE(g_eccCommSpec, nullptr);
    HcfAsyKeyParamsSpec *paramSpec = nullptr;
    res = ConstructEccKeyPairParamsSpec(g_sm2AlgName.c_str(), g_eccCommSpec, &paramSpec);

    ASSERT_EQ(res, HCF_SUCCESS);

    HcfKeyPair *keyPair = nullptr;
    res = spiObj->engineGenerateKeyPairBySpec(spiObj, paramSpec, &keyPair);
    ASSERT_EQ(res, HCF_SUCCESS);

    HcfObjDestroy(spiObj);
    HcfObjDestroy(keyPair);
    DestroyEccKeyPairSpec(reinterpret_cast<HcfEccKeyPairParamsSpec *>(paramSpec));
    HcfFree(g_eccCommSpec);
}

HWTEST_F(CryptoSm2AsyKeyGeneratorBySpecSubTest, CryptoSm2AsyKeyGeneratorBySpecTest093, TestSize.Level0)
{
    HcfAsyKeyGenParams params = {
        .algo = HCF_ALG_SM2,
        .bits = HCF_ALG_SM2_256,
        .primes = HCF_OPENSSL_PRIMES_2,
    };

    HcfAsyKeyGeneratorSpi *spiObj = nullptr;
    HcfResult res = HcfAsyKeyGeneratorSpiSm2Create(&params, &spiObj);
    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(spiObj, nullptr);

    ConstructEccKeyPairCommParamsSpec("NID_sm2", &g_eccCommSpec);
    ASSERT_NE(g_eccCommSpec, nullptr);
    HcfAsyKeyParamsSpec *paramSpec = nullptr;
    res = ConstructEccKeyPairParamsSpec(g_sm2AlgName.c_str(), g_eccCommSpec, &paramSpec);

    ASSERT_EQ(res, HCF_SUCCESS);

    HcfPubKey *pubKey = nullptr;
    res = spiObj->engineGeneratePubKeyBySpec(spiObj, paramSpec, &pubKey);
    ASSERT_EQ(res, HCF_SUCCESS);

    HcfObjDestroy(spiObj);
    HcfObjDestroy(pubKey);
    DestroyEccKeyPairSpec(reinterpret_cast<HcfEccKeyPairParamsSpec *>(paramSpec));
    HcfFree(g_eccCommSpec);
}

HWTEST_F(CryptoSm2AsyKeyGeneratorBySpecSubTest, CryptoSm2AsyKeyGeneratorBySpecTest094, TestSize.Level0)
{
    HcfAsyKeyGenParams params = {
        .algo = HCF_ALG_SM2,
        .bits = HCF_ALG_SM2_256,
        .primes = HCF_OPENSSL_PRIMES_2,
    };

    HcfAsyKeyGeneratorSpi *spiObj = nullptr;
    HcfResult res = HcfAsyKeyGeneratorSpiSm2Create(&params, &spiObj);
    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(spiObj, nullptr);

    ConstructEccKeyPairCommParamsSpec("NID_sm2", &g_eccCommSpec);
    ASSERT_NE(g_eccCommSpec, nullptr);
    HcfAsyKeyParamsSpec *paramSpec = nullptr;
    res = ConstructEccKeyPairParamsSpec(g_sm2AlgName.c_str(), g_eccCommSpec, &paramSpec);

    ASSERT_EQ(res, HCF_SUCCESS);

    HcfPriKey *priKey = nullptr;
    res = spiObj->engineGeneratePriKeyBySpec(spiObj, paramSpec, &priKey);
    ASSERT_EQ(res, HCF_SUCCESS);

    HcfObjDestroy(spiObj);
    HcfObjDestroy(priKey);
    DestroyEccKeyPairSpec(reinterpret_cast<HcfEccKeyPairParamsSpec *>(paramSpec));
    HcfFree(g_eccCommSpec);
}

HWTEST_F(CryptoSm2AsyKeyGeneratorBySpecSubTest, CryptoSm2AsyKeyGeneratorBySpecTest095, TestSize.Level0)
{
    HcfAsyKeyGenParams params = {
        .algo = HCF_ALG_SM2,
        .bits = 0,
        .primes = HCF_OPENSSL_PRIMES_2,
    };

    HcfAsyKeyGeneratorSpi *spiObj = nullptr;
    HcfResult res = HcfAsyKeyGeneratorSpiSm2Create(&params, &spiObj);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(spiObj, nullptr);

    HcfAsyKeyParamsSpec *paramSpec = nullptr;
    res = ConstructSm2256CommParamsSpec(&paramSpec);

    ASSERT_EQ(res, HCF_SUCCESS);

    HcfKeyPair *keyPair = nullptr;
    res = spiObj->engineGenerateKeyPairBySpec(spiObj, paramSpec, &keyPair);
    ASSERT_EQ(res, HCF_SUCCESS);

    HcfObjDestroy(spiObj);
    HcfObjDestroy(keyPair);
    FreeEccCommParamsSpec(reinterpret_cast<HcfEccCommParamsSpec *>(paramSpec));
    HcfFree(paramSpec);
}

HWTEST_F(CryptoSm2AsyKeyGeneratorBySpecSubTest, CryptoSm2AsyKeyGeneratorBySpecTest096, TestSize.Level0)
{
    ConstructEccKeyPairCommParamsSpec("NID_sm2", &g_eccCommSpec);
    ASSERT_NE(g_eccCommSpec, nullptr);
    HcfAsyKeyParamsSpec *paramSpec = nullptr;
    HcfResult res = ConstructEccKeyPairParamsSpec(g_sm2AlgName.c_str(), g_eccCommSpec, &paramSpec);

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
    DestroyEccKeyPairSpec(reinterpret_cast<HcfEccKeyPairParamsSpec *>(paramSpec));
    HcfFree(g_eccCommSpec);
}

HWTEST_F(CryptoSm2AsyKeyGeneratorBySpecSubTest, CryptoSm2AsyKeyGeneratorBySpecTest097, TestSize.Level0)
{
    ConstructEccKeyPairCommParamsSpec("NID_sm2", &g_eccCommSpec);
    ASSERT_NE(g_eccCommSpec, nullptr);
    HcfAsyKeyParamsSpec *paramSpec = nullptr;
    HcfResult res = ConstructEccKeyPairParamsSpec(g_sm2AlgName.c_str(), g_eccCommSpec, &paramSpec);

    ASSERT_EQ(res, HCF_SUCCESS);

    HcfAsyKeyGeneratorBySpec *generator = nullptr;
    res = HcfAsyKeyGeneratorBySpecCreate(paramSpec, &generator);

    HcfPubKey *pubKey = nullptr;
    res = generator->generatePubKey(generator, &pubKey);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(pubKey, nullptr);

    res = pubKey->getAsyKeySpecString(pubKey, ECC_CURVE_NAME_STR, nullptr);
    ASSERT_EQ(res, HCF_INVALID_PARAMS);
    char *retStr = nullptr;
    res = pubKey->getAsyKeySpecString(pubKey, ECC_FIELD_SIZE_INT, &retStr);
    ASSERT_EQ(res, HCF_INVALID_PARAMS);

    HcfObjDestroy(pubKey);
    HcfObjDestroy(generator);
    DestroyEccKeyPairSpec(reinterpret_cast<HcfEccKeyPairParamsSpec *>(paramSpec));
    HcfFree(g_eccCommSpec);
}

HWTEST_F(CryptoSm2AsyKeyGeneratorBySpecSubTest, CryptoSm2AsyKeyGeneratorBySpecTest098, TestSize.Level0)
{
    HcfAsyKeyParamsSpec *paramSpec = nullptr;
    HcfResult res = ConstructSm2256CommParamsSpec(&paramSpec);
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
    retStr = nullptr;
    res = keyPair->pubKey->getAsyKeySpecString(keyPair->pubKey, item, &retStr);
    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(retStr, nullptr);
    HcfFree(retStr);
    HcfObjDestroy(keyPair);
    HcfObjDestroy(generator);
    FreeEccCommParamsSpec(reinterpret_cast<HcfEccCommParamsSpec *>(paramSpec));
    HcfFree(paramSpec);
}

HWTEST_F(CryptoSm2AsyKeyGeneratorBySpecSubTest, CryptoSm2AsyKeyGeneratorBySpecTest099, TestSize.Level0)
{
    HcfAsyKeyParamsSpec *paramSpec = nullptr;
    HcfResult res = ConstructSm2256CommParamsSpec(&paramSpec);
    ASSERT_EQ(res, HCF_SUCCESS);

    HcfAsyKeyGeneratorBySpec *generator = nullptr;
    res = HcfAsyKeyGeneratorBySpecCreate(paramSpec, &generator);

    HcfKeyPair *keyPair = nullptr;
    res = generator->generateKeyPair(generator, &keyPair);
    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(keyPair, nullptr);

    AsyKeySpecItem item = ECC_FIELD_TYPE_STR;

    res = keyPair->pubKey->getAsyKeySpecString(keyPair->pubKey, item, nullptr);
    ASSERT_EQ(res, HCF_INVALID_PARAMS);

    HcfObjDestroy(keyPair);
    HcfObjDestroy(generator);
    FreeEccCommParamsSpec(reinterpret_cast<HcfEccCommParamsSpec *>(paramSpec));
    HcfFree(paramSpec);
}

HWTEST_F(CryptoSm2AsyKeyGeneratorBySpecSubTest, CryptoSm2AsyKeyGeneratorBySpecTest100, TestSize.Level0)
{
    ConstructEccKeyPairCommParamsSpec("NID_sm2", &g_eccCommSpec);
    ASSERT_NE(g_eccCommSpec, nullptr);
    HcfAsyKeyParamsSpec *paramSpec = nullptr;
    HcfResult res = ConstructEccKeyPairParamsSpec(g_sm2AlgName.c_str(), g_eccCommSpec, &paramSpec);

    ASSERT_EQ(res, HCF_SUCCESS);

    HcfAsyKeyGeneratorBySpec *generator = nullptr;
    res = HcfAsyKeyGeneratorBySpecCreate(paramSpec, &generator);

    HcfKeyPair *keyPair = nullptr;
    res = generator->generateKeyPair(generator, &keyPair);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(keyPair, nullptr);

    int retInt = 0;
    AsyKeySpecItem item = ECC_FIELD_SIZE_INT;
    res = keyPair->pubKey->getAsyKeySpecInt(keyPair->pubKey, item, &retInt);
    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(retInt, 0);
    retInt = 0;
    res = keyPair->priKey->getAsyKeySpecInt(keyPair->priKey, item, &retInt);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(retInt, 0);

    HcfObjDestroy(keyPair);
    HcfObjDestroy(generator);
    DestroyEccKeyPairSpec(reinterpret_cast<HcfEccKeyPairParamsSpec *>(paramSpec));
    HcfFree(g_eccCommSpec);
}

HWTEST_F(CryptoSm2AsyKeyGeneratorBySpecSubTest, CryptoSm2AsyKeyGeneratorBySpecTest101, TestSize.Level0)
{
    ConstructEccKeyPairCommParamsSpec("NID_sm2", &g_eccCommSpec);
    ASSERT_NE(g_eccCommSpec, nullptr);
    HcfAsyKeyParamsSpec *paramSpec = nullptr;
    HcfResult res = ConstructEccKeyPairParamsSpec(g_sm2AlgName.c_str(), g_eccCommSpec, &paramSpec);

    ASSERT_EQ(res, HCF_SUCCESS);

    HcfAsyKeyGeneratorBySpec *generator = nullptr;
    res = HcfAsyKeyGeneratorBySpecCreate(paramSpec, &generator);

    HcfKeyPair *keyPair = nullptr;
    res = generator->generateKeyPair(generator, &keyPair);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(keyPair, nullptr);

    res = keyPair->priKey->getAsyKeySpecInt(keyPair->priKey, ECC_FIELD_SIZE_INT, nullptr);
    ASSERT_EQ(res, HCF_INVALID_PARAMS);
    int retInt = 0;
    res = keyPair->priKey->getAsyKeySpecInt(keyPair->priKey, ECC_FIELD_TYPE_STR, &retInt);
    ASSERT_EQ(res, HCF_INVALID_PARAMS);
    HcfBigInteger retBigInt = { .data = nullptr, .len = 0 };
    res = keyPair->priKey->getAsyKeySpecBigInteger(keyPair->priKey, ECC_SK_BN, nullptr);
    ASSERT_EQ(res, HCF_INVALID_PARAMS);
    res = keyPair->priKey->getAsyKeySpecBigInteger(keyPair->priKey, DSA_SK_BN, &retBigInt);
    ASSERT_EQ(res, HCF_INVALID_PARAMS);
    HcfObjDestroy(keyPair);
    HcfObjDestroy(generator);
    DestroyEccKeyPairSpec(reinterpret_cast<HcfEccKeyPairParamsSpec *>(paramSpec));
    HcfFree(g_eccCommSpec);
}

static HcfResult ConstructSm2256KeyPairParamsSpecByGet(HcfEccKeyPairParamsSpec *eccKeyPairSpec,
    HcfBigInteger *params, int h, HcfEccCommParamsSpec *eccCommSpec)
{
    eccKeyPairSpec->base.base.algName = eccCommSpec->base.algName;
    eccKeyPairSpec->base.base.specType = HCF_KEY_PAIR_SPEC;
    eccKeyPairSpec->base.field = eccCommSpec->field;
    eccKeyPairSpec->base.field->fieldType = eccCommSpec->field->fieldType;
    ((HcfECFieldFp *)(eccKeyPairSpec->base.field))->p.data = params[ZERO].data;
    ((HcfECFieldFp *)(eccKeyPairSpec->base.field))->p.len = params[ZERO].len;
    eccKeyPairSpec->base.a.data = params[ONE].data;
    eccKeyPairSpec->base.a.len = params[ONE].len;
    eccKeyPairSpec->base.b.data = params[TWO].data;
    eccKeyPairSpec->base.b.len = params[TWO].len;
    eccKeyPairSpec->base.g.x.data = params[THREE].data;
    eccKeyPairSpec->base.g.x.len = params[THREE].len;
    eccKeyPairSpec->base.g.y.data = params[FOUR].data;
    eccKeyPairSpec->base.g.y.len = params[FOUR].len;

    eccKeyPairSpec->base.n.data = params[FIVE].data;
    eccKeyPairSpec->base.n.len = params[FIVE].len;
    eccKeyPairSpec->base.h = h;
    eccKeyPairSpec->pk.x.data = params[SIX].data;
    eccKeyPairSpec->pk.x.len = params[SIX].len;
    eccKeyPairSpec->pk.y.data = params[SEVEN].data;
    eccKeyPairSpec->pk.y.len = params[SEVEN].len;

    eccKeyPairSpec->sk.data = params[EIGHT].data;
    eccKeyPairSpec->sk.len = params[EIGHT].len;
    return HCF_SUCCESS;
}

static void GetParams(HcfPriKey *priKey, HcfPubKey *pubKey, HcfBigInteger *params, int *retH)
{
    HcfBigInteger retFp = { .data = nullptr, .len = 0 };
    HcfBigInteger retA = { .data = nullptr, .len = 0 };
    HcfBigInteger retB = { .data = nullptr, .len = 0 };
    HcfBigInteger retGX = { .data = nullptr, .len = 0 };
    HcfBigInteger retGY = { .data = nullptr, .len = 0 };
    HcfBigInteger retN = { .data = nullptr, .len = 0 };
    HcfBigInteger retSk = { .data = nullptr, .len = 0 };
    HcfBigInteger retPkX = { .data = nullptr, .len = 0 };
    HcfBigInteger retPkY = { .data = nullptr, .len = 0 };
    HcfResult res = priKey->getAsyKeySpecBigInteger(priKey, ECC_FP_P_BN, &retFp);
    EXPECT_EQ(res, HCF_SUCCESS);
    res = priKey->getAsyKeySpecBigInteger(priKey, ECC_A_BN, &retA);
    EXPECT_EQ(res, HCF_SUCCESS);
    res = priKey->getAsyKeySpecBigInteger(priKey, ECC_B_BN, &retB);
    EXPECT_EQ(res, HCF_SUCCESS);
    res = priKey->getAsyKeySpecBigInteger(priKey, ECC_G_X_BN, &retGX);
    EXPECT_EQ(res, HCF_SUCCESS);
    res = priKey->getAsyKeySpecBigInteger(priKey, ECC_G_Y_BN, &retGY);
    EXPECT_EQ(res, HCF_SUCCESS);
    res = priKey->getAsyKeySpecBigInteger(priKey, ECC_N_BN, &retN);
    EXPECT_EQ(res, HCF_SUCCESS);
    res = pubKey->getAsyKeySpecBigInteger(pubKey, ECC_PK_X_BN, &retPkX);
    EXPECT_EQ(res, HCF_SUCCESS);
    res = pubKey->getAsyKeySpecBigInteger(pubKey, ECC_PK_Y_BN, &retPkY);
    EXPECT_EQ(res, HCF_SUCCESS);
    res = priKey->getAsyKeySpecBigInteger(priKey, ECC_SK_BN, &retSk);
    EXPECT_EQ(res, HCF_SUCCESS);
    res = pubKey->getAsyKeySpecInt(pubKey, ECC_H_INT, retH);
    EXPECT_EQ(res, HCF_SUCCESS);
    params[ZERO].data = retFp.data;
    params[ZERO].len = retFp.len;
    params[ONE].data = retA.data;
    params[ONE].len = retA.len;
    params[TWO].data = retB.data;
    params[TWO].len = retB.len;
    params[THREE].data = retGX.data;
    params[THREE].len = retGX.len;
    params[FOUR].data = retGY.data;
    params[FOUR].len = retGY.len;
    params[FIVE].data = retN.data;
    params[FIVE].len = retN.len;
    params[SIX].data = retPkX.data;
    params[SIX].len = retPkX.len;
    params[SEVEN].data = retPkY.data;
    params[SEVEN].len = retPkY.len;
    params[EIGHT].data = retSk.data;
    params[EIGHT].len = retSk.len;
}

static void FreeEccCommParams(HcfEccCommParamsSpec *spec)
{
    if (spec == NULL) {
        return;
    }
    HcfFree(spec->a.data);
    spec->a.data = NULL;
    HcfFree(spec->b.data);
    spec->b.data = NULL;
    HcfFree(spec->n.data);
    spec->n.data = NULL;
    HcfECFieldFp *fp = reinterpret_cast<HcfECFieldFp *>(spec->field);
    HcfFree(fp->p.data);
    fp->p.data = NULL;

    FreeEcPointMem(&(spec->g));
}
HWTEST_F(CryptoSm2AsyKeyGeneratorBySpecSubTest, CryptoSm2AsyKeyGeneratorBySpecTest102, TestSize.Level0)
{
    HcfAsyKeyGenerator *generator = nullptr;
    HcfResult res = HcfAsyKeyGeneratorCreate(g_sm2AlgName.c_str(), &generator);

    HcfKeyPair *keyPair = nullptr;
    res = generator->generateKeyPair(generator, nullptr, &keyPair);

    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(keyPair, nullptr);

    int retH = 0;
    HcfBigInteger params[9];
    GetParams(keyPair->priKey, keyPair->pubKey, params, &retH);

    HcfEccCommParamsSpec *eccCommSpec = nullptr;
    ConstructEccKeyPairCommParamsSpec("NID_sm2", &eccCommSpec);
    ASSERT_NE(eccCommSpec, nullptr);
    HcfECFieldFp *fp = reinterpret_cast<HcfECFieldFp *>(eccCommSpec->field);
    HcfFree(fp->p.data);
    HcfEccKeyPairParamsSpec *eccKeyPairSpec =
        reinterpret_cast<HcfEccKeyPairParamsSpec *>(HcfMalloc(sizeof(HcfEccKeyPairParamsSpec), 0));
    res = ConstructSm2256KeyPairParamsSpecByGet(eccKeyPairSpec, params, retH, eccCommSpec);
    HcfAsyKeyGeneratorBySpec *generatorSpec = nullptr;
    res = HcfAsyKeyGeneratorBySpecCreate(reinterpret_cast<HcfAsyKeyParamsSpec *>(eccKeyPairSpec), &generatorSpec);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(generatorSpec, nullptr);

    HcfKeyPair *dupKeyPair = nullptr;
    res = generatorSpec->generateKeyPair(generatorSpec, &dupKeyPair);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(dupKeyPair, nullptr);

    HcfObjDestroy(dupKeyPair);
    HcfObjDestroy(keyPair);
    HcfObjDestroy(generator);
    HcfObjDestroy(generatorSpec);
    FreeEccCommParams(eccCommSpec);
    DestroyEccKeyPairSpec(eccKeyPairSpec);
    HcfFree(eccCommSpec);
}

static void OpensslMockTestFunc(uint32_t mallocCount, HcfAsyKeyParamsSpec *paramSpec)
{
    for (uint32_t i = 0; i < mallocCount - THREE; i++) {
        ResetOpensslCallNum();
        SetOpensslCallMockIndex(i);

        HcfAsyKeyGeneratorBySpec *generatorBySpec = nullptr;
        HcfResult res = HcfAsyKeyGeneratorBySpecCreate(paramSpec, &generatorBySpec);
        if (res != HCF_SUCCESS) {
            continue;
        }
        HcfKeyPair *keyPair = nullptr;
        res = generatorBySpec->generateKeyPair(generatorBySpec, &keyPair);
        if (res != HCF_SUCCESS) {
            HcfObjDestroy(generatorBySpec);
            continue;
        }
        HcfBlob pubKeyBlob = { .data = nullptr, .len = 0 };
        res = keyPair->pubKey->base.getEncoded(&(keyPair->pubKey->base), &pubKeyBlob);
        if (res != HCF_SUCCESS) {
            HcfObjDestroy(keyPair);
            HcfObjDestroy(generatorBySpec);
            continue;
        }
        HcfBlob priKeyBlob = { .data = nullptr, .len = 0 };
        res = keyPair->priKey->base.getEncoded(&(keyPair->priKey->base), &priKeyBlob);
        if (res != HCF_SUCCESS) {
            HcfFree(pubKeyBlob.data);
            HcfObjDestroy(keyPair);
            HcfObjDestroy(generatorBySpec);
            continue;
        }
        HcfFree(pubKeyBlob.data);
        HcfFree(priKeyBlob.data);
        HcfObjDestroy(keyPair);
        HcfObjDestroy(generatorBySpec);
    }
}

HWTEST_F(CryptoSm2AsyKeyGeneratorBySpecSubTest, CryptoSm2AsyKeyGeneratorBySpecTest103, TestSize.Level0)
{
    ConstructEccKeyPairCommParamsSpec("NID_sm2", &g_eccCommSpec);
    ASSERT_NE(g_eccCommSpec, nullptr);
    HcfAsyKeyParamsSpec *paramSpec = nullptr;
    HcfResult res = ConstructEccKeyPairParamsSpec(g_sm2AlgName.c_str(), g_eccCommSpec, &paramSpec);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(paramSpec, nullptr);

    StartRecordOpensslCallNum();
    HcfAsyKeyGeneratorBySpec *generatorBySpec = nullptr;
    res = HcfAsyKeyGeneratorBySpecCreate(paramSpec, &generatorBySpec);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(generatorBySpec, nullptr);

    HcfKeyPair *keyPair = nullptr;
    res = generatorBySpec->generateKeyPair(generatorBySpec, &keyPair);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(keyPair, nullptr);

    HcfBlob pubKeyBlob = { .data = nullptr, .len = 0 };
    res = keyPair->pubKey->base.getEncoded(&(keyPair->pubKey->base), &pubKeyBlob);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(pubKeyBlob.data, nullptr);
    ASSERT_NE(pubKeyBlob.len, 0);

    HcfBlob priKeyBlob = { .data = nullptr, .len = 0 };
    res = keyPair->priKey->base.getEncoded(&(keyPair->priKey->base), &priKeyBlob);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(priKeyBlob.data, nullptr);
    ASSERT_NE(priKeyBlob.len, 0);

    HcfFree(pubKeyBlob.data);
    HcfFree(priKeyBlob.data);
    HcfObjDestroy(keyPair);
    HcfObjDestroy(generatorBySpec);

    uint32_t mallocCount = GetOpensslCallNum();
    OpensslMockTestFunc(mallocCount, paramSpec);
    DestroyEccKeyPairSpec(reinterpret_cast<HcfEccKeyPairParamsSpec *>(paramSpec));
    HcfFree(g_eccCommSpec);

    EndRecordOpensslCallNum();
}

static void OpensslMockTestFunc1(uint32_t mallocCount, HcfAsyKeyParamsSpec *paramSpec)
{
    for (uint32_t i = 0; i < mallocCount - 1; i++) {
        ResetOpensslCallNum();
        SetOpensslCallMockIndex(i);

        HcfAsyKeyGeneratorBySpec *generatorBySpec = nullptr;
        HcfResult res = HcfAsyKeyGeneratorBySpecCreate(paramSpec, &generatorBySpec);
        if (res != HCF_SUCCESS) {
            continue;
        }
        HcfKeyPair *keyPair = nullptr;
        res = generatorBySpec->generateKeyPair(generatorBySpec, &keyPair);
        if (res != HCF_SUCCESS) {
            HcfObjDestroy(generatorBySpec);
            continue;
        }
        HcfObjDestroy(keyPair);
        HcfObjDestroy(generatorBySpec);
    }
}

HWTEST_F(CryptoSm2AsyKeyGeneratorBySpecSubTest, CryptoSm2AsyKeyGeneratorBySpecTest104, TestSize.Level0)
{
    HcfAsyKeyParamsSpec *paramSpec = nullptr;
    HcfResult res = ConstructSm2256CommParamsSpec(&paramSpec);
    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(paramSpec, nullptr);

    StartRecordOpensslCallNum();
    HcfAsyKeyGeneratorBySpec *generatorBySpec = nullptr;
    res = HcfAsyKeyGeneratorBySpecCreate(paramSpec, &generatorBySpec);
    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(generatorBySpec, nullptr);

    HcfKeyPair *keyPair = nullptr;
    res = generatorBySpec->generateKeyPair(generatorBySpec, &keyPair);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(keyPair, nullptr);

    HcfObjDestroy(keyPair);
    HcfObjDestroy(generatorBySpec);

    uint32_t mallocCount = GetOpensslCallNum();
    OpensslMockTestFunc1(mallocCount, paramSpec);
    FreeEccCommParamsSpec(reinterpret_cast<HcfEccCommParamsSpec *>(paramSpec));
    HcfFree(paramSpec);

    EndRecordOpensslCallNum();
}

static void OpensslMockTestFunc2(uint32_t mallocCount, HcfAsyKeyParamsSpec *paramSpec)
{
    for (uint32_t i = 0; i < mallocCount - FIVE; i++) {
        ResetOpensslCallNum();
        SetOpensslCallMockIndex(i);

        HcfAsyKeyGeneratorBySpec *generatorBySpec = nullptr;
        HcfResult res = HcfAsyKeyGeneratorBySpecCreate(paramSpec, &generatorBySpec);
        if (res != HCF_SUCCESS) {
            continue;
        }
        HcfPriKey *priKey = nullptr;
        res = generatorBySpec->generatePriKey(generatorBySpec, &priKey);
        if (res != HCF_SUCCESS) {
            HcfObjDestroy(generatorBySpec);
            continue;
        }
        HcfObjDestroy(priKey);
        HcfObjDestroy(generatorBySpec);
    }
}

HWTEST_F(CryptoSm2AsyKeyGeneratorBySpecSubTest, CryptoSm2AsyKeyGeneratorBySpecTest105, TestSize.Level0)
{
    ConstructEccKeyPairCommParamsSpec("NID_sm2", &g_eccCommSpec);
    ASSERT_NE(g_eccCommSpec, nullptr);
    HcfAsyKeyParamsSpec *paramSpec = nullptr;
    HcfResult res = ConstructEccPriKeyParamsSpec(g_sm2AlgName.c_str(), g_eccCommSpec, &paramSpec);
    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(paramSpec, nullptr);

    StartRecordOpensslCallNum();
    HcfAsyKeyGeneratorBySpec *generatorBySpec = nullptr;
    res = HcfAsyKeyGeneratorBySpecCreate(paramSpec, &generatorBySpec);
    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(generatorBySpec, nullptr);

    HcfPriKey *priKey = nullptr;
    res = generatorBySpec->generatePriKey(generatorBySpec, &priKey);
    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(priKey, nullptr);

    HcfObjDestroy(priKey);
    HcfObjDestroy(generatorBySpec);

    uint32_t mallocCount = GetOpensslCallNum();
    OpensslMockTestFunc2(mallocCount, paramSpec);
    DestroyEccPriKeySpec(reinterpret_cast<HcfEccPriKeyParamsSpec *>(paramSpec));
    HcfFree(g_eccCommSpec);

    EndRecordOpensslCallNum();
}

static void OpensslMockTestFunc3(uint32_t mallocCount, HcfAsyKeyParamsSpec *paramSpec)
{
    for (uint32_t i = 0; i < mallocCount - 1; i++) {
        ResetOpensslCallNum();
        SetOpensslCallMockIndex(i);

        HcfAsyKeyGeneratorBySpec *generatorBySpec = nullptr;
        HcfResult res = HcfAsyKeyGeneratorBySpecCreate(paramSpec, &generatorBySpec);
        if (res != HCF_SUCCESS) {
            continue;
        }
        HcfPubKey *pubKey = nullptr;
        res = generatorBySpec->generatePubKey(generatorBySpec, &pubKey);
        if (res != HCF_SUCCESS) {
            HcfObjDestroy(generatorBySpec);
            continue;
        }
        HcfObjDestroy(pubKey);
        HcfObjDestroy(generatorBySpec);
    }
}

HWTEST_F(CryptoSm2AsyKeyGeneratorBySpecSubTest, CryptoSm2AsyKeyGeneratorBySpecTest106, TestSize.Level0)
{
    ConstructEccKeyPairCommParamsSpec("NID_sm2", &g_eccCommSpec);
    ASSERT_NE(g_eccCommSpec, nullptr);
    HcfAsyKeyParamsSpec *paramSpec = nullptr;
    HcfResult res = ConstructEccPubKeyParamsSpec(g_sm2AlgName.c_str(), g_eccCommSpec, &paramSpec);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(paramSpec, nullptr);

    StartRecordOpensslCallNum();
    HcfAsyKeyGeneratorBySpec *generatorBySpec = nullptr;
    res = HcfAsyKeyGeneratorBySpecCreate(paramSpec, &generatorBySpec);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(generatorBySpec, nullptr);

    HcfPubKey *pubKey = nullptr;
    res = generatorBySpec->generatePubKey(generatorBySpec, &pubKey);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(pubKey, nullptr);

    HcfObjDestroy(pubKey);
    HcfObjDestroy(generatorBySpec);

    uint32_t mallocCount = GetOpensslCallNum();
    OpensslMockTestFunc3(mallocCount, paramSpec);
    DestroyEccPubKeySpec(reinterpret_cast<HcfEccPubKeyParamsSpec *>(paramSpec));

    EndRecordOpensslCallNum();
}
}
