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

class CryptoSm2AsyKeyGeneratorBySpecTest : public testing::Test {
public:
    static void SetUpTestCase(){};
    static void TearDownTestCase(){};
    void SetUp();
    void TearDown();
};

void CryptoSm2AsyKeyGeneratorBySpecTest::SetUp() {}
void CryptoSm2AsyKeyGeneratorBySpecTest::TearDown() {}

static const char *GetMockClass(void)
{
    return "HcfSymKeyGenerator";
}

HcfObjectBase g_obj = {
    .getClass = GetMockClass,
    .destroy = nullptr
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

/**
 * @tc.name: CryptoEccAsyKeyGeneratorBySpecTest.CryptoSm2AsyKeyGeneratorBySpecTest001
 * @tc.desc: Verify that the creation of the sm2 key pair generator is normal.
 * @tc.type: FUNC
 * @tc.require: I5QWEI
 */
HWTEST_F(CryptoSm2AsyKeyGeneratorBySpecTest, CryptoSm2AsyKeyGeneratorBySpecTest001, TestSize.Level0)
{
    HcfAsyKeyParamsSpec *paramSpec = nullptr;
    HcfResult res = ConstructSm2256CommParamsSpec(&paramSpec);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(paramSpec, nullptr);

    HcfAsyKeyGeneratorBySpec *generator = nullptr;
    res = HcfAsyKeyGeneratorBySpecCreate(paramSpec, &generator);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(generator, nullptr);

    HcfObjDestroy(generator);
    FreeEccCommParamsSpec(reinterpret_cast<HcfEccCommParamsSpec *>(paramSpec));
    HcfFree(paramSpec);
}

HWTEST_F(CryptoSm2AsyKeyGeneratorBySpecTest, CryptoSm2AsyKeyGeneratorBySpecTest002, TestSize.Level0)
{
    HcfAsyKeyGeneratorBySpec *generator = nullptr;

    HcfResult res = HcfAsyKeyGeneratorBySpecCreate(nullptr, &generator);

    ASSERT_NE(res, HCF_SUCCESS);
    ASSERT_EQ(generator, nullptr);

    HcfObjDestroy(generator);
}

HWTEST_F(CryptoSm2AsyKeyGeneratorBySpecTest, CryptoSm2AsyKeyGeneratorBySpecTest003, TestSize.Level0)
{
    HcfAsyKeyParamsSpec *paramSpec = nullptr;
    HcfResult res = ConstructSm2256CommParamsSpec(&paramSpec);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(paramSpec, nullptr);

    res = HcfAsyKeyGeneratorBySpecCreate(paramSpec, nullptr);
    ASSERT_NE(res, HCF_SUCCESS);
    FreeEccCommParamsSpec(reinterpret_cast<HcfEccCommParamsSpec *>(paramSpec));
    HcfFree(paramSpec);
}

HWTEST_F(CryptoSm2AsyKeyGeneratorBySpecTest, CryptoSm2AsyKeyGeneratorBySpecTest004, TestSize.Level0)
{
    HcfAsyKeyParamsSpec *paramSpec = nullptr;
    HcfResult res = ConstructSm2256CommParamsSpec(&paramSpec);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(paramSpec, nullptr);

    HcfAsyKeyGeneratorBySpec *generator = nullptr;
    res = HcfAsyKeyGeneratorBySpecCreate(paramSpec, &generator);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(generator, nullptr);

    const char *className = generator->base.getClass();
    ASSERT_NE(className, nullptr);

    HcfObjDestroy(generator);
    FreeEccCommParamsSpec(reinterpret_cast<HcfEccCommParamsSpec *>(paramSpec));
    HcfFree(paramSpec);
}

HWTEST_F(CryptoSm2AsyKeyGeneratorBySpecTest, CryptoSm2AsyKeyGeneratorBySpecTest005, TestSize.Level0)
{
    HcfAsyKeyParamsSpec *paramSpec = nullptr;
    HcfResult res = ConstructSm2256CommParamsSpec(&paramSpec);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(paramSpec, nullptr);

    HcfAsyKeyGeneratorBySpec *generator = nullptr;
    res = HcfAsyKeyGeneratorBySpecCreate(paramSpec, &generator);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(generator, nullptr);

    generator->base.destroy((HcfObjectBase *)generator);
    FreeEccCommParamsSpec(reinterpret_cast<HcfEccCommParamsSpec *>(paramSpec));
    HcfFree(paramSpec);
}

HWTEST_F(CryptoSm2AsyKeyGeneratorBySpecTest, CryptoSm2AsyKeyGeneratorBySpecTest006, TestSize.Level0)
{
    HcfAsyKeyParamsSpec *paramSpec = nullptr;
    HcfResult res = ConstructSm2256CommParamsSpec(&paramSpec);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(paramSpec, nullptr);

    HcfAsyKeyGeneratorBySpec *generator = nullptr;
    res = HcfAsyKeyGeneratorBySpecCreate(paramSpec, &generator);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(generator, nullptr);

    generator->base.destroy(nullptr);
    HcfObjDestroy(generator);
    FreeEccCommParamsSpec(reinterpret_cast<HcfEccCommParamsSpec *>(paramSpec));
    HcfFree(paramSpec);
}

HWTEST_F(CryptoSm2AsyKeyGeneratorBySpecTest, CryptoSm2AsyKeyGeneratorBySpecTest007, TestSize.Level0)
{
    HcfAsyKeyParamsSpec *paramSpec = nullptr;
    HcfResult res = ConstructSm2256CommParamsSpec(&paramSpec);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(paramSpec, nullptr);

    HcfAsyKeyGeneratorBySpec *generator = nullptr;
    res = HcfAsyKeyGeneratorBySpecCreate(paramSpec, &generator);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(generator, nullptr);

    generator->base.destroy(&g_obj);
    HcfObjDestroy(generator);
    FreeAsyKeySpec(paramSpec);
}

HWTEST_F(CryptoSm2AsyKeyGeneratorBySpecTest, CryptoSm2AsyKeyGeneratorBySpecTest008, TestSize.Level0)
{
    HcfAsyKeyParamsSpec *paramSpec = nullptr;
    HcfResult res = ConstructSm2256CommParamsSpec(&paramSpec);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(paramSpec, nullptr);

    HcfAsyKeyGeneratorBySpec *generator = nullptr;
    res = HcfAsyKeyGeneratorBySpecCreate(paramSpec, &generator);
    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(generator, nullptr);

    const char *algName = generator->getAlgName(generator);
    ASSERT_NE(algName, nullptr);

    HcfObjDestroy(generator);
    FreeEccCommParamsSpec(reinterpret_cast<HcfEccCommParamsSpec *>(paramSpec));
    HcfFree(paramSpec);
}

HWTEST_F(CryptoSm2AsyKeyGeneratorBySpecTest, CryptoSm2AsyKeyGeneratorBySpecTest009, TestSize.Level0)
{
    HcfAsyKeyParamsSpec *paramSpec = nullptr;
    HcfResult res = ConstructSm2256CommParamsSpec(&paramSpec);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(paramSpec, nullptr);

    HcfAsyKeyGeneratorBySpec *generator = nullptr;
    res = HcfAsyKeyGeneratorBySpecCreate(paramSpec, &generator);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(generator, nullptr);

    const char *algName = generator->getAlgName(nullptr);
    ASSERT_EQ(algName, nullptr);

    HcfObjDestroy(generator);
    FreeAsyKeySpec(paramSpec);
}


HWTEST_F(CryptoSm2AsyKeyGeneratorBySpecTest, CryptoSm2AsyKeyGeneratorBySpecTest010, TestSize.Level0)
{
    HcfAsyKeyParamsSpec *paramSpec = nullptr;
    HcfResult res = ConstructSm2256CommParamsSpec(&paramSpec);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(paramSpec, nullptr);

    HcfAsyKeyGeneratorBySpec *generator = nullptr;
    res = HcfAsyKeyGeneratorBySpecCreate(paramSpec, &generator);
    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(generator, nullptr);

    const char *algName = generator->getAlgName((HcfAsyKeyGeneratorBySpec *)&g_obj);
    ASSERT_EQ(algName, nullptr);

    HcfObjDestroy(generator);
    FreeEccCommParamsSpec(reinterpret_cast<HcfEccCommParamsSpec *>(paramSpec));
    HcfFree(paramSpec);
}

HWTEST_F(CryptoSm2AsyKeyGeneratorBySpecTest, CryptoSm2AsyKeyGeneratorBySpecTest011, TestSize.Level0)
{
    ConstructEccKeyPairCommParamsSpec("NID_sm2", &g_eccCommSpec);
    ASSERT_NE(g_eccCommSpec, nullptr);
    HcfAsyKeyParamsSpec *paramSpec = nullptr;
    HcfResult res = ConstructEccKeyPairParamsSpec(g_sm2AlgName.c_str(), g_eccCommSpec, &paramSpec);
    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(paramSpec, nullptr);

    HcfAsyKeyGeneratorBySpec *generator = nullptr;
    res = HcfAsyKeyGeneratorBySpecCreate(paramSpec, &generator);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(generator, nullptr);

    HcfKeyPair *keyPair = nullptr;
    res = generator->generateKeyPair(generator, &keyPair);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(keyPair, nullptr);

    HcfObjDestroy(keyPair);
    HcfObjDestroy(generator);
    DestroyEccKeyPairSpec(reinterpret_cast<HcfEccKeyPairParamsSpec *>(paramSpec));
    HcfFree(g_eccCommSpec);
}

HWTEST_F(CryptoSm2AsyKeyGeneratorBySpecTest, CryptoSm2AsyKeyGeneratorBySpecTest012, TestSize.Level0)
{
    HcfEccCommParamsSpec *eccCommSpec = nullptr;
    ConstructEccKeyPairCommParamsSpec("NID_sm2", &eccCommSpec);
    ASSERT_NE(eccCommSpec, nullptr);
    HcfAsyKeyParamsSpec *paramSpec = nullptr;
    HcfResult res = ConstructEccKeyPairParamsSpec(g_sm2AlgName.c_str(), eccCommSpec, &paramSpec);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(paramSpec, nullptr);

    HcfAsyKeyGeneratorBySpec *generator = nullptr;
    res = HcfAsyKeyGeneratorBySpecCreate(paramSpec, &generator);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(generator, nullptr);

    HcfKeyPair *keyPair = nullptr;
    res = generator->generateKeyPair(nullptr, &keyPair);

    ASSERT_NE(res, HCF_SUCCESS);
    ASSERT_EQ(keyPair, nullptr);

    HcfObjDestroy(keyPair);
    HcfObjDestroy(generator);
    FreeAsyKeySpec(paramSpec);
    HcfFree(eccCommSpec);
}

HWTEST_F(CryptoSm2AsyKeyGeneratorBySpecTest, CryptoSm2AsyKeyGeneratorBySpecTest013, TestSize.Level0)
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

    res = generator->generateKeyPair(generator, nullptr);
    ASSERT_NE(res, HCF_SUCCESS);

    HcfObjDestroy(generator);
    DestroyEccKeyPairSpec(reinterpret_cast<HcfEccKeyPairParamsSpec *>(paramSpec));
    HcfFree(g_eccCommSpec);
}

HWTEST_F(CryptoSm2AsyKeyGeneratorBySpecTest, CryptoSm2AsyKeyGeneratorBySpecTest014, TestSize.Level0)
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

    res = generator->generateKeyPair(nullptr, nullptr);
    ASSERT_NE(res, HCF_SUCCESS);

    HcfObjDestroy(generator);
    DestroyEccKeyPairSpec(reinterpret_cast<HcfEccKeyPairParamsSpec *>(paramSpec));
    HcfFree(g_eccCommSpec);
}

HWTEST_F(CryptoSm2AsyKeyGeneratorBySpecTest, CryptoSm2AsyKeyGeneratorBySpecTest015, TestSize.Level0)
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

    const char *className = keyPair->base.getClass();
    ASSERT_NE(className, nullptr);

    HcfObjDestroy(keyPair);
    HcfObjDestroy(generator);
    DestroyEccKeyPairSpec(reinterpret_cast<HcfEccKeyPairParamsSpec *>(paramSpec));
    HcfFree(g_eccCommSpec);
}

HWTEST_F(CryptoSm2AsyKeyGeneratorBySpecTest, CryptoSm2AsyKeyGeneratorBySpecTest016, TestSize.Level0)
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

    keyPair->base.destroy((HcfObjectBase *)(&(keyPair->base)));
    HcfObjDestroy(generator);
    DestroyEccKeyPairSpec(reinterpret_cast<HcfEccKeyPairParamsSpec *>(paramSpec));
    HcfFree(g_eccCommSpec);
}

HWTEST_F(CryptoSm2AsyKeyGeneratorBySpecTest, CryptoSm2AsyKeyGeneratorBySpecTest017, TestSize.Level0)
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

    keyPair->base.destroy(nullptr);
    HcfObjDestroy(keyPair);
    HcfObjDestroy(generator);
    DestroyEccKeyPairSpec(reinterpret_cast<HcfEccKeyPairParamsSpec *>(paramSpec));
    HcfFree(g_eccCommSpec);
}

HWTEST_F(CryptoSm2AsyKeyGeneratorBySpecTest, CryptoSm2AsyKeyGeneratorBySpecTest018, TestSize.Level0)
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

    keyPair->base.destroy(&g_obj);
    HcfObjDestroy(keyPair);
    HcfObjDestroy(generator);
    DestroyEccKeyPairSpec(reinterpret_cast<HcfEccKeyPairParamsSpec *>(paramSpec));
    HcfFree(g_eccCommSpec);
}

HWTEST_F(CryptoSm2AsyKeyGeneratorBySpecTest, CryptoSm2AsyKeyGeneratorBySpecTest019, TestSize.Level0)
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

    const char *className = keyPair->pubKey->base.base.getClass();
    ASSERT_NE(className, nullptr);

    HcfObjDestroy(keyPair);
    HcfObjDestroy(generator);
    DestroyEccKeyPairSpec(reinterpret_cast<HcfEccKeyPairParamsSpec *>(paramSpec));
    HcfFree(g_eccCommSpec);
}

HWTEST_F(CryptoSm2AsyKeyGeneratorBySpecTest, CryptoSm2AsyKeyGeneratorBySpecTest020, TestSize.Level0)
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

    keyPair->pubKey->base.base.destroy((HcfObjectBase *)(&(keyPair->pubKey->base.base)));
    keyPair->pubKey = nullptr;

    HcfObjDestroy(keyPair);
    HcfObjDestroy(generator);
    DestroyEccKeyPairSpec(reinterpret_cast<HcfEccKeyPairParamsSpec *>(paramSpec));
    HcfFree(g_eccCommSpec);
}


HWTEST_F(CryptoSm2AsyKeyGeneratorBySpecTest, CryptoSm2AsyKeyGeneratorBySpecTest021, TestSize.Level0)
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

    keyPair->pubKey->base.base.destroy(nullptr);
    HcfObjDestroy(keyPair);
    HcfObjDestroy(generator);
    DestroyEccKeyPairSpec(reinterpret_cast<HcfEccKeyPairParamsSpec *>(paramSpec));
    HcfFree(g_eccCommSpec);
}


HWTEST_F(CryptoSm2AsyKeyGeneratorBySpecTest, CryptoSm2AsyKeyGeneratorBySpecTest022, TestSize.Level0)
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

    keyPair->pubKey->base.base.destroy(&g_obj);
    HcfObjDestroy(keyPair);
    HcfObjDestroy(generator);
    DestroyEccKeyPairSpec(reinterpret_cast<HcfEccKeyPairParamsSpec *>(paramSpec));
    HcfFree(g_eccCommSpec);
}

HWTEST_F(CryptoSm2AsyKeyGeneratorBySpecTest, CryptoSm2AsyKeyGeneratorBySpecTest023, TestSize.Level0)
{
    HcfEccCommParamsSpec *eccCommSpec = nullptr;
    ConstructEccKeyPairCommParamsSpec("NID_sm2", &eccCommSpec);
    ASSERT_NE(eccCommSpec, nullptr);
    HcfAsyKeyParamsSpec *paramSpec = nullptr;
    HcfResult res = ConstructEccKeyPairParamsSpec(g_sm2AlgName.c_str(), eccCommSpec, &paramSpec);
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

    const char *format = keyPair->pubKey->base.getFormat(&(keyPair->pubKey->base));
    ASSERT_NE(format, nullptr);

    HcfObjDestroy(keyPair);
    HcfObjDestroy(generator);
    DestroyEccKeyPairSpec(reinterpret_cast<HcfEccKeyPairParamsSpec *>(paramSpec));
    HcfFree(eccCommSpec);
}

HWTEST_F(CryptoSm2AsyKeyGeneratorBySpecTest, CryptoSm2AsyKeyGeneratorBySpecTest024, TestSize.Level0)
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

    const char *format = keyPair->pubKey->base.getFormat(nullptr);
    ASSERT_EQ(format, nullptr);

    HcfObjDestroy(keyPair);
    HcfObjDestroy(generator);
    DestroyEccKeyPairSpec(reinterpret_cast<HcfEccKeyPairParamsSpec *>(paramSpec));
    HcfFree(g_eccCommSpec);
}


HWTEST_F(CryptoSm2AsyKeyGeneratorBySpecTest, CryptoSm2AsyKeyGeneratorBySpecTest025, TestSize.Level0)
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

    const char *format = keyPair->pubKey->base.getFormat((HcfKey *)&g_obj);
    ASSERT_EQ(format, nullptr);

    HcfObjDestroy(keyPair);
    HcfObjDestroy(generator);
    DestroyEccKeyPairSpec(reinterpret_cast<HcfEccKeyPairParamsSpec *>(paramSpec));
    HcfFree(g_eccCommSpec);
}


HWTEST_F(CryptoSm2AsyKeyGeneratorBySpecTest, CryptoSm2AsyKeyGeneratorBySpecTest026, TestSize.Level0)
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

    const char *algName = keyPair->pubKey->base.getAlgorithm(&(keyPair->pubKey->base));
    ASSERT_NE(algName, nullptr);

    HcfObjDestroy(keyPair);
    HcfObjDestroy(generator);
    DestroyEccKeyPairSpec(reinterpret_cast<HcfEccKeyPairParamsSpec *>(paramSpec));
    HcfFree(g_eccCommSpec);
}

HWTEST_F(CryptoSm2AsyKeyGeneratorBySpecTest, CryptoSm2AsyKeyGeneratorBySpecTest027, TestSize.Level0)
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

    const char *algName = keyPair->pubKey->base.getAlgorithm(nullptr);
    ASSERT_EQ(algName, nullptr);

    HcfObjDestroy(keyPair);
    HcfObjDestroy(generator);
    DestroyEccKeyPairSpec(reinterpret_cast<HcfEccKeyPairParamsSpec *>(paramSpec));
    HcfFree(g_eccCommSpec);
}

HWTEST_F(CryptoSm2AsyKeyGeneratorBySpecTest, CryptoSm2AsyKeyGeneratorBySpecTest028, TestSize.Level0)
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

    const char *algName = keyPair->pubKey->base.getAlgorithm((HcfKey *)&g_obj);
    ASSERT_EQ(algName, nullptr);

    HcfObjDestroy(keyPair);
    HcfObjDestroy(generator);
    DestroyEccKeyPairSpec(reinterpret_cast<HcfEccKeyPairParamsSpec *>(paramSpec));
    HcfFree(g_eccCommSpec);
}

HWTEST_F(CryptoSm2AsyKeyGeneratorBySpecTest, CryptoSm2AsyKeyGeneratorBySpecTest029, TestSize.Level0)
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

    HcfBlob blob = { .data = nullptr, .len = 0 };
    res = keyPair->pubKey->base.getEncoded(&(keyPair->pubKey->base), &blob);
    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(blob.data, nullptr);
    ASSERT_NE(blob.len, 0);

    HcfFree(blob.data);
    HcfObjDestroy(keyPair);
    HcfObjDestroy(generator);
    DestroyEccKeyPairSpec(reinterpret_cast<HcfEccKeyPairParamsSpec *>(paramSpec));
    HcfFree(g_eccCommSpec);
}

HWTEST_F(CryptoSm2AsyKeyGeneratorBySpecTest, CryptoSm2AsyKeyGeneratorBySpecTest030, TestSize.Level0)
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

    HcfBlob blob = { .data = nullptr, .len = 0 };
    res = keyPair->pubKey->base.getEncoded(nullptr, &blob);
    ASSERT_NE(res, HCF_SUCCESS);
    ASSERT_EQ(blob.data, nullptr);
    ASSERT_EQ(blob.len, 0);

    HcfFree(blob.data);
    HcfObjDestroy(keyPair);
    HcfObjDestroy(generator);
    DestroyEccKeyPairSpec(reinterpret_cast<HcfEccKeyPairParamsSpec *>(paramSpec));
    HcfFree(g_eccCommSpec);
}

HWTEST_F(CryptoSm2AsyKeyGeneratorBySpecTest, CryptoSm2AsyKeyGeneratorBySpecTest031, TestSize.Level0)
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

    HcfBlob blob = { .data = nullptr, .len = 0 };
    res = keyPair->pubKey->base.getEncoded((HcfKey *)&g_obj, &blob);
    ASSERT_NE(res, HCF_SUCCESS);
    ASSERT_EQ(blob.data, nullptr);
    ASSERT_EQ(blob.len, 0);

    HcfFree(blob.data);
    HcfObjDestroy(keyPair);
    HcfObjDestroy(generator);
    DestroyEccKeyPairSpec(reinterpret_cast<HcfEccKeyPairParamsSpec *>(paramSpec));
    HcfFree(g_eccCommSpec);
}

HWTEST_F(CryptoSm2AsyKeyGeneratorBySpecTest, CryptoSm2AsyKeyGeneratorBySpecTest032, TestSize.Level0)
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

    res = keyPair->pubKey->base.getEncoded(&(keyPair->pubKey->base), nullptr);
    ASSERT_NE(res, HCF_SUCCESS);

    HcfObjDestroy(keyPair);
    HcfObjDestroy(generator);
    DestroyEccKeyPairSpec(reinterpret_cast<HcfEccKeyPairParamsSpec *>(paramSpec));
    HcfFree(g_eccCommSpec);
}

HWTEST_F(CryptoSm2AsyKeyGeneratorBySpecTest, CryptoSm2AsyKeyGeneratorBySpecTest033, TestSize.Level0)
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

    keyPair->priKey->clearMem(keyPair->priKey);
    HcfObjDestroy(keyPair);
    HcfObjDestroy(generator);
    DestroyEccKeyPairSpec(reinterpret_cast<HcfEccKeyPairParamsSpec *>(paramSpec));
    HcfFree(g_eccCommSpec);
}

HWTEST_F(CryptoSm2AsyKeyGeneratorBySpecTest, CryptoSm2AsyKeyGeneratorBySpecTest034, TestSize.Level0)
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

    keyPair->priKey->clearMem(nullptr);
    HcfObjDestroy(keyPair);
    HcfObjDestroy(generator);
    DestroyEccKeyPairSpec(reinterpret_cast<HcfEccKeyPairParamsSpec *>(paramSpec));
    HcfFree(g_eccCommSpec);
}

HWTEST_F(CryptoSm2AsyKeyGeneratorBySpecTest, CryptoSm2AsyKeyGeneratorBySpecTest035, TestSize.Level0)
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

    HcfObjDestroy(keyPair);
    HcfObjDestroy(generator);
    DestroyEccKeyPairSpec(reinterpret_cast<HcfEccKeyPairParamsSpec *>(paramSpec));
    HcfFree(g_eccCommSpec);
}

HWTEST_F(CryptoSm2AsyKeyGeneratorBySpecTest, CryptoSm2AsyKeyGeneratorBySpecTest036, TestSize.Level0)
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

    const char *className = keyPair->priKey->base.base.getClass();
    ASSERT_NE(className, nullptr);

    HcfObjDestroy(keyPair);
    HcfObjDestroy(generator);
    DestroyEccKeyPairSpec(reinterpret_cast<HcfEccKeyPairParamsSpec *>(paramSpec));
    HcfFree(g_eccCommSpec);
}

HWTEST_F(CryptoSm2AsyKeyGeneratorBySpecTest, CryptoSm2AsyKeyGeneratorBySpecTest037, TestSize.Level0)
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

    keyPair->priKey->base.base.destroy((HcfObjectBase *)(&(keyPair->priKey->base.base)));
    keyPair->priKey = nullptr;
    HcfObjDestroy(keyPair);
    HcfObjDestroy(generator);
    DestroyEccKeyPairSpec(reinterpret_cast<HcfEccKeyPairParamsSpec *>(paramSpec));
    HcfFree(g_eccCommSpec);
}


HWTEST_F(CryptoSm2AsyKeyGeneratorBySpecTest, CryptoSm2AsyKeyGeneratorBySpecTest038, TestSize.Level0)
{
    HcfEccCommParamsSpec *eccCommSpec = nullptr;
    ConstructEccKeyPairCommParamsSpec("NID_sm2", &eccCommSpec);
    ASSERT_NE(eccCommSpec, nullptr);
    HcfAsyKeyParamsSpec *paramSpec = nullptr;
    HcfResult res = ConstructEccKeyPairParamsSpec(g_sm2AlgName.c_str(), eccCommSpec, &paramSpec);
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

    keyPair->priKey->base.base.destroy(nullptr);
    HcfObjDestroy(keyPair);
    HcfObjDestroy(generator);
    DestroyEccKeyPairSpec(reinterpret_cast<HcfEccKeyPairParamsSpec *>(paramSpec));
    HcfFree(eccCommSpec);
}


HWTEST_F(CryptoSm2AsyKeyGeneratorBySpecTest, CryptoSm2AsyKeyGeneratorBySpecTest039, TestSize.Level0)
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

    keyPair->priKey->base.base.destroy(&g_obj);
    HcfObjDestroy(keyPair);
    HcfObjDestroy(generator);
    DestroyEccKeyPairSpec(reinterpret_cast<HcfEccKeyPairParamsSpec *>(paramSpec));
    HcfFree(g_eccCommSpec);
}

HWTEST_F(CryptoSm2AsyKeyGeneratorBySpecTest, CryptoSm2AsyKeyGeneratorBySpecTest040, TestSize.Level0)
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

    const char *format = keyPair->priKey->base.getFormat(&(keyPair->priKey->base));
    ASSERT_NE(format, nullptr);

    HcfObjDestroy(keyPair);
    HcfObjDestroy(generator);
    DestroyEccKeyPairSpec(reinterpret_cast<HcfEccKeyPairParamsSpec *>(paramSpec));
    HcfFree(g_eccCommSpec);
}

HWTEST_F(CryptoSm2AsyKeyGeneratorBySpecTest, CryptoSm2AsyKeyGeneratorBySpecTest041, TestSize.Level0)
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

    const char *format = keyPair->priKey->base.getFormat(nullptr);
    ASSERT_EQ(format, nullptr);

    HcfObjDestroy(keyPair);
    HcfObjDestroy(generator);
    DestroyEccKeyPairSpec(reinterpret_cast<HcfEccKeyPairParamsSpec *>(paramSpec));
    HcfFree(g_eccCommSpec);
}


HWTEST_F(CryptoSm2AsyKeyGeneratorBySpecTest, CryptoSm2AsyKeyGeneratorBySpecTest042, TestSize.Level0)
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

    const char *format = keyPair->priKey->base.getFormat((HcfKey *)&g_obj);
    ASSERT_EQ(format, nullptr);

    HcfObjDestroy(keyPair);
    HcfObjDestroy(generator);
    DestroyEccKeyPairSpec(reinterpret_cast<HcfEccKeyPairParamsSpec *>(paramSpec));
    HcfFree(g_eccCommSpec);
}


HWTEST_F(CryptoSm2AsyKeyGeneratorBySpecTest, CryptoSm2AsyKeyGeneratorBySpecTest043, TestSize.Level0)
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

    const char *algName = keyPair->priKey->base.getAlgorithm(&(keyPair->priKey->base));
    ASSERT_NE(algName, nullptr);

    HcfObjDestroy(keyPair);
    HcfObjDestroy(generator);
    DestroyEccKeyPairSpec(reinterpret_cast<HcfEccKeyPairParamsSpec *>(paramSpec));
    HcfFree(g_eccCommSpec);
}

HWTEST_F(CryptoSm2AsyKeyGeneratorBySpecTest, CryptoSm2AsyKeyGeneratorBySpecTest044, TestSize.Level0)
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

    const char *algName = keyPair->priKey->base.getAlgorithm(nullptr);
    ASSERT_EQ(algName, nullptr);

    HcfObjDestroy(keyPair);
    HcfObjDestroy(generator);
    DestroyEccKeyPairSpec(reinterpret_cast<HcfEccKeyPairParamsSpec *>(paramSpec));
    HcfFree(g_eccCommSpec);
}

HWTEST_F(CryptoSm2AsyKeyGeneratorBySpecTest, CryptoSm2AsyKeyGeneratorBySpecTest045, TestSize.Level0)
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

    const char *algName = keyPair->priKey->base.getAlgorithm((HcfKey *)&g_obj);
    ASSERT_EQ(algName, nullptr);

    HcfObjDestroy(keyPair);
    HcfObjDestroy(generator);
    DestroyEccKeyPairSpec(reinterpret_cast<HcfEccKeyPairParamsSpec *>(paramSpec));
    HcfFree(g_eccCommSpec);
}

HWTEST_F(CryptoSm2AsyKeyGeneratorBySpecTest, CryptoSm2AsyKeyGeneratorBySpecTest046, TestSize.Level0)
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

    HcfBlob blob = { .data = nullptr, .len = 0 };
    res = keyPair->priKey->base.getEncoded(&(keyPair->priKey->base), &blob);
    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(blob.data, nullptr);
    ASSERT_NE(blob.len, 0);

    HcfFree(blob.data);
    HcfObjDestroy(keyPair);
    HcfObjDestroy(generator);
    DestroyEccKeyPairSpec(reinterpret_cast<HcfEccKeyPairParamsSpec *>(paramSpec));
    HcfFree(g_eccCommSpec);
}

HWTEST_F(CryptoSm2AsyKeyGeneratorBySpecTest, CryptoSm2AsyKeyGeneratorBySpecTest047, TestSize.Level0)
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

    HcfBlob blob = { .data = nullptr, .len = 0 };
    res = keyPair->priKey->base.getEncoded(nullptr, &blob);
    ASSERT_NE(res, HCF_SUCCESS);
    ASSERT_EQ(blob.data, nullptr);
    ASSERT_EQ(blob.len, 0);

    HcfFree(blob.data);
    HcfObjDestroy(keyPair);
    HcfObjDestroy(generator);
    DestroyEccKeyPairSpec(reinterpret_cast<HcfEccKeyPairParamsSpec *>(paramSpec));
    HcfFree(g_eccCommSpec);
}

HWTEST_F(CryptoSm2AsyKeyGeneratorBySpecTest, CryptoSm2AsyKeyGeneratorBySpecTest048, TestSize.Level0)
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

    HcfBlob blob = { .data = nullptr, .len = 0 };
    res = keyPair->priKey->base.getEncoded((HcfKey *)&g_obj, &blob);
    ASSERT_NE(res, HCF_SUCCESS);
    ASSERT_EQ(blob.data, nullptr);
    ASSERT_EQ(blob.len, 0);

    HcfFree(blob.data);
    HcfObjDestroy(keyPair);
    HcfObjDestroy(generator);
    DestroyEccKeyPairSpec(reinterpret_cast<HcfEccKeyPairParamsSpec *>(paramSpec));
    HcfFree(g_eccCommSpec);
}

HWTEST_F(CryptoSm2AsyKeyGeneratorBySpecTest, CryptoSm2AsyKeyGeneratorBySpecTest049, TestSize.Level0)
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

    res = keyPair->priKey->base.getEncoded(&(keyPair->priKey->base), nullptr);
    ASSERT_NE(res, HCF_SUCCESS);

    HcfObjDestroy(keyPair);
    HcfObjDestroy(generator);
    DestroyEccKeyPairSpec(reinterpret_cast<HcfEccKeyPairParamsSpec *>(paramSpec));
    HcfFree(g_eccCommSpec);
}

HWTEST_F(CryptoSm2AsyKeyGeneratorBySpecTest, CryptoSm2AsyKeyGeneratorBySpecTest050, TestSize.Level0)
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

    HcfObjDestroy(pubKey);
    HcfObjDestroy(generator);
    DestroyEccPubKeySpec(reinterpret_cast<HcfEccPubKeyParamsSpec *>(paramSpec));
    HcfFree(g_eccCommSpec);
}

HWTEST_F(CryptoSm2AsyKeyGeneratorBySpecTest, CryptoSm2AsyKeyGeneratorBySpecTest051, TestSize.Level0)
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
    res = generator->generatePubKey(nullptr, &pubKey);
    ASSERT_NE(res, HCF_SUCCESS);
    ASSERT_EQ(pubKey, nullptr);

    HcfObjDestroy(pubKey);
    HcfObjDestroy(generator);
    DestroyEccPubKeySpec(reinterpret_cast<HcfEccPubKeyParamsSpec *>(paramSpec));
    HcfFree(g_eccCommSpec);
}

HWTEST_F(CryptoSm2AsyKeyGeneratorBySpecTest, CryptoSm2AsyKeyGeneratorBySpecTest052, TestSize.Level0)
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

    res = generator->generatePubKey(generator, nullptr);
    ASSERT_NE(res, HCF_SUCCESS);

    HcfObjDestroy(generator);
    DestroyEccPubKeySpec(reinterpret_cast<HcfEccPubKeyParamsSpec *>(paramSpec));
    HcfFree(g_eccCommSpec);
}

HWTEST_F(CryptoSm2AsyKeyGeneratorBySpecTest, CryptoSm2AsyKeyGeneratorBySpecTest053, TestSize.Level0)
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

    res = generator->generatePubKey(nullptr, nullptr);
    ASSERT_NE(res, HCF_SUCCESS);

    HcfObjDestroy(generator);
    DestroyEccPubKeySpec(reinterpret_cast<HcfEccPubKeyParamsSpec *>(paramSpec));
    HcfFree(g_eccCommSpec);
}

HWTEST_F(CryptoSm2AsyKeyGeneratorBySpecTest, CryptoSm2AsyKeyGeneratorBySpecTest054, TestSize.Level0)
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

    const char *className = pubKey->base.base.getClass();
    ASSERT_NE(className, nullptr);

    HcfObjDestroy(pubKey);
    HcfObjDestroy(generator);
    DestroyEccPubKeySpec(reinterpret_cast<HcfEccPubKeyParamsSpec *>(paramSpec));
    HcfFree(g_eccCommSpec);
}

HWTEST_F(CryptoSm2AsyKeyGeneratorBySpecTest, CryptoSm2AsyKeyGeneratorBySpecTest055, TestSize.Level0)
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

    pubKey->base.base.destroy((HcfObjectBase *)(&(pubKey->base.base)));
    HcfObjDestroy(generator);
    DestroyEccPubKeySpec(reinterpret_cast<HcfEccPubKeyParamsSpec *>(paramSpec));
    HcfFree(g_eccCommSpec);
}

HWTEST_F(CryptoSm2AsyKeyGeneratorBySpecTest, CryptoSm2AsyKeyGeneratorBySpecTest056, TestSize.Level0)
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

    pubKey->base.base.destroy(nullptr);
    HcfObjDestroy(pubKey);
    HcfObjDestroy(generator);
    DestroyEccPubKeySpec(reinterpret_cast<HcfEccPubKeyParamsSpec *>(paramSpec));
    HcfFree(g_eccCommSpec);
}

HWTEST_F(CryptoSm2AsyKeyGeneratorBySpecTest, CryptoSm2AsyKeyGeneratorBySpecTest057, TestSize.Level0)
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

    pubKey->base.base.destroy(&g_obj);
    HcfObjDestroy(pubKey);
    HcfObjDestroy(generator);
    DestroyEccPubKeySpec(reinterpret_cast<HcfEccPubKeyParamsSpec *>(paramSpec));
    HcfFree(g_eccCommSpec);
}

HWTEST_F(CryptoSm2AsyKeyGeneratorBySpecTest, CryptoSm2AsyKeyGeneratorBySpecTest058, TestSize.Level0)
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

    const char *format = pubKey->base.getFormat(&(pubKey->base));
    ASSERT_NE(format, nullptr);

    HcfObjDestroy(pubKey);
    HcfObjDestroy(generator);
    DestroyEccPubKeySpec(reinterpret_cast<HcfEccPubKeyParamsSpec *>(paramSpec));
    HcfFree(g_eccCommSpec);
}

HWTEST_F(CryptoSm2AsyKeyGeneratorBySpecTest, CryptoSm2AsyKeyGeneratorBySpecTest059, TestSize.Level0)
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

    const char *format = pubKey->base.getFormat(nullptr);
    ASSERT_EQ(format, nullptr);

    HcfObjDestroy(pubKey);
    HcfObjDestroy(generator);
    DestroyEccPubKeySpec(reinterpret_cast<HcfEccPubKeyParamsSpec *>(paramSpec));
    HcfFree(g_eccCommSpec);
}

HWTEST_F(CryptoSm2AsyKeyGeneratorBySpecTest, CryptoSm2AsyKeyGeneratorBySpecTest060, TestSize.Level0)
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

    const char *format = pubKey->base.getFormat((HcfKey *)&g_obj);
    ASSERT_EQ(format, nullptr);

    HcfObjDestroy(pubKey);
    HcfObjDestroy(generator);
    DestroyEccPubKeySpec(reinterpret_cast<HcfEccPubKeyParamsSpec *>(paramSpec));
    HcfFree(g_eccCommSpec);
}

HWTEST_F(CryptoSm2AsyKeyGeneratorBySpecTest, CryptoSm2AsyKeyGeneratorBySpecTest061, TestSize.Level0)
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

    const char *algName = pubKey->base.getAlgorithm(&(pubKey->base));
    ASSERT_NE(algName, nullptr);

    HcfObjDestroy(pubKey);
    HcfObjDestroy(generator);
    DestroyEccPubKeySpec(reinterpret_cast<HcfEccPubKeyParamsSpec *>(paramSpec));
    HcfFree(g_eccCommSpec);
}

HWTEST_F(CryptoSm2AsyKeyGeneratorBySpecTest, CryptoSm2AsyKeyGeneratorBySpecTest062, TestSize.Level0)
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

    const char *algName = pubKey->base.getAlgorithm(nullptr);
    ASSERT_EQ(algName, nullptr);

    HcfObjDestroy(pubKey);
    HcfObjDestroy(generator);
    DestroyEccPubKeySpec(reinterpret_cast<HcfEccPubKeyParamsSpec *>(paramSpec));
    HcfFree(g_eccCommSpec);
}

HWTEST_F(CryptoSm2AsyKeyGeneratorBySpecTest, CryptoSm2AsyKeyGeneratorBySpecTest063, TestSize.Level0)
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

    const char *algName = pubKey->base.getAlgorithm((HcfKey *)&g_obj);
    ASSERT_EQ(algName, nullptr);

    HcfObjDestroy(pubKey);
    HcfObjDestroy(generator);
    DestroyEccPubKeySpec(reinterpret_cast<HcfEccPubKeyParamsSpec *>(paramSpec));
    HcfFree(g_eccCommSpec);
}

HWTEST_F(CryptoSm2AsyKeyGeneratorBySpecTest, CryptoSm2AsyKeyGeneratorBySpecTest064, TestSize.Level0)
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
    res = pubKey->base.getEncoded(&(pubKey->base), &blob);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(blob.data, nullptr);
    ASSERT_NE(blob.len, 0);
    HcfFree(blob.data);

    HcfObjDestroy(pubKey);
    HcfObjDestroy(generator);
    DestroyEccPubKeySpec(reinterpret_cast<HcfEccPubKeyParamsSpec *>(paramSpec));
    HcfFree(g_eccCommSpec);
}

HWTEST_F(CryptoSm2AsyKeyGeneratorBySpecTest, CryptoSm2AsyKeyGeneratorBySpecTest065, TestSize.Level0)
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
    res = pubKey->base.getEncoded(nullptr, &blob);

    ASSERT_NE(res, HCF_SUCCESS);
    ASSERT_EQ(blob.data, nullptr);
    ASSERT_EQ(blob.len, 0);

    HcfFree(blob.data);
    HcfObjDestroy(pubKey);
    HcfObjDestroy(generator);
    DestroyEccPubKeySpec(reinterpret_cast<HcfEccPubKeyParamsSpec *>(paramSpec));
    HcfFree(g_eccCommSpec);
}

HWTEST_F(CryptoSm2AsyKeyGeneratorBySpecTest, CryptoSm2PubKeyFromPriKeyTest, TestSize.Level0)
{
    ConstructEccKeyPairCommParamsSpec("NID_sm2", &g_eccCommSpec);
    ASSERT_NE(g_eccCommSpec, nullptr);
    HcfAsyKeyParamsSpec *paramSpec = nullptr;
    HcfResult res = ConstructEccKeyPairParamsSpec(g_sm2AlgName.c_str(), g_eccCommSpec, &paramSpec);
    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(paramSpec, nullptr);

    HcfAsyKeyGeneratorBySpec *generator = nullptr;
    res = HcfAsyKeyGeneratorBySpecCreate(paramSpec, &generator);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(generator, nullptr);

    HcfKeyPair *keyPair = nullptr;
    res = generator->generateKeyPair(generator, &keyPair);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(keyPair, nullptr);

    HcfBlob pubKeyBlob1 = { .data = nullptr, .len = 0 };
    res = keyPair->pubKey->base.getEncoded(&(keyPair->pubKey->base), &pubKeyBlob1);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(pubKeyBlob1.data, nullptr);
    EXPECT_NE(pubKeyBlob1.len, 0);

    HcfPubKey *pubKey = nullptr;
    res = keyPair->priKey->getPubKey(keyPair->priKey, &pubKey);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(pubKey, nullptr);

    HcfBlob pubKeyBlob = { .data = nullptr, .len = 0 };
    res = pubKey->base.getEncoded(&(pubKey->base), &pubKeyBlob);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(pubKeyBlob.data, nullptr);
    EXPECT_NE(pubKeyBlob.len, 0);
    EXPECT_EQ(memcmp(pubKeyBlob.data, pubKeyBlob1.data, pubKeyBlob.len), 0);
    HcfFree(pubKeyBlob.data);
    HcfFree(pubKeyBlob1.data);
    HcfObjDestroy(pubKey);
    HcfObjDestroy(keyPair);
    HcfObjDestroy(generator);
    DestroyEccKeyPairSpec(reinterpret_cast<HcfEccKeyPairParamsSpec *>(paramSpec));
    HcfFree(g_eccCommSpec);
}

HWTEST_F(CryptoSm2AsyKeyGeneratorBySpecTest, CryptoSm2PubKeyFromPriKeyErrTest, TestSize.Level0)
{
    ConstructEccKeyPairCommParamsSpec("NID_sm2", &g_eccCommSpec);
    ASSERT_NE(g_eccCommSpec, nullptr);
    HcfAsyKeyParamsSpec *paramSpec = nullptr;
    HcfResult res = ConstructEccKeyPairParamsSpec(g_sm2AlgName.c_str(), g_eccCommSpec, &paramSpec);
    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(paramSpec, nullptr);

    HcfAsyKeyGeneratorBySpec *generator = nullptr;
    res = HcfAsyKeyGeneratorBySpecCreate(paramSpec, &generator);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(generator, nullptr);

    HcfKeyPair *keyPair = nullptr;
    res = generator->generateKeyPair(generator, &keyPair);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(keyPair, nullptr);

    HcfPubKey *pubKey = nullptr;
    res = keyPair->priKey->getPubKey(nullptr, &pubKey);
    EXPECT_NE(res, HCF_SUCCESS);
    EXPECT_EQ(pubKey, nullptr);

    res = keyPair->priKey->getPubKey(keyPair->priKey, nullptr);
    EXPECT_NE(res, HCF_SUCCESS);

    res = keyPair->priKey->getPubKey((HcfPriKey *)&g_obj, &pubKey);
    EXPECT_NE(res, HCF_SUCCESS);
    EXPECT_EQ(pubKey, nullptr);

    HcfObjDestroy(keyPair);
    HcfObjDestroy(generator);
    DestroyEccKeyPairSpec(reinterpret_cast<HcfEccKeyPairParamsSpec *>(paramSpec));
    HcfFree(g_eccCommSpec);
}
}