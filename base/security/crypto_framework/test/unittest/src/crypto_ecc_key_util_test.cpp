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
#include "ecc_common_param_spec.h"
#include "blob.h"
#include "ecc_key_util.h"
#include "ecc_openssl_common.h"
#include "ecc_openssl_common_param_spec.h"
#include "ecc_common.h"
#include "ecdsa_openssl.h"
#include "memory.h"
#include "securec.h"
#include "memory_mock.h"
#include "openssl_adapter_mock.h"
#include "openssl_common.h"
#include "asy_key_params.h"
#include "params_parser.h"
#include "ecc_common_param_spec_generator_openssl.h"

using namespace std;
using namespace testing::ext;

namespace {
class CryptoEccKeyUtilTest : public testing::Test {
public:
    static void SetUpTestCase() {};
    static void TearDownTestCase() {};
    void SetUp();
    void TearDown();
};

static string g_brainpool160r1AlgName = "ECC_BrainPoolP160r1";
static string g_brainpool160t1AlgName = "ECC_BrainPoolP160t1";
static string g_brainpool192r1AlgName = "ECC_BrainPoolP192r1";
static string g_brainpool192t1AlgName = "ECC_BrainPoolP192t1";
static string g_brainpool224r1AlgName = "ECC_BrainPoolP224r1";
static string g_brainpool224t1AlgName = "ECC_BrainPoolP224t1";
static string g_brainpool256r1AlgName = "ECC_BrainPoolP256r1";
static string g_brainpool256t1AlgName = "ECC_BrainPoolP256t1";
static string g_brainpool320r1AlgName = "ECC_BrainPoolP320r1";
static string g_brainpool320t1AlgName = "ECC_BrainPoolP320t1";
static string g_brainpool384r1AlgName = "ECC_BrainPoolP384r1";
static string g_brainpool384t1AlgName = "ECC_BrainPoolP384t1";
static string g_brainpool512r1AlgName = "ECC_BrainPoolP512r1";
static string g_brainpool512t1AlgName = "ECC_BrainPoolP512t1";

void CryptoEccKeyUtilTest::SetUp() {}
void CryptoEccKeyUtilTest::TearDown() {}

static const char *g_mockMessage = "hello world";
static HcfBlob g_mockInput = {
    .data = (uint8_t *)g_mockMessage,
    .len = 12
};

static const char *GetMockClass(void)
{
    return "HcfEcc";
}

HcfObjectBase g_obj = {
    .getClass = GetMockClass,
    .destroy = nullptr
};

HWTEST_F(CryptoEccKeyUtilTest, CryptoEccKeyUtilTest001_1, TestSize.Level0)
{
    HcfEccCommParamsSpec *returnCommonParamSpec = nullptr;
    HcfResult res = HcfEccKeyUtilCreate("NID_brainpoolP160r1", &returnCommonParamSpec);
    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(returnCommonParamSpec, nullptr);

    FreeEccCommParamsSpec(returnCommonParamSpec);
    HcfFree(returnCommonParamSpec);
}

HWTEST_F(CryptoEccKeyUtilTest, CryptoEccKeyUtilTest001_2, TestSize.Level0)
{
    HcfEccCommParamsSpec *returnCommonParamSpec = nullptr;
    HcfResult res = HcfEccKeyUtilCreate("NID_brainpoolP160t1", &returnCommonParamSpec);
    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(returnCommonParamSpec, nullptr);

    FreeEccCommParamsSpec(returnCommonParamSpec);
    HcfFree(returnCommonParamSpec);
}

HWTEST_F(CryptoEccKeyUtilTest, CryptoEccKeyUtilTest001_3, TestSize.Level0)
{
    HcfEccCommParamsSpec *returnCommonParamSpec = nullptr;
    HcfResult res = HcfEccKeyUtilCreate("NID_brainpoolP192r1", &returnCommonParamSpec);
    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(returnCommonParamSpec, nullptr);

    FreeEccCommParamsSpec(returnCommonParamSpec);
    HcfFree(returnCommonParamSpec);
}

HWTEST_F(CryptoEccKeyUtilTest, CryptoEccKeyUtilTest001_4, TestSize.Level0)
{
    HcfEccCommParamsSpec *returnCommonParamSpec = nullptr;
    HcfResult res = HcfEccKeyUtilCreate("NID_brainpoolP192t1", &returnCommonParamSpec);
    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(returnCommonParamSpec, nullptr);

    FreeEccCommParamsSpec(returnCommonParamSpec);
    HcfFree(returnCommonParamSpec);
}

HWTEST_F(CryptoEccKeyUtilTest, CryptoEccKeyUtilTest001_5, TestSize.Level0)
{
    HcfEccCommParamsSpec *returnCommonParamSpec = nullptr;
    HcfResult res = HcfEccKeyUtilCreate("NID_brainpoolP224r1", &returnCommonParamSpec);
    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(returnCommonParamSpec, nullptr);

    FreeEccCommParamsSpec(returnCommonParamSpec);
    HcfFree(returnCommonParamSpec);
}

HWTEST_F(CryptoEccKeyUtilTest, CryptoEccKeyUtilTest001_6, TestSize.Level0)
{
    HcfEccCommParamsSpec *returnCommonParamSpec = nullptr;
    HcfResult res = HcfEccKeyUtilCreate("NID_brainpoolP224t1", &returnCommonParamSpec);
    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(returnCommonParamSpec, nullptr);

    FreeEccCommParamsSpec(returnCommonParamSpec);
    HcfFree(returnCommonParamSpec);
}

HWTEST_F(CryptoEccKeyUtilTest, CryptoEccKeyUtilTest001_7, TestSize.Level0)
{
    HcfEccCommParamsSpec *returnCommonParamSpec = nullptr;
    HcfResult res = HcfEccKeyUtilCreate("NID_brainpoolP256r1", &returnCommonParamSpec);
    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(returnCommonParamSpec, nullptr);

    FreeEccCommParamsSpec(returnCommonParamSpec);
    HcfFree(returnCommonParamSpec);
}

HWTEST_F(CryptoEccKeyUtilTest, CryptoEccKeyUtilTest001_8, TestSize.Level0)
{
    HcfEccCommParamsSpec *returnCommonParamSpec = nullptr;
    HcfResult res = HcfEccKeyUtilCreate("NID_brainpoolP256t1", &returnCommonParamSpec);
    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(returnCommonParamSpec, nullptr);

    FreeEccCommParamsSpec(returnCommonParamSpec);
    HcfFree(returnCommonParamSpec);
}

HWTEST_F(CryptoEccKeyUtilTest, CryptoEccKeyUtilTest001_9, TestSize.Level0)
{
    HcfEccCommParamsSpec *returnCommonParamSpec = nullptr;
    HcfResult res = HcfEccKeyUtilCreate("NID_brainpoolP320r1", &returnCommonParamSpec);
    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(returnCommonParamSpec, nullptr);

    FreeEccCommParamsSpec(returnCommonParamSpec);
    HcfFree(returnCommonParamSpec);
}

HWTEST_F(CryptoEccKeyUtilTest, CryptoEccKeyUtilTest001_10, TestSize.Level0)
{
    HcfEccCommParamsSpec *returnCommonParamSpec = nullptr;
    HcfResult res = HcfEccKeyUtilCreate("NID_brainpoolP320t1", &returnCommonParamSpec);
    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(returnCommonParamSpec, nullptr);

    FreeEccCommParamsSpec(returnCommonParamSpec);
    HcfFree(returnCommonParamSpec);
}

HWTEST_F(CryptoEccKeyUtilTest, CryptoEccKeyUtilTest001_11, TestSize.Level0)
{
    HcfEccCommParamsSpec *returnCommonParamSpec = nullptr;
    HcfResult res = HcfEccKeyUtilCreate("NID_brainpoolP384r1", &returnCommonParamSpec);
    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(returnCommonParamSpec, nullptr);

    FreeEccCommParamsSpec(returnCommonParamSpec);
    HcfFree(returnCommonParamSpec);
}

HWTEST_F(CryptoEccKeyUtilTest, CryptoEccKeyUtilTest001_12, TestSize.Level0)
{
    HcfEccCommParamsSpec *returnCommonParamSpec = nullptr;
    HcfResult res = HcfEccKeyUtilCreate("NID_brainpoolP384t1", &returnCommonParamSpec);
    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(returnCommonParamSpec, nullptr);

    FreeEccCommParamsSpec(returnCommonParamSpec);
    HcfFree(returnCommonParamSpec);
}

HWTEST_F(CryptoEccKeyUtilTest, CryptoEccKeyUtilTest001_13, TestSize.Level0)
{
    HcfEccCommParamsSpec *returnCommonParamSpec = nullptr;
    HcfResult res = HcfEccKeyUtilCreate("NID_brainpoolP512r1", &returnCommonParamSpec);
    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(returnCommonParamSpec, nullptr);

    FreeEccCommParamsSpec(returnCommonParamSpec);
    HcfFree(returnCommonParamSpec);
}

HWTEST_F(CryptoEccKeyUtilTest, CryptoEccKeyUtilTest001_14, TestSize.Level0)
{
    HcfEccCommParamsSpec *returnCommonParamSpec = nullptr;
    HcfResult res = HcfEccKeyUtilCreate("NID_brainpoolP512t1", &returnCommonParamSpec);
    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(returnCommonParamSpec, nullptr);

    FreeEccCommParamsSpec(returnCommonParamSpec);
    HcfFree(returnCommonParamSpec);
}

HWTEST_F(CryptoEccKeyUtilTest, CryptoEccKeyUtilTest001_15, TestSize.Level0)
{
    HcfEccCommParamsSpec *returnCommonParamSpec = nullptr;
    HcfResult res = HcfEccKeyUtilCreate("NID_secp224r1", &returnCommonParamSpec);
    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(returnCommonParamSpec, nullptr);

    FreeEccCommParamsSpec(returnCommonParamSpec);
    HcfFree(returnCommonParamSpec);
}

HWTEST_F(CryptoEccKeyUtilTest, CryptoEccKeyUtilTest001_16, TestSize.Level0)
{
    HcfEccCommParamsSpec *returnCommonParamSpec = nullptr;
    HcfResult res = HcfEccKeyUtilCreate("NID_X9_62_prime256v1", &returnCommonParamSpec);
    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(returnCommonParamSpec, nullptr);

    FreeEccCommParamsSpec(returnCommonParamSpec);
    HcfFree(returnCommonParamSpec);
}

HWTEST_F(CryptoEccKeyUtilTest, CryptoEccKeyUtilTest001_17, TestSize.Level0)
{
    HcfEccCommParamsSpec *returnCommonParamSpec = nullptr;
    HcfResult res = HcfEccKeyUtilCreate("NID_secp384r1", &returnCommonParamSpec);
    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(returnCommonParamSpec, nullptr);

    FreeEccCommParamsSpec(returnCommonParamSpec);
    HcfFree(returnCommonParamSpec);
}

HWTEST_F(CryptoEccKeyUtilTest, CryptoEccKeyUtilTest001_18, TestSize.Level0)
{
    HcfEccCommParamsSpec *returnCommonParamSpec = nullptr;
    HcfResult res = HcfEccKeyUtilCreate("NID_secp521r1", &returnCommonParamSpec);
    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(returnCommonParamSpec, nullptr);

    FreeEccCommParamsSpec(returnCommonParamSpec);
    HcfFree(returnCommonParamSpec);
}

HWTEST_F(CryptoEccKeyUtilTest, CryptoEccKeyUtilTest001_19, TestSize.Level0)
{
    HcfEccCommParamsSpec *returnCommonParamSpec = nullptr;
    HcfResult res = HcfEccKeyUtilCreate("NID_sm2", &returnCommonParamSpec);
    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(returnCommonParamSpec, nullptr);

    FreeEccCommParamsSpec(returnCommonParamSpec);
    HcfFree(returnCommonParamSpec);
}

HWTEST_F(CryptoEccKeyUtilTest, CryptoEccKeyUtilTest002, TestSize.Level0)
{
    HcfEccCommParamsSpec *returnCommonParamSpec = nullptr;
    HcfResult res = HcfEccKeyUtilCreate(nullptr, &returnCommonParamSpec);
    ASSERT_NE(res, HCF_SUCCESS);
    ASSERT_EQ(returnCommonParamSpec, nullptr);

    FreeEccCommParamsSpec(returnCommonParamSpec);
}

HWTEST_F(CryptoEccKeyUtilTest, CryptoEccKeyUtilTest003, TestSize.Level0)
{
    HcfResult res = HcfEccKeyUtilCreate("ECC_BrainPoolP160r1", nullptr);
    ASSERT_NE(res, HCF_SUCCESS);
}

HWTEST_F(CryptoEccKeyUtilTest, CryptoEccKeyUtilTest004, TestSize.Level0)
{
    HcfEccCommParamsSpec *returnCommonParamSpec = nullptr;
    HcfResult res = HcfEccKeyUtilCreate("BrainPoolP999", &returnCommonParamSpec);
    ASSERT_NE(res, HCF_SUCCESS);
    ASSERT_EQ(returnCommonParamSpec, nullptr);

    FreeEccCommParamsSpec(returnCommonParamSpec);
    HcfFree(returnCommonParamSpec);
}

HWTEST_F(CryptoEccKeyUtilTest, CryptoEccKeyUtilTest005, TestSize.Level0)
{
    HcfEccCommParamsSpec *brainpool160r1CommSpec = nullptr;
    ConstructEccKeyPairCommParamsSpec("NID_brainpoolP160r1", &brainpool160r1CommSpec);
    ASSERT_NE(brainpool160r1CommSpec, nullptr);
    HcfAsyKeyParamsSpec *paramSpec = nullptr;
    HcfResult res = ConstructEccKeyPairParamsSpec(g_brainpool160r1AlgName.c_str(),
        brainpool160r1CommSpec, &paramSpec);
    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(paramSpec, nullptr);

    HcfAsyKeyGeneratorBySpec *returnObj = nullptr;
    res = HcfAsyKeyGeneratorBySpecCreate(paramSpec, &returnObj);
    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(returnObj, nullptr);

    const char *classname = returnObj->base.getClass();
    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(classname, nullptr);

    HcfObjDestroy(returnObj);
    DestroyEccKeyPairSpec(reinterpret_cast<HcfEccKeyPairParamsSpec *>(paramSpec));
    HcfFree(brainpool160r1CommSpec);
}

HWTEST_F(CryptoEccKeyUtilTest, CryptoEccKeyUtilTest006, TestSize.Level0)
{
    HcfEccCommParamsSpec *brainpool160r1CommSpec = nullptr;
    ConstructEccKeyPairCommParamsSpec("NID_brainpoolP160r1", &brainpool160r1CommSpec);
    ASSERT_NE(brainpool160r1CommSpec, nullptr);
    HcfAsyKeyParamsSpec *paramSpec = nullptr;
    HcfResult res = ConstructEccKeyPairParamsSpec(g_brainpool160r1AlgName.c_str(),
        brainpool160r1CommSpec, &paramSpec);
    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(paramSpec, nullptr);

    HcfAsyKeyGeneratorBySpec *returnObj = nullptr;
    res = HcfAsyKeyGeneratorBySpecCreate(paramSpec, &returnObj);
    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(returnObj, nullptr);

    returnObj->base.destroy(&g_obj);
    HcfObjDestroy(returnObj);
    DestroyEccKeyPairSpec(reinterpret_cast<HcfEccKeyPairParamsSpec *>(paramSpec));
    HcfFree(brainpool160r1CommSpec);
}

HWTEST_F(CryptoEccKeyUtilTest, CryptoEccKeyUtilTest007, TestSize.Level0)
{
    HcfEccCommParamsSpec *brainpool160r1CommSpec = nullptr;
    ConstructEccKeyPairCommParamsSpec("NID_brainpoolP160r1", &brainpool160r1CommSpec);
    ASSERT_NE(brainpool160r1CommSpec, nullptr);
    HcfAsyKeyParamsSpec *paramSpec = nullptr;
    HcfResult res = ConstructEccKeyPairParamsSpec(g_brainpool160r1AlgName.c_str(),
        brainpool160r1CommSpec, &paramSpec);
    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(paramSpec, nullptr);

    HcfAsyKeyGeneratorBySpec *returnObj = nullptr;
    res = HcfAsyKeyGeneratorBySpecCreate(paramSpec, &returnObj);
    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(returnObj, nullptr);

    const char *algName = returnObj->getAlgName(returnObj);
    ASSERT_NE(algName, nullptr);
    HcfObjDestroy(returnObj);
    DestroyEccKeyPairSpec(reinterpret_cast<HcfEccKeyPairParamsSpec *>(paramSpec));
    HcfFree(brainpool160r1CommSpec);
}

HWTEST_F(CryptoEccKeyUtilTest, CryptoEccKeyUtilTest008, TestSize.Level0)
{
    HcfEccCommParamsSpec *brainpool160r1CommSpec = nullptr;
    ConstructEccKeyPairCommParamsSpec("NID_brainpoolP160r1", &brainpool160r1CommSpec);
    ASSERT_NE(brainpool160r1CommSpec, nullptr);
    HcfAsyKeyParamsSpec *paramSpec = nullptr;
    HcfResult res = ConstructEccKeyPairParamsSpec(g_brainpool160r1AlgName.c_str(),
        brainpool160r1CommSpec, &paramSpec);
    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(paramSpec, nullptr);

    HcfAsyKeyGeneratorBySpec *returnObj = nullptr;
    res = HcfAsyKeyGeneratorBySpecCreate(paramSpec, &returnObj);
    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(returnObj, nullptr);

    HcfKeyPair *returnKeyPair = nullptr;
    res = returnObj->generateKeyPair(returnObj, &returnKeyPair);
    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(returnKeyPair, nullptr);

    HcfObjDestroy(returnObj);
    HcfObjDestroy(returnKeyPair);
    DestroyEccKeyPairSpec(reinterpret_cast<HcfEccKeyPairParamsSpec *>(paramSpec));
    HcfFree(brainpool160r1CommSpec);
}

HWTEST_F(CryptoEccKeyUtilTest, CryptoEccKeyUtilTest009, TestSize.Level0)
{
    HcfEccCommParamsSpec *brainpool160r1CommSpec = nullptr;
    ConstructEccKeyPairCommParamsSpec("NID_brainpoolP160r1", &brainpool160r1CommSpec);
    ASSERT_NE(brainpool160r1CommSpec, nullptr);
    HcfAsyKeyParamsSpec *paramSpec = nullptr;
    HcfResult res = ConstructEccKeyPairParamsSpec(g_brainpool160r1AlgName.c_str(),
        brainpool160r1CommSpec, &paramSpec);
    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(paramSpec, nullptr);

    HcfAsyKeyGeneratorBySpec *returnObj = nullptr;
    res = HcfAsyKeyGeneratorBySpecCreate(paramSpec, &returnObj);
    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(returnObj, nullptr);

    HcfKeyPair *returnKeyPair = nullptr;
    res = returnObj->generateKeyPair(returnObj, &returnKeyPair);
    const char *classname = returnKeyPair->base.getClass();
    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(returnKeyPair, nullptr);
    ASSERT_NE(classname, nullptr);

    HcfObjDestroy(returnKeyPair);
    HcfObjDestroy(returnObj);
    DestroyEccKeyPairSpec(reinterpret_cast<HcfEccKeyPairParamsSpec *>(paramSpec));
    HcfFree(brainpool160r1CommSpec);
}

HWTEST_F(CryptoEccKeyUtilTest, CryptoEccKeyUtilTest010, TestSize.Level0)
{
    HcfEccCommParamsSpec *brainpool160r1CommSpec = nullptr;
    ConstructEccKeyPairCommParamsSpec("NID_brainpoolP160r1", &brainpool160r1CommSpec);
    ASSERT_NE(brainpool160r1CommSpec, nullptr);
    HcfAsyKeyParamsSpec *paramSpec = nullptr;
    HcfResult res = ConstructEccKeyPairParamsSpec(g_brainpool160r1AlgName.c_str(),
        brainpool160r1CommSpec, &paramSpec);
    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(paramSpec, nullptr);

    HcfAsyKeyGeneratorBySpec *returnObj = nullptr;
    res = HcfAsyKeyGeneratorBySpecCreate(paramSpec, &returnObj);
    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(returnObj, nullptr);

    HcfKeyPair *returnKeyPair = nullptr;
    res = returnObj->generateKeyPair(returnObj, &returnKeyPair);
    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(returnKeyPair, nullptr);

    returnKeyPair->base.destroy(&(returnKeyPair->base));
    HcfObjDestroy(returnObj);
    DestroyEccKeyPairSpec(reinterpret_cast<HcfEccKeyPairParamsSpec *>(paramSpec));
    HcfFree(brainpool160r1CommSpec);
}

HWTEST_F(CryptoEccKeyUtilTest, CryptoEccKeyUtilTest011, TestSize.Level0)
{
    HcfEccCommParamsSpec *brainpool160r1CommSpec = nullptr;
    ConstructEccKeyPairCommParamsSpec("NID_brainpoolP160r1", &brainpool160r1CommSpec);
    ASSERT_NE(brainpool160r1CommSpec, nullptr);
    HcfAsyKeyParamsSpec *paramSpec = nullptr;
    HcfResult res = ConstructEccKeyPairParamsSpec(g_brainpool160r1AlgName.c_str(),
        brainpool160r1CommSpec, &paramSpec);
    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(paramSpec, nullptr);

    HcfAsyKeyGeneratorBySpec *returnObj = nullptr;
    res = HcfAsyKeyGeneratorBySpecCreate(paramSpec, &returnObj);
    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(returnObj, nullptr);

    HcfKeyPair *returnKeyPair = nullptr;
    res = returnObj->generateKeyPair(returnObj, &returnKeyPair);
    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(returnKeyPair, nullptr);

    returnKeyPair->base.destroy(nullptr);
    HcfObjDestroy(returnKeyPair);
    HcfObjDestroy(returnObj);
    DestroyEccKeyPairSpec(reinterpret_cast<HcfEccKeyPairParamsSpec *>(paramSpec));
    HcfFree(brainpool160r1CommSpec);
}

HWTEST_F(CryptoEccKeyUtilTest, CryptoEccKeyUtilTest012, TestSize.Level0)
{
    HcfEccCommParamsSpec *brainpool160r1CommSpec = nullptr;
    ConstructEccKeyPairCommParamsSpec("NID_brainpoolP160r1", &brainpool160r1CommSpec);
    ASSERT_NE(brainpool160r1CommSpec, nullptr);
    HcfAsyKeyParamsSpec *paramSpec = nullptr;
    HcfResult res = ConstructEccKeyPairParamsSpec(g_brainpool160r1AlgName.c_str(),
        brainpool160r1CommSpec, &paramSpec);
    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(paramSpec, nullptr);

    HcfAsyKeyGeneratorBySpec *returnObj = nullptr;
    res = HcfAsyKeyGeneratorBySpecCreate(paramSpec, &returnObj);
    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(returnObj, nullptr);

    HcfKeyPair *returnKeyPair = nullptr;
    res = returnObj->generateKeyPair(returnObj, &returnKeyPair);
    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(returnKeyPair, nullptr);

    returnKeyPair->base.destroy(&g_obj);
    HcfObjDestroy(returnKeyPair);
    HcfObjDestroy(returnObj);
    DestroyEccKeyPairSpec(reinterpret_cast<HcfEccKeyPairParamsSpec *>(paramSpec));
    HcfFree(brainpool160r1CommSpec);
}

HWTEST_F(CryptoEccKeyUtilTest, CryptoEccKeyUtilTest013, TestSize.Level0)
{
    HcfEccCommParamsSpec *brainpool160r1CommSpec = nullptr;
    ConstructEccKeyPairCommParamsSpec("NID_brainpoolP160r1", &brainpool160r1CommSpec);
    ASSERT_NE(brainpool160r1CommSpec, nullptr);
    HcfAsyKeyParamsSpec *paramSpec = nullptr;
    HcfResult res = ConstructEccKeyPairParamsSpec(g_brainpool160r1AlgName.c_str(),
        brainpool160r1CommSpec, &paramSpec);
    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(paramSpec, nullptr);

    HcfAsyKeyGeneratorBySpec *returnObj = nullptr;
    res = HcfAsyKeyGeneratorBySpecCreate(paramSpec, &returnObj);
    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(returnObj, nullptr);

    HcfKeyPair *returnKeyPair = nullptr;
    res = returnObj->generateKeyPair(returnObj, &returnKeyPair);
    const char *classname = returnKeyPair->pubKey->base.base.getClass();
    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(returnKeyPair, nullptr);
    ASSERT_NE(classname, nullptr);

    HcfObjDestroy(returnKeyPair);
    HcfObjDestroy(returnObj);
    DestroyEccKeyPairSpec(reinterpret_cast<HcfEccKeyPairParamsSpec *>(paramSpec));
    HcfFree(brainpool160r1CommSpec);
}

HWTEST_F(CryptoEccKeyUtilTest, CryptoEccKeyUtilTest014, TestSize.Level0)
{
    HcfEccCommParamsSpec *brainpool160r1CommSpec = nullptr;
    ConstructEccKeyPairCommParamsSpec("NID_brainpoolP160r1", &brainpool160r1CommSpec);
    ASSERT_NE(brainpool160r1CommSpec, nullptr);
    HcfAsyKeyParamsSpec *paramSpec = nullptr;
    HcfResult res = ConstructEccKeyPairParamsSpec(g_brainpool160r1AlgName.c_str(),
        brainpool160r1CommSpec, &paramSpec);
    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(paramSpec, nullptr);

    HcfAsyKeyGeneratorBySpec *returnObj = nullptr;
    res = HcfAsyKeyGeneratorBySpecCreate(paramSpec, &returnObj);
    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(returnObj, nullptr);

    HcfKeyPair *returnKeyPair = nullptr;
    res = returnObj->generateKeyPair(returnObj, &returnKeyPair);
    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(returnKeyPair, nullptr);

    HcfObjDestroy(returnKeyPair);
    HcfObjDestroy(returnObj);
    DestroyEccKeyPairSpec(reinterpret_cast<HcfEccKeyPairParamsSpec *>(paramSpec));
    HcfFree(brainpool160r1CommSpec);
}

HWTEST_F(CryptoEccKeyUtilTest, CryptoEccKeyUtilTest015, TestSize.Level0)
{
    HcfEccCommParamsSpec *brainpool160r1CommSpec = nullptr;
    ConstructEccKeyPairCommParamsSpec("NID_brainpoolP160r1", &brainpool160r1CommSpec);
    ASSERT_NE(brainpool160r1CommSpec, nullptr);
    HcfAsyKeyParamsSpec *paramSpec = nullptr;
    HcfResult res = ConstructEccKeyPairParamsSpec(g_brainpool160r1AlgName.c_str(),
        brainpool160r1CommSpec, &paramSpec);
    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(paramSpec, nullptr);

    HcfAsyKeyGeneratorBySpec *returnObj = nullptr;
    res = HcfAsyKeyGeneratorBySpecCreate(paramSpec, &returnObj);
    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(returnObj, nullptr);

    HcfKeyPair *returnKeyPair = nullptr;
    res = returnObj->generateKeyPair(returnObj, &returnKeyPair);
    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(returnKeyPair, nullptr);

    HcfObjDestroy(returnKeyPair);
    HcfObjDestroy(returnObj);
    DestroyEccKeyPairSpec(reinterpret_cast<HcfEccKeyPairParamsSpec *>(paramSpec));
    HcfFree(brainpool160r1CommSpec);
}

HWTEST_F(CryptoEccKeyUtilTest, CryptoEccKeyUtilTest016, TestSize.Level0)
{
    HcfEccCommParamsSpec *brainpool160r1CommSpec = nullptr;
    ConstructEccKeyPairCommParamsSpec("NID_brainpoolP160r1", &brainpool160r1CommSpec);
    ASSERT_NE(brainpool160r1CommSpec, nullptr);
    HcfAsyKeyParamsSpec *paramSpec = nullptr;
    HcfResult res = ConstructEccKeyPairParamsSpec(g_brainpool160r1AlgName.c_str(),
        brainpool160r1CommSpec, &paramSpec);
    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(paramSpec, nullptr);

    HcfAsyKeyGeneratorBySpec *returnObj = nullptr;
    res = HcfAsyKeyGeneratorBySpecCreate(paramSpec, &returnObj);
    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(returnObj, nullptr);

    HcfKeyPair *returnKeyPair = nullptr;
    res = returnObj->generateKeyPair(returnObj, &returnKeyPair);
    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(returnKeyPair, nullptr);

    HcfObjDestroy(returnKeyPair);
    HcfObjDestroy(returnObj);
    DestroyEccKeyPairSpec(reinterpret_cast<HcfEccKeyPairParamsSpec *>(paramSpec));
    HcfFree(brainpool160r1CommSpec);
}

HWTEST_F(CryptoEccKeyUtilTest, CryptoEccKeyUtilTest017, TestSize.Level0)
{
    HcfEccCommParamsSpec *brainpool160r1CommSpec = nullptr;
    ConstructEccKeyPairCommParamsSpec("NID_brainpoolP160r1", &brainpool160r1CommSpec);
    ASSERT_NE(brainpool160r1CommSpec, nullptr);
    HcfAsyKeyParamsSpec *paramSpec = nullptr;
    HcfResult res = ConstructEccKeyPairParamsSpec(g_brainpool160r1AlgName.c_str(),
        brainpool160r1CommSpec, &paramSpec);
    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(paramSpec, nullptr);

    HcfAsyKeyGeneratorBySpec *returnObj = nullptr;
    res = HcfAsyKeyGeneratorBySpecCreate(paramSpec, &returnObj);
    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(returnObj, nullptr);

    HcfKeyPair *returnKeyPair = nullptr;
    res = returnObj->generateKeyPair(returnObj, &returnKeyPair);
    const char * format = returnKeyPair->pubKey->base.getFormat(&(returnKeyPair->pubKey->base));
    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(returnKeyPair, nullptr);
    ASSERT_NE(format, nullptr);

    HcfObjDestroy(returnKeyPair);
    HcfObjDestroy(returnObj);
    DestroyEccKeyPairSpec(reinterpret_cast<HcfEccKeyPairParamsSpec *>(paramSpec));
    HcfFree(brainpool160r1CommSpec);
}

HWTEST_F(CryptoEccKeyUtilTest, CryptoEccKeyUtilTest018, TestSize.Level0)
{
    HcfEccCommParamsSpec *brainpool160r1CommSpec = nullptr;
    ConstructEccKeyPairCommParamsSpec("NID_brainpoolP160r1", &brainpool160r1CommSpec);
    ASSERT_NE(brainpool160r1CommSpec, nullptr);
    HcfAsyKeyParamsSpec *paramSpec = nullptr;
    HcfResult res = ConstructEccKeyPairParamsSpec(g_brainpool160r1AlgName.c_str(),
        brainpool160r1CommSpec, &paramSpec);
    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(paramSpec, nullptr);

    HcfAsyKeyGeneratorBySpec *returnObj = nullptr;
    res = HcfAsyKeyGeneratorBySpecCreate(paramSpec, &returnObj);
    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(returnObj, nullptr);

    HcfKeyPair *returnKeyPair = nullptr;
    res = returnObj->generateKeyPair(returnObj, &returnKeyPair);
    const char * algorithm = returnKeyPair->pubKey->base.getAlgorithm(&(returnKeyPair->pubKey->base));
    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(returnKeyPair, nullptr);
    ASSERT_NE(algorithm, nullptr);

    HcfObjDestroy(returnKeyPair);
    HcfObjDestroy(returnObj);
    DestroyEccKeyPairSpec(reinterpret_cast<HcfEccKeyPairParamsSpec *>(paramSpec));
    HcfFree(brainpool160r1CommSpec);
}

HWTEST_F(CryptoEccKeyUtilTest, CryptoEccKeyUtilTest019, TestSize.Level0)
{
    HcfEccCommParamsSpec *brainpool160r1CommSpec = nullptr;
    ConstructEccKeyPairCommParamsSpec("NID_brainpoolP160r1", &brainpool160r1CommSpec);
    ASSERT_NE(brainpool160r1CommSpec, nullptr);
    HcfAsyKeyParamsSpec *paramSpec = nullptr;
    HcfResult res = ConstructEccKeyPairParamsSpec(g_brainpool160r1AlgName.c_str(),
        brainpool160r1CommSpec, &paramSpec);
    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(paramSpec, nullptr);

    HcfAsyKeyGeneratorBySpec *returnObj = nullptr;
    res = HcfAsyKeyGeneratorBySpecCreate(paramSpec, &returnObj);
    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(returnObj, nullptr);

    HcfKeyPair *returnKeyPair = nullptr;
    res = returnObj->generateKeyPair(returnObj, &returnKeyPair);
    HcfBlob pubKeyBlob = {.data = nullptr, .len = 0};
    res = returnKeyPair->pubKey->base.getEncoded(&(returnKeyPair->pubKey->base), &pubKeyBlob);
    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(returnKeyPair, nullptr);

    HcfObjDestroy(returnKeyPair);
    HcfObjDestroy(returnObj);
    HcfBlobDataFree(&pubKeyBlob);
    DestroyEccKeyPairSpec(reinterpret_cast<HcfEccKeyPairParamsSpec *>(paramSpec));
    HcfFree(brainpool160r1CommSpec);
}

HWTEST_F(CryptoEccKeyUtilTest, CryptoEccKeyUtilTest020, TestSize.Level0)
{
    HcfEccCommParamsSpec *brainpool160r1CommSpec = nullptr;
    ConstructEccKeyPairCommParamsSpec("NID_brainpoolP160r1", &brainpool160r1CommSpec);
    ASSERT_NE(brainpool160r1CommSpec, nullptr);
    HcfAsyKeyParamsSpec *paramSpec = nullptr;
    HcfResult res = ConstructEccKeyPairParamsSpec(g_brainpool160r1AlgName.c_str(),
        brainpool160r1CommSpec, &paramSpec);
    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(paramSpec, nullptr);

    HcfAsyKeyGeneratorBySpec *returnObj = nullptr;
    res = HcfAsyKeyGeneratorBySpecCreate(paramSpec, &returnObj);
    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(returnObj, nullptr);

    HcfKeyPair *returnKeyPair = nullptr;
    res = returnObj->generateKeyPair(returnObj, &returnKeyPair);
    returnKeyPair->priKey->clearMem(returnKeyPair->priKey);
    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(returnKeyPair, nullptr);

    HcfObjDestroy(returnKeyPair);
    HcfObjDestroy(returnObj);
    DestroyEccKeyPairSpec(reinterpret_cast<HcfEccKeyPairParamsSpec *>(paramSpec));
    HcfFree(brainpool160r1CommSpec);
}

HWTEST_F(CryptoEccKeyUtilTest, CryptoEccKeyUtilTest021, TestSize.Level0)
{
    HcfEccCommParamsSpec *brainpool160r1CommSpec = nullptr;
    ConstructEccKeyPairCommParamsSpec("NID_brainpoolP160r1", &brainpool160r1CommSpec);
    ASSERT_NE(brainpool160r1CommSpec, nullptr);
    HcfAsyKeyParamsSpec *paramSpec = nullptr;
    HcfResult res = ConstructEccKeyPairParamsSpec(g_brainpool160r1AlgName.c_str(),
        brainpool160r1CommSpec, &paramSpec);
    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(paramSpec, nullptr);

    HcfAsyKeyGeneratorBySpec *returnObj = nullptr;
    res = HcfAsyKeyGeneratorBySpecCreate(paramSpec, &returnObj);
    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(returnObj, nullptr);

    HcfKeyPair *returnKeyPair = nullptr;
    res = returnObj->generateKeyPair(returnObj, &returnKeyPair);
    returnKeyPair->priKey->clearMem(nullptr);
    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(returnKeyPair, nullptr);

    HcfObjDestroy(returnKeyPair);
    HcfObjDestroy(returnObj);
    DestroyEccKeyPairSpec(reinterpret_cast<HcfEccKeyPairParamsSpec *>(paramSpec));
    HcfFree(brainpool160r1CommSpec);
}

HWTEST_F(CryptoEccKeyUtilTest, CryptoEccKeyUtilTest022, TestSize.Level0)
{
    HcfEccCommParamsSpec *brainpool160r1CommSpec = nullptr;
    ConstructEccKeyPairCommParamsSpec("NID_brainpoolP160r1", &brainpool160r1CommSpec);
    ASSERT_NE(brainpool160r1CommSpec, nullptr);
    HcfAsyKeyParamsSpec *paramSpec = nullptr;
    HcfResult res = ConstructEccKeyPairParamsSpec(g_brainpool160r1AlgName.c_str(),
        brainpool160r1CommSpec, &paramSpec);
    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(paramSpec, nullptr);

    HcfAsyKeyGeneratorBySpec *returnObj = nullptr;
    res = HcfAsyKeyGeneratorBySpecCreate(paramSpec, &returnObj);
    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(returnObj, nullptr);

    HcfKeyPair *returnKeyPair = nullptr;
    res = returnObj->generateKeyPair(returnObj, &returnKeyPair);
    returnKeyPair->priKey->clearMem((HcfPriKey *)&g_obj);
    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(returnKeyPair, nullptr);

    HcfObjDestroy(returnKeyPair);
    HcfObjDestroy(returnObj);
    DestroyEccKeyPairSpec(reinterpret_cast<HcfEccKeyPairParamsSpec *>(paramSpec));
    HcfFree(brainpool160r1CommSpec);
}

HWTEST_F(CryptoEccKeyUtilTest, CryptoEccKeyUtilTest023, TestSize.Level0)
{
    HcfEccCommParamsSpec *brainpool160r1CommSpec = nullptr;
    ConstructEccKeyPairCommParamsSpec("NID_brainpoolP160r1", &brainpool160r1CommSpec);
    ASSERT_NE(brainpool160r1CommSpec, nullptr);
    HcfAsyKeyParamsSpec *paramSpec = nullptr;
    HcfResult res = ConstructEccKeyPairParamsSpec(g_brainpool160r1AlgName.c_str(),
        brainpool160r1CommSpec, &paramSpec);
    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(paramSpec, nullptr);

    HcfAsyKeyGeneratorBySpec *returnObj = nullptr;
    res = HcfAsyKeyGeneratorBySpecCreate(paramSpec, &returnObj);
    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(returnObj, nullptr);

    HcfKeyPair *returnKeyPair = nullptr;
    res = returnObj->generateKeyPair(returnObj, &returnKeyPair);
    const char *classname = returnKeyPair->priKey->base.base.getClass();
    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(returnKeyPair, nullptr);
    ASSERT_NE(classname, nullptr);

    HcfObjDestroy(returnKeyPair);
    HcfObjDestroy(returnObj);
    DestroyEccKeyPairSpec(reinterpret_cast<HcfEccKeyPairParamsSpec *>(paramSpec));
    HcfFree(brainpool160r1CommSpec);
}

HWTEST_F(CryptoEccKeyUtilTest, CryptoEccKeyUtilTest024, TestSize.Level0)
{
    HcfEccCommParamsSpec *brainpool160r1CommSpec = nullptr;
    ConstructEccKeyPairCommParamsSpec("NID_brainpoolP160r1", &brainpool160r1CommSpec);
    ASSERT_NE(brainpool160r1CommSpec, nullptr);
    HcfAsyKeyParamsSpec *paramSpec = nullptr;
    HcfResult res = ConstructEccKeyPairParamsSpec(g_brainpool160r1AlgName.c_str(),
        brainpool160r1CommSpec, &paramSpec);
    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(paramSpec, nullptr);

    HcfAsyKeyGeneratorBySpec *returnObj = nullptr;
    res = HcfAsyKeyGeneratorBySpecCreate(paramSpec, &returnObj);
    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(returnObj, nullptr);

    HcfKeyPair *returnKeyPair = nullptr;
    res = returnObj->generateKeyPair(returnObj, &returnKeyPair);
    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(returnKeyPair, nullptr);

    returnKeyPair->priKey->base.base.destroy(&(returnKeyPair->priKey->base.base));
    returnKeyPair->priKey = nullptr;
    HcfObjDestroy(returnKeyPair);
    HcfObjDestroy(returnObj);
    DestroyEccKeyPairSpec(reinterpret_cast<HcfEccKeyPairParamsSpec *>(paramSpec));
    HcfFree(brainpool160r1CommSpec);
}

HWTEST_F(CryptoEccKeyUtilTest, CryptoEccKeyUtilTest025, TestSize.Level0)
{
    HcfEccCommParamsSpec *brainpool160r1CommSpec = nullptr;
    ConstructEccKeyPairCommParamsSpec("NID_brainpoolP160r1", &brainpool160r1CommSpec);
    ASSERT_NE(brainpool160r1CommSpec, nullptr);
    HcfAsyKeyParamsSpec *paramSpec = nullptr;
    HcfResult res = ConstructEccKeyPairParamsSpec(g_brainpool160r1AlgName.c_str(),
        brainpool160r1CommSpec, &paramSpec);
    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(paramSpec, nullptr);

    HcfAsyKeyGeneratorBySpec *returnObj = nullptr;
    res = HcfAsyKeyGeneratorBySpecCreate(paramSpec, &returnObj);
    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(returnObj, nullptr);

    HcfKeyPair *returnKeyPair = nullptr;
    res = returnObj->generateKeyPair(returnObj, &returnKeyPair);
    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(returnKeyPair, nullptr);

    HcfObjDestroy(returnKeyPair);
    HcfObjDestroy(returnObj);
    DestroyEccKeyPairSpec(reinterpret_cast<HcfEccKeyPairParamsSpec *>(paramSpec));
    HcfFree(brainpool160r1CommSpec);
}

HWTEST_F(CryptoEccKeyUtilTest, CryptoEccKeyUtilTest026, TestSize.Level0)
{
    HcfEccCommParamsSpec *brainpool160r1CommSpec = nullptr;
    ConstructEccKeyPairCommParamsSpec("NID_brainpoolP160r1", &brainpool160r1CommSpec);
    ASSERT_NE(brainpool160r1CommSpec, nullptr);
    HcfAsyKeyParamsSpec *paramSpec = nullptr;
    HcfResult res = ConstructEccKeyPairParamsSpec(g_brainpool160r1AlgName.c_str(),
        brainpool160r1CommSpec, &paramSpec);
    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(paramSpec, nullptr);

    HcfAsyKeyGeneratorBySpec *returnObj = nullptr;
    res = HcfAsyKeyGeneratorBySpecCreate(paramSpec, &returnObj);
    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(returnObj, nullptr);

    HcfKeyPair *returnKeyPair = nullptr;
    res = returnObj->generateKeyPair(returnObj, &returnKeyPair);
    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(returnKeyPair, nullptr);

    HcfObjDestroy(returnKeyPair);
    HcfObjDestroy(returnObj);
    DestroyEccKeyPairSpec(reinterpret_cast<HcfEccKeyPairParamsSpec *>(paramSpec));
    HcfFree(brainpool160r1CommSpec);
}

HWTEST_F(CryptoEccKeyUtilTest, CryptoEccKeyUtilTest027, TestSize.Level0)
{
    HcfEccCommParamsSpec *brainpool160r1CommSpec = nullptr;
    ConstructEccKeyPairCommParamsSpec("NID_brainpoolP160r1", &brainpool160r1CommSpec);
    ASSERT_NE(brainpool160r1CommSpec, nullptr);
    HcfAsyKeyParamsSpec *paramSpec = nullptr;
    HcfResult res = ConstructEccKeyPairParamsSpec(g_brainpool160r1AlgName.c_str(),
        brainpool160r1CommSpec, &paramSpec);
    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(paramSpec, nullptr);

    HcfAsyKeyGeneratorBySpec *returnObj = nullptr;
    res = HcfAsyKeyGeneratorBySpecCreate(paramSpec, &returnObj);
    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(returnObj, nullptr);

    HcfKeyPair *returnKeyPair = nullptr;
    res = returnObj->generateKeyPair(returnObj, &returnKeyPair);
    const char *format = returnKeyPair->priKey->base.getFormat(&(returnKeyPair->priKey->base));
    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(returnKeyPair, nullptr);
    ASSERT_NE(format, nullptr);

    HcfObjDestroy(returnKeyPair);
    HcfObjDestroy(returnObj);
    DestroyEccKeyPairSpec(reinterpret_cast<HcfEccKeyPairParamsSpec *>(paramSpec));
    HcfFree(brainpool160r1CommSpec);
}

HWTEST_F(CryptoEccKeyUtilTest, CryptoEccKeyUtilTest028, TestSize.Level0)
{
    HcfEccCommParamsSpec *brainpool160r1CommSpec = nullptr;
    ConstructEccKeyPairCommParamsSpec("NID_brainpoolP160r1", &brainpool160r1CommSpec);
    ASSERT_NE(brainpool160r1CommSpec, nullptr);
    HcfAsyKeyParamsSpec *paramSpec = nullptr;
    HcfResult res = ConstructEccKeyPairParamsSpec(g_brainpool160r1AlgName.c_str(),
        brainpool160r1CommSpec, &paramSpec);
    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(paramSpec, nullptr);

    HcfAsyKeyGeneratorBySpec *returnObj = nullptr;
    res = HcfAsyKeyGeneratorBySpecCreate(paramSpec, &returnObj);
    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(returnObj, nullptr);

    HcfKeyPair *returnKeyPair = nullptr;
    res = returnObj->generateKeyPair(returnObj, &returnKeyPair);
    const char *algorithm = returnKeyPair->priKey->base.getAlgorithm(&(returnKeyPair->priKey->base));
    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(returnKeyPair, nullptr);
    ASSERT_NE(algorithm, nullptr);

    HcfObjDestroy(returnKeyPair);
    HcfObjDestroy(returnObj);
    DestroyEccKeyPairSpec(reinterpret_cast<HcfEccKeyPairParamsSpec *>(paramSpec));
    HcfFree(brainpool160r1CommSpec);
}

HWTEST_F(CryptoEccKeyUtilTest, CryptoEccKeyUtilTest029, TestSize.Level0)
{
    HcfEccCommParamsSpec *brainpool160r1CommSpec = nullptr;
    ConstructEccKeyPairCommParamsSpec("NID_brainpoolP160r1", &brainpool160r1CommSpec);
    ASSERT_NE(brainpool160r1CommSpec, nullptr);
    HcfAsyKeyParamsSpec *paramSpec = nullptr;
    HcfResult res = ConstructEccKeyPairParamsSpec(g_brainpool160r1AlgName.c_str(),
        brainpool160r1CommSpec, &paramSpec);
    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(paramSpec, nullptr);

    HcfAsyKeyGeneratorBySpec *returnObj = nullptr;
    res = HcfAsyKeyGeneratorBySpecCreate(paramSpec, &returnObj);
    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(returnObj, nullptr);

    HcfKeyPair *returnKeyPair = nullptr;
    res = returnObj->generateKeyPair(returnObj, &returnKeyPair);
    HcfBlob priKeyBlob = {.data = nullptr, .len = 0};
    res = returnKeyPair->priKey->base.getEncoded(&(returnKeyPair->priKey->base), &priKeyBlob);
    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(returnKeyPair, nullptr);

    HcfObjDestroy(returnKeyPair);
    HcfObjDestroy(returnObj);
    HcfBlobDataFree(&priKeyBlob);
    DestroyEccKeyPairSpec(reinterpret_cast<HcfEccKeyPairParamsSpec *>(paramSpec));
    HcfFree(brainpool160r1CommSpec);
}

HWTEST_F(CryptoEccKeyUtilTest, CryptoEccKeyUtilTest030, TestSize.Level0)
{
    HcfEccCommParamsSpec *brainpool160r1CommSpec = nullptr;
    ConstructEccKeyPairCommParamsSpec("NID_brainpoolP160r1", &brainpool160r1CommSpec);
    ASSERT_NE(brainpool160r1CommSpec, nullptr);
    HcfAsyKeyParamsSpec *paramSpec = nullptr;
    HcfResult res = ConstructEccPubKeyParamsSpec(g_brainpool160r1AlgName.c_str(), brainpool160r1CommSpec,
        &paramSpec);
    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(paramSpec, nullptr);

    HcfAsyKeyGeneratorBySpec *returnObj = nullptr;
    res = HcfAsyKeyGeneratorBySpecCreate(paramSpec, &returnObj);
    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(returnObj, nullptr);

    HcfPubKey *returnPubKey = nullptr;
    res = returnObj->generatePubKey(returnObj, &returnPubKey);
    ASSERT_NE(res, HCF_INVALID_PARAMS);
    ASSERT_NE(returnPubKey, nullptr);

    HcfObjDestroy(returnPubKey);
    HcfObjDestroy(returnObj);
    DestroyEccPubKeySpec(reinterpret_cast<HcfEccPubKeyParamsSpec *>(paramSpec));
    HcfFree(brainpool160r1CommSpec);
}

HWTEST_F(CryptoEccKeyUtilTest, CryptoEccKeyUtilTest031, TestSize.Level0)
{
    HcfEccCommParamsSpec *brainpool160r1CommSpec = nullptr;
    ConstructEccKeyPairCommParamsSpec("NID_brainpoolP160r1", &brainpool160r1CommSpec);
    ASSERT_NE(brainpool160r1CommSpec, nullptr);
    HcfAsyKeyParamsSpec *paramSpec = nullptr;
    HcfResult res = ConstructEccPubKeyParamsSpec(g_brainpool160r1AlgName.c_str(), brainpool160r1CommSpec,
        &paramSpec);
    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(paramSpec, nullptr);

    HcfAsyKeyGeneratorBySpec *returnObj = nullptr;
    res = HcfAsyKeyGeneratorBySpecCreate(paramSpec, &returnObj);
    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(returnObj, nullptr);

    HcfPubKey *returnPubKey = nullptr;
    res = returnObj->generatePubKey(returnObj, &returnPubKey);
    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(returnPubKey, nullptr);

    returnPubKey->base.base.destroy(&(returnPubKey->base.base));
    HcfObjDestroy(returnObj);
    DestroyEccPubKeySpec(reinterpret_cast<HcfEccPubKeyParamsSpec *>(paramSpec));
    HcfFree(brainpool160r1CommSpec);
}

HWTEST_F(CryptoEccKeyUtilTest, CryptoEccKeyUtilTest032, TestSize.Level0)
{
    HcfEccCommParamsSpec *brainpool160r1CommSpec = nullptr;
    ConstructEccKeyPairCommParamsSpec("NID_brainpoolP160r1", &brainpool160r1CommSpec);
    ASSERT_NE(brainpool160r1CommSpec, nullptr);
    HcfAsyKeyParamsSpec *paramSpec = nullptr;
    HcfResult res = ConstructEccPubKeyParamsSpec(g_brainpool160r1AlgName.c_str(), brainpool160r1CommSpec,
        &paramSpec);
    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(paramSpec, nullptr);

    HcfAsyKeyGeneratorBySpec *returnObj = nullptr;
    res = HcfAsyKeyGeneratorBySpecCreate(paramSpec, &returnObj);
    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(returnObj, nullptr);

    HcfPubKey *returnPubKey = nullptr;
    res = returnObj->generatePubKey(returnObj, &returnPubKey);
    const char *format = returnPubKey->base.getFormat(&(returnPubKey->base));
    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(format, nullptr);

    HcfObjDestroy(returnPubKey);
    HcfObjDestroy(returnObj);
    DestroyEccPubKeySpec(reinterpret_cast<HcfEccPubKeyParamsSpec *>(paramSpec));
    HcfFree(brainpool160r1CommSpec);
}

HWTEST_F(CryptoEccKeyUtilTest, CryptoEccKeyUtilTest033, TestSize.Level0)
{
    HcfEccCommParamsSpec *brainpool160r1CommSpec = nullptr;
    ConstructEccKeyPairCommParamsSpec("NID_brainpoolP160r1", &brainpool160r1CommSpec);
    ASSERT_NE(brainpool160r1CommSpec, nullptr);
    HcfAsyKeyParamsSpec *paramSpec = nullptr;
    HcfResult res = ConstructEccPubKeyParamsSpec(g_brainpool160r1AlgName.c_str(), brainpool160r1CommSpec,
        &paramSpec);
    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(paramSpec, nullptr);

    HcfAsyKeyGeneratorBySpec *returnObj = nullptr;
    res = HcfAsyKeyGeneratorBySpecCreate(paramSpec, &returnObj);
    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(returnObj, nullptr);

    HcfPubKey *returnPubKey = nullptr;
    res = returnObj->generatePubKey(returnObj, &returnPubKey);
    const char *algorithm = returnPubKey->base.getAlgorithm(&(returnPubKey->base));
    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(algorithm, nullptr);

    HcfObjDestroy(returnPubKey);
    HcfObjDestroy(returnObj);
    DestroyEccPubKeySpec(reinterpret_cast<HcfEccPubKeyParamsSpec *>(paramSpec));
    HcfFree(brainpool160r1CommSpec);
}

HWTEST_F(CryptoEccKeyUtilTest, CryptoEccKeyUtilTest034, TestSize.Level0)
{
    HcfEccCommParamsSpec *brainpool160r1CommSpec = nullptr;
    ConstructEccKeyPairCommParamsSpec("NID_brainpoolP160r1", &brainpool160r1CommSpec);
    ASSERT_NE(brainpool160r1CommSpec, nullptr);
    HcfAsyKeyParamsSpec *paramSpec = nullptr;
    HcfResult res = ConstructEccPubKeyParamsSpec(g_brainpool160r1AlgName.c_str(), brainpool160r1CommSpec,
        &paramSpec);
    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(paramSpec, nullptr);

    HcfAsyKeyGeneratorBySpec *returnObj = nullptr;
    res = HcfAsyKeyGeneratorBySpecCreate(paramSpec, &returnObj);
    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(returnObj, nullptr);

    HcfPubKey *returnPubKey = nullptr;
    res = returnObj->generatePubKey(returnObj, &returnPubKey);

    HcfBlob blob = { .data = nullptr, .len = 0 };
    res = returnPubKey->base.getEncoded(&(returnPubKey->base), &blob);
    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(blob.data, nullptr);
    ASSERT_NE(blob.len, 0);
    HcfFree(blob.data);
    HcfObjDestroy(returnPubKey);
    HcfObjDestroy(returnObj);
    DestroyEccPubKeySpec(reinterpret_cast<HcfEccPubKeyParamsSpec *>(paramSpec));
    HcfFree(brainpool160r1CommSpec);
}

HWTEST_F(CryptoEccKeyUtilTest, CryptoEccKeyUtilTest035, TestSize.Level0)
{
    HcfEccCommParamsSpec *brainpool160r1CommSpec = nullptr;
    ConstructEccKeyPairCommParamsSpec("NID_brainpoolP160r1", &brainpool160r1CommSpec);
    ASSERT_NE(brainpool160r1CommSpec, nullptr);
    HcfAsyKeyParamsSpec *paramSpec = nullptr;
    HcfResult res = ConstructEccPriKeyParamsSpec(g_brainpool160r1AlgName.c_str(), brainpool160r1CommSpec,
        &paramSpec);
    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(paramSpec, nullptr);

    HcfAsyKeyGeneratorBySpec *returnObj = nullptr;
    res = HcfAsyKeyGeneratorBySpecCreate(paramSpec, &returnObj);
    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(returnObj, nullptr);

    HcfPriKey *returnPriKey = nullptr;
    res = returnObj->generatePriKey(returnObj, &returnPriKey);
    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(returnPriKey, nullptr);

    HcfObjDestroy(returnPriKey);
    HcfObjDestroy(returnObj);
    DestroyEccPriKeySpec(reinterpret_cast<HcfEccPriKeyParamsSpec *>(paramSpec));
    HcfFree(brainpool160r1CommSpec);
}

HWTEST_F(CryptoEccKeyUtilTest, CryptoEccKeyUtilTest036, TestSize.Level0)
{
    HcfEccCommParamsSpec *brainpool160r1CommSpec = nullptr;
    ConstructEccKeyPairCommParamsSpec("NID_brainpoolP160r1", &brainpool160r1CommSpec);
    ASSERT_NE(brainpool160r1CommSpec, nullptr);
    HcfAsyKeyParamsSpec *paramSpec = nullptr;
    HcfResult res = ConstructEccPriKeyParamsSpec(g_brainpool160r1AlgName.c_str(), brainpool160r1CommSpec,
        &paramSpec);
    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(paramSpec, nullptr);

    HcfAsyKeyGeneratorBySpec *returnObj = nullptr;
    res = HcfAsyKeyGeneratorBySpecCreate(paramSpec, &returnObj);
    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(returnObj, nullptr);

    HcfPriKey *returnPriKey = nullptr;
    res = returnObj->generatePriKey(returnObj, &returnPriKey);
    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(returnPriKey, nullptr);

    returnPriKey->base.base.destroy(&(returnPriKey->base.base));
    HcfObjDestroy(returnObj);
    DestroyEccPriKeySpec(reinterpret_cast<HcfEccPriKeyParamsSpec *>(paramSpec));
    HcfFree(brainpool160r1CommSpec);
}

HWTEST_F(CryptoEccKeyUtilTest, CryptoEccKeyUtilTest037, TestSize.Level0)
{
    HcfEccCommParamsSpec *brainpool160r1CommSpec = nullptr;
    ConstructEccKeyPairCommParamsSpec("NID_brainpoolP160r1", &brainpool160r1CommSpec);
    ASSERT_NE(brainpool160r1CommSpec, nullptr);
    HcfAsyKeyParamsSpec *paramSpec = nullptr;
    HcfResult res = ConstructEccPriKeyParamsSpec(g_brainpool160r1AlgName.c_str(), brainpool160r1CommSpec,
        &paramSpec);
    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(paramSpec, nullptr);

    HcfAsyKeyGeneratorBySpec *returnObj = nullptr;
    res = HcfAsyKeyGeneratorBySpecCreate(paramSpec, &returnObj);
    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(returnObj, nullptr);

    HcfPriKey *returnPriKey = nullptr;
    res = returnObj->generatePriKey(returnObj, &returnPriKey);
    returnPriKey->clearMem(returnPriKey);
    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(returnPriKey, nullptr);

    HcfObjDestroy(returnPriKey);
    HcfObjDestroy(returnObj);
    DestroyEccPriKeySpec(reinterpret_cast<HcfEccPriKeyParamsSpec *>(paramSpec));
    HcfFree(brainpool160r1CommSpec);
}

HWTEST_F(CryptoEccKeyUtilTest, CryptoEccKeyUtilTest038, TestSize.Level0)
{
    HcfEccCommParamsSpec *brainpool160r1CommSpec = nullptr;
    ConstructEccKeyPairCommParamsSpec("NID_brainpoolP160r1", &brainpool160r1CommSpec);
    ASSERT_NE(brainpool160r1CommSpec, nullptr);
    HcfAsyKeyParamsSpec *paramSpec = nullptr;
    HcfResult res = ConstructEccPriKeyParamsSpec(g_brainpool160r1AlgName.c_str(), brainpool160r1CommSpec,
        &paramSpec);
    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(paramSpec, nullptr);

    HcfAsyKeyGeneratorBySpec *returnObj = nullptr;
    res = HcfAsyKeyGeneratorBySpecCreate(paramSpec, &returnObj);
    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(returnObj, nullptr);

    HcfPriKey *returnPriKey = nullptr;
    res = returnObj->generatePriKey(returnObj, &returnPriKey);
    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(returnPriKey, nullptr);
    const char *algorithm = returnPriKey->base.getAlgorithm(&(returnPriKey->base));
    ASSERT_NE(algorithm, nullptr);

    HcfObjDestroy(returnPriKey);
    HcfObjDestroy(returnObj);
    DestroyEccPriKeySpec(reinterpret_cast<HcfEccPriKeyParamsSpec *>(paramSpec));
    HcfFree(brainpool160r1CommSpec);
}

HWTEST_F(CryptoEccKeyUtilTest, CryptoEccKeyUtilTest039_1, TestSize.Level0)
{
    HcfEccCommParamsSpec *brainpool160r1CommSpec = nullptr;
    ConstructEccKeyPairCommParamsSpec("NID_brainpoolP160r1", &brainpool160r1CommSpec);
    ASSERT_NE(brainpool160r1CommSpec, nullptr);
    HcfAsyKeyParamsSpec *paramSpec = nullptr;
    int32_t res = ConstructEccKeyPairParamsSpec(g_brainpool160r1AlgName.c_str(),
        brainpool160r1CommSpec, &paramSpec);
    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(paramSpec, nullptr);

    HcfAsyKeyGeneratorBySpec *returnObj = nullptr;
    res = HcfAsyKeyGeneratorBySpecCreate(paramSpec, &returnObj);
    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(returnObj, nullptr);

    HcfKeyPair *returnKeyPair = nullptr;
    res = returnObj->generateKeyPair(returnObj, &returnKeyPair);
    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(returnObj, nullptr);

    HcfSign *sign = nullptr;
    res = HcfSignCreate("ECC_BrainPoolP160r1|SHA224", &sign);
    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(sign, nullptr);

    res = sign->init(sign, nullptr, returnKeyPair->priKey);
    ASSERT_EQ(res, HCF_SUCCESS);

    HcfBlob out = { .data = nullptr, .len = 0 };
    res = sign->sign(sign, &g_mockInput, &out);
    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(out.data, nullptr);
    ASSERT_NE(out.len, 0);

    HcfVerify *verify = nullptr;
    res = HcfVerifyCreate("ECC_BrainPoolP160r1|SHA224", &verify);
    ASSERT_EQ(res, HCF_SUCCESS);

    res = verify->init(verify, nullptr, returnKeyPair->pubKey);
    ASSERT_EQ(res, HCF_SUCCESS);

    res = verify->verify(verify, &g_mockInput, &out);
    ASSERT_EQ(res, true);
    HcfFree(out.data);
    HcfObjDestroy(returnKeyPair);
    HcfObjDestroy(returnObj);
    HcfObjDestroy(sign);
    HcfObjDestroy(verify);
    DestroyEccKeyPairSpec(reinterpret_cast<HcfEccKeyPairParamsSpec *>(paramSpec));
    HcfFree(brainpool160r1CommSpec);
}

HWTEST_F(CryptoEccKeyUtilTest, CryptoEccKeyUtilTest039_2, TestSize.Level0)
{
    HcfEccCommParamsSpec *brainpool160t1CommSpec = nullptr;
    ConstructEccKeyPairCommParamsSpec("NID_brainpoolP160t1", &brainpool160t1CommSpec);
    ASSERT_NE(brainpool160t1CommSpec, nullptr);
    HcfAsyKeyParamsSpec *paramSpec = nullptr;
    int32_t res = ConstructEccKeyPairParamsSpec(g_brainpool160t1AlgName.c_str(),
        brainpool160t1CommSpec, &paramSpec);
    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(paramSpec, nullptr);

    HcfAsyKeyGeneratorBySpec *returnObj = nullptr;
    res = HcfAsyKeyGeneratorBySpecCreate(paramSpec, &returnObj);
    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(returnObj, nullptr);

    HcfKeyPair *returnKeyPair = nullptr;
    res = returnObj->generateKeyPair(returnObj, &returnKeyPair);
    ASSERT_EQ(res, HCF_SUCCESS);
    HcfSign *sign = nullptr;
    res = HcfSignCreate("ECC_BrainPoolP160t1|SHA224", &sign);
    ASSERT_EQ(res, HCF_SUCCESS);
    res = sign->init(sign, nullptr, returnKeyPair->priKey);
    ASSERT_EQ(res, HCF_SUCCESS);
    HcfBlob out = { .data = nullptr, .len = 0 };
    res = sign->sign(sign, &g_mockInput, &out);
    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(out.data, nullptr);
    ASSERT_NE(out.len, 0);
    HcfVerify *verify = nullptr;
    res = HcfVerifyCreate("ECC_BrainPoolP160t1|SHA224", &verify);
    ASSERT_EQ(res, HCF_SUCCESS);
    res = verify->init(verify, nullptr, returnKeyPair->pubKey);
    ASSERT_EQ(res, HCF_SUCCESS);
    res = verify->verify(verify, &g_mockInput, &out);
    ASSERT_EQ(res, true);
    HcfFree(out.data);
    HcfObjDestroy(returnKeyPair);
    HcfObjDestroy(returnObj);
    HcfObjDestroy(sign);
    HcfObjDestroy(verify);
    DestroyEccKeyPairSpec(reinterpret_cast<HcfEccKeyPairParamsSpec *>(paramSpec));
    HcfFree(brainpool160t1CommSpec);
}

HWTEST_F(CryptoEccKeyUtilTest, CryptoEccKeyUtilTest039_3, TestSize.Level0)
{
    HcfEccCommParamsSpec *brainpool192r1CommSpec = nullptr;
    ConstructEccKeyPairCommParamsSpec("NID_brainpoolP192r1", &brainpool192r1CommSpec);
    ASSERT_NE(brainpool192r1CommSpec, nullptr);
    HcfAsyKeyParamsSpec *paramSpec = nullptr;
    int32_t res = ConstructEccKeyPairParamsSpec(g_brainpool192r1AlgName.c_str(),
        brainpool192r1CommSpec, &paramSpec);
    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(paramSpec, nullptr);

    HcfAsyKeyGeneratorBySpec *returnObj = nullptr;
    res = HcfAsyKeyGeneratorBySpecCreate(paramSpec, &returnObj);
    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(returnObj, nullptr);

    HcfKeyPair *returnKeyPair = nullptr;
    res = returnObj->generateKeyPair(returnObj, &returnKeyPair);
    ASSERT_EQ(res, HCF_SUCCESS);
    HcfSign *sign = nullptr;
    res = HcfSignCreate("ECC_BrainPoolP192r1|SHA224", &sign);
    ASSERT_EQ(res, HCF_SUCCESS);
    res = sign->init(sign, nullptr, returnKeyPair->priKey);
    ASSERT_EQ(res, HCF_SUCCESS);
    HcfBlob out = { .data = nullptr, .len = 0 };
    res = sign->sign(sign, &g_mockInput, &out);
    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(out.data, nullptr);
    ASSERT_NE(out.len, 0);
    HcfVerify *verify = nullptr;
    res = HcfVerifyCreate("ECC_BrainPoolP192r1|SHA224", &verify);
    ASSERT_EQ(res, HCF_SUCCESS);
    res = verify->init(verify, nullptr, returnKeyPair->pubKey);
    ASSERT_EQ(res, HCF_SUCCESS);
    res = verify->verify(verify, &g_mockInput, &out);
    ASSERT_EQ(res, true);
    HcfFree(out.data);
    HcfObjDestroy(returnKeyPair);
    HcfObjDestroy(returnObj);
    HcfObjDestroy(sign);
    HcfObjDestroy(verify);
    DestroyEccKeyPairSpec(reinterpret_cast<HcfEccKeyPairParamsSpec *>(paramSpec));
    HcfFree(brainpool192r1CommSpec);
}

HWTEST_F(CryptoEccKeyUtilTest, CryptoEccKeyUtilTest039_4, TestSize.Level0)
{
    HcfEccCommParamsSpec *brainpool192t1CommSpec = nullptr;
    ConstructEccKeyPairCommParamsSpec("NID_brainpoolP192t1", &brainpool192t1CommSpec);
    ASSERT_NE(brainpool192t1CommSpec, nullptr);
    HcfAsyKeyParamsSpec *paramSpec = nullptr;
    int32_t res = ConstructEccKeyPairParamsSpec(g_brainpool192t1AlgName.c_str(),
        brainpool192t1CommSpec, &paramSpec);
    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(paramSpec, nullptr);

    HcfAsyKeyGeneratorBySpec *returnObj = nullptr;
    res = HcfAsyKeyGeneratorBySpecCreate(paramSpec, &returnObj);
    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(returnObj, nullptr);

    HcfKeyPair *returnKeyPair = nullptr;
    res = returnObj->generateKeyPair(returnObj, &returnKeyPair);
    ASSERT_EQ(res, HCF_SUCCESS);
    HcfSign *sign = nullptr;
    res = HcfSignCreate("ECC_BrainPoolP192t1|SHA224", &sign);
    ASSERT_EQ(res, HCF_SUCCESS);
    res = sign->init(sign, nullptr, returnKeyPair->priKey);
    ASSERT_EQ(res, HCF_SUCCESS);
    HcfBlob out = { .data = nullptr, .len = 0 };
    res = sign->sign(sign, &g_mockInput, &out);
    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(out.data, nullptr);
    ASSERT_NE(out.len, 0);
    HcfVerify *verify = nullptr;
    res = HcfVerifyCreate("ECC_BrainPoolP192t1|SHA224", &verify);
    ASSERT_EQ(res, HCF_SUCCESS);
    res = verify->init(verify, nullptr, returnKeyPair->pubKey);
    ASSERT_EQ(res, HCF_SUCCESS);
    res = verify->verify(verify, &g_mockInput, &out);
    ASSERT_EQ(res, true);
    HcfFree(out.data);

    HcfObjDestroy(returnKeyPair);
    HcfObjDestroy(returnObj);
    HcfObjDestroy(sign);
    HcfObjDestroy(verify);
    DestroyEccKeyPairSpec(reinterpret_cast<HcfEccKeyPairParamsSpec *>(paramSpec));
    HcfFree(brainpool192t1CommSpec);
}

HWTEST_F(CryptoEccKeyUtilTest, CryptoEccKeyUtilTest039_5, TestSize.Level0)
{
    HcfEccCommParamsSpec *brainpoolCommSpec = nullptr;
    ConstructEccKeyPairCommParamsSpec("NID_brainpoolP224r1", &brainpoolCommSpec);
    ASSERT_NE(brainpoolCommSpec, nullptr);
    HcfAsyKeyParamsSpec *paramSpec = nullptr;
    int32_t res = ConstructEccKeyPairParamsSpec(g_brainpool224r1AlgName.c_str(),
        brainpoolCommSpec, &paramSpec);
    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(paramSpec, nullptr);

    HcfAsyKeyGeneratorBySpec *returnObj = nullptr;
    res = HcfAsyKeyGeneratorBySpecCreate(paramSpec, &returnObj);
    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(returnObj, nullptr);

    HcfKeyPair *returnKeyPair = nullptr;
    res = returnObj->generateKeyPair(returnObj, &returnKeyPair);
    ASSERT_EQ(res, HCF_SUCCESS);
    HcfSign *sign = nullptr;
    res = HcfSignCreate("ECC_BrainPoolP224r1|SHA224", &sign);
    ASSERT_EQ(res, HCF_SUCCESS);
    res = sign->init(sign, nullptr, returnKeyPair->priKey);
    ASSERT_EQ(res, HCF_SUCCESS);
    HcfBlob out = { .data = nullptr, .len = 0 };
    res = sign->sign(sign, &g_mockInput, &out);
    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(out.data, nullptr);
    ASSERT_NE(out.len, 0);
    HcfVerify *verify = nullptr;
    res = HcfVerifyCreate("ECC_BrainPoolP224r1|SHA224", &verify);
    ASSERT_EQ(res, HCF_SUCCESS);
    res = verify->init(verify, nullptr, returnKeyPair->pubKey);
    ASSERT_EQ(res, HCF_SUCCESS);
    res = verify->verify(verify, &g_mockInput, &out);
    ASSERT_EQ(res, true);
    HcfFree(out.data);
    HcfObjDestroy(returnKeyPair);
    HcfObjDestroy(returnObj);
    HcfObjDestroy(sign);
    HcfObjDestroy(verify);
    DestroyEccKeyPairSpec(reinterpret_cast<HcfEccKeyPairParamsSpec *>(paramSpec));
    HcfFree(brainpoolCommSpec);
}

HWTEST_F(CryptoEccKeyUtilTest, CryptoEccKeyUtilTest039_6, TestSize.Level0)
{
    HcfEccCommParamsSpec *brainpoolCommSpec = nullptr;
    ConstructEccKeyPairCommParamsSpec("NID_brainpoolP224t1", &brainpoolCommSpec);
    ASSERT_NE(brainpoolCommSpec, nullptr);
    HcfAsyKeyParamsSpec *paramSpec = nullptr;
    int32_t res = ConstructEccKeyPairParamsSpec(g_brainpool224t1AlgName.c_str(),
        brainpoolCommSpec, &paramSpec);
    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(paramSpec, nullptr);

    HcfAsyKeyGeneratorBySpec *returnObj = nullptr;
    res = HcfAsyKeyGeneratorBySpecCreate(paramSpec, &returnObj);
    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(returnObj, nullptr);

    HcfKeyPair *returnKeyPair = nullptr;
    res = returnObj->generateKeyPair(returnObj, &returnKeyPair);
    ASSERT_EQ(res, HCF_SUCCESS);
    HcfSign *sign = nullptr;
    res = HcfSignCreate("ECC_BrainPoolP224t1|SHA224", &sign);
    ASSERT_EQ(res, HCF_SUCCESS);
    res = sign->init(sign, nullptr, returnKeyPair->priKey);
    ASSERT_EQ(res, HCF_SUCCESS);
    HcfBlob out = { .data = nullptr, .len = 0 };
    res = sign->sign(sign, &g_mockInput, &out);
    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(out.data, nullptr);
    ASSERT_NE(out.len, 0);
    HcfVerify *verify = nullptr;
    res = HcfVerifyCreate("ECC_BrainPoolP224t1|SHA224", &verify);
    ASSERT_EQ(res, HCF_SUCCESS);
    res = verify->init(verify, nullptr, returnKeyPair->pubKey);
    ASSERT_EQ(res, HCF_SUCCESS);
    res = verify->verify(verify, &g_mockInput, &out);
    ASSERT_EQ(res, true);
    HcfFree(out.data);
    HcfObjDestroy(returnKeyPair);
    HcfObjDestroy(returnObj);
    HcfObjDestroy(sign);
    HcfObjDestroy(verify);
    DestroyEccKeyPairSpec(reinterpret_cast<HcfEccKeyPairParamsSpec *>(paramSpec));
    HcfFree(brainpoolCommSpec);
}

HWTEST_F(CryptoEccKeyUtilTest, CryptoEccKeyUtilTest039_7, TestSize.Level0)
{
    HcfEccCommParamsSpec *brainpoolCommSpec = nullptr;
    ConstructEccKeyPairCommParamsSpec("NID_brainpoolP256r1", &brainpoolCommSpec);
    ASSERT_NE(brainpoolCommSpec, nullptr);
    HcfAsyKeyParamsSpec *paramSpec = nullptr;
    int32_t res = ConstructEccKeyPairParamsSpec(g_brainpool256r1AlgName.c_str(),
        brainpoolCommSpec, &paramSpec);
    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(paramSpec, nullptr);

    HcfAsyKeyGeneratorBySpec *returnObj = nullptr;
    res = HcfAsyKeyGeneratorBySpecCreate(paramSpec, &returnObj);
    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(returnObj, nullptr);

    HcfKeyPair *returnKeyPair = nullptr;
    res = returnObj->generateKeyPair(returnObj, &returnKeyPair);
    HcfSign *sign = nullptr;
    res = HcfSignCreate("ECC_BrainPoolP256r1|SHA224", &sign);
    ASSERT_EQ(res, HCF_SUCCESS);
    res = sign->init(sign, nullptr, returnKeyPair->priKey);
    ASSERT_EQ(res, HCF_SUCCESS);
    HcfBlob out = { .data = nullptr, .len = 0 };
    res = sign->sign(sign, &g_mockInput, &out);
    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(out.data, nullptr);
    ASSERT_NE(out.len, 0);
    HcfVerify *verify = nullptr;
    res = HcfVerifyCreate("ECC_BrainPoolP256r1|SHA224", &verify);
    ASSERT_EQ(res, HCF_SUCCESS);
    res = verify->init(verify, nullptr, returnKeyPair->pubKey);
    ASSERT_EQ(res, HCF_SUCCESS);
    res = verify->verify(verify, &g_mockInput, &out);
    ASSERT_EQ(res, true);
    HcfFree(out.data);
    HcfObjDestroy(returnKeyPair);
    HcfObjDestroy(returnObj);
    HcfObjDestroy(sign);
    HcfObjDestroy(verify);
    DestroyEccKeyPairSpec(reinterpret_cast<HcfEccKeyPairParamsSpec *>(paramSpec));
    HcfFree(brainpoolCommSpec);
}

HWTEST_F(CryptoEccKeyUtilTest, CryptoEccKeyUtilTest039_8, TestSize.Level0)
{
    HcfEccCommParamsSpec *brainpoolCommSpec = nullptr;
    ConstructEccKeyPairCommParamsSpec("NID_brainpoolP256t1", &brainpoolCommSpec);
    ASSERT_NE(brainpoolCommSpec, nullptr);
    HcfAsyKeyParamsSpec *paramSpec = nullptr;
    int32_t res = ConstructEccKeyPairParamsSpec(g_brainpool256t1AlgName.c_str(),
        brainpoolCommSpec, &paramSpec);
    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(paramSpec, nullptr);

    HcfAsyKeyGeneratorBySpec *returnObj = nullptr;
    res = HcfAsyKeyGeneratorBySpecCreate(paramSpec, &returnObj);
    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(returnObj, nullptr);

    HcfKeyPair *returnKeyPair = nullptr;
    res = returnObj->generateKeyPair(returnObj, &returnKeyPair);
    ASSERT_EQ(res, HCF_SUCCESS);
    HcfSign *sign = nullptr;
    res = HcfSignCreate("ECC_BrainPoolP256t1|SHA224", &sign);
    ASSERT_EQ(res, HCF_SUCCESS);
    res = sign->init(sign, nullptr, returnKeyPair->priKey);
    ASSERT_EQ(res, HCF_SUCCESS);
    HcfBlob out = { .data = nullptr, .len = 0 };
    res = sign->sign(sign, &g_mockInput, &out);
    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(out.data, nullptr);
    ASSERT_NE(out.len, 0);
    HcfVerify *verify = nullptr;
    res = HcfVerifyCreate("ECC_BrainPoolP256t1|SHA224", &verify);
    ASSERT_EQ(res, HCF_SUCCESS);
    res = verify->init(verify, nullptr, returnKeyPair->pubKey);
    ASSERT_EQ(res, HCF_SUCCESS);
    res = verify->verify(verify, &g_mockInput, &out);
    ASSERT_EQ(res, true);
    HcfFree(out.data);
    HcfObjDestroy(returnKeyPair);
    HcfObjDestroy(returnObj);
    HcfObjDestroy(sign);
    HcfObjDestroy(verify);
    DestroyEccKeyPairSpec(reinterpret_cast<HcfEccKeyPairParamsSpec *>(paramSpec));
    HcfFree(brainpoolCommSpec);
}

HWTEST_F(CryptoEccKeyUtilTest, CryptoEccKeyUtilTest039_9, TestSize.Level0)
{
    HcfEccCommParamsSpec *brainpoolCommSpec = nullptr;
    ConstructEccKeyPairCommParamsSpec("NID_brainpoolP320r1", &brainpoolCommSpec);
    ASSERT_NE(brainpoolCommSpec, nullptr);
    HcfAsyKeyParamsSpec *paramSpec = nullptr;
    int32_t res = ConstructEccKeyPairParamsSpec(g_brainpool320r1AlgName.c_str(),
        brainpoolCommSpec, &paramSpec);
    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(paramSpec, nullptr);

    HcfAsyKeyGeneratorBySpec *returnObj = nullptr;
    res = HcfAsyKeyGeneratorBySpecCreate(paramSpec, &returnObj);
    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(returnObj, nullptr);

    HcfKeyPair *returnKeyPair = nullptr;
    res = returnObj->generateKeyPair(returnObj, &returnKeyPair);
    ASSERT_EQ(res, HCF_SUCCESS);
    HcfSign *sign = nullptr;
    res = HcfSignCreate("ECC_BrainPoolP320r1|SHA224", &sign);
    ASSERT_EQ(res, HCF_SUCCESS);
    res = sign->init(sign, nullptr, returnKeyPair->priKey);
    ASSERT_EQ(res, HCF_SUCCESS);
    HcfBlob out = { .data = nullptr, .len = 0 };
    res = sign->sign(sign, &g_mockInput, &out);
    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(out.data, nullptr);
    ASSERT_NE(out.len, 0);
    HcfVerify *verify = nullptr;
    res = HcfVerifyCreate("ECC_BrainPoolP320r1|SHA224", &verify);
    ASSERT_EQ(res, HCF_SUCCESS);
    res = verify->init(verify, nullptr, returnKeyPair->pubKey);
    ASSERT_EQ(res, HCF_SUCCESS);
    res = verify->verify(verify, &g_mockInput, &out);
    ASSERT_EQ(res, true);
    HcfFree(out.data);
    HcfObjDestroy(returnKeyPair);
    HcfObjDestroy(returnObj);
    HcfObjDestroy(sign);
    HcfObjDestroy(verify);
    DestroyEccKeyPairSpec(reinterpret_cast<HcfEccKeyPairParamsSpec *>(paramSpec));
    HcfFree(brainpoolCommSpec);
}

HWTEST_F(CryptoEccKeyUtilTest, CryptoEccKeyUtilTest039_10, TestSize.Level0)
{
    HcfEccCommParamsSpec *brainpoolCommSpec = nullptr;
    ConstructEccKeyPairCommParamsSpec("NID_brainpoolP320t1", &brainpoolCommSpec);
    ASSERT_NE(brainpoolCommSpec, nullptr);
    HcfAsyKeyParamsSpec *paramSpec = nullptr;
    int32_t res = ConstructEccKeyPairParamsSpec(g_brainpool320t1AlgName.c_str(),
        brainpoolCommSpec, &paramSpec);
    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(paramSpec, nullptr);

    HcfAsyKeyGeneratorBySpec *returnObj = nullptr;
    res = HcfAsyKeyGeneratorBySpecCreate(paramSpec, &returnObj);
    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(returnObj, nullptr);

    HcfKeyPair *returnKeyPair = nullptr;
    res = returnObj->generateKeyPair(returnObj, &returnKeyPair);
    ASSERT_EQ(res, HCF_SUCCESS);
    HcfSign *sign = nullptr;
    res = HcfSignCreate("ECC_BrainPoolP320t1|SHA224", &sign);
    ASSERT_EQ(res, HCF_SUCCESS);
    res = sign->init(sign, nullptr, returnKeyPair->priKey);
    ASSERT_EQ(res, HCF_SUCCESS);
    HcfBlob out = { .data = nullptr, .len = 0 };
    res = sign->sign(sign, &g_mockInput, &out);
    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(out.data, nullptr);
    ASSERT_NE(out.len, 0);
    HcfVerify *verify = nullptr;
    res = HcfVerifyCreate("ECC_BrainPoolP320t1|SHA224", &verify);
    ASSERT_EQ(res, HCF_SUCCESS);
    res = verify->init(verify, nullptr, returnKeyPair->pubKey);
    ASSERT_EQ(res, HCF_SUCCESS);
    res = verify->verify(verify, &g_mockInput, &out);
    ASSERT_EQ(res, true);
    HcfFree(out.data);
    HcfObjDestroy(returnKeyPair);
    HcfObjDestroy(returnObj);
    HcfObjDestroy(sign);
    HcfObjDestroy(verify);
    DestroyEccKeyPairSpec(reinterpret_cast<HcfEccKeyPairParamsSpec *>(paramSpec));
    HcfFree(brainpoolCommSpec);
}

HWTEST_F(CryptoEccKeyUtilTest, CryptoEccKeyUtilTest039_11, TestSize.Level0)
{
    HcfEccCommParamsSpec *brainpoolCommSpec = nullptr;
    ConstructEccKeyPairCommParamsSpec("NID_brainpoolP384r1", &brainpoolCommSpec);
    ASSERT_NE(brainpoolCommSpec, nullptr);
    HcfAsyKeyParamsSpec *paramSpec = nullptr;
    int32_t res = ConstructEccKeyPairParamsSpec(g_brainpool384r1AlgName.c_str(),
        brainpoolCommSpec, &paramSpec);
    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(paramSpec, nullptr);

    HcfAsyKeyGeneratorBySpec *returnObj = nullptr;
    res = HcfAsyKeyGeneratorBySpecCreate(paramSpec, &returnObj);
    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(returnObj, nullptr);

    HcfKeyPair *returnKeyPair = nullptr;
    res = returnObj->generateKeyPair(returnObj, &returnKeyPair);
    ASSERT_EQ(res, HCF_SUCCESS);
    HcfSign *sign = nullptr;
    res = HcfSignCreate("ECC_BrainPoolP384r1|SHA224", &sign);
    ASSERT_EQ(res, HCF_SUCCESS);
    res = sign->init(sign, nullptr, returnKeyPair->priKey);
    ASSERT_EQ(res, HCF_SUCCESS);
    HcfBlob out = { .data = nullptr, .len = 0 };
    res = sign->sign(sign, &g_mockInput, &out);
    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(out.data, nullptr);
    ASSERT_NE(out.len, 0);
    HcfVerify *verify = nullptr;
    res = HcfVerifyCreate("ECC_BrainPoolP384r1|SHA224", &verify);
    ASSERT_EQ(res, HCF_SUCCESS);
    res = verify->init(verify, nullptr, returnKeyPair->pubKey);
    ASSERT_EQ(res, HCF_SUCCESS);
    res = verify->verify(verify, &g_mockInput, &out);
    ASSERT_EQ(res, true);
    HcfFree(out.data);
    HcfObjDestroy(returnKeyPair);
    HcfObjDestroy(returnObj);
    HcfObjDestroy(sign);
    HcfObjDestroy(verify);
    DestroyEccKeyPairSpec(reinterpret_cast<HcfEccKeyPairParamsSpec *>(paramSpec));
    HcfFree(brainpoolCommSpec);
}

HWTEST_F(CryptoEccKeyUtilTest, CryptoEccKeyUtilTest039_12, TestSize.Level0)
{
    HcfEccCommParamsSpec *brainpoolCommSpec = nullptr;
    ConstructEccKeyPairCommParamsSpec("NID_brainpoolP384t1", &brainpoolCommSpec);
    ASSERT_NE(brainpoolCommSpec, nullptr);
    HcfAsyKeyParamsSpec *paramSpec = nullptr;
    int32_t res = ConstructEccKeyPairParamsSpec(g_brainpool384t1AlgName.c_str(),
        brainpoolCommSpec, &paramSpec);
    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(paramSpec, nullptr);

    HcfAsyKeyGeneratorBySpec *returnObj = nullptr;
    res = HcfAsyKeyGeneratorBySpecCreate(paramSpec, &returnObj);
    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(returnObj, nullptr);

    HcfKeyPair *returnKeyPair = nullptr;
    res = returnObj->generateKeyPair(returnObj, &returnKeyPair);
    ASSERT_EQ(res, HCF_SUCCESS);
    HcfSign *sign = nullptr;
    res = HcfSignCreate("ECC_BrainPoolP384t1|SHA224", &sign);
    ASSERT_EQ(res, HCF_SUCCESS);
    res = sign->init(sign, nullptr, returnKeyPair->priKey);
    ASSERT_EQ(res, HCF_SUCCESS);
    HcfBlob out = { .data = nullptr, .len = 0 };
    res = sign->sign(sign, &g_mockInput, &out);
    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(out.data, nullptr);
    ASSERT_NE(out.len, 0);
    HcfVerify *verify = nullptr;
    res = HcfVerifyCreate("ECC_BrainPoolP384t1|SHA224", &verify);
    ASSERT_EQ(res, HCF_SUCCESS);
    res = verify->init(verify, nullptr, returnKeyPair->pubKey);
    ASSERT_EQ(res, HCF_SUCCESS);
    res = verify->verify(verify, &g_mockInput, &out);
    ASSERT_EQ(res, true);
    HcfFree(out.data);
    HcfObjDestroy(returnKeyPair);
    HcfObjDestroy(returnObj);
    HcfObjDestroy(sign);
    HcfObjDestroy(verify);
    DestroyEccKeyPairSpec(reinterpret_cast<HcfEccKeyPairParamsSpec *>(paramSpec));
    HcfFree(brainpoolCommSpec);
}

HWTEST_F(CryptoEccKeyUtilTest, CryptoEccKeyUtilTest039_13, TestSize.Level0)
{
    HcfEccCommParamsSpec *brainpoolCommSpec = nullptr;
    ConstructEccKeyPairCommParamsSpec("NID_brainpoolP512r1", &brainpoolCommSpec);
    ASSERT_NE(brainpoolCommSpec, nullptr);
    HcfAsyKeyParamsSpec *paramSpec = nullptr;
    int32_t res = ConstructEccKeyPairParamsSpec(g_brainpool512r1AlgName.c_str(),
        brainpoolCommSpec, &paramSpec);
    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(paramSpec, nullptr);

    HcfAsyKeyGeneratorBySpec *returnObj = nullptr;
    res = HcfAsyKeyGeneratorBySpecCreate(paramSpec, &returnObj);
    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(returnObj, nullptr);

    HcfKeyPair *returnKeyPair = nullptr;
    res = returnObj->generateKeyPair(returnObj, &returnKeyPair);
    ASSERT_EQ(res, HCF_SUCCESS);
    HcfSign *sign = nullptr;
    res = HcfSignCreate("ECC_BrainPoolP512r1|SHA224", &sign);
    ASSERT_EQ(res, HCF_SUCCESS);
    res = sign->init(sign, nullptr, returnKeyPair->priKey);
    ASSERT_EQ(res, HCF_SUCCESS);
    HcfBlob out = { .data = nullptr, .len = 0 };
    res = sign->sign(sign, &g_mockInput, &out);
    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(out.data, nullptr);
    ASSERT_NE(out.len, 0);
    HcfVerify *verify = nullptr;
    res = HcfVerifyCreate("ECC_BrainPoolP512r1|SHA224", &verify);
    ASSERT_EQ(res, HCF_SUCCESS);
    res = verify->init(verify, nullptr, returnKeyPair->pubKey);
    ASSERT_EQ(res, HCF_SUCCESS);
    res = verify->verify(verify, &g_mockInput, &out);
    ASSERT_EQ(res, true);
    HcfFree(out.data);
    HcfObjDestroy(returnKeyPair);
    HcfObjDestroy(returnObj);
    HcfObjDestroy(sign);
    HcfObjDestroy(verify);
    DestroyEccKeyPairSpec(reinterpret_cast<HcfEccKeyPairParamsSpec *>(paramSpec));
    HcfFree(brainpoolCommSpec);
}

HWTEST_F(CryptoEccKeyUtilTest, CryptoEccKeyUtilTest039_14, TestSize.Level0)
{
    HcfEccCommParamsSpec *brainpoolCommSpec = nullptr;
    ConstructEccKeyPairCommParamsSpec("NID_brainpoolP512t1", &brainpoolCommSpec);
    ASSERT_NE(brainpoolCommSpec, nullptr);
    HcfAsyKeyParamsSpec *paramSpec = nullptr;
    int32_t res = ConstructEccKeyPairParamsSpec(g_brainpool512t1AlgName.c_str(),
        brainpoolCommSpec, &paramSpec);
    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(paramSpec, nullptr);

    HcfAsyKeyGeneratorBySpec *returnObj = nullptr;
    res = HcfAsyKeyGeneratorBySpecCreate(paramSpec, &returnObj);
    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(returnObj, nullptr);

    HcfKeyPair *returnKeyPair = nullptr;
    res = returnObj->generateKeyPair(returnObj, &returnKeyPair);
    HcfSign *sign = nullptr;
    res = HcfSignCreate("ECC_BrainPoolP512t1|SHA224", &sign);
    ASSERT_EQ(res, HCF_SUCCESS);
    res = sign->init(sign, nullptr, returnKeyPair->priKey);
    ASSERT_EQ(res, HCF_SUCCESS);
    HcfBlob out = { .data = nullptr, .len = 0 };
    res = sign->sign(sign, &g_mockInput, &out);
    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(out.data, nullptr);
    ASSERT_NE(out.len, 0);
    HcfVerify *verify = nullptr;
    res = HcfVerifyCreate("ECC_BrainPoolP512t1|SHA224", &verify);
    ASSERT_EQ(res, HCF_SUCCESS);
    res = verify->init(verify, nullptr, returnKeyPair->pubKey);
    ASSERT_EQ(res, HCF_SUCCESS);
    res = verify->verify(verify, &g_mockInput, &out);
    ASSERT_EQ(res, true);
    HcfFree(out.data);
    HcfObjDestroy(returnKeyPair);
    HcfObjDestroy(returnObj);
    HcfObjDestroy(sign);
    HcfObjDestroy(verify);
    DestroyEccKeyPairSpec(reinterpret_cast<HcfEccKeyPairParamsSpec *>(paramSpec));
    HcfFree(brainpoolCommSpec);
}

HWTEST_F(CryptoEccKeyUtilTest, CryptoEccKeyUtilTest040, TestSize.Level0)
{
    HcfEccCommParamsSpec *brainpool160r1CommSpec = nullptr;
    ConstructEccKeyPairCommParamsSpec("NID_brainpoolP160r1", &brainpool160r1CommSpec);
    ASSERT_NE(brainpool160r1CommSpec, nullptr);
    HcfAsyKeyParamsSpec *paramSpec = nullptr;
    HcfResult res = ConstructEccKeyPairParamsSpec(g_brainpool160r1AlgName.c_str(),
        brainpool160r1CommSpec, &paramSpec);
    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(paramSpec, nullptr);

    HcfAsyKeyGeneratorBySpec *returnObj = nullptr;
    res = HcfAsyKeyGeneratorBySpecCreate(paramSpec, &returnObj);
    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(returnObj, nullptr);

    HcfKeyPair *returnKeyPair = nullptr;
    res = returnObj->generateKeyPair(returnObj, &returnKeyPair);
    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(returnKeyPair, nullptr);

    HcfObjDestroy(returnKeyPair);
    HcfObjDestroy(returnObj);
    DestroyEccKeyPairSpec(reinterpret_cast<HcfEccKeyPairParamsSpec *>(paramSpec));
    HcfFree(brainpool160r1CommSpec);
}

HWTEST_F(CryptoEccKeyUtilTest, CryptoEccKeyUtilTest041, TestSize.Level0)
{
    HcfEccCommParamsSpec *brainpool160r1CommSpec = nullptr;
    ConstructEccKeyPairCommParamsSpec("NID_brainpoolP160r1", &brainpool160r1CommSpec);
    ASSERT_NE(brainpool160r1CommSpec, nullptr);
    HcfAsyKeyParamsSpec *paramSpec = nullptr;
    HcfResult res = ConstructEccPubKeyParamsSpec(g_brainpool160r1AlgName.c_str(), brainpool160r1CommSpec,
        &paramSpec);
    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(paramSpec, nullptr);

    HcfAsyKeyGeneratorBySpec *returnObj = nullptr;
    res = HcfAsyKeyGeneratorBySpecCreate(paramSpec, &returnObj);
    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(returnObj, nullptr);

    HcfPubKey *returnPubKey = nullptr;
    res = returnObj->generatePubKey(returnObj, &returnPubKey);
    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(returnPubKey, nullptr);

    HcfObjDestroy(returnPubKey);
    HcfObjDestroy(returnObj);
    DestroyEccPubKeySpec(reinterpret_cast<HcfEccPubKeyParamsSpec *>(paramSpec));
    HcfFree(brainpool160r1CommSpec);
}

HWTEST_F(CryptoEccKeyUtilTest, CryptoEccKeyUtilTest042, TestSize.Level0)
{
    HcfEccCommParamsSpec *brainpool160r1CommSpec = nullptr;
    ConstructEccKeyPairCommParamsSpec("NID_brainpoolP160r1", &brainpool160r1CommSpec);
    ASSERT_NE(brainpool160r1CommSpec, nullptr);
    HcfAsyKeyParamsSpec *paramSpec = nullptr;
    HcfResult res = ConstructEccPriKeyParamsSpec(g_brainpool160r1AlgName.c_str(), brainpool160r1CommSpec,
        &paramSpec);
    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(paramSpec, nullptr);

    HcfAsyKeyGeneratorBySpec *returnObj = nullptr;
    res = HcfAsyKeyGeneratorBySpecCreate(paramSpec, &returnObj);
    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(returnObj, nullptr);

    HcfPriKey *returnPriKey = nullptr;
    res = returnObj->generatePriKey(returnObj, &returnPriKey);
    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(returnPriKey, nullptr);

    HcfObjDestroy(returnPriKey);
    HcfObjDestroy(returnObj);
    DestroyEccPriKeySpec(reinterpret_cast<HcfEccPriKeyParamsSpec *>(paramSpec));
    HcfFree(brainpool160r1CommSpec);
}

HWTEST_F(CryptoEccKeyUtilTest, CryptoEccKeyUtilTest043, TestSize.Level0)
{
    HcfEccCommParamsSpec *brainpool160r1CommSpec = nullptr;
    ConstructEccKeyPairCommParamsSpec("NID_brainpoolP160r1", &brainpool160r1CommSpec);
    ASSERT_NE(brainpool160r1CommSpec, nullptr);
    HcfAsyKeyParamsSpec *paramSpec = nullptr;
    HcfResult res = ConstructEccPriKeyParamsSpec(g_brainpool160r1AlgName.c_str(), brainpool160r1CommSpec,
        &paramSpec);
    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(paramSpec, nullptr);

    HcfAsyKeyGeneratorBySpec *returnObj = nullptr;
    res = HcfAsyKeyGeneratorBySpecCreate(paramSpec, &returnObj);
    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(returnObj, nullptr);

    HcfKeyPair *returnPriKey = nullptr;
    res = returnObj->generateKeyPair(returnObj, &returnPriKey);
    ASSERT_NE(res, HCF_SUCCESS);
    ASSERT_EQ(returnPriKey, nullptr);

    HcfObjDestroy(returnPriKey);
    HcfObjDestroy(returnObj);
    DestroyEccPriKeySpec(reinterpret_cast<HcfEccPriKeyParamsSpec *>(paramSpec));
    HcfFree(brainpool160r1CommSpec);
}

HWTEST_F(CryptoEccKeyUtilTest, CryptoEccKeyUtilTest044, TestSize.Level0)
{
    HcfEccCommParamsSpec *brainpool160r1CommSpec = nullptr;
    ConstructEccKeyPairCommParamsSpec("NID_brainpoolP160r1", &brainpool160r1CommSpec);
    ASSERT_NE(brainpool160r1CommSpec, nullptr);
    HcfAsyKeyParamsSpec *paramSpec = nullptr;
    HcfResult res = ConstructEccKeyPairParamsSpec(g_brainpool160r1AlgName.c_str(),
        brainpool160r1CommSpec, &paramSpec);
    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(paramSpec, nullptr);

    HcfAsyKeyGeneratorBySpec *returnObj = nullptr;
    res = HcfAsyKeyGeneratorBySpecCreate(paramSpec, &returnObj);
    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(returnObj, nullptr);

    HcfPriKey *returnPriKey = nullptr;
    res = returnObj->generatePriKey(returnObj, &returnPriKey);
    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(returnPriKey, nullptr);

    HcfObjDestroy(returnPriKey);
    HcfObjDestroy(returnObj);
    DestroyEccKeyPairSpec(reinterpret_cast<HcfEccKeyPairParamsSpec *>(paramSpec));
    HcfFree(brainpool160r1CommSpec);
}

HWTEST_F(CryptoEccKeyUtilTest, CryptoEccKeyUtilTest045, TestSize.Level0)
{
    HcfEccCommParamsSpec *brainpool160r1CommSpec = nullptr;
    ConstructEccKeyPairCommParamsSpec("NID_brainpoolP160r1", &brainpool160r1CommSpec);
    ASSERT_NE(brainpool160r1CommSpec, nullptr);
    HcfAsyKeyParamsSpec *paramSpec = nullptr;
    HcfResult res = ConstructEccPriKeyParamsSpec(g_brainpool160r1AlgName.c_str(), brainpool160r1CommSpec,
        &paramSpec);
    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(paramSpec, nullptr);

    HcfAsyKeyGeneratorBySpec *returnObj = nullptr;
    res = HcfAsyKeyGeneratorBySpecCreate(paramSpec, &returnObj);
    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(returnObj, nullptr);

    HcfPubKey *returnPriKey = nullptr;
    res = returnObj->generatePubKey(returnObj, &returnPriKey);
    ASSERT_NE(res, HCF_SUCCESS);
    ASSERT_EQ(returnPriKey, nullptr);

    HcfObjDestroy(returnPriKey);
    HcfObjDestroy(returnObj);
    DestroyEccPriKeySpec(reinterpret_cast<HcfEccPriKeyParamsSpec *>(paramSpec));
    HcfFree(brainpool160r1CommSpec);
}

HWTEST_F(CryptoEccKeyUtilTest, CryptoEccKeyUtilTest046, TestSize.Level0)
{
    HcfAsyKeyGenParams params = {
        .algo = HCF_ALG_ECC,
        .bits = HCF_ALG_ECC_BP160R1,
        .primes = HCF_OPENSSL_PRIMES_2
    };
    HcfEccCommParamsSpecSpi *returnCommonParamSpec = nullptr;
    HcfResult res = HcfECCCommonParamSpecCreate(&params, &returnCommonParamSpec);
    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(returnCommonParamSpec, nullptr);
    FreeEccCommParamsSpec(&(returnCommonParamSpec->paramsSpec));
    HcfFree(returnCommonParamSpec);
}

HWTEST_F(CryptoEccKeyUtilTest, CryptoEccKeyUtilTest047, TestSize.Level0)
{
    HcfEccCommParamsSpecSpi *returnCommonParamSpec = nullptr;
    HcfResult res = HcfECCCommonParamSpecCreate(nullptr, &returnCommonParamSpec);
    ASSERT_NE(res, HCF_SUCCESS);
}

HWTEST_F(CryptoEccKeyUtilTest, CryptoEccKeyUtilTest048, TestSize.Level0)
{
    HcfAsyKeyGenParams params = {
        .algo = HCF_ALG_ECC,
        .bits = HCF_ALG_ECC_BP160R1,
        .primes = HCF_OPENSSL_PRIMES_2
    };
    HcfResult res = HcfECCCommonParamSpecCreate(&params, nullptr);
    ASSERT_NE(res, HCF_SUCCESS);
}

HWTEST_F(CryptoEccKeyUtilTest, CryptoEccKeyUtilTest049, TestSize.Level0)
{
    HcfAsyKeyGenParams obj = {
        .algo = HCF_ALG_ECC,
        .bits = HCF_OPENSSL_RSA_2048,
        .primes = HCF_OPENSSL_PRIMES_2
    };
    HcfEccCommParamsSpecSpi *returnCommonParamSpec = nullptr;
    HcfResult res = HcfECCCommonParamSpecCreate(&obj, &returnCommonParamSpec);
    ASSERT_NE(res, HCF_SUCCESS);
    ASSERT_EQ(returnCommonParamSpec, nullptr);

    FreeEccCommParamsSpec(&(returnCommonParamSpec->paramsSpec));
    HcfFree(returnCommonParamSpec);
}

HWTEST_F(CryptoEccKeyUtilTest, CryptoEccKeyUtilTest050, TestSize.Level0)
{
    HcfAsyKeyGenParams obj = {
        .algo = HCF_ALG_ECC,
        .bits = 0,
        .primes = HCF_OPENSSL_PRIMES_2
    };
    HcfEccCommParamsSpecSpi *returnCommonParamSpec = nullptr;
    HcfResult res = HcfECCCommonParamSpecCreate(&obj, &returnCommonParamSpec);
    ASSERT_NE(res, HCF_SUCCESS);
    ASSERT_EQ(returnCommonParamSpec, nullptr);

    FreeEccCommParamsSpec(&(returnCommonParamSpec->paramsSpec));
    HcfFree(returnCommonParamSpec);
}

HWTEST_F(CryptoEccKeyUtilTest, CryptoEccKeyUtilTest051, TestSize.Level0)
{
    HcfResult res = HcfEccKeyUtilCreate("NID_brainpoolP160r1", nullptr);
    ASSERT_EQ(res, HCF_INVALID_PARAMS);
}

static void OpensslMockTestFunc(uint32_t mallocCount, HcfEccCommParamsSpec *returnCommonParamSpec)
{
    for (uint32_t i = 0; i < mallocCount; i++) {
        ResetOpensslCallNum();
        SetOpensslCallMockIndex(i);

        HcfResult res = HcfEccKeyUtilCreate("NID_brainpoolP160r1", &returnCommonParamSpec);
        if (res != HCF_SUCCESS) {
            continue;
        }

        FreeEccCommParamsSpec(returnCommonParamSpec);
        HcfFree(returnCommonParamSpec);
    }
}

HWTEST_F(CryptoEccKeyUtilTest, CryptoEccKeyUtilTest052, TestSize.Level0)
{
    StartRecordOpensslCallNum();
    HcfEccCommParamsSpec *returnCommonParamSpec = nullptr;
    HcfResult res = HcfEccKeyUtilCreate("NID_brainpoolP160r1", &returnCommonParamSpec);
    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(returnCommonParamSpec, nullptr);

    FreeEccCommParamsSpec(returnCommonParamSpec);
    HcfFree(returnCommonParamSpec);

    uint32_t mallocCount = GetOpensslCallNum();
    OpensslMockTestFunc(mallocCount, returnCommonParamSpec);

    EndRecordOpensslCallNum();
}
}
