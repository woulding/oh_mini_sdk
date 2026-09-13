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
#include <climits>

#include "alg_25519_common_param_spec.h"
#include "asy_key_generator.h"
#include "blob.h"
#include "dh_key_util.h"
#include "ecdsa_openssl.h"
#include "memory.h"
#include "securec.h"
#include "openssl_common.h"
#include "asy_key_params.h"
#include "params_parser.h"
#include "dh_asy_key_generator_openssl.h"
#include "detailed_dh_key_params.h"
#include "alg_25519_asy_key_generator_openssl.h"
#include "dh_common_param_spec_generator_openssl.h"
#include "memory_mock.h"
#include "openssl_adapter_mock.h"
#include "detailed_ecc_key_params.h"
#include "sm2_crypto_params.h"

using namespace std;
using namespace testing::ext;

namespace {
constexpr int SKLEN_DH128 = 128;
constexpr int SKLEN_DH223 = 223;
constexpr int SKLEN_DH255 = 255;
constexpr int SKLEN_DH303 = 303;
constexpr int SKLEN_DH351 = 351;
constexpr int SKLEN_DH399 = 399;
constexpr int SKLEN_DH1024 = 1024;
constexpr int SKLEN_EQZERO = 0;
constexpr int PLEN_DH511 = 511;
constexpr int PLEN_DH512 = 512;
constexpr int PLEN_DH1536 = 1536;
constexpr int PLEN_DH2048 = 2048;
constexpr int PLEN_DH3072 = 3072;
constexpr int PLEN_DH4096 = 4096;
constexpr int PLEN_DH6144 = 6144;
constexpr int PLEN_DH8192 = 8192;
constexpr int PLEN_DH10001 = 10001;
constexpr int PLEN_LTSK = 20;

class CryptoDHAsyKeyGeneratorBySpecTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp();
    void TearDown();
};

static string g_dh1536AlgoName = "DH_modp1536";
static string g_dh2048AlgoName = "DH_modp2048";
static string g_dh3072AlgoName = "DH_modp3072";
static string g_dh4096AlgoName = "DH_modp4096";
static string g_dh6144AlgoName = "DH_modp6144";
static string g_dh8192AlgoName = "DH_modp8192";

static string g_dhAlgoName = "DH";
static string g_dhpubkeyformatName = "X.509";
static string g_dhprikeyformatName = "PKCS#8";

HcfDhCommParamsSpec *g_dh1536CommSpec = nullptr;
HcfDhCommParamsSpec *g_dh2048CommSpec = nullptr;
HcfDhCommParamsSpec *g_dh3072CommSpec = nullptr;
HcfDhCommParamsSpec *g_dh4096CommSpec = nullptr;
HcfDhCommParamsSpec *g_dh6144CommSpec = nullptr;
HcfDhCommParamsSpec *g_dh8192CommSpec = nullptr;
HcfKeyPair *g_dhKeyPair = nullptr;

void CryptoDHAsyKeyGeneratorBySpecTest::SetUp() {}
void CryptoDHAsyKeyGeneratorBySpecTest::TearDown() {}

static const char *GetMockClass(void)
{
    return "HcfEcc";
}
HcfObjectBase g_obj = {
    .getClass = GetMockClass,
    .destroy = nullptr
};

static void DestroyTestDhPriKeySpec(HcfDhPriKeyParamsSpec *spec)
{
    if (spec == nullptr) {
        return;
    }
    if (spec->sk.data != nullptr) {
        (void)memset_s(spec->sk.data, spec->sk.len, 0, spec->sk.len);
        HcfFree(spec->sk.data);
        spec->sk.data = nullptr;
    }
    HcfFree(spec);
}

static void DestroyTestDhPubKeySpec(HcfDhPubKeyParamsSpec *spec)
{
    if (spec == nullptr) {
        return;
    }
    HcfFree(spec->pk.data);
    spec->pk.data = nullptr;
    HcfFree(spec);
}

static void DestroyTestDhKeyPairSpec(HcfDhKeyPairParamsSpec *spec)
{
    if (spec == nullptr) {
        return;
    }
    HcfFree(spec->pk.data);
    spec->pk.data = nullptr;
    if (spec->sk.data != nullptr) {
        (void)memset_s(spec->sk.data, spec->sk.len, 0, spec->sk.len);
        HcfFree(spec->sk.data);
        spec->sk.data = nullptr;
    }
    HcfFree(spec);
}

static HcfResult ConstructDHKeyCommParamsSpec(int32_t pLen, int32_t skLen, HcfDhCommParamsSpec **spec)
{
    HcfDhCommParamsSpec *dhCommSpec = nullptr;
    HcfResult res = HcfDhKeyUtilCreate(pLen, skLen, &dhCommSpec);
    if (res != HCF_SUCCESS) {
        return HCF_INVALID_PARAMS;
    }
    *spec = dhCommSpec;
    return HCF_SUCCESS;
}

static HcfResult ConstructDhKeyPairBigInt(HcfKeyPair *keyPair, HcfDhKeyPairParamsSpec *dhKeyPairSpec)
{
    HcfBigInteger retBigInt = { .data = nullptr, .len = 0 };
    HcfResult res = keyPair->pubKey->getAsyKeySpecBigInteger(keyPair->pubKey, DH_PK_BN, &retBigInt);
    if (res != HCF_SUCCESS) {
        return res;
    }
    dhKeyPairSpec->pk.data = retBigInt.data;
    dhKeyPairSpec->pk.len = retBigInt.len;

    res = keyPair->priKey->getAsyKeySpecBigInteger(keyPair->priKey, DH_SK_BN, &retBigInt);
    if (res != HCF_SUCCESS) {
        HcfFree(dhKeyPairSpec->pk.data);
        dhKeyPairSpec->pk.data = nullptr;
        dhKeyPairSpec->pk.len = 0;
        return res;
    }
    dhKeyPairSpec->sk.data = retBigInt.data;
    dhKeyPairSpec->sk.len = retBigInt.len;
    return HCF_SUCCESS;
}

static HcfResult ConstructDHKeyPairParamsCommonSpec(const std::string &algoName,
    HcfDhCommParamsSpec *dhCommParamsSpec, HcfAsyKeyParamsSpec **spec)
{
    HcfAsyKeyGenerator *generator = nullptr;
    HcfResult res = HcfAsyKeyGeneratorCreate(algoName.c_str(), &generator);
    if (res != HCF_SUCCESS) {
        return res;
    }

    HcfKeyPair *keyPair = nullptr;
    res = generator->generateKeyPair(generator, nullptr, &keyPair);
    if (res != HCF_SUCCESS) {
        HcfObjDestroy(generator);
        return res;
    }

    HcfDhKeyPairParamsSpec *dhKeyPairSpec =
        reinterpret_cast<HcfDhKeyPairParamsSpec*>(HcfMalloc(sizeof(HcfDhKeyPairParamsSpec), 0));
    if (dhKeyPairSpec != nullptr) {
        dhKeyPairSpec->base.base.algName = dhCommParamsSpec->base.algName;
        dhKeyPairSpec->base.base.specType = HCF_COMMON_PARAMS_SPEC;
        dhKeyPairSpec->base.p.data = dhCommParamsSpec->p.data;
        dhKeyPairSpec->base.p.len = dhCommParamsSpec->p.len;
        dhKeyPairSpec->base.g.data = dhCommParamsSpec->g.data;
        dhKeyPairSpec->base.g.len = dhCommParamsSpec->g.len;
        dhKeyPairSpec->base.length = dhCommParamsSpec->length;
        res = ConstructDhKeyPairBigInt(keyPair, dhKeyPairSpec);
        if (res != HCF_SUCCESS) {
            HcfObjDestroy(generator);
            HcfObjDestroy(keyPair);
            HcfFree(dhKeyPairSpec);
            return res;
        }
        *spec = reinterpret_cast<HcfAsyKeyParamsSpec *>(dhKeyPairSpec);
    }

    HcfObjDestroy(generator);
    HcfObjDestroy(keyPair);
    return HCF_SUCCESS;
}

static HcfResult ConstructDHKeyPairParamsSpec(const std::string &algoName,
    HcfDhCommParamsSpec *dhCommParamsSpec, HcfAsyKeyParamsSpec **spec)
{
    HcfAsyKeyGenerator *generator = nullptr;
    HcfResult res = HcfAsyKeyGeneratorCreate(algoName.c_str(), &generator);
    if (res != HCF_SUCCESS) {
        return res;
    }

    HcfKeyPair *keyPair = nullptr;
    res = generator->generateKeyPair(generator, nullptr, &keyPair);
    if (res != HCF_SUCCESS) {
        HcfObjDestroy(generator);
        return res;
    }

    HcfDhKeyPairParamsSpec *dhKeyPairSpec =
        reinterpret_cast<HcfDhKeyPairParamsSpec*>(HcfMalloc(sizeof(HcfDhKeyPairParamsSpec), 0));
    if (dhKeyPairSpec != nullptr) {
        dhKeyPairSpec->base.base.algName = dhCommParamsSpec->base.algName;
        dhKeyPairSpec->base.base.specType = HCF_KEY_PAIR_SPEC;
        dhKeyPairSpec->base.p.data = dhCommParamsSpec->p.data;
        dhKeyPairSpec->base.p.len = dhCommParamsSpec->p.len;
        dhKeyPairSpec->base.g.data = dhCommParamsSpec->g.data;
        dhKeyPairSpec->base.g.len = dhCommParamsSpec->g.len;
        dhKeyPairSpec->base.length = dhCommParamsSpec->length;
        res = ConstructDhKeyPairBigInt(keyPair, dhKeyPairSpec);
        if (res != HCF_SUCCESS) {
            HcfObjDestroy(generator);
            HcfObjDestroy(keyPair);
            HcfFree(dhKeyPairSpec);
            return res;
        }
        *spec = reinterpret_cast<HcfAsyKeyParamsSpec *>(dhKeyPairSpec);
    }

    HcfObjDestroy(generator);
    HcfObjDestroy(keyPair);
    return HCF_SUCCESS;
}

static HcfResult ConstructDHPubKeyParamsSpec(const string &algoName, HcfDhCommParamsSpec *comSpec,
    HcfAsyKeyParamsSpec **spec)
{
    if (comSpec == nullptr) {
        return HCF_INVALID_PARAMS;
    }
    HcfDhPubKeyParamsSpec *dhPubKeySpec = (HcfDhPubKeyParamsSpec*)HcfMalloc(sizeof(HcfDhPubKeyParamsSpec), 0);
    if (dhPubKeySpec == nullptr) {
        return HCF_ERR_MALLOC;
    }
    HcfAsyKeyGenerator *generator = nullptr;
    HcfResult res = HcfAsyKeyGeneratorCreate(algoName.c_str(), &generator);
    if (res != HCF_SUCCESS) {
        HcfFree(dhPubKeySpec);
        return res;
    }
    HcfKeyPair *keyPair = nullptr;
    res = generator->generateKeyPair(generator, nullptr, &keyPair);
    if (res != HCF_SUCCESS) {
        HcfObjDestroy(generator);
        HcfFree(dhPubKeySpec);
        return res;
    }
    HcfBigInteger retBigInt = { .data = nullptr, .len = 0 };
    dhPubKeySpec->base.base.algName = comSpec->base.algName;
    dhPubKeySpec->base.base.specType = HCF_PUBLIC_KEY_SPEC;
    dhPubKeySpec->base.g = comSpec->g;
    dhPubKeySpec->base.length = comSpec->length;
    dhPubKeySpec->base.p = comSpec->p;
    res = keyPair->pubKey->getAsyKeySpecBigInteger(keyPair->pubKey, DH_PK_BN, &retBigInt);
    if (res != HCF_SUCCESS) {
        HcfObjDestroy(generator);
        HcfObjDestroy(keyPair);
        HcfFree(dhPubKeySpec);
        return res;
    }
    dhPubKeySpec->pk.data = retBigInt.data;
    dhPubKeySpec->pk.len = retBigInt.len;

    *spec = reinterpret_cast<HcfAsyKeyParamsSpec *>(dhPubKeySpec);
    HcfObjDestroy(generator);
    HcfObjDestroy(keyPair);
    return HCF_SUCCESS;
}

static HcfResult ConstructDHPriKeyParamsSpec(const string &algoName, HcfDhCommParamsSpec *comSpec,
    HcfAsyKeyParamsSpec **spec)
{
    if (comSpec == nullptr) {
        return HCF_INVALID_PARAMS;
    }
    HcfDhPriKeyParamsSpec *dhPriKeySpec = (HcfDhPriKeyParamsSpec*)HcfMalloc(sizeof(HcfDhPriKeyParamsSpec), 0);
    if (dhPriKeySpec == nullptr) {
        return HCF_ERR_MALLOC;
    }
    HcfAsyKeyGenerator *generator = nullptr;
    HcfResult res = HcfAsyKeyGeneratorCreate(algoName.c_str(), &generator);
    if (res != HCF_SUCCESS) {
        HcfFree(dhPriKeySpec);
        return res;
    }

    HcfKeyPair *keyPair = nullptr;
    res = generator->generateKeyPair(generator, nullptr, &keyPair);
    if (res != HCF_SUCCESS) {
        HcfObjDestroy(generator);
        HcfFree(dhPriKeySpec);
        return res;
    }
    HcfBigInteger retBigInt = { .data = nullptr, .len = 0 };
    dhPriKeySpec->base.base.algName = comSpec->base.algName;
    dhPriKeySpec->base.base.specType = HCF_PRIVATE_KEY_SPEC;
    dhPriKeySpec->base.g = comSpec->g;
    dhPriKeySpec->base.length = comSpec->length;
    dhPriKeySpec->base.p = comSpec->p;
    res = keyPair->priKey->getAsyKeySpecBigInteger(keyPair->priKey, DH_SK_BN, &retBigInt);
    if (res != HCF_SUCCESS) {
        HcfObjDestroy(generator);
        HcfObjDestroy(keyPair);
        HcfFree(dhPriKeySpec);
        return res;
    }
    dhPriKeySpec->sk.data = retBigInt.data;
    dhPriKeySpec->sk.len = retBigInt.len;

    *spec = reinterpret_cast<HcfAsyKeyParamsSpec *>(dhPriKeySpec);
    HcfObjDestroy(generator);
    HcfObjDestroy(keyPair);
    return HCF_SUCCESS;
}

static HcfResult HcfDhKeyUtilCreateTest(const int pLen, const int skLen)
{
    HcfDhCommParamsSpec *returnCommonParamSpec = nullptr;
    HcfResult res = HcfDhKeyUtilCreate(pLen, skLen, &returnCommonParamSpec);
    if (res == HCF_SUCCESS) {
        FreeDhCommParamsSpec(returnCommonParamSpec);
        HcfFree(returnCommonParamSpec);
    }
    return res;
}

static void HcfDhKeyUtilErrBranch()
{
    FreeDhCommParamsSpec(nullptr);
    DestroyDhPubKeySpec(nullptr);
    DestroyDhPriKeySpec(nullptr);
    DestroyDhKeyPairSpec(nullptr);
    FreeEcPointMem(nullptr);
    DestroyAlg25519PubKeySpec(nullptr);
    DestroyAlg25519PriKeySpec(nullptr);
    DestroyAlg25519KeyPairSpec(nullptr);
    DestroySm2CipherTextSpec(nullptr);
}

static HcfResult generateKeyPairTest(HcfKeyPair **keyPair)
{
    HcfAsyKeyParamsSpec *paramSpec = nullptr;
    HcfResult res = ConstructDHKeyPairParamsSpec(g_dh1536AlgoName, g_dh1536CommSpec, &paramSpec);
    if (res != HCF_SUCCESS) {
        return res;
    }
    HcfAsyKeyGeneratorBySpec *returnObj = nullptr;
    res = HcfAsyKeyGeneratorBySpecCreate(paramSpec, &returnObj);
    if (res != HCF_SUCCESS) {
        return res;
    }
    res = returnObj->generateKeyPair(returnObj, keyPair);
    if (res != HCF_SUCCESS) {
        return res;
    }
    HcfObjDestroy(returnObj);
    DestroyTestDhKeyPairSpec(reinterpret_cast<HcfDhKeyPairParamsSpec *>(paramSpec));
    return HCF_SUCCESS;
}

void CryptoDHAsyKeyGeneratorBySpecTest::SetUpTestCase()
{
    HcfResult res = ConstructDHKeyCommParamsSpec(PLEN_DH1536, SKLEN_DH1024, &g_dh1536CommSpec);
    ASSERT_EQ(res, HCF_SUCCESS);
    res = ConstructDHKeyCommParamsSpec(PLEN_DH2048, SKLEN_DH1024, &g_dh2048CommSpec);
    ASSERT_EQ(res, HCF_SUCCESS);
    res = ConstructDHKeyCommParamsSpec(PLEN_DH3072, SKLEN_DH1024, &g_dh3072CommSpec);
    ASSERT_EQ(res, HCF_SUCCESS);
    res = ConstructDHKeyCommParamsSpec(PLEN_DH4096, SKLEN_DH1024, &g_dh4096CommSpec);
    ASSERT_EQ(res, HCF_SUCCESS);
    res = ConstructDHKeyCommParamsSpec(PLEN_DH6144, SKLEN_DH1024, &g_dh6144CommSpec);
    ASSERT_EQ(res, HCF_SUCCESS);
    res = ConstructDHKeyCommParamsSpec(PLEN_DH8192, SKLEN_DH1024, &g_dh8192CommSpec);
    ASSERT_EQ(res, HCF_SUCCESS);
    res = generateKeyPairTest(&g_dhKeyPair);
}

void CryptoDHAsyKeyGeneratorBySpecTest::TearDownTestCase()
{
    FreeDhCommParamsSpec(g_dh1536CommSpec);
    FreeDhCommParamsSpec(g_dh2048CommSpec);
    FreeDhCommParamsSpec(g_dh3072CommSpec);
    FreeDhCommParamsSpec(g_dh4096CommSpec);
    FreeDhCommParamsSpec(g_dh6144CommSpec);
    FreeDhCommParamsSpec(g_dh8192CommSpec);
    HcfObjDestroy(g_dhKeyPair);
}

HWTEST_F(CryptoDHAsyKeyGeneratorBySpecTest, CryptoDHAsyKeyGeneratorBySpecTest001_1, TestSize.Level0)
{
    HcfResult res = HcfDhKeyUtilCreateTest(PLEN_DH2048, SKLEN_DH1024);
    ASSERT_EQ(res, HCF_SUCCESS);
}

HWTEST_F(CryptoDHAsyKeyGeneratorBySpecTest, CryptoDHAsyKeyGeneratorBySpecTest001_2, TestSize.Level0)
{
    HcfResult res = HcfDhKeyUtilCreateTest(PLEN_DH3072, SKLEN_DH1024);
    ASSERT_EQ(res, HCF_SUCCESS);
}

HWTEST_F(CryptoDHAsyKeyGeneratorBySpecTest, CryptoDHAsyKeyGeneratorBySpecTest001_3, TestSize.Level0)
{
    HcfResult res = HcfDhKeyUtilCreateTest(PLEN_DH4096, SKLEN_DH1024);
    ASSERT_EQ(res, HCF_SUCCESS);
}

HWTEST_F(CryptoDHAsyKeyGeneratorBySpecTest, CryptoDHAsyKeyGeneratorBySpecTest001_4, TestSize.Level0)
{
    HcfResult res = HcfDhKeyUtilCreateTest(PLEN_DH6144, SKLEN_DH1024);
    ASSERT_EQ(res, HCF_SUCCESS);
}

HWTEST_F(CryptoDHAsyKeyGeneratorBySpecTest, CryptoDHAsyKeyGeneratorBySpecTest001_5, TestSize.Level0)
{
    HcfResult res = HcfDhKeyUtilCreateTest(PLEN_DH8192, SKLEN_DH1024);
    ASSERT_EQ(res, HCF_SUCCESS);
}

HWTEST_F(CryptoDHAsyKeyGeneratorBySpecTest, CryptoDHAsyKeyGeneratorBySpecTest001_6, TestSize.Level0)
{
    HcfResult res = HcfDhKeyUtilCreateTest(PLEN_DH8192, SKLEN_EQZERO);
    ASSERT_EQ(res, HCF_SUCCESS);
}

HWTEST_F(CryptoDHAsyKeyGeneratorBySpecTest, CryptoDHAsyKeyGeneratorBySpecTest002_1, TestSize.Level0)
{
    HcfAsyKeyParamsSpec *paramSpec = nullptr;
    HcfResult res = ConstructDHKeyPairParamsSpec(g_dh1536AlgoName, g_dh1536CommSpec, &paramSpec);
    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(paramSpec, nullptr);

    HcfAsyKeyGeneratorBySpec *returnObj = nullptr;
    res = HcfAsyKeyGeneratorBySpecCreate(paramSpec, &returnObj);
    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(returnObj, nullptr);

    HcfObjDestroy(returnObj);
    DestroyTestDhKeyPairSpec(reinterpret_cast<HcfDhKeyPairParamsSpec *>(paramSpec));
}

HWTEST_F(CryptoDHAsyKeyGeneratorBySpecTest, CryptoDHAsyKeyGeneratorBySpecTest002_2, TestSize.Level0)
{
    HcfAsyKeyParamsSpec *paramSpec = nullptr;
    HcfResult res = ConstructDHKeyPairParamsSpec(g_dh2048AlgoName, g_dh2048CommSpec, &paramSpec);
    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(paramSpec, nullptr);

    HcfAsyKeyGeneratorBySpec *returnObj = nullptr;
    res = HcfAsyKeyGeneratorBySpecCreate(paramSpec, &returnObj);
    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(returnObj, nullptr);

    HcfObjDestroy(returnObj);
    DestroyTestDhKeyPairSpec(reinterpret_cast<HcfDhKeyPairParamsSpec *>(paramSpec));
}

HWTEST_F(CryptoDHAsyKeyGeneratorBySpecTest, CryptoDHAsyKeyGeneratorBySpecTest002_3, TestSize.Level0)
{
    HcfAsyKeyParamsSpec *paramSpec = nullptr;
    HcfResult res = ConstructDHKeyPairParamsSpec(g_dh3072AlgoName, g_dh3072CommSpec, &paramSpec);
    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(paramSpec, nullptr);

    HcfAsyKeyGeneratorBySpec *returnObj = nullptr;
    res = HcfAsyKeyGeneratorBySpecCreate(paramSpec, &returnObj);
    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(returnObj, nullptr);

    HcfObjDestroy(returnObj);
    DestroyTestDhKeyPairSpec(reinterpret_cast<HcfDhKeyPairParamsSpec *>(paramSpec));
}

HWTEST_F(CryptoDHAsyKeyGeneratorBySpecTest, CryptoDHAsyKeyGeneratorBySpecTest002_4, TestSize.Level0)
{
    HcfAsyKeyParamsSpec *paramSpec = nullptr;
    HcfResult res = ConstructDHKeyPairParamsSpec(g_dh4096AlgoName, g_dh4096CommSpec, &paramSpec);
    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(paramSpec, nullptr);

    HcfAsyKeyGeneratorBySpec *returnObj = nullptr;
    res = HcfAsyKeyGeneratorBySpecCreate(paramSpec, &returnObj);
    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(returnObj, nullptr);

    HcfObjDestroy(returnObj);
    DestroyTestDhKeyPairSpec(reinterpret_cast<HcfDhKeyPairParamsSpec *>(paramSpec));
}

HWTEST_F(CryptoDHAsyKeyGeneratorBySpecTest, CryptoDHAsyKeyGeneratorBySpecTest002_5, TestSize.Level0)
{
    HcfAsyKeyParamsSpec *paramSpec = nullptr;
    HcfResult res = ConstructDHKeyPairParamsSpec(g_dh6144AlgoName, g_dh6144CommSpec, &paramSpec);
    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(paramSpec, nullptr);

    HcfAsyKeyGeneratorBySpec *returnObj = nullptr;
    res = HcfAsyKeyGeneratorBySpecCreate(paramSpec, &returnObj);
    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(returnObj, nullptr);

    HcfObjDestroy(returnObj);
    DestroyTestDhKeyPairSpec(reinterpret_cast<HcfDhKeyPairParamsSpec *>(paramSpec));
}

HWTEST_F(CryptoDHAsyKeyGeneratorBySpecTest, CryptoDHAsyKeyGeneratorBySpecTest002_6, TestSize.Level0)
{
    HcfAsyKeyParamsSpec *paramSpec = nullptr;
    HcfResult res = ConstructDHKeyPairParamsSpec(g_dh8192AlgoName, g_dh8192CommSpec, &paramSpec);
    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(paramSpec, nullptr);

    HcfAsyKeyGeneratorBySpec *returnObj = nullptr;
    res = HcfAsyKeyGeneratorBySpecCreate(paramSpec, &returnObj);
    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(returnObj, nullptr);

    HcfObjDestroy(returnObj);
    DestroyTestDhKeyPairSpec(reinterpret_cast<HcfDhKeyPairParamsSpec *>(paramSpec));
}

HWTEST_F(CryptoDHAsyKeyGeneratorBySpecTest, CryptoDHAsyKeyGeneratorBySpecTest003, TestSize.Level0)
{
    HcfAsyKeyParamsSpec *paramSpec = nullptr;
    HcfResult res = ConstructDHKeyPairParamsSpec(g_dh1536AlgoName, g_dh1536CommSpec, &paramSpec);
    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(paramSpec, nullptr);

    HcfAsyKeyGeneratorBySpec *returnObj = nullptr;
    res = HcfAsyKeyGeneratorBySpecCreate(paramSpec, &returnObj);
    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(returnObj, nullptr);

    const char *className = returnObj->base.getClass();
    ASSERT_NE(className, nullptr);

    HcfObjDestroy(returnObj);
    DestroyTestDhKeyPairSpec(reinterpret_cast<HcfDhKeyPairParamsSpec *>(paramSpec));
}

HWTEST_F(CryptoDHAsyKeyGeneratorBySpecTest, CryptoDHAsyKeyGeneratorBySpecTest004, TestSize.Level0)
{
    HcfAsyKeyParamsSpec *paramSpec = nullptr;
    HcfResult res = ConstructDHKeyPairParamsSpec(g_dh1536AlgoName, g_dh1536CommSpec, &paramSpec);
    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(paramSpec, nullptr);

    HcfAsyKeyGeneratorBySpec *returnObj = nullptr;
    res = HcfAsyKeyGeneratorBySpecCreate(paramSpec, &returnObj);
    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(returnObj, nullptr);

    returnObj->base.destroy(&(returnObj->base));
    DestroyTestDhKeyPairSpec(reinterpret_cast<HcfDhKeyPairParamsSpec *>(paramSpec));
}

HWTEST_F(CryptoDHAsyKeyGeneratorBySpecTest, CryptoDHAsyKeyGeneratorBySpecTest005, TestSize.Level0)
{
    HcfAsyKeyParamsSpec *paramSpec = nullptr;
    HcfResult res = ConstructDHKeyPairParamsSpec(g_dh1536AlgoName, g_dh1536CommSpec, &paramSpec);
    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(paramSpec, nullptr);

    HcfAsyKeyGeneratorBySpec *returnObj = nullptr;
    res = HcfAsyKeyGeneratorBySpecCreate(paramSpec, &returnObj);
    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(returnObj, nullptr);

    const char * algName = returnObj->getAlgName(returnObj);
    ASSERT_EQ(algName, g_dhAlgoName);

    HcfObjDestroy(returnObj);
    DestroyTestDhKeyPairSpec(reinterpret_cast<HcfDhKeyPairParamsSpec *>(paramSpec));
}

HWTEST_F(CryptoDHAsyKeyGeneratorBySpecTest, CryptoDHAsyKeyGeneratorBySpecTest006, TestSize.Level0)
{
    HcfKeyPair *keyPair = nullptr;
    HcfResult res = generateKeyPairTest(&keyPair);
    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(keyPair, nullptr);

    HcfObjDestroy(keyPair);
}

HWTEST_F(CryptoDHAsyKeyGeneratorBySpecTest, CryptoDHAsyKeyGeneratorBySpecTest007, TestSize.Level0)
{
    const char *className = g_dhKeyPair->base.getClass();
    ASSERT_NE(className, nullptr);
}

HWTEST_F(CryptoDHAsyKeyGeneratorBySpecTest, CryptoDHAsyKeyGeneratorBySpecTest008, TestSize.Level0)
{
    HcfKeyPair *keyPair = nullptr;
    HcfResult res = generateKeyPairTest(&keyPair);
    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(keyPair, nullptr);

    keyPair->base.destroy(&(keyPair->base));
}

HWTEST_F(CryptoDHAsyKeyGeneratorBySpecTest, CryptoDHAsyKeyGeneratorBySpecTest009, TestSize.Level0)
{
    const char *className = g_dhKeyPair->pubKey->base.base.getClass();
    ASSERT_NE(className, nullptr);
}

HWTEST_F(CryptoDHAsyKeyGeneratorBySpecTest, CryptoDHAsyKeyGeneratorBySpecTest010, TestSize.Level0)
{
    HcfKeyPair *keyPair = nullptr;
    HcfResult res = generateKeyPairTest(&keyPair);
    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(keyPair, nullptr);

    keyPair->pubKey->base.base.destroy(&(keyPair->pubKey->base.base));
    keyPair->pubKey = nullptr;

    HcfObjDestroy(keyPair);
}

HWTEST_F(CryptoDHAsyKeyGeneratorBySpecTest, CryptoDHAsyKeyGeneratorBySpecTest011, TestSize.Level0)
{
    const char *algorithmName = g_dhKeyPair->pubKey->base.getAlgorithm(&(g_dhKeyPair->pubKey->base));
    ASSERT_EQ(algorithmName, g_dhAlgoName);

    HcfBlob blob = { .data = nullptr, .len = 0 };
    HcfResult res = g_dhKeyPair->pubKey->base.getEncoded(&(g_dhKeyPair->pubKey->base), &blob);
    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(blob.data, nullptr);
    ASSERT_NE(blob.len, 0);

    HcfFree(blob.data);
    const char *formatName = g_dhKeyPair->pubKey->base.getFormat(&(g_dhKeyPair->pubKey->base));
    ASSERT_EQ(formatName, g_dhpubkeyformatName);
}

HWTEST_F(CryptoDHAsyKeyGeneratorBySpecTest, CryptoDHAsyKeyGeneratorBySpecTest012, TestSize.Level0)
{
    const char *className = g_dhKeyPair->priKey->base.base.getClass();
    ASSERT_NE(className, nullptr);
}

HWTEST_F(CryptoDHAsyKeyGeneratorBySpecTest, CryptoDHAsyKeyGeneratorBySpecTest013, TestSize.Level0)
{
    HcfKeyPair *keyPair = nullptr;
    HcfResult res = generateKeyPairTest(&keyPair);
    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(keyPair, nullptr);

    keyPair->priKey->base.base.destroy(&(keyPair->priKey->base.base));
    keyPair->priKey = nullptr;

    HcfObjDestroy(keyPair);
}

HWTEST_F(CryptoDHAsyKeyGeneratorBySpecTest, CryptoDHAsyKeyGeneratorBySpecTest014, TestSize.Level0)
{
    const char *algorithmName = g_dhKeyPair->priKey->base.getAlgorithm(&(g_dhKeyPair->priKey->base));
    ASSERT_EQ(algorithmName, g_dhAlgoName);

    HcfBlob blob = { .data = nullptr, .len = 0 };
    HcfResult res = g_dhKeyPair->priKey->base.getEncoded(&(g_dhKeyPair->priKey->base), &blob);
    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(blob.data, nullptr);
    ASSERT_NE(blob.len, 0);
    HcfFree(blob.data);
    const char *formatName = g_dhKeyPair->priKey->base.getFormat(&(g_dhKeyPair->priKey->base));
    ASSERT_EQ(formatName, g_dhprikeyformatName);
}

HWTEST_F(CryptoDHAsyKeyGeneratorBySpecTest, CryptoDHAsyKeyGeneratorBySpecTest015, TestSize.Level0)
{
    HcfKeyPair *keyPair = nullptr;
    HcfResult res = generateKeyPairTest(&keyPair);
    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(keyPair, nullptr);

    keyPair->priKey->clearMem(keyPair->priKey);
    HcfBlob blob = { .data = nullptr, .len = 0 };
    res = keyPair->priKey->base.getEncoded(&(keyPair->priKey->base), &blob);
    ASSERT_EQ(res, HCF_ERR_CRYPTO_OPERATION);
    ASSERT_EQ(blob.data, nullptr);
    ASSERT_EQ(blob.len, 0);
    HcfFree(blob.data);
    HcfObjDestroy(keyPair);
}

HWTEST_F(CryptoDHAsyKeyGeneratorBySpecTest, CryptoDHAsyKeyGeneratorBySpecTest016, TestSize.Level0)
{
    HcfAsyKeyParamsSpec *paramSpec = nullptr;
    HcfResult res = ConstructDHPubKeyParamsSpec(g_dh1536AlgoName, g_dh1536CommSpec, &paramSpec);
    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(paramSpec, nullptr);

    HcfAsyKeyGeneratorBySpec *returnObj = nullptr;
    res = HcfAsyKeyGeneratorBySpecCreate(paramSpec, &returnObj);
    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(returnObj, nullptr);

    HcfPubKey *pubKey = nullptr;
    res = returnObj->generatePubKey(returnObj, &pubKey);
    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(pubKey, nullptr);

    HcfBigInteger returnBigInteger = { .data = nullptr, .len = 0 };
    res = pubKey->getAsyKeySpecBigInteger(pubKey, DH_P_BN, &returnBigInteger);
    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(returnBigInteger.data, nullptr);
    ASSERT_NE(returnBigInteger.len, 0);
    HcfFree(returnBigInteger.data);

    res = pubKey->getAsyKeySpecBigInteger(pubKey, DH_G_BN, &returnBigInteger);
    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(returnBigInteger.data, nullptr);
    ASSERT_NE(returnBigInteger.len, 0);
    HcfFree(returnBigInteger.data);

    res = pubKey->getAsyKeySpecBigInteger(pubKey, DH_PK_BN, &returnBigInteger);
    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(returnBigInteger.data, nullptr);
    ASSERT_NE(returnBigInteger.len, 0);
    HcfFree(returnBigInteger.data);
    int32_t returnInt = 0;
    res = pubKey->getAsyKeySpecInt(pubKey, DH_L_NUM, &returnInt);
    ASSERT_EQ(res, HCF_NOT_SUPPORT);
    ASSERT_EQ(returnInt, 0);

    HcfObjDestroy(pubKey);
    HcfObjDestroy(returnObj);
    DestroyTestDhPubKeySpec(reinterpret_cast<HcfDhPubKeyParamsSpec *>(paramSpec));
}

HWTEST_F(CryptoDHAsyKeyGeneratorBySpecTest, CryptoDHAsyKeyGeneratorBySpecTest017, TestSize.Level0)
{
    HcfAsyKeyParamsSpec *paramSpec = nullptr;
    HcfResult res = ConstructDHPriKeyParamsSpec(g_dh1536AlgoName, g_dh1536CommSpec, &paramSpec);
    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(paramSpec, nullptr);

    HcfAsyKeyGeneratorBySpec *returnObj = nullptr;
    res = HcfAsyKeyGeneratorBySpecCreate(paramSpec, &returnObj);
    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(returnObj, nullptr);

    HcfPriKey *priKey = nullptr;
    res = returnObj->generatePriKey(returnObj, &priKey);
    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(priKey, nullptr);

    HcfBigInteger returnBigInteger = { .data = nullptr, .len = 0 };
    res = priKey->getAsyKeySpecBigInteger(priKey, DH_P_BN, &returnBigInteger);
    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(returnBigInteger.data, nullptr);
    ASSERT_NE(returnBigInteger.len, 0);
    HcfFree(returnBigInteger.data);

    res = priKey->getAsyKeySpecBigInteger(priKey, DH_G_BN, &returnBigInteger);
    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(returnBigInteger.data, nullptr);
    ASSERT_NE(returnBigInteger.len, 0);
    HcfFree(returnBigInteger.data);

    res = priKey->getAsyKeySpecBigInteger(priKey, DH_SK_BN, &returnBigInteger);
    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(returnBigInteger.data, nullptr);
    ASSERT_NE(returnBigInteger.len, 0);
    HcfFree(returnBigInteger.data);
    int32_t returnInt = 0;
    res = priKey->getAsyKeySpecInt(priKey, DH_L_NUM, &returnInt);
    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(returnInt, 0);

    HcfObjDestroy(priKey);
    HcfObjDestroy(returnObj);
    DestroyTestDhPriKeySpec(reinterpret_cast<HcfDhPriKeyParamsSpec *>(paramSpec));
}

HWTEST_F(CryptoDHAsyKeyGeneratorBySpecTest, CryptoDHAsyKeyGeneratorBySpecTest018, TestSize.Level0)
{
    HcfAsyKeyGenParams params = {
        .algo = HCF_ALG_DH,
        .bits = HCF_OPENSSL_DH_MODP_1536,
        .primes = HCF_OPENSSL_PRIMES_2,
    };

    HcfAsyKeyGeneratorSpi *returnSpi = nullptr;
    HcfResult res = HcfAsyKeyGeneratorSpiDhCreate(&params, &returnSpi);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(returnSpi, nullptr);

    HcfObjDestroy(returnSpi);
}

HWTEST_F(CryptoDHAsyKeyGeneratorBySpecTest, CryptoDHAsyKeyGeneratorBySpecTest019, TestSize.Level0)
{
    HcfAsyKeyGenParams params = {
        .algo = HCF_ALG_DH,
        .bits = HCF_OPENSSL_DH_MODP_1536,
        .primes = HCF_OPENSSL_PRIMES_2,
    };

    HcfAsyKeyGeneratorSpi *returnSpi = nullptr;
    HcfResult res = HcfAsyKeyGeneratorSpiDhCreate(&params, &returnSpi);
    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(returnSpi, nullptr);

    HcfAsyKeyParamsSpec *paramSpec = nullptr;
    res = ConstructDHKeyPairParamsSpec(g_dh1536AlgoName, g_dh1536CommSpec, &paramSpec);
    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(paramSpec, nullptr);

    HcfKeyPair *keyPair = nullptr;
    res = returnSpi->engineGenerateKeyPairBySpec(returnSpi, paramSpec, &keyPair);
    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(keyPair, nullptr);

    HcfObjDestroy(returnSpi);
    HcfObjDestroy(keyPair);
    DestroyTestDhKeyPairSpec(reinterpret_cast<HcfDhKeyPairParamsSpec *>(paramSpec));
}

HWTEST_F(CryptoDHAsyKeyGeneratorBySpecTest, CryptoDHAsyKeyGeneratorBySpecTest020, TestSize.Level0)
{
    HcfAsyKeyGenParams params = {
        .algo = HCF_ALG_DH,
        .bits = HCF_OPENSSL_DH_MODP_1536,
        .primes = HCF_OPENSSL_PRIMES_2,
    };

    HcfAsyKeyGeneratorSpi *returnSpi = nullptr;
    HcfResult res = HcfAsyKeyGeneratorSpiDhCreate(&params, &returnSpi);
    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(returnSpi, nullptr);

    HcfAsyKeyParamsSpec *paramSpec = nullptr;
    res = ConstructDHPubKeyParamsSpec(g_dh1536AlgoName, g_dh1536CommSpec, &paramSpec);
    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(paramSpec, nullptr);

    HcfPubKey *pubKey = nullptr;
    res = returnSpi->engineGeneratePubKeyBySpec(returnSpi, paramSpec, &pubKey);
    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(pubKey, nullptr);

    HcfObjDestroy(returnSpi);
    HcfObjDestroy(pubKey);
    DestroyTestDhPubKeySpec(reinterpret_cast<HcfDhPubKeyParamsSpec *>(paramSpec));
}

HWTEST_F(CryptoDHAsyKeyGeneratorBySpecTest, CryptoDHAsyKeyGeneratorBySpecTest021, TestSize.Level0)
{
    HcfAsyKeyGenParams params = {
        .algo = HCF_ALG_DH,
        .bits = HCF_OPENSSL_DH_MODP_1536,
        .primes = HCF_OPENSSL_PRIMES_2,
    };

    HcfAsyKeyGeneratorSpi *returnSpi = nullptr;
    HcfResult res = HcfAsyKeyGeneratorSpiDhCreate(&params, &returnSpi);
    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(returnSpi, nullptr);

    HcfAsyKeyParamsSpec *paramSpec = nullptr;
    res = ConstructDHPriKeyParamsSpec(g_dh1536AlgoName, g_dh1536CommSpec, &paramSpec);
    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(paramSpec, nullptr);

    HcfPriKey *priKey = nullptr;
    res = returnSpi->engineGeneratePriKeyBySpec(returnSpi, paramSpec, &priKey);
    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(priKey, nullptr);

    HcfObjDestroy(returnSpi);
    HcfObjDestroy(priKey);
    DestroyTestDhPriKeySpec(reinterpret_cast<HcfDhPriKeyParamsSpec *>(paramSpec));
}

HWTEST_F(CryptoDHAsyKeyGeneratorBySpecTest, CryptoDHAsyKeyGeneratorBySpecTest022, TestSize.Level0)
{
    HcfAsyKeyParamsSpec *paramSpec = nullptr;
    HcfResult res = ConstructDHKeyPairParamsSpec(g_dh1536AlgoName, g_dh1536CommSpec, &paramSpec);
    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(paramSpec, nullptr);

    HcfAsyKeyGeneratorBySpec *returnObj = nullptr;
    res = HcfAsyKeyGeneratorBySpecCreate(paramSpec, &returnObj);
    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(returnObj, nullptr);

    const char *algName1 = returnObj->getAlgName(nullptr);
    ASSERT_NE(algName1, g_dhAlgoName.data());

    const char *algName2 = returnObj->getAlgName((HcfAsyKeyGeneratorBySpec *)&g_obj);
    ASSERT_NE(algName2, g_dhAlgoName.data());

    HcfObjDestroy(returnObj);
    DestroyTestDhKeyPairSpec(reinterpret_cast<HcfDhKeyPairParamsSpec *>(paramSpec));
}

HWTEST_F(CryptoDHAsyKeyGeneratorBySpecTest, CryptoDHAsyKeyGeneratorBySpecTest023, TestSize.Level0)
{
    HcfAsyKeyParamsSpec *paramSpec = nullptr;
    HcfResult res = ConstructDHKeyPairParamsSpec(g_dh1536AlgoName, g_dh1536CommSpec, &paramSpec);
    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(paramSpec, nullptr);

    HcfAsyKeyGeneratorBySpec *returnObj = nullptr;
    res = HcfAsyKeyGeneratorBySpecCreate(paramSpec, &returnObj);
    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(returnObj, nullptr);

    HcfKeyPair *keyPair = nullptr;
    res = returnObj->generateKeyPair(nullptr, &keyPair);
    ASSERT_EQ(res, HCF_INVALID_PARAMS);
    ASSERT_EQ(keyPair, nullptr);

    res = returnObj->generateKeyPair((HcfAsyKeyGeneratorBySpec *)&g_obj, &keyPair);
    ASSERT_EQ(res, HCF_INVALID_PARAMS);
    ASSERT_EQ(keyPair, nullptr);

    HcfObjDestroy(returnObj);
    HcfObjDestroy(keyPair);
    DestroyTestDhKeyPairSpec(reinterpret_cast<HcfDhKeyPairParamsSpec *>(paramSpec));
}

HWTEST_F(CryptoDHAsyKeyGeneratorBySpecTest, CryptoDHAsyKeyGeneratorBySpecTest024, TestSize.Level0)
{
    const char *algorithmName = g_dhKeyPair->pubKey->base.getAlgorithm(nullptr);
    ASSERT_EQ(algorithmName, nullptr);

    const char *algorithmName1 = g_dhKeyPair->pubKey->base.getAlgorithm((HcfKey *)&g_obj);
    ASSERT_EQ(algorithmName1, nullptr);
}

HWTEST_F(CryptoDHAsyKeyGeneratorBySpecTest, CryptoDHAsyKeyGeneratorBySpecTest025, TestSize.Level0)
{
    HcfBlob blob = { .data = nullptr, .len = 0 };
    HcfResult res = g_dhKeyPair->pubKey->base.getEncoded(nullptr, &blob);
    ASSERT_EQ(res, HCF_INVALID_PARAMS);
    ASSERT_EQ(blob.data, nullptr);
    ASSERT_EQ(blob.len, 0);

    res = g_dhKeyPair->pubKey->base.getEncoded(&(g_dhKeyPair->pubKey->base), nullptr);
    ASSERT_EQ(res, HCF_INVALID_PARAMS);

    res = g_dhKeyPair->pubKey->base.getEncoded((HcfKey *)&g_obj, &blob);
    ASSERT_EQ(res, HCF_INVALID_PARAMS);
    ASSERT_EQ(blob.data, nullptr);
    ASSERT_EQ(blob.len, 0);
    HcfFree(blob.data);
}

HWTEST_F(CryptoDHAsyKeyGeneratorBySpecTest, CryptoDHAsyKeyGeneratorBySpecTest026, TestSize.Level0)
{
    const char *formatName = g_dhKeyPair->pubKey->base.getFormat(nullptr);
    ASSERT_EQ(formatName, nullptr);

    const char *formatName1 = g_dhKeyPair->pubKey->base.getFormat((HcfKey *)&g_obj);
    ASSERT_EQ(formatName1, nullptr);
}

HWTEST_F(CryptoDHAsyKeyGeneratorBySpecTest, CryptoDHAsyKeyGeneratorBySpecTest027, TestSize.Level0)
{
    const char *algorithmName = g_dhKeyPair->priKey->base.getAlgorithm(nullptr);
    ASSERT_EQ(algorithmName, nullptr);

    const char *algorithmName1 = g_dhKeyPair->priKey->base.getAlgorithm((HcfKey *)&g_obj);
    ASSERT_EQ(algorithmName1, nullptr);
}

HWTEST_F(CryptoDHAsyKeyGeneratorBySpecTest, CryptoDHAsyKeyGeneratorBySpecTest028, TestSize.Level0)
{
    HcfBlob blob = { .data = nullptr, .len = 0 };
    HcfResult res = g_dhKeyPair->priKey->base.getEncoded(nullptr, &blob);
    ASSERT_EQ(res, HCF_INVALID_PARAMS);
    ASSERT_EQ(blob.data, nullptr);
    ASSERT_EQ(blob.len, 0);

    res = g_dhKeyPair->priKey->base.getEncoded(&(g_dhKeyPair->priKey->base), nullptr);
    ASSERT_EQ(res, HCF_INVALID_PARAMS);

    res = g_dhKeyPair->priKey->base.getEncoded((HcfKey *)&g_obj, &blob);
    ASSERT_EQ(res, HCF_INVALID_PARAMS);
    ASSERT_EQ(blob.data, nullptr);
    ASSERT_EQ(blob.len, 0);
    HcfFree(blob.data);
}

HWTEST_F(CryptoDHAsyKeyGeneratorBySpecTest, CryptoDHAsyKeyGeneratorBySpecTest029, TestSize.Level0)
{
    const char *formatName = g_dhKeyPair->priKey->base.getFormat(nullptr);
    ASSERT_EQ(formatName, nullptr);

    const char *formatName1 = g_dhKeyPair->priKey->base.getFormat((HcfKey *)&g_obj);
    ASSERT_EQ(formatName1, nullptr);
}

HWTEST_F(CryptoDHAsyKeyGeneratorBySpecTest, CryptoDHAsyKeyGeneratorBySpecTest030, TestSize.Level0)
{
    HcfAsyKeyParamsSpec *paramSpec = nullptr;
    HcfResult res = ConstructDHPubKeyParamsSpec(g_dh1536AlgoName, g_dh1536CommSpec, &paramSpec);
    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(paramSpec, nullptr);

    HcfAsyKeyGeneratorBySpec *returnObj = nullptr;
    res = HcfAsyKeyGeneratorBySpecCreate(paramSpec, &returnObj);
    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(returnObj, nullptr);

    HcfPubKey *pubKey = nullptr;
    res = returnObj->generatePubKey(returnObj, &pubKey);
    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(pubKey, nullptr);

    res = pubKey->getAsyKeySpecBigInteger(pubKey, DH_PK_BN, nullptr);
    ASSERT_EQ(res, HCF_INVALID_PARAMS);

    HcfBigInteger returnBigInteger = { .data = nullptr, .len = 0 };
    res = pubKey->getAsyKeySpecBigInteger(pubKey, X25519_PK_BN, &returnBigInteger);
    ASSERT_EQ(res, HCF_INVALID_PARAMS);
    ASSERT_EQ(returnBigInteger.data, nullptr);
    ASSERT_EQ(returnBigInteger.len, 0);

    res = pubKey->getAsyKeySpecBigInteger((HcfPubKey *)&g_obj, DH_PK_BN, &returnBigInteger);
    ASSERT_EQ(res, HCF_INVALID_PARAMS);
    ASSERT_EQ(returnBigInteger.data, nullptr);
    ASSERT_EQ(returnBigInteger.len, 0);
    HcfFree(returnBigInteger.data);
    res = pubKey->getAsyKeySpecInt(pubKey, DH_L_NUM, nullptr);
    ASSERT_EQ(res, HCF_NOT_SUPPORT);

    int32_t returnInt = 0;
    res = pubKey->getAsyKeySpecInt(pubKey, X25519_PK_BN, &returnInt);
    ASSERT_EQ(res, HCF_NOT_SUPPORT);
    ASSERT_EQ(returnInt, 0);

    res = pubKey->getAsyKeySpecInt((HcfPubKey *)&g_obj, DH_L_NUM, &returnInt);
    ASSERT_EQ(res, HCF_NOT_SUPPORT);
    ASSERT_EQ(returnInt, 0);

    char *returnString = nullptr;
    res = pubKey->getAsyKeySpecString(pubKey, ED25519_SK_BN, &returnString);
    ASSERT_EQ(res, HCF_NOT_SUPPORT);
    ASSERT_EQ(returnString, nullptr);

    res = pubKey->getAsyKeySpecString(pubKey, ECC_CURVE_NAME_STR, &returnString);
    ASSERT_EQ(res, HCF_NOT_SUPPORT);
    ASSERT_EQ(returnString, nullptr);

    HcfObjDestroy(pubKey);
    HcfObjDestroy(returnObj);
    DestroyTestDhPubKeySpec(reinterpret_cast<HcfDhPubKeyParamsSpec *>(paramSpec));
}

HWTEST_F(CryptoDHAsyKeyGeneratorBySpecTest, CryptoDHAsyKeyGeneratorBySpecTest031, TestSize.Level0)
{
    HcfAsyKeyParamsSpec *paramSpec = nullptr;
    HcfResult res = ConstructDHPriKeyParamsSpec(g_dh1536AlgoName, g_dh1536CommSpec, &paramSpec);
    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(paramSpec, nullptr);

    HcfAsyKeyGeneratorBySpec *returnObj = nullptr;
    res = HcfAsyKeyGeneratorBySpecCreate(paramSpec, &returnObj);
    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(returnObj, nullptr);

    HcfPriKey *priKey = nullptr;
    res = returnObj->generatePriKey(returnObj, &priKey);
    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(priKey, nullptr);

    res = priKey->getAsyKeySpecBigInteger(priKey, DH_PK_BN, nullptr);
    ASSERT_EQ(res, HCF_INVALID_PARAMS);

    HcfBigInteger returnBigInteger = { .data = nullptr, .len = 0 };
    res = priKey->getAsyKeySpecBigInteger(priKey, X25519_PK_BN, &returnBigInteger);
    ASSERT_EQ(res, HCF_INVALID_PARAMS);
    ASSERT_EQ(returnBigInteger.data, nullptr);
    ASSERT_EQ(returnBigInteger.len, 0);

    res = priKey->getAsyKeySpecBigInteger((HcfPriKey *)&g_obj, DH_PK_BN, &returnBigInteger);
    ASSERT_EQ(res, HCF_INVALID_PARAMS);
    ASSERT_EQ(returnBigInteger.data, nullptr);
    ASSERT_EQ(returnBigInteger.len, 0);
    HcfFree(returnBigInteger.data);
    res = priKey->getAsyKeySpecInt(priKey, DH_L_NUM, nullptr);
    ASSERT_EQ(res, HCF_INVALID_PARAMS);

    int32_t returnInt = 0;
    res = priKey->getAsyKeySpecInt(priKey, X25519_PK_BN, &returnInt);
    ASSERT_EQ(res, HCF_INVALID_PARAMS);
    ASSERT_EQ(returnInt, 0);

    res = priKey->getAsyKeySpecInt((HcfPriKey *)&g_obj, DH_L_NUM, &returnInt);
    ASSERT_EQ(res, HCF_INVALID_PARAMS);
    ASSERT_EQ(returnInt, 0);

    char *returnString = nullptr;
    res = priKey->getAsyKeySpecString(priKey, ED25519_SK_BN, &returnString);
    ASSERT_EQ(res, HCF_NOT_SUPPORT);
    ASSERT_EQ(returnString, nullptr);

    res = priKey->getAsyKeySpecString(priKey, ECC_CURVE_NAME_STR, &returnString);
    ASSERT_EQ(res, HCF_NOT_SUPPORT);
    ASSERT_EQ(returnString, nullptr);

    HcfObjDestroy(priKey);
    HcfObjDestroy(returnObj);
    DestroyTestDhPriKeySpec(reinterpret_cast<HcfDhPriKeyParamsSpec *>(paramSpec));
}

HWTEST_F(CryptoDHAsyKeyGeneratorBySpecTest, CryptoDHAsyKeyGeneratorBySpecTest032, TestSize.Level0)
{
    HcfDhCommParamsSpec *returnCommonParamSpec = nullptr;
    HcfResult res = HcfDhKeyUtilCreate(INT_MAX, SKLEN_DH1024, &returnCommonParamSpec);
    ASSERT_EQ(res, HCF_ERR_MALLOC);

    res = HcfDhKeyUtilCreate(PLEN_LTSK, SKLEN_DH1024, &returnCommonParamSpec);
    ASSERT_EQ(res, HCF_INVALID_PARAMS);

    res = HcfDhKeyUtilCreate(INT_MAX, SKLEN_DH1024, nullptr);
    ASSERT_EQ(res, HCF_INVALID_PARAMS);
}

HWTEST_F(CryptoDHAsyKeyGeneratorBySpecTest, CryptoDHAsyKeyGeneratorBySpecTest033, TestSize.Level0)
{
    HcfAsyKeyParamsSpec *paramSpec = nullptr;
    HcfResult res = ConstructDHPubKeyParamsSpec(g_dh1536AlgoName, g_dh1536CommSpec, &paramSpec);
    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(paramSpec, nullptr);

    HcfAsyKeyGeneratorBySpec *returnObj = nullptr;
    res = HcfAsyKeyGeneratorBySpecCreate(paramSpec, &returnObj);
    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(returnObj, nullptr);

    HcfKeyPair *keyPair = nullptr;
    res = returnObj->generateKeyPair(returnObj, &keyPair);
    ASSERT_EQ(res, HCF_INVALID_PARAMS);
    ASSERT_EQ(keyPair, nullptr);

    HcfPriKey *priKey = nullptr;
    res = returnObj->generatePriKey(returnObj, &priKey);
    ASSERT_EQ(res, HCF_INVALID_PARAMS);
    ASSERT_EQ(priKey, nullptr);

    HcfObjDestroy(returnObj);
    HcfObjDestroy(keyPair);
    DestroyTestDhPubKeySpec(reinterpret_cast<HcfDhPubKeyParamsSpec *>(paramSpec));
}

HWTEST_F(CryptoDHAsyKeyGeneratorBySpecTest, CryptoDHAsyKeyGeneratorBySpecTest034, TestSize.Level0)
{
    HcfAsyKeyParamsSpec *paramSpec = nullptr;
    HcfResult res = ConstructDHPriKeyParamsSpec(g_dh1536AlgoName, g_dh1536CommSpec, &paramSpec);
    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(paramSpec, nullptr);

    HcfAsyKeyGeneratorBySpec *returnObj = nullptr;
    res = HcfAsyKeyGeneratorBySpecCreate(paramSpec, &returnObj);
    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(returnObj, nullptr);

    HcfKeyPair *keyPair = nullptr;
    res = returnObj->generateKeyPair(returnObj, &keyPair);
    ASSERT_EQ(res, HCF_INVALID_PARAMS);
    ASSERT_EQ(keyPair, nullptr);

    HcfPubKey *pubKey = nullptr;
    res = returnObj->generatePubKey(returnObj, &pubKey);
    ASSERT_EQ(res, HCF_INVALID_PARAMS);
    ASSERT_EQ(pubKey, nullptr);

    HcfObjDestroy(returnObj);
    HcfObjDestroy(keyPair);
    DestroyTestDhPriKeySpec(reinterpret_cast<HcfDhPriKeyParamsSpec *>(paramSpec));
}

HWTEST_F(CryptoDHAsyKeyGeneratorBySpecTest, CryptoDHAsyKeyGeneratorBySpecTest035, TestSize.Level0)
{
    HcfAsyKeyGenParams params = {
        .algo = HCF_ALG_DH,
        .bits = HCF_OPENSSL_DH_MODP_1536,
        .primes = HCF_OPENSSL_PRIMES_2,
    };

    HcfAsyKeyGeneratorSpi *returnSpi = nullptr;
    HcfResult res = HcfAsyKeyGeneratorSpiDhCreate(&params, &returnSpi);
    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(returnSpi, nullptr);

    HcfAsyKeyParamsSpec *paramSpec = nullptr;
    res = ConstructDHKeyPairParamsCommonSpec(g_dh1536AlgoName, g_dh1536CommSpec, &paramSpec);
    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(paramSpec, nullptr);

    HcfKeyPair *keyPair = nullptr;
    res = returnSpi->engineGenerateKeyPairBySpec(returnSpi, paramSpec, &keyPair);
    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(keyPair, nullptr);

    HcfObjDestroy(returnSpi);
    HcfObjDestroy(keyPair);
    DestroyTestDhKeyPairSpec(reinterpret_cast<HcfDhKeyPairParamsSpec *>(paramSpec));
}

HWTEST_F(CryptoDHAsyKeyGeneratorBySpecTest, CryptoDHAsyKeyGeneratorBySpecTest036, TestSize.Level0)
{
    HcfAsyKeyGenParams params = {
        .algo = HCF_ALG_DH,
        .bits = HCF_OPENSSL_DH_MODP_1536,
        .primes = HCF_OPENSSL_PRIMES_2,
    };

    HcfAsyKeyGeneratorSpi *returnSpi = nullptr;
    HcfResult res = HcfAsyKeyGeneratorSpiDhCreate(&params, &returnSpi);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(returnSpi, nullptr);

    returnSpi->base.destroy(nullptr);
    returnSpi->base.destroy(&g_obj);
    HcfObjDestroy(returnSpi);
}

HWTEST_F(CryptoDHAsyKeyGeneratorBySpecTest, CryptoDHAsyKeyGeneratorBySpecTest037, TestSize.Level0)
{
    HcfAsyKeyGenParams params = {
        .algo = HCF_ALG_DH,
        .bits = HCF_OPENSSL_DH_MODP_1536,
        .primes = HCF_OPENSSL_PRIMES_2,
    };

    HcfAsyKeyGeneratorSpi *returnSpi = nullptr;
    HcfResult res = HcfAsyKeyGeneratorSpiDhCreate(&params, &returnSpi);
    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(returnSpi, nullptr);

    HcfAsyKeyParamsSpec *paramSpec = nullptr;
    res = ConstructDHKeyPairParamsCommonSpec(g_dh1536AlgoName, g_dh1536CommSpec, &paramSpec);
    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(paramSpec, nullptr);

    res = returnSpi->engineGenerateKeyPairBySpec(returnSpi, paramSpec, nullptr);
    ASSERT_EQ(res, HCF_INVALID_PARAMS);

    HcfKeyPair *keyPair = nullptr;
    res = returnSpi->engineGenerateKeyPairBySpec((HcfAsyKeyGeneratorSpi *)&g_obj, paramSpec, &keyPair);
    ASSERT_EQ(res, HCF_INVALID_PARAMS);
    ASSERT_EQ(keyPair, nullptr);

    HcfAsyKeyParamsSpec *paramSpec1 = nullptr;
    res = ConstructAlg25519KeyPairParamsSpec("Ed25519", true, &paramSpec1);
    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(paramSpec1, nullptr);

    HcfKeyPair *keyPair1 = nullptr;
    res = returnSpi->engineGenerateKeyPairBySpec(returnSpi, paramSpec1, &keyPair1);
    ASSERT_EQ(res, HCF_INVALID_PARAMS);
    ASSERT_EQ(keyPair1, nullptr);

    HcfObjDestroy(returnSpi);
    HcfObjDestroy(keyPair);
    HcfObjDestroy(keyPair1);
    DestroyAlg25519KeyPairSpec(reinterpret_cast<HcfAlg25519KeyPairParamsSpec *>(paramSpec1));
    DestroyTestDhKeyPairSpec(reinterpret_cast<HcfDhKeyPairParamsSpec *>(paramSpec));
}

HWTEST_F(CryptoDHAsyKeyGeneratorBySpecTest, CryptoDHAsyKeyGeneratorBySpecTest038, TestSize.Level0)
{
    HcfAsyKeyGenParams params = {
        .algo = HCF_ALG_DH,
        .bits = HCF_OPENSSL_DH_MODP_2048,
        .primes = HCF_OPENSSL_PRIMES_2,
    };

    HcfAsyKeyGeneratorSpi *returnSpi = nullptr;
    HcfResult res = HcfAsyKeyGeneratorSpiDhCreate(&params, &returnSpi);
    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(returnSpi, nullptr);

    HcfAsyKeyParamsSpec *paramSpec = nullptr;
    res = ConstructDHPubKeyParamsSpec(g_dh2048AlgoName, g_dh2048CommSpec, &paramSpec);
    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(paramSpec, nullptr);

    res = returnSpi->engineGeneratePubKeyBySpec(returnSpi, paramSpec, nullptr);
    ASSERT_EQ(res, HCF_INVALID_PARAMS);

    HcfPubKey *pubKey = nullptr;
    res = returnSpi->engineGeneratePubKeyBySpec((HcfAsyKeyGeneratorSpi *)&g_obj, paramSpec, &pubKey);
    ASSERT_EQ(res, HCF_INVALID_PARAMS);
    ASSERT_EQ(pubKey, nullptr);

    HcfAsyKeyParamsSpec *paramSpec1 = nullptr;
    res = ConstructAlg25519PubKeyParamsSpec("Ed25519", true, &paramSpec1);
    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(paramSpec1, nullptr);

    HcfPubKey *pubKey1 = nullptr;
    res = returnSpi->engineGeneratePubKeyBySpec(returnSpi, paramSpec1, &pubKey1);
    ASSERT_EQ(res, HCF_INVALID_PARAMS);
    ASSERT_EQ(pubKey1, nullptr);

    HcfObjDestroy(returnSpi);
    HcfObjDestroy(pubKey);
    HcfObjDestroy(pubKey1);
    DestroyTestDhPubKeySpec(reinterpret_cast<HcfDhPubKeyParamsSpec *>(paramSpec));
    DestroyAlg25519PubKeySpec(reinterpret_cast<HcfAlg25519PubKeyParamsSpec *>(paramSpec1));
}

HWTEST_F(CryptoDHAsyKeyGeneratorBySpecTest, CryptoDHAsyKeyGeneratorBySpecTest039, TestSize.Level0)
{
    HcfAsyKeyGenParams params = {
        .algo = HCF_ALG_DH,
        .bits = HCF_OPENSSL_DH_MODP_3072,
        .primes = HCF_OPENSSL_PRIMES_2,
    };

    HcfAsyKeyGeneratorSpi *returnSpi = nullptr;
    HcfResult res = HcfAsyKeyGeneratorSpiDhCreate(&params, &returnSpi);
    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(returnSpi, nullptr);

    HcfAsyKeyParamsSpec *paramSpec = nullptr;
    res = ConstructDHPriKeyParamsSpec(g_dh3072AlgoName, g_dh3072CommSpec, &paramSpec);
    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(paramSpec, nullptr);

    res = returnSpi->engineGeneratePriKeyBySpec(returnSpi, paramSpec, nullptr);
    ASSERT_EQ(res, HCF_INVALID_PARAMS);

    HcfPriKey *priKey = nullptr;
    res = returnSpi->engineGeneratePriKeyBySpec((HcfAsyKeyGeneratorSpi *)&g_obj, paramSpec, &priKey);
    ASSERT_EQ(res, HCF_INVALID_PARAMS);
    ASSERT_EQ(priKey, nullptr);

    HcfAsyKeyParamsSpec *paramSpec1 = nullptr;
    res = ConstructAlg25519PriKeyParamsSpec("Ed25519", true, &paramSpec1);
    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(paramSpec1, nullptr);

    HcfPriKey *priKey1 = nullptr;
    res = returnSpi->engineGeneratePriKeyBySpec(returnSpi, paramSpec1, &priKey1);
    ASSERT_EQ(res, HCF_INVALID_PARAMS);
    ASSERT_EQ(priKey1, nullptr);

    HcfObjDestroy(returnSpi);
    HcfObjDestroy(priKey);
    HcfObjDestroy(priKey1);
    DestroyTestDhPriKeySpec(reinterpret_cast<HcfDhPriKeyParamsSpec *>(paramSpec));
    DestroyAlg25519PriKeySpec(reinterpret_cast<HcfAlg25519PriKeyParamsSpec *>(paramSpec1));
}

HWTEST_F(CryptoDHAsyKeyGeneratorBySpecTest, CryptoDHAsyKeyGeneratorBySpecTest040, TestSize.Level0)
{
    HcfAsyKeyGeneratorSpi *returnSpi = nullptr;
    HcfResult res = HcfAsyKeyGeneratorSpiDhCreate(nullptr, &returnSpi);

    ASSERT_EQ(res, HCF_INVALID_PARAMS);
    ASSERT_EQ(returnSpi, nullptr);

    HcfObjDestroy(returnSpi);
}

static void OpensslMockTestFunc(uint32_t mallocCount, HcfAsyKeyParamsSpec *paramSpec)
{
    for (uint32_t i = 0; i < mallocCount; i++) {
        ResetOpensslCallNum();
        SetOpensslCallMockIndex(i);
        HcfAsyKeyGeneratorBySpec *returnObj = nullptr;
        HcfResult res = HcfAsyKeyGeneratorBySpecCreate(paramSpec, &returnObj);
        if (res != HCF_SUCCESS) {
            continue;
        }

        HcfKeyPair *keyPair = nullptr;
        res = returnObj->generateKeyPair(returnObj, &keyPair);
        if (res != HCF_SUCCESS) {
            HcfObjDestroy(returnObj);
            continue;
        }

        HcfObjDestroy(returnObj);
        HcfObjDestroy(keyPair);
    }
}

HWTEST_F(CryptoDHAsyKeyGeneratorBySpecTest, CryptoDHAsyKeyGeneratorBySpecTest041, TestSize.Level0)
{
    HcfAsyKeyParamsSpec *paramSpec = nullptr;
    HcfResult res = ConstructDHKeyPairParamsCommonSpec(g_dh1536AlgoName, g_dh1536CommSpec, &paramSpec);
    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(paramSpec, nullptr);
    StartRecordOpensslCallNum();

    HcfAsyKeyGeneratorBySpec *returnObj = nullptr;
    res = HcfAsyKeyGeneratorBySpecCreate(paramSpec, &returnObj);
    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(returnObj, nullptr);

    HcfKeyPair *keyPair = nullptr;
    res = returnObj->generateKeyPair(returnObj, &keyPair);
    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(keyPair, nullptr);

    HcfObjDestroy(returnObj);
    HcfObjDestroy(keyPair);

    uint32_t mallocCount = GetOpensslCallNum();
    OpensslMockTestFunc(mallocCount, paramSpec);

    EndRecordOpensslCallNum();
    DestroyTestDhKeyPairSpec(reinterpret_cast<HcfDhKeyPairParamsSpec *>(paramSpec));
}

static void OpensslMockTestFunc1(uint32_t mallocCount)
{
    for (uint32_t i = 0; i < mallocCount; i++) {
        ResetOpensslCallNum();
        SetOpensslCallMockIndex(i);

        HcfResult res = HcfDhKeyUtilCreateTest(PLEN_DH4096, SKLEN_DH1024);
        if (res != HCF_SUCCESS) {
            continue;
        }
    }
}

HWTEST_F(CryptoDHAsyKeyGeneratorBySpecTest, CryptoDHAsyKeyGeneratorBySpecTest042, TestSize.Level0)
{
    StartRecordOpensslCallNum();
    HcfResult res = HcfDhKeyUtilCreateTest(PLEN_DH4096, SKLEN_DH1024);
    ASSERT_EQ(res, HCF_SUCCESS);

    uint32_t mallocCount = GetOpensslCallNum();
    OpensslMockTestFunc1(mallocCount);

    EndRecordOpensslCallNum();
}

HWTEST_F(CryptoDHAsyKeyGeneratorBySpecTest, CryptoDHAsyKeyGeneratorBySpecTest043, TestSize.Level0)
{
    HcfResult res = HcfDhCommonParamSpecCreate(PLEN_DH4096, SKLEN_DH1024, nullptr);
    ASSERT_EQ(res, HCF_INVALID_PARAMS);
}

static void OpensslMockTestFunc2(uint32_t mallocCount)
{
    for (uint32_t i = 0; i < mallocCount; i++) {
        ResetOpensslCallNum();
        SetOpensslCallMockIndex(i);

        HcfResult res = HcfDhKeyUtilCreateTest(PLEN_DH512, SKLEN_DH128);
        if (res != HCF_SUCCESS) {
            continue;
        }
    }
}

HWTEST_F(CryptoDHAsyKeyGeneratorBySpecTest, CryptoDHAsyKeyGeneratorBySpecTest044, TestSize.Level0)
{
    StartRecordOpensslCallNum();
    HcfResult res = HcfDhKeyUtilCreateTest(PLEN_DH512, SKLEN_DH128);
    ASSERT_EQ(res, HCF_SUCCESS);

    uint32_t mallocCount = GetOpensslCallNum();
    OpensslMockTestFunc2(mallocCount);

    EndRecordOpensslCallNum();
}

HWTEST_F(CryptoDHAsyKeyGeneratorBySpecTest, CryptoDHAsyKeyGeneratorBySpecTest045, TestSize.Level0)
{
    HcfResult res = HcfDhKeyUtilCreateTest(PLEN_DH2048, SKLEN_DH223);
    ASSERT_EQ(res, HCF_ERR_MALLOC);

    res = HcfDhKeyUtilCreateTest(PLEN_DH3072, SKLEN_DH255);
    ASSERT_EQ(res, HCF_ERR_MALLOC);

    res = HcfDhKeyUtilCreateTest(PLEN_DH4096, SKLEN_DH303);
    ASSERT_EQ(res, HCF_ERR_MALLOC);

    res = HcfDhKeyUtilCreateTest(PLEN_DH6144, SKLEN_DH351);
    ASSERT_EQ(res, HCF_ERR_MALLOC);

    res = HcfDhKeyUtilCreateTest(PLEN_DH8192, SKLEN_DH399);
    ASSERT_EQ(res, HCF_ERR_MALLOC);
}

HWTEST_F(CryptoDHAsyKeyGeneratorBySpecTest, CryptoDHAsyKeyGeneratorBySpecTest046, TestSize.Level0)
{
    HcfAsyKeyParamsSpec *paramSpec = nullptr;
    HcfResult res = ConstructDHPriKeyParamsSpec(g_dh1536AlgoName, g_dh1536CommSpec, &paramSpec);
    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(paramSpec, nullptr);

    HcfAsyKeyGeneratorBySpec *returnObj = nullptr;
    res = HcfAsyKeyGeneratorBySpecCreate(paramSpec, &returnObj);
    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(returnObj, nullptr);

    HcfPriKey *priKey = nullptr;
    res = returnObj->generatePriKey(returnObj, &priKey);
    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(priKey, nullptr);

    HcfBlob blob = { .data = nullptr, .len = 0 };
    res = priKey->base.getEncoded(&(priKey->base), &blob);
    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(blob.data, nullptr);
    ASSERT_NE(blob.len, 0);

    HcfAsyKeyGenerator *generator = nullptr;
    res = HcfAsyKeyGeneratorCreate("DH_modp1536", &generator);
    ASSERT_EQ(res, HCF_SUCCESS);

    HcfKeyPair *keyPair = nullptr;
    res = generator->convertKey(generator, nullptr, nullptr, &blob, &keyPair);
    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(keyPair, nullptr);

    HcfFree(blob.data);
    HcfObjDestroy(returnObj);
    HcfObjDestroy(generator);
    HcfObjDestroy(priKey);
    HcfObjDestroy(keyPair);
    DestroyTestDhPriKeySpec(reinterpret_cast<HcfDhPriKeyParamsSpec *>(paramSpec));
}

HWTEST_F(CryptoDHAsyKeyGeneratorBySpecTest, CryptoDHAsyKeyGeneratorBySpecTest047, TestSize.Level0)
{
    HcfDhKeyUtilErrBranch();
    HcfResult res = HcfDhKeyUtilCreateTest(PLEN_DH10001, SKLEN_EQZERO);
    ASSERT_EQ(res, HCF_ERR_MALLOC);

    res = HcfDhKeyUtilCreateTest(PLEN_DH511, SKLEN_EQZERO);
    ASSERT_EQ(res, HCF_ERR_MALLOC);
}
}