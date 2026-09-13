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
#include "securec.h"

#include "asy_key_generator.h"
#include "detailed_ecc_key_params.h"
#include "ecc_openssl_common.h"
#include "ecc_openssl_common_param_spec.h"
#include "ecc_common.h"
#include "ecdh_openssl.h"
#include "key_agreement.h"
#include "memory.h"
#include "memory_mock.h"
#include "openssl_adapter_mock.h"
#include "openssl_common.h"
#include "params_parser.h"

using namespace std;
using namespace testing::ext;

namespace {
class CryptoEccKeyAgreementBySpecTest : public testing::Test {
public:
    static void CryptoEccNoLengthSignTestSubEcc224(void);
    static void CryptoEccNoLengthSignTestSubEcc256(void);
    static void CryptoEccNoLengthSignTestSubEcc384(void);
    static void CryptoEccNoLengthSignTestSubEcc521(void);

    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp();
    void TearDown();

    static HcfKeyPair *ecc224KeyPair_;
    static HcfKeyPair *ecc256KeyPair_;
    static HcfKeyPair *ecc384KeyPair_;
    static HcfKeyPair *ecc521KeyPair_;
};

HcfKeyPair *CryptoEccKeyAgreementBySpecTest::ecc224KeyPair_ = nullptr;
HcfKeyPair *CryptoEccKeyAgreementBySpecTest::ecc256KeyPair_ = nullptr;
HcfKeyPair *CryptoEccKeyAgreementBySpecTest::ecc384KeyPair_ = nullptr;
HcfKeyPair *CryptoEccKeyAgreementBySpecTest::ecc521KeyPair_ = nullptr;

void CryptoEccKeyAgreementBySpecTest::SetUp() {}
void CryptoEccKeyAgreementBySpecTest::TearDown() {}

static const bool IS_BIG_ENDIAN = IsBigEndian();

static string g_eccAlgName = "ECC";
static string g_eccFieldType = "Fp";
static int32_t g_ecc224CorrectH = 1;
static int32_t g_ecc256CorrectH = 1;
static int32_t g_ecc384CorrectH = 1;
static int32_t g_ecc521CorrectH = 1;

HcfEccKeyPairParamsSpec g_ecc224KeyPairSpec;
HcfEccKeyPairParamsSpec g_ecc256KeyPairSpec;
HcfEccKeyPairParamsSpec g_ecc384KeyPairSpec;
HcfEccKeyPairParamsSpec g_ecc521KeyPairSpec;
HcfECFieldFp g_fieldFp;

static HcfResult ConstructEcc224KeyPairParamsSpec(HcfAsyKeyParamsSpec **spec)
{
    HcfEccKeyPairParamsSpec *eccKeyPairSpec = &g_ecc224KeyPairSpec;
    HcfECField *tmpField = (HcfECField *)(&g_fieldFp);

    eccKeyPairSpec->base.base.algName = const_cast<char *>(g_eccAlgName.c_str());
    eccKeyPairSpec->base.base.specType = HCF_KEY_PAIR_SPEC;
    eccKeyPairSpec->base.field = tmpField;
    eccKeyPairSpec->base.field->fieldType = const_cast<char *>(g_eccFieldType.c_str());
    ((HcfECFieldFp *)(eccKeyPairSpec->base.field))->p.data =
        (IS_BIG_ENDIAN ? g_ecc224CorrectBigP : g_ecc224CorrectLittleP);
    ((HcfECFieldFp *)(eccKeyPairSpec->base.field))->p.len = NID_secp224r1_len;
    eccKeyPairSpec->base.a.data = (IS_BIG_ENDIAN ? g_ecc224CorrectBigA : g_ecc224CorrectLittleA);
    eccKeyPairSpec->base.a.len = NID_secp224r1_len;
    eccKeyPairSpec->base.b.data = (IS_BIG_ENDIAN ? g_ecc224CorrectBigB : g_ecc224CorrectLittleB);
    eccKeyPairSpec->base.b.len = NID_secp224r1_len;
    eccKeyPairSpec->base.g.x.data = (IS_BIG_ENDIAN ? g_ecc224CorrectBigGX : g_ecc224CorrectLittleGX);
    eccKeyPairSpec->base.g.x.len = NID_secp224r1_len;
    eccKeyPairSpec->base.g.y.data = (IS_BIG_ENDIAN ? g_ecc224CorrectBigGY : g_ecc224CorrectLittleGY);
    eccKeyPairSpec->base.g.y.len = NID_secp224r1_len;
    eccKeyPairSpec->base.n.data = (IS_BIG_ENDIAN ? g_ecc224CorrectBigN : g_ecc224CorrectLittleN);
    eccKeyPairSpec->base.n.len = NID_secp224r1_len;
    eccKeyPairSpec->base.h = g_ecc224CorrectH;
    eccKeyPairSpec->pk.x.data = (IS_BIG_ENDIAN ? g_ecc224CorrectBigPkX : g_ecc224CorrectLittlePkX);
    eccKeyPairSpec->pk.x.len = NID_secp224r1_len;
    eccKeyPairSpec->pk.y.data = (IS_BIG_ENDIAN ? g_ecc224CorrectBigPkY : g_ecc224CorrectLittlePkY);
    eccKeyPairSpec->pk.y.len = NID_secp224r1_len;
    eccKeyPairSpec->sk.data = (IS_BIG_ENDIAN ? g_ecc224CorrectBigSk : g_ecc224CorrectLittleSk);
    eccKeyPairSpec->sk.len = NID_secp224r1_len;

    *spec = (HcfAsyKeyParamsSpec *)eccKeyPairSpec;
    return HCF_SUCCESS;
}

static HcfResult ConstructEcc256KeyPairParamsSpec(HcfAsyKeyParamsSpec **spec)
{
    HcfEccKeyPairParamsSpec *eccKeyPairSpec = &g_ecc256KeyPairSpec;
    HcfECField *tmpField = (HcfECField *)(&g_fieldFp);

    eccKeyPairSpec->base.base.algName = const_cast<char *>(g_eccAlgName.c_str());
    eccKeyPairSpec->base.base.specType = HCF_KEY_PAIR_SPEC;
    eccKeyPairSpec->base.field = tmpField;
    eccKeyPairSpec->base.field->fieldType = const_cast<char *>(g_eccFieldType.c_str());
    ((HcfECFieldFp *)(eccKeyPairSpec->base.field))->p.data =
        (IS_BIG_ENDIAN ? g_ecc256CorrectBigP : g_ecc256CorrectLittleP);
    ((HcfECFieldFp *)(eccKeyPairSpec->base.field))->p.len = NID_X9_62_prime256v1_len;
    eccKeyPairSpec->base.a.data = (IS_BIG_ENDIAN ? g_ecc256CorrectBigA : g_ecc256CorrectLittleA);
    eccKeyPairSpec->base.a.len = NID_X9_62_prime256v1_len;
    eccKeyPairSpec->base.b.data = (IS_BIG_ENDIAN ? g_ecc256CorrectBigB : g_ecc256CorrectLittleB);
    eccKeyPairSpec->base.b.len = NID_X9_62_prime256v1_len;
    eccKeyPairSpec->base.g.x.data = (IS_BIG_ENDIAN ? g_ecc256CorrectBigGX : g_ecc256CorrectLittleGX);
    eccKeyPairSpec->base.g.x.len = NID_X9_62_prime256v1_len;
    eccKeyPairSpec->base.g.y.data = (IS_BIG_ENDIAN ? g_ecc256CorrectBigGY : g_ecc256CorrectLittleGY);
    eccKeyPairSpec->base.g.y.len = NID_X9_62_prime256v1_len;
    eccKeyPairSpec->base.n.data = (IS_BIG_ENDIAN ? g_ecc256CorrectBigN : g_ecc256CorrectLittleN);
    eccKeyPairSpec->base.n.len = NID_X9_62_prime256v1_len;
    eccKeyPairSpec->base.h = g_ecc256CorrectH;
    eccKeyPairSpec->pk.x.data = (IS_BIG_ENDIAN ? g_ecc256CorrectBigPkX : g_ecc256CorrectLittlePkX);
    eccKeyPairSpec->pk.x.len = NID_X9_62_prime256v1_len;
    eccKeyPairSpec->pk.y.data = (IS_BIG_ENDIAN ? g_ecc256CorrectBigPkY : g_ecc256CorrectLittlePkY);
    eccKeyPairSpec->pk.y.len = NID_X9_62_prime256v1_len;
    eccKeyPairSpec->sk.data = (IS_BIG_ENDIAN ? g_ecc256CorrectBigSk : g_ecc256CorrectLittleSk);
    eccKeyPairSpec->sk.len = NID_X9_62_prime256v1_len;

    *spec = (HcfAsyKeyParamsSpec *)eccKeyPairSpec;
    return HCF_SUCCESS;
}

static HcfResult ConstructEcc384KeyPairParamsSpec(HcfAsyKeyParamsSpec **spec)
{
    HcfEccKeyPairParamsSpec *eccKeyPairSpec = &g_ecc384KeyPairSpec;
    HcfECField *tmpField = (HcfECField *)(&g_fieldFp);

    eccKeyPairSpec->base.base.algName = const_cast<char *>(g_eccAlgName.c_str());
    eccKeyPairSpec->base.base.specType = HCF_KEY_PAIR_SPEC;
    eccKeyPairSpec->base.field = tmpField;
    eccKeyPairSpec->base.field->fieldType = const_cast<char *>(g_eccFieldType.c_str());
    ((HcfECFieldFp *)(eccKeyPairSpec->base.field))->p.data =
        (IS_BIG_ENDIAN ? g_ecc384CorrectBigP : g_ecc384CorrectLittleP);
    ((HcfECFieldFp *)(eccKeyPairSpec->base.field))->p.len = NID_secp384r1_len;
    eccKeyPairSpec->base.a.data = (IS_BIG_ENDIAN ? g_ecc384CorrectBigA : g_ecc384CorrectLittleA);
    eccKeyPairSpec->base.a.len = NID_secp384r1_len;
    eccKeyPairSpec->base.b.data = (IS_BIG_ENDIAN ? g_ecc384CorrectBigB : g_ecc384CorrectLittleB);
    eccKeyPairSpec->base.b.len = NID_secp384r1_len;
    eccKeyPairSpec->base.g.x.data = (IS_BIG_ENDIAN ? g_ecc384CorrectBigGX : g_ecc384CorrectLittleGX);
    eccKeyPairSpec->base.g.x.len = NID_secp384r1_len;
    eccKeyPairSpec->base.g.y.data = (IS_BIG_ENDIAN ? g_ecc384CorrectBigGY : g_ecc384CorrectLittleGY);
    eccKeyPairSpec->base.g.y.len = NID_secp384r1_len;
    eccKeyPairSpec->base.n.data = (IS_BIG_ENDIAN ? g_ecc384CorrectBigN : g_ecc384CorrectLittleN);
    eccKeyPairSpec->base.n.len = NID_secp384r1_len;
    eccKeyPairSpec->base.h = g_ecc384CorrectH;
    eccKeyPairSpec->pk.x.data = (IS_BIG_ENDIAN ? g_ecc384CorrectBigPkX : g_ecc384CorrectLittlePkX);
    eccKeyPairSpec->pk.x.len = NID_secp384r1_len;
    eccKeyPairSpec->pk.y.data = (IS_BIG_ENDIAN ? g_ecc384CorrectBigPkY : g_ecc384CorrectLittlePkY);
    eccKeyPairSpec->pk.y.len = NID_secp384r1_len;
    eccKeyPairSpec->sk.data = (IS_BIG_ENDIAN ? g_ecc384CorrectBigSk : g_ecc384CorrectLittleSk);
    eccKeyPairSpec->sk.len = NID_secp384r1_len;

    *spec = (HcfAsyKeyParamsSpec *)eccKeyPairSpec;
    return HCF_SUCCESS;
}

static HcfResult ConstructEcc521KeyPairParamsSpec(HcfAsyKeyParamsSpec **spec)
{
    HcfEccKeyPairParamsSpec *eccKeyPairSpec = &g_ecc521KeyPairSpec;
    HcfECField *tmpField = (HcfECField *)(&g_fieldFp);

    eccKeyPairSpec->base.base.algName = const_cast<char *>(g_eccAlgName.c_str());
    eccKeyPairSpec->base.base.specType = HCF_KEY_PAIR_SPEC;
    eccKeyPairSpec->base.field = tmpField;
    eccKeyPairSpec->base.field->fieldType = const_cast<char *>(g_eccFieldType.c_str());
    ((HcfECFieldFp *)(eccKeyPairSpec->base.field))->p.data =
        (IS_BIG_ENDIAN ? g_ecc521CorrectBigP : g_ecc521CorrectLittleP);
    ((HcfECFieldFp *)(eccKeyPairSpec->base.field))->p.len = NID_secp521r1_len;
    eccKeyPairSpec->base.a.data = (IS_BIG_ENDIAN ? g_ecc521CorrectBigA : g_ecc521CorrectLittleA);
    eccKeyPairSpec->base.a.len = NID_secp521r1_len;
    eccKeyPairSpec->base.b.data = (IS_BIG_ENDIAN ? g_ecc521CorrectBigB : g_ecc521CorrectLittleB);
    eccKeyPairSpec->base.b.len = NID_secp521r1_len;
    eccKeyPairSpec->base.g.x.data = (IS_BIG_ENDIAN ? g_ecc521CorrectBigGX : g_ecc521CorrectLittleGX);
    eccKeyPairSpec->base.g.x.len = NID_secp521r1_len;
    eccKeyPairSpec->base.g.y.data = (IS_BIG_ENDIAN ? g_ecc521CorrectBigGY : g_ecc521CorrectLittleGY);
    eccKeyPairSpec->base.g.y.len = NID_secp521r1_len;
    eccKeyPairSpec->base.n.data = (IS_BIG_ENDIAN ? g_ecc521CorrectBigN : g_ecc521CorrectLittleN);
    eccKeyPairSpec->base.n.len = NID_secp521r1_len;
    eccKeyPairSpec->base.h = g_ecc521CorrectH;
    eccKeyPairSpec->pk.x.data = (IS_BIG_ENDIAN ? g_ecc521CorrectBigPkX : g_ecc521CorrectLittlePkX);
    eccKeyPairSpec->pk.x.len = NID_secp521r1_len;
    eccKeyPairSpec->pk.y.data = (IS_BIG_ENDIAN ? g_ecc521CorrectBigPkY : g_ecc521CorrectLittlePkY);
    eccKeyPairSpec->pk.y.len = NID_secp521r1_len;
    eccKeyPairSpec->sk.data = (IS_BIG_ENDIAN ? g_ecc521CorrectBigSk : g_ecc521CorrectLittleSk);
    eccKeyPairSpec->sk.len = NID_secp521r1_len;

    *spec = (HcfAsyKeyParamsSpec *)eccKeyPairSpec;
    return HCF_SUCCESS;
}

void CryptoEccKeyAgreementBySpecTest::CryptoEccNoLengthSignTestSubEcc224(void)
{
    HcfAsyKeyParamsSpec *paramSpec = nullptr;
    int32_t res = ConstructEcc224KeyPairParamsSpec(&paramSpec);
    ASSERT_EQ(res, HCF_SUCCESS);

    HcfAsyKeyGeneratorBySpec *generator = nullptr;
    res = HcfAsyKeyGeneratorBySpecCreate(paramSpec, &generator);
    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(generator, nullptr);

    HcfKeyPair *keyPair = nullptr;
    res = generator->generateKeyPair(generator, &keyPair);
    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(keyPair, nullptr);

    ecc224KeyPair_ = keyPair;

    HcfObjDestroy(generator);
}

void CryptoEccKeyAgreementBySpecTest::CryptoEccNoLengthSignTestSubEcc256(void)
{
    HcfAsyKeyParamsSpec *paramSpec = nullptr;
    int32_t res = ConstructEcc256KeyPairParamsSpec(&paramSpec);
    ASSERT_EQ(res, HCF_SUCCESS);

    HcfAsyKeyGeneratorBySpec *generator = nullptr;
    res = HcfAsyKeyGeneratorBySpecCreate(paramSpec, &generator);
    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(generator, nullptr);

    HcfKeyPair *keyPair = nullptr;
    res = generator->generateKeyPair(generator, &keyPair);
    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(keyPair, nullptr);

    ecc256KeyPair_ = keyPair;

    HcfObjDestroy(generator);
}

void CryptoEccKeyAgreementBySpecTest::CryptoEccNoLengthSignTestSubEcc384(void)
{
    HcfAsyKeyParamsSpec *paramSpec = nullptr;
    int32_t res = ConstructEcc384KeyPairParamsSpec(&paramSpec);
    ASSERT_EQ(res, HCF_SUCCESS);

    HcfAsyKeyGeneratorBySpec *generator = nullptr;
    res = HcfAsyKeyGeneratorBySpecCreate(paramSpec, &generator);
    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(generator, nullptr);

    HcfKeyPair *keyPair = nullptr;
    res = generator->generateKeyPair(generator, &keyPair);
    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(keyPair, nullptr);

    ecc384KeyPair_ = keyPair;
    HcfObjDestroy(generator);
}

void CryptoEccKeyAgreementBySpecTest::CryptoEccNoLengthSignTestSubEcc521(void)
{
    HcfAsyKeyParamsSpec *paramSpec = nullptr;
    int32_t res = ConstructEcc521KeyPairParamsSpec(&paramSpec);
    ASSERT_EQ(res, HCF_SUCCESS);

    HcfAsyKeyGeneratorBySpec *generator = nullptr;
    res = HcfAsyKeyGeneratorBySpecCreate(paramSpec, &generator);
    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(generator, nullptr);

    HcfKeyPair *keyPair = nullptr;
    res = generator->generateKeyPair(generator, &keyPair);
    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(keyPair, nullptr);

    ecc521KeyPair_ = keyPair;
    HcfObjDestroy(generator);
}

void CryptoEccKeyAgreementBySpecTest::SetUpTestCase()
{
    CryptoEccNoLengthSignTestSubEcc224();
    CryptoEccNoLengthSignTestSubEcc256();
    CryptoEccNoLengthSignTestSubEcc384();
    CryptoEccNoLengthSignTestSubEcc521();
}

void CryptoEccKeyAgreementBySpecTest::TearDownTestCase()
{
    HcfObjDestroy(ecc224KeyPair_);
    HcfObjDestroy(ecc256KeyPair_);
    HcfObjDestroy(ecc384KeyPair_);
    HcfObjDestroy(ecc521KeyPair_);
}

static const char *GetMockClass(void)
{
    return "HcfSymKeyGenerator";
}

static HcfObjectBase obj = {
    .getClass = GetMockClass,
    .destroy = nullptr
};

HWTEST_F(CryptoEccKeyAgreementBySpecTest, CryptoEccKeyAgreementBySpecTest501, TestSize.Level0)
{
    HcfKeyAgreement *keyAgreement = nullptr;
    int32_t res = HcfKeyAgreementCreate("ECC", &keyAgreement);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(keyAgreement, nullptr);

    HcfObjDestroy(keyAgreement);
}

HWTEST_F(CryptoEccKeyAgreementBySpecTest, CryptoEccKeyAgreementBySpecTest502, TestSize.Level0)
{
    HcfKeyAgreement *keyAgreement = nullptr;
    int32_t res = HcfKeyAgreementCreate("ecc", &keyAgreement);

    ASSERT_EQ(res, HCF_INVALID_PARAMS);
    ASSERT_EQ(keyAgreement, nullptr);
}

HWTEST_F(CryptoEccKeyAgreementBySpecTest, CryptoEccKeyAgreementTes503, TestSize.Level0)
{
    int32_t res = HcfKeyAgreementCreate("ECC", nullptr);

    ASSERT_EQ(res, HCF_INVALID_PARAMS);
}

HWTEST_F(CryptoEccKeyAgreementBySpecTest, CryptoEccKeyAgreementBySpecTest601, TestSize.Level0)
{
    HcfKeyAgreement *keyAgreement = nullptr;
    int32_t res = HcfKeyAgreementCreate("ECC", &keyAgreement);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(keyAgreement, nullptr);

    const char *className = keyAgreement->base.getClass();

    ASSERT_NE(className, nullptr);

    HcfObjDestroy(keyAgreement);
}

HWTEST_F(CryptoEccKeyAgreementBySpecTest, CryptoEccKeyAgreementBySpecTest602, TestSize.Level0)
{
    HcfKeyAgreement *keyAgreement = nullptr;
    int32_t res = HcfKeyAgreementCreate("ECC", &keyAgreement);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(keyAgreement, nullptr);

    keyAgreement->base.destroy((HcfObjectBase *)keyAgreement);
}

HWTEST_F(CryptoEccKeyAgreementBySpecTest, CryptoEccKeyAgreementBySpecTest603, TestSize.Level0)
{
    HcfKeyAgreement *keyAgreement = nullptr;
    int32_t res = HcfKeyAgreementCreate("ECC", &keyAgreement);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(keyAgreement, nullptr);

    keyAgreement->base.destroy(nullptr);

    HcfObjDestroy(keyAgreement);
}

HWTEST_F(CryptoEccKeyAgreementBySpecTest, CryptoEccKeyAgreementBySpecTest604, TestSize.Level0)
{
    HcfKeyAgreement *keyAgreement = nullptr;
    int32_t res = HcfKeyAgreementCreate("ECC", &keyAgreement);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(keyAgreement, nullptr);

    keyAgreement->base.destroy(&obj);

    HcfObjDestroy(keyAgreement);
}

HWTEST_F(CryptoEccKeyAgreementBySpecTest, CryptoEccKeyAgreementBySpecTest605, TestSize.Level0)
{
    HcfKeyAgreement *keyAgreement = nullptr;
    int32_t res = HcfKeyAgreementCreate("ECC", &keyAgreement);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(keyAgreement, nullptr);

    const char *algName = keyAgreement->getAlgoName(keyAgreement);

    ASSERT_NE(algName, nullptr);

    HcfObjDestroy(keyAgreement);
}

HWTEST_F(CryptoEccKeyAgreementBySpecTest, CryptoEccKeyAgreementBySpecTest606, TestSize.Level0)
{
    HcfKeyAgreement *keyAgreement = nullptr;
    int32_t res = HcfKeyAgreementCreate("ECC", &keyAgreement);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(keyAgreement, nullptr);

    const char *algName = keyAgreement->getAlgoName(nullptr);

    ASSERT_EQ(algName, nullptr);

    HcfObjDestroy(keyAgreement);
}

HWTEST_F(CryptoEccKeyAgreementBySpecTest, CryptoEccKeyAgreementBySpecTest607, TestSize.Level0)
{
    HcfKeyAgreement *keyAgreement = nullptr;
    int32_t res = HcfKeyAgreementCreate("ECC", &keyAgreement);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(keyAgreement, nullptr);

    const char *algName = keyAgreement->getAlgoName((HcfKeyAgreement *)(&obj));

    ASSERT_EQ(algName, nullptr);

    HcfObjDestroy(keyAgreement);
}

HWTEST_F(CryptoEccKeyAgreementBySpecTest, CryptoEccKeyAgreementBySpecTest701, TestSize.Level0)
{
    HcfKeyAgreement *keyAgreement = nullptr;
    int32_t res = HcfKeyAgreementCreate("ECC", &keyAgreement);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(keyAgreement, nullptr);

    HcfBlob out = { .data = nullptr, .len = 0 };
    res = keyAgreement->generateSecret(keyAgreement, ecc224KeyPair_->priKey, ecc224KeyPair_->pubKey, &out);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(out.data, nullptr);
    ASSERT_NE(out.len, (const unsigned int)0);

    HcfFree(out.data);
    HcfObjDestroy(keyAgreement);
}

HWTEST_F(CryptoEccKeyAgreementBySpecTest, CryptoEccKeyAgreementBySpecTest702, TestSize.Level0)
{
    HcfKeyAgreement *keyAgreement = nullptr;
    int32_t res = HcfKeyAgreementCreate("ECC", &keyAgreement);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(keyAgreement, nullptr);

    HcfBlob out = { .data = nullptr, .len = 0 };
    res = keyAgreement->generateSecret(keyAgreement, ecc256KeyPair_->priKey, ecc256KeyPair_->pubKey, &out);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(out.data, nullptr);
    ASSERT_NE(out.len, (const unsigned int)0);

    HcfFree(out.data);
    HcfObjDestroy(keyAgreement);
}

HWTEST_F(CryptoEccKeyAgreementBySpecTest, CryptoEccKeyAgreementBySpecTest703, TestSize.Level0)
{
    HcfKeyAgreement *keyAgreement = nullptr;
    int32_t res = HcfKeyAgreementCreate("ECC", &keyAgreement);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(keyAgreement, nullptr);

    HcfBlob out = { .data = nullptr, .len = 0 };
    res = keyAgreement->generateSecret(keyAgreement, ecc384KeyPair_->priKey, ecc384KeyPair_->pubKey, &out);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(out.data, nullptr);
    ASSERT_NE(out.len, (const unsigned int)0);

    HcfFree(out.data);
    HcfObjDestroy(keyAgreement);
}

HWTEST_F(CryptoEccKeyAgreementBySpecTest, CryptoEccKeyAgreementBySpecTest704, TestSize.Level0)
{
    HcfKeyAgreement *keyAgreement = nullptr;
    int32_t res = HcfKeyAgreementCreate("ECC", &keyAgreement);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(keyAgreement, nullptr);

    HcfBlob out = { .data = nullptr, .len = 0 };
    res = keyAgreement->generateSecret(keyAgreement, ecc521KeyPair_->priKey, ecc521KeyPair_->pubKey, &out);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(out.data, nullptr);
    ASSERT_NE(out.len, (const unsigned int)0);

    HcfFree(out.data);
    HcfObjDestroy(keyAgreement);
}

HWTEST_F(CryptoEccKeyAgreementBySpecTest, CryptoEccKeyAgreementBySpecTest705, TestSize.Level0)
{
    HcfKeyAgreement *keyAgreement = nullptr;
    int32_t res = HcfKeyAgreementCreate("ECC", &keyAgreement);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(keyAgreement, nullptr);

    HcfBlob out = { .data = nullptr, .len = 0 };
    res = keyAgreement->generateSecret(nullptr, ecc256KeyPair_->priKey, ecc256KeyPair_->pubKey, &out);

    ASSERT_EQ(res, HCF_INVALID_PARAMS);
    ASSERT_EQ(out.data, nullptr);
    ASSERT_EQ(out.len, 0);

    HcfObjDestroy(keyAgreement);
}

HWTEST_F(CryptoEccKeyAgreementBySpecTest, CryptoEccKeyAgreementBySpecTest706, TestSize.Level0)
{
    HcfKeyAgreement *keyAgreement = nullptr;
    int32_t res = HcfKeyAgreementCreate("ECC", &keyAgreement);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(keyAgreement, nullptr);

    HcfBlob out = { .data = nullptr, .len = 0 };
    res = keyAgreement->generateSecret((HcfKeyAgreement *)(&obj), ecc256KeyPair_->priKey, ecc256KeyPair_->pubKey, &out);

    ASSERT_EQ(res, HCF_INVALID_PARAMS);
    ASSERT_EQ(out.data, nullptr);
    ASSERT_EQ(out.len, 0);

    HcfObjDestroy(keyAgreement);
}

HWTEST_F(CryptoEccKeyAgreementBySpecTest, CryptoEccKeyAgreementBySpecTest707, TestSize.Level0)
{
    HcfKeyAgreement *keyAgreement = nullptr;
    int32_t res = HcfKeyAgreementCreate("ECC", &keyAgreement);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(keyAgreement, nullptr);

    HcfBlob out = { .data = nullptr, .len = 0 };
    res = keyAgreement->generateSecret(keyAgreement, (HcfPriKey *)(&obj), ecc256KeyPair_->pubKey, &out);

    ASSERT_EQ(res, HCF_INVALID_PARAMS);
    ASSERT_EQ(out.data, nullptr);
    ASSERT_EQ(out.len, 0);

    HcfObjDestroy(keyAgreement);
}

HWTEST_F(CryptoEccKeyAgreementBySpecTest, CryptoEccKeyAgreementBySpecTest708, TestSize.Level0)
{
    HcfKeyAgreement *keyAgreement = nullptr;
    int32_t res = HcfKeyAgreementCreate("ECC", &keyAgreement);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(keyAgreement, nullptr);

    HcfBlob out = { .data = nullptr, .len = 0 };
    res = keyAgreement->generateSecret(keyAgreement, ecc256KeyPair_->priKey, (HcfPubKey *)(&obj), &out);

    ASSERT_EQ(res, HCF_INVALID_PARAMS);
    ASSERT_EQ(out.data, nullptr);
    ASSERT_EQ(out.len, 0);

    HcfObjDestroy(keyAgreement);
}

HWTEST_F(CryptoEccKeyAgreementBySpecTest, CryptoEccKeyAgreementBySpecTest709, TestSize.Level0)
{
    HcfKeyAgreement *keyAgreement = nullptr;
    int32_t res = HcfKeyAgreementCreate("ECC", &keyAgreement);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(keyAgreement, nullptr);

    HcfBlob out = { .data = nullptr, .len = 0 };
    res = keyAgreement->generateSecret(keyAgreement, nullptr, nullptr, &out);

    ASSERT_EQ(res, HCF_INVALID_PARAMS);
    ASSERT_EQ(out.data, nullptr);
    ASSERT_EQ(out.len, 0);

    HcfObjDestroy(keyAgreement);
}

HWTEST_F(CryptoEccKeyAgreementBySpecTest, CryptoEccKeyAgreementBySpecTest710, TestSize.Level0)
{
    HcfKeyAgreement *keyAgreement = nullptr;
    int32_t res = HcfKeyAgreementCreate("ECC", &keyAgreement);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(keyAgreement, nullptr);

    res = keyAgreement->generateSecret(keyAgreement, ecc256KeyPair_->priKey, ecc256KeyPair_->pubKey, nullptr);

    ASSERT_EQ(res, HCF_INVALID_PARAMS);

    HcfObjDestroy(keyAgreement);
}

HcfKeyAgreementParams g_params = {
    .algo = HCF_ALG_ECC
};


HWTEST_F(CryptoEccKeyAgreementBySpecTest, CryptoEccKeyAgreementBySpecTest801, TestSize.Level0)
{
    HcfKeyAgreementSpi *spiObj = nullptr;
    int32_t res = HcfKeyAgreementSpiEcdhCreate(&g_params, &spiObj);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(spiObj, nullptr);
    HcfObjDestroy(spiObj);
}

HWTEST_F(CryptoEccKeyAgreementBySpecTest, CryptoEccKeyAgreementBySpecTest802, TestSize.Level0)
{
    HcfKeyAgreementSpi *spiObj = nullptr;
    int32_t res = HcfKeyAgreementSpiEcdhCreate(&g_params, &spiObj);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(spiObj, nullptr);

    HcfBlob out = { .data = nullptr, .len = 0 };
    res = spiObj->engineGenerateSecret((HcfKeyAgreementSpi *)&obj,
        ecc256KeyPair_->priKey, ecc256KeyPair_->pubKey, &out);
    ASSERT_EQ(res, HCF_INVALID_PARAMS);

    HcfObjDestroy(spiObj);
}

HWTEST_F(CryptoEccKeyAgreementBySpecTest, CryptoEccKeyAgreementBySpecTest803, TestSize.Level0)
{
    HcfKeyAgreementSpi *spiObj = nullptr;
    int32_t res = HcfKeyAgreementSpiEcdhCreate(&g_params, &spiObj);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(spiObj, nullptr);

    HcfBlob out = { .data = nullptr, .len = 0 };
    res = spiObj->engineGenerateSecret(spiObj, (HcfPriKey *)&obj, ecc256KeyPair_->pubKey, &out);
    ASSERT_EQ(res, HCF_INVALID_PARAMS);

    HcfObjDestroy(spiObj);
}

HWTEST_F(CryptoEccKeyAgreementBySpecTest, CryptoEccKeyAgreementBySpecTest804, TestSize.Level0)
{
    HcfKeyAgreementSpi *spiObj = nullptr;
    int32_t res = HcfKeyAgreementSpiEcdhCreate(&g_params, &spiObj);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(spiObj, nullptr);

    HcfBlob out = { .data = nullptr, .len = 0 };
    res = spiObj->engineGenerateSecret(spiObj, ecc256KeyPair_->priKey, (HcfPubKey *)&obj, &out);
    ASSERT_EQ(res, HCF_INVALID_PARAMS);

    HcfObjDestroy(spiObj);
}

HWTEST_F(CryptoEccKeyAgreementBySpecTest, CryptoEccKeyAgreementBySpecTest805, TestSize.Level0)
{
    HcfKeyAgreementSpi *spiObj = nullptr;
    int32_t res = HcfKeyAgreementSpiEcdhCreate(&g_params, &spiObj);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(spiObj, nullptr);

    spiObj->base.destroy(nullptr);

    HcfObjDestroy(spiObj);
}

HWTEST_F(CryptoEccKeyAgreementBySpecTest, CryptoEccKeyAgreementBySpecTest806, TestSize.Level0)
{
    HcfKeyAgreementSpi *spiObj = nullptr;
    int32_t res = HcfKeyAgreementSpiEcdhCreate(&g_params, &spiObj);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(spiObj, nullptr);

    spiObj->base.destroy(&obj);

    HcfObjDestroy(spiObj);
}

HWTEST_F(CryptoEccKeyAgreementBySpecTest, CryptoEccKeyAgreementBySpecTest901, TestSize.Level0)
{
    StartRecordMallocNum();
    HcfKeyAgreement *keyAgreement = nullptr;
    int32_t res = HcfKeyAgreementCreate("ECC", &keyAgreement);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(keyAgreement, nullptr);

    HcfBlob out = { .data = nullptr, .len = 0 };
    res = keyAgreement->generateSecret(keyAgreement, ecc256KeyPair_->priKey, ecc256KeyPair_->pubKey, &out);

    ASSERT_EQ(res, HCF_SUCCESS);
    HcfFree(out.data);

    HcfObjDestroy(keyAgreement);

    uint32_t mallocCount = GetMallocNum();

    for (uint32_t i = 0; i < mallocCount; i++) {
        ResetRecordMallocNum();
        SetMockMallocIndex(i);
        keyAgreement = nullptr;
        res = HcfKeyAgreementCreate("ECC", &keyAgreement);

        if (res != HCF_SUCCESS) {
            continue;
        }

        out = {
            .data = nullptr,
            .len = 0
        };
        res = keyAgreement->generateSecret(keyAgreement, ecc256KeyPair_->priKey, ecc256KeyPair_->pubKey, &out);

        if (res != HCF_SUCCESS) {
            HcfObjDestroy(keyAgreement);
            continue;
        }

        HcfObjDestroy(keyAgreement);
        HcfFree(out.data);
    }
    EndRecordMallocNum();
}

HWTEST_F(CryptoEccKeyAgreementBySpecTest, CryptoEccKeyAgreementBySpecTest902, TestSize.Level0)
{
    StartRecordOpensslCallNum();
    HcfKeyAgreement *keyAgreement = nullptr;
    int32_t res = HcfKeyAgreementCreate("ECC", &keyAgreement);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(keyAgreement, nullptr);

    HcfBlob out = { .data = nullptr, .len = 0 };
    res = keyAgreement->generateSecret(keyAgreement, ecc256KeyPair_->priKey, ecc256KeyPair_->pubKey, &out);

    ASSERT_EQ(res, HCF_SUCCESS);
    HcfFree(out.data);

    HcfObjDestroy(keyAgreement);

    uint32_t mallocCount = GetOpensslCallNum();

    for (uint32_t i = 0; i < mallocCount; i++) {
        ResetOpensslCallNum();
        SetOpensslCallMockIndex(i);
        keyAgreement = nullptr;
        res = HcfKeyAgreementCreate("ECC", &keyAgreement);

        if (res != HCF_SUCCESS) {
            continue;
        }

        out = {
            .data = nullptr,
            .len = 0
        };
        res = keyAgreement->generateSecret(keyAgreement, ecc256KeyPair_->priKey, ecc256KeyPair_->pubKey, &out);

        if (res != HCF_SUCCESS) {
            HcfObjDestroy(keyAgreement);
            continue;
        }

        HcfObjDestroy(keyAgreement);
        HcfFree(out.data);
    }
    EndRecordOpensslCallNum();
}
}
