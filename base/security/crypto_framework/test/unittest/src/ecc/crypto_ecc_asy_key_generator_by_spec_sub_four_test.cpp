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
constexpr int ZERO = 0;
constexpr int ONE = 1;
constexpr int TWO = 2;
constexpr int THREE = 3;
constexpr int FOUR = 4;
constexpr int FIVE = 5;
constexpr int SIX = 6;
constexpr int SEVEN = 7;
constexpr int EIGHT = 8;

class CryptoEccAsyKeyGeneratorBySpecSubFourTest : public testing::Test {
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

HWTEST_F(CryptoEccAsyKeyGeneratorBySpecSubFourTest, CryptoEccAsyKeyGeneratorBySpecSubFourTest516, TestSize.Level0)
{
    HcfAsyKeyGenerator *generator = nullptr;
    int32_t res = HcfAsyKeyGeneratorCreate("ECC224", &generator);

    HcfKeyPair *keyPair = nullptr;
    res = generator->convertKey(generator, nullptr, &g_mockEcc224PubKeyBlob, &g_mockEcc224PriKeyBlob, &keyPair);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(keyPair, nullptr);

    int retInt = 0;
    AsyKeySpecItem item = ECC_FIELD_SIZE_INT;

    res = keyPair->priKey->getAsyKeySpecInt(keyPair->priKey, item, &retInt);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(retInt, 0);

    HcfObjDestroy(keyPair);
    HcfObjDestroy(generator);
}

// for test:ECC_FIELD_TYPE_STR
HWTEST_F(CryptoEccAsyKeyGeneratorBySpecSubFourTest, CryptoEccAsyKeyGeneratorBySpecSubFourTest517, TestSize.Level0)
{
    HcfAsyKeyGenerator *generator = nullptr;
    int32_t res = HcfAsyKeyGeneratorCreate("ECC224", &generator);

    HcfKeyPair *keyPair = nullptr;
    res = generator->convertKey(generator, nullptr, &g_mockEcc224PubKeyBlob, &g_mockEcc224PriKeyBlob, &keyPair);

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

HWTEST_F(CryptoEccAsyKeyGeneratorBySpecSubFourTest, CryptoEccAsyKeyGeneratorBySpecSubFourTest518, TestSize.Level0)
{
    HcfAsyKeyGenerator *generator = nullptr;
    int32_t res = HcfAsyKeyGeneratorCreate("ECC224", &generator);

    HcfKeyPair *keyPair = nullptr;
    res = generator->convertKey(generator, nullptr, &g_mockEcc224PubKeyBlob, &g_mockEcc224PriKeyBlob, &keyPair);

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

// for test:ECC_CURVE_NAME_STR
HWTEST_F(CryptoEccAsyKeyGeneratorBySpecSubFourTest, CryptoEccAsyKeyGeneratorBySpecSubFourTest519, TestSize.Level0)
{
    HcfAsyKeyGenerator *generator = nullptr;
    int32_t res = HcfAsyKeyGeneratorCreate("ECC224", &generator);

    HcfKeyPair *keyPair = nullptr;
    res = generator->convertKey(generator, nullptr, &g_mockEcc224PubKeyBlob, &g_mockEcc224PriKeyBlob, &keyPair);

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

HWTEST_F(CryptoEccAsyKeyGeneratorBySpecSubFourTest, CryptoEccAsyKeyGeneratorBySpecSubFourTest520, TestSize.Level0)
{
    HcfAsyKeyGenerator *generator = nullptr;
    int32_t res = HcfAsyKeyGeneratorCreate("ECC224", &generator);

    HcfKeyPair *keyPair = nullptr;
    res = generator->convertKey(generator, nullptr, &g_mockEcc224PubKeyBlob, &g_mockEcc224PriKeyBlob, &keyPair);

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

// for test:ECC_PK_X_BN
HWTEST_F(CryptoEccAsyKeyGeneratorBySpecSubFourTest, CryptoEccAsyKeyGeneratorBySpecSubFourTest521, TestSize.Level0)
{
    HcfAsyKeyGenerator *generator = nullptr;
    int32_t res = HcfAsyKeyGeneratorCreate("ECC224", &generator);

    HcfKeyPair *keyPair = nullptr;
    res = generator->convertKey(generator, nullptr, &g_mockEcc224PubKeyBlob, &g_mockEcc224PriKeyBlob, &keyPair);

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

// for test:ECC_PK_Y_BN
HWTEST_F(CryptoEccAsyKeyGeneratorBySpecSubFourTest, CryptoEccAsyKeyGeneratorBySpecSubFourTest522, TestSize.Level0)
{
    HcfAsyKeyGenerator *generator = nullptr;
    int32_t res = HcfAsyKeyGeneratorCreate("ECC224", &generator);

    HcfKeyPair *keyPair = nullptr;
    res = generator->convertKey(generator, nullptr, &g_mockEcc224PubKeyBlob, &g_mockEcc224PriKeyBlob, &keyPair);

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

// for test:ECC_SK_BN
HWTEST_F(CryptoEccAsyKeyGeneratorBySpecSubFourTest, CryptoEccAsyKeyGeneratorBySpecSubFourTest523, TestSize.Level0)
{
    HcfAsyKeyGenerator *generator = nullptr;
    int32_t res = HcfAsyKeyGeneratorCreate("ECC224", &generator);

    HcfKeyPair *keyPair = nullptr;
    res = generator->convertKey(generator, nullptr, &g_mockEcc224PubKeyBlob, &g_mockEcc224PriKeyBlob, &keyPair);

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

// for test:generateKey after convertKey
HWTEST_F(CryptoEccAsyKeyGeneratorBySpecSubFourTest, CryptoEccAsyKeyGeneratorBySpecSubFourTest524, TestSize.Level0)
{
    HcfAsyKeyParamsSpec *paramSpec = nullptr;
    int32_t res = ConstructEcc224CommParamsSpec(&paramSpec);
    ASSERT_EQ(res, HCF_SUCCESS);
    HcfAsyKeyGeneratorBySpec *generatorBySpec = nullptr;
    res = HcfAsyKeyGeneratorBySpecCreate(paramSpec, &generatorBySpec);
    HcfKeyPair *keyPair = nullptr;
    res = generatorBySpec->generateKeyPair(generatorBySpec, &keyPair);
    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(keyPair, nullptr);
    HcfBlob pubKeyBlob = { .data = nullptr, .len = 0 };
    res = keyPair->pubKey->base.getEncoded(&(keyPair->pubKey->base), &pubKeyBlob);
    ASSERT_EQ(res, HCF_SUCCESS);
    HcfBlob priKeyBlob = { .data = nullptr, .len = 0 };
    res = keyPair->priKey->base.getEncoded(&(keyPair->priKey->base), &priKeyBlob);
    ASSERT_EQ(res, HCF_SUCCESS);
    HcfAsyKeyGenerator *generator = nullptr;
    res = HcfAsyKeyGeneratorCreate("ECC224", &generator);
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
    HcfObjDestroy(outKeyPair);
    HcfObjDestroy(keyPair);
    HcfObjDestroy(generator);
    HcfObjDestroy(generatorBySpec);
}

HWTEST_F(CryptoEccAsyKeyGeneratorBySpecSubFourTest, CryptoEccAsyKeyGeneratorBySpecSubFourTest525, TestSize.Level0)
{
    HcfAsyKeyParamsSpec *paramSpec = nullptr;
    int32_t res = ConstructEcc224CommParamsSpec(&paramSpec);

    ASSERT_EQ(res, HCF_SUCCESS);

    HcfAsyKeyGeneratorBySpec *generatorBySpec = nullptr;
    res = HcfAsyKeyGeneratorBySpecCreate(paramSpec, &generatorBySpec);

    HcfKeyPair *keyPair = nullptr;
    res = generatorBySpec->generateKeyPair(generatorBySpec, &keyPair);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(keyPair, nullptr);

    HcfBlob pubKeyBlob = { .data = nullptr, .len = 0 };
    res = keyPair->pubKey->base.getEncoded(&(keyPair->pubKey->base), &pubKeyBlob);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(pubKeyBlob.data, nullptr);
    ASSERT_NE(pubKeyBlob.len, 0);

    HcfAsyKeyGenerator *generator = nullptr;
    res = HcfAsyKeyGeneratorCreate("ECC224", &generator);

    HcfKeyPair *outKeyPair = nullptr;
    res = generator->convertKey(generator, nullptr, &pubKeyBlob, nullptr, &outKeyPair);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(outKeyPair, nullptr);
    ASSERT_NE(outKeyPair->pubKey, nullptr);
    ASSERT_EQ(outKeyPair->priKey, nullptr);

    HcfBlob outPubKeyBlob = { .data = nullptr, .len = 0 };
    res = outKeyPair->pubKey->base.getEncoded(&(outKeyPair->pubKey->base), &outPubKeyBlob);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(outPubKeyBlob.data, nullptr);
    ASSERT_NE(outPubKeyBlob.len, 0);

    HcfFree(pubKeyBlob.data);
    HcfFree(outPubKeyBlob.data);
    HcfObjDestroy(outKeyPair);
    HcfObjDestroy(keyPair);
    HcfObjDestroy(generator);
    HcfObjDestroy(generatorBySpec);
}

HWTEST_F(CryptoEccAsyKeyGeneratorBySpecSubFourTest, CryptoEccAsyKeyGeneratorBySpecSubFourTest526, TestSize.Level0)
{
    HcfAsyKeyParamsSpec *paramSpec = nullptr;
    int32_t res = ConstructEcc224CommParamsSpec(&paramSpec);

    ASSERT_EQ(res, HCF_SUCCESS);

    HcfAsyKeyGeneratorBySpec *generatorBySpec = nullptr;
    res = HcfAsyKeyGeneratorBySpecCreate(paramSpec, &generatorBySpec);

    HcfKeyPair *keyPair = nullptr;
    res = generatorBySpec->generateKeyPair(generatorBySpec, &keyPair);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(keyPair, nullptr);

    HcfBlob priKeyBlob = { .data = nullptr, .len = 0 };
    res = keyPair->priKey->base.getEncoded(&(keyPair->priKey->base), &priKeyBlob);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(priKeyBlob.data, nullptr);
    ASSERT_NE(priKeyBlob.len, 0);

    HcfAsyKeyGenerator *generator = nullptr;
    res = HcfAsyKeyGeneratorCreate("ECC224", &generator);

    HcfKeyPair *outKeyPair = nullptr;
    res = generator->convertKey(generator, nullptr, nullptr, &priKeyBlob, &outKeyPair);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(outKeyPair, nullptr);
    ASSERT_EQ(outKeyPair->pubKey, nullptr);
    ASSERT_NE(outKeyPair->priKey, nullptr);

    HcfBlob outPriKeyBlob = { .data = nullptr, .len = 0 };
    res = outKeyPair->priKey->base.getEncoded(&(outKeyPair->priKey->base), &outPriKeyBlob);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(outPriKeyBlob.data, nullptr);
    ASSERT_NE(outPriKeyBlob.len, 0);

    HcfFree(priKeyBlob.data);
    HcfFree(outPriKeyBlob.data);
    HcfObjDestroy(outKeyPair);
    HcfObjDestroy(keyPair);
    HcfObjDestroy(generator);
    HcfObjDestroy(generatorBySpec);
}

// for test:测试ecc的spi类
HWTEST_F(CryptoEccAsyKeyGeneratorBySpecSubFourTest, CryptoEccAsyKeyGeneratorBySpecSubFourTest601, TestSize.Level0)
{
    HcfAsyKeyGenParams params = {
        .algo = HCF_ALG_ECC,
        .bits = 0,
        .primes = HCF_OPENSSL_PRIMES_2,
    };

    HcfAsyKeyGeneratorSpi *spiObj = nullptr;
    int32_t res = HcfAsyKeyGeneratorSpiEccCreate(&params, &spiObj);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(spiObj, nullptr);

    HcfObjDestroy(spiObj);
}

HWTEST_F(CryptoEccAsyKeyGeneratorBySpecSubFourTest, CryptoEccAsyKeyGeneratorBySpecSubFourTest602, TestSize.Level0)
{
    HcfAsyKeyGenParams params = {
        .algo = HCF_ALG_ECC,
        .bits = HCF_ALG_MODE_NONE,
        .primes = HCF_OPENSSL_PRIMES_2,
    };

    HcfAsyKeyGeneratorSpi *spiObj = nullptr;
    int32_t res = HcfAsyKeyGeneratorSpiEccCreate(&params, &spiObj);

    ASSERT_EQ(res, HCF_INVALID_PARAMS);
    ASSERT_EQ(spiObj, nullptr);
}

HWTEST_F(CryptoEccAsyKeyGeneratorBySpecSubFourTest, CryptoEccAsyKeyGeneratorBySpecSubFourTest603, TestSize.Level0)
{
    HcfAsyKeyGenParams params = {
        .algo = HCF_ALG_ECC,
        .bits = 0,
        .primes = HCF_OPENSSL_PRIMES_2,
    };

    HcfAsyKeyGeneratorSpi *spiObj = nullptr;
    int32_t res = HcfAsyKeyGeneratorSpiEccCreate(&params, &spiObj);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(spiObj, nullptr);

    HcfAsyKeyParamsSpec *paramSpec = nullptr;
    res = ConstructEcc224CommParamsSpec(&paramSpec);

    ASSERT_EQ(res, HCF_SUCCESS);

    HcfKeyPair *keyPair = nullptr;
    res = spiObj->engineGenerateKeyPairBySpec(spiObj, paramSpec, &keyPair);
    ASSERT_EQ(res, HCF_SUCCESS);

    HcfObjDestroy(keyPair);
    HcfObjDestroy(spiObj);
}

HWTEST_F(CryptoEccAsyKeyGeneratorBySpecSubFourTest, CryptoEccAsyKeyGeneratorBySpecSubFourTest604, TestSize.Level0)
{
    HcfAsyKeyGenParams params = {
        .algo = HCF_ALG_ECC,
        .bits = 0,
        .primes = HCF_OPENSSL_PRIMES_2,
    };

    HcfAsyKeyGeneratorSpi *spiObj = nullptr;
    int32_t res = HcfAsyKeyGeneratorSpiEccCreate(&params, &spiObj);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(spiObj, nullptr);

    HcfAsyKeyParamsSpec *paramSpec = nullptr;
    res = ConstructEcc224PubKeyParamsSpec(&paramSpec);

    ASSERT_EQ(res, HCF_SUCCESS);

    HcfPubKey *pubKey = nullptr;
    res = spiObj->engineGeneratePubKeyBySpec(spiObj, paramSpec, &pubKey);
    ASSERT_EQ(res, HCF_SUCCESS);

    HcfObjDestroy(pubKey);
    HcfObjDestroy(spiObj);
}

HWTEST_F(CryptoEccAsyKeyGeneratorBySpecSubFourTest, CryptoEccAsyKeyGeneratorBySpecSubFourTest605, TestSize.Level0)
{
    HcfAsyKeyGenParams params = {
        .algo = HCF_ALG_ECC,
        .bits = 0,
        .primes = HCF_OPENSSL_PRIMES_2,
    };

    HcfAsyKeyGeneratorSpi *spiObj = nullptr;
    int32_t res = HcfAsyKeyGeneratorSpiEccCreate(&params, &spiObj);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(spiObj, nullptr);

    HcfAsyKeyParamsSpec *paramSpec = nullptr;
    res = ConstructEcc224PriKeyParamsSpec(&paramSpec);

    ASSERT_EQ(res, HCF_SUCCESS);

    HcfPriKey *priKey = nullptr;
    res = spiObj->engineGeneratePriKeyBySpec(spiObj, paramSpec, &priKey);
    ASSERT_EQ(res, HCF_SUCCESS);

    HcfObjDestroy(priKey);
    HcfObjDestroy(spiObj);
}

HWTEST_F(CryptoEccAsyKeyGeneratorBySpecSubFourTest, CryptoEccAsyKeyGeneratorBySpecSubFourTest606, TestSize.Level0)
{
    HcfAsyKeyGenParams params = {
        .algo = HCF_ALG_ECC,
        .bits = 0,
        .primes = HCF_OPENSSL_PRIMES_2,
    };

    HcfAsyKeyGeneratorSpi *spiObj = nullptr;
    int32_t res = HcfAsyKeyGeneratorSpiEccCreate(&params, &spiObj);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(spiObj, nullptr);

    HcfAsyKeyParamsSpec *paramSpec = nullptr;
    res = ConstructEcc224KeyPairParamsSpec(&paramSpec);

    ASSERT_EQ(res, HCF_SUCCESS);

    HcfKeyPair *keyPair = nullptr;
    res = spiObj->engineGenerateKeyPairBySpec(spiObj, paramSpec, &keyPair);
    ASSERT_EQ(res, HCF_SUCCESS);

    HcfObjDestroy(keyPair);
    HcfObjDestroy(spiObj);
}

HWTEST_F(CryptoEccAsyKeyGeneratorBySpecSubFourTest, CryptoEccAsyKeyGeneratorBySpecSubFourTest607, TestSize.Level0)
{
    HcfAsyKeyGenParams params = {
        .algo = HCF_ALG_ECC,
        .bits = 0,
        .primes = HCF_OPENSSL_PRIMES_2,
    };

    HcfAsyKeyGeneratorSpi *spiObj = nullptr;
    int32_t res = HcfAsyKeyGeneratorSpiEccCreate(&params, &spiObj);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(spiObj, nullptr);

    spiObj->base.destroy(nullptr);

    HcfObjDestroy(spiObj);
}

HWTEST_F(CryptoEccAsyKeyGeneratorBySpecSubFourTest, CryptoEccAsyKeyGeneratorBySpecSubFourTest608, TestSize.Level0)
{
    HcfAsyKeyGenParams params = {
        .algo = HCF_ALG_ECC,
        .bits = 0,
        .primes = HCF_OPENSSL_PRIMES_2,
    };

    HcfAsyKeyGeneratorSpi *spiObj = nullptr;
    int32_t res = HcfAsyKeyGeneratorSpiEccCreate(&params, &spiObj);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(spiObj, nullptr);

    spiObj->base.destroy(&g_obj);

    HcfObjDestroy(spiObj);
}

static HcfResult ConstructEcc521KeyPairParamsSpecByGet(HcfEccKeyPairParamsSpec *eccKeyPairSpec,
    HcfBigInteger *params, int h)
{
    HcfECField *tmpField = (HcfECField *)(&g_fieldFp);

    eccKeyPairSpec->base.base.algName = const_cast<char *>(g_eccAlgName.c_str());
    eccKeyPairSpec->base.base.specType = HCF_KEY_PAIR_SPEC;
    eccKeyPairSpec->base.field = tmpField;
    eccKeyPairSpec->base.field->fieldType = const_cast<char *>(g_eccFieldType.c_str());
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
    int32_t res = priKey->getAsyKeySpecBigInteger(priKey, ECC_FP_P_BN, &retFp);
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

HWTEST_F(CryptoEccAsyKeyGeneratorBySpecSubFourTest, CryptoEccAsyKeyGeneratorBySpecSubFourTest609, TestSize.Level0)
{
    HcfAsyKeyGenerator *generator = nullptr;
    int32_t res = HcfAsyKeyGeneratorCreate("ECC521", &generator);

    HcfKeyPair *keyPair = nullptr;
    res = generator->generateKeyPair(generator, nullptr, &keyPair);

    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(keyPair, nullptr);

    int retH = 0;
    HcfBigInteger params[9];
    GetParams(keyPair->priKey, keyPair->pubKey, params, &retH);

    HcfEccKeyPairParamsSpec eccKeyPairSpec = {};
    res = ConstructEcc521KeyPairParamsSpecByGet(&eccKeyPairSpec, params, retH);
    HcfAsyKeyGeneratorBySpec *generatorSpec = nullptr;
    res = HcfAsyKeyGeneratorBySpecCreate(reinterpret_cast<HcfAsyKeyParamsSpec *>(&eccKeyPairSpec), &generatorSpec);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(generatorSpec, nullptr);

    HcfKeyPair *dupKeyPair = nullptr;
    res = generatorSpec->generateKeyPair(generatorSpec, &dupKeyPair);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(dupKeyPair, nullptr);

    HcfOpensslEccPubKey *eccPubKey = reinterpret_cast<HcfOpensslEccPubKey *>(dupKeyPair->pubKey);
    int32_t curveId = eccPubKey->curveId;
    EXPECT_EQ(curveId, NID_secp521r1) << "the curId is " << NID_secp521r1;
    for (HcfBigInteger tmp: params) {
        if (tmp.data != nullptr) {
            HcfFree(tmp.data);
        }
    }
    HcfObjDestroy(dupKeyPair);
    HcfObjDestroy(keyPair);
    HcfObjDestroy(generator);
    HcfObjDestroy(generatorSpec);
}

HWTEST_F(CryptoEccAsyKeyGeneratorBySpecSubFourTest, CryptoEccAsyKeyGeneratorBySpecSubFourTest610, TestSize.Level0)
{
    HcfAsyKeyGenParams params = {
        .algo = HCF_ALG_ECC,
        .bits = HCF_ALG_ECC_224,
        .primes = HCF_OPENSSL_PRIMES_2,
    };

    HcfAsyKeyGeneratorSpi *spiObj = nullptr;
    int32_t res = HcfAsyKeyGeneratorSpiEccCreate(&params, &spiObj);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(spiObj, nullptr);

    HcfAsyKeyParamsSpec *paramSpec = nullptr;
    res = ConstructEcc224ErrCommParamsSpec(&paramSpec);

    ASSERT_EQ(res, HCF_SUCCESS);

    HcfKeyPair *keyPair = nullptr;
    res = spiObj->engineGenerateKeyPairBySpec(spiObj, paramSpec, &keyPair);
    ASSERT_NE(res, HCF_SUCCESS);

    HcfObjDestroy(spiObj);
}

HWTEST_F(CryptoEccAsyKeyGeneratorBySpecSubFourTest, CryptoEccAsyKeyGeneratorBySpecSubFourTest611, TestSize.Level0)
{
    HcfAsyKeyGenParams params = {
        .algo = HCF_ALG_ECC,
        .bits = HCF_ALG_ECC_521,
        .primes = HCF_OPENSSL_PRIMES_2,
    };

    HcfAsyKeyGeneratorSpi *spiObj = nullptr;
    int32_t res = HcfAsyKeyGeneratorSpiEccCreate(&params, &spiObj);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(spiObj, nullptr);

    HcfAsyKeyParamsSpec *paramSpec = nullptr;
    res = ConstructEcc521ErrKeyPairParamsSpec(&paramSpec);

    ASSERT_EQ(res, HCF_SUCCESS);

    HcfKeyPair *keyPair = nullptr;
    res = spiObj->engineGenerateKeyPairBySpec(spiObj, paramSpec, &keyPair);
    ASSERT_NE(res, HCF_SUCCESS);

    HcfObjDestroy(spiObj);
}

HWTEST_F(CryptoEccAsyKeyGeneratorBySpecSubFourTest, CryptoEccAsyKeyGeneratorBySpecSubFourTest612, TestSize.Level0)
{
    HcfAsyKeyGenParams params = {
        .algo = HCF_ALG_ECC,
        .bits = HCF_ALG_ECC_224,
        .primes = HCF_OPENSSL_PRIMES_2,
    };

    HcfAsyKeyGeneratorSpi *spiObj = nullptr;
    int32_t res = HcfAsyKeyGeneratorSpiEccCreate(&params, &spiObj);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(spiObj, nullptr);

    HcfAsyKeyParamsSpec *paramSpec = nullptr;
    res = ConstructEcc224ErrPubKeyParamsSpec(&paramSpec);

    ASSERT_EQ(res, HCF_SUCCESS);

    HcfPubKey *keyPair = nullptr;
    res = spiObj->engineGeneratePubKeyBySpec(spiObj, paramSpec, &keyPair);
    ASSERT_NE(res, HCF_SUCCESS);

    HcfObjDestroy(spiObj);
}

HWTEST_F(CryptoEccAsyKeyGeneratorBySpecSubFourTest, CryptoEccAsyKeyGeneratorBySpecSubFourTest613, TestSize.Level0)
{
    HcfAsyKeyGenParams params = {
        .algo = HCF_ALG_ECC,
        .bits = HCF_ALG_ECC_224,
        .primes = HCF_OPENSSL_PRIMES_2,
    };

    HcfAsyKeyGeneratorSpi *spiObj = nullptr;
    int32_t res = HcfAsyKeyGeneratorSpiEccCreate(&params, &spiObj);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(spiObj, nullptr);

    HcfAsyKeyParamsSpec *paramSpec = nullptr;
    res = ConstructEcc224ErrPriKeyParamsSpec(&paramSpec);

    ASSERT_EQ(res, HCF_SUCCESS);

    HcfPriKey *keyPair = nullptr;
    res = spiObj->engineGeneratePriKeyBySpec(spiObj, paramSpec, &keyPair);
    ASSERT_NE(res, HCF_SUCCESS);

    HcfObjDestroy(spiObj);
}

HWTEST_F(CryptoEccAsyKeyGeneratorBySpecSubFourTest, CryptoEccAsyKeyGeneratorBySpecSubFourTest614, TestSize.Level0)
{
    HcfAsyKeyGenParams params = {
        .algo = HCF_ALG_ECC,
        .bits = HCF_ALG_ECC_256,
        .primes = HCF_OPENSSL_PRIMES_2,
    };

    HcfAsyKeyGeneratorSpi *spiObj = nullptr;
    int32_t res = HcfAsyKeyGeneratorSpiEccCreate(&params, &spiObj);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(spiObj, nullptr);

    HcfAsyKeyParamsSpec *paramSpec = nullptr;
    res = ConstructEcc256ErrCommParamsSpec(&paramSpec);

    ASSERT_EQ(res, HCF_SUCCESS);

    HcfKeyPair *keyPair = nullptr;
    res = spiObj->engineGenerateKeyPairBySpec(spiObj, paramSpec, &keyPair);
    ASSERT_NE(res, HCF_SUCCESS);

    HcfObjDestroy(spiObj);
}

HWTEST_F(CryptoEccAsyKeyGeneratorBySpecSubFourTest, CryptoEccAsyKeyGeneratorBySpecSubFourTest615, TestSize.Level0)
{
    HcfAsyKeyGenParams params = {
        .algo = HCF_ALG_ECC,
        .bits = HCF_ALG_ECC_384,
        .primes = HCF_OPENSSL_PRIMES_2,
    };

    HcfAsyKeyGeneratorSpi *spiObj = nullptr;
    int32_t res = HcfAsyKeyGeneratorSpiEccCreate(&params, &spiObj);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(spiObj, nullptr);

    HcfAsyKeyParamsSpec *paramSpec = nullptr;
    res = ConstructEcc384ErrCommParamsSpec(&paramSpec);

    ASSERT_EQ(res, HCF_SUCCESS);

    HcfKeyPair *keyPair = nullptr;
    res = spiObj->engineGenerateKeyPairBySpec(spiObj, paramSpec, &keyPair);
    ASSERT_NE(res, HCF_SUCCESS);

    HcfObjDestroy(spiObj);
}

HWTEST_F(CryptoEccAsyKeyGeneratorBySpecSubFourTest, CryptoEccAsyKeyGeneratorBySpecSubFourTest616, TestSize.Level0)
{
    HcfAsyKeyGenParams params = {
        .algo = HCF_ALG_ECC,
        .bits = HCF_ALG_ECC_521,
        .primes = HCF_OPENSSL_PRIMES_2,
    };

    HcfAsyKeyGeneratorSpi *spiObj = nullptr;
    int32_t res = HcfAsyKeyGeneratorSpiEccCreate(&params, &spiObj);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(spiObj, nullptr);

    HcfAsyKeyParamsSpec *paramSpec = nullptr;
    res = ConstructEcc521ErrCommParamsSpec(&paramSpec);

    ASSERT_EQ(res, HCF_SUCCESS);

    HcfKeyPair *keyPair = nullptr;
    res = spiObj->engineGenerateKeyPairBySpec(spiObj, paramSpec, &keyPair);
    ASSERT_NE(res, HCF_SUCCESS);

    HcfObjDestroy(spiObj);
}

HWTEST_F(CryptoEccAsyKeyGeneratorBySpecSubFourTest, CryptoEccAsyKeyGeneratorBySpecSubFourTest617, TestSize.Level0)
{
    HcfAsyKeyGenParams params = {
        .algo = HCF_ALG_ECC,
        .bits = HCF_ALG_ECC_521,
        .primes = HCF_OPENSSL_PRIMES_2,
    };

    HcfAsyKeyGeneratorSpi *spiObj = nullptr;
    int32_t res = HcfAsyKeyGeneratorSpiEccCreate(&params, &spiObj);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(spiObj, nullptr);

    HcfAsyKeyParamsSpec *paramSpec = nullptr;
    res = ConstructEcc384ErrKeyPairParamsSpec(&paramSpec);

    ASSERT_EQ(res, HCF_SUCCESS);

    HcfKeyPair *keyPair = nullptr;
    res = spiObj->engineGenerateKeyPairBySpec(spiObj, paramSpec, &keyPair);
    ASSERT_NE(res, HCF_SUCCESS);

    HcfObjDestroy(spiObj);
}
}
