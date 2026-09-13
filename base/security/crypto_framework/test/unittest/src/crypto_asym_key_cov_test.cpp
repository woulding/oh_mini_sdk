/*
 * Copyright (C) 2026 Huawei Device Co., Ltd.
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
#include "crypto_common.h"
#include "crypto_asym_key.h"
#include "blob.h"
#include "memory.h"
#include "memory_mock.h"
#include "securec.h"
#include "result.h"
#include "utils.h"
#include "crypto_operation_err.h"
#include "asy_key_generator.h"
#include "kem.h"
#include "asy_key_params.h"
#include "detailed_rsa_key_params.h"
#include "ecc_key_util.h"

using namespace std;
using namespace testing::ext;

namespace {
class CryptoAsymKeyCovTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp();
    void TearDown();
};

void CryptoAsymKeyCovTest::SetUpTestCase() {}
void CryptoAsymKeyCovTest::TearDownTestCase() {}
void CryptoAsymKeyCovTest::SetUp() {}
void CryptoAsymKeyCovTest::TearDown() {}

HWTEST_F(CryptoAsymKeyCovTest, MlKemMallocFailTest001, TestSize.Level0)
{
    OH_CryptoAsymKeyGenerator *generator = nullptr;
    OH_Crypto_ErrCode res = OH_CryptoAsymKeyGenerator_Create("ML-KEM-768", &generator);
    ASSERT_EQ(res, CRYPTO_SUCCESS);

    OH_CryptoKeyPair *keyPair = nullptr;
    StartRecordMallocNum();
    SetMockMallocIndex(0);
    res = OH_CryptoAsymKeyGenerator_Generate(generator, &keyPair);
    EndRecordMallocNum();
    EXPECT_NE(res, CRYPTO_SUCCESS);

    OH_CryptoAsymKeyGenerator_Destroy(generator);
}

HWTEST_F(CryptoAsymKeyCovTest, MlDsaMallocFailTest001, TestSize.Level0)
{
    OH_CryptoAsymKeyGenerator *generator = nullptr;
    OH_Crypto_ErrCode res = OH_CryptoAsymKeyGenerator_Create("ML-DSA-65", &generator);
    ASSERT_EQ(res, CRYPTO_SUCCESS);

    OH_CryptoKeyPair *keyPair = nullptr;
    StartRecordMallocNum();
    SetMockMallocIndex(0);
    res = OH_CryptoAsymKeyGenerator_Generate(generator, &keyPair);
    EndRecordMallocNum();
    EXPECT_NE(res, CRYPTO_SUCCESS);

    OH_CryptoAsymKeyGenerator_Destroy(generator);
}

HWTEST_F(CryptoAsymKeyCovTest, KemMallocFailTest001, TestSize.Level0)
{
    HcfKem *kem = nullptr;
    HcfResult res = HcfKemCreate("ML-KEM768", &kem);
    ASSERT_EQ(res, HCF_SUCCESS);

    HcfBlob wrappedKey = {.data = nullptr, .len = 0};
    HcfBlob sharedSecret = {.data = nullptr, .len = 0};
    StartRecordMallocNum();
    SetMockMallocIndex(0);
    res = kem->encapsulate(kem, nullptr, nullptr, &sharedSecret, &wrappedKey);
    EndRecordMallocNum();
    EXPECT_NE(res, HCF_SUCCESS);

    HcfObjDestroy(kem);
}

HWTEST_F(CryptoAsymKeyCovTest, RsaMallocFailTest001, TestSize.Level0)
{
    OH_CryptoAsymKeyGenerator *generator = nullptr;
    OH_Crypto_ErrCode res = OH_CryptoAsymKeyGenerator_Create("RSA2048|PRIMES_2", &generator);
    ASSERT_EQ(res, CRYPTO_SUCCESS);

    OH_CryptoKeyPair *keyPair = nullptr;
    StartRecordMallocNum();
    SetMockMallocIndex(0);
    res = OH_CryptoAsymKeyGenerator_Generate(generator, &keyPair);
    EndRecordMallocNum();
    EXPECT_NE(res, CRYPTO_SUCCESS);

    OH_CryptoAsymKeyGenerator_Destroy(generator);
}

HWTEST_F(CryptoAsymKeyCovTest, EccMallocFailTest001, TestSize.Level0)
{
    OH_CryptoAsymKeyGenerator *generator = nullptr;
    OH_Crypto_ErrCode res = OH_CryptoAsymKeyGenerator_Create("ECC256", &generator);
    ASSERT_EQ(res, CRYPTO_SUCCESS);

    OH_CryptoKeyPair *keyPair = nullptr;
    StartRecordMallocNum();
    SetMockMallocIndex(0);
    res = OH_CryptoAsymKeyGenerator_Generate(generator, &keyPair);
    EndRecordMallocNum();
    EXPECT_NE(res, CRYPTO_SUCCESS);

    OH_CryptoAsymKeyGenerator_Destroy(generator);
}

HWTEST_F(CryptoAsymKeyCovTest, Sm2MallocFailTest001, TestSize.Level0)
{
    OH_CryptoAsymKeyGenerator *generator = nullptr;
    OH_Crypto_ErrCode res = OH_CryptoAsymKeyGenerator_Create("SM2_256", &generator);
    ASSERT_EQ(res, CRYPTO_SUCCESS);

    OH_CryptoKeyPair *keyPair = nullptr;
    StartRecordMallocNum();
    SetMockMallocIndex(0);
    res = OH_CryptoAsymKeyGenerator_Generate(generator, &keyPair);
    EndRecordMallocNum();
    EXPECT_NE(res, CRYPTO_SUCCESS);

    OH_CryptoAsymKeyGenerator_Destroy(generator);
}

HWTEST_F(CryptoAsymKeyCovTest, DhMallocFailTest001, TestSize.Level0)
{
    OH_CryptoAsymKeyGenerator *generator = nullptr;
    OH_Crypto_ErrCode res = OH_CryptoAsymKeyGenerator_Create("DH_modp2048", &generator);
    ASSERT_EQ(res, CRYPTO_SUCCESS);

    OH_CryptoKeyPair *keyPair = nullptr;
    StartRecordMallocNum();
    SetMockMallocIndex(0);
    res = OH_CryptoAsymKeyGenerator_Generate(generator, &keyPair);
    EndRecordMallocNum();
    EXPECT_NE(res, CRYPTO_SUCCESS);

    OH_CryptoAsymKeyGenerator_Destroy(generator);
}

HWTEST_F(CryptoAsymKeyCovTest, MlKemMallocFailSecondTest001, TestSize.Level0)
{
    OH_CryptoAsymKeyGenerator *generator = nullptr;
    OH_Crypto_ErrCode res = OH_CryptoAsymKeyGenerator_Create("ML-KEM-768", &generator);
    ASSERT_EQ(res, CRYPTO_SUCCESS);

    OH_CryptoKeyPair *keyPair = nullptr;
    StartRecordMallocNum();
    SetMockMallocIndex(1);
    res = OH_CryptoAsymKeyGenerator_Generate(generator, &keyPair);
    EndRecordMallocNum();
    EXPECT_NE(res, CRYPTO_SUCCESS);

    OH_CryptoAsymKeyGenerator_Destroy(generator);
}

HWTEST_F(CryptoAsymKeyCovTest, MlDsaMallocFailSecondTest001, TestSize.Level0)
{
    OH_CryptoAsymKeyGenerator *generator = nullptr;
    OH_Crypto_ErrCode res = OH_CryptoAsymKeyGenerator_Create("ML-DSA-65", &generator);
    ASSERT_EQ(res, CRYPTO_SUCCESS);

    OH_CryptoKeyPair *keyPair = nullptr;
    StartRecordMallocNum();
    SetMockMallocIndex(1);
    res = OH_CryptoAsymKeyGenerator_Generate(generator, &keyPair);
    EndRecordMallocNum();
    EXPECT_NE(res, CRYPTO_SUCCESS);

    OH_CryptoAsymKeyGenerator_Destroy(generator);
}

HWTEST_F(CryptoAsymKeyCovTest, MlKemMallocFailThirdTest001, TestSize.Level0)
{
    OH_CryptoAsymKeyGenerator *generator = nullptr;
    OH_Crypto_ErrCode res = OH_CryptoAsymKeyGenerator_Create("ML-KEM-768", &generator);
    ASSERT_EQ(res, CRYPTO_SUCCESS);

    OH_CryptoKeyPair *keyPair = nullptr;
    StartRecordMallocNum();
    SetMockMallocIndex(2);
    res = OH_CryptoAsymKeyGenerator_Generate(generator, &keyPair);
    EndRecordMallocNum();
    EXPECT_NE(res, CRYPTO_SUCCESS);

    OH_CryptoAsymKeyGenerator_Destroy(generator);
}

HWTEST_F(CryptoAsymKeyCovTest, MlDsaMallocFailThirdTest001, TestSize.Level0)
{
    OH_CryptoAsymKeyGenerator *generator = nullptr;
    OH_Crypto_ErrCode res = OH_CryptoAsymKeyGenerator_Create("ML-DSA-65", &generator);
    ASSERT_EQ(res, CRYPTO_SUCCESS);

    OH_CryptoKeyPair *keyPair = nullptr;
    StartRecordMallocNum();
    SetMockMallocIndex(2);
    res = OH_CryptoAsymKeyGenerator_Generate(generator, &keyPair);
    EndRecordMallocNum();
    EXPECT_NE(res, CRYPTO_SUCCESS);

    OH_CryptoAsymKeyGenerator_Destroy(generator);
}

HWTEST_F(CryptoAsymKeyCovTest, KemMallocFailSecondTest001, TestSize.Level0)
{
    HcfKem *kem = nullptr;
    HcfResult res = HcfKemCreate("ML-KEM768", &kem);
    ASSERT_EQ(res, HCF_SUCCESS);

    HcfBlob wrappedKey = {.data = nullptr, .len = 0};
    HcfBlob sharedSecret = {.data = nullptr, .len = 0};
    StartRecordMallocNum();
    SetMockMallocIndex(1);
    res = kem->encapsulate(kem, nullptr, nullptr, &sharedSecret, &wrappedKey);
    EndRecordMallocNum();
    EXPECT_NE(res, HCF_SUCCESS);

    HcfObjDestroy(kem);
}

HWTEST_F(CryptoAsymKeyCovTest, RsaMallocFailSecondTest001, TestSize.Level0)
{
    OH_CryptoAsymKeyGenerator *generator = nullptr;
    OH_Crypto_ErrCode res = OH_CryptoAsymKeyGenerator_Create("RSA2048|PRIMES_2", &generator);
    ASSERT_EQ(res, CRYPTO_SUCCESS);

    OH_CryptoKeyPair *keyPair = nullptr;
    StartRecordMallocNum();
    SetMockMallocIndex(1);
    res = OH_CryptoAsymKeyGenerator_Generate(generator, &keyPair);
    EndRecordMallocNum();
    EXPECT_NE(res, CRYPTO_SUCCESS);

    OH_CryptoAsymKeyGenerator_Destroy(generator);
}

HWTEST_F(CryptoAsymKeyCovTest, EccMallocFailSecondTest001, TestSize.Level0)
{
    OH_CryptoAsymKeyGenerator *generator = nullptr;
    OH_Crypto_ErrCode res = OH_CryptoAsymKeyGenerator_Create("ECC256", &generator);
    ASSERT_EQ(res, CRYPTO_SUCCESS);

    OH_CryptoKeyPair *keyPair = nullptr;
    StartRecordMallocNum();
    SetMockMallocIndex(1);
    res = OH_CryptoAsymKeyGenerator_Generate(generator, &keyPair);
    EndRecordMallocNum();
    EXPECT_NE(res, CRYPTO_SUCCESS);

    OH_CryptoAsymKeyGenerator_Destroy(generator);
}

HWTEST_F(CryptoAsymKeyCovTest, MlKemPriKeyGetAlgorithmTest001, TestSize.Level0)
{
    HcfAsyKeyGenerator *generator = nullptr;
    HcfResult res = HcfAsyKeyGeneratorCreate("ML-KEM-768", &generator);
    ASSERT_EQ(res, HCF_SUCCESS);

    HcfKeyPair *keyPair = nullptr;
    res = generator->generateKeyPair(generator, nullptr, &keyPair);
    ASSERT_EQ(res, HCF_SUCCESS);

    const char *algoName = keyPair->priKey->base.getAlgorithm(&(keyPair->priKey->base));
    EXPECT_NE(algoName, nullptr);

    HcfObjDestroy(keyPair);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoAsymKeyCovTest, MlDsaPriKeyGetAlgorithmTest001, TestSize.Level0)
{
    HcfAsyKeyGenerator *generator = nullptr;
    HcfResult res = HcfAsyKeyGeneratorCreate("ML-DSA-65", &generator);
    ASSERT_EQ(res, HCF_SUCCESS);

    HcfKeyPair *keyPair = nullptr;
    res = generator->generateKeyPair(generator, nullptr, &keyPair);
    ASSERT_EQ(res, HCF_SUCCESS);

    const char *algoName = keyPair->priKey->base.getAlgorithm(&(keyPair->priKey->base));
    EXPECT_NE(algoName, nullptr);

    HcfObjDestroy(keyPair);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoAsymKeyCovTest, MlDsaGetStrSpecFromPubKeyTest001, TestSize.Level0)
{
    HcfAsyKeyGenerator *generator = nullptr;
    HcfResult res = HcfAsyKeyGeneratorCreate("ML-DSA-65", &generator);
    ASSERT_EQ(res, HCF_SUCCESS);

    HcfKeyPair *keyPair = nullptr;
    res = generator->generateKeyPair(generator, nullptr, &keyPair);
    ASSERT_EQ(res, HCF_SUCCESS);

    char *returnStr = nullptr;
    res = keyPair->pubKey->getAsyKeySpecString(keyPair->pubKey, ML_DSA_65_PK_BN, &returnStr);
    EXPECT_NE(res, HCF_SUCCESS);

    HcfObjDestroy(keyPair);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoAsymKeyCovTest, MlDsaGetStrSpecFromPriKeyTest001, TestSize.Level0)
{
    HcfAsyKeyGenerator *generator = nullptr;
    HcfResult res = HcfAsyKeyGeneratorCreate("ML-DSA-65", &generator);
    ASSERT_EQ(res, HCF_SUCCESS);

    HcfKeyPair *keyPair = nullptr;
    res = generator->generateKeyPair(generator, nullptr, &keyPair);
    ASSERT_EQ(res, HCF_SUCCESS);

    char *returnStr = nullptr;
    res = keyPair->priKey->getAsyKeySpecString(keyPair->priKey, ML_DSA_65_SK_BN, &returnStr);
    EXPECT_NE(res, HCF_SUCCESS);

    HcfObjDestroy(keyPair);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoAsymKeyCovTest, MlKemPriKeyGetAlgorithmNullTest001, TestSize.Level0)
{
    HcfAsyKeyGenerator *generator = nullptr;
    HcfResult res = HcfAsyKeyGeneratorCreate("ML-KEM-768", &generator);
    ASSERT_EQ(res, HCF_SUCCESS);

    HcfKeyPair *keyPair = nullptr;
    res = generator->generateKeyPair(generator, nullptr, &keyPair);
    ASSERT_EQ(res, HCF_SUCCESS);

    const char *algoName = keyPair->priKey->base.getAlgorithm(nullptr);
    EXPECT_EQ(algoName, nullptr);

    HcfObjDestroy(keyPair);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoAsymKeyCovTest, MlDsaPriKeyGetAlgorithmNullTest001, TestSize.Level0)
{
    HcfAsyKeyGenerator *generator = nullptr;
    HcfResult res = HcfAsyKeyGeneratorCreate("ML-DSA-65", &generator);
    ASSERT_EQ(res, HCF_SUCCESS);

    HcfKeyPair *keyPair = nullptr;
    res = generator->generateKeyPair(generator, nullptr, &keyPair);
    ASSERT_EQ(res, HCF_SUCCESS);

    const char *algoName = keyPair->priKey->base.getAlgorithm(nullptr);
    EXPECT_EQ(algoName, nullptr);

    HcfObjDestroy(keyPair);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoAsymKeyCovTest, RsaGetKeySpecStringTest001, TestSize.Level0)
{
    HcfAsyKeyGenerator *generator = nullptr;
    HcfResult res = HcfAsyKeyGeneratorCreate("RSA2048|PRIMES_2", &generator);
    ASSERT_EQ(res, HCF_SUCCESS);

    HcfKeyPair *keyPair = nullptr;
    res = generator->generateKeyPair(generator, nullptr, &keyPair);
    ASSERT_EQ(res, HCF_SUCCESS);

    char *returnStr = nullptr;
    res = keyPair->pubKey->getAsyKeySpecString(keyPair->pubKey, RSA_N_BN, &returnStr);
    HcfFree(returnStr);

    HcfObjDestroy(keyPair);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoAsymKeyCovTest, RsaGetKeySpecStringPriKeyTest001, TestSize.Level0)
{
    HcfAsyKeyGenerator *generator = nullptr;
    HcfResult res = HcfAsyKeyGeneratorCreate("RSA2048|PRIMES_2", &generator);
    ASSERT_EQ(res, HCF_SUCCESS);

    HcfKeyPair *keyPair = nullptr;
    res = generator->generateKeyPair(generator, nullptr, &keyPair);
    ASSERT_EQ(res, HCF_SUCCESS);

    char *returnStr = nullptr;
    res = keyPair->priKey->getAsyKeySpecString(keyPair->priKey, RSA_N_BN, &returnStr);
    HcfFree(returnStr);

    HcfObjDestroy(keyPair);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoAsymKeyCovTest, DhGetEncodedDerTest001, TestSize.Level0)
{
    HcfAsyKeyGenerator *generator = nullptr;
    HcfResult res = HcfAsyKeyGeneratorCreate("DH_modp2048", &generator);
    ASSERT_EQ(res, HCF_SUCCESS);

    HcfKeyPair *keyPair = nullptr;
    res = generator->generateKeyPair(generator, nullptr, &keyPair);
    ASSERT_EQ(res, HCF_SUCCESS);

    HcfBlob pubDer = {.data = nullptr, .len = 0};
    res = keyPair->pubKey->getEncodedDer(keyPair->pubKey, "X509", &pubDer);
    HcfBlobDataClearAndFree(&pubDer);

    HcfBlob priDer = {.data = nullptr, .len = 0};
    res = keyPair->priKey->getEncodedDer(keyPair->priKey, "PKCS8", &priDer);
    HcfBlobDataClearAndFree(&priDer);

    HcfObjDestroy(keyPair);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoAsymKeyCovTest, Sm2GetEncodedDerTest001, TestSize.Level0)
{
    HcfAsyKeyGenerator *generator = nullptr;
    HcfResult res = HcfAsyKeyGeneratorCreate("SM2_256", &generator);
    ASSERT_EQ(res, HCF_SUCCESS);

    HcfKeyPair *keyPair = nullptr;
    res = generator->generateKeyPair(generator, nullptr, &keyPair);
    ASSERT_EQ(res, HCF_SUCCESS);

    HcfBlob priDer = {.data = nullptr, .len = 0};
    res = keyPair->priKey->getEncodedDer(keyPair->priKey, "PKCS8", &priDer);
    HcfBlobDataClearAndFree(&priDer);

    HcfBlob pubDer = {.data = nullptr, .len = 0};
    res = keyPair->pubKey->getEncodedDer(keyPair->pubKey, "X509", &pubDer);
    HcfBlobDataClearAndFree(&pubDer);

    HcfObjDestroy(keyPair);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoAsymKeyCovTest, RsaKeySpecIntTest001, TestSize.Level0)
{
    HcfAsyKeyGenerator *generator = nullptr;
    HcfResult res = HcfAsyKeyGeneratorCreate("RSA2048|PRIMES_2", &generator);
    ASSERT_EQ(res, HCF_SUCCESS);

    HcfKeyPair *keyPair = nullptr;
    res = generator->generateKeyPair(generator, nullptr, &keyPair);
    ASSERT_EQ(res, HCF_SUCCESS);

    int32_t returnInt = 0;
    res = keyPair->pubKey->getAsyKeySpecInt(keyPair->pubKey, RSA_PK_BN, &returnInt);
    res = keyPair->priKey->getAsyKeySpecInt(keyPair->priKey, RSA_SK_BN, &returnInt);

    HcfObjDestroy(keyPair);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoAsymKeyCovTest, Alg25519PubKeyEncodedDerTest001, TestSize.Level0)
{
    HcfAsyKeyGenerator *generator = nullptr;
    HcfResult res = HcfAsyKeyGeneratorCreate("Ed25519", &generator);
    ASSERT_EQ(res, HCF_SUCCESS);

    HcfKeyPair *keyPair = nullptr;
    res = generator->generateKeyPair(generator, nullptr, &keyPair);
    ASSERT_EQ(res, HCF_SUCCESS);

    HcfBlob pubDer = {.data = nullptr, .len = 0};
    res = keyPair->pubKey->getEncodedDer(keyPair->pubKey, "X509", &pubDer);
    HcfBlobDataClearAndFree(&pubDer);

    HcfObjDestroy(keyPair);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoAsymKeyCovTest, DestroyRsaCommParamsSpecTest001, TestSize.Level0)
{
    HcfRsaCommParamsSpec *spec = (HcfRsaCommParamsSpec *)HcfMalloc(sizeof(HcfRsaCommParamsSpec), 0);
    ASSERT_NE(spec, nullptr);
    (void)memset_s(spec, sizeof(HcfRsaCommParamsSpec), 0, sizeof(HcfRsaCommParamsSpec));
    const char *algNameStr = "RSA";
    spec->base.algName = (char *)HcfMalloc(strlen(algNameStr) + 1, 0);
    ASSERT_NE(spec->base.algName, nullptr);
    (void)strcpy_s(spec->base.algName, strlen(algNameStr) + 1, algNameStr);
    spec->base.specType = HCF_COMMON_PARAMS_SPEC;
    uint8_t nData[] = {0x00, 0x01};
    spec->n.data = (uint8_t *)HcfMalloc(sizeof(nData), 0);
    ASSERT_NE(spec->n.data, nullptr);
    (void)memcpy_s(spec->n.data, sizeof(nData), nData, sizeof(nData));
    spec->n.len = sizeof(nData);
    FreeAsyKeySpec(reinterpret_cast<HcfAsyKeyParamsSpec *>(spec));
}

HWTEST_F(CryptoAsymKeyCovTest, EccSecp256k1KeyUtilTest001, TestSize.Level0)
{
    HcfEccCommParamsSpec *eccCommSpec = nullptr;
    HcfResult res = HcfEccKeyUtilCreate("NID_secp256k1", &eccCommSpec);
    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(eccCommSpec, nullptr);

    if (eccCommSpec != nullptr) {
        FreeAsyKeySpec(reinterpret_cast<HcfAsyKeyParamsSpec *>(eccCommSpec));
    }
}

HWTEST_F(CryptoAsymKeyCovTest, DsaPriKeyEncodedDerTest001, TestSize.Level0)
{
    HcfAsyKeyGenerator *generator = nullptr;
    HcfResult res = HcfAsyKeyGeneratorCreate("DSA2048", &generator);
    ASSERT_EQ(res, HCF_SUCCESS);

    HcfKeyPair *keyPair = nullptr;
    res = generator->generateKeyPair(generator, nullptr, &keyPair);
    ASSERT_EQ(res, HCF_SUCCESS);

    HcfBlob priDer = {.data = nullptr, .len = 0};
    res = keyPair->priKey->getEncodedDer(keyPair->priKey, "PKCS8", &priDer);
    EXPECT_EQ(res, HCF_INVALID_PARAMS);
    HcfBlobDataClearAndFree(&priDer);

    HcfObjDestroy(keyPair);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoAsymKeyCovTest, MlKemKeyFullApiTest001, TestSize.Level0)
{
    HcfAsyKeyGenerator *generator = nullptr;
    HcfResult res = HcfAsyKeyGeneratorCreate("ML-KEM-768", &generator);
    ASSERT_EQ(res, HCF_SUCCESS);

    HcfKeyPair *keyPair = nullptr;
    res = generator->generateKeyPair(generator, nullptr, &keyPair);
    ASSERT_EQ(res, HCF_SUCCESS);

    int keySize = 0;
    res = keyPair->pubKey->base.getKeySize(&(keyPair->pubKey->base), &keySize);
    res = keyPair->priKey->base.getKeySize(&(keyPair->priKey->base), &keySize);

    (void)keyPair->pubKey->base.getFormat(&(keyPair->pubKey->base));
    (void)keyPair->priKey->base.getFormat(&(keyPair->priKey->base));

    HcfBlob pubBlob = {.data = nullptr, .len = 0};
    res = keyPair->pubKey->base.getEncoded(&(keyPair->pubKey->base), &pubBlob);
    HcfBlobDataClearAndFree(&pubBlob);

    HcfBlob priBlob = {.data = nullptr, .len = 0};
    res = keyPair->priKey->base.getEncoded(&(keyPair->priKey->base), &priBlob);
    HcfBlobDataClearAndFree(&priBlob);

    keyPair->priKey->clearMem(keyPair->priKey);

    HcfObjDestroy(keyPair);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoAsymKeyCovTest, MlDsaKeyFullApiTest001, TestSize.Level0)
{
    HcfAsyKeyGenerator *generator = nullptr;
    HcfResult res = HcfAsyKeyGeneratorCreate("ML-DSA-65", &generator);
    ASSERT_EQ(res, HCF_SUCCESS);

    HcfKeyPair *keyPair = nullptr;
    res = generator->generateKeyPair(generator, nullptr, &keyPair);
    ASSERT_EQ(res, HCF_SUCCESS);

    int keySize = 0;
    res = keyPair->pubKey->base.getKeySize(&(keyPair->pubKey->base), &keySize);
    res = keyPair->priKey->base.getKeySize(&(keyPair->priKey->base), &keySize);

    (void)keyPair->pubKey->base.getFormat(&(keyPair->pubKey->base));
    (void)keyPair->priKey->base.getFormat(&(keyPair->priKey->base));

    HcfBlob pubBlob = {.data = nullptr, .len = 0};
    res = keyPair->pubKey->base.getEncoded(&(keyPair->pubKey->base), &pubBlob);
    HcfBlobDataClearAndFree(&pubBlob);

    HcfBlob priBlob = {.data = nullptr, .len = 0};
    res = keyPair->priKey->base.getEncoded(&(keyPair->priKey->base), &priBlob);
    HcfBlobDataClearAndFree(&priBlob);

    keyPair->priKey->clearMem(keyPair->priKey);

    HcfObjDestroy(keyPair);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoAsymKeyCovTest, MlKem1024KeyTest001, TestSize.Level0)
{
    HcfAsyKeyGenerator *generator = nullptr;
    HcfResult res = HcfAsyKeyGeneratorCreate("ML-KEM-1024", &generator);
    ASSERT_EQ(res, HCF_SUCCESS);

    HcfKeyPair *keyPair = nullptr;
    res = generator->generateKeyPair(generator, nullptr, &keyPair);
    ASSERT_EQ(res, HCF_SUCCESS);

    const char *algoName = keyPair->pubKey->base.getAlgorithm(&(keyPair->pubKey->base));
    EXPECT_NE(algoName, nullptr);

    HcfObjDestroy(keyPair);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoAsymKeyCovTest, MlKem512KeyTest001, TestSize.Level0)
{
    HcfAsyKeyGenerator *generator = nullptr;
    HcfResult res = HcfAsyKeyGeneratorCreate("ML-KEM-512", &generator);
    ASSERT_EQ(res, HCF_SUCCESS);

    HcfKeyPair *keyPair = nullptr;
    res = generator->generateKeyPair(generator, nullptr, &keyPair);
    ASSERT_EQ(res, HCF_SUCCESS);

    const char *algoName = keyPair->pubKey->base.getAlgorithm(&(keyPair->pubKey->base));
    EXPECT_NE(algoName, nullptr);

    HcfObjDestroy(keyPair);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoAsymKeyCovTest, MlDsa44KeyTest001, TestSize.Level0)
{
    HcfAsyKeyGenerator *generator = nullptr;
    HcfResult res = HcfAsyKeyGeneratorCreate("ML-DSA-44", &generator);
    ASSERT_EQ(res, HCF_SUCCESS);

    HcfKeyPair *keyPair = nullptr;
    res = generator->generateKeyPair(generator, nullptr, &keyPair);
    ASSERT_EQ(res, HCF_SUCCESS);

    const char *algoName = keyPair->pubKey->base.getAlgorithm(&(keyPair->pubKey->base));
    EXPECT_NE(algoName, nullptr);

    HcfObjDestroy(keyPair);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoAsymKeyCovTest, MlDsa87KeyTest001, TestSize.Level0)
{
    HcfAsyKeyGenerator *generator = nullptr;
    HcfResult res = HcfAsyKeyGeneratorCreate("ML-DSA-87", &generator);
    ASSERT_EQ(res, HCF_SUCCESS);

    HcfKeyPair *keyPair = nullptr;
    res = generator->generateKeyPair(generator, nullptr, &keyPair);
    ASSERT_EQ(res, HCF_SUCCESS);

    const char *algoName = keyPair->pubKey->base.getAlgorithm(&(keyPair->pubKey->base));
    EXPECT_NE(algoName, nullptr);

    HcfObjDestroy(keyPair);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoAsymKeyCovTest, EccKeyFullApiTest001, TestSize.Level0)
{
    HcfAsyKeyGenerator *generator = nullptr;
    HcfResult res = HcfAsyKeyGeneratorCreate("ECC224", &generator);
    ASSERT_EQ(res, HCF_SUCCESS);

    HcfKeyPair *keyPair = nullptr;
    res = generator->generateKeyPair(generator, nullptr, &keyPair);
    ASSERT_EQ(res, HCF_SUCCESS);

    int keySize = 0;
    res = keyPair->pubKey->base.getKeySize(&(keyPair->pubKey->base), &keySize);

    (void)keyPair->pubKey->base.getFormat(&(keyPair->pubKey->base));

    HcfBlob pubBlob = {.data = nullptr, .len = 0};
    res = keyPair->pubKey->base.getEncoded(&(keyPair->pubKey->base), &pubBlob);
    HcfBlobDataClearAndFree(&pubBlob);

    HcfBlob priBlob = {.data = nullptr, .len = 0};
    res = keyPair->priKey->base.getEncoded(&(keyPair->priKey->base), &priBlob);
    HcfBlobDataClearAndFree(&priBlob);

    HcfObjDestroy(keyPair);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoAsymKeyCovTest, CryptoAsymKeyConvertKeyTest001, TestSize.Level0)
{
    OH_CryptoAsymKeyGenerator *generator = nullptr;
    OH_Crypto_ErrCode res = OH_CryptoAsymKeyGenerator_Create("RSA2048|PRIMES_2", &generator);
    ASSERT_EQ(res, CRYPTO_SUCCESS);

    OH_CryptoKeyPair *keyPair = nullptr;
    res = OH_CryptoAsymKeyGenerator_Generate(generator, &keyPair);
    ASSERT_EQ(res, CRYPTO_SUCCESS);

    OH_CryptoKeyPair *convertedKeyPair = nullptr;
    Crypto_DataBlob pubData = {.data = nullptr, .len = 0};
    Crypto_DataBlob priData = {.data = nullptr, .len = 0};
    res = OH_CryptoAsymKeyGenerator_Convert(generator, CRYPTO_DER, &pubData, &priData, &convertedKeyPair);
    EXPECT_NE(res, CRYPTO_SUCCESS);

    OH_CryptoKeyPair_Destroy(keyPair);
    OH_CryptoAsymKeyGenerator_Destroy(generator);

    OH_CryptoKeyPair_Destroy(nullptr);
}

HWTEST_F(CryptoAsymKeyCovTest, RsaKeyEncodedPemTest001, TestSize.Level0)
{
    HcfAsyKeyGenerator *generator = nullptr;
    HcfResult res = HcfAsyKeyGeneratorCreate("RSA2048|PRIMES_2", &generator);
    ASSERT_EQ(res, HCF_SUCCESS);

    HcfKeyPair *keyPair = nullptr;
    res = generator->generateKeyPair(generator, nullptr, &keyPair);
    ASSERT_EQ(res, HCF_SUCCESS);

    HcfBlob pubDer = {.data = nullptr, .len = 0};
    res = keyPair->pubKey->base.getEncoded(&(keyPair->pubKey->base), &pubDer);
    ASSERT_EQ(res, HCF_SUCCESS);

    HcfKeyPair *outKeyPair = nullptr;
    res = generator->convertKey(generator, nullptr, &pubDer, nullptr, &outKeyPair);
    if (res == HCF_SUCCESS && outKeyPair != nullptr) {
        char *pemStr = nullptr;
        res = outKeyPair->pubKey->base.getEncodedPem(&(outKeyPair->pubKey->base), "X509", &pemStr);
        if (pemStr != nullptr) {
            HcfFree(pemStr);
        }
        HcfObjDestroy(outKeyPair);
    }

    HcfBlobDataClearAndFree(&pubDer);
    HcfObjDestroy(keyPair);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoAsymKeyCovTest, EccKeyConvertTest001, TestSize.Level0)
{
    HcfAsyKeyGenerator *generator = nullptr;
    HcfResult res = HcfAsyKeyGeneratorCreate("ECC256", &generator);
    ASSERT_EQ(res, HCF_SUCCESS);

    HcfKeyPair *keyPair = nullptr;
    res = generator->generateKeyPair(generator, nullptr, &keyPair);
    ASSERT_EQ(res, HCF_SUCCESS);

    HcfBlob pubDer = {.data = nullptr, .len = 0};
    res = keyPair->pubKey->base.getEncoded(&(keyPair->pubKey->base), &pubDer);
    if (res != HCF_SUCCESS) {
        HcfObjDestroy(keyPair);
        HcfObjDestroy(generator);
        return;
    }

    HcfBlob priDer = {.data = nullptr, .len = 0};
    res = keyPair->priKey->base.getEncoded(&(keyPair->priKey->base), &priDer);
    if (res != HCF_SUCCESS) {
        HcfBlobDataClearAndFree(&pubDer);
        HcfObjDestroy(keyPair);
        HcfObjDestroy(generator);
        return;
    }

    HcfKeyPair *outKeyPair = nullptr;
    res = generator->convertKey(generator, nullptr, &pubDer, &priDer, &outKeyPair);
    if (res == HCF_SUCCESS && outKeyPair != nullptr) {
        HcfObjDestroy(outKeyPair);
    }

    HcfBlobDataClearAndFree(&priDer);
    HcfBlobDataClearAndFree(&pubDer);
    HcfObjDestroy(keyPair);
    HcfObjDestroy(generator);

    generator = nullptr;
    res = HcfAsyKeyGeneratorCreate("DH_modp2048", &generator);
    ASSERT_EQ(res, HCF_SUCCESS);

    keyPair = nullptr;
    res = generator->generateKeyPair(generator, nullptr, &keyPair);
    ASSERT_EQ(res, HCF_SUCCESS);

    HcfBlob dhPubDer = {.data = nullptr, .len = 0};
    res = keyPair->pubKey->base.getEncoded(&(keyPair->pubKey->base), &dhPubDer);
    if (res == HCF_SUCCESS) {
        HcfKeyPair *dhOutKeyPair = nullptr;
        res = generator->convertKey(generator, nullptr, &dhPubDer, nullptr, &dhOutKeyPair);
        if (res == HCF_SUCCESS && dhOutKeyPair != nullptr) {
            HcfObjDestroy(dhOutKeyPair);
        }
        HcfBlobDataClearAndFree(&dhPubDer);
    }

    HcfObjDestroy(keyPair);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoAsymKeyCovTest, Kem1024EncapsulateTest001, TestSize.Level0)
{
    HcfAsyKeyGenerator *keyGen = nullptr;
    HcfResult res = HcfAsyKeyGeneratorCreate("ML-KEM-1024", &keyGen);
    ASSERT_EQ(res, HCF_SUCCESS);

    HcfKeyPair *keyPair = nullptr;
    res = keyGen->generateKeyPair(keyGen, nullptr, &keyPair);
    ASSERT_EQ(res, HCF_SUCCESS);

    HcfKem *kem = nullptr;
    res = HcfKemCreate("ML-KEM1024", &kem);
    ASSERT_EQ(res, HCF_SUCCESS);

    HcfBlob wrappedKey = {.data = nullptr, .len = 0};
    HcfBlob sharedSecret = {.data = nullptr, .len = 0};
    res = kem->encapsulate(kem, keyPair->pubKey, nullptr, &sharedSecret, &wrappedKey);
    if (res == HCF_SUCCESS) {
        HcfBlob decSecret = {.data = nullptr, .len = 0};
        res = kem->decapsulate(kem, keyPair->priKey, &wrappedKey, &decSecret);
        HcfBlobDataClearAndFree(&decSecret);
        HcfBlobDataClearAndFree(&wrappedKey);
        HcfBlobDataClearAndFree(&sharedSecret);
    }

    HcfObjDestroy(kem);
    HcfObjDestroy(keyPair);
    HcfObjDestroy(keyGen);
}

HWTEST_F(CryptoAsymKeyCovTest, Kem512EncapsulateTest001, TestSize.Level0)
{
    HcfAsyKeyGenerator *keyGen = nullptr;
    HcfResult res = HcfAsyKeyGeneratorCreate("ML-KEM-512", &keyGen);
    ASSERT_EQ(res, HCF_SUCCESS);

    HcfKeyPair *keyPair = nullptr;
    res = keyGen->generateKeyPair(keyGen, nullptr, &keyPair);
    ASSERT_EQ(res, HCF_SUCCESS);

    HcfKem *kem = nullptr;
    res = HcfKemCreate("ML-KEM512", &kem);
    ASSERT_EQ(res, HCF_SUCCESS);

    HcfBlob wrappedKey = {.data = nullptr, .len = 0};
    HcfBlob sharedSecret = {.data = nullptr, .len = 0};
    res = kem->encapsulate(kem, keyPair->pubKey, nullptr, &sharedSecret, &wrappedKey);
    if (res == HCF_SUCCESS) {
        HcfBlobDataClearAndFree(&wrappedKey);
        HcfBlobDataClearAndFree(&sharedSecret);
    }

    HcfObjDestroy(kem);
    HcfObjDestroy(keyPair);
    HcfObjDestroy(keyGen);
}

HWTEST_F(CryptoAsymKeyCovTest, CryptoAsymKeyApiNullTest001, TestSize.Level0)
{
    OH_CryptoAsymKeyGenerator *generator = nullptr;
    OH_Crypto_ErrCode res = OH_CryptoAsymKeyGenerator_Create("RSA2048|PRIMES_2", &generator);
    ASSERT_EQ(res, CRYPTO_SUCCESS);

    const char *algoName = OH_CryptoAsymKeyGenerator_GetAlgoName(generator);
    EXPECT_NE(algoName, nullptr);

    OH_CryptoAsymKeyGenerator_Destroy(generator);
}

HWTEST_F(CryptoAsymKeyCovTest, CryptoAsymKeyConvertTest001, TestSize.Level0)
{
    OH_CryptoAsymKeyGenerator *generator = nullptr;
    OH_Crypto_ErrCode res = OH_CryptoAsymKeyGenerator_Create("RSA2048|PRIMES_2", &generator);
    ASSERT_EQ(res, CRYPTO_SUCCESS);

    OH_CryptoKeyPair *keyPair = nullptr;
    res = OH_CryptoAsymKeyGenerator_Generate(generator, &keyPair);
    ASSERT_EQ(res, CRYPTO_SUCCESS);

    OH_CryptoPubKey *pubKey = OH_CryptoKeyPair_GetPubKey(keyPair);
    ASSERT_NE(pubKey, nullptr);

    OH_CryptoPrivKey *privKey = OH_CryptoKeyPair_GetPrivKey(keyPair);
    ASSERT_NE(privKey, nullptr);

    Crypto_DataBlob pubKeyBlob = {.data = nullptr, .len = 0};
    res = OH_CryptoPubKey_Encode(pubKey, CRYPTO_PEM, nullptr, &pubKeyBlob);
    if (res == CRYPTO_SUCCESS) {
        OH_Crypto_FreeDataBlob(&pubKeyBlob);
    }

    Crypto_DataBlob priKeyBlob = {.data = nullptr, .len = 0};
    res = OH_CryptoPrivKey_Encode(privKey, CRYPTO_PEM, nullptr, nullptr, &priKeyBlob);
    if (res == CRYPTO_SUCCESS) {
        OH_Crypto_FreeDataBlob(&priKeyBlob);
    }

    OH_CryptoKeyPair_Destroy(keyPair);
    OH_CryptoAsymKeyGenerator_Destroy(generator);
}

HWTEST_F(CryptoAsymKeyCovTest, CryptoAsymKeySpecRsaTest001, TestSize.Level0)
{
    OH_CryptoAsymKeySpec *spec = nullptr;
    OH_Crypto_ErrCode res = OH_CryptoAsymKeySpec_Create("RSA", CRYPTO_ASYM_KEY_PUBLIC_KEY_SPEC, &spec);
    ASSERT_EQ(res, CRYPTO_SUCCESS);

    Crypto_DataBlob nValue = {.data = nullptr, .len = 0};
    uint8_t nData[] = {0x00, 0x01, 0x02, 0x03};
    nValue.data = nData;
    nValue.len = sizeof(nData);
    EXPECT_EQ(OH_CryptoAsymKeySpec_SetParam(spec, CRYPTO_RSA_N_DATABLOB, &nValue), CRYPTO_SUCCESS);

    OH_CryptoAsymKeySpec_Destroy(spec);
}

HWTEST_F(CryptoAsymKeyCovTest, CryptoNullParamBranchTest001, TestSize.Level0)
{
    OH_CryptoAsymKeyGenerator_Destroy(nullptr);
    EXPECT_EQ(OH_CryptoKeyPair_GetPubKey(nullptr), nullptr);
    EXPECT_EQ(OH_CryptoKeyPair_GetPrivKey(nullptr), nullptr);
    OH_CryptoAsymKeyGenerator_GetAlgoName(nullptr);
}

HWTEST_F(CryptoAsymKeyCovTest, CryptoPubKeyGetParamTest001, TestSize.Level0)
{
    OH_CryptoAsymKeyGenerator *generator = nullptr;
    OH_Crypto_ErrCode res = OH_CryptoAsymKeyGenerator_Create("ECC256", &generator);
    ASSERT_EQ(res, CRYPTO_SUCCESS);

    OH_CryptoKeyPair *keyPair = nullptr;
    res = OH_CryptoAsymKeyGenerator_Generate(generator, &keyPair);
    ASSERT_EQ(res, CRYPTO_SUCCESS);

    OH_CryptoPubKey *pubKey = OH_CryptoKeyPair_GetPubKey(keyPair);
    ASSERT_NE(pubKey, nullptr);

    Crypto_DataBlob value = {.data = nullptr, .len = 0};
    (void)OH_CryptoPubKey_GetParam(pubKey, CRYPTO_ECC_H_INT, &value);
    OH_Crypto_FreeDataBlob(&value);

    (void)OH_CryptoPubKey_GetParam(pubKey, CRYPTO_ECC_CURVE_NAME_STR, &value);
    OH_Crypto_FreeDataBlob(&value);

    OH_CryptoKeyPair_Destroy(keyPair);
    OH_CryptoAsymKeyGenerator_Destroy(generator);

    generator = nullptr;
    res = OH_CryptoAsymKeyGenerator_Create("DH_modp2048", &generator);
    ASSERT_EQ(res, CRYPTO_SUCCESS);

    keyPair = nullptr;
    res = OH_CryptoAsymKeyGenerator_Generate(generator, &keyPair);
    ASSERT_EQ(res, CRYPTO_SUCCESS);

    OH_CryptoPrivKey *privKey = OH_CryptoKeyPair_GetPrivKey(keyPair);
    ASSERT_NE(privKey, nullptr);

    value = {.data = nullptr, .len = 0};
    (void)OH_CryptoPrivKey_GetParam(privKey, CRYPTO_DH_P_DATABLOB, &value);
    OH_Crypto_FreeDataBlob(&value);

    OH_CryptoKeyPair_Destroy(keyPair);
    OH_CryptoAsymKeyGenerator_Destroy(generator);
}

HWTEST_F(CryptoAsymKeyCovTest, CryptoPubKeyEncodeDerTest001, TestSize.Level0)
{
    OH_CryptoAsymKeyGenerator *generator = nullptr;
    OH_Crypto_ErrCode res = OH_CryptoAsymKeyGenerator_Create("RSA2048|PRIMES_2", &generator);
    ASSERT_EQ(res, CRYPTO_SUCCESS);

    OH_CryptoKeyPair *keyPair = nullptr;
    res = OH_CryptoAsymKeyGenerator_Generate(generator, &keyPair);
    ASSERT_EQ(res, CRYPTO_SUCCESS);

    OH_CryptoPubKey *pubKey = OH_CryptoKeyPair_GetPubKey(keyPair);
    ASSERT_NE(pubKey, nullptr);

    Crypto_DataBlob out = {.data = nullptr, .len = 0};
    res = OH_CryptoPubKey_Encode(pubKey, CRYPTO_DER, "PKCS1", &out);
    OH_Crypto_FreeDataBlob(&out);

    OH_CryptoKeyPair_Destroy(keyPair);
    OH_CryptoAsymKeyGenerator_Destroy(generator);
}

HWTEST_F(CryptoAsymKeyCovTest, CryptoPrivKeyEncodeDerTest001, TestSize.Level0)
{
    OH_CryptoAsymKeyGenerator *generator = nullptr;
    OH_Crypto_ErrCode res = OH_CryptoAsymKeyGenerator_Create("RSA2048|PRIMES_2", &generator);
    ASSERT_EQ(res, CRYPTO_SUCCESS);

    OH_CryptoKeyPair *keyPair = nullptr;
    res = OH_CryptoAsymKeyGenerator_Generate(generator, &keyPair);
    ASSERT_EQ(res, CRYPTO_SUCCESS);

    OH_CryptoPrivKey *privKey = OH_CryptoKeyPair_GetPrivKey(keyPair);
    ASSERT_NE(privKey, nullptr);

    Crypto_DataBlob out = {.data = nullptr, .len = 0};
    res = OH_CryptoPrivKey_Encode(privKey, CRYPTO_DER, "PKCS1", nullptr, &out);
    OH_Crypto_FreeDataBlob(&out);

    out = {.data = nullptr, .len = 0};
    res = OH_CryptoPrivKey_Encode(privKey, CRYPTO_DER, nullptr, nullptr, &out);
    OH_Crypto_FreeDataBlob(&out);

    OH_CryptoKeyPair_Destroy(keyPair);
    OH_CryptoAsymKeyGenerator_Destroy(generator);
}

HWTEST_F(CryptoAsymKeyCovTest, MlKemMlDsaBySpecRejectTest001, TestSize.Level0)
{
    HcfAsyKeyParamsSpec paramsSpec;
    paramsSpec.algName = const_cast<char *>("ML-KEM");
    paramsSpec.specType = HCF_KEY_PAIR_SPEC;
    HcfAsyKeyGeneratorBySpec *gen = nullptr;
    HcfResult res = HcfAsyKeyGeneratorBySpecCreate(&paramsSpec, &gen);
    EXPECT_NE(res, HCF_SUCCESS);

    paramsSpec.algName = const_cast<char *>("ML-DSA");
    res = HcfAsyKeyGeneratorBySpecCreate(&paramsSpec, &gen);
    EXPECT_NE(res, HCF_SUCCESS);
}

HWTEST_F(CryptoAsymKeyCovTest, DhKeySpecValidBranchTest001, TestSize.Level0)
{
    HcfAsyKeyParamsSpec paramsSpec;
    paramsSpec.algName = const_cast<char *>("DH");
    paramsSpec.specType = static_cast<HcfAsyKeySpecType>(99);
    HcfAsyKeyGeneratorBySpec *gen = nullptr;
    HcfResult res = HcfAsyKeyGeneratorBySpecCreate(&paramsSpec, &gen);
    EXPECT_NE(res, HCF_SUCCESS);
}

HWTEST_F(CryptoAsymKeyCovTest, CryptoGenNullTest001, TestSize.Level0)
{
    OH_CryptoAsymKeyGenerator *generator = nullptr;
    OH_Crypto_ErrCode res = OH_CryptoAsymKeyGenerator_Create("RSA2048|PRIMES_2", &generator);
    ASSERT_EQ(res, CRYPTO_SUCCESS);

    res = OH_CryptoAsymKeyGenerator_Generate(generator, nullptr);
    EXPECT_NE(res, CRYPTO_SUCCESS);

    Crypto_DataBlob nullData = {.data = nullptr, .len = 0};
    OH_CryptoKeyPair *keyCtx = nullptr;
    res = OH_CryptoAsymKeyGenerator_Convert(generator, CRYPTO_DER, &nullData, &nullData, &keyCtx);
    EXPECT_NE(res, CRYPTO_SUCCESS);

    OH_CryptoAsymKeyGenerator_Destroy(generator);
}

HWTEST_F(CryptoAsymKeyCovTest, CryptoSetPasswordTest001, TestSize.Level0)
{
    OH_CryptoAsymKeyGenerator *generator = nullptr;
    OH_Crypto_ErrCode res = OH_CryptoAsymKeyGenerator_Create("RSA2048|PRIMES_2", &generator);
    ASSERT_EQ(res, CRYPTO_SUCCESS);

    res = OH_CryptoAsymKeyGenerator_SetPassword(generator, nullptr, 0);
    EXPECT_NE(res, CRYPTO_SUCCESS);

    uint8_t pwd[] = "test";
    res = OH_CryptoAsymKeyGenerator_SetPassword(generator, pwd, 0);
    EXPECT_NE(res, CRYPTO_SUCCESS);

    OH_CryptoAsymKeyGenerator_Destroy(generator);
}

HWTEST_F(CryptoAsymKeyCovTest, CryptoAsymKeySpecNullTest001, TestSize.Level0)
{
    OH_CryptoAsymKeySpec *spec = nullptr;
    OH_Crypto_ErrCode res = OH_CryptoAsymKeySpec_GenEcCommonParamsSpec(nullptr, &spec);
    EXPECT_NE(res, CRYPTO_SUCCESS);

    res = OH_CryptoAsymKeySpec_GenDhCommonParamsSpec(2048, 256, nullptr);
    EXPECT_NE(res, CRYPTO_SUCCESS);

    Crypto_DataBlob value = {.data = nullptr, .len = 0};
    res = OH_CryptoAsymKeySpec_GetParam(nullptr, CRYPTO_RSA_N_DATABLOB, &value);
    EXPECT_NE(res, CRYPTO_SUCCESS);
}

HWTEST_F(CryptoAsymKeyCovTest, Ed25519KeySpecValidBranchTest001, TestSize.Level0)
{
    HcfAsyKeyParamsSpec paramsSpec;
    paramsSpec.algName = const_cast<char *>("Ed25519");
    paramsSpec.specType = static_cast<HcfAsyKeySpecType>(99);
    HcfAsyKeyGeneratorBySpec *gen = nullptr;
    HcfResult res = HcfAsyKeyGeneratorBySpecCreate(&paramsSpec, &gen);
    EXPECT_NE(res, HCF_SUCCESS);
}

HWTEST_F(CryptoAsymKeyCovTest, X25519KeySpecValidBranchTest001, TestSize.Level0)
{
    HcfAsyKeyParamsSpec paramsSpec;
    paramsSpec.algName = const_cast<char *>("X25519");
    paramsSpec.specType = static_cast<HcfAsyKeySpecType>(99);
    HcfAsyKeyGeneratorBySpec *gen = nullptr;
    HcfResult res = HcfAsyKeyGeneratorBySpecCreate(&paramsSpec, &gen);
    EXPECT_NE(res, HCF_SUCCESS);
}

HWTEST_F(CryptoAsymKeyCovTest, CryptoPubKeyGetParamEccTest001, TestSize.Level0)
{
    OH_CryptoAsymKeyGenerator *generator = nullptr;
    OH_Crypto_ErrCode res = OH_CryptoAsymKeyGenerator_Create("ECC256", &generator);
    ASSERT_EQ(res, CRYPTO_SUCCESS);

    OH_CryptoKeyPair *keyPair = nullptr;
    res = OH_CryptoAsymKeyGenerator_Generate(generator, &keyPair);
    ASSERT_EQ(res, CRYPTO_SUCCESS);

    OH_CryptoPubKey *pubKey = OH_CryptoKeyPair_GetPubKey(keyPair);
    OH_CryptoPrivKey *privKey = OH_CryptoKeyPair_GetPrivKey(keyPair);

    Crypto_DataBlob value = {.data = nullptr, .len = 0};
    (void)OH_CryptoPubKey_GetParam(pubKey, CRYPTO_ECC_PK_X_DATABLOB, &value);
    OH_Crypto_FreeDataBlob(&value);
    (void)OH_CryptoPubKey_GetParam(pubKey, CRYPTO_ECC_PK_Y_DATABLOB, &value);
    OH_Crypto_FreeDataBlob(&value);
    (void)OH_CryptoPrivKey_GetParam(privKey, CRYPTO_ECC_PK_X_DATABLOB, &value);
    OH_Crypto_FreeDataBlob(&value);
    (void)OH_CryptoPrivKey_GetParam(privKey, CRYPTO_ECC_CURVE_NAME_STR, &value);
    OH_Crypto_FreeDataBlob(&value);

    OH_CryptoKeyPair_Destroy(keyPair);
    OH_CryptoAsymKeyGenerator_Destroy(generator);
}

HWTEST_F(CryptoAsymKeyCovTest, CryptoRsaKeyGetParamTest001, TestSize.Level0)
{
    OH_CryptoAsymKeyGenerator *generator = nullptr;
    OH_Crypto_ErrCode res = OH_CryptoAsymKeyGenerator_Create("RSA2048|PRIMES_2", &generator);
    ASSERT_EQ(res, CRYPTO_SUCCESS);

    OH_CryptoKeyPair *keyPair = nullptr;
    res = OH_CryptoAsymKeyGenerator_Generate(generator, &keyPair);
    ASSERT_EQ(res, CRYPTO_SUCCESS);

    OH_CryptoPubKey *pubKey = OH_CryptoKeyPair_GetPubKey(keyPair);
    OH_CryptoPrivKey *privKey = OH_CryptoKeyPair_GetPrivKey(keyPair);

    Crypto_DataBlob value = {.data = nullptr, .len = 0};
    (void)OH_CryptoPubKey_GetParam(pubKey, CRYPTO_RSA_N_DATABLOB, &value);
    OH_Crypto_FreeDataBlob(&value);
    (void)OH_CryptoPrivKey_GetParam(privKey, CRYPTO_RSA_N_DATABLOB, &value);
    OH_Crypto_FreeDataBlob(&value);

    OH_CryptoKeyPair_Destroy(keyPair);
    OH_CryptoAsymKeyGenerator_Destroy(generator);
}

HWTEST_F(CryptoAsymKeyCovTest, CryptoEd25519KeyEncodeTest001, TestSize.Level0)
{
    OH_CryptoAsymKeyGenerator *generator = nullptr;
    OH_Crypto_ErrCode res = OH_CryptoAsymKeyGenerator_Create("Ed25519", &generator);
    ASSERT_EQ(res, CRYPTO_SUCCESS);

    OH_CryptoKeyPair *keyPair = nullptr;
    res = OH_CryptoAsymKeyGenerator_Generate(generator, &keyPair);
    ASSERT_EQ(res, CRYPTO_SUCCESS);

    OH_CryptoPubKey *pubKey = OH_CryptoKeyPair_GetPubKey(keyPair);
    OH_CryptoPrivKey *privKey = OH_CryptoKeyPair_GetPrivKey(keyPair);

    Crypto_DataBlob out = {.data = nullptr, .len = 0};
    (void)OH_CryptoPubKey_Encode(pubKey, CRYPTO_PEM, nullptr, &out);
    OH_Crypto_FreeDataBlob(&out);

    out = {.data = nullptr, .len = 0};
    (void)OH_CryptoPubKey_Encode(pubKey, CRYPTO_DER, nullptr, &out);
    OH_Crypto_FreeDataBlob(&out);

    out = {.data = nullptr, .len = 0};
    (void)OH_CryptoPrivKey_Encode(privKey, CRYPTO_PEM, nullptr, nullptr, &out);
    OH_Crypto_FreeDataBlob(&out);

    out = {.data = nullptr, .len = 0};
    (void)OH_CryptoPrivKey_Encode(privKey, CRYPTO_DER, nullptr, nullptr, &out);
    OH_Crypto_FreeDataBlob(&out);

    OH_CryptoKeyPair_Destroy(keyPair);
    OH_CryptoAsymKeyGenerator_Destroy(generator);
}

HWTEST_F(CryptoAsymKeyCovTest, CryptoAsymKeySpecDhTest001, TestSize.Level0)
{
    OH_CryptoAsymKeySpec *spec = nullptr;
    OH_Crypto_ErrCode res = OH_CryptoAsymKeySpec_GenDhCommonParamsSpec(2048, 256, &spec);
    ASSERT_EQ(res, CRYPTO_SUCCESS);

    Crypto_DataBlob value = {.data = nullptr, .len = 0};
    EXPECT_EQ(OH_CryptoAsymKeySpec_GetParam(spec, CRYPTO_DH_P_DATABLOB, &value), CRYPTO_SUCCESS);
    OH_Crypto_FreeDataBlob(&value);

    OH_CryptoAsymKeySpec_Destroy(spec);

    spec = nullptr;
    res = OH_CryptoAsymKeySpec_GenEcCommonParamsSpec("NID_secp256k1", &spec);
    ASSERT_EQ(res, CRYPTO_SUCCESS);

    value = {.data = nullptr, .len = 0};
    EXPECT_EQ(OH_CryptoAsymKeySpec_GetParam(spec, CRYPTO_ECC_FP_P_DATABLOB, &value), CRYPTO_SUCCESS);
    OH_Crypto_FreeDataBlob(&value);

    OH_CryptoAsymKeySpec_Destroy(spec);
}

HWTEST_F(CryptoAsymKeyCovTest, CryptoSm2KeyEncodeTest001, TestSize.Level0)
{
    OH_CryptoAsymKeyGenerator *generator = nullptr;
    OH_Crypto_ErrCode res = OH_CryptoAsymKeyGenerator_Create("SM2_256", &generator);
    ASSERT_EQ(res, CRYPTO_SUCCESS);

    OH_CryptoKeyPair *keyPair = nullptr;
    res = OH_CryptoAsymKeyGenerator_Generate(generator, &keyPair);
    ASSERT_EQ(res, CRYPTO_SUCCESS);

    OH_CryptoPubKey *pubKey = OH_CryptoKeyPair_GetPubKey(keyPair);
    OH_CryptoPrivKey *privKey = OH_CryptoKeyPair_GetPrivKey(keyPair);

    Crypto_DataBlob out = {.data = nullptr, .len = 0};
    (void)OH_CryptoPubKey_Encode(pubKey, CRYPTO_PEM, nullptr, &out);
    OH_Crypto_FreeDataBlob(&out);
    out = {.data = nullptr, .len = 0};
    (void)OH_CryptoPubKey_Encode(pubKey, CRYPTO_DER, nullptr, &out);
    OH_Crypto_FreeDataBlob(&out);
    out = {.data = nullptr, .len = 0};
    (void)OH_CryptoPrivKey_Encode(privKey, CRYPTO_PEM, nullptr, nullptr, &out);
    OH_Crypto_FreeDataBlob(&out);
    out = {.data = nullptr, .len = 0};
    (void)OH_CryptoPrivKey_Encode(privKey, CRYPTO_DER, nullptr, nullptr, &out);
    OH_Crypto_FreeDataBlob(&out);

    OH_CryptoKeyPair_Destroy(keyPair);
    OH_CryptoAsymKeyGenerator_Destroy(generator);
}

HWTEST_F(CryptoAsymKeyCovTest, CryptoSm2KeyGetParamTest001, TestSize.Level0)
{
    OH_CryptoAsymKeyGenerator *generator = nullptr;
    OH_Crypto_ErrCode res = OH_CryptoAsymKeyGenerator_Create("SM2_256", &generator);
    ASSERT_EQ(res, CRYPTO_SUCCESS);

    OH_CryptoKeyPair *keyPair = nullptr;
    res = OH_CryptoAsymKeyGenerator_Generate(generator, &keyPair);
    ASSERT_EQ(res, CRYPTO_SUCCESS);

    OH_CryptoPubKey *pubKey = OH_CryptoKeyPair_GetPubKey(keyPair);
    OH_CryptoPrivKey *privKey = OH_CryptoKeyPair_GetPrivKey(keyPair);

    Crypto_DataBlob value = {.data = nullptr, .len = 0};
    (void)OH_CryptoPubKey_GetParam(pubKey, CRYPTO_ECC_PK_X_DATABLOB, &value);
    OH_Crypto_FreeDataBlob(&value);
    (void)OH_CryptoPrivKey_GetParam(privKey, CRYPTO_ECC_PK_Y_DATABLOB, &value);
    OH_Crypto_FreeDataBlob(&value);

    OH_CryptoKeyPair_Destroy(keyPair);
    OH_CryptoAsymKeyGenerator_Destroy(generator);
}

HWTEST_F(CryptoAsymKeyCovTest, CryptoDhKeyEncodeTest001, TestSize.Level0)
{
    OH_CryptoAsymKeyGenerator *generator = nullptr;
    OH_Crypto_ErrCode res = OH_CryptoAsymKeyGenerator_Create("DH_modp2048", &generator);
    ASSERT_EQ(res, CRYPTO_SUCCESS);

    OH_CryptoKeyPair *keyPair = nullptr;
    res = OH_CryptoAsymKeyGenerator_Generate(generator, &keyPair);
    ASSERT_EQ(res, CRYPTO_SUCCESS);

    OH_CryptoPubKey *pubKey = OH_CryptoKeyPair_GetPubKey(keyPair);
    OH_CryptoPrivKey *privKey = OH_CryptoKeyPair_GetPrivKey(keyPair);

    Crypto_DataBlob out = {.data = nullptr, .len = 0};
    EXPECT_EQ(OH_CryptoPubKey_Encode(pubKey, CRYPTO_DER, nullptr, &out), CRYPTO_SUCCESS);
    OH_Crypto_FreeDataBlob(&out);
    out = {.data = nullptr, .len = 0};
    EXPECT_EQ(OH_CryptoPrivKey_Encode(privKey, CRYPTO_DER, nullptr, nullptr, &out), CRYPTO_SUCCESS);
    OH_Crypto_FreeDataBlob(&out);

    OH_CryptoKeyPair_Destroy(keyPair);
    OH_CryptoAsymKeyGenerator_Destroy(generator);
}

HWTEST_F(CryptoAsymKeyCovTest, CryptoMlKemKeyEncodeTest001, TestSize.Level0)
{
    OH_CryptoAsymKeyGenerator *generator = nullptr;
    OH_Crypto_ErrCode res = OH_CryptoAsymKeyGenerator_Create("ML-KEM-768", &generator);
    ASSERT_EQ(res, CRYPTO_SUCCESS);

    OH_CryptoKeyPair *keyPair = nullptr;
    res = OH_CryptoAsymKeyGenerator_Generate(generator, &keyPair);
    ASSERT_EQ(res, CRYPTO_SUCCESS);

    OH_CryptoPubKey *pubKey = OH_CryptoKeyPair_GetPubKey(keyPair);
    OH_CryptoPrivKey *privKey = OH_CryptoKeyPair_GetPrivKey(keyPair);

    Crypto_DataBlob value = {.data = nullptr, .len = 0};
    (void)OH_CryptoPubKey_GetParam(pubKey, CRYPTO_ECC_FIELD_SIZE_INT, &value);
    OH_Crypto_FreeDataBlob(&value);
    (void)OH_CryptoPrivKey_GetParam(privKey, CRYPTO_ECC_FIELD_SIZE_INT, &value);
    OH_Crypto_FreeDataBlob(&value);

    OH_CryptoKeyPair_Destroy(keyPair);
    OH_CryptoAsymKeyGenerator_Destroy(generator);
}

HWTEST_F(CryptoAsymKeyCovTest, CryptoAsymKeySpecCreateTest001, TestSize.Level0)
{
    OH_CryptoAsymKeySpec *spec = nullptr;
    OH_Crypto_ErrCode res = OH_CryptoAsymKeySpec_Create("RSA", CRYPTO_ASYM_KEY_PUBLIC_KEY_SPEC, &spec);
    ASSERT_EQ(res, CRYPTO_SUCCESS);

    Crypto_DataBlob value = {.data = nullptr, .len = 0};
    uint8_t nData[] = {0x00, 0x01, 0x02};
    value.data = nData;
    value.len = sizeof(nData);
    EXPECT_EQ(OH_CryptoAsymKeySpec_SetParam(spec, CRYPTO_RSA_N_DATABLOB, &value), CRYPTO_SUCCESS);

    Crypto_DataBlob getValue = {.data = nullptr, .len = 0};
    EXPECT_EQ(OH_CryptoAsymKeySpec_GetParam(spec, CRYPTO_RSA_N_DATABLOB, &getValue), CRYPTO_SUCCESS);
    OH_Crypto_FreeDataBlob(&getValue);

    OH_CryptoAsymKeySpec_Destroy(spec);

    const char *algoNames[] = {"DSA", "ECC", "SM2", "DH", "Ed25519", "X25519"};
    Crypto_DataBlob dummyValue = {.data = nullptr, .len = 0};
    uint8_t dummyData[] = {0x00, 0x01, 0x02};
    dummyValue.data = dummyData;
    dummyValue.len = sizeof(dummyData);

    for (const char *algoName : algoNames) {
        OH_CryptoAsymKeySpec *algoSpec = nullptr;
        res = OH_CryptoAsymKeySpec_Create(algoName, CRYPTO_ASYM_KEY_COMMON_PARAMS_SPEC, &algoSpec);
        if (res != CRYPTO_SUCCESS) {
            continue;
        }
        (void)OH_CryptoAsymKeySpec_SetParam(algoSpec, CRYPTO_RSA_N_DATABLOB, &dummyValue);
        Crypto_DataBlob algoValue = {.data = nullptr, .len = 0};
        (void)OH_CryptoAsymKeySpec_GetParam(algoSpec, CRYPTO_RSA_N_DATABLOB, &algoValue);
        OH_Crypto_FreeDataBlob(&algoValue);
        OH_CryptoAsymKeySpec_Destroy(algoSpec);
    }
}

HWTEST_F(CryptoAsymKeyCovTest, CryptoEccKeyGetParamFullTest001, TestSize.Level0)
{
    OH_CryptoAsymKeyGenerator *generator = nullptr;
    OH_Crypto_ErrCode res = OH_CryptoAsymKeyGenerator_Create("ECC256", &generator);
    ASSERT_EQ(res, CRYPTO_SUCCESS);

    OH_CryptoKeyPair *keyPair = nullptr;
    res = OH_CryptoAsymKeyGenerator_Generate(generator, &keyPair);
    ASSERT_EQ(res, CRYPTO_SUCCESS);

    OH_CryptoPubKey *pubKey = OH_CryptoKeyPair_GetPubKey(keyPair);
    OH_CryptoPrivKey *privKey = OH_CryptoKeyPair_GetPrivKey(keyPair);

    CryptoAsymKey_ParamType intItems[] = {CRYPTO_ECC_H_INT, CRYPTO_ECC_FIELD_SIZE_INT};
    for (auto item : intItems) {
        Crypto_DataBlob value = {.data = nullptr, .len = 0};
        (void)OH_CryptoPubKey_GetParam(pubKey, item, &value);
        OH_Crypto_FreeDataBlob(&value);
        (void)OH_CryptoPrivKey_GetParam(privKey, item, &value);
        OH_Crypto_FreeDataBlob(&value);
    }

    CryptoAsymKey_ParamType strItems[] = {CRYPTO_ECC_FIELD_TYPE_STR, CRYPTO_ECC_CURVE_NAME_STR};
    for (auto item : strItems) {
        Crypto_DataBlob value = {.data = nullptr, .len = 0};
        (void)OH_CryptoPubKey_GetParam(pubKey, item, &value);
        OH_Crypto_FreeDataBlob(&value);
        (void)OH_CryptoPrivKey_GetParam(privKey, item, &value);
        OH_Crypto_FreeDataBlob(&value);
    }

    OH_CryptoKeyPair_Destroy(keyPair);
    OH_CryptoAsymKeyGenerator_Destroy(generator);

    generator = nullptr;
    res = OH_CryptoAsymKeyGenerator_Create("DH_modp2048", &generator);
    ASSERT_EQ(res, CRYPTO_SUCCESS);

    keyPair = nullptr;
    res = OH_CryptoAsymKeyGenerator_Generate(generator, &keyPair);
    ASSERT_EQ(res, CRYPTO_SUCCESS);

    pubKey = OH_CryptoKeyPair_GetPubKey(keyPair);
    privKey = OH_CryptoKeyPair_GetPrivKey(keyPair);

    Crypto_DataBlob dhValue = {.data = nullptr, .len = 0};
    CryptoAsymKey_ParamType dhPubItems[] = {CRYPTO_DH_P_DATABLOB, CRYPTO_DH_G_DATABLOB, CRYPTO_DH_PK_DATABLOB};
    for (auto item : dhPubItems) {
        (void)OH_CryptoPubKey_GetParam(pubKey, item, &dhValue);
        OH_Crypto_FreeDataBlob(&dhValue);
    }
    CryptoAsymKey_ParamType dhPriItems[] = {CRYPTO_DH_P_DATABLOB, CRYPTO_DH_SK_DATABLOB, CRYPTO_DH_L_INT};
    for (auto item : dhPriItems) {
        (void)OH_CryptoPrivKey_GetParam(privKey, item, &dhValue);
        OH_Crypto_FreeDataBlob(&dhValue);
    }

    OH_CryptoKeyPair_Destroy(keyPair);
    OH_CryptoAsymKeyGenerator_Destroy(generator);
}

HWTEST_F(CryptoAsymKeyCovTest, CryptoEd25519KeyGetParamTest001, TestSize.Level0)
{
    OH_CryptoAsymKeyGenerator *generator = nullptr;
    OH_Crypto_ErrCode res = OH_CryptoAsymKeyGenerator_Create("Ed25519", &generator);
    ASSERT_EQ(res, CRYPTO_SUCCESS);

    OH_CryptoKeyPair *keyPair = nullptr;
    res = OH_CryptoAsymKeyGenerator_Generate(generator, &keyPair);
    ASSERT_EQ(res, CRYPTO_SUCCESS);

    OH_CryptoPubKey *pubKey = OH_CryptoKeyPair_GetPubKey(keyPair);
    OH_CryptoPrivKey *privKey = OH_CryptoKeyPair_GetPrivKey(keyPair);

    Crypto_DataBlob value = {.data = nullptr, .len = 0};
    (void)OH_CryptoPubKey_GetParam(pubKey, CRYPTO_ED25519_PK_DATABLOB, &value);
    OH_Crypto_FreeDataBlob(&value);
    (void)OH_CryptoPrivKey_GetParam(privKey, CRYPTO_ED25519_SK_DATABLOB, &value);
    OH_Crypto_FreeDataBlob(&value);

    OH_CryptoKeyPair_Destroy(keyPair);
    OH_CryptoAsymKeyGenerator_Destroy(generator);
}

HWTEST_F(CryptoAsymKeyCovTest, CryptoX25519KeyGetParamTest001, TestSize.Level0)
{
    OH_CryptoAsymKeyGenerator *generator = nullptr;
    OH_Crypto_ErrCode res = OH_CryptoAsymKeyGenerator_Create("X25519", &generator);
    ASSERT_EQ(res, CRYPTO_SUCCESS);

    OH_CryptoKeyPair *keyPair = nullptr;
    res = OH_CryptoAsymKeyGenerator_Generate(generator, &keyPair);
    ASSERT_EQ(res, CRYPTO_SUCCESS);

    OH_CryptoPubKey *pubKey = OH_CryptoKeyPair_GetPubKey(keyPair);
    OH_CryptoPrivKey *privKey = OH_CryptoKeyPair_GetPrivKey(keyPair);

    Crypto_DataBlob value = {.data = nullptr, .len = 0};
    (void)OH_CryptoPubKey_GetParam(pubKey, CRYPTO_X25519_PK_DATABLOB, &value);
    OH_Crypto_FreeDataBlob(&value);
    (void)OH_CryptoPrivKey_GetParam(privKey, CRYPTO_X25519_SK_DATABLOB, &value);
    OH_Crypto_FreeDataBlob(&value);

    Crypto_DataBlob out = {.data = nullptr, .len = 0};
    (void)OH_CryptoPubKey_Encode(pubKey, CRYPTO_PEM, nullptr, &out);
    OH_Crypto_FreeDataBlob(&out);
    out = {.data = nullptr, .len = 0};
    (void)OH_CryptoPubKey_Encode(pubKey, CRYPTO_DER, nullptr, &out);
    OH_Crypto_FreeDataBlob(&out);
    out = {.data = nullptr, .len = 0};
    (void)OH_CryptoPrivKey_Encode(privKey, CRYPTO_PEM, nullptr, nullptr, &out);
    OH_Crypto_FreeDataBlob(&out);
    out = {.data = nullptr, .len = 0};
    (void)OH_CryptoPrivKey_Encode(privKey, CRYPTO_DER, nullptr, nullptr, &out);
    OH_Crypto_FreeDataBlob(&out);

    OH_CryptoKeyPair_Destroy(keyPair);
    OH_CryptoAsymKeyGenerator_Destroy(generator);

    generator = nullptr;
    res = OH_CryptoAsymKeyGenerator_Create("DSA2048", &generator);
    ASSERT_EQ(res, CRYPTO_SUCCESS);

    keyPair = nullptr;
    res = OH_CryptoAsymKeyGenerator_Generate(generator, &keyPair);
    ASSERT_EQ(res, CRYPTO_SUCCESS);

    pubKey = OH_CryptoKeyPair_GetPubKey(keyPair);
    privKey = OH_CryptoKeyPair_GetPrivKey(keyPair);

    value = {.data = nullptr, .len = 0};
    (void)OH_CryptoPubKey_GetParam(pubKey, CRYPTO_DSA_P_DATABLOB, &value);
    OH_Crypto_FreeDataBlob(&value);
    (void)OH_CryptoPrivKey_GetParam(privKey, CRYPTO_DSA_P_DATABLOB, &value);
    OH_Crypto_FreeDataBlob(&value);

    out = {.data = nullptr, .len = 0};
    (void)OH_CryptoPubKey_Encode(pubKey, CRYPTO_PEM, nullptr, &out);
    OH_Crypto_FreeDataBlob(&out);
    out = {.data = nullptr, .len = 0};
    (void)OH_CryptoPrivKey_Encode(privKey, CRYPTO_PEM, nullptr, nullptr, &out);
    OH_Crypto_FreeDataBlob(&out);

    OH_CryptoKeyPair_Destroy(keyPair);
    OH_CryptoAsymKeyGenerator_Destroy(generator);
}

HWTEST_F(CryptoAsymKeyCovTest, CryptoRsaKeyEncodePemTest001, TestSize.Level0)
{
    OH_CryptoAsymKeyGenerator *generator = nullptr;
    OH_Crypto_ErrCode res = OH_CryptoAsymKeyGenerator_Create("RSA3072|PRIMES_2", &generator);
    ASSERT_EQ(res, CRYPTO_SUCCESS);

    OH_CryptoKeyPair *keyPair = nullptr;
    res = OH_CryptoAsymKeyGenerator_Generate(generator, &keyPair);
    ASSERT_EQ(res, CRYPTO_SUCCESS);

    OH_CryptoPubKey *pubKey = OH_CryptoKeyPair_GetPubKey(keyPair);
    OH_CryptoPrivKey *privKey = OH_CryptoKeyPair_GetPrivKey(keyPair);

    Crypto_DataBlob out = {.data = nullptr, .len = 0};
    (void)OH_CryptoPubKey_Encode(pubKey, CRYPTO_PEM, "PKCS1", &out);
    OH_Crypto_FreeDataBlob(&out);
    out = {.data = nullptr, .len = 0};
    (void)OH_CryptoPrivKey_Encode(privKey, CRYPTO_PEM, "PKCS1", nullptr, &out);
    OH_Crypto_FreeDataBlob(&out);
    out = {.data = nullptr, .len = 0};
    (void)OH_CryptoPrivKey_Encode(privKey, CRYPTO_PEM, "PKCS8", nullptr, &out);
    OH_Crypto_FreeDataBlob(&out);
    out = {.data = nullptr, .len = 0};
    (void)OH_CryptoPubKey_Encode(pubKey, CRYPTO_DER, "PKCS1", &out);
    OH_Crypto_FreeDataBlob(&out);
    out = {.data = nullptr, .len = 0};
    (void)OH_CryptoPrivKey_Encode(privKey, CRYPTO_DER, "PKCS1", nullptr, &out);
    OH_Crypto_FreeDataBlob(&out);
    out = {.data = nullptr, .len = 0};
    (void)OH_CryptoPrivKey_Encode(privKey, CRYPTO_DER, "PKCS8", nullptr, &out);
    OH_Crypto_FreeDataBlob(&out);

    OH_CryptoKeyPair_Destroy(keyPair);
    OH_CryptoAsymKeyGenerator_Destroy(generator);
}
}
