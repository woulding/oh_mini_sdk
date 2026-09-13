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
#include <string>
#include <algorithm>
#include <climits>
#include "securec.h"

#include "asy_key_generator.h"
#include "sym_key_generator.h"
#include "sym_common_defines.h"
#include "key.h"
#include "key_pair.h"
#include "sym_key.h"
#include "blob.h"
#include "memory.h"
#include "result.h"
#include "openssl_adapter_mock.h"
#include "openssl_class.h"

using namespace std;
using namespace testing::ext;

namespace {
class CryptoGetKeySizeAsyTest : public testing::TestWithParam<std::string> {
public:
    static void SetUpTestCase() {}
    static void TearDownTestCase() {}
    void SetUp() {}
    void TearDown() {}
};

static const std::vector<std::string> g_asyKeyAlgoParams = {
    "RSA512|PRIMES_2",
    "RSA1024|PRIMES_2",
    "RSA2048|PRIMES_2",
    "ECC224",
    "ECC256",
    "ECC384",
    "ECC521",
    "SM2_256",
    "DSA1024",
    "DSA2048",
    "DH_modp2048",
    "Ed25519",
    "X25519",
};

static std::string AsyGetKeySizeParamName(const ::testing::TestParamInfo<std::string> &info)
{
    std::string name = info.param;
    std::replace(name.begin(), name.end(), '|', '_');
    return name;
}

INSTANTIATE_TEST_SUITE_P(CryptoGetKeySizeAsyParam, CryptoGetKeySizeAsyTest,
    ::testing::ValuesIn(g_asyKeyAlgoParams),
    AsyGetKeySizeParamName
);

HWTEST_P(CryptoGetKeySizeAsyTest, GetKeySizeAsyAlgoTest, TestSize.Level0)
{
    std::string algoName = GetParam();

    HcfAsyKeyGenerator *generator = nullptr;
    HcfResult ret = HcfAsyKeyGeneratorCreate(algoName.c_str(), &generator);
    ASSERT_EQ(ret, HCF_SUCCESS);
    ASSERT_NE(generator, nullptr);

    HcfKeyPair *keyPair = nullptr;
    ret = generator->generateKeyPair(generator, nullptr, &keyPair);
    ASSERT_EQ(ret, HCF_SUCCESS);
    ASSERT_NE(keyPair, nullptr);
    ASSERT_NE(keyPair->pubKey, nullptr);
    ASSERT_NE(keyPair->priKey, nullptr);

    HcfPubKey *pubKey = keyPair->pubKey;
    HcfPriKey *priKey = keyPair->priKey;

    ASSERT_NE(pubKey->base.getKeySize, nullptr);
    ASSERT_NE(priKey->base.getKeySize, nullptr);

    int pubSize = 0;
    int priSize = 0;
    ret = pubKey->base.getKeySize(reinterpret_cast<HcfKey *>(pubKey), &pubSize);
    EXPECT_EQ(ret, HCF_SUCCESS);
    EXPECT_GT(pubSize, 0);

    ret = priKey->base.getKeySize(reinterpret_cast<HcfKey *>(priKey), &priSize);
    EXPECT_EQ(ret, HCF_SUCCESS);
    EXPECT_GT(priSize, 0);

    EXPECT_EQ(pubSize, priSize) << "algo: " << algoName;

    HcfObjDestroy(keyPair);
    HcfObjDestroy(generator);
}

class CryptoGetKeySizeSymTest : public testing::TestWithParam<std::string> {
public:
    static void SetUpTestCase() {}
    static void TearDownTestCase() {}
    void SetUp() {}
    void TearDown() {}
};

static const std::vector<std::string> g_symKeyAlgoParams = {
    "AES128",
    "AES192",
    "AES256",
    "SM4_128",
    "3DES",
    "DES",
    "HMAC|SHA256",
    "HMAC|SHA384",
    "HMAC|SHA512",
    "HMAC|SM3",
    "ChaCha20",
};

static std::string SymGetKeySizeParamName(const ::testing::TestParamInfo<std::string> &info)
{
    std::string name = info.param;
    std::replace(name.begin(), name.end(), '|', '_');
    std::replace(name.begin(), name.end(), '-', '_');
    return name;
}

INSTANTIATE_TEST_SUITE_P(CryptoGetKeySizeSymParam, CryptoGetKeySizeSymTest,
    ::testing::ValuesIn(g_symKeyAlgoParams),
    SymGetKeySizeParamName
);

HWTEST_P(CryptoGetKeySizeSymTest, GetKeySizeSymAlgoTest, TestSize.Level0)
{
    std::string algoName = GetParam();

    HcfSymKeyGenerator *generator = nullptr;
    int32_t ret = HcfSymKeyGeneratorCreate(algoName.c_str(), &generator);
    if (ret != HCF_SUCCESS) {
        /* Some algorithms may not be available in build (e.g. RC4, Blowfish) */
        return;
    }
    ASSERT_NE(generator, nullptr);

    HcfSymKey *symKey = nullptr;
    ret = generator->generateSymKey(generator, &symKey);
    ASSERT_EQ(ret, HCF_SUCCESS);
    ASSERT_NE(symKey, nullptr);

    HcfKey *key = reinterpret_cast<HcfKey *>(&symKey->key);
    ASSERT_NE(key->getKeySize, nullptr);

    int keySizeBits = 0;
    HcfResult res = key->getKeySize(key, &keySizeBits);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_GT(keySizeBits, 0) << "algo: " << algoName;

    HcfObjDestroy(symKey);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoGetKeySizeAsyTest, RsaGetKeySizeEqualsModulusBytes, TestSize.Level0)
{
    HcfAsyKeyGenerator *generator = nullptr;
    HcfResult ret = HcfAsyKeyGeneratorCreate("RSA2048|PRIMES_2", &generator);
    ASSERT_EQ(ret, HCF_SUCCESS);
    ASSERT_NE(generator, nullptr);

    HcfKeyPair *keyPair = nullptr;
    ret = generator->generateKeyPair(generator, nullptr, &keyPair);
    ASSERT_EQ(ret, HCF_SUCCESS);
    ASSERT_NE(keyPair, nullptr);

    int pubSize = 0;
    ret = keyPair->pubKey->base.getKeySize(reinterpret_cast<HcfKey *>(keyPair->pubKey), &pubSize);
    ASSERT_EQ(ret, HCF_SUCCESS);
    EXPECT_EQ(pubSize, 2048);

    HcfObjDestroy(keyPair);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoGetKeySizeSymTest, SymGetKeySizeReturnsBits, TestSize.Level0)
{
    HcfSymKeyGenerator *generator = nullptr;
    int32_t ret = HcfSymKeyGeneratorCreate("AES128", &generator);
    ASSERT_EQ(ret, HCF_SUCCESS);
    ASSERT_NE(generator, nullptr);

    HcfSymKey *symKey = nullptr;
    ret = generator->generateSymKey(generator, &symKey);
    ASSERT_EQ(ret, HCF_SUCCESS);
    ASSERT_NE(symKey, nullptr);

    int keySizeBits = 0;
    HcfResult res = symKey->key.getKeySize(&symKey->key, &keySizeBits);
    ASSERT_EQ(res, HCF_SUCCESS);
    EXPECT_EQ(keySizeBits, 128);

    HcfObjDestroy(symKey);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoGetKeySizeAsyTest, GetKeySizeInvalidParams, TestSize.Level1)
{
    HcfAsyKeyGenerator *generator = nullptr;
    HcfResult ret = HcfAsyKeyGeneratorCreate("RSA2048|PRIMES_2", &generator);
    ASSERT_EQ(ret, HCF_SUCCESS);

    HcfKeyPair *keyPair = nullptr;
    ret = generator->generateKeyPair(generator, nullptr, &keyPair);
    ASSERT_EQ(ret, HCF_SUCCESS);

    HcfPubKey *pubKey = keyPair->pubKey;
    int size = 0;

    ret = pubKey->base.getKeySize(nullptr, &size);
    EXPECT_NE(ret, HCF_SUCCESS);

    ret = pubKey->base.getKeySize(reinterpret_cast<HcfKey *>(pubKey), nullptr);
    EXPECT_NE(ret, HCF_SUCCESS);

    HcfObjDestroy(keyPair);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoGetKeySizeAsyTest, GetKeySizeRsaExceptionBranches, TestSize.Level1)
{
    HcfAsyKeyGenerator *rsaGen = nullptr;
    ASSERT_EQ(HcfAsyKeyGeneratorCreate("RSA2048|PRIMES_2", &rsaGen), HCF_SUCCESS);
    HcfKeyPair *rsaPair = nullptr;
    ASSERT_EQ(rsaGen->generateKeyPair(rsaGen, nullptr, &rsaPair), HCF_SUCCESS);

    HcfAsyKeyGenerator *eccGen = nullptr;
    ASSERT_EQ(HcfAsyKeyGeneratorCreate("ECC256", &eccGen), HCF_SUCCESS);
    HcfKeyPair *eccPair = nullptr;
    ASSERT_EQ(eccGen->generateKeyPair(eccGen, nullptr, &eccPair), HCF_SUCCESS);

    int size = 0;
    EXPECT_EQ(rsaPair->pubKey->base.getKeySize(reinterpret_cast<HcfKey *>(eccPair->pubKey), &size),
        HCF_ERR_PARAMETER_CHECK_FAILED);

    HcfOpensslRsaPubKey *rsaPubImpl = reinterpret_cast<HcfOpensslRsaPubKey *>(rsaPair->pubKey);
    RSA *savedPk = rsaPubImpl->pk;
    rsaPubImpl->pk = nullptr;
    EXPECT_EQ(rsaPair->pubKey->base.getKeySize(reinterpret_cast<HcfKey *>(rsaPair->pubKey), &size),
        HCF_ERR_PARAMETER_CHECK_FAILED);
    rsaPubImpl->pk = savedPk;

    HcfOpensslRsaPriKey *rsaPriImpl = reinterpret_cast<HcfOpensslRsaPriKey *>(rsaPair->priKey);
    RSA *savedSk = rsaPriImpl->sk;
    rsaPriImpl->sk = nullptr;
    EXPECT_EQ(rsaPair->priKey->base.getKeySize(reinterpret_cast<HcfKey *>(rsaPair->priKey), &size),
        HCF_ERR_PARAMETER_CHECK_FAILED);
    rsaPriImpl->sk = savedSk;

    HcfObjDestroy(eccPair);
    HcfObjDestroy(eccGen);
    HcfObjDestroy(rsaPair);
    HcfObjDestroy(rsaGen);
}

HWTEST_F(CryptoGetKeySizeAsyTest, GetKeySizeDhExceptionBranches, TestSize.Level1)
{
    HcfAsyKeyGenerator *dhGen = nullptr;
    int32_t dhRes = HcfAsyKeyGeneratorCreate("DH_modp2048", &dhGen);
    if (dhRes != HCF_SUCCESS || dhGen == nullptr) {
        return;
    }
    HcfKeyPair *dhPair = nullptr;
    dhRes = dhGen->generateKeyPair(dhGen, nullptr, &dhPair);
    if (dhRes != HCF_SUCCESS || dhPair == nullptr) {
        HcfObjDestroy(dhGen);
        return;
    }
    HcfAsyKeyGenerator *rsaGen = nullptr;
    ASSERT_EQ(HcfAsyKeyGeneratorCreate("RSA2048|PRIMES_2", &rsaGen), HCF_SUCCESS);
    HcfKeyPair *rsaPair = nullptr;
    ASSERT_EQ(rsaGen->generateKeyPair(rsaGen, nullptr, &rsaPair), HCF_SUCCESS);

    int size = 0;
    EXPECT_EQ(dhPair->pubKey->base.getKeySize(reinterpret_cast<HcfKey *>(rsaPair->pubKey), &size),
        HCF_ERR_PARAMETER_CHECK_FAILED);

    HcfOpensslDhPubKey *dhPubImpl = reinterpret_cast<HcfOpensslDhPubKey *>(dhPair->pubKey);
    DH *savedDhPk = dhPubImpl->pk;
    dhPubImpl->pk = nullptr;
    EXPECT_EQ(dhPair->pubKey->base.getKeySize(reinterpret_cast<HcfKey *>(dhPair->pubKey), &size),
        HCF_ERR_PARAMETER_CHECK_FAILED);
    dhPubImpl->pk = savedDhPk;

    HcfOpensslDhPriKey *dhPriImpl = reinterpret_cast<HcfOpensslDhPriKey *>(dhPair->priKey);
    DH *savedDhSk = dhPriImpl->sk;
    dhPriImpl->sk = nullptr;
    EXPECT_EQ(dhPair->priKey->base.getKeySize(reinterpret_cast<HcfKey *>(dhPair->priKey), &size),
        HCF_ERR_PARAMETER_CHECK_FAILED);
    dhPriImpl->sk = savedDhSk;

    HcfObjDestroy(rsaPair);
    HcfObjDestroy(rsaGen);
    HcfObjDestroy(dhPair);
    HcfObjDestroy(dhGen);
}

HWTEST_F(CryptoGetKeySizeAsyTest, GetKeySizeSm2ExceptionBranches, TestSize.Level1)
{
    HcfAsyKeyGenerator *sm2Gen = nullptr;
    int32_t sm2Res = HcfAsyKeyGeneratorCreate("SM2_256", &sm2Gen);
    if (sm2Res != HCF_SUCCESS || sm2Gen == nullptr) {
        return;
    }
    HcfKeyPair *sm2Pair = nullptr;
    sm2Res = sm2Gen->generateKeyPair(sm2Gen, nullptr, &sm2Pair);
    if (sm2Res != HCF_SUCCESS || sm2Pair == nullptr) {
        HcfObjDestroy(sm2Gen);
        return;
    }
    HcfAsyKeyGenerator *rsaGen = nullptr;
    ASSERT_EQ(HcfAsyKeyGeneratorCreate("RSA2048|PRIMES_2", &rsaGen), HCF_SUCCESS);
    HcfKeyPair *rsaPair = nullptr;
    ASSERT_EQ(rsaGen->generateKeyPair(rsaGen, nullptr, &rsaPair), HCF_SUCCESS);

    int size = 0;
    EXPECT_EQ(sm2Pair->pubKey->base.getKeySize(reinterpret_cast<HcfKey *>(rsaPair->pubKey), &size),
        HCF_ERR_PARAMETER_CHECK_FAILED);

    HcfOpensslSm2PubKey *sm2PubImpl = reinterpret_cast<HcfOpensslSm2PubKey *>(sm2Pair->pubKey);
    EC_KEY *savedEcKey = sm2PubImpl->ecKey;
    sm2PubImpl->ecKey = nullptr;
    EXPECT_EQ(sm2Pair->pubKey->base.getKeySize(reinterpret_cast<HcfKey *>(sm2Pair->pubKey), &size),
        HCF_ERR_PARAMETER_CHECK_FAILED);
    sm2PubImpl->ecKey = savedEcKey;

    StartRecordOpensslCallNum();
    SetOpensslCallMockIndex(1);
    EXPECT_EQ(sm2Pair->pubKey->base.getKeySize(reinterpret_cast<HcfKey *>(sm2Pair->pubKey), &size),
        HCF_ERR_CRYPTO_OPERATION);
    EndRecordOpensslCallNum();

    StartRecordOpensslCallNum();
    SetOpensslCallMockIndex(2);
    EXPECT_EQ(sm2Pair->pubKey->base.getKeySize(reinterpret_cast<HcfKey *>(sm2Pair->pubKey), &size),
        HCF_ERR_CRYPTO_OPERATION);
    EndRecordOpensslCallNum();

    HcfObjDestroy(rsaPair);
    HcfObjDestroy(rsaGen);
    HcfObjDestroy(sm2Pair);
    HcfObjDestroy(sm2Gen);
}

HWTEST_F(CryptoGetKeySizeAsyTest, GetKeySizeEccExceptionBranches, TestSize.Level1)
{
    HcfAsyKeyGenerator *eccGen = nullptr;
    ASSERT_EQ(HcfAsyKeyGeneratorCreate("ECC256", &eccGen), HCF_SUCCESS);
    HcfKeyPair *eccPair = nullptr;
    ASSERT_EQ(eccGen->generateKeyPair(eccGen, nullptr, &eccPair), HCF_SUCCESS);

    int size = 0;
    StartRecordOpensslCallNum();
    SetOpensslCallMockIndex(1);
    EXPECT_EQ(eccPair->pubKey->base.getKeySize(reinterpret_cast<HcfKey *>(eccPair->pubKey), &size),
        HCF_ERR_CRYPTO_OPERATION);
    EndRecordOpensslCallNum();

    StartRecordOpensslCallNum();
    SetOpensslCallMockIndex(2);
    EXPECT_EQ(eccPair->pubKey->base.getKeySize(reinterpret_cast<HcfKey *>(eccPair->pubKey), &size),
        HCF_ERR_CRYPTO_OPERATION);
    EndRecordOpensslCallNum();

    HcfObjDestroy(eccPair);
    HcfObjDestroy(eccGen);
}

HWTEST_F(CryptoGetKeySizeAsyTest, GetKeySizeAlg25519ExceptionBranches, TestSize.Level1)
{
    HcfAsyKeyGenerator *edGen = nullptr;
    int32_t edRes = HcfAsyKeyGeneratorCreate("Ed25519", &edGen);
    if (edRes != HCF_SUCCESS || edGen == nullptr) {
        return;
    }
    HcfKeyPair *edPair = nullptr;
    edRes = edGen->generateKeyPair(edGen, nullptr, &edPair);
    if (edRes != HCF_SUCCESS || edPair == nullptr) {
        HcfObjDestroy(edGen);
        return;
    }
    HcfAsyKeyGenerator *rsaGen = nullptr;
    ASSERT_EQ(HcfAsyKeyGeneratorCreate("RSA2048|PRIMES_2", &rsaGen), HCF_SUCCESS);
    HcfKeyPair *rsaPair = nullptr;
    ASSERT_EQ(rsaGen->generateKeyPair(rsaGen, nullptr, &rsaPair), HCF_SUCCESS);

    int size = 0;
    EXPECT_EQ(edPair->pubKey->base.getKeySize(reinterpret_cast<HcfKey *>(rsaPair->pubKey), &size),
        HCF_ERR_PARAMETER_CHECK_FAILED);

    HcfObjDestroy(rsaPair);
    HcfObjDestroy(rsaGen);
    HcfObjDestroy(edPair);
    HcfObjDestroy(edGen);
}

HWTEST_F(CryptoGetKeySizeSymTest, GetKeySizeSymExceptionBranches, TestSize.Level1)
{
    HcfSymKeyGenerator *generator = nullptr;
    int32_t ret = HcfSymKeyGeneratorCreate("AES128", &generator);
    ASSERT_EQ(ret, HCF_SUCCESS);
    ASSERT_NE(generator, nullptr);

    HcfSymKey *symKey = nullptr;
    ret = generator->generateSymKey(generator, &symKey);
    ASSERT_EQ(ret, HCF_SUCCESS);
    ASSERT_NE(symKey, nullptr);

    HcfKey *key = reinterpret_cast<HcfKey *>(&symKey->key);
    int keySizeBits = 0;

    EXPECT_EQ(key->getKeySize(nullptr, &keySizeBits), HCF_ERR_PARAMETER_CHECK_FAILED);
    EXPECT_EQ(key->getKeySize(key, nullptr), HCF_ERR_PARAMETER_CHECK_FAILED);

    HcfAsyKeyGenerator *asyGen = nullptr;
    ASSERT_EQ(HcfAsyKeyGeneratorCreate("RSA2048|PRIMES_2", &asyGen), HCF_SUCCESS);
    HcfKeyPair *keyPair = nullptr;
    ASSERT_EQ(asyGen->generateKeyPair(asyGen, nullptr, &keyPair), HCF_SUCCESS);
    EXPECT_EQ(key->getKeySize(reinterpret_cast<HcfKey *>(keyPair->pubKey), &keySizeBits),
        HCF_ERR_PARAMETER_CHECK_FAILED);
    HcfObjDestroy(keyPair);
    HcfObjDestroy(asyGen);

    SymKeyImpl *impl = reinterpret_cast<SymKeyImpl *>(symKey);
    size_t savedLen = impl->keyMaterial.len;
    impl->keyMaterial.len = static_cast<size_t>(INT_MAX / 8) + 1;
    EXPECT_EQ(key->getKeySize(key, &keySizeBits), HCF_ERR_PARAMETER_CHECK_FAILED);
    impl->keyMaterial.len = savedLen;

    HcfObjDestroy(symKey);
    HcfObjDestroy(generator);
}
}  // namespace
