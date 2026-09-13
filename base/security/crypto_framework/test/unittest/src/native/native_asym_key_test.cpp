/*
 * Copyright (C) 2024 Huawei Device Co., Ltd.
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
#include "memory.h"
#include "memory_mock.h"
#include "openssl_adapter_mock.h"

using namespace std;
using namespace testing::ext;

static string g_testPubkeyX509Str512 = "-----BEGIN PUBLIC KEY-----\n"
"MFwwDQYJKoZIhvcNAQEBBQADSwAwSAJBAKG0KN3tjZM8dCNfCg9bcmZM3Bhv/mRr\n"
"Mxuvua2Ru8Kr1NL+/wyeEMnIARFr+Alf1Tyfjy0PWwFnf8jHWRsz0vkCAwEAAQ==\n"
"-----END PUBLIC KEY-----\n";

static string g_testPubkeyPkcs1Str512 = "-----BEGIN RSA PUBLIC KEY-----\n"
"MEgCQQChtCjd7Y2TPHQjXwoPW3JmTNwYb/5kazMbr7mtkbvCq9TS/v8MnhDJyAER\n"
"a/gJX9U8n48tD1sBZ3/Ix1kbM9L5AgMBAAE=\n"
"-----END RSA PUBLIC KEY-----\n";

namespace {
class NativeAsymKeyTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp();
    void TearDown();
};

void NativeAsymKeyTest::SetUpTestCase() {}
void NativeAsymKeyTest::TearDownTestCase() {}

void NativeAsymKeyTest::SetUp() // add init here, this will be called before test.
{
}

void NativeAsymKeyTest::TearDown() // add destroy here, this will be called when test case done.
{
}

static OH_CryptoKeyPair *GenerateKeyPair(const char *algName)
{
    OH_CryptoAsymKeyGenerator *generator = nullptr;
    OH_Crypto_ErrCode ret = OH_CryptoAsymKeyGenerator_Create(algName, &generator);
    if (ret != CRYPTO_SUCCESS) {
        return nullptr;
    }

    OH_CryptoKeyPair *keyCtx = nullptr;
    ret = OH_CryptoAsymKeyGenerator_Generate(generator, &keyCtx);
    if (ret != CRYPTO_SUCCESS) {
        OH_CryptoAsymKeyGenerator_Destroy(generator);
        return nullptr;
    }

    OH_CryptoAsymKeyGenerator_Destroy(generator);
    return keyCtx;
}

static OH_Crypto_ErrCode GenerateKeyPairWithSpec(OH_CryptoAsymKeySpec *keySpec, OH_CryptoKeyPair **keyPair)
{
    OH_CryptoAsymKeyGeneratorWithSpec *generatorSpec = nullptr;
    OH_Crypto_ErrCode ret = OH_CryptoAsymKeyGeneratorWithSpec_Create(keySpec, &generatorSpec);
    if (ret != CRYPTO_SUCCESS) {
        return ret;
    }
    ret = OH_CryptoAsymKeyGeneratorWithSpec_GenKeyPair(generatorSpec, keyPair);
    OH_CryptoAsymKeyGeneratorWithSpec_Destroy(generatorSpec);
    return ret;
}

static OH_Crypto_ErrCode GetDsaKeyParams(OH_CryptoKeyPair *keyCtx, Crypto_DataBlob *pubKeyData,
                                         Crypto_DataBlob *privKeyData, Crypto_DataBlob *pData, Crypto_DataBlob *qData,
                                         Crypto_DataBlob *gData)
{
    OH_CryptoPubKey *pubKey = OH_CryptoKeyPair_GetPubKey(keyCtx);
    if (pubKey == nullptr) {
        return CRYPTO_OPERTION_ERROR;
    }
    OH_Crypto_ErrCode ret = OH_CryptoPubKey_GetParam(pubKey, CRYPTO_DSA_PK_DATABLOB, pubKeyData);
    if (ret != CRYPTO_SUCCESS) {
        return ret;
    }

    OH_CryptoPrivKey *privKey = OH_CryptoKeyPair_GetPrivKey(keyCtx);
    if (privKey == nullptr) {
        return CRYPTO_OPERTION_ERROR;
    }
    ret = OH_CryptoPrivKey_GetParam(privKey, CRYPTO_DSA_SK_DATABLOB, privKeyData);
    if (ret != CRYPTO_SUCCESS) {
        return ret;
    }
    ret = OH_CryptoPrivKey_GetParam(privKey, CRYPTO_DSA_P_DATABLOB, pData);
    if (ret != CRYPTO_SUCCESS) {
        return ret;
    }
    ret = OH_CryptoPrivKey_GetParam(privKey, CRYPTO_DSA_Q_DATABLOB, qData);
    if (ret != CRYPTO_SUCCESS) {
        return ret;
    }
    ret = OH_CryptoPrivKey_GetParam(privKey, CRYPTO_DSA_G_DATABLOB, gData);
    return ret;
}

static OH_Crypto_ErrCode GetRsaKeyParams(OH_CryptoKeyPair *keyCtx, Crypto_DataBlob *pubKeyData,
                                         Crypto_DataBlob *privKeyData, Crypto_DataBlob *nData)
{
    OH_CryptoPubKey *pubKey = OH_CryptoKeyPair_GetPubKey(keyCtx);
    if (pubKey == nullptr) {
        return CRYPTO_OPERTION_ERROR;
    }
    OH_Crypto_ErrCode ret = OH_CryptoPubKey_GetParam(pubKey, CRYPTO_RSA_E_DATABLOB, pubKeyData);
    if (ret != CRYPTO_SUCCESS) {
        return ret;
    }

    OH_CryptoPrivKey *privKey = OH_CryptoKeyPair_GetPrivKey(keyCtx);
    if (privKey == nullptr) {
        return CRYPTO_OPERTION_ERROR;
    }
    ret = OH_CryptoPrivKey_GetParam(privKey, CRYPTO_RSA_D_DATABLOB, privKeyData);
    if (ret != CRYPTO_SUCCESS) {
        return ret;
    }
    ret = OH_CryptoPrivKey_GetParam(privKey, CRYPTO_RSA_N_DATABLOB, nData);
    return ret;
}

static OH_Crypto_ErrCode GetDhKeyParams(OH_CryptoKeyPair *keyCtx, Crypto_DataBlob *pubKeyData,
                                        Crypto_DataBlob *privKeyData)
{
    OH_CryptoPubKey *pubKey = OH_CryptoKeyPair_GetPubKey(keyCtx);
    if (pubKey == nullptr) {
        return CRYPTO_OPERTION_ERROR;
    }
    OH_Crypto_ErrCode ret = OH_CryptoPubKey_GetParam(pubKey, CRYPTO_DH_PK_DATABLOB, pubKeyData);
    if (ret != CRYPTO_SUCCESS) {
        return ret;
    }

    OH_CryptoPrivKey *privKey = OH_CryptoKeyPair_GetPrivKey(keyCtx);
    if (privKey == nullptr) {
        return CRYPTO_OPERTION_ERROR;
    }
    ret = OH_CryptoPrivKey_GetParam(privKey, CRYPTO_DH_SK_DATABLOB, privKeyData);
    return ret;
}

static OH_Crypto_ErrCode GetX25519KeyParams(OH_CryptoKeyPair *keyCtx, Crypto_DataBlob *pubKeyData,
                                            Crypto_DataBlob *privKeyData)
{
    OH_CryptoPubKey *pubKey = OH_CryptoKeyPair_GetPubKey(keyCtx);
    if (pubKey == nullptr) {
        return CRYPTO_OPERTION_ERROR;
    }
    OH_Crypto_ErrCode ret = OH_CryptoPubKey_GetParam(pubKey, CRYPTO_X25519_PK_DATABLOB, pubKeyData);
    if (ret != CRYPTO_SUCCESS) {
        return ret;
    }

    OH_CryptoPrivKey *privKey = OH_CryptoKeyPair_GetPrivKey(keyCtx);
    if (privKey == nullptr) {
        return CRYPTO_OPERTION_ERROR;
    }
    ret = OH_CryptoPrivKey_GetParam(privKey, CRYPTO_X25519_SK_DATABLOB, privKeyData);
    return ret;
}

static OH_Crypto_ErrCode GetEccKeyParams(OH_CryptoKeyPair *keyCtx, Crypto_DataBlob *pubKeyXData,
                                         Crypto_DataBlob *pubKeyYData, Crypto_DataBlob *privKeyData)
{
    OH_CryptoPubKey *pubKey = OH_CryptoKeyPair_GetPubKey(keyCtx);
    if (pubKey == nullptr) {
        return CRYPTO_OPERTION_ERROR;
    }
    OH_Crypto_ErrCode ret = OH_CryptoPubKey_GetParam(pubKey, CRYPTO_ECC_PK_X_DATABLOB, pubKeyXData);
    if (ret != CRYPTO_SUCCESS) {
        return ret;
    }
    ret = OH_CryptoPubKey_GetParam(pubKey, CRYPTO_ECC_PK_Y_DATABLOB, pubKeyYData);
    if (ret != CRYPTO_SUCCESS) {
        return ret;
    }

    OH_CryptoPrivKey *privKey = OH_CryptoKeyPair_GetPrivKey(keyCtx);
    if (privKey == nullptr) {
        return CRYPTO_OPERTION_ERROR;
    }
    ret = OH_CryptoPrivKey_GetParam(privKey, CRYPTO_ECC_SK_DATABLOB, privKeyData);
    return ret;
}

static void FreeDsaKeyParams(Crypto_DataBlob *pubKeyData, Crypto_DataBlob *privKeyData, Crypto_DataBlob *pData,
                             Crypto_DataBlob *qData, Crypto_DataBlob *gData)
{
    OH_Crypto_FreeDataBlob(pubKeyData);
    OH_Crypto_FreeDataBlob(privKeyData);
    OH_Crypto_FreeDataBlob(pData);
    OH_Crypto_FreeDataBlob(qData);
    OH_Crypto_FreeDataBlob(gData);
}

static void FreeRsaKeyParams(Crypto_DataBlob *pubKeyData, Crypto_DataBlob *privKeyData, Crypto_DataBlob *nData)
{
    OH_Crypto_FreeDataBlob(pubKeyData);
    OH_Crypto_FreeDataBlob(privKeyData);
    OH_Crypto_FreeDataBlob(nData);
}

static void FreeDhKeyParams(Crypto_DataBlob *pubKeyData, Crypto_DataBlob *privKeyData)
{
    OH_Crypto_FreeDataBlob(pubKeyData);
    OH_Crypto_FreeDataBlob(privKeyData);
}

static void FreeX25519KeyParams(Crypto_DataBlob *pubKeyData, Crypto_DataBlob *privKeyData)
{
    OH_Crypto_FreeDataBlob(pubKeyData);
    OH_Crypto_FreeDataBlob(privKeyData);
}

static void FreeEccKeyParams(Crypto_DataBlob *pubKeyXData, Crypto_DataBlob *pubKeyYData, Crypto_DataBlob *privKeyData)
{
    OH_Crypto_FreeDataBlob(pubKeyXData);
    OH_Crypto_FreeDataBlob(pubKeyYData);
    OH_Crypto_FreeDataBlob(privKeyData);
}

static void FreeDhCommonParams(Crypto_DataBlob *pData, Crypto_DataBlob *gData, Crypto_DataBlob *lData)
{
    OH_Crypto_FreeDataBlob(pData);
    OH_Crypto_FreeDataBlob(gData);
    OH_Crypto_FreeDataBlob(lData);
}

static void FreeEccCommonParams(Crypto_DataBlob *pData, Crypto_DataBlob *aData, Crypto_DataBlob *bData,
                                Crypto_DataBlob *gxData, Crypto_DataBlob *gyData, Crypto_DataBlob *nData,
                                Crypto_DataBlob *hData)
{
    OH_Crypto_FreeDataBlob(pData);
    OH_Crypto_FreeDataBlob(aData);
    OH_Crypto_FreeDataBlob(bData);
    OH_Crypto_FreeDataBlob(gxData);
    OH_Crypto_FreeDataBlob(gyData);
    OH_Crypto_FreeDataBlob(nData);
    OH_Crypto_FreeDataBlob(hData);
}

HWTEST_F(NativeAsymKeyTest, NativeAsymKeyTest001, TestSize.Level0)
{
    OH_CryptoAsymKeyGenerator *generator = nullptr;
    OH_CryptoKeyPair *keyCtx = nullptr;
    OH_Crypto_ErrCode ret = OH_CryptoAsymKeyGenerator_Create("DSA2048", &generator);
    EXPECT_EQ(ret, CRYPTO_SUCCESS);
    ret = OH_CryptoAsymKeyGenerator_Generate(generator, &keyCtx);
    EXPECT_EQ(ret, CRYPTO_SUCCESS);

    const char *algoName = OH_CryptoAsymKeyGenerator_GetAlgoName(generator);
    ASSERT_NE(algoName, nullptr);

    OH_CryptoPubKey *pubKey = OH_CryptoKeyPair_GetPubKey(keyCtx);

    Crypto_DataBlob dataBlob = {.data = nullptr, .len = 0};
    ret = OH_CryptoPubKey_GetParam(pubKey, CRYPTO_DSA_Q_DATABLOB, &dataBlob);
    EXPECT_EQ(ret, CRYPTO_SUCCESS);
    ASSERT_NE(dataBlob.data, nullptr);
    ASSERT_NE(dataBlob.len, 0);
    HcfFree(dataBlob.data);
    OH_CryptoKeyPair_Destroy(keyCtx);
    OH_CryptoAsymKeyGenerator_Destroy(generator);
}

HWTEST_F(NativeAsymKeyTest, NativeAsymKeyTest002, TestSize.Level0)
{
    OH_CryptoAsymKeyGenerator *generator = nullptr;
    OH_Crypto_ErrCode res = OH_CryptoAsymKeyGenerator_Create("RSA512", &generator);
    EXPECT_EQ(res, CRYPTO_SUCCESS);
    EXPECT_NE(generator, nullptr);

    OH_CryptoKeyPair *dupKeyPair = nullptr;
    Crypto_DataBlob pubKeyX509Str = {};
    pubKeyX509Str.data = reinterpret_cast<uint8_t *>(const_cast<char *>(g_testPubkeyX509Str512.c_str()));
    pubKeyX509Str.len = strlen(g_testPubkeyX509Str512.c_str());

    Crypto_DataBlob pubKeyPkcs1Str = {};
    pubKeyPkcs1Str.data = reinterpret_cast<uint8_t *>(const_cast<char *>(g_testPubkeyPkcs1Str512.c_str()));
    pubKeyPkcs1Str.len = strlen(g_testPubkeyPkcs1Str512.c_str());
    res = OH_CryptoAsymKeyGenerator_Convert(generator, CRYPTO_PEM, &pubKeyX509Str, nullptr, &dupKeyPair);
    EXPECT_EQ(res, CRYPTO_SUCCESS);

    OH_CryptoPubKey *pubkey = OH_CryptoKeyPair_GetPubKey(dupKeyPair);
    Crypto_DataBlob retBlob = {.data = nullptr, .len = 0};
    res = OH_CryptoPubKey_Encode(pubkey, CRYPTO_PEM, "PKCS1", &retBlob);
    EXPECT_EQ(res, CRYPTO_SUCCESS);
    int32_t cmpRes =
        strcmp(reinterpret_cast<const char *>(retBlob.data), reinterpret_cast<const char *>(pubKeyPkcs1Str.data));
    EXPECT_EQ(cmpRes, CRYPTO_SUCCESS);

    Crypto_DataBlob retBlobX509 = {.data = nullptr, .len = 0};
    res = OH_CryptoPubKey_Encode(pubkey, CRYPTO_PEM, "X509", &retBlobX509);
    EXPECT_EQ(res, CRYPTO_SUCCESS);
    cmpRes =
        strcmp(reinterpret_cast<const char *>(retBlobX509.data), reinterpret_cast<const char *>(pubKeyX509Str.data));
    EXPECT_EQ(cmpRes, CRYPTO_SUCCESS);

    OH_Crypto_FreeDataBlob(&retBlob);
    OH_Crypto_FreeDataBlob(&retBlobX509);
    OH_CryptoKeyPair_Destroy(dupKeyPair);
    OH_CryptoAsymKeyGenerator_Destroy(generator);
}

HWTEST_F(NativeAsymKeyTest, NativeAsymKeyTest003, TestSize.Level0)
{
    OH_CryptoAsymKeyGenerator *generator = nullptr;
    OH_CryptoKeyPair *keyCtx = nullptr;
    OH_Crypto_ErrCode ret = OH_CryptoAsymKeyGenerator_Create("RSA768", &generator);
    EXPECT_EQ(ret, CRYPTO_SUCCESS);
    ret = OH_CryptoAsymKeyGenerator_Generate(generator, &keyCtx);
    EXPECT_EQ(ret, CRYPTO_SUCCESS);

    OH_CryptoPubKey *pubKey = OH_CryptoKeyPair_GetPubKey(keyCtx);
    Crypto_DataBlob dataBlobE = {.data = nullptr, .len = 0};
    ret = OH_CryptoPubKey_GetParam(pubKey, CRYPTO_RSA_E_DATABLOB, &dataBlobE);
    EXPECT_EQ(ret, CRYPTO_SUCCESS);
    ASSERT_NE(dataBlobE.data, nullptr);
    ASSERT_NE(dataBlobE.len, 0);
    HcfFree(dataBlobE.data);
    OH_CryptoKeyPair_Destroy(keyCtx);
    OH_CryptoAsymKeyGenerator_Destroy(generator);
}

HWTEST_F(NativeAsymKeyTest, NativeAsymKeyTest004, TestSize.Level0)
{
    OH_CryptoAsymKeyGenerator *ctx = nullptr;
    OH_CryptoKeyPair *keyPair = nullptr;
    OH_Crypto_ErrCode ret;

    ret = OH_CryptoAsymKeyGenerator_Create("RSA512|PRIMES_2", &ctx);
    ASSERT_EQ(ret, CRYPTO_SUCCESS);

    ret = OH_CryptoAsymKeyGenerator_Generate(ctx, &keyPair);
    ASSERT_EQ(ret, CRYPTO_SUCCESS);

    const char *algoName = OH_CryptoAsymKeyGenerator_GetAlgoName(ctx);
    EXPECT_NE(algoName, nullptr);

    OH_CryptoPubKey *pubKey = OH_CryptoKeyPair_GetPubKey(keyPair);
    ASSERT_EQ(ret, CRYPTO_SUCCESS);

    Crypto_DataBlob retBlob = {.data = nullptr, .len = 0};
    ret = OH_CryptoPubKey_Encode(pubKey, CRYPTO_PEM, "PKCS1", &retBlob);
    ASSERT_EQ(ret, CRYPTO_SUCCESS);

    OH_CryptoKeyPair *dupKeyPair = nullptr;
    ret = OH_CryptoAsymKeyGenerator_Convert(ctx, CRYPTO_PEM, &retBlob, nullptr, &dupKeyPair);
    ASSERT_EQ(ret, CRYPTO_SUCCESS);

    OH_CryptoPubKey *pubKey1 = OH_CryptoKeyPair_GetPubKey(dupKeyPair);
    ASSERT_EQ(ret, CRYPTO_SUCCESS);
    Crypto_DataBlob dataBlob = {.data = nullptr, .len = 0};

    ret = OH_CryptoPubKey_GetParam(pubKey1, CRYPTO_RSA_N_DATABLOB, &dataBlob);
    ASSERT_EQ(ret, CRYPTO_SUCCESS);
    ASSERT_NE(dataBlob.data, nullptr);
    ASSERT_NE(dataBlob.len, 0);
    OH_Crypto_FreeDataBlob(&dataBlob);

    OH_CryptoAsymKeyGenerator_Destroy(ctx);
    OH_CryptoKeyPair_Destroy(keyPair);
    OH_Crypto_FreeDataBlob(&retBlob);
    OH_CryptoKeyPair_Destroy(dupKeyPair);
}

HWTEST_F(NativeAsymKeyTest, NativeAsymKeyTest005, TestSize.Level0)
{
    OH_CryptoAsymKeyGenerator *ctx = nullptr;
    OH_CryptoKeyPair *keyPair = nullptr;
    OH_Crypto_ErrCode ret;

    ret = OH_CryptoAsymKeyGenerator_Create("Ed25519", &ctx);
    ASSERT_EQ(ret, CRYPTO_SUCCESS);

    ret = OH_CryptoAsymKeyGenerator_Generate(ctx, &keyPair);
    ASSERT_EQ(ret, CRYPTO_SUCCESS);

    const char *algoName = OH_CryptoAsymKeyGenerator_GetAlgoName(ctx);
    EXPECT_NE(algoName, nullptr);

    OH_CryptoPubKey *pubKey = OH_CryptoKeyPair_GetPubKey(keyPair);
    ASSERT_EQ(ret, CRYPTO_SUCCESS);

    Crypto_DataBlob retBlob = {.data = nullptr, .len = 0};
    ret = OH_CryptoPubKey_Encode(pubKey, CRYPTO_DER, nullptr, &retBlob);
    ASSERT_EQ(ret, CRYPTO_SUCCESS);

    OH_CryptoKeyPair *dupKeyPair = nullptr;
    ret = OH_CryptoAsymKeyGenerator_Convert(ctx, CRYPTO_DER, &retBlob, nullptr, &dupKeyPair);
    ASSERT_EQ(ret, CRYPTO_SUCCESS);

    OH_CryptoPubKey *pubKey1 = OH_CryptoKeyPair_GetPubKey(dupKeyPair);
    ASSERT_EQ(ret, CRYPTO_SUCCESS);
    Crypto_DataBlob dataBlob = {.data = nullptr, .len = 0};

    ret = OH_CryptoPubKey_GetParam(pubKey1, CRYPTO_ED25519_PK_DATABLOB, &dataBlob);
    ASSERT_EQ(ret, CRYPTO_SUCCESS);
    ASSERT_NE(dataBlob.data, nullptr);
    ASSERT_NE(dataBlob.len, 0);
    OH_Crypto_FreeDataBlob(&dataBlob);
    OH_Crypto_FreeDataBlob(&retBlob);

    OH_CryptoAsymKeyGenerator_Destroy(ctx);
    OH_CryptoKeyPair_Destroy(keyPair);
    OH_CryptoKeyPair_Destroy(dupKeyPair);
}

HWTEST_F(NativeAsymKeyTest, NativeAsymKeyTest006, TestSize.Level0)
{
    OH_CryptoAsymKeyGenerator *keyGen = nullptr;
    OH_Crypto_ErrCode ret = OH_CryptoAsymKeyGenerator_Create("RSA2048", &keyGen);
    EXPECT_EQ(ret, CRYPTO_SUCCESS);
    ASSERT_NE(keyGen, nullptr);

    OH_CryptoKeyPair *keyPair = nullptr;
    ret = OH_CryptoAsymKeyGenerator_Generate(keyGen, &keyPair);
    EXPECT_EQ(ret, CRYPTO_SUCCESS);
    ASSERT_NE(keyPair, nullptr);

    OH_CryptoPrivKey *privKey = OH_CryptoKeyPair_GetPrivKey(keyPair);
    ASSERT_NE(privKey, nullptr);

    OH_CryptoPrivKeyEncodingParams *params = nullptr;
    ret = OH_CryptoPrivKeyEncodingParams_Create(&params);
    EXPECT_EQ(ret, CRYPTO_SUCCESS);
    ASSERT_NE(params, nullptr);

    Crypto_DataBlob password = {(uint8_t *)"1234567890", 10};
    Crypto_DataBlob cipher = {(uint8_t *)"AES-128-CBC", 11};
    ret = OH_CryptoPrivKeyEncodingParams_SetParam(params, CRYPTO_PRIVATE_KEY_ENCODING_PASSWORD_STR, &password);
    EXPECT_EQ(ret, CRYPTO_SUCCESS);
    ret = OH_CryptoPrivKeyEncodingParams_SetParam(params, CRYPTO_PRIVATE_KEY_ENCODING_SYMMETRIC_CIPHER_STR, &cipher);
    EXPECT_EQ(ret, CRYPTO_SUCCESS);

    Crypto_DataBlob pemData = {0};
    ret = OH_CryptoPrivKey_Encode(privKey, CRYPTO_PEM, "PKCS8", nullptr, &pemData);
    EXPECT_EQ(ret, CRYPTO_SUCCESS);
    OH_Crypto_FreeDataBlob(&pemData);

    ret = OH_CryptoPrivKey_Encode(privKey, CRYPTO_PEM, "PKCS8", params, &pemData);
    EXPECT_EQ(ret, CRYPTO_SUCCESS);
    ret = OH_CryptoAsymKeyGenerator_SetPassword(keyGen, password.data, password.len);
    EXPECT_EQ(ret, CRYPTO_SUCCESS);
    OH_CryptoKeyPair *keyCtx = nullptr;
    ret = OH_CryptoAsymKeyGenerator_Convert(keyGen, CRYPTO_PEM, nullptr, &pemData, &keyCtx);
    EXPECT_EQ(ret, CRYPTO_SUCCESS);
    OH_CryptoKeyPair_Destroy(keyCtx);

    Crypto_DataBlob n = {0};
    Crypto_DataBlob d = {0};
    ret = OH_CryptoPrivKey_GetParam(privKey, CRYPTO_RSA_N_DATABLOB, &n);
    EXPECT_EQ(ret, CRYPTO_SUCCESS);
    ret = OH_CryptoPrivKey_GetParam(privKey, CRYPTO_RSA_D_DATABLOB, &d);
    EXPECT_EQ(ret, CRYPTO_SUCCESS);

    OH_Crypto_FreeDataBlob(&pemData);
    OH_Crypto_FreeDataBlob(&n);
    OH_Crypto_FreeDataBlob(&d);
    OH_CryptoPrivKeyEncodingParams_Destroy(params);
    OH_CryptoKeyPair_Destroy(keyPair);
    OH_CryptoAsymKeyGenerator_Destroy(keyGen);
}

HWTEST_F(NativeAsymKeyTest, NativeAsymKeyTest007, TestSize.Level0)
{
    OH_CryptoAsymKeyGenerator *keyGen = nullptr;
    OH_Crypto_ErrCode ret = OH_CryptoAsymKeyGenerator_Create("ECC224", &keyGen);
    EXPECT_EQ(ret, CRYPTO_SUCCESS);
    ASSERT_NE(keyGen, nullptr);

    OH_CryptoKeyPair *keyPair = nullptr;
    ret = OH_CryptoAsymKeyGenerator_Generate(keyGen, &keyPair);
    EXPECT_EQ(ret, CRYPTO_SUCCESS);
    ASSERT_NE(keyPair, nullptr);

    OH_CryptoPrivKey *privKey = OH_CryptoKeyPair_GetPrivKey(keyPair);
    ASSERT_NE(privKey, nullptr);

    Crypto_DataBlob derData = {0};
    ret = OH_CryptoPrivKey_Encode(nullptr, CRYPTO_DER, "PKCS8", nullptr, &derData);
    EXPECT_NE(ret, CRYPTO_SUCCESS);
    ret = OH_CryptoPrivKey_Encode(privKey, CRYPTO_DER, "PKCS8", nullptr, nullptr);
    EXPECT_NE(ret, CRYPTO_SUCCESS);

    ret = OH_CryptoPrivKey_Encode(privKey, CRYPTO_DER, "PKCS8", nullptr, &derData);
    EXPECT_EQ(ret, CRYPTO_SUCCESS);
    ASSERT_NE(derData.data, nullptr);
    ASSERT_NE(derData.len, 0);
    OH_Crypto_FreeDataBlob(&derData);

    ret = OH_CryptoPrivKey_Encode(privKey, CRYPTO_DER, nullptr, nullptr, &derData);
    EXPECT_EQ(ret, CRYPTO_SUCCESS);
    ASSERT_NE(derData.data, nullptr);
    ASSERT_NE(derData.len, 0);
    OH_Crypto_FreeDataBlob(&derData);

    OH_CryptoKeyPair_Destroy(keyPair);
    OH_CryptoAsymKeyGenerator_Destroy(keyGen);
}

HWTEST_F(NativeAsymKeyTest, NativeAsymKeyTest008, TestSize.Level0)
{
    OH_CryptoKeyPair *keyCtx = GenerateKeyPair("DSA2048");
    ASSERT_NE(keyCtx, nullptr);
    Crypto_DataBlob pubKeyData = {.data = nullptr, .len = 0};
    Crypto_DataBlob privKeyData = {.data = nullptr, .len = 0};
    Crypto_DataBlob pData = {.data = nullptr, .len = 0};
    Crypto_DataBlob qData = {.data = nullptr, .len = 0};
    Crypto_DataBlob gData = {.data = nullptr, .len = 0};
    OH_Crypto_ErrCode ret = GetDsaKeyParams(keyCtx, &pubKeyData, &privKeyData, &pData, &qData, &gData);
    EXPECT_EQ(ret, CRYPTO_SUCCESS);

    OH_CryptoAsymKeySpec *keySpec = nullptr;
    ret = OH_CryptoAsymKeySpec_Create("DSA", CRYPTO_ASYM_KEY_KEY_PAIR_SPEC, &keySpec);
    EXPECT_EQ(ret, CRYPTO_SUCCESS);
    ret = OH_CryptoAsymKeySpec_SetParam(keySpec, CRYPTO_DSA_PK_DATABLOB, &pubKeyData);
    EXPECT_EQ(ret, CRYPTO_SUCCESS);
    ret = OH_CryptoAsymKeySpec_SetParam(keySpec, CRYPTO_DSA_SK_DATABLOB, &privKeyData);
    EXPECT_EQ(ret, CRYPTO_SUCCESS);
    ret = OH_CryptoAsymKeySpec_SetParam(keySpec, CRYPTO_DSA_P_DATABLOB, &pData);
    EXPECT_EQ(ret, CRYPTO_SUCCESS);
    ret = OH_CryptoAsymKeySpec_SetParam(keySpec, CRYPTO_DSA_Q_DATABLOB, &qData);
    EXPECT_EQ(ret, CRYPTO_SUCCESS);
    ret = OH_CryptoAsymKeySpec_SetParam(keySpec, CRYPTO_DSA_G_DATABLOB, &gData);
    EXPECT_EQ(ret, CRYPTO_SUCCESS);
    FreeDsaKeyParams(&pubKeyData, &privKeyData, &pData, &qData, &gData);
    ret = OH_CryptoAsymKeySpec_GetParam(keySpec, CRYPTO_DSA_PK_DATABLOB, &pubKeyData);
    EXPECT_EQ(ret, CRYPTO_SUCCESS);
    ret = OH_CryptoAsymKeySpec_GetParam(keySpec, CRYPTO_DSA_SK_DATABLOB, &privKeyData);
    EXPECT_EQ(ret, CRYPTO_SUCCESS);
    ret = OH_CryptoAsymKeySpec_GetParam(keySpec, CRYPTO_DSA_P_DATABLOB, &pData);
    EXPECT_EQ(ret, CRYPTO_SUCCESS);
    ret = OH_CryptoAsymKeySpec_GetParam(keySpec, CRYPTO_DSA_Q_DATABLOB, &qData);
    EXPECT_EQ(ret, CRYPTO_SUCCESS);
    ret = OH_CryptoAsymKeySpec_GetParam(keySpec, CRYPTO_DSA_G_DATABLOB, &gData);
    EXPECT_EQ(ret, CRYPTO_SUCCESS);
    FreeDsaKeyParams(&pubKeyData, &privKeyData, &pData, &qData, &gData);

    OH_CryptoKeyPair *keyPair = nullptr;
    ret = GenerateKeyPairWithSpec(keySpec, &keyPair);
    EXPECT_EQ(ret, CRYPTO_SUCCESS);
    ASSERT_NE(keyPair, nullptr);
    ASSERT_NE(OH_CryptoKeyPair_GetPubKey(keyPair), nullptr);
    ASSERT_NE(OH_CryptoKeyPair_GetPrivKey(keyPair), nullptr);
    OH_CryptoKeyPair_Destroy(keyPair);
    OH_CryptoAsymKeySpec_Destroy(keySpec);
    OH_CryptoKeyPair_Destroy(keyCtx);
}

HWTEST_F(NativeAsymKeyTest, NativeAsymKeyTest009, TestSize.Level0)
{
    OH_CryptoKeyPair *keyCtx = GenerateKeyPair("DSA2048");
    ASSERT_NE(keyCtx, nullptr);
    Crypto_DataBlob pubKeyData = {.data = nullptr, .len = 0};
    Crypto_DataBlob privKeyData = {.data = nullptr, .len = 0};
    Crypto_DataBlob pData = {.data = nullptr, .len = 0};
    Crypto_DataBlob qData = {.data = nullptr, .len = 0};
    Crypto_DataBlob gData = {.data = nullptr, .len = 0};
    OH_Crypto_ErrCode ret = GetDsaKeyParams(keyCtx, &pubKeyData, &privKeyData, &pData, &qData, &gData);
    EXPECT_EQ(ret, CRYPTO_SUCCESS);

    OH_CryptoAsymKeySpec *keySpec = nullptr;
    ret = OH_CryptoAsymKeySpec_Create("DSA", CRYPTO_ASYM_KEY_PUBLIC_KEY_SPEC, &keySpec);
    EXPECT_EQ(ret, CRYPTO_SUCCESS);
    ret = OH_CryptoAsymKeySpec_SetParam(keySpec, CRYPTO_DSA_PK_DATABLOB, &pubKeyData);
    EXPECT_EQ(ret, CRYPTO_SUCCESS);
    ret = OH_CryptoAsymKeySpec_SetParam(keySpec, CRYPTO_DSA_SK_DATABLOB, &privKeyData);
    EXPECT_NE(ret, CRYPTO_SUCCESS);
    ret = OH_CryptoAsymKeySpec_SetParam(keySpec, CRYPTO_DSA_P_DATABLOB, &pData);
    EXPECT_EQ(ret, CRYPTO_SUCCESS);
    ret = OH_CryptoAsymKeySpec_SetParam(keySpec, CRYPTO_DSA_Q_DATABLOB, &qData);
    EXPECT_EQ(ret, CRYPTO_SUCCESS);
    ret = OH_CryptoAsymKeySpec_SetParam(keySpec, CRYPTO_DSA_G_DATABLOB, &gData);
    EXPECT_EQ(ret, CRYPTO_SUCCESS);
    FreeDsaKeyParams(&pubKeyData, &privKeyData, &pData, &qData, &gData);
    ret = OH_CryptoAsymKeySpec_GetParam(keySpec, CRYPTO_DSA_PK_DATABLOB, &pubKeyData);
    EXPECT_EQ(ret, CRYPTO_SUCCESS);
    ret = OH_CryptoAsymKeySpec_GetParam(keySpec, CRYPTO_DSA_SK_DATABLOB, &privKeyData);
    EXPECT_NE(ret, CRYPTO_SUCCESS);
    ret = OH_CryptoAsymKeySpec_GetParam(keySpec, CRYPTO_DSA_P_DATABLOB, &pData);
    EXPECT_EQ(ret, CRYPTO_SUCCESS);
    ret = OH_CryptoAsymKeySpec_GetParam(keySpec, CRYPTO_DSA_Q_DATABLOB, &qData);
    EXPECT_EQ(ret, CRYPTO_SUCCESS);
    ret = OH_CryptoAsymKeySpec_GetParam(keySpec, CRYPTO_DSA_G_DATABLOB, &gData);
    EXPECT_EQ(ret, CRYPTO_SUCCESS);
    FreeDsaKeyParams(&pubKeyData, &privKeyData, &pData, &qData, &gData);

    OH_CryptoKeyPair *keyPair = nullptr;
    ret = GenerateKeyPairWithSpec(keySpec, &keyPair);
    EXPECT_EQ(ret, CRYPTO_SUCCESS);
    ASSERT_NE(keyPair, nullptr);
    ASSERT_NE(OH_CryptoKeyPair_GetPubKey(keyPair), nullptr);
    ASSERT_EQ(OH_CryptoKeyPair_GetPrivKey(keyPair), nullptr);

    OH_CryptoKeyPair_Destroy(keyPair);
    OH_CryptoAsymKeySpec_Destroy(keySpec);
    OH_CryptoKeyPair_Destroy(keyCtx);
}

HWTEST_F(NativeAsymKeyTest, NativeAsymKeyTest010, TestSize.Level0)
{
    OH_CryptoKeyPair *keyCtx = GenerateKeyPair("DSA2048");
    ASSERT_NE(keyCtx, nullptr);
    Crypto_DataBlob pubKeyData = {.data = nullptr, .len = 0};
    Crypto_DataBlob privKeyData = {.data = nullptr, .len = 0};
    Crypto_DataBlob pData = {.data = nullptr, .len = 0};
    Crypto_DataBlob qData = {.data = nullptr, .len = 0};
    Crypto_DataBlob gData = {.data = nullptr, .len = 0};
    OH_Crypto_ErrCode ret = GetDsaKeyParams(keyCtx, &pubKeyData, &privKeyData, &pData, &qData, &gData);
    EXPECT_EQ(ret, CRYPTO_SUCCESS);

    OH_CryptoAsymKeySpec *keySpec = nullptr;
    ret = OH_CryptoAsymKeySpec_Create("DSA", CRYPTO_ASYM_KEY_PRIVATE_KEY_SPEC, &keySpec);
    EXPECT_NE(ret, CRYPTO_SUCCESS);
    ret = OH_CryptoAsymKeySpec_Create("DSA", CRYPTO_ASYM_KEY_COMMON_PARAMS_SPEC, &keySpec);
    EXPECT_EQ(ret, CRYPTO_SUCCESS);
    ret = OH_CryptoAsymKeySpec_SetParam(keySpec, CRYPTO_DSA_PK_DATABLOB, &pubKeyData);
    EXPECT_NE(ret, CRYPTO_SUCCESS);
    ret = OH_CryptoAsymKeySpec_SetParam(keySpec, CRYPTO_DSA_SK_DATABLOB, &privKeyData);
    EXPECT_NE(ret, CRYPTO_SUCCESS);
    ret = OH_CryptoAsymKeySpec_SetParam(keySpec, CRYPTO_DSA_P_DATABLOB, &pData);
    EXPECT_EQ(ret, CRYPTO_SUCCESS);
    ret = OH_CryptoAsymKeySpec_SetParam(keySpec, CRYPTO_DSA_Q_DATABLOB, &qData);
    EXPECT_EQ(ret, CRYPTO_SUCCESS);
    ret = OH_CryptoAsymKeySpec_SetParam(keySpec, CRYPTO_DSA_G_DATABLOB, &gData);
    EXPECT_EQ(ret, CRYPTO_SUCCESS);
    FreeDsaKeyParams(&pubKeyData, &privKeyData, &pData, &qData, &gData);
    ret = OH_CryptoAsymKeySpec_GetParam(keySpec, CRYPTO_DSA_PK_DATABLOB, &pubKeyData);
    EXPECT_NE(ret, CRYPTO_SUCCESS);
    ret = OH_CryptoAsymKeySpec_GetParam(keySpec, CRYPTO_DSA_SK_DATABLOB, &privKeyData);
    EXPECT_NE(ret, CRYPTO_SUCCESS);
    ret = OH_CryptoAsymKeySpec_GetParam(keySpec, CRYPTO_DSA_P_DATABLOB, &pData);
    EXPECT_EQ(ret, CRYPTO_SUCCESS);
    ret = OH_CryptoAsymKeySpec_GetParam(keySpec, CRYPTO_DSA_Q_DATABLOB, &qData);
    EXPECT_EQ(ret, CRYPTO_SUCCESS);
    ret = OH_CryptoAsymKeySpec_GetParam(keySpec, CRYPTO_DSA_G_DATABLOB, &gData);
    EXPECT_EQ(ret, CRYPTO_SUCCESS);
    FreeDsaKeyParams(&pubKeyData, &privKeyData, &pData, &qData, &gData);

    OH_CryptoKeyPair *keyPair = nullptr;
    ret = GenerateKeyPairWithSpec(keySpec, &keyPair);
    EXPECT_EQ(ret, CRYPTO_SUCCESS);
    ASSERT_NE(keyPair, nullptr);
    ASSERT_NE(OH_CryptoKeyPair_GetPubKey(keyPair), nullptr);
    ASSERT_NE(OH_CryptoKeyPair_GetPrivKey(keyPair), nullptr);

    OH_CryptoKeyPair_Destroy(keyPair);
    OH_CryptoAsymKeySpec_Destroy(keySpec);
    OH_CryptoKeyPair_Destroy(keyCtx);
}

HWTEST_F(NativeAsymKeyTest, NativeAsymKeyTest011, TestSize.Level0)
{
    OH_CryptoKeyPair *keyCtx = GenerateKeyPair("RSA2048");
    ASSERT_NE(keyCtx, nullptr);
    Crypto_DataBlob pubKeyData = {.data = nullptr, .len = 0};
    Crypto_DataBlob privKeyData = {.data = nullptr, .len = 0};
    Crypto_DataBlob nData = {.data = nullptr, .len = 0};
    OH_Crypto_ErrCode ret = GetRsaKeyParams(keyCtx, &pubKeyData, &privKeyData, &nData);
    EXPECT_EQ(ret, CRYPTO_SUCCESS);

    OH_CryptoAsymKeySpec *keySpec = nullptr;
    ret = OH_CryptoAsymKeySpec_Create("RSA", CRYPTO_ASYM_KEY_KEY_PAIR_SPEC, &keySpec);
    EXPECT_EQ(ret, CRYPTO_SUCCESS);
    ret = OH_CryptoAsymKeySpec_SetParam(keySpec, CRYPTO_RSA_E_DATABLOB, &pubKeyData);
    EXPECT_EQ(ret, CRYPTO_SUCCESS);
    ret = OH_CryptoAsymKeySpec_SetParam(keySpec, CRYPTO_RSA_D_DATABLOB, &privKeyData);
    EXPECT_EQ(ret, CRYPTO_SUCCESS);
    ret = OH_CryptoAsymKeySpec_SetParam(keySpec, CRYPTO_RSA_N_DATABLOB, &nData);
    EXPECT_EQ(ret, CRYPTO_SUCCESS);
    FreeRsaKeyParams(&pubKeyData, &privKeyData, &nData);
    ret = OH_CryptoAsymKeySpec_GetParam(keySpec, CRYPTO_RSA_E_DATABLOB, &pubKeyData);
    EXPECT_EQ(ret, CRYPTO_SUCCESS);
    ret = OH_CryptoAsymKeySpec_GetParam(keySpec, CRYPTO_RSA_D_DATABLOB, &privKeyData);
    EXPECT_EQ(ret, CRYPTO_SUCCESS);
    ret = OH_CryptoAsymKeySpec_GetParam(keySpec, CRYPTO_RSA_N_DATABLOB, &nData);
    EXPECT_EQ(ret, CRYPTO_SUCCESS);
    FreeRsaKeyParams(&pubKeyData, &privKeyData, &nData);

    OH_CryptoKeyPair *keyPair = nullptr;
    ret = GenerateKeyPairWithSpec(keySpec, &keyPair);
    EXPECT_EQ(ret, CRYPTO_SUCCESS);
    ASSERT_NE(keyPair, nullptr);
    ASSERT_NE(OH_CryptoKeyPair_GetPubKey(keyPair), nullptr);
    ASSERT_NE(OH_CryptoKeyPair_GetPrivKey(keyPair), nullptr);
    OH_CryptoKeyPair_Destroy(keyPair);
    OH_CryptoAsymKeySpec_Destroy(keySpec);
    OH_CryptoKeyPair_Destroy(keyCtx);
}

HWTEST_F(NativeAsymKeyTest, NativeAsymKeyTest012, TestSize.Level0)
{
    OH_CryptoKeyPair *keyCtx = GenerateKeyPair("RSA2048");
    ASSERT_NE(keyCtx, nullptr);
    Crypto_DataBlob pubKeyData = {.data = nullptr, .len = 0};
    Crypto_DataBlob privKeyData = {.data = nullptr, .len = 0};
    Crypto_DataBlob nData = {.data = nullptr, .len = 0};
    OH_Crypto_ErrCode ret = GetRsaKeyParams(keyCtx, &pubKeyData, &privKeyData, &nData);
    EXPECT_EQ(ret, CRYPTO_SUCCESS);

    OH_CryptoAsymKeySpec *keySpec = nullptr;
    ret = OH_CryptoAsymKeySpec_Create("RSA", CRYPTO_ASYM_KEY_PUBLIC_KEY_SPEC, &keySpec);
    EXPECT_EQ(ret, CRYPTO_SUCCESS);
    ret = OH_CryptoAsymKeySpec_SetParam(keySpec, CRYPTO_RSA_E_DATABLOB, &pubKeyData);
    EXPECT_EQ(ret, CRYPTO_SUCCESS);
    ret = OH_CryptoAsymKeySpec_SetParam(keySpec, CRYPTO_RSA_D_DATABLOB, &privKeyData);
    EXPECT_NE(ret, CRYPTO_SUCCESS);
    ret = OH_CryptoAsymKeySpec_SetParam(keySpec, CRYPTO_RSA_N_DATABLOB, &nData);
    EXPECT_EQ(ret, CRYPTO_SUCCESS);
    FreeRsaKeyParams(&pubKeyData, &privKeyData, &nData);
    ret = OH_CryptoAsymKeySpec_GetParam(keySpec, CRYPTO_RSA_E_DATABLOB, &pubKeyData);
    EXPECT_EQ(ret, CRYPTO_SUCCESS);
    ret = OH_CryptoAsymKeySpec_GetParam(keySpec, CRYPTO_RSA_D_DATABLOB, &privKeyData);
    EXPECT_NE(ret, CRYPTO_SUCCESS);
    ret = OH_CryptoAsymKeySpec_GetParam(keySpec, CRYPTO_RSA_N_DATABLOB, &nData);
    EXPECT_EQ(ret, CRYPTO_SUCCESS);
    FreeRsaKeyParams(&pubKeyData, &privKeyData, &nData);

    OH_CryptoKeyPair *keyPair = nullptr;
    ret = GenerateKeyPairWithSpec(keySpec, &keyPair);
    EXPECT_EQ(ret, CRYPTO_SUCCESS);
    ASSERT_NE(keyPair, nullptr);
    ASSERT_NE(OH_CryptoKeyPair_GetPubKey(keyPair), nullptr);
    EXPECT_EQ(OH_CryptoKeyPair_GetPrivKey(keyPair), nullptr);

    OH_CryptoKeyPair_Destroy(keyPair);
    OH_CryptoAsymKeySpec_Destroy(keySpec);
    OH_CryptoKeyPair_Destroy(keyCtx);
}

HWTEST_F(NativeAsymKeyTest, NativeAsymKeyTest013, TestSize.Level0)
{
    OH_CryptoAsymKeySpec *keySpec = nullptr;
    OH_Crypto_ErrCode ret = OH_CryptoAsymKeySpec_Create("RSA", CRYPTO_ASYM_KEY_PRIVATE_KEY_SPEC, &keySpec);
    ASSERT_NE(ret, CRYPTO_SUCCESS);
    ret = OH_CryptoAsymKeySpec_Create("RSA", CRYPTO_ASYM_KEY_COMMON_PARAMS_SPEC, &keySpec);
    ASSERT_NE(ret, CRYPTO_SUCCESS);
}

HWTEST_F(NativeAsymKeyTest, NativeAsymKeyTest014, TestSize.Level0)
{
    OH_CryptoKeyPair *keyCtx = GenerateKeyPair("DH_modp2048");
    ASSERT_NE(keyCtx, nullptr);
    Crypto_DataBlob pubKeyData = {.data = nullptr, .len = 0};
    Crypto_DataBlob privKeyData = {.data = nullptr, .len = 0};
    OH_Crypto_ErrCode ret = GetDhKeyParams(keyCtx, &pubKeyData, &privKeyData);
    EXPECT_EQ(ret, CRYPTO_SUCCESS);

    OH_CryptoAsymKeySpec *dhCommonSpec = nullptr;
    ret = OH_CryptoAsymKeySpec_GenDhCommonParamsSpec(2048, 1024, &dhCommonSpec);
    EXPECT_EQ(ret, CRYPTO_SUCCESS);
    OH_CryptoAsymKeySpec *keySpec = nullptr;
    ret = OH_CryptoAsymKeySpec_Create("DH", CRYPTO_ASYM_KEY_KEY_PAIR_SPEC, &keySpec);
    EXPECT_EQ(ret, CRYPTO_SUCCESS);
    ret = OH_CryptoAsymKeySpec_SetCommonParamsSpec(keySpec, dhCommonSpec);
    EXPECT_EQ(ret, CRYPTO_SUCCESS);
    ret = OH_CryptoAsymKeySpec_SetParam(keySpec, CRYPTO_DH_PK_DATABLOB, &pubKeyData);
    EXPECT_EQ(ret, CRYPTO_SUCCESS);
    ret = OH_CryptoAsymKeySpec_SetParam(keySpec, CRYPTO_DH_SK_DATABLOB, &privKeyData);
    EXPECT_EQ(ret, CRYPTO_SUCCESS);
    FreeDhKeyParams(&pubKeyData, &privKeyData);
    ret = OH_CryptoAsymKeySpec_GetParam(keySpec, CRYPTO_DH_PK_DATABLOB, &pubKeyData);
    EXPECT_EQ(ret, CRYPTO_SUCCESS);
    ret = OH_CryptoAsymKeySpec_GetParam(keySpec, CRYPTO_DH_SK_DATABLOB, &privKeyData);
    EXPECT_EQ(ret, CRYPTO_SUCCESS);
    FreeDhKeyParams(&pubKeyData, &privKeyData);

    OH_CryptoKeyPair *keyPair = nullptr;
    ret = GenerateKeyPairWithSpec(keySpec, &keyPair);
    EXPECT_EQ(ret, CRYPTO_SUCCESS);
    ASSERT_NE(keyPair, nullptr);
    ASSERT_NE(OH_CryptoKeyPair_GetPubKey(keyPair), nullptr);
    ASSERT_NE(OH_CryptoKeyPair_GetPrivKey(keyPair), nullptr);

    OH_CryptoKeyPair_Destroy(keyPair);
    OH_CryptoAsymKeySpec_Destroy(keySpec);
    OH_CryptoAsymKeySpec_Destroy(dhCommonSpec);
    OH_CryptoKeyPair_Destroy(keyCtx);
}

HWTEST_F(NativeAsymKeyTest, NativeAsymKeyTest015, TestSize.Level0)
{
    OH_CryptoKeyPair *keyCtx = GenerateKeyPair("DH_modp2048");
    ASSERT_NE(keyCtx, nullptr);
    Crypto_DataBlob pubKeyData = {.data = nullptr, .len = 0};
    Crypto_DataBlob privKeyData = {.data = nullptr, .len = 0};
    OH_Crypto_ErrCode ret = GetDhKeyParams(keyCtx, &pubKeyData, &privKeyData);
    EXPECT_EQ(ret, CRYPTO_SUCCESS);

    OH_CryptoAsymKeySpec *dhCommonSpec = nullptr;
    ret = OH_CryptoAsymKeySpec_GenDhCommonParamsSpec(2048, 1024, &dhCommonSpec);
    EXPECT_EQ(ret, CRYPTO_SUCCESS);
    OH_CryptoAsymKeySpec *keySpec = nullptr;
    ret = OH_CryptoAsymKeySpec_Create("DH", CRYPTO_ASYM_KEY_PUBLIC_KEY_SPEC, &keySpec);
    EXPECT_EQ(ret, CRYPTO_SUCCESS);
    ret = OH_CryptoAsymKeySpec_SetCommonParamsSpec(keySpec, dhCommonSpec);
    EXPECT_EQ(ret, CRYPTO_SUCCESS);
    ret = OH_CryptoAsymKeySpec_SetParam(keySpec, CRYPTO_DH_PK_DATABLOB, &pubKeyData);
    EXPECT_EQ(ret, CRYPTO_SUCCESS);
    ret = OH_CryptoAsymKeySpec_SetParam(keySpec, CRYPTO_DH_SK_DATABLOB, &privKeyData);
    EXPECT_NE(ret, CRYPTO_SUCCESS);
    FreeDhKeyParams(&pubKeyData, &privKeyData);
    ret = OH_CryptoAsymKeySpec_GetParam(keySpec, CRYPTO_DH_PK_DATABLOB, &pubKeyData);
    EXPECT_EQ(ret, CRYPTO_SUCCESS);
    ret = OH_CryptoAsymKeySpec_GetParam(keySpec, CRYPTO_DH_SK_DATABLOB, &privKeyData);
    EXPECT_NE(ret, CRYPTO_SUCCESS);
    FreeDhKeyParams(&pubKeyData, &privKeyData);

    OH_CryptoKeyPair *keyPair = nullptr;
    ret = GenerateKeyPairWithSpec(keySpec, &keyPair);
    EXPECT_EQ(ret, CRYPTO_SUCCESS);
    ASSERT_NE(keyPair, nullptr);
    ASSERT_NE(OH_CryptoKeyPair_GetPubKey(keyPair), nullptr);
    EXPECT_EQ(OH_CryptoKeyPair_GetPrivKey(keyPair), nullptr);

    OH_CryptoKeyPair_Destroy(keyPair);
    OH_CryptoAsymKeySpec_Destroy(keySpec);
    OH_CryptoAsymKeySpec_Destroy(dhCommonSpec);
    OH_CryptoKeyPair_Destroy(keyCtx);
}

HWTEST_F(NativeAsymKeyTest, NativeAsymKeyTest016, TestSize.Level0)
{
    OH_CryptoKeyPair *keyCtx = GenerateKeyPair("DH_modp2048");
    ASSERT_NE(keyCtx, nullptr);
    Crypto_DataBlob pubKeyData = {.data = nullptr, .len = 0};
    Crypto_DataBlob privKeyData = {.data = nullptr, .len = 0};
    OH_Crypto_ErrCode ret = GetDhKeyParams(keyCtx, &pubKeyData, &privKeyData);
    EXPECT_EQ(ret, CRYPTO_SUCCESS);

    OH_CryptoAsymKeySpec *dhCommonSpec = nullptr;
    ret = OH_CryptoAsymKeySpec_GenDhCommonParamsSpec(2048, 1024, &dhCommonSpec);
    EXPECT_EQ(ret, CRYPTO_SUCCESS);
    OH_CryptoAsymKeySpec *keySpec = nullptr;
    ret = OH_CryptoAsymKeySpec_Create("DH", CRYPTO_ASYM_KEY_PRIVATE_KEY_SPEC, &keySpec);
    EXPECT_EQ(ret, CRYPTO_SUCCESS);
    ret = OH_CryptoAsymKeySpec_SetCommonParamsSpec(keySpec, dhCommonSpec);
    EXPECT_EQ(ret, CRYPTO_SUCCESS);
    ret = OH_CryptoAsymKeySpec_SetParam(keySpec, CRYPTO_DH_PK_DATABLOB, &pubKeyData);
    EXPECT_NE(ret, CRYPTO_SUCCESS);
    ret = OH_CryptoAsymKeySpec_SetParam(keySpec, CRYPTO_DH_SK_DATABLOB, &privKeyData);
    EXPECT_EQ(ret, CRYPTO_SUCCESS);
    FreeDhKeyParams(&pubKeyData, &privKeyData);
    ret = OH_CryptoAsymKeySpec_GetParam(keySpec, CRYPTO_DH_PK_DATABLOB, &pubKeyData);
    EXPECT_NE(ret, CRYPTO_SUCCESS);
    ret = OH_CryptoAsymKeySpec_GetParam(keySpec, CRYPTO_DH_SK_DATABLOB, &privKeyData);
    EXPECT_EQ(ret, CRYPTO_SUCCESS);
    FreeDhKeyParams(&pubKeyData, &privKeyData);

    OH_CryptoKeyPair *keyPair = nullptr;
    ret = GenerateKeyPairWithSpec(keySpec, &keyPair);
    EXPECT_EQ(ret, CRYPTO_SUCCESS);
    ASSERT_NE(keyPair, nullptr);
    EXPECT_NE(OH_CryptoKeyPair_GetPubKey(keyPair), nullptr);
    ASSERT_NE(OH_CryptoKeyPair_GetPrivKey(keyPair), nullptr);

    OH_CryptoKeyPair_Destroy(keyPair);
    OH_CryptoAsymKeySpec_Destroy(keySpec);
    OH_CryptoAsymKeySpec_Destroy(dhCommonSpec);
    OH_CryptoKeyPair_Destroy(keyCtx);
}

HWTEST_F(NativeAsymKeyTest, NativeAsymKeyTest017, TestSize.Level0)
{
    OH_CryptoAsymKeySpec *dhCommonSpec = nullptr;
    OH_Crypto_ErrCode ret = OH_CryptoAsymKeySpec_GenDhCommonParamsSpec(2048, 1024, &dhCommonSpec);
    EXPECT_EQ(ret, CRYPTO_SUCCESS);
    OH_CryptoAsymKeySpec *keySpec = nullptr;
    ret = OH_CryptoAsymKeySpec_Create("DH", CRYPTO_ASYM_KEY_COMMON_PARAMS_SPEC, &keySpec);
    EXPECT_EQ(ret, CRYPTO_SUCCESS);
    ret = OH_CryptoAsymKeySpec_SetCommonParamsSpec(keySpec, dhCommonSpec);
    EXPECT_EQ(ret, CRYPTO_SUCCESS);

    Crypto_DataBlob p = {0};
    Crypto_DataBlob g = {0};
    Crypto_DataBlob l = {0};
    ret = OH_CryptoAsymKeySpec_GetParam(keySpec, CRYPTO_DH_P_DATABLOB, &p);
    EXPECT_EQ(ret, CRYPTO_SUCCESS);
    ret = OH_CryptoAsymKeySpec_GetParam(keySpec, CRYPTO_DH_G_DATABLOB, &g);
    EXPECT_EQ(ret, CRYPTO_SUCCESS);
    ret = OH_CryptoAsymKeySpec_GetParam(keySpec, CRYPTO_DH_L_INT, &l);
    EXPECT_EQ(ret, CRYPTO_SUCCESS);
    FreeDhCommonParams(&p, &g, &l);

    OH_CryptoKeyPair *keyPair = nullptr;
    ret = GenerateKeyPairWithSpec(keySpec, &keyPair);
    EXPECT_EQ(ret, CRYPTO_SUCCESS);
    ASSERT_NE(keyPair, nullptr);
    ASSERT_NE(OH_CryptoKeyPair_GetPubKey(keyPair), nullptr);
    ASSERT_NE(OH_CryptoKeyPair_GetPrivKey(keyPair), nullptr);

    OH_CryptoKeyPair_Destroy(keyPair);
    OH_CryptoAsymKeySpec_Destroy(dhCommonSpec);
    OH_CryptoAsymKeySpec_Destroy(keySpec);
}

HWTEST_F(NativeAsymKeyTest, NativeAsymKeyTest018, TestSize.Level0)
{
    OH_CryptoKeyPair *keyCtx = GenerateKeyPair("X25519");
    ASSERT_NE(keyCtx, nullptr);
    Crypto_DataBlob pubKeyData = {.data = nullptr, .len = 0};
    Crypto_DataBlob privKeyData = {.data = nullptr, .len = 0};
    OH_Crypto_ErrCode ret = GetX25519KeyParams(keyCtx, &pubKeyData, &privKeyData);
    EXPECT_EQ(ret, CRYPTO_SUCCESS);

    OH_CryptoAsymKeySpec *keySpec = nullptr;
    ret = OH_CryptoAsymKeySpec_Create("X25519", CRYPTO_ASYM_KEY_KEY_PAIR_SPEC, &keySpec);
    EXPECT_EQ(ret, CRYPTO_SUCCESS);
    ret = OH_CryptoAsymKeySpec_SetParam(keySpec, CRYPTO_X25519_PK_DATABLOB, &pubKeyData);
    EXPECT_EQ(ret, CRYPTO_SUCCESS);
    ret = OH_CryptoAsymKeySpec_SetParam(keySpec, CRYPTO_X25519_SK_DATABLOB, &privKeyData);
    EXPECT_EQ(ret, CRYPTO_SUCCESS);
    FreeX25519KeyParams(&pubKeyData, &privKeyData);
    ret = OH_CryptoAsymKeySpec_GetParam(keySpec, CRYPTO_X25519_PK_DATABLOB, &pubKeyData);
    EXPECT_EQ(ret, CRYPTO_SUCCESS);
    ret = OH_CryptoAsymKeySpec_GetParam(keySpec, CRYPTO_X25519_SK_DATABLOB, &privKeyData);
    EXPECT_EQ(ret, CRYPTO_SUCCESS);
    FreeX25519KeyParams(&pubKeyData, &privKeyData);

    OH_CryptoKeyPair *keyPair = nullptr;
    ret = GenerateKeyPairWithSpec(keySpec, &keyPair);
    EXPECT_EQ(ret, CRYPTO_SUCCESS);
    ASSERT_NE(keyPair, nullptr);
    ASSERT_NE(OH_CryptoKeyPair_GetPubKey(keyPair), nullptr);
    ASSERT_NE(OH_CryptoKeyPair_GetPrivKey(keyPair), nullptr);
    OH_CryptoKeyPair_Destroy(keyPair);
    OH_CryptoAsymKeySpec_Destroy(keySpec);
    OH_CryptoKeyPair_Destroy(keyCtx);
}

HWTEST_F(NativeAsymKeyTest, NativeAsymKeyTest019, TestSize.Level0)
{
    OH_CryptoKeyPair *keyCtx = GenerateKeyPair("X25519");
    ASSERT_NE(keyCtx, nullptr);
    Crypto_DataBlob pubKeyData = {.data = nullptr, .len = 0};
    Crypto_DataBlob privKeyData = {.data = nullptr, .len = 0};
    OH_Crypto_ErrCode ret = GetX25519KeyParams(keyCtx, &pubKeyData, &privKeyData);
    EXPECT_EQ(ret, CRYPTO_SUCCESS);

    OH_CryptoAsymKeySpec *keySpec = nullptr;
    ret = OH_CryptoAsymKeySpec_Create("X25519", CRYPTO_ASYM_KEY_PUBLIC_KEY_SPEC, &keySpec);
    EXPECT_EQ(ret, CRYPTO_SUCCESS);
    ret = OH_CryptoAsymKeySpec_SetParam(keySpec, CRYPTO_X25519_PK_DATABLOB, &pubKeyData);
    EXPECT_EQ(ret, CRYPTO_SUCCESS);
    ret = OH_CryptoAsymKeySpec_SetParam(keySpec, CRYPTO_X25519_SK_DATABLOB, &privKeyData);
    EXPECT_NE(ret, CRYPTO_SUCCESS);
    FreeX25519KeyParams(&pubKeyData, &privKeyData);
    ret = OH_CryptoAsymKeySpec_GetParam(keySpec, CRYPTO_X25519_PK_DATABLOB, &pubKeyData);
    EXPECT_EQ(ret, CRYPTO_SUCCESS);
    ret = OH_CryptoAsymKeySpec_GetParam(keySpec, CRYPTO_X25519_SK_DATABLOB, &privKeyData);
    EXPECT_NE(ret, CRYPTO_SUCCESS);
    FreeX25519KeyParams(&pubKeyData, &privKeyData);

    OH_CryptoKeyPair *keyPair = nullptr;
    ret = GenerateKeyPairWithSpec(keySpec, &keyPair);
    EXPECT_EQ(ret, CRYPTO_SUCCESS);
    ASSERT_NE(keyPair, nullptr);
    ASSERT_NE(OH_CryptoKeyPair_GetPubKey(keyPair), nullptr);
    EXPECT_EQ(OH_CryptoKeyPair_GetPrivKey(keyPair), nullptr);

    OH_CryptoKeyPair_Destroy(keyPair);
    OH_CryptoAsymKeySpec_Destroy(keySpec);
    OH_CryptoKeyPair_Destroy(keyCtx);
}

HWTEST_F(NativeAsymKeyTest, NativeAsymKeyTest020, TestSize.Level0)
{
    OH_CryptoKeyPair *keyCtx = GenerateKeyPair("X25519");
    ASSERT_NE(keyCtx, nullptr);
    Crypto_DataBlob pubKeyData = {.data = nullptr, .len = 0};
    Crypto_DataBlob privKeyData = {.data = nullptr, .len = 0};
    OH_Crypto_ErrCode ret = GetX25519KeyParams(keyCtx, &pubKeyData, &privKeyData);
    EXPECT_EQ(ret, CRYPTO_SUCCESS);

    OH_CryptoAsymKeySpec *keySpec = nullptr;
    ret = OH_CryptoAsymKeySpec_Create("X25519", CRYPTO_ASYM_KEY_PRIVATE_KEY_SPEC, &keySpec);
    EXPECT_EQ(ret, CRYPTO_SUCCESS);
    ret = OH_CryptoAsymKeySpec_SetParam(keySpec, CRYPTO_X25519_PK_DATABLOB, &pubKeyData);
    EXPECT_NE(ret, CRYPTO_SUCCESS);
    ret = OH_CryptoAsymKeySpec_SetParam(keySpec, CRYPTO_X25519_SK_DATABLOB, &privKeyData);
    EXPECT_EQ(ret, CRYPTO_SUCCESS);
    FreeX25519KeyParams(&pubKeyData, &privKeyData);
    ret = OH_CryptoAsymKeySpec_GetParam(keySpec, CRYPTO_X25519_PK_DATABLOB, &pubKeyData);
    EXPECT_NE(ret, CRYPTO_SUCCESS);
    ret = OH_CryptoAsymKeySpec_GetParam(keySpec, CRYPTO_X25519_SK_DATABLOB, &privKeyData);
    EXPECT_EQ(ret, CRYPTO_SUCCESS);
    FreeX25519KeyParams(&pubKeyData, &privKeyData);

    OH_CryptoKeyPair *keyPair = nullptr;
    ret = GenerateKeyPairWithSpec(keySpec, &keyPair);
    EXPECT_EQ(ret, CRYPTO_SUCCESS);
    ASSERT_NE(keyPair, nullptr);
    EXPECT_NE(OH_CryptoKeyPair_GetPubKey(keyPair), nullptr);
    ASSERT_NE(OH_CryptoKeyPair_GetPrivKey(keyPair), nullptr);

    OH_CryptoKeyPair_Destroy(keyPair);
    OH_CryptoAsymKeySpec_Destroy(keySpec);
    OH_CryptoKeyPair_Destroy(keyCtx);
}

HWTEST_F(NativeAsymKeyTest, NativeAsymKeyTest021, TestSize.Level0)
{
    OH_CryptoAsymKeySpec *keySpec = nullptr;
    OH_Crypto_ErrCode ret = OH_CryptoAsymKeySpec_Create("X25519", CRYPTO_ASYM_KEY_COMMON_PARAMS_SPEC, &keySpec);
    EXPECT_NE(ret, CRYPTO_SUCCESS);
    OH_CryptoAsymKeySpec_Destroy(keySpec);
}

HWTEST_F(NativeAsymKeyTest, NativeAsymKeyTest022, TestSize.Level0)
{
    OH_CryptoKeyPair *keyCtx = GenerateKeyPair("ECC_BrainPoolP384r1");
    ASSERT_NE(keyCtx, nullptr);
    Crypto_DataBlob pubKeyXData = {.data = nullptr, .len = 0};
    Crypto_DataBlob pubKeyYData = {.data = nullptr, .len = 0};
    Crypto_DataBlob privKeyData = {.data = nullptr, .len = 0};
    OH_Crypto_ErrCode ret = GetEccKeyParams(keyCtx, &pubKeyXData, &pubKeyYData, &privKeyData);
    EXPECT_EQ(ret, CRYPTO_SUCCESS);

    OH_CryptoAsymKeySpec *ecCommonSpec = nullptr;
    ret = OH_CryptoAsymKeySpec_GenEcCommonParamsSpec("NID_brainpoolP384r1", &ecCommonSpec);
    EXPECT_EQ(ret, CRYPTO_SUCCESS);
    OH_CryptoAsymKeySpec *keySpec = nullptr;
    ret = OH_CryptoAsymKeySpec_Create("ECC", CRYPTO_ASYM_KEY_KEY_PAIR_SPEC, &keySpec);
    EXPECT_EQ(ret, CRYPTO_SUCCESS);
    ret = OH_CryptoAsymKeySpec_SetCommonParamsSpec(keySpec, ecCommonSpec);
    EXPECT_EQ(ret, CRYPTO_SUCCESS);
    ret = OH_CryptoAsymKeySpec_SetParam(keySpec, CRYPTO_ECC_PK_X_DATABLOB, &pubKeyXData);
    EXPECT_EQ(ret, CRYPTO_SUCCESS);
    ret = OH_CryptoAsymKeySpec_SetParam(keySpec, CRYPTO_ECC_PK_Y_DATABLOB, &pubKeyYData);
    EXPECT_EQ(ret, CRYPTO_SUCCESS);
    ret = OH_CryptoAsymKeySpec_SetParam(keySpec, CRYPTO_ECC_SK_DATABLOB, &privKeyData);
    EXPECT_EQ(ret, CRYPTO_SUCCESS);
    FreeEccKeyParams(&pubKeyXData, &pubKeyYData, &privKeyData);
    ret = OH_CryptoAsymKeySpec_GetParam(keySpec, CRYPTO_ECC_PK_X_DATABLOB, &pubKeyXData);
    EXPECT_EQ(ret, CRYPTO_SUCCESS);
    ret = OH_CryptoAsymKeySpec_GetParam(keySpec, CRYPTO_ECC_PK_Y_DATABLOB, &pubKeyYData);
    EXPECT_EQ(ret, CRYPTO_SUCCESS);
    ret = OH_CryptoAsymKeySpec_GetParam(keySpec, CRYPTO_ECC_SK_DATABLOB, &privKeyData);
    EXPECT_EQ(ret, CRYPTO_SUCCESS);
    FreeEccKeyParams(&pubKeyXData, &pubKeyYData, &privKeyData);

    OH_CryptoKeyPair *keyPair = nullptr;
    ret = GenerateKeyPairWithSpec(keySpec, &keyPair);
    // 输入使用大端时会校验成功
    EXPECT_EQ(ret, CRYPTO_SUCCESS);
    ASSERT_NE(keyPair, nullptr);
    ASSERT_NE(OH_CryptoKeyPair_GetPubKey(keyPair), nullptr);
    ASSERT_NE(OH_CryptoKeyPair_GetPrivKey(keyPair), nullptr);

    OH_CryptoKeyPair_Destroy(keyPair);
    OH_CryptoAsymKeySpec_Destroy(keySpec);
    OH_CryptoAsymKeySpec_Destroy(ecCommonSpec);
    OH_CryptoKeyPair_Destroy(keyCtx);
}

HWTEST_F(NativeAsymKeyTest, NativeAsymKeyTest023, TestSize.Level0)
{
    OH_CryptoKeyPair *keyCtx = GenerateKeyPair("ECC_BrainPoolP384r1");
    ASSERT_NE(keyCtx, nullptr);
    Crypto_DataBlob pubKeyXData = {.data = nullptr, .len = 0};
    Crypto_DataBlob pubKeyYData = {.data = nullptr, .len = 0};
    Crypto_DataBlob privKeyData = {.data = nullptr, .len = 0};
    OH_Crypto_ErrCode ret = GetEccKeyParams(keyCtx, &pubKeyXData, &pubKeyYData, &privKeyData);
    EXPECT_EQ(ret, CRYPTO_SUCCESS);

    OH_CryptoAsymKeySpec *ecCommonSpec = nullptr;
    ret = OH_CryptoAsymKeySpec_GenEcCommonParamsSpec("NID_brainpoolP384r1", &ecCommonSpec);
    EXPECT_EQ(ret, CRYPTO_SUCCESS);
    OH_CryptoAsymKeySpec *keySpec = nullptr;
    ret = OH_CryptoAsymKeySpec_Create("ECC", CRYPTO_ASYM_KEY_PUBLIC_KEY_SPEC, &keySpec);
    EXPECT_EQ(ret, CRYPTO_SUCCESS);
    ret = OH_CryptoAsymKeySpec_SetCommonParamsSpec(keySpec, ecCommonSpec);
    EXPECT_EQ(ret, CRYPTO_SUCCESS);
    ret = OH_CryptoAsymKeySpec_SetParam(keySpec, CRYPTO_ECC_PK_X_DATABLOB, &pubKeyXData);
    EXPECT_EQ(ret, CRYPTO_SUCCESS);
    ret = OH_CryptoAsymKeySpec_SetParam(keySpec, CRYPTO_ECC_PK_Y_DATABLOB, &pubKeyYData);
    EXPECT_EQ(ret, CRYPTO_SUCCESS);
    ret = OH_CryptoAsymKeySpec_SetParam(keySpec, CRYPTO_ECC_SK_DATABLOB, &privKeyData);
    EXPECT_NE(ret, CRYPTO_SUCCESS);
    FreeEccKeyParams(&pubKeyXData, &pubKeyYData, &privKeyData);
    ret = OH_CryptoAsymKeySpec_GetParam(keySpec, CRYPTO_ECC_PK_X_DATABLOB, &pubKeyXData);
    EXPECT_EQ(ret, CRYPTO_SUCCESS);
    ret = OH_CryptoAsymKeySpec_GetParam(keySpec, CRYPTO_ECC_PK_Y_DATABLOB, &pubKeyYData);
    EXPECT_EQ(ret, CRYPTO_SUCCESS);
    ret = OH_CryptoAsymKeySpec_GetParam(keySpec, CRYPTO_ECC_SK_DATABLOB, &privKeyData);
    EXPECT_NE(ret, CRYPTO_SUCCESS);
    FreeEccKeyParams(&pubKeyXData, &pubKeyYData, &privKeyData);

    OH_CryptoKeyPair *keyPair = nullptr;
    ret = GenerateKeyPairWithSpec(keySpec, &keyPair);
    // 输入使用大端时会校验成功
    EXPECT_EQ(ret, CRYPTO_SUCCESS);
    ASSERT_NE(keyPair, nullptr);
    ASSERT_NE(OH_CryptoKeyPair_GetPubKey(keyPair), nullptr);
    EXPECT_EQ(OH_CryptoKeyPair_GetPrivKey(keyPair), nullptr);

    OH_CryptoKeyPair_Destroy(keyPair);
    OH_CryptoAsymKeySpec_Destroy(keySpec);
    OH_CryptoAsymKeySpec_Destroy(ecCommonSpec);
    OH_CryptoKeyPair_Destroy(keyCtx);
}

HWTEST_F(NativeAsymKeyTest, NativeAsymKeyTest024, TestSize.Level0)
{
    OH_CryptoKeyPair *keyCtx = GenerateKeyPair("ECC_BrainPoolP384r1");
    ASSERT_NE(keyCtx, nullptr);
    Crypto_DataBlob pubKeyXData = {.data = nullptr, .len = 0};
    Crypto_DataBlob pubKeyYData = {.data = nullptr, .len = 0};
    Crypto_DataBlob privKeyData = {.data = nullptr, .len = 0};
    OH_Crypto_ErrCode ret = GetEccKeyParams(keyCtx, &pubKeyXData, &pubKeyYData, &privKeyData);
    EXPECT_EQ(ret, CRYPTO_SUCCESS);

    OH_CryptoAsymKeySpec *ecCommonSpec = nullptr;
    ret = OH_CryptoAsymKeySpec_GenEcCommonParamsSpec("NID_brainpoolP384r1", &ecCommonSpec);
    EXPECT_EQ(ret, CRYPTO_SUCCESS);
    OH_CryptoAsymKeySpec *keySpec = nullptr;
    ret = OH_CryptoAsymKeySpec_Create("ECC", CRYPTO_ASYM_KEY_PRIVATE_KEY_SPEC, &keySpec);
    EXPECT_EQ(ret, CRYPTO_SUCCESS);
    ret = OH_CryptoAsymKeySpec_SetCommonParamsSpec(keySpec, ecCommonSpec);
    EXPECT_EQ(ret, CRYPTO_SUCCESS);
    ret = OH_CryptoAsymKeySpec_SetParam(keySpec, CRYPTO_ECC_PK_X_DATABLOB, &pubKeyXData);
    EXPECT_NE(ret, CRYPTO_SUCCESS);
    ret = OH_CryptoAsymKeySpec_SetParam(keySpec, CRYPTO_ECC_PK_Y_DATABLOB, &pubKeyYData);
    EXPECT_NE(ret, CRYPTO_SUCCESS);
    ret = OH_CryptoAsymKeySpec_SetParam(keySpec, CRYPTO_ECC_SK_DATABLOB, &privKeyData);
    EXPECT_EQ(ret, CRYPTO_SUCCESS);
    FreeEccKeyParams(&pubKeyXData, &pubKeyYData, &privKeyData);
    ret = OH_CryptoAsymKeySpec_GetParam(keySpec, CRYPTO_ECC_PK_X_DATABLOB, &pubKeyXData);
    EXPECT_NE(ret, CRYPTO_SUCCESS);
    ret = OH_CryptoAsymKeySpec_GetParam(keySpec, CRYPTO_ECC_PK_Y_DATABLOB, &pubKeyYData);
    EXPECT_NE(ret, CRYPTO_SUCCESS);
    ret = OH_CryptoAsymKeySpec_GetParam(keySpec, CRYPTO_ECC_SK_DATABLOB, &privKeyData);
    EXPECT_EQ(ret, CRYPTO_SUCCESS);
    FreeEccKeyParams(&pubKeyXData, &pubKeyYData, &privKeyData);

    OH_CryptoKeyPair *keyPair = nullptr;
    ret = GenerateKeyPairWithSpec(keySpec, &keyPair);
    EXPECT_EQ(ret, CRYPTO_SUCCESS);
    ASSERT_NE(keyPair, nullptr);
    EXPECT_NE(OH_CryptoKeyPair_GetPubKey(keyPair), nullptr);
    ASSERT_NE(OH_CryptoKeyPair_GetPrivKey(keyPair), nullptr);

    OH_CryptoKeyPair_Destroy(keyPair);
    OH_CryptoAsymKeySpec_Destroy(keySpec);
    OH_CryptoAsymKeySpec_Destroy(ecCommonSpec);
    OH_CryptoKeyPair_Destroy(keyCtx);
}

HWTEST_F(NativeAsymKeyTest, NativeAsymKeyTest025, TestSize.Level0)
{
    OH_CryptoAsymKeySpec *ecCommonSpec = nullptr;
    OH_Crypto_ErrCode ret = OH_CryptoAsymKeySpec_GenEcCommonParamsSpec("NID_brainpoolP384r1", &ecCommonSpec);
    EXPECT_EQ(ret, CRYPTO_SUCCESS);
    OH_CryptoAsymKeySpec *keySpec = nullptr;
    ret = OH_CryptoAsymKeySpec_Create("ECC", CRYPTO_ASYM_KEY_COMMON_PARAMS_SPEC, &keySpec);
    EXPECT_EQ(ret, CRYPTO_SUCCESS);
    ret = OH_CryptoAsymKeySpec_SetCommonParamsSpec(keySpec, ecCommonSpec);
    EXPECT_EQ(ret, CRYPTO_SUCCESS);

    Crypto_DataBlob p = {0};
    Crypto_DataBlob a = {0};
    Crypto_DataBlob b = {0};
    Crypto_DataBlob gx = {0};
    Crypto_DataBlob gy = {0};
    Crypto_DataBlob n = {0};
    Crypto_DataBlob h = {0};
    ret = OH_CryptoAsymKeySpec_GetParam(keySpec, CRYPTO_ECC_FP_P_DATABLOB, &p);
    EXPECT_EQ(ret, CRYPTO_SUCCESS);
    ret = OH_CryptoAsymKeySpec_GetParam(keySpec, CRYPTO_ECC_A_DATABLOB, &a);
    EXPECT_EQ(ret, CRYPTO_SUCCESS);
    ret = OH_CryptoAsymKeySpec_GetParam(keySpec, CRYPTO_ECC_B_DATABLOB, &b);
    EXPECT_EQ(ret, CRYPTO_SUCCESS);
    ret = OH_CryptoAsymKeySpec_GetParam(keySpec, CRYPTO_ECC_G_X_DATABLOB, &gx);
    EXPECT_EQ(ret, CRYPTO_SUCCESS);
    ret = OH_CryptoAsymKeySpec_GetParam(keySpec, CRYPTO_ECC_G_Y_DATABLOB, &gy);
    EXPECT_EQ(ret, CRYPTO_SUCCESS);
    ret = OH_CryptoAsymKeySpec_GetParam(keySpec, CRYPTO_ECC_N_DATABLOB, &n);
    EXPECT_EQ(ret, CRYPTO_SUCCESS);
    ret = OH_CryptoAsymKeySpec_GetParam(keySpec, CRYPTO_ECC_H_INT, &h);
    EXPECT_EQ(ret, CRYPTO_SUCCESS);
    FreeEccCommonParams(&p, &a, &b, &gx, &gy, &n, &h);

    OH_CryptoKeyPair *keyPair = nullptr;
    ret = GenerateKeyPairWithSpec(keySpec, &keyPair);
    EXPECT_EQ(ret, CRYPTO_SUCCESS);
    ASSERT_NE(keyPair, nullptr);
    ASSERT_NE(OH_CryptoKeyPair_GetPubKey(keyPair), nullptr);
    ASSERT_NE(OH_CryptoKeyPair_GetPrivKey(keyPair), nullptr);
    OH_CryptoKeyPair_Destroy(keyPair);
    OH_CryptoAsymKeySpec_Destroy(keySpec);
    OH_CryptoAsymKeySpec_Destroy(ecCommonSpec);
}

HWTEST_F(NativeAsymKeyTest, NativeAsymKeyTest026, TestSize.Level0)
{
    OH_CryptoAsymKeySpec *ecCommonSpec = nullptr;
    EXPECT_EQ(OH_CryptoAsymKeySpec_GenEcCommonParamsSpec("NID_brainpoolP384r1", &ecCommonSpec), CRYPTO_SUCCESS);

    Crypto_DataBlob p = {0};
    Crypto_DataBlob a = {0};
    Crypto_DataBlob b = {0};
    Crypto_DataBlob gx = {0};
    Crypto_DataBlob gy = {0};
    Crypto_DataBlob n = {0};
    Crypto_DataBlob h = {0};
    EXPECT_EQ(OH_CryptoAsymKeySpec_GetParam(ecCommonSpec, CRYPTO_ECC_FP_P_DATABLOB, &p), CRYPTO_SUCCESS);
    EXPECT_EQ(OH_CryptoAsymKeySpec_GetParam(ecCommonSpec, CRYPTO_ECC_A_DATABLOB, &a), CRYPTO_SUCCESS);
    EXPECT_EQ(OH_CryptoAsymKeySpec_GetParam(ecCommonSpec, CRYPTO_ECC_B_DATABLOB, &b), CRYPTO_SUCCESS);
    EXPECT_EQ(OH_CryptoAsymKeySpec_GetParam(ecCommonSpec, CRYPTO_ECC_G_X_DATABLOB, &gx), CRYPTO_SUCCESS);
    EXPECT_EQ(OH_CryptoAsymKeySpec_GetParam(ecCommonSpec, CRYPTO_ECC_G_Y_DATABLOB, &gy), CRYPTO_SUCCESS);
    EXPECT_EQ(OH_CryptoAsymKeySpec_GetParam(ecCommonSpec, CRYPTO_ECC_N_DATABLOB, &n), CRYPTO_SUCCESS);
    EXPECT_EQ(OH_CryptoAsymKeySpec_GetParam(ecCommonSpec, CRYPTO_ECC_H_INT, &h), CRYPTO_SUCCESS);

    OH_CryptoAsymKeySpec *keySpec = nullptr;
    EXPECT_EQ(OH_CryptoAsymKeySpec_Create("ECC", CRYPTO_ASYM_KEY_COMMON_PARAMS_SPEC, &keySpec), CRYPTO_SUCCESS);
    EXPECT_EQ(OH_CryptoAsymKeySpec_SetParam(keySpec, CRYPTO_ECC_FP_P_DATABLOB, &p), CRYPTO_SUCCESS);
    EXPECT_EQ(OH_CryptoAsymKeySpec_SetParam(keySpec, CRYPTO_ECC_A_DATABLOB, &a), CRYPTO_SUCCESS);
    EXPECT_EQ(OH_CryptoAsymKeySpec_SetParam(keySpec, CRYPTO_ECC_B_DATABLOB, &b), CRYPTO_SUCCESS);
    EXPECT_EQ(OH_CryptoAsymKeySpec_SetParam(keySpec, CRYPTO_ECC_G_X_DATABLOB, &gx), CRYPTO_SUCCESS);
    EXPECT_EQ(OH_CryptoAsymKeySpec_SetParam(keySpec, CRYPTO_ECC_G_Y_DATABLOB, &gy), CRYPTO_SUCCESS);
    EXPECT_EQ(OH_CryptoAsymKeySpec_SetParam(keySpec, CRYPTO_ECC_N_DATABLOB, &n), CRYPTO_SUCCESS);
    EXPECT_EQ(OH_CryptoAsymKeySpec_SetParam(keySpec, CRYPTO_ECC_H_INT, &h), CRYPTO_SUCCESS);

    OH_CryptoKeyPair *keyPair = nullptr;
    EXPECT_EQ(GenerateKeyPairWithSpec(keySpec, &keyPair), CRYPTO_SUCCESS);
    ASSERT_NE(keyPair, nullptr);
    ASSERT_NE(OH_CryptoKeyPair_GetPubKey(keyPair), nullptr);
    ASSERT_NE(OH_CryptoKeyPair_GetPrivKey(keyPair), nullptr);
    FreeEccCommonParams(&p, &a, &b, &gx, &gy, &n, &h);
    OH_CryptoKeyPair_Destroy(keyPair);
    OH_CryptoAsymKeySpec_Destroy(keySpec);
    OH_CryptoAsymKeySpec_Destroy(ecCommonSpec);
}

HWTEST_F(NativeAsymKeyTest, NativeAsymKeyTest027, TestSize.Level0)
{
    uint8_t prime256v1PointBlobData[] = {
        4,   153, 228, 156, 119, 184, 185, 120, 237, 233, 181, 77,  70,  183, 30,  68, 2,   70,  37,  251, 5,   22,
        199, 84,  87,  222, 65,  103, 8,   26,  255, 137, 206, 80,  159, 163, 46,  22, 104, 156, 169, 14,  149, 199,
        35,  201, 3,   160, 81,  251, 235, 236, 75,  137, 196, 253, 200, 116, 167, 59, 153, 241, 99,  90,  90};
    OH_CryptoEcPoint *point = nullptr;
    Crypto_DataBlob prime256v1PointBlob = {prime256v1PointBlobData, sizeof(prime256v1PointBlobData)};
    OH_Crypto_ErrCode ret = OH_CryptoEcPoint_Create("NID_X9_62_prime256v1", &prime256v1PointBlob, &point);
    EXPECT_EQ(ret, CRYPTO_SUCCESS);
    ASSERT_NE(point, nullptr);

    Crypto_DataBlob ecPubKeyX = {0};
    Crypto_DataBlob ecPubKeyY = {0};
    ret = OH_CryptoEcPoint_GetCoordinate(point, &ecPubKeyX, &ecPubKeyY);
    EXPECT_EQ(ret, CRYPTO_SUCCESS);
    ASSERT_NE(ecPubKeyX.data, nullptr);
    ASSERT_NE(ecPubKeyY.data, nullptr);
    ASSERT_NE(ecPubKeyX.len, 0);
    ASSERT_NE(ecPubKeyY.len, 0);

    OH_CryptoEcPoint *point2 = nullptr;
    ret = OH_CryptoEcPoint_Create("NID_X9_62_prime256v1", nullptr, &point2);
    EXPECT_EQ(ret, CRYPTO_SUCCESS);
    ASSERT_NE(point2, nullptr);

    ret = OH_CryptoEcPoint_SetCoordinate(point2, &ecPubKeyX, &ecPubKeyY);
    EXPECT_EQ(ret, CRYPTO_SUCCESS);

    Crypto_DataBlob returnPointBlobData = {0};
    ret = OH_CryptoEcPoint_Encode(point2, "UNCOMPRESSED", &returnPointBlobData);
    EXPECT_EQ(ret, CRYPTO_SUCCESS);
    ASSERT_NE(returnPointBlobData.data, nullptr);
    ASSERT_NE(returnPointBlobData.len, 0);
    EXPECT_EQ(returnPointBlobData.len, prime256v1PointBlob.len);
    EXPECT_EQ(memcmp(returnPointBlobData.data, prime256v1PointBlob.data, returnPointBlobData.len), 0);

    OH_Crypto_FreeDataBlob(&ecPubKeyX);
    OH_Crypto_FreeDataBlob(&ecPubKeyY);
    OH_Crypto_FreeDataBlob(&returnPointBlobData);
    OH_CryptoEcPoint_Destroy(point);
    OH_CryptoEcPoint_Destroy(point2);
}

HWTEST_F(NativeAsymKeyTest, NativeAsymKeyTest028, TestSize.Level0)
{
    OH_CryptoKeyPair *keyCtx = GenerateKeyPair("DSA2048");
    ASSERT_NE(keyCtx, nullptr);
    Crypto_DataBlob pubKeyData = {.data = nullptr, .len = 0};
    Crypto_DataBlob privKeyData = {.data = nullptr, .len = 0};
    Crypto_DataBlob pData = {.data = nullptr, .len = 0};
    Crypto_DataBlob qData = {.data = nullptr, .len = 0};
    Crypto_DataBlob gData = {.data = nullptr, .len = 0};
    OH_Crypto_ErrCode ret = GetDsaKeyParams(keyCtx, &pubKeyData, &privKeyData, &pData, &qData, &gData);
    EXPECT_EQ(ret, CRYPTO_SUCCESS);

    OH_CryptoAsymKeySpec *dsaCommonSpec = nullptr;
    ret = OH_CryptoAsymKeySpec_Create("DSA", CRYPTO_ASYM_KEY_COMMON_PARAMS_SPEC, &dsaCommonSpec);
    EXPECT_EQ(ret, CRYPTO_SUCCESS);
    ret = OH_CryptoAsymKeySpec_SetParam(dsaCommonSpec, CRYPTO_DSA_P_DATABLOB, &pData);
    EXPECT_EQ(ret, CRYPTO_SUCCESS);
    ret = OH_CryptoAsymKeySpec_SetParam(dsaCommonSpec, CRYPTO_DSA_Q_DATABLOB, &qData);
    EXPECT_EQ(ret, CRYPTO_SUCCESS);
    ret = OH_CryptoAsymKeySpec_SetParam(dsaCommonSpec, CRYPTO_DSA_G_DATABLOB, &gData);
    EXPECT_EQ(ret, CRYPTO_SUCCESS);

    OH_CryptoAsymKeySpec *keySpec = nullptr;
    ret = OH_CryptoAsymKeySpec_Create("DSA", CRYPTO_ASYM_KEY_KEY_PAIR_SPEC, &keySpec);
    EXPECT_EQ(ret, CRYPTO_SUCCESS);
    ret = OH_CryptoAsymKeySpec_SetParam(keySpec, CRYPTO_DSA_PK_DATABLOB, &pubKeyData);
    EXPECT_EQ(ret, CRYPTO_SUCCESS);
    ret = OH_CryptoAsymKeySpec_SetParam(keySpec, CRYPTO_DSA_SK_DATABLOB, &privKeyData);
    EXPECT_EQ(ret, CRYPTO_SUCCESS);
    FreeDsaKeyParams(&pubKeyData, &privKeyData, &pData, &qData, &gData);
    ret = OH_CryptoAsymKeySpec_SetCommonParamsSpec(keySpec, dsaCommonSpec);
    EXPECT_EQ(ret, CRYPTO_SUCCESS);

    OH_CryptoKeyPair *keyPair = nullptr;
    ret = GenerateKeyPairWithSpec(keySpec, &keyPair);
    EXPECT_EQ(ret, CRYPTO_SUCCESS);
    ASSERT_NE(keyPair, nullptr);
    ASSERT_NE(OH_CryptoKeyPair_GetPubKey(keyPair), nullptr);
    ASSERT_NE(OH_CryptoKeyPair_GetPrivKey(keyPair), nullptr);

    OH_CryptoKeyPair_Destroy(keyPair);
    OH_CryptoAsymKeySpec_Destroy(dsaCommonSpec);
    OH_CryptoAsymKeySpec_Destroy(keySpec);
    OH_CryptoKeyPair_Destroy(keyCtx);
}

HWTEST_F(NativeAsymKeyTest, NativeAsymKeyTest029, TestSize.Level0)
{
    OH_CryptoAsymKeyGenerator *ctx = nullptr;
    OH_CryptoKeyPair *keyPair = nullptr;
    OH_Crypto_ErrCode ret;
    ret = OH_CryptoAsymKeyGenerator_Create("ECC256", &ctx);
    EXPECT_EQ(ret, CRYPTO_SUCCESS);
    uint8_t privData[] = {
        0x30, 0x77, 0x02, 0x01, 0x01, 0x04, 0x20, 0x86, 0xcd, 0xb0, 0x6c, 0xed, 0x1f, 0x5b, 0x0a, 0x58,
        0x56, 0xde, 0xdc, 0x66, 0x89, 0x64, 0x3f, 0x43, 0x26, 0x98, 0xc0, 0x7b, 0x70, 0xb4, 0xed, 0x54,
        0x42, 0x52, 0xb0, 0x3e, 0x6c, 0x39, 0xcb, 0xa0, 0x0a, 0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d,
        0x03, 0x01, 0x07, 0xa1, 0x44, 0x03, 0x42, 0x00, 0x04, 0x77, 0xdf, 0x02, 0x14, 0x7e, 0x23, 0x46,
        0x15, 0x64, 0xc2, 0x9b, 0x17, 0x25, 0x2a, 0x81, 0xfe, 0x61, 0x18, 0xb1, 0x75, 0xa8, 0xca, 0x9c,
        0xf6, 0x56, 0x33, 0x19, 0x2e, 0x75, 0xb0, 0xbd, 0xd2, 0x56, 0x2f, 0xcb, 0x39, 0xfb, 0x0f, 0x08,
        0x53, 0x3f, 0xda, 0x94, 0xfd, 0x6f, 0x37, 0x95, 0x34, 0xf4, 0xa5, 0x20, 0x93, 0x50, 0x86, 0x39,
        0xb7, 0x78, 0x14, 0x1d, 0x4a, 0x65, 0x75, 0x38, 0x78
    };
    Crypto_DataBlob dataBlob = { .data = privData, .len = sizeof(privData) };
    ret = OH_CryptoAsymKeyGenerator_Convert(ctx, CRYPTO_DER, nullptr, &dataBlob, &keyPair);
    ASSERT_EQ(ret, CRYPTO_SUCCESS);
    OH_CryptoPubKey *pubKey = OH_CryptoKeyPair_GetPubKey(keyPair);
    ASSERT_NE(pubKey, nullptr);

    OH_CryptoAsymKeyGenerator_Destroy(ctx);
    OH_CryptoKeyPair_Destroy(keyPair);
}

HWTEST_F(NativeAsymKeyTest, NativeAsymKeyTest030, TestSize.Level0)
{
    OH_CryptoAsymKeyGenerator *ctx = nullptr;
    OH_CryptoKeyPair *keyPair = nullptr;
    OH_CryptoKeyPair *convertedKeyPair = nullptr;
    OH_Crypto_ErrCode ret;
    ret = OH_CryptoAsymKeyGenerator_Create("X25519", &ctx);
    EXPECT_EQ(ret, CRYPTO_SUCCESS);
    
    ret = OH_CryptoAsymKeyGenerator_Generate(ctx, &keyPair);
    ASSERT_EQ(ret, CRYPTO_SUCCESS);
    
    OH_CryptoPrivKey *privKey = OH_CryptoKeyPair_GetPrivKey(keyPair);
    ASSERT_NE(privKey, nullptr);
    
    Crypto_DataBlob derData = {.data = nullptr, .len = 0};
    ret = OH_CryptoPrivKey_Encode(privKey, CRYPTO_DER, nullptr, nullptr, &derData);
    ASSERT_EQ(ret, CRYPTO_SUCCESS);
    ASSERT_NE(derData.data, nullptr);
    ASSERT_NE(derData.len, 0);
    
    ret = OH_CryptoAsymKeyGenerator_Convert(ctx, CRYPTO_DER, nullptr, &derData, &convertedKeyPair);
    ASSERT_EQ(ret, CRYPTO_SUCCESS);
    OH_CryptoPubKey *pubKey = OH_CryptoKeyPair_GetPubKey(convertedKeyPair);
    ASSERT_NE(pubKey, nullptr);
    
    OH_Crypto_FreeDataBlob(&derData);
    OH_CryptoAsymKeyGenerator_Destroy(ctx);
    OH_CryptoKeyPair_Destroy(keyPair);
    OH_CryptoKeyPair_Destroy(convertedKeyPair);
}

HWTEST_F(NativeAsymKeyTest, NativeAsymKeyTest031, TestSize.Level0)
{
    OH_CryptoAsymKeyGenerator *ctx = nullptr;
    OH_CryptoKeyPair *keyPair = nullptr;
    OH_CryptoKeyPair *convertedKeyPair = nullptr;
    OH_Crypto_ErrCode ret;
    ret = OH_CryptoAsymKeyGenerator_Create("Ed25519", &ctx);
    EXPECT_EQ(ret, CRYPTO_SUCCESS);
    
    ret = OH_CryptoAsymKeyGenerator_Generate(ctx, &keyPair);
    ASSERT_EQ(ret, CRYPTO_SUCCESS);
    
    OH_CryptoPrivKey *privKey = OH_CryptoKeyPair_GetPrivKey(keyPair);
    ASSERT_NE(privKey, nullptr);
    
    Crypto_DataBlob derData = {.data = nullptr, .len = 0};
    ret = OH_CryptoPrivKey_Encode(privKey, CRYPTO_DER, nullptr, nullptr, &derData);
    ASSERT_EQ(ret, CRYPTO_SUCCESS);
    ASSERT_NE(derData.data, nullptr);
    ASSERT_NE(derData.len, 0);
    
    ret = OH_CryptoAsymKeyGenerator_Convert(ctx, CRYPTO_DER, nullptr, &derData, &convertedKeyPair);
    ASSERT_EQ(ret, CRYPTO_SUCCESS);
    OH_CryptoPubKey *pubKey = OH_CryptoKeyPair_GetPubKey(convertedKeyPair);
    ASSERT_NE(pubKey, nullptr);
    
    OH_Crypto_FreeDataBlob(&derData);
    OH_CryptoAsymKeyGenerator_Destroy(ctx);
    OH_CryptoKeyPair_Destroy(keyPair);
    OH_CryptoKeyPair_Destroy(convertedKeyPair);
}

HWTEST_F(NativeAsymKeyTest, NativeAsymKeyTest032, TestSize.Level0)
{
    OH_CryptoAsymKeyGenerator *ctx = nullptr;
    OH_CryptoKeyPair *keyPair = nullptr;
    OH_CryptoKeyPair *convertedKeyPair = nullptr;
    OH_Crypto_ErrCode ret;
    ret = OH_CryptoAsymKeyGenerator_Create("ECC_BrainPoolP384r1", &ctx);
    EXPECT_EQ(ret, CRYPTO_SUCCESS);
    
    ret = OH_CryptoAsymKeyGenerator_Generate(ctx, &keyPair);
    ASSERT_EQ(ret, CRYPTO_SUCCESS);
    
    OH_CryptoPrivKey *privKey = OH_CryptoKeyPair_GetPrivKey(keyPair);
    ASSERT_NE(privKey, nullptr);
    
    Crypto_DataBlob derData = {.data = nullptr, .len = 0};
    ret = OH_CryptoPrivKey_Encode(privKey, CRYPTO_DER, "PKCS8", nullptr, &derData);
    ASSERT_EQ(ret, CRYPTO_SUCCESS);
    ASSERT_NE(derData.data, nullptr);
    ASSERT_NE(derData.len, 0);
    
    ret = OH_CryptoAsymKeyGenerator_Convert(ctx, CRYPTO_DER, nullptr, &derData, &convertedKeyPair);
    ASSERT_EQ(ret, CRYPTO_SUCCESS);
    OH_CryptoPubKey *pubKey = OH_CryptoKeyPair_GetPubKey(convertedKeyPair);
    ASSERT_NE(pubKey, nullptr);
    
    OH_Crypto_FreeDataBlob(&derData);
    OH_CryptoAsymKeyGenerator_Destroy(ctx);
    OH_CryptoKeyPair_Destroy(keyPair);
    OH_CryptoKeyPair_Destroy(convertedKeyPair);
}

HWTEST_F(NativeAsymKeyTest, NativeAsymKeyTest033, TestSize.Level0)
{
    OH_CryptoAsymKeyGenerator *generator = nullptr;
    OH_Crypto_ErrCode res = OH_CryptoAsymKeyGenerator_Create("RSA512", &generator);
    EXPECT_EQ(res, CRYPTO_SUCCESS);
    EXPECT_NE(generator, nullptr);

    OH_CryptoKeyPair *dupKeyPair = nullptr;
    Crypto_DataBlob pubKeyX509Str = {};
    pubKeyX509Str.data = reinterpret_cast<uint8_t *>(const_cast<char *>(g_testPubkeyX509Str512.c_str()));
    pubKeyX509Str.len = strlen(g_testPubkeyX509Str512.c_str());

    Crypto_DataBlob pubKeyPkcs1Str = {};
    pubKeyPkcs1Str.data = reinterpret_cast<uint8_t *>(const_cast<char *>(g_testPubkeyPkcs1Str512.c_str()));
    pubKeyPkcs1Str.len = strlen(g_testPubkeyPkcs1Str512.c_str());
    res = OH_CryptoAsymKeyGenerator_Convert(generator, (Crypto_EncodingType)2, &pubKeyX509Str, nullptr, &dupKeyPair);
    EXPECT_EQ(res, CRYPTO_INVALID_PARAMS);
    EXPECT_EQ(dupKeyPair, nullptr);
    OH_CryptoAsymKeyGenerator_Destroy(generator);
}

static void OpensslMockTestFuncGetPubKey(uint32_t mallocCount)
{
    for (uint32_t i = 0; i < mallocCount; i++) {
        ResetOpensslCallNum();
        SetOpensslCallMockIndex(i);

        OH_CryptoAsymKeyGenerator *tmpGenerator = nullptr;
        OH_Crypto_ErrCode ret = OH_CryptoAsymKeyGenerator_Create("RSA512", &tmpGenerator);
        if (ret != CRYPTO_SUCCESS) {
            continue;
        }

        OH_CryptoKeyPair *tmpKeyPair = nullptr;
        ret = OH_CryptoAsymKeyGenerator_Generate(tmpGenerator, &tmpKeyPair);
        if (ret != CRYPTO_SUCCESS) {
            OH_CryptoAsymKeyGenerator_Destroy(tmpGenerator);
            continue;
        }

        OH_CryptoPubKey *tmpPubKey1 = OH_CryptoKeyPair_GetPubKey(tmpKeyPair);
        if (tmpPubKey1 == nullptr) {
            OH_CryptoKeyPair_Destroy(tmpKeyPair);
            OH_CryptoAsymKeyGenerator_Destroy(tmpGenerator);
            continue;
        }

        Crypto_DataBlob tmpPubKeyBlob1 = {.data = nullptr, .len = 0};
        ret = OH_CryptoPubKey_Encode(tmpPubKey1, CRYPTO_PEM, "X509", &tmpPubKeyBlob1);
        if (ret != CRYPTO_SUCCESS) {
            OH_CryptoKeyPair_Destroy(tmpKeyPair);
            OH_CryptoAsymKeyGenerator_Destroy(tmpGenerator);
            continue;
        }

        OH_Crypto_FreeDataBlob(&tmpPubKeyBlob1);
        OH_CryptoKeyPair_Destroy(tmpKeyPair);
        OH_CryptoAsymKeyGenerator_Destroy(tmpGenerator);
    }
}

HWTEST_F(NativeAsymKeyTest, NativeAsymKeyTest034, TestSize.Level0)
{
    StartRecordOpensslCallNum();
    OH_CryptoAsymKeyGenerator *generator = nullptr;
    OH_Crypto_ErrCode res = OH_CryptoAsymKeyGenerator_Create("RSA512", &generator);
    EXPECT_EQ(res, CRYPTO_SUCCESS);
    EXPECT_NE(generator, nullptr);

    OH_CryptoKeyPair *keyPair = nullptr;
    res = OH_CryptoAsymKeyGenerator_Generate(generator, &keyPair);
    EXPECT_EQ(res, CRYPTO_SUCCESS);
    EXPECT_NE(keyPair, nullptr);

    OH_CryptoPubKey *pubKey = OH_CryptoKeyPair_GetPubKey(keyPair);
    EXPECT_NE(pubKey, nullptr);

    Crypto_DataBlob pubKeyBlob = {.data = nullptr, .len = 0};
    res = OH_CryptoPubKey_Encode(pubKey, CRYPTO_PEM, "X509", &pubKeyBlob);
    EXPECT_EQ(res, CRYPTO_SUCCESS);
    EXPECT_NE(pubKeyBlob.data, nullptr);
    EXPECT_NE(pubKeyBlob.len, 0);

    OH_Crypto_FreeDataBlob(&pubKeyBlob);
    OH_CryptoKeyPair_Destroy(keyPair);
    OH_CryptoAsymKeyGenerator_Destroy(generator);

    uint32_t mallocCount = GetOpensslCallNum();
    OpensslMockTestFuncGetPubKey(mallocCount);

    EndRecordOpensslCallNum();
}
}
