/*
 * Copyright (C) 2022-2026 Huawei Device Co., Ltd.
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
#include "blob.h"
#include "ecc_common_asy_key_generator_openssl.h"
#include "memory.h"
#include "result.h"

using namespace std;
using namespace testing::ext;

namespace {
// JS side AsyKeyDataItem values.
static constexpr uint32_t EC_PRIVATE_K = 6;
static constexpr uint32_t EC_PRIVATE_04_X_Y_K = 7;
static constexpr uint32_t EC_PUBLIC_X_Y = 8;
static constexpr uint32_t EC_PUBLIC_04_X_Y = 9;
static constexpr uint32_t EC_PUBLIC_COMPRESS_X = 10;
/** 非 EC_PUBLIC_* / EC_PRIVATE_* 的 type，走 GetEccPubKeyDataInCommon 末尾“无匹配项”返回 HCF_SUCCESS。 */
static constexpr uint32_t EC_KEY_DATA_UNKNOWN_TYPE = 5;

static void FreeHcfBlob(HcfBlob *blob)
{
    if (blob == nullptr || blob->data == nullptr) {
        return;
    }
    HcfFree(blob->data);
    blob->data = nullptr;
    blob->len = 0;
}

static bool IsBlobEqual(const HcfBlob &first, const HcfBlob &second)
{
    if (first.data == nullptr || second.data == nullptr || first.len != second.len) {
        return false;
    }
    return (first.len == 0) ? true : (memcmp(first.data, second.data, first.len) == 0);
}

static bool ContainsText(const char *src, const char *target)
{
    if (src == nullptr || target == nullptr) {
        return false;
    }
    return strstr(src, target) != nullptr;
}

static int32_t GetPriKeyData(HcfPriKey *priKey, uint32_t type, HcfBlob *out)
{
    if (priKey == nullptr || out == nullptr) {
        return HCF_INVALID_PARAMS;
    }
    out->data = nullptr;
    out->len = 0;
    return priKey->getKeyData(priKey, type, out);
}

static int32_t GetPubKeyData(HcfPubKey *pubKey, uint32_t type, HcfBlob *out)
{
    if (pubKey == nullptr || out == nullptr) {
        return HCF_INVALID_PARAMS;
    }
    out->data = nullptr;
    out->len = 0;
    return pubKey->getKeyData(pubKey, type, out);
}
} // namespace

class CryptoEccGetKeyDataTest : public testing::Test {
public:
    static void SetUpTestCase() {};
    static void TearDownTestCase() {};
    void SetUp() {};
    void TearDown() {};
};

struct EccRawData {
    HcfBlob priK;
    HcfBlob priFull;
    HcfBlob pubXY;
    HcfBlob pub04XY;
    HcfBlob pubCompress;
};

static void InitRawData(EccRawData *raw)
{
    raw->priK = { .data = nullptr, .len = 0 };
    raw->priFull = { .data = nullptr, .len = 0 };
    raw->pubXY = { .data = nullptr, .len = 0 };
    raw->pub04XY = { .data = nullptr, .len = 0 };
    raw->pubCompress = { .data = nullptr, .len = 0 };
}

static void FreeRawData(EccRawData *raw)
{
    FreeHcfBlob(&raw->priK);
    FreeHcfBlob(&raw->priFull);
    FreeHcfBlob(&raw->pubXY);
    FreeHcfBlob(&raw->pub04XY);
    FreeHcfBlob(&raw->pubCompress);
}

static void GetRawDataFromKeyPair(HcfKeyPair *keyPair, EccRawData *raw)
{
    int32_t res = GetPriKeyData(keyPair->priKey, EC_PRIVATE_K, &raw->priK);
    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(raw->priK.data, nullptr);
    ASSERT_NE(raw->priK.len, 0);

    res = GetPriKeyData(keyPair->priKey, EC_PRIVATE_04_X_Y_K, &raw->priFull);
    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(raw->priFull.data, nullptr);
    ASSERT_NE(raw->priFull.len, 0);

    res = GetPubKeyData(keyPair->pubKey, EC_PUBLIC_X_Y, &raw->pubXY);
    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(raw->pubXY.data, nullptr);
    ASSERT_NE(raw->pubXY.len, 0);

    res = GetPubKeyData(keyPair->pubKey, EC_PUBLIC_04_X_Y, &raw->pub04XY);
    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(raw->pub04XY.data, nullptr);
    ASSERT_NE(raw->pub04XY.len, 0);

    res = GetPubKeyData(keyPair->pubKey, EC_PUBLIC_COMPRESS_X, &raw->pubCompress);
    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(raw->pubCompress.data, nullptr);
    ASSERT_NE(raw->pubCompress.len, 0);
}

static void CheckPriRoundTrip(HcfAsyKeyGenerator *generator, const HcfBlob *inputPri, const EccRawData *raw)
{
    HcfKeyPair *outKeyPair = nullptr;
    HcfBlob outPriK = { .data = nullptr, .len = 0 };
    HcfBlob outPriFull = { .data = nullptr, .len = 0 };
    int32_t res = generator->convertKey(generator, nullptr, nullptr, (HcfBlob *)inputPri, &outKeyPair);
    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(outKeyPair, nullptr);
    ASSERT_NE(outKeyPair->priKey, nullptr);

    res = GetPriKeyData(outKeyPair->priKey, EC_PRIVATE_K, &outPriK);
    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_TRUE(IsBlobEqual(raw->priK, outPriK));

    res = GetPriKeyData(outKeyPair->priKey, EC_PRIVATE_04_X_Y_K, &outPriFull);
    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_TRUE(IsBlobEqual(raw->priFull, outPriFull));

    FreeHcfBlob(&outPriK);
    FreeHcfBlob(&outPriFull);
    HcfObjDestroy(outKeyPair);
}

static void CheckPubRoundTrip(HcfAsyKeyGenerator *generator, const HcfBlob *inputPub, const EccRawData *raw)
{
    HcfKeyPair *outKeyPair = nullptr;
    HcfBlob outPubXY = { .data = nullptr, .len = 0 };
    HcfBlob outPub04 = { .data = nullptr, .len = 0 };
    HcfBlob outPubCompress = { .data = nullptr, .len = 0 };
    int32_t res = generator->convertKey(generator, nullptr, (HcfBlob *)inputPub, nullptr, &outKeyPair);
    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(outKeyPair, nullptr);
    ASSERT_NE(outKeyPair->pubKey, nullptr);

    res = GetPubKeyData(outKeyPair->pubKey, EC_PUBLIC_X_Y, &outPubXY);
    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_TRUE(IsBlobEqual(raw->pubXY, outPubXY));

    res = GetPubKeyData(outKeyPair->pubKey, EC_PUBLIC_04_X_Y, &outPub04);
    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_TRUE(IsBlobEqual(raw->pub04XY, outPub04));

    res = GetPubKeyData(outKeyPair->pubKey, EC_PUBLIC_COMPRESS_X, &outPubCompress);
    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_TRUE(IsBlobEqual(raw->pubCompress, outPubCompress));

    FreeHcfBlob(&outPubXY);
    FreeHcfBlob(&outPub04);
    FreeHcfBlob(&outPubCompress);
    HcfObjDestroy(outKeyPair);
}

static int32_t EccGetKeyDataRoundTripTest(const char *curveName)
{
    HcfAsyKeyGenerator *generator = nullptr;
    HcfAsyKeyGenerator *generator2 = nullptr;
    HcfKeyPair *keyPair = nullptr;
    EccRawData raw;
    bool rawInited = false;
    int32_t res = HcfAsyKeyGeneratorCreate(curveName, &generator);
    if (res != HCF_SUCCESS || generator == nullptr) {
        return HCF_ERR_CRYPTO_OPERATION;
    }

    res = generator->generateKeyPair(generator, nullptr, &keyPair);
    if (res != HCF_SUCCESS || keyPair == nullptr || keyPair->priKey == nullptr || keyPair->pubKey == nullptr) {
        res = HCF_ERR_CRYPTO_OPERATION;
        goto EXIT;
    }

    InitRawData(&raw);
    rawInited = true;
    GetRawDataFromKeyPair(keyPair, &raw);

    res = HcfAsyKeyGeneratorCreate(curveName, &generator2);
    if (res != HCF_SUCCESS || generator2 == nullptr) {
        res = HCF_ERR_CRYPTO_OPERATION;
        goto EXIT;
    }

    CheckPriRoundTrip(generator2, &raw.priK, &raw);
    CheckPriRoundTrip(generator2, &raw.priFull, &raw);
    CheckPubRoundTrip(generator2, &raw.pubXY, &raw);
    CheckPubRoundTrip(generator2, &raw.pub04XY, &raw);
    CheckPubRoundTrip(generator2, &raw.pubCompress, &raw);

    res = HCF_SUCCESS;
EXIT:
    HcfObjDestroy(generator2);
    if (rawInited) {
        FreeRawData(&raw);
    }
    HcfObjDestroy(keyPair);
    HcfObjDestroy(generator);
    return res;
}

HWTEST_F(CryptoEccGetKeyDataTest, CryptoEccGetKeyDataTest001, TestSize.Level0)
{
    EXPECT_EQ(EccGetKeyDataRoundTripTest("ECC256"), HCF_SUCCESS);
}

HWTEST_F(CryptoEccGetKeyDataTest, CryptoEccGetKeyDataTest002, TestSize.Level0)
{
    EXPECT_EQ(EccGetKeyDataRoundTripTest("ECC384"), HCF_SUCCESS);
}

HWTEST_F(CryptoEccGetKeyDataTest, CryptoEccGetKeyDataTest003, TestSize.Level0)
{
    EXPECT_EQ(EccGetKeyDataRoundTripTest("ECC521"), HCF_SUCCESS);
}

HWTEST_F(CryptoEccGetKeyDataTest, CryptoEccGetKeyDataTest004, TestSize.Level0)
{
    EXPECT_EQ(EccGetKeyDataRoundTripTest("ECC_BrainPoolP256r1"), HCF_SUCCESS);
}

static int32_t EccGetEncodedPemTest(const char *curveName)
{
    HcfAsyKeyGenerator *generator = nullptr;
    HcfKeyPair *keyPair = nullptr;
    char *pem = nullptr;
    int32_t res = HcfAsyKeyGeneratorCreate(curveName, &generator);
    if (res != HCF_SUCCESS || generator == nullptr) {
        return HCF_ERR_CRYPTO_OPERATION;
    }

    res = generator->generateKeyPair(generator, nullptr, &keyPair);
    if (res != HCF_SUCCESS || keyPair == nullptr || keyPair->priKey == nullptr || keyPair->pubKey == nullptr) {
        res = HCF_ERR_CRYPTO_OPERATION;
        goto EXIT;
    }

    res = keyPair->pubKey->base.getEncodedPem((HcfKey *)keyPair->pubKey, "X509", &pem);
    if (res != HCF_SUCCESS || pem == nullptr || !ContainsText(pem, "BEGIN PUBLIC KEY")) {
        res = HCF_ERR_CRYPTO_OPERATION;
        goto EXIT;
    }
    HCF_FREE_PTR(pem);

    res = keyPair->priKey->getEncodedPem(keyPair->priKey, nullptr, "PKCS8", &pem);
    if (res != HCF_SUCCESS || pem == nullptr || !ContainsText(pem, "BEGIN PRIVATE KEY")) {
        res = HCF_ERR_CRYPTO_OPERATION;
        goto EXIT;
    }
    HCF_FREE_PTR(pem);

    res = keyPair->priKey->getEncodedPem(keyPair->priKey, nullptr, "EC", &pem);
    if (res != HCF_SUCCESS || pem == nullptr || !ContainsText(pem, "BEGIN EC PRIVATE KEY")) {
        res = HCF_ERR_CRYPTO_OPERATION;
        goto EXIT;
    }
    HCF_FREE_PTR(pem);

    res = keyPair->pubKey->base.getEncodedPem((HcfKey *)keyPair->pubKey, "PKCS8", &pem);
    if (res == HCF_SUCCESS || pem != nullptr) {
        res = HCF_ERR_CRYPTO_OPERATION;
        goto EXIT;
    }

    res = keyPair->priKey->getEncodedPem(keyPair->priKey, nullptr, "X509", &pem);
    if (res == HCF_SUCCESS || pem != nullptr) {
        res = HCF_ERR_CRYPTO_OPERATION;
        goto EXIT;
    }

    res = HCF_SUCCESS;
EXIT:
    HCF_FREE_PTR(pem);
    HcfObjDestroy(keyPair);
    HcfObjDestroy(generator);
    return res;
}

HWTEST_F(CryptoEccGetKeyDataTest, CryptoEccGetEncodedPemTest001, TestSize.Level0)
{
    EXPECT_EQ(EccGetEncodedPemTest("ECC256"), HCF_SUCCESS);
}

HWTEST_F(CryptoEccGetKeyDataTest, CryptoEccGetEncodedPemTest002, TestSize.Level0)
{
    EXPECT_EQ(EccGetEncodedPemTest("ECC384"), HCF_SUCCESS);
}

HWTEST_F(CryptoEccGetKeyDataTest, CryptoEccGetEncodedPemTest003, TestSize.Level0)
{
    HcfAsyKeyGenerator *generator = nullptr;
    HcfKeyPair *keyPair = nullptr;
    char *pem = nullptr;
    int32_t res = HcfAsyKeyGeneratorCreate("ECC256", &generator);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(generator, nullptr);

    res = generator->generateKeyPair(generator, nullptr, &keyPair);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(keyPair, nullptr);
    EXPECT_NE(keyPair->priKey, nullptr);

    res = keyPair->priKey->getEncodedPem(keyPair->priKey, nullptr, nullptr, &pem);
    EXPECT_NE(res, HCF_SUCCESS);
    EXPECT_EQ(pem, nullptr);
    HCF_FREE_PTR(pem);

    res = keyPair->priKey->getEncodedPem(nullptr, nullptr, "PKCS8", &pem);
    EXPECT_NE(res, HCF_SUCCESS);
    EXPECT_EQ(pem, nullptr);
    HCF_FREE_PTR(pem);

    HcfKeyEncodingParamsSpec *encodingParamsSpec =
        reinterpret_cast<HcfKeyEncodingParamsSpec *>(HcfMalloc(sizeof(HcfKeyEncodingParamsSpec), 0));
    static char kEncodingPassword[] = "123456";
    static char kEncodingCipher[] = "AES-256-CBC";
    encodingParamsSpec->password = kEncodingPassword;
    encodingParamsSpec->cipher = kEncodingCipher;

    res = keyPair->priKey->getEncodedPem(keyPair->priKey,
        reinterpret_cast<HcfParamsSpec *>(encodingParamsSpec), "PKCS8", &pem);
    EXPECT_NE(res, HCF_SUCCESS);
    EXPECT_EQ(pem, nullptr);
    HCF_FREE_PTR(pem);
    HCF_FREE_PTR(encodingParamsSpec);

    HcfObjDestroy(keyPair);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoEccGetKeyDataTest, CryptoEccGetPubKeyDataInCommonNullSelf001, TestSize.Level0)
{
    HcfBlob out = { .data = nullptr, .len = 0 };
    EXPECT_EQ(GetEccPubKeyDataInCommon(nullptr, EC_PUBLIC_X_Y, &out), HCF_ERR_PARAMETER_CHECK_FAILED);
}

HWTEST_F(CryptoEccGetKeyDataTest, CryptoEccGetPubKeyDataInCommonNullBlob001, TestSize.Level0)
{
    HcfAsyKeyGenerator *generator = nullptr;
    HcfKeyPair *keyPair = nullptr;
    ASSERT_EQ(HcfAsyKeyGeneratorCreate("ECC256", &generator), HCF_SUCCESS);
    ASSERT_NE(generator, nullptr);
    ASSERT_EQ(generator->generateKeyPair(generator, nullptr, &keyPair), HCF_SUCCESS);
    ASSERT_NE(keyPair, nullptr);
    ASSERT_NE(keyPair->pubKey, nullptr);

    EXPECT_EQ(GetEccPubKeyDataInCommon(keyPair->pubKey, EC_PUBLIC_X_Y, nullptr), HCF_ERR_PARAMETER_CHECK_FAILED);

    HcfObjDestroy(keyPair);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoEccGetKeyDataTest, CryptoEccGetPubKeyDataInCommonWrongClass001, TestSize.Level0)
{
    HcfAsyKeyGenerator *generator = nullptr;
    HcfKeyPair *keyPair = nullptr;
    ASSERT_EQ(HcfAsyKeyGeneratorCreate("RSA1024", &generator), HCF_SUCCESS);
    ASSERT_NE(generator, nullptr);
    ASSERT_EQ(generator->generateKeyPair(generator, nullptr, &keyPair), HCF_SUCCESS);
    ASSERT_NE(keyPair, nullptr);
    ASSERT_NE(keyPair->pubKey, nullptr);

    HcfBlob out = { .data = nullptr, .len = 0 };
    EXPECT_EQ(GetEccPubKeyDataInCommon(keyPair->pubKey, EC_PUBLIC_X_Y, &out), HCF_ERR_PARAMETER_CHECK_FAILED);

    HcfObjDestroy(keyPair);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoEccGetKeyDataTest, CryptoEccGetPubKeyDataInCommonPriTypeOnPub001, TestSize.Level0)
{
    HcfAsyKeyGenerator *generator = nullptr;
    HcfKeyPair *keyPair = nullptr;
    ASSERT_EQ(HcfAsyKeyGeneratorCreate("ECC256", &generator), HCF_SUCCESS);
    ASSERT_NE(generator, nullptr);
    ASSERT_EQ(generator->generateKeyPair(generator, nullptr, &keyPair), HCF_SUCCESS);
    ASSERT_NE(keyPair, nullptr);
    ASSERT_NE(keyPair->pubKey, nullptr);

    HcfBlob out = { .data = nullptr, .len = 0 };
    EXPECT_EQ(GetEccPubKeyDataInCommon(keyPair->pubKey, EC_PRIVATE_K, &out), HCF_ERR_PARAMETER_CHECK_FAILED);
    EXPECT_EQ(GetEccPubKeyDataInCommon(keyPair->pubKey, EC_PRIVATE_04_X_Y_K, &out), HCF_ERR_PARAMETER_CHECK_FAILED);

    out = { .data = nullptr, .len = 0 };
    EXPECT_EQ(GetPubKeyData(keyPair->pubKey, EC_PRIVATE_K, &out), HCF_ERR_PARAMETER_CHECK_FAILED);
    FreeHcfBlob(&out);
    out = { .data = nullptr, .len = 0 };
    EXPECT_EQ(GetPubKeyData(keyPair->pubKey, EC_PRIVATE_04_X_Y_K, &out), HCF_ERR_PARAMETER_CHECK_FAILED);
    FreeHcfBlob(&out);

    HcfObjDestroy(keyPair);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoEccGetKeyDataTest, CryptoEccGetPubKeyDataInCommonUnknownType001, TestSize.Level0)
{
    HcfAsyKeyGenerator *generator = nullptr;
    HcfKeyPair *keyPair = nullptr;
    ASSERT_EQ(HcfAsyKeyGeneratorCreate("ECC256", &generator), HCF_SUCCESS);
    ASSERT_NE(generator, nullptr);
    ASSERT_EQ(generator->generateKeyPair(generator, nullptr, &keyPair), HCF_SUCCESS);
    ASSERT_NE(keyPair, nullptr);
    ASSERT_NE(keyPair->pubKey, nullptr);

    HcfBlob out = { .data = nullptr, .len = 0 };
    EXPECT_EQ(GetEccPubKeyDataInCommon(keyPair->pubKey, EC_KEY_DATA_UNKNOWN_TYPE, &out), HCF_SUCCESS);
    EXPECT_EQ(out.data, nullptr);
    EXPECT_EQ(out.len, 0U);

    out = { .data = nullptr, .len = 0 };
    EXPECT_EQ(GetPubKeyData(keyPair->pubKey, EC_KEY_DATA_UNKNOWN_TYPE, &out), HCF_SUCCESS);
    EXPECT_EQ(out.data, nullptr);
    EXPECT_EQ(out.len, 0U);

    HcfObjDestroy(keyPair);
    HcfObjDestroy(generator);
}

/**
 * 非 EC 非对称算法：getKeyData 应返回 HCF_ERR_INVALID_CALL（与 EC 原始数据项无关，任选一 type 即可）。
 */
static int32_t NonEcGetKeyDataInvalidCallTest(const char *algoName)
{
    HcfAsyKeyGenerator *generator = nullptr;
    HcfKeyPair *keyPair = nullptr;
    int32_t res = HcfAsyKeyGeneratorCreate(algoName, &generator);
    if (res != HCF_SUCCESS || generator == nullptr) {
        return HCF_ERR_CRYPTO_OPERATION;
    }

    res = generator->generateKeyPair(generator, nullptr, &keyPair);
    if (res != HCF_SUCCESS || keyPair == nullptr || keyPair->priKey == nullptr || keyPair->pubKey == nullptr) {
        HcfObjDestroy(generator);
        return HCF_ERR_CRYPTO_OPERATION;
    }

    HcfBlob out = { .data = nullptr, .len = 0 };
    res = GetPubKeyData(keyPair->pubKey, EC_PRIVATE_K, &out);
    if (res != HCF_ERR_INVALID_CALL) {
        FreeHcfBlob(&out);
        HcfObjDestroy(keyPair);
        HcfObjDestroy(generator);
        return HCF_ERR_CRYPTO_OPERATION;
    }
    FreeHcfBlob(&out);

    out = { .data = nullptr, .len = 0 };
    res = GetPriKeyData(keyPair->priKey, EC_PUBLIC_X_Y, &out);
    if (res != HCF_ERR_INVALID_CALL) {
        FreeHcfBlob(&out);
        HcfObjDestroy(keyPair);
        HcfObjDestroy(generator);
        return HCF_ERR_CRYPTO_OPERATION;
    }
    FreeHcfBlob(&out);

    HcfObjDestroy(keyPair);
    HcfObjDestroy(generator);
    return HCF_SUCCESS;
}

HWTEST_F(CryptoEccGetKeyDataTest, CryptoNonEcGetKeyDataInvalidCallRsa001, TestSize.Level0)
{
    EXPECT_EQ(NonEcGetKeyDataInvalidCallTest("RSA1024"), HCF_SUCCESS);
}

HWTEST_F(CryptoEccGetKeyDataTest, CryptoNonEcGetKeyDataInvalidCallDsa001, TestSize.Level0)
{
    EXPECT_EQ(NonEcGetKeyDataInvalidCallTest("DSA1024"), HCF_SUCCESS);
}

HWTEST_F(CryptoEccGetKeyDataTest, CryptoNonEcGetKeyDataInvalidCallDh001, TestSize.Level0)
{
    EXPECT_EQ(NonEcGetKeyDataInvalidCallTest("DH_modp1536"), HCF_SUCCESS);
}

HWTEST_F(CryptoEccGetKeyDataTest, CryptoNonEcGetKeyDataInvalidCallSm2_001, TestSize.Level0)
{
    EXPECT_EQ(NonEcGetKeyDataInvalidCallTest("SM2_256"), HCF_SUCCESS);
}

HWTEST_F(CryptoEccGetKeyDataTest, CryptoNonEcGetKeyDataInvalidCallEd25519001, TestSize.Level0)
{
    EXPECT_EQ(NonEcGetKeyDataInvalidCallTest("Ed25519"), HCF_SUCCESS);
}

HWTEST_F(CryptoEccGetKeyDataTest, CryptoNonEcGetKeyDataInvalidCallX25519001, TestSize.Level0)
{
    EXPECT_EQ(NonEcGetKeyDataInvalidCallTest("X25519"), HCF_SUCCESS);
}

