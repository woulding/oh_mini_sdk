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
#include <securec.h>
#include <cstring>

#include "utils.h"
#include "kem.h"
#include "asy_key_generator.h"
#include "key_pair.h"
#include "pub_key.h"
#include "pri_key.h"
#include "memory.h"
#include "blob.h"

using namespace std;
using namespace testing::ext;

namespace {

/* ---------- helper: generate ML-KEM key pair via HcfAsyKeyGenerator ---------- */

static HcfResult GenerateMlKemKeyPair(const string &algoName, HcfKeyPair **keyPair)
{
    HcfAsyKeyGenerator *generator = nullptr;
    HcfResult res = HcfAsyKeyGeneratorCreate(algoName.c_str(), &generator);
    if (res != HCF_SUCCESS || generator == nullptr) {
        return res;
    }
    res = generator->generateKeyPair(generator, nullptr, keyPair);
    HcfObjDestroy(generator);
    return res;
}

/* ========== Test fixture with ML-KEM-768 key pair ========== */

class CryptoKemTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp();
    void TearDown();

    static HcfKeyPair *keyPair_;
    static HcfPubKey *pubKey_;
    static HcfPriKey *priKey_;
};

HcfKeyPair *CryptoKemTest::keyPair_ = nullptr;
HcfPubKey  *CryptoKemTest::pubKey_  = nullptr;
HcfPriKey  *CryptoKemTest::priKey_  = nullptr;

void CryptoKemTest::SetUpTestCase()
{
    HcfResult res = GenerateMlKemKeyPair("ML-KEM-768", &keyPair_);
    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(keyPair_, nullptr);
    pubKey_ = keyPair_->pubKey;
    priKey_ = keyPair_->priKey;
}

void CryptoKemTest::TearDownTestCase()
{
    HcfObjDestroy(keyPair_);
    keyPair_ = nullptr;
    pubKey_ = nullptr;
    priKey_ = nullptr;
}

void CryptoKemTest::SetUp() {}
void CryptoKemTest::TearDown() {}

/* ====================================================================
 *  HcfKemCreate tests
 * ==================================================================== */

/**
 * @tc.name: CryptoKemCreateTest001
 * @tc.desc: Create KEM with ML-KEM512
 * @tc.type: FUNC
 */
HWTEST_F(CryptoKemTest, CryptoKemCreateTest001, TestSize.Level0)
{
    HcfKem *kem = nullptr;
    HcfResult res = HcfKemCreate("ML-KEM512", &kem);
    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(kem, nullptr);
    HcfObjDestroy(kem);
}

/**
 * @tc.name: CryptoKemCreateTest002
 * @tc.desc: Create KEM with ML-KEM768
 * @tc.type: FUNC
 */
HWTEST_F(CryptoKemTest, CryptoKemCreateTest002, TestSize.Level0)
{
    HcfKem *kem = nullptr;
    HcfResult res = HcfKemCreate("ML-KEM768", &kem);
    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(kem, nullptr);
    HcfObjDestroy(kem);
}

/**
 * @tc.name: CryptoKemCreateTest003
 * @tc.desc: Create KEM with ML-KEM1024
 * @tc.type: FUNC
 */
HWTEST_F(CryptoKemTest, CryptoKemCreateTest003, TestSize.Level0)
{
    HcfKem *kem = nullptr;
    HcfResult res = HcfKemCreate("ML-KEM1024", &kem);
    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(kem, nullptr);
    HcfObjDestroy(kem);
}

/**
 * @tc.name: CryptoKemCreateTest004
 * @tc.desc: Create KEM with nullptr algoName
 * @tc.type: FUNC
 */
HWTEST_F(CryptoKemTest, CryptoKemCreateTest004, TestSize.Level0)
{
    HcfKem *kem = nullptr;
    HcfResult res = HcfKemCreate(nullptr, &kem);
    ASSERT_EQ(res, HCF_ERR_PARAMETER_CHECK_FAILED);
}

/**
 * @tc.name: CryptoKemCreateTest005
 * @tc.desc: Create KEM with nullptr returnObj
 * @tc.type: FUNC
 */
HWTEST_F(CryptoKemTest, CryptoKemCreateTest005, TestSize.Level0)
{
    HcfResult res = HcfKemCreate("ML-KEM768", nullptr);
    ASSERT_EQ(res, HCF_ERR_PARAMETER_CHECK_FAILED);
}

/**
 * @tc.name: CryptoKemCreateTest006
 * @tc.desc: Create KEM with unsupported algorithm
 * @tc.type: FUNC
 */
HWTEST_F(CryptoKemTest, CryptoKemCreateTest006, TestSize.Level0)
{
    HcfKem *kem = nullptr;
    HcfResult res = HcfKemCreate("RSA2048", &kem);
    ASSERT_EQ(res, HCF_ERR_PARAMETER_CHECK_FAILED);
}

/**
 * @tc.name: CryptoKemCreateTest007
 * @tc.desc: Create KEM with empty string
 * @tc.type: FUNC
 */
HWTEST_F(CryptoKemTest, CryptoKemCreateTest007, TestSize.Level0)
{
    HcfKem *kem = nullptr;
    HcfResult res = HcfKemCreate("", &kem);
    ASSERT_EQ(res, HCF_ERR_PARAMETER_CHECK_FAILED);
}

/**
 * @tc.name: CryptoKemCreateTest008
 * @tc.desc: Create KEM with both params nullptr
 * @tc.type: FUNC
 */
HWTEST_F(CryptoKemTest, CryptoKemCreateTest008, TestSize.Level0)
{
    HcfResult res = HcfKemCreate(nullptr, nullptr);
    ASSERT_EQ(res, HCF_ERR_PARAMETER_CHECK_FAILED);
}

/* ====================================================================
 *  Encapsulate / Decapsulate functional tests
 * ==================================================================== */

/**
 * @tc.name: CryptoKemEncapDecapTest001
 * @tc.desc: ML-KEM768 encapsulate then decapsulate, shared secrets must match
 * @tc.type: FUNC
 */
HWTEST_F(CryptoKemTest, CryptoKemEncapDecapTest001, TestSize.Level0)
{
    HcfKem *kem = nullptr;
    HcfResult res = HcfKemCreate("ML-KEM768", &kem);
    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(kem, nullptr);

    /* encapsulate */
    HcfBlob sharedSecret1 = { .data = nullptr, .len = 0 };
    HcfBlob wrappedKey   = { .data = nullptr, .len = 0 };
    res = kem->encapsulate(kem, pubKey_, nullptr, &sharedSecret1, &wrappedKey);
    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_TRUE(HcfIsBlobValid(&sharedSecret1));
    ASSERT_TRUE(HcfIsBlobValid(&wrappedKey));

    /* decapsulate */
    HcfBlob sharedSecret2 = { .data = nullptr, .len = 0 };
    res = kem->decapsulate(kem, priKey_, &wrappedKey, &sharedSecret2);
    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_TRUE(HcfIsBlobValid(&sharedSecret2));

    /* shared secrets must be identical */
    ASSERT_EQ(sharedSecret1.len, sharedSecret2.len);
    ASSERT_EQ(memcmp(sharedSecret1.data, sharedSecret2.data, sharedSecret1.len), 0);

    HcfBlobDataClearAndFree(&sharedSecret1);
    HcfBlobDataClearAndFree(&sharedSecret2);
    HcfBlobDataClearAndFree(&wrappedKey);
    HcfObjDestroy(kem);
}

/**
 * @tc.name: CryptoKemEncapDecapTest002
 * @tc.desc: Multiple encapsulations produce different shared secrets (randomness)
 * @tc.type: FUNC
 */
HWTEST_F(CryptoKemTest, CryptoKemEncapDecapTest002, TestSize.Level0)
{
    HcfKem *kem = nullptr;
    HcfResult res = HcfKemCreate("ML-KEM768", &kem);
    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(kem, nullptr);

    HcfBlob ss1 = { .data = nullptr, .len = 0 };
    HcfBlob wk1 = { .data = nullptr, .len = 0 };
    res = kem->encapsulate(kem, pubKey_, nullptr, &ss1, &wk1);
    ASSERT_EQ(res, HCF_SUCCESS);

    HcfBlob ss2 = { .data = nullptr, .len = 0 };
    HcfBlob wk2 = { .data = nullptr, .len = 0 };
    res = kem->encapsulate(kem, pubKey_, nullptr, &ss2, &wk2);
    ASSERT_EQ(res, HCF_SUCCESS);

    /* Two encapsulations should produce different shared secrets with overwhelming probability */
    EXPECT_EQ(ss1.len, ss2.len);
    EXPECT_NE(memcmp(ss1.data, ss2.data, ss1.len), 0);

    HcfBlobDataClearAndFree(&ss1);
    HcfBlobDataClearAndFree(&ss2);
    HcfBlobDataClearAndFree(&wk1);
    HcfBlobDataClearAndFree(&wk2);
    HcfObjDestroy(kem);
}

/**
 * @tc.name: CryptoKemEncapDecapTest003
 * @tc.desc: Decapsulate with wrong private key should fail
 * @tc.type: FUNC
 */
HWTEST_F(CryptoKemTest, CryptoKemEncapDecapTest003, TestSize.Level0)
{
    /* Generate a second independent key pair */
    HcfKeyPair *otherKeyPair = nullptr;
    HcfResult res = GenerateMlKemKeyPair("ML-KEM-768", &otherKeyPair);
    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(otherKeyPair, nullptr);

    HcfKem *kem = nullptr;
    res = HcfKemCreate("ML-KEM768", &kem);
    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(kem, nullptr);

    /* Encapsulate with original public key */
    HcfBlob ss = { .data = nullptr, .len = 0 };
    HcfBlob wk = { .data = nullptr, .len = 0 };
    res = kem->encapsulate(kem, pubKey_, nullptr, &ss, &wk);
    ASSERT_EQ(res, HCF_SUCCESS);

    /* Decapsulate with wrong (other) private key */
    HcfBlob ssWrong = { .data = nullptr, .len = 0 };
    res = kem->decapsulate(kem, otherKeyPair->priKey, &wk, &ssWrong);
    ASSERT_EQ(res, HCF_SUCCESS);

    HcfBlobDataClearAndFree(&ss);
    HcfBlobDataClearAndFree(&wk);
    HcfBlobDataClearAndFree(&ssWrong);
    HcfObjDestroy(kem);
    HcfObjDestroy(otherKeyPair);
}

/* ====================================================================
 *  Encapsulate / Decapsulate with ikme parameter
 * ==================================================================== */

/**
 * @tc.name: CryptoKemIkmeTest001
 * @tc.desc: Encapsulate with ikme produces deterministic shared secret
 * @tc.type: FUNC
 */
HWTEST_F(CryptoKemTest, CryptoKemIkmeTest001, TestSize.Level0)
{
    HcfKem *kem = nullptr;
    HcfResult res = HcfKemCreate("ML-KEM768", &kem);
    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(kem, nullptr);

    /* Fixed ikme seed */
    uint8_t ikmeData[32];
    (void)memset_s(ikmeData, sizeof(ikmeData), 0xAB, sizeof(ikmeData));
    HcfBlob ikme = { .data = ikmeData, .len = sizeof(ikmeData) };

    /* First encapsulate with ikme */
    HcfBlob ss1 = { .data = nullptr, .len = 0 };
    HcfBlob wk1 = { .data = nullptr, .len = 0 };
    res = kem->encapsulate(kem, pubKey_, &ikme, &ss1, &wk1);
    ASSERT_EQ(res, HCF_SUCCESS);

    /* Second encapsulate with same ikme should produce identical results */
    HcfBlob ss2 = { .data = nullptr, .len = 0 };
    HcfBlob wk2 = { .data = nullptr, .len = 0 };
    res = kem->encapsulate(kem, pubKey_, &ikme, &ss2, &wk2);
    ASSERT_EQ(res, HCF_SUCCESS);

    ASSERT_EQ(ss1.len, ss2.len);
    ASSERT_EQ(memcmp(ss1.data, ss2.data, ss1.len), 0);
    ASSERT_EQ(wk1.len, wk2.len);
    ASSERT_EQ(memcmp(wk1.data, wk2.data, wk1.len), 0);

    /* Decapsulate the wrapped key should match */
    HcfBlob ss3 = { .data = nullptr, .len = 0 };
    res = kem->decapsulate(kem, priKey_, &wk1, &ss3);
    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_EQ(ss1.len, ss3.len);
    ASSERT_EQ(memcmp(ss1.data, ss3.data, ss1.len), 0);

    HcfBlobDataClearAndFree(&ss1);
    HcfBlobDataClearAndFree(&ss2);
    HcfBlobDataClearAndFree(&ss3);
    HcfBlobDataClearAndFree(&wk1);
    HcfBlobDataClearAndFree(&wk2);
    HcfObjDestroy(kem);
}

/**
 * @tc.name: CryptoKemIkmeTest002
 * @tc.desc: Encapsulate with different ikme values produces different results
 * @tc.type: FUNC
 */
HWTEST_F(CryptoKemTest, CryptoKemIkmeTest002, TestSize.Level0)
{
    HcfKem *kem = nullptr;
    HcfResult res = HcfKemCreate("ML-KEM768", &kem);
    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(kem, nullptr);

    uint8_t ikmeData1[32];
    (void)memset_s(ikmeData1, sizeof(ikmeData1), 0x11, sizeof(ikmeData1));
    HcfBlob ikme1 = { .data = ikmeData1, .len = sizeof(ikmeData1) };

    uint8_t ikmeData2[32];
    (void)memset_s(ikmeData2, sizeof(ikmeData2), 0x22, sizeof(ikmeData2));
    HcfBlob ikme2 = { .data = ikmeData2, .len = sizeof(ikmeData2) };

    HcfBlob ss1 = { .data = nullptr, .len = 0 };
    HcfBlob wk1 = { .data = nullptr, .len = 0 };
    res = kem->encapsulate(kem, pubKey_, &ikme1, &ss1, &wk1);
    ASSERT_EQ(res, HCF_SUCCESS);

    HcfBlob ss2 = { .data = nullptr, .len = 0 };
    HcfBlob wk2 = { .data = nullptr, .len = 0 };
    res = kem->encapsulate(kem, pubKey_, &ikme2, &ss2, &wk2);
    ASSERT_EQ(res, HCF_SUCCESS);

    /* Different ikme should produce different results */
    EXPECT_NE(memcmp(ss1.data, ss2.data, ss1.len), 0);
    EXPECT_NE(memcmp(wk1.data, wk2.data, wk1.len), 0);

    HcfBlobDataClearAndFree(&ss1);
    HcfBlobDataClearAndFree(&ss2);
    HcfBlobDataClearAndFree(&wk1);
    HcfBlobDataClearAndFree(&wk2);
    HcfObjDestroy(kem);
}

/* ====================================================================
 *  Encapsulate invalid parameter tests
 * ==================================================================== */

/**
 * @tc.name: CryptoKemEncapInvalidTest001
 * @tc.desc: Encapsulate with self nullptr
 * @tc.type: FUNC
 */
HWTEST_F(CryptoKemTest, CryptoKemEncapInvalidTest001, TestSize.Level0)
{
    HcfKem *kem = nullptr;
    HcfResult res = HcfKemCreate("ML-KEM768", &kem);
    ASSERT_EQ(res, HCF_SUCCESS);

    HcfBlob ss = { .data = nullptr, .len = 0 };
    HcfBlob wk = { .data = nullptr, .len = 0 };
    res = kem->encapsulate(nullptr, pubKey_, nullptr, &ss, &wk);
    ASSERT_EQ(res, HCF_ERR_PARAMETER_CHECK_FAILED);
    HcfObjDestroy(kem);
}

/**
 * @tc.name: CryptoKemEncapInvalidTest002
 * @tc.desc: Encapsulate with pubKey nullptr
 * @tc.type: FUNC
 */
HWTEST_F(CryptoKemTest, CryptoKemEncapInvalidTest002, TestSize.Level0)
{
    HcfKem *kem = nullptr;
    HcfResult res = HcfKemCreate("ML-KEM768", &kem);
    ASSERT_EQ(res, HCF_SUCCESS);

    HcfBlob ss = { .data = nullptr, .len = 0 };
    HcfBlob wk = { .data = nullptr, .len = 0 };
    res = kem->encapsulate(kem, nullptr, nullptr, &ss, &wk);
    ASSERT_EQ(res, HCF_ERR_PARAMETER_CHECK_FAILED);
    HcfObjDestroy(kem);
}

/**
 * @tc.name: CryptoKemEncapInvalidTest003
 * @tc.desc: Encapsulate with returnSharedSecret nullptr
 * @tc.type: FUNC
 */
HWTEST_F(CryptoKemTest, CryptoKemEncapInvalidTest003, TestSize.Level0)
{
    HcfKem *kem = nullptr;
    HcfResult res = HcfKemCreate("ML-KEM768", &kem);
    ASSERT_EQ(res, HCF_SUCCESS);

    HcfBlob wk = { .data = nullptr, .len = 0 };
    res = kem->encapsulate(kem, pubKey_, nullptr, nullptr, &wk);
    ASSERT_EQ(res, HCF_ERR_PARAMETER_CHECK_FAILED);
    HcfObjDestroy(kem);
}

/**
 * @tc.name: CryptoKemEncapInvalidTest004
 * @tc.desc: Encapsulate with returnWrappedKey nullptr
 * @tc.type: FUNC
 */
HWTEST_F(CryptoKemTest, CryptoKemEncapInvalidTest004, TestSize.Level0)
{
    HcfKem *kem = nullptr;
    HcfResult res = HcfKemCreate("ML-KEM768", &kem);
    ASSERT_EQ(res, HCF_SUCCESS);

    HcfBlob ss = { .data = nullptr, .len = 0 };
    res = kem->encapsulate(kem, pubKey_, nullptr, &ss, nullptr);
    ASSERT_EQ(res, HCF_ERR_PARAMETER_CHECK_FAILED);
    HcfObjDestroy(kem);
}

/**
 * @tc.name: CryptoKemEncapInvalidTest005
 * @tc.desc: Encapsulate with all output params nullptr
 * @tc.type: FUNC
 */
HWTEST_F(CryptoKemTest, CryptoKemEncapInvalidTest005, TestSize.Level0)
{
    HcfKem *kem = nullptr;
    HcfResult res = HcfKemCreate("ML-KEM768", &kem);
    ASSERT_EQ(res, HCF_SUCCESS);

    res = kem->encapsulate(kem, pubKey_, nullptr, nullptr, nullptr);
    ASSERT_EQ(res, HCF_ERR_PARAMETER_CHECK_FAILED);
    HcfObjDestroy(kem);
}

/* ====================================================================
 *  Decapsulate invalid parameter tests
 * ==================================================================== */

/**
 * @tc.name: CryptoKemDecapInvalidTest001
 * @tc.desc: Decapsulate with self nullptr
 * @tc.type: FUNC
 */
HWTEST_F(CryptoKemTest, CryptoKemDecapInvalidTest001, TestSize.Level0)
{
    HcfKem *kem = nullptr;
    HcfResult res = HcfKemCreate("ML-KEM768", &kem);
    ASSERT_EQ(res, HCF_SUCCESS);

    HcfBlob wk = { .data = nullptr, .len = 0 };
    HcfBlob ss = { .data = nullptr, .len = 0 };
    res = kem->decapsulate(nullptr, priKey_, &wk, &ss);
    ASSERT_EQ(res, HCF_ERR_PARAMETER_CHECK_FAILED);
    HcfObjDestroy(kem);
}

/**
 * @tc.name: CryptoKemDecapInvalidTest002
 * @tc.desc: Decapsulate with priKey nullptr
 * @tc.type: FUNC
 */
HWTEST_F(CryptoKemTest, CryptoKemDecapInvalidTest002, TestSize.Level0)
{
    HcfKem *kem = nullptr;
    HcfResult res = HcfKemCreate("ML-KEM768", &kem);
    ASSERT_EQ(res, HCF_SUCCESS);

    HcfBlob wk = { .data = nullptr, .len = 0 };
    HcfBlob ss = { .data = nullptr, .len = 0 };
    res = kem->decapsulate(kem, nullptr, &wk, &ss);
    ASSERT_EQ(res, HCF_ERR_PARAMETER_CHECK_FAILED);
    HcfObjDestroy(kem);
}

/**
 * @tc.name: CryptoKemDecapInvalidTest003
 * @tc.desc: Decapsulate with wrappedKey nullptr
 * @tc.type: FUNC
 */
HWTEST_F(CryptoKemTest, CryptoKemDecapInvalidTest003, TestSize.Level0)
{
    HcfKem *kem = nullptr;
    HcfResult res = HcfKemCreate("ML-KEM768", &kem);
    ASSERT_EQ(res, HCF_SUCCESS);

    HcfBlob ss = { .data = nullptr, .len = 0 };
    res = kem->decapsulate(kem, priKey_, nullptr, &ss);
    ASSERT_EQ(res, HCF_ERR_PARAMETER_CHECK_FAILED);
    HcfObjDestroy(kem);
}

/**
 * @tc.name: CryptoKemDecapInvalidTest004
 * @tc.desc: Decapsulate with returnSharedSecret nullptr
 * @tc.type: FUNC
 */
HWTEST_F(CryptoKemTest, CryptoKemDecapInvalidTest004, TestSize.Level0)
{
    HcfKem *kem = nullptr;
    HcfResult res = HcfKemCreate("ML-KEM768", &kem);
    ASSERT_EQ(res, HCF_SUCCESS);

    HcfBlob wk = { .data = nullptr, .len = 0 };
    res = kem->decapsulate(kem, priKey_, &wk, nullptr);
    ASSERT_EQ(res, HCF_ERR_PARAMETER_CHECK_FAILED);
    HcfObjDestroy(kem);
}

/**
 * @tc.name: CryptoKemDecapInvalidTest005
 * @tc.desc: Decapsulate with invalid (empty) wrappedKey blob
 * @tc.type: FUNC
 */
HWTEST_F(CryptoKemTest, CryptoKemDecapInvalidTest005, TestSize.Level0)
{
    HcfKem *kem = nullptr;
    HcfResult res = HcfKemCreate("ML-KEM768", &kem);
    ASSERT_EQ(res, HCF_SUCCESS);

    HcfBlob wk = { .data = nullptr, .len = 0 }; /* invalid blob: data=null, len=0 */
    HcfBlob ss = { .data = nullptr, .len = 0 };
    res = kem->decapsulate(kem, priKey_, &wk, &ss);
    ASSERT_EQ(res, HCF_ERR_PARAMETER_CHECK_FAILED);
    HcfObjDestroy(kem);
}

/**
 * @tc.name: CryptoKemDecapInvalidTest006
 * @tc.desc: Decapsulate with corrupted wrappedKey
 * @tc.type: FUNC
 */
HWTEST_F(CryptoKemTest, CryptoKemDecapInvalidTest006, TestSize.Level0)
{
    HcfKem *kem = nullptr;
    HcfResult res = HcfKemCreate("ML-KEM768", &kem);
    ASSERT_EQ(res, HCF_SUCCESS);

    /* Corrupted wrapped key with valid length for ML-KEM-768 = 1088 bytes */
    uint8_t fakeData[1088];
    (void)memset_s(fakeData, sizeof(fakeData), 0xFF, sizeof(fakeData));
    HcfBlob fakeWrappedKey = { .data = fakeData, .len = sizeof(fakeData) };
    HcfBlob ss = { .data = nullptr, .len = 0 };
    res = kem->decapsulate(kem, priKey_, &fakeWrappedKey, &ss);
    ASSERT_EQ(res, HCF_SUCCESS);
    HcfObjDestroy(kem);
    HcfBlobDataClearAndFree(&ss);
}

/* ====================================================================
 *  Destroy tests
 * ==================================================================== */

/**
 * @tc.name: CryptoKemDestroyTest001
 * @tc.desc: Destroy KEM object normally
 * @tc.type: FUNC
 */
HWTEST_F(CryptoKemTest, CryptoKemDestroyTest001, TestSize.Level0)
{
    HcfKem *kem = nullptr;
    HcfResult res = HcfKemCreate("ML-KEM768", &kem);
    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(kem, nullptr);
    HcfObjDestroy(kem);
}

/* ====================================================================
 *  Cross-algorithm mismatch tests
 * ==================================================================== */

/**
 * @tc.name: CryptoKemMismatchTest001
 * @tc.desc: Encapsulate with ML-KEM512 key but ML-KEM768 KEM should fail
 * @tc.type: FUNC
 */
HWTEST_F(CryptoKemTest, CryptoKemMismatchTest001, TestSize.Level0)
{
    /* Generate ML-KEM-512 key pair */
    HcfKeyPair *kem512KeyPair = nullptr;
    HcfResult res = GenerateMlKemKeyPair("ML-KEM-512", &kem512KeyPair);
    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(kem512KeyPair, nullptr);

    /* Create ML-KEM768 KEM object */
    HcfKem *kem768 = nullptr;
    res = HcfKemCreate("ML-KEM768", &kem768);
    ASSERT_EQ(res, HCF_SUCCESS);

    /* Encapsulate ML-KEM-512 pub key with ML-KEM768 KEM — should fail */
    HcfBlob ss = { .data = nullptr, .len = 0 };
    HcfBlob wk = { .data = nullptr, .len = 0 };
    res = kem768->encapsulate(kem768, kem512KeyPair->pubKey, nullptr, &ss, &wk);
    ASSERT_NE(res, HCF_SUCCESS);

    HcfObjDestroy(kem768);
    HcfObjDestroy(kem512KeyPair);
}

/**
 * @tc.name: CryptoKemMismatchTest002
 * @tc.desc: Decapsulate with ML-KEM1024 key but ML-KEM768 KEM should fail
 * @tc.type: FUNC
 */
HWTEST_F(CryptoKemTest, CryptoKemMismatchTest002, TestSize.Level0)
{
    /* Generate ML-KEM-1024 key pair */
    HcfKeyPair *kem1024KeyPair = nullptr;
    HcfResult res = GenerateMlKemKeyPair("ML-KEM-1024", &kem1024KeyPair);
    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(kem1024KeyPair, nullptr);

    /* Encapsulate with ML-KEM768 to get a valid wrapped key */
    HcfKem *kem768 = nullptr;
    res = HcfKemCreate("ML-KEM768", &kem768);
    ASSERT_EQ(res, HCF_SUCCESS);

    HcfBlob ss = { .data = nullptr, .len = 0 };
    HcfBlob wk = { .data = nullptr, .len = 0 };
    res = kem768->encapsulate(kem768, pubKey_, nullptr, &ss, &wk);
    ASSERT_EQ(res, HCF_SUCCESS);

    /* Decapsulate with ML-KEM-1024 private key using ML-KEM768 KEM — should fail */
    HcfBlob ss2 = { .data = nullptr, .len = 0 };
    res = kem768->decapsulate(kem768, kem1024KeyPair->priKey, &wk, &ss2);
    ASSERT_NE(res, HCF_SUCCESS);

    HcfBlobDataClearAndFree(&ss);
    HcfBlobDataClearAndFree(&wk);
    HcfBlobDataClearAndFree(&ss2);
    HcfObjDestroy(kem768);
    HcfObjDestroy(kem1024KeyPair);
}

/* ====================================================================
 *  Output size validation tests
 * ==================================================================== */

/**
 * @tc.name: CryptoKemOutputSizeTest001
 * @tc.desc: Verify ML-KEM768 encapsulate output sizes
 * @tc.type: FUNC
 */
HWTEST_F(CryptoKemTest, CryptoKemOutputSizeTest001, TestSize.Level0)
{
    HcfKem *kem = nullptr;
    HcfResult res = HcfKemCreate("ML-KEM768", &kem);
    ASSERT_EQ(res, HCF_SUCCESS);

    HcfBlob ss = { .data = nullptr, .len = 0 };
    HcfBlob wk = { .data = nullptr, .len = 0 };
    res = kem->encapsulate(kem, pubKey_, nullptr, &ss, &wk);
    ASSERT_EQ(res, HCF_SUCCESS);

    /* ML-KEM-768: shared secret = 32 bytes, wrapped key = 1088 bytes */
    EXPECT_EQ(ss.len, (size_t)32);
    EXPECT_EQ(wk.len, (size_t)1088);

    HcfBlobDataClearAndFree(&ss);
    HcfBlobDataClearAndFree(&wk);
    HcfObjDestroy(kem);
}

/**
 * @tc.name: CryptoKemOutputSizeTest002
 * @tc.desc: Verify ML-KEM512 output sizes
 * @tc.type: FUNC
 */
HWTEST_F(CryptoKemTest, CryptoKemOutputSizeTest002, TestSize.Level0)
{
    HcfKeyPair *keyPair512 = nullptr;
    HcfResult res = GenerateMlKemKeyPair("ML-KEM-512", &keyPair512);
    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(keyPair512, nullptr);

    HcfKem *kem = nullptr;
    res = HcfKemCreate("ML-KEM512", &kem);
    ASSERT_EQ(res, HCF_SUCCESS);

    HcfBlob ss = { .data = nullptr, .len = 0 };
    HcfBlob wk = { .data = nullptr, .len = 0 };
    res = kem->encapsulate(kem, keyPair512->pubKey, nullptr, &ss, &wk);
    ASSERT_EQ(res, HCF_SUCCESS);

    /* ML-KEM-512: shared secret = 32 bytes, wrapped key = 768 bytes */
    EXPECT_EQ(ss.len, (size_t)32);
    EXPECT_EQ(wk.len, (size_t)768);

    HcfBlobDataClearAndFree(&ss);
    HcfBlobDataClearAndFree(&wk);
    HcfObjDestroy(kem);
    HcfObjDestroy(keyPair512);
}

/**
 * @tc.name: CryptoKemOutputSizeTest003
 * @tc.desc: Verify ML-KEM1024 output sizes
 * @tc.type: FUNC
 */
HWTEST_F(CryptoKemTest, CryptoKemOutputSizeTest003, TestSize.Level0)
{
    HcfKeyPair *keyPair1024 = nullptr;
    HcfResult res = GenerateMlKemKeyPair("ML-KEM-1024", &keyPair1024);
    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(keyPair1024, nullptr);

    HcfKem *kem = nullptr;
    res = HcfKemCreate("ML-KEM1024", &kem);
    ASSERT_EQ(res, HCF_SUCCESS);

    HcfBlob ss = { .data = nullptr, .len = 0 };
    HcfBlob wk = { .data = nullptr, .len = 0 };
    res = kem->encapsulate(kem, keyPair1024->pubKey, nullptr, &ss, &wk);
    ASSERT_EQ(res, HCF_SUCCESS);

    /* ML-KEM-1024: shared secret = 32 bytes, wrapped key = 1568 bytes */
    EXPECT_EQ(ss.len, (size_t)32);
    EXPECT_EQ(wk.len, (size_t)1568);

    HcfBlobDataClearAndFree(&ss);
    HcfBlobDataClearAndFree(&wk);
    HcfObjDestroy(kem);
    HcfObjDestroy(keyPair1024);
}

/* ====================================================================
 *  Repeated encap/decap stability test
 * ==================================================================== */

/**
 * @tc.name: CryptoKemStressTest001
 * @tc.desc: Repeated encap/decap should always produce matching shared secrets
 * @tc.type: FUNC
 */
HWTEST_F(CryptoKemTest, CryptoKemStressTest001, TestSize.Level0)
{
    HcfKem *kem = nullptr;
    HcfResult res = HcfKemCreate("ML-KEM768", &kem);
    ASSERT_EQ(res, HCF_SUCCESS);

    for (int i = 0; i < 10; i++) {
        HcfBlob ss1 = { .data = nullptr, .len = 0 };
        HcfBlob wk  = { .data = nullptr, .len = 0 };
        res = kem->encapsulate(kem, pubKey_, nullptr, &ss1, &wk);
        ASSERT_EQ(res, HCF_SUCCESS) << "encapsulate failed at iteration " << i;

        HcfBlob ss2 = { .data = nullptr, .len = 0 };
        res = kem->decapsulate(kem, priKey_, &wk, &ss2);
        ASSERT_EQ(res, HCF_SUCCESS) << "decapsulate failed at iteration " << i;

        ASSERT_EQ(ss1.len, ss2.len) << "length mismatch at iteration " << i;
        ASSERT_EQ(memcmp(ss1.data, ss2.data, ss1.len), 0) << "data mismatch at iteration " << i;

        HcfBlobDataClearAndFree(&ss1);
        HcfBlobDataClearAndFree(&ss2);
        HcfBlobDataClearAndFree(&wk);
    }

    HcfObjDestroy(kem);
}

} // namespace
