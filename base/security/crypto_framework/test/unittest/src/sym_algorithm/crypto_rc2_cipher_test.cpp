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
#include <memory>
#include "securec.h"

#include "cipher.h"
#include "detailed_iv_params.h"
#include "log.h"
#include "memory.h"
#include "mock.h"
#include "result.h"
#include "sym_key_generator.h"
#include "sym_algorithm_common.h"
#include "cipher_openssl.h"

using namespace testing::ext;
using ::testing::_;
using ::testing::Invoke;
using ::testing::Return;

namespace {
class CryptoRc2CipherTest : public testing::Test {
public:
    static void SetUpTestCase() {};
    static void TearDownTestCase() {};
    void SetUp() override;
    void TearDown() override;

public:
    std::shared_ptr<HcfMock> mock_ = std::make_shared<HcfMock>();
};

void CryptoRc2CipherTest::SetUp()
{
    SetMock(mock_.get());
    EXPECT_CALL(*mock_, HcfMalloc(_, _)).WillRepeatedly(Invoke(__real_HcfMalloc));
    EXPECT_CALL(*mock_, HcfIsStrValid(_, _)).WillRepeatedly(Invoke(__real_HcfIsStrValid));
    EXPECT_CALL(*mock_, HcfIsClassMatch(_, _)).WillRepeatedly(Invoke(__real_HcfIsClassMatch));
    EXPECT_CALL(*mock_, OpensslEvpCipherFetch(_, _, _)).WillRepeatedly(Invoke(__real_OpensslEvpCipherFetch));
    EXPECT_CALL(*mock_, OpensslEvpCipherCtxNew()).WillRepeatedly(Invoke(__real_OpensslEvpCipherCtxNew));
    EXPECT_CALL(*mock_, OpensslEvpCipherInit(_, _, _, _, _)).WillRepeatedly(Invoke(__real_OpensslEvpCipherInit));
    EXPECT_CALL(*mock_, OpensslEvpCipherCtxSetKeyLength(_, _))
        .WillRepeatedly(Invoke(__real_OpensslEvpCipherCtxSetKeyLength));
    EXPECT_CALL(*mock_, OpensslEvpCipherCtxCtrl(_, _, _, _)).WillRepeatedly(Invoke(__real_OpensslEvpCipherCtxCtrl));
    EXPECT_CALL(*mock_, OpensslEvpCipherCtxSetPadding(_, _))
        .WillRepeatedly(Invoke(__real_OpensslEvpCipherCtxSetPadding));
    EXPECT_CALL(*mock_, OpensslEvpCipherUpdate(_, _, _, _, _)).WillRepeatedly(Invoke(__real_OpensslEvpCipherUpdate));
    EXPECT_CALL(*mock_, OpensslEvpCipherFinalEx(_, _, _)).WillRepeatedly(Invoke(__real_OpensslEvpCipherFinalEx));
}

void CryptoRc2CipherTest::TearDown()
{
    ResetMock();
}

HWTEST_F(CryptoRc2CipherTest, CryptoRc2CipherTest001, TestSize.Level0)
{
    uint8_t iv[SYM_ALG_IV_LEN] = {0};
    uint8_t cipherText[SYM_ALG_CIPHER_TEXT_MAX_LEN] = {0};
    int cipherTextLen = SYM_ALG_CIPHER_TEXT_MAX_LEN;

    HcfIvParamsSpec ivSpec = {};
    ivSpec.iv.data = iv;
    ivSpec.iv.len = SYM_ALG_IV_LEN;

    HcfSymKey *key = nullptr;
    HcfCipher *cipher = nullptr;

    uint8_t keyMaterial8[8] = {0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08};
    int ret = SymAlgConvertSymKey("RC2", keyMaterial8, sizeof(keyMaterial8), &key);
    ASSERT_EQ(ret, 0);

    ret = HcfCipherCreate("RC2|CBC|NoPadding", &cipher);
    ASSERT_EQ(ret, 0);

    ret = SymAlgEncrypt(cipher, key, (HcfParamsSpec *)&ivSpec, cipherText, &cipherTextLen);
    ASSERT_NE(ret, 0);

    HcfObjDestroy((HcfObjectBase *)key);
    HcfObjDestroy((HcfObjectBase *)cipher);
}

HWTEST_F(CryptoRc2CipherTest, CryptoRc2CipherTest002, TestSize.Level0)
{
    uint8_t iv[SYM_ALG_IV_LEN] = {0};
    uint8_t cipherText[SYM_ALG_CIPHER_TEXT_MAX_LEN] = {0};
    int cipherTextLen = SYM_ALG_CIPHER_TEXT_MAX_LEN;

    HcfIvParamsSpec ivSpec = {};
    ivSpec.iv.data = iv;
    ivSpec.iv.len = SYM_ALG_IV_LEN;

    HcfSymKey *key = nullptr;
    HcfCipher *cipher = nullptr;

    uint8_t keyMaterial8[8] = {0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08};
    int ret = SymAlgConvertSymKey("RC2", keyMaterial8, sizeof(keyMaterial8), &key);
    ASSERT_EQ(ret, 0);

    ret = HcfCipherCreate("RC2|CBC|PKCS5", &cipher);
    ASSERT_EQ(ret, 0);

    ret = SymAlgEncrypt(cipher, key, (HcfParamsSpec *)&ivSpec, cipherText, &cipherTextLen);
    ASSERT_EQ(ret, 0);

    ret = SymAlgDecrypt(cipher, key, (HcfParamsSpec *)&ivSpec, cipherText, cipherTextLen);
    ASSERT_EQ(ret, 0);

    HcfObjDestroy((HcfObjectBase *)key);
    HcfObjDestroy((HcfObjectBase *)cipher);
}

HWTEST_F(CryptoRc2CipherTest, CryptoRc2CipherTest003, TestSize.Level0)
{
    uint8_t iv[SYM_ALG_IV_LEN] = {0};
    uint8_t cipherText[SYM_ALG_CIPHER_TEXT_MAX_LEN] = {0};
    int cipherTextLen = SYM_ALG_CIPHER_TEXT_MAX_LEN;

    HcfIvParamsSpec ivSpec = {};
    ivSpec.iv.data = iv;
    ivSpec.iv.len = SYM_ALG_IV_LEN;

    HcfSymKey *key = nullptr;
    HcfCipher *cipher = nullptr;

    uint8_t keyMaterial8[8] = {0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08};
    int ret = SymAlgConvertSymKey("RC2", keyMaterial8, sizeof(keyMaterial8), &key);
    ASSERT_EQ(ret, 0);

    ret = HcfCipherCreate("RC2|CBC|PKCS7", &cipher);
    ASSERT_EQ(ret, 0);

    ret = SymAlgEncrypt(cipher, key, (HcfParamsSpec *)&ivSpec, cipherText, &cipherTextLen);
    ASSERT_EQ(ret, 0);

    ret = SymAlgDecrypt(cipher, key, (HcfParamsSpec *)&ivSpec, cipherText, cipherTextLen);
    ASSERT_EQ(ret, 0);

    HcfObjDestroy((HcfObjectBase *)key);
    HcfObjDestroy((HcfObjectBase *)cipher);
}

HWTEST_F(CryptoRc2CipherTest, CryptoRc2CipherTest004, TestSize.Level0)
{
    uint8_t iv[SYM_ALG_IV_LEN] = {0};
    uint8_t cipherText[SYM_ALG_CIPHER_TEXT_MAX_LEN] = {0};
    int cipherTextLen = SYM_ALG_CIPHER_TEXT_MAX_LEN;

    HcfIvParamsSpec ivSpec = {};
    ivSpec.iv.data = iv;
    ivSpec.iv.len = SYM_ALG_IV_LEN;

    HcfSymKey *key = nullptr;
    HcfCipher *cipher = nullptr;

    uint8_t keyMaterial8[8] = {0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08};
    int ret = SymAlgConvertSymKey("RC2", keyMaterial8, sizeof(keyMaterial8), &key);
    ASSERT_EQ(ret, 0);

    ret = HcfCipherCreate("RC2|CBC|NoPadding", &cipher);
    ASSERT_EQ(ret, 0);

    ret = SymAlgNoUpdateEncrypt(cipher, key, (HcfParamsSpec *)&ivSpec, cipherText, &cipherTextLen);
    ASSERT_NE(ret, 0);

    HcfObjDestroy((HcfObjectBase *)key);
    HcfObjDestroy((HcfObjectBase *)cipher);
}

HWTEST_F(CryptoRc2CipherTest, CryptoRc2CipherTest005, TestSize.Level0)
{
    uint8_t iv[SYM_ALG_IV_LEN] = {0};
    uint8_t cipherText[SYM_ALG_CIPHER_TEXT_MAX_LEN] = {0};
    int cipherTextLen = SYM_ALG_CIPHER_TEXT_MAX_LEN;

    HcfIvParamsSpec ivSpec = {};
    ivSpec.iv.data = iv;
    ivSpec.iv.len = SYM_ALG_IV_LEN;

    HcfSymKey *key = nullptr;
    HcfCipher *cipher = nullptr;

    uint8_t keyMaterial8[8] = {0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08};
    int ret = SymAlgConvertSymKey("RC2", keyMaterial8, sizeof(keyMaterial8), &key);
    ASSERT_EQ(ret, 0);

    ret = HcfCipherCreate("RC2|CBC|PKCS5", &cipher);
    ASSERT_EQ(ret, 0);

    ret = SymAlgNoUpdateEncrypt(cipher, key, (HcfParamsSpec *)&ivSpec, cipherText, &cipherTextLen);
    ASSERT_EQ(ret, 0);

    ret = SymAlgNoUpdateDecrypt(cipher, key, (HcfParamsSpec *)&ivSpec, cipherText, cipherTextLen);
    ASSERT_EQ(ret, 0);

    HcfObjDestroy((HcfObjectBase *)key);
    HcfObjDestroy((HcfObjectBase *)cipher);
}

HWTEST_F(CryptoRc2CipherTest, CryptoRc2CipherTest006, TestSize.Level0)
{
    uint8_t iv[SYM_ALG_IV_LEN] = {0};
    uint8_t cipherText[SYM_ALG_CIPHER_TEXT_MAX_LEN] = {0};
    int cipherTextLen = SYM_ALG_CIPHER_TEXT_MAX_LEN;

    HcfIvParamsSpec ivSpec = {};
    ivSpec.iv.data = iv;
    ivSpec.iv.len = SYM_ALG_IV_LEN;

    HcfSymKey *key = nullptr;
    HcfCipher *cipher = nullptr;

    uint8_t keyMaterial8[8] = {0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08};
    int ret = SymAlgConvertSymKey("RC2", keyMaterial8, sizeof(keyMaterial8), &key);
    ASSERT_EQ(ret, 0);

    ret = HcfCipherCreate("RC2|CBC|PKCS7", &cipher);
    ASSERT_EQ(ret, 0);

    ret = SymAlgNoUpdateEncrypt(cipher, key, (HcfParamsSpec *)&ivSpec, cipherText, &cipherTextLen);
    ASSERT_EQ(ret, 0);

    ret = SymAlgNoUpdateDecrypt(cipher, key, (HcfParamsSpec *)&ivSpec, cipherText, cipherTextLen);
    ASSERT_EQ(ret, 0);

    HcfObjDestroy((HcfObjectBase *)key);
    HcfObjDestroy((HcfObjectBase *)cipher);
}

HWTEST_F(CryptoRc2CipherTest, CryptoRc2CipherTest007, TestSize.Level0)
{
    uint8_t cipherText[SYM_ALG_CIPHER_TEXT_MAX_LEN] = {0};
    int cipherTextLen = SYM_ALG_CIPHER_TEXT_MAX_LEN;

    HcfSymKey *key = nullptr;
    HcfCipher *cipher = nullptr;

    uint8_t keyMaterial8[8] = {0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08};
    int ret = SymAlgConvertSymKey("RC2", keyMaterial8, sizeof(keyMaterial8), &key);
    ASSERT_EQ(ret, 0);

    ret = HcfCipherCreate("RC2|ECB|PKCS7", &cipher);
    ASSERT_EQ(ret, 0);

    ret = SymAlgEncrypt(cipher, key, nullptr, cipherText, &cipherTextLen);
    ASSERT_EQ(ret, 0);

    ret = SymAlgDecrypt(cipher, key, nullptr, cipherText, cipherTextLen);
    ASSERT_EQ(ret, 0);

    HcfObjDestroy((HcfObjectBase *)key);
    HcfObjDestroy((HcfObjectBase *)cipher);
}

HWTEST_F(CryptoRc2CipherTest, CryptoRc2CipherTest008, TestSize.Level0)
{
    uint8_t iv[SYM_ALG_IV_LEN] = {0};
    uint8_t cipherText[SYM_ALG_CIPHER_TEXT_MAX_LEN] = {0};
    int cipherTextLen = SYM_ALG_CIPHER_TEXT_MAX_LEN;

    HcfIvParamsSpec ivSpec = {};
    ivSpec.iv.data = iv;
    ivSpec.iv.len = SYM_ALG_IV_LEN;

    HcfSymKey *key = nullptr;
    HcfCipher *cipher = nullptr;

    uint8_t keyMaterial16[16] = {0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
                                 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10};
    int ret = SymAlgConvertSymKey("RC2", keyMaterial16, sizeof(keyMaterial16), &key);
    ASSERT_EQ(ret, 0);

    ret = HcfCipherCreate("RC2|CBC|PKCS7", &cipher);
    ASSERT_EQ(ret, 0);

    ret = SymAlgEncrypt(cipher, key, (HcfParamsSpec *)&ivSpec, cipherText, &cipherTextLen);
    ASSERT_EQ(ret, 0);

    ret = SymAlgDecrypt(cipher, key, (HcfParamsSpec *)&ivSpec, cipherText, cipherTextLen);
    ASSERT_EQ(ret, 0);

    HcfObjDestroy((HcfObjectBase *)key);
    HcfObjDestroy((HcfObjectBase *)cipher);
}

HWTEST_F(CryptoRc2CipherTest, CryptoRc2CipherTest009, TestSize.Level0)
{
    uint8_t iv[SYM_ALG_IV_LEN] = {0};
    uint8_t keyMaterial[8] = {0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08};
    uint8_t cipherText[SYM_ALG_CIPHER_TEXT_MAX_LEN] = {0};
    int cipherTextLen = SYM_ALG_CIPHER_TEXT_MAX_LEN;

    HcfIvParamsSpec ivSpec = {};
    ivSpec.iv.data = iv;
    ivSpec.iv.len = SYM_ALG_IV_LEN;

    HcfSymKey *key = nullptr;
    HcfCipher *cipher = nullptr;

    int ret = SymAlgConvertSymKey("RC2", keyMaterial, sizeof(keyMaterial), &key);
    ASSERT_EQ(ret, 0);

    ret = HcfCipherCreate("RC2|CBC|PKCS7", &cipher);
    ASSERT_EQ(ret, 0);

    ret = SymAlgEncrypt(cipher, key, (HcfParamsSpec *)&ivSpec, cipherText, &cipherTextLen);
    ASSERT_EQ(ret, 0);

    ret = SymAlgDecrypt(cipher, key, (HcfParamsSpec *)&ivSpec, cipherText, cipherTextLen);
    ASSERT_EQ(ret, 0);

    HcfObjDestroy((HcfObjectBase *)key);
    HcfObjDestroy((HcfObjectBase *)cipher);
}

HWTEST_F(CryptoRc2CipherTest, CryptoRc2CipherTest010, TestSize.Level0)
{
    uint8_t keyMaterial[8] = {0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff};
    uint8_t plaintext[8] = {0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff};
    uint8_t expected[8] = {0x27, 0x8b, 0x27, 0xe4, 0x2e, 0x2f, 0x0d, 0x49};
    HcfSymKey *key = nullptr;
    HcfCipher *cipher = nullptr;

    HcfBlob plainTextBlob = {.data = plaintext, .len = sizeof(plaintext)};
    HcfBlob cipherTextBlob = {};

    int res = SymAlgConvertSymKey("RC2", keyMaterial, sizeof(keyMaterial), &key);
    ASSERT_EQ(res, 0);

    HcfResult ret = HcfCipherCreate("RC2|ECB|NoPadding", &cipher);
    ASSERT_EQ(ret, HCF_SUCCESS);
    // Encrypt
    ret = cipher->init(cipher, ENCRYPT_MODE, (HcfKey *)key, nullptr);
    ASSERT_EQ(ret, HCF_SUCCESS);

    ret = cipher->doFinal(cipher, &plainTextBlob, &cipherTextBlob);
    EXPECT_EQ(ret, HCF_SUCCESS);
    LOGE("cipherTextBlob.len: %zu", cipherTextBlob.len);
    for (size_t i = 0; i < cipherTextBlob.len; i++) {
        LOGE("cipherTextBlob.data[%zu]: %02x", i, cipherTextBlob.data[i]);
    }
    EXPECT_EQ(cipherTextBlob.len, sizeof(expected));
    EXPECT_EQ(memcmp(cipherTextBlob.data, expected, sizeof(expected)), 0);
    if (cipherTextBlob.data != nullptr) {
        HcfBlobDataFree(&cipherTextBlob);
    }
    HcfObjDestroy(key);
    HcfObjDestroy(cipher);
}

HWTEST_F(CryptoRc2CipherTest, CryptoRc2CipherTest011, TestSize.Level0)
{
    uint8_t keyMaterial[8] = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
    uint8_t iv[8] = {0};
    uint8_t plaintext[8] = {0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08};
    uint8_t expected[8] = {0x19, 0x1d, 0x1a, 0xbf, 0x76, 0x7b, 0xfb, 0xe7};
    HcfSymKey *key = nullptr;
    HcfCipher *cipher = nullptr;
    HcfIvParamsSpec ivSpec = {};
    ivSpec.iv.data = iv;
    ivSpec.iv.len = sizeof(iv);
    HcfBlob plainTextBlob = {.data = plaintext, .len = sizeof(plaintext)};
    HcfBlob cipherTextBlob = {};

    int res = SymAlgConvertSymKey("RC2", keyMaterial, sizeof(keyMaterial), &key);
    ASSERT_EQ(res, 0);
    HcfResult ret = HcfCipherCreate("RC2|CBC|NoPadding", &cipher);
    ASSERT_EQ(ret, HCF_SUCCESS);
    ret = cipher->init(cipher, ENCRYPT_MODE, (HcfKey *)key, (HcfParamsSpec *)&ivSpec);
    ASSERT_EQ(ret, HCF_SUCCESS);
    ret = cipher->doFinal(cipher, &plainTextBlob, &cipherTextBlob);
    ASSERT_EQ(ret, HCF_SUCCESS);
    EXPECT_EQ(cipherTextBlob.len, sizeof(expected));
    EXPECT_EQ(memcmp(cipherTextBlob.data, expected, sizeof(expected)), 0);
    if (cipherTextBlob.data != nullptr) {
        HcfBlobDataFree(&cipherTextBlob);
    }
    HcfObjDestroy(key);
    HcfObjDestroy(cipher);
}

HWTEST_F(CryptoRc2CipherTest, CryptoRc2CipherTest012, TestSize.Level0)
{
    uint8_t keyMaterial[8] = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};  /* Key=0000000000000000 */
    uint8_t iv16[16] = {0};
    uint8_t plaintext[16] = {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
                             0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F};
    HcfIvParamsSpec ivSpec = {};
    ivSpec.iv.data = iv16;
    ivSpec.iv.len = 16;
    HcfSymKey *key = nullptr;
    HcfCipher *cipher = nullptr;
    HcfBlob plainTextBlob = {.data = plaintext, .len = sizeof(plaintext)};
    HcfBlob cipherTextBlob = {};

    int res = SymAlgConvertSymKey("RC2", keyMaterial, sizeof(keyMaterial), &key);
    ASSERT_EQ(res, 0);
    HcfResult ret = HcfCipherCreate("RC2|OFB|NoPadding", &cipher);
    ASSERT_EQ(ret, HCF_SUCCESS);
    ret = cipher->init(cipher, ENCRYPT_MODE, (HcfKey *)key, (HcfParamsSpec *)&ivSpec);
    if (ret == HCF_SUCCESS) {
        ret = cipher->doFinal(cipher, &plainTextBlob, &cipherTextBlob);
        if (cipherTextBlob.data != nullptr) {
            HcfBlobDataFree(&cipherTextBlob);
        }
    }
    ASSERT_NE(ret, HCF_SUCCESS);
    HcfObjDestroy(key);
    HcfObjDestroy(cipher);
}

HWTEST_F(CryptoRc2CipherTest, CryptoRc2CipherTest013, TestSize.Level0)
{
    uint8_t keyMaterial[16] = {0x88, 0xbc, 0xa9, 0x0e, 0x90, 0x87, 0x5a, 0x7f,
                                0x0f, 0x79, 0xc3, 0x84, 0x62, 0x7b, 0xaf, 0xb2};
    uint8_t plaintext[8] = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
    uint8_t expected[8] = {0x22, 0x69, 0x55, 0x2a, 0xb0, 0xf8, 0x5c, 0xa6};
    HcfSymKey *key = nullptr;
    HcfCipher *cipher = nullptr;
    HcfBlob plainTextBlob = {.data = plaintext, .len = sizeof(plaintext)};
    HcfBlob cipherTextBlob = {};

    int res = SymAlgConvertSymKey("RC2", keyMaterial, sizeof(keyMaterial), &key);
    ASSERT_EQ(res, 0);
    HcfResult ret = HcfCipherCreate("RC2|ECB|NoPadding", &cipher);
    ASSERT_EQ(ret, HCF_SUCCESS);
    ret = cipher->init(cipher, ENCRYPT_MODE, (HcfKey *)key, nullptr);
    ASSERT_EQ(ret, HCF_SUCCESS);
    ret = cipher->doFinal(cipher, &plainTextBlob, &cipherTextBlob);
    ASSERT_EQ(ret, HCF_SUCCESS);
    EXPECT_EQ(cipherTextBlob.len, sizeof(expected));
    EXPECT_EQ(memcmp(cipherTextBlob.data, expected, sizeof(expected)), 0);
    if (cipherTextBlob.data != nullptr) {
        HcfBlobDataFree(&cipherTextBlob);
    }
    HcfObjDestroy(key);
    HcfObjDestroy(cipher);
}

HWTEST_F(CryptoRc2CipherTest, CryptoRc2CipherTest014, TestSize.Level0)
{
    uint8_t keyMaterial[16] = {0x88, 0xbc, 0xa9, 0x0e, 0x90, 0x87, 0x5a, 0x7f,
                                0x0f, 0x79, 0xc3, 0x84, 0x62, 0x7b, 0xaf, 0xb2};
    HcfSymKey *key = nullptr;
    HcfCipher *cipher = nullptr;

    int res = SymAlgConvertSymKey("RC2", keyMaterial, sizeof(keyMaterial), &key);
    ASSERT_EQ(res, 0);
    HcfResult ret = HcfCipherCreate("RC2|ECB|NoPadding", &cipher);
    ASSERT_EQ(ret, HCF_SUCCESS);
    HcfBlob dataArray = { .data = nullptr, .len = 0 };
    char *returnMdName = nullptr;
    ret = cipher->getCipherSpecString(cipher, OAEP_MGF1_MD_STR, &returnMdName);
    EXPECT_NE(ret, HCF_SUCCESS);

    ret = cipher->getCipherSpecUint8Array(cipher, OAEP_MGF1_PSRC_UINT8ARR, &dataArray);
    EXPECT_NE(ret, HCF_SUCCESS);

    HcfBlob dataUint8 = { .data = nullptr, .len = 0 };
    ret = cipher->setCipherSpecUint8Array(cipher, OAEP_MGF1_PSRC_UINT8ARR, dataUint8);
    EXPECT_NE(ret, HCF_SUCCESS);
    HcfObjDestroy(key);
    HcfObjDestroy(cipher);
}

HWTEST_F(CryptoRc2CipherTest, CryptoRc2CipherTest015, TestSize.Level0)
{
    HcfResult res = HCF_SUCCESS;
    HcfCipherGeneratorSpi *cipher = nullptr;
    CipherAttr params = {
        .algo = HCF_ALG_RC2,
        .mode = HCF_ALG_MODE_ECB,
        .paddingMode = HCF_ALG_PADDING_PKCS5,
    };
    res = HcfCipherSymAlgorithmGeneratorSpiCreate(&params, nullptr);
    EXPECT_NE(res, HCF_SUCCESS);
    HcfObjDestroy(cipher);
}

HWTEST_F(CryptoRc2CipherTest, CryptoRc2CipherTest016, TestSize.Level0)
{
    HcfResult res = HCF_SUCCESS;
    HcfCipherGeneratorSpi *cipher = nullptr;
    CipherAttr params = {
        .algo = HCF_ALG_CHACHA20,
        .mode = HCF_ALG_MODE_ECB,
        .paddingMode = HCF_ALG_PADDING_PKCS5,
    };
    res = HcfCipherSymAlgorithmGeneratorSpiCreate(&params, nullptr);
    EXPECT_NE(res, HCF_SUCCESS);
    HcfObjDestroy(cipher);
}

HWTEST_F(CryptoRc2CipherTest, CryptoRc2CipherTest017, TestSize.Level0)
{
    HcfResult res = HCF_SUCCESS;
    HcfCipherGeneratorSpi *cipher = nullptr;
    CipherAttr params = {
        .algo = HCF_ALG_RC2,
        .mode = HCF_ALG_MODE_CFB128,
        .paddingMode = HCF_ALG_PADDING_PKCS5,
    };
    res = HcfCipherSymAlgorithmGeneratorSpiCreate(&params, nullptr);
    EXPECT_NE(res, HCF_SUCCESS);
    HcfObjDestroy(cipher);
}

HWTEST_F(CryptoRc2CipherTest, CryptoRc2CipherTest018, TestSize.Level0)
{
    uint8_t iv[SYM_ALG_IV_LEN] = {0};
    uint8_t cipherText[SYM_ALG_CIPHER_TEXT_MAX_LEN] = {0};
    int cipherTextLen = SYM_ALG_CIPHER_TEXT_MAX_LEN;

    HcfIvParamsSpec ivSpec = {};
    ivSpec.iv.data = iv;
    ivSpec.iv.len = SYM_ALG_IV_LEN;

    HcfSymKey *key = nullptr;
    HcfCipher *cipher = nullptr;

    uint8_t keyMaterial8[8] = {0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08};
    int ret = SymAlgConvertSymKey("RC2", keyMaterial8, sizeof(keyMaterial8), &key);
    ASSERT_EQ(ret, 0);

    ret = HcfCipherCreate("RC2|OFB|PKCS5", &cipher);
    ASSERT_EQ(ret, 0);

    ret = SymAlgEncrypt(cipher, key, (HcfParamsSpec *)&ivSpec, cipherText, &cipherTextLen);
    ASSERT_EQ(ret, 0);

    ret = SymAlgDecrypt(cipher, key, (HcfParamsSpec *)&ivSpec, cipherText, cipherTextLen);
    ASSERT_EQ(ret, 0);

    HcfObjDestroy((HcfObjectBase *)key);
    HcfObjDestroy((HcfObjectBase *)cipher);
}

HWTEST_F(CryptoRc2CipherTest, CryptoRc2CipherTest019, TestSize.Level0)
{
    uint8_t iv[SYM_ALG_IV_LEN] = {0};
    uint8_t cipherText[SYM_ALG_CIPHER_TEXT_MAX_LEN] = {0};
    int cipherTextLen = SYM_ALG_CIPHER_TEXT_MAX_LEN;

    HcfIvParamsSpec ivSpec = {};
    ivSpec.iv.data = iv;
    ivSpec.iv.len = SYM_ALG_IV_LEN;

    HcfSymKey *key = nullptr;
    HcfCipher *cipher = nullptr;

    uint8_t keyMaterial8[8] = {0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08};
    int ret = SymAlgConvertSymKey("RC2", keyMaterial8, sizeof(keyMaterial8), &key);
    ASSERT_EQ(ret, 0);

    ret = HcfCipherCreate("RC2|CFB|PKCS5", &cipher);
    ASSERT_EQ(ret, 0);

    ret = SymAlgEncrypt(cipher, key, (HcfParamsSpec *)&ivSpec, cipherText, &cipherTextLen);
    ASSERT_EQ(ret, 0);

    ret = SymAlgDecrypt(cipher, key, (HcfParamsSpec *)&ivSpec, cipherText, cipherTextLen);
    ASSERT_EQ(ret, 0);

    HcfObjDestroy((HcfObjectBase *)key);
    HcfObjDestroy((HcfObjectBase *)cipher);
}

HWTEST_F(CryptoRc2CipherTest, CryptoRc2CipherErrTest001, TestSize.Level0)
{
    HcfSymKey *key = nullptr;
    int ret = SymAlgGenerateSymKey("RC2", &key);
    ASSERT_NE(ret, 0);

    HcfObjDestroy((HcfObjectBase *)key);
}

HWTEST_F(CryptoRc2CipherTest, CryptoRc2CipherTest020, TestSize.Level0)
{
    HcfSymKey *key = nullptr;
    HcfCipher *cipher = nullptr;

    uint8_t keyMaterial8[8] = {0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08};
    int ret = SymAlgConvertSymKey("RC2", keyMaterial8, sizeof(keyMaterial8), &key);
    ASSERT_EQ(ret, 0);

    ret = HcfCipherCreate("RC2|ABC|PKCS5", &cipher);
    ASSERT_EQ(ret, HCF_NOT_SUPPORT);

    HcfObjDestroy((HcfObjectBase *)key);
    HcfObjDestroy((HcfObjectBase *)cipher);
}

HWTEST_F(CryptoRc2CipherTest, CryptoRc2CipherTest021, TestSize.Level0)
{
    HcfCipher *cipher = nullptr;
    HcfResult ret = HcfCipherCreate("RC2|ECB|NoPadding", &cipher);
    ASSERT_EQ(ret, HCF_SUCCESS);
    ret = cipher->init(cipher, ENCRYPT_MODE, nullptr, nullptr);
    ASSERT_NE(ret, HCF_SUCCESS);
    HcfObjDestroy(cipher);
}

HWTEST_F(CryptoRc2CipherTest, CryptoRc2CipherTest022, TestSize.Level0)
{
    uint8_t keyMaterial[16] = {0x88, 0xbc, 0xa9, 0x0e, 0x90, 0x87, 0x5a, 0x7f,
                                0x0f, 0x79, 0xc3, 0x84, 0x62, 0x7b, 0xaf, 0xb2};
    HcfSymKey *key = nullptr;
    HcfCipher *cipher = nullptr;

    int res = SymAlgConvertSymKey("RC2", keyMaterial, sizeof(keyMaterial), &key);
    ASSERT_EQ(res, 0);
    HcfResult ret = HcfCipherCreate("RC2|ECB|NoPadding", &cipher);
    ASSERT_EQ(ret, HCF_SUCCESS);
    EXPECT_CALL(*mock_, OpensslEvpCipherInit(_, _, _, _, _))
 	              .WillOnce(Return(-1))
 	              .WillRepeatedly(Invoke(__real_OpensslEvpCipherInit));
    ret = cipher->init(cipher, ENCRYPT_MODE, (HcfKey *)key, nullptr);
    ASSERT_NE(ret, HCF_SUCCESS);

    HcfObjDestroy(cipher);
    cipher = nullptr;
    ret = HcfCipherCreate("RC2|ECB|NoPadding", &cipher);
    ASSERT_EQ(ret, HCF_SUCCESS);
    EXPECT_CALL(*mock_, OpensslEvpCipherCtxSetKeyLength(_, _))
 	              .WillOnce(Return(-1))
 	              .WillRepeatedly(Invoke(__real_OpensslEvpCipherCtxSetKeyLength));
    ret = cipher->init(cipher, ENCRYPT_MODE, (HcfKey *)key, nullptr);
    ASSERT_NE(ret, HCF_SUCCESS);

    HcfObjDestroy(cipher);
    cipher = nullptr;
    ret = HcfCipherCreate("RC2|ECB|NoPadding", &cipher);
    ASSERT_EQ(ret, HCF_SUCCESS);
    EXPECT_CALL(*mock_, OpensslEvpCipherCtxSetPadding(_, _))
        .WillOnce(Return(-1))
        .WillRepeatedly(Invoke(__real_OpensslEvpCipherCtxSetPadding));
    ret = cipher->init(cipher, ENCRYPT_MODE, (HcfKey *)key, nullptr);
    ASSERT_NE(ret, HCF_SUCCESS);

    HcfObjDestroy(cipher);
    HcfObjDestroy(key);
}

HWTEST_F(CryptoRc2CipherTest, CryptoRc2CipherTest023, TestSize.Level0)
{
    uint8_t keyMaterial[8] = {0};
    uint8_t iv[8] = {0};
    uint8_t plaintext[16] = {0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0, 0, 0, 0, 0, 0, 0, 0};
    HcfIvParamsSpec ivSpec = {};
    ivSpec.iv.data = iv;
    ivSpec.iv.len = sizeof(iv);
    HcfBlob plainBlob = {.data = plaintext, .len = sizeof(plaintext)};
    HcfBlob outBlob = {};
    HcfSymKey *key = nullptr;
    HcfCipher *cipher = nullptr;
    ASSERT_EQ(SymAlgConvertSymKey("RC2", keyMaterial, sizeof(keyMaterial), &key), 0);
    ASSERT_EQ(HcfCipherCreate("RC2|CBC|PKCS7", &cipher), HCF_SUCCESS);
    HcfParamsSpec *params = (HcfParamsSpec *)&ivSpec;

    ASSERT_EQ(cipher->init(cipher, ENCRYPT_MODE, (HcfKey *)key, params), HCF_SUCCESS);
    EXPECT_CALL(*mock_, HcfMalloc(_, _)).WillOnce(Return(nullptr)).WillRepeatedly(Invoke(__real_HcfMalloc));
    EXPECT_EQ(cipher->update(cipher, &plainBlob, &outBlob), HCF_ERR_MALLOC);

    HcfObjDestroy(cipher);
    HcfObjDestroy(key);
}

HWTEST_F(CryptoRc2CipherTest, CryptoRc2CipherTest024, TestSize.Level0)
{
    uint8_t keyMaterial[8] = {0};
    uint8_t iv[8] = {0};
    uint8_t plaintext[16] = {0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0, 0, 0, 0, 0, 0, 0, 0};
    HcfIvParamsSpec ivSpec = {};
    ivSpec.iv.data = iv;
    ivSpec.iv.len = sizeof(iv);
    HcfBlob plainBlob = {.data = plaintext, .len = sizeof(plaintext)};
    HcfBlob outBlob = {};
    HcfSymKey *key = nullptr;
    HcfCipher *cipher = nullptr;
    ASSERT_EQ(SymAlgConvertSymKey("RC2", keyMaterial, sizeof(keyMaterial), &key), 0);
    ASSERT_EQ(HcfCipherCreate("RC2|CBC|PKCS7", &cipher), HCF_SUCCESS);
    HcfParamsSpec *params = (HcfParamsSpec *)&ivSpec;

    ASSERT_EQ(cipher->init(cipher, ENCRYPT_MODE, (HcfKey *)key, params), HCF_SUCCESS);
    EXPECT_CALL(*mock_, OpensslEvpCipherUpdate(_, _, _, _, _))
        .WillOnce(Return(0))
        .WillRepeatedly(Invoke(__real_OpensslEvpCipherUpdate));
    EXPECT_EQ(cipher->update(cipher, &plainBlob, &outBlob), HCF_ERR_CRYPTO_OPERATION);

    HcfObjDestroy(cipher);
    HcfObjDestroy(key);
}

HWTEST_F(CryptoRc2CipherTest, CryptoRc2CipherTest025, TestSize.Level0)
{
    uint8_t keyMaterial[8] = {0};
    uint8_t iv[8] = {0};
    uint8_t plaintext[16] = {0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0, 0, 0, 0, 0, 0, 0, 0};
    HcfIvParamsSpec ivSpec = {};
    ivSpec.iv.data = iv;
    ivSpec.iv.len = sizeof(iv);
    HcfBlob plainBlob = {.data = plaintext, .len = sizeof(plaintext)};
    HcfBlob outBlob = {};
    HcfSymKey *key = nullptr;
    HcfCipher *cipher = nullptr;
    ASSERT_EQ(SymAlgConvertSymKey("RC2", keyMaterial, sizeof(keyMaterial), &key), 0);
    ASSERT_EQ(HcfCipherCreate("RC2|CBC|PKCS7", &cipher), HCF_SUCCESS);
    HcfParamsSpec *params = (HcfParamsSpec *)&ivSpec;

    ASSERT_EQ(cipher->init(cipher, ENCRYPT_MODE, (HcfKey *)key, params), HCF_SUCCESS);
    EXPECT_CALL(*mock_, HcfMalloc(_, _)).WillOnce(Return(nullptr)).WillRepeatedly(Invoke(__real_HcfMalloc));
    EXPECT_EQ(cipher->doFinal(cipher, &plainBlob, &outBlob), HCF_ERR_MALLOC);

    HcfObjDestroy(cipher);
    HcfObjDestroy(key);
}

HWTEST_F(CryptoRc2CipherTest, CryptoRc2CipherTest026, TestSize.Level0)
{
    uint8_t keyMaterial[8] = {0};
    uint8_t iv[8] = {0};
    uint8_t plaintext[16] = {0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0, 0, 0, 0, 0, 0, 0, 0};
    HcfIvParamsSpec ivSpec = {};
    ivSpec.iv.data = iv;
    ivSpec.iv.len = sizeof(iv);
    HcfBlob plainBlob = {.data = plaintext, .len = sizeof(plaintext)};
    HcfBlob outBlob = {};
    HcfSymKey *key = nullptr;
    HcfCipher *cipher = nullptr;
    ASSERT_EQ(SymAlgConvertSymKey("RC2", keyMaterial, sizeof(keyMaterial), &key), 0);
    ASSERT_EQ(HcfCipherCreate("RC2|CBC|PKCS7", &cipher), HCF_SUCCESS);
    HcfParamsSpec *params = (HcfParamsSpec *)&ivSpec;

    ASSERT_EQ(cipher->init(cipher, ENCRYPT_MODE, (HcfKey *)key, params), HCF_SUCCESS);
    EXPECT_CALL(*mock_, OpensslEvpCipherFinalEx(_, _, _))
        .WillOnce(Return(0))
        .WillRepeatedly(Invoke(__real_OpensslEvpCipherFinalEx));
    EXPECT_EQ(cipher->doFinal(cipher, &plainBlob, &outBlob), HCF_ERR_CRYPTO_OPERATION);

    HcfObjDestroy(cipher);
    HcfObjDestroy(key);
}

HWTEST_F(CryptoRc2CipherTest, CryptoRc2CipherTest027, TestSize.Level0)
{
    uint8_t keyMaterial[8] = {0};
    uint8_t iv[8] = {0};
    uint8_t plaintext[16] = {0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0, 0, 0, 0, 0, 0, 0, 0};
    HcfIvParamsSpec ivSpec = {};
    ivSpec.iv.data = iv;
    ivSpec.iv.len = sizeof(iv);
    HcfBlob plainBlob = {.data = plaintext, .len = sizeof(plaintext)};
    HcfBlob outBlob = {};
    HcfSymKey *key = nullptr;
    HcfCipher *cipher = nullptr;
    ASSERT_EQ(SymAlgConvertSymKey("RC2", keyMaterial, sizeof(keyMaterial), &key), 0);
    ASSERT_EQ(HcfCipherCreate("RC2|CBC|PKCS7", &cipher), HCF_SUCCESS);
    HcfParamsSpec *params = (HcfParamsSpec *)&ivSpec;

    ASSERT_EQ(cipher->init(cipher, ENCRYPT_MODE, (HcfKey *)key, params), HCF_SUCCESS);
    ASSERT_EQ(cipher->update(cipher, &plainBlob, &outBlob), HCF_SUCCESS);
    if (outBlob.data != nullptr) {
        HcfBlobDataFree(&outBlob);
        outBlob.data = nullptr;
        outBlob.len = 0;
    }
    EXPECT_CALL(*mock_, OpensslEvpCipherUpdate(_, _, _, _, _))
        .WillOnce(Return(0))
        .WillRepeatedly(Invoke(__real_OpensslEvpCipherUpdate));
    EXPECT_EQ(cipher->doFinal(cipher, &plainBlob, &outBlob), HCF_ERR_CRYPTO_OPERATION);
    if (outBlob.data != nullptr) { HcfBlobDataFree(&outBlob); }

    HcfObjDestroy(cipher);
    HcfObjDestroy(key);
}

HWTEST_F(CryptoRc2CipherTest, CryptoRc2CipherTest028, TestSize.Level0)
{
    uint8_t keyMaterial[8] = {0};
    uint8_t iv[8] = {0};
    uint8_t plaintext[16] = {0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0, 0, 0, 0, 0, 0, 0, 0};
    HcfIvParamsSpec ivSpec = {};
    ivSpec.iv.data = iv;
    ivSpec.iv.len = sizeof(iv);
    HcfBlob plainBlob = {.data = plaintext, .len = sizeof(plaintext)};
    HcfBlob outBlob = {};
    HcfSymKey *key = nullptr;
    HcfCipher *cipher = nullptr;
    ASSERT_EQ(SymAlgConvertSymKey("RC2", keyMaterial, sizeof(keyMaterial), &key), 0);
    ASSERT_EQ(HcfCipherCreate("RC2|CBC|PKCS7", &cipher), HCF_SUCCESS);
    HcfParamsSpec *params = (HcfParamsSpec *)&ivSpec;

    ASSERT_EQ(cipher->init(cipher, ENCRYPT_MODE, (HcfKey *)key, params), HCF_SUCCESS);
    ASSERT_EQ(cipher->update(cipher, &plainBlob, &outBlob), HCF_SUCCESS);
    if (outBlob.data != nullptr) {
        HcfBlobDataFree(&outBlob);
        outBlob.data = nullptr;
        outBlob.len = 0;
    }
    EXPECT_CALL(*mock_, OpensslEvpCipherFinalEx(_, _, _))
        .WillOnce(Return(0))
        .WillRepeatedly(Invoke(__real_OpensslEvpCipherFinalEx));
    EXPECT_EQ(cipher->doFinal(cipher, &plainBlob, &outBlob), HCF_ERR_CRYPTO_OPERATION);
    if (outBlob.data != nullptr) { HcfBlobDataFree(&outBlob); }

    HcfObjDestroy(cipher);
    HcfObjDestroy(key);
}

HWTEST_F(CryptoRc2CipherTest, CryptoRc2CipherTest029, TestSize.Level0)
{
    uint8_t keyMaterial[8] = {0};
    uint8_t iv[8] = {0};
    HcfIvParamsSpec ivSpec = {};
    ivSpec.iv.data = iv;
    ivSpec.iv.len = sizeof(iv);
    HcfSymKey *key = nullptr;
    HcfCipher *cipher = nullptr;
    ASSERT_EQ(SymAlgConvertSymKey("RC2", keyMaterial, sizeof(keyMaterial), &key), 0);
    ASSERT_EQ(HcfCipherCreate("RC2|CBC|PKCS7", &cipher), HCF_SUCCESS);
    HcfParamsSpec *params = (HcfParamsSpec *)&ivSpec;

    EXPECT_CALL(*mock_, OpensslEvpCipherCtxNew())
        .WillOnce(Return(nullptr))
        .WillRepeatedly(Invoke(__real_OpensslEvpCipherCtxNew));
    ASSERT_EQ(cipher->init(cipher, ENCRYPT_MODE, (HcfKey *)key, params), HCF_ERR_MALLOC);

    EXPECT_CALL(*mock_, OpensslEvpCipherCtxCtrl(_, _, _, _))
        .WillOnce(Return(-1))
        .WillRepeatedly(Invoke(__real_OpensslEvpCipherCtxCtrl));
    ASSERT_EQ(cipher->init(cipher, ENCRYPT_MODE, (HcfKey *)key, params), HCF_ERR_CRYPTO_OPERATION);

    ASSERT_EQ(cipher->init(cipher, (enum HcfCryptoMode)123, (HcfKey *)key, params), HCF_ERR_PARAMETER_CHECK_FAILED);

    HcfObjDestroy(cipher);
    HcfObjDestroy(key);
}

HWTEST_F(CryptoRc2CipherTest, CryptoRc2CipherTest030, TestSize.Level0)
{
    uint8_t keyMaterial[8] = {0};
    uint8_t iv[8] = {0};
    HcfIvParamsSpec ivSpec = {};
    ivSpec.iv.data = iv;
    ivSpec.iv.len = sizeof(iv);

    HcfBlob plainBlob = {};
    uint8_t dummy = 0;
    plainBlob.data = &dummy;
    plainBlob.len = (size_t)UINT32_MAX;
    HcfBlob outBlob = {};

    HcfSymKey *key = nullptr;
    HcfCipher *cipher = nullptr;
    ASSERT_EQ(SymAlgConvertSymKey("RC2", keyMaterial, sizeof(keyMaterial), &key), 0);
    ASSERT_EQ(HcfCipherCreate("RC2|CBC|PKCS7", &cipher), HCF_SUCCESS);
    HcfParamsSpec *params = (HcfParamsSpec *)&ivSpec;

    ASSERT_EQ(cipher->init(cipher, ENCRYPT_MODE, (HcfKey *)key, params), HCF_SUCCESS);
    EXPECT_EQ(cipher->doFinal(cipher, &plainBlob, &outBlob), HCF_ERR_PARAMETER_CHECK_FAILED);

    if (outBlob.data != nullptr) {
        HcfBlobDataFree(&outBlob);
    }
    HcfObjDestroy(cipher);
    HcfObjDestroy(key);
}

HWTEST_F(CryptoRc2CipherTest, CryptoRc2CipherTest031, TestSize.Level0)
{
    uint8_t keyMaterial[8] = {0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08};
    HcfSymKey *key = nullptr;
    HcfCipher *cipher = nullptr;
    int ret = SymAlgConvertSymKey("RC2", keyMaterial, sizeof(keyMaterial), &key);
    ASSERT_EQ(ret, 0);
    ret = HcfCipherCreate("RC2|CBC|PKCS7", &cipher);
    ASSERT_EQ(ret, 0);

    EXPECT_CALL(*mock_, HcfIsClassMatch(_, _))
        .WillOnce(Return(true))
        .WillOnce(Return(false))
        .WillRepeatedly(Invoke(__real_HcfIsClassMatch));
    HcfResult res = cipher->init(cipher, ENCRYPT_MODE, (HcfKey *)key, nullptr);
    EXPECT_EQ(res, HCF_ERR_PARAMETER_CHECK_FAILED);

    HcfObjDestroy((HcfObjectBase *)cipher);
    HcfObjDestroy((HcfObjectBase *)key);
}

HWTEST_F(CryptoRc2CipherTest, CryptoRc2CipherTest032, TestSize.Level0)
{
    uint8_t keyMaterial[8] = {0};
    uint8_t iv[8] = {0};
    uint8_t plaintext[16] = {0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0, 0, 0, 0, 0, 0, 0, 0};
    HcfIvParamsSpec ivSpec = {};
    ivSpec.iv.data = iv;
    ivSpec.iv.len = sizeof(iv);
    HcfBlob plainBlob = {.data = plaintext, .len = sizeof(plaintext)};
    HcfBlob outBlob = {};
    HcfSymKey *key = nullptr;
    HcfCipher *cipher = nullptr;
    ASSERT_EQ(SymAlgConvertSymKey("RC2", keyMaterial, sizeof(keyMaterial), &key), 0);
    ASSERT_EQ(HcfCipherCreate("RC2|CBC|PKCS7", &cipher), HCF_SUCCESS);
    HcfParamsSpec *params = (HcfParamsSpec *)&ivSpec;
    ASSERT_EQ(cipher->init(cipher, ENCRYPT_MODE, (HcfKey *)key, params), HCF_SUCCESS);

    EXPECT_CALL(*mock_, HcfIsClassMatch(_, _))
        .WillOnce(Return(true))
        .WillOnce(Return(false))
        .WillRepeatedly(Invoke(__real_HcfIsClassMatch));
    EXPECT_EQ(cipher->update(cipher, &plainBlob, &outBlob), HCF_ERR_PARAMETER_CHECK_FAILED);

    if (outBlob.data != nullptr) {
        HcfBlobDataFree(&outBlob);
    }
    HcfObjDestroy(cipher);
    HcfObjDestroy(key);
}

HWTEST_F(CryptoRc2CipherTest, CryptoRc2CipherTest033, TestSize.Level0)
{
    uint8_t keyMaterial[8] = {0};
    uint8_t iv[8] = {0};
    uint8_t plaintext[16] = {0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0, 0, 0, 0, 0, 0, 0, 0};
    HcfIvParamsSpec ivSpec = {};
    ivSpec.iv.data = iv;
    ivSpec.iv.len = sizeof(iv);
    HcfBlob plainBlob = {.data = plaintext, .len = sizeof(plaintext)};
    HcfBlob outBlob = {};
    HcfSymKey *key = nullptr;
    HcfCipher *cipher = nullptr;
    ASSERT_EQ(SymAlgConvertSymKey("RC2", keyMaterial, sizeof(keyMaterial), &key), 0);
    ASSERT_EQ(HcfCipherCreate("RC2|CBC|PKCS7", &cipher), HCF_SUCCESS);
    HcfParamsSpec *params = (HcfParamsSpec *)&ivSpec;
    ASSERT_EQ(cipher->init(cipher, ENCRYPT_MODE, (HcfKey *)key, params), HCF_SUCCESS);

    EXPECT_CALL(*mock_, HcfIsClassMatch(_, _))
        .WillOnce(Return(true))
        .WillOnce(Return(false))
        .WillRepeatedly(Invoke(__real_HcfIsClassMatch));
    EXPECT_EQ(cipher->doFinal(cipher, &plainBlob, &outBlob), HCF_ERR_PARAMETER_CHECK_FAILED);

    if (outBlob.data != nullptr) {
        HcfBlobDataFree(&outBlob);
    }
    HcfObjDestroy(cipher);
    HcfObjDestroy(key);
}

HWTEST_F(CryptoRc2CipherTest, CryptoRc2CipherTest034, TestSize.Level0)
{
    uint8_t keyMaterial[8] = {0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08};
    HcfSymKey *key = nullptr;
    HcfCipher *cipher = nullptr;
    int ret = SymAlgConvertSymKey("RC2", keyMaterial, sizeof(keyMaterial), &key);
    ASSERT_EQ(ret, 0);
    ret = HcfCipherCreate("RC2|CBC|PKCS7", &cipher);
    ASSERT_EQ(ret, 0);

    EXPECT_CALL(*mock_, HcfIsClassMatch(_, _))
        .WillOnce(Invoke(__real_HcfIsClassMatch))
        .WillOnce(Return(false))
        .WillRepeatedly(Invoke(__real_HcfIsClassMatch));
    HcfResult res = cipher->init(cipher, ENCRYPT_MODE, (HcfKey *)key, nullptr);
    EXPECT_EQ(res, HCF_ERR_PARAMETER_CHECK_FAILED);

    HcfObjDestroy((HcfObjectBase *)cipher);
    HcfObjDestroy((HcfObjectBase *)key);
}

HWTEST_F(CryptoRc2CipherTest, CryptoRc2CipherTest035, TestSize.Level0)
{
    HcfSymKey *key = nullptr;
    HcfSymKeyGenerator *keyGenerator = nullptr;
    HcfResult ret = HcfSymKeyGeneratorCreate("RC2", &keyGenerator);
    ASSERT_EQ(ret, HCF_SUCCESS);
    ret = keyGenerator->generateSymKey(keyGenerator, &key);
    ASSERT_NE(ret, HCF_SUCCESS);
    HcfObjDestroy(keyGenerator);
    HcfObjDestroy(key);
}

}
  