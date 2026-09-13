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
#include <fstream>
#include <iostream>
#include "securec.h"

#include "aes_common.h"
#include "aes_openssl.h"
#include "blob.h"
#include "cipher.h"
#include "detailed_iv_params.h"
#include "detailed_gcm_params.h"
#include "detailed_ccm_params.h"
#include "log.h"
#include "memory.h"
#include "sym_common_defines.h"
#include "sym_key_generator.h"

using namespace std;
using namespace testing::ext;

namespace {
class CryptoAesGcmCipherTest : public testing::Test {
public:
    static void SetUpTestCase() {};
    static void TearDownTestCase() {};
    void SetUp() {};
    void TearDown() {};
};

HWTEST_F(CryptoAesGcmCipherTest, CryptoAesGcmCipherTest001, TestSize.Level0)
{
    uint8_t aad[8] = {0};
    uint8_t tag[16] = {0};
    uint8_t iv[12] = {0}; // openssl only support nonce 12 bytes, tag 16bytes
    uint8_t cipherText[128] = {0};
    int cipherTextLen = 128;

    HcfCipher *cipher = nullptr;
    HcfSymKey *key = nullptr;

    HcfGcmParamsSpec spec = {};
    spec.aad.data = aad;
    spec.aad.len = sizeof(aad);
    spec.tag.data = tag;
    spec.tag.len = sizeof(tag);
    spec.iv.data = iv;
    spec.iv.len = sizeof(iv);

    int ret = GenerateSymKey("AES128", &key);
    ASSERT_EQ(ret, 0);

    ret = HcfCipherCreate("AES128|GCM|NoPadding", &cipher);
    ASSERT_EQ(ret, 0);

    ret = AesEncrypt(cipher, key, (HcfParamsSpec *)&spec, cipherText, &cipherTextLen);
    ASSERT_EQ(ret, 0);

    (void)memcpy_s(spec.tag.data, 16, cipherText + cipherTextLen - 16, 16);
    cipherTextLen -= 16;

    ret = AesDecrypt(cipher, key, (HcfParamsSpec *)&spec, cipherText, cipherTextLen);
    ASSERT_EQ(ret, 0);

    HcfObjDestroy((HcfObjectBase *)key);
    HcfObjDestroy((HcfObjectBase *)cipher);
}

HWTEST_F(CryptoAesGcmCipherTest, CryptoAesGcmCipherTest002, TestSize.Level0)
{
    uint8_t aad[8] = {0};
    uint8_t tag[16] = {0};
    uint8_t iv[12] = {0}; // openssl only support nonce 12 bytes, tag 16bytes
    uint8_t cipherText[128] = {0};
    int cipherTextLen = 128;

    HcfCipher *cipher = nullptr;
    HcfSymKey *key = nullptr;

    HcfGcmParamsSpec spec = {};
    spec.aad.data = aad;
    spec.aad.len = sizeof(aad);
    spec.tag.data = tag;
    spec.tag.len = sizeof(tag);
    spec.iv.data = iv;
    spec.iv.len = sizeof(iv);

    int ret = GenerateSymKey("AES128", &key);
    ASSERT_EQ(ret, 0);

    ret = HcfCipherCreate("AES128|GCM|PKCS5", &cipher);
    ASSERT_EQ(ret, 0);

    ret = AesEncrypt(cipher, key, (HcfParamsSpec *)&spec, cipherText, &cipherTextLen);
    ASSERT_EQ(ret, 0);

    (void)memcpy_s(spec.tag.data, 16, cipherText + cipherTextLen - 16, 16);
    cipherTextLen -= 16;

    ret = AesDecrypt(cipher, key, (HcfParamsSpec *)&spec, cipherText, cipherTextLen);
    ASSERT_EQ(ret, 0);

    HcfObjDestroy((HcfObjectBase *)key);
    HcfObjDestroy((HcfObjectBase *)cipher);
}

HWTEST_F(CryptoAesGcmCipherTest, CryptoAesGcmCipherTest003, TestSize.Level0)
{
    uint8_t aad[8] = {0};
    uint8_t tag[16] = {0};
    uint8_t iv[12] = {0}; // openssl only support nonce 12 bytes, tag 16bytes
    uint8_t cipherText[128] = {0};
    int cipherTextLen = 128;

    HcfCipher *cipher = nullptr;
    HcfSymKey *key = nullptr;

    HcfGcmParamsSpec spec = {};
    spec.aad.data = aad;
    spec.aad.len = sizeof(aad);
    spec.tag.data = tag;
    spec.tag.len = sizeof(tag);
    spec.iv.data = iv;
    spec.iv.len = sizeof(iv);

    int ret = GenerateSymKey("AES128", &key);
    ASSERT_EQ(ret, 0);

    ret = HcfCipherCreate("AES128|GCM|PKCS7", &cipher);
    ASSERT_EQ(ret, 0);

    ret = AesEncrypt(cipher, key, (HcfParamsSpec *)&spec, cipherText, &cipherTextLen);
    ASSERT_EQ(ret, 0);

    (void)memcpy_s(spec.tag.data, 16, cipherText + cipherTextLen - 16, 16);
    cipherTextLen -= 16;

    ret = AesDecrypt(cipher, key, (HcfParamsSpec *)&spec, cipherText, cipherTextLen);
    ASSERT_EQ(ret, 0);

    HcfObjDestroy((HcfObjectBase *)key);
    HcfObjDestroy((HcfObjectBase *)cipher);
}

HWTEST_F(CryptoAesGcmCipherTest, CryptoAesGcmCipherTest004, TestSize.Level0)
{
    uint8_t aad[8] = {0};
    uint8_t tag[16] = {0};
    uint8_t iv[12] = {0}; // openssl only support nonce 12 bytes, tag 16bytes
    uint8_t cipherText[128] = {0};
    int cipherTextLen = 128;

    HcfCipher *cipher = nullptr;
    HcfSymKey *key = nullptr;

    HcfGcmParamsSpec spec = {};
    spec.aad.data = aad;
    spec.aad.len = sizeof(aad);
    spec.tag.data = tag;
    spec.tag.len = sizeof(tag);
    spec.iv.data = iv;
    spec.iv.len = sizeof(iv);

    int ret = GenerateSymKey("AES128", &key);
    ASSERT_EQ(ret, 0);

    ret = HcfCipherCreate("AES128|GCM|NoPadding", &cipher);
    ASSERT_EQ(ret, 0);

    ret = AesNoUpdateEncrypt(cipher, key, (HcfParamsSpec *)&spec, cipherText, &cipherTextLen);
    ASSERT_EQ(ret, 0);

    (void)memcpy_s(spec.tag.data, 16, cipherText + cipherTextLen - 16, 16);
    cipherTextLen -= 16;

    ret = AesNoUpdateDecrypt(cipher, key, (HcfParamsSpec *)&spec, cipherText, cipherTextLen);
    ASSERT_EQ(ret, 0);

    HcfObjDestroy((HcfObjectBase *)key);
    HcfObjDestroy((HcfObjectBase *)cipher);
}

HWTEST_F(CryptoAesGcmCipherTest, CryptoAesGcmCipherTest005, TestSize.Level0)
{
    uint8_t aad[8] = {0};
    uint8_t tag[16] = {0};
    uint8_t iv[12] = {0}; // openssl only support nonce 12 bytes, tag 16bytes
    uint8_t cipherText[128] = {0};
    int cipherTextLen = 128;

    HcfCipher *cipher = nullptr;
    HcfSymKey *key = nullptr;

    HcfGcmParamsSpec spec = {};
    spec.aad.data = aad;
    spec.aad.len = sizeof(aad);
    spec.tag.data = tag;
    spec.tag.len = sizeof(tag);
    spec.iv.data = iv;
    spec.iv.len = sizeof(iv);

    int ret = GenerateSymKey("AES128", &key);
    ASSERT_EQ(ret, 0);

    ret = HcfCipherCreate("AES128|GCM|PKCS5", &cipher);
    ASSERT_EQ(ret, 0);

    ret = AesNoUpdateEncrypt(cipher, key, (HcfParamsSpec *)&spec, cipherText, &cipherTextLen);
    ASSERT_EQ(ret, 0);

    (void)memcpy_s(spec.tag.data, 16, cipherText + cipherTextLen - 16, 16);
    cipherTextLen -= 16;

    ret = AesNoUpdateDecrypt(cipher, key, (HcfParamsSpec *)&spec, cipherText, cipherTextLen);
    ASSERT_EQ(ret, 0);

    HcfObjDestroy((HcfObjectBase *)key);
    HcfObjDestroy((HcfObjectBase *)cipher);
}

HWTEST_F(CryptoAesGcmCipherTest, CryptoAesGcmCipherTest006, TestSize.Level0)
{
    uint8_t aad[8] = {0};
    uint8_t tag[16] = {0};
    uint8_t iv[12] = {0}; // openssl only support nonce 12 bytes, tag 16bytes
    uint8_t cipherText[128] = {0};
    int cipherTextLen = 128;

    HcfCipher *cipher = nullptr;
    HcfSymKey *key = nullptr;

    HcfGcmParamsSpec spec = {};
    spec.aad.data = aad;
    spec.aad.len = sizeof(aad);
    spec.tag.data = tag;
    spec.tag.len = sizeof(tag);
    spec.iv.data = iv;
    spec.iv.len = sizeof(iv);

    int ret = GenerateSymKey("AES128", &key);
    ASSERT_EQ(ret, 0);

    ret = HcfCipherCreate("AES128|GCM|PKCS7", &cipher);
    ASSERT_EQ(ret, 0);

    ret = AesNoUpdateEncrypt(cipher, key, (HcfParamsSpec *)&spec, cipherText, &cipherTextLen);
    ASSERT_EQ(ret, 0);

    (void)memcpy_s(spec.tag.data, 16, cipherText + cipherTextLen - 16, 16);
    cipherTextLen -= 16;

    ret = AesNoUpdateDecrypt(cipher, key, (HcfParamsSpec *)&spec, cipherText, cipherTextLen);
    ASSERT_EQ(ret, 0);

    HcfObjDestroy((HcfObjectBase *)key);
    HcfObjDestroy((HcfObjectBase *)cipher);
}

HWTEST_F(CryptoAesGcmCipherTest, CryptoAesGcmCipherTest007, TestSize.Level0)
{
    uint8_t aad[GCM_AAD_LEN] = { 0 };
    uint8_t tag[GCM_TAG_LEN] = { 0 };
    uint8_t iv[GCM_IV_LEN] = { 0 }; // openssl only support nonce 12 bytes, tag 16 bytes
    uint8_t cipherText[CIPHER_TEXT_LEN] = { 0 };
    int cipherTextLen = CIPHER_TEXT_LEN;

    HcfCipher *cipher = nullptr;
    HcfSymKey *key = nullptr;

    HcfGcmParamsSpec spec = {};
    spec.aad.data = aad;
    spec.aad.len = sizeof(aad);
    spec.tag.data = tag;
    spec.tag.len = sizeof(tag);
    spec.iv.data = iv;
    spec.iv.len = sizeof(iv);

    int ret = GenerateSymKey("AES192", &key);
    ASSERT_EQ(ret, 0);

    ret = HcfCipherCreate("AES192|GCM|PKCS5", &cipher);
    ASSERT_EQ(ret, 0);

    ret = AesEncrypt(cipher, key, &(spec.base), cipherText, &cipherTextLen);
    ASSERT_EQ(ret, 0);

    (void)memcpy_s(spec.tag.data, GCM_TAG_LEN, cipherText + cipherTextLen - GCM_TAG_LEN, GCM_TAG_LEN);
    cipherTextLen -= GCM_TAG_LEN;

    ret = AesDecrypt(cipher, key, &(spec.base), cipherText, cipherTextLen);
    ASSERT_EQ(ret, 0);

    HcfObjDestroy(key);
    HcfObjDestroy(cipher);
}

HWTEST_F(CryptoAesGcmCipherTest, CryptoAesGcmCipherTest008, TestSize.Level0)
{
    uint8_t aad[GCM_AAD_LEN] = { 0 };
    uint8_t tag[GCM_TAG_LEN] = { 0 };
    uint8_t iv[GCM_IV_LEN] = { 0 }; // openssl only support nonce 12 bytes, tag 16 bytes
    uint8_t cipherText[CIPHER_TEXT_LEN] = { 0 };
    int cipherTextLen = CIPHER_TEXT_LEN;

    HcfCipher *cipher = nullptr;
    HcfSymKey *key = nullptr;

    HcfGcmParamsSpec spec = {};
    spec.aad.data = aad;
    spec.aad.len = sizeof(aad);
    spec.tag.data = tag;
    spec.tag.len = sizeof(tag);
    spec.iv.data = iv;
    spec.iv.len = sizeof(iv);

    int ret = GenerateSymKey("AES256", &key);
    ASSERT_EQ(ret, 0);

    ret = HcfCipherCreate("AES256|GCM|PKCS5", &cipher);
    ASSERT_EQ(ret, 0);

    ret = AesEncrypt(cipher, key, &(spec.base), cipherText, &cipherTextLen);
    ASSERT_EQ(ret, 0);

    (void)memcpy_s(spec.tag.data, GCM_TAG_LEN, cipherText + cipherTextLen - GCM_TAG_LEN, GCM_TAG_LEN);
    cipherTextLen -= GCM_TAG_LEN;

    ret = AesDecrypt(cipher, key, &(spec.base), cipherText, cipherTextLen);
    ASSERT_EQ(ret, 0);

    HcfObjDestroy(key);
    HcfObjDestroy(cipher);
}

HWTEST_F(CryptoAesGcmCipherTest, CryptoAesGcmCipherTest009, TestSize.Level0)
{
    int ret = 0;
    HcfCipher *cipher = nullptr;

    ret = HcfCipherCreate("RSA128|GCM|NoPadding", &cipher);
    if (ret != 0) {
        LOGE("HcfCipherCreate failed! Should not select RSA for GCM generator.");
    }

    HcfObjDestroy(cipher);
    EXPECT_NE(ret, 0);
}

HWTEST_F(CryptoAesGcmCipherTest, CryptoAesGcmCipherTest010, TestSize.Level0)
{
    int ret = 0;
    HcfCipher *cipher = nullptr;

    // not allow '|' without content, because findAbility will fail for "" input
    ret = HcfCipherCreate("AES128|GCM|", &cipher);
    if (ret != 0) {
        LOGE("HcfCipherCreate failed! Should select padding mode for AES generator.");
    }

    HcfObjDestroy(cipher);
    EXPECT_NE(ret, 0);
}

HWTEST_F(CryptoAesGcmCipherTest, CryptoAesGcmCipherTest011, TestSize.Level0)
{
    uint8_t cipherText[CIPHER_TEXT_LEN] = { 0 };
    int cipherTextLen = CIPHER_TEXT_LEN;
    HcfCipher *cipher = nullptr;
    HcfSymKey *key = nullptr;

    int ret = GenerateSymKey("AES128", &key);
    ASSERT_EQ(ret, 0);

    ret = HcfCipherCreate("AES128|GCM|PKCS5", &cipher);
    ASSERT_EQ(ret, 0);

    ret = AesEncrypt(cipher, key, nullptr, cipherText, &cipherTextLen);
    ASSERT_NE(ret, 0);

    ret = AesDecrypt(cipher, key, nullptr, cipherText, cipherTextLen);
    ASSERT_NE(ret, 0);

    HcfObjDestroy(key);
    HcfObjDestroy(cipher);
}

HWTEST_F(CryptoAesGcmCipherTest, CryptoAesGcmCipherTest012, TestSize.Level0)
{
    uint8_t aad[GCM_AAD_LEN] = { 0 };
    uint8_t tag[GCM_TAG_LEN] = { 0 };
    uint8_t iv[GCM_IV_LEN] = { 0 };
    uint8_t cipherText[CIPHER_TEXT_LEN] = { 0 };
    int cipherTextLen = CIPHER_TEXT_LEN;

    HcfCipher *cipher = nullptr;
    HcfSymKey *key = nullptr;

    HcfGcmParamsSpec spec = {};
    spec.aad.data = nullptr;
    spec.aad.len = sizeof(aad);
    spec.tag.data = tag;
    spec.tag.len = sizeof(tag);
    spec.iv.data = iv;
    spec.iv.len = sizeof(iv);

    int ret = GenerateSymKey("AES128", &key);
    ASSERT_EQ(ret, 0);

    ret = HcfCipherCreate("AES128|GCM|NoPadding", &cipher);
    ASSERT_EQ(ret, 0);

    ret = AesEncrypt(cipher, key, &(spec.base), cipherText, &cipherTextLen);
    ASSERT_EQ(ret, 0);

    HcfObjDestroy(key);
    HcfObjDestroy(cipher);
}

HWTEST_F(CryptoAesGcmCipherTest, CryptoAesGcmCipherTest013, TestSize.Level0)
{
    uint8_t aad[GCM_AAD_LEN] = { 0 };
    uint8_t tag[GCM_TAG_LEN] = { 0 };
    uint8_t iv[GCM_IV_LEN] = { 0 };
    uint8_t cipherText[CIPHER_TEXT_LEN] = { 0 };
    int cipherTextLen = CIPHER_TEXT_LEN;

    HcfCipher *cipher = nullptr;
    HcfSymKey *key = nullptr;

    HcfGcmParamsSpec spec = {};
    spec.aad.data = aad;
    spec.aad.len = sizeof(aad);
    spec.tag.data = tag;
    spec.tag.len = sizeof(tag);
    spec.iv.data = nullptr;
    spec.iv.len = sizeof(iv);

    int ret = GenerateSymKey("AES128", &key);
    ASSERT_EQ(ret, 0);

    ret = HcfCipherCreate("AES128|GCM|NoPadding", &cipher);
    ASSERT_EQ(ret, 0);

    ret = AesEncrypt(cipher, key, &(spec.base), cipherText, &cipherTextLen);
    ASSERT_NE(ret, 0);

    HcfObjDestroy(key);
    HcfObjDestroy(cipher);
}

HWTEST_F(CryptoAesGcmCipherTest, CryptoAesGcmCipherTest014, TestSize.Level0)
{
    uint8_t aad[GCM_AAD_LEN] = { 0 };
    uint8_t tag[GCM_TAG_LEN] = { 0 };
    uint8_t iv[GCM_IV_LEN] = { 0 };
    uint8_t cipherText[CIPHER_TEXT_LEN] = { 0 };
    int cipherTextLen = CIPHER_TEXT_LEN;

    HcfCipher *cipher = nullptr;
    HcfSymKey *key = nullptr;

    HcfGcmParamsSpec spec = {};
    spec.aad.data = aad;
    spec.aad.len = sizeof(aad);
    spec.tag.data = nullptr;
    spec.tag.len = sizeof(tag);
    spec.iv.data = iv;
    spec.iv.len = sizeof(iv);

    int ret = GenerateSymKey("AES128", &key);
    ASSERT_EQ(ret, 0);

    ret = HcfCipherCreate("AES128|GCM|NoPadding", &cipher);
    ASSERT_EQ(ret, 0);

    ret = AesEncrypt(cipher, key, &(spec.base), cipherText, &cipherTextLen);
    ASSERT_NE(ret, 0);

    HcfObjDestroy(key);
    HcfObjDestroy(cipher);
}

HWTEST_F(CryptoAesGcmCipherTest, CryptoAesGcmCipherTest015, TestSize.Level0)
{
    uint8_t tag[GCM_TAG_LEN] = {0};
    uint8_t iv[GCM_IV_LEN] = {0};
    uint8_t cipherText[CIPHER_TEXT_LEN] = {0};
    int cipherTextLen = CIPHER_TEXT_LEN;

    HcfCipher *cipher = nullptr;
    HcfSymKey *key = nullptr;

    HcfGcmParamsSpec spec = {};
    spec.aad.data = nullptr;
    spec.aad.len = 0;
    spec.tag.data = tag;
    spec.tag.len = sizeof(tag);
    spec.iv.data = iv;
    spec.iv.len = sizeof(iv);

    int ret = GenerateSymKey("AES128", &key);
    ASSERT_EQ(ret, 0);

    ret = HcfCipherCreate("AES128|GCM|NoPadding", &cipher);
    ASSERT_EQ(ret, 0);

    ret = AesEncrypt(cipher, key, (HcfParamsSpec *)&spec, cipherText, &cipherTextLen);
    ASSERT_EQ(ret, 0);

    (void)memcpy_s(spec.tag.data, GCM_TAG_LEN, cipherText + cipherTextLen - GCM_TAG_LEN, GCM_TAG_LEN);
    cipherTextLen -= GCM_TAG_LEN;

    ret = AesDecrypt(cipher, key, (HcfParamsSpec *)&spec, cipherText, cipherTextLen);
    ASSERT_EQ(ret, 0);

    HcfObjDestroy((HcfObjectBase *)key);
    HcfObjDestroy((HcfObjectBase *)cipher);
}

HWTEST_F(CryptoAesGcmCipherTest, CryptoAesGcmCipherTest016, TestSize.Level0)
{
    uint8_t aad[GCM_AAD_LONG_LEN] = { 0 };
    uint8_t tag[GCM_TAG_LEN] = {0};
    uint8_t iv[GCM_IV_LEN] = {0};
    uint8_t cipherText[CIPHER_TEXT_LEN] = {0};
    int cipherTextLen = CIPHER_TEXT_LEN;

    HcfCipher *cipher = nullptr;
    HcfSymKey *key = nullptr;

    HcfGcmParamsSpec spec = {};
    spec.aad.data = aad;
    spec.aad.len = sizeof(aad);
    spec.tag.data = tag;
    spec.tag.len = sizeof(tag);
    spec.iv.data = iv;
    spec.iv.len = sizeof(iv);

    int ret = GenerateSymKey("AES128", &key);
    ASSERT_EQ(ret, 0);

    ret = HcfCipherCreate("AES128|GCM|NoPadding", &cipher);
    ASSERT_EQ(ret, 0);

    ret = AesEncrypt(cipher, key, (HcfParamsSpec *)&spec, cipherText, &cipherTextLen);
    ASSERT_EQ(ret, 0);

    (void)memcpy_s(spec.tag.data, GCM_TAG_LEN, cipherText + cipherTextLen - GCM_TAG_LEN, GCM_TAG_LEN);
    cipherTextLen -= GCM_TAG_LEN;

    ret = AesDecrypt(cipher, key, (HcfParamsSpec *)&spec, cipherText, cipherTextLen);
    ASSERT_EQ(ret, 0);

    HcfObjDestroy((HcfObjectBase *)key);
    HcfObjDestroy((HcfObjectBase *)cipher);
}

HWTEST_F(CryptoAesGcmCipherTest, CryptoAesGcmCipherTest017, TestSize.Level0)
{
    uint8_t aad[GCM_AAD_LONG_LEN] = { 0 };
    uint8_t tag[GCM_TAG_LEN] = {0};
    uint8_t iv[GCM_IV_LONG_LEN] = {0};
    uint8_t cipherText[CIPHER_TEXT_LEN] = {0};
    int cipherTextLen = CIPHER_TEXT_LEN;

    HcfCipher *cipher = nullptr;
    HcfSymKey *key = nullptr;

    HcfGcmParamsSpec spec = {};
    spec.aad.data = aad;
    spec.aad.len = sizeof(aad);
    spec.tag.data = tag;
    spec.tag.len = sizeof(tag);
    spec.iv.data = iv;
    spec.iv.len = sizeof(iv);

    int ret = GenerateSymKey("AES128", &key);
    ASSERT_EQ(ret, 0);

    ret = HcfCipherCreate("AES128|GCM|NoPadding", &cipher);
    ASSERT_EQ(ret, 0);

    ret = AesEncrypt(cipher, key, (HcfParamsSpec *)&spec, cipherText, &cipherTextLen);
    ASSERT_EQ(ret, 0);

    (void)memcpy_s(spec.tag.data, GCM_TAG_LEN, cipherText + cipherTextLen - GCM_TAG_LEN, GCM_TAG_LEN);
    cipherTextLen -= GCM_TAG_LEN;

    ret = AesDecrypt(cipher, key, (HcfParamsSpec *)&spec, cipherText, cipherTextLen);
    ASSERT_EQ(ret, 0);

    HcfObjDestroy((HcfObjectBase *)key);
    HcfObjDestroy((HcfObjectBase *)cipher);
}

HWTEST_F(CryptoAesGcmCipherTest, CryptoAesGcmCipherTest018, TestSize.Level0)
{
    uint8_t aad[GCM_AAD_SHORT_LEN] = { 0 };
    uint8_t tag[GCM_TAG_LEN] = {0};
    // openssl only support ivLen [9, 16];
    uint8_t iv[GCM_IV_SHORT_LEN] = {0};
    uint8_t cipherText[CIPHER_TEXT_LEN] = {0};
    int cipherTextLen = CIPHER_TEXT_LEN;

    HcfCipher *cipher = nullptr;
    HcfSymKey *key = nullptr;

    HcfGcmParamsSpec spec = {};
    spec.aad.data = aad;
    spec.aad.len = sizeof(aad);
    spec.tag.data = tag;
    spec.tag.len = sizeof(tag);
    spec.iv.data = iv;
    spec.iv.len = sizeof(iv);

    int ret = GenerateSymKey("AES128", &key);
    ASSERT_EQ(ret, 0);

    ret = HcfCipherCreate("AES128|GCM|NoPadding", &cipher);
    ASSERT_EQ(ret, 0);

    ret = AesEncrypt(cipher, key, (HcfParamsSpec *)&spec, cipherText, &cipherTextLen);
    ASSERT_EQ(ret, 0);

    (void)memcpy_s(spec.tag.data, GCM_TAG_LEN, cipherText + cipherTextLen - GCM_TAG_LEN, GCM_TAG_LEN);
    cipherTextLen -= GCM_TAG_LEN;

    ret = AesDecrypt(cipher, key, (HcfParamsSpec *)&spec, cipherText, cipherTextLen);
    ASSERT_EQ(ret, 0);

    HcfObjDestroy((HcfObjectBase *)key);
    HcfObjDestroy((HcfObjectBase *)cipher);
}

HWTEST_F(CryptoAesGcmCipherTest, CryptoAesGcmCipherTest019, TestSize.Level0)
{
    uint8_t tag[GCM_TAG_LEN] = {0};
    uint8_t iv[GCM_IV_LONG_LEN] = {0};
    uint8_t cipherText[CIPHER_TEXT_LEN] = {0};
    int cipherTextLen = CIPHER_TEXT_LEN;

    HcfCipher *cipher = nullptr;
    HcfSymKey *key = nullptr;

    HcfGcmParamsSpec spec = {};
    spec.aad.data = nullptr;
    spec.aad.len = 0;
    spec.tag.data = tag;
    spec.tag.len = sizeof(tag);
    spec.iv.data = iv;
    spec.iv.len = sizeof(iv);

    int ret = GenerateSymKey("AES128", &key);
    ASSERT_EQ(ret, 0);

    ret = HcfCipherCreate("AES128|GCM|NoPadding", &cipher);
    ASSERT_EQ(ret, 0);

    ret = AesEncrypt(cipher, key, (HcfParamsSpec *)&spec, cipherText, &cipherTextLen);
    ASSERT_EQ(ret, 0);

    (void)memcpy_s(spec.tag.data, GCM_TAG_LEN, cipherText + cipherTextLen - GCM_TAG_LEN, GCM_TAG_LEN);
    cipherTextLen -= GCM_TAG_LEN;

    ret = AesDecrypt(cipher, key, (HcfParamsSpec *)&spec, cipherText, cipherTextLen);
    ASSERT_EQ(ret, 0);

    HcfObjDestroy((HcfObjectBase *)key);
    HcfObjDestroy((HcfObjectBase *)cipher);
}

HWTEST_F(CryptoAesGcmCipherTest, CryptoAesGcmCipherTest020, TestSize.Level0)
{
    int ret = 0;
    uint8_t aad[8] = {0};
    uint8_t tag[16] = {0};
    uint8_t iv[128] = {0}; // openssl support iv max 128 bytes
    uint8_t cipherText[128] = {0};
    int cipherTextLen = 128;

    HcfCipher *cipher = nullptr;
    HcfSymKey *key = nullptr;

    HcfGcmParamsSpec spec = {};
    spec.aad.data = aad;
    spec.aad.len = sizeof(aad);
    spec.tag.data = tag;
    spec.tag.len = sizeof(tag);
    spec.iv.data = iv;
    spec.iv.len = sizeof(iv);

    ret = GenerateSymKey("AES128", &key);
    if (ret != 0) {
        LOGE("generateSymKey failed!");
        HcfObjDestroy((HcfObjectBase *)key);
    }

    ret = HcfCipherCreate("AES128|GCM|NoPadding", &cipher);
    if (ret != 0) {
        LOGE("HcfCipherCreate failed!");
        HcfObjDestroy((HcfObjectBase *)key);
        HcfObjDestroy((HcfObjectBase *)cipher);
    }

    ret = AesEncrypt(cipher, key, (HcfParamsSpec *)&spec, cipherText, &cipherTextLen);
    EXPECT_EQ(ret, 0);

    (void)memcpy_s(spec.tag.data, 16, cipherText + cipherTextLen - 16, 16);
    cipherTextLen -= 16;

    ret = AesDecrypt(cipher, key, (HcfParamsSpec *)&spec, cipherText, cipherTextLen);
    EXPECT_EQ(ret, 0);
    HcfObjDestroy((HcfObjectBase *)key);
    HcfObjDestroy((HcfObjectBase *)cipher);
}

HWTEST_F(CryptoAesGcmCipherTest, CryptoAesGcmCipherTest021, TestSize.Level0)
{
    int ret = 0;
    uint8_t aad[8] = {0};
    uint8_t tag[16] = {0};
    uint8_t iv[129] = {0};
    uint8_t cipherText[128] = {0};
    int cipherTextLen = 128;

    HcfCipher *cipher = nullptr;
    HcfSymKey *key = nullptr;

    HcfGcmParamsSpec spec = {};
    spec.aad.data = aad;
    spec.aad.len = sizeof(aad);
    spec.tag.data = tag;
    spec.tag.len = sizeof(tag);
    spec.iv.data = iv;
    spec.iv.len = sizeof(iv);

    ret = GenerateSymKey("AES128", &key);
    if (ret != 0) {
        LOGE("generateSymKey failed!");
        HcfObjDestroy((HcfObjectBase *)key);
    }

    ret = HcfCipherCreate("AES128|GCM|NoPadding", &cipher);
    if (ret != 0) {
        LOGE("HcfCipherCreate failed!");
        HcfObjDestroy((HcfObjectBase *)key);
        HcfObjDestroy((HcfObjectBase *)cipher);
    }

    ret = AesEncrypt(cipher, key, (HcfParamsSpec *)&spec, cipherText, &cipherTextLen);
    EXPECT_NE(ret, 0);

    (void)memcpy_s(spec.tag.data, 16, cipherText + cipherTextLen - 16, 16);
    cipherTextLen -= 16;

    ret = AesDecrypt(cipher, key, (HcfParamsSpec *)&spec, cipherText, cipherTextLen);
    EXPECT_NE(ret, 0);
    HcfObjDestroy((HcfObjectBase *)key);
    HcfObjDestroy((HcfObjectBase *)cipher);
}
}