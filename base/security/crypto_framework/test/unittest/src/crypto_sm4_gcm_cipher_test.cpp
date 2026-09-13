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

#include "sm4_common.h"
#include "sm4_openssl.h"
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
class CryptoSM4GcmCipherTest : public testing::Test {
public:
    static void SetUpTestCase() {};
    static void TearDownTestCase() {};
    void SetUp() {};
    void TearDown() {};
};

HWTEST_F(CryptoSM4GcmCipherTest, CryptoSM4GcmCipherTest001, TestSize.Level0)
{
    int ret = 0;
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

    ret = GenerateSymKey("SM4_128", &key);
    ASSERT_EQ(ret, 0);

    ret = HcfCipherCreate("SM4_128|GCM|NoPadding", &cipher);
    ASSERT_EQ(ret, 0);

    ret = Sm4Encrypt(cipher, key, (HcfParamsSpec *)&spec, cipherText, &cipherTextLen);
    ASSERT_EQ(ret, 0);

    (void)memcpy_s(spec.tag.data, 16, cipherText + cipherTextLen - 16, 16);
    cipherTextLen -= 16;

    ret = Sm4Decrypt(cipher, key, (HcfParamsSpec *)&spec, cipherText, cipherTextLen);
    ASSERT_EQ(ret, 0);

    HcfObjDestroy((HcfObjectBase *)key);
    HcfObjDestroy((HcfObjectBase *)cipher);
}

HWTEST_F(CryptoSM4GcmCipherTest, CryptoSM4GcmCipherTest002, TestSize.Level0)
{
    int ret = 0;
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

    ret = GenerateSymKey("SM4_128", &key);
    ASSERT_EQ(ret, 0);

    ret = HcfCipherCreate("SM4_128|GCM|PKCS5", &cipher);
    ASSERT_EQ(ret, 0);

    ret = Sm4Encrypt(cipher, key, (HcfParamsSpec *)&spec, cipherText, &cipherTextLen);
    ASSERT_EQ(ret, 0);

    (void)memcpy_s(spec.tag.data, 16, cipherText + cipherTextLen - 16, 16);
    cipherTextLen -= 16;

    ret = Sm4Decrypt(cipher, key, (HcfParamsSpec *)&spec, cipherText, cipherTextLen);
    ASSERT_EQ(ret, 0);

    HcfObjDestroy((HcfObjectBase *)key);
    HcfObjDestroy((HcfObjectBase *)cipher);
}

HWTEST_F(CryptoSM4GcmCipherTest, CryptoSM4GcmCipherTest003, TestSize.Level0)
{
    int ret = 0;
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

    ret = GenerateSymKey("SM4_128", &key);
    ASSERT_EQ(ret, 0);

    ret = HcfCipherCreate("SM4_128|GCM|PKCS7", &cipher);
    ASSERT_EQ(ret, 0);

    ret = Sm4Encrypt(cipher, key, (HcfParamsSpec *)&spec, cipherText, &cipherTextLen);
    ASSERT_EQ(ret, 0);

    (void)memcpy_s(spec.tag.data, 16, cipherText + cipherTextLen - 16, 16);
    cipherTextLen -= 16;

    ret = Sm4Decrypt(cipher, key, (HcfParamsSpec *)&spec, cipherText, cipherTextLen);
    ASSERT_EQ(ret, 0);

    HcfObjDestroy((HcfObjectBase *)key);
    HcfObjDestroy((HcfObjectBase *)cipher);
}

HWTEST_F(CryptoSM4GcmCipherTest, CryptoSM4GcmCipherTest004, TestSize.Level0)
{
    int ret = 0;
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

    ret = GenerateSymKey("SM4_128", &key);
    ASSERT_EQ(ret, 0);

    ret = HcfCipherCreate("SM4_128|GCM|NoPadding", &cipher);
    ASSERT_EQ(ret, 0);

    ret = Sm4NoUpdateEncrypt(cipher, key, (HcfParamsSpec *)&spec, cipherText, &cipherTextLen);
    ASSERT_EQ(ret, 0);

    (void)memcpy_s(spec.tag.data, 16, cipherText + cipherTextLen - 16, 16);
    cipherTextLen -= 16;

    ret = Sm4NoUpdateDecrypt(cipher, key, (HcfParamsSpec *)&spec, cipherText, cipherTextLen);
    ASSERT_EQ(ret, 0);

    HcfObjDestroy((HcfObjectBase *)key);
    HcfObjDestroy((HcfObjectBase *)cipher);
}

HWTEST_F(CryptoSM4GcmCipherTest, CryptoSM4GcmCipherTest005, TestSize.Level0)
{
    int ret = 0;
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

    ret = GenerateSymKey("SM4_128", &key);
    ASSERT_EQ(ret, 0);

    ret = HcfCipherCreate("SM4_128|GCM|PKCS5", &cipher);
    ASSERT_EQ(ret, 0);

    ret = Sm4NoUpdateEncrypt(cipher, key, (HcfParamsSpec *)&spec, cipherText, &cipherTextLen);
    ASSERT_EQ(ret, 0);

    (void)memcpy_s(spec.tag.data, 16, cipherText + cipherTextLen - 16, 16);
    cipherTextLen -= 16;

    ret = Sm4NoUpdateDecrypt(cipher, key, (HcfParamsSpec *)&spec, cipherText, cipherTextLen);
    ASSERT_EQ(ret, 0);

    HcfObjDestroy((HcfObjectBase *)key);
    HcfObjDestroy((HcfObjectBase *)cipher);
}

HWTEST_F(CryptoSM4GcmCipherTest, CryptoSM4GcmCipherTest006, TestSize.Level0)
{
    int ret = 0;
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

    ret = GenerateSymKey("SM4_128", &key);
    ASSERT_EQ(ret, 0);

    ret = HcfCipherCreate("SM4_128|GCM|PKCS7", &cipher);
    ASSERT_EQ(ret, 0);

    ret = Sm4NoUpdateEncrypt(cipher, key, (HcfParamsSpec *)&spec, cipherText, &cipherTextLen);
    ASSERT_EQ(ret, 0);

    (void)memcpy_s(spec.tag.data, 16, cipherText + cipherTextLen - 16, 16);
    cipherTextLen -= 16;

    ret = Sm4NoUpdateDecrypt(cipher, key, (HcfParamsSpec *)&spec, cipherText, cipherTextLen);
    ASSERT_EQ(ret, 0);

    HcfObjDestroy((HcfObjectBase *)key);
    HcfObjDestroy((HcfObjectBase *)cipher);
}

HWTEST_F(CryptoSM4GcmCipherTest, CryptoSM4GcmCipherTest009, TestSize.Level0)
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

HWTEST_F(CryptoSM4GcmCipherTest, CryptoSM4GcmCipherTest010, TestSize.Level0)
{
    int ret = 0;
    HcfCipher *cipher = nullptr;

    // not allow '|' without content, because findAbility will fail for "" input
    ret = HcfCipherCreate("SM4_128|GCM|", &cipher);
    if (ret != 0) {
        LOGE("HcfCipherCreate failed! Should select padding mode for SM4_128 generator.");
    }

    HcfObjDestroy(cipher);
    EXPECT_NE(ret, 0);
}

HWTEST_F(CryptoSM4GcmCipherTest, CryptoSM4GcmCipherTest011, TestSize.Level0)
{
    int ret = 0;
    uint8_t cipherText[CIPHER_TEXT_LEN] = { 0 };
    int cipherTextLen = CIPHER_TEXT_LEN;
    HcfCipher *cipher = nullptr;
    HcfSymKey *key = nullptr;

    ret = GenerateSymKey("SM4_128", &key);
    ASSERT_EQ(ret, 0);

    // CBC, CTR, OFB, CFB enc/dec success,
    // GCM, CCM enc/dec failed with params set to nullptr.
    ret = HcfCipherCreate("SM4_128|GCM|PKCS5", &cipher);
    ASSERT_EQ(ret, 0);

    ret = Sm4Encrypt(cipher, key, nullptr, cipherText, &cipherTextLen);
    ASSERT_NE(ret, 0);

    ret = Sm4Decrypt(cipher, key, nullptr, cipherText, cipherTextLen);
    ASSERT_NE(ret, 0);

    HcfObjDestroy(key);
    HcfObjDestroy(cipher);
}

HWTEST_F(CryptoSM4GcmCipherTest, CryptoSM4GcmCipherTest012, TestSize.Level0)
{
    int ret = 0;
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

    ret = GenerateSymKey("SM4_128", &key);
    ASSERT_EQ(ret, 0);

    ret = HcfCipherCreate("SM4_128|GCM|NoPadding", &cipher);
    ASSERT_EQ(ret, 0);

    ret = Sm4Encrypt(cipher, key, &(spec.base), cipherText, &cipherTextLen);
    ASSERT_EQ(ret, 0);

    HcfObjDestroy(key);
    HcfObjDestroy(cipher);
}

HWTEST_F(CryptoSM4GcmCipherTest, CryptoSM4GcmCipherTest013, TestSize.Level0)
{
    int ret = 0;
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

    ret = GenerateSymKey("SM4_128", &key);
    ASSERT_EQ(ret, 0);

    ret = HcfCipherCreate("SM4_128|GCM|NoPadding", &cipher);
    ASSERT_EQ(ret, 0);

    ret = Sm4Encrypt(cipher, key, &(spec.base), cipherText, &cipherTextLen);
    ASSERT_NE(ret, 0);

    HcfObjDestroy(key);
    HcfObjDestroy(cipher);
}

HWTEST_F(CryptoSM4GcmCipherTest, CryptoSM4GcmCipherTest014, TestSize.Level0)
{
    int ret = 0;
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

    ret = GenerateSymKey("SM4_128", &key);
    ASSERT_EQ(ret, 0);

    ret = HcfCipherCreate("SM4_128|GCM|NoPadding", &cipher);
    ASSERT_EQ(ret, 0);

    ret = Sm4Encrypt(cipher, key, &(spec.base), cipherText, &cipherTextLen);
    ASSERT_NE(ret, 0);

    HcfObjDestroy(key);
    HcfObjDestroy(cipher);
}

HWTEST_F(CryptoSM4GcmCipherTest, CryptoSM4GcmCipherTest015, TestSize.Level0)
{
    int ret = 0;
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

    ret = GenerateSymKey("SM4_128", &key);
    ASSERT_EQ(ret, 0);

    ret = HcfCipherCreate("SM4_128|GCM|NoPadding", &cipher);
    ASSERT_EQ(ret, 0);

    ret = Sm4Encrypt(cipher, key, (HcfParamsSpec *)&spec, cipherText, &cipherTextLen);
    ASSERT_EQ(ret, 0);

    (void)memcpy_s(spec.tag.data, GCM_TAG_LEN, cipherText + cipherTextLen - GCM_TAG_LEN, GCM_TAG_LEN);
    cipherTextLen -= GCM_TAG_LEN;

    ret = Sm4Decrypt(cipher, key, (HcfParamsSpec *)&spec, cipherText, cipherTextLen);
    ASSERT_EQ(ret, 0);

    HcfObjDestroy((HcfObjectBase *)key);
    HcfObjDestroy((HcfObjectBase *)cipher);
}

HWTEST_F(CryptoSM4GcmCipherTest, CryptoSM4GcmCipherTest016, TestSize.Level0)
{
    int ret = 0;
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

    ret = GenerateSymKey("SM4_128", &key);
    ASSERT_EQ(ret, 0);

    ret = HcfCipherCreate("SM4_128|GCM|NoPadding", &cipher);
    ASSERT_EQ(ret, 0);

    ret = Sm4Encrypt(cipher, key, (HcfParamsSpec *)&spec, cipherText, &cipherTextLen);
    ASSERT_EQ(ret, 0);

    (void)memcpy_s(spec.tag.data, GCM_TAG_LEN, cipherText + cipherTextLen - GCM_TAG_LEN, GCM_TAG_LEN);
    cipherTextLen -= GCM_TAG_LEN;

    ret = Sm4Decrypt(cipher, key, (HcfParamsSpec *)&spec, cipherText, cipherTextLen);
    ASSERT_EQ(ret, 0);

    HcfObjDestroy((HcfObjectBase *)key);
    HcfObjDestroy((HcfObjectBase *)cipher);
}

HWTEST_F(CryptoSM4GcmCipherTest, CryptoSM4GcmCipherTest017, TestSize.Level0)
{
    int ret = 0;
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

    ret = GenerateSymKey("SM4_128", &key);
    ASSERT_EQ(ret, 0);

    ret = HcfCipherCreate("SM4_128|GCM|NoPadding", &cipher);
    ASSERT_EQ(ret, 0);

    ret = Sm4Encrypt(cipher, key, (HcfParamsSpec *)&spec, cipherText, &cipherTextLen);
    ASSERT_EQ(ret, 0);

    (void)memcpy_s(spec.tag.data, GCM_TAG_LEN, cipherText + cipherTextLen - GCM_TAG_LEN, GCM_TAG_LEN);
    cipherTextLen -= GCM_TAG_LEN;

    ret = Sm4Decrypt(cipher, key, (HcfParamsSpec *)&spec, cipherText, cipherTextLen);
    ASSERT_EQ(ret, 0);

    HcfObjDestroy((HcfObjectBase *)key);
    HcfObjDestroy((HcfObjectBase *)cipher);
}

HWTEST_F(CryptoSM4GcmCipherTest, CryptoSM4GcmCipherTest018, TestSize.Level0)
{
    int ret = 0;
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

    ret = GenerateSymKey("SM4_128", &key);
    ASSERT_EQ(ret, 0);

    ret = HcfCipherCreate("SM4_128|GCM|NoPadding", &cipher);
    ASSERT_EQ(ret, 0);

    ret = Sm4Encrypt(cipher, key, (HcfParamsSpec *)&spec, cipherText, &cipherTextLen);
    ASSERT_EQ(ret, 0);

    (void)memcpy_s(spec.tag.data, GCM_TAG_LEN, cipherText + cipherTextLen - GCM_TAG_LEN, GCM_TAG_LEN);
    cipherTextLen -= GCM_TAG_LEN;

    ret = Sm4Decrypt(cipher, key, (HcfParamsSpec *)&spec, cipherText, cipherTextLen);
    ASSERT_EQ(ret, 0);

    HcfObjDestroy((HcfObjectBase *)key);
    HcfObjDestroy((HcfObjectBase *)cipher);
}

HWTEST_F(CryptoSM4GcmCipherTest, CryptoSM4GcmCipherTest019, TestSize.Level0)
{
    int ret = 0;
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

    ret = GenerateSymKey("SM4_128", &key);
    ASSERT_EQ(ret, 0);

    ret = HcfCipherCreate("SM4_128|GCM|NoPadding", &cipher);
    ASSERT_EQ(ret, 0);

    ret = Sm4Encrypt(cipher, key, (HcfParamsSpec *)&spec, cipherText, &cipherTextLen);
    ASSERT_EQ(ret, 0);

    (void)memcpy_s(spec.tag.data, GCM_TAG_LEN, cipherText + cipherTextLen - GCM_TAG_LEN, GCM_TAG_LEN);
    cipherTextLen -= GCM_TAG_LEN;

    ret = Sm4Decrypt(cipher, key, (HcfParamsSpec *)&spec, cipherText, cipherTextLen);
    ASSERT_EQ(ret, 0);

    HcfObjDestroy((HcfObjectBase *)key);
    HcfObjDestroy((HcfObjectBase *)cipher);
}

HWTEST_F(CryptoSM4GcmCipherTest, CryptoSM4GcmCipherTest020, TestSize.Level0)
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

    ret = GenerateSymKey("SM4_128", &key);
    ASSERT_EQ(ret, 0);

    ret = HcfCipherCreate("SM4_128|GCM|NoPadding", &cipher);
    ASSERT_EQ(ret, 0);

    ret = Sm4Encrypt(cipher, key, (HcfParamsSpec *)&spec, cipherText, &cipherTextLen);
    ASSERT_EQ(ret, 0);

    (void)memcpy_s(spec.tag.data, 16, cipherText + cipherTextLen - 16, 16);
    cipherTextLen -= 16;

    ret = Sm4Decrypt(cipher, key, (HcfParamsSpec *)&spec, cipherText, cipherTextLen);
    ASSERT_EQ(ret, 0);

    HcfObjDestroy((HcfObjectBase *)key);
    HcfObjDestroy((HcfObjectBase *)cipher);
}

HWTEST_F(CryptoSM4GcmCipherTest, CryptoSM4GcmCipherTest021, TestSize.Level0)
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

    ret = GenerateSymKey("SM4_128", &key);
    ASSERT_EQ(ret, 0);

    ret = HcfCipherCreate("SM4_128|GCM|NoPadding", &cipher);
    ASSERT_EQ(ret, 0);

    ret = Sm4Encrypt(cipher, key, (HcfParamsSpec *)&spec, cipherText, &cipherTextLen);
    ASSERT_NE(ret, 0);

    (void)memcpy_s(spec.tag.data, 16, cipherText + cipherTextLen - 16, 16);
    cipherTextLen -= 16;

    ret = Sm4Decrypt(cipher, key, (HcfParamsSpec *)&spec, cipherText, cipherTextLen);
    ASSERT_NE(ret, 0);

    HcfObjDestroy((HcfObjectBase *)key);
    HcfObjDestroy((HcfObjectBase *)cipher);
}
}