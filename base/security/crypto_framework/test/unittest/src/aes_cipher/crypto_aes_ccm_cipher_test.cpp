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
#include "memory.h"
#include "sym_common_defines.h"
#include "sym_key_generator.h"

using namespace std;
using namespace testing::ext;

namespace {
class CryptoAesCcmCipherTest : public testing::Test {
public:
    static void SetUpTestCase() {};
    static void TearDownTestCase() {};
    void SetUp() {};
    void TearDown() {};
};

HWTEST_F(CryptoAesCcmCipherTest, CryptoAesCcmCipherTest001, TestSize.Level0)
{
    int ret = 0;
    uint8_t aad[8] = {0};
    uint8_t tag[12] = {0};
    uint8_t iv[7] = {0};
    uint8_t cipherText[128] = {0};
    int cipherTextLen = 128;

    HcfCipher *cipher = nullptr;
    HcfSymKey *key = nullptr;
    HcfCcmParamsSpec spec = {};
    spec.aad.data = aad;
    spec.aad.len = sizeof(aad);
    spec.tag.data = tag;
    spec.tag.len = sizeof(tag);
    spec.iv.data = iv;
    spec.iv.len = sizeof(iv);

    ret = GenerateSymKey("AES128", &key);
    ASSERT_EQ(ret, 0);

    ret = HcfCipherCreate("AES128|CCM|NoPadding", &cipher);
    ASSERT_EQ(ret, 0);

    ret = AesEncrypt(cipher, key, (HcfParamsSpec *)&spec, cipherText, &cipherTextLen);
    ASSERT_EQ(ret, 0);

    (void)memcpy_s(spec.tag.data, 12, cipherText + cipherTextLen - 12, 12);
    cipherTextLen -= 12;

    ret = AesDecrypt(cipher, key, (HcfParamsSpec *)&spec, cipherText, cipherTextLen);
    ASSERT_EQ(ret, 0);

    HcfObjDestroy((HcfObjectBase *)key);
    HcfObjDestroy((HcfObjectBase *)cipher);
}

HWTEST_F(CryptoAesCcmCipherTest, CryptoAesCcmCipherTest002, TestSize.Level0)
{
    int ret = 0;
    uint8_t aad[8] = {0};
    uint8_t tag[12] = {0};
    uint8_t iv[7] = {0};
    uint8_t cipherText[128] = {0};
    int cipherTextLen = 128;

    HcfCipher *cipher = nullptr;
    HcfSymKey *key = nullptr;
    HcfCcmParamsSpec spec = {};
    spec.aad.data = aad;
    spec.aad.len = sizeof(aad);
    spec.tag.data = tag;
    spec.tag.len = sizeof(tag);
    spec.iv.data = iv;
    spec.iv.len = sizeof(iv);

    ret = GenerateSymKey("AES128", &key);
    ASSERT_EQ(ret, 0);

    ret = HcfCipherCreate("AES128|CCM|PKCS5", &cipher);
    ASSERT_EQ(ret, 0);

    ret = AesEncrypt(cipher, key, (HcfParamsSpec *)&spec, cipherText, &cipherTextLen);
    ASSERT_EQ(ret, 0);

    (void)memcpy_s(spec.tag.data, 12, cipherText + cipherTextLen - 12, 12);
    cipherTextLen -= 12;

    ret = AesDecrypt(cipher, key, (HcfParamsSpec *)&spec, cipherText, cipherTextLen);
    ASSERT_EQ(ret, 0);

    HcfObjDestroy((HcfObjectBase *)key);
    HcfObjDestroy((HcfObjectBase *)cipher);
}

HWTEST_F(CryptoAesCcmCipherTest, CryptoAesCcmCipherTest003, TestSize.Level0)
{
    int ret = 0;
    uint8_t aad[8] = {0};
    uint8_t tag[12] = {0};
    uint8_t iv[7] = {0};
    uint8_t cipherText[128] = {0};
    int cipherTextLen = 128;

    HcfCipher *cipher = nullptr;
    HcfSymKey *key = nullptr;
    HcfCcmParamsSpec spec = {};
    spec.aad.data = aad;
    spec.aad.len = sizeof(aad);
    spec.tag.data = tag;
    spec.tag.len = sizeof(tag);
    spec.iv.data = iv;
    spec.iv.len = sizeof(iv);

    ret = GenerateSymKey("AES128", &key);
    ASSERT_EQ(ret, 0);

    ret = HcfCipherCreate("AES128|CCM|PKCS7", &cipher);
    ASSERT_EQ(ret, 0);

    ret = AesEncrypt(cipher, key, (HcfParamsSpec *)&spec, cipherText, &cipherTextLen);
    ASSERT_EQ(ret, 0);

    (void)memcpy_s(spec.tag.data, 12, cipherText + cipherTextLen - 12, 12);
    cipherTextLen -= 12;

    ret = AesDecrypt(cipher, key, (HcfParamsSpec *)&spec, cipherText, cipherTextLen);
    ASSERT_EQ(ret, 0);

    HcfObjDestroy((HcfObjectBase *)key);
    HcfObjDestroy((HcfObjectBase *)cipher);
}

HWTEST_F(CryptoAesCcmCipherTest, CryptoAesCcmCipherTest004, TestSize.Level0)
{
    int ret = 0;
    uint8_t aad[8] = {0};
    uint8_t tag[12] = {0};
    uint8_t iv[7] = {0};
    uint8_t cipherText[128] = {0};
    int cipherTextLen = 128;

    HcfCipher *cipher = nullptr;
    HcfSymKey *key = nullptr;
    HcfCcmParamsSpec spec = {};
    spec.aad.data = aad;
    spec.aad.len = sizeof(aad);
    spec.tag.data = tag;
    spec.tag.len = sizeof(tag);
    spec.iv.data = iv;
    spec.iv.len = sizeof(iv);

    ret = GenerateSymKey("AES128", &key);
    ASSERT_EQ(ret, 0);

    ret = HcfCipherCreate("AES128|CCM|NoPadding", &cipher);
    ASSERT_EQ(ret, 0);

    ret = AesNoUpdateEncrypt(cipher, key, (HcfParamsSpec *)&spec, cipherText, &cipherTextLen);
    ASSERT_EQ(ret, 0);

    (void)memcpy_s(spec.tag.data, 12, cipherText + cipherTextLen - 12, 12);
    cipherTextLen -= 12;

    ret = AesNoUpdateDecrypt(cipher, key, (HcfParamsSpec *)&spec, cipherText, cipherTextLen);
    ASSERT_EQ(ret, 0);

    HcfObjDestroy((HcfObjectBase *)key);
    HcfObjDestroy((HcfObjectBase *)cipher);
}

HWTEST_F(CryptoAesCcmCipherTest, CryptoAesCcmCipherTest005, TestSize.Level0)
{
    int ret = 0;
    uint8_t aad[8] = {0};
    uint8_t tag[12] = {0};
    uint8_t iv[7] = {0};
    uint8_t cipherText[128] = {0};
    int cipherTextLen = 128;

    HcfCipher *cipher = nullptr;
    HcfSymKey *key = nullptr;
    HcfCcmParamsSpec spec = {};
    spec.aad.data = aad;
    spec.aad.len = sizeof(aad);
    spec.tag.data = tag;
    spec.tag.len = sizeof(tag);
    spec.iv.data = iv;
    spec.iv.len = sizeof(iv);

    ret = GenerateSymKey("AES128", &key);
    ASSERT_EQ(ret, 0);

    ret = HcfCipherCreate("AES128|CCM|PKCS5", &cipher);
    ASSERT_EQ(ret, 0);

    ret = AesNoUpdateEncrypt(cipher, key, (HcfParamsSpec *)&spec, cipherText, &cipherTextLen);
    ASSERT_EQ(ret, 0);

    (void)memcpy_s(spec.tag.data, 12, cipherText + cipherTextLen - 12, 12);
    cipherTextLen -= 12;

    ret = AesNoUpdateDecrypt(cipher, key, (HcfParamsSpec *)&spec, cipherText, cipherTextLen);
    ASSERT_EQ(ret, 0);

    HcfObjDestroy((HcfObjectBase *)key);
    HcfObjDestroy((HcfObjectBase *)cipher);
}

HWTEST_F(CryptoAesCcmCipherTest, CryptoAesCcmCipherTest006, TestSize.Level0)
{
    int ret = 0;
    uint8_t aad[8] = {0};
    uint8_t tag[12] = {0};
    uint8_t iv[7] = {0};
    uint8_t cipherText[128] = {0};
    int cipherTextLen = 128;

    HcfCipher *cipher = nullptr;
    HcfSymKey *key = nullptr;
    HcfCcmParamsSpec spec = {};
    spec.aad.data = aad;
    spec.aad.len = sizeof(aad);
    spec.tag.data = tag;
    spec.tag.len = sizeof(tag);
    spec.iv.data = iv;
    spec.iv.len = sizeof(iv);

    ret = GenerateSymKey("AES128", &key);
    ASSERT_EQ(ret, 0);

    ret = HcfCipherCreate("AES128|CCM|PKCS7", &cipher);
    ASSERT_EQ(ret, 0);

    ret = AesNoUpdateEncrypt(cipher, key, (HcfParamsSpec *)&spec, cipherText, &cipherTextLen);
    ASSERT_EQ(ret, 0);

    (void)memcpy_s(spec.tag.data, 12, cipherText + cipherTextLen - 12, 12);
    cipherTextLen -= 12;

    ret = AesNoUpdateDecrypt(cipher, key, (HcfParamsSpec *)&spec, cipherText, cipherTextLen);
    ASSERT_EQ(ret, 0);

    HcfObjDestroy((HcfObjectBase *)key);
    HcfObjDestroy((HcfObjectBase *)cipher);
}

HWTEST_F(CryptoAesCcmCipherTest, CryptoAesCcmCipherTest007, TestSize.Level0)
{
    int ret = 0;
    uint8_t aad[CCM_AAD_LEN] = { 0 };
    uint8_t tag[CCM_TAG_LEN] = { 0 };
    uint8_t iv[CCM_IV_LEN] = { 0 };
    uint8_t cipherText[CIPHER_TEXT_LEN] = { 0 };
    int cipherTextLen = CIPHER_TEXT_LEN;

    HcfCipher *cipher = nullptr;
    HcfSymKey *key = nullptr;
    HcfCcmParamsSpec spec = {};
    spec.aad.data = aad;
    spec.aad.len = sizeof(aad);
    spec.tag.data = tag;
    spec.tag.len = sizeof(tag);
    spec.iv.data = iv;
    spec.iv.len = sizeof(iv);

    ret = GenerateSymKey("AES192", &key);
    ASSERT_EQ(ret, 0);

    ret = HcfCipherCreate("AES192|CCM|PKCS5", &cipher);
    ASSERT_EQ(ret, 0);

    ret = AesEncrypt(cipher, key, &(spec.base), cipherText, &cipherTextLen);
    ASSERT_EQ(ret, 0);

    (void)memcpy_s(spec.tag.data, CCM_TAG_LEN, cipherText + cipherTextLen - CCM_TAG_LEN, CCM_TAG_LEN);
    cipherTextLen -= CCM_TAG_LEN;

    ret = AesDecrypt(cipher, key, &(spec.base), cipherText, cipherTextLen);
    ASSERT_EQ(ret, 0);

    HcfObjDestroy(key);
    HcfObjDestroy(cipher);
}

HWTEST_F(CryptoAesCcmCipherTest, CryptoAesCcmCipherTest008, TestSize.Level0)
{
    int ret = 0;
    uint8_t aad[CCM_AAD_LEN] = { 0 };
    uint8_t tag[CCM_TAG_LEN] = { 0 };
    uint8_t iv[CCM_IV_LEN] = { 0 };
    uint8_t cipherText[CIPHER_TEXT_LEN] = { 0 };
    int cipherTextLen = CIPHER_TEXT_LEN;

    HcfCipher *cipher = nullptr;
    HcfSymKey *key = nullptr;
    HcfCcmParamsSpec spec = {};
    spec.aad.data = aad;
    spec.aad.len = sizeof(aad);
    spec.tag.data = tag;
    spec.tag.len = sizeof(tag);
    spec.iv.data = iv;
    spec.iv.len = sizeof(iv);

    ret = GenerateSymKey("AES256", &key);
    ASSERT_EQ(ret, 0);

    ret = HcfCipherCreate("AES256|CCM|PKCS5", &cipher);
    ASSERT_EQ(ret, 0);

    ret = AesEncrypt(cipher, key, &(spec.base), cipherText, &cipherTextLen);
    ASSERT_EQ(ret, 0);

    (void)memcpy_s(spec.tag.data, CCM_TAG_LEN, cipherText + cipherTextLen - CCM_TAG_LEN, CCM_TAG_LEN);
    cipherTextLen -= CCM_TAG_LEN;

    ret = AesDecrypt(cipher, key, &(spec.base), cipherText, cipherTextLen);
    ASSERT_EQ(ret, 0);

    HcfObjDestroy(key);
    HcfObjDestroy(cipher);
}

HWTEST_F(CryptoAesCcmCipherTest, CryptoAesCcmCipherTest009, TestSize.Level0)
{
    int ret = 0;
    uint8_t cipherText[CIPHER_TEXT_LEN] = {0};
    int cipherTextLen = CIPHER_TEXT_LEN;

    HcfCipher *cipher = nullptr;
    HcfSymKey *key = nullptr;

    ret = GenerateSymKey("AES128", &key);
    ASSERT_EQ(ret, 0);

    ret = HcfCipherCreate("AES128|CCM|NoPadding", &cipher);
    ASSERT_EQ(ret, 0);

    ret = AesEncrypt(cipher, key, nullptr, cipherText, &cipherTextLen);
    ASSERT_NE(ret, 0);

    HcfObjDestroy(key);
    HcfObjDestroy(cipher);
}

HWTEST_F(CryptoAesCcmCipherTest, CryptoAesCcmCipherTest010, TestSize.Level0)
{
    int ret = 0;
    uint8_t aad[CCM_AAD_LEN] = { 0 };
    uint8_t tag[CCM_TAG_LEN] = { 0 };
    uint8_t iv[CCM_IV_LEN] = { 0 };
    uint8_t cipherText[CIPHER_TEXT_LEN] = { 0 };
    int cipherTextLen = CIPHER_TEXT_LEN;

    HcfCipher *cipher = nullptr;
    HcfSymKey *key = nullptr;
    HcfCcmParamsSpec spec = {};
    spec.aad.data = nullptr;
    spec.aad.len = sizeof(aad);
    spec.tag.data = tag;
    spec.tag.len = sizeof(tag);
    spec.iv.data = iv;
    spec.iv.len = sizeof(iv);

    ret = GenerateSymKey("AES128", &key);
    ASSERT_EQ(ret, 0);

    ret = HcfCipherCreate("AES128|CCM|NoPadding", &cipher);
    ASSERT_EQ(ret, 0);

    ret = AesEncrypt(cipher, key, &(spec.base), cipherText, &cipherTextLen);
    ASSERT_NE(ret, 0);

    HcfObjDestroy(key);
    HcfObjDestroy(cipher);
}

HWTEST_F(CryptoAesCcmCipherTest, CryptoAesCcmCipherTest011, TestSize.Level0)
{
    int ret = 0;
    uint8_t aad[CCM_AAD_LEN] = { 0 };
    uint8_t tag[CCM_TAG_LEN] = { 0 };
    uint8_t iv[CCM_IV_LEN] = { 0 };
    uint8_t cipherText[CIPHER_TEXT_LEN] = { 0 };
    int cipherTextLen = CIPHER_TEXT_LEN;

    HcfCipher *cipher = nullptr;
    HcfSymKey *key = nullptr;
    HcfCcmParamsSpec spec = {};
    spec.aad.data = aad;
    spec.aad.len = sizeof(aad);
    spec.tag.data = tag;
    spec.tag.len = sizeof(tag);
    spec.iv.data = nullptr;
    spec.iv.len = sizeof(iv);

    ret = GenerateSymKey("AES128", &key);
    ASSERT_EQ(ret, 0);

    ret = HcfCipherCreate("AES128|CCM|NoPadding", &cipher);
    ASSERT_EQ(ret, 0);

    ret = AesEncrypt(cipher, key, &(spec.base), cipherText, &cipherTextLen);
    ASSERT_NE(ret, 0);

    HcfObjDestroy(key);
    HcfObjDestroy(cipher);
}

HWTEST_F(CryptoAesCcmCipherTest, CryptoAesCcmCipherTest012, TestSize.Level0)
{
    int ret = 0;
    uint8_t aad[CCM_AAD_LEN] = { 0 };
    uint8_t tag[CCM_TAG_LEN] = { 0 };
    uint8_t iv[CCM_IV_LEN] = { 0 };
    uint8_t cipherText[CIPHER_TEXT_LEN] = { 0 };
    int cipherTextLen = CIPHER_TEXT_LEN;

    HcfCipher *cipher = nullptr;
    HcfSymKey *key = nullptr;
    HcfCcmParamsSpec spec = {};
    spec.aad.data = aad;
    spec.aad.len = sizeof(aad);
    spec.tag.data = nullptr;
    spec.tag.len = sizeof(tag);
    spec.iv.data = iv;
    spec.iv.len = sizeof(iv);

    ret = GenerateSymKey("AES128", &key);
    ASSERT_EQ(ret, 0);

    ret = HcfCipherCreate("AES128|CCM|NoPadding", &cipher);
    ASSERT_EQ(ret, 0);

    ret = AesEncrypt(cipher, key, &(spec.base), cipherText, &cipherTextLen);
    ASSERT_NE(ret, 0);

    HcfObjDestroy(key);
    HcfObjDestroy(cipher);
}

HWTEST_F(CryptoAesCcmCipherTest, CryptoAesCcmCipherTest013, TestSize.Level0)
{
    int ret = 0;
    HcfCipher *cipher = nullptr;
    HcfSymKey *key = nullptr;
    HcfSymKeyGenerator *generator = nullptr;

    ret = HcfSymKeyGeneratorCreate("AES128", &generator);
    ASSERT_EQ(ret, 0);

    ret = generator->generateSymKey(generator, &key);
    ASSERT_EQ(ret, 0);

    generator->base.destroy(nullptr);

    ret = HcfCipherCreate("AES128|CCM|NoPadding", &cipher);
    ASSERT_EQ(ret, 0);

    ret = cipher->init(cipher, ENCRYPT_MODE, reinterpret_cast<HcfKey *>(key), nullptr);
    ASSERT_NE(ret, 0);

    HcfObjDestroy(key);
    HcfObjDestroy(cipher);
    HcfObjDestroy(generator);
}
}