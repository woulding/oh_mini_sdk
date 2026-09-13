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
#include "aes_openssl.h"
#include "aes_common.h"
#include "blob.h"
#include "cipher.h"
#include "detailed_iv_params.h"
#include "detailed_gcm_params.h"
#include "detailed_ccm_params.h"
#include "memory.h"
#include "sym_common_defines.h"
#include "sym_key_generator.h"
#include "sm4_common.h"
#include "sm4_openssl.h"

using namespace std;
using namespace testing::ext;

namespace {
class CryptoSM4CfbCipherTest : public testing::Test {
public:
    static void SetUpTestCase() {};
    static void TearDownTestCase() {};
    void SetUp() {};
    void TearDown() {};
};

HWTEST_F(CryptoSM4CfbCipherTest, CryptoSm4CipherTest010, TestSize.Level0)
{
    int ret = 0;
    uint8_t cipherText[128] = {0};
    int cipherTextLen = 128;

    HcfSymKeyGenerator *generator = nullptr;
    HcfCipher *cipher = nullptr;
    HcfSymKey *key = nullptr;

    ret = HcfSymKeyGeneratorCreate("SM4_128", &generator);
    ASSERT_EQ(ret, 0);

    ret = generator->generateSymKey(generator, &key);
    ASSERT_EQ(ret, 0);

    ret = HcfCipherCreate("SM4_128|CFB|NoPadding", &cipher);
    ASSERT_EQ(ret, 0);

    ret = Sm4Encrypt(cipher, key, nullptr, cipherText, &cipherTextLen);
    ASSERT_EQ(ret, 0);

    ret = Sm4Decrypt(cipher, key, nullptr, cipherText, cipherTextLen);
    ASSERT_EQ(ret, 0);

    HcfObjDestroy((HcfObjectBase *)key);
    HcfObjDestroy((HcfObjectBase *)cipher);
    HcfObjDestroy((HcfObjectBase *)generator);
}

HWTEST_F(CryptoSM4CfbCipherTest, CryptoSm4CipherTest011, TestSize.Level0)
{
    int ret = 0;
    uint8_t cipherText[128] = {0};
    int cipherTextLen = 128;

    HcfSymKeyGenerator *generator = nullptr;
    HcfCipher *cipher = nullptr;
    HcfSymKey *key = nullptr;

    ret = HcfSymKeyGeneratorCreate("SM4_128", &generator);
    ASSERT_EQ(ret, 0);

    ret = generator->generateSymKey(generator, &key);
    ASSERT_EQ(ret, 0);

    ret = HcfCipherCreate("SM4_128|CFB|PKCS5", &cipher);
    ASSERT_EQ(ret, 0);

    ret = Sm4Encrypt(cipher, key, nullptr, cipherText, &cipherTextLen);
    ASSERT_EQ(ret, 0);

    ret = Sm4Decrypt(cipher, key, nullptr, cipherText, cipherTextLen);
    ASSERT_EQ(ret, 0);

    HcfObjDestroy((HcfObjectBase *)key);
    HcfObjDestroy((HcfObjectBase *)cipher);
    HcfObjDestroy((HcfObjectBase *)generator);
}

HWTEST_F(CryptoSM4CfbCipherTest, CryptoSm4CipherTest012, TestSize.Level0)
{
    int ret = 0;
    uint8_t cipherText[128] = {0};
    int cipherTextLen = 128;

    HcfSymKeyGenerator *generator = nullptr;
    HcfCipher *cipher = nullptr;
    HcfSymKey *key = nullptr;

    ret = HcfSymKeyGeneratorCreate("SM4_128", &generator);
    ASSERT_EQ(ret, 0);

    ret = generator->generateSymKey(generator, &key);
    ASSERT_EQ(ret, 0);

    ret = HcfCipherCreate("SM4_128|CFB|PKCS7", &cipher);
    ASSERT_EQ(ret, 0);

    ret = Sm4Encrypt(cipher, key, nullptr, cipherText, &cipherTextLen);
    ASSERT_EQ(ret, 0);

    ret = Sm4Decrypt(cipher, key, nullptr, cipherText, cipherTextLen);
    ASSERT_EQ(ret, 0);

    HcfObjDestroy((HcfObjectBase *)key);
    HcfObjDestroy((HcfObjectBase *)cipher);
    HcfObjDestroy((HcfObjectBase *)generator);
}

HWTEST_F(CryptoSM4CfbCipherTest, CryptoSm4CipherTest013, TestSize.Level0)
{
    int ret = 0;
    uint8_t cipherText[128] = {0};
    int cipherTextLen = 128;

    HcfSymKeyGenerator *generator = nullptr;
    HcfCipher *cipher = nullptr;
    HcfSymKey *key = nullptr;

    ret = HcfSymKeyGeneratorCreate("SM4_128", &generator);
    ASSERT_EQ(ret, 0);

    ret = generator->generateSymKey(generator, &key);
    ASSERT_EQ(ret, 0);

    ret = HcfCipherCreate("SM4_128|CFB128|NoPadding", &cipher);
    ASSERT_EQ(ret, 0);

    ret = Sm4Encrypt(cipher, key, nullptr, cipherText, &cipherTextLen);
    ASSERT_EQ(ret, 0);

    ret = Sm4Decrypt(cipher, key, nullptr, cipherText, cipherTextLen);
    ASSERT_EQ(ret, 0);

    HcfObjDestroy((HcfObjectBase *)key);
    HcfObjDestroy((HcfObjectBase *)cipher);
    HcfObjDestroy((HcfObjectBase *)generator);
}

HWTEST_F(CryptoSM4CfbCipherTest, CryptoSm4CipherTest014, TestSize.Level0)
{
    int ret = 0;
    uint8_t cipherText[128] = {0};
    int cipherTextLen = 128;

    HcfSymKeyGenerator *generator = nullptr;
    HcfCipher *cipher = nullptr;
    HcfSymKey *key = nullptr;

    ret = HcfSymKeyGeneratorCreate("SM4_128", &generator);
    ASSERT_EQ(ret, 0);

    ret = generator->generateSymKey(generator, &key);
    ASSERT_EQ(ret, 0);

    ret = HcfCipherCreate("SM4_128|CFB128|PKCS5", &cipher);
    ASSERT_EQ(ret, 0);

    ret = Sm4Encrypt(cipher, key, nullptr, cipherText, &cipherTextLen);
    ASSERT_EQ(ret, 0);

    ret = Sm4Decrypt(cipher, key, nullptr, cipherText, cipherTextLen);
    ASSERT_EQ(ret, 0);

    HcfObjDestroy((HcfObjectBase *)key);
    HcfObjDestroy((HcfObjectBase *)cipher);
    HcfObjDestroy((HcfObjectBase *)generator);
}

HWTEST_F(CryptoSM4CfbCipherTest, CryptoSm4CipherTest015, TestSize.Level0)
{
    int ret = 0;
    uint8_t cipherText[128] = {0};
    int cipherTextLen = 128;

    HcfSymKeyGenerator *generator = nullptr;
    HcfCipher *cipher = nullptr;
    HcfSymKey *key = nullptr;

    ret = HcfSymKeyGeneratorCreate("SM4_128", &generator);
    ASSERT_EQ(ret, 0);

    ret = generator->generateSymKey(generator, &key);
    ASSERT_EQ(ret, 0);

    ret = HcfCipherCreate("SM4_128|CFB128|PKCS7", &cipher);
    ASSERT_EQ(ret, 0);

    ret = Sm4Encrypt(cipher, key, nullptr, cipherText, &cipherTextLen);
    ASSERT_EQ(ret, 0);

    ret = Sm4Decrypt(cipher, key, nullptr, cipherText, cipherTextLen);
    ASSERT_EQ(ret, 0);

    HcfObjDestroy((HcfObjectBase *)key);
    HcfObjDestroy((HcfObjectBase *)cipher);
    HcfObjDestroy((HcfObjectBase *)generator);
}

HWTEST_F(CryptoSM4CfbCipherTest, CryptoSm4CipherTest028, TestSize.Level0)
{
    int ret = 0;
    uint8_t cipherText[128] = {0};
    int cipherTextLen = 128;

    HcfSymKeyGenerator *generator = nullptr;
    HcfCipher *cipher = nullptr;
    HcfSymKey *key = nullptr;

    ret = HcfSymKeyGeneratorCreate("SM4_128", &generator);
    ASSERT_EQ(ret, 0);

    ret = generator->generateSymKey(generator, &key);
    ASSERT_EQ(ret, 0);

    ret = HcfCipherCreate("SM4_128|CFB|NoPadding", &cipher);
    ASSERT_EQ(ret, 0);

    ret = Sm4NoUpdateEncrypt(cipher, key, nullptr, cipherText, &cipherTextLen);
    ASSERT_EQ(ret, 0);

    ret = Sm4NoUpdateDecrypt(cipher, key, nullptr, cipherText, cipherTextLen);
    ASSERT_EQ(ret, 0);

    HcfObjDestroy((HcfObjectBase *)key);
    HcfObjDestroy((HcfObjectBase *)cipher);
    HcfObjDestroy((HcfObjectBase *)generator);
}

HWTEST_F(CryptoSM4CfbCipherTest, CryptoSm4CipherTest029, TestSize.Level0)
{
    int ret = 0;
    uint8_t cipherText[128] = {0};
    int cipherTextLen = 128;

    HcfSymKeyGenerator *generator = nullptr;
    HcfCipher *cipher = nullptr;
    HcfSymKey *key = nullptr;

    ret = HcfSymKeyGeneratorCreate("SM4_128", &generator);
    ASSERT_EQ(ret, 0);

    ret = generator->generateSymKey(generator, &key);
    ASSERT_EQ(ret, 0);

    ret = HcfCipherCreate("SM4_128|CFB|PKCS5", &cipher);
    ASSERT_EQ(ret, 0);

    ret = Sm4NoUpdateEncrypt(cipher, key, nullptr, cipherText, &cipherTextLen);
    ASSERT_EQ(ret, 0);

    ret = Sm4NoUpdateDecrypt(cipher, key, nullptr, cipherText, cipherTextLen);
    ASSERT_EQ(ret, 0);

    HcfObjDestroy((HcfObjectBase *)key);
    HcfObjDestroy((HcfObjectBase *)cipher);
    HcfObjDestroy((HcfObjectBase *)generator);
}

HWTEST_F(CryptoSM4CfbCipherTest, CryptoSm4CipherTest030, TestSize.Level0)
{
    int ret = 0;
    uint8_t cipherText[128] = {0};
    int cipherTextLen = 128;

    HcfSymKeyGenerator *generator = nullptr;
    HcfCipher *cipher = nullptr;
    HcfSymKey *key = nullptr;

    ret = HcfSymKeyGeneratorCreate("SM4_128", &generator);
    ASSERT_EQ(ret, 0);

    ret = generator->generateSymKey(generator, &key);
    ASSERT_EQ(ret, 0);

    ret = HcfCipherCreate("SM4_128|CFB|PKCS7", &cipher);
    ASSERT_EQ(ret, 0);

    ret = Sm4NoUpdateEncrypt(cipher, key, nullptr, cipherText, &cipherTextLen);
    ASSERT_EQ(ret, 0);

    ret = Sm4NoUpdateDecrypt(cipher, key, nullptr, cipherText, cipherTextLen);
    ASSERT_EQ(ret, 0);

    HcfObjDestroy((HcfObjectBase *)key);
    HcfObjDestroy((HcfObjectBase *)cipher);
    HcfObjDestroy((HcfObjectBase *)generator);
}

HWTEST_F(CryptoSM4CfbCipherTest, CryptoSm4CipherTest031, TestSize.Level0)
{
    int ret = 0;
    uint8_t cipherText[128] = {0};
    int cipherTextLen = 128;

    HcfSymKeyGenerator *generator = nullptr;
    HcfCipher *cipher = nullptr;
    HcfSymKey *key = nullptr;

    ret = HcfSymKeyGeneratorCreate("SM4_128", &generator);
    ASSERT_EQ(ret, 0);

    ret = generator->generateSymKey(generator, &key);
    ASSERT_EQ(ret, 0);

    ret = HcfCipherCreate("SM4_128|CFB128|NoPadding", &cipher);
    ASSERT_EQ(ret, 0);

    ret = Sm4NoUpdateEncrypt(cipher, key, nullptr, cipherText, &cipherTextLen);
    ASSERT_EQ(ret, 0);

    ret = Sm4NoUpdateDecrypt(cipher, key, nullptr, cipherText, cipherTextLen);
    ASSERT_EQ(ret, 0);

    HcfObjDestroy((HcfObjectBase *)key);
    HcfObjDestroy((HcfObjectBase *)cipher);
    HcfObjDestroy((HcfObjectBase *)generator);
}

HWTEST_F(CryptoSM4CfbCipherTest, CryptoSm4CipherTest032, TestSize.Level0)
{
    int ret = 0;
    uint8_t cipherText[128] = {0};
    int cipherTextLen = 128;

    HcfSymKeyGenerator *generator = nullptr;
    HcfCipher *cipher = nullptr;
    HcfSymKey *key = nullptr;

    ret = HcfSymKeyGeneratorCreate("SM4_128", &generator);
    ASSERT_EQ(ret, 0);

    ret = generator->generateSymKey(generator, &key);
    ASSERT_EQ(ret, 0);

    ret = HcfCipherCreate("SM4_128|CFB128|PKCS5", &cipher);
    ASSERT_EQ(ret, 0);

    ret = Sm4NoUpdateEncrypt(cipher, key, nullptr, cipherText, &cipherTextLen);
    ASSERT_EQ(ret, 0);

    ret = Sm4NoUpdateDecrypt(cipher, key, nullptr, cipherText, cipherTextLen);
    ASSERT_EQ(ret, 0);

    HcfObjDestroy((HcfObjectBase *)key);
    HcfObjDestroy((HcfObjectBase *)cipher);
    HcfObjDestroy((HcfObjectBase *)generator);
}

HWTEST_F(CryptoSM4CfbCipherTest, CryptoSm4CipherTest033, TestSize.Level0)
{
    int ret = 0;
    uint8_t cipherText[128] = {0};
    int cipherTextLen = 128;

    HcfSymKeyGenerator *generator = nullptr;
    HcfCipher *cipher = nullptr;
    HcfSymKey *key = nullptr;

    ret = HcfSymKeyGeneratorCreate("SM4_128", &generator);
    ASSERT_EQ(ret, 0);

    ret = generator->generateSymKey(generator, &key);
    ASSERT_EQ(ret, 0);

    ret = HcfCipherCreate("SM4_128|CFB128|PKCS7", &cipher);
    ASSERT_EQ(ret, 0);

    ret = Sm4NoUpdateEncrypt(cipher, key, nullptr, cipherText, &cipherTextLen);
    ASSERT_EQ(ret, 0);

    ret = Sm4NoUpdateDecrypt(cipher, key, nullptr, cipherText, cipherTextLen);
    ASSERT_EQ(ret, 0);

    HcfObjDestroy((HcfObjectBase *)key);
    HcfObjDestroy((HcfObjectBase *)cipher);
    HcfObjDestroy((HcfObjectBase *)generator);
}

HWTEST_F(CryptoSM4CfbCipherTest, CryptoSm4CipherTest040, TestSize.Level0)
{
    HcfCipher *cipher = nullptr;
    const char *cipherName = "SM4_128|CFB|NoPadding";
    const char *retAlgo = nullptr;

    int ret = HcfCipherCreate(cipherName, &cipher);
    ASSERT_EQ(ret, 0);

    retAlgo = cipher->getAlgorithm(nullptr);
    ASSERT_EQ(retAlgo, nullptr);

    HcfObjDestroy(cipher);
}

HWTEST_F(CryptoSM4CfbCipherTest, CryptoSm4CipherTest041, TestSize.Level0)
{
    HcfCipher *cipher = nullptr;
    HcfSymKeyGenerator *generator = nullptr;
    const char *cipherName = "SM4_128|CFB|NoPadding";
    const char *retAlgo = nullptr;

    int ret = HcfSymKeyGeneratorCreate("SM4_128", &generator);
    ASSERT_EQ(ret, 0);

    ret = HcfCipherCreate(cipherName, &cipher);
    ASSERT_EQ(ret, 0);

    retAlgo = cipher->getAlgorithm(reinterpret_cast<HcfCipher *>(generator));
    ASSERT_EQ(retAlgo, nullptr);

    HcfObjDestroy(generator);
    HcfObjDestroy(cipher);
}

HWTEST_F(CryptoSM4CfbCipherTest, CryptoSm4CipherTest042, TestSize.Level0)
{
    HcfCipher *cipher = nullptr;
    int ret = HcfCipherCreate("SM3|CFB|NoPadding", &cipher);
    ASSERT_NE(ret, 0);
    HcfObjDestroy(cipher);
}

HWTEST_F(CryptoSM4CfbCipherTest, CryptoSm4CipherTest043, TestSize.Level0)
{
    HcfCipher *cipher = nullptr;
    int ret = HcfCipherCreate("SM4_128|CFB|", &cipher);
    ASSERT_NE(ret, 0);
    HcfObjDestroy(cipher);
}

HWTEST_F(CryptoSM4CfbCipherTest, CryptoSm4CipherTest047, TestSize.Level0)
{
    int ret = HcfCipherCreate(nullptr, nullptr);
    ASSERT_NE(ret, 0);
}

HWTEST_F(CryptoSM4CfbCipherTest, CryptoAesCipherTest050, TestSize.Level0)
{
    uint8_t aad[8] = {0};
    uint8_t tag[12] = {0};
    uint8_t iv[16] = {0};
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

    int ret = GenerateSymKeyForSm4("SM4_128", &key);
    ASSERT_EQ(ret, 0);

    ret = HcfCipherCreate("SM4_128|CFB|PKCS5", &cipher);
    ASSERT_EQ(ret, 0);

    ret = Sm4Encrypt(cipher, key, (HcfParamsSpec *)&spec, cipherText, &cipherTextLen);
    ASSERT_EQ(ret, 0);

    (void)memcpy_s(spec.tag.data, 12, cipherText + cipherTextLen - 12, 12);
    cipherTextLen -= 12;

    ret = Sm4Decrypt(cipher, key, (HcfParamsSpec *)&spec, cipherText, cipherTextLen);
    ASSERT_NE(ret, 0);

    HcfObjDestroy((HcfObjectBase *)key);
    HcfObjDestroy((HcfObjectBase *)cipher);
}

HWTEST_F(CryptoSM4CfbCipherTest, CryptoAesCipherTest051, TestSize.Level0)
{
    HcfCipher *cipher = nullptr;
    const char *cipherName = "SM4_128|CFB|NoPadding";
    const char *retAlgo = nullptr;

    int ret = HcfCipherCreate(cipherName, &cipher);
    ASSERT_EQ(ret, 0);

    retAlgo = cipher->getAlgorithm(cipher);
    ASSERT_NE(retAlgo, nullptr);

    ret = strcmp(retAlgo, cipherName);
    ASSERT_EQ(ret, 0);

    HcfObjDestroy(cipher);
}

HWTEST_F(CryptoSM4CfbCipherTest, CryptoSm4CipherTest082, TestSize.Level0)
{
    uint8_t cipherText[CIPHER_TEXT_LEN] = { 0 };
    int cipherTextLen = CIPHER_TEXT_LEN;
    HcfCipher *cipher = nullptr;
    HcfSymKey *key = nullptr;

    int ret = GenerateSymKeyForSm4("AES256", &key);
    ASSERT_EQ(ret, 0);

    ret = HcfCipherCreate("SM4_128|CFB|PKCS5", &cipher);
    ASSERT_EQ(ret, 0);

    // It is not allowed that AES128 in key is smaller AES256 in cipher. -> now only use the size of input key.
    ret = Sm4Encrypt(cipher, key, nullptr, cipherText, &cipherTextLen);
    ASSERT_NE(ret, 0);

    HcfObjDestroy(key);
    HcfObjDestroy(cipher);
}

HWTEST_F(CryptoSM4CfbCipherTest, CryptoSm4CipherTest083, TestSize.Level0)
{
    uint8_t cipherText[CIPHER_TEXT_LEN] = { 0 };
    int cipherTextLen = CIPHER_TEXT_LEN;
    HcfCipher *cipher = nullptr;
    HcfSymKey *key = nullptr;

    int ret = GenerateSymKeyForSm4("AES256", &key);
    ASSERT_EQ(ret, 0);

    ret = HcfCipherCreate("SM4_128|CFB128|PKCS5", &cipher);
    ASSERT_EQ(ret, 0);

    // It is not allowed that AES128 in key is smaller AES256 in cipher. -> now only use the size of input key.
    ret = Sm4Encrypt(cipher, key, nullptr, cipherText, &cipherTextLen);
    ASSERT_NE(ret, 0);

    HcfObjDestroy(key);
    HcfObjDestroy(cipher);
}
}