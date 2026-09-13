/*
 * Copyright (C) 2023 Huawei Device Co., Ltd.
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
#include "securec.h"
#include "asy_key_generator.h"
#include "cipher.h"
#include "cipher_sm2_openssl.h"
#include "key_pair.h"
#include "memory.h"
#include "cstring"
#include "openssl_common.h"

using namespace std;
using namespace testing::ext;

namespace {
class CryptoSm2CipherTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp();
    void TearDown();

    static HcfKeyPair *sm2256KeyPair_;
};

HcfKeyPair *CryptoSm2CipherTest::sm2256KeyPair_ = nullptr;

void CryptoSm2CipherTest::SetUpTestCase()
{
    HcfAsyKeyGenerator *generator = nullptr;
    int32_t res = HcfAsyKeyGeneratorCreate("SM2_256", &generator);
    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(generator, nullptr);

    HcfKeyPair *keyPair = nullptr;
    res = generator->generateKeyPair(generator, nullptr, &keyPair);
    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(keyPair, nullptr);

    sm2256KeyPair_ = keyPair;

    HcfObjDestroy(generator);
}

void CryptoSm2CipherTest::TearDownTestCase()
{
    HcfObjDestroy(sm2256KeyPair_);
}

void CryptoSm2CipherTest::SetUp() {}
void CryptoSm2CipherTest::TearDown() {}

static const char *GetMockClass(void)
{
    return "HcfMock";
}

static HcfObjectBase obj = {
    .getClass = GetMockClass,
    .destroy = nullptr
};

HWTEST_F(CryptoSm2CipherTest, CryptoSm2CipherTest001, TestSize.Level0)
{
    HcfResult res = HCF_SUCCESS;
    HcfCipher *cipher = nullptr;
    res = HcfCipherCreate("SM2|SM3", &cipher);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(cipher, nullptr);
    EXPECT_NE(cipher->base.getClass(), nullptr);
    EXPECT_NE(cipher->base.destroy, nullptr);
    EXPECT_NE(cipher->init, nullptr);
    EXPECT_NE(cipher->update, nullptr);
    EXPECT_NE(cipher->doFinal, nullptr);
    EXPECT_NE(cipher->getAlgorithm, nullptr);
    HcfObjDestroy(cipher);
}

// HcfCipherCreate Incorrect case
HWTEST_F(CryptoSm2CipherTest, CryptoSm2CipherTest002, TestSize.Level0)
{
    HcfResult res = HCF_SUCCESS;
    res = HcfCipherCreate("SM2|SM3", nullptr);
    EXPECT_NE(res, HCF_SUCCESS);
}

HWTEST_F(CryptoSm2CipherTest, CryptoSm2CipherTest003, TestSize.Level0)
{
    HcfResult res = HCF_SUCCESS;
    HcfCipher *cipher = nullptr;
    res = HcfCipherCreate(nullptr, &cipher);
    EXPECT_NE(res, HCF_SUCCESS);
    EXPECT_EQ(cipher, nullptr);
}

HWTEST_F(CryptoSm2CipherTest, CryptoSm2CipherTest004, TestSize.Level0)
{
    HcfResult res = HCF_SUCCESS;
    HcfCipher *cipher = nullptr;
    res = HcfCipherCreate("SM2|2111111111111111111111111111111111111111111111"
        "111111111111123123", &cipher);
    EXPECT_NE(res, HCF_SUCCESS);
    EXPECT_EQ(cipher, nullptr);
}

HWTEST_F(CryptoSm2CipherTest, CryptoSm2CipherTest005, TestSize.Level0)
{
    HcfResult res = HCF_SUCCESS;
    HcfCipher *cipher = nullptr;
    res = HcfCipherCreate("SM222", &cipher);
    EXPECT_NE(res, HCF_SUCCESS);
    EXPECT_EQ(cipher, nullptr);
}

HWTEST_F(CryptoSm2CipherTest, CryptoSm2CipherTest006, TestSize.Level0)
{
    HcfResult res = HCF_SUCCESS;
    HcfCipher *cipher = nullptr;
    res = HcfCipherCreate("SM2|SM5", &cipher);
    EXPECT_NE(res, HCF_SUCCESS);
    EXPECT_EQ(cipher, nullptr);
}

HWTEST_F(CryptoSm2CipherTest, CryptoSm2CipherTest007, TestSize.Level0)
{
    HcfResult res = HCF_SUCCESS;
    HcfAsyKeyGenerator *generator = nullptr;
    res = HcfAsyKeyGeneratorCreate("SM2_256", &generator);
    EXPECT_EQ(res, HCF_SUCCESS);
    HcfKeyPair *keyPair = nullptr;
    res = generator->generateKeyPair(generator, nullptr, &keyPair);
    EXPECT_EQ(res, HCF_SUCCESS);

    HcfCipher *cipher = nullptr;
    res = HcfCipherCreate("SM2|SM3", &cipher);
    EXPECT_EQ(res, HCF_SUCCESS);
    res = cipher->init(cipher, ENCRYPT_MODE, (HcfKey *)keyPair->pubKey, nullptr);
    EXPECT_EQ(res, HCF_SUCCESS);

    HcfObjDestroy(keyPair);
    HcfObjDestroy(generator);
    HcfObjDestroy(cipher);
}

HWTEST_F(CryptoSm2CipherTest, CryptoSm2CipherTest008, TestSize.Level0)
{
    HcfResult res = HCF_SUCCESS;
    HcfAsyKeyGenerator *generator = nullptr;
    res = HcfAsyKeyGeneratorCreate("SM2_256", &generator);
    EXPECT_EQ(res, HCF_SUCCESS);
    HcfKeyPair *keyPair = nullptr;
    res = generator->generateKeyPair(generator, nullptr, &keyPair);
    EXPECT_EQ(res, HCF_SUCCESS);

    HcfCipher *cipher = nullptr;
    res = HcfCipherCreate("SM2|SM3", &cipher);
    EXPECT_EQ(res, HCF_SUCCESS);
    res = cipher->init(cipher, (enum HcfCryptoMode)123, (HcfKey *)keyPair->pubKey, nullptr);
    EXPECT_NE(res, HCF_SUCCESS);

    HcfObjDestroy(keyPair);
    HcfObjDestroy(generator);
    HcfObjDestroy(cipher);
}

HWTEST_F(CryptoSm2CipherTest, CryptoSm2CipherTest009, TestSize.Level0)
{
    HcfResult res = HCF_SUCCESS;
    HcfAsyKeyGenerator *generator = nullptr;
    res = HcfAsyKeyGeneratorCreate("SM2_256", &generator);
    EXPECT_EQ(res, HCF_SUCCESS);
    HcfKeyPair *keyPair = nullptr;
    res = generator->generateKeyPair(generator, nullptr, &keyPair);
    EXPECT_EQ(res, HCF_SUCCESS);

    HcfCipher *cipher = nullptr;
    res = HcfCipherCreate("SM2|SM3", &cipher);
    EXPECT_EQ(res, HCF_SUCCESS);
    res = cipher->init(cipher, DECRYPT_MODE, (HcfKey *)keyPair->priKey, nullptr);
    EXPECT_EQ(res, HCF_SUCCESS);

    HcfObjDestroy(keyPair);
    HcfObjDestroy(generator);
    HcfObjDestroy(cipher);
}

// init incorrect case
HWTEST_F(CryptoSm2CipherTest, CryptoSm2CipherTest010, TestSize.Level0)
{
    HcfResult res = HCF_SUCCESS;
    HcfAsyKeyGenerator *generator = nullptr;
    res = HcfAsyKeyGeneratorCreate("SM2_256", &generator);
    EXPECT_EQ(res, HCF_SUCCESS);
    HcfKeyPair *keyPair = nullptr;
    res = generator->generateKeyPair(generator, nullptr, &keyPair);
    EXPECT_EQ(res, HCF_SUCCESS);

    HcfCipher *cipher = nullptr;
    res = HcfCipherCreate("SM2|SM3", &cipher);
    EXPECT_EQ(res, HCF_SUCCESS);
    res = cipher->init(cipher, ENCRYPT_MODE, (HcfKey *)keyPair->priKey, nullptr);
    EXPECT_NE(res, HCF_SUCCESS);

    HcfObjDestroy(keyPair);
    HcfObjDestroy(generator);
    HcfObjDestroy(cipher);
}

HWTEST_F(CryptoSm2CipherTest, CryptoSm2CipherTest011, TestSize.Level0)
{
    HcfResult res = HCF_SUCCESS;
    HcfAsyKeyGenerator *generator = nullptr;
    res = HcfAsyKeyGeneratorCreate("SM2_256", &generator);
    EXPECT_EQ(res, HCF_SUCCESS);
    HcfKeyPair *keyPair = nullptr;
    res = generator->generateKeyPair(generator, nullptr, &keyPair);
    EXPECT_EQ(res, HCF_SUCCESS);

    HcfCipher *cipher = nullptr;
    res = HcfCipherCreate("SM2|SM3", &cipher);
    EXPECT_EQ(res, HCF_SUCCESS);
    res = cipher->init(cipher, DECRYPT_MODE, (HcfKey *)keyPair->pubKey, nullptr);
    EXPECT_NE(res, HCF_SUCCESS);

    HcfObjDestroy(keyPair);
    HcfObjDestroy(generator);
    HcfObjDestroy(cipher);
}

HWTEST_F(CryptoSm2CipherTest, CryptoSm2CipherTest012, TestSize.Level0)
{
    HcfResult res = HCF_SUCCESS;
    HcfAsyKeyGenerator *generator = nullptr;
    res = HcfAsyKeyGeneratorCreate("SM2_256", &generator);
    EXPECT_EQ(res, HCF_SUCCESS);
    HcfKeyPair *keyPair = nullptr;
    res = generator->generateKeyPair(generator, nullptr, &keyPair);
    EXPECT_EQ(res, HCF_SUCCESS);

    HcfCipher *cipher = nullptr;
    res = HcfCipherCreate("SM2|SM3", &cipher);
    EXPECT_EQ(res, HCF_SUCCESS);
    res = cipher->init(nullptr, DECRYPT_MODE, (HcfKey *)keyPair->priKey, nullptr);
    EXPECT_NE(res, HCF_SUCCESS);

    HcfObjDestroy(keyPair);
    HcfObjDestroy(generator);
    HcfObjDestroy(cipher);
}

// incorrect case: use diff class, we ignore it in this version
HWTEST_F(CryptoSm2CipherTest, CryptoSm2CipherTest013, TestSize.Level0)
{
    HcfResult res = HCF_SUCCESS;
    HcfAsyKeyGenerator *generator = nullptr;
    res = HcfAsyKeyGeneratorCreate("SM2_256", &generator);
    EXPECT_EQ(res, HCF_SUCCESS);
    HcfKeyPair *keyPair = nullptr;
    res = generator->generateKeyPair(generator, nullptr, &keyPair);
    EXPECT_EQ(res, HCF_SUCCESS);

    HcfCipher *aesCipher = nullptr;
    res = HcfCipherCreate("AES128|ECB|PKCS7", &aesCipher);
    EXPECT_EQ(res, HCF_SUCCESS);

    HcfCipher *cipher = nullptr;
    res = HcfCipherCreate("SM2|SM3", &cipher);
    EXPECT_EQ(res, HCF_SUCCESS);
    res = cipher->init(aesCipher, DECRYPT_MODE, (HcfKey *)keyPair->priKey, nullptr);
    EXPECT_NE(res, HCF_SUCCESS);

    HcfObjDestroy(keyPair);
    HcfObjDestroy(generator);
    HcfObjDestroy(cipher);
    HcfObjDestroy(aesCipher);
}

HWTEST_F(CryptoSm2CipherTest, CryptoSm2CipherTest014, TestSize.Level0)
{
    HcfResult res = HCF_SUCCESS;
    HcfCipher *cipher = nullptr;
    res = HcfCipherCreate("SM2|SM3", &cipher);
    EXPECT_EQ(res, HCF_SUCCESS);
    res = cipher->init(cipher, DECRYPT_MODE, nullptr, nullptr);
    EXPECT_NE(res, HCF_SUCCESS);
    HcfObjDestroy(cipher);
}

// correct case: update not support
HWTEST_F(CryptoSm2CipherTest, CryptoSm2CipherTest015, TestSize.Level0)
{
    uint8_t plan[] = "this is sm2 cipher test!\0";
    HcfResult res = HCF_SUCCESS;
    HcfAsyKeyGenerator *generator = nullptr;
    res = HcfAsyKeyGeneratorCreate("SM2_256", &generator);
    EXPECT_EQ(res, HCF_SUCCESS);
    HcfKeyPair *keyPair = nullptr;
    res = generator->generateKeyPair(generator, nullptr, &keyPair);
    EXPECT_EQ(res, HCF_SUCCESS);

    HcfBlob input = {.data = (uint8_t *)plan, .len = strlen((char *)plan) + 1};
    HcfBlob encoutput = {.data = nullptr, .len = 0};
    HcfCipher *cipher = nullptr;
    res = HcfCipherCreate("SM2|SM3", &cipher);
    EXPECT_EQ(res, HCF_SUCCESS);
    res = cipher->init(cipher, ENCRYPT_MODE, (HcfKey *)keyPair->pubKey, nullptr);
    EXPECT_EQ(res, HCF_SUCCESS);
    res = cipher->update(cipher, &input, &encoutput);
    EXPECT_NE(res, HCF_SUCCESS);
    EXPECT_EQ(encoutput.data, nullptr);

    HcfObjDestroy(keyPair);
    HcfObjDestroy(generator);
    HcfObjDestroy(cipher);
}

// dofinal correct case
HWTEST_F(CryptoSm2CipherTest, CryptoSm2CipherTest016, TestSize.Level0)
{
    HcfResult res = HCF_SUCCESS;
    uint8_t plan[] = "this is sm2 cipher test!\0";
    HcfAsyKeyGenerator *generator = nullptr;
    res = HcfAsyKeyGeneratorCreate("SM2_256", &generator);
    EXPECT_EQ(res, HCF_SUCCESS);
    HcfKeyPair *keyPair = nullptr;
    res = generator->generateKeyPair(generator, nullptr, &keyPair);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(keyPair, nullptr);
    EXPECT_NE(keyPair->priKey, nullptr);
    EXPECT_NE(keyPair->pubKey, nullptr);

    HcfBlob input = {.data = (uint8_t *)plan, .len = strlen((char *)plan) + 1};
    HcfBlob encoutput = {.data = nullptr, .len = 0};
    HcfCipher *cipher = nullptr;
    res = HcfCipherCreate("SM2|SM3", &cipher);
    EXPECT_EQ(res, HCF_SUCCESS);

    res = cipher->init(cipher, ENCRYPT_MODE, (HcfKey *)keyPair->pubKey, nullptr);
    EXPECT_EQ(res, HCF_SUCCESS);
    res = cipher->doFinal(cipher, &input, &encoutput);
    EXPECT_EQ(res, HCF_SUCCESS);
    HcfObjDestroy(cipher);

    HcfBlob decoutput = {.data = nullptr, .len = 0};
    cipher = nullptr;
    res = HcfCipherCreate("SM2|SM3", &cipher);
    EXPECT_EQ(res, HCF_SUCCESS);
    res = cipher->init(cipher, DECRYPT_MODE, (HcfKey *)keyPair->priKey, nullptr);
    EXPECT_EQ(res, HCF_SUCCESS);
    res = cipher->doFinal(cipher, &encoutput, &decoutput);
    EXPECT_EQ(res, HCF_SUCCESS);
    HcfObjDestroy(cipher);
    EXPECT_STREQ((char *)plan, (char *)decoutput.data);

    HcfFree(encoutput.data);
    HcfFree(decoutput.data);

    HcfObjDestroy(keyPair);
    HcfObjDestroy(generator);
}

// Correct case: test genEncoded and convert key
HWTEST_F(CryptoSm2CipherTest, CryptoSm2CipherTest017, TestSize.Level0)
{
    uint8_t plan[] = "this is sm2 cipher test!\0";
    HcfAsyKeyGenerator *generator = nullptr;
    HcfResult res = HcfAsyKeyGeneratorCreate("SM2_256", &generator);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(generator, nullptr);

    HcfKeyPair *keyPair = nullptr;
    res = generator->generateKeyPair(generator, nullptr, &keyPair);
    EXPECT_EQ(res, HCF_SUCCESS);
    HcfBlob pubKeyBlob = {.data = nullptr, .len = 0};
    HcfBlob priKeyBlob = {.data = nullptr, .len = 0};
    res = keyPair->pubKey->base.getEncoded((HcfKey *)keyPair->pubKey, &pubKeyBlob);
    EXPECT_EQ(res, HCF_SUCCESS);
    res = keyPair->priKey->base.getEncoded((HcfKey *)keyPair->priKey, &priKeyBlob);
    EXPECT_EQ(res, HCF_SUCCESS);

    HcfKeyPair *dupKeyPair = nullptr;
    res = generator->convertKey(generator, nullptr, &pubKeyBlob, &priKeyBlob, &dupKeyPair);
    EXPECT_EQ(res, HCF_SUCCESS);

    HcfObjDestroy(generator);
    HcfObjDestroy(keyPair);

    HcfBlob input = {.data = (uint8_t *)plan, .len = strlen((char *)plan) + 1};
    HcfBlob encoutput = {.data = nullptr, .len = 0};
    HcfCipher *cipher = nullptr;
    res = HcfCipherCreate("SM2|SM3", &cipher);
    EXPECT_EQ(res, HCF_SUCCESS);

    res = cipher->init(cipher, ENCRYPT_MODE, (HcfKey *)dupKeyPair->pubKey, nullptr);
    EXPECT_EQ(res, HCF_SUCCESS);
    res = cipher->doFinal(cipher, &input, &encoutput);
    EXPECT_EQ(res, HCF_SUCCESS);
    HcfObjDestroy(cipher);

    HcfBlob decoutput = {.data = nullptr, .len = 0};
    cipher = nullptr;
    res = HcfCipherCreate("SM2|SM3", &cipher);
    EXPECT_EQ(res, HCF_SUCCESS);
    res = cipher->init(cipher, DECRYPT_MODE, (HcfKey *)dupKeyPair->priKey, nullptr);
    EXPECT_EQ(res, HCF_SUCCESS);
    res = cipher->doFinal(cipher, &encoutput, &decoutput);
    EXPECT_EQ(res, HCF_SUCCESS);
    HcfObjDestroy(cipher);
    EXPECT_STREQ((char *)plan, (char *)decoutput.data);

    HcfFree(encoutput.data);
    HcfFree(decoutput.data);
    HcfFree(pubKeyBlob.data);
    HcfFree(priKeyBlob.data);
    HcfObjDestroy(dupKeyPair);
}

HWTEST_F(CryptoSm2CipherTest, CryptoSm2CipherTest018, TestSize.Level0)
{
    HcfResult res = HCF_SUCCESS;
    HcfAsyKeyGenerator *generator = nullptr;
    res = HcfAsyKeyGeneratorCreate("SM2_256", &generator);
    EXPECT_EQ(res, HCF_SUCCESS);

    HcfKeyPair *keyPair = nullptr;
    res = generator->generateKeyPair(generator, nullptr, &keyPair);
    HcfCipher *cipher = nullptr;
    res = HcfCipherCreate("SM2|SM3", &cipher);
    EXPECT_EQ(res, HCF_SUCCESS);

    res = cipher->init((HcfCipher *)generator, ENCRYPT_MODE, (HcfKey *)keyPair->pubKey, nullptr);
    EXPECT_NE(res, HCF_SUCCESS);

    HcfObjDestroy(generator);
    HcfObjDestroy(cipher);
    HcfObjDestroy(keyPair);
}

HWTEST_F(CryptoSm2CipherTest, CryptoSm2CipherTest019, TestSize.Level0)
{
    HcfResult res = HCF_SUCCESS;
    HcfAsyKeyGenerator *generator = nullptr;
    res = HcfAsyKeyGeneratorCreate("SM2_256", &generator);
    HcfKeyPair *keyPair = nullptr;
    res = generator->generateKeyPair(generator, nullptr, &keyPair);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(keyPair, nullptr);
    EXPECT_NE(keyPair->priKey, nullptr);
    EXPECT_NE(keyPair->pubKey, nullptr);

    HcfCipher *cipher = nullptr;
    res = HcfCipherCreate("SM2|SM3", &cipher);
    EXPECT_EQ(res, HCF_SUCCESS);

    uint8_t plan[] = "12312123123";
    HcfBlob input = {.data = (uint8_t *)plan, .len = strlen((char *)plan)};

    res = cipher->init(cipher, ENCRYPT_MODE, (HcfKey *)keyPair->pubKey, nullptr);
    EXPECT_EQ(res, HCF_SUCCESS);

    res = cipher->doFinal(cipher, &input, nullptr);
    EXPECT_NE(res, HCF_SUCCESS);

    HcfObjDestroy(keyPair);
    HcfObjDestroy(generator);
    HcfObjDestroy(cipher);
}

HWTEST_F(CryptoSm2CipherTest, CryptoSm2CipherTest020, TestSize.Level0)
{
    HcfResult res = HCF_SUCCESS;
    HcfAsyKeyGenerator *generator = nullptr;
    res = HcfAsyKeyGeneratorCreate("SM2_256", &generator);
    HcfKeyPair *keyPair = nullptr;
    res = generator->generateKeyPair(generator, nullptr, &keyPair);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(keyPair, nullptr);
    EXPECT_NE(keyPair->priKey, nullptr);
    EXPECT_NE(keyPair->pubKey, nullptr);

    HcfCipher *cipher = nullptr;
    res = HcfCipherCreate("SM2|SM3", &cipher);
    EXPECT_EQ(res, HCF_SUCCESS);

    uint8_t plan[] = "12312123123";
    HcfBlob input = {.data = (uint8_t *)plan, .len = strlen((char *)plan)};

    res = cipher->init(cipher, ENCRYPT_MODE, (HcfKey *)keyPair->pubKey, nullptr);
    EXPECT_EQ(res, HCF_SUCCESS);

    HcfBlob blob;
    res = cipher->doFinal((HcfCipher *)generator, &input, &blob);
    EXPECT_NE(res, HCF_SUCCESS);

    HcfObjDestroy(keyPair);
    HcfObjDestroy(generator);
    HcfObjDestroy(cipher);
}

HWTEST_F(CryptoSm2CipherTest, CryptoSm2CipherTest021, TestSize.Level0)
{
    HcfResult res = HCF_SUCCESS;
    HcfCipher *cipher = nullptr;
    res = HcfCipherCreate("SM5|PK1", &cipher);
    EXPECT_NE(res, HCF_SUCCESS);
}

// incorrect : init Cipher twice
HWTEST_F(CryptoSm2CipherTest, CryptoSm2CipherTest022, TestSize.Level0)
{
    HcfResult res = HCF_SUCCESS;
    HcfAsyKeyGenerator *generator = nullptr;
    res = HcfAsyKeyGeneratorCreate("SM2_256", &generator);
    EXPECT_EQ(res, HCF_SUCCESS);
    HcfKeyPair *keyPair = nullptr;
    res = generator->generateKeyPair(generator, nullptr, &keyPair);
    EXPECT_EQ(res, HCF_SUCCESS);

    HcfCipher *cipher = nullptr;
    res = HcfCipherCreate("SM2|SM3", &cipher);
    EXPECT_EQ(res, HCF_SUCCESS);
    res = cipher->init(cipher, DECRYPT_MODE, (HcfKey *)keyPair->priKey, nullptr);
    EXPECT_EQ(res, HCF_SUCCESS);
    res = cipher->init(cipher, DECRYPT_MODE, (HcfKey *)keyPair->priKey, nullptr);
    EXPECT_NE(res, HCF_SUCCESS);

    HcfObjDestroy(keyPair);
    HcfObjDestroy(generator);
    HcfObjDestroy(cipher);
}

HWTEST_F(CryptoSm2CipherTest, CryptoSm2CipherTest023, TestSize.Level0)
{
    HcfResult res = HCF_SUCCESS;
    HcfAsyKeyGenerator *generator = nullptr;
    res = HcfAsyKeyGeneratorCreate("SM2_256", &generator);
    EXPECT_EQ(res, HCF_SUCCESS);
    HcfKeyPair *keyPair = nullptr;
    res = generator->generateKeyPair(generator, nullptr, &keyPair);
    EXPECT_EQ(res, HCF_SUCCESS);

    HcfCipher *cipher = nullptr;
    res = HcfCipherCreate("SM2|SM3", &cipher);
    EXPECT_EQ(res, HCF_SUCCESS);
    res = cipher->init(nullptr, ENCRYPT_MODE, (HcfKey *)keyPair->pubKey, nullptr);
    EXPECT_NE(res, HCF_SUCCESS);

    HcfObjDestroy(keyPair);
    HcfObjDestroy(generator);
    HcfObjDestroy(cipher);
}

HWTEST_F(CryptoSm2CipherTest, CryptoSm2CipherTest024, TestSize.Level0)
{
    HcfResult res = HCF_SUCCESS;
    HcfAsyKeyGenerator *generator = nullptr;
    res = HcfAsyKeyGeneratorCreate("SM2_256", &generator);
    EXPECT_EQ(res, HCF_SUCCESS);
    HcfKeyPair *keyPair = nullptr;
    res = generator->generateKeyPair(generator, nullptr, &keyPair);
    EXPECT_EQ(res, HCF_SUCCESS);

    HcfCipher *cipher = nullptr;
    res = HcfCipherCreate("SM2|SM3", &cipher);
    EXPECT_EQ(res, HCF_SUCCESS);
    res = cipher->init(cipher, ENCRYPT_MODE, nullptr, nullptr);
    EXPECT_NE(res, HCF_SUCCESS);

    HcfObjDestroy(keyPair);
    HcfObjDestroy(generator);
    HcfObjDestroy(cipher);
}

HWTEST_F(CryptoSm2CipherTest, CryptoSm2CipherTest025, TestSize.Level0)
{
    HcfResult res = HCF_SUCCESS;
    HcfAsyKeyGenerator *generator = nullptr;
    res = HcfAsyKeyGeneratorCreate("SM2_256", &generator);
    EXPECT_EQ(res, HCF_SUCCESS);
    HcfKeyPair *keyPair = nullptr;
    res = generator->generateKeyPair(generator, nullptr, &keyPair);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(keyPair, nullptr);
    EXPECT_NE(keyPair->priKey, nullptr);
    EXPECT_NE(keyPair->pubKey, nullptr);

    HcfBlob encoutput = {.data = nullptr, .len = 0};
    HcfCipher *cipher = nullptr;
    res = HcfCipherCreate("SM2|SM3", &cipher);
    EXPECT_EQ(res, HCF_SUCCESS);

    res = cipher->init(cipher, ENCRYPT_MODE, (HcfKey *)keyPair->pubKey, nullptr);
    EXPECT_EQ(res, HCF_SUCCESS);
    res = cipher->doFinal(cipher, nullptr, &encoutput);
    EXPECT_NE(res, HCF_SUCCESS);
    HcfObjDestroy(cipher);

    HcfFree(encoutput.data);

    HcfObjDestroy(keyPair);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoSm2CipherTest, CryptoSm2CipherTest026, TestSize.Level0)
{
    HcfResult res = HCF_SUCCESS;
    uint8_t plan[] = "this is sm2 cipher test!\0";
    HcfAsyKeyGenerator *generator = nullptr;
    res = HcfAsyKeyGeneratorCreate("SM2_256", &generator);
    EXPECT_EQ(res, HCF_SUCCESS);
    HcfKeyPair *keyPair = nullptr;
    res = generator->generateKeyPair(generator, nullptr, &keyPair);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(keyPair, nullptr);
    EXPECT_NE(keyPair->priKey, nullptr);
    EXPECT_NE(keyPair->pubKey, nullptr);

    HcfBlob encoutput = {.data = nullptr, .len = 0};
    HcfCipher *cipher = nullptr;
    res = HcfCipherCreate("SM2|SM3", &cipher);
    EXPECT_EQ(res, HCF_SUCCESS);
    HcfBlob input = {.data = (uint8_t *)plan, .len = strlen((char *)plan) + 1};
    res = cipher->init(cipher, ENCRYPT_MODE, (HcfKey *)keyPair->pubKey, nullptr);
    EXPECT_EQ(res, HCF_SUCCESS);
    res = cipher->doFinal(nullptr, &input, &encoutput);
    EXPECT_NE(res, HCF_SUCCESS);
    HcfObjDestroy(cipher);

    HcfFree(encoutput.data);

    HcfObjDestroy(keyPair);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoSm2CipherTest, CryptoSm2CipherTest027, TestSize.Level0)
{
    HcfResult res = HCF_SUCCESS;
    HcfCipher *cipher = nullptr;
    res = HcfCipherCreate("SM2|SM3", &cipher);
    EXPECT_EQ(res, HCF_SUCCESS);

    cipher->base.destroy(nullptr);

    HcfObjDestroy(cipher);
}

HWTEST_F(CryptoSm2CipherTest, CryptoSm2CipherTest028, TestSize.Level0)
{
    HcfResult res = HCF_SUCCESS;
    HcfCipher *cipher = nullptr;
    res = HcfCipherCreate("SM2|SM3", &cipher);
    EXPECT_EQ(res, HCF_SUCCESS);

    cipher->base.destroy(&obj);

    HcfObjDestroy(cipher);
}

HWTEST_F(CryptoSm2CipherTest, CryptoSm2CipherTest029, TestSize.Level0)
{
    HcfResult res = HCF_SUCCESS;
    HcfCipherGeneratorSpi *cipher = nullptr;
    res = HcfCipherSm2CipherSpiCreate(nullptr, &cipher);

    ASSERT_EQ(res, HCF_INVALID_PARAMS);
    ASSERT_EQ(cipher, nullptr);

    HcfObjDestroy(cipher);
}

HWTEST_F(CryptoSm2CipherTest, CryptoSm2CipherTest030, TestSize.Level0)
{
    HcfResult res = HCF_SUCCESS;
    HcfCipherGeneratorSpi *cipher = nullptr;
    CipherAttr params = {
        .algo = HCF_ALG_SM2,
        .md = HCF_OPENSSL_DIGEST_SM3,
    };
    res = HcfCipherSm2CipherSpiCreate(&params, nullptr);
    ASSERT_EQ(res, HCF_INVALID_PARAMS);
    HcfObjDestroy(cipher);
}

HWTEST_F(CryptoSm2CipherTest, CryptoSm2CipherTest031, TestSize.Level0)
{
    HcfResult res = HCF_SUCCESS;
    HcfCipherGeneratorSpi *cipher = nullptr;
    CipherAttr params = {
        .algo = HCF_ALG_SM2,
        .md = HCF_OPENSSL_DIGEST_SM3,
    };
    res = HcfCipherSm2CipherSpiCreate(&params, &cipher);
    EXPECT_EQ(res, HCF_SUCCESS);
    res = cipher->init(cipher, (enum HcfCryptoMode)123, (HcfKey *)sm2256KeyPair_->pubKey, nullptr);
    ASSERT_EQ(res, HCF_INVALID_PARAMS);

    HcfObjDestroy(cipher);
}

HWTEST_F(CryptoSm2CipherTest, CryptoSm2CipherTest032, TestSize.Level0)
{
    HcfResult res = HCF_SUCCESS;
    HcfCipherGeneratorSpi *cipher = nullptr;
    CipherAttr params = {
        .algo = HCF_ALG_SM2,
        .md = HCF_OPENSSL_DIGEST_SM3,
    };
    res = HcfCipherSm2CipherSpiCreate(&params, &cipher);
    EXPECT_EQ(res, HCF_SUCCESS);
    res = cipher->init(cipher, ENCRYPT_MODE, nullptr, nullptr);
    ASSERT_EQ(res, HCF_INVALID_PARAMS);

    HcfObjDestroy(cipher);
}

HWTEST_F(CryptoSm2CipherTest, CryptoSm2CipherTest033, TestSize.Level0)
{
    HcfResult res = HCF_SUCCESS;
    HcfCipherGeneratorSpi *cipher = nullptr;
    CipherAttr params = {
        .algo = HCF_ALG_SM2,
        .md = HCF_OPENSSL_DIGEST_SM3,
    };
    res = HcfCipherSm2CipherSpiCreate(&params, &cipher);
    EXPECT_EQ(res, HCF_SUCCESS);
    res = cipher->init(cipher, ENCRYPT_MODE, (HcfKey *)sm2256KeyPair_->priKey, nullptr);
    ASSERT_EQ(res, HCF_INVALID_PARAMS);

    HcfObjDestroy(cipher);
}

HWTEST_F(CryptoSm2CipherTest, CryptoSm2CipherTest034, TestSize.Level0)
{
    HcfResult res = HCF_SUCCESS;
    HcfCipherGeneratorSpi *cipher = nullptr;
    CipherAttr params = {
        .algo = HCF_ALG_SM2,
        .md = HCF_OPENSSL_DIGEST_SM3,
    };
    const char *message = "hello world";
    HcfBlob input = {
        .data = (uint8_t *)message,
        .len = 12
    };
    res = HcfCipherSm2CipherSpiCreate(&params, &cipher);
    EXPECT_EQ(res, HCF_SUCCESS);
    res = cipher->doFinal(cipher, &input, nullptr);
    ASSERT_EQ(res, HCF_INVALID_PARAMS);

    HcfObjDestroy(cipher);
}

HWTEST_F(CryptoSm2CipherTest, CryptoSm2CipherTest035, TestSize.Level0)
{
    HcfResult res = HCF_SUCCESS;
    HcfCipherGeneratorSpi *cipher = nullptr;
    CipherAttr params = {
        .algo = HCF_ALG_SM2,
        .md = HCF_OPENSSL_DIGEST_SM3,
    };
    HcfBlob out = { .data = nullptr, .len = 0 };
    res = HcfCipherSm2CipherSpiCreate(&params, &cipher);
    EXPECT_EQ(res, HCF_SUCCESS);
    res = cipher->doFinal(cipher, nullptr, &out);
    ASSERT_EQ(res, HCF_INVALID_PARAMS);

    HcfObjDestroy(cipher);
}

HWTEST_F(CryptoSm2CipherTest, CryptoSm2CipherTest036, TestSize.Level0)
{
    HcfResult res = HCF_SUCCESS;
    HcfCipherGeneratorSpi *cipher = nullptr;
    CipherAttr params = {
        .algo = HCF_ALG_SM2,
        .md = HCF_OPENSSL_DIGEST_SM3,
    };
    const char *message = "hello world";
    HcfBlob input = {
        .data = (uint8_t *)message,
        .len = 12
    };
    HcfBlob out = { .data = nullptr, .len = 0 };
    res = HcfCipherSm2CipherSpiCreate(&params, &cipher);
    EXPECT_EQ(res, HCF_SUCCESS);
    res = cipher->doFinal(nullptr, &input, &out);
    ASSERT_EQ(res, HCF_INVALID_PARAMS);

    HcfObjDestroy(cipher);
}

HWTEST_F(CryptoSm2CipherTest, CryptoSm2CipherTest037, TestSize.Level0)
{
    HcfResult res = HCF_SUCCESS;
    HcfCipherGeneratorSpi *cipher = nullptr;
    CipherAttr params = {
        .algo = HCF_ALG_SM2,
        .md = HCF_OPENSSL_DIGEST_SM3,
    };
    HcfBlob input = {
        .data = nullptr,
        .len = 12
    };
    HcfBlob out = { .data = nullptr, .len = 0 };
    res = HcfCipherSm2CipherSpiCreate(&params, &cipher);
    EXPECT_EQ(res, HCF_SUCCESS);
    res = cipher->doFinal(cipher, &input, &out);
    ASSERT_EQ(res, HCF_INVALID_PARAMS);

    HcfObjDestroy(cipher);
}

HWTEST_F(CryptoSm2CipherTest, CryptoSm2CipherTest038, TestSize.Level0)
{
    HcfResult res = HCF_SUCCESS;
    HcfCipherGeneratorSpi *cipher = nullptr;
    CipherAttr params = {
        .algo = HCF_ALG_SM2,
        .md = HCF_OPENSSL_DIGEST_SM3,
    };
    const char *message = "hello world";
    HcfBlob input = {
        .data = (uint8_t *)message,
        .len = 0
    };
    HcfBlob out = { .data = nullptr, .len = 0 };
    res = HcfCipherSm2CipherSpiCreate(&params, &cipher);
    EXPECT_EQ(res, HCF_SUCCESS);
    res = cipher->doFinal(cipher, &input, &out);
    ASSERT_EQ(res, HCF_INVALID_PARAMS);

    HcfObjDestroy(cipher);
}

HWTEST_F(CryptoSm2CipherTest, CryptoSm2CipherTest039, TestSize.Level0)
{
    HcfResult res = HCF_SUCCESS;
    HcfCipher *cipher = nullptr;
    res = HcfCipherCreate("SM2|NoHash", &cipher);
    EXPECT_NE(res, HCF_SUCCESS);
    EXPECT_EQ(cipher, nullptr);
}

HWTEST_F(CryptoSm2CipherTest, CryptoSm2CipherTest040, TestSize.Level0)
{
    HcfResult res = HCF_SUCCESS;
    HcfCipherGeneratorSpi *cipher = nullptr;
    CipherAttr params = {
        .algo = HCF_ALG_SM2,
        .md = HCF_OPENSSL_DIGEST_SM3,
    };
    res = HcfCipherSm2CipherSpiCreate(&params, &cipher);
    EXPECT_EQ(res, HCF_SUCCESS);
    cipher->base.destroy(nullptr);
    HcfObjDestroy(cipher);
}

HWTEST_F(CryptoSm2CipherTest, CryptoSm2CipherTest042, TestSize.Level0)
{
    HcfResult res = HCF_SUCCESS;
    HcfAsyKeyGenerator *generator = nullptr;
    res = HcfAsyKeyGeneratorCreate("SM2_256", &generator);
    EXPECT_EQ(res, HCF_SUCCESS);
    HcfKeyPair *keyPair = nullptr;
    res = generator->generateKeyPair(generator, nullptr, &keyPair);
    EXPECT_EQ(res, HCF_SUCCESS);
    HcfCipher *cipher = nullptr;
    res = HcfCipherCreate("SM2|SM3", &cipher);
    EXPECT_EQ(res, HCF_SUCCESS);
    res = cipher->init(cipher, ENCRYPT_MODE, (HcfKey *)keyPair->priKey, nullptr);
    EXPECT_NE(res, HCF_SUCCESS);

    HcfObjDestroy(keyPair);
    HcfObjDestroy(generator);
    HcfObjDestroy(cipher);
}

HWTEST_F(CryptoSm2CipherTest, CryptoSm2CipherTest048, TestSize.Level0)
{
    HcfResult res = HCF_SUCCESS;
    HcfAsyKeyGenerator *generator = nullptr;
    res = HcfAsyKeyGeneratorCreate("SM2_256", &generator);
    EXPECT_EQ(res, HCF_SUCCESS);
    HcfKeyPair *keyPair = nullptr;
    res = generator->generateKeyPair(generator, nullptr, &keyPair);
    EXPECT_EQ(res, HCF_SUCCESS);
    HcfCipherGeneratorSpi *cipher = nullptr;
    CipherAttr params = {
        .algo = HCF_ALG_SM2,
        .md = HCF_OPENSSL_DIGEST_SM3,
    };
    res = HcfCipherSm2CipherSpiCreate(&params, &cipher);
    EXPECT_EQ(res, HCF_SUCCESS);
    res = cipher->init(cipher, ENCRYPT_MODE, (HcfKey *)keyPair->pubKey, nullptr);
    EXPECT_EQ(res, HCF_SUCCESS);
    char *returnStr = nullptr;
    res = cipher->getCipherSpecString(cipher, SM2_MD_NAME_STR, &returnStr);
    EXPECT_EQ(res, HCF_SUCCESS);

    HcfFree(returnStr);
    HcfObjDestroy(keyPair);
    HcfObjDestroy(generator);
    HcfObjDestroy(cipher);
}

HWTEST_F(CryptoSm2CipherTest, CryptoSm2CipherTest049, TestSize.Level0)
{
    HcfResult res = HCF_SUCCESS;
    HcfAsyKeyGenerator *generator = nullptr;
    res = HcfAsyKeyGeneratorCreate("SM2_256", &generator);
    EXPECT_EQ(res, HCF_SUCCESS);
    HcfKeyPair *keyPair = nullptr;
    res = generator->generateKeyPair(generator, nullptr, &keyPair);
    EXPECT_EQ(res, HCF_SUCCESS);
    HcfCipherGeneratorSpi *cipher = nullptr;
    CipherAttr params = {
        .algo = HCF_ALG_SM2,
        .md = HCF_OPENSSL_DIGEST_SM3,
    };
    res = HcfCipherSm2CipherSpiCreate(&params, &cipher);
    EXPECT_EQ(res, HCF_SUCCESS);
    res = cipher->init(cipher, ENCRYPT_MODE, (HcfKey *)keyPair->pubKey, nullptr);
    EXPECT_EQ(res, HCF_SUCCESS);
    char *returnStr = nullptr;
    res = cipher->getCipherSpecString(cipher, OAEP_MGF1_PSRC_UINT8ARR, &returnStr);
    EXPECT_EQ(res, HCF_INVALID_PARAMS);

    HcfFree(returnStr);
    HcfObjDestroy(keyPair);
    HcfObjDestroy(generator);
    HcfObjDestroy(cipher);
}

HWTEST_F(CryptoSm2CipherTest, CryptoSm2CipherTest050, TestSize.Level0)
{
    HcfResult res = HCF_SUCCESS;
    HcfAsyKeyGenerator *generator = nullptr;
    res = HcfAsyKeyGeneratorCreate("SM2_256", &generator);
    EXPECT_EQ(res, HCF_SUCCESS);
    HcfKeyPair *keyPair = nullptr;
    res = generator->generateKeyPair(generator, nullptr, &keyPair);
    EXPECT_EQ(res, HCF_SUCCESS);
    HcfCipherGeneratorSpi *cipher = nullptr;
    CipherAttr params = {
        .algo = HCF_ALG_SM2,
        .md = HCF_OPENSSL_DIGEST_SM3,
    };
    res = HcfCipherSm2CipherSpiCreate(&params, &cipher);
    EXPECT_EQ(res, HCF_SUCCESS);
    res = cipher->init(cipher, ENCRYPT_MODE, (HcfKey *)keyPair->pubKey, nullptr);
    EXPECT_EQ(res, HCF_SUCCESS);
    res = cipher->getCipherSpecString(cipher, SM2_MD_NAME_STR, nullptr);
    EXPECT_EQ(res, HCF_INVALID_PARAMS);

    HcfObjDestroy(keyPair);
    HcfObjDestroy(generator);
    HcfObjDestroy(cipher);
}

HWTEST_F(CryptoSm2CipherTest, CryptoSm2CipherTest051, TestSize.Level0)
{
    HcfResult res = HCF_SUCCESS;
    HcfAsyKeyGenerator *generator = nullptr;
    res = HcfAsyKeyGeneratorCreate("SM2_256", &generator);
    EXPECT_EQ(res, HCF_SUCCESS);
    HcfKeyPair *keyPair = nullptr;
    res = generator->generateKeyPair(generator, nullptr, &keyPair);
    EXPECT_EQ(res, HCF_SUCCESS);
    HcfCipherGeneratorSpi *cipher = nullptr;
    CipherAttr params = {
        .algo = HCF_ALG_SM2,
        .md = HCF_OPENSSL_DIGEST_SM3,
    };
    res = HcfCipherSm2CipherSpiCreate(&params, &cipher);
    EXPECT_EQ(res, HCF_SUCCESS);
    res = cipher->init(cipher, ENCRYPT_MODE, (HcfKey *)keyPair->pubKey, nullptr);
    EXPECT_EQ(res, HCF_SUCCESS);
    char *returnStr = nullptr;
    res = cipher->getCipherSpecString(nullptr, SM2_MD_NAME_STR, &returnStr);
    EXPECT_EQ(res, HCF_INVALID_PARAMS);

    HcfFree(returnStr);
    HcfObjDestroy(keyPair);
    HcfObjDestroy(generator);
    HcfObjDestroy(cipher);
}

HWTEST_F(CryptoSm2CipherTest, CryptoSm2CipherTest052, TestSize.Level0)
{
    HcfResult res = HCF_SUCCESS;
    HcfAsyKeyGenerator *generator = nullptr;
    res = HcfAsyKeyGeneratorCreate("SM2_256", &generator);
    EXPECT_EQ(res, HCF_SUCCESS);
    HcfKeyPair *keyPair = nullptr;
    res = generator->generateKeyPair(generator, nullptr, &keyPair);
    EXPECT_EQ(res, HCF_SUCCESS);
    HcfCipherGeneratorSpi *cipher = nullptr;
    CipherAttr params = {
        .algo = HCF_ALG_SM2,
        .md = HCF_OPENSSL_DIGEST_SM3,
    };
    res = HcfCipherSm2CipherSpiCreate(&params, &cipher);
    EXPECT_EQ(res, HCF_SUCCESS);
    res = cipher->init(cipher, DECRYPT_MODE, (HcfKey *)keyPair->priKey, nullptr);
    EXPECT_EQ(res, HCF_SUCCESS);
    char *returnStr = nullptr;
    res = cipher->getCipherSpecString(cipher, SM2_MD_NAME_STR, &returnStr);
    EXPECT_EQ(res, HCF_SUCCESS);

    HcfFree(returnStr);
    HcfObjDestroy(keyPair);
    HcfObjDestroy(generator);
    HcfObjDestroy(cipher);
}

    HWTEST_F(CryptoSm2CipherTest, CryptoSm2CipherTest053, TestSize.Level0)
{
    HcfResult res = HCF_SUCCESS;
    HcfAsyKeyGenerator *generator = nullptr;
    res = HcfAsyKeyGeneratorCreate("SM2_256", &generator);
    EXPECT_EQ(res, HCF_SUCCESS);
    HcfKeyPair *keyPair = nullptr;
    res = generator->generateKeyPair(generator, nullptr, &keyPair);
    EXPECT_EQ(res, HCF_SUCCESS);
    HcfCipherGeneratorSpi *cipher = nullptr;
    CipherAttr params = {
        .algo = HCF_ALG_SM2,
        .md = HCF_OPENSSL_DIGEST_SM3,
    };
    res = HcfCipherSm2CipherSpiCreate(&params, &cipher);
    EXPECT_EQ(res, HCF_SUCCESS);
    res = cipher->init(cipher, DECRYPT_MODE, (HcfKey *)keyPair->priKey, nullptr);
    EXPECT_EQ(res, HCF_SUCCESS);
    char *returnStr = nullptr;
    res = cipher->getCipherSpecString(cipher, OAEP_MGF1_PSRC_UINT8ARR, &returnStr);
    EXPECT_EQ(res, HCF_INVALID_PARAMS);

    HcfFree(returnStr);
    HcfObjDestroy(keyPair);
    HcfObjDestroy(generator);
    HcfObjDestroy(cipher);
}

HWTEST_F(CryptoSm2CipherTest, CryptoSm2CipherTest054, TestSize.Level0)
{
    HcfResult res = HCF_SUCCESS;
    HcfAsyKeyGenerator *generator = nullptr;
    res = HcfAsyKeyGeneratorCreate("SM2_256", &generator);
    EXPECT_EQ(res, HCF_SUCCESS);
    HcfKeyPair *keyPair = nullptr;
    res = generator->generateKeyPair(generator, nullptr, &keyPair);
    EXPECT_EQ(res, HCF_SUCCESS);
    HcfCipherGeneratorSpi *cipher = nullptr;
    CipherAttr params = {
        .algo = HCF_ALG_SM2,
        .md = HCF_OPENSSL_DIGEST_SM3,
    };
    res = HcfCipherSm2CipherSpiCreate(&params, &cipher);
    EXPECT_EQ(res, HCF_SUCCESS);
    res = cipher->init(cipher, DECRYPT_MODE, (HcfKey *)keyPair->priKey, nullptr);
    EXPECT_EQ(res, HCF_SUCCESS);
    res = cipher->getCipherSpecString(cipher, SM2_MD_NAME_STR, nullptr);
    EXPECT_EQ(res, HCF_INVALID_PARAMS);

    HcfObjDestroy(keyPair);
    HcfObjDestroy(generator);
    HcfObjDestroy(cipher);
}

HWTEST_F(CryptoSm2CipherTest, CryptoSm2CipherTest055, TestSize.Level0)
{
    HcfResult res = HCF_SUCCESS;
    HcfAsyKeyGenerator *generator = nullptr;
    res = HcfAsyKeyGeneratorCreate("SM2_256", &generator);
    EXPECT_EQ(res, HCF_SUCCESS);
    HcfKeyPair *keyPair = nullptr;
    res = generator->generateKeyPair(generator, nullptr, &keyPair);
    EXPECT_EQ(res, HCF_SUCCESS);
    HcfCipherGeneratorSpi *cipher = nullptr;
    CipherAttr params = {
        .algo = HCF_ALG_SM2,
        .md = HCF_OPENSSL_DIGEST_SM3,
    };
    res = HcfCipherSm2CipherSpiCreate(&params, &cipher);
    EXPECT_EQ(res, HCF_SUCCESS);
    res = cipher->init(cipher, DECRYPT_MODE, (HcfKey *)keyPair->priKey, nullptr);
    EXPECT_EQ(res, HCF_SUCCESS);
    char *returnStr = nullptr;
    res = cipher->getCipherSpecString(nullptr, SM2_MD_NAME_STR, &returnStr);
    EXPECT_EQ(res, HCF_INVALID_PARAMS);

    HcfFree(returnStr);
    HcfObjDestroy(keyPair);
    HcfObjDestroy(generator);
    HcfObjDestroy(cipher);
}

HWTEST_F(CryptoSm2CipherTest, CryptoSm2CipherTest056, TestSize.Level0)
{
    HcfResult res = HCF_SUCCESS;
    HcfAsyKeyGenerator *generator = nullptr;
    res = HcfAsyKeyGeneratorCreate("SM2_256", &generator);
    EXPECT_EQ(res, HCF_SUCCESS);
    HcfKeyPair *keyPair = nullptr;
    res = generator->generateKeyPair(generator, nullptr, &keyPair);
    EXPECT_EQ(res, HCF_SUCCESS);
    HcfCipherGeneratorSpi *cipher = nullptr;
    CipherAttr params = {
        .algo = HCF_ALG_SM2,
        .md = HCF_OPENSSL_DIGEST_SM3,
    };
    res = HcfCipherSm2CipherSpiCreate(&params, &cipher);
    EXPECT_EQ(res, HCF_SUCCESS);
    res = cipher->init(cipher, DECRYPT_MODE, (HcfKey *)keyPair->priKey, nullptr);
    EXPECT_EQ(res, HCF_SUCCESS);
    HcfBlob returnUint8Array = {.data = nullptr, .len = 0};
    res = cipher->getCipherSpecUint8Array(cipher, SM2_MD_NAME_STR, &returnUint8Array);
    EXPECT_EQ(res, HCF_NOT_SUPPORT);

    HcfFree(returnUint8Array.data);
    HcfObjDestroy(keyPair);
    HcfObjDestroy(generator);
    HcfObjDestroy(cipher);
}

HWTEST_F(CryptoSm2CipherTest, CryptoSm2CipherTest057, TestSize.Level0)
{
    HcfResult res = HCF_SUCCESS;
    HcfAsyKeyGenerator *generator = nullptr;
    res = HcfAsyKeyGeneratorCreate("SM2_256", &generator);
    EXPECT_EQ(res, HCF_SUCCESS);
    HcfKeyPair *keyPair = nullptr;
    res = generator->generateKeyPair(generator, nullptr, &keyPair);
    EXPECT_EQ(res, HCF_SUCCESS);
    HcfCipherGeneratorSpi *cipher = nullptr;
    CipherAttr params = {
        .algo = HCF_ALG_SM2,
        .md = HCF_OPENSSL_DIGEST_SM3,
    };
    res = HcfCipherSm2CipherSpiCreate(&params, &cipher);
    EXPECT_EQ(res, HCF_SUCCESS);
    res = cipher->init(cipher, DECRYPT_MODE, (HcfKey *)keyPair->priKey, nullptr);
    EXPECT_EQ(res, HCF_SUCCESS);
    HcfBlob pSource = {.data = nullptr, .len = 0};
    res = cipher->setCipherSpecUint8Array(cipher, SM2_MD_NAME_STR, pSource);
    EXPECT_EQ(res, HCF_NOT_SUPPORT);

    HcfFree(pSource.data);
    HcfObjDestroy(keyPair);
    HcfObjDestroy(generator);
    HcfObjDestroy(cipher);
}

HWTEST_F(CryptoSm2CipherTest, CryptoSm2CipherTest058, TestSize.Level0)
{
    HcfResult res = HCF_SUCCESS;
    uint8_t plan[] = "this is sm2 cipher test!\0";
    HcfAsyKeyGenerator *generator = nullptr;
    res = HcfAsyKeyGeneratorCreate("SM2_256", &generator);
    EXPECT_EQ(res, HCF_SUCCESS);
    HcfKeyPair *keyPair = nullptr;
    res = generator->generateKeyPair(generator, nullptr, &keyPair);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(keyPair, nullptr);
    EXPECT_NE(keyPair->priKey, nullptr);
    EXPECT_NE(keyPair->pubKey, nullptr);

    HcfBlob input = {.data = (uint8_t *)plan, .len = strlen((char *)plan) + 1};
    HcfBlob encoutput = {.data = nullptr, .len = 0};
    HcfCipherGeneratorSpi *cipher = nullptr;
    CipherAttr params = {
        .algo = HCF_ALG_SM2,
        .md = HCF_OPENSSL_DIGEST_SM3,
    };
    res = HcfCipherSm2CipherSpiCreate(&params, &cipher);
    EXPECT_EQ(res, HCF_SUCCESS);

    res = cipher->init(cipher, ENCRYPT_MODE, (HcfKey *)keyPair->pubKey, nullptr);
    EXPECT_EQ(res, HCF_SUCCESS);
    char *returnStr = nullptr;
    res = cipher->getCipherSpecString(cipher, SM2_MD_NAME_STR, &returnStr);
    EXPECT_EQ(res, HCF_SUCCESS);
    res = cipher->doFinal(cipher, &input, &encoutput);
    EXPECT_EQ(res, HCF_SUCCESS);
    HcfFree(returnStr);
    HcfObjDestroy(cipher);

    HcfBlob decoutput = {.data = nullptr, .len = 0};
    cipher = nullptr;
    res = HcfCipherSm2CipherSpiCreate(&params, &cipher);
    EXPECT_EQ(res, HCF_SUCCESS);
    res = cipher->init(cipher, DECRYPT_MODE, (HcfKey *)keyPair->priKey, nullptr);
    EXPECT_EQ(res, HCF_SUCCESS);
    res = cipher->doFinal(cipher, &encoutput, &decoutput);
    EXPECT_EQ(res, HCF_SUCCESS);
    HcfObjDestroy(cipher);
    EXPECT_STREQ((char *)plan, (char *)decoutput.data);

    HcfFree(encoutput.data);
    HcfFree(decoutput.data);

    HcfObjDestroy(keyPair);
    HcfObjDestroy(generator);
}
}
