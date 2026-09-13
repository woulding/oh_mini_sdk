/*
 * Copyright (C) 2022 Huawei Device Co., Ltd.
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

#include "sym_key_generator.h"
#include "cipher.h"
#include "log.h"
#include "memory.h"
#include "detailed_iv_params.h"
#include "detailed_gcm_params.h"
#include "detailed_ccm_params.h"
#include "des_openssl.h"

using namespace std;
using namespace testing::ext;

namespace {
constexpr int32_t CIPHER_TEXT_LEN = 128;
constexpr int32_t DES_IV_LEN = 8;
constexpr int32_t PLAINTEXT_LEN = 13;

class Crypto3DesCipherTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp();
    void TearDown();
};

void Crypto3DesCipherTest::SetUpTestCase() {}
void Crypto3DesCipherTest::TearDownTestCase() {}

void Crypto3DesCipherTest::SetUp() // add init here, this will be called before test.
{
}

void Crypto3DesCipherTest::TearDown() // add destroy here, this will be called when test case done.
{
}

static HcfResult Generate3DesSymKey(HcfSymKey **key)
{
    HcfSymKeyGenerator *generator = nullptr;

    HcfResult ret = HcfSymKeyGeneratorCreate("3DES192", &generator);
    if (ret != HCF_SUCCESS) {
        LOGE("HcfSymKeyGeneratorCreate failed!");
        return ret;
    }

    ret = generator->generateSymKey(generator, key);
    if (ret != HCF_SUCCESS) {
        LOGE("generateSymKey failed!");
    }
    HcfObjDestroy(generator);
    return ret;
}

static HcfResult GenerateDesSymKey(HcfSymKey **key)
{
    HcfSymKeyGenerator *generator = nullptr;

    HcfResult ret = HcfSymKeyGeneratorCreate("DES64", &generator);
    if (ret != HCF_SUCCESS) {
        LOGE("HcfSymKeyGeneratorCreate failed!");
        return ret;
    }

    ret = generator->generateSymKey(generator, key);
    if (ret != HCF_SUCCESS) {
        LOGE("generateSymKey failed!");
    }
    HcfObjDestroy(generator);
    return ret;
}

static int32_t DesEncrypt(HcfCipher *cipher, HcfSymKey *key, HcfParamsSpec *params,
    uint8_t *cipherText, int *cipherTextLen)
{
    uint8_t plainText[] = "this is test!";
    HcfBlob input = {.data = (uint8_t *)plainText, .len = 13};
    HcfBlob output = {};
    int32_t maxLen = *cipherTextLen;
    int32_t ret = cipher->init(cipher, ENCRYPT_MODE, (HcfKey *)key, params);
    if (ret != 0) {
        LOGE("init failed! %{public}d", ret);
        return ret;
    }

    ret = cipher->update(cipher, &input, &output);
    if (ret != 0) {
        LOGE("update failed!");
        return ret;
    }
    *cipherTextLen = output.len;
    if (output.data != nullptr) {
        if (memcpy_s(cipherText, maxLen, output.data, output.len) != EOK) {
            HcfBlobDataFree(&output);
            return -1;
        }
        HcfBlobDataFree(&output);
    }

    ret = cipher->doFinal(cipher, nullptr, &output);
    if (ret != 0) {
        LOGE("doFinal failed!");
        return ret;
    }
    if (output.data != nullptr) {
        if (memcpy_s(cipherText + *cipherTextLen, maxLen - *cipherTextLen, output.data, output.len) != EOK) {
            HcfBlobDataFree(&output);
            return -1;
        }
        *cipherTextLen += output.len;
        HcfBlobDataFree(&output);
    }
    return 0;
}

static int32_t DesDecrypt(HcfCipher *cipher, HcfSymKey *key, HcfParamsSpec *params,
    uint8_t *cipherText, int cipherTextLen)
{
    uint8_t plainText[] = "this is test!";
    HcfBlob input = {.data = (uint8_t *)cipherText, .len = static_cast<size_t>(cipherTextLen)};
    HcfBlob output = {};
    int32_t maxLen = cipherTextLen;
    int32_t ret = cipher->init(cipher, DECRYPT_MODE, (HcfKey *)key, params);
    if (ret != 0) {
        LOGE("init failed! %{public}d", ret);
        return ret;
    }

    ret = cipher->update(cipher, &input, &output);
    if (ret != 0) {
        LOGE("update failed!");
        return ret;
    }
    cipherTextLen = output.len;
    if (output.data != nullptr) {
        if (memcpy_s(cipherText, maxLen, output.data, output.len) != EOK) {
            HcfBlobDataFree(&output);
            return -1;
        }
        HcfBlobDataFree(&output);
    }

    ret = cipher->doFinal(cipher, nullptr, &output);
    if (ret != 0) {
        LOGE("doFinal failed!");
        return ret;
    }
    if (output.data != nullptr) {
        if (memcpy_s(cipherText + cipherTextLen, maxLen - cipherTextLen, output.data, output.len) != EOK) {
            HcfBlobDataFree(&output);
            return -1;
        }
        cipherTextLen += output.len;
        HcfBlobDataFree(&output);
    }

    if (cipherTextLen != sizeof(plainText) - 1) {
        return -1;
    }
    return memcmp(cipherText, plainText, cipherTextLen);
}

static int32_t DesNoUpdateEncrypt(HcfCipher *cipher, HcfSymKey *key, HcfParamsSpec *params,
    uint8_t *cipherText, int *cipherTextLen)
{
    uint8_t plainText[] = "this is test!";
    HcfBlob input = {.data = (uint8_t *)plainText, .len = 13};
    HcfBlob output = {};
    int32_t maxLen = *cipherTextLen;
    int32_t ret = cipher->init(cipher, ENCRYPT_MODE, (HcfKey *)key, params);
    if (ret != 0) {
        LOGE("init failed! %{public}d", ret);
        return ret;
    }

    *cipherTextLen = 0;
    ret = cipher->doFinal(cipher, &input, &output);
    if (ret != 0) {
        LOGE("doFinal failed!");
        return ret;
    }
    if (output.data != nullptr) {
        if (memcpy_s(cipherText, maxLen, output.data, output.len) != EOK) {
            HcfBlobDataFree(&output);
            return -1;
        }
        *cipherTextLen += output.len;
        HcfBlobDataFree(&output);
    }
    return 0;
}

static int32_t DesNoUpdateDecrypt(HcfCipher *cipher, HcfSymKey *key, HcfParamsSpec *params,
    uint8_t *cipherText, int cipherTextLen)
{
    uint8_t plainText[] = "this is test!";
    HcfBlob input = {.data = (uint8_t *)cipherText, .len = static_cast<size_t>(cipherTextLen)};
    HcfBlob output = {};
    int32_t maxLen = cipherTextLen;
    int32_t ret = cipher->init(cipher, DECRYPT_MODE, (HcfKey *)key, params);
    if (ret != 0) {
        LOGE("init failed! %{public}d", ret);
        return ret;
    }

    cipherTextLen = 0;
    ret = cipher->doFinal(cipher, &input, &output);
    if (ret != 0) {
        LOGE("doFinal failed!");
        return ret;
    }
    if (output.data != nullptr) {
        if (memcpy_s(cipherText, maxLen, output.data, output.len) != EOK) {
            HcfBlobDataFree(&output);
            return -1;
        }
        cipherTextLen += output.len;
        HcfBlobDataFree(&output);
    }

    if (cipherTextLen != sizeof(plainText) - 1) {
        return -1;
    }
    return memcmp(cipherText, plainText, cipherTextLen);
}

HWTEST_F(Crypto3DesCipherTest, Crypto3DesCipherTest001, TestSize.Level0)
{
    uint8_t cipherText[128] = {0};
    int cipherTextLen = 128;

    HcfSymKeyGenerator *generator = nullptr;
    HcfCipher *cipher = nullptr;
    HcfSymKey *key = nullptr;

    int ret = HcfSymKeyGeneratorCreate("3DES192", &generator);
    ASSERT_EQ(ret, 0);

    ret = generator->generateSymKey(generator, &key);
    ASSERT_EQ(ret, 0);

    ret = HcfCipherCreate("3DES192|ECB|NoPadding", &cipher);
    ASSERT_EQ(ret, 0);

    ret = DesEncrypt(cipher, key, nullptr, cipherText, &cipherTextLen);
    ASSERT_NE(ret, 0);

    HcfObjDestroy((HcfObjectBase *)key);
    HcfObjDestroy((HcfObjectBase *)cipher);
    HcfObjDestroy((HcfObjectBase *)generator);
}

HWTEST_F(Crypto3DesCipherTest, Crypto3DesCipherTest002, TestSize.Level0)
{
    uint8_t cipherText[128] = {0};
    int cipherTextLen = 128;

    HcfSymKeyGenerator *generator = nullptr;
    HcfCipher *cipher = nullptr;
    HcfSymKey *key = nullptr;

    int ret = HcfSymKeyGeneratorCreate("3DES192", &generator);
    ASSERT_EQ(ret, 0);

    ret = generator->generateSymKey(generator, &key);
    ASSERT_EQ(ret, 0);

    ret = HcfCipherCreate("3DES192|ECB|PKCS5", &cipher);
    ASSERT_EQ(ret, 0);

    ret = DesEncrypt(cipher, key, nullptr, cipherText, &cipherTextLen);
    ASSERT_EQ(ret, 0);

    ret = DesDecrypt(cipher, key, nullptr, cipherText, cipherTextLen);
    ASSERT_EQ(ret, 0);

    HcfObjDestroy((HcfObjectBase *)key);
    HcfObjDestroy((HcfObjectBase *)cipher);
    HcfObjDestroy((HcfObjectBase *)generator);
}

HWTEST_F(Crypto3DesCipherTest, Crypto3DesCipherTest003, TestSize.Level0)
{
    uint8_t cipherText[128] = {0};
    int cipherTextLen = 128;

    HcfSymKeyGenerator *generator = nullptr;
    HcfCipher *cipher = nullptr;
    HcfSymKey *key = nullptr;

    int ret = HcfSymKeyGeneratorCreate("3DES192", &generator);
    ASSERT_EQ(ret, 0);

    ret = generator->generateSymKey(generator, &key);
    ASSERT_EQ(ret, 0);

    ret = HcfCipherCreate("3DES192|ECB|PKCS7", &cipher);
    ASSERT_EQ(ret, 0);

    ret = DesEncrypt(cipher, key, nullptr, cipherText, &cipherTextLen);
    ASSERT_EQ(ret, 0);

    ret = DesDecrypt(cipher, key, nullptr, cipherText, cipherTextLen);
    ASSERT_EQ(ret, 0);

    HcfObjDestroy((HcfObjectBase *)key);
    HcfObjDestroy((HcfObjectBase *)cipher);
    HcfObjDestroy((HcfObjectBase *)generator);
}

HWTEST_F(Crypto3DesCipherTest, Crypto3DesCipherTest004, TestSize.Level0)
{
    uint8_t cipherText[128] = {0};
    int cipherTextLen = 128;

    HcfSymKeyGenerator *generator = nullptr;
    HcfCipher *cipher = nullptr;
    HcfSymKey *key = nullptr;
    uint8_t iv[8] = {0};
    HcfIvParamsSpec ivSpec = {};
    ivSpec.iv.data = iv;
    ivSpec.iv.len = 8;

    int ret = HcfSymKeyGeneratorCreate("3DES192", &generator);
    ASSERT_EQ(ret, 0);

    ret = generator->generateSymKey(generator, &key);
    ASSERT_EQ(ret, 0);

    ret = HcfCipherCreate("3DES192|CBC|NoPadding", &cipher);
    ASSERT_EQ(ret, 0);

    ret = DesEncrypt(cipher, key, (HcfParamsSpec *)&ivSpec, cipherText, &cipherTextLen);
    ASSERT_NE(ret, 0);

    HcfObjDestroy((HcfObjectBase *)key);
    HcfObjDestroy((HcfObjectBase *)cipher);
    HcfObjDestroy((HcfObjectBase *)generator);
}

HWTEST_F(Crypto3DesCipherTest, Crypto3DesCipherTest005, TestSize.Level0)
{
    uint8_t cipherText[128] = {0};
    int cipherTextLen = 128;

    HcfSymKeyGenerator *generator = nullptr;
    HcfCipher *cipher = nullptr;
    HcfSymKey *key = nullptr;
    uint8_t iv[8] = {0};
    HcfIvParamsSpec ivSpec = {};
    ivSpec.iv.data = iv;
    ivSpec.iv.len = 8;

    int ret = HcfSymKeyGeneratorCreate("3DES192", &generator);
    ASSERT_EQ(ret, 0);

    ret = generator->generateSymKey(generator, &key);
    ASSERT_EQ(ret, 0);

    ret = HcfCipherCreate("3DES192|CBC|PKCS5", &cipher);
    ASSERT_EQ(ret, 0);

    ret = DesEncrypt(cipher, key, (HcfParamsSpec *)&ivSpec, cipherText, &cipherTextLen);
    ASSERT_EQ(ret, 0);

    ret = DesDecrypt(cipher, key, (HcfParamsSpec *)&ivSpec, cipherText, cipherTextLen);
    ASSERT_EQ(ret, 0);

    HcfObjDestroy((HcfObjectBase *)key);
    HcfObjDestroy((HcfObjectBase *)cipher);
    HcfObjDestroy((HcfObjectBase *)generator);
}

HWTEST_F(Crypto3DesCipherTest, Crypto3DesCipherTest006, TestSize.Level0)
{
    uint8_t cipherText[128] = {0};
    int cipherTextLen = 128;

    HcfSymKeyGenerator *generator = nullptr;
    HcfCipher *cipher = nullptr;
    HcfSymKey *key = nullptr;
    uint8_t iv[8] = {0};
    HcfIvParamsSpec ivSpec = {};
    ivSpec.iv.data = iv;
    ivSpec.iv.len = 8;

    int ret = HcfSymKeyGeneratorCreate("3DES192", &generator);
    ASSERT_EQ(ret, 0);

    ret = generator->generateSymKey(generator, &key);
    ASSERT_EQ(ret, 0);

    ret = HcfCipherCreate("3DES192|CBC|PKCS7", &cipher);
    ASSERT_EQ(ret, 0);

    ret = DesEncrypt(cipher, key, (HcfParamsSpec *)&ivSpec, cipherText, &cipherTextLen);
    ASSERT_EQ(ret, 0);

    ret = DesDecrypt(cipher, key, (HcfParamsSpec *)&ivSpec, cipherText, cipherTextLen);
    ASSERT_EQ(ret, 0);

    HcfObjDestroy((HcfObjectBase *)key);
    HcfObjDestroy((HcfObjectBase *)cipher);
    HcfObjDestroy((HcfObjectBase *)generator);
}

HWTEST_F(Crypto3DesCipherTest, Crypto3DesCipherTest007, TestSize.Level0)
{
    uint8_t cipherText[128] = {0};
    int cipherTextLen = 128;

    HcfSymKeyGenerator *generator = nullptr;
    HcfCipher *cipher = nullptr;
    HcfSymKey *key = nullptr;
    uint8_t iv[8] = {0};
    HcfIvParamsSpec ivSpec = {};
    ivSpec.iv.data = iv;
    ivSpec.iv.len = 8;

    int ret = HcfSymKeyGeneratorCreate("3DES192", &generator);
    ASSERT_EQ(ret, 0);

    ret = generator->generateSymKey(generator, &key);
    ASSERT_EQ(ret, 0);

    ret = HcfCipherCreate("3DES192|OFB|NoPadding", &cipher);
    ASSERT_EQ(ret, 0);

    ret = DesEncrypt(cipher, key, (HcfParamsSpec *)&ivSpec, cipherText, &cipherTextLen);
    ASSERT_EQ(ret, 0);

    ret = DesDecrypt(cipher, key, (HcfParamsSpec *)&ivSpec, cipherText, cipherTextLen);
    ASSERT_EQ(ret, 0);

    HcfObjDestroy((HcfObjectBase *)key);
    HcfObjDestroy((HcfObjectBase *)cipher);
    HcfObjDestroy((HcfObjectBase *)generator);
}

HWTEST_F(Crypto3DesCipherTest, Crypto3DesCipherTest008, TestSize.Level0)
{
    uint8_t cipherText[128] = {0};
    int cipherTextLen = 128;

    HcfSymKeyGenerator *generator = nullptr;
    HcfCipher *cipher = nullptr;
    HcfSymKey *key = nullptr;
    uint8_t iv[8] = {0};
    HcfIvParamsSpec ivSpec = {};
    ivSpec.iv.data = iv;
    ivSpec.iv.len = 8;

    int ret = HcfSymKeyGeneratorCreate("3DES192", &generator);
    ASSERT_EQ(ret, 0);

    ret = generator->generateSymKey(generator, &key);
    ASSERT_EQ(ret, 0);

    ret = HcfCipherCreate("3DES192|OFB|PKCS5", &cipher);
    ASSERT_EQ(ret, 0);

    ret = DesEncrypt(cipher, key, (HcfParamsSpec *)&ivSpec, cipherText, &cipherTextLen);
    ASSERT_EQ(ret, 0);

    ret = DesDecrypt(cipher, key, (HcfParamsSpec *)&ivSpec, cipherText, cipherTextLen);
    ASSERT_EQ(ret, 0);

    HcfObjDestroy((HcfObjectBase *)key);
    HcfObjDestroy((HcfObjectBase *)cipher);
    HcfObjDestroy((HcfObjectBase *)generator);
}

HWTEST_F(Crypto3DesCipherTest, Crypto3DesCipherTest009, TestSize.Level0)
{
    uint8_t cipherText[128] = {0};
    int cipherTextLen = 128;

    HcfSymKeyGenerator *generator = nullptr;
    HcfCipher *cipher = nullptr;
    HcfSymKey *key = nullptr;
    uint8_t iv[8] = {0};
    HcfIvParamsSpec ivSpec = {};
    ivSpec.iv.data = iv;
    ivSpec.iv.len = 8;

    int ret = HcfSymKeyGeneratorCreate("3DES192", &generator);
    ASSERT_EQ(ret, 0);

    ret = generator->generateSymKey(generator, &key);
    ASSERT_EQ(ret, 0);

    ret = HcfCipherCreate("3DES192|OFB|PKCS7", &cipher);
    ASSERT_EQ(ret, 0);

    ret = DesEncrypt(cipher, key, (HcfParamsSpec *)&ivSpec, cipherText, &cipherTextLen);
    ASSERT_EQ(ret, 0);

    ret = DesDecrypt(cipher, key, (HcfParamsSpec *)&ivSpec, cipherText, cipherTextLen);
    ASSERT_EQ(ret, 0);

    HcfObjDestroy((HcfObjectBase *)key);
    HcfObjDestroy((HcfObjectBase *)cipher);
    HcfObjDestroy((HcfObjectBase *)generator);
}

HWTEST_F(Crypto3DesCipherTest, Crypto3DesCipherTest010, TestSize.Level0)
{
    uint8_t cipherText[128] = {0};
    int cipherTextLen = 128;

    HcfSymKeyGenerator *generator = nullptr;
    HcfCipher *cipher = nullptr;
    HcfSymKey *key = nullptr;
    uint8_t iv[8] = {0};
    HcfIvParamsSpec ivSpec = {};
    ivSpec.iv.data = iv;
    ivSpec.iv.len = 8;

    int ret = HcfSymKeyGeneratorCreate("3DES192", &generator);
    ASSERT_EQ(ret, 0);

    ret = generator->generateSymKey(generator, &key);
    ASSERT_EQ(ret, 0);

    ret = HcfCipherCreate("3DES192|CFB|NoPadding", &cipher);
    ASSERT_EQ(ret, 0);

    ret = DesEncrypt(cipher, key, (HcfParamsSpec *)&ivSpec, cipherText, &cipherTextLen);
    ASSERT_EQ(ret, 0);

    ret = DesDecrypt(cipher, key, (HcfParamsSpec *)&ivSpec, cipherText, cipherTextLen);
    ASSERT_EQ(ret, 0);

    HcfObjDestroy((HcfObjectBase *)key);
    HcfObjDestroy((HcfObjectBase *)cipher);
    HcfObjDestroy((HcfObjectBase *)generator);
}

HWTEST_F(Crypto3DesCipherTest, Crypto3DesCipherTest011, TestSize.Level0)
{
    uint8_t cipherText[128] = {0};
    int cipherTextLen = 128;

    HcfSymKeyGenerator *generator = nullptr;
    HcfCipher *cipher = nullptr;
    HcfSymKey *key = nullptr;
    uint8_t iv[8] = {0};
    HcfIvParamsSpec ivSpec = {};
    ivSpec.iv.data = iv;
    ivSpec.iv.len = 8;

    int ret = HcfSymKeyGeneratorCreate("3DES192", &generator);
    ASSERT_EQ(ret, 0);

    ret = generator->generateSymKey(generator, &key);
    ASSERT_EQ(ret, 0);

    ret = HcfCipherCreate("3DES192|CFB|PKCS5", &cipher);
    ASSERT_EQ(ret, 0);

    ret = DesEncrypt(cipher, key, (HcfParamsSpec *)&ivSpec, cipherText, &cipherTextLen);
    ASSERT_EQ(ret, 0);

    ret = DesDecrypt(cipher, key, (HcfParamsSpec *)&ivSpec, cipherText, cipherTextLen);
    ASSERT_EQ(ret, 0);

    HcfObjDestroy((HcfObjectBase *)key);
    HcfObjDestroy((HcfObjectBase *)cipher);
    HcfObjDestroy((HcfObjectBase *)generator);
}

HWTEST_F(Crypto3DesCipherTest, Crypto3DesCipherTest012, TestSize.Level0)
{
    uint8_t cipherText[128] = {0};
    int cipherTextLen = 128;

    HcfSymKeyGenerator *generator = nullptr;
    HcfCipher *cipher = nullptr;
    HcfSymKey *key = nullptr;
    uint8_t iv[8] = {0};
    HcfIvParamsSpec ivSpec = {};
    ivSpec.iv.data = iv;
    ivSpec.iv.len = 8;

    int ret = HcfSymKeyGeneratorCreate("3DES192", &generator);
    ASSERT_EQ(ret, 0);

    ret = generator->generateSymKey(generator, &key);
    ASSERT_EQ(ret, 0);

    ret = HcfCipherCreate("3DES192|CFB|PKCS7", &cipher);
    ASSERT_EQ(ret, 0);

    ret = DesEncrypt(cipher, key, (HcfParamsSpec *)&ivSpec, cipherText, &cipherTextLen);
    ASSERT_EQ(ret, 0);

    ret = DesDecrypt(cipher, key, (HcfParamsSpec *)&ivSpec, cipherText, cipherTextLen);
    ASSERT_EQ(ret, 0);

    HcfObjDestroy((HcfObjectBase *)key);
    HcfObjDestroy((HcfObjectBase *)cipher);
    HcfObjDestroy((HcfObjectBase *)generator);
}

HWTEST_F(Crypto3DesCipherTest, Crypto3DesCipherTest013, TestSize.Level0)
{
    uint8_t cipherText[128] = {0};
    int cipherTextLen = 128;

    HcfSymKeyGenerator *generator = nullptr;
    HcfCipher *cipher = nullptr;
    HcfSymKey *key = nullptr;

    int ret = HcfSymKeyGeneratorCreate("3DES192", &generator);
    ASSERT_EQ(ret, 0);

    ret = generator->generateSymKey(generator, &key);
    ASSERT_EQ(ret, 0);

    ret = HcfCipherCreate("3DES192|ECB|NoPadding", &cipher);
    ASSERT_EQ(ret, 0);

    ret = DesNoUpdateEncrypt(cipher, key, nullptr, cipherText, &cipherTextLen);
    ASSERT_NE(ret, 0);

    HcfObjDestroy((HcfObjectBase *)key);
    HcfObjDestroy((HcfObjectBase *)cipher);
    HcfObjDestroy((HcfObjectBase *)generator);
}

HWTEST_F(Crypto3DesCipherTest, Crypto3DesCipherTest014, TestSize.Level0)
{
    uint8_t cipherText[128] = {0};
    int cipherTextLen = 128;

    HcfSymKeyGenerator *generator = nullptr;
    HcfCipher *cipher = nullptr;
    HcfSymKey *key = nullptr;

    int ret = HcfSymKeyGeneratorCreate("3DES192", &generator);
    ASSERT_EQ(ret, 0);

    ret = generator->generateSymKey(generator, &key);
    ASSERT_EQ(ret, 0);

    ret = HcfCipherCreate("3DES192|ECB|PKCS5", &cipher);
    ASSERT_EQ(ret, 0);

    ret = DesNoUpdateEncrypt(cipher, key, nullptr, cipherText, &cipherTextLen);
    ASSERT_EQ(ret, 0);

    ret = DesNoUpdateDecrypt(cipher, key, nullptr, cipherText, cipherTextLen);
    ASSERT_EQ(ret, 0);

    HcfObjDestroy((HcfObjectBase *)key);
    HcfObjDestroy((HcfObjectBase *)cipher);
    HcfObjDestroy((HcfObjectBase *)generator);
}

HWTEST_F(Crypto3DesCipherTest, Crypto3DesCipherTest015, TestSize.Level0)
{
    uint8_t cipherText[128] = {0};
    int cipherTextLen = 128;

    HcfSymKeyGenerator *generator = nullptr;
    HcfCipher *cipher = nullptr;
    HcfSymKey *key = nullptr;

    int ret = HcfSymKeyGeneratorCreate("3DES192", &generator);
    ASSERT_EQ(ret, 0);

    ret = generator->generateSymKey(generator, &key);
    ASSERT_EQ(ret, 0);

    ret = HcfCipherCreate("3DES192|ECB|PKCS7", &cipher);
    ASSERT_EQ(ret, 0);

    ret = DesNoUpdateEncrypt(cipher, key, nullptr, cipherText, &cipherTextLen);
    ASSERT_EQ(ret, 0);

    ret = DesNoUpdateDecrypt(cipher, key, nullptr, cipherText, cipherTextLen);
    ASSERT_EQ(ret, 0);

    HcfObjDestroy((HcfObjectBase *)key);
    HcfObjDestroy((HcfObjectBase *)cipher);
    HcfObjDestroy((HcfObjectBase *)generator);
}

HWTEST_F(Crypto3DesCipherTest, Crypto3DesCipherTest016, TestSize.Level0)
{
    uint8_t cipherText[128] = {0};
    int cipherTextLen = 128;

    HcfSymKeyGenerator *generator = nullptr;
    HcfCipher *cipher = nullptr;
    HcfSymKey *key = nullptr;
    uint8_t iv[8] = {0};
    HcfIvParamsSpec ivSpec = {};
    ivSpec.iv.data = iv;
    ivSpec.iv.len = 8;

    int ret = HcfSymKeyGeneratorCreate("3DES192", &generator);
    ASSERT_EQ(ret, 0);

    ret = generator->generateSymKey(generator, &key);
    ASSERT_EQ(ret, 0);

    ret = HcfCipherCreate("3DES192|CBC|NoPadding", &cipher);
    ASSERT_EQ(ret, 0);

    ret = DesNoUpdateEncrypt(cipher, key, (HcfParamsSpec *)&ivSpec, cipherText, &cipherTextLen);
    ASSERT_NE(ret, 0);

    HcfObjDestroy((HcfObjectBase *)key);
    HcfObjDestroy((HcfObjectBase *)cipher);
    HcfObjDestroy((HcfObjectBase *)generator);
}

HWTEST_F(Crypto3DesCipherTest, Crypto3DesCipherTest017, TestSize.Level0)
{
    uint8_t cipherText[128] = {0};
    int cipherTextLen = 128;

    HcfSymKeyGenerator *generator = nullptr;
    HcfCipher *cipher = nullptr;
    HcfSymKey *key = nullptr;
    uint8_t iv[8] = {0};
    HcfIvParamsSpec ivSpec = {};
    ivSpec.iv.data = iv;
    ivSpec.iv.len = 8;

    int ret = HcfSymKeyGeneratorCreate("3DES192", &generator);
    ASSERT_EQ(ret, 0);

    ret = generator->generateSymKey(generator, &key);
    ASSERT_EQ(ret, 0);

    ret = HcfCipherCreate("3DES192|CBC|PKCS5", &cipher);
    ASSERT_EQ(ret, 0);

    ret = DesNoUpdateEncrypt(cipher, key, (HcfParamsSpec *)&ivSpec, cipherText, &cipherTextLen);
    ASSERT_EQ(ret, 0);

    ret = DesNoUpdateDecrypt(cipher, key, (HcfParamsSpec *)&ivSpec, cipherText, cipherTextLen);
    ASSERT_EQ(ret, 0);

    HcfObjDestroy((HcfObjectBase *)key);
    HcfObjDestroy((HcfObjectBase *)cipher);
    HcfObjDestroy((HcfObjectBase *)generator);
}

HWTEST_F(Crypto3DesCipherTest, Crypto3DesCipherTest018, TestSize.Level0)
{
    uint8_t cipherText[128] = {0};
    int cipherTextLen = 128;

    HcfSymKeyGenerator *generator = nullptr;
    HcfCipher *cipher = nullptr;
    HcfSymKey *key = nullptr;
    uint8_t iv[8] = {0};
    HcfIvParamsSpec ivSpec = {};
    ivSpec.iv.data = iv;
    ivSpec.iv.len = 8;

    int ret = HcfSymKeyGeneratorCreate("3DES192", &generator);
    ASSERT_EQ(ret, 0);

    ret = generator->generateSymKey(generator, &key);
    ASSERT_EQ(ret, 0);

    ret = HcfCipherCreate("3DES192|CBC|PKCS7", &cipher);
    ASSERT_EQ(ret, 0);

    ret = DesNoUpdateEncrypt(cipher, key, (HcfParamsSpec *)&ivSpec, cipherText, &cipherTextLen);
    ASSERT_EQ(ret, 0);

    ret = DesNoUpdateDecrypt(cipher, key, (HcfParamsSpec *)&ivSpec, cipherText, cipherTextLen);
    ASSERT_EQ(ret, 0);

    HcfObjDestroy((HcfObjectBase *)key);
    HcfObjDestroy((HcfObjectBase *)cipher);
    HcfObjDestroy((HcfObjectBase *)generator);
}

HWTEST_F(Crypto3DesCipherTest, Crypto3DesCipherTest019, TestSize.Level0)
{
    uint8_t cipherText[128] = {0};
    int cipherTextLen = 128;

    HcfSymKeyGenerator *generator = nullptr;
    HcfCipher *cipher = nullptr;
    HcfSymKey *key = nullptr;
    uint8_t iv[8] = {0};
    HcfIvParamsSpec ivSpec = {};
    ivSpec.iv.data = iv;
    ivSpec.iv.len = 8;

    int ret = HcfSymKeyGeneratorCreate("3DES192", &generator);
    ASSERT_EQ(ret, 0);

    ret = generator->generateSymKey(generator, &key);
    ASSERT_EQ(ret, 0);

    ret = HcfCipherCreate("3DES192|OFB|NoPadding", &cipher);
    ASSERT_EQ(ret, 0);

    ret = DesNoUpdateEncrypt(cipher, key, (HcfParamsSpec *)&ivSpec, cipherText, &cipherTextLen);
    ASSERT_EQ(ret, 0);

    ret = DesNoUpdateDecrypt(cipher, key, (HcfParamsSpec *)&ivSpec, cipherText, cipherTextLen);
    ASSERT_EQ(ret, 0);

    HcfObjDestroy((HcfObjectBase *)key);
    HcfObjDestroy((HcfObjectBase *)cipher);
    HcfObjDestroy((HcfObjectBase *)generator);
}

HWTEST_F(Crypto3DesCipherTest, Crypto3DesCipherTest020, TestSize.Level0)
{
    uint8_t cipherText[128] = {0};
    int cipherTextLen = 128;

    HcfSymKeyGenerator *generator = nullptr;
    HcfCipher *cipher = nullptr;
    HcfSymKey *key = nullptr;
    uint8_t iv[8] = {0};
    HcfIvParamsSpec ivSpec = {};
    ivSpec.iv.data = iv;
    ivSpec.iv.len = 8;

    int ret = HcfSymKeyGeneratorCreate("3DES192", &generator);
    ASSERT_EQ(ret, 0);

    ret = generator->generateSymKey(generator, &key);
    ASSERT_EQ(ret, 0);

    ret = HcfCipherCreate("3DES192|OFB|PKCS5", &cipher);
    ASSERT_EQ(ret, 0);

    ret = DesNoUpdateEncrypt(cipher, key, (HcfParamsSpec *)&ivSpec, cipherText, &cipherTextLen);
    ASSERT_EQ(ret, 0);

    ret = DesNoUpdateDecrypt(cipher, key, (HcfParamsSpec *)&ivSpec, cipherText, cipherTextLen);
    ASSERT_EQ(ret, 0);

    HcfObjDestroy((HcfObjectBase *)key);
    HcfObjDestroy((HcfObjectBase *)cipher);
    HcfObjDestroy((HcfObjectBase *)generator);
}

HWTEST_F(Crypto3DesCipherTest, Crypto3DesCipherTest021, TestSize.Level0)
{
    uint8_t cipherText[128] = {0};
    int cipherTextLen = 128;

    HcfSymKeyGenerator *generator = nullptr;
    HcfCipher *cipher = nullptr;
    HcfSymKey *key = nullptr;
    uint8_t iv[8] = {0};
    HcfIvParamsSpec ivSpec = {};
    ivSpec.iv.data = iv;
    ivSpec.iv.len = 8;

    int ret = HcfSymKeyGeneratorCreate("3DES192", &generator);
    ASSERT_EQ(ret, 0);

    ret = generator->generateSymKey(generator, &key);
    ASSERT_EQ(ret, 0);

    ret = HcfCipherCreate("3DES192|OFB|PKCS7", &cipher);
    ASSERT_EQ(ret, 0);

    ret = DesNoUpdateEncrypt(cipher, key, (HcfParamsSpec *)&ivSpec, cipherText, &cipherTextLen);
    ASSERT_EQ(ret, 0);

    ret = DesNoUpdateDecrypt(cipher, key, (HcfParamsSpec *)&ivSpec, cipherText, cipherTextLen);
    ASSERT_EQ(ret, 0);

    HcfObjDestroy((HcfObjectBase *)key);
    HcfObjDestroy((HcfObjectBase *)cipher);
    HcfObjDestroy((HcfObjectBase *)generator);
}

HWTEST_F(Crypto3DesCipherTest, Crypto3DesCipherTest022, TestSize.Level0)
{
    uint8_t cipherText[128] = {0};
    int cipherTextLen = 128;

    HcfSymKeyGenerator *generator = nullptr;
    HcfCipher *cipher = nullptr;
    HcfSymKey *key = nullptr;
    uint8_t iv[8] = {0};
    HcfIvParamsSpec ivSpec = {};
    ivSpec.iv.data = iv;
    ivSpec.iv.len = 8;

    int ret = HcfSymKeyGeneratorCreate("3DES192", &generator);
    ASSERT_EQ(ret, 0);

    ret = generator->generateSymKey(generator, &key);
    ASSERT_EQ(ret, 0);

    ret = HcfCipherCreate("3DES192|CFB|NoPadding", &cipher);
    ASSERT_EQ(ret, 0);

    ret = DesNoUpdateEncrypt(cipher, key, (HcfParamsSpec *)&ivSpec, cipherText, &cipherTextLen);
    ASSERT_EQ(ret, 0);

    ret = DesNoUpdateDecrypt(cipher, key, (HcfParamsSpec *)&ivSpec, cipherText, cipherTextLen);
    ASSERT_EQ(ret, 0);

    HcfObjDestroy((HcfObjectBase *)key);
    HcfObjDestroy((HcfObjectBase *)cipher);
    HcfObjDestroy((HcfObjectBase *)generator);
}

HWTEST_F(Crypto3DesCipherTest, Crypto3DesCipherTest023, TestSize.Level0)
{
    uint8_t cipherText[128] = {0};
    int cipherTextLen = 128;

    HcfSymKeyGenerator *generator = nullptr;
    HcfCipher *cipher = nullptr;
    HcfSymKey *key = nullptr;
    uint8_t iv[8] = {0};
    HcfIvParamsSpec ivSpec = {};
    ivSpec.iv.data = iv;
    ivSpec.iv.len = 8;

    int ret = HcfSymKeyGeneratorCreate("3DES192", &generator);
    ASSERT_EQ(ret, 0);

    ret = generator->generateSymKey(generator, &key);
    ASSERT_EQ(ret, 0);

    ret = HcfCipherCreate("3DES192|CFB|PKCS5", &cipher);
    ASSERT_EQ(ret, 0);

    ret = DesNoUpdateEncrypt(cipher, key, (HcfParamsSpec *)&ivSpec, cipherText, &cipherTextLen);
    ASSERT_EQ(ret, 0);

    ret = DesNoUpdateDecrypt(cipher, key, (HcfParamsSpec *)&ivSpec, cipherText, cipherTextLen);
    ASSERT_EQ(ret, 0);

    HcfObjDestroy((HcfObjectBase *)key);
    HcfObjDestroy((HcfObjectBase *)cipher);
    HcfObjDestroy((HcfObjectBase *)generator);
}

HWTEST_F(Crypto3DesCipherTest, Crypto3DesCipherTest024, TestSize.Level0)
{
    uint8_t cipherText[128] = {0};
    int cipherTextLen = 128;

    HcfSymKeyGenerator *generator = nullptr;
    HcfCipher *cipher = nullptr;
    HcfSymKey *key = nullptr;
    uint8_t iv[8] = {0};
    HcfIvParamsSpec ivSpec = {};
    ivSpec.iv.data = iv;
    ivSpec.iv.len = 8;

    int ret = HcfSymKeyGeneratorCreate("3DES192", &generator);
    ASSERT_EQ(ret, 0);

    ret = generator->generateSymKey(generator, &key);
    ASSERT_EQ(ret, 0);

    ret = HcfCipherCreate("3DES192|CFB|PKCS7", &cipher);
    ASSERT_EQ(ret, 0);

    ret = DesNoUpdateEncrypt(cipher, key, (HcfParamsSpec *)&ivSpec, cipherText, &cipherTextLen);
    ASSERT_EQ(ret, 0);

    ret = DesNoUpdateDecrypt(cipher, key, (HcfParamsSpec *)&ivSpec, cipherText, cipherTextLen);
    ASSERT_EQ(ret, 0);

    HcfObjDestroy((HcfObjectBase *)key);
    HcfObjDestroy((HcfObjectBase *)cipher);
    HcfObjDestroy((HcfObjectBase *)generator);
}

HWTEST_F(Crypto3DesCipherTest, Crypto3DesCipherTest025, TestSize.Level0)
{
    uint8_t cipherText[CIPHER_TEXT_LEN] = { 0 };
    int cipherTextLen = CIPHER_TEXT_LEN;
    HcfCipher *cipher = nullptr;
    HcfSymKey *key = nullptr;
    uint8_t iv[DES_IV_LEN] = { 0 };
    HcfIvParamsSpec ivSpec = {};
    ivSpec.iv.data = iv;
    ivSpec.iv.len = DES_IV_LEN;

    int ret = Generate3DesSymKey(&key);
    ASSERT_EQ(ret, 0);

    ret = HcfCipherCreate("3DES192|CFB1|NoPadding", &cipher);
    ASSERT_EQ(ret, 0);

    ret = DesEncrypt(cipher, key, &(ivSpec.base), cipherText, &cipherTextLen);
    ASSERT_EQ(ret, 0);

    ret = DesDecrypt(cipher, key, &(ivSpec.base), cipherText, cipherTextLen);
    ASSERT_EQ(ret, 0);

    HcfObjDestroy(key);
    HcfObjDestroy(cipher);
}

HWTEST_F(Crypto3DesCipherTest, Crypto3DesCipherTest026, TestSize.Level0)
{
    uint8_t cipherText[CIPHER_TEXT_LEN] = { 0 };
    int cipherTextLen = CIPHER_TEXT_LEN;
    HcfCipher *cipher = nullptr;
    HcfSymKey *key = nullptr;
    uint8_t iv[DES_IV_LEN] = { 0 };
    HcfIvParamsSpec ivSpec = {};
    ivSpec.iv.data = iv;
    ivSpec.iv.len = DES_IV_LEN;

    int ret = Generate3DesSymKey(&key);
    ASSERT_EQ(ret, 0);

    ret = HcfCipherCreate("3DES192|CFB8|NoPadding", &cipher);
    ASSERT_EQ(ret, 0);

    ret = DesEncrypt(cipher, key, &(ivSpec.base), cipherText, &cipherTextLen);
    ASSERT_EQ(ret, 0);

    ret = DesDecrypt(cipher, key, &(ivSpec.base), cipherText, cipherTextLen);
    ASSERT_EQ(ret, 0);

    HcfObjDestroy(key);
    HcfObjDestroy(cipher);
}

HWTEST_F(Crypto3DesCipherTest, Crypto3DesCipherTest027, TestSize.Level0)
{
    uint8_t cipherText[CIPHER_TEXT_LEN] = { 0 };
    int cipherTextLen = CIPHER_TEXT_LEN;
    HcfCipher *cipher = nullptr;
    HcfSymKey *key = nullptr;
    uint8_t iv[DES_IV_LEN] = { 0 };
    HcfIvParamsSpec ivSpec = {};
    ivSpec.iv.data = iv;
    ivSpec.iv.len = DES_IV_LEN;

    int ret = Generate3DesSymKey(&key);
    ASSERT_EQ(ret, 0);

    ret = HcfCipherCreate("3DES192|PKCS5", &cipher);
    ASSERT_EQ(ret, 0);

    ret = DesEncrypt(cipher, key, &(ivSpec.base), cipherText, &cipherTextLen);
    ASSERT_EQ(ret, 0);

    ret = DesDecrypt(cipher, key, &(ivSpec.base), cipherText, cipherTextLen);
    ASSERT_EQ(ret, 0);

    HcfObjDestroy(key);
    HcfObjDestroy(cipher);
}

HWTEST_F(Crypto3DesCipherTest, Crypto3DesCipherTest028, TestSize.Level0)
{
    HcfCipher *cipher = nullptr;
    HcfSymKey *key = nullptr;

    int ret = Generate3DesSymKey(&key);
    ASSERT_EQ(ret, 0);

    ret = HcfCipherCreate("3DES192|ECB|PKCS5", &cipher);
    ASSERT_EQ(ret, 0);

    ret = cipher->init(nullptr, ENCRYPT_MODE, &(key->key), nullptr);
    EXPECT_EQ(ret, HCF_INVALID_PARAMS);

    HcfObjDestroy(key);
    HcfObjDestroy(cipher);
}

HWTEST_F(Crypto3DesCipherTest, Crypto3DesCipherTest029, TestSize.Level0)
{
    HcfSymKeyGenerator *generator = nullptr;
    HcfCipher *cipher = nullptr;
    HcfSymKey *key = nullptr;

    int ret = HcfSymKeyGeneratorCreate("3DES192", &generator);
    ASSERT_EQ(ret, 0);

    ret = generator->generateSymKey(generator, &key);
    ASSERT_EQ(ret, 0);

    ret = HcfCipherCreate("3DES192|ECB|PKCS5", &cipher);
    ASSERT_EQ(ret, 0);

    ret = cipher->init(reinterpret_cast<HcfCipher *>(generator), ENCRYPT_MODE, &(key->key), nullptr);
    EXPECT_NE(ret, 0);

    HcfObjDestroy(key);
    HcfObjDestroy(cipher);
    HcfObjDestroy(generator);
}

HWTEST_F(Crypto3DesCipherTest, Crypto3DesCipherTest030, TestSize.Level0)
{
    HcfCipher *cipher = nullptr;
    HcfSymKey *key = nullptr;

    int ret = Generate3DesSymKey(&key);
    ASSERT_EQ(ret, 0);

    ret = HcfCipherCreate("3DES192|ECB|PKCS5", &cipher);
    ASSERT_EQ(ret, 0);

    ret = cipher->init(cipher, ENCRYPT_MODE, reinterpret_cast<HcfKey *>(cipher), nullptr);
    EXPECT_NE(ret, 0);

    HcfObjDestroy(key);
    HcfObjDestroy(cipher);
}

HWTEST_F(Crypto3DesCipherTest, Crypto3DesCipherTest031, TestSize.Level0)
{
    HcfCipher *cipher = nullptr;
    HcfSymKey *key = nullptr;
    uint8_t plainText[] = "this is test!";
    HcfBlob input = { .data = plainText, .len = PLAINTEXT_LEN };
    HcfBlob output = { .data = nullptr, .len = 0 };

    int ret = Generate3DesSymKey(&key);
    ASSERT_EQ(ret, 0);

    ret = HcfCipherCreate("3DES192|ECB|PKCS5", &cipher);
    ASSERT_EQ(ret, 0);

    ret = cipher->init(cipher, ENCRYPT_MODE, &(key->key), nullptr);
    ASSERT_EQ(ret, 0);

    ret = cipher->update(nullptr, &input, &output);
    EXPECT_EQ(ret, HCF_INVALID_PARAMS);

    if (output.data != nullptr) {
        HcfFree(output.data);
        output.data = nullptr;
    }
    HcfObjDestroy(key);
    HcfObjDestroy(cipher);
}

HWTEST_F(Crypto3DesCipherTest, Crypto3DesCipherTest032, TestSize.Level0)
{
    HcfCipher *cipher = nullptr;
    HcfSymKey *key = nullptr;
    uint8_t plainText[] = "this is test!";
    HcfBlob input = { .data = plainText, .len = PLAINTEXT_LEN };
    HcfBlob output = { .data = nullptr, .len = 0 };

    int ret = Generate3DesSymKey(&key);
    ASSERT_EQ(ret, 0);

    ret = HcfCipherCreate("3DES192|ECB|PKCS5", &cipher);
    ASSERT_EQ(ret, 0);

    ret = cipher->init(cipher, ENCRYPT_MODE, &(key->key), nullptr);
    ASSERT_EQ(ret, 0);

    ret = cipher->doFinal(reinterpret_cast<HcfCipher *>(key), &input, &output);
    EXPECT_NE(ret, 0);

    HcfObjDestroy(key);
    HcfObjDestroy(cipher);
    if (output.data != nullptr) {
        HcfFree(output.data);
        output.data = nullptr;
    }
}

HWTEST_F(Crypto3DesCipherTest, Crypto3DesCipherTest033, TestSize.Level0)
{
    int ret = 0;
    HcfCipher *cipher = nullptr;
    HcfSymKey *key = nullptr;
    uint8_t plainText[] = "this is test!";
    HcfBlob input = { .data = plainText, .len = PLAINTEXT_LEN };
    HcfBlob output = { .data = nullptr, .len = 0 };

    ret = Generate3DesSymKey(&key);
    EXPECT_EQ(ret, HCF_SUCCESS);

    ret = HcfCipherCreate("3DES192|ECB|PKCS5", &cipher);
    EXPECT_EQ(ret, HCF_SUCCESS);

    cipher->base.destroy(nullptr);
    ret = cipher->getCipherSpecString(nullptr, SM2_MD_NAME_STR, nullptr);
    EXPECT_EQ(ret, HCF_INVALID_PARAMS);
    ret = cipher->getCipherSpecUint8Array(nullptr, SM2_MD_NAME_STR, nullptr);
    EXPECT_EQ(ret, HCF_INVALID_PARAMS);
    HcfBlob blob = { .data = nullptr, .len = 0 };
    ret = cipher->setCipherSpecUint8Array(nullptr, SM2_MD_NAME_STR, blob);
    EXPECT_EQ(ret, HCF_INVALID_PARAMS);
    ret = cipher->init(cipher, ENCRYPT_MODE, &(key->key), nullptr);
    EXPECT_EQ(ret, HCF_SUCCESS);
    ret = cipher->doFinal(nullptr, &input, &output);
    EXPECT_EQ(ret, HCF_INVALID_PARAMS);
    HcfObjDestroy(key);
    HcfObjDestroy(cipher);
    if (output.data != nullptr) {
        HcfFree(output.data);
        output.data = nullptr;
    }
}

HWTEST_F(Crypto3DesCipherTest, Crypto3DesCipherTest034, TestSize.Level0)
{
    HcfCipher *cipher = nullptr;
    HcfSymKey *key = nullptr;
    uint8_t plainText[] = "this is test!";
    HcfBlob input = { .data = plainText, .len = PLAINTEXT_LEN };
    HcfBlob output = { .data = nullptr, .len = 0 };

    int ret = Generate3DesSymKey(&key);
    ASSERT_EQ(ret, 0);

    ret = HcfCipherCreate("3DES192|ECB|PKCS5", &cipher);
    ASSERT_EQ(ret, 0);

    ret = cipher->init(cipher, ENCRYPT_MODE, &(key->key), nullptr);
    ASSERT_EQ(ret, 0);

    ret = cipher->doFinal(reinterpret_cast<HcfCipher *>(key), &input, &output);
    EXPECT_NE(ret, 0);

    HcfObjDestroy(key);
    HcfObjDestroy(cipher);
    if (output.data != nullptr) {
        HcfFree(output.data);
        output.data = nullptr;
    }
}

HWTEST_F(Crypto3DesCipherTest, Crypto3DesCipherTest035, TestSize.Level0)
{
    HcfResult ret = HcfCipherDesGeneratorSpiCreate(nullptr, nullptr);
    if (ret != 0) {
        LOGE("HcfCipherDesGeneratorSpiCreate failed!");
    }
    EXPECT_NE(ret, 0);

    HcfCipherGeneratorSpi *cipher = nullptr;
    CipherAttr params = {
        .algo = HCF_ALG_3DES,
        .mode = HCF_ALG_MODE_ECB,
        .paddingMode = HCF_ALG_PADDING_PKCS5,
    };
    ret = HcfCipherDesGeneratorSpiCreate(&params, &cipher);
    EXPECT_EQ(ret, HCF_SUCCESS);

    ret = cipher->init(nullptr, ENCRYPT_MODE, nullptr, nullptr);
    EXPECT_EQ(ret, HCF_INVALID_PARAMS);

    ret = cipher->update(nullptr, nullptr, nullptr);
    EXPECT_EQ(ret, HCF_INVALID_PARAMS);

    ret = cipher->doFinal(nullptr, nullptr, nullptr);
    EXPECT_EQ(ret, HCF_INVALID_PARAMS);

    HcfBlob dataArray = { .data = nullptr, .len = 0 };
    ret = cipher->getCipherSpecString(nullptr, OAEP_MGF1_MD_STR, nullptr);
    EXPECT_EQ(ret, HCF_NOT_SUPPORT);

    ret = cipher->getCipherSpecUint8Array(nullptr, OAEP_MGF1_MD_STR, &dataArray);
    EXPECT_EQ(ret, HCF_NOT_SUPPORT);

    HcfBlob dataUint8 = { .data = nullptr, .len = 0 };
    ret = cipher->setCipherSpecUint8Array(nullptr, OAEP_MGF1_MD_STR, dataUint8);
    EXPECT_EQ(ret, HCF_NOT_SUPPORT);

    (void)cipher->base.destroy(nullptr);

    HcfObjDestroy(cipher);
    HcfBlobDataFree(&dataArray);
}

HWTEST_F(Crypto3DesCipherTest, CryptoDesCipherTest001, TestSize.Level0)
{
    int ret = 0;
    uint8_t cipherText[CIPHER_TEXT_LEN] = {0};
    int cipherTextLen = CIPHER_TEXT_LEN;

    HcfSymKey *key = nullptr;
    HcfCipher *cipher = nullptr;

    ret = GenerateDesSymKey(&key);
    EXPECT_EQ(ret, HCF_SUCCESS);

    ret = HcfCipherCreate("DES64|ECB|PKCS7", &cipher);
    EXPECT_EQ(ret, HCF_SUCCESS);

    ret = DesEncrypt(cipher, key, nullptr, cipherText, &cipherTextLen);
    EXPECT_EQ(ret, HCF_SUCCESS);

    ret = DesDecrypt(cipher, key, nullptr, cipherText, cipherTextLen);
    EXPECT_EQ(ret, HCF_SUCCESS);

    HcfObjDestroy(key);
    HcfObjDestroy(cipher);
}

static HcfResult ConvertDesSymKey(HcfBlob *dataBlob, HcfSymKey **key)
{
    HcfSymKeyGenerator *generator = nullptr;

    HcfResult ret = HcfSymKeyGeneratorCreate("DES64", &generator);
    if (ret != HCF_SUCCESS) {
        LOGE("HcfSymKeyGeneratorCreate failed!");
        return ret;
    }

    ret = generator->convertSymKey(generator, dataBlob, key);
    if (ret != HCF_SUCCESS) {
        LOGE("generateSymKey failed!");
    }
    HcfObjDestroy(generator);
    return ret;
}

HWTEST_F(Crypto3DesCipherTest, CryptoDesCipherTestVecderEnc, TestSize.Level0)
{
    int ret = 0;
    uint8_t plainText[] = {0x4e, 0x6f, 0x77, 0x20, 0x69, 0x73, 0x20, 0x74}; // "Now is t"
    uint8_t keyData[] = {0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef};   // Test key
    uint8_t expectedCipherText[] = {0x3f, 0xa4, 0x0e, 0x8a, 0x98, 0x4d, 0x48, 0x15}; // Expected ciphertext

    HcfBlob input = {.data = plainText, .len = sizeof(plainText)};
    HcfBlob output = {};
    HcfBlob keyDataBlob = {.data = keyData, .len = sizeof(keyData)};

    HcfSymKey *key = nullptr;
    HcfCipher *cipher = nullptr;

    // Convert key data to HcfSymKey
    ret = ConvertDesSymKey(&keyDataBlob, &key);
    EXPECT_EQ(ret, HCF_SUCCESS);

    // Create DES cipher
    ret = HcfCipherCreate("DES64|ECB|NoPadding", &cipher);
    EXPECT_EQ(ret, HCF_SUCCESS);

    // Encrypt
    ret = cipher->init(cipher, ENCRYPT_MODE, (HcfKey *)key, nullptr);
    EXPECT_EQ(ret, HCF_SUCCESS);

    ret = cipher->doFinal(cipher, &input, &output);
    EXPECT_EQ(ret, HCF_SUCCESS);

    // Verify ciphertext
    EXPECT_EQ(output.len, sizeof(expectedCipherText));
    EXPECT_EQ(memcmp(output.data, expectedCipherText, sizeof(expectedCipherText)), 0);

    HcfObjDestroy(key);
    HcfObjDestroy(cipher);
    if (output.data != nullptr) {
        HcfBlobDataFree(&output);
    }
}

HWTEST_F(Crypto3DesCipherTest, CryptoDesCipherTestVecderDec, TestSize.Level0)
{
    int ret = 0;
    uint8_t expectedCipherText[] = {0x4e, 0x6f, 0x77, 0x20, 0x69, 0x73, 0x20, 0x74}; // "Now is t"
    uint8_t keyData[] = {0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef};   // Test key
    uint8_t plainText[] = {0x3f, 0xa4, 0x0e, 0x8a, 0x98, 0x4d, 0x48, 0x15}; // Expected ciphertext

    HcfBlob input = {.data = plainText, .len = sizeof(plainText)};
    HcfBlob output = {};
    HcfBlob keyDataBlob = {.data = keyData, .len = sizeof(keyData)};

    HcfSymKey *key = nullptr;
    HcfCipher *cipher = nullptr;

    // Convert key data to HcfSymKey
    ret = ConvertDesSymKey(&keyDataBlob, &key);
    EXPECT_EQ(ret, HCF_SUCCESS);

    // Create DES cipher
    ret = HcfCipherCreate("DES64|ECB|NoPadding", &cipher);
    EXPECT_EQ(ret, HCF_SUCCESS);

    // Encrypt
    ret = cipher->init(cipher, DECRYPT_MODE, (HcfKey *)key, nullptr);
    EXPECT_EQ(ret, HCF_SUCCESS);

    ret = cipher->doFinal(cipher, &input, &output);
    EXPECT_EQ(ret, HCF_SUCCESS);

    // Verify ciphertext
    EXPECT_EQ(output.len, sizeof(expectedCipherText));
    EXPECT_EQ(memcmp(output.data, expectedCipherText, sizeof(expectedCipherText)), 0);

    HcfObjDestroy(key);
    HcfObjDestroy(cipher);
    if (output.data != nullptr) {
        HcfBlobDataFree(&output);
    }
}
}
