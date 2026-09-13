/*
 * Copyright (C) 2025 Huawei Device Co., Ltd.
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
#include "log.h"
#include "memory.h"
#include "sym_common_defines.h"
#include "sym_key_generator.h"

using namespace std;
using namespace testing::ext;

namespace {
class CryptoAesWrapCipherTest : public testing::Test {
public:
    static void SetUpTestCase() {};
    static void TearDownTestCase() {};
    void SetUp() {};
    void TearDown() {};
};

static int32_t AesWrapEncrypt(HcfCipher *cipher, HcfSymKey *key, HcfParamsSpec *params,
    HcfBlob *keyBlob, HcfBlob *output)
{
    int32_t ret = cipher->init(cipher, ENCRYPT_MODE, reinterpret_cast<HcfKey *>(key), params);
    if (ret != 0) {
        LOGE("init failed! %{public}d", ret);
        return ret;
    }

    ret = cipher->doFinal(cipher, keyBlob, output);
    if (ret != 0) {
        LOGE("doFinal failed!");
        return ret;
    }

    return 0;
}

static int32_t AesWrapDecrypt(HcfCipher *cipher, HcfSymKey *key, HcfParamsSpec *params,
    HcfBlob *input, HcfBlob *output)
{
    int32_t ret = cipher->init(cipher, DECRYPT_MODE, reinterpret_cast<HcfKey *>(key), params);
    if (ret != 0) {
        LOGE("init failed! %{public}d", ret);
        return ret;
    }

    ret = cipher->doFinal(cipher, input, output);
    if (ret != 0) {
        LOGE("doFinal failed!");
        return ret;
    }

    return 0;
}

HWTEST_F(CryptoAesWrapCipherTest, CryptoAesWrapCipherTest001, TestSize.Level0)
{
    int ret = 0;
    uint8_t iv[8] = {0};

    HcfIvParamsSpec ivSpec = {};
    HcfSymKeyGenerator *generator = nullptr;
    HcfCipher *cipher = nullptr;
    HcfSymKey *key = nullptr;
    HcfBlob keyBlob = {};
    HcfBlob cipherInput = {};
    HcfBlob plainOutput = {};
    ivSpec.iv.data = iv;
    ivSpec.iv.len = 8;

    ret = HcfSymKeyGeneratorCreate("AES128", &generator);
    ASSERT_EQ(ret, 0);

    ret = generator->generateSymKey(generator, &key);
    ASSERT_EQ(ret, 0);

    ret = key->key.getEncoded(reinterpret_cast<HcfKey *>(key), &keyBlob);
    ASSERT_EQ(ret, 0);

    ret = HcfCipherCreate("AES128-WRAP", &cipher);
    ASSERT_EQ(ret, 0);

    ret = AesWrapEncrypt(cipher, key, (HcfParamsSpec *)&ivSpec, &keyBlob, &cipherInput);
    ASSERT_EQ(ret, 0);

    ret = AesWrapDecrypt(cipher, key, (HcfParamsSpec *)&ivSpec, &cipherInput, &plainOutput);
    ASSERT_EQ(ret, 0);

    ASSERT_EQ(plainOutput.len, keyBlob.len);
    ASSERT_EQ(memcmp(plainOutput.data, keyBlob.data, keyBlob.len), 0);

    HcfBlobDataFree(&keyBlob);
    HcfBlobDataFree(&cipherInput);
    HcfBlobDataFree(&plainOutput);
    HcfObjDestroy((HcfObjectBase *)key);
    HcfObjDestroy((HcfObjectBase *)cipher);
    HcfObjDestroy((HcfObjectBase *)generator);
}

HWTEST_F(CryptoAesWrapCipherTest, CryptoAesWrapCipherTest002, TestSize.Level0)
{
    int ret = 0;
    uint8_t iv[8] = {0};

    HcfIvParamsSpec ivSpec = {};
    HcfSymKeyGenerator *generator = nullptr;
    HcfCipher *cipher = nullptr;
    HcfSymKey *key = nullptr;
    HcfBlob keyBlob = {};
    HcfBlob cipherInput = {};
    HcfBlob plainOutput = {};
    ivSpec.iv.data = iv;
    ivSpec.iv.len = 8;

    ret = HcfSymKeyGeneratorCreate("AES192", &generator);
    ASSERT_EQ(ret, 0);

    ret = generator->generateSymKey(generator, &key);
    ASSERT_EQ(ret, 0);

    ret = key->key.getEncoded(reinterpret_cast<HcfKey *>(key), &keyBlob);
    ASSERT_EQ(ret, 0);

    ret = HcfCipherCreate("AES192-WRAP", &cipher);
    ASSERT_EQ(ret, 0);

    ret = AesWrapEncrypt(cipher, key, (HcfParamsSpec *)&ivSpec, &keyBlob, &cipherInput);
    ASSERT_EQ(ret, 0);

    ret = AesWrapDecrypt(cipher, key, (HcfParamsSpec *)&ivSpec, &cipherInput, &plainOutput);
    ASSERT_EQ(ret, 0);

    ASSERT_EQ(plainOutput.len, keyBlob.len);
    ASSERT_EQ(memcmp(plainOutput.data, keyBlob.data, keyBlob.len), 0);

    HcfBlobDataFree(&keyBlob);
    HcfBlobDataFree(&cipherInput);
    HcfBlobDataFree(&plainOutput);
    HcfObjDestroy((HcfObjectBase *)key);
    HcfObjDestroy((HcfObjectBase *)cipher);
    HcfObjDestroy((HcfObjectBase *)generator);
}

HWTEST_F(CryptoAesWrapCipherTest, CryptoAesWrapCipherTest003, TestSize.Level0)
{
    int ret = 0;
    uint8_t iv[8] = {0};

    HcfIvParamsSpec ivSpec = {};
    HcfSymKeyGenerator *generator = nullptr;
    HcfCipher *cipher = nullptr;
    HcfSymKey *key = nullptr;
    HcfBlob keyBlob = {};
    HcfBlob cipherInput = {};
    HcfBlob plainOutput = {};
    ivSpec.iv.data = iv;
    ivSpec.iv.len = 8;

    ret = HcfSymKeyGeneratorCreate("AES256", &generator);
    ASSERT_EQ(ret, 0);

    ret = generator->generateSymKey(generator, &key);
    ASSERT_EQ(ret, 0);

    ret = key->key.getEncoded(reinterpret_cast<HcfKey *>(key), &keyBlob);
    ASSERT_EQ(ret, 0);

    ret = HcfCipherCreate("AES256-WRAP", &cipher);
    ASSERT_EQ(ret, 0);

    ret = AesWrapEncrypt(cipher, key, (HcfParamsSpec *)&ivSpec, &keyBlob, &cipherInput);
    ASSERT_EQ(ret, 0);

    ret = AesWrapDecrypt(cipher, key, (HcfParamsSpec *)&ivSpec, &cipherInput, &plainOutput);
    ASSERT_EQ(ret, 0);

    ASSERT_EQ(plainOutput.len, keyBlob.len);
    ASSERT_EQ(memcmp(plainOutput.data, keyBlob.data, keyBlob.len), 0);

    HcfBlobDataFree(&keyBlob);
    HcfBlobDataFree(&cipherInput);
    HcfBlobDataFree(&plainOutput);
    HcfObjDestroy((HcfObjectBase *)key);
    HcfObjDestroy((HcfObjectBase *)cipher);
    HcfObjDestroy((HcfObjectBase *)generator);
}

HWTEST_F(CryptoAesWrapCipherTest, CryptoAesWrapCipherTest004, TestSize.Level0)
{
    int ret = 0;
    uint8_t iv[8] = {0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08};

    HcfIvParamsSpec ivSpec = {};
    HcfSymKeyGenerator *generator = nullptr;
    HcfCipher *cipher = nullptr;
    HcfSymKey *key = nullptr;
    HcfBlob keyBlob = {};
    HcfBlob cipherInput = {};
    HcfBlob plainOutput = {};
    ivSpec.iv.data = iv;
    ivSpec.iv.len = 8;

    ret = HcfSymKeyGeneratorCreate("AES128", &generator);
    ASSERT_EQ(ret, 0);

    ret = generator->generateSymKey(generator, &key);
    ASSERT_EQ(ret, 0);

    ret = key->key.getEncoded(reinterpret_cast<HcfKey *>(key), &keyBlob);
    ASSERT_EQ(ret, 0);

    ret = HcfCipherCreate("AES128-WRAP", &cipher);
    ASSERT_EQ(ret, 0);

    ret = AesWrapEncrypt(cipher, key, (HcfParamsSpec *)&ivSpec, &keyBlob, &cipherInput);
    ASSERT_EQ(ret, 0);

    ret = AesWrapDecrypt(cipher, key, (HcfParamsSpec *)&ivSpec, &cipherInput, &plainOutput);
    ASSERT_EQ(ret, 0);

    ASSERT_EQ(plainOutput.len, keyBlob.len);
    ASSERT_EQ(memcmp(plainOutput.data, keyBlob.data, keyBlob.len), 0);

    HcfBlobDataFree(&keyBlob);
    HcfBlobDataFree(&cipherInput);
    HcfBlobDataFree(&plainOutput);
    HcfObjDestroy((HcfObjectBase *)key);
    HcfObjDestroy((HcfObjectBase *)cipher);
    HcfObjDestroy((HcfObjectBase *)generator);
}

HWTEST_F(CryptoAesWrapCipherTest, CryptoAesWrapCipherTest005, TestSize.Level0)
{
    HcfCipher *cipher = nullptr;
    HcfSymKey *key = nullptr;

    int ret = GenerateSymKey("AES128", &key);
    ASSERT_EQ(ret, 0);

    ret = HcfCipherCreate("AES128-WRAP", &cipher);
    ASSERT_EQ(ret, 0);

    ret = cipher->init(nullptr, ENCRYPT_MODE, &(key->key), nullptr);
    ASSERT_NE(ret, 0);

    HcfObjDestroy((HcfObjectBase *)key);
    HcfObjDestroy((HcfObjectBase *)cipher);
}

HWTEST_F(CryptoAesWrapCipherTest, CryptoAesWrapCipherTest006, TestSize.Level0)
{
    HcfCipher *cipher = nullptr;

    int ret = HcfCipherCreate("AES128-WRAP", &cipher);
    ASSERT_EQ(ret, 0);

    ret = cipher->init(cipher, ENCRYPT_MODE, nullptr, nullptr);
    ASSERT_NE(ret, 0);

    HcfObjDestroy((HcfObjectBase *)cipher);
}

HWTEST_F(CryptoAesWrapCipherTest, CryptoAesWrapCipherTest007, TestSize.Level0)
{
    HcfSymKeyGenerator *generator = nullptr;
    HcfSymKey *key = nullptr;
    HcfCipher *cipher = nullptr;

    int ret = HcfSymKeyGeneratorCreate("AES128", &generator);
    ASSERT_EQ(ret, 0);

    ret = generator->generateSymKey(generator, &key);
    ASSERT_EQ(ret, 0);

    ret = HcfCipherCreate("AES128-WRAP", &cipher);
    ASSERT_EQ(ret, 0);

    ret = cipher->init(reinterpret_cast<HcfCipher *>(generator), ENCRYPT_MODE, &(key->key), nullptr);
    ASSERT_NE(ret, 0);

    HcfObjDestroy((HcfObjectBase *)key);
    HcfObjDestroy((HcfObjectBase *)cipher);
    HcfObjDestroy((HcfObjectBase *)generator);
}

HWTEST_F(CryptoAesWrapCipherTest, CryptoAesWrapCipherTest008, TestSize.Level0)
{
    HcfCipher *cipher = nullptr;

    int ret = HcfCipherCreate("INVALID-ALGORITHM", &cipher);
    ASSERT_NE(ret, 0);
}

HWTEST_F(CryptoAesWrapCipherTest, CryptoAesWrapCipherTest009, TestSize.Level0)
{
    int ret = 0;
    uint8_t iv[16] = {0};

    HcfIvParamsSpec ivSpec = {};
    HcfSymKeyGenerator *generator = nullptr;
    HcfCipher *cipher = nullptr;
    HcfSymKey *key = nullptr;
    HcfBlob keyBlob = {};
    HcfBlob cipherInput = {};
    ivSpec.iv.data = iv;
    ivSpec.iv.len = 16;

    ret = HcfSymKeyGeneratorCreate("AES128", &generator);
    ASSERT_EQ(ret, 0);

    ret = generator->generateSymKey(generator, &key);
    ASSERT_EQ(ret, 0);

    ret = key->key.getEncoded(reinterpret_cast<HcfKey *>(key), &keyBlob);
    ASSERT_EQ(ret, 0);

    ret = HcfCipherCreate("AES256-WRAP", &cipher);
    ASSERT_EQ(ret, 0);

    ret = AesWrapEncrypt(cipher, key, (HcfParamsSpec *)&ivSpec, &keyBlob, &cipherInput);
    ASSERT_NE(ret, 0);

    HcfBlobDataFree(&keyBlob);
    HcfObjDestroy((HcfObjectBase *)key);
    HcfObjDestroy((HcfObjectBase *)cipher);
    HcfObjDestroy((HcfObjectBase *)generator);
}

HWTEST_F(CryptoAesWrapCipherTest, CryptoAesWrapCipherTest010, TestSize.Level0)
{
    int ret = 0;
    uint8_t iv[32] = {0};

    HcfIvParamsSpec ivSpec = {};
    HcfSymKeyGenerator *generator = nullptr;
    HcfCipher *cipher = nullptr;
    HcfSymKey *key = nullptr;
    HcfBlob keyBlob = {};
    HcfBlob cipherInput = {};
    ivSpec.iv.data = iv;
    ivSpec.iv.len = 32;

    ret = HcfSymKeyGeneratorCreate("AES128", &generator);
    ASSERT_EQ(ret, 0);

    ret = generator->generateSymKey(generator, &key);
    ASSERT_EQ(ret, 0);

    ret = key->key.getEncoded(reinterpret_cast<HcfKey *>(key), &keyBlob);
    ASSERT_EQ(ret, 0);

    ret = HcfCipherCreate("AES128-WRAP", &cipher);
    ASSERT_EQ(ret, 0);

    ret = AesWrapEncrypt(cipher, key, (HcfParamsSpec *)&ivSpec, &keyBlob, &cipherInput);
    ASSERT_NE(ret, 0);

    HcfBlobDataFree(&keyBlob);
    HcfObjDestroy((HcfObjectBase *)key);
    HcfObjDestroy((HcfObjectBase *)cipher);
    HcfObjDestroy((HcfObjectBase *)generator);
}

HWTEST_F(CryptoAesWrapCipherTest, CryptoAesWrapCipherTest011, TestSize.Level0)
{
    int ret = 0;

    HcfSymKeyGenerator *generator = nullptr;
    HcfCipher *cipher = nullptr;
    HcfSymKey *key = nullptr;
    HcfBlob keyBlob = {};
    HcfBlob cipherInput = {};

    ret = HcfSymKeyGeneratorCreate("AES128", &generator);
    ASSERT_EQ(ret, 0);

    ret = generator->generateSymKey(generator, &key);
    ASSERT_EQ(ret, 0);

    ret = key->key.getEncoded(reinterpret_cast<HcfKey *>(key), &keyBlob);
    ASSERT_EQ(ret, 0);

    ret = HcfCipherCreate("AES128-WRAP", &cipher);
    ASSERT_EQ(ret, 0);

    ret = AesWrapEncrypt(cipher, key, nullptr, &keyBlob, &cipherInput);
    ASSERT_EQ(ret, 0);

    HcfBlobDataFree(&keyBlob);
    HcfBlobDataFree(&cipherInput);
    HcfObjDestroy((HcfObjectBase *)key);
    HcfObjDestroy((HcfObjectBase *)cipher);
    HcfObjDestroy((HcfObjectBase *)generator);
}

HWTEST_F(CryptoAesWrapCipherTest, CryptoAesWrapCipherTest012, TestSize.Level0)
{
    int ret = 0;
    uint8_t iv[16] = {0};

    HcfIvParamsSpec ivSpec = {};
    HcfSymKeyGenerator *generator = nullptr;
    HcfCipher *cipher = nullptr;
    HcfSymKey *key = nullptr;
    HcfBlob keyBlob = {.data = nullptr, .len = 0};
    HcfBlob cipherInput = {};
    ivSpec.iv.data = iv;
    ivSpec.iv.len = 16;

    ret = HcfSymKeyGeneratorCreate("AES128", &generator);
    ASSERT_EQ(ret, 0);

    ret = generator->generateSymKey(generator, &key);
    ASSERT_EQ(ret, 0);

    ret = HcfCipherCreate("AES128-WRAP", &cipher);
    ASSERT_EQ(ret, 0);

    ret = AesWrapEncrypt(cipher, key, (HcfParamsSpec *)&ivSpec, &keyBlob, &cipherInput);
    ASSERT_NE(ret, 0);

    HcfObjDestroy((HcfObjectBase *)key);
    HcfObjDestroy((HcfObjectBase *)cipher);
    HcfObjDestroy((HcfObjectBase *)generator);
}

HWTEST_F(CryptoAesWrapCipherTest, CryptoAesWrapCipherTest013, TestSize.Level0)
{
    int ret = 0;
    uint8_t iv[8] = {0};

    HcfIvParamsSpec ivSpec = {};
    HcfSymKeyGenerator *generator = nullptr;
    HcfCipher *cipher = nullptr;
    HcfSymKey *key = nullptr;
    HcfBlob keyBlob = {};
    HcfBlob cipherInput = {};
    ivSpec.iv.data = iv;
    ivSpec.iv.len = 8;

    ret = HcfSymKeyGeneratorCreate("AES128", &generator);
    ASSERT_EQ(ret, 0);

    ret = generator->generateSymKey(generator, &key);
    ASSERT_EQ(ret, 0);

    ret = key->key.getEncoded(reinterpret_cast<HcfKey *>(key), &keyBlob);
    ASSERT_EQ(ret, 0);

    ret = HcfCipherCreate("AES128-WRAP", &cipher);
    ASSERT_EQ(ret, 0);

    ret = cipher->init(cipher, ENCRYPT_MODE, reinterpret_cast<HcfKey *>(key), (HcfParamsSpec *)&ivSpec);
    ASSERT_EQ(ret, 0);

    ret = cipher->update(cipher, &keyBlob, &cipherInput);
    ASSERT_EQ(ret, HCF_ERR_CRYPTO_OPERATION);

    HcfBlobDataFree(&keyBlob);
    HcfBlobDataFree(&cipherInput);
    HcfObjDestroy((HcfObjectBase *)key);
    HcfObjDestroy((HcfObjectBase *)cipher);
    HcfObjDestroy((HcfObjectBase *)generator);
}
}