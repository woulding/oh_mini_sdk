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
#include <fstream>
#include <iostream>
#include "securec.h"
#include "sym_common_defines.h"
#include "sym_key_generator.h"
#include "cipher.h"
#include "blob.h"
#include "log.h"
#include "memory.h"
#include "detailed_iv_params.h"
#include "detailed_gcm_params.h"
#include "detailed_ccm_params.h"
#include "aes_openssl.h"

using namespace std;
using namespace testing::ext;

namespace {
constexpr int32_t KEY_MATERIAL_LEN = 16;

class CryptoSM4GeneratorTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp();
    void TearDown();
};

void CryptoSM4GeneratorTest::SetUpTestCase() {}
void CryptoSM4GeneratorTest::TearDownTestCase() {}

void CryptoSM4GeneratorTest::SetUp() // add init here, this will be called before test.
{
}

void CryptoSM4GeneratorTest::TearDown() // add destroy here, this will be called when test case done.
{
}

static int32_t GenerateSymKey(const char *algoName, HcfSymKey **key)
{
    HcfSymKeyGenerator *generator = nullptr;

    int32_t ret = HcfSymKeyGeneratorCreate(algoName, &generator);
    if (ret != 0) {
        LOGE("HcfSymKeyGeneratorCreate failed!");
        return ret;
    }

    ret = generator->generateSymKey(generator, key);
    if (ret != 0) {
        LOGE("generateSymKey failed!");
    }
    HcfObjDestroy((HcfObjectBase *)generator);
    return ret;
}

HWTEST_F(CryptoSM4GeneratorTest, CryptoSm4GeneratorTest001, TestSize.Level0)
{
    int ret = 0;
    HcfSymKeyGenerator *generator = nullptr;
    HcfSymKey *key = nullptr;
    const char *inputAlgoName = "SM4_128";
    const char *generatorAlgoName = nullptr;

    ret = HcfSymKeyGeneratorCreate(inputAlgoName, &generator);
    ASSERT_EQ(ret, 0);
    ret = generator->generateSymKey(generator, &key);
    ASSERT_EQ(ret, 0);

    // generator getAlgoName
    generatorAlgoName = generator->getAlgoName(generator);
    ASSERT_NE(generatorAlgoName, nullptr);

    ret = strcmp(generatorAlgoName, inputAlgoName);
    ASSERT_EQ(ret, 0);

    HcfObjDestroy(key);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoSM4GeneratorTest, CryptoSm4GeneratorTest002, TestSize.Level0)
{
    int ret = 0;
    HcfSymKeyGenerator *generator = nullptr;
    const char *generatorAlgoName = nullptr;
    const char *inputAlgoName = "SM4_128";

    ret = HcfSymKeyGeneratorCreate(inputAlgoName, &generator);
    ASSERT_EQ(ret, 0);

    // generator getAlgoName
    generatorAlgoName = generator->getAlgoName(nullptr);
    ASSERT_EQ(generatorAlgoName, nullptr);

    HcfObjDestroy(generator);
}

HWTEST_F(CryptoSM4GeneratorTest, CryptoSm4GeneratorTest003, TestSize.Level0)
{
    HcfSymKeyGenerator *generator = nullptr;
    HcfSymKey *key = nullptr;
    const char *generatorAlgoName = nullptr;
    const char *inputAlgoName = "SM4_128";

    int ret = HcfSymKeyGeneratorCreate(inputAlgoName, &generator);
    ASSERT_EQ(ret, 0);
    ret = generator->generateSymKey(generator, &key);
    ASSERT_EQ(ret, 0);

    // generator getAlgoName
    generatorAlgoName = generator->getAlgoName(reinterpret_cast<HcfSymKeyGenerator *>(key));
    ASSERT_EQ(generatorAlgoName, nullptr);

    HcfObjDestroy(key);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoSM4GeneratorTest, CryptoSm4GeneratorTest004, TestSize.Level0)
{
    HcfSymKey *key = nullptr;
    const char *inputAlgoName = "SM4_128";
    const char *keyAlgoName = nullptr;

    int ret = GenerateSymKey(inputAlgoName, &key);
    ASSERT_EQ(ret, 0);

    keyAlgoName = key->key.getAlgorithm(nullptr);
    ASSERT_EQ(keyAlgoName, nullptr);

    HcfObjDestroy(key);
}

HWTEST_F(CryptoSM4GeneratorTest, CryptoSm4GeneratorTest005, TestSize.Level0)
{
    HcfSymKeyGenerator *generator = nullptr;
    HcfSymKey *key = nullptr;
    const char *inputAlgoName = "SM4_128";
    const char *keyAlgoName = nullptr;

    int ret = HcfSymKeyGeneratorCreate(inputAlgoName, &generator);
    ASSERT_EQ(ret, 0);

    ret = generator->generateSymKey(generator, &key);
    ASSERT_EQ(ret, 0);

    keyAlgoName = key->key.getAlgorithm(reinterpret_cast<HcfKey *>(generator));
    ASSERT_EQ(keyAlgoName, nullptr);

    HcfObjDestroy(key);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoSM4GeneratorTest, CryptoSm4GeneratorTest006, TestSize.Level0)
{
    HcfSymKey *key = nullptr;
    const char *retFormat = nullptr;

    int ret = GenerateSymKey("SM4_128", &key);
    ASSERT_EQ(ret, 0);

    retFormat = key->key.getFormat(nullptr);
    ASSERT_EQ(retFormat, nullptr);

    HcfObjDestroy(key);
}

HWTEST_F(CryptoSM4GeneratorTest, CryptoSm4GeneratorTest007, TestSize.Level0)
{
    HcfSymKeyGenerator *generator = nullptr;
    HcfSymKey *key = nullptr;
    const char *retFormat = nullptr;

    int ret = HcfSymKeyGeneratorCreate("SM4_128", &generator);
    ASSERT_EQ(ret, 0);

    ret = generator->generateSymKey(generator, &key);
    ASSERT_EQ(ret, 0);

    retFormat = key->key.getFormat(reinterpret_cast<HcfKey *>(generator));
    ASSERT_EQ(retFormat, nullptr);

    HcfObjDestroy(key);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoSM4GeneratorTest, CryptoSm4GeneratorTest008, TestSize.Level0)
{
    HcfSymKeyGenerator *generator = nullptr;
    HcfSymKey *key = nullptr;
    HcfBlob encodedBlob = { 0 };
    uint8_t keyMaterial[] = {
        0xba, 0x3b, 0xc2, 0x71, 0x21, 0x1e, 0x30, 0x56,
        0xad, 0x47, 0xfc, 0x5a, 0x46, 0x39, 0xee, 0x7c
    };
    HcfBlob keyTmpBlob = { .data = keyMaterial, .len = KEY_MATERIAL_LEN };

    int ret = HcfSymKeyGeneratorCreate("SM4_128", &generator);
    ASSERT_EQ(ret, 0);

    ret = generator->convertSymKey(generator, &keyTmpBlob, &key);
    ASSERT_EQ(ret, 0);

    ret = key->key.getEncoded(nullptr, &encodedBlob);
    ASSERT_NE(ret, 0);

    HcfObjDestroy(key);
    HcfObjDestroy(generator);
    if (encodedBlob.data != nullptr) {
        HcfFree(encodedBlob.data);
        encodedBlob.data = nullptr;
    }
}

HWTEST_F(CryptoSM4GeneratorTest, CryptoSm4GeneratorTest009, TestSize.Level0)
{
    HcfSymKeyGenerator *generator = nullptr;
    HcfSymKey *key = nullptr;
    HcfBlob encodedBlob = { 0 };
    uint8_t keyMaterial[] = {
        0xba, 0x3b, 0xc2, 0x71, 0x21, 0x1e, 0x30, 0x56,
        0xad, 0x47, 0xfc, 0x5a, 0x46, 0x39, 0xee, 0x7c
    };
    HcfBlob keyTmpBlob = { .data = keyMaterial, .len = KEY_MATERIAL_LEN };

    int ret = HcfSymKeyGeneratorCreate("SM4_128", &generator);
    ASSERT_EQ(ret, 0);

    ret = generator->convertSymKey(generator, &keyTmpBlob, &key);
    ASSERT_EQ(ret, 0);

    ret = key->key.getEncoded(reinterpret_cast<HcfKey *>(generator), &encodedBlob);
    ASSERT_NE(ret, 0);

    HcfObjDestroy(key);
    HcfObjDestroy(generator);
    if (encodedBlob.data != nullptr) {
        HcfFree(encodedBlob.data);
        encodedBlob.data = nullptr;
    }
}

HWTEST_F(CryptoSM4GeneratorTest, CryptoSm4GeneratorTest010, TestSize.Level0)
{
    HcfSymKeyGenerator *generator = nullptr;
    HcfSymKey *key = nullptr;
    HcfBlob encodedBlob = { 0 };
    uint8_t keyMaterial[] = {
        0xba, 0x3b, 0xc2, 0x71, 0x21, 0x1e, 0x30, 0x56,
        0xad, 0x47, 0xfc, 0x5a, 0x46, 0x39, 0xee, 0x7c
    };
    HcfBlob keyTmpBlob = { .data = keyMaterial, .len = KEY_MATERIAL_LEN };
    SymKeyImpl *impl = nullptr;
    size_t tmpLen = 0;

    int ret = HcfSymKeyGeneratorCreate("SM4_128", &generator);
    ASSERT_EQ(ret, 0);

    ret = generator->convertSymKey(generator, &keyTmpBlob, &key);
    ASSERT_EQ(ret, 0);

    impl = reinterpret_cast<SymKeyImpl *>(key);
    tmpLen = impl->keyMaterial.len;
    impl->keyMaterial.len = 0;

    ret = key->key.getEncoded(&(key->key), &encodedBlob);
    impl->keyMaterial.len = tmpLen;
    ASSERT_NE(ret, 0);

    HcfObjDestroy(key);
    HcfObjDestroy(generator);
    if (encodedBlob.data != nullptr) {
        HcfFree(encodedBlob.data);
        encodedBlob.data = nullptr;
    }
}

HWTEST_F(CryptoSM4GeneratorTest, CryptoSm4GeneratorTest011, TestSize.Level0)
{
    HcfSymKeyGenerator *generator = nullptr;
    HcfSymKey *key = nullptr;
    HcfBlob encodedBlob = { 0 };
    uint8_t keyMaterial[] = {
        0xba, 0x3b, 0xc2, 0x71, 0x21, 0x1e, 0x30, 0x56,
        0xad, 0x47, 0xfc, 0x5a, 0x46, 0x39, 0xee, 0x7c
    };
    HcfBlob keyTmpBlob = { .data = keyMaterial, .len = KEY_MATERIAL_LEN };

    int ret = HcfSymKeyGeneratorCreate("SM4_128", &generator);
    ASSERT_EQ(ret, 0);

    ret = generator->convertSymKey(generator, &keyTmpBlob, &key);
    ASSERT_EQ(ret, 0);

    key->clearMem(nullptr);

    ret = key->key.getEncoded(&(key->key), &encodedBlob);
    ASSERT_EQ(ret, 0);
    ASSERT_FALSE((encodedBlob.data == nullptr) || (encodedBlob.data[0] == '\0'));

    HcfObjDestroy(key);
    HcfObjDestroy(generator);
    if (encodedBlob.data != nullptr) {
        HcfFree(encodedBlob.data);
        encodedBlob.data = nullptr;
    }
}

HWTEST_F(CryptoSM4GeneratorTest, CryptoSm4GeneratorTest012, TestSize.Level0)
{
    int ret = 0;
    HcfSymKeyGenerator *generator = nullptr;

    ret = HcfSymKeyGeneratorCreate("SM4_128", &generator);
    if (ret != 0) {
        LOGE("HcfSymKeyGeneratorCreate failed! Should not select RSA for symKey generator.");
    }

    HcfObjDestroy(generator);
    EXPECT_EQ(ret, 0);
}

HWTEST_F(CryptoSM4GeneratorTest, CryptoSm4GeneratorTest013, TestSize.Level0)
{
    int ret = 0;
    HcfSymKeyGenerator *generator = nullptr;

    ret = HcfSymKeyGeneratorCreate("", &generator);
    if (ret != 0) {
        LOGE("HcfSymKeyGeneratorCreate failed! Should not select empty string for symKey generator.");
    }

    HcfObjDestroy(generator);
    EXPECT_NE(ret, 0);
}

HWTEST_F(CryptoSM4GeneratorTest, CryptoSm4GeneratorTest014, TestSize.Level0)
{
    int ret = 0;
    HcfSymKeyGenerator *generator = nullptr;

    ret = HcfSymKeyGeneratorCreate(nullptr, &generator);
    if (ret != 0) {
        LOGE("HcfSymKeyGeneratorCreate failed! Should not select nullptr for symKey generator.");
    }

    HcfObjDestroy(generator);
    EXPECT_NE(ret, 0);
}

HWTEST_F(CryptoSM4GeneratorTest, CryptoSm4GeneratorTest015, TestSize.Level0)
{
    int ret = 0;
    HcfSymKeyGenerator *generator = nullptr;

    ret = HcfSymKeyGeneratorSpiCreate(nullptr, nullptr);
    if (ret != 0) {
        LOGE("HcfSymKeyGeneratorSpiCreate failed!");
    }

    HcfObjDestroy(generator);
    EXPECT_NE(ret, 0);
}

HWTEST_F(CryptoSM4GeneratorTest, CryptoSm4GeneratorTest016, TestSize.Level0)
{
    HcfSymKeyGenerator *generator = nullptr;
    HcfSymKey *key = nullptr;

    int ret = HcfSymKeyGeneratorCreate("SM4_128", &generator);
    ASSERT_EQ(ret, 0);

    ret = generator->generateSymKey(nullptr, &key);
    ASSERT_NE(ret, 0);

    HcfObjDestroy(key);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoSM4GeneratorTest, CryptoSm4GeneratorTest017, TestSize.Level0)
{
    HcfSymKeyGenerator *generator = nullptr;
    HcfSymKey *key = nullptr;
    HcfCipher *cipher = nullptr;

    int ret = HcfCipherCreate("SM4_128|ECB|PKCS5", &cipher);
    ASSERT_EQ(ret, 0);

    ret = HcfSymKeyGeneratorCreate("SM4_128", &generator);
    ASSERT_EQ(ret, 0);

    ret = generator->generateSymKey(reinterpret_cast<HcfSymKeyGenerator *>(cipher), &key);
    ASSERT_NE(ret, 0);

    HcfObjDestroy(key);
    HcfObjDestroy(generator);
    HcfObjDestroy(cipher);
}

HWTEST_F(CryptoSM4GeneratorTest, CryptoSm4GeneratorTest018, TestSize.Level0)
{
    HcfSymKeyGenerator *generator = nullptr;
    HcfSymKey *key = nullptr;
    uint8_t keyMaterial[] = {
        0xba, 0x3b, 0xc2, 0x71, 0x21, 0x1e, 0x30, 0x56,
        0xad, 0x47, 0xfc, 0x5a, 0x46, 0x39, 0xee, 0x7c
    };
    HcfBlob keyTmpBlob = { .data = keyMaterial, .len = KEY_MATERIAL_LEN };

    int ret = HcfSymKeyGeneratorCreate("SM4_128", &generator);
    ASSERT_EQ(ret, 0);

    ret = generator->convertSymKey(nullptr, &keyTmpBlob, &key);
    ASSERT_NE(ret, 0);

    HcfObjDestroy(key);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoSM4GeneratorTest, CryptoSm4GeneratorTest019, TestSize.Level0)
{
    HcfSymKeyGenerator *generator = nullptr;
    HcfSymKey *key = nullptr;
    uint8_t keyMaterial[] = {
        0xba, 0x3b, 0xc2, 0x71, 0x21, 0x1e, 0x30, 0x56,
        0xad, 0x47, 0xfc, 0x5a, 0x46, 0x39, 0xee, 0x7c
    };
    HcfBlob keyTmpBlob = { .data = keyMaterial, .len = KEY_MATERIAL_LEN };
    HcfCipher *cipher = nullptr;

    int ret = HcfCipherCreate("SM4_128|ECB|PKCS5", &cipher);
    ASSERT_EQ(ret, 0);

    ret = HcfSymKeyGeneratorCreate("SM4_128", &generator);
    ASSERT_EQ(ret, 0);

    ret = generator->convertSymKey(reinterpret_cast<HcfSymKeyGenerator *>(cipher), &keyTmpBlob, &key);
    ASSERT_NE(ret, 0);

    HcfObjDestroy(key);
    HcfObjDestroy(generator);
    HcfObjDestroy(cipher);
}

HWTEST_F(CryptoSM4GeneratorTest, CryptoSm4GeneratorTest020, TestSize.Level0)
{
    HcfSymKeyGenerator *generator = nullptr;
    HcfSymKey *key = nullptr;
    uint8_t keyMaterial[] = {
        0xba, 0x3b, 0xc2, 0x71, 0x21, 0x1e, 0x30, 0x56,
        0xad, 0x47, 0xfc, 0x5a, 0x46, 0x39, 0xee, 0x7c
    };
    HcfBlob keyTmpBlob = { .data = keyMaterial, .len = 0 };

    int ret = HcfSymKeyGeneratorCreate("SM4_128", &generator);
    ASSERT_EQ(ret, 0);

    ret = generator->convertSymKey(generator, &keyTmpBlob, &key);
    ASSERT_NE(ret, 0);


    HcfObjDestroy(key);
    HcfObjDestroy(generator);
}
}