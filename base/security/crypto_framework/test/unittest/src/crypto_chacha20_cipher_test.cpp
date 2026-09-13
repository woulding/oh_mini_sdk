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
#include "securec.h"

#include "sym_key_generator.h"
#include "cipher.h"
#include "log.h"
#include "memory.h"
#include "detailed_iv_params.h"
#include "detailed_chacha20_params.h"
#include "aes_common.h"
#include "openssl_adapter_mock.h"
#include "memory_mock.h"
#include "chacha20_openssl.h"

using namespace std;
using namespace testing::ext;

namespace {

class CryptoChacha20CipherTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp();
    void TearDown();
};

void CryptoChacha20CipherTest::SetUpTestCase() {}
void CryptoChacha20CipherTest::TearDownTestCase() {}

void CryptoChacha20CipherTest::SetUp() // add init here, this will be called before test.
{
}

void CryptoChacha20CipherTest::TearDown() // add destroy here, this will be called when test case done.
{
}

static HcfResult GenerateChacha20SymKey(HcfSymKey **key)
{
    HcfSymKeyGenerator *generator = nullptr;

    HcfResult ret = HcfSymKeyGeneratorCreate("ChaCha20", &generator);
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

static int32_t Chacha20Encrypt(HcfCipher *cipher, HcfSymKey *key, HcfParamsSpec *params,
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

static int32_t Chacha20Decrypt(HcfCipher *cipher, HcfSymKey *key, HcfParamsSpec *params,
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

HWTEST_F(CryptoChacha20CipherTest, CryptoChacha20CipherTest001, TestSize.Level0)
{
    uint8_t cipherText[128] = {0};
    int cipherTextLen = 128;

    HcfCipher *cipher = nullptr;
    HcfSymKey *key = nullptr;

    int ret = GenerateChacha20SymKey(&key);
    ASSERT_EQ(ret, 0);

    ret = HcfCipherCreate("ChaCha20", &cipher);
    ASSERT_EQ(ret, 0);

    ret = Chacha20Encrypt(cipher, key, nullptr, cipherText, &cipherTextLen);
    ASSERT_NE(ret, 0);

    HcfObjDestroy((HcfObjectBase *)key);
    HcfObjDestroy((HcfObjectBase *)cipher);
}

HWTEST_F(CryptoChacha20CipherTest, CryptoChacha20CipherTest002, TestSize.Level0)
{
    uint8_t cipherText[128] = {0};
    int cipherTextLen = 128;

    HcfCipher *cipher = nullptr;
    HcfSymKey *key = nullptr;

    uint8_t iv[16] = {0};
    HcfIvParamsSpec ivSpec = {};
    ivSpec.iv.data = iv;
    ivSpec.iv.len = 16;

    int ret = GenerateChacha20SymKey(&key);
    ASSERT_EQ(ret, 0);

    ret = HcfCipherCreate("ChaCha20", &cipher);
    ASSERT_EQ(ret, 0);

    ret = Chacha20Encrypt(cipher, key, (HcfParamsSpec *)&ivSpec, cipherText, &cipherTextLen);
    ASSERT_EQ(ret, 0);

    ret = Chacha20Decrypt(cipher, key, (HcfParamsSpec *)&ivSpec, cipherText, cipherTextLen);
    ASSERT_EQ(ret, 0);

    HcfObjDestroy((HcfObjectBase *)key);
    HcfObjDestroy((HcfObjectBase *)cipher);
}

HWTEST_F(CryptoChacha20CipherTest, CryptoChacha20CipherTest003, TestSize.Level0)
{
    uint8_t cipherText[128] = {0};
    int cipherTextLen = 128;

    HcfCipher *cipher = nullptr;
    HcfSymKey *key = nullptr;

    uint8_t aad[8] = {0};
    uint8_t tag[16] = {0};
    uint8_t iv[12] = {0}; // openssl only support nonce 12 bytes, tag 16bytes

    HcfChaCha20ParamsSpec spec = {};
    spec.aad.data = aad;
    spec.aad.len = sizeof(aad);
    spec.tag.data = tag;
    spec.tag.len = sizeof(tag);
    spec.iv.data = iv;
    spec.iv.len = sizeof(iv);

    int ret = GenerateChacha20SymKey(&key);
    ASSERT_EQ(ret, 0);

    ret = HcfCipherCreate("ChaCha20|Poly1305", &cipher);
    ASSERT_EQ(ret, 0);

    ret = Chacha20Encrypt(cipher, key, (HcfParamsSpec *)&spec, cipherText, &cipherTextLen);
    ASSERT_EQ(ret, 0);

    (void)memcpy_s(spec.tag.data, 16, cipherText + cipherTextLen - 16, 16);
    cipherTextLen -= 16;

    ret = Chacha20Decrypt(cipher, key, (HcfParamsSpec *)&spec, cipherText, cipherTextLen);
    ASSERT_EQ(ret, 0);

    HcfObjDestroy((HcfObjectBase *)key);
    HcfObjDestroy((HcfObjectBase *)cipher);
}

HWTEST_F(CryptoChacha20CipherTest, CryptoChacha20CipherTest004, TestSize.Level0)
{
    uint8_t cipherText[128] = {0};
    int cipherTextLen = 128;

    HcfCipher *cipher = nullptr;
    HcfSymKey *key = nullptr;

    uint8_t aad[8] = {0};
    uint8_t tag[16] = {0};
    uint8_t iv[16] = {0};

    HcfChaCha20ParamsSpec spec = {};
    spec.aad.data = aad;
    spec.aad.len = sizeof(aad);
    spec.tag.data = tag;
    spec.tag.len = sizeof(tag);
    spec.iv.data = iv;
    spec.iv.len = sizeof(iv);

    int ret = GenerateChacha20SymKey(&key);
    ASSERT_EQ(ret, 0);

    ret = HcfCipherCreate("ChaCha20|Poly1305", &cipher);
    ASSERT_EQ(ret, 0);

    ret = Chacha20Encrypt(cipher, key, (HcfParamsSpec *)&spec, cipherText, &cipherTextLen);
    ASSERT_EQ(ret, HCF_ERR_PARAMETER_CHECK_FAILED);

    HcfObjDestroy((HcfObjectBase *)key);
    HcfObjDestroy((HcfObjectBase *)cipher);
}

HWTEST_F(CryptoChacha20CipherTest, CryptoChacha20CipherErrTest001, TestSize.Level0)
{
    HcfCipher *cipher = nullptr;
    HcfSymKey *key = nullptr;
    HcfResult ret = GenerateChacha20SymKey(&key);
    ASSERT_EQ(ret, 0);
    ret = HcfCipherCreate("ChaCha20", &cipher);
    ASSERT_EQ(ret, 0);
    StartRecordOpensslCallNum();
    ret = cipher->init(cipher, ENCRYPT_MODE, nullptr, nullptr);
    ASSERT_NE(ret, HCF_SUCCESS);
    ret = cipher->init(cipher, ENCRYPT_MODE, (HcfKey *)key, nullptr);
    ASSERT_NE(ret, HCF_SUCCESS);
    EndRecordOpensslCallNum();
    HcfObjDestroy((HcfObjectBase *)key);
    HcfObjDestroy((HcfObjectBase *)cipher);
}

HWTEST_F(CryptoChacha20CipherTest, CryptoChacha20CipherErrTest002, TestSize.Level0)
{
    int ret = HcfCipherChaCha20GeneratorSpiCreate(nullptr, nullptr);
    if (ret != 0) {
        LOGE("HcfCipherChaCha20GeneratorSpiCreate failed!");
    }
    EXPECT_NE(ret, 0);

    HcfCipherGeneratorSpi *cipher = nullptr;
    CipherAttr params = {
        .algo = HCF_ALG_CHACHA20,
        .mode = HCF_ALG_MODE_POLY1305,
    };
    ret = HcfCipherChaCha20GeneratorSpiCreate(&params, &cipher);
    EXPECT_EQ(ret, HCF_SUCCESS);

    ret = cipher->init(nullptr, ENCRYPT_MODE, nullptr, nullptr);
    EXPECT_EQ(ret, HCF_ERR_PARAMETER_CHECK_FAILED);

    ret = cipher->update(nullptr, nullptr, nullptr);
    EXPECT_EQ(ret, HCF_ERR_PARAMETER_CHECK_FAILED);

    ret = cipher->doFinal(nullptr, nullptr, nullptr);
    EXPECT_EQ(ret, HCF_ERR_PARAMETER_CHECK_FAILED);

    HcfBlob dataArray = { .data = nullptr, .len = 0 };
    ret = cipher->getCipherSpecString(nullptr, OAEP_MGF1_MD_STR, nullptr);
    EXPECT_EQ(ret, HCF_ERR_PARAMETER_CHECK_FAILED);

    ret = cipher->getCipherSpecUint8Array(nullptr, OAEP_MGF1_MD_STR, &dataArray);
    EXPECT_EQ(ret, HCF_ERR_PARAMETER_CHECK_FAILED);

    HcfBlob dataUint8 = { .data = nullptr, .len = 0 };
    ret = cipher->setCipherSpecUint8Array(nullptr, OAEP_MGF1_MD_STR, dataUint8);
    EXPECT_EQ(ret, HCF_ERR_PARAMETER_CHECK_FAILED);

    (void)cipher->base.destroy(nullptr);

    HcfObjDestroy(cipher);
    HcfBlobDataFree(&dataArray);
}


static HcfResult Chacha20SegmentedEncrypt(HcfCipher *cipher, HcfSymKey *key, HcfParamsSpec *params,
    uint8_t *cipherText, int *cipherTextLen)
{
    uint8_t plainText[] = "This is a test message for ChaCha20 segmented encryption!";
    size_t plainTextLen = sizeof(plainText) - 1;
    HcfResult ret = cipher->init(cipher, ENCRYPT_MODE, (HcfKey *)key, params);
    if (ret != HCF_SUCCESS) {
        return ret;
    }
    int totalOutputLen = 0;
    size_t inputOffset = 0;
    const size_t segmentSize = 16;
    while (inputOffset < plainTextLen) {
        size_t currentSegmentSize = (plainTextLen - inputOffset > segmentSize) ?
            segmentSize : (plainTextLen - inputOffset);
        HcfBlob input = { .data = (uint8_t *)(plainText + inputOffset), .len = currentSegmentSize };
        HcfBlob output = {};
        ret = cipher->update(cipher, &input, &output);
        if (ret != HCF_SUCCESS) {
            return ret;
        }
        if (output.data != nullptr) {
            if (memcpy_s(cipherText + totalOutputLen, *cipherTextLen - totalOutputLen,
                output.data, output.len) != EOK) {
                HcfBlobDataFree(&output);
                return HCF_ERR_MALLOC;
            }
            totalOutputLen += output.len;
            HcfBlobDataFree(&output);
        }
        inputOffset += currentSegmentSize;
    }
    HcfBlob finalOutput = {};
    ret = cipher->doFinal(cipher, nullptr, &finalOutput);
    if (ret != HCF_SUCCESS) {
        return ret;
    }
    if (finalOutput.data != nullptr) {
        if (memcpy_s(cipherText + totalOutputLen, *cipherTextLen - totalOutputLen, finalOutput.data,
            finalOutput.len) != EOK) {
            HcfBlobDataFree(&finalOutput);
            return HCF_ERR_MALLOC;
        }
        totalOutputLen += finalOutput.len;
        HcfBlobDataFree(&finalOutput);
    }
    *cipherTextLen = totalOutputLen;
    return HCF_SUCCESS;
}

static HcfResult Chacha20SegmentedDecrypt(HcfCipher *cipher, HcfSymKey *key, HcfParamsSpec *params,
    const uint8_t *cipherText, int cipherTextLen)
{
    uint8_t expectedPlainText[] = "This is a test message for ChaCha20 segmented encryption!";
    size_t expectedPlainTextLen = sizeof(expectedPlainText) - 1;
    uint8_t plainText[256] = {0};
    size_t plainTextLen = sizeof(plainText);
    HcfResult ret = cipher->init(cipher, DECRYPT_MODE, (HcfKey *)key, params);
    if (ret != HCF_SUCCESS) {
        return ret;
    }
    int totalOutputLen = 0;
    size_t inputOffset = 0;
    const size_t segmentSize = 16;
    while (inputOffset < cipherTextLen) {
        size_t currentSegmentSize = (cipherTextLen - inputOffset > segmentSize) ?
            segmentSize : (cipherTextLen - inputOffset);
        HcfBlob input = { .data = (uint8_t *)(cipherText + inputOffset), .len = currentSegmentSize };
        HcfBlob output = {};
        ret = cipher->update(cipher, &input, &output);
        if (ret != HCF_SUCCESS) {
            return ret;
        }
        if (output.data != nullptr) {
            if (memcpy_s(plainText + totalOutputLen, plainTextLen - totalOutputLen, output.data, output.len) != EOK) {
                HcfBlobDataFree(&output);
                return HCF_ERR_MALLOC;
            }
            totalOutputLen += output.len;
            HcfBlobDataFree(&output);
        }
        inputOffset += currentSegmentSize;
    }
    HcfBlob finalOutput = {};
    ret = cipher->doFinal(cipher, nullptr, &finalOutput);
    if (ret != HCF_SUCCESS) {
        return ret;
    }
    if (finalOutput.data != nullptr) {
        if (memcpy_s(plainText + totalOutputLen, plainTextLen - totalOutputLen,
            finalOutput.data, finalOutput.len) != EOK) {
            HcfBlobDataFree(&finalOutput);
            return HCF_ERR_MALLOC;
        }
        totalOutputLen += finalOutput.len;
        HcfBlobDataFree(&finalOutput);
    }
    if (memcmp(plainText, expectedPlainText, expectedPlainTextLen) != 0) {
        return HCF_ERR_CRYPTO_OPERATION;
    }
    return HCF_SUCCESS;
}


HWTEST_F(CryptoChacha20CipherTest, CryptoChacha20SegmentedTest001, TestSize.Level0)
{
    uint8_t cipherText[256] = {0};
    int cipherTextLen = sizeof(cipherText);
    HcfCipher *cipher = nullptr;
    HcfSymKey *key = nullptr;
    HcfResult ret = GenerateChacha20SymKey(&key);
    ASSERT_EQ(ret, HCF_SUCCESS);
    ret = HcfCipherCreate("ChaCha20", &cipher);
    ASSERT_EQ(ret, HCF_SUCCESS);
    uint8_t iv[16] = {0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10};
    HcfIvParamsSpec ivSpec = {};
    ivSpec.iv.data = iv;
    ivSpec.iv.len = 16;

    ret = Chacha20SegmentedEncrypt(cipher, key, (HcfParamsSpec *)&ivSpec, cipherText, &cipherTextLen);
    ASSERT_EQ(ret, HCF_SUCCESS);
    ret = Chacha20SegmentedDecrypt(cipher, key, (HcfParamsSpec *)&ivSpec, cipherText, cipherTextLen);
    ASSERT_EQ(ret, HCF_SUCCESS);

    HcfObjDestroy((HcfObjectBase *)key);
    HcfObjDestroy((HcfObjectBase *)cipher);
}


HWTEST_F(CryptoChacha20CipherTest, CryptoChacha20SegmentedTest002, TestSize.Level0)
{
    uint8_t cipherText[256] = {0};
    int cipherTextLen = sizeof(cipherText);

    HcfCipher *cipher = nullptr;
    HcfSymKey *key = nullptr;

    HcfResult ret = GenerateChacha20SymKey(&key);
    ASSERT_EQ(ret, HCF_SUCCESS);

    ret = HcfCipherCreate("ChaCha20|Poly1305", &cipher);
    ASSERT_EQ(ret, HCF_SUCCESS);


    uint8_t aad[] = "Additional Authenticated Data";
    uint8_t tag[16] = {0};
    uint8_t iv[12] = {0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47, 0x48, 0x49, 0x4a, 0x4b, 0x4c};

    HcfChaCha20ParamsSpec spec = {};
    spec.aad.data = aad;
    spec.aad.len = sizeof(aad) - 1;
    spec.tag.data = tag;
    spec.tag.len = sizeof(tag);
    spec.iv.data = iv;
    spec.iv.len = sizeof(iv);

    ret = Chacha20SegmentedEncrypt(cipher, key, (HcfParamsSpec *)&spec, cipherText, &cipherTextLen);
    ASSERT_EQ(ret, HCF_SUCCESS);


    (void)memcpy_s(spec.tag.data, 16, cipherText + cipherTextLen - 16, 16);
    cipherTextLen -= 16;

    ret = Chacha20SegmentedDecrypt(cipher, key, (HcfParamsSpec *)&spec, cipherText, cipherTextLen);
    ASSERT_EQ(ret, HCF_SUCCESS);

    HcfObjDestroy((HcfObjectBase *)key);
    HcfObjDestroy((HcfObjectBase *)cipher);
}


HWTEST_F(CryptoChacha20CipherTest, CryptoChacha20SegmentedTest003, TestSize.Level0)
{
    uint8_t cipherText[256] = {0};
    int cipherTextLen = sizeof(cipherText);

    HcfCipher *cipher = nullptr;
    HcfSymKey *key = nullptr;

    HcfResult ret = GenerateChacha20SymKey(&key);
    ASSERT_EQ(ret, HCF_SUCCESS);

    ret = HcfCipherCreate("ChaCha20", &cipher);
    ASSERT_EQ(ret, HCF_SUCCESS);


    uint8_t iv[8] = {0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08};
    HcfIvParamsSpec ivSpec = {};
    ivSpec.iv.data = iv;
    ivSpec.iv.len = 8;

    ret = Chacha20SegmentedEncrypt(cipher, key, (HcfParamsSpec *)&ivSpec, cipherText, &cipherTextLen);

    ASSERT_NE(ret, HCF_SUCCESS);

    HcfObjDestroy((HcfObjectBase *)key);
    HcfObjDestroy((HcfObjectBase *)cipher);
}


static void OpensslMockTestFunc(uint32_t mallocCount, HcfParamsSpec *params, HcfCryptoMode mode)
{
    for (uint32_t i = 0; i < mallocCount; i++) {
        ResetOpensslCallNum();
        SetOpensslCallMockIndex(i);

        HcfCipher *cipher = nullptr;
        HcfSymKey *key = nullptr;
        HcfResult ret = GenerateChacha20SymKey(&key);
        if (ret != HCF_SUCCESS) {
            continue;
        }
        ret = HcfCipherCreate("ChaCha20", &cipher);
        if (ret != HCF_SUCCESS) {
            HcfObjDestroy((HcfObjectBase *)key);
            continue;
        }
        ret = cipher->init(cipher, mode, (HcfKey *)key, params);
        if (ret != HCF_SUCCESS) {
            HcfObjDestroy((HcfObjectBase *)key);
            HcfObjDestroy((HcfObjectBase *)cipher);
            continue;
        }
        uint8_t plainText[] = "ChaCha20 test data for mock";
        HcfBlob input = {.data = (uint8_t *)plainText, .len = sizeof(plainText) - 1};
        HcfBlob output = {.data = nullptr, .len = 0};

        ret = cipher->update(cipher, &input, &output);
        if (ret != HCF_SUCCESS) {
            HcfObjDestroy((HcfObjectBase *)key);
            HcfObjDestroy((HcfObjectBase *)cipher);
            continue;
        }
        HcfBlobDataFree(&output);

        ret = cipher->doFinal(cipher, nullptr, &output);
        if (ret != HCF_SUCCESS) {
            HcfObjDestroy((HcfObjectBase *)key);
            HcfObjDestroy((HcfObjectBase *)cipher);
            continue;
        }
        HcfBlobDataFree(&output);

        HcfObjDestroy((HcfObjectBase *)key);
        HcfObjDestroy((HcfObjectBase *)cipher);
    }
}


static void OpensslMockTestFuncPoly1305(uint32_t mallocCount, HcfParamsSpec *params, HcfCryptoMode mode)
{
    for (uint32_t i = 0; i < mallocCount; i++) {
        ResetOpensslCallNum();
        SetOpensslCallMockIndex(i);

        HcfCipher *cipher = nullptr;
        HcfSymKey *key = nullptr;

        HcfResult ret = GenerateChacha20SymKey(&key);
        if (ret != HCF_SUCCESS) {
            continue;
        }

        ret = HcfCipherCreate("ChaCha20|Poly1305", &cipher);
        if (ret != HCF_SUCCESS) {
            HcfObjDestroy((HcfObjectBase *)key);
            continue;
        }

        ret = cipher->init(cipher, mode, (HcfKey *)key, params);
        if (ret != HCF_SUCCESS) {
            HcfObjDestroy((HcfObjectBase *)key);
            HcfObjDestroy((HcfObjectBase *)cipher);
            continue;
        }

        uint8_t plainText[] = "ChaCha20-Poly1305 test data for mock";
        HcfBlob input = {.data = (uint8_t *)plainText, .len = sizeof(plainText) - 1};
        HcfBlob output = {.data = nullptr, .len = 0};

        ret = cipher->update(cipher, &input, &output);
        if (ret != HCF_SUCCESS) {
            HcfObjDestroy((HcfObjectBase *)key);
            HcfObjDestroy((HcfObjectBase *)cipher);
            continue;
        }
        HcfBlobDataFree(&output);

        uint8_t finalData[] = "final data for mock";
        HcfBlob finalInput = {.data = finalData, .len = sizeof(finalData) - 1};
        ret = cipher->doFinal(cipher, &finalInput, &output);
        if (ret != HCF_SUCCESS) {
            HcfObjDestroy((HcfObjectBase *)key);
            HcfObjDestroy((HcfObjectBase *)cipher);
            continue;
        }
        HcfBlobDataFree(&output);

        HcfObjDestroy((HcfObjectBase *)key);
        HcfObjDestroy((HcfObjectBase *)cipher);
    }
}

HWTEST_F(CryptoChacha20CipherTest, CryptoChacha20MockTest001, TestSize.Level0)
{
    StartRecordOpensslCallNum();
    HcfCipher *cipher = nullptr;
    HcfSymKey *key = nullptr;

    HcfResult ret = GenerateChacha20SymKey(&key);
    ASSERT_EQ(ret, HCF_SUCCESS);

    ret = HcfCipherCreate("ChaCha20", &cipher);
    ASSERT_EQ(ret, HCF_SUCCESS);

    uint8_t iv[16] = {0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10};
    HcfIvParamsSpec ivSpec = {};
    ivSpec.iv.data = iv;
    ivSpec.iv.len = 16;

    ret = cipher->init(cipher, ENCRYPT_MODE, (HcfKey *)key, (HcfParamsSpec *)&ivSpec);
    ASSERT_EQ(ret, HCF_SUCCESS);

    uint8_t plainText[] = "ChaCha20 test data for mock test";
    HcfBlob input = {.data = (uint8_t *)plainText, .len = sizeof(plainText) - 1};
    HcfBlob output = {.data = nullptr, .len = 0};

    ret = cipher->update(cipher, &input, &output);
    ASSERT_EQ(ret, HCF_SUCCESS);
    HcfBlobDataFree(&output);

    ret = cipher->doFinal(cipher, nullptr, &output);
    ASSERT_EQ(ret, HCF_SUCCESS);
    HcfBlobDataFree(&output);

    HcfObjDestroy((HcfObjectBase *)key);
    HcfObjDestroy((HcfObjectBase *)cipher);

    uint32_t mallocCount = GetOpensslCallNum();
    OpensslMockTestFunc(mallocCount, (HcfParamsSpec *)&ivSpec, ENCRYPT_MODE);

    EndRecordOpensslCallNum();
}

HWTEST_F(CryptoChacha20CipherTest, CryptoChacha20MockTest002, TestSize.Level0)
{
    StartRecordOpensslCallNum();
    HcfCipher *cipher = nullptr;
    HcfSymKey *key = nullptr;

    HcfResult ret = GenerateChacha20SymKey(&key);
    ASSERT_EQ(ret, HCF_SUCCESS);

    ret = HcfCipherCreate("ChaCha20|Poly1305", &cipher);
    ASSERT_EQ(ret, HCF_SUCCESS);

    uint8_t aad[] = "Additional Authenticated Data";
    uint8_t tag[16] = {0};
    uint8_t iv[12] = {0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c};

    HcfChaCha20ParamsSpec spec = {};
    spec.aad.data = aad;
    spec.aad.len = sizeof(aad) - 1;
    spec.tag.data = tag;
    spec.tag.len = sizeof(tag);
    spec.iv.data = iv;
    spec.iv.len = sizeof(iv);

    ret = cipher->init(cipher, ENCRYPT_MODE, (HcfKey *)key, (HcfParamsSpec *)&spec);
    ASSERT_EQ(ret, HCF_SUCCESS);

    uint8_t plainText[] = "ChaCha20-Poly1305 test data for mock test";
    HcfBlob input = {.data = (uint8_t *)plainText, .len = sizeof(plainText) - 1};
    HcfBlob output = {.data = nullptr, .len = 0};

    ret = cipher->update(cipher, &input, &output);
    ASSERT_EQ(ret, HCF_SUCCESS);
    HcfBlobDataFree(&output);

    uint8_t finalData[] = "final data for doFinal";
    HcfBlob finalInput = {.data = finalData, .len = sizeof(finalData) - 1};
    ret = cipher->doFinal(cipher, &finalInput, &output);
    ASSERT_EQ(ret, HCF_SUCCESS);
    HcfBlobDataFree(&output);

    HcfObjDestroy((HcfObjectBase *)key);
    HcfObjDestroy((HcfObjectBase *)cipher);

    uint32_t mallocCount = GetOpensslCallNum();
    OpensslMockTestFuncPoly1305(mallocCount, (HcfParamsSpec *)&spec, ENCRYPT_MODE);

    EndRecordOpensslCallNum();
}

HWTEST_F(CryptoChacha20CipherTest, CryptoChacha20DecryptMockTest001, TestSize.Level0)
{
    StartRecordOpensslCallNum();
    HcfCipher *cipher = nullptr;
    HcfSymKey *key = nullptr;

    HcfResult ret = GenerateChacha20SymKey(&key);
    ASSERT_EQ(ret, HCF_SUCCESS);

    ret = HcfCipherCreate("ChaCha20|Poly1305", &cipher);
    ASSERT_EQ(ret, HCF_SUCCESS);

    uint8_t aad[] = "Additional Authenticated Data";
    uint8_t tag[16] = {0};
    uint8_t iv[12] = {0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c};

    HcfChaCha20ParamsSpec spec = {};
    spec.aad.data = aad;
    spec.aad.len = sizeof(aad) - 1;
    spec.tag.data = tag;
    spec.tag.len = sizeof(tag);
    spec.iv.data = iv;
    spec.iv.len = sizeof(iv);

    ret = cipher->init(cipher, DECRYPT_MODE, (HcfKey *)key, (HcfParamsSpec *)&spec);
    ASSERT_EQ(ret, HCF_SUCCESS);

    uint8_t plainText[] = "ChaCha20-Poly1305 test data for mock test";
    HcfBlob input = {.data = (uint8_t *)plainText, .len = sizeof(plainText) - 1};
    HcfBlob output = {.data = nullptr, .len = 0};

    ret = cipher->update(cipher, &input, &output);
    ASSERT_EQ(ret, HCF_SUCCESS);
    HcfBlobDataFree(&output);

    uint8_t finalData[] = "final data for doFinal";
    HcfBlob finalInput = {.data = finalData, .len = sizeof(finalData) - 1};
    ret = cipher->doFinal(cipher, &finalInput, &output);
    ASSERT_NE(ret, HCF_SUCCESS);
    HcfBlobDataFree(&output);

    HcfObjDestroy((HcfObjectBase *)key);
    HcfObjDestroy((HcfObjectBase *)cipher);

    uint32_t mallocCount = GetOpensslCallNum();
    OpensslMockTestFuncPoly1305(mallocCount, (HcfParamsSpec *)&spec, DECRYPT_MODE);

    EndRecordOpensslCallNum();
}

HWTEST_F(CryptoChacha20CipherTest, CryptoChacha20DecryptMockTest002, TestSize.Level0)
{
    StartRecordOpensslCallNum();
    HcfCipher *cipher = nullptr;
    HcfSymKey *key = nullptr;

    HcfResult ret = GenerateChacha20SymKey(&key);
    ASSERT_EQ(ret, HCF_SUCCESS);

    ret = HcfCipherCreate("ChaCha20", &cipher);
    ASSERT_EQ(ret, HCF_SUCCESS);

    uint8_t iv[16] = {0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
                      0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10};
    HcfIvParamsSpec ivSpec = {};
    ivSpec.iv.data = iv;
    ivSpec.iv.len = 16;

    ret = cipher->init(cipher, DECRYPT_MODE, (HcfKey *)key, (HcfParamsSpec *)&ivSpec);
    ASSERT_EQ(ret, HCF_SUCCESS);

    uint8_t plainText[] = "ChaCha20 test data for mock test";
    HcfBlob input = {.data = (uint8_t *)plainText, .len = sizeof(plainText) - 1};
    HcfBlob output = {.data = nullptr, .len = 0};

    ret = cipher->update(cipher, &input, &output);
    ASSERT_EQ(ret, HCF_SUCCESS);
    HcfBlobDataFree(&output);

    ret = cipher->doFinal(cipher, nullptr, &output);
    ASSERT_EQ(ret, HCF_SUCCESS);
    HcfBlobDataFree(&output);

    HcfObjDestroy((HcfObjectBase *)key);
    HcfObjDestroy((HcfObjectBase *)cipher);

    uint32_t mallocCount = GetOpensslCallNum();
    OpensslMockTestFunc(mallocCount, (HcfParamsSpec *)&ivSpec, DECRYPT_MODE);

    EndRecordOpensslCallNum();
}

HWTEST_F(CryptoChacha20CipherTest, CryptoChacha20DoFinalWithInputTest001, TestSize.Level0)
{
    uint8_t plainText[] = "Test doFinal with input data";
    size_t plainTextLen = sizeof(plainText) - 1;
    uint8_t cipherText[256] = {0};
    uint8_t decryptedText[256] = {0};
    size_t cipherTextLen = sizeof(cipherText);
    size_t decryptedTextLen = sizeof(decryptedText);

    HcfCipher *cipher = nullptr;
    HcfSymKey *key = nullptr;

    HcfResult ret = GenerateChacha20SymKey(&key);
    ASSERT_EQ(ret, HCF_SUCCESS);

    ret = HcfCipherCreate("ChaCha20", &cipher);
    ASSERT_EQ(ret, HCF_SUCCESS);

    uint8_t iv[16] = {0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
                      0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10};
    HcfIvParamsSpec ivSpec = {};
    ivSpec.iv.data = iv;
    ivSpec.iv.len = 16;

    ret = cipher->init(cipher, ENCRYPT_MODE, (HcfKey *)key, (HcfParamsSpec *)&ivSpec);
    ASSERT_EQ(ret, HCF_SUCCESS);

    HcfBlob input = {.data = (uint8_t *)plainText, .len = plainTextLen};
    HcfBlob output = {};
    ret = cipher->doFinal(cipher, &input, &output);
    ASSERT_EQ(ret, HCF_SUCCESS);

    if (output.data != nullptr) {
        (void)memcpy_s(cipherText, cipherTextLen, output.data, output.len);
        cipherTextLen = output.len;
        HcfBlobDataFree(&output);
    }

    ret = cipher->init(cipher, DECRYPT_MODE, (HcfKey *)key, (HcfParamsSpec *)&ivSpec);
    ASSERT_EQ(ret, HCF_SUCCESS);

    HcfBlob decryptInput = {.data = cipherText, .len = cipherTextLen};
    HcfBlob decryptOutput = {};
    ret = cipher->doFinal(cipher, &decryptInput, &decryptOutput);
    ASSERT_EQ(ret, HCF_SUCCESS);

    if (decryptOutput.data != nullptr) {
        (void)memcpy_s(decryptedText, decryptedTextLen, decryptOutput.data, decryptOutput.len);
        decryptedTextLen = decryptOutput.len;
        HcfBlobDataFree(&decryptOutput);
    }

    ASSERT_EQ(decryptedTextLen, plainTextLen);
    ASSERT_EQ(memcmp(plainText, decryptedText, plainTextLen), 0);

    HcfObjDestroy((HcfObjectBase *)key);
    HcfObjDestroy((HcfObjectBase *)cipher);
}

HWTEST_F(CryptoChacha20CipherTest, CryptoChacha20Poly1305DoFinalWithInputTest001, TestSize.Level0)
{
    uint8_t plainText[] = "Test ChaCha20-Poly1305 doFinal with input";
    size_t plainTextLen = sizeof(plainText) - 1;
    uint8_t cipherText[256] = {0};
    uint8_t decryptedText[256] = {0};
    size_t cipherTextLen = sizeof(cipherText);
    size_t decryptedTextLen = sizeof(decryptedText);

    HcfCipher *cipher = nullptr;
    HcfSymKey *key = nullptr;

    HcfResult ret = GenerateChacha20SymKey(&key);
    ASSERT_EQ(ret, HCF_SUCCESS);

    ret = HcfCipherCreate("ChaCha20|Poly1305", &cipher);
    ASSERT_EQ(ret, HCF_SUCCESS);

    uint8_t aad[] = "Additional Authenticated Data";
    uint8_t tag[16] = {0};
    uint8_t iv[12] = {0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c};

    HcfChaCha20ParamsSpec spec = {
        .iv = {.data = iv, .len = sizeof(iv)},
        .aad = {.data = aad, .len = sizeof(aad) - 1},
        .tag = {.data = tag, .len = sizeof(tag)}
    };

    ret = cipher->init(cipher, ENCRYPT_MODE, (HcfKey *)key, (HcfParamsSpec *)&spec);
    ASSERT_EQ(ret, HCF_SUCCESS);

    HcfBlob input = {.data = (uint8_t *)plainText, .len = plainTextLen};
    HcfBlob output = {};
    ret = cipher->doFinal(cipher, &input, &output);
    ASSERT_EQ(ret, HCF_SUCCESS);

    if (output.data != nullptr) {
        (void)memcpy_s(cipherText, cipherTextLen, output.data, output.len);
        cipherTextLen = output.len;
        HcfBlobDataFree(&output);
    }

    (void)memcpy_s(spec.tag.data, 16, cipherText + cipherTextLen - 16, 16);
    cipherTextLen -= 16;

    ret = cipher->init(cipher, DECRYPT_MODE, (HcfKey *)key, (HcfParamsSpec *)&spec);
    ASSERT_EQ(ret, HCF_SUCCESS);

    HcfBlob decryptInput = {.data = cipherText, .len = cipherTextLen};
    HcfBlob decryptOutput = {};
    ret = cipher->doFinal(cipher, &decryptInput, &decryptOutput);
    ASSERT_EQ(ret, HCF_SUCCESS);

    if (decryptOutput.data != nullptr) {
        (void)memcpy_s(decryptedText, decryptedTextLen, decryptOutput.data, decryptOutput.len);
        decryptedTextLen = decryptOutput.len;
        HcfBlobDataFree(&decryptOutput);
    }

    ASSERT_EQ(decryptedTextLen, plainTextLen);
    ASSERT_EQ(memcmp(plainText, decryptedText, plainTextLen), 0);

    HcfObjDestroy((HcfObjectBase *)key);
    HcfObjDestroy((HcfObjectBase *)cipher);
}

static void MemoryMallocTestFunc(uint32_t mallocCount, HcfParamsSpec *params)
{
    for (uint32_t i = 0; i < mallocCount; i++) {
        ResetRecordMallocNum();
        SetMockMallocIndex(i);

        HcfCipher *cipher = nullptr;
        HcfSymKey *key = nullptr;

        HcfResult ret = GenerateChacha20SymKey(&key);
        if (ret != HCF_SUCCESS) {
            continue;
        }

        ret = HcfCipherCreate("ChaCha20", &cipher);
        if (ret != HCF_SUCCESS) {
            HcfObjDestroy((HcfObjectBase *)key);
            continue;
        }

        ret = cipher->init(cipher, ENCRYPT_MODE, (HcfKey *)key, params);
        if (ret != HCF_SUCCESS) {
            HcfObjDestroy((HcfObjectBase *)key);
            HcfObjDestroy((HcfObjectBase *)cipher);
            continue;
        }

        uint8_t plainText[] = "ChaCha20 memory malloc test data";
        HcfBlob input = {.data = (uint8_t *)plainText, .len = sizeof(plainText) - 1};
        HcfBlob output = {.data = nullptr, .len = 0};

        ret = cipher->update(cipher, &input, &output);
        if (ret != HCF_SUCCESS) {
            HcfObjDestroy((HcfObjectBase *)key);
            HcfObjDestroy((HcfObjectBase *)cipher);
            continue;
        }
        HcfBlobDataFree(&output);

        ret = cipher->doFinal(cipher, nullptr, &output);
        HcfObjDestroy((HcfObjectBase *)key);
        HcfObjDestroy((HcfObjectBase *)cipher);
        if (ret == HCF_SUCCESS) {
            HcfBlobDataFree(&output);
        }
    }
}

static void MemoryMallocTestFuncPoly1305(uint32_t mallocCount, HcfParamsSpec *params)
{
    for (uint32_t i = 0; i < mallocCount; i++) {
        ResetRecordMallocNum();
        SetMockMallocIndex(i);

        HcfCipher *cipher = nullptr;
        HcfSymKey *key = nullptr;

        HcfResult ret = GenerateChacha20SymKey(&key);
        if (ret != HCF_SUCCESS) {
            continue;
        }

        ret = HcfCipherCreate("ChaCha20|Poly1305", &cipher);
        if (ret != HCF_SUCCESS) {
            HcfObjDestroy((HcfObjectBase *)key);
            continue;
        }

        ret = cipher->init(cipher, ENCRYPT_MODE, (HcfKey *)key, params);
        if (ret != HCF_SUCCESS) {
            HcfObjDestroy((HcfObjectBase *)key);
            HcfObjDestroy((HcfObjectBase *)cipher);
            continue;
        }

        uint8_t plainText[] = "ChaCha20-Poly1305 memory malloc test data";
        HcfBlob input = {.data = (uint8_t *)plainText, .len = sizeof(plainText) - 1};
        HcfBlob output = {.data = nullptr, .len = 0};

        ret = cipher->update(cipher, &input, &output);
        if (ret != HCF_SUCCESS) {
            HcfObjDestroy((HcfObjectBase *)key);
            HcfObjDestroy((HcfObjectBase *)cipher);
            continue;
        }
        HcfBlobDataFree(&output);

        ret = cipher->doFinal(cipher, nullptr, &output);
        HcfObjDestroy((HcfObjectBase *)key);
        HcfObjDestroy((HcfObjectBase *)cipher);
        if (ret == HCF_SUCCESS) {
            HcfBlobDataFree(&output);
        }
    }
}

HWTEST_F(CryptoChacha20CipherTest, CryptoChacha20MemoryMallocTest001, TestSize.Level0)
{
    StartRecordMallocNum();
    HcfCipher *cipher = nullptr;
    HcfSymKey *key = nullptr;

    HcfResult ret = GenerateChacha20SymKey(&key);
    ASSERT_EQ(ret, HCF_SUCCESS);

    ret = HcfCipherCreate("ChaCha20", &cipher);
    ASSERT_EQ(ret, HCF_SUCCESS);

    uint8_t iv[16] = {0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
                      0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10};
    HcfIvParamsSpec ivSpec = {};
    ivSpec.iv.data = iv;
    ivSpec.iv.len = 16;

    ret = cipher->init(cipher, ENCRYPT_MODE, (HcfKey *)key, (HcfParamsSpec *)&ivSpec);
    ASSERT_EQ(ret, HCF_SUCCESS);

    uint8_t plainText[] = "ChaCha20 memory malloc test";
    HcfBlob input = {.data = (uint8_t *)plainText, .len = sizeof(plainText) - 1};
    HcfBlob output = {.data = nullptr, .len = 0};

    ret = cipher->update(cipher, &input, &output);
    ASSERT_EQ(ret, HCF_SUCCESS);
    HcfBlobDataFree(&output);

    ret = cipher->doFinal(cipher, nullptr, &output);
    ASSERT_EQ(ret, HCF_SUCCESS);
    HcfBlobDataFree(&output);

    HcfObjDestroy((HcfObjectBase *)key);
    HcfObjDestroy((HcfObjectBase *)cipher);

    uint32_t mallocCount = GetMallocNum();
    MemoryMallocTestFunc(mallocCount, (HcfParamsSpec *)&ivSpec);

    EndRecordMallocNum();
}

HWTEST_F(CryptoChacha20CipherTest, CryptoChacha20MemoryMallocTest002, TestSize.Level0)
{
    StartRecordMallocNum();
    HcfCipher *cipher = nullptr;
    HcfSymKey *key = nullptr;

    HcfResult ret = GenerateChacha20SymKey(&key);
    ASSERT_EQ(ret, HCF_SUCCESS);

    ret = HcfCipherCreate("ChaCha20|Poly1305", &cipher);
    ASSERT_EQ(ret, HCF_SUCCESS);

    uint8_t aad[] = "Additional Authenticated Data";
    uint8_t tag[16] = {0};
    uint8_t iv[12] = {0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c};

    HcfChaCha20ParamsSpec spec = {};
    spec.aad.data = aad;
    spec.aad.len = sizeof(aad) - 1;
    spec.tag.data = tag;
    spec.tag.len = sizeof(tag);
    spec.iv.data = iv;
    spec.iv.len = sizeof(iv);

    ret = cipher->init(cipher, ENCRYPT_MODE, (HcfKey *)key, (HcfParamsSpec *)&spec);
    ASSERT_EQ(ret, HCF_SUCCESS);

    uint8_t plainText[] = "ChaCha20-Poly1305 memory malloc test";
    HcfBlob input = {.data = (uint8_t *)plainText, .len = sizeof(plainText) - 1};
    HcfBlob output = {.data = nullptr, .len = 0};

    ret = cipher->update(cipher, &input, &output);
    ASSERT_EQ(ret, HCF_SUCCESS);
    HcfBlobDataFree(&output);

    ret = cipher->doFinal(cipher, nullptr, &output);
    ASSERT_EQ(ret, HCF_SUCCESS);
    HcfBlobDataFree(&output);

    HcfObjDestroy((HcfObjectBase *)key);
    HcfObjDestroy((HcfObjectBase *)cipher);

    uint32_t mallocCount = GetMallocNum();
    MemoryMallocTestFuncPoly1305(mallocCount, (HcfParamsSpec *)&spec);

    EndRecordMallocNum();
}

}

 