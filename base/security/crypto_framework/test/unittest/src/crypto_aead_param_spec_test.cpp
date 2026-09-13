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
#include <vector>
#include "securec.h"

#include "aes_common.h"
#include "blob.h"
#include "cipher.h"
#include "detailed_aead_params.h"
#include "log.h"
#include "memory.h"
#include "sm4_common.h"
#include "sym_key_generator.h"

using namespace testing::ext;

namespace {
static const uint8_t TEST_PLAIN_TEXT[] = "this is test!this is testthis is testthis is test!";
static const uint32_t AEAD_TAG_LEN = 16;
static const uint32_t CHACHA20_NONCE_LEN = 12;

static const char *GetAeadParamsSpecTypeForTest(void)
{
    return "AeadParamsSpec";
}

static HcfResult GenerateChacha20SymKey(HcfSymKey **key)
{
    HcfSymKeyGenerator *generator = nullptr;
    HcfResult ret = HcfSymKeyGeneratorCreate("ChaCha20", &generator);
    if ((ret != HCF_SUCCESS) || (generator == nullptr)) {
        LOGE("HcfSymKeyGeneratorCreate failed!");
        return ret;
    }
    ret = generator->generateSymKey(generator, key);
    HcfObjDestroy(reinterpret_cast<HcfObjectBase *>(generator));
    return ret;
}

static HcfResult ConvertAesSymKeyFromData(const uint8_t *keyData, size_t keyLen, HcfSymKey **key)
{
    HcfSymKeyGenerator *generator = nullptr;
    HcfBlob keyBlob = {.data = const_cast<uint8_t *>(keyData), .len = keyLen};
    HcfResult ret = HcfSymKeyGeneratorCreate("AES128", &generator);
    if ((ret != HCF_SUCCESS) || (generator == nullptr)) {
        return ret;
    }
    ret = generator->convertSymKey(generator, &keyBlob, key);
    HcfObjDestroy(reinterpret_cast<HcfObjectBase *>(generator));
    return ret;
}

static HcfResult ConvertSm4SymKeyFromData(const uint8_t *keyData, size_t keyLen, HcfSymKey **key)
{
    HcfSymKeyGenerator *generator = nullptr;
    HcfBlob keyBlob = {.data = const_cast<uint8_t *>(keyData), .len = keyLen};
    HcfResult ret = HcfSymKeyGeneratorCreate("SM4_128", &generator);
    if ((ret != HCF_SUCCESS) || (generator == nullptr)) {
        return ret;
    }
    ret = generator->convertSymKey(generator, &keyBlob, key);
    HcfObjDestroy(reinterpret_cast<HcfObjectBase *>(generator));
    return ret;
}

static HcfResult ConvertChacha20SymKeyFromData(const uint8_t *keyData, size_t keyLen, HcfSymKey **key)
{
    HcfSymKeyGenerator *generator = nullptr;
    HcfBlob keyBlob = {.data = const_cast<uint8_t *>(keyData), .len = keyLen};
    HcfResult ret = HcfSymKeyGeneratorCreate("ChaCha20", &generator);
    if ((ret != HCF_SUCCESS) || (generator == nullptr)) {
        return ret;
    }
    ret = generator->convertSymKey(generator, &keyBlob, key);
    HcfObjDestroy(reinterpret_cast<HcfObjectBase *>(generator));
    return ret;
}

static int32_t AeadEncryptWithInput(HcfCipher *cipher, HcfSymKey *key, HcfAeadParamsSpec *params,
    const HcfBlob &input, HcfBlob *output)
{
    int32_t ret = cipher->init(cipher, ENCRYPT_MODE, reinterpret_cast<HcfKey *>(key),
        reinterpret_cast<HcfParamsSpec *>(params));
    if (ret != HCF_SUCCESS) {
        return ret;
    }
    return cipher->doFinal(cipher, const_cast<HcfBlob *>(&input), output);
}

static int32_t AeadDecryptWithInput(HcfCipher *cipher, HcfSymKey *key, HcfAeadParamsSpec *params,
    const HcfBlob &input, HcfBlob *output)
{
    int32_t ret = cipher->init(cipher, DECRYPT_MODE, reinterpret_cast<HcfKey *>(key),
        reinterpret_cast<HcfParamsSpec *>(params));
    if (ret != HCF_SUCCESS) {
        return ret;
    }
    return cipher->doFinal(cipher, const_cast<HcfBlob *>(&input), output);
}

static int32_t AeadEncrypt(HcfCipher *cipher, HcfSymKey *key, HcfAeadParamsSpec *params, std::vector<uint8_t> &out)
{
    HcfBlob input = {.data = const_cast<uint8_t *>(TEST_PLAIN_TEXT), .len = sizeof(TEST_PLAIN_TEXT) - 1};
    HcfBlob output = {};
    int32_t ret = cipher->init(cipher, ENCRYPT_MODE, reinterpret_cast<HcfKey *>(key),
        reinterpret_cast<HcfParamsSpec *>(params));
    if (ret != HCF_SUCCESS) {
        return ret;
    }
    ret = cipher->doFinal(cipher, &input, &output);
    if (ret != HCF_SUCCESS) {
        return ret;
    }
    out.assign(output.data, output.data + output.len);
    HcfBlobDataFree(&output);
    return HCF_SUCCESS;
}

static int32_t AeadDecrypt(HcfCipher *cipher, HcfSymKey *key, HcfAeadParamsSpec *params, const std::vector<uint8_t> &in)
{
    HcfBlob input = {.data = const_cast<uint8_t *>(in.data()), .len = in.size()};
    HcfBlob output = {};
    int32_t ret = cipher->init(cipher, DECRYPT_MODE, reinterpret_cast<HcfKey *>(key),
        reinterpret_cast<HcfParamsSpec *>(params));
    if (ret != HCF_SUCCESS) {
        return ret;
    }
    ret = cipher->doFinal(cipher, &input, &output);
    if (ret != HCF_SUCCESS) {
        return ret;
    }
    bool ok = (output.len == sizeof(TEST_PLAIN_TEXT) - 1) &&
        (memcmp(output.data, TEST_PLAIN_TEXT, output.len) == 0);
    HcfBlobDataFree(&output);
    return ok ? HCF_SUCCESS : HCF_ERR_CRYPTO_OPERATION;
}

static void AppendBlobToVector(const HcfBlob &blob, std::vector<uint8_t> &out)
{
    if (blob.data != nullptr && blob.len > 0) {
        out.insert(out.end(), blob.data, blob.data + blob.len);
    }
}

typedef struct {
    HcfCipher *cipher;
    HcfSymKey *key;
    HcfAeadParamsSpec *params;
    uint32_t splitPos;
} AeadUpdateFinalContext;

static int32_t AeadEncryptByUpdateAndDoFinal(const AeadUpdateFinalContext &ctx, const HcfBlob &input,
    std::vector<uint8_t> &out)
{
    if (ctx.cipher == nullptr || ctx.key == nullptr || ctx.params == nullptr) {
        return HCF_ERR_PARAMETER_CHECK_FAILED;
    }
    uint32_t splitPos = ctx.splitPos;
    if (splitPos > input.len) {
        return HCF_ERR_PARAMETER_CHECK_FAILED;
    }
    HcfBlob updateInput = {.data = input.data, .len = splitPos};
    HcfBlob finalInput = {.data = input.data + splitPos, .len = input.len - splitPos};
    HcfBlob updateOutput = {};
    HcfBlob finalOutput = {};

    int32_t ret = ctx.cipher->init(ctx.cipher, ENCRYPT_MODE, reinterpret_cast<HcfKey *>(ctx.key),
        reinterpret_cast<HcfParamsSpec *>(ctx.params));
    if (ret != HCF_SUCCESS) {
        return ret;
    }
    ret = ctx.cipher->update(ctx.cipher, &updateInput, &updateOutput);
    if (ret != HCF_SUCCESS) {
        return ret;
    }
    ret = ctx.cipher->doFinal(ctx.cipher, &finalInput, &finalOutput);
    if (ret != HCF_SUCCESS) {
        HcfBlobDataFree(&updateOutput);
        return ret;
    }
    out.clear();
    AppendBlobToVector(updateOutput, out);
    AppendBlobToVector(finalOutput, out);
    HcfBlobDataFree(&updateOutput);
    HcfBlobDataFree(&finalOutput);
    return HCF_SUCCESS;
}

static int32_t AeadDecryptByUpdateAndDoFinal(const AeadUpdateFinalContext &ctx,
    const std::vector<uint8_t> &cipherWithTag, std::vector<uint8_t> &plainOut)
{
    if (ctx.cipher == nullptr || ctx.key == nullptr || ctx.params == nullptr) {
        return HCF_ERR_PARAMETER_CHECK_FAILED;
    }
    uint32_t splitPos = ctx.splitPos;
    if (splitPos > cipherWithTag.size()) {
        return HCF_ERR_PARAMETER_CHECK_FAILED;
    }
    HcfBlob updateInput = {.data = const_cast<uint8_t *>(cipherWithTag.data()), .len = splitPos};
    HcfBlob finalInput = {.data = const_cast<uint8_t *>(cipherWithTag.data() + splitPos),
        .len = cipherWithTag.size() - splitPos};
    HcfBlob updateOutput = {};
    HcfBlob finalOutput = {};

    int32_t ret = ctx.cipher->init(ctx.cipher, DECRYPT_MODE, reinterpret_cast<HcfKey *>(ctx.key),
        reinterpret_cast<HcfParamsSpec *>(ctx.params));
    if (ret != HCF_SUCCESS) {
        return ret;
    }
    ret = ctx.cipher->update(ctx.cipher, &updateInput, &updateOutput);
    if (ret != HCF_SUCCESS) {
        return ret;
    }
    ret = ctx.cipher->doFinal(ctx.cipher, &finalInput, &finalOutput);
    if (ret != HCF_SUCCESS) {
        HcfBlobDataFree(&updateOutput);
        return ret;
    }
    plainOut.clear();
    AppendBlobToVector(updateOutput, plainOut);
    AppendBlobToVector(finalOutput, plainOut);
    HcfBlobDataFree(&updateOutput);
    HcfBlobDataFree(&finalOutput);
    return HCF_SUCCESS;
}

class CryptoAeadParamsSpecTest : public testing::Test {
public:
    static void SetUpTestCase() {};
    static void TearDownTestCase() {};
    void SetUp() {};
    void TearDown() {};
};

HWTEST_F(CryptoAeadParamsSpecTest, CryptoAeadParamsSpecAesGcmSuccess001, TestSize.Level0)
{
    HcfCipher *cipher = nullptr;
    HcfSymKey *key = nullptr;
    uint8_t aad[GCM_AAD_LEN] = {0};
    uint8_t nonce[GCM_IV_LEN] = {0};

    HcfAeadParamsSpec spec = {};
    spec.base.getType = GetAeadParamsSpecTypeForTest;
    spec.nonce.data = nonce;
    spec.nonce.len = sizeof(nonce);
    spec.aad.data = aad;
    spec.aad.len = sizeof(aad);
    spec.tagLen = AEAD_TAG_LEN;

    ASSERT_EQ(GenerateSymKey("AES256", &key), HCF_SUCCESS);
    ASSERT_EQ(HcfCipherCreate("AES256|GCM|NoPadding", &cipher), HCF_SUCCESS);

    std::vector<uint8_t> cipherWithTag;
    ASSERT_EQ(AeadEncrypt(cipher, key, &spec, cipherWithTag), HCF_SUCCESS);
    ASSERT_GT(cipherWithTag.size(), spec.tagLen);
    ASSERT_EQ(AeadDecrypt(cipher, key, &spec, cipherWithTag), HCF_SUCCESS);

    HcfObjDestroy(reinterpret_cast<HcfObjectBase *>(cipher));
    HcfObjDestroy(reinterpret_cast<HcfObjectBase *>(key));
}

HWTEST_F(CryptoAeadParamsSpecTest, CryptoAeadParamsSpecAesGcmInvalidParam001, TestSize.Level0)
{
    HcfCipher *cipher = nullptr;
    HcfSymKey *key = nullptr;
    uint8_t aad[GCM_AAD_LEN] = {0};
    uint8_t nonce[GCM_IV_LEN] = {0};

    HcfAeadParamsSpec spec = {};
    spec.base.getType = GetAeadParamsSpecTypeForTest;
    spec.nonce.data = nonce;
    spec.nonce.len = sizeof(nonce);
    spec.aad.data = aad;
    spec.aad.len = sizeof(aad);
    spec.tagLen = GCM_TAG_LEN + 1;

    ASSERT_EQ(GenerateSymKey("AES128", &key), HCF_SUCCESS);
    ASSERT_EQ(HcfCipherCreate("AES128|GCM|NoPadding", &cipher), HCF_SUCCESS);

    std::vector<uint8_t> cipherWithTag;
    ASSERT_NE(AeadEncrypt(cipher, key, &spec, cipherWithTag), HCF_SUCCESS);

    spec.tagLen = AEAD_TAG_LEN;
    spec.nonce.data = nullptr;
    ASSERT_NE(AeadEncrypt(cipher, key, &spec, cipherWithTag), HCF_SUCCESS);

    HcfObjDestroy(reinterpret_cast<HcfObjectBase *>(cipher));
    HcfObjDestroy(reinterpret_cast<HcfObjectBase *>(key));
}

HWTEST_F(CryptoAeadParamsSpecTest, CryptoAeadParamsSpecAesGcmTamperTag001, TestSize.Level0)
{
    HcfCipher *cipher = nullptr;
    HcfSymKey *key = nullptr;
    uint8_t aad[GCM_AAD_LEN] = {0};
    uint8_t nonce[GCM_IV_LEN] = {0};

    HcfAeadParamsSpec spec = {};
    spec.base.getType = GetAeadParamsSpecTypeForTest;
    spec.nonce.data = nonce;
    spec.nonce.len = sizeof(nonce);
    spec.aad.data = aad;
    spec.aad.len = sizeof(aad);
    spec.tagLen = AEAD_TAG_LEN;

    ASSERT_EQ(GenerateSymKey("AES192", &key), HCF_SUCCESS);
    ASSERT_EQ(HcfCipherCreate("AES192|GCM|NoPadding", &cipher), HCF_SUCCESS);

    std::vector<uint8_t> cipherWithTag;
    ASSERT_EQ(AeadEncrypt(cipher, key, &spec, cipherWithTag), HCF_SUCCESS);
    ASSERT_FALSE(cipherWithTag.empty());
    cipherWithTag[cipherWithTag.size() - 1] ^= 0x01;
    ASSERT_NE(AeadDecrypt(cipher, key, &spec, cipherWithTag), HCF_SUCCESS);

    HcfObjDestroy(reinterpret_cast<HcfObjectBase *>(cipher));
    HcfObjDestroy(reinterpret_cast<HcfObjectBase *>(key));
}

HWTEST_F(CryptoAeadParamsSpecTest, CryptoAeadParamsSpecAesGcmUpdateThenDoFinalSuccess001, TestSize.Level0)
{
    HcfCipher *cipher = nullptr;
    HcfSymKey *key = nullptr;
    uint8_t aad[GCM_AAD_LEN] = {0};
    uint8_t nonce[GCM_IV_LEN] = {0};
    HcfBlob plain = {.data = const_cast<uint8_t *>(TEST_PLAIN_TEXT), .len = sizeof(TEST_PLAIN_TEXT) - 1};

    HcfAeadParamsSpec spec = {};
    spec.base.getType = GetAeadParamsSpecTypeForTest;
    spec.nonce.data = nonce;
    spec.nonce.len = sizeof(nonce);
    spec.aad.data = aad;
    spec.aad.len = sizeof(aad);
    spec.tagLen = AEAD_TAG_LEN;

    ASSERT_EQ(GenerateSymKey("AES256", &key), HCF_SUCCESS);
    ASSERT_EQ(HcfCipherCreate("AES256|GCM|NoPadding", &cipher), HCF_SUCCESS);

    uint32_t splitPos = 5;
    AeadUpdateFinalContext ctx = {.cipher = cipher, .key = key, .params = &spec, .splitPos = splitPos};
    std::vector<uint8_t> cipherWithTag;
    ASSERT_EQ(AeadEncryptByUpdateAndDoFinal(ctx, plain, cipherWithTag), HCF_SUCCESS);
    ASSERT_EQ(cipherWithTag.size(), plain.len + spec.tagLen);

    std::vector<uint8_t> plainOut;
    ASSERT_EQ(AeadDecryptByUpdateAndDoFinal(ctx, cipherWithTag, plainOut), HCF_SUCCESS);
    ASSERT_EQ(plainOut.size(), plain.len);
    ASSERT_EQ(memcmp(plainOut.data(), TEST_PLAIN_TEXT, plainOut.size()), 0);

    HcfObjDestroy(reinterpret_cast<HcfObjectBase *>(cipher));
    HcfObjDestroy(reinterpret_cast<HcfObjectBase *>(key));
}

HWTEST_F(CryptoAeadParamsSpecTest, CryptoAeadParamsSpecSm4GcmSuccess001, TestSize.Level0)
{
    HcfCipher *cipher = nullptr;
    HcfSymKey *key = nullptr;
    uint8_t aad[GCM_AAD_LEN] = {0};
    uint8_t nonce[GCM_IV_LEN] = {0};

    HcfAeadParamsSpec spec = {};
    spec.base.getType = GetAeadParamsSpecTypeForTest;
    spec.nonce.data = nonce;
    spec.nonce.len = sizeof(nonce);
    spec.aad.data = aad;
    spec.aad.len = sizeof(aad);
    spec.tagLen = AEAD_TAG_LEN;

    ASSERT_EQ(GenerateSymKey("SM4_128", &key), HCF_SUCCESS);
    ASSERT_EQ(HcfCipherCreate("SM4_128|GCM|NoPadding", &cipher), HCF_SUCCESS);

    std::vector<uint8_t> cipherWithTag;
    ASSERT_EQ(AeadEncrypt(cipher, key, &spec, cipherWithTag), HCF_SUCCESS);
    ASSERT_GT(cipherWithTag.size(), spec.tagLen);
    ASSERT_EQ(AeadDecrypt(cipher, key, &spec, cipherWithTag), HCF_SUCCESS);

    HcfObjDestroy(reinterpret_cast<HcfObjectBase *>(cipher));
    HcfObjDestroy(reinterpret_cast<HcfObjectBase *>(key));
}

HWTEST_F(CryptoAeadParamsSpecTest, CryptoAeadParamsSpecSm4GcmInvalidParam001, TestSize.Level0)
{
    HcfCipher *cipher = nullptr;
    HcfSymKey *key = nullptr;
    uint8_t aad[GCM_AAD_LEN] = {0};
    uint8_t nonce[GCM_IV_LEN] = {0};

    HcfAeadParamsSpec spec = {};
    spec.base.getType = GetAeadParamsSpecTypeForTest;
    spec.nonce.data = nonce;
    spec.nonce.len = sizeof(nonce);
    spec.aad.data = aad;
    spec.aad.len = sizeof(aad);
    spec.tagLen = GCM_TAG_LEN + 1;

    ASSERT_EQ(GenerateSymKey("SM4_128", &key), HCF_SUCCESS);
    ASSERT_EQ(HcfCipherCreate("SM4_128|GCM|NoPadding", &cipher), HCF_SUCCESS);

    std::vector<uint8_t> cipherWithTag;
    ASSERT_NE(AeadEncrypt(cipher, key, &spec, cipherWithTag), HCF_SUCCESS);

    spec.tagLen = AEAD_TAG_LEN;
    spec.nonce.len = 0;
    ASSERT_NE(AeadEncrypt(cipher, key, &spec, cipherWithTag), HCF_SUCCESS);

    HcfObjDestroy(reinterpret_cast<HcfObjectBase *>(cipher));
    HcfObjDestroy(reinterpret_cast<HcfObjectBase *>(key));
}

HWTEST_F(CryptoAeadParamsSpecTest, CryptoAeadParamsSpecSm4GcmUpdateThenDoFinalSuccess001, TestSize.Level0)
{
    HcfCipher *cipher = nullptr;
    HcfSymKey *key = nullptr;
    uint8_t aad[GCM_AAD_LEN] = {0};
    uint8_t nonce[GCM_IV_LEN] = {0};
    HcfBlob plain = {.data = const_cast<uint8_t *>(TEST_PLAIN_TEXT), .len = sizeof(TEST_PLAIN_TEXT) - 1};

    HcfAeadParamsSpec spec = {};
    spec.base.getType = GetAeadParamsSpecTypeForTest;
    spec.nonce.data = nonce;
    spec.nonce.len = sizeof(nonce);
    spec.aad.data = aad;
    spec.aad.len = sizeof(aad);
    spec.tagLen = AEAD_TAG_LEN;

    ASSERT_EQ(GenerateSymKey("SM4_128", &key), HCF_SUCCESS);
    ASSERT_EQ(HcfCipherCreate("SM4_128|GCM|NoPadding", &cipher), HCF_SUCCESS);

    uint32_t splitPos = 7;
    AeadUpdateFinalContext ctx = {.cipher = cipher, .key = key, .params = &spec, .splitPos = splitPos};
    std::vector<uint8_t> cipherWithTag;
    ASSERT_EQ(AeadEncryptByUpdateAndDoFinal(ctx, plain, cipherWithTag), HCF_SUCCESS);
    ASSERT_EQ(cipherWithTag.size(), plain.len + spec.tagLen);

    std::vector<uint8_t> plainOut;
    ASSERT_EQ(AeadDecryptByUpdateAndDoFinal(ctx, cipherWithTag, plainOut), HCF_SUCCESS);
    ASSERT_EQ(plainOut.size(), plain.len);
    ASSERT_EQ(memcmp(plainOut.data(), TEST_PLAIN_TEXT, plainOut.size()), 0);

    HcfObjDestroy(reinterpret_cast<HcfObjectBase *>(cipher));
    HcfObjDestroy(reinterpret_cast<HcfObjectBase *>(key));
}

HWTEST_F(CryptoAeadParamsSpecTest, CryptoAeadParamsSpecChacha20Poly1305Success001, TestSize.Level0)
{
    HcfCipher *cipher = nullptr;
    HcfSymKey *key = nullptr;
    uint8_t aad[GCM_AAD_LEN] = {0};
    uint8_t nonce[CHACHA20_NONCE_LEN] = {0};

    HcfAeadParamsSpec spec = {};
    spec.base.getType = GetAeadParamsSpecTypeForTest;
    spec.nonce.data = nonce;
    spec.nonce.len = sizeof(nonce);
    spec.aad.data = aad;
    spec.aad.len = sizeof(aad);
    spec.tagLen = AEAD_TAG_LEN;

    ASSERT_EQ(GenerateChacha20SymKey(&key), HCF_SUCCESS);
    ASSERT_EQ(HcfCipherCreate("ChaCha20|Poly1305", &cipher), HCF_SUCCESS);

    std::vector<uint8_t> cipherWithTag;
    ASSERT_EQ(AeadEncrypt(cipher, key, &spec, cipherWithTag), HCF_SUCCESS);
    ASSERT_GT(cipherWithTag.size(), spec.tagLen);
    ASSERT_EQ(AeadDecrypt(cipher, key, &spec, cipherWithTag), HCF_SUCCESS);

    HcfObjDestroy(reinterpret_cast<HcfObjectBase *>(cipher));
    HcfObjDestroy(reinterpret_cast<HcfObjectBase *>(key));
}

HWTEST_F(CryptoAeadParamsSpecTest, CryptoAeadParamsSpecChacha20Poly1305InvalidParam001, TestSize.Level0)
{
    HcfCipher *cipher = nullptr;
    HcfSymKey *key = nullptr;
    uint8_t aad[GCM_AAD_LEN] = {0};
    uint8_t nonce[CHACHA20_NONCE_LEN] = {0};

    HcfAeadParamsSpec spec = {};
    spec.base.getType = GetAeadParamsSpecTypeForTest;
    spec.nonce.data = nonce;
    spec.nonce.len = sizeof(nonce) - 1;
    spec.aad.data = aad;
    spec.aad.len = sizeof(aad);
    spec.tagLen = AEAD_TAG_LEN;

    ASSERT_EQ(GenerateChacha20SymKey(&key), HCF_SUCCESS);
    ASSERT_EQ(HcfCipherCreate("ChaCha20|Poly1305", &cipher), HCF_SUCCESS);

    std::vector<uint8_t> cipherWithTag;
    ASSERT_NE(AeadEncrypt(cipher, key, &spec, cipherWithTag), HCF_SUCCESS);

    spec.nonce.len = sizeof(nonce);
    spec.tagLen = GCM_TAG_LEN + 1;
    ASSERT_NE(AeadEncrypt(cipher, key, &spec, cipherWithTag), HCF_SUCCESS);

    HcfObjDestroy(reinterpret_cast<HcfObjectBase *>(cipher));
    HcfObjDestroy(reinterpret_cast<HcfObjectBase *>(key));
}

HWTEST_F(CryptoAeadParamsSpecTest, CryptoAeadParamsSpecChacha20Poly1305TamperTag001, TestSize.Level0)
{
    HcfCipher *cipher = nullptr;
    HcfSymKey *key = nullptr;
    uint8_t aad[GCM_AAD_LEN] = {0};
    uint8_t nonce[CHACHA20_NONCE_LEN] = {0};

    HcfAeadParamsSpec spec = {};
    spec.base.getType = GetAeadParamsSpecTypeForTest;
    spec.nonce.data = nonce;
    spec.nonce.len = sizeof(nonce);
    spec.aad.data = aad;
    spec.aad.len = sizeof(aad);
    spec.tagLen = AEAD_TAG_LEN;

    ASSERT_EQ(GenerateChacha20SymKey(&key), HCF_SUCCESS);
    ASSERT_EQ(HcfCipherCreate("ChaCha20|Poly1305", &cipher), HCF_SUCCESS);

    std::vector<uint8_t> cipherWithTag;
    ASSERT_EQ(AeadEncrypt(cipher, key, &spec, cipherWithTag), HCF_SUCCESS);
    ASSERT_FALSE(cipherWithTag.empty());
    cipherWithTag[cipherWithTag.size() - 1] ^= 0x01;
    ASSERT_NE(AeadDecrypt(cipher, key, &spec, cipherWithTag), HCF_SUCCESS);

    HcfObjDestroy(reinterpret_cast<HcfObjectBase *>(cipher));
    HcfObjDestroy(reinterpret_cast<HcfObjectBase *>(key));
}

HWTEST_F(CryptoAeadParamsSpecTest, CryptoAeadParamsSpecChacha20Poly1305UpdateThenDoFinalSuccess001, TestSize.Level0)
{
    HcfCipher *cipher = nullptr;
    HcfSymKey *key = nullptr;
    uint8_t aad[GCM_AAD_LEN] = {0};
    uint8_t nonce[CHACHA20_NONCE_LEN] = {0};
    HcfBlob plain = {.data = const_cast<uint8_t *>(TEST_PLAIN_TEXT), .len = sizeof(TEST_PLAIN_TEXT) - 1};

    HcfAeadParamsSpec spec = {};
    spec.base.getType = GetAeadParamsSpecTypeForTest;
    spec.nonce.data = nonce;
    spec.nonce.len = sizeof(nonce);
    spec.aad.data = aad;
    spec.aad.len = sizeof(aad);
    spec.tagLen = AEAD_TAG_LEN;

    ASSERT_EQ(GenerateChacha20SymKey(&key), HCF_SUCCESS);
    ASSERT_EQ(HcfCipherCreate("ChaCha20|Poly1305", &cipher), HCF_SUCCESS);

    uint32_t splitPos = 6;
    AeadUpdateFinalContext ctx = {.cipher = cipher, .key = key, .params = &spec, .splitPos = splitPos};
    std::vector<uint8_t> cipherWithTag;
    ASSERT_EQ(AeadEncryptByUpdateAndDoFinal(ctx, plain, cipherWithTag), HCF_SUCCESS);
    ASSERT_EQ(cipherWithTag.size(), plain.len + spec.tagLen);

    std::vector<uint8_t> plainOut;
    ASSERT_EQ(AeadDecryptByUpdateAndDoFinal(ctx, cipherWithTag, plainOut), HCF_SUCCESS);
    ASSERT_EQ(plainOut.size(), plain.len);
    ASSERT_EQ(memcmp(plainOut.data(), TEST_PLAIN_TEXT, plainOut.size()), 0);

    HcfObjDestroy(reinterpret_cast<HcfObjectBase *>(cipher));
    HcfObjDestroy(reinterpret_cast<HcfObjectBase *>(key));
}

enum AeadVectorKeyType {
    AEAD_KEY_AES128 = 0,
    AEAD_KEY_SM4_128,
    AEAD_KEY_CHACHA20,
};

typedef struct {
    AeadVectorKeyType keyType;
    const char *cipherName;
    const uint8_t *key;
    size_t keyLen;
    const uint8_t *iv;
    size_t ivLen;
    const uint8_t *aad;
    size_t aadLen;
    const uint8_t *tag;
    size_t tagLen;
    const uint8_t *plain;
    size_t plainLen;
    const uint8_t *cipher;
    size_t cipherLen;
} AeadVectorCase;

static AeadVectorCase GetAesGcmVector001(void)
{
    static const uint8_t key[] = {
        0xf0, 0xd4, 0x4d, 0x3c, 0x8c, 0x8f, 0xf4, 0xd2, 0xaa, 0xb5, 0xc3, 0x15, 0xe7, 0x7a, 0x5c, 0xff
    };
    static const uint8_t iv[] = {0x3e};
    static const uint8_t tag[] = {0xfe, 0x0c, 0x50, 0xde, 0x4c, 0x54, 0x43, 0xe4, 0xc9, 0x38, 0x0a, 0x7d, 0xf0};
    static const uint8_t plain[] = {
        0xec, 0xb7, 0xe9, 0x26, 0x3c, 0x30, 0x80, 0xcb, 0x88, 0x61, 0xff, 0xc5, 0xaf, 0xdf, 0x3f, 0xe8
    };
    static const uint8_t cipher[] = {
        0xb5, 0xcf, 0xd9, 0x14, 0x1e, 0xa4, 0x3d, 0x5c, 0x16, 0xe2, 0x86, 0x66, 0xc3, 0x84, 0x08, 0x05
    };
    return { AEAD_KEY_AES128, "AES128|GCM|NoPadding", key, sizeof(key), iv, sizeof(iv), nullptr, 0, tag, sizeof(tag),
        plain, sizeof(plain), cipher, sizeof(cipher) };
}

static AeadVectorCase GetAesGcmVector002(void)
{
    static const uint8_t key[] = {
        0xc4, 0x22, 0xac, 0x02, 0x66, 0xdc, 0x9b, 0x5d, 0xdc, 0x39, 0x1d, 0x9c, 0xdb, 0x72, 0x25, 0x7e
    };
    static const uint8_t iv[] = {0xc7};
    static const uint8_t aad[] = {
        0xaa, 0x56, 0xb1, 0x60, 0xc5, 0xd5, 0x1a, 0x4a, 0xa4, 0x00, 0xe7, 0x98, 0xc8, 0x25, 0xaa, 0xa2,
        0x7d, 0x66, 0x93, 0xde
    };
    static const uint8_t tag[] = {0x95, 0xc1, 0xe4, 0x10, 0xd4, 0xea, 0x59, 0xdd, 0xa5, 0x0d, 0x84, 0x16, 0x2b, 0x49};
    static const uint8_t plain[] = {
        0x61, 0x49, 0x27, 0x71, 0x75, 0xc0, 0x2a, 0x46, 0x2d, 0xab, 0x21, 0x9b, 0x80, 0xd1, 0x56, 0x41,
        0xa4, 0xc0, 0x33, 0xdf, 0xa4, 0xc9, 0xa8, 0x1d, 0xe1, 0x76, 0x5f, 0x02, 0x76, 0x00, 0x8f, 0xa2
    };
    static const uint8_t cipher[] = {
        0x39, 0xd9, 0xf9, 0xb2, 0x34, 0x82, 0x14, 0x27, 0x0f, 0x1c, 0xa1, 0x8b, 0x52, 0x1f, 0x74, 0x85,
        0xc5, 0x39, 0x0c, 0x8e, 0x99, 0x3e, 0xb7, 0xff, 0x79, 0xa5, 0xbe, 0x99, 0xc7, 0xd5, 0x23, 0xf1
    };
    return { AEAD_KEY_AES128, "AES128|GCM|NoPadding", key, sizeof(key), iv, sizeof(iv), aad, sizeof(aad), tag,
        sizeof(tag), plain, sizeof(plain), cipher, sizeof(cipher) };
}

static AeadVectorCase GetSm4GcmVector001(void)
{
    static const uint8_t key[] = {
        0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10
    };
    static const uint8_t iv[] = {0x00, 0x00, 0x12, 0x34, 0x56, 0x78, 0x00, 0x00, 0x00, 0x00, 0xab, 0xcd};
    static const uint8_t aad[] = {
        0xfe, 0xed, 0xfa, 0xce, 0xde, 0xad, 0xbe, 0xef, 0xfe, 0xed, 0xfa, 0xce, 0xde, 0xad, 0xbe, 0xef,
        0xab, 0xad, 0xda, 0xd2
    };
    static const uint8_t tag[] = {
        0x83, 0xde, 0x35, 0x41, 0xe4, 0xc2, 0xb5, 0x81, 0x77, 0xe0, 0x65, 0xa9, 0xbf, 0x7b, 0x62, 0xec
    };
    static const uint8_t plain[] = {
        0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xbb, 0xbb, 0xbb, 0xbb, 0xbb, 0xbb, 0xbb, 0xbb,
        0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xdd, 0xdd, 0xdd, 0xdd, 0xdd, 0xdd, 0xdd, 0xdd,
        0xee, 0xee, 0xee, 0xee, 0xee, 0xee, 0xee, 0xee, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xee, 0xee, 0xee, 0xee, 0xee, 0xee, 0xee, 0xee, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa
    };
    static const uint8_t cipher[] = {
        0x17, 0xf3, 0x99, 0xf0, 0x8c, 0x67, 0xd5, 0xee, 0x19, 0xd0, 0xdc, 0x99, 0x69, 0xc4, 0xbb, 0x7d,
        0x5f, 0xd4, 0x6f, 0xd3, 0x75, 0x64, 0x89, 0x06, 0x91, 0x57, 0xb2, 0x82, 0xbb, 0x20, 0x07, 0x35,
        0xd8, 0x27, 0x10, 0xca, 0x5c, 0x22, 0xf0, 0xcc, 0xfa, 0x7c, 0xbf, 0x93, 0xd4, 0x96, 0xac, 0x15,
        0xa5, 0x68, 0x34, 0xcb, 0xcf, 0x98, 0xc3, 0x97, 0xb4, 0x02, 0x4a, 0x26, 0x91, 0x23, 0x3b, 0x8d
    };
    return { AEAD_KEY_SM4_128, "SM4_128|GCM|NoPadding", key, sizeof(key), iv, sizeof(iv), aad, sizeof(aad), tag,
        sizeof(tag), plain, sizeof(plain), cipher, sizeof(cipher) };
}

static AeadVectorCase GetChacha20Poly1305Vector001(void)
{
    static const uint8_t key[] = {
        0x80, 0x81, 0x82, 0x83, 0x84, 0x85, 0x86, 0x87, 0x88, 0x89, 0x8a, 0x8b, 0x8c, 0x8d, 0x8e, 0x8f,
        0x90, 0x91, 0x92, 0x93, 0x94, 0x95, 0x96, 0x97, 0x98, 0x99, 0x9a, 0x9b, 0x9c, 0x9d, 0x9e, 0x9f
    };
    static const uint8_t iv[] = {0x07, 0x00, 0x00, 0x00, 0x40, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47};
    static const uint8_t aad[] = {0x50, 0x51, 0x52, 0x53, 0xc0, 0xc1, 0xc2, 0xc3, 0xc4, 0xc5, 0xc6, 0xc7};
    static const uint8_t tag[] = {
        0x1a, 0xe1, 0x0b, 0x59, 0x4f, 0x09, 0xe2, 0x6a, 0x7e, 0x90, 0x2e, 0xcb, 0xd0, 0x60, 0x06, 0x91
    };
    static const uint8_t plain[] = {
        0x4c, 0x61, 0x64, 0x69, 0x65, 0x73, 0x20, 0x61, 0x6e, 0x64, 0x20, 0x47, 0x65, 0x6e, 0x74, 0x6c,
        0x65, 0x6d, 0x65, 0x6e, 0x20, 0x6f, 0x66, 0x20, 0x74, 0x68, 0x65, 0x20, 0x63, 0x6c, 0x61, 0x73,
        0x73, 0x20, 0x6f, 0x66, 0x20, 0x27, 0x39, 0x39, 0x3a, 0x20, 0x49, 0x66, 0x20, 0x49, 0x20, 0x63,
        0x6f, 0x75, 0x6c, 0x64, 0x20, 0x6f, 0x66, 0x66, 0x65, 0x72, 0x20, 0x79, 0x6f, 0x75, 0x20, 0x6f,
        0x6e, 0x6c, 0x79, 0x20, 0x6f, 0x6e, 0x65, 0x20, 0x74, 0x69, 0x70, 0x20, 0x66, 0x6f, 0x72, 0x20,
        0x74, 0x68, 0x65, 0x20, 0x66, 0x75, 0x74, 0x75, 0x72, 0x65, 0x2c, 0x20, 0x73, 0x75, 0x6e, 0x73,
        0x63, 0x72, 0x65, 0x65, 0x6e, 0x20, 0x77, 0x6f, 0x75, 0x6c, 0x64, 0x20, 0x62, 0x65, 0x20, 0x69,
        0x74, 0x2e
    };
    static const uint8_t cipher[] = {
        0xd3, 0x1a, 0x8d, 0x34, 0x64, 0x8e, 0x60, 0xdb, 0x7b, 0x86, 0xaf, 0xbc, 0x53, 0xef, 0x7e, 0xc2,
        0xa4, 0xad, 0xed, 0x51, 0x29, 0x6e, 0x08, 0xfe, 0xa9, 0xe2, 0xb5, 0xa7, 0x36, 0xee, 0x62, 0xd6,
        0x3d, 0xbe, 0xa4, 0x5e, 0x8c, 0xa9, 0x67, 0x12, 0x82, 0xfa, 0xfb, 0x69, 0xda, 0x92, 0x72, 0x8b,
        0x1a, 0x71, 0xde, 0x0a, 0x9e, 0x06, 0x0b, 0x29, 0x05, 0xd6, 0xa5, 0xb6, 0x7e, 0xcd, 0x3b, 0x36,
        0x92, 0xdd, 0xbd, 0x7f, 0x2d, 0x77, 0x8b, 0x8c, 0x98, 0x03, 0xae, 0xe3, 0x28, 0x09, 0x1b, 0x58,
        0xfa, 0xb3, 0x24, 0xe4, 0xfa, 0xd6, 0x75, 0x94, 0x55, 0x85, 0x80, 0x8b, 0x48, 0x31, 0xd7, 0xbc,
        0x3f, 0xf4, 0xde, 0xf0, 0x8e, 0x4b, 0x7a, 0x9d, 0xe5, 0x76, 0xd2, 0x65, 0x86, 0xce, 0xc6, 0x4b,
        0x61, 0x16
    };
    return { AEAD_KEY_CHACHA20, "ChaCha20|Poly1305", key, sizeof(key), iv, sizeof(iv), aad, sizeof(aad), tag,
        sizeof(tag), plain, sizeof(plain), cipher, sizeof(cipher) };
}

static HcfResult ConvertVectorKey(AeadVectorKeyType keyType, const uint8_t *keyData, size_t keyLen, HcfSymKey **key)
{
    switch (keyType) {
        case AEAD_KEY_AES128:
            return ConvertAesSymKeyFromData(keyData, keyLen, key);
        case AEAD_KEY_SM4_128:
            return ConvertSm4SymKeyFromData(keyData, keyLen, key);
        case AEAD_KEY_CHACHA20:
            return ConvertChacha20SymKeyFromData(keyData, keyLen, key);
        default:
            return HCF_ERR_PARAMETER_CHECK_FAILED;
    }
}

typedef struct {
    HcfBlob iv;
    HcfBlob aad;
    HcfBlob plain;
    HcfBlob expectCipher;
    HcfBlob expectTag;
    HcfBlob encOutput;
    HcfBlob decOutput;
    HcfCipher *cipher;
    HcfSymKey *key;
} AeadVectorRuntime;

static void InitAeadVectorRuntime(AeadVectorRuntime &rt)
{
    (void)memset_s(&rt, sizeof(rt), 0, sizeof(rt));
}

static void FreeAeadVectorRuntime(AeadVectorRuntime &rt)
{
    HcfBlobDataFree(&rt.encOutput);
    HcfBlobDataFree(&rt.decOutput);
    HcfObjDestroy(reinterpret_cast<HcfObjectBase *>(rt.cipher));
    HcfObjDestroy(reinterpret_cast<HcfObjectBase *>(rt.key));
}

HWTEST_F(CryptoAeadParamsSpecTest, CryptoAeadParamsSpecAesGcmVector001, TestSize.Level0)
{
    AeadVectorCase vec = GetAesGcmVector001();
    AeadVectorRuntime rt;
    InitAeadVectorRuntime(rt);
    rt.iv.data = const_cast<uint8_t *>(vec.iv);
    rt.iv.len = vec.ivLen;
    rt.plain.data = const_cast<uint8_t *>(vec.plain);
    rt.plain.len = vec.plainLen;
    rt.expectCipher.data = const_cast<uint8_t *>(vec.cipher);
    rt.expectCipher.len = vec.cipherLen;
    rt.expectTag.data = const_cast<uint8_t *>(vec.tag);
    rt.expectTag.len = vec.tagLen;
    ASSERT_EQ(ConvertVectorKey(vec.keyType, vec.key, vec.keyLen, &rt.key), HCF_SUCCESS);
    ASSERT_EQ(HcfCipherCreate(vec.cipherName, &rt.cipher), HCF_SUCCESS);
    HcfAeadParamsSpec spec = { .base = { .getType = GetAeadParamsSpecTypeForTest }, .nonce = rt.iv, .aad = rt.aad,
        .tagLen = static_cast<int32_t>(rt.expectTag.len) };
    ASSERT_EQ(AeadEncryptWithInput(rt.cipher, rt.key, &spec, rt.plain, &rt.encOutput), HCF_SUCCESS);
    ASSERT_EQ(rt.encOutput.len, rt.expectCipher.len + rt.expectTag.len);
    ASSERT_EQ(memcmp(rt.encOutput.data, rt.expectCipher.data, rt.expectCipher.len), 0);
    ASSERT_EQ(memcmp(rt.encOutput.data + rt.expectCipher.len, rt.expectTag.data, rt.expectTag.len), 0);
    ASSERT_EQ(AeadDecryptWithInput(rt.cipher, rt.key, &spec, rt.encOutput, &rt.decOutput), HCF_SUCCESS);
    ASSERT_EQ(rt.decOutput.len, rt.plain.len);
    ASSERT_EQ(memcmp(rt.decOutput.data, rt.plain.data, rt.plain.len), 0);
    HcfBlobDataFree(&rt.encOutput);
    HcfBlobDataFree(&rt.decOutput);
    HcfObjDestroy(reinterpret_cast<HcfObjectBase *>(rt.cipher));
    HcfObjDestroy(reinterpret_cast<HcfObjectBase *>(rt.key));
}

HWTEST_F(CryptoAeadParamsSpecTest, CryptoAeadParamsSpecAesGcmVector002, TestSize.Level0)
{
    AeadVectorCase vec = GetAesGcmVector002();
    AeadVectorRuntime rt;
    InitAeadVectorRuntime(rt);
    rt.iv.data = const_cast<uint8_t *>(vec.iv);
    rt.iv.len = vec.ivLen;
    rt.aad.data = const_cast<uint8_t *>(vec.aad);
    rt.aad.len = vec.aadLen;
    rt.plain.data = const_cast<uint8_t *>(vec.plain);
    rt.plain.len = vec.plainLen;
    rt.expectCipher.data = const_cast<uint8_t *>(vec.cipher);
    rt.expectCipher.len = vec.cipherLen;
    rt.expectTag.data = const_cast<uint8_t *>(vec.tag);
    rt.expectTag.len = vec.tagLen;
    ASSERT_EQ(ConvertVectorKey(vec.keyType, vec.key, vec.keyLen, &rt.key), HCF_SUCCESS);
    ASSERT_EQ(HcfCipherCreate(vec.cipherName, &rt.cipher), HCF_SUCCESS);
    HcfAeadParamsSpec spec = { .base = { .getType = GetAeadParamsSpecTypeForTest }, .nonce = rt.iv, .aad = rt.aad,
        .tagLen = static_cast<int32_t>(rt.expectTag.len) };
    ASSERT_EQ(AeadEncryptWithInput(rt.cipher, rt.key, &spec, rt.plain, &rt.encOutput), HCF_SUCCESS);
    ASSERT_EQ(rt.encOutput.len, rt.expectCipher.len + rt.expectTag.len);
    ASSERT_EQ(memcmp(rt.encOutput.data, rt.expectCipher.data, rt.expectCipher.len), 0);
    ASSERT_EQ(memcmp(rt.encOutput.data + rt.expectCipher.len, rt.expectTag.data, rt.expectTag.len), 0);
    ASSERT_EQ(AeadDecryptWithInput(rt.cipher, rt.key, &spec, rt.encOutput, &rt.decOutput), HCF_SUCCESS);
    ASSERT_EQ(rt.decOutput.len, rt.plain.len);
    ASSERT_EQ(memcmp(rt.decOutput.data, rt.plain.data, rt.plain.len), 0);
    FreeAeadVectorRuntime(rt);
}

HWTEST_F(CryptoAeadParamsSpecTest, CryptoAeadParamsSpecSm4GcmVector001, TestSize.Level0)
{
    AeadVectorCase vec = GetSm4GcmVector001();
    AeadVectorRuntime rt;
    InitAeadVectorRuntime(rt);
    rt.iv.data = const_cast<uint8_t *>(vec.iv);
    rt.iv.len = vec.ivLen;
    rt.aad.data = const_cast<uint8_t *>(vec.aad);
    rt.aad.len = vec.aadLen;
    rt.plain.data = const_cast<uint8_t *>(vec.plain);
    rt.plain.len = vec.plainLen;
    rt.expectCipher.data = const_cast<uint8_t *>(vec.cipher);
    rt.expectCipher.len = vec.cipherLen;
    rt.expectTag.data = const_cast<uint8_t *>(vec.tag);
    rt.expectTag.len = vec.tagLen;
    ASSERT_EQ(ConvertVectorKey(vec.keyType, vec.key, vec.keyLen, &rt.key), HCF_SUCCESS);
    ASSERT_EQ(HcfCipherCreate(vec.cipherName, &rt.cipher), HCF_SUCCESS);
    HcfAeadParamsSpec spec = { .base = { .getType = GetAeadParamsSpecTypeForTest }, .nonce = rt.iv, .aad = rt.aad,
        .tagLen = static_cast<int32_t>(rt.expectTag.len) };
    ASSERT_EQ(AeadEncryptWithInput(rt.cipher, rt.key, &spec, rt.plain, &rt.encOutput), HCF_SUCCESS);
    ASSERT_EQ(rt.encOutput.len, rt.expectCipher.len + rt.expectTag.len);
    ASSERT_EQ(memcmp(rt.encOutput.data, rt.expectCipher.data, rt.expectCipher.len), 0);
    ASSERT_EQ(memcmp(rt.encOutput.data + rt.expectCipher.len, rt.expectTag.data, rt.expectTag.len), 0);
    ASSERT_EQ(AeadDecryptWithInput(rt.cipher, rt.key, &spec, rt.encOutput, &rt.decOutput), HCF_SUCCESS);
    ASSERT_EQ(rt.decOutput.len, rt.plain.len);
    ASSERT_EQ(memcmp(rt.decOutput.data, rt.plain.data, rt.plain.len), 0);
    FreeAeadVectorRuntime(rt);
}

HWTEST_F(CryptoAeadParamsSpecTest, CryptoAeadParamsSpecChacha20Poly1305Vector001, TestSize.Level0)
{
    AeadVectorCase vec = GetChacha20Poly1305Vector001();
    AeadVectorRuntime rt;
    InitAeadVectorRuntime(rt);
    rt.iv.data = const_cast<uint8_t *>(vec.iv);
    rt.iv.len = vec.ivLen;
    rt.aad.data = const_cast<uint8_t *>(vec.aad);
    rt.aad.len = vec.aadLen;
    rt.plain.data = const_cast<uint8_t *>(vec.plain);
    rt.plain.len = vec.plainLen;
    rt.expectCipher.data = const_cast<uint8_t *>(vec.cipher);
    rt.expectCipher.len = vec.cipherLen;
    rt.expectTag.data = const_cast<uint8_t *>(vec.tag);
    rt.expectTag.len = vec.tagLen;
    ASSERT_EQ(ConvertVectorKey(vec.keyType, vec.key, vec.keyLen, &rt.key), HCF_SUCCESS);
    ASSERT_EQ(HcfCipherCreate(vec.cipherName, &rt.cipher), HCF_SUCCESS);
    HcfAeadParamsSpec spec = { .base = { .getType = GetAeadParamsSpecTypeForTest }, .nonce = rt.iv, .aad = rt.aad,
        .tagLen = static_cast<int32_t>(rt.expectTag.len) };
    ASSERT_EQ(AeadEncryptWithInput(rt.cipher, rt.key, &spec, rt.plain, &rt.encOutput), HCF_SUCCESS);
    ASSERT_EQ(rt.encOutput.len, rt.expectCipher.len + rt.expectTag.len);
    ASSERT_EQ(memcmp(rt.encOutput.data, rt.expectCipher.data, rt.expectCipher.len), 0);
    ASSERT_EQ(memcmp(rt.encOutput.data + rt.expectCipher.len, rt.expectTag.data, rt.expectTag.len), 0);
    ASSERT_EQ(AeadDecryptWithInput(rt.cipher, rt.key, &spec, rt.encOutput, &rt.decOutput), HCF_SUCCESS);
    ASSERT_EQ(rt.decOutput.len, rt.plain.len);
    ASSERT_EQ(memcmp(rt.decOutput.data, rt.plain.data, rt.plain.len), 0);
    FreeAeadVectorRuntime(rt);
}

static int32_t AeadEncryptByUpdateOnly(HcfCipher *cipher, HcfSymKey *key, HcfAeadParamsSpec *params,
    const HcfBlob &input, std::vector<uint8_t> &out)
{
    HcfBlob updateOutput = {};
    int32_t ret = cipher->init(cipher, ENCRYPT_MODE, reinterpret_cast<HcfKey *>(key),
        reinterpret_cast<HcfParamsSpec *>(params));
    if (ret != HCF_SUCCESS) {
        return ret;
    }
    ret = cipher->update(cipher, const_cast<HcfBlob *>(&input), &updateOutput);
    if (ret != HCF_SUCCESS) {
        return ret;
    }
    HcfBlob finalOutput = {};
    ret = cipher->doFinal(cipher, nullptr, &finalOutput);
    if (ret != HCF_SUCCESS) {
        HcfBlobDataFree(&updateOutput);
        return ret;
    }
    out.clear();
    AppendBlobToVector(updateOutput, out);
    AppendBlobToVector(finalOutput, out);
    HcfBlobDataFree(&updateOutput);
    HcfBlobDataFree(&finalOutput);
    return HCF_SUCCESS;
}

static int32_t AeadEncryptDoFinalNull(HcfCipher *cipher, HcfSymKey *key, HcfAeadParamsSpec *params,
    std::vector<uint8_t> &out)
{
    int32_t ret = cipher->init(cipher, ENCRYPT_MODE, reinterpret_cast<HcfKey *>(key),
        reinterpret_cast<HcfParamsSpec *>(params));
    if (ret != HCF_SUCCESS) {
        return ret;
    }
    HcfBlob output = {};
    ret = cipher->doFinal(cipher, nullptr, &output);
    if (ret != HCF_SUCCESS) {
        return ret;
    }
    out.assign(output.data, output.data + output.len);
    HcfBlobDataFree(&output);
    return HCF_SUCCESS;
}

HWTEST_F(CryptoAeadParamsSpecTest, CryptoAeadParamsSpecAesGcmUpdateOnlyDoFinal001, TestSize.Level0)
{
    HcfCipher *cipher = nullptr;
    HcfSymKey *key = nullptr;
    uint8_t aad[GCM_AAD_LEN] = {0};
    uint8_t nonce[GCM_IV_LEN] = {0};
    HcfBlob plain = {.data = const_cast<uint8_t *>(TEST_PLAIN_TEXT), .len = sizeof(TEST_PLAIN_TEXT) - 1};

    HcfAeadParamsSpec spec = {};
    spec.base.getType = GetAeadParamsSpecTypeForTest;
    spec.nonce.data = nonce;
    spec.nonce.len = sizeof(nonce);
    spec.aad.data = aad;
    spec.aad.len = sizeof(aad);
    spec.tagLen = AEAD_TAG_LEN;

    ASSERT_EQ(GenerateSymKey("AES256", &key), HCF_SUCCESS);
    ASSERT_EQ(HcfCipherCreate("AES256|GCM|NoPadding", &cipher), HCF_SUCCESS);

    std::vector<uint8_t> cipherWithTag;
    ASSERT_EQ(AeadEncryptByUpdateOnly(cipher, key, &spec, plain, cipherWithTag), HCF_SUCCESS);
    ASSERT_EQ(cipherWithTag.size(), plain.len + spec.tagLen);
    ASSERT_EQ(AeadDecrypt(cipher, key, &spec, cipherWithTag), HCF_SUCCESS);

    HcfObjDestroy(reinterpret_cast<HcfObjectBase *>(cipher));
    HcfObjDestroy(reinterpret_cast<HcfObjectBase *>(key));
}

HWTEST_F(CryptoAeadParamsSpecTest, CryptoAeadParamsSpecAesGcmDoFinalNullEncrypt001, TestSize.Level0)
{
    HcfCipher *cipher = nullptr;
    HcfSymKey *key = nullptr;
    uint8_t aad[GCM_AAD_LEN] = {0};
    uint8_t nonce[GCM_IV_LEN] = {0};

    HcfAeadParamsSpec spec = {};
    spec.base.getType = GetAeadParamsSpecTypeForTest;
    spec.nonce.data = nonce;
    spec.nonce.len = sizeof(nonce);
    spec.aad.data = aad;
    spec.aad.len = sizeof(aad);
    spec.tagLen = AEAD_TAG_LEN;

    ASSERT_EQ(GenerateSymKey("AES256", &key), HCF_SUCCESS);
    ASSERT_EQ(HcfCipherCreate("AES256|GCM|NoPadding", &cipher), HCF_SUCCESS);

    std::vector<uint8_t> tagOnly;
    ASSERT_EQ(AeadEncryptDoFinalNull(cipher, key, &spec, tagOnly), HCF_SUCCESS);
    ASSERT_EQ(tagOnly.size(), static_cast<size_t>(spec.tagLen));

    HcfObjDestroy(reinterpret_cast<HcfObjectBase *>(cipher));
    HcfObjDestroy(reinterpret_cast<HcfObjectBase *>(key));
}

HWTEST_F(CryptoAeadParamsSpecTest, CryptoAeadParamsSpecSm4GcmUpdateOnlyDoFinal001, TestSize.Level0)
{
    HcfCipher *cipher = nullptr;
    HcfSymKey *key = nullptr;
    uint8_t aad[GCM_AAD_LEN] = {0};
    uint8_t nonce[GCM_IV_LEN] = {0};
    HcfBlob plain = {.data = const_cast<uint8_t *>(TEST_PLAIN_TEXT), .len = sizeof(TEST_PLAIN_TEXT) - 1};

    HcfAeadParamsSpec spec = {};
    spec.base.getType = GetAeadParamsSpecTypeForTest;
    spec.nonce.data = nonce;
    spec.nonce.len = sizeof(nonce);
    spec.aad.data = aad;
    spec.aad.len = sizeof(aad);
    spec.tagLen = AEAD_TAG_LEN;

    ASSERT_EQ(GenerateSymKey("SM4_128", &key), HCF_SUCCESS);
    ASSERT_EQ(HcfCipherCreate("SM4_128|GCM|NoPadding", &cipher), HCF_SUCCESS);

    std::vector<uint8_t> cipherWithTag;
    ASSERT_EQ(AeadEncryptByUpdateOnly(cipher, key, &spec, plain, cipherWithTag), HCF_SUCCESS);
    ASSERT_EQ(cipherWithTag.size(), plain.len + spec.tagLen);
    ASSERT_EQ(AeadDecrypt(cipher, key, &spec, cipherWithTag), HCF_SUCCESS);

    HcfObjDestroy(reinterpret_cast<HcfObjectBase *>(cipher));
    HcfObjDestroy(reinterpret_cast<HcfObjectBase *>(key));
}

HWTEST_F(CryptoAeadParamsSpecTest, CryptoAeadParamsSpecSm4GcmDoFinalNullEncrypt001, TestSize.Level0)
{
    HcfCipher *cipher = nullptr;
    HcfSymKey *key = nullptr;
    uint8_t aad[GCM_AAD_LEN] = {0};
    uint8_t nonce[GCM_IV_LEN] = {0};

    HcfAeadParamsSpec spec = {};
    spec.base.getType = GetAeadParamsSpecTypeForTest;
    spec.nonce.data = nonce;
    spec.nonce.len = sizeof(nonce);
    spec.aad.data = aad;
    spec.aad.len = sizeof(aad);
    spec.tagLen = AEAD_TAG_LEN;

    ASSERT_EQ(GenerateSymKey("SM4_128", &key), HCF_SUCCESS);
    ASSERT_EQ(HcfCipherCreate("SM4_128|GCM|NoPadding", &cipher), HCF_SUCCESS);

    std::vector<uint8_t> tagOnly;
    ASSERT_EQ(AeadEncryptDoFinalNull(cipher, key, &spec, tagOnly), HCF_SUCCESS);
    ASSERT_EQ(tagOnly.size(), static_cast<size_t>(spec.tagLen));

    HcfObjDestroy(reinterpret_cast<HcfObjectBase *>(cipher));
    HcfObjDestroy(reinterpret_cast<HcfObjectBase *>(key));
}

HWTEST_F(CryptoAeadParamsSpecTest, CryptoAeadParamsSpecChacha20Poly1305UpdateOnlyDoFinal001, TestSize.Level0)
{
    HcfCipher *cipher = nullptr;
    HcfSymKey *key = nullptr;
    uint8_t aad[GCM_AAD_LEN] = {0};
    uint8_t nonce[CHACHA20_NONCE_LEN] = {0};
    HcfBlob plain = {.data = const_cast<uint8_t *>(TEST_PLAIN_TEXT), .len = sizeof(TEST_PLAIN_TEXT) - 1};

    HcfAeadParamsSpec spec = {};
    spec.base.getType = GetAeadParamsSpecTypeForTest;
    spec.nonce.data = nonce;
    spec.nonce.len = sizeof(nonce);
    spec.aad.data = aad;
    spec.aad.len = sizeof(aad);
    spec.tagLen = AEAD_TAG_LEN;

    ASSERT_EQ(GenerateChacha20SymKey(&key), HCF_SUCCESS);
    ASSERT_EQ(HcfCipherCreate("ChaCha20|Poly1305", &cipher), HCF_SUCCESS);

    std::vector<uint8_t> cipherWithTag;
    ASSERT_EQ(AeadEncryptByUpdateOnly(cipher, key, &spec, plain, cipherWithTag), HCF_SUCCESS);
    ASSERT_EQ(cipherWithTag.size(), plain.len + spec.tagLen);
    ASSERT_EQ(AeadDecrypt(cipher, key, &spec, cipherWithTag), HCF_SUCCESS);

    HcfObjDestroy(reinterpret_cast<HcfObjectBase *>(cipher));
    HcfObjDestroy(reinterpret_cast<HcfObjectBase *>(key));
}

HWTEST_F(CryptoAeadParamsSpecTest, CryptoAeadParamsSpecChacha20Poly1305DoFinalNullEncrypt001, TestSize.Level0)
{
    HcfCipher *cipher = nullptr;
    HcfSymKey *key = nullptr;
    uint8_t aad[GCM_AAD_LEN] = {0};
    uint8_t nonce[CHACHA20_NONCE_LEN] = {0};

    HcfAeadParamsSpec spec = {};
    spec.base.getType = GetAeadParamsSpecTypeForTest;
    spec.nonce.data = nonce;
    spec.nonce.len = sizeof(nonce);
    spec.aad.data = aad;
    spec.aad.len = sizeof(aad);
    spec.tagLen = AEAD_TAG_LEN;

    ASSERT_EQ(GenerateChacha20SymKey(&key), HCF_SUCCESS);
    ASSERT_EQ(HcfCipherCreate("ChaCha20|Poly1305", &cipher), HCF_SUCCESS);

    std::vector<uint8_t> tagOnly;
    ASSERT_EQ(AeadEncryptDoFinalNull(cipher, key, &spec, tagOnly), HCF_SUCCESS);
    ASSERT_EQ(tagOnly.size(), static_cast<size_t>(spec.tagLen));

    HcfObjDestroy(reinterpret_cast<HcfObjectBase *>(cipher));
    HcfObjDestroy(reinterpret_cast<HcfObjectBase *>(key));
}
} // namespace
