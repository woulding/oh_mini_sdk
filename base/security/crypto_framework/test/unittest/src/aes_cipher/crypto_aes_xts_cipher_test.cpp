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
#include <fstream>
#include <iostream>
#include <memory>
#include <vector>
#include "securec.h"

#include "aes_common.h"
#include "aes_openssl.h"
#include "blob.h"
#include "cipher.h"
#include "detailed_aead_params.h"
#include "detailed_ccm_params.h"
#include "memory.h"
#include "mock.h"
#include "result.h"
#include "sym_common_defines.h"
#include "sym_key_generator.h"

using namespace std;
using namespace testing::ext;
using ::testing::_;
using ::testing::Invoke;
using ::testing::Return;

#define TEST_CCM_IV_LEN 4
namespace {

static const char *GetAeadParamsSpecTypeForTest(void)
{
    return "AeadParamsSpec";
}

class CryptoAesXtsCipherTest : public testing::Test {
public:
    static void SetUpTestCase() {};
    static void TearDownTestCase() {};
    void SetUp() {};
    void TearDown() {};
};

/* CCM 打桩测试：对 openssl_adapter 接口打桩以提高 CCM 分支覆盖率 */
class CryptoAesCcmCipherStubTest : public testing::Test {
public:
    static void SetUpTestCase() {};
    static void TearDownTestCase() {};
    void SetUp() override;
    void TearDown() override;

    std::shared_ptr<HcfMock> mock_ = std::make_shared<HcfMock>();
};

void CryptoAesCcmCipherStubTest::SetUp()
{
    SetMock(mock_.get());
    EXPECT_CALL(*mock_, HcfMalloc(_, _)).WillRepeatedly(Invoke(__real_HcfMalloc));
    EXPECT_CALL(*mock_, HcfIsStrValid(_, _)).WillRepeatedly(Invoke(__real_HcfIsStrValid));
    EXPECT_CALL(*mock_, HcfIsClassMatch(_, _)).WillRepeatedly(Invoke(__real_HcfIsClassMatch));
    EXPECT_CALL(*mock_, OpensslEvpCipherFetch(_, _, _)).WillRepeatedly(Invoke(__real_OpensslEvpCipherFetch));
    EXPECT_CALL(*mock_, OpensslEvpCipherCtxNew()).WillRepeatedly(Invoke(__real_OpensslEvpCipherCtxNew));
    EXPECT_CALL(*mock_, OpensslEvpCipherInit(_, _, _, _, _)).WillRepeatedly(Invoke(__real_OpensslEvpCipherInit));
    EXPECT_CALL(*mock_, OpensslEvpCipherCtxCtrl(_, _, _, _)).WillRepeatedly(Invoke(__real_OpensslEvpCipherCtxCtrl));
    EXPECT_CALL(*mock_, OpensslEvpCipherCtxSetPadding(_, _))
        .WillRepeatedly(Invoke(__real_OpensslEvpCipherCtxSetPadding));
    EXPECT_CALL(*mock_, OpensslEvpCipherUpdate(_, _, _, _, _)).WillRepeatedly(Invoke(__real_OpensslEvpCipherUpdate));
    EXPECT_CALL(*mock_, OpensslEvpCipherFinalEx(_, _, _)).WillRepeatedly(Invoke(__real_OpensslEvpCipherFinalEx));
}

void CryptoAesCcmCipherStubTest::TearDown()
{
    ResetMock();
}

struct AesXtsEncryptContext {
    HcfCipher *cipher;
    HcfSymKey *key;
    HcfAeadParamsSpec *spec;
    const uint8_t *plain;
    size_t plainLen;
    uint8_t *cipherText;
    int *cipherTextLen;
};

struct AesXtsDecryptContext {
    HcfCipher *cipher;
    HcfSymKey *key;
    HcfAeadParamsSpec *spec;
    const uint8_t *cipherText;
    int cipherTextLen;
    uint8_t *decryptText;
    int *decryptTextLen;
};

static void DoAesXtsEncrypt(const AesXtsEncryptContext *ctx)
{
    HcfBlob input = {.data = const_cast<uint8_t *>(ctx->plain), .len = ctx->plainLen};
    HcfBlob output = {};
    int32_t retCode = ctx->cipher->init(ctx->cipher, ENCRYPT_MODE, reinterpret_cast<HcfKey *>(ctx->key),
        reinterpret_cast<HcfParamsSpec *>(ctx->spec));
    ASSERT_EQ(retCode, 0);
    retCode = ctx->cipher->update(ctx->cipher, &input, &output);
    ASSERT_EQ(retCode, 0);
    ASSERT_LE(output.len, static_cast<size_t>(*(ctx->cipherTextLen)));
    if (output.data != nullptr && output.len != 0) {
        (void)memcpy_s(ctx->cipherText, static_cast<size_t>(*(ctx->cipherTextLen)), output.data, output.len);
        *(ctx->cipherTextLen) = static_cast<int>(output.len);
        HcfBlobDataFree(&output);
    } else {
        *(ctx->cipherTextLen) = 0;
    }
    retCode = ctx->cipher->doFinal(ctx->cipher, nullptr, &output);
    ASSERT_EQ(retCode, 0);
    if (output.data != nullptr && output.len != 0) {
        ASSERT_LE(*(ctx->cipherTextLen) + static_cast<int>(output.len), *(ctx->cipherTextLen));
        (void)memcpy_s(ctx->cipherText + *(ctx->cipherTextLen),
            static_cast<size_t>(*(ctx->cipherTextLen)) - *(ctx->cipherTextLen), output.data, output.len);
        *(ctx->cipherTextLen) += static_cast<int>(output.len);
        HcfBlobDataFree(&output);
    }
}

static void DoAesXtsDecrypt(const AesXtsDecryptContext *ctx)
{
    HcfBlob input = {.data = const_cast<uint8_t *>(ctx->cipherText),
        .len = static_cast<size_t>(ctx->cipherTextLen)};
    HcfBlob output = {};
    int32_t retCode = ctx->cipher->init(ctx->cipher, DECRYPT_MODE, reinterpret_cast<HcfKey *>(ctx->key),
        reinterpret_cast<HcfParamsSpec *>(ctx->spec));
    ASSERT_EQ(retCode, 0);
    retCode = ctx->cipher->update(ctx->cipher, &input, &output);
    ASSERT_EQ(retCode, 0);
    ASSERT_LE(output.len, static_cast<size_t>(*(ctx->decryptTextLen)));
    if (output.data != nullptr && output.len != 0) {
        (void)memcpy_s(ctx->decryptText, static_cast<size_t>(*(ctx->decryptTextLen)), output.data, output.len);
        *(ctx->decryptTextLen) = static_cast<int>(output.len);
        HcfBlobDataFree(&output);
    } else {
        *(ctx->decryptTextLen) = 0;
    }
    retCode = ctx->cipher->doFinal(ctx->cipher, nullptr, &output);
    ASSERT_EQ(retCode, 0);
    if (output.data != nullptr && output.len != 0) {
        ASSERT_LE(*(ctx->decryptTextLen) + static_cast<int>(output.len), *(ctx->decryptTextLen));
        (void)memcpy_s(ctx->decryptText + *(ctx->decryptTextLen),
            static_cast<size_t>(*(ctx->decryptTextLen)) - *(ctx->decryptTextLen), output.data, output.len);
        *(ctx->decryptTextLen) += static_cast<int>(output.len);
        HcfBlobDataFree(&output);
    }
}

typedef struct {
    const uint8_t *key;
    size_t keyLen;
    const uint8_t *tweak;
    size_t tweakLen;
    const uint8_t *plaintext;
    size_t plainLen;
    const uint8_t *ciphertext;
    size_t cipherLen;
} Aes128XtsVectorCase;

static Aes128XtsVectorCase GetAes128XtsVectorTest007(void)
{
    static const uint8_t key[] = {
        0xff, 0xfe, 0xfd, 0xfc, 0xfb, 0xfa, 0xf9, 0xf8, 0xf7, 0xf6, 0xf5, 0xf4, 0xf3, 0xf2, 0xf1, 0xf0,
        0xbf, 0xbe, 0xbd, 0xbc, 0xbb, 0xba, 0xb9, 0xb8, 0xb7, 0xb6, 0xb5, 0xb4, 0xb3, 0xb2, 0xb1, 0xb0
    };
    static const uint8_t tweak[] = { 0x9a, 0x78, 0x56, 0x34, 0x12, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };
    static const uint8_t plaintext[] = {
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
        0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
        0x20, 0x21
    };
    static const uint8_t ciphertext[] = {
        0xed, 0xbf, 0x9d, 0xac, 0xe4, 0x5d, 0x6f, 0x6a, 0x73, 0x06, 0xe6, 0x4b, 0xe5, 0xdd, 0x82, 0x4b,
        0x9d, 0xc3, 0x1e, 0xfe, 0xb4, 0x18, 0xc3, 0x73, 0xce, 0x07, 0x3b, 0x66, 0x75, 0x55, 0x29, 0x98,
        0x25, 0x38
    };
    return { key, sizeof(key), tweak, sizeof(tweak), plaintext, sizeof(plaintext), ciphertext, sizeof(ciphertext) };
}

static Aes128XtsVectorCase GetAes128XtsVectorTest008(void)
{
    static const uint8_t key[] = {
        0xff, 0xfe, 0xfd, 0xfc, 0xfb, 0xfa, 0xf9, 0xf8, 0xf7, 0xf6, 0xf5, 0xf4, 0xf3, 0xf2, 0xf1, 0xf0,
        0xbf, 0xbe, 0xbd, 0xbc, 0xbb, 0xba, 0xb9, 0xb8, 0xb7, 0xb6, 0xb5, 0xb4, 0xb3, 0xb2, 0xb1, 0xb0
    };
    static const uint8_t tweak[] = { 0x9a, 0x78, 0x56, 0x34, 0x12, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };
    static const uint8_t plaintext[] = {
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
        0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
        0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28, 0x29, 0x2a, 0x2b, 0x2c, 0x2d, 0x2e, 0x2f,
        0x30, 0x31
    };
    static const uint8_t ciphertext[] = {
        0xed, 0xbf, 0x9d, 0xac, 0xe4, 0x5d, 0x6f, 0x6a, 0x73, 0x06, 0xe6, 0x4b, 0xe5, 0xdd, 0x82, 0x4b,
        0x25, 0x38, 0xf5, 0x72, 0x4f, 0xcf, 0x24, 0x24, 0x9a, 0xc1, 0x11, 0xab, 0x45, 0xad, 0x39, 0x23,
        0x7a, 0x70, 0x99, 0x59, 0x67, 0x3b, 0xd8, 0x74, 0x7d, 0x58, 0x69, 0x0f, 0x8c, 0x76, 0x2a, 0x35,
        0x3a, 0xd6
    };
    return { key, sizeof(key), tweak, sizeof(tweak), plaintext, sizeof(plaintext), ciphertext, sizeof(ciphertext) };
}

HWTEST_F(CryptoAesXtsCipherTest, CryptoAesXtsCipherTest001, TestSize.Level0)
{
    uint8_t tweak[16] = {0};
    uint8_t plain[32] = {
        0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
        0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff,
        0x10, 0x32, 0x54, 0x76, 0x98, 0xba, 0xdc, 0xfe,
        0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef
    };
    uint8_t cipherText[sizeof(plain)] = {0};
    uint8_t decryptText[sizeof(plain)] = {0};
    int cipherTextLen = static_cast<int>(sizeof(plain));
    int decryptTextLen = static_cast<int>(sizeof(plain));

    HcfCipher *cipher = nullptr;
    HcfSymKey *key = nullptr;
    HcfAeadParamsSpec spec = {};
    spec.base.getType = GetAeadParamsSpecTypeForTest;
    spec.nonce.data = tweak;
    spec.nonce.len = sizeof(tweak);
    spec.aad.data = nullptr;
    spec.aad.len = 0;
    spec.tagLen = 0;

    int ret = GenerateSymKey("AES256", &key);
    ASSERT_EQ(ret, 0);
    ret = HcfCipherCreate("AES128|XTS|NoPadding", &cipher);
    ASSERT_EQ(ret, 0);
    AesXtsEncryptContext encCtx = {
        .cipher = cipher,
        .key = key,
        .spec = &spec,
        .plain = plain,
        .plainLen = sizeof(plain),
        .cipherText = cipherText,
        .cipherTextLen = &cipherTextLen,
    };
    DoAesXtsEncrypt(&encCtx);
    AesXtsDecryptContext decCtx = {
        .cipher = cipher,
        .key = key,
        .spec = &spec,
        .cipherText = cipherText,
        .cipherTextLen = cipherTextLen,
        .decryptText = decryptText,
        .decryptTextLen = &decryptTextLen,
    };
    DoAesXtsDecrypt(&decCtx);
    ASSERT_EQ(memcmp(plain, decryptText, sizeof(plain)), 0);

    HcfObjDestroy(reinterpret_cast<HcfObjectBase *>(key));
    HcfObjDestroy(reinterpret_cast<HcfObjectBase *>(cipher));
}

HWTEST_F(CryptoAesXtsCipherTest, CryptoAesXtsCipherTest002, TestSize.Level0)
{
    int ret = 0;
    uint8_t tweak[8] = {0}; /* invalid tweak length, must be 16 bytes */
    uint8_t cipherText[CIPHER_TEXT_LEN] = {0};
    int cipherTextLen = CIPHER_TEXT_LEN;

    HcfCipher *cipher = nullptr;
    HcfSymKey *key = nullptr;
    HcfAeadParamsSpec spec = {};
    spec.base.getType = GetAeadParamsSpecTypeForTest;
    spec.nonce.data = tweak;
    spec.nonce.len = sizeof(tweak);
    spec.aad.data = nullptr;
    spec.aad.len = 0;
    spec.tagLen = 0;

    ret = GenerateSymKey("AES256", &key);
    ASSERT_EQ(ret, 0);

    ret = HcfCipherCreate("AES256|XTS|NoPadding", &cipher);
    ASSERT_EQ(ret, 0);

    ret = AesEncrypt(cipher, key, reinterpret_cast<HcfParamsSpec *>(&spec), cipherText, &cipherTextLen);
    ASSERT_NE(ret, 0);

    HcfObjDestroy(reinterpret_cast<HcfObjectBase *>(key));
    HcfObjDestroy(reinterpret_cast<HcfObjectBase *>(cipher));
}

HWTEST_F(CryptoAesXtsCipherTest, CryptoAesXtsCipherVectorTest007, TestSize.Level0)
{
    Aes128XtsVectorCase vec = GetAes128XtsVectorTest007();
    HcfCipher *cipher = nullptr;
    HcfSymKey *key = nullptr;
    HcfSymKeyGenerator *generator = nullptr;
    HcfBlob keyBlob = {.data = const_cast<uint8_t *>(vec.key), .len = vec.keyLen};

    int32_t ret = HcfSymKeyGeneratorCreate("AES256", &generator);
    ASSERT_EQ(ret, 0);
    ret = generator->convertSymKey(generator, &keyBlob, &key);
    ASSERT_EQ(ret, 0);
    HcfObjDestroy(reinterpret_cast<HcfObjectBase *>(generator));

    ret = HcfCipherCreate("AES128|XTS|NoPadding", &cipher);
    ASSERT_EQ(ret, 0);

    HcfAeadParamsSpec spec = {};
    spec.base.getType = GetAeadParamsSpecTypeForTest;
    spec.nonce.data = const_cast<uint8_t *>(vec.tweak);
    spec.nonce.len = vec.tweakLen;
    spec.aad.data = nullptr;
    spec.aad.len = 0;
    spec.tagLen = 0;

    std::vector<uint8_t> encOutBuf(vec.cipherLen);
    std::vector<uint8_t> decOutBuf(vec.plainLen);
    int encLen = static_cast<int>(encOutBuf.size());
    int decLen = static_cast<int>(decOutBuf.size());

    AesXtsEncryptContext encCtx = {
        .cipher = cipher,
        .key = key,
        .spec = &spec,
        .plain = vec.plaintext,
        .plainLen = vec.plainLen,
        .cipherText = encOutBuf.data(),
        .cipherTextLen = &encLen,
    };
    DoAesXtsEncrypt(&encCtx);
    ASSERT_EQ(memcmp(encOutBuf.data(), vec.ciphertext, vec.cipherLen), 0);

    AesXtsDecryptContext decCtx = {
        .cipher = cipher,
        .key = key,
        .spec = &spec,
        .cipherText = encOutBuf.data(),
        .cipherTextLen = encLen,
        .decryptText = decOutBuf.data(),
        .decryptTextLen = &decLen,
    };
    DoAesXtsDecrypt(&decCtx);
    ASSERT_EQ(memcmp(decOutBuf.data(), vec.plaintext, vec.plainLen), 0);

    HcfObjDestroy(reinterpret_cast<HcfObjectBase *>(key));
    HcfObjDestroy(reinterpret_cast<HcfObjectBase *>(cipher));
}

HWTEST_F(CryptoAesXtsCipherTest, CryptoAesXtsCipherVectorTest008, TestSize.Level0)
{
    Aes128XtsVectorCase vec = GetAes128XtsVectorTest008();

    HcfCipher *cipher = nullptr;
    HcfSymKey *key = nullptr;
    HcfSymKeyGenerator *generator = nullptr;
    HcfBlob keyBlob = {.data = const_cast<uint8_t *>(vec.key), .len = vec.keyLen};

    int32_t ret = HcfSymKeyGeneratorCreate("AES256", &generator);
    ASSERT_EQ(ret, 0);
    ret = generator->convertSymKey(generator, &keyBlob, &key);
    ASSERT_EQ(ret, 0);
    HcfObjDestroy(reinterpret_cast<HcfObjectBase *>(generator));

    ret = HcfCipherCreate("AES128|XTS|NoPadding", &cipher);
    ASSERT_EQ(ret, 0);

    HcfAeadParamsSpec spec = {};
    spec.base.getType = GetAeadParamsSpecTypeForTest;
    spec.nonce.data = const_cast<uint8_t *>(vec.tweak);
    spec.nonce.len = vec.tweakLen;
    spec.aad.data = nullptr;
    spec.aad.len = 0;
    spec.tagLen = 0;

    std::vector<uint8_t> encOutBuf(vec.cipherLen);
    std::vector<uint8_t> decOutBuf(vec.plainLen);
    int encLen = static_cast<int>(encOutBuf.size());
    int decLen = static_cast<int>(decOutBuf.size());

    AesXtsEncryptContext encCtx = {
        .cipher = cipher,
        .key = key,
        .spec = &spec,
        .plain = vec.plaintext,
        .plainLen = vec.plainLen,
        .cipherText = encOutBuf.data(),
        .cipherTextLen = &encLen,
    };
    DoAesXtsEncrypt(&encCtx);
    ASSERT_EQ(memcmp(encOutBuf.data(), vec.ciphertext, vec.cipherLen), 0);

    AesXtsDecryptContext decCtx = {
        .cipher = cipher,
        .key = key,
        .spec = &spec,
        .cipherText = encOutBuf.data(),
        .cipherTextLen = encLen,
        .decryptText = decOutBuf.data(),
        .decryptTextLen = &decLen,
    };
    DoAesXtsDecrypt(&decCtx);
    ASSERT_EQ(memcmp(decOutBuf.data(), vec.plaintext, vec.plainLen), 0);

    HcfObjDestroy(reinterpret_cast<HcfObjectBase *>(key));
    HcfObjDestroy(reinterpret_cast<HcfObjectBase *>(cipher));
}

HWTEST_F(CryptoAesXtsCipherTest, CryptoAesXtsCipherTest003, TestSize.Level0)
{
    int ret = 0;
    uint8_t plainText[] = "this is test!";
    uint8_t aad[CCM_AAD_LEN] = {0};
    uint8_t iv[CCM_IV_LEN] = {0}; /* 7 bytes, valid for new CCM */

    HcfCipher *cipher = nullptr;
    HcfSymKey *key = nullptr;

    HcfAeadParamsSpec encSpec = {};
    encSpec.base.getType = GetAeadParamsSpecTypeForTest;
    encSpec.nonce.data = iv;
    encSpec.nonce.len = sizeof(iv);
    encSpec.aad.data = aad;
    encSpec.aad.len = sizeof(aad);
    encSpec.tagLen = 16; /* typical CCM tag length */

    ret = GenerateSymKey("AES256", &key);
    ASSERT_EQ(ret, 0);

    ret = HcfCipherCreate("AES256|CCM|NoPadding", &cipher);
    ASSERT_EQ(ret, 0);

    HcfBlob input = {.data = plainText, .len = sizeof(plainText) - 1};
    HcfBlob output = {};
    ret = cipher->init(cipher, ENCRYPT_MODE, reinterpret_cast<HcfKey *>(key),
        reinterpret_cast<HcfParamsSpec *>(&encSpec));
    ASSERT_EQ(ret, 0);

    ret = cipher->doFinal(cipher, &input, &output);
    ASSERT_EQ(ret, 0);
    ASSERT_NE(output.data, nullptr);
    ASSERT_GT(output.len, encSpec.tagLen);

    HcfAeadParamsSpec decSpec = {};
    decSpec.base.getType = GetAeadParamsSpecTypeForTest;
    decSpec.nonce.data = iv;
    decSpec.nonce.len = sizeof(iv);
    decSpec.aad.data = aad;
    decSpec.aad.len = sizeof(aad);
    decSpec.tagLen = encSpec.tagLen;

    HcfBlob decInput = {.data = output.data, .len = output.len};
    HcfBlob decOutput = {};
    ret = cipher->init(cipher, DECRYPT_MODE, reinterpret_cast<HcfKey *>(key),
        reinterpret_cast<HcfParamsSpec *>(&decSpec));
    ASSERT_EQ(ret, 0);

    ret = cipher->doFinal(cipher, &decInput, &decOutput);
    ASSERT_EQ(ret, 0);
    ASSERT_NE(decOutput.data, nullptr);
    ASSERT_EQ(decOutput.len, sizeof(plainText) - 1);
    ASSERT_EQ(memcmp(decOutput.data, plainText, decOutput.len), 0);

    HcfBlobDataFree(&output);
    HcfBlobDataFree(&decOutput);
    HcfObjDestroy(reinterpret_cast<HcfObjectBase *>(key));
    HcfObjDestroy(reinterpret_cast<HcfObjectBase *>(cipher));
}

HWTEST_F(CryptoAesXtsCipherTest, CryptoAesXtsCipherTest004, TestSize.Level0)
{
    int ret = 0;
    uint8_t aad[CCM_AAD_LEN] = {0};
    uint8_t iv[CCM_IV_LEN] = {0};
    uint8_t cipherText[CIPHER_TEXT_LEN] = {0};
    int cipherTextLen = CIPHER_TEXT_LEN;

    HcfCipher *cipher = nullptr;
    HcfSymKey *key = nullptr;
    HcfAeadParamsSpec spec = {};
    spec.base.getType = GetAeadParamsSpecTypeForTest;
    spec.nonce.data = iv;
    spec.nonce.len = sizeof(iv);
    spec.aad.data = aad;
    spec.aad.len = sizeof(aad);
    spec.tagLen = 5; /* invalid tag length for new CCM */

    ret = GenerateSymKey("AES128", &key);
    ASSERT_EQ(ret, 0);

    ret = HcfCipherCreate("AES128|CCM|NoPadding", &cipher);
    ASSERT_EQ(ret, 0);

    ret = AesEncrypt(cipher, key, reinterpret_cast<HcfParamsSpec *>(&spec), cipherText, &cipherTextLen);
    ASSERT_NE(ret, 0);

    HcfObjDestroy(reinterpret_cast<HcfObjectBase *>(key));
    HcfObjDestroy(reinterpret_cast<HcfObjectBase *>(cipher));
}

HWTEST_F(CryptoAesXtsCipherTest, CryptoAesXtsCipherTest007, TestSize.Level0)
{
    int ret = 0;
    uint8_t plainText[] = "this is test!";
    uint8_t aad[CCM_AAD_LEN] = {0};
    uint8_t iv[CCM_IV_LEN] = {0}; /* 7 bytes, valid for new CCM */

    HcfCipher *cipher = nullptr;
    HcfSymKey *key = nullptr;

    HcfAeadParamsSpec encSpec = {};
    encSpec.base.getType = GetAeadParamsSpecTypeForTest;
    encSpec.nonce.data = iv;
    encSpec.nonce.len = sizeof(iv);
    encSpec.aad.data = aad;
    encSpec.aad.len = sizeof(aad);
    encSpec.tagLen = 16; /* typical CCM tag length */

    ret = GenerateSymKey("AES192", &key);
    ASSERT_EQ(ret, 0);

    ret = HcfCipherCreate("AES192|CCM|NoPadding", &cipher);
    ASSERT_EQ(ret, 0);

    HcfBlob input = {.data = plainText, .len = sizeof(plainText) - 1};
    HcfBlob output = {};
    ret = cipher->init(cipher, ENCRYPT_MODE, reinterpret_cast<HcfKey *>(key),
        reinterpret_cast<HcfParamsSpec *>(&encSpec));
    ASSERT_EQ(ret, 0);

    ret = cipher->doFinal(cipher, &input, &output);
    ASSERT_EQ(ret, 0);
    ASSERT_NE(output.data, nullptr);
    ASSERT_GT(output.len, encSpec.tagLen);

    HcfAeadParamsSpec decSpec = {};
    decSpec.base.getType = GetAeadParamsSpecTypeForTest;
    decSpec.nonce.data = iv;
    decSpec.nonce.len = sizeof(iv);
    decSpec.aad.data = aad;
    decSpec.aad.len = sizeof(aad);
    decSpec.tagLen = encSpec.tagLen;

    HcfBlob decInput = {.data = output.data, .len = output.len};
    HcfBlob decOutput = {};
    ret = cipher->init(cipher, DECRYPT_MODE, reinterpret_cast<HcfKey *>(key),
        reinterpret_cast<HcfParamsSpec *>(&decSpec));
    ASSERT_EQ(ret, 0);

    ret = cipher->update(cipher, &decInput, &decOutput);
    ASSERT_EQ(ret, 0);
    ASSERT_NE(decOutput.data, nullptr);
    ASSERT_EQ(decOutput.len, sizeof(plainText) - 1);
    ASSERT_EQ(memcmp(decOutput.data, plainText, decOutput.len), 0);

    HcfBlobDataFree(&output);
    HcfBlobDataFree(&decOutput);
    HcfObjDestroy(reinterpret_cast<HcfObjectBase *>(key));
    HcfObjDestroy(reinterpret_cast<HcfObjectBase *>(cipher));
}

HWTEST_F(CryptoAesXtsCipherTest, CryptoAesXtsCipherTest008, TestSize.Level0)
{
    int ret = 0;
    uint8_t plainText[] = "this is test!";
    uint8_t aad[CCM_AAD_LEN] = {0};
    uint8_t iv[CCM_IV_LEN] = {0}; /* 7 bytes, valid for new CCM */

    HcfCipher *cipher = nullptr;
    HcfSymKey *key = nullptr;

    HcfAeadParamsSpec encSpec = {};
    encSpec.base.getType = GetAeadParamsSpecTypeForTest;
    encSpec.nonce.data = iv;
    encSpec.nonce.len = sizeof(iv);
    encSpec.aad.data = aad;
    encSpec.aad.len = sizeof(aad);
    encSpec.tagLen = 16; /* typical CCM tag length */

    ret = GenerateSymKey("AES128", &key);
    ASSERT_EQ(ret, 0);

    ret = HcfCipherCreate("AES128|CCM|NoPadding", &cipher);
    ASSERT_EQ(ret, 0);

    HcfBlob input = {.data = plainText, .len = sizeof(plainText) - 1};
    HcfBlob output = {};
    ret = cipher->init(cipher, ENCRYPT_MODE, reinterpret_cast<HcfKey *>(key),
        reinterpret_cast<HcfParamsSpec *>(&encSpec));
    ASSERT_EQ(ret, 0);

    ret = cipher->update(cipher, &input, &output);
    ASSERT_EQ(ret, 0);
    ASSERT_NE(output.data, nullptr);
    HcfBlob tagData = {};
    ret = cipher->doFinal(cipher, nullptr, &tagData);
    ASSERT_EQ(ret, 0);
    ASSERT_NE(tagData.data, nullptr);
    ASSERT_EQ(tagData.len, encSpec.tagLen);
    HcfBlobDataFree(&output);
    HcfBlobDataFree(&tagData);
    HcfObjDestroy(reinterpret_cast<HcfObjectBase *>(key));
    HcfObjDestroy(reinterpret_cast<HcfObjectBase *>(cipher));
}

typedef struct {
    const uint8_t *key;
    size_t keyLen;
    const uint8_t *iv;
    size_t ivLen;
    const uint8_t *aad;
    size_t aadLen;
    const uint8_t *plaintext;
    size_t plainLen;
    const uint8_t *ciphertext;
    size_t cipherLen;
    const uint8_t *tag;
    size_t tagLen;
} Aes256CcmVectorCase;

static Aes256CcmVectorCase GetAes256CcmVectorTest005(void)
{
    static const uint8_t key[] = {
        0x60, 0x82, 0x3b, 0x64, 0xe0, 0xb2, 0xda, 0x3a,
        0x7e, 0xb7, 0x72, 0xbd, 0x59, 0x41, 0xc5, 0x34,
        0xe6, 0xff, 0x94, 0xea, 0x96, 0xb5, 0x64, 0xe2,
        0xb3, 0x8f, 0x82, 0xc7, 0x8b, 0xb5, 0x45, 0x22
    };
    static const uint8_t iv[] = {
        0x48, 0x52, 0x6f, 0x1b, 0xff, 0xc9, 0x7d, 0xd6, 0x5e, 0x42, 0x90, 0x69, 0x83
    };
    static const uint8_t aad[] = {
        0x42, 0xa7, 0x18, 0xd8, 0x92, 0xe2, 0x29, 0xa1,
        0x80, 0x7b, 0x74, 0xbd, 0x73, 0x0f, 0xb1, 0x55,
        0x00, 0xac, 0x4a, 0x79, 0x03, 0x92, 0x10, 0x0a,
        0xef, 0x36, 0x2c, 0xd7, 0x62, 0x8d, 0x58, 0x06
    };
    static const uint8_t tag[] = {
        0x75, 0xd8, 0x6c, 0xde, 0x91, 0xb6, 0x61, 0x04,
        0x96, 0xc3, 0xbb, 0x52, 0x76, 0x23, 0x87, 0x41
    };
    static const uint8_t plaintext[] = {
        0x00, 0x41, 0xa0, 0xcf, 0x48, 0xfc, 0xf8, 0x70,
        0xb2, 0x1d, 0xb6, 0x10, 0x7c, 0xfd, 0x9e, 0xf9,
        0x1e, 0x40, 0x9a, 0xfc, 0x75, 0x62, 0xff, 0xa7
    };
    static const uint8_t ciphertext[] = {
        0x64, 0xc1, 0x27, 0x8d, 0x83, 0x35, 0xea, 0xf6,
        0x1f, 0x90, 0x82, 0x2f, 0x72, 0xf9, 0xf0, 0x4e,
        0x75, 0x6f, 0x29, 0xa1, 0x8d, 0xd6, 0xb6, 0xf9
    };
    return { key, sizeof(key), iv, sizeof(iv), aad, sizeof(aad), plaintext, sizeof(plaintext),
        ciphertext, sizeof(ciphertext), tag, sizeof(tag) };
}

static Aes256CcmVectorCase GetAes256CcmVectorTest006(void)
{
    static const uint8_t key[] = {
        0x90, 0x74, 0xb1, 0xae, 0x4c, 0xa3, 0x34, 0x2f,
        0xe5, 0xbf, 0x6f, 0x14, 0xbc, 0xf2, 0xf2, 0x79,
        0x04, 0xf0, 0xb1, 0x51, 0x79, 0xd9, 0x5a, 0x65,
        0x4f, 0x61, 0xe6, 0x99, 0x69, 0x2e, 0x6f, 0x71
    };
    static const uint8_t iv[] = {
        0x2e, 0x1e, 0x01, 0x32, 0x46, 0x85, 0x00, 0xd4,
        0xbd, 0x47, 0x86, 0x25, 0x63
    };
    static const uint8_t aad[] = {
        0x3c, 0x5f, 0x54, 0x04, 0x37, 0x0a, 0xbd, 0xcb,
        0x1e, 0xdd, 0xe9, 0x9d, 0xe6, 0x0d, 0x06, 0x82,
        0xc6, 0x00, 0xb0, 0x34, 0xe0, 0x63, 0xb7, 0xd3,
        0x23, 0x77, 0x23, 0xda, 0x70, 0xab, 0x75, 0x52
    };
    static const uint8_t tag[] = { 0x3c, 0xb9, 0xaf, 0xed };
    static const uint8_t plaintext[] = {
        0x23, 0x90, 0x29, 0xf1, 0x50, 0xbc, 0xcb, 0xd6,
        0x7e, 0xdb, 0xb6, 0x7f, 0x8a, 0xe4, 0x56, 0xb4,
        0xea, 0x06, 0x6a, 0x4b, 0xee, 0xe0, 0x65, 0xf9
    };
    static const uint8_t ciphertext[] = {
        0x9c, 0x8d, 0x5d, 0xd2, 0x27, 0xfd, 0x9f, 0x81,
        0x23, 0x76, 0x01, 0x83, 0x0a, 0xfe, 0xe4, 0xf0,
        0x11, 0x56, 0x36, 0xc8, 0xe5, 0xd5, 0xfd, 0x74
    };
    return { key, sizeof(key), iv, sizeof(iv), aad, sizeof(aad), plaintext, sizeof(plaintext),
        ciphertext, sizeof(ciphertext), tag, sizeof(tag) };
}

HWTEST_F(CryptoAesXtsCipherTest, CryptoAesXtsCipherTest005, TestSize.Level0)
{
    Aes256CcmVectorCase vec = GetAes256CcmVectorTest005();

    HcfCipher *cipher = nullptr;
    HcfSymKey *key = nullptr;
    HcfSymKeyGenerator *generator = nullptr;
    HcfBlob keyBlob = {.data = const_cast<uint8_t *>(vec.key), .len = vec.keyLen};

    int32_t ret = HcfSymKeyGeneratorCreate("AES256", &generator);
    ASSERT_EQ(ret, 0);
    ret = generator->convertSymKey(generator, &keyBlob, &key);
    ASSERT_EQ(ret, 0);
    HcfObjDestroy(reinterpret_cast<HcfObjectBase *>(generator));

    ret = HcfCipherCreate("AES256|CCM|NoPadding", &cipher);
    ASSERT_EQ(ret, 0);

    HcfAeadParamsSpec spec = {};
    spec.base.getType = GetAeadParamsSpecTypeForTest;
    spec.nonce.data = const_cast<uint8_t *>(vec.iv);
    spec.nonce.len = vec.ivLen;
    spec.aad.data = const_cast<uint8_t *>(vec.aad);
    spec.aad.len = vec.aadLen;
    spec.tagLen = static_cast<uint32_t>(vec.tagLen);

    HcfBlob encIn = {.data = const_cast<uint8_t *>(vec.plaintext), .len = vec.plainLen};
    HcfBlob encOut = {};
    ret = cipher->init(cipher, ENCRYPT_MODE, reinterpret_cast<HcfKey *>(key),
        reinterpret_cast<HcfParamsSpec *>(&spec));
    ASSERT_EQ(ret, 0);
    ret = cipher->doFinal(cipher, &encIn, &encOut);
    ASSERT_EQ(ret, 0);
    ASSERT_EQ(encOut.len, vec.cipherLen + vec.tagLen);
    ASSERT_EQ(memcmp(encOut.data, vec.ciphertext, vec.cipherLen), 0);
    ASSERT_EQ(memcmp(encOut.data + vec.cipherLen, vec.tag, vec.tagLen), 0);

    HcfBlob decIn = {.data = encOut.data, .len = encOut.len};
    HcfBlob decOut = {};
    ret = cipher->init(cipher, DECRYPT_MODE, reinterpret_cast<HcfKey *>(key),
        reinterpret_cast<HcfParamsSpec *>(&spec));
    ASSERT_EQ(ret, 0);
    ret = cipher->doFinal(cipher, &decIn, &decOut);
    ASSERT_EQ(ret, 0);
    ASSERT_EQ(decOut.len, vec.plainLen);
    ASSERT_EQ(memcmp(decOut.data, vec.plaintext, vec.plainLen), 0);

    HcfBlobDataFree(&encOut);
    HcfBlobDataFree(&decOut);
    HcfObjDestroy(reinterpret_cast<HcfObjectBase *>(key));
    HcfObjDestroy(reinterpret_cast<HcfObjectBase *>(cipher));
}

HWTEST_F(CryptoAesXtsCipherTest, CryptoAesXtsCipherTest006, TestSize.Level0)
{
    Aes256CcmVectorCase vec = GetAes256CcmVectorTest006();

    HcfCipher *cipher = nullptr;
    HcfSymKey *key = nullptr;
    HcfSymKeyGenerator *generator = nullptr;
    HcfBlob keyBlob = {.data = const_cast<uint8_t *>(vec.key), .len = vec.keyLen};

    int32_t ret = HcfSymKeyGeneratorCreate("AES256", &generator);
    ASSERT_EQ(ret, 0);
    ret = generator->convertSymKey(generator, &keyBlob, &key);
    ASSERT_EQ(ret, 0);
    HcfObjDestroy(reinterpret_cast<HcfObjectBase *>(generator));

    ret = HcfCipherCreate("AES256|CCM|NoPadding", &cipher);
    ASSERT_EQ(ret, 0);

    HcfAeadParamsSpec spec = {};
    spec.base.getType = GetAeadParamsSpecTypeForTest;
    spec.nonce.data = const_cast<uint8_t *>(vec.iv);
    spec.nonce.len = vec.ivLen;
    spec.aad.data = const_cast<uint8_t *>(vec.aad);
    spec.aad.len = vec.aadLen;
    spec.tagLen = static_cast<uint32_t>(vec.tagLen);

    HcfBlob encIn = {.data = const_cast<uint8_t *>(vec.plaintext), .len = vec.plainLen};
    HcfBlob encOut = {};
    ret = cipher->init(cipher, ENCRYPT_MODE, reinterpret_cast<HcfKey *>(key),
        reinterpret_cast<HcfParamsSpec *>(&spec));
    ASSERT_EQ(ret, 0);
    ret = cipher->doFinal(cipher, &encIn, &encOut);
    ASSERT_EQ(ret, 0);
    ASSERT_EQ(encOut.len, vec.cipherLen + vec.tagLen);
    ASSERT_EQ(memcmp(encOut.data, vec.ciphertext, vec.cipherLen), 0);
    ASSERT_EQ(memcmp(encOut.data + vec.cipherLen, vec.tag, vec.tagLen), 0);

    HcfBlob decIn = {.data = encOut.data, .len = encOut.len};
    HcfBlob decOut = {};
    ret = cipher->init(cipher, DECRYPT_MODE, reinterpret_cast<HcfKey *>(key),
        reinterpret_cast<HcfParamsSpec *>(&spec));
    ASSERT_EQ(ret, 0);
    ret = cipher->doFinal(cipher, &decIn, &decOut);
    ASSERT_EQ(ret, 0);
    ASSERT_EQ(decOut.len, vec.plainLen);
    ASSERT_EQ(memcmp(decOut.data, vec.plaintext, vec.plainLen), 0);

    HcfBlobDataFree(&encOut);
    HcfBlobDataFree(&decOut);
    HcfObjDestroy(reinterpret_cast<HcfObjectBase *>(key));
    HcfObjDestroy(reinterpret_cast<HcfObjectBase *>(cipher));
}

HWTEST_F(CryptoAesCcmCipherStubTest, CryptoAesCcmCipherErrTest001, TestSize.Level0)
{
    uint8_t aad[CCM_AAD_LEN] = {0};
    uint8_t iv[TEST_CCM_IV_LEN] = {0};
    HcfAeadParamsSpec spec = {};
    spec.base.getType = GetAeadParamsSpecTypeForTest;
    spec.nonce.data = iv;
    spec.nonce.len = sizeof(iv);
    spec.aad.data = aad;
    spec.aad.len = sizeof(aad);
    spec.tagLen = 16;

    HcfSymKey *key = nullptr;
    HcfCipher *cipher = nullptr;
    ASSERT_EQ(GenerateSymKey("AES256", &key), 0);
    ASSERT_EQ(HcfCipherCreate("AES256|CCM|NoPadding", &cipher), 0);

    HcfResult ret = cipher->init(cipher, ENCRYPT_MODE, reinterpret_cast<HcfKey *>(key),
        reinterpret_cast<HcfParamsSpec *>(&spec));
    ASSERT_EQ(ret, HCF_INVALID_PARAMS);

    HcfObjDestroy(reinterpret_cast<HcfObjectBase *>(cipher));
    HcfObjDestroy(reinterpret_cast<HcfObjectBase *>(key));
}

HWTEST_F(CryptoAesCcmCipherStubTest, CryptoAesCcmCipherStubTest001, TestSize.Level0)
{
    uint8_t aad[CCM_AAD_LEN] = {0};
    uint8_t iv[CCM_IV_LEN] = {0};
    HcfAeadParamsSpec spec = {};
    spec.base.getType = GetAeadParamsSpecTypeForTest;
    spec.nonce.data = iv;
    spec.nonce.len = sizeof(iv);
    spec.aad.data = aad;
    spec.aad.len = sizeof(aad);
    spec.tagLen = 16;

    HcfSymKey *key = nullptr;
    HcfCipher *cipher = nullptr;
    ASSERT_EQ(GenerateSymKey("AES256", &key), 0);
    ASSERT_EQ(HcfCipherCreate("AES256|CCM|NoPadding", &cipher), 0);

    EXPECT_CALL(*mock_, OpensslEvpCipherCtxNew())
        .WillOnce(Return(nullptr))
        .WillRepeatedly(Invoke(__real_OpensslEvpCipherCtxNew));
    HcfResult ret = cipher->init(cipher, ENCRYPT_MODE, reinterpret_cast<HcfKey *>(key),
        reinterpret_cast<HcfParamsSpec *>(&spec));
    ASSERT_NE(ret, HCF_SUCCESS);

    HcfObjDestroy(reinterpret_cast<HcfObjectBase *>(cipher));
    HcfObjDestroy(reinterpret_cast<HcfObjectBase *>(key));
}

HWTEST_F(CryptoAesCcmCipherStubTest, CryptoAesCcmCipherStubTest002, TestSize.Level0)
{
    uint8_t aad[CCM_AAD_LEN] = {0};
    uint8_t iv[CCM_IV_LEN] = {0};
    HcfAeadParamsSpec spec = {};
    spec.base.getType = GetAeadParamsSpecTypeForTest;
    spec.nonce.data = iv;
    spec.nonce.len = sizeof(iv);
    spec.aad.data = aad;
    spec.aad.len = sizeof(aad);
    spec.tagLen = 16;

    HcfSymKey *key = nullptr;
    HcfCipher *cipher = nullptr;
    ASSERT_EQ(GenerateSymKey("AES256", &key), 0);
    ASSERT_EQ(HcfCipherCreate("AES256|CCM|NoPadding", &cipher), 0);

    EXPECT_CALL(*mock_, OpensslEvpCipherInit(_, _, _, _, _))
        .WillOnce(Return(-1))
        .WillRepeatedly(Invoke(__real_OpensslEvpCipherInit));
    HcfResult ret = cipher->init(cipher, ENCRYPT_MODE, reinterpret_cast<HcfKey *>(key),
        reinterpret_cast<HcfParamsSpec *>(&spec));
    ASSERT_NE(ret, HCF_SUCCESS);

    HcfObjDestroy(reinterpret_cast<HcfObjectBase *>(cipher));
    HcfObjDestroy(reinterpret_cast<HcfObjectBase *>(key));
}

HWTEST_F(CryptoAesCcmCipherStubTest, CryptoAesCcmCipherStubTest003, TestSize.Level0)
{
    uint8_t aad[CCM_AAD_LEN] = {0};
    uint8_t iv[CCM_IV_LEN] = {0};
    HcfAeadParamsSpec spec = {};
    spec.base.getType = GetAeadParamsSpecTypeForTest;
    spec.nonce.data = iv;
    spec.nonce.len = sizeof(iv);
    spec.aad.data = aad;
    spec.aad.len = sizeof(aad);
    spec.tagLen = 16;

    HcfSymKey *key = nullptr;
    HcfCipher *cipher = nullptr;
    ASSERT_EQ(GenerateSymKey("AES256", &key), 0);
    ASSERT_EQ(HcfCipherCreate("AES256|CCM|NoPadding", &cipher), 0);

    EXPECT_CALL(*mock_, OpensslEvpCipherCtxCtrl(_, _, _, _))
        .WillOnce(Return(-1))
        .WillRepeatedly(Invoke(__real_OpensslEvpCipherCtxCtrl));
    HcfResult ret = cipher->init(cipher, ENCRYPT_MODE, reinterpret_cast<HcfKey *>(key),
        reinterpret_cast<HcfParamsSpec *>(&spec));
    ASSERT_NE(ret, HCF_SUCCESS);

    HcfObjDestroy(reinterpret_cast<HcfObjectBase *>(cipher));
    HcfObjDestroy(reinterpret_cast<HcfObjectBase *>(key));
}

HWTEST_F(CryptoAesCcmCipherStubTest, CryptoAesCcmCipherStubTest004, TestSize.Level0)
{
    uint8_t aad[CCM_AAD_LEN] = {0};
    uint8_t iv[CCM_IV_LEN] = {0};
    HcfAeadParamsSpec spec = {};
    spec.base.getType = GetAeadParamsSpecTypeForTest;
    spec.nonce.data = iv;
    spec.nonce.len = sizeof(iv);
    spec.aad.data = aad;
    spec.aad.len = sizeof(aad);
    spec.tagLen = 16;

    HcfSymKey *key = nullptr;
    HcfCipher *cipher = nullptr;
    ASSERT_EQ(GenerateSymKey("AES256", &key), 0);
    ASSERT_EQ(HcfCipherCreate("AES256|CCM|NoPadding", &cipher), 0);

    EXPECT_CALL(*mock_, OpensslEvpCipherCtxSetPadding(_, _))
        .WillOnce(Return(-1))
        .WillRepeatedly(Invoke(__real_OpensslEvpCipherCtxSetPadding));
    HcfResult ret = cipher->init(cipher, ENCRYPT_MODE, reinterpret_cast<HcfKey *>(key),
        reinterpret_cast<HcfParamsSpec *>(&spec));
    ASSERT_NE(ret, HCF_SUCCESS);

    HcfObjDestroy(reinterpret_cast<HcfObjectBase *>(cipher));
    HcfObjDestroy(reinterpret_cast<HcfObjectBase *>(key));
}

HWTEST_F(CryptoAesCcmCipherStubTest, CryptoAesCcmCipherStubTest005, TestSize.Level0)
{
    uint8_t plainText[] = "ccm stub test";
    uint8_t aad[CCM_AAD_LEN] = {0};
    uint8_t iv[CCM_IV_LEN] = {0};
    HcfAeadParamsSpec spec = {};
    spec.base.getType = GetAeadParamsSpecTypeForTest;
    spec.nonce.data = iv;
    spec.nonce.len = sizeof(iv);
    spec.aad.data = aad;
    spec.aad.len = sizeof(aad);
    spec.tagLen = 16;

    HcfSymKey *key = nullptr;
    HcfCipher *cipher = nullptr;
    ASSERT_EQ(GenerateSymKey("AES256", &key), 0);
    ASSERT_EQ(HcfCipherCreate("AES256|CCM|NoPadding", &cipher), 0);
    ASSERT_EQ(cipher->init(cipher, ENCRYPT_MODE, reinterpret_cast<HcfKey *>(key),
        reinterpret_cast<HcfParamsSpec *>(&spec)), HCF_SUCCESS);

    HcfBlob input = {.data = plainText, .len = sizeof(plainText) - 1};
    HcfBlob output = {};
    EXPECT_CALL(*mock_, HcfMalloc(_, _)).WillOnce(Return(nullptr)).WillRepeatedly(Invoke(__real_HcfMalloc));
    HcfResult ret = cipher->doFinal(cipher, &input, &output);
    EXPECT_EQ(ret, HCF_ERR_MALLOC);

    HcfObjDestroy(reinterpret_cast<HcfObjectBase *>(cipher));
    HcfObjDestroy(reinterpret_cast<HcfObjectBase *>(key));
}

HWTEST_F(CryptoAesCcmCipherStubTest, CryptoAesCcmCipherStubTest006, TestSize.Level0)
{
    uint8_t plainText[] = "ccm stub";
    uint8_t aad[CCM_AAD_LEN] = {0};
    uint8_t iv[CCM_IV_LEN] = {0};
    HcfAeadParamsSpec spec = {};
    spec.base.getType = GetAeadParamsSpecTypeForTest;
    spec.nonce.data = iv;
    spec.nonce.len = sizeof(iv);
    spec.aad.data = aad;
    spec.aad.len = sizeof(aad);
    spec.tagLen = 16;

    HcfSymKey *key = nullptr;
    HcfCipher *cipher = nullptr;
    ASSERT_EQ(GenerateSymKey("AES256", &key), 0);
    ASSERT_EQ(HcfCipherCreate("AES256|CCM|NoPadding", &cipher), 0);
    ASSERT_EQ(cipher->init(cipher, ENCRYPT_MODE, reinterpret_cast<HcfKey *>(key),
        reinterpret_cast<HcfParamsSpec *>(&spec)), HCF_SUCCESS);

    HcfBlob input = {.data = plainText, .len = sizeof(plainText) - 1};
    HcfBlob output = {};
    EXPECT_CALL(*mock_, OpensslEvpCipherUpdate(_, _, _, _, _))
        .WillOnce(Return(0))
        .WillRepeatedly(Invoke(__real_OpensslEvpCipherUpdate));
    HcfResult ret = cipher->doFinal(cipher, &input, &output);
    EXPECT_EQ(ret, HCF_ERR_CRYPTO_OPERATION);

    HcfObjDestroy(reinterpret_cast<HcfObjectBase *>(cipher));
    HcfObjDestroy(reinterpret_cast<HcfObjectBase *>(key));
}

HWTEST_F(CryptoAesCcmCipherStubTest, CryptoAesCcmCipherStubTest007, TestSize.Level0)
{
    uint8_t plainText[] = "ccm stub final";
    uint8_t aad[CCM_AAD_LEN] = {0};
    uint8_t iv[CCM_IV_LEN] = {0};
    HcfAeadParamsSpec spec = {};
    spec.base.getType = GetAeadParamsSpecTypeForTest;
    spec.nonce.data = iv;
    spec.nonce.len = sizeof(iv);
    spec.aad.data = aad;
    spec.aad.len = sizeof(aad);
    spec.tagLen = 16;

    HcfSymKey *key = nullptr;
    HcfCipher *cipher = nullptr;
    ASSERT_EQ(GenerateSymKey("AES256", &key), 0);
    ASSERT_EQ(HcfCipherCreate("AES256|CCM|NoPadding", &cipher), 0);
    ASSERT_EQ(cipher->init(cipher, ENCRYPT_MODE, reinterpret_cast<HcfKey *>(key),
        reinterpret_cast<HcfParamsSpec *>(&spec)), HCF_SUCCESS);

    HcfBlob input = {.data = plainText, .len = sizeof(plainText) - 1};
    HcfBlob output = {};
    EXPECT_CALL(*mock_, OpensslEvpCipherFinalEx(_, _, _))
        .WillOnce(Return(0))
        .WillRepeatedly(Invoke(__real_OpensslEvpCipherFinalEx));
    HcfResult ret = cipher->doFinal(cipher, &input, &output);
    EXPECT_EQ(ret, HCF_ERR_CRYPTO_OPERATION);

    HcfObjDestroy(reinterpret_cast<HcfObjectBase *>(cipher));
    HcfObjDestroy(reinterpret_cast<HcfObjectBase *>(key));
}

HWTEST_F(CryptoAesCcmCipherStubTest, CryptoAesCcmCipherStubTest008, TestSize.Level0)
{
    uint8_t aad[CCM_AAD_LEN] = {0};
    uint8_t iv[CCM_IV_LEN] = {0};
    HcfAeadParamsSpec spec = {};
    spec.base.getType = GetAeadParamsSpecTypeForTest;
    spec.nonce.data = iv;
    spec.nonce.len = sizeof(iv);
    spec.aad.data = aad;
    spec.aad.len = sizeof(aad);
    spec.tagLen = 16;

    HcfSymKey *key = nullptr;
    HcfCipher *cipher = nullptr;
    ASSERT_EQ(GenerateSymKey("AES256", &key), 0);
    ASSERT_EQ(HcfCipherCreate("AES256|CCM|NoPadding", &cipher), 0);

    EXPECT_CALL(*mock_, HcfIsClassMatch(_, _))
        .WillOnce(Return(true))
        .WillOnce(Return(false))
        .WillRepeatedly(Invoke(__real_HcfIsClassMatch));
    HcfResult ret = cipher->init(cipher, ENCRYPT_MODE, reinterpret_cast<HcfKey *>(key),
        reinterpret_cast<HcfParamsSpec *>(&spec));
    EXPECT_EQ(ret, HCF_INVALID_PARAMS);

    HcfObjDestroy(reinterpret_cast<HcfObjectBase *>(cipher));
    HcfObjDestroy(reinterpret_cast<HcfObjectBase *>(key));
}

HWTEST_F(CryptoAesCcmCipherStubTest, CryptoAesCcmCipherStubTest009, TestSize.Level0)
{
    uint8_t plainText[] = "ccm";
    uint8_t aad[CCM_AAD_LEN] = {0};
    uint8_t iv[CCM_IV_LEN] = {0};
    HcfAeadParamsSpec spec = {};
    spec.base.getType = GetAeadParamsSpecTypeForTest;
    spec.nonce.data = iv;
    spec.nonce.len = sizeof(iv);
    spec.aad.data = aad;
    spec.aad.len = sizeof(aad);
    spec.tagLen = 16;

    HcfSymKey *key = nullptr;
    HcfCipher *cipher = nullptr;
    ASSERT_EQ(GenerateSymKey("AES256", &key), 0);
    ASSERT_EQ(HcfCipherCreate("AES256|CCM|NoPadding", &cipher), 0);
    ASSERT_EQ(cipher->init(cipher, ENCRYPT_MODE, reinterpret_cast<HcfKey *>(key),
        reinterpret_cast<HcfParamsSpec *>(&spec)), HCF_SUCCESS);

    HcfBlob input = {.data = plainText, .len = sizeof(plainText) - 1};
    HcfBlob output = {};
    EXPECT_CALL(*mock_, HcfIsClassMatch(_, _))
        .WillOnce(Return(true))
        .WillOnce(Return(false))
        .WillRepeatedly(Invoke(__real_HcfIsClassMatch));
    HcfResult ret = cipher->doFinal(cipher, &input, &output);
    EXPECT_EQ(ret, HCF_INVALID_PARAMS);

    HcfObjDestroy(reinterpret_cast<HcfObjectBase *>(cipher));
    HcfObjDestroy(reinterpret_cast<HcfObjectBase *>(key));
}

/* CCM 解密路径：OpensslEvpCipherCtxCtrl(SET_TAG) 失败 */
HWTEST_F(CryptoAesCcmCipherStubTest, CryptoAesCcmCipherStubTest010, TestSize.Level0)
{
    uint8_t aad[CCM_AAD_LEN] = {0};
    uint8_t iv[CCM_IV_LEN] = {0};
    uint8_t cipherWithTag[32] = {0}; /* 占位密文+tag */
    HcfAeadParamsSpec spec = {};
    spec.base.getType = GetAeadParamsSpecTypeForTest;
    spec.nonce.data = iv;
    spec.nonce.len = sizeof(iv);
    spec.aad.data = aad;
    spec.aad.len = sizeof(aad);
    spec.tagLen = 16;

    HcfSymKey *key = nullptr;
    HcfCipher *cipher = nullptr;
    ASSERT_EQ(GenerateSymKey("AES192", &key), 0);
    ASSERT_EQ(HcfCipherCreate("AES192|CCM|NoPadding", &cipher), 0);

    EXPECT_CALL(*mock_, OpensslEvpCipherCtxCtrl(_, _, _, _))
        .WillOnce(Invoke(__real_OpensslEvpCipherCtxCtrl))
        .WillOnce(Invoke(__real_OpensslEvpCipherCtxCtrl))
        .WillOnce(Return(-1))
        .WillRepeatedly(Invoke(__real_OpensslEvpCipherCtxCtrl));
    HcfResult ret = cipher->init(cipher, DECRYPT_MODE, reinterpret_cast<HcfKey *>(key),
        reinterpret_cast<HcfParamsSpec *>(&spec));
    if (ret != HCF_SUCCESS) {
        HcfObjDestroy(reinterpret_cast<HcfObjectBase *>(cipher));
        HcfObjDestroy(reinterpret_cast<HcfObjectBase *>(key));
        return;
    }
    HcfBlob input = {.data = cipherWithTag, .len = sizeof(cipherWithTag)};
    HcfBlob output = {};
    ret = cipher->doFinal(cipher, &input, &output);
    EXPECT_EQ(ret, HCF_ERR_CRYPTO_OPERATION);

    HcfObjDestroy(reinterpret_cast<HcfObjectBase *>(cipher));
    HcfObjDestroy(reinterpret_cast<HcfObjectBase *>(key));
}

} // namespace
