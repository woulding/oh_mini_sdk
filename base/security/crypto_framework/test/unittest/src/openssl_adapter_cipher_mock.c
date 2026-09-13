/*
 * Copyright (C) 2022-2024 Huawei Device Co., Ltd.
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

#include "openssl_adapter.h"
#include "openssl_adapter_mock.h"
#include <openssl/param_build.h>

#include "result.h"
#include <stdbool.h>

void OpensslEvpCipherCtxFree(EVP_CIPHER_CTX *ctx)
{
    if (ctx != NULL) {
        EVP_CIPHER_CTX_free(ctx);
    }
}

const EVP_CIPHER *OpensslEvpAes128Ecb(void)
{
    if (IsNeedMock()) {
        return NULL;
    }
    return EVP_aes_128_ecb();
}

const EVP_CIPHER *OpensslEvpAes192Ecb(void)
{
    if (IsNeedMock()) {
        return NULL;
    }
    return EVP_aes_192_ecb();
}

const EVP_CIPHER *OpensslEvpAes256Ecb(void)
{
    if (IsNeedMock()) {
        return NULL;
    }
    return EVP_aes_256_ecb();
}

const EVP_CIPHER *OpensslEvpAes128Cbc(void)
{
    if (IsNeedMock()) {
        return NULL;
    }
    return EVP_aes_128_cbc();
}

const EVP_CIPHER *OpensslEvpAes192Cbc(void)
{
    if (IsNeedMock()) {
        return NULL;
    }
    return EVP_aes_192_cbc();
}

const EVP_CIPHER *OpensslEvpAes256Cbc(void)
{
    if (IsNeedMock()) {
        return NULL;
    }
    return EVP_aes_256_cbc();
}

const EVP_CIPHER *OpensslEvpAes128Ctr(void)
{
    if (IsNeedMock()) {
        return NULL;
    }
    return EVP_aes_128_ctr();
}

const EVP_CIPHER *OpensslEvpAes192Ctr(void)
{
    if (IsNeedMock()) {
        return NULL;
    }
    return EVP_aes_192_ctr();
}

const EVP_CIPHER *OpensslEvpAes256Ctr(void)
{
    if (IsNeedMock()) {
        return NULL;
    }
    return EVP_aes_256_ctr();
}

const EVP_CIPHER *OpensslEvpAes128Ofb(void)
{
    if (IsNeedMock()) {
        return NULL;
    }
    return EVP_aes_128_ofb();
}

const EVP_CIPHER *OpensslEvpAes192Ofb(void)
{
    if (IsNeedMock()) {
        return NULL;
    }
    return EVP_aes_192_ofb();
}

const EVP_CIPHER *OpensslEvpAes256Ofb(void)
{
    if (IsNeedMock()) {
        return NULL;
    }
    return EVP_aes_256_ofb();
}

const EVP_CIPHER *OpensslEvpAes128Cfb(void)
{
    if (IsNeedMock()) {
        return NULL;
    }
    return EVP_aes_128_cfb();
}

const EVP_CIPHER *OpensslEvpAes192Cfb(void)
{
    if (IsNeedMock()) {
        return NULL;
    }
    return EVP_aes_192_cfb();
}

const EVP_CIPHER *OpensslEvpAes256Cfb(void)
{
    if (IsNeedMock()) {
        return NULL;
    }
    return EVP_aes_256_cfb();
}

const EVP_CIPHER *OpensslEvpAes128Cfb1(void)
{
    if (IsNeedMock()) {
        return NULL;
    }
    return EVP_aes_128_cfb1();
}

const EVP_CIPHER *OpensslEvpAes192Cfb1(void)
{
    if (IsNeedMock()) {
        return NULL;
    }
    return EVP_aes_192_cfb1();
}

const EVP_CIPHER *OpensslEvpAes256Cfb1(void)
{
    if (IsNeedMock()) {
        return NULL;
    }
    return EVP_aes_256_cfb1();
}

const EVP_CIPHER *OpensslEvpAes128Cfb128(void)
{
    if (IsNeedMock()) {
        return NULL;
    }
    return EVP_aes_128_cfb128();
}

const EVP_CIPHER *OpensslEvpAes192Cfb128(void)
{
    if (IsNeedMock()) {
        return NULL;
    }
    return EVP_aes_192_cfb128();
}

const EVP_CIPHER *OpensslEvpAes256Cfb128(void)
{
    if (IsNeedMock()) {
        return NULL;
    }
    return EVP_aes_256_cfb128();
}

const EVP_CIPHER *OpensslEvpAes128Cfb8(void)
{
    if (IsNeedMock()) {
        return NULL;
    }
    return EVP_aes_128_cfb8();
}

const EVP_CIPHER *OpensslEvpAes192Cfb8(void)
{
    if (IsNeedMock()) {
        return NULL;
    }
    return EVP_aes_192_cfb8();
}

const EVP_CIPHER *OpensslEvpAes256Cfb8(void)
{
    if (IsNeedMock()) {
        return NULL;
    }
    return EVP_aes_256_cfb8();
}

const EVP_CIPHER *OpensslEvpAes128Ccm(void)
{
    if (IsNeedMock()) {
        return NULL;
    }
    return EVP_aes_128_ccm();
}

const EVP_CIPHER *OpensslEvpAes192Ccm(void)
{
    if (IsNeedMock()) {
        return NULL;
    }
    return EVP_aes_192_ccm();
}

const EVP_CIPHER *OpensslEvpAes256Ccm(void)
{
    if (IsNeedMock()) {
        return NULL;
    }
    return EVP_aes_256_ccm();
}

const EVP_CIPHER *OpensslEvpAes128Gcm(void)
{
    if (IsNeedMock()) {
        return NULL;
    }
    return EVP_aes_128_gcm();
}

const EVP_CIPHER *OpensslEvpAes192Gcm(void)
{
    if (IsNeedMock()) {
        return NULL;
    }
    return EVP_aes_192_gcm();
}

const EVP_CIPHER *OpensslEvpAes256Gcm(void)
{
    if (IsNeedMock()) {
        return NULL;
    }
    return EVP_aes_256_gcm();
}

const EVP_CIPHER *OpensslEvpAes128Wrap(void)
{
    if (IsNeedMock()) {
        return NULL;
    }
    return EVP_aes_128_wrap();
}

const EVP_CIPHER *OpensslEvpAes192Wrap(void)
{
    if (IsNeedMock()) {
        return NULL;
    }
    return EVP_aes_192_wrap();
}

const EVP_CIPHER *OpensslEvpAes256Wrap(void)
{
    if (IsNeedMock()) {
        return NULL;
    }
    return EVP_aes_256_wrap();
}

const EVP_CIPHER *OpensslEvpAes128Xts(void)
{
    if (IsNeedMock()) {
        return NULL;
    }
    return EVP_aes_128_xts();
}

const EVP_CIPHER *OpensslEvpAes256Xts(void)
{
    if (IsNeedMock()) {
        return NULL;
    }
    return EVP_aes_256_xts();
}

EVP_CIPHER_CTX *OpensslEvpCipherCtxNew(void)
{
    if (IsNeedMock()) {
        return NULL;
    }
    return EVP_CIPHER_CTX_new();
}

int OpensslEvpCipherInit(EVP_CIPHER_CTX *ctx, const EVP_CIPHER *cipher,
                         const unsigned char *key, const unsigned char *iv, int enc)
{
    if (IsNeedMock()) {
        return -1;
    }
    return EVP_CipherInit(ctx, cipher, key, iv, enc);
}

int OpensslEvpCipherCtxSetPadding(EVP_CIPHER_CTX *ctx, int pad)
{
    if (IsNeedMock()) {
        return -1;
    }
    return EVP_CIPHER_CTX_set_padding(ctx, pad);
}

int OpensslEvpCipherCtxSetKeyLength(EVP_CIPHER_CTX *ctx, int keylen)
{
    if (IsNeedMock()) {
        return -1;
    }
    return EVP_CIPHER_CTX_set_key_length(ctx, keylen);
}

int OpensslEvpCipherFinalEx(EVP_CIPHER_CTX *ctx, unsigned char *out, int *outl)
{
    if (IsNeedMock()) {
        return -1;
    }
    return EVP_CipherFinal_ex(ctx, out, outl);
}

int OpensslEvpCipherUpdate(EVP_CIPHER_CTX *ctx, unsigned char *out, int *outl, const unsigned char *in, int inl)
{
    if (IsNeedMock()) {
        return -1;
    }
    return EVP_CipherUpdate(ctx, out, outl, in, inl);
}

const EVP_CIPHER *OpensslEvpDesEde3Ecb(void)
{
    if (IsNeedMock()) {
        return NULL;
    }
    return EVP_des_ede3_ecb();
}

const EVP_CIPHER *OpensslEvpDesEde3Cbc(void)
{
    if (IsNeedMock()) {
        return NULL;
    }
    return EVP_des_ede3_cbc();
}

const EVP_CIPHER *OpensslEvpDesEde3Ofb(void)
{
    if (IsNeedMock()) {
        return NULL;
    }
    return EVP_des_ede3_ofb();
}

const EVP_CIPHER *OpensslEvpDesEde3Cfb64(void)
{
    if (IsNeedMock()) {
        return NULL;
    }
    return EVP_des_ede3_cfb64();
}

const EVP_CIPHER *OpensslEvpDesEde3Cfb1(void)
{
    if (IsNeedMock()) {
        return NULL;
    }
    return EVP_des_ede3_cfb1();
}

const EVP_CIPHER *OpensslEvpDesEde3Cfb8(void)
{
    if (IsNeedMock()) {
        return NULL;
    }
    return EVP_des_ede3_cfb8();
}

int OpensslEvpCipherCtxCtrl(EVP_CIPHER_CTX *ctx, int type, int arg, void *ptr)
{
    if (IsNeedMock()) {
        return -1;
    }
    return EVP_CIPHER_CTX_ctrl(ctx, type, arg, ptr);
}

ASN1_SEQUENCE(Sm2CipherText) = {
    ASN1_SIMPLE(Sm2CipherText, c1X, BIGNUM),
    ASN1_SIMPLE(Sm2CipherText, c1Y, BIGNUM),
    ASN1_SIMPLE(Sm2CipherText, c3, ASN1_OCTET_STRING),
    ASN1_SIMPLE(Sm2CipherText, c2, ASN1_OCTET_STRING),
} ASN1_SEQUENCE_END(Sm2CipherText)

IMPLEMENT_ASN1_FUNCTIONS(Sm2CipherText)

void OpensslEvpCipherFree(EVP_CIPHER *cipher)
{
    EVP_CIPHER_free(cipher);
}

const EVP_CIPHER *OpensslEvpSm4Ecb(void)
{
    return EVP_sm4_ecb();
}

const EVP_CIPHER *OpensslEvpSm4Cbc(void)
{
    return EVP_sm4_cbc();
}

const EVP_CIPHER *OpensslEvpSm4Cfb(void)
{
    return EVP_sm4_cfb();
}

const EVP_CIPHER *OpensslEvpSm4Cfb128(void)
{
    return EVP_sm4_cfb128();
}

const EVP_CIPHER *OpensslEvpSm4Ctr(void)
{
    return EVP_sm4_ctr();
}

const EVP_CIPHER *OpensslEvpSm4Ofb(void)
{
    return EVP_sm4_ofb();
}

EVP_CIPHER *OpensslEvpCipherFetch(OSSL_LIB_CTX *ctx, const char *algorithm, const char *properties)
{
    return EVP_CIPHER_fetch(ctx, algorithm, properties);
}

int OpensslSm2CipherTextSize(const EC_KEY *key, const EVP_MD *digest, size_t msgLen, size_t *cipherTextSize)
{
    return ossl_sm2_ciphertext_size(key, digest, msgLen, cipherTextSize);
}

int OpensslSm2PlainTextSize(const unsigned char *cipherText, size_t cipherTextSize, size_t *plainTextSize)
{
    return ossl_sm2_plaintext_size(cipherText, cipherTextSize, plainTextSize);
}

int OpensslOsslSm2Encrypt(const EC_KEY *key, const EVP_MD *digest, const uint8_t *msg,
    size_t msgLen, uint8_t *cipherTextBuf, size_t *cipherTextLen)
{
    return ossl_sm2_encrypt(key, digest, msg, msgLen, cipherTextBuf, cipherTextLen);
}

int OpensslOsslSm2Decrypt(const EC_KEY *key, const EVP_MD *digest, const uint8_t *cipherText,
    size_t cipherTextLen, uint8_t *plainTextBuf, size_t *plainTextLen)
{
    return ossl_sm2_decrypt(key, digest, cipherText, cipherTextLen, plainTextBuf, plainTextLen);
}

struct Sm2CipherTextSt *OpensslSm2CipherTextNew(void)
{
    return Sm2CipherText_new();
}

void OpensslSm2CipherTextFree(struct Sm2CipherTextSt *sm2Text)
{
    Sm2CipherText_free(sm2Text);
}

int OpensslI2dSm2CipherText(struct Sm2CipherTextSt *sm2Text, unsigned char **returnData)
{
    return i2d_Sm2CipherText(sm2Text, returnData);
}

struct Sm2CipherTextSt *OpensslD2iSm2CipherText(const uint8_t *ciphertext, size_t ciphertextLen)
{
    return d2i_Sm2CipherText(NULL, &ciphertext, ciphertextLen);
}

const EVP_CIPHER *OpensslEvpDesEcb(void)
{
    return EVP_des_ecb();
}

const EVP_CIPHER *OpensslEvpDesCbc(void)
{
    return EVP_des_cbc();
}

const EVP_CIPHER *OpensslEvpDesOfb(void)
{
    return EVP_des_ofb();
}

const EVP_CIPHER *OpensslEvpDesCfb64(void)
{
    return EVP_des_cfb64();
}

const EVP_CIPHER *OpensslEvpDesCfb1(void)
{
    return EVP_des_cfb1();
}

const EVP_CIPHER *OpensslEvpDesCfb8(void)
{
    return EVP_des_cfb8();
}

int OpensslEvpEncryptInit(EVP_CIPHER_CTX *ctx, const EVP_CIPHER *cipher,
    const unsigned char *key, const unsigned char *iv)
{
    return EVP_EncryptInit(ctx, cipher, key, iv);
}

const EVP_CIPHER *OpensslEvpChaCha20(void)
{
    return EVP_chacha20();
}

const EVP_CIPHER *OpensslEvpChaCha20Poly1305(void)
{
    return EVP_chacha20_poly1305();
}

int OpensslDsaBits(const DSA *dsa)
{
    if (IsNeedMock()) {
        return -1;
    }
    return DSA_bits(dsa);
}

int OpensslDhBits(const DH *dh)
{
    if (IsNeedMock()) {
        return -1;
    }
    return DH_bits(dh);
}
