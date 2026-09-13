/*
 * Copyright (c) 2026 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include <cstdio>
#include <cstdlib>
#include "mock.h"

#ifdef __cplusplus
extern "C" {
#endif

HcfMock *g_mock = nullptr;
void SetMock(HcfMock *mock)
{
    g_mock = mock;
}

void ResetMock(void)
{
    g_mock = nullptr;
}

void *__wrap_HcfMalloc(uint32_t size, char val)
{
    if (g_mock != nullptr) {
        return g_mock->HcfMalloc(size, val);
    }
    return __real_HcfMalloc(size, val);
}

int __wrap_OpensslEvpMdCtxSize(const EVP_MD_CTX *ctx)
{
    if (g_mock != nullptr) {
        return g_mock->OpensslEvpMdCtxSize(ctx);
    }
    return __real_OpensslEvpMdCtxSize(ctx);
}

bool __wrap_HcfIsClassMatch(const HcfObjectBase *obj, const char *className)
{
    if (g_mock != nullptr) {
        return g_mock->HcfIsClassMatch(obj, className);
    }
    return __real_HcfIsClassMatch(obj, className);
}

bool __wrap_HcfIsStrValid(const char *str, uint32_t maxLen)
{
    if (g_mock != nullptr) {
        return g_mock->HcfIsStrValid(str, maxLen);
    }
    return __real_HcfIsStrValid(str, maxLen);
}

int __wrap_OpensslEvpDigestInitEx(EVP_MD_CTX *ctx, const EVP_MD *type, ENGINE *impl)
{
    if (g_mock != nullptr) {
        return g_mock->OpensslEvpDigestInitEx(ctx, type, impl);
    }
    return __real_OpensslEvpDigestInitEx(ctx, type, impl);
}

EVP_CIPHER *__wrap_OpensslEvpCipherFetch(OSSL_LIB_CTX *ctx, const char *algorithm, const char *properties)
{
    if (g_mock != nullptr) {
        return g_mock->OpensslEvpCipherFetch(ctx, algorithm, properties);
    }
    return __real_OpensslEvpCipherFetch(ctx, algorithm, properties);
}

EVP_CIPHER_CTX *__wrap_OpensslEvpCipherCtxNew(void)
{
    if (g_mock != nullptr) {
        return g_mock->OpensslEvpCipherCtxNew();
    }
    return __real_OpensslEvpCipherCtxNew();
}

int __wrap_OpensslEvpCipherInit(EVP_CIPHER_CTX *ctx, const EVP_CIPHER *cipher,
    const unsigned char *key, const unsigned char *iv, int enc)
{
    if (g_mock != nullptr) {
        return g_mock->OpensslEvpCipherInit(ctx, cipher, key, iv, enc);
    }
    return __real_OpensslEvpCipherInit(ctx, cipher, key, iv, enc);
}

int __wrap_OpensslEvpCipherCtxSetKeyLength(EVP_CIPHER_CTX *ctx, int keylen)
{
    if (g_mock != nullptr) {
        return g_mock->OpensslEvpCipherCtxSetKeyLength(ctx, keylen);
    }
    return __real_OpensslEvpCipherCtxSetKeyLength(ctx, keylen);
}

int __wrap_OpensslEvpCipherCtxCtrl(EVP_CIPHER_CTX *ctx, int type, int arg, void *ptr)
{
    if (g_mock != nullptr) {
        return g_mock->OpensslEvpCipherCtxCtrl(ctx, type, arg, ptr);
    }
    return __real_OpensslEvpCipherCtxCtrl(ctx, type, arg, ptr);
}

int __wrap_OpensslEvpCipherCtxSetPadding(EVP_CIPHER_CTX *ctx, int pad)
{
    if (g_mock != nullptr) {
        return g_mock->OpensslEvpCipherCtxSetPadding(ctx, pad);
    }
    return __real_OpensslEvpCipherCtxSetPadding(ctx, pad);
}

int __wrap_OpensslEvpCipherUpdate(EVP_CIPHER_CTX *ctx, unsigned char *out, int *outl,
    const unsigned char *in, int inl)
{
    if (g_mock != nullptr) {
        return g_mock->OpensslEvpCipherUpdate(ctx, out, outl, in, inl);
    }
    return __real_OpensslEvpCipherUpdate(ctx, out, outl, in, inl);
}

int __wrap_OpensslEvpCipherFinalEx(EVP_CIPHER_CTX *ctx, unsigned char *out, int *outl)
{
    if (g_mock != nullptr) {
        return g_mock->OpensslEvpCipherFinalEx(ctx, out, outl);
    }
    return __real_OpensslEvpCipherFinalEx(ctx, out, outl);
}

EC_KEY *__wrap_OpensslEcKeyDup(const EC_KEY *ecKey)
{
    if (g_mock != nullptr) {
        return g_mock->OpensslEcKeyDup(ecKey);
    }
    return __real_OpensslEcKeyDup(ecKey);
}

EVP_PKEY *__wrap_OpensslEvpPkeyNew(void)
{
    if (g_mock != nullptr) {
        return g_mock->OpensslEvpPkeyNew();
    }
    return __real_OpensslEvpPkeyNew();
}

int __wrap_OpensslEvpPkeyAssignEcKey(EVP_PKEY *pkey, EC_KEY *key)
{
    if (g_mock != nullptr) {
        return g_mock->OpensslEvpPkeyAssignEcKey(pkey, key);
    }
    return __real_OpensslEvpPkeyAssignEcKey(pkey, key);
}

EVP_PKEY_CTX *__wrap_OpensslEvpPkeyCtxNewFromPkey(OSSL_LIB_CTX *libctx, EVP_PKEY *pkey, const char *propquery)
{
    if (g_mock != nullptr) {
        return g_mock->OpensslEvpPkeyCtxNewFromPkey(libctx, pkey, propquery);
    }
    return __real_OpensslEvpPkeyCtxNewFromPkey(libctx, pkey, propquery);
}

int __wrap_OpensslEvpPkeySignInit(EVP_PKEY_CTX *ctx)
{
    if (g_mock != nullptr) {
        return g_mock->OpensslEvpPkeySignInit(ctx);
    }
    return __real_OpensslEvpPkeySignInit(ctx);
}

int __wrap_OpensslEvpPkeySign(EVP_PKEY_CTX *ctx, unsigned char *sig, size_t *siglen, const unsigned char *tbs,
    size_t tbslen)
{
    if (g_mock != nullptr) {
        return g_mock->OpensslEvpPkeySign(ctx, sig, siglen, tbs, tbslen);
    }
    return __real_OpensslEvpPkeySign(ctx, sig, siglen, tbs, tbslen);
}

int __wrap_OpensslEvpPkeyVerifyInit(EVP_PKEY_CTX *ctx)
{
    if (g_mock != nullptr) {
        return g_mock->OpensslEvpPkeyVerifyInit(ctx);
    }
    return __real_OpensslEvpPkeyVerifyInit(ctx);
}

int __wrap_OpensslEvpPkeyVerify(EVP_PKEY_CTX *ctx, const unsigned char *sig, size_t siglen, const unsigned char *tbs,
    size_t tbslen)
{
    if (g_mock != nullptr) {
        return g_mock->OpensslEvpPkeyVerify(ctx, sig, siglen, tbs, tbslen);
    }
    return __real_OpensslEvpPkeyVerify(ctx, sig, siglen, tbs, tbslen);
}

int __wrap_OpensslEvpPkeyCtxSetSignatureMd(EVP_PKEY_CTX *ctx, const EVP_MD *md)
{
    if (g_mock != nullptr) {
        return g_mock->OpensslEvpPkeyCtxSetSignatureMd(ctx, md);
    }
    return __real_OpensslEvpPkeyCtxSetSignatureMd(ctx, md);
}

int __wrap_OpensslEvpPkeyCtxSetRsaPadding(EVP_PKEY_CTX *ctx, int pad)
{
    if (g_mock != nullptr) {
        return g_mock->OpensslEvpPkeyCtxSetRsaPadding(ctx, pad);
    }
    return __real_OpensslEvpPkeyCtxSetRsaPadding(ctx, pad);
}
#ifdef __cplusplus
} /* extern "C" */
#endif
