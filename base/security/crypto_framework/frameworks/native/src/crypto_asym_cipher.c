/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
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

#include "crypto_asym_cipher.h"
#include <securec.h>
#include "result.h"
#include "memory.h"
#include "cipher.h"
#include "sm2_crypto_util.h"
#include "pub_key.h"
#include "pri_key.h"
#include "blob.h"
#include "object_base.h"
#include "native_common.h"
#include "crypto_common.h"

typedef struct OH_CryptoAsymCipher {
    HcfObjectBase base;

    HcfResult (*init)(HcfCipher *self, enum HcfCryptoMode opMode,
        HcfKey *key, HcfParamsSpec *params);

    HcfResult (*update)(HcfCipher *self, HcfBlob *input, HcfBlob *output);

    HcfResult (*doFinal)(HcfCipher *self, HcfBlob *input, HcfBlob *output);

    const char *(*getAlgorithm)(HcfCipher *self);

    HcfResult (*setCipherSpecUint8Array)(HcfCipher *self, CipherSpecItem item, HcfBlob blob);

    HcfResult (*getCipherSpecString)(HcfCipher *self, CipherSpecItem item, char **returnString);

    HcfResult (*getCipherSpecUint8Array)(HcfCipher *self, CipherSpecItem item, HcfBlob *returnUint8Array);
} OH_CryptoAsymCipher;

typedef struct OH_CryptoKeyPair {
    HcfObjectBase base;

    HcfPriKey *priKey;

    HcfPubKey *pubKey;
} OH_CryptoKeyPair;

typedef struct OH_CryptoSm2CiphertextSpec {
    HcfBigInteger xCoordinate;
    HcfBigInteger yCoordinate;
    HcfBlob cipherTextData;
    HcfBlob hashData;
} OH_CryptoSm2CiphertextSpec;

static const char *g_sm2ModeC1C3C2 = "C1C3C2";

static OH_Crypto_ErrCode CryptoAsymCipherCreate(const char *algoName, OH_CryptoAsymCipher **ctx)
{
    if ((algoName == NULL) || (ctx == NULL)) {
        return CRYPTO_PARAMETER_CHECK_FAILED;
    }
    HcfResult ret = HcfCipherCreate(algoName, (HcfCipher **)ctx);
    return GetOhCryptoErrCodeNew(ret);
}

OH_Crypto_ErrCode OH_CryptoAsymCipher_Create(const char *algoName, OH_CryptoAsymCipher **ctx)
{
    return CryptoAsymCipherCreate(algoName, ctx);
}

static OH_Crypto_ErrCode CryptoAsymCipherInit(OH_CryptoAsymCipher *ctx, Crypto_CipherMode mode, OH_CryptoKeyPair *key)
{
    if ((ctx == NULL) || (ctx->init == NULL) || (key == NULL)) {
        return CRYPTO_PARAMETER_CHECK_FAILED;
    }
    HcfResult ret = HCF_SUCCESS;
    switch (mode) {
        case CRYPTO_ENCRYPT_MODE:
            ret = ctx->init((HcfCipher *)ctx, (enum HcfCryptoMode)mode, (HcfKey *)(key->pubKey), NULL);
            break;
        case CRYPTO_DECRYPT_MODE:
            ret = ctx->init((HcfCipher *)ctx, (enum HcfCryptoMode)mode, (HcfKey *)(key->priKey), NULL);
            break;
        default:
            return CRYPTO_PARAMETER_CHECK_FAILED;
    }
    return GetOhCryptoErrCodeNew(ret);
}

OH_Crypto_ErrCode OH_CryptoAsymCipher_Init(OH_CryptoAsymCipher *ctx, Crypto_CipherMode mode, OH_CryptoKeyPair *key)
{
    return CryptoAsymCipherInit(ctx, mode, key);
}

static OH_Crypto_ErrCode CryptoAsymCipherFinal(OH_CryptoAsymCipher *ctx, const Crypto_DataBlob *in,
    Crypto_DataBlob *out)
{
    if ((ctx == NULL) || (ctx->doFinal == NULL) || (out == NULL)) {
        return CRYPTO_PARAMETER_CHECK_FAILED;
    }
    HcfResult ret = ctx->doFinal((HcfCipher *)ctx, (HcfBlob *)in, (HcfBlob *)out);
    return GetOhCryptoErrCodeNew(ret);
}

OH_Crypto_ErrCode OH_CryptoAsymCipher_Final(OH_CryptoAsymCipher *ctx, const Crypto_DataBlob *in,
    Crypto_DataBlob *out)
{
    return CryptoAsymCipherFinal(ctx, in, out);
}

static void CryptoAsymCipherDestroy(OH_CryptoAsymCipher *ctx)
{
    if ((ctx == NULL) || (ctx->base.destroy == NULL)) {
        return;
    }
    ctx->base.destroy((HcfObjectBase *)ctx);
}

void OH_CryptoAsymCipher_Destroy(OH_CryptoAsymCipher *ctx)
{
    CryptoAsymCipherDestroy(ctx);
}

static OH_Crypto_ErrCode CryptoSm2CiphertextSpecCreate(Crypto_DataBlob *sm2Ciphertext,
    OH_CryptoSm2CiphertextSpec **spec)
{
    if (spec == NULL) {
        return CRYPTO_PARAMETER_CHECK_FAILED;
    }
    if (sm2Ciphertext == NULL) {
        *spec = (OH_CryptoSm2CiphertextSpec *)HcfMalloc(sizeof(OH_CryptoSm2CiphertextSpec), 0);
        if (*spec == NULL) {
            return CRYPTO_MEMORY_ERROR;
        }
        return CRYPTO_SUCCESS;
    }
    HcfResult ret = HcfGetCipherTextSpec((HcfBlob *)sm2Ciphertext, g_sm2ModeC1C3C2, (Sm2CipherTextSpec **)spec);
    return GetOhCryptoErrCodeNew(ret);
}

OH_Crypto_ErrCode OH_CryptoSm2CiphertextSpec_Create(Crypto_DataBlob *sm2Ciphertext, OH_CryptoSm2CiphertextSpec **spec)
{
    return CryptoSm2CiphertextSpecCreate(sm2Ciphertext, spec);
}

static OH_Crypto_ErrCode CryptoSm2CiphertextSpecGetItem(OH_CryptoSm2CiphertextSpec *spec,
    CryptoSm2CiphertextSpec_item item, Crypto_DataBlob *out)
{
    if ((spec == NULL) || (out == NULL)) {
        return CRYPTO_PARAMETER_CHECK_FAILED;
    }
    uint8_t *data = NULL;
    size_t len = 0;
    switch (item) {
        case CRYPTO_SM2_CIPHERTEXT_C1_X:
            data = spec->xCoordinate.data;
            len = spec->xCoordinate.len;
            break;
        case CRYPTO_SM2_CIPHERTEXT_C1_Y:
            data = spec->yCoordinate.data;
            len = spec->yCoordinate.len;
            break;
        case CRYPTO_SM2_CIPHERTEXT_C2:
            data = spec->cipherTextData.data;
            len = spec->cipherTextData.len;
            break;
        case CRYPTO_SM2_CIPHERTEXT_C3:
            data = spec->hashData.data;
            len = spec->hashData.len;
            break;
        default:
            return CRYPTO_PARAMETER_CHECK_FAILED;
    }
    if ((data == NULL) || (len == 0)) {
        return CRYPTO_PARAMETER_CHECK_FAILED;
    }
    out->data = (uint8_t *)HcfMalloc(len, 0);
    if (out->data == NULL) {
        return CRYPTO_MEMORY_ERROR;
    }
    (void)memcpy_s(out->data, len, data, len);
    out->len = len;
    return CRYPTO_SUCCESS;
}

OH_Crypto_ErrCode OH_CryptoSm2CiphertextSpec_GetItem(OH_CryptoSm2CiphertextSpec *spec,
    CryptoSm2CiphertextSpec_item item, Crypto_DataBlob *out)
{
    return CryptoSm2CiphertextSpecGetItem(spec, item, out);
}

static OH_Crypto_ErrCode CryptoSm2CiphertextSpecSetItem(OH_CryptoSm2CiphertextSpec *spec,
    CryptoSm2CiphertextSpec_item item, Crypto_DataBlob *in)
{
    if ((spec == NULL) || (in == NULL) || (in->data == NULL) || (in->len == 0)) {
        return CRYPTO_PARAMETER_CHECK_FAILED;
    }
    uint8_t *data = (uint8_t *)HcfMalloc(in->len, 0);
    if (data == NULL) {
        return CRYPTO_MEMORY_ERROR;
    }
    (void)memcpy_s(data, in->len, in->data, in->len);
    switch (item) {
        case CRYPTO_SM2_CIPHERTEXT_C1_X:
            HcfFree(spec->xCoordinate.data);
            spec->xCoordinate.data = data;
            spec->xCoordinate.len = in->len;
            break;
        case CRYPTO_SM2_CIPHERTEXT_C1_Y:
            HcfFree(spec->yCoordinate.data);
            spec->yCoordinate.data = data;
            spec->yCoordinate.len = in->len;
            break;
        case CRYPTO_SM2_CIPHERTEXT_C2:
            HcfFree(spec->cipherTextData.data);
            spec->cipherTextData.data = data;
            spec->cipherTextData.len = in->len;
            break;
        case CRYPTO_SM2_CIPHERTEXT_C3:
            HcfFree(spec->hashData.data);
            spec->hashData.data = data;
            spec->hashData.len = in->len;
            break;
        default:
            HcfFree(data);
            data = NULL;
            return CRYPTO_PARAMETER_CHECK_FAILED;
    }

    return CRYPTO_SUCCESS;
}

OH_Crypto_ErrCode OH_CryptoSm2CiphertextSpec_SetItem(OH_CryptoSm2CiphertextSpec *spec,
    CryptoSm2CiphertextSpec_item item, Crypto_DataBlob *in)
{
    return CryptoSm2CiphertextSpecSetItem(spec, item, in);
}

static OH_Crypto_ErrCode CryptoSm2CiphertextSpecEncode(OH_CryptoSm2CiphertextSpec *spec, Crypto_DataBlob *out)
{
    if ((spec == NULL) || (out == NULL)) {
        return CRYPTO_PARAMETER_CHECK_FAILED;
    }
    HcfResult ret = HcfGenCipherTextBySpec((Sm2CipherTextSpec *)spec, g_sm2ModeC1C3C2, (HcfBlob *)out);
    return GetOhCryptoErrCodeNew(ret);
}

OH_Crypto_ErrCode OH_CryptoSm2CiphertextSpec_Encode(OH_CryptoSm2CiphertextSpec *spec, Crypto_DataBlob *out)
{
    return CryptoSm2CiphertextSpecEncode(spec, out);
}

static void CryptoSm2CiphertextSpecDestroy(OH_CryptoSm2CiphertextSpec *spec)
{
    DestroySm2CipherTextSpec((Sm2CipherTextSpec *)spec);
}

void OH_CryptoSm2CiphertextSpec_Destroy(OH_CryptoSm2CiphertextSpec *spec)
{
    CryptoSm2CiphertextSpecDestroy(spec);
}
