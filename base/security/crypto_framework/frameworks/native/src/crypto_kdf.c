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

#include "crypto_kdf.h"
#include <stdlib.h>
#include <string.h>
#include <securec.h>
#include "crypto_common.h"
#include "native_common.h"
#include "memory.h"
#include "kdf.h"
#include "kdf_params.h"
#include "detailed_hkdf_params.h"
#include "detailed_pbkdf2_params.h"
#include "detailed_scrypt_params.h"
#include "detailed_x963kdf_params.h"

typedef struct OH_CryptoKdf {
    HcfObjectBase base;

    const char *(*getAlgorithm)(HcfKdf *self);

    HcfResult (*generateSecret)(HcfKdf *self, HcfKdfParamsSpec* paramsSpec);
} OH_CryptoKdf;


typedef struct OH_CryptoKdfParams {
    const char *algName;
} OH_CryptoKdfParams;

static const char *g_hkdfName = "HKDF";
static const char *g_pbkdf2Name = "PBKDF2";
static const char *g_scryptName = "SCRYPT";
static const char *g_x963kdfName = "X963KDF";

static OH_Crypto_ErrCode CryptoKdfParamsCreate(const char *algoName, OH_CryptoKdfParams **params)
{
    if ((algoName == NULL) || (params == NULL)) {
        return CRYPTO_PARAMETER_CHECK_FAILED;
    }

    OH_CryptoKdfParams *tmParams = NULL;
    const char *algName = NULL;
    if (strcmp(algoName, g_hkdfName) == 0) {
        tmParams = (OH_CryptoKdfParams *)HcfMalloc(sizeof(HcfHkdfParamsSpec), 0);
        algName = g_hkdfName;
    } else if (strcmp(algoName, g_pbkdf2Name) == 0) {
        tmParams = (OH_CryptoKdfParams *)HcfMalloc(sizeof(HcfPBKDF2ParamsSpec), 0);
        algName = g_pbkdf2Name;
    } else if (strcmp(algoName, g_scryptName) == 0) {
        tmParams = (OH_CryptoKdfParams *)HcfMalloc(sizeof(HcfScryptParamsSpec), 0);
        algName = g_scryptName;
    } else if (strcmp(algoName, g_x963kdfName) == 0) {
        tmParams = (OH_CryptoKdfParams *)HcfMalloc(sizeof(HcfX963KDFParamsSpec), 0);
        algName = g_x963kdfName;
    } else {
        return CRYPTO_PARAMETER_CHECK_FAILED;
    }
    if (tmParams == NULL) {
        return CRYPTO_MEMORY_ERROR;
    }
    tmParams->algName = algName;
    *params = tmParams;
    return CRYPTO_SUCCESS;
}

OH_Crypto_ErrCode OH_CryptoKdfParams_Create(const char *algoName, OH_CryptoKdfParams **params)
{
    return CryptoKdfParamsCreate(algoName, params);
}

static OH_Crypto_ErrCode SetHkdfParam(HcfHkdfParamsSpec *params, CryptoKdf_ParamType type, Crypto_DataBlob *value)
{
    if (value->len > UINT32_MAX) {
        return CRYPTO_PARAMETER_CHECK_FAILED;
    }
    uint8_t *data = (uint8_t *)HcfMalloc(value->len, 0);
    if (data == NULL) {
        return CRYPTO_MEMORY_ERROR;
    }
    (void)memcpy_s(data, value->len, value->data, value->len);
    switch (type) {
        case CRYPTO_KDF_KEY_DATABLOB:
            HcfBlobDataClearAndFree(&(params->key));
            params->key.data = data;
            params->key.len = value->len;
            break;
        case CRYPTO_KDF_SALT_DATABLOB:
            HcfBlobDataClearAndFree(&(params->salt));
            params->salt.data = data;
            params->salt.len = value->len;
            break;
        case CRYPTO_KDF_INFO_DATABLOB:
            HcfBlobDataClearAndFree(&(params->info));
            params->info.data = data;
            params->info.len = value->len;
            break;
        default:
            HcfFree(data);
            data = NULL;
            return CRYPTO_PARAMETER_CHECK_FAILED;
    }
    return CRYPTO_SUCCESS;
}

static OH_Crypto_ErrCode SetPbkdf2Param(HcfPBKDF2ParamsSpec *params, CryptoKdf_ParamType type, Crypto_DataBlob *value)
{
    switch (type) {
        case CRYPTO_KDF_KEY_DATABLOB: {
            if (value->len > UINT32_MAX) {
                return CRYPTO_PARAMETER_CHECK_FAILED;
            }
            uint8_t *data = (uint8_t *)HcfMalloc(value->len, 0);
            if (data == NULL) {
                return CRYPTO_MEMORY_ERROR;
            }
            (void)memcpy_s(data, value->len, value->data, value->len);
            HcfBlobDataClearAndFree(&(params->password));
            params->password.data = data;
            params->password.len = value->len;
            break;
        }
        case CRYPTO_KDF_SALT_DATABLOB: {
            if (value->len > UINT32_MAX) {
                return CRYPTO_PARAMETER_CHECK_FAILED;
            }
            uint8_t *data = (uint8_t *)HcfMalloc(value->len, 0);
            if (data == NULL) {
                return CRYPTO_MEMORY_ERROR;
            }
            (void)memcpy_s(data, value->len, value->data, value->len);
            HcfBlobDataClearAndFree(&(params->salt));
            params->salt.data = data;
            params->salt.len = value->len;
            break;
        }
        case CRYPTO_KDF_ITER_COUNT_INT: {
            if (value->len != sizeof(int)) {
                return CRYPTO_PARAMETER_CHECK_FAILED;
            }
            params->iterations = *(int *)(value->data);
            break;
        }
        default:
            return CRYPTO_PARAMETER_CHECK_FAILED;
    }
    return CRYPTO_SUCCESS;
}

static OH_Crypto_ErrCode SetScryptKeyParam(HcfScryptParamsSpec *params, Crypto_DataBlob *value)
{
    if (value->len > UINT32_MAX) {
        return CRYPTO_PARAMETER_CHECK_FAILED;
    }
    uint8_t *data = (uint8_t *)HcfMalloc(value->len, 0);
    if (data == NULL) {
        return CRYPTO_MEMORY_ERROR;
    }
    (void)memcpy_s(data, value->len, value->data, value->len);
    HcfBlobDataClearAndFree(&(params->passPhrase));
    params->passPhrase.data = data;
    params->passPhrase.len = value->len;
    return CRYPTO_SUCCESS;
}

static OH_Crypto_ErrCode SetScryptSaltParam(HcfScryptParamsSpec *params, Crypto_DataBlob *value)
{
    if (value->len > UINT32_MAX) {
        return CRYPTO_PARAMETER_CHECK_FAILED;
    }
    uint8_t *data = (uint8_t *)HcfMalloc(value->len, 0);
    if (data == NULL) {
        return CRYPTO_MEMORY_ERROR;
    }
    (void)memcpy_s(data, value->len, value->data, value->len);
    HcfBlobDataClearAndFree(&(params->salt));
    params->salt.data = data;
    params->salt.len = value->len;
    return CRYPTO_SUCCESS;
}

static OH_Crypto_ErrCode SetScryptUint64Param(HcfScryptParamsSpec *params, Crypto_DataBlob *value, uint64_t *target)
{
    if (value->len != sizeof(uint64_t)) {
        return CRYPTO_PARAMETER_CHECK_FAILED;
    }
    *target = *(uint64_t *)(value->data);
    return CRYPTO_SUCCESS;
}

static OH_Crypto_ErrCode SetScryptParam(HcfScryptParamsSpec *params, CryptoKdf_ParamType type, Crypto_DataBlob *value)
{
    switch (type) {
        case CRYPTO_KDF_KEY_DATABLOB:
            return SetScryptKeyParam(params, value);
        case CRYPTO_KDF_SALT_DATABLOB:
            return SetScryptSaltParam(params, value);
        case CRYPTO_KDF_SCRYPT_N_UINT64:
            return SetScryptUint64Param(params, value, &params->n);
        case CRYPTO_KDF_SCRYPT_R_UINT64:
            return SetScryptUint64Param(params, value, &params->r);
        case CRYPTO_KDF_SCRYPT_P_UINT64:
            return SetScryptUint64Param(params, value, &params->p);
        case CRYPTO_KDF_SCRYPT_MAX_MEM_UINT64:
            return SetScryptUint64Param(params, value, &params->maxMem);
        default:
            return CRYPTO_PARAMETER_CHECK_FAILED;
    }
}

static OH_Crypto_ErrCode SetX963KDFParam(HcfX963KDFParamsSpec *params, CryptoKdf_ParamType type, Crypto_DataBlob *value)
{
    if (value->len > UINT32_MAX) {
        return CRYPTO_PARAMETER_CHECK_FAILED;
    }
    uint8_t *data = (uint8_t *)HcfMalloc(value->len, 0);
    if (data == NULL) {
        return CRYPTO_MEMORY_ERROR;
    }
    (void)memcpy_s(data, value->len, value->data, value->len);
    switch (type) {
        case CRYPTO_KDF_KEY_DATABLOB:
            HcfBlobDataClearAndFree(&(params->key));
            params->key.data = data;
            params->key.len = value->len;
            break;
        case CRYPTO_KDF_INFO_DATABLOB:
            HcfBlobDataClearAndFree(&(params->info));
            params->info.data = data;
            params->info.len = value->len;
            break;
        default:
            HcfFree(data);
            data = NULL;
            return CRYPTO_PARAMETER_CHECK_FAILED;
    }
    return CRYPTO_SUCCESS;
}

static OH_Crypto_ErrCode CryptoKdfParamsSetParam(OH_CryptoKdfParams *params, CryptoKdf_ParamType type,
    Crypto_DataBlob *value)
{
    if ((params == NULL) || (params->algName == NULL) || (value == NULL) || (value->data == NULL)) {
        return CRYPTO_PARAMETER_CHECK_FAILED;
    }
    if (strcmp(params->algName, g_hkdfName) == 0) {
        return SetHkdfParam((HcfHkdfParamsSpec*)params, type, value);
    } else if (strcmp(params->algName, g_pbkdf2Name) == 0) {
        return SetPbkdf2Param((HcfPBKDF2ParamsSpec*)params, type, value);
    } else if (strcmp(params->algName, g_scryptName) == 0) {
        return SetScryptParam((HcfScryptParamsSpec*)params, type, value);
    } else if (strcmp(params->algName, g_x963kdfName) == 0) {
        return SetX963KDFParam((HcfX963KDFParamsSpec*)params, type, value);
    } else {
        return CRYPTO_PARAMETER_CHECK_FAILED;
    }
}

OH_Crypto_ErrCode OH_CryptoKdfParams_SetParam(OH_CryptoKdfParams *params, CryptoKdf_ParamType type,
    Crypto_DataBlob *value)
{
    return CryptoKdfParamsSetParam(params, type, value);
}

static void FreeHkdfParamSpec(HcfHkdfParamsSpec *params)
{
    HcfBlobDataClearAndFree(&(params->key));
    HcfBlobDataClearAndFree(&(params->salt));
    HcfBlobDataClearAndFree(&(params->info));
    HcfBlobDataClearAndFree(&(params->output));
}

static void FreePbkdf2ParamSpec(HcfPBKDF2ParamsSpec *params)
{
    HcfBlobDataClearAndFree(&(params->password));
    HcfBlobDataClearAndFree(&(params->salt));
    HcfBlobDataClearAndFree(&(params->output));
}

static void FreeScryptParamSpec(HcfScryptParamsSpec *params)
{
    HcfBlobDataClearAndFree(&(params->passPhrase));
    HcfBlobDataClearAndFree(&(params->salt));
    HcfBlobDataClearAndFree(&(params->output));
}

static void FreeX963KDFParamSpec(HcfX963KDFParamsSpec *params)
{
    HcfBlobDataClearAndFree(&(params->key));
    HcfBlobDataClearAndFree(&(params->info));
    HcfBlobDataClearAndFree(&(params->output));
}

static void FreeParamSpec(OH_CryptoKdfParams *params)
{
    if (params->algName == NULL) {
        return;
    }
    if (strcmp(params->algName, g_hkdfName) == 0) {
        FreeHkdfParamSpec((HcfHkdfParamsSpec*)params);
    } else if (strcmp(params->algName, g_pbkdf2Name) == 0) {
        FreePbkdf2ParamSpec((HcfPBKDF2ParamsSpec*)params);
    } else if (strcmp(params->algName, g_scryptName) == 0) {
        FreeScryptParamSpec((HcfScryptParamsSpec*)params);
    } else if (strcmp(params->algName, g_x963kdfName) == 0) {
        FreeX963KDFParamSpec((HcfX963KDFParamsSpec*)params);
    }
}

static void CryptoKdfParamsDestroy(OH_CryptoKdfParams *params)
{
    if (params == NULL) {
        return;
    }
    FreeParamSpec(params);
    params->algName = NULL;
    HcfFree(params);
}

void OH_CryptoKdfParams_Destroy(OH_CryptoKdfParams *params)
{
    CryptoKdfParamsDestroy(params);
}

static OH_Crypto_ErrCode CryptoKdfCreate(const char *algoName, OH_CryptoKdf **ctx)
{
    if ((algoName == NULL) || (ctx == NULL)) {
        return CRYPTO_PARAMETER_CHECK_FAILED;
    }
    HcfResult ret = HcfKdfCreate(algoName, (HcfKdf **)ctx);
    return GetOhCryptoErrCodeNew(ret);
}

OH_Crypto_ErrCode OH_CryptoKdf_Create(const char *algoName, OH_CryptoKdf **ctx)
{
    return CryptoKdfCreate(algoName, ctx);
}

static OH_Crypto_ErrCode HkdfDerive(HcfKdf *ctx, const HcfHkdfParamsSpec *params, uint32_t keyLen, HcfBlob *key)
{
    uint8_t *out = (uint8_t *)HcfMalloc(keyLen, 0);
    if (out == NULL) {
        return CRYPTO_MEMORY_ERROR;
    }
    HcfBlob output = {.data = out, .len = keyLen};
    HcfHkdfParamsSpec hkdfParams = {
        .base = { .algName = g_hkdfName, },
        .key = params->key,
        .salt = params->salt,
        .info = params->info,
        .output = output,
    };
    HcfResult ret = ctx->generateSecret(ctx, &(hkdfParams.base));
    if (ret != HCF_SUCCESS) {
        HcfBlobDataClearAndFree(&output);
        return GetOhCryptoErrCodeNew(ret);
    }
    key->data = hkdfParams.output.data;
    key->len = hkdfParams.output.len;
    return CRYPTO_SUCCESS;
}

static OH_Crypto_ErrCode Pbkdf2Derive(HcfKdf *ctx, const HcfPBKDF2ParamsSpec *params, uint32_t keyLen, HcfBlob *key)
{
    uint8_t *out = (uint8_t *)HcfMalloc(keyLen, 0);
    if (out == NULL) {
        return CRYPTO_MEMORY_ERROR;
    }
    HcfBlob output = {.data = out, .len = keyLen};
    HcfPBKDF2ParamsSpec pbkdf2Params = {
        .base = { .algName = g_pbkdf2Name, },
        .password = params->password,
        .salt = params->salt,
        .iterations = params->iterations,
        .output = output,
    };
    HcfResult ret = ctx->generateSecret(ctx, &(pbkdf2Params.base));
    if (ret != HCF_SUCCESS) {
        HcfBlobDataClearAndFree(&output);
        return GetOhCryptoErrCodeNew(ret);
    }
    key->data = pbkdf2Params.output.data;
    key->len = pbkdf2Params.output.len;
    return CRYPTO_SUCCESS;
}

static OH_Crypto_ErrCode ScryptDerive(HcfKdf *ctx, const HcfScryptParamsSpec *params, uint32_t keyLen, HcfBlob *key)
{
    uint8_t *out = (uint8_t *)HcfMalloc(keyLen, 0);
    if (out == NULL) {
        return CRYPTO_MEMORY_ERROR;
    }
    HcfBlob output = {.data = out, .len = keyLen};
    HcfScryptParamsSpec scryptParams = {
        .base = { .algName = g_scryptName, },
        .passPhrase = params->passPhrase,
        .salt = params->salt,
        .n = params->n,
        .p = params->p,
        .r = params->r,
        .maxMem = params->maxMem,
        .output = output,
    };
    HcfResult ret = ctx->generateSecret(ctx, &(scryptParams.base));
    if (ret != HCF_SUCCESS) {
        HcfBlobDataClearAndFree(&output);
        return GetOhCryptoErrCodeNew(ret);
    }
    key->data = scryptParams.output.data;
    key->len = scryptParams.output.len;
    return CRYPTO_SUCCESS;
}

static OH_Crypto_ErrCode X963KDFDerive(HcfKdf *ctx, const HcfX963KDFParamsSpec *params, uint32_t keyLen, HcfBlob *key)
{
    if (keyLen <= 0 || keyLen > X963KDF_MAX_KEY_SIZE) {
        return CRYPTO_PARAMETER_CHECK_FAILED;
    }
    uint8_t *out = (uint8_t *)HcfMalloc(keyLen, 0);
    if (out == NULL) {
        return CRYPTO_MEMORY_ERROR;
    }
    HcfBlob output = {.data = out, .len = keyLen};
    HcfX963KDFParamsSpec x963kdfParams = {
        .base = { .algName = g_x963kdfName, },
        .key = params->key,
        .info = params->info,
        .output = output,
    };
    HcfResult ret = ctx->generateSecret(ctx, &(x963kdfParams.base));
    if (ret != HCF_SUCCESS) {
        HcfBlobDataClearAndFree(&output);
        return GetOhCryptoErrCodeNew(ret);
    }
    key->data = x963kdfParams.output.data;
    key->len = x963kdfParams.output.len;
    return CRYPTO_SUCCESS;
}

static OH_Crypto_ErrCode CryptoKdfDerive(OH_CryptoKdf *ctx, const OH_CryptoKdfParams *params, int keyLen,
    Crypto_DataBlob *key)
{
    if ((ctx == NULL) || (params == NULL) || (params->algName == NULL) || (key == NULL) || (keyLen <= 0)) {
        return CRYPTO_PARAMETER_CHECK_FAILED;
    }

    if (strcmp(params->algName, g_hkdfName) == 0) {
        return HkdfDerive((HcfKdf *)ctx, (HcfHkdfParamsSpec *)params, (uint32_t)keyLen, (HcfBlob *)key);
    } else if (strcmp(params->algName, g_pbkdf2Name) == 0) {
        return Pbkdf2Derive((HcfKdf *)ctx, (HcfPBKDF2ParamsSpec*)params, (uint32_t)keyLen, (HcfBlob *)key);
    } else if (strcmp(params->algName, g_scryptName) == 0) {
        return ScryptDerive((HcfKdf *)ctx, (HcfScryptParamsSpec*)params, (uint32_t)keyLen, (HcfBlob *)key);
    } else if (strcmp(params->algName, g_x963kdfName) == 0) {
        return X963KDFDerive((HcfKdf *)ctx, (HcfX963KDFParamsSpec*)params, (uint32_t)keyLen, (HcfBlob *)key);
    } else {
        return CRYPTO_PARAMETER_CHECK_FAILED;
    }
}

OH_Crypto_ErrCode OH_CryptoKdf_Derive(OH_CryptoKdf *ctx, const OH_CryptoKdfParams *params, int keyLen,
    Crypto_DataBlob *key)
{
    return CryptoKdfDerive(ctx, params, keyLen, key);
}

static void CryptoKdfDestroy(OH_CryptoKdf *ctx)
{
    HcfObjDestroy((HcfKdf *)ctx);
}

void OH_CryptoKdf_Destroy(OH_CryptoKdf *ctx)
{
    CryptoKdfDestroy(ctx);
}
