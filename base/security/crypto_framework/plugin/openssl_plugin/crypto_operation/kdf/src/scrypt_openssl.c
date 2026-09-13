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

#include "scrypt_openssl.h"

#include "log.h"
#include "memory.h"
#include "result.h"
#include "securec.h"
#include "utils.h"
#include "openssl_adapter.h"
#include "openssl_common.h"
#include "openssl/kdf.h"
#include "detailed_scrypt_params.h"

#define SCRYPT_ALG_NAME "SCRYPT"

typedef struct {
    unsigned char *salt;
    int saltLen;
    unsigned char *password;
    int passwordLen;
    uint64_t n;
    uint64_t r;
    uint64_t p;
    uint64_t maxBytes;
    unsigned char *out;
    int outLen;
} HcfScryptData;

typedef struct {
    HcfKdfSpi base;
    HcfScryptData *kdfData;
} OpensslScryptSpiImpl;

static const char *EngineGetKdfClass(void)
{
    return "OpensslScrypt";
}

static void HcfClearAndFree(unsigned char *buf, int bufLen)
{
    // when buf == null, bufLen must be 0; in check func, bufLen >= 0
    if (buf == NULL) {
        return;
    }
    (void)memset_s(buf, bufLen, 0, bufLen);
    HcfFree(buf);
}

static void FreeScryptData(HcfScryptData **data)
{
    if (data == NULL || *data == NULL) {
        return;
    }
    HcfClearAndFree((*data)->out, (*data)->outLen);
    (*data)->out = NULL;
    (*data)->outLen = 0;
    HcfClearAndFree((*data)->salt, (*data)->saltLen);
    (*data)->salt = NULL;
    (*data)->saltLen = 0;
    HcfClearAndFree((*data)->password, (*data)->passwordLen);
    (*data)->password = NULL;
    (*data)->passwordLen = 0;
    (void)memset_s(*data, sizeof(HcfScryptData), 0, sizeof(HcfScryptData));
    HcfFree(*data);
    *data = NULL;
}

static void EngineDestroyKdf(HcfObjectBase *self)
{
    if (self == NULL) {
        LOGE("Self ptr is NULL!");
        return;
    }
    if (!HcfIsClassMatch(self, EngineGetKdfClass())) {
        LOGE("Class is not match.");
        return;
    }
    OpensslScryptSpiImpl *impl = (OpensslScryptSpiImpl *)self;
    FreeScryptData(&(impl->kdfData));
    HcfFree(self);
}

static bool CheckScryptParams(HcfScryptParamsSpec *params)
{
    // openssl only support INT and blob attribute is size_t, it should samller than INT_MAX.
    if (params->output.len > INT_MAX || params->salt.len > INT_MAX || params->passPhrase.len > INT_MAX) {
            LOGE("beyond the length");
            return false;
    }
    if (params->passPhrase.data == NULL && params->passPhrase.len == 0) {
        LOGE("check params failed, passPhrase is NULL");
        return false;
    }
    if (params->output.data == NULL || params->output.len == 0) {
        LOGE("check params failed, output data is NULL");
        return false;
    }
    if (params->salt.data == NULL && params->salt.len == 0) {
        LOGD("empty salt");
    }

    return true;
}

static bool GetScryptSaltFromSpec(HcfScryptData *data, HcfScryptParamsSpec *params)
{
    if (params->salt.len == 0) {
        LOGD("salt can be empty.");
        return true;
    }

    data->salt = (unsigned char *)HcfMalloc(params->salt.len, 0);
    if (data->salt == NULL) {
        LOGE("Malloc salt failed!");
        return false;
    }
    (void)memcpy_s(data->salt, params->salt.len, params->salt.data, params->salt.len);
    data->saltLen = (int)params->salt.len;
    return true;
}

static bool GetScryptPasswordFromSpec(HcfScryptData *data, HcfScryptParamsSpec *params)
{
    if (params->passPhrase.data != NULL && params->passPhrase.len != 0) {
        data->password = (unsigned char *)HcfMalloc(params->passPhrase.len, 0);
        if (data->password == NULL) {
            LOGE("Malloc password failed!");
            return false;
        }
        (void)memcpy_s(data->password, params->passPhrase.len, params->passPhrase.data, params->passPhrase.len);
        data->passwordLen = (int)params->passPhrase.len;
    } else {
        data->passwordLen = 0;
        data->password = NULL;
    }
    return true;
}

static HcfResult InitScryptData(OpensslScryptSpiImpl *self, HcfScryptParamsSpec *params)
{
    HcfScryptData *data = (HcfScryptData *)HcfMalloc(sizeof(HcfScryptData), 0);
    do {
        if (data == NULL) {
            LOGE("malloc data failed");
            break;
        }
        if (!GetScryptSaltFromSpec(data, params)) {
            LOGE("malloc salt failed!");
            break;
        }
        if (!GetScryptPasswordFromSpec(data, params)) {
            LOGE("malloc password failed!");
            break;
        }
        data->out = (unsigned char *)HcfMalloc(params->output.len, 0);
        if (data->out == NULL) {
            LOGE("malloc out failed!");
            break;
        }
        data->n = params->n;
        data->p = params->p;
        data->r = params->r;
        data->maxBytes = params->maxMem;
        data->outLen = (int)params->output.len;
        self->kdfData = data;
        return HCF_SUCCESS;
    } while (0);
    FreeScryptData(&data);
    return HCF_ERR_MALLOC;
}

static HcfResult OpensslScrypt(OpensslScryptSpiImpl *self, HcfBlob *output)
{
    EVP_KDF *kdf = NULL;
    EVP_KDF_CTX *kctx = NULL;
    // need set 7 params
    OSSL_PARAM params[7] = {};
    OSSL_PARAM *p = params;

    kdf = OpensslEvpKdfFetch(NULL, "SCRYPT", NULL);
    if (kdf == NULL) {
        LOGE("kdf fetch failed");
        return HCF_ERR_CRYPTO_OPERATION;
    }

    kctx = OpensslEvpKdfCtxNew(kdf);
    OpensslEvpKdfFree(kdf);
    if (kctx == NULL) {
        LOGE("kdf ctx new failed");
        return HCF_ERR_CRYPTO_OPERATION;
    }

    *p++ = OpensslOsslParamConstructOctetString("pass", self->kdfData->password, self->kdfData->passwordLen);
    *p++ = OpensslOsslParamConstructOctetString("salt", self->kdfData->salt, self->kdfData->saltLen);
    *p++ = OpensslOsslParamConstructUint64("n", &self->kdfData->n);
    *p++ = OpensslOsslParamConstructUint64("r", &self->kdfData->r);
    *p++ = OpensslOsslParamConstructUint64("p", &self->kdfData->p);
    *p++ = OpensslOsslParamConstructUint64("maxmem_bytes", &self->kdfData->maxBytes);
    *p = OpensslOsslParamConstructEnd();
    if (OpensslEvpKdfDerive(kctx, output->data, output->len, params) <= 0) {
        HcfPrintOpensslError();
        LOGE("EVP_KDF_derive failed");
        OpensslEvpKdfCtxFree(kctx);
        return HCF_ERR_CRYPTO_OPERATION;
    }
    LOGD("scrypt success");
    OpensslEvpKdfCtxFree(kctx);
    return HCF_SUCCESS;
}

static HcfResult EngineGenerateSecret(HcfKdfSpi *self, HcfKdfParamsSpec *paramsSpec)
{
    if (self == NULL || paramsSpec == NULL) {
        LOGE("Invalid input parameter.");
        return HCF_INVALID_PARAMS;
    }
    if (!HcfIsClassMatch((HcfObjectBase *)self, EngineGetKdfClass())) {
        return HCF_INVALID_PARAMS;
    }
    OpensslScryptSpiImpl *scryptImpl = (OpensslScryptSpiImpl *)self;
    if (paramsSpec->algName == NULL || strcmp(paramsSpec->algName, SCRYPT_ALG_NAME) != 0) {
        LOGE("Not scrypt paramsSpec");
        return HCF_INVALID_PARAMS;
    }
    HcfScryptParamsSpec *params = (HcfScryptParamsSpec *)paramsSpec;
    if (!CheckScryptParams(params)) {
        LOGE("params error");
        return HCF_INVALID_PARAMS;
    }
    HcfResult res = InitScryptData(scryptImpl, params);
    if (res != HCF_SUCCESS) {
        LOGE("Failed to initialize scrypt data.");
        return res;
    }
    res = OpensslScrypt(scryptImpl, &params->output);
    FreeScryptData(&(scryptImpl->kdfData));
    return res;
}

HcfResult HcfKdfScryptSpiCreate(HcfKdfDeriveParams *params, HcfKdfSpi **spiObj)
{
    if (params == NULL || spiObj == NULL) {
        LOGE("Invalid input parameter.");
        return HCF_INVALID_PARAMS;
    }
    OpensslScryptSpiImpl *returnSpiImpl = (OpensslScryptSpiImpl *)HcfMalloc(sizeof(OpensslScryptSpiImpl), 0);
    if (returnSpiImpl == NULL) {
        LOGE("Failed to allocate returnImpl memory!");
        return HCF_ERR_MALLOC;
    }
    returnSpiImpl->base.base.getClass = EngineGetKdfClass;
    returnSpiImpl->base.base.destroy = EngineDestroyKdf;
    returnSpiImpl->base.generateSecret = EngineGenerateSecret;
    *spiObj = (HcfKdfSpi *)returnSpiImpl;
    return HCF_SUCCESS;
}
