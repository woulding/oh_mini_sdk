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

#include "pbkdf2_openssl.h"

#include "log.h"
#include "memory.h"
#include "result.h"
#include "securec.h"
#include "utils.h"
#include "openssl_adapter.h"
#include "openssl_common.h"
#include "detailed_pbkdf2_params.h"

#define PBKDF2_ALG_NAME "PBKDF2"

typedef struct {
    unsigned char *password;
    int passwordLen;
    int iter;
    unsigned char *salt;
    int saltLen;
    unsigned char *out;
    int outLen;
} HcfKdfData;

typedef struct {
    HcfKdfSpi base;
    const EVP_MD *digestAlg;
    HcfKdfData *kdfData;
} OpensslKdfSpiImpl;

static const char *EngineGetKdfClass(void)
{
    return "OpensslKdf";
}

static void HcfClearAndFreeUnsignedChar(unsigned char *blob, int len)
{
    // when blob == null, len must be 0; in check func, len >= 0
    if (blob == NULL) {
        LOGD("The input blob is null, no need to free.");
        return;
    }
    (void)memset_s(blob, len, 0, len);
    HcfFree(blob);
}

static void FreeKdfData(HcfKdfData **data)
{
    if (data == NULL || *data == NULL) {
        return;
    }
    if ((*data)->out != NULL) {
        HcfClearAndFreeUnsignedChar((*data)->out, (*data)->outLen);
        (*data)->out = NULL;
        (*data)->outLen = 0;
    }
    if ((*data)->salt != NULL) {
        HcfClearAndFreeUnsignedChar((*data)->salt, (*data)->saltLen);
        (*data)->salt = NULL;
        (*data)->saltLen = 0;
    }
    if ((*data)->password != NULL) {
        HcfClearAndFreeUnsignedChar((*data)->password, (*data)->passwordLen);
        (*data)->password = NULL;
        (*data)->passwordLen = 0;
    }
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
    OpensslKdfSpiImpl *impl = (OpensslKdfSpiImpl *)self;
    FreeKdfData(&(impl->kdfData));
    impl->digestAlg = NULL;
    HcfFree(self);
}

static bool CheckPBKDF2Params(HcfPBKDF2ParamsSpec *params)
{
    if (params->iterations < 1) {
        LOGE("invalid kdf iter");
        return false;
    }
    // openssl only support INT and blob attribute is size_t, it should samller than INT_MAX.
    if (params->output.len > INT_MAX || params->salt.len > INT_MAX || params->password.len > INT_MAX) {
        LOGE("beyond the length");
        return false;
    }
    // when params password == nullptr, the size will be set 0 by openssl;
    if (params->output.data == NULL || params->output.len == 0) {
        LOGE("invalid output");
        return false;
    }
    if (params->salt.data == NULL && params->salt.len == 0) {
        LOGD("empty salt");
        return true;
    }
    if (params->salt.data != NULL && params->salt.len != 0) {
        return true;
    }
    LOGE("Invalid salt params");
    return false;
}

static bool GetPBKDF2PasswordFromSpec(HcfKdfData *data, HcfPBKDF2ParamsSpec *params)
{
    if (params->password.data != NULL && params->password.len != 0) {
        data->password = (unsigned char *)HcfMalloc(params->password.len, 0);
        if (data->password == NULL) {
            LOGE("Malloc password failed!");
            return false;
        }
        (void)memcpy_s(data->password, params->password.len, params->password.data, params->password.len);
        data->passwordLen = params->password.len;
    } else {
        data->passwordLen = 0;
        data->password = NULL;
    }
    return true;
}

static bool GetPBKDF2SaltFromSpec(HcfKdfData *data, HcfPBKDF2ParamsSpec *params)
{
    if (params->salt.data != NULL) {
        data->salt = (unsigned char *)HcfMalloc(params->salt.len, 0);
        if (data->salt == NULL) {
            LOGE("Malloc salt failed!");
            return false;
        }
        (void)memcpy_s(data->salt, params->salt.len, params->salt.data, params->salt.len);
        data->saltLen = params->salt.len;
    } else {
        data->salt = NULL;
        data->saltLen = 0;
    }
    return true;
}


static HcfResult InitPBKDF2Data(OpensslKdfSpiImpl *self, HcfPBKDF2ParamsSpec *params)
{
    HcfKdfData *data = (HcfKdfData *)HcfMalloc(sizeof(HcfKdfData), 0);
    do {
        if (data == NULL) {
            LOGE("malloc data failed");
            break;
        }
        if (!GetPBKDF2PasswordFromSpec(data, params)) {
            LOGE("password malloc failed!");
            break;
        }
        if (!GetPBKDF2SaltFromSpec(data, params)) {
            LOGE("salt malloc failed!");
            break;
        }
        data->out = (unsigned char *)HcfMalloc(params->output.len, 0);
        if (data->out == NULL) {
            LOGE("out malloc failed!");
            break;
        }
        data->outLen = params->output.len;
        data->iter = params->iterations;
        self->kdfData = data;
        return HCF_SUCCESS;
    } while (0);
    FreeKdfData(&data);
    return HCF_ERR_MALLOC;
}

static HcfResult OpensslPBKDF2(OpensslKdfSpiImpl *self, HcfPBKDF2ParamsSpec *params)
{
    HcfKdfData *data = self->kdfData;
    if (OpensslPkcs5Pbkdf2Hmac((char *)(data->password), data->passwordLen,
        data->salt, data->saltLen, data->iter, self->digestAlg, data->outLen, data->out) != HCF_OPENSSL_SUCCESS) {
        HcfPrintOpensslError();
        LOGE("Pbkdf2 openssl failed!");
        return HCF_ERR_CRYPTO_OPERATION;
    }
    (void)memcpy_s(params->output.data, data->outLen, data->out, data->outLen);
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
    OpensslKdfSpiImpl *pbkdf2Impl = (OpensslKdfSpiImpl *)self;
    if (paramsSpec->algName == NULL || strcmp(paramsSpec->algName, PBKDF2_ALG_NAME) != 0) {
        LOGE("Not pbkdf2 paramsSpec");
        return HCF_INVALID_PARAMS;
    }
    HcfPBKDF2ParamsSpec *params = (HcfPBKDF2ParamsSpec *)paramsSpec;
    if (!CheckPBKDF2Params(params)) {
        LOGE("params error");
        return HCF_INVALID_PARAMS;
    }
    HcfResult res = InitPBKDF2Data(pbkdf2Impl, params);
    if (res != HCF_SUCCESS) {
        LOGE("InitPBKDF2Data failed!");
        return HCF_INVALID_PARAMS;
    }
    res = OpensslPBKDF2(pbkdf2Impl, params);
    FreeKdfData(&(pbkdf2Impl->kdfData));
    return res;
}

HcfResult HcfKdfPBKDF2SpiCreate(HcfKdfDeriveParams *params, HcfKdfSpi **spiObj)
{
    if (params == NULL || spiObj == NULL) {
        LOGE("Invalid input parameter.");
        return HCF_INVALID_PARAMS;
    }
    EVP_MD *md = NULL;
    HcfResult res = GetOpensslDigestAlg(params->md, &md);
    if (res != HCF_SUCCESS || md == NULL) {
        LOGE("get md failed");
        return HCF_INVALID_PARAMS;
    }
    OpensslKdfSpiImpl *returnSpiImpl = (OpensslKdfSpiImpl *)HcfMalloc(sizeof(OpensslKdfSpiImpl), 0);
    if (returnSpiImpl == NULL) {
        LOGE("Failed to allocate returnImpl memory!");
        return HCF_ERR_MALLOC;
    }
    returnSpiImpl->base.base.getClass = EngineGetKdfClass;
    returnSpiImpl->base.base.destroy = EngineDestroyKdf;
    returnSpiImpl->base.generateSecret = EngineGenerateSecret;
    returnSpiImpl->digestAlg = md;
    *spiObj = (HcfKdfSpi *)returnSpiImpl;
    return HCF_SUCCESS;
}