/*
 * Copyright (C) 2024 Huawei Device Co., Ltd.
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

#include "hkdf_openssl.h"

#include "log.h"
#include "memory.h"
#include "result.h"
#include "securec.h"
#include "utils.h"
#include "openssl_adapter.h"
#include "openssl_common.h"
#include "openssl/kdf.h"
#include "detailed_hkdf_params.h"

#define HKDF_ALG_NAME "HKDF"

typedef struct {
    unsigned char *salt;
    int saltLen;
    unsigned char *key;
    int keyLen;
    unsigned char *info;
    int infoLen;
    unsigned char *out;
    int outLen;
} HcfHkdfData;

typedef struct {
    HcfKdfSpi base;
    int digestAlg;
    int mode;
    HcfHkdfData *kdfData;
} OpensslHkdfSpiImpl;

static const char *EngineGetKdfClass(void)
{
    return "OpensslHkdf";
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

static void FreeHkdfData(HcfHkdfData **data)
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
    HcfClearAndFree((*data)->info, (*data)->infoLen);
    (*data)->info = NULL;
    (*data)->infoLen = 0;
    HcfClearAndFree((*data)->key, (*data)->keyLen);
    (*data)->key = NULL;
    (*data)->keyLen = 0;
    (void)memset_s(*data, sizeof(HcfHkdfData), 0, sizeof(HcfHkdfData));
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
    OpensslHkdfSpiImpl *impl = (OpensslHkdfSpiImpl *)self;
    FreeHkdfData(&(impl->kdfData));
    HcfFree(self);
}

static bool CheckHkdfParams(HcfHkdfParamsSpec *params)
{
    // openssl only support INT and blob attribute is size_t, it should samller than INT_MAX.
    if (params->output.len > INT_MAX || params->salt.len > INT_MAX || params->key.len > INT_MAX ||
        params->info.len > INT_MAX) {
            LOGE("beyond the length");
            return false;
    }
    if (params->key.data == NULL || params->key.len == 0) {
        LOGE("check params failed, key is NULL");
        return false;
    }
    if (params->output.data == NULL || params->output.len == 0) {
        LOGE("check params failed, output data is NULL");
        return false;
    }
    if (params->salt.data == NULL && params->salt.len == 0) {
        LOGD("empty salt");
    }
    if (params->info.data == NULL && params->info.len == 0) {
        LOGD("empty info");
    }
    return true;
}

static bool GetHkdfKeyFromSpec(HcfHkdfData *data, HcfHkdfParamsSpec *params)
{
    data->key = (unsigned char *)HcfMalloc(params->key.len, 0);
    if (data->key == NULL) {
        LOGE("Malloc key failed!");
        return false;
    }
    (void)memcpy_s(data->key, params->key.len, params->key.data, params->key.len);
    data->keyLen = params->key.len;
    return true;
}

static int GetHkdfMode(OpensslHkdfSpiImpl *self)
{
    switch (self->mode) {
        case HCF_ALG_MODE_EXTRACT_AND_EXPAND:
            return EVP_KDF_HKDF_MODE_EXTRACT_AND_EXPAND;
        case HCF_ALG_MODE_EXTRACT_ONLY:
            return EVP_KDF_HKDF_MODE_EXTRACT_ONLY;
        case HCF_ALG_MODE_EXPAND_ONLY:
            return EVP_KDF_HKDF_MODE_EXPAND_ONLY;
        default:
            return EVP_KDF_HKDF_MODE_EXTRACT_AND_EXPAND;
    }
}

static bool GetHkdfInfoFromSpec(OpensslHkdfSpiImpl *self, HcfHkdfData *data, HcfHkdfParamsSpec *params)
{
    if (self->mode == HCF_ALG_MODE_EXTRACT_ONLY) {
        LOGD("EXTRACT_ONLY mode does not require info");
        return true;
    }

    if (params->info.len == 0) {
        LOGD("info can be empty.");
        return true;
    }

    data->info = (unsigned char *)HcfMalloc(params->info.len, 0);
    if (data->info == NULL) {
        LOGE("Malloc info failed!");
        return false;
    }
    (void)memcpy_s(data->info, params->info.len, params->info.data, params->info.len);
    data->infoLen = params->info.len;
    return true;
}

static bool GetHkdfSaltFromSpec(OpensslHkdfSpiImpl *self, HcfHkdfData *data, HcfHkdfParamsSpec *params)
{
    if (self->mode == HCF_ALG_MODE_EXPAND_ONLY) {
        LOGD("EXPAND_ONLY mode does not require salt");
        return true;
    }

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
    data->saltLen = params->salt.len;
    return true;
}

static HcfResult InitHkdfData(OpensslHkdfSpiImpl *self, HcfHkdfParamsSpec *params)
{
    LOGD("MODE IS %{public}d", self->mode);
    HcfHkdfData *data = (HcfHkdfData *)HcfMalloc(sizeof(HcfHkdfData), 0);
    do {
        if (data == NULL) {
            LOGE("malloc data failed");
            break;
        }
        if (!GetHkdfKeyFromSpec(data, params)) {
            LOGE("malloc key failed!");
            break;
        }
        if (!GetHkdfSaltFromSpec(self, data, params)) {
            LOGE("malloc salt failed!");
            break;
        }
        if (!GetHkdfInfoFromSpec(self, data, params)) {
            LOGE("malloc info failed!");
            break;
        }
        data->out = (unsigned char *)HcfMalloc(params->output.len, 0);
        if (data->out == NULL) {
            LOGE("malloc out failed!");
            break;
        }
        data->outLen = params->output.len;
        self->kdfData = data;
        return HCF_SUCCESS;
    } while (0);
    FreeHkdfData(&data);
    return HCF_ERR_MALLOC;
}

static char *SwitchMd(OpensslHkdfSpiImpl *self)
{
    switch (self->digestAlg) {
        case HCF_OPENSSL_DIGEST_NONE:
            return "";
        case HCF_OPENSSL_DIGEST_MD5:
            return "MD5";
        case HCF_OPENSSL_DIGEST_SM3:
            return "SM3";
        case HCF_OPENSSL_DIGEST_SHA1:
            return "SHA1";
        case HCF_OPENSSL_DIGEST_SHA224:
            return "SHA224";
        case HCF_OPENSSL_DIGEST_SHA256:
            return "SHA256";
        case HCF_OPENSSL_DIGEST_SHA384:
            return "SHA384";
        case HCF_OPENSSL_DIGEST_SHA512:
            return "SHA512";
        case HCF_OPENSSL_DIGEST_SHA3_256:
            return "SHA3-256";
        case HCF_OPENSSL_DIGEST_SHA3_384:
            return "SHA3-384";
        case HCF_OPENSSL_DIGEST_SHA3_512:
            return "SHA3-512";
        default:
            LOGE("Unsupport digest alg.");
            return "";
    }
}

static HcfResult OpensslHkdf(OpensslHkdfSpiImpl *self, HcfBlob *output)
{
    EVP_KDF *kdf = NULL;
    EVP_KDF_CTX *kctx = NULL;
    // need set 6 params
    OSSL_PARAM params[6] = {};
    OSSL_PARAM *p = params;

    kdf = OpensslEvpKdfFetch(NULL, "HKDF", NULL);
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

    int mode = GetHkdfMode(self);
    char *digest = SwitchMd(self);
    *p++ = OpensslOsslParamConstructUtf8String("digest", digest, 0);
    *p++ = OpensslOsslParamConstructOctetString("key", self->kdfData->key, self->kdfData->keyLen);
    *p++ = OpensslOsslParamConstructOctetString("info", self->kdfData->info, self->kdfData->infoLen);
    *p++ = OpensslOsslParamConstructOctetString("salt", self->kdfData->salt, self->kdfData->saltLen);
    *p++ = OpensslOsslParamConstructInt("mode", &mode);
    *p = OpensslOsslParamConstructEnd();
    if (OpensslEvpKdfDerive(kctx, output->data, output->len, params) <= 0) {
        HcfPrintOpensslError();
        LOGE("EVP_KDF_derive failed");
        OpensslEvpKdfCtxFree(kctx);
        return HCF_ERR_CRYPTO_OPERATION;
    }
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
    OpensslHkdfSpiImpl *hkdfImpl = (OpensslHkdfSpiImpl *)self;
    if (paramsSpec->algName == NULL || strcmp(paramsSpec->algName, HKDF_ALG_NAME) != 0) {
        LOGE("Not hkdf paramsSpec");
        return HCF_INVALID_PARAMS;
    }
    HcfHkdfParamsSpec *params = (HcfHkdfParamsSpec *)paramsSpec;
    if (!CheckHkdfParams(params)) {
        LOGE("params error");
        return HCF_INVALID_PARAMS;
    }
    HcfResult res = InitHkdfData(hkdfImpl, params);
    if (res != HCF_SUCCESS) {
        LOGE("Failed to initialize HKDF data.");
        return res;
    }
    res = OpensslHkdf(hkdfImpl, &params->output);
    FreeHkdfData(&(hkdfImpl->kdfData));
    return res;
}

HcfResult HcfKdfHkdfSpiCreate(HcfKdfDeriveParams *params, HcfKdfSpi **spiObj)
{
    if (params == NULL || spiObj == NULL) {
        LOGE("Invalid input parameter.");
        return HCF_INVALID_PARAMS;
    }
    OpensslHkdfSpiImpl *returnSpiImpl = (OpensslHkdfSpiImpl *)HcfMalloc(sizeof(OpensslHkdfSpiImpl), 0);
    if (returnSpiImpl == NULL) {
        LOGE("Failed to allocate returnImpl memory!");
        return HCF_ERR_MALLOC;
    }
    returnSpiImpl->base.base.getClass = EngineGetKdfClass;
    returnSpiImpl->base.base.destroy = EngineDestroyKdf;
    returnSpiImpl->base.generateSecret = EngineGenerateSecret;
    returnSpiImpl->digestAlg = params->md;
    returnSpiImpl->mode = params->mode;
    *spiObj = (HcfKdfSpi *)returnSpiImpl;
    return HCF_SUCCESS;
}
