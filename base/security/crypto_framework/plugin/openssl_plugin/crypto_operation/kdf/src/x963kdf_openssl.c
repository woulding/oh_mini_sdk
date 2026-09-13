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

#include "x963kdf_openssl.h"

#include "log.h"
#include "memory.h"
#include "result.h"
#include "securec.h"
#include "utils.h"
#include "openssl_adapter.h"
#include "openssl_common.h"
#include "openssl/kdf.h"
#include "detailed_x963kdf_params.h"

#define X963KDF_ALG_NAME "X963KDF"

typedef struct {
    unsigned char *key;
    int keyLen;
    unsigned char *info;
    int infoLen;
    unsigned char *out;
    int outLen;
} HcfX963KDFData;

typedef struct {
    HcfKdfSpi base;
    int digestAlg;
    HcfX963KDFData *kdfData;
} OpensslX963KDFSpiImpl;

static const char *EngineGetKdfClass(void)
{
    return "OpensslX963KDF";
}

static void HcfClearAndFree(unsigned char *buf, int bufLen)
{
    if (buf == NULL) {
        return;
    }
    (void)memset_s(buf, bufLen, 0, bufLen);
    HcfFree(buf);
}

static void FreeX963KDFData(HcfX963KDFData **data)
{
    if (data == NULL || *data == NULL) {
        return;
    }
    HcfClearAndFree((*data)->out, (*data)->outLen);
    (*data)->out = NULL;
    (*data)->outLen = 0;
    HcfClearAndFree((*data)->info, (*data)->infoLen);
    (*data)->info = NULL;
    (*data)->infoLen = 0;
    HcfClearAndFree((*data)->key, (*data)->keyLen);
    (*data)->key = NULL;
    (*data)->keyLen = 0;
    (void)memset_s(*data, sizeof(HcfX963KDFData), 0, sizeof(HcfX963KDFData));
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
    OpensslX963KDFSpiImpl *impl = (OpensslX963KDFSpiImpl *)self;
    FreeX963KDFData(&(impl->kdfData));
    HcfFree(self);
}

static bool CheckX963KDFParams(HcfX963KDFParamsSpec *params)
{
    // openssl only support INT and blob attribute is size_t, it should samller than INT_MAX.
    if (params->output.len > INT_MAX || params->key.len > INT_MAX ||
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
    if (params->info.data == NULL && params->info.len == 0) {
        LOGD("empty info");
    }
    return true;
}

static bool GetX963KDFKeyFromSpec(HcfX963KDFData *data, HcfX963KDFParamsSpec *params)
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

static bool GetX963KDFInfoFromSpec(OpensslX963KDFSpiImpl *self, HcfX963KDFData *data, HcfX963KDFParamsSpec *params)
{
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

static HcfResult InitX963KDFData(OpensslX963KDFSpiImpl *self, HcfX963KDFParamsSpec *params)
{
    HcfX963KDFData *data = (HcfX963KDFData *)HcfMalloc(sizeof(HcfX963KDFData), 0);
    do {
        if (data == NULL) {
            LOGE("malloc data failed");
            break;
        }
        if (!GetX963KDFKeyFromSpec(data, params)) {
            LOGE("malloc key failed!");
            break;
        }
        if (!GetX963KDFInfoFromSpec(self, data, params)) {
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
    FreeX963KDFData(&data);
    return HCF_ERR_MALLOC;
}

static HcfResult CheckX963KDFDigest(OpensslX963KDFSpiImpl *self)
{
    if (self->digestAlg == HCF_OPENSSL_DIGEST_MD5 || self->digestAlg == HCF_OPENSSL_DIGEST_SM3) {
        LOGE("MD5 and SM3 are not supported");
        return HCF_ERR_PARAMETER_CHECK_FAILED;
    }
    return HCF_SUCCESS;
}

static char *SwitchMd(OpensslX963KDFSpiImpl *self)
{
    switch (self->digestAlg) {
        case HCF_OPENSSL_DIGEST_NONE:
            return "";
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

static HcfResult OpensslX963KDF(OpensslX963KDFSpiImpl *self, HcfBlob *output)
{
    EVP_KDF *kdf = NULL;
    EVP_KDF_CTX *kctx = NULL;
    OSSL_PARAM params[4] = {};
    OSSL_PARAM *p = params;
    HcfResult res = CheckX963KDFDigest(self);
    if (res != HCF_SUCCESS) {
        LOGE("CheckX963KDFDigest failed");
        return res;
    }

    kdf = OpensslEvpKdfFetch(NULL, "X963KDF", NULL);
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

    char *digest = SwitchMd(self);
    *p++ = OpensslOsslParamConstructUtf8String("digest", digest, 0);
    *p++ = OpensslOsslParamConstructOctetString("key", self->kdfData->key, self->kdfData->keyLen);
    *p++ = OpensslOsslParamConstructOctetString("info", self->kdfData->info, self->kdfData->infoLen);
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
        return HCF_ERR_PARAMETER_CHECK_FAILED;
    }
    if (!HcfIsClassMatch((HcfObjectBase *)self, EngineGetKdfClass())) {
        return HCF_ERR_PARAMETER_CHECK_FAILED;
    }
    OpensslX963KDFSpiImpl *x963kdfImpl = (OpensslX963KDFSpiImpl *)self;
    if (paramsSpec->algName == NULL || strcmp(paramsSpec->algName, X963KDF_ALG_NAME) != 0) {
        LOGE("Not x963kdf paramsSpec");
        return HCF_ERR_PARAMETER_CHECK_FAILED;
    }
    HcfX963KDFParamsSpec *params = (HcfX963KDFParamsSpec *)paramsSpec;
    if (!CheckX963KDFParams(params)) {
        LOGE("params error");
        return HCF_ERR_PARAMETER_CHECK_FAILED;
    }
    HcfResult res = InitX963KDFData(x963kdfImpl, params);
    if (res != HCF_SUCCESS) {
        LOGE("InitX963KDFData failed!");
        return res;
    }
    res = OpensslX963KDF(x963kdfImpl, &params->output);
    FreeX963KDFData(&(x963kdfImpl->kdfData));
    return res;
}

HcfResult HcfKdfX963SpiCreate(HcfKdfDeriveParams *params, HcfKdfSpi **spiObj)
{
    if (params == NULL || spiObj == NULL) {
        LOGE("Invalid input parameter.");
        return HCF_ERR_PARAMETER_CHECK_FAILED;
    }
    OpensslX963KDFSpiImpl *returnSpiImpl = (OpensslX963KDFSpiImpl *)HcfMalloc(sizeof(OpensslX963KDFSpiImpl), 0);
    if (returnSpiImpl == NULL) {
        LOGE("Failed to allocate returnImpl memory!");
        return HCF_ERR_MALLOC;
    }
    returnSpiImpl->base.base.getClass = EngineGetKdfClass;
    returnSpiImpl->base.base.destroy = EngineDestroyKdf;
    returnSpiImpl->base.generateSecret = EngineGenerateSecret;
    returnSpiImpl->digestAlg = params->md;
    *spiObj = (HcfKdfSpi *)returnSpiImpl;
    return HCF_SUCCESS;
}
