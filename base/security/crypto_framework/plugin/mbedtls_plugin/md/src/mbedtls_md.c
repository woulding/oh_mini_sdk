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

#include "mbedtls_md.h"

#include "mbedtls_common.h"
#include "mbedtls/md.h"
#include "securec.h"
#include "log.h"
#include "memory.h"
#include "config.h"
#include "utils.h"

typedef struct {
    HcfMdSpi base;
    mbedtls_md_context_t *ctx;
    char mbedtlsAlgoName[HCF_MAX_ALGO_NAME_LEN];
} MbedtlsMdSpiImpl;

mbedtls_md_context_t *MbedtlsEvpMdCtxNew(void)
{
    return (mbedtls_md_context_t *)HcfMalloc(sizeof(mbedtls_md_context_t), 0);
}

void MbedtlsEvpMdCtxFree(mbedtls_md_context_t *ctx)
{
    HcfFree(ctx);
}

static const char *MbedtlsGetMdClass(void)
{
    return "MbedtlsMd";
}

static mbedtls_md_context_t *MbedtlsGetMdCtx(HcfMdSpi *self)
{
    if (!HcfIsClassMatch((HcfObjectBase *)self, MbedtlsGetMdClass())) {
        LOGE("Class is not match.");
        return NULL;
    }

    return ((MbedtlsMdSpiImpl *)self)->ctx;
}

static HcfResult MbedtlsEngineUpdateMd(HcfMdSpi *self, HcfBlob *input)
{
    mbedtls_md_context_t *ctx = MbedtlsGetMdCtx(self);
    if (ctx == NULL) {
        LOGE("The CTX is NULL!");
        return HCF_INVALID_PARAMS;
    }
    int32_t ret = mbedtls_md_update(ctx, (const unsigned char *)input->data, input->len);
    if (ret != HCF_MBEDTLS_SUCCESS) {
        LOGE("EVP_DigestUpdate return error %d!", ret);
        return HCF_ERR_CRYPTO_OPERATION;
    }

    return HCF_SUCCESS;
}

static HcfResult MbedtlsEngineDoFinalMd(HcfMdSpi *self, HcfBlob *output)
{
    if ((self == NULL) || (output == NULL)) {
        LOGE("The input self ptr is NULL!");
        return HCF_INVALID_PARAMS;
    }
    mbedtls_md_context_t *ctx = MbedtlsGetMdCtx(self);
    if (ctx == NULL) {
        LOGE("The CTX is NULL!");
        return HCF_INVALID_PARAMS;
    }
    unsigned char outputBuf[HCF_EVP_MAX_MD_SIZE] = { 0 };
    uint8_t outputLen = mbedtls_md_get_size(mbedtls_md_info_from_ctx(ctx));
    if (outputLen == 0) {
        LOGE("Failed to md get size is 0!");
        return HCF_ERR_CRYPTO_OPERATION;
    }
    int32_t ret = mbedtls_md_finish(ctx, outputBuf);
    if (ret != HCF_MBEDTLS_SUCCESS) {
        LOGE("Failed to md finish return error is %d!", ret);
        return HCF_ERR_CRYPTO_OPERATION;
    }
    output->data = (uint8_t *)HcfMalloc(outputLen, 0);
    if (output->data == NULL) {
        LOGE("Failed to allocate output->data memory!");
        return HCF_ERR_MALLOC;
    }
    (void)memcpy_s(output->data, outputLen, outputBuf, outputLen);
    output->len = outputLen;

    return HCF_SUCCESS;
}

static uint32_t MbedtlsEngineGetMdLength(HcfMdSpi *self)
{
    mbedtls_md_context_t *ctx = MbedtlsGetMdCtx(self);
    if (ctx == NULL) {
        LOGD("The CTX is NULL!");
        return HCF_MBEDTLS_INVALID_MD_LEN;
    }
    uint8_t outputLen = mbedtls_md_get_size(mbedtls_md_info_from_ctx(ctx));
    if ((outputLen == 0) || (outputLen > HCF_EVP_MAX_MD_SIZE)) {
        LOGD("Get the overflow path length is %d in mbedtls!", outputLen);
        return HCF_MBEDTLS_INVALID_MD_LEN;
    }

    return outputLen;
}

static void MbedtlsDestroyMd(HcfObjectBase *self)
{
    if (self == NULL) {
        LOGE("The input self ptr is NULL!");
        return;
    }
    if (!HcfIsClassMatch(self, MbedtlsGetMdClass())) {
        LOGE("Class is not match.");
        return;
    }
    if (MbedtlsGetMdCtx((HcfMdSpi *)self) != NULL) {
        mbedtls_md_free(MbedtlsGetMdCtx((HcfMdSpi *)self));
        MbedtlsEvpMdCtxFree(MbedtlsGetMdCtx((HcfMdSpi *)self));
    }
    HcfFree(self);
}

typedef struct {
    char *mdAlg;
    mbedtls_md_type_t mdType;
} MdAlgTypeMap;

static MdAlgTypeMap g_mdAlgMap[] = {
    { "MD5",    MBEDTLS_MD_MD5    },
    { "SHA1",   MBEDTLS_MD_SHA1   },
    { "SHA256", MBEDTLS_MD_SHA256 },
    { "SHA512", MBEDTLS_MD_SHA512 },
};

int MbedtlsEvpDigestInitEx(mbedtls_md_context_t *ctx, const char *mbedtlsAlgoName)
{
    for (uint32_t index = 0; index < sizeof(g_mdAlgMap) / sizeof(g_mdAlgMap[0]); index++) {
        if (strcmp(g_mdAlgMap[index].mdAlg, mbedtlsAlgoName) == 0) {
            mbedtls_md_init(ctx);
            mbedtls_md_setup(ctx, mbedtls_md_info_from_type(g_mdAlgMap[index].mdType), 0);
            mbedtls_md_starts(ctx);
            return HCF_MBEDTLS_SUCCESS;
        }
    }

    return HCF_MBEDTLS_FAILURE;
}

HcfResult MbedtlsMdSpiCreate(const char *mbedtlsAlgoName, HcfMdSpi **spiObj)
{
    if (spiObj == NULL) {
        LOGE("Invalid input parameter.");
        return HCF_INVALID_PARAMS;
    }
    MbedtlsMdSpiImpl *returnSpiImpl = (MbedtlsMdSpiImpl *)HcfMalloc(sizeof(MbedtlsMdSpiImpl), 0);
    if (returnSpiImpl == NULL) {
        LOGE("Failed to allocate returnImpl memory!");
        return HCF_ERR_MALLOC;
    }
    returnSpiImpl->ctx = MbedtlsEvpMdCtxNew();
    if (returnSpiImpl->ctx == NULL) {
        LOGE("Failed to create ctx!");
        HcfFree(returnSpiImpl);
        returnSpiImpl = NULL;
        return HCF_ERR_MALLOC;
    }
    int32_t ret = MbedtlsEvpDigestInitEx(returnSpiImpl->ctx, mbedtlsAlgoName);
    if (ret != HCF_MBEDTLS_SUCCESS) {
        LOGE("Failed to init MD ret is %d!", ret);
        MbedtlsEvpMdCtxFree(returnSpiImpl->ctx);
        returnSpiImpl->ctx = NULL;
        HcfFree(returnSpiImpl);
        returnSpiImpl = NULL;
        return HCF_ERR_CRYPTO_OPERATION;
    }
    returnSpiImpl->base.base.getClass = MbedtlsGetMdClass;
    returnSpiImpl->base.base.destroy = MbedtlsDestroyMd;
    returnSpiImpl->base.engineUpdateMd = MbedtlsEngineUpdateMd;
    returnSpiImpl->base.engineDoFinalMd = MbedtlsEngineDoFinalMd;
    returnSpiImpl->base.engineGetMdLength = MbedtlsEngineGetMdLength;
    *spiObj = (HcfMdSpi *)returnSpiImpl;

    return HCF_SUCCESS;
}
