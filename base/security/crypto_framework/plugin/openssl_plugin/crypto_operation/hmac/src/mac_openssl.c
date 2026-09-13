/*
 * Copyright (C) 2023-2024 Huawei Device Co., Ltd.
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

#include "mac_openssl.h"

#include "openssl_adapter.h"
#include "sym_common_defines.h"
#include "openssl_common.h"
#include "securec.h"
#include "log.h"
#include "memory.h"
#include "config.h"
#include "utils.h"
#include "detailed_hmac_params.h"
#include "detailed_cmac_params.h"

typedef struct {
    HcfMacSpi base;

    HMAC_CTX *ctx;

    char opensslMdName[HCF_MAX_MD_NAME_LEN];

    CryptoStatus initFlag;
} HcfHmacSpiImpl;

typedef struct {
    HcfMacSpi base;

    EVP_MAC_CTX *ctx;

    char opensslCipherName[HCF_MAX_CIPHER_NAME_LEN];

    CryptoStatus initFlag;
} HcfCmacSpiImpl;

static const char *OpensslGetHmacClass(void)
{
    return "OpensslHmac";
}

static const char *OpensslGetCmacClass(void)
{
    return "OpensslCmac";
}

static HMAC_CTX *OpensslGetHmacCtx(HcfMacSpi *self)
{
    if (!HcfIsClassMatch((HcfObjectBase *)self, OpensslGetHmacClass())) {
        LOGE("Class is not match.");
        return NULL;
    }
    return ((HcfHmacSpiImpl *)self)->ctx;
}

static EVP_MAC_CTX *OpensslGetCmacCtx(HcfMacSpi *self)
{
    if (!HcfIsClassMatch((HcfObjectBase *)self, OpensslGetCmacClass())) {
        LOGE("Class is not match.");
        return NULL;
    }
    return ((HcfCmacSpiImpl *)self)->ctx;
}

static const EVP_MD *OpensslGetHmacAlgoFromString(const char *mdName)
{
    if (strcmp(mdName, "SHA1") == 0) {
        return OpensslEvpSha1();
    } else if (strcmp(mdName, "SHA224") == 0) {
        return OpensslEvpSha224();
    } else if (strcmp(mdName, "SHA256") == 0) {
        return OpensslEvpSha256();
    } else if (strcmp(mdName, "SHA384") == 0) {
        return OpensslEvpSha384();
    } else if (strcmp(mdName, "SHA512") == 0) {
        return OpensslEvpSha512();
    } else if (strcmp(mdName, "SHA3-256") == 0) {
        return OpensslEvpSha3256();
    } else if (strcmp(mdName, "SHA3-384") == 0) {
        return OpensslEvpSha3384();
    } else if (strcmp(mdName, "SHA3-512") == 0) {
        return OpensslEvpSha3512();
    } else if (strcmp(mdName, "SM3") == 0) {
        return OpensslEvpSm3();
    } else if (strcmp(mdName, "MD5") == 0) {
        return OpensslEvpMd5();
    }
    return NULL;
}

static HcfResult OpensslEngineInitHmac(HcfMacSpi *self, const HcfSymKey *key)
{
    if (OpensslGetHmacCtx(self) == NULL) {
        LOGE("The CTX is NULL!");
        return HCF_ERR_CRYPTO_OPERATION;
    }
    if (!HcfIsClassMatch((const HcfObjectBase *)key, OPENSSL_SYM_KEY_CLASS)) {
        LOGE("Class is not match.");
        return HCF_INVALID_PARAMS;
    }
    if (!HcfIsClassMatch((HcfObjectBase *)self, OpensslGetHmacClass())) {
        LOGE("Class is not match.");
        return HCF_INVALID_PARAMS;
    }
    HcfBlob keyBlob = ((SymKeyImpl *)key)->keyMaterial;
    if (!HcfIsBlobValid(&keyBlob)) {
        LOGE("Invalid keyMaterial");
        return HCF_INVALID_PARAMS;
    }
    const EVP_MD *mdfunc = OpensslGetHmacAlgoFromString(((HcfHmacSpiImpl *)self)->opensslMdName);
    int32_t ret = OpensslHmacInitEx(OpensslGetHmacCtx(self), keyBlob.data, keyBlob.len, mdfunc, NULL);
    if (ret != HCF_OPENSSL_SUCCESS) {
        LOGE("HMAC_Init_ex return error!");
        HcfPrintOpensslError();
        return HCF_ERR_CRYPTO_OPERATION;
    }
    ((HcfHmacSpiImpl *)self)->initFlag = INITIALIZED;
    return HCF_SUCCESS;
}

static HcfResult OpensslEngineUpdateHmac(HcfMacSpi *self, HcfBlob *input)
{
    HcfHmacSpiImpl *hmacImpl = (HcfHmacSpiImpl *)self;
    if (hmacImpl->initFlag != INITIALIZED) {
        LOGW("HMAC instance may not have been initialized, "
            "ensure init interface of HMAC instance is executed completely!");
    }
    if (OpensslGetHmacCtx(self) == NULL) {
        LOGE("The CTX of HMAC instance is NULL, "
            "please check if init interface of HMAC instance is executed completely!");
        return HCF_ERR_CRYPTO_OPERATION;
    }
    if (HMAC_Update(OpensslGetHmacCtx(self), input->data, input->len) != HCF_OPENSSL_SUCCESS) {
        LOGE("HMAC_Update return error!");
        HcfPrintOpensslError();
        return HCF_ERR_CRYPTO_OPERATION;
    }
    return HCF_SUCCESS;
}

static HcfResult OpensslEngineDoFinalHmac(HcfMacSpi *self, HcfBlob *output)
{
    HcfHmacSpiImpl *hmacImpl = (HcfHmacSpiImpl *)self;
    if (hmacImpl->initFlag != INITIALIZED) {
        LOGW("HMAC instance may not have been initialized, "
            "ensure init interface of HMAC instance is executed completely!");
    }
    if (OpensslGetHmacCtx(self) == NULL) {
        LOGE("The CTX of HMAC instance is NULL, "
            "please check if init interface of HMAC instance is executed completely!");
        return HCF_ERR_CRYPTO_OPERATION;
    }
    unsigned char outputBuf[EVP_MAX_MD_SIZE];
    uint32_t outputLen;
    int32_t ret = OpensslHmacFinal(OpensslGetHmacCtx(self), outputBuf, &outputLen);
    if (ret != HCF_OPENSSL_SUCCESS) {
        LOGE("HMAC_Final return error!");
        HcfPrintOpensslError();
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

static uint32_t OpensslEngineGetHmacLength(HcfMacSpi *self)
{
    if (OpensslGetHmacCtx(self) == NULL) {
        LOGE("The CTX is NULL!");
        return HCF_OPENSSL_INVALID_MAC_LEN;
    }
    return OpensslHmacSize(OpensslGetHmacCtx(self));
}

static void OpensslDestroyHmac(HcfObjectBase *self)
{
    if (self == NULL) {
        LOGE("Self ptr is NULL");
        return;
    }
    if (!HcfIsClassMatch(self, OpensslGetHmacClass())) {
        LOGE("Class is not match.");
        return;
    }
    if (OpensslGetHmacCtx((HcfMacSpi *)self) != NULL) {
        OpensslHmacCtxFree(OpensslGetHmacCtx((HcfMacSpi *)self));
    }
    HcfFree(self);
}

HcfResult OpensslHmacSpiCreate(HcfMacParamsSpec *paramsSpec, HcfMacSpi **spiObj)
{
    if (paramsSpec == NULL || spiObj == NULL) {
        LOGE("Invalid input parameter.");
        return HCF_INVALID_PARAMS;
    }
    HcfHmacSpiImpl *returnSpiImpl = (HcfHmacSpiImpl *)HcfMalloc(sizeof(HcfHmacSpiImpl), 0);
    if (returnSpiImpl == NULL) {
        LOGE("Failed to allocate returnImpl memory!");
        return HCF_ERR_MALLOC;
    }
    if (strcpy_s(returnSpiImpl->opensslMdName, HCF_MAX_MD_NAME_LEN, ((HcfHmacParamsSpec *)paramsSpec)->mdName) != EOK) {
        LOGE("Failed to copy algoName!");
        HcfFree(returnSpiImpl);
        returnSpiImpl = NULL;
        return HCF_INVALID_PARAMS;
    }
    returnSpiImpl->ctx = OpensslHmacCtxNew();
    if (returnSpiImpl->ctx == NULL) {
        LOGE("Failed to create ctx!");
        HcfFree(returnSpiImpl);
        returnSpiImpl = NULL;
        return HCF_ERR_CRYPTO_OPERATION;
    }
    returnSpiImpl->base.base.getClass = OpensslGetHmacClass;
    returnSpiImpl->base.base.destroy = OpensslDestroyHmac;
    returnSpiImpl->base.engineInitMac = OpensslEngineInitHmac;
    returnSpiImpl->base.engineUpdateMac = OpensslEngineUpdateHmac;
    returnSpiImpl->base.engineDoFinalMac = OpensslEngineDoFinalHmac;
    returnSpiImpl->base.engineGetMacLength = OpensslEngineGetHmacLength;
    *spiObj = (HcfMacSpi *)returnSpiImpl;
    return HCF_SUCCESS;
}

static HcfResult OpensslEngineInitCmac(HcfMacSpi *self, const HcfSymKey *key)
{
    OSSL_PARAM params[4] = {};
    OSSL_PARAM *p = params;
    if (OpensslGetCmacCtx(self) == NULL) {
        LOGE("The CTX is NULL!");
        return HCF_ERR_CRYPTO_OPERATION;
    }
    if (!HcfIsClassMatch((const HcfObjectBase *)key, OPENSSL_SYM_KEY_CLASS)) {
        LOGE("Class is not match.");
        return HCF_INVALID_PARAMS;
    }
    if (!HcfIsClassMatch((HcfObjectBase *)self, OpensslGetCmacClass())) {
        LOGE("Class is not match.");
        return HCF_INVALID_PARAMS;
    }
    HcfBlob keyBlob = ((SymKeyImpl *)key)->keyMaterial;
    if (!HcfIsBlobValid(&keyBlob)) {
        LOGE("Invalid keyMaterial");
        return HCF_INVALID_PARAMS;
    }
    *p++ = OpensslOsslParamConstructUtf8String("cipher", ((HcfCmacSpiImpl *)self)->opensslCipherName,
        strlen(((HcfCmacSpiImpl *)self)->opensslCipherName));
    *p++ = OpensslOsslParamConstructEnd();
    int32_t ret = OpensslCmacInit(OpensslGetCmacCtx(self), keyBlob.data, keyBlob.len, params);
    if (ret != HCF_OPENSSL_SUCCESS) {
        LOGE("CMAC_Init return error!");
        HcfPrintOpensslError();
        return HCF_ERR_CRYPTO_OPERATION;
    }
    ((HcfCmacSpiImpl *)self)->initFlag = INITIALIZED;
    return HCF_SUCCESS;
}

static HcfResult OpensslEngineUpdateCmac(HcfMacSpi *self, HcfBlob *input)
{
    HcfCmacSpiImpl *cmacImpl = (HcfCmacSpiImpl *)self;
    if (cmacImpl->initFlag != INITIALIZED) {
        LOGW("CMAC instance may not have been initialized, "
            "ensure init interface of CMAC instance is executed completely!");
    }
    if (OpensslGetCmacCtx(self) == NULL) {
        LOGE("The CTX of CMAC instance is NULL, "
            "please check if init interface of CMAC instance is executed completely!");
        return HCF_ERR_CRYPTO_OPERATION;
    }
    if (OpensslCmacUpdate(OpensslGetCmacCtx(self), input->data, input->len) != HCF_OPENSSL_SUCCESS) {
        LOGE("CMAC_Update return error!");
        HcfPrintOpensslError();
        return HCF_ERR_CRYPTO_OPERATION;
    }
    return HCF_SUCCESS;
}

static HcfResult OpensslEngineDoFinalCmac(HcfMacSpi *self, HcfBlob *output)
{
    HcfCmacSpiImpl *cmacImpl = (HcfCmacSpiImpl *)self;
    if (cmacImpl->initFlag != INITIALIZED) {
        LOGW("CMAC instance may not have been initialized, "
            "ensure init interface of CMAC instance is executed completely!");
    }
    if (OpensslGetCmacCtx(self) == NULL) {
        LOGE("The CTX of CMAC instance is NULL, "
            "please check if init interface of CMAC instance is executed completely!");
        return HCF_ERR_CRYPTO_OPERATION;
    }
    size_t outputLen = 0;
    unsigned char outputBuf[EVP_MAX_MD_SIZE];
    int32_t ret = OpensslCmacFinal(OpensslGetCmacCtx(self), NULL, &outputLen, 0);
    if (ret != HCF_OPENSSL_SUCCESS) {
        LOGE("CMAC_Final return error!");
        HcfPrintOpensslError();
        return HCF_ERR_CRYPTO_OPERATION;
    }
    ret = OpensslCmacFinal(OpensslGetCmacCtx(self), outputBuf, &outputLen, outputLen);
    if (ret != HCF_OPENSSL_SUCCESS) {
        LOGE("CMAC_Final return error!");
        HcfPrintOpensslError();
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

static uint32_t OpensslEngineGetCmacLength(HcfMacSpi *self)
{
    if (OpensslGetCmacCtx(self) == NULL) {
        LOGE("The CTX is NULL!");
        return HCF_OPENSSL_INVALID_MAC_LEN;
    }
    return OpensslCmacSize(OpensslGetCmacCtx(self));
}

static void OpensslDestroyCmac(HcfObjectBase *self)
{
    if (self == NULL) {
        LOGE("Self ptr is NULL");
        return;
    }
    if (!HcfIsClassMatch(self, OpensslGetCmacClass())) {
        LOGE("Class is not match.");
        return;
    }
    if (OpensslGetCmacCtx((HcfMacSpi *)self) != NULL) {
        OpensslCmacCtxFree(OpensslGetCmacCtx((HcfMacSpi *)self));
    }
    HcfFree(self);
}

HcfResult OpensslCmacSpiCreate(HcfMacParamsSpec *paramsSpec, HcfMacSpi **spiObj)
{
    if (paramsSpec == NULL || spiObj == NULL) {
        LOGE("Invalid input parameter.");
        return HCF_INVALID_PARAMS;
    }
    HcfCmacSpiImpl *returnSpiImpl = (HcfCmacSpiImpl *)HcfMalloc(sizeof(HcfCmacSpiImpl), 0);
    if (returnSpiImpl == NULL) {
        LOGE("Failed to allocate returnImpl memory!");
        return HCF_ERR_MALLOC;
    }
    if (strcpy_s(returnSpiImpl->opensslCipherName, HCF_MAX_CIPHER_NAME_LEN,
        ((HcfCmacParamsSpec *)paramsSpec)->cipherName) != EOK) {
        LOGE("Failed to copy algoName!");
        HcfFree(returnSpiImpl);
        returnSpiImpl = NULL;
        return HCF_INVALID_PARAMS;
    }
    EVP_MAC *mac = EVP_MAC_fetch(NULL, "CMAC", NULL);
    if (mac == NULL) {
        LOGE("fetch failed");
        HcfFree(returnSpiImpl);
        returnSpiImpl = NULL;
        return HCF_ERR_CRYPTO_OPERATION;
    }
    returnSpiImpl->ctx = EVP_MAC_CTX_new(mac);
    if (returnSpiImpl->ctx == NULL) {
        LOGE("Failed to create ctx!");
        HcfFree(returnSpiImpl);
        returnSpiImpl = NULL;
        OpensslMacFree(mac);
        return HCF_ERR_CRYPTO_OPERATION;
    }
    OpensslMacFree(mac);
    returnSpiImpl->base.base.getClass = OpensslGetCmacClass;
    returnSpiImpl->base.base.destroy = OpensslDestroyCmac;
    returnSpiImpl->base.engineInitMac = OpensslEngineInitCmac;
    returnSpiImpl->base.engineUpdateMac = OpensslEngineUpdateCmac;
    returnSpiImpl->base.engineDoFinalMac = OpensslEngineDoFinalCmac;
    returnSpiImpl->base.engineGetMacLength = OpensslEngineGetCmacLength;
    *spiObj = (HcfMacSpi *)returnSpiImpl;
    return HCF_SUCCESS;
}