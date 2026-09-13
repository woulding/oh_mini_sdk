/*
 * Copyright (C) 2022-2026 Huawei Device Co., Ltd.
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

#include "aes_openssl_common.h"

#include <string.h>
#include "log.h"
#include "memory.h"
#include "result.h"
#include "openssl_adapter.h"

#define AEAD_PARAMS_SPEC_TYPE "AeadParamsSpec"

const unsigned char *GetIv(HcfParamsSpec *params)
{
    if (params == NULL) {
        LOGD("params is NULL!");
        return NULL;
    }
    const char *typeName = (params->getType != NULL) ? params->getType() : NULL;
    if (typeName != NULL && strcmp(typeName, AEAD_PARAMS_SPEC_TYPE) == 0) {
        HcfAeadParamsSpec *spec = (HcfAeadParamsSpec *)params;
        return spec->nonce.data;
    }
    HcfIvParamsSpec *spec = (HcfIvParamsSpec *)params;
    return spec->iv.data;
}

size_t GetIvLen(HcfParamsSpec *params)
{
    if (params == NULL) {
        return 0;
    }
    const char *typeName = (params->getType != NULL) ? params->getType() : NULL;
    if (typeName != NULL && strcmp(typeName, AEAD_PARAMS_SPEC_TYPE) == 0) {
        HcfAeadParamsSpec *spec = (HcfAeadParamsSpec *)params;
        return spec->nonce.len;
    }
    HcfIvParamsSpec *spec = (HcfIvParamsSpec *)params;
    return spec->iv.len;
}

int32_t GetCcmTagLen(HcfParamsSpec *params)
{
    if (params == NULL) {
        return 0;
    }
    HcfCcmParamsSpec *spec = (HcfCcmParamsSpec *)params;
    size_t tagLen = spec->tag.len;
    return (int)tagLen;
}

void *GetCcmTag(HcfParamsSpec *params)
{
    if (params == NULL) {
        LOGE("params is NULL!");
        return NULL;
    }
    HcfCcmParamsSpec *spec = (HcfCcmParamsSpec *)params;
    uint8_t *tag = spec->tag.data;
    return (void *)tag;
}

void FreeCipherData(CipherData **data)
{
    if (data == NULL || *data == NULL) {
        return;
    }
    if ((*data)->ctx != NULL) {
        OpensslEvpCipherCtxFree((*data)->ctx);
        (*data)->ctx = NULL;
    }
    if ((*data)->aad != NULL) {
        HcfFree((*data)->aad);
        (*data)->aad = NULL;
    }
    if ((*data)->iv != NULL) {
        HcfFree((*data)->iv);
        (*data)->iv = NULL;
    }
    if ((*data)->tag != NULL) {
        HcfFree((*data)->tag);
        (*data)->tag = NULL;
    }
    HcfFree(*data);
    *data = NULL;
}

void FreeRedundantOutput(HcfBlob *blob)
{
    if (blob == NULL) {
        return;
    }
    // when decrypt result is empty plaintext, out blob data maybe not null (malloc by hcf before decryption)
    if ((blob->len == 0) && (blob->data != NULL)) {
        HcfFree(blob->data);
        blob->data = NULL;
    }
}