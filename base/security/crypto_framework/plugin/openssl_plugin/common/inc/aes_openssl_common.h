/*
 * Copyright (C) 2022 Huawei Device Co., Ltd.
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

#ifndef HCF_AES_OPENSSL_COMMON_H
#define HCF_AES_OPENSSL_COMMON_H

#include <stdbool.h>
#include <openssl/evp.h>
#include "openssl_common.h"
#include "aes_openssl.h"
#include "detailed_iv_params.h"
#include "detailed_ccm_params.h"
#include "detailed_gcm_params.h"
#include "detailed_aead_params.h"

typedef struct {
    EVP_CIPHER_CTX *ctx;
    enum HcfCryptoMode enc;
    /* EVP_CIPH_GCM_MODE, EVP_CIPH_CCM_MODE need AEAD */
    bool aead;
    bool isNewCcmAead;  /* true when CCM uses AeadParamsSpec (GCM-style flow) */
    uint32_t updateLen;
    unsigned char *iv;
    uint32_t ivLen;
    /* GCM, CCM only */
    unsigned char *aad;
    uint32_t aadLen;
    unsigned char *tag;
    uint32_t tagLen;
} CipherData;

#ifdef __cplusplus
extern "C" {
#endif
const unsigned char *GetIv(HcfParamsSpec *params);

size_t GetIvLen(HcfParamsSpec *params);

int32_t GetCcmTagLen(HcfParamsSpec *params);

void *GetCcmTag(HcfParamsSpec *params);

void FreeCipherData(CipherData **data);

void FreeRedundantOutput(HcfBlob *blob);

#ifdef __cplusplus
}
#endif

#endif
