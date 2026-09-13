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

#include "sm2_crypto_util.h"
#include <limits.h>
#include <securec.h>
#include "cipher_sm2_crypto_util_openssl.h"
#include "log.h"
#include "memory.h"
#include "utils.h"

#define HCF_SM2_C3_LEN 32

typedef HcfResult (*HcfSm2SpecToASN1CreateFunc)(Sm2CipherTextSpec *spec, HcfBlob *output);

typedef struct {
    char *mode;
    HcfSm2SpecToASN1CreateFunc createFunc;
} HcfSm2UtilAbility;

static const HcfSm2UtilAbility CONVERT_ABILITY_SET[] = {
    { "C1C3C2", HcfSm2SpecToAsn1 },
};

static HcfSm2SpecToASN1CreateFunc FindAbility(const char *mode)
{
    // mode default C1C3C2
    if (HcfStrlen(mode) == 0) {
        return CONVERT_ABILITY_SET[0].createFunc;
    }
    for (uint32_t i = 0; i < sizeof(CONVERT_ABILITY_SET) / sizeof(HcfSm2UtilAbility); i++) {
        if (strcmp(mode, CONVERT_ABILITY_SET[i].mode) == 0) {
            return CONVERT_ABILITY_SET[i].createFunc;
        }
    }
    LOGE("No matching SM2 mode found");
    return NULL;
}

static bool CheckMode(const char *mode)
{
    if (HcfStrlen(mode) == 0) {
        return true;
    }
    for (uint32_t i = 0; i < sizeof(CONVERT_ABILITY_SET) / sizeof(HcfSm2UtilAbility); i++) {
        if (strcmp(mode, CONVERT_ABILITY_SET[i].mode) == 0) {
            return true;
        }
    }
    LOGE("Invalid param mode");
    return false;
}

static bool CheckSm2CipherTextSpec(Sm2CipherTextSpec *spec)
{
    if (spec == NULL) {
        LOGE("Spec is null");
        return false;
    }
    if ((spec->xCoordinate.data == NULL) || (spec->xCoordinate.len == 0)) {
        LOGE("Spec.xCoordinate is null");
        return false;
    }
    if ((spec->yCoordinate.data == NULL) || (spec->yCoordinate.len == 0)) {
        LOGE("Spec.yCoordinate is null");
        return false;
    }
    if ((spec->hashData.data == NULL) || (spec->hashData.len == 0)) {
        LOGE("Spec.hashData is null");
        return false;
    }
    if ((spec->cipherTextData.data == NULL) || (spec->cipherTextData.len == 0)) {
        LOGE("Spec.cipherTextData is null");
        return false;
    }
    if (spec->cipherTextData.len > INT_MAX) {
        LOGE("Invalid param cipherTextData");
        return false;
    }
    if (spec->hashData.len != HCF_SM2_C3_LEN) {
        LOGE("Invalid param hashData");
        return false;
    }
    return true;
}

HcfResult HcfGenCipherTextBySpec(Sm2CipherTextSpec *spec, const char *mode, HcfBlob *output)
{
    if (!CheckMode(mode)) {
        LOGE("Invalid param mode!");
        return HCF_INVALID_PARAMS;
    }
    if (output == NULL) {
        LOGE("Invalid param output!");
        return HCF_INVALID_PARAMS;
    }
    if (!CheckSm2CipherTextSpec(spec)) {
        LOGE("Invalid param spec!");
        return HCF_INVALID_PARAMS;
    }
    HcfSm2SpecToASN1CreateFunc createFunc = FindAbility(mode);
    if (createFunc == NULL) {
        LOGE("Failed to find create function");
        return HCF_INVALID_PARAMS;
    }
    HcfResult res = createFunc(spec, output);
    if (res != HCF_SUCCESS) {
        LOGE("Failed to convert construct to asn1!");
    }
    return res;
}

HcfResult HcfGetCipherTextSpec(HcfBlob *input, const char *mode, Sm2CipherTextSpec **returnSpc)
{
    if (!CheckMode(mode)) {
        LOGE("Invalid param mode!");
        return HCF_INVALID_PARAMS;
    }
    if (input == NULL) {
        LOGE("Invalid param input!");
        return HCF_INVALID_PARAMS;
    }
    if (returnSpc == NULL) {
        LOGE("Invalid param returnSpc!");
        return HCF_INVALID_PARAMS;
    }
    HcfResult res = HcfAsn1ToSm2Spec(input, returnSpc);
    if (res != HCF_SUCCESS) {
        LOGE("Failed to convert asn1 to construct!");
        return res;
    }
    return HCF_SUCCESS;
}