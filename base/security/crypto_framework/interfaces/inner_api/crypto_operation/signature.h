/*
 * Copyright (C) 2022-2024 Huawei Device Co., Ltd.
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

#ifndef HCF_SIGNATURE_H
#define HCF_SIGNATURE_H

#include <stdint.h>
#include <stdbool.h>
#include "algorithm_parameter.h"
#include "result.h"
#include "key_pair.h"

typedef enum {
    PSS_MD_NAME_STR = 100,
    PSS_MGF_NAME_STR = 101,
    PSS_MGF1_MD_STR = 102,
    PSS_SALT_LEN_INT = 103,  // warning: PSS_SALT_LEN_NUM in JS
    PSS_TRAILER_FIELD_INT = 104,  // warning: PSS_TRAILER_FIELD_NUM in JS
    SM2_USER_ID_UINT8ARR = 105,
    ML_DSA_DETERMINISTIC_BOOL = 106,
    ML_DSA_MU_BOOL = 107,
    ML_DSA_CONTEXT_UINT8ARR = 108
} SignSpecItem;

typedef struct HcfSign HcfSign;

struct HcfSign {
    HcfObjectBase base;

    HcfResult (*init)(HcfSign *self, HcfParamsSpec *params, HcfPriKey *privateKey);

    HcfResult (*update)(HcfSign *self, HcfBlob *data);

    HcfResult (*sign)(HcfSign *self, HcfBlob *data, HcfBlob *returnSignatureData);

    const char *(*getAlgoName)(HcfSign *self);

    HcfResult (*setSignSpecInt)(HcfSign *self, SignSpecItem item, int32_t saltLen);

    HcfResult (*getSignSpecString)(HcfSign *self, SignSpecItem item, char **returnString);

    HcfResult (*getSignSpecInt)(HcfSign *self, SignSpecItem item, int32_t *returnInt);

    HcfResult (*setSignSpecUint8Array)(HcfSign *self, SignSpecItem item, HcfBlob blob);

    HcfResult (*setSignSpecBool)(HcfSign *self, SignSpecItem item, bool flag);
};

typedef struct HcfVerify HcfVerify;

struct HcfVerify {
    HcfObjectBase base;

    HcfResult (*init)(HcfVerify *self, HcfParamsSpec *params, HcfPubKey *publicKey);

    HcfResult (*update)(HcfVerify *self, HcfBlob *data);

    bool (*verify)(HcfVerify *self, HcfBlob *data, HcfBlob *signatureData);

    HcfResult (*recover)(HcfVerify *self, HcfBlob *signatureData, HcfBlob *rawSignatureData);

    const char *(*getAlgoName)(HcfVerify *self);

    HcfResult (*setVerifySpecInt)(HcfVerify *self, SignSpecItem item, int32_t saltLen);

    HcfResult (*getVerifySpecString)(HcfVerify *self, SignSpecItem item, char **returnString);

    HcfResult (*getVerifySpecInt)(HcfVerify *self, SignSpecItem item, int32_t *returnInt);

    HcfResult (*setVerifySpecUint8Array)(HcfVerify *self, SignSpecItem item, HcfBlob blob);

    HcfResult (*setVerifySpecBool)(HcfVerify *self, SignSpecItem item, bool flag);
};

#ifdef __cplusplus
extern "C" {
#endif

HcfResult HcfSignCreate(const char *algoName, HcfSign **returnObj);

HcfResult HcfVerifyCreate(const char *algoName, HcfVerify **returnObj);

#ifdef __cplusplus
}
#endif

#endif
