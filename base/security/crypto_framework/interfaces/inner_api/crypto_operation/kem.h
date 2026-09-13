/*
 * Copyright (C) 2026 Huawei Device Co., Ltd.
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

#ifndef HCF_KEM_H
#define HCF_KEM_H

#include "blob.h"
#include "pri_key.h"
#include "pub_key.h"
#include "result.h"

typedef struct HcfKem HcfKem;

typedef enum {
    ML_KEM_512 = 0,
    ML_KEM_768 = 1,
    ML_KEM_1024 = 2
} HcfKemAlgNameId;

struct HcfKem {
    HcfObjectBase base;

    HcfResult (*encapsulate)(HcfKem *self, HcfPubKey *pubKey, const HcfBlob *ikme,
        HcfBlob *returnSharedSecret, HcfBlob *returnWrappedKey);

    HcfResult (*decapsulate)(HcfKem *self, HcfPriKey *priKey, const HcfBlob *wrappedKey,
        HcfBlob *returnSharedSecret);
};

#ifdef __cplusplus
extern "C" {
#endif

HcfResult HcfKemCreate(const char *algoName, HcfKem **returnObj);

#ifdef __cplusplus
}
#endif

#endif
