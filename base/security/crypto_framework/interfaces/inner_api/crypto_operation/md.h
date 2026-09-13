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

#ifndef HCF_MD_H
#define HCF_MD_H

#include "blob.h"
#include "result.h"
#include "object_base.h"

typedef struct HcfMd HcfMd;

struct HcfMd {
    HcfObjectBase base;

    HcfResult (*update)(HcfMd *self, HcfBlob *input);

    HcfResult (*doFinal)(HcfMd *self, HcfBlob *output);

    uint32_t (*getMdLength)(HcfMd *self);

    const char *(*getAlgoName)(HcfMd *self);
};

#ifdef __cplusplus
extern "C" {
#endif

HcfResult HcfMdCreate(const char *algoName, HcfMd **md);

#ifdef __cplusplus
}
#endif

#endif
