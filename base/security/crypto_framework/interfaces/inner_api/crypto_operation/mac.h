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

#ifndef HCF_MAC_H
#define HCF_MAC_H

#include <stdint.h>
#include "blob.h"
#include "result.h"
#include "sym_key.h"
#include "object_base.h"
#include "mac_params.h"

typedef struct HcfMac HcfMac;

struct HcfMac {
    HcfObjectBase base;

    HcfResult (*init)(HcfMac *self, const HcfSymKey *key);

    HcfResult (*update)(HcfMac *self, HcfBlob *input);

    HcfResult (*doFinal)(HcfMac *self, HcfBlob *output);

    uint32_t (*getMacLength)(HcfMac *self);

    const char *(*getAlgoName)(HcfMac *self);
};

#ifdef __cplusplus
extern "C" {
#endif

HcfResult HcfMacCreate(HcfMacParamsSpec *paramsSpec, HcfMac **mac);

#ifdef __cplusplus
}
#endif

#endif
