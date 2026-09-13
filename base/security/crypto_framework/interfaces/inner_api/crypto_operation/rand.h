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

#ifndef HCF_RAND_H
#define HCF_RAND_H

#include <stdint.h>
#include "result.h"
#include "object_base.h"

#include "blob.h"

typedef struct HcfRand HcfRand;

struct HcfRand {
    HcfObjectBase base;

    const char *(*getAlgoName)(HcfRand *self);

    HcfResult (*generateRandom)(HcfRand *self, int32_t numBytes, HcfBlob *random);

    HcfResult (*setSeed)(HcfRand *self, HcfBlob *seed);

    HcfResult (*enableHardwareEntropy)(HcfRand *self);
};

#ifdef __cplusplus
extern "C" {
#endif

HcfResult HcfRandCreate(HcfRand **random);

#ifdef __cplusplus
}
#endif

#endif