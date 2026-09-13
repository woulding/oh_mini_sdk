/*
 * Copyright (C) 2026 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#ifndef HCF_DETAILED_AEAD_PARAMS_H
#define HCF_DETAILED_AEAD_PARAMS_H

#include <stdint.h>
#include "algorithm_parameter.h"
#include "blob.h"

typedef struct HcfAeadParamsSpec HcfAeadParamsSpec;

struct HcfAeadParamsSpec {
    HcfParamsSpec base;
    HcfBlob nonce;
    HcfBlob aad;
    int32_t tagLen;
};

#endif // HCF_DETAILED_AEAD_PARAMS_H
