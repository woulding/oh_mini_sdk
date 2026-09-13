/*
 * Copyright (C) 2025 Huawei Device Co., Ltd.
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

#ifndef HCF_DETAILED_CMAC_PARAMS_H
#define HCF_DETAILED_CMAC_PARAMS_H

#include "mac_params.h"

typedef struct HcfCmacParamsSpec HcfCmacParamsSpec;

struct HcfCmacParamsSpec {
    HcfMacParamsSpec base;
    const char *cipherName;
};

#endif // HCF_DETAILED_CMAC_PARAMS_H
