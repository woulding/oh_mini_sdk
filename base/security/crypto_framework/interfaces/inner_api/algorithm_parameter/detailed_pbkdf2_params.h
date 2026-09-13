/*
 * Copyright (C) 2023 Huawei Device Co., Ltd.
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

#ifndef HCF_DETAILED_PBKDF2_PARAMS_H
#define HCF_DETAILED_PBKDF2_PARAMS_H

#include "blob.h"
#include "kdf_params.h"

typedef struct HcfPBKDF2ParamsSpec HcfPBKDF2ParamsSpec;

struct HcfPBKDF2ParamsSpec {
    HcfKdfParamsSpec base;
    HcfBlob password;
    HcfBlob salt;
    int iterations;
    HcfBlob output;
};

#endif // HCF_DETAILED_PBKDF2_PARAMS_H
