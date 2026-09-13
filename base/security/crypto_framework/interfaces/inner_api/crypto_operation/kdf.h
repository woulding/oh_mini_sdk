/*
 * Copyright (C) 2023 Huawei Device Co., Ltd.
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

#ifndef HCF_KDF_H
#define HCF_KDF_H

#include "result.h"
#include "object_base.h"
#include "kdf_params.h"

typedef struct HcfKdf HcfKdf;
/**
 * @brief this class provides kdf algorithms for key derivation,
 *
 * @since 11
 * @version 1.0
 */
struct HcfKdf {
    HcfObjectBase base;

    const char *(*getAlgorithm)(HcfKdf *self);

    HcfResult (*generateSecret)(HcfKdf *self, HcfKdfParamsSpec* paramsSpec);
};

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief Generate a corresponding key derivation operation kdf object according to the algorithm name.
 *
 * @param transformation Specifies the type of generated kdf object.
 * @param returnObj The address of the pointer to the generated kdf object.
 * @return Returns the status code of the execution.
 * @since 11
 * @version 1.0
 */
HcfResult HcfKdfCreate(const char *transformation, HcfKdf **returnObj);

#ifdef __cplusplus
}
#endif

#endif
