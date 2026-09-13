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

#ifndef HCF_SYM_KEY_GENERATOR_H
#define HCF_SYM_KEY_GENERATOR_H

#include <stdint.h>
#include "result.h"
#include "sym_key.h"

/**
 * @brief Provides a wrapped HcfSymKeyGenerator instance.
 *
 * @since 9
 * @version 1.0
 */
typedef struct HcfSymKeyGenerator HcfSymKeyGenerator;

/**
 * @brief Provides generation capabilities for symmetric key objects.
 *
 * @since 9
 * @version 1.0
 */
struct HcfSymKeyGenerator {
    HcfObjectBase base;

    /** Generate symmetric key object */
    HcfResult (*generateSymKey)(HcfSymKeyGenerator *self, HcfSymKey **symKey);

    /** Convert byte data to symmetric key object */
    HcfResult (*convertSymKey)(HcfSymKeyGenerator *self, const HcfBlob *key, HcfSymKey **symKey);

    /** Get the algorithm name of the current these key generator objects */
    const char *(*getAlgoName)(HcfSymKeyGenerator *self);
};

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief Generate a symmetric key generator object based on the algorithm name.
 *
 * @param algoName Specifies the type of generated symmetric key generator object.
 * @param returnObj return pointer to generate symmetric key generator object.
 * @return Returns the status code of the execution
 * @since 9
 * @version 1.0
 */
HcfResult HcfSymKeyGeneratorCreate(const char *algoName, HcfSymKeyGenerator **returnObj);

#ifdef __cplusplus
}
#endif

#endif
