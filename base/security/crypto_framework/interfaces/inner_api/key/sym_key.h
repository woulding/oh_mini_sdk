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

#ifndef HCF_SYM_KEY_H
#define HCF_SYM_KEY_H

#include "key.h"

/**
 * @brief Provides an encapsulated HcfSymKey instance.
 *
 * @since 9
 * @version 1.0
 */
typedef struct HcfSymKey HcfSymKey;

/**
 * @brief Provides common properties for symmetric key objects.
 *
 * @since 9
 * @version 1.0
 */
struct HcfSymKey {
    HcfKey key;

    void (*clearMem)(HcfSymKey *self);
};

#endif
