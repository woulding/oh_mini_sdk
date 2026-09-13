/*
 * Copyright (c) 2022 Huawei Device Co., Ltd.
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

#include <cstdlib>
#include "hilog_realloc.h"
#include "securec.h"
#include "hilog_vector.h"

namespace OHOS {
namespace ACELite {
static const size_t ORG_VECTOR_SIZE = 2;

HilogVector::HilogVector() : size(0), maxSize(0), str(nullptr), type(nullptr) {}

HilogVector::~HilogVector()
{
    if (str != nullptr) {
        for (size_t i = 0; i < size; i++) {
            char *tmp = str[i];
            if (tmp != nullptr) {
                free(tmp);
            }
        }
        free(str);
        str = nullptr;
    }

    if (type != nullptr) {
        free(type);
        type = nullptr;
    }
}

size_t HilogVector::Size(const HilogVector *vector)
{
    if (vector == nullptr) {
        return 0;
    }
    return vector->size;
}

char* HilogVector::GetStr(const HilogVector *vector, size_t pos)
{
    if (vector != nullptr && vector->str != nullptr && pos < vector->size) {
        return vector->str[pos];
    }
    return nullptr;
}

ValueType HilogVector::GetType(const HilogVector *vector, size_t pos)
{
    if (vector != nullptr && vector->type != nullptr && pos < vector->size) {
        return vector->type[pos];
    }
    return NONE_TYPE;
}

void HilogVector::Push(HilogVector *vector, const char *element, ValueType type)
{
    if (vector == nullptr || element == nullptr) {
        return;
    }
    if (vector->size == vector->maxSize) {
        vector->maxSize == 0 ? vector->maxSize = ORG_VECTOR_SIZE : vector->maxSize = vector->maxSize << 1;
        char **tempStr = static_cast<char**>(
            HilogRealloc::Realloc(vector->str, sizeof(char*) * vector->maxSize, sizeof(char*) * vector->size));
        ValueType *tempType = static_cast<ValueType*>(
            HilogRealloc::Realloc(
                vector->type, sizeof(ValueType) * vector->maxSize, sizeof(ValueType) * vector->size));
        if (tempStr != nullptr && tempType != nullptr) {
            vector->str = tempStr;
            vector->type = tempType;
        } else {
            return;
        }
    }
    if (vector->str != nullptr && vector->type != nullptr) {
        size_t length = sizeof(char) * (strlen(element) + 1);
        char *tempStr = static_cast<char*>(malloc(length));
        if (tempStr == nullptr) {
            return;
        }
        vector->str[vector->size] = tempStr;
        memset_s(vector->str[vector->size], length, 0, length);
        memcpy_s(vector->str[vector->size], length, element, sizeof(char) * strlen(element));
        vector->type[vector->size] = type;
        vector->size++;
    }
}
} // namespace ACELite
} // namespace OHOS