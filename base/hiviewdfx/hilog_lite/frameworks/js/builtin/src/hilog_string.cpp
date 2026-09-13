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

#include "hilog_realloc.h"
#include "securec.h"
#include "hilog_string.h"

namespace OHOS {
namespace ACELite {
static const size_t ORG_STRING_LEN = 2;

HilogString::HilogString() : size(0), maxSize(0), str(nullptr) {}

HilogString::~HilogString()
{
    size = 0;
    maxSize = 0;
    if (str != nullptr) {
        free(str);
        str = nullptr;
    }
}

char *HilogString::Get(const HilogString *str)
{
    if (str != nullptr) {
        return str->str;
    }
    return nullptr;
}

size_t HilogString::Length(const HilogString *str)
{
    if (str != nullptr) {
        return str->size;
    }
    return 0;
}

size_t HilogString::Puts(const char *src, HilogString *str, size_t strLen)
{
    if (src == nullptr || str == nullptr) {
        return 0;
    }

    size_t len = strlen(src);
    len = (len > strLen) ? ((strLen == 0) ? len : strLen) : len;
    if (str->size + len + 1 >= str->maxSize) {
        str->maxSize = str->size + len + ORG_STRING_LEN;
        char *tmp = static_cast<char*>(
            HilogRealloc::Realloc(str->str, sizeof(char) * str->maxSize, sizeof(char) * str->size));
        if (tmp != nullptr) {
            str->str = tmp;
        } else {
            return 0;
        }
    }
    if (memcpy_s(str->str + str->size, str->maxSize - str->size, src, len) != 0) {
        return 0;
    }
    str->size += len;
    str->str[str->size] = 0;
    return len;
}

char HilogString::Putc(char c, HilogString *str)
{
    if (str == nullptr) {
        return EOF;
    }
    if (str->size + 1 >= str->maxSize) {
        str->maxSize = str->size + ORG_STRING_LEN;
        char *tmp = static_cast<char*>(
            HilogRealloc::Realloc(str->str, sizeof(char) * str->maxSize, sizeof(char) * str->size));
        if (tmp != nullptr) {
            str->str = tmp;
        } else {
            return EOF;
        }
    }
    str->str[str->size++] = c;
    str->str[str->size] = 0;
    return c;
}
} // namespace ACELite
} // namespace OHOS