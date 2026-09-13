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

#ifndef HILOG_STRING_H
#define HILOG_STRING_H

#include <cstdlib>

namespace OHOS {
namespace ACELite {
class HilogString {
public:
    HilogString();
    ~HilogString();

    static char *Get(const HilogString *str);
    static size_t Length(const HilogString *str);
    static size_t Puts(const char *src, HilogString *str, size_t strLen = 0);
    static char Putc(char c, HilogString *str);

private:
    size_t size;
    size_t maxSize;
    char *str;
};
} // namespace ACELite
} // namespace OHOS
#endif  // HILOG_STRING_H