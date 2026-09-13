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

#ifndef HILOG_VECTOR_H
#define HILOG_VECTOR_H

namespace OHOS {
namespace ACELite {
enum ValueType {
    NONE_TYPE = 0,
    INT_TYPE,
    STRING_TYPE,
    OBJECT_TYPE,
};

class HilogVector {
public:
    HilogVector();
    ~HilogVector();

    static size_t Size(const HilogVector *vector);
    static char* GetStr(const HilogVector *vector, size_t pos);
    static ValueType GetType(const HilogVector *vector, size_t pos);
    static void Push(HilogVector *vector, const char *element, ValueType type);

private:
    size_t size;
    size_t maxSize;
    char** str;
    ValueType *type;
};
} // namespace ACELite
} // namespace OHOS
#endif  // HILOG_VECTOR_H