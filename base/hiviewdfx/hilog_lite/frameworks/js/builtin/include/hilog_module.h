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

#ifndef HILOG_MODULE_H
#define HILOG_MODULE_H

#include "hilog_string.h"
#include "hilog_vector.h"
#include "jsi/jsi.h"
#include "hilog_string.h"
#include "hilog_vector.h"

namespace OHOS {
namespace ACELite {
typedef struct AddLogContentOutParams {
    size_t *pos;
    size_t *count;
    HilogString *logContent;
} AddLogContentOutParams;

class HilogModule {
public:
    HilogModule() = default;
    ~HilogModule() = default;
    static JSIValue Debug(const JSIValue thisVal, const JSIValue *args, uint8_t argsNum);
    static JSIValue Info(const JSIValue thisVal, const JSIValue *args, uint8_t argsNum);
    static JSIValue Error(const JSIValue thisVal, const JSIValue *args, uint8_t argsNum);
    static JSIValue Warn(const JSIValue thisVal, const JSIValue *args, uint8_t argsNum);
    static JSIValue Fatal(const JSIValue thisVal, const JSIValue *args, uint8_t argsNum);
    static JSIValue IsLoggable(const JSIValue thisVal, const JSIValue *args, uint8_t argsNum);

private:
    static JSIValue HilogImpl(const JSIValue thisVal, const JSIValue *args, uint8_t argsNum, int level);
    static bool HilogImplParseValue(
        const JSIValue thisVal, const JSIValue *args, uint8_t argsNum, HilogVector *params);
    static void ParseNapiValue(const JSIValue thisVal, const JSIValue *element, HilogVector *params);
    static void ParseLogContent(const HilogString *formatStr, const HilogVector *params, HilogString *logContent);
    static void AddLogContent(const char *format, const HilogVector *params, bool showPriv,
        const AddLogContentOutParams *outParams);
};
} // namespace ACELite
} // namespace OHOS

#endif // HILOG_MODULE_H