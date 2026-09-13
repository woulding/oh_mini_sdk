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

#include "hilog_module.h"
#include "hilog_wrapper.h"
#include "securec.h"

namespace OHOS {
namespace ACELite {
namespace {
#define DEFAULT_LOG_TYPE LOG_TYPE_MIN
// log content prefix:"%c %05X/%s: " %05X->domain %s->tag
static const int32_t DOMAIN_LEN = 5;
static const int32_t FIX_LEN = 5;
static const int32_t MIN_DOMAIN = 0x0;
static const int32_t MAX_DOMAIN = 0xFFFF;
static const int32_t MAX_TAG = 32;
static const int32_t MAX_FORMAT = 1024;
static const int32_t MIN_NUMBER = 3;
static const int32_t MAX_NUMBER = 16;
static const int32_t PUBLIC_LEN = 6;
static const int32_t PRIVATE_LEN = 7;
static const int32_t PROPERTY_POS = 2;
static const char PRIV_STR[10] = "<private>";
static const int32_t FIRST = 0;
static const int32_t SECOND = 1;
static const int32_t THIRD = 2;
static const int32_t FOURTH = 3;
static const int32_t FIFTH = 4;
}

void HilogModule::ParseLogContent(const HilogString *formatStr, const HilogVector *params, HilogString *logContent)
{
    if (formatStr == nullptr || params == nullptr || logContent == nullptr) {
        return;
    }
    size_t size = HilogVector::Size(params);
    if (size == 0) {
        HilogString::Puts(HilogString::Get(formatStr), logContent);
        return;
    }
    char *format = HilogString::Get(formatStr);
    if (format == nullptr) {
        return;
    }
    size_t len = HilogString::Length(formatStr);
    size_t pos = 0;
    size_t count = 0;

    for (; pos < len; ++pos) {
        bool showPriv = true;
        if (count > size) {
            break;
        }
        if (format[pos] != '%') {
            HilogString::Putc(format[pos], logContent);
            continue;
        }

        if (((pos + PUBLIC_LEN + PROPERTY_POS) < len) &&
            (strncmp(format + pos + PROPERTY_POS, "public", PUBLIC_LEN) == 0)) {
            pos += (PUBLIC_LEN + PROPERTY_POS);
            showPriv = false;
        } else if (((pos + PRIVATE_LEN + PROPERTY_POS) < len) &&
            (strncmp(format + pos + PROPERTY_POS, "private", PRIVATE_LEN) == 0)) {
            pos += (PRIVATE_LEN + PROPERTY_POS);
        }

        if (pos + 1 >= len) {
            break;
        }
        AddLogContentOutParams outParams = {
            .pos = &pos,
            .count = &count,
            .logContent = logContent,
        };
        AddLogContent(format, params, showPriv, &outParams);
    }
    if (pos < len) {
        HilogString::Puts(format + pos, logContent, len - pos);
    }
    return;
}

void HilogModule::AddLogContent(const char *format, const HilogVector *params, bool showPriv,
    const AddLogContentOutParams *outParams)
{
    if (format == nullptr || outParams == nullptr || params == nullptr || outParams->pos == nullptr ||
        outParams->count == nullptr || outParams->logContent == nullptr) {
        return;
    }
    if ((*(outParams->pos) + 1) >= strlen(format)) {
        return;
    }

    switch (format[*(outParams->pos) + 1]) {
        case 'i':
        case 'd':
            if (HilogVector::GetType(params, *(outParams->count)) == INT_TYPE) {
                HilogString::Puts(
                    showPriv ? PRIV_STR : HilogVector::GetStr(params, *(outParams->count)), outParams->logContent);
            }
            (*(outParams->count))++;
            ++(*(outParams->pos));
            break;
        case 's':
            if (HilogVector::GetType(params, *(outParams->count)) == STRING_TYPE) {
                HilogString::Puts(
                    showPriv ? PRIV_STR : HilogVector::GetStr(params, *(outParams->count)), outParams->logContent);
            }
            (*(outParams->count))++;
            ++(*(outParams->pos));
            break;
        case 'O':
        case 'o':
            if (HilogVector::GetType(params, *(outParams->count)) == OBJECT_TYPE) {
                HilogString::Puts(
                    showPriv ? PRIV_STR : HilogVector::GetStr(params, *(outParams->count)), outParams->logContent);
            }
            (*(outParams->count))++;
            ++(*(outParams->pos));
            break;
        case '%':
            HilogString::Putc(format[*(outParams->pos)], outParams->logContent);
            ++(*(outParams->pos));
            break;
        default:
            HilogString::Putc(format[*(outParams->pos)], outParams->logContent);
            break;
    }
}

JSIValue HilogModule::Debug(const JSIValue thisVal, const JSIValue *args, uint8_t argsNum)
{
    return HilogModule::HilogImpl(thisVal, args, argsNum, LogLevel::LOG_DEBUG);
}

JSIValue HilogModule::Info(const JSIValue thisVal, const JSIValue *args, uint8_t argsNum)
{
    return HilogModule::HilogImpl(thisVal, args, argsNum, LogLevel::LOG_INFO);
}

JSIValue HilogModule::Error(const JSIValue thisVal, const JSIValue *args, uint8_t argsNum)
{
    return HilogModule::HilogImpl(thisVal, args, argsNum, LogLevel::LOG_ERROR);
}

JSIValue HilogModule::Warn(const JSIValue thisVal, const JSIValue *args, uint8_t argsNum)
{
    return HilogModule::HilogImpl(thisVal, args, argsNum, LogLevel::LOG_WARN);
}

JSIValue HilogModule::Fatal(const JSIValue thisVal, const JSIValue *args, uint8_t argsNum)
{
    return HilogModule::HilogImpl(thisVal, args, argsNum, LogLevel::LOG_FATAL);
}

bool HiLogIsLoggable(int32_t domain, const char *tag, LogLevel level)
{
    if ((level < LOG_DEBUG) || (level > LOG_FATAL) || tag == nullptr ||
        domain > MAX_DOMAIN || domain < MIN_DOMAIN) {
        return false;
    }
    return true;
}

JSIValue HilogModule::IsLoggable(const JSIValue thisVal, const JSIValue *args, uint8_t argsNum)
{
    if ((args == nullptr) || (argsNum < MIN_NUMBER) || JSI::ValueIsUndefined(args[FIRST]) ||
         JSI::ValueIsUndefined(args[SECOND]) || JSI::ValueIsUndefined(args[THIRD])) {
        HILOG_HILOGE("IsLoggable: args is invalid.");
        return JSI::CreateBoolean(false);
    }
    if (JSI::ValueIsNull(args[FIRST]) || JSI::ValueIsNull(args[SECOND]) ||
        JSI::ValueIsNull(args[THIRD])) {
        HILOG_HILOGE("IsLoggable: args type is null.");
        return JSI::CreateBoolean(false);
    }
    if (!JSI::ValueIsNumber(args[FIRST]) || !JSI::ValueIsString(args[SECOND]) ||
        !JSI::ValueIsNumber(args[THIRD])) {
        HILOG_HILOGE("IsLoggable: args type is invalid.");
        return JSI::CreateBoolean(false);
    }

    int32_t domain = static_cast<int32_t>(JSI::ValueToNumber(args[FIRST]));
    if (domain > MAX_DOMAIN || domain < MIN_DOMAIN) {
        HILOG_HILOGE("IsLoggable: domain is invalid.");
        return JSI::CreateBoolean(false);
    }
    char *tag = JSI::ValueToString(args[SECOND]);
    if (tag == nullptr || strlen(tag) > MAX_TAG) {
        HILOG_HILOGE("IsLoggable: tag is null or tag > %{public}d.", MAX_TAG);
        return JSI::CreateBoolean(false);
    }
    int32_t level = static_cast<int32_t>(JSI::ValueToNumber(args[THIRD]));
    if (level > LOG_FATAL || level < LOG_DEBUG) {
        HILOG_HILOGE("IsLoggable:level is error.");
        JSI::ReleaseString(tag);
        return JSI::CreateBoolean(false);
    }
    bool res = HiLogIsLoggable(domain, tag, static_cast<LogLevel>(level));
    JSI::ReleaseString(tag);
    return JSI::CreateBoolean(res);
}

void HilogModule::ParseNapiValue(const JSIValue thisVal, const JSIValue *element,  HilogVector *params)
{
    if (element == nullptr || params == nullptr) {
        HILOG_HILOGE("ParseNapiValue: element or params is nullptr.");
        return;
    }
    if (JSI::ValueIsNumber(element[0])) {
        char *value = JSI::JSIValueToString(element[0]);
        HilogVector::Push(params, value, INT_TYPE);
        JSI::ReleaseString(value);
    } else if (JSI::ValueIsString(element[0])) {
        char *value = JSI::ValueToString(element[0]);
        HilogVector::Push(params, value, STRING_TYPE);
        JSI::ReleaseString(value);
    } else if (JSI::ValueIsObject(element[0])) {
        char *value = JSI::JSIValueToString(element[0]);
        HilogVector::Push(params, value, OBJECT_TYPE);
        JSI::ReleaseString(value);
    } else {
        HILOG_HILOGE("ParseNapiValue: type mismatch.");
    }
    return;
}

JSIValue HilogModule::HilogImpl(const JSIValue thisVal, const JSIValue *args, uint8_t argsNum, int level)
{
    JSIValue undefValue = JSI::CreateUndefined();
    if ((args == nullptr) || (argsNum < MIN_NUMBER) || (argsNum > MAX_NUMBER) ||
        JSI::ValueIsUndefined(args[FIRST]) || JSI::ValueIsUndefined(args[SECOND]) ||
        JSI::ValueIsUndefined(args[THIRD]) || JSI::ValueIsNull(args[FIRST]) ||
        JSI::ValueIsNull(args[SECOND]) || JSI::ValueIsNull(args[THIRD])) {
        HILOG_HILOGE("HilogImpl: args is invalid.");
        return undefValue;
    }

    int32_t domain = static_cast<int32_t>(JSI::ValueToNumber(args[FIRST]));
    if (domain > MAX_DOMAIN || domain < MIN_DOMAIN) {
        HILOG_HILOGE("HilogImpl: domain is invalid.");
        return undefValue;
    }
    char *tag = JSI::ValueToString(args[SECOND]);
    if (tag == nullptr || strlen(tag) > MAX_TAG) {
        HILOG_HILOGE("HilogImpl: tag is null or tag > %{public}d.", MAX_TAG);
        return undefValue;
    }
    char *fmtString = JSI::ValueToString(args[THIRD]);
    if (fmtString == nullptr || strlen(fmtString) > MAX_FORMAT) {
        HILOG_HILOGE("HilogImpl: fmtString is null or fmtString > %{public}d.", MAX_FORMAT);
        JSI::ReleaseString(tag);
        return undefValue;
    }

    HilogVector params;
    bool result = HilogImplParseValue(thisVal, args, argsNum, &params);
    if (!result) {
        JSI::ReleaseString(fmtString);
        JSI::ReleaseString(tag);
        return undefValue;
    }
    HilogString fmtStringBuffer;
    HilogString logContent;
    HilogString::Puts(fmtString, &fmtStringBuffer);
    ParseLogContent(&fmtStringBuffer, &params, &logContent);
    if ((HilogString::Length(&logContent) + DOMAIN_LEN + FIX_LEN) + strlen(tag) > (MAX_FORMAT - 1)) {
        HILOG_HILOGE("HilogImpl: log length > %{public}d.", MAX_FORMAT - DOMAIN_LEN - FIX_LEN - strlen(tag) - 1);
        JSI::ReleaseString(fmtString);
        JSI::ReleaseString(tag);
        return undefValue;
    }
    HiLogPrint(DEFAULT_LOG_TYPE, static_cast<LogLevel>(level), domain, tag, HilogString::Get(&logContent), "");
    JSI::ReleaseString(fmtString);
    JSI::ReleaseString(tag);
    return undefValue;
}

bool HilogModule::HilogImplParseValue(
    const JSIValue thisVal, const JSIValue *args, uint8_t argsNum, HilogVector *params)
{
    if (params == nullptr || args == nullptr) {
        return false;
    }
    if (argsNum > MIN_NUMBER && !JSI::ValueIsUndefined(args[FOURTH]) && !JSI::ValueIsNull(args[FOURTH])) {
        if (!JSI::ValueIsArray(args[FOURTH])) {
            for (size_t i = MIN_NUMBER; i < argsNum; i++) {
                ParseNapiValue(thisVal, &args[i], params);
            }
        } else {
            if (argsNum != MIN_NUMBER + 1) {
                HILOG_HILOGE("HilogImplParseValue: args mismatch.");
                return false;
            }
            for (uint32_t i = 0; i < JSI::GetArrayLength(args[FOURTH]); i++) {
                JSIValue element = JSI::GetPropertyByIndex(args[FOURTH], i);
                ParseNapiValue(thisVal, &element, params);
            }
        }
    }
    return true;
}

void InitLogLevelType(JSIValue target)
{
    JSIValue logLevel = JSI::CreateObject();
    JSI::SetNumberProperty(logLevel, "DEBUG", LogLevel::LOG_DEBUG);
    JSI::SetNumberProperty(logLevel, "INFO", LogLevel::LOG_INFO);
    JSI::SetNumberProperty(logLevel, "WARN", LogLevel::LOG_WARN);
    JSI::SetNumberProperty(logLevel, "ERROR", LogLevel::LOG_ERROR);
    JSI::SetNumberProperty(logLevel, "FATAL", LogLevel::LOG_FATAL);
    JSI::SetNamedProperty(target, "LogLevel", logLevel);
}

void InitHilogModule(JSIValue exports)
{
    HILOG_HILOGI("InitHilogModule start");

    InitLogLevelType(exports);
    JSI::SetModuleAPI(exports, "debug", HilogModule::Debug);
    JSI::SetModuleAPI(exports, "info", HilogModule::Info);
    JSI::SetModuleAPI(exports, "error", HilogModule::Error);
    JSI::SetModuleAPI(exports, "warn", HilogModule::Warn);
    JSI::SetModuleAPI(exports, "fatal", HilogModule::Fatal);
    JSI::SetModuleAPI(exports, "isLoggable", HilogModule::IsLoggable);

    HILOG_HILOGI("InitHilogModule end");
}
} // ACELite
} // OHOS