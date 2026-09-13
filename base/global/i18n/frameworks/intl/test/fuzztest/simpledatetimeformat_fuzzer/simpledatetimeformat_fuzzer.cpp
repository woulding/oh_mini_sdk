/*
 * Copyright (c) 2026 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except", "in compliance with the License.
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

#include <cstddef>
#include <cstdint>
#include <fuzzer/FuzzedDataProvider.h>
#include <map>
#include <memory>
#include <string>
#include "simple_date_time_format.h"
#include "locale_info.h"
#include "simpledatetimeformat_fuzzer.h"

namespace OHOS {
namespace Global {
namespace I18n {
    void SimpleDateTimeFormatFuzzTest001(FuzzedDataProvider& provider)
    {
        std::string input = provider.ConsumeRandomLengthString();
        I18nErrorCode errCode = I18nErrorCode::SUCCESS;
        SimpleDateTimeFormat format(input, "en-US", true, errCode);
        format.Format(1234567890);
    }

    void SimpleDateTimeFormatFuzzTest002(FuzzedDataProvider& provider)
    {
        std::string input = provider.ConsumeRandomLengthString();
        I18nErrorCode errCode = I18nErrorCode::SUCCESS;
        SimpleDateTimeFormat format(input, "zh-CN", false, errCode);
        format.Format(1234567890);
    }

    void SimpleDateTimeFormatFuzzTest003(FuzzedDataProvider& provider)
    {
        std::string input = provider.ConsumeRandomLengthString();
        std::map<std::string, std::string> options;
        options[input] = input;
        std::shared_ptr<LocaleInfo> localeInfo = std::make_shared<LocaleInfo>(input, options);
        I18nErrorCode errCode = I18nErrorCode::SUCCESS;
        SimpleDateTimeFormat format("yyyy-MM-dd", localeInfo, true, errCode);
        format.Format(1234567890);
    }

    void SimpleDateTimeFormatFuzzTest004(FuzzedDataProvider& provider)
    {
        std::string input = provider.ConsumeRandomLengthString();
        I18nErrorCode errCode = I18nErrorCode::SUCCESS;
        SimpleDateTimeFormat format("HH:mm:ss", input, false, errCode);
        format.FormatToParts(1234567890.123);
    }

    void SimpleDateTimeFormatFuzzTest005(FuzzedDataProvider& provider)
    {
        std::string input = provider.ConsumeRandomLengthString();
        double timestamp = provider.ConsumeFloatingPoint<double>();
        I18nErrorCode errCode = I18nErrorCode::SUCCESS;
        SimpleDateTimeFormat format(input, input, false, errCode);
        format.Format(timestamp);
        errCode = I18nErrorCode::SUCCESS;
        SimpleDateTimeFormat formatEn("yyyyMMddHHmmss", "en-US", false, errCode);
        formatEn.Format(0);
        formatEn.Format(-1);
        formatEn.Format(9999999999999);
    }

    void SimpleDateTimeFormatFuzzTest006(FuzzedDataProvider& provider)
    {
        std::string input = provider.ConsumeRandomLengthString();
        I18nErrorCode errCode = I18nErrorCode::SUCCESS;
        SimpleDateTimeFormat format("yyyy年MM月dd日", input, false, errCode);
        format.Format(1609459200000);
    }

    void SimpleDateTimeFormatFuzzTest007(FuzzedDataProvider& provider)
    {
        std::string input = provider.ConsumeRandomLengthString();
        std::map<std::string, std::string> options;
        std::shared_ptr<LocaleInfo> localeInfo = std::make_shared<LocaleInfo>("en-US", options);
        I18nErrorCode errCode = I18nErrorCode::SUCCESS;
        SimpleDateTimeFormat format(input, localeInfo, true, errCode);
        format.FormatToParts(1609459200000.0);
    }

    bool DoSomethingInterestingWithMyAPI(const uint8_t* data, size_t size)
    {
        if (data == nullptr || size < 1) {
            return false;
        }

        FuzzedDataProvider provider(data, size);
        SimpleDateTimeFormatFuzzTest001(provider);
        SimpleDateTimeFormatFuzzTest002(provider);
        SimpleDateTimeFormatFuzzTest003(provider);
        SimpleDateTimeFormatFuzzTest004(provider);
        SimpleDateTimeFormatFuzzTest005(provider);
        SimpleDateTimeFormatFuzzTest006(provider);
        SimpleDateTimeFormatFuzzTest007(provider);
        return true;
    }
}
}
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    OHOS::Global::I18n::DoSomethingInterestingWithMyAPI(data, size);
    return 0;
}