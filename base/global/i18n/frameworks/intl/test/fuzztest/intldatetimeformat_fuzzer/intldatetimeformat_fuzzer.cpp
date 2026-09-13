/*
 * Copyright (c) 2026 Huawei Device Co., Ltd.
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

#include <cstddef>
#include <cstdint>
#include <fuzzer/FuzzedDataProvider.h>
#include <string>
#include <unordered_map>
#include "intl_date_time_format.h"
#include "intldatetimeformat_fuzzer.h"

namespace OHOS {
namespace Global {
namespace I18n {
    void IntlDateTimeFormatFuzzTest001(FuzzedDataProvider& provider)
    {
        std::string input = provider.ConsumeRandomLengthString();
        std::vector<std::string> localeTags;
        localeTags.push_back(input);
        std::unordered_map<std::string, std::string> configs;
        configs[input] = input;
        std::string errMessage;
        size_t sizeVal = provider.ConsumeIntegral<size_t>();

        IntlDateTimeFormat intlDateTimeFormat(localeTags, configs, errMessage);
        intlDateTimeFormat.Format(static_cast<double>(sizeVal));
        intlDateTimeFormat.FormatRange(static_cast<double>(sizeVal), static_cast<double>(sizeVal + 100), errMessage);
        intlDateTimeFormat.ResolvedOptions(configs);
    }

    void IntlDateTimeFormatFuzzTest002(FuzzedDataProvider& provider)
    {
        std::string input = provider.ConsumeRandomLengthString();
        std::vector<std::string> localeTags;
        localeTags.push_back(input);
        std::unordered_map<std::string, std::string> configs;
        std::string errMessage;
        size_t sizeVal = provider.ConsumeIntegral<size_t>();

        IntlDateTimeFormat intlDateTimeFormat(localeTags, configs, errMessage);
        intlDateTimeFormat.Format(static_cast<double>(sizeVal));
        intlDateTimeFormat.FormatToParts(static_cast<double>(sizeVal), errMessage);
    }

    void IntlDateTimeFormatFuzzTest003(FuzzedDataProvider& provider)
    {
        std::string input = provider.ConsumeRandomLengthString();
        std::vector<std::string> localeTags;
        localeTags.push_back(input);
        std::unordered_map<std::string, std::string> configs;
        configs["dateStyle"] = input;
        configs["timeStyle"] = input;
        std::string errMessage;
        size_t sizeVal = provider.ConsumeIntegral<size_t>();

        IntlDateTimeFormat intlDateTimeFormat(localeTags, configs, errMessage);
        intlDateTimeFormat.FormatToParts(static_cast<double>(sizeVal), errMessage);
        intlDateTimeFormat.FormatRangeToParts(static_cast<double>(sizeVal),
            static_cast<double>(sizeVal + 100), errMessage);
    }

    void IntlDateTimeFormatFuzzTest004(FuzzedDataProvider& provider)
    {
        std::string input = provider.ConsumeRandomLengthString();
        std::vector<std::string> localeTags;
        localeTags.push_back(input);
        std::unordered_map<std::string, std::string> configs;
        configs["hourCycle"] = input;
        configs["timeZone"] = input;
        configs["calendar"] = input;
        std::string errMessage;
        size_t sizeVal = provider.ConsumeIntegral<size_t>();

        IntlDateTimeFormat intlDateTimeFormat(localeTags, configs, errMessage);
        intlDateTimeFormat.Format(static_cast<double>(sizeVal));
    }

    void IntlDateTimeFormatFuzzTest005(FuzzedDataProvider& provider)
    {
        std::string input = provider.ConsumeRandomLengthString();
        std::vector<std::string> localeTags;
        localeTags.push_back(input);
        std::unordered_map<std::string, std::string> configs;
        configs["weekday"] = input;
        configs["era"] = input;
        configs["year"] = input;
        configs["month"] = input;
        configs["day"] = input;
        configs["hour"] = input;
        configs["minute"] = input;
        configs["second"] = input;
        std::string errMessage;
        size_t sizeVal = provider.ConsumeIntegral<size_t>();

        IntlDateTimeFormat intlDateTimeFormat(localeTags, configs, errMessage);
        intlDateTimeFormat.Format(static_cast<double>(sizeVal));
    }

    void IntlDateTimeFormatFuzzTest006(FuzzedDataProvider& provider)
    {
        std::string input = provider.ConsumeRandomLengthString();
        std::vector<std::string> localeTags;
        localeTags.push_back(input);
        std::map<std::string, std::string> configs;
        std::string errMessage;

        I18nErrorCode status = I18nErrorCode::SUCCESS;
        IntlDateTimeFormat::SupportedLocalesOf(localeTags, configs, status);
    }

    void IntlDateTimeFormatFuzzTest007(FuzzedDataProvider& provider)
    {
        std::string input = provider.ConsumeRandomLengthString();
        std::vector<std::string> localeTags;
        localeTags.push_back(input);
        std::unordered_map<std::string, std::string> configs;
        configs["numberingSystem"] = input;
        configs["fractionalSecondDigits"] = input;
        std::string errMessage;
        size_t sizeVal = provider.ConsumeIntegral<size_t>();

        IntlDateTimeFormat intlDateTimeFormat(localeTags, configs, errMessage);
        intlDateTimeFormat.Format(static_cast<double>(sizeVal));
    }

    bool DoSomethingInterestingWithMyAPI(const uint8_t* data, size_t size)
    {
        if (data == nullptr || size < 1) {
            return false;
        }

        FuzzedDataProvider provider(data, size);
        IntlDateTimeFormatFuzzTest001(provider);
        IntlDateTimeFormatFuzzTest002(provider);
        IntlDateTimeFormatFuzzTest003(provider);
        IntlDateTimeFormatFuzzTest004(provider);
        IntlDateTimeFormatFuzzTest005(provider);
        IntlDateTimeFormatFuzzTest006(provider);
        IntlDateTimeFormatFuzzTest007(provider);
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