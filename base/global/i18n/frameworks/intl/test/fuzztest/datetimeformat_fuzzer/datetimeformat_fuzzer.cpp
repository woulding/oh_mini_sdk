/*
 * Copyright (c) 2022-2024 Huawei Device Co., Ltd.
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
#include <string>
#include "date_time_format.h"
#include "datetimeformat_fuzzer.h"

namespace OHOS {
namespace Global {
namespace I18n {
    void DateTimeFormatFuzzTest001(FuzzedDataProvider& provider)
    {
        std::string input = provider.ConsumeRandomLengthString();
        std::vector<std::string> localeTags;
        localeTags.push_back(input);
        std::map<std::string, std::string> configs;
        configs[input] = input;
        size_t sizeVal = provider.ConsumeIntegral<size_t>();

        DateTimeFormat dateTimeFormat(localeTags, configs);
        dateTimeFormat.Format(sizeVal);
        dateTimeFormat.FormatRange(sizeVal, sizeVal);
        dateTimeFormat.GetResolvedOptions(configs);
        dateTimeFormat.GetDateStyle();
        dateTimeFormat.GetTimeStyle();
        dateTimeFormat.GetHourCycle();
        dateTimeFormat.GetTimeZone();
        dateTimeFormat.GetTimeZoneName();
        dateTimeFormat.GetNumberingSystem();
        dateTimeFormat.GetHour12();
        dateTimeFormat.GetWeekday();
        dateTimeFormat.GetEra();
        dateTimeFormat.GetYear();
        dateTimeFormat.GetMonth();
        dateTimeFormat.GetDay();
        dateTimeFormat.GetHour();
        dateTimeFormat.GetMinute();
        dateTimeFormat.GetSecond();
    }

    void DateTimeFormatFuzzTest002(FuzzedDataProvider& provider)
    {
        std::string input = provider.ConsumeRandomLengthString();
        std::vector<std::string> localeTags;
        localeTags.push_back(input);
        std::map<std::string, std::string> configs;
        size_t sizeVal = provider.ConsumeIntegral<size_t>();

        DateTimeFormat dateTimeFormat(localeTags, configs);
        dateTimeFormat.Format(sizeVal);
        dateTimeFormat.FormatRange(sizeVal, sizeVal);
        dateTimeFormat.GetResolvedOptions(configs);
    }

    void DateTimeFormatFuzzTest003(FuzzedDataProvider& provider)
    {
        std::string input = provider.ConsumeRandomLengthString();
        std::vector<std::string> localeTags;
        localeTags.push_back(input);
        std::map<std::string, std::string> configs;
        configs["dateStyle"] = input;
        configs["timeStyle"] = input;
        size_t sizeVal = provider.ConsumeIntegral<size_t>();

        DateTimeFormat dateTimeFormat(localeTags, configs);
        std::unique_ptr<DateTimeFormat> dtFormat =
            DateTimeFormat::CreateInstance(localeTags, configs);
        if (dtFormat != nullptr) {
            dtFormat->Format(sizeVal);
        }
    }

    bool DoSomethingInterestingWithMyAPI(const uint8_t* data, size_t size)
    {
        if (data == nullptr || size < 1) {
            return false;
        }

        FuzzedDataProvider provider(data, size);
        DateTimeFormatFuzzTest001(provider);
        DateTimeFormatFuzzTest002(provider);
        DateTimeFormatFuzzTest003(provider);
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