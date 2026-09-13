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
#include <vector>
#include "i18n_types.h"
#include "symbol_date_time_format.h"
#include "symboldatetimeformat_fuzzer.h"

namespace OHOS {
namespace Global {
namespace I18n {
    void SymbolDateTimeFormatFuzzTest001(FuzzedDataProvider& provider)
    {
        std::string input = provider.ConsumeRandomLengthString();
        std::vector<std::string> localeTags;
        localeTags.push_back(input);
        std::unordered_map<std::string, std::string> configs;
        configs[input] = input;
        std::string errMessage;

        SymbolDateTimeFormat formatter(localeTags, configs, errMessage);
        formatter.Format(static_cast<double>(provider.remaining_bytes()));
    }

    void SymbolDateTimeFormatFuzzTest002(FuzzedDataProvider& provider)
    {
        std::string input = provider.ConsumeRandomLengthString();
        std::vector<std::string> localeTags;
        localeTags.push_back(input);
        std::unordered_map<std::string, std::string> configs;
        configs["amSymbol"] = input;
        configs["pmSymbol"] = input;
        std::string errMessage;

        SymbolDateTimeFormat formatter(localeTags, configs, errMessage);
        formatter.Format(static_cast<double>(provider.remaining_bytes()));
        formatter.FormatToParts(static_cast<double>(provider.remaining_bytes()), errMessage);
    }

    void SymbolDateTimeFormatFuzzTest003(FuzzedDataProvider& provider)
    {
        std::string input = provider.ConsumeRandomLengthString();
        std::vector<std::string> localeTags;
        localeTags.push_back(input);
        std::unordered_map<std::string, std::string> configs;
        configs["dateStyle"] = "full";
        configs["timeStyle"] = "long";
        configs["amSymbol"] = "AM";
        configs["pmSymbol"] = "PM";
        std::string errMessage;

        SymbolDateTimeFormat formatter(localeTags, configs, errMessage);
        formatter.Format(static_cast<double>(provider.remaining_bytes()));
        formatter.FormatRange(static_cast<double>(provider.remaining_bytes()),
            static_cast<double>(provider.remaining_bytes() + 100), errMessage);
    }

    void SymbolDateTimeFormatFuzzTest004(FuzzedDataProvider& provider)
    {
        std::string input = provider.ConsumeRandomLengthString();
        std::vector<std::string> localeTags;
        localeTags.push_back(input);
        std::unordered_map<std::string, std::string> configs;
        configs["weekday"] = "long";
        configs["era"] = "short";
        configs["year"] = "numeric";
        configs["month"] = "long";
        configs["day"] = "2-digit";
        std::string errMessage;

        SymbolDateTimeFormat formatter(localeTags, configs, errMessage);
        formatter.Format(static_cast<double>(provider.remaining_bytes()));
    }

    void SymbolDateTimeFormatFuzzTest005(FuzzedDataProvider& provider)
    {
        std::string input = provider.ConsumeRandomLengthString();
        std::vector<std::string> localeTags;
        localeTags.push_back(input);
        std::unordered_map<std::string, std::string> configs;
        configs["timeZone"] = input;
        configs["calendar"] = input;
        configs["amSymbol"] = input;
        configs["pmSymbol"] = input;
        std::string errMessage;

        SymbolDateTimeFormat formatter(localeTags, configs, errMessage);
        formatter.Format(static_cast<double>(provider.remaining_bytes()));
        formatter.FormatToParts(static_cast<double>(provider.remaining_bytes()), errMessage);
        formatter.FormatRangeToParts(static_cast<double>(provider.remaining_bytes()),
            static_cast<double>(provider.remaining_bytes() + 100), errMessage);
    }

    bool DoSomethingInterestingWithMyAPI(const uint8_t* data, size_t size)
    {
        if (data == nullptr || size < 1) {
            return false;
        }

        FuzzedDataProvider provider(data, size);
        SymbolDateTimeFormatFuzzTest001(provider);
        SymbolDateTimeFormatFuzzTest002(provider);
        SymbolDateTimeFormatFuzzTest003(provider);
        SymbolDateTimeFormatFuzzTest004(provider);
        SymbolDateTimeFormatFuzzTest005(provider);
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