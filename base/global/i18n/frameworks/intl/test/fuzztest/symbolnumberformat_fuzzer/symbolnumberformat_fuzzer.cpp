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
#include <map>
#include <string>
#include <vector>
#include "i18n_types.h"
#include "symbol_number_format.h"
#include "symbolnumberformat_fuzzer.h"

namespace OHOS {
namespace Global {
namespace I18n {
    void SymbolNumberFormatFuzzTest001(FuzzedDataProvider& provider)
    {
        std::string input = provider.ConsumeRandomLengthString();
        std::vector<std::string> localeTags(1, input);
        std::map<std::string, std::string> configs;
        configs[input] = input;
        std::string errMessage;
        int32_t code = 0;

        SymbolNumberFormat formatter(localeTags, configs, errMessage, code);
        double number = provider.ConsumeFloatingPoint<double>();
        formatter.FormatToPartsDouble(number);
        formatter.FormatToPartsDecStr(input);
    }

    void SymbolNumberFormatFuzzTest002(FuzzedDataProvider& provider)
    {
        std::string input = provider.ConsumeRandomLengthString();
        std::vector<std::string> localeTags(1, input);
        std::map<std::string, std::string> configs;
        configs["style"] = "currency";
        configs["currency"] = input;
        std::string errMessage;
        int32_t code = 0;

        SymbolNumberFormat formatter(localeTags, configs, errMessage, code);
        formatter.FormatToPartsDouble(12345.67);
        formatter.FormatRangeDoubleDouble(100.0, 200.0);
        formatter.FormatRangeDoubleDecStr(100.0, "200");
        formatter.FormatRangeDecStrDouble("100", 200.0);
        formatter.FormatRangeDecStrDecStr("100", "200");
    }

    void SymbolNumberFormatFuzzTest003(FuzzedDataProvider& provider)
    {
        std::string input = provider.ConsumeRandomLengthString();
        std::vector<std::string> localeTags(1, input);
        std::map<std::string, std::string> configs;
        configs["style"] = "decimal";
        configs["groupingSymbol"] = input;
        configs["infinitySymbol"] = input;
        configs["plusSymbol"] = input;
        configs["minusSymbol"] = input;
        std::string errMessage;
        int32_t code = 0;

        SymbolNumberFormat formatter(localeTags, configs, errMessage, code);
        formatter.FormatToPartsDouble(std::numeric_limits<double>::infinity());
        formatter.FormatToPartsDouble(-std::numeric_limits<double>::infinity());
        formatter.FormatToPartsDouble(std::numeric_limits<double>::quiet_NaN());
    }

    void SymbolNumberFormatFuzzTest004(FuzzedDataProvider& provider)
    {
        std::string input = provider.ConsumeRandomLengthString();
        std::vector<std::string> localeTags(1, input);
        std::map<std::string, std::string> configs;
        configs["style"] = "percent";
        std::string errMessage;
        int32_t code = 0;

        SymbolNumberFormat formatter(localeTags, configs, errMessage, code);
        formatter.FormatToPartsDouble(0.123);
        formatter.FormatToRangePartsDoubleDouble(0.1, 0.2);
        formatter.FormatToRangePartsDoubleDecStr(0.1, "0.2");
        formatter.FormatToRangePartsDecStrDouble("0.1", 0.2);
        formatter.FormatToRangePartsDecStrDecStr("0.1", "0.2");
    }

    void SymbolNumberFormatFuzzTest005(FuzzedDataProvider& provider)
    {
        std::string input = provider.ConsumeRandomLengthString();
        std::vector<std::string> localeTags(1, input);
        std::map<std::string, std::string> configs;
        configs["notation"] = "scientific";
        std::string errMessage;
        int32_t code = 0;

        SymbolNumberFormat formatter(localeTags, configs, errMessage, code);
        formatter.FormatToPartsDouble(12345.67);
        formatter.FormatToPartsDecStr("12345678901234567890");
    }

    void SymbolNumberFormatFuzzTest006(FuzzedDataProvider& provider)
    {
        std::string input = provider.ConsumeRandomLengthString();
        std::vector<std::string> localeTags(1, input);
        std::map<std::string, std::string> configs;
        configs["style"] = "unit";
        configs["unit"] = input;
        configs["unitDisplay"] = "long";
        std::string errMessage;
        int32_t code = 0;

        SymbolNumberFormat formatter(localeTags, configs, errMessage, code);
        formatter.FormatToPartsDouble(12345.67);
        formatter.FormatRangeDoubleDouble(1000.0, 2000.0);
    }

    bool DoSomethingInterestingWithMyAPI(const uint8_t* data, size_t size)
    {
        if (data == nullptr || size < 1) {
            return false;
        }

        FuzzedDataProvider provider(data, size);
        SymbolNumberFormatFuzzTest001(provider);
        SymbolNumberFormatFuzzTest002(provider);
        SymbolNumberFormatFuzzTest003(provider);
        SymbolNumberFormatFuzzTest004(provider);
        SymbolNumberFormatFuzzTest005(provider);
        SymbolNumberFormatFuzzTest006(provider);
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