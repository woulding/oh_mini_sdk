/*
 * Copyright (c) 2022 Huawei Device Co., Ltd.
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
#include <map>
#include <string>
#include <vector>
#include <fuzzer/FuzzedDataProvider.h>
#include "number_format.h"
#include "numberformat_fuzzer.h"

namespace OHOS {
namespace Global {
namespace I18n {

    void NumberFormatFuzzTest001(FuzzedDataProvider& provider)
    {
        std::string input = provider.ConsumeRandomLengthString();
        std::vector<std::string> localeTags(1, input);
        std::map<std::string, std::string> options;
        options[input] = input;

        NumberFormat formatter(localeTags, options);
        double number = provider.ConsumeFloatingPoint<double>();
        formatter.Format(number);
        formatter.GetResolvedOptions(options);
        formatter.GetCurrency();
        formatter.GetCurrencySign();
        formatter.GetStyle();
        formatter.GetNumberingSystem();
        formatter.GetUseGrouping();
        formatter.GetMinimumIntegerDigits();
        formatter.GetMinimumFractionDigits();
        formatter.GetMaximumFractionDigits();
        formatter.GetMinimumSignificantDigits();
        formatter.GetMaximumSignificantDigits();
        formatter.GetLocaleMatcher();
    }

    void NumberFormatFuzzTest002(FuzzedDataProvider& provider)
    {
        std::string input = provider.ConsumeRandomLengthString();
        std::vector<std::string> localeTags(1, input);
        std::map<std::string, std::string> options;
        options["style"] = "currency";
        options["currency"] = input;

        NumberFormat formatter(localeTags, options);
        formatter.Format(12345.67);
        formatter.GetCurrency();
        formatter.GetStyle();
    }

    void NumberFormatFuzzTest003(FuzzedDataProvider& provider)
    {
        std::string input = provider.ConsumeRandomLengthString();
        std::vector<std::string> localeTags(1, input);
        std::map<std::string, std::string> options;
        options["style"] = "unit";
        options["unit"] = input;
        options["unitDisplay"] = "long";

        NumberFormat formatter(localeTags, options);
        formatter.Format(12345.67);
        formatter.GetStyle();
    }

    void NumberFormatFuzzTest004(FuzzedDataProvider& provider)
    {
        std::string input = provider.ConsumeRandomLengthString();
        std::vector<std::string> localeTags(1, input);
        std::map<std::string, std::string> options;
        options["style"] = "percent";

        NumberFormat formatter(localeTags, options);
        formatter.Format(0.123);
        formatter.GetStyle();
    }

    void NumberFormatFuzzTest005(FuzzedDataProvider& provider)
    {
        std::string input = provider.ConsumeRandomLengthString();
        std::vector<std::string> localeTags(1, input);
        std::map<std::string, std::string> options;
        options["notation"] = "scientific";

        NumberFormat formatter(localeTags, options);
        formatter.Format(12345.67);
    }

    void NumberFormatFuzzTest006(FuzzedDataProvider& provider)
    {
        std::string input = provider.ConsumeRandomLengthString();
        std::vector<std::string> localeTags(1, input);
        std::map<std::string, std::string> options;
        options["notation"] = "engineering";

        NumberFormat formatter(localeTags, options);
        formatter.Format(12345.67);
    }

    void NumberFormatFuzzTest007(FuzzedDataProvider& provider)
    {
        std::string input = provider.ConsumeRandomLengthString();
        std::vector<std::string> localeTags(1, input);
        std::map<std::string, std::string> options;
        options["notation"] = "compact";
        options["compactDisplay"] = "long";

        NumberFormat formatter(localeTags, options);
        formatter.Format(1234567.89);
    }

    void NumberFormatFuzzTest008(FuzzedDataProvider& provider)
    {
        std::string input = provider.ConsumeRandomLengthString();
        std::vector<std::string> localeTags(1, input);
        std::map<std::string, std::string> options;
        options["minimumSignificantDigits"] = "3";
        options["maximumSignificantDigits"] = "5";

        NumberFormat formatter(localeTags, options);
        formatter.Format(123.45678);
        formatter.GetMinimumSignificantDigits();
        formatter.GetMaximumSignificantDigits();
    }

    void NumberFormatFuzzTest009(FuzzedDataProvider& provider)
    {
        std::string input = provider.ConsumeRandomLengthString();
        std::vector<std::string> localeTags(1, input);
        std::map<std::string, std::string> options;
        options["minimumIntegerDigits"] = "5";

        NumberFormat formatter(localeTags, options);
        formatter.Format(123);
        formatter.GetMinimumIntegerDigits();
    }

    void NumberFormatFuzzTest010(FuzzedDataProvider& provider)
    {
        std::string input = provider.ConsumeRandomLengthString();
        std::vector<std::string> localeTags(1, input);
        std::map<std::string, std::string> options;
        options["roundingMode"] = "ceil";

        NumberFormat formatter(localeTags, options);
        formatter.Format(123.456);
    }

    void NumberFormatFuzzTest011(FuzzedDataProvider& provider)
    {
        std::string input = provider.ConsumeRandomLengthString();
        std::vector<std::string> localeTags(1, input);
        std::map<std::string, std::string> options;
        options["roundingPriority"] = "morePrecision";

        NumberFormat formatter(localeTags, options);
        formatter.Format(123.456);
    }

    void NumberFormatFuzzTest012(FuzzedDataProvider& provider)
    {
        std::string input = provider.ConsumeRandomLengthString();
        std::vector<std::string> localeTags(1, input);
        std::map<std::string, std::string> options;
        options["roundingIncrement"] = "5";

        NumberFormat formatter(localeTags, options);
        formatter.Format(123.456);
    }

    void NumberFormatFuzzTest013(FuzzedDataProvider& provider)
    {
        std::string input = provider.ConsumeRandomLengthString();
        std::vector<std::string> localeTags(1, input);
        std::map<std::string, std::string> options;
        options["signDisplay"] = "always";

        NumberFormat formatter(localeTags, options);
        formatter.Format(123.456);
    }

    void NumberFormatFuzzTest014(FuzzedDataProvider& provider)
    {
        std::string input = provider.ConsumeRandomLengthString();
        std::vector<std::string> localeTags(1, input);
        std::map<std::string, std::string> options;
        options["currencySign"] = "accounting";
        options["style"] = "currency";
        options["currency"] = "USD";

        NumberFormat formatter(localeTags, options);
        formatter.Format(-123.45);
    }

    void NumberFormatFuzzTest015(FuzzedDataProvider& provider)
    {
        std::string input = provider.ConsumeRandomLengthString();
        std::vector<std::string> localeTags(1, input);
        std::map<std::string, std::string> options;
        options["numberingSystem"] = input;

        NumberFormat formatter(localeTags, options);
        formatter.Format(12345);
    }

    bool DoSomethingInterestingWithMyAPI(const uint8_t* data, size_t size)
    {
        if (data == nullptr || size < 1) {
            return false;
        }
        FuzzedDataProvider provider(data, size);

        NumberFormatFuzzTest001(provider);
        NumberFormatFuzzTest002(provider);
        NumberFormatFuzzTest003(provider);
        NumberFormatFuzzTest004(provider);
        NumberFormatFuzzTest005(provider);
        NumberFormatFuzzTest006(provider);
        NumberFormatFuzzTest007(provider);
        NumberFormatFuzzTest008(provider);
        NumberFormatFuzzTest009(provider);
        NumberFormatFuzzTest010(provider);
        NumberFormatFuzzTest011(provider);
        NumberFormatFuzzTest012(provider);
        NumberFormatFuzzTest013(provider);
        NumberFormatFuzzTest014(provider);
        NumberFormatFuzzTest015(provider);
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