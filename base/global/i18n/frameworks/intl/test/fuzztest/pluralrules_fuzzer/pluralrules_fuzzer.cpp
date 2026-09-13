/*
 * Copyright (c) 2023-2024 Huawei Device Co., Ltd.
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
#include "plural_rules.h"
#include "pluralrules_fuzzer.h"

namespace OHOS {
namespace Global {
namespace I18n {

    void PluralRulesFuzzTest001(FuzzedDataProvider& provider)
    {
        std::string input = provider.ConsumeRandomLengthString();
        std::vector<std::string> localeTags;
        localeTags.push_back(input);
        std::map<std::string, std::string> options;
        options[input] = input;

        PluralRules pluralRules(localeTags, options);
        pluralRules.Select(12345.67);
        pluralRules.Select(0);
        pluralRules.Select(-1);
    }

    void PluralRulesFuzzTest002(FuzzedDataProvider& provider)
    {
        std::string input = provider.ConsumeRandomLengthString();
        std::vector<std::string> localeTags;
        localeTags.push_back(input);
        std::map<std::string, std::string> options;
        options["type"] = "cardinal";

        PluralRules pluralRules(localeTags, options);
        double number = provider.ConsumeFloatingPoint<double>();
        pluralRules.Select(number);
    }

    void PluralRulesFuzzTest003(FuzzedDataProvider& provider)
    {
        std::string input = provider.ConsumeRandomLengthString();
        std::vector<std::string> localeTags;
        localeTags.push_back(input);
        std::map<std::string, std::string> options;
        options["type"] = "ordinal";

        PluralRules pluralRules(localeTags, options);
        pluralRules.Select(1);
        pluralRules.Select(2);
        pluralRules.Select(3);
        pluralRules.Select(4);
        pluralRules.Select(11);
    }

    void PluralRulesFuzzTest004(FuzzedDataProvider& provider)
    {
        std::string input = provider.ConsumeRandomLengthString();
        std::vector<std::string> localeTags;
        localeTags.push_back(input);
        std::map<std::string, std::string> options;
        options["minimumIntegerDigits"] = "5";

        PluralRules pluralRules(localeTags, options);
        pluralRules.Select(123);
    }

    void PluralRulesFuzzTest005(FuzzedDataProvider& provider)
    {
        std::string input = provider.ConsumeRandomLengthString();
        std::vector<std::string> localeTags;
        localeTags.push_back(input);
        std::map<std::string, std::string> options;
        options["minimumFractionDigits"] = "3";
        options["maximumFractionDigits"] = "5";

        PluralRules pluralRules(localeTags, options);
        pluralRules.Select(123.456789);
    }

    void PluralRulesFuzzTest006(FuzzedDataProvider& provider)
    {
        std::string input = provider.ConsumeRandomLengthString();
        std::vector<std::string> localeTags;
        localeTags.push_back(input);
        std::map<std::string, std::string> options;
        options["minimumSignificantDigits"] = "3";
        options["maximumSignificantDigits"] = "5";

        PluralRules pluralRules(localeTags, options);
        pluralRules.Select(123.456789);
    }

    void PluralRulesFuzzTest007(FuzzedDataProvider& provider)
    {
        std::string input = provider.ConsumeRandomLengthString();
        std::vector<std::string> localeTags;
        localeTags.push_back(input);
        std::map<std::string, std::string> options;
        options["localeMatcher"] = "lookup";

        PluralRules pluralRules(localeTags, options);
        pluralRules.Select(100);
    }

    bool DoSomethingInterestingWithMyAPI(const uint8_t* data, size_t size)
    {
        if (data == nullptr || size < 1) {
            return false;
        }
        FuzzedDataProvider provider(data, size);

        PluralRulesFuzzTest001(provider);
        PluralRulesFuzzTest002(provider);
        PluralRulesFuzzTest003(provider);
        PluralRulesFuzzTest004(provider);
        PluralRulesFuzzTest005(provider);
        PluralRulesFuzzTest006(provider);
        PluralRulesFuzzTest007(provider);
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