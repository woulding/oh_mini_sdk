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
#include "intl_plural_rules.h"
#include "intlpluralrules_fuzzer.h"

namespace OHOS {
namespace Global {
namespace I18n {
    void IntlPluralRulesFuzzTest001(FuzzedDataProvider& provider)
    {
        std::string input = provider.ConsumeRandomLengthString();
        std::vector<std::string> localeTags;
        localeTags.push_back(input);
        std::unordered_map<std::string, std::string> options;
        ErrorMessage errorMessage;

        IntlPluralRules intlPluralRules(localeTags, options, errorMessage);
        intlPluralRules.Select(static_cast<double>(input.length()), errorMessage);
        intlPluralRules.ResolvedOptions();
    }

    void IntlPluralRulesFuzzTest002(FuzzedDataProvider& provider)
    {
        std::string input = provider.ConsumeRandomLengthString();
        std::vector<std::string> localeTags;
        localeTags.push_back(input);
        std::unordered_map<std::string, std::string> options;
        options[input] = input;
        ErrorMessage errorMessage;

        IntlPluralRules intlPluralRules(localeTags, options, errorMessage);
        intlPluralRules.Select(static_cast<double>(input.length()), errorMessage);
    }

    void IntlPluralRulesFuzzTest003(FuzzedDataProvider& provider)
    {
        std::string input = provider.ConsumeRandomLengthString();
        std::vector<std::string> localeTags;
        localeTags.push_back(input);
        std::unordered_map<std::string, std::string> options;
        options["type"] = "cardinal";
        ErrorMessage errorMessage;

        IntlPluralRules intlPluralRules(localeTags, options, errorMessage);
        intlPluralRules.Select(static_cast<double>(input.length()), errorMessage);
        intlPluralRules.Select(static_cast<double>(input.length() + 1), errorMessage);
        intlPluralRules.ResolvedOptions();
    }

    void IntlPluralRulesFuzzTest004(FuzzedDataProvider& provider)
    {
        std::string input = provider.ConsumeRandomLengthString();
        std::vector<std::string> localeTags;
        localeTags.push_back(input);
        std::unordered_map<std::string, std::string> options;
        options["type"] = "ordinal";
        ErrorMessage errorMessage;

        IntlPluralRules intlPluralRules(localeTags, options, errorMessage);
        intlPluralRules.Select(static_cast<double>(input.length()), errorMessage);
        intlPluralRules.ResolvedOptions();
    }

    void IntlPluralRulesFuzzTest005(FuzzedDataProvider& provider)
    {
        std::string input = provider.ConsumeRandomLengthString();
        std::vector<std::string> localeTags;
        localeTags.push_back(input);
        std::unordered_map<std::string, std::string> options;
        options["minimumIntegerDigits"] = input;
        options["minimumFractionDigits"] = input;
        options["maximumFractionDigits"] = input;
        ErrorMessage errorMessage;

        IntlPluralRules intlPluralRules(localeTags, options, errorMessage);
        intlPluralRules.Select(static_cast<double>(input.length()), errorMessage);
    }

    void IntlPluralRulesFuzzTest006(FuzzedDataProvider& provider)
    {
        std::string input = provider.ConsumeRandomLengthString();
        std::vector<std::string> localeTags;
        localeTags.push_back(input);
        std::unordered_map<std::string, std::string> options;
        options["minimumSignificantDigits"] = input;
        options["maximumSignificantDigits"] = input;
        ErrorMessage errorMessage;

        IntlPluralRules intlPluralRules(localeTags, options, errorMessage);
        intlPluralRules.Select(static_cast<double>(input.length()), errorMessage);
        intlPluralRules.ResolvedOptions();
    }

    void IntlPluralRulesFuzzTest007(FuzzedDataProvider& provider)
    {
        std::string input = provider.ConsumeRandomLengthString();
        std::vector<std::string> localeTags;
        localeTags.push_back(input);
        std::unordered_map<std::string, std::string> options;
        options["localeMatcher"] = "lookup";
        ErrorMessage errorMessage;

        IntlPluralRules::SupportedLocalesOf(localeTags, options, errorMessage);
    }

    void IntlPluralRulesFuzzTest008(FuzzedDataProvider& provider)
    {
        std::string input = provider.ConsumeRandomLengthString();
        std::vector<std::string> localeTags;
        localeTags.push_back(input);
        std::unordered_map<std::string, std::string> options;
        options["localeMatcher"] = "best fit";
        options["type"] = input;
        ErrorMessage errorMessage;

        IntlPluralRules intlPluralRules(localeTags, options, errorMessage);
        intlPluralRules.Select(static_cast<double>(input.length()), errorMessage);
        intlPluralRules.Select(static_cast<double>(input.length() * 2), errorMessage);
        intlPluralRules.Select(static_cast<double>(input.length() / 2), errorMessage);
    }

    bool DoSomethingInterestingWithMyAPI(const uint8_t* data, size_t size)
    {
        if (data == nullptr || size < 1) {
            return false;
        }

        FuzzedDataProvider provider(data, size);
        IntlPluralRulesFuzzTest001(provider);
        IntlPluralRulesFuzzTest002(provider);
        IntlPluralRulesFuzzTest003(provider);
        IntlPluralRulesFuzzTest004(provider);
        IntlPluralRulesFuzzTest005(provider);
        IntlPluralRulesFuzzTest006(provider);
        IntlPluralRulesFuzzTest007(provider);
        IntlPluralRulesFuzzTest008(provider);
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