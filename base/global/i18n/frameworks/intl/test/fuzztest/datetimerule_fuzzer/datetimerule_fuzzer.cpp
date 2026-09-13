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
#include <fuzzer/FuzzedDataProvider.h>
#include "locale_config.h"
#include "date_rule_init.h"
#include "date_time_rule.h"

namespace OHOS {
    bool DoSomethingInterestingWithMyAPI(const uint8_t* data, size_t size)
    {
        if (data == nullptr || size < 1) {
            return false;
        }
        FuzzedDataProvider provider(data, size);
        using namespace Global::I18n;
        std::string input = provider.ConsumeRandomLengthString();

        DateRuleInit* dateRuleInit = new DateRuleInit(input);
        icu::UnicodeString message(input.c_str());
        dateRuleInit->Detect(message);

        DateTimeRule* dateTimeRule = new DateTimeRule(input);
        dateTimeRule->GetUniverseRules();
        dateTimeRule->GetLocalesRules();
        dateTimeRule->GetLocalesRulesBackup();
        dateTimeRule->GetSubRulesMap();
        dateTimeRule->GetSubRules();
        dateTimeRule->GetFilterRules();
        dateTimeRule->GetPastRules();
        dateTimeRule->GetParam();
        dateTimeRule->GetParamBackup();
        dateTimeRule->CompareLevel(input, input);
        std::unordered_map<std::string, std::string> param = {
            {input, input}
        };
        dateTimeRule->Get(param, input);
        dateTimeRule->GetLocale();
        icu::UnicodeString hyphen(input.c_str());
        dateTimeRule->IsRelDates(hyphen, input);
        DateTimeRule::trim(input);
        DateTimeRule::CompareBeginEnd(input, input, false);
        delete dateTimeRule;
        delete dateRuleInit;
        return true;
    }
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    OHOS::DoSomethingInterestingWithMyAPI(data, size);
    return 0;
}