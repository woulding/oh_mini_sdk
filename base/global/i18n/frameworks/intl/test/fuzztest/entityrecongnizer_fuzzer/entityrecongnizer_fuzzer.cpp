/*
 * Copyright (c) 2023 Huawei Device Co., Ltd.
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
#include <unordered_map>
#include <vector>
#include "entity_recognizer.h"
#include "date_time_matched.h"
#include "phone_number_matched.h"
#include "date_time_rule.h"
#include "phone_number_rule.h"
#include "rules_engine.h"
#include "date_time_filter.h"
#include "matched_date_time_info.h"
#include "entityrecongnizer_fuzzer.h"

namespace OHOS {
namespace Global {
namespace I18n {
    void EntityRecognizerFuzzTest001(FuzzedDataProvider& provider)
    {
        std::string input = provider.ConsumeRandomLengthString();
        UErrorCode status = U_ZERO_ERROR;
        icu::Locale locale = icu::Locale::forLanguageTag(input, status);
        EntityRecognizer entityRecognizer(locale);
        entityRecognizer.FindEntityInfo(input);
    }

    void EntityRecognizerFuzzTest002(FuzzedDataProvider& provider)
    {
        std::string input = provider.ConsumeRandomLengthString();
        UErrorCode status = U_ZERO_ERROR;
        icu::Locale locale = icu::Locale::forLanguageTag("en-US", status);
        EntityRecognizer entityRecognizer(locale);
        entityRecognizer.FindEntityInfo(input);
    }

    void EntityRecognizerFuzzTest003(FuzzedDataProvider& provider)
    {
        std::string input = provider.ConsumeRandomLengthString();
        UErrorCode status = U_ZERO_ERROR;
        icu::Locale locale = icu::Locale::forLanguageTag("zh-CN", status);
        EntityRecognizer entityRecognizer(locale);
        entityRecognizer.FindEntityInfo(input);
    }

    void EntityRecognizerFuzzTest004(FuzzedDataProvider& provider)
    {
        std::string input = provider.ConsumeRandomLengthString();
        std::string phoneNumberText = "Call me at 13800138000";
        UErrorCode status = U_ZERO_ERROR;
        icu::Locale locale = icu::Locale::forLanguageTag(input, status);
        EntityRecognizer entityRecognizer(locale);
        entityRecognizer.FindEntityInfo(phoneNumberText);
    }

    void EntityRecognizerFuzzTest005(FuzzedDataProvider& provider)
    {
        std::string input = provider.ConsumeRandomLengthString();
        std::string dateTimeText = "Meet me on 2023-12-25 at 10:30 AM";
        UErrorCode status = U_ZERO_ERROR;
        icu::Locale locale = icu::Locale::forLanguageTag(input, status);
        EntityRecognizer entityRecognizer(locale);
        entityRecognizer.FindEntityInfo(dateTimeText);
    }

    void DateTimeMatchedFuzzTest001(FuzzedDataProvider& provider)
    {
        std::string input = provider.ConsumeRandomLengthString();
        DateTimeMatched dateTimeMatched(input);
        icu::UnicodeString message(input.c_str());
        dateTimeMatched.GetMatchedDateTime(message);
    }

    void DateTimeMatchedFuzzTest002(FuzzedDataProvider& provider)
    {
        std::string locale = "en";
        DateTimeMatched dateTimeMatched(locale);
        std::string input = provider.ConsumeRandomLengthString();
        icu::UnicodeString message(input.c_str());
        dateTimeMatched.GetMatchedDateTime(message);
    }

    void DateTimeMatchedFuzzTest003(FuzzedDataProvider& provider)
    {
        std::string locale = "zh";
        DateTimeMatched dateTimeMatched(locale);
        std::string input = provider.ConsumeRandomLengthString();
        icu::UnicodeString message(input.c_str());
        dateTimeMatched.GetMatchedDateTime(message);
    }

    void DateTimeMatchedFuzzTest004(FuzzedDataProvider& provider)
    {
        std::string locale = "ja";
        DateTimeMatched dateTimeMatched(locale);
        std::string input = provider.ConsumeRandomLengthString();
        icu::UnicodeString message(input.c_str());
        dateTimeMatched.GetMatchedDateTime(message);
    }

    void DateTimeMatchedFuzzTest005(FuzzedDataProvider& provider)
    {
        std::string locale = "de";
        DateTimeMatched dateTimeMatched(locale);
        std::string input = provider.ConsumeRandomLengthString();
        icu::UnicodeString message(input.c_str());
        dateTimeMatched.GetMatchedDateTime(message);
    }

    void DateTimeMatchedFuzzTest006(FuzzedDataProvider& provider)
    {
        std::string input = provider.ConsumeRandomLengthString();
        DateTimeMatched dateTimeMatched(input);
        std::string dateTimeText = "2024-01-15 14:30:00";
        icu::UnicodeString message(dateTimeText.c_str());
        dateTimeMatched.GetMatchedDateTime(message);
    }

    void DateTimeMatchedFuzzTest007(FuzzedDataProvider& provider)
    {
        std::string input = provider.ConsumeRandomLengthString();
        DateTimeMatched dateTimeMatched(input);
        std::string chineseText = "今天是2023年12月25日，明天是2024年1月1日";
        icu::UnicodeString message(chineseText.c_str());
        dateTimeMatched.GetMatchedDateTime(message);
    }

    void PhoneNumberMatchedFuzzTest001(FuzzedDataProvider& provider)
    {
        std::string input = provider.ConsumeRandomLengthString();
        PhoneNumberMatched phoneNumberMatched(input);
        icu::UnicodeString message(input.c_str());
        phoneNumberMatched.GetMatchedPhoneNumber(message);
    }

    void PhoneNumberMatchedFuzzTest002(FuzzedDataProvider& provider)
    {
        std::string country = "CN";
        PhoneNumberMatched phoneNumberMatched(country);
        std::string input = provider.ConsumeRandomLengthString();
        icu::UnicodeString message(input.c_str());
        phoneNumberMatched.GetMatchedPhoneNumber(message);
    }

    void PhoneNumberMatchedFuzzTest003(FuzzedDataProvider& provider)
    {
        std::string country = "US";
        PhoneNumberMatched phoneNumberMatched(country);
        std::string input = provider.ConsumeRandomLengthString();
        icu::UnicodeString message(input.c_str());
        phoneNumberMatched.GetMatchedPhoneNumber(message);
    }

    void PhoneNumberMatchedFuzzTest004(FuzzedDataProvider& provider)
    {
        std::string country = "GB";
        PhoneNumberMatched phoneNumberMatched(country);
        std::string input = provider.ConsumeRandomLengthString();
        icu::UnicodeString message(input.c_str());
        phoneNumberMatched.GetMatchedPhoneNumber(message);
    }

    void PhoneNumberMatchedFuzzTest005(FuzzedDataProvider& provider)
    {
        std::string country = "JP";
        PhoneNumberMatched phoneNumberMatched(country);
        std::string input = provider.ConsumeRandomLengthString();
        icu::UnicodeString message(input.c_str());
        phoneNumberMatched.GetMatchedPhoneNumber(message);
    }

    void PhoneNumberMatchedFuzzTest006(FuzzedDataProvider& provider)
    {
        std::string input = provider.ConsumeRandomLengthString();
        PhoneNumberMatched phoneNumberMatched(input);
        std::string phoneNumberText = "Call me at 13800138000 or 010-12345678";
        icu::UnicodeString message(phoneNumberText.c_str());
        phoneNumberMatched.GetMatchedPhoneNumber(message);
    }

    void PhoneNumberMatchedFuzzTest007(FuzzedDataProvider& provider)
    {
        std::string input = provider.ConsumeRandomLengthString();
        PhoneNumberMatched phoneNumberMatched(input);
        std::string internationalText = "International: +86 139 1234 5678, +1 555 123 4567";
        icu::UnicodeString message(internationalText.c_str());
        phoneNumberMatched.GetMatchedPhoneNumber(message);
    }

    void PhoneNumberMatchedFuzzTest008(FuzzedDataProvider& provider)
    {
        std::string input = provider.ConsumeRandomLengthString();
        PhoneNumberMatched phoneNumberMatched(input);
        std::string shortNumberText = "Short numbers: 110, 119, 120, 911";
        icu::UnicodeString message(shortNumberText.c_str());
        phoneNumberMatched.GetMatchedPhoneNumber(message);
    }

    void DateTimeRuleFuzzTest001(FuzzedDataProvider& provider)
    {
        std::string input = provider.ConsumeRandomLengthString();
        DateTimeRule dateTimeRule(input);
        dateTimeRule.GetUniverseRules();
        dateTimeRule.GetLocalesRules();
    }

    void DateTimeRuleFuzzTest002(FuzzedDataProvider& provider)
    {
        std::string input = provider.ConsumeRandomLengthString();
        DateTimeRule dateTimeRule(input);
        dateTimeRule.GetSubRules();
        dateTimeRule.GetFilterRules();
    }

    void DateTimeRuleFuzzTest003(FuzzedDataProvider& provider)
    {
        std::string input = provider.ConsumeRandomLengthString();
        DateTimeRule dateTimeRule(input);
        dateTimeRule.GetParam();
        dateTimeRule.GetParamBackup();
    }

    void DateTimeRuleFuzzTest004(FuzzedDataProvider& provider)
    {
        std::string input = provider.ConsumeRandomLengthString();
        DateTimeRule dateTimeRule(input);
        dateTimeRule.GetLocale();
        std::string key1 = "key1";
        std::string key2 = "key2";
        dateTimeRule.CompareLevel(key1, key2);
    }

    void DateTimeRuleFuzzTest005(FuzzedDataProvider& provider)
    {
        std::string input = provider.ConsumeRandomLengthString();
        DateTimeRule dateTimeRule(input);
        std::unordered_map<std::string, std::string> param = dateTimeRule.GetParam();
        std::string ruleName = "test_rule";
        dateTimeRule.Get(param, ruleName);
    }

    void DateTimeRuleFuzzTest006(FuzzedDataProvider& provider)
    {
        std::string locale = "en";
        DateTimeRule dateTimeRule(locale);
        std::string input = provider.ConsumeRandomLengthString();
        icu::UnicodeString hyphen(input.c_str());
        dateTimeRule.IsRelDates(hyphen, locale);
    }

    void DateTimeRuleFuzzTest007(FuzzedDataProvider& provider)
    {
        std::string locale = "zh";
        DateTimeRule dateTimeRule(locale);
        std::string input = provider.ConsumeRandomLengthString();
        icu::UnicodeString hyphen(input.c_str());
        dateTimeRule.IsRelDates(hyphen, locale);
    }

    void PhoneNumberRuleFuzzTest001(FuzzedDataProvider& provider)
    {
        std::string input = provider.ConsumeRandomLengthString();
        PhoneNumberRule phoneNumberRule(input);
        phoneNumberRule.GetBorderRules();
        phoneNumberRule.GetCodesRules();
    }

    void PhoneNumberRuleFuzzTest002(FuzzedDataProvider& provider)
    {
        std::string input = provider.ConsumeRandomLengthString();
        PhoneNumberRule phoneNumberRule(input);
        phoneNumberRule.GetPositiveRules();
        phoneNumberRule.GetNegativeRules();
    }

    void PhoneNumberRuleFuzzTest003(FuzzedDataProvider& provider)
    {
        std::string input = provider.ConsumeRandomLengthString();
        PhoneNumberRule phoneNumberRule(input);
        phoneNumberRule.GetFindRules();
    }

    void PhoneNumberRuleFuzzTest004(FuzzedDataProvider& provider)
    {
        std::string input = provider.ConsumeRandomLengthString();
        PhoneNumberRule phoneNumberRule(input);
        phoneNumberRule.GetBorderRules();
        input = "CN";
        phoneNumberRule = PhoneNumberRule(input);
        phoneNumberRule.GetBorderRules();
    }

    void PhoneNumberRuleFuzzTest005(FuzzedDataProvider& provider)
    {
        std::string input = provider.ConsumeRandomLengthString();
        PhoneNumberRule phoneNumberRule(input);
        phoneNumberRule.GetCodesRules();
        input = "US";
        phoneNumberRule = PhoneNumberRule(input);
        phoneNumberRule.GetCodesRules();
    }

    void PhoneNumberRuleFuzzTest006(FuzzedDataProvider& provider)
    {
        std::string input = provider.ConsumeRandomLengthString();
        PhoneNumberRule phoneNumberRule(input);
        phoneNumberRule.GetPositiveRules();
        input = "GB";
        phoneNumberRule = PhoneNumberRule(input);
        phoneNumberRule.GetPositiveRules();
    }

    void PhoneNumberRuleFuzzTest007(FuzzedDataProvider& provider)
    {
        std::string input = provider.ConsumeRandomLengthString();
        PhoneNumberRule phoneNumberRule(input);
        phoneNumberRule.GetNegativeRules();
        input = "JP";
        phoneNumberRule = PhoneNumberRule(input);
        phoneNumberRule.GetNegativeRules();
    }

    void RulesEngineFuzzTest001(FuzzedDataProvider& provider)
    {
        std::string input = provider.ConsumeRandomLengthString();
        std::unordered_map<std::string, std::string> rulesMap;
        rulesMap[input] = input;
        std::unordered_map<std::string, std::string> subRules;
        std::unordered_map<std::string, std::string> param;
        std::unordered_map<std::string, std::string> paramBackup;
        RulesSet rulesSet(rulesMap, subRules, param, paramBackup);
        std::string locale = "en";
        DateTimeRule dateTimeRule(locale);
        RulesEngine rulesEngine(&dateTimeRule, rulesSet);
        icu::UnicodeString message(input.c_str());
        rulesEngine.Match(message);
    }

    void RulesEngineFuzzTest002(FuzzedDataProvider& provider)
    {
        std::string locale = "en";
        DateTimeRule dateTimeRule(locale);
        std::string input = provider.ConsumeRandomLengthString();
        std::unordered_map<std::string, std::string> rulesMap = dateTimeRule.GetLocalesRules();
        std::unordered_map<std::string, std::string> subRules = dateTimeRule.GetSubRules();
        std::unordered_map<std::string, std::string> param = dateTimeRule.GetParam();
        std::unordered_map<std::string, std::string> paramBackup = dateTimeRule.GetParamBackup();
        RulesSet rulesSet(rulesMap, subRules, param, paramBackup);
        RulesEngine rulesEngine(&dateTimeRule, rulesSet);
        icu::UnicodeString message(input.c_str());
        rulesEngine.Match(message);
    }

    void RulesEngineFuzzTest003(FuzzedDataProvider& provider)
    {
        std::string locale = "zh";
        DateTimeRule dateTimeRule(locale);
        std::string input = provider.ConsumeRandomLengthString();
        std::unordered_map<std::string, std::string> rulesMap = dateTimeRule.GetLocalesRules();
        std::unordered_map<std::string, std::string> subRules = dateTimeRule.GetSubRules();
        std::unordered_map<std::string, std::string> param = dateTimeRule.GetParam();
        RulesSet rulesSet(rulesMap, subRules, param, param);
        RulesEngine rulesEngine(&dateTimeRule, rulesSet);
        icu::UnicodeString message(input.c_str());
        rulesEngine.Match(message);
    }

    void RulesEngineFuzzTest004(FuzzedDataProvider& provider)
    {
        RulesEngine rulesEngine;
        std::string input = provider.ConsumeRandomLengthString();
        icu::UnicodeString message(input.c_str());
        rulesEngine.Match(message);
    }

    void RulesEngineFuzzTest005(FuzzedDataProvider& provider)
    {
        std::string locale = "ja";
        DateTimeRule dateTimeRule(locale);
        std::unordered_map<std::string, std::string> rulesMap;
        rulesMap["test"] = "\\d{4}-\\d{2}-\\d{2}";
        std::unordered_map<std::string, std::string> subRules;
        std::unordered_map<std::string, std::string> param;
        std::unordered_map<std::string, std::string> paramBackup;
        RulesSet rulesSet(rulesMap, subRules, param, paramBackup);
        RulesEngine rulesEngine(&dateTimeRule, rulesSet);
        std::string input = provider.ConsumeRandomLengthString();
        icu::UnicodeString message(input.c_str());
        rulesEngine.Match(message);
    }

    void DateTimeFilterFuzzTest001(FuzzedDataProvider& provider)
    {
        std::string locale = "en";
        DateTimeRule dateTimeRule(locale);
        DateTimeFilter dateTimeFilter(locale, &dateTimeRule);
        std::string input = provider.ConsumeRandomLengthString();
        icu::UnicodeString content(input.c_str());
        std::vector<MatchedDateTimeInfo> matches;
        std::vector<MatchedDateTimeInfo> clearMatches;
        std::vector<MatchedDateTimeInfo> pastMatches;
        dateTimeFilter.Filter(content, matches, clearMatches, pastMatches);
    }

    void DateTimeFilterFuzzTest002(FuzzedDataProvider& provider)
    {
        std::string locale = "zh";
        DateTimeRule dateTimeRule(locale);
        DateTimeFilter dateTimeFilter(locale, &dateTimeRule);
        std::string input = provider.ConsumeRandomLengthString();
        icu::UnicodeString content(input.c_str());
        std::vector<MatchedDateTimeInfo> matches;
        std::vector<MatchedDateTimeInfo> clearMatches;
        std::vector<MatchedDateTimeInfo> pastMatches;
        dateTimeFilter.Filter(content, matches, clearMatches, pastMatches);
    }

    void DateTimeFilterFuzzTest003(FuzzedDataProvider& provider)
    {
        std::string locale = "ja";
        DateTimeRule dateTimeRule(locale);
        DateTimeFilter dateTimeFilter(locale, &dateTimeRule);
        std::string input = provider.ConsumeRandomLengthString();
        icu::UnicodeString content(input.c_str());
        std::vector<MatchedDateTimeInfo> matches;
        std::vector<MatchedDateTimeInfo> clearMatches;
        std::vector<MatchedDateTimeInfo> pastMatches;
        dateTimeFilter.Filter(content, matches, clearMatches, pastMatches);
    }

    void DateTimeFilterFuzzTest004(FuzzedDataProvider& provider)
    {
        std::string input = provider.ConsumeRandomLengthString();
        DateTimeRule dateTimeRule(input);
        DateTimeFilter dateTimeFilter(input, &dateTimeRule);
        std::string dateTimeText = "2024-01-15 to 2024-01-20";
        icu::UnicodeString content(dateTimeText.c_str());
        std::vector<MatchedDateTimeInfo> matches;
        std::vector<MatchedDateTimeInfo> clearMatches;
        std::vector<MatchedDateTimeInfo> pastMatches;
        dateTimeFilter.Filter(content, matches, clearMatches, pastMatches);
    }

    void DateTimeFilterFuzzTest005(FuzzedDataProvider& provider)
    {
        std::string locale = "en";
        DateTimeRule dateTimeRule(locale);
        DateTimeFilter dateTimeFilter(locale, &dateTimeRule);
        std::string input = provider.ConsumeRandomLengthString();
        icu::UnicodeString content(input.c_str());
        MatchedDateTimeInfo match1;
        match1.SetBegin(0);
        match1.SetEnd(10);
        match1.SetType(DateTimeFilter::TYPE_DATE);
        std::vector<MatchedDateTimeInfo> matches;
        matches.push_back(match1);
        std::vector<MatchedDateTimeInfo> clearMatches;
        std::vector<MatchedDateTimeInfo> pastMatches;
        dateTimeFilter.Filter(content, matches, clearMatches, pastMatches);
    }

    void DateTimeFilterFuzzTest006(FuzzedDataProvider& provider)
    {
        std::string locale = "zh";
        DateTimeRule dateTimeRule(locale);
        DateTimeFilter dateTimeFilter(locale, &dateTimeRule);
        std::string input = provider.ConsumeRandomLengthString();
        icu::UnicodeString content(input.c_str());
        MatchedDateTimeInfo match1;
        match1.SetBegin(0);
        match1.SetEnd(20);
        match1.SetType(DateTimeFilter::TYPE_DATETIME);
        MatchedDateTimeInfo match2;
        match2.SetBegin(25);
        match2.SetEnd(35);
        match2.SetType(DateTimeFilter::TYPE_TIME);
        std::vector<MatchedDateTimeInfo> matches;
        matches.push_back(match1);
        matches.push_back(match2);
        std::vector<MatchedDateTimeInfo> clearMatches;
        std::vector<MatchedDateTimeInfo> pastMatches;
        dateTimeFilter.Filter(content, matches, clearMatches, pastMatches);
    }

    bool DoSomethingInterestingWithMyAPI(const uint8_t* data, size_t size)
    {
        if (data == nullptr || size < 1) {
            return false;
        }

        FuzzedDataProvider provider(data, size);
        EntityRecognizerFuzzTest001(provider);
        EntityRecognizerFuzzTest002(provider);
        EntityRecognizerFuzzTest003(provider);
        EntityRecognizerFuzzTest004(provider);
        EntityRecognizerFuzzTest005(provider);

        DateTimeMatchedFuzzTest001(provider);
        DateTimeMatchedFuzzTest002(provider);
        DateTimeMatchedFuzzTest003(provider);
        DateTimeMatchedFuzzTest004(provider);
        DateTimeMatchedFuzzTest005(provider);
        DateTimeMatchedFuzzTest006(provider);
        DateTimeMatchedFuzzTest007(provider);

        PhoneNumberMatchedFuzzTest001(provider);
        PhoneNumberMatchedFuzzTest002(provider);
        PhoneNumberMatchedFuzzTest003(provider);
        PhoneNumberMatchedFuzzTest004(provider);
        PhoneNumberMatchedFuzzTest005(provider);
        PhoneNumberMatchedFuzzTest006(provider);
        PhoneNumberMatchedFuzzTest007(provider);
        PhoneNumberMatchedFuzzTest008(provider);

        DateTimeRuleFuzzTest001(provider);
        DateTimeRuleFuzzTest002(provider);
        DateTimeRuleFuzzTest003(provider);
        DateTimeRuleFuzzTest004(provider);
        DateTimeRuleFuzzTest005(provider);
        DateTimeRuleFuzzTest006(provider);
        DateTimeRuleFuzzTest007(provider);

        PhoneNumberRuleFuzzTest001(provider);
        PhoneNumberRuleFuzzTest002(provider);
        PhoneNumberRuleFuzzTest003(provider);
        PhoneNumberRuleFuzzTest004(provider);
        PhoneNumberRuleFuzzTest005(provider);
        PhoneNumberRuleFuzzTest006(provider);
        PhoneNumberRuleFuzzTest007(provider);

        RulesEngineFuzzTest001(provider);
        RulesEngineFuzzTest002(provider);
        RulesEngineFuzzTest003(provider);
        RulesEngineFuzzTest004(provider);
        RulesEngineFuzzTest005(provider);

        DateTimeFilterFuzzTest001(provider);
        DateTimeFilterFuzzTest002(provider);
        DateTimeFilterFuzzTest003(provider);
        DateTimeFilterFuzzTest004(provider);
        DateTimeFilterFuzzTest005(provider);
        DateTimeFilterFuzzTest006(provider);

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