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
#include <set>
#include <string>
#include <unordered_set>
#include <vector>
#include "locale_helper.h"
#include "localehelper_fuzzer.h"

namespace OHOS {
namespace Global {
namespace I18n {
    void LocaleHelperFuzzTest001(FuzzedDataProvider& provider)
    {
        std::string key = provider.ConsumeRandomLengthString();
        std::string option = provider.ConsumeRandomLengthString();
        LocaleHelper::IsValidOptionName(key, option);
    }

    void LocaleHelperFuzzTest002(FuzzedDataProvider& provider)
    {
        std::string input = provider.ConsumeRandomLengthString();
        std::map<std::string, std::string> options;
        options[input] = input;
        LocaleHelper::ParseOptionWithoutCheck(options, input, "default");
    }

    void LocaleHelperFuzzTest003(FuzzedDataProvider& provider)
    {
        std::string input = provider.ConsumeRandomLengthString();
        std::map<std::string, std::string> options;
        options[input] = input;
        I18nErrorCode status = I18nErrorCode::SUCCESS;
        LocaleHelper::ParseOption(options, input, "default", true, status);
    }

    void LocaleHelperFuzzTest004(FuzzedDataProvider& provider)
    {
        std::string input = provider.ConsumeRandomLengthString();
        std::map<std::string, std::string> options;
        options[input] = input;
        I18nErrorCode status = I18nErrorCode::SUCCESS;
        LocaleHelper::ParseOption(options, input, "default", false, status);
    }

    void LocaleHelperFuzzTest005(FuzzedDataProvider& provider)
    {
        std::string input = provider.ConsumeRandomLengthString();
        std::set<std::string> availableLocales;
        availableLocales.insert("en-US");
        availableLocales.insert("zh-CN");
        availableLocales.insert("ja-JP");
        LocaleHelper::BestAvailableLocale(availableLocales, input);
    }

    void LocaleHelperFuzzTest006(FuzzedDataProvider& provider)
    {
        std::string input = provider.ConsumeRandomLengthString();
        std::set<std::string> availableLocales;
        availableLocales.insert("en-US");
        availableLocales.insert("zh-CN");
        std::vector<std::string> requestLocales;
        requestLocales.push_back(input);
        LocaleHelper::LookupSupportedLocales(availableLocales, requestLocales);
    }

    void LocaleHelperFuzzTest007(FuzzedDataProvider& provider)
    {
        std::string input = provider.ConsumeRandomLengthString();
        std::vector<std::string> locales;
        locales.push_back(input);
        I18nErrorCode status = I18nErrorCode::SUCCESS;
        LocaleHelper::CanonicalizeLocaleList(locales, status);
    }

    void LocaleHelperFuzzTest008(FuzzedDataProvider& provider)
    {
        std::string input = provider.ConsumeRandomLengthString();
        LocaleHelper::IsUnicodeScriptSubtag(input);
    }

    void LocaleHelperFuzzTest009(FuzzedDataProvider& provider)
    {
        std::string input = provider.ConsumeRandomLengthString();
        LocaleHelper::IsUnicodeRegionSubtag(input);
    }

    void LocaleHelperFuzzTest010(FuzzedDataProvider& provider)
    {
        std::string input = provider.ConsumeRandomLengthString();
        LocaleHelper::IsWellFormedCurrencyCode(input);
    }

    void LocaleHelperFuzzTest011(FuzzedDataProvider& provider)
    {
        std::string input = provider.ConsumeRandomLengthString();
        LocaleHelper::IsWellFormedCalendarCode(input);
    }

    void LocaleHelperFuzzTest012(FuzzedDataProvider& provider)
    {
        std::string input = provider.ConsumeRandomLengthString();
        LocaleHelper::IsStructurallyValidLanguageTag(input);
    }

    void LocaleHelperFuzzTest013(FuzzedDataProvider& provider)
    {
        std::string input = provider.ConsumeRandomLengthString();
        LocaleHelper::IsAlpha(input, 2, 3);
        LocaleHelper::IsAlpha(input, 2, 4);
    }

    void LocaleHelperFuzzTest014(FuzzedDataProvider& provider)
    {
        std::string input = provider.ConsumeRandomLengthString();
        LocaleHelper::IsNormativeCalendar(input);
    }

    void LocaleHelperFuzzTest015(FuzzedDataProvider& provider)
    {
        std::string input = provider.ConsumeRandomLengthString();
        LocaleHelper::IsNormativeNumberingSystem(input);
    }

    void LocaleHelperFuzzTest016(FuzzedDataProvider& provider)
    {
        std::string input = provider.ConsumeRandomLengthString();
        if (input.length() < 8) {
            return;
        }
        double number = *(reinterpret_cast<const double*>(input.data()));
        LocaleHelper::TruncateDouble(number);
    }

    void LocaleHelperFuzzTest017(FuzzedDataProvider& provider)
    {
        std::string input = provider.ConsumeRandomLengthString();
        LocaleHelper::IsUnicodeScriptSubtag(input);
        LocaleHelper::GetAvailableLocales();
    }

    void LocaleHelperFuzzTest018(FuzzedDataProvider& provider)
    {
        std::string input = provider.ConsumeRandomLengthString();
        std::vector<std::string> requestLocales;
        requestLocales.push_back(input);
        std::map<std::string, std::string> configs;
        configs["localeMatcher"] = "lookup";
        I18nErrorCode status = I18nErrorCode::SUCCESS;
        LocaleHelper::SupportedLocalesOf(requestLocales, configs, status);
    }

    void LocaleHelperFuzzTest019(FuzzedDataProvider& provider)
    {
        std::string input = provider.ConsumeRandomLengthString();
        std::vector<std::string> localeArray;
        localeArray.push_back(input);
        LocaleHelper::CheckParamLocales(localeArray);
    }

    void LocaleHelperFuzzTest020(FuzzedDataProvider& provider)
    {
        std::string input = provider.ConsumeRandomLengthString();
        LocaleHelper::IsValidOptionName(input, input);
        LocaleHelper::DefaultLocale();
    }

    void LocaleHelperFuzzTest021(FuzzedDataProvider& provider)
    {
        std::string input = provider.ConsumeRandomLengthString();
        std::set<std::string> availableLocales;
        availableLocales.insert("en-US");
        availableLocales.insert("zh-CN");
        std::vector<std::string> requestedLocales;
        requestedLocales.push_back(input);
        LocaleHelper::LookupMatcher(availableLocales, requestedLocales);
    }

    void LocaleHelperFuzzTest022(FuzzedDataProvider& provider)
    {
        std::string input = provider.ConsumeRandomLengthString();
        std::map<std::string, std::string> options;
        options[input] = input;
        LocaleHelper::ParseOptionWithoutCheck(options, input, input);
        options.clear();
        options["calendar"] = "gregory";
        options["collation"] = "default";
        LocaleHelper::ParseOptionWithoutCheck(options, "calendar", "");
        LocaleHelper::ParseOptionWithoutCheck(options, "collation", "");
    }

    void LocaleHelperFuzzTest023(FuzzedDataProvider& provider)
    {
        std::string input = provider.ConsumeRandomLengthString();
        std::vector<std::string> locales;
        locales.push_back(input);
        I18nErrorCode status = I18nErrorCode::SUCCESS;
        LocaleHelper::CanonicalizeLocaleList(locales, status);
        locales.clear();
        locales.push_back("en-US");
        locales.push_back("zh-CN");
        locales.push_back("ja-JP");
        status = I18nErrorCode::SUCCESS;
        LocaleHelper::CanonicalizeLocaleList(locales, status);
    }

    void LocaleHelperFuzzTest024(FuzzedDataProvider& provider)
    {
        std::string input = provider.ConsumeRandomLengthString();
        LocaleHelper::IsUnicodeScriptSubtag(input);
        LocaleHelper::IsUnicodeRegionSubtag(input);
        LocaleHelper::IsUnicodeScriptSubtag("Latn");
        LocaleHelper::IsUnicodeScriptSubtag("Hans");
        LocaleHelper::IsUnicodeRegionSubtag("US");
        LocaleHelper::IsUnicodeRegionSubtag("CN");
    }

    void LocaleHelperFuzzTest025(FuzzedDataProvider& provider)
    {
        std::string input = provider.ConsumeRandomLengthString();
        LocaleHelper::IsWellFormedCurrencyCode(input);
        LocaleHelper::IsWellFormedCalendarCode(input);
        LocaleHelper::IsWellFormedCurrencyCode("USD");
        LocaleHelper::IsWellFormedCurrencyCode("CNY");
        LocaleHelper::IsWellFormedCalendarCode("gregory");
        LocaleHelper::IsWellFormedCalendarCode("chinese");
    }

    void LocaleHelperFuzzTest026(FuzzedDataProvider& provider)
    {
        std::string input = provider.ConsumeRandomLengthString();
        std::vector<std::string> requestLocales;
        requestLocales.push_back("en-US");
        requestLocales.push_back("zh-CN");
        std::map<std::string, std::string> configs;
        configs[input] = input;
        I18nErrorCode status = I18nErrorCode::SUCCESS;
        LocaleHelper::SupportedLocalesOf(requestLocales, configs, status);
    }

    bool DoSomethingInterestingWithMyAPI(const uint8_t* data, size_t size)
    {
        if (data == nullptr || size < 1) {
            return false;
        }

        FuzzedDataProvider provider(data, size);
        LocaleHelperFuzzTest001(provider);
        LocaleHelperFuzzTest002(provider);
        LocaleHelperFuzzTest003(provider);
        LocaleHelperFuzzTest004(provider);
        LocaleHelperFuzzTest005(provider);
        LocaleHelperFuzzTest006(provider);
        LocaleHelperFuzzTest007(provider);
        LocaleHelperFuzzTest008(provider);
        LocaleHelperFuzzTest009(provider);
        LocaleHelperFuzzTest010(provider);
        LocaleHelperFuzzTest011(provider);
        LocaleHelperFuzzTest012(provider);
        LocaleHelperFuzzTest013(provider);
        LocaleHelperFuzzTest014(provider);
        LocaleHelperFuzzTest015(provider);
        LocaleHelperFuzzTest016(provider);
        LocaleHelperFuzzTest017(provider);
        LocaleHelperFuzzTest018(provider);
        LocaleHelperFuzzTest019(provider);
        LocaleHelperFuzzTest020(provider);
        LocaleHelperFuzzTest021(provider);
        LocaleHelperFuzzTest022(provider);
        LocaleHelperFuzzTest023(provider);
        LocaleHelperFuzzTest024(provider);
        LocaleHelperFuzzTest025(provider);
        LocaleHelperFuzzTest026(provider);
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