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
#include <unordered_map>
#include <unordered_set>
#include "locale_config.h"
#include "localeconfig_fuzzer.h"

namespace OHOS {
namespace Global {
namespace I18n {
    void LocaleConfigFuzzTest001(FuzzedDataProvider& provider)
    {
        std::string input = provider.ConsumeRandomLengthString();
        LocaleConfig::GetSystemLanguage();
        LocaleConfig::GetSystemRegion();
        LocaleConfig::GetSystemLocale();
        LocaleConfig::GetSystemTimezone();
        LocaleConfig::GetEffectiveLanguage();
        LocaleConfig::GetEffectiveLocale();
        LocaleConfig::GetSystemLanguages();
        LocaleConfig::GetSystemCountries(input);
        LocaleConfig::GetSystemHour();
        LocaleConfig::Is24HourClock();
        LocaleConfig::IsEmpty24HourClock();
        LocaleConfig::GetUsingLocalDigit();
    }

    void LocaleConfigFuzzTest002(FuzzedDataProvider& provider)
    {
        std::string input = provider.ConsumeRandomLengthString();
        LocaleConfig::IsSuggested(input);
        LocaleConfig::IsSuggestedV15(input);
        const size_t minimalLocaleLength = 2;
        if (input.length() > minimalLocaleLength) {
            std::string firstInput(input, 0, minimalLocaleLength);
            std::string secondInput(input, minimalLocaleLength);
            LocaleConfig::IsSuggested(firstInput, secondInput);
            LocaleConfig::IsSuggestedV15(firstInput, secondInput);
        }
    }

    void LocaleConfigFuzzTest003(FuzzedDataProvider& provider)
    {
        std::string input = provider.ConsumeRandomLengthString();
        LocaleConfig::GetDisplayLanguage(input, "en-US", true);
        LocaleConfig::GetDisplayLanguage(input, "zh-CN", false);
        LocaleConfig::GetDisplayRegion(input, "en-US", true);
        LocaleConfig::GetDisplayRegion(input, "zh-CN", false);
    }

    void LocaleConfigFuzzTest004(FuzzedDataProvider& provider)
    {
        std::string input = provider.ConsumeRandomLengthString();
        LocaleConfig::IsRTL(input);
        LocaleConfig::GetValidLocale(input);
        LocaleConfig::IsValidLanguage(input);
        LocaleConfig::IsValidRegion(input);
        LocaleConfig::IsValidTag(input);
        LocaleConfig::IsValid24HourClockValue(input);
    }

    void LocaleConfigFuzzTest005(FuzzedDataProvider& provider)
    {
        std::string input = provider.ConsumeRandomLengthString();
        LocaleConfig::SetSystemLanguage(input);
        LocaleConfig::SetSystemRegion(input);
        LocaleConfig::SetSystemLocale(input);
        LocaleConfig::Set24HourClock(input);
        LocaleConfig::SetUsingLocalDigit(input.length() % 2 == 0);
    }

    void LocaleConfigFuzzTest006(FuzzedDataProvider& provider)
    {
        std::string input = provider.ConsumeRandomLengthString();
        int32_t code = 0;
        LocaleConfig::GetSimplifiedLanguage(input, code);
        LocaleConfig::GetSimplifiedSystemLanguage();
        LocaleConfig::GetBlockedLanguages();
        LocaleConfig::GetBlockedRegions(input);
    }

    void LocaleConfigFuzzTest007(FuzzedDataProvider& provider)
    {
        std::string input = provider.ConsumeRandomLengthString();
        LocaleConfig::GetTemperatureType();
        LocaleConfig::GetTemperatureName(LocaleConfig::GetTemperatureTypeFromLocale(input));
        LocaleConfig::GetFirstDayOfWeek();
    }

    void LocaleConfigFuzzTest008(FuzzedDataProvider& provider)
    {
        std::string input = provider.ConsumeRandomLengthString();
        LocaleConfig::RemoveCustExtParam(input);
        LocaleConfig::RemoveAllExtParam(input);
    }

    void LocaleConfigFuzzTest009(FuzzedDataProvider& provider)
    {
        std::string input = provider.ConsumeRandomLengthString();
        LocaleConfig::ModifyExtParam(input, "nu", "arab", "-u-");
        LocaleConfig::QueryExtParam(input, "nu", "-u-");
    }

    void LocaleConfigFuzzTest010(FuzzedDataProvider& provider)
    {
        std::string input = provider.ConsumeRandomLengthString();
        std::string invalidField;
        LocaleConfig::GetUnicodeWrappedFilePath(input, '/', "en-US", invalidField);
        LocaleConfig::GetUnicodeWrappedFilePath(input, '\\', input, invalidField);
    }

    void LocaleConfigFuzzTest011(FuzzedDataProvider& provider)
    {
        std::string input = provider.ConsumeRandomLengthString();
        LocaleConfig::IsValidTag(input);
        LocaleConfig::GetSystemLocaleInstanceTag();
    }

    void LocaleConfigFuzzTest012(FuzzedDataProvider& provider)
    {
        std::string input = provider.ConsumeRandomLengthString();
        LocaleConfig::SetSystemCollation(input);
        std::unordered_map<std::string, std::string> result;
        LocaleConfig::GetSystemCollations(result);
        std::string usingCollation;
        LocaleConfig::GetUsingCollation(usingCollation);
    }

    void LocaleConfigFuzzTest013(FuzzedDataProvider& provider)
    {
        std::string input = provider.ConsumeRandomLengthString();
        LocaleConfig::SetSystemCollation(input);
        std::unordered_map<std::string, std::string> result;
        LocaleConfig::GetSystemNumberingSystems(result);
        std::string usingNumberingSystem;
        LocaleConfig::GetUsingNumberingSystem(usingNumberingSystem);
        LocaleConfig::SetSystemNumberingSystem(input);
    }

    void LocaleConfigFuzzTest014(FuzzedDataProvider& provider)
    {
        std::string input = provider.ConsumeRandomLengthString();
        std::unordered_map<std::string, std::string> result;
        LocaleConfig::GetSystemNumberPatterns(result);
        std::string usingNumberPattern;
        LocaleConfig::GetUsingNumberPattern(usingNumberPattern);
        LocaleConfig::SetSystemNumberPattern(input);
    }

    void LocaleConfigFuzzTest015(FuzzedDataProvider& provider)
    {
        std::string input = provider.ConsumeRandomLengthString();
        std::unordered_map<std::string, std::string> result;
        LocaleConfig::GetSystemMeasurements(result);
        std::string usingMeasurement;
        LocaleConfig::GetUsingMeasurement(usingMeasurement);
        LocaleConfig::SetSystemMeasurement(input);
    }

    void LocaleConfigFuzzTest016(FuzzedDataProvider& provider)
    {
        std::string input = provider.ConsumeRandomLengthString();
        std::unordered_map<std::string, std::string> result;
        LocaleConfig::GetSystemNumericalDatePatterns(result);
        std::string usingPattern;
        LocaleConfig::GetUsingNumericalDatePattern(usingPattern);
        LocaleConfig::SetSystemNumericalDatePattern(input);
    }

    void LocaleConfigFuzzTest017(FuzzedDataProvider& provider)
    {
        std::string input = provider.ConsumeRandomLengthString();
        LocaleConfig::SetTemperatureType(TemperatureType::CELSIUS);
        LocaleConfig::SetTemperatureType(TemperatureType::FAHRENHEIT);
        LocaleConfig::SetTemperatureType(TemperatureType::KELVIN);
        LocaleConfig::SetFirstDayOfWeek(WeekDay::MON);
        LocaleConfig::SetFirstDayOfWeek(WeekDay::SUN);
    }

    void LocaleConfigFuzzTest018(FuzzedDataProvider& provider)
    {
        std::string input = provider.ConsumeRandomLengthString();
        LocaleConfig::SetUnicodeWrappedBidiDirection(input, "ltr");
        LocaleConfig::SetUnicodeWrappedBidiDirection(input, "rtl");
    }

    bool DoSomethingInterestingWithMyAPI(const uint8_t* data, size_t size)
    {
        if (data == nullptr || size < 1) {
            return false;
        }

        FuzzedDataProvider provider(data, size);
        LocaleConfigFuzzTest001(provider);
        LocaleConfigFuzzTest002(provider);
        LocaleConfigFuzzTest003(provider);
        LocaleConfigFuzzTest004(provider);
        LocaleConfigFuzzTest005(provider);
        LocaleConfigFuzzTest006(provider);
        LocaleConfigFuzzTest007(provider);
        LocaleConfigFuzzTest008(provider);
        LocaleConfigFuzzTest009(provider);
        LocaleConfigFuzzTest010(provider);
        LocaleConfigFuzzTest011(provider);
        LocaleConfigFuzzTest012(provider);
        LocaleConfigFuzzTest013(provider);
        LocaleConfigFuzzTest014(provider);
        LocaleConfigFuzzTest015(provider);
        LocaleConfigFuzzTest016(provider);
        LocaleConfigFuzzTest017(provider);
        LocaleConfigFuzzTest018(provider);
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