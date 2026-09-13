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
#include <fuzzer/FuzzedDataProvider.h>
#include <map>
#include <memory>
#include <set>
#include <string>
#include <unordered_set>
#include <vector>
#include "i18n_timezone.h"
#include "timezone_fuzzer.h"

namespace OHOS {
namespace Global {
namespace I18n {
    void TimezoneFuzzTest001(FuzzedDataProvider& provider)
    {
        std::string text = provider.ConsumeRandomLengthString();
        bool isDST = provider.ConsumeBool();
        I18nTimeZone timezone(text, isDST);
        timezone.GetRawOffset();
        timezone.GetID();
        timezone.GetDisplayName();
        timezone.GetDisplayName(isDST);
    }

    void TimezoneFuzzTest002(FuzzedDataProvider& provider)
    {
        std::string text = provider.ConsumeRandomLengthString();
        bool isDST = provider.ConsumeBool();
        I18nTimeZone timezone(text, isDST);
        double date = provider.ConsumeFloatingPoint<double>();
        timezone.GetOffset(date);
        timezone.IsDaylightSavingTime(date);
    }

    void TimezoneFuzzTest003(FuzzedDataProvider& provider)
    {
        std::string text = provider.ConsumeRandomLengthString();
        bool isDST = provider.ConsumeBool();
        I18nTimeZone timezone(text, isDST);
        timezone.GetDisplayName(text);
        timezone.GetDisplayName(text, isDST);
    }

    void TimezoneFuzzTest004(FuzzedDataProvider& provider)
    {
        std::string text = provider.ConsumeRandomLengthString();
        bool isDST = provider.ConsumeBool();
        std::unique_ptr<I18nTimeZone> timezone = I18nTimeZone::CreateInstance(text, isDST);
        if (timezone != nullptr) {
            timezone->GetID();
            timezone->GetRawOffset();
        }
    }

    void TimezoneFuzzTest005(FuzzedDataProvider& provider)
    {
        std::string input = provider.ConsumeRandomLengthString();
        I18nTimeZone timezone(input, false);
        timezone.GetID();
        I18nTimeZone::GetAvailableIDs();
        I18nTimeZone::GetAvailableZoneCityIDs();
    }

    void TimezoneFuzzTest006(FuzzedDataProvider& provider)
    {
        std::string text = provider.ConsumeRandomLengthString();
        I18nTimeZone::GetCityDisplayName(text, text);
    }

    void TimezoneFuzzTest007(FuzzedDataProvider& provider)
    {
        double x = provider.ConsumeFloatingPoint<double>();
        double y = provider.ConsumeFloatingPoint<double>();
        I18nTimeZone::GetTimezoneIdByLocation(x, y);
    }

    void TimezoneFuzzTest008(FuzzedDataProvider& provider)
    {
        std::string text = provider.ConsumeRandomLengthString();
        I18nTimeZone::FindCityDisplayNameMap(text);
    }

    void TimezoneFuzzTest009(FuzzedDataProvider& provider)
    {
        std::string text = provider.ConsumeRandomLengthString();
        I18nTimeZone::GetLocaleBaseName(text);
    }

    void TimezoneFuzzTest010(FuzzedDataProvider& provider)
    {
        std::string text = provider.ConsumeRandomLengthString();
        I18nTimeZone::GetTimezoneIdByCityId(text);
    }

    void TimezoneFuzzTest011(FuzzedDataProvider& provider)
    {
        std::string text = provider.ConsumeRandomLengthString();
        I18nTimeZone::SetAppDefaultTimeZoneById(text);
    }

    void TimezoneFuzzTest012(FuzzedDataProvider& provider)
    {
        std::string text = provider.ConsumeRandomLengthString();
        std::unique_ptr<I18nTimeZone> timezone = I18nTimeZone::GetAppDefaultTimeZone();
        if (timezone != nullptr) {
            timezone->GetID();
        }
        I18nTimeZone::GetAppDefaultTimeZoneID();
    }

    void TimezoneFuzzTest013(FuzzedDataProvider& provider)
    {
        std::string text = provider.ConsumeRandomLengthString();
        bool isDST = true;
        I18nTimeZone timezone(text, isDST);
        timezone.GetOffset(0);
        timezone.GetOffset(1234567890.0);
        timezone.GetOffset(-1234567890.0);
    }

    void TimezoneFuzzTest014(FuzzedDataProvider& provider)
    {
        std::string text = provider.ConsumeRandomLengthString();
        bool isDST = false;
        I18nTimeZone timezone(text, isDST);
        timezone.IsDaylightSavingTime(1609459200000.0);
        timezone.IsDaylightSavingTime(1704067200000.0);
    }

    void TimezoneFuzzTest015(FuzzedDataProvider& provider)
    {
        std::string input = provider.ConsumeRandomLengthString();
        I18nTimeZone::GetTimezoneIdByCityId(input);
        I18nTimeZone::GetTimezoneIdByCityId("Shanghai");
        I18nTimeZone::GetTimezoneIdByCityId("New_York");
    }

    void TimezoneFuzzTest016(FuzzedDataProvider& provider)
    {
        double x = provider.ConsumeFloatingPoint<double>();
        double y = provider.ConsumeFloatingPoint<double>();
        I18nTimeZone::GetTimezoneIdByLocation(x, y);
        I18nTimeZone::GetTimezoneIdByLocation(0.0, 0.0);
        I18nTimeZone::GetTimezoneIdByLocation(116.4, 39.9);
        I18nTimeZone::GetTimezoneIdByLocation(-74.0, 40.7);
    }

    void TimezoneFuzzTest017(FuzzedDataProvider& provider)
    {
        std::string text = provider.ConsumeRandomLengthString();
        bool isDST = provider.ConsumeBool();
        I18nTimeZone timezone(text, isDST);
        timezone.GetDisplayNameByTaboo("en-US", "test");
        timezone.GetDisplayNameByTaboo("zh-CN", "测试");
    }

    bool DoSomethingInterestingWithMyAPI(const uint8_t* data, size_t size)
    {
        if (data == nullptr || size < 1) {
            return false;
        }

        FuzzedDataProvider provider(data, size);
        TimezoneFuzzTest001(provider);
        TimezoneFuzzTest002(provider);
        TimezoneFuzzTest003(provider);
        TimezoneFuzzTest004(provider);
        TimezoneFuzzTest005(provider);
        TimezoneFuzzTest006(provider);
        TimezoneFuzzTest007(provider);
        TimezoneFuzzTest008(provider);
        TimezoneFuzzTest009(provider);
        TimezoneFuzzTest010(provider);
        TimezoneFuzzTest011(provider);
        TimezoneFuzzTest012(provider);
        TimezoneFuzzTest013(provider);
        TimezoneFuzzTest014(provider);
        TimezoneFuzzTest015(provider);
        TimezoneFuzzTest016(provider);
        TimezoneFuzzTest017(provider);
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