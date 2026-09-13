/*
 * Copyright (c) 2026 Huawei Device Co., Ltd.
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
#include <string>
#include <fuzzer/FuzzedDataProvider.h>
#include "lunar_calendar.h"
#include "lunarcalendar_fuzzer.h"

namespace OHOS {
namespace Global {
namespace I18n {

    void LunarCalendarFuzzTest001(FuzzedDataProvider& provider)
    {
        int32_t year = provider.ConsumeIntegral<int32_t>();
        int32_t month = provider.ConsumeIntegral<int32_t>();
        int32_t day = provider.ConsumeIntegral<int32_t>();

        LunarCalendar lunarCalendar;
        lunarCalendar.SetGregorianDate(year, month, day);
        lunarCalendar.GetLunarYear();
        lunarCalendar.GetLunarMonth();
        lunarCalendar.GetLunarDay();
        lunarCalendar.IsLeapMonth();
    }

    void LunarCalendarFuzzTest002(FuzzedDataProvider& provider)
    {
        int32_t year = provider.ConsumeIntegral<int32_t>();
        int32_t month = provider.ConsumeIntegral<int32_t>();
        int32_t day = provider.ConsumeIntegral<int32_t>();
        LunarCalendar lunarCalendar;
        lunarCalendar.SetGregorianDate(year, month, day);
        lunarCalendar.SetGregorianDate(2024, 1, 1);
        lunarCalendar.GetLunarYear();
        lunarCalendar.GetLunarMonth();
        lunarCalendar.GetLunarDay();
        lunarCalendar.IsLeapMonth();
    }

    void LunarCalendarFuzzTest003(FuzzedDataProvider& provider)
    {
        int32_t year = provider.ConsumeIntegral<int32_t>();
        int32_t month = provider.ConsumeIntegral<int32_t>();
        int32_t day = provider.ConsumeIntegral<int32_t>();
        LunarCalendar lunarCalendar;
        lunarCalendar.SetGregorianDate(year, month, day);
        lunarCalendar.SetGregorianDate(2024, 12, 31);
        lunarCalendar.GetLunarYear();
        lunarCalendar.GetLunarMonth();
        lunarCalendar.GetLunarDay();
        lunarCalendar.IsLeapMonth();
    }

    void LunarCalendarFuzzTest004(FuzzedDataProvider& provider)
    {
        int32_t year = provider.ConsumeIntegral<int32_t>();
        int32_t month = provider.ConsumeIntegral<int32_t>();
        int32_t day = provider.ConsumeIntegral<int32_t>();
        LunarCalendar lunarCalendar;
        lunarCalendar.SetGregorianDate(year, month, day);
        lunarCalendar.SetGregorianDate(1900, 1, 31);
        lunarCalendar.GetLunarYear();
        lunarCalendar.GetLunarMonth();
        lunarCalendar.GetLunarDay();
    }

    void LunarCalendarFuzzTest005(FuzzedDataProvider& provider)
    {
        int32_t year = provider.ConsumeIntegral<int32_t>();
        int32_t month = provider.ConsumeIntegral<int32_t>();
        int32_t day = provider.ConsumeIntegral<int32_t>();
        LunarCalendar lunarCalendar;
        lunarCalendar.SetGregorianDate(year, month, day);
        lunarCalendar.SetGregorianDate(2100, 12, 31);
        lunarCalendar.GetLunarYear();
        lunarCalendar.GetLunarMonth();
        lunarCalendar.GetLunarDay();
    }

    void LunarCalendarFuzzTest006(FuzzedDataProvider& provider)
    {
        int32_t year = provider.ConsumeIntegral<int32_t>();
        int32_t month = provider.ConsumeIntegral<int32_t>();
        int32_t day = provider.ConsumeIntegral<int32_t>();
        LunarCalendar lunarCalendar;
        lunarCalendar.SetGregorianDate(year, month, day);
        lunarCalendar.SetGregorianDate(1900, 1, 1);
        lunarCalendar.GetLunarYear();
        lunarCalendar.SetGregorianDate(2100, 12, 31);
        lunarCalendar.GetLunarYear();
    }

    void LunarCalendarFuzzTest007(FuzzedDataProvider& provider)
    {
        int32_t year = provider.ConsumeIntegral<int32_t>();
        int32_t month = provider.ConsumeIntegral<int32_t>();
        int32_t day = provider.ConsumeIntegral<int32_t>();
        LunarCalendar lunarCalendar;
        bool result = lunarCalendar.SetGregorianDate(year, month, day);
        if (result) {
            lunarCalendar.GetLunarYear();
            lunarCalendar.GetLunarMonth();
            lunarCalendar.GetLunarDay();
        }
        result = lunarCalendar.SetGregorianDate(2020, 2, 29);
        if (result) {
            lunarCalendar.GetLunarYear();
            lunarCalendar.GetLunarMonth();
            lunarCalendar.GetLunarDay();
        }
    }

    void LunarCalendarFuzzTest008(FuzzedDataProvider& provider)
    {
        int32_t year = provider.ConsumeIntegral<int32_t>();
        int32_t month = provider.ConsumeIntegral<int32_t>();
        int32_t day = provider.ConsumeIntegral<int32_t>();
        LunarCalendar lunarCalendar;
        lunarCalendar.SetGregorianDate(year, month, day);
        lunarCalendar.GetLunarYear();
        lunarCalendar.GetLunarMonth();
        lunarCalendar.GetLunarDay();
        lunarCalendar.SetGregorianDate(2019, 2, 28);
        lunarCalendar.GetLunarYear();
        lunarCalendar.GetLunarMonth();
        lunarCalendar.GetLunarDay();
        lunarCalendar.SetGregorianDate(2019, 2, 29);
    }

    bool DoSomethingInterestingWithMyAPI(const uint8_t* data, size_t size)
    {
        if (data == nullptr || size < 1) {
            return false;
        }
        FuzzedDataProvider provider(data, size);

        LunarCalendarFuzzTest001(provider);
        LunarCalendarFuzzTest002(provider);
        LunarCalendarFuzzTest003(provider);
        LunarCalendarFuzzTest004(provider);
        LunarCalendarFuzzTest005(provider);
        LunarCalendarFuzzTest006(provider);
        LunarCalendarFuzzTest007(provider);
        LunarCalendarFuzzTest008(provider);
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