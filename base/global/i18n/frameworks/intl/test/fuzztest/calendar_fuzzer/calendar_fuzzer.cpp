/*
 * Copyright (c) 2022-2024 Huawei Device Co., Ltd.
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
#include "i18n_calendar.h"
#include "calendar_fuzzer.h"
#include "unicode/ucal.h"
#include "unicode/utypes.h"

namespace OHOS {
    bool DoSomethingInterestingWithMyAPI(const uint8_t* data, size_t size)
    {
        if (data == nullptr || size < 1) {
            return false;
        }

        FuzzedDataProvider provider(data, size);
        using namespace Global::I18n;

        std::string input = provider.ConsumeRandomLengthString();
        I18nCalendar calendar(input, CalendarType::GREGORY);

        double number = provider.ConsumeFloatingPoint<double>();
        calendar.SetTime(number);

        int32_t param1 = provider.ConsumeIntegral<int32_t>();
        int32_t param2 = provider.ConsumeIntegral<int32_t>();
        int32_t param3 = provider.ConsumeIntegral<int32_t>();
        calendar.Set(param1, param2, param3);

        int32_t yearValue = provider.ConsumeIntegral<int32_t>();
        calendar.Set(UCalendarDateFields::UCAL_YEAR, yearValue);

        calendar.GetTimeZone();
        calendar.SetTimeZone(input);
        calendar.GetTimeInMillis();
        calendar.GetMinimalDaysInFirstWeek();
        calendar.GetFirstDayOfWeek();

        UErrorCode status = U_ZERO_ERROR;
        int32_t weekendParam = provider.ConsumeIntegral<int32_t>();
        calendar.IsWeekend(weekendParam, status);
        calendar.IsWeekend();
        calendar.GetDisplayName(input);

        double compareDay = provider.ConsumeFloatingPoint<double>();
        calendar.CompareDays(compareDay);

        return true;
    }
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    OHOS::DoSomethingInterestingWithMyAPI(data, size);
    return 0;
}