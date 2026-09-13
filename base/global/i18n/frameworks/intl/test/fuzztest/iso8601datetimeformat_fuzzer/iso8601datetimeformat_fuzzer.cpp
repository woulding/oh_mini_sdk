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
#include "i18n_types.h"
#include "iso8601_date_time_format.h"
#include "iso8601datetimeformat_fuzzer.h"

namespace OHOS {
namespace Global {
namespace I18n {
    void ISO8601DateTimeFormatFuzzTest001(FuzzedDataProvider& provider)
    {
        std::string input = provider.ConsumeRandomLengthString();
        I18nErrorCode errCode = I18nErrorCode::SUCCESS;
        ISO8601DateTimeFormat formatter(
            ISO8601DateTimeFormat::DateFormat::CALENDAR,
            ISO8601DateTimeFormat::TimePrecision::DATE_ONLY,
            ISO8601DateTimeFormat::SeparatorStyle::EXTENDED,
            input,
            true,
            errCode
        );
        formatter.Format(static_cast<int64_t>(input.length()));
    }

    void ISO8601DateTimeFormatFuzzTest002(FuzzedDataProvider& provider)
    {
        std::string input = provider.ConsumeRandomLengthString();
        I18nErrorCode errCode = I18nErrorCode::SUCCESS;
        ISO8601DateTimeFormat formatter(
            ISO8601DateTimeFormat::DateFormat::ORDINAL,
            ISO8601DateTimeFormat::TimePrecision::HOURS,
            ISO8601DateTimeFormat::SeparatorStyle::BASIC,
            input,
            false,
            errCode
        );
        formatter.Format(static_cast<int64_t>(input.length()));
        formatter.Format(86400000);
    }

    void ISO8601DateTimeFormatFuzzTest003(FuzzedDataProvider& provider)
    {
        std::string input = provider.ConsumeRandomLengthString();
        I18nErrorCode errCode = I18nErrorCode::SUCCESS;
        ISO8601DateTimeFormat formatter(
            ISO8601DateTimeFormat::DateFormat::WEEK,
            ISO8601DateTimeFormat::TimePrecision::MINUTES,
            ISO8601DateTimeFormat::SeparatorStyle::EXTENDED,
            "UTC",
            true,
            errCode
        );
        formatter.Format(static_cast<int64_t>(input.length()));
        formatter.Format(0);
        formatter.Format(31536000000);
    }

    void ISO8601DateTimeFormatFuzzTest004(FuzzedDataProvider& provider)
    {
        std::string input = provider.ConsumeRandomLengthString();
        I18nErrorCode errCode = I18nErrorCode::SUCCESS;
        ISO8601DateTimeFormat formatter(
            ISO8601DateTimeFormat::DateFormat::CALENDAR,
            ISO8601DateTimeFormat::TimePrecision::SECONDS,
            ISO8601DateTimeFormat::SeparatorStyle::BASIC,
            input,
            true,
            errCode
        );
        int64_t testTimes[] = {0, 1000, 60000, 3600000, 86400000};
        for (int64_t time : testTimes) {
            formatter.Format(time);
        }
    }

    void ISO8601DateTimeFormatFuzzTest005(FuzzedDataProvider& provider)
    {
        std::string input = provider.ConsumeRandomLengthString();
        I18nErrorCode errCode = I18nErrorCode::SUCCESS;
        ISO8601DateTimeFormat formatter(
            ISO8601DateTimeFormat::DateFormat::ORDINAL,
            ISO8601DateTimeFormat::TimePrecision::MILLISECONDS,
            ISO8601DateTimeFormat::SeparatorStyle::EXTENDED,
            input,
            false,
            errCode
        );
        formatter.Format(static_cast<int64_t>(input.length()));
        formatter.Format(-1);
        formatter.Format(std::numeric_limits<int64_t>::max());
        formatter.Format(std::numeric_limits<int64_t>::min());
    }

    void ISO8601DateTimeFormatFuzzTest006(FuzzedDataProvider& provider)
    {
        std::string input = provider.ConsumeRandomLengthString();
        I18nErrorCode errCode = I18nErrorCode::SUCCESS;
        ISO8601DateTimeFormat formatter(
            ISO8601DateTimeFormat::DateFormat::WEEK,
            ISO8601DateTimeFormat::TimePrecision::DATE_ONLY,
            ISO8601DateTimeFormat::SeparatorStyle::BASIC,
            input,
            true,
            errCode
        );
        for (int32_t i = 0; i < 10; i++) {
            formatter.Format(static_cast<int64_t>(input.length()) + i * 86400000);
        }
    }

    void ISO8601DateTimeFormatFuzzTest007(FuzzedDataProvider& provider)
    {
        std::string input = provider.ConsumeRandomLengthString();
        I18nErrorCode errCode = I18nErrorCode::SUCCESS;
        ISO8601DateTimeFormat::DateFormat dateFormats[] = {
            ISO8601DateTimeFormat::DateFormat::CALENDAR,
            ISO8601DateTimeFormat::DateFormat::ORDINAL,
            ISO8601DateTimeFormat::DateFormat::WEEK
        };
        ISO8601DateTimeFormat::TimePrecision timePrecisions[] = {
            ISO8601DateTimeFormat::TimePrecision::DATE_ONLY,
            ISO8601DateTimeFormat::TimePrecision::HOURS,
            ISO8601DateTimeFormat::TimePrecision::MINUTES,
            ISO8601DateTimeFormat::TimePrecision::SECONDS,
            ISO8601DateTimeFormat::TimePrecision::MILLISECONDS
        };
        ISO8601DateTimeFormat::SeparatorStyle separatorStyles[] = {
            ISO8601DateTimeFormat::SeparatorStyle::EXTENDED,
            ISO8601DateTimeFormat::SeparatorStyle::BASIC
        };
        for (auto dateFormat : dateFormats) {
            for (auto timePrecision : timePrecisions) {
                for (auto separatorStyle : separatorStyles) {
                    ISO8601DateTimeFormat formatter(dateFormat, timePrecision, separatorStyle, input, true, errCode);
                    formatter.Format(static_cast<int64_t>(input.length()));
                }
            }
        }
    }

    bool DoSomethingInterestingWithMyAPI(const uint8_t* data, size_t size)
    {
        if (data == nullptr || size < 1) {
            return false;
        }

        FuzzedDataProvider provider(data, size);
        ISO8601DateTimeFormatFuzzTest001(provider);
        ISO8601DateTimeFormatFuzzTest002(provider);
        ISO8601DateTimeFormatFuzzTest003(provider);
        ISO8601DateTimeFormatFuzzTest004(provider);
        ISO8601DateTimeFormatFuzzTest005(provider);
        ISO8601DateTimeFormatFuzzTest006(provider);
        ISO8601DateTimeFormatFuzzTest007(provider);
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