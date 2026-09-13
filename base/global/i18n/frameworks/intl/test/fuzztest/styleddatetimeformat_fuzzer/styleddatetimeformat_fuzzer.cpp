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
#include <memory>
#include <string>
#include <unordered_map>
#include <vector>
#include "i18n_types.h"
#include "intl_date_time_format.h"
#include "simple_date_time_format.h"
#include "styled_date_time_format.h"
#include "styleddatetimeformat_fuzzer.h"

namespace OHOS {
namespace Global {
namespace I18n {
    void StyledDateTimeFormatFuzzTest001(FuzzedDataProvider& provider)
    {
        std::string input = provider.ConsumeRandomLengthString();
        std::vector<std::string> localeTags;
        localeTags.push_back(input);
        std::unordered_map<std::string, std::string> configs;
        std::string errMessage;
        std::shared_ptr<IntlDateTimeFormat> intlFormatter =
            std::make_shared<IntlDateTimeFormat>(localeTags, configs, errMessage);

        StyledDateTimeFormat styledFormat(intlFormatter);
        styledFormat.Format(static_cast<double>(provider.remaining_bytes()));
    }

    void StyledDateTimeFormatFuzzTest002(FuzzedDataProvider& provider)
    {
        std::string input = provider.ConsumeRandomLengthString();
        I18nErrorCode errCode = I18nErrorCode::SUCCESS;
        std::shared_ptr<LocaleInfo> localeInfo = std::make_shared<LocaleInfo>(input);
        std::shared_ptr<SimpleDateTimeFormat> simpleFormatter =
            std::make_shared<SimpleDateTimeFormat>(input, localeInfo, true, errCode);

        StyledDateTimeFormat styledFormat(simpleFormatter);
        styledFormat.Format(static_cast<double>(provider.remaining_bytes()));
    }

    void StyledDateTimeFormatFuzzTest003(FuzzedDataProvider& provider)
    {
        std::string input = provider.ConsumeRandomLengthString();
        std::vector<std::string> localeTags;
        localeTags.push_back(input);
        std::unordered_map<std::string, std::string> configs;
        configs["dateStyle"] = "full";
        configs["timeStyle"] = "long";
        std::string errMessage;
        std::shared_ptr<IntlDateTimeFormat> intlFormatter =
            std::make_shared<IntlDateTimeFormat>(localeTags, configs, errMessage);

        StyledDateTimeFormat styledFormat(intlFormatter);
        styledFormat.Format(static_cast<double>(provider.remaining_bytes()));
        styledFormat.Format(static_cast<double>(provider.remaining_bytes() + 86400000));
    }

    void StyledDateTimeFormatFuzzTest004(FuzzedDataProvider& provider)
    {
        std::string input = provider.ConsumeRandomLengthString();
        I18nErrorCode errCode = I18nErrorCode::SUCCESS;
        std::shared_ptr<SimpleDateTimeFormat> simpleFormatter =
            std::make_shared<SimpleDateTimeFormat>("yyyyMMdd", input, false, errCode);

        StyledDateTimeFormat styledFormat(simpleFormatter);
        int64_t testTimes[] = {0, 1000, 86400000, 31536000000};
        for (int64_t time : testTimes) {
            styledFormat.Format(static_cast<double>(time));
        }
    }

    void StyledDateTimeFormatFuzzTest005(FuzzedDataProvider& provider)
    {
        std::string input = provider.ConsumeRandomLengthString();
        std::vector<std::string> localeTags;
        localeTags.push_back(input);
        std::unordered_map<std::string, std::string> configs;
        configs["weekday"] = "long";
        configs["year"] = "numeric";
        configs["month"] = "long";
        configs["day"] = "2-digit";
        std::string errMessage;
        std::shared_ptr<IntlDateTimeFormat> intlFormatter =
            std::make_shared<IntlDateTimeFormat>(localeTags, configs, errMessage);

        StyledDateTimeFormat styledFormat(intlFormatter);
        styledFormat.Format(static_cast<double>(provider.remaining_bytes()));
        StyledDateTimeFormat::GetSupportedTypes();
    }

    void StyledDateTimeFormatFuzzTest006(FuzzedDataProvider& provider)
    {
        std::string input = provider.ConsumeRandomLengthString();
        I18nErrorCode errCode = I18nErrorCode::SUCCESS;
        std::shared_ptr<SimpleDateTimeFormat> simpleFormatter =
            std::make_shared<SimpleDateTimeFormat>("yMdHms", input, true, errCode);

        StyledDateTimeFormat styledFormat(simpleFormatter);
        double testValues[] = {std::numeric_limits<double>::min(), std::numeric_limits<double>::max(), 0.0, -1.0};
        for (double val : testValues) {
            styledFormat.Format(val);
        }
    }

    bool DoSomethingInterestingWithMyAPI(const uint8_t* data, size_t size)
    {
        if (data == nullptr || size < 1) {
            return false;
        }

        FuzzedDataProvider provider(data, size);
        StyledDateTimeFormatFuzzTest001(provider);
        StyledDateTimeFormatFuzzTest002(provider);
        StyledDateTimeFormatFuzzTest003(provider);
        StyledDateTimeFormatFuzzTest004(provider);
        StyledDateTimeFormatFuzzTest005(provider);
        StyledDateTimeFormatFuzzTest006(provider);
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