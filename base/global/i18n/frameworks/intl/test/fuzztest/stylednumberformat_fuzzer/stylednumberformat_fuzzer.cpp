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
#include <memory>
#include <string>
#include <vector>
#include "i18n_types.h"
#include "locale_info.h"
#include "number_format.h"
#include "simple_number_format.h"
#include "styled_number_format.h"
#include "stylednumberformat_fuzzer.h"

namespace OHOS {
namespace Global {
namespace I18n {
    void StyledNumberFormatFuzzTest001(FuzzedDataProvider& provider)
    {
        std::string input = provider.ConsumeRandomLengthString();
        std::vector<std::string> localeTags(1, input);
        std::map<std::string, std::string> configs;
        configs["style"] = "decimal";
        std::shared_ptr<NumberFormat> numberFormat = std::make_shared<NumberFormat>(localeTags, configs);

        StyledNumberFormat styledFormat(numberFormat);
        styledFormat.Format(12345.67);
        styledFormat.ParseToParts(12345.67);
    }

    void StyledNumberFormatFuzzTest002(FuzzedDataProvider& provider)
    {
        std::string input = provider.ConsumeRandomLengthString();
        I18nErrorCode errCode = I18nErrorCode::SUCCESS;
        std::shared_ptr<LocaleInfo> localeInfo = std::make_shared<LocaleInfo>(input);
        std::shared_ptr<SimpleNumberFormat> simpleFormat =
            std::make_shared<SimpleNumberFormat>(input, localeInfo, errCode);

        StyledNumberFormat styledFormat(simpleFormat);
        styledFormat.Format(0.123456);
        styledFormat.ParseToParts(0.123456);
    }

    void StyledNumberFormatFuzzTest003(FuzzedDataProvider& provider)
    {
        std::string input = provider.ConsumeRandomLengthString();
        std::vector<std::string> localeTags(1, input);
        std::map<std::string, std::string> configs;
        configs["style"] = "currency";
        configs["currency"] = "USD";
        std::shared_ptr<NumberFormat> numberFormat = std::make_shared<NumberFormat>(localeTags, configs);

        StyledNumberFormat styledFormat(numberFormat);
        styledFormat.Format(-12345.67);
        styledFormat.ParseToParts(-12345.67);
        styledFormat.Format(std::numeric_limits<double>::infinity());
        styledFormat.ParseToParts(std::numeric_limits<double>::quiet_NaN());
    }

    void StyledNumberFormatFuzzTest004(FuzzedDataProvider& provider)
    {
        std::string input = provider.ConsumeRandomLengthString();
        std::vector<std::string> localeTags(1, input);
        std::map<std::string, std::string> configs;
        configs["style"] = "percent";
        std::shared_ptr<NumberFormat> numberFormat = std::make_shared<NumberFormat>(localeTags, configs);

        StyledNumberFormat styledFormat(numberFormat);
        styledFormat.Format(0.5);
        styledFormat.ParseToParts(0.5);
        styledFormat.Format(100.0);
        styledFormat.ParseToParts(100.0);
    }

    void StyledNumberFormatFuzzTest005(FuzzedDataProvider& provider)
    {
        std::string input = provider.ConsumeRandomLengthString();
        I18nErrorCode errCode = I18nErrorCode::SUCCESS;
        std::shared_ptr<SimpleNumberFormat> simpleFormat =
            std::make_shared<SimpleNumberFormat>(input, "en-US", errCode);

        StyledNumberFormat styledFormat(simpleFormat);
        double testValues[] = {0.0, 1.0, -1.0, 1e10, -1e10, 1.23456789};
        for (double val : testValues) {
            styledFormat.Format(val);
            styledFormat.ParseToParts(val);
        }
    }

    void StyledNumberFormatFuzzTest006(FuzzedDataProvider& provider)
    {
        std::string input = provider.ConsumeRandomLengthString();
        std::vector<std::string> localeTags(1, input);
        std::map<std::string, std::string> configs;
        configs["notation"] = "scientific";
        std::shared_ptr<NumberFormat> numberFormat = std::make_shared<NumberFormat>(localeTags, configs);

        StyledNumberFormat styledFormat(numberFormat);
        styledFormat.Format(1e6);
        styledFormat.ParseToParts(1e6);
        styledFormat.Format(1e-6);
        styledFormat.ParseToParts(1e-6);
    }

    bool DoSomethingInterestingWithMyAPI(const uint8_t* data, size_t size)
    {
        if (data == nullptr || size < 1) {
            return false;
        }

        FuzzedDataProvider provider(data, size);
        StyledNumberFormatFuzzTest001(provider);
        StyledNumberFormatFuzzTest002(provider);
        StyledNumberFormatFuzzTest003(provider);
        StyledNumberFormatFuzzTest004(provider);
        StyledNumberFormatFuzzTest005(provider);
        StyledNumberFormatFuzzTest006(provider);
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