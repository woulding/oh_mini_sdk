/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
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
#include <string>
#include "simple_number_format.h"
#include "locale_info.h"
#include "simplenumberformat_fuzzer.h"

namespace OHOS {
namespace Global {
namespace I18n {
    void SimpleNumberFormatFuzzTest001(FuzzedDataProvider& provider)
    {
        std::string input = provider.ConsumeRandomLengthString();
        I18nErrorCode errCode = I18nErrorCode::SUCCESS;
        SimpleNumberFormat format(input, "en-US", errCode);
        format.Format(12345.67);
    }

    void SimpleNumberFormatFuzzTest002(FuzzedDataProvider& provider)
    {
        std::string input = provider.ConsumeRandomLengthString();
        I18nErrorCode errCode = I18nErrorCode::SUCCESS;
        SimpleNumberFormat format("###,###.##", input, errCode);
        format.Format(1234567.89);
    }

    void SimpleNumberFormatFuzzTest003(FuzzedDataProvider& provider)
    {
        std::string input = provider.ConsumeRandomLengthString();
        std::map<std::string, std::string> options;
        options[input] = input;
        std::shared_ptr<LocaleInfo> localeInfo = std::make_shared<LocaleInfo>(input, options);
        I18nErrorCode errCode = I18nErrorCode::SUCCESS;
        SimpleNumberFormat format("###.00", localeInfo, errCode);
        format.Format(123.456);
    }

    void SimpleNumberFormatFuzzTest004(FuzzedDataProvider& provider)
    {
        std::string input = provider.ConsumeRandomLengthString();
        double number = provider.ConsumeFloatingPoint<double>();
        I18nErrorCode errCode = I18nErrorCode::SUCCESS;
        SimpleNumberFormat format(input, input, errCode);
        if (errCode == I18nErrorCode::SUCCESS) {
            format.Format(number);
        }
        errCode = I18nErrorCode::SUCCESS;
        SimpleNumberFormat formatZh("", "zh-CN", errCode);
        if (errCode == I18nErrorCode::SUCCESS) {
            formatZh.Format(0);
            formatZh.Format(-1);
            formatZh.Format(1000000);
        }
    }

    void SimpleNumberFormatFuzzTest005(FuzzedDataProvider& provider)
    {
        std::string input = provider.ConsumeRandomLengthString();
        I18nErrorCode errCode = I18nErrorCode::SUCCESS;
        SimpleNumberFormat format("scientific", "en-US", errCode);
        format.FormatToFormattedNumber(12345.67);
    }

    void SimpleNumberFormatFuzzTest006(FuzzedDataProvider& provider)
    {
        std::string input = provider.ConsumeRandomLengthString();
        I18nErrorCode errCode = I18nErrorCode::SUCCESS;
        SimpleNumberFormat format("percent", input, errCode);
        format.Format(0.123);
        format.Format(1.0);
        format.Format(-0.5);
    }

    void SimpleNumberFormatFuzzTest007(FuzzedDataProvider& provider)
    {
        std::string input = provider.ConsumeRandomLengthString();
        I18nErrorCode errCode = I18nErrorCode::SUCCESS;
        SimpleNumberFormat format("currency", input, errCode);
        format.Format(123.45);
    }

    bool DoSomethingInterestingWithMyAPI(const uint8_t* data, size_t size)
    {
        if (data == nullptr || size < 1) {
            return false;
        }

        FuzzedDataProvider provider(data, size);
        SimpleNumberFormatFuzzTest001(provider);
        SimpleNumberFormatFuzzTest002(provider);
        SimpleNumberFormatFuzzTest003(provider);
        SimpleNumberFormatFuzzTest004(provider);
        SimpleNumberFormatFuzzTest005(provider);
        SimpleNumberFormatFuzzTest006(provider);
        SimpleNumberFormatFuzzTest007(provider);
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