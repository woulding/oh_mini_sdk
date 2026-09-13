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
#include <map>
#include <string>
#include <vector>
#include <fuzzer/FuzzedDataProvider.h>
#include "relative_time_format.h"
#include "relativetimeformat_fuzzer.h"

namespace OHOS {
namespace Global {
namespace I18n {

    void RelativeTimeFormatFuzzTest001(FuzzedDataProvider& provider)
    {
        std::string input = provider.ConsumeRandomLengthString();
        std::vector<std::string> localeTags(1, input);
        std::map<std::string, std::string> options;
        options[input] = input;

        RelativeTimeFormat formatter(localeTags, options);
        formatter.Format(5, "second");
        formatter.Format(10, "minute");
        formatter.Format(2, "hour");
        formatter.Format(3, "day");
        formatter.Format(1, "week");
        formatter.Format(6, "month");
        formatter.Format(7, "quarter");
        formatter.Format(8, "year");
        std::map<std::string, std::string> res;
        formatter.GetResolvedOptions(res);
    }

    void RelativeTimeFormatFuzzTest002(FuzzedDataProvider& provider)
    {
        std::string input = provider.ConsumeRandomLengthString();
        std::vector<std::string> localeTags(1, input);
        std::map<std::string, std::string> options;
        options["style"] = "long";

        RelativeTimeFormat formatter(localeTags, options);
        double number = provider.ConsumeFloatingPoint<double>();
        formatter.Format(number, input);
    }

    void RelativeTimeFormatFuzzTest003(FuzzedDataProvider& provider)
    {
        std::string input = provider.ConsumeRandomLengthString();
        std::vector<std::string> localeTags(1, input);
        std::map<std::string, std::string> options;
        options["style"] = "short";

        RelativeTimeFormat formatter(localeTags, options);
        formatter.Format(1, "second");
        formatter.Format(1, "minute");
        formatter.Format(1, "hour");
    }

    void RelativeTimeFormatFuzzTest004(FuzzedDataProvider& provider)
    {
        std::string input = provider.ConsumeRandomLengthString();
        std::vector<std::string> localeTags(1, input);
        std::map<std::string, std::string> options;
        options["style"] = "narrow";

        RelativeTimeFormat formatter(localeTags, options);
        formatter.Format(-5, "day");
        formatter.Format(-10, "hour");
    }

    void RelativeTimeFormatFuzzTest005(FuzzedDataProvider& provider)
    {
        std::string input = provider.ConsumeRandomLengthString();
        std::vector<std::string> localeTags(1, input);
        std::map<std::string, std::string> options;
        options["numeric"] = "auto";

        RelativeTimeFormat formatter(localeTags, options);
        std::vector<std::vector<std::string>> timeVector;
        double number = provider.ConsumeFloatingPoint<double>();
        formatter.FormatToParts(number, input, timeVector);
    }

    void RelativeTimeFormatFuzzTest006(FuzzedDataProvider& provider)
    {
        std::string input = provider.ConsumeRandomLengthString();
        std::vector<std::string> localeTags(1, input);
        std::map<std::string, std::string> options;
        options["localeMatcher"] = "lookup";

        RelativeTimeFormat formatter(localeTags, options);
        formatter.Format(100, "second");
        std::map<std::string, std::string> res;
        formatter.GetResolvedOptions(res);
    }

    bool DoSomethingInterestingWithMyAPI(const uint8_t* data, size_t size)
    {
        if (data == nullptr || size < 1) {
            return false;
        }
        FuzzedDataProvider provider(data, size);

        RelativeTimeFormatFuzzTest001(provider);
        RelativeTimeFormatFuzzTest002(provider);
        RelativeTimeFormatFuzzTest003(provider);
        RelativeTimeFormatFuzzTest004(provider);
        RelativeTimeFormatFuzzTest005(provider);
        RelativeTimeFormatFuzzTest006(provider);
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