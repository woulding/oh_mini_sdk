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
#include <vector>
#include "displaynames.h"
#include "displaynames_fuzzer.h"

namespace OHOS {
namespace Global {
namespace I18n {
    void DisplayNamesFuzzTest001(FuzzedDataProvider& provider)
    {
        std::string input = provider.ConsumeRandomLengthString();
        std::vector<std::string> localeTags;
        localeTags.push_back(input);
        std::map<std::string, std::string> options;
        options["type"] = input;
        options[input] = input;

        DisplayNames displayNames(localeTags, options);
        displayNames.Display(input);
        displayNames.ResolvedOptions();
        displayNames.GetError();
        displayNames.GetErrorMessage();
    }

    void DisplayNamesFuzzTest002(FuzzedDataProvider& provider)
    {
        std::string input = provider.ConsumeRandomLengthString();
        std::vector<std::string> localeTags;
        localeTags.push_back(input);
        std::map<std::string, std::string> options;
        options["type"] = "language";

        DisplayNames displayNames(localeTags, options);
        displayNames.Display(input);
        displayNames.ResolvedOptions();
    }

    void DisplayNamesFuzzTest003(FuzzedDataProvider& provider)
    {
        std::string input = provider.ConsumeRandomLengthString();
        std::vector<std::string> localeTags;
        localeTags.push_back(input);
        std::map<std::string, std::string> options;
        options["type"] = "region";

        DisplayNames displayNames(localeTags, options);
        displayNames.Display(input);
        displayNames.ResolvedOptions();
    }

    void DisplayNamesFuzzTest004(FuzzedDataProvider& provider)
    {
        std::string input = provider.ConsumeRandomLengthString();
        std::vector<std::string> localeTags;
        localeTags.push_back(input);
        std::map<std::string, std::string> options;
        options["type"] = "calendar";

        DisplayNames displayNames(localeTags, options);
        displayNames.Display(input);
        displayNames.ResolvedOptions();
    }

    void DisplayNamesFuzzTest005(FuzzedDataProvider& provider)
    {
        std::string input = provider.ConsumeRandomLengthString();
        std::vector<std::string> requestLocales;
        requestLocales.push_back(input);
        std::map<std::string, std::string> options;
        options[input] = input;

        I18nErrorCode status = I18nErrorCode::SUCCESS;
        DisplayNames::SupportedLocalesOf(requestLocales, options, status);
    }

    bool DoSomethingInterestingWithMyAPI(const uint8_t* data, size_t size)
    {
        if (data == nullptr || size < 1) {
            return false;
        }

        FuzzedDataProvider provider(data, size);
        DisplayNamesFuzzTest001(provider);
        DisplayNamesFuzzTest002(provider);
        DisplayNamesFuzzTest003(provider);
        DisplayNamesFuzzTest004(provider);
        DisplayNamesFuzzTest005(provider);
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