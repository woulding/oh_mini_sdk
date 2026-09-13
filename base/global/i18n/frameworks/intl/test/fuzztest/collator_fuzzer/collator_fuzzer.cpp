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
#include <string>
#include <vector>
#include "collator.h"
#include "collator_fuzzer.h"

namespace OHOS {
namespace Global {
namespace I18n {
    void CollatorFuzzTest001(FuzzedDataProvider& provider)
    {
        std::string input = provider.ConsumeRandomLengthString();
        std::vector<std::string> localeTags(1, input);
        std::map<std::string, std::string> options;
        options[input] = input;

        Collator collator(localeTags, options);
        collator.Compare(input, "for test");
        collator.ResolvedOptions(options);
        collator.GetError();
    }

    void CollatorFuzzTest002(FuzzedDataProvider& provider)
    {
        std::string input = provider.ConsumeRandomLengthString();
        std::vector<std::string> localeTags(1, input);
        std::map<std::string, std::string> options;
        options["usage"] = "search";

        Collator collator(localeTags, options);
        collator.Compare(input, input);
        collator.GetError();
    }

    void CollatorFuzzTest003(FuzzedDataProvider& provider)
    {
        std::string input = provider.ConsumeRandomLengthString();
        std::vector<std::string> localeTags(1, input);
        std::map<std::string, std::string> options;
        options["sensitivity"] = "base";

        Collator collator(localeTags, options);
        collator.Compare(input, input);
        collator.GetError();
    }

    void CollatorFuzzTest004(FuzzedDataProvider& provider)
    {
        std::string input = provider.ConsumeRandomLengthString();
        std::vector<std::string> localeTags(1, input);
        std::map<std::string, std::string> options;
        options["sensitivity"] = "accent";

        Collator collator(localeTags, options);
        collator.Compare(input, input);
        collator.GetError();
    }

    void CollatorFuzzTest005(FuzzedDataProvider& provider)
    {
        std::string input = provider.ConsumeRandomLengthString();
        std::vector<std::string> localeTags(1, input);
        std::map<std::string, std::string> options;
        options["sensitivity"] = "case";

        Collator collator(localeTags, options);
        collator.Compare(input, input);
        collator.GetError();
    }

    void CollatorFuzzTest006(FuzzedDataProvider& provider)
    {
        std::string input = provider.ConsumeRandomLengthString();
        std::vector<std::string> localeTags(1, input);
        std::map<std::string, std::string> options;
        options["caseFirst"] = "upper";

        Collator collator(localeTags, options);
        collator.Compare(input, input);
        collator.GetError();
    }

    void CollatorFuzzTest007(FuzzedDataProvider& provider)
    {
        std::string input = provider.ConsumeRandomLengthString();
        std::vector<std::string> localeTags(1, input);
        std::map<std::string, std::string> options;
        options["caseFirst"] = "lower";

        Collator collator(localeTags, options);
        collator.Compare(input, input);
        collator.GetError();
    }

    void CollatorFuzzTest008(FuzzedDataProvider& provider)
    {
        std::string input = provider.ConsumeRandomLengthString();
        std::vector<std::string> localeTags(1, input);
        std::map<std::string, std::string> options;
        options["numeric"] = "true";

        Collator collator(localeTags, options);
        collator.Compare(input, input);
        collator.GetError();
    }

    void CollatorFuzzTest009(FuzzedDataProvider& provider)
    {
        std::string input = provider.ConsumeRandomLengthString();
        std::vector<std::string> localeTags(1, input);
        std::map<std::string, std::string> options;
        options["ignorePunctuation"] = "true";

        Collator collator(localeTags, options);
        collator.Compare(input, input);
        collator.GetError();
    }

    void CollatorFuzzTest010(FuzzedDataProvider& provider)
    {
        std::string input = provider.ConsumeRandomLengthString();
        std::vector<std::string> localeTags(1, input);
        std::map<std::string, std::string> options;
        options["collation"] = input;

        Collator collator(localeTags, options);
        collator.Compare(input, input);
        collator.GetError();
    }

    void CollatorFuzzTest011(FuzzedDataProvider& provider)
    {
        std::string input = provider.ConsumeRandomLengthString();
        std::vector<std::string> localeTags;
        localeTags.push_back(input);
        std::map<std::string, std::string> options;
        options[input] = input;

        I18nErrorCode status = I18nErrorCode::SUCCESS;
        Collator::SupportedLocalesOf(localeTags, options, status);
    }

    void CollatorFuzzTest012(FuzzedDataProvider& provider)
    {
        std::string input = provider.ConsumeRandomLengthString();
        std::vector<std::string> localeTags(1, input);
        std::map<std::string, std::string> options;
        options["localeMatcher"] = "lookup";

        I18nErrorCode status = I18nErrorCode::SUCCESS;
        Collator::SupportedLocalesOf(localeTags, options, status);
    }

    void CollatorFuzzTest013(FuzzedDataProvider& provider)
    {
        std::string input = provider.ConsumeRandomLengthString();
        std::vector<std::string> localeTags(1, "invalid-locale");
        std::map<std::string, std::string> options;
        options[input] = input;

        Collator collator(localeTags, options);
        collator.Compare(input, input);
        collator.GetError();
    }

    bool DoSomethingInterestingWithMyAPI(const uint8_t* data, size_t size)
    {
        if (data == nullptr || size < 1) {
            return false;
        }

        FuzzedDataProvider provider(data, size);
        CollatorFuzzTest001(provider);
        CollatorFuzzTest002(provider);
        CollatorFuzzTest003(provider);
        CollatorFuzzTest004(provider);
        CollatorFuzzTest005(provider);
        CollatorFuzzTest006(provider);
        CollatorFuzzTest007(provider);
        CollatorFuzzTest008(provider);
        CollatorFuzzTest009(provider);
        CollatorFuzzTest010(provider);
        CollatorFuzzTest011(provider);
        CollatorFuzzTest012(provider);
        CollatorFuzzTest013(provider);
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