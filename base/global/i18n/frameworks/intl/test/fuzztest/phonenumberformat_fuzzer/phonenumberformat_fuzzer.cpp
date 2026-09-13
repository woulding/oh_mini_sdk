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
#include "phone_number_format.h"
#include "phonenumberformat_fuzzer.h"

namespace OHOS {
    bool DoSomethingInterestingWithMyAPI(const uint8_t* data, size_t size)
    {
        if (data == nullptr || size < 1) {
            return false;
        }
        FuzzedDataProvider provider(data, size);
        using namespace Global::I18n;
        std::string input = provider.ConsumeRandomLengthString();
        std::map<std::string, std::string> options;
        options[input] = input;
        PhoneNumberFormat formatter(input, options);
        formatter.isValidPhoneNumber(input);
        formatter.format(input);
        formatter.getLocationName(input, input);
        formatter.getPhoneLocationName(input, input, input);
        formatter.getBlockedRegionName(input, input);
        formatter.getCityName(input, input, input);
        PhoneNumberFormat::CreateInstance(input, options);
        return true;
    }
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    OHOS::DoSomethingInterestingWithMyAPI(data, size);
    return 0;
}