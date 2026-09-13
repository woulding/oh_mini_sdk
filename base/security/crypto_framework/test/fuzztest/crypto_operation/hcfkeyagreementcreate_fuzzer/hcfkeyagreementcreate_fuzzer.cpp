/*
 * Copyright (C) 2022 Huawei Device Co., Ltd.
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

#include "hcfkeyagreementcreate_fuzzer.h"

#include <cstddef>
#include <cstdint>
#include <string>

#include "blob.h"
#include "key_agreement.h"
#include "result.h"
#include <fuzzer/FuzzedDataProvider.h>

namespace OHOS {
    bool HcfKeyAgreementCreateFuzzTest(const uint8_t* data, size_t size)
    {
        if (data == nullptr || size == 0) {
            return false;
        }
        HcfKeyAgreement *keyAgreement = nullptr;
        FuzzedDataProvider fdp(data, size);
        std::string algoName = fdp.ConsumeRemainingBytesAsString();
        int32_t res = HcfKeyAgreementCreate(algoName.c_str(), &keyAgreement);
        if (res != HCF_SUCCESS) {
            return false;
        }
        HcfObjDestroy(keyAgreement);
        return true;
    }
}

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    /* Run your code on data */
    OHOS::HcfKeyAgreementCreateFuzzTest(data, size);
    return 0;
}
