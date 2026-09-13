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

#include "symkeygenerator_fuzzer.h"

#include <cstddef>
#include <cstdint>
#include <string>
#include "securec.h"
#include "result.h"
#include "memory.h"
#include "sym_key_generator.h"
#include <fuzzer/FuzzedDataProvider.h>

namespace OHOS {
bool SymKeyGeneratorFuzzTest(const uint8_t* data, size_t size)
{
    int ret = 0;
    HcfSymKeyGenerator *generator = nullptr;
    HcfSymKey *key = nullptr;
    FuzzedDataProvider fdp(data, size);
    std::string algoName = fdp.ConsumeRemainingBytesAsString();
    ret = HcfSymKeyGeneratorCreate(algoName.c_str(), &generator);
    if (ret != HCF_SUCCESS) {
        return false;
    }

    ret = generator->generateSymKey(generator, &key);
    if (ret != HCF_SUCCESS) {
        HcfObjDestroy(generator);
        return false;
    }
    key->clearMem(key);
    HcfObjDestroy(generator);
    HcfObjDestroy(key);
    return true;
}
}

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    /* Run your code on data */
    OHOS::SymKeyGeneratorFuzzTest(data, size);
    return 0;
}
