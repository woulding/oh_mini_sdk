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

#include "hcfrandcreate_fuzzer.h"

#include <cstddef>
#include <cstdint>

#include "blob.h"
#include "rand.h"
#include "result.h"
#include "securec.h"
#include <fuzzer/FuzzedDataProvider.h>

const uint8_t* g_testFuzzData = nullptr;
size_t g_testFuzzSize = 0;
size_t g_testFuzzPos = 0;

template<class T>
T GetData()
{
    T object{};
    size_t objectSize = sizeof(T);
    if (g_testFuzzData == nullptr || objectSize > g_testFuzzSize - g_testFuzzPos) {
        return object;
    }
    if (memcpy_s(&object, objectSize, g_testFuzzData + g_testFuzzPos, objectSize) != EOK) {
        return {};
    }
    g_testFuzzPos += objectSize;
    return object;
}

namespace OHOS {
    bool HcfRandCreateFuzzTest(FuzzedDataProvider &fdp)
    {
        std::vector<uint8_t> inputData = fdp.ConsumeRemainingBytes<uint8_t>();
        const uint8_t *data = inputData.empty() ? nullptr : inputData.data();
        size_t size = inputData.size();
        g_testFuzzData = data;
        g_testFuzzSize = size;
        g_testFuzzPos = 0;
        int32_t numBytes = GetData<int32_t>();
        HcfRand *randObj = nullptr;
        HcfResult res = HcfRandCreate(&randObj);
        if (res != HCF_SUCCESS) {
            return false;
        }
        struct HcfBlob randomBlob = { 0 };
        (void)randObj->generateRandom(randObj, numBytes, &randomBlob);
        struct HcfBlob seedBlob = { 0 };
        (void)randObj->setSeed(randObj, &seedBlob);
        (void)randObj->getAlgoName(randObj);
        HcfBlobDataFree(&randomBlob);
        HcfBlobDataFree(&seedBlob);
        HcfObjDestroy(randObj);
        return true;
    }
}

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    /* Run your code on data */
    FuzzedDataProvider fdp(data, size);
    OHOS::HcfRandCreateFuzzTest(fdp);
    return 0;
}

