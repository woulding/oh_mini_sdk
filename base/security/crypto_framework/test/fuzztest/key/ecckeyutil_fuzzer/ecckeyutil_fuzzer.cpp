/*
 * Copyright (C) 2023 Huawei Device Co., Ltd.
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

#include "ecckeyutil_fuzzer.h"

#include <cstddef>
#include <cstdint>
#include <string>

#include "ecc_key_util.h"
#include "blob.h"
#include "detailed_ecc_key_params.h"
#include "result.h"
#include <fuzzer/FuzzedDataProvider.h>

using namespace std;

namespace OHOS {
    static bool g_testFlag = true;
    static void TestEccKey(void)
    {
        HcfEccCommParamsSpec *returnCommonParamSpec = nullptr;
        int32_t res = HcfEccKeyUtilCreate("NID_secp224r1", &returnCommonParamSpec);
        if (res != HCF_SUCCESS) {
            return;
        }
        FreeEccCommParamsSpec(returnCommonParamSpec);
    }

    static void TestSm2Key(void)
    {
        HcfEccCommParamsSpec *returnCommonParamSpec = nullptr;
        int32_t res = HcfEccKeyUtilCreate("NID_sm2", &returnCommonParamSpec);
        if (res != HCF_SUCCESS) {
            return;
        }
        FreeEccCommParamsSpec(returnCommonParamSpec);
    }

    static void TestBrainpoolKey(void)
    {
        HcfEccCommParamsSpec *returnCommonParamSpec = nullptr;
        int32_t res = HcfEccKeyUtilCreate("NID_brainpoolP160r1", &returnCommonParamSpec);
        if (res != HCF_SUCCESS) {
            return;
        }
        FreeEccCommParamsSpec(returnCommonParamSpec);
    }

    bool EccKeyUtilFuzzTest(const uint8_t* data, size_t size)
    {
        if (g_testFlag) {
            TestEccKey();
            TestSm2Key();
            TestBrainpoolKey();
            g_testFlag = false;
        }
        HcfEccCommParamsSpec *returnCommonParamSpec = nullptr;
        FuzzedDataProvider fdp(data, size);
        std::string algoName = fdp.ConsumeRemainingBytesAsString();
        HcfResult res = HcfEccKeyUtilCreate(algoName.c_str(), &returnCommonParamSpec);
        if (res != HCF_SUCCESS) {
            return false;
        }
        FreeEccCommParamsSpec(returnCommonParamSpec);
        return true;
    }
}

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    /* Run your code on data */
    OHOS::EccKeyUtilFuzzTest(data, size);
    return 0;
}
