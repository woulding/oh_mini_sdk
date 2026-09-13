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

#include "hcfsm2create_fuzzer.h"

#include <cstddef>
#include <cstdint>
#include <string>
#include "securec.h"

#include "blob.h"
#include "memory.h"
#include "sm2_crypto_params.h"
#include "sm2_crypto_util.h"
#include "result.h"
#include <fuzzer/FuzzedDataProvider.h>

namespace OHOS {
    static const char *g_sm2ModeC1C3C2 = "C1C3C2";
    static const int INPUT_LEN = 121;
    static uint8_t g_input[INPUT_LEN] = {
        48, 119, 2, 33, 0, 183, 70, 70, 149, 188, 64, 6, 110, 236, 85, 149, 216, 224, 102, 95, 92, 41, 105, 232, 5,
        248, 122, 21, 174, 43, 226, 221, 104, 82, 88, 153, 45, 2, 32, 96, 229, 78, 209, 233, 110, 5, 149, 91, 110,
        109, 181, 17, 75, 109, 146, 128, 170, 113, 205, 158, 193, 156, 90, 110, 40, 18, 119, 247, 198, 93, 107, 4,
        32, 87, 167, 167, 247, 88, 146, 203, 234, 83, 126, 117, 129, 52, 142, 82, 54, 152, 226, 201, 111, 143, 115,
        169, 125, 128, 42, 157, 31, 114, 198, 109, 244, 4, 14, 100, 227, 78, 195, 249, 179, 43, 70, 242, 69, 169, 10,
        65, 123
    };
    static HcfBlob g_correctInput = {
        .data = g_input,
        .len = INPUT_LEN
    };
    static const int X_COORDINATE_LEN = 32;
    static unsigned char g_xCoordinate[] = {
        45, 153, 88, 82, 104, 221, 226, 43, 174, 21, 122, 248, 5, 232, 105, 41, 92, 95, 102, 224, 216, 149, 85, 236,
        110, 6, 64, 188, 149, 70, 70, 183
    };
    static const int Y_COORDINATE_LEN = 32;
    static unsigned char g_yCoordinate[] = {
        107, 93, 198, 247, 119, 18, 40, 110, 90, 156, 193, 158, 205, 113, 170, 128, 146, 109, 75, 17, 181, 109, 110,
        91, 149, 5, 110, 233, 209, 78, 229, 96
    };
    static const int HASH_DATA_LEN = 32;
    static unsigned char g_hashData[] = {
        87, 167, 167, 247, 88, 146, 203, 234, 83, 126, 117, 129, 52, 142, 82, 54, 152, 226, 201, 111, 143, 115, 169,
        125, 128, 42, 157, 31, 114, 198, 109, 244
    };
    static const int CIPHER_TEXT_DATA_LEN = 14;
    static unsigned char g_cipherTextData[] = {
        100, 227, 78, 195, 249, 179, 43, 70, 242, 69, 169, 10, 65, 123
    };

    HcfResult ConstructCorrectSm2CipherTextXSpec(Sm2CipherTextSpec **spec, std::vector<uint8_t> &buf)
    {
        Sm2CipherTextSpec *tempSpec = static_cast<Sm2CipherTextSpec *>(HcfMalloc(sizeof(Sm2CipherTextSpec), 0));
        if (tempSpec == nullptr) {
            return HCF_ERR_MALLOC;
        }
        tempSpec->xCoordinate.data = buf.empty() ? nullptr : buf.data();
        tempSpec->xCoordinate.len = buf.size();
        tempSpec->yCoordinate.data = g_yCoordinate;
        tempSpec->yCoordinate.len = Y_COORDINATE_LEN;
        tempSpec->cipherTextData.data = g_cipherTextData;
        tempSpec->cipherTextData.len = CIPHER_TEXT_DATA_LEN;
        tempSpec->hashData.data = g_hashData;
        tempSpec->hashData.len = HASH_DATA_LEN;
        *spec = tempSpec;
        return HCF_SUCCESS;
    }

    HcfResult ConstructCorrectSm2CipherTextYSpec(Sm2CipherTextSpec **spec, std::vector<uint8_t> &buf)
    {
        Sm2CipherTextSpec *tempSpec = static_cast<Sm2CipherTextSpec *>(HcfMalloc(sizeof(Sm2CipherTextSpec), 0));
        if (tempSpec == nullptr) {
            return HCF_ERR_MALLOC;
        }
        tempSpec->xCoordinate.data = g_xCoordinate;
        tempSpec->xCoordinate.len = X_COORDINATE_LEN;
        tempSpec->yCoordinate.data = buf.empty() ? nullptr : buf.data();
        tempSpec->yCoordinate.len = buf.size();
        tempSpec->cipherTextData.data = g_cipherTextData;
        tempSpec->cipherTextData.len = CIPHER_TEXT_DATA_LEN;
        tempSpec->hashData.data = g_hashData;
        tempSpec->hashData.len = HASH_DATA_LEN;
        *spec = tempSpec;
        return HCF_SUCCESS;
    }

    HcfResult ConstructCorrectSm2CipherTextSpec(Sm2CipherTextSpec **spec, std::vector<uint8_t> &buf)
    {
        Sm2CipherTextSpec *tempSpec = static_cast<Sm2CipherTextSpec *>(HcfMalloc(sizeof(Sm2CipherTextSpec), 0));
        if (tempSpec == nullptr) {
            return HCF_ERR_MALLOC;
        }
        tempSpec->xCoordinate.data = g_xCoordinate;
        tempSpec->xCoordinate.len = X_COORDINATE_LEN;
        tempSpec->yCoordinate.data = g_yCoordinate;
        tempSpec->yCoordinate.len = Y_COORDINATE_LEN;
        tempSpec->cipherTextData.data = buf.empty() ? nullptr : buf.data();
        tempSpec->cipherTextData.len = buf.size();
        tempSpec->hashData.data = g_hashData;
        tempSpec->hashData.len = HASH_DATA_LEN;
        *spec = tempSpec;
        return HCF_SUCCESS;
    }

    static void TestHcfGenCipherTextBySpec(FuzzedDataProvider &fdp)
    {
        int res = 0;
        Sm2CipherTextSpec *spec = nullptr;
        std::vector<uint8_t> buf = fdp.ConsumeRemainingBytes<uint8_t>();
        res = ConstructCorrectSm2CipherTextSpec(&spec, buf);
        if (res != HCF_SUCCESS) {
            return;
        }
        HcfBlob output = { .data = nullptr, .len = 0 };
        res = HcfGenCipherTextBySpec(spec, g_sm2ModeC1C3C2, &output);
        if (res != HCF_SUCCESS) {
            HcfFree(spec);
            return;
        }
        if (g_correctInput.len == output.len) {
            (void)memcmp(output.data, g_correctInput.data, g_correctInput.len);
        }
        HcfBlobDataFree(&output);
        HcfFree(spec);
    }

    static void TestHcfGenCipherTextByXSpec(FuzzedDataProvider &fdp)
    {
        int res = 0;
        Sm2CipherTextSpec *spec = nullptr;
        std::vector<uint8_t> buf = fdp.ConsumeRemainingBytes<uint8_t>();
        res = ConstructCorrectSm2CipherTextXSpec(&spec, buf);
        if (res != HCF_SUCCESS) {
            return;
        }
        HcfBlob output = { .data = nullptr, .len = 0 };
        res = HcfGenCipherTextBySpec(spec, g_sm2ModeC1C3C2, &output);
        if (res != HCF_SUCCESS) {
            HcfFree(spec);
            return;
        }
        if (g_correctInput.len == output.len) {
            (void)memcmp(output.data, g_correctInput.data, g_correctInput.len);
        }
        HcfBlobDataFree(&output);
        HcfFree(spec);
    }

    static void TestHcfGenCipherTextByYSpec(FuzzedDataProvider &fdp)
    {
        int res = 0;
        Sm2CipherTextSpec *spec = nullptr;
        std::vector<uint8_t> buf = fdp.ConsumeRemainingBytes<uint8_t>();
        res = ConstructCorrectSm2CipherTextYSpec(&spec, buf);
        if (res != HCF_SUCCESS) {
            return;
        }
        HcfBlob output = { .data = nullptr, .len = 0 };
        res = HcfGenCipherTextBySpec(spec, g_sm2ModeC1C3C2, &output);
        if (res != HCF_SUCCESS) {
            HcfFree(spec);
            return;
        }
        if (g_correctInput.len == output.len) {
            (void)memcmp(output.data, g_correctInput.data, g_correctInput.len);
        }
        HcfBlobDataFree(&output);
        HcfFree(spec);
    }

    static void TestHcfGetCipherTextSpec(FuzzedDataProvider &fdp)
    {
        Sm2CipherTextSpec *spec = nullptr;
        size_t size = fdp.ConsumeIntegral<size_t>();
        char *sm2Mode = reinterpret_cast<char *>(HcfMalloc(size + 1, 0));
        if (sm2Mode == nullptr) {
            return;
        }
        std::vector<uint8_t> buf = fdp.ConsumeBytes<uint8_t>(size);
        if (memcpy_s(sm2Mode, size, buf.data(), size) != EOK) {
            HcfFree(sm2Mode);
            return;
        }
        HcfResult res = HcfGetCipherTextSpec(&g_correctInput, sm2Mode, &spec);
        HcfFree(sm2Mode);
        if (res != HCF_SUCCESS) {
            return;
        }
        DestroySm2CipherTextSpec(spec);
    }

    bool HcfSm2CreateFuzzTest(const uint8_t* data, size_t size)
    {
        if ((data == nullptr) || size < sizeof(uint32_t)) {
            return false;
        }
        FuzzedDataProvider fdp(data, size);
        TestHcfGenCipherTextBySpec(fdp);
        TestHcfGenCipherTextByXSpec(fdp);
        TestHcfGenCipherTextByYSpec(fdp);
        TestHcfGetCipherTextSpec(fdp);

        Sm2CipherTextSpec spec = {};
        spec.xCoordinate.data = g_xCoordinate;
        spec.xCoordinate.len = X_COORDINATE_LEN;
        spec.yCoordinate.data = g_yCoordinate;
        spec.yCoordinate.len = Y_COORDINATE_LEN;
        spec.cipherTextData.data = g_cipherTextData;
        spec.cipherTextData.len = CIPHER_TEXT_DATA_LEN;
        spec.hashData.data = g_hashData;
        spec.hashData.len = HASH_DATA_LEN;

        HcfBlob output = { .data = nullptr, .len = 0 };
        HcfGenCipherTextBySpec(&spec, g_sm2ModeC1C3C2, &output);
        HcfBlobDataFree(&output);
        return true;
    }
}

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    /* Run your code on data */
    OHOS::HcfSm2CreateFuzzTest(data, size);
    return 0;
}
