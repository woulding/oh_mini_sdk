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

#include "hcfsigncreate_fuzzer.h"

#include <cstddef>
#include <cstdint>
#include <string>

#include "asy_key_generator.h"
#include "blob.h"
#include "result.h"
#include "signature.h"
#include <fuzzer/FuzzedDataProvider.h>

namespace OHOS {
    static void TestSign(FuzzedDataProvider &fdp)
    {
        HcfAsyKeyGenerator *generator = nullptr;
        HcfResult res = HcfAsyKeyGeneratorCreate("ECC384", &generator);
        if (res != HCF_SUCCESS) {
            return;
        }

        HcfKeyPair *ecc384KeyPair = nullptr;
        res = generator->generateKeyPair(generator, nullptr, &ecc384KeyPair);
        HcfObjDestroy(generator);
        if (res != HCF_SUCCESS) {
            return;
        }

        HcfSign *sign = nullptr;
        res = HcfSignCreate("ECC384|SHA384", &sign);
        if (res != HCF_SUCCESS) {
            HcfObjDestroy(ecc384KeyPair);
            return;
        }
        std::vector<uint8_t> inputData = fdp.ConsumeRemainingBytes<uint8_t>();
        HcfBlob mockInput = {
            .data = inputData.empty() ? nullptr : inputData.data(),
            .len = inputData.size()
        };
        (void)sign->init(sign, nullptr, ecc384KeyPair->priKey);
        (void)sign->update(sign, &mockInput);
        HcfObjDestroy(ecc384KeyPair);
        HcfObjDestroy(sign);
    }

    static void TestSignSm2(FuzzedDataProvider &fdp)
    {
        HcfAsyKeyGenerator *generator = nullptr;
        HcfResult res = HcfAsyKeyGeneratorCreate("SM2_256", &generator);
        if (res != HCF_SUCCESS) {
            return;
        }

        HcfKeyPair *sm2256KeyPair = nullptr;
        res = generator->generateKeyPair(generator, nullptr, &sm2256KeyPair);
        HcfObjDestroy(generator);
        if (res != HCF_SUCCESS) {
            return;
        }

        HcfSign *sign = nullptr;
        res = HcfSignCreate("SM2_256|SM3", &sign);
        if (res != HCF_SUCCESS) {
            HcfObjDestroy(sm2256KeyPair);
            return;
        }
        std::vector<uint8_t> inputData = fdp.ConsumeRemainingBytes<uint8_t>();
        HcfBlob mockInput = {
            .data = inputData.empty() ? nullptr : inputData.data(),
            .len = inputData.size()
        };
        (void)sign->init(sign, nullptr, sm2256KeyPair->priKey);
        (void)sign->update(sign, &mockInput);
        HcfObjDestroy(sm2256KeyPair);
        HcfObjDestroy(sign);
    }

    static void TestSignBrainpool(FuzzedDataProvider &fdp)
    {
        HcfAsyKeyGenerator *generator = nullptr;
        HcfResult res = HcfAsyKeyGeneratorCreate("ECC_BrainPoolP160r1", &generator);
        if (res != HCF_SUCCESS) {
            return;
        }

        HcfKeyPair *brainPoolP160r1KeyPair = nullptr;
        res = generator->generateKeyPair(generator, nullptr, &brainPoolP160r1KeyPair);
        HcfObjDestroy(generator);
        if (res != HCF_SUCCESS) {
            return;
        }

        HcfSign *sign = nullptr;
        res = HcfSignCreate("ECC_BrainPoolP160r1|SHA1", &sign);
        if (res != HCF_SUCCESS) {
            HcfObjDestroy(brainPoolP160r1KeyPair);
            return;
        }
        std::vector<uint8_t> inputData = fdp.ConsumeRemainingBytes<uint8_t>();
        HcfBlob mockInput = {
            .data = inputData.empty() ? nullptr : inputData.data(),
            .len = inputData.size()
        };
        (void)sign->init(sign, nullptr, brainPoolP160r1KeyPair->priKey);
        (void)sign->update(sign, &mockInput);
        HcfObjDestroy(brainPoolP160r1KeyPair);
        HcfObjDestroy(sign);
    }

    static void TestSignEd25519(FuzzedDataProvider &fdp)
    {
        HcfAsyKeyGenerator *generator = nullptr;
        HcfResult res = HcfAsyKeyGeneratorCreate("Ed25519", &generator);
        if (res != HCF_SUCCESS) {
            return;
        }

        HcfKeyPair *ed25519KeyPair = nullptr;
        res = generator->generateKeyPair(generator, nullptr, &ed25519KeyPair);
        HcfObjDestroy(generator);
        if (res != HCF_SUCCESS) {
            return;
        }

        HcfSign *sign = nullptr;
        res = HcfSignCreate("Ed25519", &sign);
        if (res != HCF_SUCCESS) {
            HcfObjDestroy(ed25519KeyPair);
            return;
        }
        std::vector<uint8_t> inputData = fdp.ConsumeRemainingBytes<uint8_t>();
        HcfBlob mockInput = {
            .data = inputData.empty() ? nullptr : inputData.data(),
            .len = inputData.size()
        };
        (void)sign->init(sign, nullptr, ed25519KeyPair->priKey);
        (void)sign->update(sign, &mockInput);
        HcfObjDestroy(ed25519KeyPair);
        HcfObjDestroy(sign);
    }

    bool HcfSignCreateFuzzTest(const uint8_t* data, size_t size)
    {
        FuzzedDataProvider fdp(data, size);
        TestSign(fdp);
        TestSignSm2(fdp);
        TestSignBrainpool(fdp);
        TestSignEd25519(fdp);
        HcfSign *sign = nullptr;
        std::string algoName = fdp.ConsumeRemainingBytesAsString();
        HcfResult res = HcfSignCreate(algoName.c_str(), &sign);
        if (res != HCF_SUCCESS) {
            return false;
        }
        HcfObjDestroy(sign);
        return true;
    }
}

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    /* Run your code on data */
    OHOS::HcfSignCreateFuzzTest(data, size);
    return 0;
}
