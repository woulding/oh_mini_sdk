/*
 * Copyright (c) 2025-2025 Huawei Device Co., Ltd.
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

#include "ani_sm2_crypto_util.h"
#include "sm2_crypto_params.h"
#include "sm2_crypto_util.h"

namespace ANI::CryptoFramework {
DataBlob GenCipherTextBySpec(SM2CipherTextSpec const& spec, optional_view<string> mode)
{
    Sm2CipherTextSpec hcfSpec = {};
    bool bigintValid = true;
    bigintValid &= ArrayU8ToBigInteger(spec.xCoordinate, hcfSpec.xCoordinate);
    bigintValid &= ArrayU8ToBigInteger(spec.yCoordinate, hcfSpec.yCoordinate);
    if (!bigintValid) {
        ANI_LOGE_THROW(HCF_INVALID_PARAMS, "params is invalid.");
        return {};
    }
    ArrayU8ToDataBlob(spec.cipherTextData, hcfSpec.cipherTextData);
    ArrayU8ToDataBlob(spec.hashData, hcfSpec.hashData);
    string dataMode = mode.has_value() ? mode.value() : "";
    HcfBlob outBlob = {};
    HcfResult res = HcfGenCipherTextBySpec(&hcfSpec, dataMode.c_str(), &outBlob);
    if (res != HCF_SUCCESS) {
        ANI_LOGE_THROW(res, "gen cipher text by spec fail.");
        return {};
    }
    array<uint8_t> data = {};
    DataBlobToArrayU8(outBlob, data);
    HcfBlobDataClearAndFree(&outBlob);
    return { data };
}

SM2CipherTextSpec GetCipherTextSpec(DataBlob const& cipherText, optional_view<string> mode)
{
    HcfBlob inBlob = {};
    ArrayU8ToDataBlob(cipherText.data, inBlob);
    string dataMode = mode.has_value() ? mode.value() : "";
    Sm2CipherTextSpec *hcfSpec = nullptr;
    HcfResult res = HcfGetCipherTextSpec(&inBlob, dataMode.c_str(), &hcfSpec);
    if (res != HCF_SUCCESS) {
        ANI_LOGE_THROW(res, "get cipher text spec fail.");
        return {};
    }
    SM2CipherTextSpec spec = {};
    BigIntegerToArrayU8(hcfSpec->xCoordinate, spec.xCoordinate);
    BigIntegerToArrayU8(hcfSpec->yCoordinate, spec.yCoordinate);
    DataBlobToArrayU8(hcfSpec->cipherTextData, spec.cipherTextData);
    DataBlobToArrayU8(hcfSpec->hashData, spec.hashData);
    DestroySm2CipherTextSpec(hcfSpec);
    return spec;
}
} // namespace ANI::CryptoFramework

// Since these macros are auto-generate, lint will cause false positive.
// NOLINTBEGIN
TH_EXPORT_CPP_API_GenCipherTextBySpec(ANI::CryptoFramework::GenCipherTextBySpec);
TH_EXPORT_CPP_API_GetCipherTextSpec(ANI::CryptoFramework::GetCipherTextSpec);
// NOLINTEND
