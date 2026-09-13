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

#include "ani_signature_utils.h"
#include "sm2_ec_signature_data.h"
#include "sm2_crypto_params.h"

namespace ANI::CryptoFramework {
EccSignatureSpec GenEccSignatureSpec(array_view<uint8_t> data)
{
    HcfBlob inBlob = {};
    ArrayU8ToDataBlob(data, inBlob);
    Sm2EcSignatureDataSpec *hcfSpec = nullptr;
    HcfResult res = HcfGenEcSignatureSpecByData(&inBlob, &hcfSpec);
    if (res != HCF_SUCCESS) {
        ANI_LOGE_THROW(res, "gen ec signature spec fail.");
        return {};
    }
    EccSignatureSpec spec = {};
    BigIntegerToArrayU8(hcfSpec->rCoordinate, spec.r);
    BigIntegerToArrayU8(hcfSpec->sCoordinate, spec.s);
    DestroySm2EcSignatureSpec(hcfSpec);
    return spec;
}

array<uint8_t> GenEccSignature(EccSignatureSpec const& spec)
{
    Sm2EcSignatureDataSpec hcfSpec = {};
    bool bigintValid = true;
    bigintValid &= ArrayU8ToBigInteger(spec.r, hcfSpec.rCoordinate);
    bigintValid &= ArrayU8ToBigInteger(spec.s, hcfSpec.sCoordinate);
    if (!bigintValid) {
        ANI_LOGE_THROW(HCF_INVALID_PARAMS, "params is invalid.");
        return {};
    }

    HcfBlob outBlob = {};
    HcfResult res = HcfGenEcSignatureDataBySpec(&hcfSpec, &outBlob);
    if (res != HCF_SUCCESS) {
        ANI_LOGE_THROW(res, "gen ec signature data fail.");
        return {};
    }
    array<uint8_t> data = {};
    DataBlobToArrayU8(outBlob, data);
    HcfBlobDataClearAndFree(&outBlob);
    return data;
}
} // namespace ANI::CryptoFramework

// Since these macros are auto-generate, lint will cause false positive.
// NOLINTBEGIN
TH_EXPORT_CPP_API_GenEccSignatureSpec(ANI::CryptoFramework::GenEccSignatureSpec);
TH_EXPORT_CPP_API_GenEccSignature(ANI::CryptoFramework::GenEccSignature);
// NOLINTEND
