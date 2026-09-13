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
#include "ani_ecc_key_util.h"
#include "detailed_ecc_key_params.h"
#include "ecc_key_util.h"

namespace ANI::CryptoFramework {
ECCCommonParamsSpec GenECCCommonParamsSpec(string_view curveName)
{
    ECFieldFp ecFieldFp = {};
    ECCCommonParamsSpec ecc = {
        .base = {
            .specType = AsyKeySpecType::key_t::COMMON_PARAMS_SPEC,
        },
        .field = OptECField::make_ECFIELDFP(ecFieldFp)
    };
    HcfEccCommParamsSpec *eccCommParamsSpec = nullptr;
    HcfResult res = HcfEccKeyUtilCreate(curveName.c_str(), &eccCommParamsSpec);
    if (res != HCF_SUCCESS) {
        ANI_LOGE_THROW(res, "create eccKey obj fail!");
        return ecc;
    }
    HcfECFieldFp *tmp = reinterpret_cast<HcfECFieldFp *>(eccCommParamsSpec->field);
    ecFieldFp.base.fieldType = string(tmp->base.fieldType);
    BigIntegerToArrayU8(tmp->p, ecFieldFp.p);
    ecc.field = OptECField::make_ECFIELDFP(ecFieldFp);
    ecc.base.algName = string(eccCommParamsSpec->base.algName);
    ecc.base.specType = AsyKeySpecType(static_cast<AsyKeySpecType::key_t>(eccCommParamsSpec->base.specType));
    ecc.h = eccCommParamsSpec->h;
    BigIntegerToArrayU8(eccCommParamsSpec->a, ecc.a);
    BigIntegerToArrayU8(eccCommParamsSpec->b, ecc.b);
    BigIntegerToArrayU8(eccCommParamsSpec->g.x, ecc.g.x);
    BigIntegerToArrayU8(eccCommParamsSpec->g.y, ecc.g.y);
    BigIntegerToArrayU8(eccCommParamsSpec->n, ecc.n);
    FreeEccCommParamsSpec(eccCommParamsSpec);
    HCF_FREE_PTR(eccCommParamsSpec);
    return ecc;
}

Point ConvertPoint(string_view curveName, array_view<uint8_t> encodedPoint)
{
    HcfPoint hcfPoint = {};
    HcfBlob pointBlob = {};
    ArrayU8ToDataBlob(encodedPoint, pointBlob);
    HcfResult res = HcfConvertPoint(curveName.c_str(), &pointBlob, &hcfPoint);
    if (res != HCF_SUCCESS) {
        ANI_LOGE_THROW(res, "failed to convert point.");
        return {};
    }
    Point point = {};
    BigIntegerToArrayU8(hcfPoint.x, point.x);
    BigIntegerToArrayU8(hcfPoint.y, point.y);
    FreeEcPointMem(&hcfPoint);
    return point;
}

array<uint8_t> GetEncodedPoint(string_view curveName, Point const& point, string_view format)
{
    HcfPoint hcfPoint = {};
    bool bigintValid = true;
    bigintValid &= ArrayU8ToBigInteger(point.x, hcfPoint.x);
    bigintValid &= ArrayU8ToBigInteger(point.y, hcfPoint.y);
    if (!bigintValid) {
        ANI_LOGE_THROW(HCF_INVALID_PARAMS, "params is invalid.");
        return {};
    }
    HcfBlob outBlob = {};
    HcfResult res = HcfGetEncodedPoint(curveName.c_str(), &hcfPoint, format.c_str(), &outBlob);
    if (res != HCF_SUCCESS) {
        ANI_LOGE_THROW(res, "fail to get point data.");
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
TH_EXPORT_CPP_API_GenECCCommonParamsSpec(ANI::CryptoFramework::GenECCCommonParamsSpec);
TH_EXPORT_CPP_API_ConvertPoint(ANI::CryptoFramework::ConvertPoint);
TH_EXPORT_CPP_API_GetEncodedPoint(ANI::CryptoFramework::GetEncodedPoint);
// NOLINTEND
