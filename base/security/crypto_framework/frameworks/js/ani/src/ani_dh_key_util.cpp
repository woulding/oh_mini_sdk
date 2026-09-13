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

#include "ani_dh_key_util.h"
#include "dh_key_util.h"
#include "detailed_dh_key_params.h"

namespace ANI::CryptoFramework {
DHCommonParamsSpec GenDHCommonParamsSpec(int32_t pLen, optional_view<int32_t> skLen)
{
    DHCommonParamsSpec dh = {
        .base = {
            .specType = AsyKeySpecType::key_t::COMMON_PARAMS_SPEC
        }
    };
    int32_t skLenValue = skLen.has_value() ? skLen.value() : 0;
    HcfDhCommParamsSpec *dhCommParamsSpec = nullptr;
    HcfResult res = HcfDhKeyUtilCreate(pLen, skLenValue, &dhCommParamsSpec);
    if (res != HCF_SUCCESS) {
        ANI_LOGE_THROW(HCF_INVALID_PARAMS, "create dhKey obj fail!"); // the error code is consistent with 1.1
        return dh;
    }
    dh.base.algName = string(dhCommParamsSpec->base.algName);
    dh.base.specType = AsyKeySpecType(static_cast<AsyKeySpecType::key_t>(dhCommParamsSpec->base.specType));
    dh.l = dhCommParamsSpec->length;
    BigIntegerToArrayU8(dhCommParamsSpec->p, dh.p);
    BigIntegerToArrayU8(dhCommParamsSpec->g, dh.g);
    FreeDhCommParamsSpec(dhCommParamsSpec);
    HCF_FREE_PTR(dhCommParamsSpec);
    return dh;
}
} // namespace ANI::CryptoFramework

// Since these macros are auto-generate, lint will cause false positive.
// NOLINTBEGIN
TH_EXPORT_CPP_API_GenDHCommonParamsSpec(ANI::CryptoFramework::GenDHCommonParamsSpec);
// NOLINTEND
