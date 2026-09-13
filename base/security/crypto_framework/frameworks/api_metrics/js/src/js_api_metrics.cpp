/*
 * Copyright (c) 2026 Huawei Device Co., Ltd.
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

#include "js_api_metrics.h"
#include <string>
#include <unordered_map>
#include <unordered_set>

#ifdef CRYPTO_FRAMEWORK_API_METRICS_ENABLE
#include "histogram_plugin_macros.h"
#endif

#define HCF "cryptoFramework."

static const std::unordered_map<HcfJsApiId, std::string> APIS_NAME = {
    /* AsyKeyGenerator */
    { API_CREATE_ASY_KEY_GENERATOR, HCF "createAsyKeyGenerator" },
    /* Sign */
    { API_CREATE_SIGN, HCF "createSign" },
    /* Verify */
    { API_CREATE_VERIFY, HCF "createVerify" },
    /* Kem */
    { API_CREATE_KEM, HCF "createKem" },
    { API_KEM_ENCAPSULATE, HCF "Kem.encapsulate" },
    { API_KEM_ENCAPSULATE_SYNC, HCF "Kem.encapsulateSync" },
    { API_KEM_DECAPSULATE, HCF "Kem.decapsulate" },
    { API_KEM_DECAPSULATE_SYNC, HCF "Kem.decapsulateSync" },
};

static const std::unordered_map<HcfResult, int32_t> ERROR_CODES = {
    { HCF_SUCCESS, 0 },                     /* 0 */
    { HCF_INVALID_PARAMS, 1 },              /* 401 */
    { HCF_NOT_SUPPORT, 2 },                 /* 801 */
    { HCF_ERR_MALLOC, 3 },                  /* 17620001 */
    { HCF_ERR_NAPI, 4 },                    /* 17620002 */
    { HCF_ERR_ANI, 4 },                     /* 17620002 */
    { HCF_ERR_PARAMETER_CHECK_FAILED, 5 },  /* 17620003 */
    { HCF_ERR_INVALID_CALL, 6 },            /* 17620004 */
    { HCF_ERR_CRYPTO_OPERATION, 7 },        /* 17630001 */
};

HistogramScopeGuard::HistogramScopeGuard(HcfJsApiId id) : name_(""), code_(HCF_SUCCESS)
{
    auto it = APIS_NAME.find(id);
    if (it != APIS_NAME.end()) {
        name_ = it->second;
    }
}

HistogramScopeGuard::~HistogramScopeGuard()
{
    int32_t success = (code_ == HCF_SUCCESS ? 1 : 0);
    auto [value, boundary] = GetCodeValue(code_);
    HistogramApiReport(name_, success, value, boundary);
}

void HistogramScopeGuard::DisableScopeGuard()
{
     // clear name, skip report when name is empty in function called
    name_.clear();
}

void HistogramScopeGuard::SetErrorCode(HcfResult code)
{
    code_ = code;
}

std::pair<int32_t, int32_t> HistogramScopeGuard::GetCodeValue(HcfResult code) const
{
    int32_t boundary = static_cast<int32_t>(ERROR_CODES.size());
    int32_t value = -1;
    auto it = ERROR_CODES.find(code);
    if (it != ERROR_CODES.end()) {
        value = it->second;
    }
    return { value, boundary };
}

std::string HistogramScopeGuard::GetApiName() const
{
    return name_;
}

void HistogramScopeGuard::HistogramApiReport(const std::string &name, int32_t success, int32_t value, int32_t boundary)
{
#ifdef CRYPTO_FRAMEWORK_API_METRICS_ENABLE
    if (!name.empty()) {
        HISTOGRAM_BOOLEAN((name + ".call").c_str(), success);
        // Only report non-zero errcodes, skip HCF_SUCCESS(0) to reduce invalid report traffic
        if (value > 0) {
            HISTOGRAM_ENUMERATION((name + ".errcode").c_str(), value, boundary);
        }
    }
#endif
}

bool IsPqcAsyKeyAlgorithm(const std::string &algName)
{
    return algName == "ML-KEM-512" || algName == "ML-KEM-768" || algName == "ML-KEM-1024" ||
           algName == "ML-DSA-44" || algName == "ML-DSA-65" || algName == "ML-DSA-87";
}

bool IsPqcSignVerifyAlgorithm(const std::string &algName)
{
    return algName == "ML-DSA";
}
