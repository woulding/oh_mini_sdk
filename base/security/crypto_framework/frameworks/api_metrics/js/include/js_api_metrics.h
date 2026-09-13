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

#ifndef JS_API_METRICS_H
#define JS_API_METRICS_H

#include <string>
#include "result.h"

enum HcfJsApiId {
    /* AsyKeyGenerator */
    API_CREATE_ASY_KEY_GENERATOR,
    /* Sign */
    API_CREATE_SIGN,
    /* Verify */
    API_CREATE_VERIFY,
    /* Kem */
    API_CREATE_KEM,
    API_KEM_ENCAPSULATE,
    API_KEM_ENCAPSULATE_SYNC,
    API_KEM_DECAPSULATE,
    API_KEM_DECAPSULATE_SYNC,
};

class HistogramScopeGuard {
public:
    explicit HistogramScopeGuard(HcfJsApiId id);
    ~HistogramScopeGuard();
    void DisableScopeGuard();
    void SetErrorCode(HcfResult code);
    std::pair<int32_t, int32_t> GetCodeValue(HcfResult code) const;
    std::string GetApiName() const; // for self-validation only

    HistogramScopeGuard(const HistogramScopeGuard &) = delete;
    HistogramScopeGuard &operator=(const HistogramScopeGuard &) = delete;

private:
    static void HistogramApiReport(const std::string &name, int32_t success, int32_t value, int32_t boundary);

    std::string name_;
    HcfResult code_;
};

// createAsyKeyGenerator metrics are only reported for PQC asymmetric key algorithms.
bool IsPqcAsyKeyAlgorithm(const std::string &algName);

// createSign/createVerify metrics are only reported for PQC algorithms.
bool IsPqcSignVerifyAlgorithm(const std::string &algName);

#endif /* JS_API_METRICS_H */
