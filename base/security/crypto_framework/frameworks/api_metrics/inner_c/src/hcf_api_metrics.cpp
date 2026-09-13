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

#include "hcf_api_metrics.h"
#include <string>

#ifdef OPENSSL_API_METRICS_ENABLE
#include "histogram_plugin_macros.h"
#endif

void HcfHistogramAddBoolean(const char *name, int32_t success)
{
    if (name == nullptr) {
        return;
    }

#ifdef OPENSSL_API_METRICS_ENABLE
    std::string full_name(name);
    HISTOGRAM_BOOLEAN((full_name + ".call").c_str(), success);
#endif
}
