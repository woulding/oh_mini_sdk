/*
 * Copyright (C) 2026 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 *
 * You may not use this file except in compliance with the License.
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

#include "histogram_base.h"

namespace OHOS::histogram {

/**
 * @brief Constructor for the base histogram class.
 * @param name Unique identifier for the histogram.
 * @param minimum Minimum value for the range.
 * @param maximum Maximum value for the range.
 * @param bucket_count Number of statistical buckets.
 */
HistogramBase::HistogramBase(const std::string &name, int32_t minimum, int32_t maximum, size_t bucket_count)
    : name_(name), minimum_(minimum), maximum_(maximum), bucket_count_(bucket_count) {}

HistogramBase::~HistogramBase() = default;

}  // namespace OHOS::histogram