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

#ifndef HISTOGRAM_PLUGIN_MACROS_H
#define HISTOGRAM_PLUGIN_MACROS_H

#include "plugin_interface.h"

namespace OHOS::histogram {

/**
 * @brief Returns the process-wide singleton PluginInterface instance.
 *
 * This accessor is intentionally inline for zero-cost expansion on hot paths.
 * The local static object is initialized once in a thread-safe manner
 * according to modern C++ static initialization guarantees.
 *
 * @return Reference to singleton PluginInterface.
 */
inline PluginInterface &GetHistogramPlugin()
{
    static PluginInterface instance;
    return instance;
}

} // namespace OHOS::histogram

/**
 * @brief Record a boolean histogram sample.
 *
 * Valid sample values:
 *   0 = false / failure / disabled / no
 *   1 = true  / success / enabled  / yes
 *
 * Typical use cases:
 *   - API success rate
 *   - Feature switch enabled ratio
 *   - Permission granted or denied
 *
 * @param name Histogram metric name.
 * @param sample Must be 0 or 1.
 */
#define HISTOGRAM_BOOLEAN(name, sample) \
    (void)OHOS::histogram::GetHistogramPlugin().AddBooleanSample(name, sample)

/**
 * @brief Record an enumeration histogram sample.
 *
 * Valid input range:
 *   sample   ∈ [0, boundary]
 *   boundary > 0
 *
 * Typical use cases:
 *   - Error codes mapped to small enums
 *   - State machine final state
 *   - User selected mode index
 *
 * Example:
 *   boundary = 4 means legal values are 0,1,2,3,4
 *
 * @param name Histogram metric name.
 * @param sample Enum value to record.
 * @param boundary Maximum enum value (inclusive).
 */
#define HISTOGRAM_ENUMERATION(name, sample, boundary) \
    (void)OHOS::histogram::GetHistogramPlugin().AddEnumSample(name, sample, boundary)

/**
 * @brief Record a custom count histogram sample.
 *
 * Valid input rules:
 *   sample       ∈ [0, INT32_MAX)
 *   min          >= 0
 *   max          < INT32_MAX
 *   min          < max
 *   bucket_count >= 2
 *   bucket_count < 100
 *
 * Typical use cases:
 *   - Retry count
 *   - Object count
 *   - Cache item count
 *   - Queue depth
 *
 * Example:
 *   HISTOGRAM_CUSTOM_COUNTS("task.retry", 3, 1, 50, 20)
 *
 * @param name Histogram metric name.
 * @param sample Sample value to record.
 * @param min Lower bound of histogram domain.
 * @param max Upper bound of histogram domain.
 * @param bucket_count Bucket count, must be < 100.
 */
#define HISTOGRAM_CUSTOM_COUNTS(name, sample, min, max, bucket_count) \
    (void)OHOS::histogram::GetHistogramPlugin().AddCountSample(name, sample, min, max, bucket_count)

/**
 * @brief Record a time histogram sample.
 *
 * Valid sample range:
 *   sample ∈ [0, INT32_MAX)
 *
 * Unit recommendation:
 *   milliseconds (ms)
 *
 * Typical use cases:
 *   - API latency
 *   - Page render time
 *   - Startup duration
 *   - IPC execution cost
 *
 * @param name Histogram metric name.
 * @param sample Time cost value, normally milliseconds.
 */
#define HISTOGRAM_TIMES(name, sample) \
    (void)OHOS::histogram::GetHistogramPlugin().AddTimeSample(name, sample)

/**
 * @brief Record a percentage histogram sample.
 *
 * Valid sample range:
 *   sample ∈ [0, 100]
 *
 * Typical use cases:
 *   - CPU utilization
 *   - Success percentage
 *   - Download progress
 *   - Cache hit ratio
 *
 * @param name Histogram metric name.
 * @param sample Percentage value from 0 to 100 inclusive.
 */
#define HISTOGRAM_PERCENTAGE(name, sample) \
    (void)OHOS::histogram::GetHistogramPlugin().AddPercentageSample(name, sample)

#endif // HISTOGRAM_PLUGIN_MACROS_H