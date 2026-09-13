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

#ifndef HISTOGRAM_PLUGIN_INTERFACE_H
#define HISTOGRAM_PLUGIN_INTERFACE_H

#include "ihistogram_plugin.h"
#include "plugin_manager.h"
#include "log_wrapper.h"

#include <cstdint>
#include <string>

namespace OHOS {
namespace histogram {

/**
 * @brief High-performance histogram api metrics interface.
 *
 * This class provides a stable API layer for business modules to report
 * histogram metrics without directly depending on plugin implementation
 * details.
 *
 * Design goals:
 * - Lazy plugin loading
 * - Low-overhead hot path
 * - Unified validation entry
 * - Stable SDK-facing interface
 *
 * Typical usage:
 * @code
 * PluginInterface api;
 * api.AddBooleanSample("login.success", 1);
 * api.AddTimeSample("page.load.ms", 135);
 * @endcode
 *
 */
class PluginInterface {
public:
    /**
     * @brief Construct a PluginInterface object.
     */
    PluginInterface() = default;

    /**
     * @brief Destroy the PluginInterface object.
     */
    ~PluginInterface() = default;

    /**
     * @brief Record a boolean histogram sample.
     *
     * Valid sample values:
     * - 0 = false / failed / disabled
     * - 1 = true / success / enabled
     *
     * Typical scenarios:
     * - API success rate
     * - Permission granted
     * - Feature switch state
     *
     * @param name Histogram metric name.
     * @param sample Boolean sample, must be 0 or 1.
     * @return 0 on success, negative value on failure.
     */
    int32_t AddBooleanSample(const std::string &name, int32_t sample);

    /**
     * @brief Record an enumeration histogram sample.
     *
     * Valid input:
     * - boundary > 0
     * - sample in range [0, boundary]
     *
     * Typical scenarios:
     * - Error type enum
     * - User mode selection
     * - State machine result
     *
     * @param name Histogram metric name.
     * @param sample Enum sample value.
     * @param boundary Maximum enum value (inclusive).
     * @return 0 on success, negative value on failure.
     */
    int32_t AddEnumSample(const std::string &name, int32_t sample, int32_t boundary);

    /**
     * @brief Record a custom count histogram sample.
     *
     * Valid input:
     * - sample in [0, INT32_MAX)
     * - min >= 0
     * - max < INT32_MAX
     * - min < max
     * - bucketCount >= 2
     * - bucketCount < 100
     *
     * Typical scenarios:
     * - Retry count
     * - Queue depth
     * - Object quantity
     * - Cache size distribution
     *
     * @param name Histogram metric name.
     * @param sample Value to record.
     * @param min Minimum configured range.
     * @param max Maximum configured range.
     * @param bucketCount Number of buckets (<100).
     * @return 0 on success, negative value on failure.
     */
    int32_t AddCountSample(
        const std::string &name,
        int32_t sample,
        int32_t min,
        int32_t max,
        size_t bucketCount);

    /**
     * @brief Record a time histogram sample.
     *
     * Recommended unit:
     * - milliseconds (ms)
     *
     * Typical scenarios:
     * - API latency
     * - Page render cost
     * - Startup duration
     * - IPC response time
     *
     * @param name Histogram metric name.
     * @param sample Time value, usually milliseconds.
     * @return 0 on success, negative value on failure.
     */
    int32_t AddTimeSample(const std::string &name, int32_t sample);

    /**
     * @brief Record a percentage histogram sample.
     *
     * Valid input:
     * - sample in [0, 100]
     *
     * Typical scenarios:
     * - CPU usage
     * - Success percentage
     * - Progress value
     * - Cache hit ratio
     *
     * @param name Histogram metric name.
     * @param sample Percentage value from 0 to 100.
     * @return 0 on success, negative value on failure.
     */
    int32_t AddPercentageSample(const std::string &name, int32_t sample);
};

} // namespace histogram
} // namespace OHOS

#endif // HISTOGRAM_PLUGIN_INTERFACE_H