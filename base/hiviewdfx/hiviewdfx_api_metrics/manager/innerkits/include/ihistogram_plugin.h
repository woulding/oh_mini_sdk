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

#ifndef HISTOGRAM_IHISTOGRAM_PLUGIN_H
#define HISTOGRAM_IHISTOGRAM_PLUGIN_H

#include <cstddef>
#include <cstdint>
#include <string>

namespace OHOS {
namespace histogram {

/**
 * Dynamic Library Path Configuration
 * * Defines the path of the histogram plugin based on the CPU architecture.
 * - 64-bit systems (__aarch64__, __x86_64__) use the /lib64/ directory.
 * - 32-bit systems use the /lib/ directory.
 */
#if (defined(__aarch64__) || defined(__x86_64__))
inline const std::string HISTOGRAM_PLUGIN_SO_PATH = "/system/lib64/platformsdk/libhistogram.z.so";
#else
inline const std::string HISTOGRAM_PLUGIN_SO_PATH = "/system/lib/platformsdk/libhistogram.z.so";
#endif

/**
 * Plugin Entry Symbol
 * * The factory function name used by dlsym() to instantiate the plugin.
 * This must match the 'extern "C"' function exported in the shared object.
 */
inline const std::string CREATE_HISTOGRAM_PLUGIN = "create_histogram_plugin";

/**
 * Plugin Operational Status Codes
 * * HISTOGRAM_PLUGIN_ENABLE:  Standard return code for successful operations.
 * HISTOGRAM_PLUGIN_DISABLE: Return code when the plugin is unavailable or fails to load.
 */
static constexpr int32_t HISTOGRAM_PLUGIN_ENABLE = 0;
static constexpr int32_t HISTOGRAM_PLUGIN_DISABLE = -1;

/**
 * @class IHistogramPlugin
 * @brief Abstract interface for histogram plugins.
 */
class IHistogramPlugin {
public:
    virtual ~IHistogramPlugin() = default;

    /**
     * @brief Records enumerated histogram samples.
     * @param histogram_name Name of the histogram.
     * @param sample Enumerated value.
     * @param max Upper bound of the enum.
     * @return 0 on success, -1 on failure.
     */
    virtual int32_t AddEnumSample(const std::string &histogram_name, int32_t sample, int32_t max) = 0;

    /**
     * @brief Records time-based histogram samples.
     * @param histogram_name Name of the histogram.
     * @param sample Time duration value.
     * @return 0 on success, -1 on failure.
     */
    virtual int32_t AddTimeSample(const std::string &histogram_name, int32_t sample) = 0;

    /**
     * @brief Records linear or exponential count samples.
     * @param histogram_name Name of the histogram.
     * @param sample Measured value.
     * @param min Minimum expected value.
     * @param max Maximum expected value.
     * @param bucket_count Number of histogram buckets.
     * @return 0 on success, -1 on failure.
     */
    virtual int32_t AddCountSample(
        const std::string &histogram_name, int32_t sample, int32_t min, int32_t max, size_t bucket_count) = 0;

    /**
     * @brief Records boolean histogram samples.
     * @param histogram_name Name of the histogram.
     * @param sample Boolean value (0 or 1).
     * @return 0 on success, -1 on failure.
     */
    virtual int32_t AddBooleanSample(const std::string &histogram_name, int32_t sample) = 0;

    /**
     * @brief Records percentage-based histogram samples.
     * @param histogram_name Name of the histogram.
     * @param sample Percentage value (typically 0-100).
     * @return 0 on success, -1 on failure.
     */
    virtual int32_t AddPercentageSample(const std::string &histogram_name, int32_t sample) = 0;
};

}  // namespace histogram
}  // namespace OHOS

#endif  // HISTOGRAM_IHISTOGRAM_PLUGIN_H