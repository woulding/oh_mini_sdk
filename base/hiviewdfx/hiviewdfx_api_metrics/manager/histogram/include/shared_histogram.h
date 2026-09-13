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

#ifndef SHARED_HISTOGRAM_H
#define SHARED_HISTOGRAM_H

#include "histogram_base.h"
#include <vector>
#include <atomic>

namespace OHOS::histogram {

class Histogram : public HistogramBase {
public:
    Histogram(); // 必须声明无参构造
    Histogram(const std::string &name, int32_t minimum, int32_t maximum, size_t bucket_count);
    virtual ~Histogram() = default;

    void Initialize() override;
    void Add(int32_t value) override;
    int64_t TotalCount() const override;
    int64_t Sum() const override;

protected:
    void WriteToBucket(int32_t value);
    std::vector<int64_t> counts_;
    std::atomic<int64_t> total_count_{0};
    std::atomic<int64_t> sum_{0};
};

class LinearHistogram : public Histogram {
public:
    LinearHistogram();
    LinearHistogram(const std::string &name, int32_t minimum, int32_t maximum, size_t bucket_count);
    void Initialize() override;
};

// 确保以下类全部被声明
class BooleanHistogram : public LinearHistogram {
public:
    BooleanHistogram();
    BooleanHistogram(const std::string &name, int32_t minimum, int32_t maximum, size_t bucket_count);
};

class EnumHistogram : public LinearHistogram {
public:
    EnumHistogram();
    EnumHistogram(const std::string &name, int32_t minimum, int32_t maximum, size_t bucket_count);
};

class CountHistogram : public Histogram {
public:
    CountHistogram();
    CountHistogram(const std::string &name, int32_t minimum, int32_t maximum, size_t bucket_count);
};

class TimeHistogram : public Histogram {
public:
    TimeHistogram();
    TimeHistogram(const std::string &name, int32_t minimum, int32_t maximum, size_t bucket_count);
};

class PercentageHistogram : public LinearHistogram {
public:
    PercentageHistogram();
    PercentageHistogram(const std::string &name, int32_t minimum, int32_t maximum, size_t bucket_count);
};

}  // namespace OHOS::histogram
#endif