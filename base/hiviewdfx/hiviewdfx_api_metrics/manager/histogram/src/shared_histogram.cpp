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

#include "shared_histogram.h"

#include <algorithm>
#include <cmath>
#include "bucket_ranges.h"

namespace OHOS::histogram {

// --- Histogram Implementation ---

Histogram::Histogram() : HistogramBase("", 0, 0, 0) {}

Histogram::Histogram(const std::string &name, int32_t minimum, int32_t maximum, size_t bucket_count)
    : HistogramBase(name, minimum, maximum, bucket_count)
{
    Histogram::Initialize();
}

void Histogram::Initialize()
{
    bucket_ranges_ = std::make_unique<BucketRanges>(bucket_count_ + 1);
    bucket_ranges_->InitializeExponentialBuckets(minimum_, maximum_, bucket_count_);
    counts_.assign(bucket_count_ + 1, 0);
}

void Histogram::Add(int32_t value)
{
    WriteToBucket(value);
}

void Histogram::WriteToBucket(int32_t value)
{
    if (!bucket_ranges_) {
        return;
    }
    
    int bucket_index = bucket_ranges_->GetBucketIndex(value);
    if (bucket_index < 0 || bucket_index >= static_cast<int>(counts_.size())) {
        return;
    }
    
    counts_[bucket_index]++;
    total_count_.fetch_add(1);
    sum_.fetch_add(value);
}

int64_t Histogram::TotalCount() const
{
    return total_count_.load();
}

int64_t Histogram::Sum() const
{
    return sum_.load();
}

// --- LinearHistogram Implementation ---

LinearHistogram::LinearHistogram() : Histogram("", 0, 0, 0) {}

LinearHistogram::LinearHistogram(const std::string &name, int32_t minimum, int32_t maximum, size_t bucket_count)
    : Histogram(name, minimum, maximum, bucket_count)
{
    LinearHistogram::Initialize();
}

void LinearHistogram::Initialize()
{
    bucket_ranges_ = std::make_unique<BucketRanges>(bucket_count_ + 1);
    bucket_ranges_->InitializeLinearBuckets(minimum_, maximum_, bucket_count_);
    counts_.assign(bucket_count_ + 1, 0);
}

// --- Specialized Histograms ---

BooleanHistogram::BooleanHistogram() : LinearHistogram("", 0, 0, 0) {}

BooleanHistogram::BooleanHistogram(const std::string &name, int32_t minimum, int32_t maximum, size_t bucket_count)
    : LinearHistogram(name, minimum, maximum, bucket_count + 1) {}

EnumHistogram::EnumHistogram() : LinearHistogram("", 0, 0, 0) {}

EnumHistogram::EnumHistogram(const std::string &name, int32_t minimum, int32_t maximum, size_t bucket_count)
    : LinearHistogram(name, minimum, maximum, bucket_count + 1) {}

CountHistogram::CountHistogram() : Histogram("", 0, 0, 0) {}

CountHistogram::CountHistogram(const std::string &name, int32_t minimum, int32_t maximum, size_t bucket_count)
    : Histogram(name, minimum, maximum, bucket_count + 1) {}

TimeHistogram::TimeHistogram() : Histogram("", 0, 0, 0) {}

TimeHistogram::TimeHistogram(const std::string &name, int32_t minimum, int32_t maximum, size_t bucket_count)
    : Histogram(name, minimum, maximum, bucket_count + 1) {}

PercentageHistogram::PercentageHistogram() : LinearHistogram("", 0, 0, 0) {}

PercentageHistogram::PercentageHistogram(const std::string &name, int32_t minimum, int32_t maximum, size_t bucket_count)
    : LinearHistogram(name, minimum, maximum, bucket_count + 1) {}

} // namespace OHOS::histogram