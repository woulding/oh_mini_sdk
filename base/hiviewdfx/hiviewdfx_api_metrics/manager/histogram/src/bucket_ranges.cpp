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

#include "bucket_ranges.h"

#include <algorithm>
#include <cmath>
#include <climits>

namespace OHOS::histogram {
namespace {

constexpr size_t MIN_LINEAR_BUCKET_COUNT = 2;
constexpr size_t MIN_EXP_BUCKET_COUNT = 3;

constexpr size_t EXTRA_BUCKET = 1;

constexpr size_t FIRST_BUCKET_INDEX = 1;
constexpr size_t SECOND_BUCKET_INDEX = 2;

}  // namespace

BucketRanges::BucketRanges(size_t num_ranges) : ranges_(num_ranges)
{}

BucketRanges::~BucketRanges() = default;

/**
 * Linear Buckets:
 * ranges_[0] = 0 (underflow)
 * ranges_[1 ... bucket_count-2] = linear buckets
 * ranges_[bucket_count-1] = max
 * ranges_[bucket_count] = INT_MAX (overflow)
 */
void BucketRanges::InitializeLinearBuckets(int32_t minimum, int32_t maximum, size_t bucket_count)
{
    if (bucket_count < MIN_LINEAR_BUCKET_COUNT ||
        ranges_.size() < bucket_count + EXTRA_BUCKET) {
        return;
    }

    size_t divisor = bucket_count - MIN_LINEAR_BUCKET_COUNT;

    double bucket_width = (divisor == 0)
        ? 0
        : static_cast<double>(maximum - minimum) / divisor;
    ranges_[0] = 0;

    for (size_t i = 1; i < bucket_count - 1; i++) {
        ranges_[i] = minimum + static_cast<int32_t>(bucket_width * (i - 1));
    }

    ranges_[bucket_count - 1] = maximum;
    ranges_[bucket_count] = INT_MAX;
}

void BucketRanges::InitializeExponentialBuckets(int32_t minimum, int32_t maximum, size_t bucket_count)
{
    if (bucket_count < MIN_EXP_BUCKET_COUNT ||
        minimum <= 0 ||
        maximum <= minimum ||
        ranges_.size() < bucket_count + EXTRA_BUCKET) {
        return;
    }

    ranges_[0] = 0;
    ranges_[FIRST_BUCKET_INDEX] = minimum;

    double log_max = std::log(static_cast<double>(maximum));
    int32_t current = minimum;

    for (size_t bucket_index = SECOND_BUCKET_INDEX;
         bucket_index < bucket_count;
         ++bucket_index) {
        double log_current = std::log(static_cast<double>(current));
        size_t remaining_buckets = bucket_count - bucket_index;

        double log_ratio = (log_max - log_current) /
            static_cast<double>(remaining_buckets);
        double log_next = log_current + log_ratio;
        int32_t next =
            static_cast<int32_t>(std::round(std::exp(log_next)));
        current = (next > current) ? next : (current + 1);
        if (current > maximum) {
            current = maximum;
        }
        ranges_[bucket_index] = current;
    }
    ranges_[bucket_count - 1] = maximum;
    ranges_[bucket_count] = INT_MAX;
}

int BucketRanges::GetBucketIndex(int32_t value) const
{
    if (ranges_.empty()) {
        return -1;
    }
    auto it = std::upper_bound(ranges_.begin(), ranges_.end(), value);
    int32_t index =
        static_cast<int32_t>(std::distance(ranges_.begin(), it)) - 1;
    if (index < 0 ||
        index >= static_cast<int32_t>(ranges_.size() - 1)) {
        return -1;
    }
    return index;
}

}  // namespace OHOS::histogram