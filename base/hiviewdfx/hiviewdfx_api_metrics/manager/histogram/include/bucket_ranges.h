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

#ifndef BUCKET_RANGES_H
#define BUCKET_RANGES_H

#include <cstdint>
#include <vector>
#include <memory>

namespace OHOS::histogram {

class BucketRanges {
public:
    explicit BucketRanges(size_t num_ranges);
    ~BucketRanges();

    void InitializeLinearBuckets(int32_t minimum, int32_t maximum, size_t bucket_count);
    void InitializeExponentialBuckets(int32_t minimum, int32_t maximum, size_t bucket_count);
    int GetBucketIndex(int32_t value) const;

private:
    std::vector<int32_t> ranges_;
};

}  // namespace OHOS::histogram

#endif  // BUCKET_RANGES_H
