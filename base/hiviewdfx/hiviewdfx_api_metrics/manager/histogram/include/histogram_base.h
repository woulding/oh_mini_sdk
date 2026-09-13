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

#ifndef HISTOGRAM_BASE_H
#define HISTOGRAM_BASE_H

#include <string>
#include <memory>
#include <cstdint>

namespace OHOS::histogram {

class BucketRanges;

class HistogramBase {
public:
    // 仅声明构造函数
    HistogramBase(const std::string &name, int32_t minimum, int32_t maximum, size_t bucket_count);
    virtual ~HistogramBase(); // 必须显式声明析构函数

    virtual void Initialize() = 0;
    virtual void Add(int32_t value) = 0;
    virtual int64_t TotalCount() const = 0;
    virtual int64_t Sum() const = 0;
    const std::string& GetName() const { return name_; }

protected:
    std::string name_;
    int32_t minimum_ = 0;
    int32_t maximum_ = 0;
    size_t bucket_count_ = 0;
    std::unique_ptr<BucketRanges> bucket_ranges_;
};

}  // namespace OHOS::histogram
#endif