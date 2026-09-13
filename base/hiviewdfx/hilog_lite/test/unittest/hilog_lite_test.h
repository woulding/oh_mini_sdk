/*
 * Copyright (C) 2022 Huawei Device Co., Ltd.
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

#ifndef HILOG_LITE_TEST_H
#define HILOG_LITE_TEST_H
#define private public

#include <cstdint>
#include <cstring>

#include "gtest/gtest.h"
#include "hilog_module.h"
#include "jsi/jsi.h"
#include "hilog_realloc.h"
#include "hilog_string.h"
#include "hilog_vector.h"
#include "hilog_wrapper.h"

namespace OHOS {
namespace ACELite {
class HilogLiteTest : public testing::Test {
public:
    // SetUpTestCase: before all testcasee
    static void SetUpTestCase(void);
    // TearDownTestCase: after all testcase
    static void TearDownTestCase(void);
    // SetUp
    void SetUp(void);
    // TearDown
    void TearDown(void);
};
} // namespace ACELite
} // namespace OHOS
#endif // HILOG_LITE_TEST_H