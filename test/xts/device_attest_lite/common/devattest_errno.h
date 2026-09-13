/*
 * Copyright (C) 2023 Huawei Device Co., Ltd.
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

#ifndef DEVATTEST_ERRNO_H
#define DEVATTEST_ERRNO_H

#define DEVATTEST_FAIL                              (-1)

#define DEVATTEST_SUCCESS                           0

// 设备认证结果
#define DEVATTEST_RESULT_INIT                       (-2)
#define DEVATTEST_RESULT_FAIL                       (-1)
#define DEVATTEST_RESULT_PASS                       (0)

#define DEVATTEST_ERR_JS_IS_NOT_SYSTEM_APP          202
#define DEVATTEST_ERR_JS_PARAMETER_ERROR            401
#define DEVATTEST_ERR_JS_SYSTEM_SERVICE_EXCEPTION   20000001

#endif // DEVATTEST_ERRNO_H
