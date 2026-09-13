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


#include "napi/native_api.h"
#include "napi/native_node_api.h"
#include "log_wrapper.h"
#include "histogram_plugin_macros.h"

namespace OHOS::histogramNapi {

// ----------------------------- 常量定义 -----------------------------
namespace {
    // 参数限制
    constexpr size_t ARGC_SINGLE = 1;
    constexpr size_t ARGC_ENUMERATION = 2;
    constexpr size_t ARGC_CUSTOM_COUNTS = 4;

    // 参数索引定义
    enum ArgIndex : size_t {
        INDEX_0 = 0,
        INDEX_1 = 1,
        INDEX_2 = 2,
        INDEX_3 = 3
    };

    // 默认模块版本
    constexpr int32_t NAPI_MODULE_VERSION = 1;
}

// ----------------------------- 工具函数 -----------------------------
static bool GetInt32Arg(napi_env env, napi_value value, int32_t &out)
{
    napi_status status = napi_get_value_int32(env, value, &out);
    if (status != napi_ok) {
        AP_ERROR_LOG("Failed to parse int32 argument");
        return false;
    }
    return true;
}

static napi_value CreateInt32Result(napi_env env, int32_t value)
{
    napi_value result = nullptr;
    napi_create_int32(env, value, &result);
    return result;
}

static napi_value CreateUndefined(napi_env env)
{
    napi_value result = nullptr;
    napi_get_undefined(env, &result);
    return result;
}

// ----------------------------- 1. BOOLEAN -----------------------------
// JS: histogram.AddBoolean(sample)
static napi_value AddBoolean(napi_env env, napi_callback_info info)
{
    size_t argc = ARGC_SINGLE;
    napi_value args[ARGC_SINGLE] = {nullptr};
    napi_get_cb_info(env, info, &argc, args, nullptr, nullptr);

    if (argc < ARGC_SINGLE) {
        AP_ERROR_LOG("AddBoolean requires %{public}zu argument: sample", ARGC_SINGLE);
        return CreateUndefined(env);
    }

    int32_t sample = 0;
    if (!GetInt32Arg(env, args[ArgIndex::INDEX_0], sample)) {
        return CreateUndefined(env);
    }

    AP_INFO_LOG("NAPI AddBoolean called, sample=%{public}d", sample);

    HISTOGRAM_BOOLEAN("accountkit.createAcount.is_success", sample);

    return CreateInt32Result(env, sample);
}

// ----------------------------- 2. ENUMERATION -----------------------------
// JS: histogram.AddEnumeration(sample, boundary)
static napi_value AddEnumeration(napi_env env, napi_callback_info info)
{
    size_t argc = ARGC_ENUMERATION;
    napi_value args[ARGC_ENUMERATION] = {nullptr, nullptr};
    napi_get_cb_info(env, info, &argc, args, nullptr, nullptr);

    if (argc < ARGC_ENUMERATION) {
        AP_ERROR_LOG("AddEnumeration requires %{public}zu arguments: sample, boundary", ARGC_ENUMERATION);
        return CreateUndefined(env);
    }

    int32_t sample = 0;
    int32_t boundary = 0;
    if (!GetInt32Arg(env, args[ArgIndex::INDEX_0], sample) ||
        !GetInt32Arg(env, args[ArgIndex::INDEX_1], boundary)) {
        return CreateUndefined(env);
    }

    AP_INFO_LOG("NAPI AddEnumeration called, sample=%{public}d, boundary=%{public}d", sample, boundary);

    HISTOGRAM_ENUMERATION("accountkit.createAcount.error_code", sample, boundary);

    return CreateInt32Result(env, sample);
}

// ----------------------------- 3. CUSTOM COUNTS -----------------------------
// JS: histogram.AddCustomCounts(sample, min, max, bucketCount)
static napi_value AddCustomCounts(napi_env env, napi_callback_info info)
{
    size_t argc = ARGC_CUSTOM_COUNTS;
    napi_value args[ARGC_CUSTOM_COUNTS] = {nullptr};
    napi_get_cb_info(env, info, &argc, args, nullptr, nullptr);

    if (argc < ARGC_CUSTOM_COUNTS) {
        return CreateUndefined(env);
    }

    int32_t sample = 0;
    int32_t min = 0;
    int32_t max = 0;
    int32_t bucketCount = 0;
    if (!GetInt32Arg(env, args[ArgIndex::INDEX_0], sample) ||
        !GetInt32Arg(env, args[ArgIndex::INDEX_1], min) ||
        !GetInt32Arg(env, args[ArgIndex::INDEX_2], max) ||
        !GetInt32Arg(env, args[ArgIndex::INDEX_3], bucketCount)) {
        return CreateUndefined(env);
    }

    AP_INFO_LOG("NAPI AddCustomCounts called, "
        "sample=%{public}d, min=%{public}d, max=%{public}d, bucketCount=%{public}d",
        sample, min, max, bucketCount);

    HISTOGRAM_CUSTOM_COUNTS("accountkit.createAcount.call_count", sample, min, max, bucketCount);

    return CreateInt32Result(env, sample);
}

// ----------------------------- 4. TIMES -----------------------------
// JS: histogram.AddTimes(sample)
static napi_value AddTimes(napi_env env, napi_callback_info info)
{
    size_t argc = ARGC_SINGLE;
    napi_value args[ARGC_SINGLE] = {nullptr};
    napi_get_cb_info(env, info, &argc, args, nullptr, nullptr);

    if (argc < ARGC_SINGLE) {
        AP_ERROR_LOG("AddTimes requires %{public}zu argument: sample", ARGC_SINGLE);
        return CreateUndefined(env);
    }

    int32_t sample = 0;
    if (!GetInt32Arg(env, args[ArgIndex::INDEX_0], sample)) {
        return CreateUndefined(env);
    }

    AP_INFO_LOG("NAPI AddTimes called, sample=%{public}d", sample);

    HISTOGRAM_TIMES("accountkit.createAcount.time", sample);

    return CreateInt32Result(env, sample);
}

// ----------------------------- 5. PERCENTAGE -----------------------------
// JS: histogram.AddPercentage(sample)
static napi_value AddPercentage(napi_env env, napi_callback_info info)
{
    size_t argc = ARGC_SINGLE;
    napi_value args[ARGC_SINGLE] = {nullptr};
    napi_get_cb_info(env, info, &argc, args, nullptr, nullptr);

    if (argc < ARGC_SINGLE) {
        AP_ERROR_LOG("AddPercentage requires %{public}zu argument: sample", ARGC_SINGLE);
        return CreateUndefined(env);
    }

    int32_t sample = 0;
    if (!GetInt32Arg(env, args[ArgIndex::INDEX_0], sample)) {
        return CreateUndefined(env);
    }

    AP_INFO_LOG("NAPI AddPercentage called, sample=%{public}d", sample);

    HISTOGRAM_PERCENTAGE("accountkit.createAcount.success_percentage", sample);

    return CreateInt32Result(env, sample);
}

// ----------------------------- 模块注册 -----------------------------
EXTERN_C_START
static napi_value NapiInit(napi_env env, napi_value exports)
{
    AP_INFO_LOG("Histogram NAPI module init");

    napi_property_descriptor descriptors[] = {
        DECLARE_NAPI_FUNCTION("AddBoolean", AddBoolean),
        DECLARE_NAPI_FUNCTION("AddEnumeration", AddEnumeration),
        DECLARE_NAPI_FUNCTION("AddCustomCounts", AddCustomCounts),
        DECLARE_NAPI_FUNCTION("AddTimes", AddTimes),
        DECLARE_NAPI_FUNCTION("AddPercentage", AddPercentage),
    };

    size_t propertyCount = sizeof(descriptors) / sizeof(descriptors[0]);

    NAPI_CALL(env, napi_define_properties(
        env,
        exports,
        propertyCount,
        descriptors));

    return exports;
}
EXTERN_C_END

static napi_module _module = {
    .nm_version = NAPI_MODULE_VERSION,
    .nm_flags = 0,
    .nm_filename = nullptr,
    .nm_register_func = NapiInit,
    .nm_modname = "histogram",
    .nm_priv = nullptr,
    .reserved = {0}
};

extern "C" __attribute__((constructor)) void RegisterModule(void)
{
    napi_module_register(&_module);
}

}  // namespace OHOS::histogramNapi