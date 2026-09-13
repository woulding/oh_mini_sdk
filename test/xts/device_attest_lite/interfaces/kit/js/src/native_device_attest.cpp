/*
 * Copyright (c) 2023 Huawei Device Co., Ltd.
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
#include <string>
#include <unordered_map>
#include "securec.h"
#include "js_async_work.h"
#include "devattest_errno.h"
#include "devattest_interface.h"
#include "devattest_log.h"
#include "native_device_attest.h"
using namespace std;

namespace OHOS {
namespace ACELite {
static const std::unordered_map<uint32_t, std::string> g_errorStringMap = {
    {DEVATTEST_ERR_JS_IS_NOT_SYSTEM_APP,
        "This api is system api, Please use the system application to call this api"},
    {DEVATTEST_ERR_JS_PARAMETER_ERROR, "Input paramters wrong"},
    {DEVATTEST_ERR_JS_SYSTEM_SERVICE_EXCEPTION, "System service exception, please try again or reboot your device"},
};

string GetErrorMessage(uint32_t errorCode)
{
    auto iter = g_errorStringMap.find(errorCode);
    if (iter != g_errorStringMap.end()) {
        return iter->second;
    } else {
        return "Unknown error, please reboot your device and try again";
    }
}

static JSIValue GetJsiErrorMessage(int32_t errorCode)
{
    JSIValue error = JSI::CreateObject();
    if (error == nullptr) {
        return nullptr;
    }
    if (errorCode == DEVATTEST_FAIL) {
        errorCode = DEVATTEST_ERR_JS_SYSTEM_SERVICE_EXCEPTION;
    }
    JSI::SetStringProperty(error, "message", GetErrorMessage(errorCode).c_str());
    JSI::SetNumberProperty(error, "code", errorCode);
    return error;
}


void FailCallBack(const JSIValue thisVal, const JSIValue args, int32_t ret)
{
    if (JSI::ValueIsUndefined(args)) {
        return;
    }
    JSIValue error = GetJsiErrorMessage(ret);
    JSIValue data = JSI::CreateUndefined();
    JSIValue argv[ARGC_TWO] = {error, data};
    JSI::CallFunction(args, thisVal, argv, ARGC_TWO);
    JSI::ReleaseValueList(error, data, ARGS_END);
}

void SuccessCallBack(const JSIValue thisVal, const JSIValue args, JSIValue jsiValue)
{
    if (JSI::ValueIsUndefined(args)) {
        return;
    }
    JSIValue error = JSI::CreateUndefined();
    JSIValue argv[ARGC_TWO] = {error, jsiValue};
    JSI::CallFunction(args, thisVal, argv, ARGC_TWO);
    JSI::ReleaseValueList(error, ARGS_END);
}

bool IsValidParam(const JSIValue* args, uint8_t argsNum)
{
    if ((argsNum == 1) && !JSI::ValueIsUndefined(args[0])) {
        return true;
    }
    return false;
}

JSIValue ExecuteAsyncWork(const JSIValue thisVal, const JSIValue* args,
    uint8_t argsNum, AsyncWorkHandler ExecuteFunc)
{
    JSIValue undefValue = JSI::CreateUndefined();
    if (args == NULL) {
        return GetJsiErrorMessage(DEVATTEST_ERR_JS_PARAMETER_ERROR);
    }
    if (!IsValidParam(args, argsNum)) {
        FailCallBack(thisVal, *args, DEVATTEST_ERR_JS_PARAMETER_ERROR);
        return undefValue;
    }
    FuncParams* params = new(std::nothrow) FuncParams();
    if (params == nullptr) {
        FailCallBack(thisVal, *args, DEVATTEST_ERR_JS_SYSTEM_SERVICE_EXCEPTION);
        return undefValue;
    }
    params->thisVal = JSI::AcquireValue(thisVal);
    params->args = JSI::AcquireValue(args[0]);
    JsAsyncWork::DispatchAsyncWork(ExecuteFunc, reinterpret_cast<void *>(params));
    return undefValue;
}

int32_t SetJsResult(JSIValue *result, AttestResultInfo *attestResultInfo)
{
    JSI::SetNumberProperty(*result, "authResult", attestResultInfo->authResult);
    JSI::SetNumberProperty(*result, "softwareResult", attestResultInfo->softwareResult);
    
    JSIValue array = JSI::CreateNull();
    size_t size = sizeof(attestResultInfo->softwareResultDetail) / sizeof(int32_t);
    if (size > 0) {
        bool isArray = false;
        array = JSI::CreateArray(size);
        isArray = JSI::ValueIsArray(array);
        if (!isArray) {
            HILOGE("JSI_create_array fail");
            return DEVATTEST_FAIL;
        }
        JSIValue element = JSI::CreateNull();
        for (size_t i = 0; i != size; ++i) {
            element = JSI::CreateNumber(attestResultInfo->softwareResultDetail[i]);
            JSI::SetPropertyByIndex(array, i, element);
            JSI::ReleaseValue(element);
        }
    }
    JSI::SetNamedProperty(*result, "softwareResultDetail", array);

    JSI::SetStringProperty(*result, "ticket", attestResultInfo->ticket);
    return DEVATTEST_SUCCESS;
}

int32_t GetAttestResultInfo(JSIValue *result)
{
    AttestResultInfo attestResultInfo = { 0 };
    attestResultInfo.ticket = NULL;
    int32_t ret = GetAttestStatus(&attestResultInfo);
    if (ret != DEVATTEST_SUCCESS) {
        HILOGE("[GetAttestResultInfo] Failed to GetAttestStatus");
        return ret;
    }

    if (attestResultInfo.ticket == NULL) {
        return ret;
    }
    
    ret = SetJsResult(result, &attestResultInfo);
    free(attestResultInfo.ticket);
    attestResultInfo.ticket = NULL;
    return ret;
}

void ExecuteGetAttestResult(void* data)
{
    FuncParams* params = reinterpret_cast<FuncParams *>(data);
    if (params == nullptr) {
        return;
    }
    JSIValue args = params->args;
    JSIValue thisVal = params->thisVal;
    JSIValue result = JSI::CreateObject();
    int32_t ret = GetAttestResultInfo(&result);
    if (ret != DEVATTEST_SUCCESS) {
        FailCallBack(thisVal, args, ret);
    } else {
        SuccessCallBack(thisVal, args, result);
    }
    JSI::ReleaseValueList(args, thisVal, result, ARGS_END);
    delete params;
    params = nullptr;
    return;
}

JSIValue NativeDeviceAttest::GetAttestResultInfoSync(const JSIValue thisVal, const JSIValue *args, uint8_t argsNum)
{
    HILOGI("[GetAttestResultInfoSync] In.");
    AttestResultInfo attestResultInfo = { 0 };
    attestResultInfo.ticket = NULL;
    
    int32_t ret = GetAttestStatus(&attestResultInfo);
    if (ret != DEVATTEST_SUCCESS) {
        HILOGE("[GetAttestResultInfoSync] Failed to GetAttestStatus");
        return GetJsiErrorMessage(ret);
    }

    if (attestResultInfo.ticket == NULL) {
        return GetJsiErrorMessage(DEVATTEST_ERR_JS_SYSTEM_SERVICE_EXCEPTION);
    }

    JSIValue result = JSI::CreateObject();
    ret = SetJsResult(&result, &attestResultInfo);
    if (ret != DEVATTEST_SUCCESS) {
        JSI::ReleaseValueList(result, ARGS_END);
        return GetJsiErrorMessage(DEVATTEST_ERR_JS_SYSTEM_SERVICE_EXCEPTION);
    }

    free(attestResultInfo.ticket);
    attestResultInfo.ticket = NULL;

    return result;
}

JSIValue NativeDeviceAttest::GetAttestResultInfoAsync(const JSIValue thisVal, const JSIValue *args, uint8_t argsNum)
{
    HILOGI("[GetAttestResultInfoAsync] In.");
    return ExecuteAsyncWork(thisVal, args, argsNum, ExecuteGetAttestResult);
}

     
void InitDeviceAttestModule(JSIValue exports)
{
    JSI::SetModuleAPI(exports, "getAttestStatus", NativeDeviceAttest::GetAttestResultInfoAsync);
    JSI::SetModuleAPI(exports, "getAttestStatusSync", NativeDeviceAttest::GetAttestResultInfoSync);
}
} // namespace ACELite
} // namespace OHOS