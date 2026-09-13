/*
 * Copyright (C) 2024 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include "jsi_api_errcode.h"
#include "jsi_api_common.h"

namespace OHOS {
namespace ACELite {

constexpr uint32_t JSI_ERR_CODE_DEFAULT_ERR = 0;
constexpr uint32_t JSI_ERR_CODE_OUT_OF_MEMORY = 17620001;
constexpr uint32_t JSI_ERR_CODE_RUNTIME_ERROR = 17620002;
constexpr uint32_t JSI_ERR_CODE_CRYPTO_OPERATION = 17630001;

typedef struct {
    uint32_t errorCode;
    const char *errorMsg;
} JsiErrMsg;

static JsiErrMsg g_errMsg[] = {
    { JSI_ERR_CODE_PARAM_CHECK_FAILED, "Parameter error. Possible causes: 1. Mandatory parameters are left unspecified;\
                                        2. Incorrect parameter types; 3. Parameter verification failed." },
    { JSI_ERR_CODE_NOT_SUPPORTED, "Capability not supported. Failed to call the API due to limited device\
                                    capabilities." },
    { JSI_ERR_CODE_OUT_OF_MEMORY, "memory error." },
    { JSI_ERR_CODE_RUNTIME_ERROR, "runtime error." },
    { JSI_ERR_CODE_CRYPTO_OPERATION, "crypto operation error." },
};

static uint32_t GetJsiErrValueByErrCode(HcfResult errCode)
{
    switch (errCode) {
        case HCF_INVALID_PARAMS:
            return JSI_ERR_CODE_PARAM_CHECK_FAILED;
        case HCF_NOT_SUPPORT:
            return JSI_ERR_CODE_NOT_SUPPORTED;
        case HCF_ERR_MALLOC:
            return JSI_ERR_CODE_OUT_OF_MEMORY;
        case HCF_ERR_NAPI:
            return JSI_ERR_CODE_RUNTIME_ERROR;
        case HCF_ERR_CRYPTO_OPERATION:
            return JSI_ERR_CODE_CRYPTO_OPERATION;
        default:
            return JSI_ERR_CODE_DEFAULT_ERR;
    }
}

JSIValue ThrowErrorCodeResult(int32_t errCode)
{
    for (uint32_t index = 0; index < sizeof(g_errMsg) / sizeof(g_errMsg[0]); index++) {
        if (g_errMsg[index].errorCode == GetJsiErrValueByErrCode((HcfResult)errCode)) {
            return JSI::CreateErrorWithCode(g_errMsg[index].errorCode, g_errMsg[index].errorMsg);
        }
    }

    return JSI::CreateUndefined();
}

void CallbackErrorCodeOrDataResult(const JSIValue thisVal, const JSIValue args, int32_t errCode, const JSIValue data)
{
    for (uint32_t index = 0; index < sizeof(g_errMsg) /sizeof(g_errMsg[0]); index++) {
        if (g_errMsg[index].errorCode == GetJsiErrValueByErrCode((HcfResult)errCode)) {
            JSIValue errObj = JSI::CreateObject();
            JSI::SetNumberProperty(errObj, "code", g_errMsg[index].errorCode);
            JSI::SetStringProperty(errObj, "message", g_errMsg[index].errorMsg);
            JSIValue params[ARRAY_MAX_SIZE] = { errObj, data };
            JsiAsyncCallback(thisVal, args, params, ARRAY_MAX_SIZE);
            return;
        }
    }
    JSIValue params[ARRAY_MAX_SIZE] = { JSI::CreateUndefined(), data };
    JsiAsyncCallback(thisVal, args, params, ARRAY_MAX_SIZE);
}

} // ACELite
} // OHOS
