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

#include "jsi_api.h"
#include "jsi_api_common.h"
#include "jsi_api_errcode.h"
#include "jsi_utils.h"
#include "jsi_list.h"
#include "securec.h"
#include "jsi.h"
#include "jsi_types.h"
#include "log.h"

namespace OHOS {
namespace ACELite {

JSIValue CryptoFrameworkLiteModule::CreateRandom(const JSIValue thisVal, const JSIValue *args, uint8_t argsNum)
{
    (void)argsNum;
    (void)thisVal;
    (void)args;
    HcfRand *randObj = nullptr;
    HcfResult res = HcfRandCreate(&randObj);
    if (res != HCF_SUCCESS) {
        LOGE("CreateRandom is randObj err %d!", res);
        return ThrowErrorCodeResult(res);
    }

    res = ListAddObjNode(JSI_ALG_RAND, (uint32_t)randObj);
    if (res != HCF_SUCCESS) {
        LOGE("rand add node is %d err!", res);
        HcfObjDestroy(static_cast<void *>(randObj));
        return ThrowErrorCodeResult(res);
    }

    JSIValue serviceObj = JSI::CreateObject();
    JSIValue generateRandom = JSI::CreateFunction(GenerateRandom);
    JSIValue generateRandomSync = JSI::CreateFunction(GenerateRandomSync);
    JSIValue setSeed = JSI::CreateFunction(SetSeed);
    JSIValue enableHardwareEntropy = JSI::CreateFunction(EnableHardwareEntropy);

    JSI::SetNamedProperty(serviceObj, "generateRandom", generateRandom);
    JSI::SetNamedProperty(serviceObj, "generateRandomSync", generateRandomSync);
    JSI::SetNamedProperty(serviceObj, "setSeed", setSeed);
    JSI::SetNamedProperty(serviceObj, "enableHardwareEntropy", enableHardwareEntropy);
    JSI::SetNumberProperty(serviceObj, "randObj", (double)(uint32_t)randObj);
    JSI::ReleaseValueList(generateRandom, generateRandomSync, setSeed, enableHardwareEntropy, ARGS_END);

    return serviceObj;
}

JSIValue CryptoFrameworkLiteModule::GenerateRandom(const JSIValue thisVal, const JSIValue *args, uint8_t argsNum)
{
    if ((args == nullptr) || (argsNum != ARRAY_MAX_SIZE) || (args[ARRAY_INDEX_ONE] == nullptr)) {
        LOGE("GenerateRandom params is err!");
        return JSI::CreateUndefined();
    }

    HcfRand *randObj = reinterpret_cast<HcfRand *>((uint32_t)JSI::GetNumberProperty(thisVal, "randObj"));
    if (randObj == nullptr) {
        LOGE("GenerateRandom randObj is null!");
        CallbackErrorCodeOrDataResult(thisVal, args[ARRAY_INDEX_ONE], HCF_INVALID_PARAMS, JSI::CreateUndefined());
        return JSI::CreateUndefined();
    }

    int32_t numBytes = (int32_t)JSI::ValueToNumber(args[0]);
    if (numBytes <= 0) {
        LOGE("GenerateRandom numBytes too small!");
        CallbackErrorCodeOrDataResult(thisVal, args[ARRAY_INDEX_ONE], HCF_INVALID_PARAMS, JSI::CreateUndefined());
        return JSI::CreateUndefined();
    }
    HcfBlob randBlob = { .data = nullptr, .len = 0 };
    HcfResult res = randObj->generateRandom(randObj, numBytes, &randBlob);
    if (res != HCF_SUCCESS) {
        LOGE("GenerateRandom randObj not is success!");
        CallbackErrorCodeOrDataResult(thisVal, args[ARRAY_INDEX_ONE], res, JSI::CreateUndefined());
        return JSI::CreateUndefined();
    }

    JSIValue outVlaue = ConstructJSIReturnResult(&randBlob);
    CallbackErrorCodeOrDataResult(thisVal, args[ARRAY_INDEX_ONE], res, outVlaue);
    HcfBlobDataClearAndFree(&randBlob);

    return JSI::CreateUndefined();
}

JSIValue CryptoFrameworkLiteModule::GenerateRandomSync(const JSIValue thisVal, const JSIValue *args, uint8_t argsNum)
{
    if ((args == nullptr) || (argsNum != ARRAY_INDEX_ONE)) {
        LOGE("GenerateRandomSync params is err");
        return ThrowErrorCodeResult(HCF_INVALID_PARAMS);
    }

    HcfRand *randObj = reinterpret_cast<HcfRand *>((uint32_t)JSI::GetNumberProperty(thisVal, "randObj"));
    if (randObj == nullptr) {
        LOGE("GenerateRandom randObj is null!!");
        return ThrowErrorCodeResult(HCF_INVALID_PARAMS);
    }

    int32_t numBytes = (int32_t)JSI::ValueToNumber(args[0]);
    if (numBytes <= 0) {
        LOGE("GenerateRandomSync numBytes too small!");
        return ThrowErrorCodeResult(HCF_INVALID_PARAMS);
    }
    HcfBlob randBlob = { .data = nullptr, .len = 0 };
    HcfResult res = randObj->generateRandom(randObj, numBytes, &randBlob);
    if (res != HCF_SUCCESS) {
        LOGE("GenerateRandomSync randObj not is success!");
        HcfBlobDataClearAndFree(&randBlob);
        return ThrowErrorCodeResult(res);
    }
    JSIValue randomSyncData = ConstructJSIReturnResult(&randBlob);
    HcfBlobDataClearAndFree(&randBlob);

    return randomSyncData;
}

JSIValue CryptoFrameworkLiteModule::SetSeed(const JSIValue thisVal, const JSIValue *args, uint8_t argsNum)
{
    HcfRand *randObj = reinterpret_cast<HcfRand *>((uint32_t)JSI::GetNumberProperty(thisVal, "randObj"));
    if (randObj == nullptr) {
        LOGE("SetSeed randObj is null!!");
        return ThrowErrorCodeResult(HCF_INVALID_PARAMS);
    }
    if ((args == nullptr) || (argsNum != ARRAY_INDEX_ONE)) {
        LOGE("SetSeed params is null");
        return ThrowErrorCodeResult(HCF_INVALID_PARAMS);
    }
    JSIValue inVlaue = JSI::GetNamedProperty(args[ARRAY_INDEX_ZERO], "data");
    HcfBlob seedBlob = { .data = nullptr, .len = 0 };
    HcfResult errCode = ParseUint8ArrayToBlob(inVlaue, &seedBlob);
    if (errCode != HCF_SUCCESS) {
        LOGE("SetSeed seedBlob is null!");
        return ThrowErrorCodeResult(HCF_ERR_MALLOC);
    }

    HcfResult res = randObj->setSeed(randObj, &seedBlob);
    HcfBlobDataClearAndFree(&seedBlob);
    if (res != HCF_SUCCESS) {
        LOGE("setSeed randObj not is success!");
        return ThrowErrorCodeResult(res);
    }

    return ThrowErrorCodeResult(HCF_SUCCESS);
}

JSIValue CryptoFrameworkLiteModule::EnableHardwareEntropy(const JSIValue thisVal, const JSIValue *args, uint8_t argsNum)
{
    (void)argsNum;
    (void)thisVal;
    (void)args;
    return ThrowErrorCodeResult(HCF_NOT_SUPPORT);
}

void CryptoFrameworkLiteModule::RandomDestroy(void)
{
    ListDestroy(JSI_ALG_RAND);
}

}  // namespace ACELite
}  // namespace OHOS
