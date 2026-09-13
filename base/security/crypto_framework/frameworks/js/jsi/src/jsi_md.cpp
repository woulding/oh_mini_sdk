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
#include "log.h"

namespace OHOS {
namespace ACELite {

JSIValue CryptoFrameworkLiteModule::CreateMd(const JSIValue thisVal, const JSIValue *args, uint8_t argsNum)
{
    (void)thisVal;
    if ((args == nullptr) || (argsNum != ARRAY_INDEX_ONE)) {
        LOGE("CreateMd args is err!");
        return ThrowErrorCodeResult(HCF_INVALID_PARAMS);
    }
    char *alg = JSI::ValueToString(args[0]);
    if (alg == nullptr) {
        LOGE("Update alg is null!");
        return ThrowErrorCodeResult(HCF_INVALID_PARAMS);
    }

    HcfMd *mdObj = nullptr;
    HcfResult res = HcfMdCreate(reinterpret_cast<const char *>(alg), &mdObj);
    if (res != HCF_SUCCESS) {
        LOGE("CreateMd is mdObj err res %d!", res);
        JSI::ReleaseString(alg);
        return ThrowErrorCodeResult(res);
    }
    res = ListAddObjNode(JSI_ALG_MD, (uint32_t)mdObj);
    if (res != HCF_SUCCESS) {
        LOGE("md add node is %d err!", res);
        HcfObjDestroy(static_cast<void *>(mdObj));
        JSI::ReleaseString(alg);
        return ThrowErrorCodeResult(res);
    }

    JSIValue serviceObj = JSI::CreateObject();
    JSIValue update = JSI::CreateFunction(Update);
    JSIValue updateSync = JSI::CreateFunction(UpdateSync);
    JSIValue digest = JSI::CreateFunction(Digest);
    JSIValue digestSync = JSI::CreateFunction(DigestSync);
    JSIValue getMdLength = JSI::CreateFunction(GetMdLength);
    JSI::SetNamedProperty(serviceObj, "update", update);
    JSI::SetNamedProperty(serviceObj, "updateSync", updateSync);
    JSI::SetNamedProperty(serviceObj, "digest", digest);
    JSI::SetNamedProperty(serviceObj, "digestSync", digestSync);
    JSI::SetNamedProperty(serviceObj, "getMdLength", getMdLength);
    JSI::SetNumberProperty(serviceObj, "mdObj", (double)(uint32_t)mdObj);
    JSI::ReleaseValueList(update, updateSync, digest, digestSync, getMdLength, ARGS_END);

    JSI::ReleaseString(alg);
    return serviceObj;
}

JSIValue CryptoFrameworkLiteModule::Update(const JSIValue thisVal, const JSIValue *args, uint8_t argsNum)
{
    if ((args == nullptr) || (argsNum != ARRAY_MAX_SIZE)) {
        LOGE("Update args is null!");
        return JSI::CreateUndefined();
    }
    HcfMd *mdObj = reinterpret_cast<HcfMd *>((uint32_t)JSI::GetNumberProperty(thisVal, "mdObj"));
    if (mdObj == nullptr) {
        LOGE("Update mdObj is null!!");
        CallbackErrorCodeOrDataResult(thisVal, args[ARRAY_INDEX_ONE], HCF_INVALID_PARAMS, JSI::CreateNull());
        return JSI::CreateUndefined();
    }

    JSIValue inVlaue = JSI::GetNamedProperty(args[ARRAY_INDEX_ZERO], "data");
    HcfBlob inBlob = { .data = nullptr, .len = 0 };
    HcfResult errCode = ParseUint8ArrayToBlob(inVlaue, &inBlob);
    if (errCode != HCF_SUCCESS) {
        LOGE("Update inBlob is null!");
        CallbackErrorCodeOrDataResult(thisVal, args[ARRAY_INDEX_ONE], HCF_INVALID_PARAMS, JSI::CreateNull());
        return JSI::CreateUndefined();
    }

    errCode = mdObj->update(mdObj, &inBlob);
    HcfBlobDataClearAndFree(&inBlob);
    if (errCode != HCF_SUCCESS) {
        LOGE("Update errCode not is success!");
        CallbackErrorCodeOrDataResult(thisVal, args[ARRAY_INDEX_ONE], errCode, JSI::CreateNull());
        return JSI::CreateUndefined();
    }
    CallbackErrorCodeOrDataResult(thisVal, args[ARRAY_INDEX_ONE], HCF_SUCCESS, JSI::CreateNull());

    return JSI::CreateUndefined();
}

JSIValue CryptoFrameworkLiteModule::UpdateSync(const JSIValue thisVal, const JSIValue *args, uint8_t argsNum)
{
    if ((args == nullptr) || (argsNum != ARRAY_INDEX_ONE)) {
        LOGE("UpdateSync args is null!");
        return ThrowErrorCodeResult(HCF_INVALID_PARAMS);
    }
    HcfMd *mdObj = reinterpret_cast<HcfMd *>((uint32_t)JSI::GetNumberProperty(thisVal, "mdObj"));
    if (mdObj == nullptr) {
        LOGE("UpdateSync mdObj is null!!");
        return ThrowErrorCodeResult(HCF_INVALID_PARAMS);
    }
    JSIValue inVlaue = JSI::GetNamedProperty(args[ARRAY_INDEX_ZERO], "data");
    HcfBlob inBlob = { .data = nullptr, .len = 0 };
    HcfResult errCode = ParseUint8ArrayToBlob(inVlaue, &inBlob);
    if (errCode != HCF_SUCCESS) {
        LOGE("UpdateSync inBlob is null!");
        return ThrowErrorCodeResult(errCode);
    }

    errCode = mdObj->update(mdObj, &inBlob);
    HcfBlobDataClearAndFree(&inBlob);
    if (errCode != HCF_SUCCESS) {
        LOGE("UpdateSync update ret is error!");
    }

    return ThrowErrorCodeResult(errCode);
}

JSIValue CryptoFrameworkLiteModule::Digest(const JSIValue thisVal, const JSIValue *args, uint8_t argsNum)
{
    if ((args == nullptr) || (argsNum != ARRAY_INDEX_ONE)) {
        LOGE("Digest args is err or mdObj nullptr!");
        return JSI::CreateUndefined();
    }
    HcfMd *mdObj = reinterpret_cast<HcfMd *>((uint32_t)JSI::GetNumberProperty(thisVal, "mdObj"));
    if (mdObj == nullptr) {
        LOGE("Digest mdObj is null!!");
        CallbackErrorCodeOrDataResult(thisVal, args[ARRAY_INDEX_ZERO], HCF_INVALID_PARAMS, JSI::CreateUndefined());
        return JSI::CreateUndefined();
    }
    HcfBlob outBlob = { .data = nullptr, .len = 0 };
    HcfResult errCode = mdObj->doFinal(mdObj, &outBlob);
    if (errCode != HCF_SUCCESS) {
        LOGE("Digest errCode not is success!");
        HcfBlobDataClearAndFree(&outBlob);
        CallbackErrorCodeOrDataResult(thisVal, args[ARRAY_INDEX_ZERO], errCode, JSI::CreateUndefined());
        return JSI::CreateUndefined();
    }
    JSIValue outVlaue = ConstructJSIReturnResult(&outBlob);
    CallbackErrorCodeOrDataResult(thisVal, args[0], errCode, outVlaue);
    HcfBlobDataClearAndFree(&outBlob);

    return JSI::CreateUndefined();
}

JSIValue CryptoFrameworkLiteModule::DigestSync(const JSIValue thisVal, const JSIValue *args, uint8_t argsNum)
{
    (void)args;
    (void)argsNum;
    HcfMd *mdObj = reinterpret_cast<HcfMd *>((uint32_t)JSI::GetNumberProperty(thisVal, "mdObj"));
    if (mdObj == nullptr) {
        LOGE("DigestSync mdObj is null!!");
        return ThrowErrorCodeResult(HCF_INVALID_PARAMS);
    }

    HcfBlob outBlob = { .data = nullptr, .len = 0 };
    HcfResult errCode = mdObj->doFinal(mdObj, &outBlob);
    if (errCode != HCF_SUCCESS) {
        LOGE("DigestSync errCode not is success!");
        HcfBlobDataClearAndFree(&outBlob);
        return ThrowErrorCodeResult(errCode);
    }

    JSIValue mdSyncData = ConstructJSIReturnResult(&outBlob);
    HcfBlobDataClearAndFree(&outBlob);

    return mdSyncData;
}

JSIValue CryptoFrameworkLiteModule::GetMdLength(const JSIValue thisVal, const JSIValue *args, uint8_t argsNum)
{
    (void)args;
    (void)argsNum;
    HcfMd *mdObj = reinterpret_cast<HcfMd *>((uint32_t)JSI::GetNumberProperty(thisVal, "mdObj"));
    if (mdObj == nullptr) {
        LOGE("GetMdLength mdObj is null!");
        return ThrowErrorCodeResult(HCF_INVALID_PARAMS);
    }

    return JSI::CreateNumber(mdObj->getMdLength(mdObj));
}

void CryptoFrameworkLiteModule::MdDestroy(void)
{
    ListDestroy(JSI_ALG_MD);
}

} // namespace ACELite
} // namespace OHOS
