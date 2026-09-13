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

#include "jsi_utils.h"
#include "jsi.h"
#include "jsi_types.h"
#include "memory.h"
#include "securec.h"
#include "utils.h"
#include "log.h"

namespace OHOS {
namespace ACELite {

HcfResult ParseUint8ArrayToBlob(JSIValue value, HcfBlob *blob)
{
    if (!JSI::ValueIsTypedArray(value) || (blob == nullptr)) {
        LOGE("value is not a typed array!");
        return HCF_INVALID_PARAMS;
    }
    TypedArrayType arrayType;
    size_t arraySize = 0;
    size_t byteOffset = 0;
    JSIValue arrayBuffer = nullptr;
    HcfResult ret = HCF_SUCCESS;
    do {
        uint8_t *dataArray = JSI::GetTypedArrayInfo(value, arrayType, arraySize, arrayBuffer, byteOffset);
        if (dataArray == nullptr) {
            ret = HCF_ERR_CRYPTO_OPERATION;
            break;
        }
        if (arrayType != TypedArrayType::JSI_UINT8_ARRAY) {
            LOGE("value is not a uint8 array");
            ret = HCF_INVALID_PARAMS;
            break;
        }
        blob->data = reinterpret_cast<uint8_t *>(HcfMalloc(arraySize, 0));
        if (blob->data == nullptr) {
            ret = HCF_ERR_MALLOC;
            break;
        }
        memcpy_s(blob->data, arraySize, dataArray + byteOffset, arraySize);
        blob->len = arraySize;
    } while (0);
    if (arrayBuffer != nullptr) {
        JSI::ReleaseValue(arrayBuffer);
        arrayBuffer = nullptr;
    }
    return ret;
}

JSIValue ConstructJSIReturnResult(const HcfBlob *blob)
{
    JSIValue res;
    do {
        res = JSI::CreateObject();
        if (res == nullptr) {
            break;
        }
        if (blob->data != nullptr) {
            uint8_t *arrayBuffer = nullptr;
            JSIValue buffer = JSI::CreateArrayBuffer(blob->len, arrayBuffer);
            if (arrayBuffer == nullptr) {
                LOGE("create jsi array buffer failed");
                JSI::ReleaseValue(buffer);
                return res;
            }
            (void)memcpy_s(arrayBuffer, blob->len, blob->data, blob->len);
            JSIValue typedArray = JSI::CreateTypedArray(TypedArrayType::JSI_UINT8_ARRAY, blob->len, buffer, 0);
            JSI::ReleaseValue(buffer);
            JSI::SetNamedProperty(res, "data", typedArray);
        }
    } while (0);
    return res;
}

} // namespace ACELite
} // namespace OHOS
