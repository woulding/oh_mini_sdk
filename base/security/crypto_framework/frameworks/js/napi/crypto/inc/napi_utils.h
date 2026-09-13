/*
 * Copyright (C) 2022-2024 Huawei Device Co., Ltd.
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

#ifndef HCF_NAPI_UILTS_H
#define HCF_NAPI_UILTS_H

#include <cstdint>
#include <string>

#include "algorithm_parameter.h"
#include "asy_key_params.h"
#include "blob.h"
#include "big_integer.h"
#include "cipher.h"
#include "detailed_dh_key_params.h"
#include "detailed_ecc_key_params.h"
#include "detailed_alg_25519_key_params.h"
#include "napi/native_api.h"
#include "napi/native_common.h"
#include "signature.h"
#include "js_api_metrics.h"
#include "log.h"

namespace OHOS {
namespace CryptoFramework {
#define PARAMS_NUM_ONE 1
#define PARAMS_NUM_TWO 2
#define PARAMS_NUM_THREE 3
#define PARAMS_NUM_FOUR 4

#define NAPI_LOG_THROW(env, code, msg) \
    do { \
        LOGE(msg); \
        napi_throw(env, GenerateBusinessError(env, code, msg)); \
    } while (0)

#define NAPI_LOG_THROW_EX(env, code, msg) \
    do { \
        LOGE(msg); \
        napi_throw(env, GenerateBusinessErrorEx(env, code, msg)); \
    } while (0)

enum AsyncType {
    ASYNC_CALLBACK = 1,
    ASYNC_PROMISE = 2
};

inline void AddUint32Property(napi_env env, napi_value object, const char *name, uint32_t value)
{
    napi_value property = nullptr;
    napi_create_uint32(env, value, &property);
    napi_set_named_property(env, object, name, property);
}

HcfBlob *GetBlobFromNapiUint8Arr(napi_env env, napi_value data);
HcfBlob *GetBlobFromNapiDataBlob(napi_env env, napi_value arg);

bool GetParamsSpecFromNapiValue(napi_env env, napi_value arg, HcfCryptoMode opMode, HcfParamsSpec **paramsSpec);
bool GetEncodingParamsSpec(napi_env env, napi_value arg, HcfParamsSpec **returnSpec);
napi_value ConvertBlobToNapiValue(napi_env env, HcfBlob *blob);

napi_value ConvertObjectBlobToNapiValue(napi_env env, HcfBlob *blob);

bool GetAsyKeySpecFromNapiValue(napi_env env, napi_value arg, HcfAsyKeyParamsSpec **asyKeySpec);
bool BuildSetNamedProperty(napi_env env, HcfBigInteger *number, const char *name, napi_value *intence);
napi_value ConvertBigIntToNapiValue(napi_env env, HcfBigInteger *blob);

bool GetPointFromNapiValue(napi_env env, napi_value arg, HcfPoint *point);
bool GetStringFromJSParams(napi_env env, napi_value arg, std::string &returnStr);
bool GetInt32FromJSParams(napi_env env, napi_value arg, int32_t &returnInt);
bool GetUint32FromJSParams(napi_env env, napi_value arg, uint32_t &returnInt);
bool GetUint64FromJSParams(napi_env env, napi_value arg, uint64_t &returnInt);
bool GetCallbackFromJSParams(napi_env env, napi_value arg, napi_ref *returnCb);
bool CheckArgsCount(napi_env env, size_t argc, size_t expectedCount, bool isSync);
bool isCallback(napi_env env, napi_value argv, size_t argc, size_t expectedArgc);
napi_value GetResourceName(napi_env env, const char *name);
napi_value NapiGetNull(napi_env env);
napi_value GenerateBusinessError(napi_env env, HcfResult errCode, const char *errMsg);
napi_value GenerateBusinessErrorEx(napi_env env, HcfResult errCode, const char *errMsg);
int32_t GetAsyKeySpecType(AsyKeySpecItem targetItemType);
int32_t GetSignSpecType(SignSpecItem targetItemType);
int32_t GetCipherSpecType(CipherSpecItem targetItemType);

napi_value GetDetailAsyKeySpecValue(napi_env env, napi_value arg, std::string argName);
bool GetBigIntFromNapiValue(napi_env env, napi_value arg, HcfBigInteger *bigInt);

HcfResult ConvertDataBlobToNapiValue(napi_env env, HcfBlob *blob, napi_value *napiValue);
HcfResult GetBlobFromNapiValue(napi_env env, napi_value arg, HcfBlob *blob);

HcfResult GetNapiUint8ArrayDataNoCopy(napi_env env, napi_value arg, HcfBlob *blob);

}  // namespace CryptoFramework
}  // namespace OHOS
#endif
