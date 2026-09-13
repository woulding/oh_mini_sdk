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

#include "napi_utils.h"
#include "params_parser.h"
#include "log.h"
#include "memory.h"
#include "securec.h"
#include "napi_crypto_framework_defines.h"
#include "detailed_iv_params.h"
#include "detailed_gcm_params.h"
#include "detailed_ccm_params.h"
#include "detailed_aead_params.h"
#include "detailed_dsa_key_params.h"
#include "detailed_ecc_key_params.h"
#include "detailed_rsa_key_params.h"
#include "detailed_alg_25519_key_params.h"
#include "detailed_dh_key_params.h"
#include "detailed_chacha20_params.h"
#include "utils.h"
#include "pri_key.h"
#include "asy_key_generator.h"
#include "crypto_operation_err.h"

namespace OHOS {
namespace CryptoFramework {
using namespace std;

constexpr int PASSWORD_MAX_LENGTH = 4096;
struct AsyKeySpecItemRelationT {
    AsyKeySpecItem item;
    int32_t itemType;
};
using AsyKeySpecItemRelation = AsyKeySpecItemRelationT;

static const AsyKeySpecItemRelation ASY_KEY_SPEC_RELATION_SET[] = {
    { DSA_P_BN, SPEC_ITEM_TYPE_BIG_INT },
    { DSA_Q_BN, SPEC_ITEM_TYPE_BIG_INT },
    { DSA_G_BN, SPEC_ITEM_TYPE_BIG_INT },
    { DSA_SK_BN, SPEC_ITEM_TYPE_BIG_INT },
    { DSA_PK_BN, SPEC_ITEM_TYPE_BIG_INT },

    { ECC_FP_P_BN, SPEC_ITEM_TYPE_BIG_INT },
    { ECC_A_BN, SPEC_ITEM_TYPE_BIG_INT },
    { ECC_B_BN, SPEC_ITEM_TYPE_BIG_INT },
    { ECC_G_X_BN, SPEC_ITEM_TYPE_BIG_INT },
    { ECC_G_Y_BN, SPEC_ITEM_TYPE_BIG_INT },
    { ECC_N_BN, SPEC_ITEM_TYPE_BIG_INT },
    { ECC_H_INT, SPEC_ITEM_TYPE_NUM },  // warning: ECC_H_NUM in JS
    { ECC_SK_BN, SPEC_ITEM_TYPE_BIG_INT },
    { ECC_PK_X_BN, SPEC_ITEM_TYPE_BIG_INT },
    { ECC_PK_Y_BN, SPEC_ITEM_TYPE_BIG_INT },
    { ECC_FIELD_TYPE_STR, SPEC_ITEM_TYPE_STR },
    { ECC_FIELD_SIZE_INT, SPEC_ITEM_TYPE_NUM },  // warning: ECC_FIELD_SIZE_NUM in JS
    { ECC_CURVE_NAME_STR, SPEC_ITEM_TYPE_STR },

    { RSA_N_BN, SPEC_ITEM_TYPE_BIG_INT },
    { RSA_SK_BN, SPEC_ITEM_TYPE_BIG_INT },
    { RSA_PK_BN, SPEC_ITEM_TYPE_BIG_INT },
    { DH_P_BN, SPEC_ITEM_TYPE_BIG_INT },
    { DH_G_BN, SPEC_ITEM_TYPE_BIG_INT },
    { DH_L_NUM, SPEC_ITEM_TYPE_NUM },
    { DH_PK_BN, SPEC_ITEM_TYPE_BIG_INT },
    { DH_SK_BN, SPEC_ITEM_TYPE_BIG_INT },
    { ED25519_SK_BN, SPEC_ITEM_TYPE_BIG_INT },
    { ED25519_PK_BN, SPEC_ITEM_TYPE_BIG_INT },
    { X25519_SK_BN, SPEC_ITEM_TYPE_BIG_INT },
    { X25519_PK_BN, SPEC_ITEM_TYPE_BIG_INT },
};

int32_t GetAsyKeySpecType(AsyKeySpecItem targetItemType)
{
    for (uint32_t i = 0; i < sizeof(ASY_KEY_SPEC_RELATION_SET) / sizeof(AsyKeySpecItemRelation); i++) {
        if (ASY_KEY_SPEC_RELATION_SET[i].item == targetItemType) {
            return ASY_KEY_SPEC_RELATION_SET[i].itemType;
        }
    }
    LOGE("AsyKeySpecItem not support! ItemType: %{public}d", targetItemType);
    return -1;
}

int32_t GetSignSpecType(SignSpecItem targetItemType)
{
    if (targetItemType == PSS_MD_NAME_STR || targetItemType == PSS_MGF_NAME_STR || targetItemType == PSS_MGF1_MD_STR) {
        return SPEC_ITEM_TYPE_STR;
    }
    if (targetItemType == SM2_USER_ID_UINT8ARR || targetItemType == ML_DSA_CONTEXT_UINT8ARR) {
        return SPEC_ITEM_TYPE_UINT8ARR;
    }
    if (targetItemType == PSS_SALT_LEN_INT || targetItemType == PSS_TRAILER_FIELD_INT) {
        return SPEC_ITEM_TYPE_NUM;
    }
    if (targetItemType == ML_DSA_DETERMINISTIC_BOOL || targetItemType == ML_DSA_MU_BOOL) {
        return SPEC_ITEM_TYPE_BOOL;
    }
    LOGE("SignSpecItem not support! ItemType: %{public}d", targetItemType);
    return -1;
}

int32_t GetCipherSpecType(CipherSpecItem targetItemType)
{
    if (targetItemType == OAEP_MD_NAME_STR || targetItemType == OAEP_MGF_NAME_STR ||
        targetItemType == OAEP_MGF1_MD_STR || targetItemType == SM2_MD_NAME_STR) {
        return SPEC_ITEM_TYPE_STR;
    }
    if (targetItemType == OAEP_MGF1_PSRC_UINT8ARR) {
        return SPEC_ITEM_TYPE_UINT8ARR;
    }
    LOGE("CipherSpecItem not support! ItemType: %{public}d", targetItemType);
    return -1;
}

napi_value NapiGetNull(napi_env env)
{
    napi_value result = nullptr;
    napi_get_null(env, &result);
    return result;
}

static napi_value GetUint8ArrFromNapiDataBlob(napi_env env, napi_value arg)
{
    if ((env == nullptr) || (arg == nullptr)) {
        LOGE("Invalid params!");
        return nullptr;
    }
    napi_value data = nullptr;
    napi_valuetype valueType = napi_undefined;
    napi_status status = napi_get_named_property(env, arg, CRYPTO_TAG_DATA.c_str(), &data);
    napi_typeof(env, data, &valueType);
    if ((status != napi_ok) || (data == nullptr) || (valueType == napi_undefined)) {
        LOGE("failed to get valid data property!");
        return nullptr;
    }
    return data;
}

HcfBlob *GetBlobFromNapiUint8Arr(napi_env env, napi_value data)
{
    size_t length = 0;
    size_t offset = 0;
    void *rawData = nullptr;
    napi_value arrayBuffer = nullptr;
    napi_typedarray_type arrayType;
    // Warning: Do not release the rawData returned by this interface because the rawData is managed by VM.
    napi_status status = napi_get_typedarray_info(env, data, &arrayType, &length,
        reinterpret_cast<void **>(&rawData), &arrayBuffer, &offset);
    if ((status != napi_ok)) {
        LOGE("failed to get valid rawData.");
        return nullptr;
    }
    if (arrayType != napi_uint8_array) {
        LOGE("input data is not uint8 array.");
        return nullptr;
    }

    HcfBlob *newBlob = reinterpret_cast<HcfBlob *>(HcfMalloc(sizeof(HcfBlob), 0));
    if (newBlob == nullptr) {
        LOGE("Failed to allocate newBlob memory!");
        return nullptr;
    }

    // input empty uint8Arr, ex: new Uint8Arr(), the length is 0 and rawData is nullptr;
    if ((length == 0) || (rawData == nullptr)) {
        newBlob->len = 0;
        newBlob->data = nullptr;
        LOGD("napi Uint8Arr is null");
        return newBlob;
    }
    newBlob->len = length;
    newBlob->data = static_cast<uint8_t *>(HcfMalloc(length, 0));
    if (newBlob->data == nullptr) {
        LOGE("malloc blob data failed!");
        HCF_FREE_PTR(newBlob);
        return nullptr;
    }
    (void)memcpy_s(newBlob->data, length, rawData, length);
    return newBlob;
}

HcfBlob *GetBlobFromNapiDataBlob(napi_env env, napi_value arg)
{
    napi_value data = GetUint8ArrFromNapiDataBlob(env, arg);
    if (data == nullptr) {
        LOGE("failed to get data in DataBlob");
        return nullptr;
    }
    return GetBlobFromNapiUint8Arr(env, data);
}

HcfResult GetNapiUint8ArrayDataNoCopy(napi_env env, napi_value arg, HcfBlob *blob)
{
    napi_value data = GetUint8ArrFromNapiDataBlob(env, arg);
    if (data == nullptr) {
        LOGE("failed to get data in DataBlob");
        return HCF_INVALID_PARAMS;
    }

    void *rawData = nullptr;
    size_t len = 0;
    napi_typedarray_type arrayType;
    napi_status status = napi_get_typedarray_info(env, data, &arrayType, &len, &rawData, nullptr, nullptr);
    if (status != napi_ok) {
        LOGE("failed to get valid rawData.");
        return HCF_ERR_NAPI;
    }
    if (arrayType != napi_uint8_array) {
        LOGE("input data is not uint8 array.");
        return HCF_INVALID_PARAMS;
    }

    blob->data = reinterpret_cast<uint8_t *>(rawData);
    blob->len = len;
    return HCF_SUCCESS;
}

HcfResult GetBlobFromNapiValue(napi_env env, napi_value arg, HcfBlob *blob)
{
    napi_value data = GetUint8ArrFromNapiDataBlob(env, arg);
    if (data == nullptr) {
        LOGE("failed to get data in DataBlob");
        return HCF_INVALID_PARAMS;
    }

    void *rawData = nullptr;
    napi_typedarray_type arrayType;
    napi_status status = napi_get_typedarray_info(env, data, &arrayType, &(blob->len),
        reinterpret_cast<void **>(&rawData), nullptr, nullptr);
    if (status != napi_ok) {
        LOGE("failed to get valid rawData.");
        return HCF_ERR_NAPI;
    }
    if (arrayType != napi_uint8_array) {
        LOGE("input data is not uint8 array.");
        return HCF_INVALID_PARAMS;
    }

    blob->data = nullptr;
    if (blob->len == 0 || rawData == nullptr) {
        LOGD("napi Uint8Arr is null");
        return HCF_SUCCESS;
    }

    blob->data = static_cast<uint8_t *>(HcfMalloc(blob->len, 0));
    if (blob->data == nullptr) {
        LOGE("malloc blob data failed!");
        return HCF_ERR_MALLOC;
    }
    (void)memcpy_s(blob->data, blob->len, rawData, blob->len);
    return HCF_SUCCESS;
}

static HcfBlob *GetAadFromParamsSpec(napi_env env, napi_value arg)
{
    napi_value data = nullptr;
    HcfBlob *blob = nullptr;
    napi_valuetype valueType = napi_undefined;

    napi_status status = napi_get_named_property(env, arg, AAD_PARAMS.c_str(), &data);
    napi_typeof(env, data, &valueType);
    if ((status != napi_ok) || (data == nullptr) || (valueType == napi_undefined)) {
        LOGE("failed to get valid param property!");
        return nullptr;
    }
    if (valueType == napi_null) {
        blob = reinterpret_cast<HcfBlob *>(HcfMalloc(sizeof(HcfBlob), 0));
        if (blob == nullptr) {
            LOGE("Failed to allocate newBlob memory!");
            return nullptr;
        }
        return blob;
    }
    blob = GetBlobFromNapiDataBlob(env, data);
    if (blob == nullptr) {
        LOGE("GetBlobFromNapiDataBlob failed!");
        return nullptr;
    }
    return blob;
}

bool GetBigIntFromNapiValue(napi_env env, napi_value arg, HcfBigInteger *bigInt)
{
    if ((env == nullptr) || (arg == nullptr) || (bigInt == nullptr)) {
        LOGE("Invalid params!");
        return false;
    }

    int signBit;
    size_t wordCount;

    napi_get_value_bigint_words(env, arg, nullptr, &wordCount, nullptr);
    if ((wordCount == 0) || (wordCount > (INT_MAX / sizeof(uint64_t)))) {
        LOGE("Get big int failed.");
        return false;
    }
    int length = wordCount * sizeof(uint64_t);
    uint8_t *retArr = reinterpret_cast<uint8_t *>(HcfMalloc(length, 0));
    if (retArr == nullptr) {
        LOGE("malloc blob data failed!");
        return false;
    }
    if (napi_get_value_bigint_words(env, arg, &signBit, &wordCount, reinterpret_cast<uint64_t *>(retArr)) != napi_ok) {
        HcfFree(retArr);
        LOGE("failed to get valid rawData.");
        return false;
    }
    if (signBit != 0) {
        HcfFree(retArr);
        LOGE("failed to get gegative rawData.");
        return false;
    }
    bigInt->data = retArr;
    bigInt->len = length;
    return true;
}

bool GetPointFromNapiValue(napi_env env, napi_value arg, HcfPoint *point)
{
    if ((env == nullptr) || (arg == nullptr) || (point == nullptr)) {
        LOGE("Invalid params!");
        return false;
    }
    napi_value dataX = nullptr;
    napi_value dataY = nullptr;
    napi_valuetype valueType = napi_undefined;
    napi_status status = napi_get_named_property(env, arg, "x", &dataX);
    napi_typeof(env, dataX, &valueType);
    if ((status != napi_ok) || (dataX == nullptr) || (valueType == napi_undefined)) {
        LOGE("failed to get valid algo name!");
        return false;
    }
    status = napi_get_named_property(env, arg, "y", &dataY);
    napi_typeof(env, dataY, &valueType);
    if ((status != napi_ok) || (dataY == nullptr) || (valueType == napi_undefined)) {
        LOGE("failed to get valid algo name!");
        return false;
    }

    bool ret = GetBigIntFromNapiValue(env, dataX, &point->x);
    if (!ret) {
        LOGE("get point x failed!");
        return false;
    }
    ret = GetBigIntFromNapiValue(env, dataY, &point->y);
    if (!ret) {
        LOGE("get point y failed!");
        HCF_FREE_PTR((point->x).data);
        return false;
    }
    return true;
}

static const char *GetIvParamsSpecType()
{
    return IV_PARAMS_SPEC.c_str();
}

static const char *GetGcmParamsSpecType()
{
    return GCM_PARAMS_SPEC.c_str();
}

static const char *GetCcmParamsSpecType()
{
    return CCM_PARAMS_SPEC.c_str();
}

static const char *GetPoly1305ParamsSpecType()
{
    return POLY1305_PARAMS_SPEC.c_str();
}

static const char *GetAeadParamsSpecType()
{
    return AEAD_PARAMS_SPEC.c_str();
}

static HcfBlob *GetBlobFromParamsSpec(napi_env env, napi_value arg, const string &type)
{
    napi_value data = nullptr;
    HcfBlob *blob = nullptr;
    napi_valuetype valueType = napi_undefined;

    napi_status status = napi_get_named_property(env, arg, type.c_str(), &data);
    napi_typeof(env, data, &valueType);
    if ((status != napi_ok) || (data == nullptr) || (valueType == napi_undefined)) {
        LOGE("failed to get valid param property!");
        return nullptr;
    }
    blob = GetBlobFromNapiDataBlob(env, data);
    if (blob == nullptr) {
        LOGE("GetBlobFromNapiDataBlob failed!");
        return nullptr;
    }
    return blob;
}

static HcfBlob *GetBlobFromNapiUint8ArrParamsSpec(napi_env env, napi_value arg, const string &type)
{
    napi_value data = nullptr;
    HcfBlob *blob = nullptr;
    napi_valuetype valueType = napi_undefined;

    napi_status status = napi_get_named_property(env, arg, type.c_str(), &data);
    if (status != napi_ok) {
        LOGE("get property failed!");
        return nullptr;
    }
    status = napi_typeof(env, data, &valueType);
    if (status != napi_ok || valueType == napi_undefined) {
        LOGE("get property type failed!");
        return nullptr;
    }
    blob = GetBlobFromNapiUint8Arr(env, data);
    if (blob == nullptr) {
        LOGE("GetBlobFromNapiUint8Arr failed!");
        return nullptr;
    }
    return blob;
}

static bool GetIvParamsSpec(napi_env env, napi_value arg, HcfParamsSpec **paramsSpec)
{
    HcfIvParamsSpec *ivParamsSpec = reinterpret_cast<HcfIvParamsSpec *>(HcfMalloc(sizeof(HcfIvParamsSpec), 0));
    if (ivParamsSpec == nullptr) {
        LOGE("ivParamsSpec malloc failed!");
        return false;
    }

    HcfBlob *iv = GetBlobFromParamsSpec(env, arg, IV_PARAMS);
    if (iv == nullptr) {
        LOGE("GetBlobFromNapiDataBlob failed!");
        HcfFree(ivParamsSpec);
        return false;
    }
    ivParamsSpec->base.getType = GetIvParamsSpecType;
    ivParamsSpec->iv = *iv;
    *paramsSpec = reinterpret_cast<HcfParamsSpec *>(ivParamsSpec);
    HCF_FREE_PTR(iv);
    return true;
}

static bool GetIvAndAadBlob(napi_env env, napi_value arg, HcfBlob **iv, HcfBlob **aad)
{
    *iv = GetBlobFromParamsSpec(env, arg, IV_PARAMS);
    if (*iv == nullptr) {
        LOGE("get iv failed!");
        return false;
    }

    *aad = GetAadFromParamsSpec(env, arg);
    // error case free is in get paramspec func.
    if (*aad == nullptr) {
        LOGE("get aad failed!");
        return false;
    }
    return true;
}

static bool GetNonceAndAadBlob(napi_env env, napi_value arg, HcfBlob **nonce, HcfBlob **aad)
{
    *nonce = GetBlobFromNapiUint8ArrParamsSpec(env, arg, NONCE_PARAMS);
    if (*nonce == nullptr) {
        LOGE("get nonce failed!");
        return false;
    }

    bool result = false;
    napi_status status = napi_has_named_property(env, arg, AUTHENTICATED_DATA_PARAMS.c_str(), &result);
    if (status != napi_ok) {
        LOGE("check property failed!");
        return false;
    }
    if (!result) {
        *aad = nullptr;
        LOGI("aad is null!");
        return true;
    }
    *aad = GetBlobFromNapiUint8ArrParamsSpec(env, arg, AUTHENTICATED_DATA_PARAMS);
    if (*aad == nullptr) {
        LOGI("aad is null!");
        return true;
    }
    return true;
}

static bool GetGcmParamsSpec(napi_env env, napi_value arg, HcfCryptoMode opMode, HcfParamsSpec **paramsSpec)
{
    HcfBlob *iv = nullptr;
    HcfBlob *aad = nullptr;
    HcfBlob *tag = nullptr;
    HcfBlob authTag = {};
    bool ret = false;

    HcfGcmParamsSpec *gcmParamsSpec = reinterpret_cast<HcfGcmParamsSpec *>(HcfMalloc(sizeof(HcfGcmParamsSpec), 0));
    if (gcmParamsSpec == nullptr) {
        LOGE("gcmParamsSpec malloc failed!");
        return false;
    }

    if (!GetIvAndAadBlob(env, arg, &iv, &aad)) {
        LOGE("GetIvAndAadBlob failed!");
        goto clearup;
    }

    if (opMode == DECRYPT_MODE) {
        tag = GetBlobFromParamsSpec(env, arg, AUTHTAG_PARAMS);
        if (tag == nullptr) {
            LOGE("get tag failed!");
            goto clearup;
        }
    } else if (opMode == ENCRYPT_MODE) {
        authTag.data = static_cast<uint8_t *>(HcfMalloc(GCM_AUTH_TAG_LEN, 0));
        if (authTag.data == nullptr) {
            LOGE("get tag failed!");
            goto clearup;
        }
        authTag.len = GCM_AUTH_TAG_LEN;
    } else {
        goto clearup;
    }

    gcmParamsSpec->base.getType = GetGcmParamsSpecType;
    gcmParamsSpec->iv = *iv;
    gcmParamsSpec->aad = *aad;
    gcmParamsSpec->tag = opMode == DECRYPT_MODE ? *tag : authTag;
    *paramsSpec = reinterpret_cast<HcfParamsSpec *>(gcmParamsSpec);
    ret = true;
clearup:
   if (!ret) {
        HcfBlobDataFree(iv);
        HcfBlobDataFree(aad);
        HcfBlobDataFree(tag);
        HCF_FREE_PTR(gcmParamsSpec);
    }
    HCF_FREE_PTR(iv);
    HCF_FREE_PTR(aad);
    HCF_FREE_PTR(tag);
    return ret;
}

static bool GetCcmParamsSpec(napi_env env, napi_value arg, HcfCryptoMode opMode, HcfParamsSpec **paramsSpec)
{
    HcfBlob *iv = nullptr;
    HcfBlob *aad = nullptr;
    HcfBlob *tag = nullptr;
    HcfBlob authTag = {};
    bool ret = false;

    HcfCcmParamsSpec *ccmParamsSpec = reinterpret_cast<HcfCcmParamsSpec *>(HcfMalloc(sizeof(HcfCcmParamsSpec), 0));
    if (ccmParamsSpec == nullptr) {
        LOGE("ccmParamsSpec malloc failed!");
        return ret;
    }

    if (!GetIvAndAadBlob(env, arg, &iv, &aad)) {
        LOGE("GetIvAndAadBlob failed!");
        goto clearup;
    }

    if (opMode == DECRYPT_MODE) {
        tag = GetBlobFromParamsSpec(env, arg, AUTHTAG_PARAMS);
        if (tag == nullptr) {
            LOGE("get tag failed!");
            goto clearup;
        }
    } else if (opMode == ENCRYPT_MODE) {
        authTag.data = static_cast<uint8_t *>(HcfMalloc(CCM_AUTH_TAG_LEN, 0));
        if (authTag.data == nullptr) {
            LOGE("get tag failed!");
            goto clearup;
        }
        authTag.len = CCM_AUTH_TAG_LEN;
    } else {
        goto clearup;
    }
    ccmParamsSpec->base.getType = GetCcmParamsSpecType;
    ccmParamsSpec->iv = *iv;
    ccmParamsSpec->aad = *aad;
    ccmParamsSpec->tag = opMode == DECRYPT_MODE ? *tag : authTag;
    *paramsSpec = reinterpret_cast<HcfParamsSpec *>(ccmParamsSpec);
    ret = true;
clearup:
    if (!ret) {
        HcfBlobDataFree(iv);
        HcfBlobDataFree(aad);
        HcfBlobDataFree(tag);
        HCF_FREE_PTR(ccmParamsSpec);
    }
    HCF_FREE_PTR(iv);
    HCF_FREE_PTR(aad);
    HCF_FREE_PTR(tag);
    return ret;
}

static bool GetPoly1305ParamsSpec(napi_env env, napi_value arg, HcfCryptoMode opMode, HcfParamsSpec **paramsSpec)
{
    HcfBlob *iv = nullptr;
    HcfBlob *aad = nullptr;
    HcfBlob *tag = nullptr;
    HcfBlob authTag = {};
    bool ret = false;

    HcfChaCha20ParamsSpec *poly1305ParamsSpec =
        reinterpret_cast<HcfChaCha20ParamsSpec *>(HcfMalloc(sizeof(HcfChaCha20ParamsSpec), 0));
    if (poly1305ParamsSpec == nullptr) {
        LOGE("poly1305ParamsSpec malloc failed!");
        return false;
    }

    if (!GetIvAndAadBlob(env, arg, &iv, &aad)) {
        LOGE("GetIvAndAadBlob failed!");
        goto clearup;
    }

    if (opMode == DECRYPT_MODE) {
        tag = GetBlobFromParamsSpec(env, arg, AUTHTAG_PARAMS);
        if (tag == nullptr) {
            LOGE("get tag failed!");
            goto clearup;
        }
    } else if (opMode == ENCRYPT_MODE) {
        authTag.data = static_cast<uint8_t *>(HcfMalloc(POLY1305_AUTH_TAG_LEN, 0));
        if (authTag.data == nullptr) {
            LOGE("get tag failed!");
            goto clearup;
        }
        authTag.len = POLY1305_AUTH_TAG_LEN;
    } else {
        goto clearup;
    }

    poly1305ParamsSpec->base.getType = GetPoly1305ParamsSpecType;
    poly1305ParamsSpec->iv = *iv;
    poly1305ParamsSpec->aad = *aad;
    poly1305ParamsSpec->tag = opMode == DECRYPT_MODE ? *tag : authTag;
    *paramsSpec = reinterpret_cast<HcfParamsSpec *>(poly1305ParamsSpec);
    ret = true;
clearup:
   if (!ret) {
        HcfBlobDataFree(iv);
        HcfBlobDataFree(aad);
        HcfBlobDataFree(tag);
        HCF_FREE_PTR(poly1305ParamsSpec);
    }
    HCF_FREE_PTR(iv);
    HCF_FREE_PTR(aad);
    HCF_FREE_PTR(tag);
    return ret;
}

static bool GetOptionalInt32FromParamsSpec(napi_env env, napi_value arg, const string &type, int32_t &outVal)
{
    bool result = false;
    napi_valuetype valueType = napi_undefined;
    napi_status status = napi_has_named_property(env, arg, type.c_str(), &result);
    if (status != napi_ok) {
        LOGE("check property failed!");
        return false;
    }
    if (!result) {
        LOGI("tag len is not set, use default value!");
        outVal = 0;
        return true;
    }
    napi_value data = nullptr;
    status = napi_get_named_property(env, arg, type.c_str(), &data);
    if (status != napi_ok) {
        LOGE("get property failed!");
        return false;
    }
    status = napi_typeof(env, data, &valueType);
    if (status != napi_ok) {
        LOGE("get property type failed!");
        return false;
    }
    if (valueType != napi_number) {
        LOGE("property value type is not number!");
        return false;
    }
    status = napi_get_value_int32(env, data, &outVal);
    if (status != napi_ok) {
        LOGE("get property value failed!");
        return false;
    }
    return true;
}

static bool GetAeadParamsSpec(napi_env env, napi_value arg, HcfCryptoMode opMode, HcfParamsSpec **paramsSpec)
{
    (void)opMode;
    HcfBlob *nonce = nullptr;
    HcfBlob *aad = nullptr;
    bool ret = false;

    HcfAeadParamsSpec *aeadParamsSpec = reinterpret_cast<HcfAeadParamsSpec *>(HcfMalloc(sizeof(HcfAeadParamsSpec), 0));
    if (aeadParamsSpec == nullptr) {
        LOGE("aeadParamsSpec malloc failed!");
        return ret;
    }

    if (!GetNonceAndAadBlob(env, arg, &nonce, &aad)) {
        LOGE("GetNonceAndAadBlob failed!");
        goto clearup;
    }

    if (!GetOptionalInt32FromParamsSpec(env, arg, TAG_LEN_PARAMS, aeadParamsSpec->tagLen)) {
        LOGE("get tag len failed!");
        goto clearup;
    }

    aeadParamsSpec->base.getType = GetAeadParamsSpecType;
    aeadParamsSpec->nonce = *nonce;
    if (aad == nullptr) {
        aeadParamsSpec->aad = { .data = nullptr, .len = 0 };
    } else {
        aeadParamsSpec->aad = *aad;
    }
    *paramsSpec = reinterpret_cast<HcfParamsSpec *>(aeadParamsSpec);
    ret = true;
clearup:
    if (!ret) {
        HcfBlobDataFree(nonce);
        if (aad != nullptr) {
            HcfBlobDataFree(aad);
        }
        HCF_FREE_PTR(aeadParamsSpec);
    }
    HCF_FREE_PTR(nonce);
    HCF_FREE_PTR(aad);
    return ret;
}

bool GetParamsSpecFromNapiValue(napi_env env, napi_value arg, HcfCryptoMode opMode, HcfParamsSpec **paramsSpec)
{
    napi_value data = nullptr;
    napi_valuetype valueType = napi_undefined;
    if ((env == nullptr) || (arg == nullptr) || (paramsSpec == nullptr)) {
        LOGE("Invalid params!");
        return false;
    }

    napi_status status = napi_get_named_property(env, arg, ALGO_PARAMS.c_str(), &data);
    napi_typeof(env, data, &valueType);
    if ((status != napi_ok) || (data == nullptr) || (valueType == napi_undefined)) {
        status = napi_get_named_property(env, arg, ALGO_PARAMS_OLD.c_str(), &data);
        napi_typeof(env, data, &valueType);
        if ((status != napi_ok) || (data == nullptr) || (valueType == napi_undefined)) {
            LOGE("failed to get valid algo name!");
            return false;
        }
    }
    string algoName;
    if (!GetStringFromJSParams(env, data, algoName)) {
        LOGE("GetStringFromJSParams failed!");
        return false;
    }
    if (algoName.compare(IV_PARAMS_SPEC) == 0) {
        return GetIvParamsSpec(env, arg, paramsSpec);
    } else if (algoName.compare(GCM_PARAMS_SPEC) == 0) {
        return GetGcmParamsSpec(env, arg, opMode, paramsSpec);
    } else if (algoName.compare(CCM_PARAMS_SPEC) == 0) {
        return GetCcmParamsSpec(env, arg, opMode, paramsSpec);
    } else if (algoName.compare(POLY1305_PARAMS_SPEC) == 0) {
        return GetPoly1305ParamsSpec(env, arg, opMode, paramsSpec);
    } else if (algoName.compare(AEAD_PARAMS_SPEC) == 0) {
        return GetAeadParamsSpec(env, arg, opMode, paramsSpec);
    } else {
        LOGE("Unsupported params spec algorithm name");
        return false;
    }
}

static bool GetCharArrayFromJsString(napi_env env, napi_value arg, HcfBlob *retBlob)
{
    size_t length = 0;
    if (napi_get_value_string_utf8(env, arg, nullptr, 0, &length) != napi_ok) {
        LOGE("can not get char string length");
        return false;
    }
    if (length > PASSWORD_MAX_LENGTH) {
        LOGE("password length should not exceed 4096");
        return false;
    }
    if (length == 0) {
        LOGD("empty string");
        return false;
    }
    char *tmpPassword = static_cast<char *>(HcfMalloc(length + 1, 0));
    if (tmpPassword == nullptr) {
        LOGE("malloc string failed");
        return false;
    }
    if (napi_get_value_string_utf8(env, arg, tmpPassword, (length + 1), &length) != napi_ok) {
        LOGE("can not get char string value");
        HCF_FREE_PTR(tmpPassword);
        return false;
    }
    retBlob->data = reinterpret_cast<uint8_t *>(tmpPassword);
    retBlob->len = length;
    return true;
}

static bool InitEncodingParams(napi_env env, napi_value arg, HcfKeyEncodingParamsSpec *spec, HcfBlob *tmpPw,
    HcfBlob *tmpCipher)
{
    napi_value passWd = GetDetailAsyKeySpecValue(env, arg, PASSWD_PARAMS);
    napi_value cipher = GetDetailAsyKeySpecValue(env, arg, CIPHER_PARAMS);
    if ((passWd == nullptr) || (cipher == nullptr)) {
        LOGE("Invalid params.");
        return false;
    }

    if (!GetCharArrayFromJsString(env, passWd, tmpPw)) {
        LOGE("Failed to get passWord string from napi!");
        return false;
    }

    if (!GetCharArrayFromJsString(env, cipher, tmpCipher)) {
        LOGE("Failed to get cipher string from napi!");
        HcfBlobDataClearAndFree(tmpPw);
        return false;
    }

    spec->cipher = reinterpret_cast<char *>(tmpCipher->data);
    spec->password = reinterpret_cast<char *>(tmpPw->data);
    return true;
}

bool GetEncodingParamsSpec(napi_env env, napi_value arg, HcfParamsSpec **returnSpec)
{
    if ((env == nullptr) || (arg == nullptr) || (returnSpec == nullptr)) {
        LOGE("Invalid params.");
        return false;
    }

    HcfKeyEncodingParamsSpec *encodingParamsSpec =
        reinterpret_cast<HcfKeyEncodingParamsSpec *>(HcfMalloc(sizeof(HcfKeyEncodingParamsSpec), 0));
    if (encodingParamsSpec == nullptr) {
        LOGE("encodingParamsSpec malloc failed!");
        return false;
    }

    HcfBlob tmpPw = { .data = nullptr, .len = 0 };
    HcfBlob tmpCipher = { .data = nullptr, .len = 0 };
    if (!InitEncodingParams(env, arg, encodingParamsSpec, &tmpPw, &tmpCipher)) {
        LOGE("Failed to get passWord string from napi!");
        HCF_FREE_PTR(encodingParamsSpec);
        return false;
    }
    *returnSpec = reinterpret_cast<HcfParamsSpec *>(encodingParamsSpec);
    return true;
}

napi_value GetDetailAsyKeySpecValue(napi_env env, napi_value arg, string argName)
{
    napi_value data = nullptr;
    napi_valuetype valueType = napi_undefined;
    if ((env == nullptr) || (arg == nullptr)) {
        LOGE("Invalid params!");
        return nullptr;
    }
    napi_status status = napi_get_named_property(env, arg, argName.c_str(), &data);
    napi_typeof(env, data, &valueType);
    if ((status != napi_ok) || (data == nullptr) || (valueType == napi_undefined)) {
        LOGE("failed to get valid algo name!");
        return nullptr;
    }
    return data;
}

static napi_value GetCommSpecNapiValue(napi_env env, napi_value arg)
{
    napi_value data = nullptr;
    napi_valuetype valueType = napi_undefined;

    napi_status status = napi_get_named_property(env, arg, CRYPTO_TAG_COMM_PARAMS.c_str(), &data);
    napi_typeof(env, data, &valueType);

    if ((status != napi_ok) || (data == nullptr) || (valueType == napi_undefined)) {
        LOGE("failed to get valid algo name!");
        return nullptr;
    }
    return data;
}

static bool InitDsaCommonAsyKeySpec(napi_env env, napi_value arg, HcfDsaCommParamsSpec *spec)
{
    size_t algNameLen = DSA_ASY_KEY_SPEC.length();
    spec->base.algName = static_cast<char *>(HcfMalloc(algNameLen + 1, 0));
    if (spec->base.algName == nullptr) {
        LOGE("malloc DSA algName failed!");
        return false;
    }
    (void)memcpy_s(spec->base.algName, algNameLen+ 1, DSA_ASY_KEY_SPEC.c_str(), algNameLen);
    spec->base.specType = HCF_COMMON_PARAMS_SPEC;

    napi_value p = GetDetailAsyKeySpecValue(env, arg, "p");
    napi_value q = GetDetailAsyKeySpecValue(env, arg, "q");
    napi_value g = GetDetailAsyKeySpecValue(env, arg, "g");
    bool ret = GetBigIntFromNapiValue(env, p, &spec->p);
    if (!ret) {
        LOGE("Failed to get DSA p big integer from NAPI value");
        HCF_FREE_PTR(spec->base.algName);
        return false;
    }
    ret = GetBigIntFromNapiValue(env, q, &spec->q);
    if (!ret) {
        LOGE("Failed to get DSA q big integer from NAPI value");
        FreeDsaCommParamsSpec(spec);
        return false;
    }
    ret = GetBigIntFromNapiValue(env, g, &spec->g);
    if (!ret) {
        LOGE("Failed to get DSA g big integer from NAPI value");
        FreeDsaCommParamsSpec(spec);
        return false;
    }
    return true;
}

static bool GetDsaCommonAsyKeySpec(napi_env env, napi_value arg, HcfAsyKeyParamsSpec **asyKeySpec)
{
    HcfDsaCommParamsSpec *spec = reinterpret_cast<HcfDsaCommParamsSpec *>(HcfMalloc(sizeof(HcfDsaCommParamsSpec), 0));
    if (spec == nullptr) {
        LOGE("malloc failed!");
        return false;
    }
    if (!InitDsaCommonAsyKeySpec(env, arg, spec)) {
        LOGE("InitDsaCommonAsyKeySpec failed!");
        HcfFree(spec);
        return false;
    }
    *asyKeySpec = reinterpret_cast<HcfAsyKeyParamsSpec *>(spec);
    return true;
}

static bool GetDsaPubKeySpec(napi_env env, napi_value arg, HcfAsyKeyParamsSpec **asyKeySpec)
{
    HcfDsaPubKeyParamsSpec *spec = reinterpret_cast<HcfDsaPubKeyParamsSpec *>(
        HcfMalloc(sizeof(HcfDsaPubKeyParamsSpec), 0));
    if (spec == nullptr) {
        LOGE("malloc failed!");
        return false;
    }

    napi_value commSpecValue = GetCommSpecNapiValue(env, arg);
    if (commSpecValue == nullptr) {
        LOGE("Get comm spec napi value failed.");
        HCF_FREE_PTR(spec);
        return false;
    }
    if (!InitDsaCommonAsyKeySpec(env, commSpecValue, reinterpret_cast<HcfDsaCommParamsSpec *>(spec))) {
        LOGE("InitDsaCommonAsyKeySpec failed.");
        HCF_FREE_PTR(spec);
        return false;
    }
    spec->base.base.specType = HCF_PUBLIC_KEY_SPEC;

    napi_value pk = GetDetailAsyKeySpecValue(env, arg, "pk");
    bool ret = GetBigIntFromNapiValue(env, pk, &spec->pk);
    if (!ret) {
        LOGE("Failed to get DSA pub key big integer from NAPI value");
        DestroyDsaPubKeySpec(spec);
        return false;
    }
    *asyKeySpec = reinterpret_cast<HcfAsyKeyParamsSpec *>(spec);
    return true;
}

static bool GetDsaKeyPairAsyKeySpec(napi_env env, napi_value arg, HcfAsyKeyParamsSpec **asyKeySpec)
{
    HcfDsaKeyPairParamsSpec *spec = reinterpret_cast<HcfDsaKeyPairParamsSpec *>(
        HcfMalloc(sizeof(HcfDsaKeyPairParamsSpec), 0));
    if (spec == nullptr) {
        LOGE("malloc failed!");
        return false;
    }

    napi_value commSpecValue = GetCommSpecNapiValue(env, arg);
    if (commSpecValue == nullptr) {
        LOGE("Get comm spec napi value failed.");
        HCF_FREE_PTR(spec);
        return false;
    }
    if (!InitDsaCommonAsyKeySpec(env, commSpecValue, reinterpret_cast<HcfDsaCommParamsSpec *>(spec))) {
        LOGE("InitDsaCommonAsyKeySpec failed!");
        HCF_FREE_PTR(spec);
        return false;
    }
    spec->base.base.specType = HCF_KEY_PAIR_SPEC;

    napi_value pk = GetDetailAsyKeySpecValue(env, arg, "pk");
    bool ret = GetBigIntFromNapiValue(env, pk, &spec->pk);
    if (!ret) {
        LOGE("Failed to get DSA key pair pub key big integer from NAPI value");
        FreeDsaCommParamsSpec(reinterpret_cast<HcfDsaCommParamsSpec *>(spec));
        HCF_FREE_PTR(spec);
        return false;
    }
    napi_value sk = GetDetailAsyKeySpecValue(env, arg, "sk");
    ret = GetBigIntFromNapiValue(env, sk, &spec->sk);
    if (!ret) {
        LOGE("Failed to get DSA key pair pri key big integer from NAPI value");
        FreeDsaCommParamsSpec(reinterpret_cast<HcfDsaCommParamsSpec *>(spec));
        HCF_FREE_PTR(spec->pk.data);
        HCF_FREE_PTR(spec);
        return false;
    }
    *asyKeySpec = reinterpret_cast<HcfAsyKeyParamsSpec *>(spec);
    return true;
}

static bool GetDsaAsyKeySpec(napi_env env, napi_value arg, HcfAsyKeyParamsSpec **asyKeySpec)
{
    napi_value data = nullptr;
    napi_valuetype valueType = napi_undefined;

    napi_status status = napi_get_named_property(env, arg, TAG_SPEC_TYPE.c_str(), &data);
    napi_typeof(env, data, &valueType);
    if ((status != napi_ok) || (data == nullptr) || (valueType == napi_undefined)) {
        LOGE("failed to get valid algo name!");
        return false;
    }
    HcfAsyKeySpecType asyKeySpecType;
    status = napi_get_value_uint32(env, data, reinterpret_cast<uint32_t *>(&asyKeySpecType));
    if (status != napi_ok) {
        LOGE("failed to get valid asyKeySpecType!");
        return false;
    }
    if (asyKeySpecType == HCF_COMMON_PARAMS_SPEC) {
        return GetDsaCommonAsyKeySpec(env, arg, asyKeySpec);
    } else if (asyKeySpecType == HCF_PUBLIC_KEY_SPEC) {
        return GetDsaPubKeySpec(env, arg, asyKeySpec);
    } else if (asyKeySpecType == HCF_KEY_PAIR_SPEC) {
        return GetDsaKeyPairAsyKeySpec(env, arg, asyKeySpec);
    } else {
        LOGE("Unsupported DSA asy key spec type");
        return false;
    }
}

static bool GetFpField(napi_env env, napi_value arg, HcfECField **ecField)
{
    HcfECFieldFp *fp = reinterpret_cast<HcfECFieldFp *>(HcfMalloc(sizeof(HcfECFieldFp), 0));
    if (fp == nullptr) {
        LOGE("malloc fp failed!");
        return false;
    }

    size_t fieldTpyeLen = ECC_FIELD_TYPE_FP.length();
    fp->base.fieldType = static_cast<char *>(HcfMalloc(fieldTpyeLen + 1, 0));
    if (fp->base.fieldType == nullptr) {
        LOGE("malloc fieldType failed!");
        HcfFree(fp);
        return false;
    }
    (void)memcpy_s(fp->base.fieldType, fieldTpyeLen+ 1, ECC_FIELD_TYPE_FP.c_str(), fieldTpyeLen);

    napi_value p = GetDetailAsyKeySpecValue(env, arg, "p");
    bool ret = GetBigIntFromNapiValue(env, p, &fp->p);
    if (!ret) {
        LOGE("Failed to get Fp field p big integer from NAPI value");
        HCF_FREE_PTR(fp->base.fieldType);
        HcfFree(fp);
        return false;
    }
    *ecField = reinterpret_cast<HcfECField *>(fp);
    return true;
}

static bool GetField(napi_env env, napi_value arg, HcfECField **ecField)
{
    // get fieldData in { field : fieldData, a : xxx, b : xxx, ... } of ECCCommonParamsSpec first
    napi_value fieldData = nullptr;
    napi_valuetype valueType = napi_undefined;
    napi_status status = napi_get_named_property(env, arg, "field", &fieldData);
    napi_typeof(env, fieldData, &valueType);
    if ((status != napi_ok) || (fieldData == nullptr) || (valueType == napi_undefined)) {
        LOGE("failed to get valid field data!");
        return false;
    }

    // get fieldType in { fieldType : fieldTypeData } of ECField
    napi_value fieldTypeData = nullptr;
    status = napi_get_named_property(env, fieldData, "fieldType", &fieldTypeData);
    napi_typeof(env, fieldTypeData, &valueType);
    if ((status != napi_ok) || (fieldTypeData == nullptr) || (valueType == napi_undefined)) {
        LOGE("failed to get valid fieldType data!");
        return false;
    }
    string fieldType;
    if (!GetStringFromJSParams(env, fieldTypeData, fieldType)) {
        LOGE("GetStringFromJSParams failed when extracting fieldType!");
        return false;
    }

    // get p in { p : pData } of ECField, and generateECField
    if (fieldType.compare("Fp") == 0) {
        return GetFpField(env, fieldData, ecField);
    }
    LOGE("Unsupported EC field type");
    return false;
}

static bool InitEccDetailAsyKeySpec(napi_env env, napi_value arg, HcfEccCommParamsSpec *spec)
{
    napi_value a = GetDetailAsyKeySpecValue(env, arg, "a");
    napi_value b = GetDetailAsyKeySpecValue(env, arg, "b");
    napi_value n = GetDetailAsyKeySpecValue(env, arg, "n");
    napi_value g = GetDetailAsyKeySpecValue(env, arg, "g");
    bool ret = GetBigIntFromNapiValue(env, a, &spec->a);
    if (!ret) {
        LOGE("get ecc asyKeySpec a failed!");
        return false;
    }
    ret = GetBigIntFromNapiValue(env, b, &spec->b);
    if (!ret) {
        LOGE("get ecc asyKeySpec b failed!");
        return false;
    }
    ret = GetBigIntFromNapiValue(env, n, &spec->n);
    if (!ret) {
        LOGE("get ecc asyKeySpec n failed!");
        return false;
    }
    ret = GetPointFromNapiValue(env, g, &spec->g);
    if (!ret) {
        LOGE("get ecc asyKeySpec g failed!");
        return false;
    }
    return true;
}

static bool InitEccCommonAsyKeySpec(napi_env env, napi_value arg, HcfEccCommParamsSpec *spec, const string &algName)
{
    size_t algNameLen = ECC_ASY_KEY_SPEC.length();
    spec->base.algName = static_cast<char *>(HcfMalloc(algNameLen + 1, 0));
    if (spec->base.algName == nullptr) {
        LOGE("malloc ECC algName failed!");
        return false;
    }
    (void)memcpy_s(spec->base.algName, algNameLen+ 1, algName.c_str(), algNameLen);
    spec->base.specType = HCF_COMMON_PARAMS_SPEC;

    // get h
    napi_value hData = nullptr;
    napi_valuetype valueType = napi_undefined;
    napi_status status = napi_get_named_property(env, arg, "h", &hData);
    napi_typeof(env, hData, &valueType);
    if ((status != napi_ok) || (hData == nullptr) || (valueType == napi_undefined)) {
        LOGE("failed to get valid h!");
        HCF_FREE_PTR(spec->base.algName);
        return false;
    }
    if (!GetInt32FromJSParams(env, hData, spec->h)) {
        LOGE("get ecc asyKeySpec h failed!");
        HCF_FREE_PTR(spec->base.algName);
        return false;
    }
    // get field
    if (!GetField(env, arg, &spec->field)) {
        LOGE("GetField failed!");
        HCF_FREE_PTR(spec->base.algName);
        return false;
    }
    bool ret = InitEccDetailAsyKeySpec(env, arg, spec);
    if (!ret) {
        LOGE("get ecc asyKeySpec g failed!");
        FreeEccCommParamsSpec(spec);
        return false;
    }
    return true;
}

static bool GetEccCommonAsyKeySpec(napi_env env, napi_value arg, HcfAsyKeyParamsSpec **asyKeySpec,
    const string &algName)
{
    HcfEccCommParamsSpec *spec = reinterpret_cast<HcfEccCommParamsSpec *>(HcfMalloc(sizeof(HcfEccCommParamsSpec), 0));
    if (spec == nullptr) {
        LOGE("malloc failed!");
        return false;
    }
    if (!InitEccCommonAsyKeySpec(env, arg, spec, algName)) {
        LOGE("InitEccCommonAsyKeySpec failed!");
        HCF_FREE_PTR(spec);
        return false;
    }
    *asyKeySpec = reinterpret_cast<HcfAsyKeyParamsSpec *>(spec);
    return true;
}

static bool GetEccPriKeySpec(napi_env env, napi_value arg, HcfAsyKeyParamsSpec **asyKeySpec, const string &algName)
{
    HcfEccPriKeyParamsSpec *spec =
        reinterpret_cast<HcfEccPriKeyParamsSpec *>(HcfMalloc(sizeof(HcfEccPriKeyParamsSpec), 0));
    if (spec == nullptr) {
        LOGE("malloc failed!");
        return false;
    }

    napi_value commSpecValue = GetCommSpecNapiValue(env, arg);
    if (commSpecValue == nullptr) {
        LOGE("Get comm spec napi value failed.");
        HCF_FREE_PTR(spec);
        return false;
    }
    if (!InitEccCommonAsyKeySpec(env, commSpecValue, reinterpret_cast<HcfEccCommParamsSpec *>(spec), algName)) {
        LOGE("InitEccCommonAsyKeySpec failed!");
        HCF_FREE_PTR(spec);
        return false;
    }
    spec->base.base.specType = HCF_PRIVATE_KEY_SPEC;

    napi_value sk = GetDetailAsyKeySpecValue(env, arg, "sk");
    bool ret = GetBigIntFromNapiValue(env, sk, &spec->sk);
    if (!ret) {
        LOGE("Failed to get ECC pri key big integer from NAPI value");
        // get big int fail, sk is null
        FreeEccCommParamsSpec(reinterpret_cast<HcfEccCommParamsSpec *>(spec));
        HCF_FREE_PTR(spec);
        return false;
    }
    *asyKeySpec = reinterpret_cast<HcfAsyKeyParamsSpec *>(spec);
    return true;
}

static bool GetEccPubKeySpec(napi_env env, napi_value arg, HcfAsyKeyParamsSpec **asyKeySpec, const string &algName)
{
    HcfEccPubKeyParamsSpec *spec =
        reinterpret_cast<HcfEccPubKeyParamsSpec *>(HcfMalloc(sizeof(HcfEccPubKeyParamsSpec), 0));
    if (spec == nullptr) {
        LOGE("malloc failed!");
        return false;
    }

    napi_value commSpecValue = GetCommSpecNapiValue(env, arg);
    if (commSpecValue == nullptr) {
        LOGE("Get comm spec napi value failed.");
        HCF_FREE_PTR(spec);
        return false;
    }
    if (!InitEccCommonAsyKeySpec(env, commSpecValue, reinterpret_cast<HcfEccCommParamsSpec *>(spec), algName)) {
        LOGE("InitEccCommonAsyKeySpec failed!");
        HCF_FREE_PTR(spec);
        return false;
    }
    spec->base.base.specType = HCF_PUBLIC_KEY_SPEC;

    napi_value pk = GetDetailAsyKeySpecValue(env, arg, "pk");
    bool ret = GetPointFromNapiValue(env, pk, &spec->pk);
    if (!ret) {
        LOGE("Failed to get ECC pub key point from NAPI value");
        DestroyEccPubKeySpec(spec);
        return false;
    }
    *asyKeySpec = reinterpret_cast<HcfAsyKeyParamsSpec *>(spec);
    return true;
}

static bool GetEccKeyPairAsyKeySpec(napi_env env, napi_value arg, HcfAsyKeyParamsSpec **asyKeySpec,
    const string &algName)
{
    HcfEccKeyPairParamsSpec *spec =
        reinterpret_cast<HcfEccKeyPairParamsSpec *>(HcfMalloc(sizeof(HcfEccKeyPairParamsSpec), 0));
    if (spec == nullptr) {
        LOGE("malloc failed!");
        return false;
    }

    napi_value commSpecValue = GetCommSpecNapiValue(env, arg);
    if (commSpecValue == nullptr) {
        LOGE("Get comm spec napi value failed.");
        HCF_FREE_PTR(spec);
        return false;
    }
    if (!InitEccCommonAsyKeySpec(env, commSpecValue, reinterpret_cast<HcfEccCommParamsSpec *>(spec), algName)) {
        LOGE("InitEccCommonAsyKeySpec failed!");
        HCF_FREE_PTR(spec);
        return false;
    }
    spec->base.base.specType = HCF_KEY_PAIR_SPEC;

    // get big int fail, sk is null
    napi_value pk = GetDetailAsyKeySpecValue(env, arg, "pk");
    bool ret = GetPointFromNapiValue(env, pk, &spec->pk);
    if (!ret) {
        LOGE("Failed to get ECC key pair pub key point from NAPI value");
        FreeEccCommParamsSpec(reinterpret_cast<HcfEccCommParamsSpec *>(spec));
        HCF_FREE_PTR(spec);
        return false;
    }
    napi_value sk = GetDetailAsyKeySpecValue(env, arg, "sk");
    ret = GetBigIntFromNapiValue(env, sk, &spec->sk);
    if (!ret) {
        LOGE("Failed to get ECC key pair pri key big integer from NAPI value");
        FreeEccCommParamsSpec(reinterpret_cast<HcfEccCommParamsSpec *>(spec));
        HCF_FREE_PTR(spec->pk.x.data);
        HCF_FREE_PTR(spec->pk.y.data);
        HCF_FREE_PTR(spec);
        return false;
    }
    *asyKeySpec = reinterpret_cast<HcfAsyKeyParamsSpec *>(spec);
    return true;
}

static bool GetEccAsyKeySpec(napi_env env, napi_value arg, HcfAsyKeyParamsSpec **asyKeySpec, const string &algName)
{
    napi_value data = nullptr;
    napi_valuetype valueType = napi_undefined;

    napi_status status = napi_get_named_property(env, arg, TAG_SPEC_TYPE.c_str(), &data);
    napi_typeof(env, data, &valueType);
    if ((status != napi_ok) || (data == nullptr) || (valueType == napi_undefined)) {
        LOGE("failed to get valid algo name!");
        return false;
    }
    HcfAsyKeySpecType asyKeySpecType;
    status = napi_get_value_uint32(env, data, reinterpret_cast<uint32_t *>(&asyKeySpecType));
    if (status != napi_ok) {
        LOGE("failed to get valid asyKeySpecType!");
        return false;
    }
    if (asyKeySpecType == HCF_COMMON_PARAMS_SPEC) {
        return GetEccCommonAsyKeySpec(env, arg, asyKeySpec, algName);
    } else if (asyKeySpecType == HCF_PRIVATE_KEY_SPEC) {
        return GetEccPriKeySpec(env, arg, asyKeySpec, algName);
    } else if (asyKeySpecType == HCF_PUBLIC_KEY_SPEC) {
        return GetEccPubKeySpec(env, arg, asyKeySpec, algName);
    } else if (asyKeySpecType == HCF_KEY_PAIR_SPEC) {
        return GetEccKeyPairAsyKeySpec(env, arg, asyKeySpec, algName);
    } else {
        LOGE("keySpec not support!");
        return false;
    }
}

static bool InitRsaCommonAsyKeySpec(napi_env env, napi_value arg, HcfRsaCommParamsSpec *spec)
{
    size_t algNameLen = RSA_ASY_KEY_SPEC.length();
    spec->base.algName = static_cast<char *>(HcfMalloc(algNameLen + 1, 0));
    if (spec->base.algName == nullptr) {
        LOGE("malloc RSA algName failed!");
        return false;
    }
    (void)memcpy_s(spec->base.algName, algNameLen+ 1, RSA_ASY_KEY_SPEC.c_str(), algNameLen);
    spec->base.specType = HCF_COMMON_PARAMS_SPEC;

    napi_value n = GetDetailAsyKeySpecValue(env, arg, "n");

    bool ret = GetBigIntFromNapiValue(env, n, &spec->n);
    if (!ret) {
        LOGE("Rsa asyKeySpec get n failed!");
        HCF_FREE_PTR(spec->base.algName);
        return false;
    }
    return true;
}

static bool GetRsaPubKeySpec(napi_env env, napi_value arg, HcfAsyKeyParamsSpec **asyKeySpec)
{
    HcfRsaPubKeyParamsSpec *spec =
        reinterpret_cast<HcfRsaPubKeyParamsSpec *>(HcfMalloc(sizeof(HcfRsaPubKeyParamsSpec), 0));
    if (spec == nullptr) {
        LOGE("malloc failed!");
        return false;
    }

    napi_value commSpecValue = GetCommSpecNapiValue(env, arg);
    if (commSpecValue == nullptr) {
        LOGE("Get comm spec napi value failed.");
        HCF_FREE_PTR(spec);
        return false;
    }
    if (!InitRsaCommonAsyKeySpec(env, commSpecValue, reinterpret_cast<HcfRsaCommParamsSpec *>(spec))) {
        LOGE("InitRsaCommonAsyKeySpec failed!");
        HCF_FREE_PTR(spec);
        return false;
    }
    spec->base.base.specType = HCF_PUBLIC_KEY_SPEC;

    napi_value pk = GetDetailAsyKeySpecValue(env, arg, "pk");
    bool ret = GetBigIntFromNapiValue(env, pk, &spec->pk);
    if (!ret) {
        LOGE("Failed to get RSA pub key big integer from NAPI value");
        DestroyRsaPubKeySpec(spec);
        return false;
    }
    *asyKeySpec = reinterpret_cast<HcfAsyKeyParamsSpec *>(spec);
    return true;
}

static bool GetRsaKeyPairAsyKeySpec(napi_env env, napi_value arg, HcfAsyKeyParamsSpec **asyKeySpec)
{
    HcfRsaKeyPairParamsSpec *spec =
        reinterpret_cast<HcfRsaKeyPairParamsSpec *>(HcfMalloc(sizeof(HcfRsaKeyPairParamsSpec), 0));
    if (spec == nullptr) {
        LOGE("malloc failed!");
        return false;
    }

    napi_value commSpecValue = GetCommSpecNapiValue(env, arg);
    if (commSpecValue == nullptr) {
        LOGE("Get comm spec napi value failed.");
        HCF_FREE_PTR(spec);
        return false;
    }
    if (!InitRsaCommonAsyKeySpec(env, commSpecValue, reinterpret_cast<HcfRsaCommParamsSpec *>(spec))) {
        LOGE("InitRsaCommonAsyKeySpec failed!");
        HCF_FREE_PTR(spec);
        return false;
    }
    spec->base.base.specType = HCF_KEY_PAIR_SPEC;

    napi_value pk = GetDetailAsyKeySpecValue(env, arg, "pk");
    bool ret = GetBigIntFromNapiValue(env, pk, &spec->pk);
    if (!ret) {
        LOGE("Failed to get RSA key pair pub key big integer from NAPI value");
        FreeRsaCommParamsSpec(&(spec->base));
        HCF_FREE_PTR(spec);
        return false;
    }
    napi_value sk = GetDetailAsyKeySpecValue(env, arg, "sk");
    ret = GetBigIntFromNapiValue(env, sk, &spec->sk);
    if (!ret) {
        LOGE("Failed to get RSA key pair pri key big integer from NAPI value");
        FreeRsaCommParamsSpec(&(spec->base));
        HCF_FREE_PTR(spec->pk.data);
        HCF_FREE_PTR(spec);
        return false;
    }
    *asyKeySpec = reinterpret_cast<HcfAsyKeyParamsSpec *>(spec);
    return true;
}

static bool GetRsaAsyKeySpec(napi_env env, napi_value arg, HcfAsyKeyParamsSpec **asyKeySpec)
{
    napi_value data = nullptr;
    napi_valuetype valueType = napi_undefined;

    napi_status status = napi_get_named_property(env, arg, TAG_SPEC_TYPE.c_str(), &data);
    napi_typeof(env, data, &valueType);
    if ((status != napi_ok) || (data == nullptr) || (valueType == napi_undefined)) {
        LOGE("failed to get valid algo name!");
        return false;
    }
    HcfAsyKeySpecType asyKeySpecType;
    status = napi_get_value_uint32(env, data, reinterpret_cast<uint32_t *>(&asyKeySpecType));
    if (status != napi_ok) {
        LOGE("failed to get valid asyKeySpecType!");
        return false;
    }
    if (asyKeySpecType == HCF_COMMON_PARAMS_SPEC) {
        LOGE("RSA not support comm key spec");
        return false;
    } else if (asyKeySpecType == HCF_PUBLIC_KEY_SPEC) {
        return GetRsaPubKeySpec(env, arg, asyKeySpec);
    } else if (asyKeySpecType == HCF_KEY_PAIR_SPEC) {
        return GetRsaKeyPairAsyKeySpec(env, arg, asyKeySpec);
    } else {
        LOGE("Unsupported RSA asy key spec type");
        return false;
    }
}

static bool InitAlg25519CommonAsyKeySpec(HcfAsyKeyParamsSpec *spec, const string &algName)
{
    size_t algNameLen = algName.length();
    spec->algName = static_cast<char *>(HcfMalloc(algNameLen + 1, 0));
    if (spec->algName == nullptr) {
        LOGE("malloc alg25519 algName failed!");
        return false;
    }
    (void)memcpy_s(spec->algName, algNameLen + 1, algName.c_str(), algNameLen);
    return true;
}

static bool GetAlg25519PriKeySpec(napi_env env, napi_value arg, HcfAsyKeyParamsSpec **asyKeySpec, const string &algName)
{
    HcfAlg25519PriKeyParamsSpec *spec =
        reinterpret_cast<HcfAlg25519PriKeyParamsSpec *>(HcfMalloc(sizeof(HcfAlg25519PriKeyParamsSpec), 0));
    if (spec == nullptr) {
        LOGE("malloc failed!");
        return false;
    }
    if (!InitAlg25519CommonAsyKeySpec(reinterpret_cast<HcfAsyKeyParamsSpec *>(spec), algName)) {
        LOGE("InitRsaCommonAsyKeySpec failed!");
        DestroyAlg25519PriKeySpec(spec);
        return false;
    }
    spec->base.specType = HCF_PRIVATE_KEY_SPEC;

    napi_value sk = GetDetailAsyKeySpecValue(env, arg, "sk");
    bool ret = GetBigIntFromNapiValue(env, sk, &spec->sk);
    if (!ret) {
        LOGE("Failed to get Alg25519 pri key big integer from NAPI value");
        // get big int fail, sk is null
        DestroyAlg25519PriKeySpec(spec);
        return false;
    }
    *asyKeySpec = reinterpret_cast<HcfAsyKeyParamsSpec *>(spec);
    return true;
}

static bool GetAlg25519PubKeySpec(napi_env env, napi_value arg, HcfAsyKeyParamsSpec **asyKeySpec, const string &algName)
{
    HcfAlg25519PubKeyParamsSpec *spec =
        reinterpret_cast<HcfAlg25519PubKeyParamsSpec *>(HcfMalloc(sizeof(HcfAlg25519PubKeyParamsSpec), 0));
    if (spec == nullptr) {
        LOGE("malloc failed!");
        return false;
    }
    if (!InitAlg25519CommonAsyKeySpec(reinterpret_cast<HcfAsyKeyParamsSpec *>(spec), algName)) {
        LOGE("InitRsaCommonAsyKeySpec failed!");
        DestroyAlg25519PubKeySpec(spec);
        return false;
    }
    spec->base.specType = HCF_PUBLIC_KEY_SPEC;

    napi_value pk = GetDetailAsyKeySpecValue(env, arg, "pk");
    bool ret = GetBigIntFromNapiValue(env, pk, &spec->pk);
    if (!ret) {
        LOGE("Failed to get Alg25519 pub key big integer from NAPI value");
        DestroyAlg25519PubKeySpec(spec);
        return false;
    }
    *asyKeySpec = reinterpret_cast<HcfAsyKeyParamsSpec *>(spec);
    return true;
}

static bool GetAlg25519KeyPairAsyKeySpec(napi_env env, napi_value arg,
    HcfAsyKeyParamsSpec **asyKeySpec, const string &algName)
{
    HcfAlg25519KeyPairParamsSpec *spec =
        reinterpret_cast<HcfAlg25519KeyPairParamsSpec *>(HcfMalloc(sizeof(HcfAlg25519KeyPairParamsSpec), 0));
    if (spec == nullptr) {
        LOGE("malloc failed!");
        return false;
    }
    if (!InitAlg25519CommonAsyKeySpec(reinterpret_cast<HcfAsyKeyParamsSpec *>(spec), algName)) {
        LOGE("InitRsaCommonAsyKeySpec failed!");
        HCF_FREE_PTR(spec);
        return false;
    }
    spec->base.specType = HCF_KEY_PAIR_SPEC;

    // get big int fail, sk is null
    napi_value pk = GetDetailAsyKeySpecValue(env, arg, "pk");
    bool ret = GetBigIntFromNapiValue(env, pk, &spec->pk);
    if (!ret) {
        LOGE("Failed to get Alg25519 key pair pub key big integer from NAPI value");
        DestroyAlg25519KeyPairSpec(spec);
        return false;
    }
    napi_value sk = GetDetailAsyKeySpecValue(env, arg, "sk");
    ret = GetBigIntFromNapiValue(env, sk, &spec->sk);
    if (!ret) {
        LOGE("Failed to get Alg25519 key pair pri key big integer from NAPI value");
        DestroyAlg25519KeyPairSpec(spec);
        return false;
    }
    *asyKeySpec = reinterpret_cast<HcfAsyKeyParamsSpec *>(spec);
    return true;
}

static bool GetAlg25519AsyKeySpec(napi_env env, napi_value arg, HcfAsyKeyParamsSpec **asyKeySpec, const string &algName)
{
    napi_value data = nullptr;
    napi_valuetype valueType = napi_undefined;

    napi_status status = napi_get_named_property(env, arg, TAG_SPEC_TYPE.c_str(), &data);
    napi_typeof(env, data, &valueType);
    if ((status != napi_ok) || (data == nullptr) || (valueType == napi_undefined)) {
        LOGE("failed to get valid algo name!");
        return false;
    }
    HcfAsyKeySpecType asyKeySpecType;
    status = napi_get_value_uint32(env, data, reinterpret_cast<uint32_t *>(&asyKeySpecType));
    if (status != napi_ok) {
        LOGE("failed to get valid asyKeySpecType!");
        return false;
    }
    if (asyKeySpecType == HCF_PRIVATE_KEY_SPEC) {
        return GetAlg25519PriKeySpec(env, arg, asyKeySpec, algName);
    } else if (asyKeySpecType == HCF_PUBLIC_KEY_SPEC) {
        return GetAlg25519PubKeySpec(env, arg, asyKeySpec, algName);
    } else if (asyKeySpecType == HCF_KEY_PAIR_SPEC) {
        return GetAlg25519KeyPairAsyKeySpec(env, arg, asyKeySpec, algName);
    } else {
        LOGE("keySpec not support!");
        return false;
    }
}

static bool InitDhCommonAsyKeySpec(napi_env env, napi_value arg, HcfDhCommParamsSpec *spec)
{
    size_t algNameLen = DH_ASY_KEY_SPEC.length();
    spec->base.algName = static_cast<char *>(HcfMalloc(algNameLen + 1, 0));
    if (spec->base.algName == nullptr) {
        LOGE("malloc DH algName failed!");
        return false;
    }
    (void)memcpy_s(spec->base.algName, algNameLen+ 1, DH_ASY_KEY_SPEC.c_str(), algNameLen);
    spec->base.specType = HCF_COMMON_PARAMS_SPEC;

    napi_value length = nullptr;
    napi_valuetype valueType = napi_undefined;
    napi_status status = napi_get_named_property(env, arg, "l", &length);
    napi_typeof(env, length, &valueType);
    if ((status != napi_ok) || (length == nullptr) || (valueType == napi_undefined)) {
        LOGE("failed to get valid l!");
        HCF_FREE_PTR(spec->base.algName);
        return false;
    }
    if (!GetInt32FromJSParams(env, length, spec->length)) {
        LOGE("get dh asyKeySpec length failed!");
        HCF_FREE_PTR(spec->base.algName);
        return false;
    }
    napi_value p = GetDetailAsyKeySpecValue(env, arg, "p");
    napi_value g = GetDetailAsyKeySpecValue(env, arg, "g");
    bool ret = GetBigIntFromNapiValue(env, p, &spec->p);
    if (!ret) {
        LOGE("Failed to get DH p big integer from NAPI value");
        HCF_FREE_PTR(spec->base.algName);
        return false;
    }
    ret = GetBigIntFromNapiValue(env, g, &spec->g);
    if (!ret) {
        LOGE("Failed to get DH g big integer from NAPI value");
        FreeDhCommParamsSpec(spec);
        return false;
    }
    return true;
}

static bool GetDhCommonAsyKeySpec(napi_env env, napi_value arg, HcfAsyKeyParamsSpec **asyKeySpec)
{
    HcfDhCommParamsSpec *spec = reinterpret_cast<HcfDhCommParamsSpec *>(HcfMalloc(sizeof(HcfDhCommParamsSpec), 0));
    if (spec == nullptr) {
        LOGE("malloc failed!");
        return false;
    }
    if (!InitDhCommonAsyKeySpec(env, arg, spec)) {
        LOGE("InitDhCommonAsyKeySpec failed!");
        HCF_FREE_PTR(spec);
        return false;
    }
    *asyKeySpec = reinterpret_cast<HcfAsyKeyParamsSpec *>(spec);
    return true;
}

static bool GetDhPubKeySpec(napi_env env, napi_value arg, HcfAsyKeyParamsSpec **asyKeySpec)
{
    HcfDhPubKeyParamsSpec *spec = reinterpret_cast<HcfDhPubKeyParamsSpec *>(
        HcfMalloc(sizeof(HcfDhPubKeyParamsSpec), 0));
    if (spec == nullptr) {
        LOGE("malloc failed!");
        return false;
    }

    napi_value commSpecValue = GetCommSpecNapiValue(env, arg);
    if (commSpecValue == nullptr) {
        LOGE("Get comm spec napi value failed.");
        HCF_FREE_PTR(spec);
        return false;
    }
    if (!InitDhCommonAsyKeySpec(env, commSpecValue, reinterpret_cast<HcfDhCommParamsSpec *>(spec))) {
        LOGE("InitDhCommonAsyKeySpec failed.");
        HCF_FREE_PTR(spec);
        return false;
    }
    spec->base.base.specType = HCF_PUBLIC_KEY_SPEC;

    napi_value pk = GetDetailAsyKeySpecValue(env, arg, "pk");
    bool ret = GetBigIntFromNapiValue(env, pk, &spec->pk);
    if (!ret) {
        LOGE("Failed to get DH pub key big integer from NAPI value");
        DestroyDhPubKeySpec(spec);
        return false;
    }
    *asyKeySpec = reinterpret_cast<HcfAsyKeyParamsSpec *>(spec);
    return true;
}

static bool GetDhPriKeySpec(napi_env env, napi_value arg, HcfAsyKeyParamsSpec **asyKeySpec)
{
    HcfDhPriKeyParamsSpec *spec = reinterpret_cast<HcfDhPriKeyParamsSpec *>(
        HcfMalloc(sizeof(HcfDhPriKeyParamsSpec), 0));
    if (spec == nullptr) {
        LOGE("malloc failed!");
        return false;
    }

    napi_value commSpecValue = GetCommSpecNapiValue(env, arg);
    if (commSpecValue == nullptr) {
        LOGE("Get comm spec napi value failed.");
        HCF_FREE_PTR(spec);
        return false;
    }
    if (!InitDhCommonAsyKeySpec(env, commSpecValue, reinterpret_cast<HcfDhCommParamsSpec *>(spec))) {
        LOGE("InitDhCommonAsyKeySpec failed.");
        HCF_FREE_PTR(spec);
        return false;
    }
    spec->base.base.specType = HCF_PRIVATE_KEY_SPEC;

    napi_value pk = GetDetailAsyKeySpecValue(env, arg, "sk");
    bool ret = GetBigIntFromNapiValue(env, pk, &spec->sk);
    if (!ret) {
        LOGE("Failed to get DH pri key big integer from NAPI value");
        DestroyDhPriKeySpec(spec);
        return false;
    }
    *asyKeySpec = reinterpret_cast<HcfAsyKeyParamsSpec *>(spec);
    return true;
}

static bool GetDhKeyPairAsyKeySpec(napi_env env, napi_value arg, HcfAsyKeyParamsSpec **asyKeySpec)
{
    HcfDhKeyPairParamsSpec *spec = reinterpret_cast<HcfDhKeyPairParamsSpec *>(
        HcfMalloc(sizeof(HcfDhKeyPairParamsSpec), 0));
    if (spec == nullptr) {
        LOGE("malloc failed!");
        return false;
    }

    napi_value commSpecValue = GetCommSpecNapiValue(env, arg);
    if (commSpecValue == nullptr) {
        LOGE("Get comm spec napi value failed.");
        HCF_FREE_PTR(spec);
        return false;
    }
    if (!InitDhCommonAsyKeySpec(env, commSpecValue, reinterpret_cast<HcfDhCommParamsSpec *>(spec))) {
        LOGE("InitDhCommonAsyKeySpec failed!");
        HCF_FREE_PTR(spec);
        return false;
    }
    spec->base.base.specType = HCF_KEY_PAIR_SPEC;

    napi_value pk = GetDetailAsyKeySpecValue(env, arg, "pk");
    bool ret = GetBigIntFromNapiValue(env, pk, &spec->pk);
    if (!ret) {
        LOGE("Failed to get DH key pair pub key big integer from NAPI value");
        FreeDhCommParamsSpec(reinterpret_cast<HcfDhCommParamsSpec *>(spec));
        HCF_FREE_PTR(spec);
        return false;
    }
    napi_value sk = GetDetailAsyKeySpecValue(env, arg, "sk");
    ret = GetBigIntFromNapiValue(env, sk, &spec->sk);
    if (!ret) {
        LOGE("Failed to get DH key pair pri key big integer from NAPI value");
        FreeDhCommParamsSpec(reinterpret_cast<HcfDhCommParamsSpec *>(spec));
        HCF_FREE_PTR(spec->pk.data);
        HCF_FREE_PTR(spec);
        return false;
    }
    *asyKeySpec = reinterpret_cast<HcfAsyKeyParamsSpec *>(spec);
    return true;
}

static bool GetDh25519AsyKeySpec(napi_env env, napi_value arg, HcfAsyKeyParamsSpec **asyKeySpec)
{
    napi_value data = nullptr;
    napi_valuetype valueType = napi_undefined;

    napi_status status = napi_get_named_property(env, arg, TAG_SPEC_TYPE.c_str(), &data);
    napi_typeof(env, data, &valueType);
    if ((status != napi_ok) || (data == nullptr) || (valueType == napi_undefined)) {
        LOGE("failed to get valid algo name!");
        return false;
    }
    HcfAsyKeySpecType asyKeySpecType;
    status = napi_get_value_uint32(env, data, reinterpret_cast<uint32_t *>(&asyKeySpecType));
    if (status != napi_ok) {
        LOGE("failed to get valid asyKeySpecType!");
        return false;
    }
    if (asyKeySpecType == HCF_PRIVATE_KEY_SPEC) {
        return GetDhPriKeySpec(env, arg, asyKeySpec);
    } else if (asyKeySpecType == HCF_PUBLIC_KEY_SPEC) {
        return GetDhPubKeySpec(env, arg, asyKeySpec);
    } else if (asyKeySpecType == HCF_KEY_PAIR_SPEC) {
        return GetDhKeyPairAsyKeySpec(env, arg, asyKeySpec);
    } else if (asyKeySpecType == HCF_COMMON_PARAMS_SPEC) {
        return GetDhCommonAsyKeySpec(env, arg, asyKeySpec);
    } else {
        LOGE("keySpec not support!");
        return false;
    }
}

bool GetAsyKeySpecFromNapiValue(napi_env env, napi_value arg, HcfAsyKeyParamsSpec **asyKeySpec)
{
    napi_value data = nullptr;

    if ((env == nullptr) || (arg == nullptr) || (asyKeySpec == nullptr)) {
        LOGE("Invalid params!");
        return false;
    }

    napi_valuetype valueType = napi_undefined;

    napi_status status = napi_get_named_property(env, arg, CRYPTO_TAG_ALG_NAME.c_str(), &data);
    napi_typeof(env, data, &valueType);
    if ((status != napi_ok) || (data == nullptr) || (valueType == napi_undefined)) {
        LOGE("failed to get valid algName!");
        return false;
    }
    string algName;
    if (!GetStringFromJSParams(env, data, algName)) {
        LOGE("GetStringFromJSParams failed!");
        return false;
    }
    if (algName.compare(DSA_ASY_KEY_SPEC) == 0) {
        return GetDsaAsyKeySpec(env, arg, asyKeySpec);
    } else if (algName.compare(ECC_ASY_KEY_SPEC) == 0 || algName.compare(SM2_ASY_KEY_SPEC) == 0) {
        return GetEccAsyKeySpec(env, arg, asyKeySpec, algName);
    } else if (algName.compare(RSA_ASY_KEY_SPEC) == 0) {
        return GetRsaAsyKeySpec(env, arg, asyKeySpec);
    } else if (algName.compare(ED25519_ASY_KEY_SPEC) == 0 || algName.compare(X25519_ASY_KEY_SPEC) == 0) {
        return GetAlg25519AsyKeySpec(env, arg, asyKeySpec, algName);
    } else if (algName.compare(DH_ASY_KEY_SPEC) == 0) {
        return GetDh25519AsyKeySpec(env, arg, asyKeySpec);
    } else {
        LOGE("AlgName not support! [AlgName]: %{public}s", algName.c_str());
        return false;
    }
}

napi_value ConvertBlobToNapiValue(napi_env env, HcfBlob *blob)
{
    if (blob == nullptr || blob->data == nullptr || blob->len == 0) {
        LOGD("Invalid blob!");
        return NapiGetNull(env);
    }
    uint8_t *buffer = reinterpret_cast<uint8_t *>(HcfMalloc(blob->len, 0));
    if (buffer == nullptr) {
        LOGE("malloc uint8 array buffer failed!");
        return NapiGetNull(env);
    }

    if (memcpy_s(buffer, blob->len, blob->data, blob->len) != EOK) {
        LOGE("memcpy_s data to buffer failed!");
        HCF_FREE_PTR(buffer);
        return NapiGetNull(env);
    }

    napi_value outBuffer = nullptr;
    napi_status status = napi_create_external_arraybuffer(
        env, buffer, blob->len, [](napi_env env, void *data, void *hint) { HcfFree(data); }, nullptr, &outBuffer);
    if (status != napi_ok) {
        LOGE("create uint8 array buffer failed!");
        (void)memset_s(buffer, blob->len, 0, blob->len);
        HCF_FREE_PTR(buffer);
        return NapiGetNull(env);
    }
    buffer = nullptr;

    napi_value outData = nullptr;
    napi_create_typedarray(env, napi_uint8_array, blob->len, outBuffer, 0, &outData);
    napi_value dataBlob = nullptr;
    napi_create_object(env, &dataBlob);
    napi_set_named_property(env, dataBlob, CRYPTO_TAG_DATA.c_str(), outData);

    return dataBlob;
}

HcfResult ConvertDataBlobToNapiValue(napi_env env, HcfBlob *blob, napi_value *napiValue)
{
    if (blob->data == nullptr || blob->len == 0) { // inner api, allow empty data
        *napiValue = NapiGetNull(env);
        return HCF_SUCCESS;
    }

    uint8_t *buffer = reinterpret_cast<uint8_t *>(HcfMalloc(blob->len, 0));
    if (buffer == nullptr) {
        LOGE("malloc uint8 array buffer failed!");
        return HCF_ERR_MALLOC;
    }
    (void)memcpy_s(buffer, blob->len, blob->data, blob->len);

    napi_value outBuffer = nullptr;
    napi_status status = napi_create_external_arraybuffer(
        env, buffer, blob->len, [](napi_env env, void *data, void *hint) { HcfFree(data); }, nullptr, &outBuffer);
    if (status != napi_ok) {
        LOGE("create napi uint8 array buffer failed!");
        (void)memset_s(buffer, blob->len, 0, blob->len);
        HCF_FREE_PTR(buffer);
        return HCF_ERR_NAPI;
    }

    napi_value outData = nullptr;
    napi_create_typedarray(env, napi_uint8_array, blob->len, outBuffer, 0, &outData);
    napi_value dataBlob = nullptr;
    napi_create_object(env, &dataBlob);
    napi_set_named_property(env, dataBlob, CRYPTO_TAG_DATA.c_str(), outData);
    *napiValue = dataBlob;
    return HCF_SUCCESS;
}

napi_value ConvertObjectBlobToNapiValue(napi_env env, HcfBlob *blob)
{
    if (blob == nullptr || blob->data == nullptr || blob->len == 0) {
        NAPI_LOG_THROW(env, HCF_INVALID_PARAMS, "Invalid blob!");
        return NapiGetNull(env);
    }
    uint8_t *buffer = reinterpret_cast<uint8_t *>(HcfMalloc(blob->len, 0));
    if (buffer == nullptr) {
        NAPI_LOG_THROW(env, HCF_ERR_MALLOC, "malloc uint8 array buffer failed!");
        return NapiGetNull(env);
    }

    if (memcpy_s(buffer, blob->len, blob->data, blob->len) != EOK) {
        NAPI_LOG_THROW(env, HCF_ERR_MALLOC, "memcpy_s data to buffer failed!");
        HCF_FREE_PTR(buffer);
        return NapiGetNull(env);
    }

    napi_value outBuffer = nullptr;
    napi_status status = napi_create_external_arraybuffer(
        env, buffer, blob->len, [](napi_env env, void *data, void *hint) { HcfFree(data); }, nullptr, &outBuffer);
    if (status != napi_ok) {
        NAPI_LOG_THROW(env, HCF_INVALID_PARAMS, "create uint8 array buffer failed!");
        HCF_FREE_PTR(buffer);
        return NapiGetNull(env);
    }
    buffer = nullptr;

    napi_value outData = nullptr;
    napi_create_typedarray(env, napi_uint8_array, blob->len, outBuffer, 0, &outData);
    return outData;
}

napi_value ConvertBigIntToNapiValue(napi_env env, HcfBigInteger *blob)
{
    if (blob == nullptr || blob->data == nullptr || blob->len == 0) {
        NAPI_LOG_THROW(env, HCF_INVALID_PARAMS, "Invalid blob!");
        return NapiGetNull(env);
    }
    size_t wordsCount = (blob->len / sizeof(uint64_t)) + ((blob->len % sizeof(uint64_t)) == 0 ? 0 : 1);
    uint64_t *words = reinterpret_cast<uint64_t *>(HcfMalloc(wordsCount * sizeof(uint64_t), 0));
    if (words == nullptr) {
        NAPI_LOG_THROW(env, HCF_ERR_MALLOC, "malloc uint8 array buffer failed!");
        return NapiGetNull(env);
    }

    size_t index = 0;
    for (size_t i = 0; index < wordsCount; i += sizeof(uint64_t), index++) {
        uint64_t tmp = 0;
        for (size_t j = 0; j < sizeof(uint64_t); j++) {
            if (i + j < blob->len) {
                tmp += ((uint64_t)blob->data[i + j] << (sizeof(uint64_t) * j));
            }
        }
        words[index] = tmp;
    }
    napi_value bigInt = nullptr;
    napi_status status = napi_create_bigint_words(env, 0, wordsCount, words, &bigInt);
    if (status != napi_ok) {
        NAPI_LOG_THROW(env, HCF_INVALID_PARAMS, "create bigint failed!");
        (void)memset_s(words, wordsCount * sizeof(uint64_t), 0, wordsCount * sizeof(uint64_t));
        HCF_FREE_PTR(words);
        return NapiGetNull(env);
    }
    if (bigInt == nullptr) {
        NAPI_LOG_THROW(env, HCF_INVALID_PARAMS, "bigInt is null!");
    }
    (void)memset_s(words, wordsCount * sizeof(uint64_t), 0, wordsCount * sizeof(uint64_t));
    HCF_FREE_PTR(words);
    return bigInt;
}

bool GetStringFromJSParams(napi_env env, napi_value arg, string &returnStr)
{
    napi_valuetype valueType;
    napi_typeof(env, arg, &valueType);
    if (valueType != napi_string) {
        LOGE("wrong argument type. expect string type.");
        return false;
    }

    size_t length = 0;
    if (napi_get_value_string_utf8(env, arg, nullptr, 0, &length) != napi_ok) {
        LOGE("can not get string length");
        return false;
    }
    returnStr.reserve(length + 1);
    returnStr.resize(length);
    if (napi_get_value_string_utf8(env, arg, returnStr.data(), (length + 1), &length) != napi_ok) {
        LOGE("can not get string value");
        return false;
    }
    return true;
}

bool GetInt32FromJSParams(napi_env env, napi_value arg, int32_t &returnInt)
{
    napi_valuetype valueType;
    napi_typeof(env, arg, &valueType);
    if (valueType != napi_number) {
        LOGE("wrong argument type. expect int type. [Type]: %{public}d", valueType);
        return false;
    }

    if (napi_get_value_int32(env, arg, &returnInt) != napi_ok) {
        LOGE("can not get int value");
        return false;
    }
    return true;
}

bool GetUint32FromJSParams(napi_env env, napi_value arg, uint32_t &returnInt)
{
    napi_valuetype valueType;
    napi_typeof(env, arg, &valueType);
    if (valueType != napi_number) {
        LOGE("wrong argument type. expect int type. [Type]: %{public}d", valueType);
        return false;
    }

    if (napi_get_value_uint32(env, arg, &returnInt) != napi_ok) {
        LOGE("can not get int value");
        return false;
    }
    return true;
}

bool GetUint64FromJSParams(napi_env env, napi_value arg, uint64_t &returnInt)
{
    napi_valuetype valueType;
    napi_typeof(env, arg, &valueType);
    if (valueType != napi_number) {
        LOGE("wrong argument type. expect int type. [Type]: %{public}d", valueType);
        return false;
    }
    int64_t int64Value = 0;
    if (napi_get_value_int64(env, arg, &int64Value) != napi_ok) {
        LOGE("can not get int value");
        return false;
    }
    if (int64Value < 0) {
        LOGE("int64Value is less than 0");
        return false;
    }
    returnInt = static_cast<uint64_t>(int64Value);
    return true;
}

bool GetCallbackFromJSParams(napi_env env, napi_value arg, napi_ref *returnCb)
{
    napi_valuetype valueType = napi_undefined;
    napi_typeof(env, arg, &valueType);
    if (valueType != napi_function) {
        LOGE("wrong argument type. expect callback type. [Type]: %{public}d", valueType);
        return false;
    }

    napi_create_reference(env, arg, 1, returnCb);
    return true;
}

static uint32_t GetJsErrValueByErrCode(HcfResult errCode)
{
    switch (errCode) {
        case HCF_INVALID_PARAMS:
            return JS_ERR_INVALID_PARAMS;
        case HCF_NOT_SUPPORT:
            return JS_ERR_NOT_SUPPORT;
        case HCF_ERR_MALLOC:
            return JS_ERR_OUT_OF_MEMORY;
        case HCF_ERR_NAPI:
            return JS_ERR_RUNTIME_ERROR;
        case HCF_ERR_CRYPTO_OPERATION:
            return JS_ERR_CRYPTO_OPERATION;
        case HCF_ERR_PARAMETER_CHECK_FAILED:
            return JS_ERR_PARAMETER_CHECK_FAILED;
        case HCF_ERR_INVALID_CALL:
            return JS_ERR_INVALID_CALL;
        default:
            return JS_ERR_DEFAULT_ERR;
    }
}

napi_value GenerateBusinessError(napi_env env, HcfResult errCode, const char *errMsg)
{
    napi_value businessError = nullptr;

    napi_value code = nullptr;
    napi_create_uint32(env, GetJsErrValueByErrCode(errCode), &code);

    napi_value msg = nullptr;
    napi_create_string_utf8(env, errMsg, NAPI_AUTO_LENGTH, &msg);

    napi_create_error(env, nullptr, msg, &businessError);
    napi_set_named_property(env, businessError, CRYPTO_TAG_ERR_CODE.c_str(), code);

    return businessError;
}

napi_value GenerateBusinessErrorEx(napi_env env, HcfResult errCode, const char *errMsg)
{
    if (errCode != HCF_ERR_CRYPTO_OPERATION) {
        return GenerateBusinessError(env, errCode, errMsg);
    }
    const char *newErrMsg = errMsg;
    char *errMsgBuf = nullptr;
    HcfGetCryptoOperationErrMsg(errCode, &newErrMsg, &errMsgBuf);
    napi_value res = GenerateBusinessError(env, errCode, newErrMsg);
    HcfFree(errMsgBuf);
    return res;
}

bool CheckArgsCount(napi_env env, size_t argc, size_t expectedCount, bool isSync)
{
    if (isSync) {
        if (argc != expectedCount) {
            LOGE("invalid params count!");
            return false;
        }
    } else {
        if ((argc != expectedCount) && (argc != (expectedCount - ARGS_SIZE_ONE))) {
            LOGE("invalid params count!");
            return false;
        }
    }
    return true;
}

bool isCallback(napi_env env, napi_value argv, size_t argc, size_t expectedArgc)
{
    if (argc == expectedArgc - 1) {
        return false;
    }
    napi_valuetype valueType = napi_undefined;
    napi_typeof(env, argv, &valueType);
    if (valueType == napi_undefined || valueType == napi_null) {
        return false;
    }
    return true;
}

napi_value GetResourceName(napi_env env, const char *name)
{
    napi_value resourceName = nullptr;
    napi_create_string_utf8(env, name, NAPI_AUTO_LENGTH, &resourceName);
    return resourceName;
}

bool BuildSetNamedProperty(napi_env env, HcfBigInteger *number, const char *name, napi_value *instance)
{
    napi_value value = ConvertBigIntToNapiValue(env, number);
    napi_status status = napi_set_named_property(env, *instance, name, value);
    if (status != napi_ok) {
        LOGE("create value failed!");
        return false;
    }
    return true;
}
}  // namespace CryptoFramework
}  // namespace OHOS
