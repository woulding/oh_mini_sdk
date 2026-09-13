/*
 * Copyright (c) 2025-2025 Huawei Device Co., Ltd.
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

#include "ani_common.h"
#include <unordered_map>

namespace {
using namespace ANI::CryptoFramework;

enum ResultCode {
    SUCCESS = 0,
    INVALID_PARAMS = 401,
    NOT_SUPPORT = 801,
    ERR_OUT_OF_MEMORY = 17620001,
    ERR_RUNTIME_ERROR = 17620002,
    ERR_PARAMETER_CHECK_FAILED = 17620003,
    ERR_INVALID_CALL = 17620004,
    ERR_CRYPTO_OPERATION = 17630001,
};

static const std::unordered_map<HcfResult, ResultCode> RESULT_CODE = {
    { HCF_SUCCESS, SUCCESS },
    { HCF_INVALID_PARAMS, INVALID_PARAMS },
    { HCF_NOT_SUPPORT, NOT_SUPPORT },
    { HCF_ERR_MALLOC, ERR_OUT_OF_MEMORY },
    { HCF_ERR_ANI, ERR_RUNTIME_ERROR },
    { HCF_ERR_PARAMETER_CHECK_FAILED, ERR_PARAMETER_CHECK_FAILED },
    { HCF_ERR_INVALID_CALL, ERR_INVALID_CALL },
    { HCF_ERR_CRYPTO_OPERATION, ERR_CRYPTO_OPERATION },
};

static const std::unordered_map<HcfAsyKeySpecItem, int> ASY_KEY_SPEC_RELATION_MAP = {
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

static const std::unordered_map<HcfSignSpecItem, int> SIGN_SPEC_RELATION_MAP = {
    { PSS_MD_NAME_STR, SPEC_ITEM_TYPE_STR },
    { PSS_MGF_NAME_STR, SPEC_ITEM_TYPE_STR },
    { PSS_MGF1_MD_STR, SPEC_ITEM_TYPE_STR },
    { PSS_SALT_LEN_INT, SPEC_ITEM_TYPE_NUM },  // warning: PSS_SALT_LEN_NUM in JS
    { PSS_TRAILER_FIELD_INT, SPEC_ITEM_TYPE_NUM },  // warning: PSS_TRAILER_FIELD_NUM in JS
    { SM2_USER_ID_UINT8ARR, SPEC_ITEM_TYPE_UINT8ARR },
    { ML_DSA_DETERMINISTIC_BOOL, SPEC_ITEM_TYPE_BOOL },
    { ML_DSA_MU_BOOL, SPEC_ITEM_TYPE_BOOL },
    { ML_DSA_CONTEXT_UINT8ARR, SPEC_ITEM_TYPE_UINT8ARR },
};
} // namespace

namespace ANI::CryptoFramework {
// template specialization for ArrayU8ToDataBlob
template
void ArrayU8ToDataBlob<array<uint8_t>>(const array<uint8_t> &arr, HcfBlob &blob);
template
void ArrayU8ToDataBlob<array_view<uint8_t>>(const array_view<uint8_t> &arr, HcfBlob &blob);

// template specialization for ArrayU8ToBigInteger
template
bool ArrayU8ToBigInteger<array<uint8_t>>(const array<uint8_t> &arr, HcfBigInteger &bigint);
template
bool ArrayU8ToBigInteger<array_view<uint8_t>>(const array_view<uint8_t> &arr, HcfBigInteger &bigint);

int ConvertResultCode(HcfResult res)
{
    if (RESULT_CODE.count(res) > 0) {
        return RESULT_CODE.at(res);
    }
    return ERR_RUNTIME_ERROR;
}

template<typename T>
void ArrayU8ToDataBlob(const T &arr, HcfBlob &blob)
{
    blob.data = arr.empty() ? nullptr : arr.data();
    blob.len = arr.size();
}

void DataBlobToArrayU8(const HcfBlob &blob, array<uint8_t> &arr)
{
    arr = array<uint8_t>(move_data_t{}, blob.data, blob.len);
}

template<typename T>
bool ArrayU8ToBigInteger(const T &arr, HcfBigInteger &bigint)
{
    if (arr.empty()) {
        return false;
    }
    uint8_t sign = arr.back() >> (sizeof(uint8_t) * 8 - 1);
    if (sign != 0) { // not support negative of big integer
        return false;
    }
    bigint.data = arr.data();
    bigint.len = arr.size();
    if (bigint.len > 1 && bigint.data[bigint.len - 1] == 0) { // remove the sign bit of big integer
        bigint.len--;
    }
    return true;
}

void BigIntegerToArrayU8(const HcfBigInteger &bigint, array<uint8_t> &arr)
{
    arr = array<uint8_t>(bigint.len + 1, 0);
    std::copy(bigint.data, bigint.data + bigint.len, arr.data());
    // 0x00 is the sign bit of big integer, it's always a positive number in this implementation
    arr[bigint.len] = 0x00;
}

void StringToDataBlob(const string &str, HcfBlob &blob)
{
    blob.data = str.empty() ? nullptr : reinterpret_cast<uint8_t *>(const_cast<char *>(str.c_str()));
    blob.len = str.empty() ? 0 : str.size() + 1;
}

int GetAsyKeySpecType(HcfAsyKeySpecItem item)
{
    if (ASY_KEY_SPEC_RELATION_MAP.count(item) > 0) {
        return ASY_KEY_SPEC_RELATION_MAP.at(item);
    }
    return -1;
}

int GetSignSpecType(HcfSignSpecItem item)
{
    if (SIGN_SPEC_RELATION_MAP.count(item) > 0) {
        return SIGN_SPEC_RELATION_MAP.at(item);
    }
    return -1;
}
} // namespace ANI::CryptoFramework
