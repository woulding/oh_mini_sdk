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

#include "ani_sign.h"

namespace {
using namespace ANI::CryptoFramework;

void SetSignSpecInt(HcfSign *sign, HcfSignSpecItem item, int32_t saltLen)
{
    HcfResult res = sign->setSignSpecInt(sign, item, saltLen);
    if (res != HCF_SUCCESS) {
        ANI_LOGE_THROW(res, "set sign spec int fail.");
        return;
    }
}

void SetSignSpecUint8Array(HcfSign *sign, HcfSignSpecItem item, const array<uint8_t> &data)
{
    HcfBlob inBlob = {};
    ArrayU8ToDataBlob(data, inBlob);
    HcfResult res = sign->setSignSpecUint8Array(sign, item, inBlob);
    if (res != HCF_SUCCESS) {
        ANI_LOGE_THROW(res, "set sign spec uint8 array fail.");
        return;
    }
}

void SetSignSpecBool(HcfSign *sign, HcfSignSpecItem item, bool flag)
{
    HcfResult res = sign->setSignSpecBool(sign, item, flag);
    if (res != HCF_SUCCESS) {
        ANI_LOGE_THROW(res, "set sign spec bool fail.");
        return;
    }
}

OptStrInt GetSignSpecString(HcfSign *sign, HcfSignSpecItem item)
{
    char *str = nullptr;
    HcfResult res = sign->getSignSpecString(sign, item, &str);
    if (res != HCF_SUCCESS) {
        ANI_LOGE_THROW(res, "get sign spec string fail.");
        return OptStrInt::make_STRING("");
    }
    string data = string(str);
    HCF_FREE_PTR(str);
    return OptStrInt::make_STRING(data);
}

OptStrInt GetSignSpecNumber(HcfSign *sign, HcfSignSpecItem item)
{
    int num = 0;
    HcfResult res = sign->getSignSpecInt(sign, item, &num);
    if (res != HCF_SUCCESS) {
        ANI_LOGE_THROW(res, "get sign spec number fail.");
        return OptStrInt::make_INT32(-1);
    }
    return OptStrInt::make_INT32(num);
}
} // namespace

namespace ANI::CryptoFramework {
SignImpl::SignImpl() {}

SignImpl::SignImpl(HcfSign *sign) : sign_(sign) {}

SignImpl::~SignImpl()
{
    HcfObjDestroy(this->sign_);
    this->sign_ = nullptr;
}

void SignImpl::InitSync(weak::PriKey priKey)
{
    if (this->sign_ == nullptr) {
        ANI_LOGE_THROW(HCF_ERR_ANI, "sign obj is nullptr!");
        return;
    }
    HcfPriKey *hcfPriKey = reinterpret_cast<HcfPriKey *>(priKey->GetPriKeyObj());
    HcfResult res = this->sign_->init(this->sign_, nullptr, hcfPriKey);
    if (res != HCF_SUCCESS) {
        ANI_LOGE_THROW(res, "sign init failed.");
        return;
    }
}

void SignImpl::UpdateSync(DataBlob const& data)
{
    if (this->sign_ == nullptr) {
        ANI_LOGE_THROW(HCF_ERR_ANI, "sign obj is nullptr!");
        return;
    }
    HcfBlob inBlob = {};
    ArrayU8ToDataBlob(data.data, inBlob);
    HcfResult res = this->sign_->update(this->sign_, &inBlob);
    if (res != HCF_SUCCESS) {
        ANI_LOGE_THROW(res, "sign update failed!");
        return;
    }
}

DataBlob SignImpl::SignSync(OptDataBlob const& data)
{
    if (this->sign_ == nullptr) {
        ANI_LOGE_THROW(HCF_ERR_ANI, "sign obj is nullptr!");
        return {};
    }
    HcfBlob *inBlob = nullptr;
    HcfBlob dataBlob = {};
    if (data.get_tag() == OptDataBlob::tag_t::DATABLOB) {
        ArrayU8ToDataBlob(data.get_DATABLOB_ref().data, dataBlob);
        inBlob = &dataBlob;
    }
    HcfBlob outBlob = {};
    HcfResult res = this->sign_->sign(this->sign_, inBlob, &outBlob);
    if (res != HCF_SUCCESS) {
        ANI_LOGE_THROW(res, "sign doFinal failed!");
        return {};
    }
    array<uint8_t> out = {};
    DataBlobToArrayU8(outBlob, out);
    HcfBlobDataClearAndFree(&outBlob);
    return { out };
}

void SignImpl::SetSignSpec(ThSignSpecItem itemType, OptIntUint8Arr const& itemValue)
{
    if (this->sign_ == nullptr) {
        ANI_LOGE_THROW(HCF_ERR_ANI, "sign obj is nullptr!");
        return;
    }
    HcfSignSpecItem item = static_cast<HcfSignSpecItem>(itemType.get_value());
    if (itemValue.get_tag() == OptIntUint8Arr::tag_t::INT32 && item == PSS_SALT_LEN_INT) {
        return SetSignSpecInt(this->sign_, item, itemValue.get_INT32_ref());
    } else if (itemValue.get_tag() == OptIntUint8Arr::tag_t::UINT8ARRAY &&
        (item == SM2_USER_ID_UINT8ARR || item == ML_DSA_CONTEXT_UINT8ARR)) {
        return SetSignSpecUint8Array(this->sign_, item, itemValue.get_UINT8ARRAY_ref());
    } else {
        ANI_LOGE_THROW(HCF_INVALID_PARAMS, "sign spec item not support!");
        return;
    }
}

void SignImpl::SetSignSpecBoolean(ThSignSpecItem itemType, bool itemValue)
{
    if (this->sign_ == nullptr) {
        ANI_LOGE_THROW(HCF_ERR_ANI, "sign obj is nullptr!");
        return;
    }
    HcfSignSpecItem item = static_cast<HcfSignSpecItem>(itemType.get_value());
    if (item == ML_DSA_DETERMINISTIC_BOOL || item == ML_DSA_MU_BOOL) {
        return SetSignSpecBool(this->sign_, item, itemValue);
    } else {
        ANI_LOGE_THROW(HCF_INVALID_PARAMS, "sign spec item not support!");
        return;
    }
}

OptStrInt SignImpl::GetSignSpec(ThSignSpecItem itemType)
{
    if (this->sign_ == nullptr) {
        ANI_LOGE_THROW(HCF_ERR_ANI, "sign obj is nullptr!");
        return OptStrInt::make_INT32(-1);
    }
    HcfSignSpecItem item = static_cast<HcfSignSpecItem>(itemType.get_value());
    int32_t type = GetSignSpecType(item);
    if (type == SPEC_ITEM_TYPE_STR) {
        return GetSignSpecString(this->sign_, item);
    } else if (type == SPEC_ITEM_TYPE_NUM) {
        return GetSignSpecNumber(this->sign_, item);
    } else {
        HcfResult res = HCF_INVALID_PARAMS;
        if (this->GetAlgName() == "ML-DSA") {
            res = HCF_ERR_INVALID_CALL;
        }
        ANI_LOGE_THROW(res, "sign spec item not support!");
        return OptStrInt::make_INT32(-1);
    }
}

string SignImpl::GetAlgName()
{
    if (this->sign_ == nullptr) {
        ANI_LOGE_THROW(HCF_ERR_ANI, "sign obj is nullptr!");
        return "";
    }
    const char *algName = this->sign_->getAlgoName(this->sign_);
    return (algName == nullptr) ? "" : string(algName);
}

Sign CreateSign(string_view algName)
{
    HistogramScopeGuard guard(API_CREATE_SIGN);
    if (!IsPqcSignVerifyAlgorithm(algName.c_str())) {
        guard.DisableScopeGuard();
    }
    HcfSign *sign = nullptr;
    HcfResult res = HcfSignCreate(algName.c_str(), &sign);
    if (res != HCF_SUCCESS) {
        guard.SetErrorCode(HCF_INVALID_PARAMS);
        ANI_LOGE_THROW(HCF_INVALID_PARAMS, "create sign obj fail!");
        return make_holder<SignImpl, Sign>();
    }
    return make_holder<SignImpl, Sign>(sign);
}
} // namespace ANI::CryptoFramework

// Since these macros are auto-generate, lint will cause false positive.
// NOLINTBEGIN
TH_EXPORT_CPP_API_CreateSign(ANI::CryptoFramework::CreateSign);
// NOLINTEND
