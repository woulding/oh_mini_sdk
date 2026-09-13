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

#include "ani_verify.h"
#include "ani_pub_key.h"

namespace {
using namespace ANI::CryptoFramework;

void SetVerifySpecInt(HcfVerify *verify, HcfSignSpecItem item, int32_t saltLen)
{
    HcfResult res = verify->setVerifySpecInt(verify, item, saltLen);
    if (res != HCF_SUCCESS) {
        ANI_LOGE_THROW(res, "set verify spec int fail.");
        return;
    }
}

void SetVerifySpecUint8Array(HcfVerify *verify, HcfSignSpecItem item, const array<uint8_t> &data)
{
    HcfBlob inBlob = {};
    ArrayU8ToDataBlob(data, inBlob);
    HcfResult res = verify->setVerifySpecUint8Array(verify, item, inBlob);
    if (res != HCF_SUCCESS) {
        ANI_LOGE_THROW(res, "set verify spec uint8 array fail.");
        return;
    }
}

void SetVerifySpecBool(HcfVerify *verify, HcfSignSpecItem item, bool flag)
{
    HcfResult res = verify->setVerifySpecBool(verify, item, flag);
    if (res != HCF_SUCCESS) {
        ANI_LOGE_THROW(res, "set verify spec bool fail.");
        return;
    }
}

OptStrInt GetVerifySpecString(HcfVerify *verify, HcfSignSpecItem item)
{
    char *str = nullptr;
    HcfResult res = verify->getVerifySpecString(verify, item, &str);
    if (res != HCF_SUCCESS) {
        ANI_LOGE_THROW(res, "get verify spec string fail.");
        return OptStrInt::make_STRING("");
    }
    string data = string(str);
    HCF_FREE_PTR(str);
    return OptStrInt::make_STRING(data);
}

OptStrInt GetVerifySpecNumber(HcfVerify *verify, HcfSignSpecItem item)
{
    int num = 0;
    HcfResult res = verify->getVerifySpecInt(verify, item, &num);
    if (res != HCF_SUCCESS) {
        ANI_LOGE_THROW(res, "get verify spec number fail.");
        return OptStrInt::make_INT32(-1);
    }
    return OptStrInt::make_INT32(num);
}
} // namespace

namespace ANI::CryptoFramework {
VerifyImpl::VerifyImpl() {}

VerifyImpl::VerifyImpl(HcfVerify *verify) : verify_(verify) {}

VerifyImpl::~VerifyImpl()
{
    HcfObjDestroy(this->verify_);
    this->verify_ = nullptr;
}

void VerifyImpl::InitSync(weak::PubKey pubKey)
{
    if (this->verify_ == nullptr) {
        ANI_LOGE_THROW(HCF_ERR_ANI, "verify obj is nullptr!");
        return;
    }
    HcfPubKey *hcfPubKey = reinterpret_cast<HcfPubKey *>(pubKey->GetPubKeyObj());
    HcfResult res = this->verify_->init(this->verify_, nullptr, hcfPubKey);
    if (res != HCF_SUCCESS) {
        ANI_LOGE_THROW(res, "verify init failed.");
        return;
    }
}

void VerifyImpl::UpdateSync(DataBlob const& input)
{
    if (this->verify_ == nullptr) {
        ANI_LOGE_THROW(HCF_ERR_ANI, "verify obj is nullptr!");
        return;
    }
    HcfBlob inBlob = {};
    ArrayU8ToDataBlob(input.data, inBlob);
    HcfResult res = this->verify_->update(this->verify_, &inBlob);
    if (res != HCF_SUCCESS) {
        ANI_LOGE_THROW(res, "verify update failed!");
        return;
    }
}

bool VerifyImpl::VerifySync(OptDataBlob const& data, DataBlob const& signature)
{
    if (this->verify_ == nullptr) {
        ANI_LOGE_THROW(HCF_ERR_ANI, "verify obj is nullptr!");
        return false;
    }
    HcfBlob *inBlob = nullptr;
    HcfBlob dataBlob = {};
    if (data.get_tag() == OptDataBlob::tag_t::DATABLOB) {
        ArrayU8ToDataBlob(data.get_DATABLOB_ref().data, dataBlob);
        inBlob = &dataBlob;
    }
    HcfBlob signData = {};
    ArrayU8ToDataBlob(signature.data, signData);
    bool res = this->verify_->verify(this->verify_, inBlob, &signData);
    if (!res) {
        LOGE("verify doFinal failed.");
        return false;
    }
    return true;
}

OptDataBlob VerifyImpl::RecoverSync(DataBlob const& signature)
{
    if (this->verify_ == nullptr) {
        ANI_LOGE_THROW(HCF_ERR_ANI, "verify obj is nullptr!");
        return OptDataBlob::make_EMPTY();
    }
    HcfBlob inBlob = {};
    HcfBlob outBlob = {};
    ArrayU8ToDataBlob(signature.data, inBlob);
    HcfResult res = this->verify_->recover(this->verify_, &inBlob, &outBlob);
    if (res != HCF_SUCCESS) {
        ANI_LOGE_THROW(res, "verify recover failed!");
        return OptDataBlob::make_EMPTY();
    }
    array<uint8_t> data = {};
    DataBlobToArrayU8(outBlob, data);
    HcfBlobDataClearAndFree(&outBlob);
    if (data.empty()) {
        return OptDataBlob::make_EMPTY();
    }
    return OptDataBlob::make_DATABLOB(DataBlob({ data }));
}

void VerifyImpl::SetVerifySpec(ThSignSpecItem itemType, OptIntUint8Arr const& itemValue)
{
    if (this->verify_ == nullptr) {
        ANI_LOGE_THROW(HCF_ERR_ANI, "verify obj is nullptr!");
        return;
    }

    HcfSignSpecItem item = static_cast<HcfSignSpecItem>(itemType.get_value());
    if (itemValue.get_tag() == OptIntUint8Arr::tag_t::INT32 && item == PSS_SALT_LEN_INT) {
        return SetVerifySpecInt(this->verify_, item, itemValue.get_INT32_ref());
    } else if (itemValue.get_tag() == OptIntUint8Arr::tag_t::UINT8ARRAY &&
        (item == SM2_USER_ID_UINT8ARR || item == ML_DSA_CONTEXT_UINT8ARR)) {
        return SetVerifySpecUint8Array(this->verify_, item, itemValue.get_UINT8ARRAY_ref());
    } else {
        ANI_LOGE_THROW(HCF_INVALID_PARAMS, "verify spec item not support!");
        return;
    }
}

void VerifyImpl::SetVerifySpecBoolean(ThSignSpecItem itemType, bool itemValue)
{
    if (this->verify_ == nullptr) {
        ANI_LOGE_THROW(HCF_ERR_ANI, "verify obj is nullptr!");
        return;
    }
    HcfSignSpecItem item = static_cast<HcfSignSpecItem>(itemType.get_value());
    if (item == ML_DSA_DETERMINISTIC_BOOL || item == ML_DSA_MU_BOOL) {
        return SetVerifySpecBool(this->verify_, item, itemValue);
    } else {
        ANI_LOGE_THROW(HCF_INVALID_PARAMS, "verify spec item not support!");
        return;
    }
}

OptStrInt VerifyImpl::GetVerifySpec(ThSignSpecItem itemType)
{
    if (this->verify_ == nullptr) {
        ANI_LOGE_THROW(HCF_ERR_ANI, "verify obj is nullptr!");
        return OptStrInt::make_INT32(-1);
    }
    HcfSignSpecItem item = static_cast<HcfSignSpecItem>(itemType.get_value());
    int32_t type = GetSignSpecType(item);
    if (type == SPEC_ITEM_TYPE_STR) {
        return GetVerifySpecString(this->verify_, item);
    } else if (type == SPEC_ITEM_TYPE_NUM) {
        return GetVerifySpecNumber(this->verify_, item);
    } else {
        HcfResult res = HCF_INVALID_PARAMS;
        if (this->GetAlgName() == "ML-DSA") {
            res = HCF_ERR_INVALID_CALL;
        }
        ANI_LOGE_THROW(res, "verify spec item not support!");
        return OptStrInt::make_INT32(-1);
    }
}

string VerifyImpl::GetAlgName()
{
    if (this->verify_ == nullptr) {
        ANI_LOGE_THROW(HCF_ERR_ANI, "verify obj is nullptr!");
        return "";
    }
    const char *algName = this->verify_->getAlgoName(this->verify_);
    return (algName == nullptr) ? "" : string(algName);
}

Verify CreateVerify(string_view algName)
{
    HistogramScopeGuard guard(API_CREATE_VERIFY);
    if (!IsPqcSignVerifyAlgorithm(algName.c_str())) {
        guard.DisableScopeGuard();
    }
    HcfVerify *verify = nullptr;
    HcfResult res = HcfVerifyCreate(algName.c_str(), &verify);
    if (res != HCF_SUCCESS) {
        guard.SetErrorCode(res);
        ANI_LOGE_THROW(res, "create verify obj fail!");
        return make_holder<VerifyImpl, Verify>();
    }
    return make_holder<VerifyImpl, Verify>(verify);
}
} // namespace ANI::CryptoFramework

// Since these macros are auto-generate, lint will cause false positive.
// NOLINTBEGIN
TH_EXPORT_CPP_API_CreateVerify(ANI::CryptoFramework::CreateVerify);
// NOLINTEND
