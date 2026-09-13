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

#include "ani_mac.h"
#include "detailed_hmac_params.h"
#include "detailed_cmac_params.h"

namespace {
using namespace ANI::CryptoFramework;

const std::string HMAC_ALG_NAME = "HMAC";
const std::string CMAC_ALG_NAME = "CMAC";

Mac CreateMacInner(HcfMacParamsSpec *spec)
{
    HcfMac *mac = nullptr;
    HcfResult res = HcfMacCreate(spec, &mac);
    if (res != HCF_SUCCESS) {
        ANI_LOGE_THROW(res, "create mac obj failed.");
        return make_holder<MacImpl, Mac>();
    }
    return make_holder<MacImpl, Mac>(mac);
}
} // namespace

namespace ANI::CryptoFramework {
MacImpl::MacImpl() {}

MacImpl::MacImpl(HcfMac *mac) : mac_(mac) {}

MacImpl::~MacImpl()
{
    HcfObjDestroy(this->mac_);
    this->mac_ = nullptr;
}

void MacImpl::InitSync(weak::SymKey key)
{
    if (this->mac_ == nullptr) {
        ANI_LOGE_THROW(HCF_ERR_ANI, "mac obj is nullptr!");
        return;
    }
    HcfSymKey *hcfSymKey = reinterpret_cast<HcfSymKey *>(key->GetSymKeyObj());
    HcfResult res = this->mac_->init(this->mac_, hcfSymKey);
    if (res != HCF_SUCCESS) {
        ANI_LOGE_THROW(res, "mac init failed!");
        return;
    }
}

void MacImpl::UpdateSync(DataBlob const& input)
{
    if (this->mac_ == nullptr) {
        ANI_LOGE_THROW(HCF_ERR_ANI, "mac obj is nullptr!");
        return;
    }
    HcfBlob inBlob = {};
    ArrayU8ToDataBlob(input.data, inBlob);
    HcfResult res = this->mac_->update(this->mac_, &inBlob);
    if (res != HCF_SUCCESS) {
        ANI_LOGE_THROW(res, "mac update failed!");
        return;
    }
}

DataBlob MacImpl::DoFinalSync()
{
    if (this->mac_ == nullptr) {
        ANI_LOGE_THROW(HCF_ERR_ANI, "mac obj is nullptr!");
        return {};
    }
    HcfBlob outBlob = {};
    HcfResult res = this->mac_->doFinal(this->mac_, &outBlob);
    if (res != HCF_SUCCESS) {
        ANI_LOGE_THROW(res, "mac doFinal failed!");
        return {};
    }
    array<uint8_t> data = {};
    DataBlobToArrayU8(outBlob, data);
    HcfBlobDataClearAndFree(&outBlob);
    return { data };
}

int32_t MacImpl::GetMacLength()
{
    if (this->mac_ == nullptr) {
        ANI_LOGE_THROW(HCF_ERR_ANI, "mac obj is nullptr!");
        return 0;
    }
    uint32_t length = this->mac_->getMacLength(this->mac_);
    return static_cast<int32_t>(length);
}

string MacImpl::GetAlgName()
{
    if (this->mac_ == nullptr) {
        ANI_LOGE_THROW(HCF_ERR_ANI, "mac obj is nullptr!");
        return "";
    }
    const char *algName = this->mac_->getAlgoName(this->mac_);
    return (algName == nullptr) ? "" : string(algName);
}

Mac CreateMacByStr(string_view algName)
{
    HcfHmacParamsSpec spec = {};
    spec.base.algName = HMAC_ALG_NAME.c_str();
    spec.mdName = algName.c_str();
    return CreateMacInner(reinterpret_cast<HcfMacParamsSpec *>(&spec));
}

Mac CreateMacBySpec(OptExtMacSpec const& macSpec)
{
    HcfMacParamsSpec *spec = nullptr;
    HcfHmacParamsSpec hmacSpec = {};
    HcfCmacParamsSpec cmacSpec = {};
    const std::string &algName = macSpec.get_MACSPEC_ref().algName.c_str();
    if (macSpec.get_tag() == OptExtMacSpec::tag_t::HMACSPEC && algName == HMAC_ALG_NAME) {
        hmacSpec.base.algName = algName.c_str();
        hmacSpec.mdName = macSpec.get_HMACSPEC_ref().mdName.c_str();
        spec = reinterpret_cast<HcfMacParamsSpec *>(&hmacSpec);
    } else if (macSpec.get_tag() == OptExtMacSpec::tag_t::CMACSPEC && algName == CMAC_ALG_NAME) {
        cmacSpec.base.algName = algName.c_str();
        cmacSpec.cipherName = macSpec.get_CMACSPEC_ref().cipherName.c_str();
        spec = reinterpret_cast<HcfMacParamsSpec *>(&cmacSpec);
    } else {
        ANI_LOGE_THROW(HCF_INVALID_PARAMS, "invalid mac spec!");
        return make_holder<MacImpl, Mac>();
    }
    return CreateMacInner(spec);
}
} // namespace ANI::CryptoFramework

// Since these macros are auto-generate, lint will cause false positive.
// NOLINTBEGIN
TH_EXPORT_CPP_API_CreateMacByStr(ANI::CryptoFramework::CreateMacByStr);
TH_EXPORT_CPP_API_CreateMacBySpec(ANI::CryptoFramework::CreateMacBySpec);
// NOLINTEND
