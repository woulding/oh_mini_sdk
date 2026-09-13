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

#include "ani_key_agreement.h"

namespace ANI::CryptoFramework {
KeyAgreementImpl::KeyAgreementImpl() {}

KeyAgreementImpl::KeyAgreementImpl(HcfKeyAgreement *keyAgreement) : keyAgreement_(keyAgreement) {}

KeyAgreementImpl::~KeyAgreementImpl()
{
    HcfObjDestroy(this->keyAgreement_);
    this->keyAgreement_ = nullptr;
}

DataBlob KeyAgreementImpl::GenerateSecretSync(weak::PriKey priKey, weak::PubKey pubKey)
{
    if (this->keyAgreement_ == nullptr) {
        ANI_LOGE_THROW(HCF_ERR_ANI, "keyAgreement obj is nullptr!");
        return {};
    }
    HcfPriKey *hcfPriKey = reinterpret_cast<HcfPriKey *>(priKey->GetPriKeyObj());
    HcfPubKey *hcfPubKey = reinterpret_cast<HcfPubKey *>(pubKey->GetPubKeyObj());
    HcfBlob outBlob = {};
    HcfResult res = this->keyAgreement_->generateSecret(this->keyAgreement_, hcfPriKey, hcfPubKey, &outBlob);
    if (res != HCF_SUCCESS) {
        ANI_LOGE_THROW(res, "keyAgreement generateSecret fail.");
        return {};
    }
    array<uint8_t> data = {};
    DataBlobToArrayU8(outBlob, data);
    HcfBlobDataClearAndFree(&outBlob);
    return { data };
}

string KeyAgreementImpl::GetAlgName()
{
    if (this->keyAgreement_ == nullptr) {
        ANI_LOGE_THROW(HCF_ERR_ANI, "keyAgreement obj is nullptr!");
        return "";
    }
    const char *algName = this->keyAgreement_->getAlgoName(this->keyAgreement_);
    return (algName == nullptr) ? "" : string(algName);
}

KeyAgreement CreateKeyAgreement(string_view algName)
{
    HcfKeyAgreement *keyAgreement = nullptr;
    HcfResult res = HcfKeyAgreementCreate(algName.c_str(), &keyAgreement);
    if (res != HCF_SUCCESS) {
        ANI_LOGE_THROW(res, "create keyAgreement obj fail.");
        return make_holder<KeyAgreementImpl, KeyAgreement>();
    }
    return make_holder<KeyAgreementImpl, KeyAgreement>(keyAgreement);
}
} // namespace ANI::CryptoFramework

// Since these macros are auto-generate, lint will cause false positive.
// NOLINTBEGIN
TH_EXPORT_CPP_API_CreateKeyAgreement(ANI::CryptoFramework::CreateKeyAgreement);
// NOLINTEND
