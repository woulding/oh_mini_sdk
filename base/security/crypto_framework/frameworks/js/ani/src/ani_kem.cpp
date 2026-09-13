/*
 * Copyright (c) 2026-2026 Huawei Device Co., Ltd.
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

#include "ani_kem.h"

namespace {
using namespace ANI::CryptoFramework;
} // namespace

namespace ANI::CryptoFramework {
KemImpl::KemImpl() {}

KemImpl::KemImpl(HcfKem *kem) : kem_(kem) {}

KemImpl::~KemImpl()
{
    HcfObjDestroy(this->kem_);
    this->kem_ = nullptr;
}

KemEncapResult KemImpl::EncapsulateSync(weak::PubKey pubKey, OptUint8Arr const& ikme)
{
    HistogramScopeGuard guard(API_KEM_ENCAPSULATE_SYNC);
    if (this->kem_ == nullptr) {
        guard.SetErrorCode(HCF_ERR_ANI);
        ANI_LOGE_THROW(HCF_ERR_ANI, "kem obj is nullptr!");
        return {};
    }
    HcfPubKey *hcfPubKey = reinterpret_cast<HcfPubKey *>(pubKey->GetPubKeyObj());
    HcfBlob ikmeBlob = {};
    HcfBlob *ikmePtr = nullptr;
    if (ikme.get_tag() == OptUint8Arr::tag_t::UINT8ARRAY) {
        ArrayU8ToDataBlob(ikme.get_UINT8ARRAY_ref(), ikmeBlob);
        ikmePtr = &ikmeBlob;
    }
    HcfBlob sharedSecret = {};
    HcfBlob wrappedKey = {};
    HcfResult res = this->kem_->encapsulate(this->kem_, hcfPubKey, ikmePtr, &sharedSecret, &wrappedKey);
    if (res != HCF_SUCCESS) {
        guard.SetErrorCode(res);
        ANI_LOGE_THROW(res, "kem encapsulate failed.");
        return {};
    }
    array<uint8_t> secretData = {};
    array<uint8_t> wrappedData = {};
    DataBlobToArrayU8(sharedSecret, secretData);
    DataBlobToArrayU8(wrappedKey, wrappedData);
    HcfBlobDataClearAndFree(&sharedSecret);
    HcfBlobDataClearAndFree(&wrappedKey);
    return { secretData, wrappedData };
}

array<uint8_t> KemImpl::DecapsulateSync(weak::PriKey priKey, array_view<uint8_t> wrappedKey)
{
    HistogramScopeGuard guard(API_KEM_DECAPSULATE_SYNC);
    if (this->kem_ == nullptr) {
        guard.SetErrorCode(HCF_ERR_ANI);
        ANI_LOGE_THROW(HCF_ERR_ANI, "kem obj is nullptr!");
        return {};
    }
    HcfPriKey *hcfPriKey = reinterpret_cast<HcfPriKey *>(priKey->GetPriKeyObj());
    HcfBlob wrappedKeyBlob = {};
    ArrayU8ToDataBlob(wrappedKey, wrappedKeyBlob);
    HcfBlob sharedSecret = {};
    HcfResult res = this->kem_->decapsulate(this->kem_, hcfPriKey, &wrappedKeyBlob, &sharedSecret);
    if (res != HCF_SUCCESS) {
        guard.SetErrorCode(res);
        ANI_LOGE_THROW(res, "kem decapsulate failed.");
        return {};
    }
    array<uint8_t> secretData = {};
    DataBlobToArrayU8(sharedSecret, secretData);
    HcfBlobDataClearAndFree(&sharedSecret);
    return secretData;
}

static const char *GetKemAlgoNameById(KemAlgNameId algId)
{
    HcfKemAlgNameId id = static_cast<HcfKemAlgNameId>(algId.get_value());
    switch (id) {
        case ML_KEM_512:
            return "ML-KEM512";
        case ML_KEM_768:
            return "ML-KEM768";
        case ML_KEM_1024:
            return "ML-KEM1024";
        default:
            return nullptr;
    }
}

Kem CreateKem(KemAlgNameId algNameId)
{
    HistogramScopeGuard guard(API_CREATE_KEM);
    const char *algName = GetKemAlgoNameById(algNameId);
    if (algName == nullptr) {
        guard.SetErrorCode(HCF_ERR_PARAMETER_CHECK_FAILED);
        ANI_LOGE_THROW(HCF_ERR_PARAMETER_CHECK_FAILED, "Unsupported kem alg id.");
        return make_holder<KemImpl, Kem>();
    }
    HcfKem *kem = nullptr;
    HcfResult res = HcfKemCreate(algName, &kem);
    if (res != HCF_SUCCESS) {
        guard.SetErrorCode(res);
        ANI_LOGE_THROW(res, "create kem obj failed.");
        return make_holder<KemImpl, Kem>();
    }
    return make_holder<KemImpl, Kem>(kem);
}
} // namespace ANI::CryptoFramework

// Since these macros are auto-generate, lint will cause false positive.
// NOLINTBEGIN
TH_EXPORT_CPP_API_CreateKem(ANI::CryptoFramework::CreateKem);
// NOLINTEND
