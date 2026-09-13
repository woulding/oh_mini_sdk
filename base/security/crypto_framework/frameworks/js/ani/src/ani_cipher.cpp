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

#include "ani_cipher.h"
#include "detailed_iv_params.h"
#include "detailed_gcm_params.h"
#include "detailed_ccm_params.h"
#include "detailed_chacha20_params.h"
#include "detailed_aead_params.h"

namespace {
using namespace ANI::CryptoFramework;

const std::string IV_PARAMS_SPEC = "IvParamsSpec";
const std::string GCM_PARAMS_SPEC = "GcmParamsSpec";
const std::string CCM_PARAMS_SPEC = "CcmParamsSpec";
const std::string POLY1305_PARAMS_SPEC = "Poly1305ParamsSpec";
const std::string AEAD_PARAMS_SPEC = "AeadParamsSpec";

static const std::unordered_map<HcfCipherSpecItem, int> CIPHER_SPEC_RELATION_MAP = {
    { OAEP_MD_NAME_STR, SPEC_ITEM_TYPE_STR },
    { OAEP_MGF_NAME_STR, SPEC_ITEM_TYPE_STR },
    { OAEP_MGF1_MD_STR, SPEC_ITEM_TYPE_STR },
    { OAEP_MGF1_PSRC_UINT8ARR, SPEC_ITEM_TYPE_UINT8ARR },
    { SM2_MD_NAME_STR, SPEC_ITEM_TYPE_STR },
};

const char *GetIvParamsSpecType()
{
    return IV_PARAMS_SPEC.c_str();
}

const char *GetGcmParamsSpecType()
{
    return GCM_PARAMS_SPEC.c_str();
}

const char *GetCcmParamsSpecType()
{
    return CCM_PARAMS_SPEC.c_str();
}

const char *GetPoly1305ParamsSpecType()
{
    return POLY1305_PARAMS_SPEC.c_str();
}

const char *GetAeadParamsSpecType()
{
    return AEAD_PARAMS_SPEC.c_str();
}

void SetIvParamsSpecAttribute(const IvParamsSpec &params, HcfIvParamsSpec &ivParamsSpec)
{
    ivParamsSpec.base.getType = GetIvParamsSpecType;
    ArrayU8ToDataBlob(params.iv.data, ivParamsSpec.iv);
}

void SetGcmParamsSpecAttribute(const GcmParamsSpec &params, HcfGcmParamsSpec &gcmParamsSpec)
{
    gcmParamsSpec.base.getType = GetGcmParamsSpecType;
    ArrayU8ToDataBlob(params.iv.data, gcmParamsSpec.iv);
    ArrayU8ToDataBlob(params.aad.data, gcmParamsSpec.aad);
    ArrayU8ToDataBlob(params.authTag.data, gcmParamsSpec.tag);
}

void SetCcmParamsSpecAttribute(const CcmParamsSpec &params, HcfCcmParamsSpec &ccmParamsSpec)
{
    ccmParamsSpec.base.getType = GetCcmParamsSpecType;
    ArrayU8ToDataBlob(params.iv.data, ccmParamsSpec.iv);
    ArrayU8ToDataBlob(params.aad.data, ccmParamsSpec.aad);
    ArrayU8ToDataBlob(params.authTag.data, ccmParamsSpec.tag);
}

void SetPoly1305ParamsSpecAttribute(const Poly1305ParamsSpec &params, HcfChaCha20ParamsSpec &poly1305ParamsSpec)
{
    poly1305ParamsSpec.base.getType = GetPoly1305ParamsSpecType;
    ArrayU8ToDataBlob(params.iv.data, poly1305ParamsSpec.iv);
    ArrayU8ToDataBlob(params.aad.data, poly1305ParamsSpec.aad);
    ArrayU8ToDataBlob(params.authTag.data, poly1305ParamsSpec.tag);
}

void SetAeadParamsSpecAttribute(const AeadParamsSpec &params, HcfAeadParamsSpec &aeadParamsSpec)
{
    aeadParamsSpec.base.getType = GetAeadParamsSpecType;
    ArrayU8ToDataBlob(params.nonce, aeadParamsSpec.nonce);
    if (params.authenticatedData.has_value()) {
        ArrayU8ToDataBlob(params.authenticatedData.value(), aeadParamsSpec.aad);
    } else {
        aeadParamsSpec.aad.data = nullptr;
        aeadParamsSpec.aad.len = 0;
    }
    aeadParamsSpec.tagLen = params.tagLen.has_value() ? params.tagLen.value() : 0;
}

int32_t GetCipherSpecType(HcfCipherSpecItem item)
{
    if (CIPHER_SPEC_RELATION_MAP.count(item) > 0) {
        return CIPHER_SPEC_RELATION_MAP.at(item);
    }
    return -1;
}

OptStrUint8Arr GetCipherSpecString(HcfCipher *cipher, HcfCipherSpecItem item)
{
    char *str = nullptr;
    HcfResult res = cipher->getCipherSpecString(cipher, item, &str);
    if (res != HCF_SUCCESS) {
        ANI_LOGE_THROW(res, "get cipher spec string fail.");
        return OptStrUint8Arr::make_STRING("");
    }
    string data = string(str);
    HCF_FREE_PTR(str);
    return OptStrUint8Arr::make_STRING(data);
}

OptStrUint8Arr GetCipherSpecUint8Array(HcfCipher *cipher, HcfCipherSpecItem item)
{
    HcfBlob outBlob = {};
    HcfResult res = cipher->getCipherSpecUint8Array(cipher, item, &outBlob);
    if (res != HCF_SUCCESS) {
        ANI_LOGE_THROW(res, "get cipher spec uint8 array fail.");
        return OptStrUint8Arr::make_UINT8ARRAY(array<uint8_t>{});
    }
    array<uint8_t> data = {};
    DataBlobToArrayU8(outBlob, data);
    HcfBlobDataClearAndFree(&outBlob);
    return OptStrUint8Arr::make_UINT8ARRAY(data);
}
} // namespace

namespace ANI::CryptoFramework {
CipherImpl::CipherImpl() {}

CipherImpl::CipherImpl(HcfCipher *cipher) : cipher_(cipher) {}

CipherImpl::~CipherImpl()
{
    HcfObjDestroy(this->cipher_);
    this->cipher_ = nullptr;
}

void CipherImpl::InitSync(CryptoMode opMode, weak::Key key, OptParamsSpec const& params)
{
    if (this->cipher_ == nullptr) {
        ANI_LOGE_THROW(HCF_ERR_ANI, "cipher obj is nullptr!");
        return;
    }
    HcfParamsSpec *paramsSpec = nullptr;
    HcfIvParamsSpec ivParamsSpec = {};
    HcfGcmParamsSpec gcmParamsSpec = {};
    HcfCcmParamsSpec ccmParamsSpec = {};
    HcfChaCha20ParamsSpec poly1305ParamsSpec = {};
    HcfAeadParamsSpec aeadParamsSpec = {};
    if (params.get_tag() == OptParamsSpec::tag_t::PARAMSSPEC) { // params: ParamsSpec | null
        const OptExtParamsSpec &tmp = params.get_PARAMSSPEC_ref();
        const std::string &algName = tmp.get_PARAMSSPEC_ref().algName.c_str();
        if (tmp.get_tag() == OptExtParamsSpec::tag_t::IVPARAMSSPEC && algName == IV_PARAMS_SPEC) {
            SetIvParamsSpecAttribute(tmp.get_IVPARAMSSPEC_ref(), ivParamsSpec);
            paramsSpec = reinterpret_cast<HcfParamsSpec *>(&ivParamsSpec);
        } else if (tmp.get_tag() == OptExtParamsSpec::tag_t::GCMPARAMSSPEC && algName == GCM_PARAMS_SPEC) {
            SetGcmParamsSpecAttribute(tmp.get_GCMPARAMSSPEC_ref(), gcmParamsSpec);
            paramsSpec = reinterpret_cast<HcfParamsSpec *>(&gcmParamsSpec);
        } else if (tmp.get_tag() == OptExtParamsSpec::tag_t::CCMPARAMSSPEC && algName == CCM_PARAMS_SPEC) {
            SetCcmParamsSpecAttribute(tmp.get_CCMPARAMSSPEC_ref(), ccmParamsSpec);
            paramsSpec = reinterpret_cast<HcfParamsSpec *>(&ccmParamsSpec);
        } else if (tmp.get_tag() == OptExtParamsSpec::tag_t::POLY1305PARAMSSPEC && algName == POLY1305_PARAMS_SPEC) {
            SetPoly1305ParamsSpecAttribute(tmp.get_POLY1305PARAMSSPEC_ref(), poly1305ParamsSpec);
            paramsSpec = reinterpret_cast<HcfParamsSpec *>(&poly1305ParamsSpec);
        } else if (tmp.get_tag() == OptExtParamsSpec::tag_t::AEADPARAMSSPEC && algName == AEAD_PARAMS_SPEC) {
            SetAeadParamsSpecAttribute(tmp.get_AEADPARAMSSPEC_ref(), aeadParamsSpec);
            paramsSpec = reinterpret_cast<HcfParamsSpec *>(&aeadParamsSpec);
        } else {
            ANI_LOGE_THROW(HCF_INVALID_PARAMS, "invalid cipher spec!");
            return;
        }
    }
    HcfKey *hcfKey = reinterpret_cast<HcfKey *>(key->GetKeyObj());
    HcfResult res = this->cipher_->init(this->cipher_, static_cast<HcfCryptoMode>(opMode.get_value()),
        hcfKey, paramsSpec);
    if (res != HCF_SUCCESS) {
        ANI_LOGE_THROW(res, "init cipher fail.");
        return;
    }
}

OptDataBlob CipherImpl::UpdateSync(DataBlob const& input)
{
    if (this->cipher_ == nullptr) {
        ANI_LOGE_THROW(HCF_ERR_ANI, "cipher obj is nullptr!");
        return OptDataBlob::make_EMPTY();
    }
    HcfBlob inBlob = {};
    HcfBlob outBlob = {};
    ArrayU8ToDataBlob(input.data, inBlob);
    HcfResult res = this->cipher_->update(this->cipher_, &inBlob, &outBlob);
    if (res != HCF_SUCCESS) {
        ANI_LOGE_THROW(res, "cipher update failed!");
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

OptDataBlob CipherImpl::DoFinalSync(OptDataBlob const& input)
{
    if (this->cipher_ == nullptr) {
        ANI_LOGE_THROW(HCF_ERR_ANI, "cipher obj is nullptr!");
        return OptDataBlob::make_EMPTY();
    }
    HcfBlob *inBlob = nullptr;
    HcfBlob dataBlob = {};
    if (input.get_tag() == OptDataBlob::tag_t::DATABLOB) {
        ArrayU8ToDataBlob(input.get_DATABLOB_ref().data, dataBlob);
        inBlob = &dataBlob;
    }
    HcfBlob outBlob = {};
    HcfResult res = this->cipher_->doFinal(this->cipher_, inBlob, &outBlob);
    if (res != HCF_SUCCESS) {
        ANI_LOGE_THROW(res, "cipher doFinal failed!");
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

void CipherImpl::SetCipherSpec(ThCipherSpecItem itemType, array_view<uint8_t> itemValue)
{
    if (this->cipher_ == nullptr) {
        ANI_LOGE_THROW(HCF_ERR_ANI, "cipher obj is nullptr!");
        return;
    }
    HcfBlob inBlob = {};
    ArrayU8ToDataBlob(itemValue, inBlob);
    HcfCipherSpecItem item = static_cast<HcfCipherSpecItem>(itemType.get_value());
    HcfResult res = this->cipher_->setCipherSpecUint8Array(this->cipher_, item, inBlob);
    if (res != HCF_SUCCESS) {
        ANI_LOGE_THROW(res, "set cipher spec uint8 array failed.");
        return;
    }
}

OptStrUint8Arr CipherImpl::GetCipherSpec(ThCipherSpecItem itemType)
{
    if (this->cipher_ == nullptr) {
        ANI_LOGE_THROW(HCF_ERR_ANI, "cipher obj is nullptr!");
        return OptStrUint8Arr::make_STRING("");
    }
    HcfCipherSpecItem item = static_cast<HcfCipherSpecItem>(itemType.get_value());
    int32_t type = GetCipherSpecType(item);
    if (type == SPEC_ITEM_TYPE_STR) {
        return GetCipherSpecString(this->cipher_, item);
    } else if (type == SPEC_ITEM_TYPE_UINT8ARR) {
        return GetCipherSpecUint8Array(this->cipher_, item);
    } else {
        ANI_LOGE_THROW(HCF_INVALID_PARAMS, "cipher spec item not support!");
        return OptStrUint8Arr::make_STRING("");
    }
}

string CipherImpl::GetAlgName()
{
    if (this->cipher_ == nullptr) {
        ANI_LOGE_THROW(HCF_ERR_ANI, "cipher obj is nullptr!");
        return "";
    }
    const char *algName = this->cipher_->getAlgorithm(this->cipher_);
    return (algName == nullptr) ? "" : string(algName);
}

Cipher CreateCipher(string_view transformation)
{
    HcfCipher *cipher = nullptr;
    HcfResult res = HcfCipherCreate(transformation.c_str(), &cipher);
    if (res != HCF_SUCCESS) {
        ANI_LOGE_THROW(res, "create cipher obj fail!");
        return make_holder<CipherImpl, Cipher>();
    }
    return make_holder<CipherImpl, Cipher>(cipher);
}
} // namespace ANI::CryptoFramework

// Since these macros are auto-generate, lint will cause false positive.
// NOLINTBEGIN
TH_EXPORT_CPP_API_CreateCipher(ANI::CryptoFramework::CreateCipher);
// NOLINTEND
