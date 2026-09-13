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

#include "ani_kdf.h"
#include "detailed_pbkdf2_params.h"
#include "detailed_hkdf_params.h"
#include "detailed_scrypt_params.h"
#include "detailed_x963kdf_params.h"

namespace {
using namespace ANI::CryptoFramework;

const std::string PBKDF2_ALG_NAME = "PBKDF2";
const std::string HKDF_ALG_NAME = "HKDF";
const std::string SCRYPT_ALG_NAME = "SCRYPT";
const std::string X963KDF_ALG_NAME = "X963KDF";

bool SetPBKDF2ParamsSpecAttribute(const PBKDF2Spec &params, HcfPBKDF2ParamsSpec &pbkdf2Spec, HcfBlob &outBlob)
{
    if (params.keySize <= 0 || params.iterations <= 0) {
        return false;
    }
    pbkdf2Spec.base.algName = params.base.algName.c_str();
    if (params.password.get_tag() == OptStrUint8Arr::tag_t::STRING) {
        StringToDataBlob(params.password.get_STRING_ref(), pbkdf2Spec.password);
    } else { // OptStrUint8Arr::tag_t::UINT8ARRAY
        ArrayU8ToDataBlob(params.password.get_UINT8ARRAY_ref(), pbkdf2Spec.password);
    }
    ArrayU8ToDataBlob(params.salt, pbkdf2Spec.salt);
    pbkdf2Spec.iterations = params.iterations;
    size_t keySize = params.keySize;
    outBlob.data = static_cast<uint8_t *>(HcfMalloc(keySize, 0));
    outBlob.len = (outBlob.data == nullptr) ? 0 : keySize;
    pbkdf2Spec.output = outBlob;
    return true;
}

bool SetHkdfParamsSpecAttribute(const HKDFSpec &params, HcfHkdfParamsSpec &hkdfSpec, HcfBlob &outBlob)
{
    if (params.keySize <= 0) {
        return false;
    }
    hkdfSpec.base.algName = params.base.algName.c_str();
    if (params.key.get_tag() == OptStrUint8Arr::tag_t::STRING) {
        StringToDataBlob(params.key.get_STRING_ref(), hkdfSpec.key);
    } else { // OptStrUint8Arr::tag_t::UINT8ARRAY
        ArrayU8ToDataBlob(params.key.get_UINT8ARRAY_ref(), hkdfSpec.key);
    }
    ArrayU8ToDataBlob(params.salt, hkdfSpec.salt);
    ArrayU8ToDataBlob(params.info, hkdfSpec.info);
    size_t keySize = params.keySize;
    outBlob.data = static_cast<uint8_t *>(HcfMalloc(keySize, 0));
    outBlob.len = (outBlob.data == nullptr) ? 0 : keySize;
    hkdfSpec.output = outBlob;
    return true;
}

bool SetScryptParamsSpecAttribute(const ScryptSpec &params, HcfScryptParamsSpec &scryptSpec, HcfBlob &outBlob)
{
    if (params.keySize <= 0 || params.n < 0 || params.r < 0 || params.p < 0 || params.maxMemory < 0) {
        return false;
    }
    scryptSpec.base.algName = params.base.algName.c_str();
    if (params.passphrase.get_tag() == OptStrUint8Arr::tag_t::STRING) {
        StringToDataBlob(params.passphrase.get_STRING_ref(), scryptSpec.passPhrase);
    } else { // OptStrUint8Arr::tag_t::UINT8ARRAY
        ArrayU8ToDataBlob(params.passphrase.get_UINT8ARRAY_ref(), scryptSpec.passPhrase);
    }
    ArrayU8ToDataBlob(params.salt, scryptSpec.salt);
    scryptSpec.n = params.n;
    scryptSpec.r = params.r;
    scryptSpec.p = params.p;
    scryptSpec.maxMem = params.maxMemory;
    size_t keySize = params.keySize;
    outBlob.data = static_cast<uint8_t *>(HcfMalloc(keySize, 0));
    outBlob.len = (outBlob.data == nullptr) ? 0 : keySize;
    scryptSpec.output = outBlob;
    return true;
}

bool SetX963KDFParamsSpecAttribute(const X963KdfSpec &params, HcfX963KDFParamsSpec &x963kdfSpec, HcfBlob &outBlob)
{
    if (params.keySize <= 0 || params.keySize > X963KDF_MAX_KEY_SIZE) {
        return false;
    }
    x963kdfSpec.base.algName = params.base.algName.c_str();
    if (params.key.get_tag() == OptStrUint8Arr::tag_t::STRING) {
        StringToDataBlob(params.key.get_STRING_ref(), x963kdfSpec.key);
    } else { // OptStrUint8Arr::tag_t::UINT8ARRAY
        ArrayU8ToDataBlob(params.key.get_UINT8ARRAY_ref(), x963kdfSpec.key);
    }
    ArrayU8ToDataBlob(params.info, x963kdfSpec.info);
    size_t keySize = params.keySize;
    outBlob.data = static_cast<uint8_t *>(HcfMalloc(keySize, 0));
    outBlob.len = (outBlob.data == nullptr) ? 0 : keySize;
    x963kdfSpec.output = outBlob;
    return true;
}
} // namespace

namespace ANI::CryptoFramework {
KdfImpl::KdfImpl() {}

KdfImpl::KdfImpl(HcfKdf *kdf) : kdf_(kdf) {}

KdfImpl::~KdfImpl()
{
    HcfObjDestroy(this->kdf_);
    this->kdf_ = nullptr;
}

DataBlob KdfImpl::GenerateSecretSync(OptExtKdfSpec const& params)
{
    if (this->kdf_ == nullptr) {
        ANI_LOGE_THROW(HCF_ERR_ANI, "kdf obj is nullptr!");
        return {};
    }
    HcfKdfParamsSpec *paramsSpec = nullptr;
    HcfPBKDF2ParamsSpec pbkdf2Spec = {};
    HcfHkdfParamsSpec hkdfSpec = {};
    HcfScryptParamsSpec scryptSpec = {};
    HcfX963KDFParamsSpec x963kdfSpec = {};
    HcfBlob outBlob = {};
    const std::string &algName = params.get_KDFSPEC_ref().algName.c_str();
    bool flag = false;
    if (params.get_tag() == OptExtKdfSpec::tag_t::PBKDF2SPEC && algName == PBKDF2_ALG_NAME) {
        flag = SetPBKDF2ParamsSpecAttribute(params.get_PBKDF2SPEC_ref(), pbkdf2Spec, outBlob);
        paramsSpec = reinterpret_cast<HcfKdfParamsSpec *>(&pbkdf2Spec);
    } else if (params.get_tag() == OptExtKdfSpec::tag_t::HKDFSPEC && algName == HKDF_ALG_NAME) {
        flag = SetHkdfParamsSpecAttribute(params.get_HKDFSPEC_ref(), hkdfSpec, outBlob);
        paramsSpec = reinterpret_cast<HcfKdfParamsSpec *>(&hkdfSpec);
    } else if (params.get_tag() == OptExtKdfSpec::tag_t::SCRYPTSPEC && algName == SCRYPT_ALG_NAME) {
        flag = SetScryptParamsSpecAttribute(params.get_SCRYPTSPEC_ref(), scryptSpec, outBlob);
        paramsSpec = reinterpret_cast<HcfKdfParamsSpec *>(&scryptSpec);
    } else if (params.get_tag() == OptExtKdfSpec::tag_t::X963KDFSPEC && algName == X963KDF_ALG_NAME) {
        flag = SetX963KDFParamsSpecAttribute(params.get_X963KDFSPEC_ref(), x963kdfSpec, outBlob);
        paramsSpec = reinterpret_cast<HcfKdfParamsSpec *>(&x963kdfSpec);
    }
    if (!flag) {
        ANI_LOGE_THROW(HCF_INVALID_PARAMS, "invalid kdf spec!");
        return {};
    }
    HcfResult res = this->kdf_->generateSecret(this->kdf_, paramsSpec);
    if (res != HCF_SUCCESS) {
        ANI_LOGE_THROW(res, "kdf generateSecret failed!");
        HcfBlobDataClearAndFree(&outBlob);
        return {};
    }
    array<uint8_t> data = {};
    DataBlobToArrayU8(outBlob, data);
    HcfBlobDataClearAndFree(&outBlob);
    return { data };
}

string KdfImpl::GetAlgName()
{
    if (this->kdf_ == nullptr) {
        ANI_LOGE_THROW(HCF_ERR_ANI, "kdf obj is nullptr!");
        return "";
    }
    const char *algName = this->kdf_->getAlgorithm(this->kdf_);
    return (algName == nullptr) ? "" : string(algName);
}

Kdf CreateKdf(string_view algName)
{
    HcfKdf *kdf = nullptr;
    HcfResult res = HcfKdfCreate(algName.c_str(), &kdf);
    if (res != HCF_SUCCESS) {
        ANI_LOGE_THROW(res, "create kdf obj failed.");
        return make_holder<KdfImpl, Kdf>();
    }
    return make_holder<KdfImpl, Kdf>(kdf);
}
} // namespace ANI::CryptoFramework

// Since these macros are auto-generate, lint will cause false positive.
// NOLINTBEGIN
TH_EXPORT_CPP_API_CreateKdf(ANI::CryptoFramework::CreateKdf);
// NOLINTEND
