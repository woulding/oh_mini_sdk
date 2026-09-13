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

#include "ani_asy_key_generator.h"
#include "ani_key_pair.h"

namespace {
using namespace ANI::CryptoFramework;

KeyPair ConvertPemKeyInner(HcfAsyKeyGenerator *self, HcfParamsSpec *spec,
    OptString const& pubKey, OptString const& priKey)
{
    if (self == nullptr) {
        ANI_LOGE_THROW(HCF_ERR_ANI, "generator obj is nullptr!");
        return make_holder<KeyPairImpl, KeyPair>();
    }
    const char *pkStr = nullptr;
    const char *skStr = nullptr;
    if (pubKey.get_tag() == OptString::tag_t::STRING) {
        pkStr = pubKey.get_STRING_ref().c_str();
    }
    if (priKey.get_tag() == OptString::tag_t::STRING) {
        skStr = priKey.get_STRING_ref().c_str();
    }
    HcfKeyPair *keyPair = nullptr;
    HcfResult res = self->convertPemKey(self, spec, pkStr, skStr, &keyPair);
    if (res != HCF_SUCCESS) {
        ANI_LOGE_THROW(res, "convert pem key fail.");
        return make_holder<KeyPairImpl, KeyPair>();
    }
    return make_holder<KeyPairImpl, KeyPair>(keyPair);
}
} // namespace

namespace ANI::CryptoFramework {
AsyKeyGeneratorImpl::AsyKeyGeneratorImpl() {}

AsyKeyGeneratorImpl::AsyKeyGeneratorImpl(HcfAsyKeyGenerator *generator) : generator_(generator) {}

AsyKeyGeneratorImpl::~AsyKeyGeneratorImpl()
{
    HcfObjDestroy(this->generator_);
    this->generator_ = nullptr;
}

KeyPair AsyKeyGeneratorImpl::GenerateKeyPairSync()
{
    if (this->generator_ == nullptr) {
        ANI_LOGE_THROW(HCF_ERR_ANI, "generator obj is nullptr!");
        return make_holder<KeyPairImpl, KeyPair>();
    }
    HcfKeyPair *keyPair = nullptr;
    HcfResult res = this->generator_->generateKeyPair(this->generator_, nullptr, &(keyPair));
    if (res != HCF_SUCCESS) {
        ANI_LOGE_THROW(res, "generate key pair fail.");
        return make_holder<KeyPairImpl, KeyPair>();
    }
    return make_holder<KeyPairImpl, KeyPair>(keyPair);
}

KeyPair AsyKeyGeneratorImpl::ConvertKeySync(OptDataBlob const& pubKey, OptDataBlob const& priKey)
{
    if (this->generator_ == nullptr) {
        ANI_LOGE_THROW(HCF_ERR_ANI, "generator obj is nullptr!");
        return make_holder<KeyPairImpl, KeyPair>();
    }
    HcfKeyPair *keyPair = nullptr;
    HcfBlob *pubKeyBlob = nullptr;
    HcfBlob *priKeyBlob = nullptr;
    HcfBlob pkBlob = {};
    HcfBlob skBlob = {};
    if (pubKey.get_tag() == OptDataBlob::tag_t::DATABLOB) {
        ArrayU8ToDataBlob(pubKey.get_DATABLOB_ref().data, pkBlob);
        pubKeyBlob = &pkBlob;
    }
    if (priKey.get_tag() == OptDataBlob::tag_t::DATABLOB) {
        ArrayU8ToDataBlob(priKey.get_DATABLOB_ref().data, skBlob);
        priKeyBlob = &skBlob;
    }
    HcfResult res = this->generator_->convertKey(this->generator_, nullptr, pubKeyBlob, priKeyBlob, &keyPair);
    if (res != HCF_SUCCESS) {
        ANI_LOGE_THROW(res, "convert key fail.");
        return make_holder<KeyPairImpl, KeyPair>();
    }
    return make_holder<KeyPairImpl, KeyPair>(keyPair);
}

KeyPair AsyKeyGeneratorImpl::ConvertPemKeySync(OptString const& pubKey, OptString const& priKey)
{
    return ConvertPemKeyInner(this->generator_, nullptr, pubKey, priKey);
}

KeyPair AsyKeyGeneratorImpl::ConvertPemKeySyncEx(OptString const& pubKey, OptString const& priKey, string_view password)
{
    HcfKeyDecodingParamsSpec spec = {};
    spec.password = const_cast<char *>(password.c_str());
    return ConvertPemKeyInner(this->generator_, reinterpret_cast<HcfParamsSpec *>(&spec), pubKey, priKey);
}

string AsyKeyGeneratorImpl::GetAlgName()
{
    if (this->generator_ == nullptr) {
        ANI_LOGE_THROW(HCF_ERR_ANI, "generator obj is nullptr!");
        return "";
    }
    const char *algName = this->generator_->getAlgoName(this->generator_);
    return (algName == nullptr) ? "" : string(algName);
}

AsyKeyGenerator CreateAsyKeyGenerator(string_view algName)
{
    HistogramScopeGuard guard(API_CREATE_ASY_KEY_GENERATOR);
    if (!IsPqcAsyKeyAlgorithm(algName.c_str())) {
        guard.DisableScopeGuard();
    }
    HcfAsyKeyGenerator *generator = nullptr;
    HcfResult res = HcfAsyKeyGeneratorCreate(algName.c_str(), &generator);
    if (res != HCF_SUCCESS) {
        guard.SetErrorCode(res);
        ANI_LOGE_THROW(res, "create generator obj fail!");
        return make_holder<AsyKeyGeneratorImpl, AsyKeyGenerator>();
    }
    return make_holder<AsyKeyGeneratorImpl, AsyKeyGenerator>(generator);
}
} // namespace ANI::CryptoFramework

// Since these macros are auto-generate, lint will cause false positive.
// NOLINTBEGIN
TH_EXPORT_CPP_API_CreateAsyKeyGenerator(ANI::CryptoFramework::CreateAsyKeyGenerator);
// NOLINTEND
