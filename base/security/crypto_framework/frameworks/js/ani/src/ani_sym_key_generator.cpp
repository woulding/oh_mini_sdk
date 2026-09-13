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

#include "ani_sym_key_generator.h"
#include "ani_sym_key.h"

namespace ANI::CryptoFramework {
SymKeyGeneratorImpl::SymKeyGeneratorImpl() {}

SymKeyGeneratorImpl::SymKeyGeneratorImpl(HcfSymKeyGenerator *generator) : generator_(generator) {}

SymKeyGeneratorImpl::~SymKeyGeneratorImpl()
{
    HcfObjDestroy(this->generator_);
    this->generator_ = nullptr;
}

SymKey SymKeyGeneratorImpl::GenerateSymKeySync()
{
    if (this->generator_ == nullptr) {
        ANI_LOGE_THROW(HCF_ERR_ANI, "generator obj is nullptr!");
        return make_holder<SymKeyImpl, SymKey>();
    }
    HcfSymKey *symKey = nullptr;
    HcfResult res = this->generator_->generateSymKey(this->generator_, &symKey);
    if (res != HCF_SUCCESS) {
        ANI_LOGE_THROW(res, "generate sym key failed.");
        return make_holder<SymKeyImpl, SymKey>();
    }
    return make_holder<SymKeyImpl, SymKey>(symKey);
}

SymKey SymKeyGeneratorImpl::ConvertKeySync(DataBlob const& key)
{
    if (this->generator_ == nullptr) {
        ANI_LOGE_THROW(HCF_ERR_ANI, "generator obj is nullptr!");
        return make_holder<SymKeyImpl, SymKey>();
    }
    HcfSymKey *symKey = nullptr;
    HcfBlob keyData = {};
    ArrayU8ToDataBlob(key.data, keyData);
    HcfResult res = this->generator_->convertSymKey(this->generator_, &keyData, &symKey);
    if (res != HCF_SUCCESS) {
        ANI_LOGE_THROW(res, "convertSymKey key failed!");
        return make_holder<SymKeyImpl, SymKey>();
    }
    return make_holder<SymKeyImpl, SymKey>(symKey);
}

string SymKeyGeneratorImpl::GetAlgName()
{
    if (this->generator_ == nullptr) {
        ANI_LOGE_THROW(HCF_ERR_ANI, "generator obj is nullptr!");
        return "";
    }
    const char *algName = this->generator_->getAlgoName(this->generator_);
    return (algName == nullptr) ? "" : string(algName);
}

SymKeyGenerator CreateSymKeyGenerator(string_view algName)
{
    HcfSymKeyGenerator *generator = nullptr;
    HcfResult res = HcfSymKeyGeneratorCreate(algName.c_str(), &generator);
    if (res != HCF_SUCCESS) {
        ANI_LOGE_THROW(res, "create generator obj fail.");
        return make_holder<SymKeyGeneratorImpl, SymKeyGenerator>();
    }
    return make_holder<SymKeyGeneratorImpl, SymKeyGenerator>(generator);
}
} // namespace ANI::CryptoFramework

// Since these macros are auto-generate, lint will cause false positive.
// NOLINTBEGIN
TH_EXPORT_CPP_API_CreateSymKeyGenerator(ANI::CryptoFramework::CreateSymKeyGenerator);
// NOLINTEND
