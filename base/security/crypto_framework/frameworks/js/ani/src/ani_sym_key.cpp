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

#include "ani_sym_key.h"

namespace ANI::CryptoFramework {
SymKeyImpl::SymKeyImpl() : symKey_(nullptr) {}

SymKeyImpl::SymKeyImpl(HcfSymKey *symKey) : symKey_(symKey) {}

SymKeyImpl::~SymKeyImpl()
{
    HcfObjDestroy(this->symKey_);
    this->symKey_ = nullptr;
}

int64_t SymKeyImpl::GetSymKeyObj()
{
    return reinterpret_cast<int64_t>(this->symKey_);
}

void SymKeyImpl::ClearMem()
{
    if (this->symKey_ == nullptr) {
        ANI_LOGE_THROW(HCF_ERR_ANI, "symKey obj is nullptr!");
        return;
    }
    this->symKey_->clearMem(this->symKey_);
}

int64_t SymKeyImpl::GetKeyObj()
{
    return reinterpret_cast<int64_t>(&this->symKey_->key);
}

DataBlob SymKeyImpl::GetEncoded()
{
    if (this->symKey_ == nullptr) {
        ANI_LOGE_THROW(HCF_ERR_ANI, "symKey obj is nullptr!");
        return {};
    }
    HcfBlob outBlob = {};
    HcfResult res = this->symKey_->key.getEncoded(&this->symKey_->key, &outBlob);
    if (res != HCF_SUCCESS) {
        ANI_LOGE_THROW(res, "getEncoded failed.");
        return {};
    }
    array<uint8_t> data = {};
    DataBlobToArrayU8(outBlob, data);
    HcfBlobDataClearAndFree(&outBlob);
    return { data };
}

int SymKeyImpl::GetKeySize()
{
    if (this->symKey_ == nullptr) {
        ANI_LOGE_THROW(HCF_ERR_ANI, "symKey obj is nullptr!");
        return 0;
    }
    int keySize = 0;
    HcfResult res = this->symKey_->key.getKeySize(&this->symKey_->key, &keySize);
    if (res != HCF_SUCCESS) {
        ANI_LOGE_THROW(res, "getKeySize failed.");
        return 0;
    }
    return keySize;
}

string SymKeyImpl::GetFormat()
{
    if (this->symKey_ == nullptr) {
        ANI_LOGE_THROW(HCF_ERR_ANI, "symKey obj is nullptr!");
        return "";
    }
    const char *format = this->symKey_->key.getFormat(&this->symKey_->key);
    return (format == nullptr) ? "" : string(format);
}

string SymKeyImpl::GetAlgName()
{
    if (this->symKey_ == nullptr) {
        ANI_LOGE_THROW(HCF_ERR_ANI, "symKey obj is nullptr!");
        return "";
    }
    const char *algName = this->symKey_->key.getAlgorithm(&this->symKey_->key);
    return (algName == nullptr) ? "" : string(algName);
}
} // namespace ANI::CryptoFramework
