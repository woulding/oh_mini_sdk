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

#include "ani_key.h"

namespace ANI::CryptoFramework {
KeyImpl::KeyImpl() {}

KeyImpl::KeyImpl(HcfKey *key) : key_(key) {}

KeyImpl::~KeyImpl()
{
    HcfObjDestroy(this->key_);
    this->key_ = nullptr;
}

int64_t KeyImpl::GetKeyObj()
{
    return reinterpret_cast<int64_t>(this->key_);
}

DataBlob KeyImpl::GetEncoded()
{
    if (this->key_ == nullptr) {
        ANI_LOGE_THROW(HCF_ERR_ANI, "key obj is nullptr!");
        return {};
    }
    HcfBlob outBlob = {};
    HcfResult res = this->key_->getEncoded(this->key_, &outBlob);
    if (res != HCF_SUCCESS) {
        ANI_LOGE_THROW(res, "getEncoded failed.");
        return {};
    }
    array<uint8_t> data = {};
    DataBlobToArrayU8(outBlob, data);
    HcfBlobDataClearAndFree(&outBlob);
    return { data };
}

string KeyImpl::GetFormat()
{
    if (this->key_ == nullptr) {
        ANI_LOGE_THROW(HCF_ERR_ANI, "key obj is nullptr!");
        return "";
    }
    const char *format = this->key_->getFormat(this->key_);
    return (format == nullptr) ? "" : string(format);
}

string KeyImpl::GetAlgName()
{
    if (this->key_ == nullptr) {
        ANI_LOGE_THROW(HCF_ERR_ANI, "key obj is nullptr!");
        return "";
    }
    const char *algName = this->key_->getAlgorithm(this->key_);
    return (algName == nullptr) ? "" : string(algName);
}

int KeyImpl::GetKeySize()
{
    if (this->key_ == nullptr) {
        ANI_LOGE_THROW(HCF_ERR_ANI, "key obj is nullptr!");
        return 0;
    }
    int keySize = 0;
    HcfResult res = this->key_->getKeySize(this->key_, &keySize);
    if (res != HCF_SUCCESS) {
        ANI_LOGE_THROW(res, "getKeySize failed.");
        return 0;
    }
    return keySize;
}
} // namespace ANI::CryptoFramework
