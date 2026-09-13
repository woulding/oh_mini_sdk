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

#include "ani_key_pair.h"
#include "ani_pri_key.h"
#include "ani_pub_key.h"

namespace ANI::CryptoFramework {
KeyPairImpl::KeyPairImpl() {}

KeyPairImpl::KeyPairImpl(HcfKeyPair *keyPair) : keyPair_(keyPair) {}

KeyPairImpl::~KeyPairImpl()
{
    HcfObjDestroy(this->keyPair_);
    this->keyPair_ = nullptr;
}

PriKey KeyPairImpl::GetPriKey()
{
    if (this->keyPair_ == nullptr) {
        ANI_LOGE_THROW(HCF_ERR_ANI, "keyPair obj is nullptr!");
        return make_holder<PriKeyImpl, PriKey>();
    }
    HcfPriKey *priKey = this->keyPair_->priKey;
    return make_holder<PriKeyImpl, PriKey>(priKey, false);
}

PubKey KeyPairImpl::GetPubKey()
{
    if (this->keyPair_ == nullptr) {
        ANI_LOGE_THROW(HCF_ERR_ANI, "keyPair obj is nullptr!");
        return make_holder<PubKeyImpl, PubKey>();
    }
    HcfPubKey *pubKey = this->keyPair_->pubKey;
    return make_holder<PubKeyImpl, PubKey>(pubKey, false);
}
} // namespace ANI::CryptoFramework
