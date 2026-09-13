/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
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
#include "key_impl.h"
#include "log.h"

namespace OHOS {
    namespace CryptoFramework {
        KeyImpl::KeyImpl(HcfKey *hcfKey)
        {
            hcfKey_ = hcfKey;
        }

        KeyImpl::~KeyImpl() {}

        HcfKey *KeyImpl::GetHcfKey() const
        {
            return hcfKey_;
        }

        const char *KeyImpl::GetFormat(int32_t* errCode)
        {
            if (hcfKey_ == nullptr) {
                LOGE("fail to get key obj!");
                *errCode = HCF_ERR_MALLOC;
                return nullptr;
            }
            const char *format = hcfKey_->getFormat(hcfKey_);
            *errCode = HCF_SUCCESS;
            return format;
        }

        const char *KeyImpl::GetAlgorithm(int32_t* errCode)
        {
            if (hcfKey_ == nullptr) {
                LOGE("fail to get key obj!");
                *errCode = HCF_ERR_MALLOC;
                return nullptr;
            }
            const char *algo = hcfKey_->getAlgorithm(hcfKey_);
            *errCode = HCF_SUCCESS;
            return algo;
        }

        HcfResult KeyImpl::GetEncoded(HcfBlob *returnBlob)
        {
            if (hcfKey_ == nullptr) {
                LOGE("fail to get key obj!");
                return HCF_ERR_MALLOC;
            }
            return hcfKey_->getEncoded(hcfKey_, returnBlob);
        }
    }
}