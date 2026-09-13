/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include "mac_impl.h"

namespace OHOS {
    namespace CryptoFramework {
        MacImpl::MacImpl(HcfMac *macObj)
        {
            macObj_ = macObj;
        }

        MacImpl::~MacImpl()
        {
            HcfObjDestroy(this->macObj_);
        }

        HcfResult MacImpl::MacInit(HcfSymKey *symKey)
        {
            if (macObj_ == nullptr) {
                LOGE("fail to get mac obj!");
                return HCF_ERR_MALLOC;
            }
            HcfResult res = macObj_->init(macObj_, symKey);
            return res;
        }

        HcfResult MacImpl::MacUpdate(HcfBlob *input)
        {
            if (macObj_ == nullptr) {
                LOGE("fail to get mac obj!");
                return HCF_ERR_MALLOC;
            }
            HcfResult res = macObj_->update(macObj_, input);
            return res;
        }

        HcfResult MacImpl::MacDoFinal(HcfBlob *output)
        {
            if (macObj_ == nullptr) {
                LOGE("fail to get mac obj!");
                return HCF_ERR_MALLOC;
            }
            HcfResult res = macObj_->doFinal(macObj_, output);
            return res;
        }

        uint32_t MacImpl::GetMacLength()
        {
            if (macObj_ == nullptr) {
                LOGE("fail to get mac obj!");
                return HCF_ERR_MALLOC;
            }
            uint32_t retLen = macObj_->getMacLength(macObj_);
            return retLen;
        }

    }
}