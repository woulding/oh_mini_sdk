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
#include "md_impl.h"

namespace OHOS {
    namespace CryptoFramework {
        MdImpl::MdImpl(HcfMd *mdObj)
        {
            mdObj_ = mdObj;
        }

        HcfResult MdImpl::MdUpdate(HcfBlob *input)
        {
            if (mdObj_ == nullptr) {
                LOGE("fail to get md obj!");
                return HCF_ERR_MALLOC;
            }
            HcfResult res = mdObj_->update(mdObj_, input);
            return res;
        }

        MdImpl::~MdImpl()
        {
            HcfObjDestroy(this->mdObj_);
        }

        HcfResult MdImpl::MdDoFinal(HcfBlob *output)
        {
            if (mdObj_ == nullptr) {
                LOGE("fail to get md obj!");
                return HCF_ERR_MALLOC;
            }
            HcfResult res = mdObj_->doFinal(mdObj_, output);
            return res;
        }

        uint32_t MdImpl::GetMdLength(int32_t* errCode)
        {
            if (mdObj_ == nullptr) {
                LOGE("fail to get md obj!");
                *errCode = HCF_ERR_MALLOC;
                return 0;
            }
            uint32_t retLen = mdObj_->getMdLength(mdObj_);
            *errCode = HCF_SUCCESS;
            return retLen;
        }
    }
}