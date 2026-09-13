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

#include "sign_impl.h"

namespace OHOS {
namespace CryptoFramework {
SignImpl::SignImpl(HcfSign *signObj)
{
    signObj_ = signObj;
}

SignImpl::~SignImpl()
{
    HcfObjDestroy(this->signObj_);
}

HcfResult SignImpl::Init(HcfPriKey *priKey)
{
    if (this->signObj_ == nullptr)  {
        return HCF_INVALID_PARAMS;
    }
    return this->signObj_->init(signObj_, nullptr, priKey);
}

HcfResult SignImpl::Update(HcfBlob *input)
{
    if (this->signObj_ == nullptr)  {
        return HCF_INVALID_PARAMS;
    }
    return this->signObj_->update(signObj_, input);
}

HcfResult SignImpl::Sign(HcfBlob *input, HcfBlob *output)
{
    if (this->signObj_ == nullptr)  {
        return HCF_INVALID_PARAMS;
    }
    return this->signObj_->sign(signObj_, input, output);
}

HcfResult SignImpl::SetSignSpecByNum(int32_t itemValue)
{
    if (this->signObj_ == nullptr)  {
        return HCF_INVALID_PARAMS;
    }
    return this->signObj_->setSignSpecInt(signObj_, PSS_SALT_LEN_INT, itemValue);
}

HcfResult SignImpl::SetSignSpecByArr(HcfBlob itemValue)
{
    if (this->signObj_ == nullptr)  {
        return HCF_INVALID_PARAMS;
    }
    return this->signObj_->setSignSpecUint8Array(signObj_, SM2_USER_ID_UINT8ARR, itemValue);
}

HcfResult SignImpl::GetSignSpecString(SignSpecItem item, char **itemValue)
{
    if (this->signObj_ == nullptr)  {
        return HCF_INVALID_PARAMS;
    }
    return this->signObj_->getSignSpecString(signObj_, item, itemValue);
}

HcfResult SignImpl::GetSignSpecNum(SignSpecItem item, int32_t *itemValue)
{
    if (this->signObj_ == nullptr)  {
        return HCF_INVALID_PARAMS;
    }
    return this->signObj_->getSignSpecInt(signObj_, item, itemValue);
}
}
}