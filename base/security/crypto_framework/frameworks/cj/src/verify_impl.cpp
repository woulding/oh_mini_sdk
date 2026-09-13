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

#include "verify_impl.h"

namespace OHOS {
namespace CryptoFramework {
VerifyImpl::VerifyImpl(HcfVerify *verify)
{
    this->verify_ = verify;
}

VerifyImpl::~VerifyImpl()
{
    HcfObjDestroy(this->verify_);
}

HcfResult VerifyImpl::Init(HcfPubKey *pubKey)
{
    if (this->verify_ == nullptr)  {
        return HCF_INVALID_PARAMS;
    }
    return this->verify_->init(verify_, nullptr, pubKey);
}

HcfResult VerifyImpl::Update(HcfBlob *input)
{
    if (this->verify_ == nullptr)  {
        return HCF_INVALID_PARAMS;
    }
    return this->verify_->update(verify_, input);
}

bool VerifyImpl::Verify(HcfBlob *data, HcfBlob signatureData, int32_t *errCode)
{
    if (this->verify_ == nullptr)  {
        *errCode = HCF_INVALID_PARAMS;
        return false;
    }
    *errCode = HCF_SUCCESS;
    return this->verify_->verify(verify_, data, &signatureData);
}

HcfResult VerifyImpl::Recover(HcfBlob input, HcfBlob *output)
{
    if (this->verify_ == nullptr)  {
        return HCF_INVALID_PARAMS;
    }
    return this->verify_->recover(verify_, &input, output);
}

HcfResult VerifyImpl::SetVerifySpecByNum(int32_t itemValue)
{
    if (this->verify_ == nullptr)  {
        return HCF_INVALID_PARAMS;
    }
    return this->verify_->setVerifySpecInt(verify_, PSS_SALT_LEN_INT, itemValue);
}

HcfResult VerifyImpl::SetVerifySpecByArr(HcfBlob itemValue)
{
    if (this->verify_ == nullptr)  {
        return HCF_INVALID_PARAMS;
    }
    return this->verify_->setVerifySpecUint8Array(verify_, SM2_USER_ID_UINT8ARR, itemValue);
}

HcfResult VerifyImpl::GetVerifySpecString(SignSpecItem item, char **itemValue)
{
    if (this->verify_ == nullptr)  {
        return HCF_INVALID_PARAMS;
    }
    return this->verify_->getVerifySpecString(verify_, item, itemValue);
}

HcfResult VerifyImpl::GetVerifySpecNum(SignSpecItem item, int32_t *itemValue)
{
    if (this->verify_ == nullptr)  {
        return HCF_INVALID_PARAMS;
    }
    return this->verify_->getVerifySpecInt(verify_, item, itemValue);
}
}
}