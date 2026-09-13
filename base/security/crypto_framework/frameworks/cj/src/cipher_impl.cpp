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
#include "cipher_impl.h"
#include "log.h"

namespace OHOS {
    namespace CryptoFramework {
        CipherImpl::CipherImpl(HcfCipher *cipher)
        {
            cipher_ = cipher;
        }

        CipherImpl::~CipherImpl()
        {
            HcfObjDestroy(this->cipher_);
        }

        HcfResult CipherImpl::CipherInit(HcfCryptoMode opMode, HcfKey *key, HcfParamsSpec *params)
        {
            if (cipher_ == nullptr) {
                LOGE("fail to get cipher obj!");
                return HCF_ERR_MALLOC;
            }
            HcfResult res = cipher_->init(cipher_, opMode, key, params);
            return res;
        }

        HcfResult CipherImpl::CipherUpdate(HcfBlob *input, HcfBlob *output)
        {
            if (cipher_ == nullptr) {
                LOGE("fail to get cipher obj!");
                return HCF_ERR_MALLOC;
            }
            HcfResult res = cipher_->update(cipher_, input, output);
            return res;
        }

        HcfResult CipherImpl::CipherDoFinal(HcfBlob *input, HcfBlob *output)
        {
            if (cipher_ == nullptr) {
                LOGE("fail to get cipher obj!");
                return HCF_ERR_MALLOC;
            }
            HcfResult res = cipher_->doFinal(cipher_, input, output);
            return res;
        }

        HcfResult CipherImpl::SetCipherSpec(CipherSpecItem item, HcfBlob pSource)
        {
            if (cipher_ == nullptr) {
                LOGE("fail to get cipher obj!");
                return HCF_INVALID_PARAMS;
            }
            return cipher_->setCipherSpecUint8Array(cipher_, item, pSource);
        }

        HcfResult CipherImpl::GetCipherSpecString(CipherSpecItem item, char **returnString)
        {
            if (cipher_ == nullptr) {
                LOGE("fail to get cipher obj!");
                return HCF_INVALID_PARAMS;
            }
            return cipher_->getCipherSpecString(cipher_, item, returnString);
        }

        HcfResult CipherImpl::GetCipherSpecUint8Array(CipherSpecItem item, HcfBlob *returnUint8Array)
        {
            if (cipher_ == nullptr) {
                LOGE("fail to get cipher obj!");
                return HCF_INVALID_PARAMS;
            }
            return cipher_->getCipherSpecUint8Array(cipher_, item, returnUint8Array);
        }

        const char *CipherImpl::GetAlgorithm(int32_t* errCode)
        {
            if (cipher_ == nullptr) {
                LOGE("fail to get cipher obj!");
                *errCode = HCF_ERR_MALLOC;
                return nullptr;
            }
            const char *algo = cipher_->getAlgorithm(cipher_);
            *errCode = HCF_SUCCESS;
            return algo;
        }
    }
}