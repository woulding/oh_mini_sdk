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
#include "sym_key_generator_impl.h"

namespace OHOS {
    namespace CryptoFramework {
        SymKeyGeneratorImpl::SymKeyGeneratorImpl(HcfSymKeyGenerator *generator)
        {
            generator_ = generator;
        }

        SymKeyGeneratorImpl::~SymKeyGeneratorImpl()
        {
            HcfObjDestroy(this->generator_);
        }

        const char *SymKeyGeneratorImpl::GetAlgName(int32_t* errCode)
        {
            if (generator_ == nullptr) {
                *errCode = HCF_ERR_MALLOC;
                LOGE("fail to get symKeyGenerator obj!");
                return nullptr;
            }
            const char *algo = generator_->getAlgoName(generator_);
            *errCode = HCF_SUCCESS;
            return algo;
        }

        HcfResult SymKeyGeneratorImpl::GenerateSymKey(HcfSymKey **symKey)
        {
            if (generator_ == nullptr) {
                LOGE("fail to get symKeyGenerator obj!");
                return HCF_ERR_MALLOC;
            }
            HcfResult res = generator_->generateSymKey(generator_, symKey);
            return res;
        }

        HcfResult SymKeyGeneratorImpl::ConvertKey(const HcfBlob key, HcfSymKey **symKey)
        {
            if (generator_ == nullptr) {
                LOGE("fail to get symKeyGenerator obj!");
                return HCF_ERR_MALLOC;
            }
            HcfResult res = generator_->convertSymKey(generator_, &key, symKey);
            return res;
        }
    }
}