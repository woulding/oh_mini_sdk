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
#include "random_impl.h"

namespace OHOS {
    namespace CryptoFramework {
        RandomImpl::RandomImpl(HcfRand *randObj)
        {
            randObj_ = randObj;
        }

        RandomImpl::~RandomImpl()
        {
            HcfObjDestroy(this->randObj_);
        }

        const char* RandomImpl::GetAlgName(int32_t* errCode)
        {
            if (randObj_ == nullptr) {
                LOGE("fail to get rand obj!");
                *errCode = HCF_ERR_MALLOC;
                return nullptr;
            }
            const char *algoName = randObj_->getAlgoName(randObj_);
            *errCode = HCF_SUCCESS;
            return algoName;
        }

        HcfBlob RandomImpl::GenerateRandom(int32_t numBytes, int32_t* errCode)
        {
            HcfBlob randBlob = { .data = nullptr, .len = 0};
            if (randObj_ == nullptr) {
                *errCode = HCF_ERR_MALLOC;
                LOGE("fail to get rand obj!");
                return randBlob;
            }
            HcfResult res = randObj_->generateRandom(randObj_, numBytes, &randBlob);
            if (res != HCF_SUCCESS) {
                LOGE("generateRandom failed!");
            }
            *errCode = static_cast<int32_t>(res);
            return randBlob;
        }

        void RandomImpl::SetSeed(HcfBlob *seed, int32_t* errCode)
        {
            if (randObj_ == nullptr) {
                *errCode = HCF_ERR_MALLOC;
                LOGE("fail to get rand obj!");
                return;
            }
            HcfResult res = randObj_->setSeed(randObj_, seed);
            if (res != HCF_SUCCESS) {
                LOGE("set seed failed.");
            }
            *errCode = static_cast<int32_t>(res);
        }
    }
}