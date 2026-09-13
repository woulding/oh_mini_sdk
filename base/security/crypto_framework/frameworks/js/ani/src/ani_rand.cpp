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

#include "ani_rand.h"

namespace ANI::CryptoFramework {
RandomImpl::RandomImpl() {}

RandomImpl::RandomImpl(HcfRand *rand) : rand_(rand) {}

RandomImpl::~RandomImpl()
{
    HcfObjDestroy(this->rand_);
    this->rand_ = nullptr;
}

DataBlob RandomImpl::GenerateRandomSync(int32_t len)
{
    if (this->rand_ == nullptr) {
        ANI_LOGE_THROW(HCF_ERR_ANI, "rand obj is nullptr!");
        return {};
    }
    HcfBlob outBlob = {};
    HcfResult res = this->rand_->generateRandom(this->rand_, len, &outBlob);
    if (res != HCF_SUCCESS) {
        ANI_LOGE_THROW(res, "generateRandom failed!");
        return {};
    }
    array<uint8_t> data = {};
    DataBlobToArrayU8(outBlob, data);
    HcfBlobDataClearAndFree(&outBlob);
    return { data };
}

void RandomImpl::SetSeed(DataBlob const& seed)
{
    if (this->rand_ == nullptr) {
        ANI_LOGE_THROW(HCF_ERR_ANI, "rand obj is nullptr!");
        return;
    }
    HcfBlob seedBlob = {};
    ArrayU8ToDataBlob(seed.data, seedBlob);
    HcfResult res = this->rand_->setSeed(this->rand_, &seedBlob);
    if (res != HCF_SUCCESS) {
        ANI_LOGE_THROW(res, "set seed failed.");
        return;
    }
}

void RandomImpl::EnableHardwareEntropy()
{
    if (this->rand_ == nullptr) {
        ANI_LOGE_THROW(HCF_ERR_ANI, "rand obj is nullptr!");
        return;
    }
    HcfResult res = this->rand_->enableHardwareEntropy(this->rand_);
    if (res != HCF_SUCCESS) {
        ANI_LOGE_THROW(res, "enable hardware entropy failed.");
        return;
    }
}

string RandomImpl::GetAlgName()
{
    if (this->rand_ == nullptr) {
        ANI_LOGE_THROW(HCF_ERR_ANI, "rand obj is nullptr!");
        return "";
    }
    const char *algName = this->rand_->getAlgoName(this->rand_);
    return (algName == nullptr) ? "" : string(algName);
}

Random CreateRandom()
{
    HcfRand *rand = nullptr;
    HcfResult res = HcfRandCreate(&rand);
    if (res != HCF_SUCCESS) {
        ANI_LOGE_THROW(res, "create rand obj failed.");
        return make_holder<RandomImpl, Random>();
    }
    return make_holder<RandomImpl, Random>(rand);
}
} // namespace ANI::CryptoFramework

// Since these macros are auto-generate, lint will cause false positive.
// NOLINTBEGIN
TH_EXPORT_CPP_API_CreateRandom(ANI::CryptoFramework::CreateRandom);
// NOLINTEND
