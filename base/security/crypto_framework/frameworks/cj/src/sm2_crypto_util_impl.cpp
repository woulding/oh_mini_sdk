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

#include "sm2_crypto_util_impl.h"

namespace OHOS {
namespace CryptoFramework {
Sm2CryptoUtilImpl::Sm2CryptoUtilImpl() {}

Sm2CryptoUtilImpl::~Sm2CryptoUtilImpl() {}

HcfBlob Sm2CryptoUtilImpl::GenCipherTextBySpec(Sm2CipherTextSpec spec, char *mode, int32_t *errCode)
{
    HcfBlob output = { 0 };
    *errCode = HcfGenCipherTextBySpec(&spec, mode, &output);
    return output;
}

Sm2CipherTextSpec *Sm2CryptoUtilImpl::GetCipherTextSpec(HcfBlob input, char *mode, int32_t *errCode)
{
    Sm2CipherTextSpec *returnSpec = nullptr;
    *errCode = HcfGetCipherTextSpec(&input, mode, &returnSpec);
    return returnSpec;
}
}
}