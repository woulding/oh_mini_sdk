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
#ifndef SM2_CRYPTO_UTIL_IMPL_H
#define SM2_CRYPTO_UTIL_IMPL_H

#include "sm2_crypto_util.h"

namespace OHOS {
namespace CryptoFramework {
class Sm2CryptoUtilImpl {
public:
    explicit Sm2CryptoUtilImpl();
    ~Sm2CryptoUtilImpl();
    static HcfBlob GenCipherTextBySpec(Sm2CipherTextSpec spec, char *mode, int32_t *errCode);
    static Sm2CipherTextSpec *GetCipherTextSpec(HcfBlob input, char *mode, int32_t *errCode);
};
}
}
#endif