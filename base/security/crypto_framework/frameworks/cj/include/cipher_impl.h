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
#ifndef CIPHER_IMPL_H
#define CIPHER_IMPL_H

#include "ffi_remote_data.h"
#include "algorithm_parameter.h"
#include "key.h"
#include "cipher.h"
#include "blob.h"

namespace OHOS {
namespace CryptoFramework {
class CipherImpl : public OHOS::FFI::FFIData {
    DECL_TYPE(CipherImpl, OHOS::FFI::FFIData)
public:
    explicit CipherImpl(HcfCipher *cipher);
    ~CipherImpl();
    HcfResult CipherInit(HcfCryptoMode opMode, HcfKey *key, HcfParamsSpec *params);
    HcfResult CipherUpdate(HcfBlob *input, HcfBlob *output);
    HcfResult CipherDoFinal(HcfBlob *input, HcfBlob *output);
    HcfResult SetCipherSpec(CipherSpecItem item, HcfBlob pSource);
    HcfResult GetCipherSpecString(CipherSpecItem item, char **returnString);
    HcfResult GetCipherSpecUint8Array(CipherSpecItem item, HcfBlob *returnUint8Array);
    const char *GetAlgorithm(int32_t* errCode);

private:
    HcfCipher *cipher_;
};
}
}

#endif
