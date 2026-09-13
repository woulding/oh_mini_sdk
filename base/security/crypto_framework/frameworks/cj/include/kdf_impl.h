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
#ifndef KDF_IMPL_H
#define KDF_IMPL_H

#include "ffi_remote_data.h"
#include "blob.h"
#include "kdf.h"
#include "kdf_params.h"
#include "detailed_pbkdf2_params.h"
#include "detailed_hkdf_params.h"

namespace OHOS {
namespace CryptoFramework {
class KdfImpl : public OHOS::FFI::FFIData {
    DECL_TYPE(KdfImpl, OHOS::FFI::FFIData)
public:
    explicit KdfImpl(HcfKdf *kdf);
    ~KdfImpl();
    HcfKdf *GetKdf() const;
    int32_t GenerateSecret(HcfKdfParamsSpec *paramsSpec);
private:
    HcfKdf *kdf = nullptr;
};
}
}
#endif