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
#ifndef SYM_KEY_GENERATOR_IMPL_H
#define SYM_KEY_GENERATOR_IMPL_H

#include "ffi_remote_data.h"
#include "sym_key.h"
#include "result.h"
#include "sym_key_generator.h"
#include "log.h"

namespace OHOS {
namespace CryptoFramework {
class SymKeyGeneratorImpl : public OHOS::FFI::FFIData {
    DECL_TYPE(SymKeyGeneratorImpl, OHOS::FFI::FFIData)
public:
    explicit SymKeyGeneratorImpl(HcfSymKeyGenerator *generator);
    ~SymKeyGeneratorImpl();
    const char *GetAlgName(int32_t* errCode);
    HcfResult GenerateSymKey(HcfSymKey **symKey);
    HcfResult ConvertKey(const HcfBlob key, HcfSymKey **symKey);

private:
    HcfSymKeyGenerator *generator_;
};
}
}

#endif
