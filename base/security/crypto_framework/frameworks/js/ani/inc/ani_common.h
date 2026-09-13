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

#ifndef ANI_COMMON_H
#define ANI_COMMON_H

#include "stdexcept"
#include "taihe/runtime.hpp"
#include "ohos.security.cryptoFramework.cryptoFramework.proj.hpp"
#include "ohos.security.cryptoFramework.cryptoFramework.impl.hpp"

#include "log.h"
#include "blob.h"
#include "result.h"
#include "memory.h"
#include "object_base.h"
#include "big_integer.h"
#include "js_api_metrics.h"

#include "key.h"
#include "cipher.h"
#include "signature.h"

namespace ANI::CryptoFramework {
using namespace taihe;
using namespace ohos::security::cryptoFramework::cryptoFramework;

// Resolve the issue of enumeration conflicts with the same name between inner and taihe
using HcfAsyKeySpecItem = ::AsyKeySpecItem;
using HcfCipherSpecItem = ::CipherSpecItem;
using HcfSignSpecItem = ::SignSpecItem;
using ThAsyKeySpecItem = ohos::security::cryptoFramework::cryptoFramework::AsyKeySpecItem;
using ThCipherSpecItem = ohos::security::cryptoFramework::cryptoFramework::CipherSpecItem;
using ThSignSpecItem = ohos::security::cryptoFramework::cryptoFramework::SignSpecItem;

constexpr int SPEC_ITEM_TYPE_BIG_INT = 1;
constexpr int SPEC_ITEM_TYPE_NUM = 2;
constexpr int SPEC_ITEM_TYPE_STR = 3;
constexpr int SPEC_ITEM_TYPE_UINT8ARR = 4;
constexpr int SPEC_ITEM_TYPE_BOOL = 5;

#define ANI_LOGE_THROW(code, msg) \
    do { \
        int rc = ConvertResultCode(code); \
        LOGE("%{public}s code: %{public}d", msg, rc); \
        set_business_error(rc, msg); \
    } while (0)

int ConvertResultCode(HcfResult res);

template<typename T>
void ArrayU8ToDataBlob(const T &arr, HcfBlob &blob);
void DataBlobToArrayU8(const HcfBlob &blob, array<uint8_t> &arr);

template<typename T>
bool ArrayU8ToBigInteger(const T &arr, HcfBigInteger &bigint);
void BigIntegerToArrayU8(const HcfBigInteger &bigint, array<uint8_t> &arr);

void StringToDataBlob(const string &str, HcfBlob &blob);

int GetAsyKeySpecType(HcfAsyKeySpecItem item);
int GetSignSpecType(HcfSignSpecItem item);
} // namespace ANI::CryptoFramework

#endif // ANI_COMMON_H
