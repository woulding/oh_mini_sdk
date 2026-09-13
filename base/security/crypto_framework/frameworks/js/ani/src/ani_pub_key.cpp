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

#include "ani_pub_key.h"
#include "key.h"

namespace {
using namespace ANI::CryptoFramework;

OptKeySpec GetAsyKeySpecNumber(HcfPubKey *pubKey, HcfAsyKeySpecItem item)
{
    int num = 0;
    HcfResult res = pubKey->getAsyKeySpecInt(pubKey, item, &num);
    if (res != HCF_SUCCESS) {
        ANI_LOGE_THROW(res, "get asy key spec int fail.");
        return OptKeySpec::make_INT32(-1);
    }
    return OptKeySpec::make_INT32(num);
}

OptKeySpec GetAsyKeySpecString(HcfPubKey *pubKey, HcfAsyKeySpecItem item)
{
    char *str = nullptr;
    HcfResult res = pubKey->getAsyKeySpecString(pubKey, item, &str);
    if (res != HCF_SUCCESS) {
        ANI_LOGE_THROW(res, "get asy key spec string fail.");
        return OptKeySpec::make_STRING("");
    }
    string data = string(str);
    HCF_FREE_PTR(str);
    return OptKeySpec::make_STRING(data);
}

OptKeySpec GetAsyKeySpecBigInt(HcfPubKey *pubKey, HcfAsyKeySpecItem item)
{
    HcfBigInteger bigint = {};
    HcfResult res = pubKey->getAsyKeySpecBigInteger(pubKey, item, &bigint);
    if (res != HCF_SUCCESS) {
        ANI_LOGE_THROW(res, "get asy key spec bigint failed.");
        return OptKeySpec::make_BIGINT(array<uint8_t>{});
    }
    array<uint8_t> data = {};
    BigIntegerToArrayU8(bigint, data);
    HCF_FREE_PTR(bigint.data);
    return OptKeySpec::make_BIGINT(data);
}
} // namespace

namespace ANI::CryptoFramework {
PubKeyImpl::PubKeyImpl() {}

PubKeyImpl::PubKeyImpl(HcfPubKey *pubKey, bool owner /* = true */) : pubKey_(pubKey), owner_(owner) {}

PubKeyImpl::~PubKeyImpl()
{
    if (this->owner_) {
        HcfObjDestroy(this->pubKey_);
        this->pubKey_ = nullptr;
    }
}

int64_t PubKeyImpl::GetPubKeyObj()
{
    return reinterpret_cast<int64_t>(this->pubKey_);
}

OptKeySpec PubKeyImpl::GetAsyKeySpec(ThAsyKeySpecItem itemType)
{
    if (this->pubKey_ == nullptr) {
        ANI_LOGE_THROW(HCF_ERR_ANI, "pubKey obj is nullptr!");
        return OptKeySpec::make_INT32(-1);
    }
    HcfAsyKeySpecItem item = static_cast<HcfAsyKeySpecItem>(itemType.get_value());
    int type = GetAsyKeySpecType(item);
    if (type == SPEC_ITEM_TYPE_NUM) {
        return GetAsyKeySpecNumber(this->pubKey_, item);
    } else if (type == SPEC_ITEM_TYPE_STR) {
        return GetAsyKeySpecString(this->pubKey_, item);
    } else if (type == SPEC_ITEM_TYPE_BIG_INT) {
        return GetAsyKeySpecBigInt(this->pubKey_, item);
    } else {
        ANI_LOGE_THROW(HCF_INVALID_PARAMS, "asy key spec item not support!");
        return OptKeySpec::make_INT32(-1);
    }
}

array<uint8_t> PubKeyImpl::GetKeyDataSync(AsyKeyDataItem itemType)
{
    if (this->pubKey_ == nullptr) {
        ANI_LOGE_THROW(HCF_ERR_ANI, "pubKey obj is nullptr!");
        return {};
    }
    int type = static_cast<int>(itemType.get_value());
    HcfBlob outBlob = {};
    HcfResult res = this->pubKey_->getKeyData(this->pubKey_, type, &outBlob);
    if (res != HCF_SUCCESS) {
        ANI_LOGE_THROW(res, "getKeyData failed.");
        return {};
    }
    array<uint8_t> data = {};
    DataBlobToArrayU8(outBlob, data);
    HcfBlobDataClearAndFree(&outBlob);
    return data;
}

DataBlob PubKeyImpl::GetEncodedDer(string_view format)
{
    if (this->pubKey_ == nullptr) {
        ANI_LOGE_THROW(HCF_ERR_ANI, "pubKey obj is nullptr!");
        return {};
    }
    HcfBlob outBlob = {};
    HcfResult res = this->pubKey_->getEncodedDer(this->pubKey_, format.c_str(), &outBlob);
    if (res != HCF_SUCCESS) {
        ANI_LOGE_THROW(res, "getEncodedDer failed.");
        return {};
    }
    array<uint8_t> data = {};
    DataBlobToArrayU8(outBlob, data);
    HcfBlobDataClearAndFree(&outBlob);
    return { data };
}

string PubKeyImpl::GetEncodedPem(string_view format)
{
    if (this->pubKey_ == nullptr) {
        ANI_LOGE_THROW(HCF_ERR_ANI, "pubKey obj is nullptr!");
        return "";
    }
    char *encoded = nullptr;
    HcfResult res = this->pubKey_->base.getEncodedPem(&this->pubKey_->base, format.c_str(), &encoded);
    if (res != HCF_SUCCESS) {
        ANI_LOGE_THROW(res, "getEncodedPem failed.");
        return "";
    }
    string str = string(encoded);
    HCF_FREE_PTR(encoded);
    return str;
}

int64_t PubKeyImpl::GetKeyObj()
{
    return reinterpret_cast<int64_t>(&this->pubKey_->base);
}

DataBlob PubKeyImpl::GetEncoded()
{
    if (this->pubKey_ == nullptr) {
        ANI_LOGE_THROW(HCF_ERR_ANI, "pubKey obj is nullptr!");
        return {};
    }
    HcfBlob outBlob = {};
    HcfResult res = this->pubKey_->base.getEncoded(&this->pubKey_->base, &outBlob);
    if (res != HCF_SUCCESS) {
        ANI_LOGE_THROW(res, "getEncoded failed.");
        return {};
    }
    array<uint8_t> data = {};
    DataBlobToArrayU8(outBlob, data);
    HcfBlobDataClearAndFree(&outBlob);
    return { data };
}

string PubKeyImpl::GetFormat()
{
    if (this->pubKey_ == nullptr) {
        ANI_LOGE_THROW(HCF_ERR_ANI, "pubKey obj is nullptr!");
        return "";
    }
    const char *format = this->pubKey_->base.getFormat(&this->pubKey_->base);
    return (format == nullptr) ? "" : string(format);
}

string PubKeyImpl::GetAlgName()
{
    if (this->pubKey_ == nullptr) {
        ANI_LOGE_THROW(HCF_ERR_ANI, "pubKey obj is nullptr!");
        return "";
    }
    const char *algName = this->pubKey_->base.getAlgorithm(&this->pubKey_->base);
    return (algName == nullptr) ? "" : string(algName);
}

int PubKeyImpl::GetKeySize()
{
    if (this->pubKey_ == nullptr) {
        ANI_LOGE_THROW(HCF_ERR_ANI, "pubKey obj is nullptr!");
        return 0;
    }
    int keySize = 0;
    HcfResult res = this->pubKey_->base.getKeySize(&this->pubKey_->base, &keySize);
    if (res != HCF_SUCCESS) {
        ANI_LOGE_THROW(res, "getKeySize failed.");
        return 0;
    }
    return keySize;
}
} // namespace ANI::CryptoFramework
