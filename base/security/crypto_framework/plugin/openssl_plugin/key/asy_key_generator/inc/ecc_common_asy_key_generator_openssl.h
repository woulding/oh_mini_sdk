/*
 * Copyright (C) 2026 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#ifndef HCF_ECC_COMMON_ASY_KEY_GENERATOR_OPENSSL_H
#define HCF_ECC_COMMON_ASY_KEY_GENERATOR_OPENSSL_H

#include "blob.h"
#include "openssl_class.h"
#include "result.h"

#ifdef __cplusplus
extern "C" {
#endif

HcfResult ConvertEcPubKey(int32_t curveId, HcfBlob *pubKeyBlob, HcfOpensslEccPubKey **returnPubKey);
HcfResult ConvertEcPriKey(int32_t curveId, HcfBlob *priKeyBlob, HcfOpensslEccPriKey **returnPriKey);
HcfResult GetEccPubKeyDataInCommon(const HcfPubKey *self, uint32_t type, HcfBlob *returnBlob);
HcfResult GetEccPriKeyDataInCommon(const HcfPriKey *self, uint32_t type, HcfBlob *returnBlob);
HcfResult GetEccPubKeyEncodedPemInCommon(HcfKey *self, const char *format, char **returnString);
HcfResult GetEccPriKeyEncodedPemInCommon(const HcfPriKey *self, const char *format, char **returnString);
HcfResult EccCopyPemFromBIO(BIO *bio, char **returnString);

HcfResult EccPackPubKeyForConvert(int32_t curveId, EC_KEY *ecKey, HcfOpensslEccPubKey **returnPubKey);
HcfResult EccPackPriKeyForConvert(int32_t curveId, EC_KEY *ecKey, HcfOpensslEccPriKey **returnPriKey);

#ifdef __cplusplus
}
#endif

#endif
