/*
 * Copyright (C) 2023 Huawei Device Co., Ltd.
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

#ifndef HCF_ECC_OPENSSL_COMMON_H
#define HCF_ECC_OPENSSL_COMMON_H

#include "detailed_ecc_key_params.h"
#include "openssl_class.h"
#include "openssl_common.h"

#ifdef __cplusplus
extern "C" {
#endif
HcfResult NewEcKeyPair(int32_t curveId, EC_KEY **returnEcKey);
void FreeCurveBigNum(BIGNUM *pStd, BIGNUM *bStd, BIGNUM *xStd, BIGNUM *yStd);
HcfResult GenerateEcGroupWithParamsSpec(const HcfEccCommParamsSpec *ecParams, EC_GROUP **ecGroup);
HcfResult SetEcKey(const HcfPoint *pubKey, const HcfBigInteger *priKey, EC_KEY *ecKey);
HcfResult GetCurveGFp(const EC_GROUP *group, const AsyKeySpecItem item, HcfBigInteger *returnBigInteger);
HcfResult GetGenerator(const EC_GROUP *group, const AsyKeySpecItem item, HcfBigInteger *returnBigInteger);
HcfResult GetOrder(const EC_GROUP *group, HcfBigInteger *returnBigInteger);
HcfResult GetCofactor(const EC_GROUP *group, int *returnCofactor);
HcfResult GetFieldSize(const EC_GROUP *group, int32_t *fieldSize);
HcfResult GetFieldType(const HcfKey *self, const bool isPrivate, char **returnString);
HcfResult GetPkSkBigInteger(const HcfKey *self, bool isPrivate,
    const AsyKeySpecItem item, HcfBigInteger *returnBigInteger);
HcfResult HcfSetPubKeyDataToNewEcKey(EC_KEY *ecKey, EC_KEY **returnEcKey);
#ifdef __cplusplus
}
#endif

#endif
