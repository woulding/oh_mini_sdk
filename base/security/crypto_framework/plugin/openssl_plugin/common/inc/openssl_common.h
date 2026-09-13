/*
 * Copyright (C) 2022-2024 Huawei Device Co., Ltd.
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

#ifndef HCF_OPENSSL_COMMON_H
#define HCF_OPENSSL_COMMON_H

#include <stdint.h>
#include <stdbool.h>
#include <openssl/bn.h>
#include <openssl/ec.h>
#include <openssl/evp.h>
#include <openssl/rsa.h>

#include "big_integer.h"
#include "params_parser.h"
#include "result.h"
#include "utils.h"
#include "algorithm_parameter.h"

#define HCF_OPENSSL_SUCCESS 1     /* openssl return 1: success */
#define HCF_BITS_PER_BYTE 8

typedef enum {
    UNINITIALIZED = 0,
    INITIALIZED = 1,
    READY = 2,
} CryptoStatus;

#ifdef __cplusplus
extern "C" {
#endif

HcfResult GetCurveNameByCurveId(int32_t curveId, char **curveName);
HcfResult GetNidByCurveNameValue(int32_t curveNameValue, int32_t *nid);
HcfResult GetGroupNameByNid(int32_t nid, char **groupName);
HcfResult GetFormatTypeByFormatValue(int32_t formatValue, int32_t *formatType);
HcfResult GetAlgNameByBits(int32_t keyLen, char **algName);
HcfResult GetOpensslCurveId(int32_t keyLen, int32_t *returnCurveId);
HcfResult GetOpensslDigestAlg(uint32_t alg, EVP_MD **digestAlg);
void HcfPrintOpensslError(void);

HcfResult GetOpensslPadding(int32_t padding, int32_t *opensslPadding);

bool IsBigEndian(void);

HcfResult BigIntegerToBigNum(const HcfBigInteger *src, BIGNUM **dest);

HcfResult BigNumToBigInteger(const BIGNUM *src, HcfBigInteger *dest);

HcfResult BigNumToBigIntegerSecp256k1(const BIGNUM *src, HcfBigInteger *dest);

HcfResult GetRsaSpecStringMd(const HcfAlgParaValue md, char **returnString);

HcfResult GetRsaSpecStringMGF(char **returnString);

HcfResult GetSm2SpecStringSm3(char **returnString);

HcfResult KeyDerive(EVP_PKEY *priKey, EVP_PKEY *pubKey, HcfBlob *returnSecret);

HcfResult GetKeyEncoded(EVP_PKEY *pkey, const char *outPutStruct, const char *format, int selection,
    HcfBlob *returnBlob);

HcfResult ConvertPubPemStrToKey(EVP_PKEY **pkey, const char *keyType, int selection, const char *keyStr);

HcfResult ConvertPriPemStrToKey(const char *keyStr, EVP_PKEY **pkey, const char *keyType);

#ifdef __cplusplus
}
#endif

#endif
