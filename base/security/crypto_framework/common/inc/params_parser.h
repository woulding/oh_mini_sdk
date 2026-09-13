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

#ifndef HCF_PARAMS_PARSER_H
#define HCF_PARAMS_PARSER_H

#include <stdint.h>
#include "result.h"

typedef enum {
    HCF_ALG_TYPE = 1,
    HCF_ALG_KEY_TYPE,
    HCF_ALG_MODE,
    HCF_ALG_PADDING_TYPE,
    HCF_ALG_PRIMES,
    HCF_ALG_DIGEST,
    HCF_ALG_MGF1_DIGEST,
    HCF_ALG_TEXT_FORMAT,
    HCF_ALG_SIGN_TYPE,
    HCF_ALG_VERIFY_TYPE,
} HcfAlgParaType;

typedef enum {
    HCF_ALG_AES = 1,
    HCF_ALG_DES,
    HCF_ALG_3DES,
    HCF_ALG_RSA,
    HCF_ALG_ECC,
    HCF_ALG_DSA,
    HCF_ALG_SM2,
    HCF_ALG_SM4,
    HCF_ALG_HMAC,
    HCF_ALG_PKBDF2,
    HCF_ALG_ECC_BRAINPOOL,
    HCF_ALG_ED25519,
    HCF_ALG_X25519,
    HCF_ALG_DH,
    HCF_ALG_HKDF,
    HCF_ALG_SCRYPT,
    HCF_ALG_X963KDF,
    HCF_ALG_AES_WRAP,
    HCF_ALG_CHACHA20,
    HCF_ALG_CHACHA20_POLY1305,
    HCF_ALG_RC2,
    HCF_ALG_RC4,
    HCF_ALG_BLOWFISH,
    HCF_ALG_CAST,
    HCF_ALG_ML_KEM,
    HCF_ALG_ML_DSA,
} HcfAlgValue;

typedef enum {
    HCF_ALG_ECC_192 = 1,
    HCF_ALG_ECC_224,
    HCF_ALG_ECC_256,
    HCF_ALG_ECC_384,
    HCF_ALG_ECC_521,

    HCF_ALG_AES_128,
    HCF_ALG_AES_192,
    HCF_ALG_AES_256,
    HCF_ALG_AES_128_WRAP,
    HCF_ALG_AES_192_WRAP,
    HCF_ALG_AES_256_WRAP,
    HCF_ALG_SM4_128,
    HCF_ALG_DES_64,
    HCF_ALG_3DES_192,
    HCF_ALG_CHACHA20_256,

    HCF_ALG_MODE_NONE,
    HCF_ALG_MODE_ECB,
    HCF_ALG_MODE_CBC,
    HCF_ALG_MODE_CTR,
    HCF_ALG_MODE_OFB,
    HCF_ALG_MODE_CFB,
    HCF_ALG_MODE_CFB1,
    HCF_ALG_MODE_CFB8,
    HCF_ALG_MODE_CFB64,
    HCF_ALG_MODE_CFB128,
    HCF_ALG_MODE_CCM,
    HCF_ALG_MODE_GCM,
    HCF_ALG_MODE_XTS,
    HCF_ALG_MODE_WRAP,
    HCF_ALG_MODE_POLY1305,

    HCF_ALG_NOPADDING,
    HCF_ALG_PADDING_PKCS5,
    HCF_ALG_PADDING_PKCS7,

    // rsa keysize
    HCF_OPENSSL_RSA_512,
    HCF_OPENSSL_RSA_768,
    HCF_OPENSSL_RSA_1024,
    HCF_OPENSSL_RSA_2048,
    HCF_OPENSSL_RSA_3072,
    HCF_OPENSSL_RSA_4096,
    HCF_OPENSSL_RSA_8192,

    // rsa cipher padding,
    HCF_OPENSSL_RSA_PKCS1_PADDING,
    HCF_OPENSSL_RSA_PKCS1_OAEP_PADDING,
    HCF_OPENSSL_RSA_PSS_PADDING,

    // digest
    HCF_OPENSSL_DIGEST_NONE,
    HCF_OPENSSL_DIGEST_MD5,
    HCF_OPENSSL_DIGEST_SM3,
    HCF_OPENSSL_DIGEST_SHA1,
    HCF_OPENSSL_DIGEST_SHA224,
    HCF_OPENSSL_DIGEST_SHA256,
    HCF_OPENSSL_DIGEST_SHA384,
    HCF_OPENSSL_DIGEST_SHA512,
    HCF_OPENSSL_DIGEST_SHA3_256,
    HCF_OPENSSL_DIGEST_SHA3_384,
    HCF_OPENSSL_DIGEST_SHA3_512,

    // primes
    HCF_OPENSSL_PRIMES_2,
    HCF_OPENSSL_PRIMES_3,
    HCF_OPENSSL_PRIMES_4,
    HCF_OPENSSL_PRIMES_5,

    // dsa
    HCF_ALG_DSA_1024,
    HCF_ALG_DSA_2048,
    HCF_ALG_DSA_3072,

    // sm2
    HCF_ALG_SM2_256,

    // only for algName(NO SIZE)
    HCF_ALG_DSA_DEFAULT,
    HCF_ALG_RSA_DEFAULT,
    HCF_ALG_ECC_DEFAULT,
    HCF_ALG_SM2_DEFAULT,
    HCF_ALG_AES_DEFAULT,
    HCF_ALG_SM4_DEFAULT,
    HCF_ALG_DES_DEFAULT,
    HCF_ALG_3DES_DEFAULT,
    HCF_ALG_HMAC_DEFAULT,
    HCF_ALG_ECC_BRAINPOOL_DEFAULT,
    HCF_ALG_X25519_DEFAULT,
    HCF_ALG_DH_DEFAULT,
    HCF_ALG_AES_WRAP_DEFAULT,
    HCF_ALG_CHACHA20_DEFAULT,
    HCF_ALG_RC2_DEFAULT,
    HCF_ALG_RC4_DEFAULT,
    HCF_ALG_BLOWFISH_DEFAULT,
    HCF_ALG_CAST_DEFAULT,

    HCF_ALG_ML_KEM_DEFAULT,
    HCF_ALG_ML_DSA_DEFAULT,

    // key derivation function, PBKDF2
    HCF_ALG_PBKDF2_DEFAULT,

    // sm2 text format
    HCF_ALG_TEXT_FORMAT_C1C3C2,
    HCF_ALG_TEXT_FORMAT_C1C2C3,

    // brainpool
    HCF_ALG_ECC_BP160R1,
    HCF_ALG_ECC_BP160T1,
    HCF_ALG_ECC_BP192R1,
    HCF_ALG_ECC_BP192T1,
    HCF_ALG_ECC_BP224R1,
    HCF_ALG_ECC_BP224T1,
    HCF_ALG_ECC_BP256R1,
    HCF_ALG_ECC_BP256T1,
    HCF_ALG_ECC_BP320R1,
    HCF_ALG_ECC_BP320T1,
    HCF_ALG_ECC_BP384R1,
    HCF_ALG_ECC_BP384T1,
    HCF_ALG_ECC_BP512R1,
    HCF_ALG_ECC_BP512T1,

    HCF_ALG_ECC_SECP256K1,

    // ed25519
    HCF_ALG_ED25519_256,
    HCF_ALG_X25519_256,

    // ML-KEM keysize
    HCF_ALG_ML_KEM_512,
    HCF_ALG_ML_KEM_768,
    HCF_ALG_ML_KEM_1024,

    HCF_ALG_ML_DSA_44,
    HCF_ALG_ML_DSA_65,
    HCF_ALG_ML_DSA_87,

    // DH keysize
    HCF_OPENSSL_DH_MODP_1536,
    HCF_OPENSSL_DH_MODP_2048,
    HCF_OPENSSL_DH_MODP_3072,
    HCF_OPENSSL_DH_MODP_4096,
    HCF_OPENSSL_DH_MODP_6144,
    HCF_OPENSSL_DH_MODP_8192,
    HCF_OPENSSL_DH_FFDHE_2048,
    HCF_OPENSSL_DH_FFDHE_3072,
    HCF_OPENSSL_DH_FFDHE_4096,
    HCF_OPENSSL_DH_FFDHE_6144,
    HCF_OPENSSL_DH_FFDHE_8192,

    HCF_ALG_ONLY_SIGN,
    HCF_ALG_ONLY_VERIFY,
    HCF_ALG_VERIFY_RECOVER,
    // key derivation function, HKDF
    HCF_ALG_HKDF_DEFAULT,
    HCF_ALG_SCRYPT_DEFAULT,
    HCF_ALG_X963KDF_DEFAULT,

    // hkdf mode
    HCF_ALG_MODE_EXTRACT_AND_EXPAND,
    HCF_ALG_MODE_EXTRACT_ONLY,
    HCF_ALG_MODE_EXPAND_ONLY,
} HcfAlgParaValue;

typedef enum {
    HCF_OPERATION_ONLY_SIGN = 1,
    HCF_OPERATION_SIGN,
} HcfSignParams;

typedef enum {
    HCF_OPERATION_ONLY_VERIFY = 1,
    HCF_OPERATION_VERIFY,
} HcfVerifyParams;

typedef enum {
    HCF_UNCOMPRESSED_FORMAT_VALUE = 1,
    HCF_COMPRESSED_FORMAT_VALUE,
} HcfFormatValue;

typedef struct {
    const char *formatName;
    HcfFormatValue formatValue;
} HcfFormatMap;

typedef struct {
    const char *tag;
    HcfAlgParaType paraType;
    HcfAlgParaValue paraValue;
} HcfParaConfig;

typedef struct {
    const char *algNameStr;
    HcfAlgValue algValue;
} HcfAlgMap;

typedef struct {
    const char *curveNameStr;
    HcfAlgParaValue algValue;
} HcfCurveMap;

typedef struct {
    HcfAlgValue algo;
    HcfAlgParaValue keySize;
    HcfAlgParaValue mode;
    HcfAlgParaValue paddingMode;
    HcfAlgParaValue md;
    HcfAlgParaValue mgf1md;
} CipherAttr;

typedef struct {
    HcfAlgValue algo; // algType
    int32_t bits; // keyLen
    int32_t primes; // number of primes
} HcfAsyKeyGenParams;

typedef struct {
    HcfAlgValue algo; // algType
    HcfAlgParaValue padding;
    HcfAlgParaValue md;
    HcfAlgParaValue mgf1md;
    HcfAlgParaValue operation;
} HcfSignatureParams;

typedef struct {
    HcfAlgValue algo;
} HcfKeyAgreementParams;

typedef struct {
    HcfAlgValue algo; // algType
    HcfAlgParaValue md;
    HcfAlgParaValue mode;
} HcfKdfDeriveParams;

typedef HcfResult (*SetParameterFunc) (const HcfParaConfig* config, void *params);

#ifdef __cplusplus
extern "C" {
#endif

HcfResult ParseAndSetParameter(const char *paramsStr, void *params, SetParameterFunc setFunc);

HcfResult ParseAlgNameToParams(const char *algNameStr, HcfAsyKeyGenParams *params);

HcfResult ParseCurveNameToParams(const char *curveNameStr, HcfAsyKeyGenParams *params);

HcfResult GetAlgValueByCurveName(const char *curveNameStr, HcfAlgParaValue *algValue);

HcfResult GetFormatValueByFormatName(const char *formatName, HcfFormatValue *formatValue);

#ifdef __cplusplus
}
#endif
#endif
