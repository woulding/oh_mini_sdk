/*
 * Copyright (C) 2022-2026 Huawei Device Co., Ltd.
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

#include "params_parser.h"

#include <stdbool.h>
#include <stddef.h>
#include <string.h>
#include "hcf_string.h"
#include "log.h"

static const HcfParaConfig PARAM_CONFIG[] = {
    {"ECC192",       HCF_ALG_KEY_TYPE,       HCF_ALG_ECC_192},
    {"ECC224",       HCF_ALG_KEY_TYPE,       HCF_ALG_ECC_224},
    {"ECC256",       HCF_ALG_KEY_TYPE,       HCF_ALG_ECC_256},
    {"ECC384",       HCF_ALG_KEY_TYPE,       HCF_ALG_ECC_384},
    {"ECC521",       HCF_ALG_KEY_TYPE,       HCF_ALG_ECC_521},

    {"AES128",       HCF_ALG_KEY_TYPE,       HCF_ALG_AES_128},
    {"AES192",       HCF_ALG_KEY_TYPE,       HCF_ALG_AES_192},
    {"AES256",       HCF_ALG_KEY_TYPE,       HCF_ALG_AES_256},
    {"AES128-WRAP",  HCF_ALG_KEY_TYPE,       HCF_ALG_AES_128_WRAP},
    {"AES192-WRAP",  HCF_ALG_KEY_TYPE,       HCF_ALG_AES_192_WRAP},
    {"AES256-WRAP",  HCF_ALG_KEY_TYPE,       HCF_ALG_AES_256_WRAP},
    {"SM4_128",      HCF_ALG_KEY_TYPE,       HCF_ALG_SM4_128},
    {"3DES192",      HCF_ALG_KEY_TYPE,       HCF_ALG_3DES_192},
    {"DES64",        HCF_ALG_KEY_TYPE,       HCF_ALG_DES_64},
    {"ChaCha20", HCF_ALG_KEY_TYPE,           HCF_ALG_CHACHA20_256},

    {"ECB",          HCF_ALG_MODE,           HCF_ALG_MODE_ECB},
    {"CBC",          HCF_ALG_MODE,           HCF_ALG_MODE_CBC},
    {"CTR",          HCF_ALG_MODE,           HCF_ALG_MODE_CTR},
    {"OFB",          HCF_ALG_MODE,           HCF_ALG_MODE_OFB},
    {"CFB",          HCF_ALG_MODE,           HCF_ALG_MODE_CFB},
    {"CFB1",         HCF_ALG_MODE,           HCF_ALG_MODE_CFB1},
    {"CFB8",         HCF_ALG_MODE,           HCF_ALG_MODE_CFB8},
    {"CFB64",        HCF_ALG_MODE,           HCF_ALG_MODE_CFB64},
    {"CFB128",       HCF_ALG_MODE,           HCF_ALG_MODE_CFB128},
    {"CCM",          HCF_ALG_MODE,           HCF_ALG_MODE_CCM},
    {"GCM",          HCF_ALG_MODE,           HCF_ALG_MODE_GCM},
    {"XTS",          HCF_ALG_MODE,           HCF_ALG_MODE_XTS},
    {"WRAP",         HCF_ALG_MODE,           HCF_ALG_MODE_WRAP},
    {"Poly1305",     HCF_ALG_MODE,           HCF_ALG_MODE_POLY1305},

    {"NoPadding",    HCF_ALG_PADDING_TYPE,   HCF_ALG_NOPADDING},
    {"PKCS5",        HCF_ALG_PADDING_TYPE,   HCF_ALG_PADDING_PKCS5},
    {"PKCS7",        HCF_ALG_PADDING_TYPE,   HCF_ALG_PADDING_PKCS7},

    {"RSA512",        HCF_ALG_KEY_TYPE,       HCF_OPENSSL_RSA_512},
    {"RSA768",        HCF_ALG_KEY_TYPE,       HCF_OPENSSL_RSA_768},
    {"RSA1024",       HCF_ALG_KEY_TYPE,       HCF_OPENSSL_RSA_1024},
    {"RSA2048",       HCF_ALG_KEY_TYPE,       HCF_OPENSSL_RSA_2048},
    {"RSA3072",       HCF_ALG_KEY_TYPE,       HCF_OPENSSL_RSA_3072},
    {"RSA4096",       HCF_ALG_KEY_TYPE,       HCF_OPENSSL_RSA_4096},
    {"RSA8192",       HCF_ALG_KEY_TYPE,       HCF_OPENSSL_RSA_8192},

    {"DH_modp1536",       HCF_ALG_KEY_TYPE,       HCF_OPENSSL_DH_MODP_1536},
    {"DH_modp2048",       HCF_ALG_KEY_TYPE,       HCF_OPENSSL_DH_MODP_2048},
    {"DH_modp3072",       HCF_ALG_KEY_TYPE,       HCF_OPENSSL_DH_MODP_3072},
    {"DH_modp4096",       HCF_ALG_KEY_TYPE,       HCF_OPENSSL_DH_MODP_4096},
    {"DH_modp6144",       HCF_ALG_KEY_TYPE,       HCF_OPENSSL_DH_MODP_6144},
    {"DH_modp8192",       HCF_ALG_KEY_TYPE,       HCF_OPENSSL_DH_MODP_8192},

    {"DH_ffdhe2048",       HCF_ALG_KEY_TYPE,       HCF_OPENSSL_DH_FFDHE_2048},
    {"DH_ffdhe3072",       HCF_ALG_KEY_TYPE,       HCF_OPENSSL_DH_FFDHE_3072},
    {"DH_ffdhe4096",       HCF_ALG_KEY_TYPE,       HCF_OPENSSL_DH_FFDHE_4096},
    {"DH_ffdhe6144",       HCF_ALG_KEY_TYPE,       HCF_OPENSSL_DH_FFDHE_6144},
    {"DH_ffdhe8192",       HCF_ALG_KEY_TYPE,       HCF_OPENSSL_DH_FFDHE_8192},

    {"PKCS1",        HCF_ALG_PADDING_TYPE,   HCF_OPENSSL_RSA_PKCS1_PADDING},
    {"PKCS1_OAEP",   HCF_ALG_PADDING_TYPE,   HCF_OPENSSL_RSA_PKCS1_OAEP_PADDING},
    {"PSS",          HCF_ALG_PADDING_TYPE,   HCF_OPENSSL_RSA_PSS_PADDING},

    {"NoHash",       HCF_ALG_DIGEST,         HCF_OPENSSL_DIGEST_NONE},
    {"MD5",          HCF_ALG_DIGEST,         HCF_OPENSSL_DIGEST_MD5},
    {"SM3",          HCF_ALG_DIGEST,         HCF_OPENSSL_DIGEST_SM3},
    {"SHA1",         HCF_ALG_DIGEST,         HCF_OPENSSL_DIGEST_SHA1},
    {"SHA224",       HCF_ALG_DIGEST,         HCF_OPENSSL_DIGEST_SHA224},
    {"SHA256",       HCF_ALG_DIGEST,         HCF_OPENSSL_DIGEST_SHA256},
    {"SHA384",       HCF_ALG_DIGEST,         HCF_OPENSSL_DIGEST_SHA384},
    {"SHA512",       HCF_ALG_DIGEST,         HCF_OPENSSL_DIGEST_SHA512},
    {"SHA3-256",     HCF_ALG_DIGEST,         HCF_OPENSSL_DIGEST_SHA3_256},
    {"SHA3-384",     HCF_ALG_DIGEST,         HCF_OPENSSL_DIGEST_SHA3_384},
    {"SHA3-512",     HCF_ALG_DIGEST,         HCF_OPENSSL_DIGEST_SHA3_512},

    {"MGF1_MD5",          HCF_ALG_MGF1_DIGEST,         HCF_OPENSSL_DIGEST_MD5},
    {"MGF1_SHA1",         HCF_ALG_MGF1_DIGEST,         HCF_OPENSSL_DIGEST_SHA1},
    {"MGF1_SHA224",       HCF_ALG_MGF1_DIGEST,         HCF_OPENSSL_DIGEST_SHA224},
    {"MGF1_SHA256",       HCF_ALG_MGF1_DIGEST,         HCF_OPENSSL_DIGEST_SHA256},
    {"MGF1_SHA384",       HCF_ALG_MGF1_DIGEST,         HCF_OPENSSL_DIGEST_SHA384},
    {"MGF1_SHA512",       HCF_ALG_MGF1_DIGEST,         HCF_OPENSSL_DIGEST_SHA512},

    {"PRIMES_2",          HCF_ALG_PRIMES,              HCF_OPENSSL_PRIMES_2},
    {"PRIMES_3",          HCF_ALG_PRIMES,              HCF_OPENSSL_PRIMES_3},
    {"PRIMES_4",          HCF_ALG_PRIMES,              HCF_OPENSSL_PRIMES_4},
    {"PRIMES_5",          HCF_ALG_PRIMES,              HCF_OPENSSL_PRIMES_5},

    {"DSA1024",       HCF_ALG_KEY_TYPE,       HCF_ALG_DSA_1024},
    {"DSA2048",       HCF_ALG_KEY_TYPE,       HCF_ALG_DSA_2048},
    {"DSA3072",       HCF_ALG_KEY_TYPE,       HCF_ALG_DSA_3072},

    {"SM2_256",       HCF_ALG_KEY_TYPE,       HCF_ALG_SM2_256},

    {"RSA",       HCF_ALG_TYPE,       HCF_ALG_RSA_DEFAULT},
    {"DSA",       HCF_ALG_TYPE,       HCF_ALG_DSA_DEFAULT},
    {"ECC",       HCF_ALG_TYPE,       HCF_ALG_ECC_DEFAULT},
    {"SM2",       HCF_ALG_TYPE,       HCF_ALG_SM2_DEFAULT},
    {"AES",       HCF_ALG_TYPE,       HCF_ALG_AES_DEFAULT},
    {"SM4",       HCF_ALG_TYPE,       HCF_ALG_SM4_DEFAULT},
    {"DES",      HCF_ALG_TYPE,       HCF_ALG_DES_DEFAULT},
    {"3DES",      HCF_ALG_TYPE,       HCF_ALG_3DES_DEFAULT},
    {"HMAC",      HCF_ALG_TYPE,       HCF_ALG_HMAC_DEFAULT},
    {"PBKDF2",    HCF_ALG_TYPE,       HCF_ALG_PBKDF2_DEFAULT},
    {"HKDF",      HCF_ALG_TYPE,       HCF_ALG_HKDF_DEFAULT},
    {"SCRYPT",      HCF_ALG_TYPE,       HCF_ALG_SCRYPT_DEFAULT},
    {"X963KDF",      HCF_ALG_TYPE,       HCF_ALG_X963KDF_DEFAULT},
    {"EXTRACT_AND_EXPAND",          HCF_ALG_MODE,           HCF_ALG_MODE_EXTRACT_AND_EXPAND},
    {"EXTRACT_ONLY",                HCF_ALG_MODE,           HCF_ALG_MODE_EXTRACT_ONLY},
    {"EXPAND_ONLY",                 HCF_ALG_MODE,           HCF_ALG_MODE_EXPAND_ONLY},
    {"ECC_BP",    HCF_ALG_TYPE,       HCF_ALG_ECC_BRAINPOOL_DEFAULT},
    {"X25519_BP",    HCF_ALG_TYPE,       HCF_ALG_X25519_DEFAULT},
    {"DH",       HCF_ALG_TYPE,       HCF_ALG_DH_DEFAULT},
    {"AES_WRAP",       HCF_ALG_TYPE,       HCF_ALG_AES_WRAP_DEFAULT},
    {"ChaCha20", HCF_ALG_TYPE,       HCF_ALG_CHACHA20_DEFAULT},
    {"RC2",       HCF_ALG_TYPE,       HCF_ALG_RC2_DEFAULT},
    {"RC4",       HCF_ALG_TYPE,       HCF_ALG_RC4_DEFAULT},
    {"Blowfish",  HCF_ALG_TYPE,       HCF_ALG_BLOWFISH_DEFAULT},
    {"CAST",      HCF_ALG_TYPE,       HCF_ALG_CAST_DEFAULT},
    {"ML-KEM",    HCF_ALG_TYPE,       HCF_ALG_ML_KEM_DEFAULT},
    {"ML-DSA",    HCF_ALG_TYPE,       HCF_ALG_ML_DSA_DEFAULT},

    {"C1C3C2",    HCF_ALG_TEXT_FORMAT, HCF_ALG_TEXT_FORMAT_C1C3C2},
    {"C1C2C3",    HCF_ALG_TEXT_FORMAT, HCF_ALG_TEXT_FORMAT_C1C2C3},

    {"ECC_BrainPoolP160r1",       HCF_ALG_KEY_TYPE,       HCF_ALG_ECC_BP160R1},
    {"ECC_BrainPoolP160t1",       HCF_ALG_KEY_TYPE,       HCF_ALG_ECC_BP160T1},
    {"ECC_BrainPoolP192r1",       HCF_ALG_KEY_TYPE,       HCF_ALG_ECC_BP192R1},
    {"ECC_BrainPoolP192t1",       HCF_ALG_KEY_TYPE,       HCF_ALG_ECC_BP192T1},
    {"ECC_BrainPoolP224r1",       HCF_ALG_KEY_TYPE,       HCF_ALG_ECC_BP224R1},
    {"ECC_BrainPoolP224t1",       HCF_ALG_KEY_TYPE,       HCF_ALG_ECC_BP224T1},
    {"ECC_BrainPoolP256r1",       HCF_ALG_KEY_TYPE,       HCF_ALG_ECC_BP256R1},
    {"ECC_BrainPoolP256t1",       HCF_ALG_KEY_TYPE,       HCF_ALG_ECC_BP256T1},
    {"ECC_BrainPoolP320r1",       HCF_ALG_KEY_TYPE,       HCF_ALG_ECC_BP320R1},
    {"ECC_BrainPoolP320t1",       HCF_ALG_KEY_TYPE,       HCF_ALG_ECC_BP320T1},
    {"ECC_BrainPoolP384r1",       HCF_ALG_KEY_TYPE,       HCF_ALG_ECC_BP384R1},
    {"ECC_BrainPoolP384t1",       HCF_ALG_KEY_TYPE,       HCF_ALG_ECC_BP384T1},
    {"ECC_BrainPoolP512r1",       HCF_ALG_KEY_TYPE,       HCF_ALG_ECC_BP512R1},
    {"ECC_BrainPoolP512t1",       HCF_ALG_KEY_TYPE,       HCF_ALG_ECC_BP512T1},
    {"ECC_Secp256k1",             HCF_ALG_KEY_TYPE,       HCF_ALG_ECC_SECP256K1},

    {"Ed25519",       HCF_ALG_KEY_TYPE,       HCF_ALG_ED25519_256},
    {"X25519",       HCF_ALG_KEY_TYPE,       HCF_ALG_X25519_256},

    {"ML-KEM-512",   HCF_ALG_KEY_TYPE,       HCF_ALG_ML_KEM_512},
    {"ML-KEM-768",   HCF_ALG_KEY_TYPE,       HCF_ALG_ML_KEM_768},
    {"ML-KEM-1024",  HCF_ALG_KEY_TYPE,       HCF_ALG_ML_KEM_1024},

    {"ML-DSA-44",    HCF_ALG_KEY_TYPE,       HCF_ALG_ML_DSA_44},
    {"ML-DSA-65",    HCF_ALG_KEY_TYPE,       HCF_ALG_ML_DSA_65},
    {"ML-DSA-87",    HCF_ALG_KEY_TYPE,       HCF_ALG_ML_DSA_87},

    {"OnlySign",      HCF_ALG_SIGN_TYPE,       HCF_ALG_ONLY_SIGN},
    {"OnlyVerify",    HCF_ALG_VERIFY_TYPE,     HCF_ALG_ONLY_VERIFY},
    {"Recover",       HCF_ALG_VERIFY_TYPE,       HCF_ALG_VERIFY_RECOVER}
};

static const HcfAlgMap ALG_MAP[] = {
    {"DSA", HCF_ALG_DSA},
    {"RSA", HCF_ALG_RSA},
    {"ECC", HCF_ALG_ECC},
    {"SM2", HCF_ALG_SM2},
    {"Ed25519", HCF_ALG_ED25519},
    {"X25519", HCF_ALG_X25519},
    {"DH", HCF_ALG_DH},
    {"ML-KEM", HCF_ALG_ML_KEM},
    {"ML-DSA", HCF_ALG_ML_DSA}
};

static const HcfCurveMap CURVE_MAP[] = {
    {"NID_X9_62_prime192v1", HCF_ALG_ECC_192},
    {"NID_secp224r1", HCF_ALG_ECC_224},
    {"NID_X9_62_prime256v1", HCF_ALG_ECC_256},
    {"NID_secp384r1", HCF_ALG_ECC_384},
    {"NID_secp521r1", HCF_ALG_ECC_521},
    {"NID_sm2", HCF_ALG_SM2_256},
    {"NID_brainpoolP160r1", HCF_ALG_ECC_BP160R1},
    {"NID_brainpoolP160t1", HCF_ALG_ECC_BP160T1},
    {"NID_brainpoolP192r1", HCF_ALG_ECC_BP192R1},
    {"NID_brainpoolP192t1", HCF_ALG_ECC_BP192T1},
    {"NID_brainpoolP224r1", HCF_ALG_ECC_BP224R1},
    {"NID_brainpoolP224t1", HCF_ALG_ECC_BP224T1},
    {"NID_brainpoolP256r1", HCF_ALG_ECC_BP256R1},
    {"NID_brainpoolP256t1", HCF_ALG_ECC_BP256T1},
    {"NID_brainpoolP320r1", HCF_ALG_ECC_BP320R1},
    {"NID_brainpoolP320t1", HCF_ALG_ECC_BP320T1},
    {"NID_brainpoolP384r1", HCF_ALG_ECC_BP384R1},
    {"NID_brainpoolP384t1", HCF_ALG_ECC_BP384T1},
    {"NID_brainpoolP512r1", HCF_ALG_ECC_BP512R1},
    {"NID_brainpoolP512t1", HCF_ALG_ECC_BP512T1},
    {"NID_secp256k1", HCF_ALG_ECC_SECP256K1},
};

static const HcfFormatMap FORMAT_MAP[] = {
    {"UNCOMPRESSED", HCF_UNCOMPRESSED_FORMAT_VALUE},
    {"COMPRESSED", HCF_COMPRESSED_FORMAT_VALUE}
};

static const HcfParaConfig *FindConfig(const HcString* tag)
{
    if (tag == NULL) {
        LOGE("Tag is null when looking up config");
        return NULL;
    }

    for (uint32_t i = 0; i < sizeof(PARAM_CONFIG) / sizeof(HcfParaConfig); ++i) {
        if (StringCompare(tag, PARAM_CONFIG[i].tag) == 0) {
            return &PARAM_CONFIG[i];
        }
    }
    LOGE("Config not found for given tag");
    return NULL;
}

HcfResult ParseAndSetParameter(const char *paramsStr, void *params, SetParameterFunc setFunc)
{
    if (paramsStr == NULL || setFunc == NULL) {
        LOGE("ParamsStr or setFunc is null");
        return HCF_INVALID_PARAMS;
    }
    HcString str = CreateString();
    HcString subStr = CreateString();
    if (!StringSetPointer(&str, paramsStr)) {
        LOGE("Failed to set string pointer for parameter parsing");
        DeleteString(&subStr);
        DeleteString(&str);
        return HCF_INVALID_PARAMS;
    }
    HcfResult ret = HCF_INVALID_PARAMS;
    uint32_t pos = 0;
    do {
        int findPos = StringFind(&str, '|', pos);
        if (findPos >= 0) {
            if (!StringSubString(&str, pos, findPos - pos, &subStr)) {
                LOGE("StringSubString failed!");
                break;
            }
            ret = (*setFunc)(FindConfig(&subStr), params);
            if (ret != HCF_SUCCESS) {
                break;
            }
            pos = findPos + 1;
        } else {
            uint32_t strLen = StringLength(&str);
            if (strLen < pos) {
                break;
            }
            if (!StringSubString(&str, pos, strLen - pos, &subStr)) {
                LOGE("Get last string failed!");
                break;
            }
            ret = (*setFunc)(FindConfig(&subStr), params);
            break;
        }
    } while (true);

    DeleteString(&subStr);
    DeleteString(&str);
    return ret;
}

HcfResult ParseAlgNameToParams(const char *algNameStr, HcfAsyKeyGenParams *params)
{
    if (algNameStr == NULL || params == NULL) {
        LOGE("AlgNameStr or params is null");
        return HCF_INVALID_PARAMS;
    }
    for (uint32_t i = 0; i < sizeof(ALG_MAP) / sizeof(HcfAlgMap); ++i) {
        if (strcmp(algNameStr, ALG_MAP[i].algNameStr) == 0) {
            params->algo = ALG_MAP[i].algValue;
            params->bits = 0;
            return HCF_SUCCESS;
        }
    }
    LOGE("Not support algorithm name!");
    return HCF_INVALID_PARAMS;
}

HcfResult ParseCurveNameToParams(const char *curveNameStr, HcfAsyKeyGenParams *params)
{
    if (curveNameStr == NULL || params == NULL) {
        LOGE("CurveName to Params failed!");
        return HCF_INVALID_PARAMS;
    }
    for (uint32_t i = 0; i < sizeof(CURVE_MAP) / sizeof(HcfCurveMap); ++i) {
        if (strcmp(curveNameStr, CURVE_MAP[i].curveNameStr) == 0) {
            params->algo = HCF_ALG_ECC;
            params->bits = CURVE_MAP[i].algValue;
            return HCF_SUCCESS;
        }
    }
    LOGE("Not support algorithm name: %{public}s", curveNameStr);
    return HCF_NOT_SUPPORT;
}

HcfResult GetAlgValueByCurveName(const char *curveNameStr, HcfAlgParaValue *algValue)
{
    if (curveNameStr == NULL || algValue == NULL) {
        LOGE("Invalid parameter!");
        return HCF_INVALID_PARAMS;
    }
    for (uint32_t i = 0; i < sizeof(CURVE_MAP) / sizeof(CURVE_MAP[0]); i++) {
        if (strcmp(CURVE_MAP[i].curveNameStr, curveNameStr) == 0) {
            *algValue = CURVE_MAP[i].algValue;
            return HCF_SUCCESS;
        }
    }
    LOGE("Invalid curve name: %{public}s", curveNameStr);
    return HCF_INVALID_PARAMS;
}

HcfResult GetFormatValueByFormatName(const char *formatName, HcfFormatValue *formatValue)
{
    if (formatName == NULL || formatValue == NULL) {
        LOGE("Invalid parameter!");
        return HCF_INVALID_PARAMS;
    }

    for (uint32_t i = 0; i < sizeof(FORMAT_MAP) / sizeof(FORMAT_MAP[0]); i++) {
        if (strcmp(FORMAT_MAP[i].formatName, formatName) == 0) {
            *formatValue = FORMAT_MAP[i].formatValue;
            return HCF_SUCCESS;
        }
    }
    LOGE("Invalid format name: %{public}s", formatName);
    return HCF_INVALID_PARAMS;
}
