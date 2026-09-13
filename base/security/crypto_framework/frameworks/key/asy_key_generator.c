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

#include "asy_key_generator.h"

#include <securec.h>

#include "asy_key_generator_spi.h"
#include "config.h"
#include "detailed_alg_25519_key_params.h"
#include "detailed_dh_key_params.h"
#include "detailed_dsa_key_params.h"
#include "detailed_rsa_key_params.h"
#include "detailed_ecc_key_params.h"
#include "dh_asy_key_generator_openssl.h"
#include "dsa_asy_key_generator_openssl.h"
#include "alg_25519_asy_key_generator_openssl.h"
#include "ml_kem_asy_key_generator_openssl.h"
#include "ml_dsa_asy_key_generator_openssl.h"
#include "ecc_asy_key_generator_openssl.h"
#include "key_utils.h"
#include "params_parser.h"
#include "rsa_asy_key_generator_openssl.h"
#include "sm2_asy_key_generator_openssl.h"
#include "log.h"
#include "memory.h"
#include "utils.h"

#define ALG_NAME_DSA "DSA"
#define ALG_NAME_ECC "ECC"
#define ALG_NAME_SM2 "SM2"
#define ALG_NAME_RSA "RSA"
#define ALG_NAME_DH "DH"
#define ALG_NAME_X25519 "X25519"
#define ALG_NAME_ED25519 "Ed25519"
#define ALG_NAME_ML_KEM "ML-KEM"
#define ALG_NAME_ML_DSA "ML-DSA"
#define ASY_KEY_GENERATOR_CLASS "HcfAsyKeyGenerator"
#define ASY_KEY_GENERATOR_BY_SPEC_CLASS "HcfAsyKeyGeneratorBySpec"

typedef HcfResult (*HcfAsyKeyGeneratorSpiCreateFunc)(HcfAsyKeyGenParams *, HcfAsyKeyGeneratorSpi **);

typedef struct {
    HcfAsyKeyGenerator base;

    HcfAsyKeyGeneratorSpi *spiObj;

    char algoName[HCF_MAX_ALGO_NAME_LEN];
} HcfAsyKeyGeneratorImpl;

typedef struct {
    HcfAsyKeyGeneratorBySpec base;

    HcfAsyKeyGeneratorSpi *spiObj;

    HcfAsyKeyParamsSpec *paramsSpec;
} HcfAsyKeyGeneratorBySpecImpl;

typedef struct {
    HcfAlgValue algo;

    HcfAsyKeyGeneratorSpiCreateFunc createSpiFunc;
} HcfAsyKeyGenAbility;

static const HcfAsyKeyGenAbility ASY_KEY_GEN_ABILITY_SET[] = {
    { HCF_ALG_RSA, HcfAsyKeyGeneratorSpiRsaCreate },
    { HCF_ALG_ECC, HcfAsyKeyGeneratorSpiEccCreate },
    { HCF_ALG_DSA, HcfAsyKeyGeneratorSpiDsaCreate },
    { HCF_ALG_SM2, HcfAsyKeyGeneratorSpiSm2Create },
    { HCF_ALG_ED25519, HcfAsyKeyGeneratorSpiEd25519Create },
    { HCF_ALG_X25519, HcfAsyKeyGeneratorSpiX25519Create },
    { HCF_ALG_DH, HcfAsyKeyGeneratorSpiDhCreate },
    { HCF_ALG_ML_KEM, HcfAsyKeyGeneratorSpiMlKemCreate },
    { HCF_ALG_ML_DSA, HcfAsyKeyGeneratorSpiMlDsaCreate }
};

typedef struct {
    HcfAlgParaValue value;
    int32_t bits; // keyLen
    HcfAlgValue algo; // algType
} KeyTypeAlg;

static const KeyTypeAlg KEY_TYPE_MAP[] = {
    { HCF_ALG_ECC_192, HCF_ALG_ECC_192, HCF_ALG_ECC },
    { HCF_ALG_ECC_224, HCF_ALG_ECC_224, HCF_ALG_ECC },
    { HCF_ALG_ECC_256, HCF_ALG_ECC_256, HCF_ALG_ECC },
    { HCF_ALG_ECC_384, HCF_ALG_ECC_384, HCF_ALG_ECC },
    { HCF_ALG_ECC_521, HCF_ALG_ECC_521, HCF_ALG_ECC },
    { HCF_OPENSSL_RSA_512, HCF_RSA_KEY_SIZE_512, HCF_ALG_RSA },
    { HCF_OPENSSL_RSA_768, HCF_RSA_KEY_SIZE_768, HCF_ALG_RSA },
    { HCF_OPENSSL_RSA_1024, HCF_RSA_KEY_SIZE_1024, HCF_ALG_RSA },
    { HCF_OPENSSL_RSA_2048, HCF_RSA_KEY_SIZE_2048, HCF_ALG_RSA },
    { HCF_OPENSSL_RSA_3072, HCF_RSA_KEY_SIZE_3072, HCF_ALG_RSA },
    { HCF_OPENSSL_RSA_4096, HCF_RSA_KEY_SIZE_4096, HCF_ALG_RSA },
    { HCF_OPENSSL_RSA_4096, HCF_RSA_KEY_SIZE_4096, HCF_ALG_RSA },
    { HCF_OPENSSL_RSA_8192, HCF_RSA_KEY_SIZE_8192, HCF_ALG_RSA },
    { HCF_ALG_DSA_1024, HCF_DSA_KEY_SIZE_1024, HCF_ALG_DSA },
    { HCF_ALG_DSA_2048, HCF_DSA_KEY_SIZE_2048, HCF_ALG_DSA },
    { HCF_ALG_DSA_3072, HCF_DSA_KEY_SIZE_3072, HCF_ALG_DSA },
    { HCF_ALG_SM2_256, HCF_ALG_SM2_256, HCF_ALG_SM2 },
    { HCF_ALG_ECC_BP160R1, HCF_ALG_ECC_BP160R1, HCF_ALG_ECC },
    { HCF_ALG_ECC_BP160T1, HCF_ALG_ECC_BP160T1, HCF_ALG_ECC },
    { HCF_ALG_ECC_BP192R1, HCF_ALG_ECC_BP192R1, HCF_ALG_ECC },
    { HCF_ALG_ECC_BP192T1, HCF_ALG_ECC_BP192T1, HCF_ALG_ECC },
    { HCF_ALG_ECC_BP224R1, HCF_ALG_ECC_BP224R1, HCF_ALG_ECC },
    { HCF_ALG_ECC_BP224T1, HCF_ALG_ECC_BP224T1, HCF_ALG_ECC },
    { HCF_ALG_ECC_BP256R1, HCF_ALG_ECC_BP256R1, HCF_ALG_ECC },
    { HCF_ALG_ECC_BP256T1, HCF_ALG_ECC_BP256T1, HCF_ALG_ECC },
    { HCF_ALG_ECC_BP320R1, HCF_ALG_ECC_BP320R1, HCF_ALG_ECC },
    { HCF_ALG_ECC_BP320T1, HCF_ALG_ECC_BP320T1, HCF_ALG_ECC },
    { HCF_ALG_ECC_BP384R1, HCF_ALG_ECC_BP384R1, HCF_ALG_ECC },
    { HCF_ALG_ECC_BP384T1, HCF_ALG_ECC_BP384T1, HCF_ALG_ECC },
    { HCF_ALG_ECC_BP512R1, HCF_ALG_ECC_BP512R1, HCF_ALG_ECC },
    { HCF_ALG_ECC_BP512T1, HCF_ALG_ECC_BP512T1, HCF_ALG_ECC },
    { HCF_ALG_ECC_SECP256K1, HCF_ALG_ECC_SECP256K1, HCF_ALG_ECC },
    { HCF_ALG_ED25519_256, HCF_ALG_ED25519_256, HCF_ALG_ED25519 },
    { HCF_ALG_X25519_256, HCF_ALG_X25519_256, HCF_ALG_X25519 },
    { HCF_OPENSSL_DH_MODP_1536, HCF_DH_MODP_SIZE_1536, HCF_ALG_DH },
    { HCF_OPENSSL_DH_MODP_2048, HCF_DH_MODP_SIZE_2048, HCF_ALG_DH },
    { HCF_OPENSSL_DH_MODP_3072, HCF_DH_MODP_SIZE_3072, HCF_ALG_DH },
    { HCF_OPENSSL_DH_MODP_4096, HCF_DH_MODP_SIZE_4096, HCF_ALG_DH },
    { HCF_OPENSSL_DH_MODP_6144, HCF_DH_MODP_SIZE_6144, HCF_ALG_DH },
    { HCF_OPENSSL_DH_MODP_8192, HCF_DH_MODP_SIZE_8192, HCF_ALG_DH },
    { HCF_OPENSSL_DH_FFDHE_2048, HCF_DH_FFDHE_SIZE_2048, HCF_ALG_DH },
    { HCF_OPENSSL_DH_FFDHE_3072, HCF_DH_FFDHE_SIZE_3072, HCF_ALG_DH },
    { HCF_OPENSSL_DH_FFDHE_4096, HCF_DH_FFDHE_SIZE_4096, HCF_ALG_DH },
    { HCF_OPENSSL_DH_FFDHE_6144, HCF_DH_FFDHE_SIZE_6144, HCF_ALG_DH },
    { HCF_OPENSSL_DH_FFDHE_8192, HCF_DH_FFDHE_SIZE_8192, HCF_ALG_DH },

    { HCF_ALG_ML_KEM_512, HCF_ALG_ML_KEM_512, HCF_ALG_ML_KEM },
    { HCF_ALG_ML_KEM_768, HCF_ALG_ML_KEM_768, HCF_ALG_ML_KEM },
    { HCF_ALG_ML_KEM_1024, HCF_ALG_ML_KEM_1024, HCF_ALG_ML_KEM },

    { HCF_ALG_ML_DSA_44, HCF_ALG_ML_DSA_44, HCF_ALG_ML_DSA },
    { HCF_ALG_ML_DSA_65, HCF_ALG_ML_DSA_65, HCF_ALG_ML_DSA },
    { HCF_ALG_ML_DSA_87, HCF_ALG_ML_DSA_87, HCF_ALG_ML_DSA }
};
static bool IsDsaCommParamsSpecValid(HcfDsaCommParamsSpec *paramsSpec)
{
    if ((paramsSpec->p.data == NULL) || (paramsSpec->p.len == 0)) {
        LOGE("BigInteger p is invalid");
        return false;
    }
    if ((paramsSpec->q.data == NULL) || (paramsSpec->q.len == 0)) {
        LOGE("BigInteger q is invalid");
        return false;
    }
    if ((paramsSpec->g.data == NULL) || (paramsSpec->g.len == 0)) {
        LOGE("BigInteger g is invalid");
        return false;
    }
    return true;
}

static bool IsDsaPubKeySpecValid(HcfDsaPubKeyParamsSpec *paramsSpec)
{
    if (!IsDsaCommParamsSpecValid(&(paramsSpec->base))) {
        LOGE("DSA common params spec is invalid");
        return false;
    }
    if ((paramsSpec->pk.data == NULL) || (paramsSpec->pk.len == 0)) {
        LOGE("BigInteger pk is invalid");
        return false;
    }
    return true;
}

static bool IsDsaKeyPairSpecValid(HcfDsaKeyPairParamsSpec *paramsSpec)
{
    if (!IsDsaCommParamsSpecValid(&(paramsSpec->base))) {
        LOGE("DSA common params spec is invalid");
        return false;
    }
    if ((paramsSpec->pk.data == NULL) || (paramsSpec->pk.len == 0)) {
        LOGE("BigInteger pk is invalid");
        return false;
    }
    if ((paramsSpec->sk.data == NULL) || (paramsSpec->sk.len == 0)) {
        LOGE("BigInteger sk is invalid");
        return false;
    }
    return true;
}

static bool IsDsaParamsSpecValid(const HcfAsyKeyParamsSpec *paramsSpec)
{
    bool ret = false;
    switch (paramsSpec->specType) {
        case HCF_COMMON_PARAMS_SPEC:
            ret = IsDsaCommParamsSpecValid((HcfDsaCommParamsSpec *)paramsSpec);
            break;
        case HCF_PUBLIC_KEY_SPEC:
            ret = IsDsaPubKeySpecValid((HcfDsaPubKeyParamsSpec *)paramsSpec);
            break;
        case HCF_KEY_PAIR_SPEC:
            ret = IsDsaKeyPairSpecValid((HcfDsaKeyPairParamsSpec *)paramsSpec);
            break;
        default:
            LOGE("SpecType not support! [SpecType]: %{public}d", paramsSpec->specType);
            break;
    }
    return ret;
}

static bool IsDhCommParamsSpecValid(HcfDhCommParamsSpec *paramsSpec)
{
    if ((paramsSpec->p.data == NULL) || (paramsSpec->p.len == 0)) {
        LOGE("BigInteger p is invalid");
        return false;
    }
    if ((paramsSpec->g.data == NULL) || (paramsSpec->g.len == 0)) {
        LOGE("BigInteger g is invalid");
        return false;
    }
    return true;
}

static bool IsDhPriKeySpecValid(HcfDhPriKeyParamsSpec *paramsSpec)
{
    if (!IsDhCommParamsSpecValid(&(paramsSpec->base))) {
        LOGE("DH common params spec is invalid");
        return false;
    }
    if ((paramsSpec->sk.data == NULL) || (paramsSpec->sk.len == 0)) {
        LOGE("BigInteger sk is invalid");
        return false;
    }
    return true;
}

static bool IsDhPubKeySpecValid(HcfDhPubKeyParamsSpec *paramsSpec)
{
    if (!IsDhCommParamsSpecValid(&(paramsSpec->base))) {
        LOGE("DH common params spec is invalid");
        return false;
    }
    if ((paramsSpec->pk.data == NULL) || (paramsSpec->pk.len == 0)) {
        LOGE("BigInteger pk is invalid");
        return false;
    }
    return true;
}

static bool IsDhKeyPairSpecValid(HcfDhKeyPairParamsSpec *paramsSpec)
{
    if (!IsDhCommParamsSpecValid(&(paramsSpec->base))) {
        LOGE("DH common params spec is invalid");
        return false;
    }
    if ((paramsSpec->pk.data == NULL) || (paramsSpec->pk.len == 0)) {
        LOGE("BigInteger pk is invalid");
        return false;
    }
    if ((paramsSpec->sk.data == NULL) || (paramsSpec->sk.len == 0)) {
        LOGE("BigInteger sk is invalid");
        return false;
    }
    return true;
}

static bool IsDhParamsSpecValid(const HcfAsyKeyParamsSpec *paramsSpec)
{
    bool ret = false;
    switch (paramsSpec->specType) {
        case HCF_COMMON_PARAMS_SPEC:
            ret = IsDhCommParamsSpecValid((HcfDhCommParamsSpec *)paramsSpec);
            break;
        case HCF_PRIVATE_KEY_SPEC:
            ret = IsDhPriKeySpecValid((HcfDhPriKeyParamsSpec *)paramsSpec);
            break;
        case HCF_PUBLIC_KEY_SPEC:
            ret = IsDhPubKeySpecValid((HcfDhPubKeyParamsSpec *)paramsSpec);
            break;
        case HCF_KEY_PAIR_SPEC:
            ret = IsDhKeyPairSpecValid((HcfDhKeyPairParamsSpec *)paramsSpec);
            break;
        default:
            LOGE("SpecType not support! [SpecType]: %{public}d", paramsSpec->specType);
            break;
    }
    return ret;
}

static bool IsEccCommParamsSpecValid(HcfEccCommParamsSpec *paramsSpec)
{
    if ((paramsSpec->a.data == NULL) || (paramsSpec->a.len == 0)) {
        LOGE("BigInteger a is invalid");
        return false;
    }
    if ((paramsSpec->b.data == NULL) || (paramsSpec->b.len == 0)) {
        LOGE("BigInteger b is invalid");
        return false;
    }
    if ((paramsSpec->n.data == NULL) || (paramsSpec->n.len == 0)) {
        LOGE("BigInteger n is invalid");
        return false;
    }
    if ((paramsSpec->g.x.data == NULL) || (paramsSpec->g.x.len == 0) ||
        (paramsSpec->g.y.data == NULL) || (paramsSpec->g.y.len == 0)) {
        LOGE("Point g is invalid");
        return false;
    }
    if (paramsSpec->field == NULL) {
        LOGE("Field is null.");
        return false;
    }
    if (strcmp(paramsSpec->field->fieldType, "Fp") != 0) {
        LOGE("Unknown field type.");
        return false;
    }
    HcfECFieldFp *tmp = (HcfECFieldFp *)(paramsSpec->field);
    if ((tmp->p.data == NULL) || (tmp->p.len == 0)) {
        LOGE("EcFieldFp p is invalid");
        return false;
    }
    return true;
}

static bool IsEccPriKeySpecValid(HcfEccPriKeyParamsSpec *paramsSpec)
{
    if (!IsEccCommParamsSpecValid(&(paramsSpec->base))) {
        LOGE("ECC common params spec is invalid");
        return false;
    }
    if ((paramsSpec->sk.data == NULL) || (paramsSpec->sk.len == 0)) {
        LOGE("BigInteger sk is invalid");
        return false;
    }
    return true;
}

static bool IsEccPubKeySpecValid(HcfEccPubKeyParamsSpec *paramsSpec)
{
    if (!IsEccCommParamsSpecValid(&(paramsSpec->base))) {
        LOGE("ECC common params spec is invalid");
        return false;
    }
    if ((paramsSpec->pk.x.data == NULL) || (paramsSpec->pk.x.len == 0) ||
        (paramsSpec->pk.y.data == NULL) || (paramsSpec->pk.y.len == 0)) {
        LOGE("Point pk is invalid");
        return false;
    }
    return true;
}

static bool IsEccKeyPairSpecValid(HcfEccKeyPairParamsSpec *paramsSpec)
{
    if (!IsEccCommParamsSpecValid(&(paramsSpec->base))) {
        LOGE("ECC common params spec is invalid");
        return false;
    }
    if ((paramsSpec->pk.x.data == NULL) || (paramsSpec->pk.x.len == 0) ||
        (paramsSpec->pk.y.data == NULL) || (paramsSpec->pk.y.len == 0)) {
        LOGE("Point pk is invalid");
        return false;
    }
    if ((paramsSpec->sk.data == NULL) || (paramsSpec->sk.len == 0)) {
        LOGE("BigInteger sk is invalid");
        return false;
    }
    return true;
}

static bool IsEccParamsSpecValid(const HcfAsyKeyParamsSpec *paramsSpec)
{
    bool ret = false;
    switch (paramsSpec->specType) {
        case HCF_COMMON_PARAMS_SPEC:
            ret = IsEccCommParamsSpecValid((HcfEccCommParamsSpec *)paramsSpec);
            break;
        case HCF_PRIVATE_KEY_SPEC:
            ret = IsEccPriKeySpecValid((HcfEccPriKeyParamsSpec *)paramsSpec);
            break;
        case HCF_PUBLIC_KEY_SPEC:
            ret = IsEccPubKeySpecValid((HcfEccPubKeyParamsSpec *)paramsSpec);
            break;
        case HCF_KEY_PAIR_SPEC:
            ret = IsEccKeyPairSpecValid((HcfEccKeyPairParamsSpec *)paramsSpec);
            break;
        default:
            LOGE("SpecType not support! [SpecType]: %{public}d", paramsSpec->specType);
            break;
    }
    return ret;
}

static bool IsAlg25519PriKeySpecValid(HcfAlg25519PriKeyParamsSpec *paramsSpec)
{
    if ((paramsSpec->sk.data == NULL) || (paramsSpec->sk.len == 0)) {
        LOGE("Uint8Array sk is invalid");
        return false;
    }
    return true;
}

static bool IsAlg25519PubKeySpecValid(HcfAlg25519PubKeyParamsSpec *paramsSpec)
{
    if ((paramsSpec->pk.data == NULL) || (paramsSpec->pk.len == 0)) {
        LOGE("Uint8Array pk is invalid");
        return false;
    }
    return true;
}

static bool IsAlg25519KeyPairSpecValid(HcfAlg25519KeyPairParamsSpec *paramsSpec)
{
    if ((paramsSpec->pk.data == NULL) || (paramsSpec->pk.len == 0)) {
        LOGE("Uint8Array pk is invalid");
        return false;
    }
    if ((paramsSpec->sk.data == NULL) || (paramsSpec->sk.len == 0)) {
        LOGE("Uint8Array sk is invalid");
        return false;
    }
    return true;
}

static bool IsAlg25519ParamsSpecValid(const HcfAsyKeyParamsSpec *paramsSpec)
{
    bool ret = false;
    switch (paramsSpec->specType) {
        case HCF_PRIVATE_KEY_SPEC:
            ret = IsAlg25519PriKeySpecValid((HcfAlg25519PriKeyParamsSpec *)paramsSpec);
            break;
        case HCF_PUBLIC_KEY_SPEC:
            ret = IsAlg25519PubKeySpecValid((HcfAlg25519PubKeyParamsSpec *)paramsSpec);
            break;
        case HCF_KEY_PAIR_SPEC:
            ret = IsAlg25519KeyPairSpecValid((HcfAlg25519KeyPairParamsSpec *)paramsSpec);
            break;
        default:
            LOGE("SpecType not support! [SpecType]: %{public}d", paramsSpec->specType);
            break;
    }
    return ret;
}

static bool IsRsaCommParamsSpecValid(HcfRsaCommParamsSpec *paramsSpec)
{
    if ((paramsSpec->n.data == NULL) || (paramsSpec->n.len == 0)) {
        LOGE("BigInteger n is invalid");
        return false;
    }
    return true;
}

static bool IsRsaPubKeySpecValid(HcfRsaPubKeyParamsSpec *paramsSpec)
{
    if (!IsRsaCommParamsSpecValid(&(paramsSpec->base))) {
        LOGE("RSA common params spec is invalid");
        return false;
    }
    if ((paramsSpec->pk.data == NULL) || (paramsSpec->pk.len == 0)) {
        LOGE("BigInteger pk is invalid");
        return false;
    }
    return true;
}

static bool IsRsaKeyPairSpecValid(HcfRsaKeyPairParamsSpec *paramsSpec)
{
    if (!IsRsaCommParamsSpecValid(&(paramsSpec->base))) {
        LOGE("RSA common params spec is invalid");
        return false;
    }
    if ((paramsSpec->pk.data == NULL) || (paramsSpec->pk.len == 0)) {
        LOGE("BigInteger pk is invalid");
        return false;
    }
    if ((paramsSpec->sk.data == NULL) || (paramsSpec->sk.len == 0)) {
        LOGE("BigInteger sk is invalid");
        return false;
    }
    return true;
}

static bool IsRsaParamsSpecValid(const HcfAsyKeyParamsSpec *paramsSpec)
{
    bool ret = false;
    switch (paramsSpec->specType) {
        case HCF_COMMON_PARAMS_SPEC:
            ret = IsRsaCommParamsSpecValid((HcfRsaCommParamsSpec *)paramsSpec);
            break;
        case HCF_PUBLIC_KEY_SPEC:
            ret = IsRsaPubKeySpecValid((HcfRsaPubKeyParamsSpec *)paramsSpec);
            break;
        case HCF_KEY_PAIR_SPEC:
            ret = IsRsaKeyPairSpecValid((HcfRsaKeyPairParamsSpec *)paramsSpec);
            break;
        default:
            LOGE("SpecType not support! [SpecType]: %{public}d", paramsSpec->specType);
            break;
    }
    return ret;
}

static bool IsParamsSpecValid(const HcfAsyKeyParamsSpec *paramsSpec)
{
    if ((paramsSpec == NULL) || (paramsSpec->algName == NULL)) {
        LOGE("Params spec is null");
        return false;
    }
    if (strcmp(paramsSpec->algName, ALG_NAME_DSA) == 0) {
        return IsDsaParamsSpecValid(paramsSpec);
    } else if (strcmp(paramsSpec->algName, ALG_NAME_ECC) == 0 || strcmp(paramsSpec->algName, ALG_NAME_SM2) == 0) {
        return IsEccParamsSpecValid(paramsSpec);
    } else if (strcmp(paramsSpec->algName, ALG_NAME_RSA) == 0) {
        return IsRsaParamsSpecValid(paramsSpec);
    } else if (strcmp(paramsSpec->algName, ALG_NAME_X25519) == 0 ||
        strcmp(paramsSpec->algName, ALG_NAME_ED25519) == 0) {
        return IsAlg25519ParamsSpecValid(paramsSpec);
    } else if (strcmp(paramsSpec->algName, ALG_NAME_DH) == 0) {
        return IsDhParamsSpecValid(paramsSpec);
    } else if (strcmp(paramsSpec->algName, ALG_NAME_ML_KEM) == 0) {
        LOGE("ML-KEM not support params spec.");
        return false;
    } else if (strcmp(paramsSpec->algName, ALG_NAME_ML_DSA) == 0) {
        LOGE("ML-DSA not support params spec.");
        return false;
    } else {
        LOGE("AlgName not support! [AlgName]: %{public}s", paramsSpec->algName);
        return false;
    }
}

static HcfAsyKeyGeneratorSpiCreateFunc FindAbility(HcfAsyKeyGenParams *params)
{
    for (uint32_t i = 0; i < sizeof(ASY_KEY_GEN_ABILITY_SET) / sizeof(ASY_KEY_GEN_ABILITY_SET[0]); i++) {
        if (ASY_KEY_GEN_ABILITY_SET[i].algo == params->algo) {
            return ASY_KEY_GEN_ABILITY_SET[i].createSpiFunc;
        }
    }
    LOGE("Algo not support! [Algo]: %{public}d", params->algo);
    return NULL;
}

static void SetPrimes(HcfAlgParaValue value, HcfAsyKeyGenParams *params)
{
    if (params == NULL) {
        LOGE("Params is null.");
        return;
    }
    switch (value) {
        case HCF_OPENSSL_PRIMES_2:
            params->primes = (int32_t)HCF_RSA_PRIMES_SIZE_2;
            break;
        case HCF_OPENSSL_PRIMES_3:
            params->primes = (int32_t)HCF_RSA_PRIMES_SIZE_3;
            break;
        case HCF_OPENSSL_PRIMES_4:
            params->primes = (int32_t)HCF_RSA_PRIMES_SIZE_4;
            break;
        case HCF_OPENSSL_PRIMES_5:
            params->primes = (int32_t)HCF_RSA_PRIMES_SIZE_5;
            break;
        default:
            params->primes = (int32_t)HCF_RSA_PRIMES_SIZE_2; // default primes is 2
            LOGD("User default primes 2");
            break;
    }
    LOGD("Set primes:%{public}d!", params->primes);
}

static void SetKeyType(HcfAlgParaValue value, HcfAsyKeyGenParams *params)
{
    for (uint32_t i = 0; i < sizeof(KEY_TYPE_MAP) / sizeof(KEY_TYPE_MAP[0]); i++) {
        if (KEY_TYPE_MAP[i].value == value) {
            params->bits = KEY_TYPE_MAP[i].bits;
            params->algo = KEY_TYPE_MAP[i].algo;
            return;
        }
    }
    LOGE("There is not matched algorithm.");
}

static HcfResult ParseAsyKeyGenParams(const HcfParaConfig* config, void *params)
{
    if (config == NULL || params == NULL) {
        LOGE("Config or params is null");
        return HCF_INVALID_PARAMS;
    }
    HcfResult ret = HCF_SUCCESS;
    HcfAsyKeyGenParams *paramsObj = (HcfAsyKeyGenParams *)params;
    LOGD("Set Parameter: %{public}s", config->tag);
    switch (config->paraType) {
        case HCF_ALG_KEY_TYPE:
            SetKeyType(config->paraValue, paramsObj);
            break;
        case HCF_ALG_PRIMES:
            SetPrimes(config->paraValue, paramsObj);
            break;
        default:
            LOGE("Unsupported parameter type in asy key gen params");
            ret = HCF_INVALID_PARAMS;
            break;
    }
    return ret;
}

static HcfResult CopyDsaCommonSpec(const HcfDsaCommParamsSpec *srcSpec, HcfDsaCommParamsSpec *destSpec)
{
    if (CopyAsyKeyParamsSpec(&(srcSpec->base), &(destSpec->base)) != HCF_SUCCESS) {
        LOGE("Failed to copy asy key params spec");
        return HCF_INVALID_PARAMS;
    }
    destSpec->p.data = (unsigned char *)HcfMalloc(srcSpec->p.len, 0);
    if (destSpec->p.data == NULL) {
        LOGE("Failed to allocate p data memory");
        FreeDsaCommParamsSpec(destSpec);
        return HCF_ERR_MALLOC;
    }
    destSpec->q.data = (unsigned char *)HcfMalloc(srcSpec->q.len, 0);
    if (destSpec->q.data == NULL) {
        LOGE("Failed to allocate q data memory");
        FreeDsaCommParamsSpec(destSpec);
        return HCF_ERR_MALLOC;
    }
    destSpec->g.data = (unsigned char *)HcfMalloc(srcSpec->g.len, 0);
    if (destSpec->g.data == NULL) {
        LOGE("Failed to allocate g data memory");
        FreeDsaCommParamsSpec(destSpec);
        return HCF_ERR_MALLOC;
    }
    (void)memcpy_s(destSpec->p.data, srcSpec->p.len, srcSpec->p.data, srcSpec->p.len);
    (void)memcpy_s(destSpec->q.data, srcSpec->q.len, srcSpec->q.data, srcSpec->q.len);
    (void)memcpy_s(destSpec->g.data, srcSpec->g.len, srcSpec->g.data, srcSpec->g.len);
    destSpec->p.len = srcSpec->p.len;
    destSpec->q.len = srcSpec->q.len;
    destSpec->g.len = srcSpec->g.len;
    return HCF_SUCCESS;
}

static HcfResult CreateDsaCommonSpecImpl(const HcfDsaCommParamsSpec *srcSpec, HcfDsaCommParamsSpec **destSpec)
{
    HcfDsaCommParamsSpec *spec = (HcfDsaCommParamsSpec *)HcfMalloc(sizeof(HcfDsaCommParamsSpec), 0);
    if (spec == NULL) {
        LOGE("Failed to allocate dest spec memory");
        return HCF_ERR_MALLOC;
    }

    if (CopyDsaCommonSpec(srcSpec, spec) != HCF_SUCCESS) {
        HcfFree(spec);
        spec = NULL;
        LOGE("Failed to copy DSA common spec");
        return HCF_INVALID_PARAMS;
    }

    *destSpec = spec;
    return HCF_SUCCESS;
}

static HcfResult CreateDsaPubKeySpecImpl(const HcfDsaPubKeyParamsSpec *srcSpec, HcfDsaPubKeyParamsSpec **destSpec)
{
    HcfDsaPubKeyParamsSpec *spec = (HcfDsaPubKeyParamsSpec *)HcfMalloc(sizeof(HcfDsaPubKeyParamsSpec), 0);
    if (spec == NULL) {
        LOGE("Failed to allocate dest spec memory");
        return HCF_ERR_MALLOC;
    }
    if (CopyDsaCommonSpec(&(srcSpec->base), &(spec->base)) != HCF_SUCCESS) {
        HcfFree(spec);
        spec = NULL;
        LOGE("Failed to copy DSA common spec");
        return HCF_INVALID_PARAMS;
    }
    spec->pk.data = (unsigned char *)HcfMalloc(srcSpec->pk.len, 0);
    if (spec->pk.data == NULL) {
        LOGE("Failed to allocate public key memory");
        FreeDsaCommParamsSpec(&(spec->base));
        HcfFree(spec);
        spec = NULL;
        return HCF_ERR_MALLOC;
    }
    (void)memcpy_s(spec->pk.data, srcSpec->pk.len, srcSpec->pk.data, srcSpec->pk.len);
    spec->pk.len = srcSpec->pk.len;

    *destSpec = spec;
    return HCF_SUCCESS;
}

static HcfResult CreateDsaKeyPairSpecImpl(const HcfDsaKeyPairParamsSpec *srcSpec, HcfDsaKeyPairParamsSpec **destSpec)
{
    HcfDsaKeyPairParamsSpec *spec = (HcfDsaKeyPairParamsSpec *)HcfMalloc(sizeof(HcfDsaKeyPairParamsSpec), 0);
    if (spec == NULL) {
        LOGE("Failed to allocate dest spec memory");
        return HCF_ERR_MALLOC;
    }
    if (CopyDsaCommonSpec(&(srcSpec->base), &(spec->base)) != HCF_SUCCESS) {
        HcfFree(spec);
        spec = NULL;
        LOGE("Failed to copy DSA common spec");
        return HCF_INVALID_PARAMS;
    }
    spec->pk.data = (unsigned char *)HcfMalloc(srcSpec->pk.len, 0);
    if (spec->pk.data == NULL) {
        LOGE("Failed to allocate public key memory");
        FreeDsaCommParamsSpec(&(spec->base));
        HcfFree(spec);
        spec = NULL;
        return HCF_ERR_MALLOC;
    }
    spec->sk.data = (unsigned char *)HcfMalloc(srcSpec->sk.len, 0);
    if (spec->sk.data == NULL) {
        LOGE("Failed to allocate private key memory");
        FreeDsaCommParamsSpec(&(spec->base));
        HcfFree(spec->pk.data);
        spec->pk.data = NULL;
        HcfFree(spec);
        spec = NULL;
        return HCF_ERR_MALLOC;
    }
    (void)memcpy_s(spec->pk.data, srcSpec->pk.len, srcSpec->pk.data, srcSpec->pk.len);
    (void)memcpy_s(spec->sk.data, srcSpec->sk.len, srcSpec->sk.data, srcSpec->sk.len);
    spec->pk.len = srcSpec->pk.len;
    spec->sk.len = srcSpec->sk.len;

    *destSpec = spec;
    return HCF_SUCCESS;
}

static HcfResult CreateDsaParamsSpecImpl(const HcfAsyKeyParamsSpec *paramsSpec, HcfAsyKeyParamsSpec **impl)
{
    HcfResult ret = HCF_SUCCESS;
    HcfDsaCommParamsSpec *spec = NULL;
    switch (paramsSpec->specType) {
        case HCF_COMMON_PARAMS_SPEC:
            ret = CreateDsaCommonSpecImpl((HcfDsaCommParamsSpec *)paramsSpec, &spec);
            break;
        case HCF_PUBLIC_KEY_SPEC:
            ret = CreateDsaPubKeySpecImpl((HcfDsaPubKeyParamsSpec *)paramsSpec, (HcfDsaPubKeyParamsSpec **)&spec);
            break;
        case HCF_KEY_PAIR_SPEC:
            ret = CreateDsaKeyPairSpecImpl((HcfDsaKeyPairParamsSpec *)paramsSpec, (HcfDsaKeyPairParamsSpec **)&spec);
            break;
        default:
            LOGE("Unsupported DSA params spec type");
            ret = HCF_INVALID_PARAMS;
            break;
    }
    if (ret == HCF_SUCCESS) {
        *impl = (HcfAsyKeyParamsSpec *)spec;
    }
    return ret;
}

static HcfResult CreateDhPubKeySpecImpl(const HcfDhPubKeyParamsSpec *srcSpec, HcfDhPubKeyParamsSpec **destSpec)
{
    HcfDhPubKeyParamsSpec *spec = (HcfDhPubKeyParamsSpec *)HcfMalloc(sizeof(HcfDhPubKeyParamsSpec), 0);
    if (spec == NULL) {
        LOGE("Failed to allocate dest spec memory");
        return HCF_ERR_MALLOC;
    }
    if (CopyDhCommonSpec(&(srcSpec->base), &(spec->base)) != HCF_SUCCESS) {
        LOGE("Failed to copy src spec");
        HcfFree(spec);
        spec = NULL;
        return HCF_INVALID_PARAMS;
    }
    spec->pk.data = (unsigned char *)HcfMalloc(srcSpec->pk.len, 0);
    if (spec->pk.data == NULL) {
        LOGE("Failed to allocate public key memory");
        DestroyDhPubKeySpec(spec);
        return HCF_ERR_MALLOC;
    }
    (void)memcpy_s(spec->pk.data, srcSpec->pk.len, srcSpec->pk.data, srcSpec->pk.len);
    spec->pk.len = srcSpec->pk.len;

    *destSpec = spec;
    return HCF_SUCCESS;
}

static HcfResult CreateDhPriKeySpecImpl(const HcfDhPriKeyParamsSpec *srcSpec, HcfDhPriKeyParamsSpec **destSpec)
{
    HcfDhPriKeyParamsSpec *spec = (HcfDhPriKeyParamsSpec *)HcfMalloc(sizeof(HcfDhPriKeyParamsSpec), 0);
    if (spec == NULL) {
        LOGE("Failed to allocate dest spec memory");
        return HCF_ERR_MALLOC;
    }
    if (CopyDhCommonSpec(&(srcSpec->base), &(spec->base)) != HCF_SUCCESS) {
        LOGE("Failed to copy src spec");
        HcfFree(spec);
        spec = NULL;
        return HCF_INVALID_PARAMS;
    }
    spec->sk.data = (unsigned char *)HcfMalloc(srcSpec->sk.len, 0);
    if (spec->sk.data == NULL) {
        LOGE("Failed to allocate private key memory");
        FreeDhCommParamsSpec(&(spec->base));
        HcfFree(spec);
        spec = NULL;
        return HCF_ERR_MALLOC;
    }
    (void)memcpy_s(spec->sk.data, srcSpec->sk.len, srcSpec->sk.data, srcSpec->sk.len);
    spec->sk.len = srcSpec->sk.len;

    *destSpec = spec;
    return HCF_SUCCESS;
}

static HcfResult CreateDhKeyPairSpecImpl(const HcfDhKeyPairParamsSpec *srcSpec, HcfDhKeyPairParamsSpec **destSpec)
{
    HcfDhKeyPairParamsSpec *spec = (HcfDhKeyPairParamsSpec *)HcfMalloc(sizeof(HcfDhKeyPairParamsSpec), 0);
    if (spec == NULL) {
        LOGE("Failed to allocate dest spec memory");
        return HCF_ERR_MALLOC;
    }
    if (CopyDhCommonSpec(&(srcSpec->base), &(spec->base)) != HCF_SUCCESS) {
        LOGE("Failed to copy src spec");
        HcfFree(spec);
        spec = NULL;
        return HCF_INVALID_PARAMS;
    }
    spec->pk.data = (unsigned char *)HcfMalloc(srcSpec->pk.len, 0);
    if (spec->pk.data == NULL) {
        LOGE("Failed to allocate public key memory");
        FreeDhCommParamsSpec(&(spec->base));
        HcfFree(spec);
        spec = NULL;
        return HCF_ERR_MALLOC;
    }
    spec->sk.data = (unsigned char *)HcfMalloc(srcSpec->sk.len, 0);
    if (spec->sk.data == NULL) {
        LOGE("Failed to allocate private key memory");
        FreeDhCommParamsSpec(&(spec->base));
        HcfFree(spec->pk.data);
        spec->pk.data = NULL;
        HcfFree(spec);
        spec = NULL;
        return HCF_ERR_MALLOC;
    }
    (void)memcpy_s(spec->pk.data, srcSpec->pk.len, srcSpec->pk.data, srcSpec->pk.len);
    (void)memcpy_s(spec->sk.data, srcSpec->sk.len, srcSpec->sk.data, srcSpec->sk.len);
    spec->pk.len = srcSpec->pk.len;
    spec->sk.len = srcSpec->sk.len;

    *destSpec = spec;
    return HCF_SUCCESS;
}

static HcfResult CreateDhParamsSpecImpl(const HcfAsyKeyParamsSpec *paramsSpec, HcfAsyKeyParamsSpec **impl)
{
    HcfResult ret = HCF_SUCCESS;
    HcfDhCommParamsSpec *spec = NULL;
    switch (paramsSpec->specType) {
        case HCF_COMMON_PARAMS_SPEC:
            ret = CreateDhCommonSpecImpl((HcfDhCommParamsSpec *)paramsSpec, &spec);
            break;
        case HCF_PUBLIC_KEY_SPEC:
            ret = CreateDhPubKeySpecImpl((HcfDhPubKeyParamsSpec *)paramsSpec, (HcfDhPubKeyParamsSpec **)&spec);
            break;
        case HCF_PRIVATE_KEY_SPEC:
            ret = CreateDhPriKeySpecImpl((HcfDhPriKeyParamsSpec *)paramsSpec, (HcfDhPriKeyParamsSpec **)&spec);
            break;
        case HCF_KEY_PAIR_SPEC:
            ret = CreateDhKeyPairSpecImpl((HcfDhKeyPairParamsSpec *)paramsSpec, (HcfDhKeyPairParamsSpec **)&spec);
            break;
        default:
            LOGE("Invalid spec type [%{public}d]", paramsSpec->specType);
            ret = HCF_INVALID_PARAMS;
            break;
    }
    if (ret == HCF_SUCCESS) {
        *impl = (HcfAsyKeyParamsSpec *)spec;
    }
    return ret;
}

static HcfResult CreateEccPubKeySpecImpl(const HcfEccPubKeyParamsSpec *srcSpec, HcfEccPubKeyParamsSpec **destSpec)
{
    HcfEccPubKeyParamsSpec *tmpSpec = (HcfEccPubKeyParamsSpec *)HcfMalloc(sizeof(HcfEccPubKeyParamsSpec), 0);
    if (tmpSpec == NULL) {
        LOGE("Failed to allocate dest spec memory");
        return HCF_ERR_MALLOC;
    }
    if (CopyEccCommonSpec(&(srcSpec->base), &(tmpSpec->base)) != HCF_SUCCESS) {
        HcfFree(tmpSpec);
        tmpSpec = NULL;
        LOGE("Failed to copy ECC common spec");
        return HCF_INVALID_PARAMS;
    }
    HcfResult res = CopyPoint(&(srcSpec->pk), &(tmpSpec->pk));
    if (res != HCF_SUCCESS) {
        LOGE("Failed to allocate public key memory");
        FreeEccCommParamsSpec(&(tmpSpec->base));
        HcfFree(tmpSpec);
        tmpSpec = NULL;
        return res;
    }

    *destSpec = tmpSpec;
    return HCF_SUCCESS;
}

static HcfResult CreateEccPriKeySpecImpl(const HcfEccPriKeyParamsSpec *srcSpec, HcfEccPriKeyParamsSpec **destSpec)
{
    HcfEccPriKeyParamsSpec *tmpSpec = (HcfEccPriKeyParamsSpec *)HcfMalloc(sizeof(HcfEccPriKeyParamsSpec), 0);
    if (tmpSpec == NULL) {
        LOGE("Failed to allocate dest spec memory");
        return HCF_ERR_MALLOC;
    }
    if (CopyEccCommonSpec(&(srcSpec->base), &(tmpSpec->base)) != HCF_SUCCESS) {
        HcfFree(tmpSpec);
        tmpSpec = NULL;
        LOGE("Failed to copy ECC common spec");
        return HCF_INVALID_PARAMS;
    }
    tmpSpec->sk.data = (unsigned char *)HcfMalloc(srcSpec->sk.len, 0);
    if (tmpSpec->sk.data == NULL) {
        LOGE("Failed to allocate private key memory");
        FreeEccCommParamsSpec(&(tmpSpec->base));
        HcfFree(tmpSpec);
        tmpSpec = NULL;
        return HCF_ERR_MALLOC;
    }
    (void)memcpy_s(tmpSpec->sk.data, srcSpec->sk.len, srcSpec->sk.data, srcSpec->sk.len);
    tmpSpec->sk.len = srcSpec->sk.len;

    *destSpec = tmpSpec;
    return HCF_SUCCESS;
}

static HcfResult CreateEccKeyPairSpecImpl(const HcfEccKeyPairParamsSpec *srcSpec, HcfEccKeyPairParamsSpec **destSpec)
{
    HcfEccKeyPairParamsSpec *tmpSpec = (HcfEccKeyPairParamsSpec *)HcfMalloc(sizeof(HcfEccKeyPairParamsSpec), 0);
    if (tmpSpec == NULL) {
        LOGE("Failed to allocate dest spec memory");
        return HCF_ERR_MALLOC;
    }
    if (CopyEccCommonSpec(&(srcSpec->base), &(tmpSpec->base)) != HCF_SUCCESS) {
        HcfFree(tmpSpec);
        tmpSpec = NULL;
        LOGE("Failed to copy ECC common spec");
        return HCF_INVALID_PARAMS;
    }
    HcfResult res = CopyPoint(&(srcSpec->pk), &(tmpSpec->pk));
    if (res != HCF_SUCCESS) {
        LOGE("Failed to allocate public key memory");
        FreeEccCommParamsSpec(&(tmpSpec->base));
        HcfFree(tmpSpec);
        tmpSpec = NULL;
        return res;
    }
    tmpSpec->sk.data = (unsigned char *)HcfMalloc(srcSpec->sk.len, 0);
    if (tmpSpec->sk.data == NULL) {
        LOGE("Failed to allocate private key memory");
        FreeEccCommParamsSpec(&(tmpSpec->base));
        HcfFree(tmpSpec->pk.x.data);
        tmpSpec->pk.x.data = NULL;
        HcfFree(tmpSpec->pk.y.data);
        tmpSpec->pk.y.data = NULL;
        HcfFree(tmpSpec);
        tmpSpec = NULL;
        return HCF_ERR_MALLOC;
    }
    (void)memcpy_s(tmpSpec->sk.data, srcSpec->sk.len, srcSpec->sk.data, srcSpec->sk.len);
    tmpSpec->sk.len = srcSpec->sk.len;

    *destSpec = tmpSpec;
    return HCF_SUCCESS;
}

static HcfResult CreateEccParamsSpecImpl(const HcfAsyKeyParamsSpec *paramsSpec, HcfAsyKeyParamsSpec **impl)
{
    HcfResult ret = HCF_SUCCESS;
    HcfEccCommParamsSpec *spec = NULL;
    switch (paramsSpec->specType) {
        case HCF_COMMON_PARAMS_SPEC:
            ret = CreateEccCommonSpecImpl((HcfEccCommParamsSpec *)paramsSpec, &spec);
            break;
        case HCF_PUBLIC_KEY_SPEC:
            ret = CreateEccPubKeySpecImpl((HcfEccPubKeyParamsSpec *)paramsSpec, (HcfEccPubKeyParamsSpec **)(&spec));
            break;
        case HCF_PRIVATE_KEY_SPEC:
            ret = CreateEccPriKeySpecImpl((HcfEccPriKeyParamsSpec *)paramsSpec, (HcfEccPriKeyParamsSpec **)(&spec));
            break;
        case HCF_KEY_PAIR_SPEC:
            ret = CreateEccKeyPairSpecImpl((HcfEccKeyPairParamsSpec *)paramsSpec, (HcfEccKeyPairParamsSpec **)(&spec));
            break;
        default:
            LOGE("Unsupported ECC params spec type");
            ret = HCF_INVALID_PARAMS;
            break;
    }
    if (ret == HCF_SUCCESS) {
        *impl = (HcfAsyKeyParamsSpec *)spec;
    }
    return ret;
}

static HcfResult CopyRsaCommonSpec(const HcfRsaCommParamsSpec *srcSpec, HcfRsaCommParamsSpec *destSpec)
{
    if (CopyAsyKeyParamsSpec(&(srcSpec->base), &(destSpec->base)) != HCF_SUCCESS) {
        LOGE("Failed to copy asy key params spec");
        return HCF_INVALID_PARAMS;
    }
    destSpec->n.data = (unsigned char *)HcfMalloc(srcSpec->n.len, 0);
    if (destSpec->n.data == NULL) {
        LOGE("Failed to allocate n data memory");
        HcfFree(destSpec->base.algName);
        destSpec->base.algName = NULL;
        return HCF_ERR_MALLOC;
    }
    (void)memcpy_s(destSpec->n.data, srcSpec->n.len, srcSpec->n.data, srcSpec->n.len);
    destSpec->n.len = srcSpec->n.len;
    return HCF_SUCCESS;
}

static HcfResult CreateRsaPubKeySpecImpl(const HcfRsaPubKeyParamsSpec *srcSpec, HcfRsaPubKeyParamsSpec **destSpec)
{
    HcfRsaPubKeyParamsSpec *spec = (HcfRsaPubKeyParamsSpec *)HcfMalloc(sizeof(HcfRsaPubKeyParamsSpec), 0);
    if (spec == NULL) {
        LOGE("Failed to allocate dest spec memory");
        return HCF_ERR_MALLOC;
    }
    if (CopyRsaCommonSpec(&(srcSpec->base), &(spec->base)) != HCF_SUCCESS) {
        HcfFree(spec);
        spec = NULL;
        LOGE("Failed to copy RSA common spec");
        return HCF_INVALID_PARAMS;
    }
    spec->pk.data = (unsigned char *)HcfMalloc(srcSpec->pk.len, 0);
    if (spec->pk.data == NULL) {
        LOGE("Failed to allocate public key memory");
        DestroyRsaPubKeySpec(spec);
        return HCF_ERR_MALLOC;
    }
    (void)memcpy_s(spec->pk.data, srcSpec->pk.len, srcSpec->pk.data, srcSpec->pk.len);
    spec->pk.len = srcSpec->pk.len;

    *destSpec = spec;
    return HCF_SUCCESS;
}

static HcfResult CreateRsaKeyPairSpecImpl(const HcfRsaKeyPairParamsSpec *srcSpec, HcfRsaKeyPairParamsSpec **destSpec)
{
    HcfRsaKeyPairParamsSpec *spec = (HcfRsaKeyPairParamsSpec *)HcfMalloc(sizeof(HcfRsaKeyPairParamsSpec), 0);
    if (spec == NULL) {
        LOGE("Failed to allocate dest spec memory");
        return HCF_ERR_MALLOC;
    }
    if (CopyRsaCommonSpec(&(srcSpec->base), &(spec->base)) != HCF_SUCCESS) {
        HcfFree(spec);
        spec = NULL;
        LOGE("Failed to copy RSA common spec");
        return HCF_INVALID_PARAMS;
    }
    spec->pk.data = (unsigned char *)HcfMalloc(srcSpec->pk.len, 0);
    if (spec->pk.data == NULL) {
        LOGE("Failed to allocate public key memory");
        FreeRsaCommParamsSpec(&(spec->base));
        HcfFree(spec);
        spec = NULL;
        return HCF_ERR_MALLOC;
    }
    spec->sk.data = (unsigned char *)HcfMalloc(srcSpec->sk.len, 0);
    if (spec->sk.data == NULL) {
        LOGE("Failed to allocate private key memory");
        FreeRsaCommParamsSpec(&(spec->base));
        HcfFree(spec->pk.data);
        spec->pk.data = NULL;
        HcfFree(spec);
        spec = NULL;
        return HCF_ERR_MALLOC;
    }
    (void)memcpy_s(spec->pk.data, srcSpec->pk.len, srcSpec->pk.data, srcSpec->pk.len);
    (void)memcpy_s(spec->sk.data, srcSpec->sk.len, srcSpec->sk.data, srcSpec->sk.len);
    spec->pk.len = srcSpec->pk.len;
    spec->sk.len = srcSpec->sk.len;

    *destSpec = spec;
    return HCF_SUCCESS;
}

static HcfResult CreateRsaParamsSpecImpl(const HcfAsyKeyParamsSpec *paramsSpec, HcfAsyKeyParamsSpec **impl)
{
    HcfResult ret = HCF_SUCCESS;
    HcfRsaCommParamsSpec *spec = NULL;
    switch (paramsSpec->specType) {
        // commonspe should not be used in RSA
        case HCF_COMMON_PARAMS_SPEC:
            LOGE("RSA not support comm spec");
            ret = HCF_INVALID_PARAMS;
            break;
        case HCF_PUBLIC_KEY_SPEC:
            ret = CreateRsaPubKeySpecImpl((HcfRsaPubKeyParamsSpec *)paramsSpec, (HcfRsaPubKeyParamsSpec **)&spec);
            break;
        case HCF_KEY_PAIR_SPEC:
            ret = CreateRsaKeyPairSpecImpl((HcfRsaKeyPairParamsSpec *)paramsSpec, (HcfRsaKeyPairParamsSpec **)&spec);
            break;
        default:
            LOGE("Unsupported RSA params spec type");
            ret = HCF_INVALID_PARAMS;
            break;
    }
    if (ret == HCF_SUCCESS) {
        *impl = (HcfAsyKeyParamsSpec *)spec;
    }
    return ret;
}

static HcfResult CreateAlg25519PubKeySpecImpl(const HcfAlg25519PubKeyParamsSpec *srcSpec,
    HcfAlg25519PubKeyParamsSpec **destSpec)
{
    HcfAlg25519PubKeyParamsSpec *tmpSpec =
        (HcfAlg25519PubKeyParamsSpec *)HcfMalloc(sizeof(HcfAlg25519PubKeyParamsSpec), 0);
    if (tmpSpec == NULL) {
        LOGE("Failed to allocate dest spec memory");
        return HCF_ERR_MALLOC;
    }
    if (CopyAsyKeyParamsSpec(&(srcSpec->base), &(tmpSpec->base)) != HCF_SUCCESS) {
        DestroyAlg25519PubKeySpec(tmpSpec);
        LOGE("Copy alg25519 commonSpec memory");
        return HCF_INVALID_PARAMS;
    }
    tmpSpec->pk.data = (unsigned char *)HcfMalloc(srcSpec->pk.len, 0);
    if (tmpSpec->pk.data == NULL) {
        LOGE("Failed to allocate private key memory");
        DestroyAlg25519PubKeySpec(tmpSpec);
        return HCF_ERR_MALLOC;
    }
    (void)memcpy_s(tmpSpec->pk.data, srcSpec->pk.len, srcSpec->pk.data, srcSpec->pk.len);
    tmpSpec->pk.len = srcSpec->pk.len;

    *destSpec = tmpSpec;
    return HCF_SUCCESS;
}

static HcfResult CreateAlg25519PriKeySpecImpl(const HcfAlg25519PriKeyParamsSpec *srcSpec,
    HcfAlg25519PriKeyParamsSpec **destSpec)
{
    HcfAlg25519PriKeyParamsSpec *tmpSpec =
        (HcfAlg25519PriKeyParamsSpec *)HcfMalloc(sizeof(HcfAlg25519PriKeyParamsSpec), 0);
    if (tmpSpec == NULL) {
        LOGE("Failed to allocate dest spec memory");
        return HCF_ERR_MALLOC;
    }
    if (CopyAsyKeyParamsSpec(&(srcSpec->base), &(tmpSpec->base)) != HCF_SUCCESS) {
        DestroyAlg25519PriKeySpec(tmpSpec);
        LOGE("Copy alg25519 commonSpec memory");
        return HCF_INVALID_PARAMS;
    }
    tmpSpec->sk.data = (unsigned char *)HcfMalloc(srcSpec->sk.len, 0);
    if (tmpSpec->sk.data == NULL) {
        LOGE("Failed to allocate private key memory");
        DestroyAlg25519PriKeySpec(tmpSpec);
        return HCF_ERR_MALLOC;
    }
    (void)memcpy_s(tmpSpec->sk.data, srcSpec->sk.len, srcSpec->sk.data, srcSpec->sk.len);
    tmpSpec->sk.len = srcSpec->sk.len;

    *destSpec = tmpSpec;
    return HCF_SUCCESS;
}

static HcfResult CreateAlg25519KeyPairSpecImpl(const HcfAlg25519KeyPairParamsSpec *srcSpec,
    HcfAlg25519KeyPairParamsSpec **destSpec)
{
    HcfAlg25519KeyPairParamsSpec *tmpSpec =
        (HcfAlg25519KeyPairParamsSpec *)HcfMalloc(sizeof(HcfAlg25519KeyPairParamsSpec), 0);
    if (tmpSpec == NULL) {
        LOGE("Failed to allocate dest spec memory");
        return HCF_ERR_MALLOC;
    }
    if (CopyAsyKeyParamsSpec(&(srcSpec->base), &(tmpSpec->base)) != HCF_SUCCESS) {
        DestroyAlg25519KeyPairSpec(tmpSpec);
        LOGE("Copy alg25519 commonSpec memory");
        return HCF_INVALID_PARAMS;
    }
    tmpSpec->pk.data = (unsigned char *)HcfMalloc(srcSpec->pk.len, 0);
    if (tmpSpec->pk.data == NULL) {
        LOGE("Failed to allocate private key memory");
        DestroyAlg25519KeyPairSpec(tmpSpec);
        return HCF_ERR_MALLOC;
    }

    tmpSpec->sk.data = (unsigned char *)HcfMalloc(srcSpec->sk.len, 0);
    if (tmpSpec->sk.data == NULL) {
        LOGE("Failed to allocate private key memory");
        DestroyAlg25519KeyPairSpec(tmpSpec);
        return HCF_ERR_MALLOC;
    }
    (void)memcpy_s(tmpSpec->pk.data, srcSpec->pk.len, srcSpec->pk.data, srcSpec->pk.len);
    tmpSpec->pk.len = srcSpec->pk.len;
    (void)memcpy_s(tmpSpec->sk.data, srcSpec->sk.len, srcSpec->sk.data, srcSpec->sk.len);
    tmpSpec->sk.len = srcSpec->sk.len;

    *destSpec = tmpSpec;
    return HCF_SUCCESS;
}

static HcfResult CreateAlg25519ParamsSpecImpl(const HcfAsyKeyParamsSpec *paramsSpec, HcfAsyKeyParamsSpec **impl)
{
    HcfResult ret = HCF_SUCCESS;
    HcfAlg25519PubKeyParamsSpec *pubKeySpec = NULL;
    HcfAlg25519PriKeyParamsSpec *priKeySpec = NULL;
    HcfAlg25519KeyPairParamsSpec *keyPairSpec = NULL;
    switch (paramsSpec->specType) {
        case HCF_PUBLIC_KEY_SPEC:
            ret = CreateAlg25519PubKeySpecImpl((HcfAlg25519PubKeyParamsSpec *)paramsSpec, &pubKeySpec);
            if (ret == HCF_SUCCESS) {
                *impl = (HcfAsyKeyParamsSpec *)pubKeySpec;
            }
            break;
        case HCF_PRIVATE_KEY_SPEC:
            ret = CreateAlg25519PriKeySpecImpl((HcfAlg25519PriKeyParamsSpec *)paramsSpec, &priKeySpec);
            if (ret == HCF_SUCCESS) {
                *impl = (HcfAsyKeyParamsSpec *)priKeySpec;
            }
            break;
        case HCF_KEY_PAIR_SPEC:
            ret = CreateAlg25519KeyPairSpecImpl((HcfAlg25519KeyPairParamsSpec *)paramsSpec, &keyPairSpec);
            if (ret == HCF_SUCCESS) {
                *impl = (HcfAsyKeyParamsSpec *)keyPairSpec;
            }
            break;
        default:
            LOGE("SpecType not support! [SpecType]: %{public}d", paramsSpec->specType);
            ret = HCF_INVALID_PARAMS;
            break;
    }
    return ret;
}

static HcfResult CreateAsyKeyParamsSpecImpl(const HcfAsyKeyParamsSpec *paramsSpec, HcfAlgValue alg,
    HcfAsyKeyParamsSpec **impl)
{
    HcfResult ret = HCF_SUCCESS;
    switch (alg) {
        case HCF_ALG_DSA:
            ret = CreateDsaParamsSpecImpl(paramsSpec, impl);
            break;
        case HCF_ALG_SM2:
        case HCF_ALG_ECC:
            ret = CreateEccParamsSpecImpl(paramsSpec, impl);
            break;
        case HCF_ALG_RSA:
            ret = CreateRsaParamsSpecImpl(paramsSpec, impl);
            break;
        case HCF_ALG_ED25519:
        case HCF_ALG_X25519:
            ret = CreateAlg25519ParamsSpecImpl(paramsSpec, impl);
            break;
        case HCF_ALG_DH:
            ret = CreateDhParamsSpecImpl(paramsSpec, impl);
            break;
        case HCF_ALG_ML_KEM:
        case HCF_ALG_ML_DSA:
            LOGE("ML-KEM/ML-DSA does not support params spec creation");
            ret = HCF_INVALID_PARAMS;
            break;
        default:
            LOGE("Unsupported algorithm for asy key params spec creation");
            ret = HCF_INVALID_PARAMS;
            break;
    }
    return ret;
}

// export interfaces
static const char *GetAsyKeyGeneratorClass(void)
{
    return ASY_KEY_GENERATOR_CLASS;
}

static const char *GetAsyKeyGeneratorBySpecClass(void)
{
    return ASY_KEY_GENERATOR_BY_SPEC_CLASS;
}

static const char *GetAlgoName(HcfAsyKeyGenerator *self)
{
    if (self == NULL) {
        LOGE("The input self ptr is NULL!");
        return NULL;
    }
    if (!HcfIsClassMatch((HcfObjectBase *)self, GetAsyKeyGeneratorClass())) {
        return NULL;
    }
    HcfAsyKeyGeneratorImpl *impl = (HcfAsyKeyGeneratorImpl *)self;
    return impl->algoName;
}

static const char *GetAlgNameBySpec(const HcfAsyKeyGeneratorBySpec *self)
{
    if (self == NULL) {
        LOGE("The input self ptr is NULL!");
        return NULL;
    }
    if (!HcfIsClassMatch((HcfObjectBase *)self, GetAsyKeyGeneratorBySpecClass())) {
        return NULL;
    }
    HcfAsyKeyGeneratorBySpecImpl *impl = (HcfAsyKeyGeneratorBySpecImpl *)self;
    return impl->paramsSpec->algName;
}

static HcfResult ConvertKey(HcfAsyKeyGenerator *self, HcfParamsSpec *params, HcfBlob *pubKeyBlob,
    HcfBlob *priKeyBlob, HcfKeyPair **returnKeyPair)
{
    if (self == NULL) {
        LOGE("Invalid input parameter.");
        return HCF_INVALID_PARAMS;
    }
    if (!HcfIsClassMatch((HcfObjectBase *)self, GetAsyKeyGeneratorClass())) {
        return HCF_INVALID_PARAMS;
    }
    HcfAsyKeyGeneratorImpl *impl = (HcfAsyKeyGeneratorImpl *)self;
    if (impl->spiObj == NULL || impl->spiObj->engineConvertKey == NULL) {
        LOGE("Invalid input parameter.");
        return HCF_INVALID_PARAMS;
    }
    return impl->spiObj->engineConvertKey(impl->spiObj, params, pubKeyBlob, priKeyBlob, returnKeyPair);
}

static HcfResult ConvertPemKey(HcfAsyKeyGenerator *self, HcfParamsSpec *params, const char *pubKeyStr,
    const char *priKeyStr, HcfKeyPair **returnKeyPair)
{
    if (self == NULL) {
        LOGE("Invalid input parameter.");
        return HCF_INVALID_PARAMS;
    }
    if (!HcfIsClassMatch((HcfObjectBase *)self, GetAsyKeyGeneratorClass())) {
        return HCF_INVALID_PARAMS;
    }
    HcfAsyKeyGeneratorImpl *impl = (HcfAsyKeyGeneratorImpl *)self;
    if (impl->spiObj == NULL || impl->spiObj->engineConvertPemKey == NULL) {
        LOGE("Invalid input parameter.");
        return HCF_INVALID_PARAMS;
    }
    return impl->spiObj->engineConvertPemKey(impl->spiObj, params, pubKeyStr, priKeyStr, returnKeyPair);
}

static HcfResult GenerateKeyPair(HcfAsyKeyGenerator *self, HcfParamsSpec *params,
    HcfKeyPair **returnKeyPair)
{
    (void)params;
    if (self == NULL) {
        LOGE("Invalid input parameter.");
        return HCF_INVALID_PARAMS;
    }
    if (!HcfIsClassMatch((HcfObjectBase *)self, GetAsyKeyGeneratorClass())) {
        return HCF_INVALID_PARAMS;
    }
    HcfAsyKeyGeneratorImpl *impl = (HcfAsyKeyGeneratorImpl *)self;
    if (impl->spiObj == NULL || impl->spiObj->engineGenerateKeyPair == NULL) {
        LOGE("Invalid input parameter.");
        return HCF_INVALID_PARAMS;
    }
    return impl->spiObj->engineGenerateKeyPair(impl->spiObj, returnKeyPair);
}

static HcfResult GenerateKeyPairBySpec(const HcfAsyKeyGeneratorBySpec *self, HcfKeyPair **returnKeyPair)
{
    if (self == NULL) {
        LOGE("Invalid input parameter.");
        return HCF_INVALID_PARAMS;
    }
    if (!HcfIsClassMatch((HcfObjectBase *)self, GetAsyKeyGeneratorBySpecClass())) {
        return HCF_INVALID_PARAMS;
    }
    HcfAsyKeyGeneratorBySpecImpl *impl = (HcfAsyKeyGeneratorBySpecImpl *)self;
    if (impl->spiObj == NULL || impl->spiObj->engineGenerateKeyPairBySpec == NULL) {
        LOGE("Invalid input parameter.");
        return HCF_INVALID_PARAMS;
    }
    return impl->spiObj->engineGenerateKeyPairBySpec(impl->spiObj, impl->paramsSpec, returnKeyPair);
}

static HcfResult GeneratePubKeyBySpec(const HcfAsyKeyGeneratorBySpec *self, HcfPubKey **returnPubKey)
{
    if (self == NULL) {
        LOGE("Invalid input parameter.");
        return HCF_INVALID_PARAMS;
    }
    if (!HcfIsClassMatch((HcfObjectBase *)self, GetAsyKeyGeneratorBySpecClass())) {
        return HCF_INVALID_PARAMS;
    }
    HcfAsyKeyGeneratorBySpecImpl *impl = (HcfAsyKeyGeneratorBySpecImpl *)self;
    if (impl->spiObj == NULL || impl->spiObj->engineGeneratePubKeyBySpec == NULL) {
        LOGE("Invalid input parameter.");
        return HCF_INVALID_PARAMS;
    }
    return impl->spiObj->engineGeneratePubKeyBySpec(impl->spiObj, impl->paramsSpec, returnPubKey);
}

static HcfResult GeneratePriKeyBySpec(const HcfAsyKeyGeneratorBySpec *self, HcfPriKey **returnPriKey)
{
    if (self == NULL) {
        LOGE("Invalid input parameter.");
        return HCF_INVALID_PARAMS;
    }
    if (!HcfIsClassMatch((HcfObjectBase *)self, GetAsyKeyGeneratorBySpecClass())) {
        return HCF_INVALID_PARAMS;
    }
    HcfAsyKeyGeneratorBySpecImpl *impl = (HcfAsyKeyGeneratorBySpecImpl *)self;
    if (impl->spiObj == NULL || impl->spiObj->engineGeneratePriKeyBySpec == NULL) {
        LOGE("Invalid input parameter.");
        return HCF_INVALID_PARAMS;
    }
    return impl->spiObj->engineGeneratePriKeyBySpec(impl->spiObj, impl->paramsSpec, returnPriKey);
}

static void DestroyAsyKeyGenerator(HcfObjectBase *self)
{
    if (self == NULL) {
        return;
    }
    if (!HcfIsClassMatch((HcfObjectBase *)self, GetAsyKeyGeneratorClass())) {
        return;
    }
    HcfAsyKeyGeneratorImpl *impl = (HcfAsyKeyGeneratorImpl *)self;
    HcfObjDestroy(impl->spiObj);
    impl->spiObj = NULL;
    HcfFree(impl);
}

static void DestroyAsyKeyGeneratorBySpec(HcfObjectBase *self)
{
    if (self == NULL) {
        return;
    }
    if (!HcfIsClassMatch((HcfObjectBase *)self, GetAsyKeyGeneratorBySpecClass())) {
        return;
    }
    HcfAsyKeyGeneratorBySpecImpl *impl = (HcfAsyKeyGeneratorBySpecImpl *)self;
    HcfObjDestroy(impl->spiObj);
    impl->spiObj = NULL;
    FreeAsyKeySpec(impl->paramsSpec);
    impl->paramsSpec = NULL;
    HcfFree(impl);
}

HcfResult HcfAsyKeyGeneratorCreate(const char *algoName, HcfAsyKeyGenerator **returnObj)
{
    if ((!HcfIsStrValid(algoName, HCF_MAX_ALGO_NAME_LEN)) || (returnObj == NULL)) {
        LOGE("AlgoName is invalid or returnObj is null");
        return HCF_INVALID_PARAMS;
    }

    HcfAsyKeyGenParams params = { 0 };
    if (ParseAndSetParameter(algoName, &params, ParseAsyKeyGenParams) != HCF_SUCCESS) {
        LOGE("Failed to parse params!");
        return HCF_INVALID_PARAMS;
    }

    HcfAsyKeyGeneratorSpiCreateFunc createSpiFunc = FindAbility(&params);
    if (createSpiFunc == NULL) {
        LOGE("No matching asy key generator ability found");
        return HCF_NOT_SUPPORT;
    }

    HcfAsyKeyGeneratorImpl *returnGenerator = (HcfAsyKeyGeneratorImpl *)HcfMalloc(sizeof(HcfAsyKeyGeneratorImpl), 0);
    if (returnGenerator == NULL) {
        LOGE("Failed to allocate returnGenerator memory!");
        return HCF_ERR_MALLOC;
    }
    if (strcpy_s(returnGenerator->algoName, HCF_MAX_ALGO_NAME_LEN, algoName) != EOK) {
        LOGE("Failed to copy algoName!");
        HcfFree(returnGenerator);
        returnGenerator = NULL;
        return HCF_INVALID_PARAMS;
    }
    HcfAsyKeyGeneratorSpi *spiObj = NULL;
    HcfResult res = HCF_SUCCESS;
    res = createSpiFunc(&params, &spiObj);
    if (res != HCF_SUCCESS) {
        LOGE("Failed to create spi object!");
        HcfFree(returnGenerator);
        returnGenerator = NULL;
        return res;
    }
    returnGenerator->base.base.destroy = DestroyAsyKeyGenerator;
    returnGenerator->base.base.getClass = GetAsyKeyGeneratorClass;
    returnGenerator->base.convertKey = ConvertKey;
    returnGenerator->base.convertPemKey = ConvertPemKey;
    returnGenerator->base.generateKeyPair = GenerateKeyPair;
    returnGenerator->base.getAlgoName = GetAlgoName;
    returnGenerator->spiObj = spiObj;
    *returnObj = (HcfAsyKeyGenerator *)returnGenerator;
    return HCF_SUCCESS;
}

HcfResult HcfAsyKeyGeneratorBySpecCreate(const HcfAsyKeyParamsSpec *paramsSpec, HcfAsyKeyGeneratorBySpec **returnObj)
{
    if ((!IsParamsSpecValid(paramsSpec)) || (returnObj == NULL)) {
        LOGE("ParamsSpec is invalid or returnObj is null");
        return HCF_INVALID_PARAMS;
    }
    HcfAsyKeyGenParams params = { 0 };
    if (ParseAlgNameToParams(paramsSpec->algName, &params) != HCF_SUCCESS) {
        LOGE("Failed to parse params!");
        return HCF_INVALID_PARAMS;
    }
    HcfAsyKeyGeneratorSpiCreateFunc createSpiFunc = FindAbility(&params);
    if (createSpiFunc == NULL) {
        LOGE("No matching asy key generator by spec ability found");
        return HCF_NOT_SUPPORT;
    }
    HcfAsyKeyGeneratorBySpecImpl *returnGenerator =
        (HcfAsyKeyGeneratorBySpecImpl *)HcfMalloc(sizeof(HcfAsyKeyGeneratorBySpecImpl), 0);
    if (returnGenerator == NULL) {
        LOGE("Failed to allocate returnGenerator memory!");
        return HCF_ERR_MALLOC;
    }
    HcfAsyKeyParamsSpec *paramsSpecImpl = NULL;
    HcfResult ret = CreateAsyKeyParamsSpecImpl(paramsSpec, params.algo, &paramsSpecImpl);
    if (ret != HCF_SUCCESS) {
        LOGE("Failed to create asy key params spec impl!");
        HcfFree(returnGenerator);
        returnGenerator = NULL;
        return ret;
    }
    HcfAsyKeyGeneratorSpi *spiObj = NULL;
    ret = createSpiFunc(&params, &spiObj);
    if (ret != HCF_SUCCESS) {
        LOGE("Failed to create spi object!");
        HcfFree(returnGenerator);
        returnGenerator = NULL;
        FreeAsyKeySpec(paramsSpecImpl);
        paramsSpecImpl = NULL;
        return ret;
    }
    returnGenerator->base.base.destroy = DestroyAsyKeyGeneratorBySpec;
    returnGenerator->base.base.getClass = GetAsyKeyGeneratorBySpecClass;
    returnGenerator->base.generateKeyPair = GenerateKeyPairBySpec;
    returnGenerator->base.generatePubKey = GeneratePubKeyBySpec;
    returnGenerator->base.generatePriKey = GeneratePriKeyBySpec;
    returnGenerator->base.getAlgName = GetAlgNameBySpec;
    returnGenerator->paramsSpec = paramsSpecImpl;
    returnGenerator->spiObj = spiObj;
    *returnObj = (HcfAsyKeyGeneratorBySpec *)returnGenerator;
    return HCF_SUCCESS;
}
