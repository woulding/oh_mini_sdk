/*
 * Copyright (C) 2023-2024 Huawei Device Co., Ltd.
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

#include "asy_key_params.h"

#include <string.h>
#include <securec.h>
#include "params_parser.h"
#include "big_integer.h"
#include "detailed_dsa_key_params.h"
#include "detailed_dh_key_params.h"
#include "detailed_ecc_key_params.h"
#include "detailed_rsa_key_params.h"
#include "detailed_alg_25519_key_params.h"
#include "sm2_crypto_params.h"
#include "memory.h"
#include "log.h"

#define ALG_NAME_DSA "DSA"
#define ALG_NAME_ECC "ECC"
#define ALG_NAME_SM2 "SM2"
#define ALG_NAME_RSA "RSA"
#define ALG_NAME_DH "DH"
#define ALG_NAME_ED25519 "Ed25519"
#define ALG_NAME_X25519 "X25519"

typedef void (*HcfFreeParamsAsyKeySpec)(HcfAsyKeyParamsSpec *);

typedef struct {
    char *algo;

    HcfFreeParamsAsyKeySpec createFreeFunc;
} HcfFreeAsyKeySpec;

void FreeDsaCommParamsSpec(HcfDsaCommParamsSpec *spec)
{
    if (spec == NULL) {
        return;
    }
    HcfFree(spec->base.algName);
    spec->base.algName = NULL;
    HcfFree(spec->p.data);
    spec->p.data = NULL;
    HcfFree(spec->q.data);
    spec->q.data = NULL;
    HcfFree(spec->g.data);
    spec->g.data = NULL;
}

void FreeDhCommParamsSpec(HcfDhCommParamsSpec *spec)
{
    if (spec == NULL) {
        return;
    }
    HcfFree(spec->base.algName);
    spec->base.algName = NULL;
    HcfFree(spec->p.data);
    spec->p.data = NULL;
    HcfFree(spec->g.data);
    spec->g.data = NULL;
}

static void DestroyDsaCommParamsSpec(HcfDsaCommParamsSpec *spec)
{
    FreeDsaCommParamsSpec(spec);
    HcfFree(spec);
}

void DestroyDsaPubKeySpec(HcfDsaPubKeyParamsSpec *spec)
{
    if (spec == NULL) {
        return;
    }
    FreeDsaCommParamsSpec(&(spec->base));
    HcfFree(spec->pk.data);
    spec->pk.data = NULL;
    HcfFree(spec);
}

void DestroyDsaKeyPairSpec(HcfDsaKeyPairParamsSpec *spec)
{
    if (spec == NULL) {
        return;
    }
    FreeDsaCommParamsSpec(&(spec->base));
    HcfFree(spec->pk.data);
    spec->pk.data = NULL;
    if (spec->sk.data != NULL) {
        (void)memset_s(spec->sk.data, spec->sk.len, 0, spec->sk.len);
        HcfFree(spec->sk.data);
        spec->sk.data = NULL;
    }
    HcfFree(spec);
}

static void DestroyDhCommParamsSpec(HcfDhCommParamsSpec *spec)
{
    FreeDhCommParamsSpec(spec);
    HcfFree(spec);
}

void DestroyDhPubKeySpec(HcfDhPubKeyParamsSpec *spec)
{
    if (spec == NULL) {
        return;
    }
    FreeDhCommParamsSpec(&(spec->base));
    HcfFree(spec->pk.data);
    spec->pk.data = NULL;
    HcfFree(spec);
}

void DestroyDhPriKeySpec(HcfDhPriKeyParamsSpec *spec)
{
    if (spec == NULL) {
        return;
    }
    FreeDhCommParamsSpec(&(spec->base));
    if (spec->sk.data != NULL) {
        (void)memset_s(spec->sk.data, spec->sk.len, 0, spec->sk.len);
        HcfFree(spec->sk.data);
        spec->sk.data = NULL;
    }
    HcfFree(spec);
}

void DestroyDhKeyPairSpec(HcfDhKeyPairParamsSpec *spec)
{
    if (spec == NULL) {
        return;
    }
    FreeDhCommParamsSpec(&(spec->base));
    HcfFree(spec->pk.data);
    spec->pk.data = NULL;
    if (spec->sk.data != NULL) {
        (void)memset_s(spec->sk.data, spec->sk.len, 0, spec->sk.len);
        HcfFree(spec->sk.data);
        spec->sk.data = NULL;
    }
    HcfFree(spec);
}

static void FreeEcFieldMem(HcfECField **field)
{
    HcfFree((*field)->fieldType);
    (*field)->fieldType = NULL;
    HcfFree(((HcfECFieldFp *)(*field))->p.data);
    ((HcfECFieldFp *)(*field))->p.data = NULL;
    HcfFree(*field);
    *field = NULL;
}

void FreeEcPointMem(HcfPoint *point)
{
    if (point == NULL) {
        return;
    }
    HcfFree(point->x.data);
    point->x.data = NULL;
    HcfFree(point->y.data);
    point->y.data = NULL;
}

void FreeEccCommParamsSpec(HcfEccCommParamsSpec *spec)
{
    if (spec == NULL) {
        return;
    }
    HcfFree(spec->base.algName);
    spec->base.algName = NULL;
    HcfFree(spec->a.data);
    spec->a.data = NULL;
    HcfFree(spec->b.data);
    spec->b.data = NULL;
    HcfFree(spec->n.data);
    spec->n.data = NULL;
    if (spec->field != NULL) {
        FreeEcFieldMem(&(spec->field));
        spec->field = NULL;
    }
    FreeEcPointMem(&(spec->g));
}

static void DestroyEccCommParamsSpec(HcfEccCommParamsSpec *spec)
{
    FreeEccCommParamsSpec(spec);
    HcfFree(spec);
}

void DestroyEccPubKeySpec(HcfEccPubKeyParamsSpec *spec)
{
    if (spec == NULL) {
        return;
    }
    FreeEccCommParamsSpec(&(spec->base));
    FreeEcPointMem(&(spec->pk));
    HcfFree(spec);
}

void DestroyEccPriKeySpec(HcfEccPriKeyParamsSpec *spec)
{
    if (spec == NULL) {
        return;
    }
    FreeEccCommParamsSpec(&(spec->base));
    if (spec->sk.data != NULL) {
        (void)memset_s(spec->sk.data, spec->sk.len, 0, spec->sk.len);
        HcfFree(spec->sk.data);
        spec->sk.data = NULL;
    }
    HcfFree(spec);
}

void DestroyEccKeyPairSpec(HcfEccKeyPairParamsSpec *spec)
{
    if (spec == NULL) {
        return;
    }
    FreeEccCommParamsSpec(&(spec->base));
    FreeEcPointMem(&(spec->pk));
    if (spec->sk.data != NULL) {
        (void)memset_s(spec->sk.data, spec->sk.len, 0, spec->sk.len);
        HcfFree(spec->sk.data);
        spec->sk.data = NULL;
    }
    HcfFree(spec);
}

void FreeRsaCommParamsSpec(HcfRsaCommParamsSpec *spec)
{
    if (spec == NULL) {
        return;
    }
    HcfFree(spec->base.algName);
    spec->base.algName = NULL;
    HcfFree(spec->n.data);
    spec->n.data = NULL;
}

static void DestroyRsaCommParamsSpec(HcfRsaCommParamsSpec *spec)
{
    FreeRsaCommParamsSpec(spec);
    HcfFree(spec);
}

void DestroyRsaPubKeySpec(HcfRsaPubKeyParamsSpec *spec)
{
    if (spec == NULL) {
        return;
    }
    FreeRsaCommParamsSpec(&(spec->base));
    HcfFree(spec->pk.data);
    spec->pk.data = NULL;
    HcfFree(spec);
}

void DestroyRsaKeyPairSpec(HcfRsaKeyPairParamsSpec *spec)
{
    if (spec == NULL) {
        return;
    }
    FreeRsaCommParamsSpec(&(spec->base));
    HcfFree(spec->pk.data);
    spec->pk.data = NULL;
    if (spec->sk.data != NULL) {
        (void)memset_s(spec->sk.data, spec->sk.len, 0, spec->sk.len);
        HcfFree(spec->sk.data);
        spec->sk.data = NULL;
    }
    HcfFree(spec);
}

static void DestroyDsaParamsSpec(HcfAsyKeyParamsSpec *spec)
{
    switch (spec->specType) {
        case HCF_COMMON_PARAMS_SPEC:
            DestroyDsaCommParamsSpec((HcfDsaCommParamsSpec *)spec);
            break;
        case HCF_PUBLIC_KEY_SPEC:
            DestroyDsaPubKeySpec((HcfDsaPubKeyParamsSpec *)spec);
            break;
        case HCF_KEY_PAIR_SPEC:
            DestroyDsaKeyPairSpec((HcfDsaKeyPairParamsSpec *)spec);
            break;
        default:
            LOGE("No matching DSA key params spec type.");
            break;
    }
}

static void DestroyDhParamsSpec(HcfAsyKeyParamsSpec *spec)
{
    switch (spec->specType) {
        case HCF_COMMON_PARAMS_SPEC:
            DestroyDhCommParamsSpec((HcfDhCommParamsSpec *)spec);
            break;
        case HCF_PUBLIC_KEY_SPEC:
            DestroyDhPubKeySpec((HcfDhPubKeyParamsSpec *)spec);
            break;
        case HCF_PRIVATE_KEY_SPEC:
            DestroyDhPriKeySpec((HcfDhPriKeyParamsSpec *)spec);
            break;
        case HCF_KEY_PAIR_SPEC:
            DestroyDhKeyPairSpec((HcfDhKeyPairParamsSpec *)spec);
            break;
        default:
            LOGE("No matching DH key params spec type.");
            break;
    }
}

static void DestroyEccParamsSpec(HcfAsyKeyParamsSpec *spec)
{
    switch (spec->specType) {
        case HCF_COMMON_PARAMS_SPEC:
            DestroyEccCommParamsSpec((HcfEccCommParamsSpec *)spec);
            break;
        case HCF_PRIVATE_KEY_SPEC:
            DestroyEccPriKeySpec((HcfEccPriKeyParamsSpec *)spec);
            break;
        case HCF_PUBLIC_KEY_SPEC:
            DestroyEccPubKeySpec((HcfEccPubKeyParamsSpec *)spec);
            break;
        case HCF_KEY_PAIR_SPEC:
            DestroyEccKeyPairSpec((HcfEccKeyPairParamsSpec *)spec);
            break;
        default:
            LOGE("No matching ECC key params spec type.");
            break;
    }
}

static void DestroyRsaParamsSpec(HcfAsyKeyParamsSpec *spec)
{
    switch (spec->specType) {
        case HCF_COMMON_PARAMS_SPEC:
            DestroyRsaCommParamsSpec((HcfRsaCommParamsSpec *)spec);
            break;
        case HCF_PUBLIC_KEY_SPEC:
            DestroyRsaPubKeySpec((HcfRsaPubKeyParamsSpec *)spec);
            break;
        case HCF_KEY_PAIR_SPEC:
            DestroyRsaKeyPairSpec((HcfRsaKeyPairParamsSpec *)spec);
            break;
        default:
            LOGE("No matching RSA key params spec type.");
            break;
    }
}

void DestroyAlg25519PubKeySpec(HcfAlg25519PubKeyParamsSpec *spec)
{
    if (spec == NULL) {
        return;
    }
    if (spec->pk.data != NULL) {
        (void)memset_s(spec->pk.data, spec->pk.len, 0, spec->pk.len);
        HcfFree(spec->pk.data);
        spec->pk.data = NULL;
    }
    if (spec->base.algName != NULL) {
        HcfFree(spec->base.algName);
        spec->base.algName = NULL;
    }
    HcfFree(spec);
}

void DestroyAlg25519PriKeySpec(HcfAlg25519PriKeyParamsSpec *spec)
{
    if (spec == NULL) {
        return;
    }
    if (spec->sk.data != NULL) {
        (void)memset_s(spec->sk.data, spec->sk.len, 0, spec->sk.len);
        HcfFree(spec->sk.data);
        spec->sk.data = NULL;
    }
    if (spec->base.algName != NULL) {
        HcfFree(spec->base.algName);
        spec->base.algName = NULL;
    }
    HcfFree(spec);
}

void DestroyAlg25519KeyPairSpec(HcfAlg25519KeyPairParamsSpec *spec)
{
    if (spec == NULL) {
        return;
    }
    if (spec->pk.data != NULL) {
        (void)memset_s(spec->pk.data, spec->pk.len, 0, spec->pk.len);
        HcfFree(spec->pk.data);
        spec->pk.data = NULL;
    }
    if (spec->sk.data != NULL) {
        (void)memset_s(spec->sk.data, spec->sk.len, 0, spec->sk.len);
        HcfFree(spec->sk.data);
        spec->sk.data = NULL;
    }
    if (spec->base.algName != NULL) {
        HcfFree(spec->base.algName);
        spec->base.algName = NULL;
    }
    HcfFree(spec);
}

static void DestroyAlg25519ParamsSpec(HcfAsyKeyParamsSpec *spec)
{
    switch (spec->specType) {
        case HCF_PUBLIC_KEY_SPEC:
            DestroyAlg25519PubKeySpec((HcfAlg25519PubKeyParamsSpec *)spec);
            break;
        case HCF_PRIVATE_KEY_SPEC:
            DestroyAlg25519PriKeySpec((HcfAlg25519PriKeyParamsSpec *)spec);
            break;
        case HCF_KEY_PAIR_SPEC:
            DestroyAlg25519KeyPairSpec((HcfAlg25519KeyPairParamsSpec *)spec);
            break;
        default:
            LOGE("No matching alg25519 key params spec type.");
            break;
    }
}

static HcfFreeAsyKeySpec g_asyKeyFreeAbility[] = {
    { ALG_NAME_DSA, DestroyDsaParamsSpec },
    { ALG_NAME_ECC, DestroyEccParamsSpec },
    { ALG_NAME_SM2, DestroyEccParamsSpec },
    { ALG_NAME_RSA, DestroyRsaParamsSpec },
    { ALG_NAME_X25519, DestroyAlg25519ParamsSpec },
    { ALG_NAME_ED25519, DestroyAlg25519ParamsSpec },
    { ALG_NAME_DH, DestroyDhParamsSpec }
};

static HcfFreeParamsAsyKeySpec FindAsyKeySpecFreeAbility(HcfAsyKeyParamsSpec *spec)
{
    for (uint32_t i = 0; i < sizeof(g_asyKeyFreeAbility) / sizeof(g_asyKeyFreeAbility[0]); i++) {
        if (strcmp(spec->algName, g_asyKeyFreeAbility[i].algo) == 0) {
            return g_asyKeyFreeAbility[i].createFreeFunc;
        }
    }
    LOGE("No matching key params spec alg name! [Algo]: %{public}s", spec->algName);
    return NULL;
}

void FreeAsyKeySpec(HcfAsyKeyParamsSpec *spec)
{
    if (spec == NULL || spec->algName == NULL) {
        LOGE("Invalid input parameter.");
        return;
    }
    HcfFreeParamsAsyKeySpec createFreeFunc = FindAsyKeySpecFreeAbility(spec);
    if (createFreeFunc != NULL) {
        createFreeFunc(spec);
    } else {
        LOGE("create freeFunc failed.");
    }
}

void DestroySm2CipherTextSpec(Sm2CipherTextSpec *spec)
{
    if (spec == NULL) {
        return;
    }
    HcfFree(spec->xCoordinate.data);
    spec->xCoordinate.data = NULL;
    HcfFree(spec->yCoordinate.data);
    spec->yCoordinate.data = NULL;
    HcfBlobDataFree(&(spec->cipherTextData));
    HcfBlobDataFree(&(spec->hashData));
    HcfFree(spec);
}

void DestroySm2EcSignatureSpec(Sm2EcSignatureDataSpec *spec)
{
    if (spec == NULL) {
        return;
    }
    HcfFree(spec->rCoordinate.data);
    spec->rCoordinate.data = NULL;
    HcfFree(spec->sCoordinate.data);
    spec->sCoordinate.data = NULL;
    HcfFree(spec);
}
