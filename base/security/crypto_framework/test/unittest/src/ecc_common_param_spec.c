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

#include "ecc_common_param_spec.h"
#include "securec.h"
#include "asy_key_generator.h"
#include "ecc_key_util.h"
#include "memory.h"
#include "memory_mock.h"

static char *g_brainpool160r1AlgName = "ECC_BrainPoolP160r1";
HcfEccCommParamsSpec *g_eccCommSpec = NULL;

HcfResult ConstructEccKeyPairCommParamsSpec(const char *algoName, HcfEccCommParamsSpec **spec)
{
    HcfEccCommParamsSpec *eccCommSpec = NULL;
    HcfEccKeyUtilCreate(algoName, &eccCommSpec);
    if (eccCommSpec == NULL) {
        return HCF_INVALID_PARAMS;
    }
    *spec = eccCommSpec;
    return HCF_SUCCESS;
}

static HcfResult ConstructEccKeyPairBigInt(HcfKeyPair *keyPair, HcfEccKeyPairParamsSpec *eccKeyPairSpec)
{
    HcfBigInteger retBigInt = { .data = NULL, .len = 0 };
    HcfResult res = keyPair->pubKey->getAsyKeySpecBigInteger(keyPair->pubKey, ECC_PK_X_BN, &retBigInt);
    if (res != HCF_SUCCESS) {
        return res;
    }
    eccKeyPairSpec->pk.x.data = retBigInt.data;
    eccKeyPairSpec->pk.x.len = retBigInt.len;

    res = keyPair->pubKey->getAsyKeySpecBigInteger(keyPair->pubKey, ECC_PK_Y_BN, &retBigInt);
    if (res != HCF_SUCCESS) {
        HcfFree(eccKeyPairSpec->pk.x.data);
        eccKeyPairSpec->pk.x.data = NULL;
        eccKeyPairSpec->pk.x.len = 0;
        return res;
    }
    eccKeyPairSpec->pk.y.data = retBigInt.data;
    eccKeyPairSpec->pk.y.len = retBigInt.len;

    res = keyPair->priKey->getAsyKeySpecBigInteger(keyPair->priKey, ECC_SK_BN, &retBigInt);
    if (res != HCF_SUCCESS) {
        HcfFree(eccKeyPairSpec->pk.x.data);
        eccKeyPairSpec->pk.x.data = NULL;
        eccKeyPairSpec->pk.x.len = 0;
        HcfFree(eccKeyPairSpec->pk.y.data);
        eccKeyPairSpec->pk.y.data = NULL;
        eccKeyPairSpec->pk.y.len = 0;
        return res;
    }
    eccKeyPairSpec->sk.data = retBigInt.data;
    eccKeyPairSpec->sk.len = retBigInt.len;
    return HCF_SUCCESS;
}

HcfResult ConstructEccKeyPairParamsSpec(const char *algoName, HcfEccCommParamsSpec *eccCommSpec,
    HcfAsyKeyParamsSpec **spec)
{
    if (eccCommSpec == NULL) {
        return HCF_INVALID_PARAMS;
    }
    HcfAsyKeyGenerator *generator = NULL;
    HcfResult res = HCF_ERR_CRYPTO_OPERATION;
    if (HcfAsyKeyGeneratorCreate(algoName, &generator) != HCF_SUCCESS) {
        return res;
    }
    HcfKeyPair *keyPair = NULL;
    if (generator->generateKeyPair(generator, NULL, &keyPair) != HCF_SUCCESS) {
        HcfObjDestroy(generator);
        return res;
    }

    HcfEccKeyPairParamsSpec *eccKeyPairSpec = (HcfEccKeyPairParamsSpec*)HcfMalloc(sizeof(HcfEccKeyPairParamsSpec), 0);
    if (eccKeyPairSpec != NULL) {
        eccKeyPairSpec->base.base.algName = eccCommSpec->base.algName;
        eccKeyPairSpec->base.base.specType = HCF_KEY_PAIR_SPEC;
        eccKeyPairSpec->base.field = eccCommSpec->field;
        eccKeyPairSpec->base.field->fieldType = eccCommSpec->field->fieldType;
        ((HcfECFieldFp *)(eccKeyPairSpec->base.field))->p.data = ((HcfECFieldFp *)(eccCommSpec->field))->p.data;
        ((HcfECFieldFp *)(eccKeyPairSpec->base.field))->p.len = ((HcfECFieldFp *)(eccCommSpec->field))->p.len;
        eccKeyPairSpec->base.a.data = eccCommSpec->a.data;
        eccKeyPairSpec->base.a.len = eccCommSpec->a.len;
        eccKeyPairSpec->base.b.data = eccCommSpec->b.data;
        eccKeyPairSpec->base.b.len = eccCommSpec->b.len;
        eccKeyPairSpec->base.g.x.data = eccCommSpec->g.x.data;
        eccKeyPairSpec->base.g.x.len = eccCommSpec->g.x.len;
        eccKeyPairSpec->base.g.y.data = eccCommSpec->g.y.data;
        eccKeyPairSpec->base.g.y.len = eccCommSpec->g.y.len;
        eccKeyPairSpec->base.n.data = eccCommSpec->n.data;
        eccKeyPairSpec->base.n.len = eccCommSpec->n.len;
        eccKeyPairSpec->base.h = eccCommSpec->h;
        if (ConstructEccKeyPairBigInt(keyPair, eccKeyPairSpec) != HCF_SUCCESS) {
            HcfFree(eccKeyPairSpec);
        } else {
            *spec = (HcfAsyKeyParamsSpec *)eccKeyPairSpec;
            res = HCF_SUCCESS;
        }
    }
    HcfObjDestroy(generator);
    HcfObjDestroy(keyPair);
    return res;
}

static HcfResult ConstructEccPubKeyBigInt(HcfKeyPair *keyPair, HcfEccPubKeyParamsSpec *eccPubKeySpec)
{
    HcfBigInteger retBigInt = { .data = NULL, .len = 0 };
    HcfResult res = keyPair->pubKey->getAsyKeySpecBigInteger(keyPair->pubKey, ECC_PK_X_BN, &retBigInt);
    if (res != HCF_SUCCESS) {
        return res;
    }
    eccPubKeySpec->pk.x.data = retBigInt.data;
    eccPubKeySpec->pk.x.len = retBigInt.len;

    res = keyPair->pubKey->getAsyKeySpecBigInteger(keyPair->pubKey, ECC_PK_Y_BN, &retBigInt);
    if (res != HCF_SUCCESS) {
        HcfFree(eccPubKeySpec->pk.x.data);
        eccPubKeySpec->pk.x.data = NULL;
        eccPubKeySpec->pk.x.len = 0;
        return res;
    }
    eccPubKeySpec->pk.y.data = retBigInt.data;
    eccPubKeySpec->pk.y.len = retBigInt.len;
    return HCF_SUCCESS;
}

HcfResult ConstructEccPubKeyParamsSpec(const char *algoName, HcfEccCommParamsSpec *eccCommSpec,
    HcfAsyKeyParamsSpec **spec)
{
    if (eccCommSpec == NULL) {
        return HCF_INVALID_PARAMS;
    }

    HcfResult res = HCF_ERR_CRYPTO_OPERATION;
    HcfAsyKeyGenerator *generator = NULL;
    if (HcfAsyKeyGeneratorCreate(algoName, &generator) != HCF_SUCCESS) {
        return res;
    }

    HcfKeyPair *keyPair = NULL;
    if (generator->generateKeyPair(generator, NULL, &keyPair) != HCF_SUCCESS) {
        HcfObjDestroy(generator);
        return res;
    }

    HcfEccPubKeyParamsSpec *eccPubKeySpec = (HcfEccPubKeyParamsSpec*)HcfMalloc(sizeof(HcfEccPubKeyParamsSpec), 0);
    if (eccPubKeySpec != NULL) {
        eccPubKeySpec->base.base.algName = eccCommSpec->base.algName;
        eccPubKeySpec->base.base.specType = HCF_PUBLIC_KEY_SPEC;
        eccPubKeySpec->base.field = eccCommSpec->field;
        eccPubKeySpec->base.field->fieldType = eccCommSpec->field->fieldType;
        ((HcfECFieldFp *)(eccPubKeySpec->base.field))->p.data = ((HcfECFieldFp *)(eccCommSpec->field))->p.data;
        ((HcfECFieldFp *)(eccPubKeySpec->base.field))->p.len = ((HcfECFieldFp *)(eccCommSpec->field))->p.len;
        eccPubKeySpec->base.a.data = eccCommSpec->a.data;
        eccPubKeySpec->base.a.len = eccCommSpec->a.len;
        eccPubKeySpec->base.b.data = eccCommSpec->b.data;
        eccPubKeySpec->base.b.len = eccCommSpec->b.len;
        eccPubKeySpec->base.g.x.data = eccCommSpec->g.x.data;
        eccPubKeySpec->base.g.x.len = eccCommSpec->g.x.len;
        eccPubKeySpec->base.g.y.data = eccCommSpec->g.y.data;
        eccPubKeySpec->base.g.y.len = eccCommSpec->g.y.len;
        eccPubKeySpec->base.n.data = eccCommSpec->n.data;
        eccPubKeySpec->base.n.len = eccCommSpec->n.len;
        eccPubKeySpec->base.h = eccCommSpec->h;
        if (ConstructEccPubKeyBigInt(keyPair, eccPubKeySpec) != HCF_SUCCESS) {
            HcfFree(eccPubKeySpec);
        } else {
            *spec = (HcfAsyKeyParamsSpec *)eccPubKeySpec;
            res = HCF_SUCCESS;
        }
    }

    HcfObjDestroy(generator);
    HcfObjDestroy(keyPair);
    return res;
}

HcfResult ConstructEccPriKeyParamsSpec(const char *algoName, HcfEccCommParamsSpec *eccCommSpec,
    HcfAsyKeyParamsSpec **spec)
{
    if (eccCommSpec == NULL) {
        return HCF_INVALID_PARAMS;
    }

    HcfResult res = HCF_ERR_CRYPTO_OPERATION;
    HcfAsyKeyGenerator *generator = NULL;
    if (HcfAsyKeyGeneratorCreate(algoName, &generator) != HCF_SUCCESS) {
        return res;
    }

    HcfKeyPair *keyPair = NULL;
    if (generator->generateKeyPair(generator, NULL, &keyPair) != HCF_SUCCESS) {
        HcfObjDestroy(generator);
        return res;
    }

    HcfEccPriKeyParamsSpec *eccPriKeySpec = (HcfEccPriKeyParamsSpec*)HcfMalloc(sizeof(HcfEccPriKeyParamsSpec), 0);
    if (eccPriKeySpec != NULL) {
        eccPriKeySpec->base.base.algName = eccCommSpec->base.algName;
        eccPriKeySpec->base.base.specType = HCF_PRIVATE_KEY_SPEC;
        eccPriKeySpec->base.field = eccCommSpec->field;
        eccPriKeySpec->base.field->fieldType = eccCommSpec->field->fieldType;
        ((HcfECFieldFp *)(eccPriKeySpec->base.field))->p.data = ((HcfECFieldFp *)(eccCommSpec->field))->p.data;
        ((HcfECFieldFp *)(eccPriKeySpec->base.field))->p.len = ((HcfECFieldFp *)(eccCommSpec->field))->p.len;
        eccPriKeySpec->base.a.data = eccCommSpec->a.data;
        eccPriKeySpec->base.a.len = eccCommSpec->a.len;
        eccPriKeySpec->base.b.data = eccCommSpec->b.data;
        eccPriKeySpec->base.b.len = eccCommSpec->b.len;
        eccPriKeySpec->base.g.x.data = eccCommSpec->g.x.data;
        eccPriKeySpec->base.g.x.len = eccCommSpec->g.x.len;
        eccPriKeySpec->base.g.y.data = eccCommSpec->g.y.data;
        eccPriKeySpec->base.g.y.len = eccCommSpec->g.y.len;
        eccPriKeySpec->base.n.data = eccCommSpec->n.data;
        eccPriKeySpec->base.n.len = eccCommSpec->n.len;
        eccPriKeySpec->base.h = eccCommSpec->h;
        HcfBigInteger retBigInt = { .data = NULL, .len = 0 };
        if (keyPair->priKey->getAsyKeySpecBigInteger(keyPair->priKey, ECC_SK_BN, &retBigInt) != HCF_SUCCESS) {
            HcfFree(eccPriKeySpec);
        } else {
            eccPriKeySpec->sk.data = retBigInt.data;
            eccPriKeySpec->sk.len = retBigInt.len;
            *spec = (HcfAsyKeyParamsSpec *)eccPriKeySpec;
            res = HCF_SUCCESS;
        }
    }
    HcfObjDestroy(generator);
    HcfObjDestroy(keyPair);
    return res;
}

HcfResult GenerateBrainpoolP160r1KeyPair(HcfKeyPair **keyPair)
{
    HcfEccCommParamsSpec *eccCommSpec = NULL;
    HcfResult res = ConstructEccKeyPairCommParamsSpec("NID_brainpoolP160r1", &eccCommSpec);
    if (res != HCF_SUCCESS) {
        return res;
    }
    HcfAsyKeyParamsSpec *paramSpec = NULL;
    res = ConstructEccKeyPairParamsSpec(g_brainpool160r1AlgName, eccCommSpec, &paramSpec);
    if (res != HCF_SUCCESS) {
        FreeEccCommParamsSpec(eccCommSpec);
        HcfFree(eccCommSpec);
        return res;
    }
    HcfAsyKeyGeneratorBySpec *generator = NULL;
    res = HcfAsyKeyGeneratorBySpecCreate(paramSpec, &generator);
    if (res != HCF_SUCCESS) {
        DestroyEccKeyPairSpec((HcfEccKeyPairParamsSpec *)paramSpec);
        HcfFree(eccCommSpec);
        return res;
    }
    res = generator->generateKeyPair(generator, keyPair);
    if (res != HCF_SUCCESS) {
        HcfObjDestroy(generator);
        DestroyEccKeyPairSpec((HcfEccKeyPairParamsSpec *)paramSpec);
        HcfFree(eccCommSpec);
        return res;
    }
    HcfObjDestroy(generator);
    DestroyEccKeyPairSpec((HcfEccKeyPairParamsSpec *)paramSpec);
    HcfFree(eccCommSpec);
    return HCF_SUCCESS;
}
