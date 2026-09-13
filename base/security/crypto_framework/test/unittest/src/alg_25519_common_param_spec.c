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

#include "alg_25519_common_param_spec.h"
#include "securec.h"
#include "asy_key_generator.h"
#include "memory.h"
#include "memory_mock.h"

static HcfResult CreateAlg25519KeyPairSpec(bool choose, HcfAlg25519KeyPairParamsSpec **alg25519KeyPairSpec)
{
    *alg25519KeyPairSpec = (HcfAlg25519KeyPairParamsSpec*)HcfMalloc(sizeof(HcfAlg25519KeyPairParamsSpec), 0);
    if (*alg25519KeyPairSpec == NULL) {
        return HCF_ERR_MALLOC;
    }
    if (choose) {
        (*alg25519KeyPairSpec)->base.algName = (char*)HcfMalloc(sizeof("Ed25519"), 0);
        if ((*alg25519KeyPairSpec)->base.algName == NULL) {
            HcfFree(*alg25519KeyPairSpec);
            *alg25519KeyPairSpec = NULL;
            return HCF_ERR_MALLOC;
        }
        (void)memcpy_s((*alg25519KeyPairSpec)->base.algName, sizeof("Ed25519"),
            "Ed25519", sizeof("Ed25519"));
    } else {
        (*alg25519KeyPairSpec)->base.algName = (char*)HcfMalloc(sizeof("X25519"), 0);
        if ((*alg25519KeyPairSpec)->base.algName == NULL) {
            HcfFree(*alg25519KeyPairSpec);
            *alg25519KeyPairSpec = NULL;
            return HCF_ERR_MALLOC;
        }
        (void)memcpy_s((*alg25519KeyPairSpec)->base.algName, sizeof("X25519"),
            "X25519", sizeof("X25519"));
    }
    return HCF_SUCCESS;
}

HcfResult ConstructAlg25519KeyPairParamsSpec(const char *algoName, bool choose, HcfAsyKeyParamsSpec **spec)
{
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

    HcfAlg25519KeyPairParamsSpec *alg25519KeyPairSpec = NULL;
    if (CreateAlg25519KeyPairSpec(choose, &alg25519KeyPairSpec) == HCF_SUCCESS) {
        HcfBigInteger retBigInt = { .data = NULL, .len = 0 };
        alg25519KeyPairSpec->base.specType = HCF_KEY_PAIR_SPEC;
        if (choose) {
            res = keyPair->pubKey->getAsyKeySpecBigInteger(keyPair->pubKey, ED25519_PK_BN, &retBigInt);
        } else {
            res = keyPair->pubKey->getAsyKeySpecBigInteger(keyPair->pubKey, X25519_PK_BN, &retBigInt);
        }
        if (res == HCF_SUCCESS) {
            alg25519KeyPairSpec->pk.data = retBigInt.data;
            alg25519KeyPairSpec->pk.len = retBigInt.len;
            if (choose) {
                res = keyPair->priKey->getAsyKeySpecBigInteger(keyPair->priKey, ED25519_SK_BN, &retBigInt);
            } else {
                res = keyPair->priKey->getAsyKeySpecBigInteger(keyPair->priKey, X25519_SK_BN, &retBigInt);
            }
            if (res == HCF_SUCCESS) {
                alg25519KeyPairSpec->sk.data = retBigInt.data;
                alg25519KeyPairSpec->sk.len = retBigInt.len;
                *spec = (HcfAsyKeyParamsSpec *)alg25519KeyPairSpec;
            } else {
                HcfFree(alg25519KeyPairSpec->pk.data);
                alg25519KeyPairSpec->pk.data = NULL;
                alg25519KeyPairSpec->pk.len = 0;
            }
        }
        if (res != HCF_SUCCESS) {
            DestroyAlg25519KeyPairSpec((HcfAlg25519KeyPairParamsSpec *)alg25519KeyPairSpec);
        }
    }

    HcfObjDestroy(generator);
    HcfObjDestroy(keyPair);
    return res;
}

static HcfResult CreateAlg25519PubKeySpec(bool choose, HcfAlg25519PubKeyParamsSpec **alg25519PubKeySpec)
{
    *alg25519PubKeySpec = (HcfAlg25519PubKeyParamsSpec*)HcfMalloc(sizeof(HcfAlg25519PubKeyParamsSpec), 0);
    if (*alg25519PubKeySpec == NULL) {
        return HCF_ERR_MALLOC;
    }
    if (choose) {
        (*alg25519PubKeySpec)->base.algName = (char*)HcfMalloc(sizeof("Ed25519"), 0);
        if ((*alg25519PubKeySpec)->base.algName == NULL) {
            HcfFree(*alg25519PubKeySpec);
            *alg25519PubKeySpec = NULL;
            return HCF_ERR_MALLOC;
        }
        (void)memcpy_s((*alg25519PubKeySpec)->base.algName, sizeof("Ed25519"),
            "Ed25519", sizeof("Ed25519"));
    } else {
        (*alg25519PubKeySpec)->base.algName = (char*)HcfMalloc(sizeof("X25519"), 0);
        if ((*alg25519PubKeySpec)->base.algName == NULL) {
            HcfFree(*alg25519PubKeySpec);
            *alg25519PubKeySpec = NULL;
            return HCF_ERR_MALLOC;
        }
        (void)memcpy_s((*alg25519PubKeySpec)->base.algName, sizeof("X25519"),
            "X25519", sizeof("X25519"));
    }
    return HCF_SUCCESS;
}

HcfResult ConstructAlg25519PubKeyParamsSpec(const char *algoName, bool choose, HcfAsyKeyParamsSpec **spec)
{
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

    HcfAlg25519PubKeyParamsSpec *alg25519PubKeySpec = NULL;
    if (CreateAlg25519PubKeySpec(choose, &alg25519PubKeySpec) == HCF_SUCCESS) {
        HcfBigInteger retBigInt = { .data = NULL, .len = 0 };
        alg25519PubKeySpec->base.specType = HCF_PUBLIC_KEY_SPEC;
        if (choose) {
            res = keyPair->pubKey->getAsyKeySpecBigInteger(keyPair->pubKey, ED25519_PK_BN, &retBigInt);
        } else {
            res = keyPair->pubKey->getAsyKeySpecBigInteger(keyPair->pubKey, X25519_PK_BN, &retBigInt);
        }
        if (res == HCF_SUCCESS) {
            alg25519PubKeySpec->pk.data = retBigInt.data;
            alg25519PubKeySpec->pk.len = retBigInt.len;
            *spec = (HcfAsyKeyParamsSpec *)alg25519PubKeySpec;
        } else {
            DestroyAlg25519PubKeySpec((HcfAlg25519PubKeyParamsSpec *)alg25519PubKeySpec);
        }
    }

    HcfObjDestroy(generator);
    HcfObjDestroy(keyPair);
    return res;
}

static HcfResult CreateAlg25519PriKeySpec(bool choose, HcfAlg25519PriKeyParamsSpec **alg25519PriKeySpec)
{
    *alg25519PriKeySpec = (HcfAlg25519PriKeyParamsSpec*)HcfMalloc(sizeof(HcfAlg25519PriKeyParamsSpec), 0);
    if (*alg25519PriKeySpec == NULL) {
        return HCF_ERR_MALLOC;
    }
    if (choose) {
        (*alg25519PriKeySpec)->base.algName = (char*)HcfMalloc(sizeof("Ed25519"), 0);
        if ((*alg25519PriKeySpec)->base.algName == NULL) {
            HcfFree(*alg25519PriKeySpec);
            *alg25519PriKeySpec = NULL;
            return HCF_ERR_MALLOC;
        }
        (void)memcpy_s((*alg25519PriKeySpec)->base.algName, sizeof("Ed25519"),
            "Ed25519", sizeof("Ed25519"));
    } else {
        (*alg25519PriKeySpec)->base.algName = (char*)HcfMalloc(sizeof("X25519"), 0);
        if ((*alg25519PriKeySpec)->base.algName == NULL) {
            HcfFree(*alg25519PriKeySpec);
            *alg25519PriKeySpec = NULL;
            return HCF_ERR_MALLOC;
        }
        (void)memcpy_s((*alg25519PriKeySpec)->base.algName, sizeof("X25519"),
            "X25519", sizeof("X25519"));
    }
    return HCF_SUCCESS;
}

HcfResult ConstructAlg25519PriKeyParamsSpec(const char *algoName, bool choose, HcfAsyKeyParamsSpec **spec)
{
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
    HcfAlg25519PriKeyParamsSpec *alg25519PriKeySpec = NULL;
    if (CreateAlg25519PriKeySpec(choose, &alg25519PriKeySpec) == HCF_SUCCESS) {
        HcfBigInteger retBigInt = { .data = NULL, .len = 0 };
        alg25519PriKeySpec->base.specType = HCF_PRIVATE_KEY_SPEC;
        if (choose) {
            res = keyPair->priKey->getAsyKeySpecBigInteger(keyPair->priKey, ED25519_SK_BN, &retBigInt);
        } else {
            res = keyPair->priKey->getAsyKeySpecBigInteger(keyPair->priKey, X25519_SK_BN, &retBigInt);
        }
        if (res == HCF_SUCCESS) {
            alg25519PriKeySpec->sk.data = retBigInt.data;
            alg25519PriKeySpec->sk.len = retBigInt.len;
            *spec = (HcfAsyKeyParamsSpec *)alg25519PriKeySpec;
        } else {
            DestroyAlg25519PriKeySpec((HcfAlg25519PriKeyParamsSpec *)alg25519PriKeySpec);
        }
    }
    HcfObjDestroy(generator);
    HcfObjDestroy(keyPair);
    return res;
}

HcfResult TestHcfAsyKeyGeneratorCreate(const char *algName, HcfAsyKeyGenerator **generator)
{
    HcfResult res = HcfAsyKeyGeneratorCreate(algName, generator);
    if (res != HCF_SUCCESS) {
        return HCF_ERR_CRYPTO_OPERATION;
    }
    if (*generator == NULL) {
        return HCF_ERR_CRYPTO_OPERATION;
    }
    return HCF_SUCCESS;
}

HcfResult TestGenerateKeyPair(HcfAsyKeyGenerator *generator, HcfKeyPair **keyPair)
{
    HcfResult res = generator->generateKeyPair(generator, NULL, keyPair);
    if (res != HCF_SUCCESS) {
        return HCF_ERR_CRYPTO_OPERATION;
    }
    if (*keyPair == NULL) {
        return HCF_ERR_CRYPTO_OPERATION;
    }
    return HCF_SUCCESS;
}

HcfResult TestKeyGeneratorAndGenerateKeyPair(const char *algName, HcfAsyKeyGenerator **generator, HcfKeyPair **keyPair)
{
    HcfResult res = TestHcfAsyKeyGeneratorCreate(algName, generator);
    if (res != HCF_SUCCESS) {
        return HCF_ERR_CRYPTO_OPERATION;
    }
    res = TestGenerateKeyPair(*generator, keyPair);
    if (res != HCF_SUCCESS) {
        HcfObjDestroy(*generator);
        *generator = NULL;
        return HCF_ERR_CRYPTO_OPERATION;
    }
    return HCF_SUCCESS;
}

HcfResult TestGenerateConvertKey(HcfAsyKeyGenerator *generator, HcfBlob *pubKeyBlob, HcfBlob *priKeyBlob,
    HcfKeyPair **keyPair)
{
    HcfResult res = generator->convertKey(generator, NULL, pubKeyBlob, priKeyBlob, keyPair);
    if (res != HCF_SUCCESS) {
        return HCF_ERR_CRYPTO_OPERATION;
    }
    if (*keyPair == NULL) {
        return HCF_ERR_CRYPTO_OPERATION;
    }
    return HCF_SUCCESS;
}

HcfResult TestGenerateKeyPairAndConvertKey(const char *algName, HcfAsyKeyGenerator **generator, HcfBlob *pubKeyBlob,
    HcfBlob *priKeyBlob, HcfKeyPair **keyPair)
{
    HcfResult res = TestKeyGeneratorAndGenerateKeyPair(algName, generator, keyPair);
    if (res != HCF_SUCCESS) {
        return HCF_ERR_CRYPTO_OPERATION;
    }
    HcfObjDestroy(*keyPair);
    *keyPair = NULL;
    res = TestGenerateConvertKey(*generator, pubKeyBlob, priKeyBlob, keyPair);
    if (res != HCF_SUCCESS) {
        return HCF_ERR_CRYPTO_OPERATION;
    }
    return HCF_SUCCESS;
}

HcfResult TestCreateKeyPairParamsSpecAndGeneratorBySpec(const char *algName, bool choose,
    HcfAsyKeyParamsSpec **paramSpec, HcfAsyKeyGeneratorBySpec **generator)
{
    HcfResult res = ConstructAlg25519KeyPairParamsSpec(algName, choose, paramSpec);
    if (res != HCF_SUCCESS) {
        return HCF_ERR_CRYPTO_OPERATION;
    }
    if (*paramSpec == NULL) {
        return HCF_ERR_CRYPTO_OPERATION;
    }
    res = HcfAsyKeyGeneratorBySpecCreate(*paramSpec, generator);
    if (res != HCF_SUCCESS) {
        return HCF_ERR_CRYPTO_OPERATION;
    }
    if (*generator == NULL) {
        return HCF_ERR_CRYPTO_OPERATION;
    }
    return HCF_SUCCESS;
}

HcfResult TestCreatePubKeyParamsSpecAndGeneratorBySpec(const char *algName, bool choose,
    HcfAsyKeyParamsSpec **paramSpec, HcfAsyKeyGeneratorBySpec **generator)
{
    HcfResult res = ConstructAlg25519PubKeyParamsSpec(algName, choose, paramSpec);
    if (res != HCF_SUCCESS) {
        return HCF_ERR_CRYPTO_OPERATION;
    }
    if (*paramSpec == NULL) {
        return HCF_ERR_CRYPTO_OPERATION;
    }
    res = HcfAsyKeyGeneratorBySpecCreate(*paramSpec, generator);
    if (res != HCF_SUCCESS) {
        return HCF_ERR_CRYPTO_OPERATION;
    }
    if (*generator == NULL) {
        return HCF_ERR_CRYPTO_OPERATION;
    }
    return HCF_SUCCESS;
}

HcfResult TestCreatePriKeyParamsSpecAndGeneratorBySpec(const char *algName, bool choose,
    HcfAsyKeyParamsSpec **paramSpec, HcfAsyKeyGeneratorBySpec **generator)
{
    HcfResult res = ConstructAlg25519PriKeyParamsSpec(algName, choose, paramSpec);
    if (res != HCF_SUCCESS) {
        return HCF_ERR_CRYPTO_OPERATION;
    }
    if (*paramSpec == NULL) {
        return HCF_ERR_CRYPTO_OPERATION;
    }
    res = HcfAsyKeyGeneratorBySpecCreate(*paramSpec, generator);
    if (res != HCF_SUCCESS) {
        return HCF_ERR_CRYPTO_OPERATION;
    }
    if (*generator == NULL) {
        return HCF_ERR_CRYPTO_OPERATION;
    }
    return HCF_SUCCESS;
}