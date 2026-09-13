/*
 * Copyright (C) 2022 Huawei Device Co., Ltd.
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

#ifndef HCF_OEPNSSL_CLASS_H
#define HCF_OEPNSSL_CLASS_H

#include "pub_key.h"
#include "pri_key.h"
#include "key_pair.h"

#include <openssl/bn.h>
#include <openssl/dsa.h>
#include <openssl/ec.h>
#include <openssl/evp.h>
#include <openssl/rsa.h>

typedef struct {
    HcfPubKey base;

    int32_t curveId;

    EC_KEY *ecKey;

    char *fieldType;
} HcfOpensslEccPubKey;
#define HCF_OPENSSL_ECC_PUB_KEY_CLASS "OPENSSL.ECC.PUB_KEY"

typedef struct {
    HcfPriKey base;

    int32_t curveId;

    EC_KEY *ecKey;

    char *fieldType;
} HcfOpensslEccPriKey;
#define HCF_OPENSSL_ECC_PRI_KEY_CLASS "OPENSSL.ECC.PRI_KEY"

typedef struct {
    HcfKeyPair base;
} HcfOpensslEccKeyPair;
#define HCF_OPENSSL_ECC_KEY_PAIR_CLASS "OPENSSL.ECC.KEY_PAIR"

typedef struct {
    HcfPubKey base;

    uint32_t bits;

    RSA *pk;
} HcfOpensslRsaPubKey;
#define OPENSSL_RSA_PUBKEY_CLASS "OPENSSL.RSA.PUB_KEY"

typedef struct {
    HcfPriKey base;

    uint32_t bits;

    RSA *sk;
} HcfOpensslRsaPriKey;
#define OPENSSL_RSA_PRIKEY_CLASS "OPENSSL.RSA.PRI_KEY"

typedef struct {
    HcfKeyPair base;
} HcfOpensslRsaKeyPair;
#define OPENSSL_RSA_KEYPAIR_CLASS "OPENSSL.RSA.KEY_PAIR"

typedef struct {
    HcfPubKey base;

    DSA *pk;
} HcfOpensslDsaPubKey;
#define OPENSSL_DSA_PUBKEY_CLASS "OPENSSL.DSA.PUB_KEY"

typedef struct {
    HcfPriKey base;

    DSA *sk;
} HcfOpensslDsaPriKey;
#define OPENSSL_DSA_PRIKEY_CLASS "OPENSSL.DSA.PRI_KEY"

typedef struct {
    HcfKeyPair base;
} HcfOpensslDsaKeyPair;
#define OPENSSL_DSA_KEYPAIR_CLASS "OPENSSL.DSA.KEY_PAIR"

typedef struct {
    HcfPubKey base;

    int type;

    EVP_PKEY *pkey;
} HcfOpensslAlg25519PubKey;
#define OPENSSL_ALG25519_PUBKEY_CLASS "OPENSSL.ALG25519.PUB_KEY"

typedef struct {
    HcfPriKey base;

    int type;

    EVP_PKEY *pkey;
} HcfOpensslAlg25519PriKey;
#define OPENSSL_ALG25519_PRIKEY_CLASS "OPENSSL.ALG25519.PRI_KEY"

typedef struct {
    HcfKeyPair base;
} HcfOpensslAlg25519KeyPair;
#define OPENSSL_ALG25519_KEYPAIR_CLASS "OPENSSL.ALG25519.KEY_PAIR"


typedef struct {
    HcfPubKey base;

    int32_t curveId;

    EC_KEY *ecKey;

    char *fieldType;
} HcfOpensslSm2PubKey;
#define HCF_OPENSSL_SM2_PUB_KEY_CLASS "OPENSSL.SM2.PUB_KEY"

typedef struct {
    HcfPriKey base;

    int32_t curveId;

    EC_KEY *ecKey;

    char *fieldType;
} HcfOpensslSm2PriKey;
#define HCF_OPENSSL_SM2_PRI_KEY_CLASS "OPENSSL.SM2.PRI_KEY"

typedef struct {
    HcfKeyPair base;
} HcfOpensslSm2KeyPair;
#define HCF_OPENSSL_SM2_KEY_PAIR_CLASS "OPENSSL.SM2.KEY_PAIR"

typedef struct {
    HcfPubKey base;

    uint32_t bits;

    DH *pk;
} HcfOpensslDhPubKey;
#define OPENSSL_DH_PUBKEY_CLASS "OPENSSL.DH.PUB_KEY"

typedef struct {
    HcfPriKey base;

    uint32_t bits;

    DH *sk;
} HcfOpensslDhPriKey;
#define OPENSSL_DH_PRIKEY_CLASS "OPENSSL.DH.PRI_KEY"

typedef struct {
    HcfKeyPair base;
} HcfOpensslDhKeyPair;
#define OPENSSL_DH_KEYPAIR_CLASS "OPENSSL.DH.KEY_PAIR"

typedef struct {
    HcfPubKey base;

    int type;

    EVP_PKEY *pkey;
} HcfOpensslMlKemPubKey;
#define OPENSSL_ML_KEM_PUBKEY_CLASS "OPENSSL.ML_KEM.PUB_KEY"

typedef struct {
    HcfPriKey base;

    int type;

    EVP_PKEY *pkey;
} HcfOpensslMlKemPriKey;
#define OPENSSL_ML_KEM_PRIKEY_CLASS "OPENSSL.ML_KEM.PRI_KEY"

typedef struct {
    HcfKeyPair base;
} HcfOpensslMlKemKeyPair;
#define OPENSSL_ML_KEM_KEYPAIR_CLASS "OPENSSL.ML_KEM.KEY_PAIR"

typedef struct {
    HcfPubKey base;

    int type;

    EVP_PKEY *pkey;
} HcfOpensslMlDsaPubKey;
#define OPENSSL_ML_DSA_PUBKEY_CLASS "OPENSSL.ML_DSA.PUB_KEY"

typedef struct {
    HcfPriKey base;

    int type;

    EVP_PKEY *pkey;
} HcfOpensslMlDsaPriKey;
#define OPENSSL_ML_DSA_PRIKEY_CLASS "OPENSSL.ML_DSA.PRI_KEY"

typedef struct {
    HcfKeyPair base;
} HcfOpensslMlDsaKeyPair;
#define OPENSSL_ML_DSA_KEYPAIR_CLASS "OPENSSL.ML_DSA.KEY_PAIR"

#define OPENSSL_RSA_CIPHER_CLASS "OPENSSL.RSA.CIPHER"
#define OPENSSL_3DES_CIPHER_CLASS "OPENSSL.3DES.CIPHER"
#define OPENSSL_AES_CIPHER_CLASS "OPENSSL.AES.CIPHER"
#define OPENSSL_SM4_CIPHER_CLASS "OPENSSL.SM4.CIPHER"
#define OPENSSL_SM2_CIPHER_CLASS "OPENSSL.SM2.CIPHER"
#define OPENSSL_CHACHA20_CIPHER_CLASS "OPENSSL.CHACHA20.CIPHER"

#endif
