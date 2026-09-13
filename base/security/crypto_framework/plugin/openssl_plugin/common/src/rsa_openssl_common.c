/*
 * Copyright (C) 2022-2023 Huawei Device Co., Ltd.
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
#include "rsa_openssl_common.h"
#include "log.h"
#include "openssl_adapter.h"
#include "openssl_common.h"

static RSA *DuplicateRsaPriKeyForSpec(const RSA *rsa)
{
    RSA *tmp = OpensslRsaNew();
    if (tmp == NULL) {
        LOGE("malloc rsa failed");
        return NULL;
    }
    const BIGNUM *n = NULL;
    const BIGNUM *e = NULL;
    const BIGNUM *d = NULL;
    OpensslRsaGet0Key(rsa, &n, &e, &d);
    if (n == NULL || e == NULL || d == NULL) {
        LOGE("get key attribute fail");
        OpensslRsaFree(tmp);
        return NULL;
    }
    BIGNUM *dupN = OpensslBnDup(n);
    BIGNUM *dupE = OpensslBnDup(e);
    BIGNUM *dupD = OpensslBnDup(d);
    if (dupN == NULL || dupE == NULL || dupD == NULL) {
        LOGE("Duplicate key attribute fail");
        OpensslBnFree(dupN);
        OpensslBnFree(dupE);
        OpensslBnClearFree(dupD);
        OpensslRsaFree(tmp);
        return NULL;
    }
    if (OpensslRsaSet0Key(tmp, dupN, dupE, dupD) != HCF_OPENSSL_SUCCESS) {
        LOGE("assign RSA n, e, d failed");
        OpensslBnFree(dupN);
        OpensslBnFree(dupE);
        OpensslBnClearFree(dupD);
        OpensslRsaFree(tmp);
        return NULL;
    }
    return tmp;
}

HcfResult DuplicateRsa(RSA *rsa, bool needPrivate, RSA **dupRsa)
{
    RSA *retRSA = NULL;
    if (rsa == NULL || dupRsa == NULL) {
        LOGE("Rsa or dupRsa is NULL.");
        return HCF_INVALID_PARAMS;
    }
    if (needPrivate) {
        retRSA = OpensslRsaPrivateKeyDup(rsa);
        // RSAPrivateKey_dup needs p&q, it fails when the key only contains n, e, d, so it needs another func.
        if (retRSA == NULL) {
            retRSA = DuplicateRsaPriKeyForSpec(rsa);
        }
    } else {
        retRSA = OpensslRsaPublicKeyDup(rsa);
    }
    if (retRSA == NULL) {
        LOGE("Duplicate RSA fail.");
        HcfPrintOpensslError();
        return HCF_ERR_CRYPTO_OPERATION;
    }
    *dupRsa = retRSA;
    return HCF_SUCCESS;
}

EVP_PKEY *NewEvpPkeyByRsa(RSA *rsa, bool withDuplicate)
{
    if (rsa == NULL) {
        LOGE("RSA is NULL");
        return NULL;
    }
    EVP_PKEY *pKey = OpensslEvpPkeyNew();
    if (pKey == NULL) {
        LOGE("EVP_PKEY_new fail");
        HcfPrintOpensslError();
        return NULL;
    }
    if (withDuplicate) {
        if (OpensslEvpPkeySet1Rsa(pKey, rsa) != HCF_OPENSSL_SUCCESS) {
            LOGE("EVP_PKEY_set1_RSA fail");
            HcfPrintOpensslError();
            OpensslEvpPkeyFree(pKey);
            return NULL;
        }
    } else {
        if (OpensslEvpPkeyAssignRsa(pKey, rsa) != HCF_OPENSSL_SUCCESS) {
            LOGE("EVP_PKEY_assign_RSA fail");
            HcfPrintOpensslError();
            OpensslEvpPkeyFree(pKey);
            return NULL;
        }
    }
    return pKey;
}
