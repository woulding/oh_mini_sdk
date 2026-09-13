/*
 * Copyright (C) 2025 Huawei Device Co., Ltd.
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

#include "cipher_sm2_ecdsa_signature_openssl.h"
#include <stdbool.h>
#include <string.h>
#include "log.h"
#include "memory.h"
#include "openssl_adapter.h"
#include "openssl_common.h"
#include "securec.h"
#include "utils.h"

static HcfResult BuildSm2Ciphertext(const Sm2EcSignatureDataSpec *spec, ECDSA_SIG *sm2Text)
{
    if (spec == NULL || sm2Text == NULL) {
        LOGE("Invalid params");
        return HCF_ERR_PARAMETER_CHECK_FAILED;
    }
    BIGNUM *r = NULL;
    BIGNUM *s = NULL;
    if (BigIntegerToBigNum(&(spec->rCoordinate), &r) != HCF_SUCCESS) {
        LOGE("Build r failed.");
        return HCF_ERR_CRYPTO_OPERATION;
    }
    if (BigIntegerToBigNum(&(spec->sCoordinate), &s) != HCF_SUCCESS) {
        LOGE("Build s failed.");
        OpensslBnFree(r);
        return HCF_ERR_CRYPTO_OPERATION;
    }
    if (OpensslEcdsaSigSet0(sm2Text, r, s) != HCF_OPENSSL_SUCCESS) {
        LOGE("Set SM2 ECDSA signature failed.");
        OpensslBnFree(r);
        OpensslBnFree(s);
        return HCF_ERR_CRYPTO_OPERATION;
    }
    return HCF_SUCCESS;
}

HcfResult HcfSm2SpecToDerData(Sm2EcSignatureDataSpec *spec, HcfBlob *output)
{
    if (spec == NULL || output == NULL) {
        LOGE("Invalid params");
        return HCF_ERR_PARAMETER_CHECK_FAILED;
    }
    ECDSA_SIG *sig = OpensslEcdsaSigNew();
    HcfResult res = BuildSm2Ciphertext(spec, sig);
    if (res != HCF_SUCCESS) {
        OpensslSm2EcdsaSigFree(sig);
        LOGE("SM2 build SM2Ciphertext fail");
        return res;
    }
    unsigned char *returnData = NULL;
    int returnDataLen = OpensslI2dSm2EcdsaSig(sig, &returnData);
    OpensslSm2EcdsaSigFree(sig);
    if (returnData == NULL || returnDataLen < 0) {
        LOGE("SM2 openssl [i2d_SM2_Ciphertext] error");
        HcfPrintOpensslError();
        return HCF_ERR_CRYPTO_OPERATION;
    }
    output->data = returnData;
    output->len = (size_t)returnDataLen;
    return HCF_SUCCESS;
}

static HcfResult BuildSm2EcdsaSigSpec(ECDSA_SIG *sig, Sm2EcSignatureDataSpec *tempSpec)
{
    const BIGNUM *r = OpensslEcdsaSigGet0r(sig);
    const BIGNUM *s = OpensslEcdsaSigGet0s(sig);
    if (r == NULL || s == NULL) {
        LOGE("get r or s failed");
        return HCF_ERR_CRYPTO_OPERATION;
    }
    if (BigNumToBigInteger(r, &(tempSpec->rCoordinate)) != HCF_SUCCESS) {
        LOGE("BigNumToBigInteger rCoordinate failed.");
        return HCF_ERR_CRYPTO_OPERATION;
    }
    if (BigNumToBigInteger(s, &(tempSpec->sCoordinate)) != HCF_SUCCESS) {
        LOGE("BigNumToBigInteger sCoordinate failed.");
        return HCF_ERR_CRYPTO_OPERATION;
    }
    return HCF_SUCCESS;
}

HcfResult HcfDerDataToSm2Spec(HcfBlob *input, Sm2EcSignatureDataSpec **returnSpec)
{
    if (input == NULL || returnSpec == NULL) {
        LOGE("Invalid signature params");
        return HCF_ERR_PARAMETER_CHECK_FAILED;
    }

    Sm2EcSignatureDataSpec *tempSpec = (Sm2EcSignatureDataSpec *)(HcfMalloc(sizeof(Sm2EcSignatureDataSpec), 0));
    if (tempSpec == NULL) {
        LOGE("Failed to allocate Sm2EcSignatureDataSpec memory");
        return HCF_ERR_MALLOC;
    }
    const unsigned char *data = (const unsigned char *)input->data;
    ECDSA_SIG *sig = OpensslD2iSm2EcdsaSig(&data, (int)input->len);
    if (sig == NULL) {
        LOGE("SM2 build SM2Ciphertext fail");
        DestroySm2EcSignatureSpec(tempSpec);
        OpensslSm2EcdsaSigFree(sig);
        return HCF_ERR_CRYPTO_OPERATION;
    }
    HcfResult res = BuildSm2EcdsaSigSpec(sig, tempSpec);
    if (res != HCF_SUCCESS) {
        LOGE("SM2 build SM2ECDSA sig spec fail");
        DestroySm2EcSignatureSpec(tempSpec);
        OpensslSm2EcdsaSigFree(sig);
        return res;
    }

    *returnSpec = tempSpec;
    OpensslSm2EcdsaSigFree(sig);
    return HCF_SUCCESS;
}