/*
 * Copyright (C) 2024 Huawei Device Co., Ltd.
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

#include "cipher_sm2_crypto_util_openssl.h"
#include <stdbool.h>
#include <string.h>
#include "log.h"
#include "memory.h"
#include "openssl_adapter.h"
#include "openssl_common.h"
#include "securec.h"
#include "utils.h"

static HcfResult BuildSm2Ciphertext(const Sm2CipherTextSpec *spec, struct Sm2CipherTextSt *sm2Text)
{
    if (BigIntegerToBigNum(&(spec->xCoordinate), &(sm2Text->c1X)) != HCF_SUCCESS) {
        LOGE("Build x failed.");
        return HCF_ERR_CRYPTO_OPERATION;
    }
    if (BigIntegerToBigNum(&(spec->yCoordinate), &(sm2Text->c1Y)) != HCF_SUCCESS) {
        LOGE("Build y failed.");
        return HCF_ERR_CRYPTO_OPERATION;
    }
    if (sm2Text->c3 == NULL || sm2Text->c2 == NULL) {
        LOGE("SM2 openssl [ASN1_OCTET_STRING_new] c3 c2 fail");
        HcfPrintOpensslError();
        return HCF_ERR_CRYPTO_OPERATION;
    }
    if (OpensslAsn1OctetStringSet(sm2Text->c3, spec->hashData.data, spec->hashData.len) != HCF_OPENSSL_SUCCESS) {
        LOGE("SM2 openssl [ASN1_OCTET_STRING_set] c3 error");
        HcfPrintOpensslError();
        return HCF_ERR_CRYPTO_OPERATION;
    }
    if (OpensslAsn1OctetStringSet(sm2Text->c2, spec->cipherTextData.data,
        spec->cipherTextData.len) != HCF_OPENSSL_SUCCESS) {
        LOGE("SM2 openssl [ASN1_OCTET_STRING_set] c2 error");
        HcfPrintOpensslError();
        return HCF_ERR_CRYPTO_OPERATION;
    }
    return HCF_SUCCESS;
}

HcfResult HcfSm2SpecToAsn1(Sm2CipherTextSpec *spec, HcfBlob *output)
{
    struct Sm2CipherTextSt *sm2Text = OpensslSm2CipherTextNew();
    if (sm2Text == NULL) {
        LOGE("SM2 openssl [SM2_Ciphertext_new] failed");
        HcfPrintOpensslError();
        return HCF_ERR_CRYPTO_OPERATION;
    }
    HcfResult res = BuildSm2Ciphertext(spec, sm2Text);
    if (res != HCF_SUCCESS) {
        OpensslSm2CipherTextFree(sm2Text);
        LOGE("SM2 build SM2Ciphertext fail");
        return res;
    }
    unsigned char *returnData = NULL;
    int returnDataLen = OpensslI2dSm2CipherText(sm2Text, &returnData);
    OpensslSm2CipherTextFree(sm2Text);
    if (returnData == NULL || returnDataLen < 0) {
        LOGE("SM2 openssl [i2d_SM2_Ciphertext] error");
        HcfPrintOpensslError();
        return HCF_ERR_CRYPTO_OPERATION;
    }
    output->data = returnData;
    output->len = (size_t)returnDataLen;
    return HCF_SUCCESS;
}

static HcfResult BuildSm2CiphertextSpec(struct Sm2CipherTextSt *sm2Text, Sm2CipherTextSpec *tempSpec)
{
    if (BigNumToBigInteger(sm2Text->c1X, &(tempSpec->xCoordinate)) != HCF_SUCCESS) {
        LOGE("BigNumToBigInteger xCoordinate failed.");
        return HCF_ERR_CRYPTO_OPERATION;
    }
    if (BigNumToBigInteger(sm2Text->c1Y, &(tempSpec->yCoordinate)) != HCF_SUCCESS) {
        LOGE("BigNumToBigInteger yCoordinate failed.");
        return HCF_ERR_CRYPTO_OPERATION;
    }
    const unsigned char *c2Data = OpensslAsn1StringGet0Data(sm2Text->c2);
    int c2Len = OpensslAsn1StringLength(sm2Text->c2);
    if (c2Data == NULL || c2Len <= 0) {
        LOGE("SM2 openssl [OpensslAsn1StringGet0Data] error.");
        return HCF_ERR_CRYPTO_OPERATION;
    }
    const unsigned char *c3Data = OpensslAsn1StringGet0Data(sm2Text->c3);
    int c3Len = OpensslAsn1StringLength(sm2Text->c3);
    if (c3Data == NULL || c3Len <= 0) {
        LOGE("SM2 openssl [OpensslAsn1StringGet0Data] error.");
        return HCF_ERR_CRYPTO_OPERATION;
    }

    tempSpec->cipherTextData.data = (unsigned char *)HcfMalloc(c2Len, 0);
    if (tempSpec->cipherTextData.data == NULL) {
        LOGE("Failed to allocate cipherTextData.data memory");
        return HCF_ERR_MALLOC;
    }
    tempSpec->hashData.data = (unsigned char *)HcfMalloc(c3Len, 0);
    if (tempSpec->hashData.data == NULL) {
        LOGE("Failed to allocate hashData.data memory");
        return HCF_ERR_MALLOC;
    }
    (void)memcpy_s(tempSpec->cipherTextData.data, c2Len, c2Data, c2Len);
    (void)memcpy_s(tempSpec->hashData.data, c3Len, c3Data, c3Len);
    tempSpec->cipherTextData.len = c2Len;
    tempSpec->hashData.len = c3Len;
    return HCF_SUCCESS;
}

HcfResult HcfAsn1ToSm2Spec(HcfBlob *input, Sm2CipherTextSpec **returnSpec)
{
    struct Sm2CipherTextSt *sm2Text = OpensslD2iSm2CipherText(input->data, input->len);
    if (sm2Text == NULL) {
        LOGE("SM2 openssl [d2i_SM2_Ciphertext] error");
        return HCF_ERR_CRYPTO_OPERATION;
    }
    Sm2CipherTextSpec *tempSpec = (Sm2CipherTextSpec *)(HcfMalloc(sizeof(Sm2CipherTextSpec), 0));
    if (tempSpec == NULL) {
        LOGE("Failed to allocate Sm2CipherTextSpec memory");
        OpensslSm2CipherTextFree(sm2Text);
        return HCF_ERR_MALLOC;
    }
    HcfResult res = BuildSm2CiphertextSpec(sm2Text, tempSpec);
    if (res != HCF_SUCCESS) {
        LOGE("SM2 build SM2Ciphertext fail");
        DestroySm2CipherTextSpec(tempSpec);
        OpensslSm2CipherTextFree(sm2Text);
        return res;
    }
    *returnSpec = tempSpec;
    OpensslSm2CipherTextFree(sm2Text);
    return HCF_SUCCESS;
}