/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
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

#include "crypto_key_agreement.h"
#include "native_common.h"
#include "crypto_common.h"
#include "crypto_asym_key.h"
#include "key_agreement.h"

typedef struct OH_CryptoKeyAgreement {
    HcfObjectBase base;

    HcfResult (*generateSecret)(HcfKeyAgreement *self, HcfPriKey *priKey,
        HcfPubKey *pubKey, HcfBlob *returnSecret);

    const char *(*getAlgoName)(HcfKeyAgreement *self);
} OH_CryptoKeyAgreement;

static OH_Crypto_ErrCode CryptoKeyAgreementCreate(const char *algoName, OH_CryptoKeyAgreement **ctx)
{
    if (ctx == NULL) {
        return CRYPTO_PARAMETER_CHECK_FAILED;
    }
    HcfResult ret = HcfKeyAgreementCreate(algoName, (HcfKeyAgreement **)ctx);
    return GetOhCryptoErrCodeNew(ret);
}

OH_Crypto_ErrCode OH_CryptoKeyAgreement_Create(const char *algoName, OH_CryptoKeyAgreement **ctx)
{
    return CryptoKeyAgreementCreate(algoName, ctx);
}

static OH_Crypto_ErrCode CryptoKeyAgreementGenerateSecret(OH_CryptoKeyAgreement *ctx, OH_CryptoPrivKey *privkey,
    OH_CryptoPubKey *pubkey, Crypto_DataBlob *secret)
{
    if ((ctx == NULL) || (ctx->generateSecret == NULL) || (privkey == NULL) || (pubkey == NULL) || (secret == NULL)) {
        return CRYPTO_PARAMETER_CHECK_FAILED;
    }
    HcfResult ret = ctx->generateSecret((HcfKeyAgreement *)ctx, (HcfPriKey *)privkey, (HcfPubKey *)pubkey,
        (HcfBlob *)secret);
    return GetOhCryptoErrCodeNew(ret);
}

OH_Crypto_ErrCode OH_CryptoKeyAgreement_GenerateSecret(OH_CryptoKeyAgreement *ctx, OH_CryptoPrivKey *privkey,
    OH_CryptoPubKey *pubkey, Crypto_DataBlob *secret)
{
    return CryptoKeyAgreementGenerateSecret(ctx, privkey, pubkey, secret);
}

static void CryptoKeyAgreementDestroy(OH_CryptoKeyAgreement *ctx)
{
    HcfObjDestroy((HcfKeyAgreement*)ctx);
}

void OH_CryptoKeyAgreement_Destroy(OH_CryptoKeyAgreement *ctx)
{
    CryptoKeyAgreementDestroy(ctx);
}
