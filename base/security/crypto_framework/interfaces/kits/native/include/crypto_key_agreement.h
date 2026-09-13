/*
 * Copyright (c) 2025-2026 Huawei Device Co., Ltd.
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

/**
 * @addtogroup CryptoKeyAgreementApi
 * @{
 * @brief Describes the key agreement interfaces provided by OpenHarmony for applications.
 * @since 20
 */

/**
 * @file crypto_key_agreement.h
 * @brief Defines the key agreement interfaces.
 * @syscap SystemCapability.Security.CryptoFramework
 * @library libohcrypto.so
 * @kit CryptoArchitectureKit
 * @since 20
 */

#ifndef CRYPTO_KEY_AGREEMENT_H
#define CRYPTO_KEY_AGREEMENT_H

#include "crypto_common.h"
#include "crypto_asym_key.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief Key agreement structure, representing a key agreement context.
 * @since 20
 */
typedef struct OH_CryptoKeyAgreement OH_CryptoKeyAgreement;

/**
 * @brief Creates a key agreement context based on the given algorithm name.
 * @param algoName [in] Key agreement algorithm name. Cannot be NULL. Values:
 *     - ECDH series since API version 20: "ECC224", "ECC256", "ECC384", "ECC521".
 *     - ECDH BrainPool series since API version 20: "ECC_BrainPoolP160r1", "ECC_BrainPoolP160t1",
 *     "ECC_BrainPoolP192r1", "ECC_BrainPoolP192t1", "ECC_BrainPoolP224r1", "ECC_BrainPoolP224t1",
 *     "ECC_BrainPoolP256r1", "ECC_BrainPoolP256t1", "ECC_BrainPoolP320r1", "ECC_BrainPoolP320t1",
 *     "ECC_BrainPoolP384r1", "ECC_BrainPoolP384t1", "ECC_BrainPoolP512r1", "ECC_BrainPoolP512t1".
 *     - "ECC_Secp256k1" supported since API version 20.
 *     - "X25519" supported since API version 20.
 *     - DH series since API version 20: "DH_modp1536", "DH_modp2048", "DH_modp3072",
 *     "DH_modp4096", "DH_modp6144", "DH_modp8192", "DH_ffdhe2048", "DH_ffdhe3072",
 *     "DH_ffdhe4096", "DH_ffdhe6144", "DH_ffdhe8192".
 *     - "ECC192" supported since API version 26.0.0.
 * @param ctx [out] Pointer to the key agreement context pointer. ctx cannot be NULL,
 *     *ctx must be NULL.
 * @return <ul>
 *         <li>{@link OH_Crypto_ErrCode#CRYPTO_SUCCESS} if the operation succeeds.</li>
 *         <li>{@link OH_Crypto_ErrCode#CRYPTO_PARAMETER_CHECK_FAILED} if algoName or ctx is NULL.</li>
 *         <li>{@link OH_Crypto_ErrCode#CRYPTO_NOT_SUPPORTED} if the algorithm is not supported.</li>
 *         <li>{@link OH_Crypto_ErrCode#CRYPTO_MEMORY_ERROR} if memory allocation fails.</li>
 *         <li>{@link OH_Crypto_ErrCode#CRYPTO_OPERTION_ERROR} if key agreement operation fails.</li>
 *         </ul>
 * @release crypto_key_agreement/OH_CryptoKeyAgreement_Destroy {ctx}
 * @since 20
 * @see {@link OH_CryptoKeyAgreement_GenerateSecret} Generates a shared secret.
 */
OH_Crypto_ErrCode OH_CryptoKeyAgreement_Create(const char *algoName, OH_CryptoKeyAgreement **ctx);

/**
 * @brief Generates a shared secret.
 * @param ctx [in] Key agreement context. Cannot be NULL.
 * @param privkey [in] Private key. Cannot be NULL.
 * @param pubkey [in] Public key. Cannot be NULL.
 * @param secret [out] Pointer to the Crypto_DataBlob structure for storing the shared secret. Cannot be NULL.
 *     Initialize secret to {0} before calling. Do not pre-allocate secret->data.
 * @return <ul>
 *         <li>{@link OH_Crypto_ErrCode#CRYPTO_SUCCESS} if the operation succeeds.</li>
 *         <li>{@link OH_Crypto_ErrCode#CRYPTO_PARAMETER_CHECK_FAILED} if ctx, privkey, pubkey, or secret is NULL.</li>
 *         <li>{@link OH_Crypto_ErrCode#CRYPTO_NOT_SUPPORTED} if the algorithm is not supported.</li>
 *         <li>{@link OH_Crypto_ErrCode#CRYPTO_MEMORY_ERROR} if memory allocation fails.</li>
 *         <li>{@link OH_Crypto_ErrCode#CRYPTO_OPERTION_ERROR} if the key agreement operation fails.
 *            Possible causes: the public key and private key do not belong to the same curve or
 *            algorithm, or the public key data is invalid.</li>
 *         </ul>
 * @release crypto_common/OH_Crypto_FreeDataBlob {secret}
 * @since 20
 */
OH_Crypto_ErrCode OH_CryptoKeyAgreement_GenerateSecret(OH_CryptoKeyAgreement *ctx, OH_CryptoPrivKey *privkey,
    OH_CryptoPubKey *pubkey, Crypto_DataBlob *secret);

/**
 * @brief Destroys the key agreement context.
 * @param ctx [in] Key agreement context.
 * @since 20
 */
void OH_CryptoKeyAgreement_Destroy(OH_CryptoKeyAgreement *ctx);

#ifdef __cplusplus
}
#endif

#endif /* CRYPTO_KEY_AGREEMENT_H */
/** @} */
