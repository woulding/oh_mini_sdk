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
 * @addtogroup CryptoAsymCipherApi
 * @{
 * @brief Describes the asymmetric cipher interfaces provided by OpenHarmony for applications.
 * @since 20
 */

/**
 * @file crypto_asym_cipher.h
 * @brief Defines the asymmetric cipher interfaces.
 * @syscap SystemCapability.Security.CryptoFramework
 * @library libohcrypto.so
 * @kit CryptoArchitectureKit
 * @since 20
 */

#ifndef CRYPTO_ASYM_CIPHER_H
#define CRYPTO_ASYM_CIPHER_H

#include "crypto_common.h"
#include "crypto_asym_key.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief Asymmetric cipher structure, representing an asymmetric cipher context.
 * @since 20
 */
typedef struct OH_CryptoAsymCipher OH_CryptoAsymCipher;

/**
 * @brief Creates an asymmetric cipher context based on the given algorithm name.
 * @param algoName [in] Asymmetric cipher algorithm name. Cannot be NULL. Values:
 *     - RSA algorithm PKCS1 padding mode: "RSA|PKCS1".
 *     - RSA algorithm OAEP padding mode: Format "RSA|PKCS1_OAEP|Digest|MGF1Digest",
 *     e.g. "RSA|PKCS1_OAEP|SHA256|MGF1_SHA256".
 *     Digest supports "MD5", "SHA1", "SHA224", "SHA256", "SHA384", "SHA512".
 *     MGF1 digest supports "MGF1_SHA1", "MGF1_SHA224", "MGF1_SHA256", "MGF1_SHA384", "MGF1_SHA512".
 *     - RSA algorithm NoPadding padding mode: "RSA|NoPadding".
 *     - SM2 algorithm: Format "SM2|Digest", e.g. "SM2|SM3".
 *     Digest supports "MD5", "SHA1", "SHA224", "SHA256", "SHA384", "SHA512", "SM3".
 * @param ctx [out] Pointer to the asymmetric cipher context pointer. ctx cannot be NULL, *ctx must be NULL.
 * @return <ul>
 *         <li>{@link OH_Crypto_ErrCode#CRYPTO_SUCCESS} if the operation succeeds.</li>
 *         <li>{@link OH_Crypto_ErrCode#CRYPTO_PARAMETER_CHECK_FAILED} if algoName or ctx is NULL.</li>
 *         <li>{@link OH_Crypto_ErrCode#CRYPTO_NOT_SUPPORTED} if the algorithm is not supported.</li>
 *         <li>{@link OH_Crypto_ErrCode#CRYPTO_MEMORY_ERROR} if memory allocation fails.</li>
 *         <li>{@link OH_Crypto_ErrCode#CRYPTO_OPERTION_ERROR} if crypto operation fails.</li>
 *         </ul>
 * @release crypto_asym_cipher/OH_CryptoAsymCipher_Destroy {ctx}
 * @since 20
 * @see {@link OH_CryptoAsymCipher_Init} Initializes the asymmetric cipher context.
 */
OH_Crypto_ErrCode OH_CryptoAsymCipher_Create(const char *algoName, OH_CryptoAsymCipher **ctx);

/**
 * @brief Initializes the asymmetric cipher context with the given cipher mode and key.
 * @param ctx [in] Asymmetric cipher context. Cannot be NULL.
 * @param mode [in] Cipher mode, encryption or decryption.
 * @param key [in] Asymmetric key. Cannot be NULL.
 * @return <ul>
 *         <li>{@link OH_Crypto_ErrCode#CRYPTO_SUCCESS} if the operation succeeds.</li>
 *         <li>{@link OH_Crypto_ErrCode#CRYPTO_PARAMETER_CHECK_FAILED} if ctx or key is NULL.</li>
 *         <li>{@link OH_Crypto_ErrCode#CRYPTO_NOT_SUPPORTED} if unsupported operation or algorithm.</li>
 *         <li>{@link OH_Crypto_ErrCode#CRYPTO_MEMORY_ERROR} if memory operation fails.</li>
 *         <li>{@link OH_Crypto_ErrCode#CRYPTO_OPERTION_ERROR} if cipher init fails.</li>
 *         </ul>
 * @since 20
 * @see {@link OH_CryptoAsymCipher_Final} Finishes the cipher operation.
 */
OH_Crypto_ErrCode OH_CryptoAsymCipher_Init(OH_CryptoAsymCipher *ctx, Crypto_CipherMode mode,
    OH_CryptoKeyPair *key);

/**
 * @brief Finishes the cipher operation.
 * @param ctx [in] Asymmetric cipher context. Cannot be NULL.
 * @param in [in] Data to be encrypted or decrypted. Cannot be NULL.
 * @param out [out] Pointer to the Crypto_DataBlob structure for storing the encrypted or decrypted result. Cannot be
 *     NULL. Initialize out to {0} before calling. Do not pre-allocate out->data.
 * @return <ul>
 *         <li>{@link OH_Crypto_ErrCode#CRYPTO_SUCCESS} if the operation succeeds.</li>
 *         <li>{@link OH_Crypto_ErrCode#CRYPTO_PARAMETER_CHECK_FAILED} if ctx, in, or out is NULL.</li>
 *         <li>{@link OH_Crypto_ErrCode#CRYPTO_NOT_SUPPORTED} if unsupported operation or algorithm.</li>
 *         <li>{@link OH_Crypto_ErrCode#CRYPTO_MEMORY_ERROR} if memory allocation fails.</li>
 *         <li>{@link OH_Crypto_ErrCode#CRYPTO_OPERTION_ERROR} if cipher final fails. Possible causes:
 *            RSA encryption where plaintext exceeds the maximum length allowed by the key size and
 *            padding mode; RSA decryption with incorrect key or corrupted ciphertext; SM2 decryption
 *            with incorrect key or corrupted ciphertext; SM2 ciphertext with invalid ASN.1 structure.</li>
 *         </ul>
 * @release crypto_common/OH_Crypto_FreeDataBlob {out}
 * @since 20
 */
OH_Crypto_ErrCode OH_CryptoAsymCipher_Final(OH_CryptoAsymCipher *ctx, const Crypto_DataBlob *in, Crypto_DataBlob *out);

/**
 * @brief Destroys the asymmetric cipher context.
 * @param ctx [in] Asymmetric cipher context.
 * @since 20
 */
void OH_CryptoAsymCipher_Destroy(OH_CryptoAsymCipher *ctx);

/**
 * @brief SM2 ciphertext specification structure, representing an SM2 ciphertext specification.
 * @since 20
 */
typedef struct OH_CryptoSm2CiphertextSpec OH_CryptoSm2CiphertextSpec;

/**
 * @brief Defines SM2 ciphertext specification item types.
 * @since 20
 */
typedef enum {
    /**
     * @brief Public key x, also known as C1x.
     * @since 20
     */
    CRYPTO_SM2_CIPHERTEXT_C1_X = 0,
    /**
     * @brief Public key y, also known as C1y.
     * @since 20
     */
    CRYPTO_SM2_CIPHERTEXT_C1_Y = 1,
    /**
     * @brief Ciphertext data, also known as C2.
     * @since 20
     */
    CRYPTO_SM2_CIPHERTEXT_C2 = 2,
    /**
     * @brief Message digest (hash value), also known as C3.
     * @since 20
     */
    CRYPTO_SM2_CIPHERTEXT_C3 = 3,
} CryptoSm2CiphertextSpec_item;

/**
 * @brief Creates an SM2 ciphertext specification.
 * @param sm2Ciphertext [in] SM2 ciphertext in DER format. If NULL, an empty SM2 ciphertext specification is created.
 * @param spec [out] Pointer to the SM2 ciphertext specification pointer. spec cannot be NULL, *spec must be NULL.
 * @return <ul>
 *         <li>{@link OH_Crypto_ErrCode#CRYPTO_SUCCESS} if the operation succeeds.</li>
 *         <li>{@link OH_Crypto_ErrCode#CRYPTO_PARAMETER_CHECK_FAILED} if spec is NULL.</li>
 *         <li>{@link OH_Crypto_ErrCode#CRYPTO_NOT_SUPPORTED} if unsupported operation or algorithm.</li>
 *         <li>{@link OH_Crypto_ErrCode#CRYPTO_MEMORY_ERROR} if memory allocation fails.</li>
 *         <li>{@link OH_Crypto_ErrCode#CRYPTO_OPERTION_ERROR} if parsing SM2 ciphertext fails. Possible causes:
 *            the input data is not valid DER-encoded SM2 ciphertext.</li>
 *         </ul>
 * @release crypto_asym_cipher/OH_CryptoSm2CiphertextSpec_Destroy {spec}
 * @since 20
 * @see {@link OH_CryptoSm2CiphertextSpec_GetItem} Obtains the specified item of the SM2 ciphertext.
 * @see {@link OH_CryptoSm2CiphertextSpec_SetItem} Sets the specified item of the SM2 ciphertext.
 */
OH_Crypto_ErrCode OH_CryptoSm2CiphertextSpec_Create(Crypto_DataBlob *sm2Ciphertext,
    OH_CryptoSm2CiphertextSpec **spec);

/**
 * @brief Obtains the specified item of the SM2 ciphertext.
 * @param spec [in] SM2 ciphertext specification. Cannot be NULL.
 * @param item [in] SM2 ciphertext specification item.
 * @param out [out] Pointer to the Crypto_DataBlob structure for storing the output data. Cannot be NULL. Initialize out
 *     to {0} before calling. Do not pre-allocate out->data.
 * @return <ul>
 *         <li>{@link OH_Crypto_ErrCode#CRYPTO_SUCCESS} if the operation succeeds.</li>
 *         <li>{@link OH_Crypto_ErrCode#CRYPTO_PARAMETER_CHECK_FAILED} if spec or out is NULL.</li>
 *         <li>{@link OH_Crypto_ErrCode#CRYPTO_NOT_SUPPORTED} if unsupported operation or algorithm.</li>
 *         <li>{@link OH_Crypto_ErrCode#CRYPTO_MEMORY_ERROR} if memory allocation fails.</li>
 *         <li>{@link OH_Crypto_ErrCode#CRYPTO_OPERTION_ERROR} if crypto operation fails.</li>
 *         </ul>
 * @release crypto_common/OH_Crypto_FreeDataBlob {out}
 * @since 20
 */
OH_Crypto_ErrCode OH_CryptoSm2CiphertextSpec_GetItem(OH_CryptoSm2CiphertextSpec *spec,
    CryptoSm2CiphertextSpec_item item, Crypto_DataBlob *out);

/**
 * @brief Sets the specified item of the SM2 ciphertext specification.
 * @param spec [in] SM2 ciphertext specification. Cannot be NULL.
 * @param item [in] SM2 ciphertext specification item.
 * @param in [in] Input data. Cannot be NULL. This function performs a deep copy of the input data.
 *     The caller can release in immediately after the function returns.
 * @return <ul>
 *         <li>{@link OH_Crypto_ErrCode#CRYPTO_SUCCESS} if the operation succeeds.</li>
 *         <li>{@link OH_Crypto_ErrCode#CRYPTO_PARAMETER_CHECK_FAILED} if spec or in is NULL,
 *            in->data is NULL, or in->len is 0.</li>
 *         <li>{@link OH_Crypto_ErrCode#CRYPTO_NOT_SUPPORTED} if unsupported operation or algorithm.</li>
 *         <li>{@link OH_Crypto_ErrCode#CRYPTO_MEMORY_ERROR} if memory allocation for deep copy fails.</li>
 *         <li>{@link OH_Crypto_ErrCode#CRYPTO_OPERTION_ERROR} if crypto operation fails.</li>
 *         </ul>
 * @since 20
 * @see {@link OH_CryptoSm2CiphertextSpec_Encode} Encodes the SM2 ciphertext specification to DER format.
 */
OH_Crypto_ErrCode OH_CryptoSm2CiphertextSpec_SetItem(OH_CryptoSm2CiphertextSpec *spec,
    CryptoSm2CiphertextSpec_item item, Crypto_DataBlob *in);

/**
 * @brief Encodes the SM2 ciphertext specification to DER format ciphertext.
 * @param spec [in] SM2 ciphertext specification. Cannot be NULL.
 * @param out [out] Pointer to the Crypto_DataBlob structure for storing the encoded data. Cannot be NULL. Initialize
 *     out to {0} before calling. Do not pre-allocate out->data.
 * @return <ul>
 *         <li>{@link OH_Crypto_ErrCode#CRYPTO_SUCCESS} if the operation succeeds.</li>
 *         <li>{@link OH_Crypto_ErrCode#CRYPTO_PARAMETER_CHECK_FAILED} if spec or out is NULL,
 *            or SM2 ciphertext fields (C1X, C1Y, C2, C3) have not been set, or C3 (hashData)
 *            length is not 32 bytes.</li>
 *         <li>{@link OH_Crypto_ErrCode#CRYPTO_NOT_SUPPORTED} if unsupported operation or algorithm.</li>
 *         <li>{@link OH_Crypto_ErrCode#CRYPTO_MEMORY_ERROR} if memory operation fails.</li>
 *         <li>{@link OH_Crypto_ErrCode#CRYPTO_OPERTION_ERROR} if encoding fails.</li>
 *         </ul>
 * @release crypto_common/OH_Crypto_FreeDataBlob {out}
 * @since 20
 */
OH_Crypto_ErrCode OH_CryptoSm2CiphertextSpec_Encode(OH_CryptoSm2CiphertextSpec *spec, Crypto_DataBlob *out);

/**
 * @brief Destroys the SM2 ciphertext specification.
 * @param spec [in] SM2 ciphertext specification.
 * @since 20
 */
void OH_CryptoSm2CiphertextSpec_Destroy(OH_CryptoSm2CiphertextSpec *spec);

#ifdef __cplusplus
}
#endif

#endif /* CRYPTO_ASYM_CIPHER_H */
/** @} */
