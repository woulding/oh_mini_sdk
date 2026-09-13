/*
 * Copyright (c) 2024-2026 Huawei Device Co., Ltd.
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
 * @addtogroup CryptoSymCipherApi
 * @{
 * @brief Describes the symmetric key cipher interfaces provided by OpenHarmony for applications.
 * @since 12
 */

/**
 * @file crypto_sym_cipher.h
 * @brief Defines the symmetric key cipher interfaces.
 * @syscap SystemCapability.Security.CryptoFramework
 * @library libohcrypto.so
 * @kit CryptoArchitectureKit
 * @since 12
 */

#ifndef CRYPTO_SYM_CIPHER_H
#define CRYPTO_SYM_CIPHER_H

#include "crypto_common.h"
#include "crypto_sym_key.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief Defines the cipher parameter types.
 * @since 12
 */
typedef enum {
    /**
     * @brief Initialization vector (IV) parameter.
     * @since 12
     */
    CRYPTO_IV_DATABLOB = 100,
    /**
     * @brief Additional authenticated data (AAD) for AEAD modes (e.g. GCM, CCM).
     * @since 12
     */
    CRYPTO_AAD_DATABLOB = 101,
    /**
     * @brief Authentication tag for AEAD modes (e.g. GCM, CCM), used for data integrity verification.
     * @since 12
     */
    CRYPTO_TAG_DATABLOB = 102,
} CryptoSymCipher_ParamsType;

/**
 * @brief Symmetric cipher structure, representing a symmetric cipher context.
 * @since 12
 */
typedef struct OH_CryptoSymCipher OH_CryptoSymCipher;

/**
 * @brief Symmetric cipher parameters structure, representing symmetric cipher parameters.
 * @since 12
 */
typedef struct OH_CryptoSymCipherParams OH_CryptoSymCipherParams;

/**
 * @brief Creates symmetric cipher parameters.
 * @param params [out] Pointer to the cipher parameters pointer. params cannot be NULL, *params must be NULL.
 * @return <ul>
 *         <li>{@link OH_Crypto_ErrCode#CRYPTO_SUCCESS} if the operation succeeds.</li>
 *         <li>{@link OH_Crypto_ErrCode#CRYPTO_INVALID_PARAMS} if params is NULL.</li>
 *         <li>{@link OH_Crypto_ErrCode#CRYPTO_NOT_SUPPORTED} if unsupported operation or algorithm.</li>
 *         <li>{@link OH_Crypto_ErrCode#CRYPTO_MEMORY_ERROR} if memory operation fails.</li>
 *         <li>{@link OH_Crypto_ErrCode#CRYPTO_OPERTION_ERROR} if crypto operation fails.</li>
 *         </ul>
 * @release crypto_sym_cipher/OH_CryptoSymCipherParams_Destroy {params}
 * @since 12
 * @see {@link OH_CryptoSymCipherParams_SetParam} Sets cipher parameters.
 */
OH_Crypto_ErrCode OH_CryptoSymCipherParams_Create(OH_CryptoSymCipherParams **params);

/**
 * @brief Sets cipher parameters.
 * @param params [in] Cipher parameters. Cannot be NULL.
 * @param paramsType [in] Cipher parameter type to set.
 * @param value [in] Parameter value. This function performs a shallow copy and does not copy the
 *     data in value. The caller must ensure that the memory pointed to by value remains valid until
 *     {@link OH_CryptoSymCipher_Init} completes. Cannot be NULL.
 * @return <ul>
 *         <li>{@link OH_Crypto_ErrCode#CRYPTO_SUCCESS} if the operation succeeds.</li>
 *         <li>{@link OH_Crypto_ErrCode#CRYPTO_INVALID_PARAMS} if params or value is NULL, or
 *            paramsType is unrecognized.</li>
 *         <li>{@link OH_Crypto_ErrCode#CRYPTO_NOT_SUPPORTED} if unsupported operation or algorithm.</li>
 *         <li>{@link OH_Crypto_ErrCode#CRYPTO_MEMORY_ERROR} if memory operation fails.</li>
 *         <li>{@link OH_Crypto_ErrCode#CRYPTO_OPERTION_ERROR} if crypto operation fails.</li>
 *         </ul>
 * @since 12
 */
OH_Crypto_ErrCode OH_CryptoSymCipherParams_SetParam(OH_CryptoSymCipherParams *params,
    CryptoSymCipher_ParamsType paramsType, Crypto_DataBlob *value);

/**
 * @brief Destroys cipher parameters.
 * @param params [in] Cipher parameters.
 * @since 12
 */
void OH_CryptoSymCipherParams_Destroy(OH_CryptoSymCipherParams *params);

/**
 * @brief Creates a symmetric cipher context based on the given algorithm name.
 * @param algoName [in] Symmetric cipher algorithm name. Cannot be NULL. Format: "Algorithm|Mode|Padding",
 *     separated by "|". Algorithms: AES128, AES192, AES256, SM4_128, 3DES192, DES64, ChaCha20, RC2,
 *     Blowfish, CAST. Modes: ECB, CBC, CTR, OFB, CFB, CFB1, CFB8, CFB64, CFB128, GCM, CCM, XTS,
 *     Poly1305. Padding: NoPadding, PKCS5, PKCS7. Supported combinations:
 *     - AES series since API version 12: AES128, AES192, AES256 algorithms, ECB, CBC, CTR, OFB, CFB,
 *     GCM, CCM modes, NoPadding or PKCS7. Examples: "AES128|GCM", "AES256|CBC|PKCS7".
 *     - 3DES series since API version 12: 3DES192 algorithm, ECB, CBC, OFB, CFB modes, NoPadding,
 *     PKCS5, or PKCS7. Example: "3DES192|CBC|PKCS5".
 *     - SM4 series since API version 12: SM4_128 algorithm, ECB, CBC, CTR, OFB, CFB, CFB128, GCM modes,
 *     NoPadding or PKCS7. Examples: "SM4_128|CBC|PKCS7", "SM4_128|GCM|NoPadding".
 *     - DES series since API version 20: DES64 algorithm, ECB, CBC, OFB, CFB modes, NoPadding,
 *     PKCS5, or PKCS7. Example: "DES64|CBC|PKCS5".
 *     - AES WRAP algorithms since API version 22: AES128_WRAP, AES192_WRAP, AES256_WRAP.
 *     Examples: "AES128_WRAP", "AES192_WRAP", "AES256_WRAP".
 *     - ChaCha20 since API version 22: "ChaCha20", "ChaCha20|Poly1305".
 *     Examples: "ChaCha20|Poly1305", "ChaCha20".
 *     - AES XTS mode since API version 26.0.0: "AES128|XTS", "AES256|XTS". AES192 is not supported.
 *     - RC2 since API version 26.0.0: ECB, CBC, OFB, CFB modes, NoPadding, PKCS5, or PKCS7. Example: "RC2|CBC|PKCS5".
 *     - RC4 since API version 26.0.0: "RC4". Example: "RC4".
 *     - Blowfish since API version 26.0.0: ECB, CBC, OFB, CFB modes, NoPadding, PKCS5, or PKCS7.
 *     Example: "Blowfish|CBC|PKCS5".
 *     - CAST since API version 26.0.0: ECB, CBC, OFB, CFB modes, NoPadding, PKCS5, or PKCS7. Example: "CAST|CBC|PKCS5".
 *     Padding notes:
 *     - ECB and CBC modes require padding: when plaintext length is not a multiple of the algorithm block size,
 *     PKCS5 or PKCS7 must be used; with NoPadding, input length must be a multiple of the
 *     block size (16 bytes for AES/SM4, 8 bytes for DES/3DES/RC2/Blowfish/CAST).
 *     - CTR, OFB, CFB, CFB1, CFB8, CFB64, CFB128, GCM, CCM modes convert block ciphers to stream
 *     mode and do not need padding. Any specified padding is treated as NoPadding.
 *     - XTS mode does not involve padding and does not require a padding field. Any specified padding is treated
 *     as NoPadding.
 *     - ChaCha20 is a stream cipher algorithm and does not require a padding field. Any specified padding is treated
 *     as NoPadding.
 * @param ctx [out] Pointer to the symmetric cipher context pointer. ctx cannot be NULL, *ctx must be NULL.
 * @return <ul>
 *         <li>{@link OH_Crypto_ErrCode#CRYPTO_SUCCESS} if the operation succeeds.</li>
 *         <li>{@link OH_Crypto_ErrCode#CRYPTO_INVALID_PARAMS} if ctx or algoName is NULL.</li>
 *         <li>{@link OH_Crypto_ErrCode#CRYPTO_NOT_SUPPORTED} if the algorithm is not supported.</li>
 *         <li>{@link OH_Crypto_ErrCode#CRYPTO_MEMORY_ERROR} if memory allocation fails.</li>
 *         <li>{@link OH_Crypto_ErrCode#CRYPTO_PARAMETER_CHECK_FAILED} if parameters are invalid. [since 20]</li>
 *         <li>{@link OH_Crypto_ErrCode#CRYPTO_OPERTION_ERROR} if crypto operation fails.</li>
 *         </ul>
 * @release crypto_sym_cipher/OH_CryptoSymCipher_Destroy {ctx}
 * @since 12
 * @see {@link OH_CryptoSymCipher_Init} Initializes the cipher operation with the given mode, key, and parameters.
 */
OH_Crypto_ErrCode OH_CryptoSymCipher_Create(const char *algoName, OH_CryptoSymCipher **ctx);

/**
 * @brief Initializes the cipher operation with the given mode, key, and parameters.
 * @param ctx [in] Symmetric cipher context. Cannot be NULL.
 * @param mod [in] Cipher mode, encryption or decryption.
 * @param key [in] Symmetric key. Cannot be NULL.
 * @param params [in] Algorithm parameters, e.g. IV. Must be NULL for ECB mode; cannot be NULL for other modes.
 * @return <ul>
 *         <li>{@link OH_Crypto_ErrCode#CRYPTO_SUCCESS} if the operation succeeds.</li>
 *         <li>{@link OH_Crypto_ErrCode#CRYPTO_INVALID_PARAMS} if ctx or key is NULL,
 *            or IV is missing or has wrong length for non-ECB modes.</li>
 *         <li>{@link OH_Crypto_ErrCode#CRYPTO_NOT_SUPPORTED} if the operation is not supported.</li>
 *         <li>{@link OH_Crypto_ErrCode#CRYPTO_MEMORY_ERROR} if memory allocation fails.</li>
 *         <li>{@link OH_Crypto_ErrCode#CRYPTO_PARAMETER_CHECK_FAILED} if parameters are invalid. [since 20]</li>
 *         <li>{@link OH_Crypto_ErrCode#CRYPTO_OPERTION_ERROR} if cipher init fails. Possible causes:
 *            key length does not match the algorithm.</li>
 *         </ul>
 * @since 12
 * @see {@link OH_CryptoSymCipher_Update} Updates cipher data, outputting encrypted or decrypted data.
 * @see {@link OH_CryptoSymCipher_Final} Finishes the cipher operation, outputting the final result.
 */
OH_Crypto_ErrCode OH_CryptoSymCipher_Init(OH_CryptoSymCipher *ctx, Crypto_CipherMode mod,
    OH_CryptoSymKey *key, OH_CryptoSymCipherParams *params);

/**
 * @brief Updates cipher data, outputting encrypted or decrypted data.
 * @param ctx [in] Symmetric cipher context. Cannot be NULL.
 * @param in [in] Data to be encrypted or decrypted. Cannot be NULL.
 * @param out [out] Pointer to the Crypto_DataBlob structure for storing the updated data. Cannot be NULL. Initialize
 *     out to {0} before calling. Do not pre-allocate out->data.
 * @return <ul>
 *         <li>{@link OH_Crypto_ErrCode#CRYPTO_SUCCESS} if the operation succeeds.</li>
 *         <li>{@link OH_Crypto_ErrCode#CRYPTO_INVALID_PARAMS} if ctx, in, or out is NULL.</li>
 *         <li>{@link OH_Crypto_ErrCode#CRYPTO_NOT_SUPPORTED} if unsupported operation or algorithm.</li>
 *         <li>{@link OH_Crypto_ErrCode#CRYPTO_MEMORY_ERROR} if memory operation fails.</li>
 *         <li>{@link OH_Crypto_ErrCode#CRYPTO_PARAMETER_CHECK_FAILED} if parameters are invalid. [since 20]</li>
 *         <li>{@link OH_Crypto_ErrCode#CRYPTO_OPERTION_ERROR} if cipher update fails.</li>
 *         </ul>
 * @release crypto_common/OH_Crypto_FreeDataBlob {out}
 * @since 12
 * @see {@link OH_CryptoSymCipher_Final} Finishes the cipher operation, outputting the final result.
 */
OH_Crypto_ErrCode OH_CryptoSymCipher_Update(OH_CryptoSymCipher *ctx, Crypto_DataBlob *in, Crypto_DataBlob *out);

/**
 * @brief Finishes the cipher operation, outputting the final result.
 * @param ctx [in] Symmetric cipher context. Cannot be NULL.
 * @param in [in] Data to be encrypted or decrypted. Can be NULL if all data has been updated via
 *     {@link OH_CryptoSymCipher_Update}.
 * @param out [out] Pointer to the Crypto_DataBlob structure for storing the final result. Cannot be NULL. Initialize
 *     out to {0} before calling. Do not pre-allocate out->data.
 * @return <ul>
 *         <li>{@link OH_Crypto_ErrCode#CRYPTO_SUCCESS} if the operation succeeds.</li>
 *         <li>{@link OH_Crypto_ErrCode#CRYPTO_INVALID_PARAMS} if ctx or out is NULL.</li>
 *         <li>{@link OH_Crypto_ErrCode#CRYPTO_NOT_SUPPORTED} if unsupported operation or algorithm.</li>
 *         <li>{@link OH_Crypto_ErrCode#CRYPTO_MEMORY_ERROR} if memory operation fails.</li>
 *         <li>{@link OH_Crypto_ErrCode#CRYPTO_PARAMETER_CHECK_FAILED} if parameters are invalid. [since 20]</li>
 *         <li>{@link OH_Crypto_ErrCode#CRYPTO_OPERTION_ERROR} if cipher final fails. Possible causes:
 *            incorrect IV or key during decryption; AEAD (GCM/CCM) authentication tag verification
 *            failure due to incorrect TAG, AAD, ciphertext, or key; block cipher (e.g. AES-CBC/ECB)
 *            decryption where ciphertext length is not a multiple of the block size; block cipher
 *            encryption with NoPadding where plaintext length is not a multiple of the block size.</li>
 *         </ul>
 * @release crypto_common/OH_Crypto_FreeDataBlob {out}
 * @since 12
 */
OH_Crypto_ErrCode OH_CryptoSymCipher_Final(OH_CryptoSymCipher *ctx, Crypto_DataBlob *in, Crypto_DataBlob *out);

/**
 * @brief Obtains the symmetric cipher algorithm name.
 * @param ctx [in] Symmetric cipher context. Cannot be NULL.
 * @return Returns the symmetric cipher algorithm name. No need to free by the caller. Invalid after
 *     the context is destroyed.
 * @since 12
 */
const char *OH_CryptoSymCipher_GetAlgoName(OH_CryptoSymCipher *ctx);

/**
 * @brief Destroys the symmetric cipher context.
 * @param ctx [in] Symmetric cipher context.
 * @since 12
 */
void OH_CryptoSymCipher_Destroy(OH_CryptoSymCipher *ctx);

#ifdef __cplusplus
}
#endif

#endif /* CRYPTO_SYM_CIPHER_H */
/** @} */
