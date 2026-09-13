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
 * @addtogroup CryptoSymKeyApi
 * @{
 * @brief Describes the symmetric key interfaces provided by OpenHarmony for applications.
 * @since 12
 */

/**
 * @file crypto_sym_key.h
 * @brief Defines the symmetric key interfaces.
 * @syscap SystemCapability.Security.CryptoFramework
 * @library libohcrypto.so
 * @kit CryptoArchitectureKit
 * @since 12
 */

#ifndef CRYPTO_SYM_KEY_H
#define CRYPTO_SYM_KEY_H

#include "crypto_common.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief Symmetric key structure, representing a symmetric key.
 * @since 12
 */
typedef struct OH_CryptoSymKey OH_CryptoSymKey;

/**
 * @brief Symmetric key generator structure, representing a symmetric key generator.
 * @since 12
 */
typedef struct OH_CryptoSymKeyGenerator OH_CryptoSymKeyGenerator;

/**
 * @brief Creates a symmetric key generator based on the given algorithm name, e.g. AES256.
 * @param algoName [in] Symmetric key algorithm name. Cannot be NULL. Values:
 *     - "AES128", "AES192", "AES256", "3DES192", "HMAC|SHA1", "HMAC|SHA224",
 *     "HMAC|SHA256", "HMAC|SHA384", "HMAC|SHA512", "HMAC|SM3", "HMAC|MD5" supported since API version 12.
 *     "HMAC|SHA3-256", "HMAC|SHA3-384", "HMAC|SHA3-512" supported since API version 26.0.0.
 *     - "SM4_128" supported since API version 12.
 *     - "DES64" supported since API version 20.
 *     - "ChaCha20" supported since API version 22.
 *     - "RC2", "RC4", "Blowfish", "CAST" supported since API version 26.0.0. Note: only key conversion
 *     is supported, random generation is not.
 * @param ctx [out] Pointer to the symmetric key generator pointer. ctx cannot be NULL, *ctx must be NULL.
 * @return <ul>
 *         <li>{@link OH_Crypto_ErrCode#CRYPTO_SUCCESS} if the operation succeeds.</li>
 *         <li>{@link OH_Crypto_ErrCode#CRYPTO_INVALID_PARAMS} if ctx or algoName is NULL.</li>
 *         <li>{@link OH_Crypto_ErrCode#CRYPTO_NOT_SUPPORTED} if the algorithm is not supported.</li>
 *         <li>{@link OH_Crypto_ErrCode#CRYPTO_MEMORY_ERROR} if memory allocation fails.</li>
 *         <li>{@link OH_Crypto_ErrCode#CRYPTO_OPERTION_ERROR} if crypto operation fails.</li>
 *         </ul>
 * @release crypto_sym_key/OH_CryptoSymKeyGenerator_Destroy {ctx}
 * @since 12
 * @see {@link OH_CryptoSymKeyGenerator_Generate} Generates a symmetric key randomly.
 * @see {@link OH_CryptoSymKeyGenerator_Convert} Converts symmetric key data to a symmetric key.
 */
OH_Crypto_ErrCode OH_CryptoSymKeyGenerator_Create(const char *algoName, OH_CryptoSymKeyGenerator **ctx);

/**
 * @brief Generates a symmetric key randomly.
 * @param ctx [in] Symmetric key generator. Cannot be NULL.
 * @param keyCtx [out] Pointer to the symmetric key pointer. keyCtx cannot be NULL, *keyCtx must be NULL.
 * @return <ul>
 *         <li>{@link OH_Crypto_ErrCode#CRYPTO_SUCCESS} if the operation succeeds.</li>
 *         <li>{@link OH_Crypto_ErrCode#CRYPTO_INVALID_PARAMS} if ctx or keyCtx is NULL.</li>
 *         <li>{@link OH_Crypto_ErrCode#CRYPTO_NOT_SUPPORTED} if unsupported operation or algorithm.</li>
 *         <li>{@link OH_Crypto_ErrCode#CRYPTO_MEMORY_ERROR} if memory operation fails.</li>
 *         <li>{@link OH_Crypto_ErrCode#CRYPTO_INVALID_CALL} if the function call is invalid. Possible causes:
 *            the algorithm does not support random key generation (e.g. RC2, RC4, Blowfish, CAST),
 *            use OH_CryptoSymKeyGenerator_Convert interface instead.[since 26.0.0]</li>
 *         <li>{@link OH_Crypto_ErrCode#CRYPTO_OPERTION_ERROR} if crypto operation fails.</li>
 *         </ul>
 * @release crypto_sym_key/OH_CryptoSymKey_Destroy {keyCtx}
 * @since 12
 */
OH_Crypto_ErrCode OH_CryptoSymKeyGenerator_Generate(OH_CryptoSymKeyGenerator *ctx, OH_CryptoSymKey **keyCtx);

/**
 * @brief Converts symmetric key data to a symmetric key.
 * @param ctx [in] Symmetric key generator. Cannot be NULL.
 * @param keyData [in] Data used to generate the symmetric key. Cannot be NULL.
 * @param keyCtx [out] Pointer to the symmetric key pointer. keyCtx cannot be NULL, *keyCtx must be NULL.
 * @return <ul>
 *         <li>{@link OH_Crypto_ErrCode#CRYPTO_SUCCESS} if the operation succeeds.</li>
 *         <li>{@link OH_Crypto_ErrCode#CRYPTO_INVALID_PARAMS} if ctx, keyData, or keyCtx is NULL.</li>
 *         <li>{@link OH_Crypto_ErrCode#CRYPTO_NOT_SUPPORTED} if unsupported operation or algorithm.</li>
 *         <li>{@link OH_Crypto_ErrCode#CRYPTO_MEMORY_ERROR} if memory allocation fails.</li>
 *         <li>{@link OH_Crypto_ErrCode#CRYPTO_OPERTION_ERROR} if crypto operation fails.</li>
 *         </ul>
 * @release crypto_sym_key/OH_CryptoSymKey_Destroy {keyCtx}
 * @since 12
 */
OH_Crypto_ErrCode OH_CryptoSymKeyGenerator_Convert(OH_CryptoSymKeyGenerator *ctx,
    const Crypto_DataBlob *keyData, OH_CryptoSymKey **keyCtx);

/**
 * @brief Obtains the algorithm name of the symmetric key generator.
 * @param ctx [in] Symmetric key generator. Cannot be NULL.
 * @return Returns the symmetric key algorithm name. No need to free by the caller. Invalid after
 *     the generator is destroyed.
 * @since 12
 */
const char *OH_CryptoSymKeyGenerator_GetAlgoName(OH_CryptoSymKeyGenerator *ctx);

/**
 * @brief Destroys the symmetric key generator.
 * @param ctx [in] Symmetric key generator.
 * @since 12
 */
void OH_CryptoSymKeyGenerator_Destroy(OH_CryptoSymKeyGenerator *ctx);

/**
 * @brief Obtains the symmetric key algorithm name from the symmetric key.
 * @param keyCtx [in] Symmetric key. Cannot be NULL.
 * @return Returns the algorithm name. No need to free by the caller. Invalid after the key is destroyed.
 * @since 12
 */
const char *OH_CryptoSymKey_GetAlgoName(OH_CryptoSymKey *keyCtx);

/**
 * @brief Obtains the symmetric key data from the symmetric key.
 * @param keyCtx [in] Symmetric key. Cannot be NULL.
 * @param out [out] Pointer to the Crypto_DataBlob structure for storing the key data. Cannot be NULL.
 *     Initialize out to {0} before calling. Do not pre-allocate out->data.
 * @return <ul>
 *         <li>{@link OH_Crypto_ErrCode#CRYPTO_SUCCESS} if the operation succeeds.</li>
 *         <li>{@link OH_Crypto_ErrCode#CRYPTO_INVALID_PARAMS} if keyCtx or out is NULL.</li>
 *         <li>{@link OH_Crypto_ErrCode#CRYPTO_NOT_SUPPORTED} if unsupported operation or algorithm.</li>
 *         <li>{@link OH_Crypto_ErrCode#CRYPTO_MEMORY_ERROR} if memory operation fails.</li>
 *         <li>{@link OH_Crypto_ErrCode#CRYPTO_OPERTION_ERROR} if crypto operation fails.</li>
 *         </ul>
 * @release crypto_common/OH_Crypto_FreeDataBlob {out}
 * @since 12
 */
OH_Crypto_ErrCode OH_CryptoSymKey_GetKeyData(OH_CryptoSymKey *keyCtx, Crypto_DataBlob *out);

/**
 * @brief Destroys the symmetric key.
 * @param keyCtx [in] Symmetric key.
 * @since 12
 */
void OH_CryptoSymKey_Destroy(OH_CryptoSymKey *keyCtx);

#ifdef __cplusplus
}
#endif

#endif /* CRYPTO_SYM_KEY_H */
/** @} */
