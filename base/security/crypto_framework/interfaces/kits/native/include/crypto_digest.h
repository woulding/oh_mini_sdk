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
 * @addtogroup CryptoDigestApi
 * @{
 * @brief Describes the digest algorithm interfaces provided by OpenHarmony for applications.
 * @since 12
 */

/**
 * @file crypto_digest.h
 * @brief Defines the digest algorithm interfaces.
 * @syscap SystemCapability.Security.CryptoFramework
 * @library libohcrypto.so
 * @kit CryptoArchitectureKit
 * @since 12
 */

#ifndef CRYPTO_DIGEST_H
#define CRYPTO_DIGEST_H

#include "crypto_common.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief Digest structure, representing a digest context.
 * @since 12
 */
typedef struct OH_CryptoDigest OH_CryptoDigest;

/**
 * @brief Creates a digest context based on the given algorithm name.
 * @param algoName [in] Digest algorithm name. Cannot be NULL. Values:
 *     - "SHA1", "SHA224", "SHA256", "SHA384", "SHA512", "MD5", "SM3" supported since API version 12.
 *     - "SHA3-256", "SHA3-384", "SHA3-512" supported since API version 22.
 * @param ctx [out] Pointer to the digest context pointer. ctx cannot be NULL, *ctx must be NULL.
 * @return <ul>
 *         <li>{@link OH_Crypto_ErrCode#CRYPTO_SUCCESS} if the operation succeeds.</li>
 *         <li>{@link OH_Crypto_ErrCode#CRYPTO_INVALID_PARAMS} if ctx is NULL, algoName is NULL,
 *             algoName is not a supported digest algorithm name.</li>
 *         <li>{@link OH_Crypto_ErrCode#CRYPTO_NOT_SUPPORTED} if unsupported operation or algorithm.</li>
 *         <li>{@link OH_Crypto_ErrCode#CRYPTO_MEMORY_ERROR} if memory allocation fails.</li>
 *         <li>{@link OH_Crypto_ErrCode#CRYPTO_OPERTION_ERROR} if the digest operation fails.</li>
 *         </ul>
 * @release crypto_digest/OH_DigestCrypto_Destroy {ctx}
 * @since 12
 * @see {@link OH_CryptoDigest_Update} Updates digest data.
 */
OH_Crypto_ErrCode OH_CryptoDigest_Create(const char *algoName, OH_CryptoDigest **ctx);

/**
 * @brief Updates digest data.
 * @param ctx [in] Digest context. Cannot be NULL.
 * @param in [in] Data to be digested. Cannot be NULL.
 * @return <ul>
 *         <li>{@link OH_Crypto_ErrCode#CRYPTO_SUCCESS} if the operation succeeds.</li>
 *         <li>{@link OH_Crypto_ErrCode#CRYPTO_INVALID_PARAMS} if ctx or in is NULL.</li>
 *         <li>{@link OH_Crypto_ErrCode#CRYPTO_NOT_SUPPORTED} if unsupported operation or algorithm.</li>
 *         <li>{@link OH_Crypto_ErrCode#CRYPTO_MEMORY_ERROR} if memory operation fails.</li>
 *         <li>{@link OH_Crypto_ErrCode#CRYPTO_OPERTION_ERROR} if the digest update fails.</li>
 *         </ul>
 * @since 12
 * @see {@link OH_CryptoDigest_Final} Finishes the digest operation and outputs the result.
 */
OH_Crypto_ErrCode OH_CryptoDigest_Update(OH_CryptoDigest *ctx, Crypto_DataBlob *in);

/**
 * @brief Finishes the digest operation and outputs the result.
 * @param ctx [in] Digest context. Cannot be NULL.
 * @param out [out] Pointer to the Crypto_DataBlob structure for storing the digest result. Cannot be NULL. Initialize
 *     out to {0} before calling. Do not pre-allocate out->data.
 * @return <ul>
 *         <li>{@link OH_Crypto_ErrCode#CRYPTO_SUCCESS} if the operation succeeds.</li>
 *         <li>{@link OH_Crypto_ErrCode#CRYPTO_INVALID_PARAMS} if ctx or out is NULL.</li>
 *         <li>{@link OH_Crypto_ErrCode#CRYPTO_NOT_SUPPORTED} if unsupported operation or algorithm.</li>
 *         <li>{@link OH_Crypto_ErrCode#CRYPTO_MEMORY_ERROR} if memory operation fails.</li>
 *         <li>{@link OH_Crypto_ErrCode#CRYPTO_OPERTION_ERROR} if the digest final operation fails.</li>
 *         </ul>
 * @release crypto_common/OH_Crypto_FreeDataBlob {out}
 * @since 12
 */
OH_Crypto_ErrCode OH_CryptoDigest_Final(OH_CryptoDigest *ctx, Crypto_DataBlob *out);

/**
 * @brief Obtains the length of the digest result.
 * @param ctx [in] Digest context. Cannot be NULL.
 * @return Returns the byte length of the digest result. Note: If ctx is NULL, returns 401; for other failure cases,
 *     returns 0.
 * @since 12
 */
uint32_t OH_CryptoDigest_GetLength(OH_CryptoDigest *ctx);

/**
 * @brief Obtains the algorithm name of the digest context.
 * @param ctx [in] Digest context. Cannot be NULL.
 * @return Returns the digest algorithm name. No need to free by the caller. Invalid after the context is destroyed.
 * @since 12
 */
const char *OH_CryptoDigest_GetAlgoName(OH_CryptoDigest *ctx);

/**
 * @brief Destroys the digest context.
 * @param ctx [in] Digest context.
 * @since 12
 */
void OH_DigestCrypto_Destroy(OH_CryptoDigest *ctx);

#ifdef __cplusplus
}
#endif

#endif /* CRYPTO_DIGEST_H */
/** @} */
