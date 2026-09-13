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
 * @addtogroup CryptoMacApi
 * @{
 * @brief Describes the message authentication code (MAC) interfaces provided by OpenHarmony
 *     for applications.
 * @since 20
 */

/**
 * @file crypto_mac.h
 * @brief Defines the message authentication code interfaces.
 * @syscap SystemCapability.Security.CryptoFramework
 * @library libohcrypto.so
 * @kit CryptoArchitectureKit
 * @since 20
 */

#ifndef CRYPTO_MAC_H
#define CRYPTO_MAC_H

#include "crypto_common.h"
#include "crypto_sym_key.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief MAC structure, representing a MAC context.
 * @since 20
 */
typedef struct OH_CryptoMac OH_CryptoMac;

/**
 * @brief Defines MAC algorithm parameter types.
 * @since 20
 */
typedef enum {
    /**
     * @brief Algorithm name of the message digest function for HMAC, set via {@link OH_CryptoMac_SetParam}.
     * Values: "SHA1", "SHA224", "SHA256", "SHA384", "SHA512", "SM3", "MD5".
     * "SHA3-256", "SHA3-384", "SHA3-512" are supported since API version 26.0.0.
     * @since 20
     */
    CRYPTO_MAC_DIGEST_NAME_STR = 0,

    /**
     * @brief Algorithm name of the symmetric cipher function for CMAC, set via
     * {@link OH_CryptoMac_SetParam}.
     * Values: "AES128", "AES256".
     * @since 20
     */
    CRYPTO_MAC_CIPHER_NAME_STR = 1,
} CryptoMac_ParamType;

/**
 * @brief Creates a MAC context based on the given algorithm name.
 * @param algoName [in] MAC algorithm name. Cannot be NULL. Supports "HMAC" and "CMAC".
 * @param ctx [out] Pointer to the MAC context pointer. ctx cannot be NULL, *ctx must be NULL.
 * @return <ul>
 *         <li>{@link OH_Crypto_ErrCode#CRYPTO_SUCCESS} if the operation succeeds.</li>
 *         <li>{@link OH_Crypto_ErrCode#CRYPTO_PARAMETER_CHECK_FAILED} if algoName or ctx is NULL,
 *             algoName is not "HMAC" or "CMAC".</li>
 *         <li>{@link OH_Crypto_ErrCode#CRYPTO_NOT_SUPPORTED} if unsupported operation or algorithm.</li>
 *         <li>{@link OH_Crypto_ErrCode#CRYPTO_MEMORY_ERROR} if memory operation fails.</li>
 *         <li>{@link OH_Crypto_ErrCode#CRYPTO_OPERTION_ERROR} if crypto operation fails.</li>
 *         </ul>
 * @release crypto_mac/OH_CryptoMac_Destroy {ctx}
 * @since 20
 * @see {@link OH_CryptoMac_SetParam} Sets the specified parameter of the MAC context.
 */
OH_Crypto_ErrCode OH_CryptoMac_Create(const char *algoName, OH_CryptoMac **ctx);

/**
 * @brief Sets the specified parameter of the MAC context.
 * @param ctx [in] MAC context. Cannot be NULL.
 * @param type [in] MAC parameter type.
 * @param value [in] Parameter value. This function performs a deep copy of the data in value. The
 *     caller can release value immediately after the function returns. Cannot be NULL.
 * @return <ul>
 *         <li>{@link OH_Crypto_ErrCode#CRYPTO_SUCCESS} if the operation succeeds.</li>
 *         <li>{@link OH_Crypto_ErrCode#CRYPTO_PARAMETER_CHECK_FAILED} if ctx, value, or
 *            value->data is NULL, type is not valid for the MAC algorithm,
 *            or the digest/cipher algorithm name is not supported.</li>
 *         <li>{@link OH_Crypto_ErrCode#CRYPTO_NOT_SUPPORTED} if unsupported operation or algorithm.</li>
 *         <li>{@link OH_Crypto_ErrCode#CRYPTO_MEMORY_ERROR} if memory allocation for param copy fails.</li>
 *         <li>{@link OH_Crypto_ErrCode#CRYPTO_OPERTION_ERROR} if crypto operation fails.</li>
 *         </ul>
 * @since 20
 * @see {@link OH_CryptoMac_Init} Initializes the MAC context with a symmetric key.
 */
OH_Crypto_ErrCode OH_CryptoMac_SetParam(OH_CryptoMac *ctx, CryptoMac_ParamType type, const Crypto_DataBlob *value);

/**
 * @brief Initializes the MAC context with a symmetric key.
 * @param ctx [in] MAC context. Cannot be NULL.
 * @param key [in] Symmetric key. Cannot be NULL.
 * @return <ul>
 *         <li>{@link OH_Crypto_ErrCode#CRYPTO_SUCCESS} if the operation succeeds.</li>
 *         <li>{@link OH_Crypto_ErrCode#CRYPTO_PARAMETER_CHECK_FAILED} if ctx or key is NULL.</li>
 *         <li>{@link OH_Crypto_ErrCode#CRYPTO_NOT_SUPPORTED} if unsupported operation or algorithm.</li>
 *         <li>{@link OH_Crypto_ErrCode#CRYPTO_MEMORY_ERROR} if memory operation fails.</li>
 *         <li>{@link OH_Crypto_ErrCode#CRYPTO_OPERTION_ERROR} if MAC init fails. Possible causes:
 *            the key length does not match the algorithm (e.g. CMAC with AES-128 requires a 16-byte key).</li>
 *         </ul>
 * @since 20
 * @see {@link OH_CryptoMac_Update} Updates MAC data.
 */
OH_Crypto_ErrCode OH_CryptoMac_Init(OH_CryptoMac *ctx, const OH_CryptoSymKey *key);

/**
 * @brief Updates MAC data.
 * @param ctx [in] MAC context. Cannot be NULL.
 * @param in [in] Data to update. Cannot be NULL.
 * @return <ul>
 *         <li>{@link OH_Crypto_ErrCode#CRYPTO_SUCCESS} if the operation succeeds.</li>
 *         <li>{@link OH_Crypto_ErrCode#CRYPTO_PARAMETER_CHECK_FAILED} if ctx or in is NULL.</li>
 *         <li>{@link OH_Crypto_ErrCode#CRYPTO_NOT_SUPPORTED} if unsupported operation or algorithm.</li>
 *         <li>{@link OH_Crypto_ErrCode#CRYPTO_MEMORY_ERROR} if memory operation fails.</li>
 *         <li>{@link OH_Crypto_ErrCode#CRYPTO_OPERTION_ERROR} if MAC update fails.</li>
 *         </ul>
 * @since 20
 * @see {@link OH_CryptoMac_Final} Finishes the MAC operation.
 */
OH_Crypto_ErrCode OH_CryptoMac_Update(OH_CryptoMac *ctx, const Crypto_DataBlob *in);

/**
 * @brief Finishes the MAC operation.
 * @param ctx [in] MAC context. Cannot be NULL.
 * @param out [out] Pointer to the Crypto_DataBlob structure for storing the MAC result. Cannot be NULL.
 *     Initialize out to {0} before calling. Do not pre-allocate out->data.
 * @return <ul>
 *         <li>{@link OH_Crypto_ErrCode#CRYPTO_SUCCESS} if the operation succeeds.</li>
 *         <li>{@link OH_Crypto_ErrCode#CRYPTO_PARAMETER_CHECK_FAILED} if ctx or out is NULL.</li>
 *         <li>{@link OH_Crypto_ErrCode#CRYPTO_NOT_SUPPORTED} if unsupported operation or algorithm.</li>
 *         <li>{@link OH_Crypto_ErrCode#CRYPTO_MEMORY_ERROR} if memory operation fails.</li>
 *         <li>{@link OH_Crypto_ErrCode#CRYPTO_OPERTION_ERROR} if MAC final fails.</li>
 *         </ul>
 * @release crypto_common/OH_Crypto_FreeDataBlob {out}
 * @since 20
 */
OH_Crypto_ErrCode OH_CryptoMac_Final(OH_CryptoMac *ctx, Crypto_DataBlob *out);

/**
 * @brief Obtains the MAC result length.
 * @param ctx [in] MAC context. Cannot be NULL.
 * @param length [out] MAC length in bytes. Cannot be NULL. Memory allocated by the caller.
 * @return <ul>
 *         <li>{@link OH_Crypto_ErrCode#CRYPTO_SUCCESS} if the operation succeeds.</li>
 *         <li>{@link OH_Crypto_ErrCode#CRYPTO_PARAMETER_CHECK_FAILED} if ctx or length is NULL.</li>
 *         <li>{@link OH_Crypto_ErrCode#CRYPTO_NOT_SUPPORTED} if unsupported operation or algorithm.</li>
 *         <li>{@link OH_Crypto_ErrCode#CRYPTO_MEMORY_ERROR} if memory operation fails.</li>
 *         <li>{@link OH_Crypto_ErrCode#CRYPTO_OPERTION_ERROR} if crypto operation fails.</li>
 *         </ul>
 * @since 20
 */
OH_Crypto_ErrCode OH_CryptoMac_GetLength(OH_CryptoMac *ctx, uint32_t *length);

/**
 * @brief Destroys the MAC context.
 * @param ctx [in] MAC context.
 * @since 20
 */
void OH_CryptoMac_Destroy(OH_CryptoMac *ctx);

#ifdef __cplusplus
}
#endif

#endif /* CRYPTO_MAC_H */
/** @} */
