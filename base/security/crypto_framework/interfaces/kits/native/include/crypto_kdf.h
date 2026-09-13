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
 * @addtogroup CryptoKdfApi
 * @{
 * @brief Describes the key derivation function (KDF) interfaces provided by OpenHarmony for applications.
 * @since 20
 */

/**
 * @file crypto_kdf.h
 * @brief Defines the key derivation interfaces.
 * @syscap SystemCapability.Security.CryptoFramework
 * @library libohcrypto.so
 * @kit CryptoArchitectureKit
 * @since 20
 */

#ifndef CRYPTO_KDF_H
#define CRYPTO_KDF_H

#include "crypto_common.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief KDF structure, representing a KDF context.
 * @since 20
 */
typedef struct OH_CryptoKdf OH_CryptoKdf;

/**
 * @brief KDF parameters structure, representing KDF parameters.
 * @since 20
 */
typedef struct OH_CryptoKdfParams OH_CryptoKdfParams;

/**
 * @brief Defines KDF parameter types.
 * @since 20
 */
typedef enum {
    /**
     * @brief Key or password for KDF.
     * @since 20
     */
    CRYPTO_KDF_KEY_DATABLOB = 0,

    /**
     * @brief Salt value for KDF.
     * @since 20
     */
    CRYPTO_KDF_SALT_DATABLOB = 1,

    /**
     * @brief Info for KDF.
     * @since 20
     */
    CRYPTO_KDF_INFO_DATABLOB = 2,

    /**
     * @brief Iteration count for PBKDF2.
     * @since 20
     */
    CRYPTO_KDF_ITER_COUNT_INT = 3,

    /**
     * @brief n parameter for SCRYPT KDF.
     * @since 20
     */
    CRYPTO_KDF_SCRYPT_N_UINT64 = 4,

    /**
     * @brief r parameter for SCRYPT KDF.
     * @since 20
     */
    CRYPTO_KDF_SCRYPT_R_UINT64 = 5,

    /**
     * @brief p parameter for SCRYPT KDF.
     * @since 20
     */
    CRYPTO_KDF_SCRYPT_P_UINT64 = 6,

    /**
     * @brief Maximum memory parameter for SCRYPT KDF.
     * @since 20
     */
    CRYPTO_KDF_SCRYPT_MAX_MEM_UINT64 = 7,
} CryptoKdf_ParamType;

/**
 * @brief Creates KDF parameters.
 * @param algoName [in] KDF parameter algorithm name. Cannot be NULL. Values:
 *     - "HKDF", "PBKDF2", "SCRYPT" supported since API version 20.
 *     - "X963KDF" supported since API version 22.
 * @param params [out] Pointer to the KDF parameters pointer. params cannot be NULL, *params must be NULL.
 * @return <ul>
 *         <li>{@link OH_Crypto_ErrCode#CRYPTO_SUCCESS} if the operation succeeds.</li>
 *         <li>{@link OH_Crypto_ErrCode#CRYPTO_PARAMETER_CHECK_FAILED} if algoName or params is NULL,
 *             algoName is not a supported KDF type.</li>
 *         <li>{@link OH_Crypto_ErrCode#CRYPTO_NOT_SUPPORTED} if unsupported operation or algorithm.</li>
 *         <li>{@link OH_Crypto_ErrCode#CRYPTO_MEMORY_ERROR} if memory allocation fails.</li>
 *         <li>{@link OH_Crypto_ErrCode#CRYPTO_OPERTION_ERROR} if crypto operation fails.</li>
 *         </ul>
 * @release crypto_kdf/OH_CryptoKdfParams_Destroy {params}
 * @since 20
 * @see {@link OH_CryptoKdfParams_SetParam} Sets KDF parameters.
 */
OH_Crypto_ErrCode OH_CryptoKdfParams_Create(const char *algoName, OH_CryptoKdfParams **params);

/**
 * @brief Sets KDF parameters.
 * @param params [in] KDF parameters. Cannot be NULL.
 * @param type [in] KDF parameter type.
 * @param value [in] KDF parameter value. This function performs a deep copy of the data in value.
 *     The caller can release value immediately after the function returns. Cannot be NULL.
 * @return <ul>
 *         <li>{@link OH_Crypto_ErrCode#CRYPTO_SUCCESS} if the operation succeeds.</li>
 *         <li>{@link OH_Crypto_ErrCode#CRYPTO_PARAMETER_CHECK_FAILED} if params or value is NULL,
 *            value->data is NULL, or type is not valid for the KDF algorithm.</li>
 *         <li>{@link OH_Crypto_ErrCode#CRYPTO_NOT_SUPPORTED} if unsupported operation or algorithm.</li>
 *         <li>{@link OH_Crypto_ErrCode#CRYPTO_MEMORY_ERROR} if memory allocation for param copy fails.</li>
 *         <li>{@link OH_Crypto_ErrCode#CRYPTO_OPERTION_ERROR} if crypto operation fails.</li>
 *         </ul>
 * @since 20
 */
OH_Crypto_ErrCode OH_CryptoKdfParams_SetParam(OH_CryptoKdfParams *params, CryptoKdf_ParamType type,
    Crypto_DataBlob *value);

/**
 * @brief Destroys KDF parameters.
 * @param params [in] KDF parameters.
 * @since 20
 */
void OH_CryptoKdfParams_Destroy(OH_CryptoKdfParams *params);

/**
 * @brief Creates a KDF context based on the given algorithm name.
 * @param algoName [in] KDF algorithm name. Cannot be NULL. Format: "KDFType|DigestAlgorithm". Values:
 *     - "PBKDF2|SHA1", "PBKDF2|SHA224", "PBKDF2|SHA256", "PBKDF2|SHA384", "PBKDF2|SHA512",
 *     "PBKDF2|SM3" supported since API version 20.
 *     "PBKDF2|SHA3-256", "PBKDF2|SHA3-384", "PBKDF2|SHA3-512" supported since API version 26.0.0.
 *     - "HKDF|SHA1", "HKDF|SHA224", "HKDF|SHA256", "HKDF|SHA384", "HKDF|SHA512", "HKDF|SM3"
 *     supported since API version 20. HKDF supports an optional third parameter to specify the mode:
 *     "EXTRACT_AND_EXPAND" (default), "EXTRACT_ONLY", "EXPAND_ONLY", e.g. "HKDF|SHA256|EXTRACT_ONLY".
 *     "HKDF|SHA3-256", "HKDF|SHA3-384", "HKDF|SHA3-512" supported since API version 26.0.0.
 *     - "SCRYPT" supported since API version 20.
 *     - "X963KDF|SHA1", "X963KDF|SHA224", "X963KDF|SHA256", "X963KDF|SHA384", "X963KDF|SHA512"
 *     supported since API version 22.
 *     "X963KDF|SHA3-256", "X963KDF|SHA3-384", "X963KDF|SHA3-512" supported since API version 26.0.0.
 * @param ctx [out] Pointer to the KDF context pointer. ctx cannot be NULL, *ctx must be NULL.
 * @return <ul>
 *         <li>{@link OH_Crypto_ErrCode#CRYPTO_SUCCESS} if the operation succeeds.</li>
 *         <li>{@link OH_Crypto_ErrCode#CRYPTO_PARAMETER_CHECK_FAILED} if algoName or ctx is NULL.</li>
 *         <li>{@link OH_Crypto_ErrCode#CRYPTO_NOT_SUPPORTED} if the algorithm is not supported.</li>
 *         <li>{@link OH_Crypto_ErrCode#CRYPTO_MEMORY_ERROR} if memory allocation fails.</li>
 *         <li>{@link OH_Crypto_ErrCode#CRYPTO_OPERTION_ERROR} if crypto operation fails.</li>
 *         </ul>
 * @release crypto_kdf/OH_CryptoKdf_Destroy {ctx}
 * @since 20
 * @see {@link OH_CryptoKdf_Derive} Derives a key.
 */
OH_Crypto_ErrCode OH_CryptoKdf_Create(const char *algoName, OH_CryptoKdf **ctx);

/**
 * @brief Derives a key.
 * @param ctx [in] KDF context. Cannot be NULL.
 * @param params [in] KDF parameters. Cannot be NULL.
 * @param keyLen [in] Byte length of the derived key.
 * @param key [out] Pointer to the Crypto_DataBlob structure for storing the derived key. Cannot be NULL. Initialize key
 *     to {0} before calling. Do not pre-allocate key->data.
 * @return <ul>
 *         <li>{@link OH_Crypto_ErrCode#CRYPTO_SUCCESS} if the operation succeeds.</li>
 *         <li>{@link OH_Crypto_ErrCode#CRYPTO_PARAMETER_CHECK_FAILED} if ctx, params, or key is NULL,
 *            or keyLen is less than or equal to 0, or required
 *            parameters are missing (e.g. HKDF key, Scrypt password or salt).</li>
 *         <li>{@link OH_Crypto_ErrCode#CRYPTO_NOT_SUPPORTED} if the algorithm is not supported.</li>
 *         <li>{@link OH_Crypto_ErrCode#CRYPTO_MEMORY_ERROR} if memory allocation fails.</li>
 *         <li>{@link OH_Crypto_ErrCode#CRYPTO_OPERTION_ERROR} if the key derivation fails.</li>
 *         </ul>
 * @release crypto_common/OH_Crypto_FreeDataBlob {key}
 * @since 20
 */
OH_Crypto_ErrCode OH_CryptoKdf_Derive(OH_CryptoKdf *ctx, const OH_CryptoKdfParams *params, int keyLen,
    Crypto_DataBlob *key);

/**
 * @brief Destroys the KDF context.
 * @param ctx [in] KDF context.
 * @since 20
 */
void OH_CryptoKdf_Destroy(OH_CryptoKdf *ctx);

#ifdef __cplusplus
}
#endif

#endif /* CRYPTO_KDF_H */
/** @} */
