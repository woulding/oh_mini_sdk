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
 * @addtogroup CryptoRandApi
 * @{
 * @brief Describes the random number generation interfaces provided by OpenHarmony for applications.
 * @since 20
 */

/**
 * @file crypto_rand.h
 * @brief Defines the random number generator interfaces.
 * @syscap SystemCapability.Security.CryptoFramework
 * @library libohcrypto.so
 * @kit CryptoArchitectureKit
 * @since 20
 */

#ifndef CRYPTO_RAND_H
#define CRYPTO_RAND_H

#include "crypto_common.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief Random number generator structure, representing a random number generator context.
 * @since 20
 */
typedef struct OH_CryptoRand OH_CryptoRand;

/**
 * @brief Creates a random number generator context.
 * @param ctx [out] Pointer to the random number generator context pointer. ctx cannot be NULL, *ctx must be NULL.
 * @return <ul>
 *         <li>{@link OH_Crypto_ErrCode#CRYPTO_SUCCESS} if the operation succeeds.</li>
 *         <li>{@link OH_Crypto_ErrCode#CRYPTO_PARAMETER_CHECK_FAILED} if ctx is NULL.</li>
 *         <li>{@link OH_Crypto_ErrCode#CRYPTO_NOT_SUPPORTED} if unsupported operation or algorithm.</li>
 *         <li>{@link OH_Crypto_ErrCode#CRYPTO_MEMORY_ERROR} if memory operation fails.</li>
 *         <li>{@link OH_Crypto_ErrCode#CRYPTO_OPERTION_ERROR} if crypto operation fails.</li>
 *         </ul>
 * @release crypto_rand/OH_CryptoRand_Destroy {ctx}
 * @since 20
 */
OH_Crypto_ErrCode OH_CryptoRand_Create(OH_CryptoRand **ctx);

/**
 * @brief Generates random numbers.
 * @param ctx [in] Random number generator context. Cannot be NULL.
 * @param len [in] Byte length of the random number.
 * @param out [out] Pointer to the Crypto_DataBlob structure for storing the random number. Cannot be NULL. Initialize
 *     out to {0} before calling. Do not pre-allocate out->data.
 * @return <ul>
 *         <li>{@link OH_Crypto_ErrCode#CRYPTO_SUCCESS} if the operation succeeds.</li>
 *         <li>{@link OH_Crypto_ErrCode#CRYPTO_PARAMETER_CHECK_FAILED} if ctx or out is NULL, or len is less than
 *            or equal to 0.</li>
 *         <li>{@link OH_Crypto_ErrCode#CRYPTO_NOT_SUPPORTED} if unsupported operation or algorithm.</li>
 *         <li>{@link OH_Crypto_ErrCode#CRYPTO_MEMORY_ERROR} if memory operation fails.</li>
 *         <li>{@link OH_Crypto_ErrCode#CRYPTO_OPERTION_ERROR} if crypto operation fails.</li>
 *         </ul>
 * @release crypto_common/OH_Crypto_FreeDataBlob {out}
 * @since 20
 */
OH_Crypto_ErrCode OH_CryptoRand_GenerateRandom(OH_CryptoRand *ctx, int len, Crypto_DataBlob *out);

/**
 * @brief Obtains the algorithm name of the random number generator.
 * @param ctx [in] Random number generator context. Cannot be NULL.
 * @return Returns the random number generator algorithm name. No need to free by the caller. Invalid after the context
 *     is destroyed.
 * @since 20
 */
const char *OH_CryptoRand_GetAlgoName(OH_CryptoRand *ctx);

/**
 * @brief Sets the seed for the random number generator.
 * @param ctx [in] Random number generator context. Cannot be NULL.
 * @param seed [in] Seed data. This function performs a deep copy of the data in seed. The caller can
 *     release seed immediately after the function returns. Cannot be NULL.
 * @return <ul>
 *         <li>{@link OH_Crypto_ErrCode#CRYPTO_SUCCESS} if the operation succeeds.</li>
 *         <li>{@link OH_Crypto_ErrCode#CRYPTO_PARAMETER_CHECK_FAILED} if ctx is NULL, or seed is invalid
 *            (seed is NULL, seed->data is NULL, seed->len is 0, or seed->len exceeds INT_MAX).</li>
 *         <li>{@link OH_Crypto_ErrCode#CRYPTO_NOT_SUPPORTED} if unsupported operation or algorithm.</li>
 *         <li>{@link OH_Crypto_ErrCode#CRYPTO_MEMORY_ERROR} if memory operation fails.</li>
 *         <li>{@link OH_Crypto_ErrCode#CRYPTO_OPERTION_ERROR} if crypto operation fails.</li>
 *         </ul>
 * @since 20
 */
OH_Crypto_ErrCode OH_CryptoRand_SetSeed(OH_CryptoRand *ctx, Crypto_DataBlob *seed);

/**
 * @brief Enables hardware entropy source.
 * @param ctx [in] Random number generator context. Cannot be NULL.
 * @return <ul>
 *         <li>{@link OH_Crypto_ErrCode#CRYPTO_SUCCESS} if the operation succeeds.</li>
 *         <li>{@link OH_Crypto_ErrCode#CRYPTO_PARAMETER_CHECK_FAILED} if ctx is NULL.</li>
 *         <li>{@link OH_Crypto_ErrCode#CRYPTO_NOT_SUPPORTED} if unsupported operation or algorithm.</li>
 *         <li>{@link OH_Crypto_ErrCode#CRYPTO_MEMORY_ERROR} if memory operation fails.</li>
 *         <li>{@link OH_Crypto_ErrCode#CRYPTO_OPERTION_ERROR} if crypto operation fails.</li>
 *         </ul>
 * @since 21
 */
OH_Crypto_ErrCode OH_CryptoRand_EnableHardwareEntropy(OH_CryptoRand *ctx);

/**
 * @brief Destroys the random number generator context.
 * @param ctx [in] Random number generator context.
 * @since 20
 */
void OH_CryptoRand_Destroy(OH_CryptoRand *ctx);

#ifdef __cplusplus
}
#endif

#endif /* CRYPTO_RAND_H */
/** @} */
