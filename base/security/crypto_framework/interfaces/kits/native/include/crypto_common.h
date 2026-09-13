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
 * @addtogroup CryptoCommonApi
 * @{
 * @brief Describes the common crypto interfaces provided by OpenHarmony for applications.
 * @since 12
 */

/**
 * @file crypto_common.h
 * @brief Defines common data structures and error codes for crypto operations.
 * @syscap SystemCapability.Security.CryptoFramework
 * @library libohcrypto.so
 * @kit CryptoArchitectureKit
 * @since 12
 */

#ifndef CRYPTO_COMMON_H
#define CRYPTO_COMMON_H

#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief Crypto data structure.
 * @since 12
 */
typedef struct Crypto_DataBlob {
    /**
     * @brief Data buffer.
     * @since 12
     */
    uint8_t *data;
    /**
     * @brief Data length.
     * @since 12
     */
    size_t len;
} Crypto_DataBlob;

/**
 * @brief Enumerates the error codes.
 * @since 12
 */
typedef enum {
    /**
     * @brief Operation succeeded.
     * @since 12
     */
    CRYPTO_SUCCESS = 0,
    /**
     * @brief Invalid input parameters.
     * @since 12
     */
    CRYPTO_INVALID_PARAMS = 401,
    /**
     * @brief Unsupported feature or algorithm.
     * @since 12
     */
    CRYPTO_NOT_SUPPORTED = 801,
    /**
     * @brief Memory operation failed.
     * @since 12
     */
    CRYPTO_MEMORY_ERROR = 17620001,
    /**
     * @brief Parameter check failed.
     * @since 20
     */
    CRYPTO_PARAMETER_CHECK_FAILED = 17620003,
    /**
     * @brief Invalid function call.
     * @since 26.0.0
     */
    CRYPTO_INVALID_CALL = 17620004,
    /**
     * @brief Crypto operation error.
     * @since 12
     */
    CRYPTO_OPERTION_ERROR = 17630001,
} OH_Crypto_ErrCode;

/**
 * @brief Defines the cipher mode.
 * @since 12
 */
typedef enum {
    /**
     * @brief Encryption operation.
     * @since 12
     */
    CRYPTO_ENCRYPT_MODE = 0,
    /**
     * @brief Decryption operation.
     * @since 12
     */
    CRYPTO_DECRYPT_MODE = 1,
} Crypto_CipherMode;

/**
 * @brief Frees the memory of a data blob.
 * @param dataBlob [in] Data blob to free.
 * @since 12
 */
void OH_Crypto_FreeDataBlob(Crypto_DataBlob *dataBlob);

#ifdef __cplusplus
}
#endif

#endif /* CRYPTO_COMMON_H */
/** @} */
