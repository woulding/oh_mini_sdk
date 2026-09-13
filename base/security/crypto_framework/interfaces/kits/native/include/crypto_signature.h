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
 * @addtogroup CryptoSignatureApi
 * @{
 * @brief Describes the signing and verification interfaces provided by OpenHarmony for applications.
 * @since 12
 */

/**
 * @file crypto_signature.h
 * @brief Defines the signing and verification interfaces.
 * @syscap SystemCapability.Security.CryptoFramework
 * @library libohcrypto.so
 * @kit CryptoArchitectureKit
 * @since 12
 */

#ifndef CRYPTO_SIGNATURE_H
#define CRYPTO_SIGNATURE_H

#include "crypto_common.h"
#include "crypto_asym_key.h"
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief Defines signature parameter types.
 * @since 12
 */
typedef enum {
    /**
     * @brief Algorithm name of the message digest function.
     * @since 12
     */
    CRYPTO_PSS_MD_NAME_STR = 100,
    /**
     * @brief Algorithm name of the mask generation function.
     * @since 12
     */
    CRYPTO_PSS_MGF_NAME_STR = 101,
    /**
     * @brief Message digest parameter of the MGF1 mask generation function.
     * @since 12
     */
    CRYPTO_PSS_MGF1_NAME_STR = 102,
    /**
     * @brief Byte length of the salt value.
     * @since 12
     */
    CRYPTO_PSS_SALT_LEN_INT = 103,
    /**
     * @brief Value of the trailer field.
     * @since 12
     */
    CRYPTO_PSS_TRAILER_FIELD_INT = 104,
    /**
     * @brief User ID value for the SM2 algorithm.
     * @since 12
     */
    CRYPTO_SM2_USER_ID_DATABLOB = 105,
} CryptoSignature_ParamType;

/**
 * @brief Verification structure, representing a verification context.
 * @since 12
 */
typedef struct OH_CryptoVerify OH_CryptoVerify;

/**
 * @brief Signing structure, representing a signing context.
 * @since 20
 */
typedef struct OH_CryptoSign OH_CryptoSign;

/**
 * @brief Creates a verification context based on the given algorithm name.
 * @param algoName [in] Verification algorithm name. Cannot be NULL. Values:
 *     - RSA PKCS1 mode: Format "RSA|PKCS1|Digest", e.g. "RSA|PKCS1|SHA256", "RSA|PKCS1|SHA512".
 *     Digest supports "MD5", "SHA1", "SHA224", "SHA256", "SHA384", "SHA512".
 *     - RSA PSS mode: Format "RSA|PSS|Digest|MGF1Digest", e.g. "RSA|PSS|SHA256|MGF1_SHA256".
 *     Digest supports "MD5", "SHA1", "SHA224", "SHA256", "SHA384", "SHA512".
 *     MGF1 digest supports "MGF1_MD5", "MGF1_SHA1", "MGF1_SHA224", "MGF1_SHA256", "MGF1_SHA384", "MGF1_SHA512".
 *     - RSA verify recovery: Format "RSA|PKCS1|Digest|Recover", e.g. "RSA|PKCS1|SHA256|Recover",
 *     "RSA|PKCS1|SHA512|Recover".
 *     Digest supports "NoHash", "MD5", "SHA1", "SHA224", "SHA256", "SHA384", "SHA512".
 *     - ECDSA algorithm: Format "ECC|Digest", e.g. "ECC|SHA256", "ECC|SHA384".
 *     Digest supports "SHA1", "SHA224", "SHA256", "SHA384", "SHA512".
 *     - DSA algorithm: Format "DSA|Digest", e.g. "DSA|SHA256", "DSA|SHA384".
 *     Digest supports "NoHash", "SHA1", "SHA224", "SHA256", "SHA384", "SHA512".
 *     - SM2 algorithm: "SM2|SM3".
 *     - Ed25519 algorithm: "Ed25519".
 * @param verify [out] Pointer to the verification context pointer. verify cannot be NULL,
 *     *verify must be NULL.
 * @return <ul>
 *         <li>{@link OH_Crypto_ErrCode#CRYPTO_SUCCESS} if the operation succeeds.</li>
 *         <li>{@link OH_Crypto_ErrCode#CRYPTO_INVALID_PARAMS} if verify or algoName is NULL.</li>
 *         <li>{@link OH_Crypto_ErrCode#CRYPTO_NOT_SUPPORTED} if the algorithm is not supported.</li>
 *         <li>{@link OH_Crypto_ErrCode#CRYPTO_MEMORY_ERROR} if memory allocation fails.</li>
 *         <li>{@link OH_Crypto_ErrCode#CRYPTO_OPERTION_ERROR} if crypto operation fails.</li>
 *         </ul>
 * @release crypto_signature/OH_CryptoVerify_Destroy {verify}
 * @since 12
 * @see {@link OH_CryptoVerify_Init} Initializes the verification context with the given public key.
 */
OH_Crypto_ErrCode OH_CryptoVerify_Create(const char *algoName, OH_CryptoVerify **verify);

/**
 * @brief Initializes the verification context with the given public key.
 * @param ctx [in] Verification context. Cannot be NULL.
 * @param pubKey [in] Public key. Cannot be NULL.
 * @return <ul>
 *         <li>{@link OH_Crypto_ErrCode#CRYPTO_SUCCESS} if the operation succeeds.</li>
 *         <li>{@link OH_Crypto_ErrCode#CRYPTO_INVALID_PARAMS} if ctx or pubKey is NULL, or the key
 *            type does not match the signature algorithm.</li>
 *         <li>{@link OH_Crypto_ErrCode#CRYPTO_NOT_SUPPORTED} if unsupported operation or algorithm.</li>
 *         <li>{@link OH_Crypto_ErrCode#CRYPTO_MEMORY_ERROR} if memory operation fails.</li>
 *         <li>{@link OH_Crypto_ErrCode#CRYPTO_OPERTION_ERROR} if verify init fails.</li>
 *         </ul>
 * @since 12
 * @see {@link OH_CryptoVerify_Update} Appends message data to be verified.
 * @see {@link OH_CryptoVerify_Final} Verifies message data.
 * @see {@link OH_CryptoVerify_Recover} Recovers signature data.
 */
OH_Crypto_ErrCode OH_CryptoVerify_Init(OH_CryptoVerify *ctx, OH_CryptoPubKey *pubKey);

/**
 * @brief Appends message data to be verified.
 * @param ctx [in] Verification context. Cannot be NULL.
 * @param in [in] Data to be verified. Cannot be NULL.
 * @return <ul>
 *         <li>{@link OH_Crypto_ErrCode#CRYPTO_SUCCESS} if the operation succeeds.</li>
 *         <li>{@link OH_Crypto_ErrCode#CRYPTO_INVALID_PARAMS} if ctx or in is NULL.</li>
 *         <li>{@link OH_Crypto_ErrCode#CRYPTO_NOT_SUPPORTED} if unsupported operation or algorithm.</li>
 *         <li>{@link OH_Crypto_ErrCode#CRYPTO_MEMORY_ERROR} if memory operation fails.</li>
 *         <li>{@link OH_Crypto_ErrCode#CRYPTO_INVALID_CALL} if the function call is invalid. [since 26.0.0]</li>
 *         <li>{@link OH_Crypto_ErrCode#CRYPTO_OPERTION_ERROR} if verify update fails.</li>
 *         </ul>
 * @since 12
 * @see {@link OH_CryptoVerify_Final} Verifies message data.
 */
OH_Crypto_ErrCode OH_CryptoVerify_Update(OH_CryptoVerify *ctx, Crypto_DataBlob *in);

/**
 * @brief Verifies message data.
 * @param ctx [in] Verification context. Cannot be NULL.
 * @param in [in] Data to be verified. Can be NULL if all data has been updated via {@link OH_CryptoVerify_Update}.
 * @param signData [in] Signature data. Cannot be NULL.
 * @return Returns the boolean verification result. Returns true if verification succeeds, false if verification fails.
 *     Possible causes: incorrect public key, corrupted signature data, mismatched hash algorithm,
 *     mismatched padding mode, or the data does not match the original signed data.
 * @since 12
 */
bool OH_CryptoVerify_Final(OH_CryptoVerify *ctx, Crypto_DataBlob *in, Crypto_DataBlob *signData);

/**
 * @brief Recovers signature data. Only RSA algorithm is supported.
 * @param ctx [in] Verification context. Cannot be NULL.
 * @param signData [in] Signature data. Cannot be NULL.
 * @param rawSignData [out] Pointer to the Crypto_DataBlob structure for storing the raw signature data. Cannot be NULL.
 *     Initialize rawSignData to {0} before calling. Do not pre-allocate rawSignData->data.
 * @return <ul>
 *         <li>{@link OH_Crypto_ErrCode#CRYPTO_SUCCESS} if the operation succeeds.</li>
 *         <li>{@link OH_Crypto_ErrCode#CRYPTO_INVALID_PARAMS} if ctx, signData, or rawSignData is NULL.</li>
 *         <li>{@link OH_Crypto_ErrCode#CRYPTO_NOT_SUPPORTED} if unsupported operation or algorithm.</li>
 *         <li>{@link OH_Crypto_ErrCode#CRYPTO_MEMORY_ERROR} if memory operation fails.</li>
 *         <li>{@link OH_Crypto_ErrCode#CRYPTO_INVALID_CALL} if the function call is invalid. [since 26.0.0]</li>
 *         <li>{@link OH_Crypto_ErrCode#CRYPTO_OPERTION_ERROR} if recover fails. Possible causes:
 *            signature data length does not match the RSA key modulus size.</li>
 *         </ul>
 * @release crypto_common/OH_Crypto_FreeDataBlob {rawSignData}
 * @since 12
 */
OH_Crypto_ErrCode OH_CryptoVerify_Recover(OH_CryptoVerify *ctx, Crypto_DataBlob *signData,
    Crypto_DataBlob *rawSignData);

/**
 * @brief Obtains the algorithm name of the verification context.
 * @param ctx [in] Verification context. Cannot be NULL.
 * @return Returns the verification algorithm name. No need to free by the caller. Invalid after the context is
 *     destroyed.
 * @since 12
 */
const char *OH_CryptoVerify_GetAlgoName(OH_CryptoVerify *ctx);

/**
 * @brief Sets the specified parameter of the verification context.
 * @param ctx [in] Verification context. Cannot be NULL.
 * @param type [in] Signature parameter type.
 * @param value [in] Input data. This function performs a deep copy of the data in value. The caller can release value
 *     immediately after the function returns. Cannot be NULL.
 * @return <ul>
 *         <li>{@link OH_Crypto_ErrCode#CRYPTO_SUCCESS} if the operation succeeds.</li>
 *         <li>{@link OH_Crypto_ErrCode#CRYPTO_INVALID_PARAMS} if ctx or value is NULL,
 *            value->data is NULL, value->len does not match the expected size for the
 *            type, or type is not a valid CryptoSignature_ParamType.</li>
 *         <li>{@link OH_Crypto_ErrCode#CRYPTO_NOT_SUPPORTED} if unsupported operation or algorithm.</li>
 *         <li>{@link OH_Crypto_ErrCode#CRYPTO_MEMORY_ERROR} if memory operation fails.</li>
 *         <li>{@link OH_Crypto_ErrCode#CRYPTO_OPERTION_ERROR} if setting parameter fails.</li>
 *         </ul>
 * @since 12
 */
OH_Crypto_ErrCode OH_CryptoVerify_SetParam(OH_CryptoVerify *ctx, CryptoSignature_ParamType type,
    Crypto_DataBlob *value);

/**
 * @brief Obtains the specified parameter of the verification context.
 * @param ctx [in] Verification context. Cannot be NULL.
 * @param type [in] Signature parameter type.
 * @param value [out] Pointer to the Crypto_DataBlob structure for storing the output data. Cannot be NULL.
 *     Initialize value to {0} before calling. Do not pre-allocate value->data.
 * @return <ul>
 *         <li>{@link OH_Crypto_ErrCode#CRYPTO_SUCCESS} if the operation succeeds.</li>
 *         <li>{@link OH_Crypto_ErrCode#CRYPTO_INVALID_PARAMS} if ctx or value is NULL, or type is
 *            not a valid CryptoSignature_ParamType.</li>
 *         <li>{@link OH_Crypto_ErrCode#CRYPTO_NOT_SUPPORTED} if unsupported operation or algorithm.</li>
 *         <li>{@link OH_Crypto_ErrCode#CRYPTO_MEMORY_ERROR} if memory allocation for the output fails.</li>
 *         <li>{@link OH_Crypto_ErrCode#CRYPTO_OPERTION_ERROR} if getting parameter fails.</li>
 *         </ul>
 * @release crypto_common/OH_Crypto_FreeDataBlob {value}
 * @since 12
 */
OH_Crypto_ErrCode OH_CryptoVerify_GetParam(OH_CryptoVerify *ctx, CryptoSignature_ParamType type,
    Crypto_DataBlob *value);

/**
 * @brief Destroys the verification context.
 * @param ctx [in] Verification context.
 * @since 12
 */
void OH_CryptoVerify_Destroy(OH_CryptoVerify *ctx);

/**
 * @brief Creates a signing context based on the given algorithm name.
 * @param algoName [in] Signing algorithm name. Cannot be NULL. Values:
 *     - RSA PKCS1 mode: Format "RSA|PKCS1|Digest", e.g. "RSA|PKCS1|SHA256", "RSA|PKCS1|SHA512".
 *     Digest supports "MD5", "SHA1", "SHA224", "SHA256", "SHA384", "SHA512".
 *     - RSA PSS mode: Format "RSA|PSS|Digest|MGF1Digest", e.g. "RSA|PSS|SHA256|MGF1_SHA256".
 *     Digest supports "MD5", "SHA1", "SHA224", "SHA256", "SHA384", "SHA512".
 *     MGF1 digest supports "MGF1_MD5", "MGF1_SHA1", "MGF1_SHA224", "MGF1_SHA256", "MGF1_SHA384", "MGF1_SHA512".
 *     - RSA sign only: Format "RSA|PKCS1|Digest|OnlySign", e.g. "RSA|PKCS1|SHA256|OnlySign",
 *     "RSA|PKCS1|SHA512|OnlySign".
 *     Digest supports "NoHash", "MD5", "SHA1", "SHA224", "SHA256", "SHA384", "SHA512".
 *     - ECDSA algorithm: Format "ECC|Digest", e.g. "ECC|SHA256", "ECC|SHA384".
 *     Digest supports "SHA1", "SHA224", "SHA256", "SHA384", "SHA512".
 *     - DSA algorithm: Format "DSA|Digest", e.g. "DSA|SHA256", "DSA|SHA384".
 *     Digest supports "NoHash", "SHA1", "SHA224", "SHA256", "SHA384", "SHA512".
 *     - SM2 algorithm: "SM2|SM3".
 *     - Ed25519 algorithm: "Ed25519".
 * @param sign [out] Pointer to the signing context pointer. sign cannot be NULL, *sign must be NULL.
 * @return <ul>
 *         <li>{@link OH_Crypto_ErrCode#CRYPTO_SUCCESS} if the operation succeeds.</li>
 *         <li>{@link OH_Crypto_ErrCode#CRYPTO_PARAMETER_CHECK_FAILED} if sign or algoName is NULL.</li>
 *         <li>{@link OH_Crypto_ErrCode#CRYPTO_NOT_SUPPORTED} if the algorithm is not supported.</li>
 *         <li>{@link OH_Crypto_ErrCode#CRYPTO_MEMORY_ERROR} if memory allocation fails.</li>
 *         <li>{@link OH_Crypto_ErrCode#CRYPTO_OPERTION_ERROR} if crypto operation fails.</li>
 *         </ul>
 * @release crypto_signature/OH_CryptoSign_Destroy {sign}
 * @since 20
 * @see {@link OH_CryptoSign_Init} Initializes the signing context.
 */
OH_Crypto_ErrCode OH_CryptoSign_Create(const char *algoName, OH_CryptoSign **sign);

/**
 * @brief Initializes the signing context.
 * @param ctx [in] Signing context. Cannot be NULL.
 * @param privKey [in] Private key. Cannot be NULL.
 * @return <ul>
 *         <li>{@link OH_Crypto_ErrCode#CRYPTO_SUCCESS} if the operation succeeds.</li>
 *         <li>{@link OH_Crypto_ErrCode#CRYPTO_PARAMETER_CHECK_FAILED} if ctx or privKey is NULL.</li>
 *         <li>{@link OH_Crypto_ErrCode#CRYPTO_NOT_SUPPORTED} if unsupported operation or algorithm.</li>
 *         <li>{@link OH_Crypto_ErrCode#CRYPTO_MEMORY_ERROR} if memory operation fails.</li>
 *         <li>{@link OH_Crypto_ErrCode#CRYPTO_OPERTION_ERROR} if sign init fails.</li>
 *         </ul>
 * @since 20
 * @see {@link OH_CryptoSign_Update} Updates data to be signed.
 * @see {@link OH_CryptoSign_Final} Finishes the signing operation.
 */
OH_Crypto_ErrCode OH_CryptoSign_Init(OH_CryptoSign *ctx, OH_CryptoPrivKey *privKey);

/**
 * @brief Updates data to be signed.
 * @param ctx [in] Signing context. Cannot be NULL.
 * @param in [in] Data to be signed. Cannot be NULL.
 * @return <ul>
 *         <li>{@link OH_Crypto_ErrCode#CRYPTO_SUCCESS} if the operation succeeds.</li>
 *         <li>{@link OH_Crypto_ErrCode#CRYPTO_PARAMETER_CHECK_FAILED} if ctx or in is NULL.</li>
 *         <li>{@link OH_Crypto_ErrCode#CRYPTO_NOT_SUPPORTED} if unsupported operation or algorithm.</li>
 *         <li>{@link OH_Crypto_ErrCode#CRYPTO_MEMORY_ERROR} if memory operation fails.</li>
 *         <li>{@link OH_Crypto_ErrCode#CRYPTO_INVALID_CALL} if the function call is invalid. [since 26.0.0]</li>
 *         <li>{@link OH_Crypto_ErrCode#CRYPTO_OPERTION_ERROR} if sign update fails.</li>
 *         </ul>
 * @since 20
 * @see {@link OH_CryptoSign_Final} Finishes the signing operation.
 */
OH_Crypto_ErrCode OH_CryptoSign_Update(OH_CryptoSign *ctx, const Crypto_DataBlob *in);

/**
 * @brief Finishes the signing operation.
 * @param ctx [in] Signing context. Cannot be NULL.
 * @param in [in] Data to be signed. Can be NULL if all data has been updated via {@link OH_CryptoSign_Update}.
 * @param out [out] Pointer to the Crypto_DataBlob structure for storing the signature result. Cannot be NULL.
 *     Initialize out to {0} before calling. Do not pre-allocate out->data.
 * @return <ul>
 *         <li>{@link OH_Crypto_ErrCode#CRYPTO_SUCCESS} if the operation succeeds.</li>
 *         <li>{@link OH_Crypto_ErrCode#CRYPTO_PARAMETER_CHECK_FAILED} if ctx or out is NULL.</li>
 *         <li>{@link OH_Crypto_ErrCode#CRYPTO_NOT_SUPPORTED} if unsupported operation or algorithm.</li>
 *         <li>{@link OH_Crypto_ErrCode#CRYPTO_MEMORY_ERROR} if memory operation fails.</li>
 *         <li>{@link OH_Crypto_ErrCode#CRYPTO_OPERTION_ERROR} if signing fails.</li>
 *         </ul>
 * @release crypto_common/OH_Crypto_FreeDataBlob {out}
 * @since 20
 */
OH_Crypto_ErrCode OH_CryptoSign_Final(OH_CryptoSign *ctx, const Crypto_DataBlob *in, Crypto_DataBlob *out);

/**
 * @brief Obtains the algorithm name of the signing context.
 * @param ctx [in] Signing context. Cannot be NULL.
 * @return Returns the signing algorithm name. No need to free by the caller. Invalid after the context is destroyed.
 * @since 20
 */
const char *OH_CryptoSign_GetAlgoName(OH_CryptoSign *ctx);

/**
 * @brief Sets the specified parameter for the signing context.
 * @param ctx [in] Signing context. Cannot be NULL.
 * @param type [in] Signing parameter type.
 * @param value [in] Input data. This function performs a deep copy of the data in value. The caller
 *     can release value immediately after the function returns. Cannot be NULL.
 * @return <ul>
 *         <li>{@link OH_Crypto_ErrCode#CRYPTO_SUCCESS} if the operation succeeds.</li>
 *         <li>{@link OH_Crypto_ErrCode#CRYPTO_PARAMETER_CHECK_FAILED} if ctx or value is NULL.</li>
 *         <li>{@link OH_Crypto_ErrCode#CRYPTO_NOT_SUPPORTED} if unsupported operation or algorithm.</li>
 *         <li>{@link OH_Crypto_ErrCode#CRYPTO_MEMORY_ERROR} if memory operation fails.</li>
 *         <li>{@link OH_Crypto_ErrCode#CRYPTO_OPERTION_ERROR} if crypto operation fails.</li>
 *         </ul>
 * @since 20
 */
OH_Crypto_ErrCode OH_CryptoSign_SetParam(OH_CryptoSign *ctx, CryptoSignature_ParamType type,
    const Crypto_DataBlob *value);

/**
 * @brief Obtains the specified parameter from the signing context.
 * @param ctx [in] Signing context. Cannot be NULL.
 * @param type [in] Signing parameter type.
 * @param value [out] Pointer to the Crypto_DataBlob structure for storing the output data. Cannot be NULL. Initialize
 *     value to {0} before calling. Do not pre-allocate value->data.
 * @return <ul>
 *         <li>{@link OH_Crypto_ErrCode#CRYPTO_SUCCESS} if the operation succeeds.</li>
 *         <li>{@link OH_Crypto_ErrCode#CRYPTO_PARAMETER_CHECK_FAILED} if ctx or value is NULL.</li>
 *         <li>{@link OH_Crypto_ErrCode#CRYPTO_NOT_SUPPORTED} if unsupported operation or algorithm.</li>
 *         <li>{@link OH_Crypto_ErrCode#CRYPTO_MEMORY_ERROR} if memory operation fails.</li>
 *         <li>{@link OH_Crypto_ErrCode#CRYPTO_OPERTION_ERROR} if crypto operation fails.</li>
 *         </ul>
 * @release crypto_common/OH_Crypto_FreeDataBlob {value}
 * @since 20
 */
OH_Crypto_ErrCode OH_CryptoSign_GetParam(OH_CryptoSign *ctx, CryptoSignature_ParamType type, Crypto_DataBlob *value);

/**
 * @brief Destroys the signing context.
 * @param ctx [in] Signing context.
 * @since 20
 */
void OH_CryptoSign_Destroy(OH_CryptoSign *ctx);

/**
 * @brief ECC signature specification structure, representing an ECC signature specification.
 * @since 20
 */
typedef struct OH_CryptoEccSignatureSpec OH_CryptoEccSignatureSpec;

/**
 * @brief Creates an ECC signature specification. Also supports SM2 signatures.
 * @param eccSignature [in] ECC signature data in DER format. If NULL, an empty signature specification is created.
 * @param spec [out] Pointer to the ECC signature specification pointer. spec cannot be NULL, *spec must be NULL.
 * @return <ul>
 *         <li>{@link OH_Crypto_ErrCode#CRYPTO_SUCCESS} if the operation succeeds.</li>
 *         <li>{@link OH_Crypto_ErrCode#CRYPTO_PARAMETER_CHECK_FAILED} if spec is NULL or *spec is not NULL.</li>
 *         <li>{@link OH_Crypto_ErrCode#CRYPTO_NOT_SUPPORTED} if unsupported operation or algorithm.</li>
 *         <li>{@link OH_Crypto_ErrCode#CRYPTO_MEMORY_ERROR} if memory operation fails.</li>
 *         <li>{@link OH_Crypto_ErrCode#CRYPTO_OPERTION_ERROR} if parsing eccSignature fails or
 *            eccSignature contains an invalid DER-encoded ECDSA-Sig-Value.</li>
 *         </ul>
 * @release crypto_signature/OH_CryptoEccSignatureSpec_Destroy {spec}
 * @since 20
 * @see {@link OH_CryptoEccSignatureSpec_GetRAndS} Gets the r and s values from the ECC signature specification.
 * @see {@link OH_CryptoEccSignatureSpec_SetRAndS} Sets the r and s values for the ECC signature specification.
 */
OH_Crypto_ErrCode OH_CryptoEccSignatureSpec_Create(Crypto_DataBlob *eccSignature,
    OH_CryptoEccSignatureSpec **spec);

/**
 * @brief Gets the r and s values from the ECC signature specification.
 * @param spec [in] ECC signature specification. Cannot be NULL.
 * @param r [out] Pointer to the Crypto_DataBlob structure for storing the r value. Cannot be NULL.
 *     Initialize r to {0} before calling. Do not pre-allocate r->data.
 * @param s [out] Pointer to the Crypto_DataBlob structure for storing the s value. Cannot be NULL.
 *     Initialize s to {0} before calling. Do not pre-allocate s->data.
 * @return <ul>
 *         <li>{@link OH_Crypto_ErrCode#CRYPTO_SUCCESS} if the operation succeeds.</li>
 *         <li>{@link OH_Crypto_ErrCode#CRYPTO_PARAMETER_CHECK_FAILED} if spec, r, or s is NULL.</li>
 *         <li>{@link OH_Crypto_ErrCode#CRYPTO_NOT_SUPPORTED} if unsupported operation or algorithm.</li>
 *         <li>{@link OH_Crypto_ErrCode#CRYPTO_MEMORY_ERROR} if memory operation fails.</li>
 *         <li>{@link OH_Crypto_ErrCode#CRYPTO_OPERTION_ERROR} if crypto operation fails.</li>
 *         </ul>
 * @release crypto_common/OH_Crypto_FreeDataBlob {s}
 * @release crypto_common/OH_Crypto_FreeDataBlob {r}
 * @since 20
 */
OH_Crypto_ErrCode OH_CryptoEccSignatureSpec_GetRAndS(OH_CryptoEccSignatureSpec *spec, Crypto_DataBlob *r,
    Crypto_DataBlob *s);

/**
 * @brief Sets the r and s values for the ECC signature specification.
 * @param spec [in] ECC signature specification. Cannot be NULL.
 * @param r [in] r value. This function performs a deep copy of the data in r and s. The caller can
 *     release r and s immediately after the function returns. Cannot be NULL.
 * @param s [in] s value. Cannot be NULL.
 * @return <ul>
 *         <li>{@link OH_Crypto_ErrCode#CRYPTO_SUCCESS} if the operation succeeds.</li>
 *         <li>{@link OH_Crypto_ErrCode#CRYPTO_PARAMETER_CHECK_FAILED} if spec, r, or s is NULL.</li>
 *         <li>{@link OH_Crypto_ErrCode#CRYPTO_NOT_SUPPORTED} if unsupported operation or algorithm.</li>
 *         <li>{@link OH_Crypto_ErrCode#CRYPTO_MEMORY_ERROR} if memory operation fails.</li>
 *         <li>{@link OH_Crypto_ErrCode#CRYPTO_OPERTION_ERROR} if crypto operation fails.</li>
 *         </ul>
 * @since 20
 * @see {@link OH_CryptoEccSignatureSpec_Encode} Encodes the ECC signature specification into DER format signature data.
 */
OH_Crypto_ErrCode OH_CryptoEccSignatureSpec_SetRAndS(OH_CryptoEccSignatureSpec *spec, Crypto_DataBlob *r,
    Crypto_DataBlob *s);

/**
 * @brief Encodes the ECC signature specification into DER format signature data.
 * @param spec [in] ECC signature specification. Cannot be NULL.
 * @param out [out] Pointer to the Crypto_DataBlob structure for storing the encoded signature. Cannot
 *     be NULL. Initialize out to {0} before calling. Do not pre-allocate out->data.
 * @return <ul>
 *         <li>{@link OH_Crypto_ErrCode#CRYPTO_SUCCESS} if the operation succeeds.</li>
 *         <li>{@link OH_Crypto_ErrCode#CRYPTO_PARAMETER_CHECK_FAILED} if spec or out is NULL, or
 *            r and s values have not been set via {@link OH_CryptoEccSignatureSpec_SetRAndS}.</li>
 *         <li>{@link OH_Crypto_ErrCode#CRYPTO_NOT_SUPPORTED} if unsupported operation or algorithm.</li>
 *         <li>{@link OH_Crypto_ErrCode#CRYPTO_MEMORY_ERROR} if memory allocation fails.</li>
 *         <li>{@link OH_Crypto_ErrCode#CRYPTO_OPERTION_ERROR} if encoding fails.</li>
 *         </ul>
 * @release crypto_common/OH_Crypto_FreeDataBlob {out}
 * @since 20
 */
OH_Crypto_ErrCode OH_CryptoEccSignatureSpec_Encode(OH_CryptoEccSignatureSpec *spec, Crypto_DataBlob *out);

/**
 * @brief Destroys the ECC signature specification.
 * @param spec [in] ECC signature specification.
 * @since 20
 */
void OH_CryptoEccSignatureSpec_Destroy(OH_CryptoEccSignatureSpec *spec);

#ifdef __cplusplus
}
#endif

#endif /* CRYPTO_SIGNATURE_H */
/** @} */
