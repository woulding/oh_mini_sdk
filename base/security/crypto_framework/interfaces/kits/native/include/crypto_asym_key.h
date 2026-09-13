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
 * @addtogroup CryptoAsymKeyApi
 * @{
 * @brief Describes the asymmetric key interfaces provided by OpenHarmony for applications.
 * @since 12
 */

/**
 * @file crypto_asym_key.h
 * @brief Defines the asymmetric key interfaces.
 * @syscap SystemCapability.Security.CryptoFramework
 * @library libohcrypto.so
 * @kit CryptoArchitectureKit
 * @since 12
 */

#ifndef CRYPTO_ASYM_KEY_H
#define CRYPTO_ASYM_KEY_H

#include "crypto_common.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief Key pair structure, representing a key pair.
 * @since 12
 */
typedef struct OH_CryptoKeyPair OH_CryptoKeyPair;

/**
 * @brief Public key structure, representing a public key.
 * @since 12
 */
typedef struct OH_CryptoPubKey OH_CryptoPubKey;

/**
 * @brief Private key structure, representing a private key.
 * @since 20
 */
typedef struct OH_CryptoPrivKey OH_CryptoPrivKey;

/**
 * @brief Defines asymmetric key parameter types.
 * @since 12
 */
typedef enum {
    /**
     * @brief Prime p of the DSA algorithm.
     * @since 12
     */
    CRYPTO_DSA_P_DATABLOB = 101,
    /**
     * @brief Sub-prime q of the DSA algorithm.
     * @since 12
     */
    CRYPTO_DSA_Q_DATABLOB = 102,
    /**
     * @brief Base g of the DSA algorithm.
     * @since 12
     */
    CRYPTO_DSA_G_DATABLOB = 103,
    /**
     * @brief Private key of the DSA algorithm.
     * @since 12
     */
    CRYPTO_DSA_SK_DATABLOB = 104,
    /**
     * @brief Public key of the DSA algorithm.
     * @since 12
     */
    CRYPTO_DSA_PK_DATABLOB = 105,

    /**
     * @brief Prime p of the elliptic curve (EC) prime field.
     * @since 12
     */
    CRYPTO_ECC_FP_P_DATABLOB = 201,
    /**
     * @brief First coefficient a of the elliptic curve.
     * @since 12
     */
    CRYPTO_ECC_A_DATABLOB = 202,
    /**
     * @brief Second coefficient b of the elliptic curve.
     * @since 12
     */
    CRYPTO_ECC_B_DATABLOB = 203,
    /**
     * @brief Affine x-coordinate of the base point g.
     * @since 12
     */
    CRYPTO_ECC_G_X_DATABLOB = 204,
    /**
     * @brief Affine y-coordinate of the base point g.
     * @since 12
     */
    CRYPTO_ECC_G_Y_DATABLOB = 205,
    /**
     * @brief Order of the base point g.
     * @since 12
     */
    CRYPTO_ECC_N_DATABLOB = 206,
    /**
     * @brief Cofactor of the elliptic curve.
     * @since 12
     */
    CRYPTO_ECC_H_INT = 207,
    /**
     * @brief Private key value of the ECC private key.
     * @since 12
     */
    CRYPTO_ECC_SK_DATABLOB = 208,
    /**
     * @brief Affine x-coordinate of the public key point in the ECC public key.
     * @since 12
     */
    CRYPTO_ECC_PK_X_DATABLOB = 209,
    /**
     * @brief Affine y-coordinate of the public key point in the ECC public key.
     * @since 12
     */
    CRYPTO_ECC_PK_Y_DATABLOB = 210,
    /**
     * @brief Finite field type of the elliptic curve.
     * @since 12
     */
    CRYPTO_ECC_FIELD_TYPE_STR = 211,
    /**
     * @brief Bit length of the finite field.
     * @since 12
     */
    CRYPTO_ECC_FIELD_SIZE_INT = 212,
    /**
     * @brief Curve name of the SECG standard.
     * @since 12
     */
    CRYPTO_ECC_CURVE_NAME_STR = 213,

    /**
     * @brief Modulus n of the RSA algorithm.
     * @since 12
     */
    CRYPTO_RSA_N_DATABLOB = 301,
    /**
     * @brief Private key exponent d of the RSA algorithm.
     * @since 12
     */
    CRYPTO_RSA_D_DATABLOB = 302,
    /**
     * @brief Public key exponent e of the RSA algorithm.
     * @since 12
     */
    CRYPTO_RSA_E_DATABLOB = 303,

    /**
     * @brief Prime p of the DH algorithm.
     * @since 12
     */
    CRYPTO_DH_P_DATABLOB = 401,
    /**
     * @brief Generator g of the DH algorithm.
     * @since 12
     */
    CRYPTO_DH_G_DATABLOB = 402,
    /**
     * @brief Bit length of the private key in the DH algorithm.
     * @since 12
     */
    CRYPTO_DH_L_INT = 403,
    /**
     * @brief Private key value of the DH private key.
     * @since 12
     */
    CRYPTO_DH_SK_DATABLOB = 404,
    /**
     * @brief Public key value of the DH public key.
     * @since 12
     */
    CRYPTO_DH_PK_DATABLOB = 405,

    /**
     * @brief Private key value of the ED25519 private key.
     * @since 12
     */
    CRYPTO_ED25519_SK_DATABLOB = 501,
    /**
     * @brief Public key value of the ED25519 public key.
     * @since 12
     */
    CRYPTO_ED25519_PK_DATABLOB = 502,
    /**
     * @brief Private key value of the X25519 private key.
     * @since 12
     */
    CRYPTO_X25519_SK_DATABLOB = 601,
    /**
     * @brief Public key value of the X25519 public key.
     * @since 12
     */
    CRYPTO_X25519_PK_DATABLOB = 602,
} CryptoAsymKey_ParamType;

/**
 * @brief Defines the encoding type.
 * @since 12
 */
typedef enum {
    /**
     * @brief PEM format.
     * @since 12
     */
    CRYPTO_PEM = 0,
    /**
     * @brief DER format.
     * @since 12
     */
    CRYPTO_DER = 1,
} Crypto_EncodingType;

/**
 * @brief Asymmetric key generator structure, representing an asymmetric key generator.
 * @since 12
 */
typedef struct OH_CryptoAsymKeyGenerator OH_CryptoAsymKeyGenerator;

/**
 * @brief Creates an asymmetric key generator based on the given algorithm name.
 * @param algoName [in] Asymmetric key algorithm name. Cannot be NULL. Values:
 *     - RSA series since API version 12: "RSA512", "RSA768", "RSA1024", "RSA2048", "RSA3072",
 *     "RSA4096", "RSA8192". Multi-prime format is supported, e.g. "RSA1024|PRIMES_3",
 *     "RSA4096|PRIMES_4", "RSA8192|PRIMES_5".
 *     - ECC series since API version 12: "ECC224", "ECC256", "ECC384", "ECC521".
 *     - ECC BrainPool series since API version 12: "ECC_BrainPoolP160r1", "ECC_BrainPoolP160t1",
 *     "ECC_BrainPoolP192r1", "ECC_BrainPoolP192t1", "ECC_BrainPoolP224r1", "ECC_BrainPoolP224t1",
 *     "ECC_BrainPoolP256r1", "ECC_BrainPoolP256t1", "ECC_BrainPoolP320r1", "ECC_BrainPoolP320t1",
 *     "ECC_BrainPoolP384r1", "ECC_BrainPoolP384t1", "ECC_BrainPoolP512r1", "ECC_BrainPoolP512t1".
 *     - "SM2_256", "Ed25519", "X25519" supported since API version 12.
 *     - DSA series since API version 12: "DSA1024", "DSA2048", "DSA3072".
 *     - DH series since API version 12: "DH_modp1536", "DH_modp2048", "DH_modp3072",
 *     "DH_modp4096", "DH_modp6144", "DH_modp8192", "DH_ffdhe2048", "DH_ffdhe3072",
 *     "DH_ffdhe4096", "DH_ffdhe6144", "DH_ffdhe8192".
 *     - "ECC_Secp256k1" supported since API version 14.
 *     - "ECC192" supported since API version 26.0.0.
 * @param ctx [out] Pointer to the asymmetric key generator pointer. ctx cannot be NULL, *ctx must be NULL.
 * @return <ul>
 *         <li>{@link OH_Crypto_ErrCode#CRYPTO_SUCCESS} if the operation succeeds.</li>
 *         <li>{@link OH_Crypto_ErrCode#CRYPTO_INVALID_PARAMS} if ctx or algoName is NULL.</li>
 *         <li>{@link OH_Crypto_ErrCode#CRYPTO_NOT_SUPPORTED} if the algorithm is not supported.</li>
 *         <li>{@link OH_Crypto_ErrCode#CRYPTO_MEMORY_ERROR} if memory allocation fails.</li>
 *         <li>{@link OH_Crypto_ErrCode#CRYPTO_OPERTION_ERROR} if crypto operation fails.</li>
 *         </ul>
 * @release crypto_asym_key/OH_CryptoAsymKeyGenerator_Destroy {ctx}
 * @since 12
 * @see {@link OH_CryptoAsymKeyGenerator_Generate} Generates an asymmetric key pair.
 * @see {@link OH_CryptoAsymKeyGenerator_Convert} Converts asymmetric key data to a key pair.
 */
OH_Crypto_ErrCode OH_CryptoAsymKeyGenerator_Create(const char *algoName, OH_CryptoAsymKeyGenerator **ctx);

/**
 * @brief Generates an asymmetric key pair.
 * @param ctx [in] Asymmetric key generator. Cannot be NULL.
 * @param keyCtx [out] Pointer to the key pair pointer. keyCtx cannot be NULL, *keyCtx must be NULL.
 * @return <ul>
 *         <li>{@link OH_Crypto_ErrCode#CRYPTO_SUCCESS} if the operation succeeds.</li>
 *         <li>{@link OH_Crypto_ErrCode#CRYPTO_INVALID_PARAMS} if ctx or keyCtx is NULL.</li>
 *         <li>{@link OH_Crypto_ErrCode#CRYPTO_NOT_SUPPORTED} if unsupported operation or algorithm.</li>
 *         <li>{@link OH_Crypto_ErrCode#CRYPTO_MEMORY_ERROR} if memory operation fails.</li>
 *         <li>{@link OH_Crypto_ErrCode#CRYPTO_OPERTION_ERROR} if crypto operation fails.</li>
 *         </ul>
 * @release crypto_asym_key/OH_CryptoKeyPair_Destroy {keyCtx}
 * @since 12
 */
OH_Crypto_ErrCode OH_CryptoAsymKeyGenerator_Generate(OH_CryptoAsymKeyGenerator *ctx, OH_CryptoKeyPair **keyCtx);

/**
 * @brief Converts asymmetric key data to a key pair.
 * @param ctx [in] Asymmetric key generator. Cannot be NULL.
 * @param type [in] Encoding type.
 * @param pubKeyData [in] Public key data. Cannot be NULL at the same time as priKeyData.
 * @param priKeyData [in] Private key data. Cannot be NULL at the same time as pubKeyData.
 * @param keyCtx [out] Pointer to the key pair pointer. keyCtx cannot be NULL, *keyCtx must be NULL.
 * @return <ul>
 *         <li>{@link OH_Crypto_ErrCode#CRYPTO_SUCCESS} if the operation succeeds.</li>
 *         <li>{@link OH_Crypto_ErrCode#CRYPTO_INVALID_PARAMS} if ctx is NULL, pubKeyData and
 *            priKeyData are both NULL, keyCtx is NULL, or type is not a valid Crypto_EncodingType.</li>
 *         <li>{@link OH_Crypto_ErrCode#CRYPTO_NOT_SUPPORTED} if the key format is not supported.</li>
 *         <li>{@link OH_Crypto_ErrCode#CRYPTO_MEMORY_ERROR} if memory allocation fails.</li>
 *         <li>{@link OH_Crypto_ErrCode#CRYPTO_OPERTION_ERROR} if key conversion fails. Possible causes:
 *            key data is corrupted or not valid PEM/DER format, key data does not match the algorithm,
 *            or the password for an encrypted private key is incorrect.</li>
 *         </ul>
 * @release crypto_asym_key/OH_CryptoKeyPair_Destroy {keyCtx}
 * @since 12
 */
OH_Crypto_ErrCode OH_CryptoAsymKeyGenerator_Convert(OH_CryptoAsymKeyGenerator *ctx, Crypto_EncodingType type,
    Crypto_DataBlob *pubKeyData, Crypto_DataBlob *priKeyData, OH_CryptoKeyPair **keyCtx);

/**
 * @brief Obtains the algorithm name of the asymmetric key generator.
 * @param ctx [in] Asymmetric key generator. Cannot be NULL.
 * @return <ul>
 *         <li>Returns the asymmetric key algorithm name. No need to free by the caller. Invalid after the generator is
 *             destroyed.</li>
 *         <li>Returns NULL if ctx is NULL.</li>
 *         </ul>
 * @since 12
 */
const char *OH_CryptoAsymKeyGenerator_GetAlgoName(OH_CryptoAsymKeyGenerator *ctx);

/**
 * @brief Destroys the asymmetric key generator.
 * @param ctx [in] Asymmetric key generator.
 * @since 12
 */
void OH_CryptoAsymKeyGenerator_Destroy(OH_CryptoAsymKeyGenerator *ctx);

/**
 * @brief Destroys the key pair.
 * @param keyCtx [in] Key pair.
 * @since 12
 */
void OH_CryptoKeyPair_Destroy(OH_CryptoKeyPair *keyCtx);

/**
 * @brief Obtains the public key from the key pair.
 * @param keyCtx [in] Key pair. Cannot be NULL.
 * @return <ul>
 *         <li>Returns the public key from the key pair. It is an internal reference and does not need to be destroyed
 *           separately. Invalid after the key pair is destroyed.</li>
 *         <li>Returns NULL if keyCtx is NULL or the public key does not exist.</li>
 *         </ul>
 * @since 12
 */
OH_CryptoPubKey *OH_CryptoKeyPair_GetPubKey(OH_CryptoKeyPair *keyCtx);

/**
 * @brief Obtains the private key from the key pair.
 * @param keyCtx [in] Key pair. Cannot be NULL.
 * @return <ul>
 *         <li>Returns the private key from the key pair. It is an internal reference and does not need to be destroyed
 *           separately. Invalid after the key pair is destroyed.</li>
 *         <li>Returns NULL if keyCtx is NULL or the private key does not exist.</li>
 *         </ul>
 * @since 20
 */
OH_CryptoPrivKey *OH_CryptoKeyPair_GetPrivKey(OH_CryptoKeyPair *keyCtx);

/**
 * @brief Encodes the public key.
 * @param key [in] Public key. Cannot be NULL.
 * @param type [in] Encoding type.
 * @param encodingStandard [in] Encoding standard. Supports "X509". Cannot be NULL.
 * @param out [out] Pointer to the Crypto_DataBlob structure for storing the encoding result. Cannot be NULL. Initialize
 *     out to {0} before calling. Do not pre-allocate out->data.
 * @return <ul>
 *         <li>{@link OH_Crypto_ErrCode#CRYPTO_SUCCESS} if the operation succeeds.</li>
 *         <li>{@link OH_Crypto_ErrCode#CRYPTO_INVALID_PARAMS} if key, out, or encodingStandard is NULL, type is
 *            not a valid Crypto_EncodingType, or the encoding standard is incompatible with the key type.</li>
 *         <li>{@link OH_Crypto_ErrCode#CRYPTO_NOT_SUPPORTED} if the encoding format is not supported.</li>
 *         <li>{@link OH_Crypto_ErrCode#CRYPTO_MEMORY_ERROR} if memory allocation fails.</li>
 *         <li>{@link OH_Crypto_ErrCode#CRYPTO_OPERTION_ERROR} if encoding fails.</li>
 *         </ul>
 * @release crypto_common/OH_Crypto_FreeDataBlob {out}
 * @since 12
 */
OH_Crypto_ErrCode OH_CryptoPubKey_Encode(OH_CryptoPubKey *key, Crypto_EncodingType type,
    const char *encodingStandard, Crypto_DataBlob *out);

/**
 * @brief Obtains the specified parameter of the public key.
 * @param key [in] Public key. Cannot be NULL.
 * @param item [in] Asymmetric key parameter type.
 * @param value [out] Pointer to the Crypto_DataBlob structure for storing the output data. Cannot be NULL.
 *     Initialize value to {0} before calling. Do not pre-allocate value->data.
 * @return <ul>
 *         <li>{@link OH_Crypto_ErrCode#CRYPTO_SUCCESS} if the operation succeeds.</li>
 *         <li>{@link OH_Crypto_ErrCode#CRYPTO_INVALID_PARAMS} if key or value is NULL, or the
 *            parameter type is not supported for the key algorithm.</li>
 *         <li>{@link OH_Crypto_ErrCode#CRYPTO_NOT_SUPPORTED} if the parameter type is not supported.</li>
 *         <li>{@link OH_Crypto_ErrCode#CRYPTO_MEMORY_ERROR} if memory allocation fails.</li>
 *         <li>{@link OH_Crypto_ErrCode#CRYPTO_OPERTION_ERROR} if getting param fails.</li>
 *         </ul>
 * @release crypto_common/OH_Crypto_FreeDataBlob {value}
 * @since 12
 */
OH_Crypto_ErrCode OH_CryptoPubKey_GetParam(OH_CryptoPubKey *key, CryptoAsymKey_ParamType item,
    Crypto_DataBlob *value);

/**
 * @brief Sets the password for the asymmetric key generator. Call this method to set the password if you need to use
 * {@link OH_CryptoAsymKeyGenerator_Convert} to convert encrypted private key data to a key pair.
 * @param ctx [in] Asymmetric key generator. Cannot be NULL.
 * @param password [in] Password. This function performs a deep copy of the data in password. The
 *     caller can release password immediately after the function returns. Cannot be NULL.
 * @param passwordLen [in] Byte length of the password. Must be greater than 0.
 * @return <ul>
 *         <li>{@link OH_Crypto_ErrCode#CRYPTO_SUCCESS} if the operation succeeds.</li>
 *         <li>{@link OH_Crypto_ErrCode#CRYPTO_NOT_SUPPORTED} if unsupported operation or algorithm.</li>
 *         <li>{@link OH_Crypto_ErrCode#CRYPTO_MEMORY_ERROR} if memory allocation fails.</li>
 *         <li>{@link OH_Crypto_ErrCode#CRYPTO_PARAMETER_CHECK_FAILED} if ctx or password is NULL,
 *         or passwordLen is 0.</li>
 *         <li>{@link OH_Crypto_ErrCode#CRYPTO_OPERTION_ERROR} if crypto operation fails.</li>
 *         </ul>
 * @since 20
 */
OH_Crypto_ErrCode OH_CryptoAsymKeyGenerator_SetPassword(OH_CryptoAsymKeyGenerator *ctx, const unsigned char *password,
    uint32_t passwordLen);

/**
 * @brief Private key encoding parameters structure, representing private key encoding parameters.
 * @since 20
 */
typedef struct OH_CryptoPrivKeyEncodingParams OH_CryptoPrivKeyEncodingParams;

/**
 * @brief Defines private key encoding parameter types.
 * @since 20
 */
typedef enum {
    /**
     * @brief Password string.
     * @since 20
     */
    CRYPTO_PRIVATE_KEY_ENCODING_PASSWORD_STR = 0,

    /**
     * @brief Symmetric cipher algorithm name, set via
     * {@link OH_CryptoPrivKeyEncodingParams_SetParam}.
     * Values: "DES-EDE3-CBC", "AES-128-CBC", "AES-192-CBC", "AES-256-CBC".
     * @since 20
     */
    CRYPTO_PRIVATE_KEY_ENCODING_SYMMETRIC_CIPHER_STR = 1,
} CryptoPrivKeyEncoding_ParamType;

/**
 * @brief Creates private key encoding parameters.
 * @param ctx [out] Pointer to the private key encoding parameters pointer. ctx cannot be NULL, *ctx must be NULL.
 * @return <ul>
 *         <li>{@link OH_Crypto_ErrCode#CRYPTO_SUCCESS} if the operation succeeds.</li>
 *         <li>{@link OH_Crypto_ErrCode#CRYPTO_PARAMETER_CHECK_FAILED} if ctx is NULL.</li>
 *         <li>{@link OH_Crypto_ErrCode#CRYPTO_NOT_SUPPORTED} if unsupported operation or algorithm.</li>
 *         <li>{@link OH_Crypto_ErrCode#CRYPTO_MEMORY_ERROR} if memory allocation fails.</li>
 *         <li>{@link OH_Crypto_ErrCode#CRYPTO_OPERTION_ERROR} if crypto operation fails.</li>
 *         </ul>
 * @release crypto_asym_key/OH_CryptoPrivKeyEncodingParams_Destroy {ctx}
 * @since 20
 * @see {@link OH_CryptoPrivKeyEncodingParams_SetParam} Sets private key encoding parameters.
 */
OH_Crypto_ErrCode OH_CryptoPrivKeyEncodingParams_Create(OH_CryptoPrivKeyEncodingParams **ctx);

/**
 * @brief Sets private key encoding parameters.
 * @param ctx [in] Private key encoding parameters. Cannot be NULL.
 * @param type [in] Private key encoding parameter type.
 * @param value [in] Private key encoding parameter value. This function performs a deep copy of the data in value.
 *     The caller can release value immediately after the function returns. Cannot be NULL.
 * @return <ul>
 *         <li>{@link OH_Crypto_ErrCode#CRYPTO_SUCCESS} if the operation succeeds.</li>
 *         <li>{@link OH_Crypto_ErrCode#CRYPTO_PARAMETER_CHECK_FAILED} if ctx or value is NULL,
 *            value->data is NULL, value->len is 0, or type is unrecognized.</li>
 *         <li>{@link OH_Crypto_ErrCode#CRYPTO_NOT_SUPPORTED} if unsupported operation or algorithm.</li>
 *         <li>{@link OH_Crypto_ErrCode#CRYPTO_MEMORY_ERROR} if memory allocation for deep copy fails.</li>
 *         <li>{@link OH_Crypto_ErrCode#CRYPTO_OPERTION_ERROR} if crypto operation fails.</li>
 *         </ul>
 * @since 20
 */
OH_Crypto_ErrCode OH_CryptoPrivKeyEncodingParams_SetParam(OH_CryptoPrivKeyEncodingParams *ctx,
    CryptoPrivKeyEncoding_ParamType type, Crypto_DataBlob *value);

/**
 * @brief Destroys private key encoding parameters.
 * @param ctx [in] Private key encoding parameters.
 * @since 20
 */
void OH_CryptoPrivKeyEncodingParams_Destroy(OH_CryptoPrivKeyEncodingParams *ctx);

/**
 * @brief Encodes the private key.
 * @param key [in] Private key. Cannot be NULL.
 * @param type [in] Encoding type.
 * @param encodingStandard [in] Encoding standard. Supports "PKCS8" and "PKCS1". "PKCS1" is only supported for RSA
 *     private keys. Cannot be NULL.
 * @param params [in] Private key encoding parameters. Can be NULL. Set this parameter if the private key needs to be
 *     encrypted.
 * @param out [out] Pointer to the Crypto_DataBlob structure for storing the encoding result. Cannot be NULL.
 *     Initialize out to {0} before calling. Do not pre-allocate out->data.
 * @return <ul>
 *         <li>{@link OH_Crypto_ErrCode#CRYPTO_SUCCESS} if the operation succeeds.</li>
 *         <li>{@link OH_Crypto_ErrCode#CRYPTO_PARAMETER_CHECK_FAILED} if key, out, or encodingStandard is NULL,
 *            type is not a valid Crypto_EncodingType, or the encoding standard is incompatible
 *            with the key type.</li>
 *         <li>{@link OH_Crypto_ErrCode#CRYPTO_NOT_SUPPORTED} if the encoding format is not supported.</li>
 *         <li>{@link OH_Crypto_ErrCode#CRYPTO_MEMORY_ERROR} if memory allocation fails.</li>
 *         <li>{@link OH_Crypto_ErrCode#CRYPTO_OPERTION_ERROR} if encoding fails.</li>
 *         </ul>
 * @release crypto_common/OH_Crypto_FreeDataBlob {out}
 * @since 20
 */
OH_Crypto_ErrCode OH_CryptoPrivKey_Encode(OH_CryptoPrivKey *key, Crypto_EncodingType type,
    const char *encodingStandard, OH_CryptoPrivKeyEncodingParams *params, Crypto_DataBlob *out);

/**
 * @brief Obtains the specified parameter of the private key.
 * @param key [in] Private key. Cannot be NULL.
 * @param item [in] Asymmetric key parameter type.
 * @param value [out] Pointer to the Crypto_DataBlob structure for storing the output data. Cannot be NULL.
 *     Initialize value to {0} before calling. Do not pre-allocate value->data.
 * @return <ul>
 *         <li>{@link OH_Crypto_ErrCode#CRYPTO_SUCCESS} if the operation succeeds.</li>
 *         <li>{@link OH_Crypto_ErrCode#CRYPTO_PARAMETER_CHECK_FAILED} if key or value is NULL, or
 *            the parameter type is not supported for the key algorithm.</li>
 *         <li>{@link OH_Crypto_ErrCode#CRYPTO_NOT_SUPPORTED} if the parameter type is not supported.</li>
 *         <li>{@link OH_Crypto_ErrCode#CRYPTO_MEMORY_ERROR} if memory allocation fails.</li>
 *         <li>{@link OH_Crypto_ErrCode#CRYPTO_OPERTION_ERROR} if getting param fails.</li>
 *         </ul>
 * @release crypto_common/OH_Crypto_FreeDataBlob {value}
 * @since 20
 */
OH_Crypto_ErrCode OH_CryptoPrivKey_GetParam(OH_CryptoPrivKey *key, CryptoAsymKey_ParamType item,
    Crypto_DataBlob *value);

/**
 * @brief Asymmetric key specification structure, representing an asymmetric key specification.
 * @since 20
 */
typedef struct OH_CryptoAsymKeySpec OH_CryptoAsymKeySpec;

/**
 * @brief Defines asymmetric key specification types.
 * @since 20
 */
typedef enum {
    /**
     * @brief Common parameter specification.
     * @since 20
     */
    CRYPTO_ASYM_KEY_COMMON_PARAMS_SPEC = 0,
    /**
     * @brief Private key specification.
     * @since 20
     */
    CRYPTO_ASYM_KEY_PRIVATE_KEY_SPEC = 1,
    /**
     * @brief Public key specification.
     * @since 20
     */
    CRYPTO_ASYM_KEY_PUBLIC_KEY_SPEC = 2,
    /**
     * @brief Key pair specification.
     * @since 20
     */
    CRYPTO_ASYM_KEY_KEY_PAIR_SPEC = 3,
} CryptoAsymKeySpec_Type;

/**
 * @brief Generates EC common parameter specification.
 * @param curveName [in] NID (Name Identifier) string of the ECC curve. Cannot be NULL.
 *     e.g. "NID_X9_62_prime256v1", "NID_secp384r1", "NID_secp521r1", "NID_sm2".
 * @param spec [out] Pointer to the asymmetric key specification pointer. spec cannot be NULL, *spec must be NULL.
 * @return <ul>
 *         <li>{@link OH_Crypto_ErrCode#CRYPTO_SUCCESS} if the operation succeeds.</li>
 *         <li>{@link OH_Crypto_ErrCode#CRYPTO_PARAMETER_CHECK_FAILED} if curveName or spec is NULL,
 *            or the curve name is not a valid elliptic curve.</li>
 *         <li>{@link OH_Crypto_ErrCode#CRYPTO_NOT_SUPPORTED} if the curve is not supported.</li>
 *         <li>{@link OH_Crypto_ErrCode#CRYPTO_MEMORY_ERROR} if memory allocation fails.</li>
 *         <li>{@link OH_Crypto_ErrCode#CRYPTO_OPERTION_ERROR} if generating spec fails.</li>
 *         </ul>
 * @release crypto_asym_key/OH_CryptoAsymKeySpec_Destroy {spec}
 * @since 20
 */
OH_Crypto_ErrCode OH_CryptoAsymKeySpec_GenEcCommonParamsSpec(const char *curveName, OH_CryptoAsymKeySpec **spec);

/**
 * @brief Generates DH common parameter specification.
 * @param pLen [in] Bit length of prime p.
 * @param skLen [in] Bit length of the private key.
 * @param spec [out] Pointer to the asymmetric key specification pointer. spec cannot be NULL, *spec must be NULL.
 * @return <ul>
 *         <li>{@link OH_Crypto_ErrCode#CRYPTO_SUCCESS} if the operation succeeds.</li>
 *         <li>{@link OH_Crypto_ErrCode#CRYPTO_PARAMETER_CHECK_FAILED} if spec is NULL,
 *            pLen is negative, skLen is negative, or skLen is greater than pLen.</li>
 *         <li>{@link OH_Crypto_ErrCode#CRYPTO_NOT_SUPPORTED} if unsupported operation or algorithm.</li>
 *         <li>{@link OH_Crypto_ErrCode#CRYPTO_MEMORY_ERROR} if memory allocation fails.</li>
 *         <li>{@link OH_Crypto_ErrCode#CRYPTO_OPERTION_ERROR} if crypto operation fails.</li>
 *         </ul>
 * @release crypto_asym_key/OH_CryptoAsymKeySpec_Destroy {spec}
 * @since 20
 */
OH_Crypto_ErrCode OH_CryptoAsymKeySpec_GenDhCommonParamsSpec(int pLen, int skLen, OH_CryptoAsymKeySpec **spec);

/**
 * @brief Creates an asymmetric key specification based on the given algorithm name and specification type.
 * @param algoName [in] Asymmetric key specification algorithm name. Cannot be NULL. Values:
 *     - "RSA", "ECC", "DSA", "SM2", "Ed25519", "X25519", "DH" supported since API version 20.
 * @param type [in] Asymmetric key specification type.
 * @param spec [out] Pointer to the asymmetric key specification pointer. spec cannot be NULL, *spec must be NULL.
 * @return <ul>
 *         <li>{@link OH_Crypto_ErrCode#CRYPTO_SUCCESS} if the operation succeeds.</li>
 *         <li>{@link OH_Crypto_ErrCode#CRYPTO_PARAMETER_CHECK_FAILED} if algoName or spec is NULL,
 *             algoName is not a supported algorithm name.</li>
 *         <li>{@link OH_Crypto_ErrCode#CRYPTO_NOT_SUPPORTED} if unsupported operation or algorithm.</li>
 *         <li>{@link OH_Crypto_ErrCode#CRYPTO_MEMORY_ERROR} if memory allocation fails.</li>
 *         <li>{@link OH_Crypto_ErrCode#CRYPTO_OPERTION_ERROR} if crypto operation fails.</li>
 *         </ul>
 * @release crypto_asym_key/OH_CryptoAsymKeySpec_Destroy {spec}
 * @since 20
 */
OH_Crypto_ErrCode OH_CryptoAsymKeySpec_Create(const char *algoName, CryptoAsymKeySpec_Type type,
    OH_CryptoAsymKeySpec **spec);

/**
 * @brief Sets the specified parameter of the asymmetric key specification.
 * @param spec [in] Asymmetric key specification. Cannot be NULL.
 * @param type [in] Asymmetric key parameter type.
 * @param value [in] Input data. This function performs a deep copy of the data in value. The caller can release value
 *     immediately after the function returns. Cannot be NULL.
 * @return <ul>
 *         <li>{@link OH_Crypto_ErrCode#CRYPTO_SUCCESS} if the operation succeeds.</li>
 *         <li>{@link OH_Crypto_ErrCode#CRYPTO_PARAMETER_CHECK_FAILED} if spec or value is NULL,
 *            value->data is NULL, value->len is 0, or the parameter type is not
 *            supported for the algorithm.</li>
 *         <li>{@link OH_Crypto_ErrCode#CRYPTO_NOT_SUPPORTED} if unsupported operation or algorithm.</li>
 *         <li>{@link OH_Crypto_ErrCode#CRYPTO_MEMORY_ERROR} if memory allocation for deep copy fails.</li>
 *         <li>{@link OH_Crypto_ErrCode#CRYPTO_OPERTION_ERROR} if crypto operation fails.</li>
 *         </ul>
 * @since 20
 */
OH_Crypto_ErrCode OH_CryptoAsymKeySpec_SetParam(OH_CryptoAsymKeySpec *spec, CryptoAsymKey_ParamType type,
    Crypto_DataBlob *value);

/**
 * @brief Sets the common parameter specification into the asymmetric key specification.
 * @param spec [in] Asymmetric key specification. Cannot be NULL.
 * @param commonParamsSpec [in] Common parameter specification. This function performs a deep copy of the data in
 *     commonParamsSpec. The caller can release commonParamsSpec immediately after the function returns. Cannot be NULL.
 * @return <ul>
 *         <li>{@link OH_Crypto_ErrCode#CRYPTO_SUCCESS} if the operation succeeds.</li>
 *         <li>{@link OH_Crypto_ErrCode#CRYPTO_PARAMETER_CHECK_FAILED} if spec or commonParamsSpec is NULL.</li>
 *         <li>{@link OH_Crypto_ErrCode#CRYPTO_NOT_SUPPORTED} if unsupported operation or algorithm.</li>
 *         <li>{@link OH_Crypto_ErrCode#CRYPTO_MEMORY_ERROR} if memory allocation fails.</li>
 *         <li>{@link OH_Crypto_ErrCode#CRYPTO_OPERTION_ERROR} if crypto operation fails.</li>
 *         </ul>
 * @since 20
 */
OH_Crypto_ErrCode OH_CryptoAsymKeySpec_SetCommonParamsSpec(OH_CryptoAsymKeySpec *spec,
    OH_CryptoAsymKeySpec *commonParamsSpec);

/**
 * @brief Obtains the specified parameter of the asymmetric key specification.
 * @param spec [in] Asymmetric key specification. Cannot be NULL.
 * @param type [in] Asymmetric key parameter type.
 * @param value [out] Pointer to the Crypto_DataBlob structure for storing the output data. Cannot be NULL.
 *     Initialize value to {0} before calling. Do not pre-allocate value->data.
 * @return <ul>
 *         <li>{@link OH_Crypto_ErrCode#CRYPTO_SUCCESS} if the operation succeeds.</li>
 *         <li>{@link OH_Crypto_ErrCode#CRYPTO_PARAMETER_CHECK_FAILED} if spec or value is NULL, or
 *            the parameter type is not supported for the algorithm.</li>
 *         <li>{@link OH_Crypto_ErrCode#CRYPTO_NOT_SUPPORTED} if unsupported operation or algorithm.</li>
 *         <li>{@link OH_Crypto_ErrCode#CRYPTO_MEMORY_ERROR} if memory allocation fails.</li>
 *         <li>{@link OH_Crypto_ErrCode#CRYPTO_OPERTION_ERROR} if crypto operation fails.</li>
 *         </ul>
 * @release crypto_common/OH_Crypto_FreeDataBlob {value}
 * @since 20
 */
OH_Crypto_ErrCode OH_CryptoAsymKeySpec_GetParam(OH_CryptoAsymKeySpec *spec, CryptoAsymKey_ParamType type,
    Crypto_DataBlob *value);

/**
 * @brief Destroys the asymmetric key specification.
 * @param spec [in] Asymmetric key specification.
 * @since 20
 */
void OH_CryptoAsymKeySpec_Destroy(OH_CryptoAsymKeySpec *spec);

/**
 * @brief Specification-based asymmetric key generator structure, representing a specification-based asymmetric key
 * generator.
 * @since 20
 */
typedef struct OH_CryptoAsymKeyGeneratorWithSpec OH_CryptoAsymKeyGeneratorWithSpec;

/**
 * @brief Creates a key generator based on the asymmetric key specification.
 * @param keySpec [in] Asymmetric key specification. Cannot be NULL.
 * @param generator [out] Pointer to the specification-based asymmetric key generator pointer. generator cannot be NULL,
 *     *generator must be NULL.
 * @return <ul>
 *         <li>{@link OH_Crypto_ErrCode#CRYPTO_SUCCESS} if the operation succeeds.</li>
 *         <li>{@link OH_Crypto_ErrCode#CRYPTO_PARAMETER_CHECK_FAILED} if keySpec or generator is NULL,
 *            or key specification parameters are incomplete or invalid.</li>
 *         <li>{@link OH_Crypto_ErrCode#CRYPTO_NOT_SUPPORTED} if the algorithm is not supported.</li>
 *         <li>{@link OH_Crypto_ErrCode#CRYPTO_MEMORY_ERROR} if memory allocation fails.</li>
 *         <li>{@link OH_Crypto_ErrCode#CRYPTO_OPERTION_ERROR} if creating generator fails.</li>
 *         </ul>
 * @release crypto_asym_key/OH_CryptoAsymKeyGeneratorWithSpec_Destroy {generator}
 * @since 20
 * @see {@link OH_CryptoAsymKeyGeneratorWithSpec_GenKeyPair} Generates a key pair based on the asymmetric key
 *     specification.
 */
OH_Crypto_ErrCode OH_CryptoAsymKeyGeneratorWithSpec_Create(OH_CryptoAsymKeySpec *keySpec,
    OH_CryptoAsymKeyGeneratorWithSpec **generator);

/**
 * @brief Generates a key pair based on the asymmetric key specification.
 * @param generator [in] Specification-based asymmetric key generator. Cannot be NULL.
 * @param keyPair [out] Pointer to the key pair pointer. keyPair cannot be NULL, *keyPair must be NULL.
 * @return <ul>
 *         <li>{@link OH_Crypto_ErrCode#CRYPTO_SUCCESS} if the operation succeeds.</li>
 *         <li>{@link OH_Crypto_ErrCode#CRYPTO_PARAMETER_CHECK_FAILED} if generator or keyPair is NULL.</li>
 *         <li>{@link OH_Crypto_ErrCode#CRYPTO_NOT_SUPPORTED} if the operation is not supported.</li>
 *         <li>{@link OH_Crypto_ErrCode#CRYPTO_MEMORY_ERROR} if memory allocation fails.</li>
 *         <li>{@link OH_Crypto_ErrCode#CRYPTO_OPERTION_ERROR} if generating key pair fails. Possible causes:
 *            key specification parameters are incomplete or inconsistent.</li>
 *         </ul>
 * @release crypto_asym_key/OH_CryptoKeyPair_Destroy {keyPair}
 * @since 20
 */
OH_Crypto_ErrCode OH_CryptoAsymKeyGeneratorWithSpec_GenKeyPair(OH_CryptoAsymKeyGeneratorWithSpec *generator,
    OH_CryptoKeyPair **keyPair);

/**
 * @brief Destroys the specification-based asymmetric key generator.
 * @param generator [in] Specification-based asymmetric key generator.
 * @since 20
 */
void OH_CryptoAsymKeyGeneratorWithSpec_Destroy(OH_CryptoAsymKeyGeneratorWithSpec *generator);

/**
 * @brief Elliptic curve point structure, representing a point on the elliptic curve.
 * @since 20
 */
typedef struct OH_CryptoEcPoint OH_CryptoEcPoint;

/**
 * @brief Creates an elliptic curve point.
 * @param curveName [in] NID (Name Identifier) string of the elliptic curve. Cannot be NULL.
 *     e.g. "NID_X9_62_prime256v1", "NID_secp384r1", "NID_secp521r1", "NID_sm2".
 * @param ecKeyData [in] Elliptic curve point data. Supports "04 || x || y", "02 || x", or "03 || x" format.
 *     Can be NULL. If ecKeyData is NULL, an empty elliptic curve point specification is created.
 * @param point [out] Pointer to the elliptic curve point pointer. point cannot be NULL, *point must be NULL.
 * @return <ul>
 *         <li>{@link OH_Crypto_ErrCode#CRYPTO_SUCCESS} if the operation succeeds.</li>
 *         <li>{@link OH_Crypto_ErrCode#CRYPTO_PARAMETER_CHECK_FAILED} if curveName or point is NULL,
 *            or the curve name is invalid.</li>
 *         <li>{@link OH_Crypto_ErrCode#CRYPTO_NOT_SUPPORTED} if the curve is not supported.</li>
 *         <li>{@link OH_Crypto_ErrCode#CRYPTO_MEMORY_ERROR} if memory allocation fails.</li>
 *         <li>{@link OH_Crypto_ErrCode#CRYPTO_OPERTION_ERROR} if creating EC point fails. Possible causes:
 *            the point data format is incorrect.</li>
 *         </ul>
 * @release crypto_asym_key/OH_CryptoEcPoint_Destroy {point}
 * @since 20
 * @see {@link OH_CryptoEcPoint_GetCoordinate} Obtains the x and y coordinates of the elliptic curve point.
 * @see {@link OH_CryptoEcPoint_SetCoordinate} Sets the x and y coordinates of the elliptic curve point.
 */
OH_Crypto_ErrCode OH_CryptoEcPoint_Create(const char *curveName, Crypto_DataBlob *ecKeyData,
    OH_CryptoEcPoint **point);

/**
 * @brief Obtains the x and y coordinates of the elliptic curve point.
 * @param point [in] Elliptic curve point. Cannot be NULL.
 * @param x [out] Pointer to the Crypto_DataBlob structure for storing the x-coordinate. Cannot be NULL.
 *     Initialize x to {0} before calling. Do not pre-allocate x->data.
 * @param y [out] Pointer to the Crypto_DataBlob structure for storing the y-coordinate. Cannot be NULL.
 *     Initialize y to {0} before calling. Do not pre-allocate y->data.
 * @return <ul>
 *         <li>{@link OH_Crypto_ErrCode#CRYPTO_SUCCESS} if the operation succeeds.</li>
 *         <li>{@link OH_Crypto_ErrCode#CRYPTO_PARAMETER_CHECK_FAILED} if point, x, or y is NULL.</li>
 *         <li>{@link OH_Crypto_ErrCode#CRYPTO_NOT_SUPPORTED} if unsupported operation or algorithm.</li>
 *         <li>{@link OH_Crypto_ErrCode#CRYPTO_MEMORY_ERROR} if memory allocation fails.</li>
 *         <li>{@link OH_Crypto_ErrCode#CRYPTO_OPERTION_ERROR} if crypto operation fails.</li>
 *         </ul>
 * @release crypto_common/OH_Crypto_FreeDataBlob {y}
 * @release crypto_common/OH_Crypto_FreeDataBlob {x}
 * @since 20
 */
OH_Crypto_ErrCode OH_CryptoEcPoint_GetCoordinate(OH_CryptoEcPoint *point, Crypto_DataBlob *x, Crypto_DataBlob *y);

/**
 * @brief Sets the x and y coordinates of the elliptic curve point.
 * @param point [in] Elliptic curve point. Cannot be NULL.
 * @param x [in] x-coordinate of the elliptic curve point. This function performs a deep copy of the
 *     data in x and y. The caller can release x and y immediately after the function returns. Cannot be NULL.
 * @param y [in] y-coordinate of the elliptic curve point. Cannot be NULL.
 * @return <ul>
 *         <li>{@link OH_Crypto_ErrCode#CRYPTO_SUCCESS} if the operation succeeds.</li>
 *         <li>{@link OH_Crypto_ErrCode#CRYPTO_PARAMETER_CHECK_FAILED} if point, x, or y is NULL.</li>
 *         <li>{@link OH_Crypto_ErrCode#CRYPTO_NOT_SUPPORTED} if unsupported operation or algorithm.</li>
 *         <li>{@link OH_Crypto_ErrCode#CRYPTO_MEMORY_ERROR} if memory allocation for deep copy fails.</li>
 *         <li>{@link OH_Crypto_ErrCode#CRYPTO_OPERTION_ERROR} if crypto operation fails.</li>
 *         </ul>
 * @since 20
 * @see {@link OH_CryptoEcPoint_Encode} Encodes the elliptic curve point to the specified format.
 */
OH_Crypto_ErrCode OH_CryptoEcPoint_SetCoordinate(OH_CryptoEcPoint *point, Crypto_DataBlob *x, Crypto_DataBlob *y);

/**
 * @brief Encodes the elliptic curve point to the specified format.
 * @param point [in] Elliptic curve point. Cannot be NULL.
 * @param format [in] Encoding format. Cannot be NULL. Supports "UNCOMPRESSED" and "COMPRESSED".
 * @param out [out] Pointer to the Crypto_DataBlob structure for storing the encoded point data. Cannot be NULL.
 *     Initialize out to {0} before calling. Do not pre-allocate out->data.
 * @return <ul>
 *         <li>{@link OH_Crypto_ErrCode#CRYPTO_SUCCESS} if the operation succeeds.</li>
 *         <li>{@link OH_Crypto_ErrCode#CRYPTO_PARAMETER_CHECK_FAILED} if point, format, or out is NULL,
 *            or the format string is not a valid point format.</li>
 *         <li>{@link OH_Crypto_ErrCode#CRYPTO_NOT_SUPPORTED} if the format is not supported.</li>
 *         <li>{@link OH_Crypto_ErrCode#CRYPTO_MEMORY_ERROR} if memory allocation fails.</li>
 *         <li>{@link OH_Crypto_ErrCode#CRYPTO_OPERTION_ERROR} if encoding fails. Possible causes:
 *            the point is not a valid curve point.</li>
 *         </ul>
 * @release crypto_common/OH_Crypto_FreeDataBlob {out}
 * @since 20
 */
OH_Crypto_ErrCode OH_CryptoEcPoint_Encode(OH_CryptoEcPoint *point, const char *format, Crypto_DataBlob *out);

/**
 * @brief Destroys the elliptic curve point.
 * @param point [in] Elliptic curve point.
 * @since 20
 */
void OH_CryptoEcPoint_Destroy(OH_CryptoEcPoint *point);

#ifdef __cplusplus
}
#endif

#endif /* CRYPTO_ASYM_KEY_H */
/** @} */
