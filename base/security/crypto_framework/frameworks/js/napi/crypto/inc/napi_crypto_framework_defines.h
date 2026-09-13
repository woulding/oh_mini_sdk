/*
 * Copyright (C) 2022-2024 Huawei Device Co., Ltd.
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

#ifndef NAPI_CRYPTO_FRAMEWORK_DEFINES_H
#define NAPI_CRYPTO_FRAMEWORK_DEFINES_H

#include <cstdint>
#include <string>

namespace OHOS {
namespace CryptoFramework {
constexpr size_t CALLBACK_SIZE = 1;
constexpr size_t ARGS_SIZE_ONE = 1;
constexpr size_t ARGS_SIZE_TWO = 2;
constexpr size_t ARGS_SIZE_THREE = 3;
constexpr size_t ARGS_SIZE_FOUR = 4;
constexpr size_t GCM_AUTH_TAG_LEN = 16;
constexpr size_t CCM_AUTH_TAG_LEN = 12;
constexpr size_t POLY1305_AUTH_TAG_LEN = 16;
constexpr int32_t PARAM0 = 0;
constexpr int32_t PARAM1 = 1;
constexpr int32_t PARAM2 = 2;
constexpr uint32_t JS_ERR_DEFAULT_ERR = 0;
constexpr uint32_t JS_ERR_INVALID_PARAMS = 401;
constexpr uint32_t JS_ERR_NOT_SUPPORT = 801;
constexpr uint32_t JS_ERR_OUT_OF_MEMORY = 17620001;
constexpr uint32_t JS_ERR_RUNTIME_ERROR = 17620002;
constexpr uint32_t JS_ERR_PARAMETER_CHECK_FAILED = 17620003;
constexpr uint32_t JS_ERR_INVALID_CALL = 17620004;
constexpr uint32_t JS_ERR_CRYPTO_OPERATION = 17630001;

constexpr int32_t SPEC_ITEM_TYPE_BIG_INT = 1;
constexpr int32_t SPEC_ITEM_TYPE_NUM = 2;
constexpr int32_t SPEC_ITEM_TYPE_STR = 3;
constexpr int32_t SPEC_ITEM_TYPE_UINT8ARR = 4;
constexpr int32_t SPEC_ITEM_TYPE_BOOL = 5;

// AsyKeyDataItem types for Key.getKeyData()
// Note: numeric values must be kept in sync with frameworks/js/ani/dts/cryptoFramework.d.ts
constexpr uint32_t ML_DSA_PRIVATE_SEED = 0;
constexpr uint32_t ML_DSA_PRIVATE_RAW = 1;
constexpr uint32_t ML_DSA_PUBLIC_RAW = 2;
constexpr uint32_t ML_KEM_PRIVATE_SEED = 3;
constexpr uint32_t ML_KEM_PRIVATE_RAW = 4;
constexpr uint32_t ML_KEM_PUBLIC_RAW = 5;
constexpr uint32_t EC_PRIVATE_K = 6;
constexpr uint32_t EC_PRIVATE_04_X_Y_K = 7;
constexpr uint32_t EC_PUBLIC_X_Y = 8;
constexpr uint32_t EC_PUBLIC_04_X_Y = 9;
constexpr uint32_t EC_PUBLIC_COMPRESS_X = 10;

const std::string CRYPTO_TAG_DATA = "data";
const std::string CRYPTO_TAG_ERR_CODE = "code";
const std::string CRYPTO_TAG_ERR_MSG = "message";
const std::string CRYPTO_TAG_ALG_NAME = "algName";
const std::string CRYPTO_TAG_FORMAT = "format";
const std::string CRYPTO_TAG_PUB_KEY = "pubKey";
const std::string CRYPTO_TAG_PRI_KEY = "priKey";
const std::string CRYPTO_TAG_COMM_PARAMS = "params";
const std::string IV_PARAMS = "iv";
const std::string NONCE_PARAMS = "nonce";
const std::string AUTHENTICATED_DATA_PARAMS = "authenticatedData";
const std::string TAG_LEN_PARAMS = "tagLen";
const std::string AAD_PARAMS = "aad";
const std::string AUTHTAG_PARAMS = "authTag";
const std::string ALGO_PARAMS = "algName";
const std::string PASSWD_PARAMS = "password";
const std::string CIPHER_PARAMS = "cipherName";
const std::string ALGO_PARAMS_OLD = "algoName";
const std::string IV_PARAMS_SPEC = "IvParamsSpec";
const std::string GCM_PARAMS_SPEC = "GcmParamsSpec";
const std::string CCM_PARAMS_SPEC = "CcmParamsSpec";
const std::string POLY1305_PARAMS_SPEC = "Poly1305ParamsSpec";
const std::string AEAD_PARAMS_SPEC = "AeadParamsSpec";

const std::string DSA_ASY_KEY_SPEC = "DSA";
const std::string ECC_ASY_KEY_SPEC = "ECC";
const std::string RSA_ASY_KEY_SPEC = "RSA";
const std::string X25519_ASY_KEY_SPEC = "X25519";
const std::string ED25519_ASY_KEY_SPEC = "Ed25519";
const std::string DH_ASY_KEY_SPEC = "DH";
const std::string SM2_ASY_KEY_SPEC = "SM2";
const std::string TAG_SPEC_TYPE = "specType";
const std::string DSA_COMM_ASY_KEY_SPEC = "DsaCommParamsSpec";
const std::string DSA_PUB_ASY_KEY_SPEC = "DsaPubKeyParamsSpec";
const std::string DSA_KEYPAIR_ASY_KEY_SPEC = "DsaKeyPairParamsSpec";

const std::string ECC_COMM_ASY_KEY_SPEC = "EccCommParamsSpec";
const std::string ECC_PRI_ASY_KEY_SPEC = "EccPriKeyParamsSpec";
const std::string ECC_PUB_ASY_KEY_SPEC = "EccPubKeyParamsSpec";
const std::string ECC_KEYPAIR_ASY_KEY_SPEC = "EccKeyPairParamsSpec";
const std::string ECC_FIELD_TYPE_FP = "Fp";

const std::string RSA_COMM_ASY_KEY_SPEC = "RsaCommParamsSpec";
const std::string RSA_PUB_ASY_KEY_SPEC = "RsaPubKeyParamsSpec";
const std::string RSA_KEYPAIR_ASY_KEY_SPEC = "RsaKeyPairParamsSpec";

const std::string PBKDF2_ALG_NAME = "PBKDF2";
const std::string PBKDF2_PARAMS_ITER = "iterations";
const std::string PBKDF2_PARAMS_PASSWORD = "password";

const std::string SM2_UTIL_PARAM_X_COORDINATE = "xCoordinate";
const std::string SM2_UTIL_PARAM_Y_COORDINATE = "yCoordinate";
const std::string SM2_UTIL_PARAM_CIPHER_TEXT_DATA = "cipherTextData";
const std::string SM2_UTIL_PARAM_HASH_DATA = "hashData";

const std::string SM2_EC_SIGNATURE_PARAM_R = "r";
const std::string SM2_EC_SIGNATURE_PARAM_S = "s";

const std::string KDF_PARAMS_SALT = "salt";
const std::string KDF_PARAMS_KEY_SIZE = "keySize";

const std::string HKDF_ALG_NAME = "HKDF";
const std::string KDF_PARAMS_KEY = "key";
const std::string KDF_PARAMS_INFO = "info";
const std::string X963KDF_ALG_NAME = "X963KDF";

const std::string MD_NAME = "mdName";
const std::string CIPHER_NAME = "cipherName";
const std::string SCRYPT_ALG_NAME = "SCRYPT";
const std::string SCRYPT_PASSPHRASE = "passphrase";
const std::string SCRYPT_N = "n";
const std::string SCRYPT_R = "r";
const std::string SCRYPT_P = "p";
const std::string SCRYPT_MEMORY = "maxMemory";

} // namespace CryptoFramework
} // namespace OHOS

#endif // NAPI_CRYPTO_FRAMEWORK_DEFINES_H
