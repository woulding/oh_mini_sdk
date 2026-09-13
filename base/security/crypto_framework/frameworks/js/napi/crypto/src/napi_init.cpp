/*
 * Copyright (C) 2022-2024 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include "securec.h"
#include "log.h"

#include "napi_asy_key_generator.h"
#include "napi_asy_key_spec_generator.h"
#include "napi_sym_key_generator.h"
#include "napi_cipher.h"
#include "napi_dh_key_util.h"
#include "napi_ecc_key_util.h"
#include "napi_key_pair.h"
#include "napi_pri_key.h"
#include "napi_pub_key.h"
#include "napi_sign.h"
#include "napi_sm2_crypto_util.h"
#include "napi_verify.h"
#include "napi_key_agreement.h"
#include "napi_mac.h"
#include "napi_md.h"
#include "napi_rand.h"
#include "napi_sym_key.h"
#include "napi_kdf.h"
#include "napi_kem.h"
#include "napi_key.h"
#include "napi_utils.h"
#include "napi_crypto_framework_defines.h"
#include "napi_sm2_ec_signature.h"
#include "key.h"
#include "asy_key_params.h"

namespace OHOS {
namespace CryptoFramework {
static napi_value CreateCryptoMode(napi_env env)
{
    napi_value cryptoMode = nullptr;
    napi_create_object(env, &cryptoMode);

    AddUint32Property(env, cryptoMode, "ENCRYPT_MODE", ENCRYPT_MODE);
    AddUint32Property(env, cryptoMode, "DECRYPT_MODE", DECRYPT_MODE);
    return cryptoMode;
}

static void DefineCryptoModeProperties(napi_env env, napi_value exports)
{
    napi_property_descriptor desc[] = {
        DECLARE_NAPI_PROPERTY("CryptoMode", CreateCryptoMode(env)),
    };
    napi_define_properties(env, exports, sizeof(desc) / sizeof(desc[0]), desc);
}

// enum Result in JS
static napi_value CreateResultCode(napi_env env)
{
    napi_value resultCode = nullptr;
    napi_create_object(env, &resultCode);

    AddUint32Property(env, resultCode, "INVALID_PARAMS", JS_ERR_INVALID_PARAMS);
    AddUint32Property(env, resultCode, "NOT_SUPPORT", JS_ERR_NOT_SUPPORT);
    AddUint32Property(env, resultCode, "ERR_OUT_OF_MEMORY", JS_ERR_OUT_OF_MEMORY);
    AddUint32Property(env, resultCode, "ERR_RUNTIME_ERROR", JS_ERR_RUNTIME_ERROR);
    AddUint32Property(env, resultCode, "ERR_PARAMETER_CHECK_FAILED", JS_ERR_PARAMETER_CHECK_FAILED);
    AddUint32Property(env, resultCode, "ERR_INVALID_CALL", JS_ERR_INVALID_CALL);
    AddUint32Property(env, resultCode, "ERR_CRYPTO_OPERATION", JS_ERR_CRYPTO_OPERATION);

    return resultCode;
}

static void DefineResultCodeProperties(napi_env env, napi_value exports)
{
    napi_property_descriptor desc[] = {
        DECLARE_NAPI_PROPERTY("Result", CreateResultCode(env)),
    };
    napi_define_properties(env, exports, sizeof(desc) / sizeof(desc[0]), desc);
}

// enum AsyKeySpecItem in JS
static napi_value CreateAsyKeySpecItemCode(napi_env env)
{
    napi_value code = nullptr;
    napi_create_object(env, &code);

    AddUint32Property(env, code, "DSA_P_BN", DSA_P_BN);
    AddUint32Property(env, code, "DSA_Q_BN", DSA_Q_BN);
    AddUint32Property(env, code, "DSA_G_BN", DSA_G_BN);
    AddUint32Property(env, code, "DSA_SK_BN", DSA_SK_BN);
    AddUint32Property(env, code, "DSA_PK_BN", DSA_PK_BN);

    AddUint32Property(env, code, "ECC_FP_P_BN", ECC_FP_P_BN);
    AddUint32Property(env, code, "ECC_A_BN", ECC_A_BN);
    AddUint32Property(env, code, "ECC_B_BN", ECC_B_BN);
    AddUint32Property(env, code, "ECC_G_X_BN", ECC_G_X_BN);
    AddUint32Property(env, code, "ECC_G_Y_BN", ECC_G_Y_BN);
    AddUint32Property(env, code, "ECC_N_BN", ECC_N_BN);
    AddUint32Property(env, code, "ECC_H_NUM", ECC_H_INT);
    AddUint32Property(env, code, "ECC_SK_BN", ECC_SK_BN);
    AddUint32Property(env, code, "ECC_PK_X_BN", ECC_PK_X_BN);
    AddUint32Property(env, code, "ECC_PK_Y_BN", ECC_PK_Y_BN);
    AddUint32Property(env, code, "ECC_FIELD_TYPE_STR", ECC_FIELD_TYPE_STR);
    AddUint32Property(env, code, "ECC_FIELD_SIZE_NUM", ECC_FIELD_SIZE_INT);
    AddUint32Property(env, code, "ECC_CURVE_NAME_STR", ECC_CURVE_NAME_STR);

    AddUint32Property(env, code, "RSA_N_BN", RSA_N_BN);
    AddUint32Property(env, code, "RSA_SK_BN", RSA_SK_BN);
    AddUint32Property(env, code, "RSA_PK_BN", RSA_PK_BN);
    AddUint32Property(env, code, "DH_P_BN", DH_P_BN);
    AddUint32Property(env, code, "DH_G_BN", DH_G_BN);
    AddUint32Property(env, code, "DH_L_NUM", DH_L_NUM);
    AddUint32Property(env, code, "DH_PK_BN", DH_PK_BN);
    AddUint32Property(env, code, "DH_SK_BN", DH_SK_BN);
    AddUint32Property(env, code, "ED25519_SK_BN", ED25519_SK_BN);
    AddUint32Property(env, code, "ED25519_PK_BN", ED25519_PK_BN);
    AddUint32Property(env, code, "X25519_SK_BN", X25519_SK_BN);
    AddUint32Property(env, code, "X25519_PK_BN", X25519_PK_BN);
    return code;
}

static void DefineAsyKeySpecItemProperties(napi_env env, napi_value exports)
{
    napi_property_descriptor desc[] = {
        DECLARE_NAPI_PROPERTY("AsyKeySpecItem", CreateAsyKeySpecItemCode(env)),
    };
    napi_define_properties(env, exports, sizeof(desc) / sizeof(desc[0]), desc);
}

// enum AsyKeyDataItem in JS
static napi_value CreateAsyKeyDataItemCode(napi_env env)
{
    napi_value code = nullptr;
    napi_create_object(env, &code);

    AddUint32Property(env, code, "ML_DSA_PRIVATE_SEED", ML_DSA_PRIVATE_SEED);
    AddUint32Property(env, code, "ML_DSA_PRIVATE_RAW", ML_DSA_PRIVATE_RAW);
    AddUint32Property(env, code, "ML_DSA_PUBLIC_RAW", ML_DSA_PUBLIC_RAW);
    AddUint32Property(env, code, "ML_KEM_PRIVATE_SEED", ML_KEM_PRIVATE_SEED);
    AddUint32Property(env, code, "ML_KEM_PRIVATE_RAW", ML_KEM_PRIVATE_RAW);
    AddUint32Property(env, code, "ML_KEM_PUBLIC_RAW", ML_KEM_PUBLIC_RAW);
    AddUint32Property(env, code, "EC_PRIVATE_K", EC_PRIVATE_K);
    AddUint32Property(env, code, "EC_PRIVATE_04_X_Y_K", EC_PRIVATE_04_X_Y_K);
    AddUint32Property(env, code, "EC_PUBLIC_X_Y", EC_PUBLIC_X_Y);
    AddUint32Property(env, code, "EC_PUBLIC_04_X_Y", EC_PUBLIC_04_X_Y);
    AddUint32Property(env, code, "EC_PUBLIC_COMPRESS_X", EC_PUBLIC_COMPRESS_X);
    return code;
}

static void DefineAsyKeyDataItemProperties(napi_env env, napi_value exports)
{
    napi_property_descriptor desc[] = {
        DECLARE_NAPI_PROPERTY("AsyKeyDataItem", CreateAsyKeyDataItemCode(env)),
    };
    napi_define_properties(env, exports, sizeof(desc) / sizeof(desc[0]), desc);
}

// enum AsyKeySpecType in JS
static napi_value CreateAsyKeySpecTypeCode(napi_env env)
{
    napi_value code = nullptr;
    napi_create_object(env, &code);

    AddUint32Property(env, code, "COMMON_PARAMS_SPEC", HCF_COMMON_PARAMS_SPEC);
    AddUint32Property(env, code, "PRIVATE_KEY_SPEC", HCF_PRIVATE_KEY_SPEC);
    AddUint32Property(env, code, "PUBLIC_KEY_SPEC", HCF_PUBLIC_KEY_SPEC);
    AddUint32Property(env, code, "KEY_PAIR_SPEC", HCF_KEY_PAIR_SPEC);
    return code;
}

static void DefineAsyKeySpecTypeProperties(napi_env env, napi_value exports)
{
    napi_property_descriptor desc[] = {
        DECLARE_NAPI_PROPERTY("AsyKeySpecType", CreateAsyKeySpecTypeCode(env)),
    };
    napi_define_properties(env, exports, sizeof(desc) / sizeof(desc[0]), desc);
}

// enum CipherSpecItem in JS
static napi_value CreateCipherSpecItemCode(napi_env env)
{
    napi_value code = nullptr;
    napi_create_object(env, &code);

    AddUint32Property(env, code, "OAEP_MD_NAME_STR", OAEP_MD_NAME_STR);
    AddUint32Property(env, code, "OAEP_MGF_NAME_STR", OAEP_MGF_NAME_STR);
    AddUint32Property(env, code, "OAEP_MGF1_MD_STR", OAEP_MGF1_MD_STR);
    AddUint32Property(env, code, "SM2_MD_NAME_STR", SM2_MD_NAME_STR);
    AddUint32Property(env, code, "OAEP_MGF1_PSRC_UINT8ARR", OAEP_MGF1_PSRC_UINT8ARR);
    return code;
}

static void DefineCipherSpecItemProperties(napi_env env, napi_value exports)
{
    napi_property_descriptor desc[] = {
        DECLARE_NAPI_PROPERTY("CipherSpecItem", CreateCipherSpecItemCode(env)),
    };
    napi_define_properties(env, exports, sizeof(desc) / sizeof(desc[0]), desc);
}

// enum SignSpecItem in JS
static napi_value CreateSignSpecItemCode(napi_env env)
{
    napi_value code = nullptr;
    napi_create_object(env, &code);

    AddUint32Property(env, code, "PSS_MD_NAME_STR", PSS_MD_NAME_STR);
    AddUint32Property(env, code, "PSS_MGF_NAME_STR", PSS_MGF_NAME_STR);
    AddUint32Property(env, code, "PSS_MGF1_MD_STR", PSS_MGF1_MD_STR);
    AddUint32Property(env, code, "PSS_SALT_LEN_NUM", PSS_SALT_LEN_INT);
    AddUint32Property(env, code, "PSS_TRAILER_FIELD_NUM", PSS_TRAILER_FIELD_INT);
    AddUint32Property(env, code, "SM2_USER_ID_UINT8ARR", SM2_USER_ID_UINT8ARR);
    AddUint32Property(env, code, "ML_DSA_DETERMINISTIC_BOOL", ML_DSA_DETERMINISTIC_BOOL);
    AddUint32Property(env, code, "ML_DSA_MU_BOOL", ML_DSA_MU_BOOL);
    AddUint32Property(env, code, "ML_DSA_CONTEXT_UINT8ARR", ML_DSA_CONTEXT_UINT8ARR);
    return code;
}

static void DefineSignSpecItemProperties(napi_env env, napi_value exports)
{
    napi_property_descriptor desc[] = {
        DECLARE_NAPI_PROPERTY("SignSpecItem", CreateSignSpecItemCode(env)),
    };
    napi_define_properties(env, exports, sizeof(desc) / sizeof(desc[0]), desc);
}

// enum HcfKemAlgNameId in JS
static napi_value CreateHcfKemAlgNameIdCode(napi_env env)
{
    napi_value code = nullptr;
    napi_create_object(env, &code);

    AddUint32Property(env, code, "ML_KEM_512", ML_KEM_512);
    AddUint32Property(env, code, "ML_KEM_768", ML_KEM_768);
    AddUint32Property(env, code, "ML_KEM_1024", ML_KEM_1024);
    return code;
}

static void DefineHcfKemAlgNameIdProperties(napi_env env, napi_value exports)
{
    napi_property_descriptor desc[] = {
        DECLARE_NAPI_PROPERTY("KemAlgNameId", CreateHcfKemAlgNameIdCode(env)),
    };
    napi_define_properties(env, exports, sizeof(desc) / sizeof(desc[0]), desc);
}

/***********************************************
 * Module export and register
 ***********************************************/
static napi_value ModuleExport(napi_env env, napi_value exports)
{
    LOGD("module init start.");

    DefineCryptoModeProperties(env, exports);
    DefineResultCodeProperties(env, exports);
    DefineAsyKeySpecItemProperties(env, exports);
    DefineAsyKeyDataItemProperties(env, exports);
    DefineAsyKeySpecTypeProperties(env, exports);
    DefineCipherSpecItemProperties(env, exports);
    DefineSignSpecItemProperties(env, exports);
    DefineHcfKemAlgNameIdProperties(env, exports);

    NapiKey::DefineHcfKeyJSClass(env);
    NapiPubKey::DefinePubKeyJSClass(env);
    NapiPriKey::DefinePriKeyJSClass(env);
    NapiKeyPair::DefineKeyPairJSClass(env);
    NapiSymKey::DefineSymKeyJSClass(env);

    NapiAsyKeyGenerator::DefineAsyKeyGeneratorJSClass(env, exports);
    NapiAsyKeyGeneratorBySpec::DefineAsyKeyGeneratorBySpecJSClass(env, exports);
    NapiSymKeyGenerator::DefineSymKeyGeneratorJSClass(env, exports);

    NapiSign::DefineSignJSClass(env, exports);
    NapiVerify::DefineVerifyJSClass(env, exports);
    NapiKeyAgreement::DefineKeyAgreementJSClass(env, exports);
    NapiMac::DefineMacJSClass(env, exports);
    NapiMd::DefineMdJSClass(env, exports);
    NapiRand::DefineRandJSClass(env, exports);
    NapiCipher::DefineCipherJSClass(env, exports);
    NapiKdf::DefineKdfJSClass(env, exports);
    NapiKem::DefineKemJSClass(env, exports);
    NapiECCKeyUtil::DefineNapiECCKeyUtilJSClass(env, exports);
    NapiDHKeyUtil::DefineNapiDHKeyUtilJSClass(env, exports);
    NapiSm2CryptoUtil::DefineNapiSm2CryptoUtilJSClass(env, exports);
    NapiSm2EcSignature::DefineNapiSm2EcSignatureJSClass(env, exports);
    LOGD("module init end.");
    return exports;
}

extern "C" __attribute__((constructor)) void RegisterModule(void)
{
    static napi_module cryptoFrameworkModule = {
        .nm_version = 1,
        .nm_flags = 0,
        .nm_filename = nullptr,
        .nm_register_func = ModuleExport,
        .nm_modname = "security.cryptoFramework",
        .nm_priv = nullptr,
        .reserved = { nullptr },
    };
    napi_module_register(&cryptoFrameworkModule);
}
}  // namespace CryptoFramework
}  // namespace OHOS
