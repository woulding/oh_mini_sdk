/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
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
#ifndef CRYPTO_FFI_H
#define CRYPTO_FFI_H

#include "asy_key_generator_impl.h"
#include "asy_key_spec_generator_impl.h"
#include "cipher_impl.h"
#include "dh_key_util_impl.h"
#include "detailed_iv_params.h"
#include "detailed_gcm_params.h"
#include "detailed_ccm_params.h"
#include "detailed_dsa_key_params.h"
#include "detailed_ecc_key_params.h"
#include "detailed_rsa_key_params.h"
#include "detailed_alg_25519_key_params.h"
#include "detailed_dh_key_params.h"
#include "ecc_key_util_impl.h"
#include "kdf_impl.h"
#include "key_agreement_impl.h"
#include "key_pair_impl.h"
#include "mac_impl.h"
#include "md_impl.h"
#include "pri_key_impl.h"
#include "pub_key_impl.h"
#include "random_impl.h"
#include "securec.h"
#include "sign_impl.h"
#include "sm2_crypto_util_impl.h"
#include "sym_key_generator_impl.h"
#include "sym_key_impl.h"
#include "verify_impl.h"
#include "detailed_hmac_params.h"

extern "C" {
    typedef struct {
        HcfBlob iv;
        HcfBlob add;
        HcfBlob authTag;
    } CParamsSpec;

    // random
    FFI_EXPORT int64_t FfiOHOSCreateRandom(int32_t* errCode);
    FFI_EXPORT const char *FfiOHOSRandomGetAlgName(int64_t id, int32_t* errCode);
    FFI_EXPORT HcfBlob FfiOHOSGenerateRandom(int64_t id, int32_t numBytes, int32_t* errCode);
    FFI_EXPORT void FfiOHOSSetSeed(int64_t id, HcfBlob *seed, int32_t* errCode);

    // md
    FFI_EXPORT int64_t FfiOHOSCreateMd(char* algName, int32_t* errCode);
    FFI_EXPORT int32_t FfiOHOSMdUpdate(int64_t id, HcfBlob *input);
    FFI_EXPORT HcfBlob FfiOHOSDigest(int64_t id, int32_t* errCode);
    FFI_EXPORT uint32_t FfiOHOSGetMdLength(int64_t id, int32_t* errCode);

    // symkeygenerator
    FFI_EXPORT int64_t FfiOHOSCreateSymKeyGenerator(char* algName, int32_t* errCode);
    FFI_EXPORT const char *FfiOHOSSymKeyGeneratorGetAlgName(int64_t id, int32_t* errCode);
    FFI_EXPORT int64_t FfiOHOSGenerateSymKey(int64_t id, int32_t* errCode);
    FFI_EXPORT int64_t FfiOHOSConvertKey(int64_t id, HcfBlob *key, int32_t* errCode);

    // symkey
    FFI_EXPORT const char *FfiOHOSSymKeyGetAlgName(int64_t id, int32_t* errCode);
    FFI_EXPORT const char *FfiOHOSSymKeyGetFormat(int64_t id, int32_t* errCode);
    FFI_EXPORT int32_t FfiOHOSSymKeyGetEncoded(int64_t id, HcfBlob *returnBlob);
    FFI_EXPORT void FfiOHOSClearMem(int64_t id);
    FFI_EXPORT void* FfiOHOSSymKeyGetHcfKey(int64_t id);

    // cipher
    FFI_EXPORT int64_t FfiOHOSCreateCipher(char* transformation, int32_t* errCode);
    FFI_EXPORT int32_t FfiOHOSCipherInitByIv(int64_t id, int32_t opMode, void* key, HcfBlob blob1);
    FFI_EXPORT int32_t FfiOHOSCipherInitByGcm(int64_t id, int32_t opMode, void* key, CParamsSpec spec);
    FFI_EXPORT int32_t FfiOHOSCipherInitByCcm(int64_t id, int32_t opMode, void* key, CParamsSpec spec);
    FFI_EXPORT int32_t FfiOHOSCipherInitWithOutParams(int64_t id, int32_t opMode, void* key);
    FFI_EXPORT int32_t FfiOHOSCipherUpdate(int64_t id, HcfBlob *input, HcfBlob *output);
    FFI_EXPORT int32_t FfiOHOSCipherDoFinal(int64_t id, HcfBlob *input, HcfBlob *output);
    FFI_EXPORT int32_t FfiOHOSSetCipherSpec(int64_t id, int32_t item, HcfBlob pSource);
    FFI_EXPORT char *FfiOHOSGetCipherSpecString(int64_t id, int32_t item, int32_t *errCode);
    FFI_EXPORT int32_t FfiOHOSGetCipherSpecUint8Array(int64_t id, int32_t item, HcfBlob *returnUint8Array);
    FFI_EXPORT const char *FfiOHOSCipherGetAlgName(int64_t id, int32_t* errCode);

    // mac
    FFI_EXPORT int64_t FFiOHOSCryptoMacConstructor(char* algName, int32_t* errCode);
    FFI_EXPORT int32_t FfiOHOSCryptoMacInit(int64_t id, int64_t symKeyId);
    FFI_EXPORT int32_t FfiOHOSCryptoMacUpdate(int64_t id, HcfBlob *input);
    FFI_EXPORT HcfBlob FfiOHOSCryptoMacDoFinal(int64_t id, int32_t* errCode);
    FFI_EXPORT uint32_t FfiOHOSCryptoGetMacLength(int64_t id);

    // sign
    FFI_EXPORT int64_t FFiOHOSCryptoSignConstructor(char* algName, int32_t* errCode);
    FFI_EXPORT int32_t FFiOHOSSignInit(int64_t sid, int64_t pid);
    FFI_EXPORT int32_t FFiOHOSSignUpdate(int64_t id, HcfBlob input);
    FFI_EXPORT int32_t FFiOHOSSignSign(int64_t id, HcfBlob *input, HcfBlob *output);
    FFI_EXPORT int32_t FFiOHOSSignSetSignSpecByNum(int64_t id, int32_t itemValue);
    FFI_EXPORT int32_t FFiOHOSSignSetSignSpecByArr(int64_t id, HcfBlob itemValue);
    FFI_EXPORT char *FFiOHOSSignGetSignSpecString(int64_t id, SignSpecItem item, int32_t *errCode);
    FFI_EXPORT int32_t FFiOHOSSignGetSignSpecNum(int64_t id, SignSpecItem item, int32_t *itemValue);

    // verify
    FFI_EXPORT int64_t FFiOHOSVerifyConstructor(char* algName, int32_t* errCode);
    FFI_EXPORT int32_t FFiOHOSVerifyInit(int64_t vid, int64_t pid);
    FFI_EXPORT int32_t FFiOHOSVerifyUpdate(int64_t id, HcfBlob input);
    FFI_EXPORT bool FFiOHOSVerifyVerify(int64_t id, HcfBlob *data, HcfBlob signatureData, int32_t* errCode);
    FFI_EXPORT int32_t FFiOHOSVerifyRecover(int64_t id, HcfBlob input, HcfBlob *output);
    FFI_EXPORT int32_t FFiOHOSVerifySetVerifySpecByNum(int64_t id, int32_t itemValue);
    FFI_EXPORT int32_t FFiOHOSVerifySetVerifySpecByArr(int64_t id, HcfBlob itemValue);
    FFI_EXPORT char *FFiOHOSVerifyGetVerifySpecString(int64_t id, SignSpecItem item, int32_t *errCode);
    FFI_EXPORT int32_t FFiOHOSVerifyGetVerifySpecNum(int64_t id, SignSpecItem item, int32_t *itemValue);

    // asykeygenerator
    FFI_EXPORT int64_t FFiOHOSAsyKeyGeneratorConstructor(char *algName, int32_t *errCode);
    FFI_EXPORT int64_t FFiOHOSAsyKeyGeneratorGenerateKeyPair(int64_t id, int32_t *errCode);
    FFI_EXPORT int64_t FFiOHOSAsyKeyGeneratorConvertKey(int64_t id, HcfBlob *pubKey, HcfBlob *priKey, int32_t *errCode);
    FFI_EXPORT int64_t FFiOHOSAsyKeyGeneratorConvertPemKey(int64_t id, char *pubKey, char *priKey, int32_t *errCode);

    // asykeyspecgenerator
    FFI_EXPORT int64_t FFiOHOSAsyKeyGeneratorByDsaCommonSpec(HcfDsaCommParamsSpec *spec, int32_t *errCode);
    FFI_EXPORT int64_t FFiOHOSAsyKeyGeneratorByDsaPubKeySpec(HcfDsaPubKeyParamsSpec *spec, int32_t *errCode);
    FFI_EXPORT int64_t FFiOHOSAsyKeyGeneratorByDsaKeyPairSpec(HcfDsaKeyPairParamsSpec *spec, int32_t *errCode);
    FFI_EXPORT int64_t FFiOHOSAsyKeyGeneratorByEccCommonSpec(HcfEccCommParamsSpec *spec, int32_t *errCode);
    FFI_EXPORT int64_t FFiOHOSAsyKeyGeneratorByEccPriKeySpec(HcfEccPriKeyParamsSpec *spec, int32_t *errCode);
    FFI_EXPORT int64_t FFiOHOSAsyKeyGeneratorByEccPubKeySpec(HcfEccPubKeyParamsSpec *spec, int32_t *errCode);
    FFI_EXPORT int64_t FFiOHOSAsyKeyGeneratorByEccKeyPairSpec(HcfEccKeyPairParamsSpec *spec, int32_t *errCode);
    FFI_EXPORT int64_t FFiOHOSAsyKeyGeneratorByRsaPubKeySpec(HcfRsaPubKeyParamsSpec *spec, int32_t *errCode);
    FFI_EXPORT int64_t FFiOHOSAsyKeyGeneratorByRsaKeyPairSpec(HcfRsaKeyPairParamsSpec *spec, int32_t *errCode);
    FFI_EXPORT int64_t FFiOHOSAsyKeyGeneratorByAlg25519PriKeySpec(HcfAlg25519PriKeyParamsSpec *spec, int32_t *errCode);
    FFI_EXPORT int64_t FFiOHOSAsyKeyGeneratorByAlg25519PubKeySpec(HcfAlg25519PubKeyParamsSpec *spec, int32_t *errCode);
    FFI_EXPORT int64_t FFiOHOSAsyKeyGeneratorByAlg25519KeyPairSpec(
        HcfAlg25519KeyPairParamsSpec *spec, int32_t *errCode);
    FFI_EXPORT int64_t FFiOHOSAsyKeyGeneratorByDhPriKeySpec(HcfDhPriKeyParamsSpec *spec, int32_t *errCode);
    FFI_EXPORT int64_t FFiOHOSAsyKeyGeneratorByDhPubKeySpec(HcfDhPubKeyParamsSpec *spec, int32_t *errCode);
    FFI_EXPORT int64_t FFiOHOSAsyKeyGeneratorByDhKeyPairSpec(HcfDhKeyPairParamsSpec *spec, int32_t *errCode);
    FFI_EXPORT int64_t FFiOHOSAsyKeyGeneratorByDhCommonSpec(HcfDhCommParamsSpec *spec, int32_t *errCode);
    FFI_EXPORT int64_t FFiOHOSAsyKeyGeneratorBySpecGenerateKeyPair(int64_t id, int32_t *errCode);
    FFI_EXPORT int64_t FFiOHOSAsyKeyGeneratorBySpecGeneratePriKey(int64_t id, int32_t *errCode);
    FFI_EXPORT int64_t FFiOHOSAsyKeyGeneratorBySpecGeneratePubKey(int64_t id, int32_t *errCode);

    // prikey
    FFI_EXPORT HcfBlob FFiOHOSPriKeyGetEncoded(int64_t id, int32_t *errCode);
    FFI_EXPORT HcfBlob FFiOHOSPriKeyGetEncodedDer(int64_t id, char *format, int32_t *errCode);
    FFI_EXPORT char *FFiOHOSPriKeyGetEncodedPem(int64_t id, char *format, int32_t *errCode);
    FFI_EXPORT int32_t FFiOHOSPriKeyClearMem(int64_t id);
    FFI_EXPORT int FFiOHOSPriKeyGetAsyKeySpecByNum(int64_t id, int32_t itemType, int32_t *errCode);
    FFI_EXPORT char *FFiOHOSPriKeyGetAsyKeySpecByStr(int64_t id, int32_t itemType, int32_t *errCode);
    FFI_EXPORT HcfBigInteger FFiOHOSPriKeyGetAsyKeySpecByBigInt(int64_t id, int32_t itemType, int32_t *errCode);
    FFI_EXPORT const char *FfiOHOSPriKeyGetFormat(int64_t id, int32_t* errCode);

    // pubkey
    FFI_EXPORT HcfBlob FFiOHOSPubKeyGetEncoded(int64_t id, int32_t *errCode);
    FFI_EXPORT HcfBlob FFiOHOSPubKeyGetEncodedDer(int64_t id, char *format, int32_t *errCode);
    FFI_EXPORT char *FFiOHOSPubKeyGetEncodedPem(int64_t id, char *format, int32_t *errCode);
    FFI_EXPORT int FFiOHOSPubKeyGetAsyKeySpecByNum(int64_t id, int32_t itemType, int32_t *errCode);
    FFI_EXPORT char *FFiOHOSPubKeyGetAsyKeySpecByStr(int64_t id, int32_t itemType, int32_t *errCode);
    FFI_EXPORT HcfBigInteger FFiOHOSPubKeyGetAsyKeySpecByBigInt(int64_t id, int32_t itemType, int32_t *errCode);
    FFI_EXPORT const char *FfiOHOSPubKeyGetFormat(int64_t id, int32_t* errCode);
    FFI_EXPORT void *FfiOHOSPubKeyGetRawPointer(int64_t id);
    FFI_EXPORT int64_t FfiOHOSPubKeyFromRawPointer(void *ptr, const char **retString, int32_t *errCode);

    // keypair
    FFI_EXPORT int64_t FFiOHOSKeyPairPubKey(int64_t id, int32_t *errCode);
    FFI_EXPORT int64_t FFiOHOSKeyPairPriKey(int64_t id, int32_t *errCode);

    // kdf
    FFI_EXPORT int64_t FFiOHOSKdfConstructor(char *algName, int32_t *errCode);
    FFI_EXPORT int32_t FFiOHOSKdfGenerateSecretByPB(int64_t id, HcfPBKDF2ParamsSpec *params);
    FFI_EXPORT int32_t FFiOHOSKdfGenerateSecretByH(int64_t id, HcfHkdfParamsSpec *params);

    // ecc_key_util
    FFI_EXPORT HcfEccCommParamsSpec *FFiOHOSECCKeyUtilGenECCCommonParamsSpec(char *curveName, int32_t *errCode);
    FFI_EXPORT HcfPoint FFiOHOSECCKeyUtilConvertPoint(char *curveName, HcfBlob encodedPoint, int32_t *errCode);
    FFI_EXPORT HcfBlob FFiOHOSECCKeyUtilGetEncodedPoint(
        char *curveName, HcfPoint point, char *format, int32_t *errCode);

    // keyagreement
    FFI_EXPORT int64_t FFiOHOSKeyAgreementConstructor(char *algName, int32_t *errCode);
    FFI_EXPORT HcfBlob FFiOHOSKeyAgreementGenerateSecret(int64_t id, int64_t priId, int64_t pubId, int32_t *errCode);

    // dh_key_util
    FFI_EXPORT HcfDhCommParamsSpec *FFiOHOSDHKeyUtilGenDHCommonParamsSpec(
        int32_t pLen, int32_t skLen, int32_t *errCode);

    // sm2_crypto_util
    FFI_EXPORT HcfBlob FFiOHOSSm2CryptoUtilGenCipherTextBySpec(Sm2CipherTextSpec spec, char *mode, int32_t *errCode);
    FFI_EXPORT Sm2CipherTextSpec *FFiOHOSSm2CryptoUtilGetCipherTextSpec(HcfBlob input, char *mode, int32_t *errCode);
}

#endif
