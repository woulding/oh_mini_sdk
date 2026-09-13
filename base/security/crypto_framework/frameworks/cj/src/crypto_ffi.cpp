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
#include "crypto_ffi.h"

#define MAX_MEMORY_SIZE (5 * 1024 * 1024)

using namespace OHOS::FFI;

namespace OHOS {
    namespace CryptoFramework {
        extern "C" {
            //-------------------random
            int64_t FfiOHOSCreateRandom(int32_t* errCode)
            {
                LOGD("[Random] CreateRandom start");
                HcfRand *randObj = nullptr;
                HcfResult res = HcfRandCreate(&randObj);
                *errCode = static_cast<int32_t>(res);
                if (res != HCF_SUCCESS) {
                    LOGE("create c randObj failed.");
                    return 0;
                }
                auto native = FFIData::Create<RandomImpl>(randObj);
                if (!native) {
                    LOGE("[Random] CreateRandom failed");
                    HcfObjDestroy(randObj);
                    *errCode = HCF_ERR_MALLOC;
                    return 0;
                }
                LOGD("[Randome] CreateRandom success");
                return native->GetID();
            }

            const char *FfiOHOSRandomGetAlgName(int64_t id, int32_t* errCode)
            {
                LOGD("[Random] GetAlgName start");
                auto instance = FFIData::GetData<RandomImpl>(id);
                if (!instance) {
                    LOGE("[Random] instance not exist.");
                    *errCode = HCF_ERR_MALLOC;
                    return nullptr;
                }
                const char* res = instance->GetAlgName(errCode);
                LOGD("[Randome] GetAlgName success");
                return res;
            }

            HcfBlob FfiOHOSGenerateRandom(int64_t id, int32_t numBytes, int32_t* errCode)
            {
                LOGD("[Random] GenerateRandom start");
                HcfBlob randBlob = { .data = nullptr, .len = 0 };
                auto instance = FFIData::GetData<RandomImpl>(id);
                if (!instance) {
                    LOGE("[Random] instance not exist.");
                    *errCode = HCF_ERR_MALLOC;
                    return randBlob;
                }
                randBlob = instance->GenerateRandom(numBytes, errCode);
                LOGD("[Randome] GenerateRandom success");
                return randBlob;
            }

            void FfiOHOSSetSeed(int64_t id, HcfBlob *seed, int32_t* errCode)
            {
                LOGD("[Random] SetSeed start");
                auto instance = FFIData::GetData<RandomImpl>(id);
                if (!instance) {
                    LOGE("[Random] instance not exist.");
                    *errCode = HCF_ERR_MALLOC;
                    return;
                }
                instance->SetSeed(seed, errCode);
                LOGD("[Randome] SetSeed success");
            }

            //--------------------- md
            int64_t FfiOHOSCreateMd(char* algName, int32_t* errCode)
            {
                LOGD("[Md] CreateMd start");
                HcfMd *mdObj = nullptr;
                HcfResult res = HcfMdCreate(algName, &mdObj);
                *errCode = static_cast<int32_t>(res);
                if (res != HCF_SUCCESS) {
                    LOGE("create c mdObj failed.");
                    return 0;
                }
                auto native = FFIData::Create<MdImpl>(mdObj);
                if (!native) {
                    LOGE("[Md] CreateMd failed");
                    HcfObjDestroy(mdObj);
                    *errCode = HCF_ERR_MALLOC;
                    return 0;
                }
                LOGD("[Md] CreateMd success");
                return native->GetID();
            }

            int32_t FfiOHOSMdUpdate(int64_t id, HcfBlob *input)
            {
                LOGD("[Md] FfiOHOSMdUpdate start");
                HcfResult res = HCF_ERR_MALLOC;
                auto instance = FFIData::GetData<MdImpl>(id);
                if (!instance) {
                    LOGE("[Md] instance not exist.");
                    return res;
                }
                res = instance->MdUpdate(input);
                LOGD("[Md] FfiOHOSMdUpdate success");
                return res;
            }

            HcfBlob FfiOHOSDigest(int64_t id, int32_t* errCode)
            {
                LOGD("[Md] FfiOHOSDigest start");
                auto instance = FFIData::GetData<MdImpl>(id);
                HcfBlob blob = { .data = nullptr, .len = 0};
                if (!instance) {
                    LOGE("[Md] instance not exist.");
                    *errCode = HCF_ERR_MALLOC;
                    return blob;
                }
                HcfResult res = instance->MdDoFinal(&blob);
                *errCode = static_cast<int32_t>(res);
                if (res != HCF_SUCCESS) {
                    LOGE("doFinal failed!");
                    return blob;
                }
                LOGD("[Md] FfiOHOSDigest success");
                return blob;
            }

            uint32_t FfiOHOSGetMdLength(int64_t id, int32_t* errCode)
            {
                LOGD("[Md] FfiOHOSGetMdLength start");
                auto instance = FFIData::GetData<MdImpl>(id);
                uint32_t res = 0;
                if (!instance) {
                    LOGE("[Md] instance not exist.");
                    *errCode = HCF_ERR_MALLOC;
                    return res;
                }
                res = instance->GetMdLength(errCode);
                LOGD("[Md] FfiOHOSGetMdLength success");
                return res;
            }

            //-------------------symkeygenerator
            int64_t FfiOHOSCreateSymKeyGenerator(char* algName, int32_t* errCode)
            {
                LOGD("[SymKeyGenerator] CreateSymKeyGenerator start");
                HcfSymKeyGenerator *generator = nullptr;
                HcfResult res = HcfSymKeyGeneratorCreate(algName, &generator);
                *errCode = static_cast<int32_t>(res);
                if (res != HCF_SUCCESS) {
                    LOGE("create C generator fail.");
                    return 0;
                }
                auto native = FFIData::Create<SymKeyGeneratorImpl>(generator);
                if (native == nullptr) {
                    LOGE("[SymKeyGenerator] CreateSymKeyGenerator failed");
                    HcfObjDestroy(generator);
                    *errCode = HCF_ERR_MALLOC;
                    return 0;
                }
                LOGD("[SymKeyGenerator] CreateSymKeyGenerator success");
                return native->GetID();
            }

            const char* FfiOHOSSymKeyGeneratorGetAlgName(int64_t id, int32_t* errCode)
            {
                LOGD("[SymKeyGenerator] GetAlgName start");
                auto instance = FFIData::GetData<SymKeyGeneratorImpl>(id);
                if (!instance) {
                    LOGE("[SymKeyGenerator] instance not exist.");
                    *errCode = HCF_ERR_MALLOC;
                    return nullptr;
                }
                const char* res = instance->GetAlgName(errCode);
                LOGD("[SymKeyGenerator] GetAlgName success");
                return res;
            }

            int64_t FfiOHOSGenerateSymKey(int64_t id, int32_t* errCode)
            {
                LOGD("[SymKeyGenerator] GenerateSymKey start");
                auto instance = FFIData::GetData<SymKeyGeneratorImpl>(id);
                if (!instance) {
                    LOGE("[SymKeyGenerator] instance not exist.");
                    *errCode = HCF_ERR_MALLOC;
                    return 0;
                }
                HcfSymKey *key = nullptr;
                HcfResult res = instance->GenerateSymKey(&key);
                *errCode = static_cast<int32_t>(res);
                if (res != HCF_SUCCESS) {
                    LOGE("generate sym key failed.");
                    return 0;
                }
                auto native = FFIData::Create<SymKeyImpl>(key);
                if (native == nullptr) {
                    LOGE("[SymKeyGenerator] GenerateSymKey failed");
                    HcfObjDestroy(key);
                    *errCode = HCF_ERR_MALLOC;
                    return 0;
                }
                LOGD("[SymKeyGenerator] GenerateSymKey success");
                return native->GetID();
            }

            int64_t FfiOHOSConvertKey(int64_t id, HcfBlob *key, int32_t* errCode)
            {
                LOGD("[SymKeyGenerator] ConvertKey start");
                auto instance = FFIData::GetData<SymKeyGeneratorImpl>(id);
                if (!instance) {
                    LOGE("[SymKeyGenerator] instance not exist.");
                    *errCode = HCF_ERR_MALLOC;
                    return 0;
                }
                HcfSymKey *symkey = nullptr;
                HcfResult res = instance->ConvertKey(*key, &symkey);
                *errCode = static_cast<int32_t>(res);
                if (res != HCF_SUCCESS) {
                    LOGE("generate sym key failed.");
                    return 0;
                }
                auto native = FFIData::Create<SymKeyImpl>(symkey);
                if (native == nullptr) {
                    LOGE("[SymKeyGenerator] ConvertKey failed");
                    HcfObjDestroy(symkey);
                    *errCode = HCF_ERR_MALLOC;
                    return 0;
                }
                LOGD("[SymKeyGenerator] ConvertKey success");
                return native->GetID();
            }

            //-------------------symkey
            const char *FfiOHOSSymKeyGetAlgName(int64_t id, int32_t* errCode)
            {
                LOGD("[SymKey] GetAlgName start");
                auto instance = FFIData::GetData<SymKeyImpl>(id);
                if (!instance) {
                    LOGE("[SymKey] instance not exist.");
                    *errCode = HCF_ERR_MALLOC;
                    return nullptr;
                }
                const char* res = instance->GetAlgorithm(errCode);
                LOGD("[SymKey] GetAlgName success");
                return res;
            }

            const char *FfiOHOSSymKeyGetFormat(int64_t id, int32_t* errCode)
            {
                LOGD("[SymKey] GetFormat start");
                auto instance = FFIData::GetData<SymKeyImpl>(id);
                if (!instance) {
                    LOGE("[SymKey] instance not exist.");
                    *errCode = HCF_ERR_MALLOC;
                    return nullptr;
                }
                const char* res = instance->GetFormat(errCode);
                LOGD("[SymKey] GetFormat success");
                return res;
            }

            int32_t FfiOHOSSymKeyGetEncoded(int64_t id, HcfBlob *returnBlob)
            {
                LOGD("[SymKey] GetEncoded start");
                auto instance = FFIData::GetData<SymKeyImpl>(id);
                if (!instance) {
                    LOGE("[SymKey] instance not exist.");
                    return HCF_ERR_MALLOC;
                }
                HcfResult res = instance->GetEncoded(returnBlob);
                LOGD("[SymKey] GetEncoded success");
                return res;
            }

            void FfiOHOSClearMem(int64_t id)
            {
                LOGD("[SymKey] ClearMem start");
                auto instance = FFIData::GetData<SymKeyImpl>(id);
                if (!instance) {
                    LOGE("[SymKey] instance not exist.");
                    return;
                }
                instance->ClearMem();
                LOGD("[SymKey] ClearMem success");
            }

            void* FfiOHOSSymKeyGetHcfKey(int64_t id)
            {
                LOGD("[SymKey] GetHcfKey start");
                auto instance = FFIData::GetData<SymKeyImpl>(id);
                if (!instance) {
                    LOGE("[SymKey] instance not exist.");
                    return nullptr;
                }
                HcfKey *key = instance->GetHcfKey();
                LOGD("[SymKey] GetHcfKey success");
                return key;
            }

            // cipher
            const std::string IV_PARAMS_SPEC = "IvParamsSpec";
            const std::string GCM_PARAMS_SPEC = "GcmParamsSpec";
            const std::string CCM_PARAMS_SPEC = "CcmParamsSpec";
            const size_t GCM_AUTH_TAG_LEN = 16;
            const size_t CCM_AUTH_TAG_LEN = 12;
            static const char *GetIvParamsSpecType()
            {
                return IV_PARAMS_SPEC.c_str();
            }

            static const char *GetGcmParamsSpecType()
            {
                return GCM_PARAMS_SPEC.c_str();
            }

            static const char *GetCcmParamsSpecType()
            {
                return CCM_PARAMS_SPEC.c_str();
            }

            void *HcfMalloc(uint32_t size, char val)
            {
                if ((size == 0) || (size > MAX_MEMORY_SIZE)) {
                    LOGE("malloc size is invalid");
                    return nullptr;
                }
                void *addr = malloc(size);
                if (addr != nullptr) {
                    (void)memset_s(addr, size, val, size);
                }
                return addr;
            }

            void HcfFree(void *addr)
            {
                if (addr != nullptr) {
                    free(addr);
                }
            }

            int64_t FfiOHOSCreateCipher(char* transformation, int32_t* errCode)
            {
                LOGD("[Cipher] CreateCipher start");
                HcfCipher *cipher = nullptr;
                HcfResult res = HcfCipherCreate(transformation, &cipher);
                *errCode = static_cast<int32_t>(res);
                if (res != HCF_SUCCESS) {
                    LOGE("create C cipher fail!");
                    return 0;
                }
                auto native = FFIData::Create<CipherImpl>(cipher);
                if (native == nullptr) {
                    LOGE("[Cipher] CreateCipher failed");
                    HcfObjDestroy(cipher);
                    *errCode = HCF_ERR_MALLOC;
                    return 0;
                }
                LOGD("[Cipher] CreateCipher success");
                return native->GetID();
            }

            int32_t FfiOHOSCipherInitByIv(int64_t id, int32_t opMode, void* key, HcfBlob blob1)
            {
                LOGD("[Cipher] FfiOHOSCipherInitByIv start");
                if (key == nullptr) {
                    LOGE("[Cipher] key can not be nullptr.");
                    return HCF_INVALID_PARAMS;
                }
                auto instance = FFIData::GetData<CipherImpl>(id);
                if (!instance) {
                    LOGE("[Cipher] instance not exist.");
                    return HCF_ERR_MALLOC;
                }
                HcfIvParamsSpec *ivParamsSpec = reinterpret_cast<HcfIvParamsSpec *>(
                        HcfMalloc(sizeof(HcfIvParamsSpec), 0));
                if (ivParamsSpec == nullptr) {
                    LOGE("ivParamsSpec malloc failed!");
                    return HCF_INVALID_PARAMS;
                }
                ivParamsSpec->base.getType = GetIvParamsSpecType;
                ivParamsSpec->iv = blob1;
                HcfCryptoMode mode = HcfCryptoMode(opMode);
                HcfParamsSpec *paramsSpec = reinterpret_cast<HcfParamsSpec *>(ivParamsSpec);
                ivParamsSpec = nullptr;
                HcfResult res = instance->CipherInit(mode, static_cast<HcfKey*>(key), paramsSpec);
                HcfFree(paramsSpec);
                paramsSpec = nullptr;
                LOGD("[Cipher] FfiOHOSCipherInitByIv success");
                return res;
            }

            int32_t FfiOHOSCipherInitByGcm(int64_t id, int32_t opMode, void* key, CParamsSpec spec)
            {
                LOGD("[Cipher] FfiOHOSCipherInitByGcm start");
                if (key == nullptr) {
                    LOGE("[Cipher] key can not be nullptr.");
                    return HCF_INVALID_PARAMS;
                }
                auto instance = FFIData::GetData<CipherImpl>(id);
                if (!instance) {
                    LOGE("[Cipher] instance not exist.");
                    return HCF_ERR_MALLOC;
                }
                HcfGcmParamsSpec *gcmParamsSpec = reinterpret_cast<HcfGcmParamsSpec *>(
                                                    HcfMalloc(sizeof(HcfGcmParamsSpec), 0));
                if (gcmParamsSpec == nullptr) {
                    LOGE("gcmParamsSpec malloc failed!");
                    return HCF_INVALID_PARAMS;
                }
                HcfCryptoMode mode = HcfCryptoMode(opMode);
                HcfBlob authTag = {};
                if (mode == DECRYPT_MODE) {
                    gcmParamsSpec->tag = spec.authTag;
                } else if (mode == ENCRYPT_MODE) {
                    authTag.data = static_cast<uint8_t *>(HcfMalloc(GCM_AUTH_TAG_LEN, 0));
                    if (authTag.data == nullptr) {
                        HcfFree(gcmParamsSpec);
                        return HCF_INVALID_PARAMS;
                    }
                    authTag.len = GCM_AUTH_TAG_LEN;
                    gcmParamsSpec->tag = authTag;
                }
                gcmParamsSpec->base.getType = GetGcmParamsSpecType;
                gcmParamsSpec->iv = spec.iv;
                gcmParamsSpec->aad = spec.add;
                HcfParamsSpec *paramsSpec = reinterpret_cast<HcfParamsSpec *>(gcmParamsSpec);
                gcmParamsSpec = nullptr;
                HcfResult res = instance->CipherInit(mode, static_cast<HcfKey*>(key), paramsSpec);
                HcfBlobDataFree(&authTag);
                HcfFree(paramsSpec);
                paramsSpec = nullptr;
                LOGD("[Cipher] FfiOHOSCipherInitByGcm success");
                return res;
            }

            int32_t FfiOHOSCipherInitByCcm(int64_t id, int32_t opMode, void* key, CParamsSpec spec)
            {
                LOGD("[Cipher] FfiOHOSCipherInitByCcm start");
                if (key == nullptr) {
                    LOGE("[Cipher] key can not be nullptr.");
                    return HCF_INVALID_PARAMS;
                }
                auto instance = FFIData::GetData<CipherImpl>(id);
                if (!instance) {
                    LOGE("[Cipher] instance not exist.");
                    return HCF_ERR_MALLOC;
                }
                HcfCcmParamsSpec *ccmParamsSpec = reinterpret_cast<HcfCcmParamsSpec *>(
                                                    HcfMalloc(sizeof(HcfCcmParamsSpec), 0));
                if (ccmParamsSpec == nullptr) {
                    LOGE("ccmParamsSpec malloc failed!");
                    return HCF_INVALID_PARAMS;
                }
                HcfBlob authTag = {};
                HcfCryptoMode mode = HcfCryptoMode(opMode);
                if (mode == DECRYPT_MODE) {
                    ccmParamsSpec->tag = spec.authTag;
                } else if (mode == ENCRYPT_MODE) {
                    authTag.data = static_cast<uint8_t *>(HcfMalloc(CCM_AUTH_TAG_LEN, 0));
                    if (authTag.data == nullptr) {
                        HcfFree(ccmParamsSpec);
                        return HCF_INVALID_PARAMS;
                    }
                    authTag.len = CCM_AUTH_TAG_LEN;
                    ccmParamsSpec->tag = authTag;
                }
                ccmParamsSpec->base.getType = GetCcmParamsSpecType;
                ccmParamsSpec->iv = spec.iv;
                ccmParamsSpec->aad = spec.add;
                HcfParamsSpec *paramsSpec = reinterpret_cast<HcfParamsSpec *>(ccmParamsSpec);
                ccmParamsSpec = nullptr;
                HcfResult res = instance->CipherInit(mode, static_cast<HcfKey*>(key), paramsSpec);
                HcfBlobDataFree(&authTag);
                HcfFree(paramsSpec);
                paramsSpec = nullptr;
                LOGD("[Cipher] FfiOHOSCipherInitByCcm success");
                return res;
            }

            int32_t FfiOHOSCipherInitWithOutParams(int64_t id, int32_t opMode, void* key)
            {
                LOGD("[Cipher] FfiOHOSCipherInitWithOutParams start");
                if (key == nullptr) {
                    LOGE("[Cipher] key can not be nullptr.");
                    return HCF_INVALID_PARAMS;
                }
                auto instance = FFIData::GetData<CipherImpl>(id);
                if (!instance) {
                    LOGE("[Cipher] instance not exist.");
                    return HCF_ERR_MALLOC;
                }
                HcfParamsSpec *paramsSpec = nullptr;
                HcfCryptoMode mode = HcfCryptoMode(opMode);
                HcfResult res = instance->CipherInit(mode, static_cast<HcfKey*>(key), paramsSpec);
                LOGD("[Cipher] FfiOHOSCipherInitWithOutParams success");
                return res;
            }

            int32_t FfiOHOSCipherUpdate(int64_t id, HcfBlob *input, HcfBlob *output)
            {
                LOGD("[Cipher] CipherUpdate start");
                auto instance = FFIData::GetData<CipherImpl>(id);
                if (!instance) {
                    LOGE("[Cipher] instance not exist.");
                    return HCF_ERR_MALLOC;
                }
                HcfResult res = instance->CipherUpdate(input, output);
                LOGD("[Cipher] CipherUpdate success");
                return res;
            }

            int32_t FfiOHOSCipherDoFinal(int64_t id, HcfBlob *input, HcfBlob *output)
            {
                LOGD("[Cipher] CipherDoFinal start");
                auto instance = FFIData::GetData<CipherImpl>(id);
                if (!instance) {
                    LOGE("[Cipher] instance not exist.");
                    return HCF_ERR_MALLOC;
                }
                HcfResult res = instance->CipherDoFinal(input, output);
                LOGD("[Cipher] CipherDoFinal success %{public}d", res);
                return res;
            }

            int32_t FfiOHOSSetCipherSpec(int64_t id, int32_t item, HcfBlob pSource)
            {
                LOGD("[Cipher] SetCipherSpec start");
                auto instance = FFIData::GetData<CipherImpl>(id);
                if (!instance) {
                    LOGE("[Cipher] instance not exist.");
                    return HCF_ERR_MALLOC;
                }
                CipherSpecItem csi = CipherSpecItem(item);
                HcfResult res = instance->SetCipherSpec(csi, pSource);
                LOGD("[Cipher] SetCipherSpec success");
                return res;
            }

            char *FfiOHOSGetCipherSpecString(int64_t id, int32_t item, int32_t *errCode)
            {
                LOGD("[Cipher] FfiOHOSGetCipherSpecString start");
                auto instance = FFIData::GetData<CipherImpl>(id);
                if (!instance) {
                    LOGE("[Cipher] instance not exist.");
                    *errCode = HCF_ERR_MALLOC;
                    return nullptr;
                }
                CipherSpecItem specItem = CipherSpecItem(item);
                char *returnString = nullptr;
                *errCode = instance->GetCipherSpecString(specItem, &returnString);
                LOGD("[Cipher] FfiOHOSGetCipherSpecString success");
                return returnString;
            }

            int32_t FfiOHOSGetCipherSpecUint8Array(int64_t id, int32_t item, HcfBlob *returnUint8Array)
            {
                LOGD("[Cipher] GetCipherSpecUint8Array start");
                auto instance = FFIData::GetData<CipherImpl>(id);
                if (!instance) {
                    LOGE("[Cipher] instance not exist.");
                    return HCF_ERR_MALLOC;
                }
                CipherSpecItem csi = CipherSpecItem(item);
                HcfResult res = instance->GetCipherSpecUint8Array(csi, returnUint8Array);
                LOGD("[Cipher] GetCipherSpecUint8Array success");
                return res;
            }

            const char *FfiOHOSCipherGetAlgName(int64_t id, int32_t* errCode)
            {
                LOGD("[Cipher] GetAlgName start");
                auto instance = FFIData::GetData<CipherImpl>(id);
                if (!instance) {
                    LOGE("[SymKey] instance not exist.");
                    *errCode = HCF_ERR_MALLOC;
                    return nullptr;
                }
                const char* res = instance->GetAlgorithm(errCode);
                LOGD("[Cipher] GetAlgName success");
                return res;
            }

            //--------------------- mac
            int64_t FFiOHOSCryptoMacConstructor(char* algName, int32_t* errCode)
            {
                LOGD("[Mac] CreateMac start");
                HcfMac *macObj = nullptr;
                HcfHmacParamsSpec paramsSpec = {};
                paramsSpec.base.algName = "HMAC";
                paramsSpec.mdName = algName;
                HcfResult res = HcfMacCreate(reinterpret_cast<HcfMacParamsSpec *>(&paramsSpec), &macObj);
                *errCode = static_cast<int32_t>(res);
                if (res != HCF_SUCCESS) {
                    LOGE("create c macObj failed.");
                    return 0;
                }
                auto native = FFIData::Create<MacImpl>(macObj);
                if (native == nullptr) {
                    LOGE("[Mac] CreateMac failed");
                    HcfObjDestroy(macObj);
                    *errCode = HCF_ERR_MALLOC;
                    return 0;
                }
                LOGD("[Mac] CreateMac success");
                return native->GetID();
            }

            int32_t FfiOHOSCryptoMacInit(int64_t id, int64_t symKeyId)
            {
                LOGD("[MAC] FfiOHOSCryptoMacInit start");
                auto instance = FFIData::GetData<MacImpl>(id);
                if (!instance) {
                    LOGE("[MAC] MacImpl instance not exist.");
                    return HCF_ERR_MALLOC;
                }

                auto keyInstance = FFIData::GetData<SymKeyImpl>(symKeyId);
                if (!keyInstance) {
                    LOGE("[MAC] SymKeyImpl instance not exist.");
                    return HCF_ERR_MALLOC;
                }

                HcfResult res = instance->MacInit(keyInstance->GetSymKey());
                if (res != HCF_SUCCESS) {
                    LOGE("[MAC] MacInit error %{public}d", res);
                } else {
                    LOGD("[MAC] FfiOHOSCryptoMacInit success");
                }

                return res;
            }

            int32_t FfiOHOSCryptoMacUpdate(int64_t id, HcfBlob *input)
            {
                LOGD("[Mac] FfiOHOSCryptoMacUpdate start");
                HcfResult res = HCF_ERR_MALLOC;
                auto instance = FFIData::GetData<MacImpl>(id);
                if (!instance) {
                    LOGE("[Mac] instance not exist.");
                    return res;
                }
                res = instance->MacUpdate(input);
                LOGD("[Mac] FfiOHOSCryptoMacUpdate success");
                return res;
            }

            HcfBlob FfiOHOSCryptoMacDoFinal(int64_t id, int32_t* errCode)
            {
                LOGD("[Mac] FfiOHOSCryptoMacDoFinal start");
                auto instance = FFIData::GetData<MacImpl>(id);
                HcfBlob blob = { .data = nullptr, .len = 0};
                if (!instance) {
                    LOGE("[Mac] instance not exist.");
                    *errCode = HCF_ERR_MALLOC;
                    return blob;
                }
                HcfResult res = instance->MacDoFinal(&blob);
                *errCode = static_cast<int32_t>(res);
                if (res != HCF_SUCCESS) {
                    LOGE("doFinal failed!");
                    return blob;
                }
                LOGD("[Mac] FfiOHOSCryptoMacDoFinal success");
                return blob;
            }

            uint32_t FfiOHOSCryptoGetMacLength(int64_t id)
            {
                LOGD("[Mac] FfiOHOSGCryptoGetMacLength start");
                auto instance = FFIData::GetData<MacImpl>(id);
                uint32_t res = 0;
                if (!instance) {
                    LOGE("[Mac] instance not exist.");
                    return res;
                }
                res = instance->GetMacLength();
                LOGD("[Mac] FfiOHOSGCryptoGetMacLength success");
                return res;
            }

            //--------------------- sign
            int64_t FFiOHOSCryptoSignConstructor(char* algName, int32_t* errCode)
            {
                LOGD("[Sign] FFiOHOSCryptoSignConstructor start");
                HcfSign *signObj = nullptr;
                HcfResult res = HcfSignCreate(algName, &signObj);
                *errCode = static_cast<int32_t>(res);
                if (res != HCF_SUCCESS) {
                    LOGE("[Sign] FFiOHOSCryptoSignConstructor create c signObj failed.");
                    return 0;
                }
                auto native = FFIData::Create<SignImpl>(signObj);
                if (native == nullptr) {
                    LOGE("[Sign] FFiOHOSCryptoSignConstructor create failed");
                    HcfObjDestroy(signObj);
                    *errCode = HCF_ERR_MALLOC;
                    return 0;
                }
                LOGD("[Sign] FFiOHOSCryptoSignConstructor success");
                return native->GetID();
            }

            int32_t FFiOHOSSignInit(int64_t sid, int64_t pid)
            {
                LOGD("[Sign] FFiOHOSSignInit start");
                auto sign = FFIData::GetData<SignImpl>(sid);
                if (sign == nullptr) {
                    LOGE("[Sign] FFiOHOSSignInit failed to get sign obj.");
                    return HCF_INVALID_PARAMS;
                }
                auto priKeyImpl = FFIData::GetData<PriKeyImpl>(pid);
                if (priKeyImpl == nullptr) {
                    LOGE("[Sign] FFiOHOSSignInit failed to get priKeyImpl obj.");
                    return HCF_INVALID_PARAMS;
                }
                HcfPriKey *priKey = priKeyImpl->GetPriKey();
                if (priKey == nullptr) {
                    LOGE("[Sign] FFiOHOSSignInit failed to get priKey obj.");
                    return HCF_INVALID_PARAMS;
                }
                LOGD("[Sign] FFiOHOSSignInit success");
                return sign->Init(priKey);
            }

            int32_t FFiOHOSSignUpdate(int64_t id, HcfBlob input)
            {
                LOGD("[Sign] FFiOHOSSignUpdate start");
                auto sign = FFIData::GetData<SignImpl>(id);
                if (sign == nullptr) {
                    LOGE("[Sign] FFiOHOSSignUpdate failed to get sign obj.");
                    return HCF_INVALID_PARAMS;
                }
                LOGD("[Sign] FFiOHOSSignUpdate success");
                return sign->Update(&input);
            }

            int32_t FFiOHOSSignSign(int64_t id, HcfBlob *input, HcfBlob *output)
            {
                LOGD("[Sign] FFiOHOSSignSign start");
                auto sign = FFIData::GetData<SignImpl>(id);
                if (sign == nullptr) {
                    LOGE("[Sign] FFiOHOSSignSign failed to get sign obj.");
                    return HCF_INVALID_PARAMS;
                }
                LOGD("[Sign] FFiOHOSSignSign success");
                return sign->Sign(input, output);
            }

            int32_t FFiOHOSSignSetSignSpecByNum(int64_t id, int32_t itemValue)
            {
                LOGD("[Sign] FFiOHOSSignSetSignSpecByNum start");
                auto sign = FFIData::GetData<SignImpl>(id);
                if (sign == nullptr) {
                    LOGE("[Sign] FFiOHOSSignSetSignSpecByNum failed to get sign obj.");
                    return HCF_INVALID_PARAMS;
                }
                LOGD("[Sign] FFiOHOSSignSetSignSpecByNum success");
                return sign->SetSignSpecByNum(itemValue);
            }

            int32_t FFiOHOSSignSetSignSpecByArr(int64_t id, HcfBlob itemValue)
            {
                LOGD("[Sign] FFiOHOSSignSetSignSpecByArr start");
                auto sign = FFIData::GetData<SignImpl>(id);
                if (sign == nullptr) {
                    LOGE("[Sign] FFiOHOSSignSetSignSpecByArr failed to get sign obj.");
                    return HCF_INVALID_PARAMS;
                }
                LOGD("[Sign] FFiOHOSSignSetSignSpecByArr success");
                return sign->SetSignSpecByArr(itemValue);
            }

            char *FFiOHOSSignGetSignSpecString(int64_t id, SignSpecItem item, int32_t *errCode)
            {
                LOGD("[Sign] FFiOHOSSignGetSignSpecString start");
                auto sign = FFIData::GetData<SignImpl>(id);
                if (sign == nullptr) {
                    LOGE("[Sign] FFiOHOSSignGetSignSpecString failed to get sign obj.");
                    *errCode = HCF_INVALID_PARAMS;
                    return nullptr;
                }
                char *returnString = nullptr;
                *errCode = sign->GetSignSpecString(item, &returnString);
                LOGD("[Sign] FFiOHOSSignGetSignSpecString success");
                return returnString;
            }

            int32_t FFiOHOSSignGetSignSpecNum(int64_t id, SignSpecItem item, int32_t *itemValue)
            {
                LOGD("[Sign] FFiOHOSSignGetSignSpecNum start");
                auto sign = FFIData::GetData<SignImpl>(id);
                if (sign == nullptr) {
                    LOGE("[Sign] FFiOHOSSignGetSignSpecNum failed to get sign obj.");
                    return HCF_INVALID_PARAMS;
                }
                LOGD("[Sign] FFiOHOSSignGetSignSpecNum success");
                return sign->GetSignSpecNum(item, itemValue);
            }

            //--------------------- verify
            int64_t FFiOHOSVerifyConstructor(char* algName, int32_t* errCode)
            {
                LOGD("[Verify]FFiOHOSVerifyConstructor start");
                HcfVerify *verify = nullptr;
                HcfResult res = HcfVerifyCreate(algName, &verify);
                *errCode = static_cast<int32_t>(res);
                if (res != HCF_SUCCESS) {
                    LOGE("[Verify] FFiOHOSVerifyConstructor create c verifyObj failed.");
                    return 0;
                }
                auto native = FFIData::Create<VerifyImpl>(verify);
                if (native == nullptr) {
                    LOGE("[Verify] FFiOHOSVerifyConstructor create failed");
                    HcfObjDestroy(verify);
                    *errCode = HCF_ERR_MALLOC;
                    return 0;
                }
                LOGD("[Verify] FFiOHOSVerifyConstructor success");
                return native->GetID();
            }

            int32_t FFiOHOSVerifyInit(int64_t sid, int64_t pid)
            {
                LOGD("[Verify] FFiOHOSVerifyInit start");
                auto verify = FFIData::GetData<VerifyImpl>(sid);
                if (verify == nullptr) {
                    LOGE("[Verify] FFiOHOSVerifyInit failed to get verify obj.");
                    return HCF_INVALID_PARAMS;
                }
                auto pubKeyImpl = FFIData::GetData<PubKeyImpl>(pid);
                if (pubKeyImpl == nullptr) {
                    LOGE("[Verify] FFiOHOSVerifyInit failed to get priKeyImpl obj.");
                    return HCF_INVALID_PARAMS;
                }
                HcfPubKey *pubKey = pubKeyImpl->GetPubKey();
                if (pubKey == nullptr) {
                    LOGE("[Verify] FFiOHOSVerifyInit failed to get priKey obj.");
                    return HCF_INVALID_PARAMS;
                }
                LOGD("[Verify] FFiOHOSVerifyInit success");
                return verify->Init(pubKey);
            }

            int32_t FFiOHOSVerifyUpdate(int64_t id, HcfBlob input)
            {
                LOGD("[Verify] FFiOHOSVerifyUpdate start");
                auto verify = FFIData::GetData<VerifyImpl>(id);
                if (verify == nullptr) {
                    LOGE("[Verify] FFiOHOSVerifyUpdate failed to get verify obj.");
                    return HCF_INVALID_PARAMS;
                }
                LOGD("[Verify] FFiOHOSVerifyUpdate success");
                return verify->Update(&input);
            }

            bool FFiOHOSVerifyVerify(int64_t id, HcfBlob *data, HcfBlob signatureData, int32_t* errCode)
            {
                LOGD("[Verify] FFiOHOSVerifyVerify start");
                auto verify = FFIData::GetData<VerifyImpl>(id);
                if (verify == nullptr) {
                    LOGE("[Verify] FFiOHOSVerifyVerify failed to get verify obj.");
                    return HCF_INVALID_PARAMS;
                }
                LOGD("[Verify] FFiOHOSVerifyVerify success");
                return verify->Verify(data, signatureData, errCode);
            }

            int32_t FFiOHOSVerifyRecover(int64_t id, HcfBlob input, HcfBlob *output)
            {
                LOGD("[Verify] FFiOHOSVerifyRecover start");
                auto verify = FFIData::GetData<VerifyImpl>(id);
                if (verify == nullptr) {
                    LOGE("[Verify] FFiOHOSVerifyVerify failed to get verify obj.");
                    return HCF_INVALID_PARAMS;
                }
                LOGD("[Verify] FFiOHOSVerifyRecover success");
                return verify->Recover(input, output);
            }


            int32_t FFiOHOSVerifySetVerifySpecByNum(int64_t id, int32_t itemValue)
            {
                LOGD("[Verify] FFiOHOSVerifySetVerifySpecByNum start");
                auto verify = FFIData::GetData<VerifyImpl>(id);
                if (verify == nullptr) {
                    LOGE("[Verify] FFiOHOSVerifySetVerifySpecByNum failed to get verify obj.");
                    return HCF_INVALID_PARAMS;
                }
                LOGD("[Verify] FFiOHOSVerifySetVerifySpecByNum success");
                return verify->SetVerifySpecByNum(itemValue);
            }

            int32_t FFiOHOSVerifySetVerifySpecByArr(int64_t id, HcfBlob itemValue)
            {
                LOGD("[Verify] FFiOHOSVerifySetVerifySpecByArr start");
                auto verify = FFIData::GetData<VerifyImpl>(id);
                if (verify == nullptr) {
                    LOGE("[Verify] FFiOHOSVerifySetVerifySpecByArr failed to get verify obj.");
                    return HCF_INVALID_PARAMS;
                }
                LOGD("[Verify] FFiOHOSVerifySetVerifySpecByArr success");
                return verify->SetVerifySpecByArr(itemValue);
            }

            char *FFiOHOSVerifyGetVerifySpecString(int64_t id, SignSpecItem item, int32_t *errCode)
            {
                LOGD("[Verify] FFiOHOSVerifyGetVerifySpecString start");
                auto verify = FFIData::GetData<VerifyImpl>(id);
                if (verify == nullptr) {
                    LOGE("[Verify] FFiOHOSVerifyGetVerifySpecString failed to get verify obj.");
                    *errCode =  HCF_INVALID_PARAMS;
                    return nullptr;
                }
                char *returnString = nullptr;
                *errCode = verify->GetVerifySpecString(item, &returnString);
                LOGD("[Verify] FFiOHOSVerifyGetVerifySpecString success");
                return returnString;
            }

            int32_t FFiOHOSVerifyGetVerifySpecNum(int64_t id, SignSpecItem item, int32_t *itemValue)
            {
                LOGD("[Verify] FFiOHOSVerifyGetVerifySpecNum start");
                auto verify = FFIData::GetData<VerifyImpl>(id);
                if (verify == nullptr) {
                    LOGE("[Verify] FFiOHOSVerifyGetVerifySpecNum failed to get verify obj.");
                    return HCF_INVALID_PARAMS;
                }
                LOGD("[Verify] FFiOHOSVerifyGetVerifySpecNum success");
                return verify->GetVerifySpecNum(item, itemValue);
            }

            //--------------------- asykeygenerator
            int64_t FFiOHOSAsyKeyGeneratorConstructor(char *algName, int32_t *errCode)
            {
                LOGD("[AsyKeyGenerator] FFiOHOSAsyKeyGeneratorConstructor start");
                HcfAsyKeyGenerator *generator = nullptr;
                *errCode = HcfAsyKeyGeneratorCreate(algName, &generator);
                if (*errCode != HCF_SUCCESS) {
                    *errCode = HCF_INVALID_PARAMS;
                    LOGE("create c generator fail.");
                    return 0;
                }
                auto instance = FFIData::Create<AsyKeyGeneratorImpl>(generator);
                if (!instance) {
                    *errCode = HCF_ERR_MALLOC;
                    HcfObjDestroy(generator);
                    LOGE("new asy key generator failed");
                    return 0;
                }
                LOGD("[AsyKeyGenerator] FFiOHOSAsyKeyGeneratorConstructor end");
                return instance->GetID();
            }

            int64_t FFiOHOSAsyKeyGeneratorGenerateKeyPair(int64_t id, int32_t *errCode)
            {
                LOGD("[AsyKeyGenerator] FFiOHOSAsyKeyGenerateKeyPair start");
                auto instance = FFIData::GetData<AsyKeyGeneratorImpl>(id);
                if (!instance) {
                    *errCode = HCF_INVALID_PARAMS;
                    LOGE("build instance fail.");
                    return 0;
                }
                HcfAsyKeyGenerator *generator = instance->GetAsyKeyGenerator();
                if (generator == nullptr) {
                    *errCode = HCF_INVALID_PARAMS;
                    LOGE("build generator fail.");
                    return 0;
                }
                HcfKeyPair *returnKeyPair = nullptr;
                HcfParamsSpec *params = nullptr;
                *errCode = generator->generateKeyPair(generator, params, &returnKeyPair);
                if (*errCode != HCF_SUCCESS) {
                    LOGD("generate key pair fail.");
                    return 0;
                }
                auto keyPair = FFIData::Create<KeyPairImpl>(returnKeyPair);
                if (keyPair == nullptr) {
                    *errCode = HCF_ERR_MALLOC;
                    HcfObjDestroy(returnKeyPair);
                    LOGE("new key pair failed");
                    return 0;
                }
                LOGD("[AsyKeyGenerator] FFiOHOSAsyKeyGenerateKeyPair end");
                return keyPair->GetID();
            }

            int64_t FFiOHOSAsyKeyGeneratorConvertKey(int64_t id, HcfBlob *pubKey, HcfBlob *priKey, int32_t *errCode)
            {
                LOGD("[AsyKeyGenerator] FFiOHOSAsyKeyConvertKey start");
                auto instance = FFIData::GetData<AsyKeyGeneratorImpl>(id);
                if (!instance) {
                    *errCode = HCF_INVALID_PARAMS;
                    LOGE("build instance fail.");
                    return 0;
                }
                HcfAsyKeyGenerator *generator = instance->GetAsyKeyGenerator();
                if (generator == nullptr) {
                    *errCode = HCF_INVALID_PARAMS;
                    LOGE("build generator fail.");
                    return 0;
                }
                HcfKeyPair *returnKeyPair = nullptr;
                HcfParamsSpec *params = nullptr;
                *errCode = generator->convertKey(generator, params, pubKey, priKey, &returnKeyPair);
                if (*errCode != HCF_SUCCESS) {
                    LOGD("convert key fail.");
                    return 0;
                }
                auto keyPair = FFIData::Create<KeyPairImpl>(returnKeyPair);
                if (keyPair == nullptr) {
                    *errCode = HCF_ERR_MALLOC;
                    HcfObjDestroy(returnKeyPair);
                    LOGE("new key pair failed");
                    return 0;
                }
                LOGD("[AsyKeyGenerator] FFiOHOSAsyKeyConvertKey end");
                return keyPair->GetID();
            }

            int64_t FFiOHOSAsyKeyGeneratorConvertPemKey(int64_t id, char *pubKey, char *priKey, int32_t *errCode)
            {
                LOGD("[AsyKeyGenerator] FFiOHOSAsyKeyConvertPemKey start");
                auto instance = FFIData::GetData<AsyKeyGeneratorImpl>(id);
                if (!instance) {
                    *errCode = HCF_INVALID_PARAMS;
                    LOGE("build instance fail.");
                    return 0;
                }
                HcfAsyKeyGenerator *generator = instance->GetAsyKeyGenerator();
                if (generator == nullptr) {
                    *errCode = HCF_INVALID_PARAMS;
                    LOGE("build generator fail.");
                    return 0;
                }
                HcfKeyPair *returnKeyPair = nullptr;
                HcfParamsSpec *params = nullptr;
                *errCode = generator->convertPemKey(generator, params, pubKey, priKey, &returnKeyPair);
                if (*errCode != HCF_SUCCESS) {
                    LOGE("ConvertPemKey fail.");
                    return 0;
                }
                auto keyPair = FFIData::Create<KeyPairImpl>(returnKeyPair);
                if (keyPair == nullptr) {
                    *errCode = HCF_ERR_MALLOC;
                    HcfObjDestroy(returnKeyPair);
                    LOGE("new key pair failed");
                    return 0;
                }
                LOGD("[AsyKeyGenerator] FFiOHOSAsyKeyConvertPemKey end");
                return keyPair->GetID();
            }

            //--------------------- asykeyspecgenerator
            int64_t AsyKeyGeneratorBySpecConstructor(HcfAsyKeyParamsSpec *asyKeySpec, int32_t *errCode)
            {
                HcfAsyKeyGeneratorBySpec *generator = nullptr;
                *errCode = HcfAsyKeyGeneratorBySpecCreate(asyKeySpec, &generator);
                if (*errCode != HCF_SUCCESS) {
                    *errCode = HCF_INVALID_PARAMS;
                    LOGE("create C generator by sepc fail.");
                    return 0;
                }
                auto instance = FFIData::Create<AsyKeyGeneratorBySpecImpl>(generator);
                if (!instance) {
                    *errCode = HCF_ERR_MALLOC;
                    HcfObjDestroy(generator);
                    LOGE("new asy key generator by spec failed!");
                    return 0;
                }
                return instance->GetID();
            }

            int64_t FFiOHOSAsyKeyGeneratorByDsaCommonSpec(HcfDsaCommParamsSpec *spec, int32_t *errCode)
            {
                LOGD("[AsyKeyGeneratorBySpec] FFiOHOSAsyKeyGeneratorByDsaCommonSpec start");
                HcfAsyKeyParamsSpec *asyKeySpec = reinterpret_cast<HcfAsyKeyParamsSpec *>(spec);
                int64_t id = AsyKeyGeneratorBySpecConstructor(asyKeySpec, errCode);
                LOGD("[AsyKeyGeneratorBySpec] FFiOHOSAsyKeyGeneratorByDsaCommonSpec end");
                return id;
            }

            int64_t FFiOHOSAsyKeyGeneratorByDsaPubKeySpec(HcfDsaPubKeyParamsSpec *spec, int32_t *errCode)
            {
                LOGD("[AsyKeyGeneratorBySpec] FFiOHOSAsyKeyGeneratorByDsaPubKeySpec start");
                HcfAsyKeyParamsSpec *asyKeySpec = reinterpret_cast<HcfAsyKeyParamsSpec *>(spec);
                int64_t id = AsyKeyGeneratorBySpecConstructor(asyKeySpec, errCode);
                LOGD("[AsyKeyGeneratorBySpec] FFiOHOSAsyKeyGeneratorByDsaPubKeySpec end");
                return id;
            }

            int64_t FFiOHOSAsyKeyGeneratorByDsaKeyPairSpec(HcfDsaKeyPairParamsSpec *spec, int32_t *errCode)
            {
                LOGD("[AsyKeyGeneratorBySpec] FFiOHOSAsyKeyGeneratorByDsaKeyPairSpec start");
                HcfAsyKeyParamsSpec *asyKeySpec = reinterpret_cast<HcfAsyKeyParamsSpec *>(spec);
                int64_t id = AsyKeyGeneratorBySpecConstructor(asyKeySpec, errCode);
                LOGD("[AsyKeyGeneratorBySpec] FFiOHOSAsyKeyGeneratorByDsaKeyPairSpec end");
                return id;
            }

            int64_t FFiOHOSAsyKeyGeneratorByEccCommonSpec(HcfEccCommParamsSpec *spec, int32_t *errCode)
            {
                LOGD("[AsyKeyGeneratorBySpec] FFiOHOSAsyKeyGeneratorByEccCommonSpec start");
                HcfAsyKeyParamsSpec *asyKeySpec = reinterpret_cast<HcfAsyKeyParamsSpec *>(spec);
                int64_t id = AsyKeyGeneratorBySpecConstructor(asyKeySpec, errCode);
                LOGD("[AsyKeyGeneratorBySpec] FFiOHOSAsyKeyGeneratorByEccCommonSpec end");
                return id;
            }

            int64_t FFiOHOSAsyKeyGeneratorByEccPriKeySpec(HcfEccPriKeyParamsSpec *spec, int32_t *errCode)
            {
                LOGD("[AsyKeyGeneratorBySpec] FFiOHOSAsyKeyGeneratorByEccPriKeySpec start");
                HcfAsyKeyParamsSpec *asyKeySpec = reinterpret_cast<HcfAsyKeyParamsSpec *>(spec);
                int64_t id = AsyKeyGeneratorBySpecConstructor(asyKeySpec, errCode);
                LOGD("[AsyKeyGeneratorBySpec] FFiOHOSAsyKeyGeneratorByEccPriKeySpec end");
                return id;
            }

            int64_t FFiOHOSAsyKeyGeneratorByEccPubKeySpec(HcfEccPubKeyParamsSpec *spec, int32_t *errCode)
            {
                LOGD("[AsyKeyGeneratorBySpec] FFiOHOSAsyKeyGeneratorByEccPubKeySpec start");
                HcfAsyKeyParamsSpec *asyKeySpec = reinterpret_cast<HcfAsyKeyParamsSpec *>(spec);
                int64_t id = AsyKeyGeneratorBySpecConstructor(asyKeySpec, errCode);
                LOGD("[AsyKeyGeneratorBySpec] FFiOHOSAsyKeyGeneratorByEccPubKeySpec end");
                return id;
            }

            int64_t FFiOHOSAsyKeyGeneratorByEccKeyPairSpec(HcfEccKeyPairParamsSpec *spec, int32_t *errCode)
            {
                LOGD("[AsyKeyGeneratorBySpec] FFiOHOSAsyKeyGeneratorByEccKeyPairSpec start");
                HcfAsyKeyParamsSpec *asyKeySpec = reinterpret_cast<HcfAsyKeyParamsSpec *>(spec);
                int64_t id = AsyKeyGeneratorBySpecConstructor(asyKeySpec, errCode);
                LOGD("[AsyKeyGeneratorBySpec] FFiOHOSAsyKeyGeneratorByEccKeyPairSpec end");
                return id;
            }

            int64_t FFiOHOSAsyKeyGeneratorByRsaPubKeySpec(HcfRsaPubKeyParamsSpec *spec, int32_t *errCode)
            {
                LOGD("[AsyKeyGeneratorBySpec] FFiOHOSAsyKeyGeneratorByRsaPubKeySpec start");
                HcfAsyKeyParamsSpec *asyKeySpec = reinterpret_cast<HcfAsyKeyParamsSpec *>(spec);
                int64_t id = AsyKeyGeneratorBySpecConstructor(asyKeySpec, errCode);
                LOGD("[AsyKeyGeneratorBySpec] FFiOHOSAsyKeyGeneratorByRsaPubKeySpec end");
                return id;
            }

            int64_t FFiOHOSAsyKeyGeneratorByRsaKeyPairSpec(HcfRsaKeyPairParamsSpec *spec, int32_t *errCode)
            {
                LOGD("[AsyKeyGeneratorBySpec] FFiOHOSAsyKeyGeneratorByRsaKeyPairSpec start");
                HcfAsyKeyParamsSpec *asyKeySpec = reinterpret_cast<HcfAsyKeyParamsSpec *>(spec);
                int64_t id = AsyKeyGeneratorBySpecConstructor(asyKeySpec, errCode);
                LOGD("[AsyKeyGeneratorBySpec] FFiOHOSAsyKeyGeneratorByRsaKeyPairSpec end");
                return id;
            }

            int64_t FFiOHOSAsyKeyGeneratorByAlg25519PriKeySpec(HcfAlg25519PriKeyParamsSpec *spec, int32_t *errCode)
            {
                LOGD("[AsyKeyGeneratorBySpec] FFiOHOSAsyKeyGeneratorByAlg25519PriKeySpec start");
                HcfAsyKeyParamsSpec *asyKeySpec = reinterpret_cast<HcfAsyKeyParamsSpec *>(spec);
                int64_t id = AsyKeyGeneratorBySpecConstructor(asyKeySpec, errCode);
                LOGD("[AsyKeyGeneratorBySpec] FFiOHOSAsyKeyGeneratorByAlg25519PriKeySpec end");
                return id;
            }

            int64_t FFiOHOSAsyKeyGeneratorByAlg25519PubKeySpec(HcfAlg25519PubKeyParamsSpec *spec, int32_t *errCode)
            {
                LOGD("[AsyKeyGeneratorBySpec] FFiOHOSAsyKeyGeneratorByAlg25519PubKeySpec start");
                HcfAsyKeyParamsSpec *asyKeySpec = reinterpret_cast<HcfAsyKeyParamsSpec *>(spec);
                int64_t id = AsyKeyGeneratorBySpecConstructor(asyKeySpec, errCode);
                LOGD("[AsyKeyGeneratorBySpec] FFiOHOSAsyKeyGeneratorByAlg25519PubKeySpec end");
                return id;
            }

            int64_t FFiOHOSAsyKeyGeneratorByAlg25519KeyPairSpec(HcfAlg25519KeyPairParamsSpec *spec, int32_t *errCode)
            {
                LOGD("[AsyKeyGeneratorBySpec] FFiOHOSAsyKeyGeneratorByAlg25519KeyPairSpec start");
                HcfAsyKeyParamsSpec *asyKeySpec = reinterpret_cast<HcfAsyKeyParamsSpec *>(spec);
                int64_t id = AsyKeyGeneratorBySpecConstructor(asyKeySpec, errCode);
                LOGD("[AsyKeyGeneratorBySpec] FFiOHOSAsyKeyGeneratorByAlg25519KeyPairSpec end");
                return id;
            }

            int64_t FFiOHOSAsyKeyGeneratorByDhPriKeySpec(HcfDhPriKeyParamsSpec *spec, int32_t *errCode)
            {
                LOGD("[AsyKeyGeneratorBySpec] FFiOHOSAsyKeyGeneratorByDhPriKeySpec start");
                HcfAsyKeyParamsSpec *asyKeySpec = reinterpret_cast<HcfAsyKeyParamsSpec *>(spec);
                int64_t id = AsyKeyGeneratorBySpecConstructor(asyKeySpec, errCode);
                LOGD("[AsyKeyGeneratorBySpec] FFiOHOSAsyKeyGeneratorByDhPriKeySpec end");
                return id;
            }

            int64_t FFiOHOSAsyKeyGeneratorByDhPubKeySpec(HcfDhPubKeyParamsSpec *spec, int32_t *errCode)
            {
                LOGD("[AsyKeyGeneratorBySpec] FFiOHOSAsyKeyGeneratorByDhPubKeySpec start");
                HcfAsyKeyParamsSpec *asyKeySpec = reinterpret_cast<HcfAsyKeyParamsSpec *>(spec);
                int64_t id = AsyKeyGeneratorBySpecConstructor(asyKeySpec, errCode);
                LOGD("[AsyKeyGeneratorBySpec] FFiOHOSAsyKeyGeneratorByDhPubKeySpec end");
                return id;
            }

            int64_t FFiOHOSAsyKeyGeneratorByDhKeyPairSpec(HcfDhKeyPairParamsSpec *spec, int32_t *errCode)
            {
                LOGD("[AsyKeyGeneratorBySpec] FFiOHOSAsyKeyGeneratorByDhKeyPairSpec start");
                HcfAsyKeyParamsSpec *asyKeySpec = reinterpret_cast<HcfAsyKeyParamsSpec *>(spec);
                int64_t id = AsyKeyGeneratorBySpecConstructor(asyKeySpec, errCode);
                LOGD("[AsyKeyGeneratorBySpec] FFiOHOSAsyKeyGeneratorByDhKeyPairSpecc end");
                return id;
            }

            int64_t FFiOHOSAsyKeyGeneratorByDhCommonSpec(HcfDhCommParamsSpec *spec, int32_t *errCode)
            {
                LOGD("[AsyKeyGeneratorBySpec] FFiOHOSAsyKeyGeneratorBytDhCommonSpec start");
                HcfAsyKeyParamsSpec *asyKeySpec = reinterpret_cast<HcfAsyKeyParamsSpec *>(spec);
                int64_t id = AsyKeyGeneratorBySpecConstructor(asyKeySpec, errCode);
                LOGD("[AsyKeyGeneratorBySpec] FFiOHOSAsyKeyGeneratorBytDhCommonSpec end");
                return id;
            }

            int64_t FFiOHOSAsyKeyGeneratorBySpecGenerateKeyPair(int64_t id, int32_t *errCode)
            {
                LOGD("[AsyKeyGeneratorBySpec] FFiOHOSAsyKeyGeneratorBySpecGenerateKeyPair start");
                auto instance = FFIData::GetData<AsyKeyGeneratorBySpecImpl>(id);
                if (!instance) {
                    *errCode = HCF_INVALID_PARAMS;
                    LOGE("build instance fail.");
                    return 0;
                }
                HcfAsyKeyGeneratorBySpec *generator = instance->GetAsyKeyGeneratorBySpec();
                if (generator == nullptr) {
                    *errCode = HCF_INVALID_PARAMS;
                    LOGE("build generator fail.");
                    return 0;
                }
                HcfKeyPair *returnKeyPair = nullptr;
                *errCode = generator->generateKeyPair(generator, &returnKeyPair);
                if (*errCode != HCF_SUCCESS) {
                    LOGD("generate key pair fail.");
                    return 0;
                }
                auto keyPair = FFIData::Create<KeyPairImpl>(returnKeyPair);
                if (keyPair == nullptr) {
                    *errCode = HCF_ERR_MALLOC;
                    HcfObjDestroy(returnKeyPair);
                    LOGE("new key pair failed");
                    return 0;
                }
                LOGD("[AsyKeyGeneratorBySpec] FFiOHOSAsyKeyGeneratorBySpecGenerateKeyPair end");
                return keyPair->GetID();
            }

            int64_t FFiOHOSAsyKeyGeneratorBySpecGeneratePriKey(int64_t id, int32_t *errCode)
            {
                LOGD("[AsyKeyGeneratorBySpec] FFiOHOSAsyKeyGeneratorBySpecGeneratePriKey start");
                auto instance = FFIData::GetData<AsyKeyGeneratorBySpecImpl>(id);
                if (!instance) {
                    *errCode = HCF_INVALID_PARAMS;
                    LOGE("build instance fail.");
                    return 0;
                }
                HcfAsyKeyGeneratorBySpec *generator = instance->GetAsyKeyGeneratorBySpec();
                if (generator == nullptr) {
                    *errCode = HCF_INVALID_PARAMS;
                    LOGE("build generator fail.");
                    return 0;
                }
                HcfPriKey *returnPriKey = nullptr;
                *errCode = generator->generatePriKey(generator, &returnPriKey);
                if (*errCode != HCF_SUCCESS) {
                    LOGD("generate PriKey fail.");
                    return 0;
                }
                auto priKey = FFIData::Create<PriKeyImpl>(returnPriKey);
                if (priKey == nullptr) {
                    *errCode = HCF_ERR_MALLOC;
                    HcfObjDestroy(returnPriKey);
                    LOGE("new pri key failed");
                    return 0;
                }
                LOGD("[AsyKeyGeneratorBySpec] FFiOHOSAsyKeyGeneratorBySpecGeneratePriKey end");
                return priKey->GetID();
            }

            int64_t FFiOHOSAsyKeyGeneratorBySpecGeneratePubKey(int64_t id, int32_t *errCode)
            {
                LOGD("[AsyKeyGeneratorBySpec] FFiOHOSAsyKeyGeneratorBySpecGeneratePubKey start");
                auto instance = FFIData::GetData<AsyKeyGeneratorBySpecImpl>(id);
                if (!instance) {
                    *errCode = HCF_INVALID_PARAMS;
                    LOGE("build instance fail.");
                    return 0;
                }
                HcfAsyKeyGeneratorBySpec *generator = instance->GetAsyKeyGeneratorBySpec();
                if (generator == nullptr) {
                    *errCode = HCF_INVALID_PARAMS;
                    LOGE("build generator fail.");
                    return 0;
                }
                HcfPubKey *returnPubKey = nullptr;
                *errCode = generator->generatePubKey(generator, &returnPubKey);
                if (*errCode != HCF_SUCCESS) {
                    LOGD("generate PubKey fail.");
                    return 0;
                }
                auto pubKey = FFIData::Create<PubKeyImpl>(returnPubKey);
                if (pubKey == nullptr) {
                    *errCode = HCF_ERR_MALLOC;
                    HcfObjDestroy(returnPubKey);
                    LOGE("new pub key failed");
                    return 0;
                }
                LOGD("[AsyKeyGeneratorBySpec] FFiOHOSAsyKeyGeneratorBySpecGeneratePubKey end");
                return pubKey->GetID();
            }

            //--------------------- prikey
            HcfBlob FFiOHOSPriKeyGetEncoded(int64_t id, int32_t *errCode)
            {
                LOGD("[PriKey] FFiOHOSPriKeyGetEncoded start");
                HcfBlob ret = { .data = nullptr, .len = 0 };
                auto instance = FFIData::GetData<PriKeyImpl>(id);
                if (!instance) {
                    LOGE("[PriKey] FFiOHOSPriKeyGetEncoded failed to unwrap private key obj!");
                    *errCode = HCF_INVALID_PARAMS;
                    return ret;
                }
                HcfPriKey *priKey = instance->GetPriKey();
                if (priKey == nullptr) {
                    LOGE("[PriKey] FFiOHOSPriKeyGetEncoded failed to get private key obj!");
                    *errCode = HCF_INVALID_PARAMS;
                    return ret;
                }
                *errCode = priKey->base.getEncoded(&priKey->base, &ret);
                LOGD("[PriKey] FFiOHOSPriKeyGetEncoded end");
                return ret;
            }

            HcfBlob FFiOHOSPriKeyGetEncodedDer(int64_t id, char *format, int32_t *errCode)
            {
                LOGD("[PriKey] FFiOHOSPriKeyGetEncodedDer start");
                HcfBlob ret = { .data = nullptr, .len = 0 };
                auto instance = FFIData::GetData<PriKeyImpl>(id);
                if (!instance) {
                    LOGE("[PriKey] FFiOHOSPriKeyGetEncodedDer failed to unwrap private key obj!");
                    *errCode = HCF_INVALID_PARAMS;
                    return ret;
                }
                HcfPriKey *priKey = instance->GetPriKey();
                if (priKey == nullptr) {
                    LOGE("[PriKey] FFiOHOSPriKeyGetEncodedDer failed to get private key obj!");
                    *errCode = HCF_INVALID_PARAMS;
                    return ret;
                }
                *errCode = priKey->getEncodedDer(priKey, format, &ret);
                LOGD("[PriKey] FFiOHOSPriKeyGetEncodedDer end");
                return ret;
            }

            char *FFiOHOSPriKeyGetEncodedPem(int64_t id, char *format, int32_t *errCode)
            {
                LOGD("[PriKey] FFiOHOSPriKeyGetEncodedPem start");
                char *ret = nullptr;
                auto instance = FFIData::GetData<PriKeyImpl>(id);
                if (!instance) {
                    LOGE("[PriKey] FFiOHOSPriKeyGetEncodedPem failed to unwrap private key obj!");
                    *errCode = HCF_INVALID_PARAMS;
                    return ret;
                }
                HcfPriKey *priKey = instance->GetPriKey();
                if (priKey == nullptr) {
                    LOGE("[PriKey] FFiOHOSPriKeyGetEncodedPem failed to get private key obj!");
                    *errCode = HCF_INVALID_PARAMS;
                    return ret;
                }
                HcfParamsSpec *paramsSpec = nullptr;
                *errCode = priKey->getEncodedPem(priKey, paramsSpec, format, &ret);
                LOGD("[PriKey] FFiOHOSPriKeyGetEncodedPem end");
                return ret;
            }

            int32_t FFiOHOSPriKeyClearMem(int64_t id)
            {
                LOGD("[PriKey] FFiOHOSPriKeyClearMem start");
                auto instance = FFIData::GetData<PriKeyImpl>(id);
                if (!instance) {
                    LOGE("[PriKey] FFiOHOSPriKeyClearMem failed to unwrap private key obj!");
                    return HCF_INVALID_PARAMS;
                }
                HcfPriKey *priKey = instance->GetPriKey();
                if (priKey == nullptr) {
                    LOGE("[PriKey] FFiOHOSPriKeyClearMem failed to get private key obj!");
                    return HCF_INVALID_PARAMS;
                }
                priKey->clearMem(priKey);
                LOGD("[PriKey] FFiOHOSPriKeyClearMem end");
                return HCF_SUCCESS;
            }

            int FFiOHOSPriKeyGetAsyKeySpecByNum(int64_t id, int32_t itemType, int32_t *errCode)
            {
                LOGD("[PriKey] FFiOHOSPriKeyGetAsyKeySpec start");
                auto instance = FFIData::GetData<PriKeyImpl>(id);
                int ret = 0;
                if (!instance) {
                    LOGE("[PriKey] FFiOHOSPriKeyGetAsyKeySpec failed to unwrap private key obj!");
                    *errCode = HCF_INVALID_PARAMS;
                    return ret;
                }
                HcfPriKey *priKey = instance->GetPriKey();
                if (priKey == nullptr) {
                    LOGE("[PriKey] FFiOHOSPriKeyGetAsyKeySpec failed to get private key obj!");
                    *errCode = HCF_INVALID_PARAMS;
                    return ret;
                }
                AsyKeySpecItem item = AsyKeySpecItem(itemType);
                *errCode = priKey->getAsyKeySpecInt(priKey, item, &ret);
                LOGD("[PriKey] FFiOHOSPriKeyGetAsyKeySpec end");
                return ret;
            }

            char *FFiOHOSPriKeyGetAsyKeySpecByStr(int64_t id, int32_t itemType, int32_t *errCode)
            {
                LOGD("[PriKey] FFiOHOSPriKeyGetAsyKeySpec start");
                auto instance = FFIData::GetData<PriKeyImpl>(id);
                char *ret = nullptr;
                if (!instance) {
                    LOGE("[PriKey] FFiOHOSPriKeyGetAsyKeySpec failed to unwrap private key obj!");
                    *errCode = HCF_INVALID_PARAMS;
                    return ret;
                }
                HcfPriKey *priKey = instance->GetPriKey();
                if (priKey == nullptr) {
                    LOGE("[PriKey] FFiOHOSPriKeyGetAsyKeySpec failed to get private key obj!");
                    *errCode = HCF_INVALID_PARAMS;
                    return ret;
                }
                AsyKeySpecItem item = AsyKeySpecItem(itemType);
                *errCode = priKey->getAsyKeySpecString(priKey, item, &ret);
                LOGD("[PriKey] FFiOHOSPriKeyGetAsyKeySpec end");
                return ret;
            }

            HcfBigInteger FFiOHOSPriKeyGetAsyKeySpecByBigInt(int64_t id, int32_t itemType, int32_t *errCode)
            {
                LOGD("[PriKey] FFiOHOSPriKeyGetAsyKeySpec start");
                auto instance = FFIData::GetData<PriKeyImpl>(id);
                HcfBigInteger ret = { 0 };
                if (!instance) {
                    LOGE("[PriKey] FFiOHOSPriKeyGetAsyKeySpec failed to unwrap private key obj!");
                    *errCode = HCF_INVALID_PARAMS;
                    return ret;
                }
                HcfPriKey *priKey = instance->GetPriKey();
                if (priKey == nullptr) {
                    LOGE("[PriKey] FFiOHOSPriKeyGetAsyKeySpec failed to get private key obj!");
                    *errCode = HCF_INVALID_PARAMS;
                    return ret;
                }
                AsyKeySpecItem item = AsyKeySpecItem(itemType);
                *errCode = priKey->getAsyKeySpecBigInteger(priKey, item, &ret);
                LOGD("[PriKey] FFiOHOSPriKeyGetAsyKeySpec end");
                return ret;
            }

            const char *FfiOHOSPriKeyGetFormat(int64_t id, int32_t* errCode)
            {
                LOGD("[PriKey] GetFormat start");
                auto instance = FFIData::GetData<PriKeyImpl>(id);
                if (!instance) {
                    LOGE("[PriKey] instance not exist.");
                    *errCode = HCF_ERR_MALLOC;
                    return nullptr;
                }
                const char* res = instance->GetFormat(errCode);
                LOGD("[PriKey] GetFormat success");
                return res;
            }

            //--------------------- pubkey
            HcfBlob FFiOHOSPubKeyGetEncoded(int64_t id, int32_t *errCode)
            {
                LOGD("[PubKey] FFiOHOSPubKeyGetEncoded start");
                HcfBlob ret = { .data = nullptr, .len = 0 };
                auto instance = FFIData::GetData<PubKeyImpl>(id);
                if (!instance) {
                    LOGE("[PubKey] FFiOHOSPubKeyGetEncoded failed to unwrap public key obj!");
                    *errCode = HCF_INVALID_PARAMS;
                    return ret;
                }
                HcfPubKey *pubKey = instance->GetPubKey();
                if (pubKey == nullptr) {
                    LOGE("[PubKey] FFiOHOSPubKeyGetEncoded failed to get public key obj!");
                    *errCode = HCF_INVALID_PARAMS;
                    return ret;
                }
                *errCode = pubKey->base.getEncoded(&pubKey->base, &ret);
                LOGD("[PubKey] FFiOHOSPubKeyGetEncoded end");
                return ret;
            }

            HcfBlob FFiOHOSPubKeyGetEncodedDer(int64_t id, char *format, int32_t *errCode)
            {
                LOGD("[PubKey] FFiOHOSPubKeyGetEncodedDer start");
                HcfBlob ret = { .data = nullptr, .len = 0 };
                auto instance = FFIData::GetData<PubKeyImpl>(id);
                if (!instance) {
                    LOGE("[PubKey] FFiOHOSPubKeyGetEncodedDer failed to unwrap public key obj!");
                    *errCode = HCF_INVALID_PARAMS;
                    return ret;
                }
                HcfPubKey *pubKey = instance->GetPubKey();
                if (pubKey == nullptr) {
                    LOGE("[PubKey] FFiOHOSPubKeyGetEncodedDer failed to get public key obj!");
                    *errCode = HCF_INVALID_PARAMS;
                    return ret;
                }
                *errCode = pubKey->getEncodedDer(pubKey, format, &ret);
                LOGD("[PubKey] FFiOHOSPubKeyGetEncodedDer end");
                return ret;
            }

            char *FFiOHOSPubKeyGetEncodedPem(int64_t id, char *format, int32_t *errCode)
            {
                LOGD("[PubKey] FFiOHOSPubKeyGetEncodedPem start");
                char *ret = nullptr;
                auto instance = FFIData::GetData<PubKeyImpl>(id);
                if (!instance) {
                    LOGE("[PubKey] FFiOHOSPubKeyGetEncodedPem failed to unwrap public key obj!");
                    *errCode = HCF_INVALID_PARAMS;
                    return ret;
                }
                HcfPubKey *pubKey = instance->GetPubKey();
                if (pubKey == nullptr) {
                    LOGE("[PubKey] FFiOHOSPubKeyGetEncodedPem failed to get public key obj!");
                    *errCode = HCF_INVALID_PARAMS;
                    return ret;
                }
                *errCode = pubKey->base.getEncodedPem(&pubKey->base, format, &ret);
                LOGD("[PubKey] FFiOHOSPubKeyGetEncodedPem end");
                return ret;
            }

            int FFiOHOSPubKeyGetAsyKeySpecByNum(int64_t id, int32_t itemType, int32_t *errCode)
            {
                LOGD("[PubKey] FFiOHOSPubKeyGetAsyKeySpec start");
                auto instance = FFIData::GetData<PubKeyImpl>(id);
                int ret = 0;
                if (!instance) {
                    LOGE("[PubKey] FFiOHOSPubKeyGetAsyKeySpec failed to unwrap public key obj!");
                    *errCode = HCF_INVALID_PARAMS;
                    return ret;
                }
                HcfPubKey *pubKey = instance->GetPubKey();
                if (pubKey == nullptr) {
                    LOGE("[PubKey] FFiOHOSPubKeyGetAsyKeySpec failed to get public key obj!");
                    *errCode = HCF_INVALID_PARAMS;
                    return ret;
                }
                AsyKeySpecItem item = AsyKeySpecItem(itemType);
                *errCode = pubKey->getAsyKeySpecInt(pubKey, item, &ret);
                LOGD("[PubKey] FFiOHOSPubKeyGetAsyKeySpec end");
                return ret;
            }

            char *FFiOHOSPubKeyGetAsyKeySpecByStr(int64_t id, int32_t itemType, int32_t *errCode)
            {
                LOGD("[PubKey] FFiOHOSPubKeyGetAsyKeySpec start");
                auto instance = FFIData::GetData<PubKeyImpl>(id);
                char *ret = nullptr;
                if (!instance) {
                    LOGE("[PubKey] FFiOHOSPubKeyGetAsyKeySpec failed to unwrap public key obj!");
                    *errCode = HCF_INVALID_PARAMS;
                    return ret;
                }
                HcfPubKey *pubKey = instance->GetPubKey();
                if (pubKey == nullptr) {
                    LOGE("[PubKey] FFiOHOSPubKeyGetAsyKeySpec failed to get public key obj!");
                    *errCode = HCF_INVALID_PARAMS;
                    return ret;
                }
                AsyKeySpecItem item = AsyKeySpecItem(itemType);
                *errCode = pubKey->getAsyKeySpecString(pubKey, item, &ret);
                LOGD("[PubKey] FFiOHOSPubKeyGetAsyKeySpec end");
                return ret;
            }

            HcfBigInteger FFiOHOSPubKeyGetAsyKeySpecByBigInt(int64_t id, int32_t itemType, int32_t *errCode)
            {
                LOGD("[PubKey] FFiOHOSPubKeyGetAsyKeySpec start");
                auto instance = FFIData::GetData<PubKeyImpl>(id);
                HcfBigInteger ret = { 0 };
                if (!instance) {
                    LOGE("[PubKey] FFiOHOSPubKeyGetAsyKeySpec failed to unwrap public key obj!");
                    *errCode = HCF_INVALID_PARAMS;
                    return ret;
                }
                HcfPubKey *pubKey = instance->GetPubKey();
                if (pubKey == nullptr) {
                    LOGE("[PubKey] FFiOHOSPubKeyGetAsyKeySpec failed to get public key obj!");
                    *errCode = HCF_INVALID_PARAMS;
                    return ret;
                }
                AsyKeySpecItem item = AsyKeySpecItem(itemType);
                *errCode = pubKey->getAsyKeySpecBigInteger(pubKey, item, &ret);
                LOGD("[PubKey] FFiOHOSPubKeyGetAsyKeySpec end");
                return ret;
            }

            const char *FfiOHOSPubKeyGetFormat(int64_t id, int32_t* errCode)
            {
                LOGD("[PubKey] GetFormat start");
                auto instance = FFIData::GetData<PubKeyImpl>(id);
                if (!instance) {
                    LOGE("[PubKey] instance not exist.");
                    *errCode = HCF_ERR_MALLOC;
                    return nullptr;
                }
                const char* res = instance->GetFormat(errCode);
                LOGD("[PubKey] GetFormat success");
                return res;
            }

            void *FfiOHOSPubKeyGetRawPointer(int64_t id)
            {
                LOGD("[PubKey] FfiOHOSPubKeyGetRawPointer start");
                auto instance = FFIData::GetData<PubKeyImpl>(id);
                if (!instance) {
                    LOGE("[PubKey] instance not exist.");
                    return nullptr;
                }
                HcfPubKey *key = instance->GetPubKey();
                LOGD("[PubKey] FfiOHOSPubKeyGetRawPointer success");
                return key;
            }

            int64_t FfiOHOSPubKeyFromRawPointer(void *ptr, const char **retString, int32_t *errCode)
            {
                LOGD("[PubKey] FfiOHOSPubKeyFromRawPointer start");
                HcfPubKey *pubKey = static_cast<HcfPubKey *>(ptr);
                auto pub = FFIData::Create<PubKeyImpl>(pubKey);
                if (pub == nullptr) {
                    *errCode = HCF_ERR_MALLOC;
                    LOGE("new pub key failed");
                    return 0;
                }
                *retString = pubKey->base.getAlgorithm(&pubKey->base);
                LOGD("[PubKey] FfiOHOSPubKeyFromRawPointer success");
                return pub->GetID();
            }

            // ------------------------------------keypair
            int64_t FFiOHOSKeyPairPubKey(int64_t id, int32_t *errCode)
            {
                LOGD("[KeyPair] FFiOHOSKeyPairPubKey start");
                auto instance = FFIData::GetData<KeyPairImpl>(id);
                if (!instance) {
                    *errCode = HCF_INVALID_PARAMS;
                    LOGE("build instance fail.");
                    return 0;
                }
                HcfKeyPair *keyPair = instance->GetHcfKeyPair();
                if (keyPair == nullptr) {
                    *errCode = HCF_INVALID_PARAMS;
                    LOGE("get keyPair fail.");
                    return 0;
                }
                HcfPubKey *pubKey = keyPair->pubKey;
                if (pubKey == nullptr) {
                    *errCode = HCF_INVALID_PARAMS;
                    LOGE("get pubKey fail.");
                    return 0;
                }
                auto pub = FFIData::Create<PubKeyImpl>(pubKey);
                if (pub == nullptr) {
                    *errCode = HCF_ERR_MALLOC;
                    LOGE("new pub key failed");
                    return 0;
                }
                LOGD("[KeyPair] FFiOHOSKeyPairPubKey end");
                return pub->GetID();
            }

            int64_t FFiOHOSKeyPairPriKey(int64_t id, int32_t *errCode)
            {
                LOGD("[KeyPair] FFiOHOSKeyPairPriKey start");
                auto instance = FFIData::GetData<KeyPairImpl>(id);
                if (!instance) {
                    *errCode = HCF_INVALID_PARAMS;
                    LOGE("build instance fail.");
                    return 0;
                }
                HcfKeyPair *keyPair = instance->GetHcfKeyPair();
                if (keyPair == nullptr) {
                    *errCode = HCF_INVALID_PARAMS;
                    LOGE("get keyPair fail.");
                    return 0;
                }
                HcfPriKey *priKey = keyPair->priKey;
                if (priKey == nullptr) {
                    *errCode = HCF_INVALID_PARAMS;
                    LOGE("get priKey fail.");
                    return 0;
                }
                auto pri = FFIData::Create<PriKeyImpl>(priKey);
                if (pri == nullptr) {
                    *errCode = HCF_ERR_MALLOC;
                    LOGE("new pri key failed");
                    return 0;
                }
                LOGD("[KeyPair] FFiOHOSKeyPairPriKey end");
                return pri->GetID();
            }

            // ------------------------------------kdf
            int64_t FFiOHOSKdfConstructor(char *algName, int32_t *errCode)
            {
                LOGD("[Kdf] FFiOHOSKdfConstructor start");
                HcfKdf *kdf = nullptr;
                *errCode = HcfKdfCreate(algName, &kdf);
                if (*errCode != HCF_SUCCESS) {
                    *errCode = HCF_INVALID_PARAMS;
                    LOGE("create c kdf fail.");
                    return 0;
                }
                auto instance = FFIData::Create<KdfImpl>(kdf);
                if (!instance) {
                    *errCode = HCF_ERR_MALLOC;
                    HcfObjDestroy(kdf);
                    LOGE("new kdf failed!");
                    return 0;
                }
                LOGD("[Kdf] FFiOHOSKdfConstructor end");
                return instance->GetID();
            }

            int32_t FFiOHOSKdfGenerateSecretByPB(int64_t id, HcfPBKDF2ParamsSpec *params)
            {
                LOGD("[Kdf] FiOHOSKdfGenerateSecretByPB start");
                auto instance = FFIData::GetData<KdfImpl>(id);
                if (!instance) {
                    LOGE("[PubKey] FiOHOSKdfGenerateSecretByPB failed to get kdf impl obj!");
                    return HCF_INVALID_PARAMS;
                }
                HcfKdfParamsSpec *tmp = reinterpret_cast<HcfKdfParamsSpec *>(params);
                LOGD("[Kdf] FiOHOSKdfGenerateSecretByPB end");
                return instance->GenerateSecret(tmp);
            }

            int32_t FFiOHOSKdfGenerateSecretByH(int64_t id, HcfHkdfParamsSpec *params)
            {
                LOGD("[Kdf] FFiOHOSKdfGenerateSecretByH start");
                auto instance = FFIData::GetData<KdfImpl>(id);
                if (!instance) {
                    LOGE("[PubKey] F FFiOHOSKdfGenerateSecretByH failed to get kdf impl obj!");
                    return HCF_INVALID_PARAMS;
                }
                HcfKdfParamsSpec *tmp = reinterpret_cast<HcfKdfParamsSpec *>(params);
                LOGD("[Kdf] FFiOHOSKdfGenerateSecretByH end");
                return instance->GenerateSecret(tmp);
            }

            // --------------------------ecc_key_util
            HcfEccCommParamsSpec *FFiOHOSECCKeyUtilGenECCCommonParamsSpec(char *curveName, int32_t *errCode)
            {
                return ECCKeyUtilImpl::GenECCCommonParamsSpec(curveName, errCode);
            }

            HcfPoint FFiOHOSECCKeyUtilConvertPoint(char *curveName, HcfBlob encodedPoint, int32_t *errCode)
            {
                return ECCKeyUtilImpl::ConvertPoint(curveName, encodedPoint, errCode);
            }

            HcfBlob FFiOHOSECCKeyUtilGetEncodedPoint(char *curveName, HcfPoint point, char *format, int32_t *errCode)
            {
                return ECCKeyUtilImpl::GetEncodedPoint(curveName, point, format, errCode);
            }

            // ---------------------------keyagreement
            int64_t FFiOHOSKeyAgreementConstructor(char *algName, int32_t *errCode)
            {
                LOGD("[KeyAgreement] FFiOHOSKdfConstructor start");
                HcfKeyAgreement *keyAgreement = nullptr;
                *errCode = HcfKeyAgreementCreate(algName, &keyAgreement);
                if (*errCode != HCF_SUCCESS) {
                    *errCode = HCF_INVALID_PARAMS;
                    LOGE("create c keyAgreement fail.");
                    return 0;
                }
                auto instance = FFIData::Create<KeyAgreementImpl>(keyAgreement);
                if (!instance) {
                    *errCode = HCF_ERR_MALLOC;
                    HcfObjDestroy(keyAgreement);
                    LOGE("new key agreement failed!");
                    return 0;
                }
                LOGD("[KeyAgreement] FFiOHOSKdfConstructor end");
                return instance->GetID();
            }

            HcfBlob FFiOHOSKeyAgreementGenerateSecret(int64_t id, int64_t priId, int64_t pubId, int32_t *errCode)
            {
                LOGD("[KeyAgreement] FFiOHOSKeyAgreementGenerateSecret start");
                auto instance = FFIData::GetData<KeyAgreementImpl>(id);
                HcfBlob blob = { 0 };
                if (!instance) {
                    LOGE("[KeyAgreement] FFiOHOSKeyAgreementGenerateSecret failed to get key agreement obj!");
                    *errCode = HCF_INVALID_PARAMS;
                    return blob;
                }
                auto priKey = FFIData::GetData<PriKeyImpl>(priId);
                if (!priKey) {
                    LOGE("[KeyAgreement] FFiOHOSKeyAgreementGenerateSecret failed to get priKey obj!");
                    *errCode = HCF_INVALID_PARAMS;
                    return blob;
                }
                auto pubKey = FFIData::GetData<PubKeyImpl>(pubId);
                if (!pubKey) {
                    LOGE("[KeyAgreement] FFiOHOSKeyAgreementGenerateSecret failed to get priKey obj!");
                    *errCode = HCF_INVALID_PARAMS;
                    return blob;
                }
                LOGD("[KeyAgreement] FFiOHOSKeyAgreementGenerateSecret end");
                return instance->GenerateSecret(priKey->GetPriKey(), pubKey->GetPubKey(), errCode);
            }

            // dh_key_util
            HcfDhCommParamsSpec *FFiOHOSDHKeyUtilGenDHCommonParamsSpec(int32_t pLen, int32_t skLen, int32_t *errCode)
            {
                return DHKeyUtilImpl::GenDHCommonParamsSpec(pLen, skLen, errCode);
            }

            // sm2_crypto_util
            HcfBlob FFiOHOSSm2CryptoUtilGenCipherTextBySpec(Sm2CipherTextSpec spec, char *mode, int32_t *errCode)
            {
                return Sm2CryptoUtilImpl::GenCipherTextBySpec(spec, mode, errCode);
            }

            Sm2CipherTextSpec *FFiOHOSSm2CryptoUtilGetCipherTextSpec(HcfBlob input, char *mode, int32_t *errCode)
            {
                return Sm2CryptoUtilImpl::GetCipherTextSpec(input, mode, errCode);
            }
        }
    } // namespace CryptoFramework
} // namespace OHOS