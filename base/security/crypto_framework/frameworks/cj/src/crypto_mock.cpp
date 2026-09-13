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

#include "cj_common_ffi.h"

extern "C" {
FFI_EXPORT int FfiOHOSCreateRandom = 0;
FFI_EXPORT int FfiOHOSRandomGetAlgName = 0;
FFI_EXPORT int FfiOHOSGenerateRandom = 0;
FFI_EXPORT int FfiOHOSSetSeed = 0;
FFI_EXPORT int FfiOHOSCreateMd = 0;
FFI_EXPORT int FfiOHOSMdUpdate = 0;
FFI_EXPORT int FfiOHOSDigest = 0;
FFI_EXPORT int FfiOHOSGetMdLength = 0;
FFI_EXPORT int FfiOHOSCreateSymKeyGenerator = 0;
FFI_EXPORT int FfiOHOSSymKeyGeneratorGetAlgName = 0;
FFI_EXPORT int FfiOHOSGenerateSymKey = 0;
FFI_EXPORT int FfiOHOSConvertKey = 0;
FFI_EXPORT int FfiOHOSSymKeyGetAlgName = 0;
FFI_EXPORT int FfiOHOSSymKeyGetFormat = 0;
FFI_EXPORT int FfiOHOSSymKeyGetEncoded = 0;
FFI_EXPORT int FfiOHOSClearMem = 0;
FFI_EXPORT int FfiOHOSSymKeyGetHcfKey = 0;
FFI_EXPORT int FfiOHOSCreateCipher = 0;
FFI_EXPORT int FfiOHOSCipherInitByIv = 0;
FFI_EXPORT int FfiOHOSCipherInitByGcm = 0;
FFI_EXPORT int FfiOHOSCipherInitByCcm = 0;
FFI_EXPORT int FfiOHOSCipherInitWithOutParams = 0;
FFI_EXPORT int FfiOHOSCipherUpdate = 0;
FFI_EXPORT int FfiOHOSCipherDoFinal = 0;
FFI_EXPORT int FfiOHOSSetCipherSpec = 0;
FFI_EXPORT int FfiOHOSGetCipherSpecString = 0;
FFI_EXPORT int FfiOHOSGetCipherSpecUint8Array = 0;
FFI_EXPORT int FfiOHOSCipherGetAlgName = 0;
FFI_EXPORT int FFiOHOSCryptoMacConstructor = 0;
FFI_EXPORT int FfiOHOSCryptoMacInit = 0;
FFI_EXPORT int FfiOHOSCryptoMacUpdate = 0;
FFI_EXPORT int FfiOHOSCryptoMacDoFinal = 0;
FFI_EXPORT int FfiOHOSGCryptoGetMacLength = 0;
FFI_EXPORT int FFiOHOSCryptoSignConstructor = 0;
}