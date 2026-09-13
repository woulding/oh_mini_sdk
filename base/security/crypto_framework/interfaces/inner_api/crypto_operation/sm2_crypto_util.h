/*
 * Copyright (C) 2024 Huawei Device Co., Ltd.
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

#ifndef HCF_SM2_CRYPTO_UTIL_H
#define HCF_SM2_CRYPTO_UTIL_H

#include "result.h"
#include "sm2_crypto_params.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief Generate the SM2 ciphertext in ASN.1 format according to the specific data.
 *
 * @param spec - indicates the specific data of SM2 ciphertext.
 * @param mode - indicates the arrangement mode of the SM2 ciphertext.
 * @param output - the SM2 ciphertext in ASN.1 format.
 * @return Returns the status code of the execution.
 * @since 12
 * @version 1.0
 */
HcfResult HcfGenCipherTextBySpec(Sm2CipherTextSpec *spec, const char *mode, HcfBlob *output);
/**
 * @brief Get the specific data from the SM2 ciphertext in ASN.1 format.
 *
 * @param input - indicates the SM2 ciphertext in ASN.1 format.
 * @param mode - indicates the arrangement mode of the SM2 ciphertext.
 * @param returnSpc - the specific data of SM2 ciphertext.
 * @return Returns the status code of the execution.
 * @since 12
 * @version 1.0
 */
HcfResult HcfGetCipherTextSpec(HcfBlob *input, const char *mode, Sm2CipherTextSpec **returnSpc);

#ifdef __cplusplus
}
#endif

#endif
