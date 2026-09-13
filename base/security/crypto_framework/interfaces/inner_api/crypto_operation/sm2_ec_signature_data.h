/*
 * Copyright (C) 2025 Huawei Device Co., Ltd.
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

#ifndef HCF_SM2_EC_SIGNATURE_DATA_H
#define HCF_SM2_EC_SIGNATURE_DATA_H

#include "result.h"
#include "sm2_crypto_params.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief Generate the SM2 ciphertext in ASN.1 format according to the specific data.
 *
 * @param spec - indicates the EC signature data spec..
 * @param output - indicates the signature data in DER format.
 * @return Returns the status code of the execution.
 * @since 20
 * @version 1.0
 */
HcfResult HcfGenEcSignatureDataBySpec(Sm2EcSignatureDataSpec *spec, HcfBlob *output);
/**
 * @brief Get the specific data from the SM2 ciphertext in ASN.1 format.
 *
 * @param input - indicates the signature data in DER format.
 * @param returnSpc - indicates the EC signature data spec..
 * @return Returns the status code of the execution.
 * @since 20
 * @version 1.0
 */
HcfResult HcfGenEcSignatureSpecByData(HcfBlob *input, Sm2EcSignatureDataSpec **returnSpc);

#ifdef __cplusplus
}
#endif

#endif
