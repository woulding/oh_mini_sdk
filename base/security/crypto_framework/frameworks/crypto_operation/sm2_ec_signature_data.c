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

#include "sm2_ec_signature_data.h"
#include <securec.h>
#include "cipher_sm2_ecdsa_signature_openssl.h"
#include "log.h"
#include "memory.h"
#include "utils.h"

static bool CheckSm2EcSignatureDataSpec(Sm2EcSignatureDataSpec *spec)
{
    if (spec == NULL) {
        LOGE("Spec is null");
        return false;
    }
    if ((spec->rCoordinate.data == NULL) || (spec->rCoordinate.len == 0)) {
        LOGE("Spec.xCoordinate is null");
        return false;
    }
    if ((spec->sCoordinate.data == NULL) || (spec->sCoordinate.len == 0)) {
        LOGE("Spec.yCoordinate is null");
        return false;
    }
    return true;
}

HcfResult HcfGenEcSignatureDataBySpec(Sm2EcSignatureDataSpec *spec, HcfBlob *output)
{
    if (output == NULL) {
        LOGE("Invalid param output!");
        return HCF_INVALID_PARAMS;
    }
    if (!CheckSm2EcSignatureDataSpec(spec)) {
        LOGE("Invalid param spec!");
        return HCF_INVALID_PARAMS;
    }
    HcfResult res = HcfSm2SpecToDerData(spec, output);
    if (res != HCF_SUCCESS) {
        LOGE("Failed to convert construct to asn1!");
    }
    return res;
}

HcfResult HcfGenEcSignatureSpecByData(HcfBlob *input, Sm2EcSignatureDataSpec **returnSpc)
{
    if (input == NULL) {
        LOGE("Invalid param input!");
        return HCF_INVALID_PARAMS;
    }
    if (returnSpc == NULL) {
        LOGE("Invalid param returnSpc!");
        return HCF_INVALID_PARAMS;
    }
    HcfResult res = HcfDerDataToSm2Spec(input, returnSpc);
    if (res != HCF_SUCCESS) {
        LOGE("Failed to convert asn1 to construct!");
        return res;
    }
    return HCF_SUCCESS;
}