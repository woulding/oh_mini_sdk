/*
 * Copyright (C) 2023 Huawei Device Co., Ltd.
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

#include "dh_key_util.h"
#include <securec.h>
#include "dh_key_util_spi.h"
#include "config.h"
#include "dh_common_param_spec_generator_openssl.h"
#include "key_utils.h"
#include "params_parser.h"
#include "log.h"
#include "memory.h"
#include "utils.h"

HcfResult HcfDhKeyUtilCreate(int32_t pLen, int32_t skLen, HcfDhCommParamsSpec **returnCommonParamSpec)
{
    if ((pLen < 0) || (skLen < 0) || (returnCommonParamSpec == NULL)) {
        LOGE("Failed to parse params!");
        return HCF_INVALID_PARAMS;
    }

    if (skLen > pLen) {
        LOGE("skLen is greater than pLen!");
        return HCF_INVALID_PARAMS;
    }

    HcfDhCommParamsSpecSpi *spiInstance = NULL;
    HcfResult ret = HcfDhCommonParamSpecCreate(pLen, skLen, &spiInstance);
    if (ret != HCF_SUCCESS) {
        LOGE("Failed to create spi object!");
        return HCF_ERR_MALLOC;
    }
    ret = CreateDhCommonSpecImpl(&(spiInstance->paramsSpec), returnCommonParamSpec);
    if (ret != HCF_SUCCESS) {
        LOGE("Failed to create spi impl object!");
    }
    FreeDhCommParamsSpec(&(spiInstance->paramsSpec));
    HcfFree(spiInstance);
    spiInstance = NULL;
    return ret;
}