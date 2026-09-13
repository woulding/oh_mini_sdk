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
#include "dh_openssl_common.h"
#include <string.h>

#include "securec.h"

#include "detailed_dh_key_params.h"
#include "log.h"
#include "memory.h"
#include "openssl_adapter.h"
#include "openssl_class.h"
#include "openssl_common.h"

enum HcfDhNamedGroupId {
    HCF_DH_MODP_SIZE_1536 = 0,
    HCF_DH_MODP_SIZE_2048,
    HCF_DH_MODP_SIZE_3072,
    HCF_DH_MODP_SIZE_4096,
    HCF_DH_MODP_SIZE_6144,
    HCF_DH_MODP_SIZE_8192,
    HCF_DH_FFDHE_SIZE_2048,
    HCF_DH_FFDHE_SIZE_3072,
    HCF_DH_FFDHE_SIZE_4096,
    HCF_DH_FFDHE_SIZE_6144,
    HCF_DH_FFDHE_SIZE_8192
};

enum HcfDhPLenSize {
    HCF_DH_PLEN_2048 = 2048,
    HCF_DH_PLEN_3072 = 3072,
    HCF_DH_PLEN_4096 = 4096,
    HCF_DH_PLEN_6144 = 6144,
    HCF_DH_PLEN_8192 = 8192
};

typedef struct {
    enum HcfDhNamedGroupId dhId;
    char *nidName;
} NidNameByType;

static const NidNameByType NID_NAME_BY_TYPE_MAP[] = {
    { HCF_DH_MODP_SIZE_1536, "modp_1536" },
    { HCF_DH_MODP_SIZE_2048, "modp_2048" },
    { HCF_DH_MODP_SIZE_3072, "modp_3072" },
    { HCF_DH_MODP_SIZE_4096, "modp_4096" },
    { HCF_DH_MODP_SIZE_6144, "modp_6144" },
    { HCF_DH_MODP_SIZE_8192, "modp_8192" },
    { HCF_DH_FFDHE_SIZE_2048, "ffdhe2048" },
    { HCF_DH_FFDHE_SIZE_3072, "ffdhe3072" },
    { HCF_DH_FFDHE_SIZE_4096, "ffdhe4096" },
    { HCF_DH_FFDHE_SIZE_6144, "ffdhe6144" },
    { HCF_DH_FFDHE_SIZE_8192, "ffdhe8192" }
};

typedef struct {
    enum HcfDhPLenSize pLen;
    char *nidName;
} NidNameByPLen;

static const NidNameByPLen NID_NAME_PLEN_MAP[] = {
    { HCF_DH_PLEN_2048, "ffdhe2048" },
    { HCF_DH_PLEN_3072, "ffdhe3072" },
    { HCF_DH_PLEN_4096, "ffdhe4096" },
    { HCF_DH_PLEN_6144, "ffdhe6144" },
    { HCF_DH_PLEN_8192, "ffdhe8192" }
};

EVP_PKEY *NewEvpPkeyByDh(DH *dh, bool withDuplicate)
{
    if (dh == NULL) {
        LOGE("DH is NULL");
        return NULL;
    }
    EVP_PKEY *pKey = OpensslEvpPkeyNew();
    if (pKey == NULL) {
        LOGE("EVP_PKEY_new fail");
        HcfPrintOpensslError();
        return NULL;
    }
    if (withDuplicate) {
        if (OpensslEvpPkeySet1Dh(pKey, dh) != HCF_OPENSSL_SUCCESS) {
            LOGE("EVP_PKEY_set1_DH fail");
            HcfPrintOpensslError();
            OpensslEvpPkeyFree(pKey);
            return NULL;
        }
    } else {
        if (OpensslEvpPkeyAssignDh(pKey, dh) != HCF_OPENSSL_SUCCESS) {
            LOGE("EVP_PKEY_assign_DH fail");
            HcfPrintOpensslError();
            OpensslEvpPkeyFree(pKey);
            return NULL;
        }
    }
    return pKey;
}

char *GetNidNameByDhId(int32_t pLen)
{
    if (pLen < 0) {
        LOGE("Invalid pLen");
        return NULL;
    }
    for (uint32_t i = 0; i < sizeof(NID_NAME_BY_TYPE_MAP) / sizeof(NID_NAME_BY_TYPE_MAP[0]); i++) {
        if (NID_NAME_BY_TYPE_MAP[i].dhId == (uint32_t)pLen) {
            return NID_NAME_BY_TYPE_MAP[i].nidName;
        }
    }
    LOGE("Invalid prime len:%{public}d", pLen);
    return NULL;
}

char *GetNidNameByDhPLen(int32_t pLen)
{
    if (pLen < 0) {
        LOGE("Invalid pLen");
        return NULL;
    }
    for (uint32_t i = 0; i < sizeof(NID_NAME_PLEN_MAP) / sizeof(NID_NAME_PLEN_MAP[0]); i++) {
        if (NID_NAME_PLEN_MAP[i].pLen == (uint32_t)pLen) {
            return NID_NAME_PLEN_MAP[i].nidName;
        }
    }
    LOGE("Invalid prime len:%{public}d", pLen);
    return NULL;
}
