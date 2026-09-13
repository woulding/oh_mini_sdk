/*
 * Copyright (C) 2026 Huawei Device Co., Ltd.
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

#include <string.h>
#include <openssl/err.h>
#include "securec.h"
#include "crypto_operation_err.h"
#include "log.h"

void HcfClearPluginErrorMessage(void)
{
    ERR_clear_error();
}

char *HcfGetPluginErrorMessage(char *buff, uint32_t len)
{
    if (buff == NULL || len == 0) {
        LOGE("Invalid input parameter.");
        return NULL;
    }

    unsigned long errCode = ERR_get_error();
    if (errCode == 0) {
        LOGE("No openssl error code found.");
        return NULL;
    }

    uint32_t unusedLen = len - 1;
    uint32_t pos = 0;
    while (errCode != 0 && unusedLen != 0) {
        const char *errStr = ERR_reason_error_string(errCode);
        if (errStr == NULL) {
            errCode = ERR_get_error();
            continue;
        }
        uint32_t errStrLen = strlen(errStr);
        uint32_t tmpLen = errStrLen <= unusedLen ? errStrLen : unusedLen;
        (void)memcpy_s(buff + pos, unusedLen, errStr, tmpLen);
        unusedLen -= tmpLen;
        pos += tmpLen;
        errCode = ERR_get_error();
        if (unusedLen > 0) {
            buff[pos] = ';';
            unusedLen--;
            pos++;
        }
    }
    buff[pos] = '\0';
    return buff;
}
