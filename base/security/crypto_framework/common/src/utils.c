/*
 * Copyright (C) 2022 Huawei Device Co., Ltd.
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
#include "securec.h"
#include "memory.h"
#include "log.h"
#include "crypto_operation_err.h"
#include "utils.h"

#define ERROR_STR_LENGTH 0

bool HcfIsStrValid(const char *str, uint32_t maxLen)
{
    if (str == NULL) {
        LOGE("Input string is NULL ptr");
        return false;
    }
    // One byte must be reserved for the terminator.
    if (strnlen(str, maxLen) >= maxLen) {
        LOGE("Input string is beyond max length");
        return false;
    }
    return true;
}

bool HcfIsBlobValid(const HcfBlob *blob)
{
    return ((blob != NULL) && (blob->data != NULL) && (blob->len > 0));
}

bool HcfIsClassMatch(const HcfObjectBase *obj, const char *className)
{
    if ((obj == NULL) || (obj->getClass == NULL) || (obj->getClass() == NULL) || (className == NULL)) {
        LOGE("Obj or className is null");
        return false;
    }
    if (strcmp(obj->getClass(), className) == 0) {
        return true;
    } else {
        LOGE("Class is not match. expect class: %{public}s, input class: %{public}s", className, obj->getClass());
        return false;
    }
}

size_t HcfStrlen(const char *str)
{
    if (str == NULL) {
        LOGE("Str is null");
        return ERROR_STR_LENGTH;
    }
    return strlen(str);
}

#define ERR_MSG_VALID_LEN 250
#define ERR_MSG_LEN 256
void HcfGetCryptoOperationErrMsg(HcfResult errCode, const char **errMsg, char **errMsgBuf)
{
    if (errCode != HCF_ERR_CRYPTO_OPERATION) {
        return;
    }

    uint32_t len = (uint32_t)strlen(*errMsg);
    if (len >= ERR_MSG_VALID_LEN) {
        return;
    }

    const char *p = NULL;
    char *buffer = (char *)HcfMalloc(ERR_MSG_LEN, 0);
    if (buffer == NULL) {
        return;
    }

    (void)memcpy_s(buffer, ERR_MSG_VALID_LEN, *errMsg, len);
    buffer[len++] = '(';
    buffer[len] = '\0';

    p = HcfGetOperationErrorMessage(buffer + len, ERR_MSG_VALID_LEN - len);
    if (p == NULL) {
        HcfFree(buffer);
        return;
    }
    len = strlen(buffer);
    buffer[len++] = ')';
    buffer[len] = '\0';
    *errMsg = buffer;
    if (*errMsgBuf != NULL) {
        HcfFree(*errMsgBuf);
    }
    *errMsgBuf = buffer;
}