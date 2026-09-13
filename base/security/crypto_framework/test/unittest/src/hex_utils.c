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

#include "hex_utils.h"

#include <stdio.h>
#include <string.h>

#include "memory.h"

int32_t HexCharToVal(char ch)
{
    const int32_t hexAlphaOffset = 10;
    if ((ch >= '0') && (ch <= '9')) {
        return ch - '0';
    }
    if ((ch >= 'a') && (ch <= 'f')) {
        return ch - 'a' + hexAlphaOffset;
    }
    if ((ch >= 'A') && (ch <= 'F')) {
        return ch - 'A' + hexAlphaOffset;
    }
    return -1;
}

HcfResult HexStringToBlob(const char *hexStr, HcfBlob *blob)
{
    const size_t hexCharPairLen = 2;
    const int32_t hexNibbleBits = 4;
    if ((hexStr == NULL) || (blob == NULL)) {
        return HCF_ERR_PARAMETER_CHECK_FAILED;
    }
    size_t hexLen = strlen(hexStr);
    if ((hexLen == 0) || ((hexLen % hexCharPairLen) != 0)) {
        return HCF_ERR_PARAMETER_CHECK_FAILED;
    }

    size_t outLen = hexLen / hexCharPairLen;
    uint8_t *outData = (uint8_t *)HcfMalloc(outLen, 0);
    if (outData == NULL) {
        return HCF_ERR_MALLOC;
    }

    for (size_t i = 0; i < outLen; i++) {
        int32_t high = HexCharToVal(hexStr[i * hexCharPairLen]);
        int32_t low = HexCharToVal(hexStr[i * hexCharPairLen + 1]);
        if ((high < 0) || (low < 0)) {
            HcfFree(outData);
            return HCF_ERR_PARAMETER_CHECK_FAILED;
        }
        outData[i] = (uint8_t)((high << hexNibbleBits) | low);
    }

    blob->data = outData;
    blob->len = outLen;
    return HCF_SUCCESS;
}

void PrintfHex(const char *tag, uint8_t *in, size_t inLen)
{
    printf("%s:\n", tag);
    for (size_t i = 0; i < inLen; i++) {
        printf("%02hhX", in[i]);
    }
    printf("\n");
}
