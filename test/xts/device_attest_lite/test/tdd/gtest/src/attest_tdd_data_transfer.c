/*
 * Copyright (C) 2023 Huawei Device Co., Ltd.
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

#include <pthread.h>
#include <ctype.h>
#include <securec.h>
#include "attest_utils.h"
#include "attest_utils_log.h"
#include "attest_tdd_data_transfer.h"

#define ATTEST_LEAST_MALLOC_LEN 2

static size_t AttestGetMallocLen(const char* input)
{
    size_t totalFlag = 0;
    for (size_t inputIndex = 0; inputIndex < strlen(input); inputIndex++) {
        if (*(input + inputIndex) == '\0') {
            break;
        }

        if (*(input + inputIndex) == ',') {
            totalFlag++;
        }

        if (totalFlag >= MAX_ATTEST_MALLOC_BUFF_SIZE) {
            totalFlag = 0;
            break;
        }
    }

    size_t totalByte = totalFlag + 1;
    size_t charLen = sizeof(unsigned char);
    size_t mallocLen = charLen * totalByte + 1;
    return mallocLen;
}

int32_t AttestSeriaToBinary(const char* input, uint8_t** buf, size_t len)
{
    if (buf == NULL || *buf == NULL) {
        return ATTEST_ERR;
    }
    size_t mollocLen = AttestGetMallocLen(input);
    if (mollocLen <= ATTEST_LEAST_MALLOC_LEN || mollocLen > ATTEST_MAX_TLS_LEN) {
        return ATTEST_ERR;
    }
    uint8_t *temp = (uint8_t *)malloc(mollocLen);
    if (temp == NULL) {
        return ATTEST_ERR;
    }
    memset_s(temp, mollocLen, 0, mollocLen);

    char *indexInput = (char *)input;
    size_t inputLen = strlen(input);
    size_t tempLen = 0;
    unsigned char *indexTemp = (unsigned char*)temp;
    unsigned char total = 0;
    int32_t ret = ATTEST_OK;
    while ((tempLen <= inputLen) && (*indexInput != '\0')) {
        if (*indexInput == ',') {
            *indexTemp++ = total;
            total = 0;
        } else if (isdigit(*indexInput)) {
            total = total * ATTEST_DECIMAL + (*indexInput - ATTEST_ZERO_CHAR);
        } else {
            ret = ATTEST_ERR;
            break;
        }
        tempLen++;
        indexInput++;
    }
    if (ret != ATTEST_OK) {
        free(temp);
        return ATTEST_ERR;
    }

    if (memcpy_s(*buf, len, temp, len) != 0) {
        free(temp);
        return ATTEST_ERR;
    }
    free(temp);
    return ATTEST_OK;
}

int32_t AttestBinaryToSerial(const uint8_t* input, int32_t inputLen,
    uint8_t** outputBuff, int32_t* outputLen)
{
    if (input == NULL || outputBuff == NULL || outputLen == NULL) {
        return ATTEST_ERR;
    }
    int32_t outputSize = (inputLen * ATTEST_ASCII_TO_STRING_SIZE) + sizeof(ATTEST_ZERO_CHAR) + 1;
    char* tempBuf = (char *)malloc(outputSize);
    if (tempBuf == NULL) {
        return ATTEST_ERR;
    }
    memset_s(tempBuf, outputSize, 0, outputSize);

    int32_t ret = ATTEST_OK;
    int32_t offsetLength = 0;
    char* tempBufPtr = tempBuf;
    for (int32_t i = 0; i < inputLen; i++) {
        if (sprintf_s(tempBufPtr, outputSize - offsetLength, "%u", input[i]) <= 0) {
            ret = ATTEST_ERR;
            break;
        }
        for (; *tempBufPtr != '\0'; tempBufPtr++) {
            offsetLength++;
        }
        *tempBufPtr = ',';
        offsetLength++;
        tempBufPtr++;
    }
    if (ret != ATTEST_OK) {
        free(tempBuf);
        tempBuf = NULL;
        return ATTEST_ERR;
    }
    *tempBufPtr = ATTEST_ZERO_CHAR;

    *outputBuff = (uint8_t*)tempBuf;
    *outputLen = outputSize;
    return ATTEST_OK;
}
