/*
 * Copyright (C) 2022 Huawei Device Co., Ltd.
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

#include <unistd.h>
#include <string.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <securec.h>
#include <limits.h>
#include "attest_utils_log.h"
#include "attest_utils.h"
#include "attest_utils_file.h"

char* GenFilePath(const char* dirPath, const char* fileName)
{
    if (dirPath == NULL || fileName == NULL) {
        return NULL;
    }

    uint32_t filePathLen = strlen(dirPath) + 1 + strlen(fileName) + 1;
    if (filePathLen > PATH_MAX) {
        return NULL;
    }
    char* filePath = (char *)ATTEST_MEM_MALLOC(filePathLen);
    if (filePath == NULL) {
        return NULL;
    }
    if (sprintf_s(filePath, filePathLen, "%s%s%s", dirPath, "/", fileName) < 0) {
        ATTEST_MEM_FREE(filePath);
        return NULL;
    }
    return filePath;
}

int32_t ReadFileBuffer(const char* path, const char* fileName, char** outStr)
{
    if (path == NULL || fileName == NULL || outStr == NULL) {
        return ATTEST_ERR;
    }
    
    uint32_t fileSize = 0;
    if (GetFileSize(path, fileName, &fileSize) != 0) {
        return ATTEST_ERR;
    }
    if (fileSize == 0 || fileSize > MAX_ATTEST_MALLOC_BUFF_SIZE) {
        return ATTEST_ERR;
    }
    uint32_t bufferSize = fileSize + 1;
    char* buffer = (char *)ATTEST_MEM_MALLOC(bufferSize);
    if (buffer == NULL) {
        return ATTEST_ERR;
    }
    
    int32_t ret = ReadFile(path, fileName, buffer, bufferSize);
    if (ret != ATTEST_OK) {
        ATTEST_MEM_FREE(buffer);
        return ATTEST_ERR;
    }
    *outStr = buffer;
    return ATTEST_OK;
}