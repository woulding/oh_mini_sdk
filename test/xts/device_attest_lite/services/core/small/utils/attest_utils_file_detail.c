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
#ifndef __LITEOS_M__

#include <unistd.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <limits.h>
#include <securec.h>
#include "attest_utils_log.h"
#include "attest_utils.h"
#include "attest_utils_file.h"

bool IsOverTemperatureLimit(void)
{
    return false;
}

int32_t GetFileSize(const char* path, const char* fileName, uint32_t* result)
{
    if (path == NULL || fileName == NULL || result == NULL) {
        ATTEST_LOG_ERROR("[GetFileSize] Invalid parameter");
        return ATTEST_ERR;
    }

    char* filePath = GenFilePath(path, fileName);
    if (filePath == NULL) {
        ATTEST_LOG_ERROR("[GetFileSize] Generate file path failed");
        return ATTEST_ERR;
    }

    char* formatPath = realpath(filePath, NULL);
    ATTEST_MEM_FREE(filePath);
    if (formatPath == NULL) {
        ATTEST_LOG_ERROR("[GetFileSize] Invalid path of %s/%s", path, fileName);
        return ATTEST_ERR;
    }

    FILE* fp = fopen(formatPath, "r");
    if (fp == NULL) {
        ATTEST_LOG_ERROR("[GetFileSize] open file %s failed", formatPath);
        free(formatPath);
        return ATTEST_ERR;
    }
    if (fseek(fp, 0, SEEK_END) < 0) {
        ATTEST_LOG_ERROR("[GetFileSize] seek file %s failed", formatPath);
        free(formatPath);
        (void)fclose(fp);
        return ATTEST_ERR;
    }
    *result = ftell(fp);
    free(formatPath);
    (void)fclose(fp);
    return ATTEST_OK;
}

int32_t WriteFile(const char* path, const char* fileName, const char* data, uint32_t dataLen)
{
    if (path == NULL || fileName == NULL || data == NULL || dataLen == 0) {
        ATTEST_LOG_ERROR("[WriteFile] Invalid parameter");
        return ATTEST_ERR;
    }
    char* filePath = GenFilePath(path, fileName);
    if (filePath == NULL) {
        ATTEST_LOG_ERROR("[WriteFile] Generate file path failed");
        return ATTEST_ERR;
    }

    char* formatPath = realpath(filePath, NULL);
    ATTEST_MEM_FREE(filePath);
    if (formatPath == NULL) {
        ATTEST_LOG_ERROR("[WriteFile] Invalid path of %s", path);
        return ATTEST_ERR;
    }

    FILE* fp = fopen(formatPath, "wb+");
    if (fp == NULL) {
        ATTEST_LOG_ERROR("[WriteFile] open file %s failed", formatPath);
        free(formatPath);
        return ATTEST_ERR;
    }
    int32_t ret = ATTEST_OK;
    do {
        if (chmod(formatPath, S_IRUSR | S_IWUSR) < 0) { // 文件权限改为600
            ATTEST_LOG_ERROR("[WriteFile] chmod file failed");
            ret = ATTEST_ERR;
            break;
        }
        if (fwrite(data, dataLen, 1, fp) != 1) {
            ATTEST_LOG_ERROR("[WriteFile] write file %s failed", formatPath);
            ret = ATTEST_ERR;
            break;
        }
        if (fflush(fp) != ATTEST_OK) {
            ret = ATTEST_ERR;
            break;
        }
        int fd = fileno(fp);
        if (fsync(fd) != ATTEST_OK) {
            ret = ATTEST_ERR;
            break;
        }
    } while (0);
    free(formatPath);
    (void)fclose(fp);
    return ret;
}

int32_t ReadFile(const char* path, const char* fileName, char* buffer, uint32_t bufferLen)
{
    if (path == NULL || fileName == NULL || buffer == NULL || bufferLen == 0) {
        ATTEST_LOG_ERROR("[ReadFile] Invalid parameter");
        return ATTEST_ERR;
    }

    uint32_t fileSize = 0;
    if (GetFileSize(path, fileName, &fileSize) != 0 || fileSize > bufferLen) {
        ATTEST_LOG_ERROR("[ReadFile] Invalid fileSize");
        return ATTEST_ERR;
    }

    char* filePath = GenFilePath(path, fileName);
    if (filePath == NULL) {
        ATTEST_LOG_ERROR("[ReadFile] Generate file path failed");
        return ATTEST_ERR;
    }

    char* formatPath = realpath(filePath, NULL);
    ATTEST_MEM_FREE(filePath);
    if (formatPath == NULL) {
        ATTEST_LOG_ERROR("[ReadFile] Invalid path of %s or file %s not exist", path, fileName);
        return ATTEST_ERR;
    }

    FILE* fp = fopen(formatPath, "rb");
    if (fp == NULL) {
        ATTEST_LOG_ERROR("[ReadFile] open file %s failed", formatPath);
        free(formatPath);
        return ATTEST_ERR;
    }
    if (fread(buffer, fileSize, 1, fp) != 1) {
        ATTEST_LOG_ERROR("[ReadFile] read file %s data from device failed", formatPath);
        free(formatPath);
        (void)fclose(fp);
        return ATTEST_ERR;
    }
    free(formatPath);
    (void)fclose(fp);
    return ATTEST_OK;
}

int32_t CreateFile(const char* path, const char* fileName)
{
    if (path == NULL || fileName == NULL) {
        return ATTEST_ERR;
    }

    char* formatPath = realpath(path, NULL);
    if (formatPath == NULL) {
        ATTEST_LOG_ERROR("[CreateFile] Invalid path of %s or file %s not exist", path, fileName);
        return ATTEST_ERR;
    }
    uint32_t realPathLen = strlen(formatPath) + 1 + strlen(fileName) + 1;
    if (realPathLen > PATH_MAX) {
        return ATTEST_ERR;
    }
    char* realPath = (char *)ATTEST_MEM_MALLOC(realPathLen);
    if (realPath == NULL) {
        free(formatPath);
        return ATTEST_ERR;
    }
    if (sprintf_s(realPath, realPathLen, "%s%s%s", formatPath, "/", fileName) < 0) {
        free(formatPath);
        ATTEST_MEM_FREE(realPath);
        return ATTEST_ERR;
    }
    free(formatPath);

    FILE* fp = fopen(realPath, "w");
    if (fp == NULL) {
        ATTEST_MEM_FREE(realPath);
        return ATTEST_ERR;
    }
    ATTEST_MEM_FREE(realPath);
    int32_t ret = ATTEST_OK;
    do {
        if (fflush(fp) != ATTEST_OK) {
            ret = ATTEST_ERR;
            break;
        }
        int fd = fileno(fp);
        if (fsync(fd) != ATTEST_OK) {
            ret = ATTEST_ERR;
            break;
        }
    } while (0);
    (void)fclose(fp);
    return ret;
}

bool IsFileExist(const char* path, const char* fileName)
{
    if (path == NULL || fileName == NULL) {
        return false;
    }
    char* filePath = GenFilePath(path, fileName);
    if (filePath == NULL) {
        ATTEST_LOG_ERROR("[IsFileExist] Generate file path failed");
        return false;
    }
    char* formatPath = realpath(filePath, NULL);
    ATTEST_MEM_FREE(filePath);
    if (formatPath == NULL) {
        ATTEST_LOG_ERROR("[IsFileExist] Invalid path of %s or file %s not exist", path, fileName);
        return false;
    }

    FILE* fp = fopen(formatPath, "r");
    if (fp == NULL) {
        free(formatPath);
        return false;
    }
    free(formatPath);
    (void)fclose(fp);
    return true;
}

bool DeleteFile(const char* path, const char* fileName)
{
    if (path == NULL || fileName == NULL) {
        return false;
    }
    if (strlen(path) == 0 || strlen(fileName) == 0) {
        return false;
    }
    char* filePath = GenFilePath(path, fileName);
    if (filePath == NULL) {
        return false;
    }
    int32_t ret = remove(filePath);
    ATTEST_MEM_FREE(filePath);
    if (ret != 0) {
        return false;
    }
    return true;
}
#endif
