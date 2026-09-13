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
#ifdef __LITEOS_M__
#include "securec.h"
#include <stdio.h>
#include <stdlib.h>
#include <limits.h>
#include "utils_file.h"
#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>
#include "attest_utils_log.h"
#include "attest_utils.h"
#include "attest_utils_file.h"

static const uint32_t MAX_FILE_BYTES_LIMIT = 5120;

#if defined(CHIP_VER_Hi3861)
#include <hi_tsensor.h>

#define WRITE_FLASH_MAX_TEMPERATURE 80

// 轻量设备温度监控
bool IsOverTemperatureLimit(void)
{
    hi_s16 temperature = 0;
    int32_t ret = hi_tsensor_read_temperature(&temperature);
    if (ret != HI_ERR_SUCCESS) {
        ret = hi_tsensor_read_temperature(&temperature);
        if (ret != HI_ERR_SUCCESS) {
            ATTEST_LOG_ERROR("[IsOverTemperatureLimit]: Get temperature fail, ret = %d", ret);
            return true;
        }
    }
    ATTEST_LOG_DEBUG("[IsOverTemperatureLimit]: device's temperature = %d", temperature);
    return (temperature >= WRITE_FLASH_MAX_TEMPERATURE);
}

#else

bool IsOverTemperatureLimit(void)
{
    return false;
}

#endif // defined(CHIP_VER_Hi3861)

int32_t GetFileSize(const char* path, const char* fileName, uint32_t* result)
{
    if (path == NULL || fileName == NULL || result == NULL) {
        ATTEST_LOG_ERROR("[GetFileSize] Invalid parameter");
        return ATTEST_ERR;
    }
    int32_t ret = UtilsFileStat(fileName, result);
    if (ret < 0) {
        return ATTEST_ERR;
    }
    return ATTEST_OK;
}

int32_t WriteFile(const char* path, const char* fileName, const char* data, uint32_t dataLen)
{
    if (path == NULL || fileName == NULL || data == NULL || dataLen == 0) {
        ATTEST_LOG_ERROR("[WriteFile] Invalid parameter");
        return ATTEST_ERR;
    }

    if (dataLen > MAX_FILE_BYTES_LIMIT) {
        return ATTEST_ERR;
    }
    if (IsOverTemperatureLimit()) {
        return ATTEST_ERR;
    }

    int32_t fd = UtilsFileOpen(fileName, O_CREAT_FS | O_TRUNC_FS | O_RDWR_FS, 0);
    if (fd < 0) {
        ATTEST_LOG_ERROR("[WriteFile] : Open file failed");
        return ATTEST_ERR;
    }

    int ret = 0;
    if (UtilsFileWrite(fd, data, dataLen) != (int32_t)dataLen) {
        ATTEST_LOG_ERROR("[WriteFile] : Write data failed");
        ret = ATTEST_ERR;
    }
    (void)UtilsFileClose(fd);
    if (ret < 0) {
        return ATTEST_ERR;
    }
    return ATTEST_OK;
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

    int32_t fd = UtilsFileOpen(fileName, O_EXCL_FS | O_RDWR_FS, 0);
    if (fd < 0) {
        ATTEST_LOG_ERROR("[ReadFile] : Open file failed");
        return ATTEST_ERR;
    }

    int32_t ret = 0;
    ret = UtilsFileRead(fd, buffer, bufferLen);
    (void)UtilsFileClose(fd);
    if (ret < 0) {
        return ATTEST_ERR;
    }
    return ATTEST_OK;
}

int32_t CreateFile(const char* path, const char* fileName)
{
    if (path == NULL || fileName == NULL) {
        return ATTEST_ERR;
    }

    int32_t fd = UtilsFileOpen(fileName, O_CREAT_FS, 0);
    if (fd < 0) {
        return ATTEST_ERR;
    }
    (void)UtilsFileClose(fd);
    return ATTEST_OK;
}

bool IsFileExist(const char* path, const char* fileName)
{
    if (path == NULL || fileName == NULL) {
        return false;
    }

    int32_t fd = UtilsFileOpen(fileName, O_RDONLY_FS, 0);
    if (fd < 0) {
        return false;
    }
    (void)UtilsFileClose(fd);
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

    int32_t ret = UtilsFileDelete(fileName);
    if (ret != 0) {
        return false;
    }
    return true;
}
#endif // __LITEOS_M__
