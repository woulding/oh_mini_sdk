/*
 * Copyright (c) 2026 Huawei Device Co., Ltd.
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

#include "hiview_output_log.h"
#include "hiview_config.h"
#include "hiview_def.h"
#include "hiview_log.h"
#include "hiview_log_limit.h"
#include "hiview_util.h"
#include "ohos_types.h"
#include "securec.h"

#include <time.h>

#define SINGLE_FMT_MAX_LEN      8
#define FMT_CONVERT_TRMINATOR   2
#define INI_CONVERT_DIVID_NUM 10


static char g_logLevelInfo[HILOG_LV_MAX] = {
    'N',
    'D',
    'I',
    'W',
    'E',
    'F'
};

static int32 LogCommonFmt(char *outStr, int32 outStrlen, const HiLogCommon *commonContentPtr);
static int32 LogValuesFmt(char *desStrPtr, int32 desLen, const HiLogContent *logContentPtr);
static int32 LogDebugValuesFmt(char *desStrPtr, int32 desLen, const HiLogContent *logContentPtr);
static int32 LogValuesFmtHash(char *desStrPtr, int32 desLen, const HiLogContent *logContentPtr);

static HilogProc g_hilogOutputProc = NULL;

void InitCoreLogOutput(void)
{
}

void InitLogOutput(void)
{
}

void ClearLogOutput(void)
{
}

void OutputLog(const uint8 *data, uint32 len)
{
    if (data == NULL) {
        return;
    }
    HiLogContent *hiLogContent = (HiLogContent *)data;
    if (g_hilogOutputProc != NULL && g_hilogOutputProc(hiLogContent, len) == TRUE) {
        return;
    }

#ifdef DISABLE_HILOG_LITE_PRINT_LIMIT
    boolean isDisablePrintLimited = TRUE;
#else
    boolean isDisablePrintLimited = FALSE;
#endif
    boolean isLogLimited = LogIsLimited(hiLogContent->commonContent.module);
    if (!isDisablePrintLimited && isLogLimited) {
        return;
    }
    
    char* tempOutStr = HIVIEW_MemAlloc(MEM_POOL_HIVIEW_ID, LOG_FMT_MAX_LEN);
    memset_s(tempOutStr, LOG_FMT_MAX_LEN, 0, LOG_FMT_MAX_LEN);
    if (tempOutStr == NULL) {
        HIVIEW_UartPrint("OutputLog HIVIEW_MemAlloc failed");
        return;
    }
    if (LogContentFmt(tempOutStr, LOG_FMT_MAX_LEN, data) > 0) {
        HIVIEW_UartPrint(tempOutStr);
    }
    HIVIEW_MemFree(MEM_POOL_HIVIEW_ID, tempOutStr);
}

uint32 GetLogFileSize(void)
{
    return 0;
}

uint32 ReadLogFile(uint8 *buf, uint32 len)
{
    (void)buf;
    (void)len;
    return 0;
}
 
int32 LogContentFmt(char *outStr, int32 outStrLen, const uint8 *pLogContent)
{
    int32 len;
    HiLogContent *logContentPtr = (HiLogContent *)pLogContent;
    len = LogCommonFmt(outStr, outStrLen, &(logContentPtr->commonContent));
    boolean isHash = CHECK_HASH_FLAG(logContentPtr->commonContent.level);
    if (len >= 0) {
        if (isHash) {
            len += LogValuesFmtHash(outStr + len, outStrLen - len, logContentPtr);
        } else if (GETOPTION(g_hiviewConfig.outputOption) == OUTPUT_OPTION_DEBUG) {
            len += LogDebugValuesFmt(outStr + len, outStrLen - len, logContentPtr);
        } else {
            len += LogValuesFmt(outStr + len, outStrLen - len, logContentPtr);
        }
    }

    if (len < 0) {
        return len;
    }
    
    if (len >= outStrLen - 1) {
        outStr[outStrLen - TAIL_LINE_BREAK] = '\n';
        outStr[outStrLen - 1] = '\0';
    } else {
        outStr[len++] = '\n';
        outStr[len++] = '\0';
    }

    return len;
}

static int32 LogCommonFmt(char *outStr, int32 outStrLen, const HiLogCommon *commonContentPtr)
{
    int32 ret;
    time_t time;
    uint8_t level;
    struct tm nowTime = {0};

    time = commonContentPtr->time;
    localtime_r(&time, &nowTime);
    int month = nowTime.tm_mon + 1;
    int day = nowTime.tm_mday;
    int hour = nowTime.tm_hour;
    int min = nowTime.tm_min;
    int sec = nowTime.tm_sec;
    level = CLEAR_HASH_FLAG(commonContentPtr->level);
    if (level >= HILOG_LV_MAX) {
        level = 0;
    }
    ret = snprintf_s(outStr, outStrLen, outStrLen - 1, "%02d-%02d %02d:%02d:%02d.%03d 0 %d %c %d/%s: ",
        month, day, hour, min, sec, commonContentPtr->milli, commonContentPtr->task, g_logLevelInfo[level],
        commonContentPtr->module, HiLogGetModuleName(commonContentPtr->module));

    return ret;
}

static int32 LogValuesFmt(char *desStrPtr, int32 desLen, const HiLogContent *logContentPtr)
{
    int32 i;
    int32 outLen = 0;
    int32 len;
    char fmtStr[SINGLE_FMT_MAX_LEN];
    uint32 valNum = logContentPtr->commonContent.valueNumber;
    const char *fmt = logContentPtr->commonContent.fmt;
    uint32 valueIndex = 0;
    for (i = 0; fmt[i] != 0 && outLen < desLen;) {
        if (fmt[i] != '%') {
            desStrPtr[outLen++] = fmt[i++];
            continue;
        }
        if (fmt[i + 1] == '%') {
            desStrPtr[outLen++] = fmt[i++];
            desStrPtr[outLen++] = fmt[i++];
            continue;
        }
        fmtStr[0] = fmt[i++];
        uint32 t = 1;
        while (fmt[i] != 0 && t < sizeof(fmtStr) - 1) {
            if ((fmt[i] == 's' || fmt[i] == 'S') &&
                (fmt[i - 1] == '%' || (fmt[i - 1] >= '0' && fmt[i - 1] <= '9'))) {
                fmtStr[1] = 'p';
                fmtStr[FMT_CONVERT_TRMINATOR] = 0;
                i++;
                break;
            }
            if ((fmt[i] >= 'a' && fmt[i] <= 'z') || (fmt[i] >= 'A' && fmt[i] <= 'Z')) {
                fmtStr[t++] = fmt[i++];
                fmtStr[t] = 0;
                break;
            }
            fmtStr[t++] = fmt[i++];
        }
        if (valueIndex < valNum) {
            len = snprintf_s(&desStrPtr[outLen], desLen - outLen, desLen - outLen - 1,
                fmtStr, logContentPtr->values[valueIndex]);
            if (len < 0) {
                break;
            }
            outLen += len;
            valueIndex++;
        }
    }

    return outLen;
}

static void RemovePrivacyFmt(const char* fmtStr, size_t fmtLen, char* arr, size_t arrLen)
{
    if (arrLen == 0) {
        return;
    }
    static const char *publicStr = "{public}";
    static const char *privateStr = "{private}";
    static const int publicLen = 8;
    static const int privateLen = 9;
    size_t writePos = 0;
    size_t pos = 0;
    for (; pos < fmtLen && writePos < arrLen - 1; ++pos) {
        arr[writePos++] = fmtStr[pos];
        if (fmtStr[pos] != '%') {
            continue;
        }
        if (pos + 1 + publicLen < fmtLen && strncmp(fmtStr + pos + 1, publicStr, publicLen) == 0) {
            pos += publicLen;
        } else if (pos + 1 + privateLen < fmtLen && strncmp(fmtStr + pos + 1, privateStr, privateLen) == 0) {
            pos += privateLen;
        }
    }
    while (pos < fmtLen && writePos < arrLen - 1) {
        arr[writePos++] = fmtStr[pos];
    }
    arr[writePos] = 0;
    return;
}

static int32 LogDebugValuesFmt(char *desStrPtr, int32 desLen, const HiLogContent *logContentPtr)
{
    int32 ret = 0;
    size_t fmtLen = strlen(logContentPtr->commonContent.fmt);
    char *fmt = (char *)malloc((fmtLen + 1) * sizeof(char));
    if (fmt == NULL) {
        return -1;
    }
    memset_s(fmt, fmtLen + 1, 0, fmtLen + 1);
    RemovePrivacyFmt(logContentPtr->commonContent.fmt, fmtLen, fmt, fmtLen);
    switch (logContentPtr->commonContent.valueNumber) {
        case LOG_MULTI_PARA_0:
            ret = strncpy_s(desStrPtr, desLen, fmt, desLen - 1);
            ret = (ret != EOK) ? -1 : strlen(desStrPtr);
            break;
        case LOG_MULTI_PARA_1:
            ret = snprintf_s(desStrPtr, desLen, desLen - 1, fmt,
                logContentPtr->values[0]);
            break;
        case LOG_MULTI_PARA_2:
            ret = snprintf_s(desStrPtr, desLen, desLen - 1, fmt,
                logContentPtr->values[0], logContentPtr->values[1]);
            break;
        case LOG_MULTI_PARA_3:
            ret = snprintf_s(desStrPtr, desLen, desLen - 1, fmt,
                logContentPtr->values[0], logContentPtr->values[1], logContentPtr->values[LOG_MULTI_PARA_2]);
            break;
        case LOG_MULTI_PARA_4:
            ret = snprintf_s(desStrPtr, desLen, desLen - 1, fmt,
                logContentPtr->values[0], logContentPtr->values[1], logContentPtr->values[LOG_MULTI_PARA_2],
                logContentPtr->values[LOG_MULTI_PARA_3]);
            break;
        case LOG_MULTI_PARA_5:
            ret = snprintf_s(desStrPtr, desLen, desLen - 1, fmt,
                logContentPtr->values[0], logContentPtr->values[1], logContentPtr->values[LOG_MULTI_PARA_2],
                logContentPtr->values[LOG_MULTI_PARA_3], logContentPtr->values[LOG_MULTI_PARA_4]);
            break;
        case LOG_MULTI_PARA_MAX:
            ret = snprintf_s(desStrPtr, desLen, desLen - 1, fmt,
                logContentPtr->values[0], logContentPtr->values[1], logContentPtr->values[LOG_MULTI_PARA_2],
                logContentPtr->values[LOG_MULTI_PARA_3], logContentPtr->values[LOG_MULTI_PARA_4],
                logContentPtr->values[LOG_MULTI_PARA_5]);
            break;
        default:
            break;
    }
    free(fmt);
    return (ret < 0) ? (desLen - 1) : ret;
}

static int32 IntAppendStr(char* str, int32 num, char end)
{
    int32 digits = 0;
    if (num == 0) {
        str[0] = '0';
        digits++;
        str[1] = end;
        return digits + 1;
    }
    int32 temp = num > 0 ? num : -num;
    while (temp > 0) {
        temp /= INI_CONVERT_DIVID_NUM;
        digits++;
    }
    if (num < 0) {
        str[0] = '-';
        temp = -num;
        str++;
    } else {
        temp = num;
    }
    for (int32 i = digits - 1; i >= 0; i--) {
        str[i] = temp % INI_CONVERT_DIVID_NUM + '0';
        temp /= INI_CONVERT_DIVID_NUM;
    }
    str[digits] = end;
    if (num < 0) {
        digits ++;
    }
    return digits + 1;
}

static int UIntAppendStr(char* str, uint32 num, char end)
{
    int32 digits = 0;
    if (num == 0) {
        str[0] = '0';
        digits++;
        str[1] = end;
        return digits + 1;
    }
    uint32 temp = num;
    while (temp > 0) {
        temp /= INI_CONVERT_DIVID_NUM;
        digits++;
    }
    temp = num;
    for (int32 i = digits - 1; i >= 0; i--) {
        str[i] = temp % INI_CONVERT_DIVID_NUM + '0';
        temp /= INI_CONVERT_DIVID_NUM;
    }
    str[digits] = end;
    return digits + 1;
}

static int32 LogValuesFmtHash(char *desStrPtr, int32 desLen, const HiLogContent *logContentPtr)
{
    int32 outLen = 0;
    uint32 paraNum = logContentPtr->commonContent.valueNumber;
    int32 ret = strncpy_s(&desStrPtr[outLen], desLen - outLen, "hash:", strlen("hash:"));
    if (ret != 0) {
        return -ret;
    }
    outLen += strlen("hash:");
    int32 len = UIntAppendStr(&desStrPtr[outLen], (uint32)logContentPtr->commonContent.fmt, ' ');
    outLen += len;
    ret = strncpy_s(&desStrPtr[outLen], desLen - outLen, "para:", strlen("para:"));
    if (ret != 0) {
        return -ret;
    }
    outLen += strlen("para:");
    for (uint32 i = 0; i < paraNum && i < LOG_MULTI_PARA_MAX; i++) {
        len = IntAppendStr(&desStrPtr[outLen], (int32)logContentPtr->values[i], ' ');
        outLen += len;
    }
    return outLen;
}

void FlushLog(boolean syncFlag)
{
    (void)syncFlag;
}

void HiviewRegisterHilogProc(HilogProc func)
{
    g_hilogOutputProc = func;
}

void HiviewUnRegisterHilogProc(HilogProc func)
{
    (void)func;
    if (g_hilogOutputProc != NULL) {
        g_hilogOutputProc = NULL;
    }
}

uint32 HiviewGetConfigOption(void)
{
    return 0;
}

void HiviewRegisterHiLogFileWatcher(FileProc func, const char *path)
{
    (void)func;
    (void)path;
}

void HiviewUnRegisterHiLogFileWatcher(FileProc func)
{
    (void)func;
}

int HiLogFileProcImp(const char* dest, uint8 mode)
{
    (void)dest;
    (void)mode;
    return 0;
}

void HiLogOutputFileLockImp(void)
{
}

void HiLogOutputFileUnLockImp(void)
{
}
