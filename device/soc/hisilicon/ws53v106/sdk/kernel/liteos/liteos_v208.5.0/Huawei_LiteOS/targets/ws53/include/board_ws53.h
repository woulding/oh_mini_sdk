/**
 * Copyright (c) @CompanyNameMagicTag 2024-2024. All rights reserved. \n
 *
 * Description: board ws63 header. \n
 * Author: @CompanyNameTag \n
 * History: \n
 * 2024-1-23, Create file. \n
 */

#ifndef BOARD_WS53_H
#define BOARD_WS53_H

extern unsigned int _g_sramtext_begin;
extern unsigned int _g_sramtext_end;
extern unsigned int _g_flashtext_begin;
extern unsigned int _g_flashtext_end;

extern LITE_OS_SEC_TEXT VOID OsExcInfoDisplayContext(const ExcInfo *exc);
VOID OsExcInfoDisplayContextExt(const ExcInfo *exc);
LITE_OS_SEC_TEXT VOID ArchBackTraceCustom(UINTPTR *array, UINTPTR arry_len);
#endif