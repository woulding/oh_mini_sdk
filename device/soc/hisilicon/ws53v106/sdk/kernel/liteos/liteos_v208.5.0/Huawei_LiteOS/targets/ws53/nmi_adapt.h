/**
 * Copyright (c) @CompanyNameMagicTag 2023-2023. All rights reserved. \n
 *
 * Description: LiteOS NMI adapt header. \n
 * Author: @CompanyNameTag \n
 * History: \n
 * 2023-11-09, Create file. \n
 */

#ifndef NMI_ADAPT_H
#define NMI_ADAPT_H

#include "arch/exception.h"

#ifdef __cplusplus
#if __cplusplus
extern "C" {
#endif /* __cplusplus */
#endif /* __cplusplus */

extern VOID OsClearNMI(VOID);
extern VOID OsExcInfoDisplay(UINT32 excType, const ExcContext *excBufAddr);
extern VOID irq_wdt_handler(VOID);

#ifdef __cplusplus
#if __cplusplus
}
#endif /* __cplusplus */
#endif /* __cplusplus */

#endif