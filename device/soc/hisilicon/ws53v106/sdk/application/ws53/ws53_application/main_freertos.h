/**
 * Copyright (c) @CompanyNameMagicTag 2022-2023. All rights reserved. \n
 *
 * Description: Application core os initialize interface header for standard \n
 * Author: @CompanyNameTag \n
 * History: \n
 * 2023-08-23, Create file. \n
 */
#ifndef MAIN_FREERTOS_H
#define MAIN_FREERTOS_H

#ifdef __cplusplus
#if __cplusplus
extern "C" {
#endif
#endif

extern char g_intheap_begin;
extern char g_intheap_size;
extern void *g_heap;
extern void *g_l2ramHeap;

extern UBaseType_t volatile tickcnt;

#define DELAY_TIME_MS 1000

#ifdef __cplusplus
#if __cplusplus
}
#endif
#endif

#endif