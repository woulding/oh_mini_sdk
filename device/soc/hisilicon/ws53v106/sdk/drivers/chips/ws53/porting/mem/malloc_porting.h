/**
 * Copyright (c) HiSilicon (Shanghai) Technologies Co., Ltd. 2023-2023. All rights reserved.
 * Description: malloc header.
 */

#ifndef __MALLOC_PORTING_H__
#define __MALLOC_PORTING_H__

extern unsigned int g_intheap_begin;
extern unsigned int g_intheap_size;
extern unsigned int __bt_text_begin__;
void malloc_port_init(void);

#endif
