/*
 * Copyright (c) @CompanyNameMagicTag 2022-2022. All rights reserved.
 * Description: dfx system init
 * This file should be changed only infrequently and with great care.
 */
#ifndef DFX_SYSTEM_INIT_H
#define DFX_SYSTEM_INIT_H

#include "errcode.h"

errcode_t dfx_system_init(void);
unsigned long dfx_get_osal_queue_id(void);
#endif