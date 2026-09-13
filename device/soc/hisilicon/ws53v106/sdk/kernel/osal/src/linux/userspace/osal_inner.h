/*
 * Copyright (c) @CompanyNameMagicTag. 2021-2022. All rights reserved.
 * Description: OS Abstract Layer.
 */

#ifndef OSAL_INNER_H
#define OSAL_INNER_H

#ifndef FALSE
#define FALSE 0
#endif

#ifndef TRUE
#define TRUE 1
#endif

#ifndef NULL
#define NULL ((void *)0)
#endif

#define va_num_args_impl(_1, _2, N, ...) N
#define va_num_args(...) va_num_args_impl(__VA_ARGS__, 2, 1)
#define _all_unused_impl_(nargs) _osal_unused##nargs
#define all_unused_impl(nargs) _all_unused_impl_(nargs)

#define _osal_unused1(var) (void)(var)
#define _osal_unused2(y, z) _osal_unused1(y), _osal_unused1(z)
#define _osal_unused3(x, y, z) _osal_unused1(x), _osal_unused2(y, z)
#define _osal_unused4(a, b, x, y) _osal_unused2(a, b), _osal_unused2(x, y)
#define osal_unused(...) all_unused_impl(va_num_args(__VA_ARGS__))(__VA_ARGS__)


#define osal_log(fmt, ...) osal_printk("[%s:%d]:" fmt, __FUNCTION__, __LINE__, ##__VA_ARGS__)

void osal_user_device_init(void);
void osal_user_device_exit(void);
int osal_user_proc_init(void);
void osal_user_proc_exit(void);

#endif