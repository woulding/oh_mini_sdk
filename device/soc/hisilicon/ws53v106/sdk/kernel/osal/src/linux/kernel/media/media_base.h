/*
* Copyright (c) @CompanyNameMagicTag. 2012-2022. All rights reserved.
* Description:
* Author:
* Create: 2012-12-22
* Notes:
* History: 2019-03-29 CSEC
*/
#ifndef _HIMEDIA_BASE_H_
#define _HIMEDIA_BASE_H_

#include "osal_media.h"

// bus
int media_bus_init(void);
void media_bus_exit(void);

// device
int media_device_register(pm_basedev *pdev);
void media_device_unregister(pm_basedev *pdev);
int media_device_add(pm_basedev *pdev);
void media_device_del(pm_basedev *pdev);
void media_device_put(pm_basedev *pdev);
pm_basedev *media_device_alloc(const char *name, int id);

// driver
int media_driver_register(pm_basedrv *drv);
void media_driver_unregister(pm_basedrv *drv);
void media_driver_release(pm_basedrv *drv);
pm_basedrv *media_driver_alloc(const char *name, struct module *owner, const pm_baseops *ops);

#endif
