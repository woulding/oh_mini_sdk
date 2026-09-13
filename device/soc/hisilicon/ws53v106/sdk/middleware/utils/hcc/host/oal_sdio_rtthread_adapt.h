/*
 * Copyright (c) HiSilicon (Shanghai) Technologies Co., Ltd. 2022-2023. All rights reserved.
 * Description: host sdio driver os adapt.
 * Author: Huanghe
 * Create: 2022-12-20
 */

#ifndef __OAL_SDIO_RTTHREAD_ADAPT_H__
#define __OAL_SDIO_RTTHREAD_ADAPT_H__

#ifdef CONFIG_HCC_SUPPORT_SDIO
#include "rtthread.h"
#include "drivers/sdio.h"
#include "drivers/mmcsd_core.h"

#ifdef __cplusplus
#if __cplusplus
extern "C" {
#endif
#endif
#ifndef unref_param
#define unref_param(P)  ((P) = (P))
#endif
#define SDIO_ANY_ID (~0)
#define SDIO_DEVICE(vend, dev) \
    .func_code = SDIO_ANY_ID, \
             .manufacturer = (vend), .product = (dev)

typedef struct rt_sdio_function oal_sdio_func;
typedef struct rt_sdio_device_id oal_sdio_device_id;
/*
 * SDIO function device driver
 */
typedef struct rt_sdio_driver oal_sdio_driver;
typedef td_void (*oal_sdio_isr_func)(oal_sdio_func *func);

static inline td_s32 oal_sdio_enable_func(oal_sdio_func *func)
{
    return sdio_enable_func(func);
}

static inline td_s32 oal_sdio_disable_func(oal_sdio_func *func)
{
    return sdio_disable_func(func);
}

static inline td_s32 oal_sdio_set_block_size(oal_sdio_func *func, td_u32 blksz)
{
    return sdio_set_block_size(func, blksz);
}

static inline struct oal_sdio *oal_sdio_get_drvdata(oal_sdio_func *func)
{
    return (struct oal_sdio *)sdio_get_drvdata(func);
}

static inline td_void oal_sdio_set_drvdata(oal_sdio_func *func, struct oal_sdio *priv)
{
    sdio_set_drvdata(func, (void *)priv);
}

static inline td_void oal_sdio_set_en_timeout(oal_sdio_func *func, td_u32 timeout)
{
    func->enable_timeout_val = timeout;
}

static inline td_u32 oal_sdio_func_num(oal_sdio_func *func)
{
    return func->num;
}

static inline td_u32 oal_sdio_func_host_max_blk_size(oal_sdio_func *func)
{
    return func->card->host->max_blk_size;
}

static inline td_u32 oal_sdio_func_host_max_blk_num(oal_sdio_func *func)
{
    return func->card->host->max_blk_count;
}

static inline td_u32 oal_sdio_func_host_max_req_size(oal_sdio_func *func)
{
    unref_param(func);
    return 1;
}

static inline td_void oal_sdio_claim_host(oal_sdio_func *func)
{
    mmcsd_host_lock(func->card->host);
}

static inline td_void oal_sdio_release_host(oal_sdio_func *func)
{
    mmcsd_host_unlock(func->card->host);
}

/**
 *  oal_sdio_adapt_writesb - write to a FIFO of a SDIO function
 *  @func: SDIO function to access
 *  @addr: address of (single byte) FIFO
 *  @src: buffer that contains the data to write
 *  @count: number of bytes to write
 *  Writes to the specified FIFO of a given SDIO function. Return
 *  value indicates if the transfer succeeded or not.
 */
static inline td_s32 oal_sdio_adapt_writesb(oal_sdio_func *func, td_u32 addr, td_void *src, td_u32 count)
{
    return sdio_io_write_multi_fifo_b(func, addr, src, count);
}

/**
 *  oal_sdio_adapt_readsb - read from a FIFO on a SDIO function
 *  @func: SDIO function to access
 *  @dst: buffer to store the data
 *  @addr: address of (single byte) FIFO
 *  @count: number of bytes to read
 *  Reads from the specified FIFO of a given SDIO function. Return
 *  value indicates if the transfer succeeded or not.
 */
static inline td_s32 oal_sdio_adapt_readsb(oal_sdio_func *func, td_void *dst, td_u32 addr, td_s32 count)
{
    return sdio_io_read_multi_fifo_b(func, addr, dst, count);
}

/**
 *  oal_sdio_readb - read a single byte from a SDIO function
 *  @func: SDIO function to access
 *  @addr: address to read
 *  @err_ret: optional status value from transfer
 *
 *  Reads a single byte from the address space of a given SDIO
 *  function. If there is a problem reading the address, 0xff
 *  is returned and @err_ret will contain the error code.
 */
static inline td_u8 oal_sdio_readb(oal_sdio_func *func, td_u32 addr, td_s32 *err_ret)
{
    return sdio_io_readb(func, addr, (rt_int32_t *)err_ret);
}

/**
 *  oal_sdio_writeb - write a single byte to a SDIO function
 *  @func: SDIO function to access
 *  @b: byte to write
 *  @addr: address to write to
 *  @err_ret: optional status value from transfer
 *
 *  Writes a single byte to the address space of a given SDIO
 *  function. @err_ret will contain the status of the actual
 *  transfer.
 */
static inline void oal_sdio_writeb(oal_sdio_func *func, td_u8 b, td_u32 addr, td_s32 *err_ret)
{
    unref_param(err_ret);
    sdio_io_writeb(func, addr, b);
}

/**
 *  oal_sdio_writel - write a 32 bit integer to a SDIO function
 *  @func: SDIO function to access
 *  @b: integer to write
 *  @addr: address to write to
 *  @err_ret: optional status value from transfer
 *
 *  Writes a 32 bit integer to the address space of a given SDIO
 *  function. @err_ret will contain the status of the actual
 *  transfer.
 */
static inline td_void oal_sdio_writel(oal_sdio_func *func, td_u32 b, td_u32 addr, td_s32 *err_ret)
{
    *err_ret = sdio_io_writel(func, b, addr);
}

/**
 *  oal_sdio_adapt_memcpy_fromio - read a chunk of memory from a SDIO function
 *  @func: SDIO function to access
 *  @dst: buffer to store the data
 *  @addr: address to begin reading from
 *  @count: number of bytes to read
 *  Reads from the address space of a given SDIO function. Return
 *  value indicates if the transfer succeeded or not.
 */
static inline td_s32 oal_sdio_adapt_memcpy_fromio(oal_sdio_func *func, td_void *dst,
    td_u32 addr, td_s32 count)
{
    return sdio_io_read_multi_incr_b(func, addr, dst, count);
}

static inline td_u8 oal_sdio_func0_read_byte(oal_sdio_func *func, td_u32 addr, td_s32 *err_ret)
{
    rt_int32_t ret;
    rt_uint8_t val;
    // fn = 0
    ret = sdio_io_rw_direct(func->card, 0, 0, addr, &val, 0);
    if (ret && err_ret != NULL) {
        *err_ret = ret;
        return 0xFF;
    }
    return val;
}

static inline td_void oal_sdio_func0_write_byte(oal_sdio_func *func, td_u8 byte, td_u32 addr, td_s32 *err_ret)
{
    rt_int32_t ret;
    // fn = 0
    ret = sdio_io_rw_direct(func->card, 1, 0, addr, &byte, 0);
    if (ret && err_ret != NULL) {
        *err_ret = ret;
    }
}

static inline td_void oal_sdio_release_irq(oal_sdio_func *func)
{
    (td_void)sdio_detach_irq(func);
}

static inline td_s32 oal_sdio_request_irq(oal_sdio_func *func, oal_sdio_isr_func sdio_isr)
{
    return (td_s32)sdio_attach_irq(func, sdio_isr);
}

static inline td_s32 oal_sdio_register_driver(oal_sdio_driver *driver)
{
    return sdio_register_driver(driver);
}

static inline td_void oal_sdio_unregister_driver(oal_sdio_driver *driver)
{
    sdio_unregister_driver(driver);
}

#ifdef __cplusplus
#if __cplusplus
}
#endif
#endif
#endif
#endif /* __OAL_SDIO_RTTHREAD_ADAPT_H__ */
