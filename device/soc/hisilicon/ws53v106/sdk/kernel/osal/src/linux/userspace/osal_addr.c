/*
 * Copyright (c) @CompanyNameMagicTag. 2012-2022. All rights reserved.
 */

#include <stdio.h>
#include <fcntl.h>
#include <stdlib.h>
#include <unistd.h>
#include <stdint.h>
#include <sys/ioctl.h>
#include <string.h>
#include <sys/mman.h>
#include "soc_osal.h"
#include "securec.h"
#include "osal_inner.h"

static int g_mem_device_fd = -1;
#define ADDR_MEM_DEV_OPEN if (g_mem_device_fd <= 0) \
{ \
    g_mem_device_fd = open("/dev/mem", O_RDWR | O_SYNC); \
    if (g_mem_device_fd < 0) \
    { \
        perror("Open dev/mem error"); \
        return NULL; \
    } \
} \

void *osal_ioremap(unsigned long phys_addr, unsigned long size)
{
    unsigned long diff;
    unsigned long page_phy;
    unsigned long page_size;
    unsigned char *p_page_addr = NULL;

    ADDR_MEM_DEV_OPEN;
    /**********************************************************
    PageSize will be 0 when u32size is 0 and u32Diff is 0,
    and then mmap will be error (error: Invalid argument)
    ***********************************************************/
    if (size == 0) {
        osal_printk("Func: %s u32Size can't be 0.\n", __FUNCTION__);
        return NULL;
    }

    /* The mmap address should align with page */
    page_phy = phys_addr & 0xfffffffffffff000ULL;
    diff    = phys_addr - page_phy;

    /* The mmap size shuld be mutliples of 1024 */
    page_size = ((size + diff - 1) & 0xfffff000UL) + 0x1000;

    p_page_addr = mmap((void *)0, page_size, PROT_READ | PROT_WRITE, MAP_SHARED, g_mem_device_fd, (off_t)page_phy);
    if (p_page_addr == MAP_FAILED) {
        perror("mmap error");
        return NULL;
    }
    return (void *)(p_page_addr + diff);
}

void *osal_ioremap_cached(unsigned long phys_addr, unsigned long size)
{
    return osal_ioremap(phys_addr, size);
}

void *osal_ioremap_nocache(unsigned long phys_addr, unsigned long size)
{
    return osal_ioremap(phys_addr, size);
}

void *osal_ioremap_wc(unsigned long phys_addr, unsigned long size)
{
    return osal_ioremap(phys_addr, size);
}

void osal_iounmap(void *addr, unsigned long size)
{
    unsigned long page_addr;
    unsigned long  page_size;
    unsigned long  diff;

    page_addr = (((unsigned long)(uintptr_t)addr) & 0xfffffffffffff000ULL);
    diff     = (unsigned long)(uintptr_t)addr - page_addr;
    page_size = ((size + diff - 1) & 0xfffff000UL) + 0x1000;

    munmap((void *)page_addr, page_size);
    return;
}

unsigned long osal_copy_from_user(void *to, const void *from, unsigned long n)
{
    errno_t ret = memcpy_s(to, n, from, n);
    return (ret == EOK) ? 0 : n;
}

unsigned long osal_copy_to_user(void *to, const void *from, unsigned long n)
{
    errno_t ret = memcpy_s(to, n, from, n);
    return (ret == EOK) ? 0 : n;
}

int osal_access_ok(int type, const void *addr, unsigned long size)
{
    if (addr != NULL) {
        return 1;
    }
    return 0;
}

void *osal_vmalloc(unsigned long size)
{
    return malloc(size);
}

void *osal_vzalloc(unsigned long size)
{
    void *addr = malloc(size);
    if (addr != NULL) {
        memset_s(addr, size, 0, size);
    }
    return addr;
}

void osal_vfree(void *addr)
{
    if (addr != NULL) {
        free(addr);
    }
    return;
}

void *osal_kmalloc(unsigned long size, unsigned int osal_gfp_flag)
{
    return malloc(size);
}

void *osal_kzalloc(unsigned long size, unsigned int osal_gfp_flag)
{
    void *addr = malloc(size);
    if (addr != NULL) {
        memset_s(addr, size, 0, size);
    }
    return addr;
}

void osal_kfree(void *addr)
{
    if (addr != NULL) {
        free(addr);
    }
    return;
}
