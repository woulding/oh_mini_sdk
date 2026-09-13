/*
 * Copyright (c) @CompanyNameMagicTag. 2021-2022. All rights reserved.
 * Description: osal atomic source file.
 */

#include <stdlib.h>
#include <stdio.h>
#ifdef _LIBCPP_HAS_MUSL_LIBC
#include <stdint.h>
#endif
#include "soc_osal.h"
#include "osal_inner.h"

#define ATOMIC_INLINE inline __attribute__((always_inline))

typedef struct {
    volatile int counter;
} atomic_t;

static ATOMIC_INLINE void memory_barrier(void)
{
#ifdef USER_BIT_64
    __asm__ __volatile__ ("dmb ish" : : : "memory");
#else
    __asm__ __volatile__ ("dmb" : : : "memory");
#endif
}

static ATOMIC_INLINE int atomic_add(int increment, volatile int *ptr)
{
    int prev, tmp, status;
    memory_barrier();

    do {
#ifdef USER_BIT_64
        prev = *ptr;
        status = __sync_val_compare_and_swap(ptr, prev, prev + increment) != prev;
        tmp = *ptr;
#else
        __asm__ __volatile__ ("ldrex %0, [%4]\n"
                              "add %1, %0, %5\n"
                              "strex %2, %1, [%4]"
                              : "=&r" (prev), "=&r" (tmp),
                               "=&r" (status), "+m" (*ptr)
                              : "r" (ptr), "Ir" (increment)
                              : "cc");
#endif
    } while (__builtin_expect(status != 0, 0));

    return tmp;
}

static ATOMIC_INLINE int atomic_acquire_load(volatile const int *ptr)
{
    int value = *ptr;
    memory_barrier();
    return value;
}

static ATOMIC_INLINE void atomic_acquire_store(int value, volatile int *ptr)
{
    *ptr = value;
    memory_barrier();
}

int osal_atomic_read(osal_atomic *atomic)
{
    if (atomic == NULL) {
        osal_log("parameter invalid!\n");
        return OSAL_FAILURE;
    }

    return atomic_acquire_load(&atomic->counter);
}

void osal_atomic_set(osal_atomic *atomic, int i)
{
    if (atomic == NULL) {
        osal_log("parameter invalid!\n");
        return;
    }
    atomic_acquire_store(i, &atomic->counter);
}

int osal_atomic_inc_return(osal_atomic *atomic)
{
    if (atomic == NULL) {
        osal_log("parameter invalid!\n");
        return OSAL_FAILURE;
    }
    return atomic_add(1, &atomic->counter);
}

int osal_atomic_dec_return(osal_atomic *atomic)
{
    if (atomic == NULL) {
        osal_log("parameter invalid!\n");
        return OSAL_FAILURE;
    }
    return atomic_add(-1, &atomic->counter);
}
