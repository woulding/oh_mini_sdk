/*
 * @Copyright (c) CompanyNameMagicTag 2021-2023. All rights reserved.
 * Description: ftrace hash File.
 * Create: 2023-05-17
 */
#ifdef _PRE_WLAN_FEATURE_FTRACE
#include "ftrace.h"
#include "osal_types.h"
#include "oal_types_device_rom.h"
#include "oal_util.h"
static struct ftrace_list *g_fhash_blkts[FTRACE_HASH_SIZE];

static int NOTRACE ftrace_hash_key(unsigned long func_addr)
{
    // 根据不同的子系统应该要有变化
    func_addr *= 0x61C88647; // from kernel
    return (func_addr % FTRACE_HASH_SIZE);
}

void NOTRACE ftrace_foreach_list(fttrace_list_func call)
{
    int i;
    int count;
    struct ftrace_list *entry;
    for (i = 0; i < FTRACE_HASH_SIZE; i++) {
        entry = g_fhash_blkts[i];
        if (entry == OAL_PTR_NULL) {
            continue;
        }
        count = 0;
        while (entry != OAL_PTR_NULL) {
            count++;
            if (call != OAL_PTR_NULL) {
                call(entry);
            }
            entry = entry->next;
        }
    }
}

struct ftrace_list *NOTRACE ftrace_hash_find(unsigned long func_addr)
{
    struct ftrace_list *entry = OAL_PTR_NULL;
    int key = ftrace_hash_key(func_addr);
    struct ftrace_list *head = g_fhash_blkts[key];
    if (head == OAL_PTR_NULL) {
        return OAL_PTR_NULL;
    }

    entry = head;
    while (entry != OAL_PTR_NULL) {
        /* equal */
        if (((ftrace_event *)entry)->func_addr == func_addr) {
            return entry;
        }
        entry = entry->next;
    }

    return OAL_PTR_NULL;
}

void NOTRACE ftrace_hash_add(struct ftrace_list *entry)
{
    struct ftrace_list *fnext;
    int key = ftrace_hash_key(((ftrace_event *)entry)->func_addr);
    struct ftrace_list *head = g_fhash_blkts[key];

    entry->next = OAL_PTR_NULL;
    if (head == OAL_PTR_NULL) {
        g_fhash_blkts[key] = entry;
        return;
    }

    // insert from head
    fnext = head->next;
    head->next = entry;
    entry->next = fnext;
}

void NOTRACE ftrace_hash_init(void)
{
    memset_s((void *)g_fhash_blkts, sizeof(g_fhash_blkts),
        0, sizeof(g_fhash_blkts));
}
#endif