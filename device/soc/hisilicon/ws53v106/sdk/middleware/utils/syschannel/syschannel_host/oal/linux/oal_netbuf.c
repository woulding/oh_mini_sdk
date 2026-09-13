#include "oal_netbuf.h"

#ifdef __cplusplus
#if __cplusplus
extern "C" {
#endif
#endif

osal_u32 oal_netbuf_free(oal_netbuf_stru *netbuf)
{
    dev_kfree_skb(netbuf);
    return 0;
}

osal_u8* oal_netbuf_put(oal_netbuf_stru* netbuf, osal_u32 len)
{
    return skb_put(netbuf, len);
}

oal_netbuf_stru* oal_netbuf_alloc(osal_u32 ul_size, osal_u32 l_reserve, osal_u32 l_align)
{
    oal_netbuf_stru *netbuf;
    osal_u32       offset;

    if (l_align) {
        ul_size += (l_align - 1);
    }

    // do not use dev_alloc_skb which designed for RX
    netbuf = dev_alloc_skb(ul_size);
    if (unlikely(netbuf == OSAL_NULL)) {
        return OSAL_NULL;
    }
    skb_reserve(netbuf, l_reserve);

    if (l_align) {
        offset = (osal_s32)(((osal_u32)(uintptr_t)netbuf->data) % (osal_u32)l_align);
        if (offset) {
            skb_reserve(netbuf, l_align - offset);
        }
    }

    return netbuf;
}


#ifdef __cplusplus
#if __cplusplus
}
#endif
#endif