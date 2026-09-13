/*****************************************************************************
  1 头文件包含
*****************************************************************************/
#include "wal_netlink.h"
#include "securec.h"

#include "hcc_if.h"
#include "oal_netdev.h"
#include "oal_netbuf.h"
#include "syschannel_host_adapt.h"
#ifdef __cplusplus
#if __cplusplus
extern "C" {
#endif
#endif
/*****************************************************************************
  2 枚举、结构体定义
*****************************************************************************/
typedef struct {
    struct sock *netlink_sk;
    osal_u32 user_pid;
}netlink_user_s;

static osal_void oal_recieve_user_msg(struct sk_buff *skb);
/*****************************************************************************
  3 宏定义、全局变量
*****************************************************************************/
#define NETLINK_CHANNEL_MODEID          28
#undef NLMSG_ALIGNTO
#define NLMSG_ALIGNTO                   1

static struct netlink_kernel_cfg cfg = {
    .input  = oal_recieve_user_msg,
};

static netlink_user_s g_netlink_user;
/*****************************************************************************
  4 函数实现
*****************************************************************************/
osal_u32 oal_send_user_msg(osal_u8 *pbuf, osal_s32 len)
{
    struct sk_buff *nl_skb = OSAL_NULL;
    struct nlmsghdr *nlh = OSAL_NULL;
    osal_s32 ret;
    if (g_netlink_user.netlink_sk == OSAL_NULL) {
        return OSAL_NOK;
    }

    if ((pbuf == OSAL_NULL) || (len == 0) || (len > MAX_USER_LONG_DATA_LEN)) {
        osal_printk("send_usrmsg is fail:len:%d\n", len);
        return OSAL_NOK;
    }

    /* oal_send_user_msg函数作用是发消息给主控。user_pid为0表示netlink没有用户，会发消息给驱动，所以增加拦截 返回OK */
    if (g_netlink_user.user_pid == 0) {
        return OSAL_OK;
    }

    /* 创建sk_buff 空间 */
    nl_skb = nlmsg_new(len, GFP_ATOMIC);
    if (nl_skb == OSAL_NULL) {
        osal_printk("nlmsg_new is fail.\n");
        return OSAL_NOK;
    }

    /* 设置netlink消息头部 */
    nlh = nlmsg_put(nl_skb, 0, 0, NETLINK_CHANNEL_MODEID, len, 0);
    if (nlh == OSAL_NULL) {
        osal_printk("nlmsg_put is fail.\n");
        nlmsg_free(nl_skb);
        return OSAL_NOK;
    }

    /* 拷贝数据发送 */
    (osal_void)memcpy_s(nlmsg_data(nlh), nlmsg_len(nlh), pbuf, len);
    ret = netlink_unicast(g_netlink_user.netlink_sk, nl_skb, g_netlink_user.user_pid, MSG_DONTWAIT);
    if (ret == -1) {
        osal_printk("netlink_unicast is fail.\n");
        nlmsg_free(nl_skb);
        return OSAL_NOK;
    }

    return OSAL_OK;
}

static osal_void oal_recieve_user_msg(struct sk_buff *skb)
{
    osal_u32 payload_len;
    osal_char *umsg = OSAL_NULL;
    struct nlmsghdr *nlh = OSAL_NULL;
    syschannel_stat_stru *syschannel_stat = syschannel_host_get_trx_stat();
    syschannel_handler *syschannel_handler = syschannel_host_get_handler();
    if ((syschannel_handler == OSAL_NULL) || (syschannel_handler->inuse == OSAL_FALSE)) {
        return;
    }

    if (skb == OSAL_NULL) {
        return;
    }

    if (skb->len <= nlmsg_total_size(0)) {
        osal_printk("oal_netlink_deinit is success\n", skb->len, nlmsg_total_size(0));
        return;
    }

    nlh = nlmsg_hdr(skb);
    umsg = NLMSG_DATA(nlh);
    payload_len = nlh->nlmsg_len - NLMSG_HDRLEN; /* header len is nlmsg_total_size */
    g_netlink_user.user_pid = nlh->nlmsg_pid;

    if (payload_len > MAX_USER_LONG_DATA_LEN) {
        osal_printk("payload len[%d] is fail\n", payload_len);
        return;
    }

    if (syschannel_tx_msg_adapt(syschannel_handler->hcc_id, umsg, payload_len, SYSCHANNEL_SERVICE_TYPE_MSG,
        SYSCHANNEL_SUB_TYPE_MSG_APP) != OSAL_OK) {
        syschannel_stat->app_msg_tx_fail++;
        osal_printk("syschannel_tx_msg_adapt is fail\n");
    } else {
        syschannel_stat->app_msg_tx++;
    }
}

osal_s32 oal_netlink_init(osal_void)
{
    if (g_netlink_user.netlink_sk != OSAL_NULL) {
        osal_printk("oal_netlink_init is fail\n");
        return OSAL_NOK;
    }

    /* create netlink socket */
    g_netlink_user.netlink_sk = (struct sock *)netlink_kernel_create(&init_net, NETLINK_CHANNEL_MODEID, &cfg);
    if (g_netlink_user.netlink_sk == OSAL_NULL) {
        osal_printk("netlink_kernel_create is fail\n");
        return OSAL_NOK;
    }

    osal_printk("oal_netlink_init is success\n");
    return OSAL_OK;
}

osal_s32 oal_netlink_deinit(osal_void)
{
    if (g_netlink_user.netlink_sk == OSAL_NULL) {
        printk("oal_netlink_deinit is fail\n");
        return OSAL_NOK;
    }

    netlink_kernel_release(g_netlink_user.netlink_sk); /* release. */
    g_netlink_user.netlink_sk = OSAL_NULL;
    g_netlink_user.user_pid = 0;
    osal_printk("oal_netlink_deinit is success\n");
    return OSAL_OK;
}

#ifdef __cplusplus
#if __cplusplus
}
#endif
#endif

