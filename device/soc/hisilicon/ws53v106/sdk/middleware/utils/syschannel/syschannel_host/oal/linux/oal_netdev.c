#include "oal_netdev.h"

#ifdef __cplusplus
#if __cplusplus
extern "C" {
#endif
#endif

oal_net_device_stru* oal_dev_get_by_name(const osal_char* pc_name)
{
    return dev_get_by_name(&init_net, pc_name);
}

osal_void oal_net_unregister_netdev(oal_net_device_stru* netdev)
{
    if (netdev == OSAL_NULL) {
        return;
    }
    unregister_netdev(netdev);
}

osal_void oal_ether_setup(oal_net_device_stru *net_device)
{
    if (net_device == OSAL_NULL) {
        return;
    }

    ether_setup(net_device);
    return;
}

osal_void oal_netif_stop_queue(oal_net_device_stru* netdev)
{
    if (netdev == OSAL_NULL) {
        return;
    }
    netif_stop_queue(netdev);
}

osal_void oal_netif_wake_queue(oal_net_device_stru* netdev)
{
    if (netdev == OSAL_NULL) {
        return;
    }
    netif_wake_queue(netdev);
}

#ifdef __cplusplus
#if __cplusplus
}
#endif
#endif