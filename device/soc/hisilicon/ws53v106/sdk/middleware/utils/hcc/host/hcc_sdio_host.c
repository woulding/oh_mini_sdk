/*
 * Copyright (c) HiSilicon (Shanghai) Technologies Co., Ltd. 2020-2023. All rights reserved.
 * Description: host sdio driver.
 * Author: Huanghe
 * Create: 2020-10-20
 */
#ifdef CONFIG_HCC_SUPPORT_SDIO
#include "td_base.h"
#include "td_type.h"
#include "soc_osal.h"
#include "osal_def.h"
#include "securec.h"
#include "hcc_if.h"
#include "hcc_list.h"
#include "hcc_bus_types.h"
#include "hcc.h"
#include "hcc_comm.h"
#include "hcc_adapt.h"
#include "hcc_queue.h"
#include "hcc_flow_ctrl.h"
#include "hcc_cfg_comm.h"

#include "oal_hcc_bus_os_adapt.h"

#if defined(_PRE_OS_VERSION_LINUX) && defined(_PRE_OS_VERSION) && (_PRE_OS_VERSION_LINUX == _PRE_OS_VERSION)
#include "oal_sdio_linux_adapt.h"
#define PRE_SDIO_FEATURE_SCATTER
#endif

#if defined(_PRE_OS_VERSION_LITEOS) && defined(_PRE_OS_VERSION) && (_PRE_OS_VERSION_LITEOS == _PRE_OS_VERSION)
#include "oal_sdio_liteos_adapt.h"
#include "mmcbus_if.h"
#define PRE_SDIO_FEATURE_FLAT_MEMORY
#endif

#if defined(_PRE_OS_VERSION_RTTHREAD) && defined(_PRE_OS_VERSION) && (_PRE_OS_VERSION_RTTHREAD == _PRE_OS_VERSION)
#include "oal_sdio_rtthread_adapt.h"
#include "fh_mmc.h"
#include "common_def.h"
#define PRE_SDIO_FEATURE_FLAT_MEMORY
#endif

#if defined(_PRE_PLATFORM_JZ) && defined(_PRE_OS_PLATFORM) && (_PRE_OS_PLATFORM == _PRE_PLATFORM_JZ)
#include <mach/jzmmc.h>
#include <soc/gpio.h>
#endif
#include "hcc_sdio_host.h"

#ifdef __cplusplus
#if __cplusplus
extern "C" {
#endif
#endif

#undef THIS_FILE_ID
#define THIS_FILE_ID DIAG_FILE_ID_HCC_SDIO_HOST_C

#undef THIS_MOD_ID
#define THIS_MOD_ID LOG_PFMODULE

#define SDIO_CMD_ADDR_OFFSET                      9
#define SDIO_CMD_FUNC_OFFSET                      28

#define BYTE_OFFSET1_IN_WORD                      8
#define BYTE_OFFSET2_IN_WORD                      16
#define BYTE_OFFSET3_IN_WORD                      24
#define SDIO_EN_TIMEOUT                           1000

#define HCC_SDIO_VENDOR_ID_WS73                    0x12D1      /* VENDOR ws73 */
#define HCC_SDIO_PRODUCT_ID_WS73                   0x0073      /* Product ws73 */
#define HCC_SDIO_VENDOR_ID_WS53                    0xED2E      /* VENDOR ws53 */
#define HCC_SDIO_PRODUCT_ID_WS53                   0xFFAC      /* Product ws53 */
#define HCC_FLOW_CTRL_REG_WS53                     0x5900D214      /* ws53 flow ctrl general reg */
#define HCC_WLAN_BASE_REG_WS53                     0x59009000      /* ws53 wlan base reg */
#define HCC_FLOW_CTRL_GP_REG    ((HCC_FLOW_CTRL_REG_WS53) - (HCC_WLAN_BASE_REG_WS53))     /* flow ctrl general reg */

#define HCC_SDIO_REG_FUNC1_FIFO                      0x00        /* Read Write FIFO */
#define HCC_SDIO_REG_FUNC1_INT_STATUS                0x08        /* interrupt mask and clear reg */
#define HCC_SDIO_REG_FUNC1_INT_ENABLE                0x09        /* interrupt */
#define HCC_SDIO_REG_FUNC1_XFER_COUNT                0x0c        /* notify number of bytes to be read */
#define HCC_SDIO_REG_FUNC1_WRITE_MSG                 0x24        /* write msg to device */
#define HCC_SDIO_REG_FUNC1_MSG_FROM_DEV              0x28        /* notify Host that device has got the msg */
/* notify Host that device has got the msg, Host receive the msg ack */
#define HCC_SDIO_REG_FUNC1_MSG_HIGH_FROM_DEV         0x2b

#define HCC_SDIO_WAKEUP_DEV_REG                      0xf0
#define ALLOW_TO_SLEEP_VALUE                       1
#define DISALLOW_TO_SLEEP_VALUE                    0

#define SDIO_CCCR_INTERRUPT_EXTENSION              0x16
#define SDIO_EXTEND_CREDIT_ADDR                    0x3c

/* 0x30~0x38, 0x3c~7B */
#define HCC_SDIO_EXTEND_BASE_ADDR                   0x30
#define HCC_SDIO_SCATT_MEMBUFFER_ALIGN              4
#define HCC_SDIO_COMM_REG_OFFSET                    24

static td_s32 hcc_sdio_reset_card(struct oal_sdio *sdio_priv);
static td_u32 sdio_func_max_req_size(struct oal_sdio *pst_hi_sdio);

static td_u32 sdio_align_4_or_blk(td_u32 len)
{
    return len < HCC_SDIO_BLOCK_SIZE ? OAL_ALIGN((len), HCC_SDIO_SCATT_MEMBUFFER_ALIGN) :
        OAL_ALIGN((len), HCC_SDIO_BLOCK_SIZE);
}

#ifdef CONFIG_SDIO_DEBUG
static td_u32 hcc_sdio_comm_reg_seq_get(td_u32 reg)
{
    return ((reg >> HCC_SDIO_COMM_REG_OFFSET) & 0xFF);
}
#endif

#define HCC_SDIO_FUNC1_INT_DREADY      (1 << 0)           /* data ready interrupt */
#define HCC_SDIO_FUNC1_INT_RERROR      (1 << 1)           /* data read error interrupt */
#define HCC_SDIO_FUNC1_INT_MFARM       (1 << 2)           /* ARM Msg interrupt */
#define HCC_SDIO_FUNC1_INT_ACK         (1 << 3)           /* ACK interrupt */

#define HCC_SDIO_FUNC1_INT_MASK      (HCC_SDIO_FUNC1_INT_DREADY | HCC_SDIO_FUNC1_INT_RERROR | HCC_SDIO_FUNC1_INT_MFARM)

#define SDIO_RW_BLOCKS   1
#define SDIO_RW_BLKSZ    4
#define SDIO_RW_FLAGS    0X1b5
#define SDIO_W_ARG       0x86000004
#define SDIO_R_ARG       0x06000004

#define INT_MODE_SDIO   0
/* use GPIO as SDIO interrupt */
#define INT_MODE_GPIO   1
#if defined(_PRE_OS_VERSION_LINUX) && defined(_PRE_OS_VERSION) && (_PRE_OS_VERSION_LINUX == _PRE_OS_VERSION)
#if defined(_PRE_PLATFORM_JZ) && defined(_PRE_OS_PLATFORM) && (_PRE_OS_PLATFORM == _PRE_PLATFORM_JZ)
#define HCC_SDIO_INT_GPIO_NUM        9
#elif defined(_PRE_PLATFORM_HISILICON) && defined(_PRE_OS_PLATFORM) && (_PRE_OS_PLATFORM == _PRE_PLATFORM_HISILICON)
#define HCC_SDIO_INT_GPIO_NUM        33
#else
#define HCC_SDIO_INT_GPIO_NUM        70
#endif
#define HCC_SDIO_GPIO_DESC_LABEL     "SDIO_RX_INT"
#define HCC_SDIO_RX_ISR_NAME    "rx_isr"
#define HCC_SDIO_RX_ISR_PRIO    3
#define HCC_SDIO_RX_ISR_SIZE    0x400
#endif

#define SDIO_FUNC_MAX   7
#define SDIO_PROBLE_TIMES 3

#define SDIO_BUS_DESCRIPT_BUF_LEN 64

#define SDIO_MODULE_NAME "[SDIO]"

char *g_sdio_priv_log = "sdio_priv null";
#if defined(_PRE_FEATURE_WS53_DEVICE_MODE) || defined(_PRE_FEATURE_SYSCHANNEL_LITEOS)
#define SDIO_IDS_INDEX 1
#else
#define SDIO_IDS_INDEX 0
#endif

#define CONFIG_SDIO_D2H_MSG_ACK

struct oal_sdio *g_sdio_handler = TD_NULL;

td_s32 g_sdio_panic = 0;

td_s32 g_sdio_intr_mode = INT_MODE_SDIO;
static td_bool g_sdio_intr_status = TD_FALSE;
static td_bool g_sdio_probe_status = TD_FALSE;
static td_bool g_sdio_remove_enable = TD_FALSE;
td_s32 g_sdio_wkup_device = 0;
osal_atomic g_sdio_int_set;
static td_s32 sdio_data_single_irq(struct oal_sdio *sdio_priv);
static hcc_bus *sdio_bus_init(struct oal_sdio *sdio_priv);
static td_s32 sdio_get_state(hcc_bus *pst_bus, td_u32 mask);
static td_void sdio_bus_exit(struct oal_sdio *sdio_priv);
static td_s32 sdio_wakeup_dev(struct oal_sdio *sdio_priv);
static struct oal_sdio *sdio_init_module(td_void);
static td_void sdio_exit_module(struct oal_sdio *sdio_priv);
static td_void sdio_interrupt_unregister(struct oal_sdio *sdio_priv);
static td_s32 sdio_interrupt_register(struct oal_sdio *sdio_priv);
static td_u32 sdio_rx_netbuf(struct oal_sdio *pst_sdio, hcc_data_queue *pst_head);
#ifdef PRE_SDIO_FEATURE_FLAT_MEMORY
#define OAL_HDR_TOTAL_LEN    80
static td_s32 sdio_transfer_flat_memory(struct oal_sdio *sdio_priv, hcc_data_queue *head, td_s32 rw);
#endif

#ifdef PRE_SDIO_FEATURE_SCATTER
static td_s32 sdio_transfer_netbuf_list(struct oal_sdio *sdio_priv, hcc_data_queue *head, td_s32 rw);
#endif

#define SIZE_OF_SDIO_READ_TXBUF 4
#if defined(_PRE_OS_VERSION_LINUX) && defined(_PRE_OS_VERSION) && (_PRE_OS_VERSION_LINUX == _PRE_OS_VERSION)
static struct completion g_sdio_driver_complete;
static char *g_sdio_read_fn0_txbuf = TD_NULL;
#endif

#if defined(_PRE_OS_VERSION_RTTHREAD) && defined(_PRE_OS_VERSION) && (_PRE_OS_VERSION_RTTHREAD == _PRE_OS_VERSION)
static osal_semaphore g_sdio_driver_complete;
static oal_sdio_device_id sdio_ids = {
    SDIO_DEVICE(HCC_SDIO_VENDOR_ID_WS53, HCC_SDIO_PRODUCT_ID_WS53)
};
#else
static oal_sdio_device_id sdio_ids[] = {
    { SDIO_DEVICE(HCC_SDIO_VENDOR_ID_WS73, HCC_SDIO_PRODUCT_ID_WS73) },
    { SDIO_DEVICE(HCC_SDIO_VENDOR_ID_WS53, HCC_SDIO_PRODUCT_ID_WS53) },
    {},
};
#endif

#if !defined _PRE_FEATURE_WS53_DEVICE_MODE && !defined _PRE_FEATURE_SYSCHANNEL_LITEOS && !defined(__RTTHREAD__)
MODULE_DEVICE_TABLE(sdio, sdio_ids);
#endif

#if defined(CONFIG_HCC_SUPPORT_PATCH_OPT) || defined(PRE_SDIO_FEATURE_FLAT_MEMORY)
/**
 *  oal_sdio_writesb - write to a FIFO of a SDIO function
 *  @func: SDIO function to access
 *  @addr: address of (single byte) FIFO
 *  @src: buffer that contains the data to write
 *  @count: number of bytes to write
 *  @dma:buffer support dma
 *  Writes to the specified FIFO of a given SDIO function. Return
 *  value indicates if the transfer succeeded or not.
 */
static td_s32 oal_sdio_writesb(oal_sdio_func *func, td_u32 addr, td_void *src, td_u32 count, td_bool dma)
{
    if (!dma) {
        errno_t mem_res;
        td_u8 *buf = osal_kmalloc(count, OSAL_GFP_KERNEL);
        if (buf == TD_NULL) {
            return EXT_ERR_FAILURE;
        }
        mem_res = memcpy_s(buf, count, src, count);
        if (mem_res == EOK) {
            mem_res = oal_sdio_adapt_writesb(func, addr, buf, count);
        }
        osal_kfree(buf);
        return (td_s32)mem_res;
    } else {
        return oal_sdio_adapt_writesb(func, addr, src, count);
    }
}
#endif
/**
 *  oal_sdio_readsb - read from a FIFO on a SDIO function
 *  @func: SDIO function to access
 *  @dst: buffer to store the data
 *  @addr: address of (single byte) FIFO
 *  @count: number of bytes to read
 *  @dma:buffer support dma
 *  Reads from the specified FIFO of a given SDIO function. Return
 *  value indicates if the transfer succeeded or not.
 */
static td_s32 oal_sdio_readsb(oal_sdio_func *func, td_void *dst, td_u32 addr, td_s32 count, td_bool dma)
{
    if (!dma) {
        td_s32 ret;
        td_u8 *buf = osal_kmalloc((td_u32)count, OSAL_GFP_KERNEL);
        if (buf == TD_NULL) {
            return EXT_ERR_FAILURE;
        }

        ret = oal_sdio_adapt_readsb(func, buf, addr, count);
        if (ret != 0) {
            osal_kfree(buf);
            return ret;
        }
        if (memcpy_s(dst, (td_u32)count, buf, (td_u32)count) != EOK) {
            ret = EXT_ERR_FAILURE;
        }
        osal_kfree(buf);
        return ret;
    } else {
        return oal_sdio_adapt_readsb(func, dst, addr, count);
    }
}

/**
 *  oal_sdio_memcpy_fromio - read a chunk of memory from a SDIO function
 *  @func: SDIO function to access
 *  @dst: buffer to store the data
 *  @addr: address to begin reading from
 *  @count: number of bytes to read
 *  @dma:buffer support dma
 *  Reads from the address space of a given SDIO function. Return
 *  value indicates if the transfer succeeded or not.
 */
static td_s32 oal_sdio_memcpy_fromio(oal_sdio_func *func, td_void *dst,
    td_u32 addr, td_s32 count, td_bool dma)
{
    if (!dma) {
        td_s32 ret;
        td_u8 *buf = osal_kmalloc((unsigned long)count, OSAL_GFP_KERNEL);
        if (buf == TD_NULL) {
            return EXT_ERR_FAILURE;
        }

        ret = oal_sdio_adapt_memcpy_fromio(func, buf, addr, count);
        if (ret != 0) {
            osal_kfree(buf);
            return ret;
        }
        if (memcpy_s(dst, (td_u32)count, buf, (td_u32)count) != EOK) {
            ret = EXT_ERR_FAILURE;
        }
        osal_kfree(buf);
        return ret;
    } else {
        return oal_sdio_adapt_memcpy_fromio(func, dst, addr, count);
    }
}

static hcc_bus *sdio_get_bus_handler(td_void)
{
    if (g_sdio_handler != TD_NULL) {
        return g_sdio_handler->pst_bus;
    }
    return TD_NULL;
}

static ext_errno hcc_sdio_send_msg(TD_CONST hcc_bus *pst_bus, td_u32 val)
{
    td_s32 ret = EXT_ERR_SUCCESS;
    struct oal_sdio *sdio_priv = (struct oal_sdio *)pst_bus->data;
    oal_sdio_func *func = TD_NULL;

    if (OAL_UNLIKELY(sdio_priv == TD_NULL)) {
        oal_sdio_log(BUS_LOG_ERR, "%s", g_sdio_priv_log);
        return EXT_ERR_FAILURE;
    }

    if (OAL_WARN_ON(sdio_priv->func == TD_NULL)) {
        oal_sdio_log(BUS_LOG_ERR, "sdio_func null");
        return EXT_ERR_FAILURE;
    }

    func = sdio_priv->func;
    if (val >= HCC_TX_MAX_MESSAGE) {
        oal_sdio_log(BUS_LOG_ERR, "invaild msg[%u]!", val);
        return EXT_ERR_FAILURE;
    }
    oal_sdio_claim_host(func);
    oal_sdio_writel(func, (1 << val), HCC_SDIO_REG_FUNC1_WRITE_MSG, &ret);
    oal_sdio_release_host(func);
    return ret;
}

static td_void sdio_print_state(td_u32 old_state, td_u32 new_state)
{
    if (old_state != new_state) {
        oal_sdio_log(BUS_LOG_INFO, "sdio state changed, tx[%s=>%s],rx[%s=>%s]",
            ((old_state & HCC_BUS_STATE_TX) != 0) ? "on " : "off",
            ((new_state & HCC_BUS_STATE_TX) != 0) ? "on " : "off",
            ((old_state & HCC_BUS_STATE_RX) != 0) ? "on " : "off",
            ((new_state & HCC_BUS_STATE_RX) != 0) ? "on " : "off");
    }
}

static td_void sdio_ctrl_state(hcc_bus *sdio_bus, td_u32 mask, td_bool enable)
{
    td_u32 old_state;
    struct oal_sdio *sdio_priv = TD_NULL;

    if (OAL_WARN_ON(sdio_bus == TD_NULL)) {
        oal_sdio_log(BUS_LOG_ERR, "sdio_bus null");
        return;
    }
    sdio_priv = (struct oal_sdio *)sdio_bus->data;

    old_state = sdio_priv->state;
    if (enable) {
        sdio_priv->state |= mask;
    } else {
        sdio_priv->state &= ~mask;
    }
    sdio_print_state(old_state, sdio_priv->state);
}

static td_void sdio_enable_state(hcc_bus *sdio_bus, td_u32 mask)
{
    sdio_ctrl_state(sdio_bus, mask, TD_TRUE);
}

static td_void sdio_disable_state(hcc_bus *sdio_bus, td_u32 mask)
{
    sdio_ctrl_state(sdio_bus, mask, TD_FALSE);
}

static td_s32 sdio_get_state(hcc_bus *pst_bus, td_u32 mask)
{
    struct oal_sdio *sdio_priv = TD_NULL;

    if (OAL_WARN_ON(pst_bus == TD_NULL)) {
        oal_sdio_log(BUS_LOG_ERR, "sdio_bus null");
        return TD_FALSE;
    }

    if (OAL_WARN_ON(pst_bus->data == TD_NULL)) {
        oal_sdio_log(BUS_LOG_ERR, "sdio_bus data null");
        return TD_FALSE;
    }

    sdio_priv = (struct oal_sdio *)pst_bus->data;
    if ((sdio_priv->state & mask) == mask) {
        return TD_TRUE;
    } else {
        return TD_FALSE;
    }
}

static td_s32 hcc_sdio_power_action(hcc_bus *pst_bus, hcc_bus_power_action_type action)
{
#if defined(_PRE_OS_VERSION_LINUX) && defined(_PRE_OS_VERSION) && (_PRE_OS_VERSION_LINUX == _PRE_OS_VERSION)
    struct oal_sdio *sdio_priv = TD_NULL;
    if (OAL_WARN_ON(pst_bus == TD_NULL)) {
        return EXT_ERR_FAILURE;
    }
    sdio_priv = (struct oal_sdio *)pst_bus->data;
    if (OAL_WARN_ON(sdio_priv == TD_NULL)) {
        return EXT_ERR_FAILURE;
    }
    if (action == HCC_BUS_POWER_DOWN) {
        hcc_sdio_reset_card(sdio_priv);
    }
#endif
    return EXT_ERR_SUCCESS;
}

/* init sdio function */
static td_s32 sdio_dev_init(struct oal_sdio *sdio_priv)
{
    oal_sdio_func *func = TD_NULL;
    td_s32 ret;

    if (OAL_WARN_ON(sdio_priv == TD_NULL)) {
        oal_sdio_log(BUS_LOG_ERR, "%s", g_sdio_priv_log);
        return EXT_ERR_FAILURE;
    };
    func = sdio_priv->func;

    oal_sdio_claim_host(func);
    oal_sdio_set_en_timeout(func, SDIO_EN_TIMEOUT);
    ret = oal_sdio_enable_func(func);
    if (ret < 0) {
        oal_sdio_release_host(func);
        oal_sdio_log(BUS_LOG_ERR, "sdio func enable fail=%d", ret);
        return ret;
    }

    ret = oal_sdio_set_block_size(func, HCC_SDIO_BLOCK_SIZE);
    if (ret != 0) {
        oal_sdio_log(BUS_LOG_ERR, "set sdio blk size fail=%d", ret);
        goto failed_enabe_func;
    }

    /* before enable sdio function 1, clear its interrupt flag, no matter it exist or not */
    oal_sdio_writeb(func, HCC_SDIO_FUNC1_INT_MASK, HCC_SDIO_REG_FUNC1_INT_STATUS, &ret);
    if (ret != 0) {
        oal_sdio_log(BUS_LOG_ERR, "clear sdio interrupt fail=%d", ret);
        goto failed_enabe_func;
    }

    oal_sdio_writeb(func, HCC_SDIO_FUNC1_INT_MASK, HCC_SDIO_REG_FUNC1_INT_ENABLE, &ret);
    if (ret < 0) {
        oal_sdio_log(BUS_LOG_ERR, "enable sdio interrupt fail=%d", ret);
        goto failed_enabe_func;
    }

    oal_sdio_release_host(sdio_priv->func);
    return EXT_ERR_SUCCESS;

failed_enabe_func:
    oal_sdio_disable_func(func);
    oal_sdio_release_host(func);
    return ret;
}

#if defined(_PRE_OS_VERSION_LITEOS) && defined(_PRE_OS_VERSION) && (_PRE_OS_VERSION_LITEOS == _PRE_OS_VERSION)
#define MAX_SDIO_RESCAN_NUM 10
td_s32 sdio_rescan_device(hcc_bus *pst_bus)
{
    td_s32 i;
    oal_sdio_func *new_func;
    struct oal_sdio *sdio_priv;

    if (pst_bus == TD_NULL || pst_bus->data == TD_NULL) {
        return EXT_ERR_FAILURE;
    }
    sdio_priv = (struct oal_sdio *)pst_bus->data;
    sdio_disable_state(pst_bus, HCC_BUS_STATE_ALL);
    sdio_interrupt_unregister(sdio_priv);

    oal_sdio_claim_host(sdio_priv->func);
    oal_sdio_disable_func(sdio_priv->func);
    oal_sdio_release_host(sdio_priv->func);

#if defined(CONFIG_JZMMC_V12_MMC1) || defined(CONFIG_MMC_SDHCI_INGENIC)
    jzmmc_manual_detect(1, 1);
#elif defined(CONFIG_3519D)
    bsp_sdio_rescan(2); /* mmc2 */
#elif defined(CONFIG_3516CV610)
    sdhci_nebula_sdio_rescan(2); /* mmc2 */
#else
    hisi_sdio_rescan(1);
#endif

    for (i = 0; i < MAX_SDIO_RESCAN_NUM; i++) {
        new_func = sdio_get_func(1, sdio_ids[SDIO_IDS_INDEX].vendor, sdio_ids[SDIO_IDS_INDEX].device);
        if (new_func != TD_NULL) {
            break;
        }
        osal_msleep(100); // 每次尝试后休眠100ms
    }

    if (i == MAX_SDIO_RESCAN_NUM) {
        oal_sdio_log(BUS_LOG_ERR, "sdio_get_func recan fail");
        return EXT_ERR_FAILURE;
    }
    sdio_priv->func = new_func;
    oal_sdio_set_drvdata(new_func, sdio_priv);
    return EXT_ERR_SUCCESS;
}
#endif

static td_void sdio_reinit_assemble(td_void)
{
    hcc_data_queue *hcc_queue = &g_sdio_handler->tx_assemble_info.assembled_head;
    hcc_list_free(g_sdio_handler->pst_bus->hcc, hcc_queue);
    hcc_queue = &g_sdio_handler->rx_assemble_head;
    hcc_list_free(g_sdio_handler->pst_bus->hcc, hcc_queue);
    g_sdio_handler->tx_assemble_info.assemble_num = 0;
}

static td_s32 hcc_sdio_reset_card(struct oal_sdio *sdio_priv)
{
#if defined(_PRE_OS_VERSION_LINUX) && defined(_PRE_OS_VERSION) && (_PRE_OS_VERSION_LINUX == _PRE_OS_VERSION)
    td_s32 ret = 0;
    osal_u32 sdio_host_caps = sdio_priv->func->card->host->caps;
    /* disable irq and state to avoid unexpected sdio irq */
    sdio_interrupt_unregister(sdio_priv);
    sdio_disable_state(sdio_priv->pst_bus, HCC_BUS_STATE_ALL);
    /* mmc hw reset */
    sdio_priv->func->card->host->caps |= MMC_CAP_NONREMOVABLE;
    oal_sdio_claim_host(sdio_priv->func);
#if defined(LINUX_VERSION_CODE) && defined(KERNEL_VERSION) && (LINUX_VERSION_CODE < KERNEL_VERSION(4,19,0))
    mmc_power_save_host(sdio_priv->func->card->host);
    sdio_priv->func->card->host->pm_flags &= ~MMC_PM_KEEP_POWER;
    ret = mmc_power_restore_host(sdio_priv->func->card->host);
    sdio_priv->func->card->host->pm_flags |= MMC_PM_KEEP_POWER;
#elif defined(LINUX_VERSION_CODE) && defined(KERNEL_VERSION) && (LINUX_VERSION_CODE < KERNEL_VERSION(5,18,0))
    ret = mmc_hw_reset(sdio_priv->func->card->host);
#else
    ret = mmc_hw_reset(sdio_priv->func->card);
#endif
    oal_sdio_release_host(sdio_priv->func);
    sdio_priv->func->card->host->caps = sdio_host_caps;

    return (ret < 0) ? EXT_ERR_FAILURE : EXT_ERR_SUCCESS;
#else
    return EXT_ERR_SUCCESS;
#endif
}

static td_s32 hcc_sdio_reinit(hcc_bus *pst_bus)
{
    td_s32 ret = 0;
    struct oal_sdio *sdio_priv;
    if (pst_bus == TD_NULL) {
        return EXT_ERR_FAILURE;
    }

    sdio_priv = (struct oal_sdio *)pst_bus->data;
    if (sdio_priv == TD_NULL) {
        return EXT_ERR_FAILURE;
    }

    sdio_interrupt_unregister(sdio_priv);
    sdio_disable_state(pst_bus, HCC_BUS_STATE_ALL);
    oal_sdio_log(BUS_LOG_DBG, "sdio_reinit start !");
    ret = hcc_sdio_reset_card(sdio_priv);
    if (ret != EXT_ERR_SUCCESS) {
        oal_sdio_log(BUS_LOG_INFO, "reset sdio");
        return EXT_ERR_FAILURE;
    }
    sdio_reinit_assemble();

    ret = sdio_dev_init(sdio_priv);
    if (ret < 0) {
        return ret;
    }
    ret = sdio_interrupt_register(sdio_priv);
    if (ret < 0) {
        return ret;
    }
    /* For sdio mem pg,
      sd clk 7 cycles mem pwrup cost */
    sdio_wakeup_dev(sdio_priv);

    sdio_enable_state(pst_bus, HCC_BUS_STATE_ALL);
    oal_sdio_log(BUS_LOG_DBG, "sdio_reinit over !");

    return EXT_ERR_SUCCESS;
}

/* rx data from sdio, Just support single transfer */
static td_s32 sdio_data_single_irq(struct oal_sdio *sdio_priv)
{
    if (OAL_UNLIKELY(sdio_priv == TD_NULL) || (OAL_UNLIKELY(sdio_priv->func == TD_NULL))) {
        oal_sdio_log(BUS_LOG_ERR, "sdio_priv or func is null");
        return EXT_ERR_FAILURE;
    }

    osal_atomic_set(&g_sdio_int_set, 1);
    /* beacuse get buf may cost lot of time, so release bus first */
    if (sdio_rx_netbuf(sdio_priv, &sdio_priv->rx_assemble_head) == EXT_ERR_SUCCESS) {
        hcc_bus_rx_handler(sdio_priv->pst_bus, sdio_priv->sdio_extend->comm_reg[0], &sdio_priv->rx_assemble_head);
    }
    return EXT_ERR_SUCCESS;
}

static td_s32 sdio_msg_stat(struct oal_sdio *sdio_priv, td_u32 *msg)
{
    td_s32 ret = 0;
    *msg = sdio_priv->sdio_extend->msg_stat;

    if (*msg == 0) {
        /* no sdio message! */
        return EXT_ERR_SUCCESS;
    }
#ifdef CONFIG_SDIO_D2H_MSG_ACK
    /* read from old register */
    /* 当使用0x30寄存器时需要下发CMD52读0x2B 才会产生HOST2ARM ACK中断 */
    oal_sdio_claim_host(sdio_priv->func);
    (td_void)oal_sdio_readb(sdio_priv->func, HCC_SDIO_REG_FUNC1_MSG_HIGH_FROM_DEV, &ret);
    if (ret != 0) {
        oal_sdio_log(BUS_LOG_ERR, "sdio readb ret=%d", ret);
    }
    oal_sdio_release_host(sdio_priv->func);
#endif
    return EXT_ERR_SUCCESS;
}

/* msg irq */
static td_s32 sdio_msg_irq(struct oal_sdio *sdio_priv)
{
    td_s32 bit = 0;
    td_u32 msg = 0;
    td_s32 ret = 0;
    unsigned long msg64 = 0;

    /* reading interrupt form ARM Gerneral Purpose Register(0x28)  */
    ret = sdio_msg_stat(sdio_priv, &msg);
    if (ret != 0) {
        oal_sdio_log(BUS_LOG_ERR, "sdio_msg_stat ret=%d", ret);
        return ret;
    }
    msg64 = (unsigned long)msg;

    if (msg == 0) {
        return EXT_ERR_SUCCESS;
    }

    if (test_bit(D2H_MSG_DEVICE_PANIC, &msg64) != 0) {
        /* Close sdio. */
        g_sdio_panic = 1;
        oal_sdio_log(BUS_LOG_INFO, "sdio d2h panic message");
        sdio_disable_state(sdio_priv->pst_bus, HCC_BUS_STATE_ALL);
    }

    if (test_and_clear_bit(D2H_MSG_DEVICE_PANIC, &msg64) != 0) {
        hcc_bus_call_rx_message(sdio_priv->pst_bus, D2H_MSG_DEVICE_PANIC);
    }

    bit = 0;
    for_each_set_bit(bit, (TD_CONST unsigned long *)&msg64, (uint32_t)HCC_RX_MAX_MESSAGE) {
        hcc_bus_call_rx_message(sdio_priv->pst_bus, bit);
    }
    return EXT_ERR_SUCCESS;
}

static td_s32 sdio_extend_buf_get(struct oal_sdio *sdio_priv)
{
    td_s32 ret;
    ret = oal_sdio_memcpy_fromio(sdio_priv->func, (td_void *)sdio_priv->sdio_extend, HCC_SDIO_EXTEND_BASE_ADDR,
        sizeof(struct hcc_sdio_extend_func), TD_TRUE);
    if (OAL_LIKELY(ret == EXT_ERR_SUCCESS)) {
#ifdef CONFIG_SDIO_DEBUG
        oal_sdio_log(BUS_LOG_INFO, "=========extend buff:%d=====\n",
            hcc_sdio_comm_reg_seq_get(sdio_priv->sdio_extend->credit_info));
#endif
    }

    return ret;
}

static td_s32 sdio_transfer_rx_reserved_buff(struct oal_sdio *sdio_priv)
{
    td_s32 ret;
    td_u32 extend_len;
    if (sdio_priv->sdio_extend == TD_NULL) {
        oal_sdio_log(BUS_LOG_ERR, "sdio_extend null");
        return EXT_ERR_FAILURE;
    }

    extend_len = sdio_priv->sdio_extend->xfer_count;

    if (extend_len == 0) {
        oal_sdio_log(BUS_LOG_ERR, "extend_len is zero!");
        return EXT_ERR_FAILURE;
    }

    if (extend_len > SDIO_MAX_XFER_LEN) {
        return EXT_ERR_FAILURE;
    }

    ret = oal_sdio_readsb(sdio_priv->func, sdio_priv->rx_reserved_buff, 0, (td_s32)extend_len, TD_TRUE);

    return ret;
}

static td_s32 sdio_build_rx_list(struct oal_sdio *sdio_priv, hcc_data_queue *head)
{
    td_s32 i;
    td_u8 buff_len;
    td_u16 buff_len_t;
    td_u32 sum_len = 0;
    hcc_unc_struc *unc_buf = TD_NULL;

    /* always should be empty */
    if (OAL_UNLIKELY((!hcc_is_list_empty(head)) || (sdio_priv->pst_bus == TD_NULL) ||
        (sdio_priv->pst_bus->hcc == TD_NULL))) {
        oal_sdio_log(BUS_LOG_ERR, "param err");
        goto failed_param_err;
    }

    for (i = 1; i < HCC_SDIO_EXTEND_REG_COUNT; i++) {
        buff_len = sdio_priv->sdio_extend->comm_reg[i];
        if (buff_len == 0) {
            break;
        }
        buff_len_t = buff_len << HCC_SDIO_D2H_SCATT_BUFFLEN_ALIGN_BITS;
        unc_buf = hcc_adapt_alloc_unc_buf((hcc_handler *)sdio_priv->pst_bus->hcc,
            buff_len_t, sdio_priv->sdio_extend->comm_reg[0]);
        if (unc_buf == TD_NULL) {
            oal_sdio_log(BUS_LOG_ERR, "rx no mem:%u, index:%d", buff_len, i);
            goto failed_netbuf_alloc;
        }

        sum_len += buff_len_t;
        hcc_list_add_tail(head, unc_buf);
    }

    if (sdio_align_4_or_blk(sum_len) != sdio_priv->sdio_extend->xfer_count) {
        oal_sdio_log(BUS_LOG_ERR, "error:scatt total[%u] should[%u],pad len[%u]", sum_len,
            sdio_priv->sdio_extend->xfer_count, sdio_align_4_or_blk(sum_len));

        sdio_priv->error_stat.rx_scatt_info_not_match++;
        goto failed_netbuf_alloc;
    }

    if (OAL_UNLIKELY(hcc_is_list_empty(head))) {
        oal_sdio_log(BUS_LOG_ERR, "list empty xfercount:%u\n", sdio_priv->sdio_extend->xfer_count);
        return EXT_ERR_FAILURE;
    }

    return EXT_ERR_SUCCESS;
failed_netbuf_alloc:
    hcc_list_free((hcc_handler *)(sdio_priv->pst_bus->hcc), head);
failed_param_err:
    sdio_transfer_rx_reserved_buff(sdio_priv);
    return EXT_ERR_FAILURE;
}

static td_s32 sdio_get_func1_int_status(struct oal_sdio *sdio_priv, td_u8 *int_stat)
{
    sdio_priv->sdio_extend->int_stat &= sdio_priv->func1_int_mask;
    *int_stat = (sdio_priv->sdio_extend->int_stat & 0xF);
    return EXT_ERR_SUCCESS;
}

/* sdio rx data */
static td_s32 sdio_do_isr(struct oal_sdio *sdio_priv)
{
    td_u8 int_mask;
    td_s32 ret;

    /* sdio bus state access lock by sdio bus claim locked. */
    if (OAL_UNLIKELY(sdio_get_state(sdio_priv->pst_bus, HCC_BUS_STATE_RX) != TD_TRUE)) {
        oal_sdio_log(BUS_LOG_DBG, "sdio closed panic:%d,state:%u",
            g_sdio_panic, sdio_get_state(sdio_priv->pst_bus, HCC_BUS_STATE_RX));
        return EXT_ERR_SUCCESS;
    }

    oal_sdio_claim_host(sdio_priv->func);
    ret = sdio_extend_buf_get(sdio_priv);
    if (OAL_UNLIKELY(ret)) {
        oal_sdio_release_host(sdio_priv->func);
        oal_sdio_log(BUS_LOG_ERR, "sdio_extend_buf_get ret=%d", ret);
        return EXT_ERR_FAILURE;
    }
    oal_sdio_release_host(sdio_priv->func);
    ret = sdio_get_func1_int_status(sdio_priv, &int_mask);
    if (OAL_UNLIKELY(ret)) {
        return ret;
    }

    if (OAL_UNLIKELY((int_mask & HCC_SDIO_FUNC1_INT_MASK) == 0)) {
        oal_sdio_log(BUS_LOG_VERBOSE, "no sdio interrupt[0x%x]", int_mask);
        sdio_priv->func1_stat.func1_no_int_count++;
        return EXT_ERR_SUCCESS;
    }

    sdio_priv->sdio_int_count++;

    if ((int_mask & HCC_SDIO_FUNC1_INT_RERROR) != 0) {
        oal_sdio_log(BUS_LOG_ERR, "int_mask:%x", int_mask);
        sdio_priv->func1_stat.func1_err_int_count++;
    }

    /* message interrupt, flow control */
    if ((int_mask & HCC_SDIO_FUNC1_INT_MFARM) != 0) {
        sdio_priv->func1_stat.func1_msg_int_count++;
        if (sdio_msg_irq(sdio_priv) != EXT_ERR_SUCCESS) {
            return EXT_ERR_FAILURE;
        }
    }

    if ((int_mask & HCC_SDIO_FUNC1_INT_DREADY) != 0) {
        sdio_priv->func1_stat.func1_data_int_count++;
        return sdio_data_single_irq(sdio_priv);
    }

    return EXT_ERR_SUCCESS;
}

/* sdio interrupt routine */
static td_void sdio_isr(oal_sdio_func *func)
{
    struct oal_sdio *sdio_priv = TD_NULL;

    if (OAL_UNLIKELY(func == TD_NULL)) {
        oal_sdio_log(BUS_LOG_ERR, "sdio_func null");
        return;
    };

    sdio_priv = oal_sdio_get_drvdata(func);
    if (sdio_priv == TD_NULL) {
        oal_sdio_log(BUS_LOG_ERR, "%s", g_sdio_priv_log);
        return;
    }

    sdio_do_isr(sdio_priv);
}

#if defined(_PRE_OS_VERSION_LINUX) && defined(_PRE_OS_VERSION) && (_PRE_OS_VERSION_LINUX == _PRE_OS_VERSION)
static td_s32 hcc_rx_gpio_thread(osal_void *data)
{
    struct oal_sdio *sdio_priv = (struct oal_sdio *)data;

    allow_signal(SIGTERM);
    while (down_interruptible(&sdio_priv->rx_sema) == 0) {
        if (osal_kthread_should_stop() != 0) {
            oal_sdio_log(BUS_LOG_INFO, "hcc_rx_gpio_thread stop");
            break;
        }
        /* start to read GPIO interrupt */
        sdio_isr(sdio_priv->func);
    }
    oal_sdio_log(BUS_LOG_INFO, "hcc_rx_gpio_thread is terminated");
    return EXT_ERR_SUCCESS;
}

static td_s32 sdio_start_gpio_thread(struct oal_sdio *sdio_priv)
{
    sdio_priv->sdio_rx_task = osal_kthread_create(hcc_rx_gpio_thread, sdio_priv,
        HCC_SDIO_RX_ISR_NAME, HCC_SDIO_RX_ISR_SIZE);
    if (sdio_priv->sdio_rx_task == NULL) {
        return EXT_ERR_FAILURE;
    }
    osal_kthread_set_priority(sdio_priv->sdio_rx_task, HCC_SDIO_RX_ISR_PRIO);
    return EXT_ERR_SUCCESS;
}

static irqreturn_t sdio_gpio_isr(int irq, void *data)
{
    struct oal_sdio *sdio_priv = (struct oal_sdio *)data;
    if (sdio_priv == NULL) {
        return IRQ_HANDLED;
    }

    /* 唤醒RX线程 */
    up(&sdio_priv->rx_sema);

    return IRQ_HANDLED;
}

static td_s32 sdio_interrupt_register_gpio(struct oal_sdio *sdio_priv)
{
    int ret;
    td_u32 irq;

    /* 1. 主控自行配置GPIO复用(如有) */
#if defined(_PRE_PLATFORM_JZ) && defined(_PRE_OS_PLATFORM) && (_PRE_OS_PLATFORM == _PRE_PLATFORM_JZ)
    jz_gpio_set_func(HCC_SDIO_INT_GPIO_NUM, GPIO_INT_RE);
#endif
    /* 2. 配置GPIO为上升沿中断触发 */
    ret = gpio_request_one(HCC_SDIO_INT_GPIO_NUM, GPIOF_IN, HCC_SDIO_GPIO_DESC_LABEL);
    if (ret != 0) {
        goto gpio_request_one_fail;
    }

    irq = (td_u32)gpio_to_irq(HCC_SDIO_INT_GPIO_NUM);
    sdio_priv->gpio_irq = irq;
    sema_init(&sdio_priv->rx_sema, 0);

    ret = request_irq(irq, sdio_gpio_isr, IRQF_NO_SUSPEND | IRQF_TRIGGER_RISING, "sdio_gpio_irq", sdio_priv);
    if (ret < 0) {
        goto gpio_request_irq_fail;
    }

    disable_irq(irq);
    enable_irq(irq);
    return EXT_ERR_SUCCESS;

gpio_request_irq_fail:
    gpio_free(HCC_SDIO_INT_GPIO_NUM);
gpio_request_one_fail:
    return EXT_ERR_FAILURE;
}
#endif

static td_s32 sdio_interrupt_register_sdio(struct oal_sdio *sdio_priv)
{
    td_s32 ret;
    td_u8 reg;
#if defined(_PRE_OS_VERSION_LINUX) && defined(_PRE_OS_VERSION) && (_PRE_OS_VERSION_LINUX == _PRE_OS_VERSION)
    td_u32 mmc_card_quirks;
#endif
    oal_sdio_claim_host(sdio_priv->func);
    oal_sdio_log(BUS_LOG_DBG, "sdio_interrupt_register\r\n");
    /* use sdio bus line data1 for sdio data interrupt */
    ret = oal_sdio_request_irq(sdio_priv->func, sdio_isr);
    if (ret < 0) {
        oal_sdio_log(BUS_LOG_ERR, "sdio irq=%d", ret);
        oal_sdio_release_host(sdio_priv->func);
        return EXT_ERR_FAILURE;
    }

    reg = oal_sdio_func0_read_byte(sdio_priv->func, SDIO_CCCR_INTERRUPT_EXTENSION, &ret);
    if (ret != 0) {
        oal_sdio_log(BUS_LOG_ERR, "read CCCR fail=%d", ret);
        oal_sdio_release_host(sdio_priv->func);
        return ret;
    }
    reg |= 1 << 1;
#if defined(_PRE_OS_VERSION_LINUX) && defined(_PRE_OS_VERSION) && (_PRE_OS_VERSION_LINUX == _PRE_OS_VERSION)
    mmc_card_quirks = sdio_priv->func->card->quirks;
    /* LINUX use flag MMC_QUIRK_LENIENT_FN0 to check written when(addr < 0xF0 || addr > 0xFF) */
    sdio_priv->func->card->quirks |= MMC_QUIRK_LENIENT_FN0;
#endif
    oal_sdio_func0_write_byte(sdio_priv->func, reg, SDIO_CCCR_INTERRUPT_EXTENSION, &ret);
#if defined(_PRE_OS_VERSION_LINUX) && defined(_PRE_OS_VERSION) && (_PRE_OS_VERSION_LINUX == _PRE_OS_VERSION)
    sdio_priv->func->card->quirks = mmc_card_quirks;
#endif
    if (ret != 0) {
        oal_sdio_log(BUS_LOG_ERR, "write CCCR fail=%d", ret);
        oal_sdio_release_host(sdio_priv->func);
        return ret;
    }
    oal_sdio_release_host(sdio_priv->func);
#if defined(_PRE_OS_VERSION_LINUX) && defined(_PRE_OS_VERSION) && (_PRE_OS_VERSION_LINUX == _PRE_OS_VERSION)
    pm_runtime_get_sync(mmc_dev(sdio_priv->func->card->host));
#endif

    return EXT_ERR_SUCCESS;
}

static td_s32 sdio_interrupt_register(struct oal_sdio *sdio_priv)
{
    if (g_sdio_intr_status) {
        return EXT_ERR_SUCCESS;
    }
    if (g_sdio_intr_mode == INT_MODE_SDIO) {
        td_s32 ret = sdio_interrupt_register_sdio(sdio_priv);
        if (ret == EXT_ERR_SUCCESS) {
            g_sdio_intr_status = TD_TRUE;
        }
        return ret;
    }
#if defined(_PRE_OS_VERSION_LINUX) && defined(_PRE_OS_VERSION) && (_PRE_OS_VERSION_LINUX == _PRE_OS_VERSION)
    if (g_sdio_intr_mode == INT_MODE_GPIO) {
        if (sdio_interrupt_register_gpio(sdio_priv) != EXT_ERR_SUCCESS) {
            return EXT_ERR_FAILURE;
        }
        if (sdio_start_gpio_thread(sdio_priv) != EXT_ERR_SUCCESS) {
            sdio_interrupt_unregister(sdio_priv);
            return EXT_ERR_FAILURE;
        }
        g_sdio_intr_status = TD_TRUE;
        return EXT_ERR_SUCCESS;
    }
#endif
    oal_sdio_log(BUS_LOG_ERR, "unsupported int mode=%d", g_sdio_intr_mode);
    return EXT_ERR_FAILURE;
}

td_void sdio_interrupt_unregister(struct oal_sdio *sdio_priv)
{
    if (!g_sdio_intr_status) {
        return;
    }
    if (g_sdio_intr_mode == INT_MODE_SDIO) {
        oal_sdio_claim_host(sdio_priv->func);
        /* use sdio bus line data1 for sdio data interrupt */
        oal_sdio_release_irq(sdio_priv->func);
        oal_sdio_release_host(sdio_priv->func);
#if defined(_PRE_OS_VERSION_LINUX) && defined(_PRE_OS_VERSION) && (_PRE_OS_VERSION_LINUX == _PRE_OS_VERSION)
        pm_runtime_put_sync(mmc_dev(sdio_priv->func->card->host));
#endif
    }
#if defined(_PRE_OS_VERSION_LINUX) && defined(_PRE_OS_VERSION) && (_PRE_OS_VERSION_LINUX == _PRE_OS_VERSION)
    if (g_sdio_intr_mode == INT_MODE_GPIO) {
        disable_irq_nosync(sdio_priv->gpio_irq);
        free_irq(sdio_priv->gpio_irq, sdio_priv);
        gpio_free(HCC_SDIO_INT_GPIO_NUM);
        up(&sdio_priv->rx_sema);
        osal_kthread_destroy(sdio_priv->sdio_rx_task, OSAL_TRUE);
    }
#endif
    g_sdio_intr_status = TD_FALSE;
}

static td_s32 hcc_sdio_sleep_request(hcc_bus *pst_bus)
{
    int ret = EXT_ERR_SUCCESS;
    struct oal_sdio *sdio_priv = (struct oal_sdio *)pst_bus->data;
    if (OAL_WARN_ON(sdio_priv == TD_NULL)) {
        oal_sdio_log(BUS_LOG_ERR, "%s", g_sdio_priv_log);
        return EXT_ERR_FAILURE;
    }
    oal_sdio_claim_host(sdio_priv->func);
    oal_sdio_func0_write_byte(sdio_priv->func, ALLOW_TO_SLEEP_VALUE, HCC_SDIO_WAKEUP_DEV_REG, &ret);
    oal_sdio_release_host(sdio_priv->func);

    return ret;
}

static td_s32 sdio_wakeup_dev(struct oal_sdio *sdio_priv)
{
    td_s32 ret = EXT_ERR_SUCCESS;

    oal_sdio_claim_host(sdio_priv->func);
    oal_sdio_func0_write_byte(sdio_priv->func, DISALLOW_TO_SLEEP_VALUE, HCC_SDIO_WAKEUP_DEV_REG, &ret);
    oal_sdio_release_host(sdio_priv->func);

    return ret;
}

static td_s32 hcc_sdio_wakeup_request(hcc_bus *pst_bus)
{
    td_s32 ret = EXT_ERR_SUCCESS;
    struct oal_sdio *sdio_priv = (struct oal_sdio *)pst_bus->data;
    if (OAL_WARN_ON(sdio_priv == TD_NULL)) {
        oal_sdio_log(BUS_LOG_ERR, "sdio_priv");
        return EXT_ERR_FAILURE;
    }
    oal_sdio_claim_host(sdio_priv->func);
    oal_sdio_func0_write_byte(sdio_priv->func, DISALLOW_TO_SLEEP_VALUE, HCC_SDIO_WAKEUP_DEV_REG, &ret);
    oal_sdio_release_host(sdio_priv->func);
    return ret;
}

#ifdef CONFIG_HCC_SUPPORT_PATCH_OPT
static td_s32 sdio_patch_read_ver_info(oal_sdio_func *func, td_u8 *buf, td_u32 len)
{
    td_u8 *ver_info = TD_NULL;
    td_u8 *ver_info_origin = TD_NULL;
    td_s32 ret = 0;
    td_u32 xfer_count;
    td_s32 i;

    ret = oal_sdio_memcpy_fromio(func, &xfer_count, HCC_SDIO_REG_FUNC1_XFER_COUNT, sizeof(xfer_count), TD_FALSE);
    if (ret < 0) {
        oal_sdio_log(BUS_LOG_ERR, "read xfer_count err:%d", ret);
        return EXT_ERR_FAILURE;
    }

    if (xfer_count < len) {
        len = xfer_count;
    }

#if defined(_PRE_OS_VERSION_LINUX) && defined(_PRE_OS_VERSION) && (_PRE_OS_VERSION_LINUX == _PRE_OS_VERSION)
    ver_info = kzalloc((xfer_count + 1), OSAL_GFP_KERNEL);
#endif
#if defined(_PRE_OS_VERSION_LITEOS) && defined(_PRE_OS_VERSION) && (_PRE_OS_VERSION_LITEOS == _PRE_OS_VERSION)
    ver_info_origin = (td_u8 *)osal_kmalloc(OAL_ALIGN(xfer_count + 1, CACHE_ALIGNED_SIZE) + CACHE_ALIGNED_SIZE, 0);
    if (ver_info_origin == TD_NULL) {
        oal_sdio_log(BUS_LOG_ERR, "sdio_patch_readsb alloc %d failed", xfer_count + 1);
        return EXT_ERR_FAILURE;
    }
    ver_info = (td_u8 *)(((td_u32)ver_info_origin + CACHE_ALIGNED_SIZE - 1) / CACHE_ALIGNED_SIZE * CACHE_ALIGNED_SIZE);
#endif
    if (ver_info == TD_NULL) {
        oal_sdio_log(BUS_LOG_ERR, "sdio_patch_readsb alloc %d failed", xfer_count + 1);
        return EXT_ERR_FAILURE;
    }

    ret = oal_sdio_readsb(func, ver_info, HCC_SDIO_REG_FUNC1_FIFO, xfer_count, TD_FALSE);
    if (ret < 0) {
        oal_sdio_log(BUS_LOG_ERR, "readsb ret=%d", ret);
    } else {
        for (i = 0; i < len; i++) {
            buf[i] = ver_info[i];
        }
    }
#if defined(_PRE_OS_VERSION_LINUX) && defined(_PRE_OS_VERSION) && (_PRE_OS_VERSION_LINUX == _PRE_OS_VERSION)
    osal_kfree(ver_info);
#endif
#if defined(_PRE_OS_VERSION_LITEOS) && defined(_PRE_OS_VERSION) && (_PRE_OS_VERSION_LITEOS == _PRE_OS_VERSION)
    osal_kfree(ver_info_origin);
#endif
    return xfer_count;
}

static oal_sdio_func *sdio_patch_get_func(hcc_bus *sdio_bus, td_u8 *buff, td_u32 len)
{
    struct oal_sdio *sdio_priv;
    if (sdio_bus == TD_NULL || buff == TD_NULL || len == 0) {
        oal_sdio_log(BUS_LOG_ERR, "param err");
        return TD_NULL;
    }
    sdio_priv = (struct oal_sdio *)sdio_bus->data;

    if (sdio_priv == TD_NULL) {
        oal_sdio_log(BUS_LOG_ERR, "%s", g_sdio_priv_log);
        return TD_NULL;
    }
    return sdio_priv->func;
}

static td_bool hcc_sdio_patch_int_set(osal_atomic *atomic_in)
{
    td_s32 ret = osal_atomic_read(atomic_in);
    if (OAL_LIKELY(ret == 1)) {
        osal_atomic_set(atomic_in, 0);
    }
    return (td_bool)ret;
}

static td_s32 hcc_sdio_patch_read(hcc_bus *sdio_bus, td_u8 *buff, td_u32 len, td_u32 timeout)
{
    td_u8 int_mask;
    td_s32 ret = 0;
    unsigned long timeout_jiffies;
    oal_sdio_func *func;

    func = sdio_patch_get_func(sdio_bus, buff, len);
    if (func == TD_NULL) {
        oal_sdio_log(BUS_LOG_ERR, "func err");
        return EXT_ERR_FAILURE;
    }

    oal_sdio_claim_host(func);
    timeout_jiffies = OAL_TIME_JIFFY + msecs_to_jiffies(timeout);
    for (;;) {
        int_mask = oal_sdio_readb(func, HCC_SDIO_REG_FUNC1_INT_STATUS, &ret);
        if (ret) {
            oal_sdio_log(BUS_LOG_ERR, "read int mask ret=%d", ret);
            oal_sdio_release_host(func);
            return EXT_ERR_FAILURE;
        }

        if ((int_mask & HCC_SDIO_FUNC1_INT_MASK) || hcc_sdio_patch_int_set(&g_sdio_int_set)) {
            break;
        }
        if (time_after(OAL_TIME_JIFFY, timeout_jiffies)) {
            oal_sdio_log(BUS_LOG_ERR, "read int mask timeout, int_mask=%x", int_mask);
            oal_sdio_release_host(func);
            return EXT_ERR_FAILURE;
        }
#if defined(_PRE_OS_VERSION_LINUX) && defined(_PRE_OS_VERSION) && (_PRE_OS_VERSION_LINUX == _PRE_OS_VERSION)
        cpu_relax();
#endif
    }

    oal_sdio_writeb(func, int_mask, HCC_SDIO_REG_FUNC1_INT_STATUS, &ret);
    if (ret < 0) {
        oal_sdio_log(BUS_LOG_ERR, "clear int mask ret-%d", ret);
        oal_sdio_release_host(func);
        return EXT_ERR_FAILURE;
    }
    ret = sdio_patch_read_ver_info(func, buff, len);
    oal_sdio_release_host(func);
    return ret;
}

static td_s32 hcc_sdio_patch_write(hcc_bus *sdio_bus, td_u8 *buff, td_u32 len)
{
    td_s32 ret;
    oal_sdio_func *func;

    func = sdio_patch_get_func(sdio_bus, buff, len);
    if (func == TD_NULL) {
        oal_sdio_log(BUS_LOG_ERR, "func err");
        return EXT_ERR_FAILURE;
    }

    len = sdio_align_4_or_blk(len);
    oal_sdio_claim_host(func);
    ret = oal_sdio_writesb(func, HCC_SDIO_REG_FUNC1_FIFO, buff, len, TD_FALSE);
    if (ret < 0) {
        oal_sdio_log(BUS_LOG_ERR, "writesb ret=%d", ret);
    }
    oal_sdio_release_host(func);
    return ret;
}
#endif

static td_void sdio_dev_deinit(struct oal_sdio *sdio_priv)
{
    oal_sdio_func *func = TD_NULL;
    td_s32 ret = 0;

    if (OAL_UNLIKELY(sdio_priv == TD_NULL)) {
        oal_sdio_log(BUS_LOG_ERR, "%s", g_sdio_priv_log);
        return;
    };

    if (OAL_UNLIKELY(sdio_priv->func == TD_NULL)) {
        oal_sdio_log(BUS_LOG_ERR, "sdio_func null");
        return;
    };

    func = sdio_priv->func;

    oal_sdio_claim_host(func);
    oal_sdio_writeb(func, 0, HCC_SDIO_REG_FUNC1_INT_ENABLE, &ret);
    sdio_interrupt_unregister(sdio_priv);
    oal_sdio_disable_func(func);
    sdio_disable_state(sdio_priv->pst_bus, HCC_BUS_STATE_ALL);
    oal_sdio_release_host(func);

    oal_sdio_log(BUS_LOG_DBG, "sdio_dev_deinit! ");
}

static td_u32 sdio_rx_netbuf(struct oal_sdio *pst_sdio, hcc_data_queue *pst_head)
{
    td_s32 ret = EXT_ERR_SUCCESS;
    if (pst_sdio == TD_NULL) {
        oal_sdio_log(BUS_LOG_ERR, "pst_sdio is null");
        return EXT_ERR_FAILURE;
    };

    ret = sdio_build_rx_list(pst_sdio, pst_head);
    if (ret != EXT_ERR_SUCCESS) {
        return EXT_ERR_FAILURE;
    }

#ifdef PRE_SDIO_FEATURE_FLAT_MEMORY
    ret = sdio_transfer_flat_memory(pst_sdio, pst_head, SDIO_READ);
#endif
#ifdef PRE_SDIO_FEATURE_SCATTER
    ret = sdio_transfer_netbuf_list(pst_sdio, pst_head, SDIO_READ);
#endif
    if (OAL_UNLIKELY(ret != EXT_ERR_SUCCESS)) {
        oal_sdio_log(BUS_LOG_ERR, "Failed to read scatt sdio![scatt len:%d]", hcc_list_len(pst_head));
        hcc_list_free((hcc_handler *)(pst_sdio->pst_bus->hcc), pst_head);
        return EXT_ERR_FAILURE;
    }
#ifdef CONFIG_SDIO_DEBUG
    sdio_netbuf_list_hex_dump(pst_head);
#endif
    return EXT_ERR_SUCCESS;
}

static td_s32 hcc_sdio_send_ctrl_data(struct oal_sdio *sdio_priv, hcc_trans_queue *queue)
{
    td_s32 ret = EXT_ERR_SUCCESS;
    hcc_unc_struc *descr_buf = &sdio_priv->descript_unc;
    hcc_data_queue *send_head = &queue->send_head;
    hcc_bus *bus = sdio_priv->pst_bus;

    if (queue->queue_id == sdio_priv->current_queue && bus->force_update_queue_id == 0) {
        return ret;
    }
    sdio_priv->current_queue = queue->queue_id;
    *((td_u32 *)(descr_buf->buf)) = queue->queue_id;
    hcc_list_add_head(send_head, descr_buf);
#ifdef PRE_SDIO_FEATURE_FLAT_MEMORY
    ret = sdio_transfer_flat_memory(sdio_priv, send_head, SDIO_WRITE);
#endif

#ifdef PRE_SDIO_FEATURE_SCATTER
    ret = sdio_transfer_netbuf_list(sdio_priv, send_head, SDIO_WRITE);
#endif

    hcc_list_dequeue(send_head);
    return ret;
}

static td_s32 hcc_sdio_single_pkg_prepare(hcc_trans_queue *queue, td_u16 *total_send)
{
    /*
     * SDIO / USB不论是否聚合模式下都使用描述符；
     * IPC / PCIE 单包模式下不使用描述符；
     * 单包模式下：先将数据插入发送队列，如果需要描述符最后将描述符插入队列头；
     */
    hcc_unc_struc *unc_buf = hcc_list_dequeue(&queue->queue_info);
    if (unc_buf == TD_NULL) {
        oal_sdio_log(BUS_LOG_ERR, "unc_buf null");
        return EXT_ERR_FAILURE;
    }

    hcc_list_add_tail(&queue->send_head, unc_buf);
    /* SDIO单包模式下，若携带描述符，描述符中填0，表示当前为单包发送;
     * device根据上一次的描述符判断当前是单包模式或最后一个聚合包;
     * 在writestart中断中device就能够获取到总包长
     */
    *total_send = 1;
    return EXT_ERR_SUCCESS;
}

static td_s32 hcc_sdio_bus_assemble_pkg_prepare(sdio_host_assem_info *assemble_info,
    hcc_trans_queue *queue, td_u16 *total_send)
{
    hcc_data_queue *send_head = &queue->send_head;
    hcc_unc_struc *unc_buf = TD_NULL;
    /*
     * 聚合模式下：将数据插入发送队列，最后将描述符插入队列头; assembled_head存储下一次聚合的数据;
     * 如果 assembled_head 队列为空，则为第一包，第一包只发送一包数据;
     */
    if (hcc_is_list_empty(&assemble_info->assembled_head)) {
        unc_buf = hcc_list_dequeue(&queue->queue_info);
        if (unc_buf == TD_NULL) {
            oal_sdio_log(BUS_LOG_ERR, "unc_buf null");
            return EXT_ERR_FAILURE;
        }
        hcc_list_add_tail(send_head, unc_buf);
        *total_send = 1;
    } else {
        hcc_list_splice_init(&assemble_info->assembled_head, send_head);
        *total_send = (td_u16)(assemble_info->assemble_num);
    }

    return EXT_ERR_SUCCESS;
}

static td_void hcc_sdio_bus_build_next_assemble_descr(hcc_bus *bus, hcc_trans_queue *queue, td_u16 remain_pkt_nums)
{
    td_u32 i;
    hcc_unc_struc *unc_buf = TD_NULL;
    td_u32 len = ((struct oal_sdio *)bus->data)->descript_unc.length;
    td_u8 *buf = ((struct oal_sdio *)bus->data)->descript_unc.buf;
    sdio_host_assem_info *assem_info = &((struct oal_sdio *)bus->data)->tx_assemble_info;
    td_u16 assemble_max_count = (td_u16)osal_min((td_u32)bus->tx_sched_count, (td_u32)(bus->max_assemble_cnt));
    td_u16 current_trans_len = (td_u16)osal_min(assemble_max_count, remain_pkt_nums);

    assem_info->assemble_num = 0;
    for (i = 0; i < len && current_trans_len > 0;) {
        /* move the buf from head queue to prepare-send queue, head->tail */
        unc_buf = hcc_list_dequeue(&queue->queue_info);
        if (unc_buf == TD_NULL) {
            break;
        }

        current_trans_len--;
        hcc_list_add_tail(&assem_info->assembled_head, unc_buf);
        buf[i++] = (td_u8)(unc_buf->length >> bus->descr_align_bit);
        assem_info->assemble_num++;
    }

    if (i < len) {
        if (memset_s(&buf[i], (len - i), 0, (len - i)) != EOK) {
            hcc_printf_err_log("sdio asseble memset err\r\n");
        }
    }
}

static td_void hcc_sdio_reclaim_assemble(hcc_bus *bus, hcc_trans_queue *queue, td_u16 *remain_pkt_nums)
{
    hcc_handler *hcc = (hcc_handler *)(bus->hcc);
    struct oal_sdio *sdio_priv = (struct oal_sdio *)(bus->data);
    /* 当次发送失败，下次必先发控制包，切换队列，保证清除原始的聚合信息 */
    sdio_priv->current_queue = HCC_QUEUE_COUNT;
    /* assemble队列放回原队列 */
    hcc_list_restore(&queue->queue_info, &sdio_priv->tx_assemble_info.assembled_head);
    /* send队列插回原队列 */
    hcc_list_restore(&queue->queue_info, &queue->send_head);
    hcc_list_free(hcc, &queue->queue_info);
    *remain_pkt_nums = 0;
}

static td_u32 hcc_sdio_tx_proc(hcc_bus *bus, hcc_trans_queue *queue, td_u16 *remain_pkt_nums)
{
    td_s32 ret = EXT_ERR_FAILURE;
    td_u16 total_send = 0;
    td_u16 tmp_remain = 0;
    hcc_unc_struc *descr_buf;
    hcc_data_queue *send_head = &queue->send_head;
    hcc_handler *hcc = (hcc_handler *)(bus->hcc);
    if (hcc == TD_NULL || bus->data == TD_NULL) {
        return EXT_ERR_FAILURE;
    }
    if (OAL_UNLIKELY(hcc->hcc_state != HCC_ON)) {
        oal_sdio_log(BUS_LOG_ERR, "drop sdio netbuflist %u", hcc_list_len(send_head));
        goto reclaim_assemble;
    }
    descr_buf = &((struct oal_sdio *)bus->data)->descript_unc;

    /* step1:
     * SDIO-Host: 发送数据前先发送控制报文，传递队列信息给sdio
     */
    if (hcc_sdio_send_ctrl_data((struct oal_sdio *)bus->data, queue) != EXT_ERR_SUCCESS) {
        oal_sdio_log(BUS_LOG_ERR, "hcc_sdio_send_ctrl_data");
        goto reclaim_assemble;
    }

    /* step2:
     * SDIO-Host: 单包或聚合发送
     */
    if (queue->queue_ctrl->transfer_mode == HCC_SINGLE_MODE) {
        ret = hcc_sdio_single_pkg_prepare(queue, &total_send);
        *((td_u32 *)(descr_buf->buf)) = 0;
    } else if (queue->queue_ctrl->transfer_mode == HCC_ASSEMBLE_MODE) {
        ret = hcc_sdio_bus_assemble_pkg_prepare(&((struct oal_sdio *)bus->data)->tx_assemble_info, queue, &total_send);
        tmp_remain = (*remain_pkt_nums > total_send) ? (*remain_pkt_nums - total_send) : 0;
        hcc_sdio_bus_build_next_assemble_descr(bus, queue, tmp_remain);
    }

    if (ret != EXT_ERR_SUCCESS) {
        oal_sdio_log(BUS_LOG_ERR, "sdio_bus_tx mode:%d fail", queue->queue_ctrl->transfer_mode);
        goto reclaim_assemble;
    }

    /* step3:
     * SDIO-Host: 描述符包准备；
     * SDIO / USB不论是否聚合模式下都使用描述符；
     * IPC / PCIE 单包模式下不使用描述符；
     */
    hcc_list_add_head(send_head, descr_buf);

    /* step4:
     * SDIO-Host: 驱动发送
     */
#ifdef PRE_SDIO_FEATURE_FLAT_MEMORY
     ret = sdio_transfer_flat_memory((struct oal_sdio *)bus->data, send_head, SDIO_WRITE);
#endif

#ifdef PRE_SDIO_FEATURE_SCATTER
     ret = sdio_transfer_netbuf_list((struct oal_sdio *)bus->data, send_head, SDIO_WRITE);
#endif

    /* step5:
     * SDIO-Host: 携带描述符时先将描述符出列；
     *
     * step6:
     * 再对发送队列进行释放或恢复操作；
     */
    hcc_list_dequeue(send_head);
    if (ret == EXT_ERR_SUCCESS) {
        *remain_pkt_nums = (*remain_pkt_nums > total_send) ? (*remain_pkt_nums - total_send) : 0;
        /* 发送成功全部释放 */
        hcc_list_free(hcc, send_head);
    } else {
        goto reclaim_assemble;
    }

    return (td_u32)ret;

reclaim_assemble:
    hcc_sdio_reclaim_assemble(bus, queue, remain_pkt_nums);
    return (td_u32)ret;
}

static td_void sdio_probe_complete(struct oal_sdio *sdio_priv, hcc_bus *pst_bus)
{
    sdio_enable_state(sdio_priv->pst_bus, HCC_BUS_STATE_ALL);
#if defined(_PRE_OS_VERSION_LINUX) && defined(_PRE_OS_VERSION) && (_PRE_OS_VERSION_LINUX == _PRE_OS_VERSION)
    complete(&g_sdio_driver_complete);
#elif defined(_PRE_OS_VERSION_RTTHREAD) && defined(_PRE_OS_VERSION) && (_PRE_OS_VERSION_RTTHREAD == _PRE_OS_VERSION)
    oal_sdio_log(BUS_LOG_ERR, "sdio probe complete sem up !");
    osal_sem_up(&g_sdio_driver_complete);
#endif
    oal_sdio_log(BUS_LOG_DBG, "sdio probe over !");
}

static td_s32 sdio_res_init(td_void)
{
    struct oal_sdio *sdio_priv = TD_NULL;
    hcc_bus *pst_bus = TD_NULL;

    sdio_priv = sdio_init_module();
    if (sdio_priv == TD_NULL) {
        oal_sdio_log(BUS_LOG_ERR, "%s", g_sdio_priv_log);
        return EXT_ERR_FAILURE;
    }

    pst_bus = sdio_bus_init(sdio_priv);
    if (pst_bus == TD_NULL) {
        oal_sdio_log(BUS_LOG_ERR, "sdio_bus_init fail");
        sdio_exit_module(sdio_priv);
        return EXT_ERR_FAILURE;
    }
#if defined(_PRE_OS_VERSION_RTTHREAD) && defined(_PRE_OS_VERSION) && (_PRE_OS_VERSION_RTTHREAD == _PRE_OS_VERSION)
    osal_sem_init(&g_sdio_driver_complete, 0);
#endif
#if defined(_PRE_OS_VERSION_LINUX) && defined(_PRE_OS_VERSION) && (_PRE_OS_VERSION_LINUX == _PRE_OS_VERSION)
    g_sdio_read_fn0_txbuf = (char *)osal_kmalloc(SIZE_OF_SDIO_READ_TXBUF, 0);
    if (g_sdio_read_fn0_txbuf == TD_NULL) {
        oal_sdio_log(BUS_LOG_INFO, "osal_kmalloc failed");
        hcc_free_bus(pst_bus);
        sdio_exit_module(sdio_priv);
        return EXT_ERR_FAILURE;
    }
#endif

    return EXT_ERR_SUCCESS;
}

static td_s32 sdio_probe(oal_sdio_func *func, TD_CONST oal_sdio_device_id *ids)
{
    struct oal_sdio *sdio_priv = TD_NULL;
    td_s32 ret;
    hcc_bus *pst_bus = TD_NULL;

    if (OAL_WARN_ON((func == TD_NULL) || (ids == TD_NULL))) {
        oal_sdio_log(BUS_LOG_ERR, "param");
        return EXT_ERR_FAILURE;
    };

#if !(defined(_PRE_OS_VERSION_RTTHREAD) && defined(_PRE_OS_VERSION) && (_PRE_OS_VERSION_RTTHREAD == _PRE_OS_VERSION))
    oal_sdio_log(BUS_LOG_INFO, "sdio func[%d] match vid=0x%x pid=0x%x", oal_sdio_func_num(func),
        ids->vendor, ids->device);
#endif

    /* alloce sdio control struct */
    sdio_priv = g_sdio_handler;
    if (sdio_priv == TD_NULL) {
        oal_sdio_log(BUS_LOG_ERR, "%s", g_sdio_priv_log);
        return EXT_ERR_FAILURE;
    }
    sdio_priv->func = func;
    sdio_priv->pst_bus->cap_max_trans_size = sdio_func_max_req_size(sdio_priv);
    /* func keep a pointer to oal_sdio */
    oal_sdio_set_drvdata(func, sdio_priv);

    if (g_sdio_probe_status) {
        return EXT_ERR_SUCCESS;
    }
    if (sdio_dev_init(sdio_priv) != EXT_ERR_SUCCESS) {
        return EXT_ERR_FAILURE;
    }

    /* Print the sdio's cap */
    oal_sdio_log(BUS_LOG_INFO, "max_blk_size:%u,max_blk_count:%u,max_req_size:%u",
        oal_sdio_func_host_max_blk_size(func), oal_sdio_func_host_max_blk_num(func),
        oal_sdio_func_host_max_req_size(func));
    /* register interrupt process function */
    ret = sdio_interrupt_register(sdio_priv);
    if (ret < 0) {
        oal_sdio_log(BUS_LOG_ERR, "sdio_interrupt_register ERR");
        return EXT_ERR_FAILURE;
    }

    sdio_probe_complete(sdio_priv, pst_bus);
    g_sdio_probe_status = TD_TRUE;
    return EXT_ERR_SUCCESS;
}

#if defined(_PRE_OS_VERSION_RTTHREAD) && defined(_PRE_OS_VERSION) && (_PRE_OS_VERSION_RTTHREAD == _PRE_OS_VERSION)
static rt_int32_t oal_sdio_probe(struct rt_mmcsd_card *card)
{
    oal_sdio_device_id ids = {0};

    if (OAL_WARN_ON((card == TD_NULL) || (card->sdio_function[1] == TD_NULL))) {
        oal_sdio_log(BUS_LOG_ERR, "param");
        return EXT_ERR_FAILURE;
    };
    oal_sdio_log(BUS_LOG_INFO, "sdio func[%d] match vid=0x%x pid=0x%x", 1, card->cis.manufacturer, card->cis.product);
    return sdio_probe(card->sdio_function[1], &ids);
}
#endif

#ifdef CONFIG_SDIO_DEBUG
static td_void sdio_check_sg_format(struct scatterlist *sg, td_u32 sg_len)
{
    td_s32 i;
    struct scatterlist *sg_t = TD_NULL;
    for_each_sg(sg, sg_t, sg_len, i) {
        if (OAL_WARN_ON(((unsigned long)sg_virt(sg_t) & 0x03) || (sg_t->length & 0x03))) {
            oal_sdio_log(BUS_LOG_ERR, "check_sg_format:[i:%d][addr:%p][len:%u]", i, sg_virt(sg_t),
                sg_t->length);
        }
    }
}
#endif

#ifdef CONFIG_HCC_SUPPORT_REG_OPT
#if defined(_PRE_OS_VERSION_LINUX) && defined(_PRE_OS_VERSION) && (_PRE_OS_VERSION_LINUX == _PRE_OS_VERSION)
static td_s32 sdio_fn0_reg_fill(struct mmc_request *req, struct mmc_data *data, struct mmc_command *cmd,
    td_u32 reg_addr, td_u8 *buf, td_u16 buf_len, struct sg_table *sgtable, td_bool write_flag)
{
    struct scatterlist *sg;
    td_u32 addr = reg_addr;

    if (sg_alloc_table(sgtable, 1, OSAL_GFP_KERNEL) != 0) {
        oal_sdio_log(BUS_LOG_ERR, "sg_alloc_table");
        return EXT_ERR_FAILURE;
    }
    sg = sgtable->sgl;

    memset_s(sg, sizeof(struct scatterlist), 0, sizeof(struct scatterlist));
    sg_set_buf(&sg[0], buf, SIZE_OF_SDIO_READ_TXBUF);
    sg_mark_end(&sg[0]);
    addr = addr & 0xFFFC;

    req->cmd = cmd;
    req->data = data;
    cmd->opcode = SD_IO_RW_EXTENDED;
    if (write_flag) {
        cmd->arg = SDIO_W_ARG;
    } else {
        cmd->arg = SDIO_R_ARG;
    }
    cmd->arg |= addr << SDIO_CMD_ADDR_OFFSET;
    cmd->flags = SDIO_RW_FLAGS;
    data->blksz = SDIO_RW_BLKSZ;
    data->blocks = SDIO_RW_BLOCKS;
    data->sg = sg;
    data->sg_len = 1;
    if (write_flag) {
        data->flags = MMC_DATA_WRITE;
    } else {
        data->flags = MMC_DATA_READ;
    }
    return EXT_ERR_SUCCESS;
}

static td_s32 hcc_sdio_write_fn0_reg(td_u32 reg_addr, td_u32 val)
{
    hcc_bus *pst_bus = sdio_get_bus_handler();
    if (pst_bus == TD_NULL) {
        return EXT_ERR_FAILURE;
    }
    struct oal_sdio *sdio_priv = (struct oal_sdio *)pst_bus->data;
    struct sg_table sgtable = {0};
    struct mmc_request mrq = {0};
    struct mmc_command cmd = {0};
    struct mmc_data data = {0};
    struct mmc_card *card = TD_NULL;
    td_u32 txbuf_offset = 0;
    errno_t mem_res;
    td_u8 *txbuf = TD_NULL;

    if (sdio_priv == TD_NULL) {
        return EXT_ERR_FAILURE;
    }
    txbuf = kmalloc(SIZE_OF_SDIO_READ_TXBUF, OSAL_GFP_KERNEL);
    if (txbuf == TD_NULL) {
        return EXT_ERR_FAILURE;
    }
    mem_res = memset_s(txbuf, SIZE_OF_SDIO_READ_TXBUF, 0, SIZE_OF_SDIO_READ_TXBUF);
    if (mem_res != EOK) {
        kfree(txbuf);
        return EXT_ERR_FAILURE;
    }

    oal_sdio_claim_host(sdio_priv->func);
    txbuf[txbuf_offset++] = (td_u8)((val >> 0) & 0xff);
    txbuf[txbuf_offset++] = (td_u8)((val >> BYTE_OFFSET1_IN_WORD) & 0xff);
    txbuf[txbuf_offset++] = (td_u8)((val >> BYTE_OFFSET2_IN_WORD) & 0xff);
    txbuf[txbuf_offset++] = (td_u8)((val >> BYTE_OFFSET3_IN_WORD) & 0xff);

    if (sdio_fn0_reg_fill(&mrq, &data, &cmd, reg_addr, txbuf, SIZE_OF_SDIO_READ_TXBUF, &sgtable,
        TD_TRUE) != EXT_ERR_SUCCESS) {
        oal_sdio_release_host(sdio_priv->func);
        kfree(txbuf);
        return EXT_ERR_FAILURE;
    }

    card = sdio_priv->func->card;
    mmc_set_data_timeout(&data, card);
    mmc_wait_for_req(card->host, &mrq);
    sg_free_table(&sgtable);
    oal_sdio_release_host(sdio_priv->func);
    kfree(txbuf);
    if ((cmd.error != 0) || (data.error != 0)) {
        return EXT_ERR_FAILURE;
    } else {
        return EXT_ERR_SUCCESS;
    }
}

static td_s32 hcc_sdio_read_fn0_reg(td_u32 reg_addr, td_u32 *val)
{
    hcc_bus *pst_bus = sdio_get_bus_handler();
    if (pst_bus == TD_NULL) {
        return EXT_ERR_FAILURE;
    }
    struct oal_sdio *sdio_priv = (struct oal_sdio *)pst_bus->data;
    struct sg_table sgtable = {0};
    struct mmc_request mrq = {0};
    struct mmc_command cmd = {0};
    struct mmc_data data = {0};
    struct mmc_card *card = TD_NULL;
    td_u32 reg_addr_org = reg_addr;

    if (sdio_priv == TD_NULL || val == TD_NULL || g_sdio_read_fn0_txbuf == TD_NULL) {
        return EXT_ERR_FAILURE;
    }
    oal_sdio_claim_host(sdio_priv->func);
    memset_s(g_sdio_read_fn0_txbuf, SIZE_OF_SDIO_READ_TXBUF, 0, SIZE_OF_SDIO_READ_TXBUF);
    if (sdio_fn0_reg_fill(&mrq, &data, &cmd, reg_addr, g_sdio_read_fn0_txbuf, SIZE_OF_SDIO_READ_TXBUF,
        &sgtable, TD_FALSE) != EXT_ERR_SUCCESS) {
        oal_sdio_release_host(sdio_priv->func);
        return EXT_ERR_FAILURE;
    }

    card = sdio_priv->func->card;
    mmc_set_data_timeout(&data, card);
    mmc_wait_for_req(card->host, &mrq);
    if (cmd.error != 0) {
        oal_sdio_log(BUS_LOG_ERR, "addr:0x%08x cmd.err:%d.\n", reg_addr_org, cmd.error);
        oal_sdio_release_host(sdio_priv->func);
        return EXT_ERR_FAILURE;
    }
    if (data.error != 0) {
        oal_sdio_log(BUS_LOG_ERR, "addr:0x%08x data.err:%d.\n", reg_addr_org, data.error);
        oal_sdio_release_host(sdio_priv->func);
        return EXT_ERR_FAILURE;
    }
    *val = *(td_u32 *)g_sdio_read_fn0_txbuf;
    sg_free_table(&sgtable);
    oal_sdio_release_host(sdio_priv->func);

    return EXT_ERR_SUCCESS;
}
#endif
#endif

#if defined(_PRE_OS_VERSION_LITEOS) && defined(_PRE_OS_VERSION) && (_PRE_OS_VERSION_LITEOS == _PRE_OS_VERSION)
#ifdef CONFIG_HCC_SUPPORT_REG_OPT
int sdio_io_rw_reg(td_u32 reg_addr, struct sdio_softc *sc, bool wr, uint8_t *buffer)
{
    device_t mmcbus = sc->mmcbus;
    device_t child = sc->dev;
    int err;
    struct mmc_data data;
    struct mmc_command cmd = {0};
    struct mmc_request req = {0};

    reg_addr = reg_addr & 0xFFFC;
    req.cmd = &cmd;
    cmd.data = &data;
    cmd.opcode = SD_IO_RW_EXTENDED;
    cmd.flags = SDIO_RW_FLAGS;
    if (wr) {
        cmd.arg = SDIO_W_ARG;
    } else {
        cmd.arg = SDIO_R_ARG;
    }
    cmd.arg |= reg_addr << SDIO_CMD_ADDR_OFFSET;
    data.blk_num = SDIO_RW_BLOCKS;
    data.blk_size = SDIO_RW_BLKSZ;
    data.len = SDIO_RW_BLOCKS * SDIO_RW_BLKSZ;
    if (wr)
        data.flags = MMC_DATA_WRITE;
    else
        data.flags = MMC_DATA_READ;
    data.data = buffer;
    MMCBUS_ACQUIRE_BUS(mmcbus, child);
    err = MMCBUS_WAIT_FOR_REQUEST(mmcbus, child, &req);
    MMCBUS_RELEASE_BUS(mmcbus, child);
    if (err != 0)
        return (-EIO);
    if (cmd.error != MMC_ERR_NONE) {
        return (cmd.error);
    }
    if (cmd.resp[0] & R5_RESP_CHECK)
        return (-EPERM);
    return (0);
}

td_s32 hcc_sdio_write_fn0_reg(td_u32 reg_addr, td_u32 val)
{
    hcc_bus *pst_bus = sdio_get_bus_handler();
    if (pst_bus == TD_NULL) {
        return EXT_ERR_FAILURE;
    }
    struct oal_sdio *sdio_priv = (struct oal_sdio *)pst_bus->data;
    td_u32 txbuf_offset = 0;
    td_u8 txbuf[SIZE_OF_SDIO_READ_TXBUF];
    if (sdio_priv == TD_NULL) {
        return EXT_ERR_FAILURE;
    }
    txbuf[txbuf_offset++] = (char)((val >> 0) & 0xff);
    txbuf[txbuf_offset++] = (char)((val >> BYTE_OFFSET1_IN_WORD) & 0xff);
    txbuf[txbuf_offset++] = (char)((val >> BYTE_OFFSET2_IN_WORD) & 0xff);
    txbuf[txbuf_offset++] = (char)((val >> BYTE_OFFSET3_IN_WORD) & 0xff);
    return sdio_io_rw_reg(reg_addr, sdio_priv->func->sc, 1, txbuf);
}

td_s32 hcc_sdio_read_fn0_reg(td_u32 reg_addr, td_u32 *val)
{
    hcc_bus *pst_bus = sdio_get_bus_handler();
    if (pst_bus == TD_NULL) {
        return EXT_ERR_FAILURE;
    }
    struct oal_sdio *sdio_priv = (struct oal_sdio *)pst_bus->data;
    if (sdio_priv == TD_NULL) {
        return EXT_ERR_FAILURE;
    }
    return sdio_io_rw_reg(reg_addr, sdio_priv->func->sc, 0, (td_u8 *)val);
}
#endif
#endif

#ifdef PRE_SDIO_FEATURE_FLAT_MEMORY
#define SDIO_FLAT_MEMORY_BUFFLEN_ALIGN 4
static td_s32 sdio_transfer_cal_size(struct oal_sdio *sdio_priv, hcc_data_queue *head, td_s32 rw, td_u32 *buf_len)
{
    td_u32 sum_len = 0;
    hcc_unc_struc *unc_buf = TD_NULL;
    hcc_unc_struc *tmp = TD_NULL;

    osal_list_for_each_entry_safe(unc_buf, tmp, (&head->data_queue), list) {
        if (rw == SDIO_WRITE) {
#if defined(_PRE_FEATURE_WS53_DEVICE_MODE) || defined(_PRE_FEATURE_SYSCHANNEL_LITEOS)
            if (memcpy_s((void *)((td_u32)(sdio_priv->tx_scatt_buff.buff) + sum_len), unc_buf->length, unc_buf->buf,
                unc_buf->length) != EOK) {
                oal_sdio_log(BUS_LOG_ERR, "sdio_transfer_cal_size cpy fail");
            }
#else
        if (memcpy_s(sdio_priv->tx_scatt_buff.buff + sum_len,
            sdio_priv->tx_scatt_buff.len - sum_len, unc_buf->buf, unc_buf->length) != EOK) {
            oal_sdio_log(BUS_LOG_ERR, "sdio_transfer_cal_size cpy fail");
        }
#endif
        }
        sum_len += unc_buf->length;
    }

    sum_len = sdio_align_4_or_blk(sum_len);
    *buf_len = sum_len;
    return EXT_ERR_SUCCESS;
}

static td_s32 sdio_transfer_copy(struct oal_sdio *sdio_priv, hcc_data_queue *head, td_u8* buf, td_u32 len)
{
    td_u32 sum_len = 0;
    hcc_unc_struc *unc_buf = TD_NULL;
    hcc_unc_struc *tmp = TD_NULL;

    osal_list_for_each_entry_safe(unc_buf, tmp, (&head->data_queue), list) {
        td_s32 err = memcpy_s(unc_buf->buf, unc_buf->length, buf + sum_len, unc_buf->length);
        if (err != EOK) {
            return EXT_ERR_FAILURE;
        }
        sum_len += unc_buf->length;
        len -= unc_buf->length;
        if (len  <= 0) {
            break;
        }
    }
    return EXT_ERR_SUCCESS;
}

static td_s32 sdio_transfer_flat_memory(struct oal_sdio *sdio_priv, hcc_data_queue *head, td_s32 rw)
{
    td_s32 ret;
    td_u32 buf_len = 0;
    ret = sdio_transfer_cal_size(sdio_priv, head, rw, &buf_len);
    if (ret != EXT_ERR_SUCCESS) {
        return ret;
    }

    // write or read
    oal_sdio_claim_host(sdio_priv->func);
    if (rw == SDIO_WRITE) {
        ret = oal_sdio_writesb(sdio_priv->func, HCC_SDIO_REG_FUNC1_FIFO,
            sdio_priv->tx_scatt_buff.buff, buf_len, TD_TRUE);
    } else {
        ret = oal_sdio_readsb(sdio_priv->func, sdio_priv->rx_scatt_buff.buff,
            HCC_SDIO_REG_FUNC1_FIFO, buf_len, TD_TRUE);
    }
    oal_sdio_release_host(sdio_priv->func);
    if (ret != EXT_ERR_SUCCESS) {
        return ret;
    }
    if (rw == SDIO_READ) {
        ret = sdio_transfer_copy(sdio_priv, head, sdio_priv->rx_scatt_buff.buff, buf_len);
    }
    return ret;
}
#endif

#ifdef PRE_SDIO_FEATURE_SCATTER
#if defined(_PRE_OS_VERSION_LINUX) && defined(_PRE_OS_VERSION) && (_PRE_OS_VERSION_LINUX == _PRE_OS_VERSION)
static td_s32 sdio_drv_err_return(struct mmc_data *data, struct mmc_command *cmd)
{
    if (cmd->error != 0) {
        return cmd->error;
    }
    if (data->error != 0) {
        return data->error;
    }

    if ((cmd->resp[0] & R5_ERROR) != 0) {
        return -EIO;
    }
    if ((cmd->resp[0] & R5_FUNCTION_NUMBER) != 0) {
        return -EINVAL;
    }
    if ((cmd->resp[0] & R5_OUT_OF_RANGE) != 0) {
        return -ERANGE;
    }
    return EXT_ERR_SUCCESS;
}

static td_s32 sdio_mmc_io_rw_scat_extended(struct oal_sdio *sdio_priv, td_s32 write_flag, td_u32 fn, td_u32 addr,
    td_s32 incr_addr, struct scatterlist *sg, td_u32 sg_len, td_u32 block_cnt, td_u32 blk_size)
{
    struct mmc_request mrq = {0};
    struct mmc_command cmd = {0};
    struct mmc_data data = {0};
    struct mmc_card *card = TD_NULL;

    if (OAL_UNLIKELY(sdio_priv == TD_NULL)) {
        oal_sdio_log(BUS_LOG_ERR, "%s", g_sdio_priv_log);
        return EXT_ERR_FAILURE;
    }
    if (OAL_UNLIKELY((sg == TD_NULL) || (sg_len == 0) || (blk_size == 0))) {
        oal_sdio_log(BUS_LOG_ERR, "sg_len=%d, blk_size=%d", sg_len, blk_size);
        return EXT_ERR_FAILURE;
    }
    if (OAL_UNLIKELY((addr & ~0x1FFFF) || (fn > SDIO_FUNC_MAX))) {
        oal_sdio_log(BUS_LOG_ERR, "fn is %d", fn);
        return EXT_ERR_FAILURE;
    }
    card = sdio_priv->func->card;

    /* sg format */
#ifdef CONFIG_SDIO_DEBUG
    sdio_check_sg_format(sg, sg_len);
#endif

    mrq.cmd = &cmd;
    mrq.data = &data;

    cmd.opcode = SD_IO_RW_EXTENDED;
    cmd.arg = (write_flag != 0) ? 0x80000000 : 0x00000000;
    cmd.arg |= fn << SDIO_CMD_FUNC_OFFSET;
    cmd.arg |= addr << SDIO_CMD_ADDR_OFFSET;
    if (block_cnt == 1 && blk_size <= HCC_SDIO_BLOCK_SIZE) {
        cmd.arg |= (blk_size == HCC_SDIO_BLOCK_SIZE) ? 0 : blk_size;
    } else {
        cmd.arg |= 0x08000000 | block_cnt;
    }
    cmd.flags = MMC_RSP_SPI_R5 | MMC_RSP_R5 | MMC_CMD_ADTC;

    data.blksz = blk_size;
    data.blocks = block_cnt;
    data.flags = (write_flag != 0) ? MMC_DATA_WRITE : MMC_DATA_READ;
    data.sg = sg;
    data.sg_len = sg_len;

    mmc_set_data_timeout(&data, card);
    mmc_wait_for_req(card->host, &mrq);
    return sdio_drv_err_return(&data, &cmd);
}

static td_s32 sdio_dev_transfer_scatt(struct oal_sdio *sdio_priv, td_s32 rw, td_u32 addr,
    struct scatterlist *sg, td_u32 sg_len, td_u32 rw_sz)
{
#ifdef CONFIG_SDIO_TIME_DEBUG
    ktime_t time_start = ktime_get();
#endif
    td_s32 ret;
    td_s32 write = (rw == SDIO_READ) ? 0 : 1;
    oal_sdio_func *func = sdio_priv->func;
    oal_sdio_claim_host(func);
    /* continue only when tx/rx all opened! */
    if (OAL_UNLIKELY(sdio_get_state(sdio_priv->pst_bus, HCC_BUS_STATE_ALL) != TD_TRUE)) {
        if (printk_ratelimit() != 0) {
            oal_sdio_log(BUS_LOG_INFO, "sdio closed,state:%u, %s ignored",
                sdio_get_state(sdio_priv->pst_bus, HCC_BUS_STATE_ALL), (write == 1) ? "write" : "read");
        }
        schedule();
        oal_sdio_release_host(func);
        return EXT_ERR_FAILURE;
    }
    ret = sdio_mmc_io_rw_scat_extended(sdio_priv, write, sdio_priv->func->num, addr, 0, sg, sg_len,
        ((rw_sz / HCC_SDIO_BLOCK_SIZE) != 0) ? (rw_sz / HCC_SDIO_BLOCK_SIZE) : 1,
        (td_u32)(min(rw_sz, (td_u32)HCC_SDIO_BLOCK_SIZE)));
    if (OAL_UNLIKELY(ret)) {
#ifdef CONFIG_SDIO_TIME_DEBUG
        /* If sdio transfer failed, dump the sdio info */
        oal_uint64 trans_us;
        ktime_t time_stop = ktime_get();
        trans_us = (oal_uint64)ktime_to_us(ktime_sub(time_stop, time_start));
        oal_sdio_log(BUS_LOG_ERR,
            "sdio_dev_transfer_scatt fail=%d, time cost:%llu us,[addr:%u, sg_len:%u,rw_sz:%u]",
            ret, trans_us, addr, sg_len, rw_sz);
#endif
    }
    oal_sdio_release_host(func);
    return ret;
}
#endif

#if defined(_PRE_OS_VERSION_LITEOS) && defined(_PRE_OS_VERSION) && (_PRE_OS_VERSION_LITEOS == _PRE_OS_VERSION)
static td_s32 sdio_dev_transfer_scatt(struct oal_sdio *sdio_priv, td_s32 rw, td_u32 addr,
    struct scatterlist *sg, td_u32 sg_len, td_u32 rw_sz)
{
    struct mmc_request mrq = {0};
    struct mmc_cmd cmd = {0};
    struct mmc_data data = {0};
    struct mmc_card *card = TD_NULL;
    td_s32 write_flag = (rw == SDIO_READ) ? 0 : 1;
    td_u32 block_cnt = (rw_sz / HCC_SDIO_BLOCK_SIZE) ? : 1;
    td_u32 blk_sz = osal_min(rw_sz, (td_u32)HCC_SDIO_BLOCK_SIZE);

    if ((sdio_priv == TD_NULL) || (sg == TD_NULL) || (sg_len == 0)) {
        return EXT_ERR_FAILURE;
    }

    if ((blk_sz == 0) || sdio_priv->func == TD_NULL || sdio_priv->func->card == TD_NULL) {
        return EXT_ERR_FAILURE;
    }
    oal_sdio_claim_host(sdio_priv->func);

#ifdef CONFIG_SDIO_DEBUG
    sdio_check_sg_format(sg, sg_len);
#endif
    card = sdio_priv->func->card;

    mrq.cmd = &cmd;
    mrq.data = &data;

    cmd.cmd_code = SDIO_RW_EXTENDED;
    cmd.arg = write_flag ? 0x80000000 : 0x00000000;
    cmd.arg |= sdio_priv->func->func_num << SDIO_CMD_FUNC_OFFSET;
    cmd.arg |= addr << SDIO_CMD_ADDR_OFFSET;
    if (block_cnt == 1 && blk_sz <= HCC_SDIO_BLOCK_SIZE) {
        cmd.arg |= (blk_sz == HCC_SDIO_BLOCK_SIZE) ? 0 : blk_sz;
    } else {
        cmd.arg |= 0x08000000 | block_cnt;
    }
    cmd.resp_type = MMC_RESP_SPI_R5 | MMC_RESP_R5 | MMC_CMD_ADTC;

    data.blocksz = blk_sz;
    data.blocks = block_cnt;
    data.data_flags = write_flag ? MMC_DATA_WRITE : MMC_DATA_READ;
    data.sg = sg;
    data.sg_len = sg_len;

    mmc_set_data_timeout(&data, card);
    mmc_wait_for_req(card->host, &mrq);
    oal_sdio_release_host(sdio_priv->func);

    return sdio_drv_err_return(&cmd, &data);
}
#endif

/* sdio scatter data transfer */
static td_s32 sdio_transfer_scatt(struct oal_sdio *sdio_priv, td_s32 rw, td_u32 addr, struct scatterlist *sg,
    td_u32 sg_len, td_u32 sg_max_len, td_u32 rw_sz)
{
    td_u32 align_len = 0;
    td_u32 align_t = 0;
    td_u32 sg_len_cal = sg_len;
    td_u32 local_rw_sz = rw_sz;
    if (!sdio_priv) {
        oal_sdio_log(BUS_LOG_ERR, "%s", g_sdio_priv_log);
        return EXT_ERR_FAILURE;
    }
    if ((local_rw_sz == 0) || (sg_max_len < sg_len_cal) || (sg_len_cal == 0)) {
        oal_sdio_log(BUS_LOG_ERR, "sg_max_len:%u, sg_len:%u, local_rw_sz:%u", sg_max_len, sg_len_cal, local_rw_sz);
        return EXT_ERR_FAILURE;
    }

    align_t = sdio_align_4_or_blk(local_rw_sz);
    align_len = align_t - local_rw_sz;

    if (align_len != 0) {
        if (sg_len_cal + 1 > sg_max_len) {
            oal_sdio_log(BUS_LOG_ERR, "sg list over,sg_len:%u, sg_max_len:%u", sg_len_cal, sg_max_len);
            return EXT_ERR_FAILURE;
        }
        sg_set_buf(&sg[sg_len_cal], sdio_priv->sdio_align_buff, align_len);
        sg_len_cal++;
    }
    sg_mark_end(&sg[sg_len_cal - 1]);

    local_rw_sz = align_t;
    /* sdio scatter list driver ,when letter than 512 bytes bytes mode, other blockmode */
    OAL_WARN_ON((local_rw_sz >= HCC_SDIO_BLOCK_SIZE) && (local_rw_sz & (HCC_SDIO_BLOCK_SIZE - 1)));
    OAL_WARN_ON((local_rw_sz < HCC_SDIO_BLOCK_SIZE) && (local_rw_sz & (4 - 1))); // 4 确保长度大于4
    if (OAL_WARN_ON(align_len & 0x3)) {
        oal_sdio_log(BUS_LOG_ERR, "error:not 4 bytes align:%u", align_len);
    }

    return sdio_dev_transfer_scatt(sdio_priv, rw, addr, sg, sg_len_cal, local_rw_sz);
}

#define SDIO_BUF_ALIGNED_NUM 4
static td_s32 sdio_transfer_rebuild_sglist(struct oal_sdio *sdio_priv, const hcc_data_queue *head,
    struct scatterlist *sg, td_u32 sg_max_len, td_u32 *total_len, td_u32 *sg_len, td_s32 rw)
{
    td_u32 idx = 0;
    td_u32 sum_len = 0;
    hcc_unc_struc *netbuf = TD_NULL;
    hcc_unc_struc *tmp = TD_NULL;

    memset_s(sg, sizeof(struct scatterlist) * sg_max_len, 0, sizeof(struct scatterlist) * sg_max_len);
    osal_list_for_each_entry_safe(netbuf, tmp, (&head->data_queue), list) {
        if (!OAL_IS_ALIGNED((uintptr_t)(netbuf->buf), SDIO_BUF_ALIGNED_NUM)) {
            hcc_printf_err_log("address[%p] not aligned to [%d]\r\n", netbuf->buf, SDIO_BUF_ALIGNED_NUM);
            return EXT_ERR_FAILURE;
        }

        if (!OAL_IS_ALIGNED(netbuf->length, HCC_SDIO_H2D_SCATT_BUFFLEN_ALIGN)) {
            hcc_printf_err_log("length[%d] not aligned to [%d]\r\n", netbuf->length, HCC_SDIO_H2D_SCATT_BUFFLEN_ALIGN);
            return EXT_ERR_FAILURE;
        }
        sg_set_buf(&sg[idx], netbuf->buf, netbuf->length);
        sum_len += netbuf->length;
        idx++;
    }

    *sg_len = idx;
    *total_len = sum_len;

    return EXT_ERR_SUCCESS;
}

static td_s32 sdio_transfer_netbuf_list(struct oal_sdio *sdio_priv, hcc_data_queue *head, td_s32 rw)
{
    td_u8 sg_realloc = 0;
    td_s32 ret = EXT_ERR_SUCCESS;
    td_u32 sg_len = 0;
    td_u32 queue_len;
    td_u32 sum_len = 0;
    td_u32 request_sg_len;
    struct scatterlist *sg;
    struct sg_table sgtable;
    if (OAL_WARN_ON(!sdio_priv)) {
        oal_sdio_log(BUS_LOG_ERR, "%s", g_sdio_priv_log);
        return EXT_ERR_FAILURE;
    }
    if (OAL_WARN_ON((rw >= SDIO_OPT_BUTT) || (hcc_is_list_empty(head)))) {
        oal_sdio_log(BUS_LOG_ERR, "invaild rw:%d", rw);
        return EXT_ERR_FAILURE;
    }

    queue_len = hcc_list_len(head);
    /* must realloc the sg list mem, alloc more sg for the align buff */
    request_sg_len = queue_len + 1;
    if (OAL_UNLIKELY(request_sg_len > sdio_priv->scatt_info[rw].max_scatt_num)) {
        oal_sdio_log(BUS_LOG_WARN, "request:%d,max scatt num:%d",
            request_sg_len, sdio_priv->scatt_info[rw].max_scatt_num);
        /* must realloc the sg list mem, alloc more sgs for the align buff */
        if (sg_alloc_table(&sgtable, request_sg_len, OSAL_GFP_KERNEL) != 0) {
            oal_sdio_log(BUS_LOG_ERR, "alloc sg failed!");
            return EXT_ERR_FAILURE;
        }
        sg_realloc = 1;
        sg = sgtable.sgl;
    } else {
        sg = sdio_priv->scatt_info[rw].sglist;
    }

    /* merge sg list */
    ret = sdio_transfer_rebuild_sglist(sdio_priv, head, sg, request_sg_len, &sum_len, &sg_len, rw);
    if (OAL_UNLIKELY(ret != EXT_ERR_SUCCESS)) {
        if (sg_realloc != 0) {
            sg_free_table(&sgtable);
        }
        return EXT_ERR_FAILURE;
    }

    ret = sdio_transfer_scatt(sdio_priv, rw, HCC_SDIO_REG_FUNC1_FIFO, sg, sg_len, request_sg_len, sum_len);
    if (sg_realloc != 0) {
        sg_free_table(&sgtable);
    }

    return ret;
}
#endif

static td_void sdio_res_deinit(struct oal_sdio *sdio_priv)
{
    if (OAL_UNLIKELY(sdio_priv == TD_NULL)) {
        oal_sdio_log(BUS_LOG_ERR, "%s", g_sdio_priv_log);
        return;
    };

    sdio_bus_exit(sdio_priv);
    sdio_exit_module(sdio_priv);
#if defined(_PRE_OS_VERSION_RTTHREAD) && defined(_PRE_OS_VERSION) && (_PRE_OS_VERSION_RTTHREAD == _PRE_OS_VERSION)
    osal_sem_destroy(&g_sdio_driver_complete);
#endif
#if defined(_PRE_OS_VERSION_LINUX) && defined(_PRE_OS_VERSION) && (_PRE_OS_VERSION_LINUX == _PRE_OS_VERSION)
    if (g_sdio_read_fn0_txbuf != TD_NULL) {
        osal_kfree(g_sdio_read_fn0_txbuf);
        g_sdio_read_fn0_txbuf = TD_NULL;
    }
#endif
}

static td_void sdio_remove(oal_sdio_func *func)
{
    struct oal_sdio *sdio_priv = TD_NULL;

    if (OAL_WARN_ON(func == TD_NULL)) {
        oal_sdio_log(BUS_LOG_ERR, "sdio_func null");
        return;
    };
    if (!g_sdio_remove_enable) {
        return;
    }

    sdio_priv = (struct oal_sdio *)oal_sdio_get_drvdata(func);
    if (sdio_priv == TD_NULL) {
        oal_sdio_log(BUS_LOG_ERR, "%s", g_sdio_priv_log);
        return;
    }

    sdio_dev_deinit(sdio_priv);
    oal_sdio_set_drvdata(func, TD_NULL);
    g_sdio_remove_enable = TD_FALSE;
    oal_sdio_log(BUS_LOG_INFO, "sdio_remove...");
}

#if defined(_PRE_OS_VERSION_RTTHREAD) && defined(_PRE_OS_VERSION) && (_PRE_OS_VERSION_RTTHREAD == _PRE_OS_VERSION)
rt_int32_t oal_sdio_remove(struct rt_mmcsd_card *card)
{
    if (OAL_UNLIKELY(card == TD_NULL)) {
        oal_sdio_log(BUS_LOG_ERR, "sdio_card null");
        return 0;
    }
    sdio_remove(card->sdio_function[1]);
    return 0;
}
#endif

static td_s32 hcc_sdio_pm_notify_register(hcc_bus *pst_bus, bus_pm_notify suspend_func, bus_pm_notify resume_func)
{
    struct oal_sdio *sdio_priv = (struct oal_sdio *)pst_bus->data;
    if (sdio_priv == TD_NULL) {
        oal_sdio_log(BUS_LOG_ERR, "sdio_priv null noty\n");
        return EXT_ERR_FAILURE;
    }
    sdio_priv->suspend_notify_func = suspend_func;
    sdio_priv->resume_notify_func = resume_func;
    return EXT_ERR_SUCCESS;
}

#if defined(_PRE_OS_VERSION_LINUX) && defined(_PRE_OS_VERSION) && (_PRE_OS_VERSION_LINUX == _PRE_OS_VERSION)
static td_s32 sdio_suspend(struct device *dev)
{
    /* to be implement */
    oal_sdio_func *func = TD_NULL;
    struct oal_sdio *sdio_priv = TD_NULL;

    oal_sdio_log(BUS_LOG_INFO, "sdio suspend");
    if (dev == TD_NULL) {
        oal_sdio_log(BUS_LOG_ERR, "dev is null");
        return EXT_ERR_SUCCESS;
    }
    func = dev_to_sdio_func(dev);
    sdio_priv = oal_sdio_get_drvdata(func);
    if (sdio_priv == TD_NULL) {
        oal_sdio_log(BUS_LOG_ERR, "suspend: %s", g_sdio_priv_log);
        return EXT_ERR_SUCCESS;
    }
    sdio_priv->ul_sdio_suspend++;
    if (sdio_priv->suspend_notify_func != TD_NULL) {
        return sdio_priv->suspend_notify_func();
    }
    return EXT_ERR_SUCCESS;
}

#define MMC_STATE_SUSPENDED	(1 << 5)
static td_s32 sdio_resume(struct device *dev)
{
    oal_sdio_func *dev_func = TD_NULL;
    struct oal_sdio *sdio_priv = TD_NULL;

    oal_sdio_log(BUS_LOG_INFO, "sdio resume");
    if (dev == TD_NULL) {
        oal_sdio_log(BUS_LOG_ERR, "sdio resume, dev is null");
        return EXT_ERR_SUCCESS;
    }
    dev_func = dev_to_sdio_func(dev);
    sdio_priv = oal_sdio_get_drvdata(dev_func);
    if (sdio_priv == TD_NULL) {
        oal_sdio_log(BUS_LOG_ERR, "resume: %s", g_sdio_priv_log);
        return EXT_ERR_SUCCESS;
    }

#if defined(LINUX_VERSION_CODE) && defined(KERNEL_VERSION) && (LINUX_VERSION_CODE > KERNEL_VERSION(5,1,14))
    sdio_priv->func->card->state &= ~MMC_STATE_SUSPENDED; // linux sdio低功耗机制变更，等价mmc_card_clr_suspended清除状态。
#endif

    sdio_priv->ul_sdio_resume++;
    if (sdio_priv->resume_notify_func != TD_NULL) {
        return sdio_priv->resume_notify_func();
    }
    return EXT_ERR_SUCCESS;
}

static TD_CONST struct dev_pm_ops sdio_pm_ops = {
    .suspend = sdio_suspend,
    .resume = sdio_resume,
};

static td_void sdio_dev_shutdown_disable(struct oal_sdio *sdio_priv)
{
    /* sdio interrupt */
    td_s32 ret;
    oal_sdio_claim_host(sdio_priv->func);
    ret = oal_sdio_disable_func(sdio_priv->func);
    oal_sdio_release_host(sdio_priv->func);
    if (ret != 0) {
        oal_sdio_log(BUS_LOG_INFO, "shutdown func=%d!", ret);
        return;
    }
    oal_sdio_log(BUS_LOG_DBG, "sdio shutdown");
}

static td_void sdio_dev_shutdown(struct device *dev)
{
    /* android poweroff */
    struct oal_sdio *sdio_priv = g_sdio_handler;

    if (sdio_priv == TD_NULL || sdio_get_state(sdio_priv->pst_bus, HCC_BUS_STATE_ALL) != TD_TRUE) {
        /* wlan power off */
        return;
    }

    /* disable sdio/gpio interrupt before android poweroff */
    if (g_sdio_intr_mode == INT_MODE_SDIO) {
        sdio_dev_shutdown_disable(sdio_priv);
    }
}
#endif

static oal_sdio_driver g_sdio_driver = {
    .name       = "wireless_sdio",
#if defined(_PRE_OS_VERSION_RTTHREAD) && defined(_PRE_OS_VERSION) && (_PRE_OS_VERSION_RTTHREAD == _PRE_OS_VERSION)
    .id         = &sdio_ids,
    .probe      = oal_sdio_probe,
    .remove     = oal_sdio_remove,
#else
    .id_table   = sdio_ids,
    .probe      = sdio_probe,
    .remove     = sdio_remove,
#endif
#if defined(_PRE_OS_VERSION_LINUX) && defined(_PRE_OS_VERSION) && (_PRE_OS_VERSION_LINUX == _PRE_OS_VERSION)
    .drv        = {
        .owner  = THIS_MODULE,
        .pm     = &sdio_pm_ops,
        .shutdown = sdio_dev_shutdown,
    }
#endif
};

/* sdio first enum, wifi power on, must down later. */
#if defined(_PRE_OS_VERSION_LINUX) && defined(_PRE_OS_VERSION) && (_PRE_OS_VERSION_LINUX == _PRE_OS_VERSION)
static td_s32 sdio_detectcard_change(td_void)
{
#ifdef CONFIG_SDIO_RESCAN
#if defined(CONFIG_JZMMC_V12_MMC1) || defined(CONFIG_MMC_SDHCI_INGENIC)
    jzmmc_manual_detect(1, 1);
#elif defined(CONFIG_3519D)
    bsp_sdio_rescan(2); /* mmc2 */
#elif defined(CONFIG_3516CV610)
    sdhci_nebula_sdio_rescan(2); /* mmc2 */
#else
    hisi_sdio_rescan(1);
#endif
#endif
    return EXT_ERR_SUCCESS;
}

static td_s32 sdio_trigger_probe(td_void)
{
    td_s32 ret = EXT_ERR_SUCCESS;
    td_s32 times = SDIO_PROBLE_TIMES;

    init_completion(&g_sdio_driver_complete);

    ret = sdio_detectcard_change();
    if (ret != 0) {
        oal_sdio_log(BUS_LOG_ERR, "fail to detect sdio card\n");
        goto failed_sdio_reg;
    }
    ret = oal_sdio_register_driver(&g_sdio_driver);
    if (ret != 0) {
        oal_sdio_log(BUS_LOG_ERR, "register sdio ret=%d", ret);
        goto failed_sdio_reg;
    }

    do {
        if (wait_for_completion_timeout(&g_sdio_driver_complete, 10 * HZ) != 0) { // 10 等待10个HZ时间
            break;
        }
        ret = sdio_detectcard_change();
        if (ret != 0) {
            break;
        }
    } while (--times > 0);
    if (times <= 0) {
        oal_sdio_log(BUS_LOG_ERR, "sdio load fail.\n");
        goto failed_sdio_enum;
    }
    oal_sdio_log(BUS_LOG_DBG, "sdio_trigger_probe over");
    return ret;

failed_sdio_enum:
    oal_sdio_unregister_driver(&g_sdio_driver);
failed_sdio_reg:
    return EXT_ERR_FAILURE;
}
#endif

#if defined(_PRE_OS_VERSION_RTTHREAD) && defined(_PRE_OS_VERSION) && (_PRE_OS_VERSION_RTTHREAD == _PRE_OS_VERSION)
void *fh_get_board_info_data(char *info_name);
void fh_mmc_set_sdio_remove(struct rt_mmcsd_host *host);
int sdio_reset(struct rt_mmcsd_host *host);

static struct rt_mmcsd_host *sdio_get_mmc_host(void)
{
    struct fh_mmc_obj *mmc_obj = fh_get_board_info_data("mmc");
    if (mmc_obj != TD_NULL) {
        return mmc_obj->host;
    }
    return TD_NULL;
}

static td_void sdio_remove_card(td_void)
{
    struct rt_mmcsd_host *host = sdio_get_mmc_host();
    if (host != TD_NULL) {
        /* trigger sdio card reset isr */
        sdio_reset(host);
        /* remove sdio card object */
        fh_mmc_set_sdio_remove(host);
    }
}

static td_s32 sdio_detectcard_change(td_void)
{
    struct rt_mmcsd_host *host = sdio_get_mmc_host();
    if (host != TD_NULL) {
        mmcsd_change(host);
        if (host->card != TD_NULL) {
            oal_sdio_log(BUS_LOG_ERR, "sdio card, vendor 0x%x vid 0x%x func_num %d product 0x%x 0x%x",
                host->card->cis.manufacturer, host->card->cis.product, host->card->sdio_function[1]->num,
                host->card->sdio_function[1]->manufacturer, host->card->sdio_function[1]->product);
        }
    }
    return EXT_ERR_SUCCESS;
}

static td_s32 sdio_trigger_probe(td_void)
{
    td_s32 ret = EXT_ERR_SUCCESS;
    td_s32 times = SDIO_PROBLE_TIMES;

    /* detect card */
    ret = sdio_detectcard_change();
    if (ret != 0) {
        oal_sdio_log(BUS_LOG_ERR, "fail to detect sdio card\n");
        goto failed_sdio_reg;
    }

    /* register driver */
    ret = oal_sdio_register_driver(&g_sdio_driver);
    if (ret != 0) {
        oal_sdio_log(BUS_LOG_ERR, "register sdio ret=%d", ret);
        goto failed_sdio_reg;
    }

    do {
        if (osal_sem_down_timeout(&g_sdio_driver_complete, 10000) == 0) { // 10000 ms
            break;
        }
        ret = sdio_detectcard_change();
        if (ret != 0) {
            break;
        }
    } while (--times > 0);
    if (times <= 0) {
        oal_sdio_log(BUS_LOG_ERR, "sdio load fail.\n");
        goto failed_sdio_enum;
    }
    oal_sdio_log(BUS_LOG_DBG, "sdio_trigger_probe over");
    return ret;

failed_sdio_enum:
    oal_sdio_unregister_driver(&g_sdio_driver);
failed_sdio_reg:
    return EXT_ERR_FAILURE;
}
#endif

/* sdio first enum, wifi power on, must down later. */
#if defined(_PRE_OS_VERSION_LITEOS) && defined(_PRE_OS_VERSION) && (_PRE_OS_VERSION_LITEOS == _PRE_OS_VERSION)
static td_s32 sdio_trigger_probe(td_void)
{
    td_s32 ret = EXT_ERR_SUCCESS;
    oal_sdio_func *func = TD_NULL;
    oal_sdio_log(BUS_LOG_DBG, "sdio_trigger_probe start");
    func = sdio_get_func(1, sdio_ids[SDIO_IDS_INDEX].vendor, sdio_ids[SDIO_IDS_INDEX].device);
    if (func != TD_NULL) {
        ret = g_sdio_driver.probe(func, &sdio_ids[SDIO_IDS_INDEX]);
    } else {
        ret = EXT_ERR_FAILURE;
    }
    return ret;
}

static td_s32 sdio_trigger_remove(td_void)
{
    td_s32 ret = EXT_ERR_SUCCESS;
    struct sdio_func *func = TD_NULL;
    func = sdio_get_func(1, sdio_ids[SDIO_IDS_INDEX].vendor, sdio_ids[SDIO_IDS_INDEX].device);
    if (func != TD_NULL) {
        g_sdio_driver.remove(func);
    } else {
        oal_sdio_log(BUS_LOG_ERR, "sdio remove get_func fail!");
        ret = EXT_ERR_FAILURE;
    }
    return ret;
}
#endif

static td_void sdio_func_remove(struct oal_sdio *sdio_priv)
{
#if defined(_PRE_OS_VERSION_LINUX) && defined(_PRE_OS_VERSION) && (_PRE_OS_VERSION_LINUX == _PRE_OS_VERSION)
    oal_sdio_unregister_driver(&g_sdio_driver);
    if (sdio_detectcard_change() != EXT_ERR_SUCCESS) {
        oal_sdio_log(BUS_LOG_ERR, "sdio_detectcard_change fail.\n");
    }
#elif defined(_PRE_OS_VERSION_RTTHREAD) && defined(_PRE_OS_VERSION) && (_PRE_OS_VERSION_RTTHREAD == _PRE_OS_VERSION)
    oal_sdio_unregister_driver(&g_sdio_driver);
    sdio_remove_card();
#else
    td_s32 ret;
    ret = sdio_trigger_remove();
    if (ret != EXT_ERR_SUCCESS) {
        oal_sdio_log(BUS_LOG_ERR, "sdio remove failed!");
    }
#endif
}

#define MAX_SCATT_ATTACH_NUM 2
static td_s32 sdio_rx_buf_alloc(struct oal_sdio *sdio_priv)
{
    /* alloc rx reserved mem */
    sdio_priv->rx_reserved_buff = (td_void *)osal_kmalloc(SDIO_MAX_XFER_LEN, OSAL_GFP_KERNEL);
    if (sdio_priv->rx_reserved_buff == TD_NULL) {
        oal_sdio_log(BUS_LOG_ERR, "alloc rx_reserved_buff[%u]", SDIO_MAX_XFER_LEN);
        return EXT_ERR_FAILURE;
    }
    sdio_priv->rx_reserved_buff_len = SDIO_MAX_XFER_LEN;
    sdio_priv->sdio_align_buff = osal_kmalloc(HCC_SDIO_BLOCK_SIZE, OSAL_GFP_KERNEL);
    if (sdio_priv->sdio_align_buff == TD_NULL) {
        return EXT_ERR_FAILURE;
    }
    return EXT_ERR_SUCCESS;
}

static td_s32 sdio_init_alloc_buf(struct oal_sdio *sdio_priv)
{
#ifdef PRE_SDIO_FEATURE_FLAT_MEMORY
    td_u32 tx_scatt_buff_len = 0;
    td_u32 rx_scatt_buff_len = 0;
#endif

    if (sdio_rx_buf_alloc(sdio_priv) != EXT_ERR_SUCCESS) {
        return EXT_ERR_FAILURE;
    }

#ifdef PRE_SDIO_FEATURE_SCATTER
    sdio_priv->scatt_info[SDIO_READ].max_scatt_num = HCC_SDIO_DEV2HOST_SCATT_MAX + 1;
    sdio_priv->scatt_info[SDIO_READ].sglist =
        osal_kmalloc(sizeof(struct scatterlist) * (HCC_SDIO_DEV2HOST_SCATT_MAX + 1), OSAL_GFP_KERNEL);
    if (sdio_priv->scatt_info[SDIO_READ].sglist == TD_NULL) {
        return EXT_ERR_FAILURE;
    }

    /* 1 for algin buff, 1 for scatt info buff */
    sdio_priv->scatt_info[SDIO_WRITE].max_scatt_num = HCC_SDIO_HOST2DEV_SCATT_MAX + MAX_SCATT_ATTACH_NUM;
    sdio_priv->scatt_info[SDIO_WRITE].sglist =
        osal_kmalloc(sizeof(struct scatterlist) * (sdio_priv->scatt_info[SDIO_WRITE].max_scatt_num), OSAL_GFP_KERNEL);
    if (sdio_priv->scatt_info[SDIO_WRITE].sglist == TD_NULL) {
        return EXT_ERR_FAILURE;
    }
#endif
#ifdef PRE_SDIO_FEATURE_FLAT_MEMORY
    tx_scatt_buff_len = HCC_SDIO_HOST2DEV_SCATT_SIZE + HCC_SDIO_HOST2DEV_SCATT_MAX *
        (OAL_HDR_TOTAL_LEN + OAL_ROUND_UP(HSDIO_HOST2DEV_PKTS_MAX_LEN, HCC_SDIO_H2D_SCATT_BUFFLEN_ALIGN));
    tx_scatt_buff_len = sdio_align_4_or_blk(tx_scatt_buff_len);
    sdio_priv->tx_scatt_buff.buff = osal_kmalloc(tx_scatt_buff_len, OSAL_GFP_KERNEL);
    if (sdio_priv->tx_scatt_buff.buff == TD_NULL) {
        oal_sdio_log(BUS_LOG_ERR, "alloc tx_scatt_buff[%u]", tx_scatt_buff_len);
        return EXT_ERR_FAILURE;
    }
    sdio_priv->tx_scatt_buff.len = tx_scatt_buff_len;
    oal_sdio_log(BUS_LOG_DBG, "alloc tx_scatt_buff ok[%u]", tx_scatt_buff_len);

    rx_scatt_buff_len = HCC_SDIO_DEV2HOST_SCATT_MAX *
        (OAL_HDR_TOTAL_LEN + OAL_ROUND_UP(HSDIO_HOST2DEV_PKTS_MAX_LEN, HCC_SDIO_D2H_SCATT_BUFFLEN_ALIGN));
    rx_scatt_buff_len = sdio_align_4_or_blk(rx_scatt_buff_len);
    sdio_priv->rx_scatt_buff.buff = osal_kmalloc(rx_scatt_buff_len, OSAL_GFP_KERNEL);
    if (sdio_priv->rx_scatt_buff.buff == TD_NULL) {
        oal_sdio_log(BUS_LOG_ERR, "alloc rx_scatt_buff[%u]", rx_scatt_buff_len);
        return EXT_ERR_FAILURE;
    }
    sdio_priv->rx_scatt_buff.len = rx_scatt_buff_len;
    oal_sdio_log(BUS_LOG_DBG, "alloc rx_scatt_buff ok[%u]", rx_scatt_buff_len);
#endif
    return EXT_ERR_SUCCESS;
}

static td_void sdio_init_free_buf(struct oal_sdio *sdio_priv)
{
    if (sdio_priv->rx_reserved_buff != TD_NULL) {
        osal_kfree(sdio_priv->rx_reserved_buff);
    }
    if (sdio_priv->sdio_align_buff != TD_NULL) {
        osal_kfree(sdio_priv->sdio_align_buff);
    }
#ifdef PRE_SDIO_FEATURE_SCATTER
    if (sdio_priv->scatt_info[SDIO_READ].sglist != TD_NULL) {
        osal_kfree(sdio_priv->scatt_info[SDIO_READ].sglist);
    }
    if (sdio_priv->scatt_info[SDIO_WRITE].sglist != TD_NULL) {
        osal_kfree(sdio_priv->scatt_info[SDIO_WRITE].sglist);
    }
#endif
#ifdef PRE_SDIO_FEATURE_FLAT_MEMORY
    if (sdio_priv->tx_scatt_buff.buff != TD_NULL) {
        osal_kfree(sdio_priv->tx_scatt_buff.buff);
    }
    if (sdio_priv->rx_scatt_buff.buff != TD_NULL) {
        osal_kfree(sdio_priv->rx_scatt_buff.buff);
    }
#endif
}

static td_void sdio_descript_unc_init(struct oal_sdio *sdio_priv)
{
    memset_s(sdio_priv->descript_unc.buf, SDIO_BUS_DESCRIPT_BUF_LEN, 0, SDIO_BUS_DESCRIPT_BUF_LEN);
    sdio_priv->descript_unc.length = SDIO_BUS_DESCRIPT_BUF_LEN;
    sdio_priv->descript_unc.service_type = HCC_SERVICE_TYPE_MAX;
    sdio_priv->descript_unc.user_param = TD_NULL;
    sdio_priv->descript_unc.list.next = sdio_priv->descript_unc.list.prev = &sdio_priv->descript_unc.list;
}

static struct oal_sdio *sdio_init_module(td_void)
{
    struct oal_sdio *sdio_priv = TD_NULL;

    sdio_priv = (struct oal_sdio *)osal_kzalloc(sizeof(struct oal_sdio), OSAL_GFP_KERNEL);
    if (sdio_priv == TD_NULL) {
        oal_sdio_log(BUS_LOG_ERR, "alloc sdio_priv[%d]", (td_s32)sizeof(struct oal_sdio));
        return TD_NULL;
    }

    sdio_priv->func1_int_mask = HCC_SDIO_FUNC1_INT_MASK;
    sdio_priv->sdio_extend =
        (struct hcc_sdio_extend_func *)osal_kzalloc(sizeof(struct hcc_sdio_extend_func), OSAL_GFP_KERNEL);
    if (sdio_priv->sdio_extend == TD_NULL) {
        oal_sdio_log(BUS_LOG_ERR, "alloc sdio_extend[%d]", (td_s32)sizeof(struct hcc_sdio_extend_func));
        goto failed_sdio_extend_alloc;
    }

    sdio_priv->current_queue = HCC_QUEUE_COUNT;
    sdio_priv->descript_unc.buf = (td_u8 *)osal_kmalloc(SDIO_BUS_DESCRIPT_BUF_LEN, OSAL_GFP_KERNEL);
    if (sdio_priv->descript_unc.buf == TD_NULL) {
        oal_sdio_log(BUS_LOG_ERR, "descr_buf malloc err");
        goto failed_sdio_descript_buf_malloc;
    }
    sdio_descript_unc_init(sdio_priv);

    if (hcc_list_head_init(&sdio_priv->tx_assemble_info.assembled_head) != EXT_ERR_SUCCESS) {
        oal_sdio_log(BUS_LOG_ERR, "sdio assemble head init err");
        goto failed_sdio_tx_assemble_info_init;
    }
    if (hcc_list_head_init(&sdio_priv->rx_assemble_head) != EXT_ERR_SUCCESS) {
        oal_sdio_log(BUS_LOG_ERR, "sdio head list init err");
        goto failed_sdio_rx_assemble_info_init;
    }
    if (sdio_init_alloc_buf(sdio_priv) != EXT_ERR_SUCCESS) {
        oal_sdio_log(BUS_LOG_ERR, "sdio_init_alloc_buf err");
        goto failed_sdio_buff_alloc;
    }

    g_sdio_handler = sdio_priv;
    return sdio_priv;

failed_sdio_buff_alloc:
    hcc_list_head_deinit(&sdio_priv->rx_assemble_head);
    sdio_init_free_buf(sdio_priv);
failed_sdio_rx_assemble_info_init:
    hcc_list_head_deinit(&sdio_priv->tx_assemble_info.assembled_head);
failed_sdio_tx_assemble_info_init:
    osal_kfree(sdio_priv->descript_unc.buf);
failed_sdio_descript_buf_malloc:
    osal_kfree(sdio_priv->sdio_extend);
failed_sdio_extend_alloc:
    osal_kfree(sdio_priv);
    return TD_NULL;
}

static td_void sdio_exit_module(struct oal_sdio *sdio_priv)
{
    oal_sdio_log(BUS_LOG_DBG, "sdio module unregistered");
    sdio_init_free_buf(sdio_priv);
    hcc_list_head_deinit(&sdio_priv->rx_assemble_head);
    hcc_list_head_deinit(&sdio_priv->tx_assemble_info.assembled_head);
    osal_kfree(sdio_priv->descript_unc.buf);
    osal_kfree(sdio_priv->sdio_extend);
    osal_kfree(sdio_priv);
    g_sdio_handler = TD_NULL;
}
osal_module_export(sdio_exit_module);

static td_u32 sdio_func_max_req_size(struct oal_sdio *pst_hi_sdio)
{
    td_u32 max_blocks;
    td_u32 size, size_device;

    if (OAL_WARN_ON(pst_hi_sdio == TD_NULL)) {
        oal_sdio_log(BUS_LOG_ERR, "pst_hi_sdio is null");
        return 0;
    };
    /* host transer limit */
    /* Blocks per command is limited by host count, host transfer
     * size and the maximum for IO_RW_EXTENDED of 511 blocks. */
    max_blocks = osal_min(oal_sdio_func_host_max_blk_num(pst_hi_sdio->func), 511u);
    size = max_blocks * HCC_SDIO_BLOCK_SIZE;
    size = osal_min(size, oal_sdio_func_host_max_req_size(pst_hi_sdio->func));

    /* device transer limit,per adma descr limit 32K in bootloader,
    and total we have 20 descs */
    size_device = (32 * 1024) * 20; // 1024 数据长度

    size = osal_min(size, size_device);
    return size;
}

#ifdef CONFIG_HCC_SUPPORT_FLOW_CONTRL
static td_s32 hcc_sdio_get_credit(hcc_bus *bus, td_u32 *free_cnt)
{
    struct oal_sdio *sdio_priv = (struct oal_sdio *)bus->data;
    td_s32 ret;
    if (sdio_priv == TD_NULL) {
        oal_sdio_log(BUS_LOG_ERR, "%s", g_sdio_priv_log);
        return EXT_ERR_FAILURE;
    }

    oal_sdio_claim_host(sdio_priv->func);
    ret = oal_sdio_memcpy_fromio(sdio_priv->func, (td_u8 *)free_cnt,
                                 SDIO_EXTEND_CREDIT_ADDR, sizeof(td_u32), TD_FALSE);
    if (ret != EXT_ERR_SUCCESS) {
        oal_sdio_log(BUS_LOG_ERR, "hcc_sdio_get_credit fail");
    }
    oal_sdio_release_host(sdio_priv->func);
    return ret;
}
#endif

static osal_void hcc_sdio_stop_xfer(osal_void)
{
    /* reset queue info */
    if (g_sdio_handler != TD_NULL) {
        g_sdio_handler->current_queue = HCC_QUEUE_COUNT;
    }
}

static bus_dev_ops g_sdio_opt_ops = {
    .tx_proc = hcc_sdio_tx_proc,
    .send_and_clear_msg = hcc_sdio_send_msg,
#ifdef CONFIG_HCC_SUPPORT_FLOW_CONTRL
    .update_credit              = TD_NULL,
    .get_credit                 = hcc_sdio_get_credit,
#endif
#ifdef CONFIG_HCC_SUPPORT_REG_OPT
    .read_reg = hcc_sdio_read_fn0_reg,
    .write_reg = hcc_sdio_write_fn0_reg,
#endif
    .reinit = hcc_sdio_reinit,
#ifdef CONFIG_HCC_SUPPORT_PATCH_OPT
    .patch_read = hcc_sdio_patch_read,
    .patch_write = hcc_sdio_patch_write,
#endif
    .stop_xfer = hcc_sdio_stop_xfer,
    .power_action = hcc_sdio_power_action,
    .sleep_request = hcc_sdio_sleep_request,
    .wakeup_request = hcc_sdio_wakeup_request,
    .pm_notify_register = hcc_sdio_pm_notify_register,
};

static td_u32 hcc_sdio_update_tx_limit(td_void)
{
    td_u32 tx_limit = 0;
#ifdef CONFIG_HCC_SUPPORT_REG_OPT
    hcc_sdio_read_fn0_reg(HCC_FLOW_CTRL_GP_REG, &tx_limit);
#endif
    return (tx_limit & 0xFF);
}

/* add sdio to bus */
static hcc_bus *sdio_bus_init(struct oal_sdio *sdio_priv)
{
    hcc_bus *pst_bus = hcc_alloc_bus();
    if (pst_bus == TD_NULL || sdio_priv == TD_NULL) {
        oal_sdio_log(BUS_LOG_ERR, "alloc sdio bus size:%u", (td_u32)sizeof(hcc_bus));
        return TD_NULL;
    }

    pst_bus->bus_type = HCC_BUS_SDIO;
    pst_bus->max_trans_size =  0xFFF;
    pst_bus->addr_align = HCC_SDIO_H2D_SCATT_BUFFADDR_ALIGN;
    pst_bus->len_align = HCC_SDIO_H2D_SCATT_BUFFLEN_ALIGN;
    pst_bus->max_assemble_cnt = HCC_SDIO_HOST2DEV_SCATT_MAX;
    pst_bus->descr_align_bit = HCC_SDIO_H2D_SCATT_BUFFLEN_ALIGN_BITS;
    pst_bus->tx_sched_count = HCC_SDIO_HOST2DEV_SCATT_MAX;
    pst_bus->state = 1;
    hcc_set_bus_ops(pst_bus, &g_sdio_opt_ops);

    pst_bus->data = (td_void *)sdio_priv;
    sdio_priv->pst_bus = pst_bus;

    return pst_bus;
}

static td_void sdio_bus_exit(struct oal_sdio *sdio_priv)
{
    hcc_handler *hcc;
    hcc_bus *bus = sdio_priv->pst_bus;
    if (bus == TD_NULL) {
        return;
    }
    /* unreference hcc handler and hcc bus */
    hcc = (hcc_handler *)bus->hcc;
    if (hcc != TD_NULL) {
        hcc->bus = TD_NULL;
        bus->hcc = TD_NULL;
    }
    hcc_free_bus(bus);
    sdio_priv->pst_bus = TD_NULL;
}

hcc_bus *hcc_adapt_sdio_load(const hcc_handler *hcc)
{
    td_s32 ret;
    hcc_bus *pst_bus;
    uapi_unused(hcc);
    g_sdio_probe_status = TD_FALSE;

    if (sdio_res_init() != EXT_ERR_SUCCESS) {
        oal_sdio_log(BUS_LOG_ERR, "sdio_res_init failed!");
        return TD_NULL;
    }
    ret = sdio_trigger_probe();
    if (ret != EXT_ERR_SUCCESS) {
        sdio_res_deinit(g_sdio_handler);
        oal_sdio_log(BUS_LOG_ERR, "sdio first probe failed!");
        return TD_NULL;
    }
    pst_bus = sdio_get_bus_handler();
    if (pst_bus == TD_NULL) {
        sdio_res_deinit(g_sdio_handler);
        return TD_NULL;
    }

    hcc_flow_ctrl_tx_limit_register(hcc_sdio_update_tx_limit);
    return pst_bus;
}

td_void hcc_adapt_sdio_unload(td_void)
{
    if (g_sdio_handler) {
        hcc_flow_ctrl_tx_limit_unregister();
        sdio_disable_state(g_sdio_handler->pst_bus, HCC_BUS_STATE_ALL);
        g_sdio_remove_enable = TD_TRUE;
        sdio_func_remove(g_sdio_handler);
        sdio_res_deinit(g_sdio_handler);
    }
}

#ifdef CONFIG_SDIO_DEBUG
td_void sdio_netbuf_list_hex_dump(hcc_data_queue *head)
{
#ifdef CONFIG_PRINTK
    td_s32 index = 0;
    hcc_unc_struc *unc_buf = TD_NULL;
    hcc_unc_struc *tmp = TD_NULL;
    if (hcc_is_list_empty(head)) {
        return;
    }
    oal_sdio_log(BUS_LOG_DBG, "prepare to dump %d pkts=========\n", hcc_list_len(head));

    osal_list_for_each_entry_safe(unc_buf, tmp, (&head->data_queue), list) {
        index++;
    }
#else
    OAL_REFERENCE(head);
#endif
}
#endif

#ifdef __cplusplus
#if __cplusplus
}
#endif
#endif
#endif
