/**
 * Copyright (c) HiSilicon (Shanghai) Technologies Co., Ltd. 2022-2022. All rights reserved.
 *
 * Description: Provides spi port UT \n
 *
 * History: \n
 * 2022-08-18， Create file. \n
 */
#ifdef CONFIG_DRIVER_SUPPORT_SPI
#include "hal_spi_v151_100_adapt_op.h"
#include "hal_spi_v151_100.h"
#include "hal_spi.h"
#include "osal_interrupt.h"
#include "chip_io.h"
#include "std_def.h"
#include "pinctrl.h"
#include "platform_core.h"
#include "osal_interrupt.h"
#include "chip_core_irq.h"
#include "arch_port.h"
#include "clock_recover.h"
#include "spi_porting.h"

/** -----------------------------------------------------
 *          Reg Bit fild Max and Shift Value
 * ---------------------------------------------------- */
 /**
  * @brief  SPI_CTRA : Control register 0.
  */
#define HAL_SPI_CTRA_REG_MAX       0xFFFFFFFF
#define HAL_SPI_CE_LIN_TOGGLE_ENABLE (BIT(24))

/**
 * @brief  FRF : Frame format.
 */
#define HAL_SPI_FRAME_FORMAT_MAX   0x03
#define HAL_SPI_FRAME_FORMAT_SHIFT 0x15

/**
 * @brief  DFS : Data frame size.
 */
#define HAL_SPI_FRAME_SIZE_MAX   0x1F
#define HAL_SPI_FRAME_SIZE_SHIFT 0x10
#define HAL_SPI_FRAME_SIZE_8     0x07
#define HAL_SPI_FRAME_SIZE_16    0x0F
#define HAL_SPI_FRAME_SIZE_32    0x1F

/**
 * @brief  TMOD : Trans mode.
 */
#define HAL_SPI_TRANS_MODE_MAX    0x03
#define HAL_SPI_TRANS_MODE_SHIFT  0x08
#define HAL_SPI_TRANS_MODE_TXRX   0x00
#define HAL_SPI_TRANS_MODE_TX     0x01
#define HAL_SPI_TRANS_MODE_RX     0x02
#define HAL_SPI_TRANS_MODE_EEPROM 0x03

/**
 * @brief  CLOCK : SCPOL and SCPH.
 */
#define HAL_SPI_CLKS_MODE_MAX   0x03
#define HAL_SPI_CLKS_MODE_SHIFT 0x06

/**
 * @brief  SPI_CTRB : Control register 1.
 */
#define HAL_SPI_RECEIVED_DATA_REG_MAX 0xFFFF

/**
 * @brief  SPI_ER : SSI enable register.
 */
#define HAL_SPI_ENABLE 0x01

/**
 * @brief  SPI_SLENR : Slave enable register.
 */
#define HAL_SPI_SLAVE_ENABLE_REG_MAX 0xFFFFFFFF

/**
 * @brief  BAUDR : Baud rate select.
 */
#define HAL_SPI_CLK_DIV_REG_MAX 0xFFFF

/**
 * @brief  SPI_WSR : Status register.
 */
#define HAL_SPI_RX_FIFO_FULL_FLAG      (BIT(4))
#define HAL_SPI_RX_FIFO_NOT_EMPTY_FLAG (BIT(3))
#define HAL_SPI_TX_FIFO_EMPTY_FLAG     (BIT(2))
#define HAL_SPI_TX_FIFO_NOT_FULL_FLAG  (BIT(1))
#define HAL_SPI_BUSY_FLAG              (BIT(0))

/**
 * @brief IMR : Interrupt mask register.
 */
#define HAL_SPI_INTERRUPT_REG_MAX 0x3F


/**
 * @brief  SPI_CTRA:  SPI control register.
 */
#define HAL_QSPI_CTRA_REG_MAX 0xFFFFFFFF

/**
 * @brief  Wait cycles.
 */
#define HAL_QSPI_WAIT_CYCLE_MAX   0x1F
#define HAL_QSPI_WAIT_CYCLE_SHIFT 0x0B
#define HAL_QSPI_WAIT_CYCLE_6     0x06
#define HAL_QSPI_WAIT_CYCLE_4     0x04
#define HAL_QSPI_WAIT_CYCLE_2     0x02

#define HAL_SPI_RX_SAMPLE_DLY_MAX   0xFF
#define HAL_SPI_RX_SAMPLE_DLY_SHIFT 0

/**
 * @brief  Command length.
 */
#define HAL_QSPI_CMD_LENTH_MAX   0x03
#define HAL_QSPI_CMD_LENTH_SHIFT 0x08
#define HAL_QSPI_CMD_LENTH_8     0x02

/**
 * @brief  Address length.
 */
#define HAL_QSPI_ADDR_LENTH_MAX   0x0F
#define HAL_QSPI_ADDR_LENTH_SHIFT 0x02
#define HAL_QSPI_ADDR_LENTH_24    0x06

/**
 * @brief  Trans type.
 */
#define HAL_QSPI_TRANS_TYPES_MAX          0x03
#define HAL_QSPI_TRANS_TYPES_SHIFT        0x00
#define HAL_QSPI_TRANS_TYPES_CMD_S_ADDR_Q 0x01

#define HAL_SPI_BUS_MAX_NUM (SPI_BUS_MAX_NUMBER)

#define HAL_SPI_DR_REG_SIZE 36

/** -----------------------------------------------------
 *          SPI Register Address
 * ----------------------------------------------------
 */
#define HAL_SPI_BUS_1_DEVICE_MODE_SET_BIT       0x00
#define HAL_SPI_BUS_1_DEVICE_MODE_SET_BIT_MAX   0x01
#define HAL_SPI_BUS_1_DEVICE_MODE_SET_BIT_SHIFT 0x00
#define HAL_SPI_BUS_2_DEVICE_MODE_MASTER        0x01
#define HAL_SPI_BUS_2_DEVICE_MODE_SET_BIT_MAX   0x01
#define HAL_SPI_BUS_2_DEVICE_MODE_SET_BIT_SHIFT 0x01

#define HAL_QSPI_DMA_CFG        (*(volatile unsigned short *)(0x5C000404))
#define HAL_QSPI_1_DMA_CFG_MASK 0x0FU
#define HAL_QSPI_1_DMA_SEC_CORE 0x05
#define HAL_QSPI_1_DMA_APP_CORE 0x0A
#define HAL_QSPI_1_DMA_DSP_CORE 0x0F
#define HAL_QSPI_2_DMA_CFG_MASK 0xF0U
#define HAL_QSPI_2_DMA_SEC_CORE 0x50
#define HAL_QSPI_2_DMA_APP_CORE 0xA0
#define HAL_QSPI_2_DMA_DSP_CORE 0xF0

#define HAL_QSPI_INT_CFG             (*(volatile unsigned short *)(0x5C000408))
#define HAL_QSPI_1_INT_SEC_CORE_MASK (BIT(0))
#define HAL_QSPI_1_INT_APP_CORE_MASK (BIT(2))
#define HAL_QSPI_2_INT_SEC_CORE_MASK (BIT(4))
#define HAL_QSPI_2_INT_APP_CORE_MASK (BIT(6))

#define HAL_SPI_DATA_FRAME_SIZE_BIT     16
#define HAL_SPI_DATA_FRAME_SIZE_BITFILD 5
#define hal_spi_frame_size_trans_to_frame_bytes(x) (((x) + 1) >> 0x03)

#define HAL_SPI_MINUMUM_CLK_DIV 2
#define HAL_SPI_MAXIMUM_CLK_DIV 65534

#define hal_spi_mhz_to_hz(x) ((x) * 1000000)

#define HAL_SPI_RXDS_EN     BIT(18)
#define HAL_SPI_INST_DDR_EN BIT(17)
#define HAL_SPI_DDR_EN      BIT(16)
#define HAL_SPI_INST_L_POSE 8
#define HAL_SPI_ADDR_L_POSE 2

#define HAL_SPI_RSVD_NONE   0
#define HAL_SPI_RSVD_X8     0
#define HAL_SPI_RSVD_X8_X8  1
#define HAL_SPI_RSVD_X16    0x11
#define HAL_SPI_CLK_DIV_2   2
#define HAL_SPI_CLK_DIV_4   4
#define HAL_SPI_CLK_DIV_20  20

#define SPI_DMA_TX_DATA_LEVEL_4     4
#define QSPI_DMA_TX_DATA_LEVEL_8    8

#define SPI_REC_OFFSET 1
spi_v151_100_regs_t *g_spi_base_addrs[SPI_BUS_MAX_NUM] = {
    (spi_v151_100_regs_t *)SPI_BUS_0_BASE_ADDR,
    (spi_v151_100_regs_t *)SPI_BUS_1_BASE_ADDR,
};

static int irq_spi0_handler(int i, void *p);
static int irq_spi1_handler(int i, void *p);

typedef struct spi_interrupt {
    core_irq_t irq_num;
    osal_irq_handler irq_func;
}
hal_spi_interrupt_t;

static const hal_spi_interrupt_t g_spi_interrupt_lines[SPI_BUS_MAX_NUMBER] = {
    { SPI_3_IRQN, irq_spi0_handler },
    { QSPI0_2CS_IRQN, irq_spi1_handler },
};

#ifdef TEST_SUITE
/* ws53 SPI testsuit pinctrl config */
void spi_porting_test_spi_init_pin(void)
{
    uapi_pin_set_mode(S_MGPIO6, PIN_MODE_2);
    uapi_pin_set_mode(S_MGPIO7, PIN_MODE_2);
    uapi_pin_set_mode(S_MGPIO8, PIN_MODE_2);
    uapi_pin_set_mode(S_MGPIO9, PIN_MODE_2);
}
#endif

static int irq_spi0_handler(int i, void *p)
{
    unused(i);
    unused(p);
#if defined(CONFIG_SPI_SUPPORT_INTERRUPT) && (CONFIG_SPI_SUPPORT_INTERRUPT == 1)
    hal_spi_v151_100_irq_handler(SPI_BUS_0);
    osal_irq_clear(g_spi_interrupt_lines[SPI_BUS_0].irq_num);
#endif
    return 0;
}

static int irq_spi1_handler(int i, void *p)
{
    unused(i);
    unused(p);
#if defined(CONFIG_SPI_SUPPORT_INTERRUPT) && (CONFIG_SPI_SUPPORT_INTERRUPT == 1)
    hal_spi_v151_100_irq_handler(SPI_BUS_1);
    osal_irq_clear(g_spi_interrupt_lines[SPI_BUS_1].irq_num);
#endif
    return 0;
}

void spi_port_register_irq(spi_bus_t bus)
{
    osal_irq_request(g_spi_interrupt_lines[bus].irq_num, g_spi_interrupt_lines[bus].irq_func, NULL, NULL, NULL);
    osal_irq_set_priority(g_spi_interrupt_lines[bus].irq_num, irq_prio(g_spi_interrupt_lines[bus].irq_num));
    osal_irq_enable(g_spi_interrupt_lines[bus].irq_num);
}

void spi_port_unregister_irq(spi_bus_t bus)
{
    osal_irq_disable(g_spi_interrupt_lines[bus].irq_num);
}

uintptr_t spi_porting_base_addr_get(spi_bus_t index)
{
    return (uintptr_t)g_spi_base_addrs[index];
}

uint32_t spi_porting_max_slave_select_get(spi_bus_t bus)
{
    unused(bus);
    return (uint32_t)(SPI_SLAVE_MAX_NUM - 1);
}

errcode_t spi_porting_set_device_mode(spi_bus_t bus, spi_mode_t mode)
{
    if (mode >= SPI_MODE_MAX_NUM || bus >= SPI_BUS_MAX_NUMBER) {
        return ERRCODE_INVALID_PARAM;
    }

    /* bus1为qspi，仅支持master模式 */
    if (bus == SPI_BUS_1 && mode == SPI_MODE_SLAVE) {
        return ERRCODE_NOT_SUPPORT;
    }

    if (bus == SPI_BUS_0) {
        reg16_setbits(HAL_SPI_DEVICE_MODE_SET_REG, 0, 1, mode);
    }
    return ERRCODE_SUCC;
}

spi_mode_t spi_porting_get_device_mode(spi_bus_t bus)
{
    spi_mode_t mode = SPI_MODE_NONE;

    if (bus == SPI_BUS_0) {
        mode = ((readw(HAL_SPI_DEVICE_MODE_SET_REG) & (uint16_t)1) == 1) ? SPI_MODE_MASTER : SPI_MODE_SLAVE;
    } else if (bus == SPI_BUS_1) {
        mode = SPI_MODE_MASTER;
    }

    return mode;
}

uint32_t spi_porting_lock(spi_bus_t bus)
{
    unused(bus);
    return osal_irq_lock();
}

void spi_porting_unlock(spi_bus_t bus, uint32_t irq_sts)
{
    unused(bus);
    osal_irq_restore(irq_sts);
}

uint8_t spi_port_get_dma_trans_dest_handshaking(spi_bus_t bus)
{
    switch (bus) {
        case SPI_BUS_0:
            return (uint8_t)DMA_HANDSHAKE_SPI_BUS_0_TX;
        case SPI_BUS_1:
            return (uint8_t)DMA_HANDSHAKE_SPI_BUS_1_TX;
        default:
            return (uint8_t)HAL_DMA_HANDSHAKING_MAX_NUM;
    }
}

uint8_t spi_port_get_dma_trans_src_handshaking(spi_bus_t bus)
{
    switch (bus) {
        case SPI_BUS_0:
            return (uint8_t)DMA_HANDSHAKE_SPI_BUS_0_RX;
        case SPI_BUS_1:
            return (uint8_t)DMA_HANDSHAKE_SPI_BUS_1_RX;
        default:
            return (uint8_t)HAL_DMA_HANDSHAKING_MAX_NUM;
    }
}

uint8_t spi_port_tx_data_level_get(spi_bus_t bus)
{
    switch (bus) {
        case SPI_BUS_0:
        case SPI_BUS_1:
            return (uint8_t)SPI_DMA_TX_DATA_LEVEL_4;
        default:
            return 0;
    }
}

uint8_t spi_port_rx_data_level_get(spi_bus_t bus)
{
    unused(bus);
    return 0;
}

void spi_port_clock_enable(spi_bus_t bus, bool on)
{
    if (bus == SPI_BUS_0) {
        u_m_cken_1 m_cken_1;
        m_cken_1.u32 = readl(M_CTL_RB_M_CLKEN1);
        if (on) {
            writew(M_CTL_RB_MCU_PERP_SPI_CR, 1);
            m_cken_1.bits.spi3_ms_clken = 1;
        } else {
            writew(M_CTL_RB_MCU_PERP_SPI_CR, 0);
            m_cken_1.bits.spi3_ms_clken = 0;
        }
        writew(M_CTL_RB_M_CLKEN1, m_cken_1.u32);
        return;
    }

    if (bus == SPI_BUS_1) {
        u_xip_clken_0 xip_clken_0;
        u_xip_qspi_cr qspi_cr;
        u_glb_clken glb_clken;
        xip_clken_0.u16 = readw(M_CTL_RB_XIP_CLKEN0);
        qspi_cr.u16 = readw(M_CTL_RB_XIP_QSPI_CR);
        glb_clken.u16 = readw(M_CTL_RB_GLB_CLKEN);
        if (on) {
            xip_clken_0.bits.qspi1_div_en = 1;
            xip_clken_0.bits.qspi1_div_clken = 1;
            xip_clken_0.bits.qspi1_clken = 1;
            qspi_cr.bits.xip_qspi_cr_ctrl = 1;
            glb_clken.bits.glb_clken_xip_qspi = 1;
        } else {
            xip_clken_0.bits.qspi1_div_en = 0;
            xip_clken_0.bits.qspi1_div_clken = 0;
            xip_clken_0.bits.qspi1_clken = 0;
            qspi_cr.bits.xip_qspi_cr_ctrl = 0;
            glb_clken.bits.glb_clken_xip_qspi = 0;
        }
        writew(M_CTL_RB_XIP_CLKEN0, xip_clken_0.u16);
        writew(M_CTL_RB_XIP_QSPI_CR, qspi_cr.u16);
        writew(M_CTL_RB_GLB_CLKEN, glb_clken.u16);
    }
}
#endif // CONFIG_DRIVER_SUPPORT_SPI