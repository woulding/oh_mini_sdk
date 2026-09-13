/**
 * Copyright (c) HiSilicon (Shanghai) Technologies Co., Ltd. 2024-2024. All rights reserved.
 *
 * Description: Provides v151_100 spi adapt, qspi_v151_100 origin from spi_v100, spi_v151_100 origin from spi_v151. \n
 */
#ifndef HAL_SPI_V151_100_ADAPT_OP_H
#define HAL_SPI_V151_100_ADAPT_OP_H

#include <stdint.h>
#include "common_def.h"
#include "hal_spi.h"
#include "hal_qspi_v151_100_regs_op.h"
#include "hal_spi_v151_100_regs_op.h"

#ifdef __cplusplus
#if __cplusplus
extern "C" {
#endif /* __cplusplus */
#endif /* __cplusplus */

/**
 * @defgroup drivers_hal_spi_v151_100_adapt_op SPI v151_100 Regs Operation Adapt
 * @ingroup  drivers_hal_spi
 * @{
 */

/**
 * @brief  Get the value of @ref ctrlr0_data.spi_frf.
 * @param  [in]  bus The index of ssi.
 * @return The value of @ref ctrlr0_data.spi_frf.
 */
static inline uint32_t hal_spi_v151_100_ctrlr0_get_spi_frf(spi_bus_t bus)
{
    if (bus <= SPI_BUS_MAX) {
        return hal_spi0_v151_100_spi_ctra_get_enhff(bus);
    } else {
        return hal_qspi_v151_100_ctrlr0_get_spi_frf(bus);
    }
}

/**
 * @brief  Get the value of @ref sr_data.tfe.
 * @param  [in]  bus The index of ssi.
 * @return The value of @ref sr_data.tfe.
 */
static inline uint32_t hal_spi_v151_100_sr_get_tfe(spi_bus_t bus)
{
    if (bus <= SPI_BUS_MAX) {
        return hal_spi0_v151_100_spi_wsr_get_tfe(bus);
    } else {
        return hal_qspi_v151_100_sr_get_tfe(bus);
    }
}

/**
 * @brief  Get the value of @ref sr_data.rfne.
 * @param  [in]  bus The index of ssi.
 * @return The value of @ref sr_data.rfne.
 */
static inline uint32_t hal_spi_v151_100_sr_get_rfne(spi_bus_t bus)
{
    if (bus <= SPI_BUS_MAX) {
        return hal_spi0_v151_100_spi_wsr_get_rfne(bus);
    } else {
        return hal_qspi_v151_100_sr_get_rfne(bus);
    }
}

/**
 * @brief  Set the value of @ref spi_ctrlr0_data.trans_type.
 * @param  [in]  bus The index of uart.
 * @param  [in]  val The value of @ref spi_ctrlr0_data.trans_type.
 */
static inline void hal_spi_v151_100_spi_ctrlr0_set_trans_type(spi_bus_t bus, uint32_t val)
{
    if (bus <= SPI_BUS_MAX) {
        hal_spi0_v151_100_spi_enhctl_set_aaitf(bus, val);
    } else {
        hal_qspi_v151_100_spi_ctrlr0_set_trans_type(bus, val);
    }
}

/**
 * @brief  Set the value of @ref spi_ctrlr0_data.inst_l.
 * @param  [in]  bus The index of uart.
 * @param  [in]  val The value of @ref spi_ctrlr0_data.inst_l.
 */
static inline void hal_spi_v151_100_spi_ctrlr0_set_inst_l(spi_bus_t bus, uint32_t val)
{
    if (bus <= SPI_BUS_MAX) {
        hal_spi0_v151_100_spi_enhctl_set_ilen(bus, val);
    } else {
        hal_qspi_v151_100_spi_ctrlr0_set_inst_l(bus, val);
    }
}

/**
 * @brief  Set the value of @ref spi_ctrlr0_data.addr_l.
 * @param  [in]  bus The index of uart.
 * @param  [in]  val The value of @ref spi_ctrlr0_data.addr_l.
 */
static inline void hal_spi_v151_100_spi_ctrlr0_set_addr_l(spi_bus_t bus, uint32_t val)
{
    if (bus <= SPI_BUS_MAX) {
        hal_spi0_v151_100_spi_enhctl_set_addrlen(bus, val);
    } else {
        hal_qspi_v151_100_spi_ctrlr0_set_addr_l(bus, val);
    }
}

/**
 * @brief  Set the value of @ref spi_ctrlr0_data.wait_cycles.
 * @param  [in]  bus The index of uart.
 * @param  [in]  val The value of @ref spi_ctrlr0_data.wait_cycles.
 */
static inline void hal_spi_v151_100_spi_ctrlr0_set_wait_cycles(spi_bus_t bus, uint32_t val)
{
    if (bus <= SPI_BUS_MAX) {
        hal_spi0_v151_100_spi_enhctl_set_waitnum(bus, val);
    } else {
        hal_qspi_v151_100_spi_ctrlr0_set_wait_cycles(bus, val);
    }
}

/**
 * @brief  Set the value of rsvd.
 * @param  [in]  bus The index of ssi.
 * @param  [in]  val The value of rsvd.
 */
static inline void hal_spi_v151_100_rsvd_set(spi_bus_t bus, uint32_t val)
{
    if (bus <= SPI_BUS_MAX) {
        hal_spi0_v151_100_spi_rsvd_set(bus, val);
    } else {
        hal_qspi_v151_100_rsvd_set(bus, val);
    }
}

/**
 * @brief  Set the value of @ref ctrlr0_data.spi_frf.
 * @param  [in]  bus The index of ssi.
 * @param  [in]  val The value of @ref ctrlr0_data.spi_frf.
 */
static inline void hal_spi_v151_100_ctrlr0_set_spi_frf(spi_bus_t bus, uint32_t val)
{
    if (bus <= SPI_BUS_MAX) {
        hal_spi0_v151_100_spi_ctra_set_enhff(bus, val);
    } else {
        hal_qspi_v151_100_ctrlr0_set_spi_frf(bus, val);
    }
}

/**
 * @brief  Set the value of @ref ctrlr1_data.ndf.
 * @param  [in]  bus The index of ssi.
 * @param  [in]  val The value of @ref ctrlr1_data.ndf.
 */
static inline void hal_spi_v151_100_ctrlr1_set_ndf(spi_bus_t bus, uint32_t val)
{
    if (bus <= SPI_BUS_MAX) {
        hal_spi0_v151_100_spi_ctrb_set_nrdf(bus, val);
    } else {
        hal_qspi_v151_100_ctrlr1_set_ndf(bus, val);
    }
}

/**
 * @brief  Set the value of @ref ctrlr0_data.
 * @param  [in]  bus The index of ssi.
 * @param  [in]  val The value of @ref ctrlr0_data.
 */
static inline void hal_spi_v151_100_ctrlr0_set(spi_bus_t bus, uint32_t val)
{
    if (bus <= SPI_BUS_MAX) {
        hal_spi0_v151_100_spi_ctra_set(bus, val);
    } else {
        hal_qspi_v151_100_ctrlr0_set(bus, val);
    }
}

/**
 * @brief  Set the value of @ref spi_ctrlr0_data.
 * @param  [in]  bus The index of uart.
 * @param  [in]  val The value of @ref spi_ctrlr0_data.
 */
static inline void hal_spi_v151_100_spi_ctrlr0_set(spi_bus_t bus, uint32_t val)
{
    if (bus <= SPI_BUS_MAX) {
        hal_spi0_v151_100_spi_enhctl_set(bus, val);
    } else {
        hal_qspi_v151_100_spi_ctrlr0_set(bus, val);
    }
}

/**
 * @brief  Set the value of @ref ctrlr0_data.frf.
 * @param  [in]  bus The index of ssi.
 * @param  [in]  val The value of @ref ctrlr0_data.frf.
 */
static inline void hal_spi_v151_100_ctrlr0_set_frf(spi_bus_t bus, uint32_t val)
{
    if (bus <= SPI_BUS_MAX) {
        hal_spi0_v151_100_spi_ctra_set_prs(bus, val);
    } else {
        hal_qspi_v151_100_ctrlr0_set_frf(bus, val);
    }
}

/**
 * @brief  Get the value of @ref sr_data.rff.
 * @param  [in]  bus The index of ssi.
 * @return The value of @ref sr_data.rff.
 */
static inline uint32_t hal_spi_v151_100_sr_get_rff(spi_bus_t bus)
{
    if (bus <= SPI_BUS_MAX) {
        return hal_spi0_v151_100_spi_wsr_get_rffe(bus);
    } else {
        return hal_qspi_v151_100_sr_get_rff(bus);
    }
}

/**
 * @brief  Set the value of @ref ctrlr0_data.scph.
 * @param  [in]  bus The index of ssi.
 * @param  [in]  val The value of @ref ctrlr0_data.scph.
 */
static inline void hal_spi_v151_100_ctrlr0_set_scph(spi_bus_t bus, uint32_t val)
{
    if (bus <= SPI_BUS_MAX) {
        hal_spi0_v151_100_spi_ctra_set_scph(bus, val);
    } else {
        hal_qspi_v151_100_ctrlr0_set_scph(bus, val);
    }
}

/**
 * @brief  Set the value of @ref ctrlr0_data.scpol.
 * @param  [in]  bus The index of ssi.
 * @param  [in]  val The value of @ref ctrlr0_data.scpol.
 */
static inline void hal_spi_v151_100_ctrlr0_set_scpol(spi_bus_t bus, uint32_t val)
{
    if (bus <= SPI_BUS_MAX) {
        hal_spi0_v151_100_spi_ctra_set_scpol(bus, val);
    } else {
        hal_qspi_v151_100_ctrlr0_set_scpol(bus, val);
    }
}

/**
 * @brief  Set the value of @ref ctrlr0_data.dfs_32.
 * @param  [in]  bus The index of ssi.
 * @param  [in]  val The value of @ref ctrlr0_data.dfs_32.
 */
static inline void hal_spi_v151_100_ctrlr0_set_dfs_32(spi_bus_t bus, uint32_t val)
{
    if (bus <= SPI_BUS_MAX) {
        hal_spi0_v151_100_spi_ctra_set_dfs32(bus, val);
    } else {
        hal_qspi_v151_100_ctrlr0_set_dfs_32(bus, val);
    }
}

/**
 * @brief  Set the value of @ref ctrlr0_data.cfs.
 * @param  [in]  bus The index of ssi.
 * @param  [in]  val The value of @ref ctrlr0_data.cfs.
 */
static inline void hal_spi_v151_100_ctrlr0_set_cfs(spi_bus_t bus, uint32_t val)
{
    if (bus <= SPI_BUS_MAX) {
        hal_spi0_v151_100_spi_ctra_set_cfs16(bus, val);
    } else {
        hal_qspi_v151_100_ctrlr0_set_cfs(bus, val);
    }
}

/**
 * @brief  Set the value of @ref ctrlr0_data.tmod.
 * @param  [in]  bus The index of ssi.
 * @param  [in]  val The value of @ref ctrlr0_data.tmod.
 */
static inline void hal_spi_v151_100_ctrlr0_set_tmod(spi_bus_t bus, uint32_t val)
{
    if (bus <= SPI_BUS_MAX) {
        hal_spi0_v151_100_spi_ctra_set_trsm(bus, val);
    } else {
        hal_qspi_v151_100_ctrlr0_set_tmod(bus, val);
    }
}

/**
 * @brief  Set the value of @ref mwcr_data.mdd.
 * @param  [in]  bus The index of ssi.
 * @param  [in]  val The value of @ref mwcr_data.mdd.
 */
static inline void hal_spi_v151_100_mwcr_set_mdd(spi_bus_t bus, uint32_t val)
{
    if (bus <= SPI_BUS_MAX) {
        hal_spi0_v151_100_spi_mcr_set_mtrc(bus, val);
    } else {
        hal_qspi_v151_100_mwcr_set_mdd(bus, val);
    }
}

/**
 * @brief  Set the value of @ref ctrlr0_data.sste.
 * @param  [in]  bus The index of ssi.
 * @param  [in]  val The value of @ref ctrlr0_data.sste.
 */
static inline void hal_spi_v151_100_ctrlr0_set_sste(spi_bus_t bus, uint32_t val)
{
    if (bus <= SPI_BUS_MAX) {
        hal_spi0_v151_100_spi_ctra_set_ssn_te(bus, val);
    } else {
        hal_qspi_v151_100_ctrlr0_set_sste(bus, val);
    }
}

/**
 * @brief  Set the value of @ref interrupt_data
 * @param  [in]  bus The index of ssi.
 * @param  [in]  reg The register need to set.
 * @param  [in]  val The value of @ref interrupt_data.
 */
static inline void hal_spi_v151_100_int_set(spi_bus_t bus, spi_v151_100_int_reg_t reg, uint32_t val)
{
    if (bus <= SPI_BUS_MAX) {
        hal_spi0_v151_100_int_set(bus, reg, val);
    } else {
        hal_qspi_v151_100_int_set(bus, reg, val);
    }
}

/**
 * @brief  Get the value of @ref spi_ctrlr0_data.inst_l.
 * @param  [in]  bus The index of ssi.
 * @return The value of @ref spi_ctrlr0_data.inst_l.
 */
static inline uint32_t hal_spi_v151_100_spi_ctrlr0_get_inst_l(spi_bus_t bus)
{
    if (bus <= SPI_BUS_MAX) {
        return hal_spi0_v151_100_spi_enhctl_get_ilen(bus);
    } else {
        return hal_qspi_v151_100_spi_ctrlr0_get_inst_l(bus);
    }
}

/**
 * @brief  Get the value of @ref spi_ctrlr0_data.addr_l.
 * @param  [in]  bus The index of ssi.
 * @return The value of @ref spi_ctrlr0_data.addr_l.
 */
static inline uint32_t hal_spi_v151_100_spi_ctrlr0_get_addr_l(spi_bus_t bus)
{
    if (bus <= SPI_BUS_MAX) {
        return hal_spi0_v151_100_spi_enhctl_get_addrlen(bus);
    } else {
        return hal_qspi_v151_100_spi_ctrlr0_get_addr_l(bus);
    }
}

/**
 * @brief  Get the value of @ref sr_data.tfnf.
 * @param  [in]  bus The index of ssi.
 * @return The value of @ref sr_data.tfnf.
 */
static inline uint32_t hal_spi_v151_100_sr_get_tfnf(spi_bus_t bus)
{
    if (bus <= SPI_BUS_MAX) {
        return hal_spi0_v151_100_spi_wsr_get_tfnf(bus);
    } else {
        return hal_qspi_v151_100_sr_get_tfnf(bus);
    }
}

/**
 * @brief  Get the value of @ref ctrlr0_data.tmod.
 * @param  [in]  bus The index of ssi.
 * @return The value of @ref ctrlr0_data.tmod.
 */
static inline uint32_t hal_spi_v151_100_ctrlr0_get_tmod(spi_bus_t bus)
{
    if (bus <= SPI_BUS_MAX) {
        return hal_spi0_v151_100_spi_ctra_get_trsm(bus);
    } else {
        return hal_qspi_v151_100_ctrlr0_get_tmod(bus);
    }
}

/**
 * @brief  Get the value of @ref ctrlr0_data.dfs_32.
 * @param  [in]  bus The index of ssi.
 * @return The value of @ref ctrlr0_data.dfs_32.
 */
static inline uint32_t hal_spi_v151_100_ctrlr0_get_dfs_32(spi_bus_t bus)
{
    if (bus <= SPI_BUS_MAX) {
        return hal_spi0_v151_100_spi_ctra_get_dfs32(bus);
    } else {
        return hal_qspi_v151_100_ctrlr0_get_dfs_32(bus);
    }
}

/**
 * @brief  Set the value of @ref dmacr_data.tdmae.
 * @param  [in]  bus The index of uart.
 * @param  [in]  val The value of @ref dmacr_data.tdmae.
 */
static inline void hal_spi_v151_100_dmacr_set_tdmae(spi_bus_t bus, uint32_t val)
{
    if (bus <= SPI_BUS_MAX) {
        hal_spi0_v151_100_spi_dcr_set_tden(bus, val);
    } else {
        hal_qspi_v151_100_dmacr_set_tdmae(bus, val);
    }
}

/**
 * @brief  Set the value of dmatdl @ref dmatdlr_data_t.
 * @param  [in]  bus The index of uart.
 * @param  [in]  val The value of dmatdl @ref dmatdlr_data_t.
 */
static inline void hal_spi_v151_100_dmatdlr_set_dmatdl(spi_bus_t bus, uint32_t val)
{
    if (bus <= SPI_BUS_MAX) {
        hal_spi0_v151_100_spi_dtdl_data_set_dl(bus, val);
    } else {
        hal_qspi_v151_100_dmatdlr_set_dmatdl(bus, val);
    }
}

/**
 * @brief  Set the value of @ref imr_data_t.rxfi.
 * @param  [in]  bus The index of uart.
 * @param  [in]  val The value of @ref imr_data_t.rxfi.
 */
static inline void hal_spi_v151_100_imr_set_rxfi(spi_bus_t bus, uint32_t val)
{
    if (bus <= SPI_BUS_MAX) {
        hal_spi0_v151_100_spi_inmar_set_rffis(bus, val);
    } else {
        hal_qspi_v151_100_imr_set_rxfi(bus, val);
    }
}

/**
 * @brief  Set the value of @ref imr_data_t.txei.
 * @param  [in]  bus The index of uart.
 * @param  [in]  val The value of @ref imr_data_t.txei.
 */
static inline void hal_spi_v151_100_imr_set_txei(spi_bus_t bus, uint32_t val)
{
    if (bus <= SPI_BUS_MAX) {
        hal_spi0_v151_100_spi_inmar_set_tfeis(bus, val);
    } else {
        hal_qspi_v151_100_imr_set_txei(bus, val);
    }
}

/**
 * @brief  Get the value of @ref isr_data_t.rxfi.
 * @param  [in]  bus The index of ssi.
 * @param  [in]  reg The register need to get.
 * @return The value of @ref isr_data_t.rxfi.
 */
static inline uint32_t hal_spi_v151_100_isr_get_rxfi(spi_bus_t bus, spi_v151_100_int_reg_t reg)
{
    if (bus <= SPI_BUS_MAX) {
        return hal_spi0_v151_100_int_get_rffis(bus, reg);
    } else {
        return hal_qspi_v151_100_isr_get_rxfi(bus);
    }
}

/**
 * @brief  Get the value of @ref isr_data_t.rxui.
 * @param  [in]  bus The index of ssi.
 * @param  [in]  reg The register need to get.
 * @return The value of @ref isr_data_t.rxui.
 */
static inline uint32_t hal_spi_v151_100_isr_get_rxui(spi_bus_t bus, spi_v151_100_int_reg_t reg)
{
    if (bus <= SPI_BUS_MAX) {
        return hal_spi0_v151_100_int_get_rfufis(bus, reg);
    } else {
        return hal_qspi_v151_100_isr_get_rxui(bus);
    }
}

/**
 * @brief  Get the value of @ref isr_data_t.rxoi.
 * @param  [in]  bus The index of ssi.
 * @param  [in]  reg The register need to get.
 * @return The value of @ref isr_data_t.rxoi.
 */
static inline uint32_t hal_spi_v151_100_isr_get_rxoi(spi_bus_t bus, spi_v151_100_int_reg_t reg)
{
    if (bus <= SPI_BUS_MAX) {
        return hal_spi0_v151_100_int_get_rfofis(bus, reg);
    } else {
        return hal_qspi_v151_100_isr_get_rxoi(bus);
    }
}

/**
 * @brief  Get the value of @ref isr_data_t.txei.
 * @param  [in]  bus The index of ssi.
 * @param  [in]  reg The register need to get.
 * @return The value of @ref isr_data_t.txei.
 */
static inline uint32_t hal_spi_v151_100_isr_get_txei(spi_bus_t bus, spi_v151_100_int_reg_t reg)
{
    if (bus <= SPI_BUS_MAX) {
        return hal_spi0_v151_100_int_get_tfeis(bus, reg);
    } else {
        return hal_qspi_v151_100_isr_get_txei(bus);
    }
}

/**
 * @brief  Get the value of @ref isr_data_t.txoi.
 * @param  [in]  bus The index of ssi.
 * @param  [in]  reg The register need to get.
 * @return The value of @ref isr_data_t.txoi.
 */
static inline uint32_t hal_spi_v151_100_isr_get_txoi(spi_bus_t bus, spi_v151_100_int_reg_t reg)
{
    if (bus <= SPI_BUS_MAX) {
        return hal_spi0_v151_100_int_get_tfofis(bus, reg);
    } else {
        return hal_qspi_v151_100_isr_get_txoi(bus);
    }
}

/**
 * @brief  Get the value of @ref isr_data_t.msti.
 * @param  [in]  bus The index of ssi.
 * @param  [in]  reg The register need to get.
 * @return The value of @ref isr_data_t.msti.
 */
static inline uint32_t hal_spi_v151_100_isr_get_msti(spi_bus_t bus, spi_v151_100_int_reg_t reg)
{
    if (bus <= SPI_BUS_MAX) {
        return hal_spi0_v151_100_int_get_mmcris(bus, reg);
    } else {
        return hal_qspi_v151_100_isr_get_msti(bus);
    }
}

/**
 * @brief  Set the value of @ref icr_data_t.icr.
 * @param  [in]  bus The index of uart.
 */
static inline void hal_spi_v151_100_icr_set_any(spi_bus_t bus)
{
    if (bus <= SPI_BUS_MAX) {
        hal_spi0_v151_100_icr_set_any(bus);
    } else {
        hal_qspi_v151_100_icr_set_any(bus);
    }
}

/**
 * @brief  Set the value of @ref ssienr_data.ssi_en.
 * @param  [in]  bus The index of ssi.
 * @param  [in]  val The value of @ref ssienr_data.ssi_en.
 */
static inline void hal_spi_v151_100_ssienr_set_ssi_en(spi_bus_t bus, uint32_t val)
{
    if (bus <= SPI_BUS_MAX) {
        hal_spi0_v151_100_ssienr_set_ssi_en(bus, val);
    } else {
        hal_qspi_v151_100_ssienr_set_ssi_en(bus, val);
    }
}

/**
 * @brief  Get the value of @ref sr_data.busy.
 * @param  [in]  bus The index of ssi.
 * @return The value of @ref sr_data.busy.
 */
static inline uint32_t hal_spi_v151_100_sr_get_busy(spi_bus_t bus)
{
    if (bus <= SPI_BUS_MAX) {
        return hal_spi0_v151_100_sr_get_busy(bus);
    } else {
        return hal_qspi_v151_100_sr_get_busy(bus);
    }
}

/**
 * @brief  Set the value of @ref baudr_data.sckdv.
 * @param  [in]  bus The index of ssi.
 * @param  [in]  val The value of @ref baudr_data.sckdv.
 */
static inline void hal_spi_v151_100_baudr_set_sckdv(spi_bus_t bus, uint32_t val)
{
    if (bus <= SPI_BUS_MAX) {
        hal_spi0_v151_100_baudr_set_sckdv(bus, val);
    } else {
        hal_qspi_v151_100_baudr_set_sckdv(bus, val);
    }
}

/**
 * @brief  Set the value of @ref ser_data.ser.
 * @param  [in]  bus The index of ssi.
 * @param  [in]  val The value of @ref ser_data.ser.
 */
static inline void hal_spi_v151_100_ser_set_ser(spi_bus_t bus, uint32_t val)
{
    if (bus <= SPI_BUS_MAX) {
        hal_spi0_v151_100_ser_set_ser(bus, val);
    } else {
        hal_qspi_v151_100_ser_set_ser(bus, val);
    }
}

/**
 * @brief  Set the value of @ref dmacr_data.rdmae.
 * @param  [in]  bus The index of uart.
 * @param  [in]  val The value of @ref dmacr_data.rdmae.
 */
static inline void hal_spi_v151_100_dmacr_set_rdmae(spi_bus_t bus, uint32_t val)
{
    if (bus <= SPI_BUS_MAX) {
        hal_spi0_v151_100_dmacr_set_rdmae(bus, val);
    } else {
        hal_qspi_v151_100_dmacr_set_rdmae(bus, val);
    }
}

/**
 * @brief  Set the value of dmardl @ref dmardlr_data_t.
 * @param  [in]  bus The index of uart.
 * @param  [in]  val The value of dmardl @ref dmardlr_data_t.
 */
static inline void hal_spi_v151_100_dmardlr_set_dmardl(spi_bus_t bus, uint32_t val)
{
    if (bus <= SPI_BUS_MAX) {
        hal_spi0_v151_100_dmardlr_set_dmardl(bus, val);
    } else {
        hal_qspi_v151_100_dmardlr_set_dmardl(bus, val);
    }
}

#if defined(CONFIG_SPI_SUPPORT_DMA) && (CONFIG_SPI_SUPPORT_DMA == 1)
static inline errcode_t hal_spi_v151_100_ctrl_get_dma_data_addr(spi_bus_t bus, hal_spi_ctrl_id_t id, uintptr_t param)
{
    unused(id);
    uint32_t *addr = (uint32_t *)param;
    if (bus <= SPI_BUS_MAX) {
        *addr = (uint32_t)(uintptr_t)(&(spis_v151_100_regs(bus)->spi_drnm[0]));
    } else {
        *addr = (uint32_t)(uintptr_t)(&(qspis_v151_100_regs(bus)->dr[0]));
    }
    return ERRCODE_SUCC;
}
#endif  /* CONFIG_SPI_SUPPORT_DMA */

/**
 * @brief  Set data into data register.
 * @param  [in]  bus The index of ssi.
 * @param  [in]  val The data need to set into data register.
 */
static inline void hal_spi_v151_100_dr_set_dr(spi_bus_t bus, uint32_t val)
{
    if (bus <= SPI_BUS_MAX) {
        hal_spi0_v151_100_dr_set_dr(bus, val);
    } else {
        hal_qspi_v151_100_dr_set_dr(bus, val);
    }
}

/**
 * @brief  Set the value of @ref txftlr_data.tft.
 * @param  [in]  bus The index of ssi.
 * @param  [in]  val The value of @ref txftlr_data.tft.
 */
static inline void hal_spi_v151_100_txftlr_set_tft(spi_bus_t bus, uint32_t val)
{
    if (bus <= SPI_BUS_MAX) {
        hal_spi0_v151_100_txftlr_set_tft(bus, val);
    } else {
        hal_qspi_v151_100_txftlr_set_tft(bus, val);
    }
}

/**
 * @brief  Set the value of @ref rxftlr_data.rft.
 * @param  [in]  bus The index of ssi.
 * @param  [in]  val The value of @ref rxftlr_data.rft.
 */
static inline void hal_spi_v151_100_rxftlr_set_rft(spi_bus_t bus, uint32_t val)
{
    if (bus <= SPI_BUS_MAX) {
        hal_spi0_v151_100_rxftlr_set_rft(bus, val);
    } else {
        hal_qspi_v151_100_rxftlr_set_rft(bus, val);
    }
}

/**
 * @brief  Get data from data register.
 * @param  [in]  bus The index of ssi.
 * @return The data from data register.
 */
static inline uint32_t hal_spi_v151_100_dr_get_dr(spi_bus_t bus)
{
    if (bus <= SPI_BUS_MAX) {
        return hal_spi0_v151_100_dr_get_dr(bus);
    } else {
        return hal_qspi_v151_100_dr_get_dr(bus);
    }
}

/**
 * @brief  Get the value of @ref rxflr_data.rxtfl.
 * @param  [in]  bus The index of ssi.
 * @return The value of @ref rxflr_data.rxtfl.
 */
static inline uint32_t hal_spi_v151_100_rxflr_get_rxtfl(spi_bus_t bus)
{
    if (bus <= SPI_BUS_MAX) {
        return hal_spi0_v151_100_rxflr_get_rxtfl(bus);
    } else {
        return hal_qspi_v151_100_rxflr_get_rxtfl(bus);
    }
}

/**
 * @}
 */

#ifdef __cplusplus
#if __cplusplus
}
#endif /* __cplusplus */
#endif /* __cplusplus */

#endif