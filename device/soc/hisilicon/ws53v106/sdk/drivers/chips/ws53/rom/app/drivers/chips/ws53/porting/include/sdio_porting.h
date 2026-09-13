/**
 * Copyright (c) @CompanyNameMagicTag 2023-2023. All rights reserved. \n
 *
 * Description: Provides sdio port template \n
 * Author: @CompanyNameTag \n
 * History: \n
 * 2023-01-17， Create file. \n
 */

#ifndef SDIO_PORT_H
#define SDIO_PORT_H

#include <stdint.h>
#include "common_def.h"
#include "soc_osal.h"

#ifdef __cplusplus
#if __cplusplus
extern "C" {
#endif /* __cplusplus */
#endif /* __cplusplus */

/**
 * @defgroup drivers_port_sdios SDIOS
 * @ingroup  drivers_port
 * @{
 */

/**
 * @brief  Definition of SDIO bus index.
 */
typedef enum sdio_bus {
    SDIO_BUS_0,             /*!< SDIO Bus 0 */
    SDIO_BUS_MAX_NUM
} sdio_bus_t;

#define D2H_MSG_COUNT 32

/* a standard sd card information of cid, csd, scr */
#define SDIO_MEM_CID0_SET     (uint32_t)(0x5600F239)
#define SDIO_MEM_CID1_SET     (uint32_t)(0x1043CA28)
#define SDIO_MEM_CID2_SET     (uint32_t)(0x30303030)
#define SDIO_MEM_CID3_SET     (uint32_t)(0x1B534D30)
#define SDIO_MEM_CSD0_SET     (uint32_t)(0x0A4000A3)
#define SDIO_MEM_CSD1_SET     (uint32_t)(0x775D7F80)
#define SDIO_MEM_CSD2_SET     (uint32_t)(0x5B58F000)
#define SDIO_MEM_CSD3_SET     (uint32_t)(0x400E0011)
#define SDIO_MEM_SCR0_SET     (uint32_t)(0x00000000)
#define SDIO_MEM_SCR1_SET     (uint32_t)(0x02358003)

#define SDIO_RST_CS_REG      0x52000128

/* ADMA description table parameters */
#define SDIO_ADMA_STEP       8
#define SDIO_ADMA_VALID      bit(0)
#define SDIO_ADMA_END        bit(1)
#define SDIO_ADMA_INT        bit(2)
#define SDIO_ADMA_NOP        0
#define SDIO_ADMA_TRAN       bit(5)
#define SDIO_ADMA_LINK       (bit(5) | bit(4))
#define SDIO_ADMA_PARAM_MASK (bit(0) | bit(1) | bit(2) | bit(3) | bit(4) | bit(5))

/* SDIO register setting value, setting CCCR */
#define CCCR_REVISION       3               /* 4Bit 0~3: 1.0, 1.1, 2.0, 3.0, */
#define SDIO_REVISION       (4 << 4)        /* 4Bit 0~4: 1.0, 1.1, 1.2, 2.0, 3.0 */
#define SD_REVISION         (3 << 8)        /* 4Bit 0~3: 1.0, 1.1, 2.0, 3.0, */
#define CCCR_SCSI           (0 << 12)       /* 1Bit Support Continuous SPI interrupt */
#define CCCR_SDC            (1 << 13)       /* 1Bit In the process of data transmission, whether can perform CMD52 */
#define CCCR_SMB            (1 << 14)       /* 1Bit Can be performed in Block way CMD53 */
#define CCCR_SRW            (0 << 15)       /* 1Bit Support the Read Wait Control (RWC) operation */
#define CCCR_SBS            (1 << 16)       /* 1Bit Support Suspend/Resume */
#define CCCR_S4MI           (1 << 17)       /* 1Bit Whether the card supports 4bit multi-block transmission */
#define CCCR_LSC            (0 << 18)       /* 1Bit 1=Low speed card;0=High speed card */
#define CCCR_4BLS           (0 << 19)       /* 1Bit Point out that it is a low-speed card and supports 4bit data */
#define CCCR_SMPC           (1 << 20)       /* 1Bit Card's total current is greater than 200mA */
#define CCCR_SHS            (1 << 21)       /* 1Bit Supports high speed */
#ifdef SDIO_MEM_ONLY_MODE
#define CCCR_MEM_PRE        (1 << 22)       /* 2Bit 0x01(1) Memory card,0x10(2) IO card,0x11(3) Combo card */
#else
#define CCCR_MEM_PRE        (2 << 22)       /* 2Bit 0x01(1) Memory card,0x10(2) IO card,0x11(3) Combo card */
#endif

#define SDIO_ESW_CCCR_SET  (uint32_t) \
    (CCCR_REVISION | SDIO_REVISION | SD_REVISION | CCCR_SCSI | CCCR_SDC | CCCR_SMB | CCCR_SRW | \
     CCCR_SBS | CCCR_S4MI | CCCR_LSC | CCCR_4BLS | CCCR_SMPC | CCCR_SHS | CCCR_MEM_PRE)

/* Set ESW FBR1 Register */
#define IO_DEVICE_CODE1             7
#define FUN_CSA_SUPPORT             0
#define EXT_IO_DEVICE_CODE1         0
#define FBR1_SPS                    0

/* Set IO ACCESS MODE */
#define SSDR50                  1
#define SSDR104                 1
#define SDDR50                  1
#define SDTA                    1
#define SDTC                    1
#define SDTD                    1
#define SAI                     1

/* UHS Support */
#define UHS_SUPPORT             1

#define SDIO_EXTENDREG_COUNT        64

/* The max scatter buffers when device to host */
#define SDIO_DEV2HOST_SCATT_MAX           63

/* the following parameters are used in sdio flash */
#define MAX_ADMA_DESCR_NUM (SDIO_DEV2HOST_SCATT_MAX * 2 + 1 + 1 + 1)

/**
 * @if Eng
 * @brief  Get the base address of a specified SDIO.
 * @param  [in]  bus The sdio bus. see @ref sdio_bus_t
 * @return The base address of specified SDIO.
 * @else
 * @brief  获取指定SDIO的基地址。
 * @param  [in]  bus 串口号， 参考 @ref sdio_bus_t
 * @return 指定SDIO的基地址。
 * @endif
 */
uintptr_t sdio_porting_base_addr_get(sdio_bus_t bus);

/**
 * @if Eng
 * @brief  Register hal funcs objects into hal_sdio module.
 * @param  [in]  bus The sdio bus. see @ref sdio_bus_t
 * @else
 * @brief  将hal funcs对象注册到hal_sdio模块中
 * @param  [in]  bus 串口号， 参考 @ref sdio_bus_t
 * @endif
 */
void sdio_port_register_hal_funcs(sdio_bus_t bus);

/**
 * @if Eng
 * @brief  Unregister hal funcs objects from hal_sdio module.
 * @param  [in]  bus The sdio bus. see @ref sdio_bus_t
 * @else
 * @brief  从hal_sdio模块注销hal funcs对象
 * @param  [in]  bus 串口号， 参考 @ref sdio_bus_t
 * @endif
 */
void sdio_port_unregister_hal_funcs(sdio_bus_t bus);

/**
 * @brief  Lock of pwm interrupt.
 * @param  [in]  bus The sdio bus. see @ref sdio_bus_t
 */
static inline void sdio_irq_lock(sdio_bus_t bus)
{
    unused(bus);
    osal_irq_lock();
}

/**
 * @brief  Unlock of pwm interrupt.
 * @param  [in]  bus The sdio bus. see @ref sdio_bus_t
 */
static inline void sdio_irq_unlock(sdio_bus_t bus)
{
    unused(bus);
    osal_irq_unlock();
}

/**
 * @if Eng
 * @brief  Register the interrupt of SDIO.
 * @param  [in]  bus The sdio bus. see @ref sdio_bus_t
 * @else
 * @brief  注册SDIO中断。
 * @param  [in]  bus 串口号， 参考 @ref sdio_bus_t
 * @endif
 */
void sdio_port_register_irq(sdio_bus_t bus);

/**
 * @if Eng
 * @brief  Unregister the interrupt of SDIO.
 * @param  [in]  bus The sdio bus. see @ref sdio_bus_t
 * @else
 * @brief  去注册SDIO中断。
 * @param  [in]  bus 串口号， 参考 @ref sdio_bus_t
 * @endif
 */
void sdio_port_unregister_irq(sdio_bus_t bus);

/**
 * @if Eng
 * @brief  SDIO soft reset function.
 * @param  [in]  bus The sdio bus. see @ref sdio_bus_t
 * @else
 * @brief  软件复位函数。
 * @param  [in]  bus 串口号， 参考 @ref sdio_bus_t
 * @endif
 */
void sdio_port_soft_reset(sdio_bus_t bus);

/**
 * @if Eng
 * @brief  Get the unused memory of SDIO.
 * @return The unused memory of SDIO.
 * @else
 * @brief  取得结束发送时填充的ADMA表。
 * @return 结束发送时填充的ADMA表。
 * @endif
 */
uint8_t* sdio_port_get_unused_mem(void);

/**
 * @if Eng
 * @brief  Get the padding memory of SDIO.
 * @return The padding memory of SDIO.
 * @else
 * @brief  取得配置数据对齐后的ADMA表。
 * @return 配置数据对齐后的ADMA表。
 * @endif
 */
uint8_t* sdio_port_get_padding_mem(void);

/**
 * @}
 */

#ifdef __cplusplus
#if __cplusplus
}
#endif /* __cplusplus */
#endif /* __cplusplus */

#endif