/*
 * Copyright (c) HiSilicon (Shanghai) Technologies Co., Ltd. 2022-2023. All rights reserved.
 * Description:  Application Core Platform Definitions
 *
 * Create:  2022-06-16
 */

#ifndef PLATFORM_CORE_H
#define PLATFORM_CORE_H

#include "product.h"
#include "chip_core_definition.h"

/**
 * @defgroup DRIVER_PLATFORM_CORE CHIP Platform CORE Driver
 * @ingroup DRIVER_PLATFORM
 * @{
 */
#ifdef TARGET_CONTROL_MASTER_CODE
extern unsigned int _g_logbuff_start;
#define LOGGING_REGION_START _g_logbuff_start
#endif

/* patch cfg base addr & patch nums cfg */
#define RISCV31_PATCH_FLPCTRL    0xB0000000
#define RISCV31_PATCH_I_NUM      160    // 指令 patch 的数量 (芯片规格)
#define RISCV31_PATCH_L_NUM      2      // 数据 patch 的数量 (芯片规格)
#define RISCV31_PATCH_NUM        162    // 指令 patch + 数据 patch 的数量 (可根据实际使用数量调整)

#define DISPLAY_CTL_RB_BASE      0x56000000
#define GPU_BASE_ADDR            0x56200000
#define DSS_BASE_ADDR            0x56100000

#define B_CTL_RB_BASE            0x59000000
#define M_CTL_RB_BASE            0x52000000
#define COM_CTL_RB_BASE          0x55000000
#define PMU1_CTL_RB_BASE         0x57004000
#define ULP_AON_CTL_RB_ADDR      0x57030000
#define XIP_CACHE_CTL            0xA3006000
#define NMI_CTL_REG_BASE_ADDR    0x59000300

#define FLASH_START_ADDR 0x10000000

#define SFC_FLASH_START_ADDR    0x00400000
#define SFC_FLASH_END_ADDR      0x013FFFFF

#define DMA_BASE_ADDR  0x52070000 /* M_DMA */
#define SDMA_BASE_ADDR 0x520A0000 /* S_DMA */

/* I2C reg base addr */
#define I2C_BUS_0_BASE_ADDR 0x52083000
#define I2C_BUS_1_BASE_ADDR 0x52084000
#define I2C_BUS_2_BASE_ADDR 0x52085000
#define I2C_BUS_3_BASE_ADDR 0x52086000
#define I2C_BUS_4_BASE_ADDR 0x52087000

/* spi reg base addr */
#define SPI_BUS_0_BASE_ADDR 0x52088000 // SPI_M0
#define SPI_BUS_1_BASE_ADDR 0x52089000 // SPI_MS_1
#define SPI_BUS_2_BASE_ADDR 0x5208A000 // SPI_MS_2
#define SPI_BUS_3_BASE_ADDR 0x5208B000 // SPI_MS_3
#define SPI_BUS_4_BASE_ADDR 0x5208C000 // SPI_S_4
#define SPI_BUS_5_BASE_ADDR 0xA3000000 // QSPI_0
#define SPI_BUS_6_BASE_ADDR 0xA3002000 // QSPI_1

#define I2S_BUS_0_BASE_ADDR 0x5203003c

#define DMA_HANDSHAKE_SPI_BUS_0_TX HAL_DMA_HANDSHAKING_SPI_M_TX
#define DMA_HANDSHAKE_SPI_BUS_0_RX HAL_DMA_HANDSHAKING_SPI_M_RX
#define DMA_HANDSHAKE_SPI_BUS_1_TX HAL_DMA_HANDSHAKING_SPI_MS0_TX
#define DMA_HANDSHAKE_SPI_BUS_1_RX HAL_DMA_HANDSHAKING_SPI_MS0_RX
#define DMA_HANDSHAKE_SPI_BUS_2_TX HAL_DMA_HANDSHAKING_SPI_MS1_TX
#define DMA_HANDSHAKE_SPI_BUS_2_RX HAL_DMA_HANDSHAKING_SPI_MS1_RX
#define DMA_HANDSHAKE_SPI_BUS_3_TX HAL_DMA_HANDSHAKING_SPI3_M_TX
#define DMA_HANDSHAKE_SPI_BUS_3_RX HAL_DMA_HANDSHAKING_SPI3_M_RX
#define DMA_HANDSHAKE_SPI_BUS_4_TX HAL_DMA_HANDSHAKING_SPI4_S_RX  // SPI4 can only function as the slave device.
#define DMA_HANDSHAKE_SPI_BUS_4_RX HAL_DMA_HANDSHAKING_SPI4_S_RX
#define DMA_HANDSHAKE_SPI_BUS_5_TX HAL_DMA_HANDSHAKING_QSPI0_2CS_TX
#define DMA_HANDSHAKE_SPI_BUS_5_RX HAL_DMA_HANDSHAKING_QSPI0_2CS_RX
#define DMA_HANDSHAKE_SPI_BUS_6_TX HAL_DMA_HANDSHAKING_QSPI1_2CS_TX
#define DMA_HANDSHAKE_SPI_BUS_6_RX HAL_DMA_HANDSHAKING_QSPI1_2CS_RX

#define DMA_HANDSHAKE_I2C_BUS_0_TX HAL_DMA_HANDSHAKING_I2C0_TX
#define DMA_HANDSHAKE_I2C_BUS_0_RX HAL_DMA_HANDSHAKING_I2C0_RX
#define DMA_HANDSHAKE_I2C_BUS_1_TX HAL_DMA_HANDSHAKING_I2C1_TX
#define DMA_HANDSHAKE_I2C_BUS_1_RX HAL_DMA_HANDSHAKING_I2C1_RX
#define DMA_HANDSHAKE_I2C_BUS_2_TX HAL_DMA_HANDSHAKING_I2C2_TX
#define DMA_HANDSHAKE_I2C_BUS_2_RX HAL_DMA_HANDSHAKING_I2C2_RX
#define DMA_HANDSHAKE_I2C_BUS_3_TX HAL_DMA_HANDSHAKING_I2C3_TX
#define DMA_HANDSHAKE_I2C_BUS_3_RX HAL_DMA_HANDSHAKING_I2C3_RX
#define DMA_HANDSHAKE_I2C_BUS_4_TX HAL_DMA_HANDSHAKING_I2C4_TX
#define DMA_HANDSHAKE_I2C_BUS_4_RX HAL_DMA_HANDSHAKING_I2C4_RX

#define HAL_SPI_DEVICE_MODE_SET_REG   (*(volatile unsigned short *)(0x52000828))
#define HAL_SPI3_MODE_SET_REG         (M_CTL_RB_BASE + 0x950)

#define HAL_IPC_SOFT_RST_N       0x59000618
#define IPC_SOFT_RST_VALUE       0x1


// GPIO select core
#define HAL_GPIO_CORE_SET_CHANNEL_OFFSET    0x08
#define HAL_GPIO_CORE_SET_REG_OFFSET        2
#define HAL_GPIO_CORE_SET_GPIOS             16

// ULP GPIO int clk config
#define HAL_GPIO_ULP_AON_PCLK_INT_EN_BIT        0
#define HAL_GPIO_ULP_AON_PCLK_INT_CLK_SEL_BIT   1
#define HAL_GPIO_ULP_PCLK_INTR_STATUS_BITS      0x3

// RTC reg base addr.
#define RTC_BASE_ADDR        0x5702A000
#define RTC_0_BASE_ADDR      (RTC_BASE_ADDR + 0x100)
#define RTC_1_BASE_ADDR      (RTC_BASE_ADDR + 0x200)

#define SYSTICK_BASE_ADDR    0x57030330

#define TCXO_COUNT_BASE_ADDR 0x57000214

#define CHIP_WDT_BASE_ADDRESS 0x59005000
#define HAL_SOFT_RST_CTL_BASE               (B_CTL_RB_BASE)
#define HAL_GLB_CTL_M_ATOP1_L_REG_OFFSET    0x60
#define HAL_CHIP_WDT_ATOP1_RST_BIT          3

// SEC BASE ADDR
#define SEC_CTL_RB_BASE 0x52009000
#define RSAV2_S_RB_BASE 0x52009900
#define TRNG_RB_BASE 0x52009800

// Timer reg base addr.
#define TIMER_BASE_ADDR                         0x59004000
#define TIMER_0_BASE_ADDR                       (TIMER_BASE_ADDR + 0x100)
#define TIMER_1_BASE_ADDR                       (TIMER_BASE_ADDR + 0x200)
#define TIMER_2_BASE_ADDR                       (TIMER_BASE_ADDR + 0x300)

// cpu trace memory
#define TRACE_MEM_REGION_START                  MCPU_TRACE_MEM_REGION_START
#define TRACE_MEM_REGION_LENGTH                 CPU_TRACE_MEM_REGION_LENGTH

/*
 * Maximum UART buses
 * Defined here rather than in the uart_bus_t enum, due to needing to use it for conditional compilation
 */
#define I2C_BUS_MAX_NUMBER  2  // !< Max number of I2C available
#define TIMER_MAX_AVAILABLE_NUMBER    2  // !< Max number of timer available
#define RTC_MAX_AVAILABLE_NUMBER      2  // !< Max number of rtc available

#define SPI_BUS_MAX_NUMBER  7  // !< Max number of SPI available
#define GPIO_MAX_NUMBER     3  // !< Max number of GPIO available

#define PDM_PIN_DATA          S_MGPIO30
#define PDM_PIN_CLK           S_MGPIO31

#define PDM_PIO_FUNC_DATA     HAL_PIO_DMIC_DIN
#define PDM_PIO_FUNC_CLK      HAL_PIO_DMIC_CLK

#define CHIP_BCPU_SWDDIO  0
#define CHIP_BCPU_SWDCLK  0

#define TEST_SUITE_UART_BUS UART_BUS_0 // UART H0
/* Test Suite UART Transmission PIN to use */
#define TEST_SUITE_UART_TX_PIN S_MGPIO31
/* Test Suite UART Reception PIN to use */
#define TEST_SUITE_UART_RX_PIN S_MGPIO30

#ifdef PRE_ASIC
#ifdef SW_UART_DEBUG
    #define CHIP_FIXED_RX_PIN S_MGPIO30
    #define CHIP_FIXED_TX_PIN S_MGPIO31
#else
    #define CHIP_FIXED_RX_PIN ULP_GPIO1
    #define CHIP_FIXED_TX_PIN ULP_GPIO0
#endif

#else
    #define CHIP_FIXED_RX_PIN S_MGPIO30
    #define CHIP_FIXED_TX_PIN S_MGPIO31
#endif

#define UART_BUS_MAX_NUMBER 2
#define UART0_BASE     0x52081000 /* UART_H1 */
#define UART1_BASE     0x52080000 /* UART_H0 */
#define UART2_BASE     0x57014000 /* UART_L0 */

#ifdef DEVICE_ONLY
#define SW_DEBUG_UART_BUS   UART_BUS_NONE
#else
#define SW_DEBUG_UART_BUS   UART_BUS_0
#endif
#define CHIP_FIXED_UART_BUS UART_BUS_0

#define CODELOADER_UART_BUS    UART_BUS_1
#define CODELOADER_UART_RX_PIN S_MGPIO30
#define CODELOADER_UART_TX_PIN S_MGPIO31

#define LOGR_UART_BUS   UART_BUS_0
#define LOG_UART_RX_PIN S_MGPIO27
#define LOG_UART_TX_PIN S_MGPIO26

#define LOG_UART_BUS    UART_BUS_0

#define QSPI_MAX_NUMBER    2
#define FLASH_QSPI_ID      QSPI_BUS_1
#define QSPI_0_BASE_ADDR   0xA3000000
#define QSPI_1_BASE_ADDR   0xA3002000

/* !< QSPI bus */
typedef enum {
    QSPI_BUS_0 = 0,
    QSPI_BUS_1,
    QSPI_BUS_NONE = QSPI_MAX_NUMBER
} qspi_bus_t;

/***************************************
For BS21 config:
    SPI_M0,
    SPI_MS_1,
    SPI_MS_2,
    SPI_MS_3,
    SPI_S_4,
    QSPI_0,
    QSPI_1
***************************************/
typedef enum {
    SPI_BUS_0 = 0,
    SPI_BUS_1,
    SPI_BUS_2,
    SPI_BUS_3,
    SPI_BUS_4,
    SPI_BUS_5,
    SPI_BUS_6,
    SPI_BUS_NONE = SPI_BUS_MAX_NUMBER
} spi_bus_t;

typedef enum {
    UART_BUS_0 = 0,  // !< UART L | UART H1
#if UART_BUS_MAX_NUMBER > 1
    UART_BUS_1 = 1,  // !< UART H | UART H0
#endif
#if UART_BUS_MAX_NUMBER > 2
    UART_BUS_2 = 2,  // !< M UART | UART L0
#endif
    UART_BUS_NONE = UART_BUS_MAX_NUMBER  // !< Value used as invalid/unused UART number
} uart_bus_t;

/* !< SLAVE CPU */
typedef enum {
    SLAVE_CPU_BT,
    SLAVE_CPU_MAX_NUM,
} slave_cpu_t;

/**********************************************************************/
/************************* MPU config base addr ***********************/
/**********************************************************************/
// config register region
#define MPU_REG_ADDR0_BASE           0x50000000
#define MPU_REG_ADDR0_LEN            0x10000000

#define MPU_REG_ADDR1_BASE           0xA3000000
#define MPU_REG_ADDR1_LEN            0x01000000

// ROM region
#define MPU_ROM_ADDR_BASE               0x0
#define MPU_ROM_ADDR_LEN                0x8000

// ITCM region
#define MPU_ITCM_ADDR_BASE              0x80000
#define MPU_ITCM_ADDR_LEN               0x80000

// L2ram region
#define MPU_L2RAM_ADDR0_BASE            0x100000
#define MPU_L2RAM_ADDR0_LEN             0x100000
#define MPU_L2RAM_ADDR1_BASE            0x200000
#define MPU_L2RAM_ADDR1_LEN             0x100000

// XIP PSRAM read & execute region
#define MPU_XIP_PSRAM_RO_ADDR_BASE      0x08000000
#define MPU_XIP_PSRAM_RO_ADDR_LEN       0x04000000

// XIP PSRAM bypass(read/write) region
#define MPU_XIP_PSRAM_RW_ADDR_BASE      0x0C000000
#define MPU_XIP_PSRAM_RW_ADDR_LEN       0x04000000

// XIP NorFlash region
#define MPU_XIP_FLASE_RO_ADDR_BASE      0x10000000
#define MPU_XIP_FLASE_RO_ADDR_LEN       0x10000000

// Sharemem region
#define MPU_SHAREMEM_ADDR_BASE          0x87000000
#define MPU_SHAREMEM_ADDR_LEN           0x10000

// MDMA(m0) address judge
#define MEM_X2P_MEMORY_START    0xA3000000
#define MEM_X2P_MEMORY_END      0xA3008FFF
#define L2RAM_MEMORY_START      0x00100000
#define L2RAM_MEMORY_END        0x0035FFFF
#define QSPI_XIP_MEMORY_START   0x08000000
#define QSPI_XIP_MEMORY_END     0x1FFFFFFF

typedef enum {
    S_MGPIO0  = 0,
    S_MGPIO1  = 38, // MGPIO1 <=> AGPIO6 (AON)
    S_MGPIO2  = 2,
    S_MGPIO3  = 3,
    S_MGPIO4  = 4,
    S_MGPIO5  = 5,
    S_MGPIO6  = 32, // MGPIO6 <=> AGPIO0 (AON)
    S_MGPIO7  = 41, // MGPIO7 <=> AGPIO9 (AON)
    S_MGPIO8  = 8,
    S_MGPIO9  = 9,
    S_MGPIO10 = 10,
    S_MGPIO11 = 39, // MGPI11 <=> AGPIO7 (AON)
    S_MGPIO12 = 12,
    S_MGPIO13 = 13,
    S_MGPIO14 = 45, // same as SGPIO0 (SEC GPIO)
    S_MGPIO15 = 46, // same as SGPIO1 (SEC GPIO)
    S_MGPIO16 = 40, // MGPIO16 <=> AGPIO8 (AON)
    S_MGPIO17 = 17,
    S_MGPIO18 = 18,
    S_MGPIO19 = 19,
    S_MGPIO20 = 20,
    S_MGPIO21 = 47, // same as SGPIO2 (SEC GPIO)
    S_MGPIO22 = 22,
    // 23
    // 24 S_MGPIO24 not pin out
    // 25 S_MGPIO25 not pin out
    // 26 S_MGPIO26 not pin out
    // 27 S_MGPIO27 not pin out
    // 28 S_MGPIO28 not pin out
    // 29 S_MGPIO29 not pin out
    S_MGPIO30 = 30,
    S_MGPIO31 = 31,

    S_AGPIO0  = S_MGPIO6, // 32
    S_AGPIO1  = 33,
    S_AGPIO2  = 34,
    S_AGPIO3  = 35,
    S_AGPIO4  = 36,
    S_AGPIO5  = 37,
    S_AGPIO6  = S_MGPIO1,   // 38
    S_AGPIO7  = S_MGPIO11,  // 39
    S_AGPIO8  = S_MGPIO16,  // 40
    S_AGPIO9  = S_MGPIO7,   // 41
    S_AGPIO10 = 42, // RTC_IN
    S_AGPIO11 = 43, // RTC_OUT
    S_AGPIO12 = 44, // RST_N (不能作为GPIO,不能配置pinmux,但可以配置padctrl)

    S_SGPIO0  = S_MGPIO14, // 45 same as MGPIO14
    S_SGPIO1  = S_MGPIO15, // 46 same as MGPIO15
    S_SGPIO2  = S_MGPIO21, // 47 same as MGPIO21

    PIN_NONE  = 48, // used as invalid/unused PIN number
} pin_t;

// Ccore ROM化时，PIN_NONE值为51，后续适配修改后，值有变化
// 于是ROM化代码中，原来使用PIN_NONE的地方统一改为LEGACY_PIN_NONE
#define LEGACY_PIN_NONE 51

#define MGPIO0      S_MGPIO0
// 1
#define MGPIO2      S_MGPIO2
#define MGPIO3      S_MGPIO3
#define MGPIO4      S_MGPIO4
#define MGPIO5      S_MGPIO5
// 6
// 7
#define MGPIO8      S_MGPIO8
#define MGPIO9      S_MGPIO9
#define MGPIO10     S_MGPIO10
// 11
#define MGPIO12     S_MGPIO12
#define MGPIO13     S_MGPIO13
#define MGPIO14     S_MGPIO14
#define MGPIO15     S_MGPIO15
// 16
#define MGPIO17     S_MGPIO17
#define MGPIO18     S_MGPIO18
#define MGPIO19     S_MGPIO19
#define MGPIO20     S_MGPIO20
#define MGPIO21     S_MGPIO21
#define MGPIO22     S_MGPIO22
// 23
// :
// 31

#define AGPIO0      S_AGPIO0
#define AGPIO1      S_AGPIO1
#define AGPIO2      S_AGPIO2
#define AGPIO3      S_AGPIO3
#define AGPIO4      S_AGPIO4
#define AGPIO5      S_AGPIO5
#define AGPIO6      S_AGPIO6
#define AGPIO7      S_AGPIO7
#define AGPIO8      S_AGPIO8
#define AGPIO9      S_AGPIO9
#define AGPIO10     S_AGPIO10
#define AGPIO11     S_AGPIO11
#define AGPIO12     S_AGPIO12

#define SGPIO0      S_SGPIO0
#define SGPIO1      S_SGPIO1
#define SGPIO2      S_SGPIO2

#define PIN_MAX_NUMBER                    PIN_NONE // value USED to iterate in arrays

#define TCXO_COUNT_ENABLE                 YES

#define WATCHDOG_ROM_ENABLE               YES

#define GPIO_WITH_ULP                     YES
#define GPIO_FUNC                         HAL_PIO_FUNC_GPIO

#define I2C_AUTO_SEND_STOP_CMD            NO
#define I2C_WITH_BUS_RECOVERY             YES

#define SPI_WITH_OPI                      NO
#define SPI_DMA_TRANSFER_NUM_BY_BYTE      NO

#define DMA_TRANSFER_DEBUG                YES
#define DMA_USE_HIDMA                     NO
#define DMA_WITH_SMDMA                    YES // Small dma
#define DMA_WITH_MDMA                     NO // Small dma
#define DMA_TRANS_BY_LLI                  NO

#define XIP_WITH_OPI                      YES
#define XIP_INT_BY_NMI                    YES
#define FLASH_SLAVE_NOTIFY_MASTER_BOOTUP YES

#define ENABLE_CPU_TRACE                  2
#define ADC_WITH_AUTO_SCAN                YES

#define OTP_HAS_READ_PERMISSION           YES
#define OTP_HAS_WRITE_PERMISSION          YES
#define OTP_HAS_CLKLDO_VSET               NO

#define SEC_IAMGE_AES_DECRYPT_EN          NO
#define SEC_BOOT_SIGN_CHECK_EN            YES
#define SEC_SUB_RST_BY_SECURITY_CORE      NO
#define TRNG_WITH_SEC_COMMON              YES
#define IS_MAIN_CORE                      NO
#define EXTERNAL_CLOCK_CALIBRATION        YES
#define AON_SPECIAL_PIO                   YES

#define SUPPORT_HI_EMMC_PHY               NO

#define OPI_PIN_FIX_DM1_DRIVER            NO
#define OPI_USE_MCU_HS_CLK                NO
#define QSPI0_FUNC  HAL_PIO_SPI0_RXD
#define QSPI0_D0    S_MGPIO0
#define QSPI0_D1    S_MGPIO1
#define QSPI0_D2    S_MGPIO2
#define QSPI0_D3    S_MGPIO3
#define QSPI0_CLK   S_MGPIO4
#define QSPI0_CS    S_MGPIO5

#ifdef ATE_FLASH_CHECK
#define QSPI1_FUNC  HAL_PIO_FUNC_QSPI0
#define QSPI1_D0    S_MGPIO0
#define QSPI1_D1    S_MGPIO1
#define QSPI1_D2    S_MGPIO2
#define QSPI1_D3    S_MGPIO3
#define QSPI1_CLK   S_MGPIO4
#define QSPI1_CS    S_MGPIO5
#else
#define QSPI1_FUNC  HAL_PIO_FUNC_QSPI1
#define QSPI1_D0    S_MGPIO6
#define QSPI1_D1    S_MGPIO7
#define QSPI1_D2    S_MGPIO8
#define QSPI1_D3    S_MGPIO9
#define QSPI1_CLK   S_MGPIO10
#define QSPI1_CS    S_MGPIO11
#endif

#define XIP_EXIST                         YES
#define CHIP_FLASH_ID                     0
#define USE_XIP_INDEX                     1
#define BCPU_INT0_ID                      26
#define UART_BAUD_RATE_DIV_8              NO
#define FIXED_IN_ROM                      NO
#define PMU_LPM_WAKEUP_SRC_NUM            16
#define ENABLE_GPIO_INTERRUPT             YES
#define CLK_AUTO_CG_ENABLE                NO
#if defined(BUILD_APPLICATION_ROM)
#define BOOT_ROM_DFR_PRINT                YES
#else
#define BOOT_ROM_DFR_PRINT                NO
#endif
#define FLASH_WRITE_CLK_DIV_AUTO_ADJ     NO
#define DMA_WITH_MUX_CHANNEL              YES
#define CRITICAL_INT_RESTORE              YES
#define SUPPORT_SEC_TRNG                  NO
#define TCXO_CLK_DYN_ADJUST              NO
#define DCACHE_IS_ENABLE                  NO
#define CODELOADER_SINGLE_PARTITION_EXP   YES
#define AUXLDO_ENABLE_FLASH               NO
/**
 * @}
 */
#endif
