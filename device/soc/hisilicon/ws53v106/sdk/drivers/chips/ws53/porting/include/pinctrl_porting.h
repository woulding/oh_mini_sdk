/**
 * Copyright (c) HiSilicon (Shanghai) Technologies Co., Ltd. 2022-2022. All rights reserved.
 *
 * Description: Provides pinctrl port \n
 *
 * History: \n
 * 2022-08-25， Create file. \n
 */
#ifndef PINCTRL_PORTING_H
#define PINCTRL_PORTING_H

#include <stdint.h>
#include <stdbool.h>
#include "securec.h"
#include "platform_core.h"
#include "chip_io.h"

#ifdef __cplusplus
#if __cplusplus
extern "C" {
#endif /* __cplusplus */
#endif /* __cplusplus */

/**
 * @defgroup drivers_port_pinctrl Pinctrl
 * @ingroup  drivers_port
 * @{
 */

/**
 * @brief  Definition of mode-multiplexing.
 */
typedef enum {
    PIN_MODE_0        = 0,
    PIN_MODE_1        = 1,
    PIN_MODE_2        = 2,
    PIN_MODE_3        = 3,
    PIN_MODE_4        = 4,
    PIN_MODE_5        = 5,
    PIN_MODE_6        = 6,
    PIN_MODE_7        = 7,
    PIN_MODE_MAX
} pin_mode_t;

/**
 * @brief  Definition of drive-strength.
 */
typedef enum {
    PIN_DS_0    = 0,
    PIN_DS_1    = 1,
    PIN_DS_2    = 2,
    PIN_DS_3    = 3,
    PIN_DS_4    = 4,
    PIN_DS_5    = 5,
    PIN_DS_6    = 6,
    PIN_DS_7    = 7,
    PIN_DS_8    = 8,
    PIN_DS_9    = 9,
    PIN_DS_10   = 10,
    PIN_DS_11   = 11,
    PIN_DS_12   = 12,
    PIN_DS_13   = 13,
    PIN_DS_14   = 14,
    PIN_DS_15   = 15,
    PIN_DS_MAX
} pin_drive_strength_t;

/**
 * @brief  Definition of pull-up/pull-down.
 */
typedef enum {
    PIN_PULL_NONE = 0,
    PIN_PULL_UP   = 1,
    PIN_PULL_DOWN = 2,
    PIN_PULL_MAX
} pin_pull_t;


typedef enum {
    /* pinmux mode 0 funciton */
    HAL_PIO_FUNC_GPIO           = 0,

    /* pinmux mode 1 funciton */
    HAL_PIO_QSPI0               = 1,
    HAL_PIO_QSPI1               = 1,
    HAL_PIO_SDIO                = 1,
    HAL_PIO_UART_H0             = 1,
    HAL_PIO_UART_L0             = 1,
    HAL_PIO_SPI0                = 1,
    HAL_PIO_I2C0                = 1,
    HAL_PIO_I2C1                = 1,
    HAL_PIO_SPWMP               = 1,
    HAL_PIO_SPWMN               = 1,
    HAL_PIO_PWM3P               = 1,
    HAL_PIO_PWM3N               = 1,
    HAL_PIO_SWT_CTRL0           = 1,
    HAL_PIO_SWT_CTRL1           = 1,
    HAL_PIO_ANT_SEL0            = 1,
    HAL_PIO_ANT_SEL1            = 1,

    /* pinmux mode 2 funciton */
    HAL_PIO_I2C0_M2             = 2,
    HAL_PIO_SPI0_M2             = 2,
    HAL_PIO_GLP_WK_NB           = 2,
    HAL_PIO_GLP_EN              = 2,
    HAL_PIO_SYNC_BOOT_SEL       = 2,
    HAL_PIO_NB_WK_GLP           = 2,
    HAL_PIO_UART_H0_M2          = 2,
    HAL_PIO_UART_H1             = 2,
    HAL_PIO_UART_L0_M2          = 2,
    HAL_PIO_PWM0P               = 2,
    HAL_PIO_PWM0N               = 2,
    HAL_PIO_PWM1P               = 2,
    HAL_PIO_PWM1N               = 2,
    HAL_PIO_PWM2P               = 2,
    HAL_PIO_PWM2N               = 2,
    HAL_PIO_PWM3P_M2            = 2,
    HAL_PIO_PWM3N_M2            = 2,
    HAL_PIO_SWDIO_SSI_DATA      = 2,
    HAL_PIO_SWDCLK_SSI_CLK      = 2,

    /* pinmux mode 3 funciton */
    HAL_PIO_UART_L0_M3          = 3,
    HAL_PIO_UART_H1_M3          = 3,
    HAL_PIO_I2C1_M3             = 3,
    HAL_PIO_SPI0_M3             = 3,
    HAL_PIO_PWM0P_M3            = 3,
    HAL_PIO_PWM0N_M3            = 3,
    HAL_PIO_PWM1P_M3            = 3,
    HAL_PIO_PWM1N_M3            = 3,
    HAL_PIO_PWM2P_M3            = 3,
    HAL_PIO_PWM2N_M3            = 3,
    HAL_PIO_SPWMP_M3            = 3,
    HAL_PIO_SPWMN_M3            = 3,
    HAL_PIO_ANT_SEL0_M3         = 3,
    HAL_PIO_ANT_SEL1_M3         = 3,

    /* pinmux mode 4 funciton */
    HAL_PIO_PWM0P_M4            = 4,
    HAL_PIO_PWM0N_M4            = 4,
    HAL_PIO_PWM1P_M4            = 4,
    HAL_PIO_PWM1N_M4            = 4,
    HAL_PIO_PWM2P_M4            = 4,
    HAL_PIO_PWM2N_M4            = 4,
    HAL_PIO_SPWMP_M4            = 4,
    HAL_PIO_SPWMN_M4            = 4,
    HAL_PIO_COEX0               = 4,
    HAL_PIO_COEX1               = 4,
    HAL_PIO_COEX2               = 4,
    HAL_PIO_COEX3               = 4,
    HAL_PIO_ANT_SEL0_M4         = 4,
    HAL_PIO_UART_H0_M4          = 4,
    HAL_PIO_UART_L0_M4          = 4,
    HAL_PIO_SYNC_BOOT_SEL_M4    = 4,

    /* pinmux mode 5 funciton */
    HAL_PIO_COEX0_M5            = 5,
    HAL_PIO_COEX1_M5            = 5,
    HAL_PIO_I2S                 = 5,
    HAL_PIO_ANT_SEL0_M5         = 5,
    HAL_PIO_SWT_CTRL0_M5        = 5,
    HAL_PIO_SWT_CTRL1_M5        = 5,

    /* pinmux mode 6 funciton */
    HAL_PIO_COEX0_M6            = 6,
    HAL_PIO_COEX1_M6            = 6,
    HAL_PIO_COEX2_M6            = 6,
    HAL_PIO_COEX3_M6            = 6,

    /* pinmux mode 7 funciton */
    HAL_PIO_DIAG                = 7, // DIAG[0] ~ DIAG[15]

    HAL_PIO_FUNC_MAX            = 8,

    HAL_PIO_FUNC_DEFAULT_HIGH_Z = 0xf,
} hal_pio_func_t;

typedef enum {
    HAL_PIO_PULL_NONE,  //!< No pull down or pull up enabled.
    HAL_PIO_PULL_DOWN,  //!< Pull down enabled for this pin.
    HAL_PIO_PULL_UP,    //!< Pull up enabled for this pin.
    HAL_PIO_PULL_MAX,
} hal_pio_pull_t;

typedef enum {
    HAL_PIO_DRIVE_0 =  0,   //!< lowest pio current dirve strength.
    HAL_PIO_DRIVE_1 =  1,
    HAL_PIO_DRIVE_2 =  2,
    HAL_PIO_DRIVE_3 =  3,
    HAL_PIO_DRIVE_MAX,
} hal_pio_drive_t;

typedef struct {
    hal_pio_func_t func;
    hal_pio_drive_t drive;
    hal_pio_pull_t pull;
} hal_pio_config_t;

typedef enum {
    PIN_ST_DISABLE = 0,
    PIN_ST_ENABLE = 1,
    PIN_ST_MAX,
} pin_schmitt_trigger_t;

/**
 * @brief  Check whether the mode configured for the pin is valid.
 * @param  [in]  pin  The index of pins. see @ref pin_t
 * @param  [in]  mode The Multiplexing mode. see @ref pin_mode_t
 * @return The value 'true' indicates that the mode is valid and the value 'false' indicates that the mode is invalid.
 */
bool pin_check_mode_is_valid(pin_t pin, pin_mode_t mode);

/**
 * @brief  Register hal funcs objects into hal_pinctrl module.
 */
void pin_port_register_hal_funcs(void);

/**
 * @brief  Unregister hal funcs objects from hal_pinctrl module.
 */
void pin_port_unregister_hal_funcs(void);

void get_pio_func_config(size_t *pin_num, hal_pio_config_t **pin_func_array);


#ifdef _PRE_FEATURE_WS53_DEVICE_MODE
void qpsi0_pin_config_pull_down(void);
#endif

/**
 * @}
 */

#define HAL_PIO_FUNC_INVALID        HAL_PIO_FUNC_MAX

#ifdef __cplusplus
#if __cplusplus
}
#endif /* __cplusplus */
#endif /* __cplusplus */

#endif
