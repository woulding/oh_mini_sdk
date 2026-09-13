/**
 * Copyright (c) HiSilicon (Shanghai) Technologies Co., Ltd. 2023-2023. All rights reserved.
 *
 * Description: Provides hal pinctrl
 */

#include <stdio.h>
#include <stdint.h>
#include <stdbool.h>
#include "common_def.h"
#include "errcode.h"
#include "pinctrl_porting.h"
#include "hal_pinctrl_ws53.h"

#define HAL_MCU_PINMUX_CTL_RB_BASE_ADDR 0x52008000
#define HAL_AON_PINMUX_CTL_RB_BASE_ADDR 0x57036000 // AON域
#define HAL_TZPC_PINMUX_CTL_RB_BASE_ADDR 0x5703A000 // TZPC域


#define HAL_PIN_MODE_GROUP_NUM 9
#define HAL_PIN_MODE_CONFIG_PER_NUM 1
#define HAL_PIN_SEL_START_BIT 0
#define HAL_PIN_SEL_BITS_NUM 3

// pinmux: MGPIO0 ~ MGPIO29, lack 1/6/7/11/16/23
#define HAL_PIN_MGPIO_00_SEL_ADDR       (HAL_MCU_PINMUX_CTL_RB_BASE_ADDR + 0x0000)  // MGPIO00
// pinmux: AGPIO0 ~ AGPIO11
#define HAL_PIN_AGPIO_00_SEL_ADDR       (HAL_AON_PINMUX_CTL_RB_BASE_ADDR + 0x00BC)  // AGPIO0
#define HAL_PIN_AGPIO_01_SEL_ADDR       (HAL_AON_PINMUX_CTL_RB_BASE_ADDR + 0x0004)  // AGPIO1 ~ AGPIO5
#define HAL_PIN_AGPIO_06_SEL_ADDR       (HAL_AON_PINMUX_CTL_RB_BASE_ADDR + 0x00B8)  // AGPIO6
#define HAL_PIN_AGPIO_07_SEL_ADDR       (HAL_AON_PINMUX_CTL_RB_BASE_ADDR + 0x00C4)  // AGPIO7 ~ AGPIO8
#define HAL_PIN_AGPIO_09_SEL_ADDR       (HAL_AON_PINMUX_CTL_RB_BASE_ADDR + 0x00C0)  // AGPIO9
#define HAL_PIN_AGPIO_10_SEL_ADDR       (HAL_AON_PINMUX_CTL_RB_BASE_ADDR + 0x0018)  // AGPIO10 ~ AGPIO11
// pinmux: SGPIO0 ~ SGPIO2
#define HAL_PIN_SGPIO_00_SEL_ADDR       (HAL_MCU_PINMUX_CTL_RB_BASE_ADDR + 0x0038)  // MGPIO014 ~ MGPIO15
#define HAL_PIN_SGPIO_02_SEL_ADDR       (HAL_MCU_PINMUX_CTL_RB_BASE_ADDR + 0x0054)  // MGPIO021

#define HAL_PIN_PULL_GROUP_NUM 13
#define HAL_PIN_PULL_CONFIG_PER_NUM 1
#define HAL_PIN_PULL_START_BIT 3
#define HAL_PIN_PULL_BITS_NUM 2

// pin pull up/down MGPIO0 ~ MGPIO29
#define HAL_MGPIO0_PAD_CTL_ADDR     (HAL_AON_PINMUX_CTL_RB_BASE_ADDR + 0x40)
#define HAL_MGPIO14_PAD_CTL_ADDR    (HAL_TZPC_PINMUX_CTL_RB_BASE_ADDR + 0x170)  // S_MGPIO14_PAD_CTL (TZPC)
#define HAL_MGPIO17_PAD_CTL_ADDR    (HAL_AON_PINMUX_CTL_RB_BASE_ADDR + 0x84)
#define HAL_MGPIO21_PAD_CTL_ADDR    (HAL_TZPC_PINMUX_CTL_RB_BASE_ADDR + 0x178)  // S_MGPIO21_PAD_CTL (TZPC)
#define HAL_MGPIO22_PAD_CTL_ADDR    (HAL_AON_PINMUX_CTL_RB_BASE_ADDR + 0x98)
#define HAL_MGPIO24_PAD_CTL_ADDR    (HAL_AON_PINMUX_CTL_RB_BASE_ADDR + 0xA0)
// pin pull up/down AGPIO0 ~ AGPIO11
#define HAL_AGPIO0_PAD_CTL_ADDR     (HAL_AON_PINMUX_CTL_RB_BASE_ADDR + 0x58)    // S_MGPIO6_PAD_CTL
#define HAL_AGPIO1_PAD_CTL_ADDR     (HAL_AON_PINMUX_CTL_RB_BASE_ADDR + 0x24)
#define HAL_AGPIO5_PAD_CTL_ADDR     (HAL_AON_PINMUX_CTL_RB_BASE_ADDR + 0x34)
#define HAL_AGPIO6_PAD_CTL_ADDR     (HAL_AON_PINMUX_CTL_RB_BASE_ADDR + 0x44)    // S_MGPIO1_PAD_CTL
#define HAL_AGPIO7_PAD_CTL_ADDR     (HAL_AON_PINMUX_CTL_RB_BASE_ADDR + 0x6C)    // S_MGPIO11_PAD_CTL
#define HAL_AGPIO8_PAD_CTL_ADDR     (HAL_AON_PINMUX_CTL_RB_BASE_ADDR + 0x80)    // S_MGPIO16_PAD_CTL
#define HAL_AGPIO9_PAD_CTL_ADDR     (HAL_AON_PINMUX_CTL_RB_BASE_ADDR + 0x5C)    // S_MGPIO7_PAD_CTL
#define HAL_AGPIO10_PAD_CTL_ADDR    (HAL_AON_PINMUX_CTL_RB_BASE_ADDR + 0x38)    // S_AGPIO6_PAD_CTL
#define HAL_AGPIO12_PAD_CTL_ADDR    (HAL_AON_PINMUX_CTL_RB_BASE_ADDR + 0x20)    // S_AGPIO0_PAD_CTL


// pin ds
#define HAL_PIN_DS_GROUP_NUM 13
#define HAL_PIN_DS2_GROUP_NUM 6
#define HAL_PIN_DS_CONFIG_PER_NUM 1
#define HAL_PIN_DS_START_BIT 0
#define HAL_PIN_DS_BITS_NUM 2
#define HAL_PIN_DS_BITS_NUM_24_29 3
#define HAL_PIN_DS2_START_BIT 6
#define HAL_PIN_DS2_BITS_NUM 2


// pin st
#define HAL_PIN_ST_GROUP_NUM 13
#define HAL_PIN_ST_CONFIG_PER_NUM 1
#define HAL_PIN_ST_START_BIT 5
#define HAL_PIN_ST_BITS_NUM 1


// pin ie
#define HAL_PIN_IE_GROUP_NUM 13
#define HAL_PIN_IE_CONFIG_PER_NUM 1
#define HAL_PIN_IE_START_BIT 2
#define HAL_PIN_IE_BITS_NUM 1


/**
 * @brief  PIN config type enum.
 */
typedef enum {
    PIN_CONFIG_TYPE_MODE = 0,
    PIN_CONFIG_TYPE_DS,
    PIN_CONFIG_TYPE_DS2,
    PIN_CONFIG_TYPE_PULL,
#if defined(CONFIG_PINCTRL_SUPPORT_IE)
    PIN_CONFIG_TYPE_IE,
#endif /* CONFIG_PINCTRL_SUPPORT_IE */
#if defined(CONFIG_PINCTRL_SUPPORT_ST)
    PIN_CONFIG_TYPE_ST,
#endif /* CONFIG_PINCTRL_SUPPORT_ST */
    PIN_CONFIG_TYPE_NUM
} hal_pin_config_type_t;

/**
 * @brief  PIN config addr group struct.
 */
typedef struct {
    pin_t begin;             //!< The first pin of each group.
    pin_t end;               //!< The last pin of each group.
    uint32_t reg_addr;       //!< Address of the group.
    uint32_t per_num;        //!< Number of pins that can be configured by one register.
    uint32_t first_bit;      //!< The first bit to config.
    uint32_t bits_num;       //!< Num of bits to config.
} hal_pin_config_group_t;

/**
 * @brief  PIN config addr map struct.
 */
typedef struct {
    uint32_t config_type;
    uint32_t group_num;
    hal_pin_config_group_t *group;
} hal_pin_config_map_t;

static hal_pin_config_group_t const g_pin_mode_map[HAL_PIN_MODE_GROUP_NUM] = {
    { // MGPIO00 ~ MGPIO22
        S_MGPIO0,
        S_MGPIO22,
        HAL_PIN_MGPIO_00_SEL_ADDR,
        HAL_PIN_MODE_CONFIG_PER_NUM,
        HAL_PIN_SEL_START_BIT,
        HAL_PIN_SEL_BITS_NUM
    },
    { // AGPIO0 ~ AGPIO0
        S_AGPIO0,
        S_AGPIO0,
        HAL_PIN_AGPIO_00_SEL_ADDR,
        HAL_PIN_MODE_CONFIG_PER_NUM,
        HAL_PIN_SEL_START_BIT,
        HAL_PIN_SEL_BITS_NUM
    },
    { // AGPIO1 ~ AGPIO5
        S_AGPIO1,
        S_AGPIO5,
        HAL_PIN_AGPIO_01_SEL_ADDR,
        HAL_PIN_MODE_CONFIG_PER_NUM,
        HAL_PIN_SEL_START_BIT,
        HAL_PIN_SEL_BITS_NUM
    },
    { // AGPIO6
        S_AGPIO6,
        S_AGPIO6,
        HAL_PIN_AGPIO_06_SEL_ADDR,
        HAL_PIN_MODE_CONFIG_PER_NUM,
        HAL_PIN_SEL_START_BIT,
        HAL_PIN_SEL_BITS_NUM
    },
    { // AGPIO7 ~ AGPIO8
        S_AGPIO7,
        S_AGPIO8,
        HAL_PIN_AGPIO_07_SEL_ADDR,
        HAL_PIN_MODE_CONFIG_PER_NUM,
        HAL_PIN_SEL_START_BIT,
        HAL_PIN_SEL_BITS_NUM
    },
    { // AGPIO9
        S_AGPIO9,
        S_AGPIO9,
        HAL_PIN_AGPIO_09_SEL_ADDR,
        HAL_PIN_MODE_CONFIG_PER_NUM,
        HAL_PIN_SEL_START_BIT,
        HAL_PIN_SEL_BITS_NUM
    },
    { // AGPIO10 ~ AGPIO11
        S_AGPIO10,
        S_AGPIO11,
        HAL_PIN_AGPIO_10_SEL_ADDR,
        HAL_PIN_MODE_CONFIG_PER_NUM,
        HAL_PIN_SEL_START_BIT,
        HAL_PIN_SEL_BITS_NUM
    },
    { // SGPIO0 ~ SGPIO1
        S_SGPIO0,
        S_SGPIO1,
        HAL_PIN_SGPIO_00_SEL_ADDR,
        HAL_PIN_MODE_CONFIG_PER_NUM,
        HAL_PIN_SEL_START_BIT,
        HAL_PIN_SEL_BITS_NUM
    },
    { // SGPIO2
        S_SGPIO2,
        S_SGPIO2,
        HAL_PIN_SGPIO_02_SEL_ADDR,
        HAL_PIN_MODE_CONFIG_PER_NUM,
        HAL_PIN_SEL_START_BIT,
        HAL_PIN_SEL_BITS_NUM
    }
};

static hal_pin_config_group_t const g_pin_pull_map[HAL_PIN_PULL_GROUP_NUM] = {
    { // MGPIO0 ~ MGPIO13
        S_MGPIO0,
        S_MGPIO13,
        HAL_MGPIO0_PAD_CTL_ADDR,
        HAL_PIN_PULL_CONFIG_PER_NUM,
        HAL_PIN_PULL_START_BIT,
        HAL_PIN_PULL_BITS_NUM
    },
    { // MGPIO17 ~ MGPIO20
        S_MGPIO17,
        S_MGPIO20,
        HAL_MGPIO17_PAD_CTL_ADDR,
        HAL_PIN_PULL_CONFIG_PER_NUM,
        HAL_PIN_PULL_START_BIT,
        HAL_PIN_PULL_BITS_NUM
    },
    { // MGPIO22 ~ MGPIO22
        S_MGPIO22,
        S_MGPIO22,
        HAL_MGPIO22_PAD_CTL_ADDR,
        HAL_PIN_PULL_CONFIG_PER_NUM,
        HAL_PIN_PULL_START_BIT,
        HAL_PIN_PULL_BITS_NUM
    },
    { // AGPIO0 ~ AGPIO0
        S_AGPIO0,
        S_AGPIO0,
        HAL_AGPIO0_PAD_CTL_ADDR,
        HAL_PIN_PULL_CONFIG_PER_NUM,
        HAL_PIN_PULL_START_BIT,
        HAL_PIN_PULL_BITS_NUM
    },
    { // AGPIO1 ~ AGPIO5
        S_AGPIO1,
        S_AGPIO5,
        HAL_AGPIO1_PAD_CTL_ADDR,
        HAL_PIN_PULL_CONFIG_PER_NUM,
        HAL_PIN_PULL_START_BIT,
        HAL_PIN_PULL_BITS_NUM
    },
    { // AGPIO6 ~ AGPIO6
        S_AGPIO6,
        S_AGPIO6,
        HAL_AGPIO6_PAD_CTL_ADDR,
        HAL_PIN_PULL_CONFIG_PER_NUM,
        HAL_PIN_PULL_START_BIT,
        HAL_PIN_PULL_BITS_NUM
    },
    { // AGPIO7 ~ AGPIO7
        S_AGPIO7,
        S_AGPIO7,
        HAL_AGPIO7_PAD_CTL_ADDR,
        HAL_PIN_PULL_CONFIG_PER_NUM,
        HAL_PIN_PULL_START_BIT,
        HAL_PIN_PULL_BITS_NUM
    },
    { // AGPIO8 ~ AGPIO8
        S_AGPIO8,
        S_AGPIO8,
        HAL_AGPIO8_PAD_CTL_ADDR,
        HAL_PIN_PULL_CONFIG_PER_NUM,
        HAL_PIN_PULL_START_BIT,
        HAL_PIN_PULL_BITS_NUM
    },
    { // AGPIO9 ~ AGPIO9
        S_AGPIO9,
        S_AGPIO9,
        HAL_AGPIO9_PAD_CTL_ADDR,
        HAL_PIN_PULL_CONFIG_PER_NUM,
        HAL_PIN_PULL_START_BIT,
        HAL_PIN_PULL_BITS_NUM
    },
    { // AGPIO10 ~ AGPIO11
        S_AGPIO10,
        S_AGPIO11,
        HAL_AGPIO10_PAD_CTL_ADDR,
        HAL_PIN_PULL_CONFIG_PER_NUM,
        HAL_PIN_PULL_START_BIT,
        HAL_PIN_PULL_BITS_NUM
    },
    { // AGPIO12 ~ AGPIO12
        S_AGPIO12,
        S_AGPIO12,
        HAL_AGPIO12_PAD_CTL_ADDR,
        HAL_PIN_PULL_CONFIG_PER_NUM,
        HAL_PIN_PULL_START_BIT,
        HAL_PIN_PULL_BITS_NUM
    },
    { // SGPIO0 ~ SGPIO1 aka MGPIO14 ~ MGPIO15 (SEC GPIO)
        S_SGPIO0,
        S_SGPIO1,
        HAL_MGPIO14_PAD_CTL_ADDR,
        HAL_PIN_PULL_CONFIG_PER_NUM,
        HAL_PIN_PULL_START_BIT,
        HAL_PIN_PULL_BITS_NUM
    },
    { // SGPIO2 aka MGPIO21 (SEC GPIO)
        S_SGPIO2,
        S_SGPIO2,
        HAL_MGPIO21_PAD_CTL_ADDR,
        HAL_PIN_PULL_CONFIG_PER_NUM,
        HAL_PIN_PULL_START_BIT,
        HAL_PIN_PULL_BITS_NUM
    }
};

static hal_pin_config_group_t const g_pin_ds_map[HAL_PIN_DS_GROUP_NUM] = {
    { // MGPIO0 ~ MGPIO13
        S_MGPIO0,
        S_MGPIO13,
        HAL_MGPIO0_PAD_CTL_ADDR,
        HAL_PIN_DS_CONFIG_PER_NUM,
        HAL_PIN_DS_START_BIT,
        HAL_PIN_DS_BITS_NUM
    },
    { // MGPIO17 ~ MGPIO20
        S_MGPIO17,
        S_MGPIO20,
        HAL_MGPIO17_PAD_CTL_ADDR,
        HAL_PIN_DS_CONFIG_PER_NUM,
        HAL_PIN_DS_START_BIT,
        HAL_PIN_DS_BITS_NUM
    },
    { // MGPIO22 ~ MGPIO22
        S_MGPIO22,
        S_MGPIO22,
        HAL_MGPIO22_PAD_CTL_ADDR,
        HAL_PIN_DS_CONFIG_PER_NUM,
        HAL_PIN_DS_START_BIT,
        HAL_PIN_DS_BITS_NUM
    },
    { // AGPIO0 ~ AGPIO0
        S_AGPIO0,
        S_AGPIO0,
        HAL_AGPIO0_PAD_CTL_ADDR,
        HAL_PIN_DS_CONFIG_PER_NUM,
        HAL_PIN_DS_START_BIT,
        HAL_PIN_DS_BITS_NUM
    },
    { // AGPIO1 ~ AGPIO5
        S_AGPIO1,
        S_AGPIO5,
        HAL_AGPIO1_PAD_CTL_ADDR,
        HAL_PIN_DS_CONFIG_PER_NUM,
        HAL_PIN_DS_START_BIT,
        HAL_PIN_DS_BITS_NUM
    },
    { // AGPIO6 ~ AGPIO6
        S_AGPIO6,
        S_AGPIO6,
        HAL_AGPIO6_PAD_CTL_ADDR,
        HAL_PIN_DS_CONFIG_PER_NUM,
        HAL_PIN_DS_START_BIT,
        HAL_PIN_DS_BITS_NUM
    },
    { // AGPIO7 ~ AGPIO7
        S_AGPIO7,
        S_AGPIO7,
        HAL_AGPIO7_PAD_CTL_ADDR,
        HAL_PIN_DS_CONFIG_PER_NUM,
        HAL_PIN_DS_START_BIT,
        HAL_PIN_DS_BITS_NUM
    },
    { // AGPIO8 ~ AGPIO8
        S_AGPIO8,
        S_AGPIO8,
        HAL_AGPIO8_PAD_CTL_ADDR,
        HAL_PIN_DS_CONFIG_PER_NUM,
        HAL_PIN_DS_START_BIT,
        HAL_PIN_DS_BITS_NUM
    },
    { // AGPIO9 ~ AGPIO9
        S_AGPIO9,
        S_AGPIO9,
        HAL_AGPIO9_PAD_CTL_ADDR,
        HAL_PIN_DS_CONFIG_PER_NUM,
        HAL_PIN_DS_START_BIT,
        HAL_PIN_DS_BITS_NUM
    },
    { // AGPIO10 ~ AGPIO11
        S_AGPIO10,
        S_AGPIO11,
        HAL_AGPIO10_PAD_CTL_ADDR,
        HAL_PIN_DS_CONFIG_PER_NUM,
        HAL_PIN_DS_START_BIT,
        HAL_PIN_DS_BITS_NUM
    },
    { // AGPIO12 ~ AGPIO12
        S_AGPIO12,
        S_AGPIO12,
        HAL_AGPIO12_PAD_CTL_ADDR,
        HAL_PIN_DS_CONFIG_PER_NUM,
        HAL_PIN_DS_START_BIT,
        HAL_PIN_DS_BITS_NUM
    },
    { // SGPIO0 ~ SGPIO1 aka MGPIO14 ~ MGPIO15 (SEC GPIO)
        S_SGPIO0,
        S_SGPIO1,
        HAL_MGPIO14_PAD_CTL_ADDR,
        HAL_PIN_DS_CONFIG_PER_NUM,
        HAL_PIN_DS_START_BIT,
        HAL_PIN_DS_BITS_NUM
    },
    { // SGPIO2 aka MGPIO21 (SEC GPIO)
        S_SGPIO2,
        S_SGPIO2,
        HAL_MGPIO21_PAD_CTL_ADDR,
        HAL_PIN_DS_CONFIG_PER_NUM,
        HAL_PIN_DS_START_BIT,
        HAL_PIN_DS_BITS_NUM
    }
};

static hal_pin_config_group_t const g_pin_ds2_map[HAL_PIN_DS2_GROUP_NUM] = {
    { // MGPIO0 ~ MGPIO4
        S_MGPIO0,
        S_MGPIO4,
        HAL_MGPIO0_PAD_CTL_ADDR,
        HAL_PIN_DS_CONFIG_PER_NUM,
        HAL_PIN_DS2_START_BIT,
        HAL_PIN_DS2_BITS_NUM
    },
    { // MGPIO5 ~ AGPIO4
        S_MGPIO5,
        S_AGPIO4,
        0,
        0, // has no ds2 ds3 bits
        0,
        0
    },
    { // AGPIO5 ~ AGPIO5
        S_AGPIO5,
        S_AGPIO5,
        HAL_AGPIO5_PAD_CTL_ADDR,
        HAL_PIN_DS_CONFIG_PER_NUM,
        HAL_PIN_DS2_START_BIT,
        HAL_PIN_DS2_BITS_NUM
    },
    { // AGPIO6 ~ AGPIO6
        S_AGPIO6,
        S_AGPIO6,
        HAL_AGPIO6_PAD_CTL_ADDR,
        HAL_PIN_DS_CONFIG_PER_NUM,
        HAL_PIN_DS2_START_BIT,
        HAL_PIN_DS2_BITS_NUM
    },
    { // AGPIO7 ~ AGPIO12
        S_AGPIO7,
        S_AGPIO12,
        0,
        0, // has no ds2 ds3 bits
        0,
        0
    },
    { // SGPIO0 ~ SGPIO2
        S_SGPIO0,
        S_SGPIO2,
        0,
        0, // has no ds2 ds3 bits
        0,
        0
    }
};

#if defined(CONFIG_PINCTRL_SUPPORT_IE)
static hal_pin_config_group_t const g_pin_ie_map[HAL_PIN_IE_GROUP_NUM] = {
    { // MGPIO0 ~ MGPIO13
        S_MGPIO0,
        S_MGPIO13,
        HAL_MGPIO0_PAD_CTL_ADDR,
        HAL_PIN_IE_CONFIG_PER_NUM,
        HAL_PIN_IE_START_BIT,
        HAL_PIN_IE_BITS_NUM
    },
    { // MGPIO17 ~ MGPIO20
        S_MGPIO17,
        S_MGPIO20,
        HAL_MGPIO17_PAD_CTL_ADDR,
        HAL_PIN_IE_CONFIG_PER_NUM,
        HAL_PIN_IE_START_BIT,
        HAL_PIN_IE_BITS_NUM
    },
    { // MGPIO22 ~ MGPIO22
        S_MGPIO22,
        S_MGPIO22,
        HAL_MGPIO22_PAD_CTL_ADDR,
        HAL_PIN_IE_CONFIG_PER_NUM,
        HAL_PIN_IE_START_BIT,
        HAL_PIN_IE_BITS_NUM
    },
    { // AGPIO0 ~ AGPIO0
        S_AGPIO0,
        S_AGPIO0,
        HAL_AGPIO0_PAD_CTL_ADDR,
        HAL_PIN_IE_CONFIG_PER_NUM,
        HAL_PIN_IE_START_BIT,
        HAL_PIN_IE_BITS_NUM
    },
    { // AGPIO1 ~ AGPIO5
        S_AGPIO1,
        S_AGPIO5,
        HAL_AGPIO1_PAD_CTL_ADDR,
        HAL_PIN_IE_CONFIG_PER_NUM,
        HAL_PIN_IE_START_BIT,
        HAL_PIN_IE_BITS_NUM
    },
    { // AGPIO6 ~ AGPIO6
        S_AGPIO6,
        S_AGPIO6,
        HAL_AGPIO6_PAD_CTL_ADDR,
        HAL_PIN_IE_CONFIG_PER_NUM,
        HAL_PIN_IE_START_BIT,
        HAL_PIN_IE_BITS_NUM
    },
    { // AGPIO7 ~ AGPIO7
        S_AGPIO7,
        S_AGPIO7,
        HAL_AGPIO7_PAD_CTL_ADDR,
        HAL_PIN_IE_CONFIG_PER_NUM,
        HAL_PIN_IE_START_BIT,
        HAL_PIN_IE_BITS_NUM
    },
    { // AGPIO8 ~ AGPIO8
        S_AGPIO8,
        S_AGPIO8,
        HAL_AGPIO8_PAD_CTL_ADDR,
        HAL_PIN_IE_CONFIG_PER_NUM,
        HAL_PIN_IE_START_BIT,
        HAL_PIN_IE_BITS_NUM
    },
    { // AGPIO9 ~ AGPIO9
        S_AGPIO9,
        S_AGPIO9,
        HAL_AGPIO9_PAD_CTL_ADDR,
        HAL_PIN_IE_CONFIG_PER_NUM,
        HAL_PIN_IE_START_BIT,
        HAL_PIN_IE_BITS_NUM
    },
    { // AGPIO10 ~ AGPIO11
        S_AGPIO10,
        S_AGPIO11,
        HAL_AGPIO10_PAD_CTL_ADDR,
        HAL_PIN_IE_CONFIG_PER_NUM,
        HAL_PIN_IE_START_BIT,
        HAL_PIN_IE_BITS_NUM
    },
    { // AGPIO12 ~ AGPIO12
        S_AGPIO12,
        S_AGPIO12,
        HAL_AGPIO12_PAD_CTL_ADDR,
        HAL_PIN_IE_CONFIG_PER_NUM,
        HAL_PIN_IE_START_BIT,
        HAL_PIN_IE_BITS_NUM
    },
    { // SGPIO0 ~ SGPIO1 aka MGPIO14 ~ MGPIO15 (SEC GPIO)
        S_SGPIO0,
        S_SGPIO1,
        HAL_MGPIO14_PAD_CTL_ADDR,
        HAL_PIN_IE_CONFIG_PER_NUM,
        HAL_PIN_IE_START_BIT,
        HAL_PIN_IE_BITS_NUM
    },
    { // SGPIO2 aka MGPIO21 (SEC GPIO)
        S_SGPIO2,
        S_SGPIO2,
        HAL_MGPIO21_PAD_CTL_ADDR,
        HAL_PIN_IE_CONFIG_PER_NUM,
        HAL_PIN_IE_START_BIT,
        HAL_PIN_IE_BITS_NUM
    }
};
#endif /* CONFIG_PINCTRL_SUPPORT_IE */

#if defined(CONFIG_PINCTRL_SUPPORT_ST)
static hal_pin_config_group_t const g_pin_st_map[HAL_PIN_ST_GROUP_NUM] = {
    { // MGPIO0 ~ MGPIO13
        S_MGPIO0,
        S_MGPIO13,
        HAL_MGPIO0_PAD_CTL_ADDR,
        HAL_PIN_ST_CONFIG_PER_NUM,
        HAL_PIN_ST_START_BIT,
        HAL_PIN_ST_BITS_NUM
    },
    { // MGPIO17 ~ MGPIO20
        S_MGPIO17,
        S_MGPIO20,
        HAL_MGPIO17_PAD_CTL_ADDR,
        HAL_PIN_ST_CONFIG_PER_NUM,
        HAL_PIN_ST_START_BIT,
        HAL_PIN_ST_BITS_NUM
    },
    { // MGPIO22 ~ MGPIO22
        S_MGPIO22,
        S_MGPIO22,
        HAL_MGPIO22_PAD_CTL_ADDR,
        HAL_PIN_ST_CONFIG_PER_NUM,
        HAL_PIN_ST_START_BIT,
        HAL_PIN_ST_BITS_NUM
    },
    { // AGPIO0 ~ AGPIO0
        S_AGPIO0,
        S_AGPIO0,
        HAL_AGPIO0_PAD_CTL_ADDR,
        HAL_PIN_ST_CONFIG_PER_NUM,
        HAL_PIN_ST_START_BIT,
        HAL_PIN_ST_BITS_NUM
    },
    { // AGPIO1 ~ AGPIO5
        S_AGPIO1,
        S_AGPIO5,
        HAL_AGPIO1_PAD_CTL_ADDR,
        HAL_PIN_ST_CONFIG_PER_NUM,
        HAL_PIN_ST_START_BIT,
        HAL_PIN_ST_BITS_NUM
    },
    { // AGPIO6 ~ AGPIO6
        S_AGPIO6,
        S_AGPIO6,
        HAL_AGPIO6_PAD_CTL_ADDR,
        HAL_PIN_ST_CONFIG_PER_NUM,
        HAL_PIN_ST_START_BIT,
        HAL_PIN_ST_BITS_NUM
    },
    { // AGPIO7 ~ AGPIO7
        S_AGPIO7,
        S_AGPIO7,
        HAL_AGPIO7_PAD_CTL_ADDR,
        HAL_PIN_ST_CONFIG_PER_NUM,
        HAL_PIN_ST_START_BIT,
        HAL_PIN_ST_BITS_NUM
    },
    { // AGPIO8 ~ AGPIO8
        S_AGPIO8,
        S_AGPIO8,
        HAL_AGPIO8_PAD_CTL_ADDR,
        HAL_PIN_ST_CONFIG_PER_NUM,
        HAL_PIN_ST_START_BIT,
        HAL_PIN_ST_BITS_NUM
    },
    { // AGPIO9 ~ AGPIO9
        S_AGPIO9,
        S_AGPIO9,
        HAL_AGPIO9_PAD_CTL_ADDR,
        HAL_PIN_ST_CONFIG_PER_NUM,
        HAL_PIN_ST_START_BIT,
        HAL_PIN_ST_BITS_NUM
    },
    { // AGPIO10 ~ AGPIO11
        S_AGPIO10,
        S_AGPIO11,
        HAL_AGPIO10_PAD_CTL_ADDR,
        HAL_PIN_ST_CONFIG_PER_NUM,
        HAL_PIN_ST_START_BIT,
        HAL_PIN_ST_BITS_NUM
    },
    { // AGPIO12 ~ AGPIO12
        S_AGPIO12,
        S_AGPIO12,
        HAL_AGPIO12_PAD_CTL_ADDR,
        HAL_PIN_ST_CONFIG_PER_NUM,
        HAL_PIN_ST_START_BIT,
        HAL_PIN_ST_BITS_NUM
    },
    { // SGPIO0 ~ SGPIO1 aka MGPIO14 ~ MGPIO15 (SEC GPIO)
        S_SGPIO0,
        S_SGPIO1,
        HAL_MGPIO14_PAD_CTL_ADDR,
        HAL_PIN_ST_CONFIG_PER_NUM,
        HAL_PIN_ST_START_BIT,
        HAL_PIN_ST_BITS_NUM
    },
    { // SGPIO2 aka MGPIO21 (SEC GPIO)
        S_SGPIO2,
        S_SGPIO2,
        HAL_MGPIO21_PAD_CTL_ADDR,
        HAL_PIN_ST_CONFIG_PER_NUM,
        HAL_PIN_ST_START_BIT,
        HAL_PIN_ST_BITS_NUM
    }
};
#endif /* CONFIG_PINCTRL_SUPPORT_ST */

static hal_pin_config_map_t const g_pin_config_map_pinctrl[] = {
    {PIN_CONFIG_TYPE_MODE,  HAL_PIN_MODE_GROUP_NUM,     (hal_pin_config_group_t *)g_pin_mode_map},
    {PIN_CONFIG_TYPE_DS,    HAL_PIN_DS_GROUP_NUM,       (hal_pin_config_group_t *)g_pin_ds_map},
    {PIN_CONFIG_TYPE_DS2,   HAL_PIN_DS2_GROUP_NUM,      (hal_pin_config_group_t *)g_pin_ds2_map},
    {PIN_CONFIG_TYPE_PULL,  HAL_PIN_PULL_GROUP_NUM,     (hal_pin_config_group_t *)g_pin_pull_map},
#if defined(CONFIG_PINCTRL_SUPPORT_IE)
    {PIN_CONFIG_TYPE_IE,    HAL_PIN_IE_GROUP_NUM,       (hal_pin_config_group_t *)g_pin_ie_map},
#endif /* CONFIG_PINCTRL_SUPPORT_IE */
#if defined(CONFIG_PINCTRL_SUPPORT_ST)
    {PIN_CONFIG_TYPE_ST,    HAL_PIN_ST_GROUP_NUM,       (hal_pin_config_group_t *)g_pin_st_map},
#endif /* CONFIG_PINCTRL_SUPPORT_ST */
};

STATIC errcode_t hal_pin_get_config_map(uint32_t config_type, hal_pin_config_group_t **pin_map, uint32_t *map_size)
{
    if (config_type >= PIN_CONFIG_TYPE_NUM) {
        return ERRCODE_FAIL;
    }
    *map_size = g_pin_config_map_pinctrl[config_type].group_num;
    *pin_map = g_pin_config_map_pinctrl[config_type].group;
    return ERRCODE_SUCC;
}

STATIC hal_pin_config_group_t *hal_pin_get_config_group(uint32_t config_type, pin_t pin)
{
    hal_pin_config_group_t *pin_group = NULL;
    uint32_t map_size = 0;
    errcode_t ret;

    ret = hal_pin_get_config_map(config_type, &pin_group, &map_size);
    if (ret != ERRCODE_SUCC) {
        return NULL;
    }
    for (uint32_t i = 0; i < map_size; i++) {
        if ((pin >= pin_group[i].begin) && (pin <= pin_group[i].end)) {
            return (pin_group + i);
        }
    }
    return NULL;
}

STATIC errcode_t hal_pin_set_config_val(uint32_t config_type, pin_t pin, uint32_t val)
{
    uint32_t reg_addr;
    hal_pin_config_group_t *pin_group = hal_pin_get_config_group(config_type, pin);
    if ((pin_group == NULL) || (pin_group->per_num == 0)) {
        return ERRCODE_FAIL;
    }
    reg_addr = (uintptr_t)pin_group->reg_addr +
               ((uint32_t)(pin - pin_group->begin) / pin_group->per_num) * (sizeof(uint32_t));
    if (val > (uint32_t)((1 << pin_group->bits_num) - 1)) {
        return ERRCODE_INVALID_PARAM;
    }
    uapi_reg_setbits(reg_addr, pin_group->first_bit, pin_group->bits_num, val);
    return ERRCODE_SUCC;
}

STATIC errcode_t hal_pin_get_config_val(uint32_t config_type, pin_t pin, uint32_t *val)
{
    uint32_t reg_addr;
    hal_pin_config_group_t *pin_group = hal_pin_get_config_group(config_type, pin);
    if ((pin_group == NULL) || (pin_group->per_num == 0)) {
        return ERRCODE_FAIL;
    }
    reg_addr = (uintptr_t)pin_group->reg_addr + ((uint32_t)(pin - pin_group->begin) / pin_group->per_num) *
               (sizeof(uint32_t));
    *val = uapi_reg_getbits(reg_addr, pin_group->first_bit, pin_group->bits_num);
    return ERRCODE_SUCC;
}

STATIC errcode_t hal_pin_ws53_set_mode(pin_t pin, pin_mode_t mode)
{
    return hal_pin_set_config_val(PIN_CONFIG_TYPE_MODE, pin, mode);
}

STATIC pin_mode_t hal_pin_ws53_get_mode(pin_t pin)
{
    uint32_t val;
    if (hal_pin_get_config_val(PIN_CONFIG_TYPE_MODE, pin, &val) != ERRCODE_SUCC) {
        return PIN_MODE_MAX;
    }
    return val;
}

STATIC errcode_t hal_pin_ws53_set_ds(pin_t pin, pin_drive_strength_t ds)
{
    errcode_t ret = hal_pin_set_config_val(PIN_CONFIG_TYPE_DS, pin, ds & 3); // 3: mask of bit0,1

    hal_pin_config_group_t *pin_group = hal_pin_get_config_group(PIN_CONFIG_TYPE_DS2, pin);
    if (pin_group == NULL) {
        return ret;
    }
    if ((pin_group->per_num == 0) && (((ds >> 2) & 3) > 0)) { // 2: bit3,4; 3: mask
        return ERRCODE_INVALID_PARAM;
    }
    if (pin_group->per_num == 0) {
        return ret;
    }
    ret |= hal_pin_set_config_val(PIN_CONFIG_TYPE_DS2, pin, (ds >> 2) & 3); // 2: bit3,4; 3: mask

    return ret;
}

STATIC pin_drive_strength_t hal_pin_ws53_get_ds(pin_t pin)
{
    uint32_t val;
    uint32_t val2;

    if (hal_pin_get_config_val(PIN_CONFIG_TYPE_DS, pin, &val) != ERRCODE_SUCC) {
        return PIN_DS_MAX;
    }

    hal_pin_config_group_t *pin_group = hal_pin_get_config_group(PIN_CONFIG_TYPE_DS2, pin);
    if ((pin_group == NULL) || (pin_group->per_num == 0)) {
        return val;
    }

    if (hal_pin_get_config_val(PIN_CONFIG_TYPE_DS2, pin, &val2) != ERRCODE_SUCC) {
        return PIN_DS_MAX;
    }

    return val | (val2 << 2); // 2: val2 is bit[2:3], val is bit[0,1]
}

STATIC errcode_t hal_pin_ws53_set_pull(pin_t pin, pin_pull_t pull_type)
{
    return hal_pin_set_config_val(PIN_CONFIG_TYPE_PULL, pin, pull_type);
}

STATIC pin_pull_t hal_pin_ws53_get_pull(pin_t pin)
{
    uint32_t val;
    if (hal_pin_get_config_val(PIN_CONFIG_TYPE_PULL, pin, &val) != ERRCODE_SUCC) {
        return PIN_PULL_MAX;
    }
    return val;
}

#if defined(CONFIG_PINCTRL_SUPPORT_IE)
STATIC errcode_t hal_pin_ws53_set_ie(pin_t pin, pin_input_enable_t ie)
{
    return hal_pin_set_config_val(PIN_CONFIG_TYPE_IE, pin, ie);
}

STATIC pin_input_enable_t hal_pin_ws53_get_ie(pin_t pin)
{
    uint32_t val;
    if (hal_pin_get_config_val(PIN_CONFIG_TYPE_IE, pin, &val) != ERRCODE_SUCC) {
        return PIN_IE_MAX;
    }
    return val;
}
#endif /* CONFIG_PINCTRL_SUPPORT_IE */

#if defined(CONFIG_PINCTRL_SUPPORT_ST)
STATIC errcode_t hal_pin_ws53_set_st(pin_t pin, pin_schmitt_trigger_t st)
{
    return hal_pin_set_config_val(PIN_CONFIG_TYPE_ST, pin, st);
}

STATIC pin_schmitt_trigger_t hal_pin_ws53_get_st(pin_t pin)
{
    uint32_t val;
    if (hal_pin_get_config_val(PIN_CONFIG_TYPE_ST, pin, &val) != ERRCODE_SUCC) {
        return PIN_ST_MAX;
    }
    return val;
}
#endif /* CONFIG_PINCTRL_SUPPORT_ST */

#if defined(CONFIG_PINCTRL_SUPPORT_LPM)
#define HAL_PIN_TZPC_REGS_CNT  3        // TZPC域PADCTRL数量
#define HAL_PIN_CTLRB_REGS_CNT 18       // MCU_PINUX_RB域需要保存的寄存器数量,MGPIO22往后的pin未引管脚，不作处理
#define HAL_PIN_CTLRB_MAX_NUM  23
static uint8_t g_pin_regs[HAL_PIN_CTLRB_REGS_CNT] = { 0 };
static uint8_t g_pin_tzpc_regs[HAL_PIN_TZPC_REGS_CNT] = { 0 };
#define HAL_PIN_CTLRB_MASK  0x7EF73D   // 每bit表示MGPIO[n]是否存在
STATIC errcode_t hal_pin_ws53_suspend(pin_t pin)
{
    unused(pin);
    uint32_t cnt = 0;
    /* 保存复用配置  */
    for (uint32_t i = 0; i < HAL_PIN_CTLRB_MAX_NUM; i++) {
        if ((HAL_PIN_CTLRB_MASK >> i) & 0x1) {
            g_pin_regs[cnt++] = (uint8_t)readw(HAL_MCU_PINMUX_CTL_RB_BASE_ADDR + i * (sizeof(uint32_t)));
        }
    }
    /* PADCTRL保存 */
    for (uint32_t i = 0; i < HAL_PIN_TZPC_REGS_CNT; i++) {
        g_pin_tzpc_regs[i] = (uint8_t)readw(HAL_MGPIO14_PAD_CTL_ADDR + i * (sizeof(uint32_t)));
    }
    return ERRCODE_SUCC;
}

STATIC errcode_t hal_pin_ws53_resume(pin_t pin)
{
    unused(pin);
    uint32_t cnt = 0;
    /* 恢复复用配置 */
    for (uint32_t i = 0; i < HAL_PIN_CTLRB_MAX_NUM; i++) {
        if ((HAL_PIN_CTLRB_MASK >> i) & 0x1) {
            writew(HAL_MCU_PINMUX_CTL_RB_BASE_ADDR + i * (sizeof(uint32_t)), g_pin_regs[cnt++]);
        }
    }
    /* PADCTRL恢复 */
    for (uint32_t i = 0; i < HAL_PIN_TZPC_REGS_CNT; i++) {
        writew(HAL_MGPIO14_PAD_CTL_ADDR + i * (sizeof(uint32_t)), g_pin_tzpc_regs[i]);
    }
    return ERRCODE_SUCC;
}
#endif /* CONFIG_PINCTRL_SUPPORT_LPM */

static hal_pin_funcs_t g_hal_pin_ws53_funcs = {
    .set_mode = hal_pin_ws53_set_mode,
    .get_mode = hal_pin_ws53_get_mode,
    .set_ds = hal_pin_ws53_set_ds,
    .get_ds = hal_pin_ws53_get_ds,
    .set_pull = hal_pin_ws53_set_pull,
    .get_pull = hal_pin_ws53_get_pull,
#if defined(CONFIG_PINCTRL_SUPPORT_IE)
    .set_ie = hal_pin_ws53_set_ie,
    .get_ie = hal_pin_ws53_get_ie,
#endif /* CONFIG_PINCTRL_SUPPORT_IE */
#if defined(CONFIG_PINCTRL_SUPPORT_ST)
    .set_st = hal_pin_ws53_set_st,
    .get_st = hal_pin_ws53_get_st,
#endif /* CONFIG_PINCTRL_SUPPORT_ST */
#if defined(CONFIG_PINCTRL_SUPPORT_LPM)
    .suspend = hal_pin_ws53_suspend,
    .resume = hal_pin_ws53_resume,
#endif /* CONFIG_PINCTRL_SUPPORT_LPM */
};

hal_pin_funcs_t *hal_pin_ws53_funcs_get(void)
{
    return &g_hal_pin_ws53_funcs;
}

uint32_t hal_pin_get_pull_regaddr(pin_t pin)
{
    uint32_t reg_addr = 0;
    hal_pin_config_group_t *pin_group = hal_pin_get_config_group(PIN_CONFIG_TYPE_PULL, pin);
    if ((pin_group == NULL) || (pin_group->per_num == 0)) {
        return 0;
    }
    reg_addr = (uintptr_t)pin_group->reg_addr + ((uint32_t)(pin - pin_group->begin) / pin_group->per_num) *
               (sizeof(uint32_t));
    return reg_addr;
}
