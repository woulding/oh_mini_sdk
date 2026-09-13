/**
 * Description: Boards Definition Header. \n
 * Author: @CompanyNameTag \n
 * History: \n
 * 2023-05-06, Create file. \n
 */

#ifndef SAMPLE_BOARDS_H
#define SAMPLE_BOARDS_H

#include "platform_types.h"

#ifdef __cplusplus
#if __cplusplus
extern "C" {
#endif /* __cplusplus */
#endif /* __cplusplus */

/**
 * @defgroup boards_board Board
 * @ingroup  boards
 * @{
 */

#define BSP_LED_0  S_AGPIO1
#define BSP_LED_1  S_AGPIO2
#define BSP_LED_2  S_AGPIO3

#define BUTTON_0 S_AGPIO4
#define BUTTON_1 S_AGPIO5

/**
 * @}
 */

#ifdef __cplusplus
#if __cplusplus
}
#endif /* __cplusplus */
#endif /* __cplusplus */

#endif
