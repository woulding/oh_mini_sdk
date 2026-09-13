/*
 * Copyright (c) HiSilicon (Shanghai) Technologies Co., Ltd. 2018-2020. All rights reserved.
 * Description: calibration interface
 * Author:
 * Create:
 */
#include "connectivity_calibration.h"
#include "securec.h"
#if defined(BUILD_APPLICATION_STANDARD)
#include "cmsis_os2.h"
#endif

static calibration_config_t g_calibration_config;
#if defined(BUILD_APPLICATION_STANDARD)
static osSemaphoreId_t g_semaphore_calibration = NULL;
#endif

static bool ap_bt_calibration_param_req_handler(ipc_action_t message,
    const volatile ipc_payload *payload_p, cores_t src, uint32_t id)
{
    errno_t sec_ret;

    UNUSED(message);
    UNUSED(id);
    UNUSED(src);

    /* The parameter is longer than the max value or has no parameters */
    if (payload_p->ap_bt_calibration_param_req.length == 0 ||
        payload_p->ap_bt_calibration_param_req.length > CALIBRATION_PARAMS_LENGTH) {
        return true;
    }

    g_calibration_config.length = payload_p->ap_bt_calibration_param_req.length;
    sec_ret = memcpy_s((void *)g_calibration_config.params, CALIBRATION_PARAMS_LENGTH,
                       (void *)payload_p->ap_bt_calibration_param_req.params, g_calibration_config.length);
    if (sec_ret != EOK) {
        g_calibration_config.length = 0;
    }

#if defined(BUILD_APPLICATION_STANDARD)
    /* Release the mutex that can make the BT finish the configuration of calibration */
    (void)osSemaphoreRelease(g_semaphore_calibration);
#endif

    return true;
}

#if defined(BUILD_APPLICATION_STANDARD)
void calibration_release_sem(void)
{
#if defined(BUILD_APPLICATION_STANDARD)
    (void)osSemaphoreRelease(g_semaphore_calibration);
#endif
}

bool bt_calibration_param_set(uint8_t *cali_data, uint16_t length)
{
    if ((cali_data == NULL) || (length == 0) || (length > CALIBRATION_PARAMS_LENGTH)) {
        return false;
    }

    g_calibration_config.length = length;
    errno_t sec_ret = memcpy_s((void *)g_calibration_config.params, CALIBRATION_PARAMS_LENGTH,
                               (void *)cali_data, g_calibration_config.length);
    if (sec_ret != EOK) {
        g_calibration_config.length = 0;
        return false;
    }
    return true;
}
#endif

calibration_ret_e calibration_init(void)
{
    memset_s((void *)&g_calibration_config, CALIBRATION_PARAMS_LENGTH, 0, CALIBRATION_PARAMS_LENGTH);

    (void)ipc_register_handler(IPC_ACTION_AP_BT_CALIBRATION_PARAM_REQ, ap_bt_calibration_param_req_handler);

#if defined(BUILD_APPLICATION_STANDARD)
    /* Create the mutex used to control the calibration parameters write. */
    g_semaphore_calibration = osSemaphoreNew(1, 0, NULL);
    if (!g_semaphore_calibration) {
        return CALIBRATION_MUTEX_NOT_READY;
    }
#endif

    return CALIBRATION_RET_OK;
}

calibration_config_t *calibration_config_get(void)
{
#if defined(BUILD_APPLICATION_STANDARD)
    /* Wait until the parameters from App core is ready */
    if (osSemaphoreAcquire(g_semaphore_calibration, osWaitForever) != osOK) {
        return NULL; //lint !e454 !e456
    }
#endif

    if (g_calibration_config.length != 0) {
        return &g_calibration_config;
    } else {
        return NULL;
    }
}
