/**
 * Copyright (c) HiSilicon (Shanghai) Technologies Co., Ltd. 2024. All rights reserved.
 *
 * Description: some common struct for 3in1 algorithm \n
 *
 * History: \n
 * 2024-04-30, Create file. \n
 */

#ifndef ALG_COMMON_3IN1_H
#define ALG_COMMON_3IN1_H

#include "stdbool.h"

typedef struct {
    unsigned char key_id;
    unsigned char used_times;  // the times this data have been used in slem_posalg_get_po
    unsigned char invaild_times;
    bool is_new_data;  // if this data have not been used in slem_posalg_get_pos, this param is true
    bool is_valid_data;  // if dis & float have not been cleared, this param is true
    unsigned int timeofms;  // the time master receives dis_data
    float dis;
    float dis_double;
    float prob;
    float rssi; // received signal strength indication
    float high; // confidence correlation coefficient
    unsigned long long reboot_moment;
    unsigned char smooth_num;
} alg_dis_struct_t;

#endif