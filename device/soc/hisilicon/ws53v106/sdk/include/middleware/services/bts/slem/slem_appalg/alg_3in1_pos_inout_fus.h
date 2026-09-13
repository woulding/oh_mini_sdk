/**
 * Copyright (c) HiSilicon (Shanghai) Technologies Co., Ltd. 2024. All rights reserved.
 *
 * Description: 3 algorithm in 1: posalg/car_in_out/door_dis \n
 *
 * History: \n
 * 2024-04-30, Create file. \n
 */

#ifndef ALG_3IN1_POS_INOUT_FUS_H
#define ALG_3IN1_POS_INOUT_FUS_H

#include "posalg.h"
#include "preprocess.h"
#include "alg_common_3in1.h"

#define ALG_CAR_TRIGGER_NUM             2
#define ALG_POS_TRIGGER_NUM             3
#define ALG_SLAVE_NUM_FOR_POS           4
#define ALG_ANCHOR_NUM_FOR_POS          5
#define ALG_ANCHOR_NUM_FOR_CAR_IN_OUT   5
#define ALG_ALL_FEATURE_NUM             15
#define ALG_NV_NUM_OF_R                 12
#define ALG_NV_ANCHOR_NUM               8
#define CAR_IN_OUT_CFG_NUM              6
#define ANCHOR_ALL_NUM                  5
#define POSALG_MEASURE_DEMISION         3
#define ALG_DIS_DATA_CLEAR_TRIGGER_NUM  3
#define ALG_EKF_INIT_THRESHOLD          6
#define ALG_FUSION_TRIGGER_NUM          1
#define ALG_NUM3                        3

#define SONG_DMI_X 0
#define SONG_DMI_Y 1
#define SONG_DMI_Z 2
#define ANCHOR_A_INDEX 0
#define ANCHOR_B_INDEX 1
#define ANCHOR_C_INDEX 2

#define ALG_NUM_CARRY_1000              1000
#define ALG_POSALG_POS_ERR_VAL          150
#define ALG_DIS_INVALID                 (-1)
#define ALG_RSSI_INVALID                (-128)
#define ALG_HIGH_INVALID                (-10)
#define POSALG_POS_ERR_ACCURACY         0.0001
#define FLOAT_ZERO                      0.

typedef struct {
unsigned char num;
unsigned char slave_num;  // means how many slave the system have
int key_num_all;
} alg_anchor_info;

typedef struct {
bool flag_in_out;
short int in_out_start_dis;
short int in_out_stop_dis;
unsigned char g_discbk_flag;
bool refresh;
} alg_3in1_switch;

typedef struct {
    float e_r[ALG_NV_NUM_OF_R];
    unsigned char enable_det_in_out_alg;
    unsigned char enable_pos_in_out_alg;
} alg_config_pos_in_out_t;

typedef struct {
    float x[ALG_NV_ANCHOR_NUM];
    float y[ALG_NV_ANCHOR_NUM];
    float z[ALG_NV_ANCHOR_NUM];
    float calib_val_pos[ALG_NV_ANCHOR_NUM];
} alg_slem_config_ext_t;

typedef struct {
    TagPos pos_result;
    int inout_result;  // 1:OUTSIDE 0:INSIDE
    float fusion_dis;
    int fusion_key;
    bool pos_flag;
    bool inout_flag;
    bool fusion_flag;
} alg_3in1_result;

typedef struct {
    carinout_para *parameters;
    alg_config_pos_in_out_t *conf_pos_inout;
    PosCfg *pos_cfg;
    alg_slem_config_ext_t *con_ext;
    unsigned char anchor_used_num_fusion;
    float (*g_anchor_para)[POSALG_MEASURE_DEMISION];
} alg_config_pack;

alg_3in1_result slem_alg_3in1(alg_dis_struct_t *dis, alg_config_pack *conf_p, alg_anchor_info anc, alg_3in1_switch swi);

#endif