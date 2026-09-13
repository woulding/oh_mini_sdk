/**
 * Copyright (c) HiSilicon (Shanghai) Technologies Co., Ltd. 2024. All rights reserved.
 *
 * Description: interface of position algorithom. \n
 *
 * History: \n
 * 2024-04-30, Create file. \n
 */
#ifndef __POS_ALG_H__
#define __POS_ALG_H__

#include "securec.h"

typedef struct _tagPos {
    float x;
    float y;
    float z;
} TagPos;

typedef struct _tagPosCfg {
    int flag_init; // 1 identify first time use this interface(reset EKF data)
                   // 0 not first time use this interface, use the EKF data of last time
    int R_method;  // 0 fix R
                   // 1 prob R
                   // 2 Nine palace grid R
/* car in out config
 ┌────────────────────────────┐
 │          ud_space          │
 │         ┌─────────┐        │
 │car_out_r│         │        │
 │         │ car_in_r│        │
 │         │         │        │
 │lr_space │   car   │lr_space│
 │         │         │        │
 │         │         │        │
 │         │         │        │
 │         └─────────┘        │
 │          ud_space          │
 └────────────────────────────┘
 */
    float lr_space;
    float ud_space;
    // EKF R
    float car_in_r[5];
    float car_out_r[5];
} PosCfg;


typedef struct {
    float *dMeas;
    int dMeasNum;
    float *probMeas;
    int probMeasNum;
    unsigned char *smooth_num;
} pos_dis_prob;

/* get position algorithm
   If you want to change the algorithm version, see the header file posver.h
   param:
         anchorPara:  Position of anchors(5 * 3 array)
         dMeas:       Measured distance for each anchor(1 * 5 array)
         dMeasNum:    element num of dMeas(5/4)
         probMeas:    Probability of distances for each anchor(1 * 5 or 1 * 4 array)
         probMeasNum: element num of probMeas(5/4)
         cfg:         config of pos alg
   return:
         value of dimension x and dimension y and dimension z
*/
TagPos GetPos(float (*anchorPara)[3], pos_dis_prob *p_dis_prob, PosCfg *cfg, int key_num, int key_num_all);

#endif