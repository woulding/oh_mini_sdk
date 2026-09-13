/**
 * Copyright (c) HiSilicon (Shanghai) Technologies Co., Ltd. 2024. All rights reserved.
 *
 * Description: for car_in_out algorithm \n
 *
 * History: \n
 * 2024-04-30, Create file. \n
 */

#ifndef PREPROCESS_H_
#define PREPROCESS_H_

#include <math.h>
#define NUM_OF_FEATURES 8

typedef struct {
    float intercepts;
    short int index[NUM_OF_FEATURES];
    float mean[NUM_OF_FEATURES];
    float scale[NUM_OF_FEATURES];
    float coef[NUM_OF_FEATURES];
} carinout_para;

void scale(float *arr, int feature_num);
void select_features(float *features, float *features_out, int feature_num);
void feature_process(float *arr, float *features, int feature_num);
void set_carinout_para(carinout_para *parameters);

#endif