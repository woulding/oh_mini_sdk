/**
 * Copyright (c) HiSilicon (Shanghai) Technologies Co., Ltd. 2024-2024. All rights reserved.
 *
 * Description: At mipi cmd table \n
 *
 */

#if !defined(AT_MIPI_CMD_TALBE_H)
#define AT_MIPI_CMD_TALBE_H

#include "at.h"

typedef struct {
    uint32_t             para_map;
    char                 *para1;
    char                 *para2;
    char                 *para3;
    char                 *para4;
    char                 *para5;
    char                 *para6;
    char                 *para7;
    char                 *para8;
    char                 *para9;
    char                 *para10;
    char                 *para11;
    char                 *para12;
} mipi_args_t;

/* AT+MIPI */
at_ret_t at_mipi_tx_process(const mipi_args_t *arg);

const at_para_parse_syntax_t g_mipi_parse_syntax[] = {
    {
        .type = AT_SYNTAX_TYPE_STRING,
        .attribute = AT_SYNTAX_ATTR_OPTIONAL| AT_SYNTAX_ATTR_FIX_CASE | AT_SYNTAX_ATTR_MAX_LENGTH,
        .entry.string.max_length = 100,
        .offset = offsetof(mipi_args_t, para1)
    },
    {
        .type = AT_SYNTAX_TYPE_STRING,
        .attribute = AT_SYNTAX_ATTR_OPTIONAL| AT_SYNTAX_ATTR_FIX_CASE | AT_SYNTAX_ATTR_MAX_LENGTH,
        .entry.string.max_length = 100,
        .offset = offsetof(mipi_args_t, para2)
    },
    {
        .type = AT_SYNTAX_TYPE_STRING,
        .attribute = AT_SYNTAX_ATTR_OPTIONAL| AT_SYNTAX_ATTR_FIX_CASE | AT_SYNTAX_ATTR_MAX_LENGTH,
        .entry.string.max_length = 100,
        .offset = offsetof(mipi_args_t, para3)
    },
    {
        .type = AT_SYNTAX_TYPE_STRING,
        .attribute = AT_SYNTAX_ATTR_OPTIONAL| AT_SYNTAX_ATTR_FIX_CASE | AT_SYNTAX_ATTR_MAX_LENGTH,
        .entry.string.max_length = 100,
        .offset = offsetof(mipi_args_t, para4)
    },
    {
        .type = AT_SYNTAX_TYPE_STRING,
        .attribute = AT_SYNTAX_ATTR_OPTIONAL| AT_SYNTAX_ATTR_FIX_CASE | AT_SYNTAX_ATTR_MAX_LENGTH,
        .entry.string.max_length = 100,
        .offset = offsetof(mipi_args_t, para5)
    },
    {
        .type = AT_SYNTAX_TYPE_STRING,
        .attribute = AT_SYNTAX_ATTR_OPTIONAL| AT_SYNTAX_ATTR_FIX_CASE | AT_SYNTAX_ATTR_MAX_LENGTH,
        .entry.string.max_length = 100,
        .offset = offsetof(mipi_args_t, para6)
    },
    {
        .type = AT_SYNTAX_TYPE_STRING,
        .attribute = AT_SYNTAX_ATTR_OPTIONAL| AT_SYNTAX_ATTR_FIX_CASE | AT_SYNTAX_ATTR_MAX_LENGTH,
        .entry.string.max_length = 100,
        .offset = offsetof(mipi_args_t, para7)
    },
    {
        .type = AT_SYNTAX_TYPE_STRING,
        .attribute = AT_SYNTAX_ATTR_OPTIONAL| AT_SYNTAX_ATTR_FIX_CASE | AT_SYNTAX_ATTR_MAX_LENGTH,
        .entry.string.max_length = 100,
        .offset = offsetof(mipi_args_t, para8)
    },
    {
        .type = AT_SYNTAX_TYPE_STRING,
        .attribute = AT_SYNTAX_ATTR_OPTIONAL| AT_SYNTAX_ATTR_FIX_CASE | AT_SYNTAX_ATTR_MAX_LENGTH,
        .entry.string.max_length = 100,
        .offset = offsetof(mipi_args_t, para9)
    },
    {
        .type = AT_SYNTAX_TYPE_STRING,
        .attribute = AT_SYNTAX_ATTR_OPTIONAL| AT_SYNTAX_ATTR_FIX_CASE | AT_SYNTAX_ATTR_MAX_LENGTH,
        .entry.string.max_length = 100,
        .offset = offsetof(mipi_args_t, para10)
    },
    {
        .type = AT_SYNTAX_TYPE_STRING,
        .attribute = AT_SYNTAX_ATTR_OPTIONAL| AT_SYNTAX_ATTR_FIX_CASE | AT_SYNTAX_ATTR_MAX_LENGTH,
        .entry.string.max_length = 100,
        .offset = offsetof(mipi_args_t, para11)
    },
    {
        .type = AT_SYNTAX_TYPE_STRING,
        .attribute = AT_SYNTAX_ATTR_OPTIONAL| AT_SYNTAX_ATTR_FIX_CASE | AT_SYNTAX_ATTR_MAX_LENGTH,
        .entry.string.max_length = 100,
        .last = true,
        .offset = offsetof(mipi_args_t, para12)
    },
};

const at_cmd_entry_t g_at_mipi_cmd_parse_table[] = {
    {
        "MIPI",                             // name
        2,                                 // ID
        0,                                 // ATTRIBUTE
        g_mipi_parse_syntax,                // SYNTAX
        NULL,                              // cmd with no args, eg: AT+MIPI
        (at_set_func_t)at_mipi_tx_process, // cmd with args, eg: AT+MIPI=XX,XX,XX,XX
        NULL,                              // read cmd, eg: AT+MIPI?
        NULL,                              // test cmd, eg: AT+MIPI=?
    },
};

#endif  /* AT_MIPI_CMD_AT_CMD_TALBE_H */