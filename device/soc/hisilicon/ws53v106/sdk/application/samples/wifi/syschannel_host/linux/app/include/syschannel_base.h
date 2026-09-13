#ifndef __SYSCHANNEL_BASE_H__
#define __SYSCHANNEL_BASE_H__

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

#define CMD_MAX_LEN         1500
#define SOCK_BUF_MAX        1500
#define SOCK_PORT           8822

#define sample_log_print(fmt, args...) \
        printf("[%s][%s][%d]," fmt "\r\n", __FILE__, __FUNCTION__, __LINE__, ##args)

#define sample_unused(x) ((x) = (x))
#ifdef __cplusplus
}
#endif /* __cplusplus */
#endif