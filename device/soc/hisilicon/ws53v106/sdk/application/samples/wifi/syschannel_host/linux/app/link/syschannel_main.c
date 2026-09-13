/*
 * Copyright (c) HiSilicon (Shanghai) Technologies Co., Ltd. 2020-2020. All rights reserved.
 * Description: sample cli file.
 * Create: 2020-09-09
 */
/*****************************************************************************
  1 头文件包含
*****************************************************************************/
#include <unistd.h>
#include <signal.h>
#include <pthread.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <linux/sockios.h>
#include <linux/if.h>
#include <linux/wireless.h>

#include "securec.h"
#include "syschannel_host.h"
#include "syschannel_host_comm.h"

/*****************************************************************************
  2 宏定义、全局变量
*****************************************************************************/
static osal_s32 sample_exit_cmd_process(osal_void *wdata, osal_char *param, osal_u32 len, osal_void *pmsg);
static osal_s32 sample_help_cmd_process(osal_void *wdata, osal_char *param, osal_u32 len, osal_void *pmsg);

static const sample_cmd_entry_stru  g_sample_cmd[] = {
    {"help", sample_help_cmd_process},
    {"exit", sample_exit_cmd_process},
};

#define MAX_CMD_LEN 20
#define MAX_IPV4_LEN 16
#define WIFI_MAC_LEN 6
#define SLEEP_TIME 10
#define SAMPLE_CMD_NUM (sizeof(g_sample_cmd) / sizeof(g_sample_cmd[0]))
/*****************************************************************************
  3 枚举、结构体定义
*****************************************************************************/
typedef enum {
    /* commands */
    SAMPLE_CMD_IOCTL,
    SAMPLE_CMD_HELP,
    SAMPLE_CMD_EXIT,
    SAMPLE_CMD_BUTT,
} sample_cmd_e;

typedef enum {
    HOST_CMD_GET_MAC,
    HOST_CMD_GET_IP,
    HOST_CMD_SET_FILTER,
    HOST_CMD_TBTT,
}host_cmd_e;

/* command/event information */
typedef struct {
    sample_cmd_e what;
    osal_u32 len;
    osal_u8 obj[CMD_MAX_LEN];
} sample_message_s;

struct snode {
    sample_message_s message;
    struct snode *next;
};

struct squeue {
    struct snode *front;
    struct snode *rear;
};

typedef struct {
    pthread_mutex_t mut;
    pthread_cond_t cond;
    struct squeue cmd_queue;
    pthread_t sock_thread;
    osal_s32 sockfd;
} sample_link_s;

static osal_bool g_terminate = OSAL_FALSE;
static sample_link_s *g_sample_link = OSAL_NULL;
static osal_char host_cmd[][MAX_CMD_LEN] = {"cmd_get_mac", "cmd_get_ip", "cmd_set_filter"};
/*****************************************************************************
  4 函数实现
*****************************************************************************/
static osal_void sample_usage(osal_void)
{
    printf("\nUsage:\n");
    printf("\tsample_cli  quit          quit sample_ap\n");
    printf("\tsample_cli  help          show this message\n");
}

osal_s32 sample_str_cmd_process(osal_void *wdata, osal_char *param, osal_u32 len, osal_void *pmsg)
{
    sample_unused(wdata);
    sample_message_s *msg = (sample_message_s *)pmsg;
    msg->what = SAMPLE_CMD_IOCTL;
    msg->len = len;
    (osal_void)memcpy_s(msg->obj, CMD_MAX_LEN, param, len);
    msg->obj[CMD_MAX_LEN - 1] = '\0';
    return OSAL_OK;
}

osal_s32 sample_help_cmd_process(osal_void *wdata, osal_char *param, osal_u32 len, osal_void *pmsg)
{
    sample_unused(wdata);
    sample_unused(param);
    sample_unused(len);
    sample_message_s *msg = (sample_message_s *)pmsg;
    msg->what = SAMPLE_CMD_HELP;
    return OSAL_OK;
}

static osal_s32 sample_exit_cmd_process(osal_void *wdata, osal_char *param, osal_u32 len, osal_void *pmsg)
{
    sample_unused(wdata);
    sample_unused(param);
    sample_unused(len);
    sample_message_s *msg = (sample_message_s *)pmsg;
    msg->what = SAMPLE_CMD_EXIT;
    return OSAL_OK;
}

static osal_void sample_cleanup(osal_void)
{
    sample_log_print("sample_cleanup enter\n");
    if (g_sample_link->sock_thread) {
        pthread_cancel(g_sample_link->sock_thread);
        pthread_join(g_sample_link->sock_thread, OSAL_NULL);
    }

    pthread_mutex_destroy(&g_sample_link->mut);
    pthread_cond_destroy(&g_sample_link->cond);

    if (g_sample_link->sockfd != -1) {
        close(g_sample_link->sockfd);
    }

    if (g_sample_link != OSAL_NULL) {
        free(g_sample_link);
        g_sample_link = OSAL_NULL;
    }
}

static osal_void sample_terminate(osal_s32 sig)
{
    sample_unused(sig);
    sample_cleanup();
    g_terminate = OSAL_TRUE;
    _exit(0);
}

static osal_void sample_power(osal_s32 sig)
{
    sample_unused(sig);
}

static osal_s32 sample_wlan_init_up(osal_void)
{
    osal_s32 ret;
    osal_char cmd[SYSTEM_CMD_SIZE] = {0};

    (osal_void)memset_s(cmd, SYSTEM_CMD_SIZE, 0, SYSTEM_CMD_SIZE);
    if (snprintf_s(cmd, SYSTEM_CMD_SIZE, SYSTEM_CMD_SIZE - 1, "ifconfig %s up", SYSTEM_NETDEV_NAME) == -1) {
        sample_log_print("snprintf_s fail\n");
        return OSAL_NOK;
    }
    ret = system(cmd);
    if (ret == -1) {
        sample_log_print("%s up error\n", SYSTEM_NETDEV_NAME);
        return OSAL_NOK;
    }

    sample_log_print("net device up success\n");
    return OSAL_OK;
}

static osal_s32 sample_wlan_init_mac(osal_u8 *mac_addr, osal_u8 len)
{
    osal_s32 ret;
    osal_char cmd[SYSTEM_CMD_SIZE] = {0};

    if (len != WIFI_MAC_LEN) {
        return OSAL_NOK;
    }

    (osal_void)memset_s(cmd, SYSTEM_CMD_SIZE, 0, SYSTEM_CMD_SIZE);
    if (snprintf_s(cmd, SYSTEM_CMD_SIZE, SYSTEM_CMD_SIZE - 1, "ifconfig %s down", SYSTEM_NETDEV_NAME) == -1) {
        sample_log_print("snprintf_s fail\n");
        return OSAL_NOK;
    }
    ret = system(cmd);
    if (ret == -1) {
        sample_log_print("%s down error\n", SYSTEM_NETDEV_NAME);
        return OSAL_NOK;
    }

    (osal_void)memset_s(cmd, SYSTEM_CMD_SIZE, 0, SYSTEM_CMD_SIZE);
    if (snprintf_s(cmd, SYSTEM_CMD_SIZE, SYSTEM_CMD_SIZE - 1, "ifconfig %s hw ether %x:%x:%x:%x:%x:%x",
        /* 2, 3, 4, 5: MAC地址的第2, 3, 4, 5 Byte */
        SYSTEM_NETDEV_NAME, mac_addr[0], mac_addr[1], mac_addr[2], mac_addr[3], mac_addr[4], mac_addr[5]) == -1) {
        sample_log_print("snprintf_s fail\n");
        return OSAL_NOK;
    }
    ret = system(cmd);
    if (ret == -1) {
        sample_log_print("%s set mac error\n", SYSTEM_NETDEV_NAME);
        return OSAL_NOK;
    }

    (osal_void)memset_s(cmd, SYSTEM_CMD_SIZE, 0, SYSTEM_CMD_SIZE);
    if (snprintf_s(cmd, SYSTEM_CMD_SIZE, SYSTEM_CMD_SIZE - 1, "ifconfig %s up", SYSTEM_NETDEV_NAME) == -1) {
        sample_log_print("snprintf_s fail\n");
        return OSAL_NOK;
    }
    ret = system(cmd);
    if (ret == -1) {
        sample_log_print("%s up error\n", SYSTEM_NETDEV_NAME);
        return OSAL_NOK;
    }

    sample_log_print("net device set mac success\n");

    return OSAL_OK;
}

static osal_s32 sample_wlan_init_ip(osal_u8 *ip_addr, osal_u8 len)
{
    osal_s32 ret;
    osal_char cmd[SYSTEM_CMD_SIZE] = {0};

    sample_unused(len);
    if ((ip_addr[0] == 0) && (ip_addr[1] == 0) && (ip_addr[2] == 0) && (ip_addr[3] == 0)) { /* 1 2 3 ipaddr */
        return OSAL_OK;
    }

    (osal_void)memset_s(cmd, SYSTEM_CMD_SIZE, 0, SYSTEM_CMD_SIZE);
    if (snprintf_s(cmd, SYSTEM_CMD_SIZE, SYSTEM_CMD_SIZE - 1, "ifconfig %s down", SYSTEM_NETDEV_NAME) == -1) {
        sample_log_print("snprintf_s fail\n");
        return OSAL_NOK;
    }
    ret = system(cmd);
    if (ret == -1) {
        sample_log_print("%s down error\n", SYSTEM_NETDEV_NAME);
        return OSAL_NOK;
    }

    (osal_void)memset_s(cmd, SYSTEM_CMD_SIZE, 0, SYSTEM_CMD_SIZE);
    if (snprintf_s(cmd, SYSTEM_CMD_SIZE, SYSTEM_CMD_SIZE - 1,
        "ifconfig %s %d.%d.%d.%d netmask %d.%d.%d.%d",
        SYSTEM_NETDEV_NAME,
         /* 2, 3, 4, 5, 6, 7: 分别为IP地址的第2, 3, 4, 5, 6, 7 Byte */
        ip_addr[0], ip_addr[1], ip_addr[2], ip_addr[3], ip_addr[4], ip_addr[5], ip_addr[6], ip_addr[7]) == -1) {
        sample_log_print("snprintf_s fail\n");
        return OSAL_NOK;
    }

    ret = system(cmd);
    if (ret == -1) {
        sample_log_print("%s set ip error\n", SYSTEM_NETDEV_NAME);
        return OSAL_NOK;
    }

    (osal_void)memset_s(cmd, SYSTEM_CMD_SIZE, 0, SYSTEM_CMD_SIZE);
    if (snprintf_s(cmd, SYSTEM_CMD_SIZE, SYSTEM_CMD_SIZE - 1, "ifconfig %s up", SYSTEM_NETDEV_NAME) == -1) {
        sample_log_print("snprintf_s fail\n");
        return OSAL_NOK;
    }
    ret = system(cmd);
    if (ret == -1) {
        sample_log_print("%s up error\n", SYSTEM_NETDEV_NAME);
        return OSAL_NOK;
    }

    sample_log_print("net device set ip success\n");

    return OSAL_OK;
}

static osal_void set_lo_ipaddr(osal_void)
{
    osal_s32 ret;
    osal_s32 results;
    osal_char cmd[SYSTEM_CMD_SIZE] = {0}; /* system Temporary variables */
    osal_char *spawn_args[] = {"ifconfig", "lo", "127.0.0.1", OSAL_NULL};

    results = sprintf_s(cmd, sizeof(cmd), "%s %s %s", spawn_args[0], /* spawn_args[0]:ifconfig */
                        spawn_args[1], spawn_args[2]); /* spawn_args[1]:lo,spawn_args[2]:ipaddr */
    if (results < EOK) {
        sample_log_print("SAMPLE_STA: set lo ipaddr sprintf_s err!\n");
        return;
    }

    ret = system(cmd);
    if (ret == -1) {
        sample_log_print("%s up error\n", SYSTEM_NETDEV_NAME);
        return;
    }
}

static osal_s32 sample_sock_create(osal_void)
{
    osal_char errbuf[256];
    errbuf[0] = '\0';
    if (g_sample_link == OSAL_NULL) {
        return OSAL_NOK;
    }

    g_sample_link->sockfd = socket(AF_INET, SOCK_DGRAM, 0);
    if (g_sample_link->sockfd == -1) {
        strerror_r(errno, errbuf, sizeof(errbuf));
        sample_log_print("error:%s", errbuf);
        return OSAL_NOK;
    }

    struct sockaddr_in servaddr;
    servaddr.sin_family = AF_INET;
    servaddr.sin_addr.s_addr = htonl(INADDR_ANY);
    servaddr.sin_port = htons(SOCK_PORT);

    if (bind(g_sample_link->sockfd, (const struct sockaddr *)&servaddr, sizeof(servaddr)) == -1) {
        strerror_r(errno, errbuf, sizeof(errbuf));
        sample_log_print("error:%s", errbuf);
        return OSAL_NOK;
    }

    return OSAL_OK;
}

static osal_s32 sample_enqueue(struct squeue *pqueue, const sample_message_s *element)
{
    struct snode *pnew = OSAL_NULL;

    if (pqueue == OSAL_NULL || element == OSAL_NULL) {
        return -1;
    }
    /* Create a new node */
    pnew = malloc(sizeof(struct snode));
    if (pnew == OSAL_NULL) {
        return -1;
    }

    pnew->message = *element;
    pnew->next = OSAL_NULL;

    if (pqueue->rear == OSAL_NULL) {
        /* queue is empty, set front and rear points to new node */
        pqueue->front = pqueue->rear = pnew;
    } else {
        /* queue is not empty, set rear points to the new node */
        pqueue->rear = pqueue->rear->next = pnew;
    }

    return OSAL_OK;
}

static osal_s32 sample_dequeue(struct squeue *pqueue, sample_message_s *element)
{
    struct snode *p = OSAL_NULL;

    if (pqueue == OSAL_NULL || element == OSAL_NULL) {
        return OSAL_NOK;
    }

    if (pqueue->front == OSAL_NULL) {
        return OSAL_NOK;
    }

    *element = pqueue->front->message;
    p = pqueue->front;
    pqueue->front = p->next;
    /* if the queue is empty, set rear = NULL */
    if (pqueue->front == OSAL_NULL) {
        pqueue->rear = OSAL_NULL;
    }

    free(p);
    return OSAL_OK;
}

static osal_void *sample_sock_thread(osal_void *args)
{
    osal_char link_buf[SOCK_BUF_MAX];
    ssize_t recvbytes;
    sample_message_s message;
    struct sockaddr_in clientaddr;
    socklen_t addrlen = sizeof(clientaddr);
    sample_unused(args);

    while (1) {
        /* 安全编程规则6.6例外(1) 对固定长度的数组进行初始化，或对固定长度的结构体进行内存初始化 */
        (osal_void)memset_s(link_buf, sizeof(link_buf), 0, sizeof(link_buf));
        /* 安全编程规则6.6例外(1) 对固定长度的数组进行初始化，或对固定长度的结构体进行内存初始化 */
        (osal_void)memset_s(&clientaddr, sizeof(struct sockaddr_in), 0, addrlen);

        recvbytes = recvfrom(g_sample_link->sockfd, link_buf, sizeof(link_buf), 0,
                             (struct sockaddr *)&clientaddr, &addrlen);
        if (recvbytes < 0) {
            if (errno == EINTR) {
                usleep(SLEEP_TIME);
                continue;
            } else {
                sample_log_print("recvfrom error! fd:%d\n", g_sample_link->sockfd);
                return OSAL_NULL;
            }
        }

        if (sample_sock_cmd_entry(g_sample_link, link_buf, recvbytes, (osal_void *)&message) != OSAL_OK) {
            sample_log_print("sample_str_cmd_process entry\n");
            sample_str_cmd_process(g_sample_link, link_buf, recvbytes, (osal_void *)&message);
        }

        if (sendto(g_sample_link->sockfd, "OK", strlen("OK"), MSG_DONTWAIT, (const struct sockaddr *)&clientaddr,
                   addrlen) == -1) {
            sample_log_print("sendto error!fd:%d\n", g_sample_link->sockfd);
        }

        pthread_mutex_lock(&g_sample_link->mut);
        if (sample_enqueue(&g_sample_link->cmd_queue, &message) == OSAL_OK) {
            pthread_cond_signal(&g_sample_link->cond);
        }
        pthread_mutex_unlock(&g_sample_link->mut);
    }
}

void sample_link_rec_cb(unsigned char *msg_data, int len)
{
    osal_s32 ret;
    osal_s32 index;

    if ((len == 0) || (msg_data == OSAL_NULL)) {
        return;
    }

    index = msg_data[0];
    sample_log_print("hisi_link_rec:%d\n", index);
    if (index == HOST_CMD_GET_MAC) {
        ret = sample_wlan_init_mac(&msg_data[1], WIFI_MAC_LEN);
        if (ret != OSAL_OK) {
            sample_log_print("sample_wlan_init_mac is fail\n");
        }
    } else if (index == HOST_CMD_GET_IP) {
        ret = sample_wlan_init_ip(&msg_data[1], len - 1);
        if (ret != OSAL_OK) {
            sample_log_print("sample_wlan_init_ip is fail\n");
        }
    } else {
        sample_log_print("hisi_link_rec is fail\n");
    }
}

void main_process(void)
{
    /* main loop */
    while (!g_terminate) {
        sample_message_s message;
        pthread_mutex_lock(&g_sample_link->mut);
        while (sample_dequeue(&g_sample_link->cmd_queue, &message) != OSAL_OK) {
            pthread_cond_wait(&g_sample_link->cond, &g_sample_link->mut);
        }
        pthread_mutex_unlock(&g_sample_link->mut);
        sample_log_print("=====SAMPLE LOOP RECIEVE MSG:%d LEN:%d=====\n", message.what, message.len);
        if (fflush(stdout) != 0) {
            sample_log_print("fflush stdout fail\n");
        }

        switch (message.what) {
            case SAMPLE_CMD_HELP:
                sample_usage();
                break;
            case SAMPLE_CMD_EXIT:
                g_terminate = OSAL_TRUE;
                break;
            case SAMPLE_CMD_IOCTL:
                if (syschannel_send_to_dev(message.obj, message.len) != OSAL_OK) {
                    sample_log_print("sample_iwpriv_cmd send fail\n");
                }
                break;
            default:
                break;
        }
    }
}

int main(int argc, char *argv[])
{
    osal_s32 ret;
    sample_unused(argc);
    sample_unused(argv);
    set_lo_ipaddr();

    if ((signal(SIGINT, sample_terminate) == SIG_ERR) || \
        (signal(SIGTERM, sample_terminate) == SIG_ERR) || \
        (signal(SIGPWR, sample_power) == SIG_ERR)) {
        return -1;
    }

    g_sample_link = (sample_link_s *)malloc(sizeof(sample_link_s));
    if (g_sample_link == OSAL_NULL) {
        return -1;
    }

    (void)memset_s(g_sample_link, sizeof(sample_link_s), 0, sizeof(sample_link_s));
    pthread_mutex_init(&g_sample_link->mut, OSAL_NULL);
    pthread_cond_init(&g_sample_link->cond, OSAL_NULL);

    if (sample_wlan_init_up() != OSAL_OK) {
        sample_log_print("sample_wlan_init_up is fail\n");
    }

    if (syschannel_init() != OSAL_OK) {
        sample_log_print("syschannel_init is fail\n");
    }

    syschannel_register_rx_cb(sample_link_rec_cb);
    syschannel_send_to_dev((osal_u8 *)host_cmd[HOST_CMD_GET_MAC], (osal_s32)strlen(host_cmd[HOST_CMD_GET_MAC]));

    if (sample_register_cmd((sample_cmd_entry_stru *)&g_sample_cmd, SAMPLE_CMD_NUM) != OSAL_OK) {
        sample_log_print("register wlan cmd is fail\n");
        goto link_out;
    }

    if (sample_sock_create() != OSAL_OK) {
        sample_log_print("create sock is fail\n");
        goto link_out;
    }

    ret = pthread_create(&g_sample_link->sock_thread, OSAL_NULL, sample_sock_thread, OSAL_NULL);
    if (ret != OSAL_OK) {
        sample_log_print("create sock thread is fail\n");
        goto link_out;
    }

    main_process();

link_out:
    sample_cleanup();
    return 0;
}

