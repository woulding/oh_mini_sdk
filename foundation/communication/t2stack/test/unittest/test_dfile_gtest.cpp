/*
 * Copyright (C) 2023 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include <string>
#include <random>
#include <algorithm>

#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <openssl/md5.h>
#include <dirent.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <sys/mman.h>
#include "nstackx_dfile.h"
#include "nstackx_dfile_session.h"
#include "nstackx_dfile_dfx.h"
#include "nstackx_dfile_retransmission.h"
#include "nstackx_dfile_private.h"
#include "nstackx_file_manager_client.h"
#include "rbtree.h"
#include "gtest/gtest.h"
#include "securec.h"

using namespace std;

#define DFILE_SEND_FILE_NAME "dfile.1M"
#define DFILE_SEND_FILE_RENAME_BAK "-BAK"
#define DFILE_SEND_FILE_SIZE (1024 * 1024)
#define DFILE_SEND_FILE_NAME_100M "dfile.100M"
#define DFILE_SEND_FILE_SIZE_100M (100 * 1024 * 1024)
#define DFILE_RECV_REMOTE_PATH "/sdcard/"
#define DFILE_DEFAULT_STORAGE_PATH  "./recv/"
#define DFILE_DEFAULT_SEND_PATH  "./send/"
#define DFILE_SESSION_ID_OFFEST 2
#define DFILE_DEFAULT_PATH_LEN 100
#define DFILE_MD5_ARRAY_SIZE   16
#define DFILE_MD5_STR_SIZE     100
#define DFLIE_MD5_BLOCK_LENGTH 1024
#define DFILE_MP_PARA_NUM      2
#define RBTREE_NUM_NODES       1000000
#define DFILE_DUMP_CMD_NUM_MAX 20
#define DFILE_UT_BUF_LEN       1000
#define DEFAULT_DFILE_SERVER_PORT 8197
#define FILE_PATH_LEN 4100
#define SLEEP_SECOND_LOW 2
#define SLEEP_SECOND_HIGH 10
#define SET_CAPABILITIES_VALUE_FOUR 4
#define CMD_COUNT 2
#define FILE_AUTHOPITY_LOW 0600
#define FILE_AUTHOPITY_HIGH 0755

const string g_default_ip("127.0.0.1");
const string g_default_second_ip("192.168.10.1");
const unsigned short g_default_port = 8097;
const char *g_files[FILE_PATH_LEN] = { nullptr };
struct sockaddr_in g_defaultAddr;
NSTACKX_ServerParaMp g_mp_serverPara[DFILE_MP_PARA_NUM];
NSTACKX_SessionParaMp g_mp_clinetPara[DFILE_MP_PARA_NUM];
DFileDirCallback g_set;
static int g_recvSucc = NSTACKX_FALSE;
static int g_sendFileNums = 10;
static int g_restFileNums = 0;
static int g_sid = 0;
static int g_cid = 0;
static sem_t g_sem;

using pii = std::pair<int, int>;

static void InitDefaultAddr(unsigned short port)
{
    (void)memset_s(&g_defaultAddr, sizeof(g_defaultAddr), 0, sizeof(g_defaultAddr));
    g_defaultAddr.sin_family = AF_INET;
    if (port) {
        g_defaultAddr.sin_port = port;
    } else {
        g_defaultAddr.sin_port = g_default_port;
    }
    g_defaultAddr.sin_addr.s_addr = ntohl(inet_addr(g_default_ip.c_str()));
}

static int CreateFileWithSize(const char *fileName, int fileSize)
{
    FILE *fp = fopen(fileName, "wb");
    if (!fp) {
        return NSTACKX_EFAILED;
    }

    (void)fseek(fp, fileSize - 1, SEEK_SET);
    int ret = fwrite(" ", 1, 1, fp);
    if (ret <= 0) {
        return NSTACKX_EFAILED;
    }
    (void)fclose(fp);
    return NSTACKX_EOK;
}

static int CreateFolder(const char *path)
{
#ifdef BUILD_FOR_UNIX
    return (mkdir(path, FILE_AUTHOPITY_HIGH) == 0);
#else
    return (mkdir(path, FILE_AUTHOPITY_LOW) == 0);
#endif
}

static int UTIsExistingFile(const char *fileName)
{
    return (access(fileName, F_OK) == 0);
}

static int RemoveDir(const char *dir)
{
    char cur_dir[] = ".";
    char up_dir[] = "..";
    char dir_name[PATH_MAX] = {0};
    DIR *dirp;
    struct dirent *dp;
    struct stat dirStat;
    if ((access(dir, F_OK) != 0)) {
        return NSTACKX_EOK;
    }
    if (stat(dir, &dirStat) < 0) {
        return NSTACKX_EFAILED;
    }
    if (S_ISREG(dirStat.st_mode)) {
        (void)remove(dir);
    } else if (S_ISDIR(dirStat.st_mode)) {
        dirp = opendir(dir);
        while ((dp = readdir(dirp)) != nullptr) {
            if ((strcmp(cur_dir, dp->d_name) == 0) || (strcmp(up_dir, dp->d_name) == 0)) {
                continue;
            }
            (void)sprintf_s(dir_name, sizeof(dir_name), "%s/%s", dir, dp->d_name);
            RemoveDir(dir_name);
        }
        closedir(dirp);
        rmdir(dir);
    } else {
        return NSTACKX_EFAILED;
    }
    return NSTACKX_EOK;
}

static void RenameFileCalbak(DFileRenamePara *renamePara)
{
    (void)sprintf_s(renamePara->newFileName, NSTACKX_MAX_REMOTE_PATH_LEN, "%s%s",
        renamePara->initFileName, DFILE_SEND_FILE_RENAME_BAK);
    return;
}

static int GetFileMD5(const char *filepath, char *md5Str, int length)
{
    struct stat fileStat;
    unsigned char md5[DFILE_MD5_ARRAY_SIZE];
    int fd;

    if ((fd = open(filepath, O_RDONLY)) <= 0) {
        return NSTACKX_EFAILED;
    }

    if (stat(filepath, &fileStat) < 0) {
        close(fd);
        return NSTACKX_EFAILED;
    }

    int fileSize = fileStat.st_size;
    unsigned char *p = (unsigned char*)mmap(nullptr, fileSize,
        PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_POPULATE, fd, 0);
    if (p == MAP_FAILED) {
        close(fd);
        return NSTACKX_EFAILED;
    }

    MD5((unsigned char *)p, fileSize, md5);

    (void)memset_s(md5Str, length, 0, length);
    for (int i = 0; i < DFILE_MD5_ARRAY_SIZE; i++) {
        (void)sprintf_s(md5Str + strlen(md5Str), DFILE_MD5_STR_SIZE - strlen(md5Str), "%02X", md5[i]);
    }

    munmap(p, fileSize);
    close(fd);
    return NSTACKX_EOK;
}

int FileMd5Equal(char *file1, char *file2)
{
    char sendFileMD5[DFILE_MD5_STR_SIZE];
    char recvFileMD5[DFILE_MD5_STR_SIZE];

    if (!UTIsExistingFile(file1) || !UTIsExistingFile(file2)) {
        return NSTACKX_EFAILED;
    }

    if (GetFileMD5(file1, sendFileMD5, DFILE_MD5_STR_SIZE) != NSTACKX_EOK ||
        GetFileMD5(file2, recvFileMD5, DFILE_MD5_STR_SIZE) != NSTACKX_EOK) {
        return NSTACKX_EFAILED;
    }

    int ret = (strcmp(sendFileMD5, recvFileMD5) == 0) ? NSTACKX_TRUE : NSTACKX_FALSE;
    return ret;
}

static void MsgReceiver(int32_t sid, DFileMsgType msgType, const DFileMsg *msg)
{
    (void)msg;
    printf("MsgReceiver: session %d, msgtype: %d\n", sid, msgType);

    if (msgType == DFILE_ON_FILE_RECEIVE_SUCCESS) {
        for (uint32_t i = 0; i < msg->fileList.fileNum; i++) {
            printf("MsgReceiver: recv success, %s\n", msg->fileList.files[i]);
        }
        g_recvSucc += msg->fileList.fileNum;
    }
    if (msgType == DFILE_ON_FILE_SEND_FAIL || msgType == DFILE_ON_FATAL_ERROR) {
        for (uint32_t i = 0; i < msg->fileList.fileNum; i++) {
            printf("MsgReceiver: rest files, %s\n", msg->fileList.files[i]);
        }
        if (msg->fileList.fileNum) {
            int ret = NSTACKX_DFileSendFiles(g_cid, msg->fileList.files, msg->fileList.fileNum, nullptr);
            EXPECT_EQ(ret, 0);
            g_restFileNums = msg->fileList.fileNum;
        }
    }
    return;
}

static void NewLogImpl(const char *tag, uint32_t level, const char *format, va_list args)
{
    time_t now;

    (void)time(&now);
    struct tm *tm_now = localtime(&now);

    printf("%02d-%02d %02d:%02d:%02d %d %d %s: ",
        tm_now->tm_mon, tm_now->tm_mday, tm_now->tm_hour, tm_now->tm_min, tm_now->tm_sec,
        getpid(), level, tag);
    vprintf(format, args);
}

#ifdef ENABLE_USER_LOG
__attribute__((format(printf, 3, 4))) static void Printflog(const char *moduleName,
    uint32_t logLevel, const char *format, ...)
{
    const char *tag = moduleName;
    va_list args;
    va_start(args, format);
    time_t now;
    (void)time(&now);
    struct tm *tm_now = localtime(&now);

    printf("PLOG %02d-%02d %02d:%02d:%02d %d %d %s: ",
        tm_now->tm_mon, tm_now->tm_mday, tm_now->tm_hour,
        tm_now->tm_min, tm_now->tm_sec, getpid(), logLevel, tag);
    vprintf(format, args);
    va_end(args);
}
#endif

static int32_t InitDFileServerParaMp(NSTACKX_ServerParaMp *para, uint8_t paraNum, int port)
{
    if (para == nullptr || paraNum <= 0) {
        return NSTACKX_EFAILED;
    }

    for (int32_t i = 0; i < paraNum; i++) {
        para[i].addr = (struct sockaddr_in *)calloc(1, sizeof(struct sockaddr_in));
        if (para[i].addr == nullptr) {
            goto MALLOC_FAIL;
        }
        para[i].addr->sin_family = AF_INET;
        if (port) {
            para[i].addr->sin_port = port + i;
        } else {
            para[i].addr->sin_port = g_default_port + i;
        }
        para[i].addr->sin_addr.s_addr = ntohl(inet_addr(g_default_ip.c_str()));
        para[i].addrLen = sizeof(struct sockaddr_in);
    }
    return NSTACKX_EOK;

MALLOC_FAIL:
    for (int32_t i = 0; i < paraNum; i++) {
        if (para[i].addr != nullptr) {
            free(para[i].addr);
            para[i].addr = nullptr;
        }
    }
    return NSTACKX_EFAILED;
}

static int32_t InitDFileServerParaMpEscape(NSTACKX_ServerParaMp *para, uint8_t paraNum)
{
    if (para == nullptr || paraNum <= 0) {
        return NSTACKX_EFAILED;
    }

    for (int32_t i = 0; i < paraNum; i++) {
        para[i].addr = (struct sockaddr_in *)calloc(1, sizeof(struct sockaddr_in));
        if (para[i].addr == nullptr) {
            goto MALLOC_FAIL;
        }
        para[i].addr->sin_family = AF_INET;
        para[i].addr->sin_port = g_default_port + i;
        para[i].addrLen = sizeof(struct sockaddr_in);
    }
    para[0].addr->sin_addr.s_addr = ntohl(inet_addr(g_default_ip.c_str()));
    para[1].addr->sin_addr.s_addr = ntohl(inet_addr(g_default_second_ip.c_str()));
    return NSTACKX_EOK;

MALLOC_FAIL:
    for (int32_t i = 0; i < paraNum; i++) {
        if (para[i].addr != nullptr) {
            free(para[i].addr);
            para[i].addr = nullptr;
        }
    }
    return NSTACKX_EFAILED;
}

static uint32_t InitDFileClientParaMp(NSTACKX_SessionParaMp *clientPara,
    NSTACKX_ServerParaMp *serverPara, uint8_t paraNum)
{
    if (clientPara == nullptr || serverPara == nullptr || paraNum <= 0) {
        return NSTACKX_EFAILED;
    }

    for (int32_t i = 0; i < paraNum; i++) {
        clientPara[i].addr = serverPara[i].addr;
        clientPara[i].addrLen = serverPara[i].addrLen;
        clientPara[i].localInterfaceName = nullptr;
    }
    return NSTACKX_EOK;
}

static void FreeDFileServerAddrMp(NSTACKX_ServerParaMp *para, uint8_t paraNum)
{
    if (para == nullptr || paraNum <= 0) {
        return;
    }

    for (int32_t i = 0; i < paraNum; i++) {
        if (para[i].addr != nullptr) {
            free(para[i].addr);
            para[i].addr = nullptr;
        }
    }
}

class NSTACKX_DFILE_WITH_SETUP_AND_TEARDOWN : public ::testing::Test {
public:
    void SetUp()
    {
        g_recvSucc = NSTACKX_FALSE;
        InitDefaultAddr(0);
        int ret = CreateFileWithSize(DFILE_SEND_FILE_NAME, DFILE_SEND_FILE_SIZE);
        ASSERT_EQ(ret, NSTACKX_EOK);
        ret = CreateFileWithSize(DFILE_SEND_FILE_NAME_100M, DFILE_SEND_FILE_SIZE_100M);
        ASSERT_EQ(ret, NSTACKX_EOK);
        if (!UTIsExistingFile(DFILE_DEFAULT_STORAGE_PATH)) {
            ret = CreateFolder(DFILE_DEFAULT_STORAGE_PATH);
            ASSERT_GT(ret, 0);
        }
    }
    void TearDown()
    {
        (void)remove(DFILE_SEND_FILE_NAME);
        (void)remove(DFILE_SEND_FILE_NAME_100M);
        RemoveDir(DFILE_DEFAULT_STORAGE_PATH);
    }
};

class BREAKPOINT_RESUME_SETUP_AND_TEARDOWN : public ::testing::Test {
public:
    char fileName[DFILE_DEFAULT_PATH_LEN] = {0};
    void SetUp()
    {
        g_recvSucc = NSTACKX_FALSE;
        InitDefaultAddr(0);
        int ret = InitDFileServerParaMp(g_mp_serverPara, DFILE_MP_PARA_NUM, 0);
        ASSERT_EQ(ret, NSTACKX_EOK);

        ret = InitDFileClientParaMp(g_mp_clinetPara, g_mp_serverPara, DFILE_MP_PARA_NUM);
        ASSERT_EQ(ret, NSTACKX_EOK);

        for (int i = 0; i < g_sendFileNums; i++) {
            (void)memset_s(fileName, sizeof(fileName), 0, sizeof(fileName));
            (void)sprintf_s(fileName, sizeof(fileName), "%s-%d", DFILE_SEND_FILE_NAME_100M, i);
            ret = CreateFileWithSize(fileName, DFILE_SEND_FILE_SIZE_100M);
            ASSERT_EQ(ret, NSTACKX_EOK);
        }

        if (!UTIsExistingFile(DFILE_DEFAULT_STORAGE_PATH)) {
            ret = CreateFolder(DFILE_DEFAULT_STORAGE_PATH);
            ASSERT_GT(ret, 0);
        }
        system("iptables -D INPUT -p tcp --dport 8097 -j REJECT");
        system("iptables -D OUTPUT -p tcp --sport 8097 -j REJECT");
        system("iptables -D INPUT -p udp --dport 8097 -j REJECT");
        system("iptables -D OUTPUT -p udp --sport 8097 -j REJECT");
    }
    void TearDown()
    {
        for (int i = 0; i < g_sendFileNums; i++) {
            (void)memset_s(fileName, sizeof(fileName), 0, sizeof(fileName));
            (void)sprintf_s(fileName, sizeof(fileName), "%s-%d", DFILE_SEND_FILE_NAME_100M, i);
            printf("delete file %s\n", fileName);
            (void)remove(fileName);
        }
        RemoveDir(DFILE_DEFAULT_STORAGE_PATH);
        FreeDFileServerAddrMp(g_mp_serverPara, DFILE_MP_PARA_NUM);
        system("iptables -D INPUT -p tcp --dport 8097 -j REJECT");
        system("iptables -D OUTPUT -p tcp --sport 8097 -j REJECT");
        system("iptables -D INPUT -p udp --dport 8097 -j REJECT");
        system("iptables -D OUTPUT -p udp --sport 8097 -j REJECT");
    }
};

class MpEscape_SETUP_AND_TEARDOWN : public ::testing::Test {
public:
    char fileName[DFILE_DEFAULT_PATH_LEN] = {0};
    void SetUp()
    {
        g_recvSucc = NSTACKX_FALSE;
        InitDefaultAddr(0);
        int ret = InitDFileServerParaMpEscape(g_mp_serverPara, DFILE_MP_PARA_NUM);
        ASSERT_EQ(ret, NSTACKX_EOK);

        ret = InitDFileClientParaMp(g_mp_clinetPara, g_mp_serverPara, DFILE_MP_PARA_NUM);
        ASSERT_EQ(ret, NSTACKX_EOK);

        for (int i = 0; i < g_sendFileNums; i++) {
            (void)memset_s(fileName, sizeof(fileName), 0, sizeof(fileName));
            (void)sprintf_s(fileName, sizeof(fileName), "%s-%d", DFILE_SEND_FILE_NAME_100M, i);
            ret = CreateFileWithSize(fileName, DFILE_SEND_FILE_SIZE_100M);
            ASSERT_EQ(ret, NSTACKX_EOK);
        }

        if (!UTIsExistingFile(DFILE_DEFAULT_STORAGE_PATH)) {
            ret = CreateFolder(DFILE_DEFAULT_STORAGE_PATH);
            ASSERT_GT(ret, 0);
        }
        system("mkdir -p /dev/net && ln -s  /dev/tun /dev/net/tun");
        system("ip tuntap add dev tap0 mod tap");
        system("ifconfig tap0 192.168.10.1");
    }
    void TearDown()
    {
        for (int i = 0; i < g_sendFileNums; i++) {
            (void)memset_s(fileName, sizeof(fileName), 0, sizeof(fileName));
            (void)sprintf_s(fileName, sizeof(fileName), "%s-%d", DFILE_SEND_FILE_NAME_100M, i);
            printf("delete file %s\n", fileName);
            (void)remove(fileName);
        }
        RemoveDir(DFILE_DEFAULT_STORAGE_PATH);
        FreeDFileServerAddrMp(g_mp_serverPara, DFILE_MP_PARA_NUM);
        system("ip tuntap del dev tap0 mod tap");
    }
};

class NSTACKX_DFILE_MP : public ::testing::Test {
public:
    void SetUp()
    {
        g_recvSucc = NSTACKX_FALSE;
        int ret = InitDFileServerParaMp(g_mp_serverPara, DFILE_MP_PARA_NUM, 0);
        ASSERT_EQ(ret, NSTACKX_EOK);

        ret = InitDFileClientParaMp(g_mp_clinetPara, g_mp_serverPara, DFILE_MP_PARA_NUM);
        ASSERT_EQ(ret, NSTACKX_EOK);

        ret = CreateFileWithSize(DFILE_SEND_FILE_NAME_100M, DFILE_SEND_FILE_SIZE_100M);
        ASSERT_EQ(ret, NSTACKX_EOK);

        if (!UTIsExistingFile(DFILE_DEFAULT_STORAGE_PATH)) {
            ret = CreateFolder(DFILE_DEFAULT_STORAGE_PATH);
            ASSERT_GT(ret, 0);
        }
    }
    void TearDown()
    {
        (void)remove(DFILE_SEND_FILE_NAME_100M);
        RemoveDir(DFILE_DEFAULT_STORAGE_PATH);
        FreeDFileServerAddrMp(g_mp_serverPara, DFILE_MP_PARA_NUM);
    }
};

TEST(NSTACKX_DFILE, CreateServerEncrypt)
{
    const string key("aaaaaaaaaaaaaaaa");

    InitDefaultAddr(0);
    int sid = NSTACKX_DFileServer(nullptr, 0, nullptr, 0, nullptr);
    ASSERT_LT(sid, 0);

    sid = NSTACKX_DFileServer(&g_defaultAddr, sizeof(g_defaultAddr),
                              (const uint8_t *)key.c_str(), key.length(), nullptr);
    ASSERT_GT(sid, 0);

    NSTACKX_DFileClose(sid);
    sleep(1);
}

TEST(NSTACKX_DFILE, CreateServerNonEncrypt)
{
    InitDefaultAddr(0);
    int sid = NSTACKX_DFileServer(nullptr, 0, nullptr, 0, nullptr);
    ASSERT_LT(sid, 0);

    sid = NSTACKX_DFileServer(&g_defaultAddr, sizeof(g_defaultAddr), nullptr, 0, nullptr);
    ASSERT_GT(sid, 0);

    NSTACKX_DFileClose(sid);
    sleep(1);
}

TEST(NSTACKX_DFILE, CreateClientEncrypt)
{
    const string key("aaaaaaaaaaaaaaaa");

    InitDefaultAddr(0);
    int sid = NSTACKX_DFileClient(nullptr, 0, nullptr, 0, nullptr);
    ASSERT_LT(sid, 0);

    sid = NSTACKX_DFileClient(&g_defaultAddr, sizeof(g_defaultAddr),
                              (const uint8_t *)key.c_str(), key.length(), nullptr);
    ASSERT_GT(sid, 0);

    NSTACKX_DFileClose(sid);
    sleep(1);
}

TEST(NSTACKX_DFILE, CreateClientNonEncrypt)
{
    InitDefaultAddr(0);
    int sid = NSTACKX_DFileClient(&g_defaultAddr, sizeof(g_defaultAddr), nullptr, 0, nullptr);
    ASSERT_GT(sid, 0);

    NSTACKX_DFileClose(sid);
    sleep(1);
}

TEST(NSTACKX_DFILE, CreateServerV2Encrypt)
{
    const string key("aaaaaaaaaaaaaaaa");

    uint32_t abmStatus = 0;

    InitDefaultAddr(0);
    int sid = NSTACKX_DFileServerV2(nullptr, 0, nullptr, 0, nullptr, abmStatus);
    ASSERT_LT(sid, 0);

    sid = NSTACKX_DFileServerV2(&g_defaultAddr, sizeof(g_defaultAddr),
                                (const uint8_t *)key.c_str(), key.length(), nullptr, abmStatus);
    ASSERT_GT(sid, 0);

    NSTACKX_DFileClose(sid);
    sleep(1);
}

TEST(NSTACKX_DFILE, CreateServerV2NonEncrypt)
{
    uint32_t abmStatus = 0;

    InitDefaultAddr(0);
    int sid = NSTACKX_DFileServerV2(nullptr, 0, nullptr, 0, nullptr, abmStatus);
    ASSERT_LT(sid, 0);

    sid = NSTACKX_DFileServerV2(&g_defaultAddr, sizeof(g_defaultAddr), nullptr, 0, nullptr, abmStatus);
    ASSERT_GT(sid, 0);

    NSTACKX_DFileClose(sid);
    sleep(1);
}

TEST(NSTACKX_DFILE, CreateClientV2Encrypt)
{
    const string key("aaaaaaaaaaaaaaaa");

    uint32_t abmStatus = 0;

    InitDefaultAddr(0);
    int sid = NSTACKX_DFileClientV2(nullptr, 0, nullptr, 0, nullptr, abmStatus);
    ASSERT_LT(sid, 0);

    sid = NSTACKX_DFileClientV2(&g_defaultAddr, sizeof(g_defaultAddr),
                                (const uint8_t *)key.c_str(), key.length(), nullptr, abmStatus);
    ASSERT_GT(sid, 0);

    NSTACKX_DFileClose(sid);
    sleep(1);
}

TEST(NSTACKX_DFILE, CreateClientV2NonEncrypt)
{
    uint32_t abmStatus = 0;

    InitDefaultAddr(0);
    int sid = NSTACKX_DFileClientV2(&g_defaultAddr, sizeof(g_defaultAddr), nullptr, 0, nullptr, abmStatus);
    ASSERT_GT(sid, 0);

    NSTACKX_DFileClose(sid);
    sleep(1);
}

TEST(NSTACKX_DFILE, SetStoragePath)
{
    InitDefaultAddr(0);
    int sid = NSTACKX_DFileServer(&g_defaultAddr, sizeof(g_defaultAddr), nullptr, 0, nullptr);
    ASSERT_GT(sid, 0);

    int err = NSTACKX_DFileSetStoragePath(sid, "/qqqqqqqq");
    EXPECT_LT(err, 0);

#ifdef BUILD_FOR_UNIX
    if (!UTIsExistingFile(DFILE_DEFAULT_STORAGE_PATH)) {
        err = CreateFolder(DFILE_DEFAULT_STORAGE_PATH);
        ASSERT_GT(err, 0);
    }
    err = NSTACKX_DFileSetStoragePath(sid, DFILE_DEFAULT_STORAGE_PATH); // diff path
    EXPECT_EQ(err, 0);
    RemoveDir(DFILE_DEFAULT_STORAGE_PATH);
#else
    err = NSTACKX_DFileSetStoragePath(sid, DFILE_RECV_REMOTE_PATH); // diff path
    EXPECT_EQ(err, 0);
#endif

    NSTACKX_DFileClose(sid);
    sleep(1);
}

TEST(NSTACKX_DFILE, CreateClientWithTargetDev)
{
    NSTACKX_SessionPara sessionPara;

    InitDefaultAddr(0);
    sessionPara.addr = &g_defaultAddr;
    sessionPara.addrLen = sizeof(g_defaultAddr);
    sessionPara.key = nullptr;
    sessionPara.keyLen = 0;
    sessionPara.msgReceiver = nullptr;
    sessionPara.localInterfaceName = nullptr;

    int sid = NSTACKX_DFileClientWithTargetDev(nullptr);
    ASSERT_LT(sid, 0);
    sid = NSTACKX_DFileClientWithTargetDev(&sessionPara);
    ASSERT_GT(sid, 0);
    NSTACKX_DFileClose(sid);

    const string key("aaaaaaaaaaaaaaaa");
    sessionPara.key = (const uint8_t *)key.c_str();
    sessionPara.keyLen = key.length();

    /* Encrypt */
    sid = NSTACKX_DFileClientWithTargetDev(&sessionPara);
    ASSERT_GT(sid, 0);
    NSTACKX_DFileClose(sid);
    sleep(1);
}

TEST(NSTACKX_DFILE, CreateClientWithTargetDevV2)
{
    NSTACKX_SessionPara sessionPara;
    uint32_t abmStatus = 0;

    InitDefaultAddr(0);
    sessionPara.addr = &g_defaultAddr;
    sessionPara.addrLen = sizeof(g_defaultAddr);
    sessionPara.key = nullptr;
    sessionPara.keyLen = 0;
    sessionPara.msgReceiver = nullptr;
    sessionPara.localInterfaceName = nullptr;

    int sid = NSTACKX_DFileClientWithTargetDevV2(nullptr, abmStatus);
    ASSERT_LT(sid, 0);
    sid = NSTACKX_DFileClientWithTargetDevV2(&sessionPara, abmStatus);
    ASSERT_GT(sid, 0);
    NSTACKX_DFileClose(sid);

    const string key("aaaaaaaaaaaaaaaa");
    sessionPara.key = (const uint8_t *)key.c_str();
    sessionPara.keyLen = key.length();

    /* Encrypt */
    sid = NSTACKX_DFileClientWithTargetDevV2(&sessionPara, abmStatus);
    ASSERT_GT(sid, 0);
    NSTACKX_DFileClose(sid);
    sleep(1);
}

#ifdef DFILE_ENABLE_HIDUMP
static void DFileDumpFuncUT(void *softObj, const char *data, uint32_t len)
{
    (void)softObj;
    (void)data;
    (void)len;
    printf("--------------------------------\n");
}

static DFileDump_UT(const char *argv1, int expectVal)
{
    const char *argv[DFILE_DUMP_CMD_NUM_MAX] =  {nullptr};
    uint32_t argc = 0;
    argv[argc++] = "dfile";
    argv[argc++] = argv1;
    if (argv2) {
        argv[argc++] = argv2;
    }
    int ret = NSTACKX_DFileDump(argc, argv, nullptr, dump);
    ASSERT_EQ(ret, expectVal);
}

TEST(NSTACKX_DFILE, DFileDump)
{
    const char *argv[DFILE_DUMP_CMD_NUM_MAX] =  {nullptr};
    char sidBuf[DFILE_UT_BUF_LEN];
    DFileDumpFunc dump = DFileDumpFuncUT;

    int ret = NSTACKX_DFileDump(0, nullptr, nullptr, dump);
    ASSERT_LT(ret, 0);

    ret = NSTACKX_DFileDump(argc, argv, nullptr, dump);
    ASSERT_LT(ret, 0);

    uint32_t argc = 0;
    argv[argc++] = "-h";
    argv[argc++] = nullptr;
    ret = NSTACKX_DFileDump(argc, argv, nullptr, dump);
    ASSERT_LT(ret, 0);

    argc = 0;
    argv[argc++] = "dfile";
    argv[argc++] = "-h";
    argv[argc++] = nullptr;
    ret = NSTACKX_DFileDump(argc, argv, nullptr, dump);
    ASSERT_LT(ret, 0);

    DFileDump_UT("h", nullptr, -1);

    DFileDump_UT("-h", nullptr, 0);

    DFileDump_UT("-l", nullptr, 0);

    DFileDump_UT("-m", nullptr, -1);

    DFileDump_UT("-m", "a", 0);

    DFileDump_UT("-m", "1", 0);

    DFileDump_UT("-m", "0", 0);

    DFileDump_UT("-m", "0a", 0);

    DFileDump_UT("-m", "1a", 0);

    DFileDump_UT("-m", "11", 0);

    DFileDump_UT("-m", "00", 0);

    DFileDump_UT("-s", "-1", 0);

    DFileDump_UT("-s", "0", 0);

    InitDefaultAddr(0);
    int sid = NSTACKX_DFileServer(&g_defaultAddr, sizeof(g_defaultAddr), nullptr, 0, nullptr);
    ASSERT_GT(sid, 0);
    (void)sprintf_s(sidBuf, DFILE_UT_BUF_LEN - 1, "%d", sid);
    printf("dfile -s %d (server id), expect success\n", sid);
    DFileDump_UT("-s", (const char *)sidBuf, 0);
    NSTACKX_DFileClose(sid);

    InitDefaultAddr(0);
    sid = NSTACKX_DFileClientV2(&g_defaultAddr, sizeof(g_defaultAddr), nullptr, 0, nullptr, 0);
    ASSERT_GT(sid, 0);
    (void)sprintf_s(sidBuf, DFILE_UT_BUF_LEN - 1, "%d", sid);
    printf("dfile -s %d (client id), expect success\n", sid);
    DFileDump_UT("-s", (const char *)sidBuf, 0);
    NSTACKX_DFileClose(sid);
    sleep(1);

    DFileDump_UT("-s", "a", 0);

    DFileDump_UT("x", nullptr, -1);
}
#endif

TEST(NSTACKX_DFILE, DFileSetEventFunc)
{
    NSTACKX_DFileSetEventFunc(nullptr, nullptr);
}

static int32_t OpenFuncRegister(const char *fileName, int32_t flag, int32_t mode)
{
    return open(fileName, flag, mode);
}

TEST(NSTACKX_DFILE, DFileSetOpenFdCallback)
{
    int ret = NSTACKX_DFileSetOpenFdCallback(nullptr);
    ASSERT_EQ(ret, -1);

    ret = NSTACKX_DFileSetOpenFdCallback(OpenFuncRegister);
    ASSERT_EQ(ret, 0);
}

TEST(NSTACKX_DFILE, DFileSetCloseFdCallback)
{
    int ret;

    ret = NSTACKX_DFileSetCloseFdCallback(nullptr);
    ASSERT_EQ(ret, -1);

    ret = NSTACKX_DFileSetCloseFdCallback(close);
    ASSERT_EQ(ret, 0);
}

TEST(NSTACKX_DFILE, AckLossEvent)
{
    AckLossEvent(0);
    AckLossEvent(1);
}

TEST(NSTACKX_DFILE, WaitFileHeaderTimeoutEvent)
{
    WaitFileHeaderTimeoutEvent(DFILE_TRANS_NO_ERROR);
    WaitFileHeaderTimeoutEvent(DFILE_TRANS_SOCKET_ERROR);
}

TEST(NSTACKX_DFILE, ReceiverIdleTimeoutEvent)
{
    ReceiverIdleTimeoutEvent(0);
    ReceiverIdleTimeoutEvent(1);
}

static DFileSessionNode *GTestGetDFileSessionNodeById(uint16_t sessionId)
{
    List *pos = nullptr;
    DFileSessionNode *node = nullptr;
    uint8_t isFound = NSTACKX_FALSE;
    LIST_FOR_EACH(pos, &g_dFileSessionChain) {
        node = (DFileSessionNode *)pos;
        if (node->sessionId == sessionId) {
            isFound = NSTACKX_TRUE;
            break;
        }
    }
    return isFound ? node : nullptr;
}

pii gtest_parse_address(const char *s)
{
    struct in_addr ip;
    int port;
    std::string str(s);
    size_t pos = str.find(':');
    if (pos != std::string::npos) {
        std::string sp = str.substr(pos + 1);
        if (sp.length() == 0) {
            port = DEFAULT_DFILE_SERVER_PORT;
        } else {
            port = std::stoi(sp);
        }
        str.erase(pos);
        if (str.length() == 0) {
            s = "192.168.49.1";
            inet_pton(AF_INET, s, &ip);
        } else {
            inet_pton(AF_INET, str.c_str(), &ip);
        }
    } else {
        port = DEFAULT_DFILE_SERVER_PORT;
    }
    return std::make_pair(ntohl(ip.s_addr), port);
}

static int GTestGetSockAddr(const char *s, struct sockaddr_in *addr)
{
    if (s == nullptr || addr == nullptr) {
        return NSTACKX_EFAILED;
    }
    pii pair = gtest_parse_address(s);
    (void)memset_s(addr, sizeof(*addr), 0, sizeof(*addr));
    addr->sin_family = AF_INET;
    addr->sin_port = pair.second;
    addr->sin_addr.s_addr = pair.first;
    return NSTACKX_EOK;
}

TEST(NSTACKX_DFILE, DISABLED_NotifyTransAddRetryNodeZS)
{
    DFileSession *sessionServer;
    uint16_t sessionServerId, sessionClientId;
    struct sockaddr_in addr;
    char address[64] = "127.0.0.1:8097";
    int32_t ret = NSTACKX_EOK;
    uint8_t socketIndex = 0;
    FileDataFrameZS tmp;
    FileDataFrameZS *fileDataFrame = &tmp;

    ret = GTestGetSockAddr(address, &addr);
    ASSERT_EQ(ret, NSTACKX_EOK);
    sessionServerId = NSTACKX_DFileServer(&addr, sizeof(addr), nullptr, 0, MsgReceiver);
    sessionClientId = NSTACKX_DFileClient(&addr, sizeof(addr), nullptr, 0, MsgReceiver);
    sessionServer = GTestGetDFileSessionNodeById(sessionServerId)->session;
    fileDataFrame->header.type = NSTACKX_DFILE_FILE_DATA_FRAME;
    fileDataFrame->header.transId = 0;
    fileDataFrame->fileId = 0;
    fileDataFrame->linkSequence = 1;

    DFileTrans ttmp;
    DFileTrans *transtmp = &ttmp;
    transtmp->transId = 0;
    sessionServer->dFileTransChain.next = &transtmp->list;
    transtmp->list.next = &sessionServer->dFileTransChain;
    transtmp->receivedDataFrameCnt = 1;

    NotifyTransAddRetryNodeZS(sessionServer, (const DFileFrame *)fileDataFrame, socketIndex);
    sleep(1);
    ASSERT_EQ(transtmp->receivedDataFrameCnt, (uint64_t)0);

    sessionServer->dFileTransChain.next = &sessionServer->dFileTransChain;
    sessionServer->peerInfoChain.next = &sessionServer->peerInfoChain;
    NSTACKX_DFileClose(sessionServerId);
    NSTACKX_DFileClose(sessionClientId);
    sleep(1);
}

TEST(NSTACKX_DFILE, DFilePrintControlFrame)
{
    char opt[DFILE_UT_BUF_LEN] = {'1', '\0'};
    char message[DUMP_INFO_MAX];
    size_t size;
    char frame[DFILE_UT_BUF_LEN] = {0};
    DFileFrame *dFileFrame = (DFileFrame *)frame;

    // open hidump
    printf("call HidumpMessage, opt %s\n", opt);
    int ret = HidumpMessage(message, &size, opt);
    printf("call HidumpMessage, result: %s\n", message);
    ASSERT_EQ(ret, 0);

    dFileFrame->header.type = NSTACKX_DFILE_SETTING_FRAME;
    DFilePrintControlFrame((const DFileFrame *)frame, 1);

    dFileFrame->header.type = NSTACKX_DFILE_FILE_HEADER_FRAME;
    DFilePrintControlFrame((const DFileFrame *)frame, 1);

    dFileFrame->header.type = NSTACKX_DFILE_FILE_HEADER_CONFIRM_FRAME;
    DFilePrintControlFrame((const DFileFrame *)frame, 1);

    dFileFrame->header.type = NSTACKX_DFILE_FILE_DATA_ACK_FRAME;
    DFilePrintControlFrame((const DFileFrame *)frame, 1);

    dFileFrame->header.type = NSTACKX_DFILE_FILE_BACK_PRESSURE_FRAME;
    DFilePrintControlFrame((const DFileFrame *)frame, 1);

    dFileFrame->header.type = NSTACKX_DFILE_FILE_TRANSFER_DONE_FRAME;
    DFilePrintControlFrame((const DFileFrame *)frame, 1);
}

TEST(NSTACKX_DFILE, CheckDFileRealPath)
{
    OpenCloseFdSwtich(false);
    char *ret = DFileRealPath(nullptr, "test", nullptr);
    printf("DFileRealPath(test, nullptr) return %08lx\n", (unsigned long)ret);
    if (ret != nullptr) {
        free(ret);
    }

    OpenCloseFdSwtich(true);
    ret = DFileRealPath(nullptr, "test", nullptr);
    printf("DFileRealPath(test, nullptr) return %08lx\n", (unsigned long)ret);
    if (ret != nullptr) {
        free(ret);
    }
    OpenCloseFdSwtich(false);
}

struct TestNode {
    struct RbNode rb;
    uint32_t key;

    TestNode()
    {
        rb.parentColor = 0;
        rb.left = nullptr;
        rb.right = nullptr;

        key = 0;
    }
};

static void TestInsert(TestNode *node, RbRoot *root)
{
    RbNode **next = &root->node;
    RbNode *parent = nullptr;
    uint32_t key = node->key;
    TestNode *current = nullptr;

    while (*next) {
        parent = *next;
        current = container_of(parent, TestNode, rb);
        if (key < current->key) {
            next = &parent->left;
        } else {
            next = &parent->right;
        }
    }

    RbLinkNode(&node->rb, parent, next);
    RbInsertColor(&node->rb, root);
}

static inline void TestErase(TestNode *node, RbRoot *root)
{
    RbErase(&node->rb, root);
}

TEST(NSTACKX_DFILE, UtilRBTree)
{
    RbRoot root  nullptr};
    RbNode *node = nullptr;
    TestNode *nodes = nullptr;
    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_int_distribution<uint32_t> distrib(0, UINT32_MAX);
    int k = 0;
    uint32_t *keys = nullptr;

    nodes = new TestNode[RBTREE_NUM_NODES];
    ASSERT_TRUE(nodes);

    keys = new uint32_t[RBTREE_NUM_NODES];
    ASSERT_TRUE(keys);

    for (int i = 0; i < RBTREE_NUM_NODES; i++) {
        nodes[i].key = distrib(gen);
        TestInsert(&nodes[i], &root);
        ASSERT_TRUE(RB_IS_BLACK(root.node));
    }

    for (node = RbFirst(&root); node; node = RbNext(node)) {
        TestNode *tmp = container_of(node, TestNode, rb);
        keys[k++] = tmp->key;
    }

    ASSERT_EQ(k, RBTREE_NUM_NODES);
    ASSERT_TRUE(std::is_sorted(keys, keys + k));

    for (node = RbLast(&root); node; node = RbPrev(node)) {
        TestNode *tmp = container_of(node, TestNode, rb);
        keys[--k] -= tmp->key;
        ASSERT_EQ(keys[k], 0U);
    }

    ASSERT_EQ(k, 0);

    for (int i = RBTREE_NUM_NODES - 1; i > 0; i--) {
        TestErase(&nodes[i], &root);
        ASSERT_FALSE(RB_IS_RED(root.node));
    }

    ASSERT_EQ(root.node, &nodes[0].rb);

    TestErase(&nodes[0], &root);

    ASSERT_TRUE(root.node == nullptr);

    delete[] nodes;
    delete[] keys;
}

TEST_F(NSTACKX_DFILE_WITH_SETUP_AND_TEARDOWN, DFileSendFiles)
{
    const char *files[NSTACKX_DFILE_MAX_FILE_NUM] = { nullptr };
    int second = 10;
    DFileOpt opt;
    uint8_t tos = 0xBC;
    opt.optType = OPT_TYPE_SOCK_PRIO;
    opt.value = (uint64_t)(uintptr_t)&tos;
    opt.valLen = sizeof(tos);

    int ssid = NSTACKX_DFileServer(&g_defaultAddr, sizeof(g_defaultAddr), nullptr, 0, MsgReceiver);
    ASSERT_GT(ssid, 0);
    int ret = NSTACKX_DFileSetSessionOpt(ssid, &opt);
    EXPECT_EQ(ret, 0);

    ret = NSTACKX_DFileSetStoragePath(ssid, DFILE_DEFAULT_STORAGE_PATH);
    EXPECT_EQ(ret, 0);

    int csid = NSTACKX_DFileClient(&g_defaultAddr, sizeof(g_defaultAddr), nullptr, 0, MsgReceiver);
    EXPECT_GT(csid, 0);
    ret = NSTACKX_DFileSetSessionOpt(csid, &opt);
    EXPECT_EQ(ret, 0);

    /* para is nullptr, return vaule shuold be less than 0 */
    ret = NSTACKX_DFileSendFiles(csid, nullptr, 0, nullptr);
    EXPECT_LT(ret, 0);

    files[0] = DFILE_SEND_FILE_NAME;
    ret = NSTACKX_DFileSendFiles(csid, files, 1, nullptr);
    EXPECT_EQ(ret, 0);

    while (second) {
        if (g_recvSucc) {
            break;
        }
        sleep(1);
        tos = ~tos;
        ret = NSTACKX_DFileSetSessionOpt(csid, &opt);
        EXPECT_EQ(ret, 0);
        second--;
    }

    ret = NSTACKX_DFileGetSessionOpt(csid, &opt);
    EXPECT_EQ(ret, 0);
    ASSERT_GE(g_recvSucc, 1);

    ret = FileMd5Equal((char *)DFILE_SEND_FILE_NAME, (char *)DFILE_DEFAULT_STORAGE_PATH DFILE_SEND_FILE_NAME);
    ASSERT_EQ(ret, NSTACKX_TRUE);

    NSTACKX_DFileClose(csid);
    NSTACKX_DFileClose(ssid);

    sleep(1);
}

TEST_F(NSTACKX_DFILE_WITH_SETUP_AND_TEARDOWN, DFileSendFilesWithAlgNoRate)
{
    const char *files[NSTACKX_DFILE_MAX_FILE_NUM] = { nullptr };
    int second = 10;

    int ret = NSTACKX_DFileSetCapabilities(NSTACKX_CAPS_ALG_NORATE, 0);
    EXPECT_EQ(ret, 0);

    int ssid = NSTACKX_DFileServer(&g_defaultAddr, sizeof(g_defaultAddr), nullptr, 0, MsgReceiver);
    ASSERT_GT(ssid, 0);

    ret = NSTACKX_DFileSetStoragePath(ssid, DFILE_DEFAULT_STORAGE_PATH);
    EXPECT_EQ(ret, 0);

    int csid = NSTACKX_DFileClient(&g_defaultAddr, sizeof(g_defaultAddr), nullptr, 0, MsgReceiver);
    EXPECT_GT(csid, 0);

    files[0] = DFILE_SEND_FILE_NAME;
    ret = NSTACKX_DFileSendFiles(csid, files, 1, nullptr);
    EXPECT_EQ(ret, 0);

    while (second) {
        if (g_recvSucc) {
            break;
        }
        sleep(1);
        second--;
    }

    ASSERT_GE(g_recvSucc, 1);

    ret = FileMd5Equal((char *)DFILE_SEND_FILE_NAME, (char *)DFILE_DEFAULT_STORAGE_PATH DFILE_SEND_FILE_NAME);
    ASSERT_EQ(ret, NSTACKX_TRUE);

    NSTACKX_DFileClose(csid);
    NSTACKX_DFileClose(ssid);

    sleep(1);
}

TEST_F(NSTACKX_DFILE_WITH_SETUP_AND_TEARDOWN, MemLog)
{
    const char *files[NSTACKX_DFILE_MAX_FILE_NUM] = { nullptr };
    int second = 10;

    NSTACKX_DFileSetInternalCapabilities(NSTACKX_INTERNAL_CAPS_MEMLOG);

    int ssid = NSTACKX_DFileServer(&g_defaultAddr, sizeof(g_defaultAddr), nullptr, 0, MsgReceiver);
    ASSERT_GT(ssid, 0);

    int ret = NSTACKX_DFileSetStoragePath(ssid, DFILE_DEFAULT_STORAGE_PATH);
    EXPECT_EQ(ret, 0);

    int csid = NSTACKX_DFileClient(&g_defaultAddr, sizeof(g_defaultAddr), nullptr, 0, MsgReceiver);
    EXPECT_GT(csid, 0);

    files[0] = DFILE_SEND_FILE_NAME;
    ret = NSTACKX_DFileSendFiles(csid, files, 1, nullptr);
    EXPECT_EQ(ret, 0);

    while (second) {
        if (g_recvSucc) {
            break;
        }
        sleep(1);
        second--;
    }
    ASSERT_GE(g_recvSucc, 1);

    ret = FileMd5Equal((char *)DFILE_SEND_FILE_NAME, (char *)DFILE_DEFAULT_STORAGE_PATH DFILE_SEND_FILE_NAME);
    ASSERT_EQ(ret, NSTACKX_TRUE);

    NSTACKX_DFileClose(csid);
    NSTACKX_DFileClose(ssid);
    sleep(1);
    NSTACKX_DFileSetInternalCapabilities(0);
    ret = NSTACKX_DFileSetCapabilities(NSTACKX_CAPS_UDP_GSO, 0);
    EXPECT_EQ(ret, 0);
}

TEST_F(NSTACKX_DFILE_WITH_SETUP_AND_TEARDOWN, DFileSendFilesV2)
{
    uint32_t abmStatus = 1;
    const char *files[NSTACKX_DFILE_MAX_FILE_NUM] = { nullptr };
    int second = 10;

    int ssid = NSTACKX_DFileServerV2(&g_defaultAddr, sizeof(g_defaultAddr), nullptr, 0, MsgReceiver, abmStatus);
    ASSERT_GT(ssid, 0);

    int ret = NSTACKX_DFileSetStoragePath(ssid, DFILE_DEFAULT_STORAGE_PATH);
    EXPECT_EQ(ret, 0);

    int csid = NSTACKX_DFileClientV2(&g_defaultAddr, sizeof(g_defaultAddr), nullptr, 0, MsgReceiver, abmStatus);
    EXPECT_GT(csid, 0);

    /* para is nullptr, return vaule shuold be less than 0 */
    ret = NSTACKX_DFileSendFiles(csid, nullptr, 0, nullptr);
    EXPECT_LT(ret, 0);

    files[0] = DFILE_SEND_FILE_NAME;
    ret = NSTACKX_DFileSendFiles(csid, files, 1, nullptr);
    EXPECT_EQ(ret, 0);

    while (second) {
        if (g_recvSucc) {
            break;
        }
        sleep(1);
        second--;
    }
    ASSERT_GE(g_recvSucc, 1);

    ret = FileMd5Equal((char *)DFILE_SEND_FILE_NAME, (char *)DFILE_DEFAULT_STORAGE_PATH DFILE_SEND_FILE_NAME);
    ASSERT_EQ(ret, NSTACKX_TRUE);

    NSTACKX_DFileClose(csid);
    NSTACKX_DFileClose(ssid);
    sleep(1);
}

TEST_F(NSTACKX_DFILE_WITH_SETUP_AND_TEARDOWN, DFileSendFilesV3)
{
    int filenum = 2;
    const char *files[NSTACKX_DFILE_MAX_FILE_NUM] = { nullptr };
    uint8_t tos = 0xBC;
    DFileOpt opt;
    opt.optType = OPT_TYPE_SOCK_PRIO;
    opt.value = (uint64_t)(uintptr_t)&tos;
    opt.valLen = sizeof(tos);
    if (!UTIsExistingFile(DFILE_DEFAULT_SEND_PATH)) {
        ret = CreateFolder(DFILE_DEFAULT_SEND_PATH);
        ASSERT_GT(ret, 0);
    }
    int ret = NSTACKX_DFileConfigSet(DFILE_CONF_DIR_CALLBACK, &g_set, sizeof(DFileDirCallback));
    int ssid = NSTACKX_DFileServer(&g_defaultAddr, sizeof(g_defaultAddr), nullptr, 0, MsgReceiver);
    ASSERT_GT(ssid, 0);
    ret = NSTACKX_DFileSetSessionOpt(ssid, &opt);
    EXPECT_EQ(ret, 0);
 
    ret = NSTACKX_DFileSetStoragePath(ssid, DFILE_DEFAULT_STORAGE_PATH);
    EXPECT_EQ(ret, 0);
 
    int csid = NSTACKX_DFileClient(&g_defaultAddr, sizeof(g_defaultAddr), nullptr, 0, MsgReceiver);
    EXPECT_GT(csid, 0);
    ret = NSTACKX_DFileSetSessionOpt(csid, &opt);
    EXPECT_EQ(ret, 0);
 
    sleep(SLEEP_SECOND_LOW);
    /* para is nullptr, return vaule shuold be less than 0 */
    ret = NSTACKX_DFileSendFiles(csid, nullptr, 0, nullptr);
    EXPECT_LT(ret, 0);
 
    files[0] = DFILE_SEND_FILE_NAME;
    files[1] = DFILE_DEFAULT_SEND_PATH;
    ret = NSTACKX_DFileSendFiles(csid + DFILE_SESSION_ID_OFFEST, files, 1, nullptr);
    ret = NSTACKX_DFileSendFiles(csid, files, filenum, nullptr);
    EXPECT_EQ(ret, 0);
 
    for (int second = 1; second <= SLEEP_SECOND_HIGH; second++) {
        if (g_recvSucc) {
            break;
        }
        sleep(1);
        tos = ~tos;
        ret = NSTACKX_DFileSetSessionOpt(csid, &opt);
        EXPECT_EQ(ret, 0);
    }
 
    ret = NSTACKX_DFileGetSessionOpt(csid, &opt);
    EXPECT_EQ(ret, 0);
    ASSERT_GE(g_recvSucc, 1);
 
    ret = FileMd5Equal((char *)DFILE_SEND_FILE_NAME, (char *)DFILE_DEFAULT_STORAGE_PATH DFILE_SEND_FILE_NAME);
    ASSERT_EQ(ret, NSTACKX_TRUE);
 
    NSTACKX_DFileClose(csid);
    NSTACKX_DFileClose(ssid);
    RemoveDir(DFILE_DEFAULT_SEND_PATH);
    sleep(1);
}

TEST_F(NSTACKX_DFILE_WITH_SETUP_AND_TEARDOWN, DFileSendFilesWithRemotePath)
{
    const char *files[NSTACKX_DFILE_MAX_FILE_NUM] = { nullptr };
    const char *remotePath[NSTACKX_DFILE_MAX_FILE_NUM] = { nullptr };

    int sid = NSTACKX_DFileClient(&g_defaultAddr, sizeof(g_defaultAddr), nullptr, 0, nullptr);
    ASSERT_GT(sid, 0);

    /* para is nullptr, return vaule shuold be less than 0 */
    int ret = NSTACKX_DFileSendFilesWithRemotePath(sid, nullptr, nullptr, 0, nullptr);
    EXPECT_LT(ret, 0);

    files[0] = DFILE_SEND_FILE_NAME;
    remotePath[0] = DFILE_DEFAULT_STORAGE_PATH;
    ret = NSTACKX_DFileSendFilesWithRemotePath(sid, files, remotePath, 1, nullptr);
    EXPECT_EQ(ret, 0);

    NSTACKX_DFileClose(sid);
    sleep(1);
}

TEST_F(NSTACKX_DFILE_WITH_SETUP_AND_TEARDOWN, DFileSendFilesWithRemotePathAndType)
{
    NSTACKX_FilesInfo fileInfo;

    (void)memset_s(&fileInfo, sizeof(fileInfo), 0, sizeof(fileInfo));
    fileInfo.files[0] = DFILE_SEND_FILE_NAME;
    fileInfo.fileNum = 1;
    fileInfo.remotePath[0] = DFILE_DEFAULT_STORAGE_PATH;
    fileInfo.smallFlag = 1;
    fileInfo.pathType = 1;
    fileInfo.tarFlag = 0;
    fileInfo.unuse = 0;
    fileInfo.userData = nullptr;

    int sid = NSTACKX_DFileClient(&g_defaultAddr, sizeof(g_defaultAddr), nullptr, 0, nullptr);
    ASSERT_GT(sid, 0);

    int ret = NSTACKX_DFileSendFilesWithRemotePathAndType(sid, nullptr);
    EXPECT_LT(ret, 0);

    ret = NSTACKX_DFileSendFilesWithRemotePathAndType(sid, &fileInfo);
    EXPECT_EQ(ret, 0);

    fileInfo.tarFlag = 1;
    ret = NSTACKX_DFileSendFilesWithRemotePathAndType(sid, &fileInfo);
 
    fileInfo.pathType = NSTACKX_RESERVED_PATH_TYPE;
    fileInfo.remotePath[0] = nullptr;
    ret = NSTACKX_DFileSendFilesWithRemotePathAndType(sid, &fileInfo);
 
    fileInfo.tarFlag = 0;
    ret = NSTACKX_DFileSendFilesWithRemotePathAndType(sid, &fileInfo);
    ret = NSTACKX_DFileSendFilesWithRemotePathAndType(sid + DFILE_SESSION_ID_OFFEST, &fileInfo);
 
    fileInfo.pathType = 1;
    fileInfo.remotePath[0] = DFILE_DEFAULT_STORAGE_PATH;
    ret = NSTACKX_DFileSendFilesWithRemotePathAndType(sid + DFILE_SESSION_ID_OFFEST, &fileInfo);
    fileInfo.files[0] = nullptr;
    ret = NSTACKX_DFileSendFilesWithRemotePathAndType(sid, &fileInfo);
 
    fileInfo.files[0] = "\0";
    ret = NSTACKX_DFileSendFilesWithRemotePathAndType(sid, &fileInfo);
 
    ret = NSTACKX_DFileSetRenameHook(sid + DFILE_SESSION_ID_OFFEST, RenameFileCalbak);

    NSTACKX_DFileClose(sid);
    sleep(1);
}

TEST_F(NSTACKX_DFILE_WITH_SETUP_AND_TEARDOWN, DFileSetRenameHook)
{
    const char *files[NSTACKX_DFILE_MAX_FILE_NUM] = { nullptr };
    int second = 10;

    int ssid = NSTACKX_DFileServer(&g_defaultAddr, sizeof(g_defaultAddr), nullptr, 0, MsgReceiver);
    ASSERT_GT(ssid, 0);

    int ret = NSTACKX_DFileSetStoragePath(ssid, DFILE_DEFAULT_STORAGE_PATH);
    EXPECT_EQ(ret, 0);

    int csid = NSTACKX_DFileClient(&g_defaultAddr, sizeof(g_defaultAddr), nullptr, 0, MsgReceiver);
    EXPECT_GT(csid, 0);

    files[0] = DFILE_SEND_FILE_NAME;
    ret = NSTACKX_DFileSendFiles(csid, files, 1, nullptr);
    EXPECT_EQ(ret, 0);

    while (second) {
        if (g_recvSucc) {
            break;
        }
        sleep(1);
        second--;
    }
    ASSERT_GE(g_recvSucc, 1);

    char recvFile[] = DFILE_DEFAULT_STORAGE_PATH DFILE_SEND_FILE_NAME;
    ret = UTIsExistingFile(recvFile);
    EXPECT_EQ(ret, NSTACKX_TRUE);

    /* para is nullptr, return vaule shuold be less than 0 */
    ret = NSTACKX_DFileSetRenameHook(ssid, nullptr);
    EXPECT_LT(ret, 0);

    ret = NSTACKX_DFileSetRenameHook(ssid, RenameFileCalbak);
    EXPECT_GE(ret, 0);

    g_recvSucc = 0;
    second = SLEEP_SECOND_HIGH;
    ret = NSTACKX_DFileSendFiles(csid, files, 1, nullptr);
    EXPECT_EQ(ret, 0);

    while (second) {
        if (g_recvSucc) {
            break;
        }
        sleep(1);
        second--;
    }
    ASSERT_GE(g_recvSucc, 1);

    char recvFileRename[] = DFILE_DEFAULT_STORAGE_PATH DFILE_SEND_FILE_NAME DFILE_SEND_FILE_RENAME_BAK;
    char sendFile[] = DFILE_SEND_FILE_NAME;
    ret = FileMd5Equal(sendFile, recvFile);
    ASSERT_EQ(ret, NSTACKX_TRUE);
    ret = FileMd5Equal(recvFileRename, recvFile);
    ASSERT_EQ(ret, NSTACKX_TRUE);

    NSTACKX_DFileClose(ssid);
    NSTACKX_DFileClose(csid);
    sleep(1);
}

TEST_F(NSTACKX_DFILE_WITH_SETUP_AND_TEARDOWN, DFileSendRecvLinkSeq)
{
    const char *files[NSTACKX_DFILE_MAX_FILE_NUM] = { nullptr };
    int second = 10;

    int cap = NSTACKX_DFileGetCapabilities();
    EXPECT_GT(cap, 0);

    int ret = NSTACKX_DFileSetCapabilities(NSTACKX_CAPS_LINK_SEQUENCE | NSTACKX_CAPS_UDP_GSO, 0);
    EXPECT_EQ(ret, 0);

    int ssid = NSTACKX_DFileServer(&g_defaultAddr, sizeof(g_defaultAddr), nullptr, 0, MsgReceiver);
    ASSERT_GT(ssid, 0);

    ret = NSTACKX_DFileSetStoragePath(ssid, DFILE_DEFAULT_STORAGE_PATH);
    EXPECT_EQ(ret, 0);

    int csid = NSTACKX_DFileClient(&g_defaultAddr, sizeof(g_defaultAddr), nullptr, 0, MsgReceiver);
    EXPECT_GT(csid, 0);

    files[0] = DFILE_SEND_FILE_NAME;
    ret = NSTACKX_DFileSendFiles(csid, files, 1, nullptr);
    EXPECT_EQ(ret, 0);

    while (second) {
        if (g_recvSucc) {
            break;
        }
        sleep(1);
        second--;
    }
    ASSERT_GE(g_recvSucc, 1);

    ret = FileMd5Equal((char *)DFILE_SEND_FILE_NAME, (char *)DFILE_DEFAULT_STORAGE_PATH DFILE_SEND_FILE_NAME);
    ASSERT_EQ(ret, NSTACKX_TRUE);

    ret = NSTACKX_DFileSetCapabilities(NSTACKX_CAPS_UDP_GSO, 0);
    EXPECT_EQ(ret, 0);

    NSTACKX_DFileClose(ssid);
    NSTACKX_DFileClose(csid);
    sleep(1);
}

TEST(NSTACKX_DFILE, DFileSetStoragePathList)
{
    InitDefaultAddr(0);
    int sid = NSTACKX_DFileServer(&g_defaultAddr, sizeof(g_defaultAddr), nullptr, 0, nullptr);
    ASSERT_GT(sid, 0);

    int ret = NSTACKX_DFileSetStoragePathList(sid, nullptr, nullptr, 0);
    EXPECT_LT(ret, 0);

    char path[DFILE_DEFAULT_PATH_LEN] = DFILE_DEFAULT_STORAGE_PATH;
    char *spath[1] = {nullptr};
    spath[0] = path;
    uint16_t pathType = 1;
#ifdef BUILD_FOR_UNIX
    if (!UTIsExistingFile(DFILE_DEFAULT_STORAGE_PATH)) {
        ret = CreateFolder(DFILE_DEFAULT_STORAGE_PATH);
        ASSERT_GT(ret, 0);
    }
    ret = NSTACKX_DFileSetStoragePathList(sid, (const char**)spath, &pathType, 1);
    EXPECT_EQ(ret, 0);
    RemoveDir(DFILE_DEFAULT_STORAGE_PATH);
#else
    ret = NSTACKX_DFileSetStoragePathList(sid, (const char**)spath, &pathType, 1);
    EXPECT_EQ(ret, 0);
#endif

    NSTACKX_DFileClose(sid);
    sleep(1);
}

TEST_F(NSTACKX_DFILE_MP, NSTACKX_DFileMP)
{
    const string key("OW~zx9+rfTt'8yvn");
    int keyLen = 16;
    const char *files[NSTACKX_DFILE_MAX_FILE_NUM] = { nullptr };
    int second = 60;

    int32_t sid = NSTACKX_DFileServerMp(nullptr, 0, nullptr, 0, nullptr);
    ASSERT_EQ(sid, NSTACKX_EFAILED);

    sid = NSTACKX_DFileServerMp(g_mp_serverPara, DFILE_MP_PARA_NUM, (uint8_t *)key.c_str(), keyLen, MsgReceiver);
    ASSERT_GT(sid, 0);

    int32_t ret = NSTACKX_DFileSetStoragePath(sid, DFILE_DEFAULT_STORAGE_PATH);
    ASSERT_EQ(ret, 0);

    int32_t cid = NSTACKX_DFileClientMp(nullptr, 0, nullptr, 0, nullptr);
    ASSERT_EQ(cid, NSTACKX_EFAILED);

    cid = NSTACKX_DFileClientMp(g_mp_clinetPara, DFILE_MP_PARA_NUM, (uint8_t *)key.c_str(), keyLen, MsgReceiver);
    ASSERT_GT(cid, 0);

    files[0] = DFILE_SEND_FILE_NAME_100M;
    ret = NSTACKX_DFileSendFiles(cid, files, 1, nullptr);
    ASSERT_EQ(ret, NSTACKX_EOK);

    /* Expect to receive file within 60 seconds */
    while (second) {
        if (g_recvSucc) {
            break;
        }
        sleep(1);
        second--;
    }
    ASSERT_GE(g_recvSucc, 1);

    ret = FileMd5Equal((char *)DFILE_SEND_FILE_NAME_100M,
        (char *)DFILE_DEFAULT_STORAGE_PATH DFILE_SEND_FILE_NAME_100M);
    ASSERT_EQ(ret, NSTACKX_TRUE);

    NSTACKX_DFileClose(sid);
    NSTACKX_DFileClose(cid);
    sleep(1);
}

TEST_F(NSTACKX_DFILE_MP, NSTACKX_DFileRegisterLog)
{
    int ret;

    ret = NSTACKX_DFileRegisterLog(nullptr);
    EXPECT_EQ(ret, NSTACKX_EFAILED);

    ret = NSTACKX_DFileRegisterLog(NewLogImpl);
    EXPECT_EQ(ret, NSTACKX_EOK);
#ifdef ENABLE_USER_LOG
    ret = NSTACKX_DFileRegisterLogCallback(nullptr);
    EXPECT_EQ(ret, NSTACKX_EFAILED);

    ret = NSTACKX_DFileRegisterLogCallback(Printflog);
    EXPECT_EQ(ret, NSTACKX_EOK);

    NSTACKX_DFileRegisterDefaultLog();
#endif
}

TEST_F(NSTACKX_DFILE_MP, NSTACKX_DFileGetCapabilities)
{
    int ret;

    ret = NSTACKX_DFileGetCapabilities();
    EXPECT_GT(ret, 0);
}

TEST_F(NSTACKX_DFILE_MP, NSTACKX_DFileSetCapabilities)
{
    int ret;
    int cap;

    cap = NSTACKX_DFileGetCapabilities();
    EXPECT_GT(cap, 0);

    ret = NSTACKX_DFileSetCapabilities(0, 0);
    EXPECT_EQ(ret, 0);

    /* set itself, must be success */
    ret = NSTACKX_DFileSetCapabilities(cap, 0);
    EXPECT_EQ(ret, 0);

    /* link sequence and tcp is not coexist */
    if (cap & NSTACKX_CAPS_LINK_SEQUENCE) {
        ret = NSTACKX_DFileSetCapabilities(cap, SET_CAPABILITIES_VALUE_FOUR);
        EXPECT_EQ(ret, 1);
    }

    if (cap & NSTACKX_CAPS_LINK_SEQUENCE) {
        ret = NSTACKX_DFileSetCapabilities(cap, 1);
        EXPECT_EQ(ret, 0);
    }
}

TEST_F(NSTACKX_DFILE_MP, MpLinkSeq)
{
    const char *files[NSTACKX_DFILE_MAX_FILE_NUM] = { nullptr };
    int second = 60;

    NSTACKX_DFileSetCapabilities(NSTACKX_CAPS_UDP_GSO | NSTACKX_CAPS_LINK_SEQUENCE | NSTACKX_CAPS_WLAN_CATEGORY,
        SET_CAPABILITIES_VALUE_FOUR);
    int32_t sid = NSTACKX_DFileServerMp(g_mp_serverPara, DFILE_MP_PARA_NUM, nullptr, 0, MsgReceiver);
    ASSERT_GT(sid, 0);

    int32_t ret = NSTACKX_DFileSetStoragePath(sid, DFILE_DEFAULT_STORAGE_PATH);
    ASSERT_EQ(ret, 0);

    int32_t cid = NSTACKX_DFileClientMp(g_mp_clinetPara, DFILE_MP_PARA_NUM, nullptr, 0, MsgReceiver);
    ASSERT_GT(cid, 0);

    files[0] = DFILE_SEND_FILE_NAME_100M;
    ret = NSTACKX_DFileSendFiles(cid, files, 1, nullptr);
    ASSERT_EQ(ret, NSTACKX_EOK);

    while (second) {
        if (g_recvSucc) {
            break;
        }
        sleep(1);
        second--;
    }
    ASSERT_GE(g_recvSucc, 1);

    ret = FileMd5Equal((char *)DFILE_SEND_FILE_NAME_100M, (char *)DFILE_DEFAULT_STORAGE_PATH DFILE_SEND_FILE_NAME_100M);
    ASSERT_EQ(ret, NSTACKX_TRUE);

    NSTACKX_DFileClose(sid);
    NSTACKX_DFileClose(cid);
    sleep(1);
}

TEST_F(NSTACKX_DFILE_MP, DISABLED_MpLinkSeqEncrypted)
{
    const string key("OW~zx9+rfTt'8yvn");
    const char *files[NSTACKX_DFILE_MAX_FILE_NUM] = { nullptr };
    int second = 60;

    NSTACKX_DFileSetCapabilities(NSTACKX_CAPS_UDP_GSO | NSTACKX_CAPS_LINK_SEQUENCE | NSTACKX_CAPS_WLAN_CATEGORY,
        SET_CAPABILITIES_VALUE_FOUR);
    int32_t sid = NSTACKX_DFileServerMp(g_mp_serverPara, DFILE_MP_PARA_NUM,
                                        (const uint8_t *)key.c_str(), key.length(), MsgReceiver);
    ASSERT_GT(sid, 0);

    int32_t ret = NSTACKX_DFileSetStoragePath(sid, DFILE_DEFAULT_STORAGE_PATH);
    ASSERT_EQ(ret, 0);

    int32_t cid = NSTACKX_DFileClientMp(g_mp_clinetPara, DFILE_MP_PARA_NUM,
                                        (const uint8_t *)key.c_str(), key.length(), MsgReceiver);
    ASSERT_GT(cid, 0);

    files[0] = DFILE_SEND_FILE_NAME_100M;
    ret = NSTACKX_DFileSendFiles(cid, files, 1, nullptr);
    ASSERT_EQ(ret, NSTACKX_EOK);

    /* Expect to receive file within 60 seconds */
    while (second) {
        if (g_recvSucc) {
            break;
        }
        sleep(1);
        second--;
    }
    ASSERT_GE(g_recvSucc, 1);

    ret = FileMd5Equal((char *)DFILE_SEND_FILE_NAME_100M, (char *)DFILE_DEFAULT_STORAGE_PATH DFILE_SEND_FILE_NAME_100M);
    ASSERT_EQ(ret, NSTACKX_TRUE);

    NSTACKX_DFileClose(sid);
    NSTACKX_DFileClose(cid);
    sleep(1);
}

TEST_F(BREAKPOINT_RESUME_SETUP_AND_TEARDOWN, DISABLED_SP_BreakPoint)
{
    const char *files[NSTACKX_DFILE_MAX_FILE_NUM] = { nullptr };
    char sendFile[g_sendFileNums][DFILE_DEFAULT_PATH_LEN];
    char recvFile[g_sendFileNums][DFILE_DEFAULT_PATH_LEN];

    int ret = NSTACKX_DFileSetCapabilities(NSTACKX_CAPS_RESUMABLE_TRANS, 0);
    EXPECT_EQ(ret, 0);

    int ssid = NSTACKX_DFileServer(&g_defaultAddr, sizeof(g_defaultAddr), nullptr, 0, MsgReceiver);
    ASSERT_GT(ssid, 0);

    ret = NSTACKX_DFileSetStoragePath(ssid, DFILE_DEFAULT_STORAGE_PATH);
    EXPECT_EQ(ret, 0);

    int csid = NSTACKX_DFileClient(&g_defaultAddr, sizeof(g_defaultAddr), nullptr, 0, MsgReceiver);
    EXPECT_GT(csid, 0);

    for (int i = 0; i < g_sendFileNums; i++) {
        (void)memset_s(sendFile[i], sizeof(sendFile[i]), 0, sizeof(sendFile[i]));
        (void)sprintf_s(sendFile[i], sizeof(sendFile[i]), "%s-%d", DFILE_SEND_FILE_NAME_100M, i);
        files[i] = sendFile[i];
    }
    ret = NSTACKX_DFileSendFiles(csid, files, g_sendFileNums, nullptr);
    EXPECT_EQ(ret, 0);

    sleep(rand() % SLEEP_SECOND_HIGH);
    if (g_recvSucc != g_sendFileNums) {
        InitDefaultAddr(g_default_port + 1);
        g_sid = NSTACKX_DFileServer(&g_defaultAddr, sizeof(g_defaultAddr), nullptr, 0, MsgReceiver);
        ASSERT_GT(g_sid, 0);

        ret = NSTACKX_DFileSetStoragePath(g_sid, DFILE_DEFAULT_STORAGE_PATH);
        EXPECT_EQ(ret, 0);

        g_cid = NSTACKX_DFileClient(&g_defaultAddr, sizeof(g_defaultAddr), nullptr, 0, MsgReceiver);
        EXPECT_GT(g_cid, 0);

        // close server to trigger breakPoint resume
        NSTACKX_DFileClose(ssid);
    }

    int second = 120;
    while (second) {
        if (g_recvSucc && g_recvSucc >= g_restFileNums) {
            break;
        }
        sleep(1);
        second--;
    }
    ASSERT_GE(g_recvSucc, g_restFileNums);

    for (int i = 0; i < g_sendFileNums; i++) {
        (void)sprintf_s(recvFile[i], sizeof(recvFile[i]), "%s-%d",
            DFILE_DEFAULT_STORAGE_PATH DFILE_SEND_FILE_NAME_100M, i);
        ret = FileMd5Equal(sendFile[i], recvFile[i]);
        ASSERT_EQ(ret, NSTACKX_TRUE);
    }

    NSTACKX_DFileClose(g_sid);
    NSTACKX_DFileClose(g_cid);
    NSTACKX_DFileClose(csid);
    sleep(1);
}

TEST_F(BREAKPOINT_RESUME_SETUP_AND_TEARDOWN, DISABLED_TCP_BreakPoint)
{
    const char *files[NSTACKX_DFILE_MAX_FILE_NUM] = { nullptr };
    char sendFile[g_sendFileNums][DFILE_DEFAULT_PATH_LEN];
    char recvFile[g_sendFileNums][DFILE_DEFAULT_PATH_LEN];

    (void)signal(SIGPIPE, SIG_IGN);
    // set tcp caps
    NSTACKX_DFileSetCapabilities(NSTACKX_CAPS_WLAN_CATEGORY | NSTACKX_CAPS_RESUMABLE_TRANS, NSTACKX_WLAN_CAT_TCP);
    int ssid = NSTACKX_DFileServer(&g_defaultAddr, sizeof(g_defaultAddr), nullptr, 0, MsgReceiver);
    ASSERT_GT(ssid, 0);

    int ret = NSTACKX_DFileSetStoragePath(ssid, DFILE_DEFAULT_STORAGE_PATH);
    EXPECT_EQ(ret, 0);

    int csid = NSTACKX_DFileClient(&g_defaultAddr, sizeof(g_defaultAddr), nullptr, 0, MsgReceiver);
    EXPECT_GT(csid, 0);

    for (int i = 0; i < g_sendFileNums; i++) {
        (void)memset_s(sendFile[i], sizeof(sendFile[i]), 0, sizeof(sendFile[i]));
        (void)sprintf_s(sendFile[i], sizeof(sendFile[i]), "%s-%d", DFILE_SEND_FILE_NAME_100M, i);
        files[i] = sendFile[i];
    }
    ret = NSTACKX_DFileSendFiles(csid, files, g_sendFileNums, nullptr);
    EXPECT_EQ(ret, 0);

    sleep(1);
    if (g_recvSucc != g_sendFileNums) {
        InitDefaultAddr(g_default_port + 1);
        NSTACKX_DFileSetCapabilities(NSTACKX_CAPS_WLAN_CATEGORY | NSTACKX_CAPS_RESUMABLE_TRANS, NSTACKX_WLAN_CAT_TCP);
        g_sid = NSTACKX_DFileServer(&g_defaultAddr, sizeof(g_defaultAddr), nullptr, 0, MsgReceiver);
        ASSERT_GT(g_sid, 0);

        ret = NSTACKX_DFileSetStoragePath(g_sid, DFILE_DEFAULT_STORAGE_PATH);
        EXPECT_EQ(ret, 0);

        g_cid = NSTACKX_DFileClient(&g_defaultAddr, sizeof(g_defaultAddr), nullptr, 0, MsgReceiver);
        EXPECT_GT(g_cid, 0);

        // close server to trigger breakPoint resume
        NSTACKX_DFileClose(ssid);
    }

    int second = 120;
    while (second--) {
        if (g_recvSucc && g_recvSucc >= g_restFileNums) {
            break;
        }
        sleep(1);
    }
    ASSERT_GE(g_recvSucc, g_restFileNums);

    for (int i = 0; i < g_sendFileNums; i++) {
        (void)sprintf_s(recvFile[i], sizeof(recvFile[i]), "%s-%d",
            DFILE_DEFAULT_STORAGE_PATH DFILE_SEND_FILE_NAME_100M, i);
        ret = FileMd5Equal(sendFile[i], recvFile[i]);
        ASSERT_EQ(ret, NSTACKX_TRUE);
    }

    NSTACKX_DFileClose(g_sid);
    NSTACKX_DFileClose(g_cid);
    NSTACKX_DFileClose(csid);
    sleep(1);
}

TEST_F(BREAKPOINT_RESUME_SETUP_AND_TEARDOWN, DISABLED_TCP_ZEROCOPY)
{
    const char *files[NSTACKX_DFILE_MAX_FILE_NUM] = { nullptr };
    char sendFile[g_sendFileNums][DFILE_DEFAULT_PATH_LEN];
    char recvFile[g_sendFileNums][DFILE_DEFAULT_PATH_LEN];

    // set tcp caps
    NSTACKX_DFileSetCapabilities(NSTACKX_CAPS_WLAN_CATEGORY | NSTACKX_CAPS_ZEROCOPY | NSTACKX_CAPS_NO_RTT,
        NSTACKX_WLAN_CAT_TCP);
    int ssid = NSTACKX_DFileServer(&g_defaultAddr, sizeof(g_defaultAddr), nullptr, 0, MsgReceiver);
    ASSERT_GT(ssid, 0);

    int ret = NSTACKX_DFileSetStoragePath(ssid, DFILE_DEFAULT_STORAGE_PATH);
    EXPECT_EQ(ret, 0);

    int csid = NSTACKX_DFileClient(&g_defaultAddr, sizeof(g_defaultAddr), nullptr, 0, MsgReceiver);
    EXPECT_GT(csid, 0);

    for (int i = 0; i < g_sendFileNums; i++) {
        (void)memset_s(sendFile[i], sizeof(sendFile[i]), 0, sizeof(sendFile[i]));
        (void)sprintf_s(sendFile[i], sizeof(sendFile[i]), "%s-%d", DFILE_SEND_FILE_NAME_100M, i);
        files[i] = sendFile[i];
    }
    ret = NSTACKX_DFileSendFiles(csid, files, g_sendFileNums, nullptr);
    EXPECT_EQ(ret, 0);

    int second = 120;
    while (second) {
        if (g_recvSucc && g_recvSucc >= g_restFileNums) {
            break;
        }
        sleep(1);
        second--;
    }
    ASSERT_GE(g_recvSucc, g_restFileNums);

    for (int i = 0; i < g_sendFileNums; i++) {
        (void)sprintf_s(recvFile[i], sizeof(recvFile[i]), "%s-%d",
            DFILE_DEFAULT_STORAGE_PATH DFILE_SEND_FILE_NAME_100M, i);
        ret = FileMd5Equal(sendFile[i], recvFile[i]);
        ASSERT_EQ(ret, NSTACKX_TRUE);
    }

    NSTACKX_DFileClose(csid);
    NSTACKX_DFileClose(ssid);
    sleep(1);
}

TEST_F(BREAKPOINT_RESUME_SETUP_AND_TEARDOWN, DISABLED_NSTACKX_DFileMPTcp)
{
    const string key("OW~zx9+rfTt'8yvn");
    int32_t keyLen = 16;
    char sendFile[NSTACKX_MAX_FILE_NAME_LEN];
    char recvFile[NSTACKX_MAX_FILE_NAME_LEN];
    const char *p[1];

    NSTACKX_DFileSetCapabilities(NSTACKX_CAPS_WLAN_CATEGORY | NSTACKX_CAPS_NO_RTT, NSTACKX_WLAN_CAT_TCP);
    int32_t sid = NSTACKX_DFileServerMp(g_mp_serverPara, DFILE_MP_PARA_NUM,
                                        (uint8_t *)key.c_str(), keyLen, MsgReceiver);
    ASSERT_GT(sid, 0);

    int32_t ret = NSTACKX_DFileSetStoragePath(sid, DFILE_DEFAULT_STORAGE_PATH);
    ASSERT_EQ(ret, 0);

    int32_t cid = NSTACKX_DFileClientMp(g_mp_clinetPara, DFILE_MP_PARA_NUM,
                                        (uint8_t *)key.c_str(), keyLen, MsgReceiver);
    ASSERT_GT(cid, 0);

    ret = sprintf_s(sendFile, sizeof(sendFile), "%s-0", DFILE_SEND_FILE_NAME_100M);
    ASSERT_GE(ret, 0);
    p[0] = sendFile;
    ret = NSTACKX_DFileSendFiles(cid, p, 1, nullptr);
    ASSERT_EQ(ret, NSTACKX_EOK);

    int second = 120;
    while (second) {
        if (g_recvSucc) {
            break;
        }
        sleep(1);
        second--;
    }

    ASSERT_GE(g_recvSucc, 1);
    ret = sprintf_s(recvFile, sizeof(recvFile), "%s-0",
        DFILE_DEFAULT_STORAGE_PATH DFILE_SEND_FILE_NAME_100M);
    ASSERT_GE(ret, 0);

    ret = FileMd5Equal(sendFile, recvFile);
    ASSERT_EQ(ret, NSTACKX_TRUE);

    NSTACKX_DFileClose(sid);
    NSTACKX_DFileClose(cid);
    sleep(1);
}

TEST_F(BREAKPOINT_RESUME_SETUP_AND_TEARDOWN, DISABLED_NSTACKX_DFileMPTcpEscapeTimeout)
{
    int sendNums = 5;
    int second = 120;
    char sendFile[sendNums][NSTACKX_MAX_FILE_NAME_LEN];
    char recvFile[sendNums][NSTACKX_MAX_FILE_NAME_LEN];
    const char *p[sendNums];

    NSTACKX_DFileSetCapabilities(NSTACKX_CAPS_WLAN_CATEGORY | NSTACKX_CAPS_NO_RTT, NSTACKX_WLAN_CAT_TCP);
    int32_t sid = NSTACKX_DFileServerMp(g_mp_serverPara, DFILE_MP_PARA_NUM, nullptr, 0, MsgReceiver);
    ASSERT_GT(sid, 0);

    int32_t ret = NSTACKX_DFileSetStoragePath(sid, DFILE_DEFAULT_STORAGE_PATH);
    ASSERT_EQ(ret, 0);

    int32_t cid = NSTACKX_DFileClientMp(g_mp_clinetPara, DFILE_MP_PARA_NUM, nullptr, 0, MsgReceiver);
    ASSERT_GT(cid, 0);

    for (int i = 0; i < sendNums; i++) {
        ret = sprintf_s(sendFile[i], NSTACKX_MAX_FILE_NAME_LEN,
            "%s-%d", DFILE_SEND_FILE_NAME_100M, i);
        ASSERT_GE(ret, 0);
        p[i] = sendFile[i];
    }
    ret = NSTACKX_DFileSendFiles(cid, p, sendNums, nullptr);
    ASSERT_EQ(ret, NSTACKX_EOK);

    sleep(1);
    const char *cmd[2] = {
        "iptables -A INPUT -p tcp --dport 8097 -j REJECT",
        "iptables -A OUTPUT -p tcp --sport 8097 -j REJECT",
    };

    for (int i = 0; i < CMD_COUNT; i++) {
        ret = system(cmd[i]);
        ASSERT_GE(ret, NSTACKX_EOK);
    }

    while (second) {
        if (g_recvSucc) {
            break;
        }
        sleep(1);
        second--;
    }
    ASSERT_GE(g_recvSucc, sendNums);
    for (int i = 0; i < sendNums; i++) {
        ret = sprintf_s(recvFile[i], NSTACKX_MAX_FILE_NAME_LEN, "%s-%d",
            DFILE_DEFAULT_STORAGE_PATH DFILE_SEND_FILE_NAME_100M, i);
        ASSERT_GE(ret, 0);
        ret = FileMd5Equal(sendFile[i], recvFile[i]);
        ASSERT_EQ(ret, NSTACKX_TRUE);
    }

    NSTACKX_DFileClose(sid);
    NSTACKX_DFileClose(cid);
    sleep(1);
}

TEST_F(BREAKPOINT_RESUME_SETUP_AND_TEARDOWN, DISABLED_NSTACKX_DFileMPUdpEscapeTimeout)
{
    int sendNums = 5;
    int second = 120;
    char sendFile[sendNums][NSTACKX_MAX_FILE_NAME_LEN];
    char recvFile[sendNums][NSTACKX_MAX_FILE_NAME_LEN];
    const char *p[sendNums];

    NSTACKX_DFileSetCapabilities(0, 0);
    int32_t sid = NSTACKX_DFileServerMp(g_mp_serverPara, DFILE_MP_PARA_NUM, nullptr, 0, MsgReceiver);
    ASSERT_GT(sid, 0);

    int32_t ret = NSTACKX_DFileSetStoragePath(sid, DFILE_DEFAULT_STORAGE_PATH);
    ASSERT_EQ(ret, 0);

    int32_t cid = NSTACKX_DFileClientMp(g_mp_clinetPara, DFILE_MP_PARA_NUM, nullptr, 0, MsgReceiver);
    ASSERT_GT(cid, 0);

    for (int i = 0; i < sendNums; i++) {
        ret = sprintf_s(sendFile[i], NSTACKX_MAX_FILE_NAME_LEN,
            "%s-%d", DFILE_SEND_FILE_NAME_100M, i);
        ASSERT_GE(ret, 0);
        p[i] = sendFile[i];
    }
    ret = NSTACKX_DFileSendFiles(cid, p, sendNums, nullptr);
    ASSERT_EQ(ret, NSTACKX_EOK);

    sleep(1);
    const char *cmd[2] = {
        "iptables -A INPUT -p udp --dport 8097 -j REJECT",
        "iptables -A OUTPUT -p udp --sport 8097 -j REJECT",
    };

    for (int i = 0; i < CMD_COUNT; i++) {
        ret = system(cmd[i]);
        ASSERT_GE(ret, NSTACKX_EOK);
    }

    while (second) {
        if (g_recvSucc) {
            break;
        }
        sleep(1);
        second--;
    }

    ASSERT_GE(g_recvSucc, sendNums);
    for (int i = 0; i < sendNums; i++) {
        ret = sprintf_s(recvFile[i], NSTACKX_MAX_FILE_NAME_LEN, "%s-%d",
            DFILE_DEFAULT_STORAGE_PATH DFILE_SEND_FILE_NAME_100M, i);
        ASSERT_GE(ret, 0);
        ret = FileMd5Equal(sendFile[i], recvFile[i]);
        ASSERT_EQ(ret, NSTACKX_TRUE);
    }

    NSTACKX_DFileClose(sid);
    NSTACKX_DFileClose(cid);
    sleep(1);
}

TEST_F(BREAKPOINT_RESUME_SETUP_AND_TEARDOWN, DISABLED_NSTACKX_DFileMPLinkSeqEscapeTimeout)
{
    int sendNums = 5；
    int second = 120;
    char sendFile[sendNums][NSTACKX_MAX_FILE_NAME_LEN];
    char recvFile[sendNums][NSTACKX_MAX_FILE_NAME_LEN];
    const char *p[sendNums];

    NSTACKX_DFileSetCapabilities(NSTACKX_CAPS_LINK_SEQUENCE | NSTACKX_CAPS_WLAN_CATEGORY,
        SET_CAPABILITIES_VALUE_FOUR);
    int32_t sid = NSTACKX_DFileServerMp(g_mp_serverPara, DFILE_MP_PARA_NUM, nullptr, 0, MsgReceiver);
    ASSERT_GT(sid, 0);

    int32_t ret = NSTACKX_DFileSetStoragePath(sid, DFILE_DEFAULT_STORAGE_PATH);
    ASSERT_EQ(ret, 0);

    int32_t cid = NSTACKX_DFileClientMp(g_mp_clinetPara, DFILE_MP_PARA_NUM, nullptr, 0, MsgReceiver);
    ASSERT_GT(cid, 0);

    for (int i = 0; i < sendNums; i++) {
        ret = sprintf_s(sendFile[i], NSTACKX_MAX_FILE_NAME_LEN,
            "%s-%d", DFILE_SEND_FILE_NAME_100M, i);
        ASSERT_GE(ret, 0);
        p[i] = sendFile[i];
    }
    ret = NSTACKX_DFileSendFiles(cid, p, sendNums, nullptr);
    ASSERT_EQ(ret, NSTACKX_EOK);

    sleep(1);
    const char *cmd[2] = {
        "iptables -A INPUT -p udp --dport 8097 -j REJECT",
        "iptables -A OUTPUT -p udp --sport 8097 -j REJECT",
    };

    for (int i = 0; i < CMD_COUNT; i++) {
        ret = system(cmd[i]);
        ASSERT_GE(ret, NSTACKX_EOK);
    }

    while (second) {
        if (g_recvSucc) {
            break;
        }
        sleep(1);
        second--;
    }

    ASSERT_GE(g_recvSucc, sendNums);
    for (int i = 0; i < sendNums; i++) {
        ret = sprintf_s(recvFile[i], NSTACKX_MAX_FILE_NAME_LEN, "%s-%d",
            DFILE_DEFAULT_STORAGE_PATH DFILE_SEND_FILE_NAME_100M, i);
        ASSERT_GE(ret, 0);
        ret = FileMd5Equal(sendFile[i], recvFile[i]);
        ASSERT_EQ(ret, NSTACKX_TRUE);
    }

    NSTACKX_DFileClose(sid);
    NSTACKX_DFileClose(cid);
    sleep(1);
}

TEST_F(MpEscape_SETUP_AND_TEARDOWN, DISABLED_NstackxDFileMPTcpEscapeDisconnect)
{
    int sendNums = 5;
    int second = 120;
    char sendFile[sendNums][NSTACKX_MAX_FILE_NAME_LEN];
    char recvFile[sendNums][NSTACKX_MAX_FILE_NAME_LEN];
    const char *p[sendNums];

    NSTACKX_DFileSetCapabilities(NSTACKX_CAPS_WLAN_CATEGORY, NSTACKX_WLAN_CAT_TCP);
    int32_t sid = NSTACKX_DFileServerMp(g_mp_serverPara, DFILE_MP_PARA_NUM, nullptr, 0, MsgReceiver);
    ASSERT_GT(sid, 0);

    int32_t ret = NSTACKX_DFileSetStoragePath(sid, DFILE_DEFAULT_STORAGE_PATH);
    ASSERT_EQ(ret, 0);

    int32_t cid = NSTACKX_DFileClientMp(g_mp_clinetPara, DFILE_MP_PARA_NUM, nullptr, 0, MsgReceiver);
    ASSERT_GT(cid, 0);

    for (int i = 0; i < sendNums; i++) {
        ret = sprintf_s(sendFile[i], NSTACKX_MAX_FILE_NAME_LEN,
            "%s-%d", DFILE_SEND_FILE_NAME_100M, i);
        ASSERT_GE(ret, 0);
        p[i] = sendFile[i];
    }
    ret = NSTACKX_DFileSendFiles(cid, p, sendNums, nullptr);
    ASSERT_EQ(ret, NSTACKX_EOK);

    sleep(1);
    system("ip tuntap del dev tap0 mod tap");
    ASSERT_GE(ret, NSTACKX_EOK);

    while (second) {
        if (g_recvSucc) {
            break;
        }
        sleep(1);
        second--;
    }

    ASSERT_GE(g_recvSucc, sendNums);
    for (int i = 0; i < sendNums; i++) {
        ret = sprintf_s(recvFile[i], NSTACKX_MAX_FILE_NAME_LEN, "%s-%d",
            DFILE_DEFAULT_STORAGE_PATH DFILE_SEND_FILE_NAME_100M, i);
        ASSERT_GE(ret, 0);
        ret = FileMd5Equal(sendFile[i], recvFile[i]);
        ASSERT_EQ(ret, NSTACKX_TRUE);
    }

    NSTACKX_DFileClose(sid);
    NSTACKX_DFileClose(cid);
    sleep(1);
}

TEST_F(MpEscape_SETUP_AND_TEARDOWN, DISABLED_NstackxDFileMPUdpEscapeDisconnect)
{
    int sendNums = 5;
    int second = 120;
    char sendFile[sendNums][NSTACKX_MAX_FILE_NAME_LEN];
    char recvFile[sendNums][NSTACKX_MAX_FILE_NAME_LEN];
    const char *p[sendNums];

    NSTACKX_DFileSetCapabilities(0, 0);
    int32_t sid = NSTACKX_DFileServerMp(g_mp_serverPara, DFILE_MP_PARA_NUM, nullptr, 0, MsgReceiver);
    ASSERT_GT(sid, 0);

    int32_t ret = NSTACKX_DFileSetStoragePath(sid, DFILE_DEFAULT_STORAGE_PATH);
    ASSERT_EQ(ret, 0);

    int32_t cid = NSTACKX_DFileClientMp(g_mp_clinetPara, DFILE_MP_PARA_NUM, nullptr, 0, MsgReceiver);
    ASSERT_GT(cid, 0);

    for (int i = 0; i < sendNums; i++) {
        ret = sprintf_s(sendFile[i], NSTACKX_MAX_FILE_NAME_LEN,
            "%s-%d", DFILE_SEND_FILE_NAME_100M, i);
        ASSERT_GE(ret, 0);
        p[i] = sendFile[i];
    }
    ret = NSTACKX_DFileSendFiles(cid, p, sendNums, nullptr);
    ASSERT_EQ(ret, NSTACKX_EOK);

    sleep(1);
    system("ip tuntap del dev tap0 mod tap");
    ASSERT_GE(ret, NSTACKX_EOK);

    while (second) {
        if (g_recvSucc) {
            break;
        }
        sleep(1);
        second--;
    }

    ASSERT_GE(g_recvSucc, sendNums);
    for (int i = 0; i < sendNums; i++) {
        ret = sprintf_s(recvFile[i], NSTACKX_MAX_FILE_NAME_LEN, "%s-%d",
            DFILE_DEFAULT_STORAGE_PATH DFILE_SEND_FILE_NAME_100M, i);
        ASSERT_GE(ret, 0);
        ret = FileMd5Equal(sendFile[i], recvFile[i]);
        ASSERT_EQ(ret, NSTACKX_TRUE);
    }

    NSTACKX_DFileClose(sid);
    NSTACKX_DFileClose(cid);
    sleep(1);
}

TEST_F(MpEscape_SETUP_AND_TEARDOWN, DISABLED_NstackxDFileMPLinkSeqEscapeDisconnect)
{
    int sendNums = 5;
    int second = 120;
    char sendFile[sendNums][NSTACKX_MAX_FILE_NAME_LEN];
    char recvFile[sendNums][NSTACKX_MAX_FILE_NAME_LEN];
    const char *p[sendNums];

    NSTACKX_DFileSetCapabilities(NSTACKX_CAPS_LINK_SEQUENCE | NSTACKX_CAPS_WLAN_CATEGORY, SET_CAPABILITIES_VALUE_FOUR);
    int32_t sid = NSTACKX_DFileServerMp(g_mp_serverPara, DFILE_MP_PARA_NUM, nullptr, 0, MsgReceiver);
    ASSERT_GT(sid, 0);

    int32_t ret = NSTACKX_DFileSetStoragePath(sid, DFILE_DEFAULT_STORAGE_PATH);
    ASSERT_EQ(ret, 0);

    int32_t cid = NSTACKX_DFileClientMp(g_mp_clinetPara, DFILE_MP_PARA_NUM, nullptr, 0, MsgReceiver);
    ASSERT_GT(cid, 0);

    for (int i = 0; i < sendNums; i++) {
        ret = sprintf_s(sendFile[i], NSTACKX_MAX_FILE_NAME_LEN,
            "%s-%d", DFILE_SEND_FILE_NAME_100M, i);
        ASSERT_GE(ret, 0);
        p[i] = sendFile[i];
    }
    ret = NSTACKX_DFileSendFiles(cid, p, sendNums, nullptr);
    ASSERT_EQ(ret, NSTACKX_EOK);

    sleep(1);
    system("ip tuntap del dev tap0 mod tap");
    ASSERT_GE(ret, NSTACKX_EOK);

    while (second) {
        if (g_recvSucc) {
            break;
        }
        sleep(1);
        second--;
    }

    ASSERT_GE(g_recvSucc, sendNums);
    for (int i = 0; i < sendNums; i++) {
        ret = sprintf_s(recvFile[i], NSTACKX_MAX_FILE_NAME_LEN, "%s-%d",
            DFILE_DEFAULT_STORAGE_PATH DFILE_SEND_FILE_NAME_100M, i);
        ASSERT_GE(ret, 0);
        ret = FileMd5Equal(sendFile[i], recvFile[i]);
        ASSERT_EQ(ret, NSTACKX_TRUE);
    }

    NSTACKX_DFileClose(sid);
    NSTACKX_DFileClose(cid);
    sleep(1);
}

TEST(NSTACKX_DFILE, CheckDecodeSettingFrameDfxPayload)
{
    int32_t ret = NSTACKX_EOK;
    uint8_t *buf = (uint8_t *)calloc(14720, sizeof(uint8_t));
    if (buf == nullptr) {
        return;
    }
    SettingFrame hostSettingFrame;
    (void)memset_s(&hostSettingFrame, sizeof(SettingFrame), 0, sizeof(SettingFrame));

    (void)memset_s(buf, 14720, 0x01, 14720);
    SettingFrame *settingFrame = (SettingFrame *)buf;
    settingFrame->header.type = NSTACKX_DFILE_SETTING_FRAME;
    settingFrame->header.flag = 0;
    settingFrame->header.sessionId = 0;
    settingFrame->header.transId = 0;
    settingFrame->header.length = htons(14720 - DFILE_FRAME_HEADER_LEN);
    settingFrame->connType = htons(CONNECT_TYPE_P2P);
    settingFrame->mtu = htons(14720);

    ret = DecodeSettingFrame((SettingFrame *)buf, &hostSettingFrame);
    ASSERT_EQ(ret, NSTACKX_EOK);
    ASSERT_EQ(strlen(hostSettingFrame.productVersion), (size_t)0);

    settingFrame->header.length = htons(sizeof(SettingFrame) - DFILE_FRAME_HEADER_LEN);
    ret = DecodeSettingFrame((SettingFrame *)buf, &hostSettingFrame);
    ASSERT_EQ(ret, NSTACKX_EOK);
    ASSERT_EQ(strlen(hostSettingFrame.productVersion), (size_t)0);

    if (strcpy_s(settingFrame->productVersion, VERSION_STR_LEN, "123456") != EOK) {
        printf("strcpy productVersion failed!\n");
        free(buf);
        return;
    }
    ret = DecodeSettingFrame((SettingFrame *)buf, &hostSettingFrame);
    ASSERT_EQ(ret, NSTACKX_EOK);
    ASSERT_EQ(strlen(hostSettingFrame.productVersion), (size_t)6);
    printf("productVersion:%s\n", hostSettingFrame.productVersion);

    (void)memset_s(settingFrame->productVersion, VERSION_STR_LEN, 0, VERSION_STR_LEN);
    ret = DecodeSettingFrame((SettingFrame *)buf, &hostSettingFrame);
    ASSERT_EQ(ret, NSTACKX_EOK);
    ASSERT_EQ(strlen(hostSettingFrame.productVersion), (size_t)0);

    free(buf);
}

static void MsgReceiverWithSem(int32_t sid, DFileMsgType msgType, const DFileMsg *msg)
{
    (void)msg;
    printf("MsgReceiver: session %d, msgtype: %d\n", sid, msgType);
    if (msgType == DFILE_ON_CONNECT_SUCCESS) {
        printf("Callback:connect success\n");
        SemPost(&g_sem);
    }
    if (msgType == DFILE_ON_FILE_RECEIVE_SUCCESS) {
        for (uint32_t i = 0; i < msg->fileList.fileNum; i++) {
            printf("MsgReceiver: recv success, %s\n", msg->fileList.files[i]);
        }
        g_recvSucc += msg->fileList.fileNum;
    }
    if (msgType == DFILE_ON_FILE_SEND_FAIL || msgType == DFILE_ON_FATAL_ERROR) {
        for (uint32_t i = 0; i < msg->fileList.fileNum; i++) {
            printf("MsgReceiver: rest files, %s\n", msg->fileList.files[i]);
        }
        if (msg->fileList.fileNum) {
            int ret = NSTACKX_DFileSendFiles(g_cid, msg->fileList.files, msg->fileList.fileNum, nullptr);
            EXPECT_EQ(ret, 0);
            g_restFileNums = msg->fileList.fileNum;
        }
    }
    return;
}

TEST_F(NSTACKX_DFILE_WITH_SETUP_AND_TEARDOWN, DFileGetFileList)
{
    const char *files[NSTACKX_DFILE_MAX_FILE_NUM] = { nullptr };
    int second = 10;
    SemInit(&g_sem, 0, 0);
    int ssid = NSTACKX_DFileServer(&g_defaultAddr, sizeof(g_defaultAddr), nullptr, 0, MsgReceiverWithSem);
    ASSERT_GT(ssid, 0);

    int ret = NSTACKX_DFileSetStoragePath(ssid, DFILE_DEFAULT_STORAGE_PATH);
    EXPECT_EQ(ret, 0);

    int csid = NSTACKX_DFileClient(&g_defaultAddr, sizeof(g_defaultAddr), nullptr, 0, MsgReceiverWithSem);
    EXPECT_GT(csid, 0);

    struct timespec expire;
    expire.tv_sec = SLEEP_SECOND_LOW;
    expire.tv_nsec = 0;
    ret = SemTimedWait(&g_sem, expire);
    EXPECT_EQ(ret, 0);

    DFileOpt opt;
    opt.optType = OPT_TYPE_CLEAR_POLICY;
    opt.value = CLEAR_POLICY_NOTHING;
    opt.valLen = sizeof(DFileOptValueClearPolicy);
    ret = NSTACKX_DFileSetSessionOpt(csid, &opt);
    EXPECT_EQ(ret, 0);

    files[0] = DFILE_SEND_FILE_NAME;
    ret = NSTACKX_DFileSendFiles(csid, files, 1, nullptr);
    EXPECT_EQ(ret, 0);

    while (second) {
        if (g_recvSucc) {
            break;
        }
        sleep(1);
        second--;
    }

    ret = NSTACKX_DFileGetSessionOpt(csid, &opt);
    EXPECT_EQ(ret, 0);
    ASSERT_GE(g_recvSucc, 1);

    ret = NSTACKX_DFileSessionGetFileList(csid);
    EXPECT_EQ(ret, 0);
    ret = NSTACKX_DFileSessionGetFileList(ssid);
    EXPECT_EQ(ret, 0);

    ret = FileMd5Equal((char *)DFILE_SEND_FILE_NAME, (char *)DFILE_DEFAULT_STORAGE_PATH DFILE_SEND_FILE_NAME);
    ASSERT_EQ(ret, NSTACKX_TRUE);

    SemDestroy(&g_sem);
    NSTACKX_DFileClose(csid);
    NSTACKX_DFileClose(ssid);

    sleep(1);
}