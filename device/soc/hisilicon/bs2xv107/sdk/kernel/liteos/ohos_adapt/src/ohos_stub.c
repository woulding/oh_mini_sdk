/*
 * Copyright (c) 2026 Hihope Open Source Organization.
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
 *
 * Description: Stubs for OHOS lite components on bs21e.
 *
 * The bs21e SDK is a prebuilt-library SDK without POSIX/VFS/littlefs/pthread
 * support, but a few OHOS components reference those symbols:
 *   - hiview_lite        -> open/close/read/write/lseek/fsync/unlink
 *   - blackbox_lite      -> UtilsFile* + pthread_create
 *   - param_client_lite  -> UtilsFile*
 * These stubs let the firmware link. File logging and the blackbox save thread
 * are not functional on bs21e; replace with real implementations if needed.
 */
#include <stddef.h>
#include <errno.h>
#include <sys/types.h>
#include <unistd.h>
#include <pthread.h>

int open(const char *path, int oflag, ...)
{
    (void)path;
    (void)oflag;
    errno = ENOSYS;
    return -1;
}

int close(int fd)
{
    (void)fd;
    errno = ENOSYS;
    return -1;
}

ssize_t read(int fd, void *buf, size_t count)
{
    (void)fd;
    (void)buf;
    (void)count;
    errno = ENOSYS;
    return -1;
}

ssize_t write(int fd, const void *buf, size_t count)
{
    (void)fd;
    (void)buf;
    (void)count;
    errno = ENOSYS;
    return -1;
}

off_t lseek(int fd, off_t offset, int whence)
{
    (void)fd;
    (void)offset;
    (void)whence;
    errno = ENOSYS;
    return (off_t)-1;
}

int fsync(int fd)
{
    (void)fd;
    errno = ENOSYS;
    return -1;
}

int unlink(const char *path)
{
    (void)path;
    errno = ENOSYS;
    return -1;
}

int pthread_create(pthread_t *thread, const pthread_attr_t *attr,
                   void *(*start_routine)(void *), void *arg)
{
    (void)thread;
    (void)attr;
    (void)start_routine;
    (void)arg;
    return -1;
}

int UtilsFileOpen(const char *path, int oflag, int mode)
{
    (void)path;
    (void)oflag;
    (void)mode;
    return -1;
}

int UtilsFileClose(int fd)
{
    (void)fd;
    return -1;
}

int UtilsFileRead(int fd, char *buf, unsigned int len)
{
    (void)fd;
    (void)buf;
    (void)len;
    return -1;
}

int UtilsFileWrite(int fd, const char *buf, unsigned int len)
{
    (void)fd;
    (void)buf;
    (void)len;
    return -1;
}

int UtilsFileStat(const char *path, unsigned int *fileSize)
{
    (void)path;
    (void)fileSize;
    return -1;
}
