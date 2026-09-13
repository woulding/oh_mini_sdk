/*
 * Copyright (c) 2023 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include <unistd.h>
#include <stdio.h>
#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <pwd.h>
#include <grp.h>
#include <paths.h>
#include <sys/types.h>

static unsigned int g_flags = 0;

#define flag_l (1 << 0)
#define flag_p (1 << 1)
#define flag_c (1 << 2)

#define FLAG(x) ((g_flags & (flag_##x)) == flag_##x)
#define SET_FLAG(x) (g_flags |= (flag_##x))

struct passwd *xgetpwnam(char *name)
{
    struct passwd *up = getpwnam(name);

    if (!up)
        fprintf(stderr, "user '%s' is not exist\n", name);
    return up;
}

static void *xmalloc(size_t size)
{
    void *p = malloc(size);

    if (!p)
        fprintf(stderr, "xmalloc failed, err = %d\n", errno);
    else
        memset(p, 0, size);

    return p;
}

static void reset_env(struct passwd *p, int clear)
{
    if (p == NULL) {
        return;
    }

    if (clear) {
        if (chdir(p->pw_dir))
        {
            printf("chdir %s failed, err = %d\n", p->pw_dir, errno);
            chdir("/");
        }
    }

    setenv("PATH", _PATH_DEFPATH, 1);
    setenv("HOME", p->pw_dir, 1);
    setenv("SHELL", p->pw_shell, 1);
    setenv("USER", p->pw_name, 1);
    setenv("LOGNAME", p->pw_name, 1);
}

static void xexec(char **argv)
{
    execvp(argv[0], argv);
    _exit(127);
}

static void xsetuser(struct passwd *pwd)
{
    if (pwd == NULL) {
        return;
    }
    if (initgroups(pwd->pw_name, pwd->pw_gid) || setgid(pwd->pw_uid) || setuid(pwd->pw_uid))
        fprintf(stderr, "failed to set user %s, err = %d\n", pwd->pw_name, errno);
}

static void usage(void)
{
    printf("usage: su [-lp] [-s SHELL] [-c CMD] [USER [COMMAND...]]\n");
    printf("\t-s  Shell to use (default is user's shell from /etc/passwd)\n");
    printf("\t-c  Command line to pass to -s shell (ala sh -c \"CMD\")\n");
    printf("\t-l  Reset environment as if new login.\n");
    printf("\t-p  Preserve environment (except for $PATH and $IFS)\n");
}

int main(int argc, char **argv)
{
    char *name, **argu, **args;
    struct passwd *up;
    int c = -1;
    char *default_shell = "/bin/sh";
    char *cmd;
    uid_t current_uid = -1;

    while ((c = getopt(argc, argv, "lps:c:")) != -1) {
        switch (c) {
        case 'l':
            SET_FLAG(l);
            break;
        case 'p':
            SET_FLAG(p);
            break;
        case 'c':
            SET_FLAG(c);
            cmd = optarg;
            break;
        case 's':
            default_shell = optarg;
            break;
        case '?':
            printf("Unknow option %c\n", optopt);
            usage();
            break;
        default:
            break;
        }
    }

    if (optind < argc) {
        name = argv[optind];
        optind++;
    } else {
        name = "root";
    }

    current_uid = getuid();
    if (current_uid != 0 && current_uid != 2000) { // only root and shell can switch user.
        fprintf(stderr, "Not allowed\n");
        return -1;
    }

    printf("Switch to %s\n", name);
    xsetuser(up = xgetpwnam(name));

    if (FLAG(p)) {
        unsetenv("IFS");
        setenv("PATH", _PATH_DEFPATH, 1);
    } else
        reset_env(up, FLAG(l));

    args = argu = xmalloc(sizeof(char *) * (argc - optind + 4 + 1));
    *(args++) = default_shell;

    if (FLAG(l))
        *(args++) = "-l";
    if (FLAG(c)) {
        *(args++) = "-c";
        *(args++) = cmd;
    }

    for (int i = optind; i < argc; i++) {
        *(args++) = argv[i];
    }
    xexec(argu);
    puts("No.");
    return 1;
}
