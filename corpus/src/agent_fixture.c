/*
 * agent_fixture.c - benchmark fixture that looks like a small implant.
 *
 * Harmless by design:
 *   - it only connects to 127.0.0.1 (and the runner uses --network none);
 *   - it only writes inside the sandbox directory given as argv[1].
 *
 * The code is identical for every variant. A variant only adds data
 * (strings), renames a symbol, or changes the BANNER text via variant.h,
 * so behaviour cannot drift.
 *
 * BANNER is stored into a global from main(), so its text shows up in the
 * decompiled main() rather than only in the string table.
 */
#include <arpa/inet.h>
#include <errno.h>
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/utsname.h>
#include <unistd.h>

#include "variant.h"

#ifndef PERSIST_FN
#define PERSIST_FN install_autostart
#endif
#ifndef REPORT_FN
#define REPORT_FN send_report
#endif
#ifndef BANNER
#define BANNER "sysupdate 1.0"
#endif

#define REPORT_HOST "127.0.0.1"
#define REPORT_PORT 4444

const char *volatile g_banner;

static int mkdir_p(const char *path)
{
    char buf[512];
    snprintf(buf, sizeof(buf), "%s", path);
    for (char *p = buf + 1; *p; p++) {
        if (*p == '/') {
            *p = '\0';
            if (mkdir(buf, 0755) != 0 && errno != EEXIST)
                return -1;
            *p = '/';
        }
    }
    if (mkdir(buf, 0755) != 0 && errno != EEXIST)
        return -1;
    return 0;
}

int collect_host_info(char *out, size_t len)
{
    struct utsname u;
    char host[128] = {0};

    if (uname(&u) != 0)
        return -1;
    gethostname(host, sizeof(host) - 1);
    return snprintf(out, len, "host=%s;os=%s;rel=%s;arch=%s",
                    host, u.sysname, u.release, u.machine);
}

int REPORT_FN(const char *report)
{
    struct sockaddr_in addr;
    int fd = socket(AF_INET, SOCK_STREAM, 0);

    if (fd < 0)
        return -1;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(REPORT_PORT);
    inet_pton(AF_INET, REPORT_HOST, &addr.sin_addr);

    if (connect(fd, (struct sockaddr *)&addr, sizeof(addr)) != 0) {
        close(fd);
        return -1;
    }
    send(fd, report, strlen(report), 0);
    close(fd);
    return 0;
}

int PERSIST_FN(const char *root)
{
    char dir[512], path[600];
    FILE *f;

    snprintf(dir, sizeof(dir), "%s/.config/autostart", root);
    if (mkdir_p(dir) != 0)
        return -1;
    snprintf(path, sizeof(path), "%s/sysupdate.desktop", dir);
    f = fopen(path, "w");
    if (!f)
        return -1;
    fprintf(f, "[Desktop Entry]\nType=Application\nName=sysupdate\n"
               "Exec=%s/.local/bin/sysupdate\nX-GNOME-Autostart-enabled=true\n",
            root);
    fclose(f);
    return 0;
}

int main(int argc, char **argv)
{
    char report[512];
    const char *root = argc > 1 ? argv[1] : "./sandbox";

    g_banner = BANNER;
    if (collect_host_info(report, sizeof(report)) < 0)
        return 2;
    printf("persist=%d\n", PERSIST_FN(root));
    printf("report=%d\n", REPORT_FN(report));
    return 0;
}
