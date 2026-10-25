/*
 * health_fixture.c - second benchmark fixture for re-agent-lab.
 *
 * A small, benign host health reporter. It is deliberately harmless:
 *   - it sends one UDP datagram to 127.0.0.1 only (runner uses --network none);
 *   - it writes only inside the directory given as argv[1].
 * It exists so the triage findings can be checked on a program with a
 * different shape from agent_fixture.c:
 *   - work is dispatched through a table of function pointers;
 *   - UDP instead of TCP; a systemd user unit instead of a .desktop file;
 *   - host facts come from /etc/os-release and getuid().
 *
 * The same three capability classes are present by construction:
 *   host_info_collection  read_osrelease()
 *   network_connection    send_stats() -> UDP 127.0.0.1:5140
 *   persistence           PERSIST_FN() writes a systemd user timer unit
 *
 * Variants change data or a symbol name only (variant.h); the code is fixed.
 */
#include <arpa/inet.h>
#include <errno.h>
#include <netinet/in.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <unistd.h>

#include "variant.h"

#ifndef PERSIST_FN
#define PERSIST_FN install_user_timer
#endif

#define STATS_HOST "127.0.0.1"
#define STATS_PORT 5140

static int mkdirs(const char *path)
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
    return (mkdir(buf, 0755) != 0 && errno != EEXIST) ? -1 : 0;
}

int read_osrelease(char *out, size_t len)
{
    FILE *f = fopen("/etc/os-release", "r");
    size_t n = 0;

    if (!f) {
        out[0] = '\0';
        return -1;
    }
    n = fread(out, 1, len - 1, f);
    out[n] = '\0';
    fclose(f);
    return (int)n;
}

int send_stats(const char *payload)
{
    struct sockaddr_in addr;
    int fd = socket(AF_INET, SOCK_DGRAM, 0);

    if (fd < 0)
        return -1;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(STATS_PORT);
    inet_pton(AF_INET, STATS_HOST, &addr.sin_addr);
    sendto(fd, payload, strlen(payload), 0, (struct sockaddr *)&addr, sizeof(addr));
    close(fd);
    return 0;
}

int PERSIST_FN(const char *root)
{
    char dir[512], path[600];
    FILE *f;

    snprintf(dir, sizeof(dir), "%s/.config/systemd/user", root);
    if (mkdirs(dir) != 0)
        return -1;
    snprintf(path, sizeof(path), "%s/health-report.timer", dir);
    f = fopen(path, "w");
    if (!f)
        return -1;
    fprintf(f, "[Unit]\nDescription=health report\n\n[Timer]\nOnBootSec=5min\n"
               "OnUnitActiveSec=1h\n\n[Install]\nWantedBy=timers.target\n");
    fclose(f);
    return 0;
}

typedef int (*step_fn)(const char *);

static int step_host(const char *root)
{
    char buf[1024];
    (void)root;
    return read_osrelease(buf, sizeof(buf)) < 0 ? -1 : 0;
}

static int step_net(const char *root)
{
    char msg[128];
    snprintf(msg, sizeof(msg), "uid=%d;root=%s", (int)getuid(), root);
    return send_stats(msg);
}

static int step_persist(const char *root)
{
    return PERSIST_FN(root);
}

int main(int argc, char **argv)
{
    const char *root = argc > 1 ? argv[1] : "./sandbox";
    step_fn steps[] = {step_host, step_net, step_persist};

    for (size_t i = 0; i < sizeof(steps) / sizeof(steps[0]); i++)
        printf("step%zu=%d\n", i, steps[i](root));
    return 0;
}
