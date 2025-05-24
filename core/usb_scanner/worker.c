#include "shared.h"
#include <limits.h>
#include <unistd.h>
#include <stdio.h>
#include <string.h>

/* Provided by report.c */
void report_file_modification(const char *filepath,
                              uint64_t     mask,
                              pid_t        pid);
void report_suspicious(pid_t pid, const char *exe_path);

/* Helpers to resolve paths */
static void get_path_from_fd(int fd, char *out, size_t sz) {
    char link[64];
    snprintf(link, sizeof(link), "/proc/self/fd/%d", fd);
    ssize_t len = readlink(link, out, sz-1);
    out[(len>0)?len:0] = '\0';
}

static void get_exe_path(pid_t pid, char *out, size_t sz) {
    char link[64];
    snprintf(link, sizeof(link), "/proc/%d/exe", pid);
    ssize_t len = readlink(link, out, sz-1);
    out[(len>0)?len:0] = '\0';
}

/* Whitelist check */
static int is_legit(const char *exe) {
    const char *ok[] = { "/bin/", "/usr/bin/", "/sbin/", "/usr/sbin/", NULL };
    for (int i = 0; ok[i]; i++)
        if (strncmp(exe, ok[i], strlen(ok[i])) == 0)
            return 1;
    return 0;
}

void *worker_thread(void *arg) {
    (void)arg;
    while (1) {
        event_t ev;
        pop_event(&ev);

        char path[PATH_MAX] = {0}, exe[PATH_MAX] = {0};
        if (ev.fd >= 0) {
            get_path_from_fd(ev.fd, path, sizeof(path));
            close(ev.fd);
        }
        get_exe_path(ev.pid, exe, sizeof(exe));

        if (!is_legit(exe)) {
            report_suspicious(ev.pid, exe);
            report_file_modification(path, ev.mask, ev.pid);
        }
    }
    return NULL;
}
