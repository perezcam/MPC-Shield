#include <stdio.h>
#include <time.h>
#include <stdint.h>
#include <sys/types.h>
#include "shared.h"

/* Timestamp helper */
static void timestamp(char *buf, size_t sz) {
    time_t t = time(NULL);
    strftime(buf, sz, "%Y-%m-%d %H:%M:%S", localtime(&t));
}

void report_file_modification(const char *filepath,
                              uint64_t     mask,
                              pid_t        pid) {
    char ts[64];
    timestamp(ts, sizeof(ts));
    printf("[%s] File change: %s (pid=%d, mask=0x%lx)\n",
           ts, filepath, pid, mask);
}

void report_suspicious(pid_t pid, const char *exe_path) {
    char ts[64];
    timestamp(ts, sizeof(ts));
    printf("[%s] Suspicious process: pid=%d exe=%s\n",
           ts, pid, exe_path);
}

void report_connected_devices(const char **devices, int count) {
    char ts[64];
    timestamp(ts, sizeof(ts));
    printf("[%s] USB devices mounted:\n", ts);
    for (int i = 0; i < count; i++)
        printf("    - %s\n", devices[i]);
}
