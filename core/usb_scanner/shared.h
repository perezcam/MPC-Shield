#ifndef SHARED_H
#define SHARED_H

#define _GNU_SOURCE

#include <limits.h>
#include <stdint.h>
#include <sys/fanotify.h>
#include <pthread.h>
#include <unistd.h>
#include <openssl/sha.h>
#include <sys/stat.h>
#include <linux/limits.h>

#define CMDLINE_MAX 4096
#define QUEUE_SIZE   1024

#ifndef NUM_WORKERS
#define NUM_WORKERS   10
#endif

#define MAX_USBS      64

typedef struct {
    pid_t  pid;
    uid_t  uid;
    gid_t  gid;
    char   exe[PATH_MAX];
    char   cmdline[CMDLINE_MAX];
    pid_t  ppid;
} ProcessInfo;

typedef struct {
    char   path[PATH_MAX];
    unsigned char sha256[SHA256_DIGEST_LENGTH];
    mode_t mode;
    struct timespec mtime;
} FileInfo;

typedef struct {
    uint64_t   mask;
    ProcessInfo proc;
    FileInfo    file;
} EventInfo;

/* Cola de eventos */
void push_event(EventInfo ev);
void pop_event(EventInfo *ev);

/* Entrypoints de hilos */
void *monitor_thread(void *arg);
void *scanner_thread(void *arg);
void *worker_thread(void *arg);

/* scanner.c exporta */
void  mark_path(const char *path);
int   get_current_mounts(char *mounts[], int max);

/* report.c (o utils.c) exporta */
int   get_path_from_fd(int fd, char *buf, size_t bufsiz);
void  report_current_mounts(void);
void  report_file_modification(const char *filepath, uint64_t mask, pid_t pid);
void  report_suspicious(pid_t pid, const char *exe_path);

/* Variables globales (definidas en shared.c) */
extern int g_fan_content_fd;
extern int g_fan_notify_fd;

#endif // SHARED_H
