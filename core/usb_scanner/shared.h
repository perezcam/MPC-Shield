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

#define MAX_ENTRIES 128

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

typedef struct {
    char        path[PATH_MAX];  // absolute path
    struct stat st;              // stat snapshot
    int         in_use;          // 0 = free; 1 = used
} pst_entry_t;

typedef struct {
    pst_entry_t entries[MAX_ENTRIES];
    int count;  // how many in use
} path_stat_table_t;


/* Variables globales (definidas en shared.c) */
extern int g_fan_content_fd;
extern int g_fan_notify_fd;

/* Global path-stat table and its mutex */
extern path_stat_table_t path_table;
extern pthread_mutex_t path_table_mutex;


/* Cola de eventos */
void push_event(EventInfo ev);
void pop_event(EventInfo *ev);

/* Entrypoints de hilos */
void *monitor_thread(void *arg);
void *scanner_thread(void *arg);
void *worker_thread(void *arg);

/* scanner.c */
void  mark_path(const char *path);
int   get_current_mounts(char *mounts[], int max);

/* report.c  */
int   get_path_from_fd(int fd, char *buf, size_t bufsiz);
void  report_current_mounts(void);
void  report_file_modification(const char *filepath, uint64_t mask, pid_t pid);
void  report_suspicious(pid_t pid, const char *exe_path);
void report_metadata_change(const char *filepath, const struct stat *old_s, const struct stat *new_s, pid_t pid);

/*path_stat_table.c*/
static void pst_init(path_stat_table_t *tbl);
static int pst_find_index(path_stat_table_t *tbl, const char *path);
static int pst_update(path_stat_table_t *tbl, char *path, const struct stat *st);
static int pst_remove(path_stat_table_t *tbl, const char *path);
static int pst_lookup(path_stat_table_t *tbl, const char *path, struct stat *out);

/*monitor_utils.c*/
int get_event_fullpath(struct fanotify_event_metadata *md, char *out, size_t outlen);
#endif // SHARED_H
