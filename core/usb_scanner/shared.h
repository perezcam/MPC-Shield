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
extern void push_event(EventInfo ev);
extern void pop_event(EventInfo *ev);

/* Entrypoints de hilos */
extern void *monitor_thread(void *arg);
extern void *scanner_thread(void *arg);
extern void *worker_thread(void *arg);

/* scanner.c */
extern void  mark_path(const char *path);
extern int get_current_mounts(char *mounts[], int max);
int find_mount_by_fsid(__kernel_fsid_t event_fsid, char *out);

/* report.c  */
int   get_path_from_fd(int fd, char *buf, size_t bufsiz);
extern void  report_current_mounts(void);
extern void  report_file_modification(const char *filepath, uint64_t mask, pid_t pid);
extern void  report_suspicious(pid_t pid, const char *exe_path);
extern void report_metadata_change(const char *filepath, const struct stat *old_s, const struct stat *new_s, pid_t pid);
void report_file_deletion(const char *filepath, pid_t pid);

/*path_stat_table.c*/
extern void pst_init(path_stat_table_t *tbl);
extern int pst_find_index(path_stat_table_t *tbl, const char *path);
extern int pst_update(path_stat_table_t *tbl, const char *path, const struct stat *st);
extern int pst_remove(path_stat_table_t *tbl, const char *path);
extern int pst_lookup(path_stat_table_t *tbl, const char *path, struct stat *out);

/*monitor_utils.c*/
extern int get_event_fullpath(struct fanotify_event_metadata *md, char *out, size_t outlen);
#endif // SHARED_H
