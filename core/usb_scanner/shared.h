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
#include <glib.h>

#define CMDLINE_MAX 4096
#define QUEUE_SIZE   1024

#ifndef NUM_WORKERS
#define NUM_WORKERS   10
#endif

#define MAX_USBS      64
#define MAX_ENTRIES   128

typedef struct {
    pid_t  pid;
    uid_t  uid;
    gid_t  gid;
    char   exe[PATH_MAX];
    char   cmdline[CMDLINE_MAX];
    pid_t  ppid;
} ProcessInfo;

typedef struct {
    char             path[PATH_MAX];
    unsigned char    sha256[SHA256_DIGEST_LENGTH];
    mode_t           mode;
    struct timespec  mtime;
} FileInfo;

typedef struct {
    uint64_t    mask;
    ProcessInfo proc;
    FileInfo    file;
} EventInfo;

typedef struct {
    char        path[PATH_MAX];
    struct stat st;
    int         in_use;
} pst_entry_t;

typedef struct {
    pst_entry_t entries[MAX_ENTRIES];
    int         count;
} path_stat_table_t;
typedef struct {
    char *time;
    char *path;
    char *cause;
    char *pid;      
} GuiEvent;

/* ---------------------------------------------------------------- */
/*   Variables globales DEFINIDAS en main.c (solo aquí)            */
/* ---------------------------------------------------------------- */
extern int               g_fan_content_fd;
extern int               g_fan_notify_fd;
extern pthread_mutex_t   path_table_mutex;
extern path_stat_table_t path_table;
extern GAsyncQueue *event_queue;


/* ---------------------------------------------------------------- */
/*   Funciones para arrancar/parar el backend (scann.c)            */
/* ---------------------------------------------------------------- */
void scann_start(void);
void scann_stop(void);

/* ---------------------------------------------------------------- */
/*   Cola de eventos (event_queue)                                 */
/* ---------------------------------------------------------------- */
void push_event(EventInfo ev);
void pop_event(EventInfo *ev);

/* ---------------------------------------------------------------- */
/*   Entrypoints de los hilos                                      */
/* ---------------------------------------------------------------- */
void *monitor_thread(void *arg);
void *scanner_thread(void *arg);
void *worker_thread(void *arg);

/* ---------------------------------------------------------------- */
/*   Funciones del scanner (scanner.c)                             */
/* ---------------------------------------------------------------- */
void  mark_path(const char *path);
int   get_current_mounts(char *mounts[], int max);
int   find_mount_by_fsid(__kernel_fsid_t event_fsid, char *out);

/* ---------------------------------------------------------------- */
/*   Funciones de reporte (report.c)                               */
/* ---------------------------------------------------------------- */
int   get_path_from_fd(int fd, char *buf, size_t bufsiz);
void  report_current_mounts(void);
void  report_file_modification(const char *filepath, uint64_t mask, pid_t pid);
void  report_suspicious(pid_t pid, const char *exe_path);
void  report_metadata_change(const char *filepath,
                             const struct stat *old_s,
                             const struct stat *new_s,
                             pid_t pid);
void  report_file_deletion(const char *filepath, pid_t pid);

/* ---------------------------------------------------------------- */
/*   Tabla de estados de paths (path_stat_table.c)                 */
/* ---------------------------------------------------------------- */
void pst_init(path_stat_table_t *tbl);
int  pst_find_index(path_stat_table_t *tbl, const char *path);
int  pst_update(path_stat_table_t *tbl, const char *path, const struct stat *st);
int  pst_remove(path_stat_table_t *tbl, const char *path);
int  pst_lookup(path_stat_table_t *tbl, const char *path, struct stat *out);

/* ---------------------------------------------------------------- */
/*   Utilidades de monitor (monitor_utils.c)                       */
/* ---------------------------------------------------------------- */
int get_event_fullpath(struct fanotify_event_metadata *md, char *out, size_t outlen);

#endif // SHARED_H
