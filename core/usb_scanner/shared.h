#ifndef SHARED_H
#define SHARED_H

#define _GNU_SOURCE
#include <limits.h>
#include <stdint.h>
#include <sys/fanotify.h>
#include <pthread.h>
#include <unistd.h>
#include <openssl/sha.h>          // crypto SHA‑256
#include <sys/stat.h>             // permisos & atributos

#define CMDLINE_MAX 4096         
#define QUEUE_SIZE   1024
#define NUM_WORKERS   10
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
    uint64_t mask;            // FAN_* mask               
    ProcessInfo proc;         // quién lo hizo            
    FileInfo    file;         // qué archivo tocó         
} EventInfo;

void push_event(EventInfo ev);
void pop_event(EventInfo *ev);

/* scanner.c exports */
static void full_mark(const char *root);     // Changed: mark entire mount instead of recursive
int  get_current_mounts(char *mounts[], int max);

/* report.c exports */
void report_connected_devices(const char **devices, int count);
void report_current_mounts(void);
void report_file_modification(const char *filepath, uint64_t mask, pid_t pid);
void report_suspicious(pid_t pid, const char *exe_path);

/* Global fanotify fds (declared in main.c) */
extern int g_fan_content_fd;   // Added for content events
extern int g_fan_notify_fd;    // Added for metadata create/delete events

#endif // SHARED_H