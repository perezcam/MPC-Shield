#ifndef SHARED_H
#define SHARED_H

#define _GNU_SOURCE

#include <limits.h>
#include <stdint.h>
#include <sys/fanotify.h>
#include <pthread.h>
#include <unistd.h>

#define QUEUE_SIZE   1024
#define NUM_WORKERS   10
#define MAX_USBS      64

typedef struct {
    uint64_t mask;
    pid_t pid;
    char filepath[PATH_MAX];
} event_t;

void push_event(event_t ev);
void pop_event(event_t *ev);

/* scanner.c exports */
void mark_mount(const char *root);     // Changed: mark entire mount instead of recursive
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