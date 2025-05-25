// shared.h
#ifndef SHARED_H
#define SHARED_H

#define _GNU_SOURCE

#include <limits.h>
#include <stdint.h>
#include <sys/fanotify.h>
#include <pthread.h>
#include <unistd.h>

#define QUEUE_SIZE   1024
#define NUM_WORKERS    4
#define MAX_USBS      64

/* Global fanotify FD */
extern int g_fan_fd;

/* Event record pushed by monitor, popped by workers */
typedef struct {
    uint64_t mask;
    pid_t    pid;
    int      fd;
} event_t;


/* monitor.c exports */
void push_event(event_t ev);
void pop_event(event_t *ev);

/* scanner.c exports */
void mark_all_dirs(const char *root);
int  get_current_mounts(char *mounts[], int max);


/* report.c exports */
void report_connected_devices(const char **devices, int count);
void report_current_mounts(void);
void report_file_modification(const char *filepath, uint64_t mask, pid_t pid);
void report_suspicious(pid_t pid, const char *exe_path);

#endif // SHARED_H