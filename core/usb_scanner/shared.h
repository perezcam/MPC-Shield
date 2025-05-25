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

/* Global fanotify FD */
extern int g_fan_fd;

/* Event record pushed by monitor, popped by workers */
typedef struct {
    uint64_t mask;
    pid_t    pid;
    int      fd;
} event_t;

/* Enqueue/dequeue (implemented in monitor.c) */
void push_event(event_t ev);
void pop_event(event_t *ev);

/* Recursively mark `root` and all subdirectories for fanotify */
void mark_all_dirs(const char *root);

#endif // SHARED_H
