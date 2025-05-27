#include "shared.h"
#include <stdlib.h>
#include <stdio.h>
#include <sys/fanotify.h>
#include <fcntl.h>
#include <unistd.h>
#include <pthread.h>

/* Thread entrypoints */
void *monitor_thread(void *arg);
void *scanner_thread(void *arg);
void *worker_thread (void *arg);

/* Definition of the global fanotify FDs */
int g_fan_content_fd;
int g_fan_notify_fd;

int main(int argc, char **argv) {
    /* 1) Initialize fanotify fds */
    g_fan_content_fd = fanotify_init(
        FAN_CLASS_CONTENT | FAN_CLOEXEC | FAN_NONBLOCK,
        O_RDONLY | O_LARGEFILE
    );
    if (g_fan_content_fd < 0) {
        perror("fanotify_init content");
        exit(EXIT_FAILURE);
    }
    g_fan_notify_fd = fanotify_init(
        FAN_CLASS_NOTIF | FAN_CLOEXEC | FAN_NONBLOCK,
        O_RDONLY | O_LARGEFILE
    );
    if (g_fan_notify_fd < 0) {
        perror("fanotify_init notify");
        exit(EXIT_FAILURE);
    }

    /* 2) Spawn threads */
    pthread_t scan_tid, mon_tid, workers[NUM_WORKERS];
    if (pthread_create(&scan_tid, NULL, scanner_thread, NULL) != 0) {
        perror("pthread_create(scanner)");
        exit(EXIT_FAILURE);
    }
    if (pthread_create(&mon_tid,  NULL, monitor_thread, NULL) != 0) {
        perror("pthread_create(monitor)");
        exit(EXIT_FAILURE);
    }
    for (int i = 0; i < NUM_WORKERS; i++) {
        if (pthread_create(&workers[i], NULL, worker_thread, NULL) != 0) {
            perror("pthread_create(worker)");
            exit(EXIT_FAILURE);
        }
    }

    /* 3) Join (daemon-style) */
    pthread_join(scan_tid,  NULL);
    pthread_join(mon_tid,   NULL);
    for (int i = 0; i < NUM_WORKERS; i++)
        pthread_join(workers[i], NULL);

    /* 4) Cleanup */
    close(g_fan_content_fd);
    close(g_fan_notify_fd);
    return 0;
}