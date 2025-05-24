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

/* Definition of the global fanotify FD */
int g_fan_fd;

int main(int argc, char *argv[]) {
    /* 1) Initialize fanotify to watch all file‐content events */
    g_fan_fd = fanotify_init(
        FAN_CLASS_CONTENT | FAN_CLOEXEC | FAN_NONBLOCK,
        O_RDONLY | O_LARGEFILE
    );
    if (g_fan_fd < 0) {
        perror("fanotify_init");
        exit(EXIT_FAILURE);
    }

    /* 2) Spawn scanner thread (USB detection & marking) */
    pthread_t scan_tid;
    if (pthread_create(&scan_tid, NULL, scanner_thread, NULL) != 0) {
        perror("pthread_create(scanner)");
        exit(EXIT_FAILURE);
    }

    /* 3) Spawn monitor thread (reads fanotify, enqueues events) */
    pthread_t mon_tid;
    if (pthread_create(&mon_tid, NULL, monitor_thread, NULL) != 0) {
        perror("pthread_create(monitor)");
        exit(EXIT_FAILURE);
    }

    /* 4) Spawn worker pool */
    pthread_t workers[NUM_WORKERS];
    for (int i = 0; i < NUM_WORKERS; i++) {
        if (pthread_create(&workers[i], NULL, worker_thread, NULL) != 0) {
            perror("pthread_create(worker)");
            exit(EXIT_FAILURE);
        }
    }

    /* 5) Join (these threads run forever in a daemon-style tool) */
    pthread_join(scan_tid,  NULL);
    pthread_join(mon_tid,   NULL);
    for (int i = 0; i < NUM_WORKERS; i++)
        pthread_join(workers[i], NULL);

    close(g_fan_fd);
    return 0;
}
